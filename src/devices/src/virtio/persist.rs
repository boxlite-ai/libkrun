// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
//
// Adapted from Firecracker 6ec271414300fb8f0ff1ff79ad321bb7467d072f:
// src/vmm/src/devices/virtio/persist.rs (QueueState, VirtioDeviceState,
// MmioTransportState). Local differences: the serialized state carries
// event_idx_enabled and shm_region_select, validation covers ring
// alignment/ranges and cursor consistency against guest RAM (including u16
// wrapping), inactive partially negotiated queues are preserved without
// activation checks, and guest-written selector registers are preserved
// verbatim instead of being range-checked.

//! Reusable serde state for virtio queues, devices and the MMIO transport.
//!
//! Stage-3 block snapshots are the first consumer; later device stages must
//! reuse these structures instead of inventing per-device restore protocols.

use std::num::Wrapping;

use serde::{Deserialize, Serialize};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::queue::Queue;

/// Errors thrown while validating or restoring virtio snapshot state.
#[derive(Debug)]
pub enum PersistError {
    /// Snapshot state contains invalid device info.
    InvalidInput,
    /// Activated queue state is inconsistent: {0}
    InvalidQueue(&'static str),
    /// Guest memory access failed while validating ring cursors.
    GuestMemory(vm_memory::GuestMemoryError),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::InvalidInput => write!(f, "snapshot state contains invalid device info"),
            PersistError::InvalidQueue(why) => {
                write!(f, "activated queue state is inconsistent: {why}")
            }
            PersistError::GuestMemory(e) => {
                write!(f, "guest memory access failed while validating queue: {e}")
            }
        }
    }
}

/// Queue information saved in a snapshot.
///
/// `next_avail`/`next_used`/`num_added` are u16 ring-sequence cursors that
/// are NOT stored in guest RAM; losing them desynchronizes the device from
/// the rings. `event_idx_enabled` mirrors the queue-local copy of the
/// negotiated VIRTIO_RING_F_EVENT_IDX bit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueState {
    /// The maximal size in elements offered by the device
    pub max_size: u16,
    /// The queue size in elements the driver selected
    pub size: u16,
    /// Indicates if the queue is finished with configuration
    pub ready: bool,
    /// Guest physical address of the descriptor table
    pub desc_table: u64,
    /// Guest physical address of the available ring
    pub avail_ring: u64,
    /// Guest physical address of the used ring
    pub used_ring: u64,
    pub next_avail: u16,
    pub next_used: u16,
    /// Whether VIRTIO_RING_F_EVENT_IDX notification suppression is in use
    pub event_idx_enabled: bool,
    /// The number of added used buffers since the last notification check
    pub num_added: u16,
}

impl QueueState {
    /// Capture the queue-local state that is not part of guest RAM.
    pub fn from_queue(queue: &Queue) -> Self {
        QueueState {
            max_size: queue.max_size,
            size: queue.size,
            ready: queue.ready,
            desc_table: queue.desc_table.raw_value(),
            avail_ring: queue.avail_ring.raw_value(),
            used_ring: queue.used_ring.raw_value(),
            next_avail: queue.next_avail.0,
            next_used: queue.next_used.0,
            event_idx_enabled: queue.is_event_idx_enabled(),
            num_added: queue.num_added.0,
        }
    }

    /// Rebuild the queue-local cursor/configuration state.
    ///
    /// The caller must have validated this state (`validate`) beforehand;
    /// rings themselves live in guest RAM and are not rewritten here.
    pub fn to_queue(&self) -> Queue {
        let mut queue = Queue::new(self.max_size);
        queue.size = self.size;
        queue.ready = self.ready;
        queue.desc_table = GuestAddress(self.desc_table);
        queue.avail_ring = GuestAddress(self.avail_ring);
        queue.used_ring = GuestAddress(self.used_ring);
        queue.next_avail = Wrapping(self.next_avail);
        queue.next_used = Wrapping(self.next_used);
        queue.set_event_idx(self.event_idx_enabled);
        queue.num_added = Wrapping(self.num_added);
        queue
    }

    /// Validate structural constraints; activated queues additionally must
    /// match the rings in guest RAM (ranges, alignment, cursor consistency
    /// including wrapping). Inactive partially negotiated queues may carry
    /// incomplete configuration and are preserved as-is.
    pub fn validate(&self, mem: &GuestMemoryMmap, activated: bool) -> Result<(), PersistError> {
        if self.max_size == 0
            || self.max_size & (self.max_size - 1) != 0
            || self.max_size > 32768
            || self.size > self.max_size
            || (self.size != 0 && self.size & (self.size - 1) != 0)
        {
            return Err(PersistError::InvalidQueue(
                "queue size is not a valid power of two",
            ));
        }
        if !activated {
            return Ok(());
        }
        if !self.ready || self.size == 0 {
            return Err(PersistError::InvalidQueue("activated queue is not ready"));
        }
        let size = u64::from(self.size);
        let desc_table = GuestAddress(self.desc_table);
        let avail_ring = GuestAddress(self.avail_ring);
        let used_ring = GuestAddress(self.used_ring);
        if self.desc_table & 0xf != 0
            || !mem.check_range(desc_table, (16 * size) as usize)
            || self.avail_ring & 0x1 != 0
            || !mem.check_range(avail_ring, (6 + 2 * size) as usize)
            || self.used_ring & 0x3 != 0
            || !mem.check_range(used_ring, (6 + 8 * size) as usize)
        {
            return Err(PersistError::InvalidQueue(
                "ring address/range breaks alignment or guest memory bounds",
            ));
        }
        let read_idx =
            |addr: u64| mem.read_obj::<u16>(GuestAddress(addr)).map_err(PersistError::GuestMemory);
        // The device mirrors used.idx in RAM after every add_used, so at a
        // freeze boundary both must be equal.
        let used_idx = read_idx(self.used_ring + 2)?;
        if used_idx != self.next_used {
            return Err(PersistError::InvalidQueue(
                "used ring index differs from next_used",
            ));
        }
        // Unconsumed descriptors = avail.idx - next_avail in the u16 sequence
        // space; anything longer than the queue means the cursors do not
        // belong to these rings.
        let avail_idx = read_idx(self.avail_ring + 2)?;
        let pending = (Wrapping(avail_idx) - Wrapping(self.next_avail)).0;
        if pending > self.size {
            return Err(PersistError::InvalidQueue(
                "available ring cursor is behind next_avail by more than the queue size",
            ));
        }
        Ok(())
    }
}

/// State of a VirtioDevice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtioDeviceState {
    /// Device type.
    pub device_type: u32,
    /// Available virtio features.
    pub avail_features: u64,
    /// Negotiated virtio features.
    pub acked_features: u64,
    /// List of queues.
    pub queues: Vec<QueueState>,
    /// Flag for activated status.
    pub activated: bool,
}

impl VirtioDeviceState {
    /// Structural check only: type, feature subset, queue count/max size and
    /// event-index consistency. Usable before guest RAM exists.
    pub fn validate_structure(
        &self,
        expected_device_type: u32,
        expected_num_queues: usize,
        expected_queue_max_size: u16,
    ) -> Result<(), PersistError> {
        let uses_event_idx = (self.acked_features & (1u64 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        if self.device_type != expected_device_type
            || (self.acked_features & !self.avail_features) != 0
            || self.queues.len() != expected_num_queues
            || self
                .queues
                .iter()
                .any(|q| q.max_size != expected_queue_max_size)
            || self
                .queues
                .iter()
                .any(|q| q.event_idx_enabled != (self.activated && uses_event_idx))
        {
            return Err(PersistError::InvalidInput);
        }
        Ok(())
    }

    /// Full check: structure plus ring/range/cursor consistency against the
    /// loaded guest RAM; callers reconstruct queues through `to_queue`.
    pub fn validate(
        &self,
        mem: &GuestMemoryMmap,
        expected_device_type: u32,
        expected_num_queues: usize,
        expected_queue_max_size: u16,
    ) -> Result<(), PersistError> {
        self.validate_structure(expected_device_type, expected_num_queues, expected_queue_max_size)?;
        for queue in &self.queues {
            queue.validate(mem, self.activated)?;
        }
        Ok(())
    }
}

/// Transport information saved in a snapshot.
///
/// Selector registers (`features_select`, `acked_features_select`,
/// `queue_select`, `shm_region_select`) are arbitrary guest-written u32
/// values with safe transport fallbacks for unknown pages; they are
/// preserved verbatim and never range-checked here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmioTransportState {
    /// The register where feature bits are stored.
    pub features_select: u32,
    /// The register where the features page is selected.
    pub acked_features_select: u32,
    pub queue_select: u32,
    pub shm_region_select: u32,
    pub device_status: u32,
    pub config_generation: u32,
    pub interrupt_status: u32,
}

impl MmioTransportState {
    /// Only genuinely unreachable register contents are rejected: the device
    /// status must be a value the transport state machine can hold, and the
    /// interrupt status cannot hold bits the transport never sets.
    pub fn validate(&self) -> Result<(), PersistError> {
        const ACKNOWLEDGE: u32 = 0b0001;
        const DRIVER: u32 = 0b0010;
        const DRIVER_OK: u32 = 0b0100;
        const FEATURES_OK: u32 = 0b1000;
        const FAILED: u32 = 0b1000_0000;
        // Values, not or-patterns: each reachable status is the full
        // accumulated bitmask at that point of the state machine.
        let legal_status = matches!(
            self.device_status & !FAILED,
            0 | 0b0001 | 0b0011 | 0b1011 | 0b1111
        );
        if !legal_status
            || self.device_status & !(FAILED | ACKNOWLEDGE | DRIVER | DRIVER_OK | FEATURES_OK) != 0
            || self.interrupt_status > 0b11
        {
            return Err(PersistError::InvalidInput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test names include "snapshot" so `make snapshot-test` selects them.

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 128 * 1024)]).unwrap()
    }

    /// A valid activated QueueState whose cursors agree with the rings that
    /// `mem` actually holds; tests mutate copies to introduce defects.
    fn coherent(mem: &GuestMemoryMmap) -> QueueState {
        let state = QueueState {
            max_size: 256,
            size: 8,
            ready: true,
            desc_table: 0x1000,
            avail_ring: 0x2000,
            used_ring: 0x3000,
            next_avail: 0x1234,
            next_used: 0x1200,
            event_idx_enabled: false,
            num_added: 3,
        };
        mem.write_obj(state.next_avail, GuestAddress(state.avail_ring + 2))
            .unwrap();
        mem.write_obj(state.next_used, GuestAddress(state.used_ring + 2))
            .unwrap();
        state
    }

    #[test]
    fn queue_state_snapshot_roundtrip_preserves_cursors_and_event_idx() {
        let mem = memory();
        let mut state = coherent(&mem);
        state.event_idx_enabled = true;
        let queue = state.to_queue();
        assert_eq!(QueueState::from_queue(&queue), state);
        assert!(queue.is_event_idx_enabled());
        assert_eq!(queue.num_added.0, 3);
    }

    #[test]
    fn queue_state_snapshot_accepts_wrapped_cursors() {
        let mem = memory();
        // True wrap: the driver's avail.idx wrapped past 0xffff back to 3
        // while the device still owes everything up to 0xffff -> 4 pending.
        let mut state = coherent(&mem);
        state.next_avail = 0xffff;
        mem.write_obj(3u16, GuestAddress(state.avail_ring + 2))
            .unwrap();
        assert!(state.validate(&mem, true).is_ok());
        // Exactly a full queue of pending chains also wraps legally.
        state.next_avail = 0xfffc;
        assert!(state.validate(&mem, true).is_ok());
    }

    #[test]
    fn queue_state_snapshot_rejects_cursor_and_ring_inconsistency() {
        let mem = memory();
        // Saved next_used disagrees with the used ring index in guest RAM.
        let mut mismatch = coherent(&mem);
        mismatch.next_used += 1;
        assert!(matches!(
            mismatch.validate(&mem, true),
            Err(PersistError::InvalidQueue(
                "used ring index differs from next_used"
            ))
        ));
        // More unconsumed descriptors than the queue can hold.
        let mut behind = coherent(&mem);
        behind.size = 2;
        behind.next_avail = 0xfffc;
        // avail.idx stays at 0x1234 from coherent(): pending = 0x1234-0xfffc
        // wraps to 0x1238, far above the queue size.
        assert!(matches!(
            behind.validate(&mem, true),
            Err(PersistError::InvalidQueue(
                "available ring cursor is behind next_avail by more than the queue size"
            ))
        ));
        // Misaligned rings.
        let mut misaligned = coherent(&mem);
        misaligned.used_ring += 2;
        assert!(misaligned.validate(&mem, true).is_err());
        // Descriptor table crossing the end of guest memory.
        let mut out_of_range = coherent(&mem);
        out_of_range.size = 256;
        out_of_range.desc_table = 128 * 1024 - 16;
        assert!(out_of_range.validate(&mem, true).is_err());
        // Activated queues must be ready with a power-of-two size.
        let mut unready = coherent(&mem);
        unready.ready = false;
        assert!(unready.validate(&mem, true).is_err());
        let mut odd_size = coherent(&mem);
        odd_size.size = 7;
        assert!(odd_size.validate(&mem, true).is_err());
    }

    #[test]
    fn queue_state_snapshot_preserves_inactive_partial_configuration() {
        let mem = memory();
        // Partially negotiated queue: size selected, rings never written.
        let mut partial = coherent(&mem);
        partial.ready = false;
        partial.size = 0;
        partial.desc_table = u64::MAX;
        assert!(partial.validate(&mem, false).is_ok());
        // Structural bounds still apply to inactive queues.
        partial.size = 512;
        assert!(matches!(
            partial.validate(&mem, false),
            Err(PersistError::InvalidQueue(
                "queue size is not a valid power of two"
            ))
        ));
    }

    #[test]
    fn virtio_device_state_snapshot_checks_type_features_and_event_idx() {
        let mem = memory();
        let base = VirtioDeviceState {
            device_type: 2,
            avail_features: 0x1_0000_00ff,
            acked_features: 0x1,
            queues: vec![coherent(&mem)],
            activated: true,
        };
        assert!(base.validate(&mem, 2, 1, 256).is_ok());

        // Wrong device type, unrequested feature bits, queue count and
        // mismatching max size are all rejected.
        let mut wrong_type = base.clone();
        wrong_type.device_type = 3;
        assert!(matches!(
            wrong_type.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));
        let mut unrequested = base.clone();
        unrequested.acked_features |= 1 << 40;
        assert!(matches!(
            unrequested.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));
        let mut count = base.clone();
        count.queues.clear();
        assert!(matches!(
            count.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));
        let mut big = base.clone();
        big.queues[0].max_size = 512;
        assert!(matches!(
            big.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));

        // event_idx must match the negotiated feature bit on activated
        // devices (checked on the unmodified state, no normalization).
        let mut mismatch = base.clone();
        mismatch.acked_features |= 1 << VIRTIO_RING_F_EVENT_IDX;
        assert!(mismatch.validate(&mem, 2, 1, 256).is_ok());
        mismatch.queues[0].event_idx_enabled = !mismatch.queues[0].event_idx_enabled;
        assert!(matches!(
            mismatch.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));
        // Inactive queues never carry event_idx_enabled.
        let mut inactive = base;
        inactive.activated = false;
        inactive.acked_features |= 1 << VIRTIO_RING_F_EVENT_IDX;
        assert!(inactive.validate(&mem, 2, 1, 256).is_ok());
        inactive.queues[0].event_idx_enabled = true;
        assert!(matches!(
            inactive.validate(&mem, 2, 1, 256),
            Err(PersistError::InvalidInput)
        ));
    }

    #[test]
    fn mmio_transport_state_snapshot_validates_registers() {
        let state = |status: u32, interrupt: u32| MmioTransportState {
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            shm_region_select: 0,
            device_status: status,
            config_generation: 3,
            interrupt_status: interrupt,
        };
        assert!(state(0b1111, 0b11).validate().is_ok());
        assert!(state(0b1111 | 0b1000_0000, 0).validate().is_ok());
        // Individual bits or unreachable accumulations are not statuses the
        // transport state machine can hold.
        assert!(matches!(
            state(0b0110, 0).validate(),
            Err(PersistError::InvalidInput)
        ));
        assert!(matches!(
            state(0b0100, 0).validate(),
            Err(PersistError::InvalidInput)
        ));
        assert!(matches!(
            state(0b1000, 0).validate(),
            Err(PersistError::InvalidInput)
        ));
        assert!(matches!(
            state(0b1_0000, 0).validate(),
            Err(PersistError::InvalidInput)
        ));
        assert!(matches!(
            state(0b1111, 0b100).validate(),
            Err(PersistError::InvalidInput)
        ));
        // Guest-written selector registers are preserved, never rejected:
        // unknown pages and queue indices fall back safely inside MMIO.
        let mut selectors = state(0b1111, 0);
        selectors.features_select = u32::MAX;
        selectors.acked_features_select = 7;
        selectors.queue_select = 99;
        selectors.shm_region_select = 5;
        assert!(selectors.validate().is_ok());
    }
}
