// SPDX-License-Identifier: Apache-2.0

//! Device-layer state only; callers must stop guest and host RAM writers before capture.
//! These types are not a versioned on-disk format and do not freeze any device.

use std::io::{self, ErrorKind};
use std::num::Wrapping;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use super::{Queue, VirtioDevice};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

pub(crate) fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, reason)
}

/// Queue registers plus host cursors absent from the RAM image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueState {
    pub max_size: u16,
    pub size: u16,
    pub ready: bool,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
    pub next_avail: u16,
    pub next_used: u16,
    pub event_idx_enabled: bool,
    pub num_added: u16,
}

impl Queue {
    /// Capture against quiesced RAM. `activated` describes the owning device,
    /// not QueueReady: a guest can set QueueReady before finishing negotiation.
    pub fn save_state(&self, mem: &GuestMemoryMmap, activated: bool) -> io::Result<QueueState> {
        let state = QueueState {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: self.desc_table.raw_value(),
            avail_ring: self.avail_ring.raw_value(),
            used_ring: self.used_ring.raw_value(),
            next_avail: self.next_avail.0,
            next_used: self.next_used.0,
            event_idx_enabled: self.event_idx_enabled,
            num_added: self.num_added.0,
        };
        state.validate(mem, self.max_size, activated)?;
        Ok(state)
    }
}

impl QueueState {
    fn queue(&self) -> Queue {
        Queue {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: GuestAddress(self.desc_table),
            avail_ring: GuestAddress(self.avail_ring),
            used_ring: GuestAddress(self.used_ring),
            next_avail: Wrapping(self.next_avail),
            next_used: Wrapping(self.next_used),
            event_idx_enabled: self.event_idx_enabled,
            num_added: Wrapping(self.num_added),
        }
    }

    pub fn validate(
        &self,
        mem: &GuestMemoryMmap,
        max_size: u16,
        activated: bool,
    ) -> io::Result<()> {
        if self.max_size != max_size {
            return Err(invalid("queue capacity differs from destination"));
        }
        if !activated || !self.ready {
            if self.next_avail != 0 || self.next_used != 0 || self.num_added != 0 {
                return Err(invalid("unused queue has processing cursors"));
            }
            // Preserve arbitrary guest-written sizes and addresses during negotiation.
            return Ok(());
        }
        if self.size > 32768 || !self.queue().is_valid(mem) {
            return Err(invalid("invalid active queue layout"));
        }
        let avail: u16 = mem
            .read_obj(GuestAddress(self.avail_ring + 2))
            .map_err(io::Error::other)?;
        let used: u16 = mem
            .read_obj(GuestAddress(self.used_ring + 2))
            .map_err(io::Error::other)?;
        let pending = avail.wrapping_sub(self.next_avail);
        let in_flight = self.next_avail.wrapping_sub(self.next_used);
        if used != self.next_used
            || u32::from(pending) + u32::from(in_flight) > u32::from(self.size)
        {
            return Err(invalid("queue cursors disagree with RAM"));
        }
        // num_added is a wrapping notification accumulator, not an in-flight count;
        // it may exceed queue size when notifications have not been checked.
        Ok(())
    }

    /// Reconstruct without touching rings. In-flight descriptor chains, if any,
    /// remain the device's responsibility and must be restored separately.
    pub fn restore(
        &self,
        mem: &GuestMemoryMmap,
        max_size: u16,
        activated: bool,
    ) -> io::Result<Queue> {
        self.validate(mem, max_size, activated)?;
        Ok(self.queue())
    }
}

/// Common device identity and negotiation state. Device-specific state and worker
/// activation are owned by each device's restore implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioDeviceState {
    pub device_type: u32,
    pub avail_features: u64,
    pub acked_features: u64,
    pub activated: bool,
    pub queue_max_sizes: Vec<u16>,
}

impl VirtioDeviceState {
    pub fn save(device: &dyn VirtioDevice) -> io::Result<Self> {
        let state = Self {
            device_type: device.device_type(),
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            activated: device.is_activated(),
            queue_max_sizes: device.queue_config().iter().map(|q| q.size).collect(),
        };
        state.validate(device)?;
        Ok(state)
    }

    pub fn validate(&self, device: &dyn VirtioDevice) -> io::Result<()> {
        if self.device_type != device.device_type()
            || self.avail_features != device.avail_features()
            || self.acked_features & !self.avail_features != 0
            || !self
                .queue_max_sizes
                .iter()
                .copied()
                .eq(device.queue_config().iter().map(|q| q.size))
        {
            return Err(invalid("incompatible virtio device"));
        }
        Ok(())
    }

    /// Apply negotiation before device-specific frozen activation. This never
    /// calls activate(), starts workers, or changes the destination's lifecycle.
    pub fn restore_features(&self, device: &mut dyn VirtioDevice) -> io::Result<()> {
        self.validate(device)?;
        if device.is_activated() {
            return Err(invalid("cannot restore features on an active device"));
        }
        device.set_acked_features(self.acked_features);
        Ok(())
    }

    /// Validate and reconstruct a device's queues, including EVENT_IDX agreement.
    pub fn restore_queues(
        &self,
        states: &[QueueState],
        mem: &GuestMemoryMmap,
    ) -> io::Result<Vec<Queue>> {
        if states.len() != self.queue_max_sizes.len() {
            return Err(invalid("queue count differs from device"));
        }
        let event_idx = self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX) != 0;
        states
            .iter()
            .zip(&self.queue_max_sizes)
            .map(|(state, max)| {
                if self.activated && state.event_idx_enabled != event_idx {
                    return Err(invalid("queue EVENT_IDX differs from negotiated features"));
                }
                state.restore(mem, *max, self.activated)
            })
            .collect()
    }
}

/// MMIO registers plus queues still owned by an inactive transport. Active
/// queues belong to device workers and must be captured separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmioTransportState {
    pub device: VirtioDeviceState,
    pub features_select: u32,
    pub acked_features_select: u32,
    pub queue_select: u32,
    pub device_status: u32,
    pub config_generation: u32,
    pub shm_region_select: u32,
    pub interrupt_status: u32,
    pub queues: Option<Vec<QueueState>>,
}

#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;
