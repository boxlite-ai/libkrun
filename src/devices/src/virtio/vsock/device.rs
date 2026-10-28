// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::descriptor_utils::Writer;
use super::super::persist::QueueState;
use super::super::queue::VIRTQ_DESC_F_NEXT;
use super::super::{
    ActivateError, ActivateResult, DescriptorChain, DeviceQueue, DeviceState, Queue as VirtQueue,
    QueueConfig, VirtioDevice,
};
use super::gate::VsockGate;
use super::muxer::VsockMuxer;
use super::packet::VsockPacket;
use super::TsiFlags;
use super::{defs, defs::uapi, VsockError};
use crate::virtio::InterruptTransport;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_F_IN_ORDER as u64)
    | (1 << uapi::VIRTIO_VSOCK_F_DGRAM);

/// Bytes of a `struct virtio_vsock_event` (one le32 id).
const EVENT_LEN: u32 = 4;

/// What a snapshot must carry about the guest's transport reset event
/// (virtio 1.2 §5.10.6.7); no host resource is part of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VsockResetState {
    /// The backend was stopped and the guest has not been sent
    /// `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` since: the backend stays closed
    /// until an event buffer takes the reset.
    pub pending: bool,
    /// Used entries (a delivered reset, an unusable event buffer, stale TX
    /// completed empty) whose interrupt has not been raised yet.
    pub interrupt_owed: bool,
}

pub struct Vsock {
    cid: u64,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Option<Arc<Mutex<VirtQueue>>>,
    pub(crate) queue_tx: Option<Arc<Mutex<VirtQueue>>>,
    /// Takes the transport reset event after a backend stop.
    queue_ev: Option<VirtQueue>,
    reset: VsockResetState,
    /// Written when an event-queue kick cannot reopen the backend; see
    /// `set_failure_notifier`.
    failure_notifier: Option<EventFd>,
    /// Runs right after a transport reset's used entry is published.
    #[cfg(test)]
    pub(crate) reset_published_hook: Option<Box<dyn FnMut() + Send>>,
    // Queue events are stored separately for event handling.
    pub(crate) queue_events: Vec<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM CID.
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> super::Result<Vsock> {
        Ok(Vsock {
            cid,
            muxer: VsockMuxer::new(cid, host_port_map, unix_ipc_port_map, tsi_flags),
            queue_rx: None,
            queue_tx: None,
            queue_ev: None,
            reset: VsockResetState::default(),
            failure_notifier: None,
            #[cfg(test)]
            reset_published_hook: None,
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// The gate an owner keeps to quiesce the Unix IPC backend without the
    /// device lock, which a blocked send can hold. Snapshots support only
    /// Unix IPC: refused when any TSI flag is enabled.
    pub fn snapshot_control(&self) -> super::Result<Arc<VsockGate>> {
        if self.muxer.tsi_flags().tsi_enabled() {
            return Err(VsockError::TsiEnabled);
        }
        Ok(self.muxer.gate().clone())
    }

    /// Write `notifier` once a reopen fails on an event-queue kick, where no
    /// caller can be told: the owner passes its exit notifier, so the
    /// failure stops the VM instead of leaving the guest running on a dead
    /// backend.
    pub fn set_failure_notifier(&mut self, notifier: EventFd) {
        self.failure_notifier = Some(notifier);
    }

    /// Stop the backend once the event thread no longer calls into this
    /// device: quiesce, join the muxer and reaper, then release every
    /// proxy, pending RX packet, guest RAM reference held by the backend and
    /// socket path it bound. Every connection is gone, so an activated
    /// device then completes the TX chains still in its ring with length 0
    /// (their interrupt is owed until `restart_backend`) and owes the guest
    /// a transport reset; the device stays activated with its queues.
    /// Idempotent, but once a worker panicked every stop still releases the
    /// backend and returns `BackendFailed`: the owner must not snapshot or
    /// resume the device.
    pub fn stop_backend(&mut self) -> super::Result<()> {
        self.muxer.stop()?;
        if self.is_activated() {
            self.discard_stale_tx()?;
            self.reset.pending = true;
        }
        Ok(())
    }

    /// End the hold of the owner's quiesce and reopen a stopped backend
    /// with the original configuration: write the pending transport reset
    /// into the next event buffer, complete every TX chain the guest queued
    /// before it could see the reset with length 0, publish the reset, raise
    /// the owed interrupt, then bind every original listening path, start
    /// the workers and notify the RX and TX queues. Without an event buffer the
    /// owed interrupt is still raised but the reset stays pending and the
    /// backend closed (TX stays in the ring) until the guest's next
    /// event-queue kick reopens it. A path that cannot bind fails the
    /// restart, names the path and leaves the backend stopped. A failed
    /// backend (a worker panicked) never restarts.
    pub fn restart_backend(&mut self) -> super::Result<()> {
        if self.muxer.has_failed() {
            return Err(VsockError::BackendFailed);
        }
        if self.muxer.is_running() {
            return Err(VsockError::BackendState("the backend is running"));
        }
        if !self.is_activated() {
            return Err(VsockError::BackendState("the device is not activated"));
        }
        self.muxer.gate().release();
        self.open_backend()
    }

    /// The transport reset state to save; stable while the backend is
    /// stopped and the event thread frozen.
    pub fn snapshot_reset_state(&self) -> VsockResetState {
        self.reset
    }

    /// Restore a saved transport reset state into a device that is not
    /// activated yet (a restore activates it afterwards with
    /// `activate_frozen`).
    pub fn restore_reset_state(&mut self, state: VsockResetState) -> super::Result<()> {
        if self.is_activated() {
            return Err(VsockError::BackendState("the device is activated"));
        }
        self.reset = state;
        Ok(())
    }

    /// RX, TX and event queue state of a device whose backend is stopped
    /// and whose event thread is frozen; `None` while inactive or running.
    pub fn snapshot_queue_states(&self) -> Option<Vec<QueueState>> {
        if self.muxer.is_running() {
            return None;
        }
        let rx = QueueState::from_queue(&self.queue_rx.as_ref()?.lock().unwrap());
        let tx = QueueState::from_queue(&self.queue_tx.as_ref()?.lock().unwrap());
        Some(vec![
            rx,
            tx,
            QueueState::from_queue(self.queue_ev.as_ref()?),
        ])
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        debug!("process_stream_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        debug!("process_rx before while");
        let queue_rx = self
            .queue_rx
            .as_ref()
            .expect("queue_rx should exist when activated");
        let mut queue_rx = queue_rx.lock().unwrap();
        while let Some(head) = queue_rx.pop(mem) {
            debug!("process_rx inside while");
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.muxer.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        queue_rx.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("RX queue error: {e:?}");
                    0
                }
            };

            debug!("process_rx: something to queue");
            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        debug!("process_stream_tx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let queue_tx = self
            .queue_tx
            .as_ref()
            .expect("queue_tx should exist when activated");
        let mut queue_tx = queue_tx.lock().unwrap();
        while let Some(head) = queue_tx.pop(mem) {
            // A quiesced backend leaves the rest of the ring to the next one.
            if !self.muxer.gate().is_open() {
                queue_tx.undo_pop();
                break;
            }
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("error reading TX packet: {e:?}");
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    continue;
                }
            };

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                debug!("process_stream_tx() is DGRAM");
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            } else {
                debug!("process_stream_tx() is STREAM");
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

impl Vsock {
    /// An event-queue kick reopens a backend whose reset waited for an
    /// event buffer, unless a pause holds the gate (its resume restarts the
    /// backend). Nobody can be told about a failure here: it marks the
    /// backend failed (sticky) and writes the failure notifier.
    pub(crate) fn process_evq(&mut self) {
        if !self.reset.pending || self.muxer.has_failed() || self.muxer.gate().is_held() {
            return;
        }
        if let Err(e) = self.open_backend() {
            error!("cannot reopen the vsock backend after a transport reset: {e:?}");
            self.muxer.mark_failed();
            if let Some(notifier) = &self.failure_notifier {
                if let Err(e) = notifier.write(1) {
                    error!("cannot signal the vsock backend failure: {e:?}");
                }
            }
        }
    }

    /// Deliver a pending reset, complete the TX queued before the guest
    /// could see it, raise the owed interrupt, then start the backend. The
    /// stale TX completes after the event is written but before its used
    /// entry is published: every chain it drops was queued before the guest
    /// could see the reset, and one queued afterwards reaches the new
    /// backend instead of being dropped.
    fn open_backend(&mut self) -> super::Result<()> {
        if self.reset.pending {
            let Some(head) = self.write_reset_event()? else {
                return self.signal_owed_interrupt();
            };
            if let Err(e) = self.discard_stale_tx() {
                // Unpublished: the guest still owns the event buffer.
                self.queue_ev
                    .as_mut()
                    .expect("activated vsock has an event queue")
                    .undo_pop();
                return Err(e);
            }
            self.publish_reset(head)?;
        }
        self.signal_owed_interrupt()?;
        self.start_backend(true)?;
        for index in [RXQ_INDEX, TXQ_INDEX] {
            if let Err(e) = self.queue_events[index].write(1) {
                error!("failed to notify vsock queue {index}: {e:?}");
            }
        }
        Ok(())
    }

    /// Write the reset event (le32 id 0) into the next usable event buffer
    /// the guest offered and return its head, not yet published. Every
    /// unusable buffer before it (see `event_writer`) completes with length
    /// 0. A head the queue cannot pop (an invalid index) ends the search and
    /// leaves the reset pending.
    fn write_reset_event(&mut self) -> super::Result<Option<u16>> {
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return Err(VsockError::BackendState("the device is not activated"));
        };
        let queue = self
            .queue_ev
            .as_mut()
            .expect("activated vsock has an event queue");
        while let Some(head) = queue.pop(mem) {
            let index = head.index;
            let event = uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.to_le();
            if let Some(mut writer) = event_writer(mem, head) {
                if writer.write_obj(event).is_ok() {
                    return Ok(Some(index));
                }
            }
            warn!("vsock event buffer {index} cannot take an event");
            queue.add_used(mem, index, 0).map_err(VsockError::Queue)?;
            self.reset.interrupt_owed = true;
        }
        Ok(None)
    }

    /// Complete the event buffer `write_reset_event` filled: from here on
    /// the guest can see the reset, so the reset is no longer pending.
    fn publish_reset(&mut self, head: u16) -> super::Result<()> {
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return Err(VsockError::BackendState("the device is not activated"));
        };
        self.queue_ev
            .as_mut()
            .expect("activated vsock has an event queue")
            .add_used(mem, head, EVENT_LEN)
            .map_err(VsockError::Queue)?;
        self.reset.interrupt_owed = true;
        self.reset.pending = false;
        #[cfg(test)]
        if let Some(hook) = self.reset_published_hook.as_mut() {
            hook();
        }
        Ok(())
    }

    /// Complete every TX chain in the ring with length 0, reading only the
    /// avail ring: the packets belong to connections that no longer exist.
    fn discard_stale_tx(&mut self) -> super::Result<()> {
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return Ok(());
        };
        let queue_tx = self
            .queue_tx
            .as_ref()
            .expect("activated vsock has a TX queue");
        let discarded = queue_tx
            .lock()
            .unwrap()
            .discard_available(mem)
            .map_err(VsockError::Queue)?;
        if discarded > 0 {
            self.reset.interrupt_owed = true;
        }
        Ok(())
    }

    fn signal_owed_interrupt(&mut self) -> super::Result<()> {
        if !self.reset.interrupt_owed {
            return Ok(());
        }
        let DeviceState::Activated(_, interrupt) = &self.device_state else {
            return Err(VsockError::BackendState("the device is not activated"));
        };
        interrupt
            .try_signal_used_queue()
            .map_err(VsockError::Interrupt)?;
        self.reset.interrupt_owed = false;
        Ok(())
    }

    fn start_backend(&mut self, require_listeners: bool) -> super::Result<()> {
        let DeviceState::Activated(mem, interrupt) = &self.device_state else {
            return Err(VsockError::BackendState("the device is not activated"));
        };
        let queue_rx = self
            .queue_rx
            .clone()
            .expect("activated vsock has an RX queue");
        self.muxer
            .start(mem.clone(), queue_rx, interrupt.clone(), require_listeners)
            .map_err(VsockError::Backend)
    }

    fn activate_impl(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
        start_backend: bool,
    ) -> ActivateResult {
        let [rx, tx, ev]: [DeviceQueue; defs::NUM_QUEUES] =
            queues.try_into().map_err(|q: Vec<_>| {
                error!(
                    "Cannot perform activate. Expected {} queue(s), got {}",
                    defs::NUM_QUEUES,
                    q.len()
                );
                ActivateError::BadActivate
            })?;

        // Store queue events for event handling.
        self.queue_events = vec![rx.event, tx.event, ev.event];
        self.queue_rx = Some(Arc::new(Mutex::new(rx.queue)));
        self.queue_tx = Some(Arc::new(Mutex::new(tx.queue)));
        self.queue_ev = Some(ev.queue);
        self.device_state = DeviceState::Activated(mem, interrupt);

        let started = if start_backend {
            self.start_backend(false)
        } else {
            Ok(())
        };
        if let Err(e) = started {
            error!("Cannot start the vsock backend: {e:?}");
        } else if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
        } else {
            return Ok(());
        }
        // Undo the partial activation, releasing every thread and RAM reference.
        if let Err(e) = self.muxer.stop() {
            error!("Cannot stop the vsock backend: {e:?}");
        }
        self.queue_rx = None;
        self.queue_tx = None;
        self.queue_ev = None;
        self.device_state = DeviceState::Inactive;
        Err(ActivateError::BadActivate)
    }
}

/// A writer over an event buffer that can take the event: every descriptor
/// of its chain is device-writable, every NEXT link leads to a valid
/// descriptor within the queue's chain limit (no invalid tail or cycle),
/// every declared range lies in guest RAM, and the ranges total at least
/// four bytes, scattered or not.
fn event_writer<'m>(mem: &'m GuestMemoryMmap, head: DescriptorChain<'m>) -> Option<Writer<'m>> {
    let mut desc = head.clone();
    while desc.is_write_only() {
        if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
            // Checks each descriptor's whole range.
            let writer = Writer::new(mem, head).ok()?;
            return (writer.available_bytes() >= EVENT_LEN as usize).then_some(writer);
        }
        desc = desc.next_descriptor()?;
    }
    None
}

impl VirtioDevice for Vsock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn device_name(&self) -> &str {
        "vsock"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate_impl(mem, interrupt, queues, true)
    }

    /// Activate with the backend stopped, for a restore: `restart_backend`
    /// starts it. Refused when TSI is enabled, like `snapshot_control`.
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.muxer.tsi_flags().tsi_enabled() {
            error!("vsock snapshots do not support TSI");
            return Err(ActivateError::BadActivate);
        }
        self.activate_impl(mem, interrupt, queues, false)
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
