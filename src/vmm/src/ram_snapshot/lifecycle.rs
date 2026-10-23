// SPDX-License-Identifier: Apache-2.0

//! The owner's explicit pause/resume lifecycle. `pause` quiesces the vsock
//! gate (cancelling a send blocked under the vsock device lock, which a
//! vCPU's MMIO access could wait for) before it stops every vCPU, then
//! freezes every device writer (disks, the NIC, then the event thread with
//! RNG, balloon, vsock queues and UART input), stops the vsock backend and
//! drains every irqfd; the frozen
//! worker queue cursors and the drained irqfd count stay in `Paused` until
//! `resume`, so any number of exports capture the same cut. An import ends
//! in the same paused state, and both take one resume path: reattach the
//! irqfds, resume every device, then every vCPU last.
//!
//! Lifecycle control is all-or-nothing: a pause or resume that fails or
//! cannot be confirmed disables the owner and stops and joins every thread,
//! so no guest or device execution is left partially running.

#[cfg(feature = "blk")]
use devices::virtio::persist::QueueState;

use super::{vsock, wiring};
use super::{Control, Error, RamSnapshotVm, Result, CONTROL_TIMEOUT};

#[cfg(feature = "blk")]
use super::blk;
#[cfg(all(feature = "blk", feature = "net"))]
use super::nic;

/// What a confirmed pause holds until resume.
pub(super) struct Paused {
    /// The frozen worker queue per disk (None when inactive).
    #[cfg(feature = "blk")]
    pub(super) disks: Vec<Option<QueueState>>,
    /// The frozen NIC worker's cursors (None when inactive or absent).
    #[cfg(all(feature = "blk", feature = "net"))]
    pub(super) nic: Option<devices::virtio::net::NetQueueStates>,
    /// Deassigned irqfds, in `wiring` order; resume reassigns exactly these.
    drained_irqfds: usize,
}

impl RamSnapshotVm {
    /// Quiesce the vsock gate, pause and acknowledge every vCPU, then freeze
    /// every device and drain every irqfd. Nothing runs afterwards until `resume`; RAM, devices and
    /// irqchip stay at one cut. Rejected without any effect when the owner
    /// is not running and usable or is exiting; any later
    /// failure, including an exit found at the freeze boundary, disables
    /// the owner and stops every thread.
    pub(crate) fn pause(&mut self) -> Result<()> {
        if self.control.unusable
            || self.handles.is_empty()
            || self.pause.is_some()
            || !self.irqchip_ready
        {
            return Err(Error::Invalid("pause requires a running usable VM"));
        }
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        let paused = if self
            .handles
            .iter()
            .any(|h| !h.response_receiver().is_empty())
        {
            Err(Error::Invalid("unconsumed vCPU response before pause"))
        } else {
            // Before waiting for any acknowledgment; see the module comment.
            vsock::quiesce_gate(self);
            Control::transition(&self.handles, true, CONTROL_TIMEOUT)
        }
        .and_then(|()| self.quiesce());
        match paused {
            Ok(paused) => {
                self.pause = Some(paused);
                Ok(())
            }
            Err(error) => {
                self.disable();
                Err(error)
            }
        }
    }

    /// Reattach the drained irqfds (so resumed devices cannot signal an
    /// unregistered eventfd), resume every device (each actively
    /// re-examines its queues, so drained notifications cannot hang), then
    /// every vCPU. Shared by a paused source and an import. Any failure
    /// disables the owner and stops every thread; no vCPU runs unless every
    /// device resumed.
    pub(crate) fn resume(&mut self) -> Result<()> {
        let drained = match &self.pause {
            Some(paused) if !self.control.unusable => paused.drained_irqfds,
            _ => return Err(Error::Invalid("resume requires a paused usable VM")),
        };
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        let resumed = wiring::reassign_irqfds(self, drained)
            .and_then(|()| self.resume_devices())
            .and_then(|()| Control::transition(&self.handles, false, CONTROL_TIMEOUT));
        if let Err(error) = resumed {
            self.disable();
            return Err(error);
        }
        self.pause = None;
        Ok(())
    }

    /// Whether a confirmed pause holds the owner.
    #[cfg(test)]
    pub(super) fn is_paused(&self) -> bool {
        self.pause.is_some()
    }

    /// Freeze every device writer behind paused vCPUs, stop the vsock
    /// backend (its connections close, stale TX completes empty and a
    /// transport reset is owed) and drain every irqfd. Each step is
    /// idempotent, so an import uses it on its frozen-started devices to
    /// reach the same state as a paused source.
    pub(super) fn quiesce(&self) -> Result<Paused> {
        #[cfg(feature = "blk")]
        let disks = blk::freeze_disks(self)?;
        #[cfg(all(feature = "blk", feature = "net"))]
        let nic = nic::freeze(self)?;
        if let Some(events) = &self.events {
            events.freeze()?;
        }
        // A frozen event thread leaves an exit unread; either form aborts.
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        vsock::stop(self)?;
        let drained_irqfds = wiring::drain_irqfds(self)?;
        Ok(Paused {
            #[cfg(feature = "blk")]
            disks,
            #[cfg(all(feature = "blk", feature = "net"))]
            nic,
            drained_irqfds,
        })
    }

    /// Resume every device (disks, the NIC, the vsock backend, which
    /// delivers its reset first, then the event thread); one failure does
    /// not skip the rest.
    fn resume_devices(&self) -> Result<()> {
        let mut results = Vec::new();
        #[cfg(feature = "blk")]
        results.push(blk::resume_devices(self));
        #[cfg(all(feature = "blk", feature = "net"))]
        results.push(nic::resume(self));
        results.push(vsock::resume(self));
        if let Some(events) = &self.events {
            results.push(events.resume());
        }
        results.into_iter().find(Result::is_err).unwrap_or(Ok(()))
    }

    /// Lifecycle control failed or is uncertain: accept no further
    /// snapshot, pause or resume, and stop and join every thread.
    pub(super) fn disable(&mut self) {
        self.control.unusable = true;
        self.stop_threads();
    }
}
