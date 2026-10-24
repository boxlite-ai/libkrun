// SPDX-License-Identifier: Apache-2.0

//! The owner's explicit pause/resume lifecycle. `pause` quiesces the vsock
//! gate (cancelling a send blocked under the vsock device lock, which a
//! vCPU's MMIO access could wait for) before it stops every vCPU, then
//! freezes every device writer (disks, the NIC, the virtio-fs workers, then
//! the event thread with RNG, balloon, vsock and console control queues and
//! UART input, then the console's port workers), stops the vsock backend
//! and drains every irqfd; the frozen
//! worker queue cursors and the drained irqfd count stay in `Paused` until
//! `resume`, so any number of exports capture the same cut. An import ends
//! in the same paused state, and both take one resume path: reattach the
//! irqfds, resume every device, then every vCPU last.
//!
//! Lifecycle control is all-or-nothing: a pause or resume that fails or
//! cannot be confirmed disables the owner and stops and joins every thread,
//! so no guest or device execution is left partially running.
//!
//! The declaration that every host writer of the virtio-fs shares stopped
//! (`declare_host_writers_stopped`) survives a pause and ends with resume
//! or disable.
//!
//! A failed DAX window remapping ends guest execution on its own (see
//! `execution`); the next pause, resume, export or declaration disables
//! the owner, joining every thread, and fails. A pause also fails when one
//! failed before the workers froze, and a resume when one failed while the
//! devices resumed (a resumed worker may run queued DAX requests), before
//! any vCPU resumes, and again before it reports success.

#[cfg(test)]
use std::cell::Cell;

use devices::virtio::persist::QueueState;

use super::{console, virtio_fs, vsock, wiring};
use super::{Control, Error, RamSnapshotVm, Result, CONTROL_TIMEOUT};

#[cfg(feature = "blk")]
use super::blk;
#[cfg(all(feature = "blk", feature = "net"))]
use super::nic;

#[cfg(test)]
thread_local! {
    /// Fail the execution barrier once the devices resumed, as a resumed
    /// worker's queued DAX request whose host call fails does.
    pub(super) static FAIL_REMAPPING_ON_RESUME: Cell<bool> = const { Cell::new(false) };
}

/// What a confirmed pause holds until resume.
pub(super) struct Paused {
    /// The frozen worker queue per disk (None when inactive).
    #[cfg(feature = "blk")]
    pub(super) disks: Vec<Option<QueueState>>,
    /// The frozen NIC worker's cursors (None when inactive or absent).
    #[cfg(all(feature = "blk", feature = "net"))]
    pub(super) nic: Option<devices::virtio::net::NetQueueStates>,
    /// The frozen worker's queues per virtio-fs share (None when inactive).
    pub(super) fs: Vec<Option<Vec<QueueState>>>,
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
        self.check_execution()?;
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
        self.check_execution()?;
        let drained = match &self.pause {
            Some(paused) if !self.control.unusable => paused.drained_irqfds,
            _ => return Err(Error::Invalid("resume requires a paused usable VM")),
        };
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        // Host writers may run again once anything in the guest does.
        self.host_writers_stopped = false;
        let resumed = wiring::reassign_irqfds(self, drained)
            .and_then(|()| self.resume_devices())
            .and_then(|()| self.execution_intact())
            .and_then(|()| Control::transition(&self.handles, false, CONTROL_TIMEOUT))
            .and_then(|()| self.execution_intact());
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

    /// Freeze every device writer behind paused vCPUs (a virtio-fs share
    /// that lost its DAX window fails it; the console's port workers after
    /// the event thread), stop the vsock
    /// backend (its connections close, stale TX completes empty and a
    /// transport reset is owed) and drain every irqfd. Each step is
    /// idempotent, so an import uses it on its frozen-started devices to
    /// reach the same state as a paused source.
    pub(super) fn quiesce(&self) -> Result<Paused> {
        #[cfg(feature = "blk")]
        let disks = blk::freeze_disks(self)?;
        #[cfg(all(feature = "blk", feature = "net"))]
        let nic = nic::freeze(self)?;
        let fs = virtio_fs::freeze(&self.fs)?;
        if let Some(events) = &self.events {
            events.freeze()?;
        }
        // After the event thread: no control-queue callback runs anymore.
        console::freeze(self)?;
        // A frozen event thread leaves an exit unread; either form aborts.
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        // No worker remaps a window anymore; one may have failed before.
        self.execution_intact()?;
        vsock::stop(self)?;
        let drained_irqfds = wiring::drain_irqfds(self)?;
        Ok(Paused {
            #[cfg(feature = "blk")]
            disks,
            #[cfg(all(feature = "blk", feature = "net"))]
            nic,
            fs,
            drained_irqfds,
        })
    }

    /// Resume every device (disks, the NIC, the virtio-fs workers, the
    /// vsock backend, which delivers its reset first, the console's port
    /// workers and control queues, then the event thread); one failure does
    /// not skip the rest.
    fn resume_devices(&self) -> Result<()> {
        let mut results = Vec::new();
        #[cfg(feature = "blk")]
        results.push(blk::resume_devices(self));
        #[cfg(all(feature = "blk", feature = "net"))]
        results.push(nic::resume(self));
        results.push(virtio_fs::resume(&self.fs));
        results.push(vsock::resume(self));
        // Workers and control queues first: the event thread then sees a
        // live console.
        results.push(console::resume(self));
        if let Some(events) = &self.events {
            results.push(events.resume());
        }
        #[cfg(test)]
        if FAIL_REMAPPING_ON_RESUME.with(Cell::take) {
            use devices::virtio::fs::passthrough::DaxMappingControl;
            self.execution.exclusive(&mut || false);
        }
        results.into_iter().find(Result::is_err).unwrap_or(Ok(()))
    }

    /// Fails once a DAX window remapping failed: guest execution ended.
    fn execution_intact(&self) -> Result<()> {
        if self.execution.failed() {
            return Err(Error::Invalid(
                "a DAX window remapping failed; guest execution ended",
            ));
        }
        Ok(())
    }

    /// A failed DAX window remapping ended guest execution for good:
    /// disable the owner and fail.
    pub(super) fn check_execution(&mut self) -> Result<()> {
        let intact = self.execution_intact();
        if intact.is_err() {
            self.disable();
        }
        intact
    }

    /// Lifecycle control failed or is uncertain: accept no further
    /// snapshot, pause or resume, and stop and join every thread.
    pub(super) fn disable(&mut self) {
        self.control.unusable = true;
        self.host_writers_stopped = false;
        self.stop_threads();
    }
}
