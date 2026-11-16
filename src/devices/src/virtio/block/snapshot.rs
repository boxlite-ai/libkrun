// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vm_memory::ByteValued;

use super::Block;
use crate::virtio::control::{Command, WorkerControl};
use crate::virtio::persist::{invalid, QueueState, VirtioDeviceState};
use crate::virtio::VirtioDevice;

/// The application supplies a matching disk image saved while the VM is paused.
/// This state preserves the guest-visible disk ID,
/// which must not change when the new backing file has a different host inode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockState {
    pub device: VirtioDeviceState,
    pub queue: Option<QueueState>,
    pub config: Vec<u8>,
    pub disk_id: Vec<u8>,
}

pub(super) struct WorkerCheckpoint {
    pub control: WorkerControl,
    pub queue: Arc<Mutex<Option<QueueState>>>,
    pub frozen: bool,
}

impl Block {
    /// End a worker after a failed/uncertain request. A timeout retains the join
    /// handle and its resources; the owner must keep the VM stopped and retry.
    pub fn stop_worker(&mut self, deadline: Instant) -> io::Result<()> {
        self.snapshot_failed = true;
        if let Some(worker) = &self.worker_thread {
            self.worker_stopfd.write(1)?;
            while !worker.is_finished() {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "block worker still owns I/O",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        if let Some(worker) = self.worker_thread.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("block worker panicked"))?;
        }
        self.worker_control = None;
        Ok(())
    }

    /// Stop dequeueing, finish the current synchronous request and sync backing
    /// storage before acknowledging. All vCPUs/other RAM writers must already
    /// be stopped. A failure poisons snapshot control until worker teardown.
    pub fn freeze(&mut self, deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "block freeze deadline elapsed",
            ));
        }
        if self.snapshot_failed {
            return Err(invalid("block snapshot control requires teardown"));
        }
        if self.frozen {
            return Ok(());
        }
        self.snapshot_failed = true;
        if let Some(control) = &mut self.worker_control {
            control
                .request(Command::Freeze, deadline)
                .map_err(io::Error::other)?;
        } else {
            let disk = self.disk_image.lock().unwrap();
            disk.flush()?;
            disk.sync()?;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "block freeze deadline elapsed",
            ));
        }
        self.frozen = true;
        self.snapshot_failed = false;
        Ok(())
    }

    pub fn save_state(&self) -> io::Result<BlockState> {
        if !self.frozen || self.snapshot_failed {
            return Err(invalid("block capture requires confirmed freeze"));
        }
        let queue = self.snapshot_queue.lock().unwrap().clone();
        if self.is_activated() != queue.is_some() {
            return Err(invalid("block queue was not captured"));
        }
        Ok(BlockState {
            device: VirtioDeviceState::save(self)?,
            queue,
            config: self.config.as_slice().to_vec(),
            disk_id: self.disk_image_id.clone(),
        })
    }

    /// Prepare an inactive destination to activate frozen. Restore its queue
    /// using device.restore_queues() against accessible restored RAM, and pass
    /// the result and fresh eventfd to activate(). No I/O runs until resume().
    pub fn restore_state(&mut self, state: &BlockState) -> io::Result<()> {
        state.device.validate(self)?;
        if self.is_activated()
            || self.worker_thread.is_some()
            || self.snapshot_failed
            || state.config != self.config.as_slice()
            || state.disk_id.len() != virtio_bindings::virtio_blk::VIRTIO_BLK_ID_BYTES as usize
            || state.device.activated != state.queue.is_some()
        {
            return Err(invalid("incompatible block snapshot or destination"));
        }
        if state
            .queue
            .as_ref()
            .is_some_and(|q| q.next_avail != q.next_used)
        {
            return Err(invalid("block snapshot has unfinished I/O"));
        }
        state.device.restore_features(self)?;
        self.disk_image_id.clone_from(&state.disk_id);
        // The constructor's DiskProperties derived an ID from the new host
        // inode. Recreate it at activation with the saved guest-visible ID.
        self.disk = None;
        *self.snapshot_queue.lock().unwrap() = state.queue.clone();
        self.frozen = true;
        Ok(())
    }

    pub fn resume(&mut self, deadline: Instant) -> io::Result<()> {
        if !self.frozen || self.snapshot_failed {
            return Err(invalid("block resume requires confirmed freeze"));
        }
        self.snapshot_failed = true;
        if let Some(control) = &mut self.worker_control {
            control
                .request(Command::Resume, deadline)
                .map_err(io::Error::other)?;
        } else if self.snapshot_queue.lock().unwrap().is_some() {
            return Err(invalid("restored block worker has not been activated"));
        }
        self.frozen = false;
        self.snapshot_failed = false;
        *self.snapshot_queue.lock().unwrap() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
