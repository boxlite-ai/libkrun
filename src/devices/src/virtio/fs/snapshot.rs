// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::passthrough::checkpoint::FsState;
use super::Fs;
use crate::virtio::control::{Command, WorkerControl};
use crate::virtio::persist::{invalid, QueueState, VirtioDeviceState};
use crate::virtio::VirtioDevice;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsDeviceState {
    pub device: VirtioDeviceState,
    pub tag: String,
    pub read_only: bool,
    pub retired_root: bool,
    pub worker: Option<FsWorkerState>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsWorkerState {
    pub queues: Vec<QueueState>,
    pub filesystem: FsState,
    pub options: u64,
}

pub(super) struct WorkerCheckpoint {
    pub control: WorkerControl,
    pub state: Arc<Mutex<Option<FsWorkerState>>>,
    pub frozen: bool,
    pub restore: Option<FsWorkerState>,
}

impl Fs {
    pub fn freeze(&mut self, deadline: Instant) -> io::Result<()> {
        if self.shm_region.is_some() {
            return Err(invalid(
                "checkpoint requires virtio-fs without a DAX window",
            ));
        }
        if self.snapshot_failed {
            return Err(invalid("fs checkpoint requires teardown"));
        }
        if self.frozen {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        self.snapshot_failed = true;
        if let Some(control) = &mut self.worker_control {
            control
                .request(Command::Freeze, deadline)
                .map_err(io::Error::other)?;
        }
        self.frozen = true;
        self.snapshot_failed = false;
        Ok(())
    }

    pub fn save_state(&self) -> io::Result<FsDeviceState> {
        if !self.frozen || self.snapshot_failed {
            return Err(invalid("fs capture requires confirmed freeze"));
        }
        let worker = self.snapshot_worker.lock().unwrap().clone();
        if self.is_activated() != worker.is_some() {
            return Err(invalid("fs worker was not captured"));
        }
        Ok(FsDeviceState {
            device: VirtioDeviceState::save(self)?,
            tag: self.tag().into(),
            read_only: self.read_only,
            retired_root: self.snapshot_retired_root
                || (self.passthrough_cfg.allow_root_dir_delete
                    && std::fs::metadata(&self.passthrough_cfg.root_dir)
                        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)),
            worker,
        })
    }

    pub fn restore_state(&mut self, state: &FsDeviceState) -> io::Result<()> {
        state.device.validate(self)?;
        if self.is_activated()
            || self.worker_thread.is_some()
            || self.snapshot_failed
            || self.shm_region.is_some()
            || state.tag != self.tag()
            || state.read_only != self.read_only
            || state.worker.is_some() != state.device.activated
        {
            return Err(invalid("incompatible fs checkpoint or destination"));
        }
        if let Some(worker) = &state.worker {
            worker.filesystem.validate()?;
            if state.retired_root
                && (worker
                    .filesystem
                    .inodes
                    .iter()
                    .any(|i| i.object.path.is_some())
                    || worker
                        .filesystem
                        .handles
                        .iter()
                        .any(|h| h.object.path.is_some()))
            {
                return Err(invalid("retired bootstrap root contains live host objects"));
            }
            if worker.queues.len() != super::defs::NUM_QUEUES
                || worker.queues.iter().any(|q| q.next_avail != q.next_used)
            {
                return Err(invalid("fs checkpoint contains unfinished requests"));
            }
        }
        state.device.restore_features(self)?;
        *self.snapshot_worker.lock().unwrap() = state.worker.clone();
        self.restore_worker = state.worker.clone();
        self.snapshot_retired_root = state.retired_root;
        self.frozen = true;
        Ok(())
    }

    pub fn resume(&mut self, deadline: Instant) -> io::Result<()> {
        if !self.frozen || self.snapshot_failed {
            return Err(invalid("fs resume requires confirmed freeze"));
        }
        self.snapshot_failed = true;
        if let Some(control) = &mut self.worker_control {
            control
                .request(Command::Resume, deadline)
                .map_err(io::Error::other)?;
        } else if self.restore_worker.is_some() {
            return Err(invalid("restored fs worker has not been activated"));
        }
        self.frozen = false;
        self.snapshot_failed = false;
        *self.snapshot_worker.lock().unwrap() = None;
        Ok(())
    }

    pub fn stop_worker(&mut self, deadline: Instant) -> io::Result<()> {
        self.snapshot_failed = true;
        if let Some(worker) = &self.worker_thread {
            self.worker_stopfd.write(1)?;
            while !worker.is_finished() {
                if Instant::now() >= deadline {
                    return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        if let Some(worker) = self.worker_thread.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("fs worker panicked"))?;
        }
        self.worker_control = None;
        Ok(())
    }
}
