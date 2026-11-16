use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, FsError, QueueConfig, VirtioDevice,
    VirtioShmRegion,
};
use super::passthrough;

use super::snapshot::{FsWorkerState, WorkerCheckpoint};
use super::worker::FsWorker;
use super::ExportTable;
use super::{defs, defs::uapi};

use crate::virtio::control::{self, WorkerController};
use crate::virtio::InterruptTransport;

use std::sync::Mutex;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    pub(super) shm_region: Option<VirtioShmRegion>,
    pub(super) passthrough_cfg: passthrough::Config,
    pub(super) read_only: bool,
    pub(super) worker_thread: Option<JoinHandle<()>>,
    pub(super) worker_stopfd: EventFd,

    pub(super) worker_control: Option<WorkerController>,

    pub(super) snapshot_worker: Arc<Mutex<Option<FsWorkerState>>>,

    pub(super) restore_worker: Option<FsWorkerState>,

    pub(super) frozen: bool,

    pub(super) snapshot_failed: bool,

    pub(super) snapshot_retired_root: bool,
    exit_code: Arc<AtomicI32>,
}

impl Fs {
    pub fn new(
        fs_id: String,
        shared_dir: String,
        exit_code: Arc<AtomicI32>,
        allow_root_dir_delete: bool,
        read_only: bool,
    ) -> super::Result<Fs> {
        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let fs_cfg = passthrough::Config {
            root_dir: shared_dir,
            allow_root_dir_delete,
            ..Default::default()
        };

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            passthrough_cfg: fs_cfg,
            read_only,
            worker_thread: None,

            worker_control: None,

            snapshot_worker: Arc::new(Mutex::new(None)),

            restore_worker: None,

            frozen: false,

            snapshot_failed: false,

            snapshot_retired_root: false,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
        })
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn tag(&self) -> &str {
        let end = self
            .config
            .tag
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.config.tag.len());
        std::str::from_utf8(&self.config.tag[..end])
            .expect("virtio-fs tags originate from UTF-8 strings")
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) -> u64 {
        static FS_UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        self.passthrough_cfg.export_fsid = FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        self.passthrough_cfg.export_table = Some(export_table);

        self.passthrough_cfg.export_fsid
    }
}

impl VirtioDevice for Fs {
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if !self.frozen || self.snapshot_failed {
            return Err(ActivateError::BadActivate);
        }
        self.activate(mem, interrupt, queues)
    }
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
        uapi::VIRTIO_ID_FS
    }

    fn device_name(&self) -> &str {
        "fs"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "fs: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if queues.len() != defs::NUM_QUEUES {
            return Err(ActivateError::BadActivate);
        }
        if self.worker_thread.is_some() {
            panic!("virtio_fs: worker thread already exists");
        }

        if self.snapshot_failed {
            return Err(ActivateError::BadActivate);
        }

        if let Some(saved) = &self.restore_worker {
            if queues.len() != saved.queues.len() {
                return Err(ActivateError::BadActivate);
            }
            for (queue, saved) in queues.iter().zip(&saved.queues) {
                if queue
                    .queue
                    .save_state(&mem, true)
                    .map_err(|_| ActivateError::BadActivate)?
                    != *saved
                {
                    return Err(ActivateError::BadActivate);
                }
            }
        }

        let (controller, control) = control::channel().map_err(|_| ActivateError::BadActivate)?;
        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let worker = FsWorker::new(
            worker_queues,
            queue_evts,
            interrupt.clone(),
            mem.clone(),
            self.shm_region.clone(),
            self.passthrough_cfg.clone(),
            self.read_only,
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
            WorkerCheckpoint {
                control,
                state: self.snapshot_worker.clone(),
                frozen: self.frozen,
                restore: self.restore_worker.clone(),
            },
        )
        .map_err(|e| {
            error!("virtio_fs: failed to create worker: {}", e);
            ActivateError::BadActivate
        })?;
        self.worker_thread = Some(worker.run());

        {
            self.worker_control = Some(controller);
            self.restore_worker = None;
        }

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }

        {
            self.worker_control = None;
            self.frozen = false;
            self.snapshot_failed = false;
            self.restore_worker = None;
            *self.snapshot_worker.lock().unwrap() = None;
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}
