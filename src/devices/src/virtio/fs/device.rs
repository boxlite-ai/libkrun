#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, FsError, QueueConfig, VirtioDevice,
    VirtioShmRegion,
};
use super::passthrough;
#[cfg(target_os = "linux")]
use super::passthrough::{
    DaxPages, DaxWindow, PassthroughCheckpoint, PassthroughSnapshotError, PassthroughState,
    RestoredObject,
};
use super::worker::{FsServer, FsWorker, FsWorkerHandle};
use super::ExportTable;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

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

/// The FUSE session of an activated, frozen share.
#[cfg(target_os = "linux")]
pub struct FsSessionCheckpoint {
    /// The FUSE options FUSE_INIT negotiated (0 before it).
    pub options: u64,
    pub passthrough: PassthroughCheckpoint,
}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: passthrough::Config,
    read_only: bool,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    worker_control: Option<FsWorkerHandle>,
    /// The session the activated worker serves; shared so a frozen share
    /// can be checkpointed.
    server: Option<Arc<FsServer>>,
    /// A restored session waiting for `activate_frozen`.
    restored_server: Option<FsServer>,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
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
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            worker_control: None,
            server: None,
            restored_server: None,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
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

    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }

    /// Opt this share into checkpointable runtime state (see
    /// `passthrough::Config::snapshot`). Must precede activation.
    #[cfg(target_os = "linux")]
    pub fn enable_snapshot(&mut self) {
        self.passthrough_cfg.snapshot = true;
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn allow_root_dir_delete(&self) -> bool {
        self.passthrough_cfg.allow_root_dir_delete
    }

    /// The complete guest-visible device configuration, byte-exact.
    pub fn config_bytes(&self) -> Vec<u8> {
        self.config.as_slice().to_vec()
    }

    /// Snapshot control handle for the activated worker, if any.
    pub fn worker_control(&self) -> Option<&FsWorkerHandle> {
        self.worker_control.as_ref()
    }

    /// The DAX window as this process maps it, if the device has one.
    #[cfg(target_os = "linux")]
    fn dax_window(&self) -> Option<DaxWindow> {
        self.shm_region.as_ref().map(|shm| DaxWindow {
            host_addr: shm.host_addr,
            size: shm.size as u64,
        })
    }

    /// Capture the FUSE session and the DAX window; None for an inactive
    /// device. The caller must hold a freeze confirmation (no request runs
    /// concurrently) and keep the guest paused.
    #[cfg(target_os = "linux")]
    pub fn snapshot_session(
        &self,
    ) -> Result<Option<FsSessionCheckpoint>, PassthroughSnapshotError> {
        let Some(server) = &self.server else {
            return Ok(None);
        };
        Ok(Some(FsSessionCheckpoint {
            options: server.options(),
            passthrough: server
                .passthrough()
                .checkpoint_with_dax(self.dax_window())?,
        }))
    }

    /// Prepare the session a restored, activated device continues; the
    /// next `activate_frozen` serves it instead of a new share, without
    /// FUSE_INIT. The saved DAX window is mapped into this device's window
    /// (set before) with `dax_pages`; on a failure the device must be
    /// discarded.
    #[cfg(target_os = "linux")]
    pub fn restore_session(
        &mut self,
        options: u64,
        state: &PassthroughState,
        objects: Vec<RestoredObject>,
        init_binary: Arc<[u8]>,
        dax_pages: &DaxPages,
    ) -> Result<(), PassthroughSnapshotError> {
        if self.is_activated() || self.restored_server.is_some() {
            return Err(PassthroughSnapshotError::Invalid(
                "device already holds a session",
            ));
        }
        let window = self.dax_window();
        if state.dax.as_ref().map(|dax| dax.size) != window.map(|w| w.size) {
            return Err(PassthroughSnapshotError::Invalid(
                "DAX window differs from the saved one",
            ));
        }
        if window.is_none() && *dax_pages != DaxPages::default() {
            return Err(PassthroughSnapshotError::Invalid(
                "DAX pages without a DAX window",
            ));
        }
        let server = FsServer::restored(
            self.passthrough_cfg.clone(),
            self.read_only,
            options,
            state,
            objects,
            init_binary,
        )?;
        if let Some(window) = window {
            server.passthrough().map_dax(window, dax_pages)?;
        }
        self.restored_server = Some(server);
        Ok(())
    }

    fn activate_impl(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
        start_frozen: bool,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_fs: worker thread already exists");
        }

        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let server = match self.restored_server.take() {
            Some(server) => server,
            None => FsServer::new(self.passthrough_cfg.clone(), self.read_only).map_err(|e| {
                error!("virtio_fs: failed to create worker: {}", e);
                ActivateError::BadActivate
            })?,
        };
        let server = Arc::new(server);
        let control_fd = EventFd::new(EFD_NONBLOCK).map_err(|_| ActivateError::BadActivate)?;
        let (commands, command_receiver) = crossbeam_channel::bounded(16);
        let worker = FsWorker::new(
            worker_queues,
            queue_evts,
            interrupt.clone(),
            mem.clone(),
            self.shm_region.clone(),
            server.clone(),
            self.worker_stopfd.try_clone().unwrap(),
            control_fd.try_clone().unwrap(),
            command_receiver,
            self.exit_code.clone(),
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
        );
        self.worker_thread = Some(worker.run(start_frozen));
        self.worker_control = Some(FsWorkerHandle {
            control_fd,
            commands,
        });
        self.server = Some(server);

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }
}

impl VirtioDevice for Fs {
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
        self.activate_impl(mem, interrupt, queues, false)
    }

    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate_impl(mem, interrupt, queues, true)
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
        self.worker_control = None;
        self.server = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}

impl Drop for Fs {
    /// A dropped device stops and joins its worker first, including one an
    /// owner activated but never inserted (a failed restore); the session
    /// and guest memory the worker uses stay alive until it exits.
    fn drop(&mut self) {
        self.reset();
    }
}
