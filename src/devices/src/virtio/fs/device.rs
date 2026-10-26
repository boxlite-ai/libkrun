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
    ArchiveError, DaxMappingControl, DaxPages, DaxWindow, ImportedArchive, PassthroughCheckpoint,
    PassthroughSnapshotError, PassthroughState, RestoredObject, ShareSource,
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

/// The features every virtio-fs device offers.
pub const FS_FEATURES: u64 = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

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
    /// A reset could not return the DAX window to its initial state, or
    /// left a window a failed host call lost alone: the device activates,
    /// restores and captures nothing anymore and must be discarded.
    #[cfg(target_os = "linux")]
    dax_lost: bool,
    /// Window ranges (offset, length) a failed `mmap(MAP_FIXED)` may have
    /// unmapped, so other memory may now live there; see `dax_unowned`.
    #[cfg(target_os = "linux")]
    dax_unowned: Vec<(u64, u64)>,
    /// `retire` ended the device for good.
    retired: bool,
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
        let fs_cfg = passthrough::Config {
            root_dir: shared_dir.into(),
            allow_root_dir_delete,
            ..Default::default()
        };
        Self::create(fs_id, fs_cfg, exit_code, read_only)
    }

    /// `new` for a root directory whose path need not be UTF-8.
    #[cfg(target_os = "linux")]
    pub fn new_at(
        fs_id: String,
        root_dir: std::path::PathBuf,
        exit_code: Arc<AtomicI32>,
        allow_root_dir_delete: bool,
        read_only: bool,
    ) -> super::Result<Fs> {
        let fs_cfg = passthrough::Config {
            root_dir,
            allow_root_dir_delete,
            ..Default::default()
        };
        Self::create(fs_id, fs_cfg, exit_code, read_only)
    }

    fn create(
        fs_id: String,
        fs_cfg: passthrough::Config,
        exit_code: Arc<AtomicI32>,
        read_only: bool,
    ) -> super::Result<Fs> {
        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        Ok(Fs {
            avail_features: FS_FEATURES,
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
            #[cfg(target_os = "linux")]
            dax_lost: false,
            #[cfg(target_os = "linux")]
            dax_unowned: Vec::new(),
            retired: false,
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

    /// Make every host mapping call on the DAX window run inside `control`
    /// (see `passthrough::DaxMappingControl`). Must precede activation and
    /// restore.
    #[cfg(target_os = "linux")]
    pub fn set_dax_control(&mut self, control: Arc<dyn DaxMappingControl>) {
        self.passthrough_cfg.dax_control = Some(control);
    }

    /// Acknowledge the guest's root removal request without removing the
    /// share root; whoever created the root removes it when the VM ends
    /// (see `passthrough::Config::defer_root_dir_delete`). Must precede
    /// activation.
    #[cfg(target_os = "linux")]
    pub fn defer_root_dir_delete(&mut self) {
        self.passthrough_cfg.defer_root_dir_delete = true;
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

    /// The device must be discarded: a lost DAX window, a failed reset
    /// remapping or `retire` ended it.
    pub fn must_discard(&self) -> bool {
        #[cfg(target_os = "linux")]
        if self.dax_lost {
            return true;
        }
        self.retired
    }

    /// Window ranges (offset, length) this device no longer vouches for: a
    /// failed `mmap(MAP_FIXED)` may have unmapped them, so other memory of
    /// the process may live there now. Whoever owns the window must leave
    /// them mapped as they are.
    #[cfg(target_os = "linux")]
    pub fn dax_unowned(&self) -> &[(u64, u64)] {
        &self.dax_unowned
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
        if self.dax_lost {
            return Err(PassthroughSnapshotError::DaxLost);
        }
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
        if self.dax_lost {
            return Err(PassthroughSnapshotError::DaxLost);
        }
        if self.retired {
            return Err(PassthroughSnapshotError::Invalid("device retired"));
        }
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
        let served = init_binary.clone();
        let server = FsServer::restored(
            self.passthrough_cfg.clone(),
            self.read_only,
            options,
            state,
            objects,
            init_binary,
        )?;
        if let Some(window) = window {
            if let Err(e) = server.passthrough().map_dax(window, dax_pages) {
                // A host call that failed part way retires the device.
                self.keep_lost_window(&server);
                return Err(e);
            }
        }
        self.restored_server = Some(server);
        // A reset device serves the same init.krun again.
        self.passthrough_cfg.init_binary = Some(served);
        Ok(())
    }

    /// This share as an archive source (see `passthrough::ShareArchive`):
    /// the session it serves or holds for its activation, else a
    /// pre-FUSE_INIT one with its DAX window. The caller must hold a freeze
    /// confirmation for an activated device and keep the guest paused.
    #[cfg(target_os = "linux")]
    pub fn archive_source(&self) -> Result<ShareSource<'_>, PassthroughSnapshotError> {
        if !self.passthrough_cfg.snapshot {
            return Err(PassthroughSnapshotError::Disabled);
        }
        if self.dax_lost {
            return Err(PassthroughSnapshotError::DaxLost);
        }
        if self.retired {
            return Err(PassthroughSnapshotError::Invalid("device retired"));
        }
        let server = self.server.as_deref().or(self.restored_server.as_ref());
        let Some(server) = server else {
            return ShareSource::inactive(&self.passthrough_cfg, self.dax_window());
        };
        let checkpoint = server
            .passthrough()
            .checkpoint_with_dax(self.dax_window())?;
        Ok(ShareSource::active(
            &self.passthrough_cfg,
            server.passthrough(),
            server.options(),
            checkpoint,
        ))
    }

    /// Continue share `share` of `archive` on this new device, created on
    /// `archive.root(share)` with the source's mode and DAX window: its
    /// session (and DAX window) is restored, and the device continues it
    /// from `activate_frozen` when the source was activated, else from the
    /// guest's own activation.
    #[cfg(target_os = "linux")]
    pub fn restore_imported(
        &mut self,
        archive: &ImportedArchive,
        share: usize,
    ) -> Result<(), ArchiveError> {
        if share >= archive.shares() {
            return Err(ArchiveError::Invalid("no such imported share"));
        }
        if self.passthrough_cfg.root_dir != archive.root(share) {
            return Err(ArchiveError::Invalid(
                "device root is not the imported share root",
            ));
        }
        let session = archive.session(share)?;
        self.restore_session(
            session.options,
            &session.state,
            session.objects,
            archive.init_binary(share),
            &session.dax_pages,
        )?;
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
        if self.must_discard() {
            error!(
                "virtio_fs: the device was retired or lost its DAX window; it must be discarded"
            );
            return Err(ActivateError::BadActivate);
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

    /// Stop and join the worker and take the sessions it served or holds
    /// for its activation.
    fn stop(&mut self) -> (Option<Arc<FsServer>>, Option<FsServer>) {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.worker_control = None;
        self.device_state = DeviceState::Inactive;
        (self.server.take(), self.restored_server.take())
    }

    /// Record a session's window lost by a failed host call, with the
    /// ranges it may no longer own.
    #[cfg(target_os = "linux")]
    fn keep_lost_window(&mut self, session: &FsServer) {
        if session.passthrough().dax_window_lost() {
            self.dax_lost = true;
            self.dax_unowned.extend(session.passthrough().dax_unowned());
        }
    }

    /// End the device for good on teardown: stop and join its worker and
    /// drop its sessions, but leave the DAX window as it is. Unlike a guest
    /// reset this never remaps memory, which the window's owner may be
    /// about to release; `dax_unowned` still names the ranges a failed host
    /// call may have unmapped. A retired device never activates, restores
    /// or captures again.
    pub fn retire(&mut self) {
        let (served, restored) = self.stop();
        #[cfg(target_os = "linux")]
        for session in served.as_deref().into_iter().chain(restored.as_ref()) {
            self.keep_lost_window(session);
        }
        drop((served, restored));
        self.retired = true;
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
        // A reset ends the session the device serves or holds for its
        // activation (a restore); the next one starts with FUSE_INIT on a
        // fresh share, which serves the same init.krun (`passthrough_cfg`).
        let (served, restored) = self.stop();
        // The session's DAX mappings outlive it; a snapshot-mode share's
        // next ledger starts from private zero memory. A window a failed
        // host call lost may no longer be wholly the device's, so it is
        // left alone.
        #[cfg(target_os = "linux")]
        if let (Some(session), Some(window), true, false) = (
            served.as_deref().or(restored.as_ref()),
            self.dax_window(),
            self.passthrough_cfg.snapshot,
            self.dax_lost,
        ) {
            if session.passthrough().dax_window_lost() {
                self.keep_lost_window(session);
            } else {
                let control = self.passthrough_cfg.dax_control.as_deref();
                match passthrough::reset_dax_window(window, control) {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        // `MAP_FIXED` over the whole window may have
                        // unmapped it.
                        error!("virtio_fs: cannot reset the DAX window: {e}");
                        self.dax_lost = true;
                        self.dax_unowned = vec![(0, window.size)];
                    }
                    // The owner's guest execution ended: the window is
                    // unchanged, but not the zero memory a new session
                    // needs.
                    None => self.dax_lost = true,
                }
            }
        }
        drop((served, restored));
        true
    }
}

impl Drop for Fs {
    /// A dropped device is retired: its worker is stopped and joined first,
    /// including one an owner activated but never inserted (a failed
    /// restore), while the session and guest memory it uses are alive. The
    /// DAX window is not remapped.
    fn drop(&mut self) {
        self.retire();
    }
}
