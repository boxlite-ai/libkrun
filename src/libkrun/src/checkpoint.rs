// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_char, CStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const SUPPORTED: bool = cfg!(all(
    not(feature = "tee"),
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
));

#[no_mangle]
pub unsafe extern "C" fn krun_build_from_checkpoint(ctx_id: u32, path: *const c_char) -> i32 {
    if !SUPPORTED {
        return -libc::ENOTSUP;
    }
    let path = match checkpoint_path(path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    super::with_cfg(ctx_id, |ctx| {
        ctx.checkpoint_restore = Some(path);
        0
    })
}

unsafe fn checkpoint_path(path: *const c_char) -> Result<PathBuf, i32> {
    if path.is_null() {
        return Err(-libc::EINVAL);
    }
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(path).to_bytes()));
    if path.as_os_str().is_empty() {
        return Err(-libc::EINVAL);
    }
    Ok(path)
}

#[no_mangle]
pub unsafe extern "C" fn krun_save_checkpoint(ctx_id: u32, path: *const c_char) -> i32 {
    let path = match checkpoint_path(path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    #[cfg(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    ))]
    return runtime::request(ctx_id, runtime::Operation::Save(path));
    #[allow(unreachable_code)]
    {
        let _ = (ctx_id, path);
        -libc::ENOTSUP
    }
}

#[no_mangle]
pub extern "C" fn krun_pause(ctx_id: u32) -> i32 {
    #[cfg(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    ))]
    return runtime::request(ctx_id, runtime::Operation::Pause);
    #[allow(unreachable_code)]
    {
        let _ = ctx_id;
        -libc::ENOTSUP
    }
}

#[no_mangle]
pub extern "C" fn krun_resume(ctx_id: u32) -> i32 {
    #[cfg(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    ))]
    return runtime::request(ctx_id, runtime::Operation::Resume);
    #[allow(unreachable_code)]
    {
        let _ = ctx_id;
        -libc::ENOTSUP
    }
}

#[cfg(all(
    not(feature = "tee"),
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
pub(crate) mod runtime {
    use super::*;
    use crossbeam_channel::{bounded, Receiver, Sender};
    use once_cell::sync::Lazy;
    use polly::event_manager::{EventManager, Subscriber};
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use utils::epoll::{EpollEvent, EventSet};
    use utils::eventfd::{EventFd, EFD_NONBLOCK};

    static RUNNING: Lazy<Mutex<HashMap<u32, Arc<Control>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    pub(super) enum Operation {
        Pause,
        Resume,
        Save(PathBuf),
    }
    struct Request {
        operation: Operation,
        reply: Sender<io::Result<()>>,
    }
    struct Control {
        requests: Sender<Request>,
        event: Arc<EventFd>,
        busy: AtomicBool,
        paused: AtomicBool,
        gates: Vec<Arc<devices::virtio::vsock::VsockGate>>,
    }
    struct Handler {
        requests: Receiver<Request>,
        control: Arc<Control>,
        vmm: Option<Arc<Mutex<vmm::Vmm>>>,
    }

    pub(crate) struct Pending {
        control: Arc<Control>,
        handler: Arc<Mutex<Handler>>,
    }

    pub(crate) fn prepare(
        events: &mut EventManager,
        resources: &vmm::resources::VmResources,
    ) -> io::Result<Pending> {
        let gates = resources
            .vsock
            .get()
            .map(|device| device.lock().unwrap().snapshot_control())
            .into_iter()
            .collect();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK)?);
        let (sender, receiver) = bounded(1);
        let control = Arc::new(Control {
            requests: sender,
            event,
            busy: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            gates,
        });
        let handler = Arc::new(Mutex::new(Handler {
            requests: receiver,
            control: control.clone(),
            vmm: None,
        }));
        events
            .add_subscriber(handler.clone())
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        Ok(Pending { control, handler })
    }

    pub(crate) fn unregister(id: u32) {
        RUNNING.lock().unwrap().remove(&id);
    }

    impl Pending {
        pub(crate) fn attach(self, id: u32, vmm: Arc<Mutex<vmm::Vmm>>) {
            self.handler.lock().unwrap().vmm = Some(vmm);
            RUNNING.lock().unwrap().insert(id, self.control);
        }
    }

    pub(super) fn request(id: u32, operation: Operation) -> i32 {
        let Some(control) = RUNNING.lock().unwrap().get(&id).cloned() else {
            return -libc::EAGAIN;
        };
        if control.busy.swap(true, Ordering::AcqRel) {
            return -libc::EBUSY;
        }
        // A running event loop can be blocked in external I/O. Reject saves
        // without dispatching, and make an already-running resume a no-op.
        if !control.paused.load(Ordering::Acquire) {
            if matches!(operation, Operation::Save(_)) {
                control.busy.store(false, Ordering::Release);
                return -libc::EBUSY;
            }
            if matches!(operation, Operation::Resume) {
                control.busy.store(false, Ordering::Release);
                return 0;
            }
        }
        if matches!(operation, Operation::Pause) {
            // Interrupt blocking Unix sends before the event thread takes locks.
            for gate in &control.gates {
                gate.quiesce();
            }
        }
        let (reply, result) = bounded(1);
        let result = if control.requests.send(Request { operation, reply }).is_err() {
            -libc::EIO
        } else {
            if let Err(error) = control.event.write(1) {
                error!("VM control wake failed: {error}");
            }
            match result.recv() {
                Ok(Ok(())) => 0,
                Ok(Err(error)) => {
                    error!("VM control failed: {error}");
                    -error.raw_os_error().unwrap_or_else(|| {
                        if error.kind() == io::ErrorKind::Unsupported {
                            libc::ENOTSUP
                        } else {
                            libc::EIO
                        }
                    })
                }
                Err(_) => -libc::EIO,
            }
        };
        control.busy.store(false, Ordering::Release);
        result
    }

    impl Subscriber for Handler {
        fn interest_list(&self) -> Vec<EpollEvent> {
            vec![EpollEvent::new(
                EventSet::IN,
                self.control.event.as_raw_fd() as u64,
            )]
        }
        fn process(&mut self, _: &EpollEvent, _: &mut EventManager) {
            let _ = self.control.event.read();
            let mut next = self.requests.try_recv().ok();
            while let Some(request) = next {
                let vmm = self.vmm.as_ref().unwrap();
                let mut vmm = vmm.lock().unwrap();
                let result = match request.operation {
                    Operation::Pause => vmm.pause(),
                    Operation::Resume => vmm.resume(),
                    Operation::Save(path) => vmm.save_checkpoint(&path),
                };
                let stopped = vmm.is_paused() || vmm.checkpoint_failed();
                self.control.paused.store(stopped, Ordering::Release);
                let result = if vmm.checkpoint_failed() {
                    Err(io::Error::from_raw_os_error(libc::ESHUTDOWN))
                } else {
                    result
                };
                drop(vmm);
                let _ = request.reply.try_send(result);
                // Remain inside the event-loop barrier while paused. No serial,
                // timer or device subscriber can mutate the captured state.
                next = if stopped {
                    self.requests.recv().ok()
                } else {
                    self.requests.try_recv().ok()
                };
            }
        }
    }

    pub(crate) fn start_restore(
        id: u32,
        mut ctx: super::super::ContextConfig,
        path: &Path,
        events: &mut EventManager,
    ) -> i32 {
        #[cfg(feature = "blk")]
        for config in ctx.get_block_cfg() {
            if let Err(error) = ctx.vmr.add_block_device(config) {
                error!("restore disk configuration: {error}");
                return -libc::EINVAL;
            }
        }
        #[cfg(feature = "net")]
        if let Some(config) = ctx.legacy_net_cfg.clone() {
            use super::super::{LegacyNetworkConfig, NET_COMPAT_FEATURES};
            use devices::virtio::net::device::VirtioNetBackend;
            let backend = match config {
                LegacyNetworkConfig::VirtioNetGvproxy(path) => {
                    VirtioNetBackend::UnixgramPath(path, true)
                }
                LegacyNetworkConfig::VirtioNetPasst(fd) => VirtioNetBackend::UnixstreamFd(fd),
            };
            let mac = ctx
                .legacy_mac
                .unwrap_or([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]);
            super::super::create_virtio_net(&mut ctx, backend, mac, NET_COMPAT_FEATURES);
        }
        super::super::configure_vsock(&mut ctx);
        if let Some(output) = ctx.console_output.take() {
            ctx.vmr.set_console_output(output);
        }
        if let Some(gid) = ctx.vmm_gid {
            if unsafe { libc::setgid(gid) } != 0 {
                return -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
            }
        }
        if let Some(uid) = ctx.vmm_uid {
            if unsafe { libc::setuid(uid) } != 0 {
                return -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
            }
        }
        let pending = match prepare(events, &ctx.vmr) {
            Ok(pending) => pending,
            Err(error) => {
                error!("checkpoint control: {error}");
                return -libc::EIO;
            }
        };
        let vmm = match vmm::checkpoint::restore(
            path,
            &ctx.vmr,
            events,
            #[cfg(target_os = "macos")]
            ctx.shutdown_efd.take(),
        ) {
            Ok(vmm) => vmm,
            Err(error) => {
                error!("checkpoint restore failed: {error}");
                return -error.raw_os_error().unwrap_or(libc::EIO);
            }
        };
        pending.attach(id, vmm);
        loop {
            if let Err(error) = events.run() {
                error!("restored event loop failed: {error:?}");
                RUNNING.lock().unwrap().remove(&id);
                return -libc::EIO;
            }
        }
    }
}
