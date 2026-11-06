// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_char, c_void, CStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Existing image flattening implementation supplied by the application. The
/// callback runs synchronously inside the VM's frozen checkpoint window.
pub type FlattenCallback = unsafe extern "C" fn(
    id: *const c_char,
    source: *const c_char,
    destination: *const c_char,
    format: u32,
    opaque: *mut c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn krun_set_checkpointing(ctx_id: u32, enabled: bool) -> i32 {
    if enabled
        && !cfg!(all(
            not(feature = "tee"),
            any(
                all(target_os = "linux", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64")
            )
        ))
    {
        return -libc::ENOTSUP;
    }
    super::with_cfg(ctx_id, |ctx| {
        ctx.vmr.checkpoint_enabled = enabled;
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_checkpoint_restore(ctx_id: u32, path: *const c_char) -> i32 {
    if !cfg!(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    )) {
        return -libc::ENOTSUP;
    }
    if path.is_null() {
        return -libc::EINVAL;
    }
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(path).to_bytes()));
    if path.as_os_str().is_empty() {
        return -libc::EINVAL;
    }
    super::with_cfg(ctx_id, |ctx| {
        ctx.vmr.checkpoint_enabled = true;
        ctx.checkpoint_restore = Some(path);
        0
    })
}

/// The caller must keep opaque alive until this call returns. The callback must
/// not reenter VM-control APIs or mutate the source image. No request timeout
/// returns control to C while its callback could still execute on another thread.
#[no_mangle]
pub unsafe extern "C" fn krun_save_checkpoint(
    ctx_id: u32,
    path: *const c_char,
    flatten: Option<FlattenCallback>,
    opaque: *mut c_void,
) -> i32 {
    if path.is_null() {
        return -libc::EINVAL;
    }
    #[cfg(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    ))]
    {
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(path).to_bytes()));
        runtime::save(ctx_id, path, flatten, opaque as usize)
    }
    #[cfg(not(all(
        not(feature = "tee"),
        any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (ctx_id, flatten, opaque);
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
    use std::ffi::CString;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use utils::epoll::{EpollEvent, EventSet};
    use utils::eventfd::{EventFd, EFD_NONBLOCK};

    static RUNNING: Lazy<Mutex<HashMap<u32, Arc<Control>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    struct Request {
        path: PathBuf,
        flatten: Option<FlattenCallback>,
        opaque: usize,
        reply: Sender<io::Result<()>>,
    }
    struct Control {
        requests: Sender<Request>,
        event: Arc<EventFd>,
        busy: AtomicBool,
        gates: Vec<Arc<devices::virtio::vsock::VsockGate>>,
    }
    struct Handler {
        requests: Receiver<Request>,
        event: Arc<EventFd>,
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
            .map(|device| {
                device
                    .lock()
                    .unwrap()
                    .snapshot_control()
                    .map_err(|e| io::Error::other(format!("{e:?}")))
            })
            .transpose()?
            .into_iter()
            .collect();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK)?);
        let (sender, receiver) = bounded(1);
        let handler = Arc::new(Mutex::new(Handler {
            requests: receiver,
            event: event.clone(),
            vmm: None,
        }));
        events
            .add_subscriber(handler.clone())
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        Ok(Pending {
            control: Arc::new(Control {
                requests: sender,
                event,
                busy: AtomicBool::new(false),
                gates,
            }),
            handler,
        })
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

    pub(super) fn save(
        id: u32,
        path: PathBuf,
        flatten: Option<FlattenCallback>,
        opaque: usize,
    ) -> i32 {
        let Some(control) = RUNNING.lock().unwrap().get(&id).cloned() else {
            return -libc::EAGAIN;
        };
        if path.exists() {
            return -libc::EEXIST;
        }
        if control.busy.swap(true, Ordering::AcqRel) {
            return -libc::EBUSY;
        }
        for gate in &control.gates {
            gate.quiesce();
        }
        let (reply, result) = bounded(1);
        if control
            .requests
            .send(Request {
                path,
                flatten,
                opaque,
                reply,
            })
            .is_err()
        {
            control.busy.store(false, Ordering::Release);
            return -libc::EIO;
        }
        if let Err(error) = control.event.write(1) {
            error!("checkpoint request wake failed: {error}");
        }
        // Once queued, a C callback/opaque pointer must remain valid until the
        // event thread has finished with it, even if wake/control fails.
        let result = result.recv();
        control.busy.store(false, Ordering::Release);
        match result {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => {
                error!("checkpoint failed: {error}");
                -error.raw_os_error().unwrap_or(libc::EIO)
            }
            Err(_) => -libc::EIO,
        }
    }

    impl Subscriber for Handler {
        fn interest_list(&self) -> Vec<EpollEvent> {
            vec![EpollEvent::new(EventSet::IN, self.event.as_raw_fd() as u64)]
        }
        fn process(&mut self, _: &EpollEvent, _: &mut EventManager) {
            let _ = self.event.read();
            while let Ok(request) = self.requests.try_recv() {
                let result = (|| {
                    let vmm = self
                        .vmm
                        .as_ref()
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::EAGAIN))?;
                    let mut flatten = |id: &str,
                                       source: &Path,
                                       destination: &Path,
                                       format: u32|
                     -> io::Result<()> {
                        if let Some(callback) = request.flatten {
                            let id = CString::new(id)?;
                            let source = CString::new(source.as_os_str().as_bytes())?;
                            let destination = CString::new(destination.as_os_str().as_bytes())?;
                            let result = unsafe {
                                callback(
                                    id.as_ptr(),
                                    source.as_ptr(),
                                    destination.as_ptr(),
                                    format,
                                    request.opaque as *mut c_void,
                                )
                            };
                            if result != 0 {
                                return Err(io::Error::from_raw_os_error(
                                    result.checked_abs().unwrap_or(libc::EIO),
                                ));
                            }
                            Ok(())
                        } else if format == 0 {
                            // Raw images already have no backing chain.
                            std::fs::copy(source, destination).map(|_| ())
                        } else {
                            Err(io::Error::from_raw_os_error(libc::ENOTSUP))
                        }
                    };
                    let mut vmm = vmm.lock().unwrap();
                    let result = vmm.save_checkpoint(&request.path, &mut flatten);
                    if vmm.checkpoint_failed() {
                        error!("checkpoint left the VM stopped; teardown required: {result:?}");
                        Err(io::Error::from_raw_os_error(libc::ESHUTDOWN))
                    } else {
                        // Reserve ESHUTDOWN for an unusable VM, even when an
                        // application's flatten callback returned that errno.
                        result.map_err(|error| {
                            if error.raw_os_error() == Some(libc::ESHUTDOWN) {
                                io::Error::from_raw_os_error(libc::EIO)
                            } else {
                                error
                            }
                        })
                    }
                })();
                let _ = request.reply.try_send(result);
            }
        }
    }

    pub(crate) fn start_restore(
        id: u32,
        mut ctx: super::super::ContextConfig,
        path: &Path,
        events: &mut EventManager,
    ) -> i32 {
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
