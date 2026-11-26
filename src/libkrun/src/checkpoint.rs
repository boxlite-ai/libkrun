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

    static RUNNING: Lazy<Mutex<HashMap<u32, Running>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    #[derive(Clone)]
    struct Running {
        control: Arc<Control>,
        checkpoint_supported: bool,
    }

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
            let checkpoint_supported = vmm.lock().unwrap().checkpoint_supported();
            self.handler.lock().unwrap().vmm = Some(vmm);
            RUNNING.lock().unwrap().insert(
                id,
                Running {
                    control: self.control,
                    checkpoint_supported,
                },
            );
        }
    }

    pub(super) fn request(id: u32, operation: Operation) -> i32 {
        let Some(Running {
            control,
            checkpoint_supported,
        }) = RUNNING.lock().unwrap().get(&id).cloned()
        else {
            return -libc::EAGAIN;
        };
        if control.busy.swap(true, Ordering::AcqRel) {
            return -libc::EBUSY;
        }
        // Reject known-unsupported pauses before quiescing vsock: quiescing
        // disconnects live streams even if the VM never pauses.
        if matches!(operation, Operation::Pause) && !checkpoint_supported {
            control.busy.store(false, Ordering::Release);
            return -libc::ENOTSUP;
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use devices::legacy::{IrqChip, IrqChipDevice};
        use devices::virtio::vsock::{TsiFlags, Vsock};
        use devices::virtio::{DeviceQueue, InterruptTransport, Queue, VirtioDevice};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use utils::tempdir::TempDir;

        fn interrupt() -> InterruptTransport {
            #[cfg(target_os = "macos")]
            let chip = devices::legacy::GicV3::new(Arc::new(devices::legacy::VcpuList::new(1)));
            #[cfg(target_os = "linux")]
            let chip = {
                struct TestChip;
                impl devices::BusDevice for TestChip {}
                impl devices::legacy::IrqChipT for TestChip {
                    fn get_mmio_addr(&self) -> u64 {
                        0
                    }
                    fn get_mmio_size(&self) -> u64 {
                        0
                    }
                    fn set_irq(
                        &self,
                        _: Option<u32>,
                        _: Option<&EventFd>,
                    ) -> Result<(), devices::Error> {
                        Ok(())
                    }
                }
                TestChip
            };
            let chip: IrqChip = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(chip))));
            InterruptTransport::new(chip, "vsock-test".into()).unwrap()
        }

        #[test]
        fn unsupported_pause_skips_quiesce_and_releases_busy() {
            const ID: u32 = u32::MAX;
            const CID: u64 = 3;
            const PORT: u32 = 1024;
            let dir = TempDir::new().unwrap();
            let path = dir.as_path().join("peer");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut vsock = Vsock::new(
                CID,
                None,
                Some(HashMap::from([(PORT, (path, false))])),
                TsiFlags::empty(),
            )
            .unwrap();

            // Registration is private to devices. Submit one guest connection
            // request so the Unix proxy registers a real stream with the gate.
            const AVAIL: usize = 0x100;
            const USED: usize = 0x200;
            const PACKET: usize = 0x300;
            const RAM_LEN: usize = 0x4000;
            const HDR_LEN: u32 = 44;
            let mut image = b"KRUNRAM\0\x01\0\0\0\x01\0\0\0".to_vec();
            image.extend_from_slice(&0u64.to_le_bytes()); // Guest address.
            image.extend_from_slice(&(RAM_LEN as u64).to_le_bytes());
            image.extend_from_slice(&0u64.to_le_bytes()); // Region attributes.
            let header_len = image.len();
            image.resize(header_len + RAM_LEN, 0);
            let ram = &mut image[header_len..];
            ram[..8].copy_from_slice(&(PACKET as u64).to_le_bytes());
            ram[8..12].copy_from_slice(&HDR_LEN.to_le_bytes());
            ram[AVAIL + 2..AVAIL + 4].copy_from_slice(&1u16.to_le_bytes()); // One descriptor.
            let hdr = &mut ram[PACKET..PACKET + HDR_LEN as usize];
            hdr[..8].copy_from_slice(&CID.to_le_bytes());
            hdr[8..16].copy_from_slice(&2u64.to_le_bytes()); // Host CID.
            hdr[16..20].copy_from_slice(&PORT.to_le_bytes());
            hdr[20..24].copy_from_slice(&PORT.to_le_bytes());
            hdr[28..30].copy_from_slice(&1u16.to_le_bytes()); // STREAM.
            hdr[30..32].copy_from_slice(&1u16.to_le_bytes()); // REQUEST.
            let mem = vmm::ram_snapshot::restore(&image).unwrap();
            let mut tx = Queue::new(1);
            tx.ready = true;
            tx.size = 1;
            tx.avail_ring.0 = AVAIL as u64;
            tx.used_ring.0 = USED as u64;
            let queues = [Queue::new(1), tx, Queue::new(1)]
                .into_iter()
                .map(|queue| DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())))
                .collect();
            vsock.activate(mem, interrupt(), queues).unwrap();
            assert!(vsock.process_stream_tx());
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_nonblocking(true).unwrap();

            let (sender, requests) = bounded(1);
            RUNNING.lock().unwrap().insert(
                ID,
                Running {
                    control: Arc::new(Control {
                        requests: sender,
                        event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                        busy: AtomicBool::new(false),
                        paused: AtomicBool::new(false),
                        gates: vec![vsock.snapshot_control()],
                    }),
                    checkpoint_supported: false,
                },
            );
            struct Registration;
            impl Drop for Registration {
                fn drop(&mut self) {
                    unregister(ID);
                }
            }
            let _registration = Registration;

            // Watch the request channel so a regression that dispatches to
            // the (absent) VM event loop fails instead of hanging the test.
            std::thread::scope(|scope| {
                let (done, finished) = bounded::<()>(0);
                scope.spawn(move || {
                    let _done = done;
                    assert_eq!(request(ID, Operation::Pause), -libc::ENOTSUP);
                    assert_eq!(request(ID, Operation::Pause), -libc::ENOTSUP);
                    assert_eq!(request(ID, Operation::Save("unused".into())), -libc::EBUSY);
                    assert_eq!(request(ID, Operation::Resume), 0);
                });
                crossbeam_channel::select! {
                    recv(finished) -> _ => assert!(requests.try_recv().is_err()),
                    recv(requests) -> unexpected => {
                        drop(unexpected);
                        drop(requests);
                        panic!("checkpoint operation reached the event loop");
                    }
                }
            });

            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            peer.write_all(b"x").unwrap();
        }
    }
}
