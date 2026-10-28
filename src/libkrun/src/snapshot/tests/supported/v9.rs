// SPDX-License-Identifier: Apache-2.0
//! C ABI ownership and connected import using a real production capture.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vmm::snapshot_vm::checkpoint::ExportMetadata;
use vmm::snapshot_vm::{SnapshotDevices, SnapshotVm};

struct Pair(PathBuf);
impl Pair {
    fn capture() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "krun-capi-v9-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let pair = Self(dir);
        assert!(std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .arg(pair.path("source.qcow2"))
            .arg("1M")
            .status()
            .unwrap()
            .success());
        let firmware = unsafe {
            libloading::Library::new(
                std::env::var_os("KRUN_SNAPSHOT_TEST_LIBKRUNFW").expect("real libkrunfw required"),
            )
        }
        .unwrap();
        let kernel = unsafe {
            firmware
                .get::<unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char>(
                    b"krunfw_get_kernel",
                )
        }
        .unwrap();
        let (mut guest_addr, mut entry_addr, mut size) = (0, 0, 0);
        let host = unsafe { kernel(&mut guest_addr, &mut entry_addr, &mut size) };
        let mut resources = VmResources::default();
        resources
            .set_vm_config(&VmConfig {
                vcpu_count: Some(1),
                mem_size_mib: Some(256),
                ht_enabled: Some(false),
                cpu_template: None,
            })
            .unwrap();
        resources.kernel_bundle = Some(KernelBundle {
            host_addr: host as u64,
            guest_addr,
            entry_addr,
            size,
        });
        resources.disable_implicit_console = true;
        let disk = vmm::vmm_config::block::BlockDeviceConfig {
            block_id: "vda".into(),
            cache_type: devices::virtio::CacheType::Writeback,
            disk_image_path: pair.path("source.qcow2").to_str().unwrap().into(),
            disk_image_format: devices::virtio::block::ImageType::Qcow2,
            is_disk_read_only: false,
            direct_io: false,
            sync_mode: devices::virtio::block::SyncMode::Full,
        };
        let mut vm = SnapshotVm::boot(
            &resources,
            SnapshotDevices {
                disks: vec![disk],
                ..Default::default()
            },
        )
        .unwrap();
        vm.pause().unwrap();
        vm.prepare_checkpoint().unwrap();
        fs::copy(pair.path("source.qcow2"), pair.path("snapshot.qcow2")).unwrap();
        vm.export_fd(
            pair.writable("snapshot.mem"),
            File::open(pair.path("snapshot.qcow2")).unwrap(),
            ExportMetadata {
                application_schema: 1,
                application: serde_json::Value::Null,
                objects: vec![],
            },
        )
        .unwrap();
        drop(vm);
        pair
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn writable(&self, name: &str) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.path(name))
            .unwrap()
    }
    fn queue(&self, ctx: u32, json: &[u8], fds: &[i32]) -> i32 {
        let memory = File::open(self.path("snapshot.mem")).unwrap();
        unsafe {
            krun_snapshot_import_fd(
                ctx,
                memory.as_raw_fd(),
                json.as_ptr(),
                json.len(),
                fds.as_ptr(),
                fds.len(),
            )
        }
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn open_fds() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn snapshot_capi_v9_import_indices_borrowing_and_positive_owner_start() {
    let pair = Pair::capture();
    fs::copy(pair.path("snapshot.qcow2"), pair.path("private.qcow2")).unwrap();
    let disk = OpenOptions::new()
        .read(true)
        .write(true)
        .open(pair.path("private.qcow2"))
        .unwrap();
    let ctx = enabled();
    assert_eq!(krun_disable_implicit_vsock(ctx), 0);
    for config in [
        br#"{"disks":[1],"shares":[]}"#.as_slice(),
        br#"{"disks":[0,0],"shares":[]}"#,
        br#"{"disks":[],"shares":[]}"#,
        br#"{"disks":[0],"shares":[],"unknown":true}"#,
    ] {
        let before = open_fds();
        assert_eq!(pair.queue(ctx, config, &[disk.as_raw_fd()]), -libc::EINVAL);
        assert_eq!(
            open_fds(),
            before,
            "failed binding kept duplicated descriptors"
        );
        assert_ne!(
            unsafe { libc::fcntl(disk.as_raw_fd(), libc::F_GETFD) },
            -1,
            "borrowed input closed"
        );
    }
    let config = br#"{"disks":[0],"shares":[]}"#;
    let plain = krun_create_ctx() as u32;
    assert_eq!(
        pair.queue(plain, config, &[disk.as_raw_fd()]),
        -libc::EINVAL
    );
    assert_eq!(krun_free_ctx(plain), 0);
    assert_eq!(
        pair.queue(u32::MAX, config, &[disk.as_raw_fd()]),
        -libc::ENOENT
    );
    assert_eq!(pair.queue(ctx, config, &[disk.as_raw_fd()]), 0);
    assert_eq!(
        pair.queue(ctx, config, &[disk.as_raw_fd()]),
        -libc::EINVAL,
        "import twice"
    );
    {
        let map = CTX_MAP.lock().unwrap();
        let import = map[&ctx]
            .snapshot
            .as_ref()
            .unwrap()
            .fd_import
            .as_ref()
            .unwrap();
        for file in [&import.image, &import.bindings.disks[0]] {
            assert_ne!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }
    drop(disk);
    let owner = std::thread::spawn(move || krun_start_enter(ctx));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let state = get_state(ctx).unwrap().0;
        if state == crate::snapshot::STATE_PAUSED {
            break;
        }
        assert_ne!(
            state,
            crate::snapshot::STATE_FAILED,
            "positive descriptor import failed"
        );
        assert!(Instant::now() < deadline, "import did not publish Paused");
        std::thread::yield_now();
    }
    assert!(!CTX_MAP.lock().unwrap().contains_key(&ctx));
    assert_eq!(krun_snapshot_stop(ctx), 0);
    assert_eq!(owner.join().unwrap(), 0);
    assert_eq!(krun_free_ctx(ctx), 0);
    assert!(pair.path("private.qcow2").exists());
}

#[test]
fn snapshot_capi_v9_refused_and_failed_import_keep_queryable_control_and_no_endpoint() {
    let pair = Pair::capture();
    for configuration_refused in [true, false] {
        let ctx = enabled();
        assert_eq!(krun_disable_implicit_vsock(ctx), 0);
        let output = pair.path(if configuration_refused {
            "refused.log"
        } else {
            "failed.log"
        });
        assert_eq!(
            unsafe { krun_set_console_output(ctx, c(output.to_str().unwrap()).as_ptr()) },
            0
        );
        let disk = if configuration_refused {
            File::open(pair.path("snapshot.qcow2")).unwrap()
        } else {
            pair.writable("wrong.qcow2")
        };
        assert_eq!(
            pair.queue(ctx, br#"{"disks":[0],"shares":[]}"#, &[disk.as_raw_fd()]),
            0
        );
        if configuration_refused {
            assert_eq!(
                unsafe {
                    krun_add_disk2(
                        ctx,
                        c("extra").as_ptr(),
                        c(pair.path("extra.raw").to_str().unwrap()).as_ptr(),
                        0,
                        false,
                    )
                },
                0
            );
        }
        assert_eq!(
            krun_start_enter(ctx),
            if configuration_refused {
                -libc::EINVAL
            } else {
                -libc::EIO
            }
        );
        assert_eq!(get_state(ctx), Ok((crate::snapshot::STATE_FAILED, 0)));
        assert_eq!(krun_snapshot_resume(ctx), -libc::ESRCH);
        assert_eq!(krun_snapshot_stop(ctx), 0);
        assert!(!output.exists(), "failed start created endpoint");
        assert!(pair.path("snapshot.mem").exists() && pair.path("snapshot.qcow2").exists());
        assert_eq!(krun_free_ctx(ctx), 0);
        assert_eq!(get_state(ctx), Err(-libc::ENOENT));
    }
}

#[test]
fn snapshot_capi_v9_complete_descriptor_limit_closes_every_duplicate() {
    struct DescriptorLimit(libc::rlimit);
    impl Drop for DescriptorLimit {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
        }
    }
    let mut saved = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) },
        0
    );
    assert!(
        saved.rlim_max >= 32768,
        "descriptor-bound test requires hard RLIMIT_NOFILE >= 32768"
    );
    let _restore = DescriptorLimit(saved);
    let raised = libc::rlimit {
        rlim_cur: saved.rlim_cur.max(32768),
        rlim_max: saved.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) }, 0);
    let pair = Pair::capture();
    let disk = File::open(pair.path("snapshot.qcow2")).unwrap();
    let fds = vec![disk.as_raw_fd(); 16384];
    let config = serde_json::to_vec(
        &serde_json::json!({"disks": (0..16384).collect::<Vec<_>>(), "shares": []}),
    )
    .unwrap();
    let ctx = enabled();
    let before = open_fds();
    assert_eq!(
        pair.queue(ctx, &config, &fds),
        0,
        "complete limit was rejected"
    );
    assert_eq!(
        open_fds(),
        before + 16385,
        "not all input descriptors and memory were retained"
    );
    assert_eq!(krun_free_ctx(ctx), 0);
    assert_eq!(open_fds(), before, "free leaked queued descriptors");
    let ctx = enabled();
    let memory = File::open(pair.path("snapshot.mem")).unwrap();
    assert_eq!(
        unsafe {
            krun_snapshot_import_fd(
                ctx,
                memory.as_raw_fd(),
                config.as_ptr(),
                config.len(),
                fds.as_ptr(),
                16385,
            )
        },
        -libc::EINVAL
    );
    assert_eq!(krun_free_ctx(ctx), 0);
}

/// A deterministic producer isolates the C ABI's two-capacity transfer
/// contract; real full export/import is exercised by the tests above.
#[test]
fn snapshot_capi_v9_prepare_enobufs_transfers_no_fds_then_cloexec_ownership() {
    use crate::snapshot::control::{self, State, Vm};
    use std::sync::{Arc, Condvar, Mutex};
    use vmm::snapshot_vm::checkpoint::PreparedResources;
    struct Producer {
        file: File,
        ended: Arc<(Mutex<bool>, Condvar)>,
    }
    impl Vm for Producer {
        fn pause(&mut self, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn prepare(&mut self) -> Result<PreparedResources, String> {
            Ok(PreparedResources {
                metadata: b"prepared-object".to_vec(),
                files: vec![self.file.try_clone().unwrap()],
            })
        }
        fn stop(&mut self) {
            *self.ended.0.lock().unwrap() = true;
            self.ended.1.notify_all();
        }
        fn state(&mut self) -> State {
            if *self.ended.0.lock().unwrap() {
                State::Stopped
            } else {
                State::Paused
            }
        }
        fn exit_watch(&self) -> Box<dyn FnOnce() + Send> {
            let ended = self.ended.clone();
            Box::new(move || {
                let mut value = ended.0.lock().unwrap();
                while !*value {
                    value = ended.1.wait(value).unwrap();
                }
            })
        }
        fn restored_shares(&self) -> Vec<(String, PathBuf)> {
            vec![]
        }
    }
    let ctx = enabled();
    let file = File::open("/dev/null").unwrap();
    let ended = Arc::new((Mutex::new(false), Condvar::new()));
    let owner = std::thread::spawn(move || control::serve(ctx, || Ok(Producer { file, ended })));
    let deadline = Instant::now() + Duration::from_secs(3);
    while get_state(ctx).unwrap().0 != crate::snapshot::STATE_PAUSED {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let (session, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut token = 0;
    assert_eq!(
        unsafe { krun_snapshot_begin_capture(ctx, 0, session.as_raw_fd(), &mut token) },
        0
    );
    let before = open_fds();
    let mut buffer = [0u8; 64];
    let mut received = -731;
    for (json_capacity, fd_capacity) in [(0, 1), (64, 0)] {
        let (mut length, mut count) = (json_capacity, fd_capacity);
        assert_eq!(
            unsafe {
                krun_snapshot_prepare_capture(
                    ctx,
                    token,
                    buffer.as_mut_ptr(),
                    &mut length,
                    &mut received,
                    &mut count,
                )
            },
            -libc::ENOBUFS
        );
        assert_eq!((length, count), (15, 1));
        assert_eq!(
            received, -731,
            "short buffer transferred descriptor ownership"
        );
        assert_eq!(open_fds(), before, "short prepare leaked duplicate");
    }
    let (mut length, mut count) = (buffer.len(), 1);
    assert_eq!(
        unsafe {
            krun_snapshot_prepare_capture(
                ctx,
                token,
                buffer.as_mut_ptr(),
                &mut length,
                &mut received,
                &mut count,
            )
        },
        0
    );
    assert_eq!(&buffer[..length], b"prepared-object");
    assert_eq!(count, 1);
    assert_ne!(
        unsafe { libc::fcntl(received, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let retained = unsafe { File::from_raw_fd(received) };
    assert_eq!(krun_snapshot_end_capture(ctx, token, 0), 0);
    assert_eq!(krun_snapshot_stop(ctx), 0);
    assert_eq!(owner.join().unwrap(), 0);
    assert_ne!(
        unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFD) },
        -1,
        "owner closed transferred duplicate"
    );
    drop(retained);
    assert_eq!(krun_free_ctx(ctx), 0);
}
