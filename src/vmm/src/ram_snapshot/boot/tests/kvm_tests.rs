// SPDX-License-Identifier: Apache-2.0

//! Real Linux guests through the public `SnapshotVm`: they need /dev/kvm
//! and libkrunfw (`KRUN_SNAPSHOT_TEST_LIBKRUNFW` names its shared
//! library), and fail without either. The guest boots from a virtio-fs
//! root marked VM-owned, as the disk-root boot share is, and its
//! init.krun cannot execute the missing `KRUN_INIT`: init reports 127
//! through virtio-fs and reboots, which ends the VM.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

use super::*;
use crate::snapshot_vm::{RestoreEndpoints, SnapshotDevices, SnapshotVm, VmState};

const GUEST_EXIT: Duration = Duration::from_secs(60);
const MISSING_INIT: &str = "/krun-snapshot-test-missing-init";

/// libkrunfw's kernel mapping, kept for the life of the process.
fn libkrunfw_kernel() -> KernelBundle {
    KvmContext::new().expect("these tests need /dev/kvm");
    let path = std::env::var_os("KRUN_SNAPSHOT_TEST_LIBKRUNFW")
        .expect("KRUN_SNAPSHOT_TEST_LIBKRUNFW must name libkrunfw's shared library");
    let path = CString::new(path.as_bytes()).unwrap();
    // SAFETY: loading libkrunfw runs no code of ours; it is never unloaded,
    // so the kernel mapping it returns stays valid.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "dlopen libkrunfw");
    // SAFETY: a NUL-terminated symbol name on a live handle.
    let symbol = unsafe { libc::dlsym(handle, c"krunfw_get_kernel".as_ptr()) };
    assert!(!symbol.is_null(), "krunfw_get_kernel");
    type GetKernel = unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char;
    // SAFETY: libkrunfw's documented signature, as libkrun binds it.
    let get_kernel: GetKernel = unsafe { std::mem::transmute(symbol) };
    let (mut guest_addr, mut entry_addr, mut size) = (0, 0, 0);
    // SAFETY: three valid out-pointers.
    let host = unsafe { get_kernel(&mut guest_addr, &mut entry_addr, &mut size) };
    KernelBundle {
        host_addr: host as u64,
        guest_addr,
        entry_addr,
        size,
    }
}

/// A two-vCPU guest on `dir/root` (VM-owned, with the boot share's DAX
/// window) and a user share `dir/user`, writing its console to
/// `dir/console.log`.
fn guest(dir: &TempDir) -> VmResources {
    let mut resources = VmResources::default();
    resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(2),
            mem_size_mib: Some(256),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .unwrap();
    resources.kernel_bundle = Some(libkrunfw_kernel());
    resources.kernel_cmdline = KernelCmdlineConfig {
        prolog: Some(format!("{DEFAULT_KERNEL_CMDLINE} init=/init.krun")),
        krun_env: Some(format!("KRUN_INIT={MISSING_INIT} KRUN_WORKDIR=/")),
        epilog: Some("--".into()),
    };
    fs::create_dir(dir.path("root")).unwrap();
    fs::create_dir(dir.path("user")).unwrap();
    resources.add_fs_device(FsDeviceConfig {
        fs_id: "/dev/root".into(),
        shared_dir: dir.path("root").to_str().unwrap().into(),
        shm_size: Some(1 << 29),
        allow_root_dir_delete: true,
        read_only: false,
        vm_owned: true,
    });
    resources.add_fs_device(FsDeviceConfig {
        fs_id: "user".into(),
        shared_dir: dir.path("user").to_str().unwrap().into(),
        shm_size: None,
        allow_root_dir_delete: false,
        read_only: false,
        vm_owned: false,
    });
    resources.set_console_output(dir.path("console.log"));
    resources
}

fn wait_exit(vm: &mut SnapshotVm) -> VmState {
    assert!(
        vm.exit_waiter().wait(Some(GUEST_EXIT)),
        "the guest did not end"
    );
    vm.state()
}

fn console(path: &Path) -> String {
    String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned()
}

#[test]
fn snapshot_boot_kvm_linux_guest_reports_its_init_exit_code_and_its_root_goes_with_the_vm() {
    let dir = TempDir::new();
    let mut vm = SnapshotVm::boot(&guest(&dir), SnapshotDevices::default()).unwrap();
    assert_eq!(wait_exit(&mut vm), VmState::Exited(127));
    assert!(console(&dir.path("console.log")).contains(MISSING_INIT));
    assert!(dir.path("root").is_dir(), "kept until the VM ends");
    drop(vm);
    assert!(
        !dir.path("root").exists(),
        "the VM-owned root goes with the VM"
    );
    assert!(dir.path("user").is_dir(), "a user share stays");
}

/// Paused early in boot, exported, the source destroyed with its root:
/// an import onto the source's console output is refused untouched, and
/// one onto new endpoints continues the same boot (no payload or boot
/// setup again) on the copies and reports the guest's exit through its
/// own shares.
#[test]
fn snapshot_boot_kvm_linux_guest_import_continues_the_boot_after_the_source_is_gone() {
    let dir = TempDir::new();
    let mut source = SnapshotVm::boot(&guest(&dir), SnapshotDevices::default()).unwrap();
    source.declare_host_writers_stopped().unwrap();
    source.pause().unwrap();
    assert_eq!(source.state(), VmState::Paused);
    let image = dir.path("checkpoint");
    source.export(&image).unwrap();
    source.stop();
    drop(source);
    assert!(!dir.path("root").exists());
    fs::remove_dir_all(dir.path("user")).unwrap();

    let shares = dir.path("shares");
    // An existing console output is refused untouched, before the import
    // created anything.
    let source_console = fs::read(dir.path("console.log")).unwrap();
    let onto_existing = SnapshotVm::import(
        &image,
        RestoreEndpoints {
            console_output: Some(dir.path("console.log")),
            fs_dir: Some(shares.clone()),
            ..Default::default()
        },
    );
    assert!(onto_existing.is_err());
    assert_eq!(fs::read(dir.path("console.log")).unwrap(), source_console);
    assert!(!shares.exists());
    let mut target = SnapshotVm::import(
        &image,
        RestoreEndpoints {
            console_output: Some(dir.path("restored.log")),
            fs_dir: Some(shares.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(target.state(), VmState::Paused);
    target.resume().unwrap();
    assert_eq!(wait_exit(&mut target), VmState::Exited(127));
    assert!(console(&dir.path("restored.log")).contains(MISSING_INIT));
    assert!(shares.join("0").is_dir(), "kept until the VM ends");
    drop(target);
    assert!(
        !shares.join("0").exists(),
        "the imported boot root copy goes"
    );
    assert!(shares.join("1").is_dir(), "the user share copy stays");
}

/// An import hands its disk and share copies over to the caller: they
/// outlive the restored VM, the disk as `disk-0.raw` with the source's
/// bytes, the user share at the root `restored_shares` names; only the
/// VM-owned boot root copy goes with the VM.
#[test]
fn snapshot_boot_kvm_import_hands_its_disk_and_share_copies_over() {
    let dir = TempDir::new();
    let mut data = vec![0u8; 1 << 20];
    data[..8].copy_from_slice(b"KRUNDISK");
    fs::write(dir.path("data.raw"), &data).unwrap();
    let devices = SnapshotDevices {
        disks: vec![BlockDeviceConfig {
            block_id: "vda".into(),
            cache_type: CacheType::Writeback,
            disk_image_path: dir.path("data.raw").to_str().unwrap().into(),
            disk_image_format: ImageType::Raw,
            is_disk_read_only: true,
            direct_io: false,
            sync_mode: SyncMode::Full,
        }],
        ..Default::default()
    };
    let mut source = SnapshotVm::boot(&guest(&dir), devices).unwrap();
    source.declare_host_writers_stopped().unwrap();
    source.pause().unwrap();
    let image = dir.path("checkpoint");
    source.export(&image).unwrap();
    source.stop();
    drop(source);
    fs::remove_file(dir.path("data.raw")).unwrap();
    fs::remove_dir_all(dir.path("user")).unwrap();

    let (disks, shares) = (dir.path("disks"), dir.path("shares"));
    let mut target = SnapshotVm::import(
        &image,
        RestoreEndpoints {
            disk_dir: Some(disks.clone()),
            console_output: Some(dir.path("restored.log")),
            fs_dir: Some(shares.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        target.restored_shares(),
        [("user".to_string(), shares.join("1"))]
    );
    target.resume().unwrap();
    assert_eq!(wait_exit(&mut target), VmState::Exited(127));
    drop(target);
    assert_eq!(fs::read(disks.join("disk-0.raw")).unwrap(), data);
    assert!(shares.join("1").is_dir());
    assert!(!shares.join("0").exists());
}

#[test]
fn snapshot_boot_kvm_stop_ends_a_running_guest_without_an_exit_status() {
    let dir = TempDir::new();
    let mut vm = SnapshotVm::boot(&guest(&dir), SnapshotDevices::default()).unwrap();
    let waiter = vm.exit_waiter();
    vm.stop();
    assert!(waiter.wait(Some(Duration::ZERO)));
    assert_eq!(vm.state(), VmState::Stopped);
    assert!(vm.pause().is_err());
}
