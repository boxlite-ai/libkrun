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

/// The same Linux boot continues on a separately prepared recipe root;
/// external roots and the private disk remain caller-owned after teardown.
#[cfg(feature = "blk")]
#[test]
fn snapshot_boot_kvm_v9_linux_continues_after_source_destruction_on_recipe_root() {
    use crate::snapshot_vm::checkpoint::{
        ExportMetadata, ExternalReference, ImportBindings, ShareBinding,
    };
    use devices::virtio::fs::passthrough::RestoredRoles;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TempDir::new();
    let disk = dir.path("source.qcow2");
    assert!(std::process::Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&disk)
        .arg("1M")
        .status()
        .unwrap()
        .success());
    let devices = SnapshotDevices {
        disks: vec![BlockDeviceConfig {
            block_id: "vda".into(),
            cache_type: CacheType::Writeback,
            disk_image_path: disk.to_str().unwrap().into(),
            disk_image_format: ImageType::Qcow2,
            is_disk_read_only: false,
            direct_io: false,
            sync_mode: SyncMode::Full,
        }],
        ..Default::default()
    };
    let mut source = SnapshotVm::boot(&guest(&dir), devices).unwrap();
    source.declare_host_writers_stopped().unwrap();
    source.pause().unwrap();
    let prepared = source.prepare_checkpoint().unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&prepared.metadata).unwrap();
    let refs = meta["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|session| {
            session["objects"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .filter(|(_, object)| object["recipe"].is_null())
                .map(|(index, _)| ExternalReference {
                    resource_id: "boot-test".into(),
                    recovery_point: "cut".into(),
                    object_key: index.to_string(),
                })
                .collect()
        })
        .collect();
    fs::copy(&disk, dir.path("private.qcow2")).unwrap();
    let memory = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.path("snapshot.mem"))
        .unwrap();
    source
        .export_fd(
            memory,
            File::open(dir.path("private.qcow2")).unwrap(),
            ExportMetadata {
                application_schema: 1,
                application: serde_json::Value::Null,
                objects: refs,
            },
        )
        .unwrap();
    drop(prepared);
    source.stop();
    drop(source);
    assert!(!dir.path("root").exists());
    fs::remove_dir_all(dir.path("user")).unwrap();
    fs::remove_file(disk).unwrap();
    let boot = dir.path("recovered-boot");
    let user = dir.path("recovered-user");
    fs::create_dir(&boot).unwrap();
    fs::create_dir(&user).unwrap();
    for name in ["dev", "proc", "sys", "newroot"] {
        fs::create_dir(boot.join(name)).unwrap();
    }
    let bindings = || {
        let shares = meta["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, session)| {
                let root = if index == 0 {
                    boot.clone()
                } else {
                    user.clone()
                };
                let recipe = meta["devices"][index]["vm_owned"].as_bool().unwrap();
                let objects = if recipe {
                    vec![]
                } else {
                    session["objects"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|object| {
                            assert_eq!(object["kind"].as_u64().unwrap(), libc::S_IFDIR as u64);
                            OpenOptions::new()
                                .read(true)
                                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                                .open(&root)
                                .unwrap()
                        })
                        .collect()
                };
                let handles = session["state"]["handles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|handle| {
                        let object =
                            &session["objects"][handle["object"].as_u64().unwrap() as usize];
                        let path = if recipe {
                            root.join(object["recipe"].as_str().unwrap())
                        } else {
                            root.clone()
                        };
                        let flags = handle["flags"].as_i64().unwrap() as i32;
                        let file = OpenOptions::new()
                            .read(true)
                            .custom_flags(flags)
                            .open(path)
                            .unwrap();
                        (handle["handle"].as_u64().unwrap(), file)
                    })
                    .collect();
                ShareBinding {
                    root,
                    objects: objects.into_iter().map(Some).collect(),
                    roles: RestoredRoles {
                        handles,
                        dax: Default::default(),
                    },
                }
            })
            .collect();
        ImportBindings {
            disks: vec![OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.path("private.qcow2"))
                .unwrap()],
            shares,
        }
    };
    let source_console = fs::read(dir.path("console.log")).unwrap();
    assert!(SnapshotVm::import_fd(
        File::open(dir.path("snapshot.mem")).unwrap(),
        bindings(),
        RestoreEndpoints {
            console_output: Some(dir.path("console.log")),
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(fs::read(dir.path("console.log")).unwrap(), source_console);
    let mut target = SnapshotVm::import_fd(
        File::open(dir.path("snapshot.mem")).unwrap(),
        bindings(),
        RestoreEndpoints {
            console_output: Some(dir.path("restored.log")),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(target.state(), VmState::Paused);
    target.resume().unwrap();
    assert_eq!(wait_exit(&mut target), VmState::Exited(127));
    assert!(console(&dir.path("restored.log")).contains(MISSING_INIT));
    drop(target);
    assert!(
        boot.is_dir() && user.is_dir() && dir.path("private.qcow2").is_file(),
        "import teardown removed caller resources"
    );
}
