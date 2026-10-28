// SPDX-License-Identifier: Apache-2.0

//! Version-9 owner boundaries. Requires Linux/KVM and qemu-img; no BoxLite acceptance claim.
use super::*;
use crate::snapshot_vm::checkpoint::{ExportMetadata, ImportBindings, ShareBinding};
use devices::virtio::block::ImageType;
use devices::virtio::fs::passthrough::RestoredRoles;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicUsize;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krun-v9-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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
    fn qcow2(&self, name: &str) -> File {
        assert!(std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .arg(self.path(name))
            .arg("1M")
            .status()
            .unwrap()
            .success());
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(name))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn count(owner: &RamSnapshotVm) -> u16 {
    owner.memory.read_obj(GuestAddress(0x8000)).unwrap()
}
fn advanced(owner: &RamSnapshotVm, before: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while count(owner) == before {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}
fn guest(fixture: &Fixture) -> RamSnapshotVm {
    let mut vm = crate::builder::build_ram_snapshot_vm(
        2,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    vm.memory
        .write_slice(include_bytes!("guest.bin"), GuestAddress(0x1000))
        .unwrap();
    vm.attach_disk(
        &fixture.path("source.qcow2"),
        ImageType::Qcow2,
        false,
        false,
    )
    .unwrap();
    vm.attach_disk(&fixture.path("boot.ext4"), ImageType::Raw, true, false)
        .unwrap();
    vm.attach_fs(virtio_fs::FsShareConfig {
        tag: "external".into(),
        source: fixture.path("share"),
        read_only: false,
        allow_root_dir_delete: false,
        vm_owned: false,
        dax: None,
    })
    .unwrap();
    vm.start_vcpus(1, 0x1000).unwrap();
    advanced(&vm, 0);
    vm
}
fn config() -> ExportMetadata {
    ExportMetadata {
        application_schema: 1,
        application: serde_json::json!({"execution":"v9-test"}),
        objects: vec![vec![]],
    }
}
fn bindings(disk: File, boot: File, root: PathBuf) -> ImportBindings {
    ImportBindings {
        disks: vec![disk, boot],
        shares: vec![ShareBinding {
            root,
            objects: vec![],
            roles: RestoredRoles::default(),
        }],
    }
}

#[test]
fn snapshot_v9_kvm_memory_external_pair_continues_and_reexports() {
    let f = Fixture::new();
    drop(f.qcow2("source.qcow2"));
    fs::write(f.path("boot.ext4"), vec![0x61; 65537]).unwrap();
    fs::create_dir(f.path("share")).unwrap();
    let secret = b"UNTOUCHED-SHARE-CONTENT-MUST-NOT-BE-IN-MEMORY-FILE";
    fs::write(f.path("share/untouched"), secret).unwrap();
    let mut source = guest(&f);
    source.declare_host_writers_stopped().unwrap();
    source.pause().unwrap();
    let cut = count(&source);
    let prepared = source.prepare_checkpoint().unwrap();
    assert!(prepared.files.is_empty()); // inactive share did not discover any files
    fs::copy(f.path("source.qcow2"), f.path("snapshot.qcow2")).unwrap();
    let disk = OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.path("snapshot.qcow2"))
        .unwrap();
    source
        .export_fd(
            f.writable("snapshot.mem"),
            disk.try_clone().unwrap(),
            config(),
        )
        .unwrap();
    assert_eq!(count(&source), cut);
    let memory = File::open(f.path("snapshot.mem")).unwrap();
    let inspected = inspect(&memory).unwrap();
    assert!(std::str::from_utf8(&inspected)
        .unwrap()
        .contains("execution"));
    let dependencies: serde_json::Value = serde_json::from_slice(&inspected).unwrap();
    assert_eq!(
        dependencies["disk_dependencies"][1]["external_readonly_boot"]["length"],
        65537
    );
    assert!(!fs::read(f.path("snapshot.mem"))
        .unwrap()
        .windows(secret.len())
        .any(|bytes| bytes == secret));
    // O_APPEND changes Linux pwrite semantics, so reject it before writing any bytes.
    source.prepare_checkpoint().unwrap();
    let append = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .open(f.path("append.mem"))
        .unwrap();
    assert!(source
        .export_fd(append, disk.try_clone().unwrap(), config())
        .is_err());
    assert_eq!(fs::metadata(f.path("append.mem")).unwrap().len(), 0);
    let original_digest = format::digest(&disk, 0, disk.metadata().unwrap().len()).unwrap();
    let boot = File::open(f.path("boot.ext4")).unwrap();
    drop(source);
    fs::remove_file(f.path("source.qcow2")).unwrap();
    fs::remove_file(f.path("boot.ext4")).unwrap(); // exact retained dependency, never regenerated
    fs::copy(f.path("snapshot.qcow2"), f.path("owned.qcow2")).unwrap();
    let owned = OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.path("owned.qcow2"))
        .unwrap();
    let mut target = RamSnapshotVm::import_fd(
        memory,
        bindings(owned, boot, f.path("share")),
        RestoreResources::default(),
    )
    .unwrap();
    assert_eq!(count(&target), cut);
    assert_eq!(target.run_state(), super::super::RunState::Paused);
    target.resume().unwrap();
    advanced(&target, cut);
    assert_eq!(
        target.memory.read_obj::<u16>(GuestAddress(0x8002)).unwrap(),
        0
    );
    assert_eq!(
        target.memory.read_obj::<u16>(GuestAddress(0x8004)).unwrap(),
        1
    );
    target.declare_host_writers_stopped().unwrap();
    target.pause().unwrap();
    target.prepare_checkpoint().unwrap();
    fs::copy(f.path("owned.qcow2"), f.path("second.qcow2")).unwrap();
    let second = File::open(f.path("second.qcow2")).unwrap();
    target
        .export_fd(f.writable("second.mem"), second, config())
        .unwrap();
    assert_eq!(
        format::digest(&disk, 0, disk.metadata().unwrap().len()).unwrap(),
        original_digest
    );
}

#[test]
fn snapshot_v9_external_disk_integrity_and_role_refusals() {
    let f = Fixture::new();
    let qcow = f.qcow2("disk.qcow2");
    let boot = f.writable("boot");
    boot.write_all_at(b"exact boot", 0).unwrap();
    let boot = File::open(f.path("boot")).unwrap();
    let envelope = format::Envelope {
        metadata: vec![],
        payload: 0,
        disk_len: qcow.metadata().unwrap().len(),
        disk_hash: format::digest(&qcow, 0, qcow.metadata().unwrap().len()).unwrap(),
    };
    let deps = [
        DiskDependency::ContainerQcow2,
        DiskDependency::ExternalReadonlyBoot {
            length: 10,
            sha256: format::digest(&boot, 0, 10).unwrap(),
        },
    ];
    verify_disks(
        &deps,
        &[qcow.try_clone().unwrap(), boot.try_clone().unwrap()],
        &envelope,
    )
    .unwrap();
    assert!(verify_disks(
        &deps,
        &[
            File::open(f.path("disk.qcow2")).unwrap(),
            boot.try_clone().unwrap()
        ],
        &envelope
    )
    .is_err());
    let wrong = f.writable("wrong");
    wrong.write_all_at(b"wrong boot", 0).unwrap();
    assert!(verify_disks(
        &deps,
        &[
            qcow.try_clone().unwrap(),
            File::open(f.path("wrong")).unwrap()
        ],
        &envelope
    )
    .is_err());
    assert!(verify_disks(&deps, &[qcow.try_clone().unwrap()], &envelope).is_err());
    qcow.write_all_at(&1234u64.to_be_bytes(), 8).unwrap();
    assert!(verify_qcow2(&qcow).is_err());
}

mod continuation;
