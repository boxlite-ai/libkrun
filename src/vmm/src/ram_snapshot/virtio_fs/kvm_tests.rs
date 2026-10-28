// SPDX-License-Identifier: Apache-2.0

//! virtio-fs lifecycle tests on a real KVM VM. The guest runs the fixture's
//! MMIO entry (0x900, loaded at 0x1000): every register access of the
//! share — status, features, queue setup, notifications, interrupt status —
//! and every DAX window access is a real 32-bit access by the guest vCPU at
//! an absolute guest address, requested through the fixture's RAM mailbox,
//! while the fixture's loop counter proves CPU continuation and its vector
//! 0x29 handler counts the share's interrupts (GSI 9). FUSE requests and
//! replies live in guest RAM (`tests::Fuse`). Every test name contains
//! "snapshot" for `make snapshot-test`.
//!
//! These tests require Linux/KVM. Share contents remain external and the
//! descriptor fixtures run without privileged archive capture.

use std::fs;
use std::sync::atomic::fence;
use std::time::{Duration, Instant};

use devices::virtio::fs::fuse::{self, Opcode};
use devices::virtio::fs::passthrough::DaxMappingControl;
use vm_memory::{Bytes, GuestAddress};

use super::tests::{Fuse, TempDir, INT_VRING, REQUEST};
use super::*;
use crate::ram_snapshot::console::tests::{wait_until, Driver, Mmio, QUIET, WAIT};
use crate::ram_snapshot::{DaxRange, FsShareConfig, RestoreResources};

const RAM_MIB: usize = 2;
const MMIO_ENTRY: u16 = 0x1900;
const MAILBOX: u64 = 0x9100;
const COUNTER: u64 = 0x9120;
/// The fixture's vector 0x29 (GSI 9, share 0) handler counts here.
const IRQ_COUNT: u64 = 0x9126;
const OP_WRITE: u32 = 1;
const OP_READ: u32 = 2;
const OP_STI: u32 = 3;
const PAGE: u64 = 4096;
/// A real-mode loop for every vCPU, `inc word [COUNTER]; jmp` back to it,
/// below the fixture.
const SPIN: [u8; 6] = [0xff, 0x06, 0x20, 0x91, 0xeb, 0xfa];
const SPIN_ENTRY: u16 = 0x500;
/// Inside the fixture's 4 GiB data segment, clear of RAM, the MMIO slots
/// and the architectural windows.
const DAX: DaxRange = DaxRange {
    gpa: 0x8000_0000,
    len: 0x20_0000,
};

/// The guest vCPU performs each 32-bit access at an absolute address; the
/// call returns once the guest recorded it as done. As `Mmio` it targets
/// share 0's slot.
struct Guest<'a>(&'a RamSnapshotVm);

impl Guest<'_> {
    fn sti(&self) {
        self.request(OP_STI, 0, 0);
    }

    fn read32(&self, addr: u64) -> u32 {
        self.request(OP_READ, addr, 0)
    }

    fn write32(&self, addr: u64, value: u32) {
        self.request(OP_WRITE, addr, value);
    }

    fn request(&self, op: u32, addr: u64, value: u32) -> u32 {
        let mem = &self.0.memory;
        let at = |field: u64| GuestAddress(MAILBOX + field);
        let seq = mem.read_obj::<u32>(at(0)).unwrap().wrapping_add(1);
        mem.write_obj(op, at(4)).unwrap();
        mem.write_obj(u32::try_from(addr).unwrap(), at(8)).unwrap();
        mem.write_obj(value, at(0xc)).unwrap();
        fence(std::sync::atomic::Ordering::SeqCst);
        mem.write_obj(seq, at(0)).unwrap();
        let deadline = Instant::now() + WAIT;
        while mem.read_obj::<u32>(at(0x10)).unwrap() != seq {
            assert!(
                Instant::now() < deadline,
                "the guest did not perform the access"
            );
            std::thread::yield_now();
        }
        fence(std::sync::atomic::Ordering::SeqCst);
        mem.read_obj(at(0xc)).unwrap()
    }
}

impl Mmio for Guest<'_> {
    fn write(&self, offset: u64, value: u32) {
        self.write32(FS_MMIO_BASE + offset, value);
    }

    fn read(&self, offset: u64) -> u32 {
        self.read32(FS_MMIO_BASE + offset)
    }
}

fn read16(vm: &RamSnapshotVm, addr: u64) -> u16 {
    vm.memory.read_obj(GuestAddress(addr)).unwrap()
}

fn wait_counter(vm: &RamSnapshotVm, previous: u16) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let current = read16(vm, COUNTER);
        if current != previous {
            return current;
        }
        assert!(Instant::now() < deadline, "guest counter stopped");
        std::thread::yield_now();
    }
}

fn fixture() -> RamSnapshotVm {
    let vm = crate::builder::build_ram_snapshot_vm(
        RAM_MIB,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    vm.memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    vm
}

fn share(source: &Path, dax: Option<DaxRange>) -> FsShareConfig {
    FsShareConfig {
        tag: "share".into(),
        source: source.to_owned(),
        read_only: false,
        allow_root_dir_delete: false,
        vm_owned: false,
        dax,
    }
}

/// A running owner with one share (and its DAX window) attached before the
/// CPU starts.
fn source(dir: &Path) -> RamSnapshotVm {
    let mut vm = fixture();
    vm.attach_fs(share(dir, Some(DAX))).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    wait_counter(&vm, 0);
    vm
}

/// A share directory holding "f", one page of 0x33.
fn share_dir(dir: &TempDir) -> PathBuf {
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), vec![0x33; PAGE as usize]).unwrap();
    src
}

/// The guest's handle on "f" and the mapping of its first page at window
/// offset 0, written once through the handle ("hello") and once through
/// the window ("ABCD" at 8), with interrupts still off.
fn bring_up(vm: &RamSnapshotVm) -> (Fuse, u64, u64) {
    let guest = Guest(vm);
    let mut client = Fuse::new();
    client.activate(&guest);
    client.init(&vm.memory, &guest);
    let f = client.lookup(&vm.memory, &guest, fuse::ROOT_ID, b"f");
    let fh = client.open(&vm.memory, &guest, f.nodeid, libc::O_RDWR);
    let write = Fuse::write_body(fh, 0, b"hello");
    client.ok(&vm.memory, &guest, Opcode::Write, f.nodeid, &write);
    let mapping = Fuse::mapping_body(fh, 0, PAGE, 0, true);
    client.ok(&vm.memory, &guest, Opcode::SetupMapping, f.nodeid, &mapping);
    assert_eq!(guest.read32(DAX.gpa), u32::from_le_bytes(*b"hell"));
    guest.write32(DAX.gpa + 8, u32::from_le_bytes(*b"ABCD"));
    (client, f.nodeid, fh)
}

/// Attachments are checked whichever comes first: a DAX window over RAM,
/// an existing slot or the local APIC is refused without effect, a device
/// attached later over a window is refused, and at most seven shares with
/// distinct tags attach before the CPUs start.
#[test]
fn snapshot_fs_kvm_attachments_check_layout_in_every_order() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = fixture();
    vm.attach_rng().unwrap();
    for gpa in [0, 0xd000_9000, 0xfee0_0000] {
        let range = DaxRange { gpa, len: PAGE };
        assert!(vm.attach_fs(share(&src, Some(range))).is_err());
    }
    vm.attach_fs(share(&src, Some(DAX))).unwrap();
    assert!(vm.attach_fs(share(&src, None)).is_err(), "a repeated tag");
    for index in 1..MAX_SHARES {
        let mut config = share(&src, None);
        config.tag = format!("share{index}");
        vm.attach_fs(config).unwrap();
    }
    let mut eighth = share(&src, None);
    eighth.tag = "eighth".into();
    assert!(vm.attach_fs(eighth).is_err());

    // A window over the balloon's slot refuses the balloon attached later.
    let mut vm = fixture();
    let over_balloon = DaxRange {
        gpa: 0xd000_a000,
        len: PAGE,
    };
    vm.attach_fs(share(&src, Some(over_balloon))).unwrap();
    assert!(vm.attach_balloon().is_err());
}

/// Two running vCPUs of an owner with a DAX window: a remapping runs only
/// while neither executes guest code (the counter both increment stands
/// still) and both continue after it; a failed remapping ends both without
/// any pause, and the next pause disables the owner, joining them.
#[test]
fn snapshot_fs_kvm_dax_remapping_stops_every_vcpu_and_failure_ends_them() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = fixture();
    vm.memory
        .write_slice(&SPIN, GuestAddress(SPIN_ENTRY.into()))
        .unwrap();
    vm.attach_fs(share(&src, Some(DAX))).unwrap();
    vm.start_vcpus(2, SPIN_ENTRY).unwrap();
    wait_counter(&vm, 0);
    let mut frozen = None;
    vm.execution.exclusive(&mut || {
        let before = read16(&vm, COUNTER);
        std::thread::sleep(QUIET);
        frozen = Some((before, read16(&vm, COUNTER)));
        true
    });
    let (before, after) = frozen.unwrap();
    assert_eq!(before, after, "a vCPU ran during the remapping");
    wait_counter(&vm, after);

    vm.execution.exclusive(&mut || false);
    wait_until("both vCPUs ended", || {
        vm.handles
            .iter()
            .all(crate::vstate::VcpuHandle::is_finished)
    });
    let ended = read16(&vm, COUNTER);
    std::thread::sleep(QUIET);
    assert_eq!(read16(&vm, COUNTER), ended);
    assert!(vm.pause().is_err());
    assert!(vm.control.unusable);
}

/// A remapping that fails while the devices resume (a resumed worker's
/// queued DAX request) fails the resume before any vCPU runs: the owner is
/// disabled and the guest counter never moves again.
#[test]
fn snapshot_fs_kvm_dax_failure_during_resume_resumes_no_vcpu() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = source(&src);
    vm.pause().unwrap();
    let paused_at = read16(&vm, COUNTER);
    crate::ram_snapshot::lifecycle::FAIL_REMAPPING_ON_RESUME.with(|fail| fail.set(true));
    assert!(vm.resume().is_err());
    assert!(vm.control.unusable);
    assert!(vm
        .handles
        .iter()
        .all(crate::vstate::VcpuHandle::is_finished));
    std::thread::sleep(QUIET);
    assert_eq!(read16(&vm, COUNTER), paused_at);
}

/// Full v9 import consumes provider objects/roles before restoring an active FUSE/DAX device.
#[test]
fn snapshot_fs_kvm_v9_external_orphan_session_and_dax_continue() {
    use crate::snapshot_vm::checkpoint::{
        ExportMetadata, ExternalReference, ImportBindings, ShareBinding,
    };
    use devices::virtio::block::ImageType;
    use devices::virtio::fs::passthrough::RestoredRoles;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
    let dir = TempDir::new();
    let root = share_dir(&dir);
    let disk = dir.path("source.qcow2");
    assert!(std::process::Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&disk)
        .arg("1M")
        .status()
        .unwrap()
        .success());
    let mut vm = fixture();
    vm.attach_disk(&disk, ImageType::Qcow2, false, false)
        .unwrap();
    vm.attach_fs(share(&root, Some(DAX))).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    wait_counter(&vm, 0);
    let mut fuse = Fuse::new();
    fuse.activate(&Guest(&vm));
    fuse.init(&vm.memory, &Guest(&vm));
    let inode = fuse
        .lookup(&vm.memory, &Guest(&vm), fuse::ROOT_ID, b"f")
        .nodeid;
    let handle = fuse.open(&vm.memory, &Guest(&vm), inode, libc::O_RDWR);
    // Provider preopens independent descriptions while the external object still has a name.
    let handle_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("f"))
        .unwrap();
    let dax_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("f"))
        .unwrap();
    let root_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(&root)
        .unwrap();
    let mapping = Fuse::mapping_body(handle, 0, PAGE, PAGE, true);
    fuse.ok(
        &vm.memory,
        &Guest(&vm),
        Opcode::SetupMapping,
        inode,
        &mapping,
    );
    Guest(&vm).write32(DAX.gpa + PAGE, 0xaabbccdd);
    fuse.ok(
        &vm.memory,
        &Guest(&vm),
        Opcode::Unlink,
        fuse::ROOT_ID,
        b"f\0",
    );
    // Forget the lookup as well: the unlinked object now survives only via
    // its open handle and writable DAX role, without a path-only inode FD.
    let before_forget = Driver::used(&vm.memory, REQUEST).len();
    fuse.post(&vm.memory, Opcode::Forget, inode, &1u64.to_ne_bytes());
    Guest(&vm).write(0x50, REQUEST as u32);
    wait_until("forget completion", || {
        Driver::used(&vm.memory, REQUEST).len() == before_forget + 1
    });
    use std::os::fd::AsRawFd;
    let identity = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(format!("/proc/self/fd/{}", handle_fd.as_raw_fd()))
        .unwrap();
    assert_eq!(
        identity.metadata().unwrap().ino(),
        handle_fd.metadata().unwrap().ino()
    );
    let flags = unsafe { libc::fcntl(identity.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags & libc::O_PATH, 0);
    assert_eq!(
        flags & libc::O_NOFOLLOW,
        0,
        "proc FD reopen must follow the pinned description"
    );
    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    let prepared = vm.prepare_checkpoint().unwrap();
    let meta: FsMeta = serde_json::from_slice(&prepared.metadata).unwrap();
    assert_eq!(meta.sessions[0].objects.len(), 2);
    assert!(meta.sessions[0]
        .state
        .nodes
        .iter()
        .all(|node| node.inode != inode));
    assert_eq!(meta.sessions[0].state.handles.len(), 1);
    let orphan_ino = identity.metadata().unwrap().ino();
    // Recover an independent provider tree and orphan while the source is
    // frozen; the restored owner must use these new objects exclusively.
    use std::os::unix::ffi::OsStrExt;
    let recovered = dir
        .0
        .join(std::ffi::OsStr::from_bytes(b"recovered-\xff"))
        .join("nested");
    fs::create_dir_all(&recovered).unwrap();
    fs::copy(
        format!("/proc/self/fd/{}", handle_fd.as_raw_fd()),
        recovered.join("f"),
    )
    .unwrap();
    drop((identity, handle_fd, dax_fd, root_fd));
    let handle_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(recovered.join("f"))
        .unwrap();
    let dax_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(recovered.join("f"))
        .unwrap();
    fs::remove_file(recovered.join("f")).unwrap();
    let identity = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(format!("/proc/self/fd/{}", handle_fd.as_raw_fd()))
        .unwrap();
    let root_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(&recovered)
        .unwrap();
    let mut objects = Vec::new();
    for source in &prepared.files {
        objects.push(if source.metadata().unwrap().ino() == orphan_ino {
            identity.try_clone().unwrap()
        } else {
            root_fd.try_clone().unwrap()
        });
    }
    let object = meta.sessions[0]
        .state
        .handles
        .iter()
        .find(|h| h.handle == handle)
        .unwrap()
        .object;
    let refs = (0..objects.len())
        .map(|index| ExternalReference {
            resource_id: "share".into(),
            recovery_point: "retained-cut".into(),
            object_key: format!("object-{index}"),
        })
        .collect();
    fs::copy(&disk, dir.path("snapshot.qcow2")).unwrap();
    let memory = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path("snapshot.mem"))
        .unwrap();
    vm.export_fd(
        memory,
        File::open(dir.path("snapshot.qcow2")).unwrap(),
        ExportMetadata {
            application_schema: 1,
            application: serde_json::Value::Null,
            objects: vec![refs],
        },
    )
    .unwrap();
    let paused = read16(&vm, COUNTER);
    drop(prepared);
    drop(vm);
    fs::remove_file(&disk).unwrap();
    fs::remove_dir_all(&root).unwrap();
    fs::copy(dir.path("snapshot.qcow2"), dir.path("owned.qcow2")).unwrap();
    let probe = handle_fd.try_clone().unwrap();
    let roles = RestoredRoles {
        handles: [(handle, handle_fd)].into(),
        dax: [((object, true), dax_fd)].into(),
    };
    let bindings = ImportBindings {
        disks: vec![OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path("owned.qcow2"))
            .unwrap()],
        shares: vec![ShareBinding {
            root: recovered.clone(),
            objects: objects.into_iter().map(Some).collect(),
            roles,
        }],
    };
    validate_bindings(&meta, &bindings.shares).unwrap();
    let mut target = RamSnapshotVm::import_fd(
        File::open(dir.path("snapshot.mem")).unwrap(),
        bindings,
        RestoreResources::default(),
    )
    .unwrap();
    assert_eq!(
        target.exit_code.load(std::sync::atomic::Ordering::SeqCst),
        i32::MAX,
        "unset guest exit code changed on import"
    );
    assert_eq!(read16(&target, COUNTER), paused);
    target.resume().unwrap();
    wait_counter(&target, paused);
    assert_eq!(Guest(&target).read32(DAX.gpa + PAGE), 0xaabbccdd);
    Guest(&target).write32(DAX.gpa + PAGE, 0x10203040);
    let mut changed = [0; 4];
    probe.read_exact_at(&mut changed, 0).unwrap();
    assert_eq!(u32::from_le_bytes(changed), 0x10203040);
    // Short-read length is an independently preserved baseline defect.
    let mut expected = vec![0; PAGE as usize];
    probe.read_exact_at(&mut expected, 0).unwrap();
    let read = Fuse::read_body(handle, 0, PAGE as u32);
    let reply = fuse.ok(&target.memory, &Guest(&target), Opcode::Read, inode, &read);
    assert_eq!(reply, expected);
    assert!(
        !recovered.join("f").exists(),
        "orphan was recreated as a named archive file"
    );
    target.declare_host_writers_stopped().unwrap();
    target.pause().unwrap();
    assert_eq!(target.prepare_checkpoint().unwrap().files.len(), 2);
    drop(target);
    assert!(
        recovered.is_dir(),
        "teardown removed caller-owned recovered share"
    );
}

/// A deterministic boot root on a different tree, with a live directory
/// stream, an unnotified FUSE request, anonymous DAX and a posted exit code.
#[cfg(feature = "blk")]
#[test]
fn snapshot_fs_v9_boot_recipe_cursor_queued_request_and_posted_exit_continue() {
    use crate::ram_snapshot::test_fixture::attach_disk;
    use crate::snapshot_vm::checkpoint::{ExportMetadata, ImportBindings, ShareBinding};
    use devices::virtio::fs::fuse::{IoctlIn, OpenIn, OpenOut};
    use devices::virtio::fs::passthrough::RestoredRoles;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use vm_memory::ByteValued;
    let dir = TempDir::new();
    let root = dir.path("recipe-source");
    let recovered = dir.path("recipe-recovered");
    for base in [&root, &recovered] {
        fs::create_dir(base).unwrap();
        for name in ["dev", "proc", "sys", "newroot"] {
            fs::create_dir(base.join(name)).unwrap();
        }
    }
    let mut vm = fixture();
    attach_disk(&mut vm);
    vm.attach_fs(FsShareConfig {
        tag: "/dev/root".into(),
        source: root.clone(),
        vm_owned: true,
        allow_root_dir_delete: true,
        read_only: false,
        dax: Some(DAX),
    })
    .unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    let mut client = Fuse::new();
    client.activate(&Guest(&vm));
    client.init(&vm.memory, &Guest(&vm));
    let open = OpenIn {
        flags: libc::O_RDONLY as u32,
        open_flags: 0,
    };
    let reply = client.ok(
        &vm.memory,
        &Guest(&vm),
        Opcode::Opendir,
        fuse::ROOT_ID,
        open.as_slice(),
    );
    let directory = OpenOut::from_slice(&reply).unwrap().fh;
    let all = client.ok(
        &vm.memory,
        &Guest(&vm),
        Opcode::Readdir,
        fuse::ROOT_ID,
        &Fuse::read_body(directory, 0, 4096),
    );
    let first_cookie = u64::from_ne_bytes(all[8..16].try_into().unwrap());
    let name_len = u32::from_ne_bytes(all[16..20].try_into().unwrap()) as usize;
    let first_len = (24 + name_len + 7) & !7;
    let suffix = all[first_len..].to_vec();
    let ioctl = IoctlIn {
        cmd: (b'v' as u32) << 8 | 2,
        arg: 3,
        ..Default::default()
    };
    client.ok(
        &vm.memory,
        &Guest(&vm),
        Opcode::Ioctl,
        fuse::ROOT_ID,
        ioctl.as_slice(),
    );
    assert_eq!(vm.exit_code.load(std::sync::atomic::Ordering::SeqCst), 3);
    Guest(&vm).write32(DAX.gpa, 0xfeed1234);
    vm.pause().unwrap();
    let undeclared = vm
        .prepare_checkpoint()
        .err()
        .expect("undeclared host writers accepted");
    assert!(
        undeclared
            .to_string()
            .contains("declare_host_writers_stopped"),
        "{undeclared}"
    );
    vm.resume().unwrap();
    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    let before = Driver::used(&vm.memory, REQUEST).len();
    let (unique, pending_reply) =
        client.post(&vm.memory, Opcode::Lookup, fuse::ROOT_ID, b"newroot\0");
    let prepared = vm.prepare_checkpoint().unwrap();
    let meta: FsMeta = serde_json::from_slice(&prepared.metadata).unwrap();
    assert_eq!(meta.exit_code, 3);
    assert!(prepared.files.len() > 0);
    assert!(meta.sessions[0]
        .objects
        .iter()
        .all(|object| object.recipe.is_some() && object.reference.is_none()));
    let memory_path = dir.path("recipe.mem");
    let disk_path = dir.path("recipe.qcow2");
    assert!(std::process::Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&disk_path)
        .arg("1M")
        .status()
        .unwrap()
        .success());
    vm.export_fd(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&memory_path)
            .unwrap(),
        File::open(&disk_path).unwrap(),
        ExportMetadata {
            application_schema: 1,
            application: serde_json::Value::Null,
            objects: vec![vec![]],
        },
    )
    .unwrap();
    drop(prepared);
    drop(vm);
    assert!(!root.exists(), "source-owned root survived teardown");
    let role = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(&recovered)
        .unwrap();
    let mut target = RamSnapshotVm::import_fd(
        File::open(&memory_path).unwrap(),
        ImportBindings {
            disks: vec![OpenOptions::new()
                .read(true)
                .write(true)
                .open(&disk_path)
                .unwrap()],
            shares: vec![ShareBinding {
                root: recovered.clone(),
                objects: vec![],
                roles: RestoredRoles {
                    handles: [(directory, role)].into(),
                    dax: Default::default(),
                },
            }],
        },
        RestoreResources::default(),
    )
    .unwrap();
    assert_eq!(
        target.exit_code.load(std::sync::atomic::Ordering::SeqCst),
        3
    );
    assert_eq!(Driver::used(&target.memory, REQUEST).len(), before);
    target.resume().unwrap();
    wait_until("queued request after v9 restore", || {
        Driver::used(&target.memory, REQUEST).len() == before + 1
    });
    let (header, _) = Fuse::reply(&target.memory, pending_reply);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0);
    std::thread::sleep(QUIET);
    assert_eq!(
        Driver::used(&target.memory, REQUEST).len(),
        before + 1,
        "queued FUSE request repeated"
    );
    assert_eq!(Guest(&target).read32(DAX.gpa), 0xfeed1234);
    let continued = client.ok(
        &target.memory,
        &Guest(&target),
        Opcode::Readdir,
        fuse::ROOT_ID,
        &Fuse::read_body(directory, first_cookie, 4096),
    );
    assert_eq!(
        continued, suffix,
        "saved directory cookies/order/inode projection changed"
    );
    let remove = IoctlIn {
        cmd: (b'v' as u32) << 8 | 3,
        ..Default::default()
    };
    client.ok(
        &target.memory,
        &Guest(&target),
        Opcode::Ioctl,
        fuse::ROOT_ID,
        remove.as_slice(),
    );
    assert!(
        recovered.join("newroot").is_dir(),
        "guest removal was not deferred"
    );
    target.pause().unwrap();
    let undeclared = target
        .prepare_checkpoint()
        .err()
        .expect("resume kept host-writer declaration");
    assert!(
        undeclared
            .to_string()
            .contains("declare_host_writers_stopped"),
        "{undeclared}"
    );
    target.resume().unwrap();
    target.declare_host_writers_stopped().unwrap();
    target.pause().unwrap();
    target.prepare_checkpoint().unwrap();
    drop(target);
    assert!(
        recovered.join("newroot").is_dir(),
        "import teardown removed caller-owned recipe root"
    );
}
