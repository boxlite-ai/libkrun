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
//! Their execution is UNVERIFIED until run on a Linux KVM host (see the
//! README's stage-12 validation status); the archive capture also needs
//! root with CAP_SYS_ADMIN.

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

fn resources(fs_dir: &Path) -> RestoreResources {
    RestoreResources {
        fs_dir: Some(fs_dir.to_owned()),
        ..Default::default()
    }
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

/// A share continues on an independent copy after its source VM and
/// directory are gone: the CPU continues from the cut, the interrupt
/// raised before the cut (interrupts off) is delivered once by the
/// restored irqchip, the original handle reads and writes the copy, and
/// the guest's DAX window maps the copy.
#[test]
fn snapshot_fs_kvm_restored_guest_continues_handles_dax_and_irq() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = source(&src);
    let (mut client, nodeid, fh) = bring_up(&vm);
    assert_eq!(
        &fs::read(src.join("f")).unwrap()[..12],
        b"hello\x33\x33\x33ABCD"
    );
    assert_ne!(Guest(&vm).read(0x60) & INT_VRING, 0);
    assert_eq!(read16(&vm, IRQ_COUNT), 0);

    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    let paused_at = read16(&vm, COUNTER);
    let image = dir.path("image");
    vm.export(&image).unwrap();
    drop(vm);
    fs::remove_dir_all(&src).unwrap();

    let shares = dir.path("shares");
    let mut target = RamSnapshotVm::import(&image, resources(&shares)).unwrap();
    assert_eq!(read16(&target, COUNTER), paused_at);
    // The copies are the owner's own: it exports again before it runs.
    target.export(&dir.path("again")).unwrap();
    target.resume().unwrap();
    wait_counter(&target, paused_at);
    let guest = Guest(&target);
    assert_ne!(guest.read(0x60) & INT_VRING, 0);
    std::thread::sleep(QUIET);
    assert_eq!(read16(&target, IRQ_COUNT), 0, "taken with IF=0");
    guest.sti();
    wait_until("pending IRQ", || read16(&target, IRQ_COUNT) == 1);
    guest.write(0x64, INT_VRING);

    let read = Fuse::read_body(fh, 0, PAGE as u32);
    let data = client.ok(&target.memory, &guest, Opcode::Read, nodeid, &read);
    assert_eq!(&data[..12], b"hello\x33\x33\x33ABCD");
    let write = Fuse::write_body(fh, 0, b"HE");
    client.ok(&target.memory, &guest, Opcode::Write, nodeid, &write);
    assert_eq!(guest.read32(DAX.gpa), u32::from_le_bytes(*b"HEll"));
    guest.write32(DAX.gpa + 12, u32::from_le_bytes(*b"WXYZ"));
    let copy = shares.join("0").join("f");
    assert_eq!(
        &fs::read(&copy).unwrap()[..16],
        b"HEllo\x33\x33\x33ABCDWXYZ"
    );
    // New replies interrupt the guest again.
    wait_until("reply IRQ", || read16(&target, IRQ_COUNT) > 1);
    assert_eq!(Driver::used(&target.memory, REQUEST).len(), 7);
}

/// Exports with shares need the caller's declaration, made while running
/// and kept through a pause; resume clears it and an undeclared export
/// creates nothing.
#[test]
fn snapshot_fs_kvm_exports_need_host_writers_declared_stopped() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = fixture();
    vm.attach_fs(share(&src, Some(DAX))).unwrap();
    assert!(vm.declare_host_writers_stopped().is_err(), "before start");
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    vm.pause().unwrap();
    assert!(vm.declare_host_writers_stopped().is_err(), "while paused");
    let refused = dir.path("refused");
    assert!(vm.export(&refused).is_err());
    assert!(!refused.exists());
    vm.resume().unwrap();
    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    vm.export(&dir.path("first")).unwrap();
    vm.export(&dir.path("second")).unwrap();
    vm.resume().unwrap();
    vm.pause().unwrap();
    assert!(vm.export(&refused).is_err(), "resume cleared it");
    assert!(!refused.exists());
}

/// The archive mode is chosen before the CPUs start; a guest-visible
/// export records the exporter's IDs in the image, and the imported owner
/// keeps exporting in that mode.
#[test]
fn snapshot_fs_kvm_archive_mode_is_set_before_start_and_kept_by_import() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = fixture();
    vm.attach_fs(share(&src, Some(DAX))).unwrap();
    vm.set_fs_archive_mode(ArchiveMode::GuestVisible).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    assert!(vm.set_fs_archive_mode(ArchiveMode::FullAttributes).is_err());
    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    let image = dir.path("image");
    vm.export(&image).unwrap();
    let bytes = fs::read(&image).unwrap();
    let len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let json: serde_json::Value = serde_json::from_slice(&bytes[16..16 + len]).unwrap();
    // SAFETY: these calls only return the effective IDs.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    assert_eq!(
        json["fs"]["archive"]["contract"],
        serde_json::json!({"guest_visible": {"uid": uid, "gid": gid}})
    );
    drop(vm);
    let target = RamSnapshotVm::import(&image, resources(&dir.path("shares"))).unwrap();
    assert_eq!(target.fs_archive_mode, ArchiveMode::GuestVisible);
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

/// An import needs exactly its share directory: a missing one or an
/// existing one is refused, the existing one untouched, before the import
/// creates anything; a failed export leaves no image and the source paused.
#[test]
fn snapshot_fs_kvm_imports_need_a_new_share_directory() {
    let dir = TempDir::new();
    let src = share_dir(&dir);
    let mut vm = source(&src);
    bring_up(&vm);
    vm.declare_host_writers_stopped().unwrap();
    vm.pause().unwrap();
    let image = dir.path("image");
    vm.export(&image).unwrap();
    assert!(vm.export(&image).is_err(), "never overwrites an image");
    assert!(vm.is_paused());
    drop(vm);

    assert!(RamSnapshotVm::import(&image, RestoreResources::default()).is_err());
    let existing = dir.path("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), b"keep").unwrap();
    assert!(RamSnapshotVm::import(&image, resources(&existing)).is_err());
    assert_eq!(fs::read(existing.join("keep")).unwrap(), b"keep");
    let target = RamSnapshotVm::import(&image, resources(&dir.path("shares"))).unwrap();
    drop(target);
    // A successful import keeps its copies.
    assert!(dir.path("shares").join("0").join("f").is_file());
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
