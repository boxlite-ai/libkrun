// SPDX-License-Identifier: Apache-2.0

//! Vsock lifecycle tests on a real KVM VM. The guest is the stage-2
//! real-mode counter fixture, which proves CPU continuation; the test plays
//! the virtio-vsock driver through the owner's MMIO bus and guest RAM (like
//! the NIC tests), so no guest driver code runs. Real Unix sockets are the
//! host side. Every test name contains "snapshot" for `make snapshot-test`.

#![cfg(feature = "blk")]

use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use vm_memory::{Bytes, GuestAddress};

use super::tests::{
    wait, Driver, GUEST_CID, GUEST_PORT, HOST_PORT, OP_REQUEST, OP_RESPONSE, OP_RW, QSIZE, RINGS,
};
use super::*;
use crate::ram_snapshot::test_fixture::{attach_disk, DescriptorFixture};
use crate::ram_snapshot::RestoreResources;

const RAM_MIB: usize = 2;
/// CPU 0's continuation counter in the fixture.
const COUNTER: u64 = 0x8000;
const TX: usize = 1;

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Short: Unix socket paths must fit sun_path.
        let path = std::env::temp_dir().join(format!(
            "kvk{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Port HOST_PORT listens at `listen` (host-initiated); HOST_PORT + 1
/// connects guest-initiated connections to the host listener at `host`.
fn port_map(dir: &TempDir, listen: &str, host: &str) -> VsockPorts {
    [
        (HOST_PORT, (dir.path(listen), true)),
        (HOST_PORT + 1, (dir.path(host), false)),
    ]
    .into_iter()
    .collect()
}

fn resources(ports: VsockPorts) -> RestoreResources {
    RestoreResources {
        vsock_ports: Some(ports),
        ..Default::default()
    }
}

/// A running owner with the counter fixture on CPU 0 and the vsock
/// attached before the CPU starts.
fn source(ports: &VsockPorts) -> RamSnapshotVm {
    let mut vm = crate::builder::build_ram_snapshot_vm(
        RAM_MIB,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    vm.memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    attach_disk(&mut vm);
    vm.attach_vsock(GUEST_CID, ports).unwrap();
    vm.start_vcpus(1, 0x1000).unwrap();
    wait_counter(&vm, 0);
    vm
}

fn counter(vm: &RamSnapshotVm) -> u16 {
    vm.memory.read_obj(GuestAddress(COUNTER)).unwrap()
}

fn wait_counter(vm: &RamSnapshotVm, previous: u16) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let current = counter(vm);
        if current != previous {
            return current;
        }
        assert!(Instant::now() < deadline, "guest counter stopped");
        std::thread::yield_now();
    }
}

fn assert_paused(vm: &RamSnapshotVm) {
    let paused_at = counter(vm);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(counter(vm), paused_at, "a CPU ran while paused");
}

fn mmio_write(vm: &RamSnapshotVm, offset: u64, value: u32) {
    assert!(vm
        .bus
        .write(0, VSOCK_MMIO_ADDR + offset, &value.to_le_bytes()));
}

fn mmio_read(vm: &RamSnapshotVm, offset: u64) -> u32 {
    let mut bytes = [0u8; 4];
    assert!(vm.bus.read(0, VSOCK_MMIO_ADDR + offset, &mut bytes));
    u32::from_le_bytes(bytes)
}

/// Negotiate VIRTIO_F_VERSION_1 and set up all three queues like a
/// virtio-mmio driver; DRIVER_OK starts the backend.
fn activate(vm: &RamSnapshotVm) {
    assert_eq!(mmio_read(vm, 0x08), TYPE_VSOCK);
    mmio_write(vm, 0x70, 0b0001);
    mmio_write(vm, 0x70, 0b0011);
    mmio_write(vm, 0x24, 1);
    mmio_write(vm, 0x20, 1);
    mmio_write(vm, 0x70, 0b1011);
    for (queue, (desc, avail, used)) in RINGS.into_iter().enumerate() {
        mmio_write(vm, 0x30, queue as u32);
        mmio_write(vm, 0x38, u32::from(QSIZE));
        for (offset, addr) in [(0x80, desc), (0x90, avail), (0xa0, used)] {
            mmio_write(vm, offset, addr as u32);
            mmio_write(vm, offset + 4, 0);
        }
        mmio_write(vm, 0x44, 1);
    }
    mmio_write(vm, 0x70, 0b1111);
    assert_eq!(mmio_read(vm, 0x70), 0b1111, "vsock activation failed");
}

fn kick(vm: &RamSnapshotVm, queue: u32) {
    mmio_write(vm, 0x50, queue);
}

/// Read and acknowledge the transport's interrupt status.
fn take_interrupt(vm: &RamSnapshotVm) -> u32 {
    let status = mmio_read(vm, 0x60);
    mmio_write(vm, 0x64, status);
    status
}

fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}

/// A host-initiated connection the driver accepts.
fn host_connect(vm: &RamSnapshotVm, driver: &mut Driver, path: &Path) -> (UnixStream, u32) {
    let peer = connect(path);
    let request = driver.recv_op(&vm.memory, OP_REQUEST);
    assert_eq!(request.dst_port, HOST_PORT);
    driver.send(&vm.memory, OP_RESPONSE, (HOST_PORT, request.src_port), 0);
    kick(vm, TX as u32);
    (peer, request.src_port)
}

/// A guest-initiated connection to the host listener `listener`.
fn guest_connect(
    vm: &RamSnapshotVm,
    driver: &mut Driver,
    listener: &UnixListener,
    src_port: u32,
) -> UnixStream {
    driver.send(&vm.memory, OP_REQUEST, (src_port, HOST_PORT + 1), 0);
    kick(vm, TX as u32);
    assert_eq!(driver.recv_op(&vm.memory, OP_RESPONSE).dst_port, src_port);
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}

fn assert_closed(peer: &mut UnixStream) {
    let mut sink = Vec::new();
    peer.read_to_end(&mut sink).unwrap();
}

fn assert_no_connection(listener: &UnixListener) {
    listener.set_nonblocking(true).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("a stale request reached the host: {other:?}"),
    }
    listener.set_nonblocking(false).unwrap();
}

/// Source with connections in both directions and stale TX at the cut:
/// two exports of one pause, then a source resume that delivers the reset
/// (and its interrupt) before reopening its original paths. An import at
/// fresh paths is exported again before it ever runs; both images resume
/// with the reset first, no stale request replayed, both directions
/// working and the CPU continuing.
#[test]
fn snapshot_vsock_kvm_pause_export_import_resume_resets_connections() {
    let dir = TempDir::new();
    let ports_a = port_map(&dir, "la.sock", "ha.sock");
    let host_a = UnixListener::bind(dir.path("ha.sock")).unwrap();
    let mut source = source(&ports_a);
    let mut driver = Driver::default();
    activate(&source);
    driver.post_rx(&source.memory, QSIZE);
    kick(&source, 0);
    driver.offer_event(&source.memory);
    let (mut inbound, peer_port) = host_connect(&source, &mut driver, &dir.path("la.sock"));
    let mut outbound = guest_connect(&source, &mut driver, &host_a, GUEST_PORT);

    // Stale at the cut: a REQUEST and an RW, available but never kicked.
    let cut = driver.tx_sent();
    driver.send(
        &source.memory,
        OP_REQUEST,
        (GUEST_PORT + 1, HOST_PORT + 1),
        0,
    );
    driver.send(&source.memory, OP_RW, (HOST_PORT, peer_port), 64);
    take_interrupt(&source);

    source.pause().unwrap();
    assert_paused(&source);
    assert_closed(&mut inbound);
    assert_closed(&mut outbound);
    assert!(!dir.path("la.sock").exists(), "a paused backend listens");
    assert_eq!(Driver::used_idx(&source.memory, TX), driver.tx_sent());
    for n in cut..driver.tx_sent() {
        assert_eq!(Driver::used_elem(&source.memory, TX, n).1, 0);
    }
    assert_eq!(
        Driver::used_idx(&source.memory, 2),
        0,
        "reset before resume"
    );
    let (first, second) = (dir.path("first"), dir.path("second"));
    source.export_test(&first).unwrap();
    source.export_test(&second).unwrap();
    assert_paused(&source);

    // The source resumes on its original configuration, reset first.
    source.resume().unwrap();
    assert_eq!(Driver::used_idx(&source.memory, 2), 1);
    assert!(Driver::is_reset(&source.memory, 0));
    assert_ne!(take_interrupt(&source) & 1, 0, "the owed interrupt");
    wait_counter(&source, counter(&source));
    assert_no_connection(&host_a);
    let _inbound = host_connect(&source, &mut driver, &dir.path("la.sock"));
    let _outbound = guest_connect(&source, &mut driver, &host_a, GUEST_PORT + 2);
    drop(source);

    // Import at fresh paths: paused, nothing bound, exportable again.
    let ports_b = port_map(&dir, "lb.sock", "hb.sock");
    let host_b = UnixListener::bind(dir.path("hb.sock")).unwrap();
    let mut restored = RamSnapshotVm::import_test(&first, resources(ports_b.clone())).unwrap();
    assert_paused(&restored);
    assert!(!dir.path("lb.sock").exists());
    let again = dir.path("again");
    restored.export_test(&again).unwrap();
    drop(restored);

    for image in [&second, &again] {
        let mut restored = RamSnapshotVm::import_test(image, resources(ports_b.clone())).unwrap();
        restored.resume().unwrap();
        assert_eq!(Driver::used_idx(&restored.memory, 2), 1);
        assert!(Driver::is_reset(&restored.memory, 0));
        assert_ne!(mmio_read(&restored, 0x60) & 1, 0, "the owed interrupt");
        wait_counter(&restored, counter(&restored));
        assert_no_connection(&host_b);
        assert!(!dir.path("la.sock").exists(), "the source path came back");
        // The image's rings hold the source driver's buffers.
        let mut target = Driver::from_rings(&restored.memory);
        let _inbound = host_connect(&restored, &mut target, &dir.path("lb.sock"));
        let _outbound = guest_connect(&restored, &mut target, &host_b, GUEST_PORT + 3);
        drop(restored);
        assert!(!dir.path("lb.sock").exists());
    }
}

/// The guest offers no event buffer at resume: the CPU runs while the
/// backend stays closed, and the guest's first event buffer brings the
/// reset and then the listening path. An inactive vsock stays inactive
/// across an import and activates afterwards.
#[test]
fn snapshot_vsock_kvm_reset_waits_for_buffer_and_inactive_stays_inactive() {
    let dir = TempDir::new();
    let ports = port_map(&dir, "la.sock", "ha.sock");
    let mut source = source(&ports);
    let mut driver = Driver::default();
    activate(&source);
    driver.post_rx(&source.memory, QSIZE);
    source.pause().unwrap();
    source.resume().unwrap();
    wait_counter(&source, counter(&source));
    assert!(!dir.path("la.sock").exists(), "opened before the reset");
    driver.offer_event(&source.memory);
    kick(&source, 2);
    wait("the reset", || Driver::used_idx(&source.memory, 2) == 1);
    assert!(Driver::is_reset(&source.memory, 0));
    wait("the listening path", || dir.path("la.sock").exists());
    let _inbound = host_connect(&source, &mut driver, &dir.path("la.sock"));
    drop(source);

    let mut idle = self::source(&ports);
    idle.pause().unwrap();
    let image = dir.path("inactive");
    idle.export_test(&image).unwrap();
    drop(idle);
    let ports_b = port_map(&dir, "lb.sock", "hb.sock");
    let mut restored = RamSnapshotVm::import_test(&image, resources(ports_b)).unwrap();
    assert_eq!(mmio_read(&restored, 0x70), 0, "an inactive vsock activated");
    restored.resume().unwrap();
    activate(&restored);
    let mut target = Driver::default();
    target.post_rx(&restored.memory, QSIZE);
    kick(&restored, 0);
    wait("the listening path", || dir.path("lb.sock").exists());
    let _inbound = host_connect(&restored, &mut target, &dir.path("lb.sock"));
}

/// Wrong or missing vsock resources are rejected before anything is
/// created; a listening path that cannot bind fails the resume, which then
/// disables the owner and joins every thread.
#[test]
fn snapshot_vsock_kvm_resource_errors_and_failed_restart() {
    let dir = TempDir::new();
    let ports = port_map(&dir, "la.sock", "ha.sock");
    let mut source = source(&ports);
    activate(&source);
    Driver::default().offer_event(&source.memory);
    source.pause().unwrap();
    let image = dir.path("checkpoint");
    source.export_test(&image).unwrap();
    drop(source);

    assert!(RamSnapshotVm::import_test(&image, RestoreResources::default()).is_err());
    let mut swapped = port_map(&dir, "lb.sock", "hb.sock");
    swapped.get_mut(&HOST_PORT).unwrap().1 = false;
    assert!(RamSnapshotVm::import_test(&image, resources(swapped)).is_err());
    let mut extra = port_map(&dir, "lb.sock", "hb.sock");
    extra.insert(HOST_PORT + 2, (dir.path("x.sock"), true));
    assert!(RamSnapshotVm::import_test(&image, resources(extra)).is_err());
    assert!(!dir.path("lb.sock").exists());

    let ports_b = port_map(&dir, "lb.sock", "hb.sock");
    fs::write(dir.path("lb.sock"), b"occupied").unwrap();
    let mut restored = RamSnapshotVm::import_test(&image, resources(ports_b)).unwrap();
    assert!(restored.resume().is_err());
    assert!(
        restored.pause().is_err(),
        "a failed resume disables the owner"
    );
    assert_eq!(fs::read(dir.path("lb.sock")).unwrap(), b"occupied");
    let stopped = counter(&restored);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(counter(&restored), stopped, "a CPU runs after the failure");

    // A vsock-free image takes no vsock ports.
    let plain = dir.path("plain");
    {
        let mut vm = crate::builder::build_ram_snapshot_vm(
            RAM_MIB,
            &Default::default(),
            &crate::builder::Payload::Empty,
        )
        .unwrap();
        vm.memory
            .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
            .unwrap();
        attach_disk(&mut vm);
        vm.start_vcpus(1, 0x1000).unwrap();
        vm.pause().unwrap();
        vm.export_test(&plain).unwrap();
    }
    let ports_c = port_map(&dir, "lc.sock", "hc.sock");
    assert!(RamSnapshotVm::import_test(&plain, resources(ports_c)).is_err());
}

/// The vsock's fixed slot and GSI 7 coexist with the RNG and balloon; a
/// second vsock, a reserved CID and a late attach are rejected, and the
/// RAM-only save refuses an owner with a vsock.
#[test]
fn snapshot_vsock_kvm_attach_limits() {
    let dir = TempDir::new();
    let ports = port_map(&dir, "la.sock", "ha.sock");
    let build = || {
        crate::builder::build_ram_snapshot_vm(
            RAM_MIB,
            &Default::default(),
            &crate::builder::Payload::Empty,
        )
        .unwrap()
    };
    let mut vm = build();
    vm.attach_rng().unwrap();
    vm.attach_balloon().unwrap();
    vm.attach_vsock(GUEST_CID, &ports).unwrap();
    assert!(vm.attach_vsock(GUEST_CID, &ports).is_err(), "second vsock");
    assert!(vm.save(&dir.path("ram")).is_err());

    let mut vm = build();
    assert!(vm.attach_vsock(2, &ports).is_err(), "host CID");
    let mut vm = build();
    vm.memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    vm.start_vcpus(1, 0x1000).unwrap();
    assert!(vm.attach_vsock(GUEST_CID, &ports).is_err(), "late attach");
}
