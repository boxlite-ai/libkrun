// SPDX-License-Identifier: Apache-2.0

//! Stage-4 NIC continuation tests on a real KVM VM. The guest is the
//! stage-2 real-mode counter fixture, which proves CPU continuation; the
//! test plays the virtio-net driver through the owner's MMIO bus and guest
//! RAM, so device continuation is checked without guest driver code. A
//! UnixStream server per test stands in for the network backend. Every
//! test name contains "snapshot" for `make snapshot-test`.

use super::*;
use crate::ram_snapshot::tests::with_failed_payload_write;
use crate::ram_snapshot::RestoreResources;
use devices::virtio::block::ImageType;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vm_memory::{Bytes, GuestAddress};

const RAM_MIB: usize = 2;
const QSIZE: u16 = 64;
const VNET_HDR_LEN: usize = 12;
const BUF_LEN: u32 = 2048;
/// Rings and buffers stay clear of the fixture (code 0x1000, CPU areas from
/// 0x8000, stacks below 0xc000).
const RX_DESC: u64 = 0x4_0000;
const RX_AVAIL: u64 = 0x4_1000;
const RX_USED: u64 = 0x4_2000;
const TX_DESC: u64 = 0x4_8000;
const TX_AVAIL: u64 = 0x4_9000;
const TX_USED: u64 = 0x4_a000;
const RX_BUFS: u64 = 0x8_0000;
const TX_BUFS: u64 = 0xc_0000;
/// CPU 0's continuation counter in the fixture.
const COUNTER: u64 = 0x8000;
const MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
/// VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC; no event index, so every used
/// entry needs a notification.
const DRIVER_FEATURES: u64 = (1 << 32) | (1 << 5);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Short: Unix socket paths must fit sun_path.
        let path = std::env::temp_dir().join(format!(
            "krn{}-{}",
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

/// A freshly started UnixStream backend.
struct Backend {
    listener: UnixListener,
    path: PathBuf,
}

impl Backend {
    fn start(path: PathBuf) -> Self {
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { listener, path }
    }

    fn accept(&self) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    return stream;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "the NIC never connected");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }
}

fn resources(disk_dir: Option<&Path>, socket: &Path) -> RestoreResources {
    RestoreResources {
        disk_dir: disk_dir.map(Path::to_owned),
        nic_socket: Some(socket.to_owned()),
        ..Default::default()
    }
}

fn send_frame(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
}

fn recv_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0u8; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut frame).unwrap();
    frame
}

fn assert_idle(stream: &mut UnixStream) {
    stream.set_nonblocking(true).unwrap();
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("backend received unexpected data: {other:?}"),
    }
    stream.set_nonblocking(false).unwrap();
}

fn payload(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag ^ (i as u8)).collect()
}

/// A running source owner with the counter fixture on CPU 0, the NIC and
/// optional disks attached before the CPU starts.
fn source(socket: &Path, disks: &[PathBuf]) -> RamSnapshotVm {
    let mut vm = crate::builder::build_ram_snapshot_vm(
        RAM_MIB,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    vm.memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    vm.memory
        .write_slice(&[0x00, 0x16, 0, 0], GuestAddress(0x20 * 4))
        .unwrap();
    vm.memory
        .write_slice(&[0x80, 0x16, 0, 0], GuestAddress(0x30 * 4))
        .unwrap();
    for disk in disks {
        vm.attach_disk(disk, ImageType::Raw, false, false).unwrap();
    }
    vm.attach_net(socket, MAC, 0).unwrap();
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

/// Host-side virtio-net driver state: what the guest driver would track.
#[derive(Default)]
struct Driver {
    rx_posted: u16,
    tx_posted: u16,
}

impl Driver {
    fn write(vm: &RamSnapshotVm, offset: u64, value: u32) {
        assert!(vm
            .bus
            .write(0, NIC_MMIO_ADDR + offset, &value.to_le_bytes()));
    }

    fn read(vm: &RamSnapshotVm, offset: u64) -> u32 {
        let mut bytes = [0u8; 4];
        assert!(vm.bus.read(0, NIC_MMIO_ADDR + offset, &mut bytes));
        u32::from_le_bytes(bytes)
    }

    /// Negotiate and activate exactly like a virtio-mmio driver; DRIVER_OK
    /// connects the device to its backend.
    fn activate(vm: &RamSnapshotVm) {
        assert_eq!(Self::read(vm, 0x08), TYPE_NET);
        Self::write(vm, 0x70, 0b0001);
        Self::write(vm, 0x70, 0b0011);
        for page in 0..2u32 {
            Self::write(vm, 0x24, page);
            Self::write(vm, 0x20, (DRIVER_FEATURES >> (32 * page)) as u32);
        }
        Self::write(vm, 0x70, 0b1011);
        for (queue, (desc, avail, used)) in
            [(RX_DESC, RX_AVAIL, RX_USED), (TX_DESC, TX_AVAIL, TX_USED)]
                .into_iter()
                .enumerate()
        {
            Self::write(vm, 0x30, queue as u32);
            Self::write(vm, 0x38, u32::from(QSIZE));
            Self::write(vm, 0x80, desc as u32);
            Self::write(vm, 0x84, 0);
            Self::write(vm, 0x90, avail as u32);
            Self::write(vm, 0x94, 0);
            Self::write(vm, 0xa0, used as u32);
            Self::write(vm, 0xa4, 0);
            Self::write(vm, 0x44, 1);
        }
        Self::write(vm, 0x70, 0b1111);
        assert_eq!(Self::read(vm, 0x70), 0b1111, "activation failed");
    }

    fn kick(vm: &RamSnapshotVm, queue: u32) {
        Self::write(vm, 0x50, queue);
    }

    fn interrupt_status(vm: &RamSnapshotVm) -> u32 {
        Self::read(vm, 0x60)
    }

    fn publish(vm: &RamSnapshotVm, avail: u64, posted: u16, head: u16) {
        vm.memory
            .write_obj(
                head,
                GuestAddress(avail + 4 + 2 * u64::from(posted % QSIZE)),
            )
            .unwrap();
        vm.memory
            .write_obj(posted.wrapping_add(1), GuestAddress(avail + 2))
            .unwrap();
    }

    fn post_rx(&mut self, vm: &RamSnapshotVm, count: u16) {
        for _ in 0..count {
            let slot = self.rx_posted % QSIZE;
            let descriptor = devices::virtio::Descriptor {
                addr: RX_BUFS + u64::from(slot) * u64::from(BUF_LEN),
                len: BUF_LEN,
                flags: 2, // VIRTQ_DESC_F_WRITE
                next: 0,
            };
            vm.memory
                .write_obj(descriptor, GuestAddress(RX_DESC + 16 * u64::from(slot)))
                .unwrap();
            Self::publish(vm, RX_AVAIL, self.rx_posted, slot);
            self.rx_posted = self.rx_posted.wrapping_add(1);
        }
    }

    /// Make one TX chain available; the caller decides whether to kick.
    fn submit_tx(&mut self, vm: &RamSnapshotVm, frame: &[u8]) -> u16 {
        let slot = self.tx_posted % QSIZE;
        let addr = TX_BUFS + u64::from(slot) * u64::from(BUF_LEN);
        let mut bytes = vec![0u8; VNET_HDR_LEN];
        bytes.extend_from_slice(frame);
        vm.memory.write_slice(&bytes, GuestAddress(addr)).unwrap();
        let descriptor = devices::virtio::Descriptor {
            addr,
            len: bytes.len() as u32,
            flags: 0,
            next: 0,
        };
        vm.memory
            .write_obj(descriptor, GuestAddress(TX_DESC + 16 * u64::from(slot)))
            .unwrap();
        Self::publish(vm, TX_AVAIL, self.tx_posted, slot);
        self.tx_posted = self.tx_posted.wrapping_add(1);
        slot
    }

    fn used_idx(vm: &RamSnapshotVm, used: u64) -> u16 {
        vm.memory.read_obj(GuestAddress(used + 2)).unwrap()
    }

    fn used_elem(vm: &RamSnapshotVm, used: u64, index: u16) -> (u32, u32) {
        let at = used + 4 + 8 * u64::from(index % QSIZE);
        (
            vm.memory.read_obj(GuestAddress(at)).unwrap(),
            vm.memory.read_obj(GuestAddress(at + 4)).unwrap(),
        )
    }

    fn wait_used(vm: &RamSnapshotVm, used: u64, target: u16) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Self::used_idx(vm, used) != target {
            assert!(
                Instant::now() < deadline,
                "used ring {used:#x} stuck at {} (want {target})",
                Self::used_idx(vm, used)
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn rx_frame(vm: &RamSnapshotVm, index: u16) -> Vec<u8> {
        let (id, len) = Self::used_elem(vm, RX_USED, index);
        let mut frame = vec![0u8; len as usize];
        vm.memory
            .read_slice(
                &mut frame,
                GuestAddress(RX_BUFS + u64::from(id) * u64::from(BUF_LEN)),
            )
            .unwrap();
        frame.split_off(VNET_HDR_LEN)
    }
}

/// Source with active RX/TX, a partial backend frame and TX the device had
/// not consumed at the cut; the restore uses a new backend.
#[test]
fn snapshot_nic_kvm_restore_new_backend_drops_cut_tx_and_continues() {
    let dir = TempDir::new();
    let old = Backend::start(dir.path("a.sock"));
    let mut source = source(&old.path, &[]);
    let mut driver = Driver::default();
    Driver::activate(&source);
    let mut stream = old.accept();

    // Active traffic before the cut: one RX frame, two sent TX frames.
    driver.post_rx(&source, 8);
    Driver::kick(&source, 0);
    let before = payload(1, 100);
    send_frame(&mut stream, &before);
    Driver::wait_used(&source, RX_USED, 1);
    assert_eq!(Driver::rx_frame(&source, 0), before);
    let sent: Vec<_> = (0..2).map(|i| payload(0x10 + i, 300)).collect();
    for frame in &sent {
        driver.submit_tx(&source, frame);
    }
    Driver::kick(&source, 1);
    for frame in &sent {
        assert_eq!(&recv_frame(&mut stream), frame);
    }
    Driver::wait_used(&source, TX_USED, 2);
    // Let the write-space wakeup from those reads settle, then acknowledge
    // every interrupt so the cut starts with a clear status.
    std::thread::sleep(Duration::from_millis(50));
    Driver::write(&source, 0x64, 0b11);
    assert_eq!(Driver::interrupt_status(&source), 0);

    // State at the cut: a partial RX frame in the source worker and three
    // available TX chains the device has not consumed (no kick yet).
    let partial = payload(2, 900);
    stream
        .write_all(&(partial.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&partial[..400]).unwrap();
    // An edge-triggered wakeup for those bytes also reports the socket
    // writable, so the worker examines TX: let it pass before the cut-time
    // chains become available.
    std::thread::sleep(Duration::from_millis(50));
    let cut: Vec<_> = (0..3).map(|i| payload(0x20 + i, 200)).collect();
    let cut_heads: Vec<_> = cut
        .iter()
        .map(|frame| driver.submit_tx(&source, frame))
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(Driver::used_idx(&source, TX_USED), 2);

    let image = dir.path("checkpoint");
    source.save_full(&image).unwrap();

    // The saved source keeps its backend and buffers: the partial frame
    // completes and the cut-time TX is sent there, then the guest runs on.
    stream.write_all(&partial[400..]).unwrap();
    Driver::wait_used(&source, RX_USED, 2);
    assert_eq!(Driver::rx_frame(&source, 1), partial);
    for frame in &cut {
        assert_eq!(&recv_frame(&mut stream), frame);
    }
    Driver::wait_used(&source, TX_USED, 5);
    wait_counter(&source, counter(&source));
    drop(source);
    drop(stream);
    drop(old);

    // Restore with a freshly started backend.
    let new = Backend::start(dir.path("b.sock"));
    let mut restored = RamSnapshotVm::restore_full(&image, resources(None, &new.path)).unwrap();
    let mut stream = new.accept();

    // Before any vCPU runs: the cut-time TX is completed as dropped exactly
    // once, earlier completions are untouched, and the discard raised a
    // fresh used-buffer interrupt (the status was clear at the cut);
    // nothing reached the new backend.
    assert_eq!(Driver::used_idx(&restored, TX_USED), 5);
    for (offset, head) in cut_heads.iter().enumerate() {
        assert_eq!(
            Driver::used_elem(&restored, TX_USED, 2 + offset as u16),
            (u32::from(*head), 0)
        );
    }
    assert_eq!(Driver::used_elem(&restored, TX_USED, 0).0, 0);
    assert_eq!(Driver::used_elem(&restored, TX_USED, 1).0, 1);
    assert_ne!(Driver::interrupt_status(&restored) & 1, 0);
    assert_eq!(Driver::used_idx(&restored, RX_USED), 1);
    let paused_at = counter(&restored);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(
        counter(&restored),
        paused_at,
        "restored CPU ran before resume"
    );
    assert_idle(&mut stream);

    // Resume: the CPU continues, the RX buffers saved at the cut take new
    // frames without a kick, and new TX reaches only the new backend.
    restored.resume().unwrap();
    wait_counter(&restored, paused_at);
    let fresh = payload(3, 120);
    send_frame(&mut stream, &fresh);
    Driver::wait_used(&restored, RX_USED, 2);
    assert_eq!(Driver::rx_frame(&restored, 1), fresh);
    let out = payload(4, 64);
    let head = driver.submit_tx(&restored, &out);
    Driver::kick(&restored, 1);
    assert_eq!(recv_frame(&mut stream), out);
    Driver::wait_used(&restored, TX_USED, 6);
    assert_eq!(
        Driver::used_elem(&restored, TX_USED, 5),
        (u32::from(head), 0)
    );
    std::thread::sleep(Duration::from_millis(30));
    assert_idle(&mut stream);
    assert_eq!(
        Driver::used_idx(&restored, TX_USED),
        6,
        "a TX entry repeated"
    );

    // The restored owner checkpoints again.
    restored.save_full(&dir.path("second")).unwrap();
}

#[test]
fn snapshot_nic_kvm_inactive_nic_with_disk_activates_after_restore() {
    let dir = TempDir::new();
    let disk = dir.path("disk.raw");
    let bytes: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&disk, &bytes).unwrap();
    // The NIC is attached but the driver never activates it before the cut;
    // its backend need not exist.
    let source = source(&dir.path("absent.sock"), &[disk.clone()]);
    let image = dir.path("checkpoint");
    let mut source = source;
    source.save_full(&image).unwrap();
    drop(source);

    // An inactive NIC connects nothing at restore time.
    let destination = dir.path("disks");
    let mut restored =
        RamSnapshotVm::restore_full(&image, resources(Some(&destination), &dir.path("b.sock")))
            .unwrap();
    assert_eq!(fs::read(destination.join("disk-0.raw")).unwrap(), bytes);
    restored.resume().unwrap();
    wait_counter(&restored, counter(&restored));

    // The driver activates after the restore; only then does the new
    // backend get its connection, and traffic flows both ways.
    let new = Backend::start(dir.path("b.sock"));
    let mut driver = Driver::default();
    Driver::activate(&restored);
    let mut stream = new.accept();
    driver.post_rx(&restored, 2);
    Driver::kick(&restored, 0);
    let inbound = payload(5, 80);
    send_frame(&mut stream, &inbound);
    Driver::wait_used(&restored, RX_USED, 1);
    assert_eq!(Driver::rx_frame(&restored, 0), inbound);
    let outbound = payload(6, 80);
    driver.submit_tx(&restored, &outbound);
    Driver::kick(&restored, 1);
    assert_eq!(recv_frame(&mut stream), outbound);
}

#[test]
fn snapshot_nic_kvm_backend_failure_and_resource_mismatch_clean_up() {
    let dir = TempDir::new();
    let disk = dir.path("disk.raw");
    fs::write(&disk, vec![0x5a; 4096]).unwrap();
    let old = Backend::start(dir.path("a.sock"));
    let mut source = source(&old.path, &[disk]);
    Driver::activate(&source);
    let _stream = old.accept();
    let image = dir.path("checkpoint");
    source.save_full(&image).unwrap();
    drop(source);

    // Resources without the NIC socket are rejected before any import.
    let destination = dir.path("disks");
    let disks_only = RestoreResources {
        disk_dir: Some(destination.clone()),
        ..Default::default()
    };
    assert!(RamSnapshotVm::restore_full(&image, disks_only).is_err());
    assert!(!destination.exists());

    // No backend listening: the restore fails after importing the disk and
    // removes everything it created.
    let missing = dir.path("missing.sock");
    assert!(RamSnapshotVm::restore_full(&image, resources(Some(&destination), &missing)).is_err());
    assert!(!destination.exists(), "failed restore left imported disks");

    // A NIC-free image takes no NIC socket.
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
        vm.start_vcpus(1, 0x1000).unwrap();
        vm.save_full(&plain).unwrap();
    }
    let new = Backend::start(dir.path("b.sock"));
    assert!(RamSnapshotVm::restore_full(&plain, resources(None, &new.path)).is_err());
    assert!(!destination.exists());
}

#[test]
fn snapshot_nic_kvm_save_failure_resumes_source_network() {
    let dir = TempDir::new();
    let old = Backend::start(dir.path("a.sock"));
    let mut source = source(&old.path, &[]);
    let mut driver = Driver::default();
    Driver::activate(&source);
    let mut stream = old.accept();
    driver.post_rx(&source, 4);
    Driver::kick(&source, 0);

    let image = dir.path("checkpoint");
    let failed = with_failed_payload_write(64 * 1024, || source.save_full(&image));
    assert!(failed.is_err());
    assert!(!image.exists(), "a failed save published an image");

    // Every source resource resumed: the CPU runs and the NIC still moves
    // frames on its original backend.
    wait_counter(&source, counter(&source));
    let inbound = payload(7, 90);
    send_frame(&mut stream, &inbound);
    Driver::wait_used(&source, RX_USED, 1);
    assert_eq!(Driver::rx_frame(&source, 0), inbound);
    let outbound = payload(8, 90);
    driver.submit_tx(&source, &outbound);
    Driver::kick(&source, 1);
    assert_eq!(recv_frame(&mut stream), outbound);
    source.save_full(&image).unwrap();
}

#[test]
fn snapshot_nic_kvm_attach_limits_share_the_last_gsi() {
    let dir = TempDir::new();
    let disks: Vec<_> = (0..8)
        .map(|i| {
            let path = dir.path(&format!("d{i}.raw"));
            fs::write(&path, vec![0u8; 4096]).unwrap();
            path
        })
        .collect();
    let socket = dir.path("n.sock");
    let build = || {
        crate::builder::build_ram_snapshot_vm(
            RAM_MIB,
            &Default::default(),
            &crate::builder::Payload::Empty,
        )
        .unwrap()
    };

    // Eight disks take GSI 16-23: no NIC.
    let mut vm = build();
    for disk in &disks {
        vm.attach_disk(disk, ImageType::Raw, false, false).unwrap();
    }
    assert!(vm.attach_net(&socket, MAC, 0).is_err());

    // A NIC leaves seven disk slots.
    let mut vm = build();
    vm.attach_net(&socket, MAC, 0).unwrap();
    assert!(vm.attach_net(&socket, MAC, 0).is_err(), "second NIC");
    for disk in &disks[..7] {
        vm.attach_disk(disk, ImageType::Raw, false, false).unwrap();
    }
    assert!(vm
        .attach_disk(&disks[7], ImageType::Raw, false, false)
        .is_err());

    // Unknown feature bits and late attach are rejected.
    let mut vm = build();
    assert!(vm.attach_net(&socket, MAC, 1 << 2).is_err());
    vm.memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    vm.start_vcpus(1, 0x1000).unwrap();
    assert!(vm.attach_net(&socket, MAC, 0).is_err());
}
