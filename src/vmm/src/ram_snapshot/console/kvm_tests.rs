// SPDX-License-Identifier: Apache-2.0

//! Console lifecycle tests on a real KVM VM. The guest runs the fixture's
//! MMIO entry (0x900): every console register access — status, features,
//! queue setup, notifications, interrupt status — is a real 32-bit MMIO
//! access by the guest vCPU, requested through the fixture's RAM mailbox,
//! while the fixture's loop counter proves CPU continuation. The rings and
//! buffers are the shared `tests::Driver`'s, in guest RAM. Real Unix
//! sockets are the host endpoints. Every test name contains "snapshot" for
//! `make snapshot-test`.
//!
//! Their execution is unverified until run on a Linux KVM host (see the
//! README's stage-8 validation status).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use devices::virtio::port_io;
use vm_memory::{Bytes, GuestAddress};

use super::tests::{
    pattern, ports, rx, tx, wait_until, Driver, Mmio, Pipe, CONTROL_RX, CONTROL_TX, DEVICE_READY,
    PORT_OPEN, PORT_READY, QUIET, WAIT,
};
use super::*;
use crate::ram_snapshot::{ConsoleEndpoints, RestoreResources, VsockPorts};

const RAM_MIB: usize = 2;
/// The fixture's MMIO entry (loaded at 0x1000, entry offset 0x900).
const MMIO_ENTRY: u16 = 0x1900;
const MAILBOX: u64 = 0x9100;
const COUNTER: u64 = 0x9120;
/// The fixture's console interrupt handler (vector 0x28) counts here.
const IRQ_COUNT: u64 = 0x9124;
const OP_WRITE: u32 = 1;
const OP_READ: u32 = 2;
const OP_STI: u32 = 3;
/// VIRTIO_MMIO_INT_VRING in InterruptStatus.
const INT_VRING: u32 = 1;

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Short: vsock socket paths must fit sun_path.
        let path = std::env::temp_dir().join(format!(
            "kcn{}-{}",
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

/// The guest vCPU performs each access; the call returns once the guest
/// recorded it as done.
struct Guest<'a>(&'a RamSnapshotVm);

impl Guest<'_> {
    /// Let the guest take interrupts from now on.
    fn sti(&self) {
        self.request(OP_STI, 0, 0);
    }

    /// A 32-bit read of guest RAM by the guest itself.
    fn read_ram(&self, addr: u64) -> u32 {
        self.request(OP_READ, addr - CONSOLE_MMIO_ADDR, 0)
    }

    fn request(&self, op: u32, offset: u64, value: u32) -> u32 {
        let mem = &self.0.memory;
        let at = |field: u64| GuestAddress(MAILBOX + field);
        let seq = mem.read_obj::<u32>(at(0)).unwrap().wrapping_add(1);
        mem.write_obj(op, at(4)).unwrap();
        mem.write_obj((CONSOLE_MMIO_ADDR + offset) as u32, at(8))
            .unwrap();
        mem.write_obj(value, at(0xc)).unwrap();
        fence(Ordering::SeqCst);
        mem.write_obj(seq, at(0)).unwrap();
        let deadline = Instant::now() + WAIT;
        while mem.read_obj::<u32>(at(0x10)).unwrap() != seq {
            assert!(Instant::now() < deadline, "the guest did not perform MMIO");
            std::thread::yield_now();
        }
        fence(Ordering::SeqCst);
        mem.read_obj(at(0xc)).unwrap()
    }
}

impl Mmio for Guest<'_> {
    fn write(&self, offset: u64, value: u32) {
        self.request(OP_WRITE, offset, value);
    }

    fn read(&self, offset: u64) -> u32 {
        self.request(OP_READ, offset, 0)
    }
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

/// A running owner with the console attached before the CPU starts.
fn source(ports: Vec<PortDescription>) -> RamSnapshotVm {
    let mut vm = fixture();
    vm.attach_console(ports).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    wait_counter(&vm, 0);
    vm
}

fn resources(ports: Vec<PortDescription>) -> RestoreResources {
    RestoreResources {
        console_ports: Some(ConsoleEndpoints::Ports(ports)),
        ..Default::default()
    }
}

/// The image's console section, for comparing exports.
fn console_section(path: &Path) -> serde_json::Value {
    let mut file = File::open(path).unwrap();
    let mut header = [0u8; 16];
    file.read_exact(&mut header).unwrap();
    let len = u32::from_le_bytes(header[12..].try_into().unwrap()) as usize;
    let mut json = vec![0; len];
    file.read_exact(&mut json).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&json).unwrap();
    metadata["console"].clone()
}

/// Activate, handshake and open both ports from the guest.
fn bring_up(vm: &RamSnapshotVm) -> Driver {
    let mut driver = Driver::new(2);
    driver.activate(&Guest(vm));
    driver.open_ports(&vm.memory, &Guest(vm), 2);
    driver
}

fn kick(vm: &RamSnapshotVm, q: usize) {
    Guest(vm).write(0x50, q as u32);
}

/// Partial TX offset, log half-line, RX, control backlog and a pending
/// interrupt survive a destroyed source; the target endpoints replace the
/// source's and see no replayed byte, and the CPU continues.
#[test]
fn snapshot_console_kvm_restored_guest_continues_io_on_new_endpoints() {
    let dir = TempDir::new();
    let image = dir.path("image");
    let (input, mut output) = (Pipe::new(), Pipe::narrow());
    let mut vm = source(ports(&input, &output));
    let mut driver = bring_up(&vm);

    (&input.host).write_all(b"ping").unwrap();
    let rx_buf = driver.post_rx(&vm.memory, rx(0), 64);
    kick(&vm, rx(0));
    wait_until("guest RX", || Driver::used(&vm.memory, rx(0)).len() == 1);
    assert_eq!(Driver::read(&vm.memory, rx_buf, 4), b"ping");
    driver.post_tx(&vm.memory, tx(1), &[b"boot: hal"]);
    kick(&vm, tx(1));
    wait_until("log TX", || Driver::used(&vm.memory, tx(1)).len() == 1);
    // The guest runs with interrupts off: the transport's used-buffer
    // status bit stays set (see the IRQ test for delivery).
    assert_ne!(Guest(&vm).read(0x60) & INT_VRING, 0);
    let data = pattern(3 * 32 * 1024);
    let parts: Vec<&[u8]> = data.chunks(32 * 1024).collect();
    driver.post_tx(&vm.memory, tx(0), &parts);
    kick(&vm, tx(0));
    let mut first = [0u8; 1];
    output.host.read_exact(&mut first).unwrap();

    vm.pause().unwrap();
    assert_paused(&vm);
    vm.export(&image).unwrap();
    let section = console_section(&image);
    let delivered = section["console"]["ports"][0]["tx_in_flight"]["delivered"]
        .as_u64()
        .expect("a chain is in flight") as usize;
    let mut accepted = first.to_vec();
    accepted.extend(output.drain());
    assert_eq!(accepted, data[..delivered]);
    let paused_at = counter(&vm);
    drop(vm);

    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let mut target =
        RamSnapshotVm::import(&image, resources(ports(&fresh_in, &fresh_out))).unwrap();
    assert_eq!(counter(&target), paused_at);
    std::thread::sleep(QUIET);
    assert!(
        fresh_out.drain().is_empty(),
        "the target wrote before resume"
    );
    target.resume().unwrap();
    wait_counter(&target, paused_at);

    // The restored guest reads the restored status bit, then the remainder
    // arrives without a kick and without replay, completing once.
    assert_ne!(Guest(&target).read(0x60) & INT_VRING, 0);
    Guest(&target).write(0x64, INT_VRING);
    assert_eq!(
        fresh_out.read_exact(data.len() - delivered),
        data[delivered..]
    );
    wait_until("restored completion", || {
        Driver::used(&target.memory, tx(0)).len() == 1
    });
    // No new handshake: the guest keeps using its open ports.
    (&fresh_in.host).write_all(b"pong").unwrap();
    let rx_buf = driver.post_rx(&target.memory, rx(0), 64);
    kick(&target, rx(0));
    wait_until("restored RX", || {
        Driver::used(&target.memory, rx(0)).len() == 2
    });
    assert_eq!(Driver::read(&target.memory, rx_buf, 4), b"pong");
    let pending = section["console"]["pending_control"]
        .as_array()
        .unwrap()
        .len();
    for _ in 0..pending {
        driver.post_rx(&target.memory, CONTROL_RX, 64);
    }
    kick(&target, CONTROL_RX);
    wait_until("control backlog", || {
        Driver::used(&target.memory, CONTROL_RX).len() == pending
    });
    driver.post_tx(&target.memory, tx(0), &[b"after"]);
    kick(&target, tx(0));
    assert_eq!(fresh_out.read_exact(5), b"after");
}

/// An interrupt raised before the cut and not yet taken (the guest runs
/// with interrupts off) is delivered exactly once by the restored irqchip
/// once the target guest enables interrupts, with no new console work; the
/// guest itself reads the RX data and used index it received before the
/// cut.
#[test]
fn snapshot_console_kvm_pending_irq_is_delivered_once_after_restore() {
    let dir = TempDir::new();
    let (input, output) = (Pipe::new(), Pipe::new());
    let mut vm = source(ports(&input, &output));
    let mut driver = bring_up(&vm);
    (&input.host).write_all(b"ping").unwrap();
    let buf = driver.post_rx(&vm.memory, rx(0), 64);
    kick(&vm, rx(0));
    wait_until("guest RX", || Driver::used(&vm.memory, rx(0)).len() == 1);
    assert_eq!(counter_at(&vm, IRQ_COUNT), 0);

    vm.pause().unwrap();
    vm.export(&dir.path("image")).unwrap();
    drop(vm);
    let (fresh_in, fresh_out) = (Pipe::new(), Pipe::new());
    let mut target =
        RamSnapshotVm::import(&dir.path("image"), resources(ports(&fresh_in, &fresh_out))).unwrap();
    target.resume().unwrap();
    let guest = Guest(&target);
    assert_eq!(guest.read_ram(buf), u32::from_le_bytes(*b"ping"));
    assert_eq!(guest.read_ram(Driver::used_idx_addr(rx(0))) & 0xffff, 1);
    std::thread::sleep(QUIET);
    assert_eq!(counter_at(&target, IRQ_COUNT), 0, "taken with IF=0");
    guest.sti();
    wait_until("pending IRQ", || counter_at(&target, IRQ_COUNT) == 1);
    std::thread::sleep(QUIET);
    assert_eq!(
        counter_at(&target, IRQ_COUNT),
        1,
        "delivered more than once"
    );
}

fn counter_at(vm: &RamSnapshotVm, addr: u64) -> u16 {
    vm.memory.read_obj(GuestAddress(addr)).unwrap()
}

/// Exports repeat the same console state; the source resumes from the cut
/// without duplicating output; an import exports the same state again
/// before it ever runs.
#[test]
fn snapshot_console_kvm_repeated_exports_source_resume_and_reexport() {
    let dir = TempDir::new();
    let (input, mut output) = (Pipe::new(), Pipe::narrow());
    let mut vm = source(ports(&input, &output));
    let mut driver = bring_up(&vm);
    let data = pattern(64 * 1024);
    driver.post_tx(&vm.memory, tx(0), &[&data]);
    kick(&vm, tx(0));
    let mut first = [0u8; 1];
    output.host.read_exact(&mut first).unwrap();

    vm.pause().unwrap();
    vm.export(&dir.path("a")).unwrap();
    vm.export(&dir.path("b")).unwrap();
    let section = console_section(&dir.path("a"));
    assert_eq!(section, console_section(&dir.path("b")));
    let delivered = section["console"]["ports"][0]["tx_in_flight"]["delivered"]
        .as_u64()
        .unwrap() as usize;
    let mut accepted = first.to_vec();
    accepted.extend(output.drain());
    assert_eq!(accepted.len(), delivered);

    vm.resume().unwrap();
    assert_eq!(output.read_exact(data.len() - delivered), data[delivered..]);
    wait_until("source completion", || {
        Driver::used(&vm.memory, tx(0)).len() == 1
    });

    let (fresh_in, fresh_out) = (Pipe::new(), Pipe::new());
    let mut target =
        RamSnapshotVm::import(&dir.path("a"), resources(ports(&fresh_in, &fresh_out))).unwrap();
    target.export(&dir.path("c")).unwrap();
    assert_eq!(console_section(&dir.path("c")), section);
    target.resume().unwrap();
    wait_counter(&target, counter(&target));
}

/// Chains made available while paused, with no kick, are served after
/// each resume, for a source and through export/import rounds.
#[test]
fn snapshot_console_kvm_multi_round_resume_needs_no_kick() {
    let dir = TempDir::new();
    let (input, mut output) = (Pipe::new(), Pipe::new());
    let mut vm = source(ports(&input, &output));
    let mut driver = bring_up(&vm);
    for round in 0..3u8 {
        vm.pause().unwrap();
        driver.post_tx(&vm.memory, tx(0), &[&[b'a' + round]]);
        vm.resume().unwrap();
        assert_eq!(output.read_exact(1), [b'a' + round]);
    }
    for round in 0..3u8 {
        vm.pause().unwrap();
        driver.post_tx(&vm.memory, tx(0), &[&[b'x' + round]]);
        let image = dir.path(&format!("round{round}"));
        vm.export(&image).unwrap();
        drop(vm);
        let (fresh_in, fresh_out) = (Pipe::new(), Pipe::new());
        vm = RamSnapshotVm::import(&image, resources(ports(&fresh_in, &fresh_out))).unwrap();
        vm.resume().unwrap();
        output = fresh_out;
        assert_eq!(output.read_exact(1), [b'x' + round]);
    }
}

/// An inactive console restores inactive; the restored guest then
/// activates and handshakes it as a fresh driver would.
#[test]
fn snapshot_console_kvm_inactive_console_activates_after_restore() {
    let dir = TempDir::new();
    let (input, output) = (Pipe::new(), Pipe::new());
    let mut vm = source(ports(&input, &output));
    vm.pause().unwrap();
    vm.export(&dir.path("image")).unwrap();
    assert_eq!(
        console_section(&dir.path("image"))["device"]["activated"],
        false
    );
    drop(vm);
    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let mut target =
        RamSnapshotVm::import(&dir.path("image"), resources(ports(&fresh_in, &fresh_out))).unwrap();
    target.resume().unwrap();
    assert_eq!(
        Guest(&target).read(0x70),
        0,
        "an inactive console activated"
    );
    let mut driver = bring_up(&target);
    driver.post_tx(&target.memory, tx(0), &[b"late start"]);
    kick(&target, tx(0));
    assert_eq!(fresh_out.read_exact(10), b"late start");
}

/// The console alongside every featureless device: one cut, one import.
#[test]
fn snapshot_console_kvm_combined_with_every_device() {
    let dir = TempDir::new();
    let vsock_ports: VsockPorts = [(1234, (dir.path("v-listen"), true))].into_iter().collect();
    let (input, mut output) = (Pipe::new(), Pipe::new());
    let serial = || {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        (ours, theirs)
    };
    let (com1, _com1_peer) = serial();
    let mut vm = fixture();
    vm.attach_rng().unwrap();
    vm.attach_balloon().unwrap();
    vm.attach_vsock(3, &vsock_ports).unwrap();
    vm.attach_legacy([Some(com1), None, None, None]).unwrap();
    vm.attach_console(ports(&input, &output)).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    wait_counter(&vm, 0);
    let mut driver = bring_up(&vm);
    driver.post_tx(&vm.memory, tx(0), &[b"one"]);
    kick(&vm, tx(0));
    assert_eq!(output.read_exact(3), b"one");

    vm.pause().unwrap();
    vm.export(&dir.path("image")).unwrap();
    drop(vm);
    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let (com1, _com1_peer) = serial();
    let resources = RestoreResources {
        vsock_ports: Some(
            [(1234, (dir.path("v-listen2"), true))]
                .into_iter()
                .collect(),
        ),
        serial: Some([Some(com1), None, None, None]),
        console_ports: Some(ConsoleEndpoints::Ports(ports(&fresh_in, &fresh_out))),
        ..Default::default()
    };
    let mut target = RamSnapshotVm::import(&dir.path("image"), resources).unwrap();
    target.resume().unwrap();
    driver.post_tx(&target.memory, tx(0), &[b"two"]);
    kick(&target, tx(0));
    assert_eq!(fresh_out.read_exact(3), b"two");
}

fn open_fds() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

/// Rejected attaches and imports leave nothing behind, and teardown is
/// bounded while a port's output is full.
#[test]
fn snapshot_console_kvm_failures_clean_up() {
    struct Custom;
    impl port_io::PortOutput for Custom {
        fn write_volatile(&mut self, buf: &vm_memory::VolatileSlice) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn wait_until_writable(&self, _stopfd: Option<&utils::eventfd::EventFd>) {}
    }
    // A custom endpoint is rejected before any effect: the owner stays
    // usable and takes a valid console afterwards.
    let mut vm = fixture();
    let custom = vec![PortDescription::output_pipe("c", Box::new(Custom))];
    assert!(vm.attach_console(custom).is_err());
    assert!(vm.console.is_none());
    let (input, output) = (Pipe::new(), Pipe::narrow());
    vm.attach_console(ports(&input, &output)).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    let mut driver = bring_up(&vm);
    vm.pause().unwrap();
    let dir = TempDir::new();
    vm.export(&dir.path("image")).unwrap();

    // Missing or mismatched console resources fail before RAM, devices or
    // threads exist.
    let fds = open_fds();
    assert!(RamSnapshotVm::import(&dir.path("image"), RestoreResources::default()).is_err());
    let one = vec![PortDescription::output_pipe(
        "krun-log",
        port_io::output_to_log_as_err(),
    )];
    assert!(RamSnapshotVm::import(&dir.path("image"), resources(one)).is_err());
    assert_eq!(open_fds(), fds, "a rejected import kept descriptors");

    // A TX blocked on a full output does not hold up teardown.
    vm.resume().unwrap();
    let data = pattern(256 * 1024);
    driver.post_tx(&vm.memory, tx(0), &[&data]);
    kick(&vm, tx(0));
    std::thread::sleep(QUIET);
    let started = Instant::now();
    drop(vm);
    assert!(
        started.elapsed() < WAIT,
        "teardown waited on output backpressure"
    );
}

/// A failed export (an injected mid-copy write error) leaves the source
/// paused with its console frozen: nothing more reaches the output, a
/// retried export captures the same console state, and the source resumes
/// the in-flight chain exactly from its delivered offset.
#[test]
fn snapshot_console_kvm_failed_export_keeps_source_paused_and_retryable() {
    let dir = TempDir::new();
    let (input, mut output) = (Pipe::new(), Pipe::narrow());
    let mut vm = source(ports(&input, &output));
    let mut driver = bring_up(&vm);
    let data = pattern(3 * 32 * 1024);
    let parts: Vec<&[u8]> = data.chunks(32 * 1024).collect();
    driver.post_tx(&vm.memory, tx(0), &parts);
    kick(&vm, tx(0));
    let mut first = [0u8; 1];
    output.host.read_exact(&mut first).unwrap();

    vm.pause().unwrap();
    let failed = dir.path("failed");
    let result = crate::ram_snapshot::tests::with_failed_payload_write(17, || vm.export(&failed));
    assert!(result.is_err());
    assert!(!failed.exists(), "a failed export left a file");
    assert!(vm.is_paused() && !vm.control.unusable);
    assert_paused(&vm);
    let mut accepted = first.to_vec();
    accepted.extend(output.drain());
    std::thread::sleep(QUIET);
    assert!(
        output.drain().is_empty(),
        "a failed export resumed the console"
    );

    vm.export(&dir.path("a")).unwrap();
    vm.export(&dir.path("b")).unwrap();
    let section = console_section(&dir.path("a"));
    assert_eq!(section, console_section(&dir.path("b")));
    let delivered = section["console"]["ports"][0]["tx_in_flight"]["delivered"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(accepted, data[..delivered]);
    vm.resume().unwrap();
    assert_eq!(output.read_exact(data.len() - delivered), data[delivered..]);
    wait_until("completion", || Driver::used(&vm.memory, tx(0)).len() == 1);
}

/// An activated console between PORT_READY and PORT_OPEN: the guest's
/// handshake state and the queued replies survive the import without a
/// repeated handshake, and the guest then opens the port on the target.
#[test]
fn snapshot_console_kvm_midway_handshake_continues_after_restore() {
    let dir = TempDir::new();
    let (input, output) = (Pipe::new(), Pipe::new());
    let mut vm = source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&Guest(&vm));
    driver.control(&vm.memory, &Guest(&vm), 0, DEVICE_READY, 1);
    driver.control(&vm.memory, &Guest(&vm), 0, PORT_READY, 1);
    driver.control(&vm.memory, &Guest(&vm), 1, PORT_READY, 1);
    wait_until("handshake", || {
        Driver::used(&vm.memory, CONTROL_TX).len() == 3
    });
    vm.pause().unwrap();
    vm.export(&dir.path("image")).unwrap();
    let section = console_section(&dir.path("image"));
    assert_eq!(section["console"]["ports"][0]["ready"], true);
    assert_eq!(section["console"]["ports"][0]["started"], false);
    let pending = section["console"]["pending_control"]
        .as_array()
        .unwrap()
        .len();
    drop(vm);

    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let mut target =
        RamSnapshotVm::import(&dir.path("image"), resources(ports(&fresh_in, &fresh_out))).unwrap();
    target.resume().unwrap();
    for _ in 0..=pending {
        driver.post_rx(&target.memory, CONTROL_RX, 64);
    }
    kick(&target, CONTROL_RX);
    wait_until("backlog", || {
        Driver::used(&target.memory, CONTROL_RX).len() == pending
    });
    std::thread::sleep(QUIET);
    assert_eq!(
        Driver::used(&target.memory, CONTROL_RX).len(),
        pending,
        "the handshake was replayed"
    );
    driver.control(&target.memory, &Guest(&target), 0, PORT_OPEN, 1);
    wait_until("open", || {
        Driver::used(&target.memory, CONTROL_TX).len() == 4
    });
    driver.post_tx(&target.memory, tx(0), &[b"opened"]);
    kick(&target, tx(0));
    assert_eq!(fresh_out.read_exact(6), b"opened");
}

/// Claims the built-in FD kind, then panics on its first read, ending its
/// RX worker thread.
struct PanickingInput(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl port_io::PortInput for PanickingInput {
    fn read_volatile(&mut self, _buf: &mut vm_memory::VolatileSlice) -> std::io::Result<usize> {
        self.0.store(true, Ordering::SeqCst);
        panic!("injected console input failure");
    }

    fn wait_until_readable(&self, _stopfd: Option<&utils::eventfd::EventFd>) {
        std::thread::sleep(Duration::from_millis(5));
    }

    fn snapshot_kind(&self) -> Option<port_io::InputKind> {
        Some(port_io::InputKind::Fd)
    }
}

/// A console worker that died before the pause makes the freeze control
/// uncertain: the pause fails, the owner is disabled and every thread
/// stops, so the guest no longer runs and no snapshot or resume is
/// accepted.
#[test]
fn snapshot_console_kvm_gone_worker_disables_owner_and_stops_threads() {
    let dir = TempDir::new();
    let read = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let output = Pipe::new();
    let mut vm = source(vec![
        PortDescription::console(
            Some(Box::new(PanickingInput(read.clone()))),
            Some(output.output()),
            port_io::term_fixed_size(80, 25),
        ),
        PortDescription::output_pipe("krun-log", port_io::output_to_log_as_err()),
    ]);
    let mut driver = bring_up(&vm);
    driver.post_rx(&vm.memory, rx(0), 8);
    kick(&vm, rx(0));
    wait_until("the injected panic", || read.load(Ordering::SeqCst));
    std::thread::sleep(QUIET);
    assert!(vm.pause().is_err());
    assert!(vm.control.unusable);
    assert_paused(&vm);
    assert!(vm.export(&dir.path("image")).is_err());
    assert!(vm.resume().is_err());
    assert!(vm.pause().is_err());
    assert_eq!(
        vm.console
            .as_ref()
            .unwrap()
            .device
            .lock()
            .unwrap()
            .memory_clones(),
        0,
        "console workers survived the disable"
    );
}

/// The console with an internal disk and NIC (attached, not activated by
/// this guest, so the NIC never connects) through one cut and import.
#[cfg(all(feature = "blk", feature = "net"))]
#[test]
fn snapshot_console_kvm_combined_with_disk_and_nic() {
    use devices::virtio::block::ImageType;
    use std::os::unix::net::UnixListener;

    let dir = TempDir::new();
    let disk = dir.path("disk.raw");
    fs::write(&disk, vec![0u8; 1 << 20]).unwrap();
    let socket = dir.path("nic.sock");
    let _backend = UnixListener::bind(&socket).unwrap();
    let (input, output) = (Pipe::new(), Pipe::new());
    let mut vm = fixture();
    vm.attach_disk(&disk, ImageType::Raw, false, false).unwrap();
    vm.attach_net(&socket, [2, 0, 0, 0, 0, 1], 0).unwrap();
    vm.attach_console(ports(&input, &output)).unwrap();
    vm.start_vcpus(1, MMIO_ENTRY).unwrap();
    wait_counter(&vm, 0);
    let mut driver = bring_up(&vm);
    vm.pause().unwrap();
    vm.export(&dir.path("image")).unwrap();
    drop(vm);

    let target_socket = dir.path("nic2.sock");
    let _target_backend = UnixListener::bind(&target_socket).unwrap();
    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let resources = RestoreResources {
        disk_dir: Some(dir.path("imported")),
        nic_socket: Some(target_socket),
        console_ports: Some(ConsoleEndpoints::Ports(ports(&fresh_in, &fresh_out))),
        ..Default::default()
    };
    let mut target = RamSnapshotVm::import(&dir.path("image"), resources).unwrap();
    target.resume().unwrap();
    wait_counter(&target, counter(&target));
    driver.post_tx(&target.memory, tx(0), &[b"disk+nic"]);
    kick(&target, tx(0));
    assert_eq!(fresh_out.read_exact(8), b"disk+nic");
}
