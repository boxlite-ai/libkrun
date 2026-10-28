// SPDX-License-Identifier: Apache-2.0

//! Console checkpoints without KVM: the production build, freeze, capture,
//! metadata/resource/ring validation and restore paths on a transport and
//! the owner's event thread, driven through MMIO and guest RAM. The guest
//! ring driver here is shared with `kvm_tests`, where the guest vCPU itself
//! performs every MMIO access, and with the virtio-fs tests. Every test name contains "snapshot" for
//! `make snapshot-test`.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{fence, Ordering};
use std::time::{Duration, Instant};

use devices::legacy::DummyIrqChip;
use devices::virtio::port_io::{self, PortOutput};
use devices::BusDevice;
use nix::sys::socket::{setsockopt, sockopt};
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryRegion, VolatileSlice};

use super::*;
use crate::ram_snapshot::events::{Devices, EventThread, Exit, Start};

pub(in crate::ram_snapshot) const QSIZE: u16 = 32;
/// Queue `q` of the driver: descriptor table, avail ring and used ring in
/// one 4 KiB page, clear of the fixture (0x1000), the CPU and mailbox areas
/// (0x8000–0x9200) and the stacks (below 0xc000).
const RINGS: u64 = 0x2_0000;
const BUFS: u64 = 0x4_0000;
pub(in crate::ram_snapshot) const RAM_LEN: usize = 2 << 20;
pub(super) const CONTROL_RX: usize = 2;
pub(super) const CONTROL_TX: usize = 3;
const NEXT: u16 = 1;
const WRITE: u16 = 2;
pub(super) const DEVICE_READY: u16 = 0;
pub(super) const PORT_READY: u16 = 3;
pub(super) const PORT_OPEN: u16 = 6;
pub(in crate::ram_snapshot) const WAIT: Duration = Duration::from_secs(5);
pub(in crate::ram_snapshot) const QUIET: Duration = Duration::from_millis(150);

pub(super) fn rx(port: usize) -> usize {
    if port == 0 {
        0
    } else {
        2 + 2 * port
    }
}

pub(super) fn tx(port: usize) -> usize {
    rx(port) + 1
}

pub(in crate::ram_snapshot) fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Register access to a device's MMIO window, from the test (here) or
/// from the guest vCPU (`kvm_tests`).
pub(in crate::ram_snapshot) trait Mmio {
    fn write(&self, offset: u64, value: u32);
    fn read(&self, offset: u64) -> u32;
}

/// What a virtio guest driver tracks; the rings and buffers live in guest
/// RAM, so a copy taken with the RAM image continues on a restored VM.
#[derive(Clone)]
pub(in crate::ram_snapshot) struct Driver {
    queues: usize,
    posted: Vec<u16>,
    next_desc: Vec<u16>,
    next_buf: u64,
}

impl Driver {
    pub(super) fn new(ports: usize) -> Driver {
        Driver::with_queues(2 + 2 * ports)
    }

    /// A driver of `queues` queues.
    pub(in crate::ram_snapshot) fn with_queues(queues: usize) -> Driver {
        Driver {
            queues,
            posted: vec![0; queues],
            next_desc: vec![0; queues],
            next_buf: BUFS,
        }
    }

    fn desc(q: usize) -> u64 {
        RINGS + q as u64 * 0x1000
    }

    fn avail(q: usize) -> u64 {
        Self::desc(q) + 0x200
    }

    fn used_ring(q: usize) -> u64 {
        Self::desc(q) + 0x400
    }

    /// Negotiate SIZE, MULTIPORT and VERSION_1, configure every queue and
    /// set DRIVER_OK.
    pub(super) fn activate(&self, mmio: &dyn Mmio) {
        self.activate_with(mmio, 0b11);
    }

    /// Negotiate VERSION_1 plus the low feature bits `features`, configure
    /// every queue and set DRIVER_OK.
    pub(in crate::ram_snapshot) fn activate_with(&self, mmio: &dyn Mmio, features: u32) {
        mmio.write(0x70, 0b0001);
        mmio.write(0x70, 0b0011);
        mmio.write(0x24, 0);
        mmio.write(0x20, features);
        mmio.write(0x24, 1);
        mmio.write(0x20, 1);
        mmio.write(0x70, 0b1011);
        for q in 0..self.queues {
            mmio.write(0x30, q as u32);
            mmio.write(0x38, u32::from(QSIZE));
            for (offset, addr) in [
                (0x80, Self::desc(q)),
                (0x90, Self::avail(q)),
                (0xa0, Self::used_ring(q)),
            ] {
                mmio.write(offset, addr as u32);
                mmio.write(offset + 4, 0);
            }
            mmio.write(0x44, 1);
        }
        mmio.write(0x70, 0b1111);
        assert_eq!(mmio.read(0x70), 0b1111, "device activation failed");
    }

    pub(in crate::ram_snapshot) fn alloc(&mut self, len: usize) -> u64 {
        let addr = self.next_buf;
        self.next_buf += (len as u64).next_multiple_of(0x100);
        assert!(self.next_buf <= RAM_LEN as u64);
        addr
    }

    /// Make a chain of (address, length, device-writable) descriptors
    /// available; the device sees it on its next look at the queue.
    pub(in crate::ram_snapshot) fn post(
        &mut self,
        mem: &GuestMemoryMmap,
        q: usize,
        bufs: &[(u64, u32, bool)],
    ) {
        let head = self.next_desc[q];
        for (i, &(addr, len, write)) in bufs.iter().enumerate() {
            let index = (head + i as u16) % QSIZE;
            let mut flags = if write { WRITE } else { 0 };
            if i + 1 < bufs.len() {
                flags |= NEXT;
            }
            let at = GuestAddress(Self::desc(q) + 16 * u64::from(index));
            mem.write_obj(addr, at).unwrap();
            mem.write_obj(len, GuestAddress(at.0 + 8)).unwrap();
            mem.write_obj(flags, GuestAddress(at.0 + 12)).unwrap();
            mem.write_obj((index + 1) % QSIZE, GuestAddress(at.0 + 14))
                .unwrap();
        }
        self.next_desc[q] = (head + bufs.len() as u16) % QSIZE;
        let slot = u64::from(self.posted[q] % QSIZE);
        mem.write_obj(head, GuestAddress(Self::avail(q) + 4 + 2 * slot))
            .unwrap();
        self.posted[q] = self.posted[q].wrapping_add(1);
        fence(Ordering::SeqCst);
        mem.write_obj(self.posted[q], GuestAddress(Self::avail(q) + 2))
            .unwrap();
    }

    pub(super) fn post_tx(&mut self, mem: &GuestMemoryMmap, q: usize, parts: &[&[u8]]) {
        let bufs: Vec<_> = parts
            .iter()
            .map(|part| {
                let addr = self.alloc(part.len());
                mem.write_slice(part, GuestAddress(addr)).unwrap();
                (addr, part.len() as u32, false)
            })
            .collect();
        self.post(mem, q, &bufs);
    }

    pub(super) fn post_rx(&mut self, mem: &GuestMemoryMmap, q: usize, len: u32) -> u64 {
        let addr = self.alloc(len as usize);
        self.post(mem, q, &[(addr, len, true)]);
        addr
    }

    /// Queue a control message on the control transmitq and notify it.
    pub(super) fn control(
        &mut self,
        mem: &GuestMemoryMmap,
        mmio: &dyn Mmio,
        id: u32,
        event: u16,
        value: u16,
    ) {
        let mut msg = id.to_le_bytes().to_vec();
        msg.extend(event.to_le_bytes());
        msg.extend(value.to_le_bytes());
        self.post_tx(mem, CONTROL_TX, &[&msg]);
        mmio.write(0x50, CONTROL_TX as u32);
    }

    /// The guest handshake for every port, then open them all.
    pub(super) fn open_ports(&mut self, mem: &GuestMemoryMmap, mmio: &dyn Mmio, ports: u32) {
        self.control(mem, mmio, 0, DEVICE_READY, 1);
        for port in 0..ports {
            self.control(mem, mmio, port, PORT_READY, 1);
            self.control(mem, mmio, port, PORT_OPEN, 1);
        }
        let expected = 1 + 2 * ports as usize;
        wait_until("control handshake", || {
            Self::used(mem, CONTROL_TX).len() == expected
        });
    }

    /// Where queue `q`'s used index lives in guest RAM.
    pub(super) fn used_idx_addr(q: usize) -> u64 {
        Self::used_ring(q) + 2
    }

    /// Used entries (id, len) of queue `q` since the start.
    pub(in crate::ram_snapshot) fn used(mem: &GuestMemoryMmap, q: usize) -> Vec<(u32, u32)> {
        let idx: u16 = mem.read_obj(GuestAddress(Self::used_ring(q) + 2)).unwrap();
        (0..idx)
            .map(|i| {
                let at = Self::used_ring(q) + 4 + 8 * u64::from(i % QSIZE);
                let id: u32 = mem.read_obj(GuestAddress(at)).unwrap();
                let len: u32 = mem.read_obj(GuestAddress(at + 4)).unwrap();
                (id, len)
            })
            .collect()
    }

    pub(in crate::ram_snapshot) fn read(mem: &GuestMemoryMmap, addr: u64, len: u32) -> Vec<u8> {
        let mut buf = vec![0; len as usize];
        mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
        buf
    }
}

/// One host socket pair: `port` goes to the console (dup'd), `host` is the
/// test's end.
pub(super) struct Pipe {
    port: UnixStream,
    pub(super) host: UnixStream,
}

impl Pipe {
    pub(super) fn new() -> Pipe {
        let (port, host) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(WAIT)).unwrap();
        Pipe { port, host }
    }

    /// Small socket buffers, so a large chain meets backpressure.
    pub(super) fn narrow() -> Pipe {
        let pipe = Pipe::new();
        setsockopt(&pipe.port, sockopt::SndBuf, &4096).unwrap();
        setsockopt(&pipe.host, sockopt::RcvBuf, &4096).unwrap();
        pipe
    }

    pub(super) fn input(&self) -> Box<dyn port_io::PortInput + Send> {
        port_io::input_to_raw_fd_dup(self.port.as_raw_fd()).unwrap()
    }

    pub(super) fn output(&self) -> Box<dyn PortOutput + Send> {
        port_io::output_to_raw_fd_dup(self.port.as_raw_fd()).unwrap()
    }

    pub(super) fn drain(&mut self) -> Vec<u8> {
        self.host.set_nonblocking(true).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.host.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("host read failed: {e}"),
            }
        }
        self.host.set_nonblocking(false).unwrap();
        out
    }

    pub(super) fn read_exact(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        self.host.read_exact(&mut out).unwrap();
        out
    }
}

pub(super) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Port 0: the BoxLite-style console (FD input and output, fixed
/// terminal); port 1: a named log port.
pub(super) fn ports(input: &Pipe, output: &Pipe) -> Vec<PortDescription> {
    vec![
        PortDescription::console(
            Some(input.input()),
            Some(output.output()),
            port_io::term_fixed_size(80, 25),
        ),
        PortDescription::output_pipe("krun-log", port_io::output_to_log_as_err()),
    ]
}

/// A console on a transport with the owner's event thread, as the owner
/// wires it minus KVM.
struct Side {
    mem: GuestMemoryMmap,
    device: Arc<Mutex<Console>>,
    transport: Arc<Mutex<MmioTransport>>,
    events: EventThread,
}

impl Mmio for Side {
    fn write(&self, offset: u64, value: u32) {
        self.transport
            .lock()
            .unwrap()
            .write(0, offset, &value.to_le_bytes());
    }

    fn read(&self, offset: u64) -> u32 {
        let mut bytes = [0; 4];
        self.transport.lock().unwrap().read(0, offset, &mut bytes);
        u32::from_le_bytes(bytes)
    }
}

impl Side {
    fn spawn(mem: GuestMemoryMmap, parts: Parts, start: Start) -> Side {
        let (device, transport) = parts;
        let devices = Devices {
            exit: Exit::new().unwrap(),
            rng: None,
            balloon: None,
            memory: None,
            vsock: None,
            console: Some(device.clone()),
            serials: Vec::new(),
        };
        let events = EventThread::spawn(devices, start).unwrap();
        Side {
            mem,
            device,
            transport,
            events,
        }
    }

    fn source(ports: Vec<PortDescription>) -> Side {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
        let parts = build(mem.clone(), DummyIrqChip::new().into(), ports).unwrap();
        Side::spawn(mem, parts, Start::Running)
    }

    /// The import path minus KVM: RAM copied, every check before the device
    /// exists, the production restore, then a frozen event thread.
    fn restored(&self, meta: &ConsoleMeta, ports: Vec<PortDescription>) -> Side {
        check_resources(meta, &ports).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
        let mut ram = vec![0; RAM_LEN];
        self.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
        mem.write_slice(&ram, GuestAddress(0)).unwrap();
        validate_rings(meta, &mem).unwrap();
        let parts = build(mem.clone(), DummyIrqChip::new().into(), ports).unwrap();
        restore_parts(&parts.0, &parts.1, meta).unwrap();
        Side::spawn(mem, parts, Start::Restored)
    }

    /// The owner's pause order after the vCPUs: event thread, then console.
    fn pause(&self) {
        self.events.freeze().unwrap();
        self.device.lock().unwrap().snapshot_freeze().unwrap();
    }

    /// The owner's resume order: console (workers, control queues), then
    /// the event thread.
    fn resume(&self) {
        self.device.lock().unwrap().snapshot_resume().unwrap();
        self.events.resume().unwrap();
    }

    fn capture(&self) -> ConsoleMeta {
        capture_device(
            &self.transport.lock().unwrap(),
            &self.device.lock().unwrap(),
            &self.mem,
            &regions(),
        )
        .unwrap()
    }

    /// References to the RAM mapping: this side, the probe's and every
    /// device clone, as `probe_ram_aliases` counts them.
    fn mapping_refs(&self) -> usize {
        let region = self.mem.iter().next().unwrap();
        let (_rest, mapping) = self
            .mem
            .remove_region(region.start_addr(), region.len())
            .unwrap();
        Arc::strong_count(&mapping)
    }
}

fn regions() -> Vec<Region> {
    vec![Region {
        gpa: 0,
        len: RAM_LEN as u64,
        attributes: 0,
    }]
}

fn json(meta: &ConsoleMeta) -> String {
    serde_json::to_string(meta).unwrap()
}

#[test]
fn snapshot_console_vmm_export_import_continues_without_replay() {
    let (input, mut output) = (Pipe::new(), Pipe::narrow());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.open_ports(&source.mem, &source, 2);

    // A chain the narrow output accepts only part of, and an unfinished
    // log line.
    let data = pattern(3 * 32 * 1024);
    let parts: Vec<&[u8]> = data.chunks(32 * 1024).collect();
    driver.post_tx(&source.mem, tx(0), &parts);
    source.write(0x50, tx(0) as u32);
    driver.post_tx(&source.mem, tx(1), &[b"boot: hal"]);
    source.write(0x50, tx(1) as u32);
    wait_until("log write", || Driver::used(&source.mem, tx(1)).len() == 1);
    let mut first = [0u8; 1];
    output.host.read_exact(&mut first).unwrap();

    source.pause();
    // One mapping clone each: transport, activated device, port 0 RX and
    // TX, port 1 TX; capture takes none.
    let console_clones = 1 + source.device.lock().unwrap().memory_clones();
    assert_eq!(console_clones, 5);
    assert_eq!(source.mapping_refs(), 2 + console_clones);
    let meta = source.capture();
    assert_eq!(source.mapping_refs(), 2 + console_clones);
    assert_eq!(
        json(&source.capture()),
        json(&meta),
        "repeated capture differs"
    );

    let delivered = meta.console.ports[0]
        .tx_in_flight
        .expect("a chain is in flight")
        .delivered as usize;
    assert!(delivered > 1 && delivered < data.len());
    let mut accepted = first.to_vec();
    accepted.extend(output.drain());
    assert_eq!(accepted, data[..delivered]);
    assert!(meta.console.device_ready);
    assert!(meta.console.ports.iter().all(|p| p.ready && p.guest_open));
    assert_eq!(
        meta.console.ports[1].output,
        Some(port_io::OutputState::Log {
            partial_line: b"boot: hal".to_vec()
        })
    );
    // The guest offered no control buffer: the handshake replies wait.
    assert!(!meta.console.pending_control.is_empty());

    // The image round-trips through JSON and passes every import check.
    let meta: ConsoleMeta = serde_json::from_str(&json(&meta)).unwrap();
    validate_metadata(&meta, &regions()).unwrap();

    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    (&fresh_in.host).write_all(b"to the target").unwrap();
    let target = source.restored(&meta, ports(&fresh_in, &fresh_out));
    std::thread::sleep(QUIET);
    assert!(
        fresh_out.drain().is_empty(),
        "the target wrote before resume"
    );
    assert_eq!(json(&target.capture()), json(&meta), "import changed state");

    // Resume needs no kick: only the remainder reaches the fresh output,
    // and the chain completes exactly once.
    target.resume();
    assert_eq!(
        fresh_out.read_exact(data.len() - delivered),
        data[delivered..]
    );
    wait_until("TX completion", || {
        Driver::used(&target.mem, tx(0)).len() == 1
    });
    // The restored event thread registered the queues: new kicks work,
    // without a new handshake.
    let mut driver = driver.clone();
    let buf = driver.post_rx(&target.mem, rx(0), 64);
    target.write(0x50, rx(0) as u32);
    wait_until("fresh input", || {
        Driver::used(&target.mem, rx(0)).len() == 1
    });
    assert_eq!(Driver::read(&target.mem, buf, 13), b"to the target");
    let controls: Vec<_> = (0..meta.console.pending_control.len())
        .map(|_| driver.post_rx(&target.mem, CONTROL_RX, 64))
        .collect();
    target.write(0x50, CONTROL_RX as u32);
    wait_until("control backlog", || {
        Driver::used(&target.mem, CONTROL_RX).len() == controls.len()
    });
    for (i, (_, len)) in Driver::used(&target.mem, CONTROL_RX)
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            Driver::read(&target.mem, controls[i], len),
            meta.console.pending_control[i]
        );
    }

    // The source continues from the same cut without duplicating bytes.
    source.resume();
    assert_eq!(output.read_exact(data.len() - delivered), data[delivered..]);
    wait_until("source completion", || {
        Driver::used(&source.mem, tx(0)).len() == 1
    });
    assert!(output.drain().is_empty());
}

#[test]
fn snapshot_console_vmm_frozen_console_ignores_kicks_until_resume() {
    let (input, mut output) = (Pipe::new(), Pipe::new());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.open_ports(&source.mem, &source, 2);
    source.pause();
    let meta = json(&source.capture());

    // Kicks and input while frozen change nothing.
    driver.post_tx(&source.mem, tx(0), &[b"later"]);
    source.write(0x50, tx(0) as u32);
    driver.post_rx(&source.mem, rx(0), 16);
    source.write(0x50, rx(0) as u32);
    (&input.host).write_all(b"in").unwrap();
    driver.post_rx(&source.mem, CONTROL_RX, 64);
    source.write(0x50, CONTROL_RX as u32);
    std::thread::sleep(QUIET);
    assert!(output.drain().is_empty());
    for q in [rx(0), tx(0), CONTROL_RX] {
        assert!(Driver::used(&source.mem, q).is_empty(), "queue {q} moved");
    }
    // Only the avail rings moved, which the image carries anyway.
    let frozen: ConsoleMeta = serde_json::from_str(&json(&source.capture())).unwrap();
    let before: ConsoleMeta = serde_json::from_str(&meta).unwrap();
    assert_eq!(frozen.console, before.console);
    assert_eq!(frozen.device.queues, before.device.queues);

    // Resume processes everything without a new kick.
    source.resume();
    assert_eq!(output.read_exact(5), b"later");
    wait_until("input", || Driver::used(&source.mem, rx(0)).len() == 1);
    wait_until("control", || {
        Driver::used(&source.mem, CONTROL_RX).len() == 1
    });
}

/// An activated console whose guest finished DEVICE_READY and PORT_READY
/// but opened no port yet: the handshake state and the queued replies
/// survive, the target does not repeat the handshake, and a later
/// PORT_OPEN starts the port on the fresh endpoints.
#[test]
fn snapshot_console_vmm_midway_handshake_roundtrips() {
    let (input, output) = (Pipe::new(), Pipe::new());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.control(&source.mem, &source, 0, DEVICE_READY, 1);
    driver.control(&source.mem, &source, 0, PORT_READY, 1);
    driver.control(&source.mem, &source, 1, PORT_READY, 1);
    wait_until("handshake", || {
        Driver::used(&source.mem, CONTROL_TX).len() == 3
    });
    source.pause();
    let meta = source.capture();
    assert!(meta.device.activated && meta.console.device_ready);
    let size = Some(devices::virtio::TerminalSize { cols: 80, rows: 25 });
    let handshake: Vec<_> = meta
        .console
        .ports
        .iter()
        .map(|p| (p.ready, p.guest_open, p.started, p.size))
        .collect();
    assert_eq!(
        handshake,
        [(true, false, false, size), (true, false, false, None)]
    );
    // PORT_ADD ×2; console port, host open, resize; host open, name.
    assert_eq!(meta.console.pending_control.len(), 7);

    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let target = source.restored(&meta, ports(&fresh_in, &fresh_out));
    assert_eq!(json(&target.capture()), json(&meta));
    target.resume();
    let mut driver = driver.clone();
    let controls: Vec<_> = (0..8)
        .map(|_| driver.post_rx(&target.mem, CONTROL_RX, 64))
        .collect();
    target.write(0x50, CONTROL_RX as u32);
    wait_until("backlog", || {
        Driver::used(&target.mem, CONTROL_RX).len() == 7
    });
    std::thread::sleep(QUIET);
    let used = Driver::used(&target.mem, CONTROL_RX);
    assert_eq!(used.len(), 7, "the handshake was replayed");
    for (i, (_, len)) in used.into_iter().enumerate() {
        assert_eq!(
            Driver::read(&target.mem, controls[i], len),
            meta.console.pending_control[i]
        );
    }
    driver.control(&target.mem, &target, 0, PORT_OPEN, 1);
    wait_until("open", || Driver::used(&target.mem, CONTROL_TX).len() == 4);
    driver.post_tx(&target.mem, tx(0), &[b"opened"]);
    target.write(0x50, tx(0) as u32);
    assert_eq!(fresh_out.read_exact(6), b"opened");
}

/// Aborting a restored device with the production `discard` (what a failed
/// import runs after its workers started) is prompt and releases every
/// worker's RAM clone, with the workers frozen and again after resume with
/// a worker blocked on a full output nobody reads. The restore itself
/// succeeds; no restore failure is injected.
#[test]
fn snapshot_console_vmm_failed_restore_releases_workers_promptly() {
    let (input, output) = (Pipe::new(), Pipe::narrow());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.open_ports(&source.mem, &source, 2);
    let data = pattern(3 * 32 * 1024);
    let parts: Vec<&[u8]> = data.chunks(32 * 1024).collect();
    driver.post_tx(&source.mem, tx(0), &parts);
    source.write(0x50, tx(0) as u32);
    let mut first = [0u8; 1];
    let mut host = &output.host;
    host.read_exact(&mut first).unwrap();
    source.pause();
    let meta = source.capture();
    assert!(meta.console.ports[0].tx_in_flight.is_some());

    for resumed in [false, true] {
        let (fresh_in, fresh_out) = (Pipe::new(), Pipe::narrow());
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
        let mut ram = vec![0; RAM_LEN];
        source.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
        mem.write_slice(&ram, GuestAddress(0)).unwrap();
        let (device, transport) = build(
            mem.clone(),
            DummyIrqChip::new().into(),
            ports(&fresh_in, &fresh_out),
        )
        .unwrap();
        restore_parts(&device, &transport, &meta).unwrap();
        let clones = device.lock().unwrap().memory_clones();
        assert_eq!(clones, 4, "activated state and three workers");
        if resumed {
            device.lock().unwrap().snapshot_resume().unwrap();
            // The remainder fills the narrow output; nobody reads it.
            std::thread::sleep(QUIET);
        }
        let started = Instant::now();
        discard(&device);
        assert!(started.elapsed() < WAIT, "cleanup waited on a worker");
        assert_eq!(device.lock().unwrap().memory_clones(), 0);
        let side = Side {
            mem,
            device,
            transport,
            events: EventThread::spawn(
                Devices {
                    exit: Exit::new().unwrap(),
                    rng: None,
                    balloon: None,
                    memory: None,
                    vsock: None,
                    console: None,
                    serials: Vec::new(),
                },
                Start::Running,
            )
            .unwrap(),
        };
        // Only this side, the probe and the transport hold the mapping.
        assert_eq!(side.mapping_refs(), 3, "a worker kept guest RAM");
    }
}

#[test]
fn snapshot_console_vmm_inactive_console_roundtrips_and_activates_later() {
    let (input, output) = (Pipe::new(), Pipe::new());
    let source = Side::source(ports(&input, &output));
    source.pause();
    let meta = source.capture();
    assert!(!meta.device.activated);
    assert!(meta.console.ports.iter().all(|p| !p.started && !p.ready));

    let (fresh_in, mut fresh_out) = (Pipe::new(), Pipe::new());
    let target = source.restored(&meta, ports(&fresh_in, &fresh_out));
    target.resume();
    let mut driver = Driver::new(2);
    driver.activate(&target);
    driver.open_ports(&target.mem, &target, 2);
    driver.post_tx(&target.mem, tx(0), &[b"hello"]);
    target.write(0x50, tx(0) as u32);
    assert_eq!(fresh_out.read_exact(5), b"hello");
}

struct CustomOutput;

impl PortOutput for CustomOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn wait_until_writable(&self, _stopfd: Option<&EventFd>) {}
}

#[test]
fn snapshot_console_vmm_rejects_unsupported_ports_and_mismatched_resources() {
    assert!(check_descriptions(&[]).is_err());
    let custom = vec![PortDescription::output_pipe("c", Box::new(CustomOutput))];
    let error = check_descriptions(&custom).unwrap_err().to_string();
    assert!(error.contains("output endpoint"), "{error}");

    let (input, output) = (Pipe::new(), Pipe::new());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.open_ports(&source.mem, &source, 2);
    source.pause();
    let meta = source.capture();
    check_resources(&meta, &ports(&input, &output)).unwrap();

    // Order, names, directions and kinds must match the image.
    let mut swapped = ports(&input, &output);
    swapped.reverse();
    let renamed = vec![
        ports(&input, &output).remove(0),
        PortDescription::output_pipe("other", port_io::output_to_log_as_err()),
    ];
    let fd_log = vec![
        ports(&input, &output).remove(0),
        PortDescription::output_pipe("krun-log", output.output()),
    ];
    let no_input = vec![
        PortDescription::console(
            None,
            Some(output.output()),
            port_io::term_fixed_size(80, 25),
        ),
        PortDescription::output_pipe("krun-log", port_io::output_to_log_as_err()),
    ];
    let other_terminal = vec![
        PortDescription::console(
            Some(input.input()),
            Some(output.output()),
            port_io::term_fixed_size(120, 40),
        ),
        PortDescription::output_pipe("krun-log", port_io::output_to_log_as_err()),
    ];
    let custom = vec![
        ports(&input, &output).remove(0),
        PortDescription::output_pipe("krun-log", Box::new(CustomOutput)),
    ];
    let one = vec![ports(&input, &output).remove(0)];
    for (case, candidate) in [
        ("swapped", swapped),
        ("renamed", renamed),
        ("fd for log", fd_log),
        ("no input", no_input),
        ("other terminal", other_terminal),
        ("custom", custom),
        ("one port", one),
    ] {
        assert!(
            check_resources(&meta, &candidate).is_err(),
            "{case} accepted"
        );
    }
}

/// No port limit below the queue index range: a 24-port console attaches,
/// captures and passes every import check.
#[test]
fn snapshot_console_vmm_many_ports_roundtrip() {
    let logs = || -> Vec<_> {
        (0..24)
            .map(|i| {
                PortDescription::output_pipe(format!("log{i}"), port_io::output_to_log_as_err())
            })
            .collect()
    };
    check_descriptions(&logs()).unwrap();
    let source = Side::source(logs());
    source.pause();
    let meta = source.capture();
    assert_eq!(meta.console.ports.len(), 24);
    let meta: ConsoleMeta = serde_json::from_str(&json(&meta)).unwrap();
    validate_metadata(&meta, &regions()).unwrap();
    check_resources(&meta, &logs()).unwrap();
    validate_rings(&meta, &source.mem).unwrap();
}

#[test]
fn snapshot_console_vmm_metadata_and_rings_are_validated() {
    let (input, output) = (Pipe::new(), Pipe::narrow());
    let source = Side::source(ports(&input, &output));
    let mut driver = Driver::new(2);
    driver.activate(&source);
    driver.open_ports(&source.mem, &source, 2);
    let data = pattern(64 * 1024);
    driver.post_tx(&source.mem, tx(0), &[&data]);
    source.write(0x50, tx(0) as u32);
    let mut first = [0u8; 1];
    let mut host = &output.host;
    host.read_exact(&mut first).unwrap();
    source.pause();
    let meta = source.capture();
    let encoded = json(&meta);
    let reject = |what: &str, edit: &dyn Fn(&mut ConsoleMeta)| {
        let mut bad: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
        edit(&mut bad);
        assert!(
            validate_metadata(&bad, &regions()).is_err(),
            "{what} accepted"
        );
    };
    reject("slot", &|m| m.mmio_addr += MMIO_LEN);
    reject("irq", &|m| m.irq = 7);
    reject("features", &|m| m.device.avail_features |= 1 << 2);
    reject("queue count", &|m| {
        m.device.queues.pop();
    });
    reject("no ports", &|m| m.console.ports.clear());
    reject("activation", &|m| m.transport.device_status = 0b1011);
    reject("transport", &|m| m.transport.interrupt_status = 0b100);
    // EOF on a port without input.
    reject("port progress", &|m| m.console.ports[1].eof = true);
    // A RAM window overlapping the slot.
    let overlapping = vec![Region {
        gpa: CONSOLE_MMIO_ADDR,
        len: MMIO_LEN,
        attributes: 0,
    }];
    assert!(validate_metadata(&meta, &overlapping).is_err());

    // Against loaded RAM: a corrupt in-flight offset or head, and a
    // malformed available chain, fail before anything starts.
    validate_rings(&meta, &source.mem).unwrap();
    let mut offset: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
    offset.console.ports[0]
        .tx_in_flight
        .as_mut()
        .unwrap()
        .delivered = data.len() as u32;
    assert!(validate_rings(&offset, &source.mem).is_err());
    let mut head: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
    head.console.ports[0].tx_in_flight.as_mut().unwrap().head += 1;
    assert!(validate_rings(&head, &source.mem).is_err());
    // Cursors that disagree with the in-flight record: an already completed
    // chain (RAM's used index moved with it, so the common queue checks
    // pass) would be replayed; a popped chain without a record would be
    // lost.
    let completed_ram = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
    let mut ram = vec![0; RAM_LEN];
    source.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
    completed_ram.write_slice(&ram, GuestAddress(0)).unwrap();
    let mut completed: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
    let tx_queue = &mut completed.device.queues[tx(0)];
    tx_queue.next_used = tx_queue.next_avail;
    completed_ram
        .write_obj(tx_queue.next_used, GuestAddress(tx_queue.used_ring + 2))
        .unwrap();
    completed
        .device
        .validate_ready_queues(
            &completed_ram,
            TYPE_CONSOLE,
            console_num_queues(2),
            CONSOLE_QUEUE_SIZE,
        )
        .unwrap();
    assert!(validate_rings(&completed, &completed_ram).is_err());
    let mut lost: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
    lost.console.ports[0].tx_in_flight = None;
    assert!(validate_rings(&lost, &source.mem).is_err());
    // A started port's worker on an unready queue.
    let mut unready: ConsoleMeta = serde_json::from_str(&encoded).unwrap();
    unready.device.queues[rx(0)].ready = false;
    assert!(validate_rings(&unready, &source.mem).is_err());
    let mut chain = driver.clone();
    chain.post(&source.mem, rx(0), &[(RAM_LEN as u64 - 4, 64, true)]);
    assert!(validate_rings(&meta, &source.mem).is_err());
}
