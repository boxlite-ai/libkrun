// SPDX-License-Identifier: Apache-2.0

//! Vsock metadata and resource validation, the event thread's blocked send
//! cancelled through the gate, and a deferred reopen failure stopping the
//! vCPUs through the exit watch; none needs KVM. The guest-side ring
//! driver here is shared with `kvm_tests`. Every test name contains
//! "snapshot" for `make snapshot-test`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use devices::virtio::{DeviceQueue, InterruptTransport, Queue};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Bytes, GuestAddress};

use super::*;
use crate::ram_snapshot::events::tests::{fake_vcpu, wait_finished};
use crate::ram_snapshot::events::{Devices, EventThread, Exit, Start};

pub(super) const QSIZE: u16 = 64;
pub(super) const RX: usize = 0;
pub(super) const EV: usize = 2;
/// (descriptor table, avail ring, used ring) of RX, TX and the event queue,
/// clear of the counter fixture (code 0x1000, CPU areas from 0x8000,
/// stacks below 0xc000).
pub(super) const RINGS: [(u64, u64, u64); 3] = [
    (0x4_0000, 0x4_1000, 0x4_2000),
    (0x4_4000, 0x4_5000, 0x4_6000),
    (0x4_8000, 0x4_9000, 0x4_a000),
];
const RX_BUFS: u64 = 0x8_0000;
const RX_BUF_LEN: u32 = 0x1000;
const TX_HDRS: u64 = 0xc_0000;
const TX_DATA: u64 = 0x10_0000;
const EV_BUFS: u64 = 0xe_0000;
const HDR_LEN: u32 = 44;
pub(super) const GUEST_CID: u64 = 3;
pub(super) const HOST_PORT: u32 = 1234;
pub(super) const GUEST_PORT: u32 = 5000;
pub(super) const OP_REQUEST: u16 = 1;
pub(super) const OP_RESPONSE: u16 = 2;
pub(super) const OP_RW: u16 = 5;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const TRANSPORT_RESET: u32 = 0;
const WAIT: Duration = Duration::from_secs(5);

/// A host packet header as the guest reads it from an RX buffer.
#[derive(Debug)]
pub(super) struct Hdr {
    pub(super) op: u16,
    pub(super) src_port: u32,
    pub(super) dst_port: u32,
}

/// What a vsock guest driver tracks; the rings live in `RINGS`.
#[derive(Default)]
pub(super) struct Driver {
    rx_posted: u16,
    rx_seen: u16,
    tx_sent: u16,
    ev_offered: u16,
}

impl Driver {
    /// The driver state the rings in `mem` record, such as a restored
    /// image's: posted counts from the avail rings, RX consumed up to the
    /// used ring.
    pub(super) fn from_rings(mem: &GuestMemoryMmap) -> Self {
        let avail = |queue: usize| {
            mem.read_obj::<u16>(GuestAddress(RINGS[queue].1 + 2))
                .unwrap()
        };
        Driver {
            rx_posted: avail(RX),
            rx_seen: Self::used_idx(mem, RX),
            tx_sent: avail(1),
            ev_offered: avail(EV),
        }
    }

    /// The queues as the driver configured them, for a device activated
    /// without the MMIO transport.
    pub(super) fn queues(&self) -> Vec<Queue> {
        RINGS
            .iter()
            .map(|&(desc, avail, used)| {
                let mut queue = Queue::new(VSOCK_QUEUE_SIZE);
                queue.size = QSIZE;
                queue.ready = true;
                queue.desc_table = GuestAddress(desc);
                queue.avail_ring = GuestAddress(avail);
                queue.used_ring = GuestAddress(used);
                queue
            })
            .collect()
    }

    fn set_desc(mem: &GuestMemoryMmap, queue: usize, index: u16, d: (u64, u32, u16, u16)) {
        let descriptor = devices::virtio::Descriptor {
            addr: d.0,
            len: d.1,
            flags: d.2,
            next: d.3,
        };
        let at = RINGS[queue].0 + 16 * u64::from(index);
        mem.write_obj(descriptor, GuestAddress(at)).unwrap();
    }

    fn publish(mem: &GuestMemoryMmap, queue: usize, posted: u16, head: u16) {
        let avail = RINGS[queue].1;
        let slot = avail + 4 + 2 * u64::from(posted % QSIZE);
        mem.write_obj(head, GuestAddress(slot)).unwrap();
        mem.write_obj(posted.wrapping_add(1), GuestAddress(avail + 2))
            .unwrap();
    }

    pub(super) fn used_idx(mem: &GuestMemoryMmap, queue: usize) -> u16 {
        mem.read_obj(GuestAddress(RINGS[queue].2 + 2)).unwrap()
    }

    /// (descriptor head, length) of used entry `n` of `queue`.
    pub(super) fn used_elem(mem: &GuestMemoryMmap, queue: usize, n: u16) -> (u32, u32) {
        let at = RINGS[queue].2 + 4 + 8 * u64::from(n % QSIZE);
        (
            mem.read_obj(GuestAddress(at)).unwrap(),
            mem.read_obj(GuestAddress(at + 4)).unwrap(),
        )
    }

    pub(super) fn post_rx(&mut self, mem: &GuestMemoryMmap, count: u16) {
        for _ in 0..count {
            let slot = self.rx_posted % QSIZE;
            let addr = RX_BUFS + u64::from(slot) * u64::from(RX_BUF_LEN);
            Self::set_desc(mem, RX, slot, (addr, RX_BUF_LEN, VIRTQ_DESC_F_WRITE, 0));
            Self::publish(mem, RX, self.rx_posted, slot);
            self.rx_posted = self.rx_posted.wrapping_add(1);
        }
    }

    /// Queue one packet; `len` zero bytes of data for OP_RW. The caller
    /// kicks.
    pub(super) fn send(&mut self, mem: &GuestMemoryMmap, op: u16, ports: (u32, u32), len: u32) {
        let slot = self.tx_sent % (QSIZE / 2);
        let (head, hdr) = (slot * 2, TX_HDRS + u64::from(slot) * 64);
        let at = |off| GuestAddress(hdr + off);
        mem.write_obj(GUEST_CID, at(0)).unwrap();
        mem.write_obj(2u64, at(8)).unwrap();
        mem.write_obj(ports.0, at(16)).unwrap();
        mem.write_obj(ports.1, at(20)).unwrap();
        mem.write_obj(len, at(24)).unwrap();
        mem.write_obj(1u16, at(28)).unwrap(); // VSOCK_TYPE_STREAM
        mem.write_obj(op, at(30)).unwrap();
        mem.write_obj(0u32, at(32)).unwrap();
        mem.write_obj(256 * 1024u32, at(36)).unwrap();
        mem.write_obj(0u32, at(40)).unwrap();
        if len == 0 {
            Self::set_desc(mem, 1, head, (hdr, HDR_LEN, 0, 0));
        } else {
            let data = TX_DATA + u64::from(slot) * 64 * 1024;
            Self::set_desc(mem, 1, head, (hdr, HDR_LEN, VIRTQ_DESC_F_NEXT, head + 1));
            Self::set_desc(mem, 1, head + 1, (data, len, 0, 0));
        }
        Self::publish(mem, 1, self.tx_sent, head);
        self.tx_sent = self.tx_sent.wrapping_add(1);
    }

    pub(super) fn tx_sent(&self) -> u16 {
        self.tx_sent
    }

    /// Offer one four-byte event buffer, poisoned until the device writes.
    pub(super) fn offer_event(&mut self, mem: &GuestMemoryMmap) {
        let slot = self.ev_offered % QSIZE;
        let addr = EV_BUFS + 16 * u64::from(slot);
        mem.write_obj(u32::MAX, GuestAddress(addr)).unwrap();
        Self::set_desc(mem, EV, slot, (addr, 4, VIRTQ_DESC_F_WRITE, 0));
        Self::publish(mem, EV, self.ev_offered, slot);
        self.ev_offered = self.ev_offered.wrapping_add(1);
    }

    /// Whether used event entry `n` is a delivered transport reset.
    pub(super) fn is_reset(mem: &GuestMemoryMmap, n: u16) -> bool {
        let (head, len) = Self::used_elem(mem, EV, n);
        let id: u32 = mem
            .read_obj(GuestAddress(EV_BUFS + 16 * u64::from(head)))
            .unwrap();
        (id, len) == (TRANSPORT_RESET, 4)
    }

    /// The next host packet, waiting for the device; its buffer is offered
    /// again.
    pub(super) fn recv(&mut self, mem: &GuestMemoryMmap) -> Hdr {
        wait("an RX packet", || Self::used_idx(mem, RX) != self.rx_seen);
        let (id, _) = Self::used_elem(mem, RX, self.rx_seen);
        self.rx_seen = self.rx_seen.wrapping_add(1);
        let addr = RX_BUFS + u64::from(id) * u64::from(RX_BUF_LEN);
        let read_u32 = |off| mem.read_obj::<u32>(GuestAddress(addr + off)).unwrap();
        let hdr = Hdr {
            op: mem.read_obj(GuestAddress(addr + 30)).unwrap(),
            src_port: read_u32(16),
            dst_port: read_u32(20),
        };
        Self::publish(mem, RX, self.rx_posted, id as u16);
        self.rx_posted = self.rx_posted.wrapping_add(1);
        hdr
    }

    pub(super) fn recv_op(&mut self, mem: &GuestMemoryMmap, op: u16) -> Hdr {
        loop {
            let hdr = self.recv(mem);
            if hdr.op == op {
                return hdr;
            }
        }
    }
}

pub(super) fn wait(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn ports(entries: &[(u32, &str, bool)]) -> VsockPorts {
    entries
        .iter()
        .map(|(port, path, listen)| (*port, (PathBuf::from(path), *listen)))
        .collect()
}

const RAM_LEN: u64 = 0x10_0000;

fn regions() -> Vec<Region> {
    vec![Region {
        gpa: 0,
        len: RAM_LEN,
        attributes: 0,
    }]
}

fn transport(device_status: u32) -> MmioTransportState {
    MmioTransportState {
        features_select: 0,
        acked_features_select: 0,
        queue_select: 0,
        shm_region_select: 0,
        device_status,
        config_generation: 0,
        interrupt_status: 0,
    }
}

/// A valid activated vsock section as a paused source would capture it.
fn meta() -> VsockMeta {
    let queues = Driver::default()
        .queues()
        .iter()
        .map(QueueState::from_queue)
        .collect();
    VsockMeta {
        mmio_addr: VSOCK_MMIO_ADDR,
        mmio_len: MMIO_LEN,
        irq: VSOCK_IRQ,
        cid: GUEST_CID,
        ports: vec![
            PortMeta {
                port: HOST_PORT,
                listen: true,
            },
            PortMeta {
                port: HOST_PORT + 1,
                listen: false,
            },
        ],
        transport: transport(0b1111),
        device: VirtioDeviceState {
            device_type: TYPE_VSOCK,
            avail_features: VSOCK_FEATURES,
            acked_features: 1 << 32,
            queues,
            activated: true,
        },
        reset_pending: true,
        interrupt_owed: true,
    }
}

/// Every malformed section is rejected before guest RAM exists; an
/// inactive device owes no reset.
#[test]
fn snapshot_vsock_metadata_rejects_inconsistent_sections() {
    validate_metadata(&meta(), &regions()).unwrap();
    let mut inactive = meta();
    inactive.transport = transport(0b1011);
    inactive.device.activated = false;
    inactive.reset_pending = false;
    inactive.interrupt_owed = false;
    validate_metadata(&inactive, &regions()).unwrap();

    let cases: Vec<(&str, fn(&mut VsockMeta))> = vec![
        ("slot", |m| m.mmio_addr += MMIO_LEN),
        ("irq", |m| m.irq = 5),
        ("host CID", |m| m.cid = 2),
        ("CID ANY", |m| m.cid = u64::from(u32::MAX)),
        ("duplicate port", |m| m.ports[1].port = HOST_PORT),
        ("unordered ports", |m| m.ports.reverse()),
        ("features", |m| m.device.avail_features |= 1 << 2),
        ("unacked feature", |m| m.device.acked_features |= 1 << 40),
        ("queue count", |m| {
            m.device.queues.pop();
        }),
        ("queue max size", |m| m.device.queues[0].max_size = 128),
        ("transport", |m| m.transport.device_status = 0b0100),
        ("activation", |m| m.transport.device_status = 0b1011),
        ("no pending reset", |m| m.reset_pending = false),
        ("inactive owes", |m| {
            m.transport.device_status = 0b1011;
            m.device.activated = false;
            m.reset_pending = false;
        }),
        ("inactive pending", |m| {
            m.transport.device_status = 0b1011;
            m.device.activated = false;
            m.interrupt_owed = false;
        }),
    ];
    for (what, corrupt) in cases {
        let mut bad = meta();
        corrupt(&mut bad);
        assert!(validate_metadata(&bad, &regions()).is_err(), "{what}");
    }
    let overlapping = vec![Region {
        gpa: VSOCK_MMIO_ADDR,
        len: MMIO_LEN,
        attributes: 0,
    }];
    assert!(validate_metadata(&meta(), &overlapping).is_err());
}

/// The caller's ports must match the image's ports and roles exactly, each
/// with a usable path; the paths themselves are new.
#[test]
fn snapshot_vsock_restore_ports_must_match_roles() {
    let image = meta();
    check_resources(
        &image,
        &ports(&[
            (HOST_PORT, "/new/l.sock", true),
            (HOST_PORT + 1, "/new/h.sock", false),
        ]),
    )
    .unwrap();
    let mismatches = [
        ports(&[(HOST_PORT, "/n/l.sock", true)]),
        ports(&[
            (HOST_PORT, "/n/l.sock", true),
            (HOST_PORT + 1, "/n/h.sock", false),
            (HOST_PORT + 2, "/n/x.sock", false),
        ]),
        ports(&[
            (HOST_PORT, "/n/l.sock", false),
            (HOST_PORT + 1, "/n/h.sock", false),
        ]),
        ports(&[(HOST_PORT, "", true), (HOST_PORT + 1, "/n/h.sock", false)]),
    ];
    for (n, mismatch) in mismatches.iter().enumerate() {
        assert!(check_resources(&image, mismatch).is_err(), "case {n}");
    }
    let long = "/".repeat(MAX_SOCKET_PATH + 1);
    let too_long = ports(&[
        (HOST_PORT, &long, true),
        (HOST_PORT + 1, "/n/h.sock", false),
    ]);
    assert!(check_resources(&image, &too_long).is_err());
}

/// A path with a NUL byte, which the Unix socket address cannot hold, is
/// rejected by the pure check that runs before guest RAM or any resource
/// exists.
#[test]
fn snapshot_vsock_port_paths_reject_nul() {
    let mut nul = ports(&[(HOST_PORT + 1, "/n/h.sock", false)]);
    nul.insert(
        HOST_PORT,
        (PathBuf::from(OsStr::from_bytes(b"/n/l\0.sock")), true),
    );
    assert!(check_resources(&meta(), &nul).is_err());
}

/// One path bound by two listening ports is rejected by the same pure
/// check; connecting ports may share a path, with each other or with a
/// listener.
#[test]
fn snapshot_vsock_port_paths_reject_shared_listeners() {
    let mut image = meta();
    image.ports = (0..3)
        .map(|n| PortMeta {
            port: HOST_PORT + n,
            listen: n < 2,
        })
        .collect();
    let shared_listener = ports(&[
        (HOST_PORT, "/n/l.sock", true),
        (HOST_PORT + 1, "/n/l.sock", true),
        (HOST_PORT + 2, "/n/h.sock", false),
    ]);
    assert!(check_resources(&image, &shared_listener).is_err());
    let listen_and_connect = ports(&[
        (HOST_PORT, "/n/l.sock", true),
        (HOST_PORT + 1, "/n/m.sock", true),
        (HOST_PORT + 2, "/n/l.sock", false),
    ]);
    check_resources(&image, &listen_and_connect).unwrap();

    image.ports.iter_mut().for_each(|role| role.listen = false);
    let shared_connect = ports(&[
        (HOST_PORT, "/n/h.sock", false),
        (HOST_PORT + 1, "/n/h.sock", false),
        (HOST_PORT + 2, "/n/h.sock", false),
    ]);
    check_resources(&image, &shared_connect).unwrap();
}

/// Active rings must fit guest RAM and every TX head the resume will
/// complete must be a valid descriptor index.
#[test]
fn snapshot_vsock_rings_are_checked_against_guest_ram() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let image = meta();
    validate_rings(&image, &mem).unwrap();
    let mut driver = Driver::default();
    driver.send(&mem, OP_REQUEST, (GUEST_PORT, HOST_PORT), 0);
    validate_rings(&image, &mem).unwrap();
    mem.write_obj(QSIZE, GuestAddress(RINGS[1].1 + 4)).unwrap();
    assert!(validate_rings(&image, &mem).is_err(), "invalid TX head");
    let small = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4_0000)]).unwrap();
    assert!(
        validate_rings(&meta(), &small).is_err(),
        "rings outside RAM"
    );
}

/// The event thread blocks in a vsock send under the device lock while the
/// host peer reads nothing. Quiescing the gate, taken before and never
/// through that lock, cancels the send so the thread can freeze; the stop
/// then completes the rest of the guest's TX empty.
#[test]
fn snapshot_vsock_gate_cancels_event_thread_send_before_freeze() {
    let dir = std::env::temp_dir().join(format!("kvs{}-evt", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("host.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let mut driver = Driver::default();
    driver.post_rx(&mem, QSIZE);
    let kicks: Vec<Arc<EventFd>> = (0..3)
        .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
        .collect();
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(devices::legacy::KvmIoapic {}),
    )));
    let mut vsock = Vsock::new(
        GUEST_CID,
        None,
        Some(ports(&[(HOST_PORT, path.to_str().unwrap(), false)])),
        TsiFlags::empty(),
    )
    .unwrap();
    let queues = driver
        .queues()
        .into_iter()
        .zip(&kicks)
        .map(|(queue, kick)| DeviceQueue::new(queue, kick.clone()))
        .collect();
    vsock
        .activate(
            mem.clone(),
            InterruptTransport::new(intc, "vsock".into()).unwrap(),
            queues,
        )
        .unwrap();
    let gate = vsock.snapshot_control().unwrap();
    let vsock = Arc::new(Mutex::new(vsock));
    let mut events = EventThread::spawn(
        Devices {
            exit: Exit::new().unwrap(),
            rng: None,
            balloon: None,
            vsock: Some(vsock.clone()),
            console: None,
            serials: Vec::new(),
        },
        Start::Running,
    )
    .unwrap();

    driver.send(&mem, OP_REQUEST, (GUEST_PORT, HOST_PORT), 0);
    kicks[1].write(1).unwrap();
    driver.recv_op(&mem, OP_RESPONSE);
    let (peer, _) = listener.accept().unwrap();
    for _ in 0..QSIZE / 2 - 1 {
        driver.send(&mem, OP_RW, (GUEST_PORT, HOST_PORT), 64 * 1024);
    }
    kicks[1].write(1).unwrap();
    // Stuck: the device lock stays held and TX stops moving.
    let mut last = Driver::used_idx(&mem, 1);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let used = Driver::used_idx(&mem, 1);
        if used == last && vsock.try_lock().is_err() {
            assert_ne!(used, driver.tx_sent(), "every send completed");
            break;
        }
        last = used;
    }

    gate.quiesce();
    let started = Instant::now();
    events.freeze().unwrap();
    assert!(started.elapsed() < WAIT, "the freeze waited for the send");
    peer.set_read_timeout(Some(WAIT)).unwrap();
    std::io::copy(&mut &peer, &mut std::io::sink()).unwrap();
    vsock.lock().unwrap().stop_backend().unwrap();
    assert_eq!(Driver::used_idx(&mem, 1), driver.tx_sent());
    events.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reopen on the guest's event-queue kick that cannot bind its listening
/// path has no caller to fail: the device the owner builds writes the exit
/// notifier, so the event thread latches the exit and stops every armed
/// vCPU (which the owner's pause, export and resume then reject), and the
/// backend stays failed.
#[test]
fn snapshot_vsock_deferred_reopen_failure_stops_vcpus() {
    let dir = std::env::temp_dir().join(format!("kvs{}-fatal", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("guest.sock");
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let mut driver = Driver::default();
    driver.post_rx(&mem, QSIZE);
    let kicks: Vec<Arc<EventFd>> = (0..3)
        .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
        .collect();
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(devices::legacy::KvmIoapic {}),
    )));
    let exit = Exit::new().unwrap();
    let (mut vsock, _gate) = new_vsock(
        GUEST_CID,
        &ports(&[(HOST_PORT, path.to_str().unwrap(), true)]),
        &exit,
    )
    .unwrap();
    let queues = driver
        .queues()
        .into_iter()
        .zip(&kicks)
        .map(|(queue, kick)| DeviceQueue::new(queue, kick.clone()))
        .collect();
    vsock
        .activate(
            mem.clone(),
            InterruptTransport::new(intc, "vsock".into()).unwrap(),
            queues,
        )
        .unwrap();
    // A resume without an event buffer: the reopen waits for the kick.
    vsock.stop_backend().unwrap();
    vsock.restart_backend().unwrap();
    std::fs::write(&path, b"occupied").unwrap();
    let vsock = Arc::new(Mutex::new(vsock));
    // Before the thread: on a failed assertion it drops first, releasing
    // its stop handles before the fake vCPUs are joined.
    let finished = Arc::new(AtomicUsize::new(0));
    let mut vcpus: Vec<_> = (0..2).map(|_| fake_vcpu(finished.clone())).collect();
    let mut events = EventThread::spawn(
        Devices {
            exit: exit.clone(),
            rng: None,
            balloon: None,
            vsock: Some(vsock.clone()),
            console: None,
            serials: Vec::new(),
        },
        Start::Running,
    )
    .unwrap();
    events
        .arm(vcpus.iter().map(|vcpu| vcpu.stop_handle()).collect())
        .unwrap();
    assert!(!exit.requested());

    driver.offer_event(&mem);
    kicks[EV].write(1).unwrap();
    wait_finished(&finished, 2);
    assert!(exit.requested());
    assert!(Driver::is_reset(&mem, 0), "the reset itself was delivered");

    events.stop();
    vcpus.iter_mut().for_each(|vcpu| vcpu.finish());
    let stopped = vsock.lock().unwrap().stop_backend();
    assert!(matches!(
        stopped,
        Err(devices::virtio::VsockError::BackendFailed)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"occupied");
    let _ = std::fs::remove_dir_all(&dir);
}
