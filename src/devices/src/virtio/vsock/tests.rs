// Test names contain "snapshot_vsock" so `make snapshot-vsock-host-test` and
// `make snapshot-test` select them. Every test drives the device through
// its production entry points with rings in guest RAM and real Unix sockets.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::defs::uapi;
use super::gate::VsockGate;
use super::proxy::ProxyError;
use super::{TsiFlags, Vsock, VsockError, VsockResetState};
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{Descriptor, DeviceQueue, InterruptTransport, Queue, VirtioDevice};

const MEM_SIZE: u64 = 0x40_0000;
const RX_RING: u64 = 0x0;
const TX_RING: u64 = 0x2000;
const EV_RING: u64 = 0x4000;
const EV_BUFS: u64 = 0x8000;
const RX_BUFS: u64 = 0x1_0000;
const TX_HDRS: u64 = 0x2_0000;
const TX_DATA: u64 = 0x10_0000;
const RX_SLOTS: u16 = 16;
/// Two descriptors (header, data) per TX packet.
const TX_PACKETS: u16 = 16;
const EV_SLOTS: u16 = 8;
const RX_BUF_LEN: u32 = 0x1000;
const DATA_LEN: u32 = 64 * 1024;
const GUEST_CID: u64 = 3;
const HOST_PORT: u32 = 1234;
const GUEST_PORT: u32 = 5000;
const WAIT: Duration = Duration::from_secs(5);
/// How long a negative check gives a wrongly acting backend.
const SETTLE: Duration = Duration::from_millis(100);
/// Poison written into event buffers before the device fills them.
const UNWRITTEN: u32 = 0xdead_beef;

#[derive(Debug)]
struct Hdr {
    op: u16,
    src_port: u32,
    dst_port: u32,
}

/// One split virtqueue in guest RAM, addressed only through that RAM, so a
/// copy of the RAM carries it.
#[derive(Clone, Copy)]
struct Ring {
    desc: u64,
    avail: u64,
    used: u64,
    size: u16,
}

impl Ring {
    /// Lay out an empty ring at `start` (zeroing its indexes).
    fn new(mem: &GuestMemoryMmap, start: u64, size: u16) -> Self {
        let queue = VirtQueue::new(GuestAddress(start), mem, size).create_queue();
        Ring {
            desc: queue.desc_table.0,
            avail: queue.avail_ring.0,
            used: queue.used_ring.0,
            size,
        }
    }

    fn queue(&self) -> Queue {
        let mut queue = Queue::new(self.size);
        queue.size = self.size;
        queue.ready = true;
        queue.desc_table = GuestAddress(self.desc);
        queue.avail_ring = GuestAddress(self.avail);
        queue.used_ring = GuestAddress(self.used);
        queue
    }

    fn set_desc(
        &self,
        mem: &GuestMemoryMmap,
        index: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let descriptor = Descriptor {
            addr,
            len,
            flags,
            next,
        };
        let at = self.desc + 16 * u64::from(index);
        mem.write_obj(descriptor, GuestAddress(at)).unwrap();
    }

    fn publish(&self, mem: &GuestMemoryMmap, head: u16) {
        let idx: u16 = mem.read_obj(GuestAddress(self.avail + 2)).unwrap();
        let slot = self.avail + 4 + 2 * u64::from(idx % self.size);
        mem.write_obj(head, GuestAddress(slot)).unwrap();
        mem.write_obj(idx.wrapping_add(1), GuestAddress(self.avail + 2))
            .unwrap();
    }

    fn used_idx(&self, mem: &GuestMemoryMmap) -> u16 {
        mem.read_obj(GuestAddress(self.used + 2)).unwrap()
    }

    /// (descriptor head, length) of used entry `n`.
    fn used_elem(&self, mem: &GuestMemoryMmap, n: u16) -> (u32, u32) {
        let at = self.used + 4 + 8 * u64::from(n % self.size);
        (
            mem.read_obj(GuestAddress(at)).unwrap(),
            mem.read_obj(GuestAddress(at + 4)).unwrap(),
        )
    }
}

/// The test's guest driver: RX buffers, TX packets and event buffers. Its
/// rings live in guest RAM, so `on` carries the driver to a RAM copy.
struct Guest<'a> {
    mem: &'a GuestMemoryMmap,
    rx: Ring,
    tx: Ring,
    ev: Ring,
    rx_seen: u16,
    tx_sent: u16,
    ev_offered: u16,
    tx_event: Arc<EventFd>,
}

impl<'a> Guest<'a> {
    fn new(mem: &'a GuestMemoryMmap) -> Self {
        let guest = Guest {
            mem,
            rx: Ring::new(mem, RX_RING, RX_SLOTS),
            tx: Ring::new(mem, TX_RING, TX_PACKETS * 2),
            ev: Ring::new(mem, EV_RING, EV_SLOTS),
            rx_seen: 0,
            tx_sent: 0,
            ev_offered: 0,
            tx_event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
        };
        for slot in 0..RX_SLOTS {
            let addr = RX_BUFS + u64::from(slot) * u64::from(RX_BUF_LEN);
            guest
                .rx
                .set_desc(mem, slot, addr, RX_BUF_LEN, VIRTQ_DESC_F_WRITE, 0);
            guest.rx.publish(mem, slot);
        }
        guest
    }

    /// The same driver state on a copy of its guest RAM.
    fn on<'b>(&self, mem: &'b GuestMemoryMmap) -> Guest<'b> {
        Guest {
            mem,
            rx: self.rx,
            tx: self.tx,
            ev: self.ev,
            rx_seen: self.rx_seen,
            tx_sent: self.tx_sent,
            ev_offered: self.ev_offered,
            tx_event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
        }
    }

    fn queues(&self) -> Vec<DeviceQueue> {
        self.device_queues([self.rx.queue(), self.tx.queue(), self.ev.queue()])
    }

    fn device_queues(&self, [rx, tx, ev]: [Queue; 3]) -> Vec<DeviceQueue> {
        let event = || Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        vec![
            DeviceQueue::new(rx, event()),
            DeviceQueue::new(tx, self.tx_event.clone()),
            DeviceQueue::new(ev, event()),
        ]
    }

    /// Queue one guest packet; `len` zero bytes of data for OP_RW.
    fn send(&mut self, op: u16, src_port: u32, dst_port: u32, len: u32) {
        queue_tx(
            self.mem,
            &self.tx,
            self.tx_sent,
            (op, src_port, dst_port, len),
        );
        self.tx_sent += 1;
    }

    fn tx_used(&self) -> u16 {
        self.tx.used_idx(self.mem)
    }

    /// Offer one event buffer described by (address, length, flags).
    fn offer_event(&mut self, addr: u64, len: u32, flags: u16) {
        let slot = self.ev_offered % EV_SLOTS;
        self.ev.set_desc(self.mem, slot, addr, len, flags, 0);
        self.ev.publish(self.mem, slot);
        self.ev_offered += 1;
    }

    /// Offer one event buffer chained from `descs` (index, address, length,
    /// flags, next); the first is the head.
    fn offer_event_chain(&mut self, descs: &[(u16, u64, u32, u16, u16)]) {
        for &(index, addr, len, flags, next) in descs {
            self.ev.set_desc(self.mem, index, addr, len, flags, next);
        }
        self.ev.publish(self.mem, descs[0].0);
        self.ev_offered += 1;
    }

    /// Offer one well-formed four-byte event buffer.
    fn offer_event_buffer(&mut self) {
        let addr = EV_BUFS + 16 * u64::from(self.ev_offered % EV_SLOTS);
        self.mem.write_obj(UNWRITTEN, GuestAddress(addr)).unwrap();
        self.offer_event(addr, 4, VIRTQ_DESC_F_WRITE);
    }

    fn events_used(&self) -> u16 {
        self.ev.used_idx(self.mem)
    }

    /// The event id the device wrote into used event entry `n` and its
    /// used length.
    fn event(&self, n: u16) -> (u32, u32) {
        let (head, len) = self.ev.used_elem(self.mem, n);
        let addr: u64 = self
            .mem
            .read_obj(GuestAddress(self.ev.desc + 16 * u64::from(head)))
            .unwrap();
        (self.mem.read_obj(GuestAddress(addr)).unwrap(), len)
    }

    fn rx_used(&self) -> u16 {
        self.rx.used_idx(self.mem)
    }

    /// The next host packet, waiting for the device; its buffer is offered again.
    fn recv(&mut self) -> Hdr {
        wait_for("an RX packet", || self.rx_used() != self.rx_seen);
        let (id, _) = self.rx.used_elem(self.mem, self.rx_seen);
        self.rx_seen = self.rx_seen.wrapping_add(1);
        let addr = RX_BUFS + u64::from(id) * u64::from(RX_BUF_LEN);
        let read_u32 = |off| self.mem.read_obj::<u32>(GuestAddress(addr + off)).unwrap();
        let hdr = Hdr {
            op: self.mem.read_obj(GuestAddress(addr + 30)).unwrap(),
            src_port: read_u32(16),
            dst_port: read_u32(20),
        };
        self.rx.publish(self.mem, id as u16);
        hdr
    }

    /// Every host packet delivered so far, without waiting.
    fn recv_delivered(&mut self) -> Vec<Hdr> {
        let mut delivered = Vec::new();
        while self.rx_used() != self.rx_seen {
            delivered.push(self.recv());
        }
        delivered
    }

    /// After a settle time: no host packet for any of the guest `ports`
    /// (macOS also delivers unrelated timesync packets).
    fn assert_nothing_for(&mut self, ports: &[u32]) {
        thread::sleep(SETTLE);
        let stale: Vec<_> = self
            .recv_delivered()
            .into_iter()
            .filter(|hdr| ports.contains(&hdr.dst_port))
            .collect();
        assert!(stale.is_empty(), "a stale packet was answered: {stale:?}");
    }

    fn recv_op(&mut self, op: u16) -> Hdr {
        loop {
            let hdr = self.recv();
            if hdr.op == op {
                return hdr;
            }
        }
    }

    /// Every TX chain from `from` on completed with length 0.
    fn assert_tx_completed_empty(&self, from: u16) {
        assert_eq!(self.tx_used(), self.tx_sent, "TX left in the ring");
        for n in from..self.tx_sent {
            assert_eq!(self.tx.used_elem(self.mem, n).1, 0, "TX entry {n}");
        }
    }
}

/// Queue guest packet number `sent` (op, src_port, dst_port, len) on `tx`;
/// `len` zero bytes of data for OP_RW.
fn queue_tx(
    mem: &GuestMemoryMmap,
    tx: &Ring,
    sent: u16,
    (op, src, dst, len): (u16, u32, u32, u32),
) {
    let slot = sent % TX_PACKETS;
    let hdr = TX_HDRS + u64::from(slot) * 64;
    let head = slot * 2;
    write_hdr(mem, hdr, src, dst, len, op);
    if len == 0 {
        tx.set_desc(mem, head, hdr, 44, 0, 0);
    } else {
        let data = TX_DATA + u64::from(slot) * u64::from(DATA_LEN);
        tx.set_desc(mem, head, hdr, 44, VIRTQ_DESC_F_NEXT, head + 1);
        tx.set_desc(mem, head + 1, data, len, 0, 0);
    }
    tx.publish(mem, head);
}

fn write_hdr(mem: &GuestMemoryMmap, addr: u64, src_port: u32, dst_port: u32, len: u32, op: u16) {
    let at = |off| GuestAddress(addr + off);
    mem.write_obj(GUEST_CID, at(0)).unwrap();
    mem.write_obj(uapi::VSOCK_HOST_CID, at(8)).unwrap();
    mem.write_obj(src_port, at(16)).unwrap();
    mem.write_obj(dst_port, at(20)).unwrap();
    mem.write_obj(len, at(24)).unwrap();
    mem.write_obj(uapi::VSOCK_TYPE_STREAM, at(28)).unwrap();
    mem.write_obj(op, at(30)).unwrap();
    mem.write_obj(0u32, at(32)).unwrap();
    mem.write_obj(256 * 1024u32, at(36)).unwrap();
    mem.write_obj(0u32, at(40)).unwrap();
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(1));
    }
}

fn guest_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap()
}

/// A new guest RAM holding a copy of `mem`, like a restored image.
fn copy_memory(mem: &GuestMemoryMmap) -> GuestMemoryMmap {
    let mut bytes = vec![0u8; MEM_SIZE as usize];
    mem.read_slice(&mut bytes, GuestAddress(0)).unwrap();
    let copy = guest_memory();
    copy.write_slice(&bytes, GuestAddress(0)).unwrap();
    copy
}

/// Holders of the guest RAM mapping besides the probe itself.
fn ram_refs(mem: &GuestMemoryMmap) -> usize {
    let (_, region) = mem.remove_region(GuestAddress(0), MEM_SIZE).unwrap();
    Arc::strong_count(&region) - 1
}

/// Live vsock worker threads (Linux only: thread names from procfs).
fn vsock_threads() -> Option<usize> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let tasks = std::fs::read_dir("/proc/self/task").unwrap();
    Some(
        tasks
            .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .filter(|name| name.starts_with("vsock "))
            .count(),
    )
}

/// A joined thread can stay listed until the kernel reaps it, shortly after
/// the join returned.
fn assert_vsock_threads(expected: usize) {
    if vsock_threads().is_some() {
        wait_for("the expected vsock worker threads", || {
            vsock_threads() == Some(expected)
        });
    }
}

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kv{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

fn new_vsock(ports: &[(u32, &Path, bool)], tsi: TsiFlags) -> Vsock {
    let map: HashMap<u32, (PathBuf, bool)> = ports
        .iter()
        .map(|(port, path, listen)| (*port, (path.to_path_buf(), *listen)))
        .collect();
    Vsock::new(GUEST_CID, None, Some(map), tsi).unwrap()
}

fn interrupt() -> InterruptTransport {
    InterruptTransport::new(DummyIrqChip::new().into(), "vsock".to_string()).unwrap()
}

/// Take the used-buffer interrupt status bit: whether it was raised since
/// the last call.
fn take_interrupt(interrupt: &InterruptTransport) -> bool {
    interrupt.status().swap(0, Ordering::SeqCst) & 1 != 0
}

/// A host listener that must not see a connection: polled without blocking.
fn idle_listener(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_no_connection(listener: &UnixListener) {
    thread::sleep(SETTLE);
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("a stale request reached the host: {other:?}"),
    }
}

fn accept(listener: &UnixListener) -> UnixStream {
    let mut stream = None;
    wait_for("a host connection", || {
        stream = listener.accept().ok().map(|(stream, _)| stream);
        stream.is_some()
    });
    // macOS hands out accepted sockets nonblocking like their listener.
    let stream = stream.unwrap();
    stream.set_nonblocking(false).unwrap();
    stream
}

/// Queue more guest data than the host socket buffers hold, run TX on
/// another thread under the device lock, like the event thread, and wait
/// until it is stuck in a send: the lock stays held and TX makes no
/// progress. The receiver reports when TX processing returned.
fn block_in_send(
    vsock: &Arc<Mutex<Vsock>>,
    guest: &mut Guest,
    src_port: u32,
    dst_port: u32,
) -> Receiver<()> {
    let start = guest.tx_used();
    for _ in 0..TX_PACKETS {
        guest.send(uapi::VSOCK_OP_RW, src_port, dst_port, DATA_LEN);
    }
    let (done, finished) = channel();
    let device = vsock.clone();
    thread::spawn(move || {
        device.lock().unwrap().process_stream_tx();
        let _ = done.send(());
    });
    let mut last = guest.tx_used();
    loop {
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            finished.try_recv(),
            Err(TryRecvError::Empty),
            "send never blocked"
        );
        let used = guest.tx_used();
        if used == last && vsock.try_lock().is_err() {
            assert!(used.wrapping_sub(start) < TX_PACKETS);
            return finished;
        }
        last = used;
    }
}

/// A host peer whose reads give up instead of hanging a failing test (macOS
/// refuses the timeout once the socket is disconnected, so set it first).
fn bounded(peer: UnixStream) -> UnixStream {
    peer.set_read_timeout(Some(WAIT)).unwrap();
    peer
}

/// The host peer sees end-of-stream after the data that was sent.
fn assert_peer_closed(peer: &mut UnixStream) {
    let mut sink = Vec::new();
    peer.read_to_end(&mut sink).unwrap();
}

/// A guest-initiated connection from `src_port` to `dst_port`, which the
/// device maps to the host listener `listener`.
fn guest_connect(
    vsock: &mut Vsock,
    guest: &mut Guest,
    listener: &UnixListener,
    (src_port, dst_port): (u32, u32),
) -> UnixStream {
    guest.send(uapi::VSOCK_OP_REQUEST, src_port, dst_port, 0);
    vsock.process_stream_tx();
    let response = guest.recv_op(uapi::VSOCK_OP_RESPONSE);
    assert_eq!(response.dst_port, src_port);
    bounded(accept(listener))
}

/// A host-initiated connection through the listening path `path`; the guest
/// accepts it on `HOST_PORT`. Returns the host peer and the connection's
/// host-side vsock port.
fn host_connect(vsock: &mut Vsock, guest: &mut Guest, path: &Path) -> (UnixStream, u32) {
    let peer = bounded(UnixStream::connect(path).unwrap());
    let request = guest.recv_op(uapi::VSOCK_OP_REQUEST);
    assert_eq!(request.dst_port, HOST_PORT);
    guest.send(uapi::VSOCK_OP_RESPONSE, HOST_PORT, request.src_port, 0);
    vsock.process_stream_tx();
    (peer, request.src_port)
}

/// Quiescing through the gate taken before the device lock interrupts a
/// guest-initiated connection's send blocked under that lock. The stop
/// completes the rest of the ring empty, and the restart delivers the
/// transport reset before anything else: no stale packet is replayed.
#[test]
fn snapshot_vsock_quiesce_interrupts_guest_connection_send() {
    let dir = test_dir("guest");
    let path = dir.join("host.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let irq = interrupt();
    let mut device = new_vsock(&[(HOST_PORT, &path, false)], TsiFlags::empty());
    device
        .activate(mem.clone(), irq.clone(), guest.queues())
        .unwrap();
    let gate = device.snapshot_control().unwrap();
    let vsock = Arc::new(Mutex::new(device));

    guest.send(uapi::VSOCK_OP_REQUEST, GUEST_PORT, HOST_PORT, 0);
    vsock.lock().unwrap().process_stream_tx();
    guest.recv_op(uapi::VSOCK_OP_RESPONSE);
    let mut peer = bounded(listener.accept().unwrap().0);

    let finished = block_in_send(&vsock, &mut guest, GUEST_PORT, HOST_PORT);
    gate.quiesce();
    finished
        .recv_timeout(WAIT)
        .expect("quiesce must interrupt the blocked send");
    assert_peer_closed(&mut peer);
    let consumed = guest.tx_used();
    assert!(
        consumed < guest.tx_sent,
        "deferred packets stay in the ring until the stop"
    );

    let mut device = vsock.lock().unwrap();
    take_interrupt(&irq);
    device.stop_backend().unwrap();
    guest.assert_tx_completed_empty(consumed);
    assert!(!take_interrupt(&irq), "the stop raises nothing; it is owed");
    assert_eq!(
        device.snapshot_reset_state(),
        VsockResetState {
            pending: true,
            interrupt_owed: true
        }
    );
    let states = device.snapshot_queue_states().unwrap();
    assert_eq!(states.len(), 3);
    assert_eq!(states[1].next_avail, guest.tx_sent);

    let _ = guest.tx_event.read();
    guest.recv_delivered();
    guest.offer_event_buffer();
    device.restart_backend().unwrap();
    assert_eq!(guest.events_used(), 1);
    assert_eq!(
        guest.event(0),
        (uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, 4)
    );
    assert!(take_interrupt(&irq), "the owed interrupt is raised");
    assert_eq!(device.snapshot_reset_state(), VsockResetState::default());
    assert_eq!(guest.tx_event.read().unwrap(), 1, "restart notifies TX");
    device.process_stream_tx();
    guest.assert_nothing_for(&[GUEST_PORT]);
}

/// The same for a host-initiated connection accepted on a listening path,
/// which a stopped backend removes and a restarted one serves again only
/// after the reset was delivered.
#[test]
fn snapshot_vsock_quiesce_interrupts_host_connection_send() {
    let dir = test_dir("host");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let mut device = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    device
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let gate = device.snapshot_control().unwrap();
    let vsock = Arc::new(Mutex::new(device));

    let (mut peer, peer_port) = host_connect(&mut vsock.lock().unwrap(), &mut guest, &path);

    let finished = block_in_send(&vsock, &mut guest, HOST_PORT, peer_port);
    gate.quiesce();
    finished
        .recv_timeout(WAIT)
        .expect("quiesce must interrupt the blocked send");
    assert_peer_closed(&mut peer);

    let mut device = vsock.lock().unwrap();
    device.stop_backend().unwrap();
    assert!(!path.exists(), "the bound path is removed");
    guest.offer_event_buffer();
    device.restart_backend().unwrap();
    assert_eq!(guest.events_used(), 1);
    let _peer = UnixStream::connect(&path).unwrap();
    assert_eq!(guest.recv_op(uapi::VSOCK_OP_REQUEST).dst_port, HOST_PORT);
}

/// Repeated stop/restart releases every worker thread and backend RAM
/// reference each time; dropping the device releases the rest and its path.
#[test]
fn snapshot_vsock_repeated_stop_restart_and_drop_release_everything() {
    let dir = test_dir("cycle");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    assert_eq!(ram_refs(&mem), 1);
    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let gate = vsock.snapshot_control().unwrap();

    for cycle in 0..3 {
        let _peer = UnixStream::connect(&path).unwrap();
        guest.recv_op(uapi::VSOCK_OP_REQUEST);
        assert!(ram_refs(&mem) > 2);
        assert_vsock_threads(2);

        gate.quiesce();
        vsock.stop_backend().unwrap();
        assert_eq!(ram_refs(&mem), 2, "only the test and the device state");
        assert_vsock_threads(0);
        assert!(!path.exists());
        assert!(matches!(
            vsock.snapshot_queue_states().as_deref(),
            Some([_, _, _])
        ));

        guest.offer_event_buffer();
        vsock.restart_backend().unwrap();
        assert_eq!(guest.events_used(), cycle + 1, "one reset per stop");
        assert!(is_socket(&path));
        assert!(matches!(
            vsock.restart_backend(),
            Err(VsockError::BackendState(_))
        ));
        assert!(vsock.snapshot_queue_states().is_none(), "running");
    }

    drop(vsock);
    assert_eq!(ram_refs(&mem), 1);
    assert_vsock_threads(0);
    assert!(!path.exists());
}

fn backend_failed(stopped: Result<(), VsockError>) -> bool {
    matches!(stopped, Err(VsockError::BackendFailed))
}

/// A worker panic reaches the owner through `stop_backend`, now and on every
/// later stop, yet the stop still joins every other worker and releases the
/// backend's guest RAM and paths; the failed backend never restarts.
#[test]
fn snapshot_vsock_stop_reports_worker_panic_after_full_cleanup() {
    let dir = test_dir("panic");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let gate = vsock.snapshot_control().unwrap();
    // Joined after the panicked worker, ahead of the real ones; it still
    // holds guest RAM when the stop starts.
    let slow_mem = mem.clone();
    vsock.muxer.adopt_worker_for_test(thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        drop(slow_mem);
    }));
    vsock
        .muxer
        .adopt_worker_for_test(thread::spawn(|| panic!("injected vsock worker panic")));
    assert!(is_socket(&path));

    gate.quiesce();
    assert!(
        backend_failed(vsock.stop_backend()),
        "stop must report the panicked worker"
    );
    assert_eq!(
        ram_refs(&mem),
        2,
        "every worker joined, backend RAM released"
    );
    assert_vsock_threads(0);
    assert!(!path.exists());
    assert!(
        backend_failed(vsock.stop_backend()),
        "a later stop keeps the failure"
    );
    assert!(backend_failed(vsock.restart_backend()));
    assert!(!path.exists());

    drop(vsock);
    assert_eq!(ram_refs(&mem), 1);
}

/// Every device, TSI included, joins its workers and releases guest RAM and
/// the paths it bound on drop.
#[test]
fn snapshot_vsock_drop_joins_workers_and_releases_ram_and_paths() {
    let dir = test_dir("drop");
    for tsi in [
        TsiFlags::empty(),
        TsiFlags::HIJACK_INET | TsiFlags::HIJACK_UNIX,
    ] {
        let path = dir.join("guest.sock");
        let mem = guest_memory();
        let guest = Guest::new(&mem);
        let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], tsi);
        vsock
            .activate(mem.clone(), interrupt(), guest.queues())
            .unwrap();
        wait_for("the listening path", || is_socket(&path));
        assert!(ram_refs(&mem) > 2);

        drop(vsock);
        assert_vsock_threads(0);
        assert_eq!(ram_refs(&mem), 1);
        assert!(!path.exists());
    }
}

/// TSI devices refuse every snapshot hook without keeping anything.
#[test]
fn snapshot_vsock_tsi_refuses_snapshot_hooks() {
    for tsi in [TsiFlags::HIJACK_INET, TsiFlags::HIJACK_UNIX] {
        let mem = guest_memory();
        let guest = Guest::new(&mem);
        let mut vsock = new_vsock(&[], tsi);
        assert!(matches!(
            vsock.snapshot_control(),
            Err(VsockError::TsiEnabled)
        ));
        assert!(vsock
            .activate_frozen(mem.clone(), interrupt(), guest.queues())
            .is_err());
        assert!(!vsock.is_activated());
        assert_eq!(ram_refs(&mem), 1);
    }
}

/// An inactive device binds nothing, has nothing to stop or capture and
/// owes no reset, so it stays inactive; a frozen activation (a restore)
/// binds nothing until its restart.
#[test]
fn snapshot_vsock_inactive_and_frozen_devices_bind_only_on_restart() {
    let dir = test_dir("inactive");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    vsock.snapshot_control().unwrap().quiesce();
    vsock.stop_backend().unwrap();
    assert!(vsock.snapshot_queue_states().is_none());
    assert_eq!(vsock.snapshot_reset_state(), VsockResetState::default());
    assert!(matches!(
        vsock.restart_backend(),
        Err(VsockError::BackendState(_))
    ));
    assert!(!vsock.is_activated());
    assert!(!path.exists());

    vsock
        .activate_frozen(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    assert!(!path.exists());
    assert_vsock_threads(0);
    assert_eq!(ram_refs(&mem), 2);
    assert!(vsock.snapshot_queue_states().is_some());
    assert!(
        vsock
            .restore_reset_state(VsockResetState::default())
            .is_err(),
        "reset state is restored before activation"
    );
    vsock.restart_backend().unwrap();
    assert!(is_socket(&path));
    drop(vsock);
    assert!(!path.exists());
}

/// Only paths this backend bound are removed: an occupied path is skipped
/// on activation but fails a restart, which then leaves no listener
/// behind; a path replaced after binding survives the stop.
#[test]
fn snapshot_vsock_restart_requires_every_listener_and_keeps_foreign_paths() {
    let dir = test_dir("paths");
    let ours = dir.join("ours.sock");
    let taken = dir.join("taken.sock");
    std::fs::write(&taken, b"not ours").unwrap();
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let ports = [
        (HOST_PORT, ours.as_path(), true),
        (HOST_PORT + 1, &taken, true),
    ];
    let mut vsock = new_vsock(&ports, TsiFlags::empty());

    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    assert!(
        is_socket(&ours),
        "activation keeps the warn-and-skip policy"
    );
    vsock.stop_backend().unwrap();
    assert!(!ours.exists());
    assert_eq!(std::fs::read(&taken).unwrap(), b"not ours");

    guest.offer_event_buffer();
    let error = vsock.restart_backend().unwrap_err();
    assert!(format!("{error:?}").contains("taken.sock"), "{error:?}");
    assert!(!ours.exists(), "a failed restart leaves no listener");
    assert_eq!(std::fs::read(&taken).unwrap(), b"not ours");
    assert_eq!(ram_refs(&mem), 2);
    assert_vsock_threads(0);

    std::fs::remove_file(&taken).unwrap();
    vsock.restart_backend().unwrap();
    assert!(is_socket(&ours) && is_socket(&taken));
    std::fs::remove_file(&ours).unwrap();
    std::fs::write(&ours, b"replaced").unwrap();
    drop(vsock);
    assert_eq!(std::fs::read(&ours).unwrap(), b"replaced");
    assert!(!taken.exists());
}

/// Without an event buffer the restart raises the owed interrupt but keeps
/// the reset pending and the backend closed. The first event buffer then
/// takes the reset, and only afterwards is the listening path bound. A kick
/// while a pause holds the gate delivers nothing; that pause's resume does.
#[test]
fn snapshot_vsock_reset_waits_for_an_event_buffer_before_connections() {
    let dir = test_dir("evq");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let irq = interrupt();
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), irq.clone(), guest.queues())
        .unwrap();
    let gate = vsock.snapshot_control().unwrap();
    let (_peer, peer_port) = host_connect(&mut vsock, &mut guest, &path);

    gate.quiesce();
    guest.send(uapi::VSOCK_OP_RW, HOST_PORT, peer_port, 16);
    vsock.stop_backend().unwrap();
    take_interrupt(&irq);
    vsock.restart_backend().unwrap();
    assert!(
        take_interrupt(&irq),
        "the owed TX interrupt is raised anyway"
    );
    assert!(vsock.snapshot_reset_state().pending);
    assert!(!path.exists(), "no connection before the reset");
    assert!(UnixStream::connect(&path).is_err());
    assert!(vsock.snapshot_queue_states().is_some(), "backend closed");

    guest.offer_event_buffer();
    vsock.process_evq();
    assert_eq!(guest.events_used(), 1);
    assert_eq!(
        guest.event(0),
        (uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, 4)
    );
    assert!(take_interrupt(&irq));
    assert_eq!(vsock.snapshot_reset_state(), VsockResetState::default());
    assert!(is_socket(&path), "the backend opens after the reset");
    let _peer = host_connect(&mut vsock, &mut guest, &path);
    vsock.process_evq();
    assert_eq!(guest.events_used(), 1, "one reset per stop");

    // The next pause: a kick while the gate is held changes nothing.
    gate.quiesce();
    vsock.stop_backend().unwrap();
    guest.offer_event_buffer();
    vsock.process_evq();
    assert_eq!(guest.events_used(), 1, "a held gate delivers nothing");
    assert!(!path.exists());
    vsock.restart_backend().unwrap();
    assert_eq!(guest.events_used(), 2);
    assert!(is_socket(&path));
}

/// Event buffers that are read-only, too short, outside guest RAM or
/// chained to a read-only descriptor complete with length 0 and never count as the delivery; with
/// only such buffers the reset stays pending, and the next good one takes it.
#[test]
fn snapshot_vsock_malformed_event_buffers_complete_empty() {
    let dir = test_dir("evbad");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let irq = interrupt();
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), irq.clone(), guest.queues())
        .unwrap();
    vsock.stop_backend().unwrap();
    mem.write_obj(UNWRITTEN, GuestAddress(EV_BUFS)).unwrap();

    let malformed = [
        (EV_BUFS, 4, 0),
        (EV_BUFS, 2, VIRTQ_DESC_F_WRITE),
        (MEM_SIZE - 2, 4, VIRTQ_DESC_F_WRITE),
        (EV_BUFS, 4, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT),
    ];
    for (addr, len, flags) in malformed {
        guest.offer_event(addr, len, flags);
    }
    take_interrupt(&irq);
    vsock.restart_backend().unwrap();
    assert_eq!(guest.events_used(), malformed.len() as u16);
    for n in 0..malformed.len() as u16 {
        assert_eq!(guest.ev.used_elem(&mem, n).1, 0, "event entry {n}");
    }
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(EV_BUFS)).unwrap(),
        UNWRITTEN,
        "no event was written"
    );
    assert!(take_interrupt(&irq), "their completion is signalled");
    assert!(vsock.snapshot_reset_state().pending);
    assert!(!path.exists());

    guest.offer_event_buffer();
    vsock.process_evq();
    assert_eq!(
        guest.event(malformed.len() as u16),
        (uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, 4)
    );
    assert!(is_socket(&path));
}

/// The whole event buffer chain is checked before any write: a declared
/// range crossing the end of guest RAM (even when its first four bytes
/// fit), a NEXT link to an invalid descriptor, a cycle and a read-only tail
/// complete with length 0 and keep the reset pending. A device-writable
/// 2 + 2 byte chain then takes the event across both descriptors.
#[test]
fn snapshot_vsock_event_buffer_chains_are_checked_whole() {
    let dir = test_dir("evchain");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let irq = interrupt();
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), irq.clone(), guest.queues())
        .unwrap();
    vsock.stop_backend().unwrap();
    let (near_end, low, high) = (MEM_SIZE - 8, EV_BUFS + 0x100, EV_BUFS + 0x200);
    for addr in [EV_BUFS, near_end, low, high] {
        mem.write_obj(UNWRITTEN, GuestAddress(addr)).unwrap();
    }
    let (w, wn) = (VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
    let invalid = EV_SLOTS + 1;
    let malformed: [&[(u16, u64, u32, u16, u16)]; 4] = [
        &[(0, near_end, 16, w, 0)],
        &[(1, EV_BUFS, 2, wn, 2), (2, EV_BUFS + 2, 2, wn, invalid)],
        &[(3, EV_BUFS, 2, wn, 4), (4, EV_BUFS + 2, 2, wn, 3)],
        &[(5, EV_BUFS, 2, wn, 6), (6, EV_BUFS + 2, 2, 0, 0)],
    ];
    for chain in malformed {
        guest.offer_event_chain(chain);
    }
    vsock.restart_backend().unwrap();
    assert_eq!(guest.events_used(), malformed.len() as u16);
    for n in 0..malformed.len() as u16 {
        assert_eq!(guest.ev.used_elem(&mem, n).1, 0, "event entry {n}");
    }
    for addr in [EV_BUFS, near_end] {
        assert_eq!(mem.read_obj::<u32>(GuestAddress(addr)).unwrap(), UNWRITTEN);
    }
    assert!(vsock.snapshot_reset_state().pending);
    assert!(!path.exists());

    guest.offer_event_chain(&[(7, low, 2, wn, 0), (0, high, 2, w, 0)]);
    vsock.process_evq();
    assert_eq!(guest.events_used(), malformed.len() as u16 + 1);
    assert_eq!(guest.ev.used_elem(&mem, malformed.len() as u16), (7, 4));
    let id = uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET as u16;
    for addr in [low, high] {
        assert_eq!(mem.read_obj::<u16>(GuestAddress(addr)).unwrap(), id);
    }
    assert!(!vsock.snapshot_reset_state().pending);
    assert!(is_socket(&path));
}

/// The stale TX is cut before the reset is published: a REQUEST queued
/// before the reset completes empty and never connects, while one the
/// guest queues the moment the reset becomes visible (the test hook runs
/// right after publication) stays in the ring and connects.
#[test]
fn snapshot_vsock_request_after_reset_publication_is_kept() {
    let dir = test_dir("cut");
    let path = dir.join("host.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, false)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let listener = idle_listener(&path);
    vsock.stop_backend().unwrap();
    vsock.restart_backend().unwrap();
    let cut = guest.tx_used();
    guest.send(uapi::VSOCK_OP_REQUEST, GUEST_PORT, HOST_PORT, 0);

    let (late_mem, tx, sent) = (mem.clone(), guest.tx, guest.tx_sent);
    let fresh = (uapi::VSOCK_OP_REQUEST, GUEST_PORT + 1, HOST_PORT, 0);
    vsock.reset_published_hook = Some(Box::new(move || {
        queue_tx(&late_mem, &tx, sent, fresh);
    }));
    guest.offer_event_buffer();
    vsock.process_evq();
    vsock.reset_published_hook = None;
    guest.tx_sent += 1;
    assert_eq!(guest.events_used(), 1);
    assert_eq!(guest.tx_used(), cut + 1, "only the stale REQUEST completed");
    assert_eq!(guest.tx.used_elem(&mem, cut).1, 0);

    vsock.process_stream_tx();
    let response = guest.recv_op(uapi::VSOCK_OP_RESPONSE);
    assert_eq!(response.dst_port, GUEST_PORT + 1);
    let _peer = accept(&listener);
    assert_no_connection(&listener);
    guest.assert_nothing_for(&[GUEST_PORT]);
}

/// Neither a REQUEST nor an RW queued before the reset reaches a host
/// listener or peer: the stop completes the cut-time TX empty, and the
/// reopen completes what the guest queued while the reset waited. A REQUEST
/// after the reset connects.
#[test]
fn snapshot_vsock_stale_tx_never_replays() {
    let dir = test_dir("stale");
    let path = dir.join("host.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, false)], TsiFlags::empty());
    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let gate = vsock.snapshot_control().unwrap();
    let listener = idle_listener(&path);
    let mut peer = guest_connect(&mut vsock, &mut guest, &listener, (GUEST_PORT, HOST_PORT));

    gate.quiesce();
    let cut = guest.tx_used();
    guest.send(uapi::VSOCK_OP_REQUEST, GUEST_PORT + 1, HOST_PORT, 0);
    guest.send(uapi::VSOCK_OP_RW, GUEST_PORT, HOST_PORT, 32);
    vsock.process_stream_tx();
    assert_eq!(guest.tx_used(), cut, "a quiesced device leaves TX queued");
    vsock.stop_backend().unwrap();
    guest.assert_tx_completed_empty(cut);
    assert_peer_closed(&mut peer);
    // Delivered before the stop; nothing for these ports may follow.
    guest.recv_delivered();

    // Queued after the stop, while the reset waits for an event buffer.
    vsock.restart_backend().unwrap();
    let waiting = guest.tx_used();
    guest.send(uapi::VSOCK_OP_REQUEST, GUEST_PORT + 2, HOST_PORT, 0);
    vsock.process_stream_tx();
    assert_eq!(
        guest.tx_used(),
        waiting,
        "a closed backend leaves TX queued"
    );
    guest.offer_event_buffer();
    vsock.process_evq();
    assert_eq!(guest.events_used(), 1);
    guest.assert_tx_completed_empty(waiting);
    vsock.process_stream_tx();
    assert_no_connection(&listener);
    guest.assert_nothing_for(&[GUEST_PORT, GUEST_PORT + 1, GUEST_PORT + 2]);

    let _fresh = guest_connect(
        &mut vsock,
        &mut guest,
        &listener,
        (GUEST_PORT + 3, HOST_PORT),
    );
}

/// A stopped source restarts with its original paths and serves both
/// directions; a device restored on a copy of its RAM at fresh paths gets
/// the reset first, then serves both directions there and never touches the
/// source's paths.
#[test]
fn snapshot_vsock_source_and_copied_restore_serve_both_directions() {
    let dir = test_dir("restore");
    let (listen_a, host_a) = (dir.join("la.sock"), dir.join("ha.sock"));
    let (listen_b, host_b) = (dir.join("lb.sock"), dir.join("hb.sock"));
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let ports_a = [
        (HOST_PORT, listen_a.as_path(), true),
        (HOST_PORT + 1, &host_a, false),
    ];
    let mut source = new_vsock(&ports_a, TsiFlags::empty());
    source
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    let gate = source.snapshot_control().unwrap();
    let host_listener_a = idle_listener(&host_a);
    let _in = host_connect(&mut source, &mut guest, &listen_a);
    let _out = guest_connect(
        &mut source,
        &mut guest,
        &host_listener_a,
        (GUEST_PORT, HOST_PORT + 1),
    );

    gate.quiesce();
    source.stop_backend().unwrap();
    let states = source.snapshot_queue_states().unwrap();
    let reset = source.snapshot_reset_state();
    assert!(reset.pending);
    let copy = copy_memory(&mem);
    let mut target_guest = guest.on(&copy);

    // The source continues on its original configuration.
    guest.offer_event_buffer();
    source.restart_backend().unwrap();
    assert_eq!(guest.events_used(), 1);
    let _in = host_connect(&mut source, &mut guest, &listen_a);
    let _out = guest_connect(
        &mut source,
        &mut guest,
        &host_listener_a,
        (GUEST_PORT + 1, HOST_PORT + 1),
    );
    drop(source);
    assert!(!listen_a.exists());

    // The restore: queues rebuilt from the cut on the RAM copy, new paths.
    let ports_b = [
        (HOST_PORT, listen_b.as_path(), true),
        (HOST_PORT + 1, &host_b, false),
    ];
    let mut target = new_vsock(&ports_b, TsiFlags::empty());
    target.restore_reset_state(reset).unwrap();
    let queues: Vec<Queue> = states.iter().map(QueueState::to_queue).collect();
    let queues: [Queue; 3] = queues.try_into().unwrap();
    target
        .activate_frozen(
            copy.clone(),
            interrupt(),
            target_guest.device_queues(queues),
        )
        .unwrap();
    assert!(!listen_b.exists());
    target_guest.offer_event_buffer();
    target.restart_backend().unwrap();
    assert_eq!(target_guest.events_used(), 1);
    assert_eq!(
        target_guest.event(0),
        (uapi::VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, 4)
    );
    assert!(!listen_a.exists(), "the source path is not recreated");
    let _in = host_connect(&mut target, &mut target_guest, &listen_b);
    let host_listener_b = idle_listener(&host_b);
    let _out = guest_connect(
        &mut target,
        &mut target_guest,
        &host_listener_b,
        (GUEST_PORT + 2, HOST_PORT + 1),
    );
    assert_no_connection(&host_listener_a);
}

/// A reopen that fails on an event-queue kick (nobody to report it to)
/// writes the failure notifier once and marks the backend failed: the next
/// stop and restart report it.
#[test]
fn snapshot_vsock_deferred_reopen_failure_is_sticky() {
    let dir = test_dir("deferred");
    let path = dir.join("guest.sock");
    let mem = guest_memory();
    let mut guest = Guest::new(&mem);
    let mut vsock = new_vsock(&[(HOST_PORT, &path, true)], TsiFlags::empty());
    let failed = EventFd::new(EFD_NONBLOCK).unwrap();
    vsock.set_failure_notifier(failed.try_clone().unwrap());
    vsock
        .activate(mem.clone(), interrupt(), guest.queues())
        .unwrap();
    vsock.stop_backend().unwrap();
    vsock.restart_backend().unwrap();
    std::fs::write(&path, b"occupied").unwrap();

    guest.offer_event_buffer();
    vsock.process_evq();
    assert_eq!(guest.events_used(), 1, "the reset itself was delivered");
    assert_eq!(failed.read().unwrap(), 1, "the failure was signalled");
    vsock.process_evq();
    assert!(failed.read().is_err(), "a failed backend stays quiet");
    assert!(backend_failed(vsock.stop_backend()));
    assert!(backend_failed(vsock.restart_backend()));
    assert_eq!(std::fs::read(&path).unwrap(), b"occupied");
}

/// The gate shuts a registered socket down through its own duplicate,
/// refuses registrations once quiesced, and keeps no duplicate after the
/// registration is dropped (the peer then sees the proxy's close). A
/// quiesce holds the gate: opening it again for a backend admits nothing
/// until it is released.
#[test]
fn snapshot_vsock_gate_registration_races_and_release() {
    let gate = VsockGate::new();
    let (ours, peer) = UnixStream::pair().unwrap();
    let (ours, mut peer) = (OwnedFd::from(ours), bounded(peer));
    assert!(matches!(gate.register(&ours), Err(ProxyError::Quiesced)));

    gate.open(EventFd::new(EFD_NONBLOCK).unwrap());
    let registration = gate.register(&ours).unwrap();
    let (released, released_peer) = UnixStream::pair().unwrap();
    let (released, mut released_peer) = (OwnedFd::from(released), bounded(released_peer));
    drop(gate.register(&released).unwrap());
    drop(released);
    assert_peer_closed(&mut released_peer);

    gate.quiesce();
    assert!(!registration.is_gate_open());
    assert_peer_closed(&mut peer);
    assert!(matches!(gate.register(&ours), Err(ProxyError::Quiesced)));
    // The proxy's own, still-open descriptor can no longer send.
    let mut stream = UnixStream::from(ours.try_clone().unwrap());
    let sent = stream.write(&[0u8]).map_err(|e| e.kind());
    assert_eq!(sent, Err(ErrorKind::BrokenPipe));

    let wake = EventFd::new(EFD_NONBLOCK).unwrap();
    gate.open(wake.try_clone().unwrap());
    assert!(!gate.is_open(), "a held gate stays closed");
    assert_eq!(wake.read().unwrap(), 1, "its muxer thread is told to exit");
    gate.release();
    gate.open(wake);
    assert!(gate.is_open());
}
