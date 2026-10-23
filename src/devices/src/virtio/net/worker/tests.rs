// Every test name starts with "snapshot_net" so `make snapshot-net-host-test`
// (and the Linux `snapshot` filter) selects them.

use super::*;
use crate::legacy::DummyIrqChip;
use crate::virtio::net::device::{Net, VirtioNetBackend};
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::{Descriptor, Queue, VirtioDevice};
use nix::sys::socket::{setsockopt, socketpair, sockopt, AddressFamily, SockFlag, SockType};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use utils::eventfd::EFD_NONBLOCK;
use vm_memory::{Address, GuestAddress, GuestMemory};

const QSIZE: u16 = 16;
const BUF_LEN: u32 = 2048;
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const TX_DESC: u64 = 0x4000;
const TX_AVAIL: u64 = 0x5000;
const TX_USED: u64 = 0x6000;
const RX_BUFS: u64 = 0x10000;
const TX_BUFS: u64 = 0x20000;

struct Rig {
    mem: GuestMemoryMmap,
    net: Net,
    interrupt: InterruptTransport,
    rx_kick: Arc<EventFd>,
    tx_kick: Arc<EventFd>,
    peer: UnixStream,
    backend_fd: i32,
    rx_posted: u16,
    tx_posted: u16,
}

fn queue(desc: u64, avail: u64, used: u64) -> Queue {
    let mut queue = Queue::new(QSIZE);
    queue.size = QSIZE;
    queue.ready = true;
    queue.desc_table = GuestAddress(desc);
    queue.avail_ring = GuestAddress(avail);
    queue.used_ring = GuestAddress(used);
    queue
}

fn device_queue(queue: Queue) -> (DeviceQueue, Arc<EventFd>) {
    let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
    (DeviceQueue::new(queue, event.clone()), event)
}

impl Rig {
    fn new(start_frozen: bool) -> Rig {
        Rig::new_with(0, false, start_frozen)
    }

    /// Queues whose avail/used indexes and device cursors all start at
    /// `start` (to cross the u16 wrap), with the event index negotiated or
    /// not.
    fn new_with(start: u16, event_idx: bool, start_frozen: bool) -> Rig {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let mut queues = [
            queue(RX_DESC, RX_AVAIL, RX_USED),
            queue(TX_DESC, TX_AVAIL, TX_USED),
        ];
        for queue in &mut queues {
            mem.write_obj(start, queue.avail_ring.unchecked_add(2))
                .unwrap();
            mem.write_obj(start, queue.used_ring.unchecked_add(2))
                .unwrap();
            queue.next_avail = std::num::Wrapping(start);
            queue.next_used = std::num::Wrapping(start);
            queue.set_event_idx(event_idx);
        }
        let [rx, tx] = queues;
        let mut rig = Rig::start(mem, rx, tx, start_frozen);
        rig.rx_posted = start;
        rig.tx_posted = start;
        rig
    }

    /// The device side of a restore, without KVM: guest RAM copied from the
    /// frozen source, queues rebuilt from the cut cursors, every cut-time TX
    /// chain completed as dropped before the worker exists, then a new
    /// backend and a frozen worker. Returns the rig and the discard count.
    fn restored(source: &Rig, states: &NetQueueStates) -> (Rig, u16) {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        mem.write_slice(&source.ram(), GuestAddress(0)).unwrap();
        let mut tx = states.tx.to_queue();
        let discarded = tx.discard_available(&mem).unwrap();
        let owed = discarded > 0 && tx.needs_notification(&mem).unwrap();
        let mut rig = Rig::start(mem, states.rx.to_queue(), tx, true);
        if owed {
            rig.interrupt.try_signal_used_queue().unwrap();
        }
        rig.rx_posted = source.rx_posted;
        rig.tx_posted = source.tx_posted;
        (rig, discarded)
    }

    fn start(mem: GuestMemoryMmap, rx: Queue, tx: Queue, start_frozen: bool) -> Rig {
        let (ours, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let backend_fd = ours.into_raw_fd();
        let mut net = Net::new(
            "snapshot-net".to_string(),
            VirtioNetBackend::UnixstreamFd(backend_fd),
            [2, 0, 0, 0, 0, 1],
            0,
        )
        .unwrap();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
        let (rx_q, rx_kick) = device_queue(rx);
        let (tx_q, tx_kick) = device_queue(tx);
        if start_frozen {
            net.activate_frozen(mem.clone(), interrupt.clone(), vec![rx_q, tx_q])
        } else {
            net.activate(mem.clone(), interrupt.clone(), vec![rx_q, tx_q])
        }
        .unwrap();
        let peer = UnixStream::from(peer);
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        Rig {
            mem,
            net,
            interrupt,
            rx_kick,
            tx_kick,
            peer,
            backend_fd,
            rx_posted: 0,
            tx_posted: 0,
        }
    }

    fn handle(&self) -> &NetWorkerHandle {
        self.net.worker_control().unwrap()
    }

    fn publish(&self, avail: u64, posted: u16, head: u16) {
        self.mem
            .write_obj(
                head,
                GuestAddress(avail + 4 + 2 * u64::from(posted % QSIZE)),
            )
            .unwrap();
        self.mem
            .write_obj(posted.wrapping_add(1), GuestAddress(avail + 2))
            .unwrap();
    }

    /// Offer `count` single-descriptor device-writable RX buffers.
    fn post_rx(&mut self, count: u16) {
        for _ in 0..count {
            let slot = self.rx_posted % QSIZE;
            let descriptor = Descriptor {
                addr: RX_BUFS + u64::from(slot) * u64::from(BUF_LEN),
                len: BUF_LEN,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            self.mem
                .write_obj(descriptor, GuestAddress(RX_DESC + 16 * u64::from(slot)))
                .unwrap();
            self.publish(RX_AVAIL, self.rx_posted, slot);
            self.rx_posted = self.rx_posted.wrapping_add(1);
        }
    }

    /// Submit one TX chain: a zeroed virtio-net header plus `payload`, or a
    /// raw descriptor with explicit flags for malformed-chain tests.
    fn submit_tx_raw(&mut self, bytes: &[u8], flags: u16) {
        let slot = self.tx_posted % QSIZE;
        let addr = TX_BUFS + u64::from(slot) * u64::from(BUF_LEN);
        self.mem.write_slice(bytes, GuestAddress(addr)).unwrap();
        let descriptor = Descriptor {
            addr,
            len: bytes.len() as u32,
            flags,
            next: 0,
        };
        self.mem
            .write_obj(descriptor, GuestAddress(TX_DESC + 16 * u64::from(slot)))
            .unwrap();
        self.publish(TX_AVAIL, self.tx_posted, slot);
        self.tx_posted = self.tx_posted.wrapping_add(1);
    }

    fn submit_tx(&mut self, payload: &[u8]) {
        let mut bytes = vec![0u8; VNET_HDR_LEN];
        bytes.extend_from_slice(payload);
        self.submit_tx_raw(&bytes, 0);
    }

    fn used_idx(&self, used: u64) -> u16 {
        self.mem.read_obj(GuestAddress(used + 2)).unwrap()
    }

    fn used_len(&self, used: u64, index: u16) -> u32 {
        self.mem
            .read_obj(GuestAddress(used + 4 + 8 * u64::from(index % QSIZE) + 4))
            .unwrap()
    }

    fn wait_used(&self, used: u64, target: u16) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.used_idx(used) != target {
            assert!(
                Instant::now() < deadline,
                "used ring {used:#x} stuck at {} (want {target})",
                self.used_idx(used)
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Frame payload the device wrote into RX completion `index`.
    fn rx_frame(&self, index: u16) -> Vec<u8> {
        let id: u32 = self
            .mem
            .read_obj(GuestAddress(RX_USED + 4 + 8 * u64::from(index % QSIZE)))
            .unwrap();
        let len = self.used_len(RX_USED, index) as usize;
        assert!(
            len >= VNET_HDR_LEN,
            "rx completion {index} has length {len}"
        );
        let mut frame = vec![0u8; len];
        self.mem
            .read_slice(
                &mut frame,
                GuestAddress(RX_BUFS + u64::from(id) * u64::from(BUF_LEN)),
            )
            .unwrap();
        assert!(frame[..VNET_HDR_LEN].iter().all(|byte| *byte == 0));
        frame.split_off(VNET_HDR_LEN)
    }

    fn peer_send(&mut self, payload: &[u8]) {
        self.peer
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        self.peer.write_all(payload).unwrap();
    }

    fn peer_recv(&mut self) -> Vec<u8> {
        let mut prefix = [0u8; 4];
        self.peer.read_exact(&mut prefix).unwrap();
        let mut frame = vec![0u8; u32::from_be_bytes(prefix) as usize];
        self.peer.read_exact(&mut frame).unwrap();
        frame
    }

    fn assert_peer_idle(&mut self) {
        self.peer.set_nonblocking(true).unwrap();
        let mut byte = [0u8; 1];
        match self.peer.read(&mut byte) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            other => panic!("peer received data from a frozen worker: {other:?}"),
        }
        self.peer.set_nonblocking(false).unwrap();
    }

    fn ram(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.mem.last_addr().raw_value() as usize + 1];
        self.mem.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        bytes
    }

    fn wait_irq(&self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.irq_status() == 0 {
            assert!(Instant::now() < deadline, "no used-ring interrupt");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn irq_status(&self) -> usize {
        self.interrupt.status().load(Ordering::SeqCst)
    }

    fn clear_irq(&self) {
        self.interrupt.status().store(0, Ordering::SeqCst);
    }
}

fn payload(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag ^ (i as u8)).collect()
}

/// A frozen cut sits on complete descriptor boundaries: every popped chain
/// was completed and mirrored into the used ring in RAM.
fn assert_boundary(rig: &Rig, states: &NetQueueStates) {
    assert_eq!(states.rx.next_used, rig.used_idx(RX_USED));
    assert_eq!(states.tx.next_used, rig.used_idx(TX_USED));
    assert_eq!(states.rx.next_avail, states.rx.next_used);
    assert_eq!(states.tx.next_avail, states.tx.next_used);
}

/// While frozen, neither kicks nor backend traffic may change guest RAM,
/// raise an interrupt or reach the backend.
fn assert_frozen_quiet(rig: &mut Rig) {
    rig.clear_irq();
    let before = rig.ram();
    rig.rx_kick.write(1).unwrap();
    rig.tx_kick.write(1).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(rig.ram() == before, "frozen worker wrote guest RAM");
    assert_eq!(rig.irq_status(), 0, "frozen worker raised an interrupt");
    rig.assert_peer_idle();
}

#[test]
fn snapshot_net_worker_moves_frames_both_ways() {
    let mut rig = Rig::new(false);
    rig.post_rx(4);
    rig.rx_kick.write(1).unwrap();
    let first = payload(1, 60);
    let second = payload(2, 1514);
    rig.peer_send(&first);
    rig.peer_send(&second);
    rig.wait_used(RX_USED, 2);
    assert_eq!(rig.rx_frame(0), first);
    assert_eq!(rig.rx_frame(1), second);
    assert_ne!(rig.irq_status(), 0);

    let out = payload(3, 600);
    rig.submit_tx(&out);
    rig.tx_kick.write(1).unwrap();
    assert_eq!(rig.peer_recv(), out);
    rig.wait_used(TX_USED, 1);
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_freeze_is_quiet_and_resume_needs_no_kick() {
    let mut rig = Rig::new(false);
    rig.post_rx(8);
    rig.rx_kick.write(1).unwrap();
    rig.peer_send(&payload(1, 100));
    rig.wait_used(RX_USED, 1);

    let states = rig.handle().freeze().unwrap();
    assert_boundary(&rig, &states);
    assert_eq!(states.rx.next_used, 1);

    // Traffic in both directions arrives at the frozen worker.
    let inbound: Vec<_> = (0..3)
        .map(|i| payload(0x10 + i, 200 + i as usize))
        .collect();
    for frame in &inbound {
        rig.peer_send(frame);
    }
    let outbound: Vec<_> = (0..2).map(|i| payload(0x20 + i, 300)).collect();
    for frame in &outbound {
        rig.submit_tx(frame);
    }
    assert_frozen_quiet(&mut rig);
    // A repeated freeze reports the same cut.
    assert_eq!(rig.handle().freeze().unwrap(), states);

    // The kicks were drained while frozen; resume alone must make progress.
    rig.handle().resume().unwrap();
    rig.wait_used(RX_USED, 4);
    for (i, frame) in inbound.iter().enumerate() {
        assert_eq!(&rig.rx_frame(1 + i as u16), frame);
    }
    for frame in &outbound {
        assert_eq!(&rig.peer_recv(), frame);
    }
    rig.wait_used(TX_USED, 2);
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_keeps_partial_backend_frame_across_freeze() {
    let mut rig = Rig::new(false);
    rig.post_rx(4);
    rig.rx_kick.write(1).unwrap();
    let frame = payload(7, 900);
    // Prefix and part of the body; the worker must not block on the rest.
    rig.peer
        .write_all(&(frame.len() as u32).to_be_bytes())
        .unwrap();
    rig.peer.write_all(&frame[..300]).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let states = rig.handle().freeze().unwrap();
    assert_boundary(&rig, &states);
    assert_eq!(states.rx.next_used, 0);
    rig.peer.write_all(&frame[300..]).unwrap();
    assert_frozen_quiet(&mut rig);

    rig.handle().resume().unwrap();
    rig.wait_used(RX_USED, 1);
    assert_eq!(rig.rx_frame(0), frame);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(rig.used_idx(RX_USED), 1, "partial frame delivered twice");
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_defers_rx_without_guest_buffers() {
    let mut rig = Rig::new(false);
    let frame = payload(9, 400);
    rig.peer_send(&frame);
    std::thread::sleep(Duration::from_millis(50));
    let states = rig.handle().freeze().unwrap();
    assert_boundary(&rig, &states);
    assert_eq!(rig.used_idx(RX_USED), 0);
    // A buffer posted while frozen is not consumed until resume.
    rig.post_rx(1);
    assert_frozen_quiet(&mut rig);
    rig.handle().resume().unwrap();
    rig.wait_used(RX_USED, 1);
    assert_eq!(rig.rx_frame(0), frame);
    // The deferred frame's completion raises its own interrupt; no later
    // frame is needed to flush it.
    rig.wait_irq();

    // Live path: deferred again, then a kick with a new buffer delivers it.
    let second = payload(10, 500);
    rig.peer_send(&second);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(rig.used_idx(RX_USED), 1);
    rig.clear_irq();
    rig.post_rx(1);
    rig.rx_kick.write(1).unwrap();
    rig.wait_used(RX_USED, 2);
    assert_eq!(rig.rx_frame(1), second);
    rig.wait_irq();
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_freeze_and_stop_under_continuous_traffic() {
    let mut rig = Rig::new(false);
    rig.post_rx(QSIZE);
    rig.rx_kick.write(1).unwrap();
    let first = payload(0x42, 120);
    rig.peer_send(&first);
    rig.wait_used(RX_USED, 1);

    // Endless empty frames from the backend, bounded by a stop flag, a
    // deadline and the worker closing the socket.
    let stop = Arc::new(AtomicBool::new(false));
    let producer = {
        let stop = stop.clone();
        let mut peer = rig.peer.try_clone().unwrap();
        peer.set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        std::thread::spawn(move || {
            let empty_frames = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut sent = 0usize;
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                match peer.write(&empty_frames) {
                    Ok(n) => sent += n,
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    Err(_) => break,
                }
            }
            sent
        })
    };
    // Collect every TX frame the worker sends until the socket closes.
    let reader = {
        let mut peer = rig.peer.try_clone().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        std::thread::spawn(move || {
            let mut frames = Vec::new();
            let mut prefix = [0u8; 4];
            while peer.read_exact(&mut prefix).is_ok() {
                let mut frame = vec![0u8; u32::from_be_bytes(prefix) as usize];
                if peer.read_exact(&mut frame).is_err() {
                    break;
                }
                frames.push(frame);
            }
            frames
        })
    };
    std::thread::sleep(Duration::from_millis(100));

    // TX keeps its turn while RX is flooded.
    let outbound: Vec<_> = (0..6).map(|i| payload(0x60 + i, 200)).collect();
    for frame in &outbound[..4] {
        rig.submit_tx(frame);
    }
    rig.tx_kick.write(1).unwrap();
    rig.wait_used(TX_USED, 4);

    // Freeze lands promptly despite the flood, and stays quiet under it.
    let states = rig
        .handle()
        .freeze_with_timeout(Duration::from_secs(2))
        .unwrap();
    assert_boundary(&rig, &states);
    rig.clear_irq();
    let before = rig.ram();
    std::thread::sleep(Duration::from_millis(100));
    assert!(rig.ram() == before, "frozen worker wrote guest RAM");
    assert_eq!(rig.irq_status(), 0, "frozen worker raised an interrupt");

    rig.handle()
        .resume_with_timeout(Duration::from_secs(2))
        .unwrap();
    for frame in &outbound[4..] {
        rig.submit_tx(frame);
    }
    rig.tx_kick.write(1).unwrap();
    rig.wait_used(TX_USED, 6);
    let states = rig
        .handle()
        .freeze_with_timeout(Duration::from_secs(2))
        .unwrap();
    assert_boundary(&rig, &states);

    // Stop joins promptly; the producer and reader see the closed socket.
    let started = Instant::now();
    rig.net.stop_worker();
    assert!(started.elapsed() < Duration::from_secs(2));
    stop.store(true, Ordering::SeqCst);
    assert!(producer.join().unwrap() > 0);
    assert_eq!(reader.join().unwrap(), outbound);
    // Empty frames are skipped, never delivered to the guest.
    assert_eq!(rig.used_idx(RX_USED), 1);
}

#[test]
fn snapshot_net_worker_tx_backpressure_freeze_and_drain() {
    let mut rig = Rig::new(false);
    // Tiny kernel buffers on both ends so the guest outruns the peer.
    let backend = unsafe { std::os::fd::BorrowedFd::borrow_raw(rig.backend_fd) };
    let _ = setsockopt(&backend, sockopt::SndBuf, &4096);
    let _ = setsockopt(&rig.peer, sockopt::RcvBuf, &4096);
    let frames: Vec<_> = (0..QSIZE).map(|i| payload(i as u8, 1500)).collect();
    for frame in &frames {
        rig.submit_tx(frame);
    }
    rig.tx_kick.write(1).unwrap();
    // Wait until the worker stops making progress against the full socket.
    let mut last = u16::MAX;
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let now = rig.used_idx(TX_USED);
        if now == last {
            break;
        }
        last = now;
    }
    assert!(last < QSIZE, "backpressure never engaged");

    let states = rig.handle().freeze().unwrap();
    assert_boundary(&rig, &states);
    // Unconsumed TX stays in the avail ring for the cut.
    assert_eq!(states.tx.next_avail, last);

    // Draining the peer frees socket space, but a frozen worker must not
    // finish its partial write or pop more chains.
    let before = rig.ram();
    rig.clear_irq();
    rig.peer.set_nonblocking(true).unwrap();
    let mut drained = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match rig.peer.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => drained.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                match rig.peer.read(&mut chunk) {
                    Ok(n) if n > 0 => drained.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            Err(e) => panic!("{e}"),
        }
    }
    rig.peer.set_nonblocking(false).unwrap();
    assert!(rig.ram() == before, "frozen worker wrote guest RAM");
    assert_eq!(rig.irq_status(), 0);
    assert_eq!(rig.used_idx(TX_USED), last);

    // Resume: everything arrives exactly once, in order, intact.
    rig.handle().resume().unwrap();
    let expected: Vec<u8> = frames
        .iter()
        .flat_map(|frame| {
            let mut bytes = (frame.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(frame);
            bytes
        })
        .collect();
    let mut received = drained;
    let mut rest = vec![0u8; expected.len() - received.len()];
    rig.peer.read_exact(&mut rest).unwrap();
    received.extend(rest);
    assert!(
        received == expected,
        "TX byte stream reordered or duplicated"
    );
    rig.wait_used(TX_USED, QSIZE);
    rig.assert_peer_idle();
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_drops_malformed_tx_chains() {
    let mut rig = Rig::new(false);
    // Header-only, shorter-than-header and device-writable chains cannot be
    // sent; they complete as used instead of stalling or panicking.
    rig.submit_tx(&[]);
    rig.submit_tx_raw(&[0u8; 4], 0);
    rig.submit_tx_raw(&[0u8; 64], VIRTQ_DESC_F_WRITE);
    let good = payload(5, 80);
    rig.submit_tx(&good);
    rig.tx_kick.write(1).unwrap();
    assert_eq!(rig.peer_recv(), good);
    rig.wait_used(TX_USED, 4);
    rig.assert_peer_idle();
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_backend_eof_drops_tx_and_stays_controllable() {
    let mut rig = Rig::new(false);
    rig.post_rx(4);
    rig.rx_kick.write(1).unwrap();
    let last = payload(6, 70);
    rig.peer_send(&last);
    rig.peer.shutdown(std::net::Shutdown::Both).unwrap();
    rig.wait_used(RX_USED, 1);
    assert_eq!(rig.rx_frame(0), last);

    // Guest TX keeps completing (as dropped) so its queue never stalls.
    rig.submit_tx(&payload(7, 70));
    rig.submit_tx(&payload(8, 70));
    rig.tx_kick.write(1).unwrap();
    rig.wait_used(TX_USED, 2);

    let states = rig.handle().freeze().unwrap();
    assert_boundary(&rig, &states);
    rig.handle().resume().unwrap();
    rig.net.stop_worker();
}

#[test]
fn snapshot_net_worker_starts_frozen_and_stops_while_frozen() {
    let mut rig = Rig::new(true);
    rig.post_rx(2);
    rig.peer_send(&payload(1, 64));
    rig.submit_tx(&payload(2, 64));
    assert_frozen_quiet(&mut rig);

    let states = rig.handle().freeze().unwrap();
    assert_eq!(states.rx.next_avail, 0);
    assert_eq!(states.tx.next_avail, 0);

    // Stop joins a frozen worker promptly and leaves RAM untouched.
    let control_fd = rig.handle().control_fd.try_clone().unwrap();
    let commands = rig.handle().commands.clone();
    let before = rig.ram();
    let started = Instant::now();
    rig.net.stop_worker();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(rig.net.worker_control().is_none());
    assert!(rig.ram() == before);
    assert_eq!(rig.used_idx(RX_USED), 0);
    assert_eq!(rig.used_idx(TX_USED), 0);

    // Controls to a stopped worker fail instead of hanging.
    let stale = NetWorkerHandle {
        control_fd,
        commands,
    };
    assert_eq!(stale.freeze(), Err(WorkerControlError::WorkerGone));
    // The backend connection closed with the worker: end of stream, or a
    // reset on Linux because the frozen worker never read the queued frame.
    let mut byte = [0u8; 1];
    match rig.peer.read(&mut byte) {
        Ok(0) => {}
        Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
        other => panic!("backend socket still open after stop: {other:?}"),
    }
}

#[test]
fn snapshot_net_restore_with_new_backend_drops_cut_tx_and_flows() {
    let mut source = Rig::new(false);
    source.post_rx(4);
    source.rx_kick.write(1).unwrap();
    let first = payload(1, 100);
    source.peer_send(&first);
    source.wait_used(RX_USED, 1);
    let sent: Vec<_> = (0..2).map(|i| payload(0x10 + i, 300)).collect();
    for frame in &sent {
        source.submit_tx(frame);
    }
    source.tx_kick.write(1).unwrap();
    for frame in &sent {
        assert_eq!(&source.peer_recv(), frame);
    }
    source.wait_used(TX_USED, 2);
    // Let the write-space wakeup from those reads settle before the cut.
    std::thread::sleep(Duration::from_millis(50));

    // At the cut: a partial frame inside the source worker, three TX chains
    // available but not consumed, and a clear interrupt status.
    let partial = payload(2, 900);
    source
        .peer
        .write_all(&(partial.len() as u32).to_be_bytes())
        .unwrap();
    source.peer.write_all(&partial[..300]).unwrap();
    // On Linux an edge-triggered wakeup for those bytes also reports the
    // socket writable, so the worker examines TX: let it pass before the
    // cut-time chains become available.
    std::thread::sleep(Duration::from_millis(50));
    let cut: Vec<_> = (0..3).map(|i| payload(0x20 + i, 200)).collect();
    for frame in &cut {
        source.submit_tx(frame);
    }
    std::thread::sleep(Duration::from_millis(50));
    let states = source.handle().freeze().unwrap();
    assert_boundary(&source, &states);
    assert_eq!(states.tx.next_avail, 2);
    source.clear_irq();

    let (mut target, discarded) = Rig::restored(&source, &states);
    // The source is gone; its backend and buffers go with it.
    source.net.stop_worker();
    assert_eq!(discarded, 3);

    // Cut-time TX is used exactly once with length 0, never sent; earlier
    // completions and RX are untouched; the discard is notified.
    assert_eq!(target.used_idx(TX_USED), 5);
    for index in 2..5u16 {
        assert_eq!(target.used_len(TX_USED, index), 0);
    }
    assert_eq!(target.used_idx(RX_USED), 1);
    assert_ne!(target.irq_status(), 0);
    target.clear_irq();
    assert_frozen_quiet(&mut target);

    // Resume without any kick: RX buffers left at the cut take new frames
    // from the new backend, and new TX reaches only the new backend.
    target.handle().resume().unwrap();
    let fresh = payload(3, 120);
    target.peer_send(&fresh);
    target.wait_used(RX_USED, 2);
    assert_eq!(target.rx_frame(1), fresh);
    let out = payload(4, 64);
    target.submit_tx(&out);
    target.tx_kick.write(1).unwrap();
    assert_eq!(target.peer_recv(), out);
    target.wait_used(TX_USED, 6);
    std::thread::sleep(Duration::from_millis(30));
    target.assert_peer_idle();
    assert_eq!(target.used_idx(TX_USED), 6, "a TX completion repeated");
    target.net.stop_worker();
}

/// Engage TX backpressure: tiny kernel buffers, a peer that does not read,
/// and `frames` submitted at once; returns the TX used index once the
/// worker stops making progress.
fn stall_tx(rig: &mut Rig, frames: &[Vec<u8>]) -> u16 {
    let backend = unsafe { std::os::fd::BorrowedFd::borrow_raw(rig.backend_fd) };
    let _ = setsockopt(&backend, sockopt::SndBuf, &4096);
    let _ = setsockopt(&rig.peer, sockopt::RcvBuf, &4096);
    for frame in frames {
        rig.submit_tx(frame);
    }
    rig.tx_kick.write(1).unwrap();
    let mut last = rig.used_idx(TX_USED).wrapping_sub(1);
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        let now = rig.used_idx(TX_USED);
        if now == last {
            return now;
        }
        last = now;
    }
    panic!("TX never settled");
}

#[test]
fn snapshot_net_restore_after_deferred_rx_and_partial_tx_with_wrapped_event_idx() {
    const START: u16 = 0xfffc;
    let mut source = Rig::new_with(START, true, false);
    // Deferred RX: one guest buffer, two frames.
    source.post_rx(1);
    source.rx_kick.write(1).unwrap();
    let delivered = payload(1, 200);
    let deferred = payload(2, 300);
    source.peer_send(&delivered);
    source.peer_send(&deferred);
    source.wait_used(RX_USED, START.wrapping_add(1));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(source.used_idx(RX_USED), START.wrapping_add(1));
    // TX under backpressure: some sent, possibly one partially, the rest
    // still available at the cut.
    let frames: Vec<_> = (0..12).map(|i| payload(0x30 + i, 1500)).collect();
    let used = stall_tx(&mut source, &frames);
    assert_ne!(used, START.wrapping_add(12), "backpressure never engaged");
    // The driver asks to be notified on the next TX completion.
    source
        .mem
        .write_obj(used, GuestAddress(TX_AVAIL + 4 + 2 * u64::from(QSIZE)))
        .unwrap();

    let states = source.handle().freeze().unwrap();
    assert_boundary(&source, &states);
    assert!(states.rx.event_idx_enabled && states.tx.event_idx_enabled);
    let pending = START.wrapping_add(12).wrapping_sub(states.tx.next_avail);
    assert!(pending > 0);
    source.clear_irq();
    let (mut target, discarded) = Rig::restored(&source, &states);
    assert_eq!(discarded, pending);

    // The source keeps its backend and buffers: after resume the deferred
    // frame and every TX frame (the partial one finished) arrive once, in
    // order, on the ORIGINAL peer.
    source.handle().resume().unwrap();
    source.post_rx(1);
    source.rx_kick.write(1).unwrap();
    source.wait_used(RX_USED, START.wrapping_add(2));
    assert_eq!(source.rx_frame(START.wrapping_add(1)), deferred);
    for frame in &frames {
        assert_eq!(&source.peer_recv(), frame);
    }
    source.wait_used(TX_USED, START.wrapping_add(12));
    source.net.stop_worker();

    // The target completed only the cut-time TX, across the wrap, notified
    // it, and its new peer saw nothing of the old frames.
    assert_eq!(target.used_idx(TX_USED), START.wrapping_add(12));
    for offset in 0..pending {
        let index = states.tx.next_avail.wrapping_add(offset);
        assert_eq!(target.used_len(TX_USED, index), 0);
    }
    assert_ne!(target.irq_status(), 0, "discard owed no notification");
    target.clear_irq();
    assert_frozen_quiet(&mut target);

    // Resume: the deferred frame was not migrated; a fresh buffer takes a
    // fresh frame, and new TX reaches the new peer exactly once.
    target.handle().resume().unwrap();
    target.post_rx(1);
    target.rx_kick.write(1).unwrap();
    let fresh = payload(3, 120);
    target.peer_send(&fresh);
    target.wait_used(RX_USED, START.wrapping_add(2));
    assert_eq!(target.rx_frame(START.wrapping_add(1)), fresh);
    let out = payload(4, 64);
    target.submit_tx(&out);
    target.tx_kick.write(1).unwrap();
    assert_eq!(target.peer_recv(), out);
    target.wait_used(TX_USED, START.wrapping_add(13));
    std::thread::sleep(Duration::from_millis(30));
    target.assert_peer_idle();
    target.net.stop_worker();
}

#[test]
fn snapshot_net_backend_connects_only_on_activation() {
    let dir = std::env::temp_dir().join(format!("kn{}", std::process::id()));
    let _ = std::fs::create_dir(&dir);
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
    let activate = |net: &mut Net| {
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
        let (rx, _) = device_queue(queue(RX_DESC, RX_AVAIL, RX_USED));
        let (tx, _) = device_queue(queue(TX_DESC, TX_AVAIL, TX_USED));
        net.activate_frozen(mem.clone(), interrupt, vec![rx, tx])
    };

    // An inactive device never connects: a missing backend is fine until
    // the guest activates it, and activation then fails with no worker.
    let missing = dir.join("missing.sock");
    let mut net = Net::new(
        "n".to_string(),
        VirtioNetBackend::UnixstreamPath(missing),
        [2, 0, 0, 0, 0, 1],
        0,
    )
    .unwrap();
    assert!(activate(&mut net).is_err());
    assert!(net.worker_control().is_none());
    assert!(!net.is_activated());

    // A listening backend is connected synchronously during activation.
    let path = dir.join("up.sock");
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut net = Net::new(
        "n".to_string(),
        VirtioNetBackend::UnixstreamPath(path.clone()),
        [2, 0, 0, 0, 0, 1],
        0,
    )
    .unwrap();
    assert!(matches!(
        listener.accept(),
        Err(e) if e.kind() == ErrorKind::WouldBlock
    ));
    activate(&mut net).unwrap();
    assert!(listener.accept().is_ok());
    net.stop_worker();
    let _ = std::fs::remove_dir_all(&dir);
}
