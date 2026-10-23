// Every test name starts with "snapshot_console" so `make
// snapshot-console-host-test` (and the Linux `snapshot` filter) selects them.

use std::io::{ErrorKind, Read, Write};
use std::num::Wrapping;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::socket::{recv, setsockopt, sockopt, MsgFlags};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap, VolatileSlice};

use super::console_control::VirtioConsoleControl;
use super::defs::control_event;
use super::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use super::persist::{ConsoleState, SnapshotError, TerminalSize, TxProgress};
use super::port_io::{self, InputKind, OutputState, PortOutput, TerminalKind};
use super::port_queue_mapping::{num_queues, port_id_to_queue_idx, QueueDirection};
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{
    Console, Descriptor, DeviceQueue, InterruptTransport, PortDescription, Queue, VirtioDevice,
};

const QSIZE: u16 = super::defs::QUEUE_SIZE;
const MEM_SIZE: usize = 0x20_0000;
const RINGS: u64 = 0x1_0000;
const BUFS: u64 = 0x4_0000;
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);

fn rx(port: usize) -> usize {
    port_id_to_queue_idx(QueueDirection::Rx, port)
}

fn tx(port: usize) -> usize {
    port_id_to_queue_idx(QueueDirection::Tx, port)
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The driver side of every queue: rings at fixed addresses, a bump
/// allocator for buffers, cursors starting at `start` (to cross the u16
/// wrap).
struct Guest {
    mem: GuestMemoryMmap,
    start: u16,
    posted: Vec<u16>,
    next_desc: Vec<u16>,
    next_buf: u64,
}

impl Guest {
    fn new(queues: usize, start: u16) -> Guest {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
        let guest = Guest {
            mem,
            start,
            posted: vec![start; queues],
            next_desc: vec![0; queues],
            next_buf: BUFS,
        };
        for q in 0..queues {
            guest
                .mem
                .write_obj(start, guest.avail(q).unchecked_add(2))
                .unwrap();
            guest
                .mem
                .write_obj(start, guest.used_ring(q).unchecked_add(2))
                .unwrap();
        }
        guest
    }

    /// The same driver state over a copy of this guest's RAM.
    fn copy(&self) -> Guest {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
        let mut ram = vec![0u8; MEM_SIZE];
        self.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
        mem.write_slice(&ram, GuestAddress(0)).unwrap();
        Guest {
            mem,
            start: self.start,
            posted: self.posted.clone(),
            next_desc: self.next_desc.clone(),
            next_buf: self.next_buf,
        }
    }

    fn desc(&self, q: usize) -> GuestAddress {
        GuestAddress(RINGS + q as u64 * 0x1000)
    }

    fn avail(&self, q: usize) -> GuestAddress {
        self.desc(q).unchecked_add(0x200)
    }

    fn used_ring(&self, q: usize) -> GuestAddress {
        self.desc(q).unchecked_add(0x400)
    }

    fn queue(&self, q: usize) -> Queue {
        let mut queue = Queue::new(QSIZE);
        queue.size = QSIZE;
        queue.ready = true;
        queue.desc_table = self.desc(q);
        queue.avail_ring = self.avail(q);
        queue.used_ring = self.used_ring(q);
        queue.next_avail = Wrapping(self.start);
        queue.next_used = Wrapping(self.start);
        queue
    }

    fn alloc(&mut self, len: u32) -> GuestAddress {
        let addr = GuestAddress(self.next_buf);
        self.next_buf += u64::from(len).next_multiple_of(0x100);
        assert!(self.next_buf <= MEM_SIZE as u64);
        addr
    }

    /// Post a chain of (address, length, device-writable) descriptors.
    fn post(&mut self, q: usize, bufs: &[(GuestAddress, u32, bool)]) -> u16 {
        let head = self.next_desc[q];
        for (i, &(addr, len, write)) in bufs.iter().enumerate() {
            let index = (head + i as u16) % QSIZE;
            let mut flags = if write { VIRTQ_DESC_F_WRITE } else { 0 };
            if i + 1 < bufs.len() {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            let desc = crate::virtio::Descriptor {
                addr: addr.0,
                len,
                flags,
                next: (index + 1) % QSIZE,
            };
            self.mem
                .write_obj(desc, self.desc(q).unchecked_add(16 * u64::from(index)))
                .unwrap();
        }
        self.next_desc[q] = (head + bufs.len() as u16) % QSIZE;
        self.publish(q, head);
        head
    }

    /// Make the chain at `head` available.
    fn publish(&mut self, q: usize, head: u16) {
        let slot = u64::from(self.posted[q] % QSIZE);
        self.mem
            .write_obj(head, self.avail(q).unchecked_add(4 + 2 * slot))
            .unwrap();
        self.posted[q] = self.posted[q].wrapping_add(1);
        self.mem
            .write_obj(self.posted[q], self.avail(q).unchecked_add(2))
            .unwrap();
    }

    /// Overwrite descriptor `index` of queue `q`.
    fn write_desc(&self, q: usize, index: u16, desc: crate::virtio::Descriptor) {
        self.mem
            .write_obj(desc, self.desc(q).unchecked_add(16 * u64::from(index)))
            .unwrap();
    }

    /// Post a driver-readable chain holding `parts`.
    fn post_tx(&mut self, q: usize, parts: &[&[u8]]) -> u16 {
        let bufs: Vec<_> = parts
            .iter()
            .map(|part| {
                let addr = self.alloc(part.len() as u32);
                self.mem.write_slice(part, addr).unwrap();
                (addr, part.len() as u32, false)
            })
            .collect();
        self.post(q, &bufs)
    }

    /// Post one device-writable buffer and return its address.
    fn post_rx(&mut self, q: usize, len: u32) -> GuestAddress {
        let addr = self.alloc(len);
        self.post(q, &[(addr, len, true)]);
        addr
    }

    fn post_control(&mut self, id: u32, event: u16, value: u16) {
        let msg = VirtioConsoleControl { id, event, value };
        self.post_tx(CONTROL_TXQ_INDEX, &[msg.as_slice()]);
    }

    /// Used entries (id, len) since the start cursor.
    fn used(&self, q: usize) -> Vec<(u32, u32)> {
        let idx: u16 = self
            .mem
            .read_obj(self.used_ring(q).unchecked_add(2))
            .unwrap();
        let count = idx.wrapping_sub(self.start);
        (0..count)
            .map(|i| {
                let slot = u64::from(self.start.wrapping_add(i) % QSIZE);
                let at = self.used_ring(q).unchecked_add(4 + 8 * slot);
                let id: u32 = self.mem.read_obj(at).unwrap();
                let len: u32 = self.mem.read_obj(at.unchecked_add(4)).unwrap();
                (id, len)
            })
            .collect()
    }

    fn read(&self, addr: GuestAddress, len: u32) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        self.mem.read_slice(&mut buf, addr).unwrap();
        buf
    }
}

/// One host socket pair: `port` is handed to the console (dup'd), `host`
/// is the test's end.
struct Pipe {
    port: UnixStream,
    host: UnixStream,
}

impl Pipe {
    fn new() -> Pipe {
        let (port, host) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(WAIT)).unwrap();
        Pipe { port, host }
    }

    /// Small socket buffers, so large writes see backpressure.
    fn narrow() -> Pipe {
        let pipe = Pipe::new();
        setsockopt(&pipe.port, sockopt::SndBuf, &4096).unwrap();
        setsockopt(&pipe.host, sockopt::RcvBuf, &4096).unwrap();
        pipe
    }

    fn input(&self) -> Box<dyn port_io::PortInput + Send> {
        port_io::input_to_raw_fd_dup(self.port.as_raw_fd()).unwrap()
    }

    fn output(&self) -> Box<dyn PortOutput + Send> {
        port_io::output_to_raw_fd_dup(self.port.as_raw_fd()).unwrap()
    }

    /// Everything the console wrote that is readable right now.
    fn drain(&mut self) -> Vec<u8> {
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

    /// Wait until the console wrote something, without reading it; the
    /// worker then holds a partly delivered chain while backpressure lasts.
    fn wait_written(&self) {
        let mut byte = [0u8; 1];
        let flags = MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT;
        wait_until("output", || {
            recv(self.host.as_raw_fd(), &mut byte, flags).is_ok_and(|n| n > 0)
        });
    }

    fn read_exact(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.host.read_exact(&mut out).unwrap();
        out
    }
}

struct Rig {
    guest: Guest,
    console: Console,
    interrupt: InterruptTransport,
}

impl Rig {
    /// An activated console whose ports the guest has not opened yet.
    fn new(ports: Vec<PortDescription>, start: u16) -> Rig {
        let guest = Guest::new(num_queues(ports.len()), start);
        let queues = (0..guest.posted.len()).map(|q| guest.queue(q)).collect();
        Rig::activate(guest, Console::new(ports).unwrap(), queues, None)
    }

    /// Activate `console` over `queues`, frozen when restoring `state`.
    fn activate(
        guest: Guest,
        mut console: Console,
        queues: Vec<Queue>,
        state: Option<&ConsoleState>,
    ) -> Rig {
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
        let queues = queues
            .into_iter()
            .map(|q| DeviceQueue::new(q, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())))
            .collect();
        match state {
            Some(state) => {
                console.restore_state(state, true).unwrap();
                console
                    .activate_frozen(guest.mem.clone(), interrupt.clone(), queues)
                    .unwrap();
            }
            None => console
                .activate(guest.mem.clone(), interrupt.clone(), queues)
                .unwrap(),
        }
        Rig {
            guest,
            console,
            interrupt,
        }
    }

    /// The device side of a restore, without KVM: RAM copied from the
    /// frozen source, queues rebuilt from the cut, fresh endpoints.
    fn restored(source: &Rig, ports: Vec<PortDescription>) -> Rig {
        let state = source.console.snapshot_state().unwrap();
        let queues = source.console.snapshot_queue_states().unwrap().unwrap();
        let guest = source.guest.copy();
        state.validate_guest(&guest.mem, &queues, true).unwrap();
        for queue in &queues {
            queue.validate(&guest.mem, true).unwrap();
        }
        let queues = queues.iter().map(QueueState::to_queue).collect();
        Rig::activate(guest, Console::new(ports).unwrap(), queues, Some(&state))
    }

    /// The guest opens `port` (VIRTIO_CONSOLE_PORT_OPEN), starting its I/O.
    fn open(&mut self, port: u32) {
        self.guest
            .post_control(port, control_event::VIRTIO_CONSOLE_PORT_OPEN, 1);
        self.console.process_control_tx();
        assert!(self.console.ports[port as usize].is_started());
    }

    fn kick(&mut self, q: usize) {
        self.console.notify_port_queue_event(q);
    }

    fn freeze(&mut self) -> (ConsoleState, Vec<QueueState>) {
        self.console
            .snapshot_freeze_with_timeout(Duration::from_secs(5))
            .unwrap();
        let state = self.console.snapshot_state().unwrap();
        let queues = self.console.snapshot_queue_states().unwrap().unwrap();
        // Repeated captures of one freeze are pure and identical.
        assert_eq!(self.console.snapshot_state().unwrap(), state);
        assert_eq!(
            self.console.snapshot_queue_states().unwrap().unwrap(),
            queues
        );
        (state, queues)
    }

    fn resume(&mut self) {
        self.console
            .snapshot_resume_with_timeout(Duration::from_secs(5))
            .unwrap();
    }

    /// Received bytes of every used RX entry, given the buffer addresses in
    /// posting order.
    fn received(&self, q: usize, bufs: &[GuestAddress]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (_, len)) in self.guest.used(q).into_iter().enumerate() {
            out.extend(self.guest.read(bufs[i], len));
        }
        out
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn fd_port(name: &'static str, input: Option<&Pipe>, output: Option<&Pipe>) -> PortDescription {
    PortDescription {
        name: name.into(),
        input: input.map(Pipe::input),
        output: output.map(Pipe::output),
        terminal: None,
    }
}

#[test]
fn snapshot_console_multiport_rx_tx_capture_is_pure_and_resumable() {
    let (con_in, mut con_out, mut out1, in2) = (Pipe::new(), Pipe::new(), Pipe::new(), Pipe::new());
    let ports = vec![
        PortDescription::console(
            Some(con_in.input()),
            Some(con_out.output()),
            port_io::term_fixed_size(80, 24),
        ),
        PortDescription::output_pipe("krun-stdout", out1.output()),
        PortDescription::input_pipe("krun-stdin", in2.input()),
    ];
    let mut rig = Rig::new(ports, 0);
    for port in 0..3 {
        rig.open(port);
    }

    (&con_in.host).write_all(b"hello").unwrap();
    let rx0 = rig.guest.post_rx(rx(0), 64);
    rig.kick(rx(0));
    (&in2.host).write_all(b"in2").unwrap();
    let rx2 = rig.guest.post_rx(rx(2), 64);
    rig.kick(rx(2));
    rig.guest.post_tx(tx(0), &[b"con-", b"out"]);
    rig.kick(tx(0));
    rig.guest.post_tx(tx(1), &[b"out1"]);
    rig.kick(tx(1));

    assert_eq!(con_out.read_exact(7), b"con-out");
    assert_eq!(out1.read_exact(4), b"out1");
    wait_until("both RX ports", || {
        rig.guest.used(rx(0)).len() == 1 && rig.guest.used(rx(2)).len() == 1
    });
    assert_eq!(rig.received(rx(0), &[rx0]), b"hello");
    assert_eq!(rig.received(rx(2), &[rx2]), b"in2");
    wait_until("both TX completions", || {
        rig.guest.used(tx(0)) == [(0, 7)] && rig.guest.used(tx(1)) == [(0, 4)]
    });

    let (state, queues) = rig.freeze();
    assert_eq!(state.ports.len(), 3);
    assert_eq!(state.ports[0].input, Some(InputKind::Fd));
    assert_eq!(state.ports[0].output, Some(OutputState::Fd));
    assert_eq!(
        state.ports[0].terminal,
        Some(TerminalKind::Fixed { cols: 80, rows: 24 })
    );
    assert_eq!(
        (state.ports[1].name.as_str(), state.ports[1].input.is_none()),
        ("krun-stdout", true)
    );
    assert_eq!(
        (
            state.ports[2].name.as_str(),
            state.ports[2].output.is_none()
        ),
        ("krun-stdin", true)
    );
    assert!(state.ports.iter().all(|p| p.started && !p.eof));
    assert!(state.ports.iter().all(|p| p.tx_in_flight.is_none()));
    // Port 2 has no output: its idle TX queue is captured untouched.
    assert_eq!(queues[tx(2)].next_avail, 0);
    assert_eq!((queues[rx(0)].next_avail, queues[rx(0)].next_used), (1, 1));
    for queue in &queues {
        queue.validate(&rig.guest.mem, true).unwrap();
    }
    state.validate_guest(&rig.guest.mem, &queues, true).unwrap();

    rig.resume();
    (&con_in.host).write_all(b"again").unwrap();
    let rx0b = rig.guest.post_rx(rx(0), 64);
    rig.kick(rx(0));
    wait_until("RX after resume", || rig.guest.used(rx(0)).len() == 2);
    assert_eq!(rig.received(rx(0), &[rx0, rx0b]), b"helloagain");
}

#[test]
fn snapshot_console_partial_tx_resumes_exact_remainder_once() {
    // Cursors start just before the u16 wrap, so the in-flight chain sits
    // in the last slot of the sequence space.
    let mut source_out = Pipe::narrow();
    let mut rig = Rig::new(vec![fd_port("", None, Some(&source_out))], 0xffff);
    rig.open(0);
    let data = pattern(3 * 48 * 1024);
    let parts: Vec<&[u8]> = data.chunks(48 * 1024).collect();
    let head = rig.guest.post_tx(tx(0), &parts);
    rig.kick(tx(0));
    source_out.wait_written();

    let (state, queues) = rig.freeze();
    let progress = state.ports[0].tx_in_flight.expect("a chain is in flight");
    assert_eq!(progress.head, head);
    let delivered = progress.delivered as usize;
    assert!(delivered > 0 && delivered < data.len(), "{delivered}");
    // The host holds exactly the delivered prefix, and a frozen worker
    // writes nothing more although the output is writable again.
    assert_eq!(source_out.drain(), data[..delivered]);
    thread::sleep(QUIET);
    assert!(source_out.drain().is_empty());
    assert!(rig.guest.used(tx(0)).is_empty());
    assert_eq!(queues[tx(0)].next_avail, 0);
    assert_eq!(rig.console.snapshot_state().unwrap(), state);

    // A corrupted cut is rejected against RAM.
    let mut bad = state.clone();
    bad.ports[0].tx_in_flight = Some(TxProgress {
        head,
        delivered: data.len() as u32,
    });
    assert!(bad.validate_guest(&rig.guest.mem, &queues, true).is_err());
    bad.ports[0].tx_in_flight = Some(TxProgress {
        head: head + 1,
        delivered: 1,
    });
    assert!(bad.validate_guest(&rig.guest.mem, &queues, true).is_err());

    // Restore with a fresh output: nothing is written before resume, then
    // only the remainder, and the chain completes exactly once.
    let mut fresh_out = Pipe::new();
    let mut restored = Rig::restored(&rig, vec![fd_port("", None, Some(&fresh_out))]);
    thread::sleep(QUIET);
    assert!(fresh_out.drain().is_empty());
    restored.resume();
    assert_eq!(
        fresh_out.read_exact(data.len() - delivered),
        data[delivered..]
    );
    wait_until("restored completion", || {
        !restored.guest.used(tx(0)).is_empty()
    });
    assert_eq!(
        restored.guest.used(tx(0)),
        [(u32::from(head), data.len() as u32)]
    );

    // The source continues from the same cut without duplicating bytes.
    rig.resume();
    assert_eq!(
        source_out.read_exact(data.len() - delivered),
        data[delivered..]
    );
    wait_until("source completion", || !rig.guest.used(tx(0)).is_empty());
    thread::sleep(QUIET);
    assert_eq!(
        rig.guest.used(tx(0)),
        [(u32::from(head), data.len() as u32)]
    );
    assert!(source_out.drain().is_empty());
    assert!(fresh_out.drain().is_empty());
}

#[test]
fn snapshot_console_rx_freeze_commits_reads_and_rolls_back_waiting_buffers() {
    let input = Pipe::new();
    let mut rig = Rig::new(vec![fd_port("", Some(&input), None)], 0);
    rig.open(0);

    // Waiting for input with a buffer: the freeze hands the buffer back.
    let first = rig.guest.post_rx(rx(0), 64);
    rig.kick(rx(0));
    thread::sleep(QUIET);
    let (_, queues) = rig.freeze();
    assert_eq!((queues[rx(0)].next_avail, queues[rx(0)].next_used), (0, 0));
    // Input arriving while frozen stays in the host descriptor.
    (&input.host).write_all(b"late").unwrap();
    thread::sleep(QUIET);
    assert!(rig.guest.used(rx(0)).is_empty());
    rig.resume();
    wait_until("input after resume", || rig.guest.used(rx(0)).len() == 1);
    assert_eq!(rig.received(rx(0), &[first]), b"late");

    // Freezes landing while input streams in: every popped buffer is used
    // with what it got, and no byte is lost or repeated.
    let data = pattern(6000);
    let writer = {
        let host = input.host.try_clone().unwrap();
        let data = data.clone();
        thread::spawn(move || {
            for chunk in data.chunks(500) {
                (&host).write_all(chunk).unwrap();
                thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let mut bufs = vec![first];
    for round in 0..8 {
        for _ in 0..3 {
            bufs.push(rig.guest.post_rx(rx(0), 300));
        }
        rig.kick(rx(0));
        thread::sleep(Duration::from_millis(3 * round));
        let (_, queues) = rig.freeze();
        let used = rig.guest.used(rx(0)).len() as u16;
        assert_eq!(
            queues[rx(0)].next_avail,
            used,
            "no popped-but-unused buffer"
        );
        rig.resume();
    }
    writer.join().unwrap();
    let total = 4 + data.len();
    let deadline = Instant::now() + WAIT;
    while rig.received(rx(0), &bufs).len() < total {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for streamed input"
        );
        if rig.guest.used(rx(0)).len() == bufs.len() {
            bufs.push(rig.guest.post_rx(rx(0), 300));
            rig.kick(rx(0));
        }
        thread::sleep(Duration::from_millis(5));
    }
    let mut expected = b"late".to_vec();
    expected.extend(&data);
    assert_eq!(rig.received(rx(0), &bufs), expected);
}

#[test]
fn snapshot_console_eof_survives_restore_without_rereading() {
    let input = Pipe::new();
    let mut rig = Rig::new(vec![fd_port("eof", Some(&input), None)], 0);
    rig.open(0);
    input.host.shutdown(std::net::Shutdown::Write).unwrap();
    rig.guest.post_rx(rx(0), 64);
    rig.kick(rx(0));
    let closed = {
        let mut msg = VirtioConsoleControl {
            id: 0,
            event: control_event::VIRTIO_CONSOLE_PORT_OPEN,
            value: 0,
        }
        .as_slice()
        .to_vec();
        msg.truncate(8);
        msg
    };
    wait_until("EOF report", || {
        rig.console.control.snapshot_pending().contains(&closed)
    });

    let (state, queues) = rig.freeze();
    assert!(state.ports[0].eof);
    assert_eq!(state.pending_control, [closed.clone()]);
    // The buffer that saw EOF stays with the guest.
    assert_eq!(queues[rx(0)].next_avail, 0);

    // A fresh input with data is never read: the port stays at EOF. The
    // pending close reaches a control buffer posted while frozen, no kick.
    let fresh = Pipe::new();
    (&fresh.host).write_all(b"xyz").unwrap();
    let mut restored = Rig::restored(&rig, vec![fd_port("eof", Some(&fresh), None)]);
    let control_buf = restored.guest.post_rx(CONTROL_RXQ_INDEX, 64);
    restored.resume();
    assert_eq!(restored.guest.used(CONTROL_RXQ_INDEX), [(0, 8)]);
    assert_eq!(restored.guest.read(control_buf, 8), closed);
    restored.kick(rx(0));
    thread::sleep(QUIET);
    assert!(restored.guest.used(rx(0)).is_empty());
    let mut unread = [0u8; 3];
    (&fresh.port).read_exact(&mut unread).unwrap();
    assert_eq!(&unread, b"xyz");
}

#[test]
fn snapshot_console_control_backlog_and_deferred_resize() {
    let ports = || {
        vec![PortDescription::console(
            Some(port_io::input_empty().unwrap()),
            Some(port_io::output_to_log_as_err()),
            port_io::term_fixed_size(100, 40),
        )]
    };
    let mut rig = Rig::new(ports(), 0);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_PORT_READY, 1);
    rig.console.process_control_tx();

    let (state, _) = rig.freeze();
    let events: Vec<u16> = state
        .pending_control
        .iter()
        .map(|m| u16::from_le_bytes([m[4], m[5]]))
        .collect();
    assert_eq!(
        events,
        [
            control_event::VIRTIO_CONSOLE_PORT_ADD,
            control_event::VIRTIO_CONSOLE_CONSOLE_PORT,
            control_event::VIRTIO_CONSOLE_PORT_OPEN,
            control_event::VIRTIO_CONSOLE_RESIZE,
        ]
    );
    assert_eq!(&state.pending_control[3][8..], [100, 0, 40, 0]);
    assert!(!state.ports[0].started);

    // A resize while frozen queues nothing; the source reports it on resume.
    rig.console.sigwinch_evt.write(1).unwrap();
    let mut event_manager = EventManager::new().unwrap();
    let fd = rig.console.get_sigwinch_fd();
    rig.console.process(
        &EpollEvent::new(EventSet::IN, fd as u64),
        &mut event_manager,
    );
    assert_eq!(rig.console.snapshot_state().unwrap(), state);

    // The restored device delivers the same backlog in order on resume,
    // into buffers posted while frozen, without a kick.
    let mut restored = Rig::restored(&rig, ports());
    let bufs: Vec<_> = (0..5)
        .map(|_| restored.guest.post_rx(CONTROL_RXQ_INDEX, 64))
        .collect();
    restored.resume();
    let used = restored.guest.used(CONTROL_RXQ_INDEX);
    assert_eq!(used.len(), 4);
    for (i, (_, len)) in used.into_iter().enumerate() {
        assert_eq!(restored.guest.read(bufs[i], len), state.pending_control[i]);
    }

    let bufs: Vec<_> = (0..5)
        .map(|_| rig.guest.post_rx(CONTROL_RXQ_INDEX, 64))
        .collect();
    rig.resume();
    let used = rig.guest.used(CONTROL_RXQ_INDEX);
    assert_eq!(used.len(), 5);
    let resize = rig.guest.read(bufs[4], used[4].1);
    assert_eq!(
        u16::from_le_bytes([resize[4], resize[5]]),
        control_event::VIRTIO_CONSOLE_RESIZE
    );
}

#[test]
fn snapshot_console_log_partial_line_survives_restore() {
    let ports = || {
        vec![PortDescription::output_pipe(
            "log",
            port_io::output_to_log_as_err(),
        )]
    };
    let mut rig = Rig::new(ports(), 0);
    rig.open(0);
    rig.guest.post_tx(tx(0), &[b"boot: hal"]);
    rig.kick(tx(0));
    wait_until("log write", || rig.guest.used(tx(0)).len() == 1);

    let (state, _) = rig.freeze();
    let half = OutputState::Log {
        partial_line: b"boot: hal".to_vec(),
    };
    assert_eq!(state.ports[0].output, Some(half.clone()));

    let mut restored = Rig::restored(&rig, ports());
    assert_eq!(
        restored.console.snapshot_state().unwrap().ports[0].output,
        Some(half)
    );
    restored.resume();
    restored.guest.post_tx(tx(0), &[b"f\n"]);
    restored.kick(tx(0));
    wait_until("line end", || restored.guest.used(tx(0)).len() == 2);
    let (state, _) = restored.freeze();
    assert_eq!(
        state.ports[0].output,
        Some(OutputState::Log {
            partial_line: Vec::new()
        })
    );
}

#[test]
fn snapshot_console_frozen_device_is_stable_and_resumes_without_kick() {
    let (input, mut output) = (Pipe::new(), Pipe::new());
    let mut rig = Rig::new(vec![fd_port("", Some(&input), Some(&output))], 0);
    rig.open(0);
    let (state, queues) = rig.freeze();
    rig.interrupt.status().store(0, Ordering::SeqCst);
    let used_before: Vec<_> = (0..4).map(|q| rig.guest.used(q)).collect();

    rig.guest.post_tx(tx(0), &[b"abc"]);
    rig.kick(tx(0));
    let buf = rig.guest.post_rx(rx(0), 16);
    rig.kick(rx(0));
    (&input.host).write_all(b"in").unwrap();
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_PORT_OPEN, 1);
    let control_txq = rig.console.queue_events[CONTROL_TXQ_INDEX].clone();
    control_txq.write(1).unwrap();
    let mut event_manager = EventManager::new().unwrap();
    rig.console.process(
        &EpollEvent::new(EventSet::IN, control_txq.as_raw_fd() as u64),
        &mut event_manager,
    );
    thread::sleep(QUIET);

    assert!(output.drain().is_empty());
    for (q, before) in used_before.iter().enumerate() {
        assert_eq!(&rig.guest.used(q), before, "queue {q} changed while frozen");
    }
    assert_eq!(rig.interrupt.status().load(Ordering::SeqCst), 0);
    assert_eq!(rig.console.snapshot_state().unwrap(), state);
    assert_eq!(
        rig.console.snapshot_queue_states().unwrap().unwrap(),
        queues
    );

    rig.resume();
    assert_eq!(output.read_exact(3), b"abc");
    wait_until("resumed RX", || rig.guest.used(rx(0)).len() == 1);
    assert_eq!(rig.received(rx(0), &[buf]), b"in");
    // The control queue was processed by the resume itself.
    assert_eq!(rig.guest.used(CONTROL_TXQ_INDEX).len(), 2);
    assert_ne!(rig.interrupt.status().load(Ordering::SeqCst), 0);
    wait_until("TX completion", || rig.guest.used(tx(0)) == [(0, 3)]);
}

#[test]
fn snapshot_console_reset_is_bounded_under_output_backpressure() {
    for frozen in [false, true] {
        let output = Pipe::narrow();
        let mut rig = Rig::new(vec![fd_port("", None, Some(&output))], 0);
        rig.open(0);
        let data = pattern(256 * 1024);
        let parts: Vec<&[u8]> = data.chunks(64 * 1024).collect();
        rig.guest.post_tx(tx(0), &parts);
        rig.kick(tx(0));
        thread::sleep(QUIET);
        if frozen {
            rig.freeze();
        }
        // Nobody reads the output: the worker is blocked on it.
        let (done, finished) = mpsc::channel();
        let mut console = rig.console;
        thread::spawn(move || {
            console.reset();
            let _ = done.send(console);
        });
        assert!(
            finished.recv_timeout(WAIT).is_ok(),
            "reset hung under backpressure (frozen: {frozen})"
        );
        drop(output);
    }
}

#[test]
fn snapshot_console_sigint_and_empty_inputs() {
    let sigint = port_io::PortInputSigInt::new();
    let sigint_evt = sigint.sigint_evt().try_clone().unwrap();
    let ports = vec![
        PortDescription::console(
            Some(Box::new(sigint)),
            Some(port_io::output_to_log_as_err()),
            port_io::term_fixed_size(0, 0),
        ),
        PortDescription::input_pipe("empty", port_io::input_empty().unwrap()),
    ];
    let mut rig = Rig::new(ports, 0);
    rig.open(0);
    rig.open(1);
    let buf = rig.guest.post_rx(rx(0), 8);
    rig.kick(rx(0));
    sigint_evt.write(1).unwrap();
    wait_until("SIGINT byte", || rig.guest.used(rx(0)).len() == 1);
    assert_eq!(rig.received(rx(0), &[buf]), [3]);
    rig.guest.post_rx(rx(1), 8);
    rig.kick(rx(1));
    wait_until("empty input EOF", || {
        !rig.console.control.snapshot_pending().is_empty()
    });

    let (state, queues) = rig.freeze();
    // Guest memory clones: the activated device, port 0's RX and TX
    // workers, and port 1's RX worker, alive after EOF; port 1 has no TX
    // worker.
    assert_eq!(rig.console.memory_clones(), 4);
    assert_eq!(state.ports[0].input, Some(InputKind::SigInt));
    assert_eq!(state.ports[1].input, Some(InputKind::Empty));
    assert_eq!((state.ports[0].eof, state.ports[1].eof), (false, true));
    assert_eq!(queues[rx(1)].next_avail, 0);
}

struct CustomOutput;

impl PortOutput for CustomOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn wait_until_writable(&self, _stopfd: Option<&EventFd>) {}
}

#[test]
fn snapshot_console_rejects_custom_endpoints_and_mismatched_restores() {
    let custom = Console::new(vec![PortDescription::output_pipe(
        "c",
        Box::new(CustomOutput),
    )])
    .unwrap();
    assert!(matches!(
        custom.check_snapshot_support(),
        Err(SnapshotError::UnsupportedEndpoint {
            port_id: 0,
            endpoint: "output"
        })
    ));

    let output = Pipe::new();
    let mut rig = Rig::new(
        vec![
            fd_port("a", None, Some(&output)),
            PortDescription::output_pipe("log", port_io::output_to_log_as_err()),
        ],
        0,
    );
    rig.open(0);
    let (state, _) = rig.freeze();
    let fresh = |first: PortDescription| {
        Console::new(vec![
            first,
            PortDescription::output_pipe("log", port_io::output_to_log_as_err()),
        ])
        .unwrap()
    };
    let matching = fresh(fd_port("a", None, Some(&output)));
    matching.validate_restore(&state, true).unwrap();
    // A started port needs an activated device.
    assert!(matching.validate_restore(&state, false).is_err());

    let rejected = |console: &Console, state: &ConsoleState| {
        assert!(matches!(
            console.validate_restore(state, true),
            Err(SnapshotError::Invalid(_)) | Err(SnapshotError::UnsupportedEndpoint { .. })
        ));
    };
    rejected(&fresh(fd_port("b", None, Some(&output))), &state);
    rejected(
        &fresh(PortDescription::output_pipe(
            "a",
            port_io::output_to_log_as_err(),
        )),
        &state,
    );
    rejected(
        &fresh(PortDescription::output_pipe("a", Box::new(CustomOutput))),
        &state,
    );
    rejected(
        &Console::new(vec![fd_port("a", None, Some(&output))]).unwrap(),
        &state,
    );

    let mut bad = state.clone();
    bad.pending_control.push(vec![0; 8]);
    bad.pending_control.last_mut().unwrap()[4] = 99;
    rejected(&matching, &bad);
    let mut bad = state.clone();
    bad.ports[1].output = Some(OutputState::Log {
        partial_line: b"two\nlines".to_vec(),
    });
    rejected(&matching, &bad);
    let mut bad = state.clone();
    bad.config[4] = 3;
    rejected(&matching, &bad);
    let mut bad = state;
    bad.ports[1].eof = true;
    rejected(&matching, &bad);
}

/// Yields its bytes on the first read, fails the next read, then has
/// nothing more.
struct FailingInput {
    reads: usize,
}

impl port_io::PortInput for FailingInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> std::io::Result<usize> {
        self.reads += 1;
        match self.reads {
            1 => {
                buf.copy_from(b"hello");
                Ok(5)
            }
            2 => Err(std::io::Error::other("injected input failure")),
            _ => Err(ErrorKind::WouldBlock.into()),
        }
    }

    fn wait_until_readable(&self, _stopfd: Option<&EventFd>) {
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn snapshot_console_rx_commits_bytes_read_before_an_input_error() {
    let port = PortDescription::input_pipe("failing", Box::new(FailingInput { reads: 0 }));
    let mut rig = Rig::new(vec![port], 0);
    rig.open(0);
    let buf = rig.guest.post_rx(rx(0), 64);
    rig.kick(rx(0));
    wait_until("committed bytes", || rig.guest.used(rx(0)).len() == 1);
    assert_eq!(rig.received(rx(0), &[buf]), b"hello");
}

#[test]
fn snapshot_console_guest_reopen_keeps_running_port() {
    // Previously a second VIRTIO_CONSOLE_PORT_OPEN panicked taking the
    // port's queues again.
    let (input, mut output) = (Pipe::new(), Pipe::new());
    let mut rig = Rig::new(vec![fd_port("", Some(&input), Some(&output))], 0);
    rig.open(0);
    rig.open(0);
    rig.guest.post_tx(tx(0), &[b"abc"]);
    rig.kick(tx(0));
    assert_eq!(output.read_exact(3), b"abc");
}

/// Process one queue eventfd through the console's event handler, as the
/// event thread would.
fn dispatch(rig: &mut Rig, q: usize) {
    let event = rig.console.queue_events[q].clone();
    event.write(1).unwrap();
    let mut event_manager = EventManager::new().unwrap();
    rig.console.process(
        &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
        &mut event_manager,
    );
}

/// A console with one output-only port, the guest's DEVICE_READY handled.
fn ready_rig(output: &Pipe) -> Rig {
    let mut rig = Rig::new(vec![fd_port("", None, Some(output))], 0);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    dispatch(&mut rig, CONTROL_TXQ_INDEX);
    assert_eq!(rig.console.control.snapshot_pending().len(), 1);
    rig
}

#[test]
fn snapshot_console_control_rx_kick_delivers_backlog() {
    // A message queued while the guest offered no control buffer reaches
    // the buffer a later control-RX kick offers.
    let output = Pipe::new();
    let mut rig = ready_rig(&output);
    rig.guest.post_rx(CONTROL_RXQ_INDEX, 64);
    dispatch(&mut rig, CONTROL_RXQ_INDEX);
    assert_eq!(rig.guest.used(CONTROL_RXQ_INDEX), [(0, 8)]);
}

#[test]
fn snapshot_console_control_ignores_unknown_port_ids() {
    let output = Pipe::new();
    let mut rig = ready_rig(&output);
    rig.guest
        .post_control(7, control_event::VIRTIO_CONSOLE_PORT_READY, 1);
    rig.guest
        .post_control(7, control_event::VIRTIO_CONSOLE_PORT_OPEN, 1);
    dispatch(&mut rig, CONTROL_TXQ_INDEX);
    assert_eq!(rig.guest.used(CONTROL_TXQ_INDEX).len(), 3);
}

#[test]
fn snapshot_console_doubled_open_in_one_batch_starts_once() {
    let mut output = Pipe::new();
    let mut rig = ready_rig(&output);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_PORT_OPEN, 1);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_PORT_OPEN, 1);
    dispatch(&mut rig, CONTROL_TXQ_INDEX);
    assert_eq!(rig.guest.used(CONTROL_TXQ_INDEX).len(), 3);
    rig.guest.post_tx(tx(0), &[b"once"]);
    rig.kick(tx(0));
    assert_eq!(output.read_exact(4), b"once");
}

#[test]
fn snapshot_console_unusable_control_buffer_keeps_message() {
    // A control buffer too small or not device-writable takes nothing: the
    // message stays pending and memory past the buffer is untouched.
    for writable in [true, false] {
        let output = Pipe::new();
        let mut rig = ready_rig(&output);
        let pending = rig.console.control.snapshot_pending();
        let len = if writable { 4 } else { 64 };
        let buf = rig.guest.alloc(64);
        rig.guest.mem.write_slice(&[0xaa; 64], buf).unwrap();
        rig.guest.post(CONTROL_RXQ_INDEX, &[(buf, len, writable)]);
        rig.console.process_control_rx();
        assert!(rig.guest.used(CONTROL_RXQ_INDEX).is_empty());
        assert_eq!(rig.guest.read(buf, 64), [0xaa; 64]);
        assert_eq!(rig.console.control.snapshot_pending(), pending);
    }
}

#[test]
fn snapshot_console_reset_drops_pending_control_messages() {
    let output = Pipe::new();
    let mut rig = ready_rig(&output);
    assert!(rig.console.reset());
    assert!(rig.console.control.snapshot_pending().is_empty());
}

#[test]
fn snapshot_console_reset_after_freeze_serves_the_next_driver_live() {
    let output = Pipe::new();
    let mut rig = ready_rig(&output);
    rig.open(0);
    rig.freeze();
    assert!(rig.console.reset());

    // The next driver activates the device again and is served live.
    let guest = Guest::new(num_queues(1), 0);
    let queues = (0..num_queues(1))
        .map(|q| {
            DeviceQueue::new(
                guest.queue(q),
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            )
        })
        .collect();
    rig.console
        .activate(guest.mem.clone(), rig.interrupt.clone(), queues)
        .unwrap();
    rig.guest = guest;
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    dispatch(&mut rig, CONTROL_TXQ_INDEX);
    assert_eq!(rig.guest.used(CONTROL_TXQ_INDEX).len(), 1);
}

#[test]
fn snapshot_console_handshake_state_survives_restore() {
    let ports = || {
        vec![
            PortDescription::console(
                Some(port_io::input_empty().unwrap()),
                Some(port_io::output_to_log_as_err()),
                port_io::term_fixed_size(100, 40),
            ),
            PortDescription::output_pipe("log", port_io::output_to_log_as_err()),
        ]
    };
    let mut rig = Rig::new(ports(), 0);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_PORT_READY, 1);
    rig.guest
        .post_control(1, control_event::VIRTIO_CONSOLE_PORT_READY, 1);
    rig.console.process_control_tx();
    rig.open(0);
    rig.open(1);
    rig.guest
        .post_control(1, control_event::VIRTIO_CONSOLE_PORT_OPEN, 0);
    rig.console.process_control_tx();
    rig.console.update_console_size(0, 120, 50);

    let (state, _) = rig.freeze();
    assert!(state.device_ready);
    let size = Some(TerminalSize {
        cols: 120,
        rows: 50,
    });
    let handshake = |p: &super::persist::ConsolePortState| (p.ready, p.guest_open, p.size);
    assert_eq!(handshake(&state.ports[0]), (true, true, size));
    assert_eq!(handshake(&state.ports[1]), (true, false, None));
    // A closed port keeps its workers and queues.
    assert!(state.ports[1].started);

    let restored = Rig::restored(&rig, ports());
    assert_eq!(restored.console.snapshot_state().unwrap(), state);

    // Structure alone, without a fresh device, rejects impossible states.
    state.validate_structure(true).unwrap();
    assert!(state.validate_structure(false).is_err());
    let mut bad = state.clone();
    bad.ports[1].size = size;
    assert!(bad.validate_structure(true).is_err());
    let mut bad = state;
    bad.ports[1].port_id = 0;
    assert!(bad.validate_structure(true).is_err());
}

#[test]
fn snapshot_console_restore_rejects_malformed_available_chains() {
    let output = Pipe::narrow();
    let mut rig = Rig::new(vec![fd_port("", None, Some(&output))], 0);
    rig.open(0);
    let data = pattern(64 * 1024);
    let head = rig.guest.post_tx(tx(0), &[&data]);
    rig.kick(tx(0));
    output.wait_written();
    let (state, queues) = rig.freeze();
    assert_eq!(state.ports[0].tx_in_flight.map(|p| p.head), Some(head));
    state.validate_guest(&rig.guest.mem, &queues, true).unwrap();

    let buf = GuestAddress(BUFS);
    let desc = |len, flags, next| Descriptor {
        addr: buf.0,
        len,
        flags,
        next,
    };
    let rejects = |q: usize, chain: &[Descriptor]| {
        let mut guest = rig.guest.copy();
        let head = guest.next_desc[q];
        for (i, d) in chain.iter().enumerate() {
            guest.write_desc(q, (head + i as u16) % QSIZE, *d);
        }
        guest.publish(q, head);
        assert!(
            state.validate_guest(&guest.mem, &queues, true).is_err(),
            "queue {q} accepted {:?}",
            chain
                .iter()
                .map(|d| (d.len, d.flags, d.next))
                .collect::<Vec<_>>()
        );
    };
    let w = VIRTQ_DESC_F_WRITE;
    let n = VIRTQ_DESC_F_NEXT;
    // A link outside the table, a cycle, INDIRECT, a range past guest RAM
    // and the wrong direction, on RX, TX and control queues.
    rejects(rx(0), &[desc(8, w | n, QSIZE)]);
    rejects(rx(0), &[desc(8, w | n, 1), desc(8, w | n, 1)]);
    rejects(CONTROL_RXQ_INDEX, &[desc(8, w | 0x4, 0)]);
    rejects(
        CONTROL_TXQ_INDEX,
        &[Descriptor {
            addr: MEM_SIZE as u64 - 4,
            len: 8,
            flags: 0,
            next: 0,
        }],
    );
    rejects(CONTROL_TXQ_INDEX, &[desc(8, w, 0)]);
    rejects(rx(0), &[desc(8, 0, 0)]);
    // The in-flight chain itself is walked strictly too.
    let guest = rig.guest.copy();
    guest.write_desc(tx(0), head, desc(data.len() as u32, n, QSIZE));
    assert!(state.validate_guest(&guest.mem, &queues, true).is_err());
    // A well-formed chain is accepted.
    let mut guest = rig.guest.copy();
    let head = guest.next_desc[rx(0)];
    guest.write_desc(rx(0), head, desc(8, w, 0));
    guest.publish(rx(0), head);
    state.validate_guest(&guest.mem, &queues, true).unwrap();
}

#[test]
fn snapshot_console_inactive_partial_queues_roundtrip() {
    // Before DRIVER_OK the transport owns the queues: one may already be
    // ready with rings nobody validated. Its state is kept, never walked.
    let ports = || {
        vec![PortDescription::output_pipe(
            "log",
            port_io::output_to_log_as_err(),
        )]
    };
    let mut console = Console::new(ports()).unwrap();
    console
        .snapshot_freeze_with_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(console.snapshot_queue_states().unwrap().is_none());
    let state = console.snapshot_state().unwrap();
    state.validate_structure(false).unwrap();

    let mut guest = Guest::new(num_queues(1), 0);
    let mut queues: Vec<QueueState> = (0..num_queues(1))
        .map(|_| QueueState::from_queue(&Queue::new(QSIZE)))
        .collect();
    // A chain is available, but the descriptor table lies outside RAM.
    guest.publish(tx(0), 0);
    let mut partial = QueueState::from_queue(&guest.queue(tx(0)));
    partial.desc_table = MEM_SIZE as u64 * 2;
    queues[tx(0)] = partial;
    for queue in &queues {
        queue.validate(&guest.mem, false).unwrap();
    }
    state.validate_guest(&guest.mem, &queues, false).unwrap();
    // The same queues would not pass as an activated device.
    assert!(state.validate_guest(&guest.mem, &queues, true).is_err());

    let mut restored = Console::new(ports()).unwrap();
    restored.restore_state(&state, false).unwrap();
    assert!(!restored.is_activated());
    assert_eq!(restored.snapshot_state().unwrap(), state);
    restored
        .snapshot_resume_with_timeout(Duration::from_secs(5))
        .unwrap();
}

#[test]
fn snapshot_console_malformed_control_tx_buffers_complete_empty() {
    let output = Pipe::new();
    let mut rig = Rig::new(vec![fd_port("", None, Some(&output))], 0);
    let ready = VirtioConsoleControl {
        id: 0,
        event: control_event::VIRTIO_CONSOLE_DEVICE_READY,
        value: 1,
    };
    // A message continuing past a 4-byte buffer, and a whole message in a
    // device-writable buffer: neither is read.
    for (len, write) in [(4, false), (8, true)] {
        let buf = rig.guest.alloc(8);
        rig.guest.mem.write_obj(ready, buf).unwrap();
        rig.guest.post(CONTROL_TXQ_INDEX, &[(buf, len, write)]);
        rig.console.process_control_tx();
        assert_eq!(rig.guest.used(CONTROL_TXQ_INDEX).last().unwrap().1, 0);
        assert!(rig.console.control.snapshot_pending().is_empty());
    }
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    rig.console.process_control_tx();
    assert_eq!(rig.console.control.snapshot_pending().len(), 1);
}

#[test]
fn snapshot_console_unready_control_queues_are_never_used() {
    let output = Pipe::new();
    let guest = Guest::new(num_queues(1), 0);
    let queues = (0..num_queues(1))
        .map(|q| {
            let mut queue = guest.queue(q);
            queue.ready = ![CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX].contains(&q);
            queue
        })
        .collect();
    let console = Console::new(vec![fd_port("", None, Some(&output))]).unwrap();
    let mut rig = Rig::activate(guest, console, queues, None);
    rig.guest
        .post_control(0, control_event::VIRTIO_CONSOLE_DEVICE_READY, 1);
    rig.console.control.port_add(0);
    rig.guest.post_rx(CONTROL_RXQ_INDEX, 64);
    assert!(!rig.console.process_control_tx());
    assert!(!rig.console.process_control_rx());
    rig.freeze();
    rig.resume();
    assert!(rig.guest.used(CONTROL_TXQ_INDEX).is_empty());
    assert!(rig.guest.used(CONTROL_RXQ_INDEX).is_empty());
    assert_eq!(rig.console.control.snapshot_pending().len(), 1);
}

#[test]
fn snapshot_console_restore_rejects_started_ports_on_unready_queues() {
    let (input, output) = (Pipe::new(), Pipe::new());
    let mut rig = Rig::new(vec![fd_port("", Some(&input), Some(&output))], 0);
    rig.open(0);
    let (state, queues) = rig.freeze();
    state.validate_guest(&rig.guest.mem, &queues, true).unwrap();
    for q in [rx(0), tx(0)] {
        let mut unready = queues.clone();
        unready[q].ready = false;
        assert!(
            state
                .validate_guest(&rig.guest.mem, &unready, true)
                .is_err(),
            "queue {q}"
        );
    }
}

/// Claims the built-in FD kind, then panics on its first read, ending its
/// RX worker thread.
struct PanickingInput(Arc<std::sync::atomic::AtomicBool>);

impl port_io::PortInput for PanickingInput {
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> std::io::Result<usize> {
        self.0.store(true, Ordering::SeqCst);
        panic!("injected console input failure");
    }

    fn wait_until_readable(&self, _stopfd: Option<&EventFd>) {
        thread::sleep(Duration::from_millis(5));
    }

    fn snapshot_kind(&self) -> Option<InputKind> {
        Some(InputKind::Fd)
    }
}

#[test]
fn snapshot_console_freeze_reports_gone_workers() {
    let read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let port = PortDescription::input_pipe("dies", Box::new(PanickingInput(read.clone())));
    let mut rig = Rig::new(vec![port], 0);
    rig.open(0);
    rig.guest.post_rx(rx(0), 8);
    rig.kick(rx(0));
    wait_until("the injected panic", || read.load(Ordering::SeqCst));
    thread::sleep(QUIET);
    assert!(matches!(
        rig.console
            .snapshot_freeze_with_timeout(Duration::from_secs(5)),
        Err(SnapshotError::Control {
            port_id: 0,
            error: crate::virtio::control::WorkerControlError::WorkerGone
        })
    ));
}

#[test]
fn snapshot_console_restore_rejects_cursors_that_disagree_with_in_flight() {
    let output = Pipe::narrow();
    let mut rig = Rig::new(vec![fd_port("", None, Some(&output))], 0);
    rig.open(0);
    let data = pattern(64 * 1024);
    rig.guest.post_tx(tx(0), &[&data]);
    rig.kick(tx(0));
    output.wait_written();
    let (state, queues) = rig.freeze();
    assert!(state.ports[0].tx_in_flight.is_some());
    state.validate_guest(&rig.guest.mem, &queues, true).unwrap();

    // The in-flight chain already completed: it would be replayed.
    let mut completed = queues.clone();
    completed[tx(0)].next_used = completed[tx(0)].next_avail;
    assert!(state
        .validate_guest(&rig.guest.mem, &completed, true)
        .is_err());
    // A popped chain with no in-flight record: it would be lost.
    let mut lost = state.clone();
    lost.ports[0].tx_in_flight = None;
    assert!(lost.validate_guest(&rig.guest.mem, &queues, true).is_err());
    // An RX or control queue never holds a popped chain at a freeze.
    for q in [rx(0), CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX] {
        let mut held = queues.clone();
        held[q].next_used = held[q].next_used.wrapping_sub(1);
        assert!(
            state.validate_guest(&rig.guest.mem, &held, true).is_err(),
            "queue {q}"
        );
    }
}
