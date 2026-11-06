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
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::console_control::VirtioConsoleControl;
use super::defs::control_event;
use super::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use super::persist::{ConsoleState, TxProgress};
use super::port_io::{self, InputKind, OutputState, PortOutput, TerminalKind};
use super::port_queue_mapping::{num_queues, port_id_to_queue_idx, QueueDirection};
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{
    Console, DeviceQueue, InterruptTransport, PortDescription, Queue, VirtioDevice,
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
            queue.validate(&guest.mem, QSIZE, true).unwrap();
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
        queue.validate(&rig.guest.mem, QSIZE, true).unwrap();
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
