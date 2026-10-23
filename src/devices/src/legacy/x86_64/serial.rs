// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::VecDeque;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

use polly::event_manager::{EventManager, Subscriber};
use serde::{Deserialize, Serialize};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;

use crate::bus::BusDevice;
use crate::legacy::ReadableFd;

const LOOP_SIZE: usize = 0x40;

const DATA: u8 = 0;
const IER: u8 = 1;
const IIR: u8 = 2;
const LCR: u8 = 3;
const MCR: u8 = 4;
const LSR: u8 = 5;
const MSR: u8 = 6;
const SCR: u8 = 7;

const DLAB_LOW: u8 = 0;
const DLAB_HIGH: u8 = 1;

const IER_RECV_BIT: u8 = 0x1;
const IER_THR_BIT: u8 = 0x2;
const IER_FIFO_BITS: u8 = 0x0f;

const IIR_FIFO_BITS: u8 = 0xc0;
const IIR_NONE_BIT: u8 = 0x1;
const IIR_THR_BIT: u8 = 0x2;
const IIR_RECV_BIT: u8 = 0x4;

const LCR_DLAB_BIT: u8 = 0x80;

const LSR_DATA_BIT: u8 = 0x1;
const LSR_OVERRUN_BIT: u8 = 0x2;
const LSR_EMPTY_BIT: u8 = 0x20;
const LSR_IDLE_BIT: u8 = 0x40;

const MCR_LOOP_BIT: u8 = 0x10;

const DEFAULT_INTERRUPT_IDENTIFICATION: u8 = IIR_NONE_BIT; // no pending interrupt
const DEFAULT_LINE_STATUS: u8 = LSR_EMPTY_BIT | LSR_IDLE_BIT; // THR empty and line is idle
const DEFAULT_LINE_CONTROL: u8 = 0x3; // 8-bits per character
const DEFAULT_MODEM_CONTROL: u8 = 0x8; // Auxiliary output 2
const DEFAULT_MODEM_STATUS: u8 = 0x20 | 0x10 | 0x80; // data ready, clear to send, carrier detect
const DEFAULT_BAUD_DIVISOR: u16 = 12; // 9600 bps

/// Unread input a snapshot UART holds; further input is dropped and sets
/// the overrun bit. Ordinary UARTs keep unbounded input.
const SNAPSHOT_INPUT_CAP: usize = 4096;
/// Bytes one readiness event reads from a snapshot endpoint.
#[cfg(target_os = "linux")]
const SNAPSHOT_READ_CHUNK: usize = 256;

/// Emulates serial COM ports commonly seen on x86 I/O ports 0x3f8/0x2f8/0x3e8/0x2e8.
///
/// This can optionally write the guest's output to a Write trait object. To send input to the
/// guest, use `raw_input`.
pub struct Serial {
    interrupt_enable: u8,
    interrupt_identification: u8,
    interrupt_evt: EventFd,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,
    in_buffer: VecDeque<u8>,
    out: Option<Box<dyn io::Write + Send>>,
    input: Option<Box<dyn ReadableFd + Send>>,
    #[cfg(target_os = "linux")]
    snapshot: Option<SnapshotEndpoint>,
}

/// The guest-visible registers and unread input of a UART. Host endpoints
/// and the dropped-output count are not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerialState {
    interrupt_enable: u8,
    interrupt_identification: u8,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,
    unread_input: Vec<u8>,
}

impl SerialState {
    /// Reject register values and input the emulation cannot reach.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.interrupt_enable & !IER_FIFO_BITS != 0 {
            return Err("serial IER has unsupported bits");
        }
        // Either "none pending" alone or a nonempty set of THR/RECV.
        let iir = self.interrupt_identification;
        if iir != IIR_NONE_BIT && (iir == 0 || iir & !(IIR_THR_BIT | IIR_RECV_BIT) != 0) {
            return Err("serial IIR is outside the interrupt state machine");
        }
        let known = LSR_DATA_BIT | LSR_OVERRUN_BIT | LSR_EMPTY_BIT | LSR_IDLE_BIT;
        if self.line_status & !known != 0
            || self.line_status & (LSR_EMPTY_BIT | LSR_IDLE_BIT) != LSR_EMPTY_BIT | LSR_IDLE_BIT
        {
            return Err("serial LSR has unsupported bits");
        }
        if self.unread_input.len() > SNAPSHOT_INPUT_CAP {
            return Err("serial unread input exceeds its capacity");
        }
        if (self.line_status & LSR_DATA_BIT != 0) == self.unread_input.is_empty() {
            return Err("serial data-ready disagrees with unread input");
        }
        Ok(())
    }
}

/// The private snapshot owner's endpoint: one caller-owned nonblocking
/// UnixStream, or none for a sink port. Output never blocks or queues: a
/// byte the peer cannot take now is dropped and counted.
#[cfg(target_os = "linux")]
struct SnapshotEndpoint {
    stream: Option<UnixStream>,
    input_open: bool,
    dropped_output: u64,
}

#[cfg(target_os = "linux")]
impl SnapshotEndpoint {
    fn send(&mut self, byte: u8) {
        let Some(stream) = &self.stream else { return };
        // MSG_NOSIGNAL: a closed peer returns EPIPE instead of raising
        // SIGPIPE. The socket is nonblocking, so a full peer returns EAGAIN.
        // SAFETY: the buffer is one live byte and the fd is owned by `stream`.
        let sent = unsafe {
            libc::send(
                stream.as_raw_fd(),
                &byte as *const u8 as *const libc::c_void,
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != 1 {
            self.dropped_output += 1;
        }
    }

    fn input_fd(&self) -> Option<i32> {
        self.stream
            .as_ref()
            .filter(|_| self.input_open)
            .map(AsRawFd::as_raw_fd)
    }
}

impl Serial {
    pub fn new(
        interrupt_evt: EventFd,
        out: Option<Box<dyn io::Write + Send>>,
        input: Option<Box<dyn ReadableFd + Send>>,
    ) -> Serial {
        Serial {
            interrupt_enable: 0,
            interrupt_identification: DEFAULT_INTERRUPT_IDENTIFICATION,
            interrupt_evt,
            line_control: DEFAULT_LINE_CONTROL,
            line_status: DEFAULT_LINE_STATUS,
            modem_control: DEFAULT_MODEM_CONTROL,
            modem_status: DEFAULT_MODEM_STATUS,
            scratch: 0,
            baud_divisor: DEFAULT_BAUD_DIVISOR,
            in_buffer: VecDeque::new(),
            out,
            input,
            #[cfg(target_os = "linux")]
            snapshot: None,
        }
    }

    /// Constructs a UART for the private snapshot owner. `stream` carries
    /// both directions and must already be nonblocking: the caller may share
    /// its file status flags, so they are checked, never changed.
    #[cfg(target_os = "linux")]
    pub fn new_snapshot(interrupt_evt: EventFd, stream: Option<UnixStream>) -> io::Result<Serial> {
        if let Some(stream) = &stream {
            Self::check_snapshot_endpoint(stream)?;
        }
        let mut serial = Self::new(interrupt_evt, None, None);
        serial.snapshot = Some(SnapshotEndpoint {
            input_open: stream.is_some(),
            stream,
            dropped_output: 0,
        });
        Ok(serial)
    }

    /// Fails unless `stream` is in nonblocking mode.
    #[cfg(target_os = "linux")]
    pub fn check_snapshot_endpoint(stream: &UnixStream) -> io::Result<()> {
        // SAFETY: F_GETFL only reads the flags of an fd owned by `stream`.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot serial endpoint must already be nonblocking",
            ));
        }
        Ok(())
    }

    /// Output bytes a snapshot UART dropped because its peer was full or
    /// gone; zero for other UARTs and for a newly restored one.
    pub fn dropped_output_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        if let Some(endpoint) = &self.snapshot {
            return endpoint.dropped_output;
        }
        0
    }

    pub fn snapshot_state(&self) -> SerialState {
        SerialState {
            interrupt_enable: self.interrupt_enable,
            interrupt_identification: self.interrupt_identification,
            line_control: self.line_control,
            line_status: self.line_status,
            modem_control: self.modem_control,
            modem_status: self.modem_status,
            scratch: self.scratch,
            baud_divisor: self.baud_divisor,
            unread_input: self.in_buffer.iter().copied().collect(),
        }
    }

    /// Load a validated state; the endpoints and dropped count stay this
    /// UART's own.
    pub fn restore_snapshot_state(&mut self, state: &SerialState) -> Result<(), &'static str> {
        state.validate()?;
        self.interrupt_enable = state.interrupt_enable;
        self.interrupt_identification = state.interrupt_identification;
        self.line_control = state.line_control;
        self.line_status = state.line_status;
        self.modem_control = state.modem_control;
        self.modem_status = state.modem_status;
        self.scratch = state.scratch;
        self.baud_divisor = state.baud_divisor;
        self.in_buffer = state.unread_input.iter().copied().collect();
        Ok(())
    }

    /// Constructs a Serial port ready for input and output.
    pub fn new_in_out(
        interrupt_evt: EventFd,
        input: Box<dyn ReadableFd + Send>,
        out: Box<dyn io::Write + Send>,
    ) -> Serial {
        Self::new(interrupt_evt, Some(out), Some(input))
    }

    /// Constructs a Serial port ready for output but with no input.
    pub fn new_out(interrupt_evt: EventFd, out: Box<dyn io::Write + Send>) -> Serial {
        Self::new(interrupt_evt, Some(out), None)
    }

    /// Constructs a Serial port with no connected input or output.
    pub fn new_sink(interrupt_evt: EventFd) -> Serial {
        Self::new(interrupt_evt, None, None)
    }

    /// Provides a reference to the interrupt event fd.
    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn is_dlab_set(&self) -> bool {
        (self.line_control & LCR_DLAB_BIT) != 0
    }

    fn is_recv_intr_enabled(&self) -> bool {
        (self.interrupt_enable & IER_RECV_BIT) != 0
    }

    fn is_thr_intr_enabled(&self) -> bool {
        (self.interrupt_enable & IER_THR_BIT) != 0
    }

    fn is_loop(&self) -> bool {
        (self.modem_control & MCR_LOOP_BIT) != 0
    }

    fn add_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !IIR_NONE_BIT;
        self.interrupt_identification |= bit;
    }

    fn del_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !bit;
        if self.interrupt_identification == 0x0 {
            self.interrupt_identification = IIR_NONE_BIT;
        }
    }

    fn thr_empty(&mut self) -> io::Result<()> {
        if self.is_thr_intr_enabled() {
            self.add_intr_bit(IIR_THR_BIT);
            self.trigger_interrupt()?
        }
        Ok(())
    }

    fn recv_data(&mut self) -> io::Result<()> {
        if self.is_recv_intr_enabled() {
            self.add_intr_bit(IIR_RECV_BIT);
            self.trigger_interrupt()?
        }
        self.line_status |= LSR_DATA_BIT;
        Ok(())
    }

    fn trigger_interrupt(&mut self) -> io::Result<()> {
        self.interrupt_evt.write(1)
    }

    fn iir_reset(&mut self) {
        self.interrupt_identification = DEFAULT_INTERRUPT_IDENTIFICATION;
    }

    // Handles a write request from the driver.
    fn handle_write(&mut self, offset: u8, value: u8) -> io::Result<()> {
        match offset {
            DLAB_LOW if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0xff00) | u16::from(value)
            }
            DLAB_HIGH if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0x00ff) | (u16::from(value) << 8)
            }
            DATA => {
                if self.is_loop() {
                    if self.in_buffer.len() < LOOP_SIZE {
                        self.in_buffer.push_back(value);
                        self.recv_data()?;
                    }
                } else {
                    // A snapshot UART completes the transmit even when the
                    // byte is dropped, so the guest never waits on the host.
                    #[cfg(target_os = "linux")]
                    if let Some(endpoint) = self.snapshot.as_mut() {
                        endpoint.send(value);
                        return self.thr_empty();
                    }
                    if let Some(out) = self.out.as_mut() {
                        out.write_all(&[value])?;
                        out.flush()?;
                    }
                    self.thr_empty()?;
                }
            }
            IER => self.interrupt_enable = value & IER_FIFO_BITS,
            LCR => self.line_control = value,
            MCR => self.modem_control = value,
            SCR => self.scratch = value,
            _ => {}
        }
        Ok(())
    }

    // Handles a read request from the driver.
    fn handle_read(&mut self, offset: u8) -> u8 {
        match offset {
            DLAB_LOW if self.is_dlab_set() => self.baud_divisor as u8,
            DLAB_HIGH if self.is_dlab_set() => (self.baud_divisor >> 8) as u8,
            DATA => {
                self.del_intr_bit(IIR_RECV_BIT);
                if self.in_buffer.len() <= 1 {
                    self.line_status &= !LSR_DATA_BIT;
                }
                self.in_buffer.pop_front().unwrap_or_default()
            }
            IER => self.interrupt_enable,
            IIR => {
                let v = self.interrupt_identification | IIR_FIFO_BITS;
                self.iir_reset();
                v
            }
            LCR => self.line_control,
            MCR => self.modem_control,
            LSR => {
                // Reading LSR clears the overrun error, as on a 16550.
                let status = self.line_status;
                self.line_status &= !LSR_OVERRUN_BIT;
                status
            }
            MSR => self.modem_status,
            SCR => self.scratch,
            _ => 0,
        }
    }

    fn raw_input(&mut self, data: &[u8]) -> io::Result<()> {
        // An empty read is not data: it must not set data-ready.
        if self.is_loop() || data.is_empty() {
            return Ok(());
        }
        let accepted = if self.is_snapshot() {
            data.len()
                .min(SNAPSHOT_INPUT_CAP.saturating_sub(self.in_buffer.len()))
        } else {
            data.len()
        };
        if accepted < data.len() {
            self.line_status |= LSR_OVERRUN_BIT;
        }
        if accepted == 0 {
            return Ok(());
        }
        self.in_buffer.extend(&data[..accepted]);
        self.recv_data()
    }

    fn is_snapshot(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.snapshot.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }

    /// One bounded read per readiness event. On hang-up, EOF or a read
    /// error, remaining data is drained up to one byte past the input
    /// capacity (so a dropped tail still sets the overrun bit) and the input
    /// is unregistered, so a closed peer can neither spin the event loop nor
    /// fake data-ready.
    #[cfg(target_os = "linux")]
    fn process_snapshot_input(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let Some(fd) = self.snapshot.as_ref().and_then(SnapshotEndpoint::input_fd) else {
            return;
        };
        if event.fd() != fd {
            return;
        }
        let hang_up = event
            .event_set()
            .intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP | EventSet::ERROR);
        let budget = if hang_up {
            SNAPSHOT_INPUT_CAP + 1
        } else {
            SNAPSHOT_READ_CHUNK
        };
        let mut closed = false;
        let mut drained = 0;
        let mut chunk = [0u8; SNAPSHOT_READ_CHUNK];
        while drained < budget {
            // Never read past the budget, so a hang-up drains at most one
            // byte beyond the capacity.
            let len = (budget - drained).min(SNAPSHOT_READ_CHUNK);
            let stream = self.snapshot.as_mut().and_then(|e| e.stream.as_mut());
            let read = match stream {
                Some(stream) => io::Read::read(stream, &mut chunk[..len]),
                None => return,
            };
            match read {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(count) => {
                    drained += count;
                    self.raw_input(&chunk[..count])
                        .unwrap_or_else(|e| warn!("Serial error on input: {e}"));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // Level-triggered epoll reports the fd again.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => {
                    warn!("snapshot serial input failed: {e}");
                    closed = true;
                    break;
                }
            }
        }
        if closed || hang_up {
            if let Err(e) = event_manager.unregister(fd) {
                warn!("snapshot serial input unregister failed: {e:?}");
            }
            if let Some(endpoint) = self.snapshot.as_mut() {
                endpoint.input_open = false;
            }
        }
    }
}

impl BusDevice for Serial {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        data[0] = self.handle_read(offset as u8);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        if let Err(e) = self.handle_write(offset as u8, data[0]) {
            error!("Failed the write to serial: {e}");
        }
    }
}

impl Subscriber for Serial {
    /// Handle a read event (EPOLLIN) on the serial input fd.
    fn process(&mut self, event: &EpollEvent, _event_manager: &mut EventManager) {
        #[cfg(target_os = "linux")]
        if self.snapshot.is_some() {
            return self.process_snapshot_input(event, _event_manager);
        }
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!("Received unknown event: {event_set:?} from source: {source:?}");
            return;
        }

        if let Some(input) = self.input.as_mut() {
            if input.as_raw_fd() == source {
                let mut out = [0u8; 32];
                match input.read(&mut out[..]) {
                    Ok(count) => {
                        self.raw_input(&out[..count])
                            .unwrap_or_else(|e| warn!("Serial error on input: {e}"));
                    }
                    Err(e) => {
                        warn!("error while reading stdin: {e:?}");
                    }
                }
            }
        }
    }

    /// Initial registration of pollable objects.
    /// If serial input is present, register the serial input FD as readable.
    fn interest_list(&self) -> Vec<EpollEvent> {
        #[cfg(target_os = "linux")]
        if let Some(endpoint) = &self.snapshot {
            return endpoint
                .input_fd()
                .map(|fd| EpollEvent::new(EventSet::IN, fd as u64))
                .into_iter()
                .collect();
        }
        match &self.input {
            Some(input) => vec![EpollEvent::new(EventSet::IN, input.as_raw_fd() as u64)],
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::Write;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::{Arc, Mutex};

    use polly::event_manager::EventManager;

    struct SharedBufferInternal {
        read_buf: Vec<u8>,
        write_buf: Vec<u8>,
        evfd: EventFd,
    }

    #[derive(Clone)]
    struct SharedBuffer {
        internal: Arc<Mutex<SharedBufferInternal>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                internal: Arc::new(Mutex::new(SharedBufferInternal {
                    read_buf: Vec::new(),
                    write_buf: Vec::new(),
                    evfd: EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                })),
            }
        }
    }
    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.internal.lock().unwrap().write_buf.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.internal.lock().unwrap().write_buf.flush()
        }
    }
    impl io::Read for SharedBuffer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.internal.lock().unwrap().read_buf.as_slice().read(buf)
        }
    }
    impl AsRawFd for SharedBuffer {
        fn as_raw_fd(&self) -> RawFd {
            self.internal.lock().unwrap().evfd.as_raw_fd()
        }
    }
    impl ReadableFd for SharedBuffer {}

    static RAW_INPUT_BUF: [u8; 3] = [b'a', b'b', b'c'];

    #[test]
    fn test_event_handling_no_in() {
        let mut event_manager = EventManager::new().unwrap();

        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out));
        // A serial without in does not have any events in the list.
        assert!(serial.interest_list().is_empty());
        // Even though there is no in, process should not panic. Call it to validate this.
        let epoll_event = EpollEvent::new(EventSet::IN, 0);
        serial.process(&epoll_event, &mut event_manager);
    }

    #[test]
    fn test_event_handling_with_in() {
        let mut event_manager = EventManager::new().unwrap();

        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();

        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out),
        );
        // Check that the interest list contains the EPOLL_IN event.
        assert_eq!(serial.interest_list().len(), 1);

        // Process an invalid event type does not panic.
        let invalid_event = EpollEvent::new(EventSet::OUT, intr_evt.as_raw_fd() as u64);
        serial.process(&invalid_event, &mut event_manager);

        // Process an event with a `RawFd` that does not correspond to `intr_evt` does not panic.
        let invalid_event = EpollEvent::new(EventSet::IN, 0);
        serial.process(&invalid_event, &mut event_manager);
    }

    #[test]
    fn test_serial_output() {
        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out.clone()));

        // Invalid write of multiple chars at once.
        serial.write(0, u64::from(DATA), &[b'x', b'y']);
        // Valid one char at a time writes.
        RAW_INPUT_BUF
            .iter()
            .for_each(|&c| serial.write(0, u64::from(DATA), &[c]));
        assert_eq!(
            serial_out.internal.lock().unwrap().write_buf.as_slice(),
            &RAW_INPUT_BUF
        );
    }

    #[test]
    fn test_serial_raw_input() {
        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt.try_clone().unwrap(), Box::new(serial_out));

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(0, u64::from(IER), &[IER_RECV_BIT]);
        serial.raw_input(&RAW_INPUT_BUF).unwrap();

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [0u8, 0u8];
        serial.read(0, u64::from(DATA), &mut data[..]);
        assert_eq!(data, [0u8, 0u8]);

        let mut data = [0u8];
        serial.read(0, u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(0, u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });

        // Check if reading from the largest u8 offset returns 0.
        serial.read(0, 0xff, &mut data[..]);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_serial_input() {
        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();

        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
        );

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(0, u64::from(IER), &[IER_RECV_BIT]);

        // Prepare the input buffer.
        {
            let mut guard = serial_in_out.internal.lock().unwrap();
            guard.read_buf.write_all(&RAW_INPUT_BUF).unwrap();
            guard.evfd.write(1).unwrap();
        }

        let mut evmgr = EventManager::new().unwrap();
        let serial_wrap = Arc::new(Mutex::new(serial));
        evmgr.add_subscriber(serial_wrap.clone()).unwrap();

        // Run the event handler which should drive serial input.
        // There should be one event reported (which should have also handled serial input).
        assert_eq!(evmgr.run_with_timeout(50).unwrap(), 1);

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        let mut serial = serial_wrap.lock().unwrap();
        let mut data = [0u8];
        serial.read(0, u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(0, u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });
    }

    #[test]
    fn test_serial_thr() {
        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let mut serial = Serial::new_sink(intr_evt.try_clone().unwrap());

        // write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks)
        assert!(intr_evt.write(1).is_ok());
        serial.write(0, u64::from(IER), &[IER_THR_BIT]);
        serial.write(0, u64::from(DATA), &[b'a']);

        assert_eq!(intr_evt.read().unwrap(), 2);
        let mut data = [0u8];
        serial.read(0, u64::from(IER), &mut data[..]);
        assert_eq!(data[0] & IER_FIFO_BITS, IER_THR_BIT);
        serial.read(0, u64::from(IIR), &mut data[..]);
        assert_ne!(data[0] & IIR_THR_BIT, 0);
    }

    #[test]
    fn test_serial_dlab() {
        let mut serial = Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());

        serial.write(0, u64::from(LCR), &[LCR_DLAB_BIT]);
        serial.write(0, u64::from(DLAB_LOW), &[0x12_u8]);
        serial.write(0, u64::from(DLAB_HIGH), &[0x34_u8]);

        let mut data = [0u8];
        serial.read(0, u64::from(LCR), &mut data[..]);
        assert_eq!(data[0], { LCR_DLAB_BIT });
        serial.read(0, u64::from(DLAB_LOW), &mut data[..]);
        assert_eq!(data[0], 0x12);
        serial.read(0, u64::from(DLAB_HIGH), &mut data[..]);
        assert_eq!(data[0], 0x34);
    }

    #[test]
    fn test_serial_modem() {
        let mut serial = Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());

        serial.write(0, u64::from(MCR), &[MCR_LOOP_BIT]);
        serial.write(0, u64::from(DATA), &[b'a']);
        serial.write(0, u64::from(DATA), &[b'b']);
        serial.write(0, u64::from(DATA), &[b'c']);

        let mut data = [0u8];
        serial.read(0, u64::from(MSR), &mut data[..]);
        assert_eq!(data[0], { DEFAULT_MODEM_STATUS });
        serial.read(0, u64::from(MCR), &mut data[..]);
        assert_eq!(data[0], { MCR_LOOP_BIT });
        serial.read(0, u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(0, u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(0, u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    /// An empty input read (EOF) is not data: data-ready stays clear and
    /// no receive interrupt is raised.
    #[test]
    fn test_serial_empty_input_is_not_data_ready() {
        let intr_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();
        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
        );
        serial.write(0, u64::from(IER), &[IER_RECV_BIT]);
        serial_in_out
            .internal
            .lock()
            .unwrap()
            .evfd
            .write(1)
            .unwrap();

        let mut evmgr = EventManager::new().unwrap();
        let serial = Arc::new(Mutex::new(serial));
        evmgr.add_subscriber(serial.clone()).unwrap();
        assert_eq!(evmgr.run_with_timeout(50).unwrap(), 1);

        let mut data = [0u8];
        serial.lock().unwrap().read(0, u64::from(LSR), &mut data);
        assert_eq!(data[0] & LSR_DATA_BIT, 0, "EOF reported as data");
        assert!(intr_evt.read().is_err(), "EOF raised an interrupt");
    }

    #[test]
    fn test_serial_scratch() {
        let mut serial = Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());

        serial.write(0, u64::from(SCR), &[0x12_u8]);

        let mut data = [0u8];
        serial.read(0, u64::from(SCR), &mut data[..]);
        assert_eq!(data[0], 0x12_u8);
    }

    #[cfg(target_os = "linux")]
    mod snapshot {
        use super::*;
        use std::os::unix::net::UnixStream;

        fn pair() -> (UnixStream, UnixStream) {
            let (ours, theirs) = UnixStream::pair().unwrap();
            ours.set_nonblocking(true).unwrap();
            (ours, theirs)
        }

        fn lsr(serial: &mut Serial) -> u8 {
            let mut data = [0u8];
            serial.read(0, u64::from(LSR), &mut data);
            data[0]
        }

        #[test]
        fn snapshot_serial_rejects_blocking_endpoint_without_changing_it() {
            let (blocking, _peer) = UnixStream::pair().unwrap();
            assert!(Serial::check_snapshot_endpoint(&blocking).is_err());
            let flags = unsafe { libc::fcntl(blocking.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_NONBLOCK, 0, "check changed the flags");
            let evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
            assert!(Serial::new_snapshot(evt, Some(blocking)).is_err());
        }

        /// A full or closed peer drops the byte and counts it, but the guest
        /// still sees the transmit complete with its THR interrupt.
        #[test]
        fn snapshot_serial_drops_output_on_backpressure_and_still_raises_thre() {
            let (ours, theirs) = pair();
            let filler = ours.try_clone().unwrap();
            let evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
            let mut serial = Serial::new_snapshot(evt.try_clone().unwrap(), Some(ours)).unwrap();
            serial.write(0, u64::from(IER), &[IER_THR_BIT]);

            serial.write(0, u64::from(DATA), b"a");
            assert_eq!(serial.dropped_output_bytes(), 0);
            assert_eq!(evt.read().unwrap(), 1);

            let chunk = [0u8; 4096];
            while (&filler).write(&chunk).is_ok() {}
            serial.write(0, u64::from(DATA), b"b");
            assert_eq!(serial.dropped_output_bytes(), 1, "full peer did not drop");
            assert_eq!(evt.read().unwrap(), 1, "THR interrupt missing on drop");
            let mut iir = [0u8];
            serial.read(0, u64::from(IIR), &mut iir);
            assert_ne!(iir[0] & IIR_THR_BIT, 0);

            drop(theirs);
            serial.write(0, u64::from(DATA), b"c");
            assert_eq!(serial.dropped_output_bytes(), 2, "closed peer did not drop");
            assert_eq!(evt.read().unwrap(), 1);
        }

        /// Snapshot input stops at 4 KiB and sets the overrun bit, which an
        /// LSR read clears; an ordinary UART stays uncapped.
        #[test]
        fn snapshot_serial_input_cap_sets_overrun() {
            let evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
            let mut serial = Serial::new_snapshot(evt, None).unwrap();
            serial.raw_input(&[7; SNAPSHOT_INPUT_CAP + 10]).unwrap();
            assert_eq!(serial.in_buffer.len(), SNAPSHOT_INPUT_CAP);
            assert_eq!(
                lsr(&mut serial) & (LSR_DATA_BIT | LSR_OVERRUN_BIT),
                LSR_DATA_BIT | LSR_OVERRUN_BIT
            );
            assert_eq!(lsr(&mut serial) & LSR_OVERRUN_BIT, 0);

            let mut ordinary =
                Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
            ordinary.raw_input(&[7; SNAPSHOT_INPUT_CAP + 10]).unwrap();
            assert_eq!(ordinary.in_buffer.len(), SNAPSHOT_INPUT_CAP + 10);
        }

        /// A peer that writes and closes: its data is drained up to the
        /// input cap, a dropped tail sets overrun, the input is
        /// unregistered, and the closed fd neither spins nor fakes data.
        #[test]
        fn snapshot_serial_eof_drains_and_unregisters_input() {
            for sent_len in [2, 0, SNAPSHOT_INPUT_CAP, SNAPSHOT_INPUT_CAP + 10] {
                let sent: Vec<u8> = (0..sent_len).map(|i| i as u8).collect();
                let (ours, mut theirs) = pair();
                let fd = ours.as_raw_fd();
                let evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
                let serial = Arc::new(Mutex::new(
                    Serial::new_snapshot(evt.try_clone().unwrap(), Some(ours)).unwrap(),
                ));
                serial
                    .lock()
                    .unwrap()
                    .write(0, u64::from(IER), &[IER_RECV_BIT]);
                theirs.write_all(&sent).unwrap();
                drop(theirs);

                let mut evmgr = EventManager::new().unwrap();
                evmgr.add_subscriber(serial.clone()).unwrap();
                assert_eq!(evmgr.run_with_timeout(1000).unwrap(), 1);
                assert!(evmgr.subscriber(fd).is_err(), "input still registered");
                assert!(serial.lock().unwrap().interest_list().is_empty());
                assert_eq!(evmgr.run_with_timeout(0).unwrap(), 0, "closed fd spins");

                let mut serial = serial.lock().unwrap();
                let status = lsr(&mut serial);
                assert_eq!(status & LSR_DATA_BIT != 0, sent_len > 0);
                assert_eq!(
                    status & LSR_OVERRUN_BIT != 0,
                    sent_len > SNAPSHOT_INPUT_CAP,
                    "overrun disagrees with a dropped tail of {sent_len} bytes"
                );
                assert_eq!(evt.read().is_ok(), sent_len > 0);
                assert_eq!(serial.in_buffer.len(), sent_len.min(SNAPSHOT_INPUT_CAP));
                for &byte in &sent[..sent_len.min(SNAPSHOT_INPUT_CAP)] {
                    let mut data = [0u8];
                    serial.read(0, u64::from(DATA), &mut data);
                    assert_eq!(data[0], byte);
                }
                assert_eq!(lsr(&mut serial) & LSR_DATA_BIT, 0);
            }
        }

        #[test]
        fn snapshot_serial_state_round_trips_registers_and_unread_input() {
            let mut source =
                Serial::new_snapshot(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(), None)
                    .unwrap();
            source.write(0, u64::from(LCR), &[LCR_DLAB_BIT]);
            source.write(0, u64::from(DLAB_LOW), &[0x34]);
            source.write(0, u64::from(DLAB_HIGH), &[0x12]);
            source.write(0, u64::from(LCR), &[0x03]);
            source.write(0, u64::from(IER), &[IER_RECV_BIT | IER_THR_BIT]);
            source.write(0, u64::from(SCR), &[0x5a]);
            source.raw_input(b"xyz").unwrap();
            let mut data = [0u8];
            source.read(0, u64::from(DATA), &mut data);
            let state = source.snapshot_state();
            state.validate().unwrap();

            let (ours, _theirs) = pair();
            let mut target = Serial::new_snapshot(
                EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                Some(ours),
            )
            .unwrap();
            target.restore_snapshot_state(&state).unwrap();
            assert_eq!(target.snapshot_state(), state);
            assert_eq!(target.dropped_output_bytes(), 0);
            for expected in *b"yz" {
                target.read(0, u64::from(DATA), &mut data);
                assert_eq!(data[0], expected);
            }

            let mut invalid = state.clone();
            invalid.unread_input.clear();
            assert!(target.restore_snapshot_state(&invalid).is_err());
            let mut invalid = state;
            invalid.interrupt_identification = 0x8;
            assert!(invalid.validate().is_err());
        }
    }
}
