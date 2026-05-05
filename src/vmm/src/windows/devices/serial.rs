//! 16550 UART serial console emulation.
//!
//! Emulates a basic 16550 UART at I/O ports 0x3F8-0x3FF (COM1).
//! Provides serial console output from the guest kernel/userspace.
//!
//! Register layout (base = 0x3F8):
//!   +0 (THR/RBR): Transmit/Receive buffer
//!   +1 (IER):     Interrupt Enable Register
//!   +2 (IIR/FCR): Interrupt Identification / FIFO Control
//!   +3 (LCR):     Line Control Register
//!   +4 (MCR):     Modem Control Register
//!   +5 (LSR):     Line Status Register
//!   +6 (MSR):     Modem Status Register
//!   +7 (SCR):     Scratch Register
//!
//! When DLAB (bit 7 of LCR) is set:
//!   +0 (DLL): Divisor Latch Low
//!   +1 (DLH): Divisor Latch High

use std::io::Write;
use std::sync::Mutex;

use super::super::vcpu::IoHandler;

/// COM1 base I/O port address.
pub const COM1_BASE: u16 = 0x3F8;

/// COM1 I/O port range (8 registers).
pub const COM1_SIZE: u16 = 8;

/// Line Status Register bit flags.
const LSR_DATA_READY: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_IDLE: u8 = 0x40;

/// Interrupt Identification Register values.
const IIR_NO_INTERRUPT: u8 = 0x01;
const IIR_THRE: u8 = 0x02; // Transmitter Holding Register Empty
const IIR_FIFO_ENABLED: u8 = 0xC0;

/// IER bit: Transmitter Holding Register Empty interrupt.
const IER_THRE: u8 = 0x02;

/// FCR bit: FIFO Enable.
const FCR_FIFO_ENABLE: u8 = 0x01;
/// FCR bit: Transmit FIFO Reset.
const FCR_TX_RESET: u8 = 0x04;

/// 16550 FIFO depth (bytes).
const FIFO_SIZE: usize = 16;

/// Serial port state.
struct SerialState {
    /// Interrupt Enable Register.
    ier: u8,
    /// Line Control Register.
    lcr: u8,
    /// Modem Control Register.
    mcr: u8,
    /// Line Status Register.
    lsr: u8,
    /// Modem Status Register.
    msr: u8,
    /// Scratch register.
    scr: u8,
    /// Divisor Latch Low byte.
    dll: u8,
    /// Divisor Latch High byte.
    dlh: u8,
    /// Output sink.
    output: Box<dyn Write + Send>,
    /// THRE interrupt pending (set after THR write when IER THRE bit is set).
    thre_pending: bool,
    /// Whether FIFO mode is enabled (FCR bit 0).
    fifo_enabled: bool,
    /// Transmit FIFO buffer. When FIFO is enabled, bytes are buffered here
    /// and flushed to `output` when the buffer is full, a newline is written,
    /// or the guest reads IIR (polling for completion).
    tx_fifo: Vec<u8>,
}

/// 16550 UART emulation.
pub struct Serial {
    base_port: u16,
    state: Mutex<SerialState>,
}

impl Serial {
    /// Create a new serial port emulation at the given base I/O port.
    pub fn new(base_port: u16, output: Box<dyn Write + Send>) -> Self {
        Serial {
            base_port,
            state: Mutex::new(SerialState {
                ier: 0,
                lcr: 0,
                mcr: 0,
                lsr: LSR_THR_EMPTY | LSR_IDLE, // Transmitter is ready
                msr: 0,
                scr: 0,
                dll: 0,
                dlh: 0,
                output,
                thre_pending: false,
                fifo_enabled: false,
                tx_fifo: Vec::with_capacity(FIFO_SIZE),
            }),
        }
    }

    /// Create a serial port that writes to stdout.
    pub fn stdout(base_port: u16) -> Self {
        Self::new(base_port, Box::new(std::io::stdout()))
    }

    /// Check if the given I/O port is within this serial port's range.
    pub fn handles_port(&self, port: u16) -> bool {
        port >= self.base_port && port < self.base_port + COM1_SIZE
    }

    /// Check if the serial device has a pending interrupt.
    pub fn has_interrupt(&self) -> bool {
        self.state.lock().unwrap().thre_pending
    }

    /// Handle an I/O port read.
    pub fn read(&self, port: u16) -> u8 {
        let offset = port - self.base_port;
        let mut state = self.state.lock().unwrap();
        let dlab = (state.lcr & 0x80) != 0;

        match offset {
            0 => {
                if dlab {
                    state.dll
                } else {
                    // RBR — receive buffer (no input support yet, return 0)
                    state.lsr &= !LSR_DATA_READY;
                    0
                }
            }
            1 => {
                if dlab {
                    state.dlh
                } else {
                    state.ier
                }
            }
            2 => {
                // IIR — check for pending interrupt.
                // Flush any buffered FIFO data (guest is polling for completion).
                if state.fifo_enabled && !state.tx_fifo.is_empty() {
                    let pending: Vec<u8> = state.tx_fifo.drain(..).collect();
                    let _ = state.output.write_all(&pending);
                    let _ = state.output.flush();
                }
                if state.thre_pending {
                    state.thre_pending = false;
                    IIR_THRE | IIR_FIFO_ENABLED
                } else {
                    IIR_NO_INTERRUPT | IIR_FIFO_ENABLED
                }
            }
            3 => state.lcr,
            4 => state.mcr,
            5 => {
                let lsr = state.lsr;
                // Reading LSR clears some bits
                state.lsr &= !(LSR_DATA_READY);
                lsr
            }
            6 => state.msr,
            7 => state.scr,
            _ => 0,
        }
    }

    /// Handle an I/O port write.
    pub fn write(&self, port: u16, data: u8) {
        let offset = port - self.base_port;
        let mut state = self.state.lock().unwrap();
        let dlab = (state.lcr & 0x80) != 0;

        match offset {
            0 => {
                if dlab {
                    state.dll = data;
                } else if state.fifo_enabled {
                    // THR with FIFO: buffer bytes, flush on newline or full.
                    state.tx_fifo.push(data);
                    if data == b'\n' || state.tx_fifo.len() >= FIFO_SIZE {
                        let pending: Vec<u8> = state.tx_fifo.drain(..).collect();
                        let _ = state.output.write_all(&pending);
                        let _ = state.output.flush();
                    }
                    state.lsr |= LSR_THR_EMPTY | LSR_IDLE;
                    if state.ier & IER_THRE != 0 {
                        state.thre_pending = true;
                    }
                } else {
                    // THR without FIFO: immediate output per byte.
                    let _ = state.output.write_all(&[data]);
                    let _ = state.output.flush();
                    state.lsr |= LSR_THR_EMPTY | LSR_IDLE;
                    if state.ier & IER_THRE != 0 {
                        state.thre_pending = true;
                    }
                }
            }
            1 => {
                if dlab {
                    state.dlh = data;
                } else {
                    let old_ier = state.ier;
                    state.ier = data & 0x0F; // Only lower 4 bits valid
                                             // Enabling THRE interrupt when THR is already empty triggers it
                    if (state.ier & IER_THRE != 0)
                        && (old_ier & IER_THRE == 0)
                        && (state.lsr & LSR_THR_EMPTY != 0)
                    {
                        state.thre_pending = true;
                    }
                }
            }
            2 => {
                // FCR — FIFO Control Register.
                state.fifo_enabled = data & FCR_FIFO_ENABLE != 0;
                if data & FCR_TX_RESET != 0 {
                    // TX FIFO reset: flush pending data and clear buffer.
                    if !state.tx_fifo.is_empty() {
                        let pending: Vec<u8> = state.tx_fifo.drain(..).collect();
                        let _ = state.output.write_all(&pending);
                        let _ = state.output.flush();
                    }
                }
                if !state.fifo_enabled && !state.tx_fifo.is_empty() {
                    // Disabling FIFO: flush remaining data.
                    let pending: Vec<u8> = state.tx_fifo.drain(..).collect();
                    let _ = state.output.write_all(&pending);
                    let _ = state.output.flush();
                }
            }
            3 => state.lcr = data,
            4 => state.mcr = data & 0x1F, // Only lower 5 bits valid
            5 => {}                       // LSR is read-only
            6 => {}                       // MSR is read-only
            7 => state.scr = data,
            _ => {}
        }
    }
}

impl IoHandler for Serial {
    fn io_read(&self, port: u16, _size: u8) -> u32 {
        self.read(port) as u32
    }

    fn io_write(&self, port: u16, _size: u8, data: u32) {
        self.write(port, data as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    /// A test output sink that captures written bytes.
    struct CaptureOutput {
        buffer: Arc<StdMutex<Vec<u8>>>,
    }

    impl CaptureOutput {
        fn new() -> (Self, Arc<StdMutex<Vec<u8>>>) {
            let buffer = Arc::new(StdMutex::new(Vec::new()));
            (
                CaptureOutput {
                    buffer: buffer.clone(),
                },
                buffer,
            )
        }
    }

    impl Write for CaptureOutput {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn create_test_serial() -> (Serial, Arc<StdMutex<Vec<u8>>>) {
        let (output, buffer) = CaptureOutput::new();
        let serial = Serial::new(COM1_BASE, Box::new(output));
        (serial, buffer)
    }

    #[test]
    fn test_serial_handles_port() {
        let (serial, _) = create_test_serial();
        assert!(serial.handles_port(COM1_BASE));
        assert!(serial.handles_port(COM1_BASE + 7));
        assert!(!serial.handles_port(COM1_BASE - 1));
        assert!(!serial.handles_port(COM1_BASE + 8));
    }

    #[test]
    fn test_serial_lsr_initially_ready() {
        let (serial, _) = create_test_serial();
        let lsr = serial.read(COM1_BASE + 5);
        assert_ne!(lsr & LSR_THR_EMPTY, 0, "THR should be empty initially");
        assert_ne!(lsr & LSR_IDLE, 0, "transmitter should be idle initially");
    }

    #[test]
    fn test_serial_write_character() {
        let (serial, buffer) = create_test_serial();

        serial.write(COM1_BASE, b'H');
        serial.write(COM1_BASE, b'i');

        let captured = buffer.lock().unwrap();
        assert_eq!(&*captured, b"Hi");
    }

    #[test]
    fn test_serial_write_string() {
        let (serial, buffer) = create_test_serial();

        for &byte in b"Hello, VM!\n" {
            serial.write(COM1_BASE, byte);
        }

        let captured = buffer.lock().unwrap();
        assert_eq!(std::str::from_utf8(&captured).unwrap(), "Hello, VM!\n");
    }

    #[test]
    fn test_serial_scratch_register() {
        let (serial, _) = create_test_serial();

        serial.write(COM1_BASE + 7, 0x42);
        assert_eq!(serial.read(COM1_BASE + 7), 0x42);

        serial.write(COM1_BASE + 7, 0xFF);
        assert_eq!(serial.read(COM1_BASE + 7), 0xFF);
    }

    #[test]
    fn test_serial_dlab_divisor_latch() {
        let (serial, _) = create_test_serial();

        // Set DLAB bit in LCR
        serial.write(COM1_BASE + 3, 0x80);

        // Write divisor
        serial.write(COM1_BASE, 0x01); // DLL
        serial.write(COM1_BASE + 1, 0x00); // DLH

        // Read divisor back
        assert_eq!(serial.read(COM1_BASE), 0x01); // DLL
        assert_eq!(serial.read(COM1_BASE + 1), 0x00); // DLH

        // Clear DLAB
        serial.write(COM1_BASE + 3, 0x03); // 8N1

        // Now register 0 is THR/RBR again, not DLL
        // Writing should output a character, not change the divisor
        let (serial2, buffer2) = create_test_serial();
        serial2.write(COM1_BASE + 3, 0x03); // 8N1, DLAB=0
        serial2.write(COM1_BASE, b'X');
        let captured = buffer2.lock().unwrap();
        assert_eq!(&*captured, b"X");
    }

    #[test]
    fn test_serial_ier_mask() {
        let (serial, _) = create_test_serial();

        // IER only uses lower 4 bits
        serial.write(COM1_BASE + 1, 0xFF);
        assert_eq!(serial.read(COM1_BASE + 1), 0x0F);
    }

    #[test]
    fn test_serial_mcr_mask() {
        let (serial, _) = create_test_serial();

        // MCR only uses lower 5 bits
        serial.write(COM1_BASE + 4, 0xFF);
        assert_eq!(serial.read(COM1_BASE + 4), 0x1F);
    }

    #[test]
    fn test_serial_iir_no_interrupt() {
        let (serial, _) = create_test_serial();

        let iir = serial.read(COM1_BASE + 2);
        assert_ne!(iir & IIR_NO_INTERRUPT, 0, "no interrupt should be pending");
    }

    #[test]
    fn test_serial_io_handler_trait() {
        let (serial, buffer) = create_test_serial();

        // Use through IoHandler trait
        serial.io_write(COM1_BASE, 1, b'A' as u32);
        serial.io_write(COM1_BASE, 1, b'B' as u32);

        let lsr = serial.io_read(COM1_BASE + 5, 1);
        assert_ne!(lsr & LSR_THR_EMPTY as u32, 0);

        let captured = buffer.lock().unwrap();
        assert_eq!(&*captured, b"AB");
    }

    #[test]
    fn test_serial_thr_stays_ready_after_write() {
        let (serial, _) = create_test_serial();

        serial.write(COM1_BASE, b'X');
        let lsr = serial.read(COM1_BASE + 5);
        assert_ne!(lsr & LSR_THR_EMPTY, 0, "THR should be ready after write");
    }

    // ---- FIFO tests ----

    #[test]
    fn test_fifo_enable_via_fcr() {
        let (serial, _) = create_test_serial();
        // FIFO should be disabled initially.
        assert!(!serial.state.lock().unwrap().fifo_enabled);
        // Write FCR with FIFO enable bit.
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);
        assert!(serial.state.lock().unwrap().fifo_enabled);
        // Disable FIFO.
        serial.write(COM1_BASE + 2, 0);
        assert!(!serial.state.lock().unwrap().fifo_enabled);
    }

    #[test]
    fn test_fifo_batches_output() {
        let (serial, buffer) = create_test_serial();
        // Enable FIFO.
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        // Write bytes that don't trigger flush (no newline, under FIFO_SIZE).
        for &b in b"Hello" {
            serial.write(COM1_BASE, b);
        }
        // Buffer should be empty (data is in FIFO, not flushed yet).
        assert!(
            buffer.lock().unwrap().is_empty(),
            "FIFO should batch writes"
        );

        // Write newline to trigger flush.
        serial.write(COM1_BASE, b'\n');
        let captured = buffer.lock().unwrap().clone();
        assert_eq!(captured, b"Hello\n", "newline should flush FIFO");
    }

    #[test]
    fn test_fifo_flushes_on_full() {
        let (serial, buffer) = create_test_serial();
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        // Write exactly FIFO_SIZE bytes (no newline).
        for i in 0..FIFO_SIZE {
            serial.write(COM1_BASE, b'A' + (i as u8 % 26));
        }
        // Should have flushed on the 16th byte.
        let captured = buffer.lock().unwrap().clone();
        assert_eq!(captured.len(), FIFO_SIZE, "FIFO should flush when full");
    }

    #[test]
    fn test_fifo_flushes_on_iir_read() {
        let (serial, buffer) = create_test_serial();
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        // Write partial data (no newline, under FIFO_SIZE).
        for &b in b"Test" {
            serial.write(COM1_BASE, b);
        }
        assert!(buffer.lock().unwrap().is_empty(), "not flushed yet");

        // Read IIR — should flush the FIFO.
        let _iir = serial.read(COM1_BASE + 2);
        let captured = buffer.lock().unwrap().clone();
        assert_eq!(captured, b"Test", "IIR read should flush FIFO");
    }

    #[test]
    fn test_fifo_disable_flushes_remaining() {
        let (serial, buffer) = create_test_serial();
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        for &b in b"Data" {
            serial.write(COM1_BASE, b);
        }
        assert!(buffer.lock().unwrap().is_empty());

        // Disable FIFO — should flush remaining data.
        serial.write(COM1_BASE + 2, 0);
        let captured = buffer.lock().unwrap().clone();
        assert_eq!(captured, b"Data", "disabling FIFO should flush");
    }

    #[test]
    fn test_fifo_tx_reset_flushes() {
        let (serial, buffer) = create_test_serial();
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        for &b in b"Reset" {
            serial.write(COM1_BASE, b);
        }
        assert!(buffer.lock().unwrap().is_empty());

        // TX FIFO reset.
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE | FCR_TX_RESET);
        let captured = buffer.lock().unwrap().clone();
        assert_eq!(captured, b"Reset", "TX reset should flush FIFO");
    }

    #[test]
    fn test_no_fifo_immediate_output() {
        let (serial, buffer) = create_test_serial();
        // FIFO disabled (default) — each byte goes out immediately.
        serial.write(COM1_BASE, b'A');
        assert_eq!(buffer.lock().unwrap().as_slice(), b"A");
        serial.write(COM1_BASE, b'B');
        assert_eq!(buffer.lock().unwrap().as_slice(), b"AB");
    }

    #[test]
    fn test_fifo_lsr_stays_ready() {
        let (serial, _) = create_test_serial();
        serial.write(COM1_BASE + 2, FCR_FIFO_ENABLE);

        // Even with FIFO buffering, LSR should report THR empty.
        serial.write(COM1_BASE, b'X');
        let lsr = serial.read(COM1_BASE + 5);
        assert_ne!(lsr & LSR_THR_EMPTY, 0, "THR should be ready in FIFO mode");
    }
}
