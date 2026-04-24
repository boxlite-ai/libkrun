//! 8259 PIC (Programmable Interrupt Controller) emulation.
//!
//! Emulates a dual 8259 PIC (master + slave) for legacy interrupt routing.
//!
//! Master PIC: I/O ports 0x20-0x21, handles IRQs 0-7
//! Slave PIC:  I/O ports 0xA0-0xA1, handles IRQs 8-15
//! Slave is connected to master IRQ 2 (cascade).
//!
//! The Linux kernel in PIC mode (noapic nolapic) programs the PICs to:
//! - Master: vector base 0x20 (IRQs 0-7 → vectors 0x20-0x27)
//! - Slave:  vector base 0x28 (IRQs 8-15 → vectors 0x28-0x2F)

use super::super::vcpu::IoHandler;

/// Master PIC command port.
pub const PIC_MASTER_CMD: u16 = 0x20;
/// Master PIC data port.
pub const PIC_MASTER_DATA: u16 = 0x21;
/// Slave PIC command port.
pub const PIC_SLAVE_CMD: u16 = 0xA0;
/// Slave PIC data port.
pub const PIC_SLAVE_DATA: u16 = 0xA1;

/// Cascade IRQ (slave connected to master IRQ 2).
const CASCADE_IRQ: u8 = 2;

/// State for a single 8259 PIC chip.
#[derive(Debug)]
struct PicChip {
    /// Interrupt Request Register — pending interrupt requests.
    irr: u8,
    /// In-Service Register — interrupts currently being serviced.
    isr: u8,
    /// Interrupt Mask Register — masked (disabled) interrupts.
    imr: u8,
    /// Vector base (aligned to 8, set by ICW2).
    vector_base: u8,
    /// ICW initialization state machine.
    init_state: InitState,
    /// Whether ICW4 is needed (from ICW1 bit 0).
    icw4_needed: bool,
    /// Whether to read ISR (true) or IRR (false) on command port read.
    read_isr: bool,
    /// Auto-EOI mode (from ICW4 bit 1).
    auto_eoi: bool,
}

/// ICW initialization state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitState {
    /// Normal operation (not in initialization).
    Ready,
    /// Waiting for ICW2 (vector base).
    WaitIcw2,
    /// Waiting for ICW3 (cascade configuration).
    WaitIcw3,
    /// Waiting for ICW4 (mode).
    WaitIcw4,
}

impl PicChip {
    fn new() -> Self {
        PicChip {
            irr: 0,
            isr: 0,
            imr: 0xFF, // All interrupts masked initially
            vector_base: 0,
            init_state: InitState::Ready,
            icw4_needed: false,
            read_isr: false,
            auto_eoi: false,
        }
    }

    /// Write to the command port (port 0x20 or 0xA0).
    fn write_command(&mut self, data: u8) {
        if data & 0x10 != 0 {
            // ICW1: bit 4 = 1 → start initialization sequence.
            self.icw4_needed = data & 0x01 != 0;
            self.init_state = InitState::WaitIcw2;
            // Reset during init.
            self.isr = 0;
            self.irr = 0;
            self.imr = 0;
            self.auto_eoi = false;
            self.read_isr = false;
        } else if data & 0x08 != 0 {
            // OCW3: bit 3 = 1.
            if data & 0x02 != 0 {
                // Read register command.
                self.read_isr = data & 0x01 != 0;
            }
        } else {
            // OCW2: End of Interrupt.
            let is_eoi = data & 0x20 != 0;
            let is_specific = data & 0x40 != 0;
            if is_eoi {
                if is_specific {
                    // Specific EOI: clear specific ISR bit.
                    let irq = data & 0x07;
                    self.isr &= !(1 << irq);
                } else {
                    // Non-specific EOI: clear highest-priority ISR bit.
                    for i in 0..8u8 {
                        if self.isr & (1 << i) != 0 {
                            self.isr &= !(1 << i);
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Write to the data port (port 0x21 or 0xA1).
    fn write_data(&mut self, data: u8) {
        match self.init_state {
            InitState::WaitIcw2 => {
                // ICW2: vector base (upper 5 bits used, lower 3 are IRQ number).
                self.vector_base = data & 0xF8;
                self.init_state = InitState::WaitIcw3;
            }
            InitState::WaitIcw3 => {
                // ICW3: cascade configuration (we accept but don't use the value).
                if self.icw4_needed {
                    self.init_state = InitState::WaitIcw4;
                } else {
                    self.init_state = InitState::Ready;
                }
            }
            InitState::WaitIcw4 => {
                // ICW4: mode configuration.
                self.auto_eoi = data & 0x02 != 0;
                self.init_state = InitState::Ready;
            }
            InitState::Ready => {
                // OCW1: set interrupt mask register.
                self.imr = data;
            }
        }
    }

    /// Read from the command port.
    fn read_command(&self) -> u8 {
        if self.read_isr {
            self.isr
        } else {
            self.irr
        }
    }

    /// Read from the data port.
    fn read_data(&self) -> u8 {
        self.imr
    }

    /// Raise an interrupt request on this chip (local IRQ 0-7).
    fn raise_irq(&mut self, irq: u8) {
        self.irr |= 1 << (irq & 7);
    }

    /// Clear an interrupt request (edge-triggered reset).
    fn clear_irq(&mut self, irq: u8) {
        self.irr &= !(1 << (irq & 7));
    }

    /// Get the highest-priority pending (unmasked, deliverable) IRQ, if any.
    ///
    /// Implements proper 8259A priority masking: when an interrupt is
    /// in-service, all equal-or-lower-priority interrupts are blocked.
    /// IRQ 0 has highest priority, IRQ 7 has lowest (default fixed
    /// priority mode).
    fn pending_irq(&self) -> Option<u8> {
        let requested = self.irr & !self.imr;
        if requested == 0 {
            return None;
        }
        // Find the highest-priority (lowest-numbered) in-service IRQ.
        // All IRQs at that level or lower are blocked.
        let priority_ceiling = (0..8u8).find(|&i| self.isr & (1 << i) != 0);
        match priority_ceiling {
            Some(ceil) => {
                // Only IRQs with higher priority (lower number) than the
                // in-service IRQ can be delivered.
                (0..ceil).find(|&i| requested & (1 << i) != 0)
            }
            None => {
                // No interrupt in-service — deliver highest priority pending.
                (0..8u8).find(|&i| requested & (1 << i) != 0)
            }
        }
    }

    /// Acknowledge the highest-priority pending interrupt.
    /// Moves the IRQ from IRR to ISR and returns the vector.
    fn acknowledge(&mut self) -> Option<u8> {
        if let Some(irq) = self.pending_irq() {
            self.irr &= !(1 << irq);
            if self.auto_eoi {
                // Auto-EOI: don't set ISR.
            } else {
                self.isr |= 1 << irq;
            }
            Some(self.vector_base + irq)
        } else {
            None
        }
    }
}

/// Dual 8259 PIC (master + slave).
pub struct Pic {
    master: PicChip,
    slave: PicChip,
}

impl Default for Pic {
    fn default() -> Self {
        Self::new()
    }
}

impl Pic {
    /// Create a new dual PIC with default state (all masked).
    pub fn new() -> Self {
        Pic {
            master: PicChip::new(),
            slave: PicChip::new(),
        }
    }

    /// Raise an interrupt request (IRQ 0-15).
    ///
    /// IRQs 0-7 go to the master PIC, IRQs 8-15 go to the slave PIC.
    /// When a slave IRQ is raised, the cascade line (master IRQ 2) is also raised.
    pub fn raise_irq(&mut self, irq: u8) {
        if irq < 8 {
            self.master.raise_irq(irq);
        } else {
            self.slave.raise_irq(irq - 8);
            // Slave cascades through master IRQ 2.
            self.master.raise_irq(CASCADE_IRQ);
        }
    }

    /// Clear an interrupt request (for edge-triggered mode).
    pub fn clear_irq(&mut self, irq: u8) {
        if irq < 8 {
            self.master.clear_irq(irq);
        } else {
            self.slave.clear_irq(irq - 8);
            // If no more slave IRQs pending, clear cascade on master.
            if self.slave.pending_irq().is_none() {
                self.master.clear_irq(CASCADE_IRQ);
            }
        }
    }

    /// Check if there are any pending (unmasked, deliverable) interrupts.
    pub fn has_pending(&self) -> bool {
        self.master.pending_irq().is_some()
    }

    /// Acknowledge the highest-priority pending interrupt.
    ///
    /// Returns the interrupt vector to deliver to the CPU, or None if
    /// no interrupts are pending.
    pub fn acknowledge(&mut self) -> Option<u8> {
        if let Some(master_irq) = self.master.pending_irq() {
            if master_irq == CASCADE_IRQ {
                // Cascade: acknowledge slave first.
                let vector = self.slave.acknowledge();
                // Acknowledge cascade on master.
                self.master.acknowledge();
                // If no more slave IRQs, clear cascade.
                if self.slave.pending_irq().is_none() {
                    self.master.clear_irq(CASCADE_IRQ);
                }
                vector
            } else {
                self.master.acknowledge()
            }
        } else {
            None
        }
    }

    /// Get master PIC state for diagnostics: (IRR, ISR, IMR, vector_base).
    pub fn master_state(&self) -> (u8, u8, u8, u8) {
        (
            self.master.irr,
            self.master.isr,
            self.master.imr,
            self.master.vector_base,
        )
    }

    /// Check if the given I/O port belongs to either PIC.
    pub fn handles_port(&self, port: u16) -> bool {
        matches!(
            port,
            PIC_MASTER_CMD | PIC_MASTER_DATA | PIC_SLAVE_CMD | PIC_SLAVE_DATA
        )
    }
}

impl IoHandler for Pic {
    fn io_read(&self, port: u16, _size: u8) -> u32 {
        let val = match port {
            PIC_MASTER_CMD => self.master.read_command(),
            PIC_MASTER_DATA => self.master.read_data(),
            PIC_SLAVE_CMD => self.slave.read_command(),
            PIC_SLAVE_DATA => self.slave.read_data(),
            _ => 0xFF,
        };
        val as u32
    }

    fn io_write(&self, port: u16, _size: u8, data: u32) {
        // IoHandler takes &self, but we need &mut self for PIC state.
        // This is a design limitation — for now, the boot_kernel example
        // uses Pic directly with &mut self methods. This trait impl is
        // provided for interface compatibility but should not be used
        // when mutation is needed.
        //
        // In practice, the vCPU loop will call write_port() directly.
        let _ = (port, data);
    }
}

impl Pic {
    /// Write to a PIC I/O port (mutable version for the vCPU loop).
    pub fn write_port(&mut self, port: u16, data: u8) {
        match port {
            PIC_MASTER_CMD => self.master.write_command(data),
            PIC_MASTER_DATA => self.master.write_data(data),
            PIC_SLAVE_CMD => self.slave.write_command(data),
            PIC_SLAVE_DATA => self.slave.write_data(data),
            _ => {}
        }
    }

    /// Read from a PIC I/O port.
    pub fn read_port(&self, port: u16) -> u8 {
        match port {
            PIC_MASTER_CMD => self.master.read_command(),
            PIC_MASTER_DATA => self.master.read_data(),
            PIC_SLAVE_CMD => self.slave.read_command(),
            PIC_SLAVE_DATA => self.slave.read_data(),
            _ => 0xFF,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PicChip unit tests ----

    #[test]
    fn test_pic_chip_initial_state() {
        let chip = PicChip::new();
        assert_eq!(chip.irr, 0);
        assert_eq!(chip.isr, 0);
        assert_eq!(chip.imr, 0xFF, "all IRQs masked initially");
        assert_eq!(chip.vector_base, 0);
        assert_eq!(chip.init_state, InitState::Ready);
    }

    #[test]
    fn test_pic_chip_raise_irq_while_masked() {
        let mut chip = PicChip::new();
        chip.raise_irq(0);
        assert_eq!(chip.irr, 0x01);
        // All masked, so no pending.
        assert_eq!(chip.pending_irq(), None);
    }

    #[test]
    fn test_pic_chip_raise_and_unmask() {
        let mut chip = PicChip::new();
        chip.imr = 0; // Unmask all.
        chip.vector_base = 0x20;
        chip.raise_irq(0);
        assert_eq!(chip.pending_irq(), Some(0));

        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x20));
        assert_eq!(chip.irr, 0, "IRR cleared after acknowledge");
        assert_eq!(chip.isr, 0x01, "ISR set after acknowledge");
    }

    #[test]
    fn test_pic_chip_priority_order() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x20;

        // Raise IRQ 3 and IRQ 1 — IRQ 1 has higher priority.
        chip.raise_irq(3);
        chip.raise_irq(1);
        assert_eq!(chip.pending_irq(), Some(1));

        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x21)); // 0x20 + 1

        // IRQ 3 is blocked while IRQ 1 is in-service (lower priority).
        assert_eq!(chip.pending_irq(), None, "IRQ 3 blocked while IRQ 1 in-service");

        // After EOI for IRQ 1, IRQ 3 becomes deliverable.
        chip.write_command(0x61); // Specific EOI for IRQ 1.
        assert_eq!(chip.pending_irq(), Some(3));
    }

    #[test]
    fn test_pic_chip_isr_blocks_lower_priority() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x20;

        chip.raise_irq(0);
        chip.acknowledge(); // IRQ 0 now in ISR.

        // Raise IRQ 1 — lower priority than IRQ 0.
        // With proper 8259A priority masking, IRQ 1 is blocked while
        // IRQ 0 is in-service (all equal-or-lower priority blocked).
        chip.raise_irq(1);
        assert_eq!(chip.pending_irq(), None, "IRQ 1 must be blocked while IRQ 0 is in-service");

        // After EOI for IRQ 0, IRQ 1 becomes deliverable.
        chip.write_command(0x60); // Specific EOI for IRQ 0.
        assert_eq!(chip.isr, 0, "ISR cleared after specific EOI");
        assert_eq!(chip.pending_irq(), Some(1), "IRQ 1 deliverable after EOI");
    }

    #[test]
    fn test_pic_chip_nonspecific_eoi() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x20;

        chip.raise_irq(0);
        chip.acknowledge(); // IRQ 0 in ISR.
        assert_eq!(chip.isr, 0x01);

        // Non-specific EOI (OCW2 with bit 5 set).
        chip.write_command(0x20);
        assert_eq!(chip.isr, 0, "ISR cleared by EOI");
    }

    #[test]
    fn test_pic_chip_specific_eoi() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x20;

        // Acknowledge IRQ 0, then EOI it, then acknowledge IRQ 2.
        chip.raise_irq(0);
        chip.raise_irq(2);
        chip.acknowledge(); // IRQ 0 acknowledged → ISR bit 0.
        assert_eq!(chip.isr, 0x01);

        // IRQ 2 is blocked while IRQ 0 in-service (priority masking).
        assert_eq!(chip.pending_irq(), None);

        // EOI IRQ 0, then IRQ 2 becomes deliverable.
        chip.write_command(0x60); // Specific EOI for IRQ 0.
        assert_eq!(chip.isr, 0x00);
        chip.acknowledge(); // IRQ 2 acknowledged → ISR bit 2.
        assert_eq!(chip.isr, 0x04);

        // Specific EOI for IRQ 2 (OCW2: 0x60 | 2 = 0x62).
        chip.write_command(0x62);
        assert_eq!(chip.isr, 0x00, "ISR should be clear after both EOIs");
    }

    #[test]
    fn test_pic_chip_icw_sequence() {
        let mut chip = PicChip::new();

        // ICW1: start init, ICW4 needed.
        chip.write_command(0x11);
        assert_eq!(chip.init_state, InitState::WaitIcw2);
        assert!(chip.icw4_needed);

        // ICW2: vector base = 0x20.
        chip.write_data(0x20);
        assert_eq!(chip.vector_base, 0x20);
        assert_eq!(chip.init_state, InitState::WaitIcw3);

        // ICW3: cascade config.
        chip.write_data(0x04); // Master: slave on IRQ 2.
        assert_eq!(chip.init_state, InitState::WaitIcw4);

        // ICW4: 8086 mode.
        chip.write_data(0x01);
        assert_eq!(chip.init_state, InitState::Ready);
    }

    #[test]
    fn test_pic_chip_icw_without_icw4() {
        let mut chip = PicChip::new();

        // ICW1 without ICW4.
        chip.write_command(0x10);
        assert!(!chip.icw4_needed);

        // ICW2.
        chip.write_data(0x28);
        assert_eq!(chip.vector_base, 0x28);

        // ICW3 → goes straight to Ready.
        chip.write_data(0x02);
        assert_eq!(chip.init_state, InitState::Ready);
    }

    #[test]
    fn test_pic_chip_imr_read_write() {
        let mut chip = PicChip::new();

        // After init, writing data port sets IMR.
        chip.write_data(0xFB); // Mask all except IRQ 2.
        assert_eq!(chip.imr, 0xFB);
        assert_eq!(chip.read_data(), 0xFB);
    }

    #[test]
    fn test_pic_chip_read_irr_isr() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x20;

        chip.raise_irq(3);

        // Default read = IRR.
        assert_eq!(chip.read_command(), 0x08); // bit 3.

        // OCW3: read ISR.
        chip.write_command(0x0B);
        assert_eq!(chip.read_command(), 0); // No ISR yet.

        chip.acknowledge(); // IRQ 3 → ISR.
        assert_eq!(chip.read_command(), 0x08); // ISR bit 3.

        // OCW3: read IRR.
        chip.write_command(0x0A);
        assert_eq!(chip.read_command(), 0); // IRR cleared.
    }

    #[test]
    fn test_pic_chip_auto_eoi() {
        let mut chip = PicChip::new();

        // Init with auto-EOI.
        chip.write_command(0x11); // ICW1.
        chip.write_data(0x20); // ICW2.
        chip.write_data(0x00); // ICW3.
        chip.write_data(0x03); // ICW4: 8086 mode + auto-EOI.
        assert!(chip.auto_eoi);

        chip.imr = 0;
        chip.raise_irq(0);
        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x20));
        assert_eq!(chip.isr, 0, "ISR should not be set in auto-EOI mode");
    }

    /// Validates the fix for the WHPX flakiness root cause: PIT (IRQ 0)
    /// in-service must block vsock (IRQ 6) delivery. Without this fix,
    /// both interrupts end up in ISR simultaneously (ISR=0x41), causing
    /// a deadlock where the kernel can't service either handler.
    #[test]
    fn test_pic_chip_pit_blocks_vsock_priority() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x30; // Linux programs master PIC to base 0x30.

        // PIT fires (IRQ 0) and gets acknowledged.
        chip.raise_irq(0);
        assert_eq!(chip.acknowledge(), Some(0x30));
        assert_eq!(chip.isr, 0x01); // PIT in-service.

        // While PIT handler runs, vsock (IRQ 6) fires.
        chip.raise_irq(6);

        // IRQ 6 must NOT be deliverable (lower priority than IRQ 0).
        assert_eq!(
            chip.pending_irq(),
            None,
            "vsock IRQ 6 must be blocked while PIT IRQ 0 is in-service"
        );

        // Kernel sends specific EOI for PIT (0x60 | 0 = 0x60).
        chip.write_command(0x60);
        assert_eq!(chip.isr, 0x00);

        // Now vsock IRQ 6 is deliverable.
        assert_eq!(chip.pending_irq(), Some(6));
        assert_eq!(chip.acknowledge(), Some(0x36));
        assert_eq!(chip.isr, 0x40); // Only vsock in-service, NOT 0x41.
    }

    #[test]
    fn test_pic_chip_higher_priority_preempts() {
        let mut chip = PicChip::new();
        chip.imr = 0;
        chip.vector_base = 0x30;

        // IRQ 6 (vsock) in-service.
        chip.raise_irq(6);
        chip.acknowledge();
        assert_eq!(chip.isr, 0x40);

        // IRQ 0 (PIT) fires — higher priority, should preempt.
        chip.raise_irq(0);
        assert_eq!(
            chip.pending_irq(),
            Some(0),
            "higher-priority IRQ 0 should preempt IRQ 6"
        );
    }

    #[test]
    fn test_pic_chip_clear_irq() {
        let mut chip = PicChip::new();
        chip.raise_irq(5);
        assert_eq!(chip.irr, 0x20);
        chip.clear_irq(5);
        assert_eq!(chip.irr, 0);
    }

    // ---- Dual Pic tests ----

    #[test]
    fn test_pic_new_no_pending() {
        let pic = Pic::new();
        assert!(!pic.has_pending());
    }

    #[test]
    fn test_pic_master_irq_lifecycle() {
        let mut pic = Pic::new();

        // Program master PIC: vector base 0x20, unmask IRQ 0.
        pic.write_port(PIC_MASTER_CMD, 0x11);
        pic.write_port(PIC_MASTER_DATA, 0x20);
        pic.write_port(PIC_MASTER_DATA, 0x04);
        pic.write_port(PIC_MASTER_DATA, 0x01);
        pic.write_port(PIC_MASTER_DATA, 0xFE); // Unmask only IRQ 0.

        pic.raise_irq(0);
        assert!(pic.has_pending());

        let vector = pic.acknowledge();
        assert_eq!(vector, Some(0x20));
        assert!(!pic.has_pending());

        // EOI.
        pic.write_port(PIC_MASTER_CMD, 0x20);
    }

    #[test]
    fn test_pic_slave_irq_lifecycle() {
        let mut pic = Pic::new();

        // Program master: vector 0x20, unmask IRQ 2 (cascade).
        pic.write_port(PIC_MASTER_CMD, 0x11);
        pic.write_port(PIC_MASTER_DATA, 0x20);
        pic.write_port(PIC_MASTER_DATA, 0x04);
        pic.write_port(PIC_MASTER_DATA, 0x01);
        pic.write_port(PIC_MASTER_DATA, 0xFB); // Unmask only IRQ 2.

        // Program slave: vector 0x28, unmask IRQ 0 (= global IRQ 8).
        pic.write_port(PIC_SLAVE_CMD, 0x11);
        pic.write_port(PIC_SLAVE_DATA, 0x28);
        pic.write_port(PIC_SLAVE_DATA, 0x02);
        pic.write_port(PIC_SLAVE_DATA, 0x01);
        pic.write_port(PIC_SLAVE_DATA, 0xFE); // Unmask only slave IRQ 0.

        // Raise IRQ 8 (slave IRQ 0).
        pic.raise_irq(8);
        assert!(pic.has_pending());

        let vector = pic.acknowledge();
        assert_eq!(vector, Some(0x28)); // Slave vector base + 0.
        assert!(!pic.has_pending());

        // EOI to both slave and master.
        pic.write_port(PIC_SLAVE_CMD, 0x20);
        pic.write_port(PIC_MASTER_CMD, 0x20);
    }

    #[test]
    fn test_pic_handles_port() {
        let pic = Pic::new();
        assert!(pic.handles_port(PIC_MASTER_CMD));
        assert!(pic.handles_port(PIC_MASTER_DATA));
        assert!(pic.handles_port(PIC_SLAVE_CMD));
        assert!(pic.handles_port(PIC_SLAVE_DATA));
        assert!(!pic.handles_port(0x22));
        assert!(!pic.handles_port(0x3F8));
    }

    #[test]
    fn test_pic_read_port() {
        let mut pic = Pic::new();

        // Init master.
        pic.write_port(PIC_MASTER_CMD, 0x11);
        pic.write_port(PIC_MASTER_DATA, 0x20);
        pic.write_port(PIC_MASTER_DATA, 0x04);
        pic.write_port(PIC_MASTER_DATA, 0x01);

        // Set IMR.
        pic.write_port(PIC_MASTER_DATA, 0xAB);
        assert_eq!(pic.read_port(PIC_MASTER_DATA), 0xAB);
    }

    #[test]
    fn test_pic_multiple_master_irqs() {
        let mut pic = Pic::new();

        // Init and unmask all.
        pic.write_port(PIC_MASTER_CMD, 0x11);
        pic.write_port(PIC_MASTER_DATA, 0x20);
        pic.write_port(PIC_MASTER_DATA, 0x04);
        pic.write_port(PIC_MASTER_DATA, 0x01);
        pic.write_port(PIC_MASTER_DATA, 0x00); // Unmask all.

        pic.raise_irq(3);
        pic.raise_irq(1);

        // IRQ 1 is higher priority.
        assert_eq!(pic.acknowledge(), Some(0x21));
        pic.write_port(PIC_MASTER_CMD, 0x20); // EOI.

        // Now IRQ 3.
        assert_eq!(pic.acknowledge(), Some(0x23));
        pic.write_port(PIC_MASTER_CMD, 0x20); // EOI.

        assert!(!pic.has_pending());
    }

    #[test]
    fn test_pic_init_resets_state() {
        let mut pic = Pic::new();

        // Set some state.
        pic.master.irr = 0xFF;
        pic.master.isr = 0xFF;
        pic.master.imr = 0xFF;

        // Re-init should reset IRR, ISR, IMR.
        pic.write_port(PIC_MASTER_CMD, 0x11);
        assert_eq!(pic.master.irr, 0);
        assert_eq!(pic.master.isr, 0);
        assert_eq!(pic.master.imr, 0);
    }

    #[test]
    fn test_pic_io_handler_read() {
        let pic = Pic::new();
        // Reading data port returns IMR (0xFF initially).
        let val = pic.io_read(PIC_MASTER_DATA, 1);
        assert_eq!(val, 0xFF);
    }

    #[test]
    fn test_pic_masked_irq_not_pending() {
        let mut pic = Pic::new();

        // Init master, mask IRQ 0.
        pic.write_port(PIC_MASTER_CMD, 0x11);
        pic.write_port(PIC_MASTER_DATA, 0x20);
        pic.write_port(PIC_MASTER_DATA, 0x04);
        pic.write_port(PIC_MASTER_DATA, 0x01);
        pic.write_port(PIC_MASTER_DATA, 0x01); // Mask IRQ 0.

        pic.raise_irq(0);
        assert!(!pic.has_pending(), "masked IRQ should not be pending");
    }
}
