//! IrqChip — coordinator wiring PIC + IOAPIC + LAPIC together.
//!
//! Manages the interrupt routing between legacy PIC (for early boot before
//! APIC is enabled) and the IOAPIC + LAPIC path (after guest enables APIC).
//!
//! The APIC mode is auto-detected: when the guest writes to the LAPIC SVR
//! register with the enable bit set, the IrqChip switches to APIC mode.

use std::time::Instant;

use super::ioapic::IoApic;
use super::lapic::LocalApic;
use super::pic::Pic;
use super::super::memory::{IOAPIC_MMIO_BASE, IOAPIC_MMIO_SIZE, LAPIC_MMIO_BASE, LAPIC_MMIO_SIZE};

/// Coordinated interrupt controller combining PIC, IOAPIC, and LAPIC.
pub struct IrqChip {
    /// Legacy PIC (for early boot before APIC is enabled).
    pub pic: Pic,
    /// I/O APIC for routing device interrupts to the LAPIC.
    ioapic: IoApic,
    /// Local APIC for priority management and timer.
    lapic: LocalApic,
    /// false = PIC mode (early boot), true = APIC mode.
    apic_mode: bool,
}

impl Default for IrqChip {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqChip {
    /// Create a new IrqChip in PIC mode (legacy boot).
    pub fn new() -> Self {
        Self {
            pic: Pic::new(),
            ioapic: IoApic::new(),
            lapic: LocalApic::new(),
            apic_mode: false,
        }
    }

    /// Whether the chip is in APIC mode (vs legacy PIC mode).
    pub fn apic_mode(&self) -> bool {
        self.apic_mode
    }

    /// Raise an interrupt on the given ISA IRQ line.
    ///
    /// Routes to IOAPIC (if APIC mode) or PIC (legacy mode).
    /// In APIC mode, applies the standard x86 IRQ-to-GSI remapping:
    /// ISA IRQ 0 (PIT timer) → IOAPIC pin 2 (GSI 2), matching the
    /// Interrupt Source Override entry in the MADT.
    pub fn raise_irq(&mut self, irq: u8) {
        if self.apic_mode {
            // Remap ISA IRQ to IOAPIC pin (GSI).
            // Standard x86: PIT timer (IRQ 0) routes to IOAPIC pin 2.
            let gsi = if irq == 0 { 2 } else { irq };
            if let Some(vector) = self.ioapic.service_irq(gsi, true) {
                self.lapic.accept_interrupt(vector);
            }
        } else {
            self.pic.raise_irq(irq);
        }
    }

    /// Get the highest-priority injectable vector, if any.
    ///
    /// Checks LAPIC (APIC mode) or PIC (legacy mode).
    pub fn get_injectable_vector(&self) -> Option<u8> {
        if self.apic_mode {
            self.lapic.get_highest_injectable()
        } else {
            if self.pic.has_pending() {
                // PIC has pending, but we need to peek — can't acknowledge yet.
                // Return a sentinel to indicate "has pending".
                Some(0) // Caller should use acknowledge_interrupt() to get actual vector.
            } else {
                None
            }
        }
    }

    /// Check if there are any pending interrupts (without acknowledging).
    pub fn has_pending(&self) -> bool {
        if self.apic_mode {
            self.lapic.get_highest_injectable().is_some()
        } else {
            self.pic.has_pending()
        }
    }

    /// Acknowledge the highest-priority interrupt.
    ///
    /// In PIC mode: acknowledges from PIC and returns the vector.
    /// In APIC mode: returns the highest injectable from LAPIC.
    pub fn acknowledge(&mut self) -> Option<u8> {
        if self.apic_mode {
            self.lapic.get_highest_injectable()
        } else {
            self.pic.acknowledge()
        }
    }

    /// Called after the vector has been injected into the vCPU.
    ///
    /// In APIC mode: moves the vector from IRR to ISR in the LAPIC.
    /// In PIC mode: no-op (PIC acknowledge already moved to ISR).
    pub fn notify_injected(&mut self, vector: u8) {
        if self.apic_mode {
            self.lapic.start_of_interrupt(vector);
        }
    }

    /// Handle an EOI from the guest.
    ///
    /// In PIC mode: handled via I/O port writes (OCW2 commands).
    /// In APIC mode: propagates EOI from LAPIC to IOAPIC for level-triggered
    /// interrupt completion.
    fn handle_lapic_eoi(&mut self, vector: u8) {
        if let Some(pin) = self.ioapic.end_of_interrupt(vector) {
            // Pin still asserted — re-deliver using the correct IOAPIC pin.
            if let Some(new_vector) = self.ioapic.service_irq(pin, true) {
                self.lapic.accept_interrupt(new_vector);
            }
        }
    }

    /// Tick the LAPIC timer. Returns the timer vector if it fired.
    pub fn tick_timer(&mut self, now: Instant) -> Option<u8> {
        if !self.apic_mode {
            return None;
        }
        if let Some(vector) = self.lapic.tick_timer(now) {
            self.lapic.accept_interrupt(vector);
            Some(vector)
        } else {
            None
        }
    }

    /// Handle an MMIO read to an IOAPIC or LAPIC address.
    ///
    /// Returns Some(value) if the address was handled, None otherwise.
    pub fn handle_mmio_read(&self, addr: u64, _size: u8) -> Option<u32> {
        if addr >= IOAPIC_MMIO_BASE && addr < IOAPIC_MMIO_BASE + IOAPIC_MMIO_SIZE {
            let offset = addr - IOAPIC_MMIO_BASE;
            Some(self.ioapic.read_mmio(offset))
        } else if addr >= LAPIC_MMIO_BASE && addr < LAPIC_MMIO_BASE + LAPIC_MMIO_SIZE {
            let offset = addr - LAPIC_MMIO_BASE;
            Some(self.lapic.read_mmio(offset))
        } else {
            None
        }
    }

    /// Handle an MMIO write to an IOAPIC or LAPIC address.
    ///
    /// Returns true if the address was handled.
    pub fn handle_mmio_write(&mut self, addr: u64, _size: u8, data: u32) -> bool {
        if addr >= IOAPIC_MMIO_BASE && addr < IOAPIC_MMIO_BASE + IOAPIC_MMIO_SIZE {
            let offset = addr - IOAPIC_MMIO_BASE;
            self.ioapic.write_mmio(offset, data);
            // An IOAPIC entry may have been unmasked — check transition.
            self.check_apic_transition();
            true
        } else if addr >= LAPIC_MMIO_BASE && addr < LAPIC_MMIO_BASE + LAPIC_MMIO_SIZE {
            let offset = addr - LAPIC_MMIO_BASE;
            let eoi_vector = self.lapic.write_mmio(offset, data);

            // LAPIC SVR may have been enabled — check transition.
            self.check_apic_transition();

            // Handle EOI propagation to IOAPIC.
            if let Some(vector) = eoi_vector {
                self.handle_lapic_eoi(vector);
            }

            true
        } else {
            false
        }
    }

    /// Check if conditions are met to switch from PIC to APIC mode.
    ///
    /// The transition requires BOTH:
    /// 1. LAPIC is software-enabled (SVR bit 8 set by guest)
    /// 2. IOAPIC has at least one unmasked redirection entry
    ///
    /// This prevents a gap where the kernel has enabled the LAPIC but hasn't
    /// yet programmed the IOAPIC entries, which would silently drop interrupts
    /// (all IOAPIC entries start masked).
    fn check_apic_transition(&mut self) {
        if self.apic_mode {
            return;
        }
        if self.lapic.is_enabled() && self.ioapic.has_unmasked_entries() {
            log::info!(
                "APIC mode enabled — LAPIC active + IOAPIC has unmasked entries"
            );
            self.apic_mode = true;
        }
    }

    /// Get PIC master state for diagnostics.
    pub fn pic_master_state(&self) -> (u8, u8, u8, u8) {
        self.pic.master_state()
    }

    /// Get PIC slave state for diagnostics.
    pub fn pic_slave_state(&self) -> (u8, u8, u8, u8) {
        self.pic.slave_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irq_chip_starts_in_pic_mode() {
        let chip = IrqChip::new();
        assert!(!chip.apic_mode());
    }

    #[test]
    fn test_irq_chip_pic_mode_raise_irq() {
        let mut chip = IrqChip::new();

        // Program PIC for testing.
        chip.pic.write_port(0x20, 0x11); // ICW1
        chip.pic.write_port(0x21, 0x20); // ICW2: vector base 0x20
        chip.pic.write_port(0x21, 0x04); // ICW3
        chip.pic.write_port(0x21, 0x01); // ICW4
        chip.pic.write_port(0x21, 0x00); // IMR: unmask all

        chip.raise_irq(0);
        assert!(chip.has_pending());

        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x20));
    }

    #[test]
    fn test_irq_chip_apic_mode_switch_requires_ioapic_entries() {
        let mut chip = IrqChip::new();
        assert!(!chip.apic_mode());

        // Write to LAPIC SVR with enable bit — NOT enough alone.
        let svr_addr = LAPIC_MMIO_BASE + 0x0F0;
        chip.handle_mmio_write(svr_addr, 4, 0x1FF);
        assert!(
            !chip.apic_mode(),
            "APIC mode must NOT activate on SVR alone"
        );

        // Unmask an IOAPIC entry (pin 2, vector 0x22) — NOW transition triggers.
        chip.handle_mmio_write(IOAPIC_MMIO_BASE, 4, 0x14); // Select reg 0x14 (pin 2 low)
        chip.handle_mmio_write(IOAPIC_MMIO_BASE + 0x10, 4, 0x22); // vector=0x22, unmasked

        assert!(
            chip.apic_mode(),
            "APIC mode should activate when LAPIC enabled + IOAPIC unmasked"
        );
    }

    #[test]
    fn test_irq_chip_apic_mode_raise_irq() {
        let mut chip = IrqChip::new();

        // Enable LAPIC SVR.
        chip.handle_mmio_write(LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 5: vector 0x25, unmasked, edge-triggered.
        // This triggers the APIC mode transition (LAPIC enabled + unmasked entry).
        chip.handle_mmio_write(IOAPIC_MMIO_BASE, 4, 0x1A); // Select register 0x1A (pin 5 low)
        chip.handle_mmio_write(IOAPIC_MMIO_BASE + 0x10, 4, 0x25); // vector=0x25, unmasked
        assert!(chip.apic_mode());

        chip.raise_irq(5);
        assert!(chip.has_pending());

        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x25));
    }

    #[test]
    fn test_irq_chip_apic_mode_irq0_remaps_to_gsi2() {
        let mut chip = IrqChip::new();

        // Enable LAPIC SVR.
        chip.handle_mmio_write(LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 2: vector 0x22, unmasked, edge-triggered.
        // This is the standard x86 PIT timer mapping (IRQ 0 → GSI 2 per MADT ISO).
        chip.handle_mmio_write(IOAPIC_MMIO_BASE, 4, 0x14); // Select register 0x14 (pin 2 low)
        chip.handle_mmio_write(IOAPIC_MMIO_BASE + 0x10, 4, 0x22); // vector=0x22, unmasked
        assert!(chip.apic_mode());

        // raise_irq(0) should remap to IOAPIC pin 2 and deliver vector 0x22.
        chip.raise_irq(0);
        assert!(chip.has_pending());

        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x22));
    }

    #[test]
    fn test_irq_chip_mmio_read_ioapic() {
        let mut chip = IrqChip::new();
        // Read IOAPIC version register.
        // First set IOREGSEL via write, then read IOWIN.
        // Write to IOREGSEL at offset 0x00 sets the register index (0x01 = version).
        // This doesn't unmask any entries, so APIC mode stays off.
        chip.ioapic.write_mmio(0x00, 0x01); // Direct access to avoid transition check
        let version = chip.handle_mmio_read(IOAPIC_MMIO_BASE + 0x10, 4);
        assert_eq!(version, Some(0x0017_0011));
    }

    #[test]
    fn test_irq_chip_mmio_read_lapic() {
        let chip = IrqChip::new();
        let version = chip.handle_mmio_read(LAPIC_MMIO_BASE + 0x030, 4);
        assert!(version.is_some());
        assert_eq!(version.unwrap() & 0xFF, 0x14);
    }

    #[test]
    fn test_irq_chip_mmio_read_unhandled() {
        let chip = IrqChip::new();
        // Address outside IOAPIC/LAPIC range.
        assert_eq!(chip.handle_mmio_read(0xDEAD_0000, 4), None);
    }

    #[test]
    fn test_irq_chip_mmio_write_unhandled() {
        let mut chip = IrqChip::new();
        assert!(!chip.handle_mmio_write(0xDEAD_0000, 4, 0));
    }

    #[test]
    fn test_irq_chip_eoi_propagation() {
        let mut chip = IrqChip::new();

        // Enable LAPIC SVR.
        chip.handle_mmio_write(LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 3: vector 0x33, level-triggered, unmasked.
        // This also triggers APIC mode transition.
        chip.handle_mmio_write(IOAPIC_MMIO_BASE, 4, 0x16); // register 0x16 = pin 3 low
        chip.handle_mmio_write(IOAPIC_MMIO_BASE + 0x10, 4, 0x33 | (1 << 15)); // vector=0x33, level-triggered
        assert!(chip.apic_mode());

        // Raise IRQ 3.
        chip.raise_irq(3);
        let vector = chip.acknowledge();
        assert_eq!(vector, Some(0x33));

        // Inject and acknowledge in LAPIC.
        chip.notify_injected(0x33);

        // Write EOI to LAPIC (offset 0x0B0).
        chip.handle_mmio_write(LAPIC_MMIO_BASE + 0x0B0, 4, 0);

        // After EOI, the pin is still asserted → re-injection.
        assert!(chip.has_pending());
    }

    #[test]
    fn test_irq_chip_timer_only_in_apic_mode() {
        let mut chip = IrqChip::new();
        let now = Instant::now();
        // In PIC mode, timer should not fire.
        assert_eq!(chip.tick_timer(now), None);
    }

    #[test]
    fn test_irq_chip_notify_injected_pic_mode() {
        let mut chip = IrqChip::new();
        // In PIC mode, notify_injected is a no-op.
        chip.notify_injected(0x20);
    }

    #[test]
    fn test_irq_chip_diagnostics() {
        let chip = IrqChip::new();
        let (irr, isr, imr, vbase) = chip.pic_master_state();
        assert_eq!(irr, 0);
        assert_eq!(isr, 0);
        assert_eq!(imr, 0xFF);
        assert_eq!(vbase, 0);
    }
}
