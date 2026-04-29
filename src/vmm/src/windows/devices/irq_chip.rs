//! IrqChip — coordinator wiring PIC + IOAPIC + LAPIC(s) together.
//!
//! Manages the interrupt routing between legacy PIC (for early boot before
//! APIC is enabled) and the IOAPIC + LAPIC path (after guest enables APIC).
//!
//! Supports multiple LAPICs for multi-vCPU configurations. Each vCPU has its
//! own LAPIC, indexed by vCPU ID. Device interrupts from the IOAPIC are routed
//! to the target LAPIC based on the redirection entry destination field.
//!
//! The APIC mode is auto-detected: when the guest writes to the LAPIC SVR
//! register with the enable bit set, the IrqChip switches to APIC mode.

use std::time::Instant;

use super::ioapic::IoApic;
use super::lapic::{IpiAction, LocalApic};
use super::pic::Pic;
use super::super::memory::{IOAPIC_MMIO_BASE, IOAPIC_MMIO_SIZE, LAPIC_MMIO_BASE, LAPIC_MMIO_SIZE};

/// Result of an IrqChip MMIO write operation.
#[derive(Debug)]
pub struct IrqChipWriteResult {
    /// Whether the address was handled by the IrqChip.
    pub handled: bool,
    /// IPI action to dispatch (from LAPIC ICR write).
    pub ipi_action: IpiAction,
}

impl Default for IrqChipWriteResult {
    fn default() -> Self {
        Self {
            handled: false,
            ipi_action: IpiAction::None,
        }
    }
}

/// Coordinated interrupt controller combining PIC, IOAPIC, and per-vCPU LAPICs.
pub struct IrqChip {
    /// Legacy PIC (for early boot before APIC is enabled).
    pub pic: Pic,
    /// I/O APIC for routing device interrupts to the LAPICs.
    ioapic: IoApic,
    /// Per-vCPU Local APICs (indexed by vCPU ID).
    lapics: Vec<LocalApic>,
    /// false = PIC mode (early boot), true = APIC mode.
    apic_mode: bool,
}

impl Default for IrqChip {
    fn default() -> Self {
        Self::new(1)
    }
}

impl IrqChip {
    /// Create a new IrqChip in PIC mode (legacy boot) with N LAPICs.
    pub fn new(num_vcpus: u8) -> Self {
        let lapics = (0..num_vcpus).map(|id| LocalApic::new_with_id(id)).collect();
        Self {
            pic: Pic::new(),
            ioapic: IoApic::new(),
            lapics,
            apic_mode: false,
        }
    }

    /// Number of vCPUs (LAPICs).
    pub fn num_vcpus(&self) -> u8 {
        self.lapics.len() as u8
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
            if let Some((vector, dest)) = self.ioapic.service_irq(gsi, true) {
                let target = (dest as usize).min(self.lapics.len() - 1);
                self.lapics[target].accept_interrupt(vector);
            }
        } else {
            self.pic.raise_irq(irq);
        }
    }

    /// Get the highest-priority injectable vector for a specific vCPU.
    ///
    /// Checks LAPIC (APIC mode) or PIC (legacy mode, only for BSP / vCPU 0).
    pub fn get_injectable_vector(&self, vcpu_id: u8) -> Option<u8> {
        if self.apic_mode {
            self.lapics[vcpu_id as usize].get_highest_injectable()
        } else if vcpu_id == 0 {
            if self.pic.has_pending() {
                // PIC has pending, but we need to peek — can't acknowledge yet.
                // Return a sentinel to indicate "has pending".
                Some(0) // Caller should use acknowledge() to get actual vector.
            } else {
                None
            }
        } else {
            None // APs don't get PIC interrupts.
        }
    }

    /// Check if there are any pending interrupts for a specific vCPU.
    pub fn has_pending(&self, vcpu_id: u8) -> bool {
        if self.apic_mode {
            self.lapics[vcpu_id as usize].get_highest_injectable().is_some()
        } else if vcpu_id == 0 {
            self.pic.has_pending()
        } else {
            false
        }
    }

    /// Acknowledge the highest-priority interrupt for a specific vCPU.
    ///
    /// In PIC mode (vCPU 0 only): acknowledges from PIC and returns the vector.
    /// In APIC mode: returns the highest injectable from the vCPU's LAPIC.
    pub fn acknowledge(&mut self, vcpu_id: u8) -> Option<u8> {
        if self.apic_mode {
            self.lapics[vcpu_id as usize].get_highest_injectable()
        } else if vcpu_id == 0 {
            self.pic.acknowledge()
        } else {
            None
        }
    }

    /// Called after the vector has been injected into the vCPU.
    ///
    /// In APIC mode: moves the vector from IRR to ISR in the vCPU's LAPIC.
    /// In PIC mode: no-op (PIC acknowledge already moved to ISR).
    pub fn notify_injected(&mut self, vcpu_id: u8, vector: u8) {
        if self.apic_mode {
            self.lapics[vcpu_id as usize].start_of_interrupt(vector);
        }
    }

    /// Handle an EOI from a specific vCPU's LAPIC.
    ///
    /// Propagates EOI from LAPIC to IOAPIC for level-triggered interrupt
    /// completion. May trigger re-injection if the pin is still asserted.
    fn handle_lapic_eoi(&mut self, vcpu_id: u8, vector: u8) {
        if let Some(pin) = self.ioapic.end_of_interrupt(vector) {
            // Pin still asserted — re-deliver using the correct IOAPIC pin.
            if let Some((new_vector, dest)) = self.ioapic.service_irq(pin, true) {
                let target = (dest as usize).min(self.lapics.len() - 1);
                self.lapics[target].accept_interrupt(new_vector);
            }
        }
        // Suppress unused variable warning — vcpu_id is used for routing context.
        let _ = vcpu_id;
    }

    /// Tick the LAPIC timer for a specific vCPU. Returns the timer vector if it fired.
    pub fn tick_timer(&mut self, vcpu_id: u8, now: Instant) -> Option<u8> {
        if !self.apic_mode {
            return None;
        }
        let lapic = &mut self.lapics[vcpu_id as usize];
        if let Some(vector) = lapic.tick_timer(now) {
            lapic.accept_interrupt(vector);
            Some(vector)
        } else {
            None
        }
    }

    /// Handle an MMIO read to an IOAPIC or LAPIC address.
    ///
    /// Returns Some(value) if the address was handled, None otherwise.
    /// LAPIC reads are dispatched to the requesting vCPU's LAPIC.
    pub fn handle_mmio_read(&self, vcpu_id: u8, addr: u64, _size: u8) -> Option<u32> {
        if addr >= IOAPIC_MMIO_BASE && addr < IOAPIC_MMIO_BASE + IOAPIC_MMIO_SIZE {
            let offset = addr - IOAPIC_MMIO_BASE;
            Some(self.ioapic.read_mmio(offset))
        } else if addr >= LAPIC_MMIO_BASE && addr < LAPIC_MMIO_BASE + LAPIC_MMIO_SIZE {
            let offset = addr - LAPIC_MMIO_BASE;
            Some(self.lapics[vcpu_id as usize].read_mmio(offset))
        } else {
            None
        }
    }

    /// Handle an MMIO write to an IOAPIC or LAPIC address.
    ///
    /// Returns an `IrqChipWriteResult` indicating whether the address was handled
    /// and any IPI action from an ICR write.
    pub fn handle_mmio_write(&mut self, vcpu_id: u8, addr: u64, _size: u8, data: u32) -> IrqChipWriteResult {
        if addr >= IOAPIC_MMIO_BASE && addr < IOAPIC_MMIO_BASE + IOAPIC_MMIO_SIZE {
            let offset = addr - IOAPIC_MMIO_BASE;
            self.ioapic.write_mmio(offset, data);
            // An IOAPIC entry may have been unmasked — check transition.
            self.check_apic_transition();
            IrqChipWriteResult {
                handled: true,
                ipi_action: IpiAction::None,
            }
        } else if addr >= LAPIC_MMIO_BASE && addr < LAPIC_MMIO_BASE + LAPIC_MMIO_SIZE {
            let offset = addr - LAPIC_MMIO_BASE;
            let result = self.lapics[vcpu_id as usize].write_mmio(offset, data);

            // LAPIC SVR may have been enabled — check transition.
            self.check_apic_transition();

            // Handle EOI propagation to IOAPIC.
            if let Some(vector) = result.eoi_vector {
                self.handle_lapic_eoi(vcpu_id, vector);
            }

            IrqChipWriteResult {
                handled: true,
                ipi_action: result.ipi_action,
            }
        } else {
            IrqChipWriteResult::default()
        }
    }

    /// Deliver an IPI to the target LAPIC.
    ///
    /// Called by the runner when a vCPU's ICR write produces an IPI action
    /// that targets another LAPIC (SendInterrupt variant only — INIT and SIPI
    /// are handled by the runner's AP startup logic).
    pub fn deliver_ipi_interrupt(&mut self, target_apic_id: u8, vector: u8) {
        if (target_apic_id as usize) < self.lapics.len() {
            self.lapics[target_apic_id as usize].accept_interrupt(vector);
        }
    }

    /// Check if conditions are met to switch from PIC to APIC mode.
    ///
    /// The transition requires BOTH:
    /// 1. Any LAPIC is software-enabled (SVR bit 8 set by guest)
    /// 2. IOAPIC has at least one unmasked redirection entry
    ///
    /// This prevents a gap where the kernel has enabled the LAPIC but hasn't
    /// yet programmed the IOAPIC entries, which would silently drop interrupts
    /// (all IOAPIC entries start masked).
    fn check_apic_transition(&mut self) {
        if self.apic_mode {
            return;
        }
        let any_lapic_enabled = self.lapics.iter().any(|l| l.is_enabled());
        if any_lapic_enabled && self.ioapic.has_unmasked_entries() {
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
        let chip = IrqChip::new(1);
        assert!(!chip.apic_mode());
    }

    #[test]
    fn test_irq_chip_multi_vcpu_creates_lapics() {
        let chip = IrqChip::new(4);
        assert_eq!(chip.num_vcpus(), 4);
        assert_eq!(chip.lapics[0].id(), 0);
        assert_eq!(chip.lapics[1].id(), 1);
        assert_eq!(chip.lapics[2].id(), 2);
        assert_eq!(chip.lapics[3].id(), 3);
    }

    #[test]
    fn test_irq_chip_pic_mode_raise_irq() {
        let mut chip = IrqChip::new(1);

        // Program PIC for testing.
        chip.pic.write_port(0x20, 0x11); // ICW1
        chip.pic.write_port(0x21, 0x20); // ICW2: vector base 0x20
        chip.pic.write_port(0x21, 0x04); // ICW3
        chip.pic.write_port(0x21, 0x01); // ICW4
        chip.pic.write_port(0x21, 0x00); // IMR: unmask all

        chip.raise_irq(0);
        assert!(chip.has_pending(0));

        let vector = chip.acknowledge(0);
        assert_eq!(vector, Some(0x20));
    }

    #[test]
    fn test_irq_chip_pic_mode_only_bsp() {
        let mut chip = IrqChip::new(2);

        // Program PIC.
        chip.pic.write_port(0x20, 0x11);
        chip.pic.write_port(0x21, 0x20);
        chip.pic.write_port(0x21, 0x04);
        chip.pic.write_port(0x21, 0x01);
        chip.pic.write_port(0x21, 0x00);

        chip.raise_irq(0);

        // BSP (vCPU 0) sees the interrupt.
        assert!(chip.has_pending(0));
        // AP (vCPU 1) does NOT see PIC interrupts.
        assert!(!chip.has_pending(1));
    }

    #[test]
    fn test_irq_chip_apic_mode_switch_requires_ioapic_entries() {
        let mut chip = IrqChip::new(1);
        assert!(!chip.apic_mode());

        // Write to LAPIC SVR with enable bit — NOT enough alone.
        let svr_addr = LAPIC_MMIO_BASE + 0x0F0;
        chip.handle_mmio_write(0, svr_addr, 4, 0x1FF);
        assert!(
            !chip.apic_mode(),
            "APIC mode must NOT activate on SVR alone"
        );

        // Unmask an IOAPIC entry (pin 2, vector 0x22) — NOW transition triggers.
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE, 4, 0x14); // Select reg 0x14 (pin 2 low)
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE + 0x10, 4, 0x22); // vector=0x22, unmasked

        assert!(
            chip.apic_mode(),
            "APIC mode should activate when LAPIC enabled + IOAPIC unmasked"
        );
    }

    #[test]
    fn test_irq_chip_apic_mode_raise_irq() {
        let mut chip = IrqChip::new(1);

        // Enable LAPIC SVR.
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 5: vector 0x25, unmasked, edge-triggered.
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE, 4, 0x1A); // Select register 0x1A (pin 5 low)
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE + 0x10, 4, 0x25); // vector=0x25, unmasked
        assert!(chip.apic_mode());

        chip.raise_irq(5);
        assert!(chip.has_pending(0));

        let vector = chip.acknowledge(0);
        assert_eq!(vector, Some(0x25));
    }

    #[test]
    fn test_irq_chip_apic_mode_irq0_remaps_to_gsi2() {
        let mut chip = IrqChip::new(1);

        // Enable LAPIC SVR.
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 2: vector 0x22, unmasked, edge-triggered.
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE, 4, 0x14); // Select register 0x14 (pin 2 low)
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE + 0x10, 4, 0x22); // vector=0x22, unmasked
        assert!(chip.apic_mode());

        // raise_irq(0) should remap to IOAPIC pin 2 and deliver vector 0x22.
        chip.raise_irq(0);
        assert!(chip.has_pending(0));

        let vector = chip.acknowledge(0);
        assert_eq!(vector, Some(0x22));
    }

    #[test]
    fn test_irq_chip_mmio_read_ioapic() {
        let mut chip = IrqChip::new(1);
        // Read IOAPIC version register.
        chip.ioapic.write_mmio(0x00, 0x01); // Direct access to avoid transition check
        let version = chip.handle_mmio_read(0, IOAPIC_MMIO_BASE + 0x10, 4);
        assert_eq!(version, Some(0x0017_0011));
    }

    #[test]
    fn test_irq_chip_mmio_read_lapic() {
        let chip = IrqChip::new(1);
        let version = chip.handle_mmio_read(0, LAPIC_MMIO_BASE + 0x030, 4);
        assert!(version.is_some());
        assert_eq!(version.unwrap() & 0xFF, 0x14);
    }

    #[test]
    fn test_irq_chip_mmio_read_lapic_id_per_vcpu() {
        let chip = IrqChip::new(2);
        // vCPU 0 reads its own LAPIC ID.
        assert_eq!(chip.handle_mmio_read(0, LAPIC_MMIO_BASE + 0x020, 4), Some(0 << 24));
        // vCPU 1 reads its own LAPIC ID.
        assert_eq!(chip.handle_mmio_read(1, LAPIC_MMIO_BASE + 0x020, 4), Some(1 << 24));
    }

    #[test]
    fn test_irq_chip_mmio_read_unhandled() {
        let chip = IrqChip::new(1);
        assert_eq!(chip.handle_mmio_read(0, 0xDEAD_0000, 4), None);
    }

    #[test]
    fn test_irq_chip_mmio_write_unhandled() {
        let mut chip = IrqChip::new(1);
        let result = chip.handle_mmio_write(0, 0xDEAD_0000, 4, 0);
        assert!(!result.handled);
    }

    #[test]
    fn test_irq_chip_eoi_propagation() {
        let mut chip = IrqChip::new(1);

        // Enable LAPIC SVR.
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);

        // Configure IOAPIC pin 3: vector 0x33, level-triggered, unmasked.
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE, 4, 0x16); // register 0x16 = pin 3 low
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE + 0x10, 4, 0x33 | (1 << 15)); // vector=0x33, level-triggered
        assert!(chip.apic_mode());

        // Raise IRQ 3.
        chip.raise_irq(3);
        let vector = chip.acknowledge(0);
        assert_eq!(vector, Some(0x33));

        // Inject and acknowledge in LAPIC.
        chip.notify_injected(0, 0x33);

        // Write EOI to LAPIC (offset 0x0B0).
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x0B0, 4, 0);

        // After EOI, the pin is still asserted → re-injection.
        assert!(chip.has_pending(0));
    }

    #[test]
    fn test_irq_chip_timer_only_in_apic_mode() {
        let mut chip = IrqChip::new(1);
        let now = Instant::now();
        // In PIC mode, timer should not fire.
        assert_eq!(chip.tick_timer(0, now), None);
    }

    #[test]
    fn test_irq_chip_notify_injected_pic_mode() {
        let mut chip = IrqChip::new(1);
        // In PIC mode, notify_injected is a no-op.
        chip.notify_injected(0, 0x20);
    }

    #[test]
    fn test_irq_chip_diagnostics() {
        let chip = IrqChip::new(1);
        let (irr, isr, imr, vbase) = chip.pic_master_state();
        assert_eq!(irr, 0);
        assert_eq!(isr, 0);
        assert_eq!(imr, 0xFF);
        assert_eq!(vbase, 0);
    }

    #[test]
    fn test_irq_chip_deliver_ipi_interrupt() {
        let mut chip = IrqChip::new(2);

        // Enable APIC mode: enable BSP's LAPIC SVR + unmask IOAPIC entry.
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x0F0, 4, 0x1FF);
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE, 4, 0x14);
        chip.handle_mmio_write(0, IOAPIC_MMIO_BASE + 0x10, 4, 0x22);
        assert!(chip.apic_mode());

        // Deliver IPI to vCPU 1.
        chip.deliver_ipi_interrupt(1, 0x40);
        assert!(chip.has_pending(1));
        assert_eq!(chip.acknowledge(1), Some(0x40));
    }

    #[test]
    fn test_irq_chip_icr_write_returns_ipi_action() {
        let mut chip = IrqChip::new(2);

        // Write ICR high on vCPU 0: destination = APIC 1.
        chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x310, 4, 1 << 24);
        // Write ICR low on vCPU 0: INIT delivery mode.
        let result = chip.handle_mmio_write(0, LAPIC_MMIO_BASE + 0x300, 4, 0x0500);
        assert!(result.handled);
        assert_eq!(result.ipi_action, IpiAction::SendInit { target_apic_id: 1 });
    }

    #[test]
    fn test_irq_chip_default_is_single_vcpu() {
        let chip = IrqChip::default();
        assert_eq!(chip.num_vcpus(), 1);
    }
}
