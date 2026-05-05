//! I/O APIC (IOAPIC) emulation.
//!
//! Emulates a 24-pin IOAPIC with redirection table entries for routing
//! interrupts from devices to the Local APIC.
//!
//! MMIO interface at 0xFEC0_0000 (4KB region):
//! - Offset 0x00: IOREGSEL (write register index)
//! - Offset 0x10: IOWIN (read/write selected register)
//!
//! Registers:
//! - 0x00: IOAPIC ID
//! - 0x01: IOAPIC Version (24 entries, version 0x11)
//! - 0x10-0x3F: Redirection table entries (low/high 32 bits)

/// Number of redirection table entries (pins).
const NUM_PINS: usize = 24;

/// IOAPIC version register value.
/// Bits [7:0] = version (0x11 = 82093AA), bits [23:16] = max redirection entry (23).
const IOAPIC_VERSION: u32 = 0x0017_0011;

/// A single redirection table entry.
///
/// Each entry controls how an interrupt on the corresponding pin is delivered.
#[derive(Debug, Clone, Copy)]
struct RedirectionEntry {
    /// IDT vector (0-255).
    vector: u8,
    /// Delivery mode: 0=Fixed, 2=SMI, 4=NMI, 5=INIT, 7=ExtINT.
    delivery_mode: u8,
    /// Destination mode: false=physical, true=logical.
    dest_mode: bool,
    /// Pin polarity: false=active-high, true=active-low.
    polarity: bool,
    /// Trigger mode: false=edge, true=level.
    trigger_mode: bool,
    /// true = masked (interrupt suppressed).
    mask: bool,
    /// Level-triggered: set on delivery, cleared on EOI.
    remote_irr: bool,
    /// LAPIC destination ID.
    dest: u8,
}

impl Default for RedirectionEntry {
    fn default() -> Self {
        Self {
            vector: 0,
            delivery_mode: 0,
            dest_mode: false,
            polarity: false,
            trigger_mode: false,
            mask: true, // Masked by default
            remote_irr: false,
            dest: 0,
        }
    }
}

impl RedirectionEntry {
    /// Read the low 32 bits of the redirection entry.
    fn read_low(&self) -> u32 {
        let mut val = self.vector as u32;
        val |= (self.delivery_mode as u32 & 0x7) << 8;
        if self.dest_mode {
            val |= 1 << 11;
        }
        if self.polarity {
            val |= 1 << 13;
        }
        if self.remote_irr {
            val |= 1 << 14;
        }
        if self.trigger_mode {
            val |= 1 << 15;
        }
        if self.mask {
            val |= 1 << 16;
        }
        val
    }

    /// Read the high 32 bits (destination field in bits [31:24]).
    fn read_high(&self) -> u32 {
        (self.dest as u32) << 24
    }

    /// Write the low 32 bits.
    fn write_low(&mut self, val: u32) {
        self.vector = (val & 0xFF) as u8;
        self.delivery_mode = ((val >> 8) & 0x7) as u8;
        self.dest_mode = val & (1 << 11) != 0;
        self.polarity = val & (1 << 13) != 0;
        // remote_irr is read-only (bit 14).
        self.trigger_mode = val & (1 << 15) != 0;
        self.mask = val & (1 << 16) != 0;
    }

    /// Write the high 32 bits.
    fn write_high(&mut self, val: u32) {
        self.dest = ((val >> 24) & 0xFF) as u8;
    }
}

/// 24-pin I/O APIC.
pub struct IoApic {
    /// IOAPIC ID (bits [27:24] of register 0x00).
    id: u8,
    /// IOREGSEL: indirect register select.
    reg_sel: u8,
    /// 24 redirection table entries.
    entries: [RedirectionEntry; NUM_PINS],
    /// Pin assertion state (for level-triggered re-injection).
    pin_state: u32,
}

impl Default for IoApic {
    fn default() -> Self {
        Self::new()
    }
}

impl IoApic {
    /// Create a new IOAPIC with default state (all pins masked).
    pub fn new() -> Self {
        Self {
            id: 0,
            reg_sel: 0,
            entries: [RedirectionEntry::default(); NUM_PINS],
            pin_state: 0,
        }
    }

    /// Process an IRQ signal. Returns `(vector, dest_apic_id)` if the interrupt
    /// is deliverable, or None if masked/blocked.
    ///
    /// - Edge-triggered: deliver if not masked, set pin state.
    /// - Level-triggered: deliver if not masked AND remote_irr not set.
    pub fn service_irq(&mut self, irq: u8, level: bool) -> Option<(u8, u8)> {
        if irq as usize >= NUM_PINS {
            return None;
        }

        if level {
            self.pin_state |= 1 << irq;
        } else {
            self.pin_state &= !(1 << irq);
            return None; // Deassertion doesn't deliver.
        }

        let entry = &mut self.entries[irq as usize];

        if entry.mask {
            return None;
        }

        if entry.trigger_mode {
            // Level-triggered: only deliver if remote_irr is not set.
            if entry.remote_irr {
                return None;
            }
            entry.remote_irr = true;
        }
        // Edge-triggered: always deliver (if not masked).

        Some((entry.vector, entry.dest))
    }

    /// Handle End-of-Interrupt for a given vector.
    ///
    /// Clears remote_irr for matching level-triggered entries.
    /// Returns the pin number if still asserted (needs re-injection), or None.
    pub fn end_of_interrupt(&mut self, vector: u8) -> Option<u8> {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if entry.vector == vector && entry.trigger_mode && entry.remote_irr {
                entry.remote_irr = false;
                // Check if pin is still asserted.
                if self.pin_state & (1 << i) != 0 {
                    return Some(i as u8);
                }
            }
        }
        None
    }

    /// Read from the IOAPIC MMIO region.
    ///
    /// Only offsets 0x00 (IOREGSEL) and 0x10 (IOWIN) are valid.
    pub fn read_mmio(&self, offset: u64) -> u32 {
        match offset {
            0x00 => self.reg_sel as u32,
            0x10 => self.read_register(self.reg_sel),
            _ => 0,
        }
    }

    /// Write to the IOAPIC MMIO region.
    pub fn write_mmio(&mut self, offset: u64, value: u32) {
        match offset {
            0x00 => self.reg_sel = value as u8,
            0x10 => self.write_register(self.reg_sel, value),
            _ => {}
        }
    }

    /// Read an indirect register by index.
    fn read_register(&self, reg: u8) -> u32 {
        match reg {
            0x00 => (self.id as u32) << 24, // IOAPIC ID
            0x01 => IOAPIC_VERSION,         // Version
            0x02 => 0,                      // Arbitration ID (not used)
            0x10..=0x3F => {
                let pin = ((reg - 0x10) / 2) as usize;
                if pin < NUM_PINS {
                    if reg & 1 == 0 {
                        self.entries[pin].read_low()
                    } else {
                        self.entries[pin].read_high()
                    }
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Check if any redirection table entry is unmasked (active).
    pub fn has_unmasked_entries(&self) -> bool {
        self.entries.iter().any(|e| !e.mask)
    }

    /// Write an indirect register by index.
    fn write_register(&mut self, reg: u8, value: u32) {
        match reg {
            0x00 => self.id = ((value >> 24) & 0x0F) as u8,
            0x10..=0x3F => {
                let pin = ((reg - 0x10) / 2) as usize;
                if pin < NUM_PINS {
                    if reg & 1 == 0 {
                        self.entries[pin].write_low(value);
                    } else {
                        self.entries[pin].write_high(value);
                    }
                }
            }
            _ => {} // Read-only or reserved registers.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioapic_initial_state() {
        let ioapic = IoApic::new();
        assert_eq!(ioapic.id, 0);
        assert_eq!(ioapic.reg_sel, 0);
        // All entries should be masked.
        for entry in &ioapic.entries {
            assert!(entry.mask);
            assert_eq!(entry.vector, 0);
        }
        assert!(!ioapic.has_unmasked_entries());
    }

    #[test]
    fn test_ioapic_has_unmasked_entries() {
        let mut ioapic = IoApic::new();
        assert!(!ioapic.has_unmasked_entries());

        // Unmask pin 2 with vector 0x22.
        ioapic.write_mmio(0x00, 0x14); // Select register 0x14 (pin 2 low)
        ioapic.write_mmio(0x10, 0x22); // vector=0x22, mask bit 16 = 0 (unmasked)
        assert!(ioapic.has_unmasked_entries());
    }

    #[test]
    fn test_ioapic_version_register() {
        let ioapic = IoApic::new();
        // Select version register.
        let version = ioapic.read_register(0x01);
        assert_eq!(version & 0xFF, 0x11, "version should be 0x11");
        assert_eq!((version >> 16) & 0xFF, 23, "max redir entry should be 23");
    }

    #[test]
    fn test_ioapic_id_read_write() {
        let mut ioapic = IoApic::new();
        ioapic.write_register(0x00, 0x0A00_0000); // Set ID = 0x0A
        assert_eq!(ioapic.read_register(0x00), 0x0A00_0000);
        assert_eq!(ioapic.id, 0x0A);
    }

    #[test]
    fn test_ioapic_redir_entry_read_write() {
        let mut ioapic = IoApic::new();

        // Write low 32 bits of entry 0 (register 0x10):
        // vector=0x30, delivery_mode=0 (Fixed), level-triggered, unmasked
        let low: u32 = 0x30 | (1 << 15); // vector=0x30, trigger=level, mask=0
        ioapic.write_register(0x10, low);

        // Write high 32 bits of entry 0 (register 0x11):
        // destination = LAPIC 0
        ioapic.write_register(0x11, 0x00 << 24);

        let read_low = ioapic.read_register(0x10);
        assert_eq!(read_low & 0xFF, 0x30, "vector");
        assert!(read_low & (1 << 15) != 0, "trigger mode should be level");
        assert!(read_low & (1 << 16) == 0, "should be unmasked");

        let read_high = ioapic.read_register(0x11);
        assert_eq!((read_high >> 24) & 0xFF, 0, "dest should be 0");
    }

    #[test]
    fn test_ioapic_masked_irq_not_delivered() {
        let mut ioapic = IoApic::new();
        // Entry 0 is masked by default.
        assert_eq!(ioapic.service_irq(0, true), None);
    }

    #[test]
    fn test_ioapic_edge_triggered_delivery() {
        let mut ioapic = IoApic::new();

        // Configure pin 5: edge-triggered, vector 0x25, dest 0, unmasked.
        ioapic.entries[5].vector = 0x25;
        ioapic.entries[5].mask = false;
        ioapic.entries[5].trigger_mode = false; // Edge

        let result = ioapic.service_irq(5, true);
        assert_eq!(result, Some((0x25, 0)));
    }

    #[test]
    fn test_ioapic_level_triggered_delivery() {
        let mut ioapic = IoApic::new();

        // Configure pin 3: level-triggered, vector 0x33, dest 0, unmasked.
        ioapic.entries[3].vector = 0x33;
        ioapic.entries[3].mask = false;
        ioapic.entries[3].trigger_mode = true; // Level

        let result = ioapic.service_irq(3, true);
        assert_eq!(result, Some((0x33, 0)));
        assert!(ioapic.entries[3].remote_irr, "remote_irr should be set");
    }

    #[test]
    fn test_ioapic_level_triggered_blocked_by_remote_irr() {
        let mut ioapic = IoApic::new();

        // Configure pin 3: level-triggered, vector 0x33, unmasked.
        ioapic.entries[3].vector = 0x33;
        ioapic.entries[3].mask = false;
        ioapic.entries[3].trigger_mode = true;

        // First delivery sets remote_irr.
        assert_eq!(ioapic.service_irq(3, true), Some((0x33, 0)));

        // Second delivery blocked by remote_irr.
        assert_eq!(ioapic.service_irq(3, true), None);
    }

    #[test]
    fn test_ioapic_eoi_clears_remote_irr() {
        let mut ioapic = IoApic::new();

        ioapic.entries[3].vector = 0x33;
        ioapic.entries[3].mask = false;
        ioapic.entries[3].trigger_mode = true;

        ioapic.service_irq(3, true);
        assert!(ioapic.entries[3].remote_irr);

        // EOI should clear remote_irr and return the pin for re-injection.
        let reinject_pin = ioapic.end_of_interrupt(0x33);
        assert!(!ioapic.entries[3].remote_irr);
        // Pin is still asserted, so re-injection needed on pin 3.
        assert_eq!(reinject_pin, Some(3));
    }

    #[test]
    fn test_ioapic_eoi_no_reinjection_when_deasserted() {
        let mut ioapic = IoApic::new();

        ioapic.entries[3].vector = 0x33;
        ioapic.entries[3].mask = false;
        ioapic.entries[3].trigger_mode = true;

        ioapic.service_irq(3, true);
        // Deassert the pin.
        ioapic.service_irq(3, false);

        let reinject_pin = ioapic.end_of_interrupt(0x33);
        assert_eq!(reinject_pin, None, "no reinjection when pin is deasserted");
    }

    #[test]
    fn test_ioapic_deassertion_does_not_deliver() {
        let mut ioapic = IoApic::new();

        ioapic.entries[5].vector = 0x25;
        ioapic.entries[5].mask = false;

        // Deassertion (level=false) should not deliver.
        assert_eq!(ioapic.service_irq(5, false), None);
    }

    #[test]
    fn test_ioapic_out_of_range_irq() {
        let mut ioapic = IoApic::new();
        assert_eq!(ioapic.service_irq(24, true), None);
        assert_eq!(ioapic.service_irq(255, true), None);
    }

    #[test]
    fn test_ioapic_mmio_regsel() {
        let mut ioapic = IoApic::new();

        // Write IOREGSEL.
        ioapic.write_mmio(0x00, 0x01);
        assert_eq!(ioapic.reg_sel, 0x01);

        // Read IOREGSEL.
        assert_eq!(ioapic.read_mmio(0x00), 0x01);
    }

    #[test]
    fn test_ioapic_mmio_iowin_version() {
        let mut ioapic = IoApic::new();

        // Select version register.
        ioapic.write_mmio(0x00, 0x01);
        let version = ioapic.read_mmio(0x10);
        assert_eq!(version & 0xFF, 0x11);
    }

    #[test]
    fn test_ioapic_mmio_invalid_offset() {
        let mut ioapic = IoApic::new();
        // Invalid offsets should return 0 / be no-ops.
        assert_eq!(ioapic.read_mmio(0x04), 0);
        ioapic.write_mmio(0x04, 0xDEAD);
    }

    #[test]
    fn test_ioapic_redir_entry_remote_irr_readonly() {
        let mut ioapic = IoApic::new();

        // Set remote_irr manually.
        ioapic.entries[0].remote_irr = true;

        // Write low word without remote_irr bit — it should NOT clear remote_irr.
        let low = 0x30u32; // vector=0x30, no remote_irr bit set
        ioapic.write_register(0x10, low);

        // remote_irr is read-only in the write path.
        assert!(ioapic.entries[0].remote_irr);
    }

    #[test]
    fn test_ioapic_multiple_pins_independent() {
        let mut ioapic = IoApic::new();

        // Configure two different pins.
        ioapic.entries[1].vector = 0x21;
        ioapic.entries[1].mask = false;
        ioapic.entries[2].vector = 0x22;
        ioapic.entries[2].mask = false;

        assert_eq!(ioapic.service_irq(1, true), Some((0x21, 0)));
        assert_eq!(ioapic.service_irq(2, true), Some((0x22, 0)));
    }

    #[test]
    fn test_ioapic_out_of_range_register() {
        let ioapic = IoApic::new();
        // Registers beyond 0x3F should return 0.
        assert_eq!(ioapic.read_register(0x40), 0);
        assert_eq!(ioapic.read_register(0xFF), 0);
    }

    #[test]
    fn test_ioapic_service_irq_returns_destination() {
        let mut ioapic = IoApic::new();

        // Configure pin 4: vector 0x24, dest APIC ID = 1, unmasked.
        ioapic.entries[4].vector = 0x24;
        ioapic.entries[4].dest = 1;
        ioapic.entries[4].mask = false;

        let result = ioapic.service_irq(4, true);
        assert_eq!(result, Some((0x24, 1)));
    }

    #[test]
    fn test_ioapic_pin_beyond_24_in_redir() {
        let ioapic = IoApic::new();
        // Register 0x10 + 24*2 = 0x40, which is pin 24 (out of range).
        assert_eq!(ioapic.read_register(0x40), 0);
    }
}
