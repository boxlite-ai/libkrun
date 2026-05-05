//! Local APIC (LAPIC) emulation.
//!
//! Per-vCPU LAPIC for interrupt priority management and IPI delivery.
//! Tracks IRR (Interrupt Request Register) and ISR (In-Service Register)
//! as 256-bit vectors, and implements priority-based interrupt delivery.
//!
//! MMIO interface at 0xFEE0_0000 (4KB region):
//! - 0x020: LAPIC ID
//! - 0x030: LAPIC Version
//! - 0x080: TPR (Task Priority Register)
//! - 0x0B0: EOI (write-only)
//! - 0x0F0: SVR (Spurious Vector Register)
//! - 0x100-0x170: ISR (read-only, 256 bits)
//! - 0x200-0x270: IRR (read-only, 256 bits)
//! - 0x300: ICR Low (Interrupt Command Register)
//! - 0x310: ICR High (destination APIC ID)
//! - 0x320: LVT Timer
//! - 0x380: Timer Initial Count
//! - 0x390: Timer Current Count
//! - 0x3E0: Timer Divide Configuration

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

/// Shared APIC state for lock-free cross-vCPU interrupt delivery.
///
/// Other vCPUs atomically OR bits into `new_irr`. The owning vCPU
/// periodically calls `pull_irr()` to merge into its local IRR.
/// Inspired by OpenVMM's `virt_support_apic::SharedState`.
pub struct SharedApicState {
    /// Remote interrupt requests (256 bits = 8 x AtomicU32).
    /// Source vCPUs atomic-OR the vector bit here.
    new_irr: [AtomicU32; 8],
}

impl SharedApicState {
    /// Create a new shared state with no pending interrupts.
    pub fn new() -> Self {
        Self {
            new_irr: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    /// Atomically request an interrupt vector on this vCPU.
    ///
    /// Returns `true` if the bit was newly set (caller should wake target vCPU).
    pub fn request_interrupt(&self, vector: u8) -> bool {
        let (bank, mask) = bank_mask(vector);
        let prev = self.new_irr[bank].fetch_or(mask, Ordering::Release);
        prev & mask == 0
    }
}

/// Compute the bank index and bit mask for a vector (0-255).
fn bank_mask(vector: u8) -> (usize, u32) {
    let bank = (vector / 32) as usize;
    let bit = vector % 32;
    (bank, 1u32 << bit)
}

/// Action resulting from an ICR write (Inter-Processor Interrupt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiAction {
    /// No IPI action (non-ICR write or unrecognized delivery mode).
    None,
    /// Fixed delivery: send interrupt vector to target LAPIC.
    SendInterrupt { target_apic_id: u8, vector: u8 },
    /// Broadcast fixed interrupt to all vCPUs except the sender.
    BroadcastInterrupt { source_apic_id: u8, vector: u8 },
    /// INIT delivery: reset target processor.
    SendInit { target_apic_id: u8 },
    /// Startup IPI (SIPI): start target processor at vector * 0x1000.
    SendSipi { target_apic_id: u8, vector: u8 },
}

/// Result of a LAPIC MMIO write operation.
#[derive(Debug, Clone, Copy)]
pub struct LapicWriteResult {
    /// If an EOI was written, the vector that was cleared from ISR.
    pub eoi_vector: Option<u8>,
    /// If an ICR was written, the resulting IPI action.
    pub ipi_action: IpiAction,
}

impl Default for LapicWriteResult {
    fn default() -> Self {
        Self {
            eoi_vector: None,
            ipi_action: IpiAction::None,
        }
    }
}

/// LAPIC version: integrated APIC with 6 LVT entries.
const LAPIC_VERSION: u32 = 0x0005_0014; // version 0x14, max LVT=5

/// SVR bit 8: APIC software enable.
const SVR_APIC_ENABLE: u32 = 1 << 8;

/// LVT mask bit (bit 16).
const LVT_MASKED: u32 = 1 << 16;

/// Timer modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerMode {
    OneShot,
    Periodic,
}

/// Per-vCPU Local APIC.
pub struct LocalApic {
    /// APIC ID (matches vCPU index).
    id: u8,
    /// 256-bit Interrupt Request Register (8 x 32-bit words).
    irr: [u32; 8],
    /// 256-bit In-Service Register.
    isr: [u32; 8],
    /// Task Priority Register (only low 8 bits used).
    tpr: u8,
    /// Spurious Vector Register (bit 8 = APIC enabled).
    svr: u32,

    // ICR (Interrupt Command Register) for IPI support.
    /// ICR low 32 bits (vector, delivery mode, destination shorthand).
    icr_low: u32,
    /// ICR high 32 bits (destination APIC ID in bits 31:24).
    icr_high: u32,

    // Timer state.
    /// Timer mode.
    timer_mode: TimerMode,
    /// LVT Timer vector.
    timer_vector: u8,
    /// LVT Timer mask.
    timer_masked: bool,
    /// Divide configuration register value.
    timer_divide_reg: u32,
    /// Computed divisor (1, 2, 4, 8, 16, 32, 64, 128).
    timer_divisor: u32,
    /// Initial count register.
    timer_initial: u32,
    /// When the timer fires next (host time).
    timer_deadline: Option<Instant>,
    /// Timer period for periodic mode.
    timer_period_ns: u64,
}

impl Default for LocalApic {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalApic {
    /// Create a new LAPIC with default state (disabled), APIC ID = 0.
    pub fn new() -> Self {
        Self::new_with_id(0)
    }

    /// Create a new LAPIC with a specific APIC ID (disabled by default).
    pub fn new_with_id(id: u8) -> Self {
        Self {
            id,
            irr: [0; 8],
            isr: [0; 8],
            tpr: 0,
            svr: 0, // APIC disabled by default

            icr_low: 0,
            icr_high: 0,

            timer_mode: TimerMode::OneShot,
            timer_vector: 0,
            timer_masked: true,
            timer_divide_reg: 0,
            timer_divisor: 2, // Default divisor
            timer_initial: 0,
            timer_deadline: None,
            timer_period_ns: 0,
        }
    }

    /// Get the APIC ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Whether the LAPIC is software-enabled (SVR bit 8).
    pub fn is_enabled(&self) -> bool {
        self.svr & SVR_APIC_ENABLE != 0
    }

    /// Pull remote interrupt requests from the shared state into the local IRR.
    ///
    /// Atomically swaps each bank to 0 and ORs the bits into the local IRR.
    /// Called at the top of each vCPU loop iteration (lock-free fast path).
    pub fn pull_irr(&mut self, shared: &SharedApicState) {
        for i in 0..8 {
            let bits = shared.new_irr[i].swap(0, Ordering::Acquire);
            if bits != 0 {
                self.irr[i] |= bits;
            }
        }
    }

    /// Accept an interrupt vector into the IRR.
    pub fn accept_interrupt(&mut self, vector: u8) {
        let word = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[word] |= 1 << bit;
    }

    /// Get the highest-priority vector in IRR that beats the current
    /// Processor Priority (PPR = max(TPR, highest ISR vector class)).
    ///
    /// Returns None if no injectable vector exists.
    pub fn get_highest_injectable(&self) -> Option<u8> {
        let highest_irr = Self::highest_bit(&self.irr)?;
        let ppr = self.processor_priority();

        // Vector must have higher priority (higher number = higher priority
        // in x86, but within the same class, lower bit wins; the priority
        // class is vector >> 4).
        if (highest_irr >> 4) > (ppr >> 4) {
            Some(highest_irr)
        } else {
            None
        }
    }

    /// Called when the vector is actually injected into the vCPU.
    /// Moves the vector from IRR to ISR.
    pub fn start_of_interrupt(&mut self, vector: u8) {
        let word = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[word] &= !(1 << bit);
        self.isr[word] |= 1 << bit;
    }

    /// Handle End-of-Interrupt.
    ///
    /// Clears the highest-priority ISR bit.
    /// Returns the vector that was cleared (for IOAPIC EOI broadcast).
    pub fn end_of_interrupt(&mut self) -> Option<u8> {
        let highest = Self::highest_bit(&self.isr)?;
        let word = (highest / 32) as usize;
        let bit = highest % 32;
        self.isr[word] &= !(1 << bit);
        Some(highest)
    }

    /// Compute the LAPIC timer current count register value.
    ///
    /// Returns the remaining count based on elapsed time since the timer was
    /// armed. The kernel reads this during timer calibration and busy-waits.
    fn current_count(&self) -> u32 {
        if let Some(deadline) = self.timer_deadline {
            let now = Instant::now();
            if now < deadline {
                let remaining_ns = deadline.duration_since(now).as_nanos() as u64;
                let tick_ns = 100 * self.timer_divisor as u64;
                let remaining_ticks = remaining_ns / tick_ns;
                (remaining_ticks as u32).min(self.timer_initial)
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Tick the LAPIC timer. Returns the timer vector if it fired.
    pub fn tick_timer(&mut self, now: Instant) -> Option<u8> {
        if self.timer_masked || self.timer_initial == 0 {
            return None;
        }

        let deadline = self.timer_deadline?;

        if now >= deadline {
            let vector = self.timer_vector;

            match self.timer_mode {
                TimerMode::OneShot => {
                    self.timer_deadline = None;
                }
                TimerMode::Periodic => {
                    // Rearm timer for next period.
                    let period = std::time::Duration::from_nanos(self.timer_period_ns);
                    self.timer_deadline = Some(deadline + period);
                }
            }

            Some(vector)
        } else {
            None
        }
    }

    /// Read from the LAPIC MMIO region.
    pub fn read_mmio(&self, offset: u64) -> u32 {
        match offset {
            0x020 => (self.id as u32) << 24, // LAPIC ID
            0x030 => LAPIC_VERSION,          // Version
            0x080 => self.tpr as u32,        // TPR
            0x0B0 => 0,                      // EOI (write-only)
            0x0F0 => self.svr,               // SVR
            // ISR: 0x100, 0x110, 0x120, ..., 0x170
            0x100..=0x170 if offset & 0x0F == 0 => {
                let idx = ((offset - 0x100) / 0x10) as usize;
                if idx < 8 {
                    self.isr[idx]
                } else {
                    0
                }
            }
            // IRR: 0x200, 0x210, 0x220, ..., 0x270
            0x200..=0x270 if offset & 0x0F == 0 => {
                let idx = ((offset - 0x200) / 0x10) as usize;
                if idx < 8 {
                    self.irr[idx]
                } else {
                    0
                }
            }
            0x300 => self.icr_low,          // ICR Low
            0x310 => self.icr_high,         // ICR High
            0x320 => self.read_lvt_timer(), // LVT Timer
            0x380 => self.timer_initial,    // Timer Initial Count
            0x390 => self.current_count(),  // Timer Current Count
            0x3E0 => self.timer_divide_reg, // Timer Divide Configuration
            _ => 0,
        }
    }

    /// Result of a LAPIC MMIO write.
    ///
    /// Contains an optional EOI vector and an IPI action from ICR writes.
    pub fn write_mmio(&mut self, offset: u64, value: u32) -> LapicWriteResult {
        match offset {
            0x080 => {
                self.tpr = (value & 0xFF) as u8;
                LapicWriteResult::default()
            }
            0x0B0 => {
                // EOI: clear highest ISR, return vector for IOAPIC.
                LapicWriteResult {
                    eoi_vector: self.end_of_interrupt(),
                    ipi_action: IpiAction::None,
                }
            }
            0x0F0 => {
                self.svr = value;
                log::debug!(
                    "LAPIC {} SVR write: {:#X} (enabled={})",
                    self.id,
                    value,
                    value & SVR_APIC_ENABLE != 0
                );
                LapicWriteResult::default()
            }
            0x300 => {
                // ICR Low write triggers IPI delivery.
                self.icr_low = value;
                let action = self.parse_icr();
                LapicWriteResult {
                    eoi_vector: None,
                    ipi_action: action,
                }
            }
            0x310 => {
                // ICR High: destination APIC ID (bits 31:24).
                self.icr_high = value;
                LapicWriteResult::default()
            }
            0x320 => {
                self.write_lvt_timer(value);
                LapicWriteResult::default()
            }
            0x380 => {
                self.write_initial_count(value);
                LapicWriteResult::default()
            }
            0x3E0 => {
                self.write_divide_config(value);
                LapicWriteResult::default()
            }
            _ => LapicWriteResult::default(),
        }
    }

    /// Parse the ICR low/high registers to produce an IPI action.
    ///
    /// ICR Low bits:
    /// - [7:0]   Vector
    /// - [10:8]  Delivery mode (000=Fixed, 101=INIT, 110=SIPI)
    /// - [11]    Destination mode (0=physical, 1=logical)
    /// - [17:12] Reserved/status
    /// - [19:18] Destination shorthand (00=none, 01=self, 10=all-incl-self, 11=all-excl-self)
    fn parse_icr(&self) -> IpiAction {
        let vector = (self.icr_low & 0xFF) as u8;
        let delivery_mode = (self.icr_low >> 8) & 0x7;
        let dest_shorthand = (self.icr_low >> 18) & 0x3;
        let dest_apic_id = ((self.icr_high >> 24) & 0xFF) as u8;

        // Handle destination shorthand first.
        match dest_shorthand {
            0b01 => {
                // Self: send to own LAPIC (used for self-IPI).
                log::debug!("LAPIC {} ICR: Self IPI vector={:#X}", self.id, vector);
                return IpiAction::SendInterrupt {
                    target_apic_id: self.id,
                    vector,
                };
            }
            0b10 | 0b11 => {
                // All Including Self (0b10) or All Excluding Self (0b11).
                // For fixed delivery, broadcast to all other vCPUs.
                if delivery_mode == 0b000 {
                    log::debug!(
                        "LAPIC {} ICR: Broadcast vector={:#X} (shorthand={})",
                        self.id,
                        vector,
                        if dest_shorthand == 0b10 {
                            "all-incl"
                        } else {
                            "all-excl"
                        }
                    );
                    return IpiAction::BroadcastInterrupt {
                        source_apic_id: self.id,
                        vector,
                    };
                }
                // Non-fixed broadcast (e.g., INIT to all) — fallthrough to per-target.
                // For now, treat as no-op (Linux doesn't broadcast INIT/SIPI with shorthand).
                log::debug!(
                    "LAPIC {} ICR: Broadcast delivery_mode={} (unsupported, ignored)",
                    self.id,
                    delivery_mode
                );
                return IpiAction::None;
            }
            _ => {
                // 0b00: No shorthand — use destination field (normal path).
            }
        }

        match delivery_mode {
            0b000 => {
                // Fixed delivery.
                log::debug!(
                    "LAPIC {} ICR: Fixed interrupt vector={:#X} → APIC {}",
                    self.id,
                    vector,
                    dest_apic_id
                );
                IpiAction::SendInterrupt {
                    target_apic_id: dest_apic_id,
                    vector,
                }
            }
            0b101 => {
                // INIT delivery.
                log::debug!("LAPIC {} ICR: INIT → APIC {}", self.id, dest_apic_id);
                IpiAction::SendInit {
                    target_apic_id: dest_apic_id,
                }
            }
            0b110 => {
                // Startup IPI (SIPI).
                log::debug!(
                    "LAPIC {} ICR: SIPI vector={:#X} → APIC {} (start at {:#X})",
                    self.id,
                    vector,
                    dest_apic_id,
                    (vector as u32) * 0x1000
                );
                IpiAction::SendSipi {
                    target_apic_id: dest_apic_id,
                    vector,
                }
            }
            _ => {
                log::debug!(
                    "LAPIC {} ICR: unsupported delivery mode {} → APIC {}",
                    self.id,
                    delivery_mode,
                    dest_apic_id
                );
                IpiAction::None
            }
        }
    }

    /// Compute Processor Priority Register (PPR).
    ///
    /// PPR = max(TPR, highest ISR priority class) — determines the minimum
    /// priority class that can be delivered.
    fn processor_priority(&self) -> u8 {
        let isr_class = Self::highest_bit(&self.isr).map(|v| v & 0xF0).unwrap_or(0);
        let tpr_class = self.tpr & 0xF0;
        std::cmp::max(isr_class, tpr_class)
    }

    /// Find the highest set bit across an 8-word (256-bit) register.
    /// Returns the bit index (0-255) or None if all zero.
    fn highest_bit(reg: &[u32; 8]) -> Option<u8> {
        for word_idx in (0..8).rev() {
            let word = reg[word_idx];
            if word != 0 {
                let bit = 31 - word.leading_zeros();
                return Some((word_idx as u8) * 32 + bit as u8);
            }
        }
        None
    }

    /// Read the LVT Timer register.
    fn read_lvt_timer(&self) -> u32 {
        let mut val = self.timer_vector as u32;
        if self.timer_masked {
            val |= LVT_MASKED;
        }
        if self.timer_mode == TimerMode::Periodic {
            val |= 1 << 17;
        }
        val
    }

    /// Write the LVT Timer register.
    fn write_lvt_timer(&mut self, value: u32) {
        self.timer_vector = (value & 0xFF) as u8;
        self.timer_masked = value & LVT_MASKED != 0;
        self.timer_mode = if value & (1 << 17) != 0 {
            TimerMode::Periodic
        } else {
            TimerMode::OneShot
        };
    }

    /// Write the Timer Initial Count register.
    fn write_initial_count(&mut self, value: u32) {
        self.timer_initial = value;
        if value == 0 {
            self.timer_deadline = None;
            return;
        }

        // Compute timer period: initial_count * divisor * base_period.
        // Base period is ~100ns (approximation of bus clock period).
        // This gives reasonable timer behavior for Linux's LAPIC timer driver.
        let ticks = value as u64 * self.timer_divisor as u64;
        self.timer_period_ns = ticks * 100; // ~100ns per bus clock tick
        let period = std::time::Duration::from_nanos(self.timer_period_ns);
        self.timer_deadline = Some(Instant::now() + period);
    }

    /// Write the Timer Divide Configuration register.
    fn write_divide_config(&mut self, value: u32) {
        self.timer_divide_reg = value & 0x0B; // Only bits 0,1,3 are used.
                                              // Decode divisor: bits [3,1,0] encode the divisor.
                                              // 0b000=2, 0b001=4, 0b010=8, 0b011=16,
                                              // 0b100=32, 0b101=64, 0b110=128, 0b111=1
        let div_bits = ((value & 0x08) >> 1) | (value & 0x03);
        self.timer_divisor = match div_bits {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            0b111 => 1,
            _ => 2,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lapic_initial_state() {
        let lapic = LocalApic::new();
        assert_eq!(lapic.id, 0);
        assert!(!lapic.is_enabled());
        assert_eq!(lapic.tpr, 0);
        assert!(lapic.timer_masked);
    }

    #[test]
    fn test_lapic_enable_via_svr() {
        let mut lapic = LocalApic::new();
        lapic.write_mmio(0x0F0, SVR_APIC_ENABLE | 0xFF);
        assert!(lapic.is_enabled());
    }

    #[test]
    fn test_lapic_accept_and_get_injectable() {
        let mut lapic = LocalApic::new();

        // Accept vector 0x30.
        lapic.accept_interrupt(0x30);
        assert_eq!(lapic.get_highest_injectable(), Some(0x30));
    }

    #[test]
    fn test_lapic_priority_ordering() {
        let mut lapic = LocalApic::new();

        // Accept vectors 0x30 and 0x50 — 0x50 has higher priority.
        lapic.accept_interrupt(0x30);
        lapic.accept_interrupt(0x50);
        assert_eq!(lapic.get_highest_injectable(), Some(0x50));
    }

    #[test]
    fn test_lapic_isr_blocks_lower_priority() {
        let mut lapic = LocalApic::new();

        // Put vector 0x50 in service.
        lapic.accept_interrupt(0x50);
        lapic.start_of_interrupt(0x50);

        // Accept vector 0x30 — lower priority class, should be blocked.
        lapic.accept_interrupt(0x30);
        assert_eq!(lapic.get_highest_injectable(), None);

        // Accept vector 0x60 — higher priority, should be injectable.
        lapic.accept_interrupt(0x60);
        assert_eq!(lapic.get_highest_injectable(), Some(0x60));
    }

    #[test]
    fn test_lapic_tpr_blocks_low_priority() {
        let mut lapic = LocalApic::new();

        // Set TPR to class 5 (0x50) — blocks vectors 0x00-0x5F.
        lapic.write_mmio(0x080, 0x50);

        lapic.accept_interrupt(0x30);
        assert_eq!(lapic.get_highest_injectable(), None);

        lapic.accept_interrupt(0x60);
        assert_eq!(lapic.get_highest_injectable(), Some(0x60));
    }

    #[test]
    fn test_lapic_start_of_interrupt() {
        let mut lapic = LocalApic::new();

        lapic.accept_interrupt(0x30);
        assert!(lapic.irr[1] & (1 << 16) != 0); // 0x30 = word 1, bit 16

        lapic.start_of_interrupt(0x30);
        assert_eq!(lapic.irr[1] & (1 << 16), 0, "IRR should be cleared");
        assert!(lapic.isr[1] & (1 << 16) != 0, "ISR should be set");
    }

    #[test]
    fn test_lapic_eoi_clears_isr() {
        let mut lapic = LocalApic::new();

        lapic.accept_interrupt(0x30);
        lapic.start_of_interrupt(0x30);

        let vector = lapic.end_of_interrupt();
        assert_eq!(vector, Some(0x30));
        assert_eq!(lapic.isr[1] & (1 << 16), 0, "ISR should be cleared");
    }

    #[test]
    fn test_lapic_eoi_clears_highest_isr() {
        let mut lapic = LocalApic::new();

        // Put two vectors in service.
        lapic.accept_interrupt(0x30);
        lapic.start_of_interrupt(0x30);
        lapic.accept_interrupt(0x50);
        lapic.start_of_interrupt(0x50);

        // EOI clears highest (0x50).
        let vector = lapic.end_of_interrupt();
        assert_eq!(vector, Some(0x50));

        // Next EOI clears 0x30.
        let vector = lapic.end_of_interrupt();
        assert_eq!(vector, Some(0x30));
    }

    #[test]
    fn test_lapic_eoi_empty_isr() {
        let mut lapic = LocalApic::new();
        assert_eq!(lapic.end_of_interrupt(), None);
    }

    #[test]
    fn test_lapic_mmio_read_id() {
        let lapic = LocalApic::new();
        assert_eq!(lapic.read_mmio(0x020), 0); // ID = 0, shifted left 24
    }

    #[test]
    fn test_lapic_mmio_read_version() {
        let lapic = LocalApic::new();
        let version = lapic.read_mmio(0x030);
        assert_eq!(version & 0xFF, 0x14);
    }

    #[test]
    fn test_lapic_mmio_svr_roundtrip() {
        let mut lapic = LocalApic::new();
        lapic.write_mmio(0x0F0, 0x1FF);
        assert_eq!(lapic.read_mmio(0x0F0), 0x1FF);
    }

    #[test]
    fn test_lapic_mmio_tpr_roundtrip() {
        let mut lapic = LocalApic::new();
        lapic.write_mmio(0x080, 0x40);
        assert_eq!(lapic.read_mmio(0x080), 0x40);
    }

    #[test]
    fn test_lapic_mmio_eoi_returns_vector() {
        let mut lapic = LocalApic::new();
        lapic.accept_interrupt(0x30);
        lapic.start_of_interrupt(0x30);

        let result = lapic.write_mmio(0x0B0, 0);
        assert_eq!(result.eoi_vector, Some(0x30));
    }

    #[test]
    fn test_lapic_mmio_isr_read() {
        let mut lapic = LocalApic::new();
        lapic.accept_interrupt(0x30);
        lapic.start_of_interrupt(0x30);

        // 0x30 = word 1 (offset 0x110)
        assert_ne!(lapic.read_mmio(0x110), 0);
        assert_eq!(lapic.read_mmio(0x100), 0); // Word 0 should be empty.
    }

    #[test]
    fn test_lapic_mmio_irr_read() {
        let mut lapic = LocalApic::new();
        lapic.accept_interrupt(0x30);

        // 0x30 = word 1 (offset 0x210)
        assert_ne!(lapic.read_mmio(0x210), 0);
        assert_eq!(lapic.read_mmio(0x200), 0);
    }

    #[test]
    fn test_lapic_lvt_timer_write_read() {
        let mut lapic = LocalApic::new();

        // Set timer: vector=0x20, periodic, unmasked.
        let lvt = 0x20 | (1 << 17); // vector=0x20, periodic
        lapic.write_mmio(0x320, lvt);

        let read = lapic.read_mmio(0x320);
        assert_eq!(read & 0xFF, 0x20);
        assert!(read & (1 << 17) != 0, "periodic bit");
        assert!(read & LVT_MASKED == 0, "should be unmasked");
    }

    #[test]
    fn test_lapic_timer_divide_config() {
        let mut lapic = LocalApic::new();

        // Divisor = 1 (bits [3,1,0] = 0b111 → register value = 0b1011 = 0x0B)
        lapic.write_mmio(0x3E0, 0x0B);
        assert_eq!(lapic.timer_divisor, 1);

        // Divisor = 16 (bits [3,1,0] = 0b011 → register value = 0b0011 = 0x03)
        lapic.write_mmio(0x3E0, 0x03);
        assert_eq!(lapic.timer_divisor, 16);
    }

    #[test]
    fn test_lapic_timer_fires_oneshot() {
        let mut lapic = LocalApic::new();

        // Configure: vector=0x20, oneshot, unmasked, divisor=1
        lapic.write_mmio(0x320, 0x20); // vector=0x20, oneshot, unmasked
        lapic.write_mmio(0x3E0, 0x0B); // divisor=1

        // Set initial count → arms the timer.
        lapic.write_mmio(0x380, 1); // count=1

        // Timer should fire after some time.
        let future = Instant::now() + std::time::Duration::from_millis(100);
        let vector = lapic.tick_timer(future);
        assert_eq!(vector, Some(0x20));

        // Second tick should not fire (oneshot).
        let vector = lapic.tick_timer(future + std::time::Duration::from_millis(100));
        assert_eq!(vector, None);
    }

    #[test]
    fn test_lapic_timer_masked_no_fire() {
        let mut lapic = LocalApic::new();

        // Configure: masked
        lapic.write_mmio(0x320, 0x20 | LVT_MASKED);
        lapic.write_mmio(0x3E0, 0x0B);
        lapic.write_mmio(0x380, 1);

        let future = Instant::now() + std::time::Duration::from_millis(100);
        assert_eq!(lapic.tick_timer(future), None);
    }

    #[test]
    fn test_lapic_timer_zero_count_disarms() {
        let mut lapic = LocalApic::new();

        lapic.write_mmio(0x320, 0x20);
        lapic.write_mmio(0x3E0, 0x0B);
        lapic.write_mmio(0x380, 0); // count=0 disarms

        let future = Instant::now() + std::time::Duration::from_millis(100);
        assert_eq!(lapic.tick_timer(future), None);
    }

    #[test]
    fn test_lapic_highest_bit() {
        let mut reg = [0u32; 8];
        assert_eq!(LocalApic::highest_bit(&reg), None);

        reg[0] = 1; // bit 0
        assert_eq!(LocalApic::highest_bit(&reg), Some(0));

        reg[7] = 1 << 31; // bit 255
        assert_eq!(LocalApic::highest_bit(&reg), Some(255));

        reg[3] = 1 << 16; // bit 112
                          // Highest should still be 255.
        assert_eq!(LocalApic::highest_bit(&reg), Some(255));
    }

    #[test]
    fn test_lapic_processor_priority() {
        let mut lapic = LocalApic::new();

        // No ISR, TPR=0 → PPR=0.
        assert_eq!(lapic.processor_priority(), 0);

        // TPR=0x40 → PPR=0x40.
        lapic.tpr = 0x40;
        assert_eq!(lapic.processor_priority(), 0x40);

        // ISR has 0x50 → PPR=max(0x40, 0x50)=0x50.
        lapic.accept_interrupt(0x50);
        lapic.start_of_interrupt(0x50);
        assert_eq!(lapic.processor_priority(), 0x50);
    }

    #[test]
    fn test_lapic_mmio_invalid_offset() {
        let mut lapic = LocalApic::new();
        assert_eq!(lapic.read_mmio(0x400), 0);
        let result = lapic.write_mmio(0x400, 0xDEAD);
        assert_eq!(result.eoi_vector, None);
        assert_eq!(result.ipi_action, IpiAction::None);
    }

    #[test]
    fn test_lapic_mmio_isr_non_aligned() {
        let lapic = LocalApic::new();
        // Non-16-byte-aligned ISR offset should return 0.
        assert_eq!(lapic.read_mmio(0x104), 0);
    }

    // ---- ICR / IPI tests ----

    #[test]
    fn test_lapic_new_with_id() {
        let lapic = LocalApic::new_with_id(3);
        assert_eq!(lapic.id(), 3);
        assert_eq!(lapic.read_mmio(0x020), 3 << 24);
        assert!(!lapic.is_enabled());
    }

    #[test]
    fn test_lapic_icr_read_write_roundtrip() {
        let mut lapic = LocalApic::new();

        // Write ICR high (destination APIC ID = 1).
        lapic.write_mmio(0x310, 1 << 24);
        assert_eq!(lapic.read_mmio(0x310), 1 << 24);

        // Write ICR low (vector=0x40, Fixed delivery).
        let result = lapic.write_mmio(0x300, 0x40);
        assert_eq!(lapic.read_mmio(0x300), 0x40);

        match result.ipi_action {
            IpiAction::SendInterrupt {
                target_apic_id,
                vector,
            } => {
                assert_eq!(target_apic_id, 1);
                assert_eq!(vector, 0x40);
            }
            other => panic!("expected SendInterrupt, got {:?}", other),
        }
    }

    #[test]
    fn test_lapic_icr_init_delivery() {
        let mut lapic = LocalApic::new();

        // Set destination = APIC 2.
        lapic.write_mmio(0x310, 2 << 24);
        // ICR low: delivery mode = 0b101 (INIT), vector ignored.
        let result = lapic.write_mmio(0x300, 0x0500);

        match result.ipi_action {
            IpiAction::SendInit { target_apic_id } => {
                assert_eq!(target_apic_id, 2);
            }
            other => panic!("expected SendInit, got {:?}", other),
        }
    }

    #[test]
    fn test_lapic_icr_sipi_delivery() {
        let mut lapic = LocalApic::new();

        // Set destination = APIC 1.
        lapic.write_mmio(0x310, 1 << 24);
        // ICR low: delivery mode = 0b110 (SIPI), vector = 0x10.
        // Start address = 0x10 * 0x1000 = 0x10000.
        let result = lapic.write_mmio(0x300, 0x0600 | 0x10);

        match result.ipi_action {
            IpiAction::SendSipi {
                target_apic_id,
                vector,
            } => {
                assert_eq!(target_apic_id, 1);
                assert_eq!(vector, 0x10);
            }
            other => panic!("expected SendSipi, got {:?}", other),
        }
    }

    #[test]
    fn test_lapic_icr_unsupported_delivery_mode() {
        let mut lapic = LocalApic::new();
        lapic.write_mmio(0x310, 1 << 24);
        // Delivery mode = 0b010 (SMI) — not supported.
        let result = lapic.write_mmio(0x300, 0x0200);
        assert_eq!(result.ipi_action, IpiAction::None);
    }

    #[test]
    fn test_lapic_non_icr_write_returns_no_ipi() {
        let mut lapic = LocalApic::new();
        // SVR write should produce no IPI.
        let result = lapic.write_mmio(0x0F0, 0x1FF);
        assert_eq!(result.ipi_action, IpiAction::None);
        assert_eq!(result.eoi_vector, None);
    }

    // ---- SharedApicState tests ----

    #[test]
    fn test_shared_request_interrupt() {
        let shared = SharedApicState::new();
        // Vector 32 → bank 1, bit 0.
        assert!(shared.request_interrupt(32)); // first set → true
        assert!(!shared.request_interrupt(32)); // already set → false
                                                // Vector 33 → bank 1, bit 1.
        assert!(shared.request_interrupt(33)); // different bit → true
    }

    #[test]
    fn test_shared_pull_irr() {
        let shared = SharedApicState::new();
        let mut lapic = LocalApic::new();

        shared.request_interrupt(48); // bank 1, bit 16
        shared.request_interrupt(100); // bank 3, bit 4

        lapic.pull_irr(&shared);

        // After pull, shared should be cleared.
        assert!(shared.request_interrupt(48)); // re-setting returns true (was cleared)

        // LAPIC should now have vector 100 injectable (highest).
        // Enable LAPIC first (SVR bit 8).
        lapic.write_mmio(0x0F0, 0x1FF);
        assert_eq!(lapic.get_highest_injectable(), Some(100));
    }

    #[test]
    fn test_shared_concurrent_ipi() {
        use std::sync::Arc;

        let shared = Arc::new(SharedApicState::new());
        let num_threads = 8;
        // Each thread sets a distinct vector: 32, 33, ..., 39.
        std::thread::scope(|s| {
            for t in 0..num_threads {
                let sh = shared.clone();
                let vector = 32 + t as u8;
                s.spawn(move || {
                    assert!(sh.request_interrupt(vector));
                });
            }
        });

        // Pull all into a LAPIC and verify all vectors present.
        let mut lapic = LocalApic::new();
        lapic.pull_irr(&shared);
        lapic.write_mmio(0x0F0, 0x1FF); // enable
                                        // Highest should be 39.
        assert_eq!(lapic.get_highest_injectable(), Some(39));
    }

    #[test]
    fn test_pull_irr_priority() {
        let shared = SharedApicState::new();
        let mut lapic = LocalApic::new();

        shared.request_interrupt(64); // lower priority
        shared.request_interrupt(200); // higher priority

        lapic.pull_irr(&shared);
        lapic.write_mmio(0x0F0, 0x1FF); // enable
        assert_eq!(lapic.get_highest_injectable(), Some(200));

        // Acknowledge 200, next should be 64.
        lapic.start_of_interrupt(200);
        assert_eq!(lapic.get_highest_injectable(), Some(64));
    }
}
