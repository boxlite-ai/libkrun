//! 8254 PIT (Programmable Interval Timer) emulation.
//!
//! Emulates the three counters of the 8254/8253 PIT at I/O ports 0x40-0x43:
//! - Counter 0 (port 0x40): System timer, connected to PIC IRQ 0.
//! - Counter 1 (port 0x41): DRAM refresh (not emulated, returns 0).
//! - Counter 2 (port 0x42): PC speaker (not emulated, returns 0).
//! - Control word (port 0x43): Mode/command register.
//!
//! The PIT oscillator runs at 1,193,182 Hz. The kernel programs a reload
//! value and the counter counts down; when it reaches zero, it fires IRQ 0
//! and reloads.
//!
//! Only counter 0 modes 2 (rate generator) and 3 (square wave) are emulated,
//! as these are the only modes Linux uses for the system timer.

/// PIT I/O port: Counter 0 data.
pub const PIT_COUNTER0: u16 = 0x40;
/// PIT I/O port: Counter 1 data.
pub const PIT_COUNTER1: u16 = 0x41;
/// PIT I/O port: Counter 2 data.
pub const PIT_COUNTER2: u16 = 0x42;
/// PIT I/O port: Control word register.
pub const PIT_COMMAND: u16 = 0x43;

/// PIT oscillator frequency in Hz.
pub const PIT_FREQUENCY: u64 = 1_193_182;

/// Nanoseconds per PIT tick (approximately 838.1 ns).
/// Calculated as 1_000_000_000 / 1_193_182 ≈ 838.
/// We use fixed-point math in tick() for accuracy.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Counter operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterMode {
    /// Mode 0: Interrupt on terminal count.
    InterruptOnTerminal,
    /// Mode 2: Rate generator (periodic, fires on reload).
    RateGenerator,
    /// Mode 3: Square wave generator (periodic).
    SquareWave,
    /// Other modes (not emulated).
    Other(u8),
}

/// Access mode for reading/writing counter values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessMode {
    /// Low byte only.
    Low,
    /// High byte only.
    High,
    /// Low byte then high byte.
    LoThenHi,
}

/// Read/write state for two-byte access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RwState {
    /// Next byte is the low byte.
    Low,
    /// Next byte is the high byte.
    High,
}

/// State for a single PIT counter.
#[derive(Debug)]
struct PitCounter {
    /// Reload value (what the counter reloads to after reaching zero).
    reload: u16,
    /// Whether the reload value has been fully written.
    reload_ready: bool,
    /// Operating mode.
    mode: CounterMode,
    /// Access mode (lo, hi, or lo-hi byte).
    access: AccessMode,
    /// Write state for two-byte writes.
    write_state: RwState,
    /// Read state for two-byte reads.
    read_state: RwState,
    /// Latched count value (for latch command).
    latched_value: Option<u16>,
    /// Low byte of partial reload write.
    write_low: u8,
    /// Accumulated nanoseconds of elapsed time (for fractional ticks).
    ns_accumulator: u64,
}

impl PitCounter {
    fn new() -> Self {
        PitCounter {
            reload: 0,
            reload_ready: false,
            mode: CounterMode::Other(0),
            access: AccessMode::LoThenHi,
            write_state: RwState::Low,
            read_state: RwState::Low,
            latched_value: None,
            write_low: 0,
            ns_accumulator: 0,
        }
    }

    /// Set the counter mode and access mode from a control word.
    fn set_control(&mut self, mode: CounterMode, access: AccessMode) {
        self.mode = mode;
        self.access = access;
        self.write_state = RwState::Low;
        self.read_state = RwState::Low;
        self.reload_ready = false;
    }

    /// Write a data byte to this counter's data port.
    fn write_data(&mut self, data: u8) {
        match self.access {
            AccessMode::Low => {
                self.reload = data as u16;
                self.reload_ready = true;
                self.ns_accumulator = 0;
            }
            AccessMode::High => {
                self.reload = (data as u16) << 8;
                self.reload_ready = true;
                self.ns_accumulator = 0;
            }
            AccessMode::LoThenHi => match self.write_state {
                RwState::Low => {
                    self.write_low = data;
                    self.write_state = RwState::High;
                }
                RwState::High => {
                    self.reload = self.write_low as u16 | ((data as u16) << 8);
                    self.write_state = RwState::Low;
                    self.reload_ready = true;
                    self.ns_accumulator = 0;
                }
            },
        }
    }

    /// Read a data byte from this counter's data port.
    fn read_data(&mut self) -> u8 {
        let value = self.latched_value.unwrap_or_else(|| self.current_count());

        match self.access {
            AccessMode::Low => {
                self.latched_value = None;
                value as u8
            }
            AccessMode::High => {
                self.latched_value = None;
                (value >> 8) as u8
            }
            AccessMode::LoThenHi => match self.read_state {
                RwState::Low => {
                    self.read_state = RwState::High;
                    value as u8
                }
                RwState::High => {
                    self.read_state = RwState::Low;
                    self.latched_value = None;
                    (value >> 8) as u8
                }
            },
        }
    }

    /// Latch the current count value for reading.
    fn latch(&mut self) {
        if self.latched_value.is_none() {
            self.latched_value = Some(self.current_count());
        }
    }

    /// Effective reload value: 0 means 65536 per 8254 specification.
    ///
    /// In the real 8254 PIT, a reload value of 0 is treated as 65536
    /// (the maximum 16-bit count). This matches BIOS behavior where the
    /// PIT is initialized with reload=0 giving ~18.2 Hz.
    fn effective_reload(&self) -> u64 {
        if self.reload == 0 { 65536 } else { self.reload as u64 }
    }

    /// Compute the current counter value based on accumulated time.
    ///
    /// A real 8254 counts down from the reload value to 0. Software
    /// reads the counter (via latch or direct read) to measure elapsed
    /// time. Without this, counter reads return the static reload value
    /// and Linux calibration loops that poll the counter never terminate.
    fn current_count(&self) -> u16 {
        if !self.reload_ready {
            // Counter not (yet) programmed, or Mode 0 finished (one-shot).
            // Mode 0 after terminal count: counter sits at 0.
            if matches!(self.mode, CounterMode::InterruptOnTerminal) {
                return 0;
            }
            return self.reload;
        }
        let reload = self.effective_reload();
        // How many PIT ticks into the current reload cycle?
        let ticks_in_period =
            (self.ns_accumulator as u128 * PIT_FREQUENCY as u128) / NS_PER_SEC as u128;
        let position = (ticks_in_period as u64) % reload;
        // Counter counts down: reload → 0.
        (reload - position) as u16
    }

    /// Advance the counter by `elapsed_ns` nanoseconds.
    ///
    /// Returns the number of times the counter reached zero (fired).
    fn tick(&mut self, elapsed_ns: u64) -> u64 {
        if !self.reload_ready {
            return 0;
        }

        let reload = self.effective_reload();

        match self.mode {
            CounterMode::RateGenerator | CounterMode::SquareWave => {
                // Accumulate elapsed time.
                self.ns_accumulator += elapsed_ns;

                // Calculate how many PIT ticks have elapsed.
                // ticks = accumulated_ns * PIT_FREQUENCY / NS_PER_SEC
                // To avoid overflow, use u128 for intermediate calculation.
                let total_ticks =
                    (self.ns_accumulator as u128 * PIT_FREQUENCY as u128) / NS_PER_SEC as u128;

                // How many full reload cycles is that?
                let fires = total_ticks / reload as u128;

                // Subtract consumed nanoseconds (keep remainder in accumulator).
                // consumed_ns = fires * reload * NS_PER_SEC / PIT_FREQUENCY
                let consumed_ns =
                    (fires * reload as u128 * NS_PER_SEC as u128) / PIT_FREQUENCY as u128;
                self.ns_accumulator -= consumed_ns as u64;

                fires as u64
            }
            CounterMode::InterruptOnTerminal => {
                // Mode 0: fires once when count reaches zero.
                self.ns_accumulator += elapsed_ns;
                let total_ticks =
                    (self.ns_accumulator as u128 * PIT_FREQUENCY as u128) / NS_PER_SEC as u128;
                if total_ticks >= reload as u128 {
                    self.reload_ready = false; // One-shot: stop after firing.
                    self.ns_accumulator = 0;
                    1
                } else {
                    0
                }
            }
            CounterMode::Other(_) => 0,
        }
    }
}

/// 8254 PIT emulation.
pub struct Pit {
    counters: [PitCounter; 3],
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit {
    /// Create a new PIT with BIOS-compatible default state.
    ///
    /// Counter 0 is pre-programmed in Mode 2 (rate generator) with a
    /// reload value of 0 (= 65536, giving ~18.2 Hz). This matches real
    /// PC behavior where the BIOS initializes the PIT before handing
    /// off to the OS. Without this, timer interrupts won't fire until
    /// the kernel programs the PIT, but the kernel may depend on timer
    /// interrupts *before* it programs the PIT (e.g., jiffies-based
    /// timeouts in early hardware probing).
    pub fn new() -> Self {
        let mut counter0 = PitCounter::new();
        counter0.mode = CounterMode::RateGenerator;
        counter0.reload = 0; // 0 = 65536 per 8254 spec → ~18.2 Hz
        counter0.reload_ready = true;
        Pit {
            counters: [counter0, PitCounter::new(), PitCounter::new()],
        }
    }

    /// Check if the given I/O port belongs to the PIT.
    pub fn handles_port(&self, port: u16) -> bool {
        (PIT_COUNTER0..=PIT_COMMAND).contains(&port)
    }

    /// Write to a PIT I/O port.
    pub fn write_port(&mut self, port: u16, data: u8) {
        match port {
            PIT_COUNTER0 => self.counters[0].write_data(data),
            PIT_COUNTER1 => self.counters[1].write_data(data),
            PIT_COUNTER2 => self.counters[2].write_data(data),
            PIT_COMMAND => self.write_command(data),
            _ => {}
        }
    }

    /// Read from a PIT I/O port.
    pub fn read_port(&mut self, port: u16) -> u8 {
        match port {
            PIT_COUNTER0 => self.counters[0].read_data(),
            PIT_COUNTER1 => self.counters[1].read_data(),
            PIT_COUNTER2 => self.counters[2].read_data(),
            PIT_COMMAND => 0, // Command register is write-only.
            _ => 0,
        }
    }

    /// Advance all counters by `elapsed_ns` nanoseconds.
    ///
    /// Returns the number of times counter 0 fired (should raise IRQ 0
    /// for each fire). Counters 1 and 2 are also ticked so their
    /// `ns_accumulator` stays current — required for `current_count()`
    /// to return meaningful values when Linux reads these counters
    /// (e.g., PIT counter 2 for TSC calibration).
    pub fn tick(&mut self, elapsed_ns: u64) -> u64 {
        let fires = self.counters[0].tick(elapsed_ns);
        self.counters[1].tick(elapsed_ns);
        self.counters[2].tick(elapsed_ns);
        fires
    }

    /// Parse and apply a control word written to port 0x43.
    fn write_command(&mut self, data: u8) {
        let counter_idx = ((data >> 6) & 0x03) as usize;
        let access_bits = (data >> 4) & 0x03;
        let mode_bits = (data >> 1) & 0x07;

        // Counter 3 is invalid (read-back command in 8254, not emulated).
        if counter_idx >= 3 {
            return;
        }

        let access = match access_bits {
            0 => {
                // Latch command: latch the current count.
                self.counters[counter_idx].latch();
                return;
            }
            1 => AccessMode::Low,
            2 => AccessMode::High,
            3 => AccessMode::LoThenHi,
            _ => unreachable!(),
        };

        let mode = match mode_bits {
            0 => CounterMode::InterruptOnTerminal,
            2 | 6 => CounterMode::RateGenerator,
            3 | 7 => CounterMode::SquareWave,
            m => CounterMode::Other(m),
        };

        self.counters[counter_idx].set_control(mode, access);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PitCounter unit tests ----

    #[test]
    fn test_counter_initial_state() {
        let counter = PitCounter::new();
        assert_eq!(counter.reload, 0);
        assert!(!counter.reload_ready);
        assert_eq!(counter.ns_accumulator, 0);
    }

    #[test]
    fn test_counter_tick_not_ready() {
        let mut counter = PitCounter::new();
        assert_eq!(counter.tick(1_000_000), 0, "should not fire when not ready");
    }

    #[test]
    fn test_counter_rate_generator_fires() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::RateGenerator;
        counter.reload = 1193; // ~1000 Hz (1 ms period)
        counter.reload_ready = true;

        // 1 ms = 1_000_000 ns, should fire ~1 time.
        let fires = counter.tick(1_000_000);
        assert_eq!(fires, 1);
    }

    #[test]
    fn test_counter_rate_generator_multiple_fires() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::RateGenerator;
        counter.reload = 1193; // ~1000 Hz
        counter.reload_ready = true;

        // 10 ms = 10_000_000 ns, should fire ~10 times.
        let fires = counter.tick(10_000_000);
        assert!(
            fires >= 9 && fires <= 11,
            "expected ~10 fires, got {}",
            fires
        );
    }

    #[test]
    fn test_counter_accumulates_remainder() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::RateGenerator;
        counter.reload = 11932; // ~100 Hz (~10.0005 ms period)
        counter.reload_ready = true;

        // Tick 5ms — not enough for one full period.
        let fires1 = counter.tick(5_000_000);
        assert_eq!(fires1, 0);

        // Tick another 6ms — total 11ms, should fire once.
        let fires2 = counter.tick(6_000_000);
        assert_eq!(fires2, 1);
    }

    #[test]
    fn test_counter_square_wave_fires() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::SquareWave;
        counter.reload = 1193;
        counter.reload_ready = true;

        let fires = counter.tick(1_000_000);
        assert_eq!(fires, 1);
    }

    #[test]
    fn test_counter_mode0_fires_once() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::InterruptOnTerminal;
        counter.reload = 1193;
        counter.reload_ready = true;

        let fires1 = counter.tick(1_000_000);
        assert_eq!(fires1, 1);

        // Mode 0 is one-shot: should not fire again.
        let fires2 = counter.tick(1_000_000);
        assert_eq!(fires2, 0);
    }

    #[test]
    fn test_counter_zero_reload_means_65536() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::RateGenerator;
        counter.reload = 0; // 0 = 65536 per 8254 spec.
        counter.reload_ready = true;

        // 65536 ticks at 1,193,182 Hz → ~54.9ms period.
        // 100ms should produce ~1 fire.
        let fires = counter.tick(100_000_000);
        assert!(fires >= 1 && fires <= 2, "expected ~1 fire, got {}", fires);
    }

    #[test]
    fn test_counter_write_lo_hi_byte() {
        let mut counter = PitCounter::new();
        counter.access = AccessMode::LoThenHi;
        counter.mode = CounterMode::RateGenerator;

        // Write low byte first, then high byte.
        counter.write_data(0x00); // Low byte.
        assert!(!counter.reload_ready);

        counter.write_data(0x10); // High byte → reload = 0x1000.
        assert!(counter.reload_ready);
        assert_eq!(counter.reload, 0x1000);
    }

    #[test]
    fn test_counter_write_lo_byte_only() {
        let mut counter = PitCounter::new();
        counter.access = AccessMode::Low;
        counter.mode = CounterMode::RateGenerator;

        counter.write_data(0x42);
        assert!(counter.reload_ready);
        assert_eq!(counter.reload, 0x42);
    }

    #[test]
    fn test_counter_write_hi_byte_only() {
        let mut counter = PitCounter::new();
        counter.access = AccessMode::High;
        counter.mode = CounterMode::RateGenerator;

        counter.write_data(0x42);
        assert!(counter.reload_ready);
        assert_eq!(counter.reload, 0x4200);
    }

    #[test]
    fn test_counter_read_lo_hi_byte() {
        let mut counter = PitCounter::new();
        counter.access = AccessMode::LoThenHi;
        counter.reload = 0x1234;

        let lo = counter.read_data();
        assert_eq!(lo, 0x34);

        let hi = counter.read_data();
        assert_eq!(hi, 0x12);
    }

    #[test]
    fn test_counter_latch() {
        let mut counter = PitCounter::new();
        counter.access = AccessMode::LoThenHi;
        counter.reload = 0xABCD;

        counter.latch();
        assert_eq!(counter.latched_value, Some(0xABCD));

        // Read should return latched value.
        let lo = counter.read_data();
        assert_eq!(lo, 0xCD);
        let hi = counter.read_data();
        assert_eq!(hi, 0xAB);

        // Latched value should be consumed.
        assert_eq!(counter.latched_value, None);
    }

    #[test]
    fn test_counter_latch_only_once() {
        let mut counter = PitCounter::new();
        counter.reload = 0x1111;

        counter.latch();
        counter.reload = 0x2222; // Change after latch.
        counter.latch(); // Should NOT overwrite first latch.

        assert_eq!(counter.latched_value, Some(0x1111));
    }

    // ---- Pit (full device) tests ----

    #[test]
    fn test_pit_handles_port() {
        let pit = Pit::new();
        assert!(pit.handles_port(PIT_COUNTER0));
        assert!(pit.handles_port(PIT_COUNTER1));
        assert!(pit.handles_port(PIT_COUNTER2));
        assert!(pit.handles_port(PIT_COMMAND));
        assert!(!pit.handles_port(0x44));
        assert!(!pit.handles_port(0x3F));
    }

    #[test]
    fn test_pit_program_counter0_rate_generator() {
        let mut pit = Pit::new();

        // Program counter 0 in rate generator mode, lo-hi access.
        // Control word: counter=0 (bits 7-6=00), access=lo-hi (bits 5-4=11),
        //               mode=2 (bits 3-1=010), BCD=0 (bit 0=0)
        // = 0b_00_11_010_0 = 0x34
        pit.write_port(PIT_COMMAND, 0x34);

        // Write reload value: 11932 = 0x2E9C (100 Hz, 10ms period).
        pit.write_port(PIT_COUNTER0, 0x9C); // Low byte.
        pit.write_port(PIT_COUNTER0, 0x2E); // High byte.

        assert_eq!(pit.counters[0].reload, 0x2E9C);
        assert!(pit.counters[0].reload_ready);

        // Tick 11ms — one period is ~10.0005ms, so 11ms is enough for one fire.
        let fires = pit.tick(11_000_000);
        assert_eq!(fires, 1);
    }

    #[test]
    fn test_pit_program_counter0_square_wave() {
        let mut pit = Pit::new();

        // Counter 0, lo-hi, mode 3 (square wave), binary.
        // = 0b_00_11_011_0 = 0x36
        pit.write_port(PIT_COMMAND, 0x36);

        // Reload 11932 = ~100 Hz (~10.0005ms period).
        pit.write_port(PIT_COUNTER0, 0x9C);
        pit.write_port(PIT_COUNTER0, 0x2E);

        let fires = pit.tick(11_000_000);
        assert_eq!(fires, 1);
    }

    #[test]
    fn test_pit_latch_command() {
        let mut pit = Pit::new();

        // Program counter 0.
        pit.write_port(PIT_COMMAND, 0x34);
        pit.write_port(PIT_COUNTER0, 0x00);
        pit.write_port(PIT_COUNTER0, 0x10); // reload = 0x1000

        // Latch counter 0: control word with access=00.
        pit.write_port(PIT_COMMAND, 0x00);

        // Read latched value.
        let lo = pit.read_port(PIT_COUNTER0);
        let hi = pit.read_port(PIT_COUNTER0);
        let val = lo as u16 | ((hi as u16) << 8);
        assert_eq!(val, 0x1000);
    }

    #[test]
    fn test_pit_command_register_read_is_zero() {
        let mut pit = Pit::new();
        assert_eq!(pit.read_port(PIT_COMMAND), 0);
    }

    #[test]
    fn test_pit_counter1_counter2_ignored() {
        let mut pit = Pit::new();

        // Programming counters 1 and 2 shouldn't affect tick().
        pit.write_port(PIT_COMMAND, 0x74); // Counter 1, lo-hi, mode 2.
        pit.write_port(PIT_COUNTER1, 0x00);
        pit.write_port(PIT_COUNTER1, 0x01);

        // Tick should only look at counter 0.
        assert_eq!(pit.tick(10_000_000), 0);
    }

    #[test]
    fn test_pit_fires_with_bios_defaults() {
        let mut pit = Pit::new();
        // PIT starts pre-programmed at ~18.2 Hz (reload 0 = 65536).
        // 100ms should produce ~1-2 fires.
        let fires = pit.tick(100_000_000);
        assert!(
            fires >= 1 && fires <= 2,
            "expected ~1-2 fires from BIOS defaults, got {}",
            fires
        );
    }

    #[test]
    fn test_pit_linux_typical_1000hz() {
        let mut pit = Pit::new();

        // Linux HZ=1000 programs PIT with reload = 1193 (≈1ms period).
        pit.write_port(PIT_COMMAND, 0x34);
        pit.write_port(PIT_COUNTER0, (1193 & 0xFF) as u8);
        pit.write_port(PIT_COUNTER0, (1193 >> 8) as u8);

        // 1 second = 1_000_000_000 ns → should fire ~1000 times.
        let fires = pit.tick(1_000_000_000);
        assert!(
            fires >= 998 && fires <= 1002,
            "expected ~1000 fires for HZ=1000, got {}",
            fires
        );
    }

    #[test]
    fn test_pit_linux_typical_100hz() {
        let mut pit = Pit::new();

        // Linux HZ=100 programs PIT with reload = 11932 (≈10ms period).
        pit.write_port(PIT_COMMAND, 0x34);
        pit.write_port(PIT_COUNTER0, (11932 & 0xFF) as u8);
        pit.write_port(PIT_COUNTER0, (11932 >> 8) as u8);

        // 1 second → should fire ~100 times.
        let fires = pit.tick(1_000_000_000);
        assert!(
            fires >= 99 && fires <= 101,
            "expected ~100 fires for HZ=100, got {}",
            fires
        );
    }

    #[test]
    fn test_counter_read_decrements_after_tick() {
        let mut counter = PitCounter::new();
        counter.mode = CounterMode::RateGenerator;
        counter.access = AccessMode::LoThenHi;
        counter.reload = 11932; // ~100 Hz
        counter.reload_ready = true;

        // Initially, count should equal reload (no time elapsed).
        assert_eq!(counter.current_count(), 11932);

        // Tick 5ms — about half a period. Counter should be roughly half.
        counter.tick(5_000_000);
        let count = counter.current_count();
        assert!(
            count < 11932 && count > 0,
            "expected count between 0 and 11932, got {}",
            count
        );
    }

    #[test]
    fn test_counter2_counts_down_for_tsc_calibration() {
        // Linux's pit_calibrate_tsc() programs counter 2 in Mode 0
        // and reads it in a loop expecting the value to decrease.
        let mut pit = Pit::new();

        // Program counter 2: mode 0 (interrupt on terminal), lo-hi.
        // Control word: counter=2 (bits 7-6=10), access=lo-hi (bits 5-4=11),
        //               mode=0 (bits 3-1=000), BCD=0 (bit 0=0)
        // = 0b_10_11_000_0 = 0xB0
        pit.write_port(PIT_COMMAND, 0xB0);
        pit.write_port(PIT_COUNTER2, 0xFF); // Low byte.
        pit.write_port(PIT_COUNTER2, 0xFF); // High byte → reload = 0xFFFF.

        // Tick the PIT (simulating vCPU loop iterations).
        pit.tick(10_000_000); // 10ms

        // Latch counter 2 and read it.
        pit.write_port(PIT_COMMAND, 0x80); // Latch counter 2 (counter=2, access=00).
        let lo = pit.read_port(PIT_COUNTER2);
        let hi = pit.read_port(PIT_COUNTER2);
        let count = lo as u16 | ((hi as u16) << 8);

        // Count should be less than the initial reload value.
        assert!(
            count < 0xFFFF,
            "counter 2 should have decremented, got {:#X}",
            count
        );
    }

    #[test]
    fn test_pit_incremental_ticks() {
        let mut pit = Pit::new();

        // HZ=100: reload = 11932.
        pit.write_port(PIT_COMMAND, 0x34);
        pit.write_port(PIT_COUNTER0, (11932 & 0xFF) as u8);
        pit.write_port(PIT_COUNTER0, (11932 >> 8) as u8);

        // Tick in small increments (1ms each) for 100ms total.
        let mut total_fires = 0u64;
        for _ in 0..100 {
            total_fires += pit.tick(1_000_000);
        }
        // 100ms at HZ=100 → should fire ~10 times.
        assert!(
            total_fires >= 9 && total_fires <= 11,
            "expected ~10 fires over 100ms, got {}",
            total_fires
        );
    }
}
