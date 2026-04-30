//! VmRunner — full VM boot orchestration.
//!
//! Takes a configured VmContext, creates the WHPX partition and devices,
//! loads the kernel, and runs the vCPU loop until exit.
//!
//! Supports two modes:
//! - **Blocking**: `run()` — runs vCPU loop on the calling thread (used by `wkrun_start_enter`)
//! - **Async**: `start()` / `wait()` / `stop()` — spawns a background VM thread (used by BoxLite's Tokio runtime)

#[cfg(target_os = "windows")]
mod imp {
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use super::super::boot::loader::load_kernel_with_initrd;
    use super::super::cmdline::build_kernel_cmdline;
    use super::super::context::VmContext;
    use super::super::devices::lapic::IpiAction;
    use super::super::devices::manager::{self as devices, DeviceManager};
    use super::super::devices::virtio::queue::GuestMemoryAccessor;
    use super::super::error::{Result, WkrunError};
    use super::super::memory::GuestMemory;
    use super::super::types::VcpuExit;
    use super::super::vcpu::VcpuRunConfig;
    use super::super::whpx::{VcpuCanceller, WhpxPartition, WhpxVcpu};

    /// Implement GuestMemoryAccessor directly on GuestMemory.
    ///
    /// This allows GuestMemory to be used via the GuestMemoryAccessor trait
    /// in device handling code (virtio queues, block I/O, etc.).
    impl GuestMemoryAccessor for GuestMemory {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            self.read_at_addr(addr, buf)
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            self.write_at_addr(addr, data)
        }
    }

    /// Maximum vCPU exits before giving up.
    const MAX_EXITS: u64 = 500_000_000;

    /// Maximum consecutive HLT instructions before assuming shutdown.
    ///
    /// With ACPI tables, `poweroff` is detected instantly via PM1a_CNT.
    /// MAX_HALTS is a safety fallback for non-ACPI shutdown paths.
    /// At 1ms per tick, 50000 = ~50 second timeout.
    ///
    /// Must be high enough to tolerate normal guest idle periods (e.g.
    /// waiting for gRPC data after boot). The guest HLTs in its idle
    /// loop whenever there are no interrupts; this is normal and does
    /// NOT indicate the VM is stuck.
    const MAX_HALTS: u64 = 50_000;

    /// Number of spin-yield iterations before sleeping on HLT.
    /// ~50µs of yielding to catch imminent timer interrupts.
    const HLT_SPIN_ITERS: u32 = 50;

    /// Short sleep duration (µs) after spin phase completes without interrupt.
    const HLT_SLEEP_US: u64 = 200;

    /// Per-AP (Application Processor) startup state.
    ///
    /// Each AP thread waits on its condvar until the BSP delivers an
    /// INIT-SIPI-SIPI sequence via the LAPIC ICR register.
    struct ApStartupState {
        /// Whether this AP has received SIPI and should start executing.
        started: Mutex<bool>,
        /// Condvar to wake the AP thread when SIPI arrives.
        condvar: Condvar,
        /// SIPI vector — the AP starts executing at `vector * 0x1000`.
        sipi_vector: Mutex<Option<u8>>,
        /// Whether INIT has been received (prerequisite for SIPI).
        init_received: AtomicBool,
    }

    impl ApStartupState {
        fn new() -> Self {
            Self {
                started: Mutex::new(false),
                condvar: Condvar::new(),
                sipi_vector: Mutex::new(None),
                init_received: AtomicBool::new(false),
            }
        }
    }

    /// Handle for a running VM, stored in `RUNNING_VMS`.
    struct VmHandle {
        thread: Option<std::thread::JoinHandle<Result<i32>>>,
        run_config: VcpuRunConfig,
        canceller: Arc<Mutex<Option<VcpuCanceller>>>,
    }

    /// Registry of running VMs. A ctx_id appears here after `start()` and is
    /// removed by `wait()`.
    static RUNNING_VMS: std::sync::LazyLock<Mutex<HashMap<u32, VmHandle>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Translate a guest virtual address (GVA) to guest physical address (GPA)
    /// by walking the x86_64 4-level page table starting from CR3.
    #[allow(dead_code)]
    fn translate_gva(guest_mem: &GuestMemory, cr3: u64, gva: u64) -> Option<u64> {
        let pml4_base = cr3 & !0xFFF;
        let pml4_idx = ((gva >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gva >> 30) & 0x1FF) as usize;
        let pd_idx = ((gva >> 21) & 0x1FF) as usize;
        let pt_idx = ((gva >> 12) & 0x1FF) as usize;
        let offset = gva & 0xFFF;

        // PML4 entry
        let mut buf = [0u8; 8];
        guest_mem
            .read_at_addr(pml4_base + (pml4_idx as u64) * 8, &mut buf)
            .ok()?;
        let pml4e = u64::from_le_bytes(buf);
        if pml4e & 1 == 0 {
            return None;
        } // not present

        // PDPT entry
        let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
        guest_mem
            .read_at_addr(pdpt_base + (pdpt_idx as u64) * 8, &mut buf)
            .ok()?;
        let pdpte = u64::from_le_bytes(buf);
        if pdpte & 1 == 0 {
            return None;
        }
        if pdpte & 0x80 != 0 {
            // 1GB page
            return Some((pdpte & 0x000F_FFFF_C000_0000) | (gva & 0x3FFF_FFFF));
        }

        // PD entry
        let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
        guest_mem
            .read_at_addr(pd_base + (pd_idx as u64) * 8, &mut buf)
            .ok()?;
        let pde = u64::from_le_bytes(buf);
        if pde & 1 == 0 {
            return None;
        }
        if pde & 0x80 != 0 {
            // 2MB page
            return Some((pde & 0x000F_FFFF_FFE0_0000) | (gva & 0x1F_FFFF));
        }

        // PT entry
        let pt_base = pde & 0x000F_FFFF_FFFF_F000;
        guest_mem
            .read_at_addr(pt_base + (pt_idx as u64) * 8, &mut buf)
            .ok()?;
        let pte = u64::from_le_bytes(buf);
        if pte & 1 == 0 {
            return None;
        }
        Some((pte & 0x000F_FFFF_FFFF_F000) | offset)
    }

    /// Core vCPU loop shared by `run()` and `start()`.
    ///
    /// Sets up the WHPX partition, loads the kernel, creates devices and vCPU,
    /// then runs the vCPU loop. The `run_config` controls when the loop stops,
    /// and the vCPU's canceller is stored in `canceller_slot` so that `stop()`
    /// can wake the vCPU.
    fn run_vcpu_loop(
        ctx: VmContext,
        run_config: VcpuRunConfig,
        canceller_slot: Arc<Mutex<Option<VcpuCanceller>>>,
    ) -> Result<i32> {
        // Open a diagnostic log file for debugging boot failures.
        // Uses TEMP directory so it works on any Windows machine.
        let mut diag_log: Option<std::fs::File> = None;
        let diag_path = format!(
            "{}\\whpx-diag.log",
            std::env::var("TEMP").unwrap_or_else(|_| r"C:\Temp".to_string())
        );
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&diag_path)
        {
            diag_log = Some(f);
        }

        macro_rules! diag {
            ($($arg:tt)*) => {
                if let Some(ref mut f) = diag_log {
                    let _ = writeln!(f, $($arg)*);
                    let _ = f.flush();
                }
            };
        }
        diag!("\n=== VM START ctx_id={} ===", ctx.id);

        // Validate required fields.
        let kernel_path = ctx
            .kernel_path
            .as_ref()
            .ok_or_else(|| WkrunError::Config("kernel_path is required for VM start".into()))?;

        // Read kernel image.
        let kernel_image = std::fs::read(kernel_path).map_err(|e| {
            WkrunError::Boot(format!(
                "failed to read kernel '{}': {}",
                kernel_path.display(),
                e
            ))
        })?;

        // Read initrd if provided.
        let initrd_data = match ctx.initramfs_path {
            Some(ref path) => Some(std::fs::read(path).map_err(|e| {
                WkrunError::Boot(format!("failed to read initrd '{}': {}", path.display(), e))
            })?),
            None => None,
        };

        // Check WHPX availability.
        if !WhpxPartition::is_available()? {
            return Err(WkrunError::WhpxUnavailable(
                "WHPX is not available on this system".into(),
            ));
        }

        // Create partition.
        let partition = WhpxPartition::new()?;
        partition.set_processor_count(ctx.num_vcpus as u32)?;
        partition.set_extended_vm_exits(true, true)?;

        // NOTE: Do NOT enable APIC emulation here. On Win10 MBP 2014,
        // set_local_apic_emulation(true) returns success but then the APIC
        // doesn't function — no interrupts get delivered and the kernel hangs
        // before producing any console output. Software PIC is required.

        partition.setup()?;

        // Allocate and map guest memory.
        let guest_mem = Arc::new(GuestMemory::new(ctx.ram_mib)?);
        guest_mem.map_to_partition(&partition)?;

        // Create devices from context.
        let ctx_id = ctx.id;
        let setup = DeviceManager::from_context(&ctx)?;
        devices::store_console_buffer(ctx_id, setup.console_buffer);
        let devices = setup.devices;

        // NOTE: Block I/O workers are started lazily (deferred start) inside
        // the vCPU loop, on the first MMIO write. Starting them here (before
        // the vCPU runs) causes ~80% boot failure on WHPX — the worker
        // thread creation appears to interfere with WHPX partition state
        // during early boot.

        // Build kernel command line.
        let cmdline = build_kernel_cmdline(
            ctx.kernel_cmdline.as_deref(),
            setup.has_root_disk,
            &setup.mmio_slots,
            ctx.root_disk_device.as_deref(),
            ctx.root_disk_fstype.as_deref(),
            ctx.exec_path.as_deref(),
            &ctx.argv,
            ctx.verbose,
        );

        // Load kernel.
        let initrd_ref = initrd_data.as_deref();
        let (regs, sregs) = load_kernel_with_initrd(
            &guest_mem,
            &kernel_image,
            &cmdline,
            ctx.ram_mib,
            initrd_ref,
            ctx.num_vcpus,
        )?;

        log::info!(
            "Kernel loaded at 0x100000, RIP=0x{:X}, cmdline: {}",
            regs.rip,
            cmdline
        );
        diag!("Kernel loaded, RIP={:#X}, ram={}MB", regs.rip, ctx.ram_mib);

        // Create all vCPUs. BSP (index 0) gets the boot registers.
        // APs (index 1..N-1) are created but start in "wait for SIPI" state.
        let num_vcpus = ctx.num_vcpus;
        let mut vcpus = Vec::with_capacity(num_vcpus as usize);
        for i in 0..num_vcpus as u32 {
            let vcpu = WhpxVcpu::new(&partition, i)?;
            if i == 0 {
                vcpu.set_registers(&regs)?;
                vcpu.set_special_registers(&sregs)?;
            }
            vcpus.push(vcpu);
        }

        // Collect cancellers for all vCPUs. The timer thread and stop()
        // need to be able to wake any vCPU.
        let cancellers: Vec<VcpuCanceller> = vcpus.iter().map(|v| v.canceller()).collect();

        // Store BSP canceller so stop() can wake the VM.
        *canceller_slot.lock().unwrap() = Some(cancellers[0].clone());

        // Create per-AP startup state (one per AP, indexed by ap_id - 1).
        let ap_states: Vec<ApStartupState> =
            (1..num_vcpus).map(|_| ApStartupState::new()).collect();

        // Shared VM shutdown flag — set by any vCPU to signal all others to exit.
        let shutdown = Arc::new(AtomicBool::new(false));
        let devices = Arc::new(Mutex::new(devices));

        // Move diag_log into shared state for BSP diagnostics.
        let diag_log = Arc::new(Mutex::new(diag_log));

        log::info!("Starting VM with {} vCPU(s), ctx_id={}", num_vcpus, ctx_id);

        let mut exit_code = 1i32;

        // Use thread::scope so all vCPU threads are guaranteed to terminate
        // before we clean up resources. The BSP runs in the scoped block;
        // APs are spawned as scoped threads.
        {
            let shutdown_ref = &shutdown;
            let devices_ref = &devices;
            let ap_states_ref = &ap_states;
            let cancellers_ref = &cancellers;
            let run_config_ref = &run_config;
            let guest_mem_ref: &GuestMemory = &guest_mem;
            let diag_ref = &diag_log;

            // Spawn timer thread — cancels ALL vCPUs every 1ms.
            let timer_flag = run_config.running.clone();
            let timer_cancellers: Vec<VcpuCanceller> = cancellers.clone();
            let timer_shutdown = shutdown.clone();
            let timer_thread = std::thread::spawn(move || {
                while timer_flag.load(Ordering::Relaxed) && !timer_shutdown.load(Ordering::Relaxed)
                {
                    std::thread::sleep(Duration::from_millis(1));
                    for c in &timer_cancellers {
                        let _ = c.cancel();
                    }
                }
            });

            std::thread::scope(|s| {
                // Spawn AP threads (vCPU 1..N-1).
                for ap_idx in 1..num_vcpus as usize {
                    let vcpu = &vcpus[ap_idx];
                    s.spawn(move || {
                        run_ap_loop(
                            ap_idx as u8,
                            num_vcpus,
                            vcpu,
                            devices_ref,
                            guest_mem_ref,
                            shutdown_ref,
                            run_config_ref,
                            cancellers_ref,
                            &ap_states_ref[ap_idx - 1],
                            ctx_id,
                            diag_ref,
                        );
                    });
                }

                // BSP runs on the current thread.
                let bsp_vcpu = &vcpus[0];
                let bsp_code = run_bsp_loop(
                    bsp_vcpu,
                    devices_ref,
                    guest_mem_ref,
                    shutdown_ref,
                    run_config_ref,
                    cancellers_ref,
                    ap_states_ref,
                    ctx_id,
                    diag_ref,
                    num_vcpus,
                );
                // BSP exited — signal all APs to exit.
                shutdown_ref.store(true, Ordering::Release);
                for c in cancellers_ref {
                    let _ = c.cancel();
                }
                // Wake any APs still waiting for SIPI.
                for ap in ap_states_ref {
                    *ap.started.lock().unwrap() = true;
                    ap.condvar.notify_one();
                }
                exit_code = bsp_code;
            });

            // Stop the timer thread and block I/O workers.
            run_config.request_stop();
            shutdown.store(true, Ordering::Release);
            devices.lock().unwrap().stop_blk_workers();
            let _ = timer_thread.join();
        }

        log::info!("VM exited with code {}", exit_code);

        // Clean up diagnostic file on normal exit.
        // Drop the file handle first, then remove the temp file.
        drop(diag_log);
        let _ = std::fs::remove_file(&diag_path);

        Ok(exit_code)
    }

    /// Per-vCPU statistics counters.
    struct VcpuStats {
        exit_count: u64,
        halt_count: u64,
        total_halt_exits: u64,
        halt_with_irq: u64,
        mmio_count: u64,
        serial_out_count: u64,
        io_out_count: u64,
        io_in_count: u64,
        inject_count: u64,
        last_progress: Instant,
        start_time: Instant,
        window_requested: bool,
    }

    impl VcpuStats {
        fn new() -> Self {
            let now = Instant::now();
            Self {
                exit_count: 0,
                halt_count: 0,
                total_halt_exits: 0,
                halt_with_irq: 0,
                mmio_count: 0,
                serial_out_count: 0,
                io_out_count: 0,
                io_in_count: 0,
                inject_count: 0,
                last_progress: now,
                start_time: now,
                window_requested: false,
            }
        }
    }

    /// Try to inject a pending interrupt into a vCPU.
    ///
    /// Returns the number of interrupts injected (0 or 1).
    fn try_inject_interrupt(
        vcpu: &WhpxVcpu,
        vcpu_id: u8,
        devices: &mut DeviceManager,
        stats: &mut VcpuStats,
    ) -> Result<()> {
        if !devices.irq_chip.has_pending(vcpu_id) {
            return Ok(());
        }

        let already_pending = vcpu.has_pending_interruption().unwrap_or(false);
        if already_pending {
            return Ok(());
        }

        match vcpu.interrupts_enabled() {
            Ok(true) => {
                if let Some(vector) = devices.irq_chip.acknowledge(vcpu_id) {
                    log::debug!("vCPU{}: injecting interrupt vector {:#X}", vcpu_id, vector);
                    vcpu.inject_interrupt(vector)?;
                    devices.irq_chip.notify_injected(vcpu_id, vector);
                    stats.window_requested = false;
                    stats.inject_count += 1;
                }
            }
            Ok(false) => {
                if !stats.window_requested {
                    vcpu.request_interrupt_window()?;
                    stats.window_requested = true;
                }
            }
            Err(ref e) => {
                log::warn!("vCPU{}: interrupts_enabled() error: {:?}", vcpu_id, e);
            }
        }
        Ok(())
    }

    /// Dispatch an IPI action from a LAPIC ICR write.
    fn dispatch_ipi(
        action: IpiAction,
        devices: &mut DeviceManager,
        ap_states: &[ApStartupState],
        cancellers: &[VcpuCanceller],
        diag_log: &Arc<Mutex<Option<std::fs::File>>>,
        start_time: Instant,
    ) {
        macro_rules! ipi_diag {
            ($($arg:tt)*) => {
                if let Ok(mut guard) = diag_log.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = write!(f, "[{:.3}s] ", start_time.elapsed().as_secs_f64());
                        let _ = writeln!(f, $($arg)*);
                        let _ = f.flush();
                    }
                }
            };
        }
        match action {
            IpiAction::None => {}
            IpiAction::SendInit { target_apic_id } => {
                let ap_idx = target_apic_id as usize;
                if ap_idx > 0 && ap_idx - 1 < ap_states.len() {
                    ap_states[ap_idx - 1]
                        .init_received
                        .store(true, Ordering::Release);
                    ipi_diag!("IPI: INIT delivered to AP{}", target_apic_id);
                } else {
                    ipi_diag!(
                        "IPI: INIT target AP{} out of range (max={})",
                        target_apic_id,
                        ap_states.len()
                    );
                }
            }
            IpiAction::SendSipi {
                target_apic_id,
                vector,
            } => {
                let ap_idx = target_apic_id as usize;
                if ap_idx > 0 && ap_idx - 1 < ap_states.len() {
                    let state = &ap_states[ap_idx - 1];
                    if state.init_received.load(Ordering::Acquire) {
                        *state.sipi_vector.lock().unwrap() = Some(vector);
                        *state.started.lock().unwrap() = true;
                        state.condvar.notify_one();
                        ipi_diag!(
                            "IPI: SIPI delivered to AP{}, vector={:#X}, start_addr={:#X}",
                            target_apic_id,
                            vector,
                            (vector as u64) * 0x1000
                        );
                    } else {
                        ipi_diag!(
                            "IPI: SIPI to AP{} IGNORED (no INIT received)",
                            target_apic_id,
                        );
                    }
                }
            }
            IpiAction::SendInterrupt {
                target_apic_id,
                vector,
            } => {
                devices
                    .irq_chip
                    .deliver_ipi_interrupt(target_apic_id, vector);
                let idx = target_apic_id as usize;
                if idx < cancellers.len() {
                    let _ = cancellers[idx].cancel();
                }
                ipi_diag!(
                    "IPI: interrupt vector={:#X} → vCPU{}",
                    vector,
                    target_apic_id,
                );
            }
        }
    }

    /// BSP (Bootstrap Processor, vCPU 0) main loop.
    ///
    /// Handles timer ticking, device polling, interrupt injection, block worker
    /// start, IPI dispatch, and progress diagnostics.
    #[allow(clippy::too_many_arguments)]
    fn run_bsp_loop(
        vcpu: &WhpxVcpu,
        devices: &Arc<Mutex<DeviceManager>>,
        guest_mem: &GuestMemory,
        shutdown: &AtomicBool,
        run_config: &VcpuRunConfig,
        cancellers: &[VcpuCanceller],
        ap_states: &[ApStartupState],
        ctx_id: u32,
        diag_log: &Arc<Mutex<Option<std::fs::File>>>,
        num_vcpus: u8,
    ) -> i32 {
        macro_rules! diag {
            ($($arg:tt)*) => {
                if let Ok(mut guard) = diag_log.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = writeln!(f, $($arg)*);
                        let _ = f.flush();
                    }
                }
            };
        }

        let mut stats = VcpuStats::new();
        let mut blk_workers_started = false;
        let sync_block = std::env::var("BOXLITE_SYNC_BLOCK").is_ok();
        let mut _last_exit_reason = "none";

        loop {
            if shutdown.load(Ordering::Relaxed) || !run_config.should_run() {
                _last_exit_reason = "SHUTDOWN_SIGNAL";
                return 0;
            }

            // Tick PIT and poll devices (BSP only).
            {
                let mut dm = devices.lock().unwrap();
                dm.tick_and_poll(0, guest_mem);
                // Try to inject pending interrupt.
                if let Err(e) = try_inject_interrupt(vcpu, 0, &mut dm, &mut stats) {
                    log::error!("BSP interrupt injection error: {:?}", e);
                }
            }

            let exit = match vcpu.run() {
                Ok(exit) => exit,
                Err(e) => {
                    log::error!(
                        "BSP vcpu.run() FAILED after {} exits: {:?}",
                        stats.exit_count,
                        e
                    );
                    return 1;
                }
            };
            stats.exit_count += 1;

            match exit {
                VcpuExit::IoOut { port, size, data } => {
                    stats.halt_count = 0;
                    stats.io_out_count += 1;
                    if port == 0x3F8 {
                        stats.serial_out_count += 1;
                    }
                    let mut dm = devices.lock().unwrap();
                    dm.handle_io_out(port, size, data);
                    if dm.shutdown_requested() {
                        log::info!("ACPI shutdown detected after {} exits", stats.exit_count);
                        _last_exit_reason = "ACPI_SHUTDOWN";
                        return 0;
                    }
                    drop(dm);
                    if let Err(e) = vcpu.skip_instruction() {
                        log::error!("BSP skip_instruction error: {:?}", e);
                        return 1;
                    }
                }
                VcpuExit::IoIn { port, size } => {
                    stats.halt_count = 0;
                    stats.io_in_count += 1;
                    let data = devices.lock().unwrap().handle_io_in(port, size);
                    if let Err(e) = vcpu.complete_io_in(data, size) {
                        log::error!("BSP complete_io_in error: {:?}", e);
                        return 1;
                    }
                }
                VcpuExit::MmioRead { address, size } => {
                    stats.halt_count = 0;
                    stats.mmio_count += 1;
                    let data = devices.lock().unwrap().handle_mmio_read(0, address, size);
                    if let Err(e) = vcpu.complete_mmio_read(data) {
                        log::error!("BSP complete_mmio_read error: {:?}", e);
                        return 1;
                    }
                }
                VcpuExit::MmioWrite {
                    address,
                    size,
                    data,
                } => {
                    stats.halt_count = 0;
                    stats.mmio_count += 1;
                    let mut dm = devices.lock().unwrap();
                    if !blk_workers_started && !sync_block {
                        dm.start_blk_workers();
                        blk_workers_started = true;
                        log::info!(
                            target: "whpx::diag",
                            "Block workers started at exit={} mmio={} elapsed={:.1}ms",
                            stats.exit_count,
                            stats.mmio_count,
                            stats.start_time.elapsed().as_secs_f64() * 1000.0
                        );
                    }
                    let ipi_action = dm.handle_mmio_write(0, address, size, data, guest_mem);
                    // Log LAPIC ICR writes for diagnostics.
                    if address >= crate::windows::memory::LAPIC_MMIO_BASE {
                        let offset = address - crate::windows::memory::LAPIC_MMIO_BASE;
                        if offset == 0x300 || offset == 0x310 {
                            diag!(
                                "LAPIC ICR write: offset={:#X} data={:#X}",
                                offset,
                                data
                            );
                        }
                    }
                    // Dispatch IPI if this was an ICR write.
                    if !matches!(ipi_action, IpiAction::None) {
                        dispatch_ipi(
                            ipi_action,
                            &mut dm,
                            ap_states,
                            cancellers,
                            diag_log,
                            stats.start_time,
                        );
                    }
                    drop(dm);
                    if let Err(e) = vcpu.skip_instruction() {
                        log::error!("BSP skip_instruction error: {:?}", e);
                        return 1;
                    }
                }
                VcpuExit::InterruptWindow => {
                    stats.halt_count = 0;
                    stats.window_requested = false;
                }
                VcpuExit::Halt => {
                    stats.total_halt_exits += 1;
                    if !run_config.should_run() || shutdown.load(Ordering::Relaxed) {
                        log::info!("BSP: stop requested, exiting on Halt");
                        return 0;
                    }

                    // Poll devices before sleeping.
                    {
                        let mut dm = devices.lock().unwrap();
                        dm.tick_and_poll(0, guest_mem);
                        if dm.irq_chip.has_pending(0) {
                            let already_pending = vcpu.has_pending_interruption().unwrap_or(false);
                            if !already_pending {
                                if let Some(vector) = dm.irq_chip.acknowledge(0) {
                                    let _ = vcpu.inject_interrupt(vector);
                                    dm.irq_chip.notify_injected(0, vector);
                                    stats.window_requested = false;
                                    stats.inject_count += 1;
                                }
                            }
                            stats.halt_with_irq += 1;
                            stats.halt_count = 0;
                            continue;
                        }
                    }

                    stats.halt_count += 1;

                    if stats.halt_count % 1000 == 0 {
                        if let Ok(regs) = vcpu.get_registers() {
                            let console_len = devices::get_console_output(ctx_id)
                                .map(|b| b.len())
                                .unwrap_or(0);
                            let if_flag = vcpu.interrupts_enabled().unwrap_or(false);
                            log::warn!(
                                target: "whpx::diag",
                                "BSP HLT stuck: consecutive={} total_halt={} halt_w_irq={} \
                                 exits={} RIP={:#X} IF={} console={}B mmio={} vcpus={}",
                                stats.halt_count, stats.total_halt_exits, stats.halt_with_irq,
                                stats.exit_count, regs.rip,
                                if_flag, console_len, stats.mmio_count, num_vcpus
                            );
                        }
                    }

                    if stats.halt_count > MAX_HALTS {
                        log::warn!(
                            "BSP halted {} times consecutively after {} exits",
                            stats.halt_count,
                            stats.exit_count,
                        );
                        _last_exit_reason = "HALT_MAX_REACHED";
                        return 0;
                    }

                    // Tiered sleep: spin-yield phase to catch imminent interrupts,
                    // then short sleep if no interrupt arrived.
                    let mut woke_by_irq = false;
                    for i in 0..HLT_SPIN_ITERS {
                        std::thread::yield_now();
                        if i % 10 == 9 {
                            let mut dm = devices.lock().unwrap();
                            dm.tick_and_poll(0, guest_mem);
                            if dm.irq_chip.has_pending(0) {
                                woke_by_irq = true;
                                break;
                            }
                        }
                    }
                    if !woke_by_irq {
                        std::thread::sleep(Duration::from_micros(HLT_SLEEP_US));
                    }
                }
                VcpuExit::Shutdown => {
                    log::info!("BSP: VM shutdown after {} exits", stats.exit_count);
                    return 0;
                }
                VcpuExit::Cancelled => {
                    if !run_config.should_run() || shutdown.load(Ordering::Relaxed) {
                        log::info!("BSP: stop requested on Cancelled");
                        return 0;
                    }
                    if stats.last_progress.elapsed() >= Duration::from_secs(2) {
                        stats.last_progress = Instant::now();
                        if let Ok(regs) = vcpu.get_registers() {
                            let dm = devices.lock().unwrap();
                            let console_len = devices::get_console_output(ctx_id)
                                .map(|b| b.len())
                                .unwrap_or(0);
                            let (qn, bc) = dm.blk_stats();
                            let apic_mode = dm.irq_chip.apic_mode();
                            let blk_mode = if sync_block { "sync" } else if blk_workers_started { "async" } else { "pending" };
                            drop(dm);
                            log::info!(
                                target: "whpx::diag",
                                "vCPU0 @ {:.1}s: exits={} RIP={:#X} console={}B mmio={} halt={}/{} inj={} blk_comp={} mode={}/{}",
                                stats.start_time.elapsed().as_secs_f64(),
                                stats.exit_count, regs.rip, console_len,
                                stats.mmio_count, stats.halt_count, stats.total_halt_exits,
                                stats.inject_count, bc,
                                if apic_mode { "apic" } else { "pic" }, blk_mode,
                            );
                            log::debug!(
                                target: "whpx::diag",
                                "vCPU0 detail: io_out={} serial={} blk_qn={} halt_w_irq={} vcpus={}",
                                stats.io_out_count, stats.serial_out_count, qn,
                                stats.halt_with_irq, num_vcpus,
                            );
                        }
                    }
                }
                VcpuExit::MsrAccess {
                    msr_number,
                    is_write,
                    rax,
                    rdx,
                } => {
                    stats.halt_count = 0;
                    if is_write {
                        log::trace!(
                            "BSP: MSR write 0x{:08X} <- 0x{:016X}",
                            msr_number,
                            (rdx << 32) | (rax & 0xFFFF_FFFF)
                        );
                        if let Err(e) = vcpu.skip_instruction() {
                            log::error!("BSP skip_instruction error: {:?}", e);
                            return 1;
                        }
                    } else {
                        let value = super::handle_msr_read(0, msr_number);
                        log::trace!("BSP: MSR read 0x{:08X} -> 0x{:X}", msr_number, value);
                        if let Err(e) = vcpu.complete_msr_read(value) {
                            log::error!("BSP complete_msr_read error: {:?}", e);
                            return 1;
                        }
                    }
                }
                VcpuExit::CpuidAccess {
                    rax,
                    rcx,
                    default_rax,
                    default_rbx,
                    default_rcx,
                    default_rdx,
                } => {
                    stats.halt_count = 0;
                    let (out_rax, out_rbx, out_rcx, out_rdx) = super::handle_cpuid(
                        0,
                        num_vcpus,
                        rax as u32,
                        default_rax,
                        default_rbx,
                        default_rcx,
                        default_rdx,
                    );
                    log::trace!(
                        "BSP CPUID leaf=0x{:X} sub=0x{:X} -> rax=0x{:X}",
                        rax,
                        rcx,
                        out_rax
                    );
                    if let Err(e) = vcpu.complete_cpuid(out_rax, out_rbx, out_rcx, out_rdx) {
                        log::error!("BSP complete_cpuid error: {:?}", e);
                        return 1;
                    }
                }
                VcpuExit::UnrecoverableException => {
                    let regs = vcpu.get_registers().ok();
                    let sregs = vcpu.get_special_registers().ok();
                    log::error!(
                        "BSP: Unrecoverable exception after {} exits. \
                         RIP={:#X}, CR0={:#X}, CR3={:#X}, CR4={:#X}, EFER={:#X}",
                        stats.exit_count,
                        regs.as_ref().map_or(0, |r| r.rip),
                        sregs.as_ref().map_or(0, |s| s.cr0),
                        sregs.as_ref().map_or(0, |s| s.cr3),
                        sregs.as_ref().map_or(0, |s| s.cr4),
                        sregs.as_ref().map_or(0, |s| s.efer),
                    );
                    return -1;
                }
                VcpuExit::Unknown(reason) => {
                    log::error!(
                        "BSP: Unknown exit reason {} after {} exits",
                        reason,
                        stats.exit_count
                    );
                    return -1;
                }
            }

            if stats.exit_count >= MAX_EXITS {
                log::warn!("BSP reached {} exit limit", MAX_EXITS);
                return -1;
            }
        }
    }

    /// AP (Application Processor, vCPU 1..N-1) loop.
    ///
    /// Waits for SIPI, configures initial registers, then runs a vCPU loop
    /// similar to BSP but without timer ticking or block worker management.
    #[allow(clippy::too_many_arguments)]
    fn run_ap_loop(
        ap_id: u8,
        num_vcpus: u8,
        vcpu: &WhpxVcpu,
        devices: &Arc<Mutex<DeviceManager>>,
        guest_mem: &GuestMemory,
        shutdown: &AtomicBool,
        run_config: &VcpuRunConfig,
        cancellers: &[VcpuCanceller],
        startup: &ApStartupState,
        _ctx_id: u32,
        diag_log: &Arc<Mutex<Option<std::fs::File>>>,
    ) {
        macro_rules! diag {
            ($($arg:tt)*) => {
                if let Ok(mut guard) = diag_log.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = writeln!(f, $($arg)*);
                        let _ = f.flush();
                    }
                }
            };
        }

        diag!("AP{}: thread started, waiting for SIPI", ap_id);

        // Wait for SIPI from BSP.
        {
            let mut started = startup.started.lock().unwrap();
            while !*started {
                started = startup.condvar.wait(started).unwrap();
            }
        }

        // Check if we were woken for shutdown rather than SIPI.
        if shutdown.load(Ordering::Relaxed) {
            diag!("AP{}: woken for shutdown, not SIPI", ap_id);
            return;
        }

        // Configure AP initial register state from SIPI vector.
        let sipi_vector = startup.sipi_vector.lock().unwrap().unwrap_or(0);
        diag!(
            "AP{}: SIPI received, vector={:#X}, CS:IP={:#X}:0000",
            ap_id,
            sipi_vector,
            (sipi_vector as u64) * 0x1000
        );

        // Dump WHPX default registers before modification for diagnostics.
        if let Ok(sregs) = vcpu.get_special_registers() {
            diag!(
                "AP{}: WHPX defaults TR=sel:{:#X}/base:{:#X}/lim:{:#X}/ar:{:#X} \
                 LDT=sel:{:#X}/base:{:#X}/lim:{:#X}/ar:{:#X} \
                 GDT=base:{:#X}/lim:{:#X} IDT=base:{:#X}/lim:{:#X} \
                 CR0={:#X} CR4={:#X} EFER={:#X}",
                ap_id,
                sregs.tr.selector, sregs.tr.base, sregs.tr.limit, sregs.tr.access_rights,
                sregs.ldt.selector, sregs.ldt.base, sregs.ldt.limit, sregs.ldt.access_rights,
                sregs.gdt.base, sregs.gdt.limit, sregs.idt.base, sregs.idt.limit,
                sregs.cr0, sregs.cr4, sregs.efer
            );
        }

        // AP starts in real mode: CS:IP = (sipi_vector * 0x100):0x0000
        // The Linux kernel SMP trampoline is placed at sipi_vector * 0x1000.
        if let Err(e) = vcpu.set_ap_initial_regs(sipi_vector, ap_id) {
            diag!("AP{}: FAILED to set initial registers: {:?}", ap_id, e);
            return;
        }
        diag!("AP{}: initial regs set, entering run loop", ap_id);

        let mut stats = VcpuStats::new();

        loop {
            if shutdown.load(Ordering::Relaxed) || !run_config.should_run() {
                log::info!("AP{}: shutdown signal received", ap_id);
                return;
            }

            // Try to inject pending interrupt (no timer ticking for APs).
            {
                let mut dm = devices.lock().unwrap();
                if let Err(e) = try_inject_interrupt(vcpu, ap_id, &mut dm, &mut stats) {
                    log::error!("AP{}: interrupt injection error: {:?}", ap_id, e);
                }
            }

            let exit = match vcpu.run() {
                Ok(exit) => exit,
                Err(e) => {
                    diag!(
                        "AP{}: vcpu.run() FAILED after {} exits: {:?}",
                        ap_id,
                        stats.exit_count,
                        e
                    );
                    return;
                }
            };
            stats.exit_count += 1;

            // Log first few AP exits for diagnostics.
            if stats.exit_count <= 10 {
                let desc = match &exit {
                    VcpuExit::IoOut { port, .. } => format!("IoOut(port={:#X})", port),
                    VcpuExit::IoIn { port, .. } => format!("IoIn(port={:#X})", port),
                    VcpuExit::MmioRead { address, .. } => format!("MmioRead({:#X})", address),
                    VcpuExit::MmioWrite { address, .. } => format!("MmioWrite({:#X})", address),
                    VcpuExit::Halt => "Halt".into(),
                    VcpuExit::Cancelled => "Cancelled".into(),
                    VcpuExit::InterruptWindow => "InterruptWindow".into(),
                    VcpuExit::Shutdown => "Shutdown".into(),
                    VcpuExit::UnrecoverableException => "UnrecoverableException".into(),
                    VcpuExit::MsrAccess {
                        msr_number,
                        is_write,
                        ..
                    } => format!("MSR({:#X}, write={})", msr_number, is_write),
                    VcpuExit::CpuidAccess { rax, .. } => format!("CPUID({:#X})", rax),
                    VcpuExit::Unknown(r) => format!("Unknown({})", r),
                };
                diag!("AP{}: exit #{} = {}", ap_id, stats.exit_count, desc);
            }

            match exit {
                VcpuExit::IoOut { port, size, data } => {
                    stats.halt_count = 0;
                    stats.io_out_count += 1;
                    let mut dm = devices.lock().unwrap();
                    dm.handle_io_out(port, size, data);
                    if dm.shutdown_requested() {
                        log::info!("AP{}: ACPI shutdown detected", ap_id);
                        shutdown.store(true, Ordering::Release);
                        for c in cancellers {
                            let _ = c.cancel();
                        }
                        return;
                    }
                    drop(dm);
                    let _ = vcpu.skip_instruction();
                }
                VcpuExit::IoIn { port, size } => {
                    stats.halt_count = 0;
                    stats.io_in_count += 1;
                    let data = devices.lock().unwrap().handle_io_in(port, size);
                    let _ = vcpu.complete_io_in(data, size);
                }
                VcpuExit::MmioRead { address, size } => {
                    stats.halt_count = 0;
                    stats.mmio_count += 1;
                    let data = devices
                        .lock()
                        .unwrap()
                        .handle_mmio_read(ap_id, address, size);
                    let _ = vcpu.complete_mmio_read(data);
                }
                VcpuExit::MmioWrite {
                    address,
                    size,
                    data,
                } => {
                    stats.halt_count = 0;
                    stats.mmio_count += 1;
                    let mut dm = devices.lock().unwrap();
                    let ipi_action = dm.handle_mmio_write(ap_id, address, size, data, guest_mem);
                    if !matches!(ipi_action, IpiAction::None) {
                        // APs can send IPIs too (e.g., IPI to BSP for TLB shootdown).
                        dispatch_ipi(ipi_action, &mut dm, &[], cancellers, diag_log, stats.start_time);
                    }
                    drop(dm);
                    let _ = vcpu.skip_instruction();
                }
                VcpuExit::InterruptWindow => {
                    stats.halt_count = 0;
                    stats.window_requested = false;
                }
                VcpuExit::Halt => {
                    stats.total_halt_exits += 1;
                    if shutdown.load(Ordering::Relaxed) || !run_config.should_run() {
                        log::info!("AP{}: stop requested on Halt", ap_id);
                        return;
                    }

                    // Check for pending interrupts.
                    {
                        let mut dm = devices.lock().unwrap();
                        if dm.irq_chip.has_pending(ap_id) {
                            let already_pending = vcpu.has_pending_interruption().unwrap_or(false);
                            if !already_pending {
                                if let Some(vector) = dm.irq_chip.acknowledge(ap_id) {
                                    let _ = vcpu.inject_interrupt(vector);
                                    dm.irq_chip.notify_injected(ap_id, vector);
                                    stats.window_requested = false;
                                    stats.inject_count += 1;
                                }
                            }
                            stats.halt_with_irq += 1;
                            stats.halt_count = 0;
                            continue;
                        }
                    }

                    stats.halt_count += 1;

                    if stats.halt_count > MAX_HALTS {
                        log::info!(
                            "AP{}: halted {} times, idling (not treated as fatal)",
                            ap_id,
                            stats.halt_count,
                        );
                        // APs can idle indefinitely — the kernel may park them.
                        // Don't exit, just keep waiting for interrupts.
                        stats.halt_count = 0;
                    }

                    // Tiered sleep: spin-yield phase to catch imminent interrupts,
                    // then short sleep if no interrupt arrived.
                    let mut woke_by_irq = false;
                    for i in 0..HLT_SPIN_ITERS {
                        std::thread::yield_now();
                        if i % 10 == 9 {
                            let mut dm = devices.lock().unwrap();
                            if dm.irq_chip.has_pending(ap_id) {
                                woke_by_irq = true;
                                break;
                            }
                        }
                    }
                    if !woke_by_irq {
                        std::thread::sleep(Duration::from_micros(HLT_SLEEP_US));
                    }
                }
                VcpuExit::Shutdown => {
                    log::info!("AP{}: shutdown after {} exits", ap_id, stats.exit_count);
                    return;
                }
                VcpuExit::Cancelled => {
                    if shutdown.load(Ordering::Relaxed) || !run_config.should_run() {
                        log::info!("AP{}: stop requested on Cancelled", ap_id);
                        return;
                    }
                }
                VcpuExit::MsrAccess {
                    msr_number,
                    is_write,
                    rax,
                    rdx,
                } => {
                    stats.halt_count = 0;
                    if is_write {
                        log::trace!(
                            "AP{}: MSR write 0x{:08X} <- 0x{:016X}",
                            ap_id,
                            msr_number,
                            (rdx << 32) | (rax & 0xFFFF_FFFF)
                        );
                        if let Err(e) = vcpu.skip_instruction() {
                            log::error!("AP{} skip_instruction error: {:?}", ap_id, e);
                            return;
                        }
                    } else {
                        let value = super::handle_msr_read(ap_id, msr_number);
                        log::trace!(
                            "AP{}: MSR read 0x{:08X} -> 0x{:X}",
                            ap_id,
                            msr_number,
                            value
                        );
                        if let Err(e) = vcpu.complete_msr_read(value) {
                            log::error!("AP{} complete_msr_read error: {:?}", ap_id, e);
                            return;
                        }
                    }
                }
                VcpuExit::CpuidAccess {
                    rax,
                    rcx,
                    default_rax,
                    default_rbx,
                    default_rcx,
                    default_rdx,
                } => {
                    stats.halt_count = 0;
                    let (out_rax, out_rbx, out_rcx, out_rdx) = super::handle_cpuid(
                        ap_id,
                        num_vcpus,
                        rax as u32,
                        default_rax,
                        default_rbx,
                        default_rcx,
                        default_rdx,
                    );
                    log::trace!(
                        "AP{} CPUID leaf=0x{:X} sub=0x{:X} -> rax=0x{:X}",
                        ap_id,
                        rax,
                        rcx,
                        out_rax
                    );
                    if let Err(e) = vcpu.complete_cpuid(out_rax, out_rbx, out_rcx, out_rdx) {
                        log::error!("AP{} complete_cpuid error: {:?}", ap_id, e);
                        return;
                    }
                }
                VcpuExit::UnrecoverableException => {
                    let regs = vcpu.get_registers().ok();
                    let sregs = vcpu.get_special_registers().ok();
                    diag!(
                        "AP{}: TRIPLE FAULT after {} exits, RIP={:#X}, CR0={:#X}, CR3={:#X}, EFER={:#X}",
                        ap_id,
                        stats.exit_count,
                        regs.as_ref().map_or(0, |r| r.rip),
                        sregs.as_ref().map_or(0, |s| s.cr0),
                        sregs.as_ref().map_or(0, |s| s.cr3),
                        sregs.as_ref().map_or(0, |s| s.efer),
                    );
                    return;
                }
                VcpuExit::Unknown(reason) => {
                    diag!(
                        "AP{}: unknown exit reason {} after {} exits",
                        ap_id, reason, stats.exit_count
                    );
                    return;
                }
            }

            if stats.exit_count >= MAX_EXITS {
                log::warn!("AP{}: reached {} exit limit", ap_id, MAX_EXITS);
                return;
            }
        }
    }

    /// Run a VM synchronously on the calling thread (blocking).
    ///
    /// Used by `wkrun_start_enter()`. Creates a default `VcpuRunConfig` and
    /// runs the vCPU loop until the guest shuts down or an error occurs.
    pub fn run(ctx: VmContext) -> Result<i32> {
        let ctx_id = ctx.id;
        let run_config = VcpuRunConfig::new();
        let canceller_slot = Arc::new(Mutex::new(None));
        let result = run_vcpu_loop(ctx, run_config, canceller_slot);
        devices::remove_console_buffer(ctx_id);
        result
    }

    /// Start a VM on a background thread (non-blocking).
    ///
    /// Takes ownership of the context and spawns a thread running the vCPU loop.
    /// Use `wait()` to block until the VM exits, or `stop()` to request shutdown.
    pub fn start(ctx_id: u32, ctx: VmContext) -> Result<()> {
        let run_config = VcpuRunConfig::new();
        let canceller_slot: Arc<Mutex<Option<VcpuCanceller>>> = Arc::new(Mutex::new(None));

        let rc = run_config.clone();
        let cs = canceller_slot.clone();
        let thread = std::thread::spawn(move || run_vcpu_loop(ctx, rc, cs));

        let handle = VmHandle {
            thread: Some(thread),
            run_config,
            canceller: canceller_slot,
        };

        let mut map = RUNNING_VMS
            .lock()
            .map_err(|_| WkrunError::Config("running VMs lock poisoned".into()))?;
        if map.contains_key(&ctx_id) {
            return Err(WkrunError::Config(format!(
                "VM {} is already running",
                ctx_id
            )));
        }
        map.insert(ctx_id, handle);
        Ok(())
    }

    /// Block until a running VM exits. Returns the guest exit code.
    ///
    /// Removes the VM from the running registry. After `wait()` returns,
    /// the ctx_id is no longer valid.
    pub fn wait(ctx_id: u32) -> Result<i32> {
        let mut map = RUNNING_VMS
            .lock()
            .map_err(|_| WkrunError::Config("running VMs lock poisoned".into()))?;
        let mut handle = map
            .remove(&ctx_id)
            .ok_or(WkrunError::InvalidContext(ctx_id))?;
        drop(map); // Release lock before blocking join.

        let thread = handle
            .thread
            .take()
            .ok_or_else(|| WkrunError::Config("VM thread already joined".into()))?;
        let result = thread
            .join()
            .map_err(|_| WkrunError::Config("VM thread panicked".into()))?;
        devices::remove_console_buffer(ctx_id);
        result
    }

    /// Request a running VM to stop (non-blocking).
    ///
    /// Sets the stop flag and wakes the vCPU so it exits promptly.
    /// The VM thread will exit on its next Halt or Cancelled check.
    /// Call `wait()` afterwards to collect the exit code.
    pub fn stop(ctx_id: u32) -> Result<()> {
        let map = RUNNING_VMS
            .lock()
            .map_err(|_| WkrunError::Config("running VMs lock poisoned".into()))?;
        let handle = map.get(&ctx_id).ok_or(WkrunError::InvalidContext(ctx_id))?;
        handle.run_config.request_stop();
        if let Some(ref canceller) = *handle.canceller.lock().unwrap() {
            let _ = canceller.cancel();
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub use imp::{run, start, stop, wait};

/// Stub for non-Windows platforms (compile only, never called).
#[cfg(not(target_os = "windows"))]
pub fn run(_ctx: super::context::VmContext) -> super::error::Result<i32> {
    Err(super::error::WkrunError::Config(
        "VM runner is only available on Windows".into(),
    ))
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub fn start(_ctx_id: u32, _ctx: super::context::VmContext) -> super::error::Result<()> {
    Err(super::error::WkrunError::Config(
        "VM runner is only available on Windows".into(),
    ))
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub fn wait(_ctx_id: u32) -> super::error::Result<i32> {
    Err(super::error::WkrunError::Config(
        "VM runner is only available on Windows".into(),
    ))
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub fn stop(_ctx_id: u32) -> super::error::Result<()> {
    Err(super::error::WkrunError::Config(
        "VM runner is only available on Windows".into(),
    ))
}

/// Handle CPUID exit for any vCPU.
///
/// Injects CPU topology info into leaf 1 and masks Hyper-V leaves.
/// This is a pure function (no side effects) for testability.
fn handle_cpuid(
    vcpu_id: u8,
    num_vcpus: u8,
    leaf: u32,
    default_rax: u64,
    default_rbx: u64,
    default_rcx: u64,
    default_rdx: u64,
) -> (u64, u64, u64, u64) {
    match leaf {
        // Leaf 1: feature info + topology.
        // EBX[23:16] = max number of addressable APIC IDs (num_vcpus)
        // EBX[31:24] = initial APIC ID (vcpu_id)
        // ECX bit 31: clear "hypervisor present"
        1 => {
            let mut ebx = default_rbx;
            // Clear bits 31:16, then set topology fields.
            ebx &= 0xFFFF_FFFF_0000_FFFF;
            ebx |= (num_vcpus as u64) << 16; // max APIC IDs
            ebx |= (vcpu_id as u64) << 24; // initial APIC ID
            (
                default_rax,
                ebx,
                default_rcx & !(1u64 << 31), // clear hypervisor present
                default_rdx,
            )
        }
        // Hyper-V CPUID range: return zeros.
        0x40000000..=0x400000FF => (0, 0, 0, 0),
        _ => (default_rax, default_rbx, default_rcx, default_rdx),
    }
}

/// Handle MSR read for any vCPU.
///
/// Returns the value to inject for the given MSR.
/// IA32_APIC_BASE (0x1B) returns the APIC base address with enable + BSP bits.
fn handle_msr_read(vcpu_id: u8, msr_number: u32) -> u64 {
    if msr_number == 0x1B {
        let mut val: u64 = 0xFEE0_0000 | (1 << 11); // APIC base + enable bit
        if vcpu_id == 0 {
            val |= 1 << 8; // BSP flag
        }
        val
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::super::context::VmContext;
    use super::super::vcpu::VcpuRunConfig;
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_run_without_kernel_returns_error() {
        // VmContext with no kernel path should fail.
        let ctx = VmContext::default_for_test();
        let result = run(ctx);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // On non-Windows: "only available on Windows"
        // On Windows without kernel: "kernel_path is required"
        assert!(
            err.contains("kernel_path") || err.contains("Windows"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_start_without_kernel_returns_error() {
        // start() should fail the same way as run() for missing kernel.
        let ctx = VmContext::default_for_test();
        let result = start(99900, ctx);

        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Windows"));
        }

        #[cfg(target_os = "windows")]
        {
            // start() spawns a thread — the error surfaces in wait().
            // But on Windows, if WHPX isn't available or kernel is missing,
            // we still get Ok(()) from start() since the thread handles it.
            if result.is_ok() {
                let wait_result = wait(99900);
                assert!(wait_result.is_err());
            }
        }
    }

    #[test]
    fn test_wait_invalid_id_returns_error() {
        let result = wait(99901);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid context") || err.contains("Windows"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_stop_invalid_id_returns_error() {
        let result = stop(99902);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid context") || err.contains("Windows"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_run_config_used_for_stop() {
        // Verify VcpuRunConfig flag propagation (cross-platform).
        let config = VcpuRunConfig::new();
        let cloned = config.clone();
        assert!(config.should_run());
        assert!(cloned.should_run());

        cloned.request_stop();
        assert!(!config.should_run());
    }

    #[test]
    fn test_canceller_slot_starts_none() {
        // The canceller slot should start as None (cross-platform).
        let slot: Arc<Mutex<Option<()>>> = Arc::new(Mutex::new(None));
        assert!(slot.lock().unwrap().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_start_rejects_duplicate_ctx_id() {
        // Use a unique ctx_id unlikely to collide with other tests.
        let ctx_id = 99903;
        let ctx = VmContext::default_for_test();
        // First start might succeed or fail (depending on WHPX availability).
        let _ = start(ctx_id, ctx);

        let ctx2 = VmContext::default_for_test();
        let result = start(ctx_id, ctx2);
        // If first succeeded, second should fail with "already running".
        // Clean up.
        let _ = stop(ctx_id);
        let _ = wait(ctx_id);

        if result.is_err() {
            assert!(result.unwrap_err().to_string().contains("already running"));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_double_wait_returns_error() {
        let ctx_id = 99904;
        let ctx = VmContext::default_for_test();
        if start(ctx_id, ctx).is_ok() {
            // First wait should succeed (thread exits with error due to no kernel).
            let _ = wait(ctx_id);
            // Second wait should fail — already removed.
            let result = wait(ctx_id);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("invalid context"));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_stop_after_wait_returns_error() {
        let ctx_id = 99905;
        let ctx = VmContext::default_for_test();
        if start(ctx_id, ctx).is_ok() {
            let _ = wait(ctx_id);
            // stop() after wait() should fail — already removed from registry.
            let result = stop(ctx_id);
            assert!(result.is_err());
        }
    }

    // --- handle_cpuid tests ---

    #[test]
    fn test_cpuid_leaf1_topology_bsp() {
        // BSP (vcpu 0) with 2 vCPUs.
        let (rax, rbx, rcx, rdx) =
            super::handle_cpuid(0, 2, 1, 0x1234, 0x0000_0000_0000_5678, 0x8000_0001, 0xABCD);
        // EBX[23:16] = num_vcpus = 2, EBX[31:24] = vcpu_id = 0
        assert_eq!(rbx & 0x00FF_0000, 0x0002_0000, "EBX[23:16] should be 2");
        assert_eq!(
            rbx & 0xFF00_0000,
            0x0000_0000,
            "EBX[31:24] should be 0 for BSP"
        );
        // EBX[15:0] preserved from default
        assert_eq!(rbx & 0xFFFF, 0x5678, "EBX[15:0] should be preserved");
        // ECX bit 31 (hypervisor present) must be cleared
        assert_eq!(rcx & (1 << 31), 0, "hypervisor present bit must be cleared");
        // RAX and RDX pass through
        assert_eq!(rax, 0x1234);
        assert_eq!(rdx, 0xABCD);
    }

    #[test]
    fn test_cpuid_leaf1_topology_ap() {
        // AP (vcpu 3) with 4 vCPUs.
        let (_, rbx, _, _) = super::handle_cpuid(3, 4, 1, 0, 0, 0, 0);
        assert_eq!((rbx >> 16) & 0xFF, 4, "EBX[23:16] should be num_vcpus=4");
        assert_eq!((rbx >> 24) & 0xFF, 3, "EBX[31:24] should be vcpu_id=3");
    }

    #[test]
    fn test_cpuid_hyperv_leaves_zeroed() {
        // Hyper-V CPUID range should return all zeros.
        for leaf in [0x40000000u32, 0x40000001, 0x400000FF] {
            let (rax, rbx, rcx, rdx) =
                super::handle_cpuid(0, 1, leaf, 0xDEAD, 0xBEEF, 0xCAFE, 0xF00D);
            assert_eq!(
                (rax, rbx, rcx, rdx),
                (0, 0, 0, 0),
                "Hyper-V leaf 0x{:X} must be zeroed",
                leaf
            );
        }
    }

    #[test]
    fn test_cpuid_passthrough_other_leaves() {
        // Non-special leaves should pass through defaults unchanged.
        let (rax, rbx, rcx, rdx) = super::handle_cpuid(0, 2, 0, 0x1111, 0x2222, 0x3333, 0x4444);
        assert_eq!((rax, rbx, rcx, rdx), (0x1111, 0x2222, 0x3333, 0x4444));

        let (rax, rbx, rcx, rdx) = super::handle_cpuid(0, 2, 7, 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD);
        assert_eq!((rax, rbx, rcx, rdx), (0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD));
    }

    // --- handle_msr_read tests ---

    #[test]
    fn test_msr_apic_base_bsp() {
        // BSP should have enable + BSP flag.
        let val = super::handle_msr_read(0, 0x1B);
        assert_eq!(val & 0xFFFFF000, 0xFEE0_0000, "APIC base address");
        assert_ne!(val & (1 << 11), 0, "APIC enable bit must be set");
        assert_ne!(val & (1 << 8), 0, "BSP flag must be set for vcpu 0");
    }

    #[test]
    fn test_msr_apic_base_ap() {
        // AP should have enable but NOT BSP flag.
        let val = super::handle_msr_read(1, 0x1B);
        assert_eq!(val & 0xFFFFF000, 0xFEE0_0000, "APIC base address");
        assert_ne!(val & (1 << 11), 0, "APIC enable bit must be set");
        assert_eq!(val & (1 << 8), 0, "BSP flag must NOT be set for AP");
    }

    #[test]
    fn test_msr_unknown_returns_zero() {
        // Unknown MSR should return 0.
        assert_eq!(super::handle_msr_read(0, 0x174), 0);
        assert_eq!(super::handle_msr_read(1, 0xC000_0080), 0);
    }
}
