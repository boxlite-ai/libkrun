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
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::super::boot::loader::load_kernel_with_initrd;
    use super::super::devices::virtio::queue::GuestMemoryAccessor;
    use super::super::error::{Result, WkrunError};
    use super::super::cmdline::build_kernel_cmdline;
    use super::super::context::VmContext;
    use super::super::devices::manager::{self as devices, DeviceManager};
    use super::super::memory::GuestMemory;
    use super::super::types::VcpuExit;
    use super::super::vcpu::VcpuRunConfig;
    use super::super::whpx::{VcpuCanceller, WhpxPartition, WhpxVcpu};

    /// Adapter to implement GuestMemoryAccessor for GuestMemory.
    struct GuestMemoryAdapter<'a>(&'a GuestMemory);

    impl GuestMemoryAccessor for GuestMemoryAdapter<'_> {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            self.0.read_at_addr(addr, buf)
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            self.0.write_at_addr(addr, data)
        }
    }

    /// Maximum vCPU exits before giving up.
    const MAX_EXITS: u64 = 500_000_000;

    /// Maximum consecutive HLT instructions before giving up.
    ///
    /// When the guest executes `poweroff -f` on WHPX (no ACPI), the kernel
    /// enters an HLT loop. With the 1ms timer tick, this translates to
    /// ~5 seconds of wall-clock time before we detect the shutdown.
    const MAX_HALTS: u64 = 5_000;

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

        // Create partition (no APIC emulation — avoids crash on some Win10 hardware).
        let partition = WhpxPartition::new()?;
        partition.set_processor_count(ctx.num_vcpus as u32)?;
        partition.setup()?;

        // Allocate and map guest memory.
        let guest_mem = GuestMemory::new(ctx.ram_mib)?;
        guest_mem.map_to_partition(&partition)?;

        // Create devices from context.
        let setup = DeviceManager::from_context(&ctx)?;
        devices::store_console_buffer(ctx.id, setup.console_buffer);
        let mut devices = setup.devices;

        // Build kernel command line.
        let cmdline = build_kernel_cmdline(
            ctx.kernel_cmdline.as_deref(),
            setup.has_root_disk,
            &setup.mmio_slots,
        );

        // Load kernel.
        let initrd_ref = initrd_data.as_deref();
        let (regs, sregs) =
            load_kernel_with_initrd(&guest_mem, &kernel_image, &cmdline, ctx.ram_mib, initrd_ref)?;

        log::info!(
            "Kernel loaded at 0x100000, RIP=0x{:X}, cmdline: {}",
            regs.rip,
            cmdline
        );

        // Create vCPU and set registers.
        let vcpu = WhpxVcpu::new(&partition, 0)?;
        vcpu.set_registers(&regs)?;
        vcpu.set_special_registers(&sregs)?;

        // Store canceller so stop() can wake the vCPU.
        *canceller_slot.lock().unwrap() = Some(vcpu.canceller());

        // Spawn timer thread for PIT interrupt delivery.
        // Uses run_config.running so that request_stop() stops both the timer
        // and the vCPU loop.
        let timer_flag = run_config.running.clone();
        let canceller = vcpu.canceller();
        let timer_thread = std::thread::spawn(move || {
            while timer_flag.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
                let _ = canceller.cancel();
            }
        });

        // vCPU run loop.
        let mem_adapter = GuestMemoryAdapter(&guest_mem);
        let mut exit_count: u64 = 0;
        let mut halt_count: u64 = 0;
        let exit_code;

        loop {
            // Tick PIT and poll devices.
            devices.tick_and_poll(&mem_adapter);

            // Try to inject pending interrupt.
            if devices.pic.has_pending() {
                match vcpu.interrupts_enabled() {
                    Ok(true) => {
                        if let Some(vector) = devices.pic.acknowledge() {
                            vcpu.inject_interrupt(vector)?;
                            devices.set_window_requested(false);
                        }
                    }
                    Ok(false) => {
                        if !devices.window_requested() {
                            vcpu.request_interrupt_window()?;
                            devices.set_window_requested(true);
                        }
                    }
                    Err(_) => {}
                }
            }

            let exit = vcpu.run()?;
            exit_count += 1;

            match exit {
                VcpuExit::IoOut { port, size, data } => {
                    halt_count = 0;
                    devices.handle_io_out(port, size, data);
                    vcpu.skip_instruction()?;
                }
                VcpuExit::IoIn { port, size } => {
                    halt_count = 0;
                    let data = devices.handle_io_in(port, size);
                    vcpu.complete_io_in(data, size)?;
                }
                VcpuExit::MmioRead { address, size } => {
                    halt_count = 0;
                    let data = devices.handle_mmio_read(address, size);
                    vcpu.complete_mmio_read(data)?;
                }
                VcpuExit::MmioWrite {
                    address,
                    size,
                    data,
                } => {
                    halt_count = 0;
                    devices.handle_mmio_write(address, size, data, &mem_adapter);
                    vcpu.skip_instruction()?;
                }
                VcpuExit::InterruptWindow => {
                    devices.set_window_requested(false);
                }
                VcpuExit::Halt => {
                    if !run_config.should_run() {
                        log::info!("VM stop requested, exiting on Halt");
                        exit_code = 0;
                        break;
                    }
                    halt_count += 1;
                    if halt_count > MAX_HALTS {
                        log::warn!(
                            "vCPU halted {} times consecutively after {} exits",
                            halt_count,
                            exit_count
                        );
                        exit_code = 0;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                VcpuExit::Shutdown => {
                    log::info!("VM shutdown after {} exits", exit_count);
                    exit_code = 0;
                    break;
                }
                VcpuExit::Cancelled => {
                    // Timer thread or stop() cancelled vCPU. Check if we should exit.
                    if !run_config.should_run() {
                        log::info!("VM stop requested, exiting on Cancelled");
                        exit_code = 0;
                        break;
                    }
                }
                VcpuExit::Unknown(reason) => {
                    log::error!(
                        "Unknown vCPU exit reason {} after {} exits",
                        reason,
                        exit_count
                    );
                    exit_code = -1;
                    break;
                }
            }

            if exit_count >= MAX_EXITS {
                log::warn!("Reached {} exit limit", MAX_EXITS);
                exit_code = -1;
                break;
            }
        }

        // Stop the timer thread.
        run_config.request_stop();
        let _ = timer_thread.join();

        log::info!("VM exited with code {} ({} exits)", exit_code, exit_count);
        Ok(exit_code)
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::context::VmContext;
    use super::super::vcpu::VcpuRunConfig;
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
}
