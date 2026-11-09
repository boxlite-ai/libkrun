// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::builder;
#[cfg(target_os = "linux")]
use crate::device_manager::{legacy::PortIODeviceManager, mmio::MMIODeviceManager};
use crate::resources::{VirtioConsoleConfigMode, VmResources};
#[cfg(target_os = "linux")]
use crate::vstate::{KvmContext, Vcpu, Vm};
#[cfg(target_os = "linux")]
use devices::legacy::{Cmos, IrqChip, IrqChipDevice, KvmIoapic};
use devices::virtio::DeviceQueue;
use polly::event_manager::EventManager;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicI32;
#[cfg(target_os = "linux")]
use utils::eventfd::EFD_NONBLOCK;

fn checked_artifact(directory: &Path, expected: &Artifact, name: &str) -> io::Result<File> {
    if expected.name != name {
        return Err(invalid("invalid checkpoint artifact name"));
    }
    let file = open_file(&directory.join(name))?;
    if file.metadata()?.len() != expected.len {
        return Err(invalid("checkpoint artifact length mismatch"));
    }
    Ok(file)
}

fn metadata(directory: &Path) -> io::Result<Metadata> {
    let mut file = open_file(&directory.join("state.bin"))?;
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if &header[..8] != MAGIC
        || version != VERSION
        || len > MAX_METADATA
        || file.metadata()?.len() != 16 + len as u64
    {
        return Err(invalid("invalid checkpoint header/version/length"));
    }
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes)?;
    let state: Metadata = serde_json::from_slice(&bytes).map_err(other)?;
    if state.version != VERSION
        || state.platform != PLATFORM
        || state.cpus.is_empty()
        || state.cpus.len() > 128
        || state.devices.len() > 24
        || state.arch_memory[7] != 0
    {
        return Err(invalid("incompatible checkpoint platform or topology"));
    }
    #[cfg(target_os = "linux")]
    {
        if state.legacy.serial.len() != 4
            || state.legacy.serial_endpoints > 4
            || state.arch_memory[4] != 4096
            || state.legacy.cmos.len() != 128
            || state.irq_counts.len() != state.devices.len() + 5
            || state.irq_counts.contains(&u64::MAX)
        {
            return Err(invalid("invalid x86 topology"));
        }
        state.legacy.keyboard.validate()?;
    }
    #[cfg(target_os = "macos")]
    hvf::validate(&state)?;
    if state
        .devices
        .windows(2)
        .any(|pair| pair[0].address >= pair[1].address)
    {
        return Err(invalid("checkpoint devices are not in address order"));
    }
    #[cfg(target_os = "linux")]
    for serial in state.legacy.serial.iter().flatten() {
        serial.validate()?;
    }
    let mut irqs = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for record in &state.devices {
        let common = match &record.state {
            DeviceSnapshot::Vsock(state) => Some(&state.device),
            #[cfg(feature = "net")]
            DeviceSnapshot::Net(state) => Some(&state.device),
            DeviceSnapshot::Fs(state) => Some(&state.device),
            DeviceSnapshot::Rng(state) | DeviceSnapshot::Balloon(state) => Some(&state.device),
            #[cfg(target_os = "linux")]
            DeviceSnapshot::Memory(state) => Some(&state.device),
            #[cfg(feature = "blk")]
            DeviceSnapshot::Block(state, _, _) => Some(&state.device),
            DeviceSnapshot::Console(_, _) => None,
        };
        if common.is_some_and(|common| common != &record.transport.device) {
            return Err(invalid("device and transport negotiation state differ"));
        }
        if record.address < arch::MMIO_MEM_START
            || record.address >= 0x1_0000_0000
            || record.address % 4096 != 0
            || !(arch::IRQ_BASE..=arch::IRQ_MAX).contains(&record.irq)
            || !irqs.insert(record.irq)
            || !ids.insert((record.transport.device.device_type, record.id.clone()))
        {
            return Err(invalid("invalid or duplicate checkpoint MMIO/IRQ layout"));
        }
    }
    Ok(state)
}

/// Restore directly from saved RAM and topology. No kernel loader, boot setup,
/// FDT/MP table construction or device negotiation is run. The event manager
/// must not dispatch until this returns; on success the VM is running. Discard
/// the event manager on failure, since it may contain inactive subscribers.
pub fn restore(
    directory: &Path,
    resources: &VmResources,
    events: &mut EventManager,
    #[cfg(target_os = "macos")] shutdown_efd: Option<EventFd>,
) -> io::Result<Arc<Mutex<Vmm>>> {
    let mut saved = metadata(directory)?;
    if resources.serial_consoles.len() != saved.legacy.serial_endpoints
        || resources.nested_enabled
        || resources.split_irqchip
        || resources.gpu_virgl_flags.is_some()
    {
        return Err(invalid("incompatible restore resources"));
    }
    let budget = resources.vm_config().mem_size_mib.unwrap_or(128) as u64 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    let memory_state = {
        let memory_state = saved
            .devices
            .iter()
            .filter_map(|record| match &record.state {
                #[cfg(target_os = "linux")]
                DeviceSnapshot::Memory(state) => Some(state),
                _ => None,
            })
            .collect::<Vec<_>>();
        if memory_state.len() > 1 || memory_state.is_empty() != saved.hotplug.is_none() {
            return Err(invalid("inconsistent hotplug checkpoint"));
        }
        if let Some(state) = memory_state.first() {
            state.validate()?;
        }
        memory_state
    };
    if saved.ram.len > budget.saturating_add(1024 * 1024) {
        return Err(invalid("checkpoint exceeds configured boot RAM budget"));
    }
    let mut ram = checked_artifact(directory, &saved.ram, "ram.bin")?;
    let ram_layout = crate::ram_snapshot::file_metadata(&mut ram)?;
    if ram_layout.memory_bytes > budget || ram_layout.regions.len() > 64 {
        return Err(invalid("checkpoint RAM layout exceeds configured budget"));
    }
    for region in &ram_layout.regions {
        let end = region
            .gpa
            .checked_add(region.len)
            .ok_or_else(|| invalid("RAM range overflow"))?;
        if region.len == 0
            || region.gpa % saved.arch_memory[4] != 0
            || region.len % saved.arch_memory[4] != 0
            || !valid_ram_range(region.gpa, end)
        {
            return Err(invalid("invalid RAM mapping or MMIO overlap"));
        }
    }
    let mut memory = crate::ram_snapshot::restore_file(&ram, &ram_layout)?;
    // DAX windows are address-space reservations, not RAM payload. Never read
    // their file-backed/protected pages through the RAM codec.
    for record in &saved.devices {
        if let DeviceSnapshot::Fs(fs) = &record.state {
            if let Some(window) = &fs.dax_window {
                // The block-root bootstrap share is recreated internally. Its
                // window has the fixed 512 MiB size used by set_root_disk_remount.
                let configured = if fs.retired_root {
                    1 << 29
                } else {
                    resources
                        .fs
                        .iter()
                        .find(|f| f.fs_id == fs.tag)
                        .and_then(|f| f.shm_size)
                        .unwrap_or(0) as u64
                };
                let end = window
                    .guest_addr
                    .checked_add(window.size)
                    .ok_or_else(|| invalid("DAX window overflow"))?;
                let page = saved.arch_memory[4];
                let configured = configured
                    .checked_add(page - 1)
                    .ok_or_else(|| invalid("DAX size budget overflow"))?
                    / page
                    * page;
                if window.size == 0
                    || window.size > configured
                    || window.guest_addr % page != 0
                    || window.size % page != 0
                    || window.guest_addr < saved.arch_memory[3]
                    || !valid_ram_range(window.guest_addr, end)
                {
                    return Err(invalid("invalid DAX window or missing size budget"));
                }
                let region = vm_memory::GuestRegionMmap::from_range(
                    vm_memory::GuestAddress(window.guest_addr),
                    window.size as usize,
                    None,
                )
                .map_err(other)?;
                memory = memory.insert_region(Arc::new(region)).map_err(other)?;
            }
        }
    }
    drop(ram);
    #[cfg(target_os = "linux")]
    let (mut vmm, intc) = {
        let kvm = KvmContext::new().map_err(other)?;
        let mut vm = Vm::new(kvm.fd()).map_err(other)?;
        vm.memory_init(&memory, kvm.max_memslots()).map_err(other)?;
        let intc: IrqChip = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(
            KvmIoapic::new(vm.fd()).map_err(other)?,
        ))));
        let exit_evt = EventFd::new(EFD_NONBLOCK)?;
        let info = saved.arch_memory;
        let mut serials = Vec::new();
        for binding in &resources.serial_consoles {
            let input = if binding.input_fd >= 0 {
                Some(Box::new(File::from(
                    unsafe { BorrowedFd::borrow_raw(binding.input_fd) }.try_clone_to_owned()?,
                ))
                    as Box<dyn devices::legacy::ReadableFd + Send>)
            } else {
                None
            };
            let output = if binding.output_fd >= 0 {
                Some(Box::new(File::from(
                    unsafe { BorrowedFd::borrow_raw(binding.output_fd) }.try_clone_to_owned()?,
                )) as Box<dyn io::Write + Send>)
            } else {
                None
            };
            serials.push(builder::setup_serial_device(events, input, output).map_err(other)?);
        }
        let mut pio = PortIODeviceManager::new(
            Arc::new(Mutex::new(Cmos::new(info[0], info[1]))),
            serials,
            exit_evt.try_clone()?,
        )
        .map_err(other)?;
        let mut base = arch::MMIO_MEM_START;
        let mut mmio = MMIODeviceManager::new(&mut base, (arch::IRQ_BASE, arch::IRQ_MAX));
        builder::attach_legacy_devices(&vm, false, &mut pio, &mut mmio, None).map_err(other)?;
        let vmm = Vmm {
            guest_memory: memory,
            arch_memory_info: arch::ArchMemoryInfo {
                ram_below_gap: info[0],
                ram_above_gap: info[1],
                ram_last_addr: info[2],
                shm_start_addr: info[3],
                page_size: info[4] as usize,
                initrd_addr: info[5],
                firmware_addr: info[6],
            },
            kernel_cmdline: kernel::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE),
            vcpus_handles: Vec::new(),
            checkpoint_enabled: true,
            checkpoint_files: Vec::new(),
            checkpoint_dirs: Vec::new(),
            vcpus_paused: true,
            vcpus_failed: false,
            exit_evt,
            vm,
            exit_observers: Vec::new(),
            exit_code: Arc::new(AtomicI32::new(i32::MAX)),
            mmio_device_manager: mmio,
            pio_device_manager: pio,
        };
        (vmm, intc)
    };
    #[cfg(target_os = "macos")]
    let (mut vmm, intc) = hvf::build(&saved, memory, resources, events, shutdown_efd)?;
    // Track devices before activation/registration: a later MMIO validation or
    // registration error must also join the worker that has just been started.
    let mut constructed: Vec<Arc<Mutex<dyn VirtioDevice>>> = Vec::new();
    let build = (|| {
        #[cfg(target_os = "linux")]
        let memory_device = if let Some(state) = memory_state.first() {
            let control = resources
                .memory_hotplug
                .clone()
                .ok_or_else(|| invalid("restore requires matching hotplug configuration"))?;
            if control.initial_mib != state.initial_mib
                || control.status().max_mib != state.status.max_mib
            {
                return Err(invalid("hotplug configuration differs from checkpoint"));
            }
            let (fd, first, count) = vmm
                .vm
                .reserve_memory_slots((state.size / devices::virtio::mem::SLOT_SIZE) as u32);
            if count as u64 * devices::virtio::mem::SLOT_SIZE != state.size {
                return Err(invalid("insufficient KVM hotplug slots"));
            }
            let region =
                devices::virtio::mem::HotplugRegion::new(fd, first, state.addr, state.size)?;
            vmm.guest_memory = vmm
                .guest_memory
                .insert_region(region.memory.clone())
                .map_err(other)?;
            let mut device = Mem::new(control, region)?;
            device.freeze();
            let artifact = saved.hotplug.as_ref().unwrap();
            if artifact.len != state.memory_bytes() {
                return Err(invalid("hotplug RAM length mismatch"));
            }
            let mut reader = checked_artifact(directory, artifact, "hotplug.bin")?;
            device.restore_state(state, &mut reader)?;
            Some(Arc::new(Mutex::new(device)))
        } else {
            None
        };
        // Memory slots exist before validating any queue, including queues whose
        // rings live in hotplug RAM. Raw aliases do not outlive the frozen Mem.
        #[cfg(target_os = "linux")]
        let memory_guard = memory_device.as_ref().map(|m| m.lock().unwrap());
        #[cfg(target_os = "linux")]
        let accessible = match &memory_guard {
            Some(device) => unsafe { device.accessible_memory(&vmm.guest_memory)? },
            None => vmm.guest_memory.clone(),
        };
        #[cfg(target_os = "macos")]
        let accessible = vmm.guest_memory.clone();
        #[cfg(feature = "net")]
        let mut network_owed = Vec::new();
        for (_index, record) in saved.devices.iter().enumerate() {
            #[cfg(target_os = "linux")]
            if matches!(record.state, DeviceSnapshot::Memory(_)) {
                continue;
            }
            let (device, queues): (Arc<Mutex<dyn VirtioDevice>>, Option<Vec<QueueState>>) =
                match &record.state {
                    DeviceSnapshot::Vsock(state) => {
                        let device = resources
                            .vsock
                            .get()
                            .ok_or_else(|| invalid("missing vsock binding"))?
                            .clone();
                        device.lock().unwrap().restore_state(state)?;
                        device
                            .lock()
                            .unwrap()
                            .set_failure_notifier(vmm.exit_evt.try_clone()?);
                        events.add_subscriber(device.clone()).map_err(other)?;
                        (device, state.queues.clone())
                    }
                    #[cfg(feature = "net")]
                    DeviceSnapshot::Net(state) => {
                        let device = resources
                            .net
                            .list
                            .iter()
                            .find(|device| device.lock().unwrap().id() == record.id)
                            .ok_or_else(|| invalid("missing fresh net backend binding"))?
                            .clone();
                        device.lock().unwrap().restore_state(state)?;
                        (
                            device,
                            state
                                .queues
                                .as_ref()
                                .map(|queues| vec![queues.rx.clone(), queues.tx.clone()]),
                        )
                    }
                    DeviceSnapshot::Rng(state) => {
                        let mut rng = Rng::new().map_err(|e| invalid(&format!("RNG: {e:?}")))?;
                        rng.restore_state(state)?;
                        let device = Arc::new(Mutex::new(rng));
                        events.add_subscriber(device.clone()).map_err(other)?;
                        (device, state.queues.clone())
                    }
                    DeviceSnapshot::Balloon(state) => {
                        let mut balloon =
                            Balloon::new().map_err(|e| invalid(&format!("balloon: {e:?}")))?;
                        balloon.restore_state(state)?;
                        let device = Arc::new(Mutex::new(balloon));
                        events.add_subscriber(device.clone()).map_err(other)?;
                        (device, state.queues.clone())
                    }
                    DeviceSnapshot::Fs(state) => {
                        let config = if state.retired_root {
                            let directory = utils::tempdir::TempDir::new().map_err(other)?;
                            let config = crate::vmm_config::fs::FsDeviceConfig {
                                fs_id: state.tag.clone(),
                                shared_dir: directory
                                    .as_path()
                                    .to_str()
                                    .ok_or_else(|| invalid("invalid temporary root path"))?
                                    .into(),
                                shm_size: None,
                                allow_root_dir_delete: true,
                                read_only: state.read_only,
                            };
                            vmm.checkpoint_dirs.push(directory);
                            config
                        } else {
                            resources
                                .fs
                                .iter()
                                .find(|fs| fs.fs_id == state.tag)
                                .ok_or_else(|| invalid("missing virtio-fs root binding"))?
                                .clone()
                        };
                        let mut fs = Fs::new(
                            config.fs_id.clone(),
                            config.shared_dir.clone(),
                            vmm.exit_code.clone(),
                            config.allow_root_dir_delete,
                            config.read_only,
                        )
                        .map_err(|e| invalid(&format!("fs: {e:?}")))?;
                        if let Some(window) = &state.dax_window {
                            use vm_memory::GuestMemory;
                            fs.set_shm_region(devices::virtio::VirtioShmRegion {
                                host_addr: vmm
                                    .guest_memory
                                    .get_host_address(vm_memory::GuestAddress(window.guest_addr))
                                    .map_err(other)?
                                    as u64,
                                guest_addr: window.guest_addr,
                                size: window.size as usize,
                            });
                        }
                        fs.restore_state(state)?;
                        let device = Arc::new(Mutex::new(fs));
                        (device, state.worker.as_ref().map(|w| w.queues.clone()))
                    }
                    DeviceSnapshot::Console(state, queues) => {
                        let id: usize = record
                            .id
                            .strip_prefix("hvc")
                            .ok_or_else(|| invalid("invalid console id"))?
                            .parse()
                            .map_err(other)?;
                        let implicit = !resources.disable_implicit_console && id == 0;
                        let config = if implicit {
                            None
                        } else {
                            Some(
                                resources
                                    .virtio_consoles
                                    .get(id - usize::from(!resources.disable_implicit_console))
                                    .ok_or_else(|| invalid("missing console endpoint binding"))?,
                            )
                        };
                        let ports = match config {
                            Some(VirtioConsoleConfigMode::Explicit(ports)) => {
                                builder::create_explicit_ports(&mut vmm, ports).map_err(other)?
                            }
                            _ => {
                                let config = match config {
                                    Some(VirtioConsoleConfigMode::Autoconfigure(config)) => {
                                        Some(config)
                                    }
                                    _ => None,
                                };
                                if implicit && resources.console_output.is_some() {
                                    let file = OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(resources.console_output.as_ref().unwrap())?;
                                    use devices::virtio::{port_io, PortDescription};
                                    let terminal =
                                        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
                                            port_io::term_fd(libc::STDIN_FILENO).map_err(other)?
                                        } else {
                                            port_io::term_fixed_size(0, 0)
                                        };
                                    vec![PortDescription::console(
                                        Some(port_io::input_empty().map_err(other)?),
                                        Some(port_io::output_file(file).map_err(other)?),
                                        terminal,
                                    )]
                                } else {
                                    builder::autoconfigure_console_ports(
                                        &mut vmm, resources, config, implicit,
                                    )
                                    .map_err(other)?
                                }
                            }
                        };
                        state
                            .validate_guest(
                                &accessible,
                                queues
                                    .as_deref()
                                    .or(record.transport.queues.as_deref())
                                    .unwrap_or(&[]),
                                record.transport.device.activated,
                            )
                            .map_err(other)?;
                        let mut console =
                            Console::new(ports).map_err(|e| invalid(&format!("console: {e:?}")))?;
                        console
                            .restore_state(state, record.transport.device.activated)
                            .map_err(other)?;
                        let device = Arc::new(Mutex::new(console));
                        events.add_subscriber(device.clone()).map_err(other)?;
                        vmm.exit_observers.push(device.clone());
                        (device, queues.clone())
                    }
                    #[cfg(feature = "blk")]
                    DeviceSnapshot::Block(state, artifact, format) => {
                        let image = utils::tempfile::TempFile::new().map_err(other)?;
                        let mut source =
                            checked_artifact(directory, artifact, &format!("disk-{_index}.img"))?;
                        let mut destination = OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(image.as_path())?;
                        let copied = io::copy(&mut source, &mut destination)?;
                        destination.sync_all()?;
                        if copied != artifact.len {
                            return Err(invalid("disk image length changed during import"));
                        }
                        validate_disk(&open_file(image.as_path())?, *format, state)?;
                        let format = match format {
                            0 => ImageType::Raw,
                            1 => ImageType::Qcow2,
                            _ => return Err(invalid("unsupported independent disk format")),
                        };
                        let readonly = state.device.avail_features & (1 << 5) != 0;
                        let sync = if state.device.avail_features & (1 << 9) != 0 {
                            devices::virtio::block::SyncMode::Full
                        } else {
                            devices::virtio::block::SyncMode::None
                        };
                        let mut block = Block::new(
                            record.id.clone(),
                            None,
                            devices::virtio::block::CacheType::Writeback,
                            image
                                .as_path()
                                .to_str()
                                .ok_or_else(|| invalid("invalid image path"))?
                                .into(),
                            format,
                            readonly,
                            false,
                            sync,
                        )?;
                        block.restore_state(state)?;
                        vmm.checkpoint_files.push(image);
                        (
                            Arc::new(Mutex::new(block)),
                            state.queue.clone().map(|q| vec![q]),
                        )
                    }
                    #[cfg(target_os = "linux")]
                    DeviceSnapshot::Memory(_) => unreachable!(),
                };
            constructed.push(device.clone());
            let mut transport =
                MmioTransport::new(vmm.guest_memory.clone(), intc.clone(), device.clone())
                    .map_err(|e| invalid(&format!("MMIO: {e:?}")))?;
            // IRQ binding must precede creating any InterruptTransport clones.
            transport.set_irq_line(record.irq);
            record
                .transport
                .device
                .restore_features(&mut *device.lock().unwrap())?;
            if record.transport.device.activated {
                #[allow(unused_mut)]
                let mut queues = record.transport.device.restore_queues(
                    queues
                        .as_deref()
                        .ok_or_else(|| invalid("missing active queues"))?,
                    &accessible,
                )?;
                #[cfg(feature = "net")]
                if matches!(record.state, DeviceSnapshot::Net(_)) {
                    let count = queues[1].discard_available(&accessible)?;
                    if count != 0 && queues[1].needs_notification(&accessible).map_err(other)? {
                        network_owed.push(transport.interrupt_transport());
                    }
                }
                let queues = queues
                    .into_iter()
                    .zip(transport.queue_evts().iter().cloned())
                    .map(|(queue, event)| DeviceQueue::new(queue, event))
                    .collect();
                device
                    .lock()
                    .unwrap()
                    .activate_frozen(
                        vmm.guest_memory.clone(),
                        transport.interrupt_transport(),
                        queues,
                    )
                    .map_err(|e| invalid(&format!("frozen activation: {e:?}")))?;
            }
            transport.restore_state(&record.transport)?;
            vmm.mmio_device_manager
                .register_checkpoint_device(
                    #[cfg(target_os = "linux")]
                    vmm.vm.fd(),
                    transport,
                    record.transport.device.device_type,
                    record.id.clone(),
                    record.address,
                    record.irq,
                )
                .map_err(other)?;
        }
        drop(accessible);
        #[cfg(target_os = "linux")]
        drop(memory_guard);
        #[cfg(target_os = "linux")]
        if let Some(device) = memory_device {
            let record = saved
                .devices
                .iter()
                .find(|r| matches!(r.state, DeviceSnapshot::Memory(_)))
                .unwrap();
            let DeviceSnapshot::Memory(state) = &record.state else {
                unreachable!()
            };
            let mut transport =
                MmioTransport::new(vmm.guest_memory.clone(), intc.clone(), device.clone())
                    .map_err(|e| invalid(&format!("MMIO: {e:?}")))?;
            transport.set_irq_line(record.irq);
            device.lock().unwrap().activate_restored(
                state,
                vmm.guest_memory.clone(),
                transport.interrupt_transport(),
                transport.queue_evts()[0].clone(),
            )?;
            transport.restore_state(&record.transport)?;
            events.add_subscriber(device).map_err(other)?;
            vmm.mmio_device_manager
                .register_checkpoint_device(
                    #[cfg(target_os = "linux")]
                    vmm.vm.fd(),
                    transport,
                    record.transport.device.device_type,
                    record.id.clone(),
                    record.address,
                    record.irq,
                )
                .map_err(other)?;
        }
        #[cfg(target_os = "linux")]
        {
            {
                let mut cmos = vmm.pio_device_manager.cmos.lock().unwrap();
                let mut state = cmos.save_state();
                state.index = saved.legacy.cmos_index;
                state.data.copy_from_slice(&saved.legacy.cmos);
                cmos.restore_state(&state)?;
            }
            vmm.pio_device_manager
                .i8042
                .lock()
                .unwrap()
                .restore_state(&saved.legacy.keyboard)?;
            for (address, state) in [0x3f8, 0x2f8, 0x3e8, 0x2e8]
                .iter()
                .zip(&saved.legacy.serial)
            {
                let target = vmm.pio_device_manager.io_bus.get_device(*address);
                match (target, state) {
                    (Some((_, device)), Some(state)) => device
                        .lock()
                        .unwrap()
                        .as_mut_any()
                        .downcast_mut::<devices::legacy::Serial>()
                        .unwrap()
                        .restore_state(state)?,
                    (None, None) => (),
                    _ => return Err(invalid("legacy serial topology mismatch")),
                }
            }
            let mut cpus = Vec::new();
            for id in 0..saved.cpus.len() {
                cpus.push(
                    Vcpu::new_x86_64(
                        id as u8,
                        vmm.vm.fd(),
                        vmm.vm.supported_cpuid().clone(),
                        vmm.vm.supported_msrs().clone(),
                        vmm.pio_device_manager.io_bus.clone(),
                        vmm.exit_evt.try_clone()?,
                    )
                    .map_err(other)?,
                );
            }
            vmm.start_vcpus_paused(cpus).map_err(other)?;
            vmm.vm.restore_state(&saved.vm).map_err(other)?;
            vmm.vm
                .rebase_tsc(&saved.vm, &mut saved.cpus)
                .map_err(other)?;
        }
        #[cfg(target_os = "macos")]
        hvf::restore_platform(&mut vmm, &saved)?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        for (handle, state) in vmm.vcpus_handles.iter_mut().zip(saved.cpus.drain(..)) {
            handle
                .control(Command::Restore(state), deadline)
                .map_err(other)?;
        }
        let devices = vmm.checkpoint_devices()?;
        for ((event, _), count) in vmm.irq_bindings(&devices)?.iter().zip(&saved.irq_counts) {
            if *count != 0 {
                event.write(*count)?;
            }
        }
        #[cfg(feature = "net")]
        for interrupt in network_owed {
            interrupt
                .try_signal_used_queue()
                .map_err(|e| invalid(&format!("net interrupt: {e:?}")))?;
        }
        for device in &devices {
            resume_device(&mut *device.device.lock().unwrap())?;
        }
        vmm.resume_vcpus().map_err(other)
    })();
    if let Err(error) = build {
        let devices = vmm.checkpoint_devices().unwrap_or_default();
        vmm.abort_checkpoint(&devices);
        for device in &constructed {
            join_device(&mut *device.lock().unwrap());
        }
        return Err(error);
    }
    let vmm = Arc::new(Mutex::new(vmm));
    if let Err(error) = events.add_subscriber(vmm.clone()) {
        let mut locked = vmm.lock().unwrap();
        let devices = locked.checkpoint_devices().unwrap_or_default();
        locked.abort_checkpoint(&devices);
        return Err(other(error));
    }
    Ok(vmm)
}

fn valid_ram_range(start: u64, end: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        !(start < 0x1_0000_0000 && end > arch::MMIO_MEM_START)
    }
    #[cfg(target_os = "macos")]
    {
        (start >= arch::aarch64::layout::DRAM_MEM_START_EFI
            && end <= arch::aarch64::layout::DRAM_MEM_END)
            || (start == 0 && end <= arch::MMIO_MEM_START)
    }
}
