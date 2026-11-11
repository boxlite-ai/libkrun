// SPDX-License-Identifier: Apache-2.0
//! HVF-specific topology, clock and interrupt-controller state.
use super::*;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::resources::VmResources;
use crate::vstate::{VcpuConfig, Vm};
use devices::legacy::gic::GICDevice;
use devices::legacy::{GicV3, HvfGicV3, IrqChip, IrqChipDevice, VcpuList};
use devices::DeviceType;
use polly::event_manager::EventManager;
use std::os::fd::BorrowedFd;
use std::sync::atomic::AtomicI32;
use utils::eventfd::EFD_NONBLOCK;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

pub(crate) struct Runtime {
    intc: IrqChip,
    cpus: Arc<VcpuList>,
    pub(crate) paused_at: Option<u64>,
}
impl Runtime {
    pub(crate) fn new(intc: IrqChip, cpus: Arc<VcpuList>) -> Self {
        Self {
            intc,
            cpus,
            paused_at: None,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmState {
    native_gic: bool,
    gic_properties: Vec<u64>,
    gic: Vec<u8>,
    pending: Vec<Vec<u32>>,
    clock: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyState {
    pub serial_endpoints: usize,
    devices: Vec<LegacyDevice>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDevice {
    kind: String,
    address: u64,
    irq: u32,
    state: Vec<u8>,
}

impl Vmm {
    pub(crate) fn resume_hvf_clock(&mut self) -> io::Result<()> {
        if let Some(ticks) = self.hvf_state.paused_at {
            let delta = unsafe { ::hvf::mach_absolute_time() }.wrapping_sub(ticks);
            let deadline = Instant::now() + CONTROL_TIMEOUT;
            for cpu in &mut self.vcpus_handles {
                cpu.control(Command::AdjustClock(delta), deadline)
                    .map_err(other)?;
            }
            self.hvf_state.paused_at = None;
        }
        Ok(())
    }
    pub(super) fn irq_bindings(&self, _: &[LiveDevice]) -> io::Result<Vec<(EventFd, u32)>> {
        Ok(Vec::new())
    }
    pub(super) fn save_hvf_vm(&self) -> io::Result<VmState> {
        let intc = self.hvf_state.intc.lock().unwrap();
        Ok(VmState {
            native_gic: intc.is_native(),
            gic_properties: intc.device_properties(),
            gic: intc.save_state()?,
            pending: self.hvf_state.cpus.save_pending(),
            clock: self
                .hvf_state
                .paused_at
                .ok_or_else(|| invalid("HVF clock is not frozen"))?,
        })
    }
    pub(super) fn save_hvf_legacy(&self) -> io::Result<LegacyState> {
        let mut devices = Vec::new();
        let mut serial_endpoints = 0;
        for ((kind, id), info) in self.mmio_device_manager.get_device_info() {
            if matches!(kind, DeviceType::Virtio(_)) {
                continue;
            }
            let bus = self
                .mmio_device_manager
                .get_device(*kind, id)
                .unwrap()
                .lock()
                .unwrap();
            let state = match kind {
                DeviceType::Serial => {
                    serial_endpoints += 1;
                    bus.as_any()
                        .downcast_ref::<devices::legacy::Serial>()
                        .unwrap()
                        .save_state()?
                }
                DeviceType::RTC => bus
                    .as_any()
                    .downcast_ref::<devices::legacy::RTC>()
                    .unwrap()
                    .save_state()?,
                DeviceType::Gpio => bus
                    .as_any()
                    .downcast_ref::<devices::legacy::Gpio>()
                    .unwrap()
                    .save_state()?,
                _ => return Err(invalid("unsupported ARM legacy device")),
            };
            devices.push(LegacyDevice {
                kind: kind.to_string(),
                address: info.addr,
                irq: info.irq,
                state,
            });
        }
        devices.sort_by_key(|d| d.address);
        Ok(LegacyState {
            serial_endpoints,
            devices,
        })
    }
}
pub(super) fn validate(saved: &Metadata) -> io::Result<()> {
    if saved.arch_memory[4] != unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64
        || saved.hotplug_len.is_some()
        || !saved.irq_counts.is_empty()
        || saved.vm.pending.len() != saved.cpus.len()
        || saved.vm.gic.is_empty()
        || saved.vm.gic_properties.len() != 4
        || saved.legacy.serial_endpoints > 1
        || saved.legacy.devices.len() > 3
    {
        return Err(invalid("incompatible HVF topology"));
    }
    Ok(())
}
pub(super) fn build(
    saved: &Metadata,
    memory: GuestMemoryMmap,
    resources: &VmResources,
    events: &mut EventManager,
    shutdown_efd: Option<EventFd>,
) -> io::Result<(Vmm, IrqChip)> {
    let mut vm = Vm::new(false).map_err(other)?;
    let cpus = Arc::new(VcpuList::new(saved.cpus.len() as u64));
    let intc = Arc::new(Mutex::new(IrqChipDevice::new(if saved.vm.native_gic {
        Box::new(HvfGicV3::new(saved.cpus.len() as u64).map_err(other)?)
    } else {
        Box::new(GicV3::new(cpus.clone()))
    })));
    let properties = intc.lock().unwrap().device_properties();
    if properties != saved.vm.gic_properties {
        return Err(invalid("incompatible GIC address layout"));
    }
    for region in memory.iter() {
        let start = region.start_addr().raw_value();
        let end = start + region.len();
        for pair in properties.as_chunks::<2>().0 {
            if start < pair[0] + pair[1] && end > pair[0] {
                return Err(invalid("RAM overlaps GIC"));
            }
        }
    }
    vm.memory_init(&memory).map_err(other)?;
    let exit_evt = EventFd::new(EFD_NONBLOCK)?;
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
        serials.push(crate::builder::setup_serial_device(events, input, output).map_err(other)?);
    }
    let mut base = arch::MMIO_MEM_START;
    let mut mmio = MMIODeviceManager::new(&mut base, (arch::IRQ_BASE, arch::IRQ_MAX));
    let mut cmdline = kernel::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
    let gpio = if saved
        .legacy
        .devices
        .iter()
        .any(|d| d.kind == DeviceType::Gpio.to_string())
    {
        Some(shutdown_efd.ok_or_else(|| invalid("missing GPIO shutdown endpoint"))?)
    } else {
        None
    };
    crate::builder::attach_legacy_devices(
        &vm,
        &mut mmio,
        &mut cmdline,
        intc.clone(),
        serials,
        events,
        gpio,
    )
    .map_err(other)?;
    let info = saved.arch_memory;
    let vmm = Vmm {
        guest_memory: memory,
        arch_memory_info: arch::ArchMemoryInfo {
            ram_start_addr: info[0],
            fdt_addr: info[1],
            ram_last_addr: info[2],
            shm_start_addr: info[3],
            page_size: info[4] as usize,
            initrd_addr: info[5],
            firmware_addr: info[6],
        },
        kernel_cmdline: cmdline,
        vcpus_handles: Vec::new(),
        checkpoint_supported: true,
        checkpoint_dirs: Vec::new(),
        vcpus_paused: true,
        vcpus_failed: false,
        exit_evt,
        vm,
        exit_observers: Vec::new(),
        exit_code: Arc::new(AtomicI32::new(i32::MAX)),
        mmio_device_manager: mmio,
        hvf_state: Runtime::new(intc.clone(), cpus),
    };
    let topology = vmm.save_hvf_legacy()?;
    if topology.devices.len() != saved.legacy.devices.len()
        || topology
            .devices
            .iter()
            .zip(&saved.legacy.devices)
            .any(|(a, b)| a.kind != b.kind || a.address != b.address || a.irq != b.irq)
    {
        return Err(invalid("ARM legacy topology mismatch"));
    }
    Ok((vmm, intc))
}
pub(super) fn restore_platform(vmm: &mut Vmm, saved: &Metadata) -> io::Result<()> {
    for device in &saved.legacy.devices {
        let mut bus = vmm
            .mmio_device_manager
            .bus
            .get_device(device.address)
            .unwrap()
            .1
            .lock()
            .unwrap();
        let any = bus.as_mut_any();
        if let Some(serial) = any.downcast_mut::<devices::legacy::Serial>() {
            serial.restore_state(&device.state)?;
        } else if let Some(rtc) = any.downcast_mut::<devices::legacy::RTC>() {
            rtc.restore_state(&device.state)?;
        } else if let Some(gpio) = any.downcast_mut::<devices::legacy::Gpio>() {
            gpio.restore_state(&device.state)?;
        } else {
            return Err(invalid("invalid legacy device"));
        }
    }
    let config = VcpuConfig {
        vcpu_count: saved.cpus.len() as u8,
        ht_enabled: false,
        cpu_template: None,
    };
    let mut cpus = crate::builder::create_vcpus_aarch64(
        &vmm.vm,
        &config,
        &vmm.arch_memory_info,
        GuestAddress(0),
        &vmm.exit_evt,
        vmm.hvf_state.cpus.clone(),
        false,
    )
    .map_err(other)?;
    for cpu in &mut cpus {
        cpu.native_gic = saved.vm.native_gic;
    }
    vmm.start_vcpus_paused(cpus).map_err(other)?;
    vmm.hvf_state
        .intc
        .lock()
        .unwrap()
        .restore_state(&saved.vm.gic)?;
    vmm.hvf_state.cpus.restore_pending(&saved.vm.pending)?;
    vmm.hvf_state.paused_at = Some(saved.vm.clock);
    Ok(())
}
