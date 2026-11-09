// SPDX-License-Identifier: Apache-2.0

//! Whole-VM checkpoint ownership. Operations run on the event-loop thread;
//! its subscriber callback is the barrier for event-loop memory writers.
//! Disk image contents belong to the embedding application.

#[cfg(target_os = "macos")]
pub(crate) mod hvf;
mod restore;
#[cfg(test)]
mod tests;
#[cfg(target_os = "macos")]
use hvf::LegacyState;
#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux-x86_64-kvm";
#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos-aarch64-hvf";

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use devices::virtio::console::ConsoleState;
use devices::virtio::fs::FsDeviceState;
#[cfg(target_os = "linux")]
use devices::virtio::mem::{Mem, MemState};
#[cfg(feature = "net")]
use devices::virtio::net::{Net, NetCheckpoint};
use devices::virtio::persist::{EventDeviceState, MmioTransportState, QueueState};
use devices::virtio::vsock::{Vsock, VsockState};
#[cfg(feature = "blk")]
use devices::virtio::{block::BlockState, Block};
use devices::virtio::{Balloon, Console, Fs, MmioTransport, Rng, VirtioDevice};

use serde::{Deserialize, Serialize};
use utils::eventfd::EventFd;

use crate::vstate::control::{Command, Reply};
use crate::vstate::{VcpuState, VmState};
use crate::Vmm;

pub use restore::restore;

const MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const VERSION: u32 = 2;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    platform: String,
    arch_memory: [u64; 8],
    ram_len: u64,
    hotplug_len: Option<u64>,
    vm: VmState,
    cpus: Vec<Box<VcpuState>>,
    devices: Vec<DeviceRecord>,
    legacy: LegacyState,
    irq_counts: Vec<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    cmos_index: u8,
    cmos: Vec<u8>,
    keyboard: devices::legacy::I8042State,
    serial: Vec<Option<devices::legacy::SerialState>>,
    serial_endpoints: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecord {
    id: String,
    address: u64,
    irq: u32,
    transport: MmioTransportState,
    state: DeviceSnapshot,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "state", deny_unknown_fields)]
enum DeviceSnapshot {
    Vsock(VsockState),
    #[cfg(feature = "net")]
    Net(NetCheckpoint),
    Console(ConsoleState, Option<Vec<QueueState>>),
    Fs(FsDeviceState),
    Rng(EventDeviceState),
    Balloon(EventDeviceState),
    #[cfg(target_os = "linux")]
    Memory(MemState),
    #[cfg(feature = "blk")]
    Block(BlockState),
}

struct LiveDevice {
    id: String,
    address: u64,
    irq: u32,
    device: Arc<Mutex<dyn VirtioDevice>>,
    #[cfg(target_os = "linux")]
    interrupt: EventFd,
}

impl Drop for Vmm {
    fn drop(&mut self) {
        // Rust would otherwise drop guest_memory before vcpus_handles. In a
        // failed restore, no event-loop owner remains to retain the VM for us.
        for handle in &mut self.vcpus_handles {
            handle.stop_and_join();
        }
        for ((kind, id), _) in self.mmio_device_manager.get_device_info() {
            if let Some(bus) = self.mmio_device_manager.get_device(*kind, id) {
                let bus = bus.lock().unwrap();
                if let Some(transport) = bus.as_any().downcast_ref::<MmioTransport>() {
                    join_device(&mut *transport.device().lock().unwrap());
                }
            }
        }
    }
}

fn join_device(device: &mut dyn VirtioDevice) {
    if let Some(vsock) = device.as_mut_any().downcast_mut::<Vsock>() {
        if let Err(error) = vsock.stop_backend() {
            error!("failed to stop vsock backend during teardown: {error:?}");
        }
        return;
    }
    #[cfg(feature = "net")]
    if let Some(net) = device.as_mut_any().downcast_mut::<Net>() {
        net.stop_worker();
        return;
    }
    device.reset();
}

impl Vmm {
    /// An uncertain CPU/device transition makes this VM permanently unusable.
    pub fn checkpoint_failed(&self) -> bool {
        self.vcpus_failed
    }

    fn checkpoint_devices(&self) -> io::Result<Vec<LiveDevice>> {
        let mut result = Vec::new();
        for ((kind, id), info) in self.mmio_device_manager.get_device_info() {
            #[cfg(target_os = "macos")]
            if !matches!(kind, devices::DeviceType::Virtio(_)) {
                continue;
            }
            let bus = self
                .mmio_device_manager
                .get_device(*kind, id)
                .ok_or_else(|| invalid("missing MMIO device"))?
                .lock()
                .unwrap();
            let transport = bus
                .as_any()
                .downcast_ref::<MmioTransport>()
                .ok_or_else(|| invalid("non-virtio MMIO device"))?;
            let device = transport.device();
            {
                let locked = device.lock().unwrap();
                let any = locked.as_any();
                let supported = any.is::<Console>()
                    || any.is::<Fs>()
                    || any.is::<Rng>()
                    || any.is::<Balloon>()
                    || any.is::<Vsock>();
                #[cfg(target_os = "linux")]
                let supported = supported || any.is::<Mem>();
                #[cfg(feature = "blk")]
                let supported = supported || any.is::<Block>();
                #[cfg(feature = "net")]
                let supported = supported || any.is::<Net>();
                if !supported {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "checkpoint device {} is not supported",
                            locked.device_name()
                        ),
                    ));
                }
                if locked.shm_region().is_some() && !any.is::<Fs>() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "checkpoint cannot capture shared host mappings",
                    ));
                }
                if let Some(console) = any.downcast_ref::<Console>() {
                    console.check_snapshot_support().map_err(other)?;
                }
            }
            result.push(LiveDevice {
                id: id.clone(),
                address: info.addr,
                #[cfg(target_os = "linux")]
                irq: info._irq,
                #[cfg(target_os = "macos")]
                irq: info.irq,
                device,
                #[cfg(target_os = "linux")]
                interrupt: transport.interrupt_evt().try_clone()?,
            });
        }
        result.sort_by_key(|device| device.address);
        Ok(result)
    }

    pub fn is_paused(&self) -> bool {
        self.vcpus_paused
    }

    /// Called by the event-loop owner, which must keep event dispatch stopped
    /// until resume. The C runtime also quiesces vsock before taking VM locks.
    pub fn pause(&mut self) -> io::Result<()> {
        if self.vcpus_failed {
            return Err(io::Error::from_raw_os_error(libc::ESHUTDOWN));
        }
        if self.vcpus_paused {
            return Ok(());
        }
        let devices = match self.checkpoint_devices().and_then(|devices| {
            if !self.checkpoint_supported {
                return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
            }
            Ok(devices)
        }) {
            Ok(devices) => devices,
            Err(error) => {
                self.recover_quiesced_vsock()?;
                return Err(error);
            }
        };
        #[cfg(target_os = "linux")]
        for device in &devices {
            if let Some(memory) = device
                .device
                .lock()
                .unwrap()
                .as_mut_any()
                .downcast_mut::<Mem>()
            {
                memory.freeze();
            }
        }
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let result = (|| {
            self.pause_vcpus(deadline).map_err(other)?;
            for device in &devices {
                freeze_device(&mut *device.device.lock().unwrap(), deadline)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.abort_checkpoint(&devices);
        }
        result
    }

    fn recover_quiesced_vsock(&mut self) -> io::Result<()> {
        if let Some(bus) = self.mmio_device_manager.get_device(
            devices::DeviceType::Virtio(devices::virtio::TYPE_VSOCK),
            "vsock",
        ) {
            let bus = bus.lock().unwrap();
            let device = bus
                .as_any()
                .downcast_ref::<MmioTransport>()
                .unwrap()
                .device();
            let mut device = device.lock().unwrap();
            if let Some(vsock) = device.as_mut_any().downcast_mut::<Vsock>() {
                if let Err(error) = vsock.recover_quiesced() {
                    drop(device);
                    drop(bus);
                    let devices = self.checkpoint_devices().unwrap_or_default();
                    self.abort_checkpoint(&devices);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub fn resume(&mut self) -> io::Result<()> {
        if self.vcpus_failed {
            return Err(io::Error::from_raw_os_error(libc::ESHUTDOWN));
        }
        if !self.vcpus_paused {
            return Ok(());
        }
        let devices = self.checkpoint_devices()?;
        let result = (|| {
            for device in &devices {
                resume_device(&mut *device.device.lock().unwrap())?;
            }
            self.resume_vcpus().map_err(other)
        })();
        if result.is_err() {
            self.abort_checkpoint(&devices);
        }
        result
    }

    /// Save a confirmed paused VM. Storage failures and success both preserve
    /// the pause so the application can capture disks at the same boundary.
    pub fn save_checkpoint(&mut self, path: &Path) -> io::Result<()> {
        if self.vcpus_failed {
            return Err(io::Error::from_raw_os_error(libc::ESHUTDOWN));
        }
        if !self.vcpus_paused {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let devices = self.checkpoint_devices()?;
        let bindings = self.irq_bindings(&devices)?;
        if path.try_exists()? {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staging = utils::tempdir::TempDir::new_with_prefix(
            parent.canonicalize()?.join(".krun-checkpoint-"),
        )
        .map_err(other)?;
        let staged_file = staging.as_path().join("checkpoint");
        #[cfg(target_os = "linux")]
        let mut detached = 0;
        let mut counts = Vec::new();
        let saved = (|| {
            for (event, _irq) in &bindings {
                #[cfg(target_os = "linux")]
                {
                    self.vm.fd().unregister_irqfd(event, *_irq).map_err(other)?;
                    detached += 1;
                }
                counts.push(drain(event)?);
            }
            self.write_checkpoint(&staged_file, &devices, counts.clone())
        })();
        // Restore IRQ delivery without restarting CPU/device writers.
        let recovered: io::Result<()> = (|| {
            #[cfg(target_os = "linux")]
            for (index, (event, irq)) in bindings.iter().take(detached).enumerate() {
                if let Some(&count) = counts.get(index) {
                    if count != 0 {
                        event.write(count)?;
                    }
                }
                self.vm.fd().register_irqfd(event, *irq).map_err(other)?;
            }
            Ok(())
        })();
        if let Err(error) = recovered {
            self.abort_checkpoint(&devices);
            return Err(error);
        }
        saved?;
        publish(&staged_file, path)?;
        File::open(parent)?.sync_all()
    }

    fn abort_checkpoint(&mut self, devices: &[LiveDevice]) {
        self.vcpus_failed = true;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let _ = self.stop_vcpus(deadline);
        for device in devices {
            let mut device = device.device.lock().unwrap();
            if let Some(vsock) = device.as_mut_any().downcast_mut::<Vsock>() {
                let _ = vsock.freeze(deadline);
            }
            #[cfg(feature = "blk")]
            if let Some(block) = device.as_mut_any().downcast_mut::<Block>() {
                let _ = block.stop_worker(deadline);
            }
            if let Some(fs) = device.as_mut_any().downcast_mut::<Fs>() {
                let _ = fs.stop_worker(deadline);
            }
            if let Some(console) = device.as_mut_any().downcast_mut::<Console>() {
                console.reset();
            }
            #[cfg(feature = "net")]
            if let Some(net) = device.as_mut_any().downcast_mut::<Net>() {
                net.stop_worker();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn irq_bindings(&self, devices: &[LiveDevice]) -> io::Result<Vec<(EventFd, u32)>> {
        let mut bindings = Vec::new();
        for device in devices {
            bindings.push((device.interrupt.try_clone()?, device.irq));
        }
        let pio = &self.pio_device_manager;
        for (fd, irq) in [
            (&pio.com_evt_1, 4),
            (&pio.com_evt_2, 3),
            (&pio.com_evt_3, 4),
            (&pio.com_evt_4, 3),
            (&pio.kbd_evt, 1),
        ] {
            bindings.push((fd.try_clone()?, irq));
        }
        Ok(bindings)
    }

    fn write_checkpoint(
        &mut self,
        path: &Path,
        devices: &[LiveDevice],
        irq_counts: Vec<u64>,
    ) -> io::Result<()> {
        if self.exit_code.load(std::sync::atomic::Ordering::Acquire) != i32::MAX {
            return Err(invalid("VM is exiting"));
        }
        let exiting = drain(&self.exit_evt)?;
        if exiting != 0 {
            self.exit_evt.write(exiting)?;
            return Err(invalid("VM is exiting"));
        }
        let ordinary_memory = without_dax(&self.guest_memory, devices)?;
        #[cfg(target_os = "linux")]
        let (memory_device, memory_guard, memory_state, accessible, boot) = {
            let memory_device = devices
                .iter()
                .find(|d| d.device.lock().unwrap().as_any().is::<Mem>());
            let memory_guard = memory_device.map(|d| d.device.lock().unwrap());
            let hotplug = memory_guard
                .as_ref()
                .map(|d| d.as_any().downcast_ref::<Mem>().unwrap());
            let boot = match hotplug {
                Some(device) => device.boot_memory(&ordinary_memory)?,
                None => ordinary_memory.clone(),
            };
            // Raw aliases remain under the frozen memory-device lock until every
            // queue validation is complete, and cannot escape this function.
            let accessible = match hotplug {
                Some(device) => unsafe { device.accessible_memory(&self.guest_memory)? },
                None => boot.clone(),
            };
            let memory_state = hotplug.map(Mem::save_state).transpose()?;
            (memory_device, memory_guard, memory_state, accessible, boot)
        };
        #[cfg(target_os = "macos")]
        let (accessible, boot) = (self.guest_memory.clone(), ordinary_memory);
        let ram_len = crate::ram_snapshot::file_size(&boot)?;
        #[cfg(target_os = "linux")]
        let hotplug_len = memory_state.as_ref().map(MemState::memory_bytes);
        #[cfg(target_os = "macos")]
        let hotplug_len = None;
        let mut records = Vec::new();
        for live in devices {
            let transport = {
                let bus = self
                    .mmio_device_manager
                    .bus
                    .get_device(live.address)
                    .unwrap()
                    .1
                    .lock()
                    .unwrap();
                // Do not relock the memory device while holding memory_guard.
                #[cfg(target_os = "linux")]
                if memory_device.is_some_and(|d| d.address == live.address) {
                    drop(bus);
                    continue;
                }
                bus.as_any()
                    .downcast_ref::<MmioTransport>()
                    .unwrap()
                    .save_state()?
            };
            let device = live.device.lock().unwrap();
            let any = device.as_any();
            #[cfg(feature = "net")]
            if let Some(net) = any.downcast_ref::<Net>() {
                let state = net.save_state()?;
                if let Some(queues) = &state.queues {
                    transport
                        .device
                        .restore_queues(&[queues.rx.clone(), queues.tx.clone()], &accessible)?;
                }
                records.push(DeviceRecord {
                    id: live.id.clone(),
                    address: live.address,
                    irq: live.irq,
                    transport,
                    state: DeviceSnapshot::Net(state),
                });
                continue;
            }
            let (state, queues) = if let Some(vsock) = any.downcast_ref::<Vsock>() {
                let state = vsock.save_state()?;
                let queues = state.queues.clone();
                (DeviceSnapshot::Vsock(state), queues)
            } else if let Some(console) = any.downcast_ref::<Console>() {
                let state = console.snapshot_state().map_err(other)?;
                let queues = console.snapshot_queue_states().map_err(other)?;
                if let Some(queues) = &queues {
                    state
                        .validate_guest(&accessible, queues, true)
                        .map_err(other)?;
                }
                (DeviceSnapshot::Console(state, queues.clone()), queues)
            } else if let Some(fs) = any.downcast_ref::<Fs>() {
                let state = fs.save_state()?;
                let queues = state.worker.as_ref().map(|w| w.queues.clone());
                (DeviceSnapshot::Fs(state), queues)
            } else if let Some(rng) = any.downcast_ref::<Rng>() {
                let state = rng.save_state()?;
                let queues = state.queues.clone();
                (DeviceSnapshot::Rng(state), queues)
            } else if let Some(balloon) = any.downcast_ref::<Balloon>() {
                let state = balloon.save_state()?;
                let queues = state.queues.clone();
                (DeviceSnapshot::Balloon(state), queues)
            } else {
                #[cfg(feature = "blk")]
                {
                    let block = any
                        .downcast_ref::<Block>()
                        .ok_or_else(|| invalid("unsupported checkpoint device"))?;
                    let state = block.save_state()?;
                    let queues = state.queue.clone().map(|q| vec![q]);
                    (DeviceSnapshot::Block(state), queues)
                }
                #[cfg(not(feature = "blk"))]
                {
                    return Err(invalid("unsupported checkpoint device"));
                }
            };
            if let Some(queues) = queues {
                transport.device.restore_queues(&queues, &accessible)?;
            }
            records.push(DeviceRecord {
                id: live.id.clone(),
                address: live.address,
                irq: live.irq,
                transport,
                state,
            });
        }
        drop(accessible);
        #[cfg(target_os = "linux")]
        drop(memory_guard);
        #[cfg(target_os = "linux")]
        if let (Some(live), Some(state)) = (memory_device, memory_state) {
            let bus = self
                .mmio_device_manager
                .bus
                .get_device(live.address)
                .unwrap()
                .1
                .lock()
                .unwrap();
            let transport = bus
                .as_any()
                .downcast_ref::<MmioTransport>()
                .unwrap()
                .save_state()?;
            records.push(DeviceRecord {
                id: live.id.clone(),
                address: live.address,
                irq: live.irq,
                transport,
                state: DeviceSnapshot::Memory(state),
            });
        }
        records.sort_by_key(|record| record.address);
        let mut cpus = Vec::new();
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        for handle in &mut self.vcpus_handles {
            match handle.control(Command::Capture, deadline).map_err(other)? {
                Reply::Saved(state) => cpus.push(state),
                _ => return Err(invalid("missing vCPU state")),
            }
        }
        #[cfg(target_os = "linux")]
        let legacy = {
            let cmos = self.pio_device_manager.cmos.lock().unwrap().save_state();
            let mut serial = Vec::new();
            for address in [0x3f8, 0x2f8, 0x3e8, 0x2e8] {
                serial.push(self.pio_device_manager.io_bus.get_device(address).map(
                    |(_, device)| {
                        device
                            .lock()
                            .unwrap()
                            .as_any()
                            .downcast_ref::<devices::legacy::Serial>()
                            .unwrap()
                            .save_state()
                    },
                ));
            }
            LegacyState {
                cmos_index: cmos.index,
                cmos: cmos.data.to_vec(),
                keyboard: self.pio_device_manager.i8042.lock().unwrap().save_state(),
                serial,
                serial_endpoints: self.pio_device_manager.stdio_serial.len(),
            }
        };
        #[cfg(target_os = "macos")]
        let legacy = self.save_hvf_legacy()?;
        let info = &self.arch_memory_info;
        let metadata = Metadata {
            version: VERSION,
            platform: PLATFORM.into(),
            #[cfg(target_os = "linux")]
            arch_memory: [
                info.ram_below_gap,
                info.ram_above_gap,
                info.ram_last_addr,
                info.shm_start_addr,
                info.page_size as u64,
                info.initrd_addr,
                info.firmware_addr,
                0,
            ],
            #[cfg(target_os = "macos")]
            arch_memory: [
                info.ram_start_addr,
                info.fdt_addr,
                info.ram_last_addr,
                info.shm_start_addr,
                info.page_size as u64,
                info.initrd_addr,
                info.firmware_addr,
                0,
            ],
            ram_len,
            hotplug_len,
            #[cfg(target_os = "linux")]
            vm: self.vm.save_state().map_err(other)?,
            #[cfg(target_os = "macos")]
            vm: self.save_hvf_vm()?,
            cpus,
            devices: records,
            legacy,
            irq_counts,
        };
        let bytes = serde_json::to_vec(&metadata).map_err(other)?;
        if bytes.len() > MAX_METADATA {
            return Err(invalid("checkpoint metadata exceeds limit"));
        }
        let mut file = create_file(path)?;
        file.write_all(MAGIC)?;
        file.write_all(&VERSION.to_le_bytes())?;
        file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        file.write_all(&bytes)?;
        let ram_offset = file.stream_position()?;
        crate::ram_snapshot::save_file_at(&boot, &mut file, ram_offset)?;
        file.seek(SeekFrom::Start(ram_offset + ram_len))?;
        #[cfg(target_os = "linux")]
        if let Some(live) = memory_device {
            let device = live.device.lock().unwrap();
            device
                .as_any()
                .downcast_ref::<Mem>()
                .unwrap()
                .save_memory(&mut file)?;
        }
        file.sync_all()
    }
}

fn freeze_device(device: &mut dyn VirtioDevice, deadline: Instant) -> io::Result<()> {
    let any = device.as_mut_any();
    if let Some(vsock) = any.downcast_mut::<Vsock>() {
        return vsock.freeze(deadline);
    }
    #[cfg(feature = "net")]
    if let Some(net) = any.downcast_mut::<Net>() {
        return net.freeze(deadline);
    }
    if let Some(console) = any.downcast_mut::<Console>() {
        return console
            .snapshot_freeze_with_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(other);
    }
    if let Some(fs) = any.downcast_mut::<Fs>() {
        return fs.freeze(deadline);
    }
    #[cfg(feature = "blk")]
    if let Some(block) = any.downcast_mut::<Block>() {
        return block.freeze(deadline);
    }
    if let Some(rng) = any.downcast_mut::<Rng>() {
        rng.freeze();
    }
    if let Some(balloon) = any.downcast_mut::<Balloon>() {
        balloon.freeze();
    }
    #[cfg(target_os = "linux")]
    if let Some(mem) = any.downcast_mut::<Mem>() {
        mem.freeze();
    }
    Ok(())
}

fn resume_device(device: &mut dyn VirtioDevice) -> io::Result<()> {
    let any = device.as_mut_any();
    if let Some(vsock) = any.downcast_mut::<Vsock>() {
        return vsock.resume();
    }
    #[cfg(feature = "net")]
    if let Some(net) = any.downcast_mut::<Net>() {
        return net.resume();
    }
    if let Some(console) = any.downcast_mut::<Console>() {
        return console.snapshot_resume().map_err(other);
    }
    if let Some(fs) = any.downcast_mut::<Fs>() {
        return fs.resume(Instant::now() + CONTROL_TIMEOUT);
    }
    #[cfg(feature = "blk")]
    if let Some(block) = any.downcast_mut::<Block>() {
        return block.resume(Instant::now() + CONTROL_TIMEOUT);
    }
    if let Some(rng) = any.downcast_mut::<Rng>() {
        return rng.resume();
    }
    if let Some(balloon) = any.downcast_mut::<Balloon>() {
        return balloon.resume();
    }
    #[cfg(target_os = "linux")]
    if let Some(mem) = any.downcast_mut::<Mem>() {
        return mem.resume();
    }
    Err(invalid("unsupported device resume"))
}

fn drain(event: &EventFd) -> io::Result<u64> {
    let mut poll = libc::pollfd {
        fd: event.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        Ok(0)
    } else {
        event.read()
    }
}
fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(path)
}

fn open_file(path: &Path) -> io::Result<File> {
    // Reject FIFOs by descriptor without waiting for a peer during open.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("checkpoint artifact is not a regular file"));
    }
    Ok(file)
}
fn without_dax(
    memory: &vm_memory::GuestMemoryMmap,
    devices: &[LiveDevice],
) -> io::Result<vm_memory::GuestMemoryMmap> {
    let mut ram = memory.clone();
    for live in devices {
        let device = live.device.lock().unwrap();
        if device.as_any().is::<Fs>() {
            if let Some(window) = device.shm_region() {
                ram = ram
                    .remove_region(
                        vm_memory::GuestAddress(window.guest_addr),
                        window.size as u64,
                    )
                    .map_err(other)?
                    .0;
            }
        }
    }
    Ok(ram)
}

fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_bytes()).map_err(other)?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes()).map_err(other)?;
    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let ret = unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
