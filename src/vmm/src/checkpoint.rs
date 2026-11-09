// SPDX-License-Identifier: Apache-2.0

//! Whole-VM checkpoint ownership. Operations run on the event-loop thread;
//! its subscriber callback is the barrier for event-loop memory writers.
//! Block image flattening belongs to the caller's existing image implementation.

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
use std::io::{self, Read, Write};
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
use devices::virtio::{block::BlockState, block::ImageType, Block};
use devices::virtio::{Balloon, Console, Fs, MmioTransport, Rng, VirtioDevice};

use serde::{Deserialize, Serialize};
use utils::eventfd::EventFd;

use crate::vstate::control::{Command, Reply};
use crate::vstate::{VcpuState, VmState};
use crate::Vmm;

pub use restore::restore;

const MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const VERSION: u32 = 1;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Called only after all guest/device writers stopped and disk sync completed.
/// Produce a standalone image at destination, without modifying source. For
/// QCOW2 the application should invoke its existing flatten implementation.
pub type Flatten<'a> = dyn FnMut(&str, &Path, &Path, u32) -> io::Result<()> + 'a;

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    len: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    platform: String,
    arch_memory: [u64; 8],
    ram: Artifact,
    hotplug: Option<Artifact>,
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
    Block(BlockState, Artifact, u32),
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
        #[cfg(target_os = "linux")]
        if !self.checkpoint_enabled {
            return;
        }
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
                    return Err(invalid("checkpoint cannot capture shared host mappings"));
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

    /// Save and resume a VM. Must be called by its event-loop thread with no
    /// concurrent event dispatch or external guest-memory aliases. The runtime
    /// C request path provides that ownership; direct Rust callers must too.
    pub fn save_checkpoint(&mut self, path: &Path, flatten: &mut Flatten<'_>) -> io::Result<()> {
        let result = self.save_checkpoint_inner(path, flatten);
        if !self.vcpus_failed {
            let recovery = (|| {
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
                    if let Some(vsock) = device.lock().unwrap().as_mut_any().downcast_mut::<Vsock>()
                    {
                        vsock.recover_quiesced()?;
                    };
                }
                Ok(())
            })();
            if let Err(error) = recovery {
                let devices = self.checkpoint_devices().unwrap_or_default();
                self.abort_checkpoint(&devices);
                return Err(error);
            }
        }
        result
    }

    fn save_checkpoint_inner(&mut self, path: &Path, flatten: &mut Flatten<'_>) -> io::Result<()> {
        if !self.checkpoint_enabled || self.vcpus_failed || self.vcpus_paused {
            return Err(invalid("checkpoint requires an enabled, running VM"));
        }
        let devices = self.checkpoint_devices()?;
        let bindings = self.irq_bindings(&devices)?;
        if path.exists() {
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
        // Online hotplug targets join the same boundary as guest requests.
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
        if let Err(error) = self.pause_vcpus(deadline) {
            self.abort_checkpoint(&devices);
            return Err(other(error));
        }
        for device in &devices {
            let frozen = freeze_device(&mut *device.device.lock().unwrap(), deadline);
            if let Err(error) = frozen {
                self.abort_checkpoint(&devices);
                return Err(error);
            }
        }
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
            self.write_checkpoint(staging.as_path(), &devices, counts.clone(), flatten)
        })();
        if let Err(error) = &saved {
            error!("checkpoint capture failed: {error}");
        }
        // Even storage/flatten failure releases a confirmed barrier. An unknown
        // control/IRQ outcome instead permanently disables and stops the VM.
        let resumed = (|| {
            #[cfg(target_os = "linux")]
            for (index, (event, irq)) in bindings.iter().take(detached).enumerate() {
                if let Some(&count) = counts.get(index) {
                    if count != 0 {
                        event.write(count)?;
                    }
                }
                self.vm.fd().register_irqfd(event, *irq).map_err(other)?;
            }
            for device in &devices {
                resume_device(&mut *device.device.lock().unwrap())?;
            }
            self.resume_vcpus().map_err(other)
        })();
        if let Err(error) = resumed {
            self.abort_checkpoint(&devices);
            return Err(error);
        }
        saved?;
        publish(staging.as_path(), path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
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
        directory: &Path,
        devices: &[LiveDevice],
        irq_counts: Vec<u64>,
        _flatten: &mut Flatten<'_>,
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
        let (memory_device, memory_guard, memory_state, accessible, ram, hotplug_artifact) = {
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
            let ram = write_ram(directory, &boot)?;
            let hotplug_artifact = if let Some(device) = hotplug {
                let mut file = create_file(&directory.join("hotplug.bin"))?;
                device.save_memory(&mut file)?;
                file.sync_all()?;
                Some(artifact(directory, "hotplug.bin")?)
            } else {
                None
            };
            let memory_state = hotplug.map(Mem::save_state).transpose()?;
            (
                memory_device,
                memory_guard,
                memory_state,
                accessible,
                ram,
                hotplug_artifact,
            )
        };
        #[cfg(target_os = "macos")]
        let (accessible, ram, hotplug_artifact) = (
            self.guest_memory.clone(),
            write_ram(directory, &ordinary_memory)?,
            None,
        );
        let mut records = Vec::new();
        for (_index, live) in devices.iter().enumerate() {
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
                    let (source, format) = block.checkpoint_source();
                    let format = match format {
                        ImageType::Raw => 0,
                        ImageType::Qcow2 => 1,
                        ImageType::Vmdk => {
                            return Err(invalid("standalone VMDK export is not implemented"))
                        }
                    };
                    let name = format!("disk-{_index}.img");
                    _flatten(&live.id, Path::new(source), &directory.join(&name), format)?;
                    let image = open_file(&directory.join(&name))?;
                    validate_disk(&image, format, &state)?;
                    use std::os::unix::fs::MetadataExt;
                    let source_meta = std::fs::metadata(source)?;
                    let target_meta = image.metadata()?;
                    if source_meta.dev() == target_meta.dev()
                        && source_meta.ino() == target_meta.ino()
                    {
                        return Err(invalid("flatten output aliases the source disk"));
                    }
                    image.sync_all()?;
                    (
                        DeviceSnapshot::Block(state, artifact(directory, &name)?, format),
                        queues,
                    )
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
            ram,
            hotplug: hotplug_artifact,
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
        let mut file = create_file(&directory.join("state.bin"))?;
        file.write_all(MAGIC)?;
        file.write_all(&VERSION.to_le_bytes())?;
        file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(directory)?.sync_all()
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

#[cfg(feature = "blk")]
fn validate_disk(file: &File, format: u32, state: &BlockState) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let capacity = state
        .config
        .get(..8)
        .ok_or_else(|| invalid("missing block capacity"))?;
    let capacity = u64::from_le_bytes(capacity.try_into().unwrap())
        .checked_mul(512)
        .ok_or_else(|| invalid("block capacity overflow"))?;
    let virtual_size = match format {
        0 => file.metadata()?.len(),
        1 => {
            let mut header = [0; 104];
            file.read_exact_at(&mut header, 0)?;
            let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
            if &header[..4] != b"QFI\xfb"
                || !matches!(version, 2 | 3)
                || header[8..20] != [0; 12]
                || (version == 3
                    && u64::from_be_bytes(header[72..80].try_into().unwrap()) & (1 << 2) != 0)
            {
                return Err(invalid(
                    "flatten must produce standalone QCOW2 without an external data file",
                ));
            }
            u64::from_be_bytes(header[24..32].try_into().unwrap())
        }
        _ => return Err(invalid("unsupported independent disk format")),
    };
    if virtual_size < capacity || virtual_size - capacity >= 512 {
        return Err(invalid("flatten changed guest disk capacity"));
    }
    Ok(())
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
fn artifact(directory: &Path, name: &str) -> io::Result<Artifact> {
    Ok(Artifact {
        name: name.into(),
        len: open_file(&directory.join(name))?.metadata()?.len(),
    })
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

fn write_ram(directory: &Path, memory: &vm_memory::GuestMemoryMmap) -> io::Result<Artifact> {
    let mut file = create_file(&directory.join("ram.bin"))?;
    crate::ram_snapshot::save_file(memory, &mut file)?;
    file.sync_all()?;
    artifact(directory, "ram.bin")
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
