// SPDX-License-Identifier: Apache-2.0

//! Production Linux boot of the private owner: the configured payload,
//! command line, vCPUs and BoxLite's devices, cold-booted into an owner
//! that pauses, exports and resumes like every other.
//!
//! `BootImage::new` checks the whole configuration and prepares guest RAM
//! before any VM, device or thread exists; it refuses every feature the
//! owner cannot checkpoint instead of dropping it. Guest RAM is ordinary
//! owned anonymous memory: libkrunfw's kernel is copied in, never mapped,
//! so no host mapping outside the owner aliases guest RAM. Each virtio-fs
//! DAX window keeps the ordinary VMM's guest address above guest RAM, but
//! is the owner's own memslot (`virtio_fs`), never guest RAM or part of
//! the E820 map. The command line is the ordinary VMM's, with every device
//! announced at its fixed owner slot in the ordinary probe order (balloon,
//! RNG, console, virtio-fs shares, disks, vsock, NIC), so guest device
//! names and the boot disk keep their order. `RamSnapshotVm::boot` then
//! attaches the devices, checks they took exactly the announced slots and
//! starts the vCPUs at the kernel entry. An import never comes here: it
//! loads the saved RAM, devices and vCPUs and runs no payload loader or
//! boot setup.

use std::fs::File;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use devices::virtio::{port_io, PortDescription};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::virtio_fs::{self, DaxRange, FsShareConfig};
use super::vsock::{VsockPorts, VSOCK_IRQ, VSOCK_MMIO_ADDR};
use super::wiring::MMIO_LEN;
use super::{console, event_devices, CreatedName, Error, RamSnapshotVm, Result, Topology};
use crate::builder::{self, Payload, StartMicrovmError};
use crate::device_manager::shm::ShmManager;
use crate::resources::VmResources;
use crate::vmm_config::vsock::VsockDeviceConfig;
use crate::vstate::{snapshot, KvmContext, VcpuConfig};
use arch::x86_64::layout::{CMDLINE_START, FIRST_ADDR_PAST_32BITS, MMIO_MEM_START};
use arch::{ArchMemoryInfo, InitrdConfig};

#[cfg(feature = "blk")]
use super::blk;
#[cfg(all(feature = "blk", feature = "net"))]
use super::nic;
#[cfg(feature = "blk")]
use crate::vmm_config::block::BlockDeviceConfig;
#[cfg(all(feature = "blk", feature = "net"))]
use crate::vmm_config::net::NetworkInterfaceConfig;
#[cfg(feature = "blk")]
use devices::virtio::{block::ImageType, block::SyncMode, CacheType};

const PAGE_SIZE: u64 = 4096;

/// The devices `VmResources` holds only built and opened, given unopened
/// instead: the owner opens each itself. A caller must take this branch
/// before the ordinary eager construction of these devices.
#[derive(Default)]
pub(crate) struct BootDevices {
    /// Disks in guest order (the first is `vda`); each must sync fully
    /// and use no direct I/O.
    #[cfg(feature = "blk")]
    pub(crate) disks: Vec<BlockDeviceConfig>,
    /// The NIC; only a UnixStream backend given by path (passt) is
    /// supported. It connects when the guest activates the device.
    #[cfg(all(feature = "blk", feature = "net"))]
    pub(crate) nic: Option<NetworkInterfaceConfig>,
    /// The vsock: Unix IPC ports only, without TSI or TCP port maps.
    pub(crate) vsock: Option<VsockDeviceConfig>,
}

#[cfg(feature = "blk")]
struct Disk {
    path: PathBuf,
    format: ImageType,
    read_only: bool,
    writeback: bool,
}

#[cfg(all(feature = "blk", feature = "net"))]
struct Nic {
    socket: PathBuf,
    mac: [u8; 6],
    features: u32,
}

/// A checked boot configuration with guest RAM prepared: payload, command
/// line, MP table and boot parameters written. Nothing of the VM exists
/// yet.
pub(crate) struct BootImage {
    memory: GuestMemoryMmap,
    memory_hotplug: Option<std::sync::Arc<devices::virtio::mem::MemoryControl>>,
    entry: GuestAddress,
    vcpus: VcpuConfig,
    console: Option<PathBuf>,
    shares: Vec<FsShareConfig>,
    #[cfg(feature = "blk")]
    disks: Vec<Disk>,
    #[cfg(all(feature = "blk", feature = "net"))]
    nic: Option<Nic>,
    vsock: Option<(u64, VsockPorts)>,
    /// Every device's (MMIO address, GSI) in the guest's probe order.
    slots: Vec<(u64, u32)>,
}

fn unsupported(why: &str) -> Error {
    Error::Full(format!("checkpointing boot: {why}"))
}

fn builder_error(what: &str, e: StartMicrovmError) -> Error {
    Error::Full(format!("checkpointing boot: {what}: {e}"))
}

impl BootImage {
    /// Check `resources` and `devices` completely, then prepare guest RAM.
    pub(crate) fn new(resources: &VmResources, devices: BootDevices) -> Result<Self> {
        check_resources(resources)?;
        let vcpus = resources.vcpu_config();
        if vcpus.vcpu_count == 0 || usize::from(vcpus.vcpu_count) > snapshot::MAX_CPUS {
            return Err(unsupported("the vCPU count is zero or above 128"));
        }
        let mem_size_mib = resources
            .vm_config()
            .mem_size_mib
            .ok_or_else(|| unsupported("no memory size is configured"))?;
        let shares = shares(resources)?;
        #[cfg(feature = "blk")]
        let disks = devices.disks.iter().map(disk).collect::<Result<Vec<_>>>()?;
        #[cfg(feature = "blk")]
        if resources.memory_hotplug.is_some() && disks.len() > event_devices::MEMORY_DISK_CAPACITY {
            return Err(unsupported("virtio-mem reserves a disk IRQ: at most six checkpoint disks"));
        }
        #[cfg(all(feature = "blk", feature = "net"))]
        let nic = devices.nic.as_ref().map(nic).transpose()?;
        #[cfg(feature = "blk")]
        check_disk_count(
            disks.len(),
            #[cfg(feature = "net")]
            nic.is_some(),
        )?;
        let vsock = devices.vsock.as_ref().map(vsock).transpose()?;
        let console =
            if resources.disable_implicit_console {
                None
            } else {
                Some(resources.console_output.clone().ok_or_else(|| {
                    unsupported("the implicit console needs a console output file")
                })?)
            };
        let payload = builder::choose_payload(resources)
            .map_err(|e| builder_error("choose the payload", e))?;
        let (info, ranges) = ram_layout(resources, &payload, mem_size_mib)?;
        let shares = dax_layout(resources, &info, shares)?;
        let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(Error::Mapping)?;
        let (entry, initrd, payload_cmdline) = load_payload(resources, &payload, &memory, &info)?;
        let slots = discovery_slots(Present {
            memory: resources.memory_hotplug.is_some(),
            console: console.is_some(),
            shares: shares.len(),
            #[cfg(feature = "blk")]
            disks: disks.len(),
            vsock: vsock.is_some(),
            #[cfg(all(feature = "blk", feature = "net"))]
            nic: nic.is_some(),
        });
        let cmdline = command_line(resources, payload_cmdline.as_deref(), &slots)?;
        configure_guest(&memory, &info, &cmdline, &initrd, vcpus.vcpu_count)?;
        Ok(Self {
            memory,
            memory_hotplug: resources.memory_hotplug.clone(),
            entry,
            vcpus,
            console,
            shares,
            #[cfg(feature = "blk")]
            disks,
            #[cfg(all(feature = "blk", feature = "net"))]
            nic,
            vsock,
            slots,
        })
    }
}

/// Refuse every configured feature the owner cannot checkpoint, and every
/// device `VmResources` already holds built (`BootDevices` names those).
pub(crate) fn check_resources(resources: &VmResources) -> Result<()> {
    if resources.nested_enabled {
        return Err(unsupported("nested virtualization is not supported"));
    }
    if resources.split_irqchip {
        return Err(unsupported("the split irqchip is not supported"));
    }
    if resources.firmware_config.is_some() {
        return Err(unsupported("firmware payloads are not supported"));
    }
    if resources.gpu_virgl_flags.is_some() {
        return Err(unsupported("virtio-gpu is not supported"));
    }
    #[cfg(feature = "snd")]
    if resources.snd_device {
        return Err(unsupported("virtio-snd is not supported"));
    }
    #[cfg(feature = "input")]
    if !resources.input_backends.is_empty() {
        return Err(unsupported("virtio-input is not supported"));
    }
    if !resources.serial_consoles.is_empty() {
        return Err(unsupported("legacy serial consoles are not supported"));
    }
    if !resources.virtio_consoles.is_empty() {
        return Err(unsupported("additional virtio consoles are not supported"));
    }
    #[cfg(feature = "blk")]
    if !resources.block.list.is_empty() {
        return Err(unsupported("disks must come unopened, as boot devices"));
    }
    #[cfg(feature = "net")]
    if !resources.net.list.is_empty() {
        return Err(unsupported("the NIC must come unopened, as a boot device"));
    }
    if resources.vsock.get().is_some() {
        return Err(unsupported(
            "the vsock must come unopened, as a boot device",
        ));
    }
    Ok(())
}

/// Every configured share in index order, at most seven; the layout adds
/// the DAX windows.
fn shares(resources: &VmResources) -> Result<Vec<FsShareConfig>> {
    if resources.fs.len() > virtio_fs::MAX_SHARES {
        return Err(unsupported("more than seven virtio-fs shares"));
    }
    Ok(resources
        .fs
        .iter()
        .map(|fs| FsShareConfig {
            tag: fs.fs_id.clone(),
            source: PathBuf::from(&fs.shared_dir),
            read_only: fs.read_only,
            allow_root_dir_delete: fs.allow_root_dir_delete,
            vm_owned: fs.vm_owned,
            dax: None,
        })
        .collect())
}

#[cfg(feature = "blk")]
fn disk(config: &BlockDeviceConfig) -> Result<Disk> {
    if config.direct_io {
        return Err(unsupported("disks with direct I/O are not supported"));
    }
    if !matches!(config.sync_mode, SyncMode::Full) {
        return Err(unsupported("disks must sync fully"));
    }
    Ok(Disk {
        path: PathBuf::from(&config.disk_image_path),
        format: config.disk_image_format.clone(),
        read_only: config.is_disk_read_only,
        writeback: matches!(config.cache_type, CacheType::Writeback),
    })
}

/// The disk slots: eight, seven with a NIC (it takes the last one).
#[cfg(feature = "blk")]
fn check_disk_count(disks: usize, #[cfg(feature = "net")] nic: bool) -> Result<()> {
    #[cfg(feature = "net")]
    let capacity = if nic {
        nic::MAX_DISKS_WITH_NIC
    } else {
        blk::MAX_DISKS
    };
    #[cfg(not(feature = "net"))]
    let capacity = blk::MAX_DISKS;
    if disks > capacity {
        return Err(unsupported(
            "more disks than the fixed slots hold (eight, seven with a NIC)",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "blk", feature = "net"))]
fn nic(config: &NetworkInterfaceConfig) -> Result<Nic> {
    use devices::virtio::net::device::VirtioNetBackend;
    match &config.backend {
        VirtioNetBackend::UnixstreamPath(socket) => Ok(Nic {
            socket: socket.clone(),
            mac: config.mac,
            features: config.features,
        }),
        _ => Err(unsupported(
            "only a UnixStream NIC backend given by path is supported",
        )),
    }
}

fn vsock(config: &VsockDeviceConfig) -> Result<(u64, VsockPorts)> {
    if !config.tsi_flags.is_empty() {
        return Err(unsupported("vsock TSI is not supported"));
    }
    if config
        .host_port_map
        .as_ref()
        .is_some_and(|map| !map.is_empty())
    {
        return Err(unsupported("vsock TCP port maps are not supported"));
    }
    Ok((
        u64::from(config.guest_cid),
        config.unix_ipc_port_map.clone().unwrap_or_default(),
    ))
}

/// The architecture's RAM ranges with the hole the ordinary VMM leaves for
/// libkrunfw's kernel mapping filled by owned RAM, adjacent ranges merged;
/// none may reach into the 32-bit device window.
fn ram_layout(
    resources: &VmResources,
    payload: &Payload,
    mem_size_mib: usize,
) -> Result<(ArchMemoryInfo, Vec<(GuestAddress, usize)>)> {
    let size = mem_size_mib
        .checked_mul(1 << 20)
        .ok_or_else(|| unsupported("the memory size overflows"))?;
    let (info, mut ranges) = match payload {
        Payload::KernelMmap => {
            let kernel = resources
                .kernel_bundle
                .as_ref()
                .ok_or_else(|| unsupported("the kernel bundle is missing"))?;
            let end = kernel.guest_addr.checked_add(kernel.size as u64);
            if kernel.size == 0
                || kernel.size as u64 % PAGE_SIZE != 0
                || kernel.guest_addr % PAGE_SIZE != 0
                || end.is_none_or(|end| end > size as u64)
            {
                return Err(unsupported(
                    "the kernel bundle is empty, unaligned or does not fit in guest RAM",
                ));
            }
            let (info, mut ranges) =
                arch::arch_memory_regions(size, Some(kernel.guest_addr), kernel.size, 0, None);
            ranges.push((GuestAddress(kernel.guest_addr), kernel.size));
            (info, ranges)
        }
        Payload::ExternalKernel(kernel) => {
            arch::arch_memory_regions(size, None, 0, kernel.initramfs_size, None)
        }
        _ => return Err(unsupported("only kernel payloads are supported")),
    };
    ranges.sort_by_key(|(start, _)| *start);
    let mut merged: Vec<(GuestAddress, usize)> = Vec::with_capacity(ranges.len());
    for (start, len) in ranges {
        match merged.last_mut() {
            Some((last, last_len)) if last.0 + *last_len as u64 == start.0 => *last_len += len,
            _ => merged.push((start, len)),
        }
    }
    if merged.iter().any(|(start, len)| {
        start.0 < FIRST_ADDR_PAST_32BITS && MMIO_MEM_START < start.0 + *len as u64
    }) {
        return Err(unsupported(
            "guest RAM reaches into the 32-bit device window",
        ));
    }
    Ok((info, merged))
}

/// Give each share with an SHM size its DAX window at the ordinary VMM's
/// guest address, above guest RAM.
fn dax_layout(
    resources: &VmResources,
    info: &ArchMemoryInfo,
    mut shares: Vec<FsShareConfig>,
) -> Result<Vec<FsShareConfig>> {
    let mut shm = ShmManager::new(info);
    for (index, (fs, share)) in resources.fs.iter().zip(&mut shares).enumerate() {
        let Some(size) = fs.shm_size else {
            continue;
        };
        shm.create_fs_region(index, size)
            .map_err(|e| unsupported(&format!("place DAX window {index}: {e:?}")))?;
        let region = shm.fs_region(index).expect("created above");
        share.dax = Some(DaxRange {
            gpa: region.guest_addr.0,
            len: region.size as u64,
        });
    }
    Ok(shares)
}

/// Load the payload into `memory`; returns the kernel entry, the initrd
/// and the payload's own command line.
fn load_payload(
    resources: &VmResources,
    payload: &Payload,
    memory: &GuestMemoryMmap,
    info: &ArchMemoryInfo,
) -> Result<(GuestAddress, Option<InitrdConfig>, Option<String>)> {
    match payload {
        Payload::KernelMmap => {
            let kernel = resources
                .kernel_bundle
                .as_ref()
                .ok_or_else(|| unsupported("the kernel bundle is missing"))?;
            // SAFETY: a `KernelBundle` names libkrunfw's mapping of `size`
            // readable bytes at `host_addr` for the life of the process, as
            // the ordinary VMM's direct mapping of it relies on.
            let bytes =
                unsafe { std::slice::from_raw_parts(kernel.host_addr as *const u8, kernel.size) };
            memory
                .write_slice(bytes, GuestAddress(kernel.guest_addr))
                .map_err(Error::Memory)?;
            Ok((GuestAddress(kernel.entry_addr), None, None))
        }
        Payload::ExternalKernel(kernel) => builder::load_external_kernel(memory, info, kernel)
            .map_err(|e| builder_error("load the external kernel", e)),
        _ => Err(unsupported("only kernel payloads are supported")),
    }
}

/// Which devices a boot attaches.
struct Present {
    memory: bool,
    console: bool,
    shares: usize,
    #[cfg(feature = "blk")]
    disks: usize,
    vsock: bool,
    #[cfg(all(feature = "blk", feature = "net"))]
    nic: bool,
}

/// (MMIO address, GSI) of every device, in the ordinary VMM's probe order:
/// balloon, RNG, memory, console, shares, disks, vsock, NIC.
fn discovery_slots(present: Present) -> Vec<(u64, u32)> {
    let mut slots = vec![event_devices::BALLOON_SLOT, event_devices::RNG_SLOT];
    if present.memory { slots.push(event_devices::MEMORY_SLOT); }
    if present.console {
        slots.push((console::CONSOLE_MMIO_ADDR, console::CONSOLE_IRQ));
    }
    slots.extend((0..present.shares).map(virtio_fs::slot_of));
    #[cfg(feature = "blk")]
    slots.extend((0..present.disks).map(blk::slot_of));
    if present.vsock {
        slots.push((VSOCK_MMIO_ADDR, VSOCK_IRQ));
    }
    #[cfg(all(feature = "blk", feature = "net"))]
    if present.nic {
        slots.push((nic::NIC_MMIO_ADDR, nic::NIC_IRQ));
    }
    slots
}

/// The ordinary VMM's command line: base and krun environment, every
/// device, DHCP, then the init arguments.
fn command_line(
    resources: &VmResources,
    payload_cmdline: Option<&str>,
    slots: &[(u64, u32)],
) -> Result<String> {
    let line = (|| -> std::result::Result<_, StartMicrovmError> {
        let mut line = builder::base_kernel_cmdline(resources, payload_cmdline)?;
        for (addr, irq) in slots {
            line.insert(
                "virtio_mmio.device",
                &format!("{}K@0x{addr:08x}:{irq}", MMIO_LEN / 1024),
            )?;
        }
        if resources.dhcp_client {
            line.insert_str("KRUN_DHCP=1")?;
        }
        if let Some(epilog) = &resources.kernel_cmdline.epilog {
            line.insert_str(epilog)?;
        }
        Ok(line)
    })()
    .map_err(|e| builder_error("build the command line", e))?;
    Ok(line.as_str().to_owned())
}

/// Write the command line, MP table and boot parameters (with the E820
/// map) the ordinary VMM writes.
fn configure_guest(
    memory: &GuestMemoryMmap,
    info: &ArchMemoryInfo,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
    vcpus: u8,
) -> Result<()> {
    let line = std::ffi::CString::new(cmdline)
        .map_err(|_| unsupported("the command line holds a NUL byte"))?;
    kernel::loader::load_cmdline(memory, GuestAddress(CMDLINE_START), &line)
        .map_err(|e| unsupported(&format!("load the command line: {e:?}")))?;
    arch::configure_system(
        memory,
        info,
        GuestAddress(CMDLINE_START),
        cmdline.len() + 1,
        initrd,
        vcpus,
    )
    .map_err(|e| unsupported(&format!("write the boot parameters: {e:?}")))
}

/// The ordinary VMM's implicit console with a console output file: no
/// input, output to the file, truncated like the ordinary VMM's, the size
/// of a terminal on stdin. An import of its image takes the same port on
/// a `NewConsoleOutput`.
fn console_output_ports(output: &Path) -> Result<Vec<PortDescription>> {
    console_ports(File::create(output)?)
}

fn console_ports(file: File) -> Result<Vec<PortDescription>> {
    let terminal = if std::io::stdin().is_terminal() {
        port_io::term_fd(libc::STDIN_FILENO)
            .map_err(|e| Error::Full(format!("console terminal: {e}")))?
    } else {
        port_io::term_fixed_size(0, 0)
    };
    let input = port_io::input_empty().map_err(|e| Error::Full(format!("console input: {e}")))?;
    let output =
        port_io::output_file(file).map_err(|e| Error::Full(format!("console output: {e}")))?;
    Ok(vec![PortDescription::console(
        Some(input),
        Some(output),
        terminal,
    )])
}

/// An import's console output file: created exclusively (an existing
/// file is refused untouched) and removed again when dropped, while its
/// path still names the file created, unless the import that created it
/// succeeded and kept it.
pub(crate) struct NewConsoleOutput(Option<CreatedName>);

impl NewConsoleOutput {
    /// Create `path` and the console port writing to it, as a boot attaches.
    pub(crate) fn create(path: &Path) -> Result<(Self, Vec<PortDescription>)> {
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| Error::Full(format!("console output {}: {e}", path.display())))?;
        let created = Self(Some(CreatedName::new(path, &file.metadata()?)));
        Ok((created, console_ports(file)?))
    }

    pub(crate) fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for NewConsoleOutput {
    fn drop(&mut self) {
        if let Some(created) = self.0.take() {
            created.remove();
        }
    }
}

impl RamSnapshotVm {
    /// Cold-boot `image`: check that the host can checkpoint it, create the
    /// VM, attach every device at its announced slot, then start the vCPUs
    /// at the kernel entry. Checkpoints retain external share references (no
    /// privilege needed). A failure leaves no thread running.
    pub(crate) fn boot(image: BootImage) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        if usize::from(image.vcpus.vcpu_count) > kvm.fd().get_max_vcpus() {
            return Err(unsupported("more vCPUs than KVM supports"));
        }
        snapshot::Compatibility::capture(kvm.fd()).map_err(|e| unsupported(&e))?;
        let BootImage {
            memory,
            memory_hotplug,
            entry,
            vcpus,
            console,
            shares,
            #[cfg(feature = "blk")]
            disks,
            #[cfg(all(feature = "blk", feature = "net"))]
            nic,
            vsock,
            slots,
        } = image;
        let mut owner = Self::register(memory, Topology::default(), &kvm)?;
        if let Some(control) = memory_hotplug {
            use devices::virtio::mem::SLOT_SIZE;
            use vm_memory::{Address, GuestMemory};
            let end = shares.iter().filter_map(|s| s.dax.map(|d| d.gpa + d.len))
                .max().unwrap_or(0).max(owner.memory.last_addr().raw_value() + 1).max(FIRST_ADDR_PAST_32BITS);
            let addr = end.checked_add(SLOT_SIZE - 1).ok_or(Error::Invalid("hotplug address overflow"))? & !(SLOT_SIZE - 1);
            let bits = unsafe { std::arch::x86_64::__cpuid(0x80000008).eax & 0xff }.min(52);
            let available = kvm.max_memslots().saturating_sub(owner.memory.num_regions() + shares.iter().filter(|s| s.dax.is_some()).count());
            let slots = (u64::from(control.status().max_mib - control.initial_mib) * (1 << 20) / SLOT_SIZE)
                .min(available as u64).min((1u64 << bits).saturating_sub(addr) / SLOT_SIZE);
            let device = owner.create_memory_device(control, addr, slots * SLOT_SIZE)?;
            event_devices::attach_memory(&mut owner, device)?;
        }
        owner.attach_legacy([None, None, None, None])?;
        owner.attach_balloon()?;
        owner.attach_rng()?;
        if let Some(output) = &console {
            owner.attach_console(console_output_ports(output)?)?;
        }
        if let Some((cid, ports)) = &vsock {
            owner.attach_vsock(*cid, ports)?;
        }
        for share in shares {
            owner.attach_fs(share)?;
        }
        #[cfg(feature = "blk")]
        for disk in &disks {
            owner.attach_disk(
                &disk.path,
                disk.format.clone(),
                disk.read_only,
                disk.writeback,
            )?;
        }
        #[cfg(all(feature = "blk", feature = "net"))]
        if let Some(nic) = &nic {
            owner.attach_net(&nic.socket, nic.mac, nic.features)?;
        }
        if owner.discovery_slots() != slots {
            return Err(Error::Invalid(
                "attached devices differ from the slots the command line announces",
            ));
        }
        let memory = owner.memory.clone();
        owner.start(vcpus.vcpu_count, |cpu| {
            cpu.configure_snapshot_x86_64(&memory, entry, &vcpus)
                .map_err(Error::State)
        })?;
        Ok(owner)
    }

    /// Every attached device's (MMIO address, GSI) in the guest's probe
    /// order; see `discovery_slots`.
    fn discovery_slots(&self) -> Vec<(u64, u32)> {
        let mut slots = Vec::new();
        slots.extend(self.balloon.iter().map(|d| (d.mmio_addr, d.irq)));
        slots.extend(self.rng.iter().map(|d| (d.mmio_addr, d.irq)));
        slots.extend(self.memory_device.iter().map(|d| (d.mmio_addr, d.irq)));
        slots.extend(
            self.console
                .iter()
                .map(|c| console::slot(c))
                .map(|(_, a, i)| (a, i)),
        );
        slots.extend(
            self.fs
                .iter()
                .map(|s| virtio_fs::slot(s))
                .map(|(_, a, i)| (a, i)),
        );
        #[cfg(feature = "blk")]
        slots.extend(self.disks.iter().map(|d| (d.mmio_addr, d.irq)));
        slots.extend(
            self.vsock
                .iter()
                .map(|v| super::vsock::slot(v))
                .map(|(_, a, i)| (a, i)),
        );
        #[cfg(all(feature = "blk", feature = "net"))]
        slots.extend(
            self.nic
                .iter()
                .map(|n| nic::slot(n))
                .map(|(_, a, i)| (a, i)),
        );
        slots
    }
}

#[cfg(test)]
mod tests;
