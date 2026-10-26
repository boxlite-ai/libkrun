// SPDX-License-Identifier: Apache-2.0

//! Internal stage-1 RAM images. This is not a runnable VM checkpoint.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use devices::virtio::MmioTransport;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::device_manager::shm::ShmRegion;
use crate::vstate::{KvmContext, Vcpu, VcpuEvent, VcpuHandle, VcpuResponse, Vm};

pub(crate) use boot::{check_resources, BootDevices, BootImage};
pub(crate) use legacy::SerialEndpoints;
pub(crate) use lifecycle::{ExitWaiter, RunState};
// Callers of the private API name `DaxRange` for `FsShareConfig::dax`; so
// far only its tests do.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use virtio_fs::{ArchiveMode, DaxRange, FsShareConfig};
pub(crate) use vsock::VsockPorts;

const MAGIC: &[u8; 8] = b"KRUNRAM\0";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 16;
const REGION_LEN: u64 = 24;
const PAGE_SIZE: u64 = 4096;
const CHUNK_SIZE: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

mod boot;
mod console;
mod event_devices;
mod events;
pub(crate) mod execution;
mod full;
mod legacy;
mod lifecycle;
mod virtio_fs;
mod vsock;
mod wiring;

#[cfg(feature = "blk")]
pub(crate) mod blk;

/// The internal NIC reuses the block device window and import guard, so it
/// needs both features.
#[cfg(all(feature = "blk", feature = "net"))]
pub(crate) mod nic;

#[derive(Debug)]
pub(crate) enum Error {
    Io(io::Error),
    Invalid(&'static str),
    Control(Vec<String>),
    Full(String),
    State(crate::vstate::Error),
    Mapping(vm_memory::mmap::FromRangesError),
    Memory(vm_memory::GuestMemoryError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "RAM snapshot I/O: {e}"),
            Self::Invalid(reason) => write!(f, "RAM snapshot: {reason}"),
            Self::Control(errors) => write!(f, "RAM snapshot vCPU control: {}", errors.join("; ")),
            Self::Full(reason) => write!(f, "full snapshot: {reason}"),
            Self::State(e) => write!(f, "RAM snapshot KVM: {e}"),
            Self::Mapping(e) => write!(f, "RAM snapshot mapping allocation: {e}"),
            Self::Memory(e) => write!(f, "RAM snapshot memory access: {e}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Only the payload loader records this exception to owned anonymous RAM.
pub(crate) struct KernelMapping {
    pub(crate) gpa: u64,
    pub(crate) len: u64,
    pub(crate) host: usize,
}

#[derive(Default)]
pub(crate) struct Topology {
    pub(crate) kernel: Option<KernelMapping>,
    pub(crate) shared: Vec<ShmRegion>,
}

impl Topology {
    fn regions(&self, memory: &GuestMemoryMmap) -> Result<Vec<Region>> {
        if !self.shared.is_empty() {
            return Err(Error::Invalid(
                "shared DAX/GPU mappings have no freeze contract",
            ));
        }
        memory
            .iter()
            .map(|region| {
                let mmap = region;
                let known_kernel = self.kernel.as_ref().is_some_and(|kernel| {
                    kernel.gpa == region.start_addr().raw_value()
                        && kernel.len == region.len()
                        && kernel.host == mmap.as_ptr() as usize
                        && !mmap.owned()
                        && mmap.flags() == 0
                        && mmap.prot() == 0
                        && mmap.file_offset().is_none()
                });
                let ordinary = mmap.owned()
                    && mmap.file_offset().is_none()
                    && mmap.flags()
                        & !(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)
                        == 0
                    && mmap.flags() & (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
                        == libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
                    && mmap.prot() == libc::PROT_READ | libc::PROT_WRITE;
                if !ordinary && !known_kernel {
                    return Err(Error::Invalid(
                        "unsupported RAM mapping or unknown raw kernel mapping",
                    ));
                }
                Ok(Region {
                    gpa: region.start_addr().raw_value(),
                    len: region.len(),
                    attributes: 0,
                })
            })
            .collect()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Region {
    gpa: u64,
    len: u64,
    attributes: u64,
}

fn validate_regions(regions: &[Region], max_slots: usize) -> Result<u64> {
    if regions.is_empty() || regions.len() > max_slots || regions.len() > u32::MAX as usize {
        return Err(Error::Invalid(
            "region count exceeds target KVM memslot capacity or is zero",
        ));
    }
    let mut file_len = HEADER_LEN
        .checked_add(
            (regions.len() as u64)
                .checked_mul(REGION_LEN)
                .ok_or(Error::Invalid("region table length overflow"))?,
        )
        .ok_or(Error::Invalid("header length overflow"))?;
    let mut previous_end = 0;
    for region in regions {
        if region.len == 0
            || region.gpa % PAGE_SIZE != 0
            || region.len % PAGE_SIZE != 0
            || region.len > isize::MAX as u64
        {
            return Err(Error::Invalid(
                "region length/address is unsupported or not page aligned",
            ));
        }
        let end = region
            .gpa
            .checked_add(region.len)
            .ok_or(Error::Invalid("GPA overflow"))?;
        if region.gpa < previous_end {
            return Err(Error::Invalid("overlapping or unordered regions"));
        }
        if region.attributes != 0 {
            return Err(Error::Invalid("unsupported RAM attributes"));
        }
        file_len = file_len
            .checked_add(region.len)
            .ok_or(Error::Invalid("snapshot length overflow"))?;
        previous_end = end;
    }
    Ok(file_len)
}

fn read_regions(file: &mut File, max_slots: usize) -> Result<Vec<Region>> {
    let file_len = file.metadata()?.len();
    let mut header = [0; HEADER_LEN as usize];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(Error::Invalid("invalid magic (incomplete snapshot)"));
    }
    if u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION {
        return Err(Error::Invalid("unsupported RAM format version"));
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > max_slots {
        return Err(Error::Invalid("invalid target memslot count"));
    }
    if HEADER_LEN + count as u64 * REGION_LEN > file_len {
        return Err(Error::Invalid("truncated region table"));
    }
    let mut regions = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = [0; REGION_LEN as usize];
        file.read_exact(&mut entry)?;
        regions.push(Region {
            gpa: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            len: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            attributes: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        });
    }
    if validate_regions(&regions, max_slots)? != file_len {
        return Err(Error::Invalid("snapshot length differs from region table"));
    }
    Ok(regions)
}

fn restore_memory(file: &mut File, max_slots: usize) -> Result<GuestMemoryMmap> {
    // Validate the ENTIRE table and exact file size before allocating any RAM.
    let regions = read_regions(file, max_slots)?;
    let ranges: Vec<_> = regions
        .iter()
        .map(|r| (GuestAddress(r.gpa), r.len as usize))
        .collect();
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(Error::Mapping)?;
    let mut buffer = [0; CHUNK_SIZE];
    for region in &regions {
        let mut offset = 0;
        while offset < region.len {
            let len = (region.len - offset).min(CHUNK_SIZE as u64) as usize;
            file.read_exact(&mut buffer[..len])?;
            memory
                .write_slice(&buffer[..len], GuestAddress(region.gpa + offset))
                .map_err(Error::Memory)?;
            offset += len as u64;
        }
    }
    Ok(memory)
}

struct PendingSnapshot {
    file: File,
    path: PathBuf,
    complete: bool,
}

impl PendingSnapshot {
    fn write(path: &Path, memory: &GuestMemoryMmap, regions: &[Region]) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let mut pending = Self {
            file,
            path: path.to_owned(),
            complete: false,
        };
        pending.file.write_all(&[0; 8])?;
        pending.file.write_all(&VERSION.to_le_bytes())?;
        pending
            .file
            .write_all(&(regions.len() as u32).to_le_bytes())?;
        for r in regions {
            pending.file.write_all(&r.gpa.to_le_bytes())?;
            pending.file.write_all(&r.len.to_le_bytes())?;
            pending.file.write_all(&r.attributes.to_le_bytes())?;
        }
        let mut buffer = [0; CHUNK_SIZE];
        for r in regions {
            let mut offset = 0;
            while offset < r.len {
                let len = (r.len - offset).min(CHUNK_SIZE as u64) as usize;
                memory
                    .read_slice(&mut buffer[..len], GuestAddress(r.gpa + offset))
                    .map_err(Error::Memory)?;
                #[cfg(test)]
                tests::write_payload(&mut pending.file, &buffer[..len])?;
                #[cfg(not(test))]
                pending.file.write_all(&buffer[..len])?;
                offset += len as u64;
            }
        }
        pending.file.sync_all()?;
        Ok(pending)
    }

    /// Publish the image: only now does it carry its valid `magic`.
    fn finish(mut self, magic: &[u8; 8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(magic)?;
        self.file.sync_all()?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        if !self.complete {
            // Invalidate before unlinking, including a partially failed finalization.
            let _ = self.file.seek(SeekFrom::Start(0));
            let _ = self.file.write_all(&[0; 8]);
            let _ = self.file.sync_all();
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Write a RAM-only image of `memory`; publishes it only when complete.
fn write_ram_image(
    path: &Path,
    memory: &GuestMemoryMmap,
    topology: &Topology,
    max_slots: usize,
) -> Result<()> {
    let regions = topology.regions(memory)?;
    validate_regions(&regions, max_slots)?;
    PendingSnapshot::write(path, memory, &regions)?.finish(MAGIC)
}

/// An uncertain control operation permanently disables subsequent snapshots.
#[derive(Default)]
struct Control {
    unusable: bool,
}

impl Control {
    /// Pause or resume every vCPU. Every handle is attempted, even after
    /// another send or acknowledgment failed.
    fn transition(handles: &[VcpuHandle], pause: bool, timeout: Duration) -> Result<()> {
        let mut errors = Vec::new();
        for (index, handle) in handles.iter().enumerate() {
            let event = if pause {
                VcpuEvent::Pause
            } else {
                VcpuEvent::Resume
            };
            if let Err(e) = handle.send_event(event) {
                errors.push(format!("vCPU {index} send: {e}"));
            }
        }
        for (index, handle) in handles.iter().enumerate() {
            let deadline = Instant::now() + timeout;
            loop {
                match handle.response_receiver().recv_deadline(deadline) {
                    Ok(VcpuResponse::Paused) if pause => break,
                    Ok(VcpuResponse::Resumed) if !pause => break,
                    // A timed-out Pause may complete before its queued Resume.
                    Ok(VcpuResponse::Paused) if !pause => continue,
                    response => {
                        errors.push(format!(
                            "vCPU {index} {} acknowledgment: {response:?}",
                            if pause { "pause" } else { "resume" }
                        ));
                        break;
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Control(errors))
        }
    }
}

/// A name an import created, with the identity (st_dev, st_ino) of the
/// object it was created for, read from the creating descriptor or right
/// after the creation: cleanup removes the name only while it still names
/// that object, so a replacement at the same path stays.
struct CreatedName {
    path: PathBuf,
    key: (u64, u64),
}

impl CreatedName {
    fn new(path: &Path, created: &fs::Metadata) -> Self {
        Self {
            path: path.to_owned(),
            key: (created.dev(), created.ino()),
        }
    }

    /// Remove the name (a directory only when empty) if it still names the
    /// created object.
    fn remove(&self) {
        match fs::symlink_metadata(&self.path) {
            Ok(meta) if (meta.dev(), meta.ino()) == self.key => {
                let _ = if meta.is_dir() {
                    fs::remove_dir(&self.path)
                } else {
                    fs::remove_file(&self.path)
                };
            }
            _ => {}
        }
    }
}

/// Target resources a full restore needs. Images never name host paths or
/// descriptors, so each device present in an image takes its new resource
/// from here; a resource without its device, or a device without its
/// resource, is rejected before anything is created.
#[derive(Default)]
pub(crate) struct RestoreResources {
    /// New directory for the imported disk segments; created exclusively.
    pub(crate) disk_dir: Option<PathBuf>,
    /// Freshly started UnixStream backend for the NIC.
    pub(crate) nic_socket: Option<PathBuf>,
    /// Fresh endpoints of the four legacy serial ports (COM1–COM4), in
    /// port order; each must already be nonblocking, and a port without one
    /// discards output and reads no input.
    pub(crate) serial: Option<SerialEndpoints>,
    /// New host socket paths of the vsock's ports; the ports and their
    /// roles must equal the image's.
    pub(crate) vsock_ports: Option<VsockPorts>,
    /// The console's fresh endpoints.
    pub(crate) console_ports: Option<ConsoleEndpoints>,
    /// New directory for the imported virtio-fs shares: an absolute path
    /// without NUL bytes, created exclusively with mode 0700 and kept once
    /// the import succeeds.
    pub(crate) fs_dir: Option<PathBuf>,
}

/// The endpoints a restored console takes.
pub(crate) enum ConsoleEndpoints {
    /// Fresh ports in the image's port order: names, directions and input,
    /// output and terminal kinds must equal the image's.
    Ports(Vec<devices::virtio::PortDescription>),
    /// A booted VM's console port on this new output file. The import
    /// creates it exclusively only after the image and every other
    /// resource passed their checks (an existing file is refused untouched)
    /// and removes it again if the import fails.
    NewOutput(PathBuf),
}

/// Owns the minimal VM. No mapping, VM fd, or vCPU handle escapes this owner.
pub(crate) struct RamSnapshotVm {
    handles: Vec<VcpuHandle>,
    vm: Vm,
    memory: GuestMemoryMmap,
    topology: Topology,
    control: Control,
    max_slots: usize,
    irqchip_ready: bool,
    /// Present exactly while a confirmed pause holds every vCPU and device.
    pause: Option<lifecycle::Paused>,
    bus: devices::Bus,
    /// Port-I/O bus: empty unless the legacy devices are attached.
    io_bus: devices::Bus,
    legacy: Option<legacy::Legacy>,
    exit: Arc<events::Exit>,
    #[cfg(feature = "blk")]
    disks: Vec<blk::BlkDevice>,
    #[cfg(feature = "blk")]
    imported: Option<blk::ImportedDir>,
    #[cfg(all(feature = "blk", feature = "net"))]
    nic: Option<nic::NicDevice>,
    rng: Option<events::EventDevice<devices::virtio::Rng>>,
    balloon: Option<events::EventDevice<devices::virtio::Balloon>>,
    vsock: Option<vsock::VsockDevice>,
    console: Option<console::ConsoleDevice>,
    events: Option<events::EventThread>,
    /// virtio-fs shares in index order.
    fs: Vec<virtio_fs::FsDevice>,
    /// The imported shares' tree until the import that created it succeeds.
    fs_import: Option<devices::virtio::fs::passthrough::ImportedArchive>,
    /// The caller declared every host writer of the shares stopped; held
    /// through a pause, cleared by resume and disable.
    host_writers_stopped: bool,
    /// How exports archive the shares: full attributes unless set before
    /// vCPU start; an imported owner keeps its image's mode.
    fs_archive_mode: ArchiveMode,
    /// Every DAX window the owner mapped, in memslot order. Declared after
    /// `vm`: a window is unmapped only after the VM fd (and its memslot)
    /// closed.
    dax: Vec<virtio_fs::DaxBacking>,
    /// Gates every KVM_RUN of an owner with a DAX window against the
    /// `MAP_FIXED` calls on its windows; see `execution`.
    execution: Arc<execution::ExecutionBarrier>,
    /// The guest's exit code, set through any virtio-fs share
    /// (`VIRTIO_IOC_EXIT_CODE`); `i32::MAX` until the guest sets one.
    exit_code: Arc<AtomicI32>,
    /// The exit status, fixed the first time an ended guest is examined.
    exit_status: Option<i32>,
    /// Each imported share's tag and root copy, except a VM-owned one.
    restored_shares: Vec<(String, PathBuf)>,
}

impl RamSnapshotVm {
    pub(crate) fn from_memory(memory: GuestMemoryMmap, topology: Topology) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        Self::register(memory, topology, &kvm)
    }

    fn register(memory: GuestMemoryMmap, topology: Topology, kvm: &KvmContext) -> Result<Self> {
        validate_regions(&topology.regions(&memory)?, kvm.max_memslots())?;
        // On any registration failure this fresh VM closes before `memory` drops,
        // removing ALL partially installed slots, including a failed TSS setup.
        let mut vm = Vm::new(kvm.fd()).map_err(Error::State)?;
        vm.memory_init(&memory, kvm.max_memslots())
            .map_err(Error::State)?;
        let exit = events::Exit::new()?;
        let execution =
            execution::ExecutionBarrier::new(exit.failure_notifier()?, execution::kick_vcpu);
        Ok(Self {
            handles: Vec::new(),
            vm,
            memory,
            topology,
            control: Control::default(),
            max_slots: kvm.max_memslots(),
            irqchip_ready: false,
            pause: None,
            bus: devices::Bus::new(),
            io_bus: devices::Bus::new(),
            legacy: None,
            exit,
            #[cfg(feature = "blk")]
            disks: Vec::new(),
            #[cfg(feature = "blk")]
            imported: None,
            #[cfg(all(feature = "blk", feature = "net"))]
            nic: None,
            rng: None,
            balloon: None,
            vsock: None,
            console: None,
            events: None,
            fs: Vec::new(),
            fs_import: None,
            host_writers_stopped: false,
            fs_archive_mode: ArchiveMode::FullAttributes,
            dax: Vec::new(),
            execution,
            exit_code: Arc::new(AtomicI32::new(i32::MAX)),
            exit_status: None,
            restored_shares: Vec::new(),
        })
    }

    pub(crate) fn restore(path: &Path) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let memory = restore_memory(&mut file, kvm.max_memslots())?;
        Self::register(memory, Topology::default(), &kvm)
    }

    /// Save guest RAM only, for an owner without vCPUs or one that `pause`
    /// holds; it never resumes anything. A failure removes the partial image
    /// and leaves a paused owner paused.
    pub(crate) fn save(&mut self, path: &Path) -> Result<()> {
        if self.control.unusable {
            return Err(Error::Invalid(
                "vCPU control is uncertain; reconstruct VM before snapshot",
            ));
        }
        if !self.handles.is_empty() && self.pause.is_none() {
            return Err(Error::Invalid("RAM-only save requires paused vCPUs"));
        }
        if self.has_devices() {
            return Err(Error::Invalid(
                "RAM-only save is not a consistent cut for attached devices; use export",
            ));
        }
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        write_ram_image(path, &self.memory, &self.topology, self.max_slots)
    }

    /// Hand an import's disk directory and files over to the caller: the
    /// owner never removes them anymore.
    #[cfg(feature = "blk")]
    pub(crate) fn hand_over_imported_disks(&mut self) {
        if let Some(imported) = self.imported.take() {
            imported.hand_over();
        }
    }

    /// Each imported share's tag and the root of its copy, in share order,
    /// except the VM-owned boot root (removed with the owner); empty unless
    /// imported.
    pub(crate) fn restored_shares(&self) -> &[(String, PathBuf)] {
        &self.restored_shares
    }

    /// Attach an internal disk (RAW/QCOW2/VMDK file) before vCPUs start.
    #[cfg(feature = "blk")]
    pub(crate) fn attach_disk(
        &mut self,
        path: &Path,
        format: devices::virtio::block::ImageType,
        read_only: bool,
        writeback: bool,
    ) -> Result<()> {
        blk::attach_disk(self, path, format, read_only, writeback)
    }

    /// Attach the internal UnixStream NIC before vCPUs start.
    #[cfg(all(feature = "blk", feature = "net"))]
    pub(crate) fn attach_net(
        &mut self,
        socket_path: &Path,
        mac: [u8; 6],
        features: u32,
    ) -> Result<()> {
        nic::attach_net(self, socket_path, mac, features)
    }

    /// Attach the internal virtio RNG before vCPUs start.
    pub(crate) fn attach_rng(&mut self) -> Result<()> {
        event_devices::attach_rng(self)
    }

    /// Attach the internal virtio balloon (free page reporting) before
    /// vCPUs start.
    pub(crate) fn attach_balloon(&mut self) -> Result<()> {
        event_devices::attach_balloon(self)
    }

    /// Attach the internal Unix IPC vsock with guest `cid` before vCPUs
    /// start; `ports` maps each vsock port to its host socket and role.
    pub(crate) fn attach_vsock(&mut self, cid: u64, ports: &VsockPorts) -> Result<()> {
        vsock::attach(self, cid, ports)
    }

    /// Attach the internal virtio console before vCPUs start. Every port
    /// must use built-in endpoints; a custom one is rejected before the
    /// attach has any effect.
    pub(crate) fn attach_console(
        &mut self,
        ports: Vec<devices::virtio::PortDescription>,
    ) -> Result<()> {
        console::attach(self, ports)
    }

    /// Attach a virtio-fs share (at most seven) before vCPUs start; see
    /// `FsShareConfig`. Every check precedes any effect.
    pub(crate) fn attach_fs(&mut self, config: FsShareConfig) -> Result<()> {
        virtio_fs::attach(self, config)
    }

    /// Choose how exports archive the virtio-fs shares, before vCPUs start
    /// (see `passthrough::ArchiveContract`): full attributes, the default,
    /// needs CAP_SYS_ADMIN in the initial user namespace at export;
    /// guest-visible works without privilege, records the effective IDs
    /// the export runs with, and an import needs exactly those.
    pub(crate) fn set_fs_archive_mode(&mut self, mode: ArchiveMode) -> Result<()> {
        if self.control.unusable || !self.handles.is_empty() {
            return Err(Error::Invalid(
                "the virtio-fs archive mode is set only before vCPU start of a usable owner",
            ));
        }
        self.fs_archive_mode = mode;
        Ok(())
    }

    /// Declare that the caller stopped every host writer of the virtio-fs
    /// share directories and of any alias of their files, until the next
    /// resume; exports of an owner with shares require it. Accepted only
    /// while the owner runs usable, unpaused and not exiting; a pause keeps
    /// it, resume and disable clear it.
    pub(crate) fn declare_host_writers_stopped(&mut self) -> Result<()> {
        self.check_execution()?;
        if self.control.unusable || self.handles.is_empty() || self.pause.is_some() {
            return Err(Error::Invalid(
                "declaring host writers stopped requires a running usable VM",
            ));
        }
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        self.host_writers_stopped = true;
        Ok(())
    }

    /// Attach COM1–COM4, CMOS and the i8042 before vCPUs start. Each
    /// endpoint must already be nonblocking; its flags are never changed.
    pub(crate) fn attach_legacy(&mut self, serial: SerialEndpoints) -> Result<()> {
        legacy::attach(self, serial)
    }

    /// Output bytes each UART dropped because its endpoint was full or
    /// closed; a restored owner starts at zero.
    pub(crate) fn serial_dropped_output_bytes(&self) -> Option<[u64; 4]> {
        self.legacy
            .as_ref()
            .map(legacy::Legacy::dropped_output_bytes)
    }

    /// Whether any userspace device is attached.
    fn has_devices(&self) -> bool {
        !self.mmio_devices().is_empty() || self.legacy.is_some()
    }

    /// Every attached MMIO device as (transport, MMIO address, GSI), in the
    /// fixed order disks, NIC, RNG, balloon, vsock, console, virtio-fs.
    pub(super) fn mmio_devices(&self) -> Vec<(&Arc<Mutex<MmioTransport>>, u64, u32)> {
        let mut devices = Vec::new();
        #[cfg(feature = "blk")]
        devices.extend(
            self.disks
                .iter()
                .map(|disk| (&disk.transport, disk.mmio_addr, disk.irq)),
        );
        #[cfg(all(feature = "blk", feature = "net"))]
        devices.extend(self.nic.iter().map(nic::slot));
        devices.extend(
            self.rng
                .iter()
                .map(|rng| (&rng.transport, rng.mmio_addr, rng.irq)),
        );
        devices.extend(
            self.balloon
                .iter()
                .map(|balloon| (&balloon.transport, balloon.mmio_addr, balloon.irq)),
        );
        devices.extend(self.vsock.iter().map(vsock::slot));
        devices.extend(self.console.iter().map(console::slot));
        devices.extend(self.fs.iter().map(virtio_fs::slot));
        devices
    }

    /// Disk slots left by the internal NIC, which takes the last GSI.
    #[cfg(feature = "blk")]
    pub(super) fn disk_capacity(&self) -> usize {
        #[cfg(feature = "net")]
        if self.nic.is_some() {
            return nic::MAX_DISKS_WITH_NIC;
        }
        blk::MAX_DISKS
    }

    /// Mapping clones every attached device legitimately holds.
    pub(super) fn expected_device_clones(&self) -> usize {
        #[cfg(feature = "blk")]
        let disks = blk::expected_alias_clones(self);
        #[cfg(not(feature = "blk"))]
        let disks = 0;
        #[cfg(all(feature = "blk", feature = "net"))]
        let nic = nic::expected_alias_clones(self);
        #[cfg(not(all(feature = "blk", feature = "net")))]
        let nic = 0;
        disks
            + nic
            + event_devices::expected_alias_clones(self)
            + vsock::expected_alias_clones(self)
            + console::expected_alias_clones(self)
            + virtio_fs::expected_alias_clones(self)
    }

    /// Start the event thread: the exit watch, plus the attached RNG,
    /// balloon, vsock, console control queues and UART input.
    fn start_event_thread(&mut self, start: events::Start) -> Result<()> {
        let devices = events::Devices {
            exit: self.exit.clone(),
            rng: self.rng.as_ref().map(|rng| rng.device.clone()),
            balloon: self.balloon.as_ref().map(|balloon| balloon.device.clone()),
            vsock: vsock::event_device(self),
            console: console::event_device(self),
            serials: self
                .legacy
                .as_ref()
                .map_or_else(Vec::new, legacy::Legacy::serials),
        };
        self.events = Some(events::EventThread::spawn(devices, start)?);
        Ok(())
    }

    /// Create `count` paused vCPU threads on the owner's buses and exit
    /// eventfd, then arm the event thread with their stop handles before
    /// any of them first runs. The buses must be complete: a `Bus` clone is
    /// a snapshot, not a live view.
    fn spawn_vcpus(
        &mut self,
        count: u8,
        mut configure: impl FnMut(&mut Vcpu) -> Result<()>,
    ) -> Result<()> {
        Vcpu::register_kick_signal_handler();
        for id in 0..count {
            let mut cpu = Vcpu::new_x86_64(
                id,
                self.vm.fd(),
                self.vm.supported_cpuid().clone(),
                self.vm.supported_msrs().clone(),
                self.io_bus.clone(),
                self.exit.notifier()?,
            )
            .map_err(Error::State)?;
            cpu.set_mmio_bus(self.bus.clone());
            // Windows exist only before the vCPUs: attached or imported.
            if !self.dax.is_empty() {
                cpu.set_execution_barrier(self.execution.clone());
            }
            configure(&mut cpu)?;
            self.handles
                .push(cpu.start_threaded().map_err(Error::State)?);
        }
        let stops = self.handles.iter().map(VcpuHandle::stop_handle).collect();
        self.events
            .as_ref()
            .ok_or(Error::Invalid("the event thread is not running"))?
            .arm(stops)
    }

    /// Stop every thread: first cancel any vsock send blocked under the
    /// device lock (the event thread or a vCPU could wait on that lock
    /// forever), then the event thread (it holds vCPU stop handles whose
    /// pthread IDs are valid only until the vCPUs are joined), then retire
    /// the execution barrier (a vCPU or remapping waiting on it gives up;
    /// nothing runs or remaps a window again), then the vCPUs (they could
    /// still touch the devices), then the disk, NIC,
    /// vsock, console and virtio-fs workers, which hold guest RAM, the disk
    /// images, the backend connections, the console endpoints and the
    /// shares (a retired share leaves its DAX window alone). Every startup,
    /// import, pause and resume failure ends here.
    fn stop_threads(&mut self) {
        vsock::quiesce_gate(self);
        if let Some(events) = &mut self.events {
            events.stop();
        }
        // No exit can latch anymore: release every waiter.
        self.exit.end();
        self.execution.retire();
        for handle in &mut self.handles {
            handle.finish();
        }
        #[cfg(feature = "blk")]
        blk::stop_devices(self);
        #[cfg(all(feature = "blk", feature = "net"))]
        nic::stop(self);
        vsock::teardown(self);
        console::teardown(self);
        virtio_fs::teardown(self);
    }

    /// The stage-2 RAM alias probe, parameterized by the clones the owner's
    /// own devices legitimately hold. External aliases always fail.
    pub(super) fn probe_ram_aliases(&self, expected_device_clones: usize) -> Result<()> {
        for region in self.memory.iter() {
            // remove_region returns a cloned collection plus the removed Arc;
            // exactly two references means only this owner and this probe
            // hold it, plus every clone the owner's own devices hold.
            let (_remaining, mapping) = self
                .memory
                .remove_region(region.start_addr(), region.len())
                .map_err(|e| Error::Full(format!("inspect RAM ownership: {e}")))?;
            if std::sync::Arc::strong_count(&mapping) != 2 + expected_device_clones {
                return Err(Error::Invalid(
                    "full snapshot RAM has external aliases/writers",
                ));
            }
        }
        Ok(())
    }

    /// Create the kernel irqchip/PIT once; later callers get the empty
    /// userspace stub that only writes the interrupt eventfd.
    pub(super) fn ensure_kernel_irqchip(&mut self) -> Result<devices::legacy::KvmIoapic> {
        if self.irqchip_ready {
            return Ok(devices::legacy::KvmIoapic {});
        }
        self.setup_irqchip()?;
        Ok(devices::legacy::KvmIoapic {})
    }

    /// Start a controlled real-mode RAM program, without boot loaders or devices.
    /// This initializes CPUs; it does not restore CPU state from a RAM image.
    pub(crate) fn start_vcpus(&mut self, count: u8, entry: u16) -> Result<()> {
        self.start(count, |cpu| {
            cpu.configure_minimal(entry, count).map_err(Error::State)
        })
    }

    /// Start `count` vCPUs, each set up by `configure`, on the complete
    /// buses; a failure stops every thread started here.
    fn start(&mut self, count: u8, configure: impl FnMut(&mut Vcpu) -> Result<()>) -> Result<()> {
        if self.control.unusable
            || count == 0
            || count as usize > crate::vstate::snapshot::MAX_CPUS
            || !self.handles.is_empty()
        {
            return Err(Error::Invalid("invalid vCPU count or owner state"));
        }
        self.control.unusable = true;
        let result = (|| {
            self.setup_irqchip()?;
            self.start_event_thread(events::Start::Running)?;
            self.spawn_vcpus(count, configure)?;
            Control::transition(&self.handles, false, CONTROL_TIMEOUT)
        })();
        if result.is_err() {
            self.stop_threads();
            self.handles.clear();
        } else {
            self.control.unusable = false;
        }
        result
    }
}

impl Drop for RamSnapshotVm {
    fn drop(&mut self) {
        // The imported guards remove only the files they created, after
        // every thread has exited; the DAX windows unmap after the VM fd
        // closed (field order). A VM-owned share root goes only now: the
        // guest may run until the VM ends.
        self.stop_threads();
        virtio_fs::remove_vm_owned_roots(&self.fs);
        #[cfg(feature = "blk")]
        drop(self.imported.take());
    }
}

#[cfg(test)]
mod tests;
