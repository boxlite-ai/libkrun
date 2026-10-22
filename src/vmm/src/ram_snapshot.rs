// SPDX-License-Identifier: Apache-2.0

//! Internal stage-1 RAM images. This is not a runnable VM checkpoint.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::device_manager::shm::ShmRegion;
use crate::vstate::{KvmContext, Vcpu, VcpuEvent, VcpuHandle, VcpuResponse, Vm};

const MAGIC: &[u8; 8] = b"KRUNRAM\0";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 16;
const REGION_LEN: u64 = 24;
const PAGE_SIZE: u64 = 4096;
const CHUNK_SIZE: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

mod full;

#[cfg(feature = "blk")]
pub(crate) mod blk;

#[derive(Debug)]
pub(crate) enum Error {
    Io(io::Error),
    Invalid(&'static str),
    Control(Vec<String>),
    Full(String),
    State(crate::vstate::Error),
    Mapping(vm_memory::mmap::FromRangesError),
    Memory(vm_memory::GuestMemoryError),
    Recovery {
        operation: Box<Error>,
        resume: Box<Error>,
    },
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
            Self::Recovery { operation, resume } => {
                write!(f, "{operation}; recovery failed: {resume}")
            }
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

    fn finish(mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(MAGIC)?;
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

/// An uncertain control operation permanently disables subsequent snapshots.
#[derive(Default)]
pub(crate) struct Control {
    unusable: bool,
}

impl Control {
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
        // Every handle is attempted, even after another send or acknowledgment failed.
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

    pub(crate) fn save(
        &mut self,
        path: &Path,
        memory: &GuestMemoryMmap,
        topology: &Topology,
        handles: &[VcpuHandle],
        max_slots: usize,
    ) -> Result<()> {
        self.save_with_timeout(path, memory, topology, handles, max_slots, CONTROL_TIMEOUT)
    }

    fn save_with_timeout(
        &mut self,
        path: &Path,
        memory: &GuestMemoryMmap,
        topology: &Topology,
        handles: &[VcpuHandle],
        max_slots: usize,
        timeout: Duration,
    ) -> Result<()> {
        if self.unusable {
            return Err(Error::Invalid(
                "vCPU control is uncertain; reconstruct VM before snapshot",
            ));
        }
        let regions = topology.regions(memory)?;
        validate_regions(&regions, max_slots)?;
        let pause = if handles.iter().any(|h| !h.response_receiver().is_empty()) {
            Err(Error::Invalid("unconsumed vCPU response before pause"))
        } else {
            Self::transition(handles, true, timeout)
        };
        if pause.is_err() {
            self.unusable = true;
        }
        let operation = pause.and_then(|_| PendingSnapshot::write(path, memory, &regions));
        let resume = Self::transition(handles, false, timeout);
        if resume.is_err() {
            self.unusable = true;
        }
        match (operation, resume) {
            (Ok(pending), Ok(())) => pending.finish(),
            (Err(operation), Err(resume)) => Err(Error::Recovery {
                operation: Box::new(operation),
                resume: Box::new(resume),
            }),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
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
    paused: bool,
    #[cfg(feature = "blk")]
    bus: devices::Bus,
    #[cfg(feature = "blk")]
    disks: Vec<blk::BlkDevice>,
    #[cfg(feature = "blk")]
    imported: Option<blk::ImportedDir>,
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
        Ok(Self {
            handles: Vec::new(),
            vm,
            memory,
            topology,
            control: Control::default(),
            max_slots: kvm.max_memslots(),
            irqchip_ready: false,
            paused: true,
            #[cfg(feature = "blk")]
            bus: devices::Bus::new(),
            #[cfg(feature = "blk")]
            disks: Vec::new(),
            #[cfg(feature = "blk")]
            imported: None,
        })
    }

    pub(crate) fn restore(path: &Path) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let memory = restore_memory(&mut file, kvm.max_memslots())?;
        Self::register(memory, Topology::default(), &kvm)
    }

    pub(crate) fn save(&mut self, path: &Path) -> Result<()> {
        if self.paused && !self.handles.is_empty() {
            return Err(Error::Invalid(
                "RAM save would resume a restored paused full VM",
            ));
        }
        #[cfg(feature = "blk")]
        if !self.disks.is_empty() {
            return Err(Error::Invalid(
                "RAM-only save is not a consistent cut for attached disks; use save_full",
            ));
        }
        self.control.save(
            path,
            &self.memory,
            &self.topology,
            &self.handles,
            self.max_slots,
        )
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

    /// The stage-2 RAM alias probe, parameterized by the clones the owner's
    /// own devices legitimately hold (transport plus, once activated, the
    /// device state and the worker). External aliases always fail.
    #[cfg(feature = "blk")]
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
    #[cfg(feature = "blk")]
    pub(super) fn ensure_kernel_irqchip(
        &mut self,
    ) -> Result<devices::legacy::KvmIoapic> {
        if self.irqchip_ready {
            return Ok(devices::legacy::KvmIoapic {});
        }
        self.setup_irqchip()?;
        Ok(devices::legacy::KvmIoapic {})
    }

    /// Start a controlled real-mode RAM program, without boot loaders or devices.
    /// This initializes CPUs; it does not restore CPU state from a RAM image.
    pub(crate) fn start_vcpus(&mut self, count: u8, entry: u16) -> Result<()> {
        if self.control.unusable
            || count == 0
            || count as usize > crate::vstate::snapshot::MAX_CPUS
            || !self.handles.is_empty()
        {
            return Err(Error::Invalid("invalid minimal vCPU count/state"));
        }
        self.control.unusable = true;
        Vcpu::register_kick_signal_handler();
        let result = (|| {
            self.setup_irqchip()?;
            for id in 0..count {
                let exit_evt = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)?;
                let mut cpu = Vcpu::new_x86_64(
                    id,
                    self.vm.fd(),
                    self.vm.supported_cpuid().clone(),
                    self.vm.supported_msrs().clone(),
                    devices::Bus::new(),
                    exit_evt,
                )
                .map_err(Error::State)?;
                // The devices live on the MMIO bus, not the port-I/O bus;
                // a Bus clone snapshots the device map, so the disks must
                // already be attached here.
                #[cfg(feature = "blk")]
                cpu.set_mmio_bus(self.bus.clone());
                cpu.configure_minimal(entry, count).map_err(Error::State)?;
                self.handles
                    .push(cpu.start_threaded().map_err(Error::State)?);
            }
            Control::transition(&self.handles, false, CONTROL_TIMEOUT)
        })();
        if result.is_err() {
            for handle in &mut self.handles {
                handle.finish();
            }
            self.handles.clear();
        } else {
            self.control.unusable = false;
            self.paused = false;
        }
        result
    }
}

impl Drop for RamSnapshotVm {
    fn drop(&mut self) {
        // vCPUs join first: a running CPU could otherwise still touch the
        // devices while they stop. Workers join next; they hold guest RAM
        // and the disk images. The imported guard removes only the files it
        // created, after every thread has exited.
        for handle in &mut self.handles {
            handle.finish();
        }
        #[cfg(feature = "blk")]
        blk::stop_devices(self);
        #[cfg(feature = "blk")]
        drop(self.imported.take());
    }
}

#[cfg(test)]
mod tests;
