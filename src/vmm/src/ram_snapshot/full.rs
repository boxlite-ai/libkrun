// SPDX-License-Identifier: Apache-2.0

//! Version-9 memory-only images with external disk and FUSE dependencies.

use super::*;
use crate::ram_snapshot::boot::NewConsoleOutput;
use crate::ram_snapshot::console::{self, ConsoleMeta};
use crate::ram_snapshot::event_devices::{self, BalloonMeta, DeviceMeta};
use crate::ram_snapshot::events;
use crate::ram_snapshot::legacy::{self, LegacyMeta};
use crate::ram_snapshot::virtio_fs::{self, FsMeta};
use crate::ram_snapshot::vsock::{self, VsockMeta};
use crate::vstate::snapshot::{self, Compatibility, CpuState, Request};
use crate::vstate::VmState;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

mod format;

const FULL_MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const FULL_VERSION: u32 = 9;
const MAX_METADATA: usize = 16 * 1024 * 1024;

#[cfg(feature = "blk")]
use crate::ram_snapshot::blk;
#[cfg(all(feature = "blk", feature = "net"))]
use crate::ram_snapshot::nic;

/// A section this build cannot hold: parsing an image that carries one
/// fails, and an empty or absent section round-trips.
#[cfg(not(all(feature = "blk", feature = "net")))]
#[derive(Serialize, Deserialize)]
enum Unsupported {}

#[cfg(feature = "blk")]
type DiskTable = Vec<blk::DiskMeta>;
#[cfg(not(feature = "blk"))]
type DiskTable = Vec<Unsupported>;
#[cfg(all(feature = "blk", feature = "net"))]
type NicSection = nic::NicMeta;
#[cfg(not(all(feature = "blk", feature = "net")))]
type NicSection = Unsupported;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    compatibility: Compatibility,
    cpus: Vec<CpuState>,
    vm: VmState,
    regions: Vec<Region>,
    disks: DiskTable,
    nic: Option<NicSection>,
    rng: Option<DeviceMeta>,
    balloon: Option<BalloonMeta>,
    vsock: Option<VsockMeta>,
    console: Option<ConsoleMeta>,
    legacy: Option<LegacyMeta>,
    fs: Option<FsMeta>,
    application_schema: u32,
    application: serde_json::Value,
    disk_dependencies: Vec<DiskDependency>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum DiskDependency {
    ContainerQcow2,
    ExternalReadonlyBoot { length: u64, sha256: [u8; 32] },
}

/// Which target resources an image needs; each must be supplied exactly
/// when its device is present.
struct Requirements {
    nic: bool,
    vsock: bool,
    console: bool,
    legacy: bool,
}

impl Requirements {
    fn of(metadata: &Metadata) -> Self {
        Self {
            nic: metadata.nic.is_some(),
            vsock: metadata.vsock.is_some(),
            console: metadata.console.is_some(),
            legacy: metadata.legacy.is_some(),
        }
    }

    fn check(&self, resources: &RestoreResources) -> Result<()> {
        if self.nic != resources.nic_socket.is_some() {
            return Err(Error::Invalid(
                "restore resources: a NIC socket is required exactly when the image has a NIC",
            ));
        }
        if self.vsock != resources.vsock_ports.is_some() {
            return Err(Error::Invalid(
                "restore resources: vsock ports are required exactly when the image has a vsock",
            ));
        }
        if self.console != resources.console_ports.is_some() {
            return Err(Error::Invalid(
                "restore resources: console ports are required exactly when the image has a console",
            ));
        }
        if self.legacy != resources.serial.is_some() {
            return Err(Error::Invalid(
                "restore resources: serial endpoints are required exactly when the image has legacy devices",
            ));
        }
        Ok(())
    }
}

struct BoundedMetadata(Vec<u8>);
impl Write for BoundedMetadata {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_METADATA - self.0.len() {
            return Err(io::Error::other("full metadata exceeds 16 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn payload_len(regions: &[Region], max_slots: usize) -> Result<u64> {
    Ok(validate_regions(regions, max_slots)? - HEADER_LEN - REGION_LEN * regions.len() as u64)
}

/// The MMIO slots of every device in `metadata` but the virtio-fs shares,
/// for the shares' DAX window checks.
fn device_slots(metadata: &Metadata) -> Vec<u64> {
    #[cfg_attr(not(feature = "blk"), allow(unused_mut))]
    let mut slots = Vec::new();
    #[cfg(feature = "blk")]
    slots.extend(metadata.disks.iter().map(|disk| disk.mmio_addr));
    #[cfg(all(feature = "blk", feature = "net"))]
    slots.extend(metadata.nic.as_ref().map(|_| nic::NIC_MMIO_ADDR));
    slots.extend(event_devices::slots(
        metadata.rng.as_ref(),
        metadata.balloon.as_ref(),
    ));
    slots.extend(metadata.vsock.as_ref().map(|_| vsock::VSOCK_MMIO_ADDR));
    slots.extend(
        metadata
            .console
            .as_ref()
            .map(|_| console::CONSOLE_MMIO_ADDR),
    );
    slots
}

fn read_metadata(
    file: &mut File,
    max_slots: usize,
    max_cpus: usize,
) -> Result<(Metadata, format::Envelope)> {
    let envelope = format::read(file)?;
    let metadata: Metadata = serde_json::from_slice(&envelope.metadata)
        .map_err(|e| Error::Full(format!("metadata JSON: {e}")))?;
    if metadata.application_schema != 1
        || metadata.cpus.is_empty()
        || metadata.cpus.len() > max_cpus.min(snapshot::MAX_CPUS)
    {
        return Err(Error::Invalid(
            "unsupported application schema or vCPU count",
        ));
    }
    metadata.vm.validate_snapshot().map_err(Error::Full)?;
    let ram = payload_len(&metadata.regions, max_slots)?;
    let shares = validate_devices(&metadata, max_slots)?;
    if ram.checked_add(shares) != Some(envelope.payload) {
        return Err(Error::Invalid(
            "memory payload extents differ from metadata",
        ));
    }
    #[cfg(feature = "blk")]
    if metadata.disk_dependencies.len() != metadata.disks.len()
        || metadata
            .disk_dependencies
            .iter()
            .filter(|d| matches!(d, DiskDependency::ContainerQcow2))
            .count()
            != 1
    {
        return Err(Error::Invalid(
            "checkpoint requires exactly one container QCOW2",
        ));
    }
    #[cfg(feature = "blk")]
    for (disk, dependency) in metadata.disks.iter().zip(&metadata.disk_dependencies) {
        if disk.read_only != matches!(dependency, DiskDependency::ExternalReadonlyBoot { .. }) {
            return Err(Error::Invalid(
                "disk dependency role differs from device access",
            ));
        }
    }
    #[cfg(not(feature = "blk"))]
    if !metadata.disk_dependencies.is_empty() {
        return Err(Error::Invalid("disk dependency requires blk support"));
    }
    file.seek(SeekFrom::Start(
        format::HEADER + envelope.metadata.len() as u64,
    ))?;
    Ok((metadata, envelope))
}

pub(crate) fn inspect(file: &File) -> Result<Vec<u8>> {
    let mut file = file.try_clone()?;
    let position = file.stream_position()?;
    let decoded = read_metadata(&mut file, usize::MAX, snapshot::MAX_CPUS);
    file.seek(SeekFrom::Start(position))?;
    let (_, envelope) = decoded?;
    Ok(envelope.metadata)
}

pub(super) fn verify_qcow2(file: &File) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let mut header = [0; 104];
    file.read_exact_at(&mut header, 0)?;
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    if &header[..4] != b"QFI\xfb"
        || !matches!(version, 2 | 3)
        || header[8..20].iter().any(|&b| b != 0)
        || (version == 3 && header[72..80].iter().any(|&b| b != 0))
    {
        return Err(Error::Invalid(
            "container must be standalone supported QCOW2 without backing",
        ));
    }
    Ok(())
}

/// Every device section against its fixed slot and the validated RAM
/// regions, and the virtio-fs shares' DAX windows against everything else;
/// returns the length of the share payloads.
fn validate_devices(metadata: &Metadata, max_slots: usize) -> Result<u64> {
    #[cfg(feature = "blk")]
    blk::validate_disk_metadata(&metadata.disks, &metadata.regions)?;
    #[cfg(all(feature = "blk", feature = "net"))]
    if let Some(nic) = &metadata.nic {
        nic::validate_nic_metadata(nic, &metadata.disks, &metadata.regions)?;
    }
    event_devices::validate_metadata(
        metadata.rng.as_ref(),
        metadata.balloon.as_ref(),
        &metadata.regions,
    )?;
    if let Some(meta) = &metadata.vsock {
        vsock::validate_metadata(meta, &metadata.regions)?;
    }
    if let Some(meta) = &metadata.console {
        console::validate_metadata(meta, &metadata.regions)?;
    }
    if let Some(legacy) = &metadata.legacy {
        legacy::validate_metadata(legacy, &metadata.regions)?;
    }
    match &metadata.fs {
        Some(meta) => virtio_fs::validate_metadata(
            meta,
            &metadata.regions,
            &device_slots(metadata),
            max_slots,
        ),
        None => Ok(0),
    }
}

fn read_ram(file: &mut File, regions: &[Region]) -> Result<GuestMemoryMmap> {
    let ranges: Vec<_> = regions
        .iter()
        .map(|r| (GuestAddress(r.gpa), r.len as usize))
        .collect();
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(Error::Mapping)?;
    let mut buffer = [0; CHUNK_SIZE];
    for region in regions {
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

/// Validate every active ring against the loaded guest RAM, before any
/// directory, socket or thread exists.
fn validate_rings(metadata: &Metadata, memory: &GuestMemoryMmap) -> Result<()> {
    #[cfg(feature = "blk")]
    blk::validate_disk_rings(&metadata.disks, memory)?;
    #[cfg(all(feature = "blk", feature = "net"))]
    if let Some(nic) = &metadata.nic {
        nic::validate_nic_rings(nic, memory)?;
    }
    event_devices::validate_rings(metadata.rng.as_ref(), metadata.balloon.as_ref(), memory)?;
    if let Some(meta) = &metadata.vsock {
        vsock::validate_rings(meta, memory)?;
    }
    if let Some(meta) = &metadata.console {
        console::validate_rings(meta, memory)?;
    }
    if let Some(meta) = &metadata.fs {
        virtio_fs::validate_rings(meta, memory)?;
    }
    Ok(())
}

/// Refuse an image of `len` bytes that this process may not write in full.
/// A write past `RLIMIT_FSIZE` raises SIGXFSZ, which would kill the owner
/// instead of failing the export, so the limit is checked before the file
/// exists.
fn check_file_size_limit(len: u64) -> Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for the call to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } != 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    if limit.rlim_cur != libc::RLIM_INFINITY && len > limit.rlim_cur {
        return Err(Error::Full(format!(
            "the image needs {len} bytes, above this process's file size limit of {} bytes",
            limit.rlim_cur
        )));
    }
    Ok(())
}

/// Write an invalid header until metadata, RAM and anonymous payloads are durable.
fn write_memory(
    file: &mut File,
    abort: &std::sync::atomic::AtomicBool,
    memory: &GuestMemoryMmap,
    metadata: &Metadata,
    shares: Option<&virtio_fs::CapturedShares>,
    qcow2: &File,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & libc::O_APPEND != 0
        || !file.metadata()?.is_file()
    {
        return Err(Error::Invalid(
            "memory output requires a regular O_RDWR file",
        ));
    }
    verify_qcow2(qcow2)?;
    let mut encoded = BoundedMetadata(Vec::new());
    serde_json::to_writer(&mut encoded, metadata).map_err(|e| Error::Full(e.to_string()))?;
    let payload = payload_len(&metadata.regions, usize::MAX)?
        .checked_add(validate_devices(metadata, usize::MAX)?)
        .ok_or(Error::Invalid("memory payload overflow"))?;
    let total = format::HEADER
        .checked_add(encoded.0.len() as u64)
        .and_then(|n| n.checked_add(payload))
        .ok_or(Error::Invalid("memory file overflow"))?;
    check_file_size_limit(total)?;
    if file.metadata()?.len() != 0 {
        return Err(Error::Invalid("memory output FD must be empty"));
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&[0; format::HEADER as usize])?;
    file.write_all(&encoded.0)?;
    let mut buffer = [0; CHUNK_SIZE];
    for region in &metadata.regions {
        let mut offset = 0;
        while offset < region.len {
            if abort.load(Ordering::SeqCst) {
                return Err(Error::Invalid("checkpoint cancelled"));
            }
            let len = (region.len - offset).min(CHUNK_SIZE as u64) as usize;
            memory
                .read_slice(&mut buffer[..len], GuestAddress(region.gpa + offset))
                .map_err(Error::Memory)?;
            #[cfg(not(test))]
            file.write_all(&buffer[..len])?;
            #[cfg(test)]
            super::tests::write_payload(file, &buffer[..len])?;
            offset += len as u64;
        }
    }
    if let Some(shares) = shares {
        virtio_fs::write_payloads(file, shares)?;
    }
    let disk_len = qcow2.metadata()?.len();
    let disk_hash = format::digest(qcow2, 0, disk_len)?;
    format::seal(file, encoded.0.len() as u64, payload, disk_len, disk_hash)
}

/// Capture the target's compatibility and check the saved CPUs against it.
fn validate_target(
    kvm: &KvmContext,
    saved: &Compatibility,
    cpus: &[CpuState],
) -> Result<Compatibility> {
    let target = Compatibility::capture(kvm.fd()).map_err(Error::Full)?;
    saved.validate_target(&target).map_err(Error::Full)?;
    for (id, state) in cpus.iter().enumerate() {
        target.validate_cpu(state).map_err(Error::Full)?;
        target
            .validate_topology(state, id, cpus.len())
            .map_err(Error::Full)?;
    }
    Ok(target)
}

impl RamSnapshotVm {
    pub(super) fn setup_irqchip(&mut self) -> Result<()> {
        if self.irqchip_ready {
            return Ok(());
        }
        self.vm
            .fd()
            .create_irq_chip()
            .map_err(|e| Error::Full(format!("create kernel irqchip: {e}")))?;
        self.vm
            .fd()
            .create_pit2(kvm_bindings::kvm_pit_config {
                flags: kvm_bindings::KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            })
            .map_err(|e| Error::Full(format!("create PIT2: {e}")))?;
        self.irqchip_ready = true;
        Ok(())
    }

    pub(crate) fn discard_prepared(&mut self) {
        self.prepared = None;
    }

    pub(crate) fn prepare_checkpoint(
        &mut self,
    ) -> Result<crate::snapshot_vm::checkpoint::PreparedResources> {
        self.check_execution()?;
        let paused = self
            .pause
            .as_ref()
            .ok_or(Error::Invalid("checkpoint requires confirmed Paused"))?;
        virtio_fs::require_declared(self.fs.len(), self.host_writers_stopped)?;
        self.prepared =
            virtio_fs::capture(&self.fs, &paused.fs, self.exit_code.load(Ordering::SeqCst))?;
        let (metadata, files) = match &self.prepared {
            Some(shares) => (
                serde_json::to_vec(&shares.meta).map_err(|e| Error::Full(e.to_string()))?,
                shares.descriptors()?,
            ),
            None => (b"null".to_vec(), Vec::new()),
        };
        if metadata.len() > MAX_METADATA {
            return Err(Error::Invalid("prepared metadata exceeds bound"));
        }
        Ok(crate::snapshot_vm::checkpoint::PreparedResources { metadata, files })
    }

    pub(crate) fn export_fd(
        &mut self,
        mut file: File,
        qcow2: File,
        config: crate::snapshot_vm::checkpoint::ExportMetadata,
    ) -> Result<()> {
        self.check_execution()?;
        // Only worker devices retain cursors.
        #[cfg_attr(not(feature = "blk"), allow(unused_variables))]
        let paused = match &self.pause {
            Some(paused) if !self.control.unusable => paused,
            _ => return Err(Error::Invalid("export requires a paused usable VM")),
        };
        if self.exit.requested() {
            return Err(Error::Invalid("the VM is exiting"));
        }
        virtio_fs::require_declared(self.fs.len(), self.host_writers_stopped)?;
        let regions = self.topology.regions(&self.memory)?;
        payload_len(&regions, self.max_slots)?;
        let kvm = KvmContext::new().map_err(Error::State)?;
        let compatibility = Compatibility::capture(kvm.fd()).map_err(Error::Full)?;
        self.probe_ram_aliases(self.expected_device_clones())?;
        #[cfg(feature = "blk")]
        let disks = blk::capture_disks(self, &paused.disks, &regions)?;
        #[cfg(not(feature = "blk"))]
        let disks = Vec::new();
        #[cfg(all(feature = "blk", feature = "net"))]
        let nic = nic::capture(self, paused.nic.as_ref(), &disks, &regions)?;
        #[cfg(not(all(feature = "blk", feature = "net")))]
        let nic = None;
        let (rng, balloon) = event_devices::capture(self, &regions)?;
        let vsock = vsock::capture(self, &regions)?;
        let console = console::capture(self, &regions)?;
        let legacy = legacy::capture(self, &regions)?;
        if virtio_fs::any_discarded(&self.fs) {
            self.disable();
            return Err(Error::Invalid("a virtio-fs share lost its DAX window"));
        }
        let mut shares = self.prepared.take();
        if shares.is_none() && !self.fs.is_empty() {
            return Err(Error::Invalid(
                "prepare external dependencies before export",
            ));
        }
        if let Some(shares) = &mut shares {
            shares.bind_references(config.objects)?;
        } else if !config.objects.is_empty() {
            return Err(Error::Invalid("references without shares"));
        }
        if config.application_schema != 1 {
            return Err(Error::Invalid("unsupported application schema"));
        }
        #[cfg(feature = "blk")]
        let disk_dependencies = capture_disk_dependencies(&self.disks, &disks)?;
        #[cfg(not(feature = "blk"))]
        let disk_dependencies = Vec::new();
        let cpus = match self.save_cpus(&compatibility) {
            Err(unanswered @ Error::Control(_)) => {
                self.disable();
                return Err(unanswered);
            }
            cpus => cpus?,
        };
        let vm = self.vm.save_state().map_err(Error::State)?;
        let metadata = Metadata {
            compatibility,
            cpus,
            vm,
            regions,
            disks,
            nic,
            rng,
            balloon,
            vsock,
            console,
            legacy,
            fs: None,
            application_schema: config.application_schema,
            application: config.application,
            disk_dependencies,
        };
        let mut metadata = metadata;
        if let Some(shares) = &shares {
            metadata.fs = Some(shares.meta.clone());
        }
        write_memory(
            &mut file,
            &self.capture_abort,
            &self.memory,
            &metadata,
            shares.as_ref(),
            &qcow2,
        )
    }

    /// Capture and check every paused vCPU's state; `Error::Control` means
    /// a vCPU never answered.
    fn save_cpus(&self, compatibility: &Compatibility) -> Result<Vec<CpuState>> {
        let mut cpus = Vec::with_capacity(self.handles.len());
        for (id, handle) in self.handles.iter().enumerate() {
            let answer = snapshot::answer(handle, |reply| Request::Save {
                size: compatibility.xsave_size,
                reply,
            })
            .map_err(|e| Error::Control(vec![format!("save vCPU {id}: {e}")]))?;
            let state = answer.map_err(|e| Error::Full(format!("save vCPU {id}: {e}")))?;
            compatibility.validate_cpu(&state).map_err(Error::Full)?;
            compatibility
                .validate_topology(&state, id, self.handles.len())
                .map_err(Error::Full)?;
            cpus.push(state);
        }
        Ok(cpus)
    }

    /// Restore scaffolding: new VM/irqchip. Devices must be attached before
    /// the vCPU threads take their bus snapshot in `restore_cpus_and_vm`: a
    /// `Bus` clone is a snapshot, not a live view.
    fn restore_scaffold(kvm: &KvmContext, memory: GuestMemoryMmap) -> Result<Self> {
        let mut owner = Self::register(memory, Topology::default(), kvm)?;
        owner.setup_irqchip()?;
        Ok(owner)
    }

    /// Paused vCPU threads and full state loading with the existing
    /// TSC/clock contract. No configure_minimal, payload loader or boot
    /// parameters on restore. Every device is already on its bus.
    fn restore_cpus_and_vm(
        &mut self,
        target: &Compatibility,
        cpus: Vec<CpuState>,
        vm: VmState,
    ) -> Result<()> {
        // At most snapshot::MAX_CPUS, checked with the metadata.
        self.spawn_vcpus(cpus.len() as u8, |_| Ok(()))?;
        Control::transition(&self.handles, true, CONTROL_TIMEOUT)?;
        for (id, (handle, state)) in self.handles.iter().zip(cpus).enumerate() {
            snapshot::request(handle, |reply| Request::Restore {
                state: Box::new(state),
                size: target.xsave_size,
                reply,
            })
            .map_err(|e| Error::Full(format!("restore vCPU {id}: {e}")))?;
        }
        snapshot::synchronize_offsets(&self.handles).map_err(Error::Full)?;
        self.vm.restore_state(&vm).map_err(Error::State)?;
        Ok(())
    }

    pub(crate) fn import_fd(
        mut file: File,
        bindings: crate::snapshot_vm::checkpoint::ImportBindings,
        mut resources: RestoreResources,
    ) -> Result<Self> {
        // Envelope, payload and external hashes are verified before allocating VM RAM.
        let (metadata, envelope) = read_metadata(&mut file, usize::MAX, snapshot::MAX_CPUS)?;
        Requirements::of(&metadata).check(&resources)?;
        verify_disks(&metadata.disk_dependencies, &bindings.disks, &envelope)?;
        if let Some(fs) = &metadata.fs {
            virtio_fs::validate_bindings(fs, &bindings.shares)?;
        } else if !bindings.shares.is_empty() {
            return Err(Error::Invalid("bindings supplied without shares"));
        }
        let kvm = KvmContext::new().map_err(Error::State)?;
        validate_regions(&metadata.regions, kvm.max_memslots())?;
        validate_devices(&metadata, kvm.max_memslots())?;
        if metadata.cpus.len() > kvm.fd().get_max_vcpus() {
            return Err(Error::Invalid("target vCPU capacity exceeded"));
        }
        #[cfg(all(feature = "blk", feature = "net"))]
        if let Some(socket) = &resources.nic_socket {
            nic::check_socket_path(socket)?;
        }
        if let (Some(meta), Some(ports)) = (&metadata.vsock, &resources.vsock_ports) {
            vsock::check_resources(meta, ports)?;
        }
        if let (Some(meta), Some(ConsoleEndpoints::Ports(ports))) =
            (&metadata.console, &resources.console_ports)
        {
            console::check_resources(meta, ports)?;
        }
        if let Some(serial) = &resources.serial {
            legacy::check_endpoints(serial)?;
        }
        let target = validate_target(&kvm, &metadata.compatibility, &metadata.cpus)?;
        // RAM first (file order), then every ring against the loaded memory.
        let memory = read_ram(&mut file, &metadata.regions)?;
        validate_rings(&metadata, &memory)?;
        // The first resource the import creates: a new console output file,
        // checked like given ports and removed again unless the import
        // succeeds (declared before the owner, so it outlives the owner's
        // console workers).
        let (console_output, console_ports) = match resources.console_ports.take() {
            Some(ConsoleEndpoints::NewOutput(path)) => {
                let (created, ports) = NewConsoleOutput::create(&path)?;
                if let Some(meta) = &metadata.console {
                    console::check_resources(meta, &ports)?;
                }
                (Some(created), Some(ports))
            }
            Some(ConsoleEndpoints::Ports(ports)) => (None, Some(ports)),
            None => (None, None),
        };
        let mut owner = Self::restore_scaffold(&kvm, memory)?;
        #[cfg(feature = "blk")]
        {
            let paths: Vec<_> = bindings
                .disks
                .iter()
                .map(|file| {
                    use std::os::fd::AsRawFd;
                    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
                })
                .collect();
            blk::restore_devices(&mut owner, &metadata.disks, &paths)?;
        }
        #[cfg(all(feature = "blk", feature = "net"))]
        if let (Some(meta), Some(socket)) = (&metadata.nic, &resources.nic_socket) {
            nic::restore_nic(&mut owner, meta, socket)?;
        }
        event_devices::restore(&mut owner, metadata.rng.as_ref(), metadata.balloon.as_ref())?;
        if let (Some(meta), Some(ports)) = (&metadata.vsock, &resources.vsock_ports) {
            vsock::restore(&mut owner, meta, ports)?;
        }
        if let (Some(meta), Some(ports)) = (&metadata.console, console_ports) {
            console::restore(&mut owner, meta, ports)?;
        }
        if let (Some(meta), Some(serial)) = (&metadata.legacy, resources.serial.take()) {
            legacy::restore(&mut owner, meta, serial)?;
        }
        if let Some(meta) = &metadata.fs {
            virtio_fs::restore_external(&mut owner, &mut file, meta, bindings.shares)?;
        }
        owner.start_event_thread(events::Start::Restored)?;
        owner.restore_cpus_and_vm(&target, metadata.cpus, metadata.vm)?;
        // Only now: loading the irqchip state would overwrite an earlier
        // injection. The vCPUs stay paused.
        #[cfg(all(feature = "blk", feature = "net"))]
        nic::signal_discarded_tx(&mut owner)?;
        if owner.exit.requested() {
            return Err(Error::Invalid("a restored vCPU exited before resume"));
        }
        // After the owed injection: draining flushes it into the irqchip.
        owner.pause = Some(owner.quiesce()?);
        owner.host_writers_stopped = true;
        if let Some(output) = console_output {
            output.keep();
        }
        Ok(owner)
    }
}

#[cfg(feature = "blk")]
fn capture_disk_dependencies(
    devices: &[blk::BlkDevice],
    metas: &[blk::DiskMeta],
) -> Result<Vec<DiskDependency>> {
    let mut result = Vec::new();
    for (device, meta) in devices.iter().zip(metas) {
        let block = device.block.lock().unwrap();
        if !meta.read_only {
            if !matches!(
                block.snapshot_image_type(),
                devices::virtio::block::ImageType::Qcow2
            ) {
                return Err(Error::Invalid(
                    "checkpoint container source must remain QCOW2",
                ));
            }
            result.push(DiskDependency::ContainerQcow2);
            continue;
        }
        if !matches!(
            block.snapshot_image_type(),
            devices::virtio::block::ImageType::Raw
        ) {
            return Err(Error::Invalid(
                "external readonly boot disk must be an exact ext4 file",
            ));
        }
        let file = block
            .snapshot_readonly_source()
            .ok_or(Error::Invalid("readonly boot source descriptor missing"))?;
        let length = file.metadata()?.len();
        result.push(DiskDependency::ExternalReadonlyBoot {
            length,
            sha256: format::digest(file, 0, length)?,
        });
    }
    if result
        .iter()
        .filter(|d| matches!(d, DiskDependency::ContainerQcow2))
        .count()
        != 1
    {
        return Err(Error::Invalid(
            "checkpoint requires exactly one writable container disk",
        ));
    }
    Ok(result)
}

fn verify_disks(
    dependencies: &[DiskDependency],
    disks: &[File],
    envelope: &format::Envelope,
) -> Result<()> {
    if dependencies.len() != disks.len() {
        return Err(Error::Invalid("external disk count differs"));
    }
    for (dependency, file) in dependencies.iter().zip(disks) {
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let expected = if matches!(dependency, DiskDependency::ContainerQcow2) {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        if flags < 0 || flags & libc::O_ACCMODE != expected || !file.metadata()?.is_file() {
            return Err(Error::Invalid(
                "external disk descriptor access or type differs",
            ));
        }
        let (length, hash) = match dependency {
            DiskDependency::ContainerQcow2 => {
                verify_qcow2(file)?;
                (envelope.disk_len, envelope.disk_hash)
            }
            DiskDependency::ExternalReadonlyBoot { length, sha256 } => (*length, *sha256),
        };
        if file.metadata()?.len() != length || format::digest(file, 0, length)? != hash {
            return Err(Error::Invalid("external disk length or checksum differs"));
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "blk"))]
mod tests;
