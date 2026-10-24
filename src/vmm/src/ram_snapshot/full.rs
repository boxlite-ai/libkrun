// SPDX-License-Identifier: Apache-2.0

//! Full checkpoints for the private minimal owner, independent of KRUNRAM.
//!
//! Every full image uses one format, version 7 (`KRUNVM\0\0`), with or
//! without devices: header, bounded JSON state, RAM payload, one raw
//! segment per disk, then the virtio-fs file, init.krun and DAX page
//! payloads. The JSON holds CPU, KVM and RAM state, the ordered disk table
//! and the optional NIC, RNG, balloon, vsock, console, legacy-device
//! (UARTs, CMOS, i8042) and virtio-fs sections. Versions 1–6 are rejected
//! explicitly.

use super::*;
use crate::ram_snapshot::console::{self, ConsoleMeta};
use crate::ram_snapshot::event_devices::{self, BalloonMeta, DeviceMeta};
use crate::ram_snapshot::events;
use crate::ram_snapshot::legacy::{self, LegacyMeta};
use crate::ram_snapshot::virtio_fs::{self, FsMeta};
use crate::ram_snapshot::vsock::{self, VsockMeta};
use crate::vstate::snapshot::{self, Compatibility, CpuState, Request};
use crate::vstate::VmState;
use serde::{Deserialize, Serialize};

const FULL_MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const FULL_VERSION: u32 = 7;
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
}

/// Which target resources an image needs; each must be supplied exactly
/// when its device is present.
struct Requirements {
    disks: bool,
    nic: bool,
    vsock: bool,
    console: bool,
    legacy: bool,
    fs: bool,
}

impl Requirements {
    fn of(metadata: &Metadata) -> Self {
        Self {
            disks: !metadata.disks.is_empty(),
            nic: metadata.nic.is_some(),
            vsock: metadata.vsock.is_some(),
            console: metadata.console.is_some(),
            legacy: metadata.legacy.is_some(),
            fs: metadata.fs.is_some(),
        }
    }

    fn check(&self, resources: &RestoreResources) -> Result<()> {
        if self.disks != resources.disk_dir.is_some() {
            return Err(Error::Invalid(
                "restore resources: a disk directory is required exactly when the image has disks",
            ));
        }
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
        if self.fs != resources.fs_dir.is_some() {
            return Err(Error::Invalid(
                "restore resources: a virtio-fs directory is required exactly when the image has shares",
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

/// Total length of the raw disk segments after the RAM payload.
#[cfg(feature = "blk")]
fn disk_segments_len(disks: &DiskTable) -> Result<u64> {
    disks.iter().try_fold(0u64, |total, disk| {
        total
            .checked_add(disk.disk_bytes)
            .ok_or(Error::Invalid("full snapshot disk length overflow"))
    })
}

#[cfg(not(feature = "blk"))]
fn disk_segments_len(_disks: &DiskTable) -> Result<u64> {
    Ok(0)
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

/// Read and check the fixed header; returns the JSON length.
fn read_header(file: &mut File) -> Result<usize> {
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    if &header[..8] != FULL_MAGIC {
        return Err(Error::Invalid("invalid/incomplete full snapshot"));
    }
    match u32::from_le_bytes(header[8..12].try_into().unwrap()) {
        FULL_VERSION => {}
        old @ 1..=6 => {
            return Err(Error::Full(format!(
                "full snapshot version {old} predates the unified version {FULL_VERSION} and is not supported"
            )))
        }
        _ => return Err(Error::Invalid("unsupported full snapshot version")),
    }
    let len = u32::from_le_bytes(header[12..].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_METADATA {
        return Err(Error::Invalid("full metadata exceeds 16 MiB or is empty"));
    }
    Ok(len)
}

/// Read the metadata and validate everything checkable before guest RAM or
/// any target resource exists, including the exact total length.
fn read_metadata(file: &mut File, max_slots: usize, max_cpus: usize) -> Result<Metadata> {
    let len = read_header(file)?;
    let mut encoded = vec![0; len];
    file.read_exact(&mut encoded)?;
    let metadata: Metadata =
        serde_json::from_slice(&encoded).map_err(|e| Error::Full(format!("metadata JSON: {e}")))?;
    if metadata.cpus.is_empty() || metadata.cpus.len() > max_cpus.min(snapshot::MAX_CPUS) {
        return Err(Error::Invalid(
            "full snapshot vCPU count exceeds target capacity or is zero",
        ));
    }
    metadata.vm.validate_snapshot().map_err(Error::Full)?;
    // Every device section relies on validated RAM regions.
    let ram = payload_len(&metadata.regions, max_slots)?;
    let shares = validate_devices(&metadata, max_slots)?;
    let segments = disk_segments_len(&metadata.disks)?;
    let expected = (16 + len as u64)
        .checked_add(ram)
        .and_then(|total| total.checked_add(segments))
        .and_then(|total| total.checked_add(shares))
        .ok_or(Error::Invalid("full snapshot length overflow"))?;
    if expected != file.metadata()?.len() {
        return Err(Error::Invalid(
            "full snapshot length differs from metadata, disk segments and share payloads",
        ));
    }
    Ok(metadata)
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
        Some(meta) => virtio_fs::payload_len(virtio_fs::validate_metadata(
            meta,
            &metadata.regions,
            &device_slots(metadata),
            max_slots,
        )?),
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

/// Create the 0600 exclusive image with an invalid magic placeholder, then
/// write the header, JSON state, RAM, disk segments and share payloads.
fn write_pending(
    path: &Path,
    memory: &GuestMemoryMmap,
    metadata: &Metadata,
    #[cfg(feature = "blk")] disks: &[blk::BlkDevice],
    shares: Option<&devices::virtio::fs::passthrough::ShareArchive>,
) -> Result<PendingSnapshot> {
    let mut encoded = BoundedMetadata(Vec::new());
    serde_json::to_writer(&mut encoded, metadata)
        .map_err(|e| Error::Full(format!("metadata encoding: {e}")))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let mut pending = PendingSnapshot {
        file,
        path: path.to_owned(),
        complete: false,
    };
    pending.file.write_all(&[0; 8])?;
    pending.file.write_all(&FULL_VERSION.to_le_bytes())?;
    pending
        .file
        .write_all(&(encoded.0.len() as u32).to_le_bytes())?;
    pending.file.write_all(&encoded.0)?;
    let mut buffer = [0; CHUNK_SIZE];
    for region in &metadata.regions {
        let mut offset = 0;
        while offset < region.len {
            let len = (region.len - offset).min(CHUNK_SIZE as u64) as usize;
            memory
                .read_slice(&mut buffer[..len], GuestAddress(region.gpa + offset))
                .map_err(Error::Memory)?;
            #[cfg(test)]
            super::tests::write_payload(&mut pending.file, &buffer[..len])?;
            #[cfg(not(test))]
            pending.file.write_all(&buffer[..len])?;
            offset += len as u64;
        }
    }
    #[cfg(feature = "blk")]
    blk::copy_disk_segments(&mut pending.file, disks, &metadata.disks)?;
    if let Some(shares) = shares {
        virtio_fs::write_payloads(&mut pending.file, shares)?;
    }
    pending.file.sync_all()?;
    Ok(pending)
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

    /// Export the paused owner's cut: ONE RAM alias probe (every device is
    /// frozen, so no transient mapping clone is alive) -> device capture
    /// from the cursors the pause retained, legacy, CPU, KVM, RAM and disk
    /// capture -> sync file -> publish valid magic. Nothing is resumed, so
    /// repeated exports capture the same RAM, device and CPU state; each
    /// captures the KVM clock and TSC at its own time, which keep running
    /// while paused, and re-reads the virtio-fs host trees
    /// (`virtio_fs::capture`). A failed export removes its partial image and leaves
    /// the owner paused and retryable, except a vCPU that never answers its
    /// state request: that uncertain control disables the owner and stops
    /// every thread. With virtio-fs shares the caller must have declared
    /// every host writer stopped (`declare_host_writers_stopped`); the
    /// shares are archived as they are at the cut, and a share whose DAX
    /// window was lost disables the owner.
    pub(crate) fn export(&mut self, path: &Path) -> Result<()> {
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
        let paused = self.pause.as_ref().expect("checked above");
        let (fs, shares) = virtio_fs::capture(&self.fs, &paused.fs)?.unzip();
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
            fs,
        };
        if let Some(meta) = &metadata.fs {
            virtio_fs::validate_metadata(
                meta,
                &metadata.regions,
                &device_slots(&metadata),
                self.max_slots,
            )?;
            virtio_fs::validate_rings(meta, &self.memory)?;
        }
        write_pending(
            path,
            &self.memory,
            &metadata,
            #[cfg(feature = "blk")]
            &self.disks,
            shares.as_ref(),
        )?
        .finish(FULL_MAGIC)
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

    /// Import a full checkpoint into a new paused owner. `resources` must
    /// supply exactly the target resources the image's devices need; all
    /// metadata is validated before RAM exists, and every ring against the
    /// loaded RAM before any directory, socket or thread. Disk segments are
    /// imported into a new 0700 directory of exclusive 0600 raw files, which
    /// the owner removes on partial failure and destruction. Cut-time NIC TX
    /// the source had not consumed is already completed as dropped and its
    /// interrupt raised into the restored irqchip. The owner ends in the
    /// state a source has after `pause`: devices frozen, their cursors
    /// retained and every irqfd drained, so it can be exported again before
    /// it ever runs; `resume` starts it. The legacy UARTs take the fresh
    /// `resources.serial` endpoints and replay no output; their
    /// dropped-output counts start at zero. The vsock takes the caller's
    /// `resources.vsock_ports` paths and keeps its backend stopped with the
    /// transport reset still owed until `resume`. The console takes the
    /// caller's `resources.console_ports` endpoints without any endpoint
    /// I/O or new guest handshake; its open ports come back with frozen
    /// workers holding the saved EOF and partial-TX offsets. The virtio-fs
    /// shares are imported into the new 0700 `resources.fs_dir` (an
    /// existing directory is refused untouched), each DAX window is mapped
    /// and its session restored before any vCPU thread exists, and the
    /// imported tree is kept once the import succeeds; host writers start
    /// declared stopped, since only the owner uses those copies.
    pub(crate) fn import(path: &Path, mut resources: RestoreResources) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let metadata = read_metadata(&mut file, kvm.max_memslots(), kvm.fd().get_max_vcpus())?;
        Requirements::of(&metadata).check(&resources)?;
        #[cfg(all(feature = "blk", feature = "net"))]
        if let Some(socket) = &resources.nic_socket {
            nic::check_socket_path(socket)?;
        }
        if let (Some(meta), Some(ports)) = (&metadata.vsock, &resources.vsock_ports) {
            vsock::check_resources(meta, ports)?;
        }
        if let (Some(meta), Some(ports)) = (&metadata.console, &resources.console_ports) {
            console::check_resources(meta, ports)?;
        }
        if let Some(serial) = &resources.serial {
            legacy::check_endpoints(serial)?;
        }
        if let Some(dir) = &resources.fs_dir {
            virtio_fs::check_fs_dir(dir)?;
        }
        let target = validate_target(&kvm, &metadata.compatibility, &metadata.cpus)?;
        // RAM first (file order), then every ring against the loaded memory.
        let memory = read_ram(&mut file, &metadata.regions)?;
        validate_rings(&metadata, &memory)?;
        // The creation guard removes ONLY what this import itself created: a
        // pre-existing destination directory is an error and is never
        // modified. The owner takes the guard before any thread starts, so
        // every later failure cleans up through the owner drop after joining
        // its threads.
        #[cfg(feature = "blk")]
        let (imported, paths) = match &resources.disk_dir {
            Some(dir) => {
                let (imported, paths) = blk::import_disks(&mut file, &metadata.disks, dir)?;
                (Some(imported), paths)
            }
            None => (None, Vec::new()),
        };
        let shares = match (&metadata.fs, &resources.fs_dir) {
            (Some(meta), Some(dir)) => Some(virtio_fs::import_shares(&file, meta, dir)?),
            _ => None,
        };
        let mut owner = Self::restore_scaffold(&kvm, memory)?;
        owner.fs_import = shares;
        #[cfg(feature = "blk")]
        {
            owner.imported = imported;
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
        if let (Some(meta), Some(ports)) = (&metadata.console, resources.console_ports.take()) {
            console::restore(&mut owner, meta, ports)?;
        }
        if let (Some(meta), Some(serial)) = (&metadata.legacy, resources.serial.take()) {
            legacy::restore(&mut owner, meta, serial)?;
        }
        if let Some(meta) = &metadata.fs {
            virtio_fs::restore(&mut owner, meta)?;
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
        if let Some(shares) = owner.fs_import.take() {
            shares.persist();
        }
        Ok(owner)
    }
}

#[cfg(test)]
mod tests;
