// SPDX-License-Identifier: Apache-2.0

//! Full checkpoints for the private minimal owner, independent of KRUNRAM.
//!
//! Version 1 (`KRUNVM\0\0`, version field 1) is the device-free stage-2
//! image: header, bounded JSON state, RAM payload. Version 2 adds ordered
//! raw disk segments after the RAM payload for block devices attached to
//! the owner. Version 3 adds the internal NIC to the JSON state (disk
//! segments stay optional); it is written only when a NIC is attached, so
//! NIC-free owners keep writing versions 1 and 2. Each restore entry
//! rejects the versions it cannot restore explicitly.

use super::*;
use crate::vstate::snapshot::{self, Compatibility, CpuState, Request};
use crate::vstate::VmState;
use serde::{Deserialize, Serialize};

const FULL_MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const FULL_VERSION: u32 = 1;
const FULL_VERSION_V2: u32 = 2;
const FULL_VERSION_V3: u32 = 3;
const MAX_METADATA: usize = 16 * 1024 * 1024;

#[cfg(feature = "blk")]
use crate::ram_snapshot::blk;
#[cfg(all(feature = "blk", feature = "net"))]
use crate::ram_snapshot::nic;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    compatibility: Compatibility,
    cpus: Vec<CpuState>,
    vm: VmState,
    regions: Vec<Region>,
}

/// Version-2 metadata: same state sections plus the ordered disk table.
#[cfg(feature = "blk")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataV2 {
    compatibility: Compatibility,
    cpus: Vec<CpuState>,
    vm: VmState,
    regions: Vec<Region>,
    disks: Vec<blk::DiskMeta>,
}

/// Version-3 metadata: version-2 sections plus the internal NIC.
#[cfg(all(feature = "blk", feature = "net"))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataV3 {
    compatibility: Compatibility,
    cpus: Vec<CpuState>,
    vm: VmState,
    regions: Vec<Region>,
    disks: Vec<blk::DiskMeta>,
    nic: nic::NicMeta,
}

/// Explicit rejection for a restore entry that cannot take `version`.
fn reject_version(version: u32) -> Error {
    match version {
        FULL_VERSION_V2 => {
            Error::Invalid("full snapshot version 2 contains disks; use restore_full_with_disks")
        }
        FULL_VERSION_V3 => Error::Invalid(
            "full snapshot version 3 contains a network device; use restore_full_with_net",
        ),
        _ => Error::Invalid("unsupported full snapshot version"),
    }
}

/// Which irqfds a capture deassigned, recorded even on failure so recovery
/// reassigns exactly those.
#[cfg(feature = "blk")]
#[derive(Default)]
struct Drained {
    disks: Vec<usize>,
    nic: bool,
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

/// Read and check the fixed header; returns (version, JSON length).
fn read_header(file: &mut File) -> Result<(u32, usize)> {
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    if &header[..8] != FULL_MAGIC {
        return Err(Error::Invalid("invalid/incomplete full snapshot"));
    }
    let len = u32::from_le_bytes(header[12..].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_METADATA {
        return Err(Error::Invalid("full metadata exceeds 16 MiB or is empty"));
    }
    Ok((u32::from_le_bytes(header[8..12].try_into().unwrap()), len))
}

fn validate_metadata_common(
    cpus: &[CpuState],
    vm: &VmState,
    regions: &[Region],
    max_cpus: usize,
    max_slots: usize,
) -> Result<()> {
    if cpus.is_empty() || cpus.len() > max_cpus.min(snapshot::MAX_CPUS) {
        return Err(Error::Invalid(
            "full snapshot vCPU count exceeds target capacity or is zero",
        ));
    }
    payload_len(regions, max_slots)?;
    vm.validate_snapshot().map_err(Error::Full)?;
    Ok(())
}

fn read_metadata(file: &mut File, max_slots: usize, max_cpus: usize) -> Result<Metadata> {
    let (version, len) = read_header(file)?;
    if version != FULL_VERSION {
        return Err(reject_version(version));
    }
    let mut encoded = vec![0; len];
    file.read_exact(&mut encoded)?;
    let metadata: Metadata =
        serde_json::from_slice(&encoded).map_err(|e| Error::Full(format!("metadata JSON: {e}")))?;
    validate_metadata_common(
        &metadata.cpus,
        &metadata.vm,
        &metadata.regions,
        max_cpus,
        max_slots,
    )?;
    let expected = (16 + len as u64)
        .checked_add(payload_len(&metadata.regions, max_slots)?)
        .ok_or(Error::Invalid("full snapshot length overflow"))?;
    if expected != file.metadata()?.len() {
        return Err(Error::Invalid("full snapshot length differs from metadata"));
    }
    Ok(metadata)
}

/// Read device-image metadata of `version` and validate the exact total
/// length, including every disk segment, before any target resource is
/// created; `validate` adds the version's own metadata checks.
#[cfg(feature = "blk")]
fn read_device_metadata<M: serde::de::DeserializeOwned>(
    file: &mut File,
    version: u32,
    max_slots: usize,
    max_cpus: usize,
    sections: impl Fn(&M) -> (&[CpuState], &VmState, &[Region], &[blk::DiskMeta]),
) -> Result<M> {
    let (found, len) = read_header(file)?;
    if found != version {
        return Err(reject_version(found));
    }
    let mut encoded = vec![0; len];
    file.read_exact(&mut encoded)?;
    let metadata: M =
        serde_json::from_slice(&encoded).map_err(|e| Error::Full(format!("metadata JSON: {e}")))?;
    let (cpus, vm, regions, disks) = sections(&metadata);
    validate_metadata_common(cpus, vm, regions, max_cpus, max_slots)?;
    let mut expected = (16 + len as u64)
        .checked_add(payload_len(regions, max_slots)?)
        .ok_or(Error::Invalid("full snapshot length overflow"))?;
    for disk in disks {
        expected = expected
            .checked_add(disk.disk_bytes)
            .ok_or(Error::Invalid("full snapshot disk length overflow"))?;
    }
    if expected != file.metadata()?.len() {
        return Err(Error::Invalid(
            "full snapshot length differs from metadata and disk segments",
        ));
    }
    blk::validate_disk_metadata(disks, regions)?;
    Ok(metadata)
}

#[cfg(feature = "blk")]
fn read_metadata_v2(file: &mut File, max_slots: usize, max_cpus: usize) -> Result<MetadataV2> {
    read_device_metadata(
        file,
        FULL_VERSION_V2,
        max_slots,
        max_cpus,
        |m: &MetadataV2| (&m.cpus, &m.vm, &m.regions, &m.disks),
    )
}

#[cfg(all(feature = "blk", feature = "net"))]
fn read_metadata_v3(file: &mut File, max_slots: usize, max_cpus: usize) -> Result<MetadataV3> {
    let metadata = read_device_metadata(
        file,
        FULL_VERSION_V3,
        max_slots,
        max_cpus,
        |m: &MetadataV3| (&m.cpus, &m.vm, &m.regions, &m.disks),
    )?;
    nic::validate_nic_metadata(&metadata.nic, &metadata.disks, &metadata.regions)?;
    Ok(metadata)
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
                .write_slice(&mut buffer[..len], GuestAddress(region.gpa + offset))
                .map_err(Error::Memory)?;
            offset += len as u64;
        }
    }
    Ok(memory)
}

/// Create the 0600 exclusive image with an invalid magic placeholder and
/// write the versioned header plus JSON state.
fn write_header_and_metadata(path: &Path, version: u32, encoded: &[u8]) -> Result<PendingSnapshot> {
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
    pending.file.write_all(&version.to_le_bytes())?;
    pending
        .file
        .write_all(&(encoded.len() as u32).to_le_bytes())?;
    pending.file.write_all(encoded)?;
    Ok(pending)
}

fn write_ram_regions(
    pending: &mut PendingSnapshot,
    memory: &GuestMemoryMmap,
    regions: &[Region],
) -> Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    for region in regions {
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
    Ok(())
}

fn write_pending(
    path: &Path,
    memory: &GuestMemoryMmap,
    metadata: &Metadata,
) -> Result<PendingSnapshot> {
    let mut encoded = BoundedMetadata(Vec::new());
    serde_json::to_writer(&mut encoded, metadata)
        .map_err(|e| Error::Full(format!("metadata encoding: {e}")))?;
    let mut pending = write_header_and_metadata(path, FULL_VERSION, &encoded.0)?;
    write_ram_regions(&mut pending, memory, &metadata.regions)?;
    pending.file.sync_all()?;
    Ok(pending)
}

/// Version-2/3 writer: header, JSON, RAM, then ordered raw disk segments.
#[cfg(feature = "blk")]
fn write_pending_with_disks<M: Serialize>(
    path: &Path,
    version: u32,
    memory: &GuestMemoryMmap,
    metadata: &M,
    regions: &[Region],
    disks: &[blk::BlkDevice],
    disk_metas: &[blk::DiskMeta],
) -> Result<PendingSnapshot> {
    let mut encoded = BoundedMetadata(Vec::new());
    serde_json::to_writer(&mut encoded, metadata)
        .map_err(|e| Error::Full(format!("metadata encoding: {e}")))?;
    let mut pending = write_header_and_metadata(path, version, &encoded.0)?;
    write_ram_regions(&mut pending, memory, regions)?;
    blk::copy_disk_segments(&mut pending.file, disks, disk_metas)?;
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

/// Fold up to three recovery results into one error: the first failure is
/// the operation error, one further failure becomes its recovery error.
/// Exhaustive by construction; no result is unwrapped.
fn combine_recovery(first: Error, second: Result<()>, third: Result<()>) -> Error {
    match second.err().or(third.err()) {
        None => first,
        Some(recovery) => Error::Recovery {
            operation: Box::new(first),
            resume: Box::new(recovery),
        },
    }
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

    pub(crate) fn save_full(&mut self, path: &Path) -> Result<()> {
        #[cfg(feature = "blk")]
        if self.has_devices() {
            return self.save_full_with_devices(path);
        }
        if self.control.unusable || self.paused || self.handles.is_empty() || !self.irqchip_ready {
            return Err(Error::Invalid(
                "full save requires a running usable minimal kernel-irqchip VM",
            ));
        }
        let regions = self.topology.regions(&self.memory)?;
        payload_len(&regions, self.max_slots)?;
        for region in self.memory.iter() {
            // remove_region returns a cloned collection plus the removed Arc;
            // exactly two references means only this owner and this probe hold it.
            let (_remaining, mapping) = self
                .memory
                .remove_region(region.start_addr(), region.len())
                .map_err(|e| Error::Full(format!("inspect RAM ownership: {e}")))?;
            if std::sync::Arc::strong_count(&mapping) != 2 {
                return Err(Error::Invalid(
                    "full snapshot RAM has external aliases/writers",
                ));
            }
        }
        let kvm = KvmContext::new().map_err(Error::State)?;
        let compatibility = Compatibility::capture(kvm.fd()).map_err(Error::Full)?;
        let pause = if self
            .handles
            .iter()
            .any(|h| !h.response_receiver().is_empty())
        {
            Err(Error::Invalid("unconsumed vCPU response before full save"))
        } else {
            Control::transition(&self.handles, true, CONTROL_TIMEOUT)
        };
        if pause.is_err() {
            self.control.unusable = true;
        }
        let operation = pause.and_then(|_| {
            let mut cpus = Vec::with_capacity(self.handles.len());
            for (id, handle) in self.handles.iter().enumerate() {
                let state = snapshot::request(handle, |reply| Request::Save {
                    size: compatibility.xsave_size,
                    reply,
                })
                .map_err(|e| Error::Full(format!("save vCPU {id}: {e}")))?;
                compatibility.validate_cpu(&state).map_err(Error::Full)?;
                compatibility
                    .validate_topology(&state, id, self.handles.len())
                    .map_err(Error::Full)?;
                cpus.push(state);
            }
            let vm = self.vm.save_state().map_err(Error::State)?;
            write_pending(
                path,
                &self.memory,
                &Metadata {
                    compatibility,
                    cpus,
                    vm,
                    regions,
                },
            )
        });
        // Always try every source CPU, including a late Pause after a timeout.
        let resume = Control::transition(&self.handles, false, CONTROL_TIMEOUT);
        if resume.is_err() {
            self.control.unusable = true;
        }
        match (operation, resume) {
            (Ok(mut pending), Ok(())) => {
                pending.file.seek(SeekFrom::Start(0))?;
                pending.file.write_all(FULL_MAGIC)?;
                pending.file.sync_all()?;
                pending.complete = true;
                Ok(())
            }
            (Err(operation), Err(resume)) => Err(Error::Recovery {
                operation: Box::new(operation),
                resume: Box::new(resume),
            }),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }

    /// Version-2 (disks) or version-3 (NIC, optional disks) save.
    ///
    /// Order: configuration checks -> pause/ack ALL vCPUs -> freeze ALL
    /// devices (every disk, then the NIC) -> ONE RAM alias probe at the
    /// quiescent boundary -> interrupt drain (synchronous KVM deassign) ->
    /// device, CPU, KVM, RAM and disk capture -> sync file -> reassign
    /// source irqfds, resume ALL devices, resume ALL CPUs (each attempted
    /// independently) -> publish valid magic. The source NIC keeps its
    /// backend connection and worker buffers across the save.
    #[cfg(feature = "blk")]
    fn save_full_with_devices(&mut self, path: &Path) -> Result<()> {
        if self.control.unusable || self.paused || self.handles.is_empty() || !self.irqchip_ready {
            return Err(Error::Invalid(
                "full save requires a running usable kernel-irqchip VM",
            ));
        }
        let regions = self.topology.regions(&self.memory)?;
        payload_len(&regions, self.max_slots)?;
        let kvm = KvmContext::new().map_err(Error::State)?;
        let compatibility = Compatibility::capture(kvm.fd()).map_err(Error::Full)?;
        let pause = if self
            .handles
            .iter()
            .any(|h| !h.response_receiver().is_empty())
        {
            Err(Error::Invalid("unconsumed vCPU response before full save"))
        } else {
            Control::transition(&self.handles, true, CONTROL_TIMEOUT)
        };
        if pause.is_err() {
            self.control.unusable = true;
        }
        let mut drained = Drained::default();
        let operation = pause.and_then(|_| {
            // vCPUs are paused: device activation cannot race the expected
            // clone count. Every worker is frozen before the single probe,
            // so no transient mapping clone is alive when it counts.
            let frozen_disks = blk::freeze_disks(self)?;
            #[cfg(feature = "net")]
            let frozen_nic = nic::freeze(self)?;
            self.probe_ram_aliases(self.expected_device_clones())?;
            blk::drain_disk_irqfds(self, &mut drained.disks)?;
            #[cfg(feature = "net")]
            nic::drain_irqfd(self, &mut drained.nic)?;
            let disks = blk::capture_disks(self, &frozen_disks, &regions)?;
            #[cfg(feature = "net")]
            let nic = nic::capture(self, frozen_nic, &disks, &regions)?;
            let mut cpus = Vec::with_capacity(self.handles.len());
            for (id, handle) in self.handles.iter().enumerate() {
                let state = snapshot::request(handle, |reply| Request::Save {
                    size: compatibility.xsave_size,
                    reply,
                })
                .map_err(|e| Error::Full(format!("save vCPU {id}: {e}")))?;
                compatibility.validate_cpu(&state).map_err(Error::Full)?;
                compatibility
                    .validate_topology(&state, id, self.handles.len())
                    .map_err(Error::Full)?;
                cpus.push(state);
            }
            let vm = self.vm.save_state().map_err(Error::State)?;
            #[cfg(feature = "net")]
            if let Some(nic) = nic {
                let metadata = MetadataV3 {
                    compatibility,
                    cpus,
                    vm,
                    regions,
                    disks,
                    nic,
                };
                return write_pending_with_disks(
                    path,
                    FULL_VERSION_V3,
                    &self.memory,
                    &metadata,
                    &metadata.regions,
                    &self.disks,
                    &metadata.disks,
                );
            }
            let metadata = MetadataV2 {
                compatibility,
                cpus,
                vm,
                regions,
                disks,
            };
            write_pending_with_disks(
                path,
                FULL_VERSION_V2,
                &self.memory,
                &metadata,
                &metadata.regions,
                &self.disks,
                &metadata.disks,
            )
        });
        // Restore source devices and ALL CPUs before deciding publication,
        // attempting every step independently: an irqfd failure must not
        // skip the device resumes, and a device failure must not skip the
        // CPU resumes. Order: reattach the irqfds (so resumed workers
        // cannot signal an unregistered eventfd), resume every device
        // (also on the success path: a saved source VM keeps running),
        // then resume every CPU.
        let irqfds = self.reassign_irqfds(&drained);
        let devices = self.resume_devices();
        let resume = Control::transition(&self.handles, false, CONTROL_TIMEOUT);
        if irqfds.is_err() || devices.is_err() || resume.is_err() {
            self.control.unusable = true;
        }
        let recovery = match (irqfds, devices, resume) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(first), second, third) => Err(combine_recovery(first, second, third)),
            (Ok(()), Err(first), third) => Err(combine_recovery(first, Ok(()), third)),
            (Ok(()), Ok(()), Err(first)) => Err(first),
        };
        match (operation, recovery) {
            (Ok(mut pending), Ok(())) => {
                pending.file.seek(SeekFrom::Start(0))?;
                pending.file.write_all(FULL_MAGIC)?;
                pending.file.sync_all()?;
                pending.complete = true;
                Ok(())
            }
            (Err(operation), Err(recovery)) => Err(Error::Recovery {
                operation: Box::new(operation),
                resume: Box::new(recovery),
            }),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }

    /// Reassign every drained irqfd (disks, then the NIC); a single failure
    /// must not skip the rest.
    #[cfg(feature = "blk")]
    fn reassign_irqfds(&self, drained: &Drained) -> Result<()> {
        let disks = blk::reassign_irqfds(self, &drained.disks);
        #[cfg(feature = "net")]
        let nic = nic::reassign_irqfd(self, drained.nic);
        #[cfg(not(feature = "net"))]
        let nic: Result<()> = Ok(());
        disks.and(nic)
    }

    /// Resume every device worker (disks, then the NIC); each actively
    /// re-examines its queues, and one failure does not skip the rest.
    #[cfg(feature = "blk")]
    fn resume_devices(&self) -> Result<()> {
        let disks = blk::resume_devices(self);
        #[cfg(feature = "net")]
        let nic = nic::resume(self);
        #[cfg(not(feature = "net"))]
        let nic: Result<()> = Ok(());
        disks.and(nic)
    }

    /// Restore scaffolding: new VM/irqchip. Devices must be attached (blk)
    /// before the vCPU threads take their bus snapshot in
    /// `restore_cpus_and_vm`: a `Bus` clone is a snapshot, not a live view.
    fn restore_scaffold(kvm: &KvmContext, memory: GuestMemoryMmap) -> Result<Self> {
        let mut owner = Self::register(memory, Topology::default(), kvm)?;
        owner.setup_irqchip()?;
        Ok(owner)
    }

    /// Shared tail of both restore entries: paused vCPU threads and full
    /// state loading with the existing TSC/clock contract. No
    /// configure_minimal, payload loader or boot parameters on restore.
    fn restore_cpus_and_vm(
        &mut self,
        target: &Compatibility,
        cpus: Vec<CpuState>,
        vm: VmState,
    ) -> Result<()> {
        Vcpu::register_kick_signal_handler();
        for id in 0..cpus.len() {
            let mut cpu = Vcpu::new_x86_64(
                id as u8,
                self.vm.fd(),
                self.vm.supported_cpuid().clone(),
                self.vm.supported_msrs().clone(),
                devices::Bus::new(),
                utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)?,
            )
            .map_err(Error::State)?;
            // The restored devices were attached before this snapshot of
            // the bus: MMIO dispatch reaches the new transports.
            #[cfg(feature = "blk")]
            cpu.set_mmio_bus(self.bus.clone());
            self.handles
                .push(cpu.start_threaded().map_err(Error::State)?);
        }
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

    pub(crate) fn restore_full(path: &Path) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let metadata = read_metadata(&mut file, kvm.max_memslots(), kvm.fd().get_max_vcpus())?;
        let target = validate_target(&kvm, &metadata.compatibility, &metadata.cpus)?;
        let memory = read_ram(&mut file, &metadata.regions)?;
        let mut owner = Self::restore_scaffold(&kvm, memory)?;
        owner.restore_cpus_and_vm(&target, metadata.cpus, metadata.vm)?;
        Ok(owner)
    }

    /// Restore a full checkpoint, importing version-2 disk segments into a
    /// new 0700 destination directory of exclusive 0600 raw files. The owner
    /// removes the imported directory on partial failure and destruction.
    #[cfg(feature = "blk")]
    pub(crate) fn restore_full_with_disks(path: &Path, destination: &Path) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let (version, _) = read_header(&mut file)?;
        if version == FULL_VERSION {
            // A device-free version-1 image has no segments to import.
            return Self::restore_full(path);
        }
        if version != FULL_VERSION_V2 {
            return Err(reject_version(version));
        }
        file.seek(SeekFrom::Start(0))?;
        let metadata = read_metadata_v2(&mut file, kvm.max_memslots(), kvm.fd().get_max_vcpus())?;
        let target = validate_target(&kvm, &metadata.compatibility, &metadata.cpus)?;
        // RAM first (file order), then validate the active rings against the
        // loaded memory, and only then create the destination directory.
        let memory = read_ram(&mut file, &metadata.regions)?;
        blk::validate_disk_rings(&metadata.disks, &memory)?;
        // The creation guard removes ONLY what this import itself created:
        // a pre-existing destination directory is an error and is never
        // modified. The owner takes the guard as soon as it exists — before
        // any worker thread starts — so every later failure path cleans up
        // through the owner drop after joining its threads.
        let restore = (|| -> Result<Self> {
            let (imported, paths) = blk::import_disks(&mut file, &metadata.disks, destination)?;
            let mut owner = Self::restore_scaffold(&kvm, memory)?;
            owner.imported = Some(imported);
            // Devices attach BEFORE the vCPU threads snapshot the bus, so
            // restored MMIO dispatch reaches the new transports.
            blk::restore_devices(&mut owner, &metadata.disks, &paths)?;
            owner.restore_cpus_and_vm(&target, metadata.cpus, metadata.vm)?;
            Ok(owner)
        })();
        // On failure the guard (still local, or already inside a half-built
        // owner whose Drop ran) removed the imported files; a foreign
        // destination was never touched.
        restore
    }

    /// Restore a version-3 checkpoint with the internal NIC, connecting a
    /// freshly started compatible UnixStream backend at `socket_path`.
    /// Disk segments, if any, are imported as in `restore_full_with_disks`
    /// (no destination is created for a disk-free image). Versions 1 and 2
    /// have no NIC and are rejected. Returns a paused owner: cut-time TX the
    /// source had not consumed is already completed as dropped and its
    /// interrupt raised into the restored irqchip; `resume` starts it.
    #[cfg(all(feature = "blk", feature = "net"))]
    pub(crate) fn restore_full_with_net(
        path: &Path,
        disk_destination: &Path,
        socket_path: &Path,
    ) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let metadata = read_metadata_v3(&mut file, kvm.max_memslots(), kvm.fd().get_max_vcpus())?;
        let target = validate_target(&kvm, &metadata.compatibility, &metadata.cpus)?;
        // RAM first (file order), then every ring against the loaded memory,
        // and only then any directory, socket or thread.
        let memory = read_ram(&mut file, &metadata.regions)?;
        blk::validate_disk_rings(&metadata.disks, &memory)?;
        nic::validate_nic_rings(&metadata.nic, &memory)?;
        // As in restore_full_with_disks, the owner takes the import guard
        // before any worker starts; a failure drops the half-built owner,
        // which joins CPUs, then workers, then removes imported files.
        let (imported, paths) = if metadata.disks.is_empty() {
            (None, Vec::new())
        } else {
            let (imported, paths) =
                blk::import_disks(&mut file, &metadata.disks, disk_destination)?;
            (Some(imported), paths)
        };
        let mut owner = Self::restore_scaffold(&kvm, memory)?;
        owner.imported = imported;
        // Devices attach BEFORE the vCPU threads snapshot the bus.
        blk::restore_devices(&mut owner, &metadata.disks, &paths)?;
        nic::restore_nic(&mut owner, &metadata.nic, socket_path)?;
        owner.restore_cpus_and_vm(&target, metadata.cpus, metadata.vm)?;
        // Only now: loading the irqchip state would overwrite an earlier
        // injection. The vCPUs stay paused.
        nic::signal_discarded_tx(&mut owner)?;
        Ok(owner)
    }

    pub(crate) fn resume(&mut self) -> Result<()> {
        if !self.paused || self.control.unusable || self.handles.is_empty() {
            return Err(Error::Invalid("resume requires a restored paused full VM"));
        }
        // Devices first: their resumed workers actively re-examine queues,
        // so no kick count is lost when the CPUs start running. If any
        // device fails to resume, no vCPU is resumed at all.
        #[cfg(feature = "blk")]
        let devices = self.resume_devices();
        #[cfg(not(feature = "blk"))]
        let devices: Result<()> = Ok(());
        let result =
            devices.and_then(|_| Control::transition(&self.handles, false, CONTROL_TIMEOUT));
        if result.is_err() {
            // Incomplete resume: no thread keeps running. CPUs join first
            // (they could still touch devices), then the workers join; the
            // imported guard removal stays with the owner drop.
            self.control.unusable = true;
            for handle in &mut self.handles {
                handle.finish();
            }
            #[cfg(feature = "blk")]
            self.stop_devices();
            return result;
        }
        self.paused = false;
        result
    }
}

#[cfg(test)]
mod tests;
