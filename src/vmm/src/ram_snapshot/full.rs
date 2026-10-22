// SPDX-License-Identifier: Apache-2.0

//! Full checkpoints for the private device-free owner, independent of KRUNRAM.

use super::*;
use crate::vstate::snapshot::{self, Compatibility, CpuState, Request};
use crate::vstate::VmState;
use serde::{Deserialize, Serialize};

const FULL_MAGIC: &[u8; 8] = b"KRUNVM\0\0";
const FULL_VERSION: u32 = 1;
const MAX_METADATA: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    compatibility: Compatibility,
    cpus: Vec<CpuState>,
    vm: VmState,
    regions: Vec<Region>,
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

fn read_metadata(file: &mut File, max_slots: usize, max_cpus: usize) -> Result<Metadata> {
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    if &header[..8] != FULL_MAGIC
        || u32::from_le_bytes(header[8..12].try_into().unwrap()) != FULL_VERSION
    {
        return Err(Error::Invalid(
            "invalid/incomplete full snapshot or unsupported version",
        ));
    }
    let len = u32::from_le_bytes(header[12..].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_METADATA {
        return Err(Error::Invalid("full metadata exceeds 16 MiB or is empty"));
    }
    let mut encoded = vec![0; len];
    file.read_exact(&mut encoded)?;
    let metadata: Metadata =
        serde_json::from_slice(&encoded).map_err(|e| Error::Full(format!("metadata JSON: {e}")))?;
    if metadata.cpus.is_empty() || metadata.cpus.len() > max_cpus.min(snapshot::MAX_CPUS) {
        return Err(Error::Invalid(
            "full snapshot vCPU count exceeds target capacity or is zero",
        ));
    }
    let expected = (16 + len as u64)
        .checked_add(payload_len(&metadata.regions, max_slots)?)
        .ok_or(Error::Invalid("full snapshot length overflow"))?;
    if expected != file.metadata()?.len() {
        return Err(Error::Invalid("full snapshot length differs from metadata"));
    }
    metadata.vm.validate_snapshot().map_err(Error::Full)?;
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
                .write_slice(&buffer[..len], GuestAddress(region.gpa + offset))
                .map_err(Error::Memory)?;
            offset += len as u64;
        }
    }
    Ok(memory)
}

fn write_pending(
    path: &Path,
    memory: &GuestMemoryMmap,
    metadata: &Metadata,
) -> Result<PendingSnapshot> {
    let mut encoded = BoundedMetadata(Vec::new());
    serde_json::to_writer(&mut encoded, metadata)
        .map_err(|e| Error::Full(format!("metadata encoding: {e}")))?;
    let encoded = encoded.0;
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
        .write_all(&(encoded.len() as u32).to_le_bytes())?;
    pending.file.write_all(&encoded)?;
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
    pending.file.sync_all()?;
    Ok(pending)
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

    pub(crate) fn restore_full(path: &Path) -> Result<Self> {
        let kvm = KvmContext::new().map_err(Error::State)?;
        let mut file = File::open(path)?;
        let metadata = read_metadata(&mut file, kvm.max_memslots(), kvm.fd().get_max_vcpus())?;
        let target = Compatibility::capture(kvm.fd()).map_err(Error::Full)?;
        metadata
            .compatibility
            .validate_target(&target)
            .map_err(Error::Full)?;
        for (id, state) in metadata.cpus.iter().enumerate() {
            target.validate_cpu(state).map_err(Error::Full)?;
            target
                .validate_topology(state, id, metadata.cpus.len())
                .map_err(Error::Full)?;
        }
        let memory = read_ram(&mut file, &metadata.regions)?;
        let mut owner = Self::register(memory, Topology::default(), &kvm)?;
        owner.setup_irqchip()?;
        Vcpu::register_kick_signal_handler();
        // No configure_minimal, payload loader or boot parameters on restore.
        for id in 0..metadata.cpus.len() {
            let cpu = Vcpu::new_x86_64(
                id as u8,
                owner.vm.fd(),
                owner.vm.supported_cpuid().clone(),
                owner.vm.supported_msrs().clone(),
                devices::Bus::new(),
                utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)?,
            )
            .map_err(Error::State)?;
            owner
                .handles
                .push(cpu.start_threaded().map_err(Error::State)?);
        }
        Control::transition(&owner.handles, true, CONTROL_TIMEOUT)?;
        for (id, (handle, state)) in owner.handles.iter().zip(metadata.cpus).enumerate() {
            snapshot::request(handle, |reply| Request::Restore {
                state: Box::new(state),
                size: target.xsave_size,
                reply,
            })
            .map_err(|e| Error::Full(format!("restore vCPU {id}: {e}")))?;
        }
        snapshot::synchronize_offsets(&owner.handles).map_err(Error::Full)?;
        owner.vm.restore_state(&metadata.vm).map_err(Error::State)?;
        Ok(owner)
    }

    pub(crate) fn resume(&mut self) -> Result<()> {
        if !self.paused || self.control.unusable || self.handles.is_empty() {
            return Err(Error::Invalid("resume requires a restored paused full VM"));
        }
        let result = Control::transition(&self.handles, false, CONTROL_TIMEOUT);
        if result.is_err() {
            self.control.unusable = true;
        } else {
            self.paused = false;
        }
        result
    }
}

#[cfg(test)]
mod tests;
