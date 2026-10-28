//! Sparse hotplug RAM belongs to virtio-mem, never to the boot RAM table.
use super::*;
use devices::virtio::mem::{HotplugRegion, Mem, MemSnapshot, MemoryControl, SLOT_SIZE};

impl RamSnapshotVm {
    pub(crate) fn memory_control(&self) -> Option<Arc<MemoryControl>> {
        self.memory_device.as_ref().map(|d| d.device.lock().unwrap().control())
    }

    pub(super) fn memory_slot_count(&self) -> usize {
        self.memory_device.as_ref().map_or(self.memory.num_regions(), |d| {
            self.memory.num_regions() - 1 + (d.device.lock().unwrap().snapshot().size / SLOT_SIZE) as usize
        })
    }

    pub(super) fn boot_memory(&self) -> Result<GuestMemoryMmap> {
        match &self.memory_device {
            None => Ok(self.memory.clone()),
            Some(d) => {
                let state = d.device.lock().unwrap().snapshot();
                self.memory.remove_region(GuestAddress(state.addr), state.size)
                    .map(|(memory, _)| memory).map_err(|e| Error::Full(e.to_string()))
            }
        }
    }

    /// This temporary view permits ring validation to touch only mapped slots.
    /// Raw mappings borrow the reservation; the owner outlives the entire view.
    pub(super) fn accessible_memory(&self) -> Result<GuestMemoryMmap> {
        let mut memory = self.boot_memory()?;
        if let Some(d) = &self.memory_device {
            let state = d.device.lock().unwrap().snapshot();
            for slot in state.mapped_slots() {
                let gpa = GuestAddress(state.addr + slot as u64 * SLOT_SIZE);
                let host = self.memory.get_host_address(gpa).map_err(Error::Memory)?;
                let raw = unsafe { vm_memory::mmap::MmapRegion::build_raw(host, SLOT_SIZE as usize, 0, 0) }
                    .map_err(|e| Error::Full(e.to_string()))?;
                let region = vm_memory::GuestRegionMmap::new(raw, gpa)
                    .ok_or(Error::Invalid("hotplug validation range overflow"))?;
                memory = memory.insert_region(Arc::new(region)).map_err(|e| Error::Full(e.to_string()))?;
            }
        }
        Ok(memory)
    }

    pub(super) fn create_memory_device(&mut self, control: Arc<MemoryControl>, addr: u64, size: u64) -> Result<Mem> {
        let wanted = u32::try_from(size / SLOT_SIZE).map_err(|_| Error::Invalid("hotplug slot overflow"))?;
        let (fd, first, count) = self.vm.reserve_memory_slots(wanted);
        if count != wanted || count == 0 { return Err(Error::Invalid("insufficient KVM hotplug slots")); }
        let region = HotplugRegion::new(fd, first, addr, size)?;
        self.memory = self.memory.insert_region(region.memory.clone()).map_err(|e| Error::Full(e.to_string()))?;
        Ok(Mem::new(control, region)?)
    }
}

pub(super) fn extents(state: &MemSnapshot) -> impl Iterator<Item = (u64, u64)> + '_ {
    state.mapped_slots().map(|slot| (state.addr + slot as u64 * SLOT_SIZE, SLOT_SIZE))
}

pub(super) fn payload_len(meta: Option<&event_devices::MemoryMeta>) -> u64 {
    meta.map_or(0, |m| m.state.mapped_slots().count() as u64 * SLOT_SIZE)
}

pub(super) fn restore(vm: &mut RamSnapshotVm, file: &mut File, meta: &event_devices::MemoryMeta) -> Result<()> {
    let state = &meta.state;
    let control = Arc::new(MemoryControl::new(state.initial_mib, state.status.max_mib)?);
    let mut device = vm.create_memory_device(control, state.addr, state.size)?;
    device.restore_snapshot(state)?;
    let mut buffer = [0; CHUNK_SIZE];
    for (gpa, len) in extents(state) {
        let mut offset = 0;
        while offset < len {
            let n = (len - offset).min(CHUNK_SIZE as u64) as usize;
            file.read_exact(&mut buffer[..n])?;
            vm.memory.write_slice(&buffer[..n], GuestAddress(gpa + offset)).map_err(Error::Memory)?;
            offset += n as u64;
        }
    }
    event_devices::restore_memory(vm, meta, device)
}
