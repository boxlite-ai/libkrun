// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};
use std::sync::Arc;

use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap};

use super::{Config, Mem, MemoryStatus, BLOCK_SIZE, MIB, SLOT_SIZE};
use crate::virtio::persist::{invalid, QueueState, VirtioDeviceState};
use crate::virtio::{DeviceState, VirtioDevice};

/// Device state; the container must also save the mapped slot bytes and MMIO
/// transport. Slot numbers are local to a VM and are allocated anew on import.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemState {
    pub device: VirtioDeviceState,
    pub queue: Option<QueueState>,
    pub initial_mib: u32,
    pub status: MemoryStatus,
    pub addr: u64,
    pub size: u64,
    pub usable_size: u64,
    pub requested_size: u64,
    pub plugged: Vec<bool>,
    pub mapped: Vec<bool>,
}

impl MemState {
    pub fn memory_bytes(&self) -> u64 {
        self.mapped.iter().filter(|&&v| v).count() as u64 * SLOT_SIZE
    }

    /// Validate before allocating memory, installing KVM slots or touching RAM.
    pub fn validate(&self) -> io::Result<()> {
        if self.size == 0
            || !self.addr.is_multiple_of(SLOT_SIZE)
            || !self.size.is_multiple_of(SLOT_SIZE)
            || self.addr.checked_add(self.size).is_none()
            || self.mapped.len() as u64 != self.size / SLOT_SIZE
            || self.plugged.len() as u64 != self.size / BLOCK_SIZE
            || self.usable_size > self.size
            || !self.usable_size.is_multiple_of(BLOCK_SIZE)
            || self.requested_size > self.size
            || !self.requested_size.is_multiple_of(SLOT_SIZE)
            || self.status.max_mib as u64 != self.initial_mib as u64 + self.size / MIB
            || self.status.requested_mib < self.initial_mib
            || self.status.requested_mib > self.status.max_mib
            || !(self.status.requested_mib - self.initial_mib).is_multiple_of(super::SLOT_MIB)
            || u64::from(self.status.requested_mib - self.initial_mib) * MIB < self.requested_size
            || self.status.active != u32::from(self.device.activated)
            || self.queue.is_some() != self.device.activated
        {
            return Err(invalid("invalid virtio-mem layout or host target"));
        }
        let plugged = self.plugged.iter().filter(|&&v| v).count() as u64 * BLOCK_SIZE;
        if plugged > self.requested_size
            || u64::from(self.status.plugged_mib) != u64::from(self.initial_mib) + plugged / MIB
            || u64::from(self.status.mapped_mib)
                != u64::from(self.initial_mib) + self.memory_bytes() / MIB
            || self.plugged[(self.usable_size / BLOCK_SIZE) as usize..]
                .iter()
                .any(|&v| v)
        {
            return Err(invalid("virtio-mem accounting disagrees with bitmap"));
        }
        for (blocks, &mapped) in self
            .plugged
            .chunks((SLOT_SIZE / BLOCK_SIZE) as usize)
            .zip(&self.mapped)
        {
            if blocks.iter().any(|&v| v) != mapped {
                return Err(invalid("virtio-mem bitmap disagrees with KVM slots"));
            }
        }
        Ok(())
    }
}

impl Mem {
    /// Called under the device lock, after stopping vCPUs and other RAM writers.
    /// This also excludes online host target requests. It does not freeze the
    /// rest of the VM, nor replace the VMM's event-loop barrier.
    pub fn freeze(&mut self) {
        self.control.freeze();
        self.frozen = true;
    }

    pub fn resume(&mut self) -> io::Result<()> {
        if !self.frozen || self.restore_failed || self.restore_pending_activation {
            return Err(invalid("virtio-mem is not frozen"));
        }
        if self.is_activated() {
            self.activate_evt.write(1)?;
        }
        if let Some(queue) = &self.queue {
            queue.event.write(1)?;
        }
        self.control.resume()?;
        self.frozen = false;
        Ok(())
    }

    pub fn save_state(&self) -> io::Result<MemState> {
        if !self.frozen || self.restore_failed {
            return Err(invalid("virtio-mem snapshot requires freeze"));
        }
        let queue = match (&self.queue, &self.state) {
            (Some(queue), DeviceState::Activated(memory, _)) => {
                // Queue validation reads ring indices. Exclude PROT_NONE slots
                // even though they are present in the ordinary guest map.
                let accessible = unsafe { self.accessible_memory(memory)? };
                Some(queue.queue.save_state(&accessible, true)?)
            }
            (None, DeviceState::Inactive) => None,
            _ => return Err(invalid("virtio-mem activation disagrees with queue")),
        };
        let state = MemState {
            device: VirtioDeviceState::save(self)?,
            queue,
            initial_mib: self.control.initial_mib,
            status: self.control.status(),
            addr: self.region.addr,
            size: self.region.size,
            usable_size: self.config.usable_region_size,
            requested_size: self.config.requested_size,
            plugged: self.plugged.clone(),
            mapped: self.region.mapped_slots().to_vec(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn save_memory(&self, writer: &mut impl Write) -> io::Result<()> {
        if !self.frozen || self.restore_failed {
            return Err(invalid("virtio-mem memory copy requires freeze"));
        }
        self.region.save_contents(writer)
    }

    /// The ordinary RAM codec must copy this view, followed by save_memory().
    /// Returning an owning view of boot RAM cannot expose raw reservation aliases.
    pub fn boot_memory(&self, memory: &GuestMemoryMmap) -> io::Result<GuestMemoryMmap> {
        if !self.frozen || self.restore_failed {
            return Err(invalid("virtio-mem RAM view requires freeze"));
        }
        let (boot, removed) = memory
            .remove_region(GuestAddress(self.region.addr), self.region.size)
            .map_err(io::Error::other)?;
        if !Arc::ptr_eq(&removed, &self.region.memory) {
            return Err(invalid("virtio-mem reservation differs from guest map"));
        }
        Ok(boot)
    }

    /// Restore into a fresh frozen device. Failure leaves it frozen and the VM
    /// must be discarded; partial RAM/slot restoration must never be resumed.
    /// Restore queues and activate the transport only after RAM is restored.
    pub fn restore_state(&mut self, state: &MemState, reader: &mut impl Read) -> io::Result<()> {
        state.validate()?;
        state.device.validate(self)?;
        if !self.frozen
            || self.restore_failed
            || self.is_activated()
            || self.region.mapped_size() != 0
            || state.initial_mib != self.control.initial_mib
            || state.addr != self.region.addr
            || state.size != self.region.size
            || state.status.max_mib != self.control.status().max_mib
        {
            return Err(invalid(
                "virtio-mem restore requires matching fresh reservation",
            ));
        }
        self.restore_failed = true;
        for (slot, &mapped) in state.mapped.iter().enumerate() {
            if mapped {
                self.region.update_slot(slot, true)?;
            }
        }
        self.region.restore_contents(reader)?;
        self.config = Config {
            block_size: BLOCK_SIZE,
            addr: state.addr,
            region_size: state.size,
            usable_region_size: state.usable_size,
            plugged_size: state.plugged.iter().filter(|&&v| v).count() as u64 * BLOCK_SIZE,
            requested_size: state.requested_size,
            ..Default::default()
        };
        self.plugged.clone_from(&state.plugged);
        self.acked_features = state.device.acked_features;
        self.control.restore(MemoryStatus {
            active: 0,
            ..state.status
        });
        self.restore_pending_activation = state.device.activated;
        self.restore_failed = false;
        Ok(())
    }

    /// Rebind the active queue to the destination transport's fresh eventfd.
    /// Kept separate from RAM loading because ring validation needs all guest
    /// RAM, including every mapped hotplug slot, to have been populated first.
    pub fn activate_restored(
        &mut self,
        state: &MemState,
        memory: GuestMemoryMmap,
        interrupt: crate::virtio::InterruptTransport,
        event: Arc<utils::eventfd::EventFd>,
    ) -> io::Result<()> {
        state.validate()?;
        state.device.validate(self)?;
        if !self.frozen
            || self.restore_failed
            || self.is_activated()
            || state.addr != self.region.addr
            || state.size != self.region.size
            || state.plugged != self.plugged
            || state.mapped != self.region.mapped_slots()
        {
            return Err(invalid(
                "virtio-mem activation requires restored frozen state",
            ));
        }
        if let Some(queue) = &state.queue {
            let accessible = unsafe { self.accessible_memory(&memory)? };
            let mut queues = state
                .device
                .restore_queues(std::slice::from_ref(queue), &accessible)?;
            self.restore_failed = true;
            self.activate(
                memory,
                interrupt,
                vec![crate::virtio::DeviceQueue::new(queues.remove(0), event)],
            )
            .map_err(|_| invalid("virtio-mem restored activation failed"))?;
            self.restore_failed = false;
        }
        self.restore_pending_activation = false;
        Ok(())
    }

    // The raw aliases are only used while self owns the reservation and the
    // device is frozen. Never return them to a caller that can outlive self.
    /// Temporary non-owning aliases for checkpoint ring validation.
    ///
    /// # Safety
    /// The returned map and all its clones must be dropped before this device
    /// resumes, changes mappings or is dropped. All RAM writers must be stopped.
    pub unsafe fn accessible_memory(
        &self,
        memory: &GuestMemoryMmap,
    ) -> io::Result<GuestMemoryMmap> {
        let mut accessible = self.boot_memory(memory)?;
        for (slot, &mapped) in self.region.mapped_slots().iter().enumerate() {
            if mapped {
                let offset = slot as u64 * SLOT_SIZE;
                // The slot was mprotected and registered successfully. The
                // reservation owns these pages; the temporary view does not.
                let mmap = unsafe {
                    vm_memory::mmap::MmapRegion::build_raw(
                        self.region.memory.as_ptr().add(offset as usize),
                        SLOT_SIZE as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    )
                }
                .map_err(io::Error::other)?;
                let region = GuestRegionMmap::new(mmap, GuestAddress(self.region.addr + offset))
                    .ok_or_else(|| invalid("virtio-mem address overflow"))?;
                accessible = accessible
                    .insert_region(Arc::new(region))
                    .map_err(io::Error::other)?;
            }
        }
        Ok(accessible)
    }
}
