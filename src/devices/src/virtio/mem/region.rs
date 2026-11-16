use std::io::{self, Read, Write};
use std::sync::Arc;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VmFd;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{Bytes, GuestAddress, GuestRegionMmap, MemoryRegionAddress};

use super::control::SLOT_SIZE;

/// Owns the reservation for the lifetime of every KVM slot. Unplugged slots
/// start PROT_NONE and are never registered with KVM until a plug request.
pub struct HotplugRegion {
    pub memory: Arc<GuestRegionMmap>,
    pub addr: u64,
    pub size: u64,
    vm: Arc<VmFd>,
    first_slot: u32,
    mapped: Vec<bool>,
}

impl HotplugRegion {
    pub fn new(vm: Arc<VmFd>, first_slot: u32, addr: u64, size: u64) -> io::Result<Self> {
        if size == 0
            || !size.is_multiple_of(SLOT_SIZE)
            || !addr.is_multiple_of(SLOT_SIZE)
            || addr.checked_add(size).is_none()
            || usize::try_from(size).is_err()
            || u32::try_from(size / SLOT_SIZE)
                .ok()
                .and_then(|count| first_slot.checked_add(count))
                .is_none()
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mmap = MmapRegionBuilder::new(size as usize)
            .with_mmap_prot(libc::PROT_NONE)
            .with_mmap_flags(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)
            .build()
            .map_err(io::Error::other)?;
        let memory = Arc::new(
            GuestRegionMmap::new(mmap, GuestAddress(addr))
                .ok_or_else(|| io::Error::other("hotplug region address overflow"))?,
        );
        Ok(Self {
            memory,
            addr,
            size,
            vm,
            first_slot,
            mapped: vec![false; (size / SLOT_SIZE) as usize],
        })
    }

    pub fn mapped_size(&self) -> u64 {
        self.mapped.iter().filter(|&&v| v).count() as u64 * SLOT_SIZE
    }

    pub(crate) fn mapped_slots(&self) -> &[bool] {
        &self.mapped
    }

    /// Only mapped slots are readable, even though the reservation's original
    /// mmap protection remains PROT_NONE in vm-memory's metadata.
    pub(crate) fn save_contents(&self, writer: &mut impl Write) -> io::Result<()> {
        let mut buffer = [0; 64 * 1024];
        for (slot, mapped) in self.mapped.iter().enumerate() {
            if !mapped {
                continue;
            }
            let start = slot as u64 * SLOT_SIZE;
            for offset in (0..SLOT_SIZE).step_by(buffer.len()) {
                self.memory
                    .read_slice(&mut buffer, MemoryRegionAddress(start + offset))
                    .map_err(io::Error::other)?;
                writer.write_all(&buffer)?;
            }
        }
        Ok(())
    }

    pub(crate) fn restore_contents(&self, reader: &mut impl Read) -> io::Result<()> {
        let mut buffer = [0; 64 * 1024];
        for (slot, mapped) in self.mapped.iter().enumerate() {
            if !mapped {
                continue;
            }
            let start = slot as u64 * SLOT_SIZE;
            for offset in (0..SLOT_SIZE).step_by(buffer.len()) {
                reader.read_exact(&mut buffer)?;
                self.memory
                    .write_slice(&buffer, MemoryRegionAddress(start + offset))
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }

    pub fn update_slot(&mut self, slot: usize, plug: bool) -> io::Result<()> {
        if slot >= self.mapped.len() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if self.mapped[slot] == plug {
            return Ok(());
        }
        let offset = slot as u64 * SLOT_SIZE;
        // The checked slot index is derived from a validated device block range.
        let host = unsafe { self.memory.as_ptr().add(offset as usize) };
        if plug
            && unsafe {
                libc::mprotect(
                    host.cast(),
                    SLOT_SIZE as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let region = kvm_userspace_memory_region {
            slot: self.first_slot + slot as u32,
            guest_phys_addr: self.addr + offset,
            memory_size: if plug { SLOT_SIZE } else { 0 },
            userspace_addr: host as u64,
            flags: 0,
        };
        // The Arc keeps the mapping alive; each slot is reserved exclusively for us.
        if let Err(error) = unsafe { self.vm.set_user_memory_region(region) } {
            if plug {
                unsafe {
                    libc::mprotect(host.cast(), SLOT_SIZE as usize, libc::PROT_NONE);
                }
            }
            return Err(io::Error::from_raw_os_error(error.errno()));
        }
        self.mapped[slot] = plug;
        if !plug {
            // Remove KVM access before discarding or protecting the host mapping.
            if unsafe { libc::mprotect(host.cast(), SLOT_SIZE as usize, libc::PROT_NONE) } != 0 {
                // KVM has already removed access. Commit that state even if
                // host protection failed, so a retry cannot lose slot accounting.
                error!(
                    "virtio-mem host protection failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
        Ok(())
    }

    pub fn discard(&self, offset: u64, len: u64) {
        let host = unsafe { self.memory.as_ptr().add(offset as usize) };
        if unsafe { libc::madvise(host.cast(), len as usize, libc::MADV_DONTNEED) } != 0 {
            warn!("virtio-mem discard failed: {}", io::Error::last_os_error());
        }
    }
}
