//! Guest memory management for WHPX VMs.
//!
//! Handles allocation and mapping of guest physical memory.
//! On Windows, we use VirtualAlloc for host-side memory allocation
//! since the rust-vmm vm-memory crate doesn't support Windows.
//!
//! Memory layout constants are available on all platforms for cross-platform
//! testing of boot setup logic.

// Guest physical memory layout constants for x86_64 Linux boot.
// These match the conventional Linux boot protocol addresses.

/// Start of the zero page (boot_params structure).
pub const ZERO_PAGE_START: u64 = 0x7000;

/// Start of the PML4 page table.
pub const PML4_START: u64 = 0x9000;

/// Start of the PDPT page table.
pub const PDPT_START: u64 = 0xA000;

/// Start of the PD page tables (4 entries for identity-mapping 4GB).
pub const PD_START: u64 = 0xB000;

/// Kernel command line address.
pub const CMDLINE_START: u64 = 0x20000;

/// Maximum kernel command line length.
pub const CMDLINE_MAX_SIZE: u64 = 0x10000;

/// Kernel load address (1MB — standard bzImage load address).
pub const KERNEL_START: u64 = 0x100000;

/// Offset of the 64-bit entry point (`startup_64`) from KERNEL_START.
pub const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;

/// ACPI tables region.
pub const ACPI_START: u64 = 0xE0000;

/// Initial stack pointer (below 1MB, above page tables).
pub const BOOT_STACK_POINTER: u64 = 0x8FF0;

/// Virtio-MMIO base address (above guest RAM, below 4GB identity map).
pub const VIRTIO_MMIO_BASE: u64 = 0xD000_0000;

/// Size of the MMIO region reserved for virtio devices.
/// 2MB provides room for many devices and aligns with 2MB page table granularity.
pub const MMIO_REGION_SIZE: u64 = 0x20_0000;

/// IOAPIC MMIO base address.
pub const IOAPIC_MMIO_BASE: u64 = 0xFEC0_0000;

/// IOAPIC MMIO region size (4 KB).
pub const IOAPIC_MMIO_SIZE: u64 = 0x1000;

/// LAPIC MMIO base address.
pub const LAPIC_MMIO_BASE: u64 = 0xFEE0_0000;

/// LAPIC MMIO region size (4 KB).
pub const LAPIC_MMIO_SIZE: u64 = 0x1000;

// Windows-specific guest memory allocation and mapping.
#[cfg(target_os = "windows")]
mod imp {
    use std::ptr;

    use windows_sys::Win32::System::Hypervisor::WHV_MAP_GPA_RANGE_FLAGS;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };

    use super::super::error::{Result, WkrunError};
    use super::super::whpx::WhpxPartition;

    /// A contiguous region of guest physical memory.
    pub struct GuestMemoryRegion {
        /// Host virtual address of the allocated memory.
        host_addr: *mut u8,
        /// Guest physical address this region maps to.
        guest_addr: u64,
        /// Size of the region in bytes.
        size: u64,
    }

    // SAFETY: The memory region is a simple allocation that can be sent between threads.
    unsafe impl Send for GuestMemoryRegion {}
    unsafe impl Sync for GuestMemoryRegion {}

    impl GuestMemoryRegion {
        /// Allocate a new memory region using VirtualAlloc.
        pub fn new(guest_addr: u64, size: u64) -> Result<Self> {
            let host_addr = unsafe {
                VirtualAlloc(
                    ptr::null(),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };

            if host_addr.is_null() {
                return Err(WkrunError::Memory(format!(
                    "VirtualAlloc failed for {} bytes at GPA 0x{:X}",
                    size, guest_addr
                )));
            }

            Ok(GuestMemoryRegion {
                host_addr: host_addr as *mut u8,
                guest_addr,
                size,
            })
        }

        /// Get the host virtual address.
        pub fn host_addr(&self) -> *mut u8 {
            self.host_addr
        }

        /// Get the guest physical address.
        pub fn guest_addr(&self) -> u64 {
            self.guest_addr
        }

        /// Get the size of this region.
        pub fn size(&self) -> u64 {
            self.size
        }

        /// Write data into guest memory at a guest physical address offset.
        pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
            if offset + data.len() as u64 > self.size {
                return Err(WkrunError::Memory(format!(
                    "write out of bounds: offset 0x{:X} + {} > region size 0x{:X}",
                    offset,
                    data.len(),
                    self.size
                )));
            }

            // SAFETY: We verified the offset + len is within bounds.
            unsafe {
                let dst = self.host_addr.add(offset as usize);
                ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
            }
            Ok(())
        }

        /// Read data from guest memory at a guest physical address offset.
        pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            if offset + buf.len() as u64 > self.size {
                return Err(WkrunError::Memory(format!(
                    "read out of bounds: offset 0x{:X} + {} > region size 0x{:X}",
                    offset,
                    buf.len(),
                    self.size
                )));
            }

            // SAFETY: We verified the offset + len is within bounds.
            unsafe {
                let src = self.host_addr.add(offset as usize);
                ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
            }
            Ok(())
        }

        /// Write a value at a specific offset.
        pub fn write_obj<T: Copy>(&self, offset: u64, val: &T) -> Result<()> {
            let size = std::mem::size_of::<T>() as u64;
            if offset + size > self.size {
                return Err(WkrunError::Memory(format!(
                    "write_obj out of bounds: offset 0x{:X} + {} > region size 0x{:X}",
                    offset, size, self.size
                )));
            }

            // SAFETY: We verified bounds, and T is Copy (no drop needed).
            unsafe {
                let dst = self.host_addr.add(offset as usize) as *mut T;
                ptr::write_unaligned(dst, *val);
            }
            Ok(())
        }

        /// Map this region into a WHPX partition's guest physical address space.
        pub fn map_to_partition(&self, partition: &WhpxPartition) -> Result<()> {
            // SAFETY: host_addr points to our VirtualAlloc'd memory which is valid
            // for the lifetime of this GuestMemoryRegion.
            unsafe {
                partition.map_gpa_range(
                    self.host_addr,
                    self.guest_addr,
                    self.size,
                    // WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute
                    0x7 as WHV_MAP_GPA_RANGE_FLAGS,
                )
            }
        }
    }

    impl Drop for GuestMemoryRegion {
        fn drop(&mut self) {
            if !self.host_addr.is_null() {
                // SAFETY: We allocated this memory with VirtualAlloc.
                unsafe {
                    VirtualFree(self.host_addr as *mut std::ffi::c_void, 0, MEM_RELEASE);
                }
            }
        }
    }

    /// Guest memory manager — holds all guest memory regions.
    pub struct GuestMemory {
        regions: Vec<GuestMemoryRegion>,
        total_size: u64,
    }

    impl GuestMemory {
        /// Create guest memory, leaving holes for device MMIO regions.
        ///
        /// When guest RAM overlaps device MMIO addresses, the memory is split
        /// into multiple regions with unmapped gaps so that WHPX generates MMIO
        /// exits (instead of treating device accesses as RAM reads).
        ///
        /// Holes are created for:
        /// - Virtio MMIO (0xD000_0000 .. 0xD020_0000) — virtio device registers
        /// - APIC MMIO (0xFEC0_0000 .. 0xFEE0_1000) — IOAPIC + LAPIC registers
        pub fn new(size_mib: u32) -> Result<Self> {
            let size = (size_mib as u64) * 1024 * 1024;

            if size > super::VIRTIO_MMIO_BASE {
                let mmio_base = super::VIRTIO_MMIO_BASE;
                let mmio_end = mmio_base + super::MMIO_REGION_SIZE;
                let region1 = GuestMemoryRegion::new(0, mmio_base)?;

                // Check if RAM extends into the APIC MMIO region.
                // IOAPIC at 0xFEC0_0000 and LAPIC at 0xFEE0_0000 must be
                // unmapped so WHPX generates MMIO exits for APIC accesses.
                let apic_start = super::IOAPIC_MMIO_BASE;
                let apic_end = super::LAPIC_MMIO_BASE + super::LAPIC_MMIO_SIZE;

                if size > apic_start {
                    // RAM extends past APIC region — 3 regions with 2 holes.
                    // Region 1: 0 .. VIRTIO_MMIO_BASE
                    // (hole):   VIRTIO MMIO
                    // Region 2: VIRTIO_MMIO_END .. IOAPIC_MMIO_BASE
                    // (hole):   APIC MMIO (IOAPIC + LAPIC)
                    // Region 3: APIC_END .. ram_end
                    let region2 = GuestMemoryRegion::new(mmio_end, apic_start - mmio_end)?;
                    let mut regions = vec![region1, region2];

                    if size > apic_end {
                        let region3 = GuestMemoryRegion::new(apic_end, size - apic_end)?;
                        regions.push(region3);
                    }

                    Ok(GuestMemory {
                        regions,
                        total_size: size,
                    })
                } else {
                    // RAM between VIRTIO and APIC — 2 regions with 1 hole.
                    let region2 = GuestMemoryRegion::new(mmio_end, size - mmio_end)?;
                    Ok(GuestMemory {
                        regions: vec![region1, region2],
                        total_size: size,
                    })
                }
            } else {
                // RAM fits below MMIO — single contiguous region.
                let region = GuestMemoryRegion::new(0, size)?;
                Ok(GuestMemory {
                    regions: vec![region],
                    total_size: size,
                })
            }
        }

        /// Map all guest memory regions into a WHPX partition.
        pub fn map_to_partition(&self, partition: &WhpxPartition) -> Result<()> {
            for region in &self.regions {
                region.map_to_partition(partition)?;
            }
            Ok(())
        }

        /// Write data at a guest physical address.
        pub fn write_at_addr(&self, guest_addr: u64, data: &[u8]) -> Result<()> {
            for region in &self.regions {
                let region_end = region.guest_addr() + region.size();
                if guest_addr >= region.guest_addr() && guest_addr < region_end {
                    let offset = guest_addr - region.guest_addr();
                    return region.write_at(offset, data);
                }
            }
            Err(WkrunError::Memory(format!(
                "no region contains GPA 0x{:X}",
                guest_addr
            )))
        }

        /// Read data from a guest physical address.
        pub fn read_at_addr(&self, guest_addr: u64, buf: &mut [u8]) -> Result<()> {
            for region in &self.regions {
                let region_end = region.guest_addr() + region.size();
                if guest_addr >= region.guest_addr() && guest_addr < region_end {
                    let offset = guest_addr - region.guest_addr();
                    return region.read_at(offset, buf);
                }
            }
            Err(WkrunError::Memory(format!(
                "no region contains GPA 0x{:X}",
                guest_addr
            )))
        }

        /// Write a typed value at a guest physical address.
        pub fn write_obj_at_addr<T: Copy>(&self, guest_addr: u64, val: &T) -> Result<()> {
            for region in &self.regions {
                let region_end = region.guest_addr() + region.size();
                if guest_addr >= region.guest_addr() && guest_addr < region_end {
                    let offset = guest_addr - region.guest_addr();
                    return region.write_obj(offset, val);
                }
            }
            Err(WkrunError::Memory(format!(
                "no region contains GPA 0x{:X}",
                guest_addr
            )))
        }

        /// Get total guest memory size in bytes.
        pub fn total_size(&self) -> u64 {
            self.total_size
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time assertions for memory layout ordering.
    const _: () = {
        assert!(ZERO_PAGE_START < PML4_START);
        assert!(PML4_START < PDPT_START);
        assert!(PDPT_START < PD_START);
        assert!(PD_START < CMDLINE_START);
        assert!(CMDLINE_START < KERNEL_START);
        assert!(ZERO_PAGE_START < BOOT_STACK_POINTER);
        assert!(BOOT_STACK_POINTER < PML4_START);
    };

    #[test]
    fn test_kernel_start_at_1mb() {
        assert_eq!(KERNEL_START, 0x100000);
    }

    #[test]
    fn test_memory_layout_no_overlap() {
        let regions = [
            ("zero_page", ZERO_PAGE_START, ZERO_PAGE_START + 0x1000),
            ("pml4", PML4_START, PML4_START + 0x1000),
            ("pdpt", PDPT_START, PDPT_START + 0x1000),
            ("pd", PD_START, PD_START + 0x4000),
            ("cmdline", CMDLINE_START, CMDLINE_START + CMDLINE_MAX_SIZE),
            ("kernel", KERNEL_START, KERNEL_START + 0x1000),
        ];

        for i in 0..regions.len() {
            for j in (i + 1)..regions.len() {
                let (name_a, start_a, end_a) = regions[i];
                let (name_b, start_b, end_b) = regions[j];
                assert!(
                    end_a <= start_b || end_b <= start_a,
                    "regions {} and {} overlap: [{:#X}..{:#X}) vs [{:#X}..{:#X})",
                    name_a,
                    name_b,
                    start_a,
                    end_a,
                    start_b,
                    end_b
                );
            }
        }
    }
}
