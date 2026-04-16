//! Linux bzImage kernel loader.
//!
//! Parses a bzImage file, loads the protected-mode kernel into guest memory,
//! sets up page tables, GDT, boot parameters, and kernel command line.

use super::params::HDRS_MAGIC;
use super::super::error::{Result, WkrunError};

#[cfg(any(target_os = "windows", test))]
use super::params::{E820Entry, E820_RAM, E820_RESERVED};

// These imports are only used by the Windows-only load_kernel() function.
#[cfg(target_os = "windows")]
use super::params::BootParams;
#[cfg(target_os = "windows")]
use super::setup::{build_gdt, build_page_tables, configure_boot_registers, gdt_bytes};
#[cfg(target_os = "windows")]
use super::super::memory::{
    CMDLINE_MAX_SIZE, CMDLINE_START, KERNEL_64BIT_ENTRY_OFFSET, KERNEL_START, PDPT_START, PD_START,
    PML4_START, ZERO_PAGE_START,
};
#[cfg(target_os = "windows")]
use super::super::types::{SpecialRegisters, StandardRegisters};

/// Loadflags bit: kernel was loaded high (at 0x100000).
#[cfg(any(target_os = "windows", test))]
const LOADED_HIGH: u8 = 0x01;

/// Loadflags bit: can use heap (setup heap).
#[cfg(target_os = "windows")]
const CAN_USE_HEAP: u8 = 0x80;

/// Parsed bzImage header information.
#[derive(Debug)]
pub struct KernelHeader {
    /// Boot protocol version (e.g., 0x020F for 2.15).
    pub protocol_version: u16,
    /// Number of setup sectors (real-mode kernel).
    pub setup_sects: u8,
    /// Byte offset of the protected-mode kernel within the bzImage.
    pub kernel_offset: usize,
    /// Size of the protected-mode kernel in bytes.
    pub kernel_size: usize,
    /// Load flags from the setup header.
    pub loadflags: u8,
}

/// Parse a bzImage and extract header information.
///
/// Validates the setup header magic ("HdrS") and protocol version,
/// then computes the offset and size of the protected-mode kernel.
pub fn parse_bzimage(kernel_image: &[u8]) -> Result<KernelHeader> {
    // Minimum size: at least the setup header through version field (0x208).
    if kernel_image.len() < 0x208 {
        return Err(WkrunError::Boot(format!(
            "kernel image too small: {} bytes (need at least {})",
            kernel_image.len(),
            0x208
        )));
    }

    // Check "HdrS" magic at offset 0x202.
    let header_magic = u32::from_le_bytes(
        kernel_image[0x202..0x206]
            .try_into()
            .map_err(|_| WkrunError::Boot("failed to read header magic".into()))?,
    );
    if header_magic != HDRS_MAGIC {
        return Err(WkrunError::Boot(format!(
            "invalid bzImage header magic: expected 0x{:08X} (HdrS), got 0x{:08X}",
            HDRS_MAGIC, header_magic
        )));
    }

    // Read boot protocol version at offset 0x206.
    let protocol_version = u16::from_le_bytes(
        kernel_image[0x206..0x208]
            .try_into()
            .map_err(|_| WkrunError::Boot("failed to read protocol version".into()))?,
    );

    // We require protocol version >= 2.06 for 64-bit boot.
    if protocol_version < 0x0206 {
        return Err(WkrunError::Boot(format!(
            "boot protocol version 0x{:04X} too old (need >= 0x0206)",
            protocol_version
        )));
    }

    // Read setup_sects at offset 0x1F1. If 0, default to 4.
    let mut setup_sects = kernel_image[0x1F1];
    if setup_sects == 0 {
        setup_sects = 4;
    }

    // Read loadflags at offset 0x211.
    let loadflags = kernel_image[0x211];

    // Protected-mode kernel starts after (setup_sects + 1) * 512 bytes.
    // The "+1" accounts for the boot sector (first 512 bytes).
    let kernel_offset = (setup_sects as usize + 1) * 512;
    if kernel_offset >= kernel_image.len() {
        return Err(WkrunError::Boot(format!(
            "setup_sects {} puts kernel offset {} beyond image size {}",
            setup_sects,
            kernel_offset,
            kernel_image.len()
        )));
    }

    let kernel_size = kernel_image.len() - kernel_offset;

    Ok(KernelHeader {
        protocol_version,
        setup_sects,
        kernel_offset,
        kernel_size,
        loadflags,
    })
}

/// Build the E820 memory map for the guest.
///
/// Creates a standard memory map with:
/// - Low memory (0 .. 0x9FC00) — 640KB conventional
/// - Reserved (0x9FC00 .. 0x100000) — BIOS area
/// - High memory (0x100000 .. ram_end) — main RAM
#[cfg(any(target_os = "windows", test))]
fn build_e820_map(ram_mib: u32) -> Vec<E820Entry> {
    let ram_bytes = (ram_mib as u64) * 1024 * 1024;

    let mut entries = Vec::new();

    // Low memory: 0 to 640KB (conventional memory).
    entries.push(E820Entry {
        addr: 0,
        size: 0x9FC00,
        entry_type: E820_RAM,
        _pad: 0,
    });

    // Reserved: 640KB to 1MB (BIOS, VGA, etc).
    entries.push(E820Entry {
        addr: 0x9FC00,
        size: 0x100000 - 0x9FC00,
        entry_type: E820_RESERVED,
        _pad: 0,
    });

    // High memory: 1MB to end of RAM.
    if ram_bytes > 0x100000 {
        entries.push(E820Entry {
            addr: 0x100000,
            size: ram_bytes - 0x100000,
            entry_type: E820_RAM,
            _pad: 0,
        });
    }

    entries
}

/// Load a Linux bzImage kernel into guest memory and configure for boot.
///
/// This performs the complete boot setup:
/// 1. Parse the bzImage header
/// 2. Copy the protected-mode kernel to KERNEL_START (0x100000)
/// 3. Write page tables (PML4, PDPT, PD) to guest memory
/// 4. Write GDT to guest memory
/// 5. Write boot parameters (zero page) with E820 map
/// 6. Write kernel command line
/// 7. Optionally load initrd into high guest memory
/// 8. Configure vCPU registers for 64-bit long mode entry
///
/// Returns the initial vCPU register state.
#[cfg(target_os = "windows")]
pub fn load_kernel(
    guest_mem: &super::super::memory::GuestMemory,
    kernel_image: &[u8],
    cmdline: &str,
    ram_mib: u32,
) -> Result<(StandardRegisters, SpecialRegisters)> {
    load_kernel_with_initrd(guest_mem, kernel_image, cmdline, ram_mib, None)
}

/// Load a Linux bzImage kernel with an optional initrd.
#[cfg(target_os = "windows")]
pub fn load_kernel_with_initrd(
    guest_mem: &super::super::memory::GuestMemory,
    kernel_image: &[u8],
    cmdline: &str,
    ram_mib: u32,
    initrd: Option<&[u8]>,
) -> Result<(StandardRegisters, SpecialRegisters)> {
    let header = parse_bzimage(kernel_image)?;

    // Validate kernel fits in guest memory.
    let kernel_end = KERNEL_START + header.kernel_size as u64;
    let ram_bytes = (ram_mib as u64) * 1024 * 1024;
    if kernel_end > ram_bytes {
        return Err(WkrunError::Boot(format!(
            "kernel ({} bytes) doesn't fit in {} MiB RAM (needs at least 0x{:X} bytes)",
            header.kernel_size, ram_mib, kernel_end
        )));
    }

    // Validate command line fits.
    let cmdline_bytes = cmdline.as_bytes();
    if cmdline_bytes.len() as u64 + 1 > CMDLINE_MAX_SIZE {
        return Err(WkrunError::Boot(format!(
            "kernel command line too long: {} bytes (max {})",
            cmdline_bytes.len(),
            CMDLINE_MAX_SIZE - 1
        )));
    }

    // 1. Copy protected-mode kernel to KERNEL_START.
    let kernel_data = &kernel_image[header.kernel_offset..];
    guest_mem.write_at_addr(KERNEL_START, kernel_data)?;

    // 2. Write page tables.
    let page_tables = build_page_tables();
    guest_mem.write_at_addr(PML4_START, page_tables.pml4_bytes())?;
    guest_mem.write_at_addr(PDPT_START, page_tables.pdpt_bytes())?;
    for i in 0..4 {
        guest_mem.write_at_addr(PD_START + i as u64 * 0x1000, page_tables.pd_bytes(i))?;
    }

    // 3. Write GDT.
    let gdt = build_gdt();
    let gdt_data = gdt_bytes(&gdt);
    // GDT_ADDR is 0x500, defined in setup.rs. Use the constant from memory layout.
    guest_mem.write_at_addr(0x500, &gdt_data)?;

    // 4. Build and write boot parameters (zero page).
    let mut boot_params = BootParams::new();
    boot_params.set_boot_flag();
    boot_params.set_header_magic();
    boot_params.set_version(header.protocol_version);
    boot_params.set_loader_type(0xFF); // Undefined bootloader
    boot_params.set_loadflags(LOADED_HIGH | CAN_USE_HEAP);

    // Copy relevant fields from the kernel's own setup header into boot_params.
    // The kernel reads some fields back from the zero page that it originally set.
    copy_setup_header(&mut boot_params, kernel_image, &header);

    // Set kernel command line.
    boot_params.set_cmdline_ptr(CMDLINE_START as u32);
    boot_params.set_cmdline_size(cmdline_bytes.len() as u32);

    // Set E820 memory map.
    let e820_map = build_e820_map(ram_mib);
    boot_params.set_e820_map(&e820_map);

    // Load initrd if provided. Place at the end of RAM (page-aligned).
    if let Some(initrd_data) = initrd {
        if !initrd_data.is_empty() {
            let initrd_size = initrd_data.len() as u64;
            // Align initrd to end of RAM, start at page boundary.
            let initrd_end = ram_bytes;
            let initrd_start = (initrd_end - initrd_size) & !0xFFF; // Page-align down

            if initrd_start < kernel_end {
                return Err(WkrunError::Boot(format!(
                    "initrd ({} bytes) overlaps with kernel at 0x{:X} (initrd at 0x{:X})",
                    initrd_size, kernel_end, initrd_start
                )));
            }

            guest_mem.write_at_addr(initrd_start, initrd_data)?;
            boot_params.set_ramdisk(initrd_start as u32, initrd_data.len() as u32);
        }
    }

    guest_mem.write_at_addr(ZERO_PAGE_START, &boot_params.data)?;

    // 5. Write kernel command line (null-terminated).
    let mut cmdline_buf = cmdline_bytes.to_vec();
    cmdline_buf.push(0); // null terminator
    guest_mem.write_at_addr(CMDLINE_START, &cmdline_buf)?;

    // 6. Configure vCPU registers for 64-bit long mode.
    // The 64-bit entry point (startup_64) is at KERNEL_START + 0x200.
    Ok(configure_boot_registers(
        KERNEL_START + KERNEL_64BIT_ENTRY_OFFSET,
    ))
}

/// Copy select fields from the kernel's setup header into boot_params.
///
/// The kernel expects certain fields in the zero page to match what it
/// originally placed in its own setup header. We copy the fields that
/// the kernel reads back during early boot.
#[cfg(target_os = "windows")]
fn copy_setup_header(boot_params: &mut BootParams, kernel_image: &[u8], header: &KernelHeader) {
    // setup_sects at offset 0x1F1.
    boot_params.data[0x1F1] = header.setup_sects;

    // Copy the setup header region (0x1F1..0x268) from the kernel image.
    // This includes fields like code32_start, kernel_alignment, init_size, etc.
    // that the kernel reads back during boot.
    let header_end = 0x268.min(kernel_image.len());
    if header_end > 0x1F1 {
        let src = &kernel_image[0x1F1..header_end];
        boot_params.data[0x1F1..header_end].copy_from_slice(src);
    }

    // Override the fields we explicitly set (they take precedence over what
    // was in the original kernel header).
    boot_params.set_boot_flag();
    boot_params.set_header_magic();
    boot_params.set_version(header.protocol_version);
    boot_params.set_loader_type(0xFF);
    boot_params.set_loadflags(LOADED_HIGH | CAN_USE_HEAP);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid bzImage header for testing.
    fn make_test_bzimage(setup_sects: u8, protocol_version: u16, kernel_payload: &[u8]) -> Vec<u8> {
        // Total real-mode size: (setup_sects + 1) * 512
        let real_mode_size = (setup_sects as usize + 1) * 512;
        let mut image = vec![0u8; real_mode_size + kernel_payload.len()];

        // setup_sects at 0x1F1
        image[0x1F1] = setup_sects;

        // "HdrS" magic at 0x202
        image[0x202..0x206].copy_from_slice(&HDRS_MAGIC.to_le_bytes());

        // Protocol version at 0x206
        image[0x206..0x208].copy_from_slice(&protocol_version.to_le_bytes());

        // Loadflags at 0x211 (LOADED_HIGH)
        image[0x211] = LOADED_HIGH;

        // Copy kernel payload after real-mode code
        image[real_mode_size..].copy_from_slice(kernel_payload);

        image
    }

    #[test]
    fn test_parse_bzimage_valid() {
        let kernel_payload = vec![0xCC; 1024]; // 1KB of int3
        let image = make_test_bzimage(4, 0x020F, &kernel_payload);

        let header = parse_bzimage(&image).expect("should parse valid bzImage");
        assert_eq!(header.protocol_version, 0x020F);
        assert_eq!(header.setup_sects, 4);
        assert_eq!(header.kernel_offset, (4 + 1) * 512);
        assert_eq!(header.kernel_size, 1024);
        assert_eq!(header.loadflags & LOADED_HIGH, LOADED_HIGH);
    }

    #[test]
    fn test_parse_bzimage_setup_sects_zero_defaults_to_4() {
        // setup_sects=0 defaults to 4, so kernel_offset = (4+1)*512 = 2560.
        // Build image large enough to accommodate this.
        let mut image = vec![0u8; (4 + 1) * 512 + 512]; // real-mode + kernel
        image[0x1F1] = 0; // setup_sects = 0
        image[0x202..0x206].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
        image[0x206..0x208].copy_from_slice(&0x0206u16.to_le_bytes());
        image[0x211] = LOADED_HIGH;

        let header = parse_bzimage(&image).expect("should parse with setup_sects=0");
        assert_eq!(header.setup_sects, 4); // defaulted from 0
        assert_eq!(header.kernel_offset, (4 + 1) * 512);
    }

    #[test]
    fn test_parse_bzimage_too_small() {
        let image = vec![0u8; 100]; // Way too small
        let err = parse_bzimage(&image).unwrap_err();
        assert!(
            err.to_string().contains("too small"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_bzimage_bad_magic() {
        let mut image = vec![0u8; 0x300];
        image[0x1F1] = 1;
        // Don't set "HdrS" magic
        let err = parse_bzimage(&image).unwrap_err();
        assert!(
            err.to_string().contains("header magic"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_bzimage_old_protocol() {
        let mut image = vec![0u8; 0x300];
        image[0x1F1] = 1;
        image[0x202..0x206].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
        image[0x206..0x208].copy_from_slice(&0x0200u16.to_le_bytes()); // too old
        let err = parse_bzimage(&image).unwrap_err();
        assert!(
            err.to_string().contains("too old"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_bzimage_kernel_offset_beyond_image() {
        let mut image = vec![0u8; 0x300]; // only ~768 bytes
        image[0x1F1] = 10; // setup_sects=10 → offset = 11*512 = 5632 > 768
        image[0x202..0x206].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
        image[0x206..0x208].copy_from_slice(&0x0206u16.to_le_bytes());
        let err = parse_bzimage(&image).unwrap_err();
        assert!(
            err.to_string().contains("beyond image size"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_e820_map_256mb() {
        let map = build_e820_map(256);
        assert_eq!(map.len(), 3);

        // Low memory: 0 .. 640KB
        assert_eq!(map[0].addr, 0);
        assert_eq!(map[0].size, 0x9FC00);
        assert_eq!(map[0].entry_type, E820_RAM);

        // Reserved: 640KB .. 1MB
        assert_eq!(map[1].addr, 0x9FC00);
        assert_eq!(map[1].entry_type, E820_RESERVED);

        // High memory: 1MB .. 256MB
        assert_eq!(map[2].addr, 0x100000);
        assert_eq!(map[2].size, 256 * 1024 * 1024 - 0x100000);
        assert_eq!(map[2].entry_type, E820_RAM);
    }

    #[test]
    fn test_build_e820_map_1mb_no_high_memory() {
        // With only 1MB of RAM, high memory region should be empty (1MB - 1MB = 0).
        let map = build_e820_map(1);
        assert_eq!(map.len(), 2, "1MB RAM should only have low + reserved");
    }
}
