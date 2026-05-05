//! Linux boot_params (zero page) structure.
//!
//! Subset of the Linux boot protocol's boot_params structure
//! needed for direct bzImage boot.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// E820 memory map entry type constants.
pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const E820_ACPI: u32 = 3;

/// Linux boot protocol magic number.
pub const BOOT_MAGIC: u16 = 0xAA55;

/// Header magic "HdrS".
pub const HDRS_MAGIC: u32 = 0x5372_6448;

/// Minimum boot protocol version we support (2.06+).
pub const MIN_BOOT_PROTOCOL: u16 = 0x0206;

/// E820 memory map entry.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
    pub _pad: u32,
}

/// Minimal subset of Linux setup_header structure.
/// Located at offset 0x1F1 in the zero page.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SetupHeader {
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_swtch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
}

/// Boot parameters (zero page) — the key structure passed to the Linux kernel.
pub struct BootParams {
    /// The raw 4096-byte zero page buffer.
    pub data: [u8; 4096],
}

impl Default for BootParams {
    fn default() -> Self {
        BootParams { data: [0u8; 4096] }
    }
}

impl BootParams {
    /// Create a new BootParams with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the E820 memory map.
    pub fn set_e820_map(&mut self, entries: &[E820Entry]) {
        let count = entries.len().min(128) as u8;
        self.data[0x1E8] = count;

        let base_offset = 0x2D0;
        for (i, entry) in entries.iter().take(128).enumerate() {
            let offset = base_offset + i * 20;
            self.data[offset..offset + 8].copy_from_slice(&entry.addr.to_le_bytes());
            self.data[offset + 8..offset + 16].copy_from_slice(&entry.size.to_le_bytes());
            self.data[offset + 16..offset + 20].copy_from_slice(&entry.entry_type.to_le_bytes());
        }
    }

    /// Set the command line pointer.
    pub fn set_cmdline_ptr(&mut self, addr: u32) {
        self.data[0x228..0x22C].copy_from_slice(&addr.to_le_bytes());
    }

    /// Set the command line size.
    pub fn set_cmdline_size(&mut self, size: u32) {
        self.data[0x238..0x23C].copy_from_slice(&size.to_le_bytes());
    }

    /// Set the boot flag (must be 0xAA55).
    pub fn set_boot_flag(&mut self) {
        self.data[0x1FE..0x200].copy_from_slice(&BOOT_MAGIC.to_le_bytes());
    }

    /// Set the setup header magic ("HdrS").
    pub fn set_header_magic(&mut self) {
        self.data[0x202..0x206].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
    }

    /// Set the boot protocol version.
    pub fn set_version(&mut self, version: u16) {
        self.data[0x206..0x208].copy_from_slice(&version.to_le_bytes());
    }

    /// Set the type_of_loader field (0xFF = undefined bootloader).
    pub fn set_loader_type(&mut self, loader_type: u8) {
        self.data[0x210] = loader_type;
    }

    /// Set load flags.
    pub fn set_loadflags(&mut self, flags: u8) {
        self.data[0x211] = flags;
    }

    /// Set the ramdisk image address.
    pub fn set_ramdisk(&mut self, addr: u32, size: u32) {
        self.data[0x218..0x21C].copy_from_slice(&addr.to_le_bytes());
        self.data[0x21C..0x220].copy_from_slice(&size.to_le_bytes());
    }

    /// Set the ACPI RSDP physical address (boot protocol 2.14+, offset 0x070).
    ///
    /// When set, the kernel uses this address directly instead of scanning
    /// the BIOS ROM area (0xE0000-0xFFFFF) for the RSDP signature.
    /// For older kernels (protocol < 2.14), this field is padding and ignored.
    pub fn set_acpi_rsdp_addr(&mut self, addr: u64) {
        self.data[0x070..0x078].copy_from_slice(&addr.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_params_default_is_zeroed() {
        let params = BootParams::new();
        assert!(params.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_boot_params_set_boot_flag() {
        let mut params = BootParams::new();
        params.set_boot_flag();
        let flag = u16::from_le_bytes([params.data[0x1FE], params.data[0x1FF]]);
        assert_eq!(flag, BOOT_MAGIC);
    }

    #[test]
    fn test_boot_params_set_header_magic() {
        let mut params = BootParams::new();
        params.set_header_magic();
        let magic = u32::from_le_bytes([
            params.data[0x202],
            params.data[0x203],
            params.data[0x204],
            params.data[0x205],
        ]);
        assert_eq!(magic, HDRS_MAGIC);
    }

    #[test]
    fn test_boot_params_set_cmdline() {
        let mut params = BootParams::new();
        params.set_cmdline_ptr(0x20000);
        params.set_cmdline_size(256);

        let ptr = u32::from_le_bytes(params.data[0x228..0x22C].try_into().unwrap());
        let size = u32::from_le_bytes(params.data[0x238..0x23C].try_into().unwrap());
        assert_eq!(ptr, 0x20000);
        assert_eq!(size, 256);
    }

    #[test]
    fn test_boot_params_e820_map() {
        let mut params = BootParams::new();
        let entries = vec![
            E820Entry {
                addr: 0,
                size: 0x9FC00,
                entry_type: E820_RAM,
                _pad: 0,
            },
            E820Entry {
                addr: 0x100000,
                size: 255 * 1024 * 1024,
                entry_type: E820_RAM,
                _pad: 0,
            },
        ];

        params.set_e820_map(&entries);
        assert_eq!(params.data[0x1E8], 2);

        let addr = u64::from_le_bytes(params.data[0x2D0..0x2D8].try_into().unwrap());
        let size = u64::from_le_bytes(params.data[0x2D8..0x2E0].try_into().unwrap());
        let etype = u32::from_le_bytes(params.data[0x2E0..0x2E4].try_into().unwrap());
        assert_eq!(addr, 0);
        assert_eq!(size, 0x9FC00);
        assert_eq!(etype, E820_RAM);
    }

    #[test]
    fn test_e820_entry_size() {
        assert_eq!(std::mem::size_of::<E820Entry>(), 24);
    }

    #[test]
    fn test_boot_params_loader_type() {
        let mut params = BootParams::new();
        params.set_loader_type(0xFF);
        assert_eq!(params.data[0x210], 0xFF);
    }

    #[test]
    fn test_boot_params_ramdisk() {
        let mut params = BootParams::new();
        params.set_ramdisk(0x1000000, 0x500000);

        let addr = u32::from_le_bytes(params.data[0x218..0x21C].try_into().unwrap());
        let size = u32::from_le_bytes(params.data[0x21C..0x220].try_into().unwrap());
        assert_eq!(addr, 0x1000000);
        assert_eq!(size, 0x500000);
    }

    #[test]
    fn test_boot_params_acpi_rsdp_addr() {
        let mut params = BootParams::new();
        params.set_acpi_rsdp_addr(0xE0000);

        let addr = u64::from_le_bytes(params.data[0x070..0x078].try_into().unwrap());
        assert_eq!(addr, 0xE0000);
    }

    #[test]
    fn test_boot_params_acpi_rsdp_addr_default_zero() {
        let params = BootParams::new();
        let addr = u64::from_le_bytes(params.data[0x070..0x078].try_into().unwrap());
        assert_eq!(addr, 0, "acpi_rsdp_addr should be 0 by default");
    }
}
