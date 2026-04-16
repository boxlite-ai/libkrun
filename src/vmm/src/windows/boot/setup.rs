//! x86_64 boot setup — page tables, GDT, and vCPU register configuration
//! for the Windows WHPX backend.

use super::super::types::{DescriptorTable, SegmentRegister, SpecialRegisters, StandardRegisters};

// Page table constants
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_WRITE: u64 = 1 << 1;
const PAGE_SIZE_2MB: u64 = 1 << 7;

// Control register bits
const CR0_PE: u64 = 1 << 0;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;

const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_SCE: u64 = 1 << 0;

// GDT entry access byte and flags
const GDT_CODE_ACCESS: u16 = 0xA09B;
const GDT_DATA_ACCESS: u16 = 0xC093;
const GDT_TSS_ACCESS: u16 = 0x808B;

/// Memory addresses for page table structures.
const PML4_ADDR: u64 = 0x9000;
const PDPT_ADDR: u64 = 0xA000;
const PD_ADDR: u64 = 0xB000;
const GDT_ADDR: u64 = 0x500;
const BOOT_STACK: u64 = 0x8FF0;

/// GDT entry indices
const GDT_NULL: usize = 0;
const GDT_CODE: usize = 1;
const GDT_DATA: usize = 2;
const GDT_TSS: usize = 3;

/// Number of GDT entries (null + code + data + TSS = 4)
const GDT_ENTRY_COUNT: usize = 4;

/// Build identity-mapped page tables for 4GB.
pub fn build_page_tables() -> PageTables {
    let mut pml4 = [0u64; 512];
    let mut pdpt = [0u64; 512];
    let mut pd = [[0u64; 512]; 4];

    pml4[0] = PDPT_ADDR | PAGE_PRESENT | PAGE_WRITE;

    for (i, entry) in pdpt.iter_mut().enumerate().take(4) {
        *entry = (PD_ADDR + i as u64 * 0x1000) | PAGE_PRESENT | PAGE_WRITE;
    }

    for (i, pd_table) in pd.iter_mut().enumerate() {
        for (j, entry) in pd_table.iter_mut().enumerate() {
            let phys_addr = (i as u64 * 512 + j as u64) * (2 * 1024 * 1024);
            *entry = phys_addr | PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB;
        }
    }

    PageTables { pml4, pdpt, pd }
}

/// Page table data ready to be written to guest memory.
pub struct PageTables {
    pub pml4: [u64; 512],
    pub pdpt: [u64; 512],
    pub pd: [[u64; 512]; 4],
}

impl PageTables {
    pub fn pml4_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pml4.as_ptr() as *const u8, 512 * 8) }
    }

    pub fn pdpt_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pdpt.as_ptr() as *const u8, 512 * 8) }
    }

    pub fn pd_bytes(&self, index: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pd[index].as_ptr() as *const u8, 512 * 8) }
    }
}

/// Build the GDT entries.
pub fn build_gdt() -> Vec<u64> {
    let mut gdt = vec![0u64; GDT_ENTRY_COUNT + 1];

    gdt[GDT_NULL] = 0;
    gdt[GDT_CODE] = gdt_entry(0, 0xFFFFF, GDT_CODE_ACCESS);
    gdt[GDT_DATA] = gdt_entry(0, 0xFFFFF, GDT_DATA_ACCESS);
    gdt[GDT_TSS] = gdt_entry(0, 0xFFFF, GDT_TSS_ACCESS);
    gdt[GDT_TSS + 1] = 0;

    gdt
}

fn gdt_entry(base: u32, limit: u32, access_rights: u16) -> u64 {
    let access = (access_rights & 0xFF) as u64;
    let flags = ((access_rights >> 8) & 0xF0) as u64;
    let limit_low = (limit & 0xFFFF) as u64;
    let limit_high = ((limit >> 16) & 0xF) as u64;
    let base_low = (base & 0xFFFF) as u64;
    let base_mid = ((base >> 16) & 0xFF) as u64;
    let base_high = ((base >> 24) & 0xFF) as u64;

    limit_low
        | (base_low << 16)
        | (base_mid << 32)
        | (access << 40)
        | (limit_high << 48)
        | (flags << 48)
        | (base_high << 56)
}

/// GDT data as bytes.
pub fn gdt_bytes(gdt: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(gdt.len() * 8);
    for entry in gdt {
        bytes.extend_from_slice(&entry.to_le_bytes());
    }
    bytes
}

/// Configure the initial vCPU registers for 64-bit long mode boot.
pub fn configure_boot_registers(kernel_entry: u64) -> (StandardRegisters, SpecialRegisters) {
    let regs = StandardRegisters {
        rip: kernel_entry,
        rsp: BOOT_STACK,
        rsi: super::super::memory::ZERO_PAGE_START,
        rflags: 0x2,
        ..Default::default()
    };

    let gdt_size = (GDT_ENTRY_COUNT + 1) * 8;

    let sregs = SpecialRegisters {
        cs: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x08,
            access_rights: GDT_CODE_ACCESS,
        },
        ds: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            access_rights: GDT_DATA_ACCESS,
        },
        es: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            access_rights: GDT_DATA_ACCESS,
        },
        fs: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            access_rights: GDT_DATA_ACCESS,
        },
        gs: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            access_rights: GDT_DATA_ACCESS,
        },
        ss: SegmentRegister {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            access_rights: GDT_DATA_ACCESS,
        },
        tr: SegmentRegister {
            base: 0,
            limit: 0xFFFF,
            selector: 0x18,
            access_rights: GDT_TSS_ACCESS,
        },
        ldt: SegmentRegister::default(),
        gdt: DescriptorTable {
            base: GDT_ADDR,
            limit: (gdt_size - 1) as u16,
        },
        idt: DescriptorTable {
            base: 0,
            limit: 0xFFFF,
        },
        cr0: CR0_PE | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG,
        cr2: 0,
        cr3: PML4_ADDR,
        cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
        efer: EFER_LME | EFER_LMA | EFER_SCE,
    };

    (regs, sregs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_tables_pml4_points_to_pdpt() {
        let pt = build_page_tables();
        let entry = pt.pml4[0];
        assert_eq!(entry & !0xFFF, PDPT_ADDR);
        assert_ne!(entry & PAGE_PRESENT, 0);
        assert_ne!(entry & PAGE_WRITE, 0);
    }

    #[test]
    fn test_page_tables_pdpt_entries() {
        let pt = build_page_tables();
        for i in 0..4 {
            let entry = pt.pdpt[i];
            let expected_addr = PD_ADDR + i as u64 * 0x1000;
            assert_eq!(entry & !0xFFF, expected_addr);
            assert_ne!(entry & PAGE_PRESENT, 0);
        }
        for i in 4..512 {
            assert_eq!(pt.pdpt[i], 0, "PDPT[{}] should be empty", i);
        }
    }

    #[test]
    fn test_page_tables_identity_map() {
        let pt = build_page_tables();
        for i in 0..4 {
            for j in 0..512 {
                let entry = pt.pd[i][j];
                let expected_phys = (i as u64 * 512 + j as u64) * 2 * 1024 * 1024;
                assert_eq!(entry & !0xFFF, expected_phys);
                assert_ne!(entry & PAGE_PRESENT, 0);
                assert_ne!(entry & PAGE_SIZE_2MB, 0);
            }
        }
    }

    #[test]
    fn test_page_tables_cover_4gb() {
        let pt = build_page_tables();
        let last_entry = pt.pd[3][511];
        let last_addr = last_entry & !0xFFF;
        let expected = (4u64 * 1024 * 1024 * 1024) - (2 * 1024 * 1024);
        assert_eq!(last_addr, expected);
    }

    #[test]
    fn test_gdt_has_null_entry() {
        let gdt = build_gdt();
        assert_eq!(gdt[GDT_NULL], 0);
    }

    #[test]
    fn test_gdt_code_segment() {
        let gdt = build_gdt();
        assert_ne!(gdt[GDT_CODE], 0);
    }

    #[test]
    fn test_gdt_data_segment() {
        let gdt = build_gdt();
        assert_ne!(gdt[GDT_DATA], 0);
    }

    #[test]
    fn test_gdt_bytes_length() {
        let gdt = build_gdt();
        let bytes = gdt_bytes(&gdt);
        assert_eq!(bytes.len(), gdt.len() * 8);
    }

    #[test]
    fn test_boot_registers_long_mode() {
        let (regs, sregs) = configure_boot_registers(0x100000);

        assert_eq!(regs.rip, 0x100000);
        assert_eq!(regs.rsp, BOOT_STACK);
        assert_eq!(regs.rsi, super::super::memory::ZERO_PAGE_START);
        assert_ne!(regs.rflags & 0x2, 0);
        assert_ne!(sregs.cr0 & CR0_PE, 0);
        assert_ne!(sregs.cr0 & CR0_PG, 0);
        assert_eq!(sregs.cr3, PML4_ADDR);
        assert_ne!(sregs.cr4 & CR4_PAE, 0);
        assert_ne!(sregs.efer & EFER_LME, 0);
        assert_ne!(sregs.efer & EFER_LMA, 0);
    }

    #[test]
    fn test_boot_registers_segment_selectors() {
        let (_, sregs) = configure_boot_registers(0x100000);

        assert_eq!(sregs.cs.selector, 0x08);
        assert_eq!(sregs.ds.selector, 0x10);
        assert_eq!(sregs.es.selector, 0x10);
        assert_eq!(sregs.ss.selector, 0x10);
        assert_eq!(sregs.tr.selector, 0x18);
    }

    #[test]
    fn test_gdt_entry_encoding() {
        let entry = gdt_entry(0, 0xFFFFF, GDT_CODE_ACCESS);
        assert_ne!(entry, 0);

        let null = gdt_entry(0, 0, 0);
        assert_eq!(null, 0);
    }
}
