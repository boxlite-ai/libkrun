//! Minimal ACPI table generation for WHPX guest boot.
//!
//! Generates RSDP, RSDT, FADT, DSDT, and MADT tables so the Linux kernel can:
//! - Discover the PM1a_CNT register for clean ACPI S5 shutdown
//! - Discover the IOAPIC and LAPIC for APIC-mode interrupt routing

/// Total size of the ACPI region in guest memory.
pub const ACPI_REGION_SIZE: u64 = 0x400; // 1024 bytes

// Table offsets within the ACPI region.
const RSDP_OFFSET: usize = 0x00;
const RSDT_OFFSET: usize = 0x20;
const FADT_OFFSET: usize = 0x60;
const DSDT_OFFSET: usize = 0x100;
const MADT_OFFSET: usize = 0x140;

// Table sizes.
const RSDP_SIZE: usize = 20;
const RSDT_HEADER_SIZE: usize = 36;
const RSDT_ENTRIES: usize = 2; // FADT + MADT
const RSDT_SIZE: usize = RSDT_HEADER_SIZE + RSDT_ENTRIES * 4; // 36 + 8 = 44
const FADT_SIZE: usize = 116;
const DSDT_HEADER_SIZE: usize = 36;

/// MADT structure sizes.
const MADT_HEADER_SIZE: usize = 44; // 36-byte ACPI header + 4-byte Local APIC Address + 4-byte Flags
const MADT_LAPIC_ENTRY_SIZE: usize = 8; // Type 0: Processor Local APIC
const MADT_IOAPIC_ENTRY_SIZE: usize = 12; // Type 1: I/O APIC
const MADT_ISO_ENTRY_SIZE: usize = 10; // Type 2: Interrupt Source Override

/// Compute the MADT size for a given number of vCPUs.
const fn madt_size(num_vcpus: u8) -> usize {
    MADT_HEADER_SIZE
        + MADT_LAPIC_ENTRY_SIZE * (num_vcpus as usize)
        + MADT_IOAPIC_ENTRY_SIZE
        + MADT_ISO_ENTRY_SIZE
}

/// MADT size for the default single-vCPU case (used for static offset validation).
const MADT_SIZE_1: usize = madt_size(1);

// ACPI PM1a I/O port addresses (must match manager.rs constants).
const PM1A_EVT_BLK: u32 = 0x600;
const PM1A_CNT_BLK: u32 = 0x604;

/// SCI interrupt number for ACPI.
///
/// Must not conflict with timer (IRQ 0), serial (IRQ 4), or
/// virtio-MMIO devices (IRQ 5-9). IRQ 11 is unused.
const SCI_INT: u16 = 11;

/// IOAPIC base address (must match memory.rs).
const IOAPIC_BASE: u32 = 0xFEC0_0000;

/// LAPIC base address (must match memory.rs).
const LAPIC_BASE: u32 = 0xFEE0_0000;

/// AML bytecode for the `\_S5_` sleep package.
///
/// Encodes: `Name(\_S5_, Package(4) { 5, 5, 0, 0 })`
/// - `08` = NameOp
/// - `5C 5F 53 35 5F` = `\_S5_`
/// - `12 0A 04` = Package, 10 bytes, 4 elements
/// - `0A 05` = ByteConst 5 (SLP_TYPa)
/// - `0A 05` = ByteConst 5 (SLP_TYPb)
/// - `00` = zero
/// - `00` = zero
const S5_AML: &[u8] = &[
    0x08, 0x5C, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x0A, 0x04, 0x0A, 0x05, 0x0A, 0x05, 0x00, 0x00,
];

/// Build ACPI tables (RSDP, RSDT, FADT, DSDT, MADT) for the given base address.
///
/// Returns a `Vec<u8>` of exactly `ACPI_REGION_SIZE` bytes. The caller
/// writes this to guest memory at `acpi_base`.
///
/// `num_vcpus` determines how many LAPIC entries are generated in the MADT.
pub fn build_acpi_tables(acpi_base: u64, num_vcpus: u8) -> Vec<u8> {
    let mut region = vec![0u8; ACPI_REGION_SIZE as usize];

    let rsdt_addr = acpi_base + RSDT_OFFSET as u64;
    let fadt_addr = acpi_base + FADT_OFFSET as u64;
    let dsdt_addr = acpi_base + DSDT_OFFSET as u64;
    let madt_addr = acpi_base + MADT_OFFSET as u64;

    // ---- RSDP (20 bytes at offset 0x00) ----
    let rsdp = &mut region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];
    rsdp[0..8].copy_from_slice(b"RSD PTR "); // Signature
                                             // rsdp[8] = checksum (computed below)
    rsdp[9..15].copy_from_slice(b"BOXLTE"); // OEMID
    rsdp[15] = 0; // Revision: ACPI 1.0
    rsdp[16..20].copy_from_slice(&(rsdt_addr as u32).to_le_bytes()); // RsdtAddress
    acpi_checksum(&mut region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE], 8);

    // ---- RSDT (44 bytes at offset 0x20) ----
    let rsdt = &mut region[RSDT_OFFSET..RSDT_OFFSET + RSDT_SIZE];
    rsdt[0..4].copy_from_slice(b"RSDT"); // Signature
    rsdt[4..8].copy_from_slice(&(RSDT_SIZE as u32).to_le_bytes()); // Length
    rsdt[8] = 1; // Revision
                 // rsdt[9] = checksum (computed below)
    rsdt[10..16].copy_from_slice(b"BOXLTE"); // OEMID
    rsdt[16..24].copy_from_slice(b"BOXLITEV"); // OEM Table ID
    rsdt[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
    rsdt[28..32].copy_from_slice(b"BXLT"); // Creator ID
    rsdt[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision
                                                       // Entry[0]: pointer to FADT
    rsdt[36..40].copy_from_slice(&(fadt_addr as u32).to_le_bytes());
    // Entry[1]: pointer to MADT
    rsdt[40..44].copy_from_slice(&(madt_addr as u32).to_le_bytes());
    acpi_checksum(&mut region[RSDT_OFFSET..RSDT_OFFSET + RSDT_SIZE], 9);

    // ---- FADT (116 bytes at offset 0x60) ----
    let fadt = &mut region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];
    fadt[0..4].copy_from_slice(b"FACP"); // Signature (NOT "FADT")
    fadt[4..8].copy_from_slice(&(FADT_SIZE as u32).to_le_bytes()); // Length
    fadt[8] = 1; // Revision
                 // fadt[9] = checksum (computed below)
    fadt[10..16].copy_from_slice(b"BOXLTE"); // OEMID
    fadt[16..24].copy_from_slice(b"BOXLITEV"); // OEM Table ID
    fadt[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
    fadt[28..32].copy_from_slice(b"BXLT"); // Creator ID
    fadt[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision
                                                       // FACS pointer (offset 36) — 0, not needed for shutdown.
                                                       // DSDT pointer (offset 40).
    fadt[40..44].copy_from_slice(&(dsdt_addr as u32).to_le_bytes());
    // SCI_INT (offset 46) — interrupt for ACPI System Control.
    fadt[46..48].copy_from_slice(&SCI_INT.to_le_bytes());
    // PM1a_EVT_BLK (offset 56).
    fadt[56..60].copy_from_slice(&PM1A_EVT_BLK.to_le_bytes());
    // PM1a_CNT_BLK (offset 64).
    fadt[64..68].copy_from_slice(&PM1A_CNT_BLK.to_le_bytes());
    // PM1_EVT_LEN (offset 88).
    fadt[88] = 4;
    // PM1_CNT_LEN (offset 89).
    fadt[89] = 2;
    acpi_checksum(&mut region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE], 9);

    // ---- DSDT (header + AML at offset 0x100) ----
    let dsdt_size = DSDT_HEADER_SIZE + S5_AML.len();
    let dsdt = &mut region[DSDT_OFFSET..DSDT_OFFSET + dsdt_size];
    dsdt[0..4].copy_from_slice(b"DSDT"); // Signature
    dsdt[4..8].copy_from_slice(&(dsdt_size as u32).to_le_bytes()); // Length
    dsdt[8] = 1; // Revision
                 // dsdt[9] = checksum (computed below)
    dsdt[10..16].copy_from_slice(b"BOXLTE"); // OEMID
    dsdt[16..24].copy_from_slice(b"BOXLITEV"); // OEM Table ID
    dsdt[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
    dsdt[28..32].copy_from_slice(b"BXLT"); // Creator ID
    dsdt[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision
                                                       // AML body: \_S5_ package.
    dsdt[DSDT_HEADER_SIZE..DSDT_HEADER_SIZE + S5_AML.len()].copy_from_slice(S5_AML);
    acpi_checksum(&mut region[DSDT_OFFSET..DSDT_OFFSET + dsdt_size], 9);

    // ---- MADT (Multiple APIC Description Table) at offset 0x140 ----
    let madt_sz = madt_size(num_vcpus);
    assert!(
        MADT_OFFSET + madt_sz <= ACPI_REGION_SIZE as usize,
        "MADT ({} bytes for {} vCPUs) exceeds ACPI region",
        madt_sz,
        num_vcpus,
    );
    build_madt(&mut region[MADT_OFFSET..MADT_OFFSET + madt_sz], num_vcpus);

    region
}

/// Build the MADT (Multiple APIC Description Table).
///
/// Tells the Linux kernel about the Local APIC(s) and I/O APIC.
///
/// Structure:
/// - Header (44 bytes): standard ACPI header + LAPIC address + flags
/// - N x Local APIC entries (type 0, 8 bytes each): one per vCPU
/// - I/O APIC entry (type 1, 12 bytes): IOAPIC ID 0, base 0xFEC00000
/// - Interrupt Source Override (type 2, 10 bytes): IRQ 0 → GSI 2
fn build_madt(madt: &mut [u8], num_vcpus: u8) {
    let total_size = madt.len();

    // ACPI header.
    madt[0..4].copy_from_slice(b"APIC"); // Signature
    madt[4..8].copy_from_slice(&(total_size as u32).to_le_bytes()); // Length
    madt[8] = 1; // Revision
                 // madt[9] = checksum (computed below)
    madt[10..16].copy_from_slice(b"BOXLTE"); // OEMID
    madt[16..24].copy_from_slice(b"BOXLITEV"); // OEM Table ID
    madt[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
    madt[28..32].copy_from_slice(b"BXLT"); // Creator ID
    madt[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision

    // Local APIC Address (offset 36, 4 bytes).
    madt[36..40].copy_from_slice(&LAPIC_BASE.to_le_bytes());

    // Flags (offset 40, 4 bytes): PCAT_COMPAT = 1 (dual 8259 PICs present).
    madt[40..44].copy_from_slice(&1u32.to_le_bytes());

    // --- N x Processor Local APIC entries (type 0, 8 bytes each) ---
    let mut off = MADT_HEADER_SIZE;
    for i in 0..num_vcpus {
        madt[off] = 0; // Entry type: Processor Local APIC
        madt[off + 1] = MADT_LAPIC_ENTRY_SIZE as u8; // Length
        madt[off + 2] = i; // ACPI Processor ID
        madt[off + 3] = i; // APIC ID
        madt[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes()); // Flags: enabled
        off += MADT_LAPIC_ENTRY_SIZE;
    }

    // --- I/O APIC entry (type 1, 12 bytes) ---
    madt[off] = 1; // Entry type: I/O APIC
    madt[off + 1] = MADT_IOAPIC_ENTRY_SIZE as u8; // Length
    madt[off + 2] = 0; // I/O APIC ID
    madt[off + 3] = 0; // Reserved
    madt[off + 4..off + 8].copy_from_slice(&IOAPIC_BASE.to_le_bytes()); // I/O APIC Address
    madt[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes()); // Global System Interrupt Base
    off += MADT_IOAPIC_ENTRY_SIZE;

    // --- Interrupt Source Override (type 2, 10 bytes) ---
    // Standard x86 convention: PIT timer (IRQ 0) routes to IOAPIC pin 2.
    madt[off] = 2; // Entry type: Interrupt Source Override
    madt[off + 1] = MADT_ISO_ENTRY_SIZE as u8; // Length
    madt[off + 2] = 0; // Bus: ISA
    madt[off + 3] = 0; // Source: IRQ 0 (PIT timer)
    madt[off + 4..off + 8].copy_from_slice(&2u32.to_le_bytes()); // Global System Interrupt: 2
    madt[off + 8..off + 10].copy_from_slice(&0u16.to_le_bytes()); // Flags: conforming

    acpi_checksum(madt, 9);
}

/// Compute ACPI checksum and store it at `checksum_offset`.
///
/// The checksum byte is set so that the sum of all bytes in the table
/// equals zero (mod 256).
fn acpi_checksum(table: &mut [u8], checksum_offset: usize) {
    table[checksum_offset] = 0;
    let sum: u8 = table.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    table[checksum_offset] = 0u8.wrapping_sub(sum);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BASE: u64 = 0xE0000;

    #[test]
    fn test_rsdp_signature_and_checksum() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let rsdp = &region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];

        assert_eq!(&rsdp[0..8], b"RSD PTR ");

        let sum: u8 = rsdp.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "RSDP checksum must be zero");
    }

    #[test]
    fn test_rsdt_signature_and_length() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let rsdt = &region[RSDT_OFFSET..RSDT_OFFSET + RSDT_SIZE];

        assert_eq!(&rsdt[0..4], b"RSDT");
        let length = u32::from_le_bytes(rsdt[4..8].try_into().unwrap());
        assert_eq!(length, RSDT_SIZE as u32);

        let sum: u8 = rsdt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "RSDT checksum must be zero");
    }

    #[test]
    fn test_rsdt_has_two_entries() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let rsdt = &region[RSDT_OFFSET..RSDT_OFFSET + RSDT_SIZE];

        // Entry[0]: FADT pointer.
        let fadt_ptr = u32::from_le_bytes(rsdt[36..40].try_into().unwrap());
        assert_eq!(fadt_ptr, (TEST_BASE + FADT_OFFSET as u64) as u32);

        // Entry[1]: MADT pointer.
        let madt_ptr = u32::from_le_bytes(rsdt[40..44].try_into().unwrap());
        assert_eq!(madt_ptr, (TEST_BASE + MADT_OFFSET as u64) as u32);
    }

    #[test]
    fn test_fadt_signature_and_pm1a_cnt() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let fadt = &region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];

        assert_eq!(&fadt[0..4], b"FACP");

        let pm1a_cnt = u32::from_le_bytes(fadt[64..68].try_into().unwrap());
        assert_eq!(pm1a_cnt, 0x604);

        let pm1a_evt = u32::from_le_bytes(fadt[56..60].try_into().unwrap());
        assert_eq!(pm1a_evt, 0x600);

        assert_eq!(fadt[88], 4, "PM1_EVT_LEN");
        assert_eq!(fadt[89], 2, "PM1_CNT_LEN");

        let sum: u8 = fadt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "FADT checksum must be zero");
    }

    #[test]
    fn test_dsdt_contains_s5_package() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let dsdt_size = DSDT_HEADER_SIZE + S5_AML.len();
        let dsdt = &region[DSDT_OFFSET..DSDT_OFFSET + dsdt_size];

        assert_eq!(&dsdt[0..4], b"DSDT");

        // Verify \_S5_ AML is present.
        let aml = &dsdt[DSDT_HEADER_SIZE..];
        assert_eq!(aml, S5_AML);

        let sum: u8 = dsdt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "DSDT checksum must be zero");
    }

    #[test]
    fn test_total_region_size() {
        let region = build_acpi_tables(TEST_BASE, 1);
        assert_eq!(region.len(), ACPI_REGION_SIZE as usize);
    }

    #[test]
    fn test_rsdp_points_to_rsdt() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let rsdp = &region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];
        let rsdt_addr = u32::from_le_bytes(rsdp[16..20].try_into().unwrap());
        assert_eq!(rsdt_addr, (TEST_BASE + RSDT_OFFSET as u64) as u32);
    }

    #[test]
    fn test_fadt_sci_int() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let fadt = &region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];
        let sci_int = u16::from_le_bytes(fadt[46..48].try_into().unwrap());
        assert_eq!(sci_int, 11, "SCI_INT must be on an unused IRQ");
    }

    #[test]
    fn test_fadt_points_to_dsdt() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let fadt = &region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];
        let dsdt_addr = u32::from_le_bytes(fadt[40..44].try_into().unwrap());
        assert_eq!(dsdt_addr, (TEST_BASE + DSDT_OFFSET as u64) as u32);
    }

    // ---- MADT tests ----

    #[test]
    fn test_madt_signature_and_checksum() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let madt = &region[MADT_OFFSET..MADT_OFFSET + MADT_SIZE_1];

        assert_eq!(&madt[0..4], b"APIC");

        let length = u32::from_le_bytes(madt[4..8].try_into().unwrap());
        assert_eq!(length, MADT_SIZE_1 as u32);

        let sum: u8 = madt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "MADT checksum must be zero");
    }

    #[test]
    fn test_madt_lapic_address() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let madt = &region[MADT_OFFSET..MADT_OFFSET + MADT_SIZE_1];

        let lapic_addr = u32::from_le_bytes(madt[36..40].try_into().unwrap());
        assert_eq!(lapic_addr, LAPIC_BASE);
    }

    #[test]
    fn test_madt_pcat_compat_flag() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let madt = &region[MADT_OFFSET..MADT_OFFSET + MADT_SIZE_1];

        let flags = u32::from_le_bytes(madt[40..44].try_into().unwrap());
        assert_eq!(flags, 1, "PCAT_COMPAT flag must be set");
    }

    #[test]
    fn test_madt_lapic_entry() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let off = MADT_OFFSET + MADT_HEADER_SIZE;

        assert_eq!(region[off], 0, "entry type: Local APIC");
        assert_eq!(region[off + 1], 8, "entry length");
        assert_eq!(region[off + 2], 0, "ACPI Processor ID");
        assert_eq!(region[off + 3], 0, "APIC ID");
        let flags = u32::from_le_bytes(region[off + 4..off + 8].try_into().unwrap());
        assert_eq!(flags, 1, "enabled flag");
    }

    #[test]
    fn test_madt_ioapic_entry() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let off = MADT_OFFSET + MADT_HEADER_SIZE + MADT_LAPIC_ENTRY_SIZE;

        assert_eq!(region[off], 1, "entry type: I/O APIC");
        assert_eq!(region[off + 1], 12, "entry length");
        assert_eq!(region[off + 2], 0, "I/O APIC ID");
        let ioapic_addr = u32::from_le_bytes(region[off + 4..off + 8].try_into().unwrap());
        assert_eq!(ioapic_addr, IOAPIC_BASE);
        let gsi_base = u32::from_le_bytes(region[off + 8..off + 12].try_into().unwrap());
        assert_eq!(gsi_base, 0, "GSI base must be 0");
    }

    #[test]
    fn test_madt_interrupt_source_override() {
        let region = build_acpi_tables(TEST_BASE, 1);
        let off = MADT_OFFSET + MADT_HEADER_SIZE + MADT_LAPIC_ENTRY_SIZE + MADT_IOAPIC_ENTRY_SIZE;

        assert_eq!(region[off], 2, "entry type: Interrupt Source Override");
        assert_eq!(region[off + 1], 10, "entry length");
        assert_eq!(region[off + 2], 0, "bus: ISA");
        assert_eq!(region[off + 3], 0, "source: IRQ 0");
        let gsi = u32::from_le_bytes(region[off + 4..off + 8].try_into().unwrap());
        assert_eq!(gsi, 2, "GSI: IRQ 0 → pin 2");
        let flags = u16::from_le_bytes(region[off + 8..off + 10].try_into().unwrap());
        assert_eq!(flags, 0, "conforming polarity/trigger");
    }

    #[test]
    fn test_tables_do_not_overlap() {
        // Verify no ACPI tables overlap each other.
        let dsdt_size = DSDT_HEADER_SIZE + S5_AML.len();
        let tables = [
            ("RSDP", RSDP_OFFSET, RSDP_OFFSET + RSDP_SIZE),
            ("RSDT", RSDT_OFFSET, RSDT_OFFSET + RSDT_SIZE),
            ("FADT", FADT_OFFSET, FADT_OFFSET + FADT_SIZE),
            ("DSDT", DSDT_OFFSET, DSDT_OFFSET + dsdt_size),
            ("MADT", MADT_OFFSET, MADT_OFFSET + MADT_SIZE_1),
        ];

        for i in 0..tables.len() {
            for j in (i + 1)..tables.len() {
                let (name_a, start_a, end_a) = tables[i];
                let (name_b, start_b, end_b) = tables[j];
                assert!(
                    end_a <= start_b || end_b <= start_a,
                    "{} [{:#X}..{:#X}) overlaps {} [{:#X}..{:#X})",
                    name_a,
                    start_a,
                    end_a,
                    name_b,
                    start_b,
                    end_b
                );
            }
        }
    }

    #[test]
    fn test_all_tables_fit_in_region() {
        let dsdt_size = DSDT_HEADER_SIZE + S5_AML.len();
        let last_table_end = MADT_OFFSET + MADT_SIZE_1;
        assert!(
            last_table_end <= ACPI_REGION_SIZE as usize,
            "tables extend beyond region: {} > {}",
            last_table_end,
            ACPI_REGION_SIZE
        );
        // Also verify DSDT doesn't extend into MADT.
        assert!(DSDT_OFFSET + dsdt_size <= MADT_OFFSET);
    }

    // ---- Multi-vCPU MADT tests ----

    #[test]
    fn test_madt_multi_vcpu_lapic_entries() {
        let region = build_acpi_tables(TEST_BASE, 4);
        let madt_sz = madt_size(4);
        let madt = &region[MADT_OFFSET..MADT_OFFSET + madt_sz];

        // Verify MADT length field matches.
        let length = u32::from_le_bytes(madt[4..8].try_into().unwrap());
        assert_eq!(length, madt_sz as u32);

        // Verify checksum.
        let sum: u8 = madt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "MADT checksum must be zero for 4 vCPUs");

        // Verify 4 LAPIC entries with correct IDs.
        for i in 0..4u8 {
            let off = MADT_HEADER_SIZE + (i as usize) * MADT_LAPIC_ENTRY_SIZE;
            assert_eq!(madt[off], 0, "entry type: Local APIC for vCPU {}", i);
            assert_eq!(madt[off + 1], 8, "entry length for vCPU {}", i);
            assert_eq!(madt[off + 2], i, "ACPI Processor ID for vCPU {}", i);
            assert_eq!(madt[off + 3], i, "APIC ID for vCPU {}", i);
            let flags = u32::from_le_bytes(madt[off + 4..off + 8].try_into().unwrap());
            assert_eq!(flags, 1, "enabled flag for vCPU {}", i);
        }

        // Verify IOAPIC entry follows the 4 LAPIC entries.
        let ioapic_off = MADT_HEADER_SIZE + 4 * MADT_LAPIC_ENTRY_SIZE;
        assert_eq!(madt[ioapic_off], 1, "entry type: I/O APIC");
    }

    #[test]
    fn test_madt_size_scales_with_vcpus() {
        assert_eq!(madt_size(1), MADT_SIZE_1);
        assert_eq!(
            madt_size(2),
            MADT_SIZE_1 + MADT_LAPIC_ENTRY_SIZE,
            "2 vCPUs adds one more LAPIC entry"
        );
        assert_eq!(
            madt_size(4),
            MADT_SIZE_1 + 3 * MADT_LAPIC_ENTRY_SIZE,
            "4 vCPUs adds three more LAPIC entries"
        );
    }
}
