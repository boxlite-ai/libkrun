//! Minimal ACPI table generation for WHPX guest boot.
//!
//! Generates RSDP, RSDT, FADT, and DSDT tables so the Linux kernel can
//! discover the PM1a_CNT register and perform clean ACPI S5 shutdown
//! instead of falling back to an HLT loop.

/// Total size of the ACPI region in guest memory.
pub const ACPI_REGION_SIZE: u64 = 0x200; // 512 bytes

// Table offsets within the ACPI region.
const RSDP_OFFSET: usize = 0x00;
const RSDT_OFFSET: usize = 0x20;
const FADT_OFFSET: usize = 0x60;
const DSDT_OFFSET: usize = 0x100;

// Table sizes.
const RSDP_SIZE: usize = 20;
const RSDT_SIZE: usize = 40; // 36-byte header + 4-byte entry
const FADT_SIZE: usize = 116;
const DSDT_HEADER_SIZE: usize = 36;

// ACPI PM1a I/O port addresses (must match manager.rs constants).
const PM1A_EVT_BLK: u32 = 0x600;
const PM1A_CNT_BLK: u32 = 0x604;

/// SCI interrupt number for ACPI.
///
/// Must not conflict with timer (IRQ 0), serial (IRQ 4), or
/// virtio-MMIO devices (IRQ 5-9). IRQ 11 is unused.
const SCI_INT: u16 = 11;

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

/// Build ACPI tables (RSDP, RSDT, FADT, DSDT) for the given base address.
///
/// Returns a `Vec<u8>` of exactly `ACPI_REGION_SIZE` bytes. The caller
/// writes this to guest memory at `acpi_base`.
pub fn build_acpi_tables(acpi_base: u64) -> Vec<u8> {
    let mut region = vec![0u8; ACPI_REGION_SIZE as usize];

    let rsdt_addr = acpi_base + RSDT_OFFSET as u64;
    let fadt_addr = acpi_base + FADT_OFFSET as u64;
    let dsdt_addr = acpi_base + DSDT_OFFSET as u64;

    // ---- RSDP (20 bytes at offset 0x00) ----
    let rsdp = &mut region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];
    rsdp[0..8].copy_from_slice(b"RSD PTR "); // Signature
    // rsdp[8] = checksum (computed below)
    rsdp[9..15].copy_from_slice(b"BOXLTE"); // OEMID
    rsdp[15] = 0; // Revision: ACPI 1.0
    rsdp[16..20].copy_from_slice(&(rsdt_addr as u32).to_le_bytes()); // RsdtAddress
    acpi_checksum(&mut region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE], 8);

    // ---- RSDT (40 bytes at offset 0x20) ----
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
    acpi_checksum(
        &mut region[DSDT_OFFSET..DSDT_OFFSET + dsdt_size],
        9,
    );

    region
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
        let region = build_acpi_tables(TEST_BASE);
        let rsdp = &region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];

        assert_eq!(&rsdp[0..8], b"RSD PTR ");

        let sum: u8 = rsdp.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "RSDP checksum must be zero");
    }

    #[test]
    fn test_rsdt_signature_and_length() {
        let region = build_acpi_tables(TEST_BASE);
        let rsdt = &region[RSDT_OFFSET..RSDT_OFFSET + RSDT_SIZE];

        assert_eq!(&rsdt[0..4], b"RSDT");
        let length = u32::from_le_bytes(rsdt[4..8].try_into().unwrap());
        assert_eq!(length, RSDT_SIZE as u32);

        let sum: u8 = rsdt.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "RSDT checksum must be zero");
    }

    #[test]
    fn test_fadt_signature_and_pm1a_cnt() {
        let region = build_acpi_tables(TEST_BASE);
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
        let region = build_acpi_tables(TEST_BASE);
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
        let region = build_acpi_tables(TEST_BASE);
        assert_eq!(region.len(), ACPI_REGION_SIZE as usize);
    }

    #[test]
    fn test_rsdp_points_to_rsdt() {
        let region = build_acpi_tables(TEST_BASE);
        let rsdp = &region[RSDP_OFFSET..RSDP_OFFSET + RSDP_SIZE];
        let rsdt_addr = u32::from_le_bytes(rsdp[16..20].try_into().unwrap());
        assert_eq!(rsdt_addr, (TEST_BASE + RSDT_OFFSET as u64) as u32);
    }

    #[test]
    fn test_fadt_sci_int() {
        let region = build_acpi_tables(TEST_BASE);
        let fadt = &region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];
        let sci_int = u16::from_le_bytes(fadt[46..48].try_into().unwrap());
        assert_eq!(sci_int, 11, "SCI_INT must be on an unused IRQ");
    }

    #[test]
    fn test_fadt_points_to_dsdt() {
        let region = build_acpi_tables(TEST_BASE);
        let fadt = &region[FADT_OFFSET..FADT_OFFSET + FADT_SIZE];
        let dsdt_addr = u32::from_le_bytes(fadt[40..44].try_into().unwrap());
        assert_eq!(dsdt_addr, (TEST_BASE + DSDT_OFFSET as u64) as u32);
    }
}
