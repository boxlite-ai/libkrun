//! Intel MultiProcessor Specification table generation.
//!
//! Generates the MP Floating Pointer Structure and MP Configuration Table
//! so the Linux kernel can discover multiple vCPUs when CONFIG_ACPI is
//! not enabled (CONFIG_X86_MPPARSE=y is sufficient).
//!
//! The kernel scans for the MP FPS in:
//! - First 1KB of EBDA
//! - Last 1KB of base memory (0x9FC00-0x9FFFF)
//! - BIOS ROM area (0xF0000-0xFFFFF)

/// Guest physical address for the MP Floating Pointer Structure.
/// Placed at 0x9FC00 (start of the last 1KB of base memory).
pub const MP_FPS_ADDR: u64 = 0x9_FC00;

/// Guest physical address for the MP Configuration Table.
/// Placed right after the 16-byte FPS.
const MP_TABLE_ADDR: u64 = MP_FPS_ADDR + 16;

/// MP FPS size (always 16 bytes).
const FPS_SIZE: usize = 16;

/// MP Configuration Table header size.
const MP_HEADER_SIZE: usize = 44;

/// Processor entry size (type 0).
const PROC_ENTRY_SIZE: usize = 20;

/// I/O APIC entry size (type 2).
const IOAPIC_ENTRY_SIZE: usize = 8;

/// LAPIC base address (must match memory.rs and acpi.rs).
const LAPIC_BASE: u32 = 0xFEE0_0000;

/// IOAPIC base address (must match memory.rs and acpi.rs).
const IOAPIC_BASE: u32 = 0xFEC0_0000;

/// Total size needed for the MP table region.
pub fn mp_region_size(num_vcpus: u8) -> usize {
    FPS_SIZE + MP_HEADER_SIZE + (num_vcpus as usize) * PROC_ENTRY_SIZE + IOAPIC_ENTRY_SIZE
}

/// Build the MP Floating Pointer Structure (16 bytes).
///
/// Placed at `fps_addr`, points to the MP Configuration Table at `table_addr`.
fn build_fps(fps: &mut [u8], table_addr: u32) {
    // Signature "_MP_"
    fps[0..4].copy_from_slice(b"_MP_");
    // Physical Address of MP Configuration Table
    fps[4..8].copy_from_slice(&table_addr.to_le_bytes());
    // Length in 16-byte paragraphs (always 1)
    fps[8] = 1;
    // MP Specification revision (1.4)
    fps[9] = 4;
    // Checksum (computed below)
    // fps[10] = checksum
    // Feature bytes 1-5 (all 0 = use MP config table)
    fps[11] = 0;
    fps[12] = 0;
    fps[13] = 0;
    fps[14] = 0;
    fps[15] = 0;

    mp_checksum(fps, 10);
}

/// Build the MP Configuration Table.
///
/// Contains:
/// - 44-byte header
/// - N processor entries (20 bytes each)
/// - 1 I/O APIC entry (8 bytes)
fn build_mp_config_table(table: &mut [u8], num_vcpus: u8) {
    let entry_count = num_vcpus as u16 + 1; // N processors + 1 I/O APIC
    let base_table_length =
        MP_HEADER_SIZE + (num_vcpus as usize) * PROC_ENTRY_SIZE + IOAPIC_ENTRY_SIZE;

    // ---- Header (44 bytes) ----
    table[0..4].copy_from_slice(b"PCMP"); // Signature
    table[4..6].copy_from_slice(&(base_table_length as u16).to_le_bytes()); // Base Table Length
    table[6] = 4; // Spec Revision (1.4)
                  // table[7] = checksum (computed below)
    table[8..16].copy_from_slice(b"BOXLTE\0\0"); // OEM ID (8 bytes)
    table[16..28].copy_from_slice(b"BOXLITE-VM\0\0"); // Product ID (12 bytes)
                                                      // OEM Table Pointer (offset 28, 4 bytes) = 0
                                                      // OEM Table Size (offset 32, 2 bytes) = 0
    table[34..36].copy_from_slice(&entry_count.to_le_bytes()); // Entry Count
    table[36..40].copy_from_slice(&LAPIC_BASE.to_le_bytes()); // Local APIC Address
                                                              // Extended Table Length (offset 40, 2 bytes) = 0
                                                              // Extended Table Checksum (offset 42, 1 byte) = 0
                                                              // Reserved (offset 43, 1 byte) = 0

    // ---- Processor entries (type 0, 20 bytes each) ----
    let mut off = MP_HEADER_SIZE;
    for i in 0..num_vcpus {
        table[off] = 0; // Entry type: Processor
        table[off + 1] = i; // Local APIC ID
        table[off + 2] = 0x14; // Local APIC Version
                               // CPU Flags: bit 0 = EN (usable), bit 1 = BP (bootstrap processor)
        table[off + 3] = if i == 0 { 0x03 } else { 0x01 }; // BSP=3, AP=1
                                                           // CPU Signature (4 bytes) — use a generic Family 6 Model signature.
                                                           // This doesn't need to match the host exactly; the kernel reads CPUID directly.
        table[off + 4..off + 8].copy_from_slice(&0x0006_0000u32.to_le_bytes());
        // Feature Flags (4 bytes) — basic x86-64 features.
        table[off + 8..off + 12].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        // Reserved (8 bytes) = 0
        off += PROC_ENTRY_SIZE;
    }

    // ---- I/O APIC entry (type 2, 8 bytes) ----
    table[off] = 2; // Entry type: I/O APIC
    table[off + 1] = num_vcpus; // I/O APIC ID (after all LAPIC IDs)
    table[off + 2] = 0x20; // I/O APIC Version
    table[off + 3] = 0x01; // Flags: EN (enabled)
    table[off + 4..off + 8].copy_from_slice(&IOAPIC_BASE.to_le_bytes()); // I/O APIC Address

    // Compute header checksum over the entire base table.
    mp_checksum(&mut table[..base_table_length], 7);
}

/// Build the complete MP table region (FPS + Configuration Table).
///
/// Returns a `Vec<u8>` that should be written to guest memory at `MP_FPS_ADDR`.
pub fn build_mp_tables(num_vcpus: u8) -> Vec<u8> {
    let total_size = mp_region_size(num_vcpus);
    let mut region = vec![0u8; total_size];

    // Build the FPS (first 16 bytes), pointing to the config table.
    build_fps(&mut region[..FPS_SIZE], MP_TABLE_ADDR as u32);

    // Build the MP Configuration Table (after the FPS).
    build_mp_config_table(&mut region[FPS_SIZE..], num_vcpus);

    region
}

/// Compute MP checksum and store at `checksum_offset`.
///
/// The checksum byte is set so the sum of all bytes equals zero (mod 256).
fn mp_checksum(data: &mut [u8], checksum_offset: usize) {
    data[checksum_offset] = 0;
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    data[checksum_offset] = 0u8.wrapping_sub(sum);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fps_signature_and_checksum() {
        let region = build_mp_tables(2);
        let fps = &region[..FPS_SIZE];

        assert_eq!(&fps[0..4], b"_MP_");
        let sum: u8 = fps.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "FPS checksum must be zero");
    }

    #[test]
    fn test_fps_points_to_table() {
        let region = build_mp_tables(2);
        let fps = &region[..FPS_SIZE];

        let table_addr = u32::from_le_bytes(fps[4..8].try_into().unwrap());
        assert_eq!(table_addr, MP_TABLE_ADDR as u32);
    }

    #[test]
    fn test_fps_revision() {
        let region = build_mp_tables(2);
        assert_eq!(region[8], 1, "FPS length must be 1 paragraph");
        assert_eq!(region[9], 4, "FPS revision must be 1.4");
    }

    #[test]
    fn test_mp_table_signature_and_checksum() {
        let region = build_mp_tables(2);
        let table_start = FPS_SIZE;
        let table_len = MP_HEADER_SIZE + 2 * PROC_ENTRY_SIZE + IOAPIC_ENTRY_SIZE;
        let table = &region[table_start..table_start + table_len];

        assert_eq!(&table[0..4], b"PCMP");

        let length = u16::from_le_bytes(table[4..6].try_into().unwrap());
        assert_eq!(length, table_len as u16);

        let sum: u8 = table.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "MP table checksum must be zero");
    }

    #[test]
    fn test_mp_table_processor_entries() {
        let region = build_mp_tables(4);
        let table_start = FPS_SIZE;

        // Check entry count
        let entry_count = u16::from_le_bytes(
            region[table_start + 34..table_start + 36]
                .try_into()
                .unwrap(),
        );
        assert_eq!(entry_count, 5, "4 processors + 1 I/O APIC");

        // Check processor entries
        for i in 0..4u8 {
            let off = table_start + MP_HEADER_SIZE + (i as usize) * PROC_ENTRY_SIZE;
            assert_eq!(region[off], 0, "entry type: Processor for vCPU {}", i);
            assert_eq!(region[off + 1], i, "APIC ID for vCPU {}", i);
            assert_eq!(region[off + 2], 0x14, "APIC version for vCPU {}", i);
            if i == 0 {
                assert_eq!(region[off + 3], 0x03, "BSP flags (EN + BP)");
            } else {
                assert_eq!(region[off + 3], 0x01, "AP flags (EN only)");
            }
        }
    }

    #[test]
    fn test_mp_table_ioapic_entry() {
        let region = build_mp_tables(2);
        let table_start = FPS_SIZE;
        let ioapic_off = table_start + MP_HEADER_SIZE + 2 * PROC_ENTRY_SIZE;

        assert_eq!(region[ioapic_off], 2, "entry type: I/O APIC");
        assert_eq!(region[ioapic_off + 1], 2, "I/O APIC ID");
        assert_eq!(region[ioapic_off + 3], 0x01, "enabled flag");

        let addr = u32::from_le_bytes(region[ioapic_off + 4..ioapic_off + 8].try_into().unwrap());
        assert_eq!(addr, IOAPIC_BASE);
    }

    #[test]
    fn test_mp_table_lapic_address() {
        let region = build_mp_tables(1);
        let table_start = FPS_SIZE;

        let lapic_addr = u32::from_le_bytes(
            region[table_start + 36..table_start + 40]
                .try_into()
                .unwrap(),
        );
        assert_eq!(lapic_addr, LAPIC_BASE);
    }

    #[test]
    fn test_single_vcpu() {
        let region = build_mp_tables(1);
        let total = mp_region_size(1);
        assert_eq!(region.len(), total);

        let table_start = FPS_SIZE;
        let entry_count = u16::from_le_bytes(
            region[table_start + 34..table_start + 36]
                .try_into()
                .unwrap(),
        );
        assert_eq!(entry_count, 2, "1 processor + 1 I/O APIC");
    }

    #[test]
    fn test_region_fits_in_base_memory() {
        // MP tables for up to 16 vCPUs must fit in the scan area.
        let max_size = mp_region_size(16);
        // FPS at 0x9FC00, scan area is 0x9FC00-0x9FFFF (1024 bytes).
        assert!(
            max_size <= 1024,
            "MP tables for 16 vCPUs ({} bytes) exceed scan area",
            max_size,
        );
    }
}
