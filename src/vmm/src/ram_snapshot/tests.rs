// SPDX-License-Identifier: Apache-2.0

use super::*;
use utils::tempfile::TempFile;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{FileOffset, GuestRegionMmap};

// Encode fixtures independently of the production writer, including bad tables.
fn fixture(entries: &[(u64, u64, u64)], payload_len: usize) -> Vec<u8> {
    let mut image = b"KRUNRAM\0\x01\0\0\0".to_vec();
    image.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for &(gpa, len, attributes) in entries {
        for field in [gpa, len, attributes] {
            image.extend_from_slice(&field.to_le_bytes());
        }
    }
    image.resize(16 + 24 * entries.len() + payload_len, 0);
    image
}

#[test]
fn discontiguous_ram_round_trip_owns_its_bytes() {
    let ranges = [
        (GuestAddress(0x1000), 0x21000),
        (GuestAddress(1 << 32), 0x2000),
    ];
    let memory = GuestMemoryMmap::from_ranges(&ranges).unwrap();
    for (index, &(gpa, len)) in ranges.iter().enumerate() {
        let data: Vec<_> = (0..len).map(|i| ((i * 37 + index) % 251) as u8).collect();
        memory.write_slice(&data, gpa).unwrap();
    }
    let encoded = save(&memory).unwrap();
    assert_eq!(&encoded[..16], b"KRUNRAM\0\x01\0\0\0\x02\0\0\0");
    assert_eq!(encoded.len(), 16 + 48 + 0x23000);
    // The codec can borrow a section of a larger single-file container.
    let mut container = b"outer header".to_vec();
    let start = container.len();
    container.extend_from_slice(&encoded);
    let end = container.len();
    container.extend_from_slice(b"other VM state");
    let restored = restore(&container[start..end], 2, 0x23000).unwrap();
    drop(container);
    assert_eq!(restored.num_regions(), 2);
    assert!(!restored.address_in_range(GuestAddress(0x100000)));
    for &(gpa, len) in &ranges {
        let mut expected = vec![0; len];
        let mut actual = vec![0; len];
        memory.read_slice(&mut expected, gpa).unwrap();
        restored.read_slice(&mut actual, gpa).unwrap();
        assert_eq!(actual, expected);
    }
    memory.write_obj(255u8, ranges[0].0).unwrap();
    assert_eq!(encoded[16 + 48], 0);
    assert_eq!(restored.read_obj::<u8>(ranges[0].0).unwrap(), 0);
}

#[test]
fn malformed_header_and_image_lengths_are_rejected() {
    for (offset, bytes) in [
        (0, b"BADMAGIC".as_slice()),
        (8, &[2, 0, 0, 0]),
        (12, &[0, 0, 0, 0]),
        (12, &[255, 255, 255, 255]),
    ] {
        let mut image = fixture(&[(0, 4096, 0)], 4096);
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            restore(&image, 2, 8192).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    // Short header/table/payload and trailing bytes are all invalid.
    for len in [0, 15, 39, 40, 4135, 4137] {
        let mut image = fixture(&[(0, 4096, 0)], 4096);
        image.resize(len, 0);
        assert!(restore(&image, 1, 4096).is_err());
    }
}

#[test]
fn invalid_regions_are_rejected_before_allocation() {
    let cases = [
        vec![(0, 0, 0)],
        vec![(1, 4096, 0)],
        vec![(0, 4095, 0)],
        vec![(0, 4096, 1)],
        vec![(u64::MAX - 4095, 4096, 0)],
        vec![(0, 1u64 << 63, 0)],
        vec![(0, 8192, 0), (4096, 4096, 0)],
        vec![(8192, 4096, 0), (0, 4096, 0)],
    ];
    for entries in cases {
        let image = fixture(&entries, 8192);
        assert_eq!(
            restore(&image, 2, u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn target_region_and_memory_limits_are_enforced() {
    let image = fixture(&[(0, 4096, 0), (8192, 4096, 0)], 8192);
    for (regions, bytes) in [(0, 8192), (1, 8192), (2, 0), (2, 8191)] {
        assert_eq!(
            restore(&image, regions, bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    let memory = restore(&image, 2, 8192).unwrap();
    assert_eq!(memory.read_obj::<u64>(GuestAddress(8192)).unwrap(), 0);
}

#[test]
fn unsupported_mappings_are_rejected() {
    let backing = TempFile::new().unwrap();
    backing.as_file().set_len(4096).unwrap();
    let file_memory = GuestMemoryMmap::from_ranges_with_files(&[(
        GuestAddress(0),
        4096,
        Some(FileOffset::new(backing.as_file().try_clone().unwrap(), 0)),
    )])
    .unwrap();
    assert!(save(&file_memory).is_err());
    for (flags, prot) in [
        (
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            libc::PROT_READ | libc::PROT_WRITE,
        ),
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, libc::PROT_READ),
    ] {
        let mapping = MmapRegionBuilder::new(4096)
            .with_mmap_flags(flags)
            .with_mmap_prot(prot)
            .build()
            .unwrap();
        let memory =
            GuestMemoryMmap::from_regions(vec![
                GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap()
            ])
            .unwrap();
        assert!(save(&memory).is_err());
    }
    let unaligned = GuestMemoryMmap::from_ranges(&[(GuestAddress(1), 4096)]).unwrap();
    assert!(save(&unaligned).is_err());
}
