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
    let restored = restore(&container[start..end]).unwrap();
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
        (12, &[255, 255, 255, 255]),
    ] {
        let mut image = fixture(&[(0, 4096, 0)], 4096);
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            restore(&image).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    // Short header/table/payload and trailing bytes are all invalid.
    for len in [0, 15, 39, 40, 4135, 4137] {
        let mut image = fixture(&[(0, 4096, 0)], 4096);
        image.resize(len, 0);
        assert!(restore(&image).is_err());
    }
}

#[test]
fn metadata_reports_layout_for_caller_policy() {
    let image = fixture(&[(1, 3, 0), (100, 2, 0)], 5);
    let metadata = get_metadata(&image).unwrap();
    assert_eq!(
        metadata,
        Metadata {
            version: 1,
            memory_bytes: 5,
            regions: vec![Region { gpa: 1, len: 3 }, Region { gpa: 100, len: 2 }],
        }
    );
    // The caller may reject this layout; the codec imposes no page alignment.
    let memory = restore(&image).unwrap();
    assert_eq!(memory.read_obj::<u8>(GuestAddress(100)).unwrap(), 0);
    assert_eq!(get_metadata(&save(&memory).unwrap()).unwrap(), metadata);

    let overlapping = fixture(&[(0, 4, 0), (2, 4, 0)], 8);
    assert_eq!(get_metadata(&overlapping).unwrap().regions[1].gpa, 2);
    assert!(restore(&overlapping).is_err()); // GuestMemoryMmap rejects overlap.
}

#[test]
fn malformed_metadata_is_rejected() {
    for entries in [
        vec![(0, 4096, 1)],
        vec![(0, u64::MAX, 0), (0, 1, 0)],
        vec![(0, 1u64 << 63, 0)],
    ] {
        let image = fixture(&entries, 8);
        assert_eq!(
            get_metadata(&image).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(restore(&image).is_err());
    }
}

#[test]
fn readable_mappings_are_copied_to_anonymous_ram() {
    let backing = TempFile::new().unwrap();
    backing.as_file().set_len(4096).unwrap();
    let file_memory = GuestMemoryMmap::from_ranges_with_files(&[(
        GuestAddress(0),
        4096,
        Some(FileOffset::new(backing.as_file().try_clone().unwrap(), 0)),
    )])
    .unwrap();
    file_memory.write_obj(42u8, GuestAddress(0)).unwrap();
    let restored = restore(&save(&file_memory).unwrap()).unwrap();
    assert_eq!(restored.read_obj::<u8>(GuestAddress(0)).unwrap(), 42);
    assert!(restored.iter().next().unwrap().file_offset().is_none());
    for (flags, prot) in [
        (
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            libc::PROT_READ | libc::PROT_WRITE,
        ),
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, libc::PROT_READ),
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, libc::PROT_NONE),
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
        if prot == libc::PROT_NONE {
            assert!(save(&memory).is_err());
        } else {
            let image = save(&memory).unwrap();
            assert_eq!(
                restore(&image)
                    .unwrap()
                    .read_obj::<u8>(GuestAddress(0))
                    .unwrap(),
                0
            );
        }
    }
}
