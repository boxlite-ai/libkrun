// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use utils::tempdir::TempDir;
use utils::tempfile::TempFile;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{FileOffset, GuestRegionMmap};

// Encode fixtures independently of the production writer, including bad tables.
fn fixture(entries: &[(u64, u64, u64)], payload_len: u64) -> TempFile {
    let temp = TempFile::new().unwrap();
    let mut file = temp.as_file();
    file.write_all(b"KRUNRAM\0\x01\0\0\0").unwrap();
    file.write_all(&(entries.len() as u32).to_le_bytes())
        .unwrap();
    for &(gpa, len, attributes) in entries {
        for field in [gpa, len, attributes] {
            file.write_all(&field.to_le_bytes()).unwrap();
        }
    }
    file.set_len(16 + 24 * entries.len() as u64 + payload_len)
        .unwrap();
    temp
}

#[test]
fn discontiguous_ram_round_trip_is_independent_and_chunked() {
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("ram");
    let ranges = [
        (GuestAddress(0x1000), 0x21000),
        (GuestAddress(1 << 32), 0x2000),
    ];
    let memory = GuestMemoryMmap::from_ranges(&ranges).unwrap();
    for (index, &(gpa, len)) in ranges.iter().enumerate() {
        let data: Vec<_> = (0..len).map(|i| ((i * 37 + index) % 251) as u8).collect();
        memory.write_slice(&data, gpa).unwrap();
    }
    save(&path, &memory).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let encoded = fs::read(&path).unwrap();
    assert_eq!(&encoded[..16], b"KRUNRAM\0\x01\0\0\0\x02\0\0\0");
    assert_eq!(encoded.len(), 16 + 48 + 0x23000);
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    let restored = restore(&mut file, 2, 0x23000).unwrap();
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
    assert_eq!(restored.read_obj::<u8>(ranges[0].0).unwrap(), 0);
}

#[test]
fn existing_file_and_symlink_are_untouched() {
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("existing");
    let link = dir.as_path().join("link");
    fs::write(&path, b"keep me").unwrap();
    symlink(&path, &link).unwrap();
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    for destination in [&path, &link] {
        assert_eq!(
            save(destination, &memory).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
    }
}

#[test]
fn incomplete_output_is_invalid_and_removed_on_drop() {
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("incomplete");
    let mut pending = PendingImage::create(&path).unwrap();
    pending.file.write_all(&[0; 16]).unwrap();
    let mut reader = File::open(&path).unwrap();
    assert!(restore(&mut reader, 1, 4096).is_err());
    drop(pending);
    assert!(!path.exists());
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut magic = [1; 8];
    reader.read_exact(&mut magic).unwrap();
    assert_eq!(magic, [0; 8]);
}

#[test]
fn malformed_header_and_file_lengths_are_rejected() {
    for (offset, bytes) in [
        (0, b"BADMAGIC".as_slice()),
        (8, &[2, 0, 0, 0]),
        (12, &[0, 0, 0, 0]),
        (12, &[255, 255, 255, 255]),
    ] {
        let temp = fixture(&[(0, 4096, 0)], 4096);
        let mut file = temp.as_file().try_clone().unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(bytes).unwrap();
        assert_eq!(
            restore(&mut file, 2, 8192).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    // Short header/table/payload and trailing bytes are all invalid.
    for len in [0, 15, 39, 40, 4135, 4137] {
        let temp = fixture(&[(0, 4096, 0)], 4096);
        temp.as_file().set_len(len).unwrap();
        assert!(restore(&mut temp.as_file().try_clone().unwrap(), 1, 4096).is_err());
    }
    assert!(restore(&mut File::open("/dev/null").unwrap(), 1, 4096).is_err());
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
        let temp = fixture(&entries, 8192);
        let mut file = temp.as_file().try_clone().unwrap();
        assert_eq!(
            restore(&mut file, 2, u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn target_region_and_memory_limits_are_enforced() {
    let temp = fixture(&[(0, 4096, 0), (8192, 4096, 0)], 8192);
    let mut file = temp.as_file().try_clone().unwrap();
    for (regions, bytes) in [(0, 8192), (1, 8192), (2, 0), (2, 8191)] {
        assert_eq!(
            restore(&mut file, regions, bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    let memory = restore(&mut file, 2, 8192).unwrap();
    assert_eq!(memory.read_obj::<u64>(GuestAddress(8192)).unwrap(), 0);
}

#[test]
fn unsupported_mappings_do_not_create_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("ram");
    let backing = TempFile::new().unwrap();
    backing.as_file().set_len(4096).unwrap();
    let file_memory = GuestMemoryMmap::from_ranges_with_files(&[(
        GuestAddress(0),
        4096,
        Some(FileOffset::new(backing.as_file().try_clone().unwrap(), 0)),
    )])
    .unwrap();
    assert!(save(&path, &file_memory).is_err());
    assert!(!path.exists());
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
        assert!(save(&path, &memory).is_err());
        assert!(!path.exists());
    }
    let unaligned = GuestMemoryMmap::from_ranges(&[(GuestAddress(1), 4096)]).unwrap();
    assert!(save(&path, &unaligned).is_err());
    assert!(!path.exists());
}
