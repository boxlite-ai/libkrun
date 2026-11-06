// SPDX-License-Identifier: Apache-2.0

//! Version-10 memory envelope, with v9 read support and no payload checksums.

use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::FileExt;

pub(super) const HEADER: u64 = 160;

#[derive(Debug)]
pub(super) struct Envelope {
    pub metadata: Vec<u8>,
    pub payload: u64,
    pub disk_len: u64,
}

pub(super) fn digest(file: &File, offset: u64, len: u64) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; CHUNK_SIZE];
    let mut done = 0;
    while done < len {
        let count = (len - done).min(buffer.len() as u64) as usize;
        file.read_exact_at(
            &mut buffer[..count],
            offset
                .checked_add(done)
                .ok_or(Error::Invalid("digest extent overflow"))?,
        )?;
        hash.update(&buffer[..count]);
        done += count as u64;
    }
    Ok(hash.finalize().into())
}

fn number(header: &[u8], start: usize) -> u64 {
    u64::from_le_bytes(header[start..start + 8].try_into().unwrap())
}

pub(super) fn read(file: &File) -> Result<Envelope> {
    // Read version first so short legacy files still receive a version error.
    let mut prefix = [0; 12];
    file.read_exact_at(&mut prefix, 0)?;
    if &prefix[..8] != FULL_MAGIC {
        return Err(Error::Invalid("invalid/incomplete full snapshot"));
    }
    let version = u32::from_le_bytes(prefix[8..12].try_into().unwrap());
    if !matches!(version, 9 | FULL_VERSION) {
        return Err(Error::Invalid(
            "unsupported full snapshot version; version 9 or 10 required",
        ));
    }
    let mut header = [0; HEADER as usize];
    file.read_exact_at(&mut header, 0)?;
    if u32::from_le_bytes(header[12..16].try_into().unwrap()) != HEADER as u32
        || header[144..].iter().any(|&byte| byte != 0)
        || (version == FULL_VERSION && header[80..144].iter().any(|&byte| byte != 0))
    {
        return Err(Error::Invalid(
            "unsupported memory header length or reserved fields",
        ));
    }
    let meta_len = number(&header, 24);
    let payload = number(&header, 32);
    let total = HEADER
        .checked_add(meta_len)
        .and_then(|n| n.checked_add(payload))
        .ok_or(Error::Invalid("memory file length overflow"))?;
    if meta_len == 0
        || meta_len > MAX_METADATA as u64
        || total != number(&header, 16)
        || total != file.metadata()?.len()
    {
        return Err(Error::Invalid(
            "memory file length or metadata bound mismatch",
        ));
    }
    let mut metadata = vec![0; meta_len as usize];
    file.read_exact_at(&mut metadata, HEADER)?;
    Ok(Envelope {
        metadata,
        payload,
        disk_len: number(&header, 40),
    })
}

pub(super) fn seal(file: &File, metadata_len: u64, payload: u64, disk_len: u64) -> Result<()> {
    let total = HEADER
        .checked_add(metadata_len)
        .and_then(|n| n.checked_add(payload))
        .ok_or(Error::Invalid("memory file length overflow"))?;
    if metadata_len == 0 || metadata_len > MAX_METADATA as u64 || file.metadata()?.len() != total {
        return Err(Error::Invalid("memory file output length mismatch"));
    }
    let mut header = [0; HEADER as usize];
    header[..8].copy_from_slice(FULL_MAGIC);
    header[8..12].copy_from_slice(&FULL_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(HEADER as u32).to_le_bytes());
    for (at, value) in [
        (16, total),
        (24, metadata_len),
        (32, payload),
        (40, disk_len),
    ] {
        header[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    // Distinguish captures for catalog replay without scanning their payloads.
    File::open("/dev/urandom")?.read_exact(&mut header[48..80])?;
    file.sync_all()?;
    file.write_all_at(&header, 0)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> File {
        // Anonymous file: production codec boundaries with real pread/pwrite.
        let name = std::ffi::CString::new("snapshot-format").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        use std::os::fd::FromRawFd;
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(HEADER + 3 + 7).unwrap();
        file.write_all_at(b"{}\n", HEADER).unwrap();
        file.write_all_at(b"payload", HEADER + 3).unwrap();
        seal(&file, 3, 7, 1234).unwrap();
        file
    }
    #[test]
    fn snapshot_v10_envelope_omits_payload_checksums() {
        let file = image();
        let decoded = read(&file).unwrap();
        let mut header = [0; HEADER as usize];
        file.read_exact_at(&mut header, 0).unwrap();
        assert_eq!(u32::from_le_bytes(header[8..12].try_into().unwrap()), 10);
        assert_eq!(&header[80..], &[0; 80]);
        let mut next = [0; HEADER as usize];
        image().read_exact_at(&mut next, 0).unwrap();
        assert_ne!(&header[48..80], &next[48..80]);
        assert_eq!(decoded.metadata, b"{}\n");
        assert_eq!((decoded.payload, decoded.disk_len), (7, 1234));
        for offset in [HEADER, HEADER + 3] {
            let file = image();
            file.write_all_at(b"!", offset).unwrap();
            assert!(read(&file).is_ok());
        }
    }
    #[test]
    fn snapshot_v9_envelope_reads_legacy_hash_fields_without_verifying_them() {
        let legacy = image();
        legacy.write_all_at(&9u32.to_le_bytes(), 8).unwrap();
        // Reproduce the v9 layout, including nonzero payload and disk hashes.
        legacy
            .write_all_at(&digest(&legacy, HEADER, 3).unwrap(), 48)
            .unwrap();
        legacy
            .write_all_at(&digest(&legacy, HEADER + 3, 7).unwrap(), 80)
            .unwrap();
        legacy.write_all_at(&[17; 32], 112).unwrap();
        let decoded = read(&legacy).unwrap();
        assert_eq!(decoded.metadata, b"{}\n");
        assert_eq!((decoded.payload, decoded.disk_len), (7, 1234));
        legacy.write_all_at(b"!", HEADER + 3).unwrap();
        legacy.write_all_at(b"[]\n", HEADER).unwrap();
        assert_eq!(read(&legacy).unwrap().metadata, b"[]\n");
    }
    #[test]
    fn snapshot_v10_envelope_bounds_and_old_versions() {
        for version in [1u32, 7, 8, 11] {
            let file = image();
            file.write_all_at(&version.to_le_bytes(), 8).unwrap();
            assert!(read(&file).unwrap_err().to_string().contains("version"));
        }
        for (offset, value) in [(16, 0), (24, u64::MAX), (32, u64::MAX)] {
            let file = image();
            file.write_all_at(&value.to_le_bytes(), offset).unwrap();
            assert!(read(&file).is_err());
        }
        let file = image();
        file.set_len(file.metadata().unwrap().len() + 1).unwrap();
        assert!(read(&file).is_err());
        let file = image();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        assert!(read(&file).is_err());
        for (version, offsets) in [(9u32, vec![144, 159]), (10, vec![80, 112, 144, 159])] {
            for offset in offsets {
                let file = image();
                file.write_all_at(&version.to_le_bytes(), 8).unwrap();
                file.write_all_at(&[1], offset).unwrap();
                assert!(read(&file).unwrap_err().to_string().contains("reserved"));
            }
        }
    }
}
