// SPDX-License-Identifier: Apache-2.0

//! Version-9 memory-file envelope. Offsets never depend on a shared FD cursor.

use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::FileExt;

pub(super) const HEADER: u64 = 160;

#[derive(Debug)]
pub(super) struct Envelope {
    pub metadata: Vec<u8>,
    pub payload: u64,
    pub disk_len: u64,
    pub disk_hash: [u8; 32],
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
    if u32::from_le_bytes(prefix[8..12].try_into().unwrap()) != FULL_VERSION {
        return Err(Error::Invalid(
            "unsupported full snapshot version; version 9 required",
        ));
    }
    let mut header = [0; HEADER as usize];
    file.read_exact_at(&mut header, 0)?;
    if u32::from_le_bytes(header[12..16].try_into().unwrap()) != HEADER as u32
        || header[144..].iter().any(|&byte| byte != 0)
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
    if digest(file, HEADER, meta_len)? != header[48..80]
        || digest(file, HEADER + meta_len, payload)? != header[80..112]
    {
        return Err(Error::Invalid("memory file checksum mismatch"));
    }
    let mut metadata = vec![0; meta_len as usize];
    file.read_exact_at(&mut metadata, HEADER)?;
    Ok(Envelope {
        metadata,
        payload,
        disk_len: number(&header, 40),
        disk_hash: header[112..144].try_into().unwrap(),
    })
}

pub(super) fn seal(
    file: &File,
    metadata_len: u64,
    payload: u64,
    disk_len: u64,
    disk_hash: [u8; 32],
) -> Result<()> {
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
    header[48..80].copy_from_slice(&digest(file, HEADER, metadata_len)?);
    header[80..112].copy_from_slice(&digest(file, HEADER + metadata_len, payload)?);
    header[112..144].copy_from_slice(&disk_hash);
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
        seal(&file, 3, 7, 1234, [17; 32]).unwrap();
        file
    }
    #[test]
    fn snapshot_v9_envelope_integrity() {
        let file = image();
        let decoded = read(&file).unwrap();
        assert_eq!(decoded.metadata, b"{}\n");
        assert_eq!(
            (decoded.payload, decoded.disk_len, decoded.disk_hash),
            (7, 1234, [17; 32])
        );
        for offset in [HEADER, HEADER + 3] {
            let file = image();
            file.write_all_at(b"!", offset).unwrap();
            assert!(read(&file).unwrap_err().to_string().contains("checksum"));
        }
    }
    #[test]
    fn snapshot_v9_envelope_bounds_and_old_versions() {
        for version in [1u32, 7, 8, 10] {
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
    }
}
