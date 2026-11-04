// SPDX-License-Identifier: Apache-2.0

//! RAM-only images, not runnable VM checkpoints or a stable external format.
//!
//! The caller must stop all writers (vCPUs, devices and other memory aliases)
//! for the entire save. Only owned, private anonymous RAM is supported. This
//! codec neither discovers mappings outside `memory` nor freezes their owners.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

const MAGIC: &[u8; 8] = b"KRUNRAM\0";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 16;
const REGION_LEN: u64 = 24;
const PAGE_SIZE: u64 = 4096;
const CHUNK_SIZE: usize = 64 * 1024;

struct Region {
    gpa: u64,
    len: u64,
    attributes: u64,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn validate_regions(
    regions: &[Region],
    max_regions: usize,
    max_memory_bytes: u64,
) -> io::Result<u64> {
    if regions.is_empty() || regions.len() > max_regions || regions.len() > u32::MAX as usize {
        return Err(invalid("invalid RAM region count"));
    }
    let mut memory_bytes = 0u64;
    let mut previous_end = 0;
    for region in regions {
        if region.len == 0
            || region.gpa & (PAGE_SIZE - 1) != 0
            || region.len & (PAGE_SIZE - 1) != 0
            || region.len > isize::MAX as u64
            || region.attributes != 0
        {
            return Err(invalid(
                "unsupported RAM region length, alignment or attributes",
            ));
        }
        let end = region
            .gpa
            .checked_add(region.len)
            .ok_or_else(|| invalid("RAM address overflow"))?;
        if region.gpa < previous_end {
            return Err(invalid("overlapping or unordered RAM regions"));
        }
        memory_bytes = memory_bytes
            .checked_add(region.len)
            .ok_or_else(|| invalid("RAM length overflow"))?;
        previous_end = end;
    }
    if memory_bytes > max_memory_bytes {
        return Err(invalid("RAM image exceeds memory budget"));
    }
    // The count is bounded by u32::MAX above, so the table fits in u64.
    (HEADER_LEN + regions.len() as u64 * REGION_LEN)
        .checked_add(memory_bytes)
        .ok_or_else(|| invalid("RAM image length overflow"))
}

fn memory_regions(memory: &GuestMemoryMmap) -> io::Result<Vec<Region>> {
    memory
        .iter()
        .map(|region| {
            let required = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            if !region.owned()
                || region.file_offset().is_some()
                || region.flags() & required != required
                || region.flags() & !(required | libc::MAP_NORESERVE) != 0
                || region.prot() != libc::PROT_READ | libc::PROT_WRITE
            {
                return Err(invalid("RAM image requires owned private anonymous memory"));
            }
            Ok(Region {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
                attributes: 0,
            })
        })
        .collect()
}

struct PendingImage {
    file: File,
    path: PathBuf,
    complete: bool,
}

impl PendingImage {
    fn create(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
            path: path.to_owned(),
            complete: false,
        })
    }

    fn finish(mut self) -> io::Result<()> {
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(MAGIC)?;
        self.file.sync_all()?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for PendingImage {
    fn drop(&mut self) {
        if !self.complete {
            // Invalidate even a partially failed finalization before unlinking.
            let _ = self.file.seek(SeekFrom::Start(0));
            let _ = self.file.write_all(&[0; 8]);
            let _ = self.file.sync_all();
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Save quiescent RAM to a new mode-0600 file; never overwrite an existing path.
///
/// The caller must keep the destination path exclusively owned during this
/// operation. Ordinary I/O failures trigger best-effort invalidation/removal.
/// The magic is written last, after the table and payload have been synced.
/// This does not provide directory crash durability or payload checksums.
pub fn save(path: &Path, memory: &GuestMemoryMmap) -> io::Result<()> {
    let regions = memory_regions(memory)?;
    validate_regions(&regions, regions.len(), u64::MAX)?;
    let mut pending = PendingImage::create(path)?;
    let file = &mut pending.file;
    file.write_all(&[0; 8])?;
    file.write_all(&VERSION.to_le_bytes())?;
    file.write_all(&(regions.len() as u32).to_le_bytes())?;
    for region in &regions {
        file.write_all(&region.gpa.to_le_bytes())?;
        file.write_all(&region.len.to_le_bytes())?;
        file.write_all(&region.attributes.to_le_bytes())?;
    }
    let mut buffer = [0; CHUNK_SIZE];
    for region in &regions {
        let mut offset = 0;
        while offset < region.len {
            let count = (region.len - offset).min(CHUNK_SIZE as u64) as usize;
            memory
                .read_slice(&mut buffer[..count], GuestAddress(region.gpa + offset))
                .map_err(io::Error::other)?;
            file.write_all(&buffer[..count])?;
            offset += count as u64;
        }
    }
    pending.finish()
}

fn read_regions(
    file: &mut File,
    max_regions: usize,
    max_memory_bytes: u64,
) -> io::Result<Vec<Region>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("RAM image must be a regular file"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0; HEADER_LEN as usize];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(invalid("invalid or incomplete RAM image"));
    }
    if u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION {
        return Err(invalid("unsupported RAM image version"));
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > max_regions {
        return Err(invalid("RAM region count exceeds target limit or is zero"));
    }
    if HEADER_LEN + count as u64 * REGION_LEN > metadata.len() {
        return Err(invalid("truncated RAM region table"));
    }
    let mut regions = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = [0; REGION_LEN as usize];
        file.read_exact(&mut entry)?;
        regions.push(Region {
            gpa: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            len: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            attributes: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        });
    }
    if validate_regions(&regions, max_regions, max_memory_bytes)? != metadata.len() {
        return Err(invalid("RAM image length differs from region table"));
    }
    Ok(regions)
}

/// Load independent anonymous RAM, checking the entire layout before allocation.
///
/// `max_regions` and `max_memory_bytes` are caller-supplied resource limits,
/// not values trusted from the image. The caller must prevent file mutation
/// during restore. Reading starts at offset zero and advances the file cursor.
/// No CPU/device state is restored and no guest execution is started.
pub fn restore(
    file: &mut File,
    max_regions: usize,
    max_memory_bytes: u64,
) -> io::Result<GuestMemoryMmap> {
    let regions = read_regions(file, max_regions, max_memory_bytes)?;
    let ranges: Vec<_> = regions
        .iter()
        .map(|r| (GuestAddress(r.gpa), r.len as usize))
        .collect();
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(io::Error::other)?;
    let mut buffer = [0; CHUNK_SIZE];
    for region in &regions {
        let mut offset = 0;
        while offset < region.len {
            let count = (region.len - offset).min(CHUNK_SIZE as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            memory
                .write_slice(&buffer[..count], GuestAddress(region.gpa + offset))
                .map_err(io::Error::other)?;
            offset += count as u64;
        }
    }
    Ok(memory)
}

#[cfg(test)]
mod tests;
