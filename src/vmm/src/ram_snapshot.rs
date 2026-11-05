// SPDX-License-Identifier: Apache-2.0

//! RAM-only images, not runnable VM checkpoints or a stable external format.
//!
//! The caller must stop all writers (vCPUs, devices and other memory aliases)
//! for the entire save. Mappings are copied as bytes and restored as anonymous
//! RAM. The caller can inspect `get_metadata` before deciding whether to restore.

use std::io::{self, Read};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

const MAGIC: &[u8; 8] = b"KRUNRAM\0";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 16;
const REGION_LEN: u64 = 24;

/// A guest RAM region described by an image.
#[derive(Debug, PartialEq, Eq)]
pub struct Region {
    pub gpa: u64,
    pub len: u64,
}

/// Image information for caller-defined resource and platform checks.
#[derive(Debug, PartialEq, Eq)]
pub struct Metadata {
    pub version: u32,
    /// Total RAM payload bytes, excluding address-space gaps and image headers.
    pub memory_bytes: u64,
    pub regions: Vec<Region>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn memory_bytes(regions: &[Region]) -> io::Result<u64> {
    regions.iter().try_fold(0u64, |total, region| {
        total
            .checked_add(region.len)
            .ok_or_else(|| invalid("RAM length overflow"))
    })
}

/// Encode quiescent RAM as one contiguous image owned by the caller.
///
/// The returned bytes include the header, region table and RAM payload. Storage
/// and publication belong to the caller. This allocates an image roughly as large
/// as guest RAM; all RAM writers must stay stopped until the copy completes.
pub fn save(memory: &GuestMemoryMmap) -> io::Result<Vec<u8>> {
    let regions = memory
        .iter()
        .map(|region| {
            if region.prot() & libc::PROT_READ == 0 {
                return Err(invalid("RAM mapping is not readable"));
            }
            Ok(Region {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let count = u32::try_from(regions.len()).map_err(|_| invalid("RAM region count overflow"))?;
    let len = (HEADER_LEN + u64::from(count) * REGION_LEN)
        .checked_add(memory_bytes(&regions)?)
        .ok_or_else(|| invalid("RAM image length overflow"))?;
    let len = usize::try_from(len).map_err(|_| invalid("RAM image exceeds host address space"))?;
    let mut image = Vec::new();
    image.try_reserve_exact(len).map_err(io::Error::other)?;
    image.extend_from_slice(MAGIC);
    image.extend_from_slice(&VERSION.to_le_bytes());
    image.extend_from_slice(&count.to_le_bytes());
    for region in &regions {
        image.extend_from_slice(&region.gpa.to_le_bytes());
        image.extend_from_slice(&region.len.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
    }
    let mut offset = image.len();
    image.resize(len, 0);
    for region in &regions {
        let end = offset + region.len as usize;
        memory
            .read_slice(&mut image[offset..end], GuestAddress(region.gpa))
            .map_err(io::Error::other)?;
        offset = end;
    }
    Ok(image)
}

/// Decode image metadata without allocating guest RAM or applying resource limits.
///
/// Checks only the encoding: header/version, reserved fields, arithmetic and
/// payload length. Region count, RAM budget and platform layout policy belong
/// to the caller. Region addresses are reported as encoded.
pub fn get_metadata(image: &[u8]) -> io::Result<Metadata> {
    let mut reader = image;
    let mut header = [0; HEADER_LEN as usize];
    reader.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(invalid("invalid or incomplete RAM image"));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(invalid("unsupported RAM image version"));
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if HEADER_LEN + count as u64 * REGION_LEN > image.len() as u64 {
        return Err(invalid("truncated RAM region table"));
    }
    let mut regions = Vec::new();
    regions.try_reserve_exact(count).map_err(io::Error::other)?;
    for _ in 0..count {
        let mut entry = [0; REGION_LEN as usize];
        reader.read_exact(&mut entry)?;
        if entry[16..24] != [0; 8] {
            return Err(invalid("unsupported RAM attributes"));
        }
        regions.push(Region {
            gpa: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            len: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
        });
    }
    let memory_bytes = memory_bytes(&regions)?;
    if memory_bytes != image.len() as u64 - HEADER_LEN - count as u64 * REGION_LEN {
        return Err(invalid("RAM image length differs from region table"));
    }
    Ok(Metadata {
        version,
        memory_bytes,
        regions,
    })
}

/// Copy an image into independent anonymous guest RAM.
///
/// Call `get_metadata` first if resource or platform checks are needed. This
/// function applies no such policy; invalid guest mappings are reported by the
/// memory allocator. The image can be released after this call. No CPU/device
/// state is restored and no guest execution is started.
pub fn restore(image: &[u8]) -> io::Result<GuestMemoryMmap> {
    let metadata = get_metadata(image)?;
    let regions = metadata.regions;
    let ranges: Vec<_> = regions
        .iter()
        .map(|r| (GuestAddress(r.gpa), r.len as usize))
        .collect();
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(io::Error::other)?;
    let mut payload = &image[HEADER_LEN as usize + regions.len() * REGION_LEN as usize..];
    for region in &regions {
        let (bytes, remaining) = payload.split_at(region.len as usize);
        memory
            .write_slice(bytes, GuestAddress(region.gpa))
            .map_err(io::Error::other)?;
        payload = remaining;
    }
    Ok(memory)
}

#[cfg(test)]
mod tests;
