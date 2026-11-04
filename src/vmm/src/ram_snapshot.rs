// SPDX-License-Identifier: Apache-2.0

//! RAM-only images, not runnable VM checkpoints or a stable external format.
//!
//! The caller must stop all writers (vCPUs, devices and other memory aliases)
//! for the entire save. Only owned, private anonymous RAM is supported. This
//! codec neither discovers mappings outside `memory` nor freezes their owners.

use std::io::{self, Read};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

const MAGIC: &[u8; 8] = b"KRUNRAM\0";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 16;
const REGION_LEN: u64 = 24;
const PAGE_SIZE: u64 = 4096;

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

/// Encode quiescent RAM as one contiguous image owned by the caller.
///
/// The returned bytes include the header, region table and RAM payload. Storage
/// and publication belong to the caller. This allocates an image roughly as large
/// as guest RAM; all RAM writers must stay stopped until the copy completes.
pub fn save(memory: &GuestMemoryMmap) -> io::Result<Vec<u8>> {
    let regions = memory_regions(memory)?;
    let len = validate_regions(&regions, regions.len(), u64::MAX)?;
    let len = usize::try_from(len).map_err(|_| invalid("RAM image exceeds host address space"))?;
    let mut image = Vec::new();
    image.try_reserve_exact(len).map_err(io::Error::other)?;
    image.extend_from_slice(MAGIC);
    image.extend_from_slice(&VERSION.to_le_bytes());
    image.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    for region in &regions {
        image.extend_from_slice(&region.gpa.to_le_bytes());
        image.extend_from_slice(&region.len.to_le_bytes());
        image.extend_from_slice(&region.attributes.to_le_bytes());
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

fn read_regions(
    image: &[u8],
    max_regions: usize,
    max_memory_bytes: u64,
) -> io::Result<Vec<Region>> {
    let mut reader = image;
    let mut header = [0; HEADER_LEN as usize];
    reader.read_exact(&mut header)?;
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
    if HEADER_LEN + count as u64 * REGION_LEN > image.len() as u64 {
        return Err(invalid("truncated RAM region table"));
    }
    let mut regions = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = [0; REGION_LEN as usize];
        reader.read_exact(&mut entry)?;
        regions.push(Region {
            gpa: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            len: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            attributes: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        });
    }
    if validate_regions(&regions, max_regions, max_memory_bytes)? != image.len() as u64 {
        return Err(invalid("RAM image length differs from region table"));
    }
    Ok(regions)
}

/// Load independent anonymous RAM, checking the entire layout before allocation.
///
/// `max_regions` and `max_memory_bytes` are caller-supplied resource limits,
/// not values trusted from the image. The borrowed image is copied into new
/// guest RAM and can be released after this call. No CPU/device state is
/// restored and no guest execution is started.
pub fn restore(
    image: &[u8],
    max_regions: usize,
    max_memory_bytes: u64,
) -> io::Result<GuestMemoryMmap> {
    let regions = read_regions(image, max_regions, max_memory_bytes)?;
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
