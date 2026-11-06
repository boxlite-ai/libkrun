// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

mod pages;

const COPY_CHUNK: usize = 1024 * 1024;

/// Writers must be frozen throughout the query and copy. Only private anonymous
/// mappings can omit pages without consulting a backing object. Failed queries
/// fall back to copying, never to assuming that a page is empty.
pub(crate) fn save_file(memory: &GuestMemoryMmap, file: &mut File) -> io::Result<()> {
    let mut header = Vec::from(MAGIC.as_slice());
    header.extend_from_slice(&VERSION.to_le_bytes());
    let count = u32::try_from(memory.num_regions()).map_err(|_| invalid("too many RAM regions"))?;
    header.extend_from_slice(&count.to_le_bytes());
    let mut total = HEADER_LEN + u64::from(count) * REGION_LEN;
    for region in memory.iter() {
        if region.prot() & libc::PROT_READ == 0 {
            return Err(invalid("RAM mapping is not readable"));
        }
        total = total
            .checked_add(region.len())
            .ok_or_else(|| invalid("RAM length overflow"))?;
        header.extend_from_slice(&region.start_addr().raw_value().to_le_bytes());
        header.extend_from_slice(&region.len().to_le_bytes());
        header.extend_from_slice(&0u64.to_le_bytes());
    }
    // Truncate first, so reusing a file cannot leave old data inside a new hole.
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.set_len(total)?;
    // SAFETY: sysconf has no pointer arguments or side effects on mappings.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let page_size = page_size as usize;
    let mut buffer = vec![0; COPY_CHUNK];
    let mut file_offset = header.len() as u64;
    for region in memory.iter() {
        let len = region.len() as usize;
        let allocated = if region.file_offset().is_none()
            && region.flags() & libc::MAP_ANONYMOUS != 0
            && region.flags() & libc::MAP_PRIVATE != 0
        {
            pages::allocated(region.as_ptr() as usize, len, page_size).ok()
        } else {
            None
        };
        let mut offset = 0;
        while offset < len {
            if allocated
                .as_ref()
                .is_some_and(|bits| !bits[offset / page_size])
            {
                offset = (offset + page_size).min(len);
                continue;
            }
            let start = offset;
            while offset < len
                && offset - start < COPY_CHUNK
                && allocated
                    .as_ref()
                    .is_none_or(|bits| bits[offset / page_size])
            {
                offset = (offset + page_size).min(len);
            }
            let bytes = &mut buffer[..offset - start];
            memory
                .read_slice(
                    bytes,
                    GuestAddress(region.start_addr().raw_value() + start as u64),
                )
                .map_err(io::Error::other)?;
            file.write_all_at(bytes, file_offset + start as u64)?;
        }
        file_offset += region.len();
    }
    Ok(())
}

pub(crate) fn file_metadata(file: &mut File) -> io::Result<Metadata> {
    file.seek(SeekFrom::Start(0))?;
    read_metadata(file, file.metadata()?.len())
}

/// Eagerly load every data extent into fresh anonymous RAM. File holes remain
/// demand-zero anonymous pages; there is no file mapping or deferred data load.
/// The caller validates the layout/resource budget before invoking this method.
pub(crate) fn restore_file(file: &File, metadata: &Metadata) -> io::Result<GuestMemoryMmap> {
    let ranges: Vec<_> = metadata
        .regions
        .iter()
        .map(|r| (GuestAddress(r.gpa), r.len as usize))
        .collect();
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(io::Error::other)?;
    let mut buffer = vec![0; COPY_CHUNK];
    let mut base = HEADER_LEN + metadata.regions.len() as u64 * REGION_LEN;
    for region in &metadata.regions {
        let end = base + region.len;
        let mut cursor = base;
        while cursor < end {
            let Some((start, stop)) = data_extent(file, cursor, end)? else {
                break;
            };
            cursor = start;
            while cursor < stop {
                let size = (stop - cursor).min(COPY_CHUNK as u64) as usize;
                file.read_exact_at(&mut buffer[..size], cursor)?;
                memory
                    .write_slice(&buffer[..size], GuestAddress(region.gpa + cursor - base))
                    .map_err(io::Error::other)?;
                cursor += size as u64;
            }
        }
        base = end;
    }
    if file.metadata()?.len() != base {
        return Err(invalid("RAM image length changed during import"));
    }
    Ok(memory)
}

fn data_extent(file: &File, start: u64, end: u64) -> io::Result<Option<(u64, u64)>> {
    // SAFETY: file owns the fd, and callers restrict offsets to the file's range.
    let data = unsafe { libc::lseek(file.as_raw_fd(), start as libc::off_t, libc::SEEK_DATA) };
    if data < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENXIO) => Ok(None),
            Some(libc::EINVAL) | Some(libc::ENOTSUP) => Ok(Some((start, end))),
            _ => Err(error),
        };
    }
    if data as u64 >= end {
        return Ok(None);
    }
    // SAFETY: data is a valid offset returned for this fd above.
    let hole = unsafe { libc::lseek(file.as_raw_fd(), data, libc::SEEK_HOLE) };
    if hole < 0 {
        return Err(io::Error::last_os_error());
    }
    if (data as u64) < start || hole <= data {
        return Err(invalid("invalid sparse RAM extent"));
    }
    Ok(Some((data as u64, (hole as u64).min(end))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use utils::tempfile::TempFile;
    use vm_memory::FileOffset;

    #[test]
    fn unallocated_pages_stay_sparse_and_allocated_zero_pages_are_kept() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let size = 32 * 1024 * 1024;
        let memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size), (GuestAddress(1 << 32), size)])
                .unwrap();
        let pattern: Vec<_> = (0..page).map(|i| (i % 251 + 1) as u8).collect();
        memory
            .write_slice(&pattern, GuestAddress(page as u64))
            .unwrap();
        let zero_offset = 8 * 1024 * 1024;
        memory
            .write_slice(&vec![0; page], GuestAddress(zero_offset))
            .unwrap();
        memory
            .write_slice(&pattern, GuestAddress((1 << 32) + (size - page) as u64))
            .unwrap();
        let region = memory.iter().next().unwrap();
        let before = pages::allocated(region.as_ptr() as usize, size, page).unwrap();
        assert!(before[1]);
        assert!(before[zero_offset as usize / page]);
        assert!(!before[size / 2 / page]);

        let snapshot = TempFile::new().unwrap();
        let mut file = snapshot.as_file().try_clone().unwrap();
        // An old allocation inside a new hole must not survive reuse.
        file.write_all_at(b"old data", (size / 2) as u64).unwrap();
        save_file(&memory, &mut file).unwrap();
        let length = 16 + 2 * 24 + size as u64 * 2;
        assert_eq!(file.metadata().unwrap().len(), length);
        assert!(file.metadata().unwrap().blocks() * 512 < length / 4);
        let after = pages::allocated(region.as_ptr() as usize, size, page).unwrap();
        assert!(
            !after[size / 2 / page],
            "export faulted in an unallocated page"
        );

        let layout = file_metadata(&mut file).unwrap();
        let restored = restore_file(&file, &layout).unwrap();
        let region = restored.iter().next().unwrap();
        assert!(region.file_offset().is_none());
        let loaded = pages::allocated(region.as_ptr() as usize, size, page).unwrap();
        assert!(
            loaded[zero_offset as usize / page],
            "allocated zero page was omitted"
        );
        assert!(!loaded[size / 2 / page], "restore materialized a file hole");
        let mut actual = vec![0; page];
        restored
            .read_slice(&mut actual, GuestAddress(page as u64))
            .unwrap();
        assert_eq!(actual, pattern);
        restored
            .read_slice(&mut actual, GuestAddress((1 << 32) + (size - page) as u64))
            .unwrap();
        assert_eq!(actual, pattern);
        assert_eq!(
            restored
                .read_obj::<u64>(GuestAddress((size / 2) as u64))
                .unwrap(),
            0
        );
        // Sparse storage retains the existing RAM codec's logical byte format.
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, super::super::save(&memory).unwrap());
    }

    #[test]
    fn file_backed_pages_are_copied_even_when_not_faulted_in() {
        let backing = TempFile::new().unwrap();
        let size = 1024 * 1024;
        backing.as_file().set_len(size).unwrap();
        backing
            .as_file()
            .write_all_at(b"backing data", 65536)
            .unwrap();
        let memory = GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(0),
            size as usize,
            Some(FileOffset::new(backing.as_file().try_clone().unwrap(), 0)),
        )])
        .unwrap();
        let snapshot = TempFile::new().unwrap();
        let mut file = snapshot.as_file().try_clone().unwrap();
        save_file(&memory, &mut file).unwrap();
        let layout = file_metadata(&mut file).unwrap();
        let restored = restore_file(&file, &layout).unwrap();
        let mut bytes = [0; 12];
        restored
            .read_slice(&mut bytes, GuestAddress(65536))
            .unwrap();
        assert_eq!(&bytes, b"backing data");
    }
}
