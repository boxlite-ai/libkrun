// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use super::passthrough::checkpoint::Object;
use crate::virtio::persist::invalid;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaxMappingState {
    pub offset: u64,
    pub len: u64,
    pub file_offset: u64,
    pub writable: bool,
    // None is the synthetic init.krun file, reconstructed from this library.
    pub object: Option<Object>,
    pub file_size: u64,
}

impl DaxMappingState {
    pub fn validate(&self, window_size: u64) -> io::Result<()> {
        validate_range(self.offset, self.len, window_size)?;
        if !self.file_offset.is_multiple_of(page_size())
            || self
                .file_offset
                .checked_add(self.len)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(invalid("invalid DAX file range"));
        }
        if let Some(object) = &self.object {
            object.validate()?;
            if object.kind != libc::S_IFREG as u32 {
                return Err(invalid("DAX backing object is not a regular file"));
            }
        }
        Ok(())
    }
}

pub fn validate_states(states: &[DaxMappingState], size: u64) -> io::Result<()> {
    let mut end = 0;
    for state in states {
        state.validate(size)?;
        if state.offset < end {
            return Err(invalid("overlapping or unsorted DAX mappings"));
        }
        end = state.offset + state.len;
    }
    Ok(())
}

fn page_size() -> u64 {
    // Supported hosts always provide a positive page size.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn validate_range(offset: u64, len: u64, size: u64) -> io::Result<()> {
    if len == 0
        || !offset.is_multiple_of(page_size())
        || !len.is_multiple_of(page_size())
        || offset.checked_add(len).is_none_or(|end| end > size)
    {
        return Err(invalid("invalid DAX window range"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct HostMapping {
    address: u64,
    len: u64,
}
#[cfg(target_os = "macos")]
impl Drop for HostMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.address as *mut libc::c_void, self.len as usize);
        }
    }
}

#[derive(Clone)]
struct Mapping {
    offset: u64,
    len: u64,
    file_offset: u64,
    writable: bool,
    file: Option<Arc<File>>,
    #[cfg(target_os = "macos")]
    backing: Arc<HostMapping>,
}

#[derive(Default)]
pub(super) struct DaxMappings {
    mappings: BTreeMap<u64, Mapping>,
    base: Option<u64>,
    failed: bool,
}

impl DaxMappings {
    // base is the host window on KVM and the guest window on HVF.
    #[allow(clippy::too_many_arguments)]
    pub fn map(
        &mut self,
        base: u64,
        size: u64,
        offset: u64,
        len: u64,
        file_offset: u64,
        writable: bool,
        file: Option<File>,
        init: &[u8],
    ) -> io::Result<()> {
        validate_range(offset, len, size)?;
        if self.failed
            || base.checked_add(size).is_none()
            || self.base.is_some_and(|previous| previous != base)
            || !file_offset.is_multiple_of(page_size())
            || file_offset
                .checked_add(len)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(invalid("invalid DAX mapping state"));
        }
        self.base = Some(base);
        let prot = libc::PROT_READ
            | if writable || file.is_none() {
                libc::PROT_WRITE
            } else {
                0
            };
        let flags = if file.is_some() {
            libc::MAP_SHARED
        } else {
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
        };
        // HVF pins shared file pages with host write access even when the
        // guest mapping is read-only. Callers open backing files O_RDWR on
        // macOS; stage-2 permissions below still enforce the guest's access.
        // MAP_PRIVATE would lose coherence with writes through the host file.
        #[cfg(target_os = "macos")]
        let prot = prot | libc::PROT_WRITE;
        #[cfg(target_os = "linux")]
        let (address, flags) = (
            (base + offset) as *mut libc::c_void,
            flags | libc::MAP_FIXED,
        );
        #[cfg(target_os = "macos")]
        let address = std::ptr::null_mut();
        // The owner supplies an allocated window on Linux; range checks keep
        // MAP_FIXED inside it. HVF uses a separately owned host allocation.
        let address = unsafe {
            libc::mmap(
                address,
                len as usize,
                prot,
                flags,
                file.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                if file.is_some() {
                    file_offset as libc::off_t
                } else {
                    0
                },
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if file.is_none() {
            let start = (file_offset as usize).min(init.len());
            let bytes = &init[start..init.len().min(start.saturating_add(len as usize))];
            // Anonymous mappings are writable and bytes never exceeds len.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.cast::<u8>(), bytes.len());
            }
        }
        #[cfg(target_os = "macos")]
        let backing = {
            let backing = Arc::new(HostMapping {
                address: address as u64,
                len,
            });
            // HVF's VM is process-wide. Mapping here avoids waiting on the VMM
            // mutex while its owner waits for this filesystem worker to freeze.
            let _ = hvf::unmap_memory(base + offset, len);
            if let Err(error) = hvf::map_memory(address as u64, base + offset, len, writable) {
                self.failed = true;
                return Err(io::Error::other(format!("DAX map: {error:?}")));
            }
            backing
        };
        self.erase(offset, len);
        self.mappings.insert(
            offset,
            Mapping {
                offset,
                len,
                file_offset,
                writable,
                file: file.map(Arc::new),
                #[cfg(target_os = "macos")]
                backing,
            },
        );
        Ok(())
    }

    // Keep both sides of partial removals, including the adjusted file offset.
    fn erase(&mut self, offset: u64, len: u64) {
        let end = offset + len;
        let affected: Vec<_> = self
            .mappings
            .range(..end)
            .filter(|(_, m)| m.offset + m.len > offset)
            .map(|(&k, _)| k)
            .collect();
        for key in affected {
            let mapping = self.mappings.remove(&key).unwrap();
            let old_end = mapping.offset + mapping.len;
            if mapping.offset < offset {
                let mut left = mapping.clone();
                left.len = offset - left.offset;
                self.mappings.insert(left.offset, left);
            }
            if old_end > end {
                let mut right = mapping;
                right.file_offset += end - right.offset;
                right.offset = end;
                right.len = old_end - end;
                self.mappings.insert(end, right);
            }
        }
    }

    pub fn remove(&mut self, base: u64, size: u64, offset: u64, len: u64) -> io::Result<()> {
        validate_range(offset, len, size)?;
        if self.failed
            || self.base.is_some_and(|previous| previous != base)
            || base.checked_add(size).is_none()
        {
            return Err(invalid("invalid DAX window"));
        }
        #[cfg(target_os = "linux")]
        if unsafe {
            libc::mmap(
                (base + offset) as *mut libc::c_void,
                len as usize,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        } == libc::MAP_FAILED
        {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "macos")]
        {
            // Unmap only live intersections; the requested range may include holes.
            for mapping in self.mappings.values() {
                let start = offset.max(mapping.offset);
                let end = (offset + len).min(mapping.offset + mapping.len);
                if start < end {
                    if let Err(error) = hvf::unmap_memory(base + start, end - start) {
                        self.failed = true;
                        return Err(io::Error::other(format!("DAX unmap: {error:?}")));
                    }
                }
            }
        }
        self.erase(offset, len);
        Ok(())
    }

    pub fn capture(&self, root: &Path) -> io::Result<Vec<DaxMappingState>> {
        if self.failed {
            return Err(invalid("DAX mapping outcome unknown"));
        }
        self.mappings
            .values()
            .map(|m| {
                let (object, file_size) = if let Some(file) = &m.file {
                    if m.writable {
                        file.sync_all()?;
                    }
                    (Some(Object::capture(file, root)?), file.metadata()?.len())
                } else {
                    (None, 0)
                };
                Ok(DaxMappingState {
                    offset: m.offset,
                    len: m.len,
                    file_offset: m.file_offset,
                    writable: m.writable,
                    object,
                    file_size,
                })
            })
            .collect()
    }

    pub fn restore(
        &mut self,
        states: &[DaxMappingState],
        root: &File,
        base: u64,
        size: u64,
        init: &[u8],
        read_only: bool,
    ) -> io::Result<()> {
        validate_states(states, size)?;
        for state in states {
            if read_only && state.writable {
                return Err(invalid("writable DAX mapping on read-only share"));
            }
            let file = state
                .object
                .as_ref()
                .map(|object| object.reopen_mapping(root, state.writable))
                .transpose()?;
            if let Some(file) = &file {
                if file.metadata()?.len() < state.file_size.min(state.file_offset + state.len) {
                    return Err(invalid("DAX backing file was truncated"));
                }
            }
            self.map(
                base,
                size,
                state.offset,
                state.len,
                state.file_offset,
                state.writable,
                file,
                init,
            )?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for DaxMappings {
    fn drop(&mut self) {
        if let Some(base) = self.base {
            for m in self.mappings.values() {
                let _ = hvf::unmap_memory(base + m.offset, m.len);
                // Backing remains pinned through the hypervisor unmap.
                let _ = &m.backing;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

    #[test]
    fn snapshot_dax_partial_unmap_restore_and_changed_backing() {
        let dir = utils::tempdir::TempDir::new().unwrap();
        let root_path = std::fs::canonicalize(dir.as_path()).unwrap();
        let path = root_path.join("mapped");
        let page = page_size();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(4 * page).unwrap();
        file.write_all_at(b"first", page).unwrap();
        file.write_all_at(b"LIVE", 3 * page).unwrap();
        let memory = GuestMemoryMmap::<()>::from_ranges(&[(
            GuestAddress(0x8_0000_0000),
            (4 * page) as usize,
        )])
        .unwrap();
        let host = memory
            .get_host_address(GuestAddress(0x8_0000_0000))
            .unwrap() as u64;
        #[cfg(target_os = "linux")]
        let base = host;
        #[cfg(target_os = "macos")]
        let vm = hvf::HvfVm::new(false).unwrap();
        #[cfg(target_os = "macos")]
        let base = {
            vm.map_memory(host, 0x8_0000_0000, 4 * page).unwrap();
            0x8_0000_0000
        };
        let mut source = DaxMappings::default();
        source
            .map(
                base,
                4 * page,
                0,
                3 * page,
                page,
                true,
                Some(file.try_clone().unwrap()),
                &[],
            )
            .unwrap();
        #[cfg(target_os = "linux")]
        let address = host;
        #[cfg(target_os = "macos")]
        let address = source.mappings[&0].backing.address;
        unsafe {
            *(address as *mut u8) = b'F';
        }
        source.remove(base, 4 * page, page, page).unwrap();
        source
            .map(
                base,
                4 * page,
                3 * page,
                page,
                0,
                false,
                Some(file.try_clone().unwrap()),
                &[],
            )
            .unwrap();
        let saved = source.capture(&root_path).unwrap();
        assert_eq!(saved.len(), 3);
        assert!(!saved[2].writable);
        assert_eq!(
            (saved[1].offset, saved[1].file_offset, saved[1].len),
            (2 * page, 3 * page, page)
        );
        let mut bytes = [0; 5];
        file.read_exact_at(&mut bytes, page).unwrap();
        assert_eq!(&bytes, b"First");
        source.remove(base, 4 * page, 0, 4 * page).unwrap();
        drop(source);
        // Changes made while the VM is absent remain visible through DAX.
        if saved[0].object.as_ref().unwrap().birth_time {
            file.write_all_at(b"LIVE", 3 * page).unwrap();
        }
        let root = File::open(&root_path).unwrap();
        let mut restored = DaxMappings::default();
        restored
            .restore(&saved, &root, base, 4 * page, &[], false)
            .unwrap();
        #[cfg(target_os = "linux")]
        let address = base + 2 * page;
        #[cfg(target_os = "macos")]
        let address = restored.mappings[&(2 * page)].backing.address;
        assert_eq!(
            unsafe { std::slice::from_raw_parts(address as *const u8, 4) },
            b"LIVE"
        );
        unsafe {
            *(address as *mut u8) = b'R';
        }
        let mut bytes = [0; 4];
        file.read_exact_at(&mut bytes, 3 * page).unwrap();
        assert_eq!(&bytes, b"RIVE");
        #[cfg(target_os = "linux")]
        let readonly_address = base + 3 * page;
        #[cfg(target_os = "macos")]
        let readonly_address = restored.mappings[&(3 * page)].backing.address;
        file.write_all_at(b"READ", 0).unwrap();
        assert_eq!(
            unsafe { std::slice::from_raw_parts(readonly_address as *const u8, 4) },
            b"READ"
        );
        let again = restored.capture(&root_path).unwrap();
        assert_eq!(again.len(), 3);
        restored.remove(base, 4 * page, 0, 4 * page).unwrap();
        assert!(restored
            .restore(&saved, &root, base, 4 * page, &[], true)
            .is_err());
        file.set_len(page).unwrap();
        assert!(restored
            .restore(&saved, &root, base, 4 * page, &[], false)
            .is_err());
        file.set_len(4 * page).unwrap();
        std::fs::rename(&path, root_path.join("old")).unwrap();
        std::fs::write(&path, vec![0; (4 * page) as usize]).unwrap();
        assert!(restored
            .restore(&saved, &root, base, 4 * page, &[], false)
            .is_err());
        let mut invalid = saved.clone();
        invalid[1].offset = 0;
        assert!(validate_states(&invalid, 4 * page).is_err());
        invalid[1].offset = u64::MAX;
        assert!(validate_states(&invalid, 4 * page).is_err());
    }
}
