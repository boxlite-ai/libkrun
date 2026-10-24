// SPDX-License-Identifier: Apache-2.0

//! DAX window ledger of a snapshot-mode passthrough share.
//!
//! FUSE_SETUPMAPPING and FUSE_REMOVEMAPPING replace parts of the share's DAX
//! window with host mappings. A snapshot-mode share records each replacement
//! only after its host mapping succeeded, so the ledger partitions the window
//! exactly as the host maps it, in three kinds of segment:
//! - file: a `MAP_SHARED` view of a host object from a file offset,
//!   read-only or writable. The segment keeps the descriptor it was mapped
//!   with, so an object the guest only maps (its node forgotten, its name
//!   unlinked) stays capturable;
//! - anonymous: private memory, read-write for the window's initial state,
//!   with the requested access for an init.krun copy (its bytes from the
//!   requested file offset). A checkpoint carries their nonzero 4 KiB
//!   pages, so modified init.krun bytes survive;
//! - hole: the `PROT_NONE` memory FUSE_REMOVEMAPPING leaves.
//!
//! An overlapping setup or a partial removal cuts the segments it overlaps;
//! the rest of a cut file segment keeps the file offset of each byte.
//! Capturing reads only window memory, never a host object, so it leaves
//! every source atime alone.
//!
//! Requests the host would refuse up front are refused before any host
//! call. A host mapping call that still fails may have changed part of its
//! range (`MAP_FIXED` can unmap the old range and then fail, `mprotect` can
//! stop part way), so the window is lost: every later mapping request,
//! sync and capture fails without touching window memory, and the owner
//! discards the share.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::{Arc, Weak};

use serde::{Deserialize, Serialize};

use super::snapshot::ObjectTable;
use super::{einval, fuse, statx, Inode, PassthroughFs, PassthroughSnapshotError};

/// Granularity of the anonymous data a checkpoint carries.
pub const DAX_PAGE_SIZE: u64 = 4096;

/// Where a share's DAX window lives in this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaxWindow {
    pub host_addr: u64,
    pub size: u64,
}

/// What one part of the window maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DaxMappingKind {
    /// A shared view of checkpoint object `object` from file offset
    /// `foffset`.
    File {
        object: u64,
        foffset: u64,
        writable: bool,
    },
    /// Private memory; its nonzero pages are in `DaxPages`.
    Anonymous { writable: bool },
    /// Inaccessible (`PROT_NONE`) memory.
    Hole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaxMapping {
    /// Offset into the window.
    pub moffset: u64,
    pub len: u64,
    pub kind: DaxMappingKind,
}

/// The whole window: mappings in offset order covering `[0, size)` without
/// gaps or overlaps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaxState {
    pub size: u64,
    pub mappings: Vec<DaxMapping>,
}

/// The nonzero `DAX_PAGE_SIZE` pages of a window's anonymous mappings;
/// a page missing here is zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DaxPages {
    /// Window offsets, strictly increasing.
    pub offsets: Vec<u64>,
    /// One page per offset, in offset order.
    pub data: Vec<u8>,
}

fn host_page_size() -> u64 {
    // Safe because sysconf touches no memory.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn invalid<T>(why: &'static str) -> Result<T, PassthroughSnapshotError> {
    Err(PassthroughSnapshotError::Invalid(why))
}

impl DaxState {
    /// Structural checks against this host, before any side effect.
    pub fn validate(&self, objects: usize) -> Result<(), PassthroughSnapshotError> {
        let page = host_page_size();
        if self.size == 0 || self.size % page != 0 {
            return invalid("DAX window size is not a whole number of host pages");
        }
        let mut end = 0;
        for mapping in &self.mappings {
            if mapping.moffset != end {
                return invalid("DAX mappings leave a gap or overlap");
            }
            if mapping.len == 0 || mapping.len % page != 0 {
                return invalid("DAX mapping length is not a whole number of host pages");
            }
            end = match mapping.moffset.checked_add(mapping.len) {
                Some(next) if next <= self.size => next,
                _ => return invalid("DAX mapping past the window"),
            };
            if let DaxMappingKind::File {
                object, foffset, ..
            } = mapping.kind
            {
                if !usize::try_from(object).is_ok_and(|o| o < objects) {
                    return invalid("DAX mapping object out of range");
                }
                let fits = foffset
                    .checked_add(mapping.len)
                    .is_some_and(|last| last <= i64::MAX as u64);
                if foffset % page != 0 || !fits {
                    return invalid("DAX mapping file offset is unaligned or too large");
                }
            }
        }
        if end != self.size {
            return invalid("DAX mappings do not cover the window");
        }
        Ok(())
    }

    fn anonymous(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.mappings
            .iter()
            .filter(|m| matches!(m.kind, DaxMappingKind::Anonymous { .. }))
            .map(|m| (m.moffset, m.len))
    }
}

impl DaxPages {
    /// Checks against a validated `state`: whole nonzero pages, strictly
    /// increasing, each inside one anonymous mapping.
    pub fn validate(&self, state: &DaxState) -> Result<(), PassthroughSnapshotError> {
        validate_pages(self, state.anonymous())
    }

    fn page(&self, index: usize) -> &[u8] {
        let size = DAX_PAGE_SIZE as usize;
        &self.data[index * size..(index + 1) * size]
    }
}

/// `pages` against the anonymous `(offset, len)` ranges of a window, in
/// offset order.
fn validate_pages(
    pages: &DaxPages,
    anonymous: impl Iterator<Item = (u64, u64)>,
) -> Result<(), PassthroughSnapshotError> {
    if pages.offsets.len().checked_mul(DAX_PAGE_SIZE as usize) != Some(pages.data.len()) {
        return invalid("DAX page data does not match its offsets");
    }
    let mut anonymous = anonymous.peekable();
    let mut previous = None;
    for &offset in &pages.offsets {
        if offset % DAX_PAGE_SIZE != 0 {
            return invalid("DAX page offset is unaligned");
        }
        if previous.is_some_and(|p| offset <= p) {
            return invalid("DAX page offsets are not strictly increasing");
        }
        previous = Some(offset);
        while anonymous
            .peek()
            .is_some_and(|&(start, len)| start + len <= offset)
        {
            anonymous.next();
        }
        let inside = anonymous.peek().is_some_and(|&(start, len)| {
            start <= offset && offset.checked_add(DAX_PAGE_SIZE) <= Some(start + len)
        });
        if !inside {
            return invalid("DAX page outside the anonymous mappings");
        }
    }
    if pages
        .data
        .chunks(DAX_PAGE_SIZE as usize)
        .any(|page| page.iter().all(|&b| b == 0))
    {
        return invalid("DAX page is all zeros");
    }
    Ok(())
}

/// A host object file segments map, held open with their access.
pub(super) struct MappedObject {
    file: File,
    /// The node the guest mapped it through (0 after a restore), for errors.
    inode: Inode,
    dev: u64,
    ino: u64,
    mnt_id: u64,
}

#[derive(Clone)]
enum Segment {
    File {
        object: Arc<MappedObject>,
        foffset: u64,
        writable: bool,
    },
    Anonymous {
        writable: bool,
    },
    Hole,
}

/// Read-write private memory: the window's initial state.
const UNTOUCHED: Segment = Segment::Anonymous { writable: true };

fn protection(writable: bool) -> i32 {
    if writable {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        libc::PROT_READ
    }
}

/// Make `addr..addr + len` read-only.
///
/// # Safety
///
/// As `Segment::map`.
unsafe fn make_read_only(addr: u64, len: u64) -> io::Result<()> {
    #[cfg(test)]
    if faults::take(addr, faults::Fault::ProtectPartly) {
        libc::mprotect(
            addr as *mut libc::c_void,
            host_page_size() as usize,
            libc::PROT_READ,
        );
        return Err(io::Error::from_raw_os_error(libc::ENOMEM));
    }
    if libc::mprotect(addr as *mut libc::c_void, len as usize, libc::PROT_READ) < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Segment {
    /// The same mapping, `skip` bytes further in.
    fn advanced(&self, skip: u64) -> Segment {
        match self {
            Segment::File {
                object,
                foffset,
                writable,
            } => Segment::File {
                object: object.clone(),
                foffset: foffset + skip,
                writable: *writable,
            },
            other => other.clone(),
        }
    }

    /// Whether `next` seamlessly continues this segment of length `len`.
    fn continues(&self, len: u64, next: &Segment) -> bool {
        match (self, next) {
            (Segment::Anonymous { writable }, Segment::Anonymous { writable: next }) => {
                writable == next
            }
            (Segment::Hole, Segment::Hole) => true,
            (
                Segment::File {
                    object,
                    foffset,
                    writable,
                },
                Segment::File {
                    object: next_object,
                    foffset: next_foffset,
                    writable: next_writable,
                },
            ) => {
                Arc::ptr_eq(object, next_object)
                    && writable == next_writable
                    && foffset.checked_add(len) == Some(*next_foffset)
            }
            _ => false,
        }
    }

    /// Map this segment at `addr`, replacing whatever was there.
    ///
    /// # Safety
    ///
    /// `addr..addr + len` must lie inside a share's DAX window, which holds
    /// no other memory of this process.
    unsafe fn map(&self, addr: u64, len: u64) -> io::Result<()> {
        match self {
            Segment::File {
                object,
                foffset,
                writable,
            } => {
                let fd = object.file.as_raw_fd();
                let prot = protection(*writable);
                map_fixed(addr, len, prot, libc::MAP_SHARED, fd, *foffset)
            }
            Segment::Anonymous { writable } => map_fixed(
                addr,
                len,
                protection(*writable),
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ),
            Segment::Hole => map_fixed(
                addr,
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ),
        }
    }
}

/// # Safety
///
/// As `Segment::map`.
unsafe fn map_fixed(
    addr: u64,
    len: u64,
    prot: i32,
    flags: i32,
    fd: RawFd,
    offset: u64,
) -> io::Result<()> {
    #[cfg(test)]
    if faults::take(addr, faults::Fault::MapAfterUnmap) {
        libc::munmap(addr as *mut libc::c_void, len as usize);
        return Err(io::Error::from_raw_os_error(libc::ENOMEM));
    }
    let ret = libc::mmap(
        addr as *mut libc::c_void,
        len as usize,
        prot,
        flags | libc::MAP_FIXED,
        fd,
        offset as libc::off_t,
    );
    if std::ptr::eq(ret, libc::MAP_FAILED) {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Host call failures for tests, armed per target address so tests running
/// in parallel never trip each other's windows.
#[cfg(test)]
pub(crate) mod faults {
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Fault {
        /// `mmap(MAP_FIXED)` unmaps the old range, then fails.
        MapAfterUnmap,
        /// `mprotect` makes the first host page read-only, then fails.
        ProtectPartly,
    }

    static ARMED: Mutex<Vec<(u64, Fault)>> = Mutex::new(Vec::new());

    /// Fail the next `fault` host call targeting `addr`.
    pub(crate) fn arm(addr: u64, fault: Fault) {
        ARMED.lock().unwrap().push((addr, fault));
    }

    pub(super) fn take(addr: u64, fault: Fault) -> bool {
        let mut armed = ARMED.lock().unwrap();
        let found = armed.iter().position(|&armed| armed == (addr, fault));
        found.map(|index| armed.remove(index)).is_some()
    }
}

/// Append the nonzero pages of the anonymous memory at `addr`, window
/// offset `moffset`, to `pages`.
///
/// # Safety
///
/// `addr..addr + len` must be readable and nothing may write it meanwhile
/// (the share's worker is frozen and the guest paused).
unsafe fn capture_pages(addr: u64, moffset: u64, len: u64, pages: &mut DaxPages) {
    for skip in (0..len).step_by(DAX_PAGE_SIZE as usize) {
        let page = std::slice::from_raw_parts((addr + skip) as *const u8, DAX_PAGE_SIZE as usize);
        if page.iter().any(|&b| b != 0) {
            pages.offsets.push(moffset + skip);
            pages.data.extend_from_slice(page);
        }
    }
}

fn valid_window(host_addr: u64, size: u64) -> bool {
    let page = host_page_size();
    size != 0
        && size % page == 0
        && host_addr % page == 0
        && host_addr
            .checked_add(size)
            .is_some_and(|end| usize::try_from(end).is_ok())
}

/// The window of one snapshot-mode share as the host maps it.
#[derive(Default)]
pub(super) struct DaxLedger {
    /// The window size; 0 until the first mapping request or a restore.
    size: u64,
    /// The window address: from the first mapping request, or once a
    /// restored ledger was mapped. None with a nonzero size means a
    /// restored ledger that `map_dax` has not mapped yet.
    host_addr: Option<u64>,
    /// Start -> (length, segment), covering `[0, size)` once it is known.
    segments: BTreeMap<u64, (u64, Segment)>,
    /// The descriptors file segments share, per (st_dev, st_ino, writable).
    opened: HashMap<(u64, u64, bool), Weak<MappedObject>>,
    /// A host mapping call failed: `segments` may no longer match the host.
    lost: bool,
}

impl DaxLedger {
    /// Refuse a lost window.
    fn usable(&self) -> io::Result<()> {
        if self.lost {
            Err(io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    }

    /// Run host mapping call `op` on the live window; its failure loses
    /// the window.
    fn host(&mut self, op: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let result = op();
        self.lost |= result.is_err();
        result
    }

    /// Bind to the window a mapping request targets; a share maps one,
    /// made of whole host pages inside the address space.
    fn bind(&mut self, host_addr: u64, size: u64) -> io::Result<()> {
        if self.size == 0 {
            if !valid_window(host_addr, size) {
                return Err(einval());
            }
            self.size = size;
            self.host_addr = Some(host_addr);
            self.segments.insert(0, (size, UNTOUCHED));
        }
        if self.size != size || self.host_addr != Some(host_addr) {
            return Err(einval());
        }
        Ok(())
    }

    /// The host-page-rounded length a request for `len` bytes at `moffset`
    /// maps, if it is page aligned and inside the window.
    fn range(&self, moffset: u64, len: u64) -> io::Result<u64> {
        let page = host_page_size();
        let len = len
            .checked_next_multiple_of(page)
            .filter(|&len| len != 0 && moffset % page == 0)
            .ok_or_else(einval)?;
        match moffset.checked_add(len) {
            Some(end) if end <= self.size => Ok(len),
            _ => Err(einval()),
        }
    }

    /// The shared descriptor for the object behind `file`.
    fn object(
        &mut self,
        file: File,
        inode: Inode,
        writable: bool,
    ) -> io::Result<Arc<MappedObject>> {
        let (st, mnt_id) = statx(&file)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::from_raw_os_error(libc::ENODEV));
        }
        let key = (st.st_dev, st.st_ino, writable);
        if let Some(object) = self.opened.get(&key).and_then(Weak::upgrade) {
            return Ok(object);
        }
        self.opened.retain(|_, object| object.strong_count() > 0);
        let object = Arc::new(MappedObject {
            file,
            inode,
            dev: st.st_dev,
            ino: st.st_ino,
            mnt_id,
        });
        self.opened.insert(key, Arc::downgrade(&object));
        Ok(object)
    }

    /// Record that `[start, start + len)` now maps `segment`.
    fn replace(&mut self, start: u64, len: u64, segment: Segment) {
        let end = start + len;
        let overlapped: Vec<u64> = self
            .segments
            .range(..end)
            .rev()
            .take_while(|(&s, &(l, _))| s + l > start)
            .map(|(&s, _)| s)
            .collect();
        for s in overlapped {
            let (l, old) = self.segments.remove(&s).unwrap();
            if s + l > end {
                self.segments
                    .insert(end, (s + l - end, old.advanced(end - s)));
            }
            if s < start {
                self.segments.insert(s, (start - s, old));
            }
        }
        self.segments.insert(start, (len, segment));
        self.merge_into_previous(end);
        self.merge_into_previous(start);
    }

    /// Merge the segment at `at` into the one before when it continues it.
    fn merge_into_previous(&mut self, at: u64) {
        let Some((&previous, (previous_len, previous_segment))) =
            self.segments.range(..at).next_back()
        else {
            return;
        };
        let continues = self
            .segments
            .get(&at)
            .is_some_and(|(_, segment)| previous_segment.continues(*previous_len, segment));
        if continues {
            let (len, _) = self.segments.remove(&at).unwrap();
            self.segments.get_mut(&previous).unwrap().0 += len;
        }
    }

    fn anonymous(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.segments
            .iter()
            .filter(|(_, (_, segment))| matches!(segment, Segment::Anonymous { .. }))
            .map(|(&start, &(len, _))| (start, len))
    }

    /// The ledger of a restored share from a validated `state`; `open`
    /// reopens checkpoint object `object` for a mapping (`writable` or
    /// not). Nothing is mapped until `PassthroughFs::map_dax`.
    pub(super) fn restored(
        state: &DaxState,
        mut open: impl FnMut(u64, bool) -> Result<File, PassthroughSnapshotError>,
    ) -> Result<DaxLedger, PassthroughSnapshotError> {
        let mut ledger = DaxLedger {
            size: state.size,
            ..Default::default()
        };
        for mapping in &state.mappings {
            let segment = match mapping.kind {
                DaxMappingKind::File {
                    object,
                    foffset,
                    writable,
                } => Segment::File {
                    object: ledger.object(open(object, writable)?, 0, writable)?,
                    foffset,
                    writable,
                },
                DaxMappingKind::Anonymous { writable } => Segment::Anonymous { writable },
                DaxMappingKind::Hole => Segment::Hole,
            };
            ledger
                .segments
                .insert(mapping.moffset, (mapping.len, segment));
        }
        Ok(ledger)
    }
}

impl PassthroughFs {
    /// Snapshot-mode FUSE_SETUPMAPPING: the host mapping, then the ledger.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn dax_setupmapping(
        &self,
        inode: Inode,
        foffset: u64,
        len: u64,
        writable: bool,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        let mut ledger = self.dax.lock().unwrap();
        ledger.usable()?;
        ledger.bind(host_shm_base, shm_size)?;
        let mapped = ledger.range(moffset, len)?;
        if inode == self.init_inode {
            return self.map_init(&mut ledger, foffset, len, writable, moffset, mapped);
        }
        if foffset % host_page_size() != 0
            || foffset
                .checked_add(mapped)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(einval());
        }
        let flags = if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        let object = ledger.object(self.open_inode(inode, flags)?, inode, writable)?;
        let segment = Segment::File {
            object,
            foffset,
            writable,
        };
        // Safe because the range lies inside this share's window.
        ledger.host(|| unsafe { segment.map(host_shm_base + moffset, mapped) })?;
        ledger.replace(moffset, mapped, segment);
        Ok(())
    }

    /// A private copy of init.krun from `foffset` with the requested
    /// access; past its end the copy is zero.
    fn map_init(
        &self,
        ledger: &mut DaxLedger,
        foffset: u64,
        len: u64,
        writable: bool,
        moffset: u64,
        mapped: u64,
    ) -> io::Result<()> {
        let addr = ledger.host_addr.expect("bind records the window") + moffset;
        // Safe because the range lies inside this share's window.
        ledger.host(|| unsafe { UNTOUCHED.map(addr, mapped) })?;
        let init = &self.init_binary;
        let start = usize::try_from(foffset)
            .unwrap_or(usize::MAX)
            .min(init.len());
        let end = start.saturating_add(len as usize).min(init.len());
        // Safe because the private mapping just made covers `len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(init[start..end].as_ptr(), addr as *mut u8, end - start)
        };
        if !writable {
            // Safe because the range is the mapping just made.
            ledger.host(|| unsafe { make_read_only(addr, mapped) })?;
        }
        ledger.replace(moffset, mapped, Segment::Anonymous { writable });
        Ok(())
    }

    /// Snapshot-mode FUSE_REMOVEMAPPING. A refused range ends the request;
    /// the ledger keeps every range removed before it.
    pub(super) fn dax_removemapping(
        &self,
        requests: &[fuse::RemovemappingOne],
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        let mut ledger = self.dax.lock().unwrap();
        ledger.usable()?;
        ledger.bind(host_shm_base, shm_size)?;
        for req in requests {
            let len = ledger.range(req.moffset, req.len)?;
            // Safe because the range lies inside this share's window.
            ledger.host(|| unsafe { Segment::Hole.map(host_shm_base + req.moffset, len) })?;
            ledger.replace(req.moffset, len, Segment::Hole);
        }
        Ok(())
    }

    /// Write back every writable file mapping, so the host objects hold
    /// what the guest wrote through the window.
    pub(super) fn sync_dax(&self) -> io::Result<()> {
        let ledger = self.dax.lock().unwrap();
        ledger.usable()?;
        let Some(base) = ledger.host_addr else {
            return Ok(());
        };
        for (&start, (len, segment)) in &ledger.segments {
            if !matches!(segment, Segment::File { writable: true, .. }) {
                continue;
            }
            // Safe because the range is a live shared mapping of this share
            // and msync touches no memory.
            let res = unsafe {
                libc::msync(
                    (base + start) as *mut libc::c_void,
                    *len as usize,
                    libc::MS_SYNC,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// The DAX part of a checkpoint of a frozen share: `window` is where the
    /// device maps the share's window (None: the one mapping requests
    /// targeted, if any). Mapped objects join `table`.
    pub(super) fn checkpoint_dax(
        &self,
        window: Option<DaxWindow>,
        table: &mut ObjectTable,
        root_mnt: Option<u64>,
    ) -> Result<(Option<DaxState>, DaxPages), PassthroughSnapshotError> {
        let ledger = self.dax.lock().unwrap();
        if ledger.lost {
            return Err(PassthroughSnapshotError::DaxLost);
        }
        if ledger.size != 0 && ledger.host_addr.is_none() {
            return invalid("restored DAX mappings were never mapped");
        }
        let bound = ledger.host_addr.map(|host_addr| DaxWindow {
            host_addr,
            size: ledger.size,
        });
        let window = match (window, bound) {
            (Some(window), Some(bound)) if window != bound => {
                return invalid("DAX window differs from the one the share maps")
            }
            (Some(window), _) | (None, Some(window)) => window,
            (None, None) => return Ok((None, DaxPages::default())),
        };
        if !valid_window(window.host_addr, window.size) {
            return invalid("DAX window is not whole host pages");
        }
        let segments: Vec<(u64, u64, &Segment)> = if ledger.segments.is_empty() {
            vec![(0, window.size, &UNTOUCHED)]
        } else {
            ledger
                .segments
                .iter()
                .map(|(&start, (len, segment))| (start, *len, segment))
                .collect()
        };
        let mut mappings = Vec::with_capacity(segments.len());
        let mut pages = DaxPages::default();
        for (moffset, len, segment) in segments {
            let kind = match segment {
                Segment::File {
                    object,
                    foffset,
                    writable,
                } => {
                    if Some(object.mnt_id) != root_mnt {
                        return Err(PassthroughSnapshotError::HostSubmount(object.inode));
                    }
                    DaxMappingKind::File {
                        object: table.add(&object.file, (object.dev, object.ino))?,
                        foffset: *foffset,
                        writable: *writable,
                    }
                }
                Segment::Anonymous { writable } => {
                    // Safe because the ledger matches the host: this range
                    // is readable private memory, and the frozen share and
                    // paused guest write none of it.
                    unsafe { capture_pages(window.host_addr + moffset, moffset, len, &mut pages) };
                    DaxMappingKind::Anonymous {
                        writable: *writable,
                    }
                }
                Segment::Hole => DaxMappingKind::Hole,
            };
            mappings.push(DaxMapping { moffset, len, kind });
        }
        Ok((
            Some(DaxState {
                size: window.size,
                mappings,
            }),
            pages,
        ))
    }

    /// Map a restored share's DAX mappings into `window` and write the
    /// captured anonymous pages; call it before the worker or any vCPU
    /// runs. Everything is checked before the first mapping; a failure part
    /// way leaves the window partly remapped, so the caller discards it.
    pub fn map_dax(
        &self,
        window: DaxWindow,
        pages: &DaxPages,
    ) -> Result<(), PassthroughSnapshotError> {
        let mut ledger = self.dax.lock().unwrap();
        if ledger.size == 0 || ledger.host_addr.is_some() {
            return invalid("no restored DAX mappings to map");
        }
        if window.size != ledger.size || !valid_window(window.host_addr, window.size) {
            return invalid("DAX window differs from the restored one");
        }
        validate_pages(pages, ledger.anonymous())?;
        for (&start, (len, segment)) in &ledger.segments {
            // Anonymous memory is written before it becomes read-only.
            let segment = match segment {
                Segment::Anonymous { .. } => &UNTOUCHED,
                other => other,
            };
            // Safe because the caller hands over the share's whole window.
            unsafe { segment.map(window.host_addr + start, *len)? };
        }
        for (index, &offset) in pages.offsets.iter().enumerate() {
            // Safe because the page lies inside an anonymous mapping just
            // made read-write.
            unsafe {
                ptr::copy_nonoverlapping(
                    pages.page(index).as_ptr(),
                    (window.host_addr + offset) as *mut u8,
                    DAX_PAGE_SIZE as usize,
                )
            };
        }
        for (&start, (len, segment)) in &ledger.segments {
            if matches!(segment, Segment::Anonymous { writable: false }) {
                // Safe because the range is an anonymous mapping just made.
                unsafe { make_read_only(window.host_addr + start, *len)? };
            }
        }
        ledger.host_addr = Some(window.host_addr);
        Ok(())
    }
}
