// SPDX-License-Identifier: Apache-2.0

//! Checkpointable runtime state of a snapshot-mode passthrough share.
//!
//! The guest keeps FUSE node IDs, file handles, directory stream offsets and
//! inode numbers across a checkpoint, so the server must hand back exactly
//! the same values without a new FUSE_INIT. Host descriptors, paths and
//! host inode numbers never enter the serialized state: objects are indexes
//! into the checkpoint's object list, and a restore supplies one fresh
//! `O_PATH` descriptor per object.
//!
//! Snapshot mode changes three guest-visible behaviors of the share:
//! - directory streams list the whole directory through an independent
//!   descriptor when the guest starts or rewinds them, and offsets are list
//!   indexes, so a stream continues identically after a restore;
//! - inode numbers are projected: identity on a share that was never
//!   restored, the saved numbers for restored objects, and synthetic numbers
//!   from 2^63 for new objects whose host number collides, init.krun's
//!   number included;
//! - a restored object reports its saved ctime until the host object is
//!   really modified (its host ctime leaves the restore baseline).
//!
//! The DAX window ledger (see `dax`) joins the checkpoint: its mappings
//! reference the same object list, and objects only a mapping references
//! are objects too.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::{self, size_of};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;

use super::dax::{DaxLedger, DaxMappingKind, DaxPages, DaxState, DaxWindow};
use super::{
    einval, forget_one, fuse, stat, statx, Config, DirEntry, Entry, HandleData, Inode, InodeAltKey,
    InodeData, LinuxDirent64, PassthroughFs,
};

/// Open flags that only matter when a file is created; a recorded handle
/// never carries them, so a restore can never create or truncate.
pub(super) const CREATION_FLAGS: i32 = libc::O_CREAT
    | libc::O_EXCL
    | libc::O_TRUNC
    | libc::O_NOCTTY
    | (libc::O_TMPFILE & !libc::O_DIRECTORY);

/// First synthetic guest inode number, handed out only when a host inode
/// number collides with one the guest already knows.
pub const SYNTHETIC_INO_BASE: u64 = 1 << 63;

/// Longest directory entry name a list may hold.
const MAX_NAME_LEN: usize = 255;

/// getdents64 buffer for building a directory list.
const DIRENT_BUFFER: usize = 64 * 1024;

/// (st_dev, st_ino) of a host object.
type HostKey = (u64, u64);

/// One entry of a stable directory list; its offset cookie is its index + 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirListEntry {
    /// The entry name without a terminating NUL ("." and ".." included).
    pub name: Vec<u8>,
    /// The guest inode number reported for this entry.
    pub ino: u64,
    /// The `DT_*` type the host reported.
    pub type_: u32,
}

/// One FUSE node the guest holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeState {
    /// The FUSE node ID.
    pub inode: u64,
    /// Outstanding guest lookups (FUSE_FORGET counts).
    pub refcount: u64,
    /// Index into the checkpoint's object list.
    pub object: u64,
}

/// One open file or directory handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleState {
    /// The FUSE file handle.
    pub handle: u64,
    /// The node ID the handle was opened on.
    pub inode: u64,
    /// Index into the checkpoint's object list of the open object (which
    /// may be unlinked).
    pub object: u64,
    /// The flags the host descriptor was opened with, without creation
    /// flags; a restore reopens the object with exactly these.
    pub flags: i32,
    /// The directory list, once the guest read the stream.
    pub listing: Option<Vec<DirListEntry>>,
}

/// Everything a share needs to continue serving the same guest without
/// FUSE_INIT, except host objects and init.krun bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassthroughState {
    pub writeback: bool,
    pub announce_submounts: bool,
    pub next_inode: u64,
    pub next_handle: u64,
    pub init_inode: u64,
    pub init_handle: u64,
    pub next_synthetic_ino: u64,
    /// Every node, in node ID order; empty before FUSE_INIT.
    pub nodes: Vec<NodeState>,
    /// Every handle, in handle order.
    pub handles: Vec<HandleState>,
    /// The DAX window, when the share has one.
    pub dax: Option<DaxState>,
}

/// A host object referenced by a checkpoint, deduplicated by host identity.
/// Never serialized: the caller archives it and drops the descriptor.
pub struct SnapshotObject {
    /// A duplicate of the share's descriptor for the object: the node's
    /// `O_PATH` descriptor, the open handle for an object only a handle
    /// still references, or the mapping descriptor for an object only DAX
    /// mappings reference.
    pub file: File,
    pub dev: u64,
    pub ino: u64,
    /// The inode number the guest sees.
    pub guest_ino: u64,
    /// The ctime (seconds, nanoseconds) the guest sees.
    pub ctime: (i64, i64),
}

/// A consistent capture of a frozen share.
pub struct PassthroughCheckpoint {
    pub state: PassthroughState,
    /// Indexed by `NodeState::object`, `HandleState::object` and DAX file
    /// mappings.
    pub objects: Vec<SnapshotObject>,
    /// The init.krun bytes this share serves.
    pub init_binary: Arc<[u8]>,
    /// The nonzero pages of the DAX window's anonymous mappings (init.krun
    /// copies included); empty without a window.
    pub dax_pages: DaxPages,
}

/// A host object rebuilt for a restore, in checkpoint object order.
pub struct RestoredObject {
    /// An `O_PATH | O_NOFOLLOW` descriptor of the rebuilt object, which may
    /// already be unlinked.
    pub file: File,
    /// The inode number the guest saw.
    pub guest_ino: u64,
    /// The ctime the guest saw; reported until the object really changes.
    pub ctime: (i64, i64),
}

/// Why a share cannot be checkpointed or restored.
#[derive(Debug)]
pub enum PassthroughSnapshotError {
    /// The share was not created in snapshot mode.
    Disabled,
    /// The guest exported this handle's descriptor to another subsystem.
    ExportedHandle(u64),
    /// This node lies on another host mount than the share root.
    HostSubmount(u64),
    /// The saved state is inconsistent.
    Invalid(&'static str),
    /// A host mapping call failed part way, so this process no longer knows
    /// what the DAX window maps; the share must be discarded.
    DaxLost,
    Io(io::Error),
}

impl std::fmt::Display for PassthroughSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "virtio-fs share is not in snapshot mode"),
            Self::ExportedHandle(handle) => {
                write!(
                    f,
                    "virtio-fs handle {handle} was exported to another subsystem"
                )
            }
            Self::HostSubmount(inode) => {
                write!(f, "virtio-fs node {inode} lies on a host submount")
            }
            Self::Invalid(why) => write!(f, "virtio-fs snapshot state: {why}"),
            Self::DaxLost => write!(f, "virtio-fs DAX window lost to a failed host mapping"),
            Self::Io(e) => write!(f, "virtio-fs snapshot: {e}"),
        }
    }
}

impl From<io::Error> for PassthroughSnapshotError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Clone, Copy)]
struct CtimeOverride {
    saved: (i64, i64),
    /// The host ctime right after the restore; any other value means the
    /// object was modified since.
    baseline: (i64, i64),
}

/// Host identity -> guest inode projection of a snapshot-mode share.
/// Entries live as long as the share: the guest may hold any number it saw.
pub(super) struct InoMap {
    /// init.krun's inode number, which no host object may report.
    init_ino: u64,
    to_guest: HashMap<HostKey, u64>,
    /// Guest inode numbers the identity projection must not hand out again,
    /// with the host object that owns each (None: a listed object that no
    /// longer exists).
    reserved: HashMap<u64, Option<HostKey>>,
    next_synthetic: u64,
    ctime: HashMap<HostKey, CtimeOverride>,
}

impl InoMap {
    pub(super) fn new(init_ino: u64) -> Self {
        InoMap {
            init_ino,
            to_guest: HashMap::new(),
            reserved: HashMap::new(),
            next_synthetic: SYNTHETIC_INO_BASE,
            ctime: HashMap::new(),
        }
    }

    /// The guest inode of `key`: a recorded projection, else the host
    /// number unless the guest already knows it for another object, else a
    /// new synthetic number that no reservation or live host object uses.
    pub(super) fn project(&mut self, key: HostKey, host_ino_is_live: impl Fn(u64) -> bool) -> u64 {
        if let Some(&guest) = self.to_guest.get(&key) {
            return guest;
        }
        if key.1 != self.init_ino && !self.reserved.contains_key(&key.1) {
            return key.1;
        }
        loop {
            let candidate = self.next_synthetic;
            self.next_synthetic = candidate.checked_add(1).unwrap_or(SYNTHETIC_INO_BASE);
            if !self.reserved.contains_key(&candidate) && !host_ino_is_live(candidate) {
                self.to_guest.insert(key, candidate);
                self.reserved.insert(candidate, Some(key));
                return candidate;
            }
        }
    }

    /// The ctime the guest sees for `key` whose host ctime is `host`.
    pub(super) fn ctime(&mut self, key: HostKey, host: (i64, i64)) -> (i64, i64) {
        match self.ctime.get(&key) {
            Some(o) if o.baseline == host => o.saved,
            Some(_) => {
                self.ctime.remove(&key);
                host
            }
            None => host,
        }
    }

    fn restore_object(
        &mut self,
        key: HostKey,
        guest_ino: u64,
        host_ctime: (i64, i64),
        saved_ctime: (i64, i64),
    ) -> Result<(), PassthroughSnapshotError> {
        if guest_ino == self.init_ino {
            return Err(PassthroughSnapshotError::Invalid(
                "restored object uses init.krun's inode",
            ));
        }
        if self.to_guest.get(&key).is_some_and(|&g| g != guest_ino) {
            return Err(PassthroughSnapshotError::Invalid(
                "one host object restored with two guest inodes",
            ));
        }
        if matches!(self.reserved.get(&guest_ino), Some(Some(owner)) if *owner != key) {
            return Err(PassthroughSnapshotError::Invalid(
                "two restored objects share one guest inode",
            ));
        }
        self.to_guest.insert(key, guest_ino);
        self.reserved.insert(guest_ino, Some(key));
        self.ctime.insert(
            key,
            CtimeOverride {
                saved: saved_ctime,
                baseline: host_ctime,
            },
        );
        Ok(())
    }

    fn reserve(&mut self, guest_ino: u64) {
        self.reserved.entry(guest_ino).or_insert(None);
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && !name.contains(&b'/') && !name.contains(&0)
}

impl PassthroughState {
    /// Structural checks against this build, before any host side effect.
    pub fn validate(&self, objects: usize) -> Result<(), PassthroughSnapshotError> {
        let invalid = |why| Err(PassthroughSnapshotError::Invalid(why));
        let in_objects = |object: u64| usize::try_from(object).is_ok_and(|o| o < objects);
        if self.init_inode != fuse::ROOT_ID + 1 || self.init_handle != 0 {
            return invalid("init.krun node or handle differs from this build");
        }
        if self.next_inode <= self.init_inode || self.next_handle <= self.init_handle {
            return invalid("allocation counters precede the reserved IDs");
        }
        if self.next_synthetic_ino < SYNTHETIC_INO_BASE {
            return invalid("synthetic inode counter below its range");
        }
        // Node ID -> object.
        let mut nodes = BTreeMap::new();
        let mut node_objects = BTreeSet::new();
        for node in &self.nodes {
            if node.inode == 0 || node.inode == self.init_inode || node.inode >= self.next_inode {
                return invalid("node ID outside the allocated range");
            }
            if nodes.insert(node.inode, node.object).is_some() {
                return invalid("duplicate node ID");
            }
            if node.refcount == 0 {
                return invalid("node without lookups");
            }
            if !in_objects(node.object) {
                return invalid("node object out of range");
            }
            // The node table is keyed by host identity: two nodes never
            // share one object.
            if !node_objects.insert(node.object) {
                return invalid("two nodes share one object");
            }
        }
        if !self.nodes.is_empty() && !nodes.contains_key(&fuse::ROOT_ID) {
            return invalid("nodes without the root");
        }
        if self.nodes.is_empty() && !self.handles.is_empty() {
            return invalid("handles before FUSE_INIT");
        }
        let mut handles = BTreeSet::new();
        for handle in &self.handles {
            if handle.handle == self.init_handle || handle.handle >= self.next_handle {
                return invalid("handle outside the allocated range");
            }
            if !handles.insert(handle.handle) {
                return invalid("duplicate handle");
            }
            if handle.inode == 0
                || handle.inode == self.init_inode
                || handle.inode >= self.next_inode
            {
                return invalid("handle node outside the allocated range");
            }
            if !in_objects(handle.object) {
                return invalid("handle object out of range");
            }
            // A handle whose node the guest forgot keeps its own object; a
            // live node is the same host object as every handle on it.
            if nodes
                .get(&handle.inode)
                .is_some_and(|&object| object != handle.object)
            {
                return invalid("handle object differs from its node");
            }
            if handle.flags & (CREATION_FLAGS | libc::O_PATH) != 0 {
                return invalid("handle flags would create, truncate or not open the object");
            }
            if let Some(listing) = &handle.listing {
                if listing.iter().any(|e| !valid_name(&e.name)) {
                    return invalid("directory list holds an invalid name");
                }
                if listing.iter().any(|e| e.ino == self.init_inode) {
                    return invalid("directory list entry uses init.krun's inode");
                }
            }
        }
        if let Some(dax) = &self.dax {
            dax.validate(objects)?;
            let maps_files = dax
                .mappings
                .iter()
                .any(|m| matches!(m.kind, DaxMappingKind::File { .. }));
            if self.nodes.is_empty() && maps_files {
                return invalid("DAX file mapping before FUSE_INIT");
            }
        }
        Ok(())
    }
}

/// Deduplicates checkpoint objects by host identity.
#[derive(Default)]
pub(super) struct ObjectTable {
    objects: Vec<(File, HostKey)>,
    index: HashMap<HostKey, u64>,
}

impl ObjectTable {
    pub(super) fn add(&mut self, file: &File, key: HostKey) -> io::Result<u64> {
        if let Some(&object) = self.index.get(&key) {
            return Ok(object);
        }
        let object = self.objects.len() as u64;
        self.objects.push((file.try_clone()?, key));
        self.index.insert(key, object);
        Ok(object)
    }
}

impl PassthroughFs {
    /// Serve a directory stream from its stable list. Offset 0 (a new
    /// stream or a rewind) takes a fresh complete list; any other offset is
    /// the index after the last entry the guest consumed.
    pub(super) fn read_listing<F>(
        &self,
        data: &HandleData,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        let mut listing = data.listing.lock().unwrap();
        if offset == 0 || listing.is_none() {
            *listing = Some(self.list_directory(data)?);
        }
        let entries = listing.as_deref().unwrap_or_default();
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in entries.iter().enumerate().skip(start) {
            let added = add_entry(DirEntry {
                ino: entry.ino,
                offset: index as u64 + 1,
                type_: entry.type_,
                name: &entry.name,
            })?;
            if added == 0 {
                break;
            }
        }
        Ok(())
    }

    /// List a whole directory through a new open file description, so the
    /// handle's own descriptor offset is never used or moved.
    fn list_directory(&self, data: &HandleData) -> io::Result<Vec<DirListEntry>> {
        let dir = {
            let file = data.file.read().unwrap();
            self.reopen(&file, libc::O_RDONLY | libc::O_DIRECTORY)?
        };
        let dev = stat(&dir)?.st_dev;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; DIRENT_BUFFER];
        loop {
            // Safe because the kernel only writes into `buf` and we check
            // the return value.
            let res = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dir.as_raw_fd(),
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
            if res == 0 {
                break;
            }
            let mut rem = &buf[..res as usize];
            while !rem.is_empty() {
                let header = rem
                    .get(..size_of::<LinuxDirent64>())
                    .and_then(LinuxDirent64::from_slice)
                    .copied()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                let reclen = header.d_reclen as usize;
                let name = rem
                    .get(size_of::<LinuxDirent64>()..reclen)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                let len = name
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                raw.push((name[..len].to_vec(), header.d_ino, u32::from(header.d_ty)));
                rem = &rem[reclen..];
            }
        }
        let mut inos = self.inos.lock().unwrap();
        Ok(raw
            .into_iter()
            .map(|(name, host_ino, type_)| DirListEntry {
                ino: inos.project((dev, host_ino), |ino| self.host_ino_is_live(ino)),
                name,
                type_,
            })
            .collect())
    }

    /// The readdirplus entry for a listed name: a lookup, nothing for a
    /// name that no longer exists, and no lookup for "." and "..", whose
    /// entry the kernel ignores (".." of the root is outside the share).
    pub(super) fn listing_entry(
        &self,
        parent: Inode,
        dir_entry: &DirEntry,
    ) -> io::Result<Option<Entry>> {
        if dir_entry.name == b"." || dir_entry.name == b".." {
            // SAFETY: stat64 is plain data.
            let mut attr: libc::stat64 = unsafe { mem::zeroed() };
            attr.st_ino = dir_entry.ino;
            attr.st_mode = dir_entry.type_ << 12;
            return Ok(Some(Entry {
                inode: 0,
                generation: 0,
                attr,
                attr_flags: 0,
                attr_timeout: Duration::ZERO,
                entry_timeout: Duration::ZERO,
            }));
        }
        let name = CString::new(dir_entry.name).map_err(|_| einval())?;
        match self.do_lookup(parent, &name) {
            Ok(entry) => Ok(Some(entry)),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// readdirplus over the stable list. A listed name that now names
    /// another object reports that object's inode number, and an entry the
    /// reply does not take gives its lookup back.
    pub(super) fn readdirplus_listing<F>(
        &self,
        parent: Inode,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(parent, handle, size, offset, |dir_entry| {
            let Some(entry) = self.listing_entry(parent, &dir_entry)? else {
                // Renamed or unlinked since the list was taken: skip it
                // without ending the reply.
                return Ok(1);
            };
            let looked_up = entry.inode;
            let dir_entry = DirEntry {
                ino: entry.attr.st_ino,
                ..dir_entry
            };
            let added = add_entry(dir_entry, entry);
            if looked_up != 0 && !matches!(added, Ok(n) if n > 0) {
                forget_one(&mut self.inodes.write().unwrap(), looked_up, 1);
            }
            added
        })
    }

    /// Flush every writable handle and DAX file mapping so the host objects
    /// hold everything the guest already wrote through this share.
    pub fn sync_for_snapshot(&self) -> io::Result<()> {
        self.sync_dax()?;
        let handles: Vec<Arc<HandleData>> =
            self.handles.read().unwrap().values().cloned().collect();
        for handle in handles {
            if handle.flags & libc::O_ACCMODE == libc::O_RDONLY {
                continue;
            }
            let file = handle.file.read().unwrap();
            // Safe because this doesn't modify any memory and we check the
            // return value.
            if unsafe { libc::fdatasync(file.as_raw_fd()) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// `checkpoint_with_dax` of the window mapping requests targeted.
    pub fn checkpoint(&self) -> Result<PassthroughCheckpoint, PassthroughSnapshotError> {
        self.checkpoint_with_dax(None)
    }

    /// Capture the runtime state of a share whose worker is frozen (and
    /// guest paused), its DAX window at `dax` if given. Pure: it builds no
    /// directory list, moves no descriptor offset and reads no host object.
    pub fn checkpoint_with_dax(
        &self,
        dax: Option<DaxWindow>,
    ) -> Result<PassthroughCheckpoint, PassthroughSnapshotError> {
        if !self.cfg.snapshot {
            return Err(PassthroughSnapshotError::Disabled);
        }
        let handles: Vec<(u64, Arc<HandleData>)> = self
            .handles
            .read()
            .unwrap()
            .iter()
            .map(|(handle, data)| (*handle, data.clone()))
            .collect();
        if let Some((handle, _)) = handles
            .iter()
            .find(|(_, data)| data.exported.load(Ordering::Relaxed))
        {
            return Err(PassthroughSnapshotError::ExportedHandle(*handle));
        }
        let nodes: Vec<(Inode, Arc<InodeData>)> = self
            .inodes
            .read()
            .unwrap()
            .iter()
            .map(|(inode, data)| (*inode, data.clone()))
            .collect();
        let root_mnt = match nodes.iter().find(|(inode, _)| *inode == fuse::ROOT_ID) {
            Some((_, root)) => Some(root.mnt_id),
            None if nodes.is_empty() && handles.is_empty() => None,
            None => {
                return Err(PassthroughSnapshotError::Invalid(
                    "nodes or handles without the root",
                ))
            }
        };

        let mut table = ObjectTable::default();
        let mut node_states = Vec::with_capacity(nodes.len());
        for (inode, data) in &nodes {
            if Some(data.mnt_id) != root_mnt {
                return Err(PassthroughSnapshotError::HostSubmount(*inode));
            }
            node_states.push(NodeState {
                inode: *inode,
                refcount: data.refcount.load(Ordering::Acquire),
                object: table.add(&data.file, (data.dev, data.ino))?,
            });
        }
        let mut handle_states = Vec::with_capacity(handles.len());
        for (handle, data) in &handles {
            let file = data.file.read().unwrap();
            let (st, mnt_id) = statx(&file)?;
            if Some(mnt_id) != root_mnt {
                return Err(PassthroughSnapshotError::HostSubmount(data.inode));
            }
            handle_states.push(HandleState {
                handle: *handle,
                inode: data.inode,
                object: table.add(&file, (st.st_dev, st.st_ino))?,
                flags: data.flags,
                listing: data.listing.lock().unwrap().clone(),
            });
        }
        let (dax, dax_pages) = self.checkpoint_dax(dax, &mut table, root_mnt)?;

        // Every share lock is released: `inos` comes before `inodes`.
        let mut inos = self.inos.lock().unwrap();
        let mut objects = Vec::with_capacity(table.objects.len());
        for (file, key) in table.objects {
            let st = stat(&file)?;
            objects.push(SnapshotObject {
                guest_ino: inos.project(key, |ino| self.host_ino_is_live(ino)),
                ctime: inos.ctime(key, (st.st_ctime, st.st_ctime_nsec)),
                file,
                dev: key.0,
                ino: key.1,
            });
        }
        Ok(PassthroughCheckpoint {
            state: PassthroughState {
                writeback: self.writeback.load(Ordering::Relaxed),
                announce_submounts: self.announce_submounts.load(Ordering::Relaxed),
                next_inode: self.next_inode.load(Ordering::Relaxed),
                next_handle: self.next_handle.load(Ordering::Relaxed),
                init_inode: self.init_inode,
                init_handle: self.init_handle,
                next_synthetic_ino: inos.next_synthetic,
                nodes: node_states,
                handles: handle_states,
                dax,
            },
            objects,
            init_binary: self.init_binary.clone(),
            dax_pages,
        })
    }

    /// Rebuild a share that continues serving the guest of `state` without
    /// FUSE_INIT: same node IDs, refcounts, handles (reopened with their
    /// saved flags), directory lists, counters and inode numbers. DAX
    /// mapping objects are reopened; `map_dax` maps them into the window.
    pub fn restore(
        cfg: Config,
        state: &PassthroughState,
        objects: Vec<RestoredObject>,
        init_binary: Arc<[u8]>,
    ) -> Result<PassthroughFs, PassthroughSnapshotError> {
        if !cfg.snapshot {
            return Err(PassthroughSnapshotError::Disabled);
        }
        state.validate(objects.len())?;
        let mut fs = PassthroughFs::new(cfg)?;
        if state.init_inode != fs.init_inode || state.init_handle != fs.init_handle {
            return Err(PassthroughSnapshotError::Invalid(
                "init.krun node or handle differs from this build",
            ));
        }
        let mut identities = Vec::with_capacity(objects.len());
        for object in &objects {
            identities.push(statx(&object.file)?);
        }
        let root_mnt = state
            .nodes
            .iter()
            .find(|node| node.inode == fuse::ROOT_ID)
            .map(|node| identities[node.object as usize].1);

        {
            let inos = fs.inos.get_mut().unwrap();
            for (object, (st, _)) in objects.iter().zip(&identities) {
                inos.restore_object(
                    (st.st_dev, st.st_ino),
                    object.guest_ino,
                    (st.st_ctime, st.st_ctime_nsec),
                    object.ctime,
                )?;
            }
            for entry in state
                .handles
                .iter()
                .filter_map(|h| h.listing.as_ref())
                .flatten()
            {
                inos.reserve(entry.ino);
            }
            inos.next_synthetic = state.next_synthetic_ino;
        }

        {
            let inodes = fs.inodes.get_mut().unwrap();
            for node in &state.nodes {
                let object = node.object as usize;
                let (st, mnt_id) = &identities[object];
                if Some(*mnt_id) != root_mnt {
                    return Err(PassthroughSnapshotError::HostSubmount(node.inode));
                }
                inodes.insert(
                    node.inode,
                    InodeAltKey {
                        ino: st.st_ino,
                        dev: st.st_dev,
                        mnt_id: *mnt_id,
                    },
                    Arc::new(InodeData {
                        inode: node.inode,
                        file: objects[object].file.try_clone()?,
                        dev: st.st_dev,
                        ino: st.st_ino,
                        mnt_id: *mnt_id,
                        refcount: AtomicU64::new(node.refcount),
                    }),
                );
            }
        }

        for handle in &state.handles {
            let object = handle.object as usize;
            if Some(identities[object].1) != root_mnt {
                return Err(PassthroughSnapshotError::HostSubmount(handle.inode));
            }
            let mut flags = handle.flags;
            if !fs.cap_fowner {
                // As in do_open: O_NOATIME needs CAP_FOWNER or ownership.
                flags &= !libc::O_NOATIME;
            }
            let file = fs.reopen(&objects[object].file, flags)?;
            fs.handles.get_mut().unwrap().insert(
                handle.handle,
                Arc::new(HandleData {
                    inode: handle.inode,
                    file: RwLock::new(file),
                    exported: Default::default(),
                    flags,
                    listing: Mutex::new(handle.listing.clone()),
                }),
            );
        }

        if let Some(dax) = &state.dax {
            let ledger = DaxLedger::restored(dax, |object, writable| {
                let object = object as usize;
                if Some(identities[object].1) != root_mnt {
                    return Err(PassthroughSnapshotError::Invalid(
                        "DAX mapping object on another mount than the root",
                    ));
                }
                let flags = if writable {
                    libc::O_RDWR
                } else {
                    libc::O_RDONLY
                };
                Ok(fs.reopen(&objects[object].file, flags)?)
            })?;
            *fs.dax.get_mut().unwrap() = ledger;
        }

        fs.writeback.store(state.writeback, Ordering::Relaxed);
        fs.announce_submounts
            .store(state.announce_submounts, Ordering::Relaxed);
        fs.next_inode.store(state.next_inode, Ordering::Relaxed);
        fs.next_handle.store(state.next_handle, Ordering::Relaxed);
        fs.init_binary = init_binary;
        if !state.nodes.is_empty() {
            // The FUSE_INIT this share never sees again cleared the umask so
            // the guest controls every mode bit.
            // Safe because umask always succeeds and touches no memory.
            unsafe { libc::umask(0o000) };
        }
        Ok(fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_fs_init_inode_is_never_projected() {
        let init = fuse::ROOT_ID + 1;
        let unused = |_| false;
        let mut inos = InoMap::new(init);
        // A host object numbered like init.krun (an ext4 root, say) gets a
        // synthetic number; other numbers stay identity.
        let synthetic = inos.project((7, init), unused);
        assert!(synthetic >= SYNTHETIC_INO_BASE);
        assert_eq!(inos.project((7, init), unused), synthetic);
        assert_eq!(inos.project((7, 3), unused), 3);

        // A restore keeps every saved projection, also for an object whose
        // new host number is init.krun's, and still reserves init.krun's.
        let mut restored = InoMap::new(init);
        restored
            .restore_object((9, 40), synthetic, (0, 0), (0, 0))
            .unwrap();
        restored
            .restore_object((9, init), 3, (0, 0), (0, 0))
            .unwrap();
        assert_eq!(restored.project((9, 40), unused), synthetic);
        assert_eq!(restored.project((9, init), unused), 3);
        let collides = restored.project((9, 3), unused);
        let new_at_init = restored.project((8, init), unused);
        for fresh in [collides, new_at_init] {
            assert!(fresh >= SYNTHETIC_INO_BASE && fresh != synthetic);
        }
        assert_ne!(collides, new_at_init);
        assert!(matches!(
            restored.restore_object((9, 50), init, (0, 0), (0, 0)),
            Err(PassthroughSnapshotError::Invalid(_))
        ));
    }
}
