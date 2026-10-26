// SPDX-License-Identifier: Apache-2.0

//! Independent archive of snapshot-mode shares.
//!
//! A session checkpoint (see `snapshot`) references host objects; this
//! archive copies them, so a restore no longer needs the source directories.
//! It covers every share of a VM at once:
//! - every object reachable from each share root, looked up by the guest or
//!   not, plus the objects sessions reference outside every tree (unlinked
//!   files a handle or DAX mapping keeps alive, unlinked directories and
//!   symlinks a node keeps);
//! - one archived object per host identity across all shares, so hard links
//!   (also between shares) and shared or nested share roots stay single
//!   objects; a directory has at most one parent, and a share root inside
//!   another share's tree is that tree's directory, never an extra link;
//! - per share: the root, the init.krun bytes it serves and its session
//!   (pre-FUSE_INIT for a device without one, so its DAX window is kept
//!   too) with the inode number and ctime the guest sees for every object
//!   it can reach ("views").
//!
//! The manifest is plain serializable metadata. Regular file bytes, init.krun
//! bytes and DAX pages are three separate binary payloads whose lengths
//! follow from the manifest; `ShareArchive` writes them, `ImportedArchive`
//! reads them in the same order (files, init, pages).
//!
//! Only regular files, directories, symlinks and overlay whiteouts (char
//! 0:0) are archived, with permission bits, owner, atime, mtime and the exact
//! extended attributes; anything else fails the capture. Each share is
//! walked through its own descriptors from its own root, so every mount a
//! share sees is checked.
//!
//! The manifest records its contract (`ArchiveContract`), chosen by the
//! capture's `ArchiveMode`:
//! - full attributes: the capture needs CAP_SYS_ADMIN in the initial user
//!   namespace, without which `trusted.*` xattrs are hidden, and holds any
//!   owner and every xattr; the import needs whatever privilege setting
//!   them takes;
//! - guest-visible: what the capturing service, and so its guest, sees and
//!   an unprivileged process with the same effective IDs can recreate.
//!   Every object must be owned by those IDs and carry only `user.*` and
//!   POSIX ACL xattrs naming no other user or group, every directory must
//!   be listable and searchable and every regular file readable; anything
//!   else fails the capture, never a partial archive. `trusted.*` xattrs,
//!   hidden from the service and its guest alike, are outside it. Only a
//!   process with exactly the recorded effective IDs may import it.

use std::collections::HashSet;
use std::io;

use serde::{Deserialize, Serialize};

use super::snapshot::valid_name;
use super::{fuse, DaxMappingKind, PassthroughSnapshotError, PassthroughState};

mod capture;
mod host;
mod import;

pub use capture::{ShareArchive, ShareSource};
#[cfg(test)]
pub(crate) use import::faults as import_faults;
pub use import::{ImportedArchive, ImportedSession};

/// Longest symlink target (PATH_MAX without its NUL).
const MAX_SYMLINK_LEN: usize = 4095;
/// Longest extended attribute name (XATTR_NAME_MAX).
const MAX_XATTR_NAME: usize = 255;
/// Largest extended attribute value (XATTR_SIZE_MAX).
const MAX_XATTR_VALUE: usize = 65536;
/// Largest init.krun a share may serve.
const MAX_INIT_LEN: u64 = 64 << 20;

/// The access ACL xattr.
const ACL_ACCESS: &[u8] = b"system.posix_acl_access";
/// The default ACL xattr.
const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";
/// The version of the ACL xattr format (`POSIX_ACL_XATTR_VERSION`).
const ACL_VERSION: u32 = 2;
/// Entry tags naming a user or group by ID (`ACL_USER`, `ACL_GROUP`).
const ACL_USER: u16 = 0x02;
const ACL_GROUP: u16 = 0x08;

/// Which metadata a capture keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveMode {
    /// Every attribute, also what only privilege sees or sets.
    FullAttributes,
    /// What the capturing service and its guest see, restorable without
    /// privilege under the same effective IDs.
    GuestVisible,
}

/// What an archive guarantees about the metadata it holds, and so which
/// process can import it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ArchiveContract {
    /// Any owner and every xattr, `trusted.*` ones included.
    FullAttributes,
    /// Every object owned by `uid`:`gid`, the capturing service's effective
    /// IDs in its own user namespace, with only `user.*` and POSIX ACL
    /// xattrs naming no other user or group; importable only by a process
    /// with exactly these effective IDs.
    GuestVisible { uid: u32, gid: u32 },
}

impl ArchiveContract {
    /// Why `object` is outside this contract, if it is.
    fn refuses(&self, object: &ArchivedObject) -> Option<&'static str> {
        let Self::GuestVisible { uid, gid } = *self else {
            return None;
        };
        if (object.uid, object.gid) != (uid, gid) {
            return Some("owner other than the guest-visible restore identity");
        }
        for xattr in &object.xattrs {
            if xattr.name == ACL_ACCESS || xattr.name == ACL_DEFAULT {
                if !acl_names_only(&xattr.value, uid, gid) {
                    return Some("POSIX ACL naming another user or group, or malformed");
                }
            } else if !xattr.name.starts_with(b"user.") {
                return Some("extended attribute outside user.* and POSIX ACLs");
            }
        }
        None
    }

    /// Fail unless this process may import an archive of this contract: a
    /// guest-visible one needs exactly the recorded effective IDs, so the
    /// restored guest sees the same owners as the source's did.
    pub fn check_importer(&self) -> Result<(), ArchiveError> {
        match *self {
            Self::GuestVisible { uid, gid } if host::effective_ids() != (uid, gid) => {
                Err(ArchiveError::Unsupported(
                    "import under another identity than the guest-visible archive's",
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Whether `value` is a well-formed ACL xattr whose named entries name
/// only user `uid` and group `gid`.
fn acl_names_only(value: &[u8], uid: u32, gid: u32) -> bool {
    let Some((version, entries)) = value.split_first_chunk::<4>() else {
        return false;
    };
    if u32::from_le_bytes(*version) != ACL_VERSION || entries.len() % 8 != 0 {
        return false;
    }
    entries.chunks_exact(8).all(|entry| {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        match tag {
            ACL_USER => id == uid,
            ACL_GROUP => id == gid,
            _ => true,
        }
    })
}

/// A timestamp with nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedTime {
    pub sec: i64,
    pub nsec: u32,
}

impl ArchivedTime {
    fn valid(&self) -> bool {
        self.nsec < 1_000_000_000
    }
}

/// One extended attribute, name and value as raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedXattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One directory entry: a raw byte name and the object it links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEntry {
    pub name: Vec<u8>,
    pub object: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ArchivedKind {
    /// Entries in strictly increasing name order.
    Directory {
        entries: Vec<ArchivedEntry>,
    },
    /// `size` bytes of the files payload, in object order.
    Regular {
        size: u64,
    },
    Symlink {
        target: Vec<u8>,
    },
    /// An overlay whiteout: a character device numbered 0:0.
    Whiteout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedObject {
    pub kind: ArchivedKind,
    /// Permission bits, set-ID and sticky bits included (ignored for
    /// symlinks).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: ArchivedTime,
    pub mtime: ArchivedTime,
    /// Every extended attribute, in strictly increasing name order.
    pub xattrs: Vec<ArchivedXattr>,
}

/// What one share's guest sees of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectView {
    pub object: u64,
    /// The inode number the guest sees.
    pub ino: u64,
    /// The ctime the guest sees.
    pub ctime: ArchivedTime,
}

/// The session of an activated share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedSession {
    /// The FUSE options FUSE_INIT negotiated (0 before it).
    pub options: u64,
    /// Its object indexes refer to `views`.
    pub state: PassthroughState,
    /// The session's objects first, then every other object reachable from
    /// the share root.
    pub views: Vec<ObjectView>,
    /// Window offsets of the DAX pages this share's part of the pages
    /// payload holds.
    pub dax_pages: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedShare {
    /// The root directory object.
    pub root: u64,
    /// Index into `ArchiveManifest::inits`.
    pub init: u64,
    /// A device without a session (never activated, or reset) has a
    /// pre-FUSE_INIT one, which also carries its DAX window.
    pub session: ArchivedSession,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub contract: ArchiveContract,
    pub objects: Vec<ArchivedObject>,
    /// Share roots outside every other tree; an import creates the k-th as
    /// directory "k" of its destination.
    pub trees: Vec<u64>,
    pub shares: Vec<ArchivedShare>,
    /// Length of each distinct init.krun in the init payload.
    pub inits: Vec<u64>,
}

/// Byte length of each payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadLengths {
    pub files: u64,
    pub init: u64,
    pub pages: u64,
}

/// Why shares cannot be archived or an archive cannot be imported.
#[derive(Debug)]
pub enum ArchiveError {
    /// A share's session cannot be captured or restored.
    Snapshot(PassthroughSnapshotError),
    /// The source holds something an import could not reproduce.
    Unsupported(&'static str),
    /// The manifest or a payload is malformed.
    Invalid(&'static str),
    /// This object changed after its capture.
    Changed(u64),
    /// The host did not reproduce this object's archived metadata.
    Mismatch(u64, &'static str),
    Io(io::Error),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snapshot(e) => write!(f, "{e}"),
            Self::Unsupported(why) => write!(f, "virtio-fs archive: unsupported {why}"),
            Self::Invalid(why) => write!(f, "virtio-fs archive: {why}"),
            Self::Changed(object) => {
                write!(
                    f,
                    "virtio-fs archive: object {object} changed after capture"
                )
            }
            Self::Mismatch(object, what) => {
                write!(
                    f,
                    "virtio-fs archive: object {object} imported with another {what}"
                )
            }
            Self::Io(e) => write!(f, "virtio-fs archive: {e}"),
        }
    }
}

impl From<io::Error> for ArchiveError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PassthroughSnapshotError> for ArchiveError {
    fn from(e: PassthroughSnapshotError) -> Self {
        Self::Snapshot(e)
    }
}

fn invalid<T>(why: &'static str) -> Result<T, ArchiveError> {
    Err(ArchiveError::Invalid(why))
}

/// A directory entry name: a valid listing name other than "." and "..".
fn valid_entry_name(name: &[u8]) -> bool {
    valid_name(name) && name != b"." && name != b".."
}

/// Where the import creates each object, derived from a validated manifest.
pub(super) struct Topology {
    /// Each linked object's first entry (directory, entry index) in
    /// creation order; None for trees and unreachable objects.
    pub(super) first: Vec<Option<(u64, usize)>>,
    /// Every further entry of a non-directory: (object, directory, index).
    pub(super) extra: Vec<(u64, u64, usize)>,
    /// Reachable directories, parents before children.
    pub(super) dirs: Vec<u64>,
    pub(super) reachable: Vec<bool>,
}

impl ArchivedObject {
    fn is_dir(&self) -> bool {
        matches!(self.kind, ArchivedKind::Directory { .. })
    }

    fn entries(&self) -> &[ArchivedEntry] {
        match &self.kind {
            ArchivedKind::Directory { entries } => entries,
            _ => &[],
        }
    }

    fn validate(&self, objects: usize) -> Result<(), ArchiveError> {
        if self.mode & !0o7777 != 0 {
            return invalid("mode holds more than permission bits");
        }
        if !self.atime.valid() || !self.mtime.valid() {
            return invalid("timestamp nanoseconds out of range");
        }
        for pair in self.xattrs.windows(2) {
            if pair[0].name >= pair[1].name {
                return invalid("xattrs are not in strictly increasing name order");
            }
        }
        for xattr in &self.xattrs {
            if xattr.name.is_empty()
                || xattr.name.len() > MAX_XATTR_NAME
                || xattr.name.contains(&0)
                || xattr.value.len() > MAX_XATTR_VALUE
            {
                return invalid("xattr name or value length");
            }
        }
        match &self.kind {
            ArchivedKind::Directory { entries } => {
                for pair in entries.windows(2) {
                    if pair[0].name >= pair[1].name {
                        return invalid("entries are not in strictly increasing name order");
                    }
                }
                for entry in entries {
                    if !valid_entry_name(&entry.name) {
                        return invalid("invalid entry name");
                    }
                    if !in_range(entry.object, objects) {
                        return invalid("entry object out of range");
                    }
                }
            }
            ArchivedKind::Regular { size } => {
                if *size > i64::MAX as u64 {
                    return invalid("file size past off_t");
                }
            }
            ArchivedKind::Symlink { target } => {
                if target.is_empty() || target.len() > MAX_SYMLINK_LEN || target.contains(&0) {
                    return invalid("symlink target length or NUL");
                }
            }
            ArchivedKind::Whiteout => {}
        }
        Ok(())
    }
}

/// `root` and every object below it, in discovery order; `objects` holds no
/// directory cycle.
fn subtree(objects: &[ArchivedObject], root: u64) -> Vec<u64> {
    let mut found = vec![root];
    let mut seen = HashSet::from([root]);
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in objects[dir as usize].entries() {
            if seen.insert(entry.object) {
                found.push(entry.object);
                if objects[entry.object as usize].is_dir() {
                    stack.push(entry.object);
                }
            }
        }
    }
    found
}

fn in_range(index: u64, len: usize) -> bool {
    usize::try_from(index).is_ok_and(|i| i < len)
}

impl ArchiveManifest {
    /// Every check an import makes before it creates anything but the
    /// importer's identity (`ArchiveContract::check_importer`): names, IDs,
    /// references, kinds, lengths, timestamps, topology, sessions and the
    /// contract's limits on owners and xattrs.
    pub fn validate(&self) -> Result<PayloadLengths, ArchiveError> {
        self.checked().map(|(lengths, _)| lengths)
    }

    pub(super) fn checked(&self) -> Result<(PayloadLengths, Topology), ArchiveError> {
        let n = self.objects.len();
        let mut files: u64 = 0;
        for object in &self.objects {
            object.validate(n)?;
            if let Some(why) = self.contract.refuses(object) {
                return invalid(why);
            }
            if let ArchivedKind::Regular { size } = object.kind {
                files = files
                    .checked_add(size)
                    .ok_or(ArchiveError::Invalid("file payload length overflows"))?;
            }
        }
        let topology = self.topology()?;
        if self.shares.is_empty() {
            return invalid("no shares");
        }
        let mut roots = HashSet::new();
        for share in &self.shares {
            if !in_range(share.root, n)
                || !self.objects[share.root as usize].is_dir()
                || !topology.reachable[share.root as usize]
            {
                return invalid("share root is not a directory of a tree");
            }
            roots.insert(share.root);
            if !in_range(share.init, self.inits.len()) {
                return invalid("share init.krun out of range");
            }
        }
        if self.trees.iter().any(|tree| !roots.contains(tree)) {
            return invalid("tree that is no share root");
        }
        let mut init: u64 = 0;
        for (index, &len) in self.inits.iter().enumerate() {
            if len > MAX_INIT_LEN {
                return invalid("init.krun too large");
            }
            if !self.shares.iter().any(|s| s.init == index as u64) {
                return invalid("init.krun no share serves");
            }
            init += len;
        }

        let mut viewed = vec![false; n];
        let mut pages: u64 = 0;
        for share in &self.shares {
            let session = &share.session;
            self.validate_session(share.root, session, &mut viewed)?;
            let len = (session.dax_pages.len() as u64)
                .checked_mul(super::DAX_PAGE_SIZE)
                .and_then(|len| pages.checked_add(len))
                .ok_or(ArchiveError::Invalid("pages payload length overflows"))?;
            pages = len;
        }
        if (0..n).any(|o| !topology.reachable[o] && !viewed[o]) {
            return invalid("object neither linked nor referenced by a session");
        }
        Ok((PayloadLengths { files, init, pages }, topology))
    }

    fn topology(&self) -> Result<Topology, ArchiveError> {
        let n = self.objects.len();
        let mut topology = Topology {
            first: vec![None; n],
            extra: Vec::new(),
            dirs: Vec::new(),
            reachable: vec![false; n],
        };
        for &tree in &self.trees {
            if !in_range(tree, n) || !self.objects[tree as usize].is_dir() {
                return invalid("tree is not a directory");
            }
            if topology.reachable[tree as usize] {
                return invalid("tree listed twice");
            }
            topology.reachable[tree as usize] = true;
        }
        let trees: HashSet<u64> = self.trees.iter().copied().collect();
        for &tree in &self.trees {
            let mut stack = vec![tree];
            while let Some(dir) = stack.pop() {
                topology.dirs.push(dir);
                for (index, entry) in self.objects[dir as usize].entries().iter().enumerate() {
                    let child = entry.object as usize;
                    if trees.contains(&entry.object) {
                        return invalid("entry links a tree");
                    }
                    if self.objects[child].is_dir() {
                        // A second link reaches an already linked
                        // directory: several parents or a cycle.
                        if topology.reachable[child] {
                            return invalid("directory with several parents");
                        }
                        stack.push(entry.object);
                    } else if topology.reachable[child] {
                        topology.extra.push((entry.object, dir, index));
                        continue;
                    }
                    topology.reachable[child] = true;
                    topology.first[child] = Some((dir, index));
                }
            }
        }
        // An unreachable directory with entries would make its children
        // linked but unreachable (an orphan subtree or a detached cycle).
        for (object, reachable) in self.objects.iter().zip(&topology.reachable) {
            if !reachable && !object.entries().is_empty() {
                return invalid("unlinked directory with entries");
            }
        }
        Ok(topology)
    }

    fn validate_session(
        &self,
        root: u64,
        session: &ArchivedSession,
        viewed: &mut [bool],
    ) -> Result<(), ArchiveError> {
        let n = self.objects.len();
        let state = &session.state;
        state.validate(session.views.len())?;
        state.check_options(session.options)?;
        let mut objects = HashSet::new();
        let mut inos = HashSet::new();
        for view in &session.views {
            if !in_range(view.object, n) || !objects.insert(view.object) {
                return invalid("view object out of range or repeated");
            }
            if view.ino == state.init_inode || !inos.insert(view.ino) {
                return invalid("view inode is init.krun's or repeated");
            }
            if !view.ctime.valid() {
                return invalid("timestamp nanoseconds out of range");
            }
        }
        let object = |index: u64| &self.objects[session.views[index as usize].object as usize];
        let mut referenced: HashSet<u64> = state.nodes.iter().map(|node| node.object).collect();
        if let Some(root_node) = state.nodes.iter().find(|n| n.inode == fuse::ROOT_ID) {
            if session.views[root_node.object as usize].object != root {
                return invalid("root node is not the share root");
            }
        }
        for handle in &state.handles {
            referenced.insert(handle.object);
            let kind = &object(handle.object).kind;
            let listed = handle.listing.is_some();
            match kind {
                ArchivedKind::Directory { .. } => {}
                ArchivedKind::Regular { .. } if !listed => {}
                _ => return invalid("handle on an object that cannot be open"),
            }
        }
        if let Some(dax) = &state.dax {
            for mapping in &dax.mappings {
                if let DaxMappingKind::File { object: index, .. } = mapping.kind {
                    referenced.insert(index);
                    if !matches!(object(index).kind, ArchivedKind::Regular { .. }) {
                        return invalid("DAX mapping of a non-regular object");
                    }
                }
            }
            dax.validate_page_offsets(&session.dax_pages)?;
        } else if !session.dax_pages.is_empty() {
            return invalid("DAX pages without a DAX window");
        }
        let subtree = subtree(&self.objects, root);
        if subtree.iter().any(|o| !objects.contains(o)) {
            return invalid("object of the share tree without a view");
        }
        let subtree: HashSet<u64> = subtree.into_iter().collect();
        for (index, view) in session.views.iter().enumerate() {
            if !subtree.contains(&view.object) && !referenced.contains(&(index as u64)) {
                return invalid("view of an object the share cannot reach");
            }
            viewed[view.object as usize] = true;
        }
        Ok(())
    }
}
