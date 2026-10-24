// SPDX-License-Identifier: Apache-2.0

//! Importing an archive into a new directory.
//!
//! Everything the manifest says is validated before the destination is
//! created. The import then creates the destination exclusively (0700) and
//! every object descriptor-relative without following symlinks, journaling
//! each name it creates, the destination included, as soon as it exists and
//! only then learning its object's identity: from the creating descriptor
//! (a new file), before the name exists (a hard link, made to the object's
//! own descriptor), else, for a creation returning no descriptor (a
//! directory, symlink or whiteout), from the name right away. A failure,
//! or dropping the guard before `persist`, removes exactly those names
//! (directories made writable first) while they still name what was
//! created. A name that now refers to another object, a directory something
//! else wrote into, and a name whose identity could not be read (so it
//! might already name a foreign replacement) are left alone, the last with
//! a warning.
//!
//! Order: all linked directories (parents first), then each other object in
//! object order (so regular files consume the files payload in order) at
//! its first link, or under a temporary name in a staging directory for an
//! object only sessions keep; the remaining hard links; directory metadata;
//! then every staged object is opened before its temporary name is removed.
//! Metadata goes owner, xattrs (inherited and default ones the source lacks
//! removed), mode, times, so neither chown nor an ACL rewrites what was
//! set last, and every object is compared with the archive at the end.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::super::snapshot::HostKey;
use super::super::{DaxPages, PassthroughState, RestoredObject, DAX_PAGE_SIZE};
use super::host;
use super::{
    invalid, ArchiveError, ArchiveManifest, ArchivedKind, ArchivedObject, ObjectView, Topology,
};
use crate::virtio::fs::Fs;
use crate::virtio::VirtioDevice;

/// Chunk size for reading file bytes; all-zero chunks become holes.
const COPY_CHUNK: usize = 64 * 1024;
/// The staging directory for objects only sessions keep.
const STAGING: &std::ffi::CStr = c"orphans";

/// Test-only failure injection: fail the import at a stage of a given
/// created name (counted from 1, the destination first), running a hook
/// first with that name's path (to plant or swap in foreign files). Per
/// thread, so parallel tests cannot trip each other.
#[cfg(test)]
pub(crate) mod faults {
    use std::cell::RefCell;
    use std::ffi::{CStr, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    type Hook = Box<dyn FnOnce(&Path)>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stage {
        /// Right after the name was created, before its identity is read.
        Identify,
        /// Its identity journaled, before it is reopened.
        Reopen,
        /// Once it is journaled and open.
        Created,
    }

    thread_local! {
        static ARMED: RefCell<Option<(usize, Stage, Hook)>> = const { RefCell::new(None) };
    }

    pub(crate) fn fail_at(stage: Stage, created: usize, hook: impl FnOnce(&Path) + 'static) {
        ARMED.with(|armed| *armed.borrow_mut() = Some((created, stage, Box::new(hook))));
    }

    pub(crate) fn disarm() {
        ARMED.with(|armed| *armed.borrow_mut() = None);
    }

    /// Each created name `name` in `dir` reaches `Identify`, `Reopen`,
    /// then `Created`.
    pub(super) fn reached(stage: Stage, dir: &File, name: &CStr) -> io::Result<()> {
        let hook = ARMED.with(|armed| {
            let mut armed = armed.borrow_mut();
            let (left, at, _) = armed.as_mut()?;
            if stage == Stage::Identify {
                *left = left.saturating_sub(1);
            }
            if *left > 0 || *at != stage {
                return None;
            }
            armed.take().map(|(_, _, hook)| hook)
        });
        match hook {
            Some(hook) => {
                let proc = OsStr::from_bytes(super::host::proc_path(dir).to_bytes()).to_owned();
                let dir = std::fs::read_link(proc)?;
                hook(&dir.join(OsStr::from_bytes(name.to_bytes())));
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
enum Parent {
    /// The directory the destination is created in.
    Outside,
    Dest,
    Staging,
    Object(u64),
}

/// A name this import created, journaled before anything else can fail.
struct Created {
    parent: Parent,
    name: CString,
    dir: bool,
    /// (st_dev, st_ino) of the object it was created for, once known.
    key: Option<HostKey>,
    /// Until then, the descriptor the creation returned, if any.
    anchor: Option<File>,
}

impl Created {
    /// The object this name was created for, if that can be established;
    /// cleanup leaves a name it cannot vouch for.
    fn identity(&self) -> Option<HostKey> {
        self.key.or_else(|| {
            let anchor = self.anchor.as_ref()?;
            host::statx(anchor).ok().map(|meta| meta.key())
        })
    }
}

/// The imported directory and everything this import created in it.
struct Tree {
    dest_parent: File,
    dest: Option<File>,
    staging: Option<File>,
    /// An `O_PATH` descriptor of each object once created.
    objects: Vec<Option<File>>,
    journal: Vec<Created>,
    armed: bool,
}

impl Tree {
    fn dir(&self, parent: Parent) -> &File {
        match parent {
            Parent::Outside => &self.dest_parent,
            Parent::Dest => self.dest.as_ref().unwrap(),
            Parent::Staging => self.staging.as_ref().unwrap(),
            Parent::Object(id) => self.objects[id as usize].as_ref().unwrap(),
        }
    }

    /// Journal `name` in `parent`, just created, before anything else can
    /// fail, with its identity: `key` when known before the name existed
    /// (a hard link), else read from `anchor` (the descriptor the creation
    /// returned, kept until then) or, for a creation that returns none,
    /// from the name at once. Then open it `O_PATH` and check it is still
    /// that object. Gives `anchor` back.
    fn created(
        &mut self,
        parent: Parent,
        name: CString,
        dir: bool,
        key: Option<HostKey>,
        anchor: Option<File>,
    ) -> io::Result<(File, Option<File>)> {
        self.journal.push(Created {
            parent,
            name,
            dir,
            key,
            anchor,
        });
        let at = self.journal.len() - 1;
        #[cfg(test)]
        faults::reached(
            faults::Stage::Identify,
            self.dir(parent),
            &self.journal[at].name,
        )?;
        let key = match (key, &self.journal[at].anchor) {
            (Some(key), _) => key,
            (None, Some(anchor)) => host::statx(anchor)?.key(),
            (None, None) => host::statx_at(self.dir(parent), &self.journal[at].name)?.key(),
        };
        let created = &mut self.journal[at];
        created.key = Some(key);
        let anchor = created.anchor.take();
        #[cfg(test)]
        faults::reached(
            faults::Stage::Reopen,
            self.dir(parent),
            &self.journal[at].name,
        )?;
        let file = host::open_path(Some(self.dir(parent)), &self.journal[at].name)?;
        if host::statx(&file)?.key() != key {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        #[cfg(test)]
        faults::reached(
            faults::Stage::Created,
            self.dir(parent),
            &self.journal[at].name,
        )?;
        Ok((file, anchor))
    }

    fn mkdir(&mut self, parent: Parent, name: CString) -> io::Result<File> {
        host::mkdir_at(self.dir(parent), &name)?;
        let (file, _) = self.created(parent, name, true, None, None)?;
        // A default ACL above may have narrowed the mode.
        host::chmod(&file, 0o700)?;
        Ok(file)
    }

    /// Give every created directory back to this process with mode 0700,
    /// then remove the journaled names newest first, each only while it
    /// still names what was created. A name whose identity is unknown (its
    /// creation returned no descriptor and reading it failed) is left.
    fn cleanup(&mut self) {
        let mut dirs: Vec<&File> = self.objects.iter().flatten().collect();
        dirs.extend(self.staging.iter());
        dirs.extend(self.dest.iter());
        // Safe because these calls only return the effective IDs.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        for dir in dirs {
            if host::statx(dir).is_ok_and(|m| m.kind() == libc::S_IFDIR) {
                let _ = host::chown(dir, uid, gid);
                let _ = host::chmod(dir, 0o700);
            }
        }
        for created in self.journal.iter().rev() {
            let Some(key) = created.identity() else {
                warn!(
                    "virtio-fs import cleanup: {:?} left, its identity is unknown",
                    created.name
                );
                continue;
            };
            let parent = self.dir(created.parent);
            match host::statx_at(parent, &created.name) {
                Ok(meta) if meta.key() == key => {
                    if let Err(e) = host::unlink_at(parent, &created.name, created.dir) {
                        warn!("virtio-fs import cleanup: {:?}: {e}", created.name);
                    }
                }
                _ => {}
            }
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        if self.armed {
            self.cleanup();
        }
    }
}

struct Share {
    root: PathBuf,
    init: Arc<[u8]>,
    options: u64,
    state: PassthroughState,
    views: Vec<ObjectView>,
    dax_pages: DaxPages,
}

/// One share's session, ready for `Fs::restore_session`.
pub struct ImportedSession {
    pub options: u64,
    pub state: PassthroughState,
    /// The views' objects, in view order.
    pub objects: Vec<RestoredObject>,
    pub dax_pages: DaxPages,
}

/// An imported archive. Dropping it before `persist` stops and joins the
/// workers of every device it holds, then removes everything the import
/// created.
pub struct ImportedArchive {
    devices: Vec<Arc<Mutex<Fs>>>,
    shares: Vec<Share>,
    tree: Tree,
}

/// Read exactly `buf.len()` payload bytes.
fn read_payload(from: &mut dyn Read, buf: &mut [u8]) -> Result<(), ArchiveError> {
    from.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => ArchiveError::Invalid("payload is truncated"),
        _ => ArchiveError::Io(e),
    })
}

/// The payload must end where the manifest says.
fn payload_ends(from: &mut dyn Read) -> Result<(), ArchiveError> {
    if from.read(&mut [0u8; 1])? != 0 {
        return invalid("payload is longer than the manifest says");
    }
    Ok(())
}

fn number(n: u64) -> CString {
    CString::new(n.to_string()).unwrap()
}

impl ImportedArchive {
    /// Import `manifest` into the new directory `dest` from its three
    /// payloads, each holding exactly the bytes the manifest describes.
    /// `dest` must not exist; it is left untouched if it does.
    pub fn import(
        manifest: &ArchiveManifest,
        dest: &Path,
        files: &mut dyn Read,
        init: &mut dyn Read,
        pages: &mut dyn Read,
    ) -> Result<ImportedArchive, ArchiveError> {
        let (_, topology) = manifest.checked()?;
        let name = match dest.file_name() {
            Some(name) => CString::new(name.as_bytes())
                .map_err(|_| ArchiveError::Invalid("destination name"))?,
            None => return invalid("destination has no final name"),
        };
        let parent = match dest.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let parent = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| ArchiveError::Invalid("destination path"))?;
        let dest_parent = host::open_at(None, &parent, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        let mut tree = Tree {
            dest_parent,
            dest: None,
            staging: None,
            objects: (0..manifest.objects.len()).map(|_| None).collect(),
            journal: Vec::new(),
            armed: true,
        };
        // The destination is journaled like everything in it.
        tree.dest = Some(tree.mkdir(Parent::Outside, name)?);

        let mut importer = Importer {
            manifest,
            topology: &topology,
            tree: &mut tree,
        };
        importer.create(files)?;
        payload_ends(files)?;
        importer.verify()?;

        let mut inits = Vec::with_capacity(manifest.inits.len());
        for &len in &manifest.inits {
            let mut buf = vec![0u8; len as usize];
            read_payload(init, &mut buf)?;
            inits.push(Arc::<[u8]>::from(buf));
        }
        payload_ends(init)?;

        let mut shares = Vec::with_capacity(manifest.shares.len());
        for share in &manifest.shares {
            let session = &share.session;
            let len = session.dax_pages.len() * DAX_PAGE_SIZE as usize;
            let mut data = Vec::new();
            data.try_reserve_exact(len)
                .map_err(|_| ArchiveError::Invalid("DAX pages do not fit in memory"))?;
            data.resize(len, 0);
            read_payload(pages, &mut data)?;
            let dax_pages = DaxPages {
                offsets: session.dax_pages.clone(),
                data,
            };
            if let Some(dax) = &session.state.dax {
                dax_pages.validate(dax)?;
            }
            shares.push(Share {
                root: importer.path(dest, share.root),
                init: inits[share.init as usize].clone(),
                options: session.options,
                state: session.state.clone(),
                views: session.views.clone(),
                dax_pages,
            });
        }
        payload_ends(pages)?;
        Ok(ImportedArchive {
            devices: Vec::new(),
            shares,
            tree,
        })
    }

    pub fn shares(&self) -> usize {
        self.shares.len()
    }

    /// The imported root directory of `share`.
    pub fn root(&self, share: usize) -> &Path {
        &self.shares[share].root
    }

    /// The init.krun `share` served.
    pub fn init_binary(&self, share: usize) -> Arc<[u8]> {
        self.shares[share].init.clone()
    }

    /// `share`'s session over the imported objects.
    pub fn session(&self, share: usize) -> io::Result<ImportedSession> {
        let share = &self.shares[share];
        let mut objects = Vec::with_capacity(share.views.len());
        for view in &share.views {
            objects.push(RestoredObject {
                file: self.tree.objects[view.object as usize]
                    .as_ref()
                    .unwrap()
                    .try_clone()?,
                guest_ino: view.ino,
                ctime: (view.ctime.sec, i64::from(view.ctime.nsec)),
            });
        }
        Ok(ImportedSession {
            options: share.options,
            state: share.state.clone(),
            objects,
            dax_pages: share.dax_pages.clone(),
        })
    }

    /// Keep `device` (restored from this archive) until the archive is
    /// persisted; dropping the archive first resets it, stopping and
    /// joining its worker before any imported object is removed.
    pub fn hold(&mut self, device: Arc<Mutex<Fs>>) {
        self.devices.push(device);
    }

    /// Keep the imported tree; the held devices are released untouched.
    pub fn persist(mut self) {
        self.tree.armed = false;
        self.devices.clear();
    }
}

impl Drop for ImportedArchive {
    fn drop(&mut self) {
        for device in self.devices.drain(..) {
            let mut device = device.lock().unwrap_or_else(|e| e.into_inner());
            device.reset();
        }
        // `tree` drops (and cleans up) after this.
    }
}

struct Importer<'a> {
    manifest: &'a ArchiveManifest,
    topology: &'a Topology,
    tree: &'a mut Tree,
}

impl<'a> Importer<'a> {
    fn object(&self, id: u64) -> &'a ArchivedObject {
        &self.manifest.objects[id as usize]
    }

    fn file(&self, id: u64) -> &File {
        self.tree.objects[id as usize].as_ref().unwrap()
    }

    /// Where `id` gets its first name: its first link or, for a tree or an
    /// object only sessions keep, the destination or the staging directory.
    fn location(&mut self, id: u64) -> io::Result<(Parent, CString)> {
        if let Some(tree) = self.manifest.trees.iter().position(|&t| t == id) {
            return Ok((Parent::Dest, number(tree as u64)));
        }
        if let Some((dir, index)) = self.topology.first[id as usize] {
            let name = self.entry_name(dir, index);
            return Ok((Parent::Object(dir), name));
        }
        if self.tree.staging.is_none() {
            let staging = self.tree.mkdir(Parent::Dest, STAGING.to_owned())?;
            self.tree.staging = Some(staging);
        }
        Ok((Parent::Staging, number(id)))
    }

    fn entry_name(&self, dir: u64, index: usize) -> CString {
        let ArchivedKind::Directory { entries } = &self.object(dir).kind else {
            unreachable!()
        };
        CString::new(entries[index].name.clone()).unwrap()
    }

    fn create(&mut self, files: &mut dyn Read) -> Result<(), ArchiveError> {
        for &dir in &self.topology.dirs {
            let (parent, name) = self.location(dir)?;
            let file = self.tree.mkdir(parent, name)?;
            self.tree.objects[dir as usize] = Some(file);
        }
        let mut buf = vec![0u8; COPY_CHUNK];
        for id in 0..self.manifest.objects.len() as u64 {
            if self.tree.objects[id as usize].is_some() {
                continue;
            }
            let (parent, name) = self.location(id)?;
            let file = match &self.object(id).kind {
                ArchivedKind::Directory { .. } => self.tree.mkdir(parent, name)?,
                ArchivedKind::Regular { size } => {
                    let out = host::open_at(
                        Some(self.tree.dir(parent)),
                        &name,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                        0o600,
                    )?;
                    let (file, out) = self.tree.created(parent, name, false, None, Some(out))?;
                    copy(files, out.as_ref().unwrap(), *size, &mut buf)?;
                    file
                }
                ArchivedKind::Symlink { target } => {
                    host::symlink_at(target, self.tree.dir(parent), &name)?;
                    let (file, _) = self.tree.created(parent, name, false, None, None)?;
                    // Checked now: reading it later would move its atime.
                    if host::readlink(&file)? != *target {
                        return Err(ArchiveError::Mismatch(id, "symlink target"));
                    }
                    file
                }
                ArchivedKind::Whiteout => {
                    host::whiteout_at(self.tree.dir(parent), &name)?;
                    self.tree.created(parent, name, false, None, None)?.0
                }
            };
            if !self.object(id).is_dir() {
                apply(&file, self.object(id))?;
            }
            self.tree.objects[id as usize] = Some(file);
        }
        for &(id, dir, index) in &self.topology.extra {
            let name = self.entry_name(dir, index);
            // The link is to the object itself, so its identity is known
            // before the name exists.
            let key = host::statx(self.file(id))?.key();
            host::link_to(self.file(id), self.file(dir), &name)?;
            self.tree
                .created(Parent::Object(dir), name, false, Some(key), None)?;
        }
        for id in 0..self.manifest.objects.len() as u64 {
            if self.object(id).is_dir() {
                apply(self.file(id), self.object(id))?;
            }
        }
        // Every staged object is held open: remove its temporary name.
        if let Some(staging) = &self.tree.staging {
            for id in 0..self.manifest.objects.len() as u64 {
                if !self.topology.reachable[id as usize] {
                    host::unlink_at(staging, &number(id), self.object(id).is_dir())?;
                }
            }
            host::unlink_at(self.tree.dir(Parent::Dest), STAGING, true)?;
        }
        Ok(())
    }

    /// Compare every object with the archive.
    fn verify(&self) -> Result<(), ArchiveError> {
        for (id, object) in self.manifest.objects.iter().enumerate() {
            let id = id as u64;
            let file = self.file(id);
            let meta = host::statx(file)?;
            let mismatch = |what| Err(ArchiveError::Mismatch(id, what));
            let kind = match object.kind {
                ArchivedKind::Directory { .. } => libc::S_IFDIR,
                ArchivedKind::Regular { size } => {
                    if meta.size != size {
                        return mismatch("size");
                    }
                    libc::S_IFREG
                }
                ArchivedKind::Symlink { .. } => libc::S_IFLNK,
                ArchivedKind::Whiteout => {
                    if meta.rdev != 0 {
                        return mismatch("device number");
                    }
                    libc::S_IFCHR
                }
            };
            if meta.kind() != kind {
                return mismatch("file type");
            }
            if kind != libc::S_IFLNK && meta.mode & 0o7777 != object.mode {
                return mismatch("mode");
            }
            if (meta.uid, meta.gid) != (object.uid, object.gid) {
                return mismatch("owner");
            }
            if (meta.atime, meta.mtime) != (object.atime, object.mtime) {
                return mismatch("timestamps");
            }
            if !self.topology.reachable[id as usize] && meta.nlink != 0 {
                return mismatch("link count");
            }
            if host::xattrs(file)? != object.xattrs {
                return mismatch("extended attributes");
            }
        }
        Ok(())
    }

    /// The imported path of directory `id`.
    fn path(&self, dest: &Path, id: u64) -> PathBuf {
        let mut names = Vec::new();
        let mut at = id;
        while let Some((dir, index)) = self.topology.first[at as usize] {
            names.push(self.entry_name(dir, index));
            at = dir;
        }
        let tree = self.manifest.trees.iter().position(|&t| t == at).unwrap();
        let mut path = dest.join(tree.to_string());
        for name in names.iter().rev() {
            path.push(OsStr::from_bytes(name.as_bytes()));
        }
        path
    }
}

/// Write `size` payload bytes into the new file `out`, leaving all-zero
/// chunks as holes.
fn copy(from: &mut dyn Read, out: &File, size: u64, buf: &mut [u8]) -> Result<(), ArchiveError> {
    let mut offset = 0;
    while offset < size {
        let len = (size - offset).min(buf.len() as u64) as usize;
        read_payload(from, &mut buf[..len])?;
        if buf[..len].iter().any(|&b| b != 0) {
            out.write_all_at(&buf[..len], offset)?;
        }
        offset += len as u64;
    }
    out.set_len(size)?;
    Ok(())
}

/// Owner, xattrs, mode, then times: chown clears set-ID bits and file
/// capabilities, an access ACL rewrites the group bits, and nothing after
/// the times touches them.
fn apply(file: &File, object: &ArchivedObject) -> Result<(), ArchiveError> {
    host::chown(file, object.uid, object.gid)?;
    for present in host::xattrs(file)? {
        if !object.xattrs.iter().any(|x| x.name == present.name) {
            host::remove_xattr(file, &present.name)?;
        }
    }
    for xattr in &object.xattrs {
        host::set_xattr(file, &xattr.name, &xattr.value)?;
    }
    if !matches!(object.kind, ArchivedKind::Symlink { .. }) {
        host::chmod(file, object.mode)?;
    }
    host::set_times(file, object.atime, object.mtime)?;
    Ok(())
}
