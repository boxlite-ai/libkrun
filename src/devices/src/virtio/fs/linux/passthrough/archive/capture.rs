// SPDX-License-Identifier: Apache-2.0

//! Capturing shares: metadata now, file bytes when the payload is written.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use super::super::snapshot::HostKey;
use super::super::{
    fuse, Config, DaxWindow, PassthroughCheckpoint, PassthroughFs, PassthroughSnapshotError,
};
use super::host::{self, Meta};
use super::{
    subtree, valid_entry_name, ArchiveError, ArchiveManifest, ArchivedEntry, ArchivedKind,
    ArchivedObject, ArchivedSession, ArchivedShare, ArchivedTime, ObjectView, PayloadLengths,
    MAX_SYMLINK_LEN,
};

/// Chunk size for streaming file bytes.
const COPY_CHUNK: usize = 64 * 1024;

enum Server<'a> {
    /// The share an activated device serves.
    Live(&'a PassthroughFs),
    /// A fresh share standing in for a device without a session.
    Unactivated(PassthroughFs),
}

/// One share to archive: its root and session.
pub struct ShareSource<'a> {
    root_dir: &'a Path,
    server: Server<'a>,
    options: u64,
    checkpoint: PassthroughCheckpoint,
}

impl<'a> ShareSource<'a> {
    /// A share whose device holds no session (never activated, or reset):
    /// the pre-FUSE_INIT session of a fresh share from `cfg`, with the DAX
    /// window at `window` as the guest left it.
    pub fn inactive(
        cfg: &'a Config,
        window: Option<DaxWindow>,
    ) -> Result<Self, PassthroughSnapshotError> {
        // The stand-in must not take over a caller's /proc/self/fd.
        let fs = PassthroughFs::new(Config {
            proc_sfd_rawfd: None,
            ..cfg.clone()
        })?;
        let checkpoint = fs.checkpoint_with_dax(window)?;
        Ok(ShareSource {
            root_dir: &cfg.root_dir,
            server: Server::Unactivated(fs),
            options: 0,
            checkpoint,
        })
    }

    /// An activated share: `checkpoint` of `fs`, captured with its worker
    /// frozen, and the FUSE options its FUSE_INIT negotiated.
    pub fn active(
        cfg: &'a Config,
        fs: &'a PassthroughFs,
        options: u64,
        checkpoint: PassthroughCheckpoint,
    ) -> Self {
        ShareSource {
            root_dir: &cfg.root_dir,
            server: Server::Live(fs),
            options,
            checkpoint,
        }
    }

    fn fs(&self) -> &PassthroughFs {
        match &self.server {
            Server::Live(fs) => fs,
            Server::Unactivated(fs) => fs,
        }
    }
}

/// A captured archive. It holds one descriptor per object until the
/// payloads are written; the source must not change in between (the VM
/// stays paused and no host writer runs), and every regular file is checked
/// against its capture while its bytes are written.
pub struct ShareArchive {
    manifest: ArchiveManifest,
    files: Vec<File>,
    /// The host object of each archived object as captured.
    sources: Vec<Meta>,
    inits: Vec<Arc<[u8]>>,
    /// The DAX page bytes of each session, in share order.
    pages: Vec<Vec<u8>>,
    lengths: PayloadLengths,
}

#[derive(Default)]
struct Builder {
    objects: Vec<ArchivedObject>,
    files: Vec<File>,
    sources: Vec<Meta>,
    index: HashMap<HostKey, u64>,
    listed: Vec<bool>,
    /// The entry that links each directory reached from a parent.
    parent: HashMap<u64, (u64, Vec<u8>)>,
}

fn unsupported<T>(why: &'static str) -> Result<T, ArchiveError> {
    Err(ArchiveError::Unsupported(why))
}

impl Builder {
    /// The archived object of host object `file` (`meta` its statx taken
    /// before anything reads it), captured on first sight, when the table
    /// keeps its own descriptor of it.
    fn object(&mut self, file: &File, meta: Meta) -> Result<u64, ArchiveError> {
        if let Some(&id) = self.index.get(&meta.key()) {
            return Ok(id);
        }
        let xattrs = host::xattrs(file)?;
        let kind = match meta.kind() {
            libc::S_IFDIR => ArchivedKind::Directory {
                entries: Vec::new(),
            },
            libc::S_IFREG => ArchivedKind::Regular { size: meta.size },
            libc::S_IFLNK => {
                // readlink may update the symlink's atime; it was captured
                // above.
                let target = host::readlink(file)?;
                if target.len() > MAX_SYMLINK_LEN {
                    return unsupported("symlink target length");
                }
                ArchivedKind::Symlink { target }
            }
            libc::S_IFCHR if meta.rdev == 0 => ArchivedKind::Whiteout,
            _ => return unsupported("special file (FIFO, socket or device)"),
        };
        let id = self.objects.len() as u64;
        self.objects.push(ArchivedObject {
            kind,
            mode: meta.mode & 0o7777,
            uid: meta.uid,
            gid: meta.gid,
            atime: meta.atime,
            mtime: meta.mtime,
            xattrs,
        });
        self.files.push(file.try_clone()?);
        self.sources.push(meta);
        self.listed.push(false);
        self.index.insert(meta.key(), id);
        Ok(id)
    }

    fn is_dir(&self, id: u64) -> bool {
        matches!(
            self.objects[id as usize].kind,
            ArchivedKind::Directory { .. }
        )
    }

    /// Capture every object reachable from `root`, the share's own
    /// descriptor of its root directory `id`, on its mount. The share is
    /// walked through its own descriptors only: a directory another share
    /// already listed, maybe through another mount of it (a bind mount), is
    /// listed again as this share sees it, submounts included, and must
    /// hold the same entries.
    fn walk(&mut self, id: u64, root: File, mnt_id: u64) -> Result<(), ArchiveError> {
        let mut seen = HashSet::new();
        let mut stack = vec![(id, root)];
        while let Some((dir, dir_file)) = stack.pop() {
            if !seen.insert(dir) {
                return unsupported("directory cycle");
            }
            let mut entries = Vec::new();
            for name in host::list(&dir_file)? {
                if !valid_entry_name(&name) {
                    return unsupported("entry name");
                }
                let cname = CString::new(name.clone()).unwrap();
                let file = host::open_path(Some(&dir_file), &cname)?;
                let meta = host::statx(&file)?;
                if meta.mnt_id != mnt_id {
                    return unsupported("host submount inside a share");
                }
                let child = self.object(&file, meta)?;
                if self.is_dir(child) {
                    match self.parent.entry(child) {
                        Entry::Occupied(link) if *link.get() != (dir, name.clone()) => {
                            return unsupported("directory with several parents");
                        }
                        Entry::Occupied(_) => {}
                        Entry::Vacant(link) => {
                            link.insert((dir, name.clone()));
                        }
                    }
                    stack.push((child, file));
                }
                entries.push(ArchivedEntry {
                    name,
                    object: child,
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            let listed = &mut self.listed[dir as usize];
            let ArchivedKind::Directory { entries: archived } =
                &mut self.objects[dir as usize].kind
            else {
                unreachable!()
            };
            if !*listed {
                *archived = entries;
                *listed = true;
            } else if *archived != entries {
                return unsupported("directory that shares see differently");
            }
        }
        Ok(())
    }

    /// The root directory of a share, the share's own descriptor of it and
    /// its mount: the root node's object once the guest mounted it, else
    /// `root_dir`.
    fn root(&mut self, source: &ShareSource) -> Result<(u64, File, u64), ArchiveError> {
        let checkpoint = &source.checkpoint;
        let root_node = checkpoint
            .state
            .nodes
            .iter()
            .find(|node| node.inode == fuse::ROOT_ID)
            .map(|node| &checkpoint.objects[node.object as usize].file);
        let file = match root_node {
            Some(file) => file.try_clone()?,
            None => {
                let path = CString::new(source.root_dir.as_os_str().as_bytes())
                    .map_err(|_| ArchiveError::Unsupported("share root path"))?;
                host::open_at(None, &path, libc::O_PATH | libc::O_DIRECTORY, 0)?
            }
        };
        let meta = host::statx(&file)?;
        if meta.kind() != libc::S_IFDIR || meta.nlink == 0 {
            return unsupported("share root that is no linked directory");
        }
        Ok((self.object(&file, meta)?, file, meta.mnt_id))
    }

    /// The archived object of every session object; an object outside
    /// every tree must be unlinked (only the share keeps it alive).
    fn session_objects(
        &mut self,
        checkpoint: &PassthroughCheckpoint,
    ) -> Result<Vec<ObjectView>, ArchiveError> {
        let mut views = Vec::with_capacity(checkpoint.objects.len());
        for object in &checkpoint.objects {
            let id = match self.index.get(&(object.dev, object.ino)) {
                Some(&id) => id,
                None => {
                    let meta = host::statx(&object.file)?;
                    if meta.nlink != 0 {
                        return unsupported("session object linked outside every share");
                    }
                    self.object(&object.file, meta)?
                }
            };
            views.push(ObjectView {
                object: id,
                ino: object.guest_ino,
                ctime: ArchivedTime {
                    sec: object.ctime.0,
                    nsec: object.ctime.1 as u32,
                },
            });
        }
        Ok(views)
    }
}

impl ShareArchive {
    /// Capture `shares` (every share of one VM, activated ones frozen).
    /// Reads metadata, directories, symlinks and xattrs now; nothing of the
    /// source is modified except, without `O_NOATIME` permission, directory
    /// atimes, and symlink atimes that readlink updates. Refused before
    /// anything is read unless the caller has CAP_SYS_ADMIN in the initial
    /// user namespace: elsewhere `trusted.*` xattrs would be silently
    /// missing.
    pub fn capture(shares: Vec<ShareSource<'_>>) -> Result<ShareArchive, ArchiveError> {
        if !host::sees_every_xattr()? {
            return unsupported(
                "capture without CAP_SYS_ADMIN in the initial user namespace (trusted.* xattrs hidden)",
            );
        }
        let mut builder = Builder::default();
        let mut roots = Vec::with_capacity(shares.len());
        for share in &shares {
            let (root, file, mnt_id) = builder.root(share)?;
            builder.walk(root, file, mnt_id)?;
            roots.push(root);
        }

        let mut inits: Vec<Arc<[u8]>> = Vec::new();
        let mut archived = Vec::with_capacity(shares.len());
        let mut pages = Vec::new();
        for (share, &root) in shares.iter().zip(&roots) {
            let checkpoint = &share.checkpoint;
            let init = match inits.iter().position(|i| *i == checkpoint.init_binary) {
                Some(index) => index,
                None => {
                    inits.push(checkpoint.init_binary.clone());
                    inits.len() - 1
                }
            };
            let mut views = builder.session_objects(checkpoint)?;
            let viewed: HashSet<u64> = views.iter().map(|v| v.object).collect();
            for object in subtree(&builder.objects, root) {
                if viewed.contains(&object) {
                    continue;
                }
                let meta = &builder.sources[object as usize];
                let (ino, ctime) = share
                    .fs()
                    .guest_view(meta.key(), (meta.ctime.sec, meta.ctime.nsec as i64));
                views.push(ObjectView {
                    object,
                    ino,
                    ctime: ArchivedTime {
                        sec: ctime.0,
                        nsec: ctime.1 as u32,
                    },
                });
            }
            let mut state = checkpoint.state.clone();
            // Projecting objects the guest never looked up may have taken
            // synthetic numbers.
            state.next_synthetic_ino = share.fs().next_synthetic_ino();
            pages.push(checkpoint.dax_pages.data.clone());
            archived.push(ArchivedShare {
                root,
                init: init as u64,
                session: ArchivedSession {
                    options: share.options,
                    state,
                    views,
                    dax_pages: checkpoint.dax_pages.offsets.clone(),
                },
            });
        }

        let mut trees = Vec::new();
        for &root in &roots {
            if !builder.parent.contains_key(&root) && !trees.contains(&root) {
                trees.push(root);
            }
        }
        let manifest = ArchiveManifest {
            objects: builder.objects,
            trees,
            shares: archived,
            inits: inits.iter().map(|i| i.len() as u64).collect(),
        };
        // The same checks an import makes.
        let lengths = manifest.validate()?;
        Ok(ShareArchive {
            manifest,
            files: builder.files,
            sources: builder.sources,
            inits,
            pages,
            lengths,
        })
    }

    pub fn manifest(&self) -> &ArchiveManifest {
        &self.manifest
    }

    pub fn lengths(&self) -> PayloadLengths {
        self.lengths
    }

    /// Fail unless `file` is still object `id` as captured.
    fn unchanged(&self, id: usize, file: &File) -> Result<(), ArchiveError> {
        let now = host::statx(file)?;
        let then = &self.sources[id];
        if now.key() != then.key()
            || now.size != then.size
            || now.mtime != then.mtime
            || now.ctime != then.ctime
        {
            return Err(ArchiveError::Changed(id as u64));
        }
        Ok(())
    }

    /// Stream every regular file's bytes, in object order, read through a
    /// new `O_NOATIME` description where the host allows it. A file whose
    /// size, mtime or ctime moved since the capture fails the write.
    pub fn write_files(&self, out: &mut dyn Write) -> Result<(), ArchiveError> {
        let mut buf = vec![0u8; COPY_CHUNK];
        for (id, object) in self.manifest.objects.iter().enumerate() {
            let ArchivedKind::Regular { size } = object.kind else {
                continue;
            };
            let mut file = host::reopen_noatime(&self.files[id], libc::O_RDONLY)?;
            self.unchanged(id, &file)?;
            let mut left = size;
            while left > 0 {
                let want = left.min(COPY_CHUNK as u64) as usize;
                let got = file.read(&mut buf[..want])?;
                if got == 0 {
                    return Err(ArchiveError::Changed(id as u64));
                }
                out.write_all(&buf[..got])?;
                left -= got as u64;
            }
            if file.read(&mut buf[..1])? != 0 {
                return Err(ArchiveError::Changed(id as u64));
            }
            self.unchanged(id, &file)?;
        }
        Ok(())
    }

    /// Every distinct init.krun, in manifest order.
    pub fn write_init(&self, out: &mut dyn Write) -> io::Result<()> {
        for init in &self.inits {
            out.write_all(init)?;
        }
        Ok(())
    }

    /// Every session's DAX pages, in share order.
    pub fn write_pages(&self, out: &mut dyn Write) -> io::Result<()> {
        for pages in &self.pages {
            out.write_all(pages)?;
        }
        Ok(())
    }
}
