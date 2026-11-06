// SPDX-License-Identifier: Apache-2.0

//! Rebinding to the same host directory, with guest-visible errors for objects
//! that disappeared or were replaced. File contents intentionally remain live.
//! The owner must stop the fs worker and exclude exported/DAX aliases first.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    /// Relative to the share root. None represents an unreopenable object.
    pub path: Option<Vec<u8>>,
    pub dev: u64,
    pub ino: u64,
    pub kind: u32,
    pub birth_time: bool,
    pub identity_time: [i64; 2],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InodeState {
    pub inode: u64,
    pub references: u64,
    pub object: Object,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleState {
    pub handle: u64,
    pub inode: u64,
    pub object: Object,
    pub flags: i32,
    pub offset: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsState {
    pub next_inode: u64,
    pub next_handle: u64,
    pub writeback: bool,
    pub announce_submounts: bool,
    pub inodes: Vec<InodeState>,
    pub handles: Vec<HandleState>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

impl Object {
    fn identity_time(file: &File) -> io::Result<(bool, [i64; 2])> {
        let mut stat = MaybeUninit::<libc::statx>::zeroed();
        if unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS | libc::STATX_BTIME,
                stat.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let birth = stat.stx_mask & libc::STATX_BTIME != 0;
        // Birth time distinguishes a reused inode without treating ordinary
        // writes as replacement. On filesystems lacking it, changed objects
        // conservatively become stale rather than binding a recycled inode.
        let time = if birth {
            stat.stx_btime
        } else {
            stat.stx_ctime
        };
        Ok((birth, [time.tv_sec, i64::from(time.tv_nsec)]))
    }

    fn capture(file: &File, root: &Path) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let (birth_time, identity_time) = Self::identity_time(file)?;
        let path = if metadata.nlink() == 0 {
            None
        } else {
            std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .ok()
                .and_then(|path| {
                    path.strip_prefix(root)
                        .ok()
                        .map(|p| p.as_os_str().as_bytes().to_vec())
                })
        };
        Ok(Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            kind: metadata.mode() & libc::S_IFMT,
            birth_time,
            identity_time,
        })
    }

    fn validate(&self) -> io::Result<()> {
        if let Some(bytes) = &self.path {
            let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
            if bytes.contains(&0)
                || path
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(invalid("checkpoint object path escapes share root"));
            }
        }
        Ok(())
    }

    fn reopen(&self, root: &File) -> io::Result<File> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let path = CString::new(if path.is_empty() {
            b".".as_slice()
        } else {
            path
        })
        .map_err(|_| invalid("NUL in checkpoint path"))?;
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            // RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS. Never follow a changed
            // intermediate component out of the caller-bound share root.
            resolve: 0x08 | 0x02,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how,
                size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd as RawFd) };
        let metadata = file.metadata()?;
        if metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || metadata.mode() & libc::S_IFMT != self.kind
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if Self::identity_time(&file)? != (self.birth_time, self.identity_time) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(file)
    }
}

impl FsState {
    pub fn validate(&self) -> io::Result<()> {
        let mut inodes = std::collections::HashSet::new();
        let mut handles = std::collections::HashSet::new();
        if self.next_inode < fuse::ROOT_ID + 2 || self.next_handle == 0 {
            return Err(invalid("invalid checkpoint inode/handle allocator"));
        }
        for inode in &self.inodes {
            inode.object.validate()?;
            if inode.inode == 0
                || inode.inode == fuse::ROOT_ID + 1
                || inode.inode >= self.next_inode
                || inode.references == 0
                || !inodes.insert(inode.inode)
            {
                return Err(invalid("invalid or duplicate checkpoint inode"));
            }
        }
        for handle in &self.handles {
            handle.object.validate()?;
            if handle.handle == 0
                || handle.handle >= self.next_handle
                || !handles.insert(handle.handle)
                || handle.inode == 0
                || handle.inode >= self.next_inode
                || handle.offset < 0
                || handle.flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL | libc::O_PATH) != 0
            {
                return Err(invalid("invalid checkpoint handle or reopen flags"));
            }
        }
        Ok(())
    }
}

impl PassthroughFs {
    pub fn save_state(&self) -> io::Result<FsState> {
        if self
            .cfg
            .export_table
            .as_ref()
            .is_some_and(|table| !table.lock().unwrap().is_empty())
        {
            return Err(invalid(
                "exported virtio-fs aliases require their owner to participate",
            ));
        }
        let root = match std::fs::canonicalize(&self.cfg.root_dir) {
            Ok(root) => root,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && self.cfg.allow_root_dir_delete =>
            {
                // init.krun removes its private bootstrap root after pivoting
                // to a block rootfs. Its old node/handle IDs stay stale.
                PathBuf::from(&self.cfg.root_dir)
            }
            Err(error) => return Err(error),
        };
        let mut inodes = Vec::new();
        for inode in self.inodes.read().unwrap().values() {
            inodes.push(InodeState {
                inode: inode.inode,
                references: inode.refcount.load(Ordering::Acquire),
                object: Object::capture(&inode.file, &root)?,
            });
        }
        let mut handles = Vec::new();
        for (&id, handle) in self.handles.read().unwrap().iter() {
            if handle.exported.load(Ordering::Acquire) {
                return Err(invalid("exported virtio-fs handle cannot be captured"));
            }
            let file = handle.file.read().unwrap();
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let offset = unsafe { libc::lseek64(file.as_raw_fd(), 0, libc::SEEK_CUR) };
            if offset < 0 {
                return Err(io::Error::last_os_error());
            }
            if flags & libc::O_ACCMODE != libc::O_RDONLY {
                file.sync_all()?;
            }
            handles.push(HandleState {
                handle: id,
                inode: handle.inode,
                object: Object::capture(&file, &root)?,
                flags,
                offset,
            });
        }
        let state = FsState {
            next_inode: self.next_inode.load(Ordering::Acquire),
            next_handle: self.next_handle.load(Ordering::Acquire),
            writeback: self.writeback.load(Ordering::Acquire),
            announce_submounts: self.announce_submounts.load(Ordering::Acquire),
            inodes,
            handles,
        };
        state.validate()?;
        Ok(state)
    }

    /// Missing objects are omitted while allocator positions are retained. The
    /// existing FUSE dispatch then returns EBADF for their old node/handle IDs;
    /// future lookups can discover new objects without reusing those old IDs.
    pub fn restore_state(&mut self, state: &FsState) -> io::Result<()> {
        state.validate()?;
        if self.inodes.read().unwrap().values().next().is_some()
            || !self.handles.read().unwrap().is_empty()
        {
            return Err(invalid("virtio-fs restore requires a fresh server"));
        }
        let root_path = CString::new(self.cfg.root_dir.as_bytes())
            .map_err(|_| invalid("invalid share root"))?;
        let fd = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let root = unsafe { File::from_raw_fd(fd) };
        // Distinguish an unsupported host from a missing individual file.
        Object::capture(&root, &std::fs::canonicalize(&self.cfg.root_dir)?)?.reopen(&root)?;
        let mut inodes = MultikeyBTreeMap::new();
        let mut handles = BTreeMap::new();
        for saved in &state.inodes {
            if let Ok(file) = saved.object.reopen(&root) {
                let (st, mnt_id) = statx(&file)?;
                let key = InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                    mnt_id,
                };
                if inodes.get_alt(&key).is_some() {
                    return Err(invalid("duplicate host inode in checkpoint"));
                }
                inodes.insert(
                    saved.inode,
                    key,
                    Arc::new(InodeData {
                        inode: saved.inode,
                        file,
                        dev: st.st_dev,
                        mnt_id,
                        refcount: AtomicU64::new(saved.references),
                    }),
                );
            }
        }
        for saved in &state.handles {
            let Ok(object) = saved.object.reopen(&root) else {
                continue;
            };
            // Open through the pinned O_PATH descriptor, not the path again.
            // Never replay O_CREAT/O_TRUNC or silently bind a replacement inode.
            let path = CString::new(format!("/proc/self/fd/{}", object.as_raw_fd())).unwrap();
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    (saved.flags & !libc::O_NOFOLLOW) | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                continue;
            }
            let file = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::lseek64(fd, saved.offset, libc::SEEK_SET) } < 0 {
                continue;
            }
            handles.insert(
                saved.handle,
                Arc::new(HandleData {
                    inode: saved.inode,
                    file: RwLock::new(file),
                    exported: AtomicBool::new(false),
                }),
            );
        }
        *self.inodes.write().unwrap() = inodes;
        *self.handles.write().unwrap() = handles;
        self.next_inode.store(state.next_inode, Ordering::Release);
        self.next_handle.store(state.next_handle, Ordering::Release);
        self.writeback.store(state.writeback, Ordering::Release);
        self.announce_submounts
            .store(state.announce_submounts, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use utils::tempdir::TempDir;

    struct Output<'a>(&'a mut Vec<u8>);
    impl Write for Output<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ZeroCopyWriter for Output<'_> {
        fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let mut bytes = vec![0; count];
            let len = file.read_at(&mut bytes, offset)?;
            self.0.extend_from_slice(&bytes[..len]);
            Ok(len)
        }
    }

    fn context() -> Context {
        Context {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            pid: unsafe { libc::getpid() },
        }
    }

    #[test]
    fn restores_live_contents_and_reports_missing_or_replaced_handles_to_guest() {
        let dir = TempDir::new().unwrap();
        let root = dir.as_path();
        std::fs::write(root.join("kept"), b"before").unwrap();
        std::fs::write(root.join("replaced"), b"original").unwrap();
        let cfg = Config {
            root_dir: root.to_str().unwrap().into(),
            ..Default::default()
        };
        let source = PassthroughFs::new(cfg.clone()).unwrap();
        source.init(FsOptions::empty()).unwrap();
        let kept = source
            .lookup(context(), fuse::ROOT_ID, c"kept")
            .unwrap()
            .inode;
        let missing = source
            .lookup(context(), fuse::ROOT_ID, c"replaced")
            .unwrap()
            .inode;
        let kept_handle = source
            .open(context(), kept, false, libc::O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        let missing_handle = source
            .open(context(), missing, false, libc::O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        let state = source.save_state().unwrap();

        std::fs::write(root.join("kept"), b"current").unwrap();
        std::fs::remove_file(root.join("replaced")).unwrap();
        std::fs::write(root.join("replaced"), b"different inode").unwrap();
        drop(source);
        let mut target = PassthroughFs::new(cfg.clone()).unwrap();
        target.restore_state(&state).unwrap();
        let mut output = Vec::new();
        target
            .read(
                context(),
                kept,
                kept_handle,
                Output(&mut output),
                64,
                0,
                None,
                0,
            )
            .unwrap();
        assert_eq!(output, b"current");
        assert_eq!(
            target
                .read(
                    context(),
                    missing,
                    missing_handle,
                    Output(&mut output),
                    64,
                    0,
                    None,
                    0
                )
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            target.do_getattr(missing).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        let replacement = target
            .lookup(context(), fuse::ROOT_ID, c"replaced")
            .unwrap()
            .inode;
        assert!(replacement >= state.next_inode);
        assert_ne!(replacement, missing);
        let repeated = target.save_state().unwrap();
        let mut next = PassthroughFs::new(cfg).unwrap();
        next.restore_state(&repeated).unwrap();
        assert_eq!(next.next_inode.load(Ordering::Relaxed), repeated.next_inode);
    }

    #[test]
    fn rejects_reopen_side_effects_and_escaping_paths() {
        let dir = TempDir::new().unwrap();
        let cfg = Config {
            root_dir: dir.as_path().to_str().unwrap().into(),
            ..Default::default()
        };
        let source = PassthroughFs::new(cfg).unwrap();
        source.init(FsOptions::empty()).unwrap();
        let mut state = source.save_state().unwrap();
        state.inodes[0].object.path = Some(b"../outside".to_vec());
        assert!(state.validate().is_err());
        state.inodes[0].object.path = Some(Vec::new());
        state.next_handle = 2;
        state.handles.push(HandleState {
            handle: 1,
            inode: 1,
            object: state.inodes[0].object.clone(),
            flags: libc::O_TRUNC | libc::O_WRONLY,
            offset: 0,
        });
        assert!(state.validate().is_err());
    }
}
