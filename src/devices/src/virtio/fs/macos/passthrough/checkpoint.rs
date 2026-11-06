// SPDX-License-Identifier: Apache-2.0
//! Reopen macOS shares by path and birth-time identity, preserving guest IDs.
use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
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
    directory: DirStream,
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
    fn capture(file: &File, root: &Path) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let mut path = [0i8; libc::PATH_MAX as usize];
        let path = if metadata.nlink() != 0
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } == 0
        {
            let path = Path::new(std::ffi::OsStr::from_bytes(
                unsafe { CStr::from_ptr(path.as_ptr()) }.to_bytes(),
            ));
            path.strip_prefix(root)
                .ok()
                .map(|p| p.as_os_str().as_bytes().to_vec())
        } else {
            None
        };
        use std::os::macos::fs::MetadataExt as MacMetadata;
        Ok(Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            kind: metadata.mode() & u32::from(libc::S_IFMT),
            birth_time: true,
            identity_time: [metadata.st_birthtime(), metadata.st_birthtime_nsec()],
        })
    }
    fn validate(&self) -> io::Result<()> {
        if let Some(path) = &self.path {
            if path.contains(&0)
                || Path::new(std::ffi::OsStr::from_bytes(path))
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(invalid("checkpoint path escapes share root"));
            }
        }
        Ok(())
    }
    fn reopen(&self, root: &File, flags: i32) -> io::Result<File> {
        self.validate()?;
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let components: Vec<_> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        let mut parent = root.try_clone()?;
        for (index, component) in components.iter().enumerate() {
            let name = CString::new(*component)?;
            let flags = if index + 1 == components.len() {
                flags
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY
            };
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            parent = unsafe { File::from_raw_fd(fd) };
        }
        use std::os::macos::fs::MetadataExt as MacMetadata;
        let metadata = parent.metadata()?;
        if metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || metadata.mode() & u32::from(libc::S_IFMT) != self.kind
            || !self.birth_time
            || self.identity_time != [metadata.st_birthtime(), metadata.st_birthtime_nsec()]
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(parent)
    }
}
impl FsState {
    pub fn validate(&self) -> io::Result<()> {
        let mut inodes = std::collections::HashSet::new();
        let mut handles = std::collections::HashSet::new();
        if self.next_inode < fuse::ROOT_ID + 2 || self.next_handle == 0 {
            return Err(invalid("invalid fs allocators"));
        }
        for inode in &self.inodes {
            inode.object.validate()?;
            if inode.inode == 0
                || inode.inode == fuse::ROOT_ID + 1
                || inode.inode >= self.next_inode
                || inode.references == 0
                || !inodes.insert(inode.inode)
            {
                return Err(invalid("invalid fs inode"));
            }
        }
        for handle in &self.handles {
            handle.object.validate()?;
            if handle.handle == 0
                || handle.handle >= self.next_handle
                || handle.inode == 0
                || handle.inode >= self.next_inode
                || !handles.insert(handle.handle)
                || handle.offset < 0
                || handle.flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL) != 0
            {
                return Err(invalid("invalid fs handle"));
            }
        }
        Ok(())
    }
}
impl PassthroughFs {
    pub fn save_state(&self) -> io::Result<FsState> {
        if !self.map_windows.lock().unwrap().is_empty()
            || self
                .cfg
                .export_table
                .as_ref()
                .is_some_and(|t| !t.lock().unwrap().is_empty())
        {
            return Err(invalid("fs mappings cannot be checkpointed"));
        }
        let root = match std::fs::canonicalize(&self.cfg.root_dir) {
            Ok(root) => root,
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.cfg.allow_root_dir_delete => {
                Path::new(&self.cfg.root_dir).to_path_buf()
            }
            Err(e) => return Err(e),
        };
        let mut inodes = Vec::new();
        for inode in self.inodes.read().unwrap().values() {
            let path = CString::new(format!("/.vol/{}/{}", inode.dev, inode.ino)).unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC) };
            let object = if fd >= 0 {
                Object::capture(&unsafe { File::from_raw_fd(fd) }, &root)?
            } else {
                Object {
                    path: None,
                    dev: inode.dev as u64,
                    ino: inode.ino,
                    kind: 0,
                    birth_time: true,
                    identity_time: [0; 2],
                }
            };
            inodes.push(InodeState {
                inode: inode.inode,
                references: inode.refcount.load(Ordering::Acquire),
                object,
            });
        }
        let mut handles = Vec::new();
        for (&handle, data) in self.handles.read().unwrap().iter() {
            let file = data.file.read().unwrap();
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            let offset = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
            if flags < 0 || offset < 0 {
                return Err(io::Error::last_os_error());
            }
            if flags & libc::O_ACCMODE != libc::O_RDONLY {
                file.sync_all()?;
            }
            handles.push(HandleState {
                handle,
                inode: data.inode,
                object: Object::capture(&file, &root)?,
                flags: flags & !(libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL),
                offset,
                directory: data.dirstream.lock().unwrap().clone(),
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
    pub fn restore_state(&mut self, state: &FsState) -> io::Result<()> {
        state.validate()?;
        if self.inodes.read().unwrap().values().next().is_some()
            || !self.handles.read().unwrap().is_empty()
        {
            return Err(invalid("fs restore requires a fresh server"));
        }
        let root = File::open(&self.cfg.root_dir)?;
        let mut inodes = MultikeyBTreeMap::new();
        let mut handles = BTreeMap::new();
        for saved in &state.inodes {
            if let Ok(file) = saved.object.reopen(&root, libc::O_SYMLINK) {
                let metadata = file.metadata()?;
                let key = InodeAltKey {
                    ino: metadata.ino(),
                    dev: metadata.dev() as i32,
                };
                if inodes.get_alt(&key).is_some() {
                    return Err(invalid("duplicate fs object"));
                }
                inodes.insert(
                    saved.inode,
                    key,
                    Arc::new(InodeData {
                        inode: saved.inode,
                        ino: key.ino,
                        dev: key.dev,
                        refcount: AtomicU64::new(saved.references),
                        unlinked_fd: AtomicI64::new(-1),
                    }),
                );
            }
        }
        for saved in &state.handles {
            if let Ok(file) = saved.object.reopen(&root, saved.flags) {
                if unsafe { libc::lseek(file.as_raw_fd(), saved.offset, libc::SEEK_SET) } < 0 {
                    continue;
                }
                handles.insert(
                    saved.handle,
                    Arc::new(HandleData {
                        inode: saved.inode,
                        file: RwLock::new(file),
                        dirstream: Mutex::new(saved.directory.clone()),
                    }),
                );
            }
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
}
