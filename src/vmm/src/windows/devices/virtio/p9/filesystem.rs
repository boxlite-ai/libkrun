//! Host filesystem backend for 9P2000.L.
//!
//! Maps 9P operations to `std::fs` operations on a shared host directory.
//! Each FID maps to an open file or directory path. Security: all paths
//! are resolved relative to the root directory; traversal outside is rejected.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::protocol::{ByteWriter, P9Attr, Qid, QT_DIR, QT_FILE, QT_SYMLINK};

/// Linux errno constants used in Rlerror responses.
pub const ENOENT: u32 = 2;
pub const EIO: u32 = 5;
pub const EBADF: u32 = 9;
pub const EACCES: u32 = 13;
pub const EEXIST: u32 = 17;
pub const ENOTDIR: u32 = 20;
pub const EINVAL: u32 = 22;
pub const ENOSPC: u32 = 28;
pub const ENOTEMPTY: u32 = 39;

/// Linux open flags.
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;

/// Getattr request mask bits (P9_GETATTR_*).
const P9_GETATTR_MODE: u64 = 0x00000001;
const P9_GETATTR_NLINK: u64 = 0x00000002;
const P9_GETATTR_UID: u64 = 0x00000004;
const P9_GETATTR_GID: u64 = 0x00000008;
const P9_GETATTR_RDEV: u64 = 0x00000010;
const P9_GETATTR_ATIME: u64 = 0x00000020;
const P9_GETATTR_MTIME: u64 = 0x00000040;
const P9_GETATTR_CTIME: u64 = 0x00000080;
const P9_GETATTR_SIZE: u64 = 0x00000200;
const P9_GETATTR_BLOCKS: u64 = 0x00000400;
const P9_GETATTR_BTIME: u64 = 0x00000800;
const P9_GETATTR_GEN: u64 = 0x00001000;
const P9_GETATTR_DATA_VERSION: u64 = 0x00002000;
/// Convenience mask for "all basic fields".
const P9_GETATTR_BASIC: u64 = P9_GETATTR_MODE
    | P9_GETATTR_NLINK
    | P9_GETATTR_UID
    | P9_GETATTR_GID
    | P9_GETATTR_RDEV
    | P9_GETATTR_ATIME
    | P9_GETATTR_MTIME
    | P9_GETATTR_CTIME
    | P9_GETATTR_SIZE
    | P9_GETATTR_BLOCKS
    | P9_GETATTR_BTIME
    | P9_GETATTR_GEN
    | P9_GETATTR_DATA_VERSION;

/// Setattr valid bits.
const P9_SETATTR_MODE: u32 = 0x00000001;
const P9_SETATTR_SIZE: u32 = 0x00000008;

/// Unlinkat flags.
const AT_REMOVEDIR: u32 = 0x200;

/// FID state: tracks an open file or directory path.
struct FidState {
    path: PathBuf,
    file: Option<File>,
}

/// Host filesystem backend for 9P.
pub struct P9Filesystem {
    root: PathBuf,
    fids: HashMap<u32, FidState>,
    read_only: bool,
    msize: u32,
    /// Path-to-QID-path cache for consistent QID.path values (used on non-Unix).
    #[cfg(not(unix))]
    qid_cache: HashMap<PathBuf, u64>,
    /// Next synthetic QID path ID (used on non-Unix when inode not available).
    #[cfg(not(unix))]
    next_qid_path: u64,
}

impl P9Filesystem {
    pub fn new(root: PathBuf, read_only: bool) -> Self {
        P9Filesystem {
            root,
            fids: HashMap::new(),
            read_only,
            msize: 0,
            #[cfg(not(unix))]
            qid_cache: HashMap::new(),
            #[cfg(not(unix))]
            next_qid_path: 1,
        }
    }

    /// Get the current msize.
    pub fn msize(&self) -> u32 {
        self.msize
    }

    /// Negotiate protocol version. Returns negotiated msize.
    pub fn version(&mut self, client_msize: u32) -> u32 {
        self.msize = client_msize.min(65536);
        // Release all fids on version (per spec).
        self.fids.clear();
        self.msize
    }

    /// Attach: bind `fid` to the root directory.
    pub fn attach(&mut self, fid: u32) -> Result<Qid, u32> {
        let meta = fs::metadata(&self.root).map_err(|_| ENOENT)?;
        let qid = self.make_qid(&self.root.clone(), &meta);
        self.fids.insert(
            fid,
            FidState {
                path: self.root.clone(),
                file: None,
            },
        );
        Ok(qid)
    }

    /// Walk: resolve path components from `fid` into `newfid`.
    pub fn walk(&mut self, fid: u32, newfid: u32, names: &[String]) -> Result<Vec<Qid>, u32> {
        let base_path = self.fids.get(&fid).ok_or(EBADF)?.path.clone();

        if names.is_empty() {
            // Clone fid.
            self.fids.insert(
                newfid,
                FidState {
                    path: base_path,
                    file: None,
                },
            );
            return Ok(Vec::new());
        }

        let mut current = base_path;
        let mut qids = Vec::with_capacity(names.len());

        for name in names {
            if name == ".." || name.contains('/') || name.contains('\\') {
                return Err(ENOENT);
            }
            current = current.join(name);

            // Security: verify the resolved path is under root.
            if !self.is_under_root(&current) {
                return Err(EACCES);
            }

            let meta = fs::metadata(&current).map_err(|_| ENOENT)?;
            qids.push(self.make_qid(&current, &meta));
        }

        self.fids.insert(
            newfid,
            FidState {
                path: current,
                file: None,
            },
        );

        Ok(qids)
    }

    /// Open a file for I/O.
    pub fn lopen(&mut self, fid: u32, flags: u32) -> Result<(Qid, u32), u32> {
        // Clone path to release borrow on self.fids before calling other &mut self methods.
        let path = self.fids.get(&fid).ok_or(EBADF)?.path.clone();
        let meta = fs::metadata(&path).map_err(|_| ENOENT)?;

        if meta.is_dir() {
            let qid = self.make_qid_from_parts(&path, &meta);
            let iounit = self.iounit();
            return Ok((qid, iounit));
        }

        if self.read_only && (flags & 0x3) != O_RDONLY {
            return Err(EACCES);
        }

        let file = self.open_file(&path, flags)?;
        let qid = self.make_qid_from_parts(&path, &meta);
        let iounit = self.iounit();
        self.fids.get_mut(&fid).ok_or(EBADF)?.file = Some(file);
        Ok((qid, iounit))
    }

    /// Create and open a new file.
    pub fn lcreate(
        &mut self,
        fid: u32,
        name: &str,
        _flags: u32,
        _mode: u32,
        _gid: u32,
    ) -> Result<(Qid, u32), u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let dir_path = self.fids.get(&fid).ok_or(EBADF)?.path.clone();
        let file_path = dir_path.join(name);

        if !self.is_under_root(&file_path) {
            return Err(EACCES);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&file_path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => EEXIST,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EIO,
            })?;

        // Set permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&file_path, fs::Permissions::from_mode(_mode));
        }

        let meta = file.metadata().map_err(|_| EIO)?;
        let qid = self.make_qid(&file_path, &meta);
        let iounit = self.iounit();

        // Fid now points to the new file.
        let state = self.fids.get_mut(&fid).ok_or(EBADF)?;
        state.path = file_path;
        state.file = Some(file);

        Ok((qid, iounit))
    }

    /// Read from an open file.
    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, u32> {
        let state = self.fids.get_mut(&fid).ok_or(EBADF)?;
        let file = state.file.as_mut().ok_or(EBADF)?;

        file.seek(SeekFrom::Start(offset)).map_err(|_| EIO)?;

        let max_read = count.min(self.msize.saturating_sub(11)) as usize; // 11 = header(7) + count(4)
        let mut buf = vec![0u8; max_read];
        let n = file.read(&mut buf).map_err(|_| EIO)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Write to an open file.
    pub fn write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let state = self.fids.get_mut(&fid).ok_or(EBADF)?;
        let file = state.file.as_mut().ok_or(EBADF)?;

        file.seek(SeekFrom::Start(offset)).map_err(|_| EIO)?;
        file.write_all(data).map_err(|_| ENOSPC)?;
        Ok(data.len() as u32)
    }

    /// Read directory entries.
    pub fn readdir(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, u32> {
        let state = self.fids.get(&fid).ok_or(EBADF)?;
        let entries: Vec<_> = fs::read_dir(&state.path)
            .map_err(|_| ENOTDIR)?
            .filter_map(|e| e.ok())
            .collect();

        let max_size = count.min(self.msize.saturating_sub(11)) as usize;
        let mut w = ByteWriter::with_capacity(max_size);
        let mut entry_offset = offset;

        for entry in entries.iter().skip(offset as usize) {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let qid = self.make_qid(&entry.path(), &meta);
            let dtype = if meta.is_dir() { 4u8 } else { 8u8 };

            // Readdir entry: qid[13] + offset[8] + type[1] + name[s]
            let entry_size = 13 + 8 + 1 + 2 + name_str.len();
            if w.len() + entry_size > max_size {
                break;
            }

            entry_offset += 1;
            qid.write_to(&mut w);
            w.put_u64(entry_offset);
            w.put_u8(dtype);
            w.put_string(&name_str);
        }

        Ok(w.into_bytes())
    }

    /// Get file attributes.
    pub fn getattr(&mut self, fid: u32, request_mask: u64) -> Result<P9Attr, u32> {
        let state = self.fids.get(&fid).ok_or(EBADF)?;
        let meta = fs::metadata(&state.path).map_err(|_| ENOENT)?;
        let qid = self.make_qid(&state.path.clone(), &meta);

        let valid = request_mask & P9_GETATTR_BASIC;

        let mode = self.metadata_mode(&meta);
        let size = meta.len();
        let blksize = 4096u64;
        let blocks = size.div_ceil(512);

        // Timestamps.
        let (mtime_sec, mtime_nsec) = self.metadata_mtime(&meta);
        let (atime_sec, atime_nsec) = self.metadata_atime(&meta);
        let (ctime_sec, ctime_nsec) = (mtime_sec, mtime_nsec); // Approximate.

        let nlink = self.metadata_nlink(&meta);

        Ok(P9Attr {
            valid,
            qid,
            mode,
            uid: 0,
            gid: 0,
            nlink,
            rdev: 0,
            size,
            blksize,
            blocks,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            btime_sec: 0,
            btime_nsec: 0,
            gen: 0,
            data_version: 0,
        })
    }

    /// Set file attributes.
    pub fn setattr(
        &mut self,
        fid: u32,
        valid: u32,
        mode: u32,
        _uid: u32,
        _gid: u32,
        size: u64,
    ) -> Result<(), u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let state = self.fids.get(&fid).ok_or(EBADF)?;

        if valid & P9_SETATTR_MODE != 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(mode);
                fs::set_permissions(&state.path, perms).map_err(|_| EIO)?;
            }
            #[cfg(not(unix))]
            let _ = mode;
        }

        if valid & P9_SETATTR_SIZE != 0 {
            let file = OpenOptions::new()
                .write(true)
                .open(&state.path)
                .map_err(|_| EIO)?;
            file.set_len(size).map_err(|_| EIO)?;
        }

        Ok(())
    }

    /// Release a fid.
    pub fn clunk(&mut self, fid: u32) -> Result<(), u32> {
        self.fids.remove(&fid).ok_or(EBADF)?;
        Ok(())
    }

    /// Create a directory.
    pub fn mkdir(&mut self, dfid: u32, name: &str, _mode: u32, _gid: u32) -> Result<Qid, u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let dir_path = self.fids.get(&dfid).ok_or(EBADF)?.path.clone();
        let new_path = dir_path.join(name);

        if !self.is_under_root(&new_path) {
            return Err(EACCES);
        }

        fs::create_dir(&new_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => EEXIST,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => EIO,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&new_path, fs::Permissions::from_mode(_mode));
        }

        let meta = fs::metadata(&new_path).map_err(|_| EIO)?;
        Ok(self.make_qid(&new_path, &meta))
    }

    /// Rename a file or directory.
    pub fn renameat(
        &mut self,
        olddirfid: u32,
        oldname: &str,
        newdirfid: u32,
        newname: &str,
    ) -> Result<(), u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let old_dir = self.fids.get(&olddirfid).ok_or(EBADF)?.path.clone();
        let new_dir = self.fids.get(&newdirfid).ok_or(EBADF)?.path.clone();

        let old_path = old_dir.join(oldname);
        let new_path = new_dir.join(newname);

        if !self.is_under_root(&old_path) || !self.is_under_root(&new_path) {
            return Err(EACCES);
        }

        fs::rename(&old_path, &new_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => EIO,
        })?;

        Ok(())
    }

    /// Delete a file or directory.
    pub fn unlinkat(&mut self, dirfid: u32, name: &str, flags: u32) -> Result<(), u32> {
        if self.read_only {
            return Err(EACCES);
        }

        let dir_path = self.fids.get(&dirfid).ok_or(EBADF)?.path.clone();
        let target = dir_path.join(name);

        if !self.is_under_root(&target) {
            return Err(EACCES);
        }

        if flags & AT_REMOVEDIR != 0 {
            fs::remove_dir(&target).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                _ => {
                    // Check if directory is not empty.
                    if let Ok(mut entries) = fs::read_dir(&target) {
                        if entries.next().is_some() {
                            return ENOTEMPTY;
                        }
                    }
                    EIO
                }
            })?;
        } else {
            fs::remove_file(&target).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EIO,
            })?;
        }

        Ok(())
    }

    /// Flush cached data to disk.
    pub fn fsync(&mut self, fid: u32) -> Result<(), u32> {
        let state = self.fids.get_mut(&fid).ok_or(EBADF)?;
        if let Some(ref file) = state.file {
            // sync_all may fail on read-only files (especially on Windows).
            // This is harmless — there's nothing to flush for read-only handles.
            let _ = file.sync_all();
        }
        Ok(())
    }

    // -- Internal helpers --

    /// I/O unit size: max data per read/write.
    fn iounit(&self) -> u32 {
        self.msize.saturating_sub(24) // Conservative: header + read/write overhead.
    }

    /// Verify that `path` resolves under the root directory.
    fn is_under_root(&self, path: &Path) -> bool {
        // Use canonicalize if the path exists; otherwise check components.
        if let Ok(canonical) = fs::canonicalize(path) {
            if let Ok(root_canonical) = fs::canonicalize(&self.root) {
                return canonical.starts_with(&root_canonical);
            }
        }
        // Path doesn't exist yet (e.g., for create). Check the parent.
        if let Some(parent) = path.parent() {
            if let Ok(canonical_parent) = fs::canonicalize(parent) {
                if let Ok(root_canonical) = fs::canonicalize(&self.root) {
                    return canonical_parent.starts_with(&root_canonical);
                }
            }
        }
        false
    }

    /// Generate a QID from file metadata.
    fn make_qid(&mut self, path: &Path, meta: &fs::Metadata) -> Qid {
        self.make_qid_from_parts(path, meta)
    }

    fn make_qid_from_parts(&mut self, path: &Path, meta: &fs::Metadata) -> Qid {
        let qtype = if meta.is_dir() {
            QT_DIR
        } else if meta.file_type().is_symlink() {
            QT_SYMLINK
        } else {
            QT_FILE
        };

        let qid_path = self.resolve_qid_path(path, meta);

        let (mtime_sec, _) = self.metadata_mtime(meta);
        let version = mtime_sec as u32;

        Qid {
            qtype,
            version,
            path: qid_path,
        }
    }

    /// Get a unique QID path value for a file.
    fn resolve_qid_path(&mut self, path: &Path, meta: &fs::Metadata) -> u64 {
        // On Unix: use inode number directly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = path; // suppress unused on non-unix
            meta.ino()
        }

        // On non-Unix: use a cache mapping canonical paths to synthetic IDs.
        #[cfg(not(unix))]
        {
            let _ = meta;
            let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            if let Some(&id) = self.qid_cache.get(&canonical) {
                id
            } else {
                let id = self.next_qid_path;
                self.next_qid_path += 1;
                self.qid_cache.insert(canonical, id);
                id
            }
        }
    }

    /// Extract file mode from metadata.
    fn metadata_mode(&self, meta: &fs::Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.mode()
        }
        #[cfg(not(unix))]
        {
            let mut mode = 0o644u32;
            if meta.is_dir() {
                mode = 0o755 | 0o040000; // S_IFDIR
            } else {
                mode |= 0o100000; // S_IFREG
            }
            if meta.permissions().readonly() {
                mode &= !0o222; // Remove write bits.
            }
            mode
        }
    }

    /// Extract mtime from metadata as (seconds, nanoseconds).
    fn metadata_mtime(&self, meta: &fs::Metadata) -> (u64, u64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (meta.mtime() as u64, meta.mtime_nsec() as u64)
        }
        #[cfg(not(unix))]
        {
            meta.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| (d.as_secs(), d.subsec_nanos() as u64))
                .unwrap_or((0, 0))
        }
    }

    /// Extract atime from metadata as (seconds, nanoseconds).
    fn metadata_atime(&self, meta: &fs::Metadata) -> (u64, u64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (meta.atime() as u64, meta.atime_nsec() as u64)
        }
        #[cfg(not(unix))]
        {
            meta.accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| (d.as_secs(), d.subsec_nanos() as u64))
                .unwrap_or((0, 0))
        }
    }

    /// Extract nlink from metadata.
    fn metadata_nlink(&self, meta: &fs::Metadata) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.nlink()
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            1
        }
    }

    /// Open a file with Linux open flags mapped to Rust OpenOptions.
    fn open_file(&self, path: &Path, flags: u32) -> Result<File, u32> {
        let access = flags & 0x3;
        let mut opts = OpenOptions::new();

        match access {
            O_RDONLY => {
                opts.read(true);
            }
            O_WRONLY => {
                opts.write(true);
            }
            O_RDWR => {
                opts.read(true).write(true);
            }
            _ => {
                opts.read(true);
            }
        }

        if flags & O_CREAT != 0 {
            opts.create(true);
        }
        if flags & O_TRUNC != 0 {
            opts.truncate(true);
        }
        if flags & O_APPEND != 0 {
            opts.append(true);
        }

        opts.open(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => EIO,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::TempDir;

    fn setup() -> (TempDir, P9Filesystem) {
        let tmp = TempDir::new().unwrap();
        let mut fs = P9Filesystem::new(tmp.path().to_path_buf(), false);
        fs.version(8192);
        (tmp, fs)
    }

    fn setup_readonly() -> (TempDir, P9Filesystem) {
        let tmp = TempDir::new().unwrap();
        let mut fs = P9Filesystem::new(tmp.path().to_path_buf(), true);
        fs.version(8192);
        (tmp, fs)
    }

    fn create_file(dir: &Path, name: &str, content: &[u8]) {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
    }

    fn create_subdir(dir: &Path, name: &str) {
        fs::create_dir(dir.join(name)).unwrap();
    }

    // -- version --

    #[test]
    fn test_version_negotiates_msize() {
        let tmp = TempDir::new().unwrap();
        let mut fs = P9Filesystem::new(tmp.path().to_path_buf(), false);
        let msize = fs.version(65536);
        assert_eq!(msize, 65536);
        assert_eq!(fs.msize(), 65536);
    }

    #[test]
    fn test_version_caps_msize() {
        let tmp = TempDir::new().unwrap();
        let mut fs = P9Filesystem::new(tmp.path().to_path_buf(), false);
        let msize = fs.version(1_000_000);
        assert_eq!(msize, 65536); // Capped.
    }

    // -- attach --

    #[test]
    fn test_attach_returns_dir_qid() {
        let (_tmp, mut fs) = setup();
        let qid = fs.attach(0).unwrap();
        assert_eq!(qid.qtype, QT_DIR);
        assert_ne!(qid.path, 0);
    }

    // -- walk --

    #[test]
    fn test_walk_empty_clones_fid() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let qids = fs.walk(0, 1, &[]).unwrap();
        assert!(qids.is_empty());
    }

    #[test]
    fn test_walk_single_file() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "hello.txt", b"hello");
        fs.attach(0).unwrap();
        let qids = fs.walk(0, 1, &["hello.txt".to_string()]).unwrap();
        assert_eq!(qids.len(), 1);
        assert_eq!(qids[0].qtype, QT_FILE);
    }

    #[test]
    fn test_walk_multiple_components() {
        let (tmp, mut fs) = setup();
        create_subdir(tmp.path(), "a");
        create_subdir(&tmp.path().join("a"), "b");
        create_file(&tmp.path().join("a").join("b"), "c.txt", b"content");
        fs.attach(0).unwrap();
        let qids = fs
            .walk(
                0,
                1,
                &["a".to_string(), "b".to_string(), "c.txt".to_string()],
            )
            .unwrap();
        assert_eq!(qids.len(), 3);
        assert_eq!(qids[0].qtype, QT_DIR);
        assert_eq!(qids[1].qtype, QT_DIR);
        assert_eq!(qids[2].qtype, QT_FILE);
    }

    #[test]
    fn test_walk_nonexistent_returns_error() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let result = fs.walk(0, 1, &["nonexistent".to_string()]);
        assert_eq!(result, Err(ENOENT));
    }

    #[test]
    fn test_walk_dotdot_rejected() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let result = fs.walk(0, 1, &["..".to_string()]);
        assert_eq!(result, Err(ENOENT));
    }

    #[test]
    fn test_walk_bad_fid() {
        let (_tmp, mut fs) = setup();
        let result = fs.walk(99, 1, &["foo".to_string()]);
        assert_eq!(result, Err(EBADF));
    }

    // -- lopen + read + write --

    #[test]
    fn test_lopen_and_read() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "data.txt", b"hello world");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["data.txt".to_string()]).unwrap();
        let (qid, iounit) = fs.lopen(1, O_RDONLY).unwrap();
        assert_eq!(qid.qtype, QT_FILE);
        assert!(iounit > 0);

        let data = fs.read(1, 0, 4096).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_read_with_offset() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "data.txt", b"hello world");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["data.txt".to_string()]).unwrap();
        fs.lopen(1, O_RDONLY).unwrap();

        let data = fs.read(1, 6, 4096).unwrap();
        assert_eq!(data, b"world");
    }

    #[test]
    fn test_write_and_readback() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "out.txt", b"");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["out.txt".to_string()]).unwrap();
        fs.lopen(1, O_RDWR).unwrap();

        let written = fs.write(1, 0, b"test data").unwrap();
        assert_eq!(written, 9);

        let data = fs.read(1, 0, 4096).unwrap();
        assert_eq!(data, b"test data");
    }

    // -- readdir --

    #[test]
    fn test_readdir_lists_entries() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "a.txt", b"");
        create_file(tmp.path(), "b.txt", b"");
        create_subdir(tmp.path(), "subdir");
        fs.attach(0).unwrap();
        fs.lopen(0, O_RDONLY).unwrap();

        let data = fs.readdir(0, 0, 8192).unwrap();
        // Should contain directory entries for a.txt, b.txt, subdir.
        assert!(!data.is_empty());
    }

    #[test]
    fn test_readdir_offset_skips() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "a.txt", b"");
        create_file(tmp.path(), "b.txt", b"");
        create_file(tmp.path(), "c.txt", b"");
        fs.attach(0).unwrap();

        let full = fs.readdir(0, 0, 8192).unwrap();
        let partial = fs.readdir(0, 1, 8192).unwrap();
        // Partial should be smaller (skipped first entry).
        assert!(partial.len() < full.len());
    }

    // -- getattr --

    #[test]
    fn test_getattr_file() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "test.txt", b"12345");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["test.txt".to_string()]).unwrap();

        let attr = fs.getattr(1, 0x3FFF).unwrap();
        assert_eq!(attr.qid.qtype, QT_FILE);
        assert_eq!(attr.size, 5);
        assert!(attr.valid != 0);
    }

    #[test]
    fn test_getattr_dir() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();

        let attr = fs.getattr(0, 0x3FFF).unwrap();
        assert_eq!(attr.qid.qtype, QT_DIR);
    }

    // -- clunk --

    #[test]
    fn test_clunk_releases_fid() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        fs.clunk(0).unwrap();
        // Fid 0 no longer valid.
        assert_eq!(fs.walk(0, 1, &[]), Err(EBADF));
    }

    #[test]
    fn test_clunk_bad_fid() {
        let (_tmp, mut fs) = setup();
        assert_eq!(fs.clunk(99), Err(EBADF));
    }

    // -- mkdir --

    #[test]
    fn test_mkdir_creates_directory() {
        let (tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let qid = fs.mkdir(0, "newdir", 0o755, 0).unwrap();
        assert_eq!(qid.qtype, QT_DIR);
        assert!(tmp.path().join("newdir").is_dir());
    }

    #[test]
    fn test_mkdir_already_exists() {
        let (tmp, mut fs) = setup();
        create_subdir(tmp.path(), "existing");
        fs.attach(0).unwrap();
        assert_eq!(fs.mkdir(0, "existing", 0o755, 0), Err(EEXIST));
    }

    // -- lcreate --

    #[test]
    fn test_lcreate_creates_file() {
        let (tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let (qid, iounit) = fs.lcreate(0, "new.txt", O_RDWR, 0o644, 0).unwrap();
        assert_eq!(qid.qtype, QT_FILE);
        assert!(iounit > 0);
        assert!(tmp.path().join("new.txt").exists());
    }

    #[test]
    fn test_lcreate_already_exists() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "exists.txt", b"");
        fs.attach(0).unwrap();
        assert_eq!(fs.lcreate(0, "exists.txt", O_RDWR, 0o644, 0), Err(EEXIST));
    }

    // -- renameat --

    #[test]
    fn test_renameat() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "old.txt", b"data");
        fs.attach(0).unwrap();
        // Clone fid for newfid.
        fs.walk(0, 1, &[]).unwrap();
        fs.renameat(0, "old.txt", 1, "new.txt").unwrap();
        assert!(!tmp.path().join("old.txt").exists());
        assert!(tmp.path().join("new.txt").exists());
    }

    // -- unlinkat --

    #[test]
    fn test_unlinkat_file() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "del.txt", b"");
        fs.attach(0).unwrap();
        fs.unlinkat(0, "del.txt", 0).unwrap();
        assert!(!tmp.path().join("del.txt").exists());
    }

    #[test]
    fn test_unlinkat_dir() {
        let (tmp, mut fs) = setup();
        create_subdir(tmp.path(), "rmdir");
        fs.attach(0).unwrap();
        fs.unlinkat(0, "rmdir", AT_REMOVEDIR).unwrap();
        assert!(!tmp.path().join("rmdir").exists());
    }

    #[test]
    fn test_unlinkat_nonempty_dir() {
        let (tmp, mut fs) = setup();
        create_subdir(tmp.path(), "notempty");
        create_file(&tmp.path().join("notempty"), "file.txt", b"");
        fs.attach(0).unwrap();
        assert_eq!(fs.unlinkat(0, "notempty", AT_REMOVEDIR), Err(ENOTEMPTY));
    }

    // -- fsync --

    #[test]
    fn test_fsync_open_file() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "sync.txt", b"data");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["sync.txt".to_string()]).unwrap();
        fs.lopen(1, O_RDONLY).unwrap();
        fs.fsync(1).unwrap();
    }

    // -- read-only mode --

    #[test]
    fn test_readonly_blocks_write() {
        let (tmp, mut fs) = setup_readonly();
        create_file(tmp.path(), "file.txt", b"data");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["file.txt".to_string()]).unwrap();
        // Open for write should fail.
        assert_eq!(fs.lopen(1, O_WRONLY), Err(EACCES));
    }

    #[test]
    fn test_readonly_blocks_mkdir() {
        let (_tmp, mut fs) = setup_readonly();
        fs.attach(0).unwrap();
        assert_eq!(fs.mkdir(0, "new", 0o755, 0), Err(EACCES));
    }

    #[test]
    fn test_readonly_blocks_unlink() {
        let (tmp, mut fs) = setup_readonly();
        create_file(tmp.path(), "nodel.txt", b"");
        fs.attach(0).unwrap();
        assert_eq!(fs.unlinkat(0, "nodel.txt", 0), Err(EACCES));
    }

    #[test]
    fn test_readonly_allows_read() {
        let (tmp, mut fs) = setup_readonly();
        create_file(tmp.path(), "readable.txt", b"hello");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["readable.txt".to_string()]).unwrap();
        fs.lopen(1, O_RDONLY).unwrap();
        let data = fs.read(1, 0, 4096).unwrap();
        assert_eq!(data, b"hello");
    }

    // -- path traversal security --

    #[test]
    fn test_walk_slash_rejected() {
        let (_tmp, mut fs) = setup();
        fs.attach(0).unwrap();
        let result = fs.walk(0, 1, &["a/b".to_string()]);
        assert_eq!(result, Err(ENOENT));
    }

    // -- setattr --

    #[test]
    fn test_setattr_truncate() {
        let (tmp, mut fs) = setup();
        create_file(tmp.path(), "trunc.txt", b"hello world");
        fs.attach(0).unwrap();
        fs.walk(0, 1, &["trunc.txt".to_string()]).unwrap();
        fs.setattr(1, P9_SETATTR_SIZE, 0, 0, 0, 5).unwrap();

        // Verify truncation.
        let content = std::fs::read(tmp.path().join("trunc.txt")).unwrap();
        assert_eq!(content, b"hello");
    }
}
