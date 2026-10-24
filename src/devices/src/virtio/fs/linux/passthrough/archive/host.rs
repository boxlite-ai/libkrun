// SPDX-License-Identifier: Apache-2.0

//! Descriptor-relative host operations of the archive. Nothing here follows
//! a symlink: objects are opened `O_PATH | O_NOFOLLOW` relative to their
//! directory's descriptor, and metadata is read and set through the
//! `/proc/self/fd` link of that descriptor, which names the object itself
//! (a symlink included) and is never resolved further.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};

use caps::{CapSet, Capability};
use vm_memory::ByteValued;

use super::super::LinuxDirent64;
use super::{ArchivedTime, ArchivedXattr};

/// getdents64 buffer for listing a directory.
const DIRENT_BUFFER: usize = 64 * 1024;
/// The nsfs inode number of the initial user namespace (`USER_NS_INIT_INO`
/// in include/uapi/linux/nsfs.h).
const USER_NS_INIT_INO: u64 = 0xEFFF_FFFD;

/// What the archive needs to know about a host object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Meta {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) mnt_id: u64,
    /// The whole `st_mode`, file type included.
    pub(super) mode: u32,
    pub(super) nlink: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) rdev: u64,
    pub(super) size: u64,
    pub(super) atime: ArchivedTime,
    pub(super) mtime: ArchivedTime,
    pub(super) ctime: ArchivedTime,
}

impl Meta {
    pub(super) fn key(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    pub(super) fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }
}

fn check(res: libc::c_int) -> io::Result<()> {
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn time(t: libc::statx_timestamp) -> ArchivedTime {
    ArchivedTime {
        sec: t.tv_sec,
        nsec: t.tv_nsec,
    }
}

fn timespec(t: ArchivedTime) -> libc::timespec {
    libc::timespec {
        tv_sec: t.sec,
        tv_nsec: t.nsec as libc::c_long,
    }
}

/// The `/proc/self/fd` link of `file`.
pub(super) fn proc_path(file: &File) -> CString {
    CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
}

/// statx of `name` in `dir` (the object behind `dir` itself if `name` is
/// empty), never following a symlink.
pub(super) fn statx_at(dir: &File, name: &CStr) -> io::Result<Meta> {
    let mut stx = MaybeUninit::<libc::statx>::zeroed();
    let mut flags = libc::AT_SYMLINK_NOFOLLOW;
    if name.is_empty() {
        flags |= libc::AT_EMPTY_PATH;
    }
    // Safe because the kernel only writes into `stx` and we check the result.
    check(unsafe {
        libc::statx(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            stx.as_mut_ptr(),
        )
    })?;
    // Safe because the kernel initialized the struct.
    let stx = unsafe { stx.assume_init() };
    // Without the mount ID a submount would pass unnoticed.
    let wanted = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    if stx.stx_mask & wanted != wanted {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(Meta {
        dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        ino: stx.stx_ino,
        mnt_id: stx.stx_mnt_id,
        mode: u32::from(stx.stx_mode),
        nlink: stx.stx_nlink,
        uid: stx.stx_uid,
        gid: stx.stx_gid,
        rdev: libc::makedev(stx.stx_rdev_major, stx.stx_rdev_minor),
        size: stx.stx_size,
        atime: time(stx.stx_atime),
        mtime: time(stx.stx_mtime),
        ctime: time(stx.stx_ctime),
    })
}

pub(super) fn statx(file: &File) -> io::Result<Meta> {
    statx_at(file, c"")
}

/// Open `name` in `dir` (a path when `dir` is None) without following a
/// final symlink.
pub(super) fn open_at(
    dir: Option<&File>,
    name: &CStr,
    flags: i32,
    mode: libc::mode_t,
) -> io::Result<File> {
    let dir = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    // Safe because this doesn't modify any memory and we check the result.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safe because we just opened this fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn open_path(dir: Option<&File>, name: &CStr) -> io::Result<File> {
    open_at(dir, name, libc::O_PATH, 0)
}

/// A new open file description of the object behind `file`, with `flags`
/// and `O_NOATIME` when the host allows it (only the owner or a holder of
/// CAP_FOWNER may use it; otherwise reading may update the source atime).
pub(super) fn reopen_noatime(file: &File, flags: i32) -> io::Result<File> {
    let path = proc_path(file);
    for noatime in [libc::O_NOATIME, 0] {
        // Safe because this doesn't modify any memory and we check the
        // result. The /proc link names the object itself.
        let fd = unsafe { libc::open(path.as_ptr(), flags | noatime | libc::O_CLOEXEC) };
        if fd >= 0 {
            // Safe because we just opened this fd.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if noatime == 0 || err.raw_os_error() != Some(libc::EPERM) {
            return Err(err);
        }
    }
    unreachable!()
}

/// The entry names of directory `dir` without "." and "..", read through a
/// new open file description.
pub(super) fn list(dir: &File) -> io::Result<Vec<Vec<u8>>> {
    let dir = reopen_noatime(dir, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut names = Vec::new();
    let mut buf = vec![0u8; DIRENT_BUFFER];
    loop {
        // Safe because the kernel only writes into `buf` and we check the
        // return value.
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
            return Ok(names);
        }
        let mut rem = &buf[..res as usize];
        while !rem.is_empty() {
            let eio = || io::Error::from_raw_os_error(libc::EIO);
            let header = rem
                .get(..size_of::<LinuxDirent64>())
                .and_then(LinuxDirent64::from_slice)
                .copied()
                .ok_or_else(eio)?;
            let reclen = header.d_reclen as usize;
            let name = rem
                .get(size_of::<LinuxDirent64>()..reclen)
                .ok_or_else(eio)?;
            let len = name.iter().position(|&b| b == 0).ok_or_else(eio)?;
            let name = &name[..len];
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
            rem = &rem[reclen..];
        }
    }
}

/// The target of symlink `file`.
pub(super) fn readlink(file: &File) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    // Safe because the kernel writes at most `buf.len()` bytes into `buf`.
    let len = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(len as usize);
    Ok(buf)
}

/// Run a size query and fetch until the result fits (the value may grow
/// between the two calls).
fn sized(mut call: impl FnMut(&mut [u8]) -> isize) -> io::Result<Vec<u8>> {
    loop {
        let len = call(&mut []);
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len as usize];
        let got = call(&mut buf);
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ERANGE) {
            return Err(err);
        }
    }
}

/// Whether this thread lists and reads every extended attribute: the
/// kernel hides `trusted.*` ones (ENODATA, left out of listings) unless the
/// caller has CAP_SYS_ADMIN in the initial user namespace.
pub(super) fn sees_every_xattr() -> io::Result<bool> {
    let ns = std::fs::metadata("/proc/self/ns/user")?;
    let sys_admin = caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(sys_admin && ns.ino() == USER_NS_INIT_INO)
}

/// Every extended attribute of the object behind `file`, sorted by name.
pub(super) fn xattrs(file: &File) -> io::Result<Vec<ArchivedXattr>> {
    let path = proc_path(file);
    // Safe because the kernel writes at most `buf.len()` bytes into `buf`.
    let list = sized(|buf| unsafe {
        libc::listxattr(path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
    })?;
    let mut xattrs = Vec::new();
    for name in list.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let cname = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
        // Safe because the kernel writes at most `buf.len()` bytes into `buf`.
        let value = sized(|buf| unsafe {
            libc::getxattr(
                path.as_ptr(),
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        })?;
        xattrs.push(ArchivedXattr {
            name: name.to_vec(),
            value,
        });
    }
    xattrs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(xattrs)
}

pub(super) fn set_xattr(file: &File, name: &[u8], value: &[u8]) -> io::Result<()> {
    let path = proc_path(file);
    let name = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        )
    })
}

pub(super) fn remove_xattr(file: &File, name: &[u8]) -> io::Result<()> {
    let path = proc_path(file);
    let name = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) })
}

pub(super) fn chown(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe {
        libc::fchownat(
            file.as_raw_fd(),
            c"".as_ptr(),
            uid,
            gid,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    })
}

pub(super) fn chmod(file: &File, mode: u32) -> io::Result<()> {
    let path = proc_path(file);
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe { libc::chmod(path.as_ptr(), mode) })
}

pub(super) fn set_times(file: &File, atime: ArchivedTime, mtime: ArchivedTime) -> io::Result<()> {
    let path = proc_path(file);
    let times = [timespec(atime), timespec(mtime)];
    // Safe because this doesn't modify any memory and we check the result.
    // Following the /proc link reaches the object itself, also a symlink.
    check(unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) })
}

pub(super) fn mkdir_at(dir: &File, name: &CStr) -> io::Result<()> {
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) })
}

pub(super) fn symlink_at(target: &[u8], dir: &File, name: &CStr) -> io::Result<()> {
    let target = CString::new(target).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) })
}

pub(super) fn whiteout_at(dir: &File, name: &CStr) -> io::Result<()> {
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe {
        libc::mknodat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::S_IFCHR | 0o600,
            libc::makedev(0, 0),
        )
    })
}

/// A hard link `name` in `dir` to the object behind `file` itself, through
/// its `/proc/self/fd` link (no capability needed, unlike `AT_EMPTY_PATH`);
/// a symlink is linked itself, never followed.
pub(super) fn link_to(file: &File, dir: &File, name: &CStr) -> io::Result<()> {
    let path = proc_path(file);
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            path.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    })
}

pub(super) fn unlink_at(dir: &File, name: &CStr, is_dir: bool) -> io::Result<()> {
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // Safe because this doesn't modify any memory and we check the result.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) })
}
