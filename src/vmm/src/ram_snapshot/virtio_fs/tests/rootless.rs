// SPDX-License-Identifier: Apache-2.0

//! Guest-visible export and import of a share without privilege (names
//! start with "rootless_fs"), as BoxLite's default jailer runs the shim: a
//! non-root user in a user namespace mapping only its own IDs, with no
//! capability, e.g. through `make snapshot-rootless-test`. The export and
//! the import run on a thread under the seccomp filter that
//! `KRUN_TEST_SECCOMP_BPF` names (raw `sock_filter` instructions; BoxLite's
//! `make test:snapshot:rootless` passes its VMM filter), so a syscall the
//! filter lacks ends the test with SIGSYS and its number on stderr.

use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;

/// The nsfs inode number of the initial user namespace.
const USER_NS_INIT_INO: u64 = 0xEFFF_FFFD;
/// Exit status after a trapped syscall.
const SIGSYS_EXIT: i32 = 159;

/// Panic unless this process runs as BoxLite's jailer runs the shim: a
/// non-root user in a user namespace whose ID maps hold only its own
/// effective IDs (bwrap nests one namespace in another, so the outer IDs
/// they map to are not checked), with every capability set empty, the
/// bounding set included; returns those IDs.
fn assert_rootless() -> (u32, u32) {
    // SAFETY: these calls only return the effective IDs.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    assert_ne!(uid, 0, "rootless tests must not run as root");
    let ns = fs::metadata("/proc/self/ns/user").unwrap().ino();
    assert_ne!(
        ns, USER_NS_INIT_INO,
        "rootless tests run in a user namespace"
    );
    for (map, id) in [("/proc/self/uid_map", uid), ("/proc/self/gid_map", gid)] {
        let text = fs::read_to_string(map).unwrap();
        let fields: Vec<&str> = text.split_whitespace().collect();
        assert!(
            fields.len() == 3 && fields[0] == id.to_string() && fields[2] == "1",
            "{map} must map only {id}: {text}"
        );
    }
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for set in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let line = status.lines().find(|l| l.starts_with(set)).unwrap();
        let mask = u64::from_str_radix(line[set.len()..].trim(), 16).unwrap();
        assert_eq!(mask, 0, "{set} must be empty");
    }
    (uid, gid)
}

/// On SIGSYS (a syscall the filter traps), print the syscall number and
/// exit: only `write` and `exit_group`, which every filter allows.
extern "C" fn report_sigsys(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: the kernel passes a SIGSYS siginfo, whose si_syscall follows
    // the 8-byte si_call_addr at offset 24 on x86-64.
    let mut nr = unsafe { *(info as *const u8).add(24).cast::<i32>() };
    let mut msg = *b"SIGSYS: the seccomp filter trapped syscall 0000\n";
    for digit in msg[43..47].iter_mut().rev() {
        *digit = b'0' + (nr % 10) as u8;
        nr /= 10;
    }
    // SAFETY: async-signal-safe calls on a stack buffer.
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::_exit(SIGSYS_EXIT);
    }
}

/// Run `f` on a new thread (and its children) under the filter
/// `KRUN_TEST_SECCOMP_BPF` names.
fn under_seccomp<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let path = std::env::var_os("KRUN_TEST_SECCOMP_BPF")
        .expect("KRUN_TEST_SECCOMP_BPF must name the seccomp filter to run under");
    let bytes = fs::read(path).unwrap();
    assert!(
        !bytes.is_empty() && bytes.len() % 8 == 0,
        "not a BPF program"
    );
    let program: Vec<libc::sock_filter> = bytes
        .chunks_exact(8)
        .map(|i| libc::sock_filter {
            code: u16::from_ne_bytes([i[0], i[1]]),
            jt: i[2],
            jf: i[3],
            k: u32::from_ne_bytes([i[4], i[5], i[6], i[7]]),
        })
        .collect();
    // SAFETY: a zeroed sigaction with a valid SA_SIGINFO handler.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = report_sigsys as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()),
            0
        );
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let prog = libc::sock_fprog {
                    len: program.len() as u16,
                    filter: program.as_ptr() as *mut _,
                };
                // SAFETY: `prog` points at `program`, alive for the call;
                // the filter applies to this thread only.
                unsafe {
                    assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                    let res = libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        0,
                        &prog as *const libc::sock_fprog,
                    );
                    assert_eq!(res, 0, "{}", io::Error::last_os_error());
                }
                f()
            })
            .join()
            .unwrap()
    })
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    // SAFETY: every pointer is valid for the call.
    let res = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(res, 0, "{}", io::Error::last_os_error());
}

fn get_xattr(path: &Path, name: &str) -> Vec<u8> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    let mut value = vec![0u8; 4096];
    // SAFETY: the kernel writes at most `value.len()` bytes.
    let len = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    assert!(len >= 0, "{}", io::Error::last_os_error());
    value.truncate(len as usize);
    value
}

/// An access ACL naming this process's user and group.
fn own_acl(uid: u32, gid: u32) -> Vec<u8> {
    let mut value = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (0x01u16, 6u16, u32::MAX),
        (0x02, 6, uid),
        (0x04, 4, u32::MAX),
        (0x08, 4, gid),
        (0x10, 6, u32::MAX),
        (0x20, 4, u32::MAX),
    ] {
        value.extend_from_slice(&tag.to_le_bytes());
        value.extend_from_slice(&perm.to_le_bytes());
        value.extend_from_slice(&id.to_le_bytes());
    }
    value
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A paused share's pending request, handle, DAX file mapping and window
/// bytes continue on a guest-visible copy imported without privilege
/// under the shim's seccomp filter, with hard links, a symlink, a whiteout,
/// xattrs, an ACL and a read-only directory; the image records the
/// exporter's IDs, which the import requires.
#[test]
fn rootless_fs_vmm_guest_visible_export_import_continues_handles_dax_and_requests() {
    let (uid, gid) = assert_rootless();
    let dir = TempDir::new();
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), vec![0x33; PAGE as usize]).unwrap();
    set_xattr(&src.join("f"), "user.kept", b"yes");
    set_xattr(
        &src.join("f"),
        "system.posix_acl_access",
        &own_acl(uid, gid),
    );
    fs::hard_link(src.join("f"), src.join("link")).unwrap();
    std::os::unix::fs::symlink("f", src.join("s")).unwrap();
    let wh = CString::new(src.join("wh").as_os_str().as_bytes()).unwrap();
    // SAFETY: the path is a valid C string.
    let res = unsafe { libc::mknod(wh.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(0, 0)) };
    assert_eq!(res, 0, "{}", io::Error::last_os_error());
    fs::create_dir(src.join("ro")).unwrap();
    fs::write(src.join("ro").join("inside"), b"read-only dir").unwrap();
    chmod(&src.join("ro"), 0o555);

    let source = Side::source(&src, Some(DAX));
    let mut guest = Fuse::new();
    guest.activate(&source);
    let mem = &source.mem;
    guest.init(mem, &source);
    let f = guest.lookup(mem, &source, fuse::ROOT_ID, b"f");
    let fh = guest.open(mem, &source, f.nodeid, libc::O_RDWR);
    guest.ok(
        mem,
        &source,
        Opcode::Write,
        f.nodeid,
        &Fuse::write_body(fh, 0, b"hello"),
    );
    let mapping = Fuse::mapping_body(fh, 0, PAGE, PAGE, true);
    guest.ok(mem, &source, Opcode::SetupMapping, f.nodeid, &mapping);
    source.write_window(0, b"anon");
    let read = Fuse::read_body(fh, 0, PAGE as u32);
    let (unique, reply) = guest.post(mem, Opcode::Read, f.nodeid, &read);
    let cuts = freeze(source.shares()).unwrap();

    let payloads = dir.path("payloads");
    let meta = under_seccomp(|| source.export_in(ArchiveMode::GuestVisible, &cuts, &payloads));
    assert_eq!(
        meta.archive.contract,
        ArchiveContract::GuestVisible { uid, gid }
    );
    assert!(matches!(
        imported_mode(&meta),
        Ok(ArchiveMode::GuestVisible)
    ));
    chmod(&src.join("ro"), 0o755);
    fs::remove_dir_all(&src).unwrap();

    let shares = dir.path("shares");
    let (target, imported) = under_seccomp(|| source.restored(&meta, &payloads, &shares));
    imported.persist();
    let root = shares.join("0");
    assert_eq!(fs::metadata(root.join("link")).unwrap().nlink(), 2);
    assert_eq!(fs::read_link(root.join("s")).unwrap(), Path::new("f"));
    let wh = fs::symlink_metadata(root.join("wh")).unwrap();
    assert_eq!((wh.mode() & libc::S_IFMT, wh.rdev()), (libc::S_IFCHR, 0));
    assert_eq!(get_xattr(&root.join("f"), "user.kept"), b"yes");
    assert_eq!(
        get_xattr(&root.join("f"), "system.posix_acl_access"),
        get_xattr(&root.join("link"), "system.posix_acl_access")
    );
    assert_eq!(
        fs::metadata(root.join("ro")).unwrap().mode() & 0o7777,
        0o555
    );
    assert_eq!(fs::read(root.join("ro/inside")).unwrap(), b"read-only dir");
    assert_eq!(target.window(0, 4), b"anon");
    assert_eq!(target.window(PAGE, 5), b"hello");
    // The restored worker, started under the filter, answers the pending
    // request and keeps the guest's handle on the copy the window maps.
    resume(target.shares()).unwrap();
    let tmem = target.mem.clone();
    wait_until("the pending request", || {
        Driver::used(&tmem, REQUEST).len() == Driver::used(mem, REQUEST).len() + 1
    });
    let (header, payload) = Fuse::reply(&tmem, reply);
    assert_eq!((header.unique, header.error), (unique, 0));
    assert_eq!(&payload[..6], b"hello\x33");
    let write = Fuse::write_body(fh, 5, b" world");
    guest.ok(&tmem, &target, Opcode::Write, f.nodeid, &write);
    assert_eq!(&fs::read(root.join("f")).unwrap()[..11], b"hello world");
    assert_eq!(target.window(PAGE, 11), b"hello world");
    chmod(&root.join("ro"), 0o755);
    drop(source);
}
