// Share archive tests (names start with "snapshot_fs_archive"). They run as
// root with CAP_SYS_ADMIN and CAP_MKNOD on a /tmp that holds whiteouts and
// trusted xattrs (tmpfs), as in
// `docker run --cap-add SYS_ADMIN --tmpfs /tmp:rw,exec`.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use caps::Capability;

use super::super::fuse::RenameIn;
use super::super::passthrough::{
    drop_effective_cap, import_faults, ArchiveError, ArchiveManifest, ArchivedEntry, ArchivedKind,
    ArchivedObject, ArchivedTime, ArchivedXattr, ImportedArchive, ObjectView, ShareArchive,
    ShareSource,
};
use super::*;

struct Payloads {
    files: Vec<u8>,
    init: Vec<u8>,
    pages: Vec<u8>,
}

fn payloads(archive: &ShareArchive) -> Payloads {
    let mut p = Payloads {
        files: Vec::new(),
        init: Vec::new(),
        pages: Vec::new(),
    };
    archive.write_files(&mut p.files).unwrap();
    archive.write_init(&mut p.init).unwrap();
    archive.write_pages(&mut p.pages).unwrap();
    let lengths = archive.lengths();
    assert_eq!(p.files.len() as u64, lengths.files);
    assert_eq!(p.init.len() as u64, lengths.init);
    assert_eq!(p.pages.len() as u64, lengths.pages);
    p
}

fn import(
    manifest: &ArchiveManifest,
    dest: &Path,
    p: &Payloads,
) -> Result<ImportedArchive, ArchiveError> {
    ImportedArchive::import(
        manifest,
        dest,
        &mut &p.files[..],
        &mut &p.init[..],
        &mut &p.pages[..],
    )
}

/// Capture one share of `dir` whose device was never activated.
fn capture_dir(dir: &Path) -> Result<ShareArchive, ArchiveError> {
    let cfg = snapshot_config(dir);
    ShareArchive::capture(vec![ShareSource::inactive(&cfg, None)?])
}

fn device_on(root: &Path, read_only: bool) -> Fs {
    let mut fs = Fs::new(
        "snapfs".to_string(),
        root.to_str().unwrap().to_string(),
        Arc::new(AtomicI32::new(0)),
        false,
        read_only,
    )
    .unwrap();
    fs.enable_snapshot();
    fs
}

/// A device continuing share `share` of `imported` from a frozen cut.
fn restored_rig(
    imported: &ImportedArchive,
    share: usize,
    guest: Guest,
    queues: &[QueueState],
    read_only: bool,
) -> Rig {
    let mut fs = device_on(imported.root(share), read_only);
    fs.restore_imported(imported, share).unwrap();
    Rig::activate(
        guest,
        fs,
        queues.iter().map(QueueState::to_queue).collect(),
        true,
    )
}

fn fresh_queues(guest: &Guest) -> Vec<Queue> {
    (0..NUM_QUEUES).map(|q| guest.queue(q)).collect()
}

fn lookup_bytes(rig: &mut Rig, parent: u64, name: &[u8]) -> EntryOut {
    let mut body = name.to_vec();
    body.push(0);
    *EntryOut::from_slice(&rig.ok(Opcode::Lookup, parent, &body)).unwrap()
}

fn entries(dir: &Path) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().as_bytes().to_vec())
        .collect();
    names.sort();
    names
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// Every extended attribute of `path` itself (a symlink not followed).
fn xattrs_of(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let path = c_path(path);
    let mut list = vec![0u8; 65536];
    // Safe because the kernel writes at most `list.len()` bytes.
    let len = unsafe { libc::llistxattr(path.as_ptr(), list.as_mut_ptr() as *mut _, list.len()) };
    assert!(len >= 0, "{}", std::io::Error::last_os_error());
    let mut out = Vec::new();
    for name in list[..len as usize]
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
    {
        let cname = CString::new(name).unwrap();
        let mut value = vec![0u8; 65536];
        // Safe because the kernel writes at most `value.len()` bytes.
        let got = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                cname.as_ptr(),
                value.as_mut_ptr() as *mut _,
                value.len(),
            )
        };
        assert!(got >= 0);
        value.truncate(got as usize);
        out.push((name.to_vec(), value));
    }
    out.sort();
    out
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    let (path, name) = (c_path(path), cstr(name));
    // Safe because every pointer is valid for the call.
    let res = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        )
    };
    assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
}

/// Mode, owner, atime and mtime (with nanoseconds) and device number.
fn meta_of(path: &Path) -> (u32, u32, u32, i64, i64, i64, i64, u64) {
    let m = fs::symlink_metadata(path).unwrap();
    let mode = if m.file_type().is_symlink() {
        libc::S_IFLNK
    } else {
        m.mode()
    };
    (
        mode,
        m.uid(),
        m.gid(),
        m.atime(),
        m.atime_nsec(),
        m.mtime(),
        m.mtime_nsec(),
        m.rdev(),
    )
}

fn set_times(path: &Path, atime: (i64, i64), mtime: (i64, i64)) {
    let path = c_path(path);
    let times = [
        libc::timespec {
            tv_sec: atime.0,
            tv_nsec: atime.1,
        },
        libc::timespec {
            tv_sec: mtime.0,
            tv_nsec: mtime.1,
        },
    ];
    // Safe because every pointer is valid for the call.
    let res = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(res, 0);
}

fn lchown(path: &Path, uid: u32, gid: u32) {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid)).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mknod(path: &Path, mode: u32, major: u32, minor: u32) {
    let path = c_path(path);
    // Safe because the path is a valid C string.
    let res = unsafe { libc::mknod(path.as_ptr(), mode, libc::makedev(major, minor)) };
    assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
}

/// A POSIX ACL xattr value from (tag, perm, id) entries.
fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut value = 2u32.to_le_bytes().to_vec();
    for &(tag, perm, id) in entries {
        value.extend_from_slice(&tag.to_le_bytes());
        value.extend_from_slice(&perm.to_le_bytes());
        value.extend_from_slice(&id.to_le_bytes());
    }
    value
}

/// A default ACL with a named user, which new objects inherit as xattrs.
fn default_acl(user: u32) -> Vec<u8> {
    const ANY: u32 = u32::MAX;
    acl(&[
        (0x01, 7, ANY),
        (0x02, 7, user),
        (0x04, 5, ANY),
        (0x10, 7, ANY),
        (0x20, 5, ANY),
    ])
}

/// FUSE RENAME of `old` to `new` in the root.
fn rename(rig: &mut Rig, old: &str, new: &str) {
    let mut body = RenameIn {
        newdir: fuse::ROOT_ID,
    }
    .as_slice()
    .to_vec();
    body.extend_from_slice(cstr(old).as_bytes_with_nul());
    body.extend_from_slice(cstr(new).as_bytes_with_nul());
    rig.ok(Opcode::Rename, fuse::ROOT_ID, &body);
}

#[test]
fn snapshot_fs_archive_session_continues_after_source_deletion() {
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("data"), b"hello archive").unwrap();
    fs::write(src.join("unlooked"), b"never looked up").unwrap();
    fs::write(src.join("doomed"), b"open but unlinked").unwrap();
    fs::write(src.join("old"), b"renamed").unwrap();
    fs::hard_link(src.join("data"), src.join("link")).unwrap();
    std::os::unix::fs::symlink("data", src.join("sym")).unwrap();
    fs::create_dir(src.join("sub")).unwrap();
    fs::write(
        src.join("sub").join(OsStr::from_bytes(b"bad\xff")),
        b"non-utf8",
    )
    .unwrap();
    let unlooked_ino = fs::metadata(src.join("unlooked")).unwrap().ino();

    let mut rig = Rig::new(&src);
    rig.init();
    let data = rig.lookup(fuse::ROOT_ID, "data");
    let data_fh = rig.open(Opcode::Open, data.nodeid, libc::O_RDWR);
    let doomed = rig.lookup(fuse::ROOT_ID, "doomed");
    let doomed_fh = rig.open(Opcode::Open, doomed.nodeid, libc::O_RDONLY);
    rig.ok(
        Opcode::Unlink,
        fuse::ROOT_ID,
        cstr("doomed").as_bytes_with_nul(),
    );
    rename(&mut rig, "old", "new");
    let dir_fh = rig.open(Opcode::Opendir, fuse::ROOT_ID, libc::O_RDONLY);
    let first = rig.readdir(dir_fh, 0, 112);
    let cookie = first.last().unwrap().2;
    let rest = rig.readdir(dir_fh, cookie, 4096);
    assert!(!rest.is_empty());
    let queues = rig.freeze();
    let guest = rig.guest.copy();

    let archive = ShareArchive::capture(vec![rig.fs.archive_source().unwrap()]).unwrap();
    let p = payloads(&archive);
    let manifest = archive.manifest().clone();
    drop(archive);
    // The archive no longer needs the source.
    fs::remove_dir_all(&src).unwrap();

    let dest = base.path().join("restored");
    let imported = import(&manifest, &dest, &p).unwrap();
    let root = dest.join("0");
    assert_eq!(imported.root(0), root);
    // Only the share tree: no staging directory and no name for the
    // unlinked file.
    assert_eq!(entries(&dest), vec![b"0".to_vec()]);
    assert!(!root.join("doomed").exists());
    assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o7777, 0o700);

    let mut target = restored_rig(&imported, 0, guest, &queues, false);
    target.resume();
    // Original handles, nodes and directory cookies, no FUSE_INIT.
    assert_eq!(target.read(data.nodeid, data_fh, 64), b"hello archive");
    assert_eq!(
        target.read(doomed.nodeid, doomed_fh, 64),
        b"open but unlinked"
    );
    assert_eq!(target.readdir(dir_fh, cookie, 4096), rest);
    assert_eq!(target.getattr(data.nodeid).attr.ino, data.attr.ino);
    // A file the guest never looked up keeps the number it would have had.
    assert_eq!(
        target.lookup(fuse::ROOT_ID, "unlooked").attr.ino,
        unlooked_ino
    );
    let renamed = target.lookup(fuse::ROOT_ID, "new");
    let fh = target.open(Opcode::Open, renamed.nodeid, libc::O_RDONLY);
    assert_eq!(target.read(renamed.nodeid, fh, 64), b"renamed");
    let (header, _) = target.call(
        Opcode::Lookup,
        fuse::ROOT_ID,
        cstr("old").as_bytes_with_nul(),
    );
    assert_eq!(header.error, -libc::ENOENT);
    let sub = target.lookup(fuse::ROOT_ID, "sub");
    let bad = lookup_bytes(&mut target, sub.nodeid, b"bad\xff");
    let fh = target.open(Opcode::Open, bad.nodeid, libc::O_RDONLY);
    assert_eq!(target.read(bad.nodeid, fh, 64), b"non-utf8");
    // Writes land in the imported copy, hard link included.
    target.write(data.nodeid, data_fh, b"H");
    assert_eq!(fs::read(root.join("data")).unwrap(), b"Hello archive");
    assert_eq!(fs::read(root.join("link")).unwrap(), b"Hello archive");
    assert_eq!(fs::read_link(root.join("sym")).unwrap(), Path::new("data"));
}

#[test]
fn snapshot_fs_archive_isolates_source_and_restored_changes() {
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"before").unwrap();
    let mut rig = Rig::new(&src);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    let fh = rig.open(Opcode::Open, f.nodeid, libc::O_RDWR);
    let queues = rig.freeze();
    let guest = rig.guest.copy();
    let archive = ShareArchive::capture(vec![rig.fs.archive_source().unwrap()]).unwrap();
    let p = payloads(&archive);
    let late = ShareArchive::capture(vec![rig.fs.archive_source().unwrap()]).unwrap();

    // The source continues; a payload written after that is refused.
    rig.resume();
    rig.write(f.nodeid, fh, b"SOURCE");
    assert!(matches!(
        late.write_files(&mut Vec::new()),
        Err(ArchiveError::Changed(_))
    ));

    let imported = import(archive.manifest(), &base.path().join("dest"), &p).unwrap();
    let mut target = restored_rig(&imported, 0, guest, &queues, false);
    target.resume();
    assert_eq!(target.read(f.nodeid, fh, 64), b"before");
    target.write(f.nodeid, fh, b"RESTORED");
    assert_eq!(fs::read(imported.root(0).join("f")).unwrap(), b"RESTORED");
    assert_eq!(fs::read(src.join("f")).unwrap(), b"SOURCE");
}

#[test]
fn snapshot_fs_archive_multiple_shares_keep_links_roots_and_modes() {
    let base = TempDir::new();
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    fs::create_dir_all(a.join("sub")).unwrap();
    fs::create_dir(&b).unwrap();
    fs::write(a.join("x"), b"shared bytes").unwrap();
    fs::write(a.join("sub").join("s"), b"nested").unwrap();
    fs::hard_link(a.join("x"), b.join("y")).unwrap();
    let x_ino = fs::metadata(a.join("x")).unwrap().ino();

    let mut ra = Rig::new(&a);
    ra.init();
    let x = ra.lookup(fuse::ROOT_ID, "x");
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rb = Rig::activate(guest, device_on(&b, true), queues, false);
    rb.init();
    let y = rb.lookup(fuse::ROOT_ID, "y");
    assert_eq!(x.attr.ino, y.attr.ino);
    let (qa, qb) = (ra.freeze(), rb.freeze());
    let (ga, gb) = (ra.guest.copy(), rb.guest.copy());
    // Never activated: one nested in a's tree, one on a's root.
    let nested = device_on(&a.join("sub"), false);
    let shared = device_on(&a, false);

    let archive = ShareArchive::capture(vec![
        ra.fs.archive_source().unwrap(),
        rb.fs.archive_source().unwrap(),
        nested.archive_source().unwrap(),
        shared.archive_source().unwrap(),
    ])
    .unwrap();
    let m = archive.manifest();
    assert_eq!(m.trees, vec![m.shares[0].root, m.shares[1].root]);
    assert_eq!(m.shares[3].root, m.shares[0].root);
    let x_view = |share: usize| {
        *m.shares[share]
            .session
            .views
            .iter()
            .find(|v| v.ino == x_ino)
            .unwrap()
    };
    assert_eq!(x_view(0).object, x_view(1).object);
    let regular = m
        .objects
        .iter()
        .filter(|o| matches!(o.kind, ArchivedKind::Regular { .. }))
        .count();
    assert_eq!(regular, 2);

    let p = payloads(&archive);
    let dest = base.path().join("dest");
    let imported = import(m, &dest, &p).unwrap();
    assert_eq!(imported.root(1), dest.join("1"));
    assert_eq!(imported.root(2), dest.join("0").join("sub"));
    assert_eq!(imported.root(3), dest.join("0"));
    let (ix, iy) = (
        fs::metadata(dest.join("0/x")).unwrap(),
        fs::metadata(dest.join("1/y")).unwrap(),
    );
    assert_eq!((ix.ino(), ix.nlink()), (iy.ino(), 2));

    let mut ta = restored_rig(&imported, 0, ga, &qa, false);
    ta.resume();
    assert_eq!(ta.getattr(x.nodeid).attr.ino, x_ino);
    let mut tb = restored_rig(&imported, 1, gb, &qb, true);
    tb.resume();
    assert_eq!(tb.getattr(y.nodeid).attr.ino, x_ino);
    let fh = tb.open(Opcode::Open, y.nodeid, libc::O_RDONLY);
    assert_eq!(tb.read(y.nodeid, fh, 64), b"shared bytes");
    let open = OpenIn {
        flags: libc::O_WRONLY as u32,
        open_flags: 0,
    };
    assert_ne!(tb.call(Opcode::Open, y.nodeid, open.as_slice()).0.error, 0);
    // The nested share starts when its guest activates it.
    let mut fs = device_on(imported.root(2), false);
    fs.restore_imported(&imported, 2).unwrap();
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut tc = Rig::activate(guest, fs, queues, false);
    tc.init();
    let s = tc.lookup(fuse::ROOT_ID, "s");
    let fh = tc.open(Opcode::Open, s.nodeid, libc::O_RDONLY);
    assert_eq!(tc.read(s.nodeid, fh, 64), b"nested");
}

#[test]
fn snapshot_fs_archive_restores_handle_only_and_map_only_orphans() {
    let p = host_page();
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("held"), b"handle only").unwrap();
    chmod(&src.join("held"), 0o640);
    fs::write(src.join("mapped"), paged(1, 0x5a)).unwrap();
    fs::create_dir(src.join("gone")).unwrap();
    std::os::unix::fs::symlink("elsewhere", src.join("lnk")).unwrap();
    let (w, target) = (Window::new(4), Window::new(4));
    let cfg = snapshot_config(&src);
    let fs = PassthroughFs::new(cfg.clone()).unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let held = fs.lookup(CTX, fuse::ROOT_ID, &cstr("held")).unwrap();
    let (handle, _) = fs
        .open(CTX, held.inode, false, libc::O_RDONLY as u32)
        .unwrap();
    fs.forget(CTX, held.inode, 1);
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("held")).unwrap();
    let mapped = fs.lookup(CTX, fuse::ROOT_ID, &cstr("mapped")).unwrap();
    setup(&fs, &w, mapped.inode, 0, 1, true, 0).unwrap();
    fs.forget(CTX, mapped.inode, 1);
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("mapped")).unwrap();
    let gone = fs.lookup(CTX, fuse::ROOT_ID, &cstr("gone")).unwrap();
    let (gone_handle, _) = fs.opendir(CTX, gone.inode, 0).unwrap();
    fs.rmdir(CTX, fuse::ROOT_ID, &cstr("gone")).unwrap();
    let lnk = fs.lookup(CTX, fuse::ROOT_ID, &cstr("lnk")).unwrap();
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("lnk")).unwrap();
    fs.sync_for_snapshot().unwrap();

    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let source = ShareSource::active(&cfg, &fs, 0, checkpoint);
    let archive = ShareArchive::capture(vec![source]).unwrap();
    let pl = payloads(&archive);
    let dest = base.path().join("dest");
    let imported = import(archive.manifest(), &dest, &pl).unwrap();
    // Nothing of the orphans is linked anywhere.
    assert_eq!(entries(&dest), vec![b"0".to_vec()]);
    assert!(entries(&dest.join("0")).is_empty());

    let session = imported.session(0).unwrap();
    let orphan = |entry: &Entry| {
        session
            .objects
            .iter()
            .find(|o| o.guest_ino == entry.attr.st_ino)
            .unwrap()
    };
    for entry in [&held, &mapped, &gone, &lnk] {
        assert_eq!(orphan(entry).file.metadata().unwrap().nlink(), 0);
    }
    let held_file = orphan(&held);
    assert_eq!(held_file.file.metadata().unwrap().mode() & 0o7777, 0o640);
    let mut bytes = String::new();
    File::open(format!("/proc/self/fd/{}", held_file.file.as_raw_fd()))
        .unwrap()
        .read_to_string(&mut bytes)
        .unwrap();
    assert_eq!(bytes, "handle only");

    let restored = PassthroughFs::restore(
        snapshot_config(imported.root(0)),
        &session.state,
        session.objects,
        imported.init_binary(0),
    )
    .unwrap();
    restored.map_dax(target.dax(), &session.dax_pages).unwrap();
    assert_eq!(target.read(0, p), paged(1, 0x5a));
    assert_eq!(restored.readlink(CTX, lnk.inode).unwrap(), b"elsewhere");
    let (st, _) = restored.getattr(CTX, gone.inode, None).unwrap();
    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR);
    assert_eq!(st.st_ino, gone.attr.st_ino);
    let again = restored.checkpoint().unwrap();
    let handles: Vec<u64> = again.state.handles.iter().map(|h| h.handle).collect();
    assert_eq!(handles, vec![handle.unwrap(), gone_handle.unwrap()]);
    // The restored writable mapping reaches the imported orphan.
    target.write(0, b"Z");
    restored.sync_for_snapshot().unwrap();
    let again = restored.checkpoint_with_dax(Some(target.dax())).unwrap();
    let DaxMappingKind::File { object, .. } = again.state.dax.unwrap().mappings[0].kind else {
        panic!("not a file mapping");
    };
    let mut first = [0u8; 1];
    again.objects[object as usize]
        .file
        .read_exact_at(&mut first, 0)
        .unwrap();
    assert_eq!(&first, b"Z");
}

#[test]
fn snapshot_fs_archive_reproduces_metadata_xattrs_and_acls() {
    let base = TempDir::new();
    let (src, out) = (base.path().join("src"), base.path().join("out"));
    fs::create_dir(&src).unwrap();
    fs::create_dir(&out).unwrap();
    // Everything created below `out` inherits ACL xattrs.
    set_xattr(&out, "system.posix_acl_default", &default_acl(1000));

    let f = src.join("f");
    fs::write(&f, b"metadata").unwrap();
    lchown(&f, 1234, 5678);
    chmod(&f, 0o4751);
    set_xattr(&f, "user.a", b"1");
    set_xattr(&f, "user.empty", b"");
    set_times(&f, (100, 5), (200, 999_999_999));
    // A symlink with its own xattrs, distinct from its target's.
    fs::write(src.join("t"), b"target").unwrap();
    set_xattr(&src.join("t"), "user.target", b"file");
    let s = src.join("s");
    std::os::unix::fs::symlink("t", &s).unwrap();
    set_xattr(&s, "trusted.link", b"symlink");
    lchown(&s, 42, 43);
    set_times(&s, (300, 1), (400, 2));
    // A default ACL its child inherited as an access ACL.
    let d = src.join("d");
    fs::create_dir(&d).unwrap();
    set_xattr(&d, "system.posix_acl_default", &default_acl(2000));
    fs::write(d.join("c"), b"child").unwrap();
    assert!(xattrs_of(&d.join("c"))
        .iter()
        .any(|(n, _)| n == b"system.posix_acl_access"));
    chmod(&d, 0o1770);
    fs::write(src.join("plain"), b"no xattrs").unwrap();
    let ro = src.join("ro");
    fs::create_dir(&ro).unwrap();
    fs::write(ro.join("inside"), b"restricted").unwrap();
    chmod(&ro, 0o500);
    for (path, sec) in [(&d, 500), (&ro, 600), (&src, 700)] {
        set_times(path, (sec, 1), (sec + 1, 2));
    }
    let paths = ["", "f", "t", "s", "d", "d/c", "plain", "ro", "ro/inside"];
    let before: Vec<_> = paths
        .iter()
        .map(|p| (meta_of(&src.join(p)), xattrs_of(&src.join(p))))
        .collect();

    let archive = capture_dir(&src).unwrap();
    let p = payloads(&archive);
    // Capturing changed nothing, atimes included (O_NOATIME), except the
    // symlink's: reading a target moves it, and no flag prevents that. The
    // archive holds the atime from before the read.
    let mut after: Vec<_> = paths
        .iter()
        .map(|p| (meta_of(&src.join(p)), xattrs_of(&src.join(p))))
        .collect();
    let symlink = paths.iter().position(|&p| p == "s").unwrap();
    assert_ne!(after[symlink].0 .3, before[symlink].0 .3);
    after[symlink].0 .3 = before[symlink].0 .3;
    after[symlink].0 .4 = before[symlink].0 .4;
    assert_eq!(before, after);

    let dest = out.join("dest");
    let imported = import(archive.manifest(), &dest, &p).unwrap();
    let root = imported.root(0).to_path_buf();
    for (path, saved) in paths.iter().zip(&before) {
        let got = (meta_of(&root.join(path)), xattrs_of(&root.join(path)));
        assert_eq!(&got, saved, "{path}");
    }
    assert!(xattrs_of(&root.join("plain")).is_empty());
    assert_eq!(fs::read(root.join("ro/inside")).unwrap(), b"restricted");
    assert_eq!(fs::read_link(&root.join("s")).unwrap(), Path::new("t"));
    // The inheritance the import undid is real.
    fs::write(out.join("probe"), b"").unwrap();
    assert!(!xattrs_of(&out.join("probe")).is_empty());
}

#[test]
fn snapshot_fs_archive_keeps_overlay_whiteouts() {
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    mknod(&src.join("wh"), libc::S_IFCHR | 0o644, 0, 0);
    let op = src.join("op");
    fs::create_dir(&op).unwrap();
    fs::write(op.join("inner"), b"").unwrap();
    set_xattr(&op, "trusted.overlay.opaque", b"y");
    set_xattr(&op, "user.overlay.opaque", b"y");
    let archive = capture_dir(&src).unwrap();
    assert!(archive
        .manifest()
        .objects
        .iter()
        .any(|o| o.kind == ArchivedKind::Whiteout));
    let p = payloads(&archive);
    let imported = import(archive.manifest(), &base.path().join("dest"), &p).unwrap();
    let root = imported.root(0);
    for path in ["wh", "op", "op/inner"] {
        assert_eq!(
            meta_of(&src.join(path)),
            meta_of(&root.join(path)),
            "{path}"
        );
        assert_eq!(xattrs_of(&src.join(path)), xattrs_of(&root.join(path)));
    }
    let wh = fs::symlink_metadata(root.join("wh")).unwrap();
    assert_eq!((wh.mode() & libc::S_IFMT, wh.rdev()), (libc::S_IFCHR, 0));

    let session = imported.session(0).unwrap();
    let restored = PassthroughFs::restore(
        snapshot_config(root),
        &session.state,
        session.objects,
        imported.init_binary(0),
    )
    .unwrap();
    restored.init(FsOptions::empty()).unwrap();
    let entry = restored.lookup(CTX, fuse::ROOT_ID, &cstr("wh")).unwrap();
    assert_eq!(entry.attr.st_mode & libc::S_IFMT, libc::S_IFCHR);
    assert_eq!(entry.attr.st_rdev, 0);
}

/// A writer that fails after `left` bytes.
struct FailingWriter {
    left: usize,
}

impl std::io::Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let n = buf.len().min(self.left);
        self.left -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn snapshot_fs_archive_capture_refuses_what_import_cannot_reproduce() {
    let base = TempDir::new();
    let share = |name: &str| {
        let dir = base.path().join(name);
        fs::create_dir_all(dir.join("deep")).unwrap();
        fs::write(dir.join("keep"), b"untouched").unwrap();
        set_atime(&dir.join("keep"), 1);
        dir
    };
    let refused = |dir: &Path, what: &str| {
        let result = capture_dir(dir);
        assert!(
            matches!(result, Err(ArchiveError::Unsupported(_))),
            "{what}: {:?}",
            result.err()
        );
        // A refused capture changed nothing.
        assert_eq!(fs::metadata(dir.join("keep")).unwrap().atime(), 1);
    };

    let fifo = share("fifo");
    let path = c_path(&fifo.join("deep/pipe"));
    // Safe because the path is a valid C string.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    refused(&fifo, "FIFO");
    let socket = share("socket");
    let _listener = std::os::unix::net::UnixListener::bind(socket.join("deep/s")).unwrap();
    refused(&socket, "socket");
    let device = share("device");
    mknod(&device.join("deep/null"), libc::S_IFCHR | 0o600, 1, 3);
    refused(&device, "device");

    // A bind mount on the same device is a submount too.
    let mounted = share("mounted");
    fs::create_dir(mounted.join("inner")).unwrap();
    let (from, to) = (
        c_path(&mounted.join("inner")),
        c_path(&mounted.join("deep")),
    );
    // Safe because both paths are valid C strings.
    let res = unsafe {
        libc::mount(
            from.as_ptr(),
            to.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
    refused(&mounted, "bind mount");
    // Safe because the path is a valid C string.
    assert_eq!(unsafe { libc::umount2(to.as_ptr(), 0) }, 0);

    // An open file moved out of every share.
    let inside = share("inside");
    let outside = share("outside");
    fs::write(inside.join("f"), b"moving").unwrap();
    let cfg = snapshot_config(&inside);
    let fs = PassthroughFs::new(cfg.clone()).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    fs.open(CTX, f.inode, false, libc::O_RDONLY as u32).unwrap();
    fs::rename(inside.join("f"), outside.join("f")).unwrap();
    let result = ShareArchive::capture(vec![ShareSource::active(
        &cfg,
        &fs,
        0,
        fs.checkpoint().unwrap(),
    )]);
    assert!(matches!(result, Err(ArchiveError::Unsupported(_))));

    // Not in snapshot mode, or without a root.
    let plain = Fs::new(
        "snapfs".to_string(),
        inside.to_str().unwrap().to_string(),
        Arc::new(AtomicI32::new(0)),
        false,
        false,
    )
    .unwrap();
    assert!(matches!(
        plain.archive_source(),
        Err(PassthroughSnapshotError::Disabled)
    ));
    assert!(matches!(
        capture_dir(&base.path().join("missing")),
        Err(ArchiveError::Io(_))
    ));

    // A payload writer failing part way leaves the source alone.
    let archive = capture_dir(&inside).unwrap();
    let result = archive.write_files(&mut FailingWriter { left: 3 });
    assert!(matches!(result, Err(ArchiveError::Io(_))));
    assert_eq!(fs::metadata(inside.join("keep")).unwrap().atime(), 1);
}

/// A valid archive of an initialized share: a nested directory, a hard
/// link, a symlink, an open file and a listed directory stream.
fn malformed_base(base: &Path) -> (ArchiveManifest, Payloads) {
    let src = base.join("src");
    fs::create_dir_all(src.join("a/b")).unwrap();
    fs::write(src.join("f"), b"file").unwrap();
    fs::hard_link(src.join("f"), src.join("a/l")).unwrap();
    std::os::unix::fs::symlink("f", src.join("s")).unwrap();
    let cfg = snapshot_config(&src);
    let fs = PassthroughFs::new(cfg.clone()).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    fs.open(CTX, f.inode, false, libc::O_RDONLY as u32).unwrap();
    let (dir, _) = fs.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    names(&fs, dir.unwrap(), 0, 4096);
    let archive = ShareArchive::capture(vec![ShareSource::active(
        &cfg,
        &fs,
        0,
        fs.checkpoint().unwrap(),
    )])
    .unwrap();
    (archive.manifest().clone(), payloads(&archive))
}

fn object_at(m: &ArchiveManifest, path: &[&str]) -> u64 {
    let mut at = m.shares[0].root;
    for name in path {
        let ArchivedKind::Directory { entries } = &m.objects[at as usize].kind else {
            panic!("not a directory");
        };
        at = entries
            .iter()
            .find(|e| e.name == name.as_bytes())
            .unwrap()
            .object;
    }
    at
}

fn entries_mut(m: &mut ArchiveManifest, dir: u64) -> &mut Vec<ArchivedEntry> {
    match &mut m.objects[dir as usize].kind {
        ArchivedKind::Directory { entries } => entries,
        _ => panic!("not a directory"),
    }
}

fn detached(kind: ArchivedKind) -> ArchivedObject {
    ArchivedObject {
        kind,
        mode: 0o755,
        uid: 0,
        gid: 0,
        atime: ArchivedTime::default(),
        mtime: ArchivedTime::default(),
        xattrs: Vec::new(),
    }
}

#[test]
fn snapshot_fs_archive_import_rejects_malformed_manifests_and_payloads() {
    let base = TempDir::new();
    let (valid, p) = malformed_base(base.path());
    let dest = base.path().join("dest");
    // The base archive imports, and dropping the import removes it.
    drop(import(&valid, &dest, &p).unwrap());
    assert!(!dest.exists());

    let root = valid.shares[0].root;
    let (a, f, s) = (
        object_at(&valid, &["a"]),
        object_at(&valid, &["f"]),
        object_at(&valid, &["s"]),
    );
    let b = object_at(&valid, &["a", "b"]);
    let view_of = |m: &ArchiveManifest, object: u64| {
        m.shares[0]
            .session
            .views
            .iter()
            .position(|v| v.object == object)
            .unwrap()
    };
    let xattr = |name: &[u8], len: usize| ArchivedXattr {
        name: name.to_vec(),
        value: vec![0; len],
    };
    type Case = Box<dyn Fn(&mut ArchiveManifest)>;
    let rename_first = |name: &'static [u8]| -> Case {
        Box::new(move |m| entries_mut(m, root)[0].name = name.to_vec())
    };
    let cases: Vec<(&str, Case)> = vec![
        ("empty name", rename_first(b"")),
        ("dot", rename_first(b".")),
        ("dot dot", rename_first(b"..")),
        ("slash", rename_first(b"x/y")),
        ("NUL", rename_first(b"x\0y")),
        (
            "long name",
            Box::new(move |m| entries_mut(m, root)[0].name = vec![b'x'; 256]),
        ),
        (
            "unsorted",
            Box::new(move |m| entries_mut(m, root).swap(0, 1)),
        ),
        (
            "repeated name",
            Box::new(move |m| {
                let name = entries_mut(m, root)[0].name.clone();
                entries_mut(m, root)[1].name = name;
            }),
        ),
        (
            "entry out of range",
            Box::new(move |m| entries_mut(m, root)[0].object = 1000),
        ),
        (
            "two parents",
            Box::new(move |m| {
                entries_mut(m, root).push(ArchivedEntry {
                    name: b"zz".to_vec(),
                    object: b,
                })
            }),
        ),
        (
            "entry links a tree",
            Box::new(move |m| {
                entries_mut(m, a).push(ArchivedEntry {
                    name: b"zz".to_vec(),
                    object: root,
                })
            }),
        ),
        (
            "detached cycle",
            Box::new(|m| {
                let n = m.objects.len() as u64;
                for other in [n + 1, n] {
                    m.objects.push(detached(ArchivedKind::Directory {
                        entries: vec![ArchivedEntry {
                            name: b"c".to_vec(),
                            object: other,
                        }],
                    }));
                }
            }),
        ),
        (
            "unreferenced object",
            Box::new(|m| m.objects.push(detached(ArchivedKind::Regular { size: 0 }))),
        ),
        (
            "mode bits",
            Box::new(move |m| m.objects[f as usize].mode = 0o10000),
        ),
        (
            "nanoseconds",
            Box::new(move |m| m.objects[f as usize].atime.nsec = 1_000_000_000),
        ),
        (
            "view ctime",
            Box::new(|m| m.shares[0].session.views[0].ctime.nsec = 1_000_000_000),
        ),
        (
            "empty target",
            Box::new(move |m| {
                m.objects[s as usize].kind = ArchivedKind::Symlink { target: Vec::new() }
            }),
        ),
        (
            "long target",
            Box::new(move |m| {
                m.objects[s as usize].kind = ArchivedKind::Symlink {
                    target: vec![b'x'; 4096],
                }
            }),
        ),
        (
            "target NUL",
            Box::new(move |m| {
                m.objects[s as usize].kind = ArchivedKind::Symlink {
                    target: b"a\0b".to_vec(),
                }
            }),
        ),
        (
            "unsorted xattrs",
            Box::new(move |m| {
                m.objects[f as usize].xattrs = vec![xattr(b"user.b", 1), xattr(b"user.a", 1)]
            }),
        ),
        (
            "repeated xattr",
            Box::new(move |m| {
                m.objects[f as usize].xattrs = vec![xattr(b"user.a", 1), xattr(b"user.a", 1)]
            }),
        ),
        (
            "empty xattr name",
            Box::new(move |m| m.objects[f as usize].xattrs = vec![xattr(b"", 1)]),
        ),
        (
            "long xattr value",
            Box::new(move |m| m.objects[f as usize].xattrs = vec![xattr(b"user.a", 65537)]),
        ),
        (
            "size past off_t",
            Box::new(move |m| {
                m.objects[f as usize].kind = ArchivedKind::Regular {
                    size: i64::MAX as u64 + 1,
                }
            }),
        ),
        (
            "files length overflow",
            Box::new(move |m| {
                m.objects[f as usize].kind = ArchivedKind::Regular {
                    size: i64::MAX as u64,
                };
                for _ in 0..2 {
                    m.objects.push(detached(ArchivedKind::Regular {
                        size: i64::MAX as u64,
                    }));
                }
            }),
        ),
        ("init too large", Box::new(|m| m.inits[0] = (64 << 20) + 1)),
        ("init out of range", Box::new(|m| m.shares[0].init = 5)),
        ("init nobody serves", Box::new(|m| m.inits.push(3))),
        ("tree not a directory", Box::new(move |m| m.trees[0] = f)),
        ("tree twice", Box::new(|m| m.trees.push(m.trees[0]))),
        (
            "tree no share uses",
            Box::new(|m| {
                m.trees.push(m.objects.len() as u64);
                m.objects.push(detached(ArchivedKind::Directory {
                    entries: Vec::new(),
                }));
            }),
        ),
        (
            "share root not a directory",
            Box::new(move |m| m.shares[0].root = f),
        ),
        ("no shares", Box::new(|m| m.shares.clear())),
        (
            "repeated view",
            Box::new(|m| {
                let view = m.shares[0].session.views[0];
                m.shares[0].session.views.push(view);
            }),
        ),
        (
            "view uses init.krun's inode",
            Box::new(move |m| {
                let at = view_of(m, s);
                m.shares[0].session.views[at].ino = fuse::ROOT_ID + 1;
            }),
        ),
        (
            "tree object without a view",
            Box::new(move |m| {
                let at = view_of(m, b);
                m.shares[0].session.views.remove(at);
            }),
        ),
        (
            "view of an unreachable object",
            Box::new(|m| {
                let object = m.objects.len() as u64;
                m.objects.push(detached(ArchivedKind::Regular { size: 0 }));
                m.shares[0].session.views.push(ObjectView {
                    object,
                    ino: 1 << 40,
                    ctime: ArchivedTime::default(),
                });
            }),
        ),
        (
            "handle on a symlink",
            Box::new(move |m| {
                let at = view_of(m, s) as u64;
                let handle = m.shares[0]
                    .session
                    .state
                    .handles
                    .iter_mut()
                    .find(|h| h.listing.is_none())
                    .unwrap();
                handle.object = at;
            }),
        ),
        (
            "root node elsewhere",
            Box::new(move |m| {
                let views = &mut m.shares[0].session.views;
                let (r, o) = (view_of_vec(views, root), view_of_vec(views, a));
                views[r].object = a;
                views[o].object = root;
            }),
        ),
        (
            "unknown options",
            Box::new(|m| m.shares[0].session.options = 1 << 63),
        ),
        (
            "writeback disagrees",
            Box::new(|m| m.shares[0].session.options = FsOptions::WRITEBACK_CACHE.bits()),
        ),
        (
            "repeated node",
            Box::new(|m| {
                let node = m.shares[0].session.state.nodes[0].clone();
                m.shares[0].session.state.nodes.push(node);
            }),
        ),
        (
            "pages without a window",
            Box::new(|m| m.shares[0].session.dax_pages = vec![0]),
        ),
    ];
    for (index, (what, case)) in cases.iter().enumerate() {
        let mut m = valid.clone();
        case(&mut m);
        assert!(
            matches!(
                m.validate(),
                Err(ArchiveError::Invalid(_) | ArchiveError::Snapshot(_))
            ),
            "{what}"
        );
        let dest = base.path().join(format!("bad{index}"));
        let result = import(&m, &dest, &p);
        assert!(
            matches!(
                result,
                Err(ArchiveError::Invalid(_) | ArchiveError::Snapshot(_))
            ),
            "{what}: {:?}",
            result.err()
        );
        assert!(!dest.exists(), "{what}");
    }

    // Payloads shorter or longer than the manifest says: refused, and the
    // partial import removed.
    let edits: Vec<(&str, Box<dyn Fn(&mut Payloads)>)> = vec![
        (
            "short files",
            Box::new(|p| {
                p.files.pop();
            }),
        ),
        ("long files", Box::new(|p| p.files.push(0))),
        (
            "short init",
            Box::new(|p| {
                p.init.pop();
            }),
        ),
        ("long pages", Box::new(|p| p.pages.push(0))),
    ];
    for (what, edit) in edits {
        let mut q = Payloads {
            files: p.files.clone(),
            init: p.init.clone(),
            pages: p.pages.clone(),
        };
        edit(&mut q);
        let dest = base.path().join(what);
        let result = import(&valid, &dest, &q);
        assert!(
            matches!(result, Err(ArchiveError::Invalid(_))),
            "{what}: {:?}",
            result.err()
        );
        assert!(!dest.exists(), "{what}");
    }

    // An existing destination is refused and left as it was.
    let taken = base.path().join("taken");
    fs::create_dir(&taken).unwrap();
    fs::write(taken.join("keep"), b"mine").unwrap();
    let result = import(&valid, &taken, &p);
    assert!(
        matches!(&result, Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(entries(&taken), vec![b"keep".to_vec()]);
    assert_eq!(fs::read(taken.join("keep")).unwrap(), b"mine");
}

fn view_of_vec(views: &[ObjectView], object: u64) -> usize {
    views.iter().position(|v| v.object == object).unwrap()
}

/// Import `archive` into a fresh destination under `base` for each created
/// name in turn (the destination first), failing at `stage` of that name
/// after running `hook` on its path, until the import succeeds: the number
/// of names, and the destinations something was left of.
fn leaks_failing_each_name(
    archive: &ShareArchive,
    p: &Payloads,
    base: &Path,
    stage: import_faults::Stage,
    hook: impl Fn(&Path) + Clone + 'static,
) -> (usize, Vec<(usize, PathBuf)>) {
    let mut leaked = Vec::new();
    for name in 1.. {
        // A fresh destination each time, so one leak hides no other.
        let dest = base.join(format!("{stage:?}-{name}"));
        import_faults::fail_at(stage, name, hook.clone());
        match import(archive.manifest(), &dest, p) {
            Err(ArchiveError::Io(e)) if e.raw_os_error() == Some(libc::EIO) => {
                if dest.symlink_metadata().is_ok() {
                    leaked.push((name, dest));
                }
            }
            Ok(imported) => {
                import_faults::disarm();
                drop(imported);
                assert!(!dest.exists());
                return (name - 1, leaked);
            }
            Err(e) => panic!("{stage:?} {name}: {e:?}"),
        }
    }
    unreachable!()
}

/// Everything at and below `path`, a symlink not followed.
fn tree_below(path: &Path) -> Vec<(PathBuf, fs::Metadata)> {
    let meta = fs::symlink_metadata(path).unwrap();
    let mut found = vec![(path.to_path_buf(), meta.clone())];
    if meta.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            found.extend(tree_below(&entry.unwrap().path()));
        }
    }
    found
}

/// Swap the object at `path` for a foreign one of the same type, owner and
/// link count 1 (a regular file for a hard link to one).
fn replace_same_type(path: &Path) {
    let meta = fs::symlink_metadata(path).unwrap();
    let kind = meta.mode() & libc::S_IFMT;
    if kind == libc::S_IFDIR {
        fs::remove_dir(path).unwrap();
        fs::create_dir(path).unwrap();
        return;
    }
    fs::remove_file(path).unwrap();
    match kind {
        libc::S_IFREG => fs::write(path, b"foreign").unwrap(),
        libc::S_IFLNK => std::os::unix::fs::symlink("foreign", path).unwrap(),
        _ => mknod(path, libc::S_IFCHR | 0o600, 0, 0),
    }
    lchown(path, meta.uid(), meta.gid());
}

/// An archive of 11 names to import: the destination, directories (0, a
/// restrictive ro and deeper, the staging one), regular files (ro/f, an
/// orphan), a symlink, a whiteout and hard links (link, sym2).
fn eleven_names(base: &Path) -> (ShareArchive, Payloads) {
    let src = base.join("src");
    fs::create_dir_all(src.join("ro/deeper")).unwrap();
    fs::write(src.join("ro/f"), b"restricted").unwrap();
    fs::hard_link(src.join("ro/f"), src.join("link")).unwrap();
    std::os::unix::fs::symlink("ro/f", src.join("sym")).unwrap();
    fs::hard_link(src.join("sym"), src.join("sym2")).unwrap();
    mknod(&src.join("wh"), libc::S_IFCHR | 0o600, 0, 0);
    fs::write(src.join("orphan"), b"unlinked").unwrap();
    lchown(&src.join("ro"), 1234, 1234);
    chmod(&src.join("ro/deeper"), 0o500);
    chmod(&src.join("ro"), 0o500);
    let cfg = snapshot_config(&src);
    let fs = PassthroughFs::new(cfg.clone()).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let orphan = fs.lookup(CTX, fuse::ROOT_ID, &cstr("orphan")).unwrap();
    fs.open(CTX, orphan.inode, false, libc::O_RDONLY as u32)
        .unwrap();
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("orphan")).unwrap();
    let archive = ShareArchive::capture(vec![ShareSource::active(
        &cfg,
        &fs,
        0,
        fs.checkpoint().unwrap(),
    )])
    .unwrap();
    let p = payloads(&archive);
    (archive, p)
}

#[test]
fn snapshot_fs_archive_failed_import_removes_only_its_own_names() {
    use import_faults::Stage;
    let base = TempDir::new();
    let (archive, p) = eleven_names(base.path());
    // Without CAP_DAC_OVERRIDE the restrictive modes really restrict.
    let _caps = drop_effective_cap(Capability::CAP_DAC_OVERRIDE).unwrap();
    // Failing once a name is journaled and open, or after its identity was
    // journaled but before it was reopened, leaves nothing.
    for stage in [Stage::Created, Stage::Reopen] {
        let result = leaks_failing_each_name(&archive, &p, base.path(), stage, |_| {});
        assert_eq!(result, (11, Vec::new()), "{stage:?}");
    }
    // Failing right after a creation, before its identity was read: a new
    // file's identity comes from its creating descriptor and a hard link's
    // is known before, so those are removed; a directory, symlink or
    // whiteout (7 names) is left, holding only its ancestors.
    let (names, leaked) =
        leaks_failing_each_name(&archive, &p, base.path(), Stage::Identify, |_| {});
    assert_eq!((names, leaked.len()), (11, 7), "{leaked:?}");
    for (_, dest) in &leaked {
        let left = tree_below(dest);
        for (path, meta) in &left {
            assert!(!meta.is_file(), "{path:?}");
            if meta.is_dir() {
                assert!(fs::read_dir(path).unwrap().count() <= 1, "{path:?}");
            }
        }
    }
    // An existing destination is refused untouched before anything is
    // journaled.
    let taken = base.path().join("taken");
    fs::create_dir(&taken).unwrap();
    fs::write(taken.join("keep"), b"mine").unwrap();
    import_faults::fail_at(Stage::Identify, 1, |_| {});
    let result = import(archive.manifest(), &taken, &p);
    import_faults::disarm();
    assert!(
        matches!(&result, Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(entries(&taken), vec![b"keep".to_vec()]);

    // A name something else created inside the import survives it, with
    // the directory holding it; the import's own names do not.
    for stage in [Stage::Created, Stage::Reopen] {
        let dest = base.path().join(format!("planted-{stage:?}"));
        let planted = dest.join("0").join("foreign");
        let plant = planted.clone();
        import_faults::fail_at(stage, 3, move |_| fs::write(&plant, b"not ours").unwrap());
        assert!(import(archive.manifest(), &dest, &p).is_err());
        assert_eq!(entries(&dest), vec![b"0".to_vec()], "{stage:?}");
        assert_eq!(entries(&dest.join("0")), vec![b"foreign".to_vec()]);
        assert_eq!(fs::read(&planted).unwrap(), b"not ours");
    }
}

#[test]
fn snapshot_fs_archive_failed_import_keeps_a_swapped_in_foreign_object() {
    use import_faults::Stage;
    let base = TempDir::new();
    let (archive, p) = eleven_names(base.path());
    let _caps = drop_effective_cap(Capability::CAP_DAC_OVERRIDE).unwrap();
    // Each name in turn is swapped, right after its creation and before
    // its identity was read, for a foreign object of the same type, owner
    // and link count: the foreign object stays.
    let swapped = Arc::new(Mutex::new(Vec::new()));
    for name in 1..=11 {
        let record = swapped.clone();
        import_faults::fail_at(Stage::Identify, name, move |path| {
            replace_same_type(path);
            let meta = fs::symlink_metadata(path).unwrap();
            record
                .lock()
                .unwrap()
                .push((path.to_path_buf(), meta.ino()));
        });
        let dest = base.path().join(format!("swap-{name}"));
        assert!(import(archive.manifest(), &dest, &p).is_err());
    }
    let swapped = swapped.lock().unwrap();
    assert_eq!(swapped.len(), 11);
    let removed: Vec<_> = swapped
        .iter()
        .filter(|(path, ino)| !fs::symlink_metadata(path).is_ok_and(|m| m.ino() == *ino))
        .collect();
    assert!(removed.is_empty(), "{removed:?}");
}

#[test]
fn snapshot_fs_archive_inactive_device_keeps_dax_window_and_init() {
    let p = host_page();
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"file").unwrap();
    // The guest writes the window before it ever activates the device.
    let (w, target) = (Window::new(4), Window::new(4));
    let mut device = Rig::device(&src);
    device.set_shm_region(w.shm());
    w.write(p + 3, b"pre-activation");
    let archive = ShareArchive::capture(vec![device.archive_source().unwrap()]).unwrap();
    let session = &archive.manifest().shares[0].session;
    assert!(session.state.nodes.is_empty());
    assert_eq!(session.dax_pages, vec![p]);
    let pl = payloads(&archive);
    let imported = import(archive.manifest(), &base.path().join("dest"), &pl).unwrap();
    let mut restored = device_on(imported.root(0), false);
    restored.set_shm_region(target.shm());
    restored.restore_imported(&imported, 0).unwrap();
    assert_eq!(target.read(p + 3, 14), b"pre-activation");
    // The guest's own activation continues the pre-FUSE_INIT session.
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rig = Rig::activate(guest, restored, queues, false);
    rig.init();
    rig.lookup(fuse::ROOT_ID, "f");

    // A share keeps serving the archived init.krun, also after a reset.
    let mut cfg = snapshot_config(&src);
    cfg.init_binary = Some(Arc::from(&b"archived init"[..]));
    let archive = ShareArchive::capture(vec![ShareSource::inactive(&cfg, None).unwrap()]).unwrap();
    assert_eq!(archive.manifest().inits, vec![13]);
    let pl = payloads(&archive);
    let imported = import(archive.manifest(), &base.path().join("init"), &pl).unwrap();
    assert_eq!(&*imported.init_binary(0), b"archived init");
    let mut fs = device_on(imported.root(0), false);
    fs.restore_imported(&imported, 0).unwrap();
    let read_init = |rig: &mut Rig| {
        let read = ReadIn {
            fh: 0,
            size: 64,
            ..Default::default()
        };
        rig.ok(Opcode::Read, fuse::ROOT_ID + 1, read.as_slice())
    };
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rig = Rig::activate(guest, fs, queues, false);
    rig.init();
    assert_eq!(read_init(&mut rig), b"archived init");
    rig.fs.reset();
    let fs = mem::replace(&mut rig.fs, Rig::device(&src));
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rig = Rig::activate(guest, fs, queues, false);
    rig.init();
    assert_eq!(read_init(&mut rig), b"archived init");
}

#[test]
fn snapshot_fs_archive_guard_stops_held_devices_before_removing_the_tree() {
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"file").unwrap();
    let mut rig = Rig::new(&src);
    rig.init();
    rig.lookup(fuse::ROOT_ID, "f");
    let queues = rig.freeze();
    let archive = ShareArchive::capture(vec![rig.fs.archive_source().unwrap()]).unwrap();
    let p = payloads(&archive);

    let held = |dest: &Path| {
        let mut imported = import(archive.manifest(), dest, &p).unwrap();
        let mut target = restored_rig(&imported, 0, rig.guest.copy(), &queues, false);
        target.resume();
        let device = Arc::new(Mutex::new(mem::replace(&mut target.fs, Rig::device(&src))));
        assert!(device.lock().unwrap().is_activated());
        imported.hold(device.clone());
        (imported, device)
    };
    // Dropped: the worker is stopped and joined, then the tree removed.
    let dest = base.path().join("dropped");
    let (imported, device) = held(&dest);
    drop(imported);
    assert!(!device.lock().unwrap().is_activated());
    assert!(!dest.exists());
    // Persisted: the tree stays and the device keeps running.
    let dest = base.path().join("kept");
    let (imported, device) = held(&dest);
    imported.persist();
    assert!(device.lock().unwrap().is_activated());
    assert_eq!(fs::read(dest.join("0/f")).unwrap(), b"file");
}

/// Teardown never remaps a DAX window, which its owner may release next
/// (only a guest reset returns a window to zero memory): dropping a device
/// leaves the window as its session mapped it.
#[test]
fn snapshot_fs_archive_dropped_device_leaves_the_dax_window_alone() {
    let p = host_page();
    let base = TempDir::new();
    let src = page_source(&base);
    let w = Window::new(4);
    let mut rig = mapped_rig(&src, &w);
    let dropped = mem::replace(&mut rig.fs, Rig::device(&src));
    drop(dropped);
    assert_eq!(w.read(p, 1), [0x33]);
}

/// Neither does dropping an import guard: it stops the devices it holds
/// and leaves their windows as mapped.
#[test]
fn snapshot_fs_archive_dropped_guard_leaves_held_windows_alone() {
    let p = host_page();
    let base = TempDir::new();
    let src = page_source(&base);
    let w = Window::new(4);
    let rig = mapped_rig(&src, &w);
    let queues = rig.freeze();
    let archive = ShareArchive::capture(vec![rig.fs.archive_source().unwrap()]).unwrap();
    let pl = payloads(&archive);
    let mut imported = import(archive.manifest(), &base.path().join("dest"), &pl).unwrap();
    let target = Window::new(4);
    let mut device = device_on(imported.root(0), false);
    device.set_shm_region(target.shm());
    device.restore_imported(&imported, 0).unwrap();
    assert_eq!(target.read(p, 1), [0x33]);
    let mut restored = Rig::activate(
        rig.guest.copy(),
        device,
        queues.iter().map(QueueState::to_queue).collect(),
        true,
    );
    let device = Arc::new(Mutex::new(mem::replace(
        &mut restored.fs,
        Rig::device(&src),
    )));
    imported.hold(device.clone());
    drop(imported);
    assert!(!device.lock().unwrap().is_activated());
    assert_eq!(target.read(p, 1), [0x33]);
}

/// A private bind mount of `from` on `on`, detached on drop.
struct BindMount(CString);

impl BindMount {
    fn new(from: &Path, on: &Path) -> BindMount {
        let (from, on) = (c_path(from), c_path(on));
        // Safe because both paths are valid C strings.
        let res = unsafe {
            libc::mount(
                from.as_ptr(),
                on.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
        let mount = BindMount(on);
        // Nothing mounted below it later propagates to another view.
        // Safe because the path is a valid C string.
        let res = unsafe {
            libc::mount(
                std::ptr::null(),
                mount.0.as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
        mount
    }
}

impl Drop for BindMount {
    fn drop(&mut self) {
        // Safe because the path is a valid C string.
        unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
    }
}

#[test]
fn snapshot_fs_archive_walks_each_share_through_its_own_mount() {
    let base = TempDir::new();
    let real = base.path().join("real");
    fs::create_dir_all(real.join("sub")).unwrap();
    fs::write(real.join("f"), b"one object").unwrap();
    fs::write(real.join("sub/g"), b"nested").unwrap();
    let (v1, v2, other) = (
        base.path().join("v1"),
        base.path().join("v2"),
        base.path().join("other"),
    );
    for dir in [&v1, &v2, &other] {
        fs::create_dir(dir).unwrap();
    }
    fs::write(other.join("hidden"), b"submount").unwrap();
    let _v1 = BindMount::new(&real, &v1);
    let _v2 = BindMount::new(&real, &v2);
    let capture = |roots: &[&Path]| {
        let cfgs: Vec<_> = roots.iter().map(|root| snapshot_config(root)).collect();
        let sources = cfgs
            .iter()
            .map(|cfg| ShareSource::inactive(cfg, None).unwrap())
            .collect();
        ShareArchive::capture(sources)
    };

    // One directory seen through two mounts: one tree of single objects.
    let archive = capture(&[&v1, &v2]).unwrap();
    let m = archive.manifest();
    assert_eq!(m.shares[0].root, m.shares[1].root);
    assert_eq!(m.trees, vec![m.shares[0].root]);
    let regular = m
        .objects
        .iter()
        .filter(|o| matches!(o.kind, ArchivedKind::Regular { .. }))
        .count();
    assert_eq!(regular, 2);
    let p = payloads(&archive);
    let imported = import(m, &base.path().join("dest"), &p).unwrap();
    assert_eq!(imported.root(0), imported.root(1));
    assert_eq!(fs::read(imported.root(0).join("f")).unwrap(), b"one object");
    assert_eq!(fs::read(imported.root(1).join("sub/g")).unwrap(), b"nested");

    // A submount only one view shows is refused, whichever share is
    // walked first; the other view alone holds none.
    let _sub = BindMount::new(&other, &v1.join("sub"));
    assert_eq!(fs::read(v2.join("sub/g")).unwrap(), b"nested");
    for roots in [[&v1, &v2], [&v2, &v1]] {
        let result = capture(&[roots[0], roots[1]]);
        assert!(
            matches!(result, Err(ArchiveError::Unsupported(_))),
            "{roots:?}: {:?}",
            result.err()
        );
    }
    capture(&[&v2]).unwrap();
}

/// Activate `fs` on fresh queues; false if it refuses.
fn activates(fs: &mut Fs) -> bool {
    let guest = Guest::new(0xfffe);
    let interrupt =
        InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
    let queues = fresh_queues(&guest)
        .into_iter()
        .map(|q| DeviceQueue::new(q, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())))
        .collect();
    fs.activate(guest.mem.clone(), interrupt, queues).is_ok()
}

/// FUSE_SETUPMAPPING of the first host page of `nodeid` at `moffset`.
fn map_page(rig: &mut Rig, nodeid: u64, moffset: u64) -> OutHeader {
    let setup = SetupmappingIn {
        fh: 0,
        foffset: 0,
        len: host_page(),
        flags: SetupmappingFlags::READ.bits(),
        moffset,
    };
    rig.call(Opcode::SetupMapping, nodeid, setup.as_slice()).0
}

/// An activated device on `src` (holding "f") over window `w`, after
/// FUSE_INIT and a lookup of "f".
fn window_rig(src: &Path, w: &Window) -> (Rig, EntryOut) {
    let mut device = Rig::device(src);
    device.set_shm_region(w.shm());
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rig = Rig::activate(guest, device, queues, false);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    (rig, f)
}

/// A session over `w` mapping "f" at page 1 with a hole at page 3, frozen.
fn mapped_rig(src: &Path, w: &Window) -> Rig {
    let p = host_page();
    let (mut rig, f) = window_rig(src, w);
    assert_eq!(map_page(&mut rig, f.nodeid, p).error, 0);
    let removal = [
        RemovemappingIn { count: 1 }.as_slice(),
        RemovemappingOne {
            moffset: 3 * p,
            len: p,
        }
        .as_slice(),
    ]
    .concat();
    rig.ok(Opcode::RemoveMapping, 0, &removal);
    rig.freeze();
    rig
}

fn page_source(base: &TempDir) -> PathBuf {
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), paged(1, 0x33)).unwrap();
    src
}

#[test]
fn snapshot_fs_archive_failed_reset_retires_the_device() {
    use passthrough::dax_faults::{arm, Fault};
    let base = TempDir::new();
    let src = page_source(&base);
    let w = Window::new(4);
    let mut rig = mapped_rig(&src, &w);
    let session = rig.fs.snapshot_session().unwrap().unwrap();
    rig.resume();
    // The reset's remapping fails, leaving a window nothing describes: the
    // device activates, restores and captures nothing anymore.
    arm(w.addr, Fault::MapAfterUnmap);
    rig.fs.reset();
    let mut lost = mem::replace(&mut rig.fs, Rig::device(&src));
    assert!(!activates(&mut lost));
    assert!(matches!(
        lost.restore_session(
            session.options,
            &session.passthrough.state,
            same_host_objects(&session.passthrough),
            session.passthrough.init_binary.clone(),
            &session.passthrough.dax_pages,
        ),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    assert!(matches!(
        lost.archive_source(),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    drop(lost);
    reclaim(w, 0, 4 * host_page());
}

#[test]
fn snapshot_fs_archive_reset_leaves_a_lost_window_alone() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let base = TempDir::new();
    let src = page_source(&base);
    let w = Window::new(4);
    let (mut rig, f) = window_rig(&src, &w);
    // A failed host mapping lost the window, part of it unmapped.
    arm(w.addr + p, Fault::MapAfterUnmap);
    assert_eq!(map_page(&mut rig, f.nodeid, p).error, -libc::ENOMEM);
    rig.fs.reset();
    // The reset left it alone: the unmapped page is still free.
    // Safe because MAP_FIXED_NOREPLACE never replaces another mapping.
    let hole = unsafe {
        libc::mmap(
            (w.addr + p) as *mut libc::c_void,
            p as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(hole as u64, w.addr + p, "the reset remapped a lost window");
    let mut lost = mem::replace(&mut rig.fs, Rig::device(&src));
    assert!(!activates(&mut lost));
    assert!(matches!(
        lost.archive_source(),
        Err(PassthroughSnapshotError::DaxLost)
    ));
}

#[test]
fn snapshot_fs_archive_reset_ends_a_pending_restored_session() {
    let p = host_page();
    let base = TempDir::new();
    let src = page_source(&base);
    let source_window = Window::new(4);
    let source = mapped_rig(&src, &source_window);
    let session = source.fs.snapshot_session().unwrap().unwrap();
    let init: Arc<[u8]> = Arc::from(&b"archived init"[..]);
    let w = Window::new(4);
    let mut fs = Rig::device(&src);
    fs.set_shm_region(w.shm());
    fs.restore_session(
        session.options,
        &session.passthrough.state,
        same_host_objects(&session.passthrough),
        init.clone(),
        &session.passthrough.dax_pages,
    )
    .unwrap();
    assert_eq!(w.read(p, 1), [0x33]);
    // A reset before the activation drops the restored session and its
    // mappings (the file page first: the hole would fault)...
    fs.reset();
    assert_eq!(w.read(p, p), vec![0; p as usize]);
    assert_eq!(w.read(0, 4 * p), vec![0; 4 * p as usize]);
    // ...so the activation starts a new session (FUSE_INIT) that serves
    // the archived init.krun.
    let guest = Guest::new(0xfffe);
    let queues = fresh_queues(&guest);
    let mut rig = Rig::activate(guest, fs, queues, false);
    rig.init();
    let read = ReadIn {
        fh: 0,
        size: 64,
        ..Default::default()
    };
    assert_eq!(
        rig.ok(Opcode::Read, fuse::ROOT_ID + 1, read.as_slice()),
        &init[..]
    );
}

#[test]
fn snapshot_fs_archive_capture_needs_every_xattr_visible() {
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"").unwrap();
    set_xattr(&src.join("f"), "trusted.known", b"kept");
    let s = src.join("s");
    std::os::unix::fs::symlink("f", &s).unwrap();
    set_times(&s, (300, 0), (400, 0));
    {
        // Without CAP_SYS_ADMIN the kernel hides trusted.known.
        let _caps = drop_effective_cap(Capability::CAP_SYS_ADMIN)
            .unwrap()
            .expect("the archive tests run with CAP_SYS_ADMIN");
        let result = capture_dir(&src);
        assert!(
            matches!(result, Err(ArchiveError::Unsupported(_))),
            "{:?}",
            result.err()
        );
    }
    // Refused before anything was read: a readlink would move this atime.
    assert_eq!(meta_of(&s).3, 300);
    let archive = capture_dir(&src).unwrap();
    let m = archive.manifest();
    let f = object_at(m, &["f"]);
    assert_eq!(
        m.objects[f as usize].xattrs,
        vec![ArchivedXattr {
            name: b"trusted.known".to_vec(),
            value: b"kept".to_vec(),
        }]
    );
}
