// Guest-visible archive tests without privilege (names start with
// "rootless_fs"). They run as BoxLite's default jailer runs the shim: a
// non-root user in a user namespace mapping only its own IDs, with no
// capability, e.g. through `make snapshot-rootless-test`; every test checks
// that first and fails elsewhere. `make snapshot-test` skips them.

use super::*;

/// The nsfs inode number of the initial user namespace.
const USER_NS_INIT_INO: u64 = 0xEFFF_FFFD;

/// Panic unless this process runs as BoxLite's jailer runs the shim: a
/// non-root user in a user namespace whose ID maps hold only its own
/// effective IDs (bwrap nests one namespace in another, so the outer IDs
/// they map to are not checked), with every capability set empty, the
/// bounding set included; returns those IDs.
fn assert_rootless() -> (u32, u32) {
    // Safe because these calls only return the effective IDs.
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

/// Exit status after a trapped syscall.
const SIGSYS_EXIT: i32 = 159;

/// On SIGSYS (a syscall the filter traps), print the syscall number and
/// exit: only `write` and `exit_group`, which every filter allows.
extern "C" fn report_sigsys(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // Safe because the kernel passes a SIGSYS siginfo, whose si_syscall
    // follows the 8-byte si_call_addr at offset 24 on 64-bit Linux.
    let mut nr = unsafe { *(info as *const u8).add(24).cast::<i32>() };
    let mut msg = *b"SIGSYS: the seccomp filter trapped syscall 0000\n";
    for digit in msg[43..47].iter_mut().rev() {
        *digit = b'0' + (nr % 10) as u8;
        nr /= 10;
    }
    // Safe because these are async-signal-safe calls on a stack buffer.
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::_exit(SIGSYS_EXIT);
    }
}

/// Run `f` on a new thread (and its children) under the seccomp filter
/// `KRUN_TEST_SECCOMP_BPF` names (raw `sock_filter` instructions).
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
    // Safe because the sigaction is zeroed but for a valid SA_SIGINFO
    // handler.
    unsafe {
        let mut action: libc::sigaction = mem::zeroed();
        action.sa_sigaction = report_sigsys as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()),
            0
        );
    }
    thread::scope(|scope| {
        scope
            .spawn(|| {
                let prog = libc::sock_fprog {
                    len: program.len() as u16,
                    filter: program.as_ptr() as *mut _,
                };
                // Safe because `prog` points at `program`, alive for the
                // call; the filter applies to this thread only.
                unsafe {
                    assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                    let res = libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        0,
                        &prog as *const libc::sock_fprog,
                    );
                    assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
                }
                f()
            })
            .join()
            .unwrap()
    })
}

fn capture_visible(shares: Vec<ShareSource<'_>>) -> Result<ShareArchive, ArchiveError> {
    ShareArchive::capture(shares, ArchiveMode::GuestVisible)
}

fn capture_visible_dir(dir: &Path) -> Result<ShareArchive, ArchiveError> {
    let cfg = snapshot_config(dir);
    capture_visible(vec![ShareSource::inactive(&cfg, None)?])
}

fn refused(result: Result<ShareArchive, ArchiveError>, why: &str) {
    match result {
        Err(ArchiveError::Unsupported(got)) => assert!(got.contains(why), "{got}"),
        other => panic!("{why}: {:?}", other.err()),
    }
}

/// An ACL naming this process's user and group, the only ones it can name.
fn own_acl(uid: u32, gid: u32) -> Vec<u8> {
    const ANY: u32 = u32::MAX;
    acl(&[
        (0x01, 7, ANY),
        (0x02, 6, uid),
        (0x04, 5, ANY),
        (0x08, 4, gid),
        (0x10, 7, ANY),
        (0x20, 4, ANY),
    ])
}

/// A tree of every kind the contract keeps, owned by this process.
fn visible_tree(src: &Path, uid: u32, gid: u32) -> Vec<&'static str> {
    fs::create_dir(src).unwrap();
    let f = src.join("f");
    fs::write(&f, b"visible").unwrap();
    // A hole in the middle stays a hole.
    let sparse = File::create(src.join("sparse")).unwrap();
    sparse.write_all_at(b"tail", 1 << 20).unwrap();
    fs::write(src.join("empty"), b"").unwrap();
    set_xattr(&f, "user.a", b"1");
    set_xattr(&f, "user.empty", b"");
    set_xattr(&f, "system.posix_acl_access", &own_acl(uid, gid));
    chmod(&f, 0o6750);
    fs::hard_link(&f, src.join("link")).unwrap();
    std::os::unix::fs::symlink("f", src.join("s")).unwrap();
    mknod(&src.join("wh"), libc::S_IFCHR | 0o600, 0, 0);
    let d = src.join("d");
    fs::create_dir(&d).unwrap();
    set_xattr(&d, "system.posix_acl_default", &own_acl(uid, gid));
    set_xattr(&d, "user.dir", b"d");
    fs::write(d.join("c"), b"child").unwrap();
    fs::hard_link(&f, d.join("link2")).unwrap();
    fs::write(src.join(OsStr::from_bytes(b"bad\xff")), b"non-utf8").unwrap();
    chmod(&d, 0o3770);
    let ro = src.join("ro");
    fs::create_dir(&ro).unwrap();
    fs::write(ro.join("inside"), b"read-only dir").unwrap();
    chmod(&ro.join("inside"), 0o444);
    chmod(&ro, 0o555);
    for (i, path) in ["f", "s", "wh", "d/c", "ro/inside", "sparse"]
        .iter()
        .enumerate()
    {
        set_times(
            &src.join(path),
            (100 + i as i64, 7),
            (200 + i as i64, 999_999_999),
        );
    }
    for (path, sec) in [(&d, 500), (&ro, 600), (&src.to_path_buf(), 700)] {
        set_times(path, (sec, 1), (sec + 1, 2));
    }
    vec![
        "",
        "f",
        "sparse",
        "empty",
        "link",
        "s",
        "wh",
        "d",
        "d/c",
        "d/link2",
        "ro",
        "ro/inside",
    ]
}

#[test]
fn rootless_fs_guest_visible_round_trip_keeps_what_the_guest_sees() {
    let (uid, gid) = assert_rootless();
    let base = TempDir::new();
    let src = base.path().join("src");
    let paths = visible_tree(&src, uid, gid);
    let before: Vec<_> = paths
        .iter()
        .map(|p| (meta_of(&src.join(p)), xattrs_of(&src.join(p))))
        .collect();

    let archive = capture_visible_dir(&src).unwrap();
    assert_eq!(
        archive.manifest().contract,
        ArchiveContract::GuestVisible { uid, gid }
    );
    let p = payloads(&archive);
    let manifest = archive.manifest().clone();
    drop(archive);
    let dest = base.path().join("dest");
    let imported = import(&manifest, &dest, &p).unwrap();
    let root = imported.root(0).to_path_buf();
    for (path, saved) in paths.iter().zip(&before) {
        let got = (meta_of(&root.join(path)), xattrs_of(&root.join(path)));
        // The symlink's atime moved when the capture read its target; the
        // archive holds the one from before.
        if *path == "s" {
            assert_eq!(
                (got.0 .0, got.0 .1, got.0 .2),
                (saved.0 .0, saved.0 .1, saved.0 .2)
            );
            assert_eq!((got.0 .5, got.0 .6), (saved.0 .5, saved.0 .6));
            continue;
        }
        assert_eq!(&got, saved, "{path}");
    }
    assert_eq!(fs::read(root.join("f")).unwrap(), b"visible");
    assert_eq!(fs::read(root.join("d/c")).unwrap(), b"child");
    assert_eq!(fs::read(root.join("ro/inside")).unwrap(), b"read-only dir");
    assert_eq!(
        fs::read(root.join(OsStr::from_bytes(b"bad\xff"))).unwrap(),
        b"non-utf8"
    );
    let sparse = fs::metadata(root.join("sparse")).unwrap();
    assert_eq!(sparse.len(), (1 << 20) + 4);
    assert!(sparse.blocks() * 512 < 1 << 20, "the hole was filled");
    let f = fs::metadata(root.join("f")).unwrap();
    assert_eq!(f.nlink(), 3);
    assert_eq!(fs::metadata(root.join("d/link2")).unwrap().ino(), f.ino());
    assert_eq!(fs::read_link(root.join("s")).unwrap(), Path::new("f"));
    let wh = fs::symlink_metadata(root.join("wh")).unwrap();
    assert_eq!((wh.mode() & libc::S_IFMT, wh.rdev()), (libc::S_IFCHR, 0));
    imported.persist();
    // Writable for its owner again, so the TempDir can go.
    chmod(&root.join("ro"), 0o755);
    chmod(&src.join("ro"), 0o755);
}

/// Capture, payload writing, import and session restore of the visible
/// tree run under the shim's seccomp filter (`under_seccomp`).
#[test]
fn rootless_fs_guest_visible_archive_runs_under_the_seccomp_filter() {
    let (uid, gid) = assert_rootless();
    let base = TempDir::new();
    let src = base.path().join("src");
    let paths = visible_tree(&src, uid, gid);
    let dest = base.path().join("dest");
    let root = under_seccomp(|| {
        let archive = capture_visible_dir(&src).unwrap();
        let p = payloads(&archive);
        let imported = import(archive.manifest(), &dest, &p).unwrap();
        let session = imported.session(0).unwrap();
        let restored = PassthroughFs::restore(
            snapshot_config(imported.root(0)),
            &session.state,
            session.objects,
            imported.init_binary(0),
        )
        .unwrap();
        restored.init(FsOptions::empty()).unwrap();
        restored.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
        let root = imported.root(0).to_path_buf();
        imported.persist();
        root
    });
    for path in &paths {
        let (got, want) = (meta_of(&root.join(path)), meta_of(&src.join(path)));
        // Mode, owner and mtime; atimes moved when the source was read.
        assert_eq!(
            (got.0, got.1, got.2, got.5, got.6),
            (want.0, want.1, want.2, want.5, want.6),
            "{path}"
        );
        assert_eq!(
            xattrs_of(&root.join(path)),
            xattrs_of(&src.join(path)),
            "{path}"
        );
    }
    chmod(&root.join("ro"), 0o755);
    chmod(&src.join("ro"), 0o755);
}

/// A session with handles (one on an unlinked file) and a DAX file mapping
/// continues on the imported copy without the source.
#[test]
fn rootless_fs_guest_visible_session_and_dax_continue() {
    assert_rootless();
    let p = host_page();
    let base = TempDir::new();
    let src = base.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("held"), b"handle only").unwrap();
    fs::write(src.join("mapped"), paged(1, 0x5a)).unwrap();
    fs::write(src.join("data"), b"hello rootless").unwrap();
    let (w, target) = (Window::new(4), Window::new(4));
    let cfg = snapshot_config(&src);
    let fs = PassthroughFs::new(cfg.clone()).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let held = fs.lookup(CTX, fuse::ROOT_ID, &cstr("held")).unwrap();
    let (handle, _) = fs
        .open(CTX, held.inode, false, libc::O_RDONLY as u32)
        .unwrap();
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("held")).unwrap();
    let mapped = fs.lookup(CTX, fuse::ROOT_ID, &cstr("mapped")).unwrap();
    setup(&fs, &w, mapped.inode, 0, 1, true, 0).unwrap();
    let data = fs.lookup(CTX, fuse::ROOT_ID, &cstr("data")).unwrap();
    fs.sync_for_snapshot().unwrap();
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let archive = capture_visible(vec![ShareSource::active(&cfg, &fs, 0, checkpoint)]).unwrap();
    let pl = payloads(&archive);
    let manifest = archive.manifest().clone();
    drop((archive, fs));
    fs::remove_dir_all(&src).unwrap();

    let imported = import(&manifest, &base.path().join("dest"), &pl).unwrap();
    let session = imported.session(0).unwrap();
    let restored = PassthroughFs::restore(
        snapshot_config(imported.root(0)),
        &session.state,
        session.objects,
        imported.init_binary(0),
    )
    .unwrap();
    restored.map_dax(target.dax(), &session.dax_pages).unwrap();
    assert_eq!(target.read(0, p), paged(1, 0x5a));
    let again = restored.checkpoint().unwrap();
    let held_handle = again
        .state
        .handles
        .iter()
        .find(|h| Some(h.handle) == handle)
        .unwrap();
    let held_file = &again.objects[held_handle.object as usize].file;
    assert_eq!(held_file.metadata().unwrap().nlink(), 0);
    let bytes = fs::read(format!("/proc/self/fd/{}", held_file.as_raw_fd())).unwrap();
    assert_eq!(bytes, b"handle only");
    let (st, _) = restored.getattr(CTX, data.inode, None).unwrap();
    assert_eq!(st.st_ino, data.attr.st_ino);
    // The writable mapping reaches the imported copy.
    target.write(0, b"Z");
    restored.sync_for_snapshot().unwrap();
    let copy = imported.root(0).to_path_buf();
    imported.persist();
    // The window's file mapping is still the copy's after a new checkpoint.
    let again = restored.checkpoint_with_dax(Some(target.dax())).unwrap();
    assert!(matches!(
        again.state.dax.unwrap().mappings[0].kind,
        DaxMappingKind::File { writable: true, .. }
    ));
    assert_eq!(fs::read(copy.join("mapped")).unwrap()[0], b'Z');
}

/// Whatever the guest could see but the archive could not keep or an
/// unprivileged import could not recreate fails the capture: never a
/// partial archive.
#[test]
fn rootless_fs_guest_visible_capture_fails_instead_of_dropping() {
    assert_rootless();
    let base = TempDir::new();
    let case = |name: &str, mode: u32, file: bool| {
        let dir = base.path().join(name);
        fs::create_dir(&dir).unwrap();
        let target = dir.join("x");
        if file {
            fs::write(&target, b"secret").unwrap();
        } else {
            fs::create_dir(&target).unwrap();
            fs::write(target.join("inner"), b"").unwrap();
        }
        chmod(&target, mode);
        let result = capture_visible_dir(&dir);
        chmod(&target, 0o700);
        result
    };
    // An unreadable file, an unlistable directory and an unsearchable one.
    refused(case("unreadable", 0o200, true), "cannot read");
    refused(case("unlistable", 0o300, false), "cannot read");
    refused(case("unsearchable", 0o600, false), "cannot read");
    // A FIFO is outside every contract.
    let fifo = base.path().join("fifo");
    fs::create_dir(&fifo).unwrap();
    mknod(&fifo.join("p"), libc::S_IFIFO | 0o600, 0, 0);
    refused(capture_visible_dir(&fifo), "special file");
    // An object this user does not own (root's, unmapped here) cannot be
    // recreated with its owner.
    refused(capture_visible_dir(Path::new("/usr")), "owner");
    // Full attributes stay privileged: refused before anything is read.
    let full = capture_full(vec![ShareSource::inactive(
        &snapshot_config(base.path()),
        None,
    )
    .unwrap()]);
    refused(full, "CAP_SYS_ADMIN");
}

/// A failed import removes what it created, read-only directories
/// included, and an import under other IDs creates nothing.
#[test]
fn rootless_fs_guest_visible_failed_import_leaves_nothing() {
    let (uid, gid) = assert_rootless();
    let base = TempDir::new();
    let src = base.path().join("src");
    visible_tree(&src, uid, gid);
    let archive = capture_visible_dir(&src).unwrap();
    let (mut p, intact) = (payloads(&archive), payloads(&archive));
    let manifest = archive.manifest().clone();
    drop(archive);
    chmod(&src.join("ro"), 0o755);

    p.files.pop();
    let dest = base.path().join("dest");
    assert!(import(&manifest, &dest, &p).is_err());
    assert!(!dest.exists());

    let mut other = manifest.clone();
    other.contract = ArchiveContract::GuestVisible { uid: uid + 1, gid };
    for object in &mut other.objects {
        object.uid = uid + 1;
        // ACLs name the recorded user.
        object.xattrs.retain(|x| x.name.starts_with(b"user."));
    }
    other.validate().unwrap();
    match import(&other, &dest, &intact) {
        Err(ArchiveError::Unsupported(why)) => assert!(why.contains("identity"), "{why}"),
        other => panic!("imported under other IDs: {:?}", other.err()),
    }
    assert!(!dest.exists());
}

/// Actual ancillary transfer after the receiver installs the production filter.
fn receive_roles(socket: &std::os::unix::net::UnixDatagram, expected: usize) -> Vec<File> {
    let mut byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = vec![0usize; 128];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() * mem::size_of::<usize>();
    assert_eq!(
        unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) },
        1
    );
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!header.is_null());
    assert_eq!(unsafe { (*header).cmsg_type }, libc::SCM_RIGHTS);
    assert_eq!(
        unsafe { (*header).cmsg_len },
        unsafe { libc::CMSG_LEN((expected * 4) as u32) } as usize
    );
    let data = unsafe { libc::CMSG_DATA(header).cast::<i32>() };
    (0..expected)
        .map(|i| unsafe { File::from_raw_fd(*data.add(i)) })
        .collect()
}
fn send_roles(socket: &std::os::unix::net::UnixDatagram, files: &[File]) {
    let mut byte = [1u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = vec![0usize; 128];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE((files.len() * 4) as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((files.len() * 4) as u32) as usize;
        let data = libc::CMSG_DATA(header).cast::<i32>();
        for (index, file) in files.iter().enumerate() {
            *data.add(index) = file.as_raw_fd();
        }
        assert_eq!(libc::sendmsg(socket.as_raw_fd(), &message, 0), 1);
    }
}

#[test]
fn rootless_fs_external_received_orphan_handle_and_writable_dax() {
    assert_rootless();
    let dir = TempDir::new();
    dir.file("orphan", &paged(1, 0x55));
    let source = init_share(dir.path());
    let inode = source
        .lookup(CTX, fuse::ROOT_ID, &cstr("orphan"))
        .unwrap()
        .inode;
    let handle = source
        .open(CTX, inode, false, libc::O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let window = Window::new(2);
    setup(&source, &window, inode, 0, 1, true, 0).unwrap();
    let handle_fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("orphan"))
        .unwrap();
    let dax_fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("orphan"))
        .unwrap();
    source.unlink(CTX, fuse::ROOT_ID, &cstr("orphan")).unwrap();
    source.sync_for_snapshot().unwrap();
    let checkpoint = source.checkpoint_with_dax(Some(window.dax())).unwrap();
    let object = checkpoint
        .state
        .handles
        .iter()
        .find(|h| h.handle == handle)
        .unwrap()
        .object;
    let object_count = checkpoint.objects.len();
    let mut sent: Vec<File> = same_host_objects(&checkpoint)
        .into_iter()
        .map(|o| o.file)
        .collect();
    sent.push(handle_fd.try_clone().unwrap());
    sent.push(dax_fd);
    let (sender, receiver) = std::os::unix::net::UnixDatagram::pair().unwrap();
    send_roles(&sender, &sent);
    drop(sent);
    drop(source);
    under_seccomp(move || {
        let mut received = receive_roles(&receiver, object_count + 2);
        for fd in &received {
            assert_ne!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        let dax = received.pop().unwrap();
        let open = received.pop().unwrap();
        let objects = received
            .into_iter()
            .zip(&checkpoint.objects)
            .map(|(file, saved)| RestoredObject {
                file,
                guest_ino: saved.guest_ino,
                ctime: saved.ctime,
            })
            .collect();
        let roles = passthrough::RestoredRoles {
            handles: [(handle, open)].into(),
            dax: [((object, true), dax)].into(),
        };
        let restored = PassthroughFs::restore_with_roles(
            snapshot_config(dir.path()),
            &checkpoint.state,
            objects,
            checkpoint.init_binary.clone(),
            roles,
        )
        .unwrap();
        let target = Window::new(2);
        restored
            .map_dax(target.dax(), &checkpoint.dax_pages)
            .unwrap();
        target.write(0, b"received writable DAX");
        let mut bytes = vec![0; 21];
        handle_fd.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"received writable DAX");
        // Real production FUSE handle reads through the supplied orphan FD.
        #[derive(Default)]
        struct ReadResult(Vec<u8>);
        impl std::io::Write for ReadResult {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::virtio::fs::filesystem::ZeroCopyWriter for ReadResult {
            fn write_from(
                &mut self,
                file: &File,
                count: usize,
                offset: u64,
            ) -> std::io::Result<usize> {
                let mut bytes = vec![0; count];
                let len = file.read_at(&mut bytes, offset)?;
                self.0.extend_from_slice(&bytes[..len]);
                Ok(len)
            }
        }
        let mut output = ReadResult::default();
        restored
            .read(CTX, inode, handle, &mut output, 21, 0, None, 0)
            .unwrap();
        assert_eq!(output.0, bytes);
        assert!(restored
            .lookup(CTX, fuse::ROOT_ID, &cstr("orphan"))
            .is_err());
        drop(restored);
    });
}
