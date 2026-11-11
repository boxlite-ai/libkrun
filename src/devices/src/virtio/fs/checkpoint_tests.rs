// SPDX-License-Identifier: Apache-2.0

// Shared by the Linux and macOS passthrough checkpoint implementations.
use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use utils::tempdir::TempDir;

const CHILD_CASE: &str = "KRUN_FS_CHECKPOINT_TEST_CASE";

fn run_isolated(test: &str, case: &str) {
    let module = module_path!().split_once("::").unwrap().1;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &format!("{module}::{test}"), "--nocapture"])
        .env(CHILD_CASE, case)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{case}: {status}");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("{case}: filesystem checkpoint blocked");
        }
        std::thread::sleep(Duration::from_millis(10));
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
fn restore_skips_fifo_replacements_without_blocking() {
    if std::env::var(CHILD_CASE).as_deref() != Ok("fifo") {
        run_isolated("restore_skips_fifo_replacements_without_blocking", "fifo");
        return;
    }
    let dir = TempDir::new().unwrap();
    let root = dir.as_path();
    std::fs::write(root.join("file"), b"original").unwrap();
    let cfg = Config {
        root_dir: root.to_str().unwrap().into(),
        ..Default::default()
    };
    let source = PassthroughFs::new(cfg.clone()).unwrap();
    source.init(FsOptions::empty()).unwrap();
    let inode = source
        .lookup(context(), fuse::ROOT_ID, c"file")
        .unwrap()
        .inode;
    for flags in [libc::O_RDONLY, libc::O_WRONLY] {
        source.open(context(), inode, false, flags as u32).unwrap();
    }
    let state = source.save_state().unwrap();
    std::fs::remove_file(root.join("file")).unwrap();
    let path = CString::new(root.join("file").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut target = PassthroughFs::new(cfg).unwrap();
    target.restore_state(&state).unwrap();
    assert!(target.handles.read().unwrap().is_empty());
    assert_eq!(
        target.do_getattr(inode).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(
        target.next_handle.load(Ordering::Acquire),
        state.next_handle
    );
}

#[test]
fn restore_propagates_descriptor_exhaustion_without_partial_state() {
    let case = std::env::var(CHILD_CASE).unwrap_or_default();
    if case != "inodes" && case != "handles" {
        for case in ["inodes", "handles"] {
            run_isolated(
                "restore_propagates_descriptor_exhaustion_without_partial_state",
                case,
            );
        }
        return;
    }
    let dir = TempDir::new().unwrap();
    let cfg = Config {
        root_dir: dir.as_path().to_str().unwrap().into(),
        ..Default::default()
    };
    let source = PassthroughFs::new(cfg.clone()).unwrap();
    source.init(FsOptions::empty()).unwrap();
    for index in 0..4 {
        let name = format!("file{index}");
        std::fs::write(dir.as_path().join(&name), b"contents").unwrap();
        let name = CString::new(name).unwrap();
        let inode = source
            .lookup(context(), fuse::ROOT_ID, &name)
            .unwrap()
            .inode;
        source
            .open(context(), inode, false, libc::O_RDONLY as u32)
            .unwrap();
    }
    let mut state = source.save_state().unwrap();
    drop(source);
    if case == "handles" {
        // Open handles may outlive the guest's inode lookup references.
        state.inodes.clear();
    }
    let mut target = PassthroughFs::new(cfg).unwrap();
    // Leave room for the root/probe so failure occurs inside the restore loops.
    let available = if cfg!(target_os = "macos") && case == "inodes" {
        1
    } else {
        3
    };
    let result = with_descriptor_limit(available, || target.restore_state(&state));
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
    assert!(target.inodes.read().unwrap().values().next().is_none());
    assert!(target.handles.read().unwrap().is_empty());
    target.restore_state(&state).unwrap();
    assert_eq!(target.handles.read().unwrap().len(), state.handles.len());
    assert_eq!(
        target.inodes.read().unwrap().values().count(),
        state.inodes.len()
    );
}

fn with_descriptor_limit<T>(available: usize, action: impl FnOnce() -> T) -> T {
    let mut original_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original_limit) },
        0
    );
    let limit = libc::rlimit {
        rlim_cur: 64.min(original_limit.rlim_cur),
        rlim_max: original_limit.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let mut occupied = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => occupied.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    assert!(occupied.len() >= available);
    occupied.truncate(occupied.len() - available);
    let result = action();
    drop(occupied);
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit) },
        0
    );
    result
}

#[test]
fn capture_and_restore_lookup_only_fifo_without_blocking() {
    if std::env::var(CHILD_CASE).as_deref() != Ok("capture_fifo") {
        run_isolated(
            "capture_and_restore_lookup_only_fifo_without_blocking",
            "capture_fifo",
        );
        return;
    }
    let dir = TempDir::new().unwrap();
    let root = dir.as_path();
    let path = CString::new(root.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let cfg = Config {
        root_dir: root.to_str().unwrap().into(),
        ..Default::default()
    };
    let source = PassthroughFs::new(cfg.clone()).unwrap();
    source.init(FsOptions::empty()).unwrap();
    let inode = source
        .lookup(context(), fuse::ROOT_ID, c"fifo")
        .unwrap()
        .inode;
    let state = source.save_state().unwrap();
    let saved = state
        .inodes
        .iter()
        .find(|saved| saved.inode == inode)
        .unwrap();
    assert_eq!(saved.object.path.as_deref(), Some(b"fifo".as_slice()));
    assert_eq!(saved.object.kind, u32::from(libc::S_IFIFO));
    let mut target = PassthroughFs::new(cfg.clone()).unwrap();
    target.restore_state(&state).unwrap();
    target.do_getattr(inode).unwrap();

    std::fs::remove_file(root.join("fifo")).unwrap();
    let deleted = source.save_state().unwrap();
    assert!(deleted
        .inodes
        .iter()
        .find(|saved| saved.inode == inode)
        .unwrap()
        .object
        .path
        .is_none());
    let mut target = PassthroughFs::new(cfg).unwrap();
    target.restore_state(&deleted).unwrap();
    assert_eq!(
        target.do_getattr(inode).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn capture_propagates_descriptor_exhaustion_and_can_retry() {
    if std::env::var(CHILD_CASE).as_deref() != Ok("capture_emfile") {
        run_isolated(
            "capture_propagates_descriptor_exhaustion_and_can_retry",
            "capture_emfile",
        );
        return;
    }
    let dir = TempDir::new().unwrap();
    let source = PassthroughFs::new(Config {
        root_dir: dir.as_path().to_str().unwrap().into(),
        ..Default::default()
    })
    .unwrap();
    source.init(FsOptions::empty()).unwrap();
    let result = with_descriptor_limit(0, || source.save_state());
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
    let state = source.save_state().unwrap();
    assert_eq!(state.inodes.len(), 1);
    assert_eq!(state.inodes[0].object.path, Some(Vec::new()));
}

#[cfg(target_os = "macos")]
#[test]
fn capture_propagates_getpath_failure_for_a_live_inode() {
    let dir = TempDir::new().unwrap();
    let root = std::fs::canonicalize(dir.as_path()).unwrap();
    let mut parents = vec![File::open(&root).unwrap()];
    let name = CString::new("d".repeat(80)).unwrap();
    // Relative operations can create a path exceeding F_GETPATH's PATH_MAX buffer.
    for _ in 0..14 {
        let parent = parents.last().unwrap().as_raw_fd();
        assert_eq!(unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) }, 0);
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        parents.push(unsafe { File::from_raw_fd(fd) });
    }
    let result = Object::capture(parents.last().unwrap(), &root);
    // Remove by parent descriptor too, so cleanup does not need the long path.
    while parents.len() > 1 {
        parents.pop();
        assert_eq!(
            unsafe {
                libc::unlinkat(
                    parents.last().unwrap().as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            },
            0
        );
    }
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSPC));
}

#[cfg(target_os = "linux")]
#[test]
fn capture_propagates_readlink_failure_for_a_live_inode() {
    if std::env::var(CHILD_CASE).as_deref() != Ok("capture_readlink") {
        run_isolated(
            "capture_propagates_readlink_failure_for_a_live_inode",
            "capture_readlink",
        );
        return;
    }
    let dir = TempDir::new().unwrap();
    let root = std::fs::canonicalize(dir.as_path()).unwrap();
    let file = File::create(root.join("file")).unwrap();
    // Fault only the path-query syscalls in this isolated test process.
    let mut filter = vec![libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let syscalls = [
        #[cfg(target_arch = "x86_64")]
        libc::SYS_readlink,
        libc::SYS_readlinkat,
    ];
    for syscall in syscalls {
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EIO as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
    assert_eq!(
        Object::capture(&file, &root).unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
}
