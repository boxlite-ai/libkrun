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
            panic!("{case}: filesystem restore blocked");
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
    // Leave room for the root/probe so failure occurs inside the restore loops.
    let available = if cfg!(target_os = "macos") && case == "inodes" {
        1
    } else {
        3
    };
    assert!(occupied.len() >= available);
    occupied.truncate(occupied.len() - available);
    let result = target.restore_state(&state);
    drop(occupied);
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit) },
        0
    );
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
