// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::process::Command;
use utils::tempdir::TempDir;

#[test]
fn artifact_open_rejects_nonregular_files_without_blocking() {
    const FIFO_PATH: &str = "KRUN_CHECKPOINT_TEST_FIFO";
    if let Some(path) = std::env::var_os(FIFO_PATH) {
        assert_eq!(
            open_file(Path::new(&path)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        return;
    }

    let dir = TempDir::new().unwrap();
    let regular = dir.as_path().join("regular");
    std::fs::write(&regular, b"checkpoint bytes").unwrap();
    let mut contents = Vec::new();
    open_file(&regular)
        .unwrap()
        .read_to_end(&mut contents)
        .unwrap();
    assert_eq!(contents, b"checkpoint bytes");
    assert_eq!(
        open_file(dir.as_path()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let link = dir.as_path().join("symlink");
    std::os::unix::fs::symlink(&regular, &link).unwrap();
    assert_eq!(
        open_file(&link).unwrap_err().raw_os_error(),
        Some(libc::ELOOP)
    );

    let fifo = dir.as_path().join("fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    // A subprocess bounds regressions without leaving a blocked test thread.
    let module = module_path!().split_once("::").unwrap().1;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{module}::artifact_open_rejects_nonregular_files_without_blocking"),
            "--nocapture",
        ])
        .env(FIFO_PATH, &fifo)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "FIFO artifact check failed: {status}");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("checkpoint artifact open blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
