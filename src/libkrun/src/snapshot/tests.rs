// SPDX-License-Identifier: Apache-2.0

//! The `krun_snapshot_*` C API without KVM: argument and call-order
//! checks, the control entry outliving the context map's entry, failed
//! starts and the unsupported-platform stubs. Every test name contains
//! "snapshot" for the snapshot make targets' filter.

use std::ffi::CString;

use crate::*;

fn c(text: &str) -> CString {
    CString::new(text).unwrap()
}

fn get_state(ctx: u32) -> Result<(u32, i32), i32> {
    let (mut state, mut code) = (u32::MAX, i32::MIN);
    match unsafe { krun_snapshot_get_state(ctx, &mut state, &mut code) } {
        0 => Ok((state, code)),
        e => Err(e),
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
))]
mod supported {
    use std::path::Path;

    use super::*;
    use crate::snapshot::{STATE_CONFIGURED, STATE_FAILED};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("krun-capi-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn enabled() -> u32 {
        let ctx = krun_create_ctx() as u32;
        assert_eq!(krun_snapshot_enable(ctx, 0), 0);
        ctx
    }

    fn import(ctx: u32, image: &Path, disk_dir: Option<&Path>, fs_dir: Option<&Path>) -> i32 {
        let image = c(image.to_str().unwrap());
        let disk_dir = disk_dir.map(|dir| c(dir.to_str().unwrap()));
        let fs_dir = fs_dir.map(|dir| c(dir.to_str().unwrap()));
        let ptr = |dir: &Option<CString>| dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr());
        unsafe { krun_snapshot_import(ctx, image.as_ptr(), ptr(&disk_dir), ptr(&fs_dir)) }
    }

    #[test]
    fn snapshot_capi_enable_checks_its_flags_order_and_context() {
        assert_eq!(krun_snapshot_enable(0x7fff_ffee, 0), -libc::ENOENT);
        let ctx = krun_create_ctx() as u32;
        assert_eq!(krun_snapshot_enable(ctx, 1), -libc::EINVAL);
        assert_eq!(get_state(ctx), Err(-libc::ENOENT), "not enabled");
        assert_eq!(krun_snapshot_enable(ctx, 0), 0);
        assert_eq!(krun_snapshot_enable(ctx, 0), -libc::EINVAL, "enabled twice");
        assert_eq!(get_state(ctx), Ok((STATE_CONFIGURED, 0)));
        // Before krun_start_enter nothing runs.
        assert_eq!(krun_snapshot_pause(ctx, 0), -libc::EAGAIN);
        assert_eq!(krun_snapshot_resume(ctx), -libc::EAGAIN);
        assert_eq!(krun_snapshot_stop(ctx), -libc::EAGAIN);
        let export = c("/box/export.img");
        assert_eq!(
            unsafe { krun_snapshot_export(ctx, export.as_ptr()) },
            -libc::EAGAIN
        );
        assert_eq!(krun_free_ctx(ctx), 0);
        assert_eq!(get_state(ctx), Err(-libc::ENOENT));
        assert!(!CTX_MAP.lock().unwrap().contains_key(&ctx));
        assert_eq!(krun_free_ctx(ctx), -libc::ENOENT);
    }

    #[cfg(feature = "net")]
    #[test]
    fn snapshot_capi_keeps_the_nic_unopened_and_refuses_enabling_after_it() {
        let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
        let socket = c("/box/net.sock");

        let late = krun_create_ctx() as u32;
        assert_eq!(
            unsafe { krun_add_net_unixstream(late, socket.as_ptr(), -1, mac.as_ptr(), 0, 0) },
            0
        );
        assert_eq!(krun_snapshot_enable(late, 0), -libc::EINVAL);
        assert_eq!(krun_free_ctx(late), 0);

        let ctx = enabled();
        assert_eq!(
            unsafe { krun_add_net_unixstream(ctx, socket.as_ptr(), -1, mac.as_ptr(), 0, 0) },
            0
        );
        let map = CTX_MAP.lock().unwrap();
        let cfg = map.get(&ctx).unwrap();
        assert!(cfg.vmr.net.list.is_empty(), "the NIC was built");
        assert_eq!(cfg.snapshot.as_ref().unwrap().nics.len(), 1);
        drop(map);
        assert_eq!(krun_free_ctx(ctx), 0);
    }

    #[test]
    fn snapshot_capi_import_checks_its_arguments_and_order() {
        let image = Path::new("/box/checkpoint.img");
        let plain = krun_create_ctx() as u32;
        assert_eq!(
            import(plain, image, None, None),
            -libc::EINVAL,
            "not enabled"
        );
        assert_eq!(krun_free_ctx(plain), 0);

        let ctx = enabled();
        assert_eq!(
            unsafe {
                krun_snapshot_import(ctx, std::ptr::null(), std::ptr::null(), std::ptr::null())
            },
            -libc::EINVAL
        );
        assert_eq!(
            import(ctx, Path::new("checkpoint.img"), None, None),
            -libc::EINVAL
        );
        assert_eq!(
            import(ctx, image, Some(Path::new("disks")), None),
            -libc::EINVAL
        );
        assert_eq!(
            import(ctx, image, None, Some(Path::new("shares"))),
            -libc::EINVAL
        );
        assert_eq!(
            import(
                ctx,
                image,
                Some(Path::new("/box/disks")),
                Some(Path::new("/box/shares"))
            ),
            0
        );
        assert_eq!(
            import(ctx, image, None, None),
            -libc::EINVAL,
            "import twice"
        );
        assert_eq!(krun_free_ctx(ctx), 0);
    }

    #[test]
    fn snapshot_capi_checks_control_arguments() {
        let ctx = enabled();
        assert_eq!(krun_snapshot_pause(ctx, 1 << 1), -libc::EINVAL);
        assert_eq!(
            unsafe { krun_snapshot_export(ctx, std::ptr::null()) },
            -libc::EINVAL
        );
        let relative = c("export.img");
        assert_eq!(
            unsafe { krun_snapshot_export(ctx, relative.as_ptr()) },
            -libc::EINVAL
        );
        let tag = c("volume0");
        let mut path = [0 as libc::c_char; 64];
        assert_eq!(
            unsafe {
                krun_snapshot_get_restored_share(ctx, std::ptr::null(), path.as_mut_ptr(), 64)
            },
            -libc::EINVAL
        );
        assert_eq!(
            unsafe { krun_snapshot_get_restored_share(ctx, tag.as_ptr(), path.as_mut_ptr(), 64) },
            -libc::ENOENT
        );
        // NULL outputs are allowed.
        assert_eq!(
            unsafe { krun_snapshot_get_state(ctx, std::ptr::null_mut(), std::ptr::null_mut()) },
            0
        );
        assert_eq!(krun_free_ctx(ctx), 0);
    }

    /// The control entry outlives krun_start_enter's consumption of the
    /// context: a refused import's state stays readable until freed, and
    /// the import created nothing.
    #[cfg(feature = "blk")]
    #[test]
    fn snapshot_capi_refused_import_keeps_the_control_entry_until_freed() {
        let dir = temp_dir("refused");
        let console = dir.join("console.log");
        let disks = dir.join("disks");
        let ctx = enabled();
        assert_eq!(import(ctx, &dir.join("missing.img"), Some(&disks), None), 0);
        let console_c = c(console.to_str().unwrap());
        assert_eq!(
            unsafe { krun_set_console_output(ctx, console_c.as_ptr()) },
            0
        );
        let disk = c(dir.join("disk.raw").to_str().unwrap());
        let id = c("vda");
        assert_eq!(
            unsafe { krun_add_disk2(ctx, id.as_ptr(), disk.as_ptr(), 0, false) },
            0
        );
        assert_eq!(
            krun_start_enter(ctx),
            -libc::EINVAL,
            "an import brings its disks"
        );
        assert!(!CTX_MAP.lock().unwrap().contains_key(&ctx));
        assert_eq!(get_state(ctx), Ok((STATE_FAILED, 0)));
        assert_eq!(krun_snapshot_resume(ctx), -libc::ESRCH);
        assert_eq!(krun_snapshot_stop(ctx), 0);
        assert!(!console.exists() && !disks.exists());
        assert_eq!(krun_free_ctx(ctx), 0);
        assert_eq!(get_state(ctx), Err(-libc::ENOENT));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An import whose image cannot be read fails before creating any of
    /// its new endpoints (without /dev/kvm it fails even earlier).
    #[test]
    fn snapshot_capi_failed_import_creates_no_endpoint() {
        let dir = temp_dir("failed");
        let console = dir.join("console.log");
        let disks = dir.join("disks");
        let shares = dir.join("shares");
        let ctx = enabled();
        // The implicit vsock would hijack sockets (TSI), which a
        // checkpointing VM refuses.
        assert_eq!(krun_disable_implicit_vsock(ctx), 0);
        assert_eq!(
            import(ctx, &dir.join("missing.img"), Some(&disks), Some(&shares)),
            0
        );
        let console_c = c(console.to_str().unwrap());
        assert_eq!(
            unsafe { krun_set_console_output(ctx, console_c.as_ptr()) },
            0
        );
        assert_eq!(krun_start_enter(ctx), -libc::EIO);
        assert_eq!(get_state(ctx), Ok((STATE_FAILED, 0)));
        assert!(!console.exists() && !disks.exists() && !shares.exists());
        assert_eq!(krun_free_ctx(ctx), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
)))]
#[test]
fn snapshot_capi_is_unsupported_here() {
    let ctx = krun_create_ctx() as u32;
    let path = c("/box/checkpoint.img");
    let mut out = [0 as libc::c_char; 16];
    assert_eq!(krun_snapshot_enable(ctx, 0), -libc::ENOTSUP);
    assert_eq!(
        unsafe { krun_snapshot_import(ctx, path.as_ptr(), std::ptr::null(), std::ptr::null()) },
        -libc::ENOTSUP
    );
    assert_eq!(krun_snapshot_pause(ctx, 0), -libc::ENOTSUP);
    assert_eq!(krun_snapshot_resume(ctx), -libc::ENOTSUP);
    assert_eq!(
        unsafe { krun_snapshot_export(ctx, path.as_ptr()) },
        -libc::ENOTSUP
    );
    assert_eq!(krun_snapshot_stop(ctx), -libc::ENOTSUP);
    assert_eq!(get_state(ctx), Err(-libc::ENOTSUP));
    assert_eq!(
        unsafe { krun_snapshot_get_restored_share(ctx, path.as_ptr(), out.as_mut_ptr(), 16) },
        -libc::ENOTSUP
    );
    assert_eq!(krun_free_ctx(ctx), 0);
}
