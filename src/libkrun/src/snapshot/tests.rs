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
    use super::*;
    use crate::snapshot::descriptor::supported::*;
    use crate::snapshot::STATE_CONFIGURED;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};

    #[cfg(feature = "blk")]
    mod v9;

    fn enabled() -> u32 {
        let ctx = krun_create_ctx() as u32;
        assert_eq!(krun_snapshot_enable(ctx, 0), 0);
        ctx
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
            -libc::ENOTSUP
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
    fn snapshot_capi_v9_descriptor_contract_and_legacy_refusal() {
        let ctx = enabled();
        let image = c("/box/old-checkpoint");
        assert_eq!(
            unsafe {
                krun_snapshot_import(ctx, image.as_ptr(), std::ptr::null(), std::ptr::null())
            },
            -libc::ENOTSUP
        );
        assert_eq!(
            krun_snapshot_capabilities(),
            if cfg!(feature = "blk") { 7 } else { 0 }
        );
        let (session, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut token = 0;
        assert_eq!(
            unsafe { krun_snapshot_begin_capture(ctx, 0, session.as_raw_fd(), &mut token) },
            -libc::EAGAIN
        );
        assert_eq!(token, 0);
        assert_eq!(
            unsafe { krun_snapshot_begin_capture(ctx, 2, session.as_raw_fd(), &mut token) },
            -libc::EINVAL
        );
        let name = c("legacy-image");
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(b"KRUNVM\0\0").unwrap();
        file.write_all(&8u32.to_le_bytes()).unwrap();
        let config = br#"{"disks":[],"shares":[]}"#;
        assert_eq!(
            unsafe {
                krun_snapshot_import_fd(
                    ctx,
                    file.as_raw_fd(),
                    config.as_ptr(),
                    config.len(),
                    std::ptr::null(),
                    0,
                )
            },
            -libc::EINVAL
        );
        let mut length = 0;
        assert_eq!(
            unsafe {
                krun_snapshot_inspect_fd(file.as_raw_fd(), std::ptr::null_mut(), &mut length)
            },
            -libc::EINVAL
        );
        assert_eq!(get_state(ctx), Ok((STATE_CONFIGURED, 0)));
        assert_eq!(krun_free_ctx(ctx), 0);
    }

    #[test]
    fn snapshot_capi_checks_control_arguments() {
        let ctx = enabled();
        assert_eq!(krun_snapshot_pause(ctx, 1 << 1), -libc::EINVAL);
        assert_eq!(
            unsafe { krun_snapshot_export(ctx, std::ptr::null()) },
            -libc::ENOTSUP
        );
        let relative = c("export.img");
        assert_eq!(
            unsafe { krun_snapshot_export(ctx, relative.as_ptr()) },
            -libc::ENOTSUP
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
