// SPDX-License-Identifier: Apache-2.0

//! Version-9 descriptor ABI. Borrow input FDs; transfer prepared duplicates only on success.

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
))]
pub(super) mod supported {
    use super::super::{control, supported::DescriptorImport};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::net::UnixStream;
    use vmm::snapshot_vm::{
        checkpoint::{BindingIndices, ExportMetadata},
        SnapshotVm,
    };
    const MAX_JSON: usize = 16 << 20;
    const MAX_FDS: usize = 16384;

    fn duplicate(fd: i32) -> Result<File, i32> {
        let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(-std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    unsafe fn json<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
        if ptr.is_null() || len == 0 || len > MAX_JSON {
            return Err(-libc::EINVAL);
        }
        Ok(std::slice::from_raw_parts(ptr, len))
    }
    unsafe fn output(bytes: &[u8], buffer: *mut u8, length: *mut usize) -> i32 {
        if length.is_null() {
            return -libc::EINVAL;
        }
        let capacity = *length;
        *length = bytes.len();
        if capacity < bytes.len() || buffer.is_null() {
            return -libc::ENOBUFS;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        0
    }

    #[no_mangle]
    pub extern "C" fn krun_snapshot_capabilities() -> u64 {
        if cfg!(feature = "blk") {
            7
        } else {
            0
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn krun_snapshot_inspect_fd(
        memory: i32,
        buffer: *mut u8,
        length: *mut usize,
    ) -> i32 {
        let file = match duplicate(memory) {
            Ok(file) => file,
            Err(e) => return e,
        };
        match SnapshotVm::inspect_fd(&file) {
            Ok(bytes) => output(&bytes, buffer, length),
            Err(e) => {
                error!("inspect memory checkpoint: {e}");
                -libc::EINVAL
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn krun_snapshot_begin_capture(
        ctx: u32,
        kind: u32,
        session: i32,
        token: *mut u64,
    ) -> i32 {
        if token.is_null() || kind > 1 {
            return -libc::EINVAL;
        }
        let file = match duplicate(session) {
            Ok(file) => file,
            Err(e) => return e,
        };
        let mut address: libc::sockaddr_un = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&address) as libc::socklen_t;
        let mut socket_type = 0i32;
        let mut type_len = std::mem::size_of_val(&socket_type) as libc::socklen_t;
        if libc::getsockopt(
            file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut type_len,
        ) != 0
            || socket_type != libc::SOCK_STREAM
            || libc::getpeername(
                file.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut len,
            ) != 0
            || address.sun_family as i32 != libc::AF_UNIX
        {
            return -libc::EINVAL;
        }
        let stream = UnixStream::from_raw_fd(file.into_raw_fd());
        match control::begin(ctx, kind == 1, stream) {
            Ok(value) => {
                *token = value;
                0
            }
            Err(e) => e,
        }
    }

    #[no_mangle]
    pub extern "C" fn krun_snapshot_end_capture(ctx: u32, token: u64, outcome: u32) -> i32 {
        if outcome > 1 {
            return -libc::EINVAL;
        }
        control::request(
            ctx,
            control::Request::End {
                token,
                success: outcome == 0,
            },
        )
    }

    #[no_mangle]
    pub unsafe extern "C" fn krun_snapshot_prepare_capture(
        ctx: u32,
        token: u64,
        buffer: *mut u8,
        length: *mut usize,
        fds: *mut i32,
        count: *mut usize,
    ) -> i32 {
        if length.is_null() || count.is_null() {
            return -libc::EINVAL;
        }
        let prepared = match control::prepare(ctx, token) {
            Ok(prepared) => prepared,
            Err(e) => return e,
        };
        let enough = !buffer.is_null()
            && *length >= prepared.metadata.len()
            && (prepared.files.is_empty() || !fds.is_null())
            && *count >= prepared.files.len();
        *length = prepared.metadata.len();
        *count = prepared.files.len();
        if !enough {
            return -libc::ENOBUFS;
        }
        std::ptr::copy_nonoverlapping(prepared.metadata.as_ptr(), buffer, prepared.metadata.len());
        for (index, file) in prepared.files.into_iter().enumerate() {
            *fds.add(index) = file.into_raw_fd();
        }
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn krun_snapshot_export_fd(
        ctx: u32,
        token: u64,
        memory: i32,
        qcow2: i32,
        metadata: *const u8,
        length: usize,
    ) -> i32 {
        let bytes = match json(metadata, length) {
            Ok(bytes) => bytes,
            Err(e) => return e,
        };
        let metadata: ExportMetadata = match serde_json::from_slice(bytes) {
            Ok(metadata) => metadata,
            Err(_) => return -libc::EINVAL,
        };
        let memory = match duplicate(memory) {
            Ok(file) => file,
            Err(e) => return e,
        };
        let qcow2 = match duplicate(qcow2) {
            Ok(file) => file,
            Err(e) => return e,
        };
        control::request(
            ctx,
            control::Request::ExportFd {
                token,
                memory,
                qcow2,
                metadata,
            },
        )
    }

    #[no_mangle]
    pub unsafe extern "C" fn krun_snapshot_import_fd(
        ctx: u32,
        memory: i32,
        config: *const u8,
        length: usize,
        fds: *const i32,
        count: usize,
    ) -> i32 {
        if count > MAX_FDS || (count != 0 && fds.is_null()) {
            return -libc::EINVAL;
        }
        let bytes = match json(config, length) {
            Ok(bytes) => bytes,
            Err(e) => return e,
        };
        let indices: BindingIndices = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return -libc::EINVAL,
        };
        let mut files = Vec::with_capacity(count);
        for index in 0..count {
            match duplicate(*fds.add(index)) {
                Ok(file) => files.push(file),
                Err(e) => return e,
            }
        }
        let bindings = match indices.bind(files) {
            Ok(bindings) => bindings,
            Err(_) => return -libc::EINVAL,
        };
        let image = match duplicate(memory) {
            Ok(file) => file,
            Err(e) => return e,
        };
        if SnapshotVm::inspect_fd(&image).is_err() {
            return -libc::EINVAL;
        }
        let mut contexts = crate::CTX_MAP.lock().unwrap();
        let Some(cfg) = contexts.get_mut(&ctx) else {
            return -libc::ENOENT;
        };
        let Some(setup) = cfg.snapshot.as_mut() else {
            return -libc::EINVAL;
        };
        if setup.fd_import.is_some() {
            return -libc::EINVAL;
        }
        setup.fd_import = Some(DescriptorImport { image, bindings });
        0
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
)))]
mod unsupported {
    #[no_mangle]
    pub extern "C" fn krun_snapshot_capabilities() -> u64 {
        0
    }
    macro_rules! unsupported {
        ($name:ident($($arg:ident: $type:ty),* $(,)?)) => {
            #[no_mangle]
            pub extern "C" fn $name($($arg: $type),*) -> i32 {
                let _ = ($($arg),*);
                -libc::ENOTSUP
            }
        };
    }
    unsupported!(krun_snapshot_inspect_fd(memory: i32, buffer: *mut u8, length: *mut usize));
    unsupported!(krun_snapshot_begin_capture(ctx: u32, kind: u32, session: i32, token: *mut u64));
    unsupported!(krun_snapshot_end_capture(ctx: u32, token: u64, outcome: u32));
    unsupported!(
        krun_snapshot_prepare_capture(
            ctx: u32,
            token: u64,
            buffer: *mut u8,
            length: *mut usize,
            fds: *mut i32,
            count: *mut usize,
        )
    );
    unsupported!(
        krun_snapshot_export_fd(
            ctx: u32,
            token: u64,
            memory: i32,
            qcow2: i32,
            metadata: *const u8,
            length: usize,
        )
    );
    unsupported!(
        krun_snapshot_import_fd(
            ctx: u32,
            memory: i32,
            config: *const u8,
            length: usize,
            fds: *const i32,
            count: usize,
        )
    );
}
