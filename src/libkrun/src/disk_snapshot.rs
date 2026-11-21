use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::sync::Arc;

use devices::virtio::block::snapshot::{FileIdentity, SnapshotHandle};

use crate::{ImageType, CTX_MAP};

#[repr(C)]
pub struct SnapshotCommand {
    pub operation: u32,
    pub transaction: *const c_char,
    pub backing_path: *const c_char,
    pub source: FileIdentity,
    pub overlay: FileIdentity,
}

/// Registers control for a single writably attached QCOW2 disk before VM entry.
///
/// The caller owns the output handle and must free it after any calls using it finish.
#[no_mangle]
pub unsafe extern "C" fn krun_enable_disk_snapshot(
    context: u32,
    block_id: *const c_char,
    output: *mut *const c_void,
) -> i32 {
    if block_id.is_null() || output.is_null() {
        return -libc::EINVAL;
    }
    let Ok(block_id) = CStr::from_ptr(block_id).to_str() else {
        return -libc::EINVAL;
    };
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(config) = contexts.get_mut(&context) else {
        return -libc::ENOENT;
    };
    if config.snapshot_control.is_some() {
        return -libc::EBUSY;
    }
    if !config.block_cfgs.iter().any(|disk| {
        disk.block_id == block_id
            && disk.disk_image_format == ImageType::Qcow2
            && !disk.is_disk_read_only
            && !disk.direct_io
    }) {
        return -libc::ENODEV;
    }
    let handle = Arc::new(SnapshotHandle::default());
    config.snapshot_control = Some((block_id.to_owned(), handle.clone()));
    *output = Arc::into_raw(handle).cast();
    0
}

#[no_mangle]
pub unsafe extern "C" fn krun_free_disk_snapshot(handle: *const c_void) {
    if !handle.is_null() {
        drop(Arc::from_raw(handle.cast::<SnapshotHandle>()));
    }
}

/// Executes a command against an enabled disk. Returns the phase or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn krun_disk_snapshot(
    handle: *const c_void,
    command: *const SnapshotCommand,
) -> i32 {
    let (Some(handle), Some(command)) =
        (handle.cast::<SnapshotHandle>().as_ref(), command.as_ref())
    else {
        return -libc::EINVAL;
    };
    if command.transaction.is_null() {
        return -libc::EINVAL;
    }
    let Ok(transaction) = CStr::from_ptr(command.transaction).to_str() else {
        return -libc::EINVAL;
    };
    if transaction.is_empty() {
        return -libc::EINVAL;
    }
    let disk = match handle.disk() {
        Ok(disk) => disk,
        Err(error) => return -error.raw_os_error().unwrap_or(libc::EIO),
    };
    let result = match command.operation {
        0 => disk.status(transaction),
        1 => disk.fence(transaction, command.source),
        2 if !command.backing_path.is_null() => {
            let Ok(backing_path) = CStr::from_ptr(command.backing_path).to_str() else {
                return -libc::EINVAL;
            };
            disk.install(
                transaction,
                command.overlay,
                Path::new(backing_path),
                command.source,
            )
        }
        3 => disk.release(transaction, command.overlay),
        4 => disk.abort(transaction, command.source),
        _ => return -libc::EINVAL,
    };
    result.map_or_else(
        |error| -error.raw_os_error().unwrap_or(libc::EIO),
        |phase| phase as i32,
    )
}
