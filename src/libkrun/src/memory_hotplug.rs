use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use devices::virtio::mem::{MemoryControl, MemoryStatus};

use super::CTX_MAP;

static CONTROLS: LazyLock<Mutex<HashMap<u32, Arc<MemoryControl>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Configure before start; retain only the mailbox after start consumes CTX_MAP.
#[no_mangle]
pub extern "C" fn krun_set_memory_hotplug(ctx_id: u32, max_mib: u32) -> i32 {
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(ctx) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    let initial = ctx.vmr.vm_config().mem_size_mib.unwrap() as u32;
    match MemoryControl::new(initial, max_mib) {
        Ok(control) => {
            let control = Arc::new(control);
            ctx.vmr.memory_hotplug = Some(control.clone());
            CONTROLS.lock().unwrap().insert(ctx_id, control);
            0
        }
        Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
    }
}

/// Thread-safe, asynchronous request; poll krun_get_memory_status for completion.
#[no_mangle]
pub extern "C" fn krun_request_memory(ctx_id: u32, total_mib: u32) -> i32 {
    let controls = CONTROLS.lock().unwrap();
    let Some(control) = controls.get(&ctx_id) else {
        return -libc::ENOENT;
    };
    control
        .request(total_mib)
        .map_or_else(|e| -e.raw_os_error().unwrap_or(libc::EIO), |_| 0)
}

/// The caller provides a writable MemoryStatus; all sizes include boot memory.
#[no_mangle]
pub unsafe extern "C" fn krun_get_memory_status(ctx_id: u32, output: *mut MemoryStatus) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    let controls = CONTROLS.lock().unwrap();
    let Some(control) = controls.get(&ctx_id) else {
        return -libc::ENOENT;
    };
    unsafe {
        output.write(control.status());
    }
    0
}

pub fn remove(ctx_id: u32) {
    CONTROLS.lock().unwrap().remove(&ctx_id);
}
