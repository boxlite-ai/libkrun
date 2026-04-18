//! Windows C API implementation for libkrun.
//!
//! All functions follow the libkrun convention:
//! - Return 0 on success, negative on error
//! - Context IDs are u32
//! - Strings are null-terminated C strings
//!
//! On Windows, functions delegate to `vmm::windows::*` instead of the
//! Unix-specific VMM infrastructure.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

use vmm::windows::context::{
    self, DiskConfig, FsMount, NetConfig, VsockPort, DISK_FORMAT_QCOW2, DISK_FORMAT_RAW,
};
use vmm::windows::devices::manager as devices;
use vmm::windows::error::{Result, WkrunError};
use vmm::windows::types::VmState;

// ============================================================================
// Helpers
// ============================================================================

/// Convert a Result to a C API return code (0 = success, negative = error).
fn to_c_result(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(ref e) => {
            log::error!("{}", e);
            i32::from(e)
        }
    }
}

/// Convert a C string to a Rust PathBuf. Returns None for null pointers.
///
/// # Safety
///
/// The pointer must be null or point to a valid null-terminated C string.
unsafe fn c_str_to_path(ptr: *const c_char) -> Option<PathBuf> {
    if ptr.is_null() {
        None
    } else {
        Some(PathBuf::from(
            CStr::from_ptr(ptr).to_string_lossy().into_owned(),
        ))
    }
}

/// Convert a C string to a Rust String. Returns None for null pointers.
///
/// # Safety
///
/// The pointer must be null or point to a valid null-terminated C string.
unsafe fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

/// Convert a null-terminated array of C strings to a Vec<String>.
///
/// # Safety
///
/// `arr` must be null or point to a null-terminated array of null-terminated C strings.
unsafe fn c_str_array_to_vec(arr: *const *const c_char) -> Vec<String> {
    if arr.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut ptr = arr;
    loop {
        let s = *ptr;
        if s.is_null() {
            break;
        }
        result.push(CStr::from_ptr(s).to_string_lossy().into_owned());
        ptr = ptr.add(1);
    }
    result
}

// Maximum number of arguments/environment variables we allow.
const MAX_ARGS: usize = 4096;

// ============================================================================
// Logging
// ============================================================================

#[no_mangle]
pub extern "C" fn krun_set_log_level(level: u32) -> i32 {
    let filter = match level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        5 => log::LevelFilter::Trace,
        _ => return -libc::EINVAL,
    };
    log::set_max_level(filter);
    0
}

#[no_mangle]
pub unsafe extern "C" fn krun_init_log(
    _target: i32,
    level: u32,
    _style: u32,
    _options: u32,
) -> i32 {
    let env_filter = match level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        5 => "trace",
        _ => "warn",
    };
    let _ = env_logger::Builder::new()
        .parse_filters(env_filter)
        .try_init();
    0
}

// ============================================================================
// Context management
// ============================================================================

#[no_mangle]
pub extern "C" fn krun_create_ctx() -> i32 {
    match context::create_ctx() {
        Ok(id) => id as i32,
        Err(e) => {
            log::error!("krun_create_ctx: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn krun_free_ctx(ctx_id: u32) -> i32 {
    to_c_result(context::free_ctx(ctx_id))
}

// ============================================================================
// VM configuration
// ============================================================================

#[no_mangle]
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        if ctx.state != VmState::Created {
            return Err(WkrunError::InvalidState {
                expected: "Created",
                actual: ctx.state.to_string(),
            });
        }
        if num_vcpus == 0 {
            return Err(WkrunError::Config("num_vcpus must be > 0".into()));
        }
        if ram_mib == 0 {
            return Err(WkrunError::Config("ram_mib must be > 0".into()));
        }
        ctx.num_vcpus = num_vcpus;
        ctx.ram_mib = ram_mib;
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_root(ctx_id: u32, c_root_path: *const c_char) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.root_path = c_str_to_path(c_root_path);
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_virtiofs(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        let tag = c_str_to_string(c_tag)
            .ok_or_else(|| WkrunError::Config("virtiofs tag cannot be null".into()))?;
        let path = c_str_to_path(c_path)
            .ok_or_else(|| WkrunError::Config("virtiofs path cannot be null".into()))?;
        ctx.fs_mounts.push(FsMount {
            tag,
            host_path: path,
        });
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_virtiofs2(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    _port: u32,
) -> i32 {
    // On Windows, virtiofs2 is treated the same as virtiofs (no port parameter needed).
    krun_add_virtiofs(ctx_id, c_tag, c_path)
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_disk2(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        let id = c_str_to_string(c_block_id)
            .ok_or_else(|| WkrunError::Config("block_id cannot be null".into()))?;
        let path = c_str_to_path(c_disk_path)
            .ok_or_else(|| WkrunError::Config("disk_path cannot be null".into()))?;
        if disk_format != DISK_FORMAT_RAW && disk_format != DISK_FORMAT_QCOW2 {
            return Err(WkrunError::Config(format!(
                "unsupported disk format: {}",
                disk_format
            )));
        }
        ctx.disks.push(DiskConfig {
            block_id: id,
            path,
            format: disk_format,
            read_only,
        });
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_disk(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    read_only: bool,
) -> i32 {
    krun_add_disk2(ctx_id, c_block_id, c_disk_path, DISK_FORMAT_RAW, read_only)
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port2(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
    listen: bool,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        let path = c_str_to_path(c_filepath)
            .ok_or_else(|| WkrunError::Config("vsock filepath cannot be null".into()))?;
        ctx.vsock_ports.push(VsockPort {
            port,
            host_path: path,
            listen,
            host_tcp_port: None,
        });
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_exec(
    ctx_id: u32,
    c_exec_path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.exec_path = c_str_to_string(c_exec_path);
        let args = c_str_array_to_vec(argv);
        if args.len() > MAX_ARGS {
            return Err(WkrunError::Config(format!(
                "too many arguments: {} > {}",
                args.len(),
                MAX_ARGS
            )));
        }
        ctx.argv = args;
        let env = c_str_array_to_vec(envp);
        if env.len() > MAX_ARGS {
            return Err(WkrunError::Config(format!(
                "too many env vars: {} > {}",
                env.len(),
                MAX_ARGS
            )));
        }
        ctx.envp = env;
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_env(ctx_id: u32, c_envp: *const *const c_char) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        let env = c_str_array_to_vec(c_envp);
        if env.len() > MAX_ARGS {
            return Err(WkrunError::Config(format!(
                "too many env vars: {} > {}",
                env.len(),
                MAX_ARGS
            )));
        }
        ctx.envp = env;
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_workdir(ctx_id: u32, c_workdir_path: *const c_char) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.workdir = c_str_to_string(c_workdir_path);
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_rlimits(ctx_id: u32, c_rlimits: *const *const c_char) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.rlimits = c_str_array_to_vec(c_rlimits);
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.console_output = c_str_to_path(c_filepath);
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel(
    ctx_id: u32,
    c_kernel_path: *const c_char,
    _format: u32,
    c_initramfs: *const c_char,
    c_cmdline: *const c_char,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.kernel_path = c_str_to_path(c_kernel_path);
        ctx.initramfs_path = c_str_to_path(c_initramfs);
        ctx.kernel_cmdline = c_str_to_string(c_cmdline);
        Ok(())
    }))
}

// ============================================================================
// Networking
// ============================================================================

/// Add a network device backed by a TCP endpoint.
///
/// On Windows, networking uses TCP sockets to a userspace network proxy
/// (e.g., gvproxy). This replaces the Unix-specific `krun_add_net_unixstream`
/// and `krun_add_net_unixgram`.
#[no_mangle]
pub unsafe extern "C" fn krun_add_net(
    ctx_id: u32,
    c_endpoint: *const c_char,
    c_mac: *const u8,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        let path = c_str_to_path(c_endpoint)
            .ok_or_else(|| WkrunError::Config("net endpoint cannot be null".into()))?;
        let mac = if c_mac.is_null() {
            vmm::windows::devices::virtio::net::generate_mac(ctx_id)
        } else {
            let mut buf = [0u8; 6];
            std::ptr::copy_nonoverlapping(c_mac, buf.as_mut_ptr(), 6);
            buf
        };
        ctx.net_config = Some(NetConfig {
            mac,
            socket_path: path,
        });
        Ok(())
    }))
}

/// Unix stream networking — not available on Windows.
#[no_mangle]
pub unsafe extern "C" fn krun_add_net_unixstream(
    _ctx_id: u32,
    _c_path: *const c_char,
    _fd: i32,
    _c_mac: *const u8,
    _features: u32,
    _flags: u32,
) -> i32 {
    log::warn!("krun_add_net_unixstream: not available on Windows, use krun_add_net");
    -libc::ENOSYS
}

/// Unix dgram networking — not available on Windows.
#[no_mangle]
pub unsafe extern "C" fn krun_add_net_unixgram(
    _ctx_id: u32,
    _c_path: *const c_char,
    _fd: i32,
    _c_mac: *const u8,
    _features: u32,
    _flags: u32,
) -> i32 {
    log::warn!("krun_add_net_unixgram: not available on Windows, use krun_add_net");
    -libc::ENOSYS
}

// ============================================================================
// No-ops on Windows
// ============================================================================

#[no_mangle]
pub extern "C" fn krun_setuid(_ctx_id: u32, _uid: u32) -> i32 {
    0 // No-op on Windows
}

#[no_mangle]
pub extern "C" fn krun_setgid(_ctx_id: u32, _gid: u32) -> i32 {
    0 // No-op on Windows
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_gpu_options(_ctx_id: u32, _virgl_flags: u32) -> i32 {
    0 // No-op
}

#[no_mangle]
pub extern "C" fn krun_split_irqchip(_ctx_id: u32, _enable: bool) -> i32 {
    0 // No-op on Windows
}

#[no_mangle]
pub unsafe extern "C" fn krun_disable_tsi(_ctx_id: u32) -> i32 {
    0 // No-op on Windows (no TSI)
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_nested_virt(_ctx_id: u32, _enabled: bool) -> i32 {
    0 // No-op on Windows
}

#[no_mangle]
pub unsafe extern "C" fn krun_check_nested_virt() -> i32 {
    0 // Not supported on Windows
}

#[no_mangle]
pub extern "C" fn krun_get_max_vcpus() -> i32 {
    // WHPX supports up to 64 vCPUs, but we cap at a reasonable default.
    64
}

#[no_mangle]
pub extern "C" fn krun_get_shutdown_eventfd(_ctx_id: u32) -> i32 {
    -libc::ENOSYS // eventfd not available on Windows
}

#[no_mangle]
pub extern "C" fn krun_disable_implicit_console(_ctx_id: u32) -> i32 {
    0 // No-op
}

// Stubs for functions that reference Unix-only features.
#[no_mangle]
pub unsafe extern "C" fn krun_set_root_disk(_ctx_id: u32, _c_disk_path: *const c_char) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_data_disk(_ctx_id: u32, _c_disk_path: *const c_char) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_root_disk_remount(
    ctx_id: u32,
    device: *const c_char,
    fstype: *const c_char,
    _options: *const c_char,
) -> i32 {
    to_c_result(context::with_ctx_mut(ctx_id, |ctx| {
        ctx.root_disk_device = c_str_to_string(device);
        ctx.root_disk_fstype = c_str_to_string(fstype);
        Ok(())
    }))
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_mapped_volumes(
    _ctx_id: u32,
    _c_mapped_volumes: *const *const c_char,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_port_map(
    _ctx_id: u32,
    _c_port_map: *const *const c_char,
) -> i32 {
    0 // No-op
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_passt_fd(_ctx_id: u32, _fd: i32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_gvproxy_path(_ctx_id: u32, _c_path: *const c_char) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_net_mac(_ctx_id: u32, _c_mac: *const u8) -> i32 {
    0 // No-op, use krun_add_net
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_snd_device(_ctx_id: u32, _enable: bool) -> i32 {
    0 // No-op
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_firmware(_ctx_id: u32, _c_path: *const c_char) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_smbios_oem_strings(
    _ctx_id: u32,
    _strings: *const *const c_char,
) -> i32 {
    0 // No-op
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
) -> i32 {
    krun_add_vsock_port2(ctx_id, port, c_filepath, false)
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_tee_config_file(
    _ctx_id: u32,
    _c_filepath: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

// ============================================================================
// VM lifecycle
// ============================================================================

/// Start and enter the VM (blocking). Returns exit code.
#[no_mangle]
pub extern "C" fn krun_start_enter(ctx_id: u32) -> i32 {
    let ctx = match context::take_ctx(ctx_id) {
        Ok(ctx) => ctx,
        Err(e) => {
            log::error!("krun_start_enter: {}", e);
            return i32::from(&e);
        }
    };

    match vmm::windows::runner::run(ctx) {
        Ok(exit_code) => exit_code,
        Err(ref e) => {
            log::error!("krun_start_enter: {}", e);
            i32::from(e)
        }
    }
}

/// Start VM on a background thread (non-blocking). Returns 0 on success.
#[no_mangle]
pub extern "C" fn krun_start(ctx_id: u32) -> i32 {
    let ctx = match context::take_ctx(ctx_id) {
        Ok(ctx) => ctx,
        Err(ref e) => {
            log::error!("krun_start: {}", e);
            return i32::from(e);
        }
    };
    to_c_result(vmm::windows::runner::start(ctx_id, ctx))
}

/// Block until a running VM exits. Returns exit code.
#[no_mangle]
pub extern "C" fn krun_wait(ctx_id: u32) -> i32 {
    match vmm::windows::runner::wait(ctx_id) {
        Ok(exit_code) => exit_code,
        Err(ref e) => {
            log::error!("krun_wait: {}", e);
            i32::from(e)
        }
    }
}

/// Request a running VM to stop (non-blocking). Returns 0 on success.
#[no_mangle]
pub extern "C" fn krun_stop(ctx_id: u32) -> i32 {
    to_c_result(vmm::windows::runner::stop(ctx_id))
}

/// Get captured console output for a VM.
///
/// If `buf` is null or `buf_size` is 0, returns the total number of bytes available.
/// Otherwise, copies up to `buf_size` bytes into `buf` and returns the number copied.
/// Returns -1 if the ctx_id has no console buffer.
#[no_mangle]
pub unsafe extern "C" fn krun_get_console_output(
    ctx_id: u32,
    buf: *mut u8,
    buf_size: u32,
) -> i32 {
    let output = match devices::get_console_output(ctx_id) {
        Some(data) => data,
        None => return -1,
    };

    if buf.is_null() || buf_size == 0 {
        return output.len() as i32;
    }

    let copy_len = std::cmp::min(output.len(), buf_size as usize);
    if copy_len > 0 {
        std::ptr::copy_nonoverlapping(output.as_ptr(), buf, copy_len);
    }
    copy_len as i32
}

// ============================================================================
// Display / Input / Console stubs (not supported on Windows)
// ============================================================================

#[no_mangle]
pub extern "C" fn krun_set_display_backend(_ctx_id: u32, _backend: u32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_display(_ctx_id: u32, _width: u32, _height: u32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub extern "C" fn krun_display_set_refresh_rate(
    _ctx_id: u32,
    _display_id: u32,
    _rate: u32,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub extern "C" fn krun_display_set_physical_size(
    _ctx_id: u32,
    _display_id: u32,
    _mm_width: u32,
    _mm_height: u32,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub extern "C" fn krun_display_set_dpi(_ctx_id: u32, _display_id: u32, _dpi: u32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_display_set_edid(
    _ctx_id: u32,
    _display_id: u32,
    _edid: *const u8,
    _edid_size: u32,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_input_device(
    _ctx_id: u32,
    _c_path: *const c_char,
    _input_type: u32,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_input_device_fd(_ctx_id: u32, _input_fd: i32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_virtio_console_default(
    _ctx_id: u32,
    _port_name: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_virtio_console_multiport(_ctx_id: u32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_console_port_tty(
    _ctx_id: u32,
    _name: *const c_char,
    _port_name: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_console_port_inout(
    _ctx_id: u32,
    _name: *const c_char,
    _port_name: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_add_serial_console_default(_ctx_id: u32) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel_console(
    _ctx_id: u32,
    _console_id: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

// ============================================================================
// Disk format 3 stub
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn krun_add_disk3(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
    _cache_type: u32,
    _sync_mode: u32,
) -> i32 {
    // Ignore cache_type and sync_mode on Windows, delegate to disk2.
    krun_add_disk2(ctx_id, c_block_id, c_disk_path, disk_format, read_only)
}

// ============================================================================
// GPU options 2 stub
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn krun_set_gpu_options2(
    _ctx_id: u32,
    _virgl_flags: u32,
    _shm_size: u64,
) -> i32 {
    0 // No-op
}

// ============================================================================
// Nitro / TEE stubs
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn krun_nitro_set_image(
    _ctx_id: u32,
    _c_image_filepath: *const c_char,
) -> i32 {
    -libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn krun_nitro_set_start_flags(_ctx_id: u32, _start_flags: u64) -> i32 {
    -libc::ENOSYS
}

// ============================================================================
// Net tap stubs
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn krun_add_net_tap(
    _ctx_id: u32,
    _tap_name: *const c_char,
    _c_mac: *const u8,
) -> i32 {
    -libc::ENOSYS
}
