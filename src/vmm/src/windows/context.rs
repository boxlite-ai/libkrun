//! VM context — configuration state machine for building a VM.
//!
//! Mirrors libkrun's KrunContext pattern: create → configure → start.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use super::error::{Result, WkrunError};
use super::types::VmState;

/// Global context ID counter.
static NEXT_CTX_ID: AtomicU32 = AtomicU32::new(0);

/// Global context map — maps context IDs to VM configurations.
/// Uses a Mutex for thread-safe access from the C API.
static CTX_MAP: std::sync::LazyLock<Mutex<HashMap<u32, VmContext>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Disk format constants (matching libkrun).
pub const DISK_FORMAT_RAW: u32 = 0;
pub const DISK_FORMAT_QCOW2: u32 = 1;

/// Configuration for a virtual machine.
pub struct VmContext {
    /// Context ID.
    pub id: u32,
    /// Current state.
    pub state: VmState,
    /// Number of vCPUs.
    pub num_vcpus: u8,
    /// RAM size in MiB.
    pub ram_mib: u32,
    /// Root filesystem path.
    pub root_path: Option<PathBuf>,
    /// Kernel image path (for direct boot).
    pub kernel_path: Option<PathBuf>,
    /// Kernel command line.
    pub kernel_cmdline: Option<String>,
    /// Initramfs path.
    pub initramfs_path: Option<PathBuf>,
    /// Executable path for the guest init.
    pub exec_path: Option<String>,
    /// Arguments for the guest executable.
    pub argv: Vec<String>,
    /// Environment variables for the guest.
    pub envp: Vec<String>,
    /// Working directory in the guest.
    pub workdir: Option<String>,
    /// Attached block devices.
    pub disks: Vec<DiskConfig>,
    /// Virtiofs/9p mounts.
    pub fs_mounts: Vec<FsMount>,
    /// Vsock port bridges.
    pub vsock_ports: Vec<VsockPort>,
    /// Console output file path.
    pub console_output: Option<PathBuf>,
    /// Resource limits to apply in the guest (format: "RESOURCE=CUR:MAX").
    pub rlimits: Vec<String>,
    /// Whether APIC emulation is enabled.
    pub apic_emulation: bool,
    /// Network device configuration.
    pub net_config: Option<NetConfig>,
    /// Root disk device path override (e.g., "/dev/vdb").
    /// When set, the kernel cmdline uses this instead of the default "/dev/vda".
    pub root_disk_device: Option<String>,
    /// Root disk filesystem type (e.g., "ext4").
    pub root_disk_fstype: Option<String>,
    /// Enable verbose serial console output for debugging.
    ///
    /// When true, the kernel cmdline includes `console=ttyS0` for full boot
    /// logging. When false (default), quiet mode suppresses serial output and
    /// i8042 probing for faster boot (~1-2s vs ~5s).
    pub verbose: bool,
}

/// Network device configuration.
pub struct NetConfig {
    /// MAC address (6 bytes). If unset, auto-generated.
    pub mac: [u8; 6],
    /// Path to the userspace networking proxy socket.
    pub socket_path: PathBuf,
}

/// Block device configuration.
pub struct DiskConfig {
    pub block_id: String,
    pub path: PathBuf,
    pub format: u32,
    pub read_only: bool,
}

/// Filesystem mount configuration (virtiofs or 9p).
pub struct FsMount {
    pub tag: String,
    pub host_path: PathBuf,
}

/// Vsock port bridge configuration.
pub struct VsockPort {
    pub port: u32,
    pub host_path: PathBuf,
    pub listen: bool,
    /// Optional host TCP port override. When set, the vsock bridge listens on
    /// this TCP port instead of the vsock port number. Enables multiple VMs
    /// to use distinct host ports for the same guest vsock port.
    pub host_tcp_port: Option<u16>,
}

impl VmContext {
    fn new(id: u32) -> Self {
        VmContext {
            id,
            state: VmState::Created,
            num_vcpus: 1,
            ram_mib: 256,
            root_path: None,
            kernel_path: None,
            kernel_cmdline: None,
            initramfs_path: None,
            exec_path: None,
            argv: Vec::new(),
            envp: Vec::new(),
            workdir: None,
            disks: Vec::new(),
            fs_mounts: Vec::new(),
            vsock_ports: Vec::new(),
            console_output: None,
            rlimits: Vec::new(),
            apic_emulation: true,
            net_config: None,
            root_disk_device: None,
            root_disk_fstype: None,
            verbose: false,
        }
    }

    /// Create a VmContext with default values for testing.
    #[cfg(test)]
    pub fn default_for_test() -> Self {
        Self::new(0)
    }
}

/// Create a new VM context. Returns the context ID (>= 0) on success.
pub fn create_ctx() -> Result<u32> {
    let id = NEXT_CTX_ID.fetch_add(1, Ordering::Relaxed);
    let ctx = VmContext::new(id);

    let mut map = CTX_MAP
        .lock()
        .map_err(|_| WkrunError::Config("context map lock poisoned".into()))?;

    if map.contains_key(&id) {
        return Err(WkrunError::ContextExists(id));
    }

    map.insert(id, ctx);
    Ok(id)
}

/// Free (destroy) a VM context. Returns Ok(()) on success.
pub fn free_ctx(ctx_id: u32) -> Result<()> {
    let mut map = CTX_MAP
        .lock()
        .map_err(|_| WkrunError::Config("context map lock poisoned".into()))?;

    map.remove(&ctx_id)
        .ok_or(WkrunError::InvalidContext(ctx_id))?;

    Ok(())
}

/// Execute a closure with mutable access to a VM context.
pub fn with_ctx_mut<F, R>(ctx_id: u32, f: F) -> Result<R>
where
    F: FnOnce(&mut VmContext) -> Result<R>,
{
    let mut map = CTX_MAP
        .lock()
        .map_err(|_| WkrunError::Config("context map lock poisoned".into()))?;

    let ctx = map
        .get_mut(&ctx_id)
        .ok_or(WkrunError::InvalidContext(ctx_id))?;

    f(ctx)
}

/// Execute a closure with read access to a VM context.
pub fn with_ctx<F, R>(ctx_id: u32, f: F) -> Result<R>
where
    F: FnOnce(&VmContext) -> Result<R>,
{
    let map = CTX_MAP
        .lock()
        .map_err(|_| WkrunError::Config("context map lock poisoned".into()))?;

    let ctx = map.get(&ctx_id).ok_or(WkrunError::InvalidContext(ctx_id))?;

    f(ctx)
}

/// Take (remove) a VM context from the global map.
/// Used when starting the VM — the context is consumed.
pub fn take_ctx(ctx_id: u32) -> Result<VmContext> {
    let mut map = CTX_MAP
        .lock()
        .map_err(|_| WkrunError::Config("context map lock poisoned".into()))?;

    map.remove(&ctx_id)
        .ok_or(WkrunError::InvalidContext(ctx_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_free_ctx() {
        let id = create_ctx().unwrap();
        assert!(free_ctx(id).is_ok());
    }

    #[test]
    fn test_double_free_returns_error() {
        let id = create_ctx().unwrap();
        assert!(free_ctx(id).is_ok());
        assert!(free_ctx(id).is_err());
    }

    #[test]
    fn test_invalid_ctx_returns_error() {
        assert!(free_ctx(u32::MAX).is_err());
    }

    #[test]
    fn test_with_ctx_mut() {
        let id = create_ctx().unwrap();

        with_ctx_mut(id, |ctx| {
            ctx.num_vcpus = 4;
            ctx.ram_mib = 1024;
            Ok(())
        })
        .unwrap();

        with_ctx(id, |ctx| {
            assert_eq!(ctx.num_vcpus, 4);
            assert_eq!(ctx.ram_mib, 1024);
            Ok(())
        })
        .unwrap();

        free_ctx(id).unwrap();
    }

    #[test]
    fn test_take_ctx() {
        let id = create_ctx().unwrap();

        with_ctx_mut(id, |ctx| {
            ctx.ram_mib = 512;
            Ok(())
        })
        .unwrap();

        let ctx = take_ctx(id).unwrap();
        assert_eq!(ctx.ram_mib, 512);

        // After taking, the context should no longer exist
        assert!(free_ctx(id).is_err());
    }

    #[test]
    fn test_set_rlimits() {
        let id = create_ctx().unwrap();

        with_ctx_mut(id, |ctx| {
            ctx.rlimits = vec![
                "RLIMIT_NOFILE=1024:4096".to_string(),
                "RLIMIT_NPROC=512:1024".to_string(),
            ];
            Ok(())
        })
        .unwrap();

        with_ctx(id, |ctx| {
            assert_eq!(ctx.rlimits.len(), 2);
            assert_eq!(ctx.rlimits[0], "RLIMIT_NOFILE=1024:4096");
            assert_eq!(ctx.rlimits[1], "RLIMIT_NPROC=512:1024");
            Ok(())
        })
        .unwrap();

        free_ctx(id).unwrap();
    }

    #[test]
    fn test_context_defaults() {
        let id = create_ctx().unwrap();

        with_ctx(id, |ctx| {
            assert_eq!(ctx.num_vcpus, 1);
            assert_eq!(ctx.ram_mib, 256);
            assert_eq!(ctx.state, VmState::Created);
            assert!(ctx.root_path.is_none());
            assert!(ctx.kernel_path.is_none());
            assert!(ctx.disks.is_empty());
            assert!(ctx.fs_mounts.is_empty());
            assert!(ctx.vsock_ports.is_empty());
            assert!(ctx.rlimits.is_empty());
            Ok(())
        })
        .unwrap();

        free_ctx(id).unwrap();
    }
}
