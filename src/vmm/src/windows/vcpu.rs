//! vCPU thread management for the Windows WHPX backend.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Callback for handling I/O port accesses from the guest.
pub trait IoHandler: Send + Sync {
    /// Handle an I/O port read. Returns the data to inject into the guest.
    fn io_read(&self, port: u16, size: u8) -> u32;

    /// Handle an I/O port write from the guest.
    fn io_write(&self, port: u16, size: u8, data: u32);
}

/// Callback for handling MMIO accesses from the guest.
pub trait MmioHandler: Send + Sync {
    /// Handle an MMIO read. Returns the data to inject into the guest.
    fn mmio_read(&self, address: u64, size: u8) -> u64;

    /// Handle an MMIO write from the guest.
    fn mmio_write(&self, address: u64, size: u8, data: u64);
}

/// Shared state for a vCPU run loop.
pub struct VcpuRunConfig {
    /// Whether the VM should keep running (set to false to request stop).
    pub running: Arc<AtomicBool>,
}

impl Clone for VcpuRunConfig {
    fn clone(&self) -> Self {
        VcpuRunConfig {
            running: self.running.clone(),
        }
    }
}

impl Default for VcpuRunConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VcpuRunConfig {
    /// Create a new vCPU run configuration.
    pub fn new() -> Self {
        VcpuRunConfig {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Request the vCPU to stop running.
    pub fn request_stop(&self) {
        self.running.store(false, Ordering::Release);
    }

    /// Check if the vCPU should continue running.
    pub fn should_run(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

/// Result of a vCPU run loop iteration.
#[derive(Debug, PartialEq, Eq)]
pub enum VcpuAction {
    /// Continue running the vCPU.
    Continue,
    /// vCPU should halt (HLT instruction).
    Halt,
    /// VM should shut down.
    Shutdown,
    /// Run was cancelled externally.
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vcpu_run_config_lifecycle() {
        let config = VcpuRunConfig::new();
        assert!(config.should_run());

        config.request_stop();
        assert!(!config.should_run());
    }

    #[test]
    fn test_vcpu_run_config_shared() {
        let config = VcpuRunConfig::new();
        let running = config.running.clone();

        assert!(running.load(Ordering::Acquire));
        config.request_stop();
        assert!(!running.load(Ordering::Acquire));
    }

    #[test]
    fn test_vcpu_run_config_clone_shares_state() {
        let config = VcpuRunConfig::new();
        let cloned = config.clone();

        assert!(config.should_run());
        assert!(cloned.should_run());

        // Stopping the clone stops the original (shared Arc).
        cloned.request_stop();
        assert!(!config.should_run());
        assert!(!cloned.should_run());
    }
}
