//! Virtual Machine Manager — hypervisor abstraction and WHPX backend.

pub mod types;

#[cfg(target_os = "windows")]
pub mod whpx;

pub mod boot;
pub mod cmdline;
pub mod context;
pub mod devices;
pub mod error;
pub mod insn;
pub mod memory;
pub mod runner;
pub mod vcpu;
