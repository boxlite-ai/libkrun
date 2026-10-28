// SPDX-License-Identifier: Apache-2.0

//! Checkpointing VMs behind the C API (`krun_snapshot_*`), Linux
//! x86_64/KVM only; elsewhere every call returns -ENOTSUP. A context opts
//! in before `krun_start_enter`, which then branches before the ordinary
//! eager device construction: it cold-boots a `SnapshotVm` from the
//! context, or imports one paused from a checkpoint (no payload, kernel
//! loading or guest initialization) onto the context's new endpoints, and
//! owns it on the calling thread until guest execution ends (`control`).

mod descriptor;

use std::path::PathBuf;

#[cfg(feature = "net")]
use vmm::vmm_config::net::NetworkInterfaceConfig;

/// What enabling checkpoints and configuring an import record in a
/// context.
/// Unsupported builds never enable checkpoints, so never read it.
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_arch = "x86_64",
        not(feature = "tee"),
        not(feature = "aws-nitro")
    )),
    allow(dead_code)
)]
#[derive(Default)]
pub(crate) struct Setup {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        not(feature = "tee"),
        not(feature = "aws-nitro")
    ))]
    pub(crate) fd_import: Option<supported::DescriptorImport>,
    /// The NICs, kept unopened: the VM opens its NIC itself.
    #[cfg(feature = "net")]
    pub(crate) nics: Vec<NetworkInterfaceConfig>,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
))]
mod control;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
))]
mod supported {
    use std::path::PathBuf;

    use vmm::snapshot_vm::{RestoreEndpoints, SnapshotDevices, SnapshotVm, VmState};
    use vmm::vmm_config::vsock::VsockDeviceConfig;

    use super::control::{self, Request, State};
    use super::*;
    use crate::ContextConfig;

    pub(crate) use control::free;

    pub(crate) const PAUSE_HOST_WRITERS_STOPPED: u32 = 1 << 0;

    pub(crate) const STATE_CONFIGURED: u32 = 0;
    pub(crate) const STATE_STARTING: u32 = 1;
    pub(crate) const STATE_RUNNING: u32 = 2;
    pub(crate) const STATE_PAUSED: u32 = 3;
    pub(crate) const STATE_EXITED: u32 = 4;
    pub(crate) const STATE_FAILED: u32 = 5;
    pub(crate) const STATE_STOPPED: u32 = 6;

    pub(crate) fn enable(ctx_id: u32, cfg: &mut ContextConfig, flags: u32) -> i32 {
        if flags != 0 || cfg.snapshot.is_some() || cfg.net_index != 0 {
            return -libc::EINVAL;
        }
        if !control::register(ctx_id) {
            return -libc::EINVAL;
        }
        cfg.snapshot = Some(Setup::default());
        0
    }

    pub(crate) struct DescriptorImport {
        pub image: std::fs::File,
        pub bindings: vmm::snapshot_vm::checkpoint::ImportBindings,
    }

    pub(crate) fn pause(ctx_id: u32, flags: u32) -> i32 {
        if flags & !PAUSE_HOST_WRITERS_STOPPED != 0 {
            return -libc::EINVAL;
        }
        control::request(
            ctx_id,
            Request::Pause {
                host_writers_stopped: flags & PAUSE_HOST_WRITERS_STOPPED != 0,
            },
        )
    }

    pub(crate) fn resume(ctx_id: u32) -> i32 {
        control::request(ctx_id, Request::Resume)
    }

    pub(crate) fn stop(ctx_id: u32) -> i32 {
        control::request(ctx_id, Request::Stop)
    }

    /// The state constant and the exit code (0 unless exited).
    pub(crate) fn state(ctx_id: u32) -> Result<(u32, i32), i32> {
        Ok(match control::state(ctx_id)? {
            State::Configured => (STATE_CONFIGURED, 0),
            State::Starting => (STATE_STARTING, 0),
            State::Running => (STATE_RUNNING, 0),
            State::Paused => (STATE_PAUSED, 0),
            State::Exited(code) => (STATE_EXITED, code),
            State::Failed => (STATE_FAILED, 0),
            State::Stopped => (STATE_STOPPED, 0),
        })
    }

    pub(crate) fn restored_share(ctx_id: u32, tag: &str) -> Result<PathBuf, i32> {
        control::restored_share(ctx_id, tag)
    }

    /// `krun_start_enter` of a checkpointing context: start the VM and own
    /// it until execution ends.
    pub(crate) fn start_enter(ctx_id: u32, mut cfg: ContextConfig) -> i32 {
        let Some(setup) = cfg.snapshot.take() else {
            return -libc::EINVAL;
        };
        control::serve(ctx_id, || {
            let vm = start(&mut cfg, setup)?;
            crate::memory_hotplug::bind(ctx_id, vm.memory_control());
            Ok(vm)
        })
    }

    fn refused(why: &str) -> i32 {
        error!("checkpointing VM: {why}");
        -libc::EINVAL
    }

    fn start(cfg: &mut ContextConfig, setup: Setup) -> Result<SnapshotVm, i32> {
        #[cfg(feature = "net")]
        if cfg.legacy_net_cfg.is_some() {
            return Err(refused("only a NIC added by UnixStream path is supported"));
        }
        #[cfg(feature = "net")]
        let mut nics = setup.nics;
        #[cfg(feature = "net")]
        if nics.len() > 1 {
            return Err(refused("at most one NIC is supported"));
        }
        #[cfg(feature = "net")]
        let nic = nics.pop();
        #[cfg(all(feature = "net", not(feature = "blk")))]
        if nic.is_some() {
            return Err(refused("a NIC needs the blk feature"));
        }
        #[cfg(feature = "net")]
        let vsock = crate::vsock_device_config(cfg, nic.is_some());
        #[cfg(not(feature = "net"))]
        let vsock = crate::vsock_device_config(cfg, false);
        let started = match setup.fd_import {
            Some(import) => {
                #[cfg(feature = "blk")]
                if !cfg.get_block_cfg().is_empty() {
                    return Err(refused("an import brings its disks"));
                }
                SnapshotVm::check_import_configuration(&cfg.vmr)
                    .map_err(|e| refused(&e.to_string()))?;
                #[cfg(all(feature = "blk", feature = "net"))]
                let nic_socket = nic.map(nic_socket).transpose()?;
                #[cfg(not(all(feature = "blk", feature = "net")))]
                let nic_socket = None;
                let vsock_ports = vsock.map(vsock_ports).transpose()?;
                crate::set_vmm_ids(cfg)?;
                SnapshotVm::import_fd(
                    import.image,
                    import.bindings,
                    RestoreEndpoints {
                        nic_socket,
                        vsock_ports,
                        console_output: cfg.console_output.take(),
                    },
                )
            }
            None => {
                crate::load_payload(cfg)?;
                crate::set_kernel_cmdline(cfg)?;
                if let Some(output) = cfg.console_output.take() {
                    cfg.vmr.set_console_output(output);
                }
                crate::set_vmm_ids(cfg)?;
                SnapshotVm::boot(
                    &cfg.vmr,
                    SnapshotDevices {
                        #[cfg(feature = "blk")]
                        disks: cfg.get_block_cfg(),
                        #[cfg(all(feature = "blk", feature = "net"))]
                        nic,
                        vsock,
                    },
                )
            }
        };
        started.map_err(|e| {
            error!("checkpointing VM: {e}");
            -libc::EIO
        })
    }

    #[cfg(all(feature = "blk", feature = "net"))]
    fn nic_socket(nic: NetworkInterfaceConfig) -> Result<PathBuf, i32> {
        use devices::virtio::net::device::VirtioNetBackend;
        match nic.backend {
            VirtioNetBackend::UnixstreamPath(socket) => Ok(socket),
            _ => Err(refused("only a NIC added by UnixStream path is supported")),
        }
    }

    /// An import's new vsock ports: Unix IPC only.
    fn vsock_ports(
        config: VsockDeviceConfig,
    ) -> Result<std::collections::HashMap<u32, (PathBuf, bool)>, i32> {
        if !config.tsi_flags.is_empty() || config.host_port_map.is_some_and(|map| !map.is_empty()) {
            return Err(refused("vsock TSI and TCP port maps are not supported"));
        }
        Ok(config.unix_ipc_port_map.unwrap_or_default())
    }

    impl control::Vm for SnapshotVm {
        fn pause(&mut self, host_writers_stopped: bool) -> Result<(), String> {
            // A declaration lingers only if the pause fails before taking
            // effect, which after a successful declaration means the VM is
            // exiting; any later failure disables the VM, ending it.
            if host_writers_stopped {
                self.declare_host_writers_stopped()
                    .map_err(|e| e.to_string())?;
            }
            SnapshotVm::pause(self).map_err(|e| e.to_string())
        }

        fn resume(&mut self) -> Result<(), String> {
            SnapshotVm::resume(self).map_err(|e| e.to_string())
        }

        fn prepare(&mut self) -> Result<vmm::snapshot_vm::checkpoint::PreparedResources, String> {
            SnapshotVm::prepare_checkpoint(self).map_err(|e| e.to_string())
        }
        fn export_fd(
            &mut self,
            memory: std::fs::File,
            qcow2: std::fs::File,
            metadata: vmm::snapshot_vm::checkpoint::ExportMetadata,
        ) -> Result<(), String> {
            SnapshotVm::export_fd(self, memory, qcow2, metadata).map_err(|e| e.to_string())
        }
        fn discard_preparation(&mut self) {
            SnapshotVm::discard_checkpoint_preparation(self);
        }
        fn abort_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
            SnapshotVm::capture_abort(self)
        }
        fn stop_signal(&self) -> Result<Box<dyn Fn() + Send + Sync>, String> {
            SnapshotVm::stop_signal(self).map_err(|e| e.to_string())
        }

        fn stop(&mut self) {
            SnapshotVm::stop(self)
        }

        fn state(&mut self) -> State {
            match SnapshotVm::state(self) {
                VmState::Running => State::Running,
                VmState::Paused => State::Paused,
                VmState::Exited(code) => State::Exited(code),
                VmState::Failed => State::Failed,
                VmState::Stopped => State::Stopped,
            }
        }

        fn exit_watch(&self) -> Box<dyn FnOnce() + Send> {
            let waiter = self.exit_waiter();
            Box::new(move || {
                waiter.wait(None);
            })
        }

        fn restored_shares(&self) -> Vec<(String, PathBuf)> {
            SnapshotVm::restored_shares(self).to_vec()
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
))]
pub(crate) use supported::*;

/// Every call is unsupported here; no context ever enables checkpoints.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
)))]
mod unsupported {
    use std::path::PathBuf;

    use crate::ContextConfig;

    pub(crate) fn enable(_ctx_id: u32, _cfg: &mut ContextConfig, _flags: u32) -> i32 {
        -libc::ENOTSUP
    }

    pub(crate) fn pause(_ctx_id: u32, _flags: u32) -> i32 {
        -libc::ENOTSUP
    }

    pub(crate) fn resume(_ctx_id: u32) -> i32 {
        -libc::ENOTSUP
    }

    pub(crate) fn stop(_ctx_id: u32) -> i32 {
        -libc::ENOTSUP
    }

    pub(crate) fn state(_ctx_id: u32) -> Result<(u32, i32), i32> {
        Err(-libc::ENOTSUP)
    }

    pub(crate) fn restored_share(_ctx_id: u32, _tag: &str) -> Result<PathBuf, i32> {
        Err(-libc::ENOTSUP)
    }

    pub(crate) fn free(_ctx_id: u32) -> Option<i32> {
        None
    }

    pub(crate) fn start_enter(_ctx_id: u32, _cfg: ContextConfig) -> i32 {
        -libc::ENOTSUP
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee"),
    not(feature = "aws-nitro")
)))]
pub(crate) use unsupported::*;

#[cfg(test)]
mod tests;
