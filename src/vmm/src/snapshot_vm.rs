// SPDX-License-Identifier: Apache-2.0

//! The checkpointing VM for libkrun's C API: a Linux guest cold-booted
//! from `VmResources`, or imported from a checkpoint, that pauses, exports
//! a self-contained checkpoint and resumes. Linux x86_64/KVM only.
//!
//! It wraps the private owner (`ram_snapshot`): the owner holds guest RAM,
//! the VM, every device and thread; no mapping, descriptor or vCPU handle
//! escapes it. A caller branches before the ordinary eager construction of
//! disks, the NIC and the vsock, and passes those as `SnapshotDevices`.
//! An import runs no payload loader, boot setup or guest initialization:
//! it returns the paused guest of the image, which `resume` continues.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ram_snapshot::{
    check_resources, BootDevices, BootImage, ConsoleEndpoints, ExitWaiter, RamSnapshotVm,
    RestoreResources, RunState,
};
use crate::resources::VmResources;
#[cfg(feature = "blk")]
use crate::vmm_config::block::BlockDeviceConfig;
#[cfg(all(feature = "blk", feature = "net"))]
use crate::vmm_config::net::NetworkInterfaceConfig;
use crate::vmm_config::vsock::VsockDeviceConfig;

/// A failed checkpointing VM operation. Whether the VM still runs, stays
/// paused or ended is `SnapshotVm::state`.
#[derive(Debug)]
pub struct SnapshotError(String);

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SnapshotError {}

fn failed(e: crate::ram_snapshot::Error) -> SnapshotError {
    SnapshotError(e.to_string())
}

type Result<T> = std::result::Result<T, SnapshotError>;

/// The devices `VmResources` would hold built and opened, unopened: the VM
/// opens each itself.
#[derive(Default)]
pub struct SnapshotDevices {
    /// Disks in guest order (the first is `vda`); each must sync fully and
    /// use no direct I/O.
    #[cfg(feature = "blk")]
    pub disks: Vec<BlockDeviceConfig>,
    /// The NIC: a UnixStream backend given by path (passt), connected when
    /// the guest activates the device.
    #[cfg(all(feature = "blk", feature = "net"))]
    pub nic: Option<NetworkInterfaceConfig>,
    /// The vsock: Unix IPC ports only, without TSI or TCP port maps.
    pub vsock: Option<VsockDeviceConfig>,
}

/// The new host resources of an import, each required exactly when the
/// image has the device. Images never name host paths or descriptors.
#[derive(Default)]
pub struct RestoreEndpoints {
    /// A new directory for the disk copies, created exclusively with mode
    /// 0700: `disk-<i>.raw` (0600, raw) for the image's disk `i` in guest
    /// order. Once the import succeeds the directory and its files are the
    /// caller's and never removed by the VM; a failed import removes what
    /// it created.
    pub disk_dir: Option<PathBuf>,
    /// The freshly started UnixStream network backend.
    pub nic_socket: Option<PathBuf>,
    /// New host socket paths of the vsock ports; ports and roles must
    /// equal the image's.
    pub vsock_ports: Option<HashMap<u32, (PathBuf, bool)>>,
    /// A new console output file: created exclusively once the image and
    /// every other endpoint passed their checks (an existing file is
    /// refused untouched), removed again if the import fails.
    pub console_output: Option<PathBuf>,
    /// A new absolute directory for the share copies, created exclusively
    /// with mode 0700 and kept as guest data once the import succeeds (a
    /// VM-owned boot root copy inside it goes with the VM).
    pub fs_dir: Option<PathBuf>,
}

/// Where guest execution stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmState {
    Running,
    Paused,
    /// The guest ended execution with this status (the code its init set,
    /// else its vCPU's, else 0), as the ordinary VMM reports it.
    Exited(i32),
    /// A host-side failure ended guest execution.
    Failed,
    /// `stop`, or an uncertain control operation, ended execution.
    Stopped,
}

impl From<RunState> for VmState {
    fn from(state: RunState) -> Self {
        match state {
            RunState::Running => Self::Running,
            RunState::Paused => Self::Paused,
            RunState::Exited(code) => Self::Exited(code),
            RunState::Failed => Self::Failed,
            RunState::Stopped => Self::Stopped,
        }
    }
}

/// Waits for guest execution to end without holding the VM.
#[derive(Clone)]
pub struct SnapshotExitWaiter(ExitWaiter);

impl SnapshotExitWaiter {
    /// Block until execution ended or `timeout` passed (None waits for
    /// ever); returns whether it ended. `SnapshotVm::state` tells how.
    pub fn wait(&self, timeout: Option<Duration>) -> bool {
        self.0.wait(timeout)
    }
}

pub struct SnapshotVm(RamSnapshotVm);

impl SnapshotVm {
    /// Cold-boot the configured Linux guest. Every unsupported feature or
    /// device is refused before anything is created.
    pub fn boot(resources: &VmResources, devices: SnapshotDevices) -> Result<Self> {
        let image = BootImage::new(
            resources,
            BootDevices {
                #[cfg(feature = "blk")]
                disks: devices.disks,
                #[cfg(all(feature = "blk", feature = "net"))]
                nic: devices.nic,
                vsock: devices.vsock,
            },
        )
        .map_err(failed)?;
        RamSnapshotVm::boot(image).map(Self).map_err(failed)
    }

    /// Refuse an import context: what `boot` refuses, plus any share
    /// (the image brings its own).
    pub fn check_import_configuration(resources: &VmResources) -> Result<()> {
        check_resources(resources).map_err(failed)?;
        if !resources.fs.is_empty() {
            return Err(SnapshotError(
                "checkpoint import: virtio-fs shares come from the image".into(),
            ));
        }
        Ok(())
    }

    /// Import the checkpoint at `path` into a new paused VM on
    /// `endpoints`; `resume` starts it. The disk and share copies are the
    /// caller's once it succeeds (see `RestoreEndpoints`).
    pub fn import(path: &Path, endpoints: RestoreEndpoints) -> Result<Self> {
        let resources = RestoreResources {
            disk_dir: endpoints.disk_dir,
            nic_socket: endpoints.nic_socket,
            // A booted VM's UARTs are sinks.
            serial: Some([None, None, None, None]),
            vsock_ports: endpoints.vsock_ports,
            console_ports: endpoints.console_output.map(ConsoleEndpoints::NewOutput),
            fs_dir: endpoints.fs_dir,
        };
        #[cfg_attr(not(feature = "blk"), allow(unused_mut))]
        let mut vm = RamSnapshotVm::import(path, resources).map_err(failed)?;
        #[cfg(feature = "blk")]
        vm.hand_over_imported_disks();
        Ok(Self(vm))
    }

    /// Each imported share's tag and the root of its copy in
    /// `RestoreEndpoints::fs_dir`, except the VM-owned boot root; empty
    /// for a booted VM.
    pub fn restored_shares(&self) -> &[(String, PathBuf)] {
        self.0.restored_shares()
    }

    /// Pause every vCPU and device at one cut.
    pub fn pause(&mut self) -> Result<()> {
        self.0.pause().map_err(failed)
    }

    /// The caller stopped every host writer of the shares until resume;
    /// exports of a VM with shares need it.
    pub fn declare_host_writers_stopped(&mut self) -> Result<()> {
        self.0.declare_host_writers_stopped().map_err(failed)
    }

    /// Write a checkpoint of the paused VM to the new file `path`; the VM
    /// stays paused, also on failure.
    pub fn export(&mut self, path: &Path) -> Result<()> {
        self.0.export(path).map_err(failed)
    }

    pub fn resume(&mut self) -> Result<()> {
        self.0.resume().map_err(failed)
    }

    pub fn state(&mut self) -> VmState {
        self.0.run_state().into()
    }

    pub fn exit_waiter(&self) -> SnapshotExitWaiter {
        SnapshotExitWaiter(self.0.exit_waiter())
    }

    /// End guest execution for good; resources go when the VM drops.
    pub fn stop(&mut self) {
        self.0.stop()
    }
}
