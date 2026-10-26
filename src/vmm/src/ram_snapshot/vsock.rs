// SPDX-License-Identifier: Apache-2.0

//! Internal vsock checkpoints for the private minimal-VM owner: one virtio
//! vsock with ordinary Unix IPC ports (never TSI). Connections never survive
//! a pause: it stops the backend, which closes every connection, completes
//! the guest's queued TX with length 0 and owes the guest a transport reset
//! (virtio 1.2 §5.10.6.7). Every resume, of a source or an import, delivers
//! that reset before the backend accepts or opens any connection, so a
//! stale request is never replayed; guest listeners survive it.
//!
//! The image keeps the CID, each port's role, the transport, the three
//! queues and the reset state; host paths come from the caller of every
//! attach or import, never from the image.
//!
//! A reopen that fails on the guest's event-queue kick (a listening path
//! that cannot bind, an interrupt that cannot be raised) has no caller to
//! report to: the device writes the owner's failure notifier, so the event
//! thread latches the exit as a failure and stops every vCPU, and the
//! backend stays failed.
//!
//! A send blocked under the device lock (a host peer that reads nothing)
//! can stall the event thread and any vCPU touching the device's MMIO
//! window, so the owner keeps the device's gate and quiesces it, without
//! the device lock, before waiting for a vCPU or joining a thread.

use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use devices::virtio::persist::{MmioTransportState, QueueState, VirtioDeviceState};
use devices::virtio::{
    MmioTransport, TsiFlags, VirtioDevice, Vsock, VsockGate, VsockResetState, TYPE_VSOCK,
    VSOCK_FEATURES, VSOCK_NUM_QUEUES, VSOCK_QUEUE_SIZE,
};
use serde::{Deserialize, Serialize};
use vm_memory::GuestMemoryMmap;

use super::events::Exit;
use super::wiring::{self, MMIO_LEN};
use super::{Error, RamSnapshotVm, Region, Result};

/// After the RNG and balloon slots, with the next legacy-range GSI.
pub(super) const VSOCK_MMIO_ADDR: u64 = 0xd000_b000;
pub(super) const VSOCK_IRQ: u32 = 7;
const TX: usize = 1;
/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;
/// Longest Unix socket path that fits `sockaddr_un.sun_path` with its NUL.
const MAX_SOCKET_PATH: usize = 107;
/// The lowest guest CID; 0–2 address the hypervisor, loopback and host.
const MIN_GUEST_CID: u64 = 3;

/// Host Unix socket per vsock port: `(path, true)` binds `path` for
/// host-initiated connections, `(path, false)` connects guest-initiated
/// connections to the host listener at `path`.
pub(crate) type VsockPorts = HashMap<u32, (PathBuf, bool)>;

/// The vsock attached to the minimal VM owner.
pub(super) struct VsockDevice {
    device: Arc<Mutex<Vsock>>,
    transport: Arc<Mutex<MmioTransport>>,
    /// Taken at attach: a pause or teardown never locks the device for it.
    gate: Arc<VsockGate>,
    cid: u64,
    ports: Vec<PortMeta>,
}

/// One port's role; its host path is not part of an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PortMeta {
    pub(super) port: u32,
    pub(super) listen: bool,
}

/// Vsock snapshot metadata. No host path or connection state appears here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VsockMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) cid: u64,
    /// Ordered by port.
    pub(super) ports: Vec<PortMeta>,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
    pub(super) reset_pending: bool,
    pub(super) interrupt_owed: bool,
}

/// The vsock's (transport, MMIO address, GSI) for the shared wiring.
pub(super) fn slot(vsock: &VsockDevice) -> (&Arc<Mutex<MmioTransport>>, u64, u32) {
    (&vsock.transport, VSOCK_MMIO_ADDR, VSOCK_IRQ)
}

/// `GuestMemoryMmap` clones the vsock legitimately holds whenever the owner
/// probes: the transport, plus the device state once activated. The probes
/// run before vCPUs start (inactive) or paused (backend stopped).
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    vm.vsock.as_ref().map_or(0, |vsock| {
        1 + usize::from(vsock.device.lock().unwrap().is_activated())
    })
}

fn check_cid(cid: u64) -> Result<()> {
    if !(MIN_GUEST_CID..u64::from(u32::MAX)).contains(&cid) {
        return Err(Error::Invalid("vsock guest CID is reserved or not 32-bit"));
    }
    Ok(())
}

/// Each port's role, ordered by port, after checking every host path: it
/// must fit `sun_path` without a NUL byte, and no two listening ports may
/// bind the same path (connecting ports may share one).
fn port_roles(ports: &VsockPorts) -> Result<Vec<PortMeta>> {
    let mut roles = Vec::with_capacity(ports.len());
    let mut bound = HashSet::new();
    for (port, (path, listen)) in ports {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_SOCKET_PATH || bytes.contains(&0) {
            return Err(Error::Full(format!(
                "vsock port {port}: host socket path is empty, too long or holds a NUL byte"
            )));
        }
        if *listen && !bound.insert(path) {
            return Err(Error::Full(format!(
                "vsock port {port}: another port already listens on its host socket path"
            )));
        }
        roles.push(PortMeta {
            port: *port,
            listen: *listen,
        });
    }
    roles.sort_by_key(|role| role.port);
    Ok(roles)
}

/// The Unix IPC device and its gate; a deferred backend failure writes
/// `exit`.
fn new_vsock(cid: u64, ports: &VsockPorts, exit: &Exit) -> Result<(Vsock, Arc<VsockGate>)> {
    let mut vsock = Vsock::new(cid, None, Some(ports.clone()), TsiFlags::empty())
        .map_err(|e| Error::Full(format!("create vsock: {e:?}")))?;
    let gate = vsock
        .snapshot_control()
        .map_err(|e| Error::Full(format!("vsock snapshot control: {e:?}")))?;
    vsock.set_failure_notifier(exit.failure_notifier()?);
    Ok((vsock, gate))
}

fn new_device(
    vm: &mut RamSnapshotVm,
    cid: u64,
    ports: &VsockPorts,
) -> Result<(Arc<Mutex<Vsock>>, Arc<Mutex<MmioTransport>>, Arc<VsockGate>)> {
    let ioapic = vm.ensure_kernel_irqchip()?;
    let (vsock, gate) = new_vsock(cid, ports, &vm.exit)?;
    let device = Arc::new(Mutex::new(vsock));
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(ioapic),
    )));
    let transport = Arc::new(Mutex::new(
        MmioTransport::new(vm.memory.clone(), intc, device.clone())
            .map_err(|e| Error::Full(format!("create vsock transport: {e}")))?,
    ));
    Ok((device, transport, gate))
}

/// Attach the single internal vsock before vCPUs start. Its backend starts
/// when the guest driver activates the device. Any failure after the
/// checks poisons the owner for further snapshots.
pub(super) fn attach(vm: &mut RamSnapshotVm, cid: u64, ports: &VsockPorts) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "the internal vsock cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid(
            "the internal vsock attaches only before vCPU start",
        ));
    }
    if vm.vsock.is_some() {
        return Err(Error::Invalid("the internal vsock is already attached"));
    }
    check_cid(cid)?;
    let roles = port_roles(ports)?;
    let attached = (|| {
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let (device, transport, gate) = new_device(vm, cid, ports)?;
        wiring::register_device(vm, &transport, VSOCK_MMIO_ADDR, VSOCK_IRQ)?;
        Ok(VsockDevice {
            device,
            transport,
            gate,
            cid,
            ports: roles,
        })
    })();
    match attached {
        Ok(vsock) => {
            vm.vsock = Some(vsock);
            Ok(())
        }
        Err(error) => {
            vm.control.unusable = true;
            Err(error)
        }
    }
}

/// Cancel any send blocked under the device lock and hold the backend
/// closed, without taking that lock. Runs before the owner waits for a vCPU
/// pause acknowledgment or joins the event or vCPU threads.
pub(super) fn quiesce_gate(vm: &RamSnapshotVm) {
    if let Some(vsock) = &vm.vsock {
        vsock.gate.quiesce();
    }
}

/// Stop the backend once the vCPUs are paused and the event thread frozen:
/// join its workers, release its guest RAM, complete stale TX and owe the
/// guest a reset. Its queues then stay unchanged until `resume`.
pub(super) fn stop(vm: &RamSnapshotVm) -> Result<()> {
    let Some(vsock) = &vm.vsock else {
        return Ok(());
    };
    vsock
        .device
        .lock()
        .unwrap()
        .stop_backend()
        .map_err(|e| Error::Full(format!("stop vsock backend: {e:?}")))
}

/// Reopen an activated device's backend: deliver the reset first, or keep
/// it pending until the guest offers an event buffer. An inactive device
/// only loses the pause's hold, so a later activation starts its backend.
pub(super) fn resume(vm: &RamSnapshotVm) -> Result<()> {
    let Some(vsock) = &vm.vsock else {
        return Ok(());
    };
    let mut device = vsock.device.lock().unwrap();
    if !device.is_activated() {
        vsock.gate.release();
        return Ok(());
    }
    device
        .restart_backend()
        .map_err(|e| Error::Full(format!("restart vsock backend: {e:?}")))
}

/// Join the backend workers on teardown, after the event and vCPU threads.
pub(super) fn teardown(vm: &RamSnapshotVm) {
    if let Some(vsock) = &vm.vsock {
        if let Err(e) = vsock.device.lock().unwrap().stop_backend() {
            error!("vsock backend teardown: {e:?}");
        }
    }
}

/// Metadata-only validation, before guest RAM or any target resource exists.
pub(super) fn validate_metadata(meta: &VsockMeta, regions: &[Region]) -> Result<()> {
    let invalid = |why: &str| Error::Full(format!("vsock: {why}"));
    if meta.mmio_addr != VSOCK_MMIO_ADDR || meta.mmio_len != MMIO_LEN || meta.irq != VSOCK_IRQ {
        return Err(invalid("MMIO/IRQ is outside its internal slot"));
    }
    wiring::check_window(meta.mmio_addr, regions.iter().map(|r| (r.gpa, r.len)))?;
    check_cid(meta.cid)?;
    if meta
        .ports
        .windows(2)
        .any(|pair| pair[0].port >= pair[1].port)
    {
        return Err(invalid("ports are duplicated or unordered"));
    }
    if meta.device.avail_features != VSOCK_FEATURES {
        return Err(invalid(
            "offered features differ from the internal contract",
        ));
    }
    meta.transport
        .validate()
        .map_err(|_| invalid("transport registers are outside the state machine"))?;
    meta.device
        .validate_structure(TYPE_VSOCK, VSOCK_NUM_QUEUES, VSOCK_QUEUE_SIZE)
        .map_err(|_| invalid("virtio state is structurally inconsistent"))?;
    if (meta.transport.device_status & DRIVER_OK != 0) != meta.device.activated {
        return Err(invalid("activation disagrees with the transport status"));
    }
    // Every pause of an activated device closes its connections.
    if meta.reset_pending != meta.device.activated
        || (meta.interrupt_owed && !meta.device.activated)
    {
        return Err(invalid("reset state disagrees with the activation"));
    }
    Ok(())
}

/// The caller's ports must name exactly the image's ports with the same
/// roles, each with a usable host path (see `port_roles`).
pub(super) fn check_resources(meta: &VsockMeta, ports: &VsockPorts) -> Result<()> {
    if port_roles(ports)? != meta.ports {
        return Err(Error::Invalid(
            "restore resources: vsock ports and roles differ from the image",
        ));
    }
    Ok(())
}

/// Ring validation against the loaded guest RAM: all three queues of an
/// activated device, and a valid head for every TX chain the resume will
/// complete as stale.
pub(super) fn validate_rings(meta: &VsockMeta, memory: &GuestMemoryMmap) -> Result<()> {
    meta.device
        .validate(memory, TYPE_VSOCK, VSOCK_NUM_QUEUES, VSOCK_QUEUE_SIZE)
        .map_err(|e| Error::Full(format!("vsock virtio state: {e:?}")))?;
    if meta.device.activated {
        meta.device.queues[TX]
            .validate_available_heads(memory)
            .map_err(|_| Error::Invalid("vsock TX ring holds an invalid descriptor head"))?;
    }
    Ok(())
}

/// Capture the stopped device while the vCPUs are paused, the event thread
/// frozen and the irqfds drained.
pub(super) fn capture(vm: &RamSnapshotVm, regions: &[Region]) -> Result<Option<VsockMeta>> {
    let Some(vsock) = &vm.vsock else {
        return Ok(None);
    };
    let transport = vsock.transport.lock().unwrap();
    let device = vsock.device.lock().unwrap();
    let queues = if device.is_activated() {
        device
            .snapshot_queue_states()
            .ok_or(Error::Invalid("the vsock backend is running"))?
    } else {
        transport.queue_states()
    };
    let VsockResetState {
        pending,
        interrupt_owed,
    } = device.snapshot_reset_state();
    let meta = VsockMeta {
        mmio_addr: VSOCK_MMIO_ADDR,
        mmio_len: MMIO_LEN,
        irq: VSOCK_IRQ,
        cid: vsock.cid,
        ports: vsock.ports.clone(),
        transport: transport.save_transport_state(),
        device: VirtioDeviceState {
            device_type: TYPE_VSOCK,
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues,
            activated: device.is_activated(),
        },
        reset_pending: pending,
        interrupt_owed,
    };
    validate_metadata(&meta, regions)?;
    validate_rings(&meta, &vm.memory)?;
    Ok(Some(meta))
}

/// Rebuild the validated device at its fixed slot with new eventfds and the
/// caller's host paths. An activated device comes back with its backend
/// stopped and its reset still owed; `resume` reopens it.
pub(super) fn restore(vm: &mut RamSnapshotVm, meta: &VsockMeta, ports: &VsockPorts) -> Result<()> {
    let (device, transport, gate) = new_device(vm, meta.cid, ports)?;
    {
        let mut locked = device.lock().unwrap();
        locked.set_acked_features(meta.device.acked_features);
        locked
            .restore_reset_state(VsockResetState {
                pending: meta.reset_pending,
                interrupt_owed: meta.interrupt_owed,
            })
            .map_err(|e| Error::Full(format!("restore vsock reset state: {e:?}")))?;
    }
    {
        let mut locked = transport.lock().unwrap();
        locked.restore_transport_state(
            &meta.transport,
            meta.device
                .queues
                .iter()
                .map(QueueState::to_queue)
                .collect(),
        );
        if meta.device.activated {
            locked
                .activate_restored()
                .map_err(|e| Error::Full(format!("restore-activate vsock: {e:?}")))?;
        }
    }
    wiring::register_device(vm, &transport, meta.mmio_addr, meta.irq)?;
    vm.vsock = Some(VsockDevice {
        device,
        transport,
        gate,
        cid: meta.cid,
        ports: meta.ports.clone(),
    });
    Ok(())
}

/// The device the event thread dispatches.
pub(super) fn event_device(vm: &RamSnapshotVm) -> Option<Arc<Mutex<Vsock>>> {
    vm.vsock.as_ref().map(|vsock| vsock.device.clone())
}

#[cfg(test)]
mod kvm_tests;
#[cfg(test)]
mod tests;
