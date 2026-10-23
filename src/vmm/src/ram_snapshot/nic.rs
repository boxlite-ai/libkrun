// SPDX-License-Identifier: Apache-2.0

//! Internal stage-4 network checkpoints: one UnixStream virtio-net device
//! for the private minimal-VM owner. No public BoxLite entry point.
//!
//! The backend connection is never part of a checkpoint. A restore connects
//! a freshly started compatible backend; old TCP/NAT state, frames buffered
//! in the source worker or backend, and partial frames are not migrated.
//! Guest driver, device and queue state are kept: guest sockets recover by
//! their own errors and timeouts.

use std::path::Path;
use std::sync::{Arc, Mutex};

use devices::virtio::net::device::{config_bytes_for, offered_features, VirtioNetBackend};
use devices::virtio::net::{NetQueueStates, NUM_QUEUES, QUEUE_SIZE};
use devices::virtio::persist::{MmioTransportState, VirtioDeviceState};
use devices::virtio::{MmioTransport, Net, Queue, VirtioDevice, TYPE_NET};
use serde::{Deserialize, Serialize};
use vm_memory::GuestMemoryMmap;

use super::blk::{self, DiskMeta};
use super::wiring::{self, MMIO_LEN};
use super::{Error, RamSnapshotVm, Region, Result};

/// The NIC sits right after the eight-slot disk window and takes its last
/// GSI, so at most seven disks coexist with it.
pub(super) const NIC_MMIO_ADDR: u64 = blk::MMIO_BASE + blk::MAX_DISKS as u64 * MMIO_LEN;
pub(super) const NIC_IRQ: u32 = blk::IRQ_LAST;
pub(super) const MAX_DISKS_WITH_NIC: usize = blk::MAX_DISKS - 1;
const TX: usize = 1;
/// libkrun's documented NET_FEATURE_* offload bits; anything else is not
/// part of the internal snapshot contract.
const FEATURE_MASK: u32 =
    (1 << 0) | (1 << 1) | (1 << 7) | (1 << 8) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14);
/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;
/// Longest Unix socket path that fits `sockaddr_un.sun_path` with its NUL.
const MAX_SOCKET_PATH: usize = 107;

/// The network device attached to the minimal VM owner.
pub(super) struct NicDevice {
    net: Arc<Mutex<Net>>,
    transport: Arc<Mutex<MmioTransport>>,
    mac: [u8; 6],
    features: u32,
    /// A restore completed cut-time TX chains whose interrupt is still owed
    /// once the restored irqchip state is loaded.
    tx_discard_irq: bool,
}

/// NIC snapshot metadata. No backend path or connection state appears here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NicMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) device_id: String,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
    pub(super) mac: [u8; 6],
    pub(super) features: u32,
    pub(super) config: Vec<u8>,
}

/// `GuestMemoryMmap` clones the NIC legitimately holds: the transport, plus
/// the device state and the worker once activated.
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    vm.nic.as_ref().map_or(0, |nic| {
        1 + usize::from(nic.net.lock().unwrap().is_activated()) * 2
    })
}

/// The NIC's (transport, MMIO address, GSI) for the shared wiring.
pub(super) fn slot(nic: &NicDevice) -> (&Arc<Mutex<MmioTransport>>, u64, u32) {
    (&nic.transport, NIC_MMIO_ADDR, NIC_IRQ)
}

pub(super) fn check_socket_path(path: &Path) -> Result<()> {
    let length = path.as_os_str().len();
    if length == 0 || length > MAX_SOCKET_PATH {
        return Err(Error::Invalid(
            "network backend socket path is empty or too long",
        ));
    }
    Ok(())
}

fn new_device(
    vm: &mut RamSnapshotVm,
    device_id: String,
    socket_path: &Path,
    mac: [u8; 6],
    features: u32,
) -> Result<(Arc<Mutex<Net>>, Arc<Mutex<MmioTransport>>)> {
    let ioapic = vm.ensure_kernel_irqchip()?;
    let net = Net::new(
        device_id,
        VirtioNetBackend::UnixstreamPath(socket_path.to_owned()),
        mac,
        features,
    )
    .map_err(|e| Error::Full(format!("create network device: {e:?}")))?;
    let net = Arc::new(Mutex::new(net));
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(ioapic),
    )));
    let transport = Arc::new(Mutex::new(
        MmioTransport::new(vm.memory.clone(), intc, net.clone())
            .map_err(|e| Error::Full(format!("create network transport: {e}")))?,
    ));
    Ok((net, transport))
}

/// Attach the single internal NIC before vCPUs start. The backend is a
/// UnixStream (length-prefixed frames) server at `socket_path`, connected
/// when the guest driver activates the device. Any failure poisons the
/// owner for further snapshots.
pub(super) fn attach_net(
    vm: &mut RamSnapshotVm,
    socket_path: &Path,
    mac: [u8; 6],
    features: u32,
) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "the internal NIC cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid(
            "the internal NIC attaches only before vCPU start",
        ));
    }
    if vm.nic.is_some() {
        return Err(Error::Invalid("the internal NIC is already attached"));
    }
    if vm.disks.len() > MAX_DISKS_WITH_NIC {
        return Err(Error::Invalid(
            "the internal NIC needs the last disk slot; at most seven disks may be attached",
        ));
    }
    if features & !FEATURE_MASK != 0 {
        return Err(Error::Invalid(
            "the internal NIC accepts only libkrun NET_FEATURE_* offload bits",
        ));
    }
    check_socket_path(socket_path)?;
    let attach = (|| -> Result<NicDevice> {
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let (net, transport) = new_device(vm, "net0".to_string(), socket_path, mac, features)?;
        wiring::register_device(vm, &transport, NIC_MMIO_ADDR, NIC_IRQ)?;
        Ok(NicDevice {
            net,
            transport,
            mac,
            features,
            tx_discard_irq: false,
        })
    })();
    match attach {
        Ok(device) => {
            vm.nic = Some(device);
            Ok(())
        }
        Err(error) => {
            vm.control.unusable = true;
            Err(error)
        }
    }
}

/// Metadata-only validation: everything checkable before guest RAM or any
/// target resource exists.
pub(super) fn validate_nic_metadata(
    nic: &NicMeta,
    disks: &[DiskMeta],
    regions: &[Region],
) -> Result<()> {
    if disks.len() > MAX_DISKS_WITH_NIC || disks.iter().any(|disk| disk.irq == NIC_IRQ) {
        return Err(Error::Invalid(
            "snapshot disks occupy the internal NIC slot",
        ));
    }
    if nic.mmio_addr != NIC_MMIO_ADDR
        || nic.mmio_len != MMIO_LEN
        || nic.irq != NIC_IRQ
        || nic.device_id.is_empty()
        || nic.device_id.len() > 128
    {
        return Err(Error::Invalid(
            "NIC MMIO/IRQ is outside its internal slot or the identity is invalid",
        ));
    }
    wiring::check_window(nic.mmio_addr, regions.iter().map(|r| (r.gpa, r.len)))?;
    if nic.features & !FEATURE_MASK != 0
        || nic.device.avail_features != offered_features(nic.features)
    {
        return Err(Error::Invalid(
            "NIC offers features outside the internal network contract",
        ));
    }
    // The config is fully determined by the MAC; any other byte would be
    // presented to the guest by nothing a restore can rebuild.
    if nic.config != config_bytes_for(nic.mac) {
        return Err(Error::Invalid("NIC config bytes do not match its MAC"));
    }
    nic.transport
        .validate()
        .map_err(|_| Error::Invalid("NIC transport registers are outside the state machine"))?;
    nic.device
        .validate_structure(TYPE_NET, NUM_QUEUES, QUEUE_SIZE)
        .map_err(|_| Error::Invalid("NIC virtio state is structurally inconsistent"))?;
    if (nic.transport.device_status & DRIVER_OK != 0) != nic.device.activated {
        return Err(Error::Invalid(
            "NIC activation disagrees with the transport status",
        ));
    }
    Ok(())
}

/// Ring-level validation against the loaded guest RAM, before any device
/// resource exists: cursors and ranges for both queues, and valid heads for
/// every cut-time TX chain the restore will complete as dropped.
pub(super) fn validate_nic_rings(nic: &NicMeta, memory: &GuestMemoryMmap) -> Result<()> {
    nic.device
        .validate(memory, TYPE_NET, NUM_QUEUES, QUEUE_SIZE)
        .map_err(|_| Error::Invalid("NIC virtio state is inconsistent with guest RAM"))?;
    if nic.device.activated {
        nic.device.queues[TX]
            .validate_available_heads(memory)
            .map_err(|_| Error::Invalid("NIC TX ring holds an invalid descriptor head"))?;
    }
    Ok(())
}

/// Freeze the NIC worker at a descriptor boundary; None when inactive or
/// absent. A confirmed freeze writes no guest RAM, ring or interrupt.
pub(super) fn freeze(vm: &RamSnapshotVm) -> Result<Option<NetQueueStates>> {
    let Some(nic) = &vm.nic else {
        return Ok(None);
    };
    let net = nic.net.lock().unwrap();
    if !net.is_activated() {
        return Ok(None);
    }
    let handle = net
        .worker_control()
        .ok_or(Error::Invalid("activated NIC has no worker control"))?;
    handle
        .freeze()
        .map(Some)
        .map_err(|e| Error::Full(format!("freeze NIC: {e}")))
}

/// Capture the frozen, drained NIC from the cursors its freeze returned.
/// Worker-private buffers (deferred RX frame, partial backend frames,
/// unfinished TX writes) are deliberately not captured.
pub(super) fn capture(
    vm: &RamSnapshotVm,
    frozen: Option<&NetQueueStates>,
    disks: &[DiskMeta],
    regions: &[Region],
) -> Result<Option<NicMeta>> {
    let Some(nic) = &vm.nic else {
        return Ok(None);
    };
    let transport = nic.transport.lock().unwrap();
    let net = nic.net.lock().unwrap();
    let queues = match frozen {
        Some(states) => vec![states.rx.clone(), states.tx.clone()],
        None => transport.queue_states(),
    };
    let meta = NicMeta {
        mmio_addr: NIC_MMIO_ADDR,
        mmio_len: MMIO_LEN,
        irq: NIC_IRQ,
        device_id: net.id().to_string(),
        transport: transport.save_transport_state(),
        device: VirtioDeviceState {
            device_type: TYPE_NET,
            avail_features: net.avail_features(),
            acked_features: net.acked_features(),
            queues,
            activated: net.is_activated(),
        },
        mac: nic.mac,
        features: nic.features,
        config: net.config_bytes(),
    };
    validate_nic_metadata(&meta, disks, regions)?;
    validate_nic_rings(&meta, &vm.memory)?;
    Ok(Some(meta))
}

/// Resume the NIC worker; it re-examines its backend and both queues.
pub(super) fn resume(vm: &RamSnapshotVm) -> Result<()> {
    let Some(nic) = &vm.nic else {
        return Ok(());
    };
    match nic.net.lock().unwrap().worker_control() {
        Some(handle) => handle
            .resume()
            .map_err(|e| Error::Full(format!("resume NIC: {e}"))),
        None => Ok(()),
    }
}

/// Rebuild the NIC on the target VM at its fixed slot with new eventfds and
/// a fresh connection to `socket_path`. For an activated device, every TX
/// chain the source had not consumed at the cut is completed as dropped
/// BEFORE the worker exists, so no old frame can reach the new backend;
/// chains the source already used are never replayed and RX buffers stay
/// available. The completion interrupt is owed until
/// `signal_discarded_tx`, after the irqchip state is restored. The worker
/// starts frozen; on any failure it is stopped and joined.
pub(super) fn restore_nic(
    vm: &mut RamSnapshotVm,
    meta: &NicMeta,
    socket_path: &Path,
) -> Result<()> {
    check_socket_path(socket_path)?;
    let (net, transport) = new_device(
        vm,
        meta.device_id.clone(),
        socket_path,
        meta.mac,
        meta.features,
    )?;
    // Offered features and config were prevalidated against the attach
    // features and MAC this device was just built from.
    net.lock()
        .unwrap()
        .set_acked_features(meta.device.acked_features);
    let mut queues: Vec<Queue> = meta.device.queues.iter().map(|q| q.to_queue()).collect();
    let mut tx_discard_irq = false;
    if meta.device.activated {
        let discarded = queues[TX]
            .discard_available(&vm.memory)
            .map_err(|e| Error::Full(format!("discard cut-time NIC TX: {e:?}")))?;
        tx_discard_irq = discarded > 0
            && queues[TX]
                .needs_notification(&vm.memory)
                .map_err(|e| Error::Full(format!("NIC TX notification check: {e:?}")))?;
    }
    {
        let mut locked = transport.lock().unwrap();
        locked.restore_transport_state(&meta.transport, queues);
        if meta.device.activated {
            if let Err(error) = locked.activate_restored() {
                net.lock().unwrap().stop_worker();
                return Err(Error::Full(format!(
                    "restore-activate NIC (backend connect) failed: {error:?}"
                )));
            }
        }
    }
    if let Err(error) = wiring::register_device(vm, &transport, meta.mmio_addr, meta.irq) {
        net.lock().unwrap().stop_worker();
        return Err(error);
    }
    vm.nic = Some(NicDevice {
        net,
        transport,
        mac: meta.mac,
        features: meta.features,
        tx_discard_irq,
    });
    Ok(())
}

/// Raise the interrupt owed for TX chains a restore completed as dropped.
/// Must run after the VM irqchip state is restored (loading it would
/// otherwise overwrite the injection) and before any vCPU resumes.
pub(super) fn signal_discarded_tx(vm: &mut RamSnapshotVm) -> Result<()> {
    let Some(nic) = vm.nic.as_mut() else {
        return Ok(());
    };
    if !std::mem::take(&mut nic.tx_discard_irq) {
        return Ok(());
    }
    nic.transport
        .lock()
        .unwrap()
        .signal_used_queue()
        .map_err(|e| Error::Full(format!("signal discarded NIC TX: {e:?}")))
}

/// Stop and join the NIC worker, closing its backend connection.
pub(super) fn stop(vm: &RamSnapshotVm) {
    if let Some(nic) = &vm.nic {
        nic.net.lock().unwrap().stop_worker();
    }
}

#[cfg(test)]
mod kvm_tests;
#[cfg(test)]
mod tests;
