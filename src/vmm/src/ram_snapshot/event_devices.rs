// SPDX-License-Identifier: Apache-2.0

//! Internal virtio RNG and balloon checkpoints for the private minimal-VM
//! owner. Both devices run on the owner's event thread (`events`); their
//! snapshot is the common virtio/MMIO state, activation and queues, plus the
//! complete balloon configuration space. Randomness and reclaimed pages are
//! never part of it: a restored RNG draws fresh randomness.

use std::sync::{Arc, Mutex};

use devices::virtio::persist::{MmioTransportState, QueueState, VirtioDeviceState};
use devices::virtio::{
    Balloon, MmioTransport, Rng, VirtioDevice, BALLOON_CONFIG_LEN, BALLOON_FEATURES,
    BALLOON_NUM_QUEUES, BALLOON_QUEUE_SIZE, RNG_FEATURES, RNG_NUM_QUEUES, RNG_QUEUE_SIZE,
    TYPE_BALLOON, TYPE_RNG,
};
use serde::{Deserialize, Serialize};
use vm_memory::GuestMemoryMmap;

use super::events::EventDevice;
use super::wiring::{self, MMIO_LEN};
use super::{Error, RamSnapshotVm, Region, Result};

/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;

/// Fixed slot and virtio contract of one device kind. The slots sit after
/// the disk/NIC window and use legacy-range GSIs, leaving 16–23 to disks.
struct Kind {
    name: &'static str,
    mmio_addr: u64,
    irq: u32,
    device_type: u32,
    features: u64,
    queues: usize,
    queue_size: u16,
}

const RNG: Kind = Kind {
    name: "RNG",
    mmio_addr: 0xd000_9000,
    irq: 5,
    device_type: TYPE_RNG,
    features: RNG_FEATURES,
    queues: RNG_NUM_QUEUES,
    queue_size: RNG_QUEUE_SIZE,
};

const BALLOON: Kind = Kind {
    name: "balloon",
    mmio_addr: 0xd000_a000,
    irq: 6,
    device_type: TYPE_BALLOON,
    features: BALLOON_FEATURES,
    queues: BALLOON_NUM_QUEUES,
    queue_size: BALLOON_QUEUE_SIZE,
};

/// Transport and virtio state of an RNG or balloon. No host resource
/// appears here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeviceMeta {
    mmio_addr: u64,
    mmio_len: u64,
    irq: u32,
    transport: MmioTransportState,
    device: VirtioDeviceState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BalloonMeta {
    slot: DeviceMeta,
    /// The complete guest-visible configuration space.
    config: Vec<u8>,
}

pub(super) fn attach_rng(vm: &mut RamSnapshotVm) -> Result<()> {
    let already_attached = vm.rng.is_some();
    let attached = attach(vm, &RNG, already_attached, || {
        Rng::new().map_err(|e| Error::Full(format!("create RNG: {e:?}")))
    })?;
    vm.rng = Some(attached);
    Ok(())
}

pub(super) fn attach_balloon(vm: &mut RamSnapshotVm) -> Result<()> {
    let already_attached = vm.balloon.is_some();
    let attached = attach(vm, &BALLOON, already_attached, || {
        Balloon::new().map_err(|e| Error::Full(format!("create balloon: {e:?}")))
    })?;
    vm.balloon = Some(attached);
    Ok(())
}

/// Attach before vCPUs start; a failure after the checks poisons the owner
/// for further snapshots.
fn attach<D: VirtioDevice + 'static>(
    vm: &mut RamSnapshotVm,
    kind: &Kind,
    already_attached: bool,
    create: impl FnOnce() -> Result<D>,
) -> Result<EventDevice<D>> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "devices cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid("devices attach only before vCPU start"));
    }
    if already_attached {
        return Err(Error::Full(format!(
            "the internal {} is already attached",
            kind.name
        )));
    }
    let result = (|| {
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let device = Arc::new(Mutex::new(create()?));
        let transport = new_transport(vm, &device)?;
        wiring::register_device(vm, &transport, kind.mmio_addr, kind.irq)?;
        Ok(EventDevice {
            device,
            transport,
            mmio_addr: kind.mmio_addr,
            irq: kind.irq,
        })
    })();
    if result.is_err() {
        vm.control.unusable = true;
    }
    result
}

fn new_transport<D: VirtioDevice + 'static>(
    vm: &mut RamSnapshotVm,
    device: &Arc<Mutex<D>>,
) -> Result<Arc<Mutex<MmioTransport>>> {
    let ioapic = vm.ensure_kernel_irqchip()?;
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(ioapic),
    )));
    let transport = MmioTransport::new(vm.memory.clone(), intc, device.clone())
        .map_err(|e| Error::Full(format!("create device transport: {e}")))?;
    Ok(Arc::new(Mutex::new(transport)))
}

/// `GuestMemoryMmap` clones these devices really hold: each transport one,
/// plus the activated device state. Callbacks borrow the device's mapping
/// and the event thread holds none.
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    fn holders<D: VirtioDevice>(attached: &Option<EventDevice<D>>) -> usize {
        attached.as_ref().map_or(0, |attached| {
            1 + usize::from(attached.device.lock().unwrap().is_activated())
        })
    }
    holders(&vm.rng) + holders(&vm.balloon)
}

/// Metadata-only validation, before guest RAM or any target resource exists.
pub(super) fn validate_metadata(
    rng: Option<&DeviceMeta>,
    balloon: Option<&BalloonMeta>,
    regions: &[Region],
) -> Result<()> {
    if let Some(rng) = rng {
        validate_slot(&RNG, rng, regions)?;
    }
    if let Some(balloon) = balloon {
        validate_slot(&BALLOON, &balloon.slot, regions)?;
        if balloon.config.len() != BALLOON_CONFIG_LEN {
            return Err(Error::Invalid("balloon config has an unsupported length"));
        }
    }
    Ok(())
}

fn validate_slot(kind: &Kind, meta: &DeviceMeta, regions: &[Region]) -> Result<()> {
    let invalid = |why: &str| Error::Full(format!("{}: {why}", kind.name));
    if meta.mmio_addr != kind.mmio_addr || meta.mmio_len != MMIO_LEN || meta.irq != kind.irq {
        return Err(invalid("MMIO/IRQ is outside its internal slot"));
    }
    wiring::check_window(meta.mmio_addr, regions.iter().map(|r| (r.gpa, r.len)))?;
    if meta.device.avail_features != kind.features {
        return Err(invalid(
            "offered features differ from the internal contract",
        ));
    }
    meta.transport
        .validate()
        .map_err(|_| invalid("transport registers are outside the state machine"))?;
    meta.device
        .validate_structure(kind.device_type, kind.queues, kind.queue_size)
        .map_err(|_| invalid("virtio state is structurally inconsistent"))?;
    if (meta.transport.device_status & DRIVER_OK != 0) != meta.device.activated {
        return Err(invalid("activation disagrees with the transport status"));
    }
    Ok(())
}

/// Ring validation against the loaded guest RAM. The transport activates
/// without requiring every queue, so unready optional queues are allowed.
pub(super) fn validate_rings(
    rng: Option<&DeviceMeta>,
    balloon: Option<&BalloonMeta>,
    memory: &GuestMemoryMmap,
) -> Result<()> {
    let slots = [
        (&RNG, rng),
        (&BALLOON, balloon.map(|balloon| &balloon.slot)),
    ];
    for (kind, meta) in slots {
        let Some(meta) = meta else { continue };
        meta.device
            .validate_ready_queues(memory, kind.device_type, kind.queues, kind.queue_size)
            .map_err(|e| Error::Full(format!("{} virtio state: {e}", kind.name)))?;
    }
    Ok(())
}

/// Capture both devices while the event thread is frozen and the irqfds are
/// drained.
pub(super) fn capture(
    vm: &RamSnapshotVm,
    regions: &[Region],
) -> Result<(Option<DeviceMeta>, Option<BalloonMeta>)> {
    let rng = vm
        .rng
        .as_ref()
        .map(|rng| capture_slot(&RNG, rng, |device: &Rng| device.snapshot_queue_states()));
    let balloon = vm.balloon.as_ref().map(|balloon| BalloonMeta {
        slot: capture_slot(&BALLOON, balloon, |device: &Balloon| {
            device.snapshot_queue_states()
        }),
        config: balloon.device.lock().unwrap().snapshot_config(),
    });
    validate_metadata(rng.as_ref(), balloon.as_ref(), regions)?;
    validate_rings(rng.as_ref(), balloon.as_ref(), &vm.memory)?;
    Ok((rng, balloon))
}

fn capture_slot<D: VirtioDevice>(
    kind: &Kind,
    attached: &EventDevice<D>,
    device_queues: impl FnOnce(&D) -> Option<Vec<QueueState>>,
) -> DeviceMeta {
    let transport = attached.transport.lock().unwrap();
    let device = attached.device.lock().unwrap();
    // Inactive devices leave their queues with the transport.
    let queues = device_queues(&device).unwrap_or_else(|| transport.queue_states());
    DeviceMeta {
        mmio_addr: kind.mmio_addr,
        mmio_len: MMIO_LEN,
        irq: kind.irq,
        transport: transport.save_transport_state(),
        device: VirtioDeviceState {
            device_type: kind.device_type,
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues,
            activated: device.is_activated(),
        },
    }
}

/// Rebuild validated devices at their saved slots with new eventfds. They
/// process nothing until the restored event thread resumes.
pub(super) fn restore(
    vm: &mut RamSnapshotVm,
    rng: Option<&DeviceMeta>,
    balloon: Option<&BalloonMeta>,
) -> Result<()> {
    if let Some(meta) = rng {
        let device = Rng::new().map_err(|e| Error::Full(format!("create RNG: {e:?}")))?;
        vm.rng = Some(restore_slot(vm, &RNG, meta, device)?);
    }
    if let Some(meta) = balloon {
        let mut device =
            Balloon::new().map_err(|e| Error::Full(format!("create balloon: {e:?}")))?;
        device
            .restore_snapshot_config(&meta.config)
            .map_err(|e| Error::Full(format!("restore balloon config: {e:?}")))?;
        vm.balloon = Some(restore_slot(vm, &BALLOON, &meta.slot, device)?);
    }
    Ok(())
}

fn restore_slot<D: VirtioDevice + 'static>(
    vm: &mut RamSnapshotVm,
    kind: &Kind,
    meta: &DeviceMeta,
    mut device: D,
) -> Result<EventDevice<D>> {
    device.set_acked_features(meta.device.acked_features);
    let device = Arc::new(Mutex::new(device));
    let transport = new_transport(vm, &device)?;
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
                .map_err(|e| Error::Full(format!("restore-activate {}: {e:?}", kind.name)))?;
        }
    }
    wiring::register_device(vm, &transport, meta.mmio_addr, meta.irq)?;
    Ok(EventDevice {
        device,
        transport,
        mmio_addr: meta.mmio_addr,
        irq: meta.irq,
    })
}

#[cfg(test)]
mod tests;
