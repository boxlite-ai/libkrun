// SPDX-License-Identifier: Apache-2.0

//! Internal virtio-console checkpoints for the private minimal-VM owner: one
//! multiport console whose ports use only built-in endpoints (FD, empty and
//! SIGINT input, FD and log output, FD and fixed-size terminals); a custom
//! endpoint is rejected before the attach has any effect.
//!
//! The console's control queues run on the owner's event thread and each
//! opened port has its own RX and TX workers. A pause freezes the event
//! thread first, then every port worker with a confirmed control: RX stops
//! at a chain boundary, TX keeps a partly delivered chain and its exact
//! delivered offset. Until resume nothing writes guest RAM, a ring or an
//! interrupt, and no endpoint is read or written, so every export captures
//! the same state. A resume reattaches the irqfds, resumes the workers and
//! processes the control queues itself (no kick needed), then the event
//! thread and the vCPUs.
//!
//! The image keeps the transport, the queues, the config space, each port's
//! name, endpoint kinds, guest handshake, terminal size, EOF and in-flight
//! TX offset, the pending control messages and a log port's unfinished
//! line. It never holds a host path or descriptor: an import takes fresh
//! endpoints of the same kinds from its caller, and input still unread in
//! the source's host descriptors is not migrated. Bytes the source's output
//! accepted are never written again.

use std::sync::{Arc, Mutex};

use devices::virtio::persist::{MmioTransportState, QueueState, VirtioDeviceState};
use devices::virtio::{
    console_num_queues, Console, ConsoleState, MmioTransport, PortDescription, VirtioDevice,
    CONSOLE_FEATURES, CONSOLE_QUEUE_SIZE, TYPE_CONSOLE,
};
use serde::{Deserialize, Serialize};
use vm_memory::GuestMemoryMmap;

use super::wiring::{self, MMIO_LEN};
use super::{Error, RamSnapshotVm, Region, Result};

/// After the vsock slot, with the next legacy-range GSI.
pub(super) const CONSOLE_MMIO_ADDR: u64 = 0xd000_c000;
pub(super) const CONSOLE_IRQ: u32 = 8;
/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;

/// The console attached to the minimal VM owner.
pub(super) struct ConsoleDevice {
    device: Arc<Mutex<Console>>,
    transport: Arc<Mutex<MmioTransport>>,
}

/// Console snapshot metadata. No host path or descriptor appears here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsoleMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
    pub(super) console: ConsoleState,
}

/// The console's (transport, MMIO address, GSI) for the shared wiring.
pub(super) fn slot(console: &ConsoleDevice) -> (&Arc<Mutex<MmioTransport>>, u64, u32) {
    (&console.transport, CONSOLE_MMIO_ADDR, CONSOLE_IRQ)
}

/// `GuestMemoryMmap` clones the console legitimately holds: the transport,
/// the device state once activated, and every running port worker (one per
/// direction with an endpoint).
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    vm.console.as_ref().map_or(0, |console| {
        1 + console.device.lock().unwrap().memory_clones()
    })
}

/// At least one port, and every queue index (two control queues plus two
/// per port) fits the 32-bit queue select and notify registers.
fn check_port_count(count: usize) -> Result<()> {
    if count == 0 || count > (u32::MAX as usize - 2) / 2 {
        return Err(Error::Invalid(
            "console port count is zero or exceeds the queue index range",
        ));
    }
    Ok(())
}

/// At least one description, each using only built-in endpoints; checked
/// before the attach creates anything.
fn check_descriptions(ports: &[PortDescription]) -> Result<()> {
    check_port_count(ports.len())?;
    for (port, port_id) in ports.iter().zip(0u32..) {
        port.check_snapshot_support(port_id)
            .map_err(|e| Error::Full(e.to_string()))?;
    }
    Ok(())
}

type Parts = (Arc<Mutex<Console>>, Arc<Mutex<MmioTransport>>);

fn new_device(vm: &mut RamSnapshotVm, ports: Vec<PortDescription>) -> Result<Parts> {
    let ioapic = vm.ensure_kernel_irqchip()?;
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(ioapic),
    )));
    build(vm.memory.clone(), intc, ports)
}

/// The device and its transport over `memory`, before any wiring.
fn build(
    memory: GuestMemoryMmap,
    intc: devices::legacy::IrqChip,
    ports: Vec<PortDescription>,
) -> Result<Parts> {
    let console = Console::new(ports).map_err(|e| Error::Full(format!("create console: {e:?}")))?;
    let device = Arc::new(Mutex::new(console));
    let transport = Arc::new(Mutex::new(
        MmioTransport::new(memory, intc, device.clone())
            .map_err(|e| Error::Full(format!("create console transport: {e}")))?,
    ));
    Ok((device, transport))
}

/// Attach the single internal console before vCPUs start; its port workers
/// start when the guest opens each port. Any failure after the checks
/// poisons the owner for further snapshots.
pub(super) fn attach(vm: &mut RamSnapshotVm, ports: Vec<PortDescription>) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "the internal console cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid(
            "the internal console attaches only before vCPU start",
        ));
    }
    if vm.console.is_some() {
        return Err(Error::Invalid("the internal console is already attached"));
    }
    check_descriptions(&ports)?;
    let attached = (|| {
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let (device, transport) = new_device(vm, ports)?;
        wiring::register_device(vm, &transport, CONSOLE_MMIO_ADDR, CONSOLE_IRQ)?;
        Ok(ConsoleDevice { device, transport })
    })();
    match attached {
        Ok(console) => {
            vm.console = Some(console);
            Ok(())
        }
        Err(error) => {
            vm.control.unusable = true;
            Err(error)
        }
    }
}

/// Freeze the control queues and every port worker, after the vCPUs paused
/// and the event thread froze; an unconfirmed worker fails the pause.
pub(super) fn freeze(vm: &RamSnapshotVm) -> Result<()> {
    let Some(console) = &vm.console else {
        return Ok(());
    };
    console
        .device
        .lock()
        .unwrap()
        .snapshot_freeze()
        .map_err(|e| Error::Full(format!("freeze console: {e}")))
}

/// Resume every port worker and process the control queues, before the
/// event thread and the vCPUs resume.
pub(super) fn resume(vm: &RamSnapshotVm) -> Result<()> {
    let Some(console) = &vm.console else {
        return Ok(());
    };
    console
        .device
        .lock()
        .unwrap()
        .snapshot_resume()
        .map_err(|e| Error::Full(format!("resume console: {e}")))
}

/// Stop and join every port worker on teardown, after the event and vCPU
/// threads; bounded even under output backpressure or while frozen.
pub(super) fn teardown(vm: &RamSnapshotVm) {
    if let Some(console) = &vm.console {
        console.device.lock().unwrap().reset();
    }
}

/// Metadata-only validation, before guest RAM or any target resource exists.
pub(super) fn validate_metadata(meta: &ConsoleMeta, regions: &[Region]) -> Result<()> {
    let invalid = |why: &str| Error::Full(format!("console: {why}"));
    if meta.mmio_addr != CONSOLE_MMIO_ADDR || meta.mmio_len != MMIO_LEN || meta.irq != CONSOLE_IRQ {
        return Err(invalid("MMIO/IRQ is outside its internal slot"));
    }
    wiring::check_window(meta.mmio_addr, regions.iter().map(|r| (r.gpa, r.len)))?;
    let ports = meta.console.ports.len();
    check_port_count(ports)?;
    if meta.device.avail_features != CONSOLE_FEATURES {
        return Err(invalid(
            "offered features differ from the internal contract",
        ));
    }
    meta.transport
        .validate()
        .map_err(|_| invalid("transport registers are outside the state machine"))?;
    meta.device
        .validate_structure(TYPE_CONSOLE, console_num_queues(ports), CONSOLE_QUEUE_SIZE)
        .map_err(|_| invalid("virtio state is structurally inconsistent"))?;
    if (meta.transport.device_status & DRIVER_OK != 0) != meta.device.activated {
        return Err(invalid("activation disagrees with the transport status"));
    }
    meta.console
        .validate_structure(meta.device.activated)
        .map_err(|e| Error::Full(e.to_string()))
}

/// The caller's ordered descriptions must match the image's ports: names,
/// directions and the input, output and terminal kinds.
pub(super) fn check_resources(meta: &ConsoleMeta, ports: &[PortDescription]) -> Result<()> {
    meta.console
        .validate_descriptions(ports, meta.device.activated)
        .map_err(|e| Error::Full(format!("restore resources: {e}")))
}

/// Ring validation against the loaded guest RAM: every ready queue of an
/// activated device (a driver may leave a port's queues unready), every
/// available chain and every in-flight TX chain with its offset.
pub(super) fn validate_rings(meta: &ConsoleMeta, memory: &GuestMemoryMmap) -> Result<()> {
    let ports = meta.console.ports.len();
    meta.device
        .validate_ready_queues(
            memory,
            TYPE_CONSOLE,
            console_num_queues(ports),
            CONSOLE_QUEUE_SIZE,
        )
        .map_err(|e| Error::Full(format!("console virtio state: {e}")))?;
    meta.console
        .validate_guest(memory, &meta.device.queues, meta.device.activated)
        .map_err(|e| Error::Full(e.to_string()))
}

/// Capture the frozen console while the vCPUs are paused, the event thread
/// and the port workers frozen and the irqfds drained. Pure: it reads only
/// the cut the freeze confirmed, so repeated exports are equal.
pub(super) fn capture(vm: &RamSnapshotVm, regions: &[Region]) -> Result<Option<ConsoleMeta>> {
    let Some(console) = &vm.console else {
        return Ok(None);
    };
    let transport = console.transport.lock().unwrap();
    let device = console.device.lock().unwrap();
    capture_device(&transport, &device, &vm.memory, regions).map(Some)
}

fn capture_device(
    transport: &MmioTransport,
    device: &Console,
    memory: &GuestMemoryMmap,
    regions: &[Region],
) -> Result<ConsoleMeta> {
    let frozen = |e: devices::virtio::SnapshotError| Error::Full(format!("console: {e}"));
    // Inactive devices leave their queues with the transport.
    let queues = match device.snapshot_queue_states().map_err(frozen)? {
        Some(queues) => queues,
        None => transport.queue_states(),
    };
    let meta = ConsoleMeta {
        mmio_addr: CONSOLE_MMIO_ADDR,
        mmio_len: MMIO_LEN,
        irq: CONSOLE_IRQ,
        transport: transport.save_transport_state(),
        device: VirtioDeviceState {
            device_type: TYPE_CONSOLE,
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues,
            activated: device.is_activated(),
        },
        console: device.snapshot_state().map_err(frozen)?,
    };
    validate_metadata(&meta, regions)?;
    validate_rings(&meta, memory)?;
    Ok(meta)
}

/// Rebuild the validated console at its fixed slot with new eventfds and
/// the caller's fresh endpoints, without endpoint I/O or a new handshake.
/// Saved open ports come back with frozen workers that continue from the
/// saved EOF and TX offsets once resumed.
pub(super) fn restore(
    vm: &mut RamSnapshotVm,
    meta: &ConsoleMeta,
    ports: Vec<PortDescription>,
) -> Result<()> {
    let (device, transport) = new_device(vm, ports)?;
    let restored = restore_parts(&device, &transport, meta)
        .and_then(|()| wiring::register_device(vm, &transport, meta.mmio_addr, meta.irq));
    if let Err(error) = restored {
        discard(&device);
        return Err(error);
    }
    vm.console = Some(ConsoleDevice { device, transport });
    Ok(())
}

/// A restore failed after the device may have started workers: stop and
/// join them (frozen or not, bounded even with a full output) so they
/// release guest RAM before the error is reported.
fn discard(device: &Arc<Mutex<Console>>) {
    device.lock().unwrap().reset();
}

/// Adopt the saved device, transport and queue state; an activated device
/// is restore-activated with its saved open ports' workers frozen.
fn restore_parts(
    device: &Arc<Mutex<Console>>,
    transport: &Arc<Mutex<MmioTransport>>,
    meta: &ConsoleMeta,
) -> Result<()> {
    {
        let mut locked = device.lock().unwrap();
        locked.set_acked_features(meta.device.acked_features);
        locked
            .restore_state(&meta.console, meta.device.activated)
            .map_err(|e| Error::Full(format!("restore console state: {e}")))?;
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
                .map_err(|e| Error::Full(format!("restore-activate console: {e:?}")))?;
        }
    }
    Ok(())
}

/// The device the event thread dispatches (control queues, activation).
pub(super) fn event_device(vm: &RamSnapshotVm) -> Option<Arc<Mutex<Console>>> {
    vm.console.as_ref().map(|console| console.device.clone())
}

#[cfg(test)]
mod kvm_tests;
#[cfg(test)]
pub(super) mod tests;
