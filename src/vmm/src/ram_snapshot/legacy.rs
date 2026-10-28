// SPDX-License-Identifier: Apache-2.0

//! Internal legacy x86 devices of the private minimal-VM owner: the UARTs
//! COM1–COM4, CMOS and the i8042 on the owner's port-I/O bus. The snapshot
//! holds every UART register and its unread input, the CMOS index and all
//! 128 bytes, and the i8042 registers, last command and pending output in
//! read order. Host endpoints are never part of it: a restore takes fresh
//! ones, and output the source already sent is not replayed. The i8042
//! reset writes the owner's exit eventfd; a latched exit is never saved, so
//! a target never replays a reset.

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use devices::legacy::{Cmos, CmosState, I8042Device, I8042State, Serial, SerialState};
use serde::{Deserialize, Serialize};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

use super::wiring;
use super::{Error, RamSnapshotVm, Region, Result};

/// COM1–COM4 port bases and GSIs; COM1/COM3 share IRQ 4 and COM2/COM4
/// IRQ 3, as on the ordinary VMM.
const COM_PORTS: [(u64, u32, &str); 4] = [
    (0x3f8, 4, "COM1"),
    (0x2f8, 3, "COM2"),
    (0x3e8, 4, "COM3"),
    (0x2e8, 3, "COM4"),
];
const COM_LEN: u64 = 0x8;
const CMOS_PORT: u64 = 0x70;
const CMOS_LEN: u64 = 0x8;
const I8042_PORT: u64 = 0x60;
const I8042_LEN: u64 = 0x5;
const KEYBOARD_GSI: u32 = 1;
const FOUR_GIB: u64 = 1 << 32;

/// Host endpoints of COM1–COM4 in port order. Each must already be
/// nonblocking; a port without one is a sink.
pub(crate) type SerialEndpoints = [Option<UnixStream>; 4];

pub(super) struct Legacy {
    serials: Vec<Arc<Mutex<Serial>>>,
    /// The owner's clones of the UART interrupt eventfds, for the irqfds.
    com_evts: Vec<EventFd>,
    cmos: Arc<Mutex<Cmos>>,
    i8042: Arc<Mutex<I8042Device>>,
    keyboard_evt: EventFd,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyMeta {
    serial: Vec<SerialState>,
    cmos: CmosState,
    i8042: I8042State,
}

impl Legacy {
    /// Every legacy irqfd with its GSI, one per eventfd.
    pub(super) fn irqfds(&self) -> Vec<(&EventFd, u32, &'static str)> {
        let mut irqfds: Vec<_> = self
            .com_evts
            .iter()
            .zip(COM_PORTS)
            .map(|(evt, (_, irq, name))| (evt, irq, name))
            .collect();
        irqfds.push((&self.keyboard_evt, KEYBOARD_GSI, "i8042"));
        irqfds
    }

    /// The UARTs whose input the event thread reads.
    pub(super) fn serials(&self) -> Vec<Arc<Mutex<Serial>>> {
        self.serials.clone()
    }

    pub(super) fn dropped_output_bytes(&self) -> [u64; 4] {
        let mut dropped = [0; 4];
        for (count, serial) in dropped.iter_mut().zip(&self.serials) {
            *count = serial.lock().unwrap().dropped_output_bytes();
        }
        dropped
    }
}

/// Fail unless every endpoint is already nonblocking.
pub(super) fn check_endpoints(endpoints: &SerialEndpoints) -> Result<()> {
    for (stream, (_, _, name)) in endpoints.iter().zip(COM_PORTS) {
        if let Some(stream) = stream {
            Serial::check_snapshot_endpoint(stream)
                .map_err(|e| Error::Full(format!("{name} endpoint: {e}")))?;
        }
    }
    Ok(())
}

/// Attach before vCPUs start; a failure after the checks poisons the owner
/// for further snapshots.
pub(super) fn attach(vm: &mut RamSnapshotVm, endpoints: SerialEndpoints) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "devices cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid("devices attach only before vCPU start"));
    }
    if vm.legacy.is_some() {
        return Err(Error::Invalid("legacy devices are already attached"));
    }
    check_endpoints(&endpoints)?;
    let (below, above) = ram_split(memory_ranges(vm)?);
    let result =
        build(vm, endpoints, Cmos::new(below, above)).and_then(|legacy| install(vm, legacy));
    if result.is_err() {
        vm.control.unusable = true;
    }
    result
}

fn memory_ranges(vm: &RamSnapshotVm) -> Result<Vec<(u64, u64)>> {
    // CMOS describes boot RAM; virtio-mem advertises its own reservation.
    Ok(vm.boot_memory()?
        .iter()
        .map(|region| (region.start_addr().raw_value(), region.len()))
        .collect())
}

/// RAM bytes below and above 4 GiB, as the CMOS reports them.
fn ram_split(ranges: impl IntoIterator<Item = (u64, u64)>) -> (u64, u64) {
    ranges
        .into_iter()
        .fold((0, 0), |(below, above), (gpa, len)| {
            let low = (gpa + len).min(FOUR_GIB).saturating_sub(gpa.min(FOUR_GIB));
            (below + low, above + len - low)
        })
}

fn build(vm: &RamSnapshotVm, endpoints: SerialEndpoints, cmos: Cmos) -> Result<Legacy> {
    let mut serials = Vec::with_capacity(COM_PORTS.len());
    let mut com_evts = Vec::with_capacity(COM_PORTS.len());
    for (stream, (_, _, name)) in endpoints.into_iter().zip(COM_PORTS) {
        let evt = EventFd::new(EFD_NONBLOCK)?;
        let serial = Serial::new_snapshot(evt.try_clone()?, stream)
            .map_err(|e| Error::Full(format!("create {name}: {e}")))?;
        serials.push(Arc::new(Mutex::new(serial)));
        com_evts.push(evt);
    }
    let keyboard_evt = EventFd::new(EFD_NONBLOCK)?;
    let i8042 = I8042Device::new(vm.exit.notifier()?, keyboard_evt.try_clone()?);
    Ok(Legacy {
        serials,
        com_evts,
        cmos: Arc::new(Mutex::new(cmos)),
        i8042: Arc::new(Mutex::new(i8042)),
        keyboard_evt,
    })
}

/// Register the irqfds (rolled back on failure), then put every device on
/// the port-I/O bus. The owner keeps the devices from here on.
fn install(vm: &mut RamSnapshotVm, legacy: Legacy) -> Result<()> {
    vm.setup_irqchip()?;
    wiring::register_irqfds(vm, &legacy.irqfds())?;
    let mut devices: Vec<(Arc<Mutex<dyn devices::BusDevice>>, u64, u64)> = legacy
        .serials
        .iter()
        .zip(COM_PORTS)
        .map(|(serial, (base, _, _))| (serial.clone() as _, base, COM_LEN))
        .collect();
    devices.push((legacy.cmos.clone(), CMOS_PORT, CMOS_LEN));
    devices.push((legacy.i8042.clone(), I8042_PORT, I8042_LEN));
    // Whatever fails here, the irqfds stay with the owner and the VM fd.
    vm.legacy = Some(legacy);
    for (device, base, len) in devices {
        vm.io_bus
            .insert(device, base, len)
            .map_err(|e| Error::Full(format!("insert legacy device at port {base:#x}: {e:?}")))?;
    }
    Ok(())
}

/// Capture while vCPUs are paused and UART input is frozen.
pub(super) fn capture(vm: &RamSnapshotVm, regions: &[Region]) -> Result<Option<LegacyMeta>> {
    let Some(legacy) = &vm.legacy else {
        return Ok(None);
    };
    let meta = LegacyMeta {
        serial: legacy
            .serials
            .iter()
            .map(|serial| serial.lock().unwrap().snapshot_state())
            .collect(),
        cmos: legacy.cmos.lock().unwrap().snapshot_state(),
        i8042: legacy.i8042.lock().unwrap().snapshot_state(),
    };
    validate_metadata(&meta, regions)?;
    Ok(Some(meta))
}

/// Metadata-only validation, before guest RAM or any target resource exists.
pub(super) fn validate_metadata(meta: &LegacyMeta, regions: &[Region]) -> Result<()> {
    let invalid = |why: &str| Error::Full(format!("legacy devices: {why}"));
    if meta.serial.len() != COM_PORTS.len() {
        return Err(invalid("the image must hold exactly four UARTs"));
    }
    for state in &meta.serial {
        state.validate().map_err(invalid)?;
    }
    let (below, above) = ram_split(regions.iter().map(|r| (r.gpa, r.len)));
    meta.cmos.validate(below, above).map_err(invalid)?;
    meta.i8042.validate().map_err(invalid)
}

/// Rebuild validated legacy devices with fresh endpoints and eventfds.
pub(super) fn restore(
    vm: &mut RamSnapshotVm,
    meta: &LegacyMeta,
    endpoints: SerialEndpoints,
) -> Result<()> {
    let invalid = |why: &str| Error::Full(format!("restore legacy devices: {why}"));
    let (below, above) = ram_split(memory_ranges(vm)?);
    let cmos = Cmos::from_snapshot_state(&meta.cmos, below, above).map_err(invalid)?;
    let legacy = build(vm, endpoints, cmos)?;
    for (serial, state) in legacy.serials.iter().zip(&meta.serial) {
        serial
            .lock()
            .unwrap()
            .restore_snapshot_state(state)
            .map_err(invalid)?;
    }
    legacy
        .i8042
        .lock()
        .unwrap()
        .restore_snapshot_state(&meta.i8042)
        .map_err(|e| Error::Full(format!("restore legacy devices: {e}")))?;
    install(vm, legacy)
}

#[cfg(test)]
mod tests;
