// SPDX-License-Identifier: Apache-2.0

//! KVM and bus wiring shared by every internal device of the private
//! minimal-VM owner: fixed-slot collision checks, ioeventfd/irqfd
//! registration with rollback, and the irqfd drain/reassign pair around a
//! capture, covering MMIO devices and the legacy UART/keyboard lines. Each
//! device keeps its own fixed slot and state handling.

use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use devices::virtio::MmioTransport;
use kvm_ioctls::IoEventAddress;
use utils::eventfd::EventFd;
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

use super::{Error, RamSnapshotVm, Result};

/// Every internal device occupies one 4 KiB MMIO slot.
pub(super) const MMIO_LEN: u64 = 0x1000;

/// Reject an MMIO slot that overlaps any guest RAM range `(gpa, len)`.
pub(super) fn check_window(
    mmio_addr: u64,
    ram: impl IntoIterator<Item = (u64, u64)>,
) -> Result<()> {
    for (gpa, len) in ram {
        if mmio_addr < gpa + len && gpa < mmio_addr + MMIO_LEN {
            return Err(Error::Invalid("device MMIO slot overlaps guest RAM"));
        }
    }
    Ok(())
}

/// Reject a slot whose window overlaps guest RAM or whose address or GSI is
/// already taken by an attached device; GSIs are never shared.
fn check_slot(vm: &RamSnapshotVm, mmio_addr: u64, irq: u32) -> Result<()> {
    check_window(
        mmio_addr,
        vm.memory
            .iter()
            .map(|region| (region.start_addr().raw_value(), region.len())),
    )?;
    let taken = vm.mmio_devices().into_iter().any(|(_, addr, used_irq)| {
        used_irq == irq || (mmio_addr < addr + MMIO_LEN && addr < mmio_addr + MMIO_LEN)
    });
    if taken {
        return Err(Error::Invalid(
            "device MMIO slot or GSI conflicts with another device",
        ));
    }
    Ok(())
}

/// Register ioeventfd/irqfd at a fixed address and IRQ and put the transport
/// on the bus. On failure every registration made here is rolled back.
pub(super) fn register_device(
    vm: &mut RamSnapshotVm,
    transport: &Arc<Mutex<MmioTransport>>,
    mmio_addr: u64,
    irq: u32,
) -> Result<()> {
    check_slot(vm, mmio_addr, irq)?;
    let locked = transport.lock().unwrap();
    let io_addr = IoEventAddress::Mmio(mmio_addr + u64::from(devices::virtio::NOTIFY_REG_OFFSET));
    let registration = (|| -> Result<()> {
        for (queue, queue_evt) in locked.queue_evts().iter().enumerate() {
            vm.vm
                .fd()
                .register_ioevent(queue_evt, &io_addr, queue as u32)
                .map_err(|e| Error::Full(format!("register ioeventfd: {e}")))?;
        }
        vm.vm
            .fd()
            .register_irqfd(locked.interrupt_evt(), irq)
            .map_err(|e| Error::Full(format!("register irqfd: {e}")))?;
        Ok(())
    })();
    if let Err(error) = registration {
        rollback_registrations(vm, &locked, &io_addr, irq);
        return Err(error);
    }
    drop(locked);
    vm.bus
        .insert(
            Arc::clone(transport) as Arc<Mutex<dyn devices::BusDevice>>,
            mmio_addr,
            MMIO_LEN,
        )
        .map_err(|e| {
            // Roll the registrations back so the owner holds nothing of
            // this device.
            let locked = transport.lock().unwrap();
            rollback_registrations(vm, &locked, &io_addr, irq);
            Error::Full(format!("insert device on MMIO bus: {e:?}"))
        })
}

/// Undo every KVM registration of one device; best effort by design. The
/// transport is borrowed through the caller's existing guard: no relock.
fn rollback_registrations(
    vm: &RamSnapshotVm,
    transport: &MmioTransport,
    io_addr: &IoEventAddress,
    irq: u32,
) {
    for (queue, queue_evt) in transport.queue_evts().iter().enumerate() {
        let _ = vm
            .vm
            .fd()
            .unregister_ioevent(queue_evt, io_addr, queue as u32);
    }
    let _ = vm.vm.fd().unregister_irqfd(transport.interrupt_evt(), irq);
}

/// Call `each` with every irqfd the owner registered and its GSI, in a
/// fixed order: MMIO devices, then the legacy UARTs and keyboard. Stops at
/// the first error.
fn for_each_irqfd(
    vm: &RamSnapshotVm,
    mut each: impl FnMut(&EventFd, u32, String) -> Result<()>,
) -> Result<()> {
    for (transport, mmio_addr, irq) in vm.mmio_devices() {
        let transport = transport.lock().unwrap();
        each(transport.interrupt_evt(), irq, format!("{mmio_addr:#x}"))?;
    }
    if let Some(legacy) = &vm.legacy {
        for (evt, irq, name) in legacy.irqfds() {
            each(evt, irq, name.to_owned())?;
        }
    }
    Ok(())
}

/// Register the given irqfds; on failure every one registered here is
/// unregistered again.
pub(super) fn register_irqfds(vm: &RamSnapshotVm, irqfds: &[(&EventFd, u32, &str)]) -> Result<()> {
    for (index, (evt, irq, name)) in irqfds.iter().enumerate() {
        if let Err(e) = vm.vm.fd().register_irqfd(evt, *irq) {
            for (evt, irq, _) in &irqfds[..index] {
                let _ = vm.vm.fd().unregister_irqfd(evt, *irq);
            }
            return Err(Error::Full(format!("register {name} irqfd: {e}")));
        }
    }
    Ok(())
}

/// Deassign every irqfd and drain its count. KVM_IRQFD DEASSIGN flushes the
/// injection workqueue before returning (Linux v6.12 virt/kvm/eventfd.c
/// contract), so each device's interrupt state includes every completed
/// injection afterwards and an injected interrupt lives only in the KVM
/// irqchip state: nothing is replayed. `drained` counts the deassigned
/// irqfds in `for_each_irqfd` order even on failure, so recovery reassigns
/// exactly those. Shared GSIs (COM1/COM3, COM2/COM4) have one irqfd per
/// UART.
pub(super) fn drain_irqfds(vm: &RamSnapshotVm, drained: &mut usize) -> Result<()> {
    for_each_irqfd(vm, |evt, irq, name| {
        vm.vm
            .fd()
            .unregister_irqfd(evt, irq)
            .map_err(|e| Error::Full(format!("deassign irqfd of {name}: {e}")))?;
        *drained += 1;
        drain_eventfd_count(evt);
        Ok(())
    })
}

/// Reassign the first `drained` irqfds; a single failure must not skip the
/// rest.
pub(super) fn reassign_irqfds(vm: &RamSnapshotVm, drained: usize) -> Result<()> {
    let mut first = None;
    let mut index = 0;
    let _ = for_each_irqfd(vm, |evt, irq, name| {
        if index < drained {
            if let Err(e) = vm.vm.fd().register_irqfd(evt, irq) {
                first.get_or_insert(Error::Full(format!("reassign irqfd of {name}: {e}")));
            }
        }
        index += 1;
        Ok(())
    });
    first.map_or(Ok(()), Err)
}

/// Whether `fd` is readable now, without blocking or consuming.
pub(super) fn is_readable(fd: &EventFd) -> bool {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pollfd` is exclusively borrowed for the duration of the call.
    let ready = unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, 0) };
    ready > 0 && pollfd.revents & libc::POLLIN != 0
}

/// Read the current eventfd count without blocking, if any.
pub(super) fn drain_eventfd_count(fd: &EventFd) {
    if is_readable(fd) {
        let _ = fd.read();
    }
}
