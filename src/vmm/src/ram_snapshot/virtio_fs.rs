// SPDX-License-Identifier: Apache-2.0

//! Internal virtio-fs checkpoints for the private minimal-VM owner: up to
//! seven snapshot-mode passthrough shares, share `i` at the fixed MMIO slot
//! `0xd000_d000 + i * 4 KiB` and GSI `9 + i`, each with an optional DAX
//! window.
//!
//! A DAX window is private anonymous memory the owner maps itself and
//! registers as one more KVM memslot at the window's guest address, counted
//! against the target's memslot capacity. It is not guest RAM: the RAM
//! image, the RAM alias probe and every ring validation see only the
//! `GuestMemoryMmap`, so a ring placed in a DAX window is refused. A window
//! may not overlap RAM, any attached device's MMIO slot, another window or
//! an architectural window KVM serves (identity map and TSS, IOAPIC, local
//! APIC), whichever is attached first. The owner keeps every window it
//! mapped, also one of a failed attach or import, until it drops, after
//! its VM fd closed. A device that leaves its window (`Fs::retire`) names
//! the ranges a failed `mmap(MAP_FIXED)` may have unmapped; other memory of
//! the process may live there now, so the owner never unmaps them and they
//! stay reserved for the life of the process. No guest code runs over such
//! a range: a share with a window makes every host mapping call on it
//! under the owner's execution barrier (`execution`), which keeps every
//! vCPU out of `KVM_RUN` during the call and ends guest execution after a
//! failed one.
//!
//! A pause freezes every share's worker with the disk and NIC workers:
//! after the last FUSE reply, used-ring entry and interrupt, with writable
//! handles and writable DAX file mappings synced. An export needs
//! `declare_host_writers_stopped`, the caller's promise that no host writer
//! changes a share directory or any alias of its files until resume. It
//! archives every share at once (`ShareArchive`) in the owner's archive
//! mode (full attributes, or guest-visible for an unprivileged owner), so
//! the image restores without the source directories: the JSON holds each device and the
//! archive manifest (objects, share roots, sessions with their DAX
//! mappings), and the file, init.krun and DAX page payloads follow the disk
//! segments. No host path or descriptor of a share appears in the image.
//! An import recreates the shares under `RestoreResources::fs_dir`
//! (created exclusively with mode 0700; an existing directory is an error
//! and stays untouched), maps each DAX window and restores each session
//! before any vCPU thread exists, and keeps the imported tree once it
//! succeeds. Those copies belong to the owner alone, so an import starts
//! with host writers declared stopped. A guest-visible archive imports only
//! under the effective IDs it recorded, checked before anything exists, and
//! the imported owner keeps exporting in its image's mode.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) use devices::virtio::fs::passthrough::ArchiveMode;
use devices::virtio::fs::passthrough::{
    ArchiveContract, ArchiveManifest, DaxMappingKind, ImportedArchive, PassthroughState,
    PayloadLengths, ShareArchive,
};
use devices::virtio::persist::{MmioTransportState, QueueState, VirtioDeviceState};
use devices::virtio::{
    Fs, MmioTransport, VirtioDevice, VirtioShmRegion, FS_FEATURES, FS_NUM_QUEUES, FS_QUEUE_SIZE,
    TYPE_FS,
};
use serde::{Deserialize, Serialize};
use vm_memory::{GuestMemory, GuestMemoryMmap};

use super::wiring::{self, MMIO_LEN};
use super::{Error, RamSnapshotVm, Region, Result};

/// After the console slot; share `i` uses `FS_MMIO_BASE + i * MMIO_LEN`.
pub(super) const FS_MMIO_BASE: u64 = 0xd000_d000;
/// Share `i` uses GSI `FS_IRQ_BASE + i`, the rest of the legacy range.
pub(super) const FS_IRQ_BASE: u32 = 9;
pub(super) const MAX_SHARES: usize = 7;
/// Length of the virtio-fs config space tag.
const MAX_TAG: usize = 36;
/// KVM memslot and host page granularity on x86-64.
const DAX_ALIGN: u64 = 4096;
/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;
/// Architectural windows KVM serves itself, which a DAX memslot would
/// shadow: the EPT identity map page below the three TSS pages at
/// `KVM_TSS_ADDRESS`, the IOAPIC and the default local APIC page.
pub(super) const ARCH_WINDOWS: [(u64, u64); 3] = [
    (arch::x86_64::layout::KVM_TSS_ADDRESS - 0x1000, 0x4000),
    (0xfec0_0000, 0x1000),
    (0xfee0_0000, 0x1000),
];

/// A share to attach before vCPUs start.
pub(crate) struct FsShareConfig {
    /// The virtio-fs tag the guest mounts: 1–36 bytes without NUL, unique
    /// per owner.
    pub(crate) tag: String,
    /// The absolute path of the directory to share; any bytes but NUL.
    pub(crate) source: PathBuf,
    pub(crate) read_only: bool,
    /// Let the guest remove the share root (`VIRTIO_IOC_REMOVE_ROOT_DIR`).
    pub(crate) allow_root_dir_delete: bool,
    /// libkrun created `source` for this VM alone (the temporary boot
    /// root): the owner acknowledges a guest removal request without
    /// removing it, keeps it for exports and removes it when it drops.
    /// Every other share keeps the immediate removal contract.
    pub(crate) vm_owned: bool,
    pub(crate) dax: Option<DaxRange>,
}

/// The guest physical range of a DAX window: 4 KiB aligned, nonzero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaxRange {
    pub(crate) gpa: u64,
    pub(crate) len: u64,
}

/// One attached share.
pub(super) struct FsDevice {
    device: Arc<Mutex<Fs>>,
    transport: Arc<Mutex<MmioTransport>>,
    index: usize,
    tag: String,
    read_only: bool,
    allow_root_dir_delete: bool,
    /// The root of a VM-owned share, which the owner removes when it drops.
    vm_owned_root: Option<PathBuf>,
    /// The DAX window and its backing's index in `RamSnapshotVm::dax`.
    dax: Option<(DaxRange, usize)>,
}

/// The host memory of one DAX window. The owner keeps it until it drops,
/// after the VM fd (and with it the window's memslot) closed.
pub(super) struct DaxBacking {
    host: u64,
    len: u64,
    /// Ranges (offset, length) the share may no longer own; never unmapped.
    unowned: Vec<(u64, u64)>,
}

impl DaxBacking {
    /// Fresh private zero read-write memory: a share window's initial state.
    pub(super) fn new(len: u64) -> Result<Self> {
        let size = usize::try_from(len).map_err(|_| Error::Invalid("DAX window too large"))?;
        // SAFETY: a new anonymous mapping at an address the kernel picks.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(Self {
            host: addr as u64,
            len,
            unowned: Vec::new(),
        })
    }

    /// The shared memory region the device and its guest see.
    fn region(&self, gpa: u64) -> VirtioShmRegion {
        VirtioShmRegion {
            host_addr: self.host,
            guest_addr: gpa,
            size: self.len as usize,
        }
    }

    /// Keep `ranges` mapped for good: the share may no longer own them.
    pub(super) fn keep(&mut self, ranges: &[(u64, u64)]) {
        self.unowned.extend_from_slice(ranges);
    }
}

/// The parts of `[0, len)` outside every range in `unowned`, in order.
pub(super) fn owned_ranges(len: u64, unowned: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut cuts: Vec<(u64, u64)> = unowned
        .iter()
        .map(|&(start, size)| (start.min(len), start.saturating_add(size).min(len)))
        .collect();
    cuts.sort_unstable();
    let mut owned = Vec::new();
    let mut at = 0;
    for (start, end) in cuts {
        if start > at {
            owned.push((at, start - at));
        }
        at = at.max(end);
    }
    if at < len {
        owned.push((at, len - at));
    }
    owned
}

impl Drop for DaxBacking {
    fn drop(&mut self) {
        for (offset, len) in owned_ranges(self.len, &self.unowned) {
            // SAFETY: the owner mapped this range and no device, worker or
            // memslot uses it anymore; it excludes every range a failed
            // `MAP_FIXED` may have handed to other memory.
            unsafe { libc::munmap((self.host + offset) as *mut libc::c_void, len as usize) };
        }
        for (offset, len) in &self.unowned {
            warn!(
                "virtio-fs: DAX window range {:#x}+{len:#x} stays reserved after a failed host mapping",
                self.host + offset
            );
        }
    }
}

/// Snapshot metadata of every share. No host path or descriptor appears
/// here: the archive holds what the shares contain.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FsMeta {
    /// Share `i` of the archive is device `i`.
    pub(super) devices: Vec<FsDeviceMeta>,
    pub(super) archive: ArchiveManifest,
    /// The exit code the guest set through a share
    /// (`VIRTIO_IOC_EXIT_CODE`) before the cut, `i32::MAX` while unset:
    /// a guest exporting between setting it and shutting down reports it
    /// after the restore. Version 7 images restore it unset.
    pub(super) exit_code: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FsDeviceMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) tag: String,
    pub(super) read_only: bool,
    pub(super) allow_root_dir_delete: bool,
    /// The share is the VM-owned boot root: a restore keeps deferring the
    /// guest's removal request and removes its own imported copy when it
    /// drops. Version 7 images had no such share.
    pub(super) vm_owned: bool,
    pub(super) dax: Option<DaxRange>,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
}

fn mmio_addr(index: usize) -> u64 {
    FS_MMIO_BASE + index as u64 * MMIO_LEN
}

fn irq(index: usize) -> u32 {
    FS_IRQ_BASE + index as u32
}

/// Share `index`'s fixed (MMIO address, GSI).
pub(super) fn slot_of(index: usize) -> (u64, u32) {
    (mmio_addr(index), irq(index))
}

/// A share's (transport, MMIO address, GSI) for the shared wiring.
pub(super) fn slot(share: &FsDevice) -> (&Arc<Mutex<MmioTransport>>, u64, u32) {
    (&share.transport, mmio_addr(share.index), irq(share.index))
}

/// The guest range of every attached share's DAX window.
pub(super) fn windows(vm: &RamSnapshotVm) -> impl Iterator<Item = (u64, u64)> + '_ {
    vm.fs
        .iter()
        .filter_map(|share| share.dax.map(|(range, _)| (range.gpa, range.len)))
}

/// `GuestMemoryMmap` clones a share legitimately holds: the transport, plus
/// the device state and the worker once activated. A DAX window is not
/// guest RAM and holds none.
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    vm.fs
        .iter()
        .map(|share| 1 + 2 * usize::from(share.device.lock().unwrap().is_activated()))
        .sum()
}

/// 1–36 bytes without NUL, unlike every tag in `others`.
fn check_tag<'a>(tag: &str, mut others: impl Iterator<Item = &'a str>) -> Result<()> {
    if tag.is_empty() || tag.len() > MAX_TAG || tag.as_bytes().contains(&0) {
        return Err(Error::Invalid(
            "virtio-fs tag is empty, longer than 36 bytes or holds a NUL byte",
        ));
    }
    if others.any(|other| other == tag) {
        return Err(Error::Invalid("virtio-fs tag is already attached"));
    }
    Ok(())
}

/// An absolute path without NUL bytes naming a directory (not a symlink to
/// one: the share root is opened without following symlinks).
fn check_source(source: &Path) -> Result<()> {
    if !source.is_absolute() || source.as_os_str().as_bytes().contains(&0) {
        return Err(Error::Invalid(
            "virtio-fs source is not an absolute path without NUL bytes",
        ));
    }
    match std::fs::symlink_metadata(source) {
        Ok(meta) if meta.is_dir() => Ok(()),
        _ => Err(Error::Invalid("virtio-fs source is not a directory")),
    }
}

/// The new directory an import creates the shares in: an absolute path
/// without NUL bytes, so the imported roots the devices serve (and may
/// delete) never depend on the working directory.
pub(super) fn check_fs_dir(dir: &Path) -> Result<()> {
    if !dir.is_absolute() || dir.as_os_str().as_bytes().contains(&0) {
        return Err(Error::Invalid(
            "restore resources: the virtio-fs directory is not an absolute path without NUL bytes",
        ));
    }
    Ok(())
}

/// Nonzero, 4 KiB aligned, inside the guest physical address space.
fn check_dax_shape(range: DaxRange) -> Result<()> {
    if range.len == 0
        || range.gpa % DAX_ALIGN != 0
        || range.len % DAX_ALIGN != 0
        || range.len > isize::MAX as u64
        || range.gpa.checked_add(range.len).is_none()
    {
        return Err(Error::Invalid(
            "DAX window is empty, unaligned or overflows the address space",
        ));
    }
    Ok(())
}

/// The memslot of a new DAX window: RAM takes slots `0..ram_regions`, DAX
/// windows the following ones in creation order, and every one counts
/// toward the target's capacity.
pub(super) fn next_slot(ram_regions: usize, windows: usize, max_slots: usize) -> Result<u32> {
    match ram_regions.checked_add(windows) {
        Some(slot) if slot < max_slots && slot <= u32::MAX as usize => Ok(slot as u32),
        _ => Err(Error::Invalid(
            "DAX window exceeds the target KVM memslot capacity",
        )),
    }
}

/// Map a new window's backing and register it as KVM memslot `slot`. The
/// backing joins `vm.dax` before the registration, so it outlives the
/// memslot even when this or a later attach step fails.
fn add_window(vm: &mut RamSnapshotVm, range: DaxRange) -> Result<usize> {
    let slot = next_slot(vm.memory.num_regions(), vm.dax.len(), vm.max_slots)?;
    vm.dax.push(DaxBacking::new(range.len)?);
    let backing = vm.dax.len() - 1;
    let region = kvm_bindings::kvm_userspace_memory_region {
        slot,
        flags: 0,
        guest_phys_addr: range.gpa,
        memory_size: range.len,
        userspace_addr: vm.dax[backing].host,
    };
    // SAFETY: the owner keeps the backing until it drops, after the VM fd.
    unsafe { vm.vm.fd().set_user_memory_region(region) }
        .map_err(|e| Error::Full(format!("register DAX memslot: {e}")))?;
    Ok(backing)
}

type Parts = (Arc<Mutex<Fs>>, Arc<Mutex<MmioTransport>>);

/// What `build` needs to create one share's device.
struct Share<'a> {
    tag: &'a str,
    root: PathBuf,
    read_only: bool,
    allow_root_dir_delete: bool,
    vm_owned: bool,
    /// The owner's guest exit code (`VIRTIO_IOC_EXIT_CODE`), shared by every
    /// share.
    exit_code: Arc<AtomicI32>,
    window: Option<VirtioShmRegion>,
}

fn new_device(vm: &mut RamSnapshotVm, share: Share) -> Result<Parts> {
    let ioapic = vm.ensure_kernel_irqchip()?;
    let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(devices::legacy::IrqChipDevice::new(
        Box::new(ioapic),
    )));
    let window = share.window.is_some();
    let parts = build(vm.memory.clone(), intc, share)?;
    if window {
        // Before any session exists: every remapping of the live window
        // keeps the vCPUs out of KVM_RUN.
        parts
            .0
            .lock()
            .unwrap()
            .set_dax_control(vm.execution.clone());
    }
    Ok(parts)
}

/// A snapshot-mode device on `share.root` and its transport over `memory`,
/// before any wiring.
fn build(memory: GuestMemoryMmap, intc: devices::legacy::IrqChip, share: Share) -> Result<Parts> {
    let mut fs = Fs::new_at(
        share.tag.to_owned(),
        share.root,
        share.exit_code,
        share.allow_root_dir_delete,
        share.read_only,
    )
    .map_err(|e| Error::Full(format!("create virtio-fs device: {e:?}")))?;
    fs.enable_snapshot();
    if share.vm_owned {
        fs.defer_root_dir_delete();
    }
    if let Some(window) = share.window {
        fs.set_shm_region(window);
    }
    let device = Arc::new(Mutex::new(fs));
    let transport = Arc::new(Mutex::new(
        MmioTransport::new(memory, intc, device.clone())
            .map_err(|e| Error::Full(format!("create virtio-fs transport: {e}")))?,
    ));
    Ok((device, transport))
}

/// Attach one share before vCPUs start; its worker starts when the guest
/// activates the device. Every check precedes any effect; a failure after
/// them poisons the owner for further snapshots.
pub(super) fn attach(vm: &mut RamSnapshotVm, config: FsShareConfig) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "virtio-fs shares cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid(
            "virtio-fs shares attach only before vCPU start",
        ));
    }
    let index = vm.fs.len();
    if index >= MAX_SHARES {
        return Err(Error::Invalid("the virtio-fs window is full"));
    }
    check_tag(&config.tag, vm.fs.iter().map(|share| share.tag.as_str()))?;
    check_source(&config.source)?;
    if let Some(range) = config.dax {
        check_dax_shape(range)?;
        let mut taken = wiring::claimed(vm);
        taken.push((mmio_addr(index), MMIO_LEN));
        taken.extend(ARCH_WINDOWS);
        wiring::check_disjoint(
            range.gpa,
            range.len,
            taken,
            "DAX window overlaps RAM, a device or another window",
        )?;
        next_slot(vm.memory.num_regions(), vm.dax.len(), vm.max_slots)?;
    }
    let attached = (|| {
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let dax = match config.dax {
            Some(range) => Some((range, add_window(vm, range)?)),
            None => None,
        };
        let (device, transport) = new_device(
            vm,
            Share {
                tag: &config.tag,
                root: config.source.clone(),
                read_only: config.read_only,
                allow_root_dir_delete: config.allow_root_dir_delete,
                vm_owned: config.vm_owned,
                exit_code: vm.exit_code.clone(),
                window: dax.map(|(range, backing)| vm.dax[backing].region(range.gpa)),
            },
        )?;
        wiring::register_device(vm, &transport, mmio_addr(index), irq(index))?;
        Ok(FsDevice {
            device,
            transport,
            index,
            tag: config.tag,
            read_only: config.read_only,
            allow_root_dir_delete: config.allow_root_dir_delete,
            vm_owned_root: config.vm_owned.then_some(config.source),
            dax,
        })
    })();
    match attached {
        Ok(share) => {
            vm.fs.push(share);
            Ok(())
        }
        Err(error) => {
            vm.control.unusable = true;
            Err(error)
        }
    }
}

/// Exports need the caller's declaration that every host writer of the
/// shares is stopped.
pub(super) fn require_declared(shares: usize, declared: bool) -> Result<()> {
    if shares > 0 && !declared {
        return Err(Error::Invalid(
            "virtio-fs export requires declare_host_writers_stopped",
        ));
    }
    Ok(())
}

/// Whether a share must be discarded (its DAX window was lost).
pub(super) fn any_discarded(shares: &[FsDevice]) -> bool {
    shares
        .iter()
        .any(|share| share.device.lock().unwrap().must_discard())
}

/// Freeze every activated share's worker behind paused vCPUs. Returns the
/// cut of each share (None when inactive). A share that must be discarded
/// fails the pause.
pub(super) fn freeze(shares: &[FsDevice]) -> Result<Vec<Option<Vec<QueueState>>>> {
    shares
        .iter()
        .map(|share| {
            let device = share.device.lock().unwrap();
            if device.must_discard() {
                return Err(Error::Full(format!(
                    "virtio-fs share {} lost its DAX window",
                    share.index
                )));
            }
            if !device.is_activated() {
                return Ok(None);
            }
            let control = device
                .worker_control()
                .ok_or(Error::Invalid("activated virtio-fs share has no worker"))?;
            let cut = control
                .freeze()
                .map_err(|e| Error::Full(format!("freeze virtio-fs share {}: {e}", share.index)))?;
            Ok(Some(cut.queues))
        })
        .collect()
}

/// Resume every activated share's worker; each re-examines its queues. One
/// failure does not skip the others.
pub(super) fn resume(shares: &[FsDevice]) -> Result<()> {
    let mut first = None;
    for share in shares {
        let device = share.device.lock().unwrap();
        if let Some(control) = device.worker_control() {
            if let Err(e) = control.resume() {
                first.get_or_insert(Error::Full(format!(
                    "resume virtio-fs share {}: {e}",
                    share.index
                )));
            }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Retire every share after the vCPUs stopped: stop and join its worker,
/// leave its DAX window as it is, and keep the ranges it may no longer own
/// out of its backing's eventual unmapping.
pub(super) fn teardown(vm: &mut RamSnapshotVm) {
    let (shares, backings) = (&vm.fs, &mut vm.dax);
    for share in shares {
        let mut device = share.device.lock().unwrap_or_else(|e| e.into_inner());
        device.retire();
        if let Some((_, backing)) = share.dax {
            backings[backing].keep(device.dax_unowned());
        }
    }
}

/// Remove the root of every VM-owned share (a booted owner's boot root, an
/// imported owner's copy of it), after `teardown` joined every worker.
/// Nothing can report a failure at this point, so it is logged.
pub(super) fn remove_vm_owned_roots(shares: &[FsDevice]) {
    for root in shares
        .iter()
        .filter_map(|share| share.vm_owned_root.as_ref())
    {
        if let Err(e) = std::fs::remove_dir_all(root) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("remove VM-owned share root {}: {e}", root.display());
            }
        }
    }
}

/// Retire a device that failed to restore, keeping the window ranges it
/// may no longer own.
fn discard(vm: &mut RamSnapshotVm, device: &Arc<Mutex<Fs>>, backing: Option<usize>) {
    let mut device = device.lock().unwrap_or_else(|e| e.into_inner());
    device.retire();
    if let Some(backing) = backing {
        vm.dax[backing].keep(device.dax_unowned());
    }
}

fn device_meta(
    share: &FsDevice,
    transport: &MmioTransport,
    device: &Fs,
    cut: Option<&Vec<QueueState>>,
) -> FsDeviceMeta {
    FsDeviceMeta {
        mmio_addr: mmio_addr(share.index),
        mmio_len: MMIO_LEN,
        irq: irq(share.index),
        tag: share.tag.clone(),
        read_only: share.read_only,
        allow_root_dir_delete: share.allow_root_dir_delete,
        vm_owned: share.vm_owned_root.is_some(),
        dax: share.dax.map(|(range, _)| range),
        transport: transport.save_transport_state(),
        device: VirtioDeviceState {
            device_type: TYPE_FS,
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            // Inactive devices leave their queues with the transport.
            queues: cut.cloned().unwrap_or_else(|| transport.queue_states()),
            activated: device.is_activated(),
        },
    }
}

/// Capture every frozen share while the vCPUs are paused and the irqfds
/// drained: the devices and one archive of all shares. Repeated exports of
/// one pause see the same guest, RAM and device cut, but each re-reads the
/// host trees: a symlink atime an earlier readlink moved (and, without
/// `O_NOATIME` permission, file and directory atimes) is recorded as found,
/// and the first capture assigns inode projections to objects the guest
/// never looked up in the live share. Images are not byte-identical.
/// `exit_code` is the owner's guest exit code at the cut.
pub(super) fn capture(
    shares: &[FsDevice],
    cuts: &[Option<Vec<QueueState>>],
    mode: ArchiveMode,
    exit_code: i32,
) -> Result<Option<(FsMeta, ShareArchive)>> {
    if shares.is_empty() {
        return Ok(None);
    }
    let locked: Vec<_> = shares
        .iter()
        .map(|share| {
            (
                share.transport.lock().unwrap(),
                share.device.lock().unwrap(),
            )
        })
        .collect();
    let mut devices = Vec::with_capacity(shares.len());
    let mut sources = Vec::with_capacity(shares.len());
    for ((share, (transport, device)), cut) in shares.iter().zip(&locked).zip(cuts) {
        devices.push(device_meta(share, transport, device, cut.as_ref()));
        sources.push(
            device
                .archive_source()
                .map_err(|e| Error::Full(format!("virtio-fs share {}: {e}", share.index)))?,
        );
    }
    let archive = ShareArchive::capture(sources, mode)
        .map_err(|e| Error::Full(format!("virtio-fs archive: {e}")))?;
    let meta = FsMeta {
        devices,
        archive: archive.manifest().clone(),
        exit_code,
    };
    Ok(Some((meta, archive)))
}

/// A read-only share holds no writable handle, DAX file mapping or
/// writeback cache.
fn check_read_only(state: &PassthroughState) -> Result<()> {
    let writable_handle = state
        .handles
        .iter()
        .any(|handle| handle.flags & libc::O_ACCMODE != libc::O_RDONLY);
    let writable_mapping = state
        .dax
        .iter()
        .flat_map(|dax| &dax.mappings)
        .any(|mapping| matches!(mapping.kind, DaxMappingKind::File { writable: true, .. }));
    if state.writeback || writable_handle || writable_mapping {
        return Err(Error::Invalid(
            "a read-only virtio-fs share holds writable state",
        ));
    }
    Ok(())
}

/// Metadata-only validation, before guest RAM or any target resource
/// exists: the archive manifest as a whole, every device against its fixed
/// slot and its share's session, and every DAX window against RAM, the
/// MMIO slots of every other device in the image (`slots`), every share's
/// slot, the architectural windows and each other, each taking a memslot.
/// Returns the payload lengths.
pub(super) fn validate_metadata(
    meta: &FsMeta,
    regions: &[Region],
    slots: &[u64],
    max_slots: usize,
) -> Result<PayloadLengths> {
    let invalid = |why: String| Error::Full(format!("virtio-fs: {why}"));
    if meta.devices.is_empty() || meta.devices.len() > MAX_SHARES {
        return Err(invalid("share count is zero or above 7".into()));
    }
    let lengths = meta
        .archive
        .validate()
        .map_err(|e| invalid(e.to_string()))?;
    if meta.archive.shares.len() != meta.devices.len() {
        return Err(invalid("archive shares differ from the devices".into()));
    }
    let ram = || regions.iter().map(|r| (r.gpa, r.len));
    let mut tags = HashSet::new();
    let mut windows = Vec::new();
    for (index, (device, share)) in meta.devices.iter().zip(&meta.archive.shares).enumerate() {
        if device.mmio_addr != mmio_addr(index)
            || device.mmio_len != MMIO_LEN
            || device.irq != irq(index)
        {
            return Err(invalid(format!("share {index} is outside its slot")));
        }
        wiring::check_window(device.mmio_addr, ram())?;
        check_tag(&device.tag, std::iter::empty())?;
        if !tags.insert(device.tag.as_str()) {
            return Err(invalid(format!("share {index} repeats a tag")));
        }
        if device.device.avail_features != FS_FEATURES {
            return Err(invalid(format!("share {index} offers other features")));
        }
        device
            .transport
            .validate()
            .map_err(|_| invalid(format!("share {index} transport registers")))?;
        device
            .device
            .validate_structure(TYPE_FS, FS_NUM_QUEUES, FS_QUEUE_SIZE)
            .map_err(|_| invalid(format!("share {index} virtio state")))?;
        if (device.transport.device_status & DRIVER_OK != 0) != device.device.activated {
            return Err(invalid(format!(
                "share {index} activation disagrees with the transport status"
            )));
        }
        // An inactive device serves no session: its share's is the one a
        // fresh share has before FUSE_INIT (its DAX window may hold pages).
        let session = &share.session;
        let live = session.options != 0
            || !session.state.nodes.is_empty()
            || !session.state.handles.is_empty();
        if !device.device.activated && live {
            return Err(invalid(format!(
                "inactive share {index} carries a FUSE session"
            )));
        }
        if session.state.dax.as_ref().map(|dax| dax.size) != device.dax.map(|range| range.len) {
            return Err(invalid(format!(
                "share {index} DAX window differs from its session's"
            )));
        }
        if device.read_only {
            check_read_only(&session.state)?;
        }
        if let Some(range) = device.dax {
            check_dax_shape(range)?;
            windows.push(range);
        }
    }
    let shares = (0..meta.devices.len()).map(|index| (mmio_addr(index), MMIO_LEN));
    let mut taken: Vec<(u64, u64)> = ram()
        .chain(slots.iter().map(|&slot| (slot, MMIO_LEN)))
        .chain(shares)
        .chain(ARCH_WINDOWS)
        .collect();
    for range in &windows {
        wiring::check_disjoint(
            range.gpa,
            range.len,
            taken.iter().copied(),
            "DAX window overlaps RAM, a device or another window",
        )?;
        taken.push((range.gpa, range.len));
    }
    if regions.len() + windows.len() > max_slots {
        return Err(Error::Invalid(
            "DAX window exceeds the target KVM memslot capacity",
        ));
    }
    Ok(lengths)
}

/// Ring validation against the loaded guest RAM (never a DAX window): every
/// ready queue of an activated share.
pub(super) fn validate_rings(meta: &FsMeta, memory: &GuestMemoryMmap) -> Result<()> {
    for (index, device) in meta.devices.iter().enumerate() {
        device
            .device
            .validate_ready_queues(memory, TYPE_FS, FS_NUM_QUEUES, FS_QUEUE_SIZE)
            .map_err(|e| Error::Full(format!("virtio-fs share {index} rings: {e}")))?;
    }
    Ok(())
}

/// Bytes of the file, init.krun and DAX page payloads.
pub(super) fn payload_len(lengths: PayloadLengths) -> Result<u64> {
    lengths
        .files
        .checked_add(lengths.init)
        .and_then(|len| len.checked_add(lengths.pages))
        .ok_or(Error::Invalid("virtio-fs payload length overflow"))
}

/// The payload writer of an export (with the test write-fault hook).
struct Payload<'a>(&'a mut File);

impl Write for Payload<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        super::tests::write_payload(self.0, bytes)?;
        #[cfg(not(test))]
        self.0.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write the file, init.krun and DAX page payloads after the disk
/// segments; a file that changed since the capture fails the export.
pub(super) fn write_payloads(file: &mut File, archive: &ShareArchive) -> Result<()> {
    let mut out = Payload(file);
    archive
        .write_files(&mut out)
        .map_err(|e| Error::Full(format!("virtio-fs files: {e}")))?;
    archive.write_init(&mut out)?;
    archive.write_pages(&mut out)?;
    Ok(())
}

/// Upgrade a version 7 virtio-fs section (JSON, maybe null) in place: its
/// archive was captured with full attributes and records no contract, none
/// of its shares was VM-owned, and it recorded no exit code, so it restores
/// unset; one that records any of these is no version 7 section.
pub(super) fn upgrade_contractless(fs: &mut serde_json::Value) -> Result<()> {
    if let Some(archive) = fs.get_mut("archive").and_then(|a| a.as_object_mut()) {
        if archive.contains_key("contract") {
            return Err(Error::Invalid(
                "a version 7 virtio-fs archive carries a contract",
            ));
        }
        let contract = serde_json::to_value(ArchiveContract::FullAttributes)
            .map_err(|e| Error::Full(format!("virtio-fs contract: {e}")))?;
        archive.insert("contract".to_owned(), contract);
    }
    if let Some(devices) = fs.get_mut("devices").and_then(|d| d.as_array_mut()) {
        for device in devices.iter_mut().filter_map(|d| d.as_object_mut()) {
            if device.contains_key("vm_owned") {
                return Err(Error::Invalid(
                    "a version 7 virtio-fs share records VM ownership",
                ));
            }
            device.insert("vm_owned".to_owned(), serde_json::Value::Bool(false));
        }
    }
    if let Some(section) = fs.as_object_mut() {
        if section.contains_key("exit_code") {
            return Err(Error::Invalid(
                "a version 7 virtio-fs section records an exit code",
            ));
        }
        section.insert("exit_code".to_owned(), i32::MAX.into());
    }
    Ok(())
}

/// The mode an owner restored from `meta` exports in, once this process
/// passed the archive's importer check (before anything exists).
pub(super) fn imported_mode(meta: &FsMeta) -> Result<ArchiveMode> {
    let contract = &meta.archive.contract;
    contract
        .check_importer()
        .map_err(|e| Error::Full(format!("virtio-fs: {e}")))?;
    Ok(match contract {
        ArchiveContract::FullAttributes => ArchiveMode::FullAttributes,
        ArchiveContract::GuestVisible { .. } => ArchiveMode::GuestVisible,
    })
}

/// Import the shares into the new directory `dir` from the three payloads
/// at `file`'s position, consuming exactly their bytes. A failure removes
/// whatever the import created.
pub(super) fn import_shares(file: &File, meta: &FsMeta, dir: &Path) -> Result<ImportedArchive> {
    let lengths = meta
        .archive
        .validate()
        .map_err(|e| Error::Full(format!("virtio-fs: {e}")))?;
    // Each clone shares the file position, so the payloads read in order.
    let mut files = file.try_clone()?.take(lengths.files);
    let mut init = file.try_clone()?.take(lengths.init);
    let mut pages = file.try_clone()?.take(lengths.pages);
    ImportedArchive::import(&meta.archive, dir, &mut files, &mut init, &mut pages)
        .map_err(|e| Error::Full(format!("virtio-fs import: {e}")))
}

/// Rebuild every share at its fixed slot on the imported tree held in
/// `vm.fs_import`: each DAX window is mapped and registered, each session
/// restored (with its window) and each activated share restore-activated
/// with a frozen worker, before any vCPU thread exists. The archive holds
/// every device it restored until the import persists it.
pub(super) fn restore(vm: &mut RamSnapshotVm, meta: &FsMeta) -> Result<()> {
    restore_exit_code(meta, &vm.exit_code);
    let mut archive = vm
        .fs_import
        .take()
        .ok_or(Error::Invalid("virtio-fs shares were not imported"))?;
    let restored = meta
        .devices
        .iter()
        .enumerate()
        .try_for_each(|(index, device)| restore_share(vm, &mut archive, index, device));
    vm.fs_import = Some(archive);
    restored
}

/// Each restored share's tag and imported root, except the VM-owned boot
/// root, whose copy goes with the owner.
pub(super) fn restored_roots(meta: &FsMeta, archive: &ImportedArchive) -> Vec<(String, PathBuf)> {
    meta.devices
        .iter()
        .enumerate()
        .filter(|(_, device)| !device.vm_owned)
        .map(|(index, device)| (device.tag.clone(), archive.root(index).to_owned()))
        .collect()
}

/// The restored owner continues from the exit code the image recorded.
fn restore_exit_code(meta: &FsMeta, exit_code: &AtomicI32) {
    exit_code.store(meta.exit_code, Ordering::SeqCst);
}

fn restore_share(
    vm: &mut RamSnapshotVm,
    archive: &mut ImportedArchive,
    index: usize,
    meta: &FsDeviceMeta,
) -> Result<()> {
    let dax = match meta.dax {
        Some(range) => Some((range, add_window(vm, range)?)),
        None => None,
    };
    let root = archive.root(index).to_owned();
    let window = dax.map(|(range, backing)| vm.dax[backing].region(range.gpa));
    let (device, transport) = new_device(
        vm,
        restored_share(meta, root.clone(), vm.exit_code.clone(), window),
    )?;
    archive.hold(device.clone());
    let restored = restore_parts(&device, &transport, archive, index, meta)
        .and_then(|()| wiring::register_device(vm, &transport, meta.mmio_addr, meta.irq));
    if let Err(error) = restored {
        discard(vm, &device, dax.map(|(_, backing)| backing));
        return Err(error);
    }
    vm.fs.push(FsDevice {
        device,
        transport,
        index,
        tag: meta.tag.clone(),
        read_only: meta.read_only,
        allow_root_dir_delete: meta.allow_root_dir_delete,
        vm_owned_root: owned_root(meta, root),
        dax,
    });
    Ok(())
}

/// What a restored VM-owned share removes when the owner drops: only its
/// imported `root`, never a source path.
fn owned_root(meta: &FsDeviceMeta, root: PathBuf) -> Option<PathBuf> {
    meta.vm_owned.then_some(root)
}

/// The device a restore creates for `meta` on its imported `root`: a
/// VM-owned share keeps deferring the guest's removal request.
fn restored_share<'a>(
    meta: &'a FsDeviceMeta,
    root: PathBuf,
    exit_code: Arc<AtomicI32>,
    window: Option<VirtioShmRegion>,
) -> Share<'a> {
    Share {
        tag: &meta.tag,
        root,
        read_only: meta.read_only,
        allow_root_dir_delete: meta.allow_root_dir_delete,
        vm_owned: meta.vm_owned,
        exit_code,
        window,
    }
}

/// Adopt the saved device, session and transport state; an activated
/// share is restore-activated with its worker frozen.
fn restore_parts(
    device: &Arc<Mutex<Fs>>,
    transport: &Arc<Mutex<MmioTransport>>,
    archive: &ImportedArchive,
    index: usize,
    meta: &FsDeviceMeta,
) -> Result<()> {
    {
        let mut locked = device.lock().unwrap();
        locked.set_acked_features(meta.device.acked_features);
        locked
            .restore_imported(archive, index)
            .map_err(|e| Error::Full(format!("restore virtio-fs share {index}: {e}")))?;
    }
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
            .map_err(|e| Error::Full(format!("restore-activate virtio-fs share {index}: {e:?}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod kvm_tests;
#[cfg(test)]
pub(super) mod tests;
