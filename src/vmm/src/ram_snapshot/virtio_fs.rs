// SPDX-License-Identifier: Apache-2.0

//! Frozen virtio-fs sessions with external object bindings; no filesystem archive.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use devices::virtio::fs::passthrough::{
    DaxMappingKind, DaxPages, PassthroughCheckpoint, PassthroughState, RestoredObject, RestoredRoles,
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
    recipe_root: Option<PathBuf>,
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
/// here: providers retain the objects that the session references.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FsMeta {
    /// Share `i` corresponds to device `i`.
    pub(super) devices: Vec<FsDeviceMeta>,
    pub(super) sessions: Vec<SessionMeta>,
    /// The exit code the guest set through a share
    /// (`VIRTIO_IOC_EXIT_CODE`) before the cut, `i32::MAX` while unset:
    /// a guest exporting between setting it and shutting down reports it
    /// after the restore.
    pub(super) exit_code: i32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FsDeviceMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) tag: String,
    pub(super) read_only: bool,
    pub(super) allow_root_dir_delete: bool,
    /// The VM-owned boot root: source teardown removes it. Restore defers
    /// guest removal but leaves the caller-bound recipe root alive.
    pub(super) vm_owned: bool,
    pub(super) dax: Option<DaxRange>,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionMeta {
    options: u64,
    state: PassthroughState,
    objects: Vec<ObjectMeta>,
    init_len: u64,
    dax_offsets: Vec<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectMeta {
    alias: u64,
    guest_ino: u64,
    ctime: (i64, i64),
    kind: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unlinked: bool,
    reference: Option<crate::snapshot_vm::checkpoint::ExternalReference>,
    recipe: Option<String>,
}
pub(super) struct CapturedShares {
    pub meta: FsMeta,
    pub checkpoints: Vec<PassthroughCheckpoint>,
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
            recipe_root: config.vm_owned.then_some(config.source.clone()),
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
        vm_owned: share.recipe_root.is_some(),
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

/// Capture frozen device/session state and retained-object descriptors after
/// vCPUs pause and irqfds drain. Only saved directory names are resolved;
/// filesystem contents remain external. `exit_code` belongs to the cut.
pub(super) fn capture(
    shares: &[FsDevice],
    cuts: &[Option<Vec<QueueState>>],
    exit_code: i32,
) -> Result<Option<CapturedShares>> {
    if shares.is_empty() {
        return Ok(None);
    }
    let mut devices = Vec::new();
    let mut checkpoints = Vec::new();
    let mut sessions = Vec::new();
    let mut aliases = std::collections::HashMap::new();
    for (share, cut) in shares.iter().zip(cuts) {
        let transport = share.transport.lock().unwrap();
        let device = share.device.lock().unwrap();
        devices.push(device_meta(share, &transport, &device, cut.as_ref()));
        let checkpoint = device
            .checkpoint_external()
            .map_err(|e| Error::Full(format!("capture external share {}: {e}", share.index)))?;
        let mut objects = Vec::new();
        for object in &checkpoint.passthrough.objects {
            let metadata = object.file.metadata()?;
            let kind = metadata.mode() & libc::S_IFMT;
            let recipe = share
                .recipe_root
                .as_ref()
                .map(|root| boot_object(root, &object.file))
                .transpose()?;
            let next = aliases.len() as u64;
            let alias = *aliases.entry((object.dev, object.ino)).or_insert(next);
            objects.push(ObjectMeta {
                alias,
                guest_ino: object.guest_ino,
                ctime: object.ctime,
                kind,
                unlinked: kind == libc::S_IFREG && metadata.nlink() == 0,
                reference: None,
                recipe,
            });
        }
        sessions.push(SessionMeta {
            options: checkpoint.options,
            state: checkpoint.passthrough.state.clone(),
            objects,
            init_len: checkpoint.passthrough.init_binary.len() as u64,
            dax_offsets: checkpoint.passthrough.dax_pages.offsets.clone(),
        });
        checkpoints.push(checkpoint.passthrough);
    }
    Ok(Some(CapturedShares {
        meta: FsMeta {
            devices,
            sessions,
            exit_code,
        },
        checkpoints,
    }))
}

// init.c::mount_filesystems and KRUN_BLOCK_ROOT_DEVICE create these directories.
const BOOT_DIRS: [&str; 5] = [".", "dev", "proc", "sys", "newroot"];
fn boot_object(root: &Path, file: &File) -> Result<String> {
    let object = file.metadata()?;
    for name in BOOT_DIRS {
        if let Ok(candidate) = std::fs::symlink_metadata(root.join(name)) {
            if candidate.is_dir()
                && (object.dev(), object.ino()) == (candidate.dev(), candidate.ino())
            {
                return Ok(name.to_owned());
            }
        }
    }
    Err(Error::Invalid(
        "non-reconstructible runtime boot-root object",
    ))
}

impl CapturedShares {
    pub(super) fn descriptors(&self) -> Result<Vec<File>> {
        self.checkpoints
            .iter()
            .flat_map(|s| &s.objects)
            .map(|o| o.file.try_clone().map_err(Error::Io))
            .collect()
    }
    pub(super) fn bind_references(
        &mut self,
        references: Vec<Vec<crate::snapshot_vm::checkpoint::ExternalReference>>,
    ) -> Result<()> {
        if references.len() != self.meta.sessions.len() {
            return Err(Error::Invalid("external reference share count differs"));
        }
        for (session, refs) in self.meta.sessions.iter_mut().zip(references) {
            let external = session
                .objects
                .iter()
                .filter(|o| o.recipe.is_none())
                .count();
            if refs.len() != external {
                return Err(Error::Invalid("external object references missing"));
            }
            let mut refs = refs.into_iter();
            for object in &mut session.objects {
                if object.recipe.is_none() {
                    let reference = refs.next().unwrap();
                    if [
                        &reference.resource_id,
                        &reference.recovery_point,
                        &reference.object_key,
                    ]
                    .iter()
                    .any(|s| s.is_empty() || s.len() > 4096)
                    {
                        return Err(Error::Invalid("invalid external object reference"));
                    }
                    object.reference = Some(reference);
                }
            }
        }
        Ok(())
    }
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
/// exists: each session, every device against its fixed
/// slot and its share's session, and every DAX window against RAM, the
/// MMIO slots of every other device in the image (`slots`), every share's
/// slot, the architectural windows and each other, each taking a memslot.
/// Returns the payload lengths.
pub(super) fn validate_metadata(
    meta: &FsMeta,
    regions: &[Region],
    slots: &[u64],
    max_slots: usize,
) -> Result<u64> {
    let invalid = |why: String| Error::Full(format!("virtio-fs: {why}"));
    if meta.devices.is_empty() || meta.devices.len() > MAX_SHARES {
        return Err(invalid("share count is zero or above 7".into()));
    }
    if meta.sessions.len() != meta.devices.len() {
        return Err(invalid("sessions differ from devices".into()));
    }
    let mut lengths = 0u64;
    for session in &meta.sessions {
        session
            .state
            .validate(session.objects.len())
            .map_err(|e| invalid(e.to_string()))?;
        session
            .state
            .check_options(session.options)
            .map_err(|e| invalid(e.to_string()))?;
        if session.init_len > 64 << 20 {
            return Err(invalid("init.krun exceeds 64 MiB".into()));
        }
        if let Some(dax) = &session.state.dax {
            dax.validate_page_offsets(&session.dax_offsets)
                .map_err(|e| invalid(e.to_string()))?;
        } else if !session.dax_offsets.is_empty() {
            return Err(invalid("pages without DAX".into()));
        }
        lengths = lengths
            .checked_add(session.init_len)
            .and_then(|n| n.checked_add((session.dax_offsets.len() as u64).checked_mul(4096)?))
            .ok_or(Error::Invalid("share payload overflow"))?;
    }
    let ram = || regions.iter().map(|r| (r.gpa, r.len));
    let mut tags = HashSet::new();
    let mut windows = Vec::new();
    for (index, (device, share)) in meta.devices.iter().zip(&meta.sessions).enumerate() {
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
        let session = share;
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
        let mut guest_inodes = HashSet::new();
        for object in &session.objects {
            if object.guest_ino == session.state.init_inode || !guest_inodes.insert(object.guest_ino) {
                return Err(invalid("invalid or duplicate saved guest inode".into()));
            }
            if object.unlinked && (device.vm_owned || object.kind != libc::S_IFREG) {
                return Err(invalid("invalid unlinked object kind or ownership".into()));
            }
            if device.vm_owned {
                if object.reference.is_some()
                    || !object
                        .recipe
                        .as_deref()
                        .is_some_and(|name| BOOT_DIRS.contains(&name))
                    || object.kind != libc::S_IFDIR
                {
                    return Err(invalid("invalid boot-root recipe object".into()));
                }
            } else if object.recipe.is_some()
                || object.reference.as_ref().is_none_or(|r| {
                    [&r.resource_id, &r.recovery_point, &r.object_key]
                        .iter()
                        .any(|s| s.is_empty() || s.len() > 4096)
                })
            {
                return Err(invalid(
                    "missing or invalid external object reference".into(),
                ));
            }
        }
        for entry in session
            .state
            .handles
            .iter()
            .filter_map(|h| h.listing.as_ref())
            .flatten()
        {
            if entry.object.is_some_and(|index| {
                session
                    .objects
                    .get(index as usize)
                    .is_none_or(|object| object.guest_ino != entry.ino || !entry.projected)
            }) {
                return Err(invalid("cached entry object/projection differs".into()));
            }
            if entry.projected && (entry.name == b"." || entry.name == b"..") {
                return Err(invalid("dot entry cannot require a binding".into()));
            }
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
pub(super) fn write_payloads(file: &mut File, capture: &CapturedShares) -> Result<()> {
    for share in &capture.checkpoints {
        file.write_all(&share.init_binary)?;
        file.write_all(&share.dax_pages.data)?;
    }
    Ok(())
}

/// Drop only explicitly absent orphans; saved allocation counters prevent ID reuse.
fn bound_session(
    session: &SessionMeta,
    binding: &crate::snapshot_vm::checkpoint::ShareBinding,
    vm_owned: bool,
) -> Result<(PassthroughState, Vec<RestoredObject>, RestoredRoles)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    session
        .state
        .validate(session.objects.len())
        .map_err(|e| Error::Full(e.to_string()))?;
    if (vm_owned && !binding.objects.is_empty())
        || (!vm_owned && binding.objects.len() != session.objects.len())
    {
        return Err(Error::Invalid("retained object binding count differs"));
    }
    let mut remap = Vec::new();
    let mut objects = Vec::new();
    let mut identities = HashSet::new();
    for (index, saved) in session.objects.iter().enumerate() {
        let file = if vm_owned {
            let recipe = saved
                .recipe
                .as_deref()
                .ok_or(Error::Invalid("missing boot recipe"))?;
            if !BOOT_DIRS.contains(&recipe) {
                return Err(Error::Invalid("unknown boot recipe"));
            }
            Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                    .open(binding.root.join(recipe))?,
            )
        } else {
            binding.objects[index]
                .as_ref()
                .map(File::try_clone)
                .transpose()?
        };
        let Some(file) = file else {
            if !saved.unlinked
                || saved.kind != libc::S_IFREG
                || saved.recipe.is_some()
                || saved.reference.is_none()
                || session
                    .state
                    .nodes
                    .iter()
                    .any(|node| node.inode == 1 && node.object == index as u64)
            {
                return Err(Error::Invalid(
                    "missing object was not a saved unlinked regular file",
                ));
            }
            remap.push(None);
            continue;
        };
        let st = file.metadata()?;
        // SAFETY: file owns a live descriptor; fcntl only reads status flags.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || flags & libc::O_PATH == 0
            || st.mode() & libc::S_IFMT != saved.kind
            || !identities.insert((st.dev(), st.ino()))
        {
            return Err(Error::Invalid(
                "retained object descriptor type or access differs, or identity repeats",
            ));
        }
        remap.push(Some(objects.len() as u64));
        objects.push(RestoredObject {
            file,
            guest_ino: saved.guest_ino,
            ctime: saved.ctime,
        });
    }
    if let Some(node) = session.state.nodes.iter().find(|node| node.inode == 1) {
        let index = remap[node.object as usize].ok_or(Error::Invalid("root object absent"))?;
        let supplied = objects[index as usize].file.metadata()?;
        let root = std::fs::metadata(&binding.root)?;
        if (supplied.dev(), supplied.ino()) != (root.dev(), root.ino()) {
            return Err(Error::Invalid("bound root identity differs"));
        }
    }
    let mut state = session.state.clone();
    state
        .nodes
        .retain_mut(|node| match remap[node.object as usize] {
            Some(object) => {
                node.object = object;
                true
            }
            None => false,
        });
    for handle in &session.state.handles {
        if !binding.roles.handles.contains_key(&handle.handle) {
            let object = &session.objects[handle.object as usize];
            if vm_owned || !object.unlinked || object.kind != libc::S_IFREG {
                return Err(Error::Invalid("missing independent handle FD"));
            }
        } else if remap[handle.object as usize].is_none() {
            return Err(Error::Invalid("supplied handle has no object identity binding"));
        }
    }
    state
        .handles
        .retain(|handle| binding.roles.handles.contains_key(&handle.handle));
    for handle in &mut state.handles {
        handle.object = remap[handle.object as usize]
            .ok_or(Error::Invalid("supplied handle object absent"))?;
        for entry in handle.listing.iter_mut().flatten() {
            if let Some(index) = entry.object {
                entry.object = *remap
                    .get(index as usize)
                    .ok_or(Error::Invalid("cached entry object out of range"))?;
                if entry.object.is_none() {
                    entry.projected = false;
                }
            }
        }
    }
    if let Some(dax) = &mut state.dax {
        for mapping in &mut dax.mappings {
            if let DaxMappingKind::File { object, .. } = &mut mapping.kind {
                *object = remap[*object as usize]
                    .ok_or(Error::Invalid("missing object has an existing DAX mapping"))?;
            }
        }
    }
    let mut roles = RestoredRoles::default();
    for (&id, file) in &binding.roles.handles {
        roles.handles.insert(id, file.try_clone()?);
    }
    for (&(index, writable), file) in &binding.roles.dax {
        let index = remap
            .get(index as usize)
            .copied()
            .flatten()
            .ok_or(Error::Invalid("DAX role object absent"))?;
        roles.dax.insert((index, writable), file.try_clone()?);
    }
    roles
        .validate(&state, &objects)
        .map_err(|e| Error::Full(e.to_string()))?;
    Ok((state, objects, roles))
}

/// Validate external identities, aliases and role access before VM allocation.
pub(super) fn validate_bindings(
    meta: &FsMeta,
    bindings: &[crate::snapshot_vm::checkpoint::ShareBinding],
) -> Result<()> {
    use std::collections::HashMap;
    if bindings.len() != meta.devices.len() {
        return Err(Error::Invalid("share binding count differs"));
    }
    let mut references = HashMap::new();
    let mut identities = HashMap::new();
    for ((device, session), binding) in meta.devices.iter().zip(&meta.sessions).zip(bindings) {
        check_source(&binding.root)?;
        bound_session(session, binding, device.vm_owned)?;
        if device.vm_owned {
            continue;
        }
        for (file, saved) in binding.objects.iter().zip(&session.objects) {
            let identity = file
                .as_ref()
                .map(|file| file.metadata().map(|st| (st.dev(), st.ino())))
                .transpose()?;
            if references
                .insert(saved.alias, identity)
                .is_some_and(|old| old != identity)
                || identity.is_some_and(|identity| {
                    identities
                        .insert(identity, saved.alias)
                        .is_some_and(|old| old != saved.alias)
                })
            {
                return Err(Error::Invalid(
                    "external object aliases disagree across shares (identity or presence)",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn restore_external(
    vm: &mut RamSnapshotVm,
    file: &mut File,
    meta: &FsMeta,
    bindings: Vec<crate::snapshot_vm::checkpoint::ShareBinding>,
) -> Result<()> {
    if bindings.len() != meta.devices.len() {
        return Err(Error::Invalid("share binding count differs"));
    }
    vm.exit_code.store(meta.exit_code, Ordering::SeqCst);
    for (index, ((device_meta, session), binding)) in meta
        .devices
        .iter()
        .zip(&meta.sessions)
        .zip(bindings)
        .enumerate()
    {
        let mut init = vec![0; session.init_len as usize];
        file.read_exact(&mut init)?;
        let mut pages = DaxPages {
            offsets: session.dax_offsets.clone(),
            data: vec![0; session.dax_offsets.len() * 4096],
        };
        file.read_exact(&mut pages.data)?;
        if let Some(dax) = &session.state.dax {
            pages
                .validate(dax)
                .map_err(|e| Error::Full(e.to_string()))?;
        }
        let (state, objects, roles) = bound_session(session, &binding, device_meta.vm_owned)?;
        let root = binding.root.clone();
        drop(binding);
        let dax = device_meta
            .dax
            .map(|range| -> Result<_> { Ok((range, add_window(vm, range)?)) })
            .transpose()?;
        let window = dax.map(|(range, backing)| vm.dax[backing].region(range.gpa));
        let (device, transport) = new_device(
            vm,
            Share {
                tag: &device_meta.tag,
                root: root.clone(),
                read_only: device_meta.read_only,
                allow_root_dir_delete: device_meta.allow_root_dir_delete,
                vm_owned: device_meta.vm_owned,
                exit_code: vm.exit_code.clone(),
                window,
            },
        )?;
        let result = (|| {
            let mut locked = device.lock().unwrap();
            locked.set_acked_features(device_meta.device.acked_features);
            locked
                .restore_session_with_roles(
                    session.options,
                    &state,
                    objects,
                    Arc::from(init),
                    &pages,
                    roles,
                )
                .map_err(|e| Error::Full(e.to_string()))?;
            drop(locked);
            let mut locked = transport.lock().unwrap();
            locked.restore_transport_state(
                &device_meta.transport,
                device_meta
                    .device
                    .queues
                    .iter()
                    .map(QueueState::to_queue)
                    .collect(),
            );
            if device_meta.device.activated {
                locked
                    .activate_restored()
                    .map_err(|e| Error::Full(format!("activate external share: {e:?}")))?;
            }
            drop(locked);
            wiring::register_device(vm, &transport, device_meta.mmio_addr, device_meta.irq)
        })();
        if let Err(error) = result {
            discard(vm, &device, dax.map(|(_, backing)| backing));
            return Err(error);
        }
        if !device_meta.vm_owned {
            vm.restored_shares
                .push((device_meta.tag.clone(), root.clone()));
        }
        vm.fs.push(FsDevice {
            device,
            transport,
            index,
            tag: device_meta.tag.clone(),
            read_only: device_meta.read_only,
            allow_root_dir_delete: device_meta.allow_root_dir_delete,
            recipe_root: device_meta.vm_owned.then_some(root),
            vm_owned_root: None,
            dax,
        });
    }
    Ok(())
}

#[cfg(test)]
mod kvm_tests;
#[cfg(test)]
pub(super) mod tests;
