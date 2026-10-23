// SPDX-License-Identifier: Apache-2.0

//! Internal stage-3 block checkpoints: attach, freeze, capture and restore
//! for the private minimal-VM owner. No public BoxLite entry point.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as IoRead, Write as IoWrite};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use devices::virtio::block::device::VIRTIO_BLK_CONFIG_SIZE;
use devices::virtio::block::{
    snapshot_offered_features, snapshot_sync_mode, Block, ImageType, SyncMode,
};
use devices::virtio::persist::{MmioTransportState, QueueState, VirtioDeviceState};
use devices::virtio::{CacheType, MmioTransport, VirtioDevice, TYPE_BLOCK};
use kvm_ioctls::IoEventAddress;
use serde::{Deserialize, Serialize};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use super::{Error, RamSnapshotVm, Region, Result, CHUNK_SIZE};

/// Fixed internal MMIO window for snapshot disks, above ordinary guest RAM.
pub(super) const MMIO_BASE: u64 = 0xd000_0000;
pub(super) const MMIO_LEN: u64 = 0x1000;
/// Kernel-irqchip GSI space below this is reserved for legacy devices.
pub(super) const IRQ_BASE: u32 = 16;
pub(super) const IRQ_LAST: u32 = 23;
pub(super) const MAX_DISKS: usize = (IRQ_LAST - IRQ_BASE + 1) as usize;
const BLK_ID_BYTES: usize = 20;
const SECTOR_SIZE: u64 = 512;
const QUEUE_MAX_SIZE: u16 = 256;
/// device_status::DRIVER_OK, duplicated because the const is module-private
/// in the devices crate.
const DRIVER_OK: u32 = 0b0100;

/// A block device attached to the minimal VM owner.
pub(super) struct BlkDevice {
    pub(super) mmio_addr: u64,
    pub(super) irq: u32,
    pub(super) block: Arc<Mutex<Block>>,
    pub(super) transport: Arc<Mutex<MmioTransport>>,
}

impl BlkDevice {
    /// Stop and join the worker (no-op for inactive devices).
    fn stop(&self) {
        let _ = self.block.lock().unwrap().reset();
    }
}

/// Per-disk snapshot metadata; one ordered raw segment follows the RAM
/// payload for each entry. No host path ever appears here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiskMeta {
    pub(super) mmio_addr: u64,
    pub(super) mmio_len: u64,
    pub(super) irq: u32,
    pub(super) device_id: String,
    pub(super) transport: MmioTransportState,
    pub(super) device: VirtioDeviceState,
    pub(super) config: Vec<u8>,
    pub(super) image_id: Vec<u8>,
    pub(super) read_only: bool,
    pub(super) cache_writeback: bool,
    pub(super) disk_bytes: u64,
}

/// How many `GuestMemoryMmap` clones the owner's own devices legitimately
/// hold: each transport one, plus the device state and the worker once a
/// device is activated. External aliases are never part of the count.
pub(super) fn expected_alias_clones(vm: &RamSnapshotVm) -> usize {
    vm.disks
        .iter()
        .map(|device| 1 + usize::from(device.block.lock().unwrap().is_activated()) * 2)
        .sum()
}

/// Metadata-only validation: everything checkable before guest RAM or any
/// target resource exists.
pub(super) fn validate_disk_metadata(disks: &[DiskMeta], regions: &[Region]) -> Result<()> {
    if disks.len() > MAX_DISKS {
        return Err(Error::Invalid(
            "snapshot disk count exceeds the internal window",
        ));
    }
    let mut ids = HashSet::new();
    let mut addrs = HashSet::new();
    let mut irqs = HashSet::new();
    for disk in disks {
        let in_window = disk.mmio_addr >= MMIO_BASE
            && disk.mmio_addr % MMIO_LEN == 0
            && disk.mmio_addr < MMIO_BASE + MAX_DISKS as u64 * MMIO_LEN
            && disk.mmio_len == MMIO_LEN;
        let legal_irq = (IRQ_BASE..=IRQ_LAST).contains(&disk.irq);
        let legal_id = !disk.device_id.is_empty() && disk.device_id.len() <= 128;
        if !in_window || !legal_irq || !legal_id || !ids.insert(disk.device_id.clone()) {
            return Err(Error::Invalid(
                "disk MMIO/IRQ is outside the internal window or the identity is duplicated",
            ));
        }
        if !addrs.insert(disk.mmio_addr) || !irqs.insert(disk.irq) {
            return Err(Error::Invalid(
                "disk MMIO/IRQ conflicts with another device",
            ));
        }
        for region in regions {
            let end = region.gpa + region.len;
            if disk.mmio_addr < end && region.gpa < disk.mmio_addr + disk.mmio_len {
                return Err(Error::Invalid("disk MMIO range overlaps guest RAM"));
            }
        }
        if disk.config.len() != VIRTIO_BLK_CONFIG_SIZE || disk.image_id.len() != BLK_ID_BYTES {
            return Err(Error::Invalid(
                "disk config/identity bytes have an unsupported length",
            ));
        }
        if disk.disk_bytes == 0 || disk.disk_bytes % SECTOR_SIZE != 0 {
            return Err(Error::Invalid(
                "disk segment length is not a sector multiple",
            ));
        }
        // Capacity multiplication must reproduce the exact segment length.
        let capacity = u64::from_le_bytes(disk.config[0..8].try_into().unwrap());
        if capacity
            .checked_mul(SECTOR_SIZE)
            .is_none_or(|bytes| bytes != disk.disk_bytes)
        {
            return Err(Error::Invalid(
                "disk capacity does not match the captured segment length",
            ));
        }
        disk.transport.validate().map_err(|_| {
            Error::Invalid("disk transport registers are outside the state machine")
        })?;
        disk.device
            .validate_structure(TYPE_BLOCK, 1, QUEUE_MAX_SIZE)
            .map_err(|_| Error::Invalid("disk virtio state is structurally inconsistent"))?;
        // Offered features must be exactly what an internal disk can offer
        // (the devices crate owns the bit set): the read-only bit must agree
        // with the serialized read_only flag, and no foreign feature may
        // appear, before any RAM or file is created on the target.
        if disk.device.avail_features != snapshot_offered_features(disk.read_only) {
            return Err(Error::Invalid(
                "disk offers features outside the internal block contract",
            ));
        }
        // The transport and the device must agree on activation: DRIVER_OK is
        // exactly what handed the queues to the worker.
        if (disk.transport.device_status & DRIVER_OK != 0) != disk.device.activated {
            return Err(Error::Invalid(
                "disk activation disagrees with the transport status",
            ));
        }
    }
    Ok(())
}

/// Ring-level validation against the loaded guest RAM; runs after read_ram
/// and before the destination directory is created.
pub(super) fn validate_disk_rings(disks: &[DiskMeta], memory: &GuestMemoryMmap) -> Result<()> {
    for disk in disks {
        disk.device
            .validate(memory, TYPE_BLOCK, 1, QUEUE_MAX_SIZE)
            .map_err(|_| Error::Invalid("disk virtio state is inconsistent with guest RAM"))?;
    }
    Ok(())
}

/// Attach one internal disk before vCPUs start. Ordinary regular files
/// readable through the existing imago RAW/QCOW2/VMDK backends are supported.
/// Caller precondition: the source disk file AND every backing file in its
/// chain must have no writers outside this private owner for the lifetime of
/// the attachment — a consistent cut assumes sole ownership; no lock or
/// lease is taken here. Any failure poisons the owner for further snapshots.
pub(super) fn attach_disk(
    vm: &mut RamSnapshotVm,
    path: &Path,
    format: ImageType,
    read_only: bool,
    writeback: bool,
) -> Result<()> {
    if vm.control.unusable {
        return Err(Error::Invalid(
            "internal disks cannot attach to an unusable snapshot owner",
        ));
    }
    if !vm.handles.is_empty() {
        return Err(Error::Invalid(
            "internal disks attach only before vCPU start",
        ));
    }
    if vm.disks.len() >= vm.disk_capacity() {
        return Err(Error::Invalid("internal disk window is full"));
    }
    // Reject nonregular sources before anything is opened or registered.
    if !fs::metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        return Err(Error::Invalid("internal disk source is not a regular file"));
    }
    let attach = (|| -> Result<BlkDevice> {
        // The stage-2 alias protection, parameterized by the clones the
        // already-attached devices legitimately hold (none activated here:
        // no guest has run yet).
        vm.probe_ram_aliases(vm.expected_device_clones())?;
        let index = vm.disks.len();
        let mmio_addr = MMIO_BASE + index as u64 * MMIO_LEN;
        let irq = IRQ_BASE + index as u32;
        // The fixed window must never reach into guest RAM.
        for region in vm.memory.iter() {
            let start = region.start_addr().raw_value();
            let end = start + region.len();
            if mmio_addr < end && start < mmio_addr + MMIO_LEN {
                return Err(Error::Invalid(
                    "internal disk MMIO window overlaps guest RAM",
                ));
            }
        }
        let ioapic = vm.ensure_kernel_irqchip()?;
        let cache = if writeback {
            CacheType::Writeback
        } else {
            CacheType::Unsafe
        };
        let path = path
            .to_str()
            .ok_or_else(|| Error::Invalid("disk path is not valid UTF-8"))?
            .to_string();
        let block = Block::new(
            format!("blk{index}"),
            None,
            cache,
            path,
            format,
            read_only,
            false,
            SyncMode::Full,
        )
        .map_err(|e| Error::Full(format!("open internal disk: {e}")))?;
        let block = Arc::new(Mutex::new(block));
        let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(
            devices::legacy::IrqChipDevice::new(Box::new(ioapic)),
        ));
        let transport = Arc::new(Mutex::new(
            MmioTransport::new(vm.memory.clone(), intc, block.clone())
                .map_err(|e| Error::Full(format!("create block transport: {e}")))?,
        ));
        register_device(vm, &transport, mmio_addr, irq)?;
        Ok(BlkDevice {
            mmio_addr,
            irq,
            block,
            transport,
        })
    })();
    match attach {
        Ok(device) => {
            vm.disks.push(device);
            Ok(())
        }
        Err(error) => {
            // A partially registered device must never reach a snapshot.
            vm.control.unusable = true;
            Err(error)
        }
    }
}

/// Register ioeventfd/irqfd at a fixed address and IRQ and put the transport
/// on the bus. On failure every registration made here is rolled back.
pub(super) fn register_device(
    vm: &mut RamSnapshotVm,
    transport: &Arc<Mutex<MmioTransport>>,
    mmio_addr: u64,
    irq: u32,
) -> Result<()> {
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
            Error::Full(format!("insert disk on MMIO bus: {e:?}"))
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

/// Freeze every disk: each freeze lands after the in-flight request
/// finished its status write, used-ring update and interrupt, and the disk
/// was flushed and synced regardless of the guest cache mode. Inactive
/// devices hold no worker; their shared image is flushed directly. Returns
/// the frozen worker queue per disk (None when inactive).
pub(super) fn freeze_disks(vm: &RamSnapshotVm) -> Result<Vec<Option<QueueState>>> {
    let mut frozen_queues = Vec::with_capacity(vm.disks.len());
    for (index, device) in vm.disks.iter().enumerate() {
        let block = device.block.lock().unwrap();
        let frozen_queue = if block.is_activated() {
            let handle = block
                .worker_control()
                .ok_or_else(|| Error::Invalid("activated block device has no worker control"))?;
            Some(
                handle
                    .freeze()
                    .map_err(|e| Error::Full(format!("freeze disk {index}: {e}")))?,
            )
        } else {
            let image = block.shared_image();
            image
                .lock()
                .unwrap()
                .flush()
                .map_err(|e| Error::Full(format!("flush inactive disk {index}: {e}")))?;
            image
                .lock()
                .unwrap()
                .sync()
                .map_err(|e| Error::Full(format!("sync inactive disk {index}: {e}")))?;
            None
        };
        frozen_queues.push(frozen_queue);
    }
    Ok(frozen_queues)
}

/// Deassign every disk irqfd and drain its count. KVM_IRQFD DEASSIGN
/// flushes the injection workqueue before returning (Linux v6.12
/// virt/kvm/eventfd.c contract), so the transport interrupt status includes
/// every completed injection afterwards. `drained` records each deassigned
/// disk even on failure, so recovery reassigns exactly those.
pub(super) fn drain_disk_irqfds(vm: &RamSnapshotVm, drained: &mut Vec<usize>) -> Result<()> {
    for (index, device) in vm.disks.iter().enumerate() {
        let transport = device.transport.lock().unwrap();
        vm.vm
            .fd()
            .unregister_irqfd(transport.interrupt_evt(), device.irq)
            .map_err(|e| Error::Full(format!("deassign irqfd {index}: {e}")))?;
        drained.push(index);
        drain_eventfd_count(transport.interrupt_evt());
    }
    Ok(())
}

/// Capture every frozen, drained disk and validate the result against the
/// rings in guest RAM.
pub(super) fn capture_disks(
    vm: &RamSnapshotVm,
    frozen_queues: &[Option<QueueState>],
    regions: &[Region],
) -> Result<Vec<DiskMeta>> {
    let mut metas = Vec::with_capacity(vm.disks.len());
    for (index, device) in vm.disks.iter().enumerate() {
        let transport = device.transport.lock().unwrap();
        let block = device.block.lock().unwrap();
        let queues = match &frozen_queues[index] {
            Some(state) => vec![state.clone()],
            None => transport.queue_states(),
        };
        let disk_bytes = block
            .nsectors()
            .checked_mul(SECTOR_SIZE)
            .ok_or(Error::Invalid("disk capacity overflow"))?;
        metas.push(DiskMeta {
            mmio_addr: device.mmio_addr,
            mmio_len: MMIO_LEN,
            irq: device.irq,
            device_id: block.id().clone(),
            transport: transport.save_transport_state(),
            device: VirtioDeviceState {
                device_type: TYPE_BLOCK,
                avail_features: block.avail_features(),
                acked_features: block.acked_features(),
                queues,
                activated: block.is_activated(),
            },
            config: block.config_bytes(),
            image_id: block.image_id().to_vec(),
            read_only: block.is_read_only(),
            cache_writeback: matches!(block.cache_type(), CacheType::Writeback),
            disk_bytes,
        });
    }
    validate_disk_metadata(&metas, regions)?;
    validate_disk_rings(&metas, &vm.memory)?;
    Ok(metas)
}

/// Reassign every drained irqfd; a single failure must not skip the rest.
pub(super) fn reassign_irqfds(vm: &RamSnapshotVm, drained: &[usize]) -> Result<()> {
    let mut first = None;
    for index in drained {
        let device = &vm.disks[*index];
        let transport = device.transport.lock().unwrap();
        if let Err(e) = vm
            .vm
            .fd()
            .register_irqfd(transport.interrupt_evt(), device.irq)
        {
            if first.is_none() {
                first = Some(Error::Full(format!("reassign irqfd {index}: {e}")));
            }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Resume every active worker; each resume actively re-examines its queue.
/// A single dead worker must not leave the other frozen devices stuck too.
pub(super) fn resume_devices(vm: &RamSnapshotVm) -> Result<()> {
    let mut first = None;
    for (index, device) in vm.disks.iter().enumerate() {
        let block = device.block.lock().unwrap();
        if let Some(handle) = block.worker_control() {
            if let Err(e) = handle.resume() {
                if first.is_none() {
                    first = Some(Error::Full(format!("resume disk {index}: {e}")));
                }
            }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Copy the frozen logical capacity of every disk into the snapshot file.
pub(super) fn copy_disk_segments(
    file: &mut File,
    disks: &[BlkDevice],
    metas: &[DiskMeta],
) -> Result<()> {
    let mut buffer = vec![0; CHUNK_SIZE];
    for (device, meta) in disks.iter().zip(metas) {
        let block = device.block.lock().unwrap();
        let mut offset = 0;
        while offset < meta.disk_bytes {
            let len = ((meta.disk_bytes - offset).min(CHUNK_SIZE as u64)) as usize;
            let read = block
                .read_snapshot_chunk(offset, &mut buffer[..len])
                .map_err(|e| Error::Full(format!("read disk segment at {offset}: {e}")))?;
            if read != len {
                return Err(Error::Full(format!(
                    "short read from disk segment at {offset}"
                )));
            }
            #[cfg(test)]
            super::tests::write_payload(file, &buffer[..len])?;
            #[cfg(not(test))]
            file.write_all(&buffer[..len])?;
            offset += len as u64;
        }
    }
    Ok(())
}

/// Exclusive owner of the imported destination directory and the numbered
/// raw files created inside it. Removal happens only for resources this
/// guard itself created: a pre-existing directory is an error and is never
/// modified or removed.
pub(super) struct ImportedDir {
    path: PathBuf,
    files: Vec<PathBuf>,
}

impl ImportedDir {
    /// Create the new 0700 destination directory exclusively.
    fn create(path: &Path) -> Result<Self> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|e| Error::Full(format!("create import destination: {e}")))?;
        Ok(Self {
            path: path.to_owned(),
            files: Vec::new(),
        })
    }

    /// Create the next exclusive 0600 numbered file; its path is tracked
    /// before any byte is written so partial writes are cleaned up too.
    fn create_segment_file(&mut self, index: usize) -> Result<File> {
        let path = self.path.join(format!("disk-{index}.raw"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::Full(format!("create imported disk: {e}")))?;
        self.files.push(path);
        Ok(file)
    }
}

impl Drop for ImportedDir {
    fn drop(&mut self) {
        for path in &self.files {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(&self.path);
    }
}

/// Import disk segments into a new destination directory as exclusive 0600
/// numbered raw files, in bounded chunks. Metadata never provides host
/// paths. On failure the returned guard is dropped and removes everything
/// this import created; success hands the guard to the owner.
pub(super) fn import_disks(
    source: &mut File,
    metas: &[DiskMeta],
    destination: &Path,
) -> Result<(ImportedDir, Vec<PathBuf>)> {
    let mut dir = ImportedDir::create(destination)?;
    let import = (|| -> Result<Vec<PathBuf>> {
        let mut buffer = vec![0; CHUNK_SIZE];
        let mut paths = Vec::with_capacity(metas.len());
        for (index, meta) in metas.iter().enumerate() {
            let mut file = dir.create_segment_file(index)?;
            let path = destination.join(format!("disk-{index}.raw"));
            let mut offset = 0;
            while offset < meta.disk_bytes {
                let len = ((meta.disk_bytes - offset).min(CHUNK_SIZE as u64)) as usize;
                source
                    .read_exact(&mut buffer[..len])
                    .map_err(|_| Error::Invalid("truncated disk segment"))?;
                #[cfg(test)]
                super::tests::write_payload(&mut file, &buffer[..len])?;
                #[cfg(not(test))]
                file.write_all(&buffer[..len])?;
                offset += len as u64;
            }
            file.sync_all()?;
            paths.push(path);
        }
        Ok(paths)
    })();
    match import {
        Ok(paths) => Ok((dir, paths)),
        Err(error) => {
            drop(dir);
            Err(error)
        }
    }
}

/// Rebuild frozen devices on the target VM at the saved address and IRQ,
/// using new eventfds; activated devices start with frozen workers. Every
/// started worker is joined again if any later step fails.
pub(super) fn restore_devices(
    vm: &mut RamSnapshotVm,
    metas: &[DiskMeta],
    paths: &[PathBuf],
) -> Result<()> {
    for (index, (meta, path)) in metas.iter().zip(paths).enumerate() {
        let ioapic = vm.ensure_kernel_irqchip()?;
        let cache = if meta.cache_writeback {
            CacheType::Writeback
        } else {
            CacheType::Unsafe
        };
        let mut block = Block::new(
            meta.device_id.clone(),
            None,
            cache,
            path.to_string_lossy().into_owned(),
            ImageType::Raw,
            meta.read_only,
            false,
            snapshot_sync_mode(meta.device.avail_features),
        )
        .map_err(|e| Error::Full(format!("open restored disk {index}: {e}")))?;
        // The rebuilt device must offer exactly the saved features: the
        // original guest flush/read-only semantics stay identical.
        if block.nsectors().checked_mul(SECTOR_SIZE) != Some(meta.disk_bytes)
            || block.avail_features() != meta.device.avail_features
        {
            return Err(Error::Invalid(
                "restored disk capacity or offered features differ from the snapshot",
            ));
        }
        block
            .restore_snapshot_identity(&meta.config, meta.image_id.clone())
            .map_err(|e| Error::Full(format!("restore disk {index} identity: {e:?}")))?;
        block.set_acked_features(meta.device.acked_features);
        let block = Arc::new(Mutex::new(block));
        let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(
            devices::legacy::IrqChipDevice::new(Box::new(ioapic)),
        ));
        let transport = Arc::new(Mutex::new(
            MmioTransport::new(vm.memory.clone(), intc, block.clone())
                .map_err(|e| Error::Full(format!("create restored transport {index}: {e}")))?,
        ));
        {
            let mut locked = transport.lock().unwrap();
            locked.restore_transport_state(
                &meta.transport,
                meta.device.queues.iter().map(|q| q.to_queue()).collect(),
            );
            if meta.device.activated {
                // From here a worker thread exists: on any failure below it
                // must be stopped and joined, never detached.
                if let Err(error) = locked.activate_restored() {
                    let _ = block.lock().unwrap().reset();
                    return Err(Error::Full(format!(
                        "restore-activate disk {index} failed: {error:?}"
                    )));
                }
            }
        }
        if let Err(error) = register_device(vm, &transport, meta.mmio_addr, meta.irq) {
            // Join the freshly started worker and drop the device.
            let _ = block.lock().unwrap().reset();
            return Err(error);
        }
        vm.disks.push(BlkDevice {
            mmio_addr: meta.mmio_addr,
            irq: meta.irq,
            block,
            transport,
        });
    }
    Ok(())
}

/// Stop and join every worker; used by owner drop and failed restores.
pub(super) fn stop_devices(vm: &RamSnapshotVm) {
    for device in &vm.disks {
        device.stop();
    }
}

#[cfg(test)]
mod tests;

/// Read the current eventfd count without blocking, if any.
pub(super) fn drain_eventfd_count(fd: &utils::eventfd::EventFd) {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pollfd` is exclusively borrowed for the duration of the call.
    let ready = unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, 0) };
    if ready > 0 && pollfd.revents & libc::POLLIN != 0 {
        let _ = fd.read();
    }
}
