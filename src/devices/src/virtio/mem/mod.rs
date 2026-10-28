// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from Firecracker d9f9a57 src/vmm/src/devices/virtio/mem/device.rs.
// Uses libkrun's transport and applies each intersecting slot before committing
// its block state, including when an update fails partway through a request.

mod control;
mod region;

pub use control::{MemoryControl, MemoryStatus, SLOT_MIB, SLOT_SIZE};
pub use region::HotplugRegion;

use std::ops::Range;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice,
};
use control::{BLOCK_SIZE, MIB};
use super::persist::QueueState;

/// Guest block ownership and the host target are distinct from mapped KVM slots.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemSnapshot {
    pub addr: u64,
    pub size: u64,
    pub initial_mib: u32,
    pub status: MemoryStatus,
    pub requested_size: u64,
    pub usable_region_size: u64,
    pub plugged: Vec<bool>,
}

impl MemSnapshot {
    pub fn validate(&self) -> std::io::Result<()> {
        let invalid = || std::io::Error::from_raw_os_error(libc::EINVAL);
        let s = &self.status;
        if self.initial_mib == 0 || self.size == 0 || self.size % SLOT_SIZE != 0
            || self.addr < (1 << 32) || self.addr % SLOT_SIZE != 0
            || self.addr.checked_add(self.size).is_none_or(|end| end > (1 << 52))
            || self.size / MIB + u64::from(self.initial_mib) != u64::from(s.max_mib)
            || self.plugged.len() as u64 != self.size / BLOCK_SIZE
            || s.active > 1 || s.error < 0
            || s.requested_mib < self.initial_mib || s.requested_mib > s.max_mib
            || (s.requested_mib - self.initial_mib) % SLOT_MIB != 0
            || self.requested_size > u64::from(s.requested_mib - self.initial_mib) * MIB
            || self.requested_size % SLOT_SIZE != 0
            || self.usable_region_size > self.size
            || self.usable_region_size % BLOCK_SIZE != 0
            || self.usable_region_size < self.requested_size && self.usable_region_size != 0
            || s.active == 0 && (s.requested_mib != self.initial_mib
                || self.requested_size != 0 || self.usable_region_size != 0 || s.plugged_mib != self.initial_mib)
        { return Err(invalid()); }
        let plugged = self.plugged.iter().filter(|&&b| b).count() as u64 * BLOCK_SIZE;
        let mapped = self.mapped_slots().count() as u64 * SLOT_SIZE;
        if plugged > self.requested_size
            || self.plugged.iter().enumerate().any(|(i, &b)| b && (i as u64 + 1) * BLOCK_SIZE > self.usable_region_size)
            || plugged / MIB + u64::from(self.initial_mib) != u64::from(s.plugged_mib)
            || mapped / MIB + u64::from(self.initial_mib) != u64::from(s.mapped_mib)
        { return Err(invalid()); }
        Ok(())
    }

    pub fn mapped_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.plugged.chunks((SLOT_SIZE / BLOCK_SIZE) as usize)
            .enumerate().filter_map(|(i, blocks)| blocks.iter().any(|&b| b).then_some(i))
    }
}
const QUEUES: [QueueConfig; 1] = [QueueConfig::new(128)];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Config {
    block_size: u64,
    node_id: u16,
    padding: [u8; 6],
    addr: u64,
    region_size: u64,
    usable_region_size: u64,
    plugged_size: u64,
    requested_size: u64,
}
// All fields are integers; the explicit padding covers the wire layout.
unsafe impl ByteValued for Config {}

pub struct Mem {
    control: Arc<MemoryControl>,
    region: HotplugRegion,
    config: Config,
    plugged: Vec<bool>,
    acked_features: u64,
    activate_evt: EventFd,
    state: DeviceState,
    queue: Option<DeviceQueue>,
}

impl Mem {
    pub fn control(&self) -> Arc<MemoryControl> { self.control.clone() }

    pub fn snapshot(&self) -> MemSnapshot {
        MemSnapshot {
            addr: self.region.addr, size: self.region.size,
            initial_mib: self.control.initial_mib, status: self.control.status(),
            requested_size: self.config.requested_size,
            usable_region_size: self.config.usable_region_size,
            plugged: self.plugged.clone(),
        }
    }

    pub fn restore_snapshot(&mut self, state: &MemSnapshot) -> std::io::Result<()> {
        state.validate()?;
        if self.region.addr != state.addr || self.region.size != state.size {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        for slot in state.mapped_slots() { self.region.update_slot(slot, true)?; }
        self.config.plugged_size = u64::from(state.status.plugged_mib - state.initial_mib) * MIB;
        self.config.requested_size = state.requested_size;
        self.config.usable_region_size = state.usable_region_size;
        self.plugged.clone_from(&state.plugged);
        self.control.restore(state.status);
        Ok(())
    }

    pub fn snapshot_queue_states(&self) -> Option<Vec<QueueState>> {
        self.queue.as_ref().map(|q| vec![QueueState::from_queue(&q.queue)])
    }

    /// Reissue both target and queue notifications lost with source eventfds.
    pub fn snapshot_kick(&self) {
        // UNPLUG_ALL may intentionally leave usable size zero with an unchanged
        // host target. Replay only a target not yet consumed at the saved cut.
        let target = u64::from(self.control.status().requested_mib - self.control.initial_mib) * MIB;
        if target != self.config.requested_size { let _ = self.control.event.write(1); }
        if let Some(queue) = &self.queue { let _ = queue.event.write(1); }
    }

    pub fn new(control: Arc<MemoryControl>, region: HotplugRegion) -> std::io::Result<Self> {
        control.initialize(region.size);
        Ok(Self {
            config: Config {
                block_size: BLOCK_SIZE,
                addr: region.addr,
                region_size: region.size,
                ..Default::default()
            },
            plugged: vec![false; (region.size / BLOCK_SIZE) as usize],
            region,
            control,
            acked_features: 0,
            activate_evt: EventFd::new(EFD_NONBLOCK)?,
            state: DeviceState::Inactive,
            queue: None,
        })
    }

    fn requested_range(&self, addr: u64, blocks: u16) -> Option<Range<usize>> {
        let offset = addr.checked_sub(self.config.addr)?;
        let end = offset.checked_add(u64::from(blocks) * BLOCK_SIZE)?;
        if blocks == 0 || offset % BLOCK_SIZE != 0 || end > self.config.usable_region_size {
            return None;
        }
        Some((offset / BLOCK_SIZE) as usize..(end / BLOCK_SIZE) as usize)
    }

    fn range_state(&self, range: Range<usize>) -> u16 {
        let count = self.plugged[range.clone()].iter().filter(|&&v| v).count();
        if count == range.len() {
            0
        } else if count == 0 {
            1
        } else {
            2
        }
    }

    fn update_range(&mut self, range: Range<usize>, plug: bool) -> std::io::Result<()> {
        if range.is_empty() {
            return Ok(());
        }
        let blocks_per_slot = (SLOT_SIZE / BLOCK_SIZE) as usize;
        for slot in range.start / blocks_per_slot..=(range.end - 1) / blocks_per_slot {
            let whole = slot * blocks_per_slot..(slot + 1) * blocks_per_slot;
            let touched = whole.start.max(range.start)..whole.end.min(range.end);
            let keep = whole.clone().any(|b| {
                if touched.contains(&b) {
                    plug
                } else {
                    self.plugged[b]
                }
            });
            self.region.update_slot(slot, keep)?;
            let before = self.plugged[touched.clone()].iter().filter(|&&v| v).count();
            self.plugged[touched.clone()].fill(plug);
            let after = if plug { touched.len() } else { 0 };
            self.config.plugged_size =
                self.config.plugged_size - before as u64 * BLOCK_SIZE + after as u64 * BLOCK_SIZE;
            if !plug && before != 0 {
                self.region.discard(
                    touched.start as u64 * BLOCK_SIZE,
                    touched.len() as u64 * BLOCK_SIZE,
                );
            }
        }
        Ok(())
    }

    fn request(&mut self, kind: u16, addr: u64, blocks: u16) -> (u16, u16) {
        if kind == 2 {
            return match self.update_range(0..self.plugged.len(), false) {
                Ok(()) => {
                    // requested_size remains a host-owned, grow-only target.
                    self.config.usable_region_size = 0;
                    (0, 0)
                }
                Err(error) => {
                    self.report_error(error);
                    (2, 0)
                }
            };
        }
        let Some(range) = self.requested_range(addr, blocks) else {
            return (3, 0);
        };
        let state = self.range_state(range.clone());
        if kind == 3 {
            return (0, state);
        }
        if kind > 1 || (kind == 0 && state != 1) || (kind == 1 && state != 0) {
            return (3, 0);
        }
        if kind == 0
            && self.config.plugged_size + range.len() as u64 * BLOCK_SIZE
                > self.config.requested_size
        {
            return (1, 0);
        }
        match self.update_range(range, kind == 0) {
            Ok(()) => (0, 0),
            Err(error) => {
                self.report_error(error);
                (2, 0)
            }
        }
    }

    fn report_error(&self, error: std::io::Error) {
        error!("virtio-mem update failed: {error}");
        self.control.progress(
            self.config.plugged_size,
            self.region.mapped_size(),
            error.raw_os_error().unwrap_or(libc::EIO),
        );
    }

    fn process_queue(&mut self) {
        let DeviceState::Activated(mem, _) = &self.state else {
            return;
        };
        let mem = mem.clone();
        loop {
            let Some(head) = self.queue.as_mut().unwrap().queue.pop(&mem) else {
                break;
            };
            let index = head.index;
            let mut request = [0u8; 24];
            let mut used = 0;
            if !head.is_write_only()
                && head.len >= 24
                && mem.read_slice(&mut request, head.addr).is_ok()
            {
                if let Some(resp) = head.next_descriptor() {
                    if resp.is_write_only() && resp.len >= 10 {
                        let kind = u16::from_le_bytes(request[0..2].try_into().unwrap());
                        let addr = u64::from_le_bytes(request[8..16].try_into().unwrap());
                        let blocks = u16::from_le_bytes(request[16..18].try_into().unwrap());
                        let (kind, state) = self.request(kind, addr, blocks);
                        let mut response = [0u8; 10];
                        response[0..2].copy_from_slice(&kind.to_le_bytes());
                        response[8..10].copy_from_slice(&state.to_le_bytes());
                        if mem.write_slice(&response, resp.addr).is_ok() {
                            used = 10;
                        }
                    }
                }
            }
            if let Err(error) = self
                .queue
                .as_mut()
                .unwrap()
                .queue
                .add_used(&mem, index, used)
            {
                error!("virtio-mem used queue: {error:?}");
                break;
            }
        }
        self.publish_progress();
        self.state.signal_used_queue();
    }

    fn publish_progress(&self) {
        let error = self.control.status().error;
        self.control.progress(self.config.plugged_size, self.region.mapped_size(), error);
    }

    fn update_target(&mut self) {
        let target = self.control.status().requested_mib;
        self.config.requested_size = u64::from(target - self.control.initial_mib) * MIB;
        self.config.usable_region_size = self
            .config
            .usable_region_size
            .max(self.config.requested_size);
        if let DeviceState::Activated(_, interrupt) = &self.state {
            interrupt.signal_config_change();
        }
    }
}

impl VirtioDevice for Mem {
    fn avail_features(&self) -> u64 {
        (1 << 32) | (1 << 1)
    }
    fn acked_features(&self) -> u64 {
        self.acked_features
    }
    fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }
    fn device_type(&self) -> u32 {
        24
    }
    fn device_name(&self) -> &str {
        "virtio-mem"
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUES
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Both supported Linux architectures are little-endian.
        if let Some(bytes) = self.config.as_slice().get(offset as usize..) {
            let len = bytes.len().min(data.len());
            data[..len].copy_from_slice(&bytes[..len]);
        }
    }
    fn write_config(&mut self, _: u64, _: &[u8]) {}
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        mut queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != 1 {
            return Err(ActivateError::BadActivate);
        }
        self.queue = queues.pop();
        self.state = DeviceState::Activated(mem, interrupt);
        self.activate_evt
            .write(1)
            .map_err(|_| ActivateError::BadActivate)?;
        self.control.activate();
        Ok(())
    }
    fn is_activated(&self) -> bool {
        self.state.is_activated()
    }
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        // The owner's restored event thread stays frozen until resume;
        // activation only retains queues and posts its registration event.
        self.activate(mem, interrupt, queues)
    }
}

impl Subscriber for Mem {
    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![
            EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.control.event.as_raw_fd() as u64),
        ]
    }
    fn process(&mut self, event: &EpollEvent, manager: &mut EventManager) {
        if !event.event_set().contains(EventSet::IN) {
            return;
        }
        let fd = event.fd();
        if fd == self.activate_evt.as_raw_fd() {
            let _ = self.activate_evt.read();
            let subscriber = manager.subscriber(fd).unwrap();
            let queue_fd = self.queue.as_ref().unwrap().event.as_raw_fd();
            if let Err(error) = manager.register(
                queue_fd,
                EpollEvent::new(EventSet::IN, queue_fd as u64),
                subscriber,
            ) {
                error!("virtio-mem register queue: {error:?}");
            }
        } else if fd == self.control.event.as_raw_fd() {
            let _ = self.control.event.read();
            self.update_target();
        } else if self
            .queue
            .as_ref()
            .is_some_and(|q| q.event.as_raw_fd() == fd)
        {
            if self.queue.as_ref().unwrap().event.read().is_ok() {
                self.process_queue();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;

    #[test]
    fn checkpoint_kick_preserves_unplug_all_without_a_pending_target() {
        let mut device = device(0, 1, 1);
        assert_eq!(device.request(2, 0, 0).0, 0);
        device.control.event.read().unwrap();
        device.snapshot_kick();
        assert!(device.control.event.read().is_err());
        assert_eq!(device.config.usable_region_size, 0);
    }

    #[test]
    fn checkpoint_restores_partial_slots_and_pending_target_then_accepts_growth() {
        let mut source = device(0, 3, 2);
        assert_eq!(source.request(0, source.config.addr, 1).0, 0);
        assert_eq!(source.request(0, source.config.addr + SLOT_SIZE, 1).0, 0);
        source.publish_progress();
        // Freeze a target not yet consumed by the event thread.
        source.control.request(256 + 3 * SLOT_MIB).unwrap();
        source.control.freeze(true);
        let saved = source.snapshot();
        let mut target = device(0, 3, 1);
        target.restore_snapshot(&saved).unwrap();
        assert_eq!(target.region.mapped_size(), 2 * SLOT_SIZE);
        assert_eq!(target.config.plugged_size, 2 * BLOCK_SIZE);
        assert_eq!(target.config.requested_size, 2 * SLOT_SIZE);
        assert_eq!(target.control.status().requested_mib, 256 + 3 * SLOT_MIB);
        assert_eq!(target.control.request(256 + 3 * SLOT_MIB).unwrap_err().raw_os_error(), Some(libc::EBUSY));
        target.update_target();
        target.control.freeze(false);
        target.control.request(256 + 3 * SLOT_MIB).unwrap();
        assert_eq!(target.request(0, target.config.addr + 2 * SLOT_SIZE, 1).0, 0);
        assert_eq!(target.region.mapped_size(), 3 * SLOT_SIZE);
    }

    fn device(first_slot: u32, slots: u32, requested_slots: u32) -> Mem {
        let kvm = Kvm::new().unwrap();
        let vm = Arc::new(kvm.create_vm().unwrap());
        let control = Arc::new(MemoryControl::new(256, 256 + slots * SLOT_MIB).unwrap());
        let region =
            HotplugRegion::new(vm, first_slot, 1 << 32, u64::from(slots) * SLOT_SIZE).unwrap();
        let mut device = Mem::new(control, region).unwrap();
        device.control.activate();
        device
            .control
            .request(256 + requested_slots * SLOT_MIB)
            .unwrap();
        device.update_target();
        device
    }

    fn host_permissions(device: &Mem, offset: usize) -> String {
        let address = device.region.memory.as_ptr() as usize + offset;
        std::fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let (start, end) = fields.next()?.split_once('-')?;
                let start = usize::from_str_radix(start, 16).ok()?;
                let end = usize::from_str_radix(end, 16).ok()?;
                (start..end)
                    .contains(&address)
                    .then(|| fields.next().unwrap().to_owned())
            })
            .unwrap()
    }

    #[test]
    fn unallocated_slots_are_inaccessible_and_reject_guest_plugs() {
        let mut device = device(0, 2, 1);
        assert_eq!(host_permissions(&device, 0), "---p");
        assert_eq!(device.request(0, device.config.addr + SLOT_SIZE, 1).0, 3);
        assert_eq!(device.request(0, u64::MAX, 1).0, 3);
        assert_eq!(device.request(0, device.config.addr + 1, 1).0, 3);
        assert_eq!(device.request(0, device.config.addr, 0).0, 3);
        assert_eq!(device.region.mapped_size(), 0);
        assert_eq!(device.request(0, device.config.addr, 64).0, 0);
        assert_eq!(host_permissions(&device, 0), "rw-p");
        assert_eq!(host_permissions(&device, SLOT_SIZE as usize), "---p");
        assert_eq!(device.region.mapped_size(), SLOT_SIZE);
    }

    #[test]
    fn unplug_commits_only_intersecting_blocks_and_reprotects_empty_slots() {
        let mut device = device(0, 2, 2);
        let addr = device.config.addr + 60 * BLOCK_SIZE;
        assert_eq!(device.request(0, addr, 8).0, 0);
        assert_eq!(device.region.mapped_size(), 2 * SLOT_SIZE);
        assert_eq!(device.request(1, addr, 4).0, 0);
        assert_eq!(device.range_state(64..68), 0);
        assert_eq!(device.config.plugged_size, 4 * BLOCK_SIZE);
        assert_eq!(device.region.mapped_size(), SLOT_SIZE);
        assert_eq!(host_permissions(&device, 0), "---p");
        assert_eq!(host_permissions(&device, SLOT_SIZE as usize), "rw-p");
        assert_eq!(device.request(2, 0, 0).0, 0);
        assert_eq!(device.region.mapped_size(), 0);
        assert_eq!(device.config.plugged_size, 0);
        assert_eq!(host_permissions(&device, SLOT_SIZE as usize), "---p");
    }

    #[test]
    fn kvm_failure_preserves_committed_slot_and_leaves_failed_slot_unplugged() {
        let max_slots = Kvm::new().unwrap().get_nr_memslots() as u32;
        let mut device = device(max_slots - 1, 2, 2);
        assert!(device.update_range(0..128, true).is_err());
        assert_eq!(device.range_state(0..64), 0);
        assert_eq!(device.range_state(64..128), 1);
        assert_eq!(device.config.plugged_size, SLOT_SIZE);
        assert_eq!(device.region.mapped_size(), SLOT_SIZE);
        assert_eq!(host_permissions(&device, SLOT_SIZE as usize), "---p");
    }
}
