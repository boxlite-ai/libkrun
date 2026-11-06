// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::tests::VirtQueue;

const FEATURES: u64 = (1 << 32) | (1 << VIRTIO_RING_F_EVENT_IDX) | 1;
const CONFIG: [QueueConfig; 2] = [QueueConfig::new(8), QueueConfig::new(8)];

struct SnapshotDevice {
    features: u64,
    queues: Option<Vec<DeviceQueue>>,
}

impl VirtioDevice for SnapshotDevice {
    fn avail_features(&self) -> u64 {
        FEATURES
    }
    fn acked_features(&self) -> u64 {
        self.features
    }
    fn set_acked_features(&mut self, value: u64) {
        self.features = value;
    }
    fn device_type(&self) -> u32 {
        123
    }
    fn device_name(&self) -> &str {
        "snapshot-test"
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &CONFIG
    }
    fn read_config(&self, _offset: u64, _data: &mut [u8]) {}
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    fn is_activated(&self) -> bool {
        self.queues.is_some()
    }
    fn activate(
        &mut self,
        _mem: GuestMemoryMmap,
        _interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.queues = Some(queues);
        Ok(())
    }
}

fn new(mem: &GuestMemoryMmap) -> (MmioTransport, Arc<Mutex<SnapshotDevice>>) {
    let device = Arc::new(Mutex::new(SnapshotDevice {
        features: 0,
        queues: None,
    }));
    let transport =
        MmioTransport::new(mem.clone(), DummyIrqChip::new().into(), device.clone()).unwrap();
    (transport, device)
}

fn write(transport: &mut MmioTransport, offset: u64, value: u32) {
    transport.write(0, offset, &value.to_le_bytes());
}

fn read(transport: &mut MmioTransport, offset: u64) -> u32 {
    let mut data = [0; 4];
    transport.read(0, offset, &mut data);
    u32::from_le_bytes(data)
}

fn negotiate(transport: &mut MmioTransport) {
    write(transport, 0x70, 1);
    write(transport, 0x70, 3);
    write(transport, 0x20, FEATURES as u32);
    write(transport, 0x24, 1);
    write(transport, 0x20, (FEATURES >> 32) as u32);
    write(transport, 0x70, 11);
}

#[test]
fn inactive_transport_preserves_partial_registers_and_continues_negotiation() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let (mut source, _) = new(&mem);
    negotiate(&mut source);
    write(&mut source, 0x38, 3);
    write(&mut source, 0x80, 0xfffffff1);
    write(&mut source, 0x84, u32::MAX);
    write(&mut source, 0x44, 1);
    write(&mut source, 0x14, u32::MAX);
    write(&mut source, 0x24, 123);
    write(&mut source, 0x30, u32::MAX);
    write(&mut source, 0xac, 99);
    source.config_generation = u32::MAX;
    let state = source.save_state().unwrap();
    let (mut target, device) = new(&mem);
    target.restore_state(&state).unwrap();
    assert_eq!(target.save_state().unwrap(), state);
    assert!(!device.lock().unwrap().is_activated());
    assert_eq!(read(&mut target, 0x34), 0);
    assert_eq!(read(&mut target, 0x10), 0);
    assert_eq!(read(&mut target, 0xb0), u32::MAX);
    assert_eq!(read(&mut target, 0xfc), u32::MAX);
    // Continue from FEATURES_OK, without acknowledging features again.
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    target.queues.as_mut().unwrap()[0] = ring.create_queue();
    write(&mut target, 0x70, 15);
    assert!(device.lock().unwrap().is_activated());
    assert_eq!(device.lock().unwrap().features, FEATURES);
}

#[test]
fn active_transport_and_real_ring_continue_without_negotiation() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    ring.dtable[0].set(0x1000, 8, 0, 0);
    ring.dtable[1].set(0x2000, 4, 0, 0);
    ring.avail.ring[0].set(0);
    ring.avail.ring[1].set(1);
    ring.avail.idx.set(2);
    let (mut source, source_device) = new(&mem);
    negotiate(&mut source);
    source.queues.as_mut().unwrap()[0] = ring.create_queue();
    write(&mut source, 0x70, 15);
    let states: Vec<QueueState> = {
        let mut device = source_device.lock().unwrap();
        let queues = device.queues.as_mut().unwrap();
        let first = queues[0].queue.pop(&mem).unwrap().index;
        queues[0].queue.add_used(&mem, first, 8).unwrap();
        queues
            .iter()
            .map(|q| q.queue.save_state(&mem, true).unwrap())
            .collect()
    };
    source.interrupt.status().store(3, Ordering::SeqCst);
    write(&mut source, 0x14, 1);
    write(&mut source, 0x24, u32::MAX);
    write(&mut source, 0x30, 19);
    write(&mut source, 0xac, u32::MAX);
    let saved = source.save_state().unwrap();
    assert!(saved.queues.is_none());
    let (mut target, target_device) = new(&mem);
    assert!(target.restore_state(&saved).is_err());
    {
        let mut device = target_device.lock().unwrap();
        saved.device.restore_features(&mut *device).unwrap();
        let queues = saved.device.restore_queues(&states, &mem).unwrap();
        // Test device only stores queues; real devices must implement frozen activation.
        device
            .activate(
                mem.clone(),
                target.interrupt_transport(),
                queues
                    .into_iter()
                    .zip(target.queue_evts().iter().cloned())
                    .map(|(q, e)| DeviceQueue::new(q, e))
                    .collect(),
            )
            .unwrap();
    }
    target.restore_state(&saved).unwrap();
    assert_eq!(target.save_state().unwrap(), saved);
    assert_eq!(read(&mut target, 0x70), 15);
    assert_eq!(read(&mut target, 0x60), 3);
    write(&mut target, 0x64, 1);
    assert_eq!(read(&mut target, 0x60), 2);
    write(&mut target, 0x50, 0);
    let mut device = target_device.lock().unwrap();
    let queue = &mut device.queues.as_mut().unwrap()[0];
    assert_eq!(queue.event.read().unwrap(), 1);
    assert!(queue.queue.needs_notification(&mem).unwrap());
    assert_eq!(queue.queue.pop(&mem).unwrap().index, 1);
    queue.queue.add_used(&mem, 1, 4).unwrap();
    assert_eq!(ring.used.idx.get(), 2);
    assert_eq!(ring.used.ring[1].get().id, 1);
}

#[test]
fn invalid_restore_does_not_mutate_transport_or_features() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let (mut target, _) = new(&mem);
    let before = target.save_state().unwrap();
    let mut cases = Vec::new();
    let mut bad = before.clone();
    bad.device.device_type += 1;
    cases.push(bad);
    let mut bad = before.clone();
    bad.device.avail_features ^= 2;
    cases.push(bad);
    let mut bad = before.clone();
    bad.device.acked_features = 2;
    cases.push(bad);
    let mut bad = before.clone();
    bad.device.queue_max_sizes[0] = 16;
    cases.push(bad);
    let mut bad = before.clone();
    bad.queues.as_mut().unwrap().pop();
    cases.push(bad);
    let mut bad = before.clone();
    bad.queues.as_mut().unwrap()[0].next_used = 1;
    cases.push(bad);
    let mut bad = before.clone();
    bad.queues = None;
    cases.push(bad);
    for bad in cases {
        assert!(target.restore_state(&bad).is_err());
        assert_eq!(target.save_state().unwrap(), before);
    }
}

#[test]
fn active_features_and_queue_event_idx_must_agree() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let (mut source, device) = new(&mem);
    negotiate(&mut source);
    write(&mut source, 0x70, 15);
    let saved = source.save_state().unwrap();
    let states: Vec<_> = device
        .lock()
        .unwrap()
        .queues
        .as_ref()
        .unwrap()
        .iter()
        .map(|q| q.queue.save_state(&mem, true).unwrap())
        .collect();
    assert!(saved.device.restore_queues(&states, &mem).is_ok());
    let mut bad_states = states;
    bad_states[0].event_idx_enabled = false;
    assert!(saved.device.restore_queues(&bad_states, &mem).is_err());
    assert!(saved
        .device
        .restore_features(&mut *device.lock().unwrap())
        .is_err());
    let mut bad = saved.clone();
    bad.device.acked_features = 0;
    assert!(source.restore_state(&bad).is_err());
    assert_eq!(source.save_state().unwrap(), saved);
}
