// SPDX-License-Identifier: Apache-2.0

//! Event-thread controls with a real RNG and plain guest RAM, and the exit
//! watch with fake vCPU threads; no KVM. Test names contain "snapshot" for
//! `make snapshot-test`.

use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use devices::virtio::{Descriptor, DeviceQueue, InterruptTransport, Queue, VirtioDevice};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;

const QSIZE: u16 = 16;
const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const BUFS: u64 = 0x10000;

/// An activated RNG whose request queue the test drives as the driver.
struct Rig {
    mem: GuestMemoryMmap,
    rng: Arc<Mutex<Rng>>,
    notify: Arc<EventFd>,
    posted: u16,
}

impl Rig {
    fn new() -> Self {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let mut queue = Queue::new(QSIZE);
        queue.size = QSIZE;
        queue.ready = true;
        queue.desc_table = GuestAddress(DESC);
        queue.avail_ring = GuestAddress(AVAIL);
        queue.used_ring = GuestAddress(USED);
        let notify = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let intc: devices::legacy::IrqChip = Arc::new(Mutex::new(
            devices::legacy::IrqChipDevice::new(Box::new(devices::legacy::KvmIoapic {})),
        ));
        let mut rng = Rng::new().unwrap();
        rng.activate(
            mem.clone(),
            InterruptTransport::new(intc, "rng".into()).unwrap(),
            vec![DeviceQueue::new(queue, notify.clone())],
        )
        .unwrap();
        Self {
            mem,
            rng: Arc::new(Mutex::new(rng)),
            notify,
            posted: 0,
        }
    }

    fn spawn(&self, start: Start) -> EventThread {
        let devices = Devices {
            exit: Exit::new().unwrap(),
            rng: Some(self.rng.clone()),
            balloon: None,
            vsock: None,
            console: None,
            serials: Vec::new(),
        };
        EventThread::spawn(devices, start).unwrap()
    }

    /// Make one 64-byte request available without notifying the device.
    fn post(&mut self) {
        let slot = self.posted % QSIZE;
        let descriptor = Descriptor {
            addr: BUFS + 64 * u64::from(slot),
            len: 64,
            flags: 2, // VIRTQ_DESC_F_WRITE
            next: 0,
        };
        self.mem
            .write_obj(descriptor, GuestAddress(DESC + 16 * u64::from(slot)))
            .unwrap();
        self.mem
            .write_obj(slot, GuestAddress(AVAIL + 4 + 2 * u64::from(slot)))
            .unwrap();
        self.posted += 1;
        self.mem
            .write_obj(self.posted, GuestAddress(AVAIL + 2))
            .unwrap();
    }

    fn used(&self) -> u16 {
        self.mem.read_obj(GuestAddress(USED + 2)).unwrap()
    }

    fn wait_used(&self, target: u16) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.used() != target {
            assert!(
                Instant::now() < deadline,
                "used index stuck at {}",
                self.used()
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A frozen thread dispatches nothing and leaves the notification pending
/// for the resumed source; it stops and joins while frozen. A restored
/// thread completes a request nobody notified once resumed.
#[test]
fn snapshot_event_thread_freeze_stop_and_restored_kick() {
    let mut source = Rig::new();
    let mut events = source.spawn(Start::Running);
    source.post();
    source.notify.write(1).unwrap();
    source.wait_used(1);

    events.freeze().unwrap();
    source.post();
    source.notify.write(1).unwrap();
    // Negative check: give a wrongly dispatching thread time to act.
    thread::sleep(Duration::from_millis(100));
    assert_eq!(source.used(), 1, "a frozen thread processed a request");
    events.resume().unwrap();
    source.wait_used(2);

    events.freeze().unwrap();
    events.stop();
    assert!(events.thread.is_none());

    let mut target = Rig::new();
    target.post();
    let events = target.spawn(Start::Restored);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(target.used(), 0, "a restored thread ran before resume");
    events.resume().unwrap();
    target.wait_used(1);
}

/// A vCPU thread that only counts the `Finish` it receives; the kick signal
/// has the real vCPU handler installed.
pub(in crate::ram_snapshot) fn fake_vcpu(finished: Arc<AtomicUsize>) -> crate::vstate::VcpuHandle {
    crate::vstate::Vcpu::register_kick_signal_handler();
    let (sender, commands) = crossbeam_channel::unbounded();
    let (_responses, receiver) = crossbeam_channel::unbounded();
    let thread = thread::spawn(move || {
        while let Ok(event) = commands.recv() {
            if matches!(event, crate::vstate::VcpuEvent::Finish) {
                finished.fetch_add(1, Ordering::SeqCst);
                return;
            }
        }
    });
    crate::vstate::VcpuHandle::new(sender, receiver, thread)
}

fn exit_only(exit: &Arc<Exit>, start: Start) -> EventThread {
    let devices = Devices {
        exit: exit.clone(),
        rng: None,
        balloon: None,
        vsock: None,
        console: None,
        serials: Vec::new(),
    };
    EventThread::spawn(devices, start).unwrap()
}

pub(in crate::ram_snapshot) fn wait_finished(finished: &AtomicUsize, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while finished.load(Ordering::SeqCst) != count {
        assert!(Instant::now() < deadline, "vCPUs were not stopped");
        thread::sleep(Duration::from_millis(1));
    }
}

/// With no device attached, a write to an exit notifier (the eventfd the
/// i8042 reset and every vCPU get) latches the exit and stops every armed
/// vCPU; the owner then joins them after stopping the thread.
#[test]
fn snapshot_exit_watch_stops_armed_vcpus_without_devices() {
    let exit = Exit::new().unwrap();
    let mut events = exit_only(&exit, Start::Running);
    let finished = Arc::new(AtomicUsize::new(0));
    let mut vcpus: Vec<_> = (0..2).map(|_| fake_vcpu(finished.clone())).collect();
    events
        .arm(vcpus.iter().map(|vcpu| vcpu.stop_handle()).collect())
        .unwrap();
    assert!(!exit.requested());

    exit.notifier().unwrap().write(1).unwrap();
    wait_finished(&finished, 2);
    assert!(exit.exiting.load(Ordering::SeqCst));
    assert!(exit.requested());

    events.stop();
    vcpus.iter_mut().for_each(|vcpu| vcpu.finish());
}

/// A frozen thread leaves the exit unread: the owner sees it as requested
/// while nothing is latched or stopped; resuming latches and stops.
#[test]
fn snapshot_exit_watch_frozen_leaves_exit_pending_for_the_owner() {
    let exit = Exit::new().unwrap();
    let mut events = exit_only(&exit, Start::Running);
    let finished = Arc::new(AtomicUsize::new(0));
    let mut vcpu = fake_vcpu(finished.clone());
    events.arm(vec![vcpu.stop_handle()]).unwrap();

    events.freeze().unwrap();
    exit.notifier().unwrap().write(1).unwrap();
    // Negative check: give a wrongly dispatching thread time to act.
    thread::sleep(Duration::from_millis(100));
    assert!(
        !exit.exiting.load(Ordering::SeqCst),
        "frozen thread latched"
    );
    assert_eq!(finished.load(Ordering::SeqCst), 0, "frozen thread stopped");
    assert!(exit.requested(), "unread exit not visible to the owner");

    events.resume().unwrap();
    wait_finished(&finished, 1);
    events.stop();
    vcpu.finish();
}

/// A waiter wakes once a guest exit latches, or a host failure (marked as
/// a failure), or the owner stops every thread; it times out otherwise.
#[test]
fn snapshot_exit_wait_ends_on_exit_failure_or_stop() {
    let exit = Exit::new().unwrap();
    let mut events = exit_only(&exit, Start::Running);
    assert!(!exit.wait(Some(Duration::from_millis(20))));
    let waiter = {
        let exit = exit.clone();
        thread::spawn(move || exit.wait(None))
    };
    exit.notifier().unwrap().write(1).unwrap();
    assert!(waiter.join().unwrap());
    assert!(exit.requested() && !exit.failed());
    events.stop();

    let failed = Exit::new().unwrap();
    let mut events = exit_only(&failed, Start::Running);
    failed.failure_notifier().unwrap().write(1).unwrap();
    assert!(failed.wait(Some(Duration::from_secs(3))));
    assert!(failed.requested() && failed.failed());
    events.stop();

    let stopped = Exit::new().unwrap();
    let waiter = {
        let stopped = stopped.clone();
        thread::spawn(move || stopped.wait(None))
    };
    stopped.end();
    assert!(waiter.join().unwrap());
    assert!(!stopped.requested() && !stopped.failed());
}
