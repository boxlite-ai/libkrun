use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::persist::QueueState;

use super::super::DeviceQueue;
use super::device::{Block, CacheType, DiskProperties};

pub use crate::virtio::control::WorkerControlError;
use crate::virtio::control::{self, CONTROL_TIMEOUT};
use crate::virtio::InterruptTransport;
#[cfg(test)]
use crossbeam_channel::bounded;
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::result;
use std::thread;
use std::time::Duration;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

/// Test-only ONE-SHOT in-flight gates, keyed by each worker's queue eventfd
/// (tests retain the same shared `Arc<EventFd>`). Installing a gate holds
/// that worker's next popped descriptor until the test releases it; the
/// entry is removed from the map before the worker waits, making the gate
/// one-shot and lock-free during the hold. Unrelated workers are never
/// intercepted, and simultaneous installs for different workers coexist.
#[cfg(test)]
static REQUEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::os::fd::RawFd, RequestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
struct RequestGate {
    arrive: crossbeam_channel::Sender<()>,
    release: crossbeam_channel::Receiver<()>,
}

#[cfg(test)]
mod request_gate {
    use super::REQUEST_GATES;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    use std::os::fd::AsRawFd;
    use utils::eventfd::EventFd;

    /// RAII guard: removes this key's gate when dropped (including on
    /// panic), leaving other workers' gates untouched.
    pub struct Guard {
        key: std::os::fd::RawFd,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            REQUEST_GATES.lock().unwrap().remove(&self.key);
        }
    }

    /// Install a fresh one-shot gate for the worker that owns `queue_event`
    /// (tests keep the same shared eventfd); returns the arrival receiver,
    /// the release sender and the RAII guard.
    pub fn install(queue_event: &EventFd) -> (Receiver<()>, Sender<()>, Guard) {
        let (arrive_tx, arrive_rx) = unbounded();
        let (release_tx, release_rx) = unbounded();
        let key = queue_event.as_raw_fd();
        REQUEST_GATES.lock().unwrap().insert(
            key,
            super::RequestGate {
                arrive: arrive_tx,
                release: release_rx,
            },
        );
        (arrive_rx, release_tx, Guard { key })
    }
}

#[cfg(test)]
fn hold_at_request_gate(queue_event: &utils::eventfd::EventFd) {
    // Take this worker's gate out of the map under the lock, then wait
    // WITHOUT holding it: the gate is one-shot by construction.
    let Some(gate) = REQUEST_GATES
        .lock()
        .unwrap()
        .remove(&queue_event.as_raw_fd())
    else {
        return;
    };
    let _ = gate.arrive.send(());
    // The gate owns this worker until the test releases it; a dropped
    // sender (panic in the test) releases immediately.
    let _ = gate.release.recv();
}

/// Snapshot control command for the block worker.
///
/// Each request carries its own capacity-1 reply channel: a timed-out or
/// dropped reply never blocks the worker or pollutes later requests.
pub(crate) enum WorkerCommand {
    /// Stop consuming requests at the current descriptor boundary, flush and
    /// sync the disk regardless of the guest cache mode, then report the
    /// queue-local state the worker owns.
    Freeze {
        reply: Sender<result::Result<QueueState, String>>,
    },
    /// Resume processing and actively re-examine the queue so coalesced or
    /// drained notification counts cannot leave pending requests hanging.
    Resume {
        reply: Sender<result::Result<(), String>>,
    },
}

/// Controller side of the block worker snapshot control channel.
pub struct BlockWorkerHandle {
    pub(crate) control_fd: EventFd,
    pub(crate) commands: Sender<WorkerCommand>,
}

impl BlockWorkerHandle {
    /// Freeze the worker and return the queue state it owns.
    pub fn freeze(&self) -> result::Result<QueueState, WorkerControlError> {
        self.freeze_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn freeze_with_timeout(
        &self,
        timeout: Duration,
    ) -> result::Result<QueueState, WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            WorkerCommand::Freeze { reply }
        })
    }

    /// Resume the worker; the reply confirms the active queue examination
    /// finished, so unconsumed requests are visible again.
    pub fn resume(&self) -> result::Result<(), WorkerControlError> {
        self.resume_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn resume_with_timeout(&self, timeout: Duration) -> result::Result<(), WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            WorkerCommand::Resume { reply }
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
    control_fd: EventFd,
    commands: Receiver<WorkerCommand>,
    /// Single source of truth for the frozen state; no shadow flags.
    frozen: bool,
    /// Resume replies answered by the epoll loop after the command drain,
    /// never recursively from inside command handling.
    pending_resume_replies: Vec<Sender<result::Result<(), String>>>,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
        control_fd: EventFd,
        commands: Receiver<WorkerCommand>,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            control_fd,
            commands,
            frozen: false,
            pending_resume_replies: Vec::new(),
        }
    }

    /// Spawn the worker thread. `start_frozen` begins processing suspended
    /// for devices restored from a snapshot, before the owner resumes them.
    pub fn run(mut self, start_frozen: bool) -> thread::JoinHandle<()> {
        self.frozen = start_frozen;
        thread::Builder::new()
            .name("block worker".into())
            .spawn(move || self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let control_ev_fd = self.control_fd.as_raw_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            control_ev_fd,
            &EpollEvent::new(EventSet::IN, control_ev_fd as u64),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                if self.frozen {
                                    // Consume the count to keep epoll from
                                    // spinning; the resumed worker re-examines
                                    // the queue itself, so draining is safe.
                                    let _ = self.device_queue.event.read();
                                } else {
                                    self.process_queue_event();
                                }
                            }
                            EventSet::IN if source == control_ev_fd => {
                                let _ = self.control_fd.read();
                                self.handle_pending_commands();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                    // Deferred resume confirmations run at the loop level,
                    // outside any command handling: no nested drains.
                    self.finish_pending_resumes();
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    /// Drain queued control commands. A Freeze flips the single `frozen`
    /// field; a Resume only clears it and defers its reply — queue work is
    /// never started from inside command handling.
    fn handle_pending_commands(&mut self) {
        loop {
            match self.commands.try_recv() {
                Ok(WorkerCommand::Freeze { reply }) => {
                    // The freeze takes effect between descriptor chains with
                    // every temporary mapping clone unwound: whichever batch
                    // called us finished its status write, used-ring update
                    // and interrupt for the last chain.
                    let flushed = self.flush_disk_for_snapshot();
                    let state = QueueState::from_queue(&self.device_queue.queue);
                    self.frozen = true;
                    // A dropped reply means the controller timed out; the
                    // worker stays frozen and resumable, and the stale reply
                    // is dropped.
                    let _ = reply.try_send(flushed.map(|_| state));
                }
                Ok(WorkerCommand::Resume { reply }) => {
                    self.frozen = false;
                    self.pending_resume_replies.push(reply);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Answer deferred Resume replies after actively re-examining the queue.
    fn finish_pending_resumes(&mut self) {
        if self.pending_resume_replies.is_empty() {
            return;
        }
        if !self.frozen {
            self.process_virtio_queues();
        }
        // A later Freeze may have re-frozen the worker during the drain; the
        // Resume command itself was still processed and confirmed.
        for reply in self.pending_resume_replies.drain(..) {
            let _ = reply.try_send(Ok(()));
        }
    }

    /// Flush and sync the disk regardless of the guest cache mode, so the
    /// snapshot cut includes everything the device already completed.
    fn flush_disk_for_snapshot(&self) -> result::Result<(), String> {
        let disk = self.disk.file.lock().unwrap();
        disk.flush().map_err(|e| format!("flush: {e}"))?;
        disk.sync().map_err(|e| format!("sync: {e}"))
    }

    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process the device virtqueue.
    ///
    /// Controls and the frozen state are checked first — a queue event that
    /// is stale in the same epoll batch as its Freeze must not write RAM —
    /// and before popping each next descriptor, so a Freeze lands between
    /// individual requests, never after one has been popped. All guest-memory
    /// borrows are scoped inside `process_one`: a Freeze acknowledgment is
    /// never sent while a temporary mapping clone is alive. When frozen, the
    /// loop returns without re-enabling notifications — a confirmed freeze
    /// performs no further ring writes.
    fn process_virtio_queues(&mut self) {
        self.handle_pending_commands();
        loop {
            if self.frozen {
                return;
            }
            {
                let mem = self.mem.clone();
                self.device_queue.queue.disable_notification(&mem).unwrap();
            }
            loop {
                self.handle_pending_commands();
                if self.frozen {
                    return;
                }
                if !self.process_one() {
                    break;
                }
            }
            if self.frozen {
                return;
            }
            let more = {
                let mem = self.mem.clone();
                self.device_queue.queue.enable_notification(&mem).unwrap()
            };
            if !more {
                break;
            }
        }
    }

    /// Pop and complete at most one descriptor chain inside a single scope
    /// that owns the temporary mapping clone; returns false when the avail
    /// ring is drained.
    fn process_one(&mut self) -> bool {
        let mem = self.mem.clone();
        let Some(head) = self.device_queue.queue.pop(&mem) else {
            return false;
        };
        #[cfg(test)]
        hold_at_request_gate(&self.device_queue.event);
        self.process_chain(&mem, head);
        true
    }

    /// Complete exactly one descriptor chain: status write, used-ring update
    /// and, when needed, the interrupt.
    fn process_chain(&mut self, mem: &GuestMemoryMmap, head: crate::virtio::DescriptorChain<'_>) {
        let mut reader = match Reader::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                return;
            }
        };
        let mut writer = match Writer::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                return;
            }
        };
        let request_header: RequestHeader = match reader.read_obj() {
            Ok(h) => h,
            Err(e) => {
                error!("invalid request header: {e:?}");
                return;
            }
        };

        let (status, len): (u8, usize) =
            match self.process_request(request_header, &mut reader, &mut writer) {
                Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                Err(e) => {
                    error!("error processing request: {e:?}");
                    (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                }
            };

        if let Err(e) = writer.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}")
        }

        if let Err(e) = self
            .device_queue
            .queue
            .add_used(mem, head.index, len as u32)
        {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if self.device_queue.queue.needs_notification(mem).unwrap() {
            if let Err(e) = self.interrupt.try_signal_used_queue() {
                error!("error signalling queue: {e:?}");
            }
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes() - 1;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = self.disk.file.lock().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                self.disk
                    .file
                    .lock()
                    .unwrap()
                    .discard_to_any(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if unmap {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
                        .write_zeroes(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::request_gate;
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::block::{ImageType, SyncMode};
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::Descriptor;
    use crate::virtio::VirtioDevice;
    use std::fs;
    use std::sync::Arc;
    use std::time::Instant;
    use utils::eventfd::EFD_NONBLOCK;
    use utils::tempfile::TempFile;
    use vm_memory::{Bytes, GuestAddress, GuestMemory};

    // Every test name contains "snapshot" so `make snapshot-test` selects
    // them through the cargo filter.

    /// Queue of 16 descriptors = five 3-descriptor chains (header, data,
    /// status); chain i writes sector i.
    const QUEUE_SIZE: u16 = 16;
    const SLOTS: u16 = 5;
    /// Slots 0..OUT_SLOTS carry write payloads; the last slot is a flush.
    const OUT_SLOTS: u16 = 4;
    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x2000;
    const USED: u64 = 0x3000;
    const HEADERS: u64 = 0x8000;
    const DATA: u64 = 0x10000;
    const STATUS: u64 = 0x18000;
    const SECTORS: u64 = SLOTS as u64 + 1;

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 256 * 1024)]).unwrap()
    }

    /// Build a ready virtqueue of 3-descriptor chains; the returned eventfd
    /// stays shared with the worker after activation so tests can kick.
    fn queue(mem: &GuestMemoryMmap) -> (DeviceQueue, Arc<EventFd>) {
        let mut queue = crate::virtio::Queue::new(QUEUE_SIZE);
        queue.size = QUEUE_SIZE;
        queue.ready = true;
        queue.desc_table = GuestAddress(DESC);
        queue.avail_ring = GuestAddress(AVAIL);
        queue.used_ring = GuestAddress(USED);
        for slot in 0..SLOTS {
            let write_descriptor = |index: u16, descriptor: Descriptor| {
                mem.write_obj(descriptor, GuestAddress(DESC + 16 * u64::from(index)))
                    .unwrap();
            };
            write_descriptor(
                3 * slot,
                Descriptor {
                    addr: HEADERS + 16 * u64::from(slot),
                    len: 16,
                    flags: VIRTQ_DESC_F_NEXT,
                    next: 3 * slot + 1,
                },
            );
            // The data direction words (flags AND next) are rewritten per
            // request by `submit` through one aligned 32-bit store.
            write_descriptor(
                3 * slot + 1,
                Descriptor {
                    addr: DATA + 512 * u64::from(slot),
                    len: 512,
                    flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                    next: 3 * slot + 2,
                },
            );
            write_descriptor(
                3 * slot + 2,
                Descriptor {
                    addr: STATUS + u64::from(slot),
                    len: 1,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                },
            );
        }
        mem.write_obj(0u16, GuestAddress(AVAIL)).unwrap();
        mem.write_obj(0u16, GuestAddress(AVAIL + 2)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED + 2)).unwrap();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        (DeviceQueue::new(queue, event.clone()), event)
    }

    /// Submit one complete request on `slot`: header, payload direction and
    /// the avail ring entry. Chains are never reused while pending.
    fn submit(mem: &GuestMemoryMmap, slot: u16, request_type: u32, sector: u64, pattern: u8) {
        mem.write_obj(
            RequestHeader {
                request_type,
                _reserved: 0,
                sector,
            },
            GuestAddress(HEADERS + 16 * u64::from(slot)),
        )
        .unwrap();
        // Descriptor layout is addr(8) len(4) flags(2) next(2): one aligned
        // 32-bit store packs (next << 16) | flags, always keeping NEXT so
        // the chain reaches the status descriptor.
        let words: u32 = match request_type {
            VIRTIO_BLK_T_OUT => (u32::from(3 * slot + 2) << 16) | u32::from(VIRTQ_DESC_F_NEXT),
            _ => {
                (u32::from(3 * slot + 2) << 16) | u32::from(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE)
            }
        };
        mem.write_obj(
            words,
            GuestAddress(DESC + 16 * u64::from(3 * slot + 1) + 12),
        )
        .unwrap();
        if request_type == VIRTIO_BLK_T_OUT {
            mem.write_slice(&[pattern; 512], GuestAddress(DATA + 512 * u64::from(slot)))
                .unwrap();
        }
        let avail_idx: u16 = mem.read_obj(GuestAddress(AVAIL + 2)).unwrap();
        mem.write_obj(
            3 * slot,
            GuestAddress(AVAIL + 4 + 2 * u64::from(avail_idx % QUEUE_SIZE)),
        )
        .unwrap();
        mem.write_obj(avail_idx + 1, GuestAddress(AVAIL + 2))
            .unwrap();
    }

    fn used_idx(mem: &GuestMemoryMmap) -> u16 {
        mem.read_obj::<u16>(GuestAddress(USED + 2)).unwrap()
    }

    fn status(mem: &GuestMemoryMmap, slot: u16) -> u8 {
        mem.read_obj::<u8>(GuestAddress(STATUS + u64::from(slot)))
            .unwrap()
    }

    fn wait_used(mem: &GuestMemoryMmap, target: u16) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while used_idx(mem) != target {
            assert!(
                Instant::now() < deadline,
                "used ring did not reach {target}; stuck at {}",
                used_idx(mem)
            );
            std::thread::yield_now();
        }
    }

    fn activated(mem: &GuestMemoryMmap, path: &str) -> (Block, Arc<EventFd>) {
        activated_with_cache(mem, path, false)
    }

    fn activated_with_cache(
        mem: &GuestMemoryMmap,
        path: &str,
        writeback: bool,
    ) -> (Block, Arc<EventFd>) {
        let mut device = Block::new(
            "test".to_string(),
            None,
            if writeback {
                CacheType::Writeback
            } else {
                CacheType::Unsafe
            },
            path.to_string(),
            ImageType::Raw,
            false,
            false,
            SyncMode::Full,
        )
        .unwrap();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
        let (device_queue, event) = queue(mem);
        device
            .activate(mem.clone(), interrupt, vec![device_queue])
            .unwrap();
        (device, event)
    }

    /// Deterministic freeze-during-request boundary for one held request
    /// type: the worker is provably mid-request when the bounded Freeze
    /// times out; after release the held request completes exactly once,
    /// later requests stay unconsumed, the cut is stable, and the resume
    /// finishes the rest.
    fn snapshot_freeze_boundary_for(request_type: u32, writeback: bool) {
        let file = TempFile::new().unwrap();
        file.as_file().set_len(512 * SECTORS).unwrap();
        let disk_before: Vec<u8> = (0..512 * SECTORS).map(|i| (i % 251) as u8).collect();
        fs::write(file.as_path(), &disk_before).unwrap();
        let mem = memory();
        let (mut device, event) =
            activated_with_cache(&mem, file.as_path().to_str().unwrap(), writeback);
        let handle = device.worker_control().unwrap();

        // One completed WRITE proves the data path before the gate engages.
        submit(&mem, 0, VIRTIO_BLK_T_OUT, 0, 0xa0);
        event.write(1).unwrap();
        wait_used(&mem, 1);
        assert_eq!(status(&mem, 0), 0);

        // Hold the selected request type after its descriptor was popped.
        let (arrived, release, _guard) = request_gate::install(&event);
        submit(
            &mem,
            1,
            request_type,
            if request_type == VIRTIO_BLK_T_IN {
                2
            } else {
                1
            },
            0xa1,
        );
        submit(&mem, 2, VIRTIO_BLK_T_OUT, 2, 0xa2);
        submit(&mem, 3, VIRTIO_BLK_T_FLUSH, 0, 0);
        event.write(1).unwrap();
        arrived
            .recv_timeout(Duration::from_secs(3))
            .expect("worker never reached the gated request");

        // Mid-request: the bounded Freeze cannot be answered while the only
        // worker thread is held inside the gate.
        assert_eq!(
            handle.freeze_with_timeout(Duration::from_millis(50)),
            Err(WorkerControlError::Timeout)
        );

        // Release: the held request completes to its full boundary, then the
        // queued (late) Freeze lands; the later requests stay unconsumed.
        release.send(()).unwrap();
        let state = handle.freeze().unwrap();
        assert_eq!(state.next_used, 2);
        assert_eq!(state.next_used, used_idx(&mem));
        let avail_idx: u16 = mem.read_obj(GuestAddress(AVAIL + 2)).unwrap();
        assert_eq!(avail_idx, 4);
        // Exactly-once accounting: two completed, two pending, nothing lost.
        assert_eq!(
            (std::num::Wrapping(avail_idx) - std::num::Wrapping(state.next_avail)).0,
            2
        );
        for slot in 0..2 {
            assert_eq!(status(&mem, slot), 0);
        }
        // Per-type observable outcome of the held request.
        match request_type {
            VIRTIO_BLK_T_IN => {
                let mut data = [0u8; 512];
                mem.read_slice(&mut data, GuestAddress(DATA + 512)).unwrap();
                assert_eq!(&data[..], &disk_before[512 * 2..512 * 3]);
            }
            VIRTIO_BLK_T_OUT => {
                let disk = fs::read(file.as_path()).unwrap();
                assert!(disk[512..1024].iter().all(|byte| *byte == 0xa1));
            }
            _ => {
                // FLUSH under Writeback actually flushed and synced the
                // format: the pre-written pattern must be durable.
                let disk = fs::read(file.as_path()).unwrap();
                assert!(disk[..512].iter().all(|byte| *byte == 0xa0));
            }
        }

        // The frozen cut is stable: kicks drain, no ring or byte moves, and
        // the disk content does not change.
        let frozen_used = used_idx(&mem);
        event.write(1).unwrap();
        let stable_disk = fs::read(file.as_path()).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(used_idx(&mem), frozen_used);
        assert_eq!(fs::read(file.as_path()).unwrap(), stable_disk);

        // Resume actively examines the queue: the remaining WRITE and the
        // FLUSH complete exactly once, then new requests keep flowing.
        handle.resume().unwrap();
        wait_used(&mem, 4);
        for slot in 0..4 {
            assert_eq!(status(&mem, slot), 0);
        }
        submit(&mem, 0, VIRTIO_BLK_T_OUT, 0, 0xb0);
        event.write(1).unwrap();
        wait_used(&mem, 5);
        assert!(fs::read(file.as_path()).unwrap()[..512]
            .iter()
            .all(|byte| *byte == 0xb0));
        device.reset();
    }

    #[test]
    fn snapshot_freeze_boundary_holds_read_request() {
        snapshot_freeze_boundary_for(VIRTIO_BLK_T_IN, false);
    }

    #[test]
    fn snapshot_freeze_boundary_holds_write_request() {
        snapshot_freeze_boundary_for(VIRTIO_BLK_T_OUT, false);
    }

    #[test]
    fn snapshot_freeze_boundary_holds_flush_request_with_writeback() {
        snapshot_freeze_boundary_for(VIRTIO_BLK_T_FLUSH, true);
    }

    #[test]
    fn snapshot_freeze_read_requests_and_capture_path() {
        let file = TempFile::new().unwrap();
        let disk: Vec<u8> = (0..512 * SECTORS).map(|i| (i % 251) as u8).collect();
        fs::write(file.as_path(), &disk).unwrap();
        let mem = memory();
        let (mut device, event) = activated(&mem, file.as_path().to_str().unwrap());
        let handle = device.worker_control().unwrap();

        submit(&mem, 0, VIRTIO_BLK_T_IN, 2, 0);
        event.write(1).unwrap();
        wait_used(&mem, 1);
        let state = handle.freeze().unwrap();
        assert_eq!(state.next_used, 1);
        assert_eq!(state.next_used, used_idx(&mem));
        assert_eq!(status(&mem, 0), 0);
        let mut data = [0u8; 512];
        mem.read_slice(&mut data, GuestAddress(DATA)).unwrap();
        assert_eq!(&data[..], &disk[512 * 2..512 * 3]);

        // The capture path reads the frozen image through the shared
        // SyncFormatAccess, bounded by the caller's buffer.
        let mut chunk = [0u8; 512];
        assert_eq!(
            device.read_snapshot_chunk(512 * 2, &mut chunk).unwrap(),
            512
        );
        assert_eq!(&chunk[..], &disk[512 * 2..512 * 3]);
        handle.resume().unwrap();
        device.reset();
    }

    #[test]
    fn snapshot_control_timeout_late_reply_and_disconnect() {
        let file = TempFile::new().unwrap();
        file.as_file().set_len(512 * SECTORS).unwrap();
        let mem = memory();
        let (mut device, event) = activated(&mem, file.as_path().to_str().unwrap());
        let handle = device.worker_control().unwrap();

        // Hold the real worker inside a request; the bounded control cannot
        // be answered, deterministically.
        let (arrived, release, _guard) = request_gate::install(&event);
        submit(&mem, 0, VIRTIO_BLK_T_OUT, 0, 0xa0);
        event.write(1).unwrap();
        arrived
            .recv_timeout(Duration::from_secs(3))
            .expect("worker never reached the gated request");
        assert_eq!(
            handle.freeze_with_timeout(Duration::from_millis(50)),
            Err(WorkerControlError::Timeout)
        );

        // Release: the frozen boundary completes, the late Freeze command is
        // answered into its dropped receiver, and the worker stays usable.
        release.send(()).unwrap();
        let state = handle.freeze().unwrap();
        assert_eq!(state.next_used, 1);
        handle.resume().unwrap();
        wait_used(&mem, 1);

        // Worker exit turns controls into WorkerGone errors. Clone the
        // controller-side pieces before the mutable reset borrow.
        let control_fd = handle.control_fd.try_clone().unwrap();
        let commands = handle.commands.clone();
        device.reset();
        let handle = BlockWorkerHandle {
            control_fd,
            commands,
        };
        assert_eq!(handle.freeze(), Err(WorkerControlError::WorkerGone));
        let (gone, dropped) = bounded(1);
        drop(dropped);
        let handle = BlockWorkerHandle {
            control_fd: EventFd::new(EFD_NONBLOCK).unwrap(),
            commands: gone,
        };
        assert_eq!(handle.freeze(), Err(WorkerControlError::WorkerGone));
    }
}
