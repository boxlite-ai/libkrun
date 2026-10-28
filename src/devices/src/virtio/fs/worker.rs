#[cfg(target_os = "macos")]
use crossbeam_channel::Sender as MapSender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::io;
use std::os::fd::AsRawFd;
use std::result;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::Queue;
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::passthrough::{self, PassthroughFs};
#[cfg(target_os = "linux")]
use super::passthrough::{PassthroughSnapshotError, PassthroughState, RestoredObject};
use super::read_only::PassthroughFsRo;
use super::server::Server;
pub use crate::virtio::control::WorkerControlError;
use crate::virtio::control::{self, CONTROL_TIMEOUT};
use crate::virtio::persist::QueueState;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

/// Test-only ONE-SHOT in-flight gates, keyed by each worker's queue eventfd
/// (tests retain the same shared `Arc<EventFd>`), as in the block worker:
/// installing a gate holds that queue's next popped request until the test
/// releases it.
#[cfg(all(test, target_os = "linux"))]
static REQUEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::os::fd::RawFd, RequestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(all(test, target_os = "linux"))]
struct RequestGate {
    arrive: Sender<()>,
    release: Receiver<()>,
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod request_gate {
    use super::REQUEST_GATES;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    use std::os::fd::AsRawFd;
    use utils::eventfd::EventFd;

    /// RAII guard: removes this key's gate when dropped (including on panic).
    pub struct Guard {
        key: std::os::fd::RawFd,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            REQUEST_GATES.lock().unwrap().remove(&self.key);
        }
    }

    /// Install a one-shot gate for the queue that owns `queue_event`;
    /// returns the arrival receiver, the release sender and the guard.
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

#[cfg(all(test, target_os = "linux"))]
fn hold_at_request_gate(queue_event: &EventFd) {
    let Some(gate) = REQUEST_GATES
        .lock()
        .unwrap()
        .remove(&queue_event.as_raw_fd())
    else {
        return;
    };
    let _ = gate.arrive.send(());
    let _ = gate.release.recv();
}

pub(crate) enum FsServer {
    ReadWrite(Server<PassthroughFs>),
    ReadOnly(Server<PassthroughFsRo>),
}

impl FsServer {
    pub(crate) fn new(cfg: passthrough::Config, read_only: bool) -> io::Result<Self> {
        Ok(if read_only {
            FsServer::ReadOnly(Server::new(PassthroughFsRo::new(cfg)?))
        } else {
            FsServer::ReadWrite(Server::new(PassthroughFs::new(cfg)?))
        })
    }

    /// Continue a checkpointed session: the restored share plus the FUSE
    /// options its FUSE_INIT negotiated, which must agree with the share.
    #[cfg(target_os = "linux")]
    pub(crate) fn restored(
        cfg: passthrough::Config,
        read_only: bool,
        options: u64,
        state: &PassthroughState,
        objects: Vec<RestoredObject>,
        init_binary: Arc<[u8]>,
    ) -> result::Result<Self, PassthroughSnapshotError> {
        Self::restored_with_roles(cfg, read_only, options, state, objects, init_binary, None)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restored_with_roles(
        cfg: passthrough::Config,
        read_only: bool,
        options: u64,
        state: &PassthroughState,
        objects: Vec<RestoredObject>,
        init_binary: Arc<[u8]>,
        roles: Option<passthrough::RestoredRoles>,
    ) -> result::Result<Self, PassthroughSnapshotError> {
        state.check_options(options)?;
        if read_only && state.writeback {
            return Err(PassthroughSnapshotError::Invalid(
                "negotiated FUSE options disagree with the share",
            ));
        }
        let fs = match roles {
            Some(roles) => {
                PassthroughFs::restore_with_roles(cfg, state, objects, init_binary, roles)?
            }
            None => PassthroughFs::restore(cfg, state, objects, init_binary)?,
        };
        Ok(if read_only {
            FsServer::ReadOnly(Server::restored(PassthroughFsRo::from_inner(fs), options))
        } else {
            FsServer::ReadWrite(Server::restored(fs, options))
        })
    }

    /// The FUSE options FUSE_INIT negotiated (0 before it).
    #[cfg(target_os = "linux")]
    pub(crate) fn options(&self) -> u64 {
        match self {
            FsServer::ReadWrite(s) => s.options(),
            FsServer::ReadOnly(s) => s.options(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn passthrough(&self) -> &PassthroughFs {
        match self {
            FsServer::ReadWrite(s) => s.fs(),
            FsServer::ReadOnly(s) => s.fs().inner(),
        }
    }

    /// Flush what the guest already wrote through open handles.
    fn sync_for_snapshot(&self) -> result::Result<(), String> {
        #[cfg(target_os = "linux")]
        return self
            .passthrough()
            .sync_for_snapshot()
            .map_err(|e| format!("sync open files: {e}"));
        #[cfg(not(target_os = "linux"))]
        Ok(())
    }

    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<MapSender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

/// What a frozen worker reports: the cursors of both queues it owns, high
/// priority queue first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsWorkerCut {
    pub queues: Vec<QueueState>,
}

/// Snapshot control command for the fs worker; each carries its own
/// capacity-1 reply channel.
pub(crate) enum WorkerCommand {
    /// Stop between requests — after the last request's FUSE reply,
    /// used-ring entry and interrupt — sync writable open files, then
    /// report both queue cursors. Once confirmed, the worker serves no
    /// request and writes no guest RAM, ring or interrupt until resumed.
    Freeze {
        reply: Sender<result::Result<FsWorkerCut, String>>,
    },
    /// Resume and actively re-examine both queues, so notifications drained
    /// while frozen cannot leave requests hanging.
    Resume {
        reply: Sender<result::Result<(), String>>,
    },
}

/// Controller side of the fs worker snapshot control channel.
pub struct FsWorkerHandle {
    pub(crate) control_fd: EventFd,
    pub(crate) commands: Sender<WorkerCommand>,
}

impl FsWorkerHandle {
    /// Freeze the worker and return the queue state it owns.
    pub fn freeze(&self) -> result::Result<FsWorkerCut, WorkerControlError> {
        self.freeze_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn freeze_with_timeout(
        &self,
        timeout: Duration,
    ) -> result::Result<FsWorkerCut, WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            WorkerCommand::Freeze { reply }
        })
    }

    /// Resume the worker; the reply confirms both queues were re-examined.
    pub fn resume(&self) -> result::Result<(), WorkerControlError> {
        self.resume_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn resume_with_timeout(&self, timeout: Duration) -> result::Result<(), WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            WorkerCommand::Resume { reply }
        })
    }
}

pub struct FsWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: Arc<FsServer>,
    stop_fd: EventFd,
    control_fd: EventFd,
    commands: Receiver<WorkerCommand>,
    /// Single source of truth for the frozen state.
    frozen: bool,
    /// Resume replies answered by the epoll loop after the command drain.
    pending_resume_replies: Vec<Sender<result::Result<(), String>>>,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<MapSender<WorkerMessage>>,
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        shm_region: Option<VirtioShmRegion>,
        server: Arc<FsServer>,
        stop_fd: EventFd,
        control_fd: EventFd,
        commands: Receiver<WorkerCommand>,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<MapSender<WorkerMessage>>,
    ) -> Self {
        Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            shm_region,
            server,
            stop_fd,
            control_fd,
            commands,
            frozen: false,
            pending_resume_replies: Vec::new(),
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    /// Spawn the worker thread; `start_frozen` begins suspended, for a
    /// device restored from a snapshot before the owner resumes it.
    pub fn run(mut self, start_frozen: bool) -> thread::JoinHandle<()> {
        self.frozen = start_frozen;
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_hpq_ev_fd = self.queue_evts[HPQ_INDEX].as_raw_fd();
        let virtq_req_ev_fd = self.queue_evts[REQ_INDEX].as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let control_ev_fd = self.control_fd.as_raw_fd();

        let epoll = Epoll::new().unwrap();

        for fd in [virtq_hpq_ev_fd, virtq_req_ev_fd, stop_ev_fd, control_ev_fd] {
            let _ = epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, fd as u64),
            );
        }

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_hpq_ev_fd => {
                                self.handle_event(HPQ_INDEX);
                            }
                            EventSet::IN if source == virtq_req_ev_fd => {
                                self.handle_event(REQ_INDEX);
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
                    // outside any command handling.
                    self.finish_pending_resumes();
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    /// Drain queued control commands. A Freeze flips the single `frozen`
    /// field; a Resume clears it and defers its reply.
    fn handle_pending_commands(&mut self) {
        loop {
            match self.commands.try_recv() {
                Ok(WorkerCommand::Freeze { reply }) => {
                    // Requests are handled synchronously, so whichever loop
                    // called us finished the last request's reply, used-ring
                    // entry and interrupt.
                    let synced = self.server.sync_for_snapshot();
                    let cut = FsWorkerCut {
                        queues: self.queues.iter().map(QueueState::from_queue).collect(),
                    };
                    self.frozen = true;
                    // A dropped reply means the controller timed out; the
                    // worker stays frozen and resumable.
                    let _ = reply.try_send(synced.map(|_| cut));
                }
                Ok(WorkerCommand::Resume { reply }) => {
                    self.frozen = false;
                    self.pending_resume_replies.push(reply);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Answer deferred Resume replies after actively re-examining both
    /// queues.
    fn finish_pending_resumes(&mut self) {
        if self.pending_resume_replies.is_empty() {
            return;
        }
        for queue_index in [HPQ_INDEX, REQ_INDEX] {
            self.process_queue(queue_index);
        }
        for reply in self.pending_resume_replies.drain(..) {
            let _ = reply.try_send(Ok(()));
        }
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }
        // A frozen worker only consumes the count; the resumed worker
        // re-examines the queue itself.
        self.process_queue(queue_index);
    }

    /// Process one queue. Controls are checked first — a queue event stale
    /// in the same epoll batch as its Freeze must not write RAM — and before
    /// popping each request, so a Freeze lands between requests. A frozen
    /// worker returns without re-enabling notifications.
    fn process_queue(&mut self, queue_index: usize) {
        self.handle_pending_commands();
        loop {
            if self.frozen {
                return;
            }
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();
            loop {
                self.handle_pending_commands();
                if self.frozen {
                    return;
                }
                if !self.process_one(queue_index) {
                    break;
                }
            }
            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    /// Pop and complete at most one request: FUSE reply, used-ring entry
    /// and, when needed, the interrupt. Returns false when the avail ring
    /// is drained.
    fn process_one(&mut self, queue_index: usize) -> bool {
        let mem = &self.mem;
        let queue = &mut self.queues[queue_index];
        let Some(head) = queue.pop(mem) else {
            return false;
        };
        #[cfg(all(test, target_os = "linux"))]
        hold_at_request_gate(&self.queue_evts[queue_index]);
        let index = head.index;

        match (Reader::new(mem, head.clone()), Writer::new(mem, head)) {
            (Ok(reader), Ok(writer)) => {
                if let Err(e) = self.server.handle_message(
                    reader,
                    writer,
                    &self.shm_region,
                    &self.exit_code,
                    #[cfg(target_os = "macos")]
                    &self.map_sender,
                ) {
                    error!("error handling message: {e:?}");
                }
            }
            (Err(e), _) | (_, Err(e)) => error!("invalid descriptor chain: {e:?}"),
        }

        if let Err(e) = queue.add_used(mem, index, 0) {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if queue.needs_notification(mem).unwrap() {
            self.interrupt.signal_used_queue();
        }
        true
    }
}
