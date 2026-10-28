use crate::virtio::control::{self, WorkerControlError, CONTROL_TIMEOUT};
use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::MAX_BUFFER_SIZE;
use crate::virtio::persist::QueueState;
use crate::virtio::{DescriptorChain, DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, VirtioNetBackend};
use super::VNET_HDR_LEN;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::result;
use std::thread;
use std::time::Duration;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestMemoryMmap};

/// Frames moved per direction before the worker returns to its event loop;
/// leftover work re-arms through the wake eventfd, so controls and stop
/// requests are never starved by a busy guest or backend.
const RX_BUDGET: usize = 64;
const TX_BUDGET: usize = 64;

/// Cut-time queue cursors of a frozen worker. Worker-private buffers
/// (deferred RX frame, partial backend frames, unfinished TX writes) are not
/// part of it: they stay with the live worker and its backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetQueueStates {
    pub rx: QueueState,
    pub tx: QueueState,
}

/// Snapshot control command for the net worker.
pub(crate) enum NetWorkerCommand {
    /// Stop at the current descriptor boundary — every popped chain is in
    /// the used ring and its interrupt delivered — and report the cursors.
    /// Once confirmed, the worker writes no guest RAM, ring or interrupt and
    /// does no backend I/O until resumed or stopped.
    Freeze {
        reply: Sender<result::Result<NetQueueStates, String>>,
    },
    /// Resume and actively re-examine both queues and the backend, so
    /// notifications and readiness edges drained while frozen cannot hang.
    Resume {
        reply: Sender<result::Result<(), String>>,
    },
}

/// Controller side of the net worker snapshot control channel.
pub struct NetWorkerHandle {
    pub(crate) control_fd: EventFd,
    pub(crate) commands: Sender<NetWorkerCommand>,
}

impl NetWorkerHandle {
    /// Freeze the worker and return its queue cursors.
    pub fn freeze(&self) -> result::Result<NetQueueStates, WorkerControlError> {
        self.freeze_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn freeze_with_timeout(
        &self,
        timeout: Duration,
    ) -> result::Result<NetQueueStates, WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            NetWorkerCommand::Freeze { reply }
        })
    }

    /// Resume the worker; the reply confirms the active re-examination ran.
    pub fn resume(&self) -> result::Result<(), WorkerControlError> {
        self.resume_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn resume_with_timeout(&self, timeout: Duration) -> result::Result<(), WorkerControlError> {
        control::request(&self.commands, &self.control_fd, timeout, |reply| {
            NetWorkerCommand::Resume { reply }
        })
    }
}

/// Event-loop side of the control channel, handed to the worker.
pub(crate) struct NetWorkerControl {
    pub(crate) stop_fd: EventFd,
    pub(crate) control_fd: EventFd,
    /// Self-notification for work left over by a budget.
    pub(crate) wake_fd: EventFd,
    pub(crate) commands: Receiver<NetWorkerCommand>,
}

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    control: NetWorkerControl,
    /// Single source of truth for the frozen state.
    frozen: bool,
    /// Resume replies answered after the active re-examination.
    pending_resume_replies: Vec<Sender<result::Result<(), String>>>,
    /// The backend may have readable frames nobody consumed yet.
    rx_pending: bool,
    /// The TX queue or an unfinished backend write may need attention.
    tx_pending: bool,
    /// RX chains were used since the last interrupt.
    rx_used: bool,
    /// TX chains were used since the last notification check.
    tx_used: bool,
    /// The backend failed or closed; guest TX frames are dropped.
    backend_closed: bool,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_deferred_frame: bool,
}

impl NetWorker {
    pub(crate) fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
        control: NetWorkerControl,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            control,
            frozen: false,
            pending_resume_replies: Vec::new(),
            rx_pending: true,
            tx_pending: true,
            rx_used: false,
            tx_used: false,
            backend_closed: false,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_has_deferred_frame: false,
        })
    }

    /// Spawn the worker thread. `start_frozen` begins suspended for devices
    /// restored from a snapshot, before the owner resumes them.
    pub fn run(mut self, start_frozen: bool) -> thread::JoinHandle<()> {
        self.frozen = start_frozen;
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let stop_ev_fd = self.control.stop_fd.as_raw_fd();
        let control_ev_fd = self.control.control_fd.as_raw_fd();
        let wake_ev_fd = self.control.wake_fd.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();
        let mut backend_registered = true;

        let epoll = Epoll::new().unwrap();

        for fd in [
            virtq_rx_ev_fd,
            virtq_tx_ev_fd,
            stop_ev_fd,
            control_ev_fd,
            wake_ev_fd,
        ] {
            let _ = epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, fd as u64),
            );
        }
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );
        // Work queued before the first event (a restored ring or frames the
        // backend already sent) is examined without waiting for a kick.
        let _ = self.control.wake_fd.write(1);

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                // Frozen kicks are drained too: resume
                                // re-examines the queue itself.
                                let _ = self.rx_q.event.read();
                                self.rx_pending = true;
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                let _ = self.tx_q.event.read();
                                self.tx_pending = true;
                            }
                            EventSet::IN if source == control_ev_fd => {
                                let _ = self.control.control_fd.read();
                                self.handle_pending_commands();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping virtio-net worker thread");
                                let _ = self.control.stop_fd.read();
                                return;
                            }
                            EventSet::IN if source == wake_ev_fd => {
                                let _ = self.control.wake_fd.read();
                            }
                            _ if source == backend_socket => {
                                let hang_up = event_set
                                    .intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP);
                                if hang_up && !self.backend_closed {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                }
                                // Frames queued before a hang-up are still
                                // delivered; reading reports the end itself.
                                if hang_up || event_set.contains(EventSet::IN) {
                                    self.rx_pending = true;
                                }
                                if event_set.contains(EventSet::OUT) {
                                    self.tx_pending = true;
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                self.tx_pending = true;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    self.pump();
                    self.finish_pending_resumes();

                    if self.backend_closed && backend_registered {
                        // Stop readiness reports from a dead peer.
                        let _ = epoll.ctl(
                            ControlOperation::Delete,
                            backend_socket,
                            &EpollEvent::new(EventSet::empty(), backend_socket as u64),
                        );
                        backend_registered = false;
                    }
                    if !self.frozen && (self.rx_pending || self.tx_pending) {
                        let _ = self.control.wake_fd.write(1);
                    }

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if !self.frozen && self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    /// Run one budgeted round of RX and TX work unless frozen.
    fn pump(&mut self) {
        if !self.frozen && std::mem::take(&mut self.rx_pending) {
            self.process_rx();
        }
        if !self.frozen && std::mem::take(&mut self.tx_pending) {
            self.process_tx();
        }
    }

    /// Drain queued control commands. A Freeze lands only here, between
    /// descriptor chains, after the used-ring interrupts were raised; a
    /// Resume clears the frozen flag and defers its reply to the loop level.
    fn handle_pending_commands(&mut self) {
        loop {
            match self.control.commands.try_recv() {
                Ok(NetWorkerCommand::Freeze { reply }) => {
                    if !self.frozen {
                        self.signal_used_queues();
                        self.frozen = true;
                    }
                    let state = NetQueueStates {
                        rx: QueueState::from_queue(&self.rx_q.queue),
                        tx: QueueState::from_queue(&self.tx_q.queue),
                    };
                    // A dropped reply means the controller timed out; the
                    // worker stays frozen and resumable.
                    let _ = reply.try_send(Ok(state));
                }
                Ok(NetWorkerCommand::Resume { reply }) => {
                    self.frozen = false;
                    self.pending_resume_replies.push(reply);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Answer deferred Resume replies after actively re-examining the
    /// backend and both queues: kicks and readiness edges seen while frozen
    /// were drained without processing.
    fn finish_pending_resumes(&mut self) {
        if self.pending_resume_replies.is_empty() {
            return;
        }
        if !self.frozen {
            self.rx_pending = true;
            self.tx_pending = true;
            self.pump();
        }
        for reply in self.pending_resume_replies.drain(..) {
            let _ = reply.try_send(Ok(()));
        }
    }

    /// Checked before each descriptor chain: handles pending commands and
    /// reports whether the worker is now frozen.
    fn frozen_by_controls(&mut self) -> bool {
        if !self.control.commands.is_empty() {
            self.handle_pending_commands();
        }
        self.frozen
    }

    fn signal_used_queues(&mut self) {
        if std::mem::take(&mut self.rx_used) {
            if let Err(e) = self.interrupt.try_signal_used_queue() {
                log::error!("Failed to signal rx queue: {e:?}");
            }
        }
        if std::mem::take(&mut self.tx_used) {
            match self.tx_q.queue.needs_notification(&self.mem) {
                Ok(false) => {}
                Ok(true) | Err(_) => {
                    if let Err(e) = self.interrupt.try_signal_used_queue() {
                        log::error!("Failed to signal tx queue: {e:?}");
                    }
                }
            }
        }
    }

    /// Move up to RX_BUDGET frames from the backend into guest buffers.
    fn process_rx(&mut self) {
        for _ in 0..RX_BUDGET {
            if self.frozen_by_controls() {
                return;
            }
            if !self.rx_has_deferred_frame {
                match self.backend.read_frame(&mut self.rx_frame_buf) {
                    Ok(len) => {
                        self.rx_frame_buf_len = len;
                        self.rx_has_deferred_frame = true;
                    }
                    Err(ReadError::NothingRead) => return self.signal_used_queues(),
                    Err(ReadError::Again) => continue,
                    Err(ReadError::Disconnected) => {
                        log::debug!("Network backend reached end of stream");
                        self.backend_closed = true;
                        return self.signal_used_queues();
                    }
                    Err(e @ ReadError::Internal(_)) => {
                        log::error!("Failed to process rx: {e:?}");
                        return self.signal_used_queues();
                    }
                }
            }
            if self.deliver_rx_frame() {
                self.rx_has_deferred_frame = false;
                continue;
            }
            // No guest buffer: keep the frame and ask for a kick; buffers
            // added meanwhile are retried within the budget.
            match self.rx_q.queue.enable_notification(&self.mem) {
                Ok(true) => continue,
                Ok(false) => return self.signal_used_queues(),
                Err(e) => {
                    log::error!("error enabling rx queue notifications: {e:?}");
                    return self.signal_used_queues();
                }
            }
        }
        self.rx_pending = true;
        self.signal_used_queues();
    }

    /// Move up to TX_BUDGET guest frames to the backend. Every chain popped
    /// here is completed (sent, fully buffered for a partial write, or
    /// dropped) before the next control check.
    fn process_tx(&mut self) {
        if self.frozen_by_controls() {
            return;
        }
        if self.backend.has_unfinished_write() {
            match self
                .backend
                .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
            {
                Ok(()) => {}
                Err(WriteError::PartialWrite | WriteError::NothingWritten) => {
                    self.tx_has_deferred_frame = true;
                    return;
                }
                Err(e) => self.close_backend_for_tx(e),
            }
        }
        self.tx_has_deferred_frame = false;
        if let Err(e) = self.tx_q.queue.disable_notification(&self.mem) {
            log::error!("error disabling tx queue notifications: {e:?}");
        }

        for _ in 0..TX_BUDGET {
            if self.frozen_by_controls() {
                return;
            }
            let Some(head) = self.tx_q.queue.pop(&self.mem) else {
                match self.tx_q.queue.enable_notification(&self.mem) {
                    Ok(true) => {
                        if let Err(e) = self.tx_q.queue.disable_notification(&self.mem) {
                            log::error!("error disabling tx queue notifications: {e:?}");
                        }
                        continue;
                    }
                    Ok(false) => return self.signal_used_queues(),
                    Err(e) => {
                        log::error!("error enabling tx queue notifications: {e:?}");
                        return self.signal_used_queues();
                    }
                }
            };
            let head_index = head.index;
            let frame_len = read_tx_chain(&self.mem, head, &mut self.tx_frame_buf);

            match frame_len {
                Some(len) if len > VNET_HDR_LEN && !self.backend_closed => {
                    match self
                        .backend
                        .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..len])
                    {
                        Ok(()) => {}
                        Err(WriteError::NothingWritten) => {
                            // Not consumed: the chain is popped again once
                            // the backend is writable.
                            self.tx_q.queue.undo_pop();
                            self.tx_has_deferred_frame = true;
                            return self.signal_used_queues();
                        }
                        Err(WriteError::PartialWrite) => {
                            // The remainder lives in tx_frame_buf; the chain
                            // is complete from the guest's point of view.
                            log::trace!("process_tx: partial write");
                            self.tx_frame_len = len;
                            self.complete_tx(head_index);
                            self.tx_has_deferred_frame = true;
                            return self.signal_used_queues();
                        }
                        Err(e) => self.close_backend_for_tx(e),
                    }
                }
                _ => log::debug!("Dropping guest TX frame"),
            }
            self.complete_tx(head_index);
        }
        self.tx_pending = true;
        self.signal_used_queues();
    }

    fn complete_tx(&mut self, head_index: u16) {
        if let Err(e) = self.tx_q.queue.add_used(&self.mem, head_index, 0) {
            log::error!("failed to add used elements to the tx queue: {e:?}");
        }
        self.tx_used = true;
    }

    fn close_backend_for_tx(&mut self, e: WriteError) {
        if !self.backend_closed {
            log::error!("Failed to process tx: {e:?}; dropping further guest TX frames");
        }
        self.backend_closed = true;
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        self.rx_used = true;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. Unusable
    // chains are completed with length 0 and the next one is tried. Returns
    // true if the frame was delivered.
    fn deliver_rx_frame(&mut self) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => return false,
                Err(_) => continue,
            }
        }

        false
    }
}

/// Gather a driver-readable chain into `buf`. Returns `None` for chains the
/// device cannot send: a device-writable descriptor, unreadable memory or a
/// frame larger than the buffer.
fn read_tx_chain(
    mem: &GuestMemoryMmap,
    head: DescriptorChain<'_>,
    buf: &mut [u8; MAX_BUFFER_SIZE],
) -> Option<usize> {
    let mut len = 0usize;
    let mut next = Some(head);
    while let Some(desc) = next {
        if desc.is_write_only() {
            return None;
        }
        let end = len.checked_add(desc.len as usize)?;
        if end > buf.len() {
            log::warn!("Dropping oversized guest TX frame");
            return None;
        }
        if let Err(e) = mem.read_slice(&mut buf[len..end], desc.addr) {
            log::error!("Failed to read slice: {e:?}");
            return None;
        }
        len = end;
        next = desc.next_descriptor();
    }
    Some(len)
}

#[cfg(test)]
mod tests;
