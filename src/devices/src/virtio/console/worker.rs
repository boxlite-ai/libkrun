// SPDX-License-Identifier: Apache-2.0

//! Snapshot control of one port worker (RX or TX). A single wake eventfd
//! carries queue notifications, controls and stop, so every wait — input,
//! writable output, empty queue — answers all three.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use utils::eventfd::{EventFd, EFD_NONBLOCK};

use super::persist::TxProgress;
use crate::virtio::control::{self, WorkerControlError};
use crate::virtio::persist::QueueState;
use crate::virtio::InterruptTransport;

/// What a frozen worker reports: the cursors of the queue it owns and its
/// progress (`eof` for RX, the unfinished chain for TX).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkerCut {
    pub queue: QueueState,
    pub eof: bool,
    pub tx_in_flight: Option<TxProgress>,
}

pub(crate) enum WorkerCommand {
    /// Stop at a chain boundary (RX) or keep the unfinished chain (TX), with
    /// every used entry's interrupt raised, and report the cut. Once
    /// confirmed, the worker does no endpoint I/O and writes no guest RAM,
    /// ring or interrupt until resumed or stopped.
    Freeze {
        reply: Sender<result::Result<WorkerCut, String>>,
    },
    /// Resume and re-examine the queue (and endpoint) without a kick.
    Resume {
        reply: Sender<result::Result<(), String>>,
    },
}

/// Controller side of one worker thread.
pub(crate) struct WorkerHandle {
    wake: EventFd,
    commands: Sender<WorkerCommand>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WorkerHandle {
    /// Spawn `work` with its side of the control channel; `start_frozen`
    /// begins suspended, for a restored port.
    pub fn spawn(
        name: &str,
        start_frozen: bool,
        work: impl FnOnce(WorkerControl) + Send + 'static,
    ) -> std::io::Result<Self> {
        let wake = EventFd::new(EFD_NONBLOCK)?;
        let (commands, receiver) = crossbeam_channel::bounded(4);
        let stop = Arc::new(AtomicBool::new(false));
        let control = WorkerControl {
            wake: wake.try_clone()?,
            commands: receiver,
            stop: stop.clone(),
            frozen: start_frozen,
            resume_replies: Vec::new(),
        };
        let thread = thread::Builder::new()
            .name(name.into())
            .spawn(move || work(control))?;
        Ok(Self {
            wake,
            commands,
            stop,
            thread: Some(thread),
        })
    }

    pub fn notify(&self) {
        if let Err(e) = self.wake.write(1) {
            error!("failed to notify a console worker: {e:?}");
        }
    }

    pub fn freeze(&self, timeout: Duration) -> result::Result<WorkerCut, WorkerControlError> {
        control::request(&self.commands, &self.wake, timeout, |reply| {
            WorkerCommand::Freeze { reply }
        })
    }

    pub fn resume(&self, timeout: Duration) -> result::Result<(), WorkerControlError> {
        control::request(&self.commands, &self.wake, timeout, |reply| {
            WorkerCommand::Resume { reply }
        })
    }

    /// Stop the worker and join it; it never waits once stopped, so this is
    /// bounded even under output backpressure or while frozen.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.notify();
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                error!("console port worker panicked: {e:?}");
            }
        }
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Worker side of the control channel.
pub(crate) struct WorkerControl {
    wake: EventFd,
    commands: Receiver<WorkerCommand>,
    stop: Arc<AtomicBool>,
    /// Single source of truth for the frozen state.
    pub frozen: bool,
    resume_replies: Vec<Sender<result::Result<(), String>>>,
}

impl WorkerControl {
    pub fn wake_fd(&self) -> &EventFd {
        &self.wake
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Consume pending wake-ups before examining the queue; a wake-up that
    /// arrives afterwards keeps the next wait from blocking.
    pub fn drain_wake(&self) {
        let _ = self.wake.read();
    }

    /// Block until the next wake-up.
    pub fn wait(&self) {
        // SAFETY: the eventfd outlives this call.
        let fd = unsafe { BorrowedFd::borrow_raw(self.wake.as_raw_fd()) };
        let mut poll_fds = [PollFd::new(fd, PollFlags::POLLIN)];
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }

    /// Answer queued commands. `freeze` runs on the first Freeze of a
    /// running worker (raising owed interrupts); `cut` builds every reply.
    pub fn handle_commands(
        &mut self,
        mut freeze: impl FnMut() -> result::Result<(), String>,
        cut: impl Fn() -> WorkerCut,
    ) {
        loop {
            match self.commands.try_recv() {
                Ok(WorkerCommand::Freeze { reply }) => {
                    let frozen = if self.frozen { Ok(()) } else { freeze() };
                    self.frozen = true;
                    // A dropped reply means the controller timed out; the
                    // worker stays frozen and resumable.
                    let _ = reply.try_send(frozen.map(|()| cut()));
                }
                Ok(WorkerCommand::Resume { reply }) => {
                    self.frozen = false;
                    self.resume_replies.push(reply);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Answer deferred Resume replies once the queue was examined again.
    pub fn finish_resumes(&mut self) {
        for reply in self.resume_replies.drain(..) {
            let _ = reply.try_send(Ok(()));
        }
    }
}

/// Raise the used-queue interrupt if a used entry is still unannounced.
pub(crate) fn signal_owed(
    interrupt: &InterruptTransport,
    used_owed: &mut bool,
) -> result::Result<(), String> {
    if std::mem::take(used_owed) {
        interrupt
            .try_signal_used_queue()
            .map_err(|e| format!("failed to signal a console queue: {e:?}"))?;
    }
    Ok(())
}
