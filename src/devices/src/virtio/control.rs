// SPDX-License-Identifier: Apache-2.0

//! Bounded worker requests for later device integration. No production device
//! consumes these yet. A Freeze reply means success only if the worker has
//! stopped all RAM writers and settled its I/O; this channel cannot do that.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use crossbeam_channel::{bounded, Receiver, SendTimeoutError, Sender, TryRecvError};
use utils::eventfd::{EventFd, EFD_NONBLOCK};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Freeze,
    Resume,
}

#[derive(Debug)]
pub enum ControlError {
    /// Deadline elapsed before submission; no command was sent.
    Deadline,
    /// Worker disconnected before submission.
    Disconnected,
    Worker(io::Error),
    /// Submission succeeded but waking the worker failed. Outcome is unknown.
    Wake(io::Error),
    /// Submitted request timed out or lost its reply. It may still execute.
    OutcomeUnknown,
    /// An earlier request has an unknown outcome; this controller is terminal.
    Unusable,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadline => write!(f, "worker request expired before submission"),
            Self::Disconnected => write!(f, "worker disconnected before submission"),
            Self::Worker(e) => write!(f, "worker request failed: {e}"),
            Self::Wake(e) => write!(f, "worker wake failed; outcome unknown: {e}"),
            Self::OutcomeUnknown => write!(f, "worker request outcome unknown"),
            Self::Unusable => write!(
                f,
                "worker controller requires teardown after unknown outcome"
            ),
        }
    }
}

impl std::error::Error for ControlError {}

pub struct WorkerController {
    sender: Sender<ControlRequest>,
    wake: Arc<EventFd>,
    uncertain: bool,
}

pub struct WorkerControl {
    receiver: Receiver<ControlRequest>,
    wake: Arc<EventFd>,
}

pub struct ControlRequest {
    command: Command,
    deadline: Instant,
    reply: Sender<io::Result<()>>,
}

/// One request in flight per controller, with a separate one-slot reply channel
/// per request. Register WorkerControl::event() in the worker's poll loop.
pub fn channel() -> io::Result<(WorkerController, WorkerControl)> {
    let (sender, receiver) = bounded(1);
    let wake = Arc::new(EventFd::new(EFD_NONBLOCK)?);
    Ok((
        WorkerController {
            sender,
            wake: wake.clone(),
            uncertain: false,
        },
        WorkerControl { receiver, wake },
    ))
}

impl WorkerController {
    /// The same absolute deadline bounds submission and reply. On unknown
    /// outcome the caller must keep the VM stopped and tear down/join the worker;
    /// timeout is neither a freeze acknowledgement nor cancellation of I/O.
    pub fn request(&mut self, command: Command, deadline: Instant) -> Result<(), ControlError> {
        if self.uncertain {
            return Err(ControlError::Unusable);
        }
        if Instant::now() >= deadline {
            return Err(ControlError::Deadline);
        }
        let (reply, result) = bounded(1);
        let request = ControlRequest {
            command,
            deadline,
            reply,
        };
        self.sender
            .send_deadline(request, deadline)
            .map_err(|e| match e {
                SendTimeoutError::Timeout(_) => ControlError::Deadline,
                SendTimeoutError::Disconnected(_) => ControlError::Disconnected,
            })?;
        self.uncertain = true;
        self.wake.write(1).map_err(ControlError::Wake)?;
        match result.recv_deadline(deadline) {
            Ok(reply) if Instant::now() < deadline => {
                self.uncertain = false;
                reply.map_err(ControlError::Worker)
            }
            _ => Err(ControlError::OutcomeUnknown),
        }
    }
}

impl WorkerControl {
    /// Drain the wake event and then try_recv() until empty. Wake counts do not
    /// correspond to request counts. Worker teardown is owned by the device.
    pub fn event(&self) -> &EventFd {
        &self.wake
    }

    pub fn try_recv(&self) -> Result<ControlRequest, TryRecvError> {
        self.receiver.try_recv()
    }
}

impl ControlRequest {
    pub fn command(&self) -> Command {
        self.command
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Workers should skip expired requests before beginning an operation.
    /// Expiry after work begins cannot undo its effects or cancel pending I/O.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Nonblocking even if the caller timed out. A false return requires worker
    /// teardown by its owner; it does not authorize resuming a frozen worker.
    pub fn respond(self, result: io::Result<()>) -> bool {
        !self.is_expired() && self.reply.try_send(result).is_ok()
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
