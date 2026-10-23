// SPDX-License-Identifier: Apache-2.0

//! Snapshot control channel shared by device workers: bounded commands, each
//! with its own capacity-1 reply channel, answered within one deadline.

use std::result;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, RecvTimeoutError, SendTimeoutError, Sender};
use utils::eventfd::EventFd;

/// How long snapshot controls wait for a worker confirmation.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a worker control failed.
#[derive(Debug, PartialEq, Eq)]
pub enum WorkerControlError {
    /// The worker did not confirm within the control timeout. This is not an
    /// I/O cancellation: live resources must stay owned and unpublished.
    Timeout,
    /// The worker exited or its control channel is gone.
    WorkerGone,
    /// The worker answered, but reported a failure (for example a disk flush
    /// after a confirmed freeze).
    Frozen(String),
}

impl std::fmt::Display for WorkerControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerControlError::Timeout => write!(f, "device worker control timeout"),
            WorkerControlError::WorkerGone => {
                write!(f, "device worker exited or control channel disconnected")
            }
            WorkerControlError::Frozen(why) => write!(f, "device worker freeze failed: {why}"),
        }
    }
}

/// Send the command built around a fresh reply channel, wake the worker
/// through `control_fd` and wait for its answer. The bounded command queue
/// is part of the deadline: a plain send() could block forever before any
/// reply wait starts. A timed-out or dropped reply never blocks the worker.
pub(crate) fn request<C, T>(
    commands: &Sender<C>,
    control_fd: &EventFd,
    timeout: Duration,
    command: impl FnOnce(Sender<result::Result<T, String>>) -> C,
) -> result::Result<T, WorkerControlError> {
    let deadline = Instant::now() + timeout;
    let (reply, response) = bounded(1);
    commands
        .send_timeout(command(reply), timeout)
        .map_err(|e| match e {
            SendTimeoutError::Timeout(_) => WorkerControlError::Timeout,
            SendTimeoutError::Disconnected(_) => WorkerControlError::WorkerGone,
        })?;
    control_fd
        .write(1)
        .map_err(|_| WorkerControlError::WorkerGone)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    match response.recv_timeout(remaining) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(why)) => Err(WorkerControlError::Frozen(why)),
        Err(RecvTimeoutError::Timeout) => Err(WorkerControlError::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(WorkerControlError::WorkerGone),
    }
}
