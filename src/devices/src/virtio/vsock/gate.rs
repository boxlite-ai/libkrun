// SPDX-License-Identifier: Apache-2.0

//! The snapshot gate of the vsock Unix IPC backend, usable without the
//! device or proxy locks. `UnixProxy::sendmsg` runs on the event thread
//! under both locks and blocks in `send()` while the host peer reads
//! nothing, so a pause must cancel that send before it can take either.
//!
//! Quiescing shuts down every registered Unix socket through a duplicate the
//! gate owns (never a bare descriptor number, which the kernel may reuse once
//! the proxy closes it), wakes the muxer thread so it exits without accepting
//! anything, and makes the device leave further TX packets in the ring.
//! A quiesce also holds the gate: no backend start opens it again (one that
//! races the pause, such as a guest activating the device, exits at once)
//! until the owner releases it to restart the backend.
//! Registration and quiescing share one lock: a proxy registered first is
//! shut down, one registered later is refused. Shutting down a socket that
//! is not connected yet has no effect, so `UnixProxy::sendmsg` also checks
//! the gate under the proxy lock before sending: a socket connected by then
//! was shut down by a later quiesce, and an unconnected one cannot block.
//! The gate stays closed until the backend is restarted.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use nix::sys::socket::{shutdown, Shutdown};
use utils::eventfd::EventFd;

use super::proxy::ProxyError;

pub struct VsockGate {
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    open: bool,
    /// Set by `quiesce`, cleared only by `release`: `open` admits nothing.
    held: bool,
    next_key: u64,
    /// Shutdown handles of the live Unix proxies, keyed by registration.
    sockets: HashMap<u64, OwnedFd>,
    /// Wakes the running muxer thread.
    muxer_wake: Option<EventFd>,
}

/// A proxy's shutdown handle; dropping it with the proxy closes the duplicate.
pub(crate) struct GateRegistration {
    gate: Arc<VsockGate>,
    key: u64,
}

impl VsockGate {
    /// A closed gate; `open` admits proxies once a backend runs.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(VsockGate {
            state: Mutex::new(GateState::default()),
        })
    }

    /// Block new host accepts and guest connections, interrupt every
    /// blocked Unix send and wake the muxer thread so it exits; the gate
    /// stays closed until `release`. Idempotent.
    pub fn quiesce(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = false;
        state.held = true;
        for socket in state.sockets.values() {
            // ENOTCONN for a socket not connected yet; see the module comment.
            let _ = shutdown(socket.as_raw_fd(), Shutdown::Both);
        }
        if let Some(wake) = state.muxer_wake.take() {
            if let Err(e) = wake.write(1) {
                error!("failed to wake the vsock muxer thread: {e:?}");
            }
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.state.lock().unwrap().open
    }

    pub(crate) fn is_held(&self) -> bool {
        self.state.lock().unwrap().held
    }

    /// Admit proxies for a backend whose muxer thread `muxer_wake` wakes.
    /// A held gate stays closed and wakes that thread at once, so it exits.
    pub(crate) fn open(&self, muxer_wake: EventFd) {
        let mut state = self.state.lock().unwrap();
        if state.held {
            if let Err(e) = muxer_wake.write(1) {
                error!("failed to wake the vsock muxer thread: {e:?}");
            }
        } else {
            state.open = true;
        }
        state.muxer_wake = Some(muxer_wake);
    }

    /// End a quiesce's hold; the next backend start opens the gate. The
    /// owner releases an inactive device's gate on resume, so a later guest
    /// activation starts a working backend; `restart_backend` releases an
    /// activated one itself.
    pub fn release(&self) {
        self.state.lock().unwrap().held = false;
    }

    /// Keep a duplicate of `socket` to shut it down on `quiesce`; refused
    /// once the gate is closed.
    pub(crate) fn register(
        self: &Arc<Self>,
        socket: &OwnedFd,
    ) -> Result<GateRegistration, ProxyError> {
        let mut state = self.state.lock().unwrap();
        if !state.open {
            return Err(ProxyError::Quiesced);
        }
        let handle = socket.try_clone().map_err(ProxyError::SocketIo)?;
        let key = state.next_key;
        state.next_key += 1;
        state.sockets.insert(key, handle);
        Ok(GateRegistration {
            gate: self.clone(),
            key,
        })
    }
}

impl GateRegistration {
    pub(crate) fn is_gate_open(&self) -> bool {
        self.gate.is_open()
    }
}

impl Drop for GateRegistration {
    fn drop(&mut self) {
        self.gate.state.lock().unwrap().sockets.remove(&self.key);
    }
}
