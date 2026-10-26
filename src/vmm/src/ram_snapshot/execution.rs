// SPDX-License-Identifier: Apache-2.0

//! The private owner's guest execution barrier, shared by its vCPUs'
//! `KVM_RUN` entries and the host mapping calls (`MAP_FIXED`, `mprotect`)
//! on its live DAX windows.
//!
//! A `MAP_FIXED` that fails may leave its range unmapped, and other memory
//! of the process may take it while the window's memslot still points
//! there. So no guest code may run during the call, and none after a failed
//! one (a failed `mprotect` ends execution the same way). A vCPU holds a permit only around the `KVM_RUN` ioctl itself and
//! releases it before it emulates the exit, so a guest reset handled on a
//! vCPU thread can take the barrier too. A remapping (`exclusive`) blocks new
//! permits, kicks every holder out of `KVM_RUN` and waits until none is left
//! before its call; a failed (or panicking) call marks the barrier failed
//! before it reopens, so no permit is ever granted again, and signals the
//! owner's exit, whose watch stops every vCPU. Remappings serialize.
//! `retire` (the owner stopping its threads) refuses every waiting and later
//! permit and remapping.
//!
//! Only permit holders are kicked, and a holder deregisters under the same
//! lock before it leaves the ioctl path, so a kicked pthread ID always names
//! a live vCPU thread, never a joined one. Lock order: transport, device,
//! DAX ledger, then this barrier's lock, which is a leaf: it is never held
//! while taking another lock or during a remapping.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use devices::virtio::fs::passthrough::DaxMappingControl;
use utils::eventfd::EventFd;
use utils::signal::sigrtmin;

use crate::vstate::VCPU_RTSIG_OFFSET;

/// How often a waiting remapping kicks the permit holders again.
const KICK_INTERVAL: Duration = Duration::from_millis(10);

type Kick = Box<dyn Fn(libc::pthread_t) + Send + Sync>;

pub(crate) struct ExecutionBarrier {
    state: Mutex<State>,
    changed: Condvar,
    /// Gets a permit holder out of `KVM_RUN`.
    kick: Kick,
    /// The owner's failure eventfd, written once a remapping failed.
    exit: EventFd,
}

#[derive(Default)]
struct State {
    /// Threads holding a permit: inside `KVM_RUN` or about to enter it.
    running: Vec<libc::pthread_t>,
    /// A remapping holds the barrier, or waits for the permit holders.
    exclusive: bool,
    /// A remapping failed: no vCPU runs again.
    failed: bool,
    /// The owner stops its threads: nothing new runs.
    retired: bool,
}

impl State {
    fn ended(&self) -> bool {
        self.failed || self.retired
    }
}

/// A vCPU's leave to run `KVM_RUN` once.
pub(crate) struct Permit<'a> {
    barrier: &'a ExecutionBarrier,
    thread: libc::pthread_t,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self.barrier.lock();
        if let Some(index) = state.running.iter().position(|&t| t == self.thread) {
            state.running.swap_remove(index);
        }
        self.barrier.changed.notify_all();
    }
}

/// Reopens the barrier after a remapping, or fails it for good.
struct Holding<'a> {
    barrier: &'a ExecutionBarrier,
    owned: bool,
}

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        let mut state = self.barrier.lock();
        if !self.owned {
            state.failed = true;
            let _ = self.barrier.exit.write(1);
        }
        state.exclusive = false;
        self.barrier.changed.notify_all();
    }
}

/// Kick a vCPU thread out of `KVM_RUN` with the vCPU kick signal.
pub(crate) fn kick_vcpu(thread: libc::pthread_t) {
    // SAFETY: the thread holds a permit, so it has not exited, and the
    // owner installed the kick signal's handler before any vCPU existed.
    unsafe { libc::pthread_kill(thread, sigrtmin() + VCPU_RTSIG_OFFSET) };
}

impl ExecutionBarrier {
    pub(crate) fn new(
        exit: EventFd,
        kick: impl Fn(libc::pthread_t) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            changed: Condvar::new(),
            kick: Box::new(kick),
            exit,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        self.changed
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Leave for the calling vCPU thread to run `KVM_RUN` once; waits out a
    /// remapping. None once guest execution ended: the vCPU must exit.
    pub(crate) fn enter(&self) -> Option<Permit<'_>> {
        let mut state = self.lock();
        while state.exclusive && !state.ended() {
            state = self.wait(state);
        }
        if state.ended() {
            return None;
        }
        // SAFETY: pthread_self has no preconditions.
        let thread = unsafe { libc::pthread_self() };
        state.running.push(thread);
        Some(Permit {
            barrier: self,
            thread,
        })
    }

    /// Refuse every waiting and later permit and remapping.
    pub(crate) fn retire(&self) {
        self.lock().retired = true;
        self.changed.notify_all();
    }

    /// A remapping failed: guest execution ended for good.
    pub(crate) fn failed(&self) -> bool {
        self.lock().failed
    }
}

impl DaxMappingControl for ExecutionBarrier {
    fn exclusive(&self, remap: &mut dyn FnMut() -> bool) {
        let mut state = self.lock();
        while state.exclusive && !state.ended() {
            state = self.wait(state);
        }
        if state.ended() {
            return;
        }
        state.exclusive = true;
        while !state.running.is_empty() && !state.retired {
            state.running.iter().for_each(|&thread| (self.kick)(thread));
            state = self
                .changed
                .wait_timeout(state, KICK_INTERVAL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if state.retired {
            state.exclusive = false;
            self.changed.notify_all();
            return;
        }
        drop(state);
        let mut holding = Holding {
            barrier: self,
            owned: false,
        };
        holding.owned = remap();
    }
}

#[cfg(test)]
mod tests;
