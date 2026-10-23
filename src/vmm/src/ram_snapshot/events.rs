// SPDX-License-Identifier: Apache-2.0

//! The owner's event thread, present in every running or restored owner.
//! RNG, balloon, vsock and UART-input callbacks and the exit watch run on an
//! `EventManager` created inside this thread from the concrete devices, so
//! the public `Subscriber` threading bounds stay unchanged.
//!
//! Controls arrive on a command channel; the control eventfd only wakes the
//! thread. Commands are handled between callback batches: a freeze is
//! acknowledged after the whole current batch returned and released every
//! device lock, and a frozen thread dispatches nothing — no randomness, page
//! reclaim, UART input or exit handling, and notifications stay pending in
//! their fds for the source to continue. A thread started for a restore is
//! frozen and, on its first resume, notifies every ready queue itself,
//! independently of the source's notifications.
//!
//! The exit watch latches the owner's exit request (i8042 reset, any vCPU
//! exit, or a vsock backend that failed to reopen on an event-queue kick)
//! and stops every vCPU the owner armed it with.

use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use devices::legacy::Serial;
use devices::virtio::control::{self, CONTROL_TIMEOUT};
use devices::virtio::{Balloon, MmioTransport, Rng, Vsock};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};

use super::{Error, Result};
use crate::vstate::VcpuStop;

/// An RNG or balloon attached to the owner at its fixed slot.
pub(super) struct EventDevice<D> {
    pub(super) device: Arc<Mutex<D>>,
    pub(super) transport: Arc<Mutex<MmioTransport>>,
    pub(super) mmio_addr: u64,
    pub(super) irq: u32,
}

/// How a new event thread begins.
pub(super) enum Start {
    /// Dispatching immediately, for a source VM.
    Running,
    /// Frozen until resumed, then notifying every ready queue once.
    Restored,
}

type Reply = Sender<std::result::Result<(), String>>;

enum Command {
    Freeze {
        reply: Reply,
    },
    Resume {
        reply: Reply,
    },
    /// Every vCPU of the owner, before any of them first runs.
    Arm {
        vcpus: Vec<VcpuStop>,
        reply: Reply,
    },
}

/// The owner's exit request. The i8042 reset, every vCPU and the vsock (for
/// a fatal backend failure) hold a clone of the eventfd; only the event
/// thread reads it and latches `exiting`, which
/// is never cleared: an exiting owner takes no further snapshot or resume.
pub(super) struct Exit {
    evt: EventFd,
    exiting: AtomicBool,
}

impl Exit {
    pub(super) fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            evt: EventFd::new(EFD_NONBLOCK)?,
            exiting: AtomicBool::new(false),
        }))
    }

    /// An eventfd an exit source writes.
    pub(super) fn notifier(&self) -> Result<EventFd> {
        Ok(self.evt.try_clone()?)
    }

    /// Latched, or signalled but not yet read because the thread is frozen.
    /// Poll before loading the latch: the watch latches before it drains,
    /// so an exit drained between the two steps is still seen as latched.
    pub(super) fn requested(&self) -> bool {
        let unread = super::wiring::is_readable(&self.evt);
        unread || self.exiting.load(Ordering::SeqCst)
    }
}

/// Reads the exit eventfd and latches the request.
struct ExitWatch(Arc<Exit>);

impl Subscriber for ExitWatch {
    fn process(&mut self, _event: &EpollEvent, _event_manager: &mut EventManager) {
        // Latch before draining; see `Exit::requested`.
        self.0.exiting.store(true, Ordering::SeqCst);
        let _ = self.0.evt.read();
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(EventSet::IN, self.0.evt.as_raw_fd() as u64)]
    }
}

/// What runs on the thread.
pub(super) struct Devices {
    pub(super) exit: Arc<Exit>,
    pub(super) rng: Option<Arc<Mutex<Rng>>>,
    pub(super) balloon: Option<Arc<Mutex<Balloon>>>,
    /// Its queue callbacks only; the owner restarts its backend, which
    /// notifies the queues itself.
    pub(super) vsock: Option<Arc<Mutex<Vsock>>>,
    /// UARTs whose input the thread reads.
    pub(super) serials: Vec<Arc<Mutex<Serial>>>,
}

impl Devices {
    fn kick(&self) {
        if let Some(rng) = &self.rng {
            rng.lock().unwrap().snapshot_kick();
        }
        if let Some(balloon) = &self.balloon {
            balloon.lock().unwrap().snapshot_kick();
        }
    }
}

/// Reads the control eventfd: it only wakes `EventManager::run`.
struct Wake(EventFd);

impl Subscriber for Wake {
    fn process(&mut self, _event: &EpollEvent, _event_manager: &mut EventManager) {
        let _ = self.0.read();
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(EventSet::IN, self.0.as_raw_fd() as u64)]
    }
}

pub(super) struct EventThread {
    control: EventFd,
    commands: Option<Sender<Command>>,
    thread: Option<JoinHandle<()>>,
}

impl EventThread {
    /// Start the thread; returns once its `EventManager` holds every device.
    pub(super) fn spawn(devices: Devices, start: Start) -> Result<Self> {
        let control = EventFd::new(EFD_NONBLOCK)?;
        let wake = control.try_clone()?;
        let (commands, receiver) = bounded(4);
        let (ready, started) = bounded(1);
        let thread = thread::Builder::new()
            .name("snapshot device events".into())
            .spawn(move || run(wake, receiver, devices, start, ready))?;
        let mut owner = Self {
            control,
            commands: Some(commands),
            thread: Some(thread),
        };
        match started.recv() {
            Ok(Ok(())) => Ok(owner),
            Ok(Err(why)) => Err(Error::Full(format!("start device event thread: {why}"))),
            Err(_) => {
                owner.stop();
                Err(Error::Full("device event thread exited at start".into()))
            }
        }
    }

    /// Returns after the thread finished its current callback batch; it
    /// dispatches nothing until resumed.
    pub(super) fn freeze(&self) -> Result<()> {
        self.request(|reply| Command::Freeze { reply })
            .map_err(|e| Error::Full(format!("freeze device event thread: {e}")))
    }

    pub(super) fn resume(&self) -> Result<()> {
        self.request(|reply| Command::Resume { reply })
            .map_err(|e| Error::Full(format!("resume device event thread: {e}")))
    }

    /// Hand over a stop handle of every vCPU after the threads exist and
    /// before any first runs; the thread drops them when it is joined,
    /// before the owner joins the vCPUs.
    pub(super) fn arm(&self, vcpus: Vec<VcpuStop>) -> Result<()> {
        self.request(move |reply| Command::Arm { vcpus, reply })
            .map_err(|e| Error::Full(format!("arm exit watch: {e}")))
    }

    fn request(
        &self,
        command: impl FnOnce(Reply) -> Command,
    ) -> std::result::Result<(), control::WorkerControlError> {
        let commands = self
            .commands
            .as_ref()
            .ok_or(control::WorkerControlError::WorkerGone)?;
        control::request(commands, &self.control, CONTROL_TIMEOUT, command)
    }

    /// Stop and join the thread, frozen or not; idempotent.
    pub(super) fn stop(&mut self) {
        // A closed channel ends the thread; the wake reaches a running one.
        drop(self.commands.take());
        let _ = self.control.write(1);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EventThread {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    wake: EventFd,
    commands: Receiver<Command>,
    devices: Devices,
    start: Start,
    ready: Sender<std::result::Result<(), String>>,
) {
    let mut events = match event_manager(wake, &devices) {
        Ok(events) => events,
        Err(why) => {
            let _ = ready.send(Err(why));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    let mut frozen = matches!(start, Start::Restored);
    let mut kick_on_resume = frozen;
    let mut vcpus = Vec::new();
    let mut stopped = false;
    loop {
        // Stop each armed vCPU once after the exit latched.
        if !stopped && !vcpus.is_empty() && devices.exit.exiting.load(Ordering::SeqCst) {
            vcpus.iter().for_each(VcpuStop::stop);
            stopped = true;
        }
        // Between batches only: a frozen thread blocks here and dispatches
        // nothing; a running one handles every queued command first.
        let next = if frozen {
            commands.recv().map_err(|_| TryRecvError::Disconnected)
        } else {
            commands.try_recv()
        };
        match next {
            Ok(Command::Freeze { reply }) => {
                frozen = true;
                let _ = reply.try_send(Ok(()));
            }
            Ok(Command::Resume { reply }) => {
                frozen = false;
                if std::mem::take(&mut kick_on_resume) {
                    devices.kick();
                }
                let _ = reply.try_send(Ok(()));
            }
            Ok(Command::Arm {
                vcpus: armed,
                reply,
            }) => {
                vcpus = armed;
                let _ = reply.try_send(Ok(()));
            }
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {
                if let Err(e) = events.run() {
                    error!("device event thread: {e:?}");
                    return;
                }
            }
        }
    }
}

fn event_manager(wake: EventFd, devices: &Devices) -> std::result::Result<EventManager, String> {
    let mut events = EventManager::new().map_err(|e| format!("{e:?}"))?;
    let mut subscribers: Vec<Arc<Mutex<dyn Subscriber>>> = vec![
        Arc::new(Mutex::new(Wake(wake))),
        Arc::new(Mutex::new(ExitWatch(devices.exit.clone()))),
    ];
    for serial in &devices.serials {
        subscribers.push(serial.clone());
    }
    if let Some(rng) = &devices.rng {
        subscribers.push(rng.clone());
    }
    if let Some(balloon) = &devices.balloon {
        subscribers.push(balloon.clone());
    }
    if let Some(vsock) = &devices.vsock {
        subscribers.push(vsock.clone());
    }
    for subscriber in subscribers {
        events
            .add_subscriber(subscriber)
            .map_err(|e| format!("{e:?}"))?;
    }
    Ok(events)
}

#[cfg(test)]
pub(super) mod tests;
