// SPDX-License-Identifier: Apache-2.0

//! The VM owner and its control registry. The thread in `krun_start_enter`
//! owns the VM: it creates it, runs every request on it and drops it.
//! Other threads reach it only through the context's `Control`, which
//! outlives the context map's entry: a request is queued to the owner
//! (FIFO, never retried), and its caller blocks until the owner ran it and
//! published the state it left, without a timeout (an export may write
//! gigabytes). The state is read without queueing, so it never waits for
//! a running request. A request the owner never ran (the VM ended, or never
//! started) fails with ESRCH; a stop of an ended VM succeeds.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use vmm::snapshot_vm::checkpoint::{ExportMetadata, PreparedResources};

/// Where a checkpointing VM stands, as `krun_snapshot_get_state` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// Enabled; `krun_start_enter` was not called yet.
    Configured,
    /// `krun_start_enter` boots or imports the VM.
    Starting,
    Running,
    Paused,
    /// The guest ended execution with this status.
    Exited(i32),
    /// A host-side failure ended execution, or the VM never started.
    Failed,
    /// A stop request or an uncertain control operation ended execution.
    Stopped,
}

impl State {
    pub(crate) fn ended(self) -> bool {
        matches!(self, Self::Exited(_) | Self::Failed | Self::Stopped)
    }
}

pub(crate) enum Request {
    /// With the caller's declaration that every host writer of the shares
    /// stopped until the next resume.
    Pause {
        host_writers_stopped: bool,
    },
    Resume,
    Stop,
    Begin {
        token: u64,
        disk: bool,
        session: UnixStream,
    },
    End {
        token: u64,
        success: bool,
    },
    Prepare {
        token: u64,
        result: Sender<PreparedResources>,
    },
    ExportFd {
        token: u64,
        memory: File,
        qcow2: File,
        metadata: ExportMetadata,
    },
}

/// The VM as its owner drives it.
pub(crate) trait Vm {
    fn pause(&mut self, host_writers_stopped: bool) -> Result<(), String>;
    fn resume(&mut self) -> Result<(), String>;
    fn prepare(&mut self) -> Result<PreparedResources, String> {
        Err("external capture unavailable".into())
    }
    fn export_fd(
        &mut self,
        _memory: File,
        _qcow2: File,
        _metadata: ExportMetadata,
    ) -> Result<(), String> {
        Err("descriptor export unavailable".into())
    }
    fn discard_preparation(&mut self) {}
    fn abort_flag(&self) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
    fn stop_signal(&self) -> Result<Box<dyn Fn() + Send + Sync>, String> {
        Ok(Box::new(|| {}))
    }
    fn stop(&mut self);
    /// Running, Paused or how execution ended.
    fn state(&mut self) -> State;
    /// A wait, run on its own thread, that returns once execution ended
    /// (including by `stop` or dropping the VM).
    fn exit_watch(&self) -> Box<dyn FnOnce() + Send>;
    /// Each imported share's tag and root copy.
    fn restored_shares(&self) -> Vec<(String, PathBuf)>;
}

enum Message {
    Request(Request, Sender<i32>),
    /// The exit watch returned.
    Ended,
    Abort(u64),
}

struct Shared {
    state: State,
    /// The owner's queue: present from `Starting` until execution ended.
    queue: Option<Sender<Message>>,
    restored_shares: Vec<(String, PathBuf)>,
    reservation: Option<Reservation>,
    signal: Option<Box<dyn Fn() + Send + Sync>>,
}

struct Reservation {
    token: u64,
    disk: bool,
    logical: State,
    abort: Arc<AtomicBool>,
    retired: Arc<Mutex<bool>>,
    session: UnixStream,
    watcher: Option<thread::JoinHandle<()>>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        // Release the decision lock before joining: the watcher may need it
        // to observe retirement after shutdown wakes its read.
        *self.retired.lock().unwrap() = true;
        let _ = self.session.shutdown(Shutdown::Both);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

/// A checkpointing context's control entry, from `krun_snapshot_enable`
/// until `krun_free_ctx`.
pub(crate) struct Control(Mutex<Shared>);

impl Control {
    fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn publish(&self, state: State) {
        self.shared().state = state;
    }

    /// Publish the final state and close the queue: nothing is queued
    /// anymore.
    fn end(&self, state: State) {
        let mut shared = self.shared();
        shared.state = state;
        shared.queue = None;
    }
}

static CONTROLS: LazyLock<Mutex<HashMap<u32, Arc<Control>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn controls() -> std::sync::MutexGuard<'static, HashMap<u32, Arc<Control>>> {
    CONTROLS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Create `ctx_id`'s entry; false if it has one.
pub(crate) fn register(ctx_id: u32) -> bool {
    let mut controls = controls();
    if controls.contains_key(&ctx_id) {
        return false;
    }
    controls.insert(
        ctx_id,
        Arc::new(Control(Mutex::new(Shared {
            state: State::Configured,
            queue: None,
            restored_shares: Vec::new(),
            reservation: None,
            signal: None,
        }))),
    );
    true
}

fn lookup(ctx_id: u32) -> Option<Arc<Control>> {
    controls().get(&ctx_id).cloned()
}

/// Remove `ctx_id`'s entry unless its VM is starting or live: None
/// without an entry, Some(-EBUSY) when live, else Some(0).
pub(crate) fn free(ctx_id: u32) -> Option<i32> {
    let mut controls = controls();
    let state = controls.get(&ctx_id)?.shared().state;
    if state == State::Configured || state.ended() {
        controls.remove(&ctx_id);
        Some(0)
    } else {
        Some(-libc::EBUSY)
    }
}

pub(crate) fn state(ctx_id: u32) -> Result<State, i32> {
    Ok(lookup(ctx_id).ok_or(-libc::ENOENT)?.shared().state)
}

pub(crate) fn restored_share(ctx_id: u32, tag: &str) -> Result<PathBuf, i32> {
    let control = lookup(ctx_id).ok_or(-libc::ENOENT)?;
    let shared = control.shared();
    shared
        .restored_shares
        .iter()
        .find(|(share, _)| share == tag)
        .map(|(_, root)| root.clone())
        .ok_or(-libc::ENOENT)
}

/// The answer to a request the owner never ran.
fn not_run(stop: bool) -> i32 {
    if stop {
        0
    } else {
        -libc::ESRCH
    }
}

/// Queue `request` to `ctx_id`'s owner and wait for its answer.
pub(crate) fn request(ctx_id: u32, request: Request) -> i32 {
    let Some(control) = lookup(ctx_id) else {
        return -libc::ENOENT;
    };
    let stop = matches!(request, Request::Stop);
    let (reply, answer) = mpsc::channel();
    {
        let shared = control.shared();
        if let Some(reservation) = &shared.reservation {
            if stop {
                reservation.abort.store(true, Ordering::SeqCst);
                if let Some(signal) = &shared.signal {
                    signal();
                }
            } else if !belongs(&request, reservation.token) {
                return if matches!(
                    request,
                    Request::End { .. } | Request::Prepare { .. } | Request::ExportFd { .. }
                ) {
                    -libc::ESTALE
                } else {
                    -libc::EBUSY
                };
            }
        }
        if shared.state == State::Configured {
            return -libc::EAGAIN;
        }
        let queued = shared
            .queue
            .as_ref()
            .is_some_and(|queue| queue.send(Message::Request(request, reply)).is_ok());
        if !queued {
            return not_run(stop);
        }
    }
    // A dropped reply: the owner ended without running it.
    answer.recv().unwrap_or_else(|_| not_run(stop))
}

pub(crate) fn begin(ctx_id: u32, disk: bool, session: UnixStream) -> Result<u64, i32> {
    let token = loop {
        let token = rand::random::<u64>();
        if token != 0 {
            break token;
        }
    };
    let code = request(
        ctx_id,
        Request::Begin {
            token,
            disk,
            session,
        },
    );
    if code == 0 {
        Ok(token)
    } else {
        Err(code)
    }
}

pub(crate) fn prepare(ctx_id: u32, token: u64) -> Result<PreparedResources, i32> {
    let (result, answer) = mpsc::channel();
    let code = request(ctx_id, Request::Prepare { token, result });
    if code != 0 {
        return Err(code);
    }
    answer.recv().map_err(|_| -libc::ESRCH)
}

/// Run `request` on the owner's `vm`.
fn belongs(request: &Request, token: u64) -> bool {
    matches!(request, Request::End { token: t, .. } | Request::Prepare { token: t, .. }
        | Request::ExportFd { token: t, .. } if *t == token)
}

fn run<V: Vm>(control: &Control, vm: &mut V, request: Request) -> i32 {
    let state = vm.state();
    if state.ended() {
        return not_run(matches!(request, Request::Stop));
    }
    {
        let shared = control.shared();
        if let Some(reservation) = &shared.reservation {
            if !matches!(request, Request::Stop) && !belongs(&request, reservation.token) {
                return if matches!(
                    request,
                    Request::End { .. } | Request::Prepare { .. } | Request::ExportFd { .. }
                ) {
                    -libc::ESTALE
                } else {
                    -libc::EBUSY
                };
            }
        } else if matches!(
            request,
            Request::End { .. } | Request::Prepare { .. } | Request::ExportFd { .. }
        ) {
            return -libc::ESTALE;
        }
    }
    if matches!(request, Request::Prepare { .. } | Request::ExportFd { .. })
        && control
            .shared()
            .reservation
            .as_ref()
            .is_some_and(|r| r.disk)
    {
        return -libc::EINVAL;
    }
    let outcome = match request {
        Request::Begin {
            token,
            disk,
            mut session,
        } => {
            if state != if disk { State::Running } else { State::Paused } {
                return -libc::EINVAL;
            }
            vm.discard_preparation();
            let abort = vm.abort_flag();
            abort.store(false, Ordering::SeqCst);
            let retired = Arc::new(Mutex::new(false));
            let monitor_retired = retired.clone();
            let monitor_abort = abort.clone();
            let queue = control.shared().queue.as_ref().unwrap().clone();
            let signal = match vm.stop_signal() {
                Ok(signal) => signal,
                Err(_) => return -libc::EIO,
            };
            let connection = match session.try_clone() {
                Ok(connection) => connection,
                Err(_) => return -libc::EIO,
            };
            let watcher = thread::Builder::new()
                .name("krun capture session".into())
                .spawn(move || {
                    let mut byte = [0];
                    loop {
                        let mut fd = libc::pollfd {
                            fd: session.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let ready = unsafe { libc::poll(&mut fd, 1, -1) };
                        if ready < 0 {
                            if std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            break;
                        }
                        match session.read(&mut byte) {
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::Interrupted
                                ) =>
                            {
                                continue
                            }
                            _ => break,
                        }
                    }
                    // Decide cancellation and signal atomically with respect to
                    // retirement. The watcher must never acquire Control.shared.
                    let retired = monitor_retired.lock().unwrap();
                    if !*retired {
                        monitor_abort.store(true, Ordering::SeqCst);
                        signal();
                        let _ = queue.send(Message::Abort(token));
                    }
                });
            let watcher = match watcher {
                Ok(watcher) => watcher,
                Err(_) => return -libc::EIO,
            };
            control.shared().reservation = Some(Reservation {
                token,
                disk,
                logical: state,
                abort,
                retired,
                session: connection,
                watcher: Some(watcher),
            });
            if disk {
                let result = vm.pause(true);
                if result.is_err() {
                    let reservation = control.shared().reservation.take();
                    drop(reservation);
                }
                result
            } else {
                Ok(())
            }
        }
        Request::End { success, .. } => {
            vm.discard_preparation();
            // Shared orders Stop admission against completion, including a
            // disk capture's resume. Lock order: Shared -> watcher decision;
            // neither the watcher nor these VM stop/resume paths takes Shared.
            let mut shared = control.shared();
            let reservation = shared.reservation.take().unwrap();
            let abort = reservation.abort.clone();
            let disk = reservation.disk;
            // Settle the watcher before the final cancellation decision. A
            // successful COMPLETE may acknowledge publication only after this.
            drop(reservation);
            if abort.load(Ordering::SeqCst) || !success {
                vm.stop();
                if success {
                    return -libc::ECANCELED;
                }
                Ok(())
            } else if disk {
                vm.resume()
            } else {
                Ok(())
            }
        }
        Request::Prepare { result, .. } => vm.prepare().and_then(|resources| {
            result
                .send(resources)
                .map_err(|_| "capture caller disconnected".into())
        }),
        Request::ExportFd {
            memory,
            qcow2,
            metadata,
            ..
        } => {
            let result = vm.export_fd(memory, qcow2, metadata);
            if control
                .shared()
                .reservation
                .as_ref()
                .is_some_and(|r| r.abort.load(Ordering::SeqCst))
            {
                vm.stop();
                Err("capture cancelled".into())
            } else {
                result
            }
        }
        Request::Pause {
            host_writers_stopped,
        } if state == State::Running => vm.pause(host_writers_stopped),
        Request::Resume if state == State::Paused => vm.resume(),
        Request::Stop => {
            let reservation = control.shared().reservation.take();
            drop(reservation);
            vm.stop();
            Ok(())
        }
        _ => return -libc::EINVAL,
    };
    match outcome {
        Ok(()) => 0,
        Err(e) => {
            error!("checkpointing VM: {e}");
            -libc::EIO
        }
    }
}

/// Own `ctx_id`'s VM on this thread: claim the configured entry, `start`
/// the VM, serve requests until execution ends, then drop the VM (joining
/// every VM thread). Returns 0 once a started VM ended, else `start`'s
/// error (or -ENOENT without a configured entry).
pub(crate) fn serve<V: Vm>(ctx_id: u32, start: impl FnOnce() -> Result<V, i32>) -> i32 {
    let (queue, inbox) = mpsc::channel();
    let control = {
        let controls = controls();
        let Some(control) = controls.get(&ctx_id) else {
            return -libc::ENOENT;
        };
        let mut shared = control.shared();
        if shared.state != State::Configured {
            return -libc::ENOENT;
        }
        shared.state = State::Starting;
        shared.queue = Some(queue.clone());
        drop(shared);
        control.clone()
    };
    let mut vm = match start() {
        Ok(vm) => vm,
        Err(errno) => {
            // Requests queued meanwhile drop with `inbox`, unanswered.
            control.end(State::Failed);
            return errno;
        }
    };
    let watch = vm.exit_watch();
    let watcher = thread::Builder::new()
        .name("krun snapshot exit".into())
        .spawn(move || {
            watch();
            let _ = queue.send(Message::Ended);
        });
    let watcher = match watcher {
        Ok(watcher) => watcher,
        Err(e) => {
            error!("checkpointing VM: start the exit watch: {e}");
            vm.stop();
            control.end(vm.state());
            return -libc::EIO;
        }
    };
    {
        let mut shared = control.shared();
        shared.signal = vm.stop_signal().ok();
        shared.restored_shares = vm.restored_shares();
        shared.state = vm.state();
    }
    loop {
        if control
            .shared()
            .reservation
            .as_ref()
            .is_some_and(|r| r.abort.load(Ordering::SeqCst))
        {
            vm.stop();
        }
        let state = vm.state();
        if state.ended() {
            control.end(state);
            break;
        }
        // The entry keeps a sender until `end`, so this never disconnects.
        match inbox.recv() {
            Ok(Message::Request(request, reply)) => {
                let code = run(&control, &mut vm, request);
                let state = control
                    .shared()
                    .reservation
                    .as_ref()
                    .map(|r| r.logical)
                    .unwrap_or_else(|| vm.state());
                control.publish(state);
                let _ = reply.send(code);
            }
            Ok(Message::Abort(token)) => {
                let reservation = {
                    let mut shared = control.shared();
                    if shared
                        .reservation
                        .as_ref()
                        .is_some_and(|r| r.token == token)
                    {
                        shared.reservation.take()
                    } else {
                        None
                    }
                };
                if reservation.is_some() {
                    vm.stop();
                    drop(reservation);
                    control.publish(vm.state());
                }
            }
            Ok(Message::Ended) => control.publish(vm.state()),
            Err(_) => vm.stop(),
        }
    }
    let reservation = control.shared().reservation.take();
    drop(reservation);
    drop(vm);
    let _ = watcher.join();
    // Requests queued after the end drop here, unanswered.
    drop(inbox);
    0
}

#[cfg(test)]
mod tests;
