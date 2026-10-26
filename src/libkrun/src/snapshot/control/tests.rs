// SPDX-License-Identifier: Apache-2.0

//! The owner channel and lifecycle with a fake VM: no KVM. Every test
//! name contains "snapshot" for the snapshot make targets' filter.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Condvar;
use std::time::Duration;

use super::*;

const LONG: Duration = Duration::from_secs(10);
const SHORT: Duration = Duration::from_millis(200);

/// A context ID no `krun_create_ctx` hands out in these tests.
fn ctx_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0x4000_0000);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    assert!(register(id));
    id
}

/// What the fake does and records, shared with the test.
#[derive(Default)]
struct Script {
    state: Mutex<Option<State>>,
    ended: Mutex<bool>,
    changed: Condvar,
    /// The operations run, in order.
    log: Mutex<Vec<&'static str>>,
    /// Set while an operation runs; an overlap is recorded.
    busy: AtomicBool,
    overlapped: AtomicBool,
    dropped: AtomicBool,
    fail_export: AtomicBool,
    fail_pause_uncertain: AtomicBool,
    /// Holds the next export until the test sends.
    export_gate: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}

impl Script {
    fn new() -> Arc<Self> {
        let script = Arc::new(Self::default());
        *script.state.lock().unwrap() = Some(State::Running);
        script
    }

    fn state(&self) -> State {
        self.state.lock().unwrap().unwrap()
    }

    fn set(&self, state: State) {
        *self.state.lock().unwrap() = Some(state);
        if state.ended() {
            *self.ended.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    fn log(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().clone()
    }
}

struct Fake(Arc<Script>);

impl Fake {
    fn op(
        &self,
        name: &'static str,
        run: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.0.busy.swap(true, Ordering::SeqCst) {
            self.0.overlapped.store(true, Ordering::SeqCst);
        }
        self.0.log.lock().unwrap().push(name);
        let result = run();
        self.0.busy.store(false, Ordering::SeqCst);
        result
    }
}

impl Vm for Fake {
    fn pause(&mut self, host_writers_stopped: bool) -> Result<(), String> {
        let script = self.0.clone();
        let name = if host_writers_stopped {
            "pause+declared"
        } else {
            "pause"
        };
        self.op(name, || {
            if script.fail_pause_uncertain.load(Ordering::SeqCst) {
                script.set(State::Stopped);
                return Err("vCPU 0 pause acknowledgment: timeout".into());
            }
            script.set(State::Paused);
            Ok(())
        })
    }

    fn resume(&mut self) -> Result<(), String> {
        let script = self.0.clone();
        self.op("resume", || {
            script.set(State::Running);
            Ok(())
        })
    }

    fn export(&mut self, _path: &Path) -> Result<(), String> {
        let script = self.0.clone();
        self.op("export", || {
            let gate = script.export_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            if script.fail_export.load(Ordering::SeqCst) {
                return Err("RAM snapshot I/O: No space left on device".into());
            }
            Ok(())
        })
    }

    fn stop(&mut self) {
        let script = self.0.clone();
        let _ = self.op("stop", || {
            if !script.state().ended() {
                script.set(State::Stopped);
            }
            Ok(())
        });
    }

    fn state(&mut self) -> State {
        self.0.state()
    }

    fn exit_watch(&self) -> Box<dyn FnOnce() + Send> {
        let script = self.0.clone();
        Box::new(move || {
            let mut ended = script.ended.lock().unwrap();
            while !*ended {
                ended = script.changed.wait(ended).unwrap();
            }
        })
    }

    fn restored_shares(&self) -> Vec<(String, PathBuf)> {
        vec![("volume0".into(), PathBuf::from("/box/shares/0/data"))]
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        // Like the VM: dropping ends every thread and releases the waits.
        *self.0.ended.lock().unwrap() = true;
        self.0.changed.notify_all();
        self.0.dropped.store(true, Ordering::SeqCst);
    }
}

/// Start an owner on its own thread; `serve`'s result arrives on the
/// receiver.
fn own(ctx: u32, script: &Arc<Script>) -> Receiver<i32> {
    let fake = Fake(script.clone());
    let (done, served) = mpsc::channel();
    thread::spawn(move || done.send(serve(ctx, || Ok(fake))).unwrap());
    let deadline = std::time::Instant::now() + LONG;
    while state(ctx) == Ok(State::Starting) || state(ctx) == Ok(State::Configured) {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner never started"
        );
        thread::sleep(Duration::from_millis(5));
    }
    served
}

/// Send `request` from another thread; its answer arrives on the receiver.
fn send(ctx: u32, make: impl FnOnce() -> Request + Send + 'static) -> Receiver<i32> {
    let (done, answer) = mpsc::channel();
    thread::spawn(move || done.send(request(ctx, make())).unwrap());
    answer
}

#[test]
fn snapshot_control_refuses_unknown_and_unstarted_contexts_and_frees_configured_ones() {
    let unknown = 0x7fff_fff0;
    assert_eq!(request(unknown, Request::Resume), -libc::ENOENT);
    assert_eq!(state(unknown), Err(-libc::ENOENT));
    assert_eq!(free(unknown), None);

    let ctx = ctx_id();
    assert!(!register(ctx), "a second entry for one context");
    assert_eq!(state(ctx), Ok(State::Configured));
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        -libc::EAGAIN
    );
    assert_eq!(request(ctx, Request::Stop), -libc::EAGAIN);
    assert_eq!(restored_share(ctx, "volume0"), Err(-libc::ENOENT));
    assert_eq!(free(ctx), Some(0));
    assert_eq!(state(ctx), Err(-libc::ENOENT));
    // A freed context cannot be started anymore.
    let script = Script::new();
    let fake = Fake(script.clone());
    assert_eq!(serve(ctx, || Ok(fake)), -libc::ENOENT);
}

#[test]
fn snapshot_control_failed_start_leaves_queued_requests_unrun() {
    let ctx = ctx_id();
    let (starting, started) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let (done, served) = mpsc::channel();
    thread::spawn(move || {
        done.send(serve::<Fake>(ctx, || {
            starting.send(()).unwrap();
            released.recv().unwrap();
            Err(-libc::EIO)
        }))
        .unwrap()
    });
    started.recv_timeout(LONG).unwrap();
    assert_eq!(state(ctx), Ok(State::Starting));
    assert_eq!(free(ctx), Some(-libc::EBUSY));
    let pause = send(ctx, || Request::Pause {
        host_writers_stopped: true,
    });
    let stop = send(ctx, || Request::Stop);
    // Both wait in the queue for the start.
    assert_eq!(pause.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
    assert_eq!(stop.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
    release.send(()).unwrap();
    assert_eq!(served.recv_timeout(LONG).unwrap(), -libc::EIO);
    assert_eq!(pause.recv_timeout(LONG).unwrap(), -libc::ESRCH);
    assert_eq!(stop.recv_timeout(LONG).unwrap(), 0, "the VM never ran");
    assert_eq!(state(ctx), Ok(State::Failed));
    assert_eq!(request(ctx, Request::Resume), -libc::ESRCH);
    assert_eq!(free(ctx), Some(0));
}

#[test]
fn snapshot_control_serializes_requests_and_reads_state_during_a_long_export() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    assert_eq!(state(ctx), Ok(State::Running));
    assert_eq!(
        restored_share(ctx, "volume0"),
        Ok(PathBuf::from("/box/shares/0/data"))
    );
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: true
            }
        ),
        0
    );
    assert_eq!(state(ctx), Ok(State::Paused));

    let (entered, export_entered) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    *script.export_gate.lock().unwrap() = Some((entered, gate));
    let export = send(ctx, || Request::Export(PathBuf::from("/box/export.img")));
    export_entered.recv_timeout(LONG).unwrap();
    // Concurrent callers queue behind the running export; reading the
    // state does not.
    let resume = send(ctx, || Request::Resume);
    let pause = send(ctx, || Request::Pause {
        host_writers_stopped: false,
    });
    assert_eq!(state(ctx), Ok(State::Paused));
    assert_eq!(free(ctx), Some(-libc::EBUSY));
    assert_eq!(export.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
    assert_eq!(resume.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
    release.send(()).unwrap();
    assert_eq!(export.recv_timeout(LONG).unwrap(), 0);
    let mut answers = [
        resume.recv_timeout(LONG).unwrap(),
        pause.recv_timeout(LONG).unwrap(),
    ];
    answers.sort();
    // Either order runs exactly one of them first; neither overlaps.
    assert!(
        answers == [0, 0] || answers == [-libc::EINVAL, 0],
        "{answers:?}"
    );
    assert!(!script.overlapped.load(Ordering::SeqCst));
    let log = script.log();
    assert_eq!(log[..2], ["pause+declared", "export"]);
    assert!(log[2..].contains(&"resume"), "{log:?}");

    assert_eq!(request(ctx, Request::Stop), 0);
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
    assert!(script.dropped.load(Ordering::SeqCst));
    assert_eq!(state(ctx), Ok(State::Stopped));
    assert_eq!(free(ctx), Some(0));
}

#[test]
fn snapshot_control_refuses_requests_the_state_does_not_allow_without_running_them() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    assert_eq!(request(ctx, Request::Resume), -libc::EINVAL);
    assert_eq!(
        request(ctx, Request::Export(PathBuf::from("/box/export.img"))),
        -libc::EINVAL
    );
    assert!(script.log().is_empty());
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        0
    );
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        -libc::EINVAL
    );
    assert_eq!(script.log(), ["pause"]);
    assert_eq!(state(ctx), Ok(State::Paused));
    assert_eq!(request(ctx, Request::Stop), 0);
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
}

#[test]
fn snapshot_control_failed_export_keeps_the_vm_paused() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        0
    );
    script.fail_export.store(true, Ordering::SeqCst);
    assert_eq!(
        request(ctx, Request::Export(PathBuf::from("/box/export.img"))),
        -libc::EIO
    );
    assert_eq!(state(ctx), Ok(State::Paused));
    // Not replayed: one export ran.
    assert_eq!(script.log(), ["pause", "export"]);
    assert_eq!(request(ctx, Request::Resume), 0);
    assert_eq!(state(ctx), Ok(State::Running));
    assert_eq!(request(ctx, Request::Stop), 0);
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
}

#[test]
fn snapshot_control_uncertain_pause_ends_execution_and_the_owner() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    script.fail_pause_uncertain.store(true, Ordering::SeqCst);
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        -libc::EIO
    );
    assert_eq!(state(ctx), Ok(State::Stopped));
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
    assert!(script.dropped.load(Ordering::SeqCst));
    assert_eq!(request(ctx, Request::Resume), -libc::ESRCH);
    assert_eq!(request(ctx, Request::Stop), 0);
    assert_eq!(free(ctx), Some(0));
    assert_eq!(request(ctx, Request::Stop), -libc::ENOENT);
}

#[test]
fn snapshot_control_publishes_a_guest_exit_and_ends_the_owner() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    assert_eq!(free(ctx), Some(-libc::EBUSY));
    // The guest exits on its own while running: the exit watch tells the
    // owner, with no request pending.
    script.set(State::Exited(3));
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
    assert_eq!(state(ctx), Ok(State::Exited(3)));
    assert!(script.dropped.load(Ordering::SeqCst));
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        -libc::ESRCH
    );
    assert_eq!(request(ctx, Request::Stop), 0);
    assert!(script.log().is_empty(), "no request ran after the exit");
    assert_eq!(free(ctx), Some(0));
}

#[test]
fn snapshot_control_stop_of_a_paused_vm_ends_the_owner_after_dropping_it() {
    let ctx = ctx_id();
    let script = Script::new();
    let served = own(ctx, &script);
    assert_eq!(
        request(
            ctx,
            Request::Pause {
                host_writers_stopped: false
            }
        ),
        0
    );
    assert_eq!(request(ctx, Request::Stop), 0);
    assert_eq!(state(ctx), Ok(State::Stopped));
    assert_eq!(served.recv_timeout(LONG).unwrap(), 0);
    assert!(script.dropped.load(Ordering::SeqCst));
    assert_eq!(script.log(), ["pause", "stop"]);
}
