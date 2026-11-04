// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn wait_request(worker: &WorkerControl) -> ControlRequest {
    let mut fd = libc::pollfd {
        fd: worker.event().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: fd points to one initialized pollfd, valid for this call.
    assert_eq!(unsafe { libc::poll(&mut fd, 1, 3000) }, 1);
    assert_ne!(fd.revents & libc::POLLIN, 0);
    while worker.event().read().is_ok() {}
    worker.try_recv().unwrap()
}

#[test]
fn real_poll_wake_and_freeze_resume_acknowledgements() {
    let (mut controller, worker) = channel().unwrap();
    let frozen = Arc::new(AtomicBool::new(false));
    let state = frozen.clone();
    let thread = thread::spawn(move || {
        for expected in [Command::Freeze, Command::Freeze, Command::Resume] {
            let request = wait_request(&worker);
            assert_eq!(request.command(), expected);
            assert!(!request.is_expired());
            state.store(expected == Command::Freeze, Ordering::SeqCst);
            assert!(request.respond(Ok(())));
        }
    });
    controller.request(Command::Freeze, deadline()).unwrap();
    assert!(frozen.load(Ordering::SeqCst));
    controller.request(Command::Freeze, deadline()).unwrap();
    assert!(frozen.load(Ordering::SeqCst));
    controller.request(Command::Resume, deadline()).unwrap();
    assert!(!frozen.load(Ordering::SeqCst));
    thread.join().unwrap();
}

#[test]
fn expired_before_submission_has_no_request_or_wake() {
    let (mut controller, worker) = channel().unwrap();
    assert!(matches!(
        controller.request(Command::Freeze, Instant::now()),
        Err(ControlError::Deadline)
    ));
    assert!(matches!(worker.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(
        worker.event().read().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(!controller.uncertain);
}

#[test]
fn full_channel_bounds_submission() {
    let (mut controller, worker) = channel().unwrap();
    let (reply, _result) = bounded(1);
    controller
        .sender
        .try_send(ControlRequest {
            command: Command::Freeze,
            deadline: deadline(),
            reply,
        })
        .unwrap();
    let start = Instant::now();
    assert!(matches!(
        controller.request(Command::Resume, start + Duration::from_millis(30)),
        Err(ControlError::Deadline)
    ));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(worker.try_recv().unwrap().command(), Command::Freeze);
    assert!(matches!(worker.try_recv(), Err(TryRecvError::Empty)));
    assert!(!controller.uncertain);
}

#[test]
fn worker_error_is_not_a_freeze_ack() {
    let (mut controller, worker) = channel().unwrap();
    let thread = thread::spawn(move || {
        let request = wait_request(&worker);
        assert!(request.respond(Err(io::Error::other("flush failed"))));
        let request = wait_request(&worker);
        assert_eq!(request.command(), Command::Resume);
        assert!(request.respond(Ok(())));
    });
    let error = controller.request(Command::Freeze, deadline()).unwrap_err();
    assert!(matches!(error, ControlError::Worker(ref e) if e.to_string() == "flush failed"));
    controller.request(Command::Resume, deadline()).unwrap();
    thread.join().unwrap();
}

#[test]
fn disconnect_before_and_after_submission_are_distinct() {
    let (mut controller, worker) = channel().unwrap();
    drop(worker);
    assert!(matches!(
        controller.request(Command::Freeze, deadline()),
        Err(ControlError::Disconnected)
    ));

    let (mut controller, worker) = channel().unwrap();
    let thread = thread::spawn(move || {
        let result = controller.request(Command::Freeze, deadline());
        assert!(matches!(result, Err(ControlError::OutcomeUnknown)));
        assert!(matches!(
            controller.request(Command::Resume, deadline()),
            Err(ControlError::Unusable)
        ));
    });
    let request = wait_request(&worker);
    drop(request);
    drop(worker);
    thread.join().unwrap();
}

#[test]
fn timeout_does_not_cancel_work_and_late_reply_cannot_enable_resume() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let (mut controller, worker) = channel().unwrap();
    let (mut io_worker, mut io_peer) = UnixStream::pair().unwrap();
    io_worker
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let frozen = Arc::new(AtomicBool::new(false));
    let worker_frozen = frozen.clone();
    let thread = thread::spawn(move || {
        let request = wait_request(&worker);
        // Model a worker draining outstanding host I/O before acknowledging Freeze.
        let mut data = [0; 1];
        io_worker.read_exact(&mut data).unwrap();
        worker_frozen.store(true, Ordering::SeqCst);
        assert!(request.is_expired());
        assert!(request.deadline() <= Instant::now());
        assert!(!request.respond(Ok(())));
        data
    });
    let start = Instant::now();
    assert!(matches!(
        controller.request(Command::Freeze, start + Duration::from_millis(80)),
        Err(ControlError::OutcomeUnknown)
    ));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(!frozen.load(Ordering::SeqCst));
    // The host I/O still completes after the timeout; no cancellation occurred.
    io_peer.write_all(&[42]).unwrap();
    assert_eq!(thread.join().unwrap(), [42]);
    assert!(frozen.load(Ordering::SeqCst));
    assert!(matches!(
        controller.request(Command::Resume, deadline()),
        Err(ControlError::Unusable)
    ));
}

#[test]
fn reply_to_disconnected_caller_never_blocks() {
    let (reply, result) = bounded(1);
    let request = ControlRequest {
        command: Command::Freeze,
        deadline: deadline(),
        reply,
    };
    drop(result);
    assert!(!request.respond(Ok(())));
}
