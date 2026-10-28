// SPDX-License-Identifier: Apache-2.0

//! The execution barrier without KVM: a test thread holding a permit stands
//! in for a vCPU inside KVM_RUN, and the kick records its target instead of
//! signalling it. Every test name contains "snapshot" for
//! `make snapshot-test`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crossbeam_channel::{unbounded, Receiver};
use utils::eventfd::EFD_NONBLOCK;

use super::*;

const WAIT: Duration = Duration::from_secs(5);
/// Long enough for a thread that could proceed to have done so.
const QUIET: Duration = Duration::from_millis(100);

/// A barrier whose kicks arrive on the receiver, and its exit eventfd.
fn new_barrier() -> (Arc<ExecutionBarrier>, Receiver<libc::pthread_t>, EventFd) {
    let exit = EventFd::new(EFD_NONBLOCK).unwrap();
    let (kicks, kicked) = unbounded();
    let barrier = ExecutionBarrier::new(exit.try_clone().unwrap(), move |thread| {
        let _ = kicks.send(thread);
    });
    (barrier, kicked, exit)
}

fn this_thread() -> libc::pthread_t {
    // SAFETY: pthread_self has no preconditions.
    unsafe { libc::pthread_self() }
}

/// A remapping kicks the permit holder and runs only once it left KVM_RUN;
/// meanwhile no vCPU enters, and afterwards they run again.
#[test]
fn snapshot_execution_remapping_waits_for_every_vcpu_to_leave_kvm_run() {
    let (barrier, kicked, exit) = new_barrier();
    let permit = barrier.enter().unwrap();
    let ran = AtomicBool::new(false);
    let entered = AtomicBool::new(false);
    thread::scope(|scope| {
        let mapper = scope.spawn(|| {
            barrier.exclusive(&mut || {
                ran.store(true, Ordering::SeqCst);
                // The other vCPU still waits.
                thread::sleep(QUIET);
                !entered.load(Ordering::SeqCst)
            })
        });
        assert_eq!(kicked.recv_timeout(WAIT).unwrap(), this_thread());
        let other = scope.spawn(|| {
            let permit = barrier.enter();
            entered.store(true, Ordering::SeqCst);
            permit.is_some()
        });
        thread::sleep(QUIET);
        assert!(!ran.load(Ordering::SeqCst), "remapped inside KVM_RUN");
        assert!(!entered.load(Ordering::SeqCst), "entered KVM_RUN");
        drop(permit);
        mapper.join().unwrap();
        assert!(other.join().unwrap());
    });
    assert!(ran.load(Ordering::SeqCst));
    assert!(!barrier.failed());
    assert!(exit.read().is_err(), "no exit was signalled");
    assert!(barrier.enter().is_some());
}

/// A failed remapping ends guest execution before the barrier reopens: the
/// waiting vCPU and every later one is refused, later remappings run
/// nothing and the owner's exit is signalled; a panicking remapping fails
/// the same way.
#[test]
fn snapshot_execution_failed_remapping_refuses_every_later_permit() {
    let (barrier, _kicked, exit) = new_barrier();
    let inside = crossbeam_channel::bounded(0);
    let release = crossbeam_channel::bounded::<()>(0);
    thread::scope(|scope| {
        let mapper = scope.spawn(|| {
            barrier.exclusive(&mut || {
                inside.0.send(()).unwrap();
                release.1.recv().unwrap();
                false
            })
        });
        inside.1.recv_timeout(WAIT).unwrap();
        let waiting = scope.spawn(|| barrier.enter().is_none());
        thread::sleep(QUIET);
        release.0.send(()).unwrap();
        mapper.join().unwrap();
        assert!(waiting.join().unwrap(), "a vCPU entered after the failure");
    });
    assert!(barrier.failed());
    assert_eq!(exit.read().unwrap(), 1);
    assert!(barrier.enter().is_none());
    let ran = AtomicBool::new(false);
    barrier.exclusive(&mut || {
        ran.store(true, Ordering::SeqCst);
        true
    });
    assert!(!ran.load(Ordering::SeqCst));

    let (barrier, _kicked, exit) = new_barrier();
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        barrier.exclusive(&mut || panic!("remapping panicked"))
    }));
    assert!(panicked.is_err());
    assert!(barrier.failed());
    assert_eq!(exit.read().unwrap(), 1);
    assert!(barrier.enter().is_none());
}

/// Concurrent remappings never overlap.
#[test]
fn snapshot_execution_remappings_serialize() {
    let (barrier, _kicked, _exit) = new_barrier();
    let inside = AtomicUsize::new(0);
    let most = AtomicUsize::new(0);
    let remap = || {
        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
        most.fetch_max(now, Ordering::SeqCst);
        thread::sleep(QUIET / 4);
        inside.fetch_sub(1, Ordering::SeqCst);
        true
    };
    thread::scope(|scope| {
        let mappers: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| barrier.exclusive(&mut || remap())))
            .collect();
        mappers.into_iter().for_each(|m| m.join().unwrap());
    });
    assert_eq!(most.load(Ordering::SeqCst), 1);
    assert!(barrier.enter().is_some());
}

/// Retiring releases a remapping waiting for a vCPU in KVM_RUN (it runs
/// nothing) and a vCPU waiting to enter, and refuses every later one,
/// without failing the barrier or signalling an exit.
#[test]
fn snapshot_execution_retire_releases_waiting_vcpus_and_remappings() {
    let (barrier, kicked, exit) = new_barrier();
    let permit = barrier.enter().unwrap();
    let ran = AtomicBool::new(false);
    thread::scope(|scope| {
        let mapper = scope.spawn(|| {
            barrier.exclusive(&mut || {
                ran.store(true, Ordering::SeqCst);
                true
            })
        });
        kicked.recv_timeout(WAIT).unwrap();
        let waiting = scope.spawn(|| barrier.enter().is_none());
        thread::sleep(QUIET);
        barrier.retire();
        mapper.join().unwrap();
        assert!(waiting.join().unwrap(), "a vCPU entered after retire");
    });
    assert!(!ran.load(Ordering::SeqCst), "remapped inside KVM_RUN");
    drop(permit);
    assert!(barrier.enter().is_none());
    assert!(!barrier.failed());
    assert!(exit.read().is_err());
}
