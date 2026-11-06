// SPDX-License-Identifier: Apache-2.0

//! Owning-thread checkpoint requests. A fresh reply channel per request avoids
//! consuming a stale acknowledgement after a deadline. These are CPU barriers,
//! not VM barriers: device writers and IRQ/time producers must also be frozen.

use std::io;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Sender};
use utils::sm::StateMachine;

#[cfg(target_arch = "x86_64")]
use super::VcpuState;
use super::{Error, Result, Vcpu, VcpuEvent, VcpuHandle};

#[derive(Debug)]
pub(crate) enum Command {
    Pause,
    Resume,
    #[cfg(target_arch = "x86_64")]
    Capture,
    #[cfg(target_arch = "x86_64")]
    Restore(Box<VcpuState>),
}

#[derive(Debug)]
pub(crate) enum Reply {
    Done,
    #[cfg(target_arch = "x86_64")]
    Saved(Box<VcpuState>),
}

#[derive(Debug)]
pub struct Request {
    command: Command,
    deadline: Instant,
    reply: Sender<Result<Reply>>,
}

fn failed(reason: &'static str) -> Error {
    Error::Checkpoint(io::Error::other(reason))
}

impl Vcpu {
    pub(super) fn checkpoint(&mut self, request: Request, _paused: bool) -> StateMachine<Self> {
        let mut resume = false;
        let result = if self.checkpoint_failed || Instant::now() >= request.deadline {
            Err(failed(
                "vCPU checkpoint request expired or requires teardown",
            ))
        } else {
            match request.command {
                Command::Pause => {
                    #[cfg(target_arch = "x86_64")]
                    if !_paused {
                        if let Err(error) = self.fd.kvmclock_ctrl() {
                            // kvm_set_guest_paused returns EINVAL when the guest
                            // has not enabled a pvclock page (e.g. early boot).
                            if error.errno() != libc::EINVAL {
                                self.checkpoint_failed = true;
                                let _ = request
                                    .reply
                                    .try_send(Err(Error::Checkpoint(io::Error::other(error))));
                                return StateMachine::next(Self::paused);
                            }
                        }
                    }
                    Ok(Reply::Done)
                }
                Command::Resume => {
                    resume = true;
                    Ok(Reply::Done)
                }
                #[cfg(target_arch = "x86_64")]
                Command::Capture if _paused => {
                    self.save_state().map(|state| Reply::Saved(Box::new(state)))
                }
                #[cfg(target_arch = "x86_64")]
                Command::Restore(state) if _paused && !self.checkpoint_has_run => {
                    self.restore_state(*state).map(|()| Reply::Done)
                }
                #[cfg(target_arch = "x86_64")]
                _ => Err(failed("vCPU state access requires a confirmed pause")),
            }
        };
        self.checkpoint_failed |= result.is_err();
        if Instant::now() >= request.deadline || request.reply.try_send(result).is_err() {
            self.checkpoint_failed = true;
        }
        if resume && !self.checkpoint_failed {
            self.checkpoint_has_run = true;
            StateMachine::next(Self::running)
        } else {
            StateMachine::next(Self::paused)
        }
    }
}

impl VcpuHandle {
    /// Final owner destruction cannot release guest RAM while KVM still uses
    /// its slots. A timed-out control retains ownership; this final join waits
    /// until that thread really exits, even if host I/O delayed the stop.
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    pub(crate) fn stop_and_join(&mut self) {
        self.control_failed = true;
        if self.vcpu_thread.is_some() {
            let _ = self.send_event(VcpuEvent::Stop);
        }
        if let Some(thread) = self.vcpu_thread.take() {
            if thread.join().is_err() {
                error!("vCPU panicked during teardown");
            }
        }
    }

    pub(crate) fn control(&mut self, command: Command, deadline: Instant) -> Result<Reply> {
        if self.control_failed || self.vcpu_thread.is_none() {
            return Err(failed("vCPU controller requires teardown"));
        }
        if Instant::now() >= deadline {
            return Err(failed("vCPU deadline elapsed before submission"));
        }
        let (reply, receiver) = bounded(1);
        // Once submitted, wake failure or missing/late acknowledgement is an
        // unknown outcome. No later resume/state request may use this handle.
        self.control_failed = true;
        self.send_event(VcpuEvent::Checkpoint(Request {
            command,
            deadline,
            reply,
        }))?;
        match receiver.recv_deadline(deadline) {
            Ok(Ok(reply)) if Instant::now() < deadline => {
                self.control_failed = false;
                Ok(reply)
            }
            Ok(Err(error)) => Err(error),
            _ => Err(failed(
                "vCPU request outcome unknown; stop and join required",
            )),
        }
    }

    /// A timed out stop retains the thread handle. Its owner must retain the
    /// VM/resources and retry after unblocking any external I/O dependency.
    pub(crate) fn stop(&mut self, deadline: Instant) -> Result<()> {
        self.control_failed = true;
        let Some(thread) = self.vcpu_thread.as_ref() else {
            return Ok(());
        };
        if !thread.is_finished() {
            let _ = self.send_event(VcpuEvent::Stop);
        }
        while !self.vcpu_thread.as_ref().unwrap().is_finished() {
            if Instant::now() >= deadline {
                return Err(failed("vCPU stop not acknowledged; retain VM resources"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.vcpu_thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| failed("vCPU thread panicked"))
    }
}

#[cfg(all(test, target_arch = "x86_64", not(feature = "tee")))]
mod tests {
    use super::super::{KvmContext, Vm};
    use super::*;
    use devices::legacy::KvmIoapic;
    use kvm_bindings::{kvm_mp_state, kvm_regs, KVM_MP_STATE_RUNNABLE};
    use utils::eventfd::{EventFd, EFD_NONBLOCK};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn vm(memory: &GuestMemoryMmap) -> Vm {
        let kvm = KvmContext::new().unwrap();
        let mut vm = Vm::new(kvm.fd()).unwrap();
        KvmIoapic::new(vm.fd()).unwrap();
        vm.memory_init(memory, kvm.max_memslots()).unwrap();
        vm
    }

    fn cpu(vm: &Vm, id: u8) -> Vcpu {
        Vcpu::new_x86_64(
            id,
            vm.fd(),
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            devices::Bus::new(),
            EventFd::new(EFD_NONBLOCK).unwrap(),
        )
        .unwrap()
    }

    fn capture(handle: &mut VcpuHandle) -> Box<VcpuState> {
        match handle.control(Command::Capture, deadline()).unwrap() {
            Reply::Saved(state) => state,
            Reply::Done => panic!("capture returned no state"),
        }
    }

    #[test]
    fn smp_owning_thread_capture_restore_and_repeat() {
        Vcpu::register_kick_signal_handler();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let source = vm(&memory);
        let mut handles = Vec::new();
        for id in 0..2 {
            let cpu = cpu(&source, id);
            let address = 0x4000 + u16::from(id) * 8;
            let entry = 0x1000 + u64::from(id) * 32;
            memory
                .write_slice(
                    &[
                        0x66,
                        0xff,
                        0x06,
                        address as u8,
                        (address >> 8) as u8,
                        0xeb,
                        0xf9,
                    ],
                    GuestAddress(entry),
                )
                .unwrap();
            let mut sregs = cpu.fd.get_sregs().unwrap();
            sregs.cs.base = 0;
            sregs.cs.selector = 0;
            cpu.fd.set_sregs(&sregs).unwrap();
            cpu.fd
                .set_regs(&kvm_regs {
                    rip: entry,
                    rflags: 2,
                    ..Default::default()
                })
                .unwrap();
            cpu.fd
                .set_mp_state(kvm_mp_state {
                    mp_state: KVM_MP_STATE_RUNNABLE,
                })
                .unwrap();
            cpu.fd.set_cpuid2(&cpu.cpuid).unwrap();
            handles.push(cpu.start_threaded().unwrap());
        }
        for handle in &mut handles {
            handle.control(Command::Resume, deadline()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        for handle in &mut handles {
            handle.control(Command::Pause, deadline()).unwrap();
        }
        let values: Vec<u32> = (0..2)
            .map(|id| memory.read_obj(GuestAddress(0x4000 + id * 8)).unwrap())
            .collect();
        assert!(values.iter().all(|&value| value > 0));
        std::thread::sleep(Duration::from_millis(10));
        for (id, &value) in values.iter().enumerate() {
            assert_eq!(
                memory
                    .read_obj::<u32>(GuestAddress(0x4000 + id as u64 * 8))
                    .unwrap(),
                value
            );
        }
        let mut states: Vec<_> = handles.iter_mut().map(capture).collect();
        let vm_state = source.save_state().unwrap();
        let ram = crate::ram_snapshot::save(&memory).unwrap();
        for handle in &mut handles {
            handle.stop(deadline()).unwrap();
        }
        drop(handles);
        drop(source);
        drop(memory);

        let memory = crate::ram_snapshot::restore(&ram).unwrap();
        let target = vm(&memory);
        let mut handles: Vec<_> = (0..2)
            .map(|id| cpu(&target, id).start_threaded().unwrap())
            .collect();
        target.restore_state(&vm_state).unwrap();
        target.rebase_tsc(&vm_state, &mut states).unwrap();
        for (handle, state) in handles.iter_mut().zip(states) {
            handle.control(Command::Restore(state), deadline()).unwrap();
        }
        for handle in &mut handles {
            handle.control(Command::Resume, deadline()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        for handle in &mut handles {
            handle.control(Command::Pause, deadline()).unwrap();
        }
        for (id, &value) in values.iter().enumerate() {
            assert!(
                memory
                    .read_obj::<u32>(GuestAddress(0x4000 + id as u64 * 8))
                    .unwrap()
                    > value
            );
        }
        let mut repeated: Vec<_> = handles.iter_mut().map(capture).collect();
        let repeated_vm = target.save_state().unwrap();
        let repeated_ram = crate::ram_snapshot::save(&memory).unwrap();
        for handle in &mut handles {
            handle.stop(deadline()).unwrap();
        }
        drop(handles);
        drop(target);
        drop(memory);
        let memory = crate::ram_snapshot::restore(&repeated_ram).unwrap();
        let target = vm(&memory);
        let mut handles: Vec<_> = (0..2)
            .map(|id| cpu(&target, id).start_threaded().unwrap())
            .collect();
        target.restore_state(&repeated_vm).unwrap();
        target.rebase_tsc(&repeated_vm, &mut repeated).unwrap();
        for (handle, state) in handles.iter_mut().zip(repeated) {
            handle.control(Command::Restore(state), deadline()).unwrap();
        }
        for handle in &mut handles {
            handle.control(Command::Resume, deadline()).unwrap();
        }
        for handle in &mut handles {
            handle.control(Command::Pause, deadline()).unwrap();
        }
        for handle in &mut handles {
            handle.stop(deadline()).unwrap();
        }
    }

    #[test]
    fn abandoned_request_poisoning_prevents_late_resume() {
        Vcpu::register_kick_signal_handler();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = vm(&memory);
        let mut handle = cpu(&vm, 0).start_threaded().unwrap();
        let (reply, receiver) = bounded(1);
        drop(receiver);
        handle
            .send_event(VcpuEvent::Checkpoint(Request {
                command: Command::Pause,
                deadline: deadline(),
                reply,
            }))
            .unwrap();
        assert!(handle.control(Command::Resume, deadline()).is_err());
        assert!(handle.control(Command::Pause, deadline()).is_err());
        handle.stop(deadline()).unwrap();
    }
}
