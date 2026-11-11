// SPDX-License-Identifier: Apache-2.0
use super::*;
use crossbeam_channel::bounded;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcpuState {
    pub cpu: hvf::snapshot::CpuState,
    pub powered: bool,
}
#[derive(Debug)]
pub(crate) enum Command {
    Pause,
    Resume,
    Capture,
    Restore(Box<VcpuState>),
    AdjustClock(u64),
}
#[derive(Debug)]
pub(crate) enum Reply {
    Done,
    Saved(Box<VcpuState>),
}
#[derive(Debug)]
pub struct Request {
    pub(super) command: Command,
    pub(super) deadline: Instant,
    pub(super) reply: Sender<Result<Reply>>,
}
impl VcpuHandle {
    pub(crate) fn control(&mut self, command: Command, deadline: Instant) -> Result<Reply> {
        if self.control_failed || self.vcpu_thread.is_none() || Instant::now() >= deadline {
            return Err(Error::Checkpoint(io::Error::other(
                "CPU control unavailable",
            )));
        }
        let (reply, receiver) = bounded(1);
        self.control_failed = true;
        self.send_event(VcpuEvent::Checkpoint(Request {
            command,
            deadline,
            reply,
        }))?;
        loop {
            match receiver.recv_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            ) {
                Ok(Ok(reply)) if Instant::now() < deadline => {
                    self.control_failed = false;
                    return Ok(reply);
                }
                Ok(Err(e)) => return Err(e),
                _ if Instant::now() >= deadline => {
                    return Err(Error::Checkpoint(io::Error::other(
                        "CPU acknowledgement timed out",
                    )))
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    return Err(Error::VcpuRun)
                }
                _ => {
                    let _ = hvf::vcpu_request_exit(self.hvf_id);
                }
            }
        }
    }
    pub(crate) fn stop(&mut self, deadline: Instant) -> Result<()> {
        self.control_failed = true;
        if self.vcpu_thread.is_none() {
            return Ok(());
        }
        let _ = self.send_event(VcpuEvent::Stop);
        while !self.vcpu_thread.as_ref().unwrap().is_finished() {
            if Instant::now() >= deadline {
                return Err(Error::VcpuRun);
            }
            let _ = hvf::vcpu_request_exit(self.hvf_id);
            thread::sleep(Duration::from_millis(1));
        }
        self.vcpu_thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| Error::VcpuRun)
    }
    pub(crate) fn stop_and_join(&mut self) {
        while self.vcpu_thread.is_some() {
            let _ = self.stop(Instant::now() + Duration::from_secs(1));
        }
    }
}
impl Drop for VcpuHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::eventfd::EFD_NONBLOCK;
    use vm_memory::Bytes;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn capture(cpu: &mut VcpuHandle) -> Box<VcpuState> {
        match cpu.control(Command::Capture, deadline()).unwrap() {
            Reply::Saved(state) => state,
            _ => panic!("missing CPU state"),
        }
    }
    #[test]
    fn pause_covers_powered_off_and_wfe_cpus_and_restores_on_owner_thread() {
        let _guard = TEST_VM_LOCK.lock().unwrap();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x8000_0000), 0x4000)]).unwrap();
        // WFE; B back to WFE. This exercises a host-side wait with no timer.
        memory
            .write_slice(
                &[0x5f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0x17],
                GuestAddress(0x8000_0000),
            )
            .unwrap();
        let mut vm = Vm::new(false).unwrap();
        vm.memory_init(&memory).unwrap();
        let cpus = Arc::new(VcpuList::new(2));
        let (boot, receiver) = unbounded();
        let mut cpu0 = Vcpu::new_aarch64(
            0,
            GuestAddress(0x8000_0000),
            None,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            cpus.clone(),
            false,
        )
        .unwrap()
        .start_threaded()
        .unwrap();
        let mut cpu1 = Vcpu::new_aarch64(
            1,
            GuestAddress(0),
            Some(receiver),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            cpus,
            false,
        )
        .unwrap()
        .start_threaded()
        .unwrap();
        cpu0.control(Command::Resume, deadline()).unwrap();
        cpu1.control(Command::Resume, deadline()).unwrap();
        thread::sleep(Duration::from_millis(10));
        for cpu in [&mut cpu0, &mut cpu1] {
            cpu.control(Command::Pause, deadline()).unwrap();
        }
        let saved = capture(&mut cpu1);
        assert!(!saved.powered);
        let waiting = capture(&mut cpu0);
        assert!(waiting.powered);
        assert_eq!(waiting.cpu.regs[31], 0x8000_0004);
        // CPU_ON arrives while paused and must not be lost in the checkpoint.
        boot.send((0x8000_0000, 0x12345678)).unwrap();
        let saved = capture(&mut cpu1);
        assert!(saved.powered);
        assert_eq!(saved.cpu.regs[0], 0x12345678);
        cpu1.control(Command::Restore(saved), deadline()).unwrap(); // not yet executed
        cpu0.control(Command::Resume, deadline()).unwrap();
        cpu0.control(Command::Pause, deadline()).unwrap();
        cpu0.stop(deadline()).unwrap();
        cpu1.stop(deadline()).unwrap();
        drop(cpu0);
        drop(cpu1);
        drop(vm);
        let mut vm = Vm::new(false).unwrap();
        vm.memory_init(&memory).unwrap();
        let mut cpu = Vcpu::new_aarch64(
            0,
            GuestAddress(0),
            None,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Arc::new(VcpuList::new(1)),
            false,
        )
        .unwrap()
        .start_threaded()
        .unwrap();
        cpu.control(Command::Restore(waiting), deadline()).unwrap();
        cpu.control(Command::Resume, deadline()).unwrap();
        cpu.control(Command::Pause, deadline()).unwrap();
        assert!(capture(&mut cpu).powered);
        cpu.stop(deadline()).unwrap();
    }
}
