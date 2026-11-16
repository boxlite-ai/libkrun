use std::io;
use std::sync::Mutex;

use utils::eventfd::{EventFd, EFD_NONBLOCK};

pub const SLOT_MIB: u32 = 128;
pub const MIB: u64 = 1 << 20;
pub const SLOT_SIZE: u64 = SLOT_MIB as u64 * MIB;
pub const BLOCK_SIZE: u64 = 2 * MIB;

/// Absolute sizes, including boot RAM. Published atomically under the control lock.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryStatus {
    pub max_mib: u32,
    pub requested_mib: u32,
    pub plugged_mib: u32,
    pub mapped_mib: u32,
    pub error: i32,
    pub active: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_excludes_targets_and_resume_rearms_an_unprocessed_target() {
        let control = MemoryControl::new(256, 512).unwrap();
        control.activate();
        control.request(384).unwrap();
        control.freeze();
        let before = control.status();
        assert_eq!(
            control.request(512).unwrap_err().raw_os_error(),
            Some(libc::EBUSY)
        );
        assert_eq!(control.status(), before);
        control.event.read().unwrap();
        control.resume().unwrap();
        assert_eq!(control.event.read().unwrap(), 1);
        assert_eq!(control.status().requested_mib, 384);
        control.request(512).unwrap();
    }
}

/// Only the event-loop thread mutates the device. API threads submit monotonic
/// targets through this mailbox and read progress without taking its device lock.
pub struct MemoryControl {
    pub(crate) event: EventFd,
    pub initial_mib: u32,
    state: Mutex<ControlState>,
}

struct ControlState {
    status: MemoryStatus,
    frozen: bool,
}

impl MemoryControl {
    pub fn new(initial_mib: u32, max_mib: u32) -> io::Result<Self> {
        if max_mib <= initial_mib || !(max_mib - initial_mib).is_multiple_of(SLOT_MIB) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            event: EventFd::new(EFD_NONBLOCK)?,
            initial_mib,
            state: Mutex::new(ControlState {
                frozen: false,
                status: MemoryStatus {
                    max_mib,
                    requested_mib: initial_mib,
                    plugged_mib: initial_mib,
                    mapped_mib: initial_mib,
                    ..Default::default()
                },
            }),
        })
    }

    pub fn status(&self) -> MemoryStatus {
        self.state.lock().unwrap().status
    }

    pub fn request(&self, total_mib: u32) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.frozen {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let state = &mut state.status;
        if state.active == 0 {
            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
        }
        if total_mib < state.requested_mib
            || total_mib > state.max_mib
            || !(total_mib - self.initial_mib).is_multiple_of(SLOT_MIB)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.event.write(1)?;
        state.requested_mib = total_mib;
        state.error = 0;
        Ok(())
    }

    pub(crate) fn initialize(&self, region_size: u64) {
        self.state.lock().unwrap().status.max_mib = self.initial_mib + (region_size / MIB) as u32;
    }

    pub(crate) fn activate(&self) {
        self.state.lock().unwrap().status.active = 1;
    }

    pub(crate) fn progress(&self, plugged: u64, mapped: u64, error: i32) {
        let mut state = self.state.lock().unwrap();
        let state = &mut state.status;
        state.plugged_mib = self.initial_mib + (plugged / MIB) as u32;
        state.mapped_mib = self.initial_mib + (mapped / MIB) as u32;
        state.error = error;
    }

    // Called under the device lock. The same lock as request() establishes
    // whether an online target belongs before or after the snapshot boundary.
    pub(crate) fn freeze(&self) {
        self.state.lock().unwrap().frozen = true;
    }

    pub(crate) fn resume(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        // A request accepted just before freeze may not yet have reached the
        // event loop. Always re-arm it, including after cross-process restore.
        self.event.write(1)?;
        state.frozen = false;
        Ok(())
    }

    pub(crate) fn restore(&self, status: MemoryStatus) {
        let mut state = self.state.lock().unwrap();
        assert!(state.frozen);
        state.status = status;
    }
}
