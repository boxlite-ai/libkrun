use std::io;
use std::sync::Mutex;

use utils::eventfd::{EventFd, EFD_NONBLOCK};

pub const SLOT_MIB: u32 = 128;
pub const MIB: u64 = 1 << 20;
pub const SLOT_SIZE: u64 = SLOT_MIB as u64 * MIB;
pub const BLOCK_SIZE: u64 = 2 * MIB;

/// Absolute sizes, including boot RAM. Published atomically under the control lock.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStatus {
    pub max_mib: u32,
    pub requested_mib: u32,
    pub plugged_mib: u32,
    pub mapped_mib: u32,
    pub error: i32,
    pub active: u32,
}

/// Only the event-loop thread mutates the device. API threads submit monotonic
/// targets through this mailbox and read progress without taking its device lock.
pub struct MemoryControl {
    pub(crate) event: EventFd,
    pub initial_mib: u32,
    state: Mutex<MemoryStatus>,
    frozen: Mutex<bool>,
}

impl MemoryControl {
    pub fn new(initial_mib: u32, max_mib: u32) -> io::Result<Self> {
        if max_mib <= initial_mib || (max_mib - initial_mib) % SLOT_MIB != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            event: EventFd::new(EFD_NONBLOCK)?,
            initial_mib,
            frozen: Mutex::new(false),
            state: Mutex::new(MemoryStatus {
                max_mib,
                requested_mib: initial_mib,
                plugged_mib: initial_mib,
                mapped_mib: initial_mib,
                ..Default::default()
            }),
        })
    }

    pub fn status(&self) -> MemoryStatus {
        *self.state.lock().unwrap()
    }

    pub fn request(&self, total_mib: u32) -> io::Result<()> {
        let frozen = self.frozen.lock().unwrap();
        if *frozen {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let mut state = self.state.lock().unwrap();
        if state.active == 0 {
            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
        }
        if total_mib < state.requested_mib
            || total_mib > state.max_mib
            || (total_mib - self.initial_mib) % SLOT_MIB != 0
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.event.write(1)?;
        state.requested_mib = total_mib;
        state.error = 0;
        Ok(())
    }

    /// Serialize request admission with the owner's pause cut.
    pub fn freeze(&self, frozen: bool) {
        *self.frozen.lock().unwrap() = frozen;
    }

    pub(super) fn restore(&self, status: MemoryStatus) {
        self.freeze(true);
        *self.state.lock().unwrap() = status;
    }

    pub(crate) fn initialize(&self, region_size: u64) {
        self.state.lock().unwrap().max_mib = self.initial_mib + (region_size / MIB) as u32;
    }

    pub(crate) fn activate(&self) {
        self.state.lock().unwrap().active = 1;
    }

    pub(crate) fn progress(&self, plugged: u64, mapped: u64, error: i32) {
        let mut state = self.state.lock().unwrap();
        state.plugged_mib = self.initial_mib + (plugged / MIB) as u32;
        state.mapped_mib = self.initial_mib + (mapped / MIB) as u32;
        state.error = error;
    }
}
