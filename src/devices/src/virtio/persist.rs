// SPDX-License-Identifier: Apache-2.0

//! Device-layer state only; callers must stop guest and host RAM writers before capture.
//! These types are not a versioned on-disk format and do not freeze any device.

use std::io::{self, ErrorKind};
use std::num::Wrapping;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use super::Queue;

pub(crate) fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, reason)
}

/// Queue registers plus host cursors absent from the RAM image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueState {
    pub max_size: u16,
    pub size: u16,
    pub ready: bool,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
    pub next_avail: u16,
    pub next_used: u16,
    pub event_idx_enabled: bool,
    pub num_added: u16,
}

impl Queue {
    /// Capture against quiesced RAM. `activated` describes the owning device,
    /// not QueueReady: a guest can set QueueReady before finishing negotiation.
    pub fn save_state(&self, mem: &GuestMemoryMmap, activated: bool) -> io::Result<QueueState> {
        let state = QueueState {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: self.desc_table.raw_value(),
            avail_ring: self.avail_ring.raw_value(),
            used_ring: self.used_ring.raw_value(),
            next_avail: self.next_avail.0,
            next_used: self.next_used.0,
            event_idx_enabled: self.event_idx_enabled,
            num_added: self.num_added.0,
        };
        state.validate(mem, self.max_size, activated)?;
        Ok(state)
    }
}

impl QueueState {
    fn queue(&self) -> Queue {
        Queue {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: GuestAddress(self.desc_table),
            avail_ring: GuestAddress(self.avail_ring),
            used_ring: GuestAddress(self.used_ring),
            next_avail: Wrapping(self.next_avail),
            next_used: Wrapping(self.next_used),
            event_idx_enabled: self.event_idx_enabled,
            num_added: Wrapping(self.num_added),
        }
    }

    pub fn validate(
        &self,
        mem: &GuestMemoryMmap,
        max_size: u16,
        activated: bool,
    ) -> io::Result<()> {
        if self.max_size != max_size {
            return Err(invalid("queue capacity differs from destination"));
        }
        if !activated || !self.ready {
            if self.next_avail != 0 || self.next_used != 0 || self.num_added != 0 {
                return Err(invalid("unused queue has processing cursors"));
            }
            // Preserve arbitrary guest-written sizes and addresses during negotiation.
            return Ok(());
        }
        if self.size > 32768 || !self.queue().is_valid(mem) {
            return Err(invalid("invalid active queue layout"));
        }
        let avail: u16 = mem
            .read_obj(GuestAddress(self.avail_ring + 2))
            .map_err(io::Error::other)?;
        let used: u16 = mem
            .read_obj(GuestAddress(self.used_ring + 2))
            .map_err(io::Error::other)?;
        let pending = avail.wrapping_sub(self.next_avail);
        let in_flight = self.next_avail.wrapping_sub(self.next_used);
        if used != self.next_used
            || u32::from(pending) + u32::from(in_flight) > u32::from(self.size)
        {
            return Err(invalid("queue cursors disagree with RAM"));
        }
        // num_added is a wrapping notification accumulator, not an in-flight count;
        // it may exceed queue size when notifications have not been checked.
        Ok(())
    }

    /// Reconstruct without touching rings. In-flight descriptor chains, if any,
    /// remain the device's responsibility and must be restored separately.
    pub fn restore(
        &self,
        mem: &GuestMemoryMmap,
        max_size: u16,
        activated: bool,
    ) -> io::Result<Queue> {
        self.validate(mem, max_size, activated)?;
        Ok(self.queue())
    }
}

#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;
