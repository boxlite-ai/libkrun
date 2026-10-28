use rand::{rngs::OsRng, TryRngCore};
use utils::eventfd::EventFd;
use vm_memory::{Address, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, RngError, VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::persist::QueueState;
use crate::virtio::{DescriptorChain, InterruptTransport};

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

/// Complete descriptor chains handled per event callback.
const MAX_CHAINS_PER_CALLBACK: usize = 64;
/// Randomness returned for one request; larger buffers complete short.
const MAX_CHAIN_BYTES: u32 = 64 * 1024;
const FILL_CHUNK: usize = 4096;

pub struct Rng {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

impl Rng {
    pub(crate) fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub fn new() -> super::Result<Rng> {
        Ok(Rng {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(RngError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    pub fn id(&self) -> &str {
        defs::RNG_DEV_ID
    }

    pub fn process_req(&mut self) -> bool {
        debug!("rng: process_req()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let request = &mut queues[REQ_INDEX];
        if !request.queue.ready {
            return false;
        }
        let mut have_used = false;

        for _ in 0..MAX_CHAINS_PER_CALLBACK {
            let Some(head) = request.queue.pop(mem) else {
                return have_used;
            };
            let index = head.index;
            let written = fill_chain(mem, head);
            have_used = true;
            if let Err(e) = request.queue.add_used(mem, index, written) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        // Bounded callbacks keep a snapshot freeze prompt; the rest of the
        // ring is handled from a later callback.
        if !request.queue.is_empty(mem) {
            if let Err(e) = request.event.write(1) {
                error!("rng: failed to requeue the remaining requests: {e:?}");
            }
        }

        have_used
    }

    /// Queue state for a snapshot of a device whose event thread is frozen;
    /// `None` while inactive, when the transport still owns the queues.
    pub fn snapshot_queue_states(&self) -> Option<Vec<QueueState>> {
        let queues = self.queues.as_ref()?;
        Some(
            queues
                .iter()
                .map(|q| QueueState::from_queue(&q.queue))
                .collect(),
        )
    }

    /// Notify every ready queue, so a restored device examines its ring
    /// without the source's notifications.
    pub fn snapshot_kick(&self) {
        for queue in self.queues.iter().flatten() {
            queue.kick_if_ready();
        }
    }
}

/// Fill the device-writable buffers of one request with fresh randomness,
/// at most `MAX_CHAIN_BYTES`, and return how many bytes were written. A
/// failure ends the request early: it completes with the bytes actually
/// written and is never rewound, so the same chain is not completed twice.
fn fill_chain(mem: &GuestMemoryMmap, head: DescriptorChain) -> u32 {
    let mut chunk = [0u8; FILL_CHUNK];
    let mut written = 0u32;
    for desc in head.into_iter() {
        if written == MAX_CHAIN_BYTES {
            break;
        }
        if !desc.is_write_only() {
            error!("rng: request has a device-readable buffer");
            break;
        }
        let mut offset = 0u32;
        while offset < desc.len && written < MAX_CHAIN_BYTES {
            let len = (desc.len - offset)
                .min(MAX_CHAIN_BYTES - written)
                .min(FILL_CHUNK as u32);
            let bytes = &mut chunk[..len as usize];
            if let Err(e) = OsRng.try_fill_bytes(bytes) {
                error!("Failed to fill buffer with random data: {e:?}");
                return written;
            }
            let Some(target) = desc.addr.checked_add(u64::from(offset)) else {
                error!("rng: request buffer address overflows");
                return written;
            };
            // A buffer crossing the end of guest RAM is written partially;
            // only the bytes that reached the guest are reported.
            let copied = match mem.write(bytes, target) {
                Ok(copied) => copied as u32,
                Err(e) => {
                    error!("Failed to write slice: {e:?}");
                    return written;
                }
            };
            written += copied;
            if copied < len {
                error!("rng: request buffer ends outside guest RAM");
                return written;
            }
            offset += len;
        }
    }
    written
}

impl VirtioDevice for Rng {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_RNG
    }

    fn device_name(&self) -> &str {
        "rng"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("rng: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "rng: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    /// No worker exists: queue work runs on the owner's event thread, which
    /// controls when a restored device resumes.
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate(mem, interrupt, queues)
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod tests;
