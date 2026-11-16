use rand::{rngs::OsRng, TryRngCore};
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, RngError, VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::persist::{invalid, EventDeviceState, QueueState, VirtioDeviceState};
use crate::virtio::InterruptTransport;
use std::io;

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

pub struct Rng {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) frozen: bool,
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
            frozen: false,
        })
    }

    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    pub fn save_state(&self) -> io::Result<EventDeviceState> {
        if !self.frozen {
            return Err(invalid("rng capture requires freeze"));
        }
        Ok(EventDeviceState {
            device: VirtioDeviceState::save(self)?,
            config: Vec::new(),
            queues: self.queues.as_ref().map(|queues| {
                queues
                    .iter()
                    .map(|q| QueueState::from_queue(&q.queue))
                    .collect()
            }),
        })
    }

    pub fn restore_state(&mut self, state: &EventDeviceState) -> io::Result<()> {
        state.device.validate(self)?;
        if self.is_activated()
            || state.device.activated != state.queues.is_some()
            || state
                .queues
                .as_ref()
                .is_some_and(|q| q.len() != self.queue_config().len())
        {
            return Err(invalid("invalid rng checkpoint"));
        }
        if !state.config.is_empty() {
            return Err(invalid("RNG has no configuration space"));
        }
        state.device.restore_features(self)?;
        self.frozen = true;
        Ok(())
    }

    pub fn resume(&mut self) -> io::Result<()> {
        if !self.frozen {
            return Err(invalid("event device is not frozen"));
        }
        if let Some(queues) = &self.queues {
            for queue in queues {
                queue.event.write(1)?;
            }
        }
        self.frozen = false;
        Ok(())
    }

    pub fn id(&self) -> &str {
        defs::RNG_DEV_ID
    }

    pub fn process_req(&mut self) -> bool {
        if self.frozen {
            return false;
        }
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
        let mut have_used = false;

        if !queues[REQ_INDEX].queue.ready {
            return false;
        }

        while let Some(head) = queues[REQ_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                let mut rand_bytes = vec![0u8; desc.len as usize];
                if let Err(e) = OsRng.try_fill_bytes(&mut rand_bytes) {
                    error!("Failed to fill buffer with random data: {e:?}");
                    queues[REQ_INDEX].queue.go_to_previous_position();
                    break;
                }
                if let Err(e) = mem.write_slice(&rand_bytes[..], desc.addr) {
                    error!("Failed to write slice: {e:?}");
                    queues[REQ_INDEX].queue.go_to_previous_position();
                    break;
                }
                written += desc.len;
            }

            have_used = true;
            if let Err(e) = queues[REQ_INDEX].queue.add_used(mem, index, written) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
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

    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.frozen = true;
        self.activate(mem, interrupt, queues)
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

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        self.frozen = false;
        true
    }
}
