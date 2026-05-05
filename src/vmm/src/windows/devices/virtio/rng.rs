//! Virtio-rng device (virtio spec v1.2 Section 5.4).
//!
//! Provides entropy to the guest via `/dev/hwrng`. The guest driver
//! submits device-writable buffers; the device fills them with random
//! bytes and returns them on the used ring.

use super::mmio::VirtioDeviceBackend;
use super::queue::{GuestMemoryAccessor, Virtqueue};

/// Virtio device ID for entropy source (spec 5.4).
const VIRTIO_ID_RNG: u32 = 4;

/// VIRTIO_F_VERSION_1 — bit 32 (feature page 1, bit 0).
const VIRTIO_F_VERSION_1_PAGE1: u32 = 1;

/// Maximum queue size for the request queue.
const QUEUE_MAX_SIZE: u16 = 256;

/// Virtio-rng backend.
///
/// Purely guest-initiated: the guest submits device-writable buffers,
/// the device fills them with random bytes from the host OS entropy pool.
/// No async worker or polling needed.
pub struct VirtioRng {
    _priv: (),
}

impl VirtioRng {
    pub fn new() -> Self {
        VirtioRng { _priv: () }
    }
}

impl VirtioDeviceBackend for VirtioRng {
    fn device_id(&self) -> u32 {
        VIRTIO_ID_RNG
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            0 => 0,
            1 => VIRTIO_F_VERSION_1_PAGE1,
            _ => 0,
        }
    }

    fn read_config(&self, _offset: u64) -> u32 {
        0 // No config space.
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn queue_max_size(&self, _queue_idx: u32) -> u16 {
        QUEUE_MAX_SIZE
    }

    fn queue_notify(
        &mut self,
        _queue_idx: u32,
        queue: &mut Virtqueue,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool {
        let mut raised = false;

        while let Ok(Some(head)) = queue.pop_avail(mem) {
            let chain = match queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("virtio-rng: failed to read descriptor chain: {}", e);
                    break;
                }
            };

            let mut total_written = 0u32;
            for desc in &chain {
                if !desc.is_write() {
                    continue; // Skip device-readable descriptors.
                }

                // Fill with random bytes using ThreadRng (infallible, seeds from OS).
                let len = desc.len as usize;
                let mut buf = vec![0u8; len];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);

                if let Err(e) = mem.write_at(desc.addr, &buf) {
                    log::warn!("virtio-rng: failed to write random bytes: {}", e);
                    break;
                }
                total_written += desc.len;
            }

            if let Err(e) = queue.add_used(head, total_written, mem) {
                log::warn!("virtio-rng: failed to add used buffer: {}", e);
                break;
            }
            raised = true;
        }

        raised
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_id(), 4);
    }

    #[test]
    fn test_num_queues() {
        let rng = VirtioRng::new();
        assert_eq!(rng.num_queues(), 1);
    }

    #[test]
    fn test_features_page0() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_features(0), 0);
    }

    #[test]
    fn test_features_page1_version_1() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_features(1), 1); // VIRTIO_F_VERSION_1
    }

    #[test]
    fn test_features_page2_zero() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_features(2), 0);
    }

    #[test]
    fn test_read_config_returns_zero() {
        let rng = VirtioRng::new();
        assert_eq!(rng.read_config(0), 0);
        assert_eq!(rng.read_config(4), 0);
    }

    #[test]
    fn test_queue_max_size() {
        let rng = VirtioRng::new();
        assert_eq!(rng.queue_max_size(0), 256);
    }
}
