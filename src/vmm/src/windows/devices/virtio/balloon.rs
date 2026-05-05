//! Virtio-balloon device (virtio spec v1.2 Section 5.5).
//!
//! Allows the host to request the guest to return or reclaim memory pages.
//! The guest driver inflates the balloon (returns pages) or deflates it
//! (reclaims pages) by sending page frame numbers on the respective queues.
//!
//! This implementation is protocol-only: inflate/deflate queues are processed
//! but no actual memory discard happens on the host side. Actual memory
//! reclamation would require extending `GuestMemoryAccessor` with a `discard()`
//! method (deferred to a future iteration).

use super::mmio::VirtioDeviceBackend;
use super::queue::{GuestMemoryAccessor, Virtqueue};

/// Virtio device ID for balloon (spec 5.5).
const VIRTIO_ID_BALLOON: u32 = 5;

/// VIRTIO_F_VERSION_1 — bit 32 (feature page 1, bit 0).
const VIRTIO_F_VERSION_1_PAGE1: u32 = 1;

/// Maximum queue size for inflate/deflate queues.
const QUEUE_MAX_SIZE: u16 = 256;

/// Inflate queue index (guest returns pages to host).
const INFLATE_QUEUE: u32 = 0;

/// Deflate queue index (guest reclaims pages from host).
const DEFLATE_QUEUE: u32 = 1;

/// Virtio-balloon backend.
///
/// Config space layout (little-endian):
/// - offset 0: `num_pages` (u32) — target number of pages the balloon should hold.
/// - offset 4: `actual` (u32) — actual number of pages the balloon currently holds.
///
/// The host sets `num_pages` to request inflation/deflation.
/// The guest writes `actual` to report current balloon size.
pub struct VirtioBalloon {
    /// Target number of pages (set by host, read by guest).
    num_pages: u32,
    /// Actual number of pages (set by guest via config write).
    actual: u32,
}

impl VirtioBalloon {
    pub fn new() -> Self {
        VirtioBalloon {
            num_pages: 0,
            actual: 0,
        }
    }

    /// Set the target number of balloon pages (host API).
    pub fn set_target_pages(&mut self, pages: u32) {
        self.num_pages = pages;
    }

    /// Write to config space at the given byte offset.
    ///
    /// The guest writes `actual` to offset 4 to report the current balloon size.
    pub fn write_config(&mut self, offset: u64, value: u32) {
        if offset == 4 {
            self.actual = value;
        }
        // Writes to other offsets are silently ignored.
    }
}

impl VirtioDeviceBackend for VirtioBalloon {
    fn device_id(&self) -> u32 {
        VIRTIO_ID_BALLOON
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            0 => 0,
            1 => VIRTIO_F_VERSION_1_PAGE1,
            _ => 0,
        }
    }

    fn read_config(&self, offset: u64) -> u32 {
        match offset {
            0 => self.num_pages,
            4 => self.actual,
            _ => 0,
        }
    }

    fn write_config(&mut self, offset: u64, value: u32) {
        // Delegate to the inherent method.
        VirtioBalloon::write_config(self, offset, value);
    }

    fn num_queues(&self) -> usize {
        2 // inflate + deflate
    }

    fn queue_max_size(&self, _queue_idx: u32) -> u16 {
        QUEUE_MAX_SIZE
    }

    fn queue_notify(
        &mut self,
        queue_idx: u32,
        queue: &mut Virtqueue,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool {
        let mut raised = false;

        while let Ok(Some(head)) = queue.pop_avail(mem) {
            let chain = match queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("virtio-balloon: failed to read descriptor chain: {}", e);
                    break;
                }
            };

            // Count page frame numbers (PFNs) in the chain.
            // Each PFN is a u32 (4 bytes). The guest sends arrays of PFNs.
            let mut pfn_count = 0u32;
            for desc in &chain {
                if desc.is_write() {
                    continue; // PFN buffers are device-readable.
                }
                pfn_count += desc.len / 4;
            }

            match queue_idx {
                INFLATE_QUEUE => {
                    // Guest is returning pages. In a full implementation, we would
                    // call madvise(MADV_DONTNEED) or equivalent on the host pages.
                    // For now, just track the count.
                    self.actual = self.actual.saturating_add(pfn_count);
                    log::trace!(
                        "virtio-balloon: inflate {} pages, actual={}",
                        pfn_count,
                        self.actual
                    );
                }
                DEFLATE_QUEUE => {
                    // Guest is reclaiming pages.
                    self.actual = self.actual.saturating_sub(pfn_count);
                    log::trace!(
                        "virtio-balloon: deflate {} pages, actual={}",
                        pfn_count,
                        self.actual
                    );
                }
                _ => {}
            }

            if let Err(e) = queue.add_used(head, 0, mem) {
                log::warn!("virtio-balloon: failed to add used buffer: {}", e);
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
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.device_id(), 5);
    }

    #[test]
    fn test_num_queues() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.num_queues(), 2);
    }

    #[test]
    fn test_features_page0() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.device_features(0), 0);
    }

    #[test]
    fn test_features_page1_version_1() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.device_features(1), 1); // VIRTIO_F_VERSION_1
    }

    #[test]
    fn test_features_page2_zero() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.device_features(2), 0);
    }

    #[test]
    fn test_config_defaults() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.read_config(0), 0); // num_pages
        assert_eq!(balloon.read_config(4), 0); // actual
    }

    #[test]
    fn test_set_target_pages() {
        let mut balloon = VirtioBalloon::new();
        balloon.set_target_pages(100);
        assert_eq!(balloon.read_config(0), 100);
    }

    #[test]
    fn test_write_config_actual() {
        let mut balloon = VirtioBalloon::new();
        balloon.write_config(4, 50);
        assert_eq!(balloon.read_config(4), 50);
    }

    #[test]
    fn test_write_config_ignores_other_offsets() {
        let mut balloon = VirtioBalloon::new();
        balloon.write_config(0, 999); // Should not change num_pages.
        assert_eq!(balloon.read_config(0), 0);
    }

    #[test]
    fn test_read_config_unknown_offset() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.read_config(8), 0);
        assert_eq!(balloon.read_config(12), 0);
    }

    #[test]
    fn test_queue_max_size() {
        let balloon = VirtioBalloon::new();
        assert_eq!(balloon.queue_max_size(0), 256);
        assert_eq!(balloon.queue_max_size(1), 256);
    }
}
