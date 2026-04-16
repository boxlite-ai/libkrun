//! Virtio-MMIO transport (virtio spec v1.2 Section 4.2).
//!
//! Register file at a memory-mapped I/O address. The guest accesses
//! device registers via MMIO reads/writes which trigger VM exits.

use super::queue::{GuestMemoryAccessor, Virtqueue};

/// MMIO base address for the first virtio device.
/// Placed above guest RAM (256MB) and below the 4GB identity map.
pub const VIRTIO_MMIO_BASE: u64 = 0xD000_0000;

/// Size of the MMIO register region (512 bytes covers all registers + config).
pub const VIRTIO_MMIO_SIZE: u64 = 0x200;

// Virtio-MMIO register offsets (virtio spec 4.2.2).
const MAGIC_VALUE: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00C;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_AVAIL_LOW: u64 = 0x090;
const QUEUE_AVAIL_HIGH: u64 = 0x094;
const QUEUE_USED_LOW: u64 = 0x0A0;
const QUEUE_USED_HIGH: u64 = 0x0A4;
const CONFIG_GENERATION: u64 = 0x0FC;
const CONFIG_SPACE: u64 = 0x100;

// Virtio device status bits (virtio spec 2.1) — used in tests.
#[cfg(test)]
const STATUS_ACK: u32 = 1;
#[cfg(test)]
const STATUS_DRIVER: u32 = 2;
#[cfg(test)]
const STATUS_FEATURES_OK: u32 = 8;
#[cfg(test)]
const STATUS_DRIVER_OK: u32 = 4;

/// Magic value identifying a virtio-MMIO device ("virt" in little-endian).
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// Virtio-MMIO version (2 = virtio 1.0+).
const VIRTIO_MMIO_VERSION: u32 = 2;

/// Vendor ID (0 = no vendor).
const VIRTIO_VENDOR_ID: u32 = 0;

// Interrupt status bits.
const INTERRUPT_USED_RING: u32 = 1;

/// Backend trait that specific virtio devices implement.
pub trait VirtioDeviceBackend {
    /// Virtio device ID (e.g., 2 for block).
    fn device_id(&self) -> u32;

    /// Return device feature bits for the given feature page (0 or 1).
    fn device_features(&self, page: u32) -> u32;

    /// Read a 32-bit value from the device config space at the given offset.
    fn read_config(&self, offset: u64) -> u32;

    /// Handle a queue notification (guest made buffers available).
    ///
    /// Returns `true` if the device processed buffers and an interrupt
    /// should be raised.
    fn queue_notify(
        &mut self,
        queue_idx: u32,
        queue: &mut Virtqueue,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool;

    /// Number of virtqueues this device uses.
    fn num_queues(&self) -> usize;

    /// Maximum queue size for the given queue index.
    fn queue_max_size(&self, queue_idx: u32) -> u16;

    /// Poll for host-initiated events (e.g., incoming network/vsock data).
    ///
    /// Called from the vCPU run loop. Returns `true` if an interrupt
    /// should be raised (device placed data in the used ring).
    /// Default: no host-initiated events (suitable for block devices).
    fn poll(&mut self, _queues: &mut [Virtqueue], _mem: &dyn GuestMemoryAccessor) -> bool {
        false
    }
}

/// Virtio-MMIO device wrapping a backend.
pub struct VirtioMmioDevice<D: VirtioDeviceBackend> {
    backend: D,
    queues: Vec<Virtqueue>,
    /// Currently selected queue index (via QUEUE_SEL).
    queue_sel: u32,
    /// Device status register.
    status: u32,
    /// Device feature selection page.
    device_features_sel: u32,
    /// Driver feature selection page.
    driver_features_sel: u32,
    /// Driver-acknowledged feature bits (page 0 and page 1).
    driver_features: [u32; 2],
    /// Interrupt status register.
    interrupt_status: u32,
}

impl<D: VirtioDeviceBackend> VirtioMmioDevice<D> {
    /// Create a new MMIO device wrapping the given backend.
    pub fn new(backend: D) -> Self {
        let num_queues = backend.num_queues();
        let mut queues = Vec::with_capacity(num_queues);
        for i in 0..num_queues {
            queues.push(Virtqueue::new(backend.queue_max_size(i as u32)));
        }

        VirtioMmioDevice {
            backend,
            queues,
            queue_sel: 0,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            interrupt_status: 0,
        }
    }

    /// Get a reference to the backend.
    pub fn backend(&self) -> &D {
        &self.backend
    }

    /// Get a mutable reference to the backend.
    pub fn backend_mut(&mut self) -> &mut D {
        &mut self.backend
    }

    /// Get the current interrupt status (non-zero = interrupt pending).
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Handle an MMIO read at the given offset from the device base.
    pub fn read(&self, offset: u64, size: u8) -> u32 {
        // All MMIO register reads are 32-bit in virtio-MMIO v2.
        if size != 4 && offset < CONFIG_SPACE {
            return 0;
        }

        match offset {
            MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            VERSION => VIRTIO_MMIO_VERSION,
            DEVICE_ID => self.backend.device_id(),
            VENDOR_ID => VIRTIO_VENDOR_ID,
            DEVICE_FEATURES => self.backend.device_features(self.device_features_sel),
            QUEUE_NUM_MAX => {
                if let Some(q) = self.current_queue() {
                    q.max_size() as u32
                } else {
                    0
                }
            }
            QUEUE_READY => {
                if let Some(q) = self.current_queue() {
                    q.is_ready() as u32
                } else {
                    0
                }
            }
            INTERRUPT_STATUS => self.interrupt_status,
            STATUS => self.status,
            CONFIG_GENERATION => 0, // Config doesn't change dynamically.
            off if off >= CONFIG_SPACE => self.backend.read_config(off - CONFIG_SPACE),
            _ => 0,
        }
    }

    /// Handle an MMIO write at the given offset from the device base.
    ///
    /// `mem` is needed for queue_notify to process descriptor chains.
    /// Returns `true` if an interrupt should be raised.
    pub fn write(
        &mut self,
        offset: u64,
        value: u32,
        size: u8,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool {
        // All MMIO register writes are 32-bit in virtio-MMIO v2.
        if size != 4 {
            return false;
        }

        match offset {
            DEVICE_FEATURES_SEL => {
                self.device_features_sel = value;
            }
            DRIVER_FEATURES => {
                let sel = self.driver_features_sel as usize;
                if sel < self.driver_features.len() {
                    self.driver_features[sel] = value;
                }
            }
            DRIVER_FEATURES_SEL => {
                self.driver_features_sel = value;
            }
            QUEUE_SEL => {
                self.queue_sel = value;
            }
            QUEUE_NUM => {
                if let Some(q) = self.current_queue_mut() {
                    q.set_size(value as u16);
                }
            }
            QUEUE_READY => {
                if let Some(q) = self.current_queue_mut() {
                    q.set_ready(value == 1);
                }
            }
            QUEUE_NOTIFY => {
                return self.handle_queue_notify(value, mem);
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !value;
            }
            STATUS => {
                self.handle_status_write(value);
            }
            QUEUE_DESC_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    let high = 0u64; // Will be combined in set_desc_table.
                    q.set_desc_table(value as u64 | high);
                }
            }
            QUEUE_DESC_HIGH => {
                // High bits for descriptor table address (typically 0 for < 4GB).
            }
            QUEUE_AVAIL_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    q.set_avail_ring(value as u64);
                }
            }
            QUEUE_AVAIL_HIGH => {
                // High bits for avail ring address (typically 0).
            }
            QUEUE_USED_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    q.set_used_ring(value as u64);
                }
            }
            QUEUE_USED_HIGH => {
                // High bits for used ring address (typically 0).
            }
            _ => {}
        }
        false
    }

    /// Poll the backend for host-initiated events.
    ///
    /// Returns `true` if an interrupt should be raised.
    pub fn poll(&mut self, mem: &dyn GuestMemoryAccessor) -> bool {
        let raised = self.backend.poll(&mut self.queues, mem);
        if raised {
            self.interrupt_status |= INTERRUPT_USED_RING;
        }
        raised
    }

    fn current_queue(&self) -> Option<&Virtqueue> {
        self.queues.get(self.queue_sel as usize)
    }

    fn current_queue_mut(&mut self) -> Option<&mut Virtqueue> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    fn handle_queue_notify(&mut self, queue_idx: u32, mem: &dyn GuestMemoryAccessor) -> bool {
        let idx = queue_idx as usize;
        if idx >= self.queues.len() {
            return false;
        }

        // Split borrow: take queue out, call backend, put it back.
        let raised = self
            .backend
            .queue_notify(queue_idx, &mut self.queues[idx], mem);

        if raised {
            self.interrupt_status |= INTERRUPT_USED_RING;
        }

        raised
    }

    fn handle_status_write(&mut self, value: u32) {
        if value == 0 {
            // Device reset.
            self.status = 0;
            self.queue_sel = 0;
            self.interrupt_status = 0;
            self.device_features_sel = 0;
            self.driver_features_sel = 0;
            self.driver_features = [0; 2];
            for q in &mut self.queues {
                q.reset();
            }
            return;
        }
        // Status can only be set by ORing new bits in.
        self.status = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::queue::GuestMemoryAccessor;
    use super::super::super::error::Result;
    use std::cell::RefCell;

    /// Null backend for testing the MMIO transport layer.
    struct NullBackend;

    impl VirtioDeviceBackend for NullBackend {
        fn device_id(&self) -> u32 {
            0 // Invalid/null device.
        }
        fn device_features(&self, _page: u32) -> u32 {
            0
        }
        fn read_config(&self, _offset: u64) -> u32 {
            0
        }
        fn queue_notify(
            &mut self,
            _queue_idx: u32,
            _queue: &mut Virtqueue,
            _mem: &dyn GuestMemoryAccessor,
        ) -> bool {
            false
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn queue_max_size(&self, _queue_idx: u32) -> u16 {
            256
        }
    }

    /// Test backend that tracks notifications.
    struct TestBackend {
        notify_count: RefCell<u32>,
    }

    impl TestBackend {
        fn new() -> Self {
            TestBackend {
                notify_count: RefCell::new(0),
            }
        }
    }

    impl VirtioDeviceBackend for TestBackend {
        fn device_id(&self) -> u32 {
            2 // Block device.
        }
        fn device_features(&self, page: u32) -> u32 {
            if page == 0 {
                0x1234
            } else {
                0
            }
        }
        fn read_config(&self, offset: u64) -> u32 {
            if offset == 0 {
                1024
            } else {
                0
            } // Capacity low.
        }
        fn queue_notify(
            &mut self,
            _queue_idx: u32,
            _queue: &mut Virtqueue,
            _mem: &dyn GuestMemoryAccessor,
        ) -> bool {
            *self.notify_count.borrow_mut() += 1;
            true // Raise interrupt.
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn queue_max_size(&self, _queue_idx: u32) -> u16 {
            128
        }
    }

    struct MockMem(RefCell<Vec<u8>>);
    impl MockMem {
        fn new(size: usize) -> Self {
            MockMem(RefCell::new(vec![0u8; size]))
        }
    }
    impl GuestMemoryAccessor for MockMem {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            let data = self.0.borrow();
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            let a = addr as usize;
            let mut mem = self.0.borrow_mut();
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    // --- Magic and identification ---

    #[test]
    fn test_magic_value() {
        let dev = VirtioMmioDevice::new(NullBackend);
        assert_eq!(dev.read(MAGIC_VALUE, 4), VIRTIO_MMIO_MAGIC);
    }

    #[test]
    fn test_version() {
        let dev = VirtioMmioDevice::new(NullBackend);
        assert_eq!(dev.read(VERSION, 4), 2);
    }

    #[test]
    fn test_device_id() {
        let dev = VirtioMmioDevice::new(TestBackend::new());
        assert_eq!(dev.read(DEVICE_ID, 4), 2); // Block device.
    }

    #[test]
    fn test_vendor_id() {
        let dev = VirtioMmioDevice::new(NullBackend);
        assert_eq!(dev.read(VENDOR_ID, 4), 0);
    }

    // --- Device features ---

    #[test]
    fn test_device_features_page0() {
        let mut dev = VirtioMmioDevice::new(TestBackend::new());
        let mem = MockMem::new(64);
        dev.write(DEVICE_FEATURES_SEL, 0, 4, &mem);
        assert_eq!(dev.read(DEVICE_FEATURES, 4), 0x1234);
    }

    #[test]
    fn test_device_features_page1() {
        let mut dev = VirtioMmioDevice::new(TestBackend::new());
        let mem = MockMem::new(64);
        dev.write(DEVICE_FEATURES_SEL, 1, 4, &mem);
        assert_eq!(dev.read(DEVICE_FEATURES, 4), 0);
    }

    // --- Queue configuration ---

    #[test]
    fn test_queue_max_size() {
        let dev = VirtioMmioDevice::new(TestBackend::new());
        assert_eq!(dev.read(QUEUE_NUM_MAX, 4), 128);
    }

    #[test]
    fn test_queue_ready() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        assert_eq!(dev.read(QUEUE_READY, 4), 0);
        dev.write(QUEUE_READY, 1, 4, &mem);
        assert_eq!(dev.read(QUEUE_READY, 4), 1);
    }

    // --- Status state machine ---

    #[test]
    fn test_status_ack() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        assert_eq!(dev.read(STATUS, 4), 0);
        dev.write(STATUS, STATUS_ACK, 4, &mem);
        assert_eq!(dev.read(STATUS, 4), STATUS_ACK);
    }

    #[test]
    fn test_status_progression() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        dev.write(STATUS, STATUS_ACK, 4, &mem);
        dev.write(STATUS, STATUS_ACK | STATUS_DRIVER, 4, &mem);
        dev.write(
            STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK,
            4,
            &mem,
        );
        dev.write(
            STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            4,
            &mem,
        );
        assert_eq!(
            dev.read(STATUS, 4),
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
        );
    }

    #[test]
    fn test_status_reset() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        dev.write(STATUS, STATUS_ACK | STATUS_DRIVER, 4, &mem);
        assert_ne!(dev.read(STATUS, 4), 0);
        dev.write(STATUS, 0, 4, &mem); // Reset.
        assert_eq!(dev.read(STATUS, 4), 0);
    }

    // --- Interrupt handling ---

    #[test]
    fn test_interrupt_on_notify() {
        let mut dev = VirtioMmioDevice::new(TestBackend::new());
        let mem = MockMem::new(64);

        assert_eq!(dev.read(INTERRUPT_STATUS, 4), 0);

        // Notify queue 0.
        let raised = dev.write(QUEUE_NOTIFY, 0, 4, &mem);
        assert!(raised);
        assert_eq!(dev.read(INTERRUPT_STATUS, 4), INTERRUPT_USED_RING);
    }

    #[test]
    fn test_interrupt_ack() {
        let mut dev = VirtioMmioDevice::new(TestBackend::new());
        let mem = MockMem::new(64);

        dev.write(QUEUE_NOTIFY, 0, 4, &mem);
        assert_eq!(dev.read(INTERRUPT_STATUS, 4), INTERRUPT_USED_RING);

        // Acknowledge the interrupt.
        dev.write(INTERRUPT_ACK, INTERRUPT_USED_RING, 4, &mem);
        assert_eq!(dev.read(INTERRUPT_STATUS, 4), 0);
    }

    // --- Config space ---

    #[test]
    fn test_config_space_read() {
        let dev = VirtioMmioDevice::new(TestBackend::new());
        // Offset 0x100 = config space offset 0 → capacity low = 1024.
        assert_eq!(dev.read(CONFIG_SPACE, 4), 1024);
    }

    // --- Non-32-bit access ---

    #[test]
    fn test_non_32bit_read_returns_zero() {
        let dev = VirtioMmioDevice::new(NullBackend);
        // Reading magic with size != 4 should return 0.
        assert_eq!(dev.read(MAGIC_VALUE, 1), 0);
        assert_eq!(dev.read(MAGIC_VALUE, 2), 0);
    }

    #[test]
    fn test_non_32bit_write_ignored() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        dev.write(STATUS, STATUS_ACK, 2, &mem); // Wrong size.
        assert_eq!(dev.read(STATUS, 4), 0); // Should be unchanged.
    }

    // --- Invalid queue selection ---

    #[test]
    fn test_invalid_queue_sel() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        dev.write(QUEUE_SEL, 99, 4, &mem);
        assert_eq!(dev.read(QUEUE_NUM_MAX, 4), 0); // No such queue.
    }

    // --- Poll ---

    #[test]
    fn test_poll_default_returns_false() {
        let mut dev = VirtioMmioDevice::new(NullBackend);
        let mem = MockMem::new(64);
        assert!(!dev.poll(&mem));
        assert_eq!(dev.interrupt_status(), 0);
    }

    /// Backend that returns true from poll().
    struct PollBackend;

    impl VirtioDeviceBackend for PollBackend {
        fn device_id(&self) -> u32 {
            19
        }
        fn device_features(&self, _page: u32) -> u32 {
            0
        }
        fn read_config(&self, _offset: u64) -> u32 {
            0
        }
        fn queue_notify(
            &mut self,
            _queue_idx: u32,
            _queue: &mut Virtqueue,
            _mem: &dyn GuestMemoryAccessor,
        ) -> bool {
            false
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn queue_max_size(&self, _queue_idx: u32) -> u16 {
            128
        }
        fn poll(&mut self, _queues: &mut [Virtqueue], _mem: &dyn GuestMemoryAccessor) -> bool {
            true
        }
    }

    #[test]
    fn test_poll_sets_interrupt_status() {
        let mut dev = VirtioMmioDevice::new(PollBackend);
        let mem = MockMem::new(64);
        let raised = dev.poll(&mem);
        assert!(raised);
        assert_eq!(dev.interrupt_status(), INTERRUPT_USED_RING);
    }

    #[test]
    fn test_poll_interrupt_can_be_acked() {
        let mut dev = VirtioMmioDevice::new(PollBackend);
        let mem = MockMem::new(64);
        dev.poll(&mem);
        assert_eq!(dev.interrupt_status(), INTERRUPT_USED_RING);
        dev.write(INTERRUPT_ACK, INTERRUPT_USED_RING, 4, &mem);
        assert_eq!(dev.interrupt_status(), 0);
    }
}
