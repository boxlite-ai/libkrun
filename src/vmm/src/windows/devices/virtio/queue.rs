//! Split virtqueue implementation (virtio spec v1.2 Section 2.7).
//!
//! A split virtqueue consists of three regions in guest memory:
//! - Descriptor table: array of buffer descriptors
//! - Available ring: guest-to-device buffer indices
//! - Used ring: device-to-guest completion notifications

use super::super::super::error::{Result, WkrunError};

/// Abstraction over guest physical memory for cross-platform testing.
pub trait GuestMemoryAccessor {
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()>;
    fn write_at(&self, addr: u64, data: &[u8]) -> Result<()>;
}

/// Extension methods for reading typed values from guest memory.
trait GuestMemoryExt: GuestMemoryAccessor {
    fn read_u16(&self, addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_at(addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_at(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_at(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn write_u16(&self, addr: u64, val: u16) -> Result<()> {
        self.write_at(addr, &val.to_le_bytes())
    }

    fn write_u32(&self, addr: u64, val: u32) -> Result<()> {
        self.write_at(addr, &val.to_le_bytes())
    }
}

impl<T: GuestMemoryAccessor + ?Sized> GuestMemoryExt for T {}

// Descriptor table entry layout (virtio spec 2.7.5).
const DESC_ADDR_OFFSET: u64 = 0;
const DESC_LEN_OFFSET: u64 = 8;
const DESC_FLAGS_OFFSET: u64 = 12;
const DESC_NEXT_OFFSET: u64 = 14;
const DESC_SIZE: u64 = 16;

/// Descriptor flag: buffer is device-writable (for reads from device).
const VIRTQ_DESC_F_WRITE: u16 = 2;
/// Descriptor flag: next field is valid (chained descriptor).
const VIRTQ_DESC_F_NEXT: u16 = 1;

/// A single descriptor from the descriptor table.
#[derive(Debug, Clone, Copy)]
pub struct Descriptor {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Next descriptor index (valid only if VIRTQ_DESC_F_NEXT is set).
    pub next: u16,
}

impl Descriptor {
    /// Whether the buffer is device-writable (guest reads from it).
    pub fn is_write(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Whether there is a next descriptor in the chain.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0
    }
}

/// A split virtqueue.
pub struct Virtqueue {
    /// Maximum queue size (device sets this).
    max_size: u16,
    /// Negotiated queue size (driver sets this, must be <= max_size and power of 2).
    size: u16,
    /// Whether the queue is ready for use.
    ready: bool,
    /// Guest physical address of the descriptor table.
    desc_table_addr: u64,
    /// Guest physical address of the available ring.
    avail_ring_addr: u64,
    /// Guest physical address of the used ring.
    used_ring_addr: u64,
    /// Last available index consumed by the device.
    last_avail_idx: u16,
}

impl Virtqueue {
    /// Create a new virtqueue with the given maximum size.
    pub fn new(max_size: u16) -> Self {
        Virtqueue {
            max_size,
            size: 0,
            ready: false,
            desc_table_addr: 0,
            avail_ring_addr: 0,
            used_ring_addr: 0,
            last_avail_idx: 0,
        }
    }

    /// Get the maximum queue size.
    pub fn max_size(&self) -> u16 {
        self.max_size
    }

    /// Get the current queue size.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Set the queue size (called by driver during setup).
    pub fn set_size(&mut self, size: u16) {
        self.size = size;
    }

    /// Whether the queue is ready for I/O.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Mark the queue as ready.
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    /// Set the descriptor table address.
    pub fn set_desc_table(&mut self, addr: u64) {
        self.desc_table_addr = addr;
    }

    /// Set the available ring address.
    pub fn set_avail_ring(&mut self, addr: u64) {
        self.avail_ring_addr = addr;
    }

    /// Set the used ring address.
    pub fn set_used_ring(&mut self, addr: u64) {
        self.used_ring_addr = addr;
    }

    /// Read a descriptor from the descriptor table by index.
    fn read_descriptor(
        &self,
        index: u16,
        mem: &(impl GuestMemoryAccessor + ?Sized),
    ) -> Result<Descriptor> {
        if index >= self.size {
            return Err(WkrunError::Device(format!(
                "descriptor index {} out of bounds (queue size {})",
                index, self.size
            )));
        }
        let addr = self.desc_table_addr + (index as u64) * DESC_SIZE;
        Ok(Descriptor {
            addr: mem.read_u64(addr + DESC_ADDR_OFFSET)?,
            len: mem.read_u32(addr + DESC_LEN_OFFSET)?,
            flags: mem.read_u16(addr + DESC_FLAGS_OFFSET)?,
            next: mem.read_u16(addr + DESC_NEXT_OFFSET)?,
        })
    }

    /// Pop the next available descriptor chain head index, if any.
    ///
    /// Returns `None` if no new buffers are available.
    pub fn pop_avail(&mut self, mem: &(impl GuestMemoryAccessor + ?Sized)) -> Result<Option<u16>> {
        if !self.ready || self.size == 0 {
            return Ok(None);
        }

        // Avail ring layout: flags(u16) + idx(u16) + ring[size](u16 each)
        let avail_idx = mem.read_u16(self.avail_ring_addr + 2)?;

        if self.last_avail_idx == avail_idx {
            return Ok(None); // No new buffers.
        }

        let ring_offset = 4 + (self.last_avail_idx % self.size) as u64 * 2;
        let head = mem.read_u16(self.avail_ring_addr + ring_offset)?;

        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
        Ok(Some(head))
    }

    /// Read an entire descriptor chain starting from the given head index.
    ///
    /// Returns the chain of descriptors. Detects cycles by limiting
    /// the chain length to the queue size.
    pub fn read_desc_chain(
        &self,
        head: u16,
        mem: &(impl GuestMemoryAccessor + ?Sized),
    ) -> Result<Vec<Descriptor>> {
        let mut chain = Vec::new();
        let mut index = head;
        let max_chain = self.size as usize;

        loop {
            if chain.len() >= max_chain {
                return Err(WkrunError::Device(format!(
                    "descriptor chain too long (> {}), possible cycle",
                    max_chain
                )));
            }

            let desc = self.read_descriptor(index, mem)?;
            chain.push(desc);

            if !desc.has_next() {
                break;
            }
            index = desc.next;
        }

        Ok(chain)
    }

    /// Add a used buffer to the used ring.
    ///
    /// `head` is the descriptor chain head index (from `pop_avail`).
    /// `len` is the total bytes written to the descriptor chain.
    pub fn add_used(
        &mut self,
        head: u16,
        len: u32,
        mem: &(impl GuestMemoryAccessor + ?Sized),
    ) -> Result<()> {
        if !self.ready || self.size == 0 {
            return Err(WkrunError::Device("queue not ready".into()));
        }

        // Used ring layout: flags(u16) + idx(u16) + ring[size](id:u32 + len:u32)
        let used_idx = mem.read_u16(self.used_ring_addr + 2)?;
        let ring_entry_offset = 4 + (used_idx % self.size) as u64 * 8;
        let entry_addr = self.used_ring_addr + ring_entry_offset;

        // Write used ring entry: {id: u32, len: u32}.
        mem.write_u32(entry_addr, head as u32)?;
        mem.write_u32(entry_addr + 4, len)?;

        // Increment used index.
        mem.write_u16(self.used_ring_addr + 2, used_idx.wrapping_add(1))?;

        Ok(())
    }

    /// Reset the queue to its initial state.
    pub fn reset(&mut self) {
        self.size = 0;
        self.ready = false;
        self.desc_table_addr = 0;
        self.avail_ring_addr = 0;
        self.used_ring_addr = 0;
        self.last_avail_idx = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Mock guest memory backed by a Vec<u8>.
    struct MockGuestMemory {
        data: RefCell<Vec<u8>>,
    }

    impl MockGuestMemory {
        fn new(size: usize) -> Self {
            MockGuestMemory {
                data: RefCell::new(vec![0u8; size]),
            }
        }

        fn write_u16_at(&self, addr: u64, val: u16) {
            let a = addr as usize;
            let bytes = val.to_le_bytes();
            let mut data = self.data.borrow_mut();
            data[a..a + 2].copy_from_slice(&bytes);
        }

        fn write_u32_at(&self, addr: u64, val: u32) {
            let a = addr as usize;
            let bytes = val.to_le_bytes();
            let mut data = self.data.borrow_mut();
            data[a..a + 4].copy_from_slice(&bytes);
        }

        fn write_u64_at(&self, addr: u64, val: u64) {
            let a = addr as usize;
            let bytes = val.to_le_bytes();
            let mut data = self.data.borrow_mut();
            data[a..a + 8].copy_from_slice(&bytes);
        }

        fn read_u16_at(&self, addr: u64) -> u16 {
            let a = addr as usize;
            let data = self.data.borrow();
            u16::from_le_bytes([data[a], data[a + 1]])
        }

        fn read_u32_at(&self, addr: u64) -> u32 {
            let a = addr as usize;
            let data = self.data.borrow();
            u32::from_le_bytes([data[a], data[a + 1], data[a + 2], data[a + 3]])
        }
    }

    impl GuestMemoryAccessor for MockGuestMemory {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            let data = self.data.borrow();
            if a + buf.len() > data.len() {
                return Err(WkrunError::Memory(format!(
                    "read out of bounds: 0x{:X} + {}",
                    addr,
                    buf.len()
                )));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }

        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            let a = addr as usize;
            let mut mem = self.data.borrow_mut();
            if a + data.len() > mem.len() {
                return Err(WkrunError::Memory(format!(
                    "write out of bounds: 0x{:X} + {}",
                    addr,
                    data.len()
                )));
            }
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    // Memory layout for tests:
    // DESC_TABLE at 0x0000 (256 entries * 16 bytes = 4096 bytes)
    // AVAIL_RING at 0x1000 (flags:2 + idx:2 + ring[256]:512 + used_event:2 = 518)
    // USED_RING  at 0x2000 (flags:2 + idx:2 + ring[256]:(4+4)*256=2048 + avail_event:2 = 2054)
    const DESC_TABLE: u64 = 0x0000;
    const AVAIL_RING: u64 = 0x1000;
    const USED_RING: u64 = 0x2000;

    fn setup_queue(max_size: u16) -> Virtqueue {
        let mut q = Virtqueue::new(max_size);
        q.set_size(max_size);
        q.set_desc_table(DESC_TABLE);
        q.set_avail_ring(AVAIL_RING);
        q.set_used_ring(USED_RING);
        q.set_ready(true);
        q
    }

    /// Write a descriptor into mock memory.
    fn write_descriptor(
        mem: &MockGuestMemory,
        index: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let base = DESC_TABLE + index as u64 * DESC_SIZE;
        mem.write_u64_at(base + DESC_ADDR_OFFSET, addr);
        mem.write_u32_at(base + DESC_LEN_OFFSET, len);
        mem.write_u16_at(base + DESC_FLAGS_OFFSET, flags);
        mem.write_u16_at(base + DESC_NEXT_OFFSET, next);
    }

    /// Set the avail ring index and add an entry.
    fn push_avail(mem: &MockGuestMemory, ring_idx: u16, desc_head: u16) {
        // Write ring entry.
        let entry_off = AVAIL_RING + 4 + (ring_idx as u64) * 2;
        mem.write_u16_at(entry_off, desc_head);
        // Update avail idx.
        mem.write_u16_at(AVAIL_RING + 2, ring_idx + 1);
    }

    // --- Construction tests ---

    #[test]
    fn test_new_queue() {
        let q = Virtqueue::new(256);
        assert_eq!(q.max_size(), 256);
        assert_eq!(q.size(), 0);
        assert!(!q.is_ready());
    }

    #[test]
    fn test_queue_configuration() {
        let mut q = Virtqueue::new(256);
        q.set_size(128);
        q.set_desc_table(0x1000);
        q.set_avail_ring(0x2000);
        q.set_used_ring(0x3000);
        q.set_ready(true);
        assert_eq!(q.size(), 128);
        assert!(q.is_ready());
    }

    #[test]
    fn test_queue_reset() {
        let mut q = setup_queue(256);
        assert!(q.is_ready());
        q.reset();
        assert!(!q.is_ready());
        assert_eq!(q.size(), 0);
    }

    // --- pop_avail tests ---

    #[test]
    fn test_pop_avail_empty() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);
        // Avail idx = 0, last_avail_idx = 0 -> nothing.
        assert!(q.pop_avail(&mem).unwrap().is_none());
    }

    #[test]
    fn test_pop_avail_not_ready() {
        let mut q = Virtqueue::new(256);
        let mem = MockGuestMemory::new(0x4000);
        assert!(q.pop_avail(&mem).unwrap().is_none());
    }

    #[test]
    fn test_pop_avail_single() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        push_avail(&mem, 0, 42);

        let head = q.pop_avail(&mem).unwrap();
        assert_eq!(head, Some(42));

        // No more available.
        assert!(q.pop_avail(&mem).unwrap().is_none());
    }

    #[test]
    fn test_pop_avail_multiple() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        push_avail(&mem, 0, 10);
        // Push second: ring[1]=20, idx=2
        mem.write_u16_at(AVAIL_RING + 4 + 2, 20);
        mem.write_u16_at(AVAIL_RING + 2, 2);

        assert_eq!(q.pop_avail(&mem).unwrap(), Some(10));
        assert_eq!(q.pop_avail(&mem).unwrap(), Some(20));
        assert!(q.pop_avail(&mem).unwrap().is_none());
    }

    // --- read_desc_chain tests ---

    #[test]
    fn test_read_single_descriptor() {
        let q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        // Descriptor 0: addr=0x5000, len=512, no flags, no next.
        write_descriptor(&mem, 0, 0x5000, 512, 0, 0);

        let chain = q.read_desc_chain(0, &mem).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].addr, 0x5000);
        assert_eq!(chain[0].len, 512);
        assert!(!chain[0].is_write());
        assert!(!chain[0].has_next());
    }

    #[test]
    fn test_read_chained_descriptors() {
        let q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        // Descriptor 0 -> 1 -> 2 (virtio-blk: header -> data -> status).
        write_descriptor(&mem, 0, 0x5000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(
            &mem,
            1,
            0x6000,
            512,
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            2,
        );
        write_descriptor(&mem, 2, 0x7000, 1, VIRTQ_DESC_F_WRITE, 0);

        let chain = q.read_desc_chain(0, &mem).unwrap();
        assert_eq!(chain.len(), 3);

        // Header (device-readable).
        assert_eq!(chain[0].addr, 0x5000);
        assert_eq!(chain[0].len, 16);
        assert!(!chain[0].is_write());
        assert!(chain[0].has_next());

        // Data buffer (device-writable).
        assert_eq!(chain[1].addr, 0x6000);
        assert_eq!(chain[1].len, 512);
        assert!(chain[1].is_write());

        // Status (device-writable).
        assert_eq!(chain[2].addr, 0x7000);
        assert_eq!(chain[2].len, 1);
        assert!(chain[2].is_write());
        assert!(!chain[2].has_next());
    }

    #[test]
    fn test_chain_cycle_detection() {
        let q = setup_queue(4);
        let mem = MockGuestMemory::new(0x4000);

        // Descriptor 0 -> 1 -> 0 (cycle).
        write_descriptor(&mem, 0, 0x5000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(&mem, 1, 0x6000, 512, VIRTQ_DESC_F_NEXT, 0);

        let result = q.read_desc_chain(0, &mem);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cycle"), "error should mention cycle: {}", err);
    }

    #[test]
    fn test_descriptor_index_out_of_bounds() {
        let q = setup_queue(4);
        let mem = MockGuestMemory::new(0x4000);

        let result = q.read_desc_chain(5, &mem);
        assert!(result.is_err());
    }

    // --- add_used tests ---

    #[test]
    fn test_add_used_single() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        q.add_used(42, 512, &mem).unwrap();

        // Check used ring: idx should be 1.
        let used_idx = mem.read_u16_at(USED_RING + 2);
        assert_eq!(used_idx, 1);

        // Check used ring entry: {id=42, len=512}.
        let entry_id = mem.read_u32_at(USED_RING + 4);
        let entry_len = mem.read_u32_at(USED_RING + 4 + 4);
        assert_eq!(entry_id, 42);
        assert_eq!(entry_len, 512);
    }

    #[test]
    fn test_add_used_multiple() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        q.add_used(0, 100, &mem).unwrap();
        q.add_used(3, 200, &mem).unwrap();

        let used_idx = mem.read_u16_at(USED_RING + 2);
        assert_eq!(used_idx, 2);

        // First entry.
        assert_eq!(mem.read_u32_at(USED_RING + 4), 0);
        assert_eq!(mem.read_u32_at(USED_RING + 8), 100);

        // Second entry.
        assert_eq!(mem.read_u32_at(USED_RING + 12), 3);
        assert_eq!(mem.read_u32_at(USED_RING + 16), 200);
    }

    #[test]
    fn test_add_used_not_ready() {
        let mut q = Virtqueue::new(256);
        let mem = MockGuestMemory::new(0x4000);
        assert!(q.add_used(0, 0, &mem).is_err());
    }

    // --- Full round-trip: avail -> process -> used ---

    #[test]
    fn test_full_roundtrip() {
        let mut q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        // Set up a single-descriptor buffer.
        write_descriptor(&mem, 5, 0x8000, 1024, VIRTQ_DESC_F_WRITE, 0);
        push_avail(&mem, 0, 5);

        // Pop available.
        let head = q.pop_avail(&mem).unwrap().expect("should have buffer");
        assert_eq!(head, 5);

        // Read chain.
        let chain = q.read_desc_chain(head, &mem).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].len, 1024);

        // Complete: add to used.
        q.add_used(head, 1024, &mem).unwrap();

        let used_idx = mem.read_u16_at(USED_RING + 2);
        assert_eq!(used_idx, 1);
    }

    // --- Wrapping behavior ---

    #[test]
    fn test_avail_index_wraps() {
        let mut q = setup_queue(4);
        let mem = MockGuestMemory::new(0x4000);

        // Simulate avail idx at u16::MAX boundary.
        q.last_avail_idx = u16::MAX;
        // Set avail ring idx to u16::MAX + 1 = 0 (wraps).
        mem.write_u16_at(AVAIL_RING + 2, 0);

        // last_avail_idx (65535) == avail_idx (0 after wrap)?
        // No: 65535 != 0, so we should get a buffer.
        // Ring offset: (65535 % 4) * 2 = 3 * 2 = 6 -> ring[3]
        mem.write_u16_at(AVAIL_RING + 4 + 6, 2);

        let head = q.pop_avail(&mem).unwrap();
        assert_eq!(head, Some(2));
        assert_eq!(q.last_avail_idx, 0); // Wrapped.
    }

    // --- Virtio-blk style 3-descriptor chain ---

    #[test]
    fn test_virtio_blk_chain() {
        let q = setup_queue(256);
        let mem = MockGuestMemory::new(0x4000);

        // Header (device-readable): type=IN, sector=0
        write_descriptor(&mem, 0, 0xA000, 16, VIRTQ_DESC_F_NEXT, 1);
        // Data buffer (device-writable): 512 bytes
        write_descriptor(
            &mem,
            1,
            0xB000,
            512,
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            2,
        );
        // Status (device-writable): 1 byte
        write_descriptor(&mem, 2, 0xC000, 1, VIRTQ_DESC_F_WRITE, 0);

        let chain = q.read_desc_chain(0, &mem).unwrap();
        assert_eq!(chain.len(), 3);
        assert!(!chain[0].is_write()); // Header is device-readable.
        assert!(chain[1].is_write()); // Data is device-writable.
        assert!(chain[2].is_write()); // Status is device-writable.
    }

    // --- Descriptor flags ---

    #[test]
    fn test_descriptor_flags() {
        let desc = Descriptor {
            addr: 0,
            len: 0,
            flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        assert!(desc.is_write());
        assert!(desc.has_next());

        let desc2 = Descriptor {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        assert!(!desc2.is_write());
        assert!(!desc2.has_next());
    }
}
