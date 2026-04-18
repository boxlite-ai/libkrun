//! Virtio-blk device backend (virtio spec v1.2 Section 5.2).
//!
//! Provides a file-backed block device that processes read, write,
//! and flush requests through the virtqueue.

use super::disk::DiskBackend;
use super::mmio::VirtioDeviceBackend;
use super::queue::{Descriptor, GuestMemoryAccessor, Virtqueue};

/// Virtio device ID for block devices.
const VIRTIO_BLK_ID: u32 = 2;

/// Block size in bytes (standard sector size).
const SECTOR_SIZE: u64 = 512;

// Virtio-blk feature bits.
/// Device has a maximum size (not used for now).
#[allow(dead_code)]
const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
/// Device has a maximum segment size (not used for now).
#[allow(dead_code)]
const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
/// Read-only device.
const VIRTIO_BLK_F_RO: u32 = 5;
/// VIRTIO_F_VERSION_1 — required for virtio 1.0+.
const VIRTIO_F_VERSION_1: u32 = 0; // Bit 32, goes in features page 1.

// Virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = 0; // Read from disk.
const VIRTIO_BLK_T_OUT: u32 = 1; // Write to disk.
const VIRTIO_BLK_T_FLUSH: u32 = 4; // Flush.

// Virtio-blk status values.
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Virtio-blk device backed by a `DiskBackend`.
pub struct VirtioBlock {
    disk: Box<dyn DiskBackend>,
    capacity: u64, // In sectors.
    read_only: bool,
}

impl VirtioBlock {
    /// Create a new virtio-blk device from a disk backend.
    ///
    /// `read_only` marks the device as read-only (rejects write requests).
    pub fn new(disk: Box<dyn DiskBackend>, read_only: bool) -> Self {
        let capacity = disk.capacity_bytes() / SECTOR_SIZE;
        VirtioBlock {
            disk,
            capacity,
            read_only,
        }
    }

    /// Get disk capacity in sectors.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Process a single virtio-blk request from a descriptor chain.
    fn process_request(&mut self, chain: &[Descriptor], mem: &dyn GuestMemoryAccessor) -> u8 {
        // Minimum: header + status (flush has no data descriptor).
        if chain.len() < 2 {
            log::debug!("BLK: short chain len={}", chain.len());
            return VIRTIO_BLK_S_IOERR;
        }

        // First descriptor: request header (device-readable).
        let header_desc = &chain[0];
        if header_desc.len < 16 {
            log::debug!("BLK: short header len={}", header_desc.len);
            return VIRTIO_BLK_S_IOERR;
        }

        let mut header_buf = [0u8; 16];
        if mem.read_at(header_desc.addr, &mut header_buf).is_err() {
            log::debug!("BLK: header read failed addr=0x{:X}", header_desc.addr);
            return VIRTIO_BLK_S_IOERR;
        }

        let req_type =
            u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        let sector = u64::from_le_bytes([
            header_buf[8],
            header_buf[9],
            header_buf[10],
            header_buf[11],
            header_buf[12],
            header_buf[13],
            header_buf[14],
            header_buf[15],
        ]);

        // Middle descriptors: data buffer(s) (may be empty for flush).
        // Last descriptor: status byte (device-writable).
        let data_descs = &chain[1..chain.len() - 1];

        match req_type {
            VIRTIO_BLK_T_IN => {
                if data_descs.is_empty() {
                    return VIRTIO_BLK_S_IOERR;
                }
                self.handle_read(sector, data_descs, mem)
            }
            VIRTIO_BLK_T_OUT => {
                if data_descs.is_empty() {
                    return VIRTIO_BLK_S_IOERR;
                }
                self.handle_write(sector, data_descs, mem)
            }
            VIRTIO_BLK_T_FLUSH => self.handle_flush(),
            _ => VIRTIO_BLK_S_UNSUPP,
        }
    }

    fn handle_read(
        &mut self,
        sector: u64,
        data_descs: &[Descriptor],
        mem: &dyn GuestMemoryAccessor,
    ) -> u8 {
        let mut offset = sector * SECTOR_SIZE;

        for (i, desc) in data_descs.iter().enumerate() {
            if !desc.is_write() {
                log::debug!(
                    "BLK READ: desc[{}] not writable, flags=0x{:X}",
                    i, desc.flags
                );
                return VIRTIO_BLK_S_IOERR;
            }
            let mut buf = vec![0u8; desc.len as usize];
            if let Err(e) = self.disk.read_at(offset, &mut buf) {
                log::debug!(
                    "BLK READ: disk.read_at(0x{:X}, {}) failed: {}",
                    offset, desc.len, e
                );
                return VIRTIO_BLK_S_IOERR;
            }
            if let Err(e) = mem.write_at(desc.addr, &buf) {
                log::debug!(
                    "BLK READ: mem.write_at(0x{:X}, {}) failed: {}",
                    desc.addr, buf.len(), e
                );
                return VIRTIO_BLK_S_IOERR;
            }
            offset += desc.len as u64;
        }
        VIRTIO_BLK_S_OK
    }

    fn handle_write(
        &mut self,
        sector: u64,
        data_descs: &[Descriptor],
        mem: &dyn GuestMemoryAccessor,
    ) -> u8 {
        if self.read_only {
            return VIRTIO_BLK_S_IOERR;
        }

        let mut offset = sector * SECTOR_SIZE;

        for desc in data_descs {
            if desc.is_write() {
                return VIRTIO_BLK_S_IOERR; // Data buffer must be device-readable for writes.
            }
            let mut buf = vec![0u8; desc.len as usize];
            if mem.read_at(desc.addr, &mut buf).is_err() {
                return VIRTIO_BLK_S_IOERR;
            }
            if self.disk.write_at(offset, &buf).is_err() {
                return VIRTIO_BLK_S_IOERR;
            }
            offset += desc.len as u64;
        }
        VIRTIO_BLK_S_OK
    }

    fn handle_flush(&mut self) -> u8 {
        if self.disk.flush().is_err() {
            VIRTIO_BLK_S_IOERR
        } else {
            VIRTIO_BLK_S_OK
        }
    }
}

impl VirtioDeviceBackend for VirtioBlock {
    fn device_id(&self) -> u32 {
        VIRTIO_BLK_ID
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            0 => {
                let mut features = 0u32;
                if self.read_only {
                    features |= 1 << VIRTIO_BLK_F_RO;
                }
                features
            }
            1 => 1 << VIRTIO_F_VERSION_1, // VIRTIO_F_VERSION_1 is bit 32 (page 1, bit 0).
            _ => 0,
        }
    }

    fn read_config(&self, offset: u64) -> u32 {
        // Config space: capacity (u64 at offset 0).
        match offset {
            0 => self.capacity as u32,         // Low 32 bits.
            4 => (self.capacity >> 32) as u32, // High 32 bits.
            _ => 0,
        }
    }

    fn queue_notify(
        &mut self,
        _queue_idx: u32,
        queue: &mut Virtqueue,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool {
        let mut processed = false;

        while let Ok(Some(head)) = queue.pop_avail(mem) {
            let chain = match queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(_) => {
                    // Write error status and continue.
                    let _ = queue.add_used(head, 0, mem);
                    processed = true;
                    continue;
                }
            };

            let status = self.process_request(&chain, mem);

            // Write status byte to last descriptor.
            if let Some(status_desc) = chain.last() {
                let _ = mem.write_at(status_desc.addr, &[status]);
            }

            // Calculate total bytes written to device-writable descriptors.
            let total_written: u32 = chain.iter().filter(|d| d.is_write()).map(|d| d.len).sum();

            let _ = queue.add_used(head, total_written, mem);
            processed = true;
        }

        processed
    }

    fn num_queues(&self) -> usize {
        1 // Virtio-blk uses a single request queue.
    }

    fn queue_max_size(&self, _queue_idx: u32) -> u16 {
        256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::disk::RawDiskBackend;
    use super::super::super::error::WkrunError;
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    struct MockMem {
        data: RefCell<Vec<u8>>,
    }

    impl MockMem {
        fn new(size: usize) -> Self {
            MockMem {
                data: RefCell::new(vec![0u8; size]),
            }
        }

        fn write_bytes(&self, addr: u64, bytes: &[u8]) {
            let a = addr as usize;
            let mut data = self.data.borrow_mut();
            data[a..a + bytes.len()].copy_from_slice(bytes);
        }

        fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
            let a = addr as usize;
            let data = self.data.borrow();
            data[a..a + len].to_vec()
        }
    }

    impl GuestMemoryAccessor for MockMem {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> super::super::super::error::Result<()> {
            let a = addr as usize;
            let data = self.data.borrow();
            if a + buf.len() > data.len() {
                return Err(WkrunError::Memory("out of bounds".into()));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> super::super::super::error::Result<()> {
            let a = addr as usize;
            let mut mem = self.data.borrow_mut();
            if a + data.len() > mem.len() {
                return Err(WkrunError::Memory("out of bounds".into()));
            }
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    fn create_test_disk(sectors: u64) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        let data = vec![0u8; (sectors * SECTOR_SIZE) as usize];
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        f
    }

    fn create_disk_with_pattern(sectors: u64) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for sector in 0..sectors {
            let pattern = vec![(sector & 0xFF) as u8; SECTOR_SIZE as usize];
            f.write_all(&pattern).unwrap();
        }
        f.flush().unwrap();
        f
    }

    fn open_raw_backend(tmp: &NamedTempFile, read_only: bool) -> Box<dyn DiskBackend> {
        let file = File::options()
            .read(true)
            .write(!read_only)
            .open(tmp.path())
            .unwrap();
        Box::new(RawDiskBackend::new(file).unwrap())
    }

    // --- Construction ---

    #[test]
    fn test_new_block_device() {
        let tmp = create_test_disk(8);
        let backend = open_raw_backend(&tmp, false);
        let blk = VirtioBlock::new(backend, false);
        assert_eq!(blk.capacity(), 8);
        assert_eq!(blk.device_id(), VIRTIO_BLK_ID);
    }

    #[test]
    fn test_empty_disk_error() {
        let tmp = NamedTempFile::new().unwrap();
        let file = File::open(tmp.path()).unwrap();
        assert!(RawDiskBackend::new(file).is_err());
    }

    #[test]
    fn test_read_only_features() {
        let tmp = create_test_disk(1);
        let backend = open_raw_backend(&tmp, true);
        let blk = VirtioBlock::new(backend, true);
        let features = blk.device_features(0);
        assert_ne!(features & (1 << VIRTIO_BLK_F_RO), 0);
    }

    // --- Config space ---

    #[test]
    fn test_config_capacity() {
        let tmp = create_test_disk(1024);
        let backend = open_raw_backend(&tmp, false);
        let blk = VirtioBlock::new(backend, false);
        assert_eq!(blk.read_config(0), 1024); // Low.
        assert_eq!(blk.read_config(4), 0); // High.
    }

    // --- Request processing (direct) ---

    #[test]
    fn test_read_request() {
        let tmp = create_disk_with_pattern(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, false);
        let mem = MockMem::new(0x10000);

        // Write request header: type=IN, sector=2.
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        header[8..16].copy_from_slice(&2u64.to_le_bytes());
        mem.write_bytes(0x1000, &header);

        // Build descriptor chain.
        let chain = vec![
            Descriptor {
                addr: 0x1000,
                len: 16,
                flags: 0,
                next: 0,
            }, // Header (device-readable).
            Descriptor {
                addr: 0x2000,
                len: 512,
                flags: 2,
                next: 0,
            }, // Data (device-writable).
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            }, // Status (device-writable).
        ];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_OK);

        // Check that data was read (sector 2 pattern = 0x02).
        let data = mem.read_bytes(0x2000, 512);
        assert!(data.iter().all(|&b| b == 0x02));
    }

    #[test]
    fn test_write_request() {
        let tmp = create_test_disk(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, false);
        let mem = MockMem::new(0x10000);

        // Header: type=OUT, sector=1.
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        header[8..16].copy_from_slice(&1u64.to_le_bytes());
        mem.write_bytes(0x1000, &header);

        // Data to write (device-readable).
        let write_data = vec![0xABu8; 512];
        mem.write_bytes(0x2000, &write_data);

        let chain = vec![
            Descriptor {
                addr: 0x1000,
                len: 16,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x2000,
                len: 512,
                flags: 0,
                next: 0,
            }, // Device-readable.
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            }, // Status.
        ];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_OK);

        // Verify by reading back.
        let mut header2 = [0u8; 16];
        header2[0..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        header2[8..16].copy_from_slice(&1u64.to_le_bytes());
        mem.write_bytes(0x4000, &header2);

        let read_chain = vec![
            Descriptor {
                addr: 0x4000,
                len: 16,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x5000,
                len: 512,
                flags: 2,
                next: 0,
            },
            Descriptor {
                addr: 0x6000,
                len: 1,
                flags: 2,
                next: 0,
            },
        ];

        let status2 = blk.process_request(&read_chain, &mem);
        assert_eq!(status2, VIRTIO_BLK_S_OK);
        let readback = mem.read_bytes(0x5000, 512);
        assert!(readback.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_write_rejected_on_read_only() {
        let tmp = create_test_disk(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, true);
        let mem = MockMem::new(0x10000);

        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        mem.write_bytes(0x1000, &header);

        let chain = vec![
            Descriptor {
                addr: 0x1000,
                len: 16,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x2000,
                len: 512,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            },
        ];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
    }

    #[test]
    fn test_flush_request() {
        let tmp = create_test_disk(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, false);
        let mem = MockMem::new(0x10000);

        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_FLUSH.to_le_bytes());
        mem.write_bytes(0x1000, &header);

        let chain = vec![
            Descriptor {
                addr: 0x1000,
                len: 16,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            },
        ];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_unsupported_request_type() {
        let tmp = create_test_disk(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, false);
        let mem = MockMem::new(0x10000);

        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&99u32.to_le_bytes()); // Unknown type.
        mem.write_bytes(0x1000, &header);

        let chain = vec![
            Descriptor {
                addr: 0x1000,
                len: 16,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 0x2000,
                len: 512,
                flags: 2,
                next: 0,
            },
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            },
        ];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_UNSUPP);
    }

    #[test]
    fn test_short_chain_error() {
        let tmp = create_test_disk(4);
        let backend = open_raw_backend(&tmp, false);
        let mut blk = VirtioBlock::new(backend, false);
        let mem = MockMem::new(0x10000);

        let chain = vec![Descriptor {
            addr: 0x1000,
            len: 16,
            flags: 0,
            next: 0,
        }];

        let status = blk.process_request(&chain, &mem);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
    }

    // --- VirtioDeviceBackend trait ---

    #[test]
    fn test_version_1_feature() {
        let tmp = create_test_disk(1);
        let backend = open_raw_backend(&tmp, false);
        let blk = VirtioBlock::new(backend, false);
        let features_page1 = blk.device_features(1);
        assert_eq!(features_page1, 1); // Bit 0 of page 1 = VIRTIO_F_VERSION_1.
    }

    #[test]
    fn test_num_queues() {
        let tmp = create_test_disk(1);
        let backend = open_raw_backend(&tmp, false);
        let blk = VirtioBlock::new(backend, false);
        assert_eq!(blk.num_queues(), 1);
    }

    #[test]
    fn test_queue_max_size() {
        let tmp = create_test_disk(1);
        let backend = open_raw_backend(&tmp, false);
        let blk = VirtioBlock::new(backend, false);
        assert_eq!(blk.queue_max_size(0), 256);
    }
}
