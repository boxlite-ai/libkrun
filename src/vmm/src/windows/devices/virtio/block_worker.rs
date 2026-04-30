//! Async block I/O worker thread for virtio-blk.
//!
//! Moves disk I/O off the vCPU loop into a dedicated thread so that
//! long-running reads/writes don't starve vsock or net devices.
//!
//! **Plan B (WHPX-safe)**: The worker thread NEVER accesses guest memory.
//! - For reads: worker reads disk → Vec, sends Vec in completion.
//!   The vCPU thread writes the data to guest memory.
//! - For writes: vCPU thread pre-reads data from guest memory → Vec,
//!   sends Vec in request. Worker writes Vec to disk.
//! - Status byte is always written by the vCPU thread.
//!
//! This avoids WHPX memory coherence issues where non-vCPU thread
//! writes to guest memory cause ~60% boot failure on Win10.

use std::sync::mpsc;
use std::thread;

use super::disk::DiskBackend;

/// Block size in bytes (standard sector size).
const SECTOR_SIZE: u64 = 512;

// Virtio-blk status values.
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Type of block request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Read,
    Write,
    Flush,
    Unsupported,
}

/// A single buffer descriptor from the virtqueue chain.
///
/// Used in completions to tell the vCPU thread where to write read data.
#[derive(Debug, Clone)]
pub struct BufferDesc {
    /// Guest physical address.
    pub addr: u64,
    /// Length in bytes.
    pub len: u32,
    /// Whether this buffer is device-writable (guest reads from it).
    pub is_write: bool,
}

/// A block request dispatched from the vCPU thread to the worker.
#[derive(Debug)]
pub struct BlockRequest {
    /// Descriptor chain head index (for add_used later).
    pub head_index: u16,
    /// Request type (read/write/flush).
    pub req_type: RequestType,
    /// Starting sector (for read/write).
    pub sector: u64,
    /// Data buffer descriptors (between header and status).
    /// For reads: describes where vCPU thread should write the returned data.
    /// For writes: only used for metadata (the actual data is in write_data).
    pub data_buffers: Vec<BufferDesc>,
    /// Guest address of the status byte (last descriptor).
    pub status_addr: u64,
    /// Pre-read write data from guest memory (only for Write requests).
    /// The vCPU thread reads this from guest memory before sending.
    pub write_data: Option<Vec<u8>>,
}

/// Completion sent from the worker back to the vCPU thread.
#[derive(Debug)]
pub struct BlockCompletion {
    /// Descriptor chain head index.
    pub head_index: u16,
    /// Total bytes written to device-writable descriptors (for used ring).
    pub bytes_written: u32,
    /// Virtio-blk status byte (OK/IOERR/UNSUPP).
    pub status: u8,
    /// Guest address where status byte should be written.
    pub status_addr: u64,
    /// Data read from disk (only for Read requests).
    /// The vCPU thread writes this to guest memory at the addresses
    /// specified in read_targets.
    pub read_data: Option<Vec<u8>>,
    /// Guest memory targets for read data (addr, len pairs from data_buffers).
    /// The vCPU thread iterates these to scatter read_data into guest memory.
    pub read_targets: Vec<BufferDesc>,
}

/// Worker thread that processes block I/O requests.
///
/// The worker NEVER accesses guest memory. All guest memory reads/writes
/// are done by the vCPU thread (Plan B for WHPX safety).
pub struct BlockWorker {
    request_rx: mpsc::Receiver<BlockRequest>,
    completion_tx: mpsc::Sender<BlockCompletion>,
    disk: Box<dyn DiskBackend>,
    read_only: bool,
}

impl BlockWorker {
    /// Create a new block worker.
    pub fn new(
        request_rx: mpsc::Receiver<BlockRequest>,
        completion_tx: mpsc::Sender<BlockCompletion>,
        disk: Box<dyn DiskBackend>,
        read_only: bool,
    ) -> Self {
        BlockWorker {
            request_rx,
            completion_tx,
            disk,
            read_only,
        }
    }

    /// Spawn the worker on a named thread. Returns the join handle.
    pub fn run(self, name: &str) -> thread::JoinHandle<()> {
        let thread_name = name.to_string();
        thread::Builder::new()
            .name(thread_name)
            .spawn(move || self.work())
            .expect("failed to spawn block worker thread")
    }

    /// Blocking recv loop: process requests until the channel closes.
    fn work(mut self) {
        log::info!("block worker started (Plan B: no guest memory access)");

        while let Ok(req) = self.request_rx.recv() {
            let completion = self.process_request(req);

            // If the vCPU thread dropped its receiver, the VM is shutting down.
            if self.completion_tx.send(completion).is_err() {
                break;
            }
        }

        log::info!("block worker exiting");
    }

    /// Process a single block request. Returns a completion with data/status.
    fn process_request(&mut self, req: BlockRequest) -> BlockCompletion {
        match req.req_type {
            RequestType::Read => self.handle_read(req),
            RequestType::Write => self.handle_write(req),
            RequestType::Flush => self.handle_flush(req),
            RequestType::Unsupported => BlockCompletion {
                head_index: req.head_index,
                bytes_written: 0,
                status: VIRTIO_BLK_S_UNSUPP,
                status_addr: req.status_addr,
                read_data: None,
                read_targets: vec![],
            },
        }
    }

    fn handle_read(&mut self, req: BlockRequest) -> BlockCompletion {
        let mut offset = req.sector * SECTOR_SIZE;
        let mut all_data = Vec::new();
        let mut bytes_written: u32 = 0;

        for buf in &req.data_buffers {
            if !buf.is_write {
                log::debug!("BLK worker READ: buffer not device-writable");
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
            let mut data = vec![0u8; buf.len as usize];
            if let Err(e) = self.disk.read_at(offset, &mut data) {
                log::debug!("BLK worker READ: disk.read_at failed: {}", e);
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
            all_data.extend_from_slice(&data);
            offset += buf.len as u64;
            bytes_written += buf.len;
        }

        // +1 for the status byte (also device-writable).
        BlockCompletion {
            head_index: req.head_index,
            bytes_written: bytes_written + 1,
            status: VIRTIO_BLK_S_OK,
            status_addr: req.status_addr,
            read_data: Some(all_data),
            read_targets: req.data_buffers,
        }
    }

    fn handle_write(&mut self, req: BlockRequest) -> BlockCompletion {
        if self.read_only {
            return BlockCompletion {
                head_index: req.head_index,
                bytes_written: 0,
                status: VIRTIO_BLK_S_IOERR,
                status_addr: req.status_addr,
                read_data: None,
                read_targets: vec![],
            };
        }

        let write_data = match req.write_data {
            Some(ref data) => data,
            None => {
                log::debug!("BLK worker WRITE: no write_data provided");
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written: 0,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
        };

        let mut offset = req.sector * SECTOR_SIZE;
        let mut data_offset: usize = 0;

        for buf in &req.data_buffers {
            if buf.is_write {
                // Data for write must be device-readable (not device-writable).
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written: 0,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
            let end = data_offset + buf.len as usize;
            if end > write_data.len() {
                log::debug!("BLK worker WRITE: write_data too short");
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written: 0,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
            if self
                .disk
                .write_at(offset, &write_data[data_offset..end])
                .is_err()
            {
                return BlockCompletion {
                    head_index: req.head_index,
                    bytes_written: 0,
                    status: VIRTIO_BLK_S_IOERR,
                    status_addr: req.status_addr,
                    read_data: None,
                    read_targets: vec![],
                };
            }
            offset += buf.len as u64;
            data_offset = end;
        }

        // Only status byte is device-writable for writes.
        BlockCompletion {
            head_index: req.head_index,
            bytes_written: 1,
            status: VIRTIO_BLK_S_OK,
            status_addr: req.status_addr,
            read_data: None,
            read_targets: vec![],
        }
    }

    fn handle_flush(&mut self, req: BlockRequest) -> BlockCompletion {
        let status = if self.disk.flush().is_err() {
            VIRTIO_BLK_S_IOERR
        } else {
            VIRTIO_BLK_S_OK
        };
        // bytes_written=1 for the status byte (device-writable),
        // matching the sync path in VirtioBlock::queue_notify.
        BlockCompletion {
            head_index: req.head_index,
            bytes_written: 1,
            status,
            status_addr: req.status_addr,
            read_data: None,
            read_targets: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// In-memory disk backend for testing.
    struct MemDisk {
        data: Vec<u8>,
        read_only: bool,
    }

    impl MemDisk {
        fn new(size: usize) -> Self {
            MemDisk {
                data: vec![0u8; size],
                read_only: false,
            }
        }

        fn with_pattern(sectors: u64) -> Self {
            let size = (sectors * SECTOR_SIZE) as usize;
            let mut data = vec![0u8; size];
            for sector in 0..sectors {
                let start = (sector * SECTOR_SIZE) as usize;
                let end = start + SECTOR_SIZE as usize;
                data[start..end].fill((sector & 0xFF) as u8);
            }
            MemDisk {
                data,
                read_only: false,
            }
        }
    }

    // Safety: MemDisk only uses Vec<u8> which is Send.
    unsafe impl Send for MemDisk {}

    impl DiskBackend for MemDisk {
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> super::super::super::super::error::Result<()> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(super::super::super::super::error::WkrunError::Device(
                    "read out of bounds".into(),
                ));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_at(
            &mut self,
            offset: u64,
            buf: &[u8],
        ) -> super::super::super::super::error::Result<()> {
            if self.read_only {
                return Err(super::super::super::super::error::WkrunError::Device(
                    "read-only disk".into(),
                ));
            }
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(super::super::super::super::error::WkrunError::Device(
                    "write out of bounds".into(),
                ));
            }
            self.data[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn flush(&mut self) -> super::super::super::super::error::Result<()> {
            Ok(())
        }

        fn capacity_bytes(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn test_worker_read_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::with_pattern(4);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-read");

        // Send a read request for sector 2 (pattern = 0x02).
        req_tx
            .send(BlockRequest {
                head_index: 42,
                req_type: RequestType::Read,
                sector: 2,
                data_buffers: vec![BufferDesc {
                    addr: 0x2000,
                    len: 512,
                    is_write: true,
                }],
                status_addr: 0x3000,
                write_data: None,
            })
            .unwrap();

        // Close the channel to let the worker exit.
        drop(req_tx);
        handle.join().unwrap();

        // Check completion.
        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 42);
        assert_eq!(comp.bytes_written, 513); // 512 data + 1 status
        assert_eq!(comp.status, VIRTIO_BLK_S_OK);
        assert_eq!(comp.status_addr, 0x3000);

        // Verify read data is returned in completion (not written to guest mem).
        let read_data = comp.read_data.unwrap();
        assert_eq!(read_data.len(), 512);
        assert!(read_data.iter().all(|&b| b == 0x02));

        // Verify read targets match the original buffers.
        assert_eq!(comp.read_targets.len(), 1);
        assert_eq!(comp.read_targets[0].addr, 0x2000);
        assert_eq!(comp.read_targets[0].len, 512);
    }

    #[test]
    fn test_worker_write_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(2048);

        // Write data is pre-read from guest memory by the vCPU thread.
        let write_data = vec![0xAB; 512];

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-write");

        req_tx
            .send(BlockRequest {
                head_index: 7,
                req_type: RequestType::Write,
                sector: 1,
                data_buffers: vec![BufferDesc {
                    addr: 0x2000,
                    len: 512,
                    is_write: false, // Device-readable for writes.
                }],
                status_addr: 0x3000,
                write_data: Some(write_data),
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 7);
        assert_eq!(comp.bytes_written, 1); // Only status byte is writable.
        assert_eq!(comp.status, VIRTIO_BLK_S_OK);
        assert!(comp.read_data.is_none());
    }

    #[test]
    fn test_worker_flush_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-flush");

        req_tx
            .send(BlockRequest {
                head_index: 3,
                req_type: RequestType::Flush,
                sector: 0,
                data_buffers: vec![],
                status_addr: 0x3000,
                write_data: None,
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 3);
        assert_eq!(comp.bytes_written, 1); // status byte
        assert_eq!(comp.status, VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_worker_unsupported_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-unsupp");

        req_tx
            .send(BlockRequest {
                head_index: 5,
                req_type: RequestType::Unsupported,
                sector: 0,
                data_buffers: vec![],
                status_addr: 0x3000,
                write_data: None,
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 5);
        assert_eq!(comp.bytes_written, 0);
        assert_eq!(comp.status, VIRTIO_BLK_S_UNSUPP);
    }

    #[test]
    fn test_worker_multiple_requests() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::with_pattern(8);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-multi");

        // Send 3 read requests for sectors 0, 1, 2.
        for i in 0..3u16 {
            req_tx
                .send(BlockRequest {
                    head_index: i,
                    req_type: RequestType::Read,
                    sector: i as u64,
                    data_buffers: vec![BufferDesc {
                        addr: 0x2000 + (i as u64) * 0x1000,
                        len: 512,
                        is_write: true,
                    }],
                    status_addr: 0x8000 + i as u64,
                    write_data: None,
                })
                .unwrap();
        }

        drop(req_tx);
        handle.join().unwrap();

        // All 3 completions should arrive.
        let mut completions: Vec<BlockCompletion> = Vec::new();
        while let Ok(c) = comp_rx.try_recv() {
            completions.push(c);
        }
        assert_eq!(completions.len(), 3);

        // Verify each sector's data is in the completion.
        for (idx, comp) in completions.iter().enumerate() {
            let data = comp.read_data.as_ref().unwrap();
            assert_eq!(data.len(), 512);
            assert!(
                data.iter().all(|&b| b == idx as u8),
                "sector {} data mismatch",
                idx
            );
        }
    }

    #[test]
    fn test_worker_read_only_rejects_write() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), true);
        let handle = worker.run("test-blk-ro");

        req_tx
            .send(BlockRequest {
                head_index: 1,
                req_type: RequestType::Write,
                sector: 0,
                data_buffers: vec![BufferDesc {
                    addr: 0x2000,
                    len: 512,
                    is_write: false,
                }],
                status_addr: 0x3000,
                write_data: Some(vec![0xAB; 512]),
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.bytes_written, 0);
        assert_eq!(comp.status, VIRTIO_BLK_S_IOERR);
    }

    #[test]
    fn test_worker_graceful_shutdown_on_channel_close() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, _comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-shutdown");

        // Drop the sender — worker should exit gracefully.
        drop(req_tx);
        handle.join().unwrap(); // Should not hang or panic.
    }

    #[test]
    fn test_worker_write_missing_data_returns_error() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(2048);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), false);
        let handle = worker.run("test-blk-write-nodata");

        // Write request without write_data should fail.
        req_tx
            .send(BlockRequest {
                head_index: 1,
                req_type: RequestType::Write,
                sector: 0,
                data_buffers: vec![BufferDesc {
                    addr: 0x2000,
                    len: 512,
                    is_write: false,
                }],
                status_addr: 0x3000,
                write_data: None, // Missing!
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.status, VIRTIO_BLK_S_IOERR);
    }
}
