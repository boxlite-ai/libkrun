//! Async block I/O worker thread for virtio-blk.
//!
//! Moves disk I/O off the vCPU loop into a dedicated thread so that
//! long-running reads/writes don't starve vsock or net devices.
//!
//! The vCPU thread sends `BlockRequest`s (parsed descriptor chains)
//! via an mpsc channel. The worker performs disk I/O, writes data and
//! status bytes to guest memory, and sends `BlockCompletion`s back.
//! The vCPU thread drains completions during `tick_and_poll()` and
//! updates the used ring.

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use super::disk::DiskBackend;
use super::queue::GuestMemoryAccessor;

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
    pub data_buffers: Vec<BufferDesc>,
    /// Guest address of the status byte (last descriptor).
    pub status_addr: u64,
}

/// Completion sent from the worker back to the vCPU thread.
#[derive(Debug)]
pub struct BlockCompletion {
    /// Descriptor chain head index.
    pub head_index: u16,
    /// Total bytes written to device-writable descriptors (for used ring).
    pub bytes_written: u32,
}

/// Worker thread that processes block I/O requests.
pub struct BlockWorker<M: GuestMemoryAccessor + Send + Sync + 'static> {
    request_rx: mpsc::Receiver<BlockRequest>,
    completion_tx: mpsc::Sender<BlockCompletion>,
    disk: Box<dyn DiskBackend>,
    guest_mem: Arc<M>,
    read_only: bool,
}

impl<M: GuestMemoryAccessor + Send + Sync + 'static> BlockWorker<M> {
    /// Create a new block worker.
    pub fn new(
        request_rx: mpsc::Receiver<BlockRequest>,
        completion_tx: mpsc::Sender<BlockCompletion>,
        disk: Box<dyn DiskBackend>,
        guest_mem: Arc<M>,
        read_only: bool,
    ) -> Self {
        BlockWorker {
            request_rx,
            completion_tx,
            disk,
            guest_mem,
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
        log::info!("block worker started");

        while let Ok(req) = self.request_rx.recv() {
            let (status, bytes_written) = self.process_request(&req);

            // Write status byte to guest memory.
            let _ = self.guest_mem.write_at(req.status_addr, &[status]);

            let completion = BlockCompletion {
                head_index: req.head_index,
                bytes_written,
            };

            // If the vCPU thread dropped its receiver, the VM is shutting down.
            if self.completion_tx.send(completion).is_err() {
                break;
            }
        }

        log::info!("block worker exiting");
    }

    /// Process a single block request. Returns (status, bytes_written).
    fn process_request(&mut self, req: &BlockRequest) -> (u8, u32) {
        match req.req_type {
            RequestType::Read => self.handle_read(req.sector, &req.data_buffers),
            RequestType::Write => self.handle_write(req.sector, &req.data_buffers),
            RequestType::Flush => (self.handle_flush(), 0),
            RequestType::Unsupported => (VIRTIO_BLK_S_UNSUPP, 0),
        }
    }

    fn handle_read(&mut self, sector: u64, data_buffers: &[BufferDesc]) -> (u8, u32) {
        let mut offset = sector * SECTOR_SIZE;
        let mut bytes_written: u32 = 0;

        for buf in data_buffers {
            if !buf.is_write {
                log::debug!("BLK worker READ: buffer not device-writable");
                return (VIRTIO_BLK_S_IOERR, bytes_written);
            }
            let mut data = vec![0u8; buf.len as usize];
            if let Err(e) = self.disk.read_at(offset, &mut data) {
                log::debug!("BLK worker READ: disk.read_at failed: {}", e);
                return (VIRTIO_BLK_S_IOERR, bytes_written);
            }
            if let Err(e) = self.guest_mem.write_at(buf.addr, &data) {
                log::debug!("BLK worker READ: mem.write_at failed: {}", e);
                return (VIRTIO_BLK_S_IOERR, bytes_written);
            }
            offset += buf.len as u64;
            bytes_written += buf.len;
        }

        // +1 for the status byte (also device-writable).
        (VIRTIO_BLK_S_OK, bytes_written + 1)
    }

    fn handle_write(&mut self, sector: u64, data_buffers: &[BufferDesc]) -> (u8, u32) {
        if self.read_only {
            return (VIRTIO_BLK_S_IOERR, 0);
        }

        let mut offset = sector * SECTOR_SIZE;

        for buf in data_buffers {
            if buf.is_write {
                // Data for write must be device-readable (not device-writable).
                return (VIRTIO_BLK_S_IOERR, 0);
            }
            let mut data = vec![0u8; buf.len as usize];
            if self.guest_mem.read_at(buf.addr, &mut data).is_err() {
                return (VIRTIO_BLK_S_IOERR, 0);
            }
            if self.disk.write_at(offset, &data).is_err() {
                return (VIRTIO_BLK_S_IOERR, 0);
            }
            offset += buf.len as u64;
        }

        // Only status byte is device-writable for writes.
        (VIRTIO_BLK_S_OK, 1)
    }

    fn handle_flush(&mut self) -> u8 {
        if self.disk.flush().is_err() {
            VIRTIO_BLK_S_IOERR
        } else {
            VIRTIO_BLK_S_OK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
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
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> super::super::super::super::error::Result<()> {
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

        fn write_at(&mut self, offset: u64, buf: &[u8]) -> super::super::super::super::error::Result<()> {
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

    /// Thread-safe mock guest memory for testing the worker.
    struct MockMem {
        data: std::sync::Mutex<Vec<u8>>,
    }

    impl MockMem {
        fn new(size: usize) -> Self {
            MockMem {
                data: std::sync::Mutex::new(vec![0u8; size]),
            }
        }

        fn write_bytes(&self, addr: u64, bytes: &[u8]) {
            let a = addr as usize;
            let mut data = self.data.lock().unwrap();
            data[a..a + bytes.len()].copy_from_slice(bytes);
        }

        fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
            let a = addr as usize;
            let data = self.data.lock().unwrap();
            data[a..a + len].to_vec()
        }
    }

    impl GuestMemoryAccessor for MockMem {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> super::super::super::super::error::Result<()> {
            let a = addr as usize;
            let data = self.data.lock().unwrap();
            if a + buf.len() > data.len() {
                return Err(super::super::super::super::error::WkrunError::Memory(
                    "out of bounds".into(),
                ));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> super::super::super::super::error::Result<()> {
            let a = addr as usize;
            let mut mem = self.data.lock().unwrap();
            if a + data.len() > mem.len() {
                return Err(super::super::super::super::error::WkrunError::Memory(
                    "out of bounds".into(),
                ));
            }
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn test_worker_read_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::with_pattern(4);
        let mem = Arc::new(MockMem::new(0x10000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), false);
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
            })
            .unwrap();

        // Close the channel to let the worker exit.
        drop(req_tx);
        handle.join().unwrap();

        // Check completion.
        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 42);
        assert_eq!(comp.bytes_written, 513); // 512 data + 1 status

        // Verify data written to guest memory.
        let data = mem.read_bytes(0x2000, 512);
        assert!(data.iter().all(|&b| b == 0x02));

        // Verify status byte.
        let status = mem.read_bytes(0x3000, 1);
        assert_eq!(status[0], VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_worker_write_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(2048);
        let mem = Arc::new(MockMem::new(0x10000));

        // Write data to guest memory that the worker will read.
        mem.write_bytes(0x2000, &vec![0xAB; 512]);

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), false);
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
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 7);
        assert_eq!(comp.bytes_written, 1); // Only status byte is writable.

        let status = mem.read_bytes(0x3000, 1);
        assert_eq!(status[0], VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_worker_flush_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);
        let mem = Arc::new(MockMem::new(0x10000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), false);
        let handle = worker.run("test-blk-flush");

        req_tx
            .send(BlockRequest {
                head_index: 3,
                req_type: RequestType::Flush,
                sector: 0,
                data_buffers: vec![],
                status_addr: 0x3000,
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 3);
        assert_eq!(comp.bytes_written, 0);

        let status = mem.read_bytes(0x3000, 1);
        assert_eq!(status[0], VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_worker_unsupported_request() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);
        let mem = Arc::new(MockMem::new(0x10000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), false);
        let handle = worker.run("test-blk-unsupp");

        req_tx
            .send(BlockRequest {
                head_index: 5,
                req_type: RequestType::Unsupported,
                sector: 0,
                data_buffers: vec![],
                status_addr: 0x3000,
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.head_index, 5);
        assert_eq!(comp.bytes_written, 0);

        let status = mem.read_bytes(0x3000, 1);
        assert_eq!(status[0], VIRTIO_BLK_S_UNSUPP);
    }

    #[test]
    fn test_worker_multiple_requests() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::with_pattern(8);
        let mem = Arc::new(MockMem::new(0x10000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), false);
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

        // Verify each sector's data.
        for i in 0..3u16 {
            let data = mem.read_bytes(0x2000 + (i as u64) * 0x1000, 512);
            assert!(
                data.iter().all(|&b| b == i as u8),
                "sector {} data mismatch",
                i
            );
        }
    }

    #[test]
    fn test_worker_read_only_rejects_write() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);
        let mem = Arc::new(MockMem::new(0x10000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem.clone(), true);
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
            })
            .unwrap();

        drop(req_tx);
        handle.join().unwrap();

        let comp = comp_rx.recv().unwrap();
        assert_eq!(comp.bytes_written, 0);

        let status = mem.read_bytes(0x3000, 1);
        assert_eq!(status[0], VIRTIO_BLK_S_IOERR);
    }

    #[test]
    fn test_worker_graceful_shutdown_on_channel_close() {
        let (req_tx, req_rx) = mpsc::channel();
        let (comp_tx, _comp_rx) = mpsc::channel();

        let disk = MemDisk::new(1024);
        let mem = Arc::new(MockMem::new(0x1000));

        let worker = BlockWorker::new(req_rx, comp_tx, Box::new(disk), mem, false);
        let handle = worker.run("test-blk-shutdown");

        // Drop the sender — worker should exit gracefully.
        drop(req_tx);
        handle.join().unwrap(); // Should not hang or panic.
    }
}
