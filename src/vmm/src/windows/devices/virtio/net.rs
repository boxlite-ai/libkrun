//! Virtio-net device backend (virtio spec v1.2 Section 5.1).
//!
//! Provides a network device backed by a userspace networking proxy
//! (passt/gvproxy) via a stream socket. The wire protocol uses
//! length-prefixed Ethernet frames: `[4-byte BE length][frame bytes]`.
//!
//! Queue layout:
//!   Queue 0 (RX): host -> guest (device writes, guest reads)
//!   Queue 1 (TX): guest -> host (guest writes, device reads)

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use super::mmio::VirtioDeviceBackend;
use super::queue::{GuestMemoryAccessor, Virtqueue};

/// Virtio device ID for network devices.
const VIRTIO_NET_ID: u32 = 1;

/// VIRTIO_NET_F_MAC — device has given MAC address (bit 5).
const VIRTIO_NET_F_MAC: u32 = 5;

/// VIRTIO_NET_F_STATUS — device provides link status (bit 16).
const VIRTIO_NET_F_STATUS: u32 = 16;

/// VIRTIO_F_VERSION_1 — bit 32 (page 1, bit 0).
const VIRTIO_F_VERSION_1_BIT: u32 = 0;

/// Number of queues: RX and TX (no control queue).
const NUM_QUEUES: usize = 2;

/// Queue index constants.
const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;

/// Maximum queue size.
const QUEUE_MAX_SIZE: u16 = 256;

/// Size of struct virtio_net_hdr_v1 in bytes.
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Network link status: up.
const VIRTIO_NET_S_LINK_UP: u16 = 1;

/// Transport trait for pluggable networking backends.
///
/// Unix socket transports use the passt/gvproxy wire
/// protocol: each frame is `[4-byte big-endian length][frame bytes]`.
pub trait NetTransport: Send {
    /// Try to receive a complete Ethernet frame. Returns `None` if no
    /// complete frame is available (non-blocking).
    fn recv_frame(&mut self) -> Option<Vec<u8>>;

    /// Send an Ethernet frame, length-prefixed.
    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// Receive state machine for length-prefixed framing.
enum RecvState {
    /// Waiting for the 4-byte length header; `bytes_read` bytes read so far.
    LenPending { bytes_read: usize, buf: [u8; 4] },
    /// Length header complete, reading `frame_len` bytes of frame body.
    BodyPending {
        frame_len: usize,
        buf: Vec<u8>,
        bytes_read: usize,
    },
}

impl Default for RecvState {
    fn default() -> Self {
        RecvState::LenPending {
            bytes_read: 0,
            buf: [0u8; 4],
        }
    }
}

/// Unix stream socket transport (macOS/Linux).
#[cfg(unix)]
pub struct UnixStreamTransport {
    stream: std::os::unix::net::UnixStream,
    state: RecvState,
}

#[cfg(unix)]
impl UnixStreamTransport {
    /// Wrap a non-blocking Unix stream socket.
    pub fn new(stream: std::os::unix::net::UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(UnixStreamTransport {
            stream,
            state: RecvState::default(),
        })
    }
}

#[cfg(unix)]
impl NetTransport for UnixStreamTransport {
    fn recv_frame(&mut self) -> Option<Vec<u8>> {
        recv_frame_from(&mut self.stream, &mut self.state)
    }

    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        send_frame_to(&mut self.stream, frame)
    }
}

/// Unix domain socket transport (Windows, via uds_windows crate).
#[cfg(windows)]
pub struct UdsTransport {
    stream: uds_windows::UnixStream,
    state: RecvState,
}

#[cfg(windows)]
impl UdsTransport {
    /// Wrap a non-blocking Unix domain socket stream.
    pub fn new(stream: uds_windows::UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(UdsTransport {
            stream,
            state: RecvState::default(),
        })
    }
}

#[cfg(windows)]
impl NetTransport for UdsTransport {
    fn recv_frame(&mut self) -> Option<Vec<u8>> {
        recv_frame_from(&mut self.stream, &mut self.state)
    }

    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        send_frame_to(&mut self.stream, frame)
    }
}

/// Shared recv implementation using the state machine.
fn recv_frame_from<R: Read>(reader: &mut R, state: &mut RecvState) -> Option<Vec<u8>> {
    loop {
        match state {
            RecvState::LenPending { bytes_read, buf } => {
                match reader.read(&mut buf[*bytes_read..]) {
                    Ok(0) => return None, // EOF
                    Ok(n) => {
                        *bytes_read += n;
                        if *bytes_read == 4 {
                            let frame_len = u32::from_be_bytes(*buf) as usize;
                            if frame_len == 0 || frame_len > 65536 {
                                // Invalid frame, reset.
                                *state = RecvState::default();
                                return None;
                            }
                            *state = RecvState::BodyPending {
                                frame_len,
                                buf: vec![0u8; frame_len],
                                bytes_read: 0,
                            };
                            // Continue loop to read body.
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return None,
                    Err(_) => return None,
                }
            }
            RecvState::BodyPending {
                frame_len,
                buf,
                bytes_read,
            } => {
                match reader.read(&mut buf[*bytes_read..]) {
                    Ok(0) => return None, // EOF
                    Ok(n) => {
                        *bytes_read += n;
                        if *bytes_read == *frame_len {
                            let frame = std::mem::take(buf);
                            *state = RecvState::default();
                            return Some(frame);
                        }
                        // Continue loop to read more.
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return None,
                    Err(_) => return None,
                }
            }
        }
    }
}

/// Shared send implementation: 4-byte BE length + frame bytes.
fn send_frame_to<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    let len = (frame.len() as u32).to_be_bytes();
    writer.write_all(&len)?;
    writer.write_all(frame)?;
    Ok(())
}

/// Generate a MAC address deterministically from a seed.
///
/// The first three bytes are `52:54:00` (QEMU/KVM OUI prefix).
/// The remaining bytes are derived from `seed`.
pub fn generate_mac(seed: u32) -> [u8; 6] {
    let b = seed.to_le_bytes();
    [0x52, 0x54, 0x00, b[0], b[1], b[2]]
}

/// Virtio-net device backed by a userspace networking proxy.
pub struct VirtioNet {
    /// MAC address exposed to the guest.
    mac: [u8; 6],
    /// Network transport (socket to passt/gvproxy).
    transport: Option<Box<dyn NetTransport>>,
    /// Frames waiting for RX queue space.
    rx_pending: VecDeque<Vec<u8>>,
}

impl VirtioNet {
    /// Create a new virtio-net device with the given MAC and transport.
    pub fn new(mac: [u8; 6], transport: Option<Box<dyn NetTransport>>) -> Self {
        VirtioNet {
            mac,
            transport,
            rx_pending: VecDeque::new(),
        }
    }

    /// Get the MAC address.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Process the TX queue: read frames from guest, send to transport.
    fn process_tx(&mut self, queue: &mut Virtqueue, mem: &dyn GuestMemoryAccessor) -> bool {
        let mut processed = false;

        while let Ok(Some(head)) = queue.pop_avail(mem) {
            let chain = match queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(_) => {
                    let _ = queue.add_used(head, 0, mem);
                    processed = true;
                    continue;
                }
            };

            if chain.is_empty() {
                let _ = queue.add_used(head, 0, mem);
                processed = true;
                continue;
            }

            // Collect all data from device-readable descriptors.
            let mut data = Vec::new();
            for desc in &chain {
                if !desc.is_write() {
                    let mut buf = vec![0u8; desc.len as usize];
                    if mem.read_at(desc.addr, &mut buf).is_ok() {
                        data.extend_from_slice(&buf);
                    }
                }
            }

            // First VIRTIO_NET_HDR_SIZE bytes are the virtio_net_hdr — strip it.
            if data.len() > VIRTIO_NET_HDR_SIZE {
                let frame = &data[VIRTIO_NET_HDR_SIZE..];
                if let Some(ref mut transport) = self.transport {
                    let _ = transport.send_frame(frame);
                }
            }

            let _ = queue.add_used(head, 0, mem);
            processed = true;
        }

        processed
    }

    /// Inject pending frames into the RX queue.
    fn inject_rx(&mut self, rx_queue: &mut Virtqueue, mem: &dyn GuestMemoryAccessor) -> bool {
        let mut injected = false;

        while !self.rx_pending.is_empty() {
            let head = match rx_queue.pop_avail(mem) {
                Ok(Some(h)) => h,
                _ => break, // No available RX buffers.
            };

            let chain = match rx_queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(_) => {
                    let _ = rx_queue.add_used(head, 0, mem);
                    injected = true;
                    continue;
                }
            };

            let frame = self.rx_pending.pop_front().unwrap();

            // Prepend a zero virtio_net_hdr.
            let hdr = [0u8; VIRTIO_NET_HDR_SIZE];
            let total_data: Vec<u8> = hdr.iter().chain(frame.iter()).copied().collect();

            let mut offset = 0;
            let mut total_written = 0u32;
            for desc in &chain {
                if !desc.is_write() {
                    continue;
                }
                let remaining = total_data.len().saturating_sub(offset);
                let to_write = remaining.min(desc.len as usize);
                if to_write > 0 {
                    let _ = mem.write_at(desc.addr, &total_data[offset..offset + to_write]);
                    offset += to_write;
                    total_written += to_write as u32;
                }
            }

            let _ = rx_queue.add_used(head, total_written, mem);
            injected = true;
        }

        injected
    }
}

impl VirtioDeviceBackend for VirtioNet {
    fn device_id(&self) -> u32 {
        VIRTIO_NET_ID
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            0 => (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_STATUS),
            1 => 1 << VIRTIO_F_VERSION_1_BIT,
            _ => 0,
        }
    }

    fn read_config(&self, offset: u64) -> u32 {
        // Config space layout (virtio spec 5.1.4):
        //   offset 0: mac[0..3] (4 bytes as u32 LE)
        //   offset 4: mac[4..5] + status (u16 each, packed as u32 LE)
        //   offset 6: status (u16) — but guest typically reads at offset 4
        match offset {
            0 => u32::from_le_bytes([self.mac[0], self.mac[1], self.mac[2], self.mac[3]]),
            4 => {
                // mac[4], mac[5], status_lo, status_hi
                let status = VIRTIO_NET_S_LINK_UP;
                u32::from_le_bytes([
                    self.mac[4],
                    self.mac[5],
                    (status & 0xFF) as u8,
                    ((status >> 8) & 0xFF) as u8,
                ])
            }
            _ => 0,
        }
    }

    fn queue_notify(
        &mut self,
        queue_idx: u32,
        queue: &mut Virtqueue,
        mem: &dyn GuestMemoryAccessor,
    ) -> bool {
        match queue_idx as usize {
            TX_QUEUE => self.process_tx(queue, mem),
            _ => false,
        }
    }

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn queue_max_size(&self, _queue_idx: u32) -> u16 {
        QUEUE_MAX_SIZE
    }

    fn poll(&mut self, queues: &mut [Virtqueue], mem: &dyn GuestMemoryAccessor) -> bool {
        // Drain available frames from the transport.
        if let Some(ref mut transport) = self.transport {
            while let Some(frame) = transport.recv_frame() {
                self.rx_pending.push_back(frame);
            }
        }

        // Inject pending frames into the RX queue.
        if queues.len() > RX_QUEUE {
            self.inject_rx(&mut queues[RX_QUEUE], mem)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::error::{Result, WkrunError};
    use super::queue::Virtqueue;
    use super::*;
    use std::cell::RefCell;

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

        fn write_u16_at(&self, addr: u64, val: u16) {
            self.write_bytes(addr, &val.to_le_bytes());
        }

        fn write_u32_at(&self, addr: u64, val: u32) {
            self.write_bytes(addr, &val.to_le_bytes());
        }

        fn write_u64_at(&self, addr: u64, val: u64) {
            self.write_bytes(addr, &val.to_le_bytes());
        }
    }

    impl GuestMemoryAccessor for MockMem {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            let data = self.data.borrow();
            if a + buf.len() > data.len() {
                return Err(WkrunError::Memory("out of bounds".into()));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            let a = addr as usize;
            let mut mem = self.data.borrow_mut();
            if a + data.len() > mem.len() {
                return Err(WkrunError::Memory("out of bounds".into()));
            }
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    // Memory layout for tests.
    const DESC_TABLE: u64 = 0x0000;
    const DESC_SIZE: u64 = 16;
    const AVAIL_RING: u64 = 0x0800;
    const USED_RING: u64 = 0x1000;
    const BUF_BASE: u64 = 0x2000;

    fn setup_queue(max_size: u16) -> Virtqueue {
        let mut q = Virtqueue::new(max_size);
        q.set_size(max_size);
        q.set_desc_table(DESC_TABLE);
        q.set_avail_ring(AVAIL_RING);
        q.set_used_ring(USED_RING);
        q.set_ready(true);
        q
    }

    fn write_descriptor(mem: &MockMem, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let base = DESC_TABLE + index as u64 * DESC_SIZE;
        mem.write_u64_at(base, addr);
        mem.write_u32_at(base + 8, len);
        mem.write_u16_at(base + 12, flags);
        mem.write_u16_at(base + 14, next);
    }

    fn push_avail(mem: &MockMem, ring_idx: u16, desc_head: u16) {
        let entry_off = AVAIL_RING + 4 + (ring_idx as u64) * 2;
        mem.write_u16_at(entry_off, desc_head);
        mem.write_u16_at(AVAIL_RING + 2, ring_idx + 1);
    }

    /// Mock transport with shared state for inspecting sent frames
    /// and injecting received frames after the transport is owned by VirtioNet.
    struct SharedMockTransport {
        sent: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        recv_queue: std::sync::Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    }

    impl SharedMockTransport {
        fn new() -> (Self, SharedMockHandle) {
            let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let recv_queue = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::new()));
            let handle = SharedMockHandle {
                sent: sent.clone(),
                recv_queue: recv_queue.clone(),
            };
            (SharedMockTransport { sent, recv_queue }, handle)
        }
    }

    impl NetTransport for SharedMockTransport {
        fn recv_frame(&mut self) -> Option<Vec<u8>> {
            self.recv_queue.lock().unwrap().pop_front()
        }

        fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(frame.to_vec());
            Ok(())
        }
    }

    struct SharedMockHandle {
        sent: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        recv_queue: std::sync::Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    }

    impl SharedMockHandle {
        fn push_recv(&self, frame: Vec<u8>) {
            self.recv_queue.lock().unwrap().push_back(frame);
        }

        fn sent_frames(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    fn test_mac() -> [u8; 6] {
        [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
    }

    // --- Device identity ---

    #[test]
    fn test_device_id() {
        let dev = VirtioNet::new(test_mac(), None);
        assert_eq!(dev.device_id(), 1);
    }

    #[test]
    fn test_num_queues() {
        let dev = VirtioNet::new(test_mac(), None);
        assert_eq!(dev.num_queues(), 2);
    }

    #[test]
    fn test_queue_max_size() {
        let dev = VirtioNet::new(test_mac(), None);
        assert_eq!(dev.queue_max_size(0), 256);
        assert_eq!(dev.queue_max_size(1), 256);
    }

    #[test]
    fn test_features_page0() {
        let dev = VirtioNet::new(test_mac(), None);
        let features = dev.device_features(0);
        assert_ne!(features & (1 << VIRTIO_NET_F_MAC), 0);
        assert_ne!(features & (1 << VIRTIO_NET_F_STATUS), 0);
    }

    #[test]
    fn test_features_page1() {
        let dev = VirtioNet::new(test_mac(), None);
        assert_eq!(dev.device_features(1), 1); // VIRTIO_F_VERSION_1
    }

    // --- Config space ---

    #[test]
    fn test_config_mac_offset_0() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dev = VirtioNet::new(mac, None);
        let val = dev.read_config(0);
        assert_eq!(val, u32::from_le_bytes([0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn test_config_mac_offset_4() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dev = VirtioNet::new(mac, None);
        let val = dev.read_config(4);
        // mac[4]=0xEE, mac[5]=0xFF, status=0x0001 (LINK_UP)
        assert_eq!(val, u32::from_le_bytes([0xEE, 0xFF, 0x01, 0x00]));
    }

    #[test]
    fn test_config_status_link_up() {
        let dev = VirtioNet::new(test_mac(), None);
        let val = dev.read_config(4);
        // Status is in bytes 2-3 of the u32 at offset 4.
        let status = (val >> 16) as u16;
        assert_eq!(status, VIRTIO_NET_S_LINK_UP);
    }

    // --- TX queue ---

    #[test]
    fn test_tx_sends_frame() {
        let (transport, handle) = SharedMockTransport::new();
        let mut dev = VirtioNet::new(test_mac(), Some(Box::new(transport)));
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(256);

        // Write virtio_net_hdr (12 zero bytes) + Ethernet frame to guest memory.
        let mut tx_data = vec![0u8; VIRTIO_NET_HDR_SIZE];
        let frame = b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\x12\x34\x56\x08\x00hello";
        tx_data.extend_from_slice(frame);
        mem.write_bytes(BUF_BASE, &tx_data);

        // Single descriptor: header + frame (device-readable).
        write_descriptor(&mem, 0, BUF_BASE, tx_data.len() as u32, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);

        let sent = handle.sent_frames();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], frame); // virtio_net_hdr stripped.
    }

    #[test]
    fn test_tx_empty_chain_skipped() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(256);

        write_descriptor(&mem, 0, BUF_BASE, 0, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);
    }

    #[test]
    fn test_tx_short_header_skipped() {
        let (transport, handle) = SharedMockTransport::new();
        let mut dev = VirtioNet::new(test_mac(), Some(Box::new(transport)));
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(256);

        // Only 8 bytes — shorter than virtio_net_hdr.
        mem.write_bytes(BUF_BASE, &[0u8; 8]);
        write_descriptor(&mem, 0, BUF_BASE, 8, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);
        assert!(handle.sent_frames().is_empty()); // Nothing sent.
    }

    // --- RX queue ---

    #[test]
    fn test_rx_inject_frame() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(256);

        let frame = b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\x12\x34\x56\x08\x00data".to_vec();
        dev.rx_pending.push_back(frame.clone());

        // RX buffer (device-writable).
        write_descriptor(&mem, 0, BUF_BASE, 1500, 2, 0); // WRITE flag = 2
        push_avail(&mem, 0, 0);

        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(injected);

        // Check: 12-byte zero header + frame.
        let hdr = mem.read_bytes(BUF_BASE, VIRTIO_NET_HDR_SIZE);
        assert_eq!(hdr, vec![0u8; VIRTIO_NET_HDR_SIZE]);
        let written_frame = mem.read_bytes(BUF_BASE + VIRTIO_NET_HDR_SIZE as u64, frame.len());
        assert_eq!(written_frame, frame);
    }

    #[test]
    fn test_rx_no_buffers_stays_pending() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(256);
        // Don't push any available buffers.

        dev.rx_pending.push_back(b"frame1".to_vec());
        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(!injected);
        assert_eq!(dev.rx_pending.len(), 1);
    }

    #[test]
    fn test_rx_multiple_frames() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(256);

        dev.rx_pending.push_back(b"frame1".to_vec());
        dev.rx_pending.push_back(b"frame2".to_vec());

        // Two RX buffers.
        write_descriptor(&mem, 0, BUF_BASE, 1500, 2, 0);
        push_avail(&mem, 0, 0);
        write_descriptor(&mem, 1, BUF_BASE + 0x1000, 1500, 2, 0);
        push_avail(&mem, 1, 1);

        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(injected);
        assert!(dev.rx_pending.is_empty());

        // Check first frame.
        let f1 = mem.read_bytes(BUF_BASE + VIRTIO_NET_HDR_SIZE as u64, 6);
        assert_eq!(f1, b"frame1");

        // Check second frame.
        let f2 = mem.read_bytes(BUF_BASE + 0x1000 + VIRTIO_NET_HDR_SIZE as u64, 6);
        assert_eq!(f2, b"frame2");
    }

    // --- Poll ---

    #[test]
    fn test_poll_reads_transport() {
        let (transport, handle) = SharedMockTransport::new();
        let mut dev = VirtioNet::new(test_mac(), Some(Box::new(transport)));
        let mem = MockMem::new(0x10000);

        handle.push_recv(b"incoming_frame".to_vec());

        // Set up RX buffer.
        write_descriptor(&mem, 0, BUF_BASE, 1500, 2, 0);
        push_avail(&mem, 0, 0);

        let mut queues = vec![setup_queue(256), setup_queue(256)];
        // Point RX queue to our descriptors.
        queues[0].set_desc_table(DESC_TABLE);
        queues[0].set_avail_ring(AVAIL_RING);
        queues[0].set_used_ring(USED_RING);

        let raised = dev.poll(&mut queues, &mem);
        assert!(raised);

        // Frame should be in RX queue: 12-byte hdr + "incoming_frame".
        let total_len = VIRTIO_NET_HDR_SIZE + 14;
        let written = mem.read_bytes(BUF_BASE, total_len);
        assert_eq!(&written[..VIRTIO_NET_HDR_SIZE], &[0u8; VIRTIO_NET_HDR_SIZE]);
        assert_eq!(&written[VIRTIO_NET_HDR_SIZE..], b"incoming_frame");
    }

    #[test]
    fn test_poll_no_data() {
        let (transport, _handle) = SharedMockTransport::new();
        let mut dev = VirtioNet::new(test_mac(), Some(Box::new(transport)));
        let mem = MockMem::new(0x10000);

        let mut queues = vec![setup_queue(256), setup_queue(256)];
        let raised = dev.poll(&mut queues, &mem);
        assert!(!raised);
    }

    // --- Frame length prefix encoding/decoding ---

    #[test]
    fn test_frame_length_prefix_encode() {
        let mut buf = Vec::new();
        let frame = b"test frame data";
        send_frame_to(&mut buf, frame).unwrap();

        assert_eq!(buf.len(), 4 + frame.len());
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(len, frame.len() as u32);
        assert_eq!(&buf[4..], frame);
    }

    #[test]
    fn test_frame_length_prefix_decode() {
        let frame = b"hello ethernet";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        wire.extend_from_slice(frame);

        let mut state = RecvState::default();
        let mut cursor = io::Cursor::new(wire);
        let result = recv_frame_from(&mut cursor, &mut state);
        assert_eq!(result, Some(frame.to_vec()));
    }

    // --- No transport ---

    #[test]
    fn test_new_without_transport() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);

        // TX should silently drop.
        let mut tx_data = vec![0u8; VIRTIO_NET_HDR_SIZE];
        tx_data.extend_from_slice(b"dropped");
        mem.write_bytes(BUF_BASE, &tx_data);
        write_descriptor(&mem, 0, BUF_BASE, tx_data.len() as u32, 0, 0);
        push_avail(&mem, 0, 0);
        let mut tx_queue = setup_queue(256);
        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);

        // Poll with no transport = false.
        let mut queues = vec![setup_queue(256), setup_queue(256)];
        assert!(!dev.poll(&mut queues, &mem));
    }

    // --- MAC generation ---

    #[test]
    fn test_mac_generation() {
        let mac = generate_mac(42);
        assert_eq!(mac[0], 0x52);
        assert_eq!(mac[1], 0x54);
        assert_eq!(mac[2], 0x00);
        // Remaining bytes from seed.
        let b = 42u32.to_le_bytes();
        assert_eq!(mac[3], b[0]);
        assert_eq!(mac[4], b[1]);
        assert_eq!(mac[5], b[2]);
    }

    #[test]
    fn test_mac_generation_different_seeds() {
        let mac1 = generate_mac(1);
        let mac2 = generate_mac(2);
        // Same OUI prefix.
        assert_eq!(&mac1[..3], &mac2[..3]);
        // Different generated portion.
        assert_ne!(&mac1[3..], &mac2[3..]);
    }

    // --- TX with chained descriptors ---

    #[test]
    fn test_tx_chained_descriptors() {
        let (transport, handle) = SharedMockTransport::new();
        let mut dev = VirtioNet::new(test_mac(), Some(Box::new(transport)));
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(256);

        // Descriptor 0: virtio_net_hdr (device-readable), chained to 1.
        let hdr = [0u8; VIRTIO_NET_HDR_SIZE];
        mem.write_bytes(BUF_BASE, &hdr);
        write_descriptor(
            &mem,
            0,
            BUF_BASE,
            VIRTIO_NET_HDR_SIZE as u32,
            1, // NEXT flag
            1,
        );

        // Descriptor 1: Ethernet frame (device-readable).
        let frame = b"ethernet_frame_data";
        mem.write_bytes(BUF_BASE + 0x1000, frame);
        write_descriptor(&mem, 1, BUF_BASE + 0x1000, frame.len() as u32, 0, 0);

        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);

        let sent = handle.sent_frames();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], frame);
    }

    // --- Queue notify dispatch ---

    #[test]
    fn test_queue_notify_rx_returns_false() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(256);
        // Notify on RX queue should do nothing.
        assert!(!dev.queue_notify(0, &mut rx_queue, &mem));
    }

    #[test]
    fn test_queue_notify_invalid_queue() {
        let mut dev = VirtioNet::new(test_mac(), None);
        let mem = MockMem::new(0x10000);
        let mut queue = setup_queue(256);
        assert!(!dev.queue_notify(99, &mut queue, &mem));
    }
}
