//! Virtio-vsock device backend (virtio spec v1.2 Section 5.10).
//!
//! Provides a socket transport between guest (AF_VSOCK) and host (TCP).
//! The host side uses non-blocking TCP listeners on localhost for
//! cross-platform compatibility (Windows + macOS + Linux).
//!
//! Queue layout:
//!   Queue 0 (RX): host -> guest (device writes, guest reads)
//!   Queue 1 (TX): guest -> host (guest writes, device reads)
//!   Queue 2 (Event): device events (not used currently)

pub mod connection;
pub mod packet;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use super::mmio::VirtioDeviceBackend;
use super::queue::{GuestMemoryAccessor, Virtqueue};
use connection::{ConnState, VsockConnection};
use packet::{VsockHeader, VSOCK_CID_HOST, VSOCK_HEADER_SIZE, VSOCK_OP_REQUEST};

/// Virtio device ID for vsock (spec Section 5.10).
const VIRTIO_VSOCK_ID: u32 = 19;

/// VIRTIO_F_VERSION_1 — bit 32 (page 1, bit 0).
const VIRTIO_F_VERSION_1_BIT: u32 = 0;

/// Number of queues: RX, TX, Event.
const NUM_QUEUES: usize = 3;

/// Queue index constants.
const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;
// const EVENT_QUEUE: usize = 2; // Not used yet.

/// Maximum queue size.
const QUEUE_MAX_SIZE: u16 = 128;

/// Connection key: (guest_port, host_port).
type ConnKey = (u32, u32);

/// Starting ephemeral port for host-initiated vsock connections.
const EPHEMERAL_PORT_START: u32 = 49152;

/// Virtio-vsock device with TCP host-side bridge.
pub struct VirtioVsock {
    /// Guest CID (typically 3 for the first guest).
    guest_cid: u64,
    /// Active connections keyed by (guest_port, host_port).
    connections: HashMap<ConnKey, VsockConnection>,
    /// TCP listeners on the host side, keyed by vsock port.
    /// Used for host-initiated connections (host TCP → guest vsock).
    listeners: HashMap<u32, TcpListener>,
    /// Outbound TCP targets keyed by vsock port.
    /// Used for guest-initiated connections (guest vsock → host TCP).
    /// When the guest connects to a port in this map, the device makes
    /// an outbound TCP connection to the specified address.
    connect_targets: HashMap<u32, String>,
    /// Accepted TCP streams, keyed by (guest_port, host_port).
    streams: HashMap<ConnKey, TcpStream>,
    /// Pending response/control packets to inject into the RX queue.
    rx_pending: Vec<(VsockHeader, Vec<u8>)>,
    /// Next ephemeral port for host-initiated connections.
    next_host_port: u32,
}

impl VirtioVsock {
    /// Create a new vsock device with the given guest CID.
    pub fn new(guest_cid: u64) -> Self {
        VirtioVsock {
            guest_cid,
            connections: HashMap::new(),
            listeners: HashMap::new(),
            connect_targets: HashMap::new(),
            streams: HashMap::new(),
            rx_pending: Vec::new(),
            next_host_port: EPHEMERAL_PORT_START,
        }
    }

    /// Register a TCP listener on `127.0.0.1:port` for the given host port.
    ///
    /// When a guest connects to this port via AF_VSOCK, the connection
    /// is bridged to an accepted TCP client on this listener.
    pub fn listen(&mut self, port: u32) -> io::Result<()> {
        self.listen_on(port, port as u16)
    }

    /// Register a TCP listener on `127.0.0.1:host_port` for the given vsock port.
    ///
    /// The guest connects to `vsock_port` via AF_VSOCK, and the bridge listens
    /// on `host_port` on the host side. This allows multiple VMs to use
    /// distinct host ports for the same guest vsock port number.
    pub fn listen_on(&mut self, vsock_port: u32, host_port: u16) -> io::Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", host_port))?;
        listener.set_nonblocking(true)?;
        self.listeners.insert(vsock_port, listener);
        Ok(())
    }

    /// Register an outbound TCP target for guest-initiated connections.
    ///
    /// When the guest connects to `vsock_port`, the device makes an outbound
    /// TCP connection to `host_addr` instead of accepting from a listener.
    /// Used for notification channels where the guest initiates the connection
    /// and the host is already listening.
    pub fn connect_to(&mut self, vsock_port: u32, host_addr: String) {
        self.connect_targets.insert(vsock_port, host_addr);
    }

    /// Get the guest CID.
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Process the TX queue: read packets from guest, dispatch them.
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

            // First descriptor: vsock header (device-readable).
            let hdr_desc = &chain[0];
            if (hdr_desc.len as usize) < VSOCK_HEADER_SIZE {
                let _ = queue.add_used(head, 0, mem);
                processed = true;
                continue;
            }

            let hdr = match VsockHeader::read_from(mem, hdr_desc.addr) {
                Ok(h) => h,
                Err(_) => {
                    let _ = queue.add_used(head, 0, mem);
                    processed = true;
                    continue;
                }
            };

            // Read payload from subsequent descriptors.
            let mut payload = Vec::new();
            for desc in &chain[1..] {
                if !desc.is_write() {
                    // Device-readable = payload data from guest.
                    let mut buf = vec![0u8; desc.len as usize];
                    if mem.read_at(desc.addr, &mut buf).is_ok() {
                        payload.extend_from_slice(&buf);
                    }
                }
            }

            self.handle_guest_packet(&hdr, &payload);

            let _ = queue.add_used(head, 0, mem);
            processed = true;
        }

        processed
    }

    /// Handle a packet from the guest.
    fn handle_guest_packet(&mut self, hdr: &VsockHeader, payload: &[u8]) {
        let key = (hdr.src_port, hdr.dst_port);
        if !payload.is_empty() {
            log::trace!(
                "vsock TX: guest→host {} bytes, op={}, key=({},{})",
                payload.len(),
                hdr.op,
                key.0,
                key.1
            );
        }

        if hdr.op == VSOCK_OP_REQUEST {
            self.handle_connect_request(hdr);
            return;
        }

        if let Some(conn) = self.connections.get_mut(&key) {
            let (resp_hdr, fwd_data) = conn.dispatch(hdr, payload);

            // Forward data to host TCP socket.
            // Use retry loop for non-blocking sockets (write_all fails on WouldBlock).
            if let Some(data) = fwd_data {
                if let Some(stream) = self.streams.get_mut(&key) {
                    let mut written = 0;
                    let mut retries = 0;
                    while written < data.len() {
                        match stream.write(&data[written..]) {
                            Ok(n) => written += n,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                retries += 1;
                                if retries > 1000 {
                                    log::warn!(
                                        "vsock write stuck: {}/{} bytes after {} retries, key=({},{})",
                                        written, data.len(), retries, key.0, key.1
                                    );
                                    break;
                                }
                                std::thread::yield_now();
                            }
                            Err(e) => {
                                log::warn!(
                                    "vsock write failed: {}/{} bytes, err={}, key=({},{})",
                                    written, data.len(), e, key.0, key.1
                                );
                                break;
                            }
                        }
                    }
                }
            }

            // Queue response packet (if any) for RX injection.
            if let Some(r) = resp_hdr {
                self.rx_pending.push((r, Vec::new()));
            }

            // Clean up closed connections.
            if conn.state() == ConnState::Closed {
                self.connections.remove(&key);
                self.streams.remove(&key);
            }
        } else {
            // No connection for this port pair -> RST.
            let rst =
                VsockHeader::new_rst(VSOCK_CID_HOST, hdr.dst_port, self.guest_cid, hdr.src_port);
            self.rx_pending.push((rst, Vec::new()));
        }
    }

    /// Handle a guest CONNECTION REQUEST.
    fn handle_connect_request(&mut self, hdr: &VsockHeader) {
        let key = (hdr.src_port, hdr.dst_port);

        // Try outbound connection first (guest-initiated → host TCP target).
        if let Some(addr) = self.connect_targets.get(&hdr.dst_port).cloned() {
            log::debug!("guest-initiated CONNECT: port={} → {}", hdr.dst_port, addr);
            let stream = match TcpStream::connect(&addr) {
                Ok(stream) => {
                    if let Err(e) = stream.set_nonblocking(true) {
                        log::warn!("guest-connect: set_nonblocking failed: {}", e);
                    }
                    if let Err(e) = stream.set_nodelay(true) {
                        log::warn!("guest-connect: set_nodelay failed: {}", e);
                    }
                    log::debug!("TCP connect OK to {}", addr);
                    stream
                }
                Err(ref e) => {
                    log::warn!("TCP connect FAILED to {}: {}", addr, e);
                    let rst = VsockHeader::new_rst(
                        VSOCK_CID_HOST,
                        hdr.dst_port,
                        self.guest_cid,
                        hdr.src_port,
                    );
                    self.rx_pending.push((rst, Vec::new()));
                    return;
                }
            };

            let mut conn =
                VsockConnection::new(VSOCK_CID_HOST, hdr.dst_port, self.guest_cid, hdr.src_port);

            if let Some(resp) = conn.handle_request(hdr) {
                self.rx_pending.push((resp, Vec::new()));
                self.connections.insert(key, conn);
                self.streams.insert(key, stream);
            } else {
                let rst = VsockHeader::new_rst(
                    VSOCK_CID_HOST,
                    hdr.dst_port,
                    self.guest_cid,
                    hdr.src_port,
                );
                self.rx_pending.push((rst, Vec::new()));
            }
            return;
        }

        // Fall back to listener-based connection (host-initiated).
        if !self.listeners.contains_key(&hdr.dst_port) {
            let rst =
                VsockHeader::new_rst(VSOCK_CID_HOST, hdr.dst_port, self.guest_cid, hdr.src_port);
            self.rx_pending.push((rst, Vec::new()));
            return;
        }

        // Try to accept a pending TCP connection on this listener.
        let stream = if let Some(listener) = self.listeners.get(&hdr.dst_port) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = stream.set_nonblocking(true);
                    Some(stream)
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No pending TCP connection yet — still accept the vsock connection.
                    // Data will buffer until a TCP client connects.
                    None
                }
                Err(_) => {
                    let rst = VsockHeader::new_rst(
                        VSOCK_CID_HOST,
                        hdr.dst_port,
                        self.guest_cid,
                        hdr.src_port,
                    );
                    self.rx_pending.push((rst, Vec::new()));
                    return;
                }
            }
        } else {
            None
        };

        // Create and register the connection.
        let mut conn =
            VsockConnection::new(VSOCK_CID_HOST, hdr.dst_port, self.guest_cid, hdr.src_port);

        if let Some(resp) = conn.handle_request(hdr) {
            self.rx_pending.push((resp, Vec::new()));
            self.connections.insert(key, conn);
            if let Some(s) = stream {
                self.streams.insert(key, s);
            }
        } else {
            let rst =
                VsockHeader::new_rst(VSOCK_CID_HOST, hdr.dst_port, self.guest_cid, hdr.src_port);
            self.rx_pending.push((rst, Vec::new()));
        }
    }

    /// Allocate the next ephemeral host port for host-initiated connections.
    fn alloc_host_port(&mut self) -> u32 {
        let port = self.next_host_port;
        self.next_host_port = self.next_host_port.wrapping_add(1);
        if self.next_host_port < EPHEMERAL_PORT_START {
            self.next_host_port = EPHEMERAL_PORT_START;
        }
        port
    }

    /// Poll TCP listeners for pending connections and initiate vsock handshakes.
    ///
    /// When a host TCP client connects to a listener, this method:
    /// 1. Accepts the TCP connection
    /// 2. Allocates an ephemeral host port for the vsock side
    /// 3. Creates a VsockConnection in Connecting state
    /// 4. Generates a REQUEST packet to send to the guest via RX queue
    /// 5. Stores the TCP stream (data is NOT read until Connected)
    fn poll_tcp_listeners(&mut self) {
        let vsock_ports: Vec<u32> = self.listeners.keys().copied().collect();

        for vsock_port in vsock_ports {
            let stream = if let Some(listener) = self.listeners.get(&vsock_port) {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        if let Err(e) = stream.set_nonblocking(true) {
                            log::warn!(
                                "vsock set_nonblocking failed: {} (addr={:?})",
                                e, addr
                            );
                        }
                        if let Err(e) = stream.set_nodelay(true) {
                            log::warn!(
                                "vsock set_nodelay failed: {} (addr={:?})",
                                e, addr
                            );
                        }
                        stream
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(_) => continue,
                }
            } else {
                continue;
            };

            let host_port = self.alloc_host_port();
            let key = (vsock_port, host_port);

            let mut conn =
                VsockConnection::new(VSOCK_CID_HOST, host_port, self.guest_cid, vsock_port);

            if let Some(req) = conn.initiate_connect() {
                log::debug!(
                    "host-initiated CONNECT: vsock_port={}, host_port={}, queuing REQUEST",
                    vsock_port, host_port
                );
                self.rx_pending.push((req, Vec::new()));
                self.connections.insert(key, conn);
                self.streams.insert(key, stream);
            }
        }
    }

    /// Poll TCP streams for incoming data and queue it for RX injection.
    fn poll_tcp_streams(&mut self) {
        // Collect keys first to avoid borrow issues.
        let keys: Vec<ConnKey> = self.streams.keys().copied().collect();

        for key in keys {
            // Skip streams whose vsock connection is still handshaking.
            // TCP data stays in the kernel receive buffer until Connected.
            if let Some(conn) = self.connections.get(&key) {
                if conn.state() != ConnState::Connected {
                    continue;
                }
            }

            let mut buf = [0u8; 65536];
            let data = if let Some(stream) = self.streams.get_mut(&key) {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        // TCP connection closed. Send SHUTDOWN to guest.
                        log::debug!("TCP EOF, key=({},{})", key.0, key.1);
                        if let Some(conn) = self.connections.get(&key) {
                            let hdr = VsockHeader::new_shutdown(
                                conn.local_cid,
                                conn.local_port,
                                conn.peer_cid,
                                conn.peer_port,
                                packet::VSOCK_SHUTDOWN_SEND | packet::VSOCK_SHUTDOWN_RECV,
                            );
                            self.rx_pending.push((hdr, Vec::new()));
                        }
                        self.streams.remove(&key);
                        if let Some(conn) = self.connections.get_mut(&key) {
                            conn.handle_shutdown(
                                packet::VSOCK_SHUTDOWN_SEND | packet::VSOCK_SHUTDOWN_RECV,
                            );
                        }
                        continue;
                    }
                    Ok(n) => {
                        log::trace!("TCP read {} bytes, key=({},{})", n, key.0, key.1);
                        Some(buf[..n].to_vec())
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        None
                    }
                    Err(ref e) => {
                        // I/O error on TCP stream. RST the vsock connection.
                        log::warn!(
                            "vsock TCP read error: {} (raw={:?}), key=({},{})",
                            e, e.raw_os_error(), key.0, key.1
                        );
                        if let Some(conn) = self.connections.get(&key) {
                            let rst = conn.make_rst();
                            self.rx_pending.push((rst, Vec::new()));
                        }
                        self.streams.remove(&key);
                        self.connections.remove(&key);
                        continue;
                    }
                }
            } else {
                continue;
            };

            // Enqueue data from TCP into the connection's TX buffer.
            if let Some(data) = data {
                if let Some(conn) = self.connections.get_mut(&key) {
                    let enqueued = conn.enqueue_tx(&data);
                    if enqueued < data.len() {
                        log::debug!(
                            "vsock enqueue_tx partial: {}/{} bytes, credit={}, key=({},{})",
                            enqueued, data.len(), conn.peer_credit(), key.0, key.1
                        );
                    }
                }
            }
        }
    }

    /// Inject pending packets into the RX queue.
    fn inject_rx(&mut self, rx_queue: &mut Virtqueue, mem: &dyn GuestMemoryAccessor) -> bool {
        let mut injected = false;

        // First: drain connection TX buffers into rx_pending.
        let keys: Vec<ConnKey> = self.connections.keys().copied().collect();
        for key in keys {
            if let Some(conn) = self.connections.get_mut(&key) {
                // Also check for credit updates.
                if conn.needs_credit_update() {
                    let hdr = conn.make_credit_update();
                    conn.clear_credit_update();
                    self.rx_pending.push((hdr, Vec::new()));
                }

                // Drain TX data.
                while let Some((hdr, data)) = conn.drain_tx(4096) {
                    self.rx_pending.push((hdr, data));
                }
            }
        }

        // Inject all pending packets.
        while !self.rx_pending.is_empty() {
            let head = match rx_queue.pop_avail(mem) {
                Ok(Some(h)) => h,
                _ => {
                    log::debug!(
                        "vsock inject_rx: no available RX buffers, {} packets pending",
                        self.rx_pending.len()
                    );
                    break;
                }
            };

            let chain = match rx_queue.read_desc_chain(head, mem) {
                Ok(c) => c,
                Err(_) => {
                    let _ = rx_queue.add_used(head, 0, mem);
                    injected = true;
                    continue;
                }
            };

            let (hdr, payload) = self.rx_pending.remove(0);

            // Write header + payload to device-writable descriptors.
            let total_data = hdr
                .to_bytes()
                .to_vec()
                .into_iter()
                .chain(payload.into_iter())
                .collect::<Vec<u8>>();

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

impl VirtioDeviceBackend for VirtioVsock {
    fn device_id(&self) -> u32 {
        VIRTIO_VSOCK_ID
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            1 => 1 << VIRTIO_F_VERSION_1_BIT,
            _ => 0,
        }
    }

    fn read_config(&self, offset: u64) -> u32 {
        // Config space: guest_cid (u64 at offset 0).
        match offset {
            0 => self.guest_cid as u32,
            4 => (self.guest_cid >> 32) as u32,
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
        // Accept new TCP connections and initiate vsock handshakes.
        self.poll_tcp_listeners();

        // Poll TCP streams for incoming data.
        let pending_before = self.rx_pending.len();
        self.poll_tcp_streams();
        let new_data = self.rx_pending.len() - pending_before;
        if new_data > 0 {
            log::trace!(
                "vsock poll: TCP produced {} new packets, total pending={}",
                new_data,
                self.rx_pending.len()
            );
        }

        // Inject any pending data into the RX queue.
        if queues.len() > RX_QUEUE {
            let injected = self.inject_rx(&mut queues[RX_QUEUE], mem);
            if injected {
                log::debug!(
                    "vsock poll: injected data into RX queue, conns={}",
                    self.connections.len()
                );
            }
            injected
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::error::Result;
    use super::super::queue::Virtqueue;
    use super::packet::VSOCK_OP_RST;
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
                return Err(super::super::super::super::error::WkrunError::Memory(
                    "out of bounds".into(),
                ));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            let a = addr as usize;
            let mut mem = self.data.borrow_mut();
            if a + data.len() > mem.len() {
                return Err(super::super::super::super::error::WkrunError::Memory(
                    "out of bounds".into(),
                ));
            }
            mem[a..a + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    // Memory layout for tests:
    //   DESC_TABLE at 0x0000 (128 entries * 16 bytes = 2048)
    //   AVAIL_RING at 0x0800
    //   USED_RING  at 0x1000
    //   BUFFERS    at 0x2000+
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

    // --- Device identity ---

    #[test]
    fn test_device_id() {
        let dev = VirtioVsock::new(3);
        assert_eq!(dev.device_id(), 19);
    }

    #[test]
    fn test_num_queues() {
        let dev = VirtioVsock::new(3);
        assert_eq!(dev.num_queues(), 3);
    }

    #[test]
    fn test_queue_max_size() {
        let dev = VirtioVsock::new(3);
        assert_eq!(dev.queue_max_size(0), 128);
        assert_eq!(dev.queue_max_size(1), 128);
        assert_eq!(dev.queue_max_size(2), 128);
    }

    #[test]
    fn test_version_1_feature() {
        let dev = VirtioVsock::new(3);
        assert_eq!(dev.device_features(0), 0);
        assert_eq!(dev.device_features(1), 1); // VIRTIO_F_VERSION_1
    }

    // --- Config space ---

    #[test]
    fn test_config_guest_cid() {
        let dev = VirtioVsock::new(3);
        assert_eq!(dev.read_config(0), 3); // Low 32 bits.
        assert_eq!(dev.read_config(4), 0); // High 32 bits.
    }

    #[test]
    fn test_config_large_cid() {
        let dev = VirtioVsock::new(0x1_0000_0003);
        assert_eq!(dev.read_config(0), 3);
        assert_eq!(dev.read_config(4), 1);
    }

    // --- TX queue: REQUEST handling ---

    #[test]
    fn test_tx_request_no_listener_sends_rst() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Write a REQUEST header to guest memory.
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());

        // Set up descriptor: header only.
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);

        // Should have a RST pending in rx_pending.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, VSOCK_OP_RST);
    }

    #[test]
    fn test_tx_request_with_listener_sends_response() {
        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap(); // Port 0 = OS-assigned.
                                // Get the actual port.
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        // Re-register with correct port.
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: port,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Should have a RESPONSE pending.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, packet::VSOCK_OP_RESPONSE);
        assert_eq!(dev.connection_count(), 1);
    }

    // --- TX queue: RW handling ---

    #[test]
    fn test_tx_rw_forwards_data() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Establish connection directly.
        let req_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        dev.handle_guest_packet(&req_hdr, &[]);
        // The REQUEST without a listener sends RST, so let's set up directly.
        dev.rx_pending.clear();

        // Manually create a connected state.
        let mut conn = VsockConnection::new(VSOCK_CID_HOST, 2695, 3, 5000);
        conn.handle_request(&req_hdr);
        dev.connections.insert((5000, 2695), conn);

        // Now send an RW packet.
        let rw_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 5,
            type_: 1,
            op: packet::VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &rw_hdr.to_bytes());
        mem.write_bytes(BUF_BASE + VSOCK_HEADER_SIZE as u64, b"hello");

        // Two descriptors: header (readable) + payload (readable).
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 1, 1); // NEXT
        write_descriptor(&mem, 1, BUF_BASE + VSOCK_HEADER_SIZE as u64, 5, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);

        // Data was forwarded (no stream connected, so just the connection absorbed it).
        let conn = dev.connections.get(&(5000, 2695)).unwrap();
        assert_eq!(conn.fwd_cnt(), 5);
    }

    // --- TX queue: SHUTDOWN handling ---

    #[test]
    fn test_tx_shutdown_closes_connection() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Set up a connected connection.
        let req_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let mut conn = VsockConnection::new(VSOCK_CID_HOST, 2695, 3, 5000);
        conn.handle_request(&req_hdr);
        dev.connections.insert((5000, 2695), conn);

        // Send SHUTDOWN with both flags.
        let shut_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: packet::VSOCK_OP_SHUTDOWN,
            flags: packet::VSOCK_SHUTDOWN_SEND | packet::VSOCK_SHUTDOWN_RECV,
            buf_alloc: 0,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &shut_hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Connection should be removed.
        assert_eq!(dev.connection_count(), 0);
    }

    // --- TX queue: RST for unknown connection ---

    #[test]
    fn test_tx_rw_to_unknown_port_sends_rst() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let rw_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 9999,
            dst_port: 8888,
            len: 0,
            type_: 1,
            op: packet::VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &rw_hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, VSOCK_OP_RST);
    }

    // --- RX queue: inject pending ---

    #[test]
    fn test_inject_rx_writes_header_to_queue() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(128);

        // Set up an RX buffer (device-writable).
        write_descriptor(&mem, 0, BUF_BASE, 256, 2, 0); // WRITE flag = 2
        push_avail(&mem, 0, 0);

        // Queue a RESPONSE packet.
        let resp = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        dev.rx_pending.push((resp, Vec::new()));

        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(injected);

        // Read back the header from guest memory.
        let written = mem.read_bytes(BUF_BASE, VSOCK_HEADER_SIZE);
        let read_hdr = VsockHeader::from_bytes(&written.try_into().unwrap());
        assert_eq!(read_hdr.op, packet::VSOCK_OP_RESPONSE);
        assert_eq!(read_hdr.src_cid, 2);
        assert_eq!(read_hdr.dst_cid, 3);
    }

    #[test]
    fn test_inject_rx_with_payload() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(128);

        // RX buffer: 256 bytes device-writable.
        write_descriptor(&mem, 0, BUF_BASE, 256, 2, 0);
        push_avail(&mem, 0, 0);

        let rw = VsockHeader::new_rw(2, 2695, 3, 5000, 5, 65536, 0);
        dev.rx_pending.push((rw, b"hello".to_vec()));

        dev.inject_rx(&mut rx_queue, &mem);

        // Check header.
        let hdr_bytes = mem.read_bytes(BUF_BASE, VSOCK_HEADER_SIZE);
        let hdr = VsockHeader::from_bytes(&hdr_bytes.try_into().unwrap());
        assert_eq!(hdr.op, packet::VSOCK_OP_RW);
        assert_eq!(hdr.len, 5);

        // Check payload follows header.
        let payload = mem.read_bytes(BUF_BASE + VSOCK_HEADER_SIZE as u64, 5);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn test_inject_rx_no_available_buffers() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut rx_queue = setup_queue(128);
        // Don't push any available buffers.

        let resp = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        dev.rx_pending.push((resp, Vec::new()));

        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(!injected);

        // Packet should still be pending.
        assert_eq!(dev.rx_pending.len(), 1);
    }

    // --- Poll default ---

    #[test]
    fn test_poll_no_streams_no_pending() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut queues = vec![
            setup_queue(128), // RX
            setup_queue(128), // TX
            setup_queue(128), // Event
        ];

        let raised = dev.poll(&mut queues, &mem);
        assert!(!raised);
    }

    // --- Connection lifecycle through TX + RX ---

    #[test]
    fn test_connection_lifecycle() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);

        // Manually create connection to test data flow without TCP.
        let req_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let mut conn = VsockConnection::new(VSOCK_CID_HOST, 2695, 3, 5000);
        conn.handle_request(&req_hdr);
        dev.connections.insert((5000, 2695), conn);

        // Enqueue some host->guest data.
        dev.connections
            .get_mut(&(5000, 2695))
            .unwrap()
            .enqueue_tx(b"response data");

        // Set up RX buffer.
        let rx_buf = BUF_BASE + 0x2000;
        write_descriptor(&mem, 0, rx_buf, 256, 2, 0); // WRITE
        push_avail(&mem, 0, 0);

        let mut rx_queue = setup_queue(128);
        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(injected);

        // Verify the injected RW packet.
        let hdr_bytes = mem.read_bytes(rx_buf, VSOCK_HEADER_SIZE);
        let hdr = VsockHeader::from_bytes(&hdr_bytes.try_into().unwrap());
        assert_eq!(hdr.op, packet::VSOCK_OP_RW);
        assert_eq!(hdr.len, 13);

        let payload = mem.read_bytes(rx_buf + VSOCK_HEADER_SIZE as u64, 13);
        assert_eq!(payload, b"response data");
    }

    // --- Multiple connections ---

    #[test]
    fn test_multiple_connections() {
        let mut dev = VirtioVsock::new(3);

        let req1 = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let req2 = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5001,
            dst_port: 2696,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };

        let mut c1 = VsockConnection::new(VSOCK_CID_HOST, 2695, 3, 5000);
        c1.handle_request(&req1);
        let mut c2 = VsockConnection::new(VSOCK_CID_HOST, 2696, 3, 5001);
        c2.handle_request(&req2);

        dev.connections.insert((5000, 2695), c1);
        dev.connections.insert((5001, 2696), c2);

        assert_eq!(dev.connection_count(), 2);
    }

    // --- Short descriptor chain ---

    #[test]
    fn test_tx_short_header_skipped() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Descriptor with only 10 bytes (< 44 byte header).
        write_descriptor(&mem, 0, BUF_BASE, 10, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed); // Processed (skipped) the entry.
        assert!(dev.rx_pending.is_empty()); // No response generated.
    }

    // --- Empty chain ---

    #[test]
    fn test_tx_empty_chain_skipped() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Descriptor with 0 length.
        write_descriptor(&mem, 0, BUF_BASE, 0, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.process_tx(&mut tx_queue, &mem);
        assert!(processed);
    }

    // --- Credit update flow ---

    #[test]
    fn test_credit_update_injected() {
        let mut dev = VirtioVsock::new(3);
        let mem = MockMem::new(0x10000);

        let req = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let mut conn = VsockConnection::new(VSOCK_CID_HOST, 2695, 3, 5000);
        conn.handle_request(&req);
        conn.handle_credit_request();
        dev.connections.insert((5000, 2695), conn);

        // RX buffer.
        let rx_buf = BUF_BASE + 0x2000;
        write_descriptor(&mem, 0, rx_buf, 256, 2, 0);
        push_avail(&mem, 0, 0);

        let mut rx_queue = setup_queue(128);
        let injected = dev.inject_rx(&mut rx_queue, &mem);
        assert!(injected);

        let hdr_bytes = mem.read_bytes(rx_buf, VSOCK_HEADER_SIZE);
        let hdr = VsockHeader::from_bytes(&hdr_bytes.try_into().unwrap());
        assert_eq!(hdr.op, packet::VSOCK_OP_CREDIT_UPDATE);
    }

    // --- Listen and connect with TCP ---

    #[test]
    fn test_listen_creates_listener() {
        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap(); // Port 0 = OS-assigned.
        assert_eq!(dev.listeners.len(), 1);
    }

    #[test]
    fn test_listen_on_different_host_port() {
        let mut dev = VirtioVsock::new(3);
        // vsock port 2695, host TCP port 0 (OS-assigned)
        dev.listen_on(2695, 0).unwrap();
        assert_eq!(dev.listeners.len(), 1);
        // Listener is keyed by vsock port, not host port
        assert!(dev.listeners.contains_key(&2695));
        // The actual TCP port may differ from the vsock port
        let actual_port = dev
            .listeners
            .get(&2695)
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_ne!(actual_port, 2695); // OS assigned a different port
    }

    #[test]
    fn test_listen_on_two_vsock_ports_different_host_ports() {
        let mut dev = VirtioVsock::new(3);
        dev.listen_on(2695, 0).unwrap();
        dev.listen_on(2696, 0).unwrap();
        assert_eq!(dev.listeners.len(), 2);
        // Each vsock port has its own listener
        let port1 = dev
            .listeners
            .get(&2695)
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let port2 = dev
            .listeners
            .get(&2696)
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_listen_with_tcp_connect() {
        use std::net::TcpStream;

        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        // Re-register with actual port.
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Connect a TCP client before the guest sends REQUEST.
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        // Brief delay for the accept backlog to propagate.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: port,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Should have RESPONSE and a TCP stream.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, packet::VSOCK_OP_RESPONSE);
        assert_eq!(dev.connection_count(), 1);
        assert_eq!(dev.streams.len(), 1);
    }

    // --- Poll with TCP data ---

    #[test]
    fn test_poll_reads_tcp_data() {
        use std::io::Write as IoWrite;
        use std::net::TcpStream;

        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Connect TCP client.
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Establish vsock connection.
        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: port,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);
        dev.process_tx(&mut tx_queue, &mem);
        dev.rx_pending.clear();

        // Send data from TCP client to be picked up by poll.
        client.write_all(b"tcp data").unwrap();
        client.flush().unwrap();

        // Small delay to allow TCP data to arrive.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Poll should read TCP data and queue it.
        let mut queues = vec![
            setup_queue(128), // RX
            setup_queue(128), // TX
            setup_queue(128), // Event
        ];

        // Set up an RX buffer.
        let rx_buf = BUF_BASE + 0x4000;
        // Use separate addresses for the RX queue to avoid overlap.
        let rx_desc = 0x8000u64;
        let rx_avail = 0x8800u64;
        let rx_used = 0x9000u64;
        queues[0].set_desc_table(rx_desc);
        queues[0].set_avail_ring(rx_avail);
        queues[0].set_used_ring(rx_used);

        // Write descriptor for RX.
        mem.write_u64_at(rx_desc, rx_buf);
        mem.write_u32_at(rx_desc + 8, 256);
        mem.write_u16_at(rx_desc + 12, 2); // WRITE
        mem.write_u16_at(rx_desc + 14, 0);
        // Push to avail ring.
        mem.write_u16_at(rx_avail + 4, 0); // ring[0] = desc 0
        mem.write_u16_at(rx_avail + 2, 1); // avail idx = 1

        let raised = dev.poll(&mut queues, &mem);
        assert!(raised);

        // Check that data was injected.
        let hdr_bytes = mem.read_bytes(rx_buf, VSOCK_HEADER_SIZE);
        let rx_hdr = VsockHeader::from_bytes(&hdr_bytes.try_into().unwrap());
        assert_eq!(rx_hdr.op, packet::VSOCK_OP_RW);
        assert_eq!(rx_hdr.len, 8);

        let payload = mem.read_bytes(rx_buf + VSOCK_HEADER_SIZE as u64, 8);
        assert_eq!(payload, b"tcp data");
    }

    // --- Guest-initiated outbound connection ---

    #[test]
    fn test_connect_to_registers_target() {
        let mut dev = VirtioVsock::new(3);
        dev.connect_to(2696, "127.0.0.1:9999".to_string());
        assert_eq!(dev.connect_targets.len(), 1);
        assert!(dev.connect_targets.contains_key(&2696));
    }

    #[test]
    fn test_connect_to_outbound_success() {
        // Set up a host-side TCP listener to receive the outbound connection.
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host_listener.local_addr().unwrap().port();

        let mut dev = VirtioVsock::new(3);
        dev.connect_to(2696, format!("127.0.0.1:{}", host_port));

        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        // Guest sends CONNECT to vsock port 2696.
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2696,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Should get RESPONSE (not RST) and have a connection + stream.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, packet::VSOCK_OP_RESPONSE);
        assert_eq!(dev.connection_count(), 1);
        assert_eq!(dev.streams.len(), 1);

        // Host listener should have received the connection.
        host_listener.set_nonblocking(true).unwrap();
        let accepted = host_listener.accept();
        assert!(accepted.is_ok(), "Host should have received TCP connection");
    }

    #[test]
    fn test_connect_to_unreachable_sends_rst() {
        let mut dev = VirtioVsock::new(3);
        // Port 1 is not listening — connection will fail.
        dev.connect_to(2696, "127.0.0.1:1".to_string());

        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2696,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Should get RST because target is unreachable.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, VSOCK_OP_RST);
        assert_eq!(dev.connection_count(), 0);
    }

    #[test]
    fn test_connect_to_preferred_over_listener() {
        // If both connect_target and listener exist for same port,
        // connect_target should be used (checked first).
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host_listener.local_addr().unwrap().port();

        let mut dev = VirtioVsock::new(3);
        dev.connect_to(2696, format!("127.0.0.1:{}", host_port));
        dev.listen_on(2696, 0).unwrap(); // Also add a listener on same vsock port.

        let mem = MockMem::new(0x10000);
        let mut tx_queue = setup_queue(128);

        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2696,
            len: 0,
            type_: 1,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        mem.write_bytes(BUF_BASE, &hdr.to_bytes());
        write_descriptor(&mem, 0, BUF_BASE, VSOCK_HEADER_SIZE as u32, 0, 0);
        push_avail(&mem, 0, 0);

        dev.process_tx(&mut tx_queue, &mem);

        // Should get RESPONSE via outbound connection.
        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, packet::VSOCK_OP_RESPONSE);
        assert_eq!(dev.connection_count(), 1);
        assert_eq!(dev.streams.len(), 1);
    }

    // --- Host-initiated connections (poll_tcp_listeners) ---

    #[test]
    fn test_poll_tcp_listeners_accepts_and_sends_request() {
        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Host TCP client connects BEFORE any guest action.
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // poll_tcp_listeners should accept and generate a REQUEST.
        dev.poll_tcp_listeners();

        assert_eq!(dev.rx_pending.len(), 1);
        assert_eq!(dev.rx_pending[0].0.op, VSOCK_OP_REQUEST);
        assert_eq!(dev.rx_pending[0].0.src_cid, VSOCK_CID_HOST);
        assert_eq!(dev.rx_pending[0].0.dst_cid, 3); // guest CID
        assert_eq!(dev.rx_pending[0].0.dst_port, port); // guest vsock port
        assert!(dev.rx_pending[0].0.src_port >= EPHEMERAL_PORT_START);
        assert_eq!(dev.connection_count(), 1);
        assert_eq!(dev.streams.len(), 1);
    }

    #[test]
    fn test_poll_tcp_listeners_no_pending_is_noop() {
        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();

        // No TCP client connected.
        dev.poll_tcp_listeners();

        assert!(dev.rx_pending.is_empty());
        assert_eq!(dev.connection_count(), 0);
    }

    #[test]
    fn test_host_initiated_full_lifecycle() {
        use std::io::Write as IoWrite;

        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Step 1: Host TCP client connects.
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Step 2: VMM accepts and sends REQUEST to guest.
        dev.poll_tcp_listeners();
        assert_eq!(dev.rx_pending.len(), 1);
        let req = &dev.rx_pending[0].0;
        assert_eq!(req.op, VSOCK_OP_REQUEST);
        let host_ephemeral = req.src_port;
        let key = (port, host_ephemeral);
        dev.rx_pending.clear();

        // Step 3: Guest sends RESPONSE (simulated via handle_guest_packet).
        let resp = VsockHeader {
            src_cid: 3,
            dst_cid: VSOCK_CID_HOST,
            src_port: port,
            dst_port: host_ephemeral,
            len: 0,
            type_: 1,
            op: packet::VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        dev.handle_guest_packet(&resp, &[]);

        // Connection should now be Connected.
        assert_eq!(
            dev.connections.get(&key).unwrap().state(),
            ConnState::Connected
        );

        // Step 4: Host sends data via TCP -> forwarded to guest via vsock.
        client.write_all(b"hello from host").unwrap();
        client.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        dev.poll_tcp_streams();
        let conn = dev.connections.get(&key).unwrap();
        assert!(conn.tx_buf_len() > 0);
    }

    #[test]
    fn test_host_initiated_skips_data_during_handshake() {
        use std::io::Write as IoWrite;

        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Host connects and sends data before handshake completes.
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        dev.poll_tcp_listeners();
        let host_ephemeral = dev.rx_pending[0].0.src_port;
        let key = (port, host_ephemeral);
        dev.rx_pending.clear();

        // Connection is in Connecting state.
        assert_eq!(
            dev.connections.get(&key).unwrap().state(),
            ConnState::Connecting
        );

        // Host sends data while still Connecting.
        client.write_all(b"premature data").unwrap();
        client.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // poll_tcp_streams should SKIP this stream (not Connected yet).
        dev.poll_tcp_streams();
        // Data stays in kernel buffer, connection tx_buf is empty.
        assert_eq!(dev.connections.get(&key).unwrap().tx_buf_len(), 0);

        // Now complete the handshake.
        let resp = VsockHeader {
            src_cid: 3,
            dst_cid: VSOCK_CID_HOST,
            src_port: port,
            dst_port: host_ephemeral,
            len: 0,
            type_: 1,
            op: packet::VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        dev.handle_guest_packet(&resp, &[]);
        assert_eq!(
            dev.connections.get(&key).unwrap().state(),
            ConnState::Connected
        );

        // NOW poll_tcp_streams reads the data.
        dev.poll_tcp_streams();
        assert!(dev.connections.get(&key).unwrap().tx_buf_len() > 0);
    }

    #[test]
    fn test_ephemeral_port_allocation() {
        let mut dev = VirtioVsock::new(3);
        let p1 = dev.alloc_host_port();
        let p2 = dev.alloc_host_port();
        let p3 = dev.alloc_host_port();
        assert_eq!(p1, EPHEMERAL_PORT_START);
        assert_eq!(p2, EPHEMERAL_PORT_START + 1);
        assert_eq!(p3, EPHEMERAL_PORT_START + 2);
    }

    #[test]
    fn test_host_initiated_guest_data_to_host_tcp() {
        use std::io::Read as IoRead;

        let mut dev = VirtioVsock::new(3);
        dev.listen(0).unwrap();
        let port = dev
            .listeners
            .values()
            .next()
            .unwrap()
            .local_addr()
            .unwrap()
            .port() as u32;
        let listener = dev.listeners.remove(&0).unwrap();
        dev.listeners.insert(port, listener);

        // Host connects.
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_nonblocking(true).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Accept + REQUEST.
        dev.poll_tcp_listeners();
        let host_ephemeral = dev.rx_pending[0].0.src_port;
        let key = (port, host_ephemeral);
        dev.rx_pending.clear();

        // Guest RESPONSE.
        let resp = VsockHeader {
            src_cid: 3,
            dst_cid: VSOCK_CID_HOST,
            src_port: port,
            dst_port: host_ephemeral,
            len: 0,
            type_: 1,
            op: packet::VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        dev.handle_guest_packet(&resp, &[]);

        // Guest sends data (RW) → should be forwarded to host TCP stream.
        let rw_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: VSOCK_CID_HOST,
            src_port: port,
            dst_port: host_ephemeral,
            len: 11,
            type_: 1,
            op: packet::VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        dev.handle_guest_packet(&rw_hdr, b"hello guest");

        // Read from TCP client.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = [0u8; 128];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello guest");
    }
}
