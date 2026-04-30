//! Vsock connection state machine with credit-based flow control.
//!
//! Each vsock connection tracks the state of a bidirectional byte stream
//! between a guest port and a host port. Flow control follows the virtio
//! spec (Section 5.10.6.3): each side advertises buffer space (buf_alloc)
//! and reports bytes consumed (fwd_cnt). The peer computes available
//! send credit as: `peer_buf_alloc - (tx_cnt - peer_fwd_cnt)`.

use super::packet::{
    VsockHeader, VSOCK_OP_CREDIT_REQUEST, VSOCK_OP_CREDIT_UPDATE, VSOCK_OP_REQUEST,
    VSOCK_OP_RESPONSE, VSOCK_OP_RST, VSOCK_OP_RW, VSOCK_OP_SHUTDOWN, VSOCK_SHUTDOWN_RECV,
    VSOCK_SHUTDOWN_SEND,
};

/// Default buffer space we advertise to the peer (64 KiB).
const DEFAULT_BUF_ALLOC: u32 = 65536;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// No connection established.
    Idle,
    /// REQUEST sent/received, waiting for RESPONSE.
    Connecting,
    /// Data transfer active.
    Connected,
    /// SHUTDOWN sent or received; draining.
    Closing,
    /// Connection fully closed.
    Closed,
}

/// A single vsock connection between a guest port and a host port.
pub struct VsockConnection {
    state: ConnState,
    pub local_cid: u64,
    pub local_port: u32,
    pub peer_cid: u64,
    pub peer_port: u32,
    // Our credit: how much buffer space we offer to the peer.
    buf_alloc: u32,
    // Bytes we have consumed (forwarded to host TCP socket).
    fwd_cnt: u32,
    // Peer's advertised buffer space.
    peer_buf_alloc: u32,
    // Peer's forwarded count (bytes peer has consumed).
    peer_fwd_cnt: u32,
    // Total bytes we have sent to the peer (to compute remaining credit).
    tx_cnt: u32,
    // Host-to-guest transmit buffer.
    tx_buf: Vec<u8>,
    // Whether the peer has requested a credit update.
    credit_update_needed: bool,
}

impl VsockConnection {
    /// Create a new connection in the Idle state.
    pub fn new(local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32) -> Self {
        VsockConnection {
            state: ConnState::Idle,
            local_cid,
            local_port,
            peer_cid,
            peer_port,
            buf_alloc: DEFAULT_BUF_ALLOC,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            tx_cnt: 0,
            tx_buf: Vec::new(),
            credit_update_needed: false,
        }
    }

    /// Current connection state.
    pub fn state(&self) -> ConnState {
        self.state
    }

    /// Our advertised buffer space.
    pub fn buf_alloc(&self) -> u32 {
        self.buf_alloc
    }

    /// Bytes we have consumed (forwarded to host side).
    pub fn fwd_cnt(&self) -> u32 {
        self.fwd_cnt
    }

    /// Total bytes we have sent to the peer.
    pub fn tx_cnt(&self) -> u32 {
        self.tx_cnt
    }

    /// Bytes buffered for host-to-guest transmission.
    pub fn tx_buf_len(&self) -> usize {
        self.tx_buf.len()
    }

    /// Available credit to send data to the peer.
    ///
    /// `peer_buf_alloc - (tx_cnt - peer_fwd_cnt)` per spec 5.10.6.3.
    pub fn peer_credit(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }

    /// Whether we need to send a credit update to the peer.
    pub fn needs_credit_update(&self) -> bool {
        self.credit_update_needed
    }

    /// Clear the credit update flag.
    pub fn clear_credit_update(&mut self) {
        self.credit_update_needed = false;
    }

    /// Initiate a host-to-guest connection (host-initiated).
    ///
    /// Transitions Idle -> Connecting and returns a REQUEST header to send
    /// to the guest via the RX queue. Returns None if not in Idle state.
    pub fn initiate_connect(&mut self) -> Option<VsockHeader> {
        if self.state != ConnState::Idle {
            return None;
        }
        self.state = ConnState::Connecting;
        Some(VsockHeader::new_request(
            self.local_cid,
            self.local_port,
            self.peer_cid,
            self.peer_port,
            self.buf_alloc,
            self.fwd_cnt,
        ))
    }

    /// Handle a REQUEST from the guest.
    ///
    /// Transitions Idle -> Connected and returns a RESPONSE header.
    /// Returns None if the connection is not in Idle state (sends RST instead).
    pub fn handle_request(&mut self, hdr: &VsockHeader) -> Option<VsockHeader> {
        if self.state != ConnState::Idle {
            return None;
        }

        // Record peer's credit info from the REQUEST.
        self.peer_buf_alloc = hdr.buf_alloc;
        self.peer_fwd_cnt = hdr.fwd_cnt;
        self.state = ConnState::Connected;
        log::debug!(
            "vsock conn ({},{}) → Connected (guest REQUEST, buf_alloc={})",
            self.local_port,
            self.peer_port,
            hdr.buf_alloc
        );

        Some(VsockHeader::new_response(
            self.local_cid,
            self.local_port,
            self.peer_cid,
            self.peer_port,
            self.buf_alloc,
            self.fwd_cnt,
        ))
    }

    /// Handle an RW (data) packet from the guest.
    ///
    /// Returns the payload data to forward to the host TCP socket.
    /// Updates fwd_cnt. Returns None if not connected.
    pub fn handle_rw(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if self.state != ConnState::Connected {
            return None;
        }

        self.fwd_cnt = self.fwd_cnt.wrapping_add(payload.len() as u32);

        // Check if we should proactively send a credit update.
        // If the peer's remaining view of our buffer is below half, signal update.
        let peer_view = self.buf_alloc.saturating_sub(
            self.fwd_cnt
                .wrapping_sub(/* they don't know fwd_cnt yet */ 0),
        );
        if peer_view < self.buf_alloc / 2 {
            self.credit_update_needed = true;
        }

        Some(payload.to_vec())
    }

    /// Handle a SHUTDOWN from the guest.
    pub fn handle_shutdown(&mut self, flags: u32) {
        let old_state = self.state;
        match self.state {
            ConnState::Connected => {
                if flags & (VSOCK_SHUTDOWN_SEND | VSOCK_SHUTDOWN_RECV)
                    == (VSOCK_SHUTDOWN_SEND | VSOCK_SHUTDOWN_RECV)
                {
                    self.state = ConnState::Closed;
                } else {
                    self.state = ConnState::Closing;
                }
            }
            ConnState::Closing => {
                self.state = ConnState::Closed;
            }
            _ => {}
        }
        if self.state != old_state {
            log::debug!(
                "vsock conn ({},{}) → {:?} (SHUTDOWN flags=0x{:x})",
                self.local_port,
                self.peer_port,
                self.state,
                flags
            );
        }
    }

    /// Handle a RST from the guest.
    pub fn handle_rst(&mut self) {
        log::debug!(
            "vsock conn ({},{}) → Closed (RST)",
            self.local_port,
            self.peer_port
        );
        self.state = ConnState::Closed;
    }

    /// Handle a credit update from the guest.
    pub fn handle_credit_update(&mut self, hdr: &VsockHeader) {
        self.peer_buf_alloc = hdr.buf_alloc;
        self.peer_fwd_cnt = hdr.fwd_cnt;
    }

    /// Handle a credit request from the guest.
    pub fn handle_credit_request(&mut self) {
        self.credit_update_needed = true;
    }

    /// Enqueue data from the host for transmission to the guest.
    ///
    /// Returns the number of bytes actually enqueued (limited by peer credit).
    pub fn enqueue_tx(&mut self, data: &[u8]) -> usize {
        if self.state != ConnState::Connected {
            return 0;
        }

        let credit = self.peer_credit() as usize;
        let to_send = data.len().min(credit);
        if to_send > 0 {
            self.tx_buf.extend_from_slice(&data[..to_send]);
        }
        to_send
    }

    /// Drain pending host-to-guest data, limited by available credit.
    ///
    /// Returns data to be placed in an RX virtqueue buffer, along with
    /// the header to prepend.
    pub fn drain_tx(&mut self, max_payload: usize) -> Option<(VsockHeader, Vec<u8>)> {
        if self.tx_buf.is_empty() {
            return None;
        }

        let send_len = self.tx_buf.len().min(max_payload);
        let data: Vec<u8> = self.tx_buf.drain(..send_len).collect();

        self.tx_cnt = self.tx_cnt.wrapping_add(data.len() as u32);

        let hdr = VsockHeader::new_rw(
            self.local_cid,
            self.local_port,
            self.peer_cid,
            self.peer_port,
            data.len() as u32,
            self.buf_alloc,
            self.fwd_cnt,
        );

        Some((hdr, data))
    }

    /// Build a credit update header for this connection.
    pub fn make_credit_update(&self) -> VsockHeader {
        VsockHeader::new_credit_update(
            self.local_cid,
            self.local_port,
            self.peer_cid,
            self.peer_port,
            self.buf_alloc,
            self.fwd_cnt,
        )
    }

    /// Build a RST header for this connection.
    pub fn make_rst(&self) -> VsockHeader {
        VsockHeader::new_rst(
            self.local_cid,
            self.local_port,
            self.peer_cid,
            self.peer_port,
        )
    }

    /// Dispatch a packet by operation code.
    ///
    /// Returns a response header to send back (if any), and optional
    /// payload data to forward to the host side.
    pub fn dispatch(
        &mut self,
        hdr: &VsockHeader,
        payload: &[u8],
    ) -> (Option<VsockHeader>, Option<Vec<u8>>) {
        match hdr.op {
            VSOCK_OP_REQUEST => {
                let resp = self.handle_request(hdr);
                if resp.is_none() {
                    // Already connected or invalid state -> RST.
                    return (Some(self.make_rst()), None);
                }
                (resp, None)
            }
            VSOCK_OP_RW => {
                let data = self.handle_rw(payload);
                let credit_hdr = if self.credit_update_needed {
                    self.credit_update_needed = false;
                    Some(self.make_credit_update())
                } else {
                    None
                };
                (credit_hdr, data)
            }
            VSOCK_OP_SHUTDOWN => {
                self.handle_shutdown(hdr.flags);
                (None, None)
            }
            VSOCK_OP_RST => {
                self.handle_rst();
                (None, None)
            }
            VSOCK_OP_RESPONSE => {
                // Guest accepted our connection (host-initiated connect).
                if self.state == ConnState::Connecting {
                    self.peer_buf_alloc = hdr.buf_alloc;
                    self.peer_fwd_cnt = hdr.fwd_cnt;
                    self.state = ConnState::Connected;
                    log::debug!(
                        "vsock conn ({},{}) → Connected (guest RESPONSE, buf_alloc={})",
                        self.local_port,
                        self.peer_port,
                        hdr.buf_alloc
                    );
                }
                (None, None)
            }
            VSOCK_OP_CREDIT_UPDATE => {
                self.handle_credit_update(hdr);
                (None, None)
            }
            VSOCK_OP_CREDIT_REQUEST => {
                self.handle_credit_request();
                let update = self.make_credit_update();
                self.credit_update_needed = false;
                (Some(update), None)
            }
            _ => {
                // Unknown op -> RST.
                (Some(self.make_rst()), None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guest_conn() -> VsockConnection {
        // local = host (CID 2), peer = guest (CID 3)
        VsockConnection::new(2, 2695, 3, 5000)
    }

    fn make_request_hdr() -> VsockHeader {
        VsockHeader {
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
        }
    }

    // --- State transitions ---

    #[test]
    fn test_new_connection_is_idle() {
        let conn = guest_conn();
        assert_eq!(conn.state(), ConnState::Idle);
    }

    #[test]
    fn test_handle_request_transitions_to_connected() {
        let mut conn = guest_conn();
        let hdr = make_request_hdr();
        let resp = conn.handle_request(&hdr);
        assert!(resp.is_some());
        assert_eq!(conn.state(), ConnState::Connected);

        let r = resp.unwrap();
        assert_eq!(r.op, VSOCK_OP_RESPONSE);
        assert_eq!(r.src_cid, 2);
        assert_eq!(r.dst_cid, 3);
        assert_eq!(r.buf_alloc, DEFAULT_BUF_ALLOC);
    }

    // --- Host-initiated connection ---

    #[test]
    fn test_initiate_connect_transitions_to_connecting() {
        let mut conn = guest_conn();
        let req = conn.initiate_connect();
        assert!(req.is_some());
        assert_eq!(conn.state(), ConnState::Connecting);

        let r = req.unwrap();
        assert_eq!(r.op, VSOCK_OP_REQUEST);
        assert_eq!(r.src_cid, 2); // HOST
        assert_eq!(r.dst_cid, 3); // guest
        assert_eq!(r.src_port, 2695); // local_port
        assert_eq!(r.dst_port, 5000); // peer_port
        assert_eq!(r.buf_alloc, DEFAULT_BUF_ALLOC);
    }

    #[test]
    fn test_initiate_connect_on_non_idle_returns_none() {
        let mut conn = guest_conn();
        conn.initiate_connect();
        // Second call should fail (already Connecting).
        assert!(conn.initiate_connect().is_none());
    }

    #[test]
    fn test_response_transitions_connecting_to_connected() {
        let mut conn = guest_conn();
        conn.initiate_connect();
        assert_eq!(conn.state(), ConnState::Connecting);

        let resp = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let (hdr, data) = conn.dispatch(&resp, &[]);
        assert!(hdr.is_none()); // No response to a RESPONSE
        assert!(data.is_none());
        assert_eq!(conn.state(), ConnState::Connected);
        assert_eq!(conn.peer_credit(), 32768);
    }

    #[test]
    fn test_request_on_non_idle_returns_none() {
        let mut conn = guest_conn();
        let hdr = make_request_hdr();
        conn.handle_request(&hdr);
        assert_eq!(conn.state(), ConnState::Connected);

        // Second request should fail.
        let resp = conn.handle_request(&hdr);
        assert!(resp.is_none());
    }

    #[test]
    fn test_shutdown_both_transitions_to_closed() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_shutdown(VSOCK_SHUTDOWN_SEND | VSOCK_SHUTDOWN_RECV);
        assert_eq!(conn.state(), ConnState::Closed);
    }

    #[test]
    fn test_shutdown_send_only_transitions_to_closing() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_shutdown(VSOCK_SHUTDOWN_SEND);
        assert_eq!(conn.state(), ConnState::Closing);
    }

    #[test]
    fn test_shutdown_closing_to_closed() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_shutdown(VSOCK_SHUTDOWN_SEND);
        assert_eq!(conn.state(), ConnState::Closing);
        conn.handle_shutdown(VSOCK_SHUTDOWN_RECV);
        assert_eq!(conn.state(), ConnState::Closed);
    }

    #[test]
    fn test_rst_transitions_to_closed() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_rst();
        assert_eq!(conn.state(), ConnState::Closed);
    }

    // --- Data transfer ---

    #[test]
    fn test_handle_rw_returns_data() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        let data = conn.handle_rw(b"hello");
        assert_eq!(data.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_handle_rw_updates_fwd_cnt() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_rw(b"hello"); // 5 bytes
        assert_eq!(conn.fwd_cnt(), 5);
        conn.handle_rw(b"world!"); // 6 bytes
        assert_eq!(conn.fwd_cnt(), 11);
    }

    #[test]
    fn test_handle_rw_when_not_connected_returns_none() {
        let mut conn = guest_conn();
        let data = conn.handle_rw(b"hello");
        assert!(data.is_none());
    }

    // --- Credit flow control ---

    #[test]
    fn test_peer_credit_initial() {
        let mut conn = guest_conn();
        let hdr = make_request_hdr(); // peer_buf_alloc = 32768
        conn.handle_request(&hdr);
        assert_eq!(conn.peer_credit(), 32768);
    }

    #[test]
    fn test_peer_credit_decreases_with_tx() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.enqueue_tx(&[0u8; 1000]);
        conn.drain_tx(1000);
        // tx_cnt = 1000, peer_fwd_cnt = 0 -> credit = 32768 - 1000 = 31768
        assert_eq!(conn.peer_credit(), 31768);
    }

    #[test]
    fn test_peer_credit_recovers_with_update() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.enqueue_tx(&[0u8; 1000]);
        conn.drain_tx(1000);

        // Simulate peer consumed 1000 bytes.
        let mut update = make_request_hdr();
        update.op = VSOCK_OP_CREDIT_UPDATE;
        update.fwd_cnt = 1000;
        update.buf_alloc = 32768;
        conn.handle_credit_update(&update);

        assert_eq!(conn.peer_credit(), 32768);
    }

    #[test]
    fn test_enqueue_tx_respects_credit() {
        let mut conn = guest_conn();
        let mut hdr = make_request_hdr();
        hdr.buf_alloc = 100; // Only 100 bytes of credit.
        conn.handle_request(&hdr);

        let queued = conn.enqueue_tx(&[0xAA; 200]);
        assert_eq!(queued, 100); // Limited by credit.
        assert_eq!(conn.tx_buf_len(), 100);
    }

    #[test]
    fn test_enqueue_tx_when_not_connected() {
        let mut conn = guest_conn();
        let queued = conn.enqueue_tx(b"hello");
        assert_eq!(queued, 0);
    }

    // --- Drain TX ---

    #[test]
    fn test_drain_tx_returns_data_and_header() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.enqueue_tx(b"hello");

        let (hdr, data) = conn.drain_tx(1024).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(hdr.op, VSOCK_OP_RW);
        assert_eq!(hdr.len, 5);
        assert_eq!(hdr.src_cid, 2);
        assert_eq!(hdr.dst_cid, 3);
    }

    #[test]
    fn test_drain_tx_respects_max_payload() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.enqueue_tx(&[0xBB; 1000]);

        let (hdr, data) = conn.drain_tx(500).unwrap();
        assert_eq!(data.len(), 500);
        assert_eq!(hdr.len, 500);

        // Remaining data still in buffer.
        assert_eq!(conn.tx_buf_len(), 500);
    }

    #[test]
    fn test_drain_tx_empty_returns_none() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        assert!(conn.drain_tx(1024).is_none());
    }

    #[test]
    fn test_drain_tx_updates_tx_cnt() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.enqueue_tx(b"12345");
        conn.drain_tx(1024);
        assert_eq!(conn.tx_cnt(), 5);
    }

    // --- Credit request ---

    #[test]
    fn test_credit_request_sets_flag() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        assert!(!conn.needs_credit_update());
        conn.handle_credit_request();
        assert!(conn.needs_credit_update());
    }

    #[test]
    fn test_clear_credit_update() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_credit_request();
        assert!(conn.needs_credit_update());
        conn.clear_credit_update();
        assert!(!conn.needs_credit_update());
    }

    // --- Dispatch ---

    #[test]
    fn test_dispatch_request() {
        let mut conn = guest_conn();
        let hdr = make_request_hdr();
        let (resp, data) = conn.dispatch(&hdr, &[]);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().op, VSOCK_OP_RESPONSE);
        assert!(data.is_none());
        assert_eq!(conn.state(), ConnState::Connected);
    }

    #[test]
    fn test_dispatch_rw() {
        let mut conn = guest_conn();
        conn.dispatch(&make_request_hdr(), &[]);

        let rw_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 5,
            type_: 1,
            op: VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let (_, data) = conn.dispatch(&rw_hdr, b"hello");
        assert_eq!(data.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_dispatch_credit_request_sends_update() {
        let mut conn = guest_conn();
        conn.dispatch(&make_request_hdr(), &[]);

        let cr_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: VSOCK_OP_CREDIT_REQUEST,
            flags: 0,
            buf_alloc: 32768,
            fwd_cnt: 0,
        };
        let (resp, _) = conn.dispatch(&cr_hdr, &[]);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().op, VSOCK_OP_CREDIT_UPDATE);
    }

    #[test]
    fn test_dispatch_unknown_op_sends_rst() {
        let mut conn = guest_conn();
        conn.dispatch(&make_request_hdr(), &[]);

        let bad_hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: 1,
            op: 99,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        };
        let (resp, _) = conn.dispatch(&bad_hdr, &[]);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().op, VSOCK_OP_RST);
    }

    #[test]
    fn test_dispatch_request_on_connected_sends_rst() {
        let mut conn = guest_conn();
        conn.dispatch(&make_request_hdr(), &[]);
        // Second REQUEST while connected.
        let (resp, _) = conn.dispatch(&make_request_hdr(), &[]);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().op, VSOCK_OP_RST);
    }

    // --- Make helpers ---

    #[test]
    fn test_make_credit_update() {
        let mut conn = guest_conn();
        conn.handle_request(&make_request_hdr());
        conn.handle_rw(b"hello"); // fwd_cnt = 5
        let hdr = conn.make_credit_update();
        assert_eq!(hdr.op, VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(hdr.fwd_cnt, 5);
        assert_eq!(hdr.buf_alloc, DEFAULT_BUF_ALLOC);
    }

    #[test]
    fn test_make_rst() {
        let conn = guest_conn();
        let hdr = conn.make_rst();
        assert_eq!(hdr.op, VSOCK_OP_RST);
        assert_eq!(hdr.src_cid, 2);
        assert_eq!(hdr.dst_cid, 3);
    }
}
