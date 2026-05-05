//! Virtio-vsock packet header (virtio spec v1.2 Section 5.10.6).
//!
//! The 44-byte header is prepended to every vsock packet in the
//! TX and RX virtqueues. It carries addressing, flow control credits,
//! and operation codes for the vsock connection protocol.

use super::super::super::super::error::{Result, WkrunError};
use super::super::queue::GuestMemoryAccessor;

// --- CID constants ---

/// Well-known CID for the host (hypervisor).
pub const VSOCK_CID_HOST: u64 = 2;

// --- Vsock type ---

/// Stream transport (SOCK_STREAM equivalent).
pub const VIRTIO_VSOCK_TYPE_STREAM: u16 = 1;

// --- Vsock operations (spec 5.10.6.6) ---

/// Invalid operation.
pub const VSOCK_OP_INVALID: u16 = 0;
/// Connection request (guest -> host).
pub const VSOCK_OP_REQUEST: u16 = 1;
/// Connection accepted (host -> guest).
pub const VSOCK_OP_RESPONSE: u16 = 2;
/// Connection reset / refused.
pub const VSOCK_OP_RST: u16 = 3;
/// Graceful shutdown.
pub const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Data transfer.
pub const VSOCK_OP_RW: u16 = 5;
/// Credit update (no payload).
pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Credit request (ask peer to send credit update).
pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

// --- Shutdown flags ---

/// Shutdown flag: no more data to send.
pub const VSOCK_SHUTDOWN_SEND: u32 = 1;
/// Shutdown flag: no more data to receive.
pub const VSOCK_SHUTDOWN_RECV: u32 = 2;

/// Size of the vsock packet header in bytes.
pub const VSOCK_HEADER_SIZE: usize = 44;

/// Virtio-vsock packet header (44 bytes, little-endian).
///
/// Layout (spec 5.10.6):
///   offset  0: src_cid     (u64)
///   offset  8: dst_cid     (u64)
///   offset 16: src_port    (u32)
///   offset 20: dst_port    (u32)
///   offset 24: len         (u32) - payload length
///   offset 28: type_       (u16) - VIRTIO_VSOCK_TYPE_STREAM
///   offset 30: op          (u16) - operation code
///   offset 32: flags       (u32) - operation-specific flags
///   offset 36: buf_alloc   (u32) - credit: total buffer space
///   offset 40: fwd_cnt     (u32) - credit: bytes consumed so far
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub type_: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VsockHeader {
    /// Read a vsock header from guest memory at the given address.
    pub fn read_from(mem: &dyn GuestMemoryAccessor, addr: u64) -> Result<Self> {
        let mut buf = [0u8; VSOCK_HEADER_SIZE];
        mem.read_at(addr, &mut buf)?;
        Ok(Self::from_bytes(&buf))
    }

    /// Write this vsock header to guest memory at the given address.
    pub fn write_to(&self, mem: &dyn GuestMemoryAccessor, addr: u64) -> Result<()> {
        let buf = self.to_bytes();
        mem.write_at(addr, &buf)
    }

    /// Parse a vsock header from a 44-byte buffer.
    pub fn from_bytes(buf: &[u8; VSOCK_HEADER_SIZE]) -> Self {
        VsockHeader {
            src_cid: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            dst_cid: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            src_port: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            dst_port: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            len: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            type_: u16::from_le_bytes(buf[28..30].try_into().unwrap()),
            op: u16::from_le_bytes(buf[30..32].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            buf_alloc: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
            fwd_cnt: u32::from_le_bytes(buf[40..44].try_into().unwrap()),
        }
    }

    /// Serialize this header to a 44-byte buffer.
    pub fn to_bytes(&self) -> [u8; VSOCK_HEADER_SIZE] {
        let mut buf = [0u8; VSOCK_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        buf[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        buf[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        buf[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        buf[24..28].copy_from_slice(&self.len.to_le_bytes());
        buf[28..30].copy_from_slice(&self.type_.to_le_bytes());
        buf[30..32].copy_from_slice(&self.op.to_le_bytes());
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        buf[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        buf[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        buf
    }

    /// Create a REQUEST header (host -> guest) for a host-initiated connection.
    pub fn new_request(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Create a RESPONSE header (host -> guest) for a given REQUEST.
    pub fn new_response(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Create an RW (data) header.
    pub fn new_rw(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        payload_len: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: payload_len,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RW,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Create a RST header.
    pub fn new_rst(src_cid: u64, src_port: u32, dst_cid: u64, dst_port: u32) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RST,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    /// Create a SHUTDOWN header.
    pub fn new_shutdown(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        flags: u32,
    ) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_SHUTDOWN,
            flags,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    /// Create a CREDIT_UPDATE header.
    pub fn new_credit_update(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        VsockHeader {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_CREDIT_UPDATE,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Validate that this header has a known operation and stream type.
    pub fn validate(&self) -> Result<()> {
        if self.type_ != VIRTIO_VSOCK_TYPE_STREAM {
            return Err(WkrunError::Device(format!(
                "unsupported vsock type: {} (expected stream=1)",
                self.type_
            )));
        }
        if self.op > VSOCK_OP_CREDIT_REQUEST {
            return Err(WkrunError::Device(format!(
                "unknown vsock operation: {}",
                self.op
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::error::Result;
    use super::*;
    use std::cell::RefCell;

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

    #[test]
    fn test_header_size() {
        assert_eq!(VSOCK_HEADER_SIZE, 44);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 1234,
            dst_port: 2695,
            len: 100,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 512,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), VSOCK_HEADER_SIZE);
        let parsed = VsockHeader::from_bytes(&bytes);
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_field_offsets() {
        let hdr = VsockHeader {
            src_cid: 0x0102_0304_0506_0708,
            dst_cid: 0x090A_0B0C_0D0E_0F10,
            src_port: 0x11121314,
            dst_port: 0x15161718,
            len: 0x191A1B1C,
            type_: 0x1D1E,
            op: 0x1F20,
            flags: 0x21222324,
            buf_alloc: 0x25262728,
            fwd_cnt: 0x292A2B2C,
        };
        let buf = hdr.to_bytes();

        // Verify each field starts at the correct offset.
        assert_eq!(
            u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            hdr.src_cid
        );
        assert_eq!(
            u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            hdr.dst_cid
        );
        assert_eq!(
            u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            hdr.src_port
        );
        assert_eq!(
            u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            hdr.dst_port
        );
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), hdr.len);
        assert_eq!(
            u16::from_le_bytes(buf[28..30].try_into().unwrap()),
            hdr.type_
        );
        assert_eq!(u16::from_le_bytes(buf[30..32].try_into().unwrap()), hdr.op);
        assert_eq!(
            u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            hdr.flags
        );
        assert_eq!(
            u32::from_le_bytes(buf[36..40].try_into().unwrap()),
            hdr.buf_alloc
        );
        assert_eq!(
            u32::from_le_bytes(buf[40..44].try_into().unwrap()),
            hdr.fwd_cnt
        );
    }

    #[test]
    fn test_read_write_guest_memory() {
        let mem = MockMem::new(256);
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: 2,
            src_port: 5000,
            dst_port: 2695,
            len: 0,
            type_: VIRTIO_VSOCK_TYPE_STREAM,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 4096,
            fwd_cnt: 0,
        };
        hdr.write_to(&mem, 0).unwrap();
        let read_back = VsockHeader::read_from(&mem, 0).unwrap();
        assert_eq!(read_back, hdr);
    }

    #[test]
    fn test_new_request() {
        let hdr = VsockHeader::new_request(2, 49152, 3, 2695, 65536, 0);
        assert_eq!(hdr.src_cid, 2);
        assert_eq!(hdr.dst_cid, 3);
        assert_eq!(hdr.src_port, 49152);
        assert_eq!(hdr.dst_port, 2695);
        assert_eq!(hdr.len, 0);
        assert_eq!(hdr.type_, VIRTIO_VSOCK_TYPE_STREAM);
        assert_eq!(hdr.op, VSOCK_OP_REQUEST);
        assert_eq!(hdr.buf_alloc, 65536);
        assert_eq!(hdr.fwd_cnt, 0);
    }

    #[test]
    fn test_new_response() {
        let hdr = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        assert_eq!(hdr.src_cid, 2);
        assert_eq!(hdr.dst_cid, 3);
        assert_eq!(hdr.src_port, 2695);
        assert_eq!(hdr.dst_port, 5000);
        assert_eq!(hdr.len, 0);
        assert_eq!(hdr.type_, VIRTIO_VSOCK_TYPE_STREAM);
        assert_eq!(hdr.op, VSOCK_OP_RESPONSE);
        assert_eq!(hdr.buf_alloc, 65536);
        assert_eq!(hdr.fwd_cnt, 0);
    }

    #[test]
    fn test_new_rw() {
        let hdr = VsockHeader::new_rw(2, 2695, 3, 5000, 128, 65536, 64);
        assert_eq!(hdr.op, VSOCK_OP_RW);
        assert_eq!(hdr.len, 128);
        assert_eq!(hdr.buf_alloc, 65536);
        assert_eq!(hdr.fwd_cnt, 64);
    }

    #[test]
    fn test_new_rst() {
        let hdr = VsockHeader::new_rst(2, 2695, 3, 5000);
        assert_eq!(hdr.op, VSOCK_OP_RST);
        assert_eq!(hdr.len, 0);
        assert_eq!(hdr.buf_alloc, 0);
        assert_eq!(hdr.fwd_cnt, 0);
    }

    #[test]
    fn test_new_shutdown() {
        let hdr =
            VsockHeader::new_shutdown(3, 5000, 2, 2695, VSOCK_SHUTDOWN_SEND | VSOCK_SHUTDOWN_RECV);
        assert_eq!(hdr.op, VSOCK_OP_SHUTDOWN);
        assert_eq!(hdr.flags, 3);
    }

    #[test]
    fn test_new_credit_update() {
        let hdr = VsockHeader::new_credit_update(2, 2695, 3, 5000, 32768, 1024);
        assert_eq!(hdr.op, VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(hdr.buf_alloc, 32768);
        assert_eq!(hdr.fwd_cnt, 1024);
    }

    #[test]
    fn test_validate_valid() {
        let hdr = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn test_validate_bad_type() {
        let mut hdr = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        hdr.type_ = 99;
        assert!(hdr.validate().is_err());
    }

    #[test]
    fn test_validate_bad_op() {
        let mut hdr = VsockHeader::new_response(2, 2695, 3, 5000, 65536, 0);
        hdr.op = 99;
        assert!(hdr.validate().is_err());
    }

    #[test]
    fn test_zero_header() {
        let buf = [0u8; VSOCK_HEADER_SIZE];
        let hdr = VsockHeader::from_bytes(&buf);
        assert_eq!(hdr.src_cid, 0);
        assert_eq!(hdr.dst_cid, 0);
        assert_eq!(hdr.op, VSOCK_OP_INVALID);
    }
}
