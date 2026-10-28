use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    connect, getsockopt, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::{
    os::fd::{AsRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use crate::virtio::net::backend::ConnectError;

use super::backend::{NetBackend, ReadError, WriteError};
use super::{write_virtio_net_hdr, VNET_HDR_LEN};

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const FRAME_HEADER_LEN: usize = 4;

/// Most bytes and receive calls (EINTR retries included) one `read_frame`
/// may spend before returning `Again` with its progress kept, so neither a
/// flood of empty frames nor a huge skipped frame keeps the worker away from
/// its controls. Tests use a small byte budget to reach it with little
/// socket data.
#[cfg(not(test))]
const RX_BYTE_BUDGET: usize = 256 * 1024;
#[cfg(test)]
const RX_BYTE_BUDGET: usize = 512;
const RX_CALL_BUDGET: usize = 64;

#[cfg(target_os = "linux")]
const IO_FLAGS: MsgFlags = MsgFlags::MSG_DONTWAIT.union(MsgFlags::MSG_NOSIGNAL);
#[cfg(target_os = "macos")]
const IO_FLAGS: MsgFlags = MsgFlags::MSG_DONTWAIT;

/// Receive progress of the current length-prefixed frame. Partial prefixes
/// and bodies survive `NothingRead`, so a frame split across socket reads is
/// reassembled instead of blocking the worker thread.
#[derive(Debug, PartialEq, Eq)]
enum RxProgress {
    /// `filled` bytes of the length prefix are in `prefix`.
    Prefix {
        prefix: [u8; FRAME_HEADER_LEN],
        filled: usize,
    },
    /// `filled` of `len` frame bytes are already in the caller's buffer
    /// after the virtio-net header.
    Body { len: usize, filled: usize },
    /// An oversized frame is being skipped; `remaining` bytes are left.
    Discard { remaining: usize },
    /// The peer closed the stream; any partial frame was dropped.
    Closed,
}

impl RxProgress {
    const fn start() -> Self {
        RxProgress::Prefix {
            prefix: [0; FRAME_HEADER_LEN],
            filled: 0,
        }
    }
}

/// Receive work spent by one `read_frame` call.
#[derive(Default)]
struct RxBudget {
    bytes: usize,
    calls: usize,
}

impl RxBudget {
    /// One nonblocking receive: `NothingRead` when the socket is drained,
    /// `Disconnected` on end of stream, `Again` once the budget is spent.
    fn recv(&mut self, fd: RawFd, buf: &mut [u8]) -> Result<usize, ReadError> {
        loop {
            if self.bytes >= RX_BYTE_BUDGET || self.calls >= RX_CALL_BUDGET {
                return Err(ReadError::Again);
            }
            self.calls += 1;
            let len = buf.len().min(RX_BYTE_BUDGET - self.bytes);
            match recv(fd, &mut buf[..len], IO_FLAGS) {
                Ok(0) => return Err(ReadError::Disconnected),
                Ok(size) => {
                    self.bytes += size;
                    return Ok(size);
                }
                Err(nix::Error::EINTR) => continue,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    return Err(ReadError::NothingRead)
                }
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }
    }
}

pub struct Unixstream {
    fd: OwnedFd,
    rx: RxProgress,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        // Every read and write must return instead of blocking the worker,
        // including the remainder of a frame the peer has not sent yet.
        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => {
                let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags)) {
                    warn!("error switching to non-blocking: id={fd:?}, err={e}");
                }
            }
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Self {
            fd,
            rx: RxProgress::start(),
            last_partial_write_length: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;
        Ok(Self::new(fd))
    }

    fn read_frame_impl(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let fd = self.fd.as_raw_fd();
        let max_frame = buf.len() - VNET_HDR_LEN;
        let mut budget = RxBudget::default();
        loop {
            match &mut self.rx {
                RxProgress::Prefix { prefix, filled } => {
                    *filled += budget.recv(fd, &mut prefix[*filled..])?;
                    if *filled < FRAME_HEADER_LEN {
                        continue;
                    }
                    let len = u32::from_be_bytes(*prefix) as usize;
                    self.rx = if len == 0 {
                        log::debug!("Skipping empty frame from network proxy");
                        RxProgress::start()
                    } else if len > max_frame {
                        log::warn!(
                            "Skipping {len} byte frame from network proxy (max {max_frame})"
                        );
                        RxProgress::Discard { remaining: len }
                    } else {
                        RxProgress::Body { len, filled: 0 }
                    };
                }
                RxProgress::Body { len, filled } => {
                    let frame = &mut buf[VNET_HDR_LEN..VNET_HDR_LEN + *len];
                    *filled += budget.recv(fd, &mut frame[*filled..])?;
                    if *filled == *len {
                        let len = *len;
                        self.rx = RxProgress::start();
                        let hdr_len = write_virtio_net_hdr(buf);
                        log::trace!("Read eth frame from network proxy: {len} bytes");
                        return Ok(hdr_len + len);
                    }
                }
                RxProgress::Discard { remaining } => {
                    // No frame is in progress, so the caller's buffer is scratch.
                    let chunk = (*remaining).min(buf.len());
                    let size = budget.recv(fd, &mut buf[..chunk])?;
                    *remaining -= size;
                    if *remaining == 0 {
                        self.rx = RxProgress::start();
                    }
                }
                RxProgress::Closed => return Err(ReadError::Disconnected),
            }
        }
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        while bytes_send < buf.len() {
            match send(self.fd.as_raw_fd(), &buf[bytes_send..], IO_FLAGS) {
                // A stream that accepts nothing without EAGAIN is unusable.
                Ok(0) => return Err(WriteError::ProcessNotRunning),
                Ok(size) => bytes_send += size,
                Err(nix::Error::EINTR) => continue,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                        );

                        self.last_partial_write_length += bytes_send;
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(nix::Error::EPIPE | nix::Error::ECONNRESET) => {
                    return Err(WriteError::ProcessNotRunning)
                }
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = 0;
        Ok(())
    }
}

impl NetBackend for Unixstream {
    /// Try to read a frame from the proxy without blocking.
    ///
    /// `buf` must be the same buffer on every call: a partially received
    /// frame stays in it after `NothingRead` until the rest arrives. Empty
    /// and oversized frames are skipped; `Again` means the per-call budget
    /// ran out with progress kept and more data may already be readable.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let result = self.read_frame_impl(buf);
        if let Err(ReadError::Disconnected) = result {
            if self.rx != RxProgress::start() && self.rx != RxProgress::Closed {
                log::warn!("Network proxy closed the stream inside a frame; dropping it");
            }
            self.rx = RxProgress::Closed;
        }
        result
    }

    /// Try to write a frame to the proxy.
    /// (Will mutate and override parts of buf, with a frame header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= FRAME_HEADER_LEN.
    /// * `buf` - the buffer to write to the proxy, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame to the proxy, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])?;
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
            log::debug!("Finished partial write ({already_written}bytes written before)")
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::net::MAX_BUFFER_SIZE;
    use nix::sys::socket::socketpair;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn pair() -> (Unixstream, UnixStream) {
        let (ours, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        (Unixstream::new(ours), UnixStream::from(peer))
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn assert_frame(result: Result<usize, ReadError>, buf: &[u8], payload: &[u8]) {
        assert_eq!(result.unwrap(), VNET_HDR_LEN + payload.len());
        assert!(buf[..VNET_HDR_LEN].iter().all(|byte| *byte == 0));
        assert_eq!(&buf[VNET_HDR_LEN..VNET_HDR_LEN + payload.len()], payload);
    }

    #[test]
    fn snapshot_net_stream_reassembles_split_prefix_and_body() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        let payload: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let bytes = framed(&payload);

        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::NothingRead)
        ));
        // Two bytes of the prefix, then the rest of the prefix with part of
        // the body, then the remainder: every early call returns instead of
        // blocking.
        peer.write_all(&bytes[..2]).unwrap();
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::NothingRead)
        ));
        peer.write_all(&bytes[2..100]).unwrap();
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::NothingRead)
        ));
        peer.write_all(&bytes[100..]).unwrap();
        assert_frame(backend.read_frame(&mut buf), &buf, &payload);

        // Back-to-back frames in one segment come out one per call.
        let mut both = framed(b"first");
        both.extend(framed(b"second"));
        peer.write_all(&both).unwrap();
        assert_frame(backend.read_frame(&mut buf), &buf, b"first");
        assert_frame(backend.read_frame(&mut buf), &buf, b"second");
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::NothingRead)
        ));
    }

    #[test]
    fn snapshot_net_stream_skips_empty_and_oversized_frames() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        let max_frame = MAX_BUFFER_SIZE - VNET_HDR_LEN;

        // An exactly maximal frame is delivered; one byte more is skipped
        // without touching the frame that follows it.
        let largest = vec![0x5a; max_frame];
        let oversized = vec![0xa5; max_frame + 1];
        let mut bytes = framed(&[]);
        bytes.extend(framed(&oversized));
        bytes.extend(framed(b"after"));
        bytes.extend(framed(&largest));
        let writer = std::thread::spawn(move || peer.write_all(&bytes).map(|_| peer));
        let mut frames = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while frames.len() < 2 {
            assert!(std::time::Instant::now() < deadline, "frames never arrived");
            match backend.read_frame(&mut buf) {
                Ok(len) => frames.push(buf[VNET_HDR_LEN..len].to_vec()),
                Err(ReadError::NothingRead | ReadError::Again) => std::thread::yield_now(),
                Err(e) => panic!("unexpected read error {e:?}"),
            }
        }
        let _peer = writer.join().unwrap().unwrap();
        assert_eq!(frames[0], b"after");
        assert_eq!(frames[1], largest);
    }

    /// Read until a frame arrives, counting budget stops; bounded so a
    /// regression fails instead of hanging the suite.
    fn read_counting_agains(backend: &mut Unixstream, buf: &mut [u8]) -> (usize, usize) {
        let mut agains = 0;
        for _ in 0..10_000 {
            match backend.read_frame(buf) {
                Ok(len) => return (len, agains),
                Err(ReadError::Again) => agains += 1,
                Err(e) => panic!("unexpected read error {e:?}"),
            }
        }
        panic!("no frame after 10000 calls");
    }

    #[test]
    fn snapshot_net_stream_budget_bounds_empty_frame_flood() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        // 4 KiB of empty frames, then a real one: preloaded, well within
        // default socket capacity. One call must stop at the budget instead
        // of draining every empty prefix.
        let mut bytes = vec![0u8; 4096];
        bytes.extend(framed(b"after"));
        peer.write_all(&bytes).unwrap();
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::Again)
        ));
        let (len, agains) = read_counting_agains(&mut backend, &mut buf);
        assert_eq!(&buf[VNET_HDR_LEN..len], b"after");
        // Each call consumes at most the byte budget or one call budget of
        // 4-byte prefixes; the first stop was asserted above.
        let per_call = RX_BYTE_BUDGET.min(RX_CALL_BUDGET * FRAME_HEADER_LEN);
        assert!(agains + 1 >= 4096 / per_call, "{agains} budget stops");
    }

    #[test]
    fn snapshot_net_stream_budget_bounds_oversized_discard() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        // A huge length prefix with 2 KiB of its body already queued: the
        // call stops at the budget with the skip still in progress.
        let mut bytes = u32::MAX.to_be_bytes().to_vec();
        bytes.resize(4 + 2048, 0xee);
        peer.write_all(&bytes).unwrap();
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::Again)
        ));
        // Later calls drain the queued part, then report an empty socket
        // while the skip continues.
        let drained = (0..16).any(|_| match backend.read_frame(&mut buf) {
            Err(ReadError::Again) => false,
            Err(ReadError::NothingRead) => true,
            other => panic!("unexpected read result {other:?}"),
        });
        assert!(drained);
        assert!(matches!(backend.rx, RxProgress::Discard { .. }));
    }

    #[test]
    fn snapshot_net_stream_budget_keeps_large_frame_progress() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        // A frame larger than the test byte budget completes over several
        // calls without losing or duplicating bytes.
        let payload: Vec<u8> = (0..3000).map(|i| (i * 7) as u8).collect();
        peer.write_all(&framed(&payload)).unwrap();
        let (len, agains) = read_counting_agains(&mut backend, &mut buf);
        assert_eq!(agains, (4 + payload.len()) / RX_BYTE_BUDGET);
        assert_frame(Ok(len), &buf, &payload);
    }

    #[test]
    fn snapshot_net_stream_reports_eof_including_mid_frame() {
        let (mut backend, mut peer) = pair();
        let mut buf = vec![0u8; MAX_BUFFER_SIZE];
        let bytes = framed(b"complete");
        peer.write_all(&bytes).unwrap();
        // A truncated second frame: prefix plus three of its eight bytes.
        peer.write_all(&framed(b"truncate")[..7]).unwrap();
        drop(peer);

        assert_frame(backend.read_frame(&mut buf), &buf, b"complete");
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::Disconnected)
        ));
        // The closed state is sticky; nothing partial is ever delivered.
        assert!(matches!(
            backend.read_frame(&mut buf),
            Err(ReadError::Disconnected)
        ));
    }

    #[test]
    fn snapshot_net_stream_tx_pressure_partial_and_finish() {
        let (mut backend, mut peer) = pair();
        // Small kernel buffers make backpressure reachable quickly.
        let _ = setsockopt(&backend.fd, sockopt::SndBuf, &4096);
        let frame_len = 60_000;
        let mut frames = Vec::new();
        let mut sent = 0;
        let mut partial = false;
        let mut blocked = false;
        for _ in 0..10_000 {
            if blocked {
                break;
            }
            let mut buf = vec![0u8; VNET_HDR_LEN + frame_len];
            buf[VNET_HDR_LEN..].fill(sent as u8 + 1);
            match backend.write_frame(VNET_HDR_LEN, &mut buf) {
                Ok(()) => {
                    frames.push(buf);
                    sent += 1;
                }
                Err(WriteError::PartialWrite) => {
                    partial = true;
                    assert!(backend.has_unfinished_write());
                    frames.push(buf);
                    sent += 1;
                    // Nothing new can be written until the remainder is.
                    let last = frames.last().unwrap().clone();
                    match backend.try_finish_write(VNET_HDR_LEN, &last) {
                        Err(WriteError::PartialWrite | WriteError::NothingWritten) => {
                            blocked = true
                        }
                        Ok(()) => {}
                        Err(e) => panic!("unexpected write error {e:?}"),
                    }
                }
                Err(WriteError::NothingWritten) => blocked = true,
                Err(e) => panic!("unexpected write error {e:?}"),
            }
        }
        assert!(blocked, "socket never applied backpressure");

        // Drain the peer while finishing the remainder: the byte stream is
        // exactly the frames in order, each with its own prefix.
        let expected: Vec<u8> = frames
            .iter()
            .flat_map(|buf| framed(&buf[VNET_HDR_LEN..]))
            .collect();
        let reader = std::thread::spawn(move || {
            let mut received = vec![0u8; expected.len()];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);
            peer
        });
        if partial || backend.has_unfinished_write() {
            let last = frames.last().unwrap().clone();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while backend.has_unfinished_write() {
                assert!(std::time::Instant::now() < deadline);
                match backend.try_finish_write(VNET_HDR_LEN, &last) {
                    Ok(()) => {}
                    Err(WriteError::PartialWrite | WriteError::NothingWritten) => {
                        std::thread::yield_now()
                    }
                    Err(e) => panic!("unexpected write error {e:?}"),
                }
            }
        }
        let peer = reader.join().unwrap();
        // A closed peer is reported, never a signal or a panic.
        drop(peer);
        let mut buf = vec![0u8; VNET_HDR_LEN + 64];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            assert!(std::time::Instant::now() < deadline);
            match backend.write_frame(VNET_HDR_LEN, &mut buf) {
                Err(WriteError::ProcessNotRunning) => break,
                Ok(()) => {}
                Err(e) => panic!("unexpected write error {e:?}"),
            }
        }
    }
}
