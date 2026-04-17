//! Virtio-9p device backend (virtio spec v1.2 Section 5.11).
//!
//! Provides a 9P2000.L filesystem share between guest and host.
//! The guest mounts the share via `mount -t 9p -o trans=virtio,version=9p2000.L <tag> <mountpoint>`.
//!
//! Queue layout:
//!   Queue 0 (request): bidirectional 9P messages

pub mod filesystem;
pub mod protocol;

use std::path::PathBuf;

use super::mmio::VirtioDeviceBackend;
use super::queue::{GuestMemoryAccessor, Virtqueue};

use self::filesystem::P9Filesystem;
use self::protocol::*;

/// Virtio device ID for 9P transport (spec Section 5.11).
const VIRTIO_9P_ID: u32 = 9;

/// VIRTIO_F_VERSION_1 — bit 32 (page 1, bit 0).
const VIRTIO_F_VERSION_1_BIT: u32 = 0;

/// VIRTIO_9P_MOUNT_TAG feature bit (page 0, bit 0).
const VIRTIO_9P_MOUNT_TAG_BIT: u32 = 0;

/// Maximum queue size.
const QUEUE_MAX_SIZE: u16 = 128;

/// Virtio-9p device with host filesystem backend.
pub struct Virtio9p {
    /// Mount tag visible to the guest (max 255 bytes).
    tag: String,
    /// Filesystem backend.
    fs: P9Filesystem,
}

impl Virtio9p {
    /// Create a new 9p device sharing `root_path` on the host.
    ///
    /// `tag` is the mount tag the guest uses to identify this share.
    /// `root_path` is the host directory to expose.
    /// `read_only` controls whether writes are permitted.
    pub fn new(tag: &str, root_path: PathBuf, read_only: bool) -> Self {
        Virtio9p {
            tag: tag.to_string(),
            fs: P9Filesystem::new(root_path, read_only),
        }
    }

    /// Get the mount tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Process a single 9P request from a descriptor chain.
    ///
    /// Returns the response bytes to write back, and the total bytes
    /// consumed from readable descriptors.
    fn process_request(&mut self, request: &[u8]) -> Vec<u8> {
        let mut r = ByteReader::new(request);

        let hdr = match P9Header::read_from(&mut r) {
            Some(h) => h,
            None => return build_response(P9_RLERROR, 0, |w| write_rlerror(w, filesystem::EIO)),
        };

        let body = &request[P9_HEADER_SIZE..];
        let req = match parse_request(hdr.msg_type, body) {
            Some(r) => r,
            None => {
                return build_response(P9_RLERROR, hdr.tag, |w| {
                    write_rlerror(w, filesystem::EINVAL)
                })
            }
        };

        self.dispatch(hdr.tag, req)
    }

    /// Dispatch a parsed request to the filesystem backend.
    fn dispatch(&mut self, tag: u16, req: P9Request) -> Vec<u8> {
        match req {
            P9Request::Tversion { msize, version } => {
                if version != "9P2000.L" {
                    return build_response(P9_RVERSION, tag, |w| {
                        write_rversion(w, msize, "unknown");
                    });
                }
                let negotiated = self.fs.version(msize);
                build_response(P9_RVERSION, tag, |w| {
                    write_rversion(w, negotiated, "9P2000.L");
                })
            }

            P9Request::Tattach { fid, .. } => match self.fs.attach(fid) {
                Ok(qid) => build_response(P9_RATTACH, tag, |w| write_rattach(w, &qid)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Twalk { fid, newfid, names } => match self.fs.walk(fid, newfid, &names) {
                Ok(qids) => build_response(P9_RWALK, tag, |w| write_rwalk(w, &qids)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tlopen { fid, flags } => match self.fs.lopen(fid, flags) {
                Ok((qid, iounit)) => {
                    build_response(P9_RLOPEN, tag, |w| write_rlopen(w, &qid, iounit))
                }
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tlcreate {
                fid,
                name,
                flags,
                mode,
                gid,
            } => match self.fs.lcreate(fid, &name, flags, mode, gid) {
                Ok((qid, iounit)) => {
                    build_response(P9_RLCREATE, tag, |w| write_rlcreate(w, &qid, iounit))
                }
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tread { fid, offset, count } => match self.fs.read(fid, offset, count) {
                Ok(data) => build_response(P9_RREAD, tag, |w| write_rread(w, &data)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Twrite {
                fid, offset, data, ..
            } => match self.fs.write(fid, offset, &data) {
                Ok(count) => build_response(P9_RWRITE, tag, |w| write_rwrite(w, count)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Treaddir { fid, offset, count } => {
                match self.fs.readdir(fid, offset, count) {
                    Ok(data) => build_response(P9_RREADDIR, tag, |w| write_rreaddir(w, &data)),
                    Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
                }
            }

            P9Request::Tgetattr { fid, request_mask } => match self.fs.getattr(fid, request_mask) {
                Ok(attr) => build_response(P9_RGETATTR, tag, |w| write_rgetattr(w, &attr)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tsetattr {
                fid,
                valid,
                mode,
                uid,
                gid,
                size,
                ..
            } => match self.fs.setattr(fid, valid, mode, uid, gid, size) {
                Ok(()) => build_response(P9_RSETATTR, tag, write_rsetattr),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tclunk { fid } => match self.fs.clunk(fid) {
                Ok(()) => build_response(P9_RCLUNK, tag, write_rclunk),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tflush { .. } => build_response(P9_RFLUSH, tag, write_rflush),

            P9Request::Tmkdir {
                dfid,
                name,
                mode,
                gid,
            } => match self.fs.mkdir(dfid, &name, mode, gid) {
                Ok(qid) => build_response(P9_RMKDIR, tag, |w| write_rmkdir(w, &qid)),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => match self.fs.renameat(olddirfid, &oldname, newdirfid, &newname) {
                Ok(()) => build_response(P9_RRENAMEAT, tag, write_rrenameat),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tunlinkat {
                dirfid,
                name,
                flags,
            } => match self.fs.unlinkat(dirfid, &name, flags) {
                Ok(()) => build_response(P9_RUNLINKAT, tag, write_runlinkat),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },

            P9Request::Tfsync { fid } => match self.fs.fsync(fid) {
                Ok(()) => build_response(P9_RFSYNC, tag, write_rfsync),
                Err(e) => build_response(P9_RLERROR, tag, |w| write_rlerror(w, e)),
            },
        }
    }
}

impl VirtioDeviceBackend for Virtio9p {
    fn device_id(&self) -> u32 {
        VIRTIO_9P_ID
    }

    fn device_features(&self, page: u32) -> u32 {
        match page {
            0 => 1 << VIRTIO_9P_MOUNT_TAG_BIT,
            1 => 1 << VIRTIO_F_VERSION_1_BIT,
            _ => 0,
        }
    }

    fn read_config(&self, offset: u64) -> u32 {
        // Config space layout:
        //   offset 0: tag_len (u16) — only low 16 bits of the u32 read
        //   offset 2+: tag bytes (padded to u32 alignment)
        let tag_bytes = self.tag.as_bytes();
        let tag_len = tag_bytes.len() as u16;

        if offset == 0 {
            // tag_len at offset 0 (u16) + first 2 bytes of tag at offset 2.
            let mut val = tag_len as u32;
            if !tag_bytes.is_empty() {
                val |= (tag_bytes[0] as u32) << 16;
            }
            if tag_bytes.len() > 1 {
                val |= (tag_bytes[1] as u32) << 24;
            }
            val
        } else {
            // Subsequent 4-byte reads into the tag string.
            // offset is relative to config space start.
            // tag starts at byte 2 within config space.
            let tag_start = offset as usize - 2;
            let mut bytes = [0u8; 4];
            for (i, byte) in bytes.iter_mut().enumerate() {
                let tidx = tag_start + i;
                if tidx < tag_bytes.len() {
                    *byte = tag_bytes[tidx];
                }
            }
            u32::from_le_bytes(bytes)
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

            // Collect request from device-readable descriptors.
            let mut request = Vec::new();
            for desc in &chain {
                if !desc.is_write() {
                    let mut buf = vec![0u8; desc.len as usize];
                    if mem.read_at(desc.addr, &mut buf).is_ok() {
                        request.extend_from_slice(&buf);
                    }
                }
            }

            // Process the 9P request.
            let response = self.process_request(&request);

            // Write response to device-writable descriptors.
            let mut offset = 0;
            let mut total_written = 0u32;
            for desc in &chain {
                if !desc.is_write() {
                    continue;
                }
                let remaining = response.len().saturating_sub(offset);
                let to_write = remaining.min(desc.len as usize);
                if to_write > 0 {
                    let _ = mem.write_at(desc.addr, &response[offset..offset + to_write]);
                    offset += to_write;
                    total_written += to_write as u32;
                }
            }

            let _ = queue.add_used(head, total_written, mem);
            processed = true;
        }

        processed
    }

    fn num_queues(&self) -> usize {
        1 // Single request queue.
    }

    fn queue_max_size(&self, _queue_idx: u32) -> u16 {
        QUEUE_MAX_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::queue::Virtqueue;
    use super::super::super::super::error::Result;
    use std::cell::RefCell;
    use std::io::Write as IoWrite;
    use tempfile::TempDir;

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
                return Err(super::super::super::super::error::WkrunError::Memory("out of bounds".into()));
            }
            buf.copy_from_slice(&data[a..a + buf.len()]);
            Ok(())
        }
        fn write_at(&self, addr: u64, data: &[u8]) -> Result<()> {
            let a = addr as usize;
            let mut mem = self.data.borrow_mut();
            if a + data.len() > mem.len() {
                return Err(super::super::super::super::error::WkrunError::Memory("out of bounds".into()));
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
    const RESP_BASE: u64 = 0x4000;

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

    fn create_test_device(tmp: &TempDir) -> Virtio9p {
        Virtio9p::new("hostshare", tmp.path().to_path_buf(), false)
    }

    /// Submit a request through the virtqueue and return the response bytes.
    fn submit_request(
        dev: &mut Virtio9p,
        mem: &MockMem,
        queue: &mut Virtqueue,
        request: &[u8],
        avail_idx: u16,
    ) -> Vec<u8> {
        let desc_base = avail_idx * 2;
        mem.write_bytes(BUF_BASE, request);

        // Descriptor 0: request (device-readable), chained to 1.
        write_descriptor(
            mem,
            desc_base,
            BUF_BASE,
            request.len() as u32,
            1, // NEXT flag
            desc_base + 1,
        );
        // Descriptor 1: response buffer (device-writable).
        write_descriptor(mem, desc_base + 1, RESP_BASE, 8192, 2, 0); // WRITE flag

        push_avail(mem, avail_idx, desc_base);

        let raised = dev.queue_notify(0, queue, mem);
        assert!(raised);

        // Read the response from RESP_BASE.
        let resp_data = mem.read_bytes(RESP_BASE, 8192);
        // Parse size from response.
        let size = u32::from_le_bytes([resp_data[0], resp_data[1], resp_data[2], resp_data[3]]);
        resp_data[..size as usize].to_vec()
    }

    fn build_tversion() -> Vec<u8> {
        build_response(P9_TVERSION, P9_NOTAG, |w| {
            w.put_u32(8192);
            w.put_string("9P2000.L");
        })
    }

    fn build_tattach(fid: u32) -> Vec<u8> {
        build_response(P9_TATTACH, 1, |w| {
            w.put_u32(fid);
            w.put_u32(P9_NOFID);
            w.put_string("");
            w.put_string("");
        })
    }

    fn build_twalk(fid: u32, newfid: u32, names: &[&str]) -> Vec<u8> {
        build_response(P9_TWALK, 2, |w| {
            w.put_u32(fid);
            w.put_u32(newfid);
            w.put_u16(names.len() as u16);
            for name in names {
                w.put_string(name);
            }
        })
    }

    fn build_tlopen(fid: u32, flags: u32) -> Vec<u8> {
        build_response(P9_TLOPEN, 3, |w| {
            w.put_u32(fid);
            w.put_u32(flags);
        })
    }

    fn build_tread(fid: u32, offset: u64, count: u32) -> Vec<u8> {
        build_response(P9_TREAD, 4, |w| {
            w.put_u32(fid);
            w.put_u64(offset);
            w.put_u32(count);
        })
    }

    fn build_tclunk(fid: u32) -> Vec<u8> {
        build_response(P9_TCLUNK, 5, |w| {
            w.put_u32(fid);
        })
    }

    fn build_treaddir(fid: u32, offset: u64, count: u32) -> Vec<u8> {
        build_response(P9_TREADDIR, 6, |w| {
            w.put_u32(fid);
            w.put_u64(offset);
            w.put_u32(count);
        })
    }

    fn build_tgetattr(fid: u32) -> Vec<u8> {
        build_response(P9_TGETATTR, 7, |w| {
            w.put_u32(fid);
            w.put_u64(0x3FFF); // All attributes.
        })
    }

    // -- Device identity --

    #[test]
    fn test_device_id() {
        let tmp = TempDir::new().unwrap();
        let dev = create_test_device(&tmp);
        assert_eq!(dev.device_id(), 9);
    }

    #[test]
    fn test_num_queues() {
        let tmp = TempDir::new().unwrap();
        let dev = create_test_device(&tmp);
        assert_eq!(dev.num_queues(), 1);
    }

    #[test]
    fn test_queue_max_size() {
        let tmp = TempDir::new().unwrap();
        let dev = create_test_device(&tmp);
        assert_eq!(dev.queue_max_size(0), 128);
    }

    #[test]
    fn test_features() {
        let tmp = TempDir::new().unwrap();
        let dev = create_test_device(&tmp);
        assert_eq!(dev.device_features(0), 1); // VIRTIO_9P_MOUNT_TAG.
        assert_eq!(dev.device_features(1), 1); // VIRTIO_F_VERSION_1.
        assert_eq!(dev.device_features(2), 0);
    }

    // -- Config space --

    #[test]
    fn test_config_tag_len() {
        let tmp = TempDir::new().unwrap();
        let dev = Virtio9p::new("hostshare", tmp.path().to_path_buf(), false);
        let val = dev.read_config(0);
        // Low 16 bits = tag_len = 9 ("hostshare")
        assert_eq!(val & 0xFFFF, 9);
    }

    #[test]
    fn test_tag() {
        let tmp = TempDir::new().unwrap();
        let dev = create_test_device(&tmp);
        assert_eq!(dev.tag(), "hostshare");
    }

    // -- Version negotiation --

    #[test]
    fn test_version_negotiation() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);

        let resp = dev.process_request(&build_tversion());
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RVERSION);
        let msize = r.get_u32().unwrap();
        assert_eq!(msize, 8192);
        let version = r.get_string().unwrap();
        assert_eq!(version, "9P2000.L");
    }

    #[test]
    fn test_version_unknown_protocol() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);

        let msg = build_response(P9_TVERSION, P9_NOTAG, |w| {
            w.put_u32(8192);
            w.put_string("9P2000.u"); // Not supported.
        });
        let resp = dev.process_request(&msg);
        let mut r = ByteReader::new(&resp);
        let _hdr = P9Header::read_from(&mut r).unwrap();
        let _msize = r.get_u32().unwrap();
        let version = r.get_string().unwrap();
        assert_eq!(version, "unknown");
    }

    // -- Attach --

    #[test]
    fn test_attach() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);
        dev.process_request(&build_tversion());

        let resp = dev.process_request(&build_tattach(0));
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RATTACH);
        let qid = Qid::read_from(&mut r).unwrap();
        assert_eq!(qid.qtype, QT_DIR);
    }

    // -- Walk + Read file through queue --

    #[test]
    fn test_walk_and_read_via_queue() {
        let tmp = TempDir::new().unwrap();
        let mut file = std::fs::File::create(tmp.path().join("hello.txt")).unwrap();
        file.write_all(b"hello world").unwrap();
        drop(file);

        let mut dev = create_test_device(&tmp);
        let mem = MockMem::new(0x10000);
        let mut queue = setup_queue(128);

        // Version.
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tversion(), 0);

        // Attach.
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tattach(0), 1);

        // Walk to hello.txt.
        let _resp = submit_request(
            &mut dev,
            &mem,
            &mut queue,
            &build_twalk(0, 1, &["hello.txt"]),
            2,
        );

        // Open.
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tlopen(1, 0), 3);

        // Read.
        let resp = submit_request(&mut dev, &mem, &mut queue, &build_tread(1, 0, 4096), 4);
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RREAD);
        let count = r.get_u32().unwrap();
        assert_eq!(count, 11);
        let data = r.get_bytes(count as usize).unwrap();
        assert_eq!(data, b"hello world");
    }

    // -- Readdir via queue --

    #[test]
    fn test_readdir_via_queue() {
        let tmp = TempDir::new().unwrap();
        std::fs::File::create(tmp.path().join("a.txt")).unwrap();
        std::fs::File::create(tmp.path().join("b.txt")).unwrap();

        let mut dev = create_test_device(&tmp);
        let mem = MockMem::new(0x10000);
        let mut queue = setup_queue(128);

        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tversion(), 0);
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tattach(0), 1);

        // Open root dir.
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tlopen(0, 0), 2);

        // Readdir.
        let resp = submit_request(&mut dev, &mem, &mut queue, &build_treaddir(0, 0, 8192), 3);
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RREADDIR);
        let count = r.get_u32().unwrap();
        assert!(count > 0); // Should contain entries.
    }

    // -- Getattr --

    #[test]
    fn test_getattr_via_queue() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);
        let mem = MockMem::new(0x10000);
        let mut queue = setup_queue(128);

        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tversion(), 0);
        let _resp = submit_request(&mut dev, &mem, &mut queue, &build_tattach(0), 1);

        let resp = submit_request(&mut dev, &mem, &mut queue, &build_tgetattr(0), 2);
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RGETATTR);
    }

    // -- Error response for bad fid --

    #[test]
    fn test_error_bad_fid() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);
        dev.process_request(&build_tversion());

        // Try to walk with unattached fid.
        let resp = dev.process_request(&build_twalk(99, 1, &["foo"]));
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RLERROR);
        let ecode = r.get_u32().unwrap();
        assert_eq!(ecode, filesystem::EBADF);
    }

    // -- Clunk --

    #[test]
    fn test_clunk() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);
        dev.process_request(&build_tversion());
        dev.process_request(&build_tattach(0));

        let resp = dev.process_request(&build_tclunk(0));
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RCLUNK);

        // Fid 0 should now be invalid.
        let resp = dev.process_request(&build_twalk(0, 1, &[]));
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RLERROR);
    }

    // -- Multiple requests in sequence --

    #[test]
    fn test_multiple_requests() {
        let tmp = TempDir::new().unwrap();
        std::fs::File::create(tmp.path().join("f1.txt")).unwrap();
        std::fs::File::create(tmp.path().join("f2.txt")).unwrap();

        let mut dev = create_test_device(&tmp);
        dev.process_request(&build_tversion());
        dev.process_request(&build_tattach(0));

        // Walk to two different files.
        let resp1 = dev.process_request(&build_twalk(0, 1, &["f1.txt"]));
        let resp2 = dev.process_request(&build_twalk(0, 2, &["f2.txt"]));

        let mut r1 = ByteReader::new(&resp1);
        assert_eq!(P9Header::read_from(&mut r1).unwrap().msg_type, P9_RWALK);

        let mut r2 = ByteReader::new(&resp2);
        assert_eq!(P9Header::read_from(&mut r2).unwrap().msg_type, P9_RWALK);
    }

    // -- Short/malformed request --

    #[test]
    fn test_malformed_request() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);

        // Too short for a header.
        let resp = dev.process_request(&[0, 0, 0]);
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RLERROR);
    }

    // -- Flush --

    #[test]
    fn test_flush() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);

        let msg = build_response(P9_TFLUSH, 10, |w| {
            w.put_u16(5); // oldtag
        });
        let resp = dev.process_request(&msg);
        let mut r = ByteReader::new(&resp);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RFLUSH);
        assert_eq!(hdr.tag, 10);
    }

    // -- Empty chain handled --

    #[test]
    fn test_empty_chain_skipped() {
        let tmp = TempDir::new().unwrap();
        let mut dev = create_test_device(&tmp);
        let mem = MockMem::new(0x10000);
        let mut queue = setup_queue(128);

        // Descriptor with 0 length.
        write_descriptor(&mem, 0, BUF_BASE, 0, 0, 0);
        push_avail(&mem, 0, 0);

        let processed = dev.queue_notify(0, &mut queue, &mem);
        assert!(processed);
    }
}
