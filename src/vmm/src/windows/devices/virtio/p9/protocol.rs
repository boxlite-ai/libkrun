//! 9P2000.L wire protocol types and serialization.
//!
//! Implements the 9P2000.L message format used by Linux v9fs.
//! All multi-byte fields are little-endian. Messages have the format:
//!   size[4] type[1] tag[2] params...

// -- 9P message type constants --

pub const P9_RLERROR: u8 = 7;
pub const P9_TLOPEN: u8 = 12;
pub const P9_RLOPEN: u8 = 13;
pub const P9_TLCREATE: u8 = 14;
pub const P9_RLCREATE: u8 = 15;
pub const P9_TGETATTR: u8 = 24;
pub const P9_RGETATTR: u8 = 25;
pub const P9_TSETATTR: u8 = 26;
pub const P9_RSETATTR: u8 = 27;
pub const P9_TREADDIR: u8 = 40;
pub const P9_RREADDIR: u8 = 41;
pub const P9_TFSYNC: u8 = 50;
pub const P9_RFSYNC: u8 = 51;
pub const P9_TMKDIR: u8 = 72;
pub const P9_RMKDIR: u8 = 73;
pub const P9_TRENAMEAT: u8 = 74;
pub const P9_RRENAMEAT: u8 = 75;
pub const P9_TUNLINKAT: u8 = 76;
pub const P9_RUNLINKAT: u8 = 77;
pub const P9_TVERSION: u8 = 100;
pub const P9_RVERSION: u8 = 101;
pub const P9_TATTACH: u8 = 104;
pub const P9_RATTACH: u8 = 105;
pub const P9_TFLUSH: u8 = 108;
pub const P9_RFLUSH: u8 = 109;
pub const P9_TWALK: u8 = 110;
pub const P9_RWALK: u8 = 111;
pub const P9_TREAD: u8 = 116;
pub const P9_RREAD: u8 = 117;
pub const P9_TWRITE: u8 = 118;
pub const P9_RWRITE: u8 = 119;
pub const P9_TCLUNK: u8 = 120;
pub const P9_RCLUNK: u8 = 121;

/// No-fid sentinel.
pub const P9_NOFID: u32 = u32::MAX;

/// No-tag sentinel (used in Tversion).
pub const P9_NOTAG: u16 = u16::MAX;

/// 9P message header size (size[4] + type[1] + tag[2]).
pub const P9_HEADER_SIZE: usize = 7;

/// QID size in bytes (type[1] + version[4] + path[8]).
pub const QID_SIZE: usize = 13;

/// QID type: directory.
pub const QT_DIR: u8 = 0x80;
/// QID type: regular file.
pub const QT_FILE: u8 = 0x00;
/// QID type: symlink.
pub const QT_SYMLINK: u8 = 0x02;

/// Default maximum message size.
pub const DEFAULT_MSIZE: u32 = 8192 + P9_HEADER_SIZE as u32;

// -- QID --

/// 13-byte file identifier (type, version, path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

impl Qid {
    pub fn write_to(&self, w: &mut ByteWriter) {
        w.put_u8(self.qtype);
        w.put_u32(self.version);
        w.put_u64(self.path);
    }

    pub fn read_from(r: &mut ByteReader) -> Option<Self> {
        let qtype = r.get_u8()?;
        let version = r.get_u32()?;
        let path = r.get_u64()?;
        Some(Qid {
            qtype,
            version,
            path,
        })
    }
}

// -- P9 message header --

/// Parsed 9P message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P9Header {
    pub size: u32,
    pub msg_type: u8,
    pub tag: u16,
}

impl P9Header {
    pub fn read_from(r: &mut ByteReader) -> Option<Self> {
        let size = r.get_u32()?;
        let msg_type = r.get_u8()?;
        let tag = r.get_u16()?;
        Some(P9Header {
            size,
            msg_type,
            tag,
        })
    }

    pub fn write_to(&self, w: &mut ByteWriter) {
        w.put_u32(self.size);
        w.put_u8(self.msg_type);
        w.put_u16(self.tag);
    }
}

// -- Parsed T-message requests --

/// Parsed 9P T-message (client request).
#[derive(Debug)]
pub enum P9Request {
    Tversion {
        msize: u32,
        version: String,
    },
    Tattach {
        fid: u32,
        afid: u32,
        uname: String,
        aname: String,
    },
    Twalk {
        fid: u32,
        newfid: u32,
        names: Vec<String>,
    },
    Tlopen {
        fid: u32,
        flags: u32,
    },
    Tlcreate {
        fid: u32,
        name: String,
        flags: u32,
        mode: u32,
        gid: u32,
    },
    Tread {
        fid: u32,
        offset: u64,
        count: u32,
    },
    Twrite {
        fid: u32,
        offset: u64,
        count: u32,
        data: Vec<u8>,
    },
    Treaddir {
        fid: u32,
        offset: u64,
        count: u32,
    },
    Tgetattr {
        fid: u32,
        request_mask: u64,
    },
    Tsetattr {
        fid: u32,
        valid: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime_sec: u64,
        atime_nsec: u64,
        mtime_sec: u64,
        mtime_nsec: u64,
    },
    Tclunk {
        fid: u32,
    },
    Tflush {
        oldtag: u16,
    },
    Tmkdir {
        dfid: u32,
        name: String,
        mode: u32,
        gid: u32,
    },
    Trenameat {
        olddirfid: u32,
        oldname: String,
        newdirfid: u32,
        newname: String,
    },
    Tunlinkat {
        dirfid: u32,
        name: String,
        flags: u32,
    },
    Tfsync {
        fid: u32,
    },
}

/// Parse a T-message body (after header has been read).
pub fn parse_request(msg_type: u8, body: &[u8]) -> Option<P9Request> {
    let mut r = ByteReader::new(body);
    match msg_type {
        P9_TVERSION => {
            let msize = r.get_u32()?;
            let version = r.get_string()?;
            Some(P9Request::Tversion { msize, version })
        }
        P9_TATTACH => {
            let fid = r.get_u32()?;
            let afid = r.get_u32()?;
            let uname = r.get_string()?;
            let aname = r.get_string()?;
            Some(P9Request::Tattach {
                fid,
                afid,
                uname,
                aname,
            })
        }
        P9_TWALK => {
            let fid = r.get_u32()?;
            let newfid = r.get_u32()?;
            let nwname = r.get_u16()?;
            let mut names = Vec::with_capacity(nwname as usize);
            for _ in 0..nwname {
                names.push(r.get_string()?);
            }
            Some(P9Request::Twalk { fid, newfid, names })
        }
        P9_TLOPEN => {
            let fid = r.get_u32()?;
            let flags = r.get_u32()?;
            Some(P9Request::Tlopen { fid, flags })
        }
        P9_TLCREATE => {
            let fid = r.get_u32()?;
            let name = r.get_string()?;
            let flags = r.get_u32()?;
            let mode = r.get_u32()?;
            let gid = r.get_u32()?;
            Some(P9Request::Tlcreate {
                fid,
                name,
                flags,
                mode,
                gid,
            })
        }
        P9_TREAD => {
            let fid = r.get_u32()?;
            let offset = r.get_u64()?;
            let count = r.get_u32()?;
            Some(P9Request::Tread { fid, offset, count })
        }
        P9_TWRITE => {
            let fid = r.get_u32()?;
            let offset = r.get_u64()?;
            let count = r.get_u32()?;
            let data = r.get_bytes(count as usize)?;
            Some(P9Request::Twrite {
                fid,
                offset,
                count,
                data,
            })
        }
        P9_TREADDIR => {
            let fid = r.get_u32()?;
            let offset = r.get_u64()?;
            let count = r.get_u32()?;
            Some(P9Request::Treaddir { fid, offset, count })
        }
        P9_TGETATTR => {
            let fid = r.get_u32()?;
            let request_mask = r.get_u64()?;
            Some(P9Request::Tgetattr { fid, request_mask })
        }
        P9_TSETATTR => {
            let fid = r.get_u32()?;
            let valid = r.get_u32()?;
            let mode = r.get_u32()?;
            let uid = r.get_u32()?;
            let gid = r.get_u32()?;
            let size = r.get_u64()?;
            let atime_sec = r.get_u64()?;
            let atime_nsec = r.get_u64()?;
            let mtime_sec = r.get_u64()?;
            let mtime_nsec = r.get_u64()?;
            Some(P9Request::Tsetattr {
                fid,
                valid,
                mode,
                uid,
                gid,
                size,
                atime_sec,
                atime_nsec,
                mtime_sec,
                mtime_nsec,
            })
        }
        P9_TCLUNK => {
            let fid = r.get_u32()?;
            Some(P9Request::Tclunk { fid })
        }
        P9_TFLUSH => {
            let oldtag = r.get_u16()?;
            Some(P9Request::Tflush { oldtag })
        }
        P9_TMKDIR => {
            let dfid = r.get_u32()?;
            let name = r.get_string()?;
            let mode = r.get_u32()?;
            let gid = r.get_u32()?;
            Some(P9Request::Tmkdir {
                dfid,
                name,
                mode,
                gid,
            })
        }
        P9_TRENAMEAT => {
            let olddirfid = r.get_u32()?;
            let oldname = r.get_string()?;
            let newdirfid = r.get_u32()?;
            let newname = r.get_string()?;
            Some(P9Request::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            })
        }
        P9_TUNLINKAT => {
            let dirfid = r.get_u32()?;
            let name = r.get_string()?;
            let flags = r.get_u32()?;
            Some(P9Request::Tunlinkat {
                dirfid,
                name,
                flags,
            })
        }
        P9_TFSYNC => {
            let fid = r.get_u32()?;
            Some(P9Request::Tfsync { fid })
        }
        _ => None,
    }
}

// -- P9Attr: Rgetattr response payload --

/// File attributes for Rgetattr.
#[derive(Debug, Clone)]
pub struct P9Attr {
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

impl P9Attr {
    pub fn write_to(&self, w: &mut ByteWriter) {
        w.put_u64(self.valid);
        self.qid.write_to(w);
        w.put_u32(self.mode);
        w.put_u32(self.uid);
        w.put_u32(self.gid);
        w.put_u64(self.nlink);
        w.put_u64(self.rdev);
        w.put_u64(self.size);
        w.put_u64(self.blksize);
        w.put_u64(self.blocks);
        w.put_u64(self.atime_sec);
        w.put_u64(self.atime_nsec);
        w.put_u64(self.mtime_sec);
        w.put_u64(self.mtime_nsec);
        w.put_u64(self.ctime_sec);
        w.put_u64(self.ctime_nsec);
        w.put_u64(self.btime_sec);
        w.put_u64(self.btime_nsec);
        w.put_u64(self.gen);
        w.put_u64(self.data_version);
    }
}

// -- Response builders --

/// Build an Rlerror response body (after header).
pub fn write_rlerror(w: &mut ByteWriter, ecode: u32) {
    w.put_u32(ecode);
}

/// Build an Rversion response body.
pub fn write_rversion(w: &mut ByteWriter, msize: u32, version: &str) {
    w.put_u32(msize);
    w.put_string(version);
}

/// Build an Rattach response body.
pub fn write_rattach(w: &mut ByteWriter, qid: &Qid) {
    qid.write_to(w);
}

/// Build an Rwalk response body.
pub fn write_rwalk(w: &mut ByteWriter, qids: &[Qid]) {
    w.put_u16(qids.len() as u16);
    for qid in qids {
        qid.write_to(w);
    }
}

/// Build an Rlopen response body.
pub fn write_rlopen(w: &mut ByteWriter, qid: &Qid, iounit: u32) {
    qid.write_to(w);
    w.put_u32(iounit);
}

/// Build an Rlcreate response body.
pub fn write_rlcreate(w: &mut ByteWriter, qid: &Qid, iounit: u32) {
    qid.write_to(w);
    w.put_u32(iounit);
}

/// Build an Rread response body.
pub fn write_rread(w: &mut ByteWriter, data: &[u8]) {
    w.put_u32(data.len() as u32);
    w.put_raw(data);
}

/// Build an Rwrite response body.
pub fn write_rwrite(w: &mut ByteWriter, count: u32) {
    w.put_u32(count);
}

/// Build an Rreaddir response body.
pub fn write_rreaddir(w: &mut ByteWriter, data: &[u8]) {
    w.put_u32(data.len() as u32);
    w.put_raw(data);
}

/// Build an Rgetattr response body.
pub fn write_rgetattr(w: &mut ByteWriter, attr: &P9Attr) {
    attr.write_to(w);
}

/// Build an Rclunk response body (empty).
pub fn write_rclunk(_w: &mut ByteWriter) {
    // No body.
}

/// Build an Rflush response body (empty).
pub fn write_rflush(_w: &mut ByteWriter) {
    // No body.
}

/// Build an Rsetattr response body (empty).
pub fn write_rsetattr(_w: &mut ByteWriter) {
    // No body.
}

/// Build an Rmkdir response body.
pub fn write_rmkdir(w: &mut ByteWriter, qid: &Qid) {
    qid.write_to(w);
}

/// Build an Rrenameat response body (empty).
pub fn write_rrenameat(_w: &mut ByteWriter) {
    // No body.
}

/// Build an Runlinkat response body (empty).
pub fn write_runlinkat(_w: &mut ByteWriter) {
    // No body.
}

/// Build an Rfsync response body (empty).
pub fn write_rfsync(_w: &mut ByteWriter) {
    // No body.
}

// -- ByteReader: sequential reader over a byte slice --

/// Cursor for reading fields from a byte buffer.
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ByteReader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn get_u8(&mut self) -> Option<u8> {
        if self.pos + 1 > self.data.len() {
            return None;
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Some(val)
    }

    pub fn get_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(val)
    }

    pub fn get_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(val)
    }

    pub fn get_u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.data.len() {
            return None;
        }
        let val = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Some(val)
    }

    /// Read a 9P string: length[2] + data[length].
    pub fn get_string(&mut self) -> Option<String> {
        let len = self.get_u16()? as usize;
        let bytes = self.get_bytes(len)?;
        String::from_utf8(bytes).ok()
    }

    pub fn get_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        if self.pos + count > self.data.len() {
            return None;
        }
        let val = self.data[self.pos..self.pos + count].to_vec();
        self.pos += count;
        Some(val)
    }
}

// -- ByteWriter: sequential writer into a byte buffer --

/// Cursor for writing fields into a growable byte buffer.
pub struct ByteWriter {
    data: Vec<u8>,
}

impl Default for ByteWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteWriter {
    pub fn new() -> Self {
        ByteWriter { data: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        ByteWriter {
            data: Vec::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn put_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    pub fn put_u16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    pub fn put_u32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    pub fn put_u64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Write a 9P string: length[2] + data[length].
    pub fn put_string(&mut self, s: &str) {
        self.put_u16(s.len() as u16);
        self.data.extend_from_slice(s.as_bytes());
    }

    pub fn put_raw(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Patch a u32 at the given byte offset (used for message size fixup).
    pub fn patch_u32(&mut self, offset: usize, val: u32) {
        let bytes = val.to_le_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }
}

/// Build a complete 9P response message (header + body).
///
/// `msg_type` is the R-message type constant.
/// `tag` is the request tag to echo back.
/// `body_fn` writes the body fields into the ByteWriter.
pub fn build_response(msg_type: u8, tag: u16, body_fn: impl FnOnce(&mut ByteWriter)) -> Vec<u8> {
    let mut w = ByteWriter::with_capacity(128);
    // Reserve space for the size field.
    w.put_u32(0);
    w.put_u8(msg_type);
    w.put_u16(tag);
    body_fn(&mut w);
    // Patch the size field with the total message length.
    let total = w.len() as u32;
    w.patch_u32(0, total);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ByteReader tests --

    #[test]
    fn test_reader_u8() {
        let data = [0x42];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_u8(), Some(0x42));
        assert_eq!(r.get_u8(), None);
    }

    #[test]
    fn test_reader_u16() {
        let data = 0x1234u16.to_le_bytes();
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_u16(), Some(0x1234));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_reader_u32() {
        let data = 0xDEADBEEFu32.to_le_bytes();
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_u32(), Some(0xDEADBEEF));
    }

    #[test]
    fn test_reader_u64() {
        let data = 0x0102030405060708u64.to_le_bytes();
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_u64(), Some(0x0102030405060708));
    }

    #[test]
    fn test_reader_string() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend_from_slice(b"hello");
        let mut r = ByteReader::new(&buf);
        assert_eq!(r.get_string(), Some("hello".to_string()));
    }

    #[test]
    fn test_reader_empty_string() {
        let buf = 0u16.to_le_bytes();
        let mut r = ByteReader::new(&buf);
        assert_eq!(r.get_string(), Some(String::new()));
    }

    #[test]
    fn test_reader_truncated_returns_none() {
        let data = [0x01]; // Only 1 byte, but asking for u32.
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_u32(), None);
    }

    #[test]
    fn test_reader_bytes() {
        let data = [1, 2, 3, 4, 5];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.get_bytes(3), Some(vec![1, 2, 3]));
        assert_eq!(r.get_bytes(3), None); // Only 2 remaining.
        assert_eq!(r.get_bytes(2), Some(vec![4, 5]));
    }

    // -- ByteWriter tests --

    #[test]
    fn test_writer_roundtrip_u32() {
        let mut w = ByteWriter::new();
        w.put_u32(0xCAFEBABE);
        let mut r = ByteReader::new(w.as_bytes());
        assert_eq!(r.get_u32(), Some(0xCAFEBABE));
    }

    #[test]
    fn test_writer_string() {
        let mut w = ByteWriter::new();
        w.put_string("test");
        let mut r = ByteReader::new(w.as_bytes());
        assert_eq!(r.get_string(), Some("test".to_string()));
    }

    #[test]
    fn test_writer_patch_u32() {
        let mut w = ByteWriter::new();
        w.put_u32(0); // Placeholder.
        w.put_u8(0xFF);
        w.patch_u32(0, 42);
        assert_eq!(w.as_bytes()[0..4], 42u32.to_le_bytes());
        assert_eq!(w.as_bytes()[4], 0xFF);
    }

    #[test]
    fn test_writer_len() {
        let mut w = ByteWriter::new();
        assert_eq!(w.len(), 0);
        w.put_u32(0);
        assert_eq!(w.len(), 4);
        w.put_string("hi");
        assert_eq!(w.len(), 4 + 2 + 2); // u32 + u16_len + "hi"
    }

    // -- Header tests --

    #[test]
    fn test_header_roundtrip() {
        let hdr = P9Header {
            size: 23,
            msg_type: P9_TVERSION,
            tag: P9_NOTAG,
        };
        let mut w = ByteWriter::new();
        hdr.write_to(&mut w);
        assert_eq!(w.len(), P9_HEADER_SIZE);

        let mut r = ByteReader::new(w.as_bytes());
        let parsed = P9Header::read_from(&mut r).unwrap();
        assert_eq!(parsed, hdr);
    }

    // -- QID tests --

    #[test]
    fn test_qid_roundtrip() {
        let qid = Qid {
            qtype: QT_DIR,
            version: 12345,
            path: 0xDEAD_BEEF_CAFE,
        };
        let mut w = ByteWriter::new();
        qid.write_to(&mut w);
        assert_eq!(w.len(), QID_SIZE);

        let mut r = ByteReader::new(w.as_bytes());
        let parsed = Qid::read_from(&mut r).unwrap();
        assert_eq!(parsed, qid);
    }

    #[test]
    fn test_qid_file() {
        let qid = Qid {
            qtype: QT_FILE,
            version: 0,
            path: 1,
        };
        let mut w = ByteWriter::new();
        qid.write_to(&mut w);
        let mut r = ByteReader::new(w.as_bytes());
        let parsed = Qid::read_from(&mut r).unwrap();
        assert_eq!(parsed.qtype, QT_FILE);
    }

    // -- Request parsing tests --

    #[test]
    fn test_parse_tversion() {
        let mut w = ByteWriter::new();
        w.put_u32(8192); // msize
        w.put_string("9P2000.L");
        let req = parse_request(P9_TVERSION, w.as_bytes()).unwrap();
        match req {
            P9Request::Tversion { msize, version } => {
                assert_eq!(msize, 8192);
                assert_eq!(version, "9P2000.L");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tattach() {
        let mut w = ByteWriter::new();
        w.put_u32(0); // fid
        w.put_u32(P9_NOFID); // afid
        w.put_string("root");
        w.put_string("/share");
        let req = parse_request(P9_TATTACH, w.as_bytes()).unwrap();
        match req {
            P9Request::Tattach {
                fid,
                afid,
                uname,
                aname,
            } => {
                assert_eq!(fid, 0);
                assert_eq!(afid, P9_NOFID);
                assert_eq!(uname, "root");
                assert_eq!(aname, "/share");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_twalk_empty() {
        let mut w = ByteWriter::new();
        w.put_u32(0); // fid
        w.put_u32(1); // newfid
        w.put_u16(0); // nwname = 0
        let req = parse_request(P9_TWALK, w.as_bytes()).unwrap();
        match req {
            P9Request::Twalk { fid, newfid, names } => {
                assert_eq!(fid, 0);
                assert_eq!(newfid, 1);
                assert!(names.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_twalk_multi() {
        let mut w = ByteWriter::new();
        w.put_u32(0);
        w.put_u32(1);
        w.put_u16(3);
        w.put_string("usr");
        w.put_string("local");
        w.put_string("bin");
        let req = parse_request(P9_TWALK, w.as_bytes()).unwrap();
        match req {
            P9Request::Twalk { names, .. } => {
                assert_eq!(names, vec!["usr", "local", "bin"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tlopen() {
        let mut w = ByteWriter::new();
        w.put_u32(5); // fid
        w.put_u32(0); // O_RDONLY
        let req = parse_request(P9_TLOPEN, w.as_bytes()).unwrap();
        match req {
            P9Request::Tlopen { fid, flags } => {
                assert_eq!(fid, 5);
                assert_eq!(flags, 0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tread() {
        let mut w = ByteWriter::new();
        w.put_u32(3); // fid
        w.put_u64(100); // offset
        w.put_u32(4096); // count
        let req = parse_request(P9_TREAD, w.as_bytes()).unwrap();
        match req {
            P9Request::Tread { fid, offset, count } => {
                assert_eq!(fid, 3);
                assert_eq!(offset, 100);
                assert_eq!(count, 4096);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_twrite() {
        let mut w = ByteWriter::new();
        w.put_u32(3); // fid
        w.put_u64(0); // offset
        w.put_u32(5); // count
        w.put_raw(b"hello"); // data
        let req = parse_request(P9_TWRITE, w.as_bytes()).unwrap();
        match req {
            P9Request::Twrite {
                fid,
                offset,
                count,
                data,
            } => {
                assert_eq!(fid, 3);
                assert_eq!(offset, 0);
                assert_eq!(count, 5);
                assert_eq!(data, b"hello");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tclunk() {
        let mut w = ByteWriter::new();
        w.put_u32(7);
        let req = parse_request(P9_TCLUNK, w.as_bytes()).unwrap();
        match req {
            P9Request::Tclunk { fid } => assert_eq!(fid, 7),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tflush() {
        let mut w = ByteWriter::new();
        w.put_u16(42);
        let req = parse_request(P9_TFLUSH, w.as_bytes()).unwrap();
        match req {
            P9Request::Tflush { oldtag } => assert_eq!(oldtag, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tgetattr() {
        let mut w = ByteWriter::new();
        w.put_u32(1);
        w.put_u64(0x3FFF); // request_mask: all valid bits
        let req = parse_request(P9_TGETATTR, w.as_bytes()).unwrap();
        match req {
            P9Request::Tgetattr { fid, request_mask } => {
                assert_eq!(fid, 1);
                assert_eq!(request_mask, 0x3FFF);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_treaddir() {
        let mut w = ByteWriter::new();
        w.put_u32(2); // fid
        w.put_u64(0); // offset
        w.put_u32(8192); // count
        let req = parse_request(P9_TREADDIR, w.as_bytes()).unwrap();
        match req {
            P9Request::Treaddir { fid, offset, count } => {
                assert_eq!(fid, 2);
                assert_eq!(offset, 0);
                assert_eq!(count, 8192);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tmkdir() {
        let mut w = ByteWriter::new();
        w.put_u32(1); // dfid
        w.put_string("newdir");
        w.put_u32(0o755); // mode
        w.put_u32(0); // gid
        let req = parse_request(P9_TMKDIR, w.as_bytes()).unwrap();
        match req {
            P9Request::Tmkdir {
                dfid,
                name,
                mode,
                gid,
            } => {
                assert_eq!(dfid, 1);
                assert_eq!(name, "newdir");
                assert_eq!(mode, 0o755);
                assert_eq!(gid, 0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tunlinkat() {
        let mut w = ByteWriter::new();
        w.put_u32(1); // dirfid
        w.put_string("oldfile");
        w.put_u32(0); // flags
        let req = parse_request(P9_TUNLINKAT, w.as_bytes()).unwrap();
        match req {
            P9Request::Tunlinkat {
                dirfid,
                name,
                flags,
            } => {
                assert_eq!(dirfid, 1);
                assert_eq!(name, "oldfile");
                assert_eq!(flags, 0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_trenameat() {
        let mut w = ByteWriter::new();
        w.put_u32(1); // olddirfid
        w.put_string("old.txt");
        w.put_u32(2); // newdirfid
        w.put_string("new.txt");
        let req = parse_request(P9_TRENAMEAT, w.as_bytes()).unwrap();
        match req {
            P9Request::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                assert_eq!(olddirfid, 1);
                assert_eq!(oldname, "old.txt");
                assert_eq!(newdirfid, 2);
                assert_eq!(newname, "new.txt");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tfsync() {
        let mut w = ByteWriter::new();
        w.put_u32(5);
        let req = parse_request(P9_TFSYNC, w.as_bytes()).unwrap();
        match req {
            P9Request::Tfsync { fid } => assert_eq!(fid, 5),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tlcreate() {
        let mut w = ByteWriter::new();
        w.put_u32(1); // fid
        w.put_string("newfile.txt");
        w.put_u32(0x42); // flags (O_CREAT|O_RDWR)
        w.put_u32(0o644); // mode
        w.put_u32(0); // gid
        let req = parse_request(P9_TLCREATE, w.as_bytes()).unwrap();
        match req {
            P9Request::Tlcreate {
                fid,
                name,
                flags,
                mode,
                gid,
            } => {
                assert_eq!(fid, 1);
                assert_eq!(name, "newfile.txt");
                assert_eq!(flags, 0x42);
                assert_eq!(mode, 0o644);
                assert_eq!(gid, 0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_tsetattr() {
        let mut w = ByteWriter::new();
        w.put_u32(3); // fid
        w.put_u32(0x01); // valid (mode)
        w.put_u32(0o755); // mode
        w.put_u32(0); // uid
        w.put_u32(0); // gid
        w.put_u64(0); // size
        w.put_u64(0); // atime_sec
        w.put_u64(0); // atime_nsec
        w.put_u64(0); // mtime_sec
        w.put_u64(0); // mtime_nsec
        let req = parse_request(P9_TSETATTR, w.as_bytes()).unwrap();
        match req {
            P9Request::Tsetattr {
                fid, valid, mode, ..
            } => {
                assert_eq!(fid, 3);
                assert_eq!(valid, 0x01);
                assert_eq!(mode, 0o755);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_unknown_type_returns_none() {
        assert!(parse_request(0xFF, &[]).is_none());
    }

    // -- Response builder tests --

    #[test]
    fn test_build_rversion() {
        let msg = build_response(P9_RVERSION, P9_NOTAG, |w| {
            write_rversion(w, 8192, "9P2000.L");
        });
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RVERSION);
        assert_eq!(hdr.tag, P9_NOTAG);
        assert_eq!(hdr.size as usize, msg.len());

        let msize = r.get_u32().unwrap();
        let version = r.get_string().unwrap();
        assert_eq!(msize, 8192);
        assert_eq!(version, "9P2000.L");
    }

    #[test]
    fn test_build_rlerror() {
        let msg = build_response(P9_RLERROR, 1, |w| {
            write_rlerror(w, 2); // ENOENT
        });
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RLERROR);
        assert_eq!(hdr.tag, 1);
        let ecode = r.get_u32().unwrap();
        assert_eq!(ecode, 2);
    }

    #[test]
    fn test_build_rwalk() {
        let qids = vec![
            Qid {
                qtype: QT_DIR,
                version: 1,
                path: 100,
            },
            Qid {
                qtype: QT_FILE,
                version: 2,
                path: 200,
            },
        ];
        let msg = build_response(P9_RWALK, 5, |w| {
            write_rwalk(w, &qids);
        });
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RWALK);
        let nwqid = r.get_u16().unwrap();
        assert_eq!(nwqid, 2);
        let q1 = Qid::read_from(&mut r).unwrap();
        assert_eq!(q1.path, 100);
        let q2 = Qid::read_from(&mut r).unwrap();
        assert_eq!(q2.path, 200);
    }

    #[test]
    fn test_build_rread() {
        let msg = build_response(P9_RREAD, 3, |w| {
            write_rread(w, b"file data");
        });
        let mut r = ByteReader::new(&msg);
        let _hdr = P9Header::read_from(&mut r).unwrap();
        let count = r.get_u32().unwrap();
        assert_eq!(count, 9);
        let data = r.get_bytes(count as usize).unwrap();
        assert_eq!(data, b"file data");
    }

    #[test]
    fn test_build_rwrite() {
        let msg = build_response(P9_RWRITE, 3, |w| {
            write_rwrite(w, 42);
        });
        let mut r = ByteReader::new(&msg);
        let _hdr = P9Header::read_from(&mut r).unwrap();
        let count = r.get_u32().unwrap();
        assert_eq!(count, 42);
    }

    #[test]
    fn test_build_rlopen() {
        let qid = Qid {
            qtype: QT_FILE,
            version: 1,
            path: 42,
        };
        let msg = build_response(P9_RLOPEN, 2, |w| {
            write_rlopen(w, &qid, 4096);
        });
        let mut r = ByteReader::new(&msg);
        let _hdr = P9Header::read_from(&mut r).unwrap();
        let q = Qid::read_from(&mut r).unwrap();
        assert_eq!(q, qid);
        let iounit = r.get_u32().unwrap();
        assert_eq!(iounit, 4096);
    }

    #[test]
    fn test_build_rattach() {
        let qid = Qid {
            qtype: QT_DIR,
            version: 0,
            path: 1,
        };
        let msg = build_response(P9_RATTACH, 0, |w| {
            write_rattach(w, &qid);
        });
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RATTACH);
        let q = Qid::read_from(&mut r).unwrap();
        assert_eq!(q, qid);
    }

    #[test]
    fn test_build_response_size_correct() {
        // Rclunk is header-only (7 bytes total).
        let msg = build_response(P9_RCLUNK, 10, |w| {
            write_rclunk(w);
        });
        assert_eq!(msg.len(), P9_HEADER_SIZE);
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.size as usize, P9_HEADER_SIZE);
    }

    #[test]
    fn test_build_rmkdir() {
        let qid = Qid {
            qtype: QT_DIR,
            version: 3,
            path: 99,
        };
        let msg = build_response(P9_RMKDIR, 7, |w| {
            write_rmkdir(w, &qid);
        });
        let mut r = ByteReader::new(&msg);
        let hdr = P9Header::read_from(&mut r).unwrap();
        assert_eq!(hdr.msg_type, P9_RMKDIR);
        let q = Qid::read_from(&mut r).unwrap();
        assert_eq!(q, qid);
    }
}
