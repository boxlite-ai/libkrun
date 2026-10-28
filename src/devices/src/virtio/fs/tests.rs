// Every test name starts with "snapshot_fs" so `make snapshot-test` selects
// them. Linux only: the checkpointable share is the Linux passthrough.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::mem::{self, size_of};
use std::num::Wrapping;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::defs::{HPQ_INDEX, NUM_QUEUES, QUEUE_SIZE, REQ_INDEX};
use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, SetattrValid,
};
use super::fuse::{
    self, AttrOut, Dirent, EntryOut, GetattrIn, InHeader, InitInCompat, Opcode, OpenIn, OpenOut,
    OutHeader, ReadIn, RemovemappingIn, RemovemappingOne, SetupmappingFlags, SetupmappingIn,
    WriteIn,
};
use super::passthrough::{
    self, DaxMapping, DaxMappingControl, DaxMappingKind, DaxPages, DaxState, DaxWindow,
    PassthroughCheckpoint, PassthroughFs, PassthroughSnapshotError, PassthroughState,
    RestoredObject, SnapshotObject, DAX_PAGE_SIZE, SYNTHETIC_INO_BASE,
};
use super::worker::{request_gate, FsServer};
use super::{Fs, FsSessionCheckpoint};
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{
    Descriptor, DeviceQueue, InterruptTransport, Queue, VirtioDevice, VirtioShmRegion,
    VIRTIO_MMIO_INT_VRING,
};

const QSIZE: u16 = 16;
const MEM_SIZE: usize = 0x40_0000;
const RINGS: u64 = 0x1_0000;
const BUFS: u64 = 0x4_0000;
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);
const REPLY: u32 = 0x2000;
const CTX: Context = Context {
    uid: 0,
    gid: 0,
    pid: 0,
};

/// A unique host directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "snapshot-fs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, contents: &[u8]) {
        fs::write(self.0.join(name), contents).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn snapshot_config(dir: &Path) -> passthrough::Config {
    passthrough::Config {
        root_dir: dir.to_path_buf(),
        snapshot: true,
        ..Default::default()
    }
}

/// A fresh `O_PATH` descriptor of the object behind `file`.
fn o_path(file: &File) -> File {
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    // Safe because the path is a valid C string and we check the result.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    // Safe because we just opened this fd.
    unsafe { File::from_raw_fd(fd) }
}

/// Same-host restore objects: the checkpointed objects themselves (the
/// archive tests in `tests/archive.rs` rebuild them elsewhere).
fn same_host_objects(checkpoint: &PassthroughCheckpoint) -> Vec<RestoredObject> {
    checkpoint
        .objects
        .iter()
        .map(|o| RestoredObject {
            file: o_path(&o.file),
            guest_ino: o.guest_ino,
            ctime: o.ctime,
        })
        .collect()
}

/// The driver side of both queues (rings at fixed addresses, a bump
/// allocator, cursors starting at `start` to cross the u16 wrap).
struct Guest {
    mem: GuestMemoryMmap,
    start: u16,
    posted: [u16; NUM_QUEUES],
    next_desc: [u16; NUM_QUEUES],
    next_buf: u64,
    unique: u64,
}

impl Guest {
    fn new(start: u16) -> Guest {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
        let guest = Guest {
            mem,
            start,
            posted: [start; NUM_QUEUES],
            next_desc: [0; NUM_QUEUES],
            next_buf: BUFS,
            unique: 1,
        };
        for q in 0..NUM_QUEUES {
            guest
                .mem
                .write_obj(start, guest.avail(q).unchecked_add(2))
                .unwrap();
            guest
                .mem
                .write_obj(start, guest.used_ring(q).unchecked_add(2))
                .unwrap();
        }
        guest
    }

    /// The same driver state over a copy of this guest's RAM.
    fn copy(&self) -> Guest {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
        let mut ram = vec![0u8; MEM_SIZE];
        self.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
        mem.write_slice(&ram, GuestAddress(0)).unwrap();
        Guest {
            mem,
            start: self.start,
            posted: self.posted,
            next_desc: self.next_desc,
            next_buf: self.next_buf,
            unique: self.unique,
        }
    }

    fn desc(&self, q: usize) -> GuestAddress {
        GuestAddress(RINGS + q as u64 * 0x1000)
    }

    fn avail(&self, q: usize) -> GuestAddress {
        self.desc(q).unchecked_add(0x200)
    }

    fn used_ring(&self, q: usize) -> GuestAddress {
        self.desc(q).unchecked_add(0x400)
    }

    fn queue(&self, q: usize) -> Queue {
        let mut queue = Queue::new(QUEUE_SIZE);
        queue.size = QSIZE;
        queue.ready = true;
        queue.desc_table = self.desc(q);
        queue.avail_ring = self.avail(q);
        queue.used_ring = self.used_ring(q);
        queue.next_avail = Wrapping(self.start);
        queue.next_used = Wrapping(self.start);
        queue
    }

    fn alloc(&mut self, len: u32) -> GuestAddress {
        let addr = GuestAddress(self.next_buf);
        self.next_buf += u64::from(len).next_multiple_of(0x100);
        assert!(self.next_buf <= MEM_SIZE as u64);
        addr
    }

    /// Post a FUSE request (header + `body`) with a `REPLY`-byte reply
    /// buffer on queue `q`; returns the request's unique ID and the reply
    /// address. Like the Linux driver, the reply header gets its own
    /// descriptor. Nothing is kicked.
    fn post(&mut self, q: usize, opcode: Opcode, nodeid: u64, body: &[u8]) -> (u64, GuestAddress) {
        let unique = self.unique;
        self.unique += 1;
        let header = InHeader {
            len: (size_of::<InHeader>() + body.len()) as u32,
            opcode: opcode as u32,
            unique,
            nodeid,
            ..Default::default()
        };
        let mut request = header.as_slice().to_vec();
        request.extend_from_slice(body);
        let input = self.alloc(request.len() as u32);
        self.mem.write_slice(&request, input).unwrap();
        let output = self.alloc(REPLY);
        let head = self.next_desc[q];
        let out_header = size_of::<OutHeader>() as u32;
        let bufs = [
            (input, request.len() as u32, 0),
            (output, out_header, VIRTQ_DESC_F_WRITE),
            (
                output.unchecked_add(u64::from(out_header)),
                REPLY - out_header,
                VIRTQ_DESC_F_WRITE,
            ),
        ];
        for (i, (addr, len, flags)) in bufs.into_iter().enumerate() {
            let index = (head + i as u16) % QSIZE;
            let desc = Descriptor {
                addr: addr.0,
                len,
                flags: if i + 1 < bufs.len() {
                    flags | VIRTQ_DESC_F_NEXT
                } else {
                    flags
                },
                next: (index + 1) % QSIZE,
            };
            self.mem
                .write_obj(desc, self.desc(q).unchecked_add(16 * u64::from(index)))
                .unwrap();
        }
        self.next_desc[q] = (head + bufs.len() as u16) % QSIZE;
        let slot = u64::from(self.posted[q] % QSIZE);
        self.mem
            .write_obj(head, self.avail(q).unchecked_add(4 + 2 * slot))
            .unwrap();
        self.posted[q] = self.posted[q].wrapping_add(1);
        self.mem
            .write_obj(self.posted[q], self.avail(q).unchecked_add(2))
            .unwrap();
        (unique, output)
    }

    /// Number of used entries since the start cursor.
    fn used(&self, q: usize) -> u16 {
        let idx: u16 = self
            .mem
            .read_obj(self.used_ring(q).unchecked_add(2))
            .unwrap();
        idx.wrapping_sub(self.start)
    }

    /// The reply at `addr`: its header and payload.
    fn reply(&self, addr: GuestAddress) -> (OutHeader, Vec<u8>) {
        let header: OutHeader = self.mem.read_obj(addr).unwrap();
        let len = header.len as usize - size_of::<OutHeader>();
        let mut payload = vec![0u8; len];
        self.mem
            .read_slice(
                &mut payload,
                addr.unchecked_add(size_of::<OutHeader>() as u64),
            )
            .unwrap();
        (header, payload)
    }
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// An activated snapshot-mode device over `Guest`, stopped on drop.
struct Rig {
    guest: Guest,
    fs: Fs,
    interrupt: InterruptTransport,
    events: Vec<Arc<EventFd>>,
}

impl Rig {
    fn new(dir: &Path) -> Rig {
        let guest = Guest::new(0xfffe);
        let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
        Rig::activate(guest, Rig::device(dir), queues, false)
    }

    fn device(dir: &Path) -> Fs {
        let mut fs = Fs::new(
            "snapfs".to_string(),
            dir.to_str().unwrap().to_string(),
            Arc::new(AtomicI32::new(0)),
            false,
            false,
        )
        .unwrap();
        fs.enable_snapshot();
        fs
    }

    fn activate(guest: Guest, mut fs: Fs, queues: Vec<Queue>, frozen: bool) -> Rig {
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
        let events: Vec<_> = (0..NUM_QUEUES)
            .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            .collect();
        let queues = queues
            .into_iter()
            .zip(&events)
            .map(|(q, e)| DeviceQueue::new(q, e.clone()))
            .collect();
        if frozen {
            fs.activate_frozen(guest.mem.clone(), interrupt.clone(), queues)
                .unwrap();
        } else {
            fs.activate(guest.mem.clone(), interrupt.clone(), queues)
                .unwrap();
        }
        Rig {
            guest,
            fs,
            interrupt,
            events,
        }
    }

    /// Restore from a frozen source: RAM copied, queues rebuilt from the
    /// cut, the checkpointed session restored on the same host objects.
    fn restored(source: &Rig, dir: &Path, queues: &[QueueState]) -> Rig {
        Rig::restored_with_init(source, dir, queues, None)
    }

    /// `restored`, serving `init` (when given) as the archived init.krun.
    fn restored_with_init(
        source: &Rig,
        dir: &Path,
        queues: &[QueueState],
        init: Option<Arc<[u8]>>,
    ) -> Rig {
        let session = source.fs.snapshot_session().unwrap().unwrap();
        let guest = source.guest.copy();
        for queue in queues {
            queue.validate(&guest.mem, true).unwrap();
        }
        let mut fs = Rig::device(dir);
        fs.restore_session(
            session.options,
            &session.passthrough.state,
            same_host_objects(&session.passthrough),
            init.unwrap_or_else(|| session.passthrough.init_binary.clone()),
            &session.passthrough.dax_pages,
        )
        .unwrap();
        let queues = queues.iter().map(QueueState::to_queue).collect();
        Rig::activate(guest, fs, queues, true)
    }

    fn kick(&self, q: usize) {
        self.events[q].write(1).unwrap();
    }

    /// Post, kick and wait for one request's reply.
    fn call(&mut self, opcode: Opcode, nodeid: u64, body: &[u8]) -> (OutHeader, Vec<u8>) {
        let before = self.guest.used(REQ_INDEX);
        let (unique, reply) = self.guest.post(REQ_INDEX, opcode, nodeid, body);
        self.kick(REQ_INDEX);
        wait_until("reply", || self.guest.used(REQ_INDEX) != before);
        let (header, payload) = self.guest.reply(reply);
        assert_eq!(header.unique, unique);
        (header, payload)
    }

    fn ok(&mut self, opcode: Opcode, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let (header, payload) = self.call(opcode, nodeid, body);
        assert_eq!(header.error, 0, "{opcode:?} failed");
        payload
    }

    fn init(&mut self) {
        let init = InitInCompat {
            major: fuse::KERNEL_VERSION,
            minor: fuse::KERNEL_MINOR_VERSION,
            max_readahead: 0,
            flags: (FsOptions::ASYNC_READ | FsOptions::BIG_WRITES).bits() as u32,
        };
        self.ok(Opcode::Init, 0, init.as_slice());
    }

    fn lookup(&mut self, parent: u64, name: &str) -> EntryOut {
        let payload = self.ok(Opcode::Lookup, parent, cstr(name).as_bytes_with_nul());
        *EntryOut::from_slice(&payload).unwrap()
    }

    fn open(&mut self, opcode: Opcode, nodeid: u64, flags: i32) -> u64 {
        let open = OpenIn {
            flags: flags as u32,
            open_flags: 0,
        };
        let payload = self.ok(opcode, nodeid, open.as_slice());
        OpenOut::from_slice(&payload).unwrap().fh
    }

    fn read(&mut self, nodeid: u64, fh: u64, size: u32) -> Vec<u8> {
        let read = ReadIn {
            fh,
            size,
            ..Default::default()
        };
        self.ok(Opcode::Read, nodeid, read.as_slice())
    }

    fn write(&mut self, nodeid: u64, fh: u64, data: &[u8]) {
        let write = WriteIn {
            fh,
            size: data.len() as u32,
            ..Default::default()
        };
        let mut body = write.as_slice().to_vec();
        body.extend_from_slice(data);
        self.ok(Opcode::Write, nodeid, &body);
    }

    /// READDIR: (name, ino, offset cookie) per entry.
    fn readdir(&mut self, fh: u64, offset: u64, size: u32) -> Vec<(String, u64, u64)> {
        let read = ReadIn {
            fh,
            offset,
            size,
            ..Default::default()
        };
        let payload = self.ok(Opcode::Readdir, fuse::ROOT_ID, read.as_slice());
        let mut entries = Vec::new();
        let mut rem = &payload[..];
        while !rem.is_empty() {
            let dirent = *Dirent::from_slice(&rem[..size_of::<Dirent>()]).unwrap();
            let name = &rem[size_of::<Dirent>()..size_of::<Dirent>() + dirent.namelen as usize];
            entries.push((
                String::from_utf8(name.to_vec()).unwrap(),
                dirent.ino,
                dirent.off,
            ));
            let len = (size_of::<Dirent>() + dirent.namelen as usize).next_multiple_of(8);
            rem = &rem[len..];
        }
        entries
    }

    fn getattr(&mut self, nodeid: u64) -> AttrOut {
        let payload = self.ok(Opcode::Getattr, nodeid, GetattrIn::default().as_slice());
        *AttrOut::from_slice(&payload).unwrap()
    }

    fn freeze(&self) -> Vec<QueueState> {
        let cut = self
            .fs
            .worker_control()
            .unwrap()
            .freeze_with_timeout(WAIT)
            .unwrap();
        cut.queues
    }

    fn resume(&self) {
        self.fs
            .worker_control()
            .unwrap()
            .resume_with_timeout(WAIT)
            .unwrap();
    }

    fn interrupted(&self) -> bool {
        self.interrupt.status().load(Ordering::SeqCst) & VIRTIO_MMIO_INT_VRING as usize != 0
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.fs.reset();
    }
}

#[test]
fn snapshot_fs_freeze_lands_after_reply_used_entry_and_interrupt() {
    let dir = TempDir::new();
    let mut rig = Rig::new(dir.path());
    rig.init();
    rig.interrupt.status().store(0, Ordering::SeqCst);

    // Hold the next request after it was popped: a freeze must wait for
    // the complete reply, used entry and interrupt.
    let (arrived, release, _guard) = request_gate::install(&rig.events[REQ_INDEX]);
    let (unique, reply) = rig.guest.post(
        REQ_INDEX,
        Opcode::Getattr,
        fuse::ROOT_ID,
        GetattrIn::default().as_slice(),
    );
    rig.kick(REQ_INDEX);
    arrived.recv_timeout(WAIT).unwrap();
    let cut = thread::scope(|s| {
        let freezer = s.spawn(|| rig.freeze());
        thread::sleep(QUIET);
        assert!(!freezer.is_finished(), "freeze confirmed inside a request");
        assert_eq!(rig.guest.used(REQ_INDEX), 1);
        release.send(()).unwrap();
        freezer.join().unwrap()
    });
    assert_eq!(rig.guest.used(REQ_INDEX), 2);
    let (header, _) = rig.guest.reply(reply);
    assert_eq!((header.unique, header.error), (unique, 0));
    assert!(rig.interrupted());
    // Both cursors cover exactly the completed requests (across the wrap).
    assert_eq!(cut[REQ_INDEX].next_avail, 0xfffe_u16.wrapping_add(2));
    assert_eq!(cut[REQ_INDEX].next_used, 0xfffe_u16.wrapping_add(2));
    assert_eq!(cut[HPQ_INDEX].next_avail, 0xfffe);
    for queue in &cut {
        queue.validate(&rig.guest.mem, true).unwrap();
    }

    // Frozen: a kicked request stays untouched, then a resume without any
    // new kick serves it.
    rig.interrupt.status().store(0, Ordering::SeqCst);
    rig.guest.post(
        REQ_INDEX,
        Opcode::Getattr,
        fuse::ROOT_ID,
        GetattrIn::default().as_slice(),
    );
    rig.kick(REQ_INDEX);
    thread::sleep(QUIET);
    assert_eq!(rig.guest.used(REQ_INDEX), 2);
    assert!(!rig.interrupted());
    // Repeated freezes of one cut report the same cursors.
    assert_eq!(rig.freeze(), cut);
    rig.resume();
    assert_eq!(rig.guest.used(REQ_INDEX), 3);
    assert!(rig.interrupted());
}

#[test]
fn snapshot_fs_restored_session_continues_without_init() {
    let dir = TempDir::new();
    dir.file("data", b"hello snapshot");
    dir.file("log", b"stale");
    for name in ["d1", "d2", "d3", "d4", "d5", "d6"] {
        dir.file(name, b"");
    }
    let mut source = Rig::new(dir.path());
    source.init();
    let data = source.lookup(fuse::ROOT_ID, "data");
    let data_fh = source.open(Opcode::Open, data.nodeid, libc::O_RDONLY);
    let log = source.lookup(fuse::ROOT_ID, "log");
    // O_TRUNC applies once, in the source; the restore must not replay it.
    let log_fh = source.open(
        Opcode::Open,
        log.nodeid,
        libc::O_WRONLY | libc::O_APPEND | libc::O_TRUNC,
    );
    source.write(log.nodeid, log_fh, b"abc");
    let dir_fh = source.open(Opcode::Opendir, fuse::ROOT_ID, libc::O_RDONLY);
    // A small reply buffer: the guest consumed only part of the stream.
    let first = source.readdir(dir_fh, 0, 112);
    assert!(!first.is_empty());
    let cookie = first.last().unwrap().2;
    let mut whole = first.clone();
    let rest = source.readdir(dir_fh, cookie, 4096);
    whole.extend(rest.iter().cloned());
    assert_eq!(whole.len(), 10, "., .., data, log and six files");
    // Offsets are list indexes, independent of the host d_off.
    for (index, (_, _, off)) in whole.iter().enumerate() {
        assert_eq!(*off, index as u64 + 1);
    }

    let queues = source.freeze();
    let session = source.fs.snapshot_session().unwrap().unwrap();
    assert_eq!(
        session.options,
        (FsOptions::ASYNC_READ | FsOptions::BIG_WRITES).bits()
    );
    // The restored stream continues from the saved list even after the
    // host directory changed under it.
    let unread = rest
        .iter()
        .map(|e| e.0.clone())
        .find(|n| n.len() == 2 && n.starts_with('d'))
        .unwrap();
    fs::remove_file(dir.path().join(&unread)).unwrap();
    dir.file("late", b"");

    let mut target = Rig::restored(&source, dir.path(), &queues);
    // Nothing runs before the owner resumes the restored worker.
    target.guest.post(
        REQ_INDEX,
        Opcode::Getattr,
        data.nodeid,
        GetattrIn::default().as_slice(),
    );
    target.kick(REQ_INDEX);
    thread::sleep(QUIET);
    assert_eq!(target.guest.used(REQ_INDEX), source.guest.used(REQ_INDEX));
    target.resume();
    wait_until("pending request", || {
        target.guest.used(REQ_INDEX) == source.guest.used(REQ_INDEX).wrapping_add(1)
    });

    // Original node IDs and handles, no FUSE_INIT.
    assert_eq!(target.read(data.nodeid, data_fh, 64), b"hello snapshot");
    target.write(log.nodeid, log_fh, b"X");
    assert_eq!(fs::read(dir.path().join("log")).unwrap(), b"abcX");
    assert_eq!(target.getattr(data.nodeid).attr.ino, data.attr.ino);
    assert_eq!(target.readdir(dir_fh, cookie, 4096), rest);
    // A rewind lists the directory as it is now.
    let relisted: Vec<_> = target
        .readdir(dir_fh, 0, 4096)
        .into_iter()
        .map(|e| e.0)
        .collect();
    assert!(relisted.contains(&"late".to_string()));
    assert!(!relisted.contains(&unread));
    // New IDs never collide with restored ones.
    let late = target.lookup(fuse::ROOT_ID, "late");
    assert_eq!(late.nodeid, session.passthrough.state.next_inode);
    assert_eq!(
        target.open(Opcode::Open, late.nodeid, libc::O_RDONLY),
        session.passthrough.state.next_handle
    );

    // The source continues independently after its own resume.
    source.resume();
    assert_eq!(source.read(data.nodeid, data_fh, 64), b"hello snapshot");
}

#[test]
fn snapshot_fs_frozen_start_keeps_pending_requests_until_resume() {
    let dir = TempDir::new();
    let mut source = Rig::new(dir.path());
    source.init();
    let queues = source.freeze();
    // The driver queued a request on the high-priority queue right at the
    // cut; its notification is lost with the source.
    let (unique, reply) = source.guest.post(
        HPQ_INDEX,
        Opcode::Getattr,
        fuse::ROOT_ID,
        GetattrIn::default().as_slice(),
    );
    let target = Rig::restored(&source, dir.path(), &queues);
    thread::sleep(QUIET);
    assert_eq!(target.guest.used(HPQ_INDEX), 0);
    assert!(!target.interrupted());
    target.resume();
    assert_eq!(target.guest.used(HPQ_INDEX), 1);
    let (header, _) = target.guest.reply(reply);
    assert_eq!((header.unique, header.error), (unique, 0));
    assert!(target.interrupted());
}

fn init_share(dir: &Path) -> PassthroughFs {
    let fs = PassthroughFs::new(snapshot_config(dir)).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn names(fs: &PassthroughFs, handle: u64, offset: u64, size: u32) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    fs.readdir(CTX, fuse::ROOT_ID, handle, size, offset, |d: DirEntry| {
        out.push((d.name.to_vec(), d.offset));
        Ok(1)
    })
    .unwrap();
    out
}

#[test]
fn snapshot_fs_directory_list_is_stable_across_changes_and_restore() {
    let dir = TempDir::new();
    for name in ["a", "b", "c"] {
        dir.file(name, b"");
    }
    let fs = init_share(dir.path());
    let (handle, _) = fs.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    let handle = handle.unwrap();
    let mut taken = Vec::new();
    // Consume two entries, then change the directory.
    fs.readdir(CTX, fuse::ROOT_ID, handle, 4096, 0, |d: DirEntry| {
        taken.push(d.name.to_vec());
        Ok(if taken.len() < 2 { 1 } else { 0 })
    })
    .unwrap();
    let all = names(&fs, handle, 0, 4096);
    let unread = all[2..]
        .iter()
        .map(|(n, _)| n.clone())
        .find(|n| n != b"." && n != b"..")
        .unwrap();
    fs::remove_file(dir.path().join(OsStr::from_bytes(&unread))).unwrap();
    dir.file("new", b"");
    // Continuing at index 2 replays the list taken at offset 0 (the
    // rewind above), so the removed name stays and the new one is absent.
    assert_eq!(names(&fs, handle, 2, 4096), all[2..].to_vec());

    // readdirplus skips the vanished name without failing the reply.
    let mut plus = Vec::new();
    fs.readdirplus(
        CTX,
        fuse::ROOT_ID,
        handle,
        4096,
        2,
        |d: DirEntry, e: Entry| {
            plus.push((d.name.to_vec(), e.inode));
            Ok(1)
        },
    )
    .unwrap();
    assert!(plus.iter().all(|(n, _)| *n != unread));
    // Dot entries are not looked up: ".." of the root is outside the share.
    assert!(plus
        .iter()
        .filter(|(n, _)| n == b"." || n == b"..")
        .all(|(_, inode)| *inode == 0));
    assert_eq!(plus.len(), all.len() - 3);

    // The checkpoint captures the list; a restored stream continues it.
    let checkpoint = fs.checkpoint().unwrap();
    let state = &checkpoint.state.handles[0];
    let listed: Vec<_> = state
        .listing
        .as_ref()
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert_eq!(
        listed,
        all.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>()
    );
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    assert_eq!(names(&restored, handle, 2, 4096), all[2..].to_vec());
    let rewound: Vec<_> = names(&restored, handle, 0, 4096)
        .into_iter()
        .map(|e| e.0)
        .collect();
    assert!(rewound.contains(&b"new".to_vec()) && !rewound.contains(&unread));
}

#[test]
fn snapshot_fs_listing_only_projection_survives_restore() {
    let dir = TempDir::new();
    dir.file("surviving", b"untouched");
    dir.file("stale", b"removed before capture");
    let source = init_share(dir.path());
    let handle = source.opendir(CTX, fuse::ROOT_ID, 0).unwrap().0.unwrap();
    let listed = names(&source, handle, 0, 4096);
    fs::remove_file(dir.path().join("stale")).unwrap();
    let checkpoint = source.checkpoint().unwrap();
    let ino = checkpoint.state.handles[0]
        .listing
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.name == b"surviving")
        .unwrap()
        .ino;
    // Only the directory is retained; cached names have no object FD.
    assert_eq!(checkpoint.objects.len(), 1);
    let recovered = TempDir::new();
    recovered.file(
        "surviving",
        &fs::read(dir.path().join("surviving")).unwrap(),
    );
    let recovered_root = File::open(recovered.path()).unwrap();
    let objects = checkpoint
        .objects
        .iter()
        .map(|o| RestoredObject {
            file: o_path(&recovered_root),
            guest_ino: o.guest_ino,
            ctime: o.ctime,
        })
        .collect();
    let restored = PassthroughFs::restore(
        snapshot_config(recovered.path()),
        &checkpoint.state,
        objects,
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    assert_eq!(names(&restored, handle, 1, 4096), listed[1..]);
    let entry = restored
        .lookup(CTX, fuse::ROOT_ID, &cstr("surviving"))
        .unwrap();
    assert_eq!(
        entry.attr.st_ino, ino,
        "listing-only inode projection changed"
    );
    assert!(restored.lookup(CTX, fuse::ROOT_ID, &cstr("stale")).is_err());
}

#[test]
fn snapshot_fs_replaced_listing_name_does_not_project_old_inode() {
    let dir = TempDir::new();
    dir.file("name", b"old");
    dir.file("replacement", b"new");
    let source = init_share(dir.path());
    let handle = source.opendir(CTX, fuse::ROOT_ID, 0).unwrap().0.unwrap();
    names(&source, handle, 0, 4096);
    fs::rename(dir.path().join("replacement"), dir.path().join("name")).unwrap();
    let checkpoint = source.checkpoint().unwrap();
    let listed = checkpoint.state.handles[0]
        .listing
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.name == b"name")
        .unwrap();
    assert!(!listed.projected && listed.object.is_none());
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    let current = restored.lookup(CTX, fuse::ROOT_ID, &cstr("name")).unwrap();
    assert_ne!(current.attr.st_ino, listed.ino);
}

#[test]
fn snapshot_fs_restored_inodes_and_ctime_are_projected() {
    let dir = TempDir::new();
    dir.file("kept", b"");
    dir.file("other", b"");
    let fs = init_share(dir.path());
    let kept = fs.lookup(CTX, fuse::ROOT_ID, &cstr("kept")).unwrap();
    // A share that was never restored reports host inode numbers.
    let host_other = fs::metadata(dir.path().join("other")).unwrap();
    assert_eq!(
        kept.attr.st_ino,
        fs::metadata(dir.path().join("kept")).unwrap().ino()
    );

    let checkpoint = fs.checkpoint().unwrap();
    let mut objects = same_host_objects(&checkpoint);
    let kept_object = checkpoint
        .state
        .nodes
        .iter()
        .find(|n| n.inode == kept.inode)
        .unwrap()
        .object as usize;
    // The guest saw "kept" with the number the host now uses for "other",
    // and an older ctime.
    objects[kept_object].guest_ino = host_other.ino();
    objects[kept_object].ctime = (1, 2);
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        objects,
        checkpoint.init_binary.clone(),
    )
    .unwrap();

    let (st, _) = restored.getattr(CTX, kept.inode, None).unwrap();
    assert_eq!(st.st_ino, host_other.ino());
    assert_eq!((st.st_ctime, st.st_ctime_nsec), (1, 2));
    // The new object whose host number collides gets a synthetic number.
    let other = restored.lookup(CTX, fuse::ROOT_ID, &cstr("other")).unwrap();
    assert!(other.attr.st_ino >= SYNTHETIC_INO_BASE);
    assert_eq!(
        restored.getattr(CTX, other.inode, None).unwrap().0.st_ino,
        other.attr.st_ino
    );
    let mut listed = Vec::new();
    let (handle, _) = restored.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    restored
        .readdir(
            CTX,
            fuse::ROOT_ID,
            handle.unwrap(),
            4096,
            0,
            |d: DirEntry| {
                listed.push((d.name.to_vec(), d.ino));
                Ok(1)
            },
        )
        .unwrap();
    assert!(listed.contains(&(b"kept".to_vec(), host_other.ino())));
    assert!(listed.contains(&(b"other".to_vec(), other.attr.st_ino)));
    // The counter survives the next checkpoint.
    assert!(restored.checkpoint().unwrap().state.next_synthetic_ino > other.attr.st_ino);

    // A real modification ends the saved ctime.
    thread::sleep(Duration::from_millis(20));
    // SAFETY: stat64 is plain data.
    let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o600;
    let (st, _) = restored
        .setattr(CTX, kept.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_ne!((st.st_ctime, st.st_ctime_nsec), (1, 2));
}

#[test]
fn snapshot_fs_restored_counters_refcounts_and_init_bytes() {
    let dir = TempDir::new();
    dir.file("f", b"");
    let fs = init_share(dir.path());
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    let checkpoint = fs.checkpoint().unwrap();
    let node = checkpoint
        .state
        .nodes
        .iter()
        .find(|n| n.inode == f.inode)
        .unwrap();
    assert_eq!(node.refcount, 2);
    let init: Arc<[u8]> = Arc::from(&b"archived init bytes"[..]);
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        init.clone(),
    )
    .unwrap();
    // The archived init.krun is served, never this build's binary.
    let init_entry = restored
        .lookup(CTX, fuse::ROOT_ID, &cstr("init.krun"))
        .unwrap();
    assert_eq!(init_entry.attr.st_size as usize, init.len());
    assert!(Arc::ptr_eq(
        &restored.checkpoint().unwrap().init_binary,
        &init
    ));
    // Restored refcounts: one forget keeps the node, the second drops it.
    restored.forget(CTX, f.inode, 1);
    assert!(restored.getattr(CTX, f.inode, None).is_ok());
    restored.forget(CTX, f.inode, 1);
    assert!(restored.getattr(CTX, f.inode, None).is_err());
    // The allocation counter resumes after every saved ID.
    let again = restored.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    assert_eq!(again.inode, checkpoint.state.next_inode);
}

#[test]
fn snapshot_fs_checkpoint_rejects_disabled_and_exported_shares() {
    let dir = TempDir::new();
    dir.file("f", b"");
    let plain = PassthroughFs::new(passthrough::Config {
        root_dir: dir.path().to_path_buf(),
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(
        plain.checkpoint(),
        Err(PassthroughSnapshotError::Disabled)
    ));

    let mut cfg = snapshot_config(dir.path());
    cfg.export_table = Some(Default::default());
    let fs = PassthroughFs::new(cfg).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    let (handle, _) = fs.open(CTX, f.inode, false, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    assert!(fs.checkpoint().is_ok());
    // _IOR('v', 1, 16): VIRTIO_IOC_EXPORT_FD.
    const EXPORT_FD: u32 = 0x8010_7601;
    fs.ioctl(
        CTX,
        f.inode,
        handle,
        0,
        EXPORT_FD,
        0,
        0,
        16,
        &Arc::new(AtomicI32::new(0)),
    )
    .unwrap();
    assert!(matches!(
        fs.checkpoint(),
        Err(PassthroughSnapshotError::ExportedHandle(h)) if h == handle
    ));
    // FUSE_DESTROY drops the handle, not its descriptor in the export
    // table, which another subsystem may still take: a new session cannot
    // be captured either.
    fs.destroy();
    fs.init(FsOptions::empty()).unwrap();
    assert!(matches!(
        fs.checkpoint(),
        Err(PassthroughSnapshotError::ExportedHandle(h)) if h == handle
    ));
}

#[test]
fn snapshot_fs_restore_rejects_malformed_state() {
    let dir = TempDir::new();
    dir.file("f", b"");
    let fs = init_share(dir.path());
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    let (handle, _) = fs.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    names(&fs, handle.unwrap(), 0, 4096);
    fs.open(CTX, f.inode, false, libc::O_RDWR as u32).unwrap();
    let checkpoint = fs.checkpoint().unwrap();
    let good = checkpoint.state.clone();
    let objects = checkpoint.objects.len();
    assert!(good.validate(objects).is_ok());

    let cases: Vec<(&str, Box<dyn Fn(&mut PassthroughState)>)> = vec![
        (
            "duplicate node",
            Box::new(|s| s.nodes.push(s.nodes[0].clone())),
        ),
        (
            "missing root",
            Box::new(|s| s.nodes.retain(|n| n.inode != fuse::ROOT_ID)),
        ),
        (
            "node object range",
            Box::new(move |s| s.nodes[0].object = objects as u64),
        ),
        (
            "shared object",
            Box::new(|s| s.nodes[1].object = s.nodes[0].object),
        ),
        ("zero refcount", Box::new(|s| s.nodes[0].refcount = 0)),
        (
            "node past counter",
            Box::new(|s| s.next_inode = s.nodes.iter().map(|n| n.inode).max().unwrap()),
        ),
        ("init inode", Box::new(|s| s.init_inode += 1)),
        (
            "init handle node",
            Box::new(|s| s.nodes[1].inode = s.init_inode),
        ),
        ("handle range", Box::new(|s| s.next_handle = 1)),
        ("init handle", Box::new(|s| s.handles[0].handle = 0)),
        (
            "handle on init node",
            Box::new(|s| s.handles[1].inode = s.init_inode),
        ),
        (
            "handle object differs from its node",
            Box::new(|s| s.handles[1].object = s.handles[0].object),
        ),
        (
            "listing init inode",
            Box::new(|s| {
                let init = s.init_inode;
                s.handles[0].listing.as_mut().unwrap()[0].ino = init;
            }),
        ),
        (
            "truncating flags",
            Box::new(|s| s.handles[1].flags |= libc::O_TRUNC),
        ),
        (
            "creating flags",
            Box::new(|s| s.handles[1].flags |= libc::O_CREAT),
        ),
        (
            "path flags",
            Box::new(|s| s.handles[1].flags |= libc::O_PATH),
        ),
        (
            "handle object range",
            Box::new(move |s| s.handles[0].object = objects as u64),
        ),
        (
            "listing name",
            Box::new(|s| s.handles[0].listing.as_mut().unwrap()[0].name = b"a/b".to_vec()),
        ),
        (
            "empty name",
            Box::new(|s| s.handles[0].listing.as_mut().unwrap()[0].name.clear()),
        ),
        ("synthetic counter", Box::new(|s| s.next_synthetic_ino = 5)),
        ("handles before init", Box::new(|s| s.nodes.clear())),
    ];
    for (what, mutate) in cases {
        let mut state = good.clone();
        mutate(&mut state);
        assert!(
            matches!(
                state.validate(objects),
                Err(PassthroughSnapshotError::Invalid(_))
            ),
            "{what} accepted"
        );
        // The same state fails a restore before any host side effect.
        assert!(
            PassthroughFs::restore(
                snapshot_config(dir.path()),
                &state,
                same_host_objects(&checkpoint),
                checkpoint.init_binary.clone(),
            )
            .is_err(),
            "{what} restored"
        );
    }
    // Negotiated options must agree with the share they continue.
    for (options, read_only) in [
        (FsOptions::WRITEBACK_CACHE.bits(), false),
        (FsOptions::SUBMOUNTS.bits(), false),
        (1 << 63, false),
    ] {
        assert!(matches!(
            FsServer::restored(
                snapshot_config(dir.path()),
                read_only,
                options,
                &good,
                same_host_objects(&checkpoint),
                checkpoint.init_binary.clone(),
            ),
            Err(PassthroughSnapshotError::Invalid(_))
        ));
    }
    let mut writeback = good.clone();
    writeback.writeback = true;
    assert!(FsServer::restored(
        snapshot_config(dir.path()),
        true,
        FsOptions::WRITEBACK_CACHE.bits(),
        &writeback,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .is_err());
    // A restored object never takes init.krun's inode number.
    let mut objects_at_init = same_host_objects(&checkpoint);
    objects_at_init[0].guest_ino = good.init_inode;
    assert!(matches!(
        PassthroughFs::restore(
            snapshot_config(dir.path()),
            &good,
            objects_at_init,
            checkpoint.init_binary.clone(),
        ),
        Err(PassthroughSnapshotError::Invalid(_))
    ));
    // A restore needs a snapshot-mode share.
    assert!(matches!(
        PassthroughFs::restore(
            passthrough::Config {
                root_dir: dir.path().to_path_buf(),
                ..Default::default()
            },
            &good,
            same_host_objects(&checkpoint),
            checkpoint.init_binary.clone(),
        ),
        Err(PassthroughSnapshotError::Disabled)
    ));
}

#[test]
fn snapshot_fs_forgotten_node_keeps_its_open_handle() {
    let dir = TempDir::new();
    dir.file("f", b"still open");
    let fs = init_share(dir.path());
    let f = fs.lookup(CTX, fuse::ROOT_ID, &cstr("f")).unwrap();
    let (handle, _) = fs.open(CTX, f.inode, false, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    // The guest forgets the node but keeps the file open.
    fs.forget(CTX, f.inode, 1);
    let checkpoint = fs.checkpoint().unwrap();
    assert!(checkpoint.state.nodes.iter().all(|n| n.inode != f.inode));
    let saved = &checkpoint.state.handles[0];
    assert_eq!((saved.handle, saved.inode), (handle, f.inode));
    checkpoint.state.validate(checkpoint.objects.len()).unwrap();
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    let again = restored.checkpoint().unwrap();
    assert_eq!(again.state.handles, checkpoint.state.handles);
    assert_eq!(again.state.nodes, checkpoint.state.nodes);
}

#[test]
fn snapshot_fs_exhausted_counters_issue_no_ids() {
    let dir = TempDir::new();
    dir.file("known", b"");
    dir.file("unknown", b"");
    let fs = init_share(dir.path());
    let known = fs.lookup(CTX, fuse::ROOT_ID, &cstr("known")).unwrap();
    let checkpoint = fs.checkpoint().unwrap();
    let mut state = checkpoint.state.clone();
    state.next_inode = u64::MAX;
    state.next_handle = u64::MAX;
    state.validate(checkpoint.objects.len()).unwrap();
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();

    let overflow = |e: std::io::Error| e.raw_os_error() == Some(libc::EOVERFLOW);
    // Repeated: an exhausted counter never wraps to 0, a reserved ID or an
    // ID already issued.
    for _ in 0..2 {
        let lookup = restored.lookup(CTX, fuse::ROOT_ID, &cstr("unknown"));
        assert!(lookup.is_err_and(overflow));
        let open = restored.open(CTX, known.inode, false, libc::O_RDONLY as u32);
        assert!(open.is_err_and(overflow));
        let opendir = restored.opendir(CTX, fuse::ROOT_ID, 0);
        assert!(opendir.is_err_and(overflow));
        let create = restored.create(
            CTX,
            fuse::ROOT_ID,
            &cstr("new"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        );
        assert!(create.is_err_and(overflow));
    }
    assert!(!dir.path().join("new").exists());
    // A known object resolves without an allocation.
    let again = restored.lookup(CTX, fuse::ROOT_ID, &cstr("known")).unwrap();
    assert_eq!(again.inode, known.inode);
    let saved = restored.checkpoint().unwrap();
    assert_eq!(
        (saved.state.next_inode, saved.state.next_handle),
        (u64::MAX, u64::MAX)
    );
    assert_eq!(saved.state.nodes.len(), 2);
    assert!(saved.state.handles.is_empty());
    saved.state.validate(saved.objects.len()).unwrap();
}

/// The lookup count of `inode` in a fresh checkpoint (0: no node).
fn refcount(fs: &PassthroughFs, inode: u64) -> u64 {
    fs.checkpoint()
        .unwrap()
        .state
        .nodes
        .iter()
        .find(|n| n.inode == inode)
        .map_or(0, |n| n.refcount)
}

#[test]
fn snapshot_fs_readdirplus_reports_current_objects_and_returns_unused_lookups() {
    let dir = TempDir::new();
    dir.file("a", b"");
    dir.file("b", b"");
    let fs = init_share(dir.path());
    let (handle, _) = fs.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    let handle = handle.unwrap();
    let mut listed = Vec::new();
    fs.readdir(CTX, fuse::ROOT_ID, handle, 4096, 0, |d: DirEntry| {
        listed.push((d.name.to_vec(), d.ino));
        Ok(1)
    })
    .unwrap();
    let start = listed.iter().position(|(n, _)| n == b"a").unwrap();
    // Continuing at offset 0 would take a new list instead.
    assert!(start > 0, "the dot entries lead the list");
    let listed_ino = listed[start].1;
    // "a" now names another object than the one listed.
    dir.file("x", b"");
    fs::rename(dir.path().join("x"), dir.path().join("a")).unwrap();
    let current_ino = fs::metadata(dir.path().join("a")).unwrap().ino();
    assert_ne!(current_ino, listed_ino);

    let plus = |fs: &PassthroughFs, mut reply: Box<dyn FnMut() -> std::io::Result<usize>>| {
        let mut seen = Vec::new();
        let res = fs.readdirplus(
            CTX,
            fuse::ROOT_ID,
            handle,
            4096,
            start as u64,
            |d: DirEntry, e: Entry| {
                seen.push((d.name.to_vec(), d.ino, e.attr.st_ino, e.inode));
                reply()
            },
        );
        (res, seen)
    };
    // A full reply buffer and a failed reply give the lookup back: no
    // node is left behind for "a".
    let (res, seen) = plus(&fs, Box::new(|| Ok(0)));
    res.unwrap();
    assert_eq!(seen.len(), 1);
    let a_inode = seen[0].3;
    assert_eq!(refcount(&fs, a_inode), 0);
    let (res, _) = plus(
        &fs,
        Box::new(|| Err(std::io::Error::from_raw_os_error(libc::EIO))),
    );
    assert!(res.is_err());
    assert_eq!(refcount(&fs, a_inode), 0);

    // An accepted entry reports the current object's inode number.
    let (res, seen) = plus(&fs, Box::new(|| Ok(1)));
    res.unwrap();
    let (_, dir_ino, attr_ino, inode) = seen.iter().find(|e| e.0 == b"a").unwrap().clone();
    assert_eq!((dir_ino, attr_ino), (current_ino, current_ino));
    assert_eq!(refcount(&fs, inode), 1);
    // Exact counts: a rejected entry leaves an existing node unchanged.
    plus(&fs, Box::new(|| Ok(0))).0.unwrap();
    assert_eq!(refcount(&fs, inode), 1);
    plus(&fs, Box::new(|| Ok(1))).0.unwrap();
    assert_eq!(refcount(&fs, inode), 2);
}

#[test]
fn snapshot_fs_restored_init_reads_stop_at_its_end() {
    let dir = TempDir::new();
    let mut source = Rig::new(dir.path());
    source.init();
    let queues = source.freeze();
    let init: Arc<[u8]> = Arc::from(&b"archived init bytes"[..]);
    let mut target = Rig::restored_with_init(&source, dir.path(), &queues, Some(init.clone()));
    target.resume();
    let init_inode = fuse::ROOT_ID + 1;
    let mut read_at = |offset: u64| {
        let read = ReadIn {
            fh: 0,
            offset,
            size: REPLY - size_of::<OutHeader>() as u32,
            ..Default::default()
        };
        target.ok(Opcode::Read, init_inode, read.as_slice())
    };
    let len = init.len() as u64;
    assert_eq!(read_at(0), &init[..]);
    assert_eq!(read_at(len - 3), &init[init.len() - 3..]);
    for offset in [len, len + 1, u64::MAX - 1, u64::MAX] {
        assert!(read_at(offset).is_empty(), "offset {offset}");
    }
}

#[test]
fn snapshot_fs_dropped_device_joins_its_worker_and_reset_reactivates() {
    let dir = TempDir::new();
    let mut source = Rig::new(dir.path());
    source.init();
    let queues = source.freeze();
    // An owner restore that fails after activating the device, before
    // inserting it, drops the device without a reset.
    let mut target = Rig::restored(&source, dir.path(), &queues);
    // The worker holds every queue event while it runs.
    assert!(target.events.iter().all(|e| Arc::strong_count(e) == 2));
    drop(mem::replace(&mut target.fs, Rig::device(dir.path())));
    assert!(target.events.iter().all(|e| Arc::strong_count(e) == 1));

    // A reset joins the worker; the same device activates again with a
    // new session.
    source.resume();
    source.fs.reset();
    assert!(source.events.iter().all(|e| Arc::strong_count(e) == 1));
    assert!(source.fs.worker_control().is_none());
    source.fs.reset();
    let device = mem::replace(&mut source.fs, Rig::device(dir.path()));
    let guest = Guest::new(0);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut again = Rig::activate(guest, device, queues, false);
    again.init();
    again.getattr(fuse::ROOT_ID);
}

/// A share root is any path of bytes but NUL; one holding a NUL fails
/// FUSE_INIT with EINVAL instead of panicking the worker.
#[test]
fn snapshot_fs_root_with_a_nul_byte_fails_init() {
    let dir = TempDir::new();
    let mut cfg = snapshot_config(dir.path());
    cfg.root_dir = dir.path().join(OsStr::from_bytes(b"a\0b"));
    let fs = PassthroughFs::new(cfg).unwrap();
    let error = fs.init(FsOptions::empty()).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn snapshot_fs_non_utf8_names_list_and_look_up() {
    // Evaluate debug log arguments, as a VMM with debug logging does.
    log::set_max_level(log::LevelFilter::Debug);
    let dir = TempDir::new();
    let name: &[u8] = b"bad\xffname";
    fs::write(dir.path().join(OsStr::from_bytes(name)), b"").unwrap();
    let fs = init_share(dir.path());
    let entry = fs
        .lookup(CTX, fuse::ROOT_ID, &CString::new(name).unwrap())
        .unwrap();
    let (handle, _) = fs.opendir(CTX, fuse::ROOT_ID, 0).unwrap();
    let handle = handle.unwrap();
    let listed = names(&fs, handle, 0, 4096);
    let index = listed.iter().position(|(n, _)| n == name).unwrap();
    let mut plus = Vec::new();
    fs.readdirplus(
        CTX,
        fuse::ROOT_ID,
        handle,
        4096,
        index as u64,
        |d: DirEntry, e: Entry| {
            plus.push((d.name.to_vec(), e.inode));
            Ok(1)
        },
    )
    .unwrap();
    assert_eq!(plus[0], (name.to_vec(), entry.inode));

    // The byte name survives a checkpoint and a restored continuation.
    let checkpoint = fs.checkpoint().unwrap();
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    assert_eq!(
        names(&restored, handle, index as u64, 4096),
        listed[index..].to_vec()
    );
    let again = restored
        .lookup(CTX, fuse::ROOT_ID, &CString::new(name).unwrap())
        .unwrap();
    assert_eq!(again.inode, entry.inode);
}

fn host_page() -> u64 {
    // Safe because sysconf touches no memory.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// An anonymous read-write reservation standing in for a share's DAX
/// window, as the VMM provides it.
struct Window {
    addr: u64,
    size: u64,
}

impl Window {
    fn new(pages: u64) -> Window {
        let size = pages * host_page();
        // Safe because a new private mapping touches no existing memory and
        // we check the result.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(!std::ptr::eq(addr, libc::MAP_FAILED));
        Window {
            addr: addr as u64,
            size,
        }
    }

    fn dax(&self) -> DaxWindow {
        DaxWindow {
            host_addr: self.addr,
            size: self.size,
        }
    }

    fn shm(&self) -> VirtioShmRegion {
        VirtioShmRegion {
            host_addr: self.addr,
            guest_addr: 0,
            size: self.size as usize,
        }
    }

    /// What the guest reads at `offset`.
    fn read(&self, offset: u64, len: u64) -> Vec<u8> {
        assert!(offset + len <= self.size);
        // Safe because the range lies inside the reservation and the caller
        // reads only readable pages.
        unsafe { std::slice::from_raw_parts((self.addr + offset) as *const u8, len as usize) }
            .to_vec()
    }

    /// What the guest writes at `offset`.
    fn write(&self, offset: u64, bytes: &[u8]) {
        assert!(offset + bytes.len() as u64 <= self.size);
        // Safe because the range lies inside the reservation and the caller
        // writes only writable pages.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.addr + offset) as *mut u8,
                bytes.len(),
            )
        };
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // Safe because the reservation belongs to this window.
        unsafe { libc::munmap(self.addr as *mut libc::c_void, self.size as usize) };
    }
}

/// `pages` host pages, page `i` filled with `first + i`.
fn paged(pages: u64, first: u8) -> Vec<u8> {
    (0..pages)
        .flat_map(|i| vec![first + i as u8; host_page() as usize])
        .collect()
}

/// FUSE_SETUPMAPPING, in host pages.
fn setup(
    fs: &PassthroughFs,
    w: &Window,
    inode: u64,
    foffset: u64,
    len: u64,
    writable: bool,
    moffset: u64,
) -> std::io::Result<()> {
    let p = host_page();
    let flags = if writable {
        SetupmappingFlags::READ | SetupmappingFlags::WRITE
    } else {
        SetupmappingFlags::READ
    };
    fs.setupmapping(
        CTX,
        inode,
        0,
        foffset * p,
        len * p,
        flags.bits(),
        moffset * p,
        w.addr,
        w.size,
    )
}

/// FUSE_REMOVEMAPPING of (moffset, len) ranges, in host pages.
fn remove(fs: &PassthroughFs, w: &Window, ranges: &[(u64, u64)]) -> std::io::Result<()> {
    let p = host_page();
    let requests = ranges
        .iter()
        .map(|&(moffset, len)| RemovemappingOne {
            moffset: moffset * p,
            len: len * p,
        })
        .collect();
    fs.removemapping(CTX, requests, w.addr, w.size)
}

/// A mapping in host pages; file offsets are in host pages too.
fn mapping(moffset: u64, len: u64, kind: DaxMappingKind) -> DaxMapping {
    let p = host_page();
    let kind = match kind {
        DaxMappingKind::File {
            object,
            foffset,
            writable,
        } => DaxMappingKind::File {
            object,
            foffset: foffset * p,
            writable,
        },
        other => other,
    };
    DaxMapping {
        moffset: moffset * p,
        len: len * p,
        kind,
    }
}

fn file(object: u64, foffset: u64, writable: bool) -> DaxMappingKind {
    DaxMappingKind::File {
        object,
        foffset,
        writable,
    }
}

const ANON: DaxMappingKind = DaxMappingKind::Anonymous { writable: true };
const HOLE: DaxMappingKind = DaxMappingKind::Hole;

fn object_of(checkpoint: &PassthroughCheckpoint, path: &Path) -> u64 {
    let ino = fs::metadata(path).unwrap().ino();
    checkpoint
        .objects
        .iter()
        .position(|o| o.ino == ino)
        .unwrap() as u64
}

fn dax_layout(fs: &PassthroughFs, w: &Window) -> Vec<DaxMapping> {
    fs.checkpoint_with_dax(Some(w.dax()))
        .unwrap()
        .state
        .dax
        .unwrap()
        .mappings
}

/// Check every window page against the host's own mappings
/// (/proc/self/maps): protection, sharing, and for file mappings the
/// object's inode and the file offset.
fn assert_host_matches(w: &Window, state: &DaxState, objects: &[SnapshotObject]) {
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    let vmas: Vec<(u64, u64, String, u64, u64)> = maps
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next().unwrap().split_once('-').unwrap();
            let perms = fields.next().unwrap().to_string();
            let offset = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
            fields.next();
            let inode = fields.next().unwrap().parse().unwrap();
            (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
                perms,
                offset,
                inode,
            )
        })
        .collect();
    let p = host_page();
    for m in &state.mappings {
        for at in (m.moffset..m.moffset + m.len).step_by(p as usize) {
            let addr = w.addr + at;
            let (start, _, perms, offset, inode) = vmas
                .iter()
                .find(|v| v.0 <= addr && addr < v.1)
                .unwrap_or_else(|| panic!("window page {at:#x} is unmapped"));
            match m.kind {
                DaxMappingKind::File {
                    object,
                    foffset,
                    writable,
                } => {
                    assert_eq!(perms, if writable { "rw-s" } else { "r--s" }, "{at:#x}");
                    assert_eq!(*inode, objects[object as usize].ino, "{at:#x}");
                    assert_eq!(offset + (addr - start), foffset + (at - m.moffset));
                }
                DaxMappingKind::Anonymous { writable } => {
                    assert_eq!(perms, if writable { "rw-p" } else { "r--p" }, "{at:#x}");
                    assert_eq!(*inode, 0, "{at:#x}");
                }
                DaxMappingKind::Hole => {
                    assert_eq!(perms, "---p", "{at:#x}");
                    assert_eq!(*inode, 0, "{at:#x}");
                }
            }
        }
    }
}

#[test]
fn snapshot_fs_dax_ledger_tracks_overlap_partial_unmap_and_holes() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("a", &paged(4, 0x10));
    dir.file("b", &paged(2, 0x40));
    let w = Window::new(8);
    let fs = init_share(dir.path());
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    let b = fs.lookup(CTX, fuse::ROOT_ID, &cstr("b")).unwrap();

    setup(&fs, &w, a.inode, 0, 4, false, 0).unwrap();
    // A writable mapping over the middle of the first one.
    setup(&fs, &w, b.inode, 0, 2, true, 2).unwrap();
    setup(&fs, &w, a.inode, 0, 3, false, 4).unwrap();
    // One request removing a page from each of the three mappings.
    remove(&fs, &w, &[(1, 1), (3, 1), (5, 1)]).unwrap();

    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let (oa, ob) = (
        object_of(&checkpoint, &dir.path().join("a")),
        object_of(&checkpoint, &dir.path().join("b")),
    );
    let state = checkpoint.state.dax.as_ref().unwrap();
    assert_eq!(state.size, w.size);
    assert_eq!(
        state.mappings,
        vec![
            mapping(0, 1, file(oa, 0, false)),
            mapping(1, 1, HOLE),
            mapping(2, 1, file(ob, 0, true)),
            mapping(3, 1, HOLE),
            mapping(4, 1, file(oa, 0, false)),
            mapping(5, 1, HOLE),
            // The rest of a cut mapping keeps each byte's file offset.
            mapping(6, 1, file(oa, 2, false)),
            mapping(7, 1, ANON),
        ]
    );
    assert_host_matches(&w, state, &checkpoint.objects);
    assert_eq!(w.read(6 * p, 1), [0x12]);
    // The guest writes through the writable mapping into the host object.
    w.write(2 * p, b"guest");
    assert_eq!(&fs::read(dir.path().join("b")).unwrap()[..5], b"guest");

    // Adjacent views continuing one object merge; removing everything
    // leaves one hole and no object or page references.
    remove(&fs, &w, &[(0, 8)]).unwrap();
    setup(&fs, &w, a.inode, 0, 2, false, 0).unwrap();
    setup(&fs, &w, a.inode, 2, 2, false, 2).unwrap();
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let oa = object_of(&checkpoint, &dir.path().join("a"));
    let state = checkpoint.state.dax.as_ref().unwrap();
    assert_eq!(
        state.mappings,
        vec![mapping(0, 4, file(oa, 0, false)), mapping(4, 4, HOLE)]
    );
    assert_host_matches(&w, state, &checkpoint.objects);
    remove(&fs, &w, &[(0, 4)]).unwrap();
    assert_eq!(dax_layout(&fs, &w), vec![mapping(0, 8, HOLE)]);
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    assert!(checkpoint.dax_pages.offsets.is_empty());
    // Only the root and the looked-up files remain objects.
    assert_eq!(checkpoint.objects.len(), 3);
}

#[test]
fn snapshot_fs_dax_failed_mappings_keep_ledger_and_host_consistent() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("a", &paged(4, 0x10));
    let w = Window::new(4);
    // A first request on a window that is not whole host pages inside the
    // address space fails and binds nothing.
    let unbound = init_share(dir.path());
    for (base, size) in [
        (w.addr + 1, w.size),
        (w.addr, w.size - 1),
        (w.addr, 0),
        (u64::MAX - p + 1, 2 * p),
    ] {
        let one = vec![RemovemappingOne { moffset: 0, len: p }];
        assert!(unbound.removemapping(CTX, one, base, size).is_err());
    }
    assert_eq!(unbound.checkpoint().unwrap().state.dax, None);

    let fs = init_share(dir.path());
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    setup(&fs, &w, a.inode, 0, 2, false, 0).unwrap();
    let before = dax_layout(&fs, &w);

    // Every refusal comes before a host call (the host would refuse a
    // directory or an unaligned file offset too), so the window stays
    // usable.
    let read = SetupmappingFlags::READ.bits();
    let failures: Vec<(&str, std::io::Result<()>)> = vec![
        ("directory", setup(&fs, &w, fuse::ROOT_ID, 0, 1, false, 2)),
        (
            "unaligned file offset",
            fs.setupmapping(CTX, a.inode, 0, 1, p, read, 2 * p, w.addr, w.size),
        ),
        ("unknown node", setup(&fs, &w, 1 << 40, 0, 1, false, 2)),
        ("past the window", setup(&fs, &w, a.inode, 0, 2, false, 3)),
        (
            "wrapping window offset",
            fs.setupmapping(
                CTX,
                a.inode,
                0,
                0,
                2 * p,
                read,
                u64::MAX - p + 1,
                w.addr,
                w.size,
            ),
        ),
        (
            "unaligned window offset",
            fs.setupmapping(CTX, a.inode, 0, 0, p, read, 1, w.addr, w.size),
        ),
        (
            "file offset past off_t",
            fs.setupmapping(
                CTX,
                a.inode,
                0,
                u64::MAX - p + 1,
                p,
                read,
                2 * p,
                w.addr,
                w.size,
            ),
        ),
        (
            "another window",
            fs.setupmapping(CTX, a.inode, 0, 0, p, read, 0, w.addr + p, w.size - p),
        ),
    ];
    for (what, result) in failures {
        assert!(result.is_err(), "{what} accepted");
    }
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let state = checkpoint.state.dax.as_ref().unwrap();
    assert_eq!(state.mappings, before);
    assert_host_matches(&w, state, &checkpoint.objects);

    // A removal whose second range fails keeps the first and never tries
    // the third.
    assert!(remove(&fs, &w, &[(1, 1), (3, 2), (0, 1)]).is_err());
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let oa = object_of(&checkpoint, &dir.path().join("a"));
    let state = checkpoint.state.dax.as_ref().unwrap();
    assert_eq!(
        state.mappings,
        vec![
            mapping(0, 1, file(oa, 0, false)),
            mapping(1, 1, HOLE),
            mapping(2, 2, ANON),
        ]
    );
    assert_host_matches(&w, state, &checkpoint.objects);
    assert_eq!(w.read(0, 1), [0x10]);
}

/// After a failed host call: every capture, sync and mapping request on
/// `fs` fails, and the untouched window page at `offset` still holds `byte`.
fn assert_lost(fs: &PassthroughFs, w: &Window, offset: u64, byte: u8) {
    let p = host_page();
    assert!(matches!(
        fs.checkpoint_with_dax(Some(w.dax())),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    assert!(matches!(
        fs.checkpoint(),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    let eio = Some(libc::EIO);
    assert_eq!(fs.sync_for_snapshot().unwrap_err().raw_os_error(), eio);
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    let mapped = setup(fs, w, init.inode, 0, 1, true, offset / p);
    assert_eq!(mapped.unwrap_err().raw_os_error(), eio);
    let removal = remove(fs, w, &[(offset / p, 1)]);
    assert_eq!(removal.unwrap_err().raw_os_error(), eio);
    assert_eq!(w.read(offset, 1), [byte]);
}

/// Give back `len` bytes at `offset` that a failure unmapped from `w`
/// before it is dropped; if another mapping took them, leak `w` instead.
fn reclaim(w: Window, offset: u64, len: u64) {
    let at = w.addr + offset;
    // Safe because the range is the window's own unmapped part and
    // MAP_FIXED_NOREPLACE never replaces another mapping.
    let addr = unsafe {
        libc::mmap(
            at as *mut libc::c_void,
            len as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if addr as u64 != at {
        if !std::ptr::eq(addr, libc::MAP_FAILED) {
            // Safe because the kernel placed this new mapping elsewhere.
            unsafe { libc::munmap(addr, len as usize) };
        }
        mem::forget(w);
    }
}

#[test]
fn snapshot_fs_dax_host_failures_lose_the_window() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("a", &paged(4, 0x10));

    // A removal whose second range unmaps a file mapping and then fails:
    // the ledger would still show the file there.
    let w = Window::new(4);
    let fs = init_share(dir.path());
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    setup(&fs, &w, a.inode, 0, 2, false, 0).unwrap();
    w.write(3 * p, &[7]);
    arm(w.addr + p, Fault::MapAfterUnmap);
    let removal = remove(&fs, &w, &[(2, 1), (1, 1), (3, 1)]);
    assert_eq!(removal.unwrap_err().raw_os_error(), Some(libc::ENOMEM));
    assert_lost(&fs, &w, 3 * p, 7);
    assert_eq!(fs.dax_unowned(), [(p, p)]);
    reclaim(w, p, p);

    // An init.krun copy that unmaps untouched memory and then fails: a
    // capture would read the unmapped page.
    let w = Window::new(2);
    let fs = init_share(dir.path());
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    w.write(0, &[8]);
    arm(w.addr + p, Fault::MapAfterUnmap);
    assert!(setup(&fs, &w, init.inode, 0, 1, true, 1).is_err());
    assert_lost(&fs, &w, 0, 8);
    assert_eq!(fs.dax_unowned(), [(p, p)]);
    reclaim(w, p, p);

    // A read-only init.krun copy whose mprotect stops after one page.
    let w = Window::new(4);
    let fs = init_share(dir.path());
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    w.write(3 * p, &[9]);
    arm(w.addr + p, Fault::ProtectPartly);
    assert!(setup(&fs, &w, init.inode, 0, 2, false, 1).is_err());
    assert_lost(&fs, &w, 3 * p, 9);
    assert!(fs.dax_unowned().is_empty());
}

#[test]
fn snapshot_fs_dax_device_freeze_fails_on_a_lost_window() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(1, 0x33));
    let w = Window::new(4);
    let mut device = Rig::device(dir.path());
    device.set_shm_region(w.shm());
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut rig = Rig::activate(guest, device, queues, false);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    let request = |moffset| SetupmappingIn {
        fh: 0,
        foffset: 0,
        len: p,
        flags: SetupmappingFlags::READ.bits(),
        moffset,
    };
    arm(w.addr + p, Fault::MapAfterUnmap);
    let (header, _) = rig.call(Opcode::SetupMapping, f.nodeid, request(p).as_slice());
    assert_eq!(header.error, -libc::ENOMEM);
    let (header, _) = rig.call(Opcode::SetupMapping, f.nodeid, request(2 * p).as_slice());
    assert_eq!(header.error, -libc::EIO);
    // The worker reports the failure instead of confirming the freeze.
    let control = rig.fs.worker_control().unwrap();
    assert!(control.freeze_with_timeout(WAIT).is_err());
    assert!(matches!(
        rig.fs.snapshot_session(),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    // Dropping the rig stops and joins the worker before the window goes.
    drop(rig);
    reclaim(w, p, p);
}

/// A new device on `dir` over `w` and the result of restoring `session`
/// into it.
fn restore_into(
    w: &Window,
    dir: &Path,
    session: &FsSessionCheckpoint,
) -> (Fs, Result<(), PassthroughSnapshotError>) {
    let mut device = Rig::device(dir);
    device.set_shm_region(w.shm());
    let restored = device.restore_session(
        session.options,
        &session.passthrough.state,
        same_host_objects(&session.passthrough),
        session.passthrough.init_binary.clone(),
        &session.passthrough.dax_pages,
    );
    (device, restored)
}

/// A frozen session over `w` with "f" mapped read-only at window page 1
/// and a nonzero byte in the anonymous page 0.
fn mapped_session(dir: &Path, w: &Window) -> Rig {
    let p = host_page();
    let mut device = Rig::device(dir);
    device.set_shm_region(w.shm());
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut rig = Rig::activate(guest, device, queues, false);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    let setup = SetupmappingIn {
        fh: 0,
        foffset: 0,
        len: 2 * p,
        flags: SetupmappingFlags::READ.bits(),
        moffset: p,
    };
    rig.ok(Opcode::SetupMapping, f.nodeid, setup.as_slice());
    w.write(0, &[5]);
    rig.freeze();
    rig
}

/// A restore whose `map_dax` fails part way leaves a window that is neither
/// the saved one nor wholly the device's: the device is retired, so no
/// second restore maps over it and nothing activates or captures it.
#[test]
fn snapshot_fs_failed_map_dax_retires_the_device() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(2, 0x33));
    let source = Window::new(4);
    let rig = mapped_session(dir.path(), &source);
    let session = rig.fs.snapshot_session().unwrap().unwrap();
    let w = Window::new(4);
    // The file mapping's MAP_FIXED unmaps its range, then fails.
    arm(w.addr + p, Fault::MapAfterUnmap);
    let (mut device, restored) = restore_into(&w, dir.path(), &session);
    assert!(restored.is_err());
    let again = device.restore_session(
        session.options,
        &session.passthrough.state,
        same_host_objects(&session.passthrough),
        session.passthrough.init_binary.clone(),
        &session.passthrough.dax_pages,
    );
    assert!(matches!(again, Err(PassthroughSnapshotError::DaxLost)));
    assert!(matches!(
        device.archive_source(),
        Err(PassthroughSnapshotError::DaxLost)
    ));
    let guest = Guest::new(0xfffe);
    let interrupt =
        InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap();
    let queues = (0..NUM_QUEUES)
        .map(|q| {
            DeviceQueue::new(
                guest.queue(q),
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            )
        })
        .collect();
    assert!(device
        .activate(guest.mem.clone(), interrupt, queues)
        .is_err());
    drop(device);
    reclaim(w, p, 2 * p);
}

/// Retiring stops the worker but leaves the window exactly as mapped (only
/// a guest reset returns it to zero memory), and every device names the
/// ranges a failed `MAP_FIXED` may have handed to other memory: one failed
/// `map_dax` mapping, a failed reset remapping (the whole window), never a
/// failed `mprotect`.
#[test]
fn snapshot_fs_retired_devices_name_the_window_ranges_they_may_not_own() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(2, 0x33));
    let w = Window::new(4);
    let mut rig = mapped_session(dir.path(), &w);
    let session = rig.fs.snapshot_session().unwrap().unwrap();
    rig.fs.retire();
    assert!(rig.fs.must_discard());
    assert!(rig.fs.dax_unowned().is_empty());
    assert_eq!(w.read(0, 1), [5]);
    assert_eq!(w.read(p, 1), [0x33]);
    assert!(rig.fs.archive_source().is_err());
    assert!(rig.fs.snapshot_session().unwrap().is_none());

    let target = Window::new(4);
    arm(target.addr + p, Fault::MapAfterUnmap);
    let (failed, _) = restore_into(&target, dir.path(), &session);
    assert!(failed.must_discard());
    assert_eq!(failed.dax_unowned(), [(p, 2 * p)]);
    drop(failed);
    reclaim(target, p, 2 * p);

    let target = Window::new(4);
    let (mut restored, result) = restore_into(&target, dir.path(), &session);
    result.unwrap();
    assert_eq!(target.read(p, 1), [0x33]);
    arm(target.addr, Fault::MapAfterUnmap);
    restored.reset();
    assert!(restored.must_discard());
    assert_eq!(restored.dax_unowned(), [(0, 4 * p)]);
    drop(restored);
    reclaim(target, 0, 4 * p);

    // A failed mprotect leaves the window lost but still the device's.
    let w = Window::new(2);
    let fs = init_share(dir.path());
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    arm(w.addr, Fault::ProtectPartly);
    assert!(setup(&fs, &w, init.inode, 0, 2, false, 0).is_err());
    assert!(fs.dax_window_lost());
    assert!(fs.dax_unowned().is_empty());
}

/// Set the access time of `path` to `sec`, leaving its modification time.
fn set_atime(path: &Path, sec: i64) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: sec,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    ];
    // Safe because both arguments are valid for the call.
    let res = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(res, 0);
}

/// The nonzero DAX pages of `bytes` placed at window offset `at`.
fn nonzero_pages(at: u64, bytes: &[u8]) -> DaxPages {
    let mut pages = DaxPages::default();
    for (index, page) in bytes.chunks(DAX_PAGE_SIZE as usize).enumerate() {
        if page.iter().any(|&b| b != 0) {
            pages.offsets.push(at + index as u64 * DAX_PAGE_SIZE);
            pages.data.extend_from_slice(page);
        }
    }
    pages
}

#[test]
fn snapshot_fs_dax_mapped_only_objects_and_private_init_bytes_survive_restore() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("data", &paged(1, 0x55));
    dir.file("ro", &paged(1, 0x66));
    let (w, target) = (Window::new(8), Window::new(8));
    let fs = init_share(dir.path());
    let data = fs.lookup(CTX, fuse::ROOT_ID, &cstr("data")).unwrap();
    let ro = fs.lookup(CTX, fuse::ROOT_ID, &cstr("ro")).unwrap();
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    let init_bytes = fs.checkpoint().unwrap().init_binary;

    setup(&fs, &w, data.inode, 0, 1, true, 0).unwrap();
    setup(&fs, &w, ro.inode, 0, 1, false, 1).unwrap();
    // A writable init.krun copy from offset 0, and a read-only one from
    // the second host page.
    setup(&fs, &w, init.inode, 0, 2, true, 2).unwrap();
    setup(&fs, &w, init.inode, 1, 1, false, 4).unwrap();
    w.write(0, b"through the window");
    // The guest modifies its private init.krun copy and untouched memory.
    w.write(2 * p + 10, &[0xee]);
    w.write(6 * p + 7, &[0x77]);
    // Only the mapping references "data" now.
    fs.forget(CTX, data.inode, 1);
    fs.unlink(CTX, fuse::ROOT_ID, &cstr("data")).unwrap();
    set_atime(&dir.path().join("ro"), 1);

    fs.sync_for_snapshot().unwrap();
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    assert!(checkpoint.state.nodes.iter().all(|n| n.inode != data.inode));
    let state = checkpoint.state.dax.as_ref().unwrap();
    let DaxMappingKind::File { object, .. } = state.mappings[0].kind else {
        panic!("{:?}", state.mappings[0]);
    };
    let mapped = &checkpoint.objects[object as usize];
    assert_eq!(mapped.file.metadata().unwrap().nlink(), 0);
    let mut written = [0u8; 18];
    mapped.file.read_exact_at(&mut written, 0).unwrap();
    assert_eq!(&written, b"through the window");
    let oro = object_of(&checkpoint, &dir.path().join("ro"));
    assert_eq!(
        state.mappings,
        vec![
            mapping(0, 1, file(object, 0, true)),
            mapping(1, 1, file(oro, 0, false)),
            mapping(2, 2, ANON),
            mapping(4, 1, DaxMappingKind::Anonymous { writable: false }),
            mapping(5, 3, ANON),
        ]
    );
    assert_host_matches(&w, state, &checkpoint.objects);
    // The copies hold the source init.krun bytes from their offsets, plus
    // the guest's change; anonymous data is the sorted nonzero pages.
    let copy = |from: u64, len: u64| {
        let mut bytes = vec![0u8; len as usize];
        let start = (from as usize).min(init_bytes.len());
        let end = (start + len as usize).min(init_bytes.len());
        bytes[..end - start].copy_from_slice(&init_bytes[start..end]);
        bytes
    };
    let mut first = copy(0, 2 * p);
    first[10] = 0xee;
    let second = copy(p, p);
    assert_eq!(w.read(2 * p, 2 * p), first);
    assert_eq!(w.read(4 * p, p), second);
    let mut expected = nonzero_pages(2 * p, &first);
    let more = nonzero_pages(4 * p, &second);
    expected.offsets.extend(more.offsets);
    expected.data.extend(more.data);
    let mut touched = vec![0u8; DAX_PAGE_SIZE as usize];
    touched[((6 * p + 7) % DAX_PAGE_SIZE) as usize] = 0x77;
    expected
        .offsets
        .push((6 * p + 7) / DAX_PAGE_SIZE * DAX_PAGE_SIZE);
    expected.data.extend(touched);
    assert_eq!(checkpoint.dax_pages, expected);
    assert!(checkpoint.dax_pages.validate(state).is_ok());
    // Capturing read no host object.
    assert_eq!(fs::metadata(dir.path().join("ro")).unwrap().atime(), 1);

    // A restore maps the same window elsewhere, the unlinked object again.
    let restored = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    restored
        .map_dax(target.dax(), &checkpoint.dax_pages)
        .unwrap();
    assert_eq!(target.read(0, 18), b"through the window");
    assert_eq!(target.read(p, 1), [0x66]);
    assert_eq!(target.read(2 * p, 2 * p), first);
    assert_eq!(target.read(4 * p, p), second);
    assert_eq!(target.read(6 * p + 7, 1), [0x77]);
    let again = restored.checkpoint_with_dax(Some(target.dax())).unwrap();
    assert_eq!(again.state.dax, checkpoint.state.dax);
    assert_eq!(again.dax_pages, checkpoint.dax_pages);
    assert_host_matches(&target, state, &again.objects);
    // The restored writable mapping reaches the same object.
    target.write(0, b"T");
    restored.sync_for_snapshot().unwrap();
    mapped.file.read_exact_at(&mut written[..1], 0).unwrap();
    assert_eq!(&written[..1], b"T");

    // Removing the source mapping releases the mapped-only object there.
    let ino = mapped.ino;
    remove(&fs, &w, &[(0, 1)]).unwrap();
    let after = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    assert!(after.objects.iter().all(|o| o.ino != ino));
}

#[test]
fn snapshot_fs_dax_restore_rejects_malformed_mappings_and_pages() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("a", &paged(1, 0x10));
    let (w, target) = (Window::new(4), Window::new(4));
    let fs = init_share(dir.path());
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    setup(&fs, &w, a.inode, 0, 1, false, 0).unwrap();
    remove(&fs, &w, &[(1, 1)]).unwrap();
    w.write(3 * p, &[1]);
    let checkpoint = fs.checkpoint_with_dax(Some(w.dax())).unwrap();
    let objects = checkpoint.objects.len();
    let good = checkpoint.state.clone();
    assert!(good.validate(objects).is_ok());

    let cases: Vec<(&str, Box<dyn Fn(&mut DaxState)>)> = vec![
        ("gap", Box::new(move |s| s.mappings[1].moffset += p)),
        ("overlap", Box::new(move |s| s.mappings[1].moffset -= p)),
        ("empty mapping", Box::new(|s| s.mappings[1].len = 0)),
        ("unaligned length", Box::new(|s| s.mappings[1].len -= 1)),
        (
            "uncovered tail",
            Box::new(|s| {
                s.mappings.pop();
            }),
        ),
        ("past the window", Box::new(move |s| s.size -= p)),
        ("unaligned size", Box::new(|s| s.size += 1)),
        ("empty window", Box::new(|s| s.size = 0)),
        (
            "object range",
            Box::new(move |s| s.mappings[0].kind = file(objects as u64, 0, false)),
        ),
        (
            "unaligned file offset",
            Box::new(|s| s.mappings[0].kind = file(0, 1, false)),
        ),
        (
            "file offset past off_t",
            Box::new(|s| s.mappings[0].kind = file(0, i64::MAX as u64, false)),
        ),
    ];
    for (what, mutate) in cases {
        let mut state = good.clone();
        mutate(state.dax.as_mut().unwrap());
        assert!(
            matches!(
                state.validate(objects),
                Err(PassthroughSnapshotError::Invalid(_))
            ),
            "{what} accepted"
        );
        assert!(
            PassthroughFs::restore(
                snapshot_config(dir.path()),
                &state,
                same_host_objects(&checkpoint),
                checkpoint.init_binary.clone(),
            )
            .is_err(),
            "{what} restored"
        );
    }
    let mut before_init = good.clone();
    before_init.nodes.clear();
    before_init.handles.clear();
    assert!(before_init.validate(objects).is_err());

    let pages = &checkpoint.dax_pages;
    assert_eq!(pages.offsets, [3 * p]);
    let page_cases: Vec<(&str, DaxPages)> = vec![
        (
            "duplicate",
            DaxPages {
                offsets: vec![3 * p, 3 * p],
                data: [pages.data.clone(), pages.data.clone()].concat(),
            },
        ),
        (
            "unsorted",
            DaxPages {
                offsets: vec![3 * p, 2 * p],
                data: [pages.data.clone(), pages.data.clone()].concat(),
            },
        ),
        (
            "unaligned",
            DaxPages {
                offsets: vec![3 * p + 1],
                data: pages.data.clone(),
            },
        ),
        (
            "in a file mapping",
            DaxPages {
                offsets: vec![0],
                data: pages.data.clone(),
            },
        ),
        (
            "in a hole",
            DaxPages {
                offsets: vec![p],
                data: pages.data.clone(),
            },
        ),
        (
            "past the window",
            DaxPages {
                offsets: vec![4 * p],
                data: pages.data.clone(),
            },
        ),
        (
            "short data",
            DaxPages {
                offsets: vec![3 * p],
                data: pages.data[1..].to_vec(),
            },
        ),
        (
            "zero page",
            DaxPages {
                offsets: vec![3 * p],
                data: vec![0; DAX_PAGE_SIZE as usize],
            },
        ),
    ];
    let state = good.dax.as_ref().unwrap();
    let restore = || {
        PassthroughFs::restore(
            snapshot_config(dir.path()),
            &good,
            same_host_objects(&checkpoint),
            checkpoint.init_binary.clone(),
        )
        .unwrap()
    };
    let restored = restore();
    // A restored ledger is not capturable before it is mapped.
    assert!(restored.checkpoint_with_dax(Some(target.dax())).is_err());
    target.write(0, &[9]);
    for (what, bad) in page_cases {
        assert!(bad.validate(state).is_err(), "{what} accepted");
        assert!(
            restored.map_dax(target.dax(), &bad).is_err(),
            "{what} mapped"
        );
    }
    // Refused before any mapping: the target window is untouched.
    assert_eq!(target.read(0, 1), [9]);
    let small = DaxWindow {
        host_addr: target.addr,
        size: target.size - p,
    };
    assert!(restored.map_dax(small, pages).is_err());
    restored.map_dax(target.dax(), pages).unwrap();
    assert!(restored.map_dax(target.dax(), pages).is_err());
    assert_eq!(target.read(3 * p, 1), [1]);
}

#[test]
fn snapshot_fs_dax_device_session_maps_the_window_on_restore() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(1, 0x33));
    let (w, target) = (Window::new(4), Window::new(4));
    let mut device = Rig::device(dir.path());
    device.set_shm_region(w.shm());
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut rig = Rig::activate(guest, device, queues, false);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    let setup = SetupmappingIn {
        fh: 0,
        foffset: 0,
        len: p,
        flags: (SetupmappingFlags::READ | SetupmappingFlags::WRITE).bits(),
        moffset: p,
    };
    rig.ok(Opcode::SetupMapping, f.nodeid, setup.as_slice());
    w.write(p, b"dax");
    let removal = [
        RemovemappingIn { count: 1 }.as_slice(),
        RemovemappingOne {
            moffset: 3 * p,
            len: p,
        }
        .as_slice(),
    ]
    .concat();
    rig.ok(Opcode::RemoveMapping, 0, &removal);
    rig.freeze();
    // The frozen worker wrote the writable mapping back.
    assert_eq!(&fs::read(dir.path().join("f")).unwrap()[..3], b"dax");

    let session = rig.fs.snapshot_session().unwrap().unwrap();
    let state = &session.passthrough.state;
    let object = object_of(&session.passthrough, &dir.path().join("f"));
    assert_eq!(
        state.dax.as_ref().unwrap().mappings,
        vec![
            mapping(0, 1, ANON),
            mapping(1, 1, file(object, 0, true)),
            mapping(2, 1, ANON),
            mapping(3, 1, HOLE),
        ]
    );
    let restore = |device: &mut Fs| {
        device.restore_session(
            session.options,
            state,
            same_host_objects(&session.passthrough),
            session.passthrough.init_binary.clone(),
            &session.passthrough.dax_pages,
        )
    };
    // A device without a window, or with another size, refuses the session.
    let mut plain = Rig::device(dir.path());
    assert!(restore(&mut plain).is_err());
    let small = Window::new(2);
    let mut other = Rig::device(dir.path());
    other.set_shm_region(small.shm());
    assert!(restore(&mut other).is_err());
    // The restored device maps its own window before it runs.
    let mut restored = Rig::device(dir.path());
    restored.set_shm_region(target.shm());
    restore(&mut restored).unwrap();
    assert_eq!(target.read(p, 3), b"dax");
    assert_host_matches(
        &target,
        state.dax.as_ref().unwrap(),
        &session.passthrough.objects,
    );
}

#[test]
fn snapshot_fs_restore_session_rejects_pages_without_a_window() {
    let dir = TempDir::new();
    let mut rig = Rig::new(dir.path());
    rig.init();
    rig.freeze();
    let session = rig.fs.snapshot_session().unwrap().unwrap();
    let checkpoint = &session.passthrough;
    assert_eq!(checkpoint.state.dax, None);
    let restore = |device: &mut Fs, pages: &DaxPages| {
        device.restore_session(
            session.options,
            &checkpoint.state,
            same_host_objects(checkpoint),
            checkpoint.init_binary.clone(),
            pages,
        )
    };
    let mut device = Rig::device(dir.path());
    let pages = DaxPages {
        offsets: vec![0],
        data: vec![1; DAX_PAGE_SIZE as usize],
    };
    assert!(matches!(
        restore(&mut device, &pages),
        Err(PassthroughSnapshotError::Invalid(_))
    ));
    // Refused before the session was built: the device still takes one.
    restore(&mut device, &DaxPages::default()).unwrap();
}

#[test]
fn snapshot_fs_reset_returns_the_dax_window_to_zero_memory() {
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(1, 0x33));
    let w = Window::new(4);
    let mut device = Rig::device(dir.path());
    device.set_shm_region(w.shm());
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut rig = Rig::activate(guest, device, queues, false);
    rig.init();
    let f = rig.lookup(fuse::ROOT_ID, "f");
    let setup = SetupmappingIn {
        fh: 0,
        foffset: 0,
        len: p,
        flags: SetupmappingFlags::READ.bits(),
        moffset: p,
    };
    rig.ok(Opcode::SetupMapping, f.nodeid, setup.as_slice());
    let removal = [
        RemovemappingIn { count: 1 }.as_slice(),
        RemovemappingOne {
            moffset: 3 * p,
            len: p,
        }
        .as_slice(),
    ]
    .concat();
    rig.ok(Opcode::RemoveMapping, 0, &removal);
    rig.fs.reset();
    // The session's file mapping and hole are gone with it (the file page
    // first: the hole would fault).
    assert_eq!(w.read(p, p), vec![0; p as usize]);
    assert_eq!(w.read(0, 4 * p), vec![0; 4 * p as usize]);
    // The next session's ledger starts from that zero memory.
    let device = mem::replace(&mut rig.fs, Rig::device(dir.path()));
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut again = Rig::activate(guest, device, queues, false);
    again.init();
    again.freeze();
    let session = again.fs.snapshot_session().unwrap().unwrap().passthrough;
    assert!(session.dax_pages.offsets.is_empty());
    assert_eq!(
        session.state.dax.unwrap().mappings,
        vec![mapping(0, 4, ANON)]
    );
}

#[test]
fn snapshot_fs_reset_keeps_serving_the_restored_init() {
    let dir = TempDir::new();
    let mut source = Rig::new(dir.path());
    source.init();
    let queues = source.freeze();
    let init: Arc<[u8]> = Arc::from(&b"archived init"[..]);
    let mut target = Rig::restored_with_init(&source, dir.path(), &queues, Some(init.clone()));
    target.resume();
    let read_init = |rig: &mut Rig| {
        let read = ReadIn {
            fh: 0,
            size: 64,
            ..Default::default()
        };
        rig.ok(Opcode::Read, fuse::ROOT_ID + 1, read.as_slice())
    };
    assert_eq!(read_init(&mut target), &init[..]);
    // After a reset the guest mounts a new session of the same share.
    target.fs.reset();
    let device = mem::replace(&mut target.fs, Rig::device(dir.path()));
    let guest = Guest::new(0xfffe);
    let queues = (0..NUM_QUEUES).map(|q| guest.queue(q)).collect();
    let mut again = Rig::activate(guest, device, queues, false);
    again.init();
    assert_eq!(read_init(&mut again), &init[..]);
}

/// A snapshot owner's execution control as these tests see it: it records
/// whether each remapping it ran kept the window, and once `ended` it runs
/// none, as an owner whose guest execution ended.
#[derive(Default)]
struct Control {
    kept: Mutex<Vec<bool>>,
    ended: AtomicBool,
}

impl DaxMappingControl for Control {
    fn exclusive(&self, remap: &mut dyn FnMut() -> bool) {
        if !self.ended.load(Ordering::SeqCst) {
            let kept = remap();
            self.kept.lock().unwrap().push(kept);
        }
    }
}

impl Control {
    fn kept(&self) -> Vec<bool> {
        self.kept.lock().unwrap().clone()
    }
}

fn controlled_share(dir: &Path, control: &Arc<Control>) -> PassthroughFs {
    let fs = PassthroughFs::new(passthrough::Config {
        dax_control: Some(control.clone()),
        ..snapshot_config(dir)
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

/// Every host mapping call on a live window runs inside the owner's
/// control, including a `MAP_FIXED` that fails (the guest must not run over
/// a range it may have handed to other memory) and an `mprotect` that
/// fails (which hands nothing away); a control whose guest execution ended
/// runs nothing, so the window stays as it was and the share gives it up
/// without naming any range.
#[test]
fn snapshot_fs_dax_window_remappings_run_inside_the_owner_control() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("a", &paged(2, 0x10));
    let control = Arc::new(Control::default());
    let w = Window::new(4);
    let fs = controlled_share(dir.path(), &control);
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    setup(&fs, &w, a.inode, 0, 2, false, 0).unwrap();
    // The read-only copy: a `MAP_FIXED`, then an `mprotect`.
    setup(&fs, &w, init.inode, 0, 1, false, 2).unwrap();
    remove(&fs, &w, &[(0, 1), (3, 1)]).unwrap();
    assert_eq!(control.kept(), [true; 5]);
    arm(w.addr + p, Fault::MapAfterUnmap);
    let failed = setup(&fs, &w, a.inode, 0, 1, true, 1);
    assert_eq!(failed.unwrap_err().raw_os_error(), Some(libc::ENOMEM));
    assert_eq!(control.kept(), [true, true, true, true, true, false]);
    assert!(fs.dax_window_lost());
    assert_eq!(fs.dax_unowned(), [(p, p)]);
    reclaim(w, p, p);

    let w = Window::new(2);
    let fs = controlled_share(dir.path(), &control);
    let init = fs.lookup(CTX, fuse::ROOT_ID, &cstr("init.krun")).unwrap();
    arm(w.addr, Fault::ProtectPartly);
    assert!(setup(&fs, &w, init.inode, 0, 2, false, 0).is_err());
    assert_eq!(control.kept()[6..], [true, false]);
    assert!(fs.dax_window_lost());
    assert!(fs.dax_unowned().is_empty());

    let w = Window::new(2);
    let fs = controlled_share(dir.path(), &control);
    let a = fs.lookup(CTX, fuse::ROOT_ID, &cstr("a")).unwrap();
    w.write(0, &[7]);
    control.ended.store(true, Ordering::SeqCst);
    let skipped = setup(&fs, &w, a.inode, 0, 1, false, 0);
    assert_eq!(skipped.unwrap_err().raw_os_error(), Some(libc::EIO));
    assert_eq!(w.read(0, 1), [7], "the window was remapped");
    assert!(fs.dax_window_lost());
    assert!(fs.dax_unowned().is_empty(), "a skipped call named a range");
    assert_eq!(control.kept().len(), 8);
}

/// A device's restore maps each saved segment, and its guest reset remaps
/// the window, inside the owner's control; a reset the control no longer
/// runs leaves the window untouched and the device discarded, still owning
/// the whole window.
#[test]
fn snapshot_fs_dax_restore_and_reset_remap_inside_the_owner_control() {
    use passthrough::dax_faults::{arm, Fault};
    let p = host_page();
    let dir = TempDir::new();
    dir.file("f", &paged(2, 0x33));
    let source = Window::new(4);
    let rig = mapped_session(dir.path(), &source);
    let session = rig.fs.snapshot_session().unwrap().unwrap();
    let segments = session
        .passthrough
        .state
        .dax
        .as_ref()
        .unwrap()
        .mappings
        .len();
    let restore = |w: &Window, control: &Arc<Control>| {
        let mut device = Rig::device(dir.path());
        device.set_shm_region(w.shm());
        device.set_dax_control(control.clone());
        let restored = device.restore_session(
            session.options,
            &session.passthrough.state,
            same_host_objects(&session.passthrough),
            session.passthrough.init_binary.clone(),
            &session.passthrough.dax_pages,
        );
        (device, restored)
    };

    let control = Arc::new(Control::default());
    let w = Window::new(4);
    let (mut device, restored) = restore(&w, &control);
    restored.unwrap();
    assert_eq!(control.kept(), vec![true; segments]);
    device.reset();
    assert_eq!(control.kept(), vec![true; segments + 1]);
    assert!(!device.must_discard());

    let control = Arc::new(Control::default());
    let w = Window::new(4);
    arm(w.addr + p, Fault::MapAfterUnmap);
    let (failed, restored) = restore(&w, &control);
    assert!(restored.is_err());
    assert_eq!(control.kept().last(), Some(&false));
    assert_eq!(failed.dax_unowned(), [(p, 2 * p)]);
    drop(failed);
    reclaim(w, p, 2 * p);

    let control = Arc::new(Control::default());
    let w = Window::new(4);
    let (mut device, restored) = restore(&w, &control);
    restored.unwrap();
    control.ended.store(true, Ordering::SeqCst);
    device.reset();
    assert_eq!(w.read(0, 1), [5], "the window was remapped");
    assert!(device.must_discard());
    assert!(
        device.dax_unowned().is_empty(),
        "a skipped reset named a range"
    );
}

mod archive;

#[test]
fn snapshot_fs_supplied_roles_reject_missing_wrong_identity_and_access() {
    let dir = TempDir::new();
    dir.file("file", &paged(1, 0x44));
    dir.file("other", &paged(1, 0x55));
    let source = init_share(dir.path());
    let inode = source
        .lookup(CTX, fuse::ROOT_ID, &cstr("file"))
        .unwrap()
        .inode;
    let handle = source
        .open(CTX, inode, false, libc::O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let window = Window::new(1);
    setup(&source, &window, inode, 0, 1, true, 0).unwrap();
    let checkpoint = source.checkpoint_with_dax(Some(window.dax())).unwrap();
    let index = checkpoint
        .state
        .handles
        .iter()
        .find(|h| h.handle == handle)
        .unwrap()
        .object;
    for wrong in ["missing", "identity", "access", "dax", "extra"] {
        let open = |name: &str, write: bool| {
            fs::OpenOptions::new()
                .read(true)
                .write(write)
                .open(dir.path().join(name))
                .unwrap()
        };
        let mut roles = passthrough::RestoredRoles {
            handles: [(
                handle,
                open(
                    if wrong == "identity" { "other" } else { "file" },
                    wrong != "access",
                ),
            )]
            .into(),
            dax: [((index, true), open("file", wrong != "dax"))].into(),
        };
        if wrong == "missing" {
            roles.handles.clear();
        }
        if wrong == "extra" {
            roles.handles.insert(handle + 1, open("file", true));
        }
        let restored = PassthroughFs::restore_with_roles(
            snapshot_config(dir.path()),
            &checkpoint.state,
            same_host_objects(&checkpoint),
            checkpoint.init_binary.clone(),
            roles,
        );
        assert!(
            matches!(restored, Err(PassthroughSnapshotError::Invalid(_))),
            "accepted {wrong} role"
        );
    }
    assert!(PassthroughFs::restore_with_roles(
        snapshot_config(dir.path()),
        &checkpoint.state,
        vec![],
        checkpoint.init_binary.clone(),
        passthrough::RestoredRoles::default()
    )
    .is_err());
}

// Use a SNAPSHOT_RUNNER granting only CAP_FOWNER to the test process and
// appending --include-ignored. The fixture then drops the effective capability
// before provider opens and restore; no namespace or host policy is changed.
#[test]
#[ignore = "requires a real CAP_FOWNER source; restore drops the effective capability"]
fn snapshot_fs_supplied_noatime_survives_capability_drop() {
    use caps::{CapSet, Capability};
    use std::os::unix::fs::OpenOptionsExt;

    assert!(caps::has_cap(None, CapSet::Effective, Capability::CAP_FOWNER).unwrap());
    let dir = TempDir::new();
    dir.file("file", b"retained noatime handle");
    let source = init_share(dir.path());
    let inode = source
        .lookup(CTX, fuse::ROOT_ID, &cstr("file"))
        .unwrap()
        .inode;
    let handle = source
        .open(CTX, inode, false, (libc::O_RDWR | libc::O_NOATIME) as u32)
        .unwrap()
        .0
        .unwrap();
    let checkpoint = source.checkpoint().unwrap();
    let saved = checkpoint
        .state
        .handles
        .iter()
        .find(|h| h.handle == handle)
        .unwrap();
    assert_ne!(
        saved.flags & libc::O_NOATIME,
        0,
        "source stripped O_NOATIME"
    );

    let _cap = passthrough::drop_effective_cap(Capability::CAP_FOWNER)
        .unwrap()
        .unwrap();
    assert!(!caps::has_cap(None, CapSet::Effective, Capability::CAP_FOWNER).unwrap());
    // Ownership permits this independent provider open without CAP_FOWNER.
    let roles = |noatime| passthrough::RestoredRoles {
        handles: [(
            handle,
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(if noatime { libc::O_NOATIME } else { 0 })
                .open(dir.path().join("file"))
                .unwrap(),
        )]
        .into(),
        ..Default::default()
    };
    assert!(
        PassthroughFs::restore_with_roles(
            snapshot_config(dir.path()),
            &checkpoint.state,
            same_host_objects(&checkpoint),
            checkpoint.init_binary.clone(),
            roles(false)
        )
        .is_err(),
        "accepted a supplied FD missing saved O_NOATIME"
    );
    let supplied = roles(true);
    let actual = unsafe { libc::fcntl(supplied.handles[&handle].as_raw_fd(), libc::F_GETFL) };
    assert!(actual >= 0);
    assert_ne!(actual & libc::O_NOATIME, 0);
    supplied
        .validate(&checkpoint.state, &same_host_objects(&checkpoint))
        .unwrap();
    let restored = PassthroughFs::restore_with_roles(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
        supplied,
    )
    .expect("valid supplied O_NOATIME role failed after capability drop");
    let recaptured = restored.checkpoint().unwrap();
    assert_eq!(
        recaptured
            .state
            .handles
            .iter()
            .find(|h| h.handle == handle)
            .unwrap()
            .flags,
        saved.flags,
        "supplied role lost its saved flags"
    );

    // The legacy reopen path still follows the ordinary open capability policy.
    let reopened = PassthroughFs::restore(
        snapshot_config(dir.path()),
        &checkpoint.state,
        same_host_objects(&checkpoint),
        checkpoint.init_binary.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .checkpoint()
            .unwrap()
            .state
            .handles
            .iter()
            .find(|h| h.handle == handle)
            .unwrap()
            .flags,
        saved.flags & !libc::O_NOATIME
    );
}
