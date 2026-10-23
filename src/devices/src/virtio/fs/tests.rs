// Every test name starts with "snapshot_fs" so `make snapshot-test` selects
// them. Linux only: the checkpointable share is the Linux passthrough.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::mem::{self, size_of};
use std::num::Wrapping;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
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
    OutHeader, ReadIn, WriteIn,
};
use super::passthrough::{
    self, PassthroughCheckpoint, PassthroughFs, PassthroughSnapshotError, PassthroughState,
    RestoredObject, SYNTHETIC_INO_BASE,
};
use super::worker::{request_gate, FsServer};
use super::Fs;
use crate::legacy::DummyIrqChip;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{
    Descriptor, DeviceQueue, InterruptTransport, Queue, VirtioDevice, VIRTIO_MMIO_INT_VRING,
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
        root_dir: dir.to_str().unwrap().to_string(),
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
/// archive that rebuilds them elsewhere is not part of this layer).
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
        root_dir: dir.path().to_str().unwrap().to_string(),
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
                root_dir: dir.path().to_str().unwrap().to_string(),
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
