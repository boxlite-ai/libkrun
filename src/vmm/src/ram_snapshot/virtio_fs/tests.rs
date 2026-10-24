// SPDX-License-Identifier: Apache-2.0

//! virtio-fs checkpoints without KVM: the owner's device build, freeze,
//! capture, metadata and ring validation, payload, import and restore paths
//! on a transport over guest RAM and a DAX window mapped as the owner maps
//! it, driven through MMIO and FUSE requests in guest RAM; plus the layout,
//! memslot and window-ownership checks. The FUSE driver here is shared with
//! `kvm_tests`, where the guest vCPU performs every MMIO access. Tests that
//! archive a share need root with CAP_SYS_ADMIN, as the devices crate's
//! archive tests do. Every test name contains "snapshot".

use std::ffi::OsStr;
use std::fs;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicUsize, Ordering};

use devices::legacy::DummyIrqChip;
use devices::virtio::fs::fuse::{
    self, EntryOut, InHeader, InitInCompat, IoctlIn, Opcode, OpenIn, OpenOut, OutHeader, ReadIn,
    SetupmappingFlags, SetupmappingIn, WriteIn,
};
use devices::BusDevice;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryRegion};

use super::*;
use crate::ram_snapshot::console::tests::{wait_until, Driver, Mmio, RAM_LEN};
use crate::ram_snapshot::execution::ExecutionBarrier;

/// The high-priority and request queues.
pub(super) const REQUEST: usize = 1;
/// Bytes of each reply buffer.
const REPLY: u32 = 0x1000;
/// VIRTIO_MMIO_INT_VRING in InterruptStatus.
pub(super) const INT_VRING: u32 = 1;
/// `VIRTIO_IOC_REMOVE_ROOT_DIR` (`_IO('v', 3)`, the devices crate's
/// passthrough ioctl).
const REMOVE_ROOT_DIR: u32 = (b'v' as u32) << 8 | 3;
/// FUSE_INIT flags: ASYNC_READ and BIG_WRITES.
const INIT_FLAGS: u32 = 1 | 1 << 5;
const PAGE: u64 = 4096;

pub(super) struct TempDir(pub(super) PathBuf);

impl TempDir {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "kfs{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The guest side of FUSE over the request queue: rings and buffers in
/// guest RAM, so a copy taken with the RAM image continues on a restored
/// VM.
#[derive(Clone)]
pub(super) struct Fuse {
    driver: Driver,
    unique: u64,
}

impl Fuse {
    pub(super) fn new() -> Fuse {
        Fuse {
            driver: Driver::with_queues(FS_NUM_QUEUES),
            unique: 1,
        }
    }

    /// Negotiate VERSION_1 only and configure both queues.
    pub(super) fn activate(&self, mmio: &dyn Mmio) {
        self.driver.activate_with(mmio, 0);
    }

    /// Make a request (header and `body`) with its reply buffer available on
    /// the request queue, without a notification; returns its unique ID and
    /// reply address.
    pub(super) fn post(
        &mut self,
        mem: &GuestMemoryMmap,
        opcode: Opcode,
        nodeid: u64,
        body: &[u8],
    ) -> (u64, u64) {
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
        let input = self.driver.alloc(request.len());
        mem.write_slice(&request, GuestAddress(input)).unwrap();
        let output = self.driver.alloc(REPLY as usize);
        let out_header = size_of::<OutHeader>() as u32;
        self.driver.post(
            mem,
            REQUEST,
            &[
                (input, request.len() as u32, false),
                (output, out_header, true),
                (output + u64::from(out_header), REPLY - out_header, true),
            ],
        );
        (unique, output)
    }

    /// The reply at `addr`: its header and payload.
    pub(super) fn reply(mem: &GuestMemoryMmap, addr: u64) -> (OutHeader, Vec<u8>) {
        let header: OutHeader = mem.read_obj(GuestAddress(addr)).unwrap();
        let len = header.len - size_of::<OutHeader>() as u32;
        let payload = Driver::read(mem, addr + size_of::<OutHeader>() as u64, len);
        (header, payload)
    }

    /// Post, notify and wait for one request's reply.
    pub(super) fn call(
        &mut self,
        mem: &GuestMemoryMmap,
        mmio: &dyn Mmio,
        opcode: Opcode,
        nodeid: u64,
        body: &[u8],
    ) -> (OutHeader, Vec<u8>) {
        let before = Driver::used(mem, REQUEST).len();
        let (unique, reply) = self.post(mem, opcode, nodeid, body);
        mmio.write(0x50, REQUEST as u32);
        wait_until("FUSE reply", || Driver::used(mem, REQUEST).len() > before);
        let (header, payload) = Fuse::reply(mem, reply);
        assert_eq!(header.unique, unique);
        (header, payload)
    }

    pub(super) fn ok(
        &mut self,
        mem: &GuestMemoryMmap,
        mmio: &dyn Mmio,
        opcode: Opcode,
        nodeid: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let (header, payload) = self.call(mem, mmio, opcode, nodeid, body);
        assert_eq!(header.error, 0, "{opcode:?} failed");
        payload
    }

    pub(super) fn init(&mut self, mem: &GuestMemoryMmap, mmio: &dyn Mmio) {
        let init = InitInCompat {
            major: fuse::KERNEL_VERSION,
            minor: fuse::KERNEL_MINOR_VERSION,
            max_readahead: 0,
            flags: INIT_FLAGS,
        };
        self.ok(mem, mmio, Opcode::Init, 0, init.as_slice());
    }

    pub(super) fn lookup(
        &mut self,
        mem: &GuestMemoryMmap,
        mmio: &dyn Mmio,
        parent: u64,
        name: &[u8],
    ) -> EntryOut {
        let mut body = name.to_vec();
        body.push(0);
        let payload = self.ok(mem, mmio, Opcode::Lookup, parent, &body);
        *EntryOut::from_slice(&payload).unwrap()
    }

    pub(super) fn open(
        &mut self,
        mem: &GuestMemoryMmap,
        mmio: &dyn Mmio,
        nodeid: u64,
        flags: i32,
    ) -> u64 {
        let open = OpenIn {
            flags: flags as u32,
            open_flags: 0,
        };
        let payload = self.ok(mem, mmio, Opcode::Open, nodeid, open.as_slice());
        OpenOut::from_slice(&payload).unwrap().fh
    }

    pub(super) fn read_body(fh: u64, offset: u64, size: u32) -> Vec<u8> {
        ReadIn {
            fh,
            offset,
            size,
            ..Default::default()
        }
        .as_slice()
        .to_vec()
    }

    pub(super) fn write_body(fh: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut body = WriteIn {
            fh,
            offset,
            size: data.len() as u32,
            ..Default::default()
        }
        .as_slice()
        .to_vec();
        body.extend_from_slice(data);
        body
    }

    /// FUSE_SETUPMAPPING of `len` bytes of `fh` from `foffset` at window
    /// offset `moffset`.
    pub(super) fn mapping_body(
        fh: u64,
        foffset: u64,
        len: u64,
        moffset: u64,
        write: bool,
    ) -> Vec<u8> {
        let mut flags = SetupmappingFlags::READ;
        if write {
            flags |= SetupmappingFlags::WRITE;
        }
        SetupmappingIn {
            fh,
            foffset,
            len,
            flags: flags.bits(),
            moffset,
        }
        .as_slice()
        .to_vec()
    }
}

/// One share on a transport and a DAX window, as the owner wires it minus
/// KVM.
struct Side {
    mem: GuestMemoryMmap,
    share: FsDevice,
    backing: Option<DaxBacking>,
}

impl Mmio for Side {
    fn write(&self, offset: u64, value: u32) {
        self.share
            .transport
            .lock()
            .unwrap()
            .write(0, offset, &value.to_le_bytes());
    }

    fn read(&self, offset: u64) -> u32 {
        let mut bytes = [0; 4];
        self.share
            .transport
            .lock()
            .unwrap()
            .read(0, offset, &mut bytes);
        u32::from_le_bytes(bytes)
    }
}

const DAX: DaxRange = DaxRange {
    gpa: 0x1000_0000,
    len: 4 * PAGE,
};

impl Side {
    fn new(mem: GuestMemoryMmap, root: PathBuf, tag: &str, dax: Option<DaxRange>) -> Side {
        let backing = dax.map(|range| DaxBacking::new(range.len).unwrap());
        let parts = build(
            mem.clone(),
            DummyIrqChip::new().into(),
            Share {
                tag,
                root,
                read_only: false,
                allow_root_dir_delete: true,
                window: dax.zip(backing.as_ref()).map(|(r, b)| b.region(r.gpa)),
            },
        )
        .unwrap();
        Side::wrap(mem, parts, tag, dax, backing)
    }

    fn wrap(
        mem: GuestMemoryMmap,
        (device, transport): Parts,
        tag: &str,
        dax: Option<DaxRange>,
        backing: Option<DaxBacking>,
    ) -> Side {
        Side {
            mem,
            share: FsDevice {
                device,
                transport,
                index: 0,
                tag: tag.to_owned(),
                read_only: false,
                allow_root_dir_delete: true,
                dax: dax.map(|range| (range, 0)),
            },
            backing,
        }
    }

    fn source(root: &Path, dax: Option<DaxRange>) -> Side {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
        Side::new(mem, root.to_owned(), "share0", dax)
    }

    /// What the guest reads in the DAX window at `offset`.
    fn window(&self, offset: u64, len: usize) -> Vec<u8> {
        let host = self.backing.as_ref().unwrap().host + offset;
        // SAFETY: the range lies inside the window, readable while mapped.
        unsafe { std::slice::from_raw_parts(host as *const u8, len) }.to_vec()
    }

    fn write_window(&self, offset: u64, bytes: &[u8]) {
        let host = self.backing.as_ref().unwrap().host + offset;
        // SAFETY: the range lies inside the window's anonymous memory.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host as *mut u8, bytes.len()) };
    }

    fn shares(&self) -> &[FsDevice] {
        std::slice::from_ref(&self.share)
    }

    /// Capture as an export does, write the payloads to `payloads` and
    /// return the metadata after a JSON round trip.
    fn export(&self, cuts: &[Option<Vec<QueueState>>], payloads: &Path) -> FsMeta {
        let (meta, archive) = capture(self.shares(), cuts).unwrap().unwrap();
        validate_metadata(&meta, &regions(), &[], 32).unwrap();
        validate_rings(&meta, &self.mem).unwrap();
        let mut file = File::create(payloads).unwrap();
        write_payloads(&mut file, &archive).unwrap();
        serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap()
    }

    /// The import path minus KVM: RAM copied, metadata and rings checked
    /// before anything exists, the shares imported into `dir`, the device
    /// rebuilt on the imported root and restored into a new window.
    fn restored(&self, meta: &FsMeta, payloads: &Path, dir: &Path) -> (Side, ImportedArchive) {
        validate_metadata(meta, &regions(), &[], 32).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
        let mut ram = vec![0; RAM_LEN];
        self.mem.read_slice(&mut ram, GuestAddress(0)).unwrap();
        mem.write_slice(&ram, GuestAddress(0)).unwrap();
        validate_rings(meta, &mem).unwrap();
        let mut imported = import_shares(&File::open(payloads).unwrap(), meta, dir).unwrap();
        let device = &meta.devices[0];
        let side = Side::new(mem, imported.root(0).to_owned(), &device.tag, device.dax);
        imported.hold(side.share.device.clone());
        restore_parts(
            &side.share.device,
            &side.share.transport,
            &imported,
            0,
            device,
        )
        .unwrap();
        (side, imported)
    }

    /// References to the RAM mapping: this side, the probe's and every
    /// device clone, as `probe_ram_aliases` counts them.
    fn mapping_refs(&self) -> usize {
        let region = self.mem.iter().next().unwrap();
        let (_rest, mapping) = self
            .mem
            .remove_region(region.start_addr(), region.len())
            .unwrap();
        Arc::strong_count(&mapping)
    }
}

impl Drop for Side {
    fn drop(&mut self) {
        // Stop the worker before the window's backing goes.
        self.share.device.lock().unwrap().retire();
    }
}

fn regions() -> Vec<Region> {
    vec![Region {
        gpa: 0,
        len: RAM_LEN as u64,
        attributes: 0,
    }]
}

/// A paused share's interrupt status and pending request, its handle, its
/// DAX file mapping and anonymous window bytes continue on an independent
/// copy after the source directory is gone: the restored worker answers
/// the request posted at the cut without a notification, the original
/// handle reads and writes the copy, and the window maps the copy.
#[test]
fn snapshot_fs_vmm_export_import_continues_handles_dax_and_requests() {
    let dir = TempDir::new();
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), vec![0x33; PAGE as usize]).unwrap();
    let source = Side::source(&src, Some(DAX));
    assert_eq!(source.mapping_refs(), 2 + 1);
    let mut guest = Fuse::new();
    guest.activate(&source);
    let mem = &source.mem;
    guest.init(mem, &source);
    let f = guest.lookup(mem, &source, fuse::ROOT_ID, b"f");
    let fh = guest.open(mem, &source, f.nodeid, libc::O_RDWR);
    guest.ok(
        mem,
        &source,
        Opcode::Write,
        f.nodeid,
        &Fuse::write_body(fh, 0, b"hello"),
    );
    let mapping = Fuse::mapping_body(fh, 0, PAGE, PAGE, true);
    guest.ok(mem, &source, Opcode::SetupMapping, f.nodeid, &mapping);
    assert_eq!(source.window(PAGE, 5), b"hello");
    source.write_window(0, b"anon");
    // A request made available but not yet seen at the cut.
    let read = Fuse::read_body(fh, 0, PAGE as u32);
    let (unique, reply) = guest.post(mem, Opcode::Read, f.nodeid, &read);
    assert_ne!(source.read(0x60) & INT_VRING, 0);

    let cuts = freeze(source.shares()).unwrap();
    assert_eq!(
        source.mapping_refs(),
        2 + 3,
        "transport, device and worker clones"
    );
    let meta = source.export(&cuts, &dir.path("payloads"));
    assert_eq!(meta.devices[0].dax, Some(DAX));
    assert!(meta.devices[0].device.activated);
    fs::remove_dir_all(&src).unwrap();

    let (target, imported) = source.restored(&meta, &dir.path("payloads"), &dir.path("shares"));
    imported.persist();
    assert_eq!(target.window(0, 4), b"anon");
    assert_eq!(target.window(PAGE, 5), b"hello");
    assert_ne!(target.read(0x60) & INT_VRING, 0);
    // The restored worker sees the pending request once resumed.
    resume(target.shares()).unwrap();
    let tmem = target.mem.clone();
    wait_until("the pending request", || {
        Driver::used(&tmem, REQUEST).len() == Driver::used(mem, REQUEST).len() + 1
    });
    let (header, payload) = Fuse::reply(&tmem, reply);
    assert_eq!((header.unique, header.error), (unique, 0));
    assert_eq!(&payload[..6], b"hello\x33");
    // The guest keeps its node and handle on the copy, which the window maps.
    let write = Fuse::write_body(fh, 5, b" world");
    guest.ok(&tmem, &target, Opcode::Write, f.nodeid, &write);
    let copy = dir.path("shares").join("0").join("f");
    assert_eq!(&fs::read(&copy).unwrap()[..11], b"hello world");
    assert_eq!(target.window(PAGE, 11), b"hello world");
    target.write_window(PAGE, b"J");
    assert_eq!(fs::read(&copy).unwrap()[0], b'J');
    // The source side stops, never having resumed.
    drop(source);
}

/// The metadata and payloads of one activated share over `dir` (holding
/// "f") with an open read-write handle and a DAX window, as an export
/// captures them.
pub(in crate::ram_snapshot) fn captured_share(dir: &Path) -> (FsMeta, Vec<u8>) {
    let side = Side::source(dir, Some(DAX));
    let mut guest = Fuse::new();
    guest.activate(&side);
    let mem = &side.mem;
    guest.init(mem, &side);
    let f = guest.lookup(mem, &side, fuse::ROOT_ID, b"f");
    guest.open(mem, &side, f.nodeid, libc::O_RDWR);
    let cuts = freeze(side.shares()).unwrap();
    let (meta, archive) = capture(side.shares(), &cuts).unwrap().unwrap();
    let mut payloads = Vec::new();
    archive.write_files(&mut payloads).unwrap();
    archive.write_init(&mut payloads).unwrap();
    archive.write_pages(&mut payloads).unwrap();
    (meta, payloads)
}

/// A share nested in another under a non-UTF-8 name is rebuilt on its
/// exact imported root, and allow_root_dir_delete removes that root, not
/// a stand-in path.
#[test]
fn snapshot_fs_vmm_non_utf8_nested_root_restores_on_its_imported_root() {
    let dir = TempDir::new();
    let src = dir.path("src");
    let nested = src.join("sub").join(OsStr::from_bytes(b"bad\xff"));
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("g"), b"nested").unwrap();
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
    let outer = Side::new(mem.clone(), src.clone(), "outer", None);
    let mut inner = Side::new(mem, nested.clone(), "inner", None);
    inner.share.index = 1;
    let shares = [clone_share(&outer.share), clone_share(&inner.share)];
    let (meta, archive) = capture(&shares, &[None, None]).unwrap().unwrap();
    validate_metadata(&meta, &regions(), &[], 32).unwrap();
    let payloads = dir.path("payloads");
    write_payloads(&mut File::create(&payloads).unwrap(), &archive).unwrap();
    let meta: FsMeta = serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
    let shares_dir = dir.path("shares");
    let mut imported = import_shares(&File::open(&payloads).unwrap(), &meta, &shares_dir).unwrap();
    let root = imported.root(1).to_owned();
    assert_eq!(
        root,
        shares_dir.join("0/sub").join(OsStr::from_bytes(b"bad\xff"))
    );
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN)]).unwrap();
    let target = Side::new(mem.clone(), root.clone(), "inner", None);
    imported.hold(target.share.device.clone());
    restore_parts(
        &target.share.device,
        &target.share.transport,
        &imported,
        1,
        &meta.devices[1],
    )
    .unwrap();
    imported.persist();
    let mut guest = Fuse::new();
    guest.activate(&target);
    guest.init(&mem, &target);
    let g = guest.lookup(&mem, &target, fuse::ROOT_ID, b"g");
    let fh = guest.open(&mem, &target, g.nodeid, libc::O_RDONLY);
    let data = guest.ok(
        &mem,
        &target,
        Opcode::Read,
        g.nodeid,
        &Fuse::read_body(fh, 0, 16),
    );
    assert_eq!(data, b"nested");
    let ioctl = IoctlIn {
        cmd: REMOVE_ROOT_DIR,
        ..Default::default()
    };
    guest.ok(
        &mem,
        &target,
        Opcode::Ioctl,
        fuse::ROOT_ID,
        ioctl.as_slice(),
    );
    assert!(!root.exists());
    assert!(shares_dir.join("0/sub").is_dir());
    drop((outer, inner));
}

/// A second handle on the same device and transport, for a capture of
/// several shares.
fn clone_share(share: &FsDevice) -> FsDevice {
    FsDevice {
        device: share.device.clone(),
        transport: share.transport.clone(),
        index: share.index,
        tag: share.tag.clone(),
        read_only: share.read_only,
        allow_root_dir_delete: share.allow_root_dir_delete,
        dax: share.dax,
    }
}

/// `meta` is refused for the reason `reason` names.
fn rejected(meta: &FsMeta, case: &str, reason: &str) {
    match validate_metadata(meta, &regions(), &[0xd000_9000], 32) {
        Ok(_) => panic!("accepted {case}"),
        Err(e) => assert!(e.to_string().contains(reason), "{case}: {e}"),
    }
}

const SLOT: &str = "outside its slot";
const TAG: &str = "tag is empty, longer than 36 bytes";
const LAYOUT: &str = "DAX window overlaps RAM, a device or another window";
const SHAPE: &str = "DAX window is empty, unaligned";
const WRITABLE: &str = "read-only virtio-fs share holds writable state";
const WINDOW: &str = "DAX window differs from its session";

/// Every metadata check holds before anything exists: slots, tags,
/// features, activation, the share's session against the device (an
/// inactive device with a FUSE session, a DAX size, read-only state), the
/// DAX layout against RAM, devices, architectural windows and each other,
/// and the memslot capacity; rings are checked against RAM only, so a ring
/// in a DAX window is refused.
#[test]
fn snapshot_fs_vmm_metadata_is_validated_before_anything_exists() {
    let dir = TempDir::new();
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"file").unwrap();
    let side = Side::source(&src, Some(DAX));
    let mut guest = Fuse::new();
    guest.activate(&side);
    let mem = side.mem.clone();
    guest.init(&mem, &side);
    let f = guest.lookup(&mem, &side, fuse::ROOT_ID, b"f");
    guest.open(&mem, &side, f.nodeid, libc::O_RDWR);
    let cuts = freeze(side.shares()).unwrap();
    let (meta, _) = capture(side.shares(), &cuts).unwrap().unwrap();
    let json = serde_json::to_string(&meta).unwrap();
    let copy = || -> FsMeta { serde_json::from_str(&json).unwrap() };
    let lengths = validate_metadata(&copy(), &regions(), &[0xd000_9000], 32).unwrap();
    assert_eq!(lengths.files, 4);

    let mut m = copy();
    m.devices[0].mmio_addr += MMIO_LEN;
    rejected(&m, "another slot", SLOT);
    let mut m = copy();
    m.devices[0].irq = 8;
    rejected(&m, "another GSI", SLOT);
    let mut m = copy();
    m.devices[0].tag = "t".repeat(37);
    rejected(&m, "a 37-byte tag", TAG);
    let mut m = copy();
    m.devices[0].tag = "a\0b".into();
    rejected(&m, "a NUL in the tag", TAG);
    let mut m = copy();
    m.devices[0].device.avail_features |= 1 << 2;
    rejected(&m, "a foreign feature", "offers other features");
    let mut m = copy();
    m.devices[0].transport.device_status = 0b1011;
    rejected(&m, "activation without DRIVER_OK", "activation disagrees");
    let mut m = copy();
    m.devices[0].device.activated = false;
    m.devices[0].transport.device_status = 0b1011;
    for queue in &mut m.devices[0].device.queues {
        queue.event_idx_enabled = false;
    }
    rejected(
        &m,
        "an inactive device with a FUSE session",
        "carries a FUSE session",
    );
    let mut m = copy();
    m.devices[0].dax = Some(DaxRange {
        len: 2 * PAGE,
        ..DAX
    });
    rejected(
        &m,
        "a DAX window of another size than the session's",
        WINDOW,
    );
    let mut m = copy();
    m.devices[0].dax = None;
    rejected(&m, "a session window without a device window", WINDOW);
    let mut m = copy();
    m.devices[0].read_only = true;
    rejected(&m, "a read-only share with a writable handle", WRITABLE);
    let mut m = copy();
    m.devices.push(copy().devices.remove(0));
    rejected(
        &m,
        "more devices than archived shares",
        "archive shares differ",
    );
    for (gpa, case, reason) in [
        (0, "RAM", LAYOUT),
        (0xd000_9000 - PAGE, "another device's slot", LAYOUT),
        (FS_MMIO_BASE - 2 * PAGE, "the share's own slot", LAYOUT),
        (0xfee0_0000 - PAGE, "the local APIC", LAYOUT),
        (0xfec0_0000, "the IOAPIC", LAYOUT),
        (
            arch::x86_64::layout::KVM_TSS_ADDRESS - 2 * PAGE,
            "the identity map and TSS",
            LAYOUT,
        ),
        (0x1001, "an unaligned address", SHAPE),
        (u64::MAX - PAGE, "the end of the address space", SHAPE),
    ] {
        let mut m = copy();
        m.devices[0].dax = Some(DaxRange { gpa, len: DAX.len });
        rejected(&m, case, reason);
    }
    // Two shares whose windows overlap.
    let mut m = copy();
    let mut second = copy().devices.remove(0);
    second.mmio_addr += MMIO_LEN;
    second.irq += 1;
    second.tag = "second".into();
    second.dax = Some(DaxRange {
        gpa: DAX.gpa + PAGE,
        len: DAX.len,
    });
    m.devices.push(second);
    m.archive.shares.push(copy().archive.shares.remove(0));
    rejected(&m, "overlapping windows", LAYOUT);
    // Each window takes a memslot after the RAM regions.
    let full = validate_metadata(&copy(), &regions(), &[], 1);
    assert!(full.unwrap_err().to_string().contains("memslot capacity"));
    validate_metadata(&copy(), &regions(), &[], 2).unwrap();

    // A ring in the DAX window is no guest RAM.
    let mut m = copy();
    m.devices[0].device.queues[REQUEST].desc_table = DAX.gpa;
    validate_metadata(&m, &regions(), &[], 32).unwrap();
    assert!(validate_rings(&m, &side.mem).is_err());
    validate_rings(&copy(), &side.mem).unwrap();
}

/// A read-only share refuses writable state in its session: a writable
/// handle or file mapping, or the writeback cache.
#[test]
fn snapshot_fs_vmm_read_only_shares_hold_no_writable_state() {
    let dir = TempDir::new();
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), vec![1; PAGE as usize]).unwrap();
    let side = Side::source(&src, Some(DAX));
    let mut guest = Fuse::new();
    guest.activate(&side);
    let mem = side.mem.clone();
    guest.init(&mem, &side);
    let f = guest.lookup(&mem, &side, fuse::ROOT_ID, b"f");
    let ro = guest.open(&mem, &side, f.nodeid, libc::O_RDONLY);
    let mapping = Fuse::mapping_body(ro, 0, PAGE, 0, false);
    guest.ok(&mem, &side, Opcode::SetupMapping, f.nodeid, &mapping);
    let cuts = freeze(side.shares()).unwrap();
    let (meta, _) = capture(side.shares(), &cuts).unwrap().unwrap();
    let json = serde_json::to_string(&meta).unwrap();
    let read_only = || -> FsMeta {
        let mut m: FsMeta = serde_json::from_str(&json).unwrap();
        m.devices[0].read_only = true;
        m
    };
    validate_metadata(&read_only(), &regions(), &[], 32).unwrap();
    let mut m = read_only();
    m.archive.shares[0].session.state.handles[0].flags = libc::O_RDWR;
    rejected(&m, "a writable handle", WRITABLE);
    let mut m = read_only();
    let dax = m.archive.shares[0].session.state.dax.as_mut().unwrap();
    for mapping in &mut dax.mappings {
        if let DaxMappingKind::File { writable, .. } = &mut mapping.kind {
            *writable = true;
        }
    }
    rejected(&m, "a writable file mapping", WRITABLE);
}

/// Tags, sources, window shapes, memslots and guest ranges are checked
/// before an attach has any effect, whichever device came first; an
/// import's share directory must be absolute.
#[test]
fn snapshot_fs_vmm_layout_tags_sources_and_slots_are_checked() {
    check_tag("a", ["b", "c"].into_iter()).unwrap();
    check_tag(&"t".repeat(36), std::iter::empty()).unwrap();
    assert!(check_tag("", std::iter::empty()).is_err());
    assert!(check_tag(&"t".repeat(37), std::iter::empty()).is_err());
    assert!(check_tag("a\0", std::iter::empty()).is_err());
    assert!(check_tag("b", ["a", "b"].into_iter()).is_err());

    let dir = TempDir::new();
    let file = dir.path("file");
    fs::write(&file, b"").unwrap();
    let link = dir.path("link");
    std::os::unix::fs::symlink(&dir.0, &link).unwrap();
    let odd = dir.path("odd").join(OsStr::from_bytes(b"\xff"));
    fs::create_dir_all(&odd).unwrap();
    check_source(&dir.0).unwrap();
    check_source(&odd).unwrap();
    for bad in [
        PathBuf::from("relative"),
        file,
        link,
        dir.path("missing"),
        PathBuf::from(OsStr::from_bytes(b"/tmp/a\0b")),
    ] {
        assert!(check_source(&bad).is_err(), "{bad:?}");
    }

    check_fs_dir(&dir.path("shares")).unwrap();
    assert!(check_fs_dir(Path::new("shares")).is_err());
    assert!(check_fs_dir(Path::new(OsStr::from_bytes(b"/tmp/a\0b"))).is_err());

    check_dax_shape(DAX).unwrap();
    for range in [
        DaxRange { gpa: 0, len: 0 },
        DaxRange {
            gpa: 0x800,
            len: PAGE,
        },
        DaxRange {
            gpa: 0,
            len: PAGE + 1,
        },
        DaxRange {
            gpa: u64::MAX - PAGE + 1,
            len: PAGE,
        },
    ] {
        assert!(check_dax_shape(range).is_err(), "{range:?}");
    }

    // RAM slots first, then one per window, all within the capacity.
    assert_eq!(next_slot(1, 0, 32).unwrap(), 1);
    assert_eq!(next_slot(2, 3, 32).unwrap(), 5);
    assert!(next_slot(31, 1, 32).is_err());
    assert!(next_slot(usize::MAX, 1, 32).is_err());

    let taken = [(0, 0x1000), (0x2000, 0x1000)];
    wiring::check_disjoint(0x1000, 0x1000, taken, "x").unwrap();
    assert!(wiring::check_disjoint(0xfff, 2, taken, "x").is_err());
    assert!(wiring::check_disjoint(0x2fff, 1, taken, "x").is_err());
    assert!(wiring::check_disjoint(0, u64::MAX, taken, "x").is_err());
    // A device slot checked after a window holds the window too.
    assert!(wiring::check_window(DAX.gpa + PAGE, [(DAX.gpa, DAX.len)]).is_err());
    wiring::check_window(DAX.gpa + DAX.len, [(DAX.gpa, DAX.len)]).unwrap();
}

/// Whether `[addr, addr + len)` is free: a fixed mapping that may not
/// replace anything lands there (and is removed again).
fn free(addr: u64, len: u64) -> bool {
    // SAFETY: MAP_FIXED_NOREPLACE never replaces an existing mapping.
    let probe = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if probe == libc::MAP_FAILED {
        return false;
    }
    // SAFETY: the probe is this function's own mapping.
    unsafe { libc::munmap(probe, len as usize) };
    probe as u64 == addr
}

/// A window's backing unmaps only what it still owns: a range a failed
/// `MAP_FIXED` may have handed to other memory stays mapped.
#[test]
fn snapshot_fs_vmm_dax_backing_never_unmaps_ranges_it_may_not_own() {
    assert_eq!(owned_ranges(10, &[]), [(0, 10)]);
    assert_eq!(owned_ranges(10, &[(2, 3), (4, 2)]), [(0, 2), (6, 4)]);
    assert_eq!(owned_ranges(10, &[(0, 10)]), []);
    assert_eq!(owned_ranges(10, &[(8, 5), (0, 1)]), [(1, 7)]);

    let mut backing = DaxBacking::new(4 * PAGE).unwrap();
    let host = backing.host;
    backing.keep(&[(PAGE, PAGE)]);
    drop(backing);
    assert!(free(host, PAGE));
    assert!(!free(host + PAGE, PAGE), "an unowned range was unmapped");
    assert!(free(host + 2 * PAGE, 2 * PAGE));
    // The test owns what the backing left mapped.
    // SAFETY: the range is the dropped backing's kept page.
    unsafe { libc::munmap((host + PAGE) as *mut libc::c_void, PAGE as usize) };
}

/// A share remaps its live window only through the owner's execution
/// barrier: once it retired (the owner stopping its threads), a
/// FUSE_SETUPMAPPING runs no `MAP_FIXED` and leaves the window as it was,
/// and the share gives the window up but names no range it may not own, so
/// the owner's teardown steps release the whole window.
#[test]
fn snapshot_fs_vmm_live_remapping_needs_the_execution_barrier() {
    let dir = TempDir::new();
    let src = dir.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), vec![0x33; PAGE as usize]).unwrap();
    let mut side = Side::source(&src, Some(DAX));
    let exit = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
    let barrier = ExecutionBarrier::new(exit, |_| {});
    side.share
        .device
        .lock()
        .unwrap()
        .set_dax_control(barrier.clone());
    let mut guest = Fuse::new();
    guest.activate(&side);
    let mem = side.mem.clone();
    guest.init(&mem, &side);
    let f = guest.lookup(&mem, &side, fuse::ROOT_ID, b"f");
    let fh = guest.open(&mem, &side, f.nodeid, libc::O_RDWR);
    let mapping = Fuse::mapping_body(fh, 0, PAGE, PAGE, true);
    guest.ok(&mem, &side, Opcode::SetupMapping, f.nodeid, &mapping);
    assert_eq!(side.window(PAGE, 1), [0x33]);
    side.write_window(0, b"anon");

    barrier.retire();
    let mapping = Fuse::mapping_body(fh, 0, PAGE, 0, true);
    let (header, _) = guest.call(&mem, &side, Opcode::SetupMapping, f.nodeid, &mapping);
    assert_eq!(header.error, -libc::EIO);
    assert_eq!(side.window(0, 4), b"anon", "remapped past the barrier");

    // As `teardown` does for the share and its backing.
    let mut backing = side.backing.take().unwrap();
    let host = backing.host;
    {
        let mut device = side.share.device.lock().unwrap();
        device.retire();
        backing.keep(device.dax_unowned());
    }
    drop(backing);
    assert!(free(host, 4 * PAGE), "a skipped remapping leaked its range");
}

/// Exports need the caller's declaration only with shares.
#[test]
fn snapshot_fs_vmm_exports_need_declared_host_writers() {
    require_declared(0, false).unwrap();
    require_declared(1, true).unwrap();
    assert!(require_declared(1, false).is_err());
}
