// SPDX-License-Identifier: Apache-2.0

use super::*;
use crossbeam_channel::{unbounded, Sender};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vm_memory::{GuestRegionMmap, MmapRegion};

thread_local! {
    static COPY_WRITE_LIMIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static COPY_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn with_failed_payload_write<T>(bytes: usize, operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COPY_WRITE_LIMIT.with(|limit| limit.set(None));
        }
    }
    COPY_WRITE_LIMIT.with(|limit| limit.set(Some(bytes)));
    let _reset = Reset;
    operation()
}

// Per-test-thread fault injection at the real payload File write, without
// changing process resource limits or substituting the RAM copy implementation.
pub(super) fn write_payload(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    COPY_WRITE_LIMIT.with(|limit| {
        if let Some(remaining) = limit.get() {
            let len = remaining.min(bytes.len());
            file.write_all(&bytes[..len])?;
            limit.set(Some(remaining - len));
            COPY_BYTES.with(|written| written.set(written.get() + len));
            if len < bytes.len() {
                return Err(io::Error::other("injected mid-copy write failure"));
            }
            Ok(())
        } else {
            file.write_all(bytes)
        }
    })
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krun-ram-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("ram")
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn memory() -> GuestMemoryMmap {
    let memory =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(0x4000), 8192)])
            .unwrap();
    for (index, region) in memory.iter().enumerate() {
        memory
            .write_slice(
                &vec![0x31 + index as u8; region.len() as usize],
                region.start_addr(),
            )
            .unwrap();
    }
    memory
}

fn image(path: &Path, memory: &GuestMemoryMmap) {
    write_ram_image(path, memory, &Topology::default(), 32).unwrap();
}

#[test]
fn round_trip_preserves_regions_and_holes() {
    let dir = TempDir::new();
    let original = memory();
    image(&dir.path(), &original);
    let restored = restore_memory(&mut File::open(dir.path()).unwrap(), 32).unwrap();
    assert_eq!(restored.num_regions(), 2);
    assert!(restored.find_region(GuestAddress(4096)).is_none());
    for (before, after) in original.iter().zip(restored.iter()) {
        assert_eq!(
            (before.start_addr(), before.len()),
            (after.start_addr(), after.len())
        );
        assert!(after.owned());
        assert!(after.file_offset().is_none());
        let mut expected = vec![0; before.len() as usize];
        let mut actual = vec![0; after.len() as usize];
        original
            .read_slice(&mut expected, before.start_addr())
            .unwrap();
        restored
            .read_slice(&mut actual, after.start_addr())
            .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn malformed_images_are_rejected_before_ram_allocation() {
    let dir = TempDir::new();
    image(&dir.path(), &memory());
    let valid = fs::read(dir.path()).unwrap();
    let reject = |bytes: &[u8], max_slots| {
        fs::write(dir.path(), bytes).unwrap();
        assert!(restore_memory(&mut File::open(dir.path()).unwrap(), max_slots).is_err());
    };
    for end in [0, 7, 15, 16, 39, 63, valid.len() - 1] {
        reject(&valid[..end], 32);
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    reject(&trailing, 32);
    for (offset, bytes) in [
        (0, b"INVALID!".to_vec()),
        (8, 2u32.to_le_bytes().to_vec()),
        (12, 0u32.to_le_bytes().to_vec()),
        (12, u32::MAX.to_le_bytes().to_vec()),
        (16, 1u64.to_le_bytes().to_vec()), // unaligned GPA
        (24, 0u64.to_le_bytes().to_vec()),
        (24, 4095u64.to_le_bytes().to_vec()),
        (24, 8192u64.to_le_bytes().to_vec()), // declared/file length mismatch
        (32, 1u64.to_le_bytes().to_vec()),    // unknown attributes
        (40, 0u64.to_le_bytes().to_vec()),    // overlap
        (40, (u64::MAX - 4095).to_le_bytes().to_vec()), // address overflow
        (48, (1u64 << 63).to_le_bytes().to_vec()), // unsupported host mapping length
    ] {
        let mut malformed = valid.clone();
        malformed[offset..offset + bytes.len()].copy_from_slice(&bytes);
        reject(&malformed, 32);
    }
    reject(&valid, 1); // actual target slot capacity, not an arbitrary format cap
}

#[test]
fn shared_file_and_unknown_raw_mappings_are_rejected() {
    let dir = TempDir::new();
    let shared = MmapRegion::build(
        None,
        4096,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_ANONYMOUS,
    )
    .unwrap();
    let shared_memory =
        GuestMemoryMmap::from_regions(vec![GuestRegionMmap::new(shared, GuestAddress(0)).unwrap()])
            .unwrap();
    assert!(write_ram_image(&dir.path(), &shared_memory, &Topology::default(), 32).is_err());
    let backing = MmapRegion::<()>::new(4096).unwrap();
    // SAFETY: backing remains mapped until the raw guest view is dropped below.
    let raw = unsafe { MmapRegion::build_raw(backing.as_ptr(), 4096, 0, 0).unwrap() };
    let raw_memory =
        GuestMemoryMmap::from_regions(vec![GuestRegionMmap::new(raw, GuestAddress(0)).unwrap()])
            .unwrap();
    assert!(write_ram_image(&dir.path(), &raw_memory, &Topology::default(), 32).is_err());
    let mut topology = Topology {
        kernel: Some(KernelMapping {
            gpa: 0,
            len: 4096,
            host: backing.as_ptr() as usize + 4096,
        }),
        shared: Vec::new(),
    };
    assert!(topology.regions(&raw_memory).is_err()); // exact mapping identity required
    topology.kernel.as_mut().unwrap().host = backing.as_ptr() as usize;
    assert!(topology.regions(&raw_memory).is_ok());
    drop(raw_memory);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.0.join("backing"))
        .unwrap();
    file.set_len(4096).unwrap();
    let memory = GuestMemoryMmap::from_ranges_with_files(&[(
        GuestAddress(0),
        4096,
        Some(vm_memory::FileOffset::new(file, 0)),
    )])
    .unwrap();
    assert!(topology.regions(&memory).is_err());
    assert!(!dir.path().exists());
}

#[test]
fn dax_intent_is_rejected_even_when_mapping_is_anonymous() {
    let (info, _) = arch::arch_memory_regions(2 << 20, None, 0, 0, None);
    let mut shm = crate::device_manager::shm::ShmManager::new(&info);
    shm.create_fs_region(0, 4096).unwrap();
    let memory = GuestMemoryMmap::from_ranges(&shm.regions()).unwrap();
    let topology = Topology {
        kernel: None,
        shared: shm
            .regions()
            .into_iter()
            .map(|(guest_addr, size)| ShmRegion { guest_addr, size })
            .collect(),
    };
    assert!(topology.regions(&memory).is_err());
}

// These fakes exercise real VcpuHandle send/receive for the pause/resume
// transition. They model communication faults; separate KVM tests below
// exercise actual CPUs.
struct TestCpus {
    handles: Vec<VcpuHandle>,
}
impl Drop for TestCpus {
    fn drop(&mut self) {
        for h in &mut self.handles {
            h.finish();
        }
    }
}
fn cpu(mut respond: impl FnMut(VcpuEvent, &Sender<VcpuResponse>) + Send + 'static) -> VcpuHandle {
    Vcpu::register_kick_signal_handler();
    let (sender, commands) = unbounded();
    let (responses, receiver) = unbounded();
    let thread = std::thread::spawn(move || {
        while let Ok(event) = commands.recv() {
            if matches!(event, VcpuEvent::Finish) {
                break;
            }
            respond(event, &responses);
        }
    });
    VcpuHandle::new(sender, receiver, thread)
}
fn normal(event: VcpuEvent, responses: &Sender<VcpuResponse>) {
    responses
        .send(match event {
            VcpuEvent::Pause => VcpuResponse::Paused,
            VcpuEvent::Resume => VcpuResponse::Resumed,
            VcpuEvent::Finish | VcpuEvent::Snapshot(_) => unreachable!(),
        })
        .unwrap();
}

#[test]
fn pause_is_broadcast_before_waiting_for_individual_acknowledgments() {
    let (sent, received) = unbounded();
    let cpus = TestCpus {
        handles: vec![
            cpu(move |event, responses| {
                if matches!(event, VcpuEvent::Pause) {
                    received.recv_timeout(Duration::from_secs(1)).unwrap();
                }
                normal(event, responses);
            }),
            cpu(move |event, responses| {
                if matches!(event, VcpuEvent::Pause) {
                    sent.send(()).unwrap();
                }
                normal(event, responses);
            }),
        ],
    };
    Control::transition(&cpus.handles, true, CONTROL_TIMEOUT).unwrap();
}

#[test]
fn transition_timeout_and_exit_fail_and_a_late_pause_precedes_its_resume() {
    for exit in [false, true] {
        let resumes = Arc::new(AtomicUsize::new(0));
        let count = resumes.clone();
        let cpus = TestCpus {
            handles: vec![
                cpu(move |event, responses| {
                    match event {
                        VcpuEvent::Pause if exit => {
                            responses.send(VcpuResponse::Exited(1)).unwrap()
                        }
                        VcpuEvent::Pause => (), // acknowledgment arrives after timeout
                        VcpuEvent::Resume => {
                            if !exit {
                                responses.send(VcpuResponse::Paused).unwrap();
                            }
                            responses.send(VcpuResponse::Resumed).unwrap();
                        }
                        VcpuEvent::Finish | VcpuEvent::Snapshot(_) => unreachable!(),
                    }
                }),
                cpu(move |event, responses| {
                    if matches!(event, VcpuEvent::Resume) {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    normal(event, responses);
                }),
            ],
        };
        assert!(Control::transition(&cpus.handles, true, Duration::from_millis(20)).is_err());
        // The late Paused is consumed before the Resumed, not misread.
        Control::transition(&cpus.handles, false, Duration::from_millis(500)).unwrap();
        assert_eq!(resumes.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn disconnected_command_channel_still_attempts_every_cpu() {
    Vcpu::register_kick_signal_handler();
    let (sender, commands) = unbounded();
    drop(commands);
    let (responses, receiver) = unbounded();
    drop(responses);
    let (stop, wait) = unbounded::<()>();
    let thread = std::thread::spawn(move || {
        let _ = wait.recv();
    });
    let resumed = Arc::new(AtomicUsize::new(0));
    let count = resumed.clone();
    let cpus = TestCpus {
        handles: vec![
            VcpuHandle::new(sender, receiver, thread),
            cpu(move |event, responses| {
                if matches!(event, VcpuEvent::Resume) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                normal(event, responses);
            }),
        ],
    };
    let error = Control::transition(&cpus.handles, false, Duration::from_millis(20)).unwrap_err();
    assert!(
        matches!(&error, Error::Control(errors) if errors.len() == 2),
        "{error}"
    );
    assert_eq!(resumed.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap(); // allow the intentionally disconnected test handle to join
}

#[test]
fn mid_copy_file_write_failure_removes_the_unpublished_file() {
    COPY_BYTES.with(|written| written.set(0));
    let dir = TempDir::new();
    let error = with_failed_payload_write(17, || {
        write_ram_image(&dir.path(), &memory(), &Topology::default(), 32)
    })
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("injected mid-copy write failure"));
    assert_eq!(COPY_BYTES.with(|written| written.get()), 17);
    assert!(!dir.path().exists());
}

#[test]
fn failed_magic_write_removes_the_unpublished_file() {
    let dir = TempDir::new();
    let memory = memory();
    let mut pending = PendingSnapshot::write(
        &dir.path(),
        &memory,
        &Topology::default().regions(&memory).unwrap(),
    )
    .unwrap();
    // A read-only replacement FD fails at the actual final magic write.
    pending.file = File::open(dir.path()).unwrap();
    assert!(pending.finish(MAGIC).is_err());
    assert!(!dir.path().exists());
}

#[test]
fn unfinished_file_has_no_valid_magic() {
    let dir = TempDir::new();
    let memory = memory();
    let pending = PendingSnapshot::write(
        &dir.path(),
        &memory,
        &Topology::default().regions(&memory).unwrap(),
    )
    .unwrap();
    assert!(restore_memory(&mut File::open(dir.path()).unwrap(), 32).is_err());
    drop(pending);
    assert!(!dir.path().exists());
}

#[test]
fn loaded_kernel_and_gpa_holes_restore_after_source_destroyed_at_new_addresses() {
    use crate::builder::{create_guest_memory, Payload};
    use crate::resources::VmResources;
    use crate::vmm_config::kernel_bundle::KernelBundle;
    let dir = TempDir::new();
    let kernel = MmapRegion::<()>::new(4096).unwrap();
    // SAFETY: this owned mapping is writable and exclusively used by this test.
    unsafe {
        std::ptr::write_bytes(kernel.as_ptr(), 0x6b, 4096);
    }
    let mut resources = VmResources::default();
    resources.kernel_bundle = Some(KernelBundle {
        guest_addr: 0x10000,
        host_addr: kernel.as_ptr() as u64,
        entry_addr: 0x10000,
        size: 4096,
    });
    let (initial_memory, _, _, _) =
        create_guest_memory(2, &resources, &Payload::KernelMmap).unwrap();
    let memory = initial_memory
        .insert_region(Arc::new(
            GuestRegionMmap::from_range(GuestAddress(1 << 32), 4096, None).unwrap(),
        ))
        .unwrap();
    drop(initial_memory); // insert_region clones the existing region Arcs.
    memory
        .write_slice(b"after-hole", GuestAddress(1 << 32))
        .unwrap();
    let topology = Topology {
        kernel: Some(KernelMapping {
            gpa: 0x10000,
            len: 4096,
            host: kernel.as_ptr() as usize,
        }),
        shared: Vec::new(),
    };
    let mut source = RamSnapshotVm::from_memory(memory, topology).unwrap();
    let expected: Vec<_> = source
        .memory
        .iter()
        .map(|region| {
            let mut bytes = vec![0; region.len() as usize];
            source
                .memory
                .read_slice(&mut bytes, region.start_addr())
                .unwrap();
            (region.start_addr(), bytes, region.as_ptr() as usize)
        })
        .collect();
    source.save(&dir.path()).unwrap();
    drop(source);
    drop(kernel);
    // Reserve each freed source address. Restore must allocate DIFFERENT host
    // mappings; old pointers cannot accidentally make the test pass.
    struct Reservations(Vec<(*mut libc::c_void, usize)>);
    impl Drop for Reservations {
        fn drop(&mut self) {
            for (ptr, len) in &self.0 {
                // SAFETY: entries are exact successful mappings owned by this reservation.
                unsafe {
                    libc::munmap(*ptr, *len);
                }
            }
        }
    }
    let mut reservations = Reservations(Vec::new());
    for (_, bytes, host) in &expected {
        // SAFETY: MAP_FIXED_NOREPLACE never overwrites a live mapping.
        let ptr = unsafe {
            libc::mmap(
                *host as *mut _,
                bytes.len(),
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            // A concurrent allocator may already occupy the freed address.
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EEXIST)
            );
            continue;
        }
        assert_eq!(ptr as usize, *host);
        reservations.0.push((ptr, bytes.len()));
    }
    let restored = RamSnapshotVm::restore(&dir.path()).unwrap();
    assert_eq!(restored.memory.num_regions(), expected.len());
    assert!(restored.memory.find_region(GuestAddress(1 << 31)).is_none());
    for ((gpa, bytes, host), region) in expected.iter().zip(restored.memory.iter()) {
        assert_eq!(region.start_addr(), *gpa);
        assert_ne!(region.as_ptr() as usize, *host);
        assert!(region.owned());
        let mut actual = vec![0; bytes.len()];
        restored.memory.read_slice(&mut actual, *gpa).unwrap();
        assert_eq!(&actual, bytes);
    }
}

#[test]
fn new_kvm_vm_runs_against_restored_registered_mappings_and_repeated_pause() {
    let dir = TempDir::new();
    let memory = memory();
    // inc word [0x800]; jmp back. No device or host RAM writer is involved.
    memory
        .write_slice(&[0xff, 0x06, 0x00, 0x08, 0xeb, 0xfa], GuestAddress(0))
        .unwrap();
    image(&dir.path(), &memory);
    drop(memory);
    let mut restored = RamSnapshotVm::restore(&dir.path()).unwrap();
    restored.start_vcpus(2, 0).unwrap();
    restored.pause().unwrap();
    assert!(restored.pause().is_err(), "a second pause was accepted");
    let before = restored
        .memory
        .read_obj::<u16>(GuestAddress(0x800))
        .unwrap();
    restored.resume().unwrap();
    // Bounded polling checks guest writes crossing real KVM registered slots.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if restored
            .memory
            .read_obj::<u16>(GuestAddress(0x800))
            .unwrap()
            != before
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "restored vCPUs did not modify restored RAM"
        );
        std::thread::yield_now();
    }
    let running = dir.0.join("running");
    assert!(restored.save(&running).is_err(), "RAM save while running");
    assert!(!running.exists());
}

/// A RAM-only save needs a confirmed pause and never resumes: a failed
/// write leaves the owner paused and retryable, and only `resume` runs the
/// guest again.
#[test]
fn ram_save_requires_pause_and_never_resumes() {
    let dir = TempDir::new();
    let memory = memory();
    // inc word [0x800]; jmp back.
    memory
        .write_slice(&[0xff, 0x06, 0x00, 0x08, 0xeb, 0xfa], GuestAddress(0))
        .unwrap();
    let mut owner = RamSnapshotVm::from_memory(memory, Topology::default()).unwrap();
    owner.start_vcpus(1, 0).unwrap();
    let counter =
        |owner: &RamSnapshotVm| owner.memory.read_obj::<u16>(GuestAddress(0x800)).unwrap();
    owner.pause().unwrap();
    let paused_at = counter(&owner);
    let failed = with_failed_payload_write(17, || owner.save(&dir.path()));
    assert!(failed.is_err());
    assert!(!dir.path().exists());
    owner.save(&dir.path()).unwrap();
    owner.save(&dir.0.join("again")).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(counter(&owner), paused_at, "a RAM save resumed the guest");
    assert!(owner.is_paused());
    let saved = restore_memory(&mut File::open(dir.path()).unwrap(), 32).unwrap();
    assert_eq!(
        saved.read_obj::<u16>(GuestAddress(0x800)).unwrap(),
        paused_at
    );
    owner.resume().unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while counter(&owner) == paused_at {
        assert!(Instant::now() < deadline, "resume did not run the guest");
        std::thread::yield_now();
    }
}

#[test]
fn minimal_builder_has_a_reachable_no_device_save_path() {
    let dir = TempDir::new();
    let mut source = crate::builder::build_ram_snapshot_vm(
        2,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    source
        .memory
        .write_slice(&[0xeb, 0xfe], GuestAddress(0))
        .unwrap();
    source.start_vcpus(2, 0).unwrap();
    source.pause().unwrap();
    source.save(&dir.path()).unwrap();
    assert!(RamSnapshotVm::restore(&dir.path()).is_ok());
    source.resume().unwrap();
}

#[test]
fn partial_cpu_start_joins_created_threads_and_disables_snapshots() {
    let dir = TempDir::new();
    let mut owner = RamSnapshotVm::from_memory(memory(), Topology::default()).unwrap();
    owner.setup_irqchip().unwrap();
    // Occupy ID 1 so startup fails AFTER ID 0's real thread was created.
    let occupied = Vcpu::new_x86_64(
        1,
        owner.vm.fd(),
        owner.vm.supported_cpuid().clone(),
        owner.vm.supported_msrs().clone(),
        devices::Bus::new(),
        utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
    )
    .unwrap();
    assert!(owner.start_vcpus(2, 0).is_err());
    assert!(owner.handles.is_empty());
    assert!(owner.control.unusable);
    assert!(owner.save(&dir.path()).is_err());
    assert!(!dir.path().exists());
    drop(occupied);
}

#[test]
fn minimal_cpu_count_rejects_zero_and_cpuid_overflow_before_creating_threads() {
    let mut owner = RamSnapshotVm::from_memory(memory(), Topology::default()).unwrap();
    for count in [0, 129, 255] {
        assert!(owner.start_vcpus(count, 0).is_err());
        assert!(owner.handles.is_empty());
        assert!(!owner.control.unusable);
        assert!(!owner.irqchip_ready);
    }
}

#[test]
fn partial_registration_failure_does_not_return_an_owner_or_retain_mappings() {
    let kvm = KvmContext::new().unwrap();
    let first = Arc::new(GuestRegionMmap::from_range(GuestAddress(0), 4096, None).unwrap());
    let weak = Arc::downgrade(&first);
    // KVM rejects an out-of-range x86 GPA after the first memslot was installed.
    let second = Arc::new(GuestRegionMmap::from_range(GuestAddress(1 << 63), 4096, None).unwrap());
    let memory = GuestMemoryMmap::from_arc_regions(vec![first, second]).unwrap();
    let result = RamSnapshotVm::register(memory, Topology::default(), &kvm);
    assert!(matches!(
        result,
        Err(Error::State(crate::vstate::Error::SetUserMemoryRegion(_)))
    ));
    assert!(weak.upgrade().is_none());
}
