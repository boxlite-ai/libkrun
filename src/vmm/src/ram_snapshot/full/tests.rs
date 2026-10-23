// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ram_snapshot::RestoreResources;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krun-full-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("checkpoint")
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// An owner with the guest fixture and IVT loaded, vCPUs not started.
fn loaded() -> RamSnapshotVm {
    let owner = crate::builder::build_ram_snapshot_vm(
        2,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    owner
        .memory
        .write_slice(include_bytes!("guest.bin"), GuestAddress(0x1000))
        .unwrap();
    owner
        .memory
        .write_slice(&[0x00, 0x16, 0, 0], GuestAddress(0x20 * 4))
        .unwrap();
    owner
        .memory
        .write_slice(&[0x80, 0x16, 0, 0], GuestAddress(0x30 * 4))
        .unwrap();
    owner
}

fn source(count: u8, entry: u16) -> RamSnapshotVm {
    let mut owner = loaded();
    owner.start_vcpus(count, entry).unwrap();
    owner
}

fn read(owner: &RamSnapshotVm, address: u64) -> u16 {
    owner.memory.read_obj::<u16>(GuestAddress(address)).unwrap()
}

fn wait_changed(owner: &RamSnapshotVm, address: u64, previous: u16) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let current = read(owner, address);
        if current != previous {
            return current;
        }
        assert!(
            Instant::now() < deadline,
            "guest counter at {address:#x} did not advance"
        );
        std::thread::yield_now();
    }
}

#[test]
fn destroyed_source_multi_cpu_continues_register_stack_and_simd_without_reboot() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.save_full(&dir.path()).unwrap();
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(owner);
    let mut restored =
        RamSnapshotVm::restore_full(&dir.path(), RestoreResources::default()).unwrap();
    let counters: Vec<_> = (0..2).map(|id| read(&restored, 0x8000 + id * 64)).collect();
    std::thread::sleep(Duration::from_millis(30));
    for id in 0..2 {
        assert_eq!(read(&restored, 0x8000 + id * 64), counters[id as usize]);
        assert_eq!(read(&restored, 0x8004 + id * 64), 1);
    }
    assert!(restored.save(&dir.0.join("ram-while-paused")).is_err());
    restored.resume().unwrap();
    for id in 0..2 {
        wait_changed(&restored, 0x8000 + id * 64, counters[id as usize]);
        assert_eq!(
            read(&restored, 0x8002 + id * 64),
            0,
            "register/stack/SIMD corruption"
        );
        assert_eq!(
            read(&restored, 0x8004 + id * 64),
            1,
            "cold initialization reran"
        );
    }
    restored.save_full(&dir.0.join("second")).unwrap();
    assert!(restored
        .handles
        .iter()
        .all(|h| h.response_receiver().is_empty()));
}

#[test]
fn halted_pit_lapic_and_deadline_continue_after_long_offline_pause() {
    for entry in [0x1200, 0x1300, 0x1400] {
        let dir = TempDir::new();
        let mut owner = source(1, entry);
        wait_changed(&owner, 0x9000, 0);
        // Keep CPU stopped while hardware may mature a pending interrupt; the
        // subsequent full save uses the same idempotent Pause handshake.
        Control::transition(&owner.handles, true, CONTROL_TIMEOUT).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        if entry == 0x1200 {
            owner.vm.fd().set_irq_line(0, false).unwrap();
            owner.vm.fd().set_irq_line(0, true).unwrap();
        }
        owner.save_full(&dir.path()).unwrap();
        let saved =
            read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
        if entry == 0x1200 {
            assert!(
                saved.vm.test_pic_pending(),
                "PIC pending IRQ0 was not captured"
            );
        }
        drop(owner);
        std::thread::sleep(Duration::from_millis(250));
        let restore_started = Instant::now();
        let mut restored =
            RamSnapshotVm::restore_full(&dir.path(), RestoreResources::default()).unwrap();
        let before = read(&restored, 0x9000);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            read(&restored, 0x9000),
            before,
            "restored guest entered before Resume"
        );
        let state = snapshot::request(&restored.handles[0], |reply| Request::Save {
            size: saved.compatibility.xsave_size,
            reply,
        })
        .unwrap();
        let (saved_tsc, khz) = saved.cpus[0].test_tsc();
        let (current_tsc, _) = state.test_tsc();
        let allowed_ns = restore_started.elapsed().as_nanos() + 50_000_000;
        assert!(current_tsc >= saved_tsc, "guest TSC moved backwards");
        assert!(
            u128::from(current_tsc - saved_tsc) * 1_000_000 / u128::from(khz) <= allowed_ns,
            "snapshot storage wall time was added to guest TSC"
        );
        let clock = restored.vm.fd().get_clock().unwrap().clock;
        assert!(
            clock >= saved.vm.test_clock(),
            "guest clock moved backwards"
        );
        assert!(
            u128::from(clock - saved.vm.test_clock()) <= allowed_ns,
            "snapshot storage wall time was added to VM clock"
        );
        restored.resume().unwrap();
        wait_changed(&restored, 0x9000, before);
        // Repeated timer/save scheduling must not leave duplicate control replies.
        restored.save_full(&dir.0.join("second")).unwrap();
        assert!(restored.handles[0].response_receiver().is_empty());
    }
}

#[test]
fn halted_mp_state_round_trips_without_guest_entry() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1780);
    wait_changed(&owner, 0x9004, 0);
    let kvm = KvmContext::new().unwrap();
    let size = Compatibility::capture(kvm.fd()).unwrap().xsave_size;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        Control::transition(&owner.handles, true, CONTROL_TIMEOUT).unwrap();
        let state =
            snapshot::request(&owner.handles[0], |reply| Request::Save { size, reply }).unwrap();
        if state.test_halted() {
            break;
        }
        Control::transition(&owner.handles, false, CONTROL_TIMEOUT).unwrap();
        assert!(
            Instant::now() < deadline,
            "guest did not enter KVM halted MP state"
        );
        std::thread::yield_now();
    }
    owner.save_full(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
    assert!(saved.cpus[0].test_halted());
    drop(owner);
    let restored = RamSnapshotVm::restore_full(&dir.path(), RestoreResources::default()).unwrap();
    let state = snapshot::request(&restored.handles[0], |reply| Request::Save {
        size: saved.compatibility.xsave_size,
        reply,
    })
    .unwrap();
    assert!(state.test_halted());
    assert!(restored.paused);
}

fn fake_cpu(
    mut respond: impl FnMut(VcpuEvent, &crossbeam_channel::Sender<VcpuResponse>) + Send + 'static,
) -> VcpuHandle {
    Vcpu::register_kick_signal_handler();
    let (sender, commands) = crossbeam_channel::unbounded();
    let (responses, receiver) = crossbeam_channel::unbounded();
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

#[test]
fn full_pause_timeout_and_resume_failure_attempt_all_cpus_without_valid_marker() {
    use std::sync::Arc;
    for resume_failure in [false, true] {
        let dir = TempDir::new();
        let mut owner = source(2, 0x1000);
        for id in 0..2 {
            wait_changed(&owner, 0x8000 + id * 64, 0);
        }
        owner.save_full(&dir.path()).unwrap();
        let saved =
            read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
        for handle in &mut owner.handles {
            handle.finish();
        }
        owner.handles.clear();
        let resumed = Arc::new(AtomicUsize::new(0));
        // Fake only communication failures. State replies contain actual
        // production-captured KVM state, and the real full save transaction
        // controls file publication and recovery.
        for (id, state) in saved.cpus.into_iter().enumerate() {
            let state = serde_json::to_vec(&state).unwrap();
            let resumed = resumed.clone();
            owner
                .handles
                .push(fake_cpu(move |event, responses| match event {
                    VcpuEvent::Pause if !resume_failure && id == 0 => (),
                    VcpuEvent::Pause => {
                        responses.send(VcpuResponse::Paused).unwrap();
                    }
                    VcpuEvent::Resume => {
                        resumed.fetch_add(1, Ordering::Relaxed);
                        if !resume_failure && id == 0 {
                            responses.send(VcpuResponse::Paused).unwrap();
                        }
                        responses
                            .send(if resume_failure && id == 1 {
                                VcpuResponse::Exited(1)
                            } else {
                                VcpuResponse::Resumed
                            })
                            .unwrap();
                    }
                    VcpuEvent::Snapshot(Request::Save { reply, .. }) => {
                        let _ = reply.try_send(Ok(serde_json::from_slice(&state).unwrap()));
                    }
                    _ => panic!("unexpected snapshot communication event"),
                }));
        }
        let failed = dir.0.join("failed");
        assert!(owner.save_full(&failed).is_err());
        assert_eq!(resumed.load(Ordering::Relaxed), 2);
        assert!(owner.control.unusable);
        assert!(!failed.exists());
    }
}

#[test]
fn full_save_rejects_an_actual_external_ram_alias() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1000);
    wait_changed(&owner, 0x8000, 0);
    let alias = owner.memory.clone();
    let error = owner.save_full(&dir.path()).unwrap_err();
    assert!(error.to_string().contains("external aliases"));
    assert!(!dir.path().exists());
    drop(alias);
    owner.save_full(&dir.path()).unwrap();
}

#[test]
fn malformed_full_headers_are_rejected_before_ram_allocation() {
    let dir = TempDir::new();
    for (magic, version, length) in [
        (*FULL_MAGIC, 99, 1),
        ([0; 8], FULL_VERSION, 1),
        (*FULL_MAGIC, FULL_VERSION, MAX_METADATA as u32 + 1),
        (*FULL_MAGIC, FULL_VERSION, 0),
        (*FULL_MAGIC, FULL_VERSION, 20),
    ] {
        let mut file = File::create(dir.path()).unwrap();
        file.write_all(&magic).unwrap();
        file.write_all(&version.to_le_bytes()).unwrap();
        file.write_all(&length.to_le_bytes()).unwrap();
        drop(file);
        assert!(read_metadata(&mut File::open(dir.path()).unwrap(), 32, 32).is_err());
    }
}

#[test]
fn one_shot_lapic_and_deadline_complete_once_after_source_destruction() {
    for entry in [0x1500, 0x1580] {
        let dir = TempDir::new();
        let mut owner = source(1, entry);
        wait_changed(&owner, 0x9004, 0);
        owner.save_full(&dir.path()).unwrap();
        drop(owner);
        std::thread::sleep(Duration::from_millis(250));
        let mut restored =
            RamSnapshotVm::restore_full(&dir.path(), RestoreResources::default()).unwrap();
        assert_eq!(
            read(&restored, 0x9000),
            0,
            "one-shot expired before snapshot capture"
        );
        restored.resume().unwrap();
        wait_changed(&restored, 0x9000, 0);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(read(&restored, 0x9000), 1, "duplicate one-shot completion");
    }
}

#[test]
fn full_files_reject_wrong_capabilities_trailing_bytes_and_incomplete_marker() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1000);
    wait_changed(&owner, 0x8000, 0);
    owner.save_full(&dir.path()).unwrap();
    let original = fs::read(dir.path()).unwrap();
    let len = u32::from_le_bytes(original[12..16].try_into().unwrap()) as usize;
    let mut metadata: Metadata = serde_json::from_slice(&original[16..16 + len]).unwrap();
    metadata.compatibility.xsave_size += 4;
    let encoded = serde_json::to_vec(&metadata).unwrap();
    let mut malformed = original[..12].to_vec();
    malformed.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    malformed.extend_from_slice(&encoded);
    malformed.extend_from_slice(&original[16 + len..]);
    fs::write(dir.0.join("mismatch"), &malformed).unwrap();
    assert!(
        RamSnapshotVm::restore_full(&dir.0.join("mismatch"), RestoreResources::default()).is_err()
    );
    let mut trailing = original.clone();
    trailing.push(0);
    fs::write(dir.0.join("trailing"), &trailing).unwrap();
    assert!(read_metadata(&mut File::open(dir.0.join("trailing")).unwrap(), 32, 32).is_err());
    let mut incomplete = original;
    incomplete[..8].fill(0);
    fs::write(dir.0.join("incomplete"), &incomplete).unwrap();
    assert!(read_metadata(&mut File::open(dir.0.join("incomplete")).unwrap(), 32, 32).is_err());
}

#[test]
fn full_save_error_resumes_all_cpus_and_never_overwrites_existing_file() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    fs::write(dir.path(), b"keep existing file").unwrap();
    assert!(owner.save_full(&dir.path()).is_err());
    assert_eq!(fs::read(dir.path()).unwrap(), b"keep existing file");
    for id in 0..2 {
        let before = read(&owner, 0x8000 + id * 64);
        wait_changed(&owner, 0x8000 + id * 64, before);
    }
    owner.save_full(&dir.0.join("next")).unwrap();
    let failed_path = dir.0.join("mid-copy");
    let result =
        super::super::tests::with_failed_payload_write(17, || owner.save_full(&failed_path));
    assert!(result.is_err());
    assert!(!failed_path.exists());
    for id in 0..2 {
        let before = read(&owner, 0x8000 + id * 64);
        wait_changed(&owner, 0x8000 + id * 64, before);
    }
    owner.save_full(&dir.0.join("after-write-failure")).unwrap();
}

#[test]
fn partial_import_kvm_failure_joins_threads_and_closes_fds() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.save_full(&dir.path()).unwrap();
    drop(owner);
    let original = fs::read(dir.path()).unwrap();
    let length = u32::from_le_bytes(original[12..16].try_into().unwrap()) as usize;
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&original[16..16 + length]).unwrap();
    // Keep the exact serialized record size but set reserved high CR0 bits.
    // Metadata validation passes; vCPU 1's real KVM_SET_SREGS must fail after
    // both paused threads were created and vCPU 0 was restored.
    let offset = std::mem::offset_of!(kvm_bindings::kvm_sregs, cr0);
    for byte in &mut metadata["cpus"][1]["sregs"].as_array_mut().unwrap()[offset..offset + 8] {
        *byte = serde_json::json!(255);
    }
    let encoded = serde_json::to_vec(&metadata).unwrap();
    let mut malformed = original[..12].to_vec();
    malformed.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    malformed.extend_from_slice(&encoded);
    malformed.extend_from_slice(&original[16 + length..]);
    fs::write(dir.0.join("partial-import"), malformed).unwrap();
    let count = |path| fs::read_dir(path).unwrap().count();
    let threads = count("/proc/self/task");
    let fds = count("/proc/self/fd");
    let error = match RamSnapshotVm::restore_full(
        &dir.0.join("partial-import"),
        RestoreResources::default(),
    ) {
        Ok(_) => panic!("invalid CR0 restored"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("vCPU 1 state restore"),
        "{error}"
    );
    assert_eq!(
        count("/proc/self/task"),
        threads,
        "partial-import threads not joined"
    );
    assert_eq!(
        count("/proc/self/fd"),
        fds,
        "partial-import KVM/RAM FDs retained"
    );
}

/// Write a header-plus-JSON image of `version` without RAM or segments.
fn write_header_only(path: &Path, version: u32, json: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(FULL_MAGIC).unwrap();
    file.write_all(&version.to_le_bytes()).unwrap();
    file.write_all(&(json.len() as u32).to_le_bytes()).unwrap();
    file.write_all(json).unwrap();
}

fn rejection(result: Result<impl Sized>) -> String {
    match result {
        Err(error) => error.to_string(),
        Ok(_) => panic!("image was accepted"),
    }
}

/// Versions 1–3 are rejected by version before their JSON is parsed.
#[test]
fn snapshot_full_rejects_pre_unified_versions() {
    let dir = TempDir::new();
    let path = dir.path();
    for old in 1..=3 {
        write_header_only(&path, old, b"{}");
        let error = rejection(read_metadata(&mut File::open(&path).unwrap(), 32, 32));
        assert!(
            error.contains(&format!("version {old} predates")),
            "{error}"
        );
    }
}

/// Each target resource is required exactly when its device is present.
#[test]
fn snapshot_full_restore_resources_must_match_devices() {
    let none = Requirements {
        disks: false,
        nic: false,
        legacy: false,
    };
    none.check(&RestoreResources::default()).unwrap();
    let with_disks = Requirements {
        disks: true,
        ..none
    };
    let dir = RestoreResources {
        disk_dir: Some(PathBuf::from("/nonexistent")),
        ..Default::default()
    };
    with_disks.check(&dir).unwrap();
    assert!(with_disks.check(&RestoreResources::default()).is_err());
    assert!(none.check(&dir).is_err());
    let with_nic = Requirements { nic: true, ..none };
    assert!(with_nic.check(&RestoreResources::default()).is_err());
    let socket = RestoreResources {
        nic_socket: Some(PathBuf::from("/nonexistent.sock")),
        ..Default::default()
    };
    assert!(none.check(&socket).is_err());
    let serial = RestoreResources {
        serial: Some([None, None, None, None]),
        ..Default::default()
    };
    assert!(none.check(&serial).is_err());
}

/// A nonblocking owner end and a blocking-with-timeout test end.
fn serial_pair() -> (
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
) {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    ours.set_nonblocking(true).unwrap();
    theirs
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    (ours, theirs)
}

/// The legacy fixture writes COM1 output and scratch, then counts. Its
/// UART/CMOS/i8042 state survives a destroyed source; the target endpoint
/// gets no replayed output, and the restored guest continues until its
/// i8042 reset latches the exit and stops the vCPU, after which no save or
/// resume is accepted.
#[test]
fn snapshot_legacy_restored_vm_continues_then_reset_stops_it() {
    let dir = TempDir::new();
    let mut owner = loaded();
    let (ours, mut theirs) = serial_pair();
    owner.attach_legacy([Some(ours), None, None, None]).unwrap();
    owner.start_vcpus(1, 0x1800).unwrap();
    wait_changed(&owner, 0x9000, 0);
    let mut output = [0u8];
    theirs.read_exact(&mut output).unwrap();
    assert_eq!(&output, b"K");
    owner.save_full(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
    let saved_legacy =
        serde_json::to_value(saved.legacy.as_ref().expect("legacy section")).unwrap();
    drop(owner);

    let (ours, mut theirs) = serial_pair();
    let resources = RestoreResources {
        serial: Some([Some(ours), None, None, None]),
        ..Default::default()
    };
    let mut restored = RamSnapshotVm::restore_full(&dir.path(), resources).unwrap();
    let restored_legacy = legacy::capture(&restored, &saved.regions).unwrap();
    assert_eq!(serde_json::to_value(restored_legacy).unwrap(), saved_legacy);
    assert_eq!(restored.serial_dropped_output_bytes(), Some([0; 4]));
    let before = read(&restored, 0x9000);
    restored.resume().unwrap();
    wait_changed(&restored, 0x9000, before);
    theirs.set_nonblocking(true).unwrap();
    assert_eq!(
        theirs.read(&mut output).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "source output replayed to the target endpoint"
    );

    restored
        .memory
        .write_obj(1u16, GuestAddress(0x9006))
        .unwrap();
    // The guest keeps counting after its reset; only the event thread's
    // stop ends the vCPU thread.
    let deadline = Instant::now() + Duration::from_secs(3);
    while !restored.handles.iter().all(VcpuHandle::is_finished) {
        assert!(
            Instant::now() < deadline,
            "i8042 reset did not stop the vCPU"
        );
        std::thread::yield_now();
    }
    assert!(restored.exit.requested());
    let stopped = read(&restored, 0x9000);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(read(&restored, 0x9000), stopped, "vCPU ran after reset");
    let error = restored.save_full(&dir.0.join("after-reset")).unwrap_err();
    assert!(error.to_string().contains("requested exit"), "{error}");
    assert!(!dir.0.join("after-reset").exists());
    assert!(restored.resume().is_err());
}
