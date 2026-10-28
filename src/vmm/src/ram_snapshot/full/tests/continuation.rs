// SPDX-License-Identifier: Apache-2.0

//! CPU/KVM continuation assertions ported to the real v9 descriptor boundary.
use super::*;
use crate::ram_snapshot::test_fixture::DescriptorFixture;
use std::os::unix::fs::PermissionsExt;

/// How the fake vCPUs below fail one lifecycle step.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    PauseTimeout,
    ResumeExit,
    SaveTimeout,
    SaveRejected,
}

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
    let mut owner = crate::builder::build_ram_snapshot_vm(
        2,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    owner
        .memory
        .write_slice(include_bytes!("../guest.bin"), GuestAddress(0x1000))
        .unwrap();
    owner
        .memory
        .write_slice(&[0x00, 0x16, 0, 0], GuestAddress(0x20 * 4))
        .unwrap();
    owner
        .memory
        .write_slice(&[0x80, 0x16, 0, 0], GuestAddress(0x30 * 4))
        .unwrap();
    // Inactive blank disk: CPU fixtures never submit block requests. The
    // test helper below supplies a byte-equivalent standalone blank QCOW2.
    let disk = Fixture::new();
    drop(disk.qcow2("source.qcow2"));
    owner
        .attach_disk(&disk.path("source.qcow2"), ImageType::Qcow2, false, false)
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
fn snapshot_v9_destroyed_source_multi_cpu_continues_register_stack_and_simd_without_reboot() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.pause().unwrap();
    owner.export_test(&dir.path()).unwrap();
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(owner);
    let mut restored =
        RamSnapshotVm::import_test(&dir.path(), RestoreResources::default()).unwrap();
    let counters: Vec<_> = (0..2).map(|id| read(&restored, 0x8000 + id * 64)).collect();
    // A RAM-only save of the paused import neither fails nor resumes it.
    assert!(
        restored.save(&dir.0.join("ram-while-paused")).is_err(),
        "RAM-only API must refuse attached disks"
    );
    std::thread::sleep(Duration::from_millis(30));
    for id in 0..2 {
        assert_eq!(read(&restored, 0x8000 + id * 64), counters[id as usize]);
        assert_eq!(read(&restored, 0x8004 + id * 64), 1);
    }
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
    restored.pause().unwrap();
    restored.export_test(&dir.0.join("second")).unwrap();
    assert!(restored
        .handles
        .iter()
        .all(|h| h.response_receiver().is_empty()));
}

#[test]
fn snapshot_v9_halted_pit_lapic_and_deadline_continue_after_long_offline_pause() {
    for entry in [0x1200, 0x1300, 0x1400] {
        let dir = TempDir::new();
        let mut owner = source(1, entry);
        wait_changed(&owner, 0x9000, 0);
        // Keep the CPU paused while hardware may mature a pending
        // interrupt; the export captures that same pause.
        owner.pause().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        if entry == 0x1200 {
            owner.vm.fd().set_irq_line(0, false).unwrap();
            owner.vm.fd().set_irq_line(0, true).unwrap();
        }
        owner.export_test(&dir.path()).unwrap();
        let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32)
            .unwrap()
            .0;
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
            RamSnapshotVm::import_test(&dir.path(), RestoreResources::default()).unwrap();
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
        restored.pause().unwrap();
        restored.export_test(&dir.0.join("second")).unwrap();
        assert!(restored.handles[0].response_receiver().is_empty());
    }
}

#[test]
fn snapshot_v9_halted_mp_state_round_trips_without_guest_entry() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1780);
    wait_changed(&owner, 0x9004, 0);
    let kvm = KvmContext::new().unwrap();
    let size = Compatibility::capture(kvm.fd()).unwrap().xsave_size;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        owner.pause().unwrap();
        let state =
            snapshot::request(&owner.handles[0], |reply| Request::Save { size, reply }).unwrap();
        if state.test_halted() {
            break;
        }
        owner.resume().unwrap();
        assert!(
            Instant::now() < deadline,
            "guest did not enter KVM halted MP state"
        );
        std::thread::yield_now();
    }
    owner.export_test(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32)
        .unwrap()
        .0;
    assert!(saved.cpus[0].test_halted());
    drop(owner);
    let restored = RamSnapshotVm::import_test(&dir.path(), RestoreResources::default()).unwrap();
    let state = snapshot::request(&restored.handles[0], |reply| Request::Save {
        size: saved.compatibility.xsave_size,
        reply,
    })
    .unwrap();
    assert!(state.test_halted());
    assert!(restored.is_paused());
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

fn counters(owner: &RamSnapshotVm) -> Vec<u16> {
    (0..owner.handles.len() as u64)
        .map(|id| read(owner, 0x8000 + id * 64))
        .collect()
}

/// The RAM payload of a full image: everything after the JSON section.
fn ram_and_segments(path: &Path) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    let len = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
    bytes[format::HEADER as usize + len..].to_vec()
}

/// Export needs a confirmed pause and never resumes: repeated exports
/// capture the same cut while the guest stays still, an import can be
/// exported again before it ever runs, and every image continues the guest.
#[test]
fn snapshot_v9_snapshot_lifecycle_export_requires_pause_and_repeats_without_resuming() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    let error = owner.export_test(&dir.path()).unwrap_err();
    assert!(
        error.to_string().contains("requires confirmed Paused"),
        "{error}"
    );
    assert!(!dir.path().exists());
    assert!(owner.resume().is_err(), "resume of a running owner");
    owner.pause().unwrap();
    assert!(owner.pause().is_err(), "a second pause was accepted");
    let cut = counters(&owner);
    let (first, second) = (dir.0.join("first"), dir.0.join("second"));
    owner.export_test(&first).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    owner.export_test(&second).unwrap();
    assert_eq!(counters(&owner), cut, "an export resumed the guest");
    assert!(owner.is_paused());
    assert_eq!(ram_and_segments(&first), ram_and_segments(&second));
    owner.resume().unwrap();
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, cut[id as usize]);
    }
    owner.pause().unwrap();
    owner.export_test(&dir.0.join("after-resume")).unwrap();
    drop(owner);

    let imported = RamSnapshotVm::import_test(&first, RestoreResources::default()).unwrap();
    assert_eq!(counters(&imported), cut);
    drop(imported);
    let mut imported = RamSnapshotVm::import_test(&second, RestoreResources::default()).unwrap();
    let again = dir.0.join("again");
    imported.export_test(&again).unwrap();
    assert_eq!(ram_and_segments(&again), ram_and_segments(&second));
    drop(imported);
    let mut restored = RamSnapshotVm::import_test(&again, RestoreResources::default()).unwrap();
    assert_eq!(counters(&restored), cut);
    restored.resume().unwrap();
    for id in 0..2 {
        wait_changed(&restored, 0x8000 + id * 64, cut[id as usize]);
        assert_eq!(
            read(&restored, 0x8004 + id * 64),
            1,
            "cold initialization reran"
        );
    }
}

/// Replace the owner's vCPUs with fakes that acknowledge controls and
/// answer state requests unless `fault` says otherwise; returns the count
/// of Resume events they received. The event thread holds the real vCPUs'
/// stop handles, so it is joined before them and restarted armed with the
/// fakes' handles.
fn fake_cpus(owner: &mut RamSnapshotVm, fault: Fault) -> std::sync::Arc<AtomicUsize> {
    let resumed = std::sync::Arc::new(AtomicUsize::new(0));
    owner.events.take().unwrap().stop();
    for handle in &mut owner.handles {
        handle.finish();
    }
    let count = owner.handles.len();
    owner.handles.clear();
    for id in 0..count {
        let resumed = resumed.clone();
        // Unanswered requests stay alive so the requester times out.
        let mut held = Vec::new();
        owner
            .handles
            .push(fake_cpu(move |event, responses| match event {
                VcpuEvent::Pause if fault == Fault::PauseTimeout && id == 0 => (),
                VcpuEvent::Pause => responses.send(VcpuResponse::Paused).unwrap(),
                VcpuEvent::Resume => {
                    resumed.fetch_add(1, Ordering::Relaxed);
                    let exited = fault == Fault::ResumeExit && id == 1;
                    responses
                        .send(if exited {
                            VcpuResponse::Exited(1)
                        } else {
                            VcpuResponse::Resumed
                        })
                        .unwrap();
                }
                VcpuEvent::Snapshot(Request::Save { reply, .. }) if fault == Fault::SaveTimeout => {
                    held.push(reply)
                }
                VcpuEvent::Snapshot(Request::Save { reply, .. }) => {
                    let _ = reply.try_send(Err("injected state failure".into()));
                }
                _ => panic!("unexpected lifecycle event"),
            }));
    }
    owner.start_event_thread(events::Start::Running).unwrap();
    let stops = owner.handles.iter().map(VcpuHandle::stop_handle).collect();
    owner.events.as_ref().unwrap().arm(stops).unwrap();
    resumed
}

fn assert_disabled(owner: &mut RamSnapshotVm, path: &Path) {
    assert!(owner.control.unusable);
    assert!(
        owner.handles.iter().all(VcpuHandle::is_finished),
        "a vCPU thread outlived the failed control"
    );
    assert!(owner.export_test(path).is_err());
    assert!(owner.resume().is_err());
    assert!(owner.pause().is_err());
    assert!(!path.exists());
}

/// Unconfirmed lifecycle control — a pause or vCPU state request without
/// an answer, a vCPU that exits on resume — disables the owner and joins
/// every thread; a vCPU that answers its state request with an error only
/// fails that export and leaves the pause retryable.
#[test]
fn snapshot_v9_snapshot_lifecycle_uncertain_control_disables_and_joins_threads() {
    for fault in [
        Fault::PauseTimeout,
        Fault::ResumeExit,
        Fault::SaveTimeout,
        Fault::SaveRejected,
    ] {
        let dir = TempDir::new();
        let mut owner = source(2, 0x1000);
        for id in 0..2 {
            wait_changed(&owner, 0x8000 + id * 64, 0);
        }
        let resumed = fake_cpus(&mut owner, fault);
        let image = dir.path();
        match fault {
            Fault::PauseTimeout => {
                assert!(owner.pause().is_err());
                assert_disabled(&mut owner, &image);
            }
            Fault::ResumeExit => {
                owner.pause().unwrap();
                assert!(owner.resume().is_err());
                assert_eq!(
                    resumed.load(Ordering::Relaxed),
                    2,
                    "a vCPU resume was skipped"
                );
                assert_disabled(&mut owner, &image);
            }
            Fault::SaveTimeout => {
                owner.pause().unwrap();
                let error = owner.export_test(&image).unwrap_err();
                assert!(matches!(error, Error::Control(_)), "{error}");
                assert_disabled(&mut owner, &image);
            }
            Fault::SaveRejected => {
                owner.pause().unwrap();
                let error = owner.export_test(&image).unwrap_err();
                assert!(
                    error.to_string().contains("injected state failure"),
                    "{error}"
                );
                assert!(!image.exists());
                assert!(owner.is_paused() && !owner.control.unusable);
                owner.resume().unwrap();
                assert_eq!(resumed.load(Ordering::Relaxed), 2);
            }
        }
    }
}

#[test]
fn snapshot_v9_full_export_rejects_an_actual_external_ram_alias_and_stays_paused() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1000);
    wait_changed(&owner, 0x8000, 0);
    owner.pause().unwrap();
    let alias = owner.memory.clone();
    let error = owner.export_test(&dir.path()).unwrap_err();
    assert!(error.to_string().contains("external aliases"));
    assert!(!dir.path().exists());
    assert!(owner.is_paused());
    drop(alias);
    owner.export_test(&dir.path()).unwrap();
}

#[test]
fn snapshot_v9_one_shot_lapic_and_deadline_complete_once_after_source_destruction() {
    for entry in [0x1500, 0x1580] {
        let dir = TempDir::new();
        let mut owner = source(1, entry);
        wait_changed(&owner, 0x9004, 0);
        owner.pause().unwrap();
        owner.export_test(&dir.path()).unwrap();
        drop(owner);
        std::thread::sleep(Duration::from_millis(250));
        let mut restored =
            RamSnapshotVm::import_test(&dir.path(), RestoreResources::default()).unwrap();
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
    owner.pause().unwrap();
    owner.export_test(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32)
        .unwrap()
        .0;
    let saved_legacy =
        serde_json::to_value(saved.legacy.as_ref().expect("legacy section")).unwrap();
    drop(owner);

    let (ours, mut theirs) = serial_pair();
    let resources = RestoreResources {
        serial: Some([Some(ours), None, None, None]),
        ..Default::default()
    };
    let mut restored = RamSnapshotVm::import_test(&dir.path(), resources).unwrap();
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
    let error = restored.pause().unwrap_err();
    assert!(error.to_string().contains("is exiting"), "{error}");
    assert!(restored.export_test(&dir.0.join("after-reset")).is_err());
    assert!(!dir.0.join("after-reset").exists());
    assert!(restored.resume().is_err());
}

/// Keep the production payload and paired disk, replacing only full metadata
/// and recomputing the real v9 envelope so rejection reaches semantic checks.
fn rewrite_metadata(original: &Path, output: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    rewrite_metadata_and_payload(original, output, &[], mutate);
}
fn rewrite_metadata_and_payload(
    original: &Path,
    output: &Path,
    extra: &[u8],
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let file = File::open(original).unwrap();
    let envelope = format::read(&file).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&envelope.metadata).unwrap();
    mutate(&mut json);
    let encoded = serde_json::to_vec(&json).unwrap();
    let bytes = fs::read(original).unwrap();
    let mut out = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    out.write_all(&[0; format::HEADER as usize]).unwrap();
    out.write_all(&encoded).unwrap();
    out.write_all(&bytes[format::HEADER as usize + envelope.metadata.len()..])
        .unwrap();
    out.write_all(extra).unwrap();
    format::seal(
        &out,
        encoded.len() as u64,
        envelope.payload + extra.len() as u64,
        envelope.disk_len,
        envelope.disk_hash,
    )
    .unwrap();
    fs::copy(
        original.with_extension("qcow2"),
        output.with_extension("qcow2"),
    )
    .unwrap();
}

#[test]
fn snapshot_v9_full_semantic_metadata_rejection_precedes_restore() {
    let dir = TempDir::new();
    let mut owner = loaded();
    owner.attach_legacy([None, None, None, None]).unwrap();
    owner.start_vcpus(1, 0x1000).unwrap();
    owner.pause().unwrap();
    owner.export_test(&dir.path()).unwrap();
    for (name, field, value, reason) in [
        (
            "schema",
            "application_schema",
            serde_json::json!(2),
            "application schema",
        ),
        (
            "unknown",
            "required_future_field",
            serde_json::json!(true),
            "unknown field",
        ),
        ("cpus", "cpus", serde_json::json!([]), "vCPU count"),
        (
            "wrap",
            "regions",
            serde_json::json!([{"gpa": u64::MAX - 4095, "len": 8192, "attributes": 0}]),
            "GPA overflow",
        ),
        (
            "extent",
            "regions",
            serde_json::json!([{"gpa": 0, "len": 4096, "attributes": 0}]),
            "payload extents",
        ),
    ] {
        let path = dir.0.join(name);
        rewrite_metadata(&dir.path(), &path, |json| json[field] = value);
        let error = inspect(&File::open(path).unwrap()).unwrap_err();
        assert!(error.to_string().contains(reason), "{name}: {error}");
    }
    let path = dir.0.join("capability");
    rewrite_metadata(&dir.path(), &path, |json| {
        json["compatibility"]["xsave_size"] =
            (json["compatibility"]["xsave_size"].as_u64().unwrap() + 64).into();
    });
    let endpoints = || RestoreResources {
        serial: Some([None, None, None, None]),
        ..Default::default()
    };
    let error = match RamSnapshotVm::import_test(&path, endpoints()) {
        Ok(_) => panic!("wrong capability restored"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("incompatible CPU"), "{error}");
    let path = dir.0.join("illegal-queue");
    rewrite_metadata(&dir.path(), &path, |json| {
        json["disks"][0]["device"]["queues"][0]["size"] = 7.into()
    });
    let error = match RamSnapshotVm::import_test(&path, endpoints()) {
        Ok(_) => panic!("illegal queue restored"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("disk virtio state"), "{error}");
}

#[test]
fn snapshot_v9_partial_import_kvm_failure_joins_threads_and_closes_fds() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.pause().unwrap();
    owner.export_test(&dir.path()).unwrap();
    drop(owner);
    let path = dir.0.join("partial-import");
    rewrite_metadata(&dir.path(), &path, |json| {
        let offset = std::mem::offset_of!(kvm_bindings::kvm_sregs, cr0);
        for byte in &mut json["cpus"][1]["sregs"].as_array_mut().unwrap()[offset..offset + 8] {
            *byte = serde_json::json!(255);
        }
    });
    let count = |path| fs::read_dir(path).unwrap().count();
    let threads = count("/proc/self/task");
    let fds = count("/proc/self/fd");
    let error = match RamSnapshotVm::import_test(&path, RestoreResources::default()) {
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
    assert!(
        path.exists() && path.with_extension("qcow2").exists(),
        "failed import removed caller-owned pair"
    );
}

#[test]
fn snapshot_v9_full_writer_failure_stays_paused_and_retryable() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.pause().unwrap();
    let cut = counters(&owner);
    let disk_fixture = Fixture::new();
    owner.prepare_checkpoint().unwrap();
    fs::write(dir.0.join("nonempty.mem"), b"keep existing bytes").unwrap();
    let nonempty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.0.join("nonempty.mem"))
        .unwrap();
    assert!(owner
        .export_fd(
            nonempty,
            disk_fixture.qcow2("pair.qcow2"),
            ExportMetadata {
                application_schema: 1,
                application: serde_json::Value::Null,
                objects: vec![],
            }
        )
        .is_err());
    assert_eq!(
        fs::read(dir.0.join("nonempty.mem")).unwrap(),
        b"keep existing bytes"
    );
    assert!(owner.export_test_write_failure().is_err());
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(counters(&owner), cut, "failed full writer resumed guest");
    assert!(owner.is_paused() && !owner.control.unusable);
    owner.export_test(&dir.path()).unwrap();
    owner.resume().unwrap();
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, cut[id as usize]);
    }
}

#[test]
fn snapshot_v9_full_export_refuses_rlimit_without_sigxfsz() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    const CHILD: &str = "KRUN_V9_FSIZE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let dir = TempDir::new();
        let mut owner = source(1, 0x1000);
        owner.pause().unwrap();
        let error = owner.export_test(&dir.path()).unwrap_err();
        assert!(error.to_string().contains("file size limit"), "{error}");
        assert!(owner.is_paused());
        assert!(!dir.path().exists());
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", "ram_snapshot::full::tests::continuation::snapshot_v9_full_export_refuses_rlimit_without_sigxfsz", "--test-threads=1"]).env(CHILD, "1");
    unsafe {
        child.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 512 << 10,
                rlim_max: 512 << 10,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = child.status().unwrap();
    assert!(
        status.success(),
        "child {status:?}, signal {:?}, SIGXFSZ={}",
        status.signal(),
        libc::SIGXFSZ
    );
}

#[test]
fn snapshot_v9_full_session_metadata_rejection_crosses_checked_envelope() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1000);
    owner.pause().unwrap();
    owner.export_test(&dir.path()).unwrap();
    let (session, payload) = crate::ram_snapshot::virtio_fs::tests::captured_validation_session();
    let connected = dir.0.join("with-session");
    rewrite_metadata_and_payload(&dir.path(), &connected, &payload, |json| {
        json["fs"] = session
    });
    inspect(&File::open(&connected).unwrap()).unwrap();
    for case in ["inactive", "unknown", "missing", "extent", "window"] {
        let path = dir.0.join(case);
        rewrite_metadata(&connected, &path, |json| match case {
            "inactive" => {
                json["fs"]["devices"][0]["device"]["activated"] = false.into();
                json["fs"]["devices"][0]["transport"]["device_status"] = 0b1011.into();
            }
            "unknown" => json["fs"]["sessions"][0]["required_future_field"] = true.into(),
            "missing" => {
                json["fs"]["sessions"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("init_len");
            }
            "extent" => {
                let len = json["fs"]["sessions"][0]["init_len"].as_u64().unwrap();
                json["fs"]["sessions"][0]["init_len"] = (len + 1).into();
            }
            "window" => json["fs"]["devices"][0]["dax"] = serde_json::Value::Null,
            _ => unreachable!(),
        });
        let error = inspect(&File::open(&path).unwrap()).unwrap_err();
        let reason = match case {
            "inactive" => "carries a FUSE session",
            "unknown" => "unknown field",
            "missing" => "missing field",
            "extent" => "payload extents",
            "window" => "DAX window differs",
            _ => unreachable!(),
        };
        assert!(error.to_string().contains(reason), "{case}: {error}");
    }
}
