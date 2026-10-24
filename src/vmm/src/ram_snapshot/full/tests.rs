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
    owner.pause().unwrap();
    owner.export(&dir.path()).unwrap();
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(owner);
    let mut restored = RamSnapshotVm::import(&dir.path(), RestoreResources::default()).unwrap();
    let counters: Vec<_> = (0..2).map(|id| read(&restored, 0x8000 + id * 64)).collect();
    // A RAM-only save of the paused import neither fails nor resumes it.
    restored.save(&dir.0.join("ram-while-paused")).unwrap();
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
    restored.export(&dir.0.join("second")).unwrap();
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
        // Keep the CPU paused while hardware may mature a pending
        // interrupt; the export captures that same pause.
        owner.pause().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        if entry == 0x1200 {
            owner.vm.fd().set_irq_line(0, false).unwrap();
            owner.vm.fd().set_irq_line(0, true).unwrap();
        }
        owner.export(&dir.path()).unwrap();
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
        let mut restored = RamSnapshotVm::import(&dir.path(), RestoreResources::default()).unwrap();
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
        restored.export(&dir.0.join("second")).unwrap();
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
    owner.export(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
    assert!(saved.cpus[0].test_halted());
    drop(owner);
    let restored = RamSnapshotVm::import(&dir.path(), RestoreResources::default()).unwrap();
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
    let len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    bytes[16 + len..].to_vec()
}

/// Export needs a confirmed pause and never resumes: repeated exports
/// capture the same cut while the guest stays still, an import can be
/// exported again before it ever runs, and every image continues the guest.
#[test]
fn snapshot_lifecycle_export_requires_pause_and_repeats_without_resuming() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    let error = owner.export(&dir.path()).unwrap_err();
    assert!(error.to_string().contains("requires a paused"), "{error}");
    assert!(!dir.path().exists());
    assert!(owner.resume().is_err(), "resume of a running owner");
    owner.pause().unwrap();
    assert!(owner.pause().is_err(), "a second pause was accepted");
    let cut = counters(&owner);
    let (first, second) = (dir.0.join("first"), dir.0.join("second"));
    owner.export(&first).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    owner.export(&second).unwrap();
    assert_eq!(counters(&owner), cut, "an export resumed the guest");
    assert!(owner.is_paused());
    assert_eq!(ram_and_segments(&first), ram_and_segments(&second));
    owner.resume().unwrap();
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, cut[id as usize]);
    }
    owner.pause().unwrap();
    owner.export(&dir.0.join("after-resume")).unwrap();
    drop(owner);

    let imported = RamSnapshotVm::import(&first, RestoreResources::default()).unwrap();
    assert_eq!(counters(&imported), cut);
    drop(imported);
    let mut imported = RamSnapshotVm::import(&second, RestoreResources::default()).unwrap();
    let again = dir.0.join("again");
    imported.export(&again).unwrap();
    assert_eq!(ram_and_segments(&again), ram_and_segments(&second));
    drop(imported);
    let mut restored = RamSnapshotVm::import(&again, RestoreResources::default()).unwrap();
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

/// How the fake vCPUs below fail one lifecycle step.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    PauseTimeout,
    ResumeExit,
    SaveTimeout,
    SaveRejected,
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
    assert!(owner.export(path).is_err());
    assert!(owner.resume().is_err());
    assert!(owner.pause().is_err());
    assert!(!path.exists());
}

/// Unconfirmed lifecycle control — a pause or vCPU state request without
/// an answer, a vCPU that exits on resume — disables the owner and joins
/// every thread; a vCPU that answers its state request with an error only
/// fails that export and leaves the pause retryable.
#[test]
fn snapshot_lifecycle_uncertain_control_disables_and_joins_threads() {
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
                let error = owner.export(&image).unwrap_err();
                assert!(matches!(error, Error::Control(_)), "{error}");
                assert_disabled(&mut owner, &image);
            }
            Fault::SaveRejected => {
                owner.pause().unwrap();
                let error = owner.export(&image).unwrap_err();
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
fn full_export_rejects_an_actual_external_ram_alias_and_stays_paused() {
    let dir = TempDir::new();
    let mut owner = source(1, 0x1000);
    wait_changed(&owner, 0x8000, 0);
    owner.pause().unwrap();
    let alias = owner.memory.clone();
    let error = owner.export(&dir.path()).unwrap_err();
    assert!(error.to_string().contains("external aliases"));
    assert!(!dir.path().exists());
    assert!(owner.is_paused());
    drop(alias);
    owner.export(&dir.path()).unwrap();
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
        owner.pause().unwrap();
        owner.export(&dir.path()).unwrap();
        drop(owner);
        std::thread::sleep(Duration::from_millis(250));
        let mut restored = RamSnapshotVm::import(&dir.path(), RestoreResources::default()).unwrap();
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
    owner.pause().unwrap();
    owner.export(&dir.path()).unwrap();
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
    assert!(RamSnapshotVm::import(&dir.0.join("mismatch"), RestoreResources::default()).is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    fs::write(dir.0.join("trailing"), &trailing).unwrap();
    assert!(read_metadata(&mut File::open(dir.0.join("trailing")).unwrap(), 32, 32).is_err());
    let mut incomplete = original;
    incomplete[..8].fill(0);
    fs::write(dir.0.join("incomplete"), &incomplete).unwrap();
    assert!(read_metadata(&mut File::open(dir.0.join("incomplete")).unwrap(), 32, 32).is_err());
}

/// A failed export never overwrites an existing file, removes its partial
/// image and keeps the guest paused; a retry publishes, and only `resume`
/// runs the guest again.
#[test]
fn full_export_failure_stays_paused_and_never_overwrites_existing_file() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.pause().unwrap();
    let cut = counters(&owner);
    fs::write(dir.path(), b"keep existing file").unwrap();
    assert!(owner.export(&dir.path()).is_err());
    assert_eq!(fs::read(dir.path()).unwrap(), b"keep existing file");
    let failed_path = dir.0.join("mid-copy");
    let result = super::super::tests::with_failed_payload_write(17, || owner.export(&failed_path));
    assert!(result.is_err());
    assert!(!failed_path.exists());
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(counters(&owner), cut, "a failed export resumed the guest");
    assert!(owner.is_paused() && !owner.control.unusable);
    owner.export(&dir.0.join("after-write-failure")).unwrap();
    owner.resume().unwrap();
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, cut[id as usize]);
    }
}

#[test]
fn partial_import_kvm_failure_joins_threads_and_closes_fds() {
    let dir = TempDir::new();
    let mut owner = source(2, 0x1000);
    for id in 0..2 {
        wait_changed(&owner, 0x8000 + id * 64, 0);
    }
    owner.pause().unwrap();
    owner.export(&dir.path()).unwrap();
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
    let error =
        match RamSnapshotVm::import(&dir.0.join("partial-import"), RestoreResources::default()) {
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

/// Versions 1–6 (4 had no vsock section, 5 no console section, 6 no
/// virtio-fs section) are rejected by version before their JSON is parsed.
#[test]
fn snapshot_full_rejects_pre_unified_versions() {
    let dir = TempDir::new();
    let path = dir.path();
    for old in 1..=6 {
        write_header_only(&path, old, b"{}");
        let error = rejection(read_metadata(&mut File::open(&path).unwrap(), 32, 32));
        assert!(
            error.contains(&format!("version {old} predates")),
            "{error}"
        );
    }
}

/// A metadata JSON holding one zeroed CPU, complete zeroed irqchip state,
/// fresh legacy devices and the given RAM `regions`.
fn minimal_metadata(regions: serde_json::Value) -> serde_json::Value {
    use kvm_bindings::{
        kvm_clock_data, kvm_debugregs, kvm_irqchip, kvm_lapic_state, kvm_mp_state, kvm_pit_state2,
        kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    };
    use std::mem::size_of;
    let zeros = |len: usize| vec![0u8; len];
    // chip_id leads kvm_irqchip: PIC master 0, PIC slave 1, IOAPIC 2.
    let chip = |id: u8| {
        let mut bytes = zeros(size_of::<kvm_irqchip>());
        bytes[0] = id;
        bytes
    };
    let evt = || utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
    let serial: Vec<_> = (0..4)
        .map(|_| devices::legacy::Serial::new_sink(evt()).snapshot_state())
        .collect();
    serde_json::json!({
        "compatibility": {"cpuid": [], "msrs": [], "xsave_size": 0, "caps": []},
        "cpus": [{
            "cpuid": [],
            "msrs": [],
            "debug_regs": zeros(size_of::<kvm_debugregs>()),
            "lapic": zeros(size_of::<kvm_lapic_state>()),
            "mp_state": zeros(size_of::<kvm_mp_state>()),
            "regs": zeros(size_of::<kvm_regs>()),
            "sregs": zeros(size_of::<kvm_sregs>()),
            "vcpu_events": zeros(size_of::<kvm_vcpu_events>()),
            "xcrs": zeros(size_of::<kvm_xcrs>()),
            "xsave": [],
            "tsc_khz": 0,
        }],
        "vm": {
            "pitstate": zeros(size_of::<kvm_pit_state2>()),
            "clock": zeros(size_of::<kvm_clock_data>()),
            "pic_master": chip(0),
            "pic_slave": chip(1),
            "ioapic": chip(2),
        },
        "regions": regions,
        "disks": [],
        "nic": null,
        "rng": null,
        "balloon": null,
        "vsock": null,
        "console": null,
        "legacy": {
            "serial": serial,
            "cmos": devices::legacy::Cmos::new(0, 0).snapshot_state(),
            "i8042": devices::legacy::I8042Device::new(evt(), evt()).snapshot_state(),
        },
        "fs": null,
    })
}

/// Every device section relies on validated RAM regions, so the regions
/// are checked first: a region wrapping the address space next to a legacy
/// section is refused, never reaching the CMOS capacity arithmetic.
#[test]
fn snapshot_full_validates_ram_regions_before_device_sections() {
    let dir = TempDir::new();
    let path = dir.path();
    let valid = minimal_metadata(serde_json::json!([{"gpa": 0, "len": 0x2000, "attributes": 0}]));
    write_header_only(&path, FULL_VERSION, &serde_json::to_vec(&valid).unwrap());
    let error = rejection(read_metadata(&mut File::open(&path).unwrap(), 32, 32));
    assert!(error.contains("length differs"), "{error}");
    let wrapping = serde_json::json!([{"gpa": u64::MAX - 0xfff, "len": 0x2000, "attributes": 0}]);
    let metadata = minimal_metadata(wrapping);
    write_header_only(&path, FULL_VERSION, &serde_json::to_vec(&metadata).unwrap());
    let error = rejection(read_metadata(&mut File::open(&path).unwrap(), 32, 32));
    assert!(error.contains("GPA overflow"), "{error}");
}

/// A share section is checked with the rest of the metadata, before RAM or
/// any resource exists: its payload lengths decide the image length, and
/// an inactive device carrying a FUSE session is refused.
#[test]
fn snapshot_full_share_sections_are_checked_with_the_image_length() {
    let dir = TempDir::new();
    let src = dir.0.join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("f"), b"file").unwrap();
    let (share, payloads) = crate::ram_snapshot::virtio_fs::tests::captured_share(&src);
    let image = |metadata: &serde_json::Value, payloads: &[u8]| {
        let path = dir.path();
        write_header_only(&path, FULL_VERSION, &serde_json::to_vec(metadata).unwrap());
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0; 0x2000]).unwrap();
        file.write_all(payloads).unwrap();
        read_metadata(&mut File::open(&path).unwrap(), 32, 32)
    };
    let mut metadata =
        minimal_metadata(serde_json::json!([{"gpa": 0, "len": 0x2000, "attributes": 0}]));
    metadata["legacy"] = serde_json::Value::Null;
    metadata["fs"] = serde_json::to_value(&share).unwrap();
    let parsed = image(&metadata, &payloads).unwrap();
    assert_eq!(parsed.fs.unwrap().devices.len(), 1);
    let error = rejection(image(&metadata, &payloads[1..]));
    assert!(error.contains("length differs"), "{error}");
    let device = &mut metadata["fs"]["devices"][0];
    device["device"]["activated"] = false.into();
    device["transport"]["device_status"] = 0b1011.into();
    let error = rejection(image(&metadata, &payloads));
    assert!(error.contains("carries a FUSE session"), "{error}");
}

/// Each target resource is required exactly when its device is present.
#[test]
fn snapshot_full_restore_resources_must_match_devices() {
    let none = Requirements {
        disks: false,
        nic: false,
        vsock: false,
        console: false,
        legacy: false,
        fs: false,
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
    let with_vsock = Requirements {
        vsock: true,
        ..none
    };
    assert!(with_vsock.check(&RestoreResources::default()).is_err());
    let ports = RestoreResources {
        vsock_ports: Some(Default::default()),
        ..Default::default()
    };
    with_vsock.check(&ports).unwrap();
    assert!(none.check(&ports).is_err());
    let with_console = Requirements {
        console: true,
        ..none
    };
    assert!(with_console.check(&RestoreResources::default()).is_err());
    let console_ports = RestoreResources {
        console_ports: Some(Vec::new()),
        ..Default::default()
    };
    with_console.check(&console_ports).unwrap();
    assert!(none.check(&console_ports).is_err());
    let with_fs = Requirements { fs: true, ..none };
    assert!(with_fs.check(&RestoreResources::default()).is_err());
    let fs_dir = RestoreResources {
        fs_dir: Some(PathBuf::from("/nonexistent")),
        ..Default::default()
    };
    with_fs.check(&fs_dir).unwrap();
    assert!(none.check(&fs_dir).is_err());
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
/// i8042 reset latches the exit and stops the vCPU, after which no pause,
/// export or resume is accepted.
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
    owner.export(&dir.path()).unwrap();
    let saved = read_metadata(&mut File::open(dir.path()).unwrap(), owner.max_slots, 32).unwrap();
    let saved_legacy =
        serde_json::to_value(saved.legacy.as_ref().expect("legacy section")).unwrap();
    drop(owner);

    let (ours, mut theirs) = serial_pair();
    let resources = RestoreResources {
        serial: Some([Some(ours), None, None, None]),
        ..Default::default()
    };
    let mut restored = RamSnapshotVm::import(&dir.path(), resources).unwrap();
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
    assert!(restored.export(&dir.0.join("after-reset")).is_err());
    assert!(!dir.0.join("after-reset").exists());
    assert!(restored.resume().is_err());
}
