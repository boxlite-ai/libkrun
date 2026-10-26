// SPDX-License-Identifier: Apache-2.0

use super::*;

fn fixture() -> (Compatibility, CpuState) {
    let cpuid = vec![
        kvm_cpuid_entry2 {
            function: 0,
            eax: 0xd,
            ebx: 0x756e6547,
            ecx: 0x6c65746e,
            edx: 0x49656e69,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 1,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0xd,
            eax: 7,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0xd,
            index: 2,
            eax: 256,
            ebx: 576,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0xa,
            ..Default::default()
        },
    ];
    let compatibility = Compatibility {
        cpuid: cpuid.clone(),
        msrs: vec![TSC, DEADLINE],
        xsave_size: LEGACY_XSAVE,
        caps: vec![1, 2],
    };
    let mut xcrs = kvm_xcrs {
        nr_xcrs: 1,
        ..Default::default()
    };
    xcrs.xcrs[0].value = 7;
    let state = CpuState {
        cpuid,
        msrs: vec![msr(TSC, 42), msr(DEADLINE, 0)],
        debug_regs: Default::default(),
        lapic: Default::default(),
        mp_state: Default::default(),
        regs: Default::default(),
        sregs: Default::default(),
        vcpu_events: Default::default(),
        xcrs,
        xsave: vec![0; LEGACY_XSAVE / 4],
        tsc_khz: 1_000_000,
    };
    (compatibility, state)
}

#[test]
fn compatibility_rejects_actual_vendor_layout_nested_pmu_and_missing_msr() {
    for defect in 0..8 {
        let (compatibility, mut state) = fixture();
        compatibility.validate_cpu(&state).unwrap();
        match defect {
            0 => state.cpuid[0].ebx ^= 1,
            1 => state.cpuid[3].ebx += 64,
            2 => state.cpuid.push(state.cpuid[0]),
            3 => state.cpuid[1].ecx |= 1 << 5,
            4 => state.cpuid[4].eax = 1,
            5 => state.msrs.pop().map(|_| ()).unwrap(),
            6 => state.cpuid[2].eax |= 1 << 18,
            7 => state.cpuid.remove(0).function = 0,
            _ => unreachable!(),
        }
        assert!(
            compatibility.validate_cpu(&state).is_err(),
            "defect {defect}"
        );
    }
    let (a, _) = fixture();
    let (mut b, _) = fixture();
    a.validate_target(&b).unwrap();
    b.caps.pop();
    assert!(a.validate_target(&b).is_err());
    let (compatibility, mut state) = fixture();
    state.cpuid[1].ebx = 2 << 16;
    compatibility.validate_topology(&state, 0, 2).unwrap();
    assert!(compatibility.validate_topology(&state, 1, 2).is_err());
    state.cpuid[1].ebx = 1 << 16;
    assert!(compatibility.validate_topology(&state, 0, 2).is_err());
}

/// KVM_GET_SUPPORTED_CPUID never reports the hypervisor, TSC-deadline and
/// HTT bits a VMM sets itself, so a guest showing them stays compatible;
/// any other feature the target lacks is still refused.
#[test]
fn compatibility_accepts_only_vmm_synthesized_leaf_1_bits_absent_from_the_target() {
    let (compatibility, mut state) = fixture();
    state.cpuid[1].ecx |= (1 << 31) | (1 << 24);
    state.cpuid[1].edx |= 1 << 28;
    compatibility.validate_cpu(&state).unwrap();
    state.cpuid[1].ecx |= 1 << 25;
    assert!(compatibility.validate_cpu(&state).is_err());
}

#[test]
fn serde_rejects_short_or_long_fixed_kvm_records_instead_of_padding_or_truncating() {
    let (_, state) = fixture();
    let encoded = serde_json::to_value(&state).unwrap();
    for field in [
        "regs",
        "sregs",
        "lapic",
        "xcrs",
        "vcpu_events",
        "cpuid",
        "msrs",
    ] {
        for short in [true, false] {
            let mut malformed = encoded.clone();
            let bytes = if field == "cpuid" || field == "msrs" {
                &mut malformed[field][0]
            } else {
                &mut malformed[field]
            };
            let bytes = bytes.as_array_mut().unwrap();
            if short {
                bytes.pop();
            } else {
                bytes.push(serde_json::json!(0));
            }
            assert!(
                serde_json::from_value::<CpuState>(malformed).is_err(),
                "{field}: short={short}"
            );
        }
    }
}

fn msr(index: u32, data: u64) -> kvm_msr_entry {
    kvm_msr_entry {
        index,
        data,
        ..Default::default()
    }
}

#[test]
fn deadline_compensation_is_image_only_and_ordered_after_all_chunks() {
    let mut saved: Vec<_> = (0..KVM_MAX_MSR_ENTRIES * 2 + 3)
        .map(|i| msr(0x1000 + i as u32, i as u64))
        .collect();
    saved[0] = msr(DEADLINE, 0);
    saved[KVM_MAX_MSR_ENTRIES + 3] = msr(TSC, 1234);
    let source = saved.clone();
    fix_deadline(&mut saved);
    assert_eq!(source[0].data, 0);
    let mut saved = ordered_msrs(&saved);
    let mut calls = Vec::new();
    transfer_msrs(3, &mut saved, |chunk| {
        calls.push(chunk.as_slice().to_vec());
        Ok(chunk.as_slice().len())
    })
    .unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls[..2].iter().flatten().all(|m| m.index != DEADLINE));
    let last = calls.last().unwrap().last().unwrap();
    assert_eq!((last.index, last.data), (DEADLINE, 1234));
    let mut armed = [msr(DEADLINE, 5678), msr(TSC, 1234)];
    fix_deadline(&mut armed);
    assert_eq!(armed[0].data, 5678);
    let mut no_tsc = [msr(DEADLINE, 0)];
    fix_deadline(&mut no_tsc);
    assert_eq!(no_tsc[0].data, 0);
}

#[test]
fn msr_transfer_copies_read_values_and_reports_first_partial_msr() {
    let mut entries: Vec<_> = (0..KVM_MAX_MSR_ENTRIES + 5)
        .map(|i| msr(i as u32, 0))
        .collect();
    transfer_msrs(7, &mut entries, |chunk| {
        for m in chunk.as_mut_slice() {
            m.data = u64::from(m.index) + 10;
        }
        Ok(chunk.as_slice().len())
    })
    .unwrap();
    assert_eq!(
        entries.last().unwrap().data,
        (KVM_MAX_MSR_ENTRIES + 4) as u64 + 10
    );
    for read in [true, false] {
        let mut calls = 0;
        let err = transfer_msrs(7, &mut entries, |chunk| {
            calls += 1;
            Ok(if calls == 2 {
                if read {
                    2
                } else {
                    3
                }
            } else {
                chunk.as_slice().len()
            })
        })
        .unwrap_err();
        let index = KVM_MAX_MSR_ENTRIES + if read { 2 } else { 3 };
        assert!(err.contains("vCPU 7"), "{err}");
        assert!(err.contains(&format!("MSR {index:#x}")), "{err}");
        assert_eq!(calls, 2);
    }
}

#[test]
fn tsc_frequency_tolerance_is_strictly_greater_than_250_ppm() {
    for current in [999_750, 1_000_250, 1_000_000] {
        assert!(!needs_tsc_scaling(current, 1_000_000).unwrap());
    }
    for current in [999_749, 1_000_251, u32::MAX] {
        assert!(needs_tsc_scaling(current, 1_000_000).unwrap());
    }
    assert!(!needs_tsc_scaling(u32::MAX, u32::MAX).unwrap());
    assert!(needs_tsc_scaling(0, 1).is_err());
    assert!(needs_tsc_scaling(1, 0).is_err());
}

#[test]
fn dynamic_xsave_preserves_full_buffer_and_validates_bitmaps_layout_and_xcrs() {
    let size = 12 * 1024;
    let mut xsave = allocate_xsave(size).unwrap();
    xsave
        .as_mut_slice()
        .last_mut()
        .map(|last| *last = 0x12345678);
    let words = xsave_words(&xsave);
    assert_eq!(words.len() * 4, size);
    assert_eq!(words.last(), Some(&0x12345678));
    assert_eq!(xsave_size(0).unwrap(), LEGACY_XSAVE);
    for invalid in [-1, 1024, 4097, MAX_XSAVE as i32 + 4] {
        assert!(xsave_size(invalid).is_err());
    }
    let cpuid = [
        kvm_cpuid_entry2 {
            function: 0xd,
            eax: 7,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0xd,
            index: 2,
            eax: 256,
            ebx: 576,
            ..Default::default()
        },
    ];
    let mut xcrs = kvm_xcrs {
        nr_xcrs: 1,
        ..Default::default()
    };
    xcrs.xcrs[0].value = 7;
    validate_xsave(&words, size, &cpuid, &xcrs).unwrap();
    assert!(validate_xsave(&words[..1024], size, &cpuid, &xcrs).is_err());
    let mut corrupt = words.clone();
    corrupt[128] = 1 << 18;
    assert!(validate_xsave(&corrupt, size, &cpuid, &xcrs).is_err());
    corrupt = words.clone();
    corrupt[131] = 1 << 31;
    assert!(validate_xsave(&corrupt, size, &cpuid, &xcrs).is_err());
    let mut layout = cpuid;
    layout[1].ebx = size as u32 - 4;
    assert!(validate_xsave(&words, size, &layout, &xcrs).is_err());
    xcrs.nr_xcrs = u32::MAX;
    assert!(validate_xsave(&words, size, &cpuid, &xcrs).is_err());
}

fn controlled_cpu(mut f: impl FnMut(VcpuEvent) + Send + 'static) -> VcpuHandle {
    Vcpu::register_kick_signal_handler();
    let (sender, commands) = crossbeam_channel::unbounded();
    let (_responses, receiver) = crossbeam_channel::unbounded();
    let thread = std::thread::spawn(move || {
        while let Ok(event) = commands.recv() {
            if matches!(event, VcpuEvent::Finish) {
                break;
            }
            f(event);
        }
    });
    VcpuHandle::new(sender, receiver, thread)
}

#[test]
fn offset_sync_uses_vcpu_zero_and_rejects_missing_or_failed_attributes() {
    use std::sync::{Arc, Mutex};
    for failure in [0, 1, 2] {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for id in 0..2 {
            let writes = writes.clone();
            handles.push(controlled_cpu(move |event| match event {
                VcpuEvent::Snapshot(Request::GetOffset(reply)) => {
                    assert_eq!(id, 0);
                    let _ = reply.try_send(if failure == 1 {
                        Err("missing offset attribute".into())
                    } else {
                        Ok(-123)
                    });
                }
                VcpuEvent::Snapshot(Request::SetOffset(offset, reply)) => {
                    writes.lock().unwrap().push((id, offset));
                    let _ = reply.try_send(if failure == 2 && id == 1 {
                        Err("set offset failed".into())
                    } else {
                        Ok(())
                    });
                }
                _ => panic!("unexpected control event"),
            }));
        }
        let result = synchronize_offsets(&handles);
        assert_eq!(result.is_ok(), failure == 0);
        assert_eq!(
            writes.lock().unwrap().as_slice(),
            if failure == 1 {
                &[][..]
            } else {
                &[(0, -123), (1, -123)][..]
            }
        );
        for handle in &mut handles {
            handle.finish();
        }
    }
}

#[test]
fn state_reply_timeout_disconnect_and_late_reply_are_isolated() {
    let mut delayed = None;
    let mut handle = controlled_cpu(move |event| {
        if let VcpuEvent::Snapshot(Request::GetOffset(reply)) = event {
            if let Some(previous) = delayed.replace(reply) {
                assert!(previous.try_send(Ok(100)).is_err());
            }
        }
    });
    assert!(request(&handle, Request::GetOffset)
        .unwrap_err()
        .contains("timeout"));
    assert!(request(&handle, Request::GetOffset)
        .unwrap_err()
        .contains("timeout"));
    handle.finish();
    let mut handle = controlled_cpu(drop);
    assert!(request(&handle, Request::GetOffset)
        .unwrap_err()
        .contains("disconnect"));
    handle.finish();
}

#[test]
fn owning_thread_accepts_queued_state_after_pause_and_rejects_running_requests() {
    let kvm = super::super::KvmContext::new().unwrap();
    let vm = super::super::Vm::new(kvm.fd()).unwrap();
    vm.fd().create_irq_chip().unwrap();
    let mut cpu = Vcpu::new_x86_64(
        0,
        vm.fd(),
        vm.supported_cpuid().clone(),
        vm.supported_msrs().clone(),
        devices::Bus::new(),
        utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
    )
    .unwrap();
    cpu.configure_minimal(0, 1).unwrap();
    let (reply, received) = bounded(1);
    cpu.event_sender
        .as_ref()
        .unwrap()
        .send(VcpuEvent::Snapshot(Request::Save {
            size: cpu.snapshot_xsave_size,
            reply,
        }))
        .unwrap();
    let _next = cpu.process_control();
    assert!(received
        .recv_timeout(TIMEOUT)
        .unwrap()
        .unwrap_err()
        .contains("paused"));
    let (reply, received) = bounded(1);
    cpu.event_sender
        .as_ref()
        .unwrap()
        .send(VcpuEvent::Pause)
        .unwrap();
    cpu.event_sender
        .as_ref()
        .unwrap()
        .send(VcpuEvent::Snapshot(Request::Save {
            size: cpu.snapshot_xsave_size,
            reply,
        }))
        .unwrap();
    let _next = cpu.process_control();
    let state = received.recv_timeout(TIMEOUT).unwrap().unwrap();
    assert_eq!(state.regs.rip, 0);
    assert!(received.try_recv().is_err());
    assert_eq!(
        cpu.response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(TIMEOUT)
            .unwrap(),
        super::super::VcpuResponse::Paused
    );
    assert!(cpu.response_receiver.as_ref().unwrap().is_empty());
}

#[test]
fn actual_save_compensates_zero_deadline_without_writing_the_source_msr() {
    let kvm = super::super::KvmContext::new().unwrap();
    let vm = super::super::Vm::new(kvm.fd()).unwrap();
    vm.fd().create_irq_chip().unwrap();
    let mut cpu = Vcpu::new_x86_64(
        0,
        vm.fd(),
        vm.supported_cpuid().clone(),
        vm.supported_msrs().clone(),
        devices::Bus::new(),
        utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
    )
    .unwrap();
    cpu.configure_minimal(0, 1).unwrap();
    let zero_deadline = Msrs::from_entries(&[msr(DEADLINE, 0)]).unwrap();
    assert_eq!(cpu.fd.set_msrs(&zero_deadline).unwrap(), 1);
    let state = cpu.capture(cpu.snapshot_xsave_size).unwrap();
    let saved_tsc = state.msrs.iter().find(|m| m.index == TSC).unwrap().data;
    let saved_deadline = state
        .msrs
        .iter()
        .find(|m| m.index == DEADLINE)
        .unwrap()
        .data;
    assert!(saved_tsc > 0);
    assert_eq!(saved_deadline, saved_tsc);
    let mut source = Msrs::from_entries(&[msr(DEADLINE, u64::MAX)]).unwrap();
    assert_eq!(cpu.fd.get_msrs(&mut source).unwrap(), 1);
    assert_eq!(
        source.as_slice()[0].data,
        0,
        "save mutated source timer state"
    );
}
