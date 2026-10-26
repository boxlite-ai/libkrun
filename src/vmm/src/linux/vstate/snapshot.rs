// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from Firecracker 6ec271414300fb8f0ff1ff79ad321bb7467d072f:
// src/vmm/src/arch/x86_64/vcpu.rs (state, XSAVE, MSRs, TSC) and
// src/vmm/src/builder.rs (TSC offset synchronization).
// Local differences: bounded owning-thread requests, validated JSON state,
// conservative compatibility, and mandatory multi-vCPU offset synchronization.

use super::{Vcpu, VcpuEvent, VcpuHandle};
use crossbeam_channel::{bounded, Sender};
use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

pub(crate) type Result<T> = std::result::Result<T, String>;
const TIMEOUT: Duration = Duration::from_secs(1);
const TSC: u32 = 0x10;
const DEADLINE: u32 = 0x6e0;
const LEGACY_XSAVE: usize = std::mem::size_of::<kvm_xsave>();
const MAX_XSAVE: usize = 1024 * 1024;
// Existing CPUID package sizing uses a nonzero u8 power of two.
pub(crate) const MAX_CPUS: usize = 128;
// x87, SSE, AVX, AVX-512 and PKRU have complete XSAVE/XCRS coverage here.
const COVERED_XSTATE: u64 = 0x2e7;

ioctl_iow_nr!(SNAPSHOT_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(SNAPSHOT_SET_DEVICE_ATTR, KVMIO, 0xe1, kvm_device_attr);
ioctl_iow_nr!(SNAPSHOT_HAS_DEVICE_ATTR, KVMIO, 0xe3, kvm_device_attr);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compatibility {
    #[serde(with = "strict_vec")]
    cpuid: Vec<kvm_cpuid_entry2>,
    msrs: Vec<u32>,
    pub(crate) xsave_size: usize,
    caps: Vec<u32>,
}

impl Compatibility {
    pub(crate) fn validate_topology(
        &self,
        state: &CpuState,
        id: usize,
        count: usize,
    ) -> Result<()> {
        let logical = state
            .cpuid
            .iter()
            .find(|e| e.function == 1 && e.index == 0)
            .ok_or("missing topology CPUID")?;
        let expected_count = count
            .checked_next_power_of_two()
            .ok_or("CPU topology count overflow")?;
        if id >= count
            || count == 0
            || expected_count > MAX_CPUS
            || (logical.ebx >> 24) as usize != id
            || ((logical.ebx >> 16) & 0xff) as usize != expected_count
        {
            return Err("unsupported or reordered actual CPU topology".into());
        }
        Ok(())
    }
    pub(crate) fn capture(kvm: &Kvm) -> Result<Self> {
        let required = [
            Cap::Irqchip,
            Cap::Pit2,
            Cap::PitState2,
            Cap::MpState,
            Cap::VcpuEvents,
            Cap::Debugregs,
            Cap::Xsave,
            Cap::Xcrs,
            Cap::GetTscKhz,
            Cap::TscDeadlineTimer,
            Cap::AdjustClock,
        ];
        let mut caps = Vec::new();
        for cap in required {
            if !kvm.check_extension(cap) {
                return Err(format!("snapshot requires KVM {cap:?}"));
            }
            caps.push(cap as u32);
        }
        let xsave_size = xsave_size(kvm.check_extension_int(Cap::Xsave2))?;
        Ok(Self {
            cpuid: kvm
                .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                .map_err(|e| e.to_string())?
                .as_slice()
                .to_vec(),
            msrs: arch::x86_64::msr::supported_guest_msrs(kvm)
                .map_err(|e| format!("snapshot MSR list: {e:?}"))?
                .as_slice()
                .to_vec(),
            xsave_size,
            caps,
        })
    }

    pub(crate) fn validate_target(&self, target: &Self) -> Result<()> {
        validate_xsave_size(self.xsave_size)?;
        // Exact supported CPUID includes vendor, feature masks and leaf-D layout.
        // This intentionally rejects some otherwise migratable heterogeneous hosts.
        if self.cpuid != target.cpuid
            || self.xsave_size != target.xsave_size
            || self.caps != target.caps
            || self.msrs != target.msrs
        {
            return Err(
                "incompatible CPU vendor/features, MSRs, XSAVE layout or KVM capabilities".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn validate_cpu(&self, state: &CpuState) -> Result<()> {
        validate_cpuid(&state.cpuid)?;
        if state.cpuid.len() > KVM_MAX_CPUID_ENTRIES || state.cpuid.is_empty() {
            return Err("invalid actual CPUID count".into());
        }
        let mut leaves = std::collections::BTreeSet::new();
        for entry in &state.cpuid {
            if !leaves.insert((entry.function, entry.index)) {
                return Err("duplicate actual CPUID leaf".into());
            }
        }
        for function in [0, 1, 0xd] {
            if !leaves.contains(&(function, 0)) {
                return Err("missing required actual CPUID leaf".into());
            }
        }
        let vendor = state
            .cpuid
            .iter()
            .find(|e| e.function == 0 && e.index == 0)
            .unwrap();
        let host_vendor = self
            .cpuid
            .iter()
            .find(|e| e.function == 0 && e.index == 0)
            .ok_or("missing host vendor")?;
        if (vendor.ebx, vendor.ecx, vendor.edx)
            != (host_vendor.ebx, host_vendor.ecx, host_vendor.edx)
        {
            return Err("actual CPU vendor differs from target".into());
        }
        // Leaf 1 APIC ID/OSXSAVE and topology leaves are runtime values. Features
        // are checked separately; the supported-host fingerprint is exact above.
        for entry in &state.cpuid {
            let host = self
                .cpuid
                .iter()
                .find(|h| h.function == entry.function && h.index == entry.index)
                .ok_or("actual CPUID leaf absent from target")?;
            if entry.function == 0xd {
                if entry.index == 0 {
                    if entry.eax & !host.eax != 0
                        || entry.edx & !host.edx != 0
                        || entry.ebx as usize > self.xsave_size
                        || entry.ecx as usize > self.xsave_size
                    {
                        return Err("actual XSTATE mask or size differs from target".into());
                    }
                } else if entry.index >= 2
                    && (entry.eax, entry.ebx, entry.ecx, entry.edx)
                        != (host.eax, host.ebx, host.ecx, host.edx)
                {
                    return Err("actual XSAVE component layout differs from target".into());
                } else if entry.index == 1 && entry.eax & !host.eax != 0 {
                    return Err("actual XSAVE instruction feature differs from target".into());
                }
            }
            if entry.function == 1 && entry.eax != host.eax {
                return Err("actual CPU family/model differs from target".into());
            }
            if entry.function == 7 && entry.index > 0 && entry.eax & !host.eax != 0 {
                return Err("actual extended CPU feature differs from target".into());
            }
            let feature_masks = match entry.function {
                1 => (0, entry.ecx & !(1 << 27), entry.edx),
                7 => (entry.ebx, entry.ecx, entry.edx),
                0x80000001 => (0, entry.ecx, entry.edx),
                _ => continue,
            };
            if feature_masks.0 & !host.ebx != 0
                || feature_masks.1 & !host.ecx != 0
                || feature_masks.2 & !host.edx != 0
            {
                return Err("actual CPUID exposes unsupported target feature".into());
            }
        }
        if state.tsc_khz == 0 {
            return Err("zero saved TSC frequency".into());
        }
        if state.vcpu_events.smi.smm != 0
            || state.vcpu_events.smi.pending != 0
            || state.vcpu_events.smi.smm_inside_nmi != 0
            || state.vcpu_events.smi.latched_init != 0
        {
            return Err("SMM/SMI state is outside the snapshot contract".into());
        }
        let mut indices: Vec<_> = state.msrs.iter().map(|m| m.index).collect();
        indices.sort_unstable();
        let mut expected = self.msrs.clone();
        expected.sort_unstable();
        if indices != expected || !indices.contains(&TSC) {
            return Err("missing, duplicate or incompatible saved MSRs".into());
        }
        validate_xsave(&state.xsave, self.xsave_size, &state.cpuid, &state.xcrs)
    }
}

fn validate_cpuid(cpuid: &[kvm_cpuid_entry2]) -> Result<()> {
    let leaf = |f, i| cpuid.iter().find(|e| e.function == f && e.index == i);
    if leaf(1, 0).is_some_and(|e| e.ecx & (1 << 5) != 0)
        || leaf(0x80000001, 0).is_some_and(|e| e.ecx & (1 << 2) != 0)
    {
        return Err("nested VMX/SVM CPU state is unsupported".into());
    }
    if leaf(0xd, 0).is_some_and(|e| (u64::from(e.eax) | (u64::from(e.edx) << 32)) & !COVERED_XSTATE != 0)
        || leaf(0xd, 1).is_some_and(|e| e.ecx != 0 || e.edx != 0 || e.eax & ((1 << 3) | (1 << 4)) != 0)
        // SGX, processor trace, CET and architectural LBR need additional state.
        || leaf(7, 0).is_some_and(|e| e.ebx & ((1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 25)) != 0
            || e.ecx & ((1 << 7) | (1 << 31)) != 0
            || e.edx & ((1 << 5) | (1 << 19) | (1 << 20) | (1 << 22) | (1 << 24) | (1 << 25)) != 0)
    {
        return Err("CPU exposes extended state outside the snapshot contract".into());
    }
    if leaf(0xa, 0).is_some_and(|e| e.eax != 0 || e.ebx != 0 || e.ecx != 0 || e.edx != 0) {
        return Err("PMU CPU state is unsupported".into());
    }
    if leaf(0x80000001, 0).is_some_and(|e| e.ecx & (1 << 10) != 0)
        || cpuid.iter().any(|e| {
            matches!(
                e.function,
                0x8000001b | 0x8000001f | 0x80000020 | 0x80000022
            ) && (e.eax != 0 || e.ebx != 0 || e.ecx != 0 || e.edx != 0)
        })
    {
        return Err("AMD performance/encrypted/extended state is unsupported".into());
    }
    Ok(())
}

pub(crate) fn validate_xsave_size(size: usize) -> Result<()> {
    if !(LEGACY_XSAVE..=MAX_XSAVE).contains(&size) || size % 4 != 0 {
        return Err("invalid dynamic XSAVE size".into());
    }
    Ok(())
}

pub(super) fn xsave_size(capability: i32) -> Result<usize> {
    let size = if capability == 0 {
        LEGACY_XSAVE
    } else {
        usize::try_from(capability).map_err(|_| "invalid KVM XSAVE2 size")?
    };
    validate_xsave_size(size)?;
    Ok(size)
}

fn validate_xsave(
    words: &[u32],
    size: usize,
    cpuid: &[kvm_cpuid_entry2],
    xcrs: &kvm_xcrs,
) -> Result<()> {
    validate_xsave_size(size)?;
    if words.len().checked_mul(4) != Some(size) {
        return Err("XSAVE length differs from target KVM size".into());
    }
    let bitmap = u64::from(words[128]) | (u64::from(words[129]) << 32);
    let compacted = u64::from(words[130]) | (u64::from(words[131]) << 32);
    let leaf = cpuid.iter().find(|e| e.function == 0xd && e.index == 0);
    let supported = leaf.map_or(3, |e| u64::from(e.eax) | (u64::from(e.edx) << 32));
    if bitmap & !supported != 0
        || bitmap & !COVERED_XSTATE != 0
        || compacted != 0
        || words[132..144].iter().any(|v| *v != 0)
    {
        return Err("invalid or uncovered XSTATE/XCOMP bitmap".into());
    }
    let mut ranges = Vec::new();
    for bit in 2..64 {
        if supported & (1 << bit) == 0 {
            continue;
        }
        let component = cpuid
            .iter()
            .find(|e| e.function == 0xd && e.index == bit)
            .ok_or("missing XSAVE component layout")?;
        if component.eax == 0
            || component.ebx < 576
            || component.ecx & 1 != 0
            || (component.ebx as usize)
                .checked_add(component.eax as usize)
                .is_none_or(|end| end > size)
        {
            return Err("invalid XSAVE component layout".into());
        }
        let range = component.ebx..component.ebx + component.eax;
        if ranges
            .iter()
            .any(|r: &std::ops::Range<u32>| range.start < r.end && r.start < range.end)
        {
            return Err("overlapping XSAVE components".into());
        }
        ranges.push(range);
    }
    if xcrs.nr_xcrs != 1 || xcrs.flags != 0 {
        return Err("invalid XCRS count/flags".into());
    }
    for xcr in &xcrs.xcrs[..xcrs.nr_xcrs as usize] {
        if xcr.xcr != 0 || xcr.value & !supported != 0 || xcr.value & 1 == 0 {
            return Err("unsupported XCR or XCR0 mask".into());
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CpuState {
    #[serde(with = "strict_vec")]
    cpuid: Vec<kvm_cpuid_entry2>,
    #[serde(with = "strict_vec")]
    msrs: Vec<kvm_msr_entry>,
    #[serde(with = "strict")]
    debug_regs: kvm_debugregs,
    #[serde(with = "strict")]
    lapic: kvm_lapic_state,
    #[serde(with = "strict")]
    mp_state: kvm_mp_state,
    #[serde(with = "strict")]
    regs: kvm_regs,
    #[serde(with = "strict")]
    sregs: kvm_sregs,
    #[serde(with = "strict")]
    vcpu_events: kvm_vcpu_events,
    #[serde(with = "strict")]
    xcrs: kvm_xcrs,
    xsave: Vec<u32>,
    tsc_khz: u32,
}

#[derive(Debug)]
pub(crate) enum Request {
    Save {
        size: usize,
        reply: Sender<Result<CpuState>>,
    },
    Restore {
        state: Box<CpuState>,
        size: usize,
        reply: Sender<Result<()>>,
    },
    GetOffset(Sender<Result<i64>>),
    SetOffset(i64, Sender<Result<()>>),
}

impl Request {
    pub(super) fn execute(self, cpu: &Vcpu, paused: bool) {
        let rejected = || "state request requires a paused vCPU".to_string();
        match self {
            Self::Save { size, reply } => {
                let _ = reply.try_send(if paused {
                    cpu.capture(size)
                } else {
                    Err(rejected())
                });
            }
            Self::Restore { state, size, reply } => {
                let _ = reply.try_send(if paused {
                    cpu.load(&state, size)
                } else {
                    Err(rejected())
                });
            }
            Self::GetOffset(reply) => {
                let _ = reply.try_send(if paused {
                    cpu.get_offset()
                } else {
                    Err(rejected())
                });
            }
            Self::SetOffset(offset, reply) => {
                let _ = reply.try_send(if paused {
                    cpu.set_offset(offset)
                } else {
                    Err(rejected())
                });
            }
        }
    }
}

pub(crate) fn request<T>(
    handle: &VcpuHandle,
    build: impl FnOnce(Sender<Result<T>>) -> Request,
) -> Result<T> {
    answer(handle, build)?
}

/// Send a request and wait for the vCPU's answer. The outer error means the
/// vCPU never answered (not delivered, timed out, thread gone), so its
/// control state is uncertain; the inner result is the answer itself.
pub(crate) fn answer<T>(
    handle: &VcpuHandle,
    build: impl FnOnce(Sender<Result<T>>) -> Request,
) -> Result<Result<T>> {
    let (reply, response) = bounded(1);
    handle
        .send_event(VcpuEvent::Snapshot(build(reply)))
        .map_err(|e| e.to_string())?;
    response
        .recv_timeout(TIMEOUT)
        .map_err(|e| format!("vCPU state reply timeout/exit/disconnect: {e}"))
}

fn allocate_xsave(size: usize) -> Result<Xsave> {
    validate_xsave_size(size)?;
    Xsave::new((size - LEGACY_XSAVE) / 4).map_err(|e| format!("XSAVE allocation: {e:?}"))
}

fn xsave_words(xsave: &Xsave) -> Vec<u32> {
    xsave
        .as_fam_struct_ref()
        .xsave
        .region
        .iter()
        .chain(xsave.as_slice())
        .copied()
        .collect()
}

fn fix_deadline(msrs: &mut [kvm_msr_entry]) {
    if let Some(tsc) = msrs.iter().filter(|m| m.index == TSC).map(|m| m.data).max() {
        for m in msrs
            .iter_mut()
            .filter(|m| m.index == DEADLINE && m.data == 0)
        {
            m.data = tsc;
        }
    }
}

fn ordered_msrs(msrs: &[kvm_msr_entry]) -> Vec<kvm_msr_entry> {
    msrs.iter()
        .filter(|m| m.index != DEADLINE)
        .chain(msrs.iter().filter(|m| m.index == DEADLINE))
        .copied()
        .collect()
}

fn transfer_msrs(
    id: u8,
    entries: &mut [kvm_msr_entry],
    mut transfer: impl FnMut(&mut Msrs) -> std::result::Result<usize, kvm_ioctls::Error>,
) -> Result<()> {
    for chunk in entries.chunks_mut(KVM_MAX_MSR_ENTRIES) {
        let mut msrs =
            Msrs::from_entries(chunk).map_err(|e| format!("vCPU {id} MSR allocation: {e:?}"))?;
        let count = transfer(&mut msrs)
            .map_err(|e| format!("vCPU {id} MSR {:#x} ioctl: {e}", chunk[0].index))?;
        if count != chunk.len() {
            return Err(format!(
                "vCPU {id} MSR {:#x} partial transfer {count}/{}",
                chunk.get(count).unwrap_or(&chunk[0]).index,
                chunk.len()
            ));
        }
        chunk.copy_from_slice(msrs.as_slice());
    }
    Ok(())
}

fn needs_tsc_scaling(current: u32, saved: u32) -> Result<bool> {
    if current == 0 || saved == 0 {
        return Err("zero TSC frequency".into());
    }
    Ok(u64::from(current.abs_diff(saved)) * 1_000_000 > u64::from(saved) * 250)
}

impl Vcpu {
    /// Hide every CPU feature whose state `validate_cpuid` refuses to save.
    pub(super) fn restrict_cpuid_to_snapshot(&mut self) {
        self.cpuid.retain(|e| {
            e.function != 0x1f
                && (e.function != 0xd
                    || e.index < 2
                    || COVERED_XSTATE & (1u64.checked_shl(e.index).unwrap_or(0)) != 0)
        });
        for entry in self.cpuid.as_mut_slice() {
            match (entry.function, entry.index) {
                (1, 0) => {
                    entry.ecx &= !(1 << 5);
                    entry.ebx = (entry.ebx & 0x00ffffff) | (u32::from(self.id) << 24);
                }
                (0x80000001, 0) => entry.ecx &= !((1 << 2) | (1 << 10)),
                (7, 0) => {
                    entry.ebx &= !((1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 25));
                    entry.ecx &= !((1 << 7) | (1 << 31));
                    entry.edx &=
                        !((1 << 5) | (1 << 19) | (1 << 20) | (1 << 22) | (1 << 24) | (1 << 25));
                }
                (0xd, 0) => {
                    entry.eax &= COVERED_XSTATE as u32;
                    entry.edx = 0;
                }
                (0xd, 1) => {
                    entry.eax &= !((1 << 3) | (1 << 4));
                    entry.ecx = 0;
                    entry.edx = 0;
                }
                (
                    0xa | 0xf | 0x10 | 0x14 | 0x8000000a | 0x8000001b | 0x8000001f | 0x80000020
                    | 0x80000022,
                    _,
                ) => {
                    entry.eax = 0;
                    entry.ebx = 0;
                    entry.ecx = 0;
                    entry.edx = 0;
                }
                _ => (),
            }
        }
    }
    pub(super) fn notify_clock(&self) {
        if let Err(e) = self.fd.kvmclock_ctrl() {
            warn!("vCPU {} KVM_KVMCLOCK_CTRL: {e}", self.id);
        }
    }

    fn capture(&self, size: usize) -> Result<CpuState> {
        let context = |e: kvm_ioctls::Error| format!("vCPU {} state save: {e}", self.id);
        let mp_state = self.fd.get_mp_state().map_err(context)?;
        let mut cpuid = self.fd.get_cpuid2(KVM_MAX_CPUID_ENTRIES).map_err(context)?;
        cpuid.retain(|e| !(e.function == 0 && e.index == 0 && e.flags == 0 && e.eax == 0));
        validate_cpuid(cpuid.as_slice())?;
        let regs = self.fd.get_regs().map_err(context)?;
        let sregs = self.fd.get_sregs().map_err(context)?;
        let debug_regs = self.fd.get_debug_regs().map_err(context)?;
        let lapic = self.fd.get_lapic().map_err(context)?;
        let kvm = Kvm::new().map_err(context)?;
        let actual_size = self.snapshot_xsave_size;
        if size != actual_size {
            return Err("XSAVE allocation differs from actual KVM size".into());
        }
        let mut xsave = allocate_xsave(actual_size)?;
        if kvm.check_extension_int(Cap::Xsave2) > 0 {
            // SAFETY: allocation uses this host KVM_CAP_XSAVE2 byte size.
            unsafe { self.fd.get_xsave2(&mut xsave) }.map_err(context)?;
        } else {
            // SAFETY: only replacing fixed XSAVE region, not the FAM length.
            unsafe { xsave.as_mut_fam_struct() }.xsave = self.fd.get_xsave().map_err(context)?;
        }
        let xcrs = self.fd.get_xcrs().map_err(context)?;
        let tsc_khz = self.fd.get_tsc_khz().map_err(context)?;
        let mut msrs: Vec<_> = self
            .msr_list
            .as_slice()
            .iter()
            .map(|index| kvm_msr_entry {
                index: *index,
                ..Default::default()
            })
            .collect();
        transfer_msrs(self.id, &mut msrs, |chunk| self.fd.get_msrs(chunk))?;
        fix_deadline(&mut msrs);
        let vcpu_events = self.fd.get_vcpu_events().map_err(context)?;
        Ok(CpuState {
            cpuid: cpuid.as_slice().to_vec(),
            msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave: xsave_words(&xsave),
            tsc_khz,
        })
    }

    fn load(&self, state: &CpuState, size: usize) -> Result<()> {
        let kvm = Kvm::new().map_err(|e| format!("restore KVM: {e}"))?;
        let actual = Compatibility::capture(&kvm)?;
        if self.snapshot_xsave_size != size {
            return Err("XSAVE restore differs from actual KVM size".into());
        }
        actual.validate_cpu(state)?;
        validate_xsave(&state.xsave, size, &state.cpuid, &state.xcrs)?;
        let context = |e: kvm_ioctls::Error| format!("vCPU {} state restore: {e}", self.id);
        if needs_tsc_scaling(self.fd.get_tsc_khz().map_err(context)?, state.tsc_khz)? {
            self.fd.set_tsc_khz(state.tsc_khz).map_err(context)?;
        }
        let cpuid =
            CpuId::from_entries(&state.cpuid).map_err(|e| format!("CPUID allocation: {e:?}"))?;
        self.fd.set_cpuid2(&cpuid).map_err(context)?;
        self.fd.set_mp_state(state.mp_state).map_err(context)?;
        self.fd.set_regs(&state.regs).map_err(context)?;
        self.fd.set_sregs(&state.sregs).map_err(context)?;
        let mut xsave = allocate_xsave(size)?;
        // SAFETY: only copying fixed region; FAM length is unchanged.
        unsafe { xsave.as_mut_fam_struct() }
            .xsave
            .region
            .copy_from_slice(&state.xsave[..LEGACY_XSAVE / 4]);
        xsave
            .as_mut_slice()
            .copy_from_slice(&state.xsave[LEGACY_XSAVE / 4..]);
        // SAFETY: validated target size and standard layout; never truncate.
        unsafe { self.fd.set_xsave2(&xsave) }.map_err(context)?;
        self.fd.set_xcrs(&state.xcrs).map_err(context)?;
        self.fd.set_debug_regs(&state.debug_regs).map_err(context)?;
        self.fd.set_lapic(&state.lapic).map_err(context)?;
        transfer_msrs(self.id, &mut ordered_msrs(&state.msrs), |chunk| {
            self.fd.set_msrs(chunk)
        })?;
        self.fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(context)?;
        self.notify_clock();
        Ok(())
    }

    fn offset_attr(&self, address: u64) -> Result<kvm_device_attr> {
        let attr = kvm_device_attr {
            group: KVM_VCPU_TSC_CTRL,
            attr: KVM_VCPU_TSC_OFFSET as u64,
            addr: address,
            ..Default::default()
        };
        // SAFETY: HAS ignores addr, valid vCPU fd and live attribute pointer.
        if unsafe { ioctl_with_ref(&self.fd, SNAPSHOT_HAS_DEVICE_ATTR(), &attr) } != 0 {
            return Err(format!(
                "vCPU {} TSC offset attribute unavailable: {}",
                self.id,
                std::io::Error::last_os_error()
            ));
        }
        Ok(attr)
    }

    fn get_offset(&self) -> Result<i64> {
        let mut offset = 0i64;
        let attr = self.offset_attr((&mut offset as *mut i64) as u64)?;
        // SAFETY: attr.addr points to writable i64 for this synchronous ioctl.
        if unsafe { ioctl_with_ref(&self.fd, SNAPSHOT_GET_DEVICE_ATTR(), &attr) } != 0 {
            return Err(format!(
                "vCPU {} get TSC offset: {}",
                self.id,
                std::io::Error::last_os_error()
            ));
        }
        Ok(offset)
    }

    fn set_offset(&self, offset: i64) -> Result<()> {
        let attr = self.offset_attr((&offset as *const i64) as u64)?;
        // SAFETY: attr.addr points to readable i64 for this synchronous ioctl.
        if unsafe { ioctl_with_ref(&self.fd, SNAPSHOT_SET_DEVICE_ATTR(), &attr) } != 0 {
            return Err(format!(
                "vCPU {} set TSC offset: {}",
                self.id,
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

pub(crate) fn synchronize_offsets(handles: &[VcpuHandle]) -> Result<()> {
    if handles.len() <= 1 {
        return Ok(());
    }
    let offset = request(&handles[0], Request::GetOffset)?;
    for handle in handles {
        request(handle, |reply| Request::SetOffset(offset, reply))?;
    }
    Ok(())
}

impl super::VmState {
    pub(crate) fn validate_snapshot(&self) -> Result<()> {
        if self.pic_master.chip_id != KVM_IRQCHIP_PIC_MASTER
            || self.pic_slave.chip_id != KVM_IRQCHIP_PIC_SLAVE
            || self.ioapic.chip_id != KVM_IRQCHIP_IOAPIC
        {
            return Err("snapshot requires complete kernel PIC/PIC/IOAPIC state".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_clock(&self) -> u64 {
        self.clock.clock
    }

    #[cfg(test)]
    pub(crate) fn test_pic_pending(&self) -> bool {
        // SAFETY: save_state obtains the PIC variant using this chip_id.
        unsafe { self.pic_master.chip.pic.irr & 1 != 0 }
    }
}

#[cfg(test)]
impl CpuState {
    pub(crate) fn test_halted(&self) -> bool {
        self.mp_state.mp_state == KVM_MP_STATE_HALTED
    }
    pub(crate) fn test_tsc(&self) -> (u64, u32) {
        (
            self.msrs.iter().find(|m| m.index == TSC).unwrap().data,
            self.tsc_khz,
        )
    }
}

// kvm-bindings 0.12's serde visitor intentionally zero-pads short structs. A
// versioned checkpoint must reject truncated state instead of inventing it.
pub(crate) mod strict {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, T: serde::de::DeserializeOwned, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        decode(bytes).map_err(D::Error::custom)
    }

    pub(super) fn decode<T: serde::de::DeserializeOwned>(bytes: Vec<u8>) -> Result<T, String> {
        if bytes.len() != std::mem::size_of::<T>() {
            return Err("invalid fixed KVM state byte length".into());
        }
        T::deserialize(serde::de::value::SeqDeserializer::<
            _,
            serde::de::value::Error,
        >::new(bytes.into_iter()))
        .map_err(|e| e.to_string())
    }
}

mod strict_vec {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        values.serialize(serializer)
    }

    pub fn deserialize<'de, T: serde::de::DeserializeOwned, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        Vec::<Vec<u8>>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| super::strict::decode(bytes).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests;
