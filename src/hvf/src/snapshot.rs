// SPDX-License-Identifier: Apache-2.0
//! CPU state is accessed only by its HVF owning thread, after completing MMIO.
use super::*;
use serde::{Deserialize, Serialize};
use std::io;

const SYS_REGS: &[u16] = &[
    hv_sys_reg_t_HV_SYS_REG_DBGBVR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1,
    hv_sys_reg_t_HV_SYS_REG_MDSCR_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR7_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR7_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR7_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR7_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR8_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR8_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR8_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR8_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR9_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR9_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR9_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR9_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR10_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR10_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR10_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR10_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR11_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR11_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR11_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR11_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR12_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR12_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR12_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR12_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR13_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR13_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR13_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR13_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR14_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR14_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR14_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR14_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR15_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR15_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR15_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR15_EL1,
    hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CPACR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_TCR_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_SPSR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SP_EL0,
    hv_sys_reg_t_HV_SYS_REG_AFSR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_AFSR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ESR_EL1,
    hv_sys_reg_t_HV_SYS_REG_FAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_PAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_MAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_AMAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_VBAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CONTEXTIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CNTKCTL_EL1,
    hv_sys_reg_t_HV_SYS_REG_CSSELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL0,
    hv_sys_reg_t_HV_SYS_REG_TPIDRRO_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0,
    hv_sys_reg_t_HV_SYS_REG_SP_EL1,
];
const IDS: &[u16] = &[
    hv_sys_reg_t_HV_SYS_REG_MIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64DFR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64DFR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64ISAR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64ISAR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR2_EL1,
];
// Newer SDK registers are probed only for HV_BAD_ARGUMENT/HV_UNSUPPORTED.
const EXTRA_IDS: &[u16] = &[0xc022, 0xc032, 0xc03b, 0xc03c];
const EXTRA_SYS: &[u16] = &[0xc687, 0xde87]; // SCXTNUM_EL1/EL0
const ICC: &[u16] = &[
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_PMR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP0R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP1R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_CTLR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_SRE_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN1_EL1,
];
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuState {
    pub regs: Vec<u64>,
    pub simd: [[u8; 16]; 32],
    pub sys: Vec<u64>,
    pub ids: Vec<u64>,
    pub icc: Vec<u64>,
    pub pending: [bool; 2],
    pub timer_masked: bool,
    pub timer_offset: u64,
    pub frequency: u64,
    pub sme: Option<super::snapshot_sme::SmeState>,
    pub physical_timer: Option<[u64; 2]>,
    pub extra_ids: Vec<(u16, u64)>,
    pub extra_sys: Vec<(u16, u64)>,
}
#[track_caller]
pub(super) fn check(ret: hv_return_t) -> io::Result<()> {
    if ret == HV_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "HVF state error {ret:#x} at {}",
            std::panic::Location::caller()
        )))
    }
}
extern "C" {
    fn krun_hvf_set_simd(cpu: u64, reg: u32, bytes: *const u8) -> hv_return_t;
}
impl HvfVcpu<'_> {
    fn read_extra(&self, regs: &[u16]) -> io::Result<Vec<(u16, u64)>> {
        let mut values = Vec::new();
        for &reg in regs {
            let mut value = 0;
            let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &mut value) };
            if ret == HV_SUCCESS {
                values.push((reg, value));
            } else if ret != HV_BAD_ARGUMENT && ret != HV_UNSUPPORTED {
                check(ret)?;
            }
        }
        Ok(values)
    }
    pub fn save_state(&mut self, native_gic: bool) -> io::Result<CpuState> {
        self.complete_exit()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut state = CpuState {
            regs: Vec::new(),
            simd: [[0; 16]; 32],
            sys: Vec::new(),
            ids: Vec::new(),
            icc: Vec::new(),
            pending: [false; 2],
            timer_masked: false,
            timer_offset: 0,
            frequency: self.cntfrq,
            sme: None,
            physical_timer: None,
            extra_ids: Vec::new(),
            extra_sys: Vec::new(),
        };
        for reg in 0..=hv_reg_t_HV_REG_CPSR {
            let mut value = 0;
            check(unsafe { hv_vcpu_get_reg(self.vcpuid, reg, &mut value) })?;
            state.regs.push(value);
        }
        for (reg, bytes) in state.simd.iter_mut().enumerate() {
            let mut value = 0u128;
            check(unsafe { hv_vcpu_get_simd_fp_reg(self.vcpuid, reg as u32, &mut value) })?;
            *bytes = value.to_le_bytes();
        }
        for (regs, values) in [(SYS_REGS, &mut state.sys), (IDS, &mut state.ids)] {
            for &reg in regs {
                let mut value = 0;
                check(unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &mut value) })
                    .map_err(|e| io::Error::other(format!("read system register {reg:#x}: {e}")))?;
                values.push(value);
            }
        }
        state.extra_ids = self.read_extra(EXTRA_IDS)?;
        state.extra_sys = self.read_extra(EXTRA_SYS)?;
        state.sme = super::snapshot_sme::SmeState::save(self.vcpuid, (state.ids[2] >> 24) & 0xf)?;
        if native_gic {
            let mut timer = [0; 2];
            for (reg, value) in [
                hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0,
                hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
            ]
            .iter()
            .zip(&mut timer)
            {
                check(unsafe { hv_vcpu_get_sys_reg(self.vcpuid, *reg, value) })?;
            }
            state.physical_timer = Some(timer);
            let get: libloading::Symbol<unsafe extern "C" fn(u64, u16, *mut u64) -> hv_return_t> =
                unsafe { HVF.get(b"hv_gic_get_icc_reg") }.map_err(io::Error::other)?;
            for &reg in ICC {
                let mut value = 0;
                check(unsafe { get(self.vcpuid, reg, &mut value) })?;
                state.icc.push(value);
            }
        }
        for (irq, pending) in state.pending.iter_mut().enumerate().filter(|_| !native_gic) {
            check(unsafe { hv_vcpu_get_pending_interrupt(self.vcpuid, irq as u32, pending) })?;
        }
        check(unsafe { hv_vcpu_get_vtimer_mask(self.vcpuid, &mut state.timer_masked) })?;
        check(unsafe { hv_vcpu_get_vtimer_offset(self.vcpuid, &mut state.timer_offset) })?;
        Ok(state)
    }
    pub fn restore_state(&mut self, state: &CpuState, native_gic: bool) -> io::Result<()> {
        if self.cntfrq != state.frequency
            || state.regs.len() != 35
            || state.sys.len() != SYS_REGS.len()
            || state.ids.len() != IDS.len()
            || state.icc.len() != if native_gic { ICC.len() } else { 0 }
        {
            return Err(io::Error::other("incompatible HVF CPU state"));
        }
        for (&reg, &expected) in IDS.iter().zip(&state.ids) {
            let mut value = 0;
            check(unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &mut value) })?;
            if value != expected {
                return Err(io::Error::other("incompatible HVF CPU features"));
            }
        }
        for (known, values, readonly) in [
            (EXTRA_IDS, &state.extra_ids, true),
            (EXTRA_SYS, &state.extra_sys, false),
        ] {
            let current = self.read_extra(known)?;
            if current.len() != values.len()
                || current
                    .iter()
                    .zip(values)
                    .any(|(a, b)| a.0 != b.0 || (readonly && a.1 != b.1))
            {
                return Err(io::Error::other("incompatible CPU extension registers"));
            }
            if !readonly {
                for &(reg, value) in values {
                    check(unsafe { hv_vcpu_set_sys_reg(self.vcpuid, reg, value) })?;
                }
            }
        }
        let sme_version = (state.ids[2] >> 24) & 0xf;
        if state.sme.is_some() != (sme_version != 0) || state.physical_timer.is_some() != native_gic
        {
            return Err(io::Error::other("missing CPU extension state"));
        }
        if let Some(sme) = &state.sme {
            sme.restore(self.vcpuid, sme_version)?;
        }
        if let Some(timer) = &state.physical_timer {
            for (reg, &value) in [
                hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0,
                hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
            ]
            .iter()
            .zip(timer)
            {
                check(unsafe { hv_vcpu_set_sys_reg(self.vcpuid, *reg, value) })?;
            }
        }
        for (reg, &value) in state.regs.iter().enumerate() {
            check(unsafe { hv_vcpu_set_reg(self.vcpuid, reg as u32, value) })?;
        }
        for (reg, value) in state.simd.iter().enumerate() {
            check(unsafe { krun_hvf_set_simd(self.vcpuid, reg as u32, value.as_ptr()) })?;
        }
        for (&reg, &value) in SYS_REGS.iter().zip(&state.sys) {
            check(unsafe { hv_vcpu_set_sys_reg(self.vcpuid, reg, value) })
                .map_err(|e| io::Error::other(format!("write system register {reg:#x}: {e}")))?;
        }
        if native_gic {
            let set: libloading::Symbol<unsafe extern "C" fn(u64, u16, u64) -> hv_return_t> =
                unsafe { HVF.get(b"hv_gic_set_icc_reg") }.map_err(io::Error::other)?;
            for (&reg, &value) in ICC.iter().zip(&state.icc) {
                check(unsafe { set(self.vcpuid, reg, value) })?;
            }
        }
        for (irq, &pending) in state.pending.iter().enumerate().filter(|_| !native_gic) {
            check(unsafe { hv_vcpu_set_pending_interrupt(self.vcpuid, irq as u32, pending) })?;
        }
        self.set_timer_offset(state.timer_offset)?;
        check(unsafe { hv_vcpu_set_vtimer_mask(self.vcpuid, state.timer_masked) })?;
        self.vtimer_masked = state.timer_masked;
        Ok(())
    }
    pub fn adjust_clock(&self, delta: u64, native_gic: bool) -> io::Result<()> {
        let mut offset = 0;
        check(unsafe { hv_vcpu_get_vtimer_offset(self.vcpuid, &mut offset) })?;
        self.set_timer_offset(offset.wrapping_add(delta))?;
        if native_gic {
            let mut cval = 0;
            check(unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
                    &mut cval,
                )
            })?;
            check(unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
                    cval.wrapping_add(delta),
                )
            })?;
        }
        Ok(())
    }
    pub fn set_timer_offset(&self, offset: u64) -> io::Result<()> {
        check(unsafe { hv_vcpu_set_vtimer_offset(self.vcpuid, offset) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_simd_system_timer_and_completed_mmio_roundtrip() {
        let _vm = HvfVm::new(false).unwrap();
        let mut cpu = HvfVcpu::new(0, false).unwrap();
        cpu.set_initial_state(0x8000_0000, 0).unwrap();
        let mut state = cpu.save_state(false).unwrap();
        for reg in 0..31 {
            state.regs[reg] = 0x1234_5678_0000_0000 + reg as u64;
        }
        for (reg, bytes) in state.simd.iter_mut().enumerate() {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (reg * 17 + i) as u8;
            }
        }
        state.timer_offset = 12345;
        state.timer_masked = true;
        state.sys[SYS_REGS
            .iter()
            .position(|r| *r == hv_sys_reg_t_HV_SYS_REG_TPIDR_EL0)
            .unwrap()] = 0xabcd_0123;
        cpu.restore_state(&state, false).unwrap();
        let restored = cpu.save_state(false).unwrap();
        assert_eq!(state.regs, restored.regs);
        assert_eq!(state.simd, restored.simd);
        assert_eq!(state.sys, restored.sys);
        assert_eq!(state.timer_offset, restored.timer_offset);
        assert_eq!(state.timer_masked, restored.timer_masked);
        cpu.pending_advance_pc = true;
        cpu.pending_mmio_read = Some(MmioRead {
            addr: 0xa000000,
            len: 4,
            srt: 5,
        });
        cpu.mmio_buf[..4].copy_from_slice(&0x87654321u32.to_le_bytes());
        let completed = cpu.save_state(false).unwrap();
        assert_eq!(completed.regs[5], 0x87654321);
        assert_eq!(completed.regs[31], state.regs[31] + 4);
        assert_eq!(cpu.save_state(false).unwrap().regs, completed.regs);
        crate::snapshot_sme::tests::streaming_roundtrip(&mut cpu);
    }
}
