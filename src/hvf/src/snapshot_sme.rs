// SPDX-License-Identifier: Apache-2.0
//! SME state is conditional on the feature exposed to this guest, not host OS age.
use super::snapshot::check;
use super::*;
use serde::{Deserialize, Serialize};
use std::io;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Mode {
    streaming: bool,
    za: bool,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmeState {
    mode: Mode,
    svl: usize,
    sys: [u64; 3],      // SMPRI_EL1, SMCR_EL1, TPIDR2_EL0
    features: [u64; 2], // ID_AA64SMFR0_EL1, ID_AA64ZFR0_EL1
    z: Vec<Vec<u8>>,
    p: Vec<Vec<u8>>,
    za: Vec<u8>,
    zt0: Vec<u8>,
}
#[repr(C, align(64))]
struct AlignedZt([u8; 64]);

const SYS: [u16; 3] = [0xc094, 0xc096, 0xde85];
const IDS: [u16; 2] = [0xc025, 0xc024];
struct Api {
    svl: libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    get_mode: libloading::Symbol<'static, unsafe extern "C" fn(u64, *mut Mode) -> hv_return_t>,
    set_mode: libloading::Symbol<'static, unsafe extern "C" fn(u64, *const Mode) -> hv_return_t>,
    get_z:
        libloading::Symbol<'static, unsafe extern "C" fn(u64, u32, *mut u8, usize) -> hv_return_t>,
    set_z: libloading::Symbol<
        'static,
        unsafe extern "C" fn(u64, u32, *const u8, usize) -> hv_return_t,
    >,
    get_p:
        libloading::Symbol<'static, unsafe extern "C" fn(u64, u32, *mut u8, usize) -> hv_return_t>,
    set_p: libloading::Symbol<
        'static,
        unsafe extern "C" fn(u64, u32, *const u8, usize) -> hv_return_t,
    >,
    get_za: libloading::Symbol<'static, unsafe extern "C" fn(u64, *mut u8, usize) -> hv_return_t>,
    set_za: libloading::Symbol<'static, unsafe extern "C" fn(u64, *const u8, usize) -> hv_return_t>,
    get_zt0: libloading::Symbol<'static, unsafe extern "C" fn(u64, *mut u8) -> hv_return_t>,
    set_zt0: libloading::Symbol<'static, unsafe extern "C" fn(u64, *const u8) -> hv_return_t>,
}
impl Api {
    fn load() -> io::Result<Self> {
        unsafe {
            Ok(Self {
                svl: HVF
                    .get(b"hv_sme_config_get_max_svl_bytes")
                    .map_err(io::Error::other)?,
                get_mode: HVF
                    .get(b"hv_vcpu_get_sme_state")
                    .map_err(io::Error::other)?,
                set_mode: HVF
                    .get(b"hv_vcpu_set_sme_state")
                    .map_err(io::Error::other)?,
                get_z: HVF
                    .get(b"hv_vcpu_get_sme_z_reg")
                    .map_err(io::Error::other)?,
                set_z: HVF
                    .get(b"hv_vcpu_set_sme_z_reg")
                    .map_err(io::Error::other)?,
                get_p: HVF
                    .get(b"hv_vcpu_get_sme_p_reg")
                    .map_err(io::Error::other)?,
                set_p: HVF
                    .get(b"hv_vcpu_set_sme_p_reg")
                    .map_err(io::Error::other)?,
                get_za: HVF
                    .get(b"hv_vcpu_get_sme_za_reg")
                    .map_err(io::Error::other)?,
                set_za: HVF
                    .get(b"hv_vcpu_set_sme_za_reg")
                    .map_err(io::Error::other)?,
                get_zt0: HVF
                    .get(b"hv_vcpu_get_sme_zt0_reg")
                    .map_err(io::Error::other)?,
                set_zt0: HVF
                    .get(b"hv_vcpu_set_sme_zt0_reg")
                    .map_err(io::Error::other)?,
            })
        }
    }
}
impl SmeState {
    pub(super) fn save(cpu: u64, version: u64) -> io::Result<Option<Self>> {
        if version == 0 {
            return Ok(None);
        }
        let api = Api::load()?;
        let mut state = Self {
            mode: Mode::default(),
            svl: 0,
            sys: [0; 3],
            features: [0; 2],
            z: Vec::new(),
            p: Vec::new(),
            za: Vec::new(),
            zt0: Vec::new(),
        };
        check(unsafe { (api.svl)(&mut state.svl) })?;
        if !(16..=256).contains(&state.svl) || !state.svl.is_multiple_of(16) {
            return Err(io::Error::other("invalid SME vector length"));
        }
        check(unsafe { (api.get_mode)(cpu, &mut state.mode) })?;
        for (regs, values) in [
            (SYS.as_slice(), state.sys.as_mut_slice()),
            (IDS.as_slice(), state.features.as_mut_slice()),
        ] {
            for (&reg, value) in regs.iter().zip(values) {
                check(unsafe { hv_vcpu_get_sys_reg(cpu, reg, value) })?;
            }
        }
        if state.mode.streaming {
            for (count, len, get, values) in [
                (32, state.svl, &api.get_z, &mut state.z),
                (16, state.svl / 8, &api.get_p, &mut state.p),
            ] {
                for reg in 0..count {
                    let mut bytes = vec![0; len];
                    check(unsafe { get(cpu, reg, bytes.as_mut_ptr(), len) })?;
                    values.push(bytes);
                }
            }
        }
        if state.mode.za {
            state.za = vec![0; state.svl * state.svl];
            check(unsafe { (api.get_za)(cpu, state.za.as_mut_ptr(), state.za.len()) })?;
            if version >= 2 {
                let mut zt0 = AlignedZt([0; 64]);
                check(unsafe { (api.get_zt0)(cpu, zt0.0.as_mut_ptr()) })?;
                state.zt0 = zt0.0.to_vec();
            }
        }
        Ok(Some(state))
    }
    // Restore before FPSR/Q registers: changing PSTATE.SM clears vector state/FPSR.
    pub(super) fn restore(&self, cpu: u64, version: u64) -> io::Result<()> {
        let api = Api::load()?;
        let mut svl = 0;
        check(unsafe { (api.svl)(&mut svl) })?;
        if svl != self.svl
            || self.z.len() != if self.mode.streaming { 32 } else { 0 }
            || self.p.len() != if self.mode.streaming { 16 } else { 0 }
            || self.z.iter().any(|v| v.len() != svl)
            || self.p.iter().any(|v| v.len() != svl / 8)
            || self.za.len() != if self.mode.za { svl * svl } else { 0 }
            || self.zt0.len() != if self.mode.za && version >= 2 { 64 } else { 0 }
        {
            return Err(io::Error::other("incompatible SME state"));
        }
        for (&reg, &expected) in IDS.iter().zip(&self.features) {
            let mut value = 0;
            check(unsafe { hv_vcpu_get_sys_reg(cpu, reg, &mut value) })?;
            if value != expected {
                return Err(io::Error::other("incompatible SME features"));
            }
        }
        for (&reg, &value) in SYS.iter().zip(&self.sys) {
            check(unsafe { hv_vcpu_set_sys_reg(cpu, reg, value) })?;
        }
        check(unsafe { (api.set_mode)(cpu, &self.mode) })?;
        for (set, values) in [(&api.set_z, &self.z), (&api.set_p, &self.p)] {
            for (reg, bytes) in values.iter().enumerate() {
                check(unsafe { set(cpu, reg as u32, bytes.as_ptr(), bytes.len()) })?;
            }
        }
        if self.mode.za {
            check(unsafe { (api.set_za)(cpu, self.za.as_ptr(), self.za.len()) })?;
            if version >= 2 {
                let zt0 = AlignedZt(self.zt0.as_slice().try_into().unwrap());
                check(unsafe { (api.set_zt0)(cpu, zt0.0.as_ptr()) })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn streaming_roundtrip(cpu: &mut HvfVcpu) {
        if cpu.save_state(false).unwrap().sme.is_none() {
            return;
        }
        let api = Api::load().unwrap();
        check(unsafe {
            (api.set_mode)(
                cpu.id(),
                &Mode {
                    streaming: true,
                    za: true,
                },
            )
        })
        .unwrap();
        let mut saved = cpu.save_state(false).unwrap();
        let sme = saved.sme.as_mut().expect("test host needs SME");
        for (i, bytes) in sme
            .z
            .iter_mut()
            .chain(&mut sme.p)
            .chain(std::iter::once(&mut sme.za))
            .chain(std::iter::once(&mut sme.zt0))
            .enumerate()
        {
            for (j, byte) in bytes.iter_mut().enumerate() {
                *byte = (i * 13 + j) as u8;
            }
        }
        for (q, z) in saved.simd.iter_mut().zip(&sme.z) {
            q.copy_from_slice(&z[..16]);
        }
        cpu.restore_state(&saved, false).unwrap();
        assert_eq!(saved.sme, cpu.save_state(false).unwrap().sme);
        check(unsafe { (api.set_mode)(cpu.id(), &Mode::default()) }).unwrap();
    }
}
