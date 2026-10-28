// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;

use serde::{Deserialize, Serialize};

use crate::bus::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;
/// Bytes that encode the RAM layout: extended memory 0x34–0x35 and high
/// memory 0x5b–0x5d.
const CAPACITY_BYTES: [usize; 5] = [0x34, 0x35, 0x5b, 0x5c, 0x5d];

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        debug!("cmos: mem_below_4g={mem_below_4g} mem_above_4g={mem_above_4g}");

        let mut data = [0u8; DATA_LEN];

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        Cmos { index: 0, data }
    }

    pub fn snapshot_state(&self) -> CmosState {
        CmosState {
            index: self.index,
            data: self.data.to_vec(),
        }
    }

    /// Rebuild a saved CMOS for a guest with the given RAM layout.
    pub fn from_snapshot_state(
        state: &CmosState,
        mem_below_4g: u64,
        mem_above_4g: u64,
    ) -> Result<Cmos, &'static str> {
        state.validate(mem_below_4g, mem_above_4g)?;
        let mut data = [0u8; DATA_LEN];
        data.copy_from_slice(&state.data);
        Ok(Cmos {
            index: state.index,
            data,
        })
    }
}

/// The index register and all 128 data bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmosState {
    index: u8,
    data: Vec<u8>,
}

impl CmosState {
    /// Reject a malformed state or capacity bytes that differ from the
    /// RAM layout.
    pub fn validate(&self, mem_below_4g: u64, mem_above_4g: u64) -> Result<(), &'static str> {
        if self.index & !INDEX_MASK != 0 || self.data.len() != DATA_LEN {
            return Err("CMOS index or data length is invalid");
        }
        let expected = Cmos::new(mem_below_4g, mem_above_4g);
        if CAPACITY_BYTES
            .iter()
            .any(|&at| self.data[at] != expected.data[at])
        {
            return Err("CMOS memory capacity differs from the RAM layout");
        }
        Ok(())
    }
}

impl BusDevice for Cmos {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported read length");
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => {
                debug!("cmos: read index offset");
                self.index
            }
            DATA_OFFSET => {
                debug!("cmos: read data offset from index={:x}", self.index);
                self.data[(self.index & INDEX_MASK) as usize]
            }
            _ => {
                debug!("cmos: unsupported read offset");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported write length");
            return;
        }

        match offset {
            INDEX_OFFSET => {
                debug!("cmos: update index");
                self.index = data[0] & INDEX_MASK;
            }
            _ => debug!("cmos: ignoring unsupported write to CMOS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn snapshot_cmos_state_round_trips_and_checks_capacity() {
        let mut source = Cmos::new(3072 * MIB, 1024 * MIB);
        source.write(0, INDEX_OFFSET, &[0x35]);
        let state = source.snapshot_state();

        let mut target = Cmos::from_snapshot_state(&state, 3072 * MIB, 1024 * MIB).unwrap();
        assert_eq!(target.snapshot_state(), state);
        let mut data = [0u8];
        target.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data[0], source.data[0x35]);

        assert!(Cmos::from_snapshot_state(&state, 2048 * MIB, 1024 * MIB).is_err());
        assert!(Cmos::from_snapshot_state(&state, 3072 * MIB, 0).is_err());
        let truncated = CmosState {
            index: 0,
            data: vec![0; DATA_LEN - 1],
        };
        assert!(truncated.validate(0, 0).is_err());
    }
}
