// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;

use crate::bus::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

/// In-memory CMOS contents. The image owner must check the RAM layout agrees
/// with the capacity registers; no host clock or IRQ is modeled by this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmosState {
    pub index: u8,
    pub data: [u8; DATA_LEN],
}

impl CmosState {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.index & !INDEX_MASK != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid CMOS index",
            ));
        }
        Ok(())
    }
}

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    /// Caller must quiesce vCPUs and device event sources before capture.
    pub fn save_state(&self) -> CmosState {
        CmosState {
            index: self.index,
            data: self.data,
        }
    }

    /// Restore while vCPUs and device event sources remain quiesced.
    /// Invalid input leaves the device unchanged.
    pub fn restore_state(&mut self, state: &CmosState) -> std::io::Result<()> {
        state.validate()?;
        self.index = state.index;
        self.data = state.data;
        Ok(())
    }

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

    fn read(cmos: &mut Cmos, offset: u64) -> u8 {
        let mut data = [0];
        cmos.read(0, offset, &mut data);
        data[0]
    }

    #[test]
    fn snapshot_restores_all_data_and_selected_index() {
        let mut source = Cmos::new(3 << 30, 5 << 30);
        source.write(0, INDEX_OFFSET, &[0xdb]);
        let state = source.save_state();
        assert_eq!(state.index, 0x5b);
        let mut restored = Cmos::new(0, 0);
        restored.restore_state(&state).unwrap();
        assert_eq!(restored.save_state(), state);
        assert_eq!(source.save_state(), state);
        assert_eq!(read(&mut restored, INDEX_OFFSET), 0x5b);
        assert_eq!(read(&mut restored, DATA_OFFSET), state.data[0x5b]);
        for index in 0..DATA_LEN {
            restored.write(0, INDEX_OFFSET, &[index as u8]);
            assert_eq!(read(&mut restored, DATA_OFFSET), state.data[index]);
        }
        // Capacity fields were copied, rather than recomputed from the target.
        assert_eq!(&state.data[0x34..=0x35], &[0x00, 0xbf]);
        assert_eq!(&state.data[0x5b..=0x5d], &[0x00, 0x40, 0x01]);
        restored.write(0, DATA_OFFSET, &[0xff]);
        assert_eq!(read(&mut restored, DATA_OFFSET), 0); // Data writes remain ignored.
        let before = restored.save_state();
        restored.write(0, INDEX_OFFSET, &[0, 1]);
        restored.write(0, 2, &[0]);
        let mut wide = [0xa5; 2];
        restored.read(0, INDEX_OFFSET, &mut wide);
        assert_eq!(wide, [0xa5; 2]);
        assert_eq!(restored.save_state(), before);
    }

    #[test]
    fn snapshot_rejects_invalid_index_without_mutation() {
        let mut cmos = Cmos::new(1 << 30, 0);
        cmos.write(0, INDEX_OFFSET, &[0x35]);
        let original = cmos.save_state();
        let mut invalid = original.clone();
        invalid.index = 0x80;
        invalid.data.fill(0xff);
        assert_eq!(
            invalid.validate().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            cmos.restore_state(&invalid).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(cmos.save_state(), original);
        assert_eq!(read(&mut cmos, DATA_OFFSET), original.data[0x35]);
    }
}
