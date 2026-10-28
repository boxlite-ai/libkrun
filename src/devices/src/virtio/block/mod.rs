// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod worker;

pub use self::device::{Block, CacheType};
pub use self::worker::{BlockWorkerHandle, WorkerControlError};

use vm_memory::GuestMemoryError;

use super::QueueConfig;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE)];

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Snapshot identity/config bytes have an unsupported length.
    InvalidSnapshotIdentity,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}

/// Supported disk image formats
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
    Vmdk,
}

impl TryFrom<u32> for ImageType {
    type Error = ();

    fn try_from(disk_format: u32) -> Result<Self, Self::Error> {
        match disk_format {
            0 => Ok(ImageType::Raw),
            1 => Ok(ImageType::Qcow2),
            2 => Ok(ImageType::Vmdk),
            _ => {
                // Do not continue if the user cannot specify a valid disk format
                Err(())
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    None,
    Relaxed,
    #[default]
    Full,
}

impl TryFrom<u32> for SyncMode {
    type Error = ();

    fn try_from(sync_mode: u32) -> Result<Self, Self::Error> {
        match sync_mode {
            0 => Ok(SyncMode::None),
            1 => Ok(SyncMode::Relaxed),
            2 => Ok(SyncMode::Full),
            _ => {
                // Do not continue if the user cannot specify a valid sync mode
                Err(())
            }
        }
    }
}

/// Reconstruct the sync mode that offers the saved feature set: the FLUSH
/// feature is only offered when the sync mode is not `None`.
pub fn snapshot_sync_mode(avail_features: u64) -> SyncMode {
    if avail_features & (1u64 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH) != 0 {
        SyncMode::Full
    } else {
        SyncMode::None
    }
}

/// The exact feature set `Block::new` offers for an internal snapshot disk
/// (fixed `SyncMode::Full` at attach): single source of truth for save-side
/// construction and restore-side validation.
pub fn snapshot_offered_features(read_only: bool) -> u64 {
    use virtio_bindings::virtio_blk::{
        VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
        VIRTIO_BLK_F_WRITE_ZEROES,
    };
    use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
    use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
    let mut features = (1u64 << VIRTIO_F_VERSION_1)
        | (1u64 << VIRTIO_BLK_F_SEG_MAX)
        | (1u64 << VIRTIO_BLK_F_DISCARD)
        | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
        | (1u64 << VIRTIO_RING_F_EVENT_IDX)
        | (1u64 << VIRTIO_BLK_F_FLUSH);
    if read_only {
        features |= 1u64 << VIRTIO_BLK_F_RO;
    }
    features
}
