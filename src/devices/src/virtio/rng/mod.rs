mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_RNG as TYPE_RNG;
pub use self::defs::{NUM_QUEUES as RNG_NUM_QUEUES, QUEUE_SIZE as RNG_QUEUE_SIZE};
pub use self::device::{Rng, AVAIL_FEATURES as RNG_FEATURES};

mod defs {
    use crate::virtio::QueueConfig;

    pub const RNG_DEV_ID: &str = "virtio_rng";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZE: u16 = 256;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_RNG: u32 = 4;
    }
}

#[derive(Debug)]
pub enum RngError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, RngError>;
