//! Virtio device emulation.
//!
//! Implements the virtio specification (v1.2) over the MMIO transport
//! for paravirtualized device I/O. Currently supports:
//! - virtio-blk: block device (file-backed disk)
//! - virtio-vsock: socket transport (host TCP <-> guest AF_VSOCK)
//! - virtio-9p: filesystem sharing (host directory <-> guest 9P mount)
//! - virtio-net: network device (userspace proxy via passt/gvproxy)

pub mod block;
pub mod disk;
pub mod mmio;
pub mod net;
pub mod p9;
pub mod queue;
pub mod vsock;
