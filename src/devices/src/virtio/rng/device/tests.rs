// Test names contain "snapshot" so `make snapshot-test` selects them.

use std::sync::Arc;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::*;
use crate::legacy::DummyIrqChip;
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;

/// A failed request completes exactly once with the bytes actually written
/// (never rewound to be completed again): none outside guest RAM, the part
/// before the end of RAM for a crossing buffer. A request larger than the
/// per-request cap completes with the capped length.
#[test]
fn snapshot_rng_failed_request_completes_once_with_actual_length() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
    let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
    // Request 0 targets a buffer outside guest RAM, request 1 one crossing
    // its end by 100 bytes, and request 2 asks for 128 KiB.
    vq.dtable[0].set(0x100_0000, 16, VIRTQ_DESC_F_WRITE, 0);
    vq.dtable[1].set(0x40000 - 100, 4096, VIRTQ_DESC_F_WRITE, 0);
    vq.dtable[2].set(0x10000, 0x20000, VIRTQ_DESC_F_WRITE, 0);
    for slot in 0..3 {
        vq.avail.ring[slot].set(slot as u16);
    }
    vq.avail.idx.set(3);
    let mut rng = Rng::new().unwrap();
    let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "rng".into()).unwrap();
    let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
    rng.activate(
        mem.clone(),
        interrupt,
        vec![DeviceQueue::new(vq.create_queue(), event)],
    )
    .unwrap();

    assert!(rng.process_req());
    assert_eq!(vq.used.idx.get(), 3);
    let used = |slot: usize| {
        let elem = vq.used.ring[slot].get();
        (elem.id, elem.len)
    };
    assert_eq!(used(0), (0, 0));
    assert_eq!(used(1), (1, 100));
    assert_eq!(used(2), (2, 64 * 1024));
    // Nothing was rewound: no request is completed a second time.
    assert!(!rng.process_req());
    assert_eq!(vq.used.idx.get(), 3);
}
