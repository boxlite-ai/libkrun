// Test names contain "snapshot" so `make snapshot-test` selects them.

use std::sync::Arc;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;
use crate::legacy::DummyIrqChip;
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;

const PAGE: u64 = 4096;
const RAM_END: u64 = 0x40000;
const KEPT: u64 = 0x10000;

fn activated(mem: &GuestMemoryMmap, frq: &VirtQueue) -> Balloon {
    let mut balloon = Balloon::new().unwrap();
    let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "balloon".into()).unwrap();
    let queues = (0..defs::NUM_QUEUES)
        .map(|index| {
            let mut queue = frq.create_queue();
            queue.ready = index == FRQ_INDEX;
            DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
        })
        .collect();
    balloon.activate(mem.clone(), interrupt, queues).unwrap();
    balloon
}

fn page_kept(mem: &GuestMemoryMmap, addr: u64) -> bool {
    let mut bytes = [0u8; PAGE as usize];
    mem.read_slice(&mut bytes, GuestAddress(addr)).unwrap();
    bytes.iter().all(|byte| *byte == 0xaa)
}

/// A report whose valid first page is followed by a malformed descriptor
/// (an unresolvable NEXT link, or a range crossing the end of guest RAM)
/// discards nothing and still completes; a fully valid report discards.
#[test]
fn snapshot_balloon_report_is_validated_whole_before_any_discard() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_END as usize)]).unwrap();
    let frq = VirtQueue::new(GuestAddress(0), &mem, 16);
    mem.write_slice(&[0xaa; PAGE as usize], GuestAddress(KEPT))
        .unwrap();
    let next = 0x1; // VIRTQ_DESC_F_NEXT
                    // Report 0: a valid page linked to a descriptor whose own NEXT link
                    // points outside the table, so the chain cannot be walked to its end.
    frq.dtable[0].set(KEPT, PAGE as u32, VIRTQ_DESC_F_WRITE | next, 4);
    frq.dtable[4].set(KEPT + PAGE, PAGE as u32, VIRTQ_DESC_F_WRITE | next, 16);
    // Report 1: a valid page, then a range crossing the end of guest RAM.
    frq.dtable[1].set(KEPT, PAGE as u32, VIRTQ_DESC_F_WRITE | next, 2);
    frq.dtable[2].set(RAM_END - PAGE, 2 * PAGE as u32, VIRTQ_DESC_F_WRITE, 0);
    // Report 2: the same page alone, valid.
    frq.dtable[3].set(KEPT, PAGE as u32, VIRTQ_DESC_F_WRITE, 0);
    for (slot, head) in [0u16, 1, 3].into_iter().enumerate() {
        frq.avail.ring[slot].set(head);
    }
    let mut balloon = activated(&mem, &frq);

    frq.avail.idx.set(1);
    assert!(balloon.process_frq());
    assert!(
        page_kept(&mem, KEPT),
        "a truncated report discarded its prefix"
    );
    frq.avail.idx.set(2);
    assert!(balloon.process_frq());
    assert!(
        page_kept(&mem, KEPT),
        "an out-of-bounds report discarded its prefix"
    );
    assert_eq!(frq.used.idx.get(), 2);

    frq.avail.idx.set(3);
    assert!(balloon.process_frq());
    assert!(
        !page_kept(&mem, KEPT),
        "a valid report must discard the page"
    );
    assert_eq!(frq.used.idx.get(), 3);
}
