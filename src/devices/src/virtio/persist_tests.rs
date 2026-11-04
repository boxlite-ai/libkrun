// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::virtio::queue::tests::VirtQueue;

fn memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
}

#[test]
fn queue_round_trip_continues_rings_and_notification() {
    let mem = memory();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    let mut queue = ring.create_queue();
    queue.set_event_idx(true);
    for i in 0..2 {
        ring.dtable[i].set(0x1000, 32, 0, 0);
        ring.avail.ring[i].set(i as u16);
    }
    ring.avail.idx.set(2);
    let first = queue.pop(&mem).unwrap().index;
    queue.add_used(&mem, first, 32).unwrap();
    let state = queue.save_state(&mem, true).unwrap();
    assert_eq!(state.num_added, 1);
    let mut restored = state.restore(&mem, 8, true).unwrap();
    assert_eq!(queue, restored);
    assert!(restored.needs_notification(&mem).unwrap());
    assert!(!restored.needs_notification(&mem).unwrap());
    let second = restored.pop(&mem).unwrap().index;
    assert_eq!(second, 1);
    restored.add_used(&mem, second, 7).unwrap();
    assert_eq!(ring.used.idx.get(), 2);
    assert_eq!(ring.used.ring[1].get().len, 7);
    assert!(restored.pop(&mem).is_none());
}

#[test]
fn wrap_and_in_flight_chain_survive() {
    let mem = memory();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    let mut queue = ring.create_queue();
    queue.set_event_idx(true);
    queue.next_avail = Wrapping(u16::MAX);
    queue.next_used = Wrapping(u16::MAX);
    ring.used.idx.set(u16::MAX);
    ring.avail.ring[7].set(3);
    ring.dtable[3].set(0x1000, 4, 0, 0);
    ring.avail.idx.set(0);
    ring.avail.event.set(u16::MAX);
    let chain = queue.pop(&mem).unwrap().index;
    let state = queue.save_state(&mem, true).unwrap();
    assert_eq!(state.next_avail, 0);
    let mut restored = state.restore(&mem, 8, true).unwrap();
    restored.add_used(&mem, chain, 4).unwrap();
    assert_eq!(ring.used.idx.get(), 0);
    assert!(restored.needs_notification(&mem).unwrap());
    assert!(restored.save_state(&mem, true).is_ok());
}

#[test]
fn partial_negotiation_preserves_guest_registers() {
    let mem = memory();
    let mut queue = Queue::new(8);
    queue.size = 65535;
    queue.ready = true;
    queue.desc_table = GuestAddress(u64::MAX);
    queue.avail_ring = GuestAddress(3);
    let state = queue.save_state(&mem, false).unwrap();
    assert_eq!(state.restore(&mem, 8, false).unwrap(), queue);
    assert!(state.restore(&mem, 8, true).is_err());
    assert!(state.restore(&mem, 16, false).is_err());
    queue.ready = false;
    queue.set_event_idx(true);
    let state = queue.save_state(&mem, true).unwrap();
    assert_eq!(state.restore(&mem, 8, true).unwrap(), queue);
    queue.next_avail = Wrapping(1);
    assert!(queue.save_state(&mem, false).is_err());
    assert!(queue.save_state(&mem, true).is_err());
}

#[test]
fn rejects_cursor_mismatch_and_overcommit() {
    let mem = memory();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    let queue = ring.create_queue();
    let state = queue.save_state(&mem, true).unwrap();
    ring.used.idx.set(1);
    assert!(state.restore(&mem, 8, true).is_err());
    ring.used.idx.set(0);
    ring.avail.idx.set(9);
    assert!(state.restore(&mem, 8, true).is_err());
    ring.avail.idx.set(8);
    let mut bad = state.clone();
    bad.next_avail = 9;
    assert!(bad.restore(&mem, 8, true).is_err());
    bad.next_avail = u16::MAX;
    assert!(bad.restore(&mem, 8, true).is_err());
    let mut valid = state;
    valid.num_added = u16::MAX;
    assert_eq!(valid.restore(&mem, 8, true).unwrap().num_added.0, u16::MAX);
}

#[test]
fn rejects_holes_overflow_alignment_and_invalid_sizes() {
    let mem =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000), (GuestAddress(0x2000), 0x1000)])
            .unwrap();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    let good = ring.create_queue().save_state(&mem, true).unwrap();
    for field in 0..3 {
        for addr in [0xff0, 0x1ff0, u64::MAX - 15, 0x101] {
            let mut bad = good.clone();
            match field {
                0 => bad.desc_table = addr,
                1 => bad.avail_ring = addr,
                _ => bad.used_ring = addr,
            }
            assert!(bad.restore(&mem, 8, true).is_err());
        }
    }
    for size in [0, 3, 16] {
        let mut bad = good.clone();
        bad.size = size;
        assert!(bad.restore(&mem, 8, true).is_err());
    }
    // Both endpoints mapped, but the descriptor table crosses a hole.
    let mut bad = good;
    bad.max_size = 512;
    bad.size = 512;
    bad.desc_table = 0x800;
    assert!(bad.restore(&mem, 512, true).is_err());
}

#[test]
fn exact_memory_end_is_valid() {
    let mem = memory();
    let ring = VirtQueue::new(GuestAddress(0x100), &mem, 8);
    let mut queue = ring.create_queue();
    queue.desc_table = GuestAddress(0x10000 - 8 * 16);
    assert!(queue.save_state(&mem, true).is_ok());
    queue.desc_table = GuestAddress(0x100);
    queue.avail_ring = GuestAddress(0x10000 - (6 + 2 * 8));
    assert!(queue.save_state(&mem, true).is_ok());
    // Used rings need 4-byte alignment, so put an exact end in a separate mapping.
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10002)]).unwrap();
    queue.avail_ring = GuestAddress(0x200);
    queue.used_ring = GuestAddress(0x10002 - (6 + 8 * 8));
    assert!(queue.save_state(&mem, true).is_ok());
}
