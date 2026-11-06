// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::time::Duration;
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use utils::tempfile::TempFile;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::legacy::DummyIrqChip;
use crate::virtio::block::{CacheType, ImageType, SyncMode};
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::{DeviceQueue, InterruptTransport};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn block(path: &str) -> Block {
    Block::new(
        "disk".into(),
        None,
        CacheType::Writeback,
        path.into(),
        ImageType::Raw,
        false,
        false,
        SyncMode::Full,
    )
    .unwrap()
}

fn irq() -> InterruptTransport {
    InterruptTransport::new(DummyIrqChip::new().into(), "block-test".into()).unwrap()
}

// A real write request, followed by a pending read across worker destruction
// and recreation. No guest kick is issued in the importing process's equivalent
// path; resume must discover the available descriptor itself.
#[test]
fn frozen_disk_roundtrip_rescans_pending_io_and_can_snapshot_again() {
    let file = TempFile::new().unwrap();
    let path = file.as_path().to_str().unwrap();
    let disk = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    disk.set_len(4096).unwrap();
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let ring = VirtQueue::new(GuestAddress(0x1000), &memory, 256);
    let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
    let mut source = block(path);
    source.set_acked_features(1 << 32);
    source
        .activate(
            memory.clone(),
            irq(),
            vec![DeviceQueue::new(ring.create_queue(), event.clone())],
        )
        .unwrap();

    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&1u32.to_le_bytes()); // VIRTIO_BLK_T_OUT
    memory.write_slice(&header, GuestAddress(0x4000)).unwrap();
    memory
        .write_slice(&[0x5a; 512], GuestAddress(0x5000))
        .unwrap();
    ring.dtable[0].set(0x4000, 16, 1, 1);
    ring.dtable[1].set(0x5000, 512, 1, 2);
    ring.dtable[2].set(0x6000, 1, 2, 0);
    ring.avail.ring[0].set(0);
    ring.avail.idx.set(1);
    event.write(1).unwrap();
    let limit = deadline();
    while ring.used.idx.get() != 1 {
        assert!(Instant::now() < limit, "disk write did not complete");
        std::thread::sleep(Duration::from_millis(1));
    }
    source.freeze(deadline()).unwrap();
    assert_eq!(memory.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0);
    let mut data = [0; 512];
    disk.read_exact_at(&mut data, 0).unwrap();
    assert_eq!(data, [0x5a; 512]);
    let state = source.save_state().unwrap();
    assert_eq!(state.queue.as_ref().unwrap().next_used, 1);
    source.reset();
    drop(source);

    // Simulate an available descriptor captured before its kick was handled.
    header[..4].fill(0); // VIRTIO_BLK_T_IN
    memory.write_slice(&header, GuestAddress(0x4000)).unwrap();
    memory.write_slice(&[0; 512], GuestAddress(0x5000)).unwrap();
    ring.dtable[1].set(0x5000, 512, 3, 2);
    ring.avail.ring[1].set(0);
    ring.avail.idx.set(2);
    // An independently flattened image has a different host inode. Preserve
    // the guest-visible GET_ID value while binding this new backing file.
    let independent = TempFile::new().unwrap();
    std::fs::copy(path, independent.as_path()).unwrap();
    disk.write_all_at(&[0xff; 512], 0).unwrap();
    let mut target = block(independent.as_path().to_str().unwrap());
    assert_ne!(target.disk_image_id, state.disk_id);
    target.restore_state(&state).unwrap();
    assert_eq!(target.disk_image_id, state.disk_id);
    let queue = state
        .device
        .restore_queues(&[state.queue.clone().unwrap()], &memory)
        .unwrap()
        .remove(0);
    target
        .activate(
            memory.clone(),
            irq(),
            vec![DeviceQueue::new(
                queue,
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            )],
        )
        .unwrap();
    assert_eq!(ring.used.idx.get(), 1);
    target.resume(deadline()).unwrap();
    assert_eq!(ring.used.idx.get(), 2);
    memory.read_slice(&mut data, GuestAddress(0x5000)).unwrap();
    assert_eq!(data, [0x5a; 512]);
    target.freeze(deadline()).unwrap();
    assert_eq!(target.save_state().unwrap().queue.unwrap().next_used, 2);
    target.resume(deadline()).unwrap();
    target.reset();
}
