// SPDX-License-Identifier: Apache-2.0

//! RNG and balloon checkpoints on a real KVM VM. The stage-2 counter
//! fixture runs with interrupts disabled; the test plays the RNG driver
//! through the owner's MMIO bus and guest RAM. Test names contain
//! "snapshot" for `make snapshot-test`.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use vm_memory::{Bytes, GuestAddress};

use super::*;
use crate::ram_snapshot::RestoreResources;

const QSIZE: u32 = 16;
const DESC: u64 = 0x4_0000;
const AVAIL: u64 = 0x4_1000;
const USED: u64 = 0x4_2000;
const BUF: u64 = 0x5_0000;
const COUNTER: u64 = 0x8000;

fn write(vm: &RamSnapshotVm, addr: u64, offset: u64, value: u32) {
    assert!(vm.bus.write(0, addr + offset, &value.to_le_bytes()));
}

fn read(vm: &RamSnapshotVm, addr: u64, offset: u64) -> u32 {
    let mut bytes = [0u8; 4];
    assert!(vm.bus.read(0, addr + offset, &mut bytes));
    u32::from_le_bytes(bytes)
}

fn used_idx(vm: &RamSnapshotVm) -> u16 {
    vm.memory.read_obj(GuestAddress(USED + 2)).unwrap()
}

fn wait(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Activate the RNG like a virtio-mmio driver and make one request
/// available without notifying the device.
fn activate_rng_with_pending_request(vm: &RamSnapshotVm) {
    let rng = RNG.mmio_addr;
    assert_eq!(read(vm, rng, 0x08), TYPE_RNG);
    write(vm, rng, 0x70, 0b0001);
    write(vm, rng, 0x70, 0b0011);
    write(vm, rng, 0x24, 1);
    write(vm, rng, 0x20, 1); // VIRTIO_F_VERSION_1
    write(vm, rng, 0x70, 0b1011);
    write(vm, rng, 0x30, 0);
    write(vm, rng, 0x38, QSIZE);
    for (offset, addr) in [(0x80, DESC), (0x90, AVAIL), (0xa0, USED)] {
        write(vm, rng, offset, addr as u32);
        write(vm, rng, offset + 4, 0);
    }
    write(vm, rng, 0x44, 1);
    write(vm, rng, 0x70, 0b1111);
    assert_eq!(read(vm, rng, 0x70), 0b1111, "RNG activation failed");
    let descriptor = devices::virtio::Descriptor {
        addr: BUF,
        len: 256,
        flags: 2, // VIRTQ_DESC_F_WRITE
        next: 0,
    };
    vm.memory.write_obj(descriptor, GuestAddress(DESC)).unwrap();
    vm.memory.write_obj(0u16, GuestAddress(AVAIL + 4)).unwrap();
    vm.memory.write_obj(1u16, GuestAddress(AVAIL + 2)).unwrap();
}

/// The cut keeps an un-notified RNG request pending and an inactive
/// balloon; the restored VM completes the request on resume without any
/// notification, and the source continues on its own.
#[test]
fn snapshot_rng_balloon_kvm_restore_kicks_pending_request() {
    let mut source = crate::builder::build_ram_snapshot_vm(
        2,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("krun-events-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let image: PathBuf = dir.join("checkpoint");
    source
        .memory
        .write_slice(include_bytes!("../full/guest.bin"), GuestAddress(0x1000))
        .unwrap();
    source.attach_rng().unwrap();
    source.attach_balloon().unwrap();
    assert!(source.attach_rng().is_err(), "a second RNG attached");
    source.start_vcpus(1, 0x1000).unwrap();
    activate_rng_with_pending_request(&source);
    source.pause().unwrap();
    source.export(&image).unwrap();

    // The resumed source continues: its device serves the request once
    // notified.
    source.resume().unwrap();
    write(&source, RNG.mmio_addr, 0x50, 0);
    wait("source request not served", || used_idx(&source) == 1);
    drop(source);

    let mut restored = RamSnapshotVm::import(&image, RestoreResources::default()).unwrap();
    assert_eq!(used_idx(&restored), 0, "the cut completed the request");
    assert_eq!(read(&restored, BALLOON.mmio_addr, 0x08), TYPE_BALLOON);
    assert_eq!(read(&restored, BALLOON.mmio_addr, 0x70), 0);
    restored.resume().unwrap();
    wait("restored request not served", || used_idx(&restored) == 1);
    let counter: u16 = restored.memory.read_obj(GuestAddress(COUNTER)).unwrap();
    wait("restored CPU stopped", || {
        restored
            .memory
            .read_obj::<u16>(GuestAddress(COUNTER))
            .unwrap()
            != counter
    });
    drop(restored);
    fs::remove_dir_all(&dir).unwrap();
}
