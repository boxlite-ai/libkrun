// SPDX-License-Identifier: Apache-2.0

//! Stage-4 NIC metadata and ring validation tests; none needs KVM. Every
//! test name contains "snapshot" for `make snapshot-test`.

use super::*;
use devices::virtio::persist::QueueState;
use vm_memory::{Bytes, GuestAddress};

// virtio feature bits (virtio spec numbers; vmm does not link the bindings).
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_RING_F_EVENT_IDX: u32 = 29;
const MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
const FEATURES: u32 = (1 << 0) | (1 << 1);
const RAM_LEN: u64 = 0x10_0000;
/// Ring layout of queue `q` in the test RAM.
const fn ring(q: u64) -> (u64, u64, u64) {
    (
        0x1_0000 + q * 0x1_0000,
        0x1_8000 + q * 0x1_0000,
        0x1_c000 + q * 0x1_0000,
    )
}

fn memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_LEN as usize)]).unwrap()
}

fn regions() -> Vec<Region> {
    vec![Region {
        gpa: 0,
        len: RAM_LEN,
        attributes: 0,
    }]
}

fn queue(q: u64, next: u16) -> QueueState {
    let (desc, avail, used) = ring(q);
    QueueState {
        max_size: QUEUE_SIZE,
        size: 256,
        ready: true,
        desc_table: desc,
        avail_ring: avail,
        used_ring: used,
        next_avail: next,
        next_used: next,
        event_idx_enabled: true,
        num_added: 0,
    }
}

/// Write ring indexes matching `queue`, with `pending` available entries
/// whose heads are `head`.
fn publish(mem: &GuestMemoryMmap, state: &QueueState, pending: u16, head: u16) {
    for i in 0..pending {
        let slot = u64::from(state.next_avail.wrapping_add(i) % state.size);
        mem.write_obj(head, GuestAddress(state.avail_ring + 4 + 2 * slot))
            .unwrap();
    }
    mem.write_obj(
        state.next_avail.wrapping_add(pending),
        GuestAddress(state.avail_ring + 2),
    )
    .unwrap();
    mem.write_obj(state.next_used, GuestAddress(state.used_ring + 2))
        .unwrap();
}

fn config() -> Vec<u8> {
    let mut bytes = MAC.to_vec();
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

fn meta() -> NicMeta {
    let acked = (1u64 << VIRTIO_F_VERSION_1)
        | (1u64 << VIRTIO_NET_F_MAC)
        | (1u64 << VIRTIO_RING_F_EVENT_IDX);
    NicMeta {
        mmio_addr: NIC_MMIO_ADDR,
        mmio_len: blk::MMIO_LEN,
        irq: NIC_IRQ,
        device_id: "net0".to_string(),
        transport: MmioTransportState {
            features_select: 0,
            acked_features_select: 1,
            queue_select: 1,
            shm_region_select: 0,
            device_status: 0b1111,
            config_generation: 0,
            interrupt_status: 0b01,
        },
        device: VirtioDeviceState {
            device_type: TYPE_NET,
            avail_features: offered_features(FEATURES),
            acked_features: acked,
            // Wrapped cursors on RX: u16 sequence space, not ring slots.
            queues: vec![queue(0, 0xfffe), queue(1, 7)],
            activated: true,
        },
        mac: MAC,
        features: FEATURES,
        config: config(),
    }
}

fn disk_irqs(irqs: &[u32]) -> Vec<DiskMeta> {
    // Only the slot fields matter to the NIC checks; serde builds the rest
    // from a minimal valid-looking JSON document.
    irqs.iter()
        .map(|irq| {
            let base = serde_json::json!({
                "mmio_addr": blk::MMIO_BASE, "mmio_len": blk::MMIO_LEN, "irq": irq,
                "device_id": "blk", "config": [], "image_id": [], "read_only": false,
                "cache_writeback": false, "disk_bytes": 512,
                "transport": serde_json::to_value(&meta().transport).unwrap(),
                "device": serde_json::to_value(&meta().device).unwrap(),
            });
            serde_json::from_value(base).unwrap()
        })
        .collect()
}

#[test]
fn snapshot_nic_metadata_accepts_contract_and_rejects_each_violation() {
    let regions = regions();
    validate_nic_metadata(&meta(), &[], &regions).unwrap();
    validate_nic_metadata(&meta(), &disk_irqs(&[16, 17, 18, 19, 20, 21, 22]), &regions).unwrap();

    let reject = |mutate: &dyn Fn(&mut NicMeta), disks: &[DiskMeta], why: &str| {
        let mut bad = meta();
        mutate(&mut bad);
        assert!(
            validate_nic_metadata(&bad, disks, &regions).is_err(),
            "accepted {why}"
        );
    };
    let none: &[DiskMeta] = &[];
    reject(
        &|_| {},
        &disk_irqs(&[16, 17, 18, 19, 20, 21, 22, 16]),
        "eight disks",
    );
    reject(&|_| {}, &disk_irqs(&[NIC_IRQ]), "a disk on the NIC GSI");
    reject(
        &|m| m.mmio_addr = blk::MMIO_BASE,
        none,
        "a disk slot address",
    );
    reject(&|m| m.mmio_len = 0x2000, none, "a larger window");
    reject(&|m| m.irq = 22, none, "another GSI");
    reject(&|m| m.device_id.clear(), none, "an empty identity");
    reject(&|m| m.device_id = "n".repeat(129), none, "a long identity");
    reject(&|m| m.features |= 1 << 2, none, "an unknown offload bit");
    reject(
        &|m| m.device.avail_features |= 1 << 2,
        none,
        "offered features differing from the attach features",
    );
    reject(
        &|m| m.device.acked_features |= 1 << 3,
        none,
        "acked but not offered",
    );
    reject(&|m| m.config.push(0), none, "a longer config");
    reject(&|m| m.config.truncate(6), none, "a shorter config");
    reject(
        &|m| m.config[6] = 1,
        none,
        "a link status the device never sets",
    );
    reject(&|m| m.mac[5] ^= 1, none, "a config for another MAC");
    reject(
        &|m| m.transport.device_status = 0b0101,
        none,
        "an unreachable status",
    );
    reject(
        &|m| m.transport.interrupt_status = 0b100,
        none,
        "an unknown interrupt bit",
    );
    reject(&|m| m.device.queues.truncate(1), none, "one queue");
    reject(
        &|m| m.device.queues[1].max_size = 256,
        none,
        "a foreign queue size",
    );
    reject(
        &|m| m.device.activated = false,
        none,
        "activation without DRIVER_OK",
    );
    reject(
        &|m| m.device.queues[0].event_idx_enabled = false,
        none,
        "event-idx disagreeing with the features",
    );
    let overlap = vec![Region {
        gpa: 0,
        len: NIC_MMIO_ADDR + 0x1000,
        attributes: 0,
    }];
    assert!(validate_nic_metadata(&meta(), &[], &overlap).is_err());
}

#[test]
fn snapshot_nic_metadata_json_rejects_unknown_and_malformed_fields() {
    let mut value = serde_json::to_value(meta()).unwrap();
    let roundtrip: NicMeta = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(roundtrip.mac, MAC);
    value["backend_path"] = serde_json::json!("/tmp/old.sock");
    assert!(serde_json::from_value::<NicMeta>(value).is_err());
    let mut value = serde_json::to_value(meta()).unwrap();
    value["mac"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<NicMeta>(value).is_err());
}

#[test]
fn snapshot_nic_rings_check_cursors_and_cut_time_tx_heads() {
    let mem = memory();
    let nic = meta();
    // Two RX buffers and three unconsumed TX chains at the cut.
    publish(&mem, &nic.device.queues[0], 2, 3);
    publish(&mem, &nic.device.queues[1], 3, 5);
    validate_nic_rings(&nic, &mem).unwrap();

    // A cut-time TX head outside the descriptor table cannot be completed.
    publish(&mem, &nic.device.queues[1], 3, 256);
    assert!(validate_nic_rings(&nic, &mem).is_err());
    publish(&mem, &nic.device.queues[1], 3, 5);

    // Used index in RAM must equal the saved cursor.
    mem.write_obj(9u16, GuestAddress(nic.device.queues[1].used_ring + 2))
        .unwrap();
    assert!(validate_nic_rings(&nic, &mem).is_err());
    publish(&mem, &nic.device.queues[1], 3, 5);

    // More pending than the queue holds means foreign cursors.
    publish(&mem, &nic.device.queues[0], 257, 0);
    assert!(validate_nic_rings(&nic, &mem).is_err());
    publish(&mem, &nic.device.queues[0], 2, 3);

    // An inactive NIC keeps its partial negotiation; rings are not read.
    let mut inactive = meta();
    inactive.device.activated = false;
    inactive.transport.device_status = 0b1011;
    for queue in &mut inactive.device.queues {
        queue.event_idx_enabled = false;
        queue.desc_table = RAM_LEN * 4;
    }
    validate_nic_metadata(&inactive, &[], &regions()).unwrap();
    validate_nic_rings(&inactive, &mem).unwrap();
}

#[test]
fn snapshot_nic_discard_completes_only_cut_time_tx() {
    // The restore-side discard on the reconstructed TX queue: every chain
    // made available before the cut is used with length 0 exactly once,
    // already-used entries are untouched, and RX is not involved.
    let mem = memory();
    let nic = meta();
    let tx = &nic.device.queues[1];
    mem.write_obj(0xabcd_u64, GuestAddress(tx.used_ring + 4 + 8 * 6))
        .unwrap();
    publish(&mem, tx, 3, 5);
    let mut queue = tx.to_queue();
    assert_eq!(queue.discard_available(&mem).unwrap(), 3);
    let used: u16 = mem.read_obj(GuestAddress(tx.used_ring + 2)).unwrap();
    assert_eq!(used, 10);
    for slot in 7..10u64 {
        let id: u32 = mem
            .read_obj(GuestAddress(tx.used_ring + 4 + 8 * slot))
            .unwrap();
        let len: u32 = mem
            .read_obj(GuestAddress(tx.used_ring + 4 + 8 * slot + 4))
            .unwrap();
        assert_eq!((id, len), (5, 0));
    }
    // The entry before the cut keeps its bytes.
    let before: u64 = mem
        .read_obj(GuestAddress(tx.used_ring + 4 + 8 * 6))
        .unwrap();
    assert_eq!(before, 0xabcd);
    // Nothing is left for a resumed worker to send.
    assert_eq!(queue.discard_available(&mem).unwrap(), 0);
}
