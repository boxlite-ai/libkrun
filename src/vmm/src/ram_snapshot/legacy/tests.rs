// SPDX-License-Identifier: Apache-2.0

//! Legacy metadata validation without KVM. Test names contain "snapshot"
//! for `make snapshot-test`.

use super::*;

const MIB: u64 = 1 << 20;

fn regions(ranges: &[(u64, u64)]) -> Vec<Region> {
    ranges
        .iter()
        .map(|&(gpa, len)| Region {
            gpa,
            len,
            attributes: 0,
        })
        .collect()
}

/// Device states as the production devices report them for a guest with
/// the given RAM split.
fn meta(below: u64, above: u64) -> LegacyMeta {
    let evt = || EventFd::new(EFD_NONBLOCK).unwrap();
    LegacyMeta {
        serial: (0..4)
            .map(|_| Serial::new_sink(evt()).snapshot_state())
            .collect(),
        cmos: Cmos::new(below, above).snapshot_state(),
        i8042: I8042Device::new(evt(), evt()).snapshot_state(),
    }
}

#[test]
fn snapshot_legacy_metadata_checks_shape_and_cmos_capacity() {
    let layout = regions(&[(0, 3072 * MIB), (FOUR_GIB, 1024 * MIB)]);
    assert_eq!(
        ram_split(layout.iter().map(|r| (r.gpa, r.len))),
        (3072 * MIB, 1024 * MIB)
    );
    validate_metadata(&meta(3072 * MIB, 1024 * MIB), &layout).unwrap();

    let other_layout = regions(&[(0, 2048 * MIB)]);
    let error = validate_metadata(&meta(3072 * MIB, 1024 * MIB), &other_layout).unwrap_err();
    assert!(error.to_string().contains("capacity"), "{error}");

    let mut three_ports = meta(3072 * MIB, 1024 * MIB);
    three_ports.serial.pop();
    assert!(validate_metadata(&three_ports, &layout).is_err());
}

#[test]
fn snapshot_legacy_endpoints_must_be_nonblocking() {
    let (blocking, _peer) = UnixStream::pair().unwrap();
    let (nonblocking, _other) = UnixStream::pair().unwrap();
    nonblocking.set_nonblocking(true).unwrap();
    check_endpoints(&[Some(nonblocking), None, None, None]).unwrap();
    let error = check_endpoints(&[None, None, Some(blocking), None]).unwrap_err();
    assert!(error.to_string().contains("COM3"), "{error}");
}
