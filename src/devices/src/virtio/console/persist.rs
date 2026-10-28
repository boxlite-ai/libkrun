// SPDX-License-Identifier: Apache-2.0

//! Snapshot state of a virtio-console beyond the common virtio queue,
//! device and transport state (`virtio::persist`). It never holds a host
//! path, descriptor or thread: a restore supplies fresh built-in endpoints
//! of the same kinds, and input still unread in the source's host
//! descriptors is not migrated.

use std::mem::size_of;
use std::num::Wrapping;

use serde::{Deserialize, Serialize};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::console_control::VirtioConsoleControl;
use super::defs::control_event;
use super::device::VirtioConsoleConfig;
use super::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use super::port::PortDescription;
use super::port_io::{InputKind, OutputState, PortOutputLog, TerminalKind};
use super::port_queue_mapping::{
    num_queues, port_id_to_queue_idx, queue_idx_to_port_id, QueueDirection,
};
use crate::virtio::control::WorkerControlError;
use crate::virtio::persist::QueueState;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::Descriptor;

/// A TX chain the output accepted only part of: popped, not used, and
/// resumed after its first `delivered` bytes, which are never written again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxProgress {
    pub head: u16,
    pub delivered: u32,
}

/// A terminal size as the device last reported it to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

/// One port: identity, endpoint kinds, guest handshake and worker progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolePortState {
    pub port_id: u32,
    pub name: String,
    pub input: Option<InputKind>,
    pub output: Option<OutputState>,
    pub terminal: Option<TerminalKind>,
    /// The guest reported VIRTIO_CONSOLE_PORT_READY.
    pub ready: bool,
    /// The last VIRTIO_CONSOLE_PORT_OPEN value from the guest.
    pub guest_open: bool,
    /// The size of the last resize message queued for this port.
    pub size: Option<TerminalSize>,
    /// The guest opened the port and its queues moved to the port.
    pub started: bool,
    /// The input reached its end; the port never reads again.
    pub eof: bool,
    pub tx_in_flight: Option<TxProgress>,
}

/// Console state saved next to the common virtio state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleState {
    /// The complete guest-visible configuration space.
    pub config: Vec<u8>,
    /// The guest reported VIRTIO_CONSOLE_DEVICE_READY.
    pub device_ready: bool,
    pub ports: Vec<ConsolePortState>,
    /// Control messages the guest has not received yet, in order.
    pub pending_control: Vec<Vec<u8>>,
}

/// Why a console snapshot control, capture or restore failed.
#[derive(Debug)]
pub enum SnapshotError {
    /// A custom endpoint cannot be checkpointed.
    UnsupportedEndpoint {
        port_id: u32,
        endpoint: &'static str,
    },
    /// A port worker did not confirm a control; the owner must disable the
    /// device rather than trust its state.
    Control {
        port_id: u32,
        error: WorkerControlError,
    },
    /// Raising an owed interrupt failed.
    Interrupt(String),
    /// The device is not in the state the operation needs.
    State(&'static str),
    /// The saved state does not fit this device or guest RAM.
    Invalid(&'static str),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::UnsupportedEndpoint { port_id, endpoint } => write!(
                f,
                "console port {port_id}: the {endpoint} endpoint has no snapshot support"
            ),
            SnapshotError::Control { port_id, error } => {
                write!(f, "console port {port_id}: {error}")
            }
            SnapshotError::Interrupt(why) => write!(f, "console: {why}"),
            SnapshotError::State(why) => write!(f, "console: {why}"),
            SnapshotError::Invalid(why) => write!(f, "console snapshot: {why}"),
        }
    }
}

/// The endpoint kinds of a fresh port, checked against a saved port.
pub(crate) struct FreshPort<'a> {
    pub name: &'a str,
    pub input: Option<InputKind>,
    pub output: Option<OutputState>,
    pub terminal: Option<TerminalKind>,
}

impl ConsoleState {
    /// Structural check, before any endpoint, device or guest RAM exists:
    /// config, port ids, handshake and progress consistency, log lines and
    /// pending messages. `activated` is the saved device activation.
    pub fn validate_structure(&self, activated: bool) -> Result<(), SnapshotError> {
        let invalid = |why| Err(SnapshotError::Invalid(why));
        if self.config.len() != size_of::<VirtioConsoleConfig>() {
            return invalid("the config space has an unsupported length");
        }
        let mut config = VirtioConsoleConfig::default();
        config.as_mut_slice().copy_from_slice(&self.config);
        if self.ports.is_empty() || !config.is_consistent(self.ports.len()) {
            return invalid("the config space disagrees with the ports");
        }
        if self.device_ready && !activated {
            return invalid("an inactive device holds a guest handshake");
        }
        for (index, port) in self.ports.iter().enumerate() {
            if port.port_id as usize != index {
                return invalid("port ids are not in order");
            }
            if let Some(OutputState::Log { partial_line }) = &port.output {
                if partial_line.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD
                    || partial_line.contains(&b'\n')
                {
                    return invalid("a log port holds more than one partial line");
                }
            }
            if (port.ready || port.guest_open || port.size.is_some()) && !activated {
                return invalid("an inactive device holds a guest handshake");
            }
            if port.size.is_some() && port.terminal.is_none() {
                return invalid("a port without a terminal holds a size");
            }
            if (port.started && !activated)
                || (port.eof && !(port.started && port.input.is_some()))
                || (port.tx_in_flight.is_some() && !(port.started && port.output.is_some()))
            {
                return invalid("port progress is inconsistent with its state");
            }
        }
        for message in &self.pending_control {
            validate_control_message(message, self.ports.len())?;
        }
        Ok(())
    }

    /// `validate_structure` plus a match against the fresh endpoints of the
    /// device a restore targets, before guest RAM exists.
    pub(crate) fn validate_for(
        &self,
        fresh: &[FreshPort],
        activated: bool,
    ) -> Result<(), SnapshotError> {
        self.validate_structure(activated)?;
        if self.ports.len() != fresh.len() {
            return Err(SnapshotError::Invalid("the port count differs"));
        }
        for (saved, fresh) in self.ports.iter().zip(fresh) {
            let same_output = matches!(
                (&saved.output, &fresh.output),
                (None, None)
                    | (Some(OutputState::Fd), Some(OutputState::Fd))
                    | (Some(OutputState::Log { .. }), Some(OutputState::Log { .. }))
            );
            if saved.name != fresh.name
                || saved.input != fresh.input
                || !same_output
                || saved.terminal != fresh.terminal
            {
                return Err(SnapshotError::Invalid(
                    "a port name or endpoint kind differs from the fresh port",
                ));
            }
        }
        Ok(())
    }

    /// `validate_for` against the descriptions a restore will build its
    /// endpoints from, before any device exists.
    pub fn validate_descriptions(
        &self,
        ports: &[PortDescription],
        activated: bool,
    ) -> Result<(), SnapshotError> {
        let fresh = ports
            .iter()
            .zip(0u32..)
            .map(|(port, port_id)| {
                port.snapshot_kinds()
                    .map_err(|endpoint| SnapshotError::UnsupportedEndpoint { port_id, endpoint })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.validate_for(&fresh, activated)
    }

    /// Check against loaded guest RAM and the validated queue states, before
    /// any worker exists: every chain available in a ready queue of an
    /// activated device is a strict chain in its queue's direction (see
    /// `chain_len`), every worker of a started port has a ready queue, only
    /// a queue with an in-flight TX chain has a popped chain not yet used
    /// (exactly one), and every in-flight TX chain is the last chain its
    /// queue popped, strict as well, with bytes left to deliver. Queues of
    /// an inactive device may be partially negotiated (ready before
    /// DRIVER_OK) and are never walked.
    pub fn validate_guest(
        &self,
        mem: &GuestMemoryMmap,
        queues: &[QueueState],
        activated: bool,
    ) -> Result<(), SnapshotError> {
        let invalid = |why| Err(SnapshotError::Invalid(why));
        if queues.len() != num_queues(self.ports.len()) {
            return invalid("the queue count differs");
        }
        if !activated {
            // validate_structure leaves no in-flight chain to check.
            return Ok(());
        }
        // At a freeze no worker or control callback holds a popped chain,
        // except a TX worker's partly delivered one: popped and not used.
        for (index, queue) in queues.iter().enumerate() {
            let control = index == CONTROL_RXQ_INDEX || index == CONTROL_TXQ_INDEX;
            let in_flight = !control && {
                let (direction, port_id) = queue_idx_to_port_id(index);
                direction == QueueDirection::Tx && self.ports[port_id].tx_in_flight.is_some()
            };
            let outstanding = (Wrapping(queue.next_avail) - Wrapping(queue.next_used)).0;
            if outstanding != u16::from(in_flight) {
                return invalid("a queue's popped chains disagree with the in-flight state");
            }
        }
        for (index, queue) in queues.iter().enumerate() {
            if !queue.ready || queue.size == 0 {
                continue;
            }
            // Even queues (port and control receiveq) are device-writable.
            let device_writable = index % 2 == 0;
            let avail_idx: u16 = read(mem, queue.avail_ring + 2)?;
            let pending = (Wrapping(avail_idx) - Wrapping(queue.next_avail)).0;
            if pending > queue.size {
                return invalid("more chains are available than the queue holds");
            }
            for offset in 0..pending {
                let slot = queue.next_avail.wrapping_add(offset) % queue.size;
                let head = read(mem, queue.avail_ring + 4 + 2 * u64::from(slot))?;
                chain_len(mem, queue, head, device_writable)?;
            }
        }
        for (port_id, port) in self.ports.iter().enumerate() {
            // A started port's workers use the queue of every direction it
            // has an endpoint for.
            let ready = |direction| {
                let queue = &queues[port_id_to_queue_idx(direction, port_id)];
                queue.ready && queue.size != 0
            };
            if port.started
                && ((port.input.is_some() && !ready(QueueDirection::Rx))
                    || (port.output.is_some() && !ready(QueueDirection::Tx)))
            {
                return invalid("a started port has a worker on an unready queue");
            }
            let Some(progress) = port.tx_in_flight else {
                continue;
            };
            let queue = &queues[port_id_to_queue_idx(QueueDirection::Tx, port_id)];
            if !queue.ready || queue.size == 0 {
                return invalid("an in-flight TX chain is outside its queue");
            }
            let slot = (Wrapping(queue.next_avail) - Wrapping(1)).0 % queue.size;
            let popped: u16 = read(mem, queue.avail_ring + 4 + 2 * u64::from(slot))?;
            if popped != progress.head {
                return invalid("an in-flight TX chain is not the last chain popped");
            }
            if u64::from(progress.delivered) >= chain_len(mem, queue, progress.head, false)? {
                return invalid("an in-flight TX chain has nothing left to deliver");
            }
        }
        Ok(())
    }
}

fn read<T: ByteValued>(mem: &GuestMemoryMmap, addr: u64) -> Result<T, SnapshotError> {
    mem.read_obj(GuestAddress(addr))
        .map_err(|_| SnapshotError::Invalid("a queue ring is outside guest RAM"))
}

/// Walk a chain from `head` over the raw descriptor table and return its
/// byte length. Strict, unlike the device's own iteration, which stops
/// quietly at a bad link: at most one queue's worth of descriptors (no
/// cycle), every link inside the table, only the NEXT and WRITE flags (no
/// INDIRECT), every descriptor in `device_writable` direction and every
/// range inside guest RAM.
fn chain_len(
    mem: &GuestMemoryMmap,
    queue: &QueueState,
    head: u16,
    device_writable: bool,
) -> Result<u64, SnapshotError> {
    let invalid = Err(SnapshotError::Invalid("an available chain is malformed"));
    let mut index = head;
    let mut total = 0u64;
    for _ in 0..queue.size {
        if index >= queue.size {
            return invalid;
        }
        let desc: Descriptor = read(mem, queue.desc_table + 16 * u64::from(index))?;
        let writable = desc.flags & VIRTQ_DESC_F_WRITE != 0;
        if desc.flags & !(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE) != 0
            || writable != device_writable
            || (desc.len > 0 && !mem.check_range(GuestAddress(desc.addr), desc.len as usize))
        {
            return invalid;
        }
        total += u64::from(desc.len);
        if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
            return Ok(total);
        }
        index = desc.next;
    }
    invalid
}

/// A message is one the device itself queues, for an existing port.
fn validate_control_message(message: &[u8], ports: usize) -> Result<(), SnapshotError> {
    let header_len = size_of::<VirtioConsoleControl>();
    let invalid = Err(SnapshotError::Invalid(
        "a pending control message is malformed",
    ));
    if message.len() < header_len {
        return invalid;
    }
    let mut header = VirtioConsoleControl::default();
    header
        .as_mut_slice()
        .copy_from_slice(&message[..header_len]);
    let (id, event, value) = (header.id, header.event, header.value);
    let well_formed = match event {
        control_event::VIRTIO_CONSOLE_PORT_ADD | control_event::VIRTIO_CONSOLE_CONSOLE_PORT => {
            message.len() == header_len
        }
        control_event::VIRTIO_CONSOLE_PORT_OPEN => message.len() == header_len && value <= 1,
        control_event::VIRTIO_CONSOLE_RESIZE => message.len() == header_len + 4,
        control_event::VIRTIO_CONSOLE_PORT_NAME => message.len() > header_len,
        _ => false,
    };
    if !well_formed || id as usize >= ports {
        return invalid;
    }
    Ok(())
}
