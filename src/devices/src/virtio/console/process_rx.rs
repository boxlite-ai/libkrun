use std::io;
use std::sync::{Arc, Mutex};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::console::worker::{signal_owed, WorkerControl, WorkerCut};
use crate::virtio::persist::QueueState;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

/// Bytes one chain takes before the worker checks its controls again, so
/// continuously readable input cannot delay a freeze or stop.
const RX_CHAIN_BYTES: u32 = 64 * 1024;

enum RxStep {
    /// A chain was filled and used; look for the next one.
    Progress,
    WaitQueue,
    WaitInput,
    Eof,
}

/// Move input into the port's receive queue. A chain is never held across
/// a wait or a control: bytes already read are committed (used) and an
/// unfilled chain goes back to the avail ring, so a freeze always lands at
/// a chain boundary. After EOF the worker only answers controls.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    input: Arc<Mutex<Box<dyn PortInput + Send>>>,
    control: Arc<ConsoleControl>,
    port_id: u32,
    mut worker: WorkerControl,
    mut eof: bool,
) {
    let mem = &mem;
    let mut used_owed = false;

    let mut input = input.lock().unwrap();
    loop {
        worker.drain_wake();
        worker.handle_commands(
            || signal_owed(&interrupt, &mut used_owed),
            || WorkerCut {
                queue: QueueState::from_queue(&queue),
                eof,
                tx_in_flight: None,
            },
        );
        if worker.stopped() {
            let _ = signal_owed(&interrupt, &mut used_owed);
            return;
        }
        let step = if worker.frozen || eof {
            RxStep::WaitQueue
        } else {
            rx_step(&mut queue, mem, input.as_mut(), &mut used_owed)
        };
        worker.finish_resumes();
        if !matches!(step, RxStep::Progress) {
            // A frozen worker owes nothing: its freeze raised it.
            if let Err(e) = signal_owed(&interrupt, &mut used_owed) {
                error!("{e}");
            }
        }
        match step {
            RxStep::Progress => {}
            RxStep::Eof => {
                log::trace!("signaling EOF on port {port_id}");
                control.port_open(port_id, false);
                eof = true;
            }
            RxStep::WaitQueue => worker.wait(),
            RxStep::WaitInput => input.wait_until_readable(Some(worker.wake_fd())),
        }
    }
}

/// Fill one chain with what the input has now.
fn rx_step(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    input: &mut (dyn PortInput + Send),
    used_owed: &mut bool,
) -> RxStep {
    let Some(head) = queue.pop(mem) else {
        return RxStep::WaitQueue;
    };
    let head_index = head.index;
    let mut bytes_read = 0;
    let mut eof = false;
    for chain in head.into_iter().writable() {
        let len = chain.len.min(RX_CHAIN_BYTES - bytes_read as u32);
        match read_to_desc(chain, len, input, &mut eof) {
            Ok(0) => {
                break;
            }
            Ok(len) => {
                bytes_read += len;
                if bytes_read as u32 == RX_CHAIN_BYTES {
                    break;
                }
            }
            Err(e) => {
                log::error!("Failed to read: {e:?}")
            }
        }
    }

    if bytes_read == 0 {
        // Nothing reached the chain: the guest keeps it.
        queue.undo_pop();
    } else {
        log::trace!("Rx {bytes_read} bytes queue len{}", queue.len(mem));
        if let Err(e) = queue.add_used(mem, head_index, bytes_read as u32) {
            error!("failed to add used elements to the queue: {e:?}");
        }
        *used_owed = true;
    }
    if eof {
        RxStep::Eof
    } else if bytes_read == 0 {
        RxStep::WaitInput
    } else {
        RxStep::Progress
    }
}

/// Read into one descriptor, at most `len` bytes. Bytes read before an
/// input failure are reported, so the chain commits them.
fn read_to_desc(
    desc: DescriptorChain,
    len: u32,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    let mut failure = None;
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    let read = desc
        .mem
        .try_access(len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len)?;
            match input.read_volatile(&mut target) {
                Ok(0) => {
                    *eof = true;
                    Ok(0)
                }
                Ok(n) => Ok(n),
                // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => {
                    failure = Some(e);
                    Ok(0)
                }
            }
        })?;
    match failure {
        Some(e) if read == 0 => Err(GuestMemoryError::IOError(e)),
        Some(e) => {
            log::error!("Failed to read: {e:?}");
            Ok(read)
        }
        None => Ok(read),
    }
}
