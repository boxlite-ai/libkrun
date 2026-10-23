use std::io;
use std::sync::{Arc, Mutex};

use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::persist::TxProgress;
use crate::virtio::console::port_io::PortOutput;
use crate::virtio::console::worker::{signal_owed, WorkerControl, WorkerCut};
use crate::virtio::persist::QueueState;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

enum TxStep {
    /// A chain was completed; look for the next one.
    Progress,
    WaitQueue,
    WaitOutput,
}

/// Bytes written per step before the worker checks its controls again.
const TX_STEP_BYTES: u32 = 64 * 1024;

/// How far writing one chain got.
enum Written {
    Done,
    /// The step's byte budget ran out; the chain continues next step.
    Budget,
    WouldBlock,
    BrokenPipe,
    Failed,
}

/// Move the port's transmit queue to the output. The host accepting bytes
/// is the delivery boundary: a chain the output only partly accepted stays
/// popped as `in_flight` with its delivered offset, across waits and
/// freezes, and only its remainder is written later. Once stopped the
/// worker still writes what the output accepts right away, at most one
/// queue's worth of chains, but never waits.
pub(crate) fn process_tx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    mut worker: WorkerControl,
    mut in_flight: Option<TxProgress>,
) {
    let mut used_owed = false;
    let mut broken = false;
    let mut stop_budget = None;
    loop {
        worker.drain_wake();
        worker.handle_commands(
            || signal_owed(&interrupt, &mut used_owed),
            || WorkerCut {
                queue: QueueState::from_queue(&queue),
                eof: false,
                tx_in_flight: in_flight,
            },
        );
        if worker.stopped() {
            let budget = stop_budget.get_or_insert(queue.actual_size());
            if worker.frozen || *budget == 0 {
                let _ = signal_owed(&interrupt, &mut used_owed);
                return;
            }
            *budget -= 1;
        }
        let step = if worker.frozen {
            TxStep::WaitQueue
        } else {
            let mut output = output.lock().unwrap();
            tx_step(
                &mut queue,
                &mem,
                output.as_mut(),
                &mut in_flight,
                &mut broken,
                &mut used_owed,
            )
        };
        worker.finish_resumes();
        if matches!(step, TxStep::Progress) {
            continue;
        }
        if let Err(e) = signal_owed(&interrupt, &mut used_owed) {
            error!("{e}");
        }
        if worker.stopped() {
            return;
        }
        match step {
            TxStep::WaitOutput => output
                .lock()
                .unwrap()
                .wait_until_writable(Some(worker.wake_fd())),
            _ => worker.wait(),
        }
    }
}

/// Continue the in-flight chain or start the next one.
fn tx_step(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    output: &mut (dyn PortOutput + Send),
    in_flight: &mut Option<TxProgress>,
    broken: &mut bool,
    used_owed: &mut bool,
) -> TxStep {
    let progress = match in_flight.take() {
        Some(progress) => progress,
        None => match queue.pop(mem) {
            Some(head) => TxProgress {
                head: head.index,
                delivered: 0,
            },
            None => return TxStep::WaitQueue,
        },
    };
    let mut delivered = progress.delivered;
    let written = match DescriptorChain::checked_new(
        mem,
        queue.desc_table,
        queue.actual_size(),
        progress.head,
    ) {
        // Output after a broken pipe is dropped.
        Some(_) if *broken => Written::Done,
        Some(head) => write_chain(head, output, &mut delivered),
        None => Written::Failed,
    };
    match written {
        Written::WouldBlock => {
            log::trace!("Tx wait for output (would block)");
            *in_flight = Some(TxProgress {
                head: progress.head,
                delivered,
            });
            return TxStep::WaitOutput;
        }
        Written::Budget => {
            *in_flight = Some(TxProgress {
                head: progress.head,
                delivered,
            });
            return TxStep::Progress;
        }
        Written::BrokenPipe => *broken = true,
        Written::Done | Written::Failed => {}
    }
    log::trace!("Tx add used {delivered}");
    if let Err(e) = queue.add_used(mem, progress.head, delivered) {
        error!("failed to add used elements to the queue: {e:?}");
    }
    *used_owed = true;
    TxStep::Progress
}

/// Write the readable part of a chain from byte `delivered` on, at most
/// `TX_STEP_BYTES`, advancing `delivered` by exactly what the output
/// accepted.
fn write_chain(
    head: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    delivered: &mut u32,
) -> Written {
    let mut skip = *delivered;
    let mut budget = TX_STEP_BYTES;
    for desc in head.into_iter().readable() {
        if skip >= desc.len {
            skip -= desc.len;
            continue;
        }
        let remaining = desc.len - skip;
        let len = remaining.min(budget);
        let Some(addr) = desc.addr.checked_add(u64::from(skip)) else {
            return Written::Failed;
        };
        skip = 0;
        let (n, end) = write_some(desc.mem, addr, len, output);
        *delivered += n as u32;
        budget -= n as u32;
        match end {
            Some(end) => return end,
            None if n != len as usize => {
                log::error!("Failed to write output: short write");
                return Written::Failed;
            }
            None if len < remaining => return Written::Budget,
            None => {}
        }
    }
    Written::Done
}

/// Write `len` guest bytes at `addr`; returns how many the output accepted
/// (also when it stopped early) and why it stopped early.
fn write_some(
    mem: &GuestMemoryMmap,
    addr: GuestAddress,
    len: u32,
    output: &mut (dyn PortOutput + Send),
) -> (usize, Option<Written>) {
    let mut end = None;
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    let written = mem.try_access(len as usize, addr, |_, len, addr, region| {
        let src = region.get_slice(addr, len)?;
        log::trace!("Tx {src:?}, write_volatile {len} bytes");
        // try_access calls again with the offset after a partial write.
        match output.write_volatile(&src) {
            Ok(n) => Ok(n),
            // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                end = Some(Written::WouldBlock);
                Ok(0)
            }
            Err(e) => {
                log::error!("Failed to write output: {e}");
                // Errors could conceivably be spurious. Broken pipe is
                // not and there is no point in attempting to write more.
                end = Some(if e.kind() == io::ErrorKind::BrokenPipe {
                    Written::BrokenPipe
                } else {
                    Written::Failed
                });
                Ok(0)
            }
        }
    });
    match written {
        Ok(n) => (n, end),
        Err(e) => {
            log::error!("Failed to write output: {e}");
            (0, Some(Written::Failed))
        }
    }
}
