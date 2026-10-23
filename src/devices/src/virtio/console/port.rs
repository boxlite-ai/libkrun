use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::persist::{
    ConsolePortState, FreshPort, SnapshotError, TerminalSize, TxProgress,
};
use crate::virtio::console::port_io::{
    InputKind, OutputState, PortInput, PortOutput, TerminalKind,
};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::console::worker::{WorkerCut, WorkerHandle};
use crate::virtio::persist::QueueState;
use crate::virtio::port_io::PortTerminalProperties;
use crate::virtio::{InterruptTransport, Queue};

pub struct PortDescription {
    pub name: Cow<'static, str>,
    pub input: Option<Box<dyn PortInput + Send>>,
    pub output: Option<Box<dyn PortOutput + Send>>,
    pub terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl PortDescription {
    /// Fail unless every endpoint of this description can be checkpointed;
    /// usable before any device exists.
    pub fn check_snapshot_support(&self, port_id: u32) -> Result<(), SnapshotError> {
        self.snapshot_kinds()
            .map(drop)
            .map_err(|endpoint| SnapshotError::UnsupportedEndpoint { port_id, endpoint })
    }

    /// The snapshot kinds of the endpoints; `Err` names the first custom
    /// one.
    pub(crate) fn snapshot_kinds(&self) -> Result<FreshPort<'_>, &'static str> {
        let input = self.input.as_ref().map(|i| i.snapshot_kind());
        let output = self.output.as_ref().map(|o| o.snapshot_state());
        let terminal = self.terminal.as_ref().map(|t| t.snapshot_kind());
        if matches!(input, Some(None)) {
            return Err("input");
        }
        if matches!(output, Some(None)) {
            return Err("output");
        }
        if matches!(terminal, Some(None)) {
            return Err("terminal");
        }
        Ok(FreshPort {
            name: &self.name,
            input: input.flatten(),
            output: output.flatten(),
            terminal: terminal.flatten(),
        })
    }

    pub fn console(
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
        terminal: Box<dyn PortTerminalProperties>,
    ) -> Self {
        Self {
            name: "".into(),
            input,
            output,
            terminal: Some(terminal),
        }
    }

    pub fn output_pipe(
        name: impl Into<Cow<'static, str>>,
        output: Box<dyn PortOutput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: None,
            output: Some(output),
            terminal: None,
        }
    }

    pub fn input_pipe(
        name: impl Into<Cow<'static, str>>,
        input: Box<dyn PortInput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: Some(input),
            output: None,
            terminal: None,
        }
    }
}

/// One direction of an opened port.
enum PortQueue {
    /// Served by a worker; `cut` is its confirmed freeze report, kept until
    /// the worker resumes so repeated captures need no control.
    Worker {
        handle: WorkerHandle,
        cut: Option<WorkerCut>,
    },
    /// No endpoint for this direction: the queue stays with the port and is
    /// never touched.
    Idle(Queue),
}

impl PortQueue {
    fn notify(&self) {
        if let PortQueue::Worker { handle, .. } = self {
            handle.notify()
        }
    }

    fn freeze(&mut self, port_id: u32, timeout: Duration) -> Result<(), SnapshotError> {
        if let PortQueue::Worker { handle, cut } = self {
            if cut.is_none() {
                let frozen = handle
                    .freeze(timeout)
                    .map_err(|error| SnapshotError::Control { port_id, error })?;
                *cut = Some(frozen);
            }
        }
        Ok(())
    }

    fn resume(&mut self, port_id: u32, timeout: Duration) -> Result<(), SnapshotError> {
        if let PortQueue::Worker { handle, cut } = self {
            handle
                .resume(timeout)
                .map_err(|error| SnapshotError::Control { port_id, error })?;
            *cut = None;
        }
        Ok(())
    }

    /// The frozen cut, or `None` for an idle queue.
    fn cut(&self) -> Result<Option<&WorkerCut>, SnapshotError> {
        match self {
            PortQueue::Worker { cut: Some(cut), .. } => Ok(Some(cut)),
            PortQueue::Worker { cut: None, .. } => {
                Err(SnapshotError::State("a port worker is not frozen"))
            }
            PortQueue::Idle(_) => Ok(None),
        }
    }

    fn queue_state(&self) -> Result<QueueState, SnapshotError> {
        match self {
            PortQueue::Idle(queue) => Ok(QueueState::from_queue(queue)),
            worker => Ok(worker.cut()?.expect("workers have cuts").queue.clone()),
        }
    }
}

enum PortState {
    Inactive,
    Active { rx: PortQueue, tx: PortQueue },
}

/// What the guest told the device about a port, and the size last sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortHandshake {
    /// VIRTIO_CONSOLE_PORT_READY succeeded.
    pub ready: bool,
    /// The last VIRTIO_CONSOLE_PORT_OPEN value from the guest.
    pub guest_open: bool,
    /// The size of the last VIRTIO_CONSOLE_RESIZE queued.
    pub size: Option<TerminalSize>,
}

/// Worker progress a started port resumes from: none for a guest open, the
/// saved progress for a restore.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PortProgress {
    pub eof: bool,
    pub tx_in_flight: Option<TxProgress>,
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    state: PortState,
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
    terminal: Option<Box<dyn PortTerminalProperties>>,
    /// Snapshot kinds read at construction: the RX worker holds the input
    /// lock while it runs.
    input_kind: Option<InputKind>,
    terminal_kind: Option<TerminalKind>,
    /// The first endpoint without snapshot support, if any.
    unsupported: Option<&'static str>,
    pub(crate) handshake: PortHandshake,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        let (input_kind, terminal_kind, unsupported) = match description.snapshot_kinds() {
            Ok(fresh) => (fresh.input, fresh.terminal, None),
            Err(endpoint) => (None, None, Some(endpoint)),
        };
        Self {
            port_id,
            name: description.name,
            state: PortState::Inactive,
            input: description.input.map(|input| Arc::new(Mutex::new(input))),
            output: description
                .output
                .map(|output| Arc::new(Mutex::new(output))),
            terminal: description.terminal,
            input_kind,
            terminal_kind,
            unsupported,
            handshake: PortHandshake::default(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn terminal(&self) -> Option<&dyn PortTerminalProperties> {
        self.terminal.as_deref()
    }

    pub fn is_started(&self) -> bool {
        matches!(self.state, PortState::Active { .. })
    }

    /// Running workers; each holds one guest memory clone.
    pub fn workers(&self) -> usize {
        match &self.state {
            PortState::Inactive => 0,
            PortState::Active { rx, tx } => [rx, tx]
                .into_iter()
                .filter(|q| matches!(q, PortQueue::Worker { .. }))
                .count(),
        }
    }

    pub fn notify_rx(&self) {
        if let PortState::Active { rx, .. } = &self.state {
            rx.notify()
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active { tx, .. } = &self.state {
            tx.notify()
        }
    }

    /// Move the port's queues to workers (or keep them idle where the port
    /// has no endpoint). `start_frozen` begins suspended from `progress`,
    /// for a restore; the cut is then known without a control.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
        progress: PortProgress,
        start_frozen: bool,
    ) -> std::io::Result<()> {
        self.shutdown();
        let port_id = self.port_id;

        let frozen_cut = |queue: &Queue, eof, tx_in_flight| {
            start_frozen.then(|| WorkerCut {
                queue: QueueState::from_queue(queue),
                eof,
                tx_in_flight,
            })
        };
        let rx = match self.input.clone() {
            Some(input) => {
                let cut = frozen_cut(&rx_queue, progress.eof, None);
                let (mem, interrupt) = (mem.clone(), interrupt.clone());
                let handle = WorkerHandle::spawn("console port", start_frozen, move |worker| {
                    process_rx(
                        mem,
                        rx_queue,
                        interrupt,
                        input,
                        control,
                        port_id,
                        worker,
                        progress.eof,
                    )
                })?;
                PortQueue::Worker { handle, cut }
            }
            None => PortQueue::Idle(rx_queue),
        };
        let tx = match self.output.clone() {
            Some(output) => {
                let cut = frozen_cut(&tx_queue, false, progress.tx_in_flight);
                let handle = WorkerHandle::spawn("console port tx", start_frozen, move |worker| {
                    process_tx(
                        mem,
                        tx_queue,
                        interrupt,
                        output,
                        worker,
                        progress.tx_in_flight,
                    )
                })?;
                PortQueue::Worker { handle, cut }
            }
            None => PortQueue::Idle(tx_queue),
        };
        self.state = PortState::Active { rx, tx };
        Ok(())
    }

    /// Fail unless every endpoint of this port can be checkpointed.
    pub fn check_snapshot_support(&self) -> Result<(), SnapshotError> {
        match self.unsupported {
            Some(endpoint) => Err(SnapshotError::UnsupportedEndpoint {
                port_id: self.port_id,
                endpoint,
            }),
            None => Ok(()),
        }
    }

    pub fn freeze(&mut self, timeout: Duration) -> Result<(), SnapshotError> {
        if let PortState::Active { rx, tx } = &mut self.state {
            rx.freeze(self.port_id, timeout)?;
            tx.freeze(self.port_id, timeout)?;
        }
        Ok(())
    }

    pub fn resume(&mut self, timeout: Duration) -> Result<(), SnapshotError> {
        if let PortState::Active { rx, tx } = &mut self.state {
            rx.resume(self.port_id, timeout)?;
            tx.resume(self.port_id, timeout)?;
        }
        Ok(())
    }

    /// The port's saved state; started ports must be frozen. Pure: only
    /// the frozen cuts and the idle output are read.
    pub fn snapshot(&self) -> Result<ConsolePortState, SnapshotError> {
        self.check_snapshot_support()?;
        let (started, eof, tx_in_flight) = match &self.state {
            PortState::Inactive => (false, false, None),
            PortState::Active { rx, tx } => (
                true,
                rx.cut()?.is_some_and(|cut| cut.eof),
                tx.cut()?.and_then(|cut| cut.tx_in_flight),
            ),
        };
        Ok(ConsolePortState {
            port_id: self.port_id,
            name: self.name.to_string(),
            input: self.input_kind,
            output: self.output_state(),
            terminal: self.terminal_kind,
            ready: self.handshake.ready,
            guest_open: self.handshake.guest_open,
            size: self.handshake.size,
            started,
            eof,
            tx_in_flight,
        })
    }

    /// RX and TX queue states of a started, frozen port.
    pub fn queue_states(&self) -> Result<Option<[QueueState; 2]>, SnapshotError> {
        match &self.state {
            PortState::Inactive => Ok(None),
            PortState::Active { rx, tx } => Ok(Some([rx.queue_state()?, tx.queue_state()?])),
        }
    }

    /// The endpoint kinds a restore compares against the saved port.
    pub(crate) fn fresh(&self) -> FreshPort<'_> {
        FreshPort {
            name: &self.name,
            input: self.input_kind,
            output: self.output_state(),
            terminal: self.terminal_kind,
        }
    }

    /// Adopt the saved output state (the log's partial line) into this
    /// port's fresh output; the restore validated the kinds beforehand.
    pub fn restore_output(&mut self, state: Option<&OutputState>) -> bool {
        match (&self.output, state) {
            (Some(output), Some(state)) => output.lock().unwrap().restore_state(state),
            (None, None) => true,
            _ => false,
        }
    }

    fn output_state(&self) -> Option<OutputState> {
        self.output
            .as_ref()
            .and_then(|output| output.lock().unwrap().snapshot_state())
    }

    /// Stop and join the workers, frozen or not; bounded under output
    /// backpressure because a stopped worker never waits.
    pub fn shutdown(&mut self) {
        if let PortState::Active { rx, tx } =
            std::mem::replace(&mut self.state, PortState::Inactive)
        {
            for queue in [tx, rx] {
                if let PortQueue::Worker { mut handle, .. } = queue {
                    handle.stop();
                }
            }
        }
    }
}
