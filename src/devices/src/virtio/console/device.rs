use std::cmp;
use std::io::Write;
use std::iter::zip;
use std::mem::{size_of, size_of_val};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::virtio::console::console_control::{
    ConsoleControl, VirtioConsoleControl, VirtioConsoleResize,
};
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::persist::{ConsoleState, FreshPort, SnapshotError, TerminalSize};
use crate::virtio::console::port::{Port, PortHandshake, PortProgress};
use crate::virtio::console::port_queue_mapping::{
    num_queues, port_id_to_queue_idx, QueueDirection,
};
use crate::virtio::control::CONTROL_TIMEOUT;
use crate::virtio::persist::QueueState;
use crate::virtio::{InterruptTransport, PortDescription, VmmExitObserver};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

pub const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64)
    | (1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64)
    | (1 << uapi::VIRTIO_F_VERSION_1 as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16, max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports,
            emerg_wr: 0u32,
        }
    }

    /// The device only ever exposes `max_nr_ports` equal to its port count
    /// and no emergency write.
    pub(crate) fn is_consistent(&self, ports: usize) -> bool {
        let (max_nr_ports, emerg_wr) = (self.max_nr_ports, self.emerg_wr);
        max_nr_ports as usize == ports && emerg_wr == 0
    }
}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,

    queue_config: Vec<QueueConfig>,
    // Queues are stored as Option so individual queues can be taken when ports start.
    pub(crate) queues: Vec<Option<DeviceQueue>>,
    // TODO: move the queue event handling to the correct threads!
    pub(crate) queue_events: Vec<Arc<EventFd>>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

    config: VirtioConsoleConfig,

    /// Snapshot freeze of the control queues, set before the port workers
    /// freeze: queue events are drained but not processed, and no
    /// interrupt is raised, until `snapshot_resume`.
    pub(crate) snapshot_frozen: bool,
    /// A terminal resize arrived while frozen; resume reports it.
    pub(crate) sigwinch_deferred: bool,
    /// Per-port `started` flag and progress from `restore_state`, consumed
    /// by `activate_frozen`.
    restored: Option<Vec<(bool, PortProgress)>>,
    /// The guest sent VIRTIO_CONSOLE_DEVICE_READY.
    device_ready: bool,
}

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> super::Result<Console> {
        assert!(!ports.is_empty(), "Expected at least 1 port");

        let num_queues = num_queues(ports.len());
        let queue_config: Vec<QueueConfig> = (0..num_queues)
            .map(|_| QueueConfig::new(QUEUE_SIZE))
            .collect();

        let ports: Vec<Port> = zip(0u32.., ports)
            .map(|(port_id, description)| Port::new(port_id, description))
            .collect();

        let (cols, rows) = ports[0]
            .terminal()
            .map(|t| t.get_win_size())
            .unwrap_or((0, 0));
        let config = VirtioConsoleConfig::new(cols, rows, ports.len() as u32);

        Ok(Console {
            control: ConsoleControl::new(),
            ports,
            queue_config,
            queues: Vec::new(),
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
            snapshot_frozen: false,
            sigwinch_deferred: false,
            restored: None,
            device_ready: false,
        })
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn update_console_size(&mut self, port_id: u32, cols: u16, rows: u16) {
        log::debug!("update_console_size {port_id}: {cols} {rows}");
        if let Some(port) = self.ports.get_mut(port_id as usize) {
            port.handshake.size = Some(TerminalSize { cols, rows });
        }
        self.control
            .console_resize(port_id, VirtioConsoleResize { rows, cols });
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        log::trace!("process_control_rx");
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };
        let mut raise_irq = false;

        let control_rx = self.queues[CONTROL_RXQ_INDEX]
            .as_mut()
            .expect("control rx queue should exist");
        // A driver may leave the queue unconfigured; it is never used then.
        if !control_rx.queue.ready {
            return false;
        }

        while let Some(buf) = self.control.queue_pop() {
            let Some(head) = control_rx.queue.pop(mem) else {
                self.control.queue_unpop(buf);
                break;
            };
            // A message goes whole into one device-writable buffer; one
            // that cannot take it stays with the guest and the message
            // stays pending.
            let written = if !head.is_write_only() || (head.len as usize) < buf.len() {
                log::error!(
                    "process_control_rx: buffer {} cannot take a message",
                    head.index
                );
                false
            } else if let Err(e) = mem.write_slice(&buf, head.addr) {
                log::error!("process_control_rx failed to write: {e}");
                false
            } else {
                true
            };
            if !written {
                control_rx.queue.undo_pop();
                self.control.queue_unpop(buf);
                break;
            }
            raise_irq = true;
            log::trace!("process_control_rx wrote {}", buf.len());
            if let Err(e) = control_rx.queue.add_used(mem, head.index, buf.len() as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        raise_irq
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        log::trace!("process_control_tx");
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };

        let control_tx = self.queues[CONTROL_TXQ_INDEX]
            .as_mut()
            .expect("control tx queue should exist");
        if !control_tx.queue.ready {
            return false;
        }
        let mut raise_irq = false;

        let mut ports_to_start = Vec::new();

        while let Some(head) = control_tx.queue.pop(mem) {
            raise_irq = true;

            // Only a device-readable buffer holding a whole message is read;
            // any other completes empty and is ignored.
            let cmd = if !head.is_read_only()
                || (head.len as usize) < size_of::<VirtioConsoleControl>()
            {
                log::error!(
                    "control message buffer {} is device-writable or shorter than {} bytes",
                    head.index,
                    size_of::<VirtioConsoleControl>()
                );
                None
            } else {
                match mem.read_obj::<VirtioConsoleControl>(head.addr) {
                    Ok(cmd) => Some(cmd),
                    Err(e) => {
                        log::error!("Failed to read VirtioConsoleControl struct: {e:?}");
                        None
                    }
                }
            };
            let Some(cmd) = cmd else {
                if let Err(e) = control_tx.queue.add_used(mem, head.index, 0) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
                continue;
            };
            if let Err(e) = control_tx
                .queue
                .add_used(mem, head.index, size_of_val(&cmd) as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            log::trace!("VirtioConsoleControl cmd: {cmd:?}");
            let port_event = matches!(
                cmd.event,
                control_event::VIRTIO_CONSOLE_PORT_READY | control_event::VIRTIO_CONSOLE_PORT_OPEN
            );
            if port_event && cmd.id as usize >= self.ports.len() {
                log::warn!(
                    "Console control event {:x} for unknown port {}",
                    cmd.event,
                    cmd.id
                );
                continue;
            }
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    self.device_ready = true;
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );
                    for port_id in 0..self.ports.len() {
                        self.control.port_add(port_id as u32);
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {cmd:?}");
                        continue;
                    }

                    let port = &mut self.ports[cmd.id as usize];
                    port.handshake.ready = true;
                    if let Some((cols, rows)) = port.terminal().map(|t| t.get_win_size()) {
                        self.control.mark_console_port(mem, cmd.id);
                        self.control.port_open(cmd.id, true);
                        port.handshake.size = Some(TerminalSize { cols, rows });
                        self.control
                            .console_resize(cmd.id, VirtioConsoleResize { cols, rows });
                    } else {
                        // We start with all ports open, this makes sense for now,
                        // because underlying file descriptors STDIN, STDOUT, STDERR are always open too
                        self.control.port_open(cmd.id, true)
                    }

                    let name = self.ports[cmd.id as usize].name();
                    log::trace!("Port ready {id}: {name}", id = cmd.id);
                    if !name.is_empty() {
                        self.control.port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let opened = match cmd.value {
                        0 => false,
                        1 => true,
                        _ => {
                            log::error!(
                                "Invalid value ({}) for VIRTIO_CONSOLE_PORT_OPEN on port {}",
                                cmd.value,
                                cmd.id
                            );
                            continue;
                        }
                    };

                    self.ports[cmd.id as usize].handshake.guest_open = opened;
                    if !opened {
                        log::debug!("Guest closed port {}", cmd.id);
                        continue;
                    }

                    // A reopened port keeps its running workers and queues.
                    let port_id = cmd.id as usize;
                    if !self.ports[port_id].is_started() && !ports_to_start.contains(&port_id) {
                        ports_to_start.push(port_id);
                    }
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_start {
            log::trace!("Starting port io for port {port_id}");
            if let Err(e) = self.start_port(port_id, PortProgress::default(), false) {
                error!("Cannot start console port {port_id}: {e:?}");
            }
        }

        raise_irq
    }

    /// Move a port's queues to the port and start its workers.
    fn start_port(
        &mut self,
        port_id: usize,
        progress: PortProgress,
        start_frozen: bool,
    ) -> std::io::Result<()> {
        let DeviceState::Activated(ref mem, ref interrupt) = self.device_state else {
            unreachable!()
        };
        let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
        let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);

        // Take ownership of port queues - they are moved to the port.
        let rx_queue = self.queues[rx_idx]
            .take()
            .expect("port rx queue should exist")
            .queue;
        let tx_queue = self.queues[tx_idx]
            .take()
            .expect("port tx queue should exist")
            .queue;

        self.ports[port_id].start(
            mem.clone(),
            rx_queue,
            tx_queue,
            interrupt.clone(),
            self.control.clone(),
            progress,
            start_frozen,
        )
    }

    /// Report every terminal's current size to the guest.
    pub(crate) fn update_terminal_sizes(&mut self) {
        for i in 0..self.ports.len() {
            if let Some(term) = self.ports[i].terminal() {
                let (cols, rows) = term.get_win_size();
                self.update_console_size(i as u32, cols, rows);
            }
        }
    }
}

/// Snapshot support: freeze, capture, restore and resume. Only built-in
/// endpoints (FD, empty and SIGINT input, FD and log output, FD and fixed
/// terminals) can be checkpointed.
impl Console {
    /// Guest memory clones the device holds: one while activated, plus one
    /// per running port worker.
    pub fn memory_clones(&self) -> usize {
        usize::from(self.is_activated()) + self.ports.iter().map(Port::workers).sum::<usize>()
    }

    /// Snapshot attach validation: fails for a custom endpoint.
    pub fn check_snapshot_support(&self) -> Result<(), SnapshotError> {
        self.ports.iter().try_for_each(Port::check_snapshot_support)
    }

    /// Freeze the control queues, then every port worker. Idempotent; an
    /// error leaves the device frozen as far as it got, and the owner must
    /// disable it rather than resume.
    pub fn snapshot_freeze(&mut self) -> Result<(), SnapshotError> {
        self.snapshot_freeze_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn snapshot_freeze_with_timeout(&mut self, timeout: Duration) -> Result<(), SnapshotError> {
        self.check_snapshot_support()?;
        self.snapshot_frozen = true;
        for port in &mut self.ports {
            port.freeze(timeout)?;
        }
        Ok(())
    }

    /// Resume every port worker (each re-examines its queue and endpoint
    /// without a kick), then process the control queues and a deferred
    /// resize, raising their interrupt.
    pub fn snapshot_resume(&mut self) -> Result<(), SnapshotError> {
        self.snapshot_resume_with_timeout(CONTROL_TIMEOUT)
    }

    pub fn snapshot_resume_with_timeout(&mut self, timeout: Duration) -> Result<(), SnapshotError> {
        for port in &mut self.ports {
            port.resume(timeout)?;
        }
        self.snapshot_frozen = false;
        if !self.is_activated() {
            return Ok(());
        }
        let mut raise_irq = self.process_control_tx();
        if std::mem::take(&mut self.sigwinch_deferred) {
            self.update_terminal_sizes();
        }
        raise_irq |= self.process_control_rx();
        if raise_irq {
            let DeviceState::Activated(_, interrupt) = &self.device_state else {
                unreachable!()
            };
            interrupt
                .try_signal_used_queue()
                .map_err(|e| SnapshotError::Interrupt(format!("{e:?}")))?;
        }
        Ok(())
    }

    /// The console state of a frozen device. Pure: repeated captures of one
    /// freeze are identical and consume nothing.
    pub fn snapshot_state(&self) -> Result<ConsoleState, SnapshotError> {
        if !self.snapshot_frozen {
            return Err(SnapshotError::State("the console is not frozen"));
        }
        Ok(ConsoleState {
            config: self.config.as_slice().to_vec(),
            device_ready: self.device_ready,
            ports: self
                .ports
                .iter()
                .map(Port::snapshot)
                .collect::<Result<_, _>>()?,
            pending_control: self.control.snapshot_pending(),
        })
    }

    /// Every queue of a frozen, activated device in queue-index order;
    /// `None` while inactive, when the transport still owns the queues.
    pub fn snapshot_queue_states(&self) -> Result<Option<Vec<QueueState>>, SnapshotError> {
        if !self.snapshot_frozen {
            return Err(SnapshotError::State("the console is not frozen"));
        }
        if !self.is_activated() {
            return Ok(None);
        }
        let mut states: Vec<Option<QueueState>> = self
            .queues
            .iter()
            .map(|q| q.as_ref().map(|dq| QueueState::from_queue(&dq.queue)))
            .collect();
        for (port_id, port) in self.ports.iter().enumerate() {
            if let Some([rx, tx]) = port.queue_states()? {
                states[port_id_to_queue_idx(QueueDirection::Rx, port_id)] = Some(rx);
                states[port_id_to_queue_idx(QueueDirection::Tx, port_id)] = Some(tx);
            }
        }
        states
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .map(Some)
            .ok_or(SnapshotError::State("a console queue is missing"))
    }

    /// Metadata-only check of a saved state against this fresh device,
    /// before guest RAM exists. `activated` is the saved activation.
    pub fn validate_restore(
        &self,
        state: &ConsoleState,
        activated: bool,
    ) -> Result<(), SnapshotError> {
        self.check_snapshot_support()?;
        let fresh: Vec<FreshPort> = self.ports.iter().map(Port::fresh).collect();
        state.validate_for(&fresh, activated)
    }

    /// Adopt a saved state into this fresh, inactive device without any
    /// endpoint I/O: config, pending control messages and log partial lines
    /// now, port progress when `activate_frozen` starts the saved ports
    /// frozen. The device stays frozen until `snapshot_resume`; the guest
    /// driver continues without a new handshake.
    pub fn restore_state(
        &mut self,
        state: &ConsoleState,
        activated: bool,
    ) -> Result<(), SnapshotError> {
        if self.is_activated() || self.ports.iter().any(Port::is_started) {
            return Err(SnapshotError::State("the console is activated"));
        }
        self.validate_restore(state, activated)?;
        for (port, saved) in self.ports.iter_mut().zip(&state.ports) {
            if !port.restore_output(saved.output.as_ref()) {
                return Err(SnapshotError::Invalid(
                    "an output endpoint refused its state",
                ));
            }
            port.handshake = PortHandshake {
                ready: saved.ready,
                guest_open: saved.guest_open,
                size: saved.size,
            };
        }
        self.device_ready = state.device_ready;
        self.config.as_mut_slice().copy_from_slice(&state.config);
        self.control.restore_pending(&state.pending_control);
        self.restored = Some(
            state
                .ports
                .iter()
                .map(|port| {
                    let progress = PortProgress {
                        eof: port.eof,
                        tx_in_flight: port.tx_in_flight,
                    };
                    (port.started, progress)
                })
                .collect(),
        );
        self.snapshot_frozen = true;
        Ok(())
    }

    fn activate_impl(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
        start_frozen: bool,
    ) -> ActivateResult {
        if queues.len() != self.queue_config.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_config.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }
        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();
        self.queues = queues.into_iter().map(Some).collect();
        self.device_state = DeviceState::Activated(mem, interrupt);
        if !start_frozen {
            return Ok(());
        }

        self.snapshot_frozen = true;
        let restored = self.restored.take().unwrap_or_default();
        for (port_id, (started, progress)) in restored.into_iter().enumerate() {
            if !started {
                continue;
            }
            if let Err(e) = self.start_port(port_id, progress, true) {
                error!("Cannot start restored console port {port_id}: {e:?}");
                self.reset();
                return Err(ActivateError::BadActivate);
            }
        }
        Ok(())
    }
}

impl VirtioDevice for Console {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_CONSOLE
    }

    fn device_name(&self) -> &str {
        "console"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_config
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "console: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate_impl(mem, interrupt, queues, false)
    }

    /// Activate for a restore: the ports `restore_state` saved as started
    /// get their queues and frozen workers; nothing runs until
    /// `snapshot_resume`.
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate_impl(mem, interrupt, queues, true)
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        // Shutdown ports and clear queues.
        for port in &mut self.ports {
            port.shutdown();
            port.handshake = PortHandshake::default();
        }
        self.queues.clear();
        self.queue_events.clear();
        self.device_state = DeviceState::Inactive;
        // The next driver starts a new handshake on a live device.
        self.control.restore_pending(&[]);
        self.device_ready = false;
        self.snapshot_frozen = false;
        self.sigwinch_deferred = false;
        self.restored = None;
        true
    }
}

impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        self.reset();
        log::trace!("Console on_vmm_exit finished");
    }
}
