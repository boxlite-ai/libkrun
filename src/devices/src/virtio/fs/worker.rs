use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::thread;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;

use super::snapshot::{FsWorkerState, WorkerCheckpoint};

use crate::virtio::{control::Command, persist::invalid};
use crate::virtio::{InterruptTransport, VirtioShmRegion};

enum FsServer {
    ReadWrite(Server<PassthroughFs>),
    ReadOnly(Server<PassthroughFsRo>),
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(r, w, shm_region, exit_code),
            FsServer::ReadOnly(s) => s.handle_message(r, w, shm_region, exit_code),
        }
    }
}

pub struct FsWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: FsServer,
    stop_fd: EventFd,

    checkpoint: WorkerCheckpoint,
    exit_code: Arc<AtomicI32>,
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        shm_region: Option<VirtioShmRegion>,
        passthrough_cfg: passthrough::Config,
        read_only: bool,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        checkpoint: WorkerCheckpoint,
    ) -> Result<Self, io::Error> {
        let server = if read_only {
            FsServer::ReadOnly(Server::new(PassthroughFsRo::new(passthrough_cfg)?))
        } else {
            FsServer::ReadWrite(Server::new(PassthroughFs::new(passthrough_cfg)?))
        };

        let server = {
            let mut server = server;
            if let Some(saved) = &checkpoint.restore {
                let fs = match &mut server {
                    FsServer::ReadWrite(server) => server.restore_options(saved.options)?,
                    FsServer::ReadOnly(server) => &mut server.restore_options(saved.options)?.inner,
                };
                fs.restore_state(&saved.filesystem)?;
                if let Some(window) = &shm_region {
                    #[cfg(target_os = "linux")]
                    let base = window.host_addr;
                    #[cfg(target_os = "macos")]
                    let base = window.guest_addr;
                    fs.restore_mappings(&saved.filesystem, base, window.size as u64, read_only)?;
                } else if !saved.filesystem.mappings.is_empty() {
                    return Err(invalid("DAX mappings require a window"));
                }
            }
            server
        };
        Ok(Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            shm_region,
            server,
            stop_fd,

            checkpoint,
            exit_code,
        })
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| {
                if let Err(error) = self.work() {
                    error!("fs worker stopped: {error}");
                }
            })
            .unwrap()
    }

    fn work(mut self) -> io::Result<()> {
        let stop_fd = self.stop_fd.as_raw_fd();
        let epoll = Epoll::new()?;
        epoll.ctl(
            ControlOperation::Add,
            stop_fd,
            &EpollEvent::new(EventSet::IN, stop_fd as u64),
        )?;

        let control_fd = self.checkpoint.control.event().as_raw_fd();

        epoll.ctl(
            ControlOperation::Add,
            control_fd,
            &EpollEvent::new(EventSet::IN, control_fd as u64),
        )?;
        if !self.checkpoint.frozen {
            for index in [HPQ_INDEX, REQ_INDEX] {
                let event = &self.queue_evts[index];
                epoll.ctl(
                    ControlOperation::Add,
                    event.as_raw_fd(),
                    &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
                )?;
            }
        }
        let mut events = vec![EpollEvent::default(); 8];
        loop {
            let count = match epoll.wait(events.len(), -1, &mut events) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if events[..count].iter().any(|event| event.fd() == stop_fd) {
                let _ = self.stop_fd.read();
                return Ok(());
            }

            if events[..count].iter().any(|event| event.fd() == control_fd) {
                let _ = self.checkpoint.control.event().read();
                while let Ok(request) = self.checkpoint.control.try_recv() {
                    if request.is_expired() {
                        return Err(invalid("fs control deadline elapsed"));
                    }
                    let result = match request.command() {
                        Command::Freeze => self.freeze(&epoll),
                        Command::Resume => self.resume(&epoll),
                    };
                    if !request.respond(result) {
                        return Err(invalid("fs control outcome unknown"));
                    }
                }
            }
            if self.checkpoint.frozen {
                continue;
            }
            for event in &events[..count] {
                if let Some(index) = self
                    .queue_evts
                    .iter()
                    .position(|queue| queue.as_raw_fd() == event.fd())
                {
                    self.handle_event(index);
                }
            }
        }
    }

    fn freeze(&mut self, epoll: &Epoll) -> io::Result<()> {
        if !self.checkpoint.frozen {
            for event in &self.queue_evts {
                epoll.ctl(
                    ControlOperation::Delete,
                    event.as_raw_fd(),
                    &EpollEvent::default(),
                )?;
            }
            self.checkpoint.frozen = true;
        }
        let queues = self
            .queues
            .iter()
            .map(|queue| queue.save_state(&self.mem, true))
            .collect::<io::Result<Vec<_>>>()?;
        if queues
            .iter()
            .any(|queue| queue.next_avail != queue.next_used)
        {
            return Err(invalid("fs has unfinished requests"));
        }
        let (filesystem, options) = match &self.server {
            FsServer::ReadWrite(server) => {
                let (fs, options) = server.checkpoint_parts();
                (fs.save_state()?, options)
            }
            FsServer::ReadOnly(server) => {
                let (fs, options) = server.checkpoint_parts();
                (fs.inner.save_state()?, options)
            }
        };
        *self.checkpoint.state.lock().unwrap() = Some(FsWorkerState {
            queues,
            filesystem,
            options,
        });
        Ok(())
    }

    fn resume(&mut self, epoll: &Epoll) -> io::Result<()> {
        if !self.checkpoint.frozen {
            return Err(invalid("fs worker is not frozen"));
        }
        for event in &self.queue_evts {
            epoll.ctl(
                ControlOperation::Add,
                event.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
            )?;
        }
        self.checkpoint.frozen = false;
        for index in [HPQ_INDEX, REQ_INDEX] {
            self.rescan(index);
        }
        Ok(())
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        self.rescan(queue_index);
    }

    fn rescan(&mut self, queue_index: usize) {
        loop {
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(queue_index);

            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_queue(&mut self, queue_index: usize) {
        let queue = &mut self.queues[queue_index];
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            if let Err(e) =
                self.server
                    .handle_message(reader, writer, &self.shm_region, &self.exit_code)
            {
                error!("error handling message: {e:?}");
            }

            if let Err(e) = queue.add_used(&self.mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
    }
}
