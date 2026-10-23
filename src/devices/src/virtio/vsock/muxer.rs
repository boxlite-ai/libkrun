use std::collections::HashMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;

use super::super::Queue as VirtQueue;
use super::defs;
use super::defs::uapi;
use super::gate::VsockGate;
use super::muxer_rxq::{rx_to_pkt, MuxerRxQ};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiConnectReq, TsiGetnameRsp, VsockPacket};
use super::proxy::{Proxy, ProxyRemoval, ProxyUpdate};
use super::reaper::ReaperThread;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::unix::{UnixAcceptorProxy, UnixProxy};
use super::TsiFlags;
use super::VsockError;
use crossbeam_channel::{unbounded, Sender};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;
use std::net::{Ipv4Addr, SocketAddrV4};

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// Epoll data of the muxer wake eventfd. It is never looked up as a proxy:
/// the wake is written only after the gate closed, and the muxer thread
/// exits on a closed gate before it handles any event.
const MUXER_WAKE_TOKEN: u64 = u64::MAX;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    GetnameResponse {
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    OpRequest {
        local_port: u32,
        peer_port: u32,
    },
    OpResponse {
        local_port: u32,
        peer_port: u32,
    },
    CreditRequest {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    CreditUpdate {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    ListenResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
}

pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
) {
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(head) = queue.pop(mem) {
        if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
            rx_to_pkt(cid, rx, &mut pkt);
            if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len()) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
    } else {
        error!("couldn't push pkt to queue, adding it to rxq");
        drop(queue);
        rxq_mutex.lock().unwrap().push(rx);
    }
}

pub struct VsockMuxer {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    /// Shared, not cloned: an `Epoll` clone closes the same descriptor on
    /// drop, and the muxer thread now exits before this owner.
    epoll: Arc<Epoll>,
    interrupt: Option<InterruptTransport>,
    proxy_map: ProxyMap,
    reaper_sender: Option<Sender<u64>>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    tsi_flags: TsiFlags,
    gate: Arc<VsockGate>,
    /// The running backend's threads, joined by `stop`.
    threads: Vec<JoinHandle<()>>,
    /// Registered in `epoll` until the muxer thread is joined; the gate
    /// writes a duplicate.
    muxer_wake: Option<EventFd>,
    #[cfg(target_os = "macos")]
    timesync_stop: Option<Sender<()>>,
    /// Set once a worker panicked or the backend failed to open on an
    /// event-queue kick, and never cleared: the backend's state is unknown,
    /// so every later stop reports it and it never restarts.
    failed: bool,
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> Self {
        VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Arc::new(Epoll::new().unwrap()),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            tsi_flags,
            gate: VsockGate::new(),
            threads: Vec::new(),
            muxer_wake: None,
            #[cfg(target_os = "macos")]
            timesync_stop: None,
            failed: false,
        }
    }

    pub(crate) fn tsi_flags(&self) -> TsiFlags {
        self.tsi_flags
    }

    pub(crate) fn gate(&self) -> &Arc<VsockGate> {
        &self.gate
    }

    pub(crate) fn is_running(&self) -> bool {
        self.mem.is_some()
    }

    pub(crate) fn has_failed(&self) -> bool {
        self.failed
    }

    /// Record a backend failure no caller could be told about; like a
    /// worker panic, every later stop reports it.
    pub(crate) fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Start a backend from the original configuration on a fresh epoll:
    /// bind the listening paths, then the workers. A listener that cannot be
    /// bound fails the start when `require_listeners` is set (a snapshot
    /// restart must serve every original path) and is skipped with a warning
    /// otherwise (the activation policy). A failure stops whatever already
    /// started.
    pub(crate) fn start(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        require_listeners: bool,
    ) -> io::Result<()> {
        let started = self.start_workers(mem, queue, interrupt, require_listeners);
        if started.is_err() {
            if let Err(e) = self.stop() {
                error!("vsock backend stop after a failed start: {e:?}");
            }
        }
        started
    }

    fn start_workers(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        require_listeners: bool,
    ) -> io::Result<()> {
        self.epoll = Arc::new(Epoll::new()?);
        let wake = EventFd::new(EFD_NONBLOCK)?;
        self.epoll.ctl(
            ControlOperation::Add,
            wake.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, MUXER_WAKE_TOKEN),
        )?;
        self.gate.open(wake.try_clone()?);
        self.muxer_wake = Some(wake);
        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.interrupt = Some(interrupt.clone());
        self.create_listening_ipc_sockets(require_listeners)?;

        #[cfg(target_os = "macos")]
        {
            let (stop, stopped) = crossbeam_channel::bounded(0);
            self.timesync_stop = Some(stop);
            let timesync =
                TimesyncThread::new(self.cid, mem.clone(), queue.clone(), interrupt.clone());
            self.threads.push(timesync.run(stopped)?);
        }

        let (sender, receiver) = unbounded();
        self.reaper_sender = Some(sender.clone());
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        self.threads.push(reaper.run()?);

        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.gate.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            interrupt,
            sender,
        );
        self.threads.push(thread.run()?);
        Ok(())
    }

    /// Stop and join every worker, then release the proxies (closing their
    /// sockets and removing the paths this backend bound), the pending RX
    /// packets and every guest RAM reference. A worker panic does not cut
    /// this short; it is reported with `BackendFailed`, by this stop and
    /// every later one. Idempotent.
    pub(crate) fn stop(&mut self) -> super::Result<()> {
        self.gate.quiesce();
        // The reaper exits once the muxer thread dropped its sender too.
        self.reaper_sender = None;
        #[cfg(target_os = "macos")]
        {
            self.timesync_stop = None;
        }
        for thread in self.threads.drain(..) {
            if let Err(e) = thread.join() {
                error!("vsock worker thread panicked: {e:?}");
                self.failed = true;
            }
        }
        self.muxer_wake = None;
        // A panicked worker may have poisoned these; release them anyway.
        self.proxy_map
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        *self.rxq.lock().unwrap_or_else(PoisonError::into_inner) = MuxerRxQ::new();
        self.mem = None;
        self.queue = None;
        self.interrupt = None;
        if self.failed {
            return Err(VsockError::BackendFailed);
        }
        Ok(())
    }

    /// Join `worker` first on the next stop, ahead of the real workers.
    #[cfg(test)]
    pub(crate) fn adopt_worker_for_test(&mut self, worker: JoinHandle<()>) {
        self.threads.insert(0, worker);
    }

    fn create_listening_ipc_sockets(&self, required: bool) -> io::Result<()> {
        let Some(ipc_map) = &self.unix_ipc_port_map else {
            return Ok(());
        };
        for (port, (path, do_listen)) in ipc_map {
            if !do_listen {
                continue;
            }
            let id = ((*port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            // A proxy dropped on failure removes only a path it bound.
            let listener = UnixAcceptorProxy::new(id, path, *port)
                .map_err(|e| io::Error::other(format!("listen at {path:?}: {e}")))
                .and_then(|proxy| {
                    let event = EpollEvent::new(EventSet::IN, id);
                    self.epoll
                        .ctl(ControlOperation::Add, proxy.as_raw_fd(), &event)?;
                    Ok(proxy)
                });
            match listener {
                Ok(proxy) => {
                    self.proxy_map
                        .write()
                        .unwrap()
                        .insert(id, Mutex::new(Box::new(proxy)));
                }
                Err(e) if required => return Err(e),
                Err(e) => warn!("Failed to create listening proxy: {e}"),
            }
        }
        Ok(())
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("recv_stream_pkt");
        if self.rxq.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq.lock().unwrap().pop() {
            rx_to_pkt(self.cid, rx, pkt);
        }

        Ok(())
    }

    fn push_packet(&self, rx: MuxerRx) {
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => {
                error!("proxy creation without mem");
                return;
            }
        };
        let queue_mutex = match self.queue.as_ref() {
            Some(q) => q,
            None => {
                error!("stream proxy creation without stream queue");
                return;
            }
        };

        let mut queue = queue_mutex.lock().unwrap();
        if let Some(head) = queue.pop(mem) {
            if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                rx_to_pkt(self.cid, rx, &mut pkt);
                if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        } else {
            error!("couldn't push pkt to queue, adding it to rxq");
            drop(queue);
            self.rxq.lock().unwrap().push(rx);
        }
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !evset.is_empty() {
            let _ = self
                .epoll
                .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                info!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                info!("deferring proxy removal: {id}");
                if let Some(reaper_sender) = &self.reaper_sender {
                    if reaper_sender.send(id).is_err() {
                        self.proxy_map.write().unwrap().remove(&id);
                    }
                }
            }
        }

        if update.signal_queue {
            if let Some(interrupt) = &self.interrupt {
                interrupt.signal_used_queue();
            }
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        debug!("proxy create request");
        if let Some(req) = pkt.read_proxy_create() {
            debug!(
                "proxy create request: peer_port={}, type={}",
                req.peer_port, req._type
            );
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    error!("proxy creation without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            match req._type {
                defs::SOCK_STREAM => {
                    debug!("proxy create stream");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family as i32 == libc::AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting stream unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family as i32 == libc::AF_INET || req.family as i32 == libc::AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting stream inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiStreamProxy::new(
                        id,
                        self.cid,
                        req.family,
                        defs::TSI_PROXY_PORT,
                        req.peer_port,
                        pkt.src_port(),
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating tcp proxy: {e}"),
                    }
                }
                defs::SOCK_DGRAM => {
                    debug!("proxy create dgram");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family as i32 == libc::AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting dgram unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family as i32 == libc::AF_INET || req.family as i32 == libc::AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting dgram inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiDgramProxy::new(
                        id,
                        self.cid,
                        req.family,
                        req.peer_port,
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating udp proxy: {e}"),
                    }
                }
                _ => debug!("unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    self.process_proxy_update(id, proxy.lock().unwrap().connect(pkt, req));
                }
                None => self.push_packet(MuxerRx::ConnResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::ECONNREFUSED,
                }),
            }
        }
    }

    fn process_getname(&self, pkt: &VsockPacket) {
        debug!("new getname request");
        if let Some(req) = pkt.read_getname_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "new getname request: id={}, peer_port={}, local_port={}",
                id, req.peer_port, req.local_port
            );

            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => proxy.lock().unwrap().getpeername(pkt),
                None => self.push_packet(MuxerRx::GetnameResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    data: TsiGetnameRsp {
                        result: -libc::EINVAL,
                        addr_len: 0,
                        addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                    },
                }),
            }
        }
    }

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendto_addr(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM listen request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(
                    id,
                    proxy.lock().unwrap().listen(pkt, req, &self.host_port_map),
                ),
                None => self.push_packet(MuxerRx::ListenResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                }),
            };
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(id, proxy.lock().unwrap().accept(req)),
                None => self.push_packet(MuxerRx::AcceptResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EINVAL,
                }),
            }
        }
    }

    fn process_proxy_release(&self, pkt: &VsockPacket) {
        debug!("DGRAM release request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_release_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "DGRAM release request: id={} local_port={} peer_port={}",
                id, req.local_port, req.peer_port
            );
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                Some(proxy.lock().unwrap().release())
            } else {
                debug!(
                    "release without proxy: id={}, proxies={}",
                    id,
                    self.proxy_map.read().unwrap().len()
                );
                None
            };

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
        debug!(
            "DGRAM release request: proxies={}",
            self.proxy_map.read().unwrap().len()
        );
    }

    fn process_dgram_rw(&self, pkt: &VsockPacket) {
        debug!("DGRAM OP_RW");
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);

        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!("DGRAM allowing OP_RW for {}", pkt.src_port());
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("DGRAM ignoring OP_RW for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_create(pkt)
            }
            defs::TSI_CONNECT if self.tsi_flags.tsi_enabled() => self.process_connect(pkt),
            defs::TSI_GETNAME if self.tsi_flags.tsi_enabled() => self.process_getname(pkt),
            defs::TSI_SENDTO_ADDR if self.tsi_flags.tsi_enabled() => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA if self.tsi_flags.tsi_enabled() => self.process_sendto_data(pkt),
            defs::TSI_LISTEN if self.tsi_flags.tsi_enabled() => self.process_listen_request(pkt),
            defs::TSI_ACCEPT if self.tsi_flags.tsi_enabled() => self.process_accept_request(pkt),
            defs::TSI_PROXY_RELEASE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_release(pkt)
            }
            _ => {
                if pkt.op() == uapi::VSOCK_OP_RW {
                    self.process_dgram_rw(pkt);
                } else {
                    error!("unexpected dgram pkt: {}", pkt.op());
                }
            }
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("OP_REQUEST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let mut proxy_map = self.proxy_map.write().unwrap();

        if let Some(proxy) = proxy_map.get(&id) {
            if let Some(update) = proxy.lock().unwrap().confirm_connect(pkt) {
                self.process_proxy_update(id, update);
            }
        } else if let Some(ref mut ipc_map) = &mut self.unix_ipc_port_map {
            if let Some((path, listen)) = ipc_map.get(&pkt.dst_port()) {
                let mem = self.mem.as_ref().unwrap();
                let queue = self.queue.as_ref().unwrap();
                if *listen {
                    warn!("Attempting to connect a socket that is listening, sending rst");
                    let rx = MuxerRx::Reset {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    };
                    push_packet(self.cid, rx, &self.rxq, queue, mem);
                    return;
                }
                let rxq = self.rxq.clone();

                let mut unix = match UnixProxy::new(
                    id,
                    self.cid,
                    pkt.dst_port(),
                    pkt.src_port(),
                    mem.clone(),
                    queue.clone(),
                    rxq,
                    path.to_path_buf(),
                    &self.gate,
                ) {
                    Ok(unix) => unix,
                    Err(e) => {
                        warn!("refusing unix connection, sending rst: {e}");
                        let rx = MuxerRx::Reset {
                            local_port: pkt.dst_port(),
                            peer_port: pkt.src_port(),
                        };
                        push_packet(self.cid, rx, &self.rxq, queue, mem);
                        return;
                    }
                };
                let tsi = TsiConnectReq {
                    peer_port: 0,
                    addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                };
                let update = unix.connect(pkt, tsi);
                unix.confirm_connect(pkt);
                proxy_map.insert(id, Mutex::new(Box::new(unix)));
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));
        update
            .as_ref()
            .and_then(|u| u.push_accept)
            .and_then(|(_id, parent_id)| {
                self.proxy_map
                    .read()
                    .unwrap()
                    .get(&parent_id)
                    .map(|proxy| proxy.lock().unwrap().enqueue_accept())
            });

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_shutdown(&self, pkt: &VsockPacket) {
        debug!("OP_SHUTDOWN");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().shutdown(pkt);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("OP_CREDIT_UPDATE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().update_peer_credit(pkt));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("OP_RW");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RW for {}, sending reset", pkt.src_port());
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    warn!("OP_RW without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    warn!("OP_RW without queue");
                    return;
                }
            };

            // This response goes to the connection.
            let rx = MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            };
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.release();
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RST for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_pkt: src_port={} dst_port={}, op={}",
            pkt.src_port(),
            pkt.dst_port(),
            pkt.op()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => self.process_op_response(pkt),
            uapi::VSOCK_OP_SHUTDOWN => self.process_op_shutdown(pkt),
            uapi::VSOCK_OP_CREDIT_UPDATE => self.process_op_credit_update(pkt),
            uapi::VSOCK_OP_RW => self.process_stream_rw(pkt),
            uapi::VSOCK_OP_RST => self.process_stream_rst(pkt),
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

impl Drop for VsockMuxer {
    fn drop(&mut self) {
        // Never leave detached workers writing guest RAM after their owner.
        if let Err(e) = self.stop() {
            error!("vsock backend stop on drop: {e:?}");
        }
    }
}
