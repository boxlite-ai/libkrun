// SPDX-License-Identifier: Apache-2.0

use super::{defs, muxer::MuxerRx, packet::TsiGetnameRsp, packet::VsockPacket, Vsock};
use crate::virtio::persist::{invalid, QueueState, VirtioDeviceState};
use crate::virtio::VirtioDevice;
use std::io;

/// TSI waits for replies on bound datagram control sockets, which a standard
/// virtio transport reset does not wake. Complete each outstanding operation
/// with ECONNRESET, including requests still queued when the backend stops.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlReply {
    pub operation: u32,
    pub port: u32,
}
impl ControlReply {
    pub fn from_packet(packet: &VsockPacket) -> Option<Self> {
        (packet.type_() == defs::uapi::VSOCK_TYPE_DGRAM
            && matches!(
                packet.dst_port(),
                defs::TSI_CONNECT | defs::TSI_GETNAME | defs::TSI_LISTEN | defs::TSI_ACCEPT
            ))
        .then(|| Self {
            operation: packet.dst_port(),
            port: packet.src_port(),
        })
    }
    pub fn from_response(response: MuxerRx) -> Option<Self> {
        let (operation, port) = match response {
            MuxerRx::ConnResponse { peer_port, .. } => (defs::TSI_CONNECT, peer_port),
            MuxerRx::GetnameResponse { peer_port, .. } => (defs::TSI_GETNAME, peer_port),
            MuxerRx::ListenResponse { peer_port, .. } => (defs::TSI_LISTEN, peer_port),
            MuxerRx::AcceptResponse { peer_port, .. } => (defs::TSI_ACCEPT, peer_port),
            _ => return None,
        };
        Some(Self { operation, port })
    }
    pub fn response(&self) -> MuxerRx {
        let local_port = self.operation;
        let peer_port = self.port;
        let result = -libc::ECONNRESET;
        match self.operation {
            defs::TSI_CONNECT => MuxerRx::ConnResponse {
                local_port,
                peer_port,
                result,
            },
            defs::TSI_LISTEN => MuxerRx::ListenResponse {
                local_port,
                peer_port,
                result,
            },
            defs::TSI_ACCEPT => MuxerRx::AcceptResponse {
                local_port,
                peer_port,
                result,
            },
            _ => MuxerRx::GetnameResponse {
                local_port,
                peer_port,
                data: TsiGetnameRsp {
                    result,
                    addr_len: 0,
                    ..Default::default()
                },
            },
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VsockState {
    pub device: VirtioDeviceState,
    pub queues: Option<Vec<QueueState>>,
    pub cid: u64,
    pub tsi_flags: u32,
    pub reset: super::VsockResetState,
    replies: Vec<ControlReply>,
    datagrams: Vec<DatagramState>,
}

impl Vsock {
    /// The runtime can have interrupted a blocking send before its request is
    /// dispatched. Even preflight/storage rejection must finish that network
    /// transition, unless the whole VM has an unknown freeze outcome.
    pub fn recover_quiesced(&mut self) -> io::Result<()> {
        if self.muxer.gate().is_held() {
            self.freeze(std::time::Instant::now() + std::time::Duration::from_secs(5))?;
            self.resume()?;
        }
        Ok(())
    }

    pub fn freeze(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        self.stop_backend_until(Some(deadline))
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        self.frozen = true;
        Ok(())
    }
    pub fn save_state(&self) -> io::Result<VsockState> {
        if !self.frozen || self.muxer.is_running() || self.muxer.has_failed() {
            return Err(invalid("vsock capture requires stopped backend"));
        }
        Ok(VsockState {
            device: VirtioDeviceState::save(self)?,
            queues: self.snapshot_queue_states(),
            cid: self.cid(),
            tsi_flags: self.muxer.tsi_flags().bits(),
            reset: self.snapshot_reset_state(),
            replies: self.pending_controls.iter().cloned().collect(),
            datagrams: self.muxer.datagrams.clone(),
        })
    }
    pub fn restore_state(&mut self, state: &VsockState) -> io::Result<()> {
        state.device.validate(self)?;
        let mut ids = std::collections::HashSet::new();
        if self.is_activated()
            || state.cid != self.cid()
            || state.tsi_flags != self.muxer.tsi_flags().bits()
            || state.device.activated != state.queues.is_some()
            || state.reset.pending != state.device.activated
            || (!state.device.activated
                && (!state.replies.is_empty() || !state.datagrams.is_empty()))
            || (state.tsi_flags == 0 && (!state.replies.is_empty() || !state.datagrams.is_empty()))
            || state.datagrams.iter().any(|d| {
                d.id != ((u64::from(d.peer_port) << 32) | u64::from(defs::TSI_PROXY_PORT))
                    || !ids.insert(d.id)
            })
            || state.replies.iter().any(|r| {
                !matches!(
                    r.operation,
                    defs::TSI_CONNECT | defs::TSI_GETNAME | defs::TSI_LISTEN | defs::TSI_ACCEPT
                )
            })
        {
            return Err(invalid("incompatible vsock checkpoint"));
        }
        state.device.restore_features(self)?;
        self.restore_reset_state(state.reset)
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        self.pending_controls = state.replies.iter().cloned().collect();
        self.muxer.datagrams = state.datagrams.clone();
        self.frozen = true;
        Ok(())
    }
    pub fn resume(&mut self) -> io::Result<()> {
        if self.is_activated() {
            self.restart_backend()
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
        } else {
            self.muxer.gate().release();
        }
        self.frozen = false;
        Ok(())
    }
}

/// UDP has no byte-stream session to resume. Recreate its endpoint and peer
/// configuration, dropping host receive buffers; an occupied local address is
/// an explicit restore error. No host descriptor numbers enter the image.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) enum SocketAddress {
    Inet(std::net::SocketAddr),
    Unix(std::path::PathBuf),
}
impl SocketAddress {
    pub fn capture(addr: nix::sys::socket::SockaddrStorage) -> io::Result<Self> {
        if let Some(ip) = addr.as_sockaddr_in() {
            Ok(Self::Inet(std::net::SocketAddr::new(
                ip.ip().into(),
                ip.port(),
            )))
        } else if let Some(ip) = addr.as_sockaddr_in6() {
            Ok(Self::Inet(
                std::net::SocketAddrV6::new(ip.ip(), ip.port(), ip.flowinfo(), ip.scope_id())
                    .into(),
            ))
        } else if let Some(path) = addr.as_unix_addr().and_then(|a| a.path()) {
            Ok(Self::Unix(path.to_owned()))
        } else {
            Err(invalid("unsupported UDP endpoint address"))
        }
    }
    pub fn address(&self) -> io::Result<nix::sys::socket::SockaddrStorage> {
        use nix::sys::socket::{SockaddrLike, SockaddrStorage, UnixAddr};
        match self {
            Self::Inet(address) => Ok((*address).into()),
            Self::Unix(path) => {
                let address = UnixAddr::new(path).map_err(io::Error::other)?;
                // Copy exactly the initialized UnixAddr bytes into owned storage.
                unsafe { SockaddrStorage::from_raw(address.as_ptr().cast(), Some(address.len())) }
                    .ok_or_else(|| invalid("invalid Unix datagram address"))
            }
        }
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DatagramState {
    pub id: u64,
    pub family: u16,
    pub local_port: u32,
    pub peer_port: u32,
    pub local: Option<SocketAddress>,
    pub peer: Option<SocketAddress>,
    pub sendto: Option<SocketAddress>,
    pub counters: [u32; 4],
}
