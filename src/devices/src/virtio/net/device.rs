// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::virtio::net::{Error, Result};
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice, TYPE_NET,
};

use super::worker::{NetWorker, NetWorkerControl, NetWorkerHandle};

use std::cmp;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::thread::JoinHandle;
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

/// The feature set `Net::new` offers for the caller's `features`: single
/// source of truth for construction and snapshot validation.
pub fn offered_features(features: u32) -> u64 {
    features as u64
        | (1 << VIRTIO_NET_F_MAC)
        | (1 << VIRTIO_RING_F_EVENT_IDX)
        | (1 << VIRTIO_F_VERSION_1)
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

impl VirtioNetConfig {
    fn for_mac(mac: [u8; 6]) -> Self {
        VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        }
    }
}

/// The guest-visible config bytes `Net::new` exposes for `mac`: single
/// source of truth for snapshot validation.
pub fn config_bytes_for(mac: [u8; 6]) -> Vec<u8> {
    VirtioNetConfig::for_mac(mac).as_slice().to_vec()
}

#[derive(Clone)]
pub enum VirtioNetBackend {
    UnixstreamFd(RawFd),
    UnixstreamPath(PathBuf),
    UnixgramFd(RawFd),
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,

    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    worker_control: Option<NetWorkerHandle>,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        let avail_features = offered_features(features);

        let config = VirtioNetConfig::for_mac(mac);

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,

            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?,
            worker_control: None,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }

    /// The complete guest-visible device configuration, byte-exact.
    pub fn config_bytes(&self) -> Vec<u8> {
        self.config.as_slice().to_vec()
    }

    /// Snapshot control handle for the activated worker, if any.
    pub fn worker_control(&self) -> Option<&NetWorkerHandle> {
        self.worker_control.as_ref()
    }

    /// Stop the worker and wait for its thread to exit, closing its backend
    /// connection; frozen workers stop too. The device stays activated from
    /// the transport's point of view: this is owner teardown, not a guest
    /// reset, which this device still does not support.
    pub fn stop_worker(&mut self) {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for virtio-net worker thread: {e:?}");
            }
        }
        self.worker_control = None;
    }

    fn activate_impl(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
        start_frozen: bool,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            error!("virtio-net ({}) worker thread already exists", self.id());
            return Err(ActivateError::BadActivate);
        }
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let control_fd = EventFd::new(EFD_NONBLOCK).map_err(|_| ActivateError::BadActivate)?;
        let (commands, command_receiver) = crossbeam_channel::bounded(16);
        let control = NetWorkerControl {
            stop_fd: self
                .worker_stopfd
                .try_clone()
                .map_err(|_| ActivateError::BadActivate)?,
            control_fd: control_fd
                .try_clone()
                .map_err(|_| ActivateError::BadActivate)?,
            wake_fd: EventFd::new(EFD_NONBLOCK).map_err(|_| ActivateError::BadActivate)?,
            commands: command_receiver,
        };

        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
            control,
        ) {
            Ok(worker) => {
                self.worker_thread = Some(worker.run(start_frozen));
                self.worker_control = Some(NetWorkerHandle {
                    control_fd,
                    commands,
                });
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // Never leave a detached worker writing guest RAM after its owner.
        self.stop_worker();
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
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
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
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
}
