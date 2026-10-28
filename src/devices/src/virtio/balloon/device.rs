use std::cmp;
use std::io::Write;

use utils::eventfd::EventFd;
use vm_memory::{
    Address, ByteValued, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MemoryRegionAddress,
};

use super::super::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::persist::QueueState;
use crate::virtio::queue::VIRTQ_DESC_F_NEXT;
use crate::virtio::{DescriptorChain, InterruptTransport};

// Inflate queue.
pub(crate) const IFQ_INDEX: usize = 0;
// Deflate queue.
pub(crate) const DFQ_INDEX: usize = 1;
// Stats queue.
pub(crate) const STQ_INDEX: usize = 2;
// Page-hinting queue.
pub(crate) const PHQ_INDEX: usize = 3;
// Free page reporting queue.
pub(crate) const FRQ_INDEX: usize = 4;

/// Not supported by the queue implementation; such reports are ignored.
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;
/// Complete descriptor chains handled per event callback.
const MAX_CHAINS_PER_CALLBACK: usize = 64;

// Supported features.
pub const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    /* Number of pages host wants Guest to give up. */
    num_pages: u32,
    /* Number of pages we've actually got in balloon. */
    actual: u32,
    /* Free page report command id, readonly by guest */
    free_page_report_cmd_id: u32,
    /* Stores PAGE_POISON if page poisoning is in use */
    poison_val: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

/// Length of the configuration space a snapshot carries.
pub const CONFIG_LEN: usize = std::mem::size_of::<VirtioBalloonConfig>();

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
}

impl Balloon {
    pub fn new() -> super::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
        })
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    pub fn process_frq(&mut self) -> bool {
        debug!("balloon: process_frq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let reporting = &mut queues[FRQ_INDEX];
        if !reporting.queue.ready {
            return false;
        }
        let mut have_used = false;

        for _ in 0..MAX_CHAINS_PER_CALLBACK {
            let Some(head) = reporting.queue.pop(mem) else {
                return have_used;
            };
            let index = head.index;
            match reported_ranges(mem, head) {
                Ok(ranges) => {
                    for (region, offset, len) in ranges {
                        discard(region, offset, len);
                    }
                }
                Err(why) => warn!("balloon: ignoring free page report: {why}"),
            }

            have_used = true;
            if let Err(e) = reporting.queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        // Bounded callbacks keep a snapshot freeze prompt; the rest of the
        // ring is handled from a later callback.
        if !reporting.queue.is_empty(mem) {
            if let Err(e) = reporting.event.write(1) {
                error!("balloon: failed to requeue the remaining reports: {e:?}");
            }
        }

        have_used
    }

    /// Queue state for a snapshot of a device whose event thread is frozen;
    /// `None` while inactive, when the transport still owns the queues.
    pub fn snapshot_queue_states(&self) -> Option<Vec<QueueState>> {
        let queues = self.queues.as_ref()?;
        Some(
            queues
                .iter()
                .map(|q| QueueState::from_queue(&q.queue))
                .collect(),
        )
    }

    /// Notify every ready queue, so a restored device examines its rings
    /// without the source's notifications.
    pub fn snapshot_kick(&self) {
        for queue in self.queues.iter().flatten() {
            queue.kick_if_ready();
        }
    }

    /// The complete guest-visible configuration space.
    pub fn snapshot_config(&self) -> Vec<u8> {
        self.config.as_slice().to_vec()
    }

    /// Restore the configuration space saved by `snapshot_config`.
    pub fn restore_snapshot_config(&mut self, bytes: &[u8]) -> Result<(), BalloonError> {
        self.config = VirtioBalloonConfig::from_slice(bytes)
            .copied()
            .ok_or(BalloonError::ConfigLength(bytes.len()))?;
        Ok(())
    }
}

/// Validate a whole free page report before anything is discarded: every
/// descriptor must be a direct, page-aligned range inside one guest RAM
/// region, and every NEXT link must resolve. A chain that ends early (a bad
/// link or a loop longer than the queue) is malformed, never a shorter list.
fn reported_ranges<'a>(
    mem: &'a GuestMemoryMmap,
    head: DescriptorChain<'a>,
) -> Result<Vec<(&'a GuestRegionMmap, MemoryRegionAddress, usize)>, &'static str> {
    let page = host_page_size();
    let mut ranges = Vec::new();
    let mut current = head;
    loop {
        let desc = current.descriptor();
        if desc.flags & VIRTQ_DESC_F_INDIRECT != 0 {
            return Err("indirect descriptors are not supported");
        }
        if desc.addr % page != 0 || u64::from(desc.len) % page != 0 {
            return Err("range is not page aligned");
        }
        let addr = GuestAddress(desc.addr);
        let region = mem.find_region(addr).ok_or("range is outside guest RAM")?;
        let offset = MemoryRegionAddress(addr.raw_value() - region.start_addr().raw_value());
        if offset.raw_value() + u64::from(desc.len) > region.len() {
            return Err("range crosses the end of a guest RAM region");
        }
        ranges.push((region, offset, desc.len as usize));
        if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
            return Ok(ranges);
        }
        current = current
            .next_descriptor()
            .ok_or("descriptor chain is truncated or loops")?;
    }
}

/// Return a validated range to the host. Only private anonymous RAM owned by
/// guest memory is discarded (reads back as zero); shared, file-backed or
/// borrowed mappings keep their contents and the hint is ignored, as virtio
/// allows.
fn discard(region: &GuestRegionMmap, offset: MemoryRegionAddress, len: usize) {
    let private_anonymous = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    if len == 0
        || !region.owned()
        || region.file_offset().is_some()
        || region.flags() & (private_anonymous | libc::MAP_SHARED) != private_anonymous
    {
        return;
    }
    let Ok(host_addr) = region.get_host_address(offset) else {
        return;
    };
    // Guest page alignment does not imply host alignment for every mapping.
    if host_addr as u64 % host_page_size() != 0 {
        return;
    }
    // SAFETY: the range is page aligned and inside this private anonymous
    // guest RAM mapping, which stays mapped while the device holds `mem`.
    let ret = unsafe { libc::madvise(host_addr as *mut libc::c_void, len, libc::MADV_DONTNEED) };
    if ret != 0 {
        warn!(
            "balloon: discarding {len} bytes at region offset {offset:?} failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn host_page_size() -> u64 {
    // SAFETY: sysconf has no memory-safety preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

impl VirtioDevice for Balloon {
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
        uapi::VIRTIO_ID_BALLOON
    }

    fn device_name(&self) -> &str {
        "balloon"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
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
            "balloon: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    /// No worker exists: queue work runs on the owner's event thread, which
    /// controls when a restored device resumes.
    fn activate_frozen(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate(mem, interrupt, queues)
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

// MADV_DONTNEED zeroes private anonymous pages only on Linux.
#[cfg(all(test, target_os = "linux"))]
mod tests;
