//! DeviceManager — centralized I/O port and MMIO device dispatch.
//!
//! Owns all emulated devices (Serial, PIC, PIT, CMOS/RTC, virtio-*)
//! and routes vCPU exit events to the appropriate device handlers.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use super::super::cmdline::{irq_for_slot, mmio_base_for_slot, MmioSlot, MMIO_SLOT_SIZE};
use super::super::context::VmContext;
use super::super::error::{Result, WkrunError};
use super::super::vcpu::IoHandler;
use super::pic::Pic;
use super::pit::Pit;
use super::serial::{Serial, COM1_BASE};
use super::virtio::block::VirtioBlock;
use super::virtio::disk::open_disk_backend;
use super::virtio::mmio::VirtioMmioDevice;
use super::virtio::net::VirtioNet;
use super::virtio::p9::Virtio9p;
use super::virtio::queue::GuestMemoryAccessor;
use super::virtio::vsock::VirtioVsock;

/// Shared console output buffer.
pub type ConsoleBuffer = Arc<Mutex<Vec<u8>>>;

/// Writer that copies output to both an inner writer and a shared buffer.
struct TeeWriter {
    inner: Box<dyn Write + Send>,
    buffer: ConsoleBuffer,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Global console output buffers, keyed by ctx_id.
static CONSOLE_BUFFERS: LazyLock<Mutex<HashMap<u32, ConsoleBuffer>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Store a console buffer for a VM.
pub fn store_console_buffer(ctx_id: u32, buffer: ConsoleBuffer) {
    CONSOLE_BUFFERS.lock().unwrap().insert(ctx_id, buffer);
}

/// Get a snapshot of console output for a VM.
///
/// Returns None if no buffer exists for the given ctx_id.
pub fn get_console_output(ctx_id: u32) -> Option<Vec<u8>> {
    CONSOLE_BUFFERS
        .lock()
        .unwrap()
        .get(&ctx_id)
        .map(|buf| buf.lock().unwrap().clone())
}

/// Remove and drop the console buffer for a VM.
pub fn remove_console_buffer(ctx_id: u32) {
    CONSOLE_BUFFERS.lock().unwrap().remove(&ctx_id);
}

/// Default guest CID for vsock (standard value for single-VM hosts).
const GUEST_CID: u64 = 3;

/// ACPI PM1a event block base port (4 bytes wide).
const PM1A_EVT_BLK: u16 = 0x600;

/// ACPI PM1a control block base port (2 bytes wide).
const PM1A_CNT_BLK: u16 = 0x604;

/// Default vsock listen ports (BoxLite: 2695=gRPC, 2696=ready signal).
const DEFAULT_VSOCK_PORTS: &[u32] = &[2695, 2696];

/// Convert a value to BCD (Binary-Coded Decimal).
/// E.g. 26 → 0x26, 59 → 0x59.
fn to_bcd(val: u8) -> u8 {
    ((val / 10) << 4) | (val % 10)
}

/// Snapshot of host UTC time, captured once at VM start and stored as
/// BCD values for CMOS register reads.
struct CmosTime {
    seconds: u8,
    minutes: u8,
    hours: u8,
    day_of_week: u8,
    day_of_month: u8,
    month: u8,
    year: u8,    // Two-digit year in BCD (e.g. 0x26 for 2026)
    century: u8, // Century in BCD (e.g. 0x20)
}

impl CmosTime {
    /// Capture the current host UTC time.
    fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Break Unix timestamp into calendar components.
        // Algorithm from Howard Hinnant's chrono-compatible date library.
        let days = (secs / 86400) as i64;
        let time_of_day = secs % 86400;

        // Civil date from days since epoch (March-based, then adjusted).
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u64; // day of era [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };

        let hour = (time_of_day / 3600) as u8;
        let minute = ((time_of_day % 3600) / 60) as u8;
        let second = (time_of_day % 60) as u8;

        // Day of week: 1970-01-01 was Thursday (4). 1=Sun..7=Sat for CMOS.
        let dow_zero = ((days % 7) + 4) % 7; // 0=Sun..6=Sat
        let dow = dow_zero as u8 + 1; // 1=Sun..7=Sat

        let year_full = y as u16;
        let century = (year_full / 100) as u8;
        let year_2digit = (year_full % 100) as u8;

        Self {
            seconds: to_bcd(second),
            minutes: to_bcd(minute),
            hours: to_bcd(hour),
            day_of_week: to_bcd(dow),
            day_of_month: to_bcd(d as u8),
            month: to_bcd(m as u8),
            year: to_bcd(year_2digit),
            century: to_bcd(century),
        }
    }
}

/// Host time snapshot, captured once at process start.
static CMOS_TIME: LazyLock<CmosTime> = LazyLock::new(CmosTime::now);

/// CMOS register read values. Time fields use the host-UTC snapshot;
/// everything else is static hardware description.
fn cmos_read(addr: u8) -> u8 {
    let t = &*CMOS_TIME;
    match addr {
        0x00 => t.seconds,
        0x02 => t.minutes,
        0x04 => t.hours,
        0x06 => t.day_of_week,
        0x07 => t.day_of_month,
        0x08 => t.month,
        0x09 => t.year,
        0x0A => 0x26, // Status A: no update in progress, 32.768 kHz
        0x0B => 0x02, // Status B: 24-hour, BCD mode
        0x0C => 0x00, // Status C: no interrupt source
        0x0D => 0x80, // Status D: battery OK
        0x0E => 0x00, // Diagnostic status
        0x0F => 0x00, // Shutdown status
        0x10 => 0x00, // Floppy drive type
        0x12 => 0x00, // Hard drive type
        0x15 => 0x80, // Base memory low byte (640KB = 0x0280)
        0x16 => 0x02, // Base memory high byte
        0x17 => 0x00, // Extended memory low (kernel uses E820)
        0x18 => 0x00, // Extended memory high
        0x32 => t.century,
        _ => 0x00,
    }
}

/// Result of creating devices from a VmContext.
pub struct DeviceSetup {
    /// The device manager.
    pub devices: DeviceManager,
    /// MMIO slots to include in the kernel command line.
    pub mmio_slots: Vec<MmioSlot>,
    /// Whether a root disk is present.
    pub has_root_disk: bool,
    /// Shared console output buffer (captures all serial output).
    pub console_buffer: ConsoleBuffer,
}

/// Centralized device manager for all emulated devices.
pub struct DeviceManager {
    serial: Serial,
    pub pic: Pic,
    pit: Pit,
    cmos_addr: u8,

    /// Virtio-blk device (slot 0) — optional.
    virtio_blk: Option<VirtioMmioDevice<VirtioBlock>>,
    /// Virtio-vsock device (slot 1).
    virtio_vsock: VirtioMmioDevice<VirtioVsock>,
    /// Virtio-9p device (slot 2) — optional.
    virtio_9p: Option<VirtioMmioDevice<Virtio9p>>,
    /// Virtio-net device (slot 3) — optional.
    virtio_net: Option<VirtioMmioDevice<VirtioNet>>,
    /// Second virtio-blk device (slot 4) — optional, for guest rootfs.
    virtio_blk2: Option<VirtioMmioDevice<VirtioBlock>>,

    /// Diagnostic: count QUEUE_NOTIFY writes to blk devices.
    blk_queue_notify_count: u64,
    /// Diagnostic: count block I/O completions drained.
    blk_completion_count: u64,

    /// Track whether we've requested an interrupt window.
    window_requested: bool,
    /// Last PIT tick timestamp.
    last_tick: Instant,
    /// Toggle state for port 0x61 bit 5 (PIT counter 2 output).
    ///
    /// Linux's `pit_calibrate_tsc()` loops reading port 0x61 waiting for
    /// bit 5 to toggle. Without toggling, TSC calibration stalls forever.
    port61_toggle: bool,
    /// ACPI shutdown detected (PM1a_CNT S5 sleep type written).
    shutdown_requested: bool,
}

impl DeviceManager {
    /// Create all devices from a VmContext configuration.
    ///
    /// Returns the device manager plus MMIO slot info for the kernel cmdline.
    pub fn from_context(ctx: &VmContext) -> Result<DeviceSetup> {
        // Serial console with capture buffer.
        let console_buffer: ConsoleBuffer = Arc::new(Mutex::new(Vec::new()));
        let serial = if let Some(ref path) = ctx.console_output {
            let file = File::create(path).map_err(|e| {
                WkrunError::Device(format!(
                    "failed to create console output '{}': {}",
                    path.display(),
                    e
                ))
            })?;
            let tee = TeeWriter {
                inner: Box::new(file),
                buffer: console_buffer.clone(),
            };
            Serial::new(COM1_BASE, Box::new(tee))
        } else {
            let tee = TeeWriter {
                inner: Box::new(std::io::stdout()),
                buffer: console_buffer.clone(),
            };
            Serial::new(COM1_BASE, Box::new(tee))
        };

        // Virtio-blk (slot 0) — first disk (container rootfs).
        let has_root_disk = !ctx.disks.is_empty();
        let virtio_blk = if let Some(disk) = ctx.disks.first() {
            let backend = open_disk_backend(&disk.path, disk.format, disk.read_only)?;
            let blk = VirtioBlock::new(backend, disk.read_only);
            Some(VirtioMmioDevice::new(blk))
        } else {
            None
        };

        // Virtio-blk2 (slot 4) — second disk (guest rootfs), if present.
        let virtio_blk2 = if let Some(disk) = ctx.disks.get(1) {
            let backend = open_disk_backend(&disk.path, disk.format, disk.read_only)?;
            let blk = VirtioBlock::new(backend, disk.read_only);
            Some(VirtioMmioDevice::new(blk))
        } else {
            None
        };

        // Virtio-vsock (slot 1) — always present.
        let mut vsock_backend = VirtioVsock::new(GUEST_CID);
        // Configure ports: listen=true creates TCP listener (host→guest),
        // listen=false registers outbound target (guest→host).
        if ctx.vsock_ports.is_empty() {
            for &port in DEFAULT_VSOCK_PORTS {
                let _ = vsock_backend.listen(port);
            }
        } else {
            for vp in &ctx.vsock_ports {
                // Resolve the host TCP address from either:
                // 1. Explicit host_tcp_port (set by boot_kernel CLI)
                // 2. host_path as "host:port" string (set by krun_add_vsock_port2 API)
                // 3. Fallback: vsock port number as TCP port
                let host_addr = if let Some(tcp_port) = vp.host_tcp_port {
                    format!("127.0.0.1:{}", tcp_port)
                } else {
                    let path_str = vp.host_path.to_string_lossy();
                    if path_str.contains(':') {
                        // host_path is "host:port" format (e.g., "127.0.0.1:55008")
                        path_str.to_string()
                    } else {
                        format!("127.0.0.1:{}", vp.port)
                    }
                };
                if vp.listen {
                    // Parse port from host_addr for listen_on
                    let port = host_addr
                        .rsplit(':')
                        .next()
                        .and_then(|s| s.parse::<u16>().ok())
                        .unwrap_or(vp.port as u16);
                    let _ = vsock_backend.listen_on(vp.port, port);
                } else {
                    vsock_backend.connect_to(vp.port, host_addr);
                }
            }
        }
        let virtio_vsock = VirtioMmioDevice::new(vsock_backend);

        // Virtio-9p (slot 2) — optional, from fs_mounts.
        let virtio_9p = ctx.fs_mounts.first().map(|mount| {
            let p9 = Virtio9p::new(&mount.tag, mount.host_path.clone(), false);
            VirtioMmioDevice::new(p9)
        });

        // Virtio-net (slot 3) — optional, from net_config.
        let virtio_net = if let Some(ref net_cfg) = ctx.net_config {
            let transport = Self::connect_net_transport(&net_cfg.socket_path)?;
            let net = VirtioNet::new(net_cfg.mac, transport);
            Some(VirtioMmioDevice::new(net))
        } else {
            None
        };

        // Build MMIO slots for kernel cmdline.
        let mmio_slots = vec![
            MmioSlot {
                index: 0,
                active: virtio_blk.is_some(),
            },
            MmioSlot {
                index: 1,
                active: true,
            }, // vsock always active
            MmioSlot {
                index: 2,
                active: virtio_9p.is_some(),
            },
            MmioSlot {
                index: 3,
                active: virtio_net.is_some(),
            },
            MmioSlot {
                index: 4,
                active: virtio_blk2.is_some(),
            },
        ];

        let devices = DeviceManager {
            serial,
            pic: Pic::new(),
            pit: Pit::new(),
            cmos_addr: 0,
            virtio_blk,
            virtio_vsock,
            virtio_9p,
            virtio_net,
            virtio_blk2,
            blk_queue_notify_count: 0,
            blk_completion_count: 0,
            window_requested: false,
            last_tick: Instant::now(),
            port61_toggle: false,
            shutdown_requested: false,
        };

        Ok(DeviceSetup {
            devices,
            mmio_slots,
            has_root_disk,
            console_buffer,
        })
    }

    /// Handle an I/O port output (write) from the guest.
    ///
    /// Returns `true` if skip_instruction should be called after.
    pub fn handle_io_out(&mut self, port: u16, size: u8, data: u32) {
        if self.serial.handles_port(port) {
            self.serial.io_write(port, size, data);
            if self.serial.has_interrupt() {
                self.pic.raise_irq(4);
            }
        } else if self.pic.handles_port(port) {
            log::trace!("PIC write: port={:#X} data={:#X}", port, data as u8);
            self.pic.write_port(port, data as u8);
        } else if self.pit.handles_port(port) {
            log::trace!("PIT write: port={:#X} data={:#X}", port, data as u8);
            self.pit.write_port(port, data as u8);
        } else if port == PM1A_CNT_BLK {
            // ACPI PM1a control register: detect S5 shutdown.
            // SLP_EN = bit 13, SLP_TYP = bits 12:10.
            let slp_en = (data >> 13) & 1;
            let slp_typ = (data >> 10) & 0x7;
            if slp_en == 1 && slp_typ == 5 {
                log::info!("ACPI S5 shutdown detected (PM1a_CNT={:#X})", data);
                self.shutdown_requested = true;
            }
        } else if port == 0x70 {
            self.cmos_addr = (data as u8) & 0x7F;
        }
        // Ignore writes to other ports (PS/2, etc.).
    }

    /// Handle an I/O port input (read) from the guest.
    ///
    /// Returns the data to inject into the guest register.
    pub fn handle_io_in(&mut self, port: u16, size: u8) -> u32 {
        if self.serial.handles_port(port) {
            let val = self.serial.io_read(port, size);
            if self.serial.has_interrupt() {
                self.pic.raise_irq(4);
            }
            val
        } else if self.pic.handles_port(port) {
            self.pic.read_port(port) as u32
        } else if self.pit.handles_port(port) {
            self.pit.read_port(port) as u32
        } else if port == 0x71 {
            cmos_read(self.cmos_addr) as u32
        } else if (PM1A_EVT_BLK..PM1A_EVT_BLK + 4).contains(&port) {
            0x00 // PM1a event: no events pending
        } else if (PM1A_CNT_BLK..PM1A_CNT_BLK + 2).contains(&port) {
            0x00 // PM1a control: clear state
        } else if (0xCF8..=0xCFF).contains(&port) {
            0xFFFF_FFFF // PCI config: no devices.
        } else if port == 0x61 {
            // System control port B: toggle bit 5 (PIT counter 2 output).
            //
            // Linux's `pit_calibrate_tsc()` reads this port in a tight loop
            // waiting for bit 5 to change. A static value causes an infinite
            // loop that stalls kernel boot. Toggling on each read lets the
            // calibration complete.
            self.port61_toggle = !self.port61_toggle;
            if self.port61_toggle {
                0x20
            } else {
                0x00
            }
        } else if port == 0x92 {
            0x02 // System control port A: A20 enabled.
        } else if port == 0x60 || port == 0x64 {
            // i8042 PS/2 controller: data (0x60) and status (0x64).
            //
            // Return 0x00 = both buffers empty, no pending data.
            // Without this, the default 0xFF makes the i8042 driver spin in
            // udelay() loops waiting for the input buffer to drain.
            0x00
        } else {
            0xFF // Default: no device.
        }
    }

    /// Handle an MMIO read from the guest.
    ///
    /// Returns the data to inject into the destination register.
    pub fn handle_mmio_read(&self, address: u64, size: u8) -> u64 {
        let blk_offset = address.wrapping_sub(mmio_base_for_slot(0));
        let vsock_offset = address.wrapping_sub(mmio_base_for_slot(1));
        let p9_offset = address.wrapping_sub(mmio_base_for_slot(2));
        let net_offset = address.wrapping_sub(mmio_base_for_slot(3));
        let blk2_offset = address.wrapping_sub(mmio_base_for_slot(4));

        if blk_offset < MMIO_SLOT_SIZE {
            if let Some(ref dev) = self.virtio_blk {
                dev.read(blk_offset, size) as u64
            } else {
                0
            }
        } else if vsock_offset < MMIO_SLOT_SIZE {
            self.virtio_vsock.read(vsock_offset, size) as u64
        } else if p9_offset < MMIO_SLOT_SIZE {
            if let Some(ref dev) = self.virtio_9p {
                dev.read(p9_offset, size) as u64
            } else {
                0
            }
        } else if net_offset < MMIO_SLOT_SIZE {
            if let Some(ref dev) = self.virtio_net {
                dev.read(net_offset, size) as u64
            } else {
                0
            }
        } else if blk2_offset < MMIO_SLOT_SIZE {
            if let Some(ref dev) = self.virtio_blk2 {
                dev.read(blk2_offset, size) as u64
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Handle an MMIO write from the guest.
    ///
    /// Returns `true` if an interrupt should be raised.
    pub fn handle_mmio_write(
        &mut self,
        address: u64,
        size: u8,
        data: u64,
        mem: &dyn GuestMemoryAccessor,
    ) {
        let blk_offset = address.wrapping_sub(mmio_base_for_slot(0));
        let vsock_offset = address.wrapping_sub(mmio_base_for_slot(1));
        let p9_offset = address.wrapping_sub(mmio_base_for_slot(2));
        let net_offset = address.wrapping_sub(mmio_base_for_slot(3));
        let blk2_offset = address.wrapping_sub(mmio_base_for_slot(4));

        if blk_offset < MMIO_SLOT_SIZE {
            if blk_offset == 0x050 {
                self.blk_queue_notify_count += 1;
            }
            if let Some(ref mut dev) = self.virtio_blk {
                if dev.write(blk_offset, data as u32, size, mem) {
                    self.pic.raise_irq(irq_for_slot(0));
                }
            }
        } else if vsock_offset < MMIO_SLOT_SIZE {
            if self
                .virtio_vsock
                .write(vsock_offset, data as u32, size, mem)
            {
                self.pic.raise_irq(irq_for_slot(1));
            }
        } else if p9_offset < MMIO_SLOT_SIZE {
            if let Some(ref mut dev) = self.virtio_9p {
                if dev.write(p9_offset, data as u32, size, mem) {
                    self.pic.raise_irq(irq_for_slot(2));
                }
            }
        } else if net_offset < MMIO_SLOT_SIZE {
            if let Some(ref mut dev) = self.virtio_net {
                if dev.write(net_offset, data as u32, size, mem) {
                    self.pic.raise_irq(irq_for_slot(3));
                }
            }
        } else if blk2_offset < MMIO_SLOT_SIZE {
            if blk2_offset == 0x050 {
                self.blk_queue_notify_count += 1;
            }
            if let Some(ref mut dev) = self.virtio_blk2 {
                if dev.write(blk2_offset, data as u32, size, mem) {
                    self.pic.raise_irq(irq_for_slot(4));
                }
            }
        }
    }

    /// Start async block I/O workers for virtio-blk devices (Plan B: WHPX-safe).
    ///
    /// Workers never access guest memory — all guest memory I/O happens
    /// on the vCPU thread (in queue_notify and drain_completions).
    pub fn start_blk_workers(&mut self) {
        if let Some(ref mut dev) = self.virtio_blk {
            dev.backend_mut().start_worker("blk-worker-0");
        }
        if let Some(ref mut dev) = self.virtio_blk2 {
            dev.backend_mut().start_worker("blk-worker-1");
        }
    }

    /// Stop async block I/O workers.
    ///
    /// Called during shutdown. Also called by Drop if not explicitly called.
    pub fn stop_blk_workers(&mut self) {
        if let Some(ref mut dev) = self.virtio_blk {
            dev.backend_mut().stop_worker();
        }
        if let Some(ref mut dev) = self.virtio_blk2 {
            dev.backend_mut().stop_worker();
        }
    }

    /// Tick the PIT timer based on wall clock time and poll devices.
    ///
    /// Call this at the top of each vCPU run loop iteration.
    pub fn tick_and_poll(&mut self, mem: &dyn GuestMemoryAccessor) {
        // Tick PIT.
        let now = Instant::now();
        let elapsed_ns = now.duration_since(self.last_tick).as_nanos() as u64;
        self.last_tick = now;

        if elapsed_ns > 0 {
            let fires = self.pit.tick(elapsed_ns);
            for _ in 0..fires {
                self.pic.raise_irq(0);
            }
        }

        // Drain async block I/O completions.
        if let Some(ref mut dev) = self.virtio_blk {
            if dev.poll_backend(mem) {
                self.blk_completion_count += 1;
                self.pic.raise_irq(irq_for_slot(0));
            }
        }
        if let Some(ref mut dev) = self.virtio_blk2 {
            if dev.poll_backend(mem) {
                self.blk_completion_count += 1;
                self.pic.raise_irq(irq_for_slot(4));
            }
        }

        // Poll vsock for host-initiated data.
        if self.virtio_vsock.poll(mem) {
            log::debug!("vsock poll raised IRQ {}", irq_for_slot(1));
            self.pic.raise_irq(irq_for_slot(1));
        }

        // Poll net for incoming frames.
        if let Some(ref mut dev) = self.virtio_net {
            if dev.poll(mem) {
                self.pic.raise_irq(irq_for_slot(3));
            }
        }
    }

    /// Connect to the userspace networking proxy and return a transport.
    ///
    /// On Unix: connects via Unix stream socket.
    /// On Windows: parses "host:port" and connects via TCP.
    fn connect_net_transport(
        socket_path: &Path,
    ) -> Result<Option<Box<dyn super::virtio::net::NetTransport>>> {
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
                WkrunError::Device(format!(
                    "failed to connect to net socket '{}': {}",
                    socket_path.display(),
                    e
                ))
            })?;
            let transport = super::virtio::net::UnixStreamTransport::new(stream).map_err(|e| {
                WkrunError::Device(format!("failed to configure net socket: {}", e))
            })?;
            Ok(Some(Box::new(transport)))
        }
        #[cfg(not(unix))]
        {
            let addr = socket_path.to_string_lossy();
            let stream = std::net::TcpStream::connect(addr.as_ref()).map_err(|e| {
                WkrunError::Device(format!("failed to connect to net proxy '{}': {}", addr, e))
            })?;
            let transport = super::virtio::net::TcpTransport::new(stream).map_err(|e| {
                WkrunError::Device(format!("failed to configure net socket: {}", e))
            })?;
            Ok(Some(Box::new(transport)))
        }
    }

    /// Return block I/O diagnostic counters: (queue_notify_count, completion_count).
    pub fn blk_stats(&self) -> (u64, u64) {
        (self.blk_queue_notify_count, self.blk_completion_count)
    }

    /// Whether an ACPI S5 shutdown was detected.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Whether an interrupt window has been requested.
    pub fn window_requested(&self) -> bool {
        self.window_requested
    }

    /// Set the interrupt window requested flag.
    pub fn set_window_requested(&mut self, requested: bool) {
        self.window_requested = requested;
    }
}

/// Create a `DeviceManager` from explicit components (for testing).
pub fn device_manager_with_serial(serial: Serial) -> DeviceManager {
    let vsock_backend = VirtioVsock::new(GUEST_CID);
    DeviceManager {
        serial,
        pic: Pic::new(),
        pit: Pit::new(),
        cmos_addr: 0,
        virtio_blk: None,
        virtio_vsock: VirtioMmioDevice::new(vsock_backend),
        virtio_9p: None,
        virtio_net: None,
        virtio_blk2: None,
        blk_queue_notify_count: 0,
        blk_completion_count: 0,
        window_requested: false,
        last_tick: Instant::now(),
        port61_toggle: false,
        shutdown_requested: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Capture buffer for serial output in tests.
    #[derive(Clone)]
    struct CaptureSink {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl CaptureSink {
        fn new() -> Self {
            CaptureSink {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn contents(&self) -> Vec<u8> {
            self.buf.lock().unwrap().clone()
        }
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn make_test_devices() -> DeviceManager {
        let serial = Serial::new(COM1_BASE, Box::new(std::io::sink()));
        device_manager_with_serial(serial)
    }

    #[test]
    fn test_io_out_serial_write() {
        let sink = CaptureSink::new();
        let serial = Serial::new(COM1_BASE, Box::new(sink.clone()));
        let mut dm = device_manager_with_serial(serial);

        // Write 'A' to THR (port 0x3F8).
        dm.handle_io_out(0x3F8, 1, b'A' as u32);
        assert_eq!(sink.contents(), b"A");
    }

    #[test]
    fn test_io_in_serial_lsr() {
        let mut dm = make_test_devices();
        // Read LSR (port 0x3FD) — should report transmitter empty.
        let lsr = dm.handle_io_in(0x3FD, 1);
        // LSR bit 5 (THRE) and bit 6 (TEMT) should be set.
        assert_ne!(lsr & 0x60, 0);
    }

    #[test]
    fn test_io_in_pci_config_no_devices() {
        let mut dm = make_test_devices();
        let data = dm.handle_io_in(0xCF8, 4);
        assert_eq!(data, 0xFFFF_FFFF);
    }

    #[test]
    fn test_io_in_system_control_port_b_toggles() {
        let mut dm = make_test_devices();
        // Port 0x61 bit 5 toggles on each read.
        let first = dm.handle_io_in(0x61, 1);
        let second = dm.handle_io_in(0x61, 1);
        assert_ne!(first, second, "bit 5 should toggle");
        let third = dm.handle_io_in(0x61, 1);
        assert_eq!(first, third, "should cycle back");
    }

    #[test]
    fn test_io_in_system_control_port_a() {
        let mut dm = make_test_devices();
        assert_eq!(dm.handle_io_in(0x92, 1), 0x02);
    }

    #[test]
    fn test_io_in_i8042_status_empty() {
        let mut dm = make_test_devices();
        // Port 0x64 (i8042 status): both buffers empty.
        assert_eq!(dm.handle_io_in(0x64, 1), 0x00);
        // Port 0x60 (i8042 data): no data.
        assert_eq!(dm.handle_io_in(0x60, 1), 0x00);
    }

    #[test]
    fn test_io_in_unknown_port() {
        let mut dm = make_test_devices();
        assert_eq!(dm.handle_io_in(0x999, 1), 0xFF);
    }

    #[test]
    fn test_to_bcd() {
        assert_eq!(to_bcd(0), 0x00);
        assert_eq!(to_bcd(9), 0x09);
        assert_eq!(to_bcd(10), 0x10);
        assert_eq!(to_bcd(26), 0x26);
        assert_eq!(to_bcd(59), 0x59);
        assert_eq!(to_bcd(99), 0x99);
    }

    #[test]
    fn test_cmos_time_now_is_reasonable() {
        let t = CmosTime::now();
        // Year should be 2025–2099 in BCD (0x25..0x99).
        assert!(t.year >= 0x25, "year BCD too low: {:#04x}", t.year);
        // Month 1..12 in BCD (0x01..0x12).
        assert!(t.month >= 0x01 && t.month <= 0x12, "month: {:#04x}", t.month);
        // Day 1..31 in BCD.
        assert!(t.day_of_month >= 0x01 && t.day_of_month <= 0x31);
        // Hours 0..23 in BCD.
        assert!(t.hours <= 0x23);
        // Century should be 0x20.
        assert_eq!(t.century, 0x20);
    }

    #[test]
    fn test_cmos_read_via_io() {
        let mut dm = make_test_devices();
        // Select CMOS register 0x09 (year).
        dm.handle_io_out(0x70, 1, 0x09);
        let year = dm.handle_io_in(0x71, 1);
        // Year must be valid BCD (>= 0x25 for 2025+).
        assert!(year >= 0x25, "year BCD: {:#04x}", year);
    }

    #[test]
    fn test_cmos_read_battery_ok() {
        let mut dm = make_test_devices();
        dm.handle_io_out(0x70, 1, 0x0D);
        let status_d = dm.handle_io_in(0x71, 1);
        assert_eq!(status_d, 0x80);
    }

    #[test]
    fn test_mmio_read_no_blk_device() {
        let dm = make_test_devices();
        // Read from virtio-blk slot when no device present.
        let data = dm.handle_mmio_read(mmio_base_for_slot(0), 4);
        assert_eq!(data, 0);
    }

    #[test]
    fn test_mmio_read_vsock_magic() {
        let dm = make_test_devices();
        // Read virtio magic from vsock MMIO slot.
        let magic = dm.handle_mmio_read(mmio_base_for_slot(1), 4);
        assert_eq!(magic, 0x7472_6976); // "virt" in LE.
    }

    #[test]
    fn test_mmio_read_vsock_device_id() {
        let dm = make_test_devices();
        // Device ID is at offset 0x008.
        let device_id = dm.handle_mmio_read(mmio_base_for_slot(1) + 0x008, 4);
        assert_eq!(device_id, 19); // vsock device ID.
    }

    #[test]
    fn test_mmio_read_out_of_range() {
        let dm = make_test_devices();
        // Read from an address that doesn't belong to any device.
        let data = dm.handle_mmio_read(0xE000_0000, 4);
        assert_eq!(data, 0);
    }

    #[test]
    fn test_window_requested_default() {
        let dm = make_test_devices();
        assert!(!dm.window_requested());
    }

    #[test]
    fn test_window_requested_toggle() {
        let mut dm = make_test_devices();
        dm.set_window_requested(true);
        assert!(dm.window_requested());
        dm.set_window_requested(false);
        assert!(!dm.window_requested());
    }

    #[test]
    fn test_tee_writer() {
        let inner_buf = Arc::new(Mutex::new(Vec::new()));
        let capture_buf: ConsoleBuffer = Arc::new(Mutex::new(Vec::new()));

        let inner = CaptureSink {
            buf: inner_buf.clone(),
        };
        let mut tee = super::TeeWriter {
            inner: Box::new(inner),
            buffer: capture_buf.clone(),
        };

        tee.write_all(b"Hello").unwrap();
        tee.write_all(b", VM!").unwrap();
        tee.flush().unwrap();

        // Both sinks should have the same content.
        assert_eq!(inner_buf.lock().unwrap().as_slice(), b"Hello, VM!");
        assert_eq!(capture_buf.lock().unwrap().as_slice(), b"Hello, VM!");
    }

    #[test]
    fn test_console_buffer_store_and_get() {
        let buf: ConsoleBuffer = Arc::new(Mutex::new(Vec::new()));
        buf.lock().unwrap().extend_from_slice(b"test output");

        let ctx_id = 90000; // Unique ID to avoid conflicts.
        super::store_console_buffer(ctx_id, buf);

        let output = super::get_console_output(ctx_id).unwrap();
        assert_eq!(output, b"test output");

        // Cleanup.
        super::remove_console_buffer(ctx_id);
        assert!(super::get_console_output(ctx_id).is_none());
    }

    #[test]
    fn test_console_buffer_not_found() {
        assert!(super::get_console_output(89999).is_none());
    }

    #[test]
    fn test_from_context_has_console_buffer() {
        let ctx = VmContext::default_for_test();
        let setup = DeviceManager::from_context(&ctx).unwrap();
        // Buffer should be empty initially.
        assert!(setup.console_buffer.lock().unwrap().is_empty());
    }

    #[test]
    fn test_from_context_minimal() {
        let ctx = VmContext::default_for_test();
        let setup = DeviceManager::from_context(&ctx).unwrap();
        assert!(!setup.has_root_disk);
        // Slot 0 (blk) inactive, slot 1 (vsock) active, slot 2 (9p) inactive.
        assert!(!setup.mmio_slots[0].active);
        assert!(setup.mmio_slots[1].active);
        assert!(!setup.mmio_slots[2].active);
    }

    #[test]
    fn test_from_context_with_fs_mount() {
        let mut ctx = VmContext::default_for_test();
        ctx.fs_mounts.push(super::super::super::context::FsMount {
            tag: "test".to_string(),
            host_path: PathBuf::from("/tmp"),
        });
        let setup = DeviceManager::from_context(&ctx).unwrap();
        // Slot 2 (9p) should now be active.
        assert!(setup.mmio_slots[2].active);
    }

    #[test]
    fn test_from_context_net_slot_inactive_by_default() {
        let ctx = VmContext::default_for_test();
        let setup = DeviceManager::from_context(&ctx).unwrap();
        // Slot 3 (net) should be inactive when no net_config.
        assert!(!setup.mmio_slots[3].active);
    }

    #[test]
    fn test_mmio_read_no_net_device() {
        let dm = make_test_devices();
        // Read from virtio-net slot when no device present.
        let data = dm.handle_mmio_read(mmio_base_for_slot(3), 4);
        assert_eq!(data, 0);
    }

    #[test]
    fn test_acpi_shutdown_not_requested_initially() {
        let dm = make_test_devices();
        assert!(!dm.shutdown_requested());
    }

    #[test]
    fn test_acpi_s5_shutdown_detected() {
        let mut dm = make_test_devices();
        // Write SLP_TYP=5, SLP_EN=1 → bits 12:10 = 0b101, bit 13 = 1.
        // Value = (1 << 13) | (5 << 10) = 0x2000 | 0x1400 = 0x3400.
        dm.handle_io_out(0x604, 2, 0x3400);
        assert!(dm.shutdown_requested());
    }

    #[test]
    fn test_acpi_non_s5_write_ignored() {
        let mut dm = make_test_devices();
        // SLP_EN=1, SLP_TYP=0 → not S5.
        dm.handle_io_out(0x604, 2, 0x2000);
        assert!(!dm.shutdown_requested());
    }

    #[test]
    fn test_acpi_pm1a_evt_read_zero() {
        let mut dm = make_test_devices();
        assert_eq!(dm.handle_io_in(0x600, 4), 0x00);
    }

    #[test]
    fn test_acpi_pm1a_cnt_read_zero() {
        let mut dm = make_test_devices();
        assert_eq!(dm.handle_io_in(0x604, 2), 0x00);
    }
}
