// SPDX-License-Identifier: Apache-2.0

//! Boot preparation without KVM: layout, boot parameters, command line,
//! device discovery and refusals. `kvm_tests` boots real Linux guests.

use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

use arch::x86_64::layout::{EBDA_START, HIMEM_START, ZERO_PAGE_START};
use arch_gen::x86::bootparam::{boot_params, E820_RAM};
use devices::virtio::block::{ImageType, SyncMode};
use devices::virtio::net::device::VirtioNetBackend;
use devices::virtio::{CacheType, TsiFlags};
use vm_memory::mmap::MmapRegion;
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

use super::*;
use crate::vmm_config::fs::FsDeviceConfig;
use crate::vmm_config::kernel_bundle::KernelBundle;
use crate::vmm_config::kernel_cmdline::{KernelCmdlineConfig, DEFAULT_KERNEL_CMDLINE};
use crate::vmm_config::machine_config::VmConfig;

const KERNEL_GPA: u64 = 0x100_0000;
const KERNEL_LEN: usize = 0x2000;
const MIB: u64 = 1 << 20;

pub(super) struct TempDir(pub(super) PathBuf);

impl TempDir {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krun-boot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What BoxLite configures for a disk-root box: libkrunfw's kernel, the
/// VM-owned `/dev/root` boot share with its 512 MiB window, a user share,
/// a console output file, the init command line and DHCP.
struct Config {
    dir: TempDir,
    /// libkrunfw's kernel mapping, as `KernelBundle::host_addr` names it.
    kernel: MmapRegion<()>,
    resources: VmResources,
}

impl Config {
    fn new(mem_size_mib: usize) -> Self {
        let dir = TempDir::new();
        let kernel = MmapRegion::<()>::new(KERNEL_LEN).unwrap();
        // SAFETY: this owned mapping is writable and used only here.
        unsafe { std::ptr::write_bytes(kernel.as_ptr(), 0x6b, KERNEL_LEN) };
        let mut resources = VmResources::default();
        resources
            .set_vm_config(&VmConfig {
                vcpu_count: Some(2),
                mem_size_mib: Some(mem_size_mib),
                ht_enabled: Some(false),
                cpu_template: None,
            })
            .unwrap();
        resources.kernel_bundle = Some(KernelBundle {
            host_addr: kernel.as_ptr() as u64,
            guest_addr: KERNEL_GPA,
            entry_addr: KERNEL_GPA + 0x200,
            size: KERNEL_LEN,
        });
        resources.kernel_cmdline = KernelCmdlineConfig {
            prolog: Some(format!("{DEFAULT_KERNEL_CMDLINE} init=/init.krun")),
            krun_env: Some("KRUN_INIT=/sbin/init KRUN_BLOCK_ROOT_DEVICE=/dev/vda".into()),
            epilog: Some("-- arg".into()),
        };
        resources.dhcp_client = true;
        fs::create_dir(dir.path("root")).unwrap();
        fs::create_dir(dir.path("user")).unwrap();
        resources.add_fs_device(FsDeviceConfig {
            fs_id: "/dev/root".into(),
            shared_dir: dir.path("root").to_str().unwrap().into(),
            shm_size: Some(1 << 29),
            allow_root_dir_delete: true,
            read_only: false,
            vm_owned: true,
        });
        resources.add_fs_device(FsDeviceConfig {
            fs_id: "user".into(),
            shared_dir: dir.path("user").to_str().unwrap().into(),
            shm_size: None,
            allow_root_dir_delete: false,
            read_only: true,
            vm_owned: false,
        });
        resources.set_console_output(dir.path("console.log"));
        Self {
            dir,
            kernel,
            resources,
        }
    }

    /// Two disks, the UnixStream NIC and the IPC vsock BoxLite configures.
    fn devices(&self) -> BootDevices {
        let disk = |name: &str, read_only| BlockDeviceConfig {
            block_id: name.into(),
            cache_type: CacheType::Writeback,
            disk_image_path: self.dir.path(name).to_str().unwrap().into(),
            disk_image_format: ImageType::Raw,
            is_disk_read_only: read_only,
            direct_io: false,
            sync_mode: SyncMode::Full,
        };
        BootDevices {
            disks: vec![disk("root.raw", true), disk("data.raw", false)],
            nic: Some(NetworkInterfaceConfig {
                iface_id: "eth0".into(),
                backend: VirtioNetBackend::UnixstreamPath(self.dir.path("passt.sock")),
                mac: [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee],
                features: 0,
            }),
            vsock: Some(VsockDeviceConfig {
                vsock_id: "vsock0".into(),
                guest_cid: 3,
                host_port_map: None,
                unix_ipc_port_map: Some(HashMap::from([
                    (2695, (self.dir.path("grpc.sock"), true)),
                    (2696, (self.dir.path("ready.sock"), false)),
                ])),
                tsi_flags: TsiFlags::empty(),
            }),
        }
    }
}

/// The NUL-terminated command line the guest finds at `CMDLINE_START`.
fn cmdline_of(memory: &GuestMemoryMmap) -> String {
    let mut bytes = vec![0; arch::CMDLINE_MAX_SIZE];
    memory
        .read_slice(&mut bytes, GuestAddress(CMDLINE_START))
        .unwrap();
    let end = bytes.iter().position(|byte| *byte == 0).unwrap();
    String::from_utf8(bytes[..end].to_vec()).unwrap()
}

fn boot_params_of(memory: &GuestMemoryMmap) -> boot_params {
    let mut bytes = vec![0u8; std::mem::size_of::<boot_params>()];
    memory
        .read_slice(&mut bytes, GuestAddress(ZERO_PAGE_START))
        .unwrap();
    // SAFETY: `boot_params` is plain old data of exactly this size.
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) }
}

/// The kernel is copied into ordinary owned RAM (no raw libkrunfw alias),
/// the E820 map covers exactly that RAM and leaves the DAX window out, and
/// the window lies above RAM at the ordinary VMM's address.
#[test]
fn snapshot_boot_copies_the_kernel_into_owned_ram_with_an_e820_map_and_a_separate_dax_window() {
    let config = Config::new(64);
    let image = BootImage::new(&config.resources, config.devices()).unwrap();

    let ram_end = KERNEL_GPA + KERNEL_LEN as u64 + 64 * MIB;
    let regions: Vec<_> = image
        .memory
        .iter()
        .map(|region| (region.start_addr().raw_value(), region.len()))
        .collect();
    assert_eq!(
        regions,
        [(0, ram_end)],
        "the kernel hole is filled and merged"
    );
    Topology::default()
        .regions(&image.memory)
        .expect("only ordinary owned RAM, no raw kernel mapping");
    let mut copied = vec![0; KERNEL_LEN];
    image
        .memory
        .read_slice(&mut copied, GuestAddress(KERNEL_GPA))
        .unwrap();
    assert!(copied.iter().all(|byte| *byte == 0x6b));
    // SAFETY: the test's own mapping; the guest's copy must not alias it.
    unsafe { std::ptr::write_bytes(config.kernel.as_ptr(), 0, KERNEL_LEN) };
    image
        .memory
        .read_slice(&mut copied, GuestAddress(KERNEL_GPA))
        .unwrap();
    assert!(copied.iter().all(|byte| *byte == 0x6b));
    assert_eq!(image.entry, GuestAddress(KERNEL_GPA + 0x200));

    let params = boot_params_of(&image.memory);
    let entries: Vec<_> = params.e820_map[..params.e820_entries as usize]
        .iter()
        .map(|entry| (entry.addr, entry.size, entry.type_))
        .collect();
    assert_eq!(
        entries,
        [
            (0, EBDA_START, E820_RAM),
            (HIMEM_START, ram_end - HIMEM_START + 1, E820_RAM),
        ]
    );
    let window = image.shares[0].dax.unwrap();
    assert_eq!(
        window,
        DaxRange {
            gpa: 1 << 32,
            len: 1 << 29
        }
    );
    assert!(entries
        .iter()
        .all(|(addr, size, _)| addr + size <= window.gpa));
    assert!(image.shares[0].vm_owned && image.shares[0].allow_root_dir_delete);
    assert!(image.shares[1].dax.is_none() && !image.shares[1].vm_owned);
    assert_eq!({ params.hdr.cmd_line_ptr }, CMDLINE_START as u32);
    assert_eq!(
        { params.hdr.cmdline_size },
        cmdline_of(&image.memory).len() as u32 + 1
    );
    // Nothing of the VM exists yet: not even the console file.
    assert!(!config.dir.path("console.log").exists());
}

/// Every device appears at its fixed owner slot in the ordinary VMM's
/// probe order (balloon, RNG, console, shares, disks in guest order, vsock,
/// NIC), between the krun environment and the init arguments.
#[test]
fn snapshot_boot_command_line_announces_every_device_in_the_ordinary_probe_order() {
    let config = Config::new(64);
    let image = BootImage::new(&config.resources, config.devices()).unwrap();
    let devices = [
        "0xd000a000:6",
        "0xd0009000:5",
        "0xd000c000:8",
        "0xd000d000:9",
        "0xd000e000:10",
        "0xd0000000:16",
        "0xd0001000:17",
        "0xd000b000:7",
        "0xd0008000:23",
    ]
    .map(|slot| format!("virtio_mmio.device=4K@{slot}"))
    .join(" ");
    let expected = format!(
        "{DEFAULT_KERNEL_CMDLINE} init=/init.krun KRUN_INIT=/sbin/init \
         KRUN_BLOCK_ROOT_DEVICE=/dev/vda {devices} KRUN_DHCP=1 -- arg"
    );
    assert_eq!(cmdline_of(&image.memory), expected);
    assert_eq!(image.slots.len(), 9);

    // Without a NIC, console or shares the remaining devices keep order.
    let mut bare = Config::new(64);
    bare.resources.disable_implicit_console = true;
    bare.resources.fs.clear();
    let mut devices = bare.devices();
    devices.nic = None;
    let image = BootImage::new(&bare.resources, devices).unwrap();
    assert_eq!(
        image.slots,
        [
            (0xd000_a000, 6),
            (0xd000_9000, 5),
            (0xd000_0000, 16),
            (0xd000_1000, 17),
            (0xd000_b000, 7),
        ]
    );
}

/// RAM beyond the 32-bit device window continues above 4 GiB; the DAX
/// window moves to the next GiB above it, as on the ordinary VMM.
#[test]
fn snapshot_boot_large_ram_skips_the_device_window_and_moves_the_dax_window_above_it() {
    let config = Config::new(4096);
    let image = BootImage::new(&config.resources, config.devices()).unwrap();
    let regions: Vec<_> = image
        .memory
        .iter()
        .map(|region| (region.start_addr().raw_value(), region.len()))
        .collect();
    let above = 4096 * MIB - MMIO_MEM_START;
    assert_eq!(
        regions,
        [(0, MMIO_MEM_START), (FIRST_ADDR_PAST_32BITS, above)]
    );
    let ram_end = FIRST_ADDR_PAST_32BITS + above;
    let window = image.shares[0].dax.unwrap();
    assert_eq!(window.gpa, (ram_end / (1 << 30) + 1) << 30);
}

/// Every configuration the owner cannot checkpoint is refused by name
/// before anything exists; nothing is silently dropped.
#[test]
fn snapshot_boot_refuses_unsupported_configuration_before_creating_anything() {
    type Change = fn(&mut Config, &mut BootDevices);
    let cases: [(&str, Change); 20] =
        [
            ("nested virtualization", |c, _| {
                c.resources.nested_enabled = true
            }),
            ("split irqchip", |c, _| c.resources.split_irqchip = true),
            ("firmware", |c, _| {
                c.resources.kernel_bundle = None;
                c.resources.firmware_config = Some(crate::vmm_config::firmware::FirmwareConfig {
                    path: "/nonexistent".into(),
                });
            }),
            ("virtio-gpu", |c, _| c.resources.gpu_virgl_flags = Some(0)),
            ("legacy serial consoles", |c, _| {
                c.resources
                    .serial_consoles
                    .push(crate::resources::SerialConsoleConfig {
                        input_fd: -1,
                        output_fd: -1,
                    })
            }),
            ("additional virtio consoles", |c, _| {
                c.resources.virtio_consoles.push(
                    crate::resources::VirtioConsoleConfigMode::Explicit(Vec::new()),
                )
            }),
            ("console output file", |c, _| {
                c.resources.console_output = None
            }),
            ("vsock must come unopened", |c, d| {
                c.resources
                    .set_vsock_device(d.vsock.clone().unwrap())
                    .unwrap()
            }),
            ("vsock TSI", |_, d| {
                d.vsock.as_mut().unwrap().tsi_flags = TsiFlags::HIJACK_INET
            }),
            ("TCP port maps", |_, d| {
                d.vsock.as_mut().unwrap().host_port_map = Some(HashMap::from([(80, 80)]))
            }),
            ("UnixStream NIC backend", |c, d| {
                d.nic.as_mut().unwrap().backend =
                    VirtioNetBackend::UnixgramPath(c.dir.path("gvproxy.sock"), true)
            }),
            ("direct I/O", |_, d| d.disks[0].direct_io = true),
            ("sync fully", |_, d| {
                d.disks[1].sync_mode = SyncMode::Relaxed
            }),
            ("fixed slots", |_, d| {
                let disk = d.disks[0].clone();
                d.disks.resize(8, disk);
            }),
            ("seven virtio-fs shares", |c, _| {
                let share = c.resources.fs[1].clone();
                c.resources.fs.resize(8, share);
            }),
            ("vCPU count", |c, _| {
                c.resources
                    .set_vm_config(&VmConfig {
                        vcpu_count: Some(130),
                        ..Default::default()
                    })
                    .unwrap()
            }),
            ("does not fit", |c, _| {
                c.resources
                    .set_vm_config(&VmConfig {
                        mem_size_mib: Some(16),
                        ..Default::default()
                    })
                    .unwrap()
            }),
            ("unaligned", |c, _| {
                c.resources.kernel_bundle.as_mut().unwrap().size = KERNEL_LEN - 1
            }),
            ("32-bit device window", |c, _| {
                // The kernel hole pushes 3.25 GiB of RAM past the window start.
                c.resources
                    .set_vm_config(&VmConfig {
                        mem_size_mib: Some((MMIO_MEM_START / MIB) as usize),
                        ..Default::default()
                    })
                    .unwrap()
            }),
            ("the NIC must come unopened", |c, d| {
                c.resources
                    .add_network_interface(d.nic.take().unwrap())
                    .unwrap()
            }),
        ];
    for (expected, change) in cases {
        let mut config = Config::new(64);
        let mut devices = config.devices();
        change(&mut config, &mut devices);
        let error = match BootImage::new(&config.resources, devices) {
            Ok(_) => panic!("{expected}: accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(expected), "{expected}: {error}");
        assert!(!config.dir.path("console.log").exists(), "{expected}");
    }
}

/// An import that fails before it validated its image leaves the caller's
/// console path alone: an existing file keeps its bytes and a missing one
/// is not created.
#[test]
fn snapshot_import_failure_leaves_the_console_output_untouched() {
    use crate::snapshot_vm::{RestoreEndpoints, SnapshotVm};
    let dir = TempDir::new();
    let corrupt = dir.path("corrupt.krunvm");
    fs::write(&corrupt, b"not a checkpoint").unwrap();
    let existing = dir.path("existing.log");
    fs::write(&existing, b"sentinel").unwrap();
    let missing = dir.path("missing.log");
    for (image, console) in [
        (&corrupt, &existing),
        (&dir.path("absent.krunvm"), &existing),
        (&corrupt, &missing),
    ] {
        let endpoints = RestoreEndpoints {
            console_output: Some(console.clone()),
            ..Default::default()
        };
        assert!(SnapshotVm::import(image, endpoints).is_err());
    }
    assert_eq!(fs::read(&existing).unwrap(), b"sentinel");
    assert!(!missing.exists());
}

/// An import creates its console output exclusively: an existing file is
/// refused untouched, and a created one goes again unless the import kept
/// it.
#[test]
fn snapshot_import_console_output_is_created_exclusively_and_removed_unless_kept() {
    let dir = TempDir::new();
    let existing = dir.path("existing.log");
    fs::write(&existing, b"sentinel").unwrap();
    assert!(NewConsoleOutput::create(&existing).is_err());
    assert_eq!(fs::read(&existing).unwrap(), b"sentinel");

    let failed = dir.path("failed.log");
    let (created, ports) = NewConsoleOutput::create(&failed).unwrap();
    assert_eq!(ports.len(), 1);
    assert!(failed.is_file());
    drop((ports, created));
    assert!(!failed.exists(), "a failed import removes its own file");

    let kept = dir.path("kept.log");
    let (created, _ports) = NewConsoleOutput::create(&kept).unwrap();
    created.keep();
    assert!(kept.is_file());
}

/// A failed import's cleanup removes only the console file it created: a
/// file that replaced it at the same path is someone else's and stays.
#[test]
fn snapshot_import_console_cleanup_leaves_a_replacement_at_its_path() {
    let dir = TempDir::new();
    let path = dir.path("console.log");
    let (created, ports) = NewConsoleOutput::create(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();
    drop((ports, created));
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
}

mod kvm_tests;
