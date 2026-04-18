//! Smoke test: boot a Linux kernel inside a WHPX VM using the VMM runner.
//!
//! Usage:
//!   boot_kernel.exe <vmlinuz> [initrd] [options] [-- extra-cmdline-args...]
//!
//! Options:
//!   --disk <path>     Attach a raw disk image as virtio-blk device
//!   --init <path>     Set init binary path (kernel `init=<path>` parameter)
//!   --root <device>   Override root device (e.g., /dev/vda). Default: auto from --disk
//!   --fstype <type>   Root filesystem type (e.g., ext4). Used with --root
//!   --argv <args...>  Arguments passed to init after `--` separator (repeat for each arg)
//!
//! Examples:
//!   # Boot with initramfs only (existing behavior)
//!   boot_kernel.exe vmlinuz initrd.img
//!
//!   # Boot with disk as root, kernel mounts /dev/vda automatically
//!   boot_kernel.exe vmlinuz --disk rootfs.img
//!
//!   # Boot with disk + explicit init binary
//!   boot_kernel.exe vmlinuz --disk rootfs.img --init /bin/sh
//!
//!   # Full lifecycle test: disk + init + argv
//!   boot_kernel.exe vmlinuz --disk rootfs.img --init /init --argv --listen --argv vsock://2695

use std::path::PathBuf;

use vmm::windows::context::{DiskConfig, DISK_FORMAT_RAW};

fn main() {
    // Initialize logging (RUST_LOG controls verbosity).
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <vmlinuz> [initrd] [--disk <path>] [--init <path>] \
             [--root <dev>] [--fstype <type>] [--argv <arg>]... [-- extra-cmdline-args...]",
            args[0]
        );
        std::process::exit(1);
    }

    let kernel_path = PathBuf::from(&args[1]);
    if !kernel_path.exists() {
        eprintln!("Kernel not found: {}", kernel_path.display());
        std::process::exit(1);
    }

    // Parse optional arguments.
    let mut initrd_path: Option<PathBuf> = None;
    let mut disk_path: Option<PathBuf> = None;
    let mut init_path: Option<String> = None;
    let mut root_device: Option<String> = None;
    let mut root_fstype: Option<String> = None;
    let mut init_argv: Vec<String> = Vec::new();
    let mut extra_cmdline: Vec<&str> = Vec::new();
    let mut past_separator = false;
    let mut i = 2;

    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            past_separator = true;
            i += 1;
            continue;
        }
        if past_separator {
            extra_cmdline.push(arg);
            i += 1;
            continue;
        }
        match arg.as_str() {
            "--disk" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--disk requires a path argument");
                    std::process::exit(1);
                }
                let p = PathBuf::from(&args[i]);
                if !p.exists() {
                    eprintln!("Disk image not found: {}", p.display());
                    std::process::exit(1);
                }
                disk_path = Some(p);
            }
            "--init" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--init requires a path argument");
                    std::process::exit(1);
                }
                init_path = Some(args[i].clone());
            }
            "--root" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--root requires a device argument");
                    std::process::exit(1);
                }
                root_device = Some(args[i].clone());
            }
            "--fstype" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--fstype requires a type argument");
                    std::process::exit(1);
                }
                root_fstype = Some(args[i].clone());
            }
            "--argv" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--argv requires an argument");
                    std::process::exit(1);
                }
                init_argv.push(args[i].clone());
            }
            _ => {
                if initrd_path.is_none() {
                    let p = PathBuf::from(arg);
                    if p.exists() {
                        initrd_path = Some(p);
                    } else {
                        eprintln!("Warning: initrd not found: {}, treating as cmdline arg", arg);
                        extra_cmdline.push(arg);
                    }
                } else {
                    extra_cmdline.push(arg);
                }
            }
        }
        i += 1;
    }

    // Build the VmContext via the C-API-style context functions.
    let ctx_id = vmm::windows::context::create_ctx().expect("create_ctx failed");

    vmm::windows::context::with_ctx_mut(ctx_id, |ctx| {
        ctx.num_vcpus = 1;
        ctx.ram_mib = 256;
        ctx.kernel_path = Some(kernel_path.clone());
        ctx.initramfs_path = initrd_path.clone();

        // Attach disk if provided.
        if let Some(ref dp) = disk_path {
            ctx.disks.push(DiskConfig {
                block_id: "root".to_string(),
                path: dp.clone(),
                format: DISK_FORMAT_RAW,
                read_only: false,
            });
        }

        // Root disk device override.
        ctx.root_disk_device = root_device.clone();
        ctx.root_disk_fstype = root_fstype.clone();

        // Init binary path and arguments.
        ctx.exec_path = init_path.clone();
        ctx.argv = init_argv.clone();

        // Extra cmdline args are appended after the base cmdline and MMIO
        // device lines that build_kernel_cmdline() generates automatically.
        if !extra_cmdline.is_empty() {
            ctx.kernel_cmdline = Some(extra_cmdline.join(" "));
        }

        Ok(())
    })
    .expect("configure ctx failed");

    println!("=== WHPX Smoke Test ===");
    println!("Kernel:  {}", kernel_path.display());
    println!(
        "Initrd:  {}",
        initrd_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(none)".to_string())
    );
    println!(
        "Disk:    {}",
        disk_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(none)".to_string())
    );
    if let Some(ref root) = root_device {
        println!("Root:    {} (fstype: {})", root, root_fstype.as_deref().unwrap_or("auto"));
    }
    if let Some(ref init) = init_path {
        println!("Init:    {}", init);
    }
    if !init_argv.is_empty() {
        println!("Argv:    {:?}", init_argv);
    }

    // Take the context out of the global map and run synchronously.
    let ctx = vmm::windows::context::take_ctx(ctx_id).expect("take_ctx failed");

    println!("Starting VM...");
    match vmm::windows::runner::run(ctx) {
        Ok(code) => {
            println!("VM exited with code {}", code);
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("VM error: {}", e);
            std::process::exit(1);
        }
    }
}
