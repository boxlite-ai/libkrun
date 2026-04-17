//! Smoke test: boot a Linux kernel inside a WHPX VM using the VMM runner.
//!
//! Usage:
//!   boot_kernel.exe <vmlinuz> [initrd] [-- extra-cmdline-args...]
//!
//! Example:
//!   boot_kernel.exe C:\kernels\vmlinuz-6.6.75 C:\kernels\initrd.img
//!   boot_kernel.exe C:\kernels\vmlinuz-6.6.75 -- console=ttyS0 lpj=1000000

use std::path::PathBuf;

fn main() {
    // Initialize logging (RUST_LOG controls verbosity).
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <vmlinuz> [initrd] [-- extra-cmdline-args...]", args[0]);
        std::process::exit(1);
    }

    let kernel_path = PathBuf::from(&args[1]);
    if !kernel_path.exists() {
        eprintln!("Kernel not found: {}", kernel_path.display());
        std::process::exit(1);
    }

    // Parse optional initrd and extra cmdline args.
    let mut initrd_path: Option<PathBuf> = None;
    let mut extra_cmdline: Vec<&str> = Vec::new();
    let mut past_separator = false;

    for arg in &args[2..] {
        if arg == "--" {
            past_separator = true;
            continue;
        }
        if past_separator {
            extra_cmdline.push(arg);
        } else if initrd_path.is_none() {
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

    // Build the VmContext via the C-API-style context functions.
    let ctx_id = vmm::windows::context::create_ctx().expect("create_ctx failed");

    vmm::windows::context::with_ctx_mut(ctx_id, |ctx| {
        ctx.num_vcpus = 1;
        ctx.ram_mib = 256;
        ctx.kernel_path = Some(kernel_path.clone());
        ctx.initramfs_path = initrd_path.clone();

        // Build kernel command line.
        let mut cmdline_parts = vec![
            "console=ttyS0",
            "earlyprintk=serial",
            "noapic",
            "nolapic",
            "noacpi",
            "nosmp",
            "lpj=1000000",
            "nokaslr",
            "panic=-1",
        ];
        cmdline_parts.extend(extra_cmdline.iter());
        ctx.kernel_cmdline = Some(cmdline_parts.join(" "));

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
