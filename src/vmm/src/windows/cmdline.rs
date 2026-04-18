//! Kernel command line builder for the Windows WHPX backend.

use super::memory::VIRTIO_MMIO_BASE;

/// Size of each virtio-MMIO device slot in bytes.
pub const MMIO_SLOT_SIZE: u64 = 0x200;

/// IRQ number for the first MMIO device slot.
pub const FIRST_MMIO_IRQ: u8 = 5;

/// Base kernel command line parameters.
///
/// - `nohyperv`: Disable Hyper-V guest enlightenments. WHPX exposes Hyper-V
///   CPUID leaves but doesn't fully support synthetic timers/SynIC, causing
///   clock stalls if the kernel tries to use them.
/// - `lpj=1000000`: Preset loops_per_jiffy to skip delay calibration, which
///   depends on a reliable timer source.
/// - `nokaslr`: Disable kernel address space randomization for deterministic
///   boot in our controlled single-vCPU environment.
const BASE_CMDLINE: &str =
    "console=ttyS0 earlyprintk=serial,ttyS0,115200 noapic nolapic noacpi nosmp nohyperv lpj=1000000 nokaslr";

/// Description of a virtio-MMIO device slot for command line generation.
#[derive(Debug, Clone)]
pub struct MmioSlot {
    /// Slot index (0-based). Determines MMIO base address and IRQ.
    pub index: u8,
    /// Whether the slot is active (has a device).
    pub active: bool,
}

/// Build the full kernel command line.
///
/// Parameters:
/// - `user_cmdline`: Extra kernel parameters appended after device config.
/// - `has_root_disk`: Whether a root disk is attached (default `/dev/vda`).
/// - `mmio_slots`: Virtio-MMIO device slots to register.
/// - `root_disk_device`: Override root device (e.g., "/dev/vdb"). Takes priority over `has_root_disk`.
/// - `root_disk_fstype`: Filesystem type for root device (e.g., "ext4").
/// - `exec_path`: Path to init binary (added as `init=<path>`).
/// - `exec_argv`: Arguments passed after `--` separator for the init process.
pub fn build_kernel_cmdline(
    user_cmdline: Option<&str>,
    has_root_disk: bool,
    mmio_slots: &[MmioSlot],
    root_disk_device: Option<&str>,
    root_disk_fstype: Option<&str>,
    exec_path: Option<&str>,
    exec_argv: &[String],
) -> String {
    let mut cmdline = BASE_CMDLINE.to_string();

    // Root device: explicit override takes priority over default.
    if let Some(device) = root_disk_device {
        cmdline.push_str(&format!(" root={}", device));
        if let Some(fstype) = root_disk_fstype {
            cmdline.push_str(&format!(" rootfstype={}", fstype));
        }
        cmdline.push_str(" rw");
    } else if has_root_disk {
        cmdline.push_str(" root=/dev/vda rw");
    }

    // Init binary path.
    if let Some(path) = exec_path {
        cmdline.push_str(&format!(" init={}", path));
    }

    for slot in mmio_slots {
        if !slot.active {
            continue;
        }
        let base = VIRTIO_MMIO_BASE + (slot.index as u64) * MMIO_SLOT_SIZE;
        let irq = FIRST_MMIO_IRQ + slot.index;
        cmdline.push_str(&format!(
            " virtio_mmio.device={}@0x{:x}:{}",
            MMIO_SLOT_SIZE, base, irq
        ));
    }

    if let Some(extra) = user_cmdline {
        if !extra.is_empty() {
            cmdline.push(' ');
            cmdline.push_str(extra);
        }
    }

    // Init arguments after separator.
    if !exec_argv.is_empty() {
        cmdline.push_str(" -- ");
        cmdline.push_str(&exec_argv.join(" "));
    }

    cmdline
}

/// Calculate the MMIO base address for a given slot index.
pub fn mmio_base_for_slot(index: u8) -> u64 {
    VIRTIO_MMIO_BASE + (index as u64) * MMIO_SLOT_SIZE
}

/// Calculate the IRQ number for a given slot index.
pub fn irq_for_slot(index: u8) -> u8 {
    FIRST_MMIO_IRQ + index
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build cmdline with only the legacy params (no root override, no init).
    fn build_simple(user: Option<&str>, has_root: bool, slots: &[MmioSlot]) -> String {
        build_kernel_cmdline(user, has_root, slots, None, None, None, &[])
    }

    #[test]
    fn test_base_cmdline_only() {
        let cmdline = build_simple(None, false, &[]);
        assert_eq!(cmdline, BASE_CMDLINE);
    }

    #[test]
    fn test_with_root_disk() {
        let cmdline = build_simple(None, true, &[]);
        assert!(cmdline.contains("root=/dev/vda rw"));
        assert!(cmdline.starts_with(BASE_CMDLINE));
    }

    #[test]
    fn test_with_mmio_slots() {
        let slots = vec![
            MmioSlot {
                index: 0,
                active: true,
            },
            MmioSlot {
                index: 1,
                active: true,
            },
        ];
        let cmdline = build_simple(None, true, &slots);
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000000:5"));
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000200:6"));
    }

    #[test]
    fn test_inactive_slots_skipped() {
        let slots = vec![
            MmioSlot {
                index: 0,
                active: true,
            },
            MmioSlot {
                index: 1,
                active: false,
            },
            MmioSlot {
                index: 2,
                active: true,
            },
        ];
        let cmdline = build_simple(None, false, &slots);
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000000:5"));
        assert!(!cmdline.contains("0xd0000200"));
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000400:7"));
    }

    #[test]
    fn test_user_cmdline_appended() {
        let cmdline = build_simple(Some("custom_param=1"), false, &[]);
        assert!(cmdline.ends_with("custom_param=1"));
    }

    #[test]
    fn test_empty_user_cmdline_no_trailing_space() {
        let cmdline = build_simple(Some(""), false, &[]);
        assert!(!cmdline.ends_with(' '));
        assert_eq!(cmdline, BASE_CMDLINE);
    }

    #[test]
    fn test_base_cmdline_has_nohyperv() {
        let cmdline = build_simple(None, false, &[]);
        assert!(cmdline.contains("nohyperv"));
        assert!(cmdline.contains("lpj=1000000"));
        assert!(cmdline.contains("nokaslr"));
    }

    #[test]
    fn test_mmio_base_for_slot() {
        assert_eq!(mmio_base_for_slot(0), 0xD000_0000);
        assert_eq!(mmio_base_for_slot(1), 0xD000_0200);
        assert_eq!(mmio_base_for_slot(2), 0xD000_0400);
    }

    #[test]
    fn test_irq_for_slot() {
        assert_eq!(irq_for_slot(0), 5);
        assert_eq!(irq_for_slot(1), 6);
        assert_eq!(irq_for_slot(2), 7);
    }

    #[test]
    fn test_full_cmdline_with_all_options() {
        let slots = vec![
            MmioSlot {
                index: 0,
                active: true,
            },
            MmioSlot {
                index: 1,
                active: true,
            },
            MmioSlot {
                index: 2,
                active: true,
            },
        ];
        let cmdline = build_simple(Some("quiet"), true, &slots);

        let base_pos = cmdline.find(BASE_CMDLINE).unwrap();
        let root_pos = cmdline.find("root=/dev/vda").unwrap();
        let mmio0_pos = cmdline.find("0xd0000000:5").unwrap();
        let mmio1_pos = cmdline.find("0xd0000200:6").unwrap();
        let mmio2_pos = cmdline.find("0xd0000400:7").unwrap();
        let user_pos = cmdline.find("quiet").unwrap();

        assert!(base_pos < root_pos);
        assert!(root_pos < mmio0_pos);
        assert!(mmio0_pos < mmio1_pos);
        assert!(mmio1_pos < mmio2_pos);
        assert!(mmio2_pos < user_pos);
    }

    // ---- New tests for root_disk_device, exec_path, exec_argv ----

    #[test]
    fn test_root_disk_device_override() {
        let cmdline = build_kernel_cmdline(
            None,
            false,
            &[],
            Some("/dev/vdb"),
            Some("ext4"),
            None,
            &[],
        );
        assert!(cmdline.contains("root=/dev/vdb"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains("rw"));
        assert!(!cmdline.contains("/dev/vda"));
    }

    #[test]
    fn test_root_disk_overrides_default() {
        // When both has_root_disk=true and root_disk_device is set,
        // the explicit device takes priority.
        let cmdline = build_kernel_cmdline(
            None,
            true,
            &[],
            Some("/dev/vdb"),
            Some("ext4"),
            None,
            &[],
        );
        assert!(cmdline.contains("root=/dev/vdb"));
        assert!(!cmdline.contains("root=/dev/vda"));
    }

    #[test]
    fn test_root_disk_device_without_fstype() {
        let cmdline = build_kernel_cmdline(
            None,
            false,
            &[],
            Some("/dev/vdb"),
            None,
            None,
            &[],
        );
        assert!(cmdline.contains("root=/dev/vdb"));
        assert!(!cmdline.contains("rootfstype="));
        assert!(cmdline.contains("rw"));
    }

    #[test]
    fn test_init_path() {
        let cmdline = build_kernel_cmdline(
            None,
            false,
            &[],
            None,
            None,
            Some("/boxlite/bin/boxlite-guest"),
            &[],
        );
        assert!(cmdline.contains("init=/boxlite/bin/boxlite-guest"));
    }

    #[test]
    fn test_init_args_after_separator() {
        let argv = vec![
            "--listen".to_string(),
            "vsock://2695".to_string(),
            "--notify".to_string(),
            "vsock://2696".to_string(),
        ];
        let cmdline = build_kernel_cmdline(
            None,
            false,
            &[],
            None,
            None,
            Some("/boxlite/bin/boxlite-guest"),
            &argv,
        );
        assert!(cmdline.contains("init=/boxlite/bin/boxlite-guest"));
        assert!(cmdline.ends_with("-- --listen vsock://2695 --notify vsock://2696"));
    }

    #[test]
    fn test_no_separator_when_argv_empty() {
        let cmdline = build_kernel_cmdline(
            None,
            false,
            &[],
            None,
            None,
            Some("/bin/init"),
            &[],
        );
        assert!(cmdline.contains("init=/bin/init"));
        assert!(!cmdline.contains("--"));
    }

    #[test]
    fn test_full_lifecycle_cmdline() {
        // Simulates the full box lifecycle cmdline:
        // root=/dev/vdb rootfstype=ext4 rw init=/boxlite/bin/boxlite-guest
        // virtio_mmio devices, then -- <guest args>
        let slots = vec![
            MmioSlot { index: 0, active: true },
            MmioSlot { index: 1, active: true },
        ];
        let argv = vec![
            "--listen".to_string(),
            "vsock://2695".to_string(),
        ];
        let cmdline = build_kernel_cmdline(
            None,
            true,
            &slots,
            Some("/dev/vdb"),
            Some("ext4"),
            Some("/boxlite/bin/boxlite-guest"),
            &argv,
        );

        // Verify ordering: base < root < init < mmio < argv
        let root_pos = cmdline.find("root=/dev/vdb").unwrap();
        let init_pos = cmdline.find("init=/boxlite/bin/boxlite-guest").unwrap();
        let mmio_pos = cmdline.find("virtio_mmio").unwrap();
        let sep_pos = cmdline.find("-- --listen").unwrap();

        assert!(root_pos < init_pos);
        assert!(init_pos < mmio_pos);
        assert!(mmio_pos < sep_pos);
        assert!(!cmdline.contains("root=/dev/vda"));
    }
}
