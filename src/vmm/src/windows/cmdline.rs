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
pub fn build_kernel_cmdline(
    user_cmdline: Option<&str>,
    has_root_disk: bool,
    mmio_slots: &[MmioSlot],
) -> String {
    let mut cmdline = BASE_CMDLINE.to_string();

    if has_root_disk {
        cmdline.push_str(" root=/dev/vda rw");
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

    #[test]
    fn test_base_cmdline_only() {
        let cmdline = build_kernel_cmdline(None, false, &[]);
        assert_eq!(cmdline, BASE_CMDLINE);
    }

    #[test]
    fn test_with_root_disk() {
        let cmdline = build_kernel_cmdline(None, true, &[]);
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
        let cmdline = build_kernel_cmdline(None, true, &slots);
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
        let cmdline = build_kernel_cmdline(None, false, &slots);
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000000:5"));
        assert!(!cmdline.contains("0xd0000200"));
        assert!(cmdline.contains("virtio_mmio.device=512@0xd0000400:7"));
    }

    #[test]
    fn test_user_cmdline_appended() {
        let cmdline = build_kernel_cmdline(Some("init=/bin/sh"), false, &[]);
        assert!(cmdline.ends_with("init=/bin/sh"));
    }

    #[test]
    fn test_empty_user_cmdline_no_trailing_space() {
        let cmdline = build_kernel_cmdline(Some(""), false, &[]);
        assert!(!cmdline.ends_with(' '));
        assert_eq!(cmdline, BASE_CMDLINE);
    }

    #[test]
    fn test_base_cmdline_has_nohyperv() {
        let cmdline = build_kernel_cmdline(None, false, &[]);
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
        let cmdline = build_kernel_cmdline(Some("quiet"), true, &slots);

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
}
