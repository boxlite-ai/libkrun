//! Common types for the Windows WHPX VMM layer.

/// x86_64 standard registers (general-purpose + instruction pointer + flags).
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct StandardRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// x86_64 segment register.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    /// Access rights (type + S + DPL + P + AVL + L + D/B + G).
    pub access_rights: u16,
}

/// x86_64 descriptor table register (GDTR, IDTR).
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

/// x86_64 special/system registers.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: DescriptorTable,
    pub idt: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

/// Reason the vCPU exited back to the VMM.
#[derive(Debug)]
pub enum VcpuExit {
    /// Guest performed an I/O port read.
    IoIn { port: u16, size: u8 },
    /// Guest performed an I/O port write.
    IoOut { port: u16, size: u8, data: u32 },
    /// Guest performed an MMIO read.
    MmioRead { address: u64, size: u8 },
    /// Guest performed an MMIO write.
    MmioWrite { address: u64, size: u8, data: u64 },
    /// Guest executed HLT instruction.
    Halt,
    /// VM shutdown requested.
    Shutdown,
    /// Hypervisor cancelled the run (e.g., stop requested).
    Cancelled,
    /// Interrupt window available (guest RFLAGS.IF became 1).
    InterruptWindow,
    /// Guest executed RDMSR/WRMSR (requires ExtendedVmExits.X64MsrExit).
    MsrAccess {
        msr_number: u32,
        is_write: bool,
        /// RAX value (contains write data for WRMSR, undefined for RDMSR).
        rax: u64,
        /// RDX value (contains write data for WRMSR, undefined for RDMSR).
        rdx: u64,
    },
    /// Guest executed CPUID (requires ExtendedVmExits.X64CpuidExit).
    CpuidAccess {
        /// Input: EAX (leaf).
        rax: u64,
        /// Input: ECX (sub-leaf).
        rcx: u64,
        /// Default results from host CPUID (pass-through values from WHPX).
        default_rax: u64,
        default_rbx: u64,
        default_rcx: u64,
        default_rdx: u64,
    },
    /// Unrecoverable guest exception (triple fault).
    UnrecoverableException,
    /// Exit reason not handled.
    Unknown(u32),
}

/// VM lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM context created, accepting configuration.
    Created,
    /// VM is configured and ready to start.
    Configured,
    /// VM is running.
    Running,
    /// VM has stopped.
    Stopped,
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Created => write!(f, "Created"),
            VmState::Configured => write!(f, "Configured"),
            VmState::Running => write!(f, "Running"),
            VmState::Stopped => write!(f, "Stopped"),
        }
    }
}
