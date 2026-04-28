//! WHPX (Windows Hypervisor Platform) backend.
//!
//! Safe Rust wrappers around the WHPX C API for creating and managing
//! VM partitions and virtual processors.

#[cfg(not(target_os = "windows"))]
compile_error!("WHPX module requires Windows");

#[cfg(target_os = "windows")]
mod imp {
    use std::cell::Cell;
    use std::ptr;

    use windows_sys::Win32::System::Hypervisor::*;

    use super::super::error::{check_hresult, Result};
    use super::super::types::{SpecialRegisters, StandardRegisters, VcpuExit};

    // Helper: create a zeroed WHV_REGISTER_VALUE (for arrays).
    fn zeroed_reg_value() -> WHV_REGISTER_VALUE {
        // SAFETY: WHV_REGISTER_VALUE is a union of integer/struct types; all-zeros is valid.
        unsafe { std::mem::zeroed() }
    }

    // Helper: create a WHV_REGISTER_VALUE from a u64 (for Reg64 field).
    fn reg64(val: u64) -> WHV_REGISTER_VALUE {
        WHV_REGISTER_VALUE { Reg64: val }
    }

    // Helper: extract u64 from a WHV_REGISTER_VALUE Reg64 field.
    // SAFETY: Caller must ensure the register contains a 64-bit value.
    unsafe fn read_reg64(val: &WHV_REGISTER_VALUE) -> u64 {
        val.Reg64
    }

    /// Bitfield accessors for WHV_X64_IO_PORT_ACCESS_INFO.
    /// The _bitfield layout (from windows-sys):
    ///   bits [0..0]   = IsWrite
    ///   bits [1..3]   = AccessSize
    ///   bits [4..4]   = StringOp
    ///   bits [5..5]   = RepPrefix
    ///   bits [6..31]  = Reserved
    fn io_access_is_write(info: &WHV_X64_IO_PORT_ACCESS_INFO) -> bool {
        let bits = unsafe { info.Anonymous._bitfield };
        (bits & 1) != 0
    }

    fn io_access_size(info: &WHV_X64_IO_PORT_ACCESS_INFO) -> u8 {
        let bits = unsafe { info.Anonymous._bitfield };
        ((bits >> 1) & 0x7) as u8
    }

    /// Bitfield accessors for WHV_MEMORY_ACCESS_INFO.
    /// The _bitfield layout:
    ///   bits [0..1]   = AccessType (0=read, 1=write, 2=execute)
    ///   bits [2..2]   = GpaUnmapped
    ///   bits [3..3]   = GvaValid
    ///   bits [4..31]  = Reserved
    fn mem_access_type(info: &WHV_MEMORY_ACCESS_INFO) -> u32 {
        let bits = unsafe { info.Anonymous._bitfield };
        bits & 0x3
    }

    /// Bitfield constants for WHV_EXTENDED_VM_EXITS.
    /// Bit 0 = X64CpuidExit, Bit 1 = X64MsrExit.
    const EXTENDED_VM_EXITS_CPUID: u64 = 1 << 0;
    const EXTENDED_VM_EXITS_MSR: u64 = 1 << 1;

    /// Bitfield accessor for WHV_X64_MSR_ACCESS_INFO.
    /// Bit 0 = IsWrite.
    fn msr_access_is_write(info: &WHV_X64_MSR_ACCESS_INFO) -> bool {
        let bits = unsafe { info.Anonymous._bitfield };
        (bits & 1) != 0
    }

    /// A WHPX partition (VM container).
    ///
    /// Wraps `WHV_PARTITION_HANDLE` and manages its lifecycle.
    /// When dropped, the partition and all its resources are freed.
    pub struct WhpxPartition {
        handle: WHV_PARTITION_HANDLE,
    }

    // SAFETY: WHPX partition handles can be shared across threads.
    // The WHPX API is thread-safe for operations on different objects
    // (e.g., different vCPUs within the same partition).
    unsafe impl Send for WhpxPartition {}
    unsafe impl Sync for WhpxPartition {}

    impl WhpxPartition {
        /// Check if WHPX is available on this system.
        pub fn is_available() -> Result<bool> {
            let mut capability = WHV_CAPABILITY {
                HypervisorPresent: 0,
            };
            let hr = unsafe {
                WHvGetCapability(
                    WHvCapabilityCodeHypervisorPresent,
                    &mut capability as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<WHV_CAPABILITY>() as u32,
                    ptr::null_mut(),
                )
            };
            check_hresult("WHvGetCapability", hr)?;

            // SAFETY: We requested WHvCapabilityCodeHypervisorPresent,
            // so the union field HypervisorPresent is valid.
            let present = unsafe { capability.HypervisorPresent };
            Ok(present != 0)
        }

        /// Create a new WHPX partition.
        pub fn new() -> Result<Self> {
            // WHV_PARTITION_HANDLE is isize; 0 means invalid.
            let mut handle: WHV_PARTITION_HANDLE = 0;
            let hr = unsafe { WHvCreatePartition(&mut handle) };
            check_hresult("WHvCreatePartition", hr)?;

            Ok(WhpxPartition { handle })
        }

        /// Set the number of virtual processors for this partition.
        pub fn set_processor_count(&self, count: u32) -> Result<()> {
            let property = WHV_PARTITION_PROPERTY {
                ProcessorCount: count,
            };
            let hr = unsafe {
                WHvSetPartitionProperty(
                    self.handle,
                    WHvPartitionPropertyCodeProcessorCount,
                    &property as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
            };
            check_hresult("WHvSetPartitionProperty(ProcessorCount)", hr)
        }

        /// Enable APIC emulation mode (XApic).
        pub fn set_local_apic_emulation(&self, enable: bool) -> Result<()> {
            let mode = if enable {
                WHvX64LocalApicEmulationModeXApic
            } else {
                WHvX64LocalApicEmulationModeNone
            };
            let property = WHV_PARTITION_PROPERTY {
                LocalApicEmulationMode: mode,
            };
            let hr = unsafe {
                WHvSetPartitionProperty(
                    self.handle,
                    WHvPartitionPropertyCodeLocalApicEmulationMode,
                    &property as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
            };
            check_hresult("WHvSetPartitionProperty(LocalApicEmulationMode)", hr)
        }

        /// Enable extended VM exits for MSR and/or CPUID interception.
        ///
        /// Must be called before [`setup()`]. When enabled, guest RDMSR/WRMSR
        /// and CPUID instructions cause VM exits instead of being handled
        /// by the hypervisor directly. This is required for Linux kernel boot
        /// on WHPX — without it, MSR accesses to unrecognized registers cause
        /// #GP faults that cascade into triple faults.
        pub fn set_extended_vm_exits(&self, msr_exit: bool, cpuid_exit: bool) -> Result<()> {
            let mut bits: u64 = 0;
            if cpuid_exit {
                bits |= EXTENDED_VM_EXITS_CPUID;
            }
            if msr_exit {
                bits |= EXTENDED_VM_EXITS_MSR;
            }
            let property = WHV_PARTITION_PROPERTY {
                ExtendedVmExits: WHV_EXTENDED_VM_EXITS { AsUINT64: bits },
            };
            let hr = unsafe {
                WHvSetPartitionProperty(
                    self.handle,
                    WHvPartitionPropertyCodeExtendedVmExits,
                    &property as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
            };
            check_hresult("WHvSetPartitionProperty(ExtendedVmExits)", hr)
        }

        /// Finalize the partition configuration. Must be called before creating
        /// virtual processors or mapping memory.
        pub fn setup(&self) -> Result<()> {
            let hr = unsafe { WHvSetupPartition(self.handle) };
            check_hresult("WHvSetupPartition", hr)
        }

        /// Map a host memory region into the guest physical address space.
        ///
        /// # Safety
        ///
        /// `host_va` must point to a valid memory region of at least `size` bytes
        /// that will remain valid for the lifetime of this mapping.
        pub unsafe fn map_gpa_range(
            &self,
            host_va: *mut u8,
            guest_pa: u64,
            size: u64,
            flags: WHV_MAP_GPA_RANGE_FLAGS,
        ) -> Result<()> {
            let hr = WHvMapGpaRange(
                self.handle,
                host_va as *const std::ffi::c_void,
                guest_pa,
                size,
                flags,
            );
            check_hresult("WHvMapGpaRange", hr)
        }

        /// Unmap a guest physical address range.
        pub fn unmap_gpa_range(&self, guest_pa: u64, size: u64) -> Result<()> {
            let hr = unsafe { WHvUnmapGpaRange(self.handle, guest_pa, size) };
            check_hresult("WHvUnmapGpaRange", hr)
        }

        /// Get the raw partition handle (for creating vCPUs etc).
        pub fn handle(&self) -> WHV_PARTITION_HANDLE {
            self.handle
        }
    }

    impl Drop for WhpxPartition {
        fn drop(&mut self) {
            // WHV_PARTITION_HANDLE is isize; 0 means invalid.
            if self.handle != 0 {
                // SAFETY: We own this partition handle and it's valid.
                unsafe {
                    WHvDeletePartition(self.handle);
                }
            }
        }
    }

    /// A WHPX virtual processor (vCPU).
    pub struct WhpxVcpu {
        partition_handle: WHV_PARTITION_HANDLE,
        index: u32,
        // Exit context cache — populated by run(), used by skip_instruction()/complete_io_in().
        exit_rip: Cell<u64>,
        exit_instruction_len: Cell<u8>,
        exit_rax: Cell<u64>,
        // MMIO read completion cache — populated by run() on MMIO read exits.
        exit_mmio_gpr_index: Cell<Option<u8>>,
        exit_mmio_access_size: Cell<u8>,
    }

    // SAFETY: Each vCPU is operated on by a single thread at a time.
    // The WHPX API permits calling WHvRunVirtualProcessor from a dedicated thread.
    unsafe impl Send for WhpxVcpu {}

    impl WhpxVcpu {
        /// Create a new virtual processor in the given partition.
        pub fn new(partition: &WhpxPartition, index: u32) -> Result<Self> {
            let hr = unsafe { WHvCreateVirtualProcessor(partition.handle(), index, 0) };
            check_hresult("WHvCreateVirtualProcessor", hr)?;

            Ok(WhpxVcpu {
                partition_handle: partition.handle(),
                index,
                exit_rip: Cell::new(0),
                exit_instruction_len: Cell::new(0),
                exit_rax: Cell::new(0),
                exit_mmio_gpr_index: Cell::new(None),
                exit_mmio_access_size: Cell::new(0),
            })
        }

        /// Get standard (general-purpose) registers.
        pub fn get_registers(&self) -> Result<StandardRegisters> {
            let register_names = [
                WHvX64RegisterRax,
                WHvX64RegisterRbx,
                WHvX64RegisterRcx,
                WHvX64RegisterRdx,
                WHvX64RegisterRsi,
                WHvX64RegisterRdi,
                WHvX64RegisterRsp,
                WHvX64RegisterRbp,
                WHvX64RegisterR8,
                WHvX64RegisterR9,
                WHvX64RegisterR10,
                WHvX64RegisterR11,
                WHvX64RegisterR12,
                WHvX64RegisterR13,
                WHvX64RegisterR14,
                WHvX64RegisterR15,
                WHvX64RegisterRip,
                WHvX64RegisterRflags,
            ];

            // Use heap allocation (Vec) instead of stack arrays — WHPX on some
            // Win10 builds crashes with stack-allocated WHV_REGISTER_VALUE arrays
            // (likely a 16-byte alignment issue on the stack).
            let mut values: Vec<WHV_REGISTER_VALUE> =
                vec![zeroed_reg_value(); register_names.len()];

            let hr = unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    register_names.as_ptr(),
                    register_names.len() as u32,
                    values.as_mut_ptr(),
                )
            };
            check_hresult("WHvGetVirtualProcessorRegisters", hr)?;

            // SAFETY: We requested 64-bit register values, so Reg64 is the valid union field.
            unsafe {
                Ok(StandardRegisters {
                    rax: read_reg64(&values[0]),
                    rbx: read_reg64(&values[1]),
                    rcx: read_reg64(&values[2]),
                    rdx: read_reg64(&values[3]),
                    rsi: read_reg64(&values[4]),
                    rdi: read_reg64(&values[5]),
                    rsp: read_reg64(&values[6]),
                    rbp: read_reg64(&values[7]),
                    r8: read_reg64(&values[8]),
                    r9: read_reg64(&values[9]),
                    r10: read_reg64(&values[10]),
                    r11: read_reg64(&values[11]),
                    r12: read_reg64(&values[12]),
                    r13: read_reg64(&values[13]),
                    r14: read_reg64(&values[14]),
                    r15: read_reg64(&values[15]),
                    rip: read_reg64(&values[16]),
                    rflags: read_reg64(&values[17]),
                })
            }
        }

        /// Set standard (general-purpose) registers.
        pub fn set_registers(&self, regs: &StandardRegisters) -> Result<()> {
            let register_names = [
                WHvX64RegisterRax,
                WHvX64RegisterRbx,
                WHvX64RegisterRcx,
                WHvX64RegisterRdx,
                WHvX64RegisterRsi,
                WHvX64RegisterRdi,
                WHvX64RegisterRsp,
                WHvX64RegisterRbp,
                WHvX64RegisterR8,
                WHvX64RegisterR9,
                WHvX64RegisterR10,
                WHvX64RegisterR11,
                WHvX64RegisterR12,
                WHvX64RegisterR13,
                WHvX64RegisterR14,
                WHvX64RegisterR15,
                WHvX64RegisterRip,
                WHvX64RegisterRflags,
            ];

            // Use heap allocation — see get_registers() comment on alignment.
            let values: Vec<WHV_REGISTER_VALUE> = vec![
                reg64(regs.rax),
                reg64(regs.rbx),
                reg64(regs.rcx),
                reg64(regs.rdx),
                reg64(regs.rsi),
                reg64(regs.rdi),
                reg64(regs.rsp),
                reg64(regs.rbp),
                reg64(regs.r8),
                reg64(regs.r9),
                reg64(regs.r10),
                reg64(regs.r11),
                reg64(regs.r12),
                reg64(regs.r13),
                reg64(regs.r14),
                reg64(regs.r15),
                reg64(regs.rip),
                reg64(regs.rflags),
            ];

            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    register_names.as_ptr(),
                    register_names.len() as u32,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters", hr)
        }

        /// Get special/system registers (segments, control registers, EFER).
        pub fn get_special_registers(&self) -> Result<SpecialRegisters> {
            let register_names = [
                // Segment registers
                WHvX64RegisterCs,
                WHvX64RegisterDs,
                WHvX64RegisterEs,
                WHvX64RegisterFs,
                WHvX64RegisterGs,
                WHvX64RegisterSs,
                WHvX64RegisterTr,
                WHvX64RegisterLdtr,
                // Descriptor table registers
                WHvX64RegisterGdtr,
                WHvX64RegisterIdtr,
                // Control registers
                WHvX64RegisterCr0,
                WHvX64RegisterCr2,
                WHvX64RegisterCr3,
                WHvX64RegisterCr4,
                WHvX64RegisterEfer,
            ];

            // Use heap allocation — see get_registers() comment on alignment.
            let mut values: Vec<WHV_REGISTER_VALUE> =
                vec![zeroed_reg_value(); register_names.len()];

            let hr = unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    register_names.as_ptr(),
                    register_names.len() as u32,
                    values.as_mut_ptr(),
                )
            };
            check_hresult("WHvGetVirtualProcessorRegisters(special)", hr)?;

            // Helper to extract segment register from WHV_REGISTER_VALUE.
            // SAFETY: Segment register values are stored in the Segment field of the union.
            let seg = |v: &WHV_REGISTER_VALUE| {
                let s = unsafe { &v.Segment };
                super::super::types::SegmentRegister {
                    base: s.Base,
                    limit: s.Limit,
                    selector: s.Selector,
                    // WHV_X64_SEGMENT_REGISTER_0 is a union with an Attributes field.
                    access_rights: unsafe { s.Anonymous.Attributes },
                }
            };

            // SAFETY: Table register values are stored in the Table field of the union.
            let table = |v: &WHV_REGISTER_VALUE| {
                let t = unsafe { &v.Table };
                super::super::types::DescriptorTable {
                    base: t.Base,
                    limit: t.Limit,
                }
            };

            Ok(SpecialRegisters {
                cs: seg(&values[0]),
                ds: seg(&values[1]),
                es: seg(&values[2]),
                fs: seg(&values[3]),
                gs: seg(&values[4]),
                ss: seg(&values[5]),
                tr: seg(&values[6]),
                ldt: seg(&values[7]),
                gdt: table(&values[8]),
                idt: table(&values[9]),
                cr0: unsafe { read_reg64(&values[10]) },
                cr2: unsafe { read_reg64(&values[11]) },
                cr3: unsafe { read_reg64(&values[12]) },
                cr4: unsafe { read_reg64(&values[13]) },
                efer: unsafe { read_reg64(&values[14]) },
            })
        }

        /// Set special/system registers.
        pub fn set_special_registers(&self, sregs: &SpecialRegisters) -> Result<()> {
            let register_names = [
                WHvX64RegisterCs,
                WHvX64RegisterDs,
                WHvX64RegisterEs,
                WHvX64RegisterFs,
                WHvX64RegisterGs,
                WHvX64RegisterSs,
                WHvX64RegisterTr,
                WHvX64RegisterLdtr,
                WHvX64RegisterGdtr,
                WHvX64RegisterIdtr,
                WHvX64RegisterCr0,
                WHvX64RegisterCr2,
                WHvX64RegisterCr3,
                WHvX64RegisterCr4,
                WHvX64RegisterEfer,
            ];

            // Helper to build WHV_REGISTER_VALUE for a segment register.
            let seg_val = |s: &super::super::types::SegmentRegister| WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER {
                    Base: s.base,
                    Limit: s.limit,
                    Selector: s.selector,
                    Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                        Attributes: s.access_rights,
                    },
                },
            };

            // Helper to build WHV_REGISTER_VALUE for a table register.
            let table_val = |t: &super::super::types::DescriptorTable| WHV_REGISTER_VALUE {
                Table: WHV_X64_TABLE_REGISTER {
                    Pad: [0u16; 3],
                    Base: t.base,
                    Limit: t.limit,
                },
            };

            // Use heap allocation — see get_registers() comment on alignment.
            let values: Vec<WHV_REGISTER_VALUE> = vec![
                seg_val(&sregs.cs),
                seg_val(&sregs.ds),
                seg_val(&sregs.es),
                seg_val(&sregs.fs),
                seg_val(&sregs.gs),
                seg_val(&sregs.ss),
                seg_val(&sregs.tr),
                seg_val(&sregs.ldt),
                table_val(&sregs.gdt),
                table_val(&sregs.idt),
                reg64(sregs.cr0),
                reg64(sregs.cr2),
                reg64(sregs.cr3),
                reg64(sregs.cr4),
                reg64(sregs.efer),
            ];

            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    register_names.as_ptr(),
                    register_names.len() as u32,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(special)", hr)
        }

        /// Run the virtual processor until a VM exit occurs.
        ///
        /// After an I/O exit, call [`skip_instruction`] (for writes) or
        /// [`complete_io_in`] (for reads) to resume execution.
        pub fn run(&self) -> Result<VcpuExit> {
            let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
            let hr = unsafe {
                WHvRunVirtualProcessor(
                    self.partition_handle,
                    self.index,
                    &mut exit_context as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            };
            check_hresult("WHvRunVirtualProcessor", hr).map_err(|e| {
                log::error!(
                    "WHvRunVirtualProcessor FAILED: {:?} (HRESULT=0x{:08X})",
                    e,
                    hr as u32
                );
                e
            })?;

            // Cache RIP from the VP context for skip_instruction/complete_io_in.
            self.exit_rip.set(exit_context.VpContext.Rip);

            // Extract instruction length from VpContext.
            // WHV_VP_EXIT_CONTEXT layout: [ExecutionState:2][InstructionLength(4bits)|Cr8(4bits):1]...
            // InstructionLength is at byte offset 2, lower 4 bits.
            // SAFETY: VpContext is a repr(C) struct; byte access at offset 2 is within bounds.
            let vp_instruction_len = unsafe {
                let vp_bytes = &exit_context.VpContext as *const _ as *const u8;
                *vp_bytes.add(2) & 0xF
            };
            self.exit_instruction_len.set(vp_instruction_len);

            // WHV_RUN_VP_EXIT_REASON is i32; use if/else chain to avoid
            // warnings about lowercase constant names in match patterns.
            let reason = exit_context.ExitReason;
            if reason == WHvRunVpExitReasonX64IoPortAccess {
                // SAFETY: ExitReason is IoPortAccess, so the IoPortAccess union field is valid.
                let io = unsafe { &exit_context.Anonymous.IoPortAccess };
                let port = io.PortNumber;
                let size = io_access_size(&io.AccessInfo);
                let is_write = io_access_is_write(&io.AccessInfo);

                self.exit_rax.set(io.Rax);

                if is_write {
                    let data = io.Rax as u32;
                    Ok(VcpuExit::IoOut { port, size, data })
                } else {
                    Ok(VcpuExit::IoIn { port, size })
                }
            } else if reason == WHvRunVpExitReasonMemoryAccess {
                // SAFETY: ExitReason is MemoryAccess, so the MemoryAccess union field is valid.
                let mem_ctx = unsafe { &exit_context.Anonymous.MemoryAccess };
                let address = mem_ctx.Gpa;
                let access_type = mem_access_type(&mem_ctx.AccessInfo);
                let is_write = access_type == 1;

                // Decode the faulting instruction to get access size and write data.
                let byte_count = mem_ctx.InstructionByteCount as usize;
                let insn_bytes = &mem_ctx.InstructionBytes[..byte_count.min(16)];
                let regs = self.get_registers().map_err(|e| {
                    log::error!(
                        "MMIO get_registers FAILED at GPA 0x{:x}: {:?}",
                        address,
                        e
                    );
                    e
                })?;
                let insn = match super::super::insn::decode_mmio_insn(insn_bytes, &regs) {
                    Ok(insn) => insn,
                    Err(e) => {
                        log::error!(
                            "MMIO decode FAILED at GPA 0x{:x}: {:?}, bytes: {:02x?}, is_write={}",
                            address,
                            e,
                            insn_bytes,
                            is_write
                        );
                        eprintln!(
                            "[WHPX] MMIO decode FAILED at GPA 0x{:x}, bytes: {:02x?}",
                            address, insn_bytes
                        );
                        return Err(e);
                    }
                };

                self.exit_instruction_len.set(insn.len);
                self.exit_mmio_gpr_index.set(insn.gpr_index);
                self.exit_mmio_access_size.set(insn.access_size);

                if is_write {
                    Ok(VcpuExit::MmioWrite {
                        address,
                        size: insn.access_size,
                        data: insn.data,
                    })
                } else {
                    Ok(VcpuExit::MmioRead {
                        address,
                        size: insn.access_size,
                    })
                }
            } else if reason == WHvRunVpExitReasonX64InterruptWindow {
                Ok(VcpuExit::InterruptWindow)
            } else if reason == WHvRunVpExitReasonX64Halt {
                Ok(VcpuExit::Halt)
            } else if reason == WHvRunVpExitReasonCanceled {
                Ok(VcpuExit::Cancelled)
            } else if reason == WHvRunVpExitReasonX64MsrAccess {
                // SAFETY: ExitReason is MsrAccess, so the MsrAccess union field is valid.
                let msr_ctx = unsafe { &exit_context.Anonymous.MsrAccess };
                let is_write = msr_access_is_write(&msr_ctx.AccessInfo);
                Ok(VcpuExit::MsrAccess {
                    msr_number: msr_ctx.MsrNumber,
                    is_write,
                    rax: msr_ctx.Rax,
                    rdx: msr_ctx.Rdx,
                })
            } else if reason == WHvRunVpExitReasonX64Cpuid {
                // SAFETY: ExitReason is CpuidAccess, so the CpuidAccess union field is valid.
                let cpuid_ctx = unsafe { &exit_context.Anonymous.CpuidAccess };
                Ok(VcpuExit::CpuidAccess {
                    rax: cpuid_ctx.Rax,
                    rcx: cpuid_ctx.Rcx,
                    default_rax: cpuid_ctx.DefaultResultRax,
                    default_rbx: cpuid_ctx.DefaultResultRbx,
                    default_rcx: cpuid_ctx.DefaultResultRcx,
                    default_rdx: cpuid_ctx.DefaultResultRdx,
                })
            } else if reason == WHvRunVpExitReasonUnrecoverableException {
                Ok(VcpuExit::UnrecoverableException)
            } else if reason == WHvRunVpExitReasonNone {
                Ok(VcpuExit::Shutdown)
            } else {
                Ok(VcpuExit::Unknown(reason as u32))
            }
        }

        /// Get cached exit context info (for diagnostics and testing).
        ///
        /// Returns `(rip, instruction_len, rax)` from the last VM exit.
        pub fn exit_info(&self) -> (u64, u8, u64) {
            (
                self.exit_rip.get(),
                self.exit_instruction_len.get(),
                self.exit_rax.get(),
            )
        }

        /// Advance RIP past the last intercepted instruction.
        ///
        /// Call after handling [`VcpuExit::IoOut`] or [`VcpuExit::MmioWrite`]
        /// to resume execution at the next instruction.
        pub fn skip_instruction(&self) -> Result<()> {
            let instruction_len = self.exit_instruction_len.get();
            // Read current RIP from registers (guaranteed correct).
            let regs = self.get_registers()?;
            let new_rip = regs.rip + instruction_len as u64;
            let names = [WHvX64RegisterRip];
            let values: Vec<WHV_REGISTER_VALUE> = vec![reg64(new_rip)];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    1,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(skip)", hr)
        }

        /// Complete an MSR read (RDMSR): inject result into RAX:RDX and advance RIP.
        ///
        /// For RDMSR, the 64-bit result is split: low 32 bits in EAX, high 32 in EDX.
        /// Call after handling [`VcpuExit::MsrAccess`] where `is_write == false`.
        pub fn complete_msr_read(&self, value: u64) -> Result<()> {
            let instruction_len = self.exit_instruction_len.get();
            let regs = self.get_registers()?;
            let new_rip = regs.rip + instruction_len as u64;
            let new_rax = value & 0xFFFF_FFFF;
            let new_rdx = value >> 32;

            let names = [WHvX64RegisterRip, WHvX64RegisterRax, WHvX64RegisterRdx];
            let values: Vec<WHV_REGISTER_VALUE> =
                vec![reg64(new_rip), reg64(new_rax), reg64(new_rdx)];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    3,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(msr_read)", hr)
        }

        /// Complete a CPUID exit: inject results into RAX/RBX/RCX/RDX and advance RIP.
        ///
        /// Call after handling [`VcpuExit::CpuidAccess`].
        pub fn complete_cpuid(&self, rax: u64, rbx: u64, rcx: u64, rdx: u64) -> Result<()> {
            let instruction_len = self.exit_instruction_len.get();
            let regs = self.get_registers()?;
            let new_rip = regs.rip + instruction_len as u64;

            let names = [
                WHvX64RegisterRip,
                WHvX64RegisterRax,
                WHvX64RegisterRbx,
                WHvX64RegisterRcx,
                WHvX64RegisterRdx,
            ];
            let values: Vec<WHV_REGISTER_VALUE> = vec![
                reg64(new_rip),
                reg64(rax),
                reg64(rbx),
                reg64(rcx),
                reg64(rdx),
            ];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    5,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(cpuid)", hr)
        }

        /// Complete an I/O IN operation: inject data into RAX and advance RIP.
        ///
        /// Preserves upper RAX bits based on the I/O access size:
        /// - size 1: modifies AL only (bits 0-7)
        /// - size 2: modifies AX only (bits 0-15)
        /// - size 4: modifies EAX (bits 0-31)
        ///
        /// Call after handling [`VcpuExit::IoIn`].
        pub fn complete_io_in(&self, data: u32, size: u8) -> Result<()> {
            let instruction_len = self.exit_instruction_len.get();
            // Read current registers (RIP and RAX guaranteed correct).
            let regs = self.get_registers()?;
            let new_rip = regs.rip + instruction_len as u64;
            let mask: u64 = match size {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => 0xFF,
            };
            let new_rax = (regs.rax & !mask) | (data as u64 & mask);

            let names = [WHvX64RegisterRip, WHvX64RegisterRax];
            let values: Vec<WHV_REGISTER_VALUE> = vec![reg64(new_rip), reg64(new_rax)];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    2,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(io_in)", hr)
        }

        /// Complete an MMIO read: inject data into the destination GPR and advance RIP.
        ///
        /// The destination register and access size were cached during [`run()`].
        /// Data is zero-extended into the register per x86 semantics:
        /// - 1-byte: zero-extends to 64 bits (MOVZX) or writes AL (MOV)
        /// - 2-byte: zero-extends to 64 bits (MOVZX) or writes AX (MOV)
        /// - 4-byte: zero-extends to 64 bits (x86-64 implicit)
        /// - 8-byte: writes full 64-bit register
        ///
        /// Call after handling [`VcpuExit::MmioRead`].
        pub fn complete_mmio_read(&self, data: u64) -> Result<()> {
            let gpr_index = match self.exit_mmio_gpr_index.get() {
                Some(idx) => idx,
                None => {
                    return Err(super::super::error::WkrunError::Vcpu(
                        "complete_mmio_read: no cached GPR index".into(),
                    ))
                }
            };
            let access_size = self.exit_mmio_access_size.get();
            let insn_len = self.exit_instruction_len.get();

            let mut regs = self.get_registers()?;
            let new_rip = regs.rip + insn_len as u64;

            // Mask data to access size. For 4-byte writes, x86-64 zero-extends
            // the 32-bit result into the full 64-bit register.
            let masked = match access_size {
                1 => data & 0xFF,
                2 => data & 0xFFFF,
                4 => data & 0xFFFF_FFFF,
                _ => data,
            };

            // Write into the destination GPR.
            match gpr_index {
                0 => regs.rax = masked,
                1 => regs.rcx = masked,
                2 => regs.rdx = masked,
                3 => regs.rbx = masked,
                4 => regs.rsp = masked,
                5 => regs.rbp = masked,
                6 => regs.rsi = masked,
                7 => regs.rdi = masked,
                8 => regs.r8 = masked,
                9 => regs.r9 = masked,
                10 => regs.r10 = masked,
                11 => regs.r11 = masked,
                12 => regs.r12 = masked,
                13 => regs.r13 = masked,
                14 => regs.r14 = masked,
                15 => regs.r15 = masked,
                _ => {}
            }

            regs.rip = new_rip;
            self.set_registers(&regs)
        }

        /// Inject an external hardware interrupt into the vCPU.
        ///
        /// The interrupt is delivered on the next `run()` call. The caller
        /// must ensure `RFLAGS.IF = 1` before calling this (use
        /// [`interrupts_enabled`] to check, and [`request_interrupt_window`]
        /// if interrupts are currently disabled).
        pub fn inject_interrupt(&self, vector: u8) -> Result<()> {
            // Build WHV_X64_PENDING_INTERRUPTION_REGISTER as u64:
            //   Bit 0:     InterruptionPending = 1
            //   Bits 1-3:  InterruptionType = 0 (external interrupt)
            //   Bit 4:     DeliverErrorCode = 0
            //   Bits 16-31: InterruptionVector = vector
            let pending: u64 = 1 | ((vector as u64) << 16);

            let names = [WHvRegisterPendingInterruption];
            let values: Vec<WHV_REGISTER_VALUE> = vec![WHV_REGISTER_VALUE { Reg64: pending }];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    1,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(inject_interrupt)", hr)
        }

        /// Deliver an interrupt via the partition-level WHvRequestInterrupt API.
        ///
        /// Unlike [`inject_interrupt`] (which sets WHvRegisterPendingInterruption),
        /// this API delivers the interrupt at the partition level and — critically —
        /// resets the vCPU's HLT suspend state on platforms where
        /// WHvRegisterInternalActivityState is inaccessible (Win10).
        ///
        /// Uses Fixed delivery, edge-triggered, physical destination mode.
        /// Returns Ok(true) if the interrupt was delivered, Ok(false) if the
        /// API returned an error (caller should fall back to inject_interrupt).
        pub fn request_interrupt(&self, vector: u8) -> Result<bool> {
            // WHV_INTERRUPT_CONTROL layout (from Hyper-V TLFS / Windows SDK):
            //   _bitfield (u64):
            //     bits  0-31: InterruptType (u32) — 0 = Fixed
            //     bit     32: LevelTriggered — 0 = edge
            //     bit     33: LogicalDestinationMode — 0 = physical
            //     bits 34-63: Reserved (0)
            //   Destination (u32): target vCPU index
            //   Vector (u32): interrupt vector
            let interrupt = WHV_INTERRUPT_CONTROL {
                _bitfield: 0, // Fixed=0, edge-triggered=0, physical=0
                Destination: self.index,
                Vector: vector as u32,
            };
            let hr = unsafe {
                WHvRequestInterrupt(
                    self.partition_handle,
                    &interrupt,
                    std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as u32,
                )
            };
            if hr == 0 {
                Ok(true)
            } else {
                // Log at warn level (not debug) so it's visible at RUST_LOG=info.
                // This is a critical diagnostic — if WHvRequestInterrupt fails,
                // the vCPU may not wake from HLT on Win10.
                log::warn!(
                    "WHvRequestInterrupt failed: HRESULT=0x{:08X}, vector={}",
                    hr as u32,
                    vector
                );
                Ok(false)
            }
        }

        /// Check if the guest has interrupts enabled (RFLAGS.IF = 1).
        pub fn interrupts_enabled(&self) -> Result<bool> {
            let regs = self.get_registers()?;
            Ok(regs.rflags & (1 << 9) != 0)
        }

        /// Request an interrupt window exit.
        ///
        /// The next `run()` call will exit with [`VcpuExit::InterruptWindow`]
        /// as soon as the guest enables interrupts (RFLAGS.IF = 1).
        pub fn request_interrupt_window(&self) -> Result<()> {
            // WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER:
            //   Bit 1: InterruptNotification = 1
            let notifications: u64 = 1 << 1;

            let names = [WHvX64RegisterDeliverabilityNotifications];
            let values: Vec<WHV_REGISTER_VALUE> = vec![WHV_REGISTER_VALUE {
                Reg64: notifications,
            }];
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.partition_handle,
                    self.index,
                    names.as_ptr(),
                    1,
                    values.as_ptr(),
                )
            };
            check_hresult("WHvSetVirtualProcessorRegisters(interrupt_window)", hr)
        }

        /// Cancel a running vCPU (causes it to exit with Cancelled).
        pub fn cancel(&self) -> Result<()> {
            let hr = unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, self.index, 0) };
            check_hresult("WHvCancelRunVirtualProcessor", hr)
        }

        /// Get the vCPU index.
        pub fn index(&self) -> u32 {
            self.index
        }

        /// Create a lightweight canceller that can be sent to another thread.
        pub fn canceller(&self) -> VcpuCanceller {
            VcpuCanceller {
                partition_handle: self.partition_handle,
                index: self.index,
            }
        }
    }

    /// Lightweight handle for cancelling a running vCPU from another thread.
    ///
    /// Only supports the cancel operation — safe to use from a timer thread
    /// to preempt the vCPU for interrupt delivery.
    pub struct VcpuCanceller {
        partition_handle: WHV_PARTITION_HANDLE,
        index: u32,
    }

    // SAFETY: WHvCancelRunVirtualProcessor is documented as safe to call
    // from any thread while the vCPU is running.
    unsafe impl Send for VcpuCanceller {}
    unsafe impl Sync for VcpuCanceller {}

    impl VcpuCanceller {
        /// Cancel the vCPU run, causing it to exit with VcpuExit::Cancelled.
        pub fn cancel(&self) -> Result<()> {
            let hr = unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, self.index, 0) };
            check_hresult("WHvCancelRunVirtualProcessor", hr)
        }
    }

    impl Drop for WhpxVcpu {
        fn drop(&mut self) {
            // SAFETY: We own this vCPU and the partition handle is still valid
            // (guaranteed by the borrow lifetime in practice, but we store a raw handle).
            unsafe {
                WHvDeleteVirtualProcessor(self.partition_handle, self.index);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_standard_registers_default() {
            let regs = StandardRegisters::default();
            assert_eq!(regs.rax, 0);
            assert_eq!(regs.rip, 0);
            assert_eq!(regs.rflags, 0);
        }

        #[test]
        fn test_special_registers_default() {
            let sregs = SpecialRegisters::default();
            assert_eq!(sregs.cr0, 0);
            assert_eq!(sregs.cr3, 0);
            assert_eq!(sregs.efer, 0);
            assert_eq!(sregs.cs.selector, 0);
        }

        #[test]
        fn test_segment_register_construction() {
            let seg = super::super::super::types::SegmentRegister {
                base: 0,
                limit: 0xFFFF_FFFF,
                selector: 0x10,
                access_rights: 0xC093, // data segment
            };
            assert_eq!(seg.selector, 0x10);
            assert_eq!(seg.access_rights, 0xC093);
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::*;
