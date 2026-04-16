//! Minimal x86_64 instruction decoder for MMIO emulation.
//!
//! Decodes the instruction bytes provided by WHPX memory access exits
//! to extract write data, access size, and destination register for reads.
//!
//! Only handles the instruction patterns Linux generates for MMIO:
//! - MOV r/m, reg (0x88/0x89) — writeb/writel/writeq
//! - MOV reg, r/m (0x8A/0x8B) — readb/readl/readq
//! - MOV r/m, imm (0xC6/0xC7) — writeb/writel with immediate
//! - MOVZX reg, r/m (0x0F 0xB6/0xB7) — readb/readw with zero-extend

use super::error::{Result, WkrunError};
use super::types::StandardRegisters;

/// Decoded MMIO instruction information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioInsn {
    /// Number of bytes accessed (1, 2, 4, or 8).
    pub access_size: u8,
    /// For writes: the value being written.
    pub data: u64,
    /// Total instruction length in bytes.
    pub len: u8,
    /// Whether this is a write (true) or read (false).
    pub is_write: bool,
    /// For reads: which general-purpose register receives the value (0=RAX..15=R15).
    pub gpr_index: Option<u8>,
}

/// REX prefix bit fields.
struct Rex {
    /// REX.W — 64-bit operand size.
    w: bool,
    /// REX.R — extends ModRM reg field.
    r: bool,
}

impl Rex {
    fn none() -> Self {
        Rex { w: false, r: false }
    }

    fn from_byte(byte: u8) -> Self {
        Rex {
            w: byte & 0x08 != 0,
            r: byte & 0x04 != 0,
        }
    }
}

/// Read a general-purpose register value by index (0=RAX, 1=RCX, ..., 15=R15).
///
/// The index matches x86_64 ModRM/SIB encoding:
/// 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI,
/// 8=R8, 9=R9, 10=R10, 11=R11, 12=R12, 13=R13, 14=R14, 15=R15
pub fn read_gpr(regs: &StandardRegisters, index: u8) -> u64 {
    match index {
        0 => regs.rax,
        1 => regs.rcx,
        2 => regs.rdx,
        3 => regs.rbx,
        4 => regs.rsp,
        5 => regs.rbp,
        6 => regs.rsi,
        7 => regs.rdi,
        8 => regs.r8,
        9 => regs.r9,
        10 => regs.r10,
        11 => regs.r11,
        12 => regs.r12,
        13 => regs.r13,
        14 => regs.r14,
        15 => regs.r15,
        _ => 0,
    }
}

/// Calculate the length of the ModRM addressing mode (displacement bytes).
///
/// For MMIO, the ModRM byte encodes a memory operand. We need to know
/// how many bytes the addressing mode consumes to find the instruction length.
fn modrm_disp_len(modrm: u8, has_sib: bool) -> usize {
    let mod_field = modrm >> 6;
    let rm = modrm & 0x07;

    match mod_field {
        0b00 => {
            if rm == 0b101 {
                // [RIP+disp32] or [disp32] — 4-byte displacement
                4
            } else if rm == 0b100 && has_sib {
                // SIB byte present, check SIB base
                // For simplicity, return 0 (base case) — SIB with mod=00 and base=101 has disp32
                0 // Will be handled by caller checking SIB
            } else {
                0
            }
        }
        0b01 => 1, // [reg+disp8]
        0b10 => 4, // [reg+disp32]
        _ => 0,    // mod=11 is register-to-register (shouldn't happen for MMIO)
    }
}

/// Calculate total bytes consumed by ModRM + SIB + displacement.
fn addressing_mode_len(bytes: &[u8], offset: usize) -> usize {
    if offset >= bytes.len() {
        return 0;
    }
    let modrm = bytes[offset];
    let mod_field = modrm >> 6;
    let rm = modrm & 0x07;

    // Start with 1 byte for ModRM itself.
    let mut len = 1;

    // Check for SIB byte (rm=100 with mod != 11).
    let has_sib = rm == 0b100 && mod_field != 0b11;
    if has_sib {
        len += 1; // SIB byte

        // Check SIB base for special disp32 case.
        if offset + 1 < bytes.len() {
            let sib = bytes[offset + 1];
            let base = sib & 0x07;
            if mod_field == 0b00 && base == 0b101 {
                len += 4; // disp32 with SIB
                return len;
            }
        }
    }

    // Add displacement bytes.
    len += modrm_disp_len(modrm, has_sib);

    len
}

/// Decode an MMIO instruction from raw instruction bytes.
///
/// `bytes` contains the instruction bytes from the WHPX exit context.
/// `regs` contains the current vCPU register state (needed to extract
/// write values from source registers).
///
/// Returns the decoded instruction information, or an error if the
/// instruction pattern is not recognized.
pub fn decode_mmio_insn(bytes: &[u8], regs: &StandardRegisters) -> Result<MmioInsn> {
    if bytes.is_empty() {
        return Err(WkrunError::Device("empty instruction bytes".into()));
    }

    let mut pos = 0;
    let mut rex = Rex::none();
    let mut has_operand_size_prefix = false;

    // Parse prefixes.
    loop {
        if pos >= bytes.len() {
            return Err(WkrunError::Device("instruction too short".into()));
        }
        match bytes[pos] {
            0x66 => {
                has_operand_size_prefix = true;
                pos += 1;
            }
            0x67 => {
                // Address-size prefix — skip but don't change operand size.
                pos += 1;
            }
            0xF2 | 0xF3 => {
                // REP/REPNE prefix — skip.
                pos += 1;
            }
            b @ 0x40..=0x4F => {
                rex = Rex::from_byte(b);
                pos += 1;
                break; // REX must be last prefix.
            }
            _ => break,
        }
    }

    if pos >= bytes.len() {
        return Err(WkrunError::Device(
            "instruction too short after prefixes".into(),
        ));
    }

    let opcode = bytes[pos];
    pos += 1;

    match opcode {
        // MOV r/m8, reg8 (write, 8-bit)
        0x88 => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r/m8,r8: missing ModRM".into()));
            }
            let modrm = bytes[pos];
            let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
            let addr_len = addressing_mode_len(bytes, pos);
            let value = read_gpr(regs, reg) & 0xFF;
            Ok(MmioInsn {
                access_size: 1,
                data: value,
                len: (pos + addr_len) as u8,
                is_write: true,
                gpr_index: None,
            })
        }

        // MOV r/m16/32/64, reg16/32/64 (write)
        0x89 => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r/m,r: missing ModRM".into()));
            }
            let modrm = bytes[pos];
            let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
            let addr_len = addressing_mode_len(bytes, pos);
            let access_size = if rex.w {
                8
            } else if has_operand_size_prefix {
                2
            } else {
                4
            };
            let mask = match access_size {
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                8 => u64::MAX,
                _ => 0xFF,
            };
            let value = read_gpr(regs, reg) & mask;
            Ok(MmioInsn {
                access_size,
                data: value,
                len: (pos + addr_len) as u8,
                is_write: true,
                gpr_index: None,
            })
        }

        // MOV reg8, r/m8 (read, 8-bit)
        0x8A => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r8,r/m8: missing ModRM".into()));
            }
            let modrm = bytes[pos];
            let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
            let addr_len = addressing_mode_len(bytes, pos);
            Ok(MmioInsn {
                access_size: 1,
                data: 0,
                len: (pos + addr_len) as u8,
                is_write: false,
                gpr_index: Some(reg),
            })
        }

        // MOV reg16/32/64, r/m16/32/64 (read)
        0x8B => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r,r/m: missing ModRM".into()));
            }
            let modrm = bytes[pos];
            let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
            let addr_len = addressing_mode_len(bytes, pos);
            let access_size = if rex.w {
                8
            } else if has_operand_size_prefix {
                2
            } else {
                4
            };
            Ok(MmioInsn {
                access_size,
                data: 0,
                len: (pos + addr_len) as u8,
                is_write: false,
                gpr_index: Some(reg),
            })
        }

        // MOV r/m8, imm8 (write, 8-bit immediate)
        0xC6 => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r/m8,imm8: missing ModRM".into()));
            }
            let addr_len = addressing_mode_len(bytes, pos);
            let imm_pos = pos + addr_len;
            if imm_pos >= bytes.len() {
                return Err(WkrunError::Device(
                    "MOV r/m8,imm8: missing immediate".into(),
                ));
            }
            let value = bytes[imm_pos] as u64;
            Ok(MmioInsn {
                access_size: 1,
                data: value,
                len: (imm_pos + 1) as u8,
                is_write: true,
                gpr_index: None,
            })
        }

        // MOV r/m16/32, imm16/32 (write, immediate)
        0xC7 => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device("MOV r/m,imm: missing ModRM".into()));
            }
            let addr_len = addressing_mode_len(bytes, pos);
            let imm_pos = pos + addr_len;
            let (access_size, imm_len) = if has_operand_size_prefix {
                (2u8, 2usize)
            } else {
                (4u8, 4usize)
            };
            if imm_pos + imm_len > bytes.len() {
                return Err(WkrunError::Device("MOV r/m,imm: missing immediate".into()));
            }
            let value = match imm_len {
                2 => u16::from_le_bytes([bytes[imm_pos], bytes[imm_pos + 1]]) as u64,
                4 => u32::from_le_bytes([
                    bytes[imm_pos],
                    bytes[imm_pos + 1],
                    bytes[imm_pos + 2],
                    bytes[imm_pos + 3],
                ]) as u64,
                _ => unreachable!(),
            };
            Ok(MmioInsn {
                access_size,
                data: value,
                len: (imm_pos + imm_len) as u8,
                is_write: true,
                gpr_index: None,
            })
        }

        // Two-byte opcodes (0x0F prefix).
        0x0F => {
            if pos >= bytes.len() {
                return Err(WkrunError::Device(
                    "0x0F: missing second opcode byte".into(),
                ));
            }
            let opcode2 = bytes[pos];
            pos += 1;

            match opcode2 {
                // MOVZX reg, r/m8 (read, 8-bit zero-extended to 32/64)
                0xB6 => {
                    if pos >= bytes.len() {
                        return Err(WkrunError::Device("MOVZX r,r/m8: missing ModRM".into()));
                    }
                    let modrm = bytes[pos];
                    let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
                    let addr_len = addressing_mode_len(bytes, pos);
                    Ok(MmioInsn {
                        access_size: 1,
                        data: 0,
                        len: (pos + addr_len) as u8,
                        is_write: false,
                        gpr_index: Some(reg),
                    })
                }

                // MOVZX reg, r/m16 (read, 16-bit zero-extended to 32/64)
                0xB7 => {
                    if pos >= bytes.len() {
                        return Err(WkrunError::Device("MOVZX r,r/m16: missing ModRM".into()));
                    }
                    let modrm = bytes[pos];
                    let reg = ((modrm >> 3) & 0x07) | if rex.r { 8 } else { 0 };
                    let addr_len = addressing_mode_len(bytes, pos);
                    Ok(MmioInsn {
                        access_size: 2,
                        data: 0,
                        len: (pos + addr_len) as u8,
                        is_write: false,
                        gpr_index: Some(reg),
                    })
                }

                _ => Err(WkrunError::Device(format!(
                    "unrecognized 0x0F opcode: 0x{:02X} (bytes: {:02X?})",
                    opcode2, bytes
                ))),
            }
        }

        _ => Err(WkrunError::Device(format!(
            "unrecognized MMIO opcode: 0x{:02X} (bytes: {:02X?})",
            opcode, bytes
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regs() -> StandardRegisters {
        StandardRegisters {
            rax: 0xDEAD_BEEF_CAFE_BABE,
            rcx: 0x1111_1111_1111_1111,
            rdx: 0x2222_2222_2222_2222,
            rbx: 0x3333_3333_3333_3333,
            rsp: 0x4444_4444_4444_4444,
            rbp: 0x5555_5555_5555_5555,
            rsi: 0x6666_6666_6666_6666,
            rdi: 0x7777_7777_7777_7777,
            r8: 0x8888_8888_8888_8888,
            r9: 0x9999_9999_9999_9999,
            r10: 0xAAAA_AAAA_AAAA_AAAA,
            r11: 0xBBBB_BBBB_BBBB_BBBB,
            r12: 0xCCCC_CCCC_CCCC_CCCC,
            r13: 0xDDDD_DDDD_DDDD_DDDD,
            r14: 0xEEEE_EEEE_EEEE_EEEE,
            r15: 0xFFFF_FFFF_FFFF_FFFF,
            rip: 0,
            rflags: 0,
        }
    }

    // --- MOV r/m32, reg (0x89) — writel ---

    #[test]
    fn test_mov_dword_ptr_eax() {
        // mov dword [rdi], eax  →  89 07
        // ModRM: mod=00, reg=000(eax), r/m=111(rdi)
        let bytes = [0x89, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.data, regs.rax & 0xFFFF_FFFF);
        assert_eq!(insn.len, 2);
        assert_eq!(insn.gpr_index, None);
    }

    #[test]
    fn test_mov_dword_ptr_ecx_disp8() {
        // mov dword [rdi+0x10], ecx  →  89 4F 10
        // ModRM: mod=01, reg=001(ecx), r/m=111(rdi)
        let bytes = [0x89, 0x4F, 0x10];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.data, regs.rcx & 0xFFFF_FFFF);
        assert_eq!(insn.len, 3);
    }

    // --- MOV r/m64, reg (REX.W 0x89) — writeq ---

    #[test]
    fn test_mov_qword_ptr_rax() {
        // mov qword [rdi], rax  →  48 89 07
        // REX.W=1, ModRM: mod=00, reg=000(rax), r/m=111(rdi)
        let bytes = [0x48, 0x89, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 8);
        assert_eq!(insn.data, regs.rax);
        assert_eq!(insn.len, 3);
    }

    // --- MOV r/m8, reg8 (0x88) — writeb ---

    #[test]
    fn test_mov_byte_ptr_al() {
        // mov byte [rdi], al  →  88 07
        let bytes = [0x88, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 1);
        assert_eq!(insn.data, regs.rax & 0xFF);
        assert_eq!(insn.len, 2);
    }

    // --- MOV r/m16, reg16 (0x66 0x89) — writew ---

    #[test]
    fn test_mov_word_ptr_ax() {
        // mov word [rdi], ax  →  66 89 07
        let bytes = [0x66, 0x89, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 2);
        assert_eq!(insn.data, regs.rax & 0xFFFF);
        assert_eq!(insn.len, 3);
    }

    // --- MOV reg32, r/m32 (0x8B) — readl ---

    #[test]
    fn test_mov_eax_dword_ptr() {
        // mov eax, dword [rdi]  →  8B 07
        let bytes = [0x8B, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(!insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.gpr_index, Some(0)); // RAX
        assert_eq!(insn.len, 2);
    }

    // --- MOV reg64, r/m64 (REX.W 0x8B) — readq ---

    #[test]
    fn test_mov_rax_qword_ptr() {
        // mov rax, qword [rdi]  →  48 8B 07
        let bytes = [0x48, 0x8B, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(!insn.is_write);
        assert_eq!(insn.access_size, 8);
        assert_eq!(insn.gpr_index, Some(0)); // RAX
        assert_eq!(insn.len, 3);
    }

    // --- MOV r/m32, imm32 (0xC7) — writel with immediate ---

    #[test]
    fn test_mov_dword_ptr_imm32() {
        // mov dword [rdi], 0x12345678  →  C7 07 78 56 34 12
        let bytes = [0xC7, 0x07, 0x78, 0x56, 0x34, 0x12];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.data, 0x12345678);
        assert_eq!(insn.len, 6);
    }

    // --- MOV r/m8, imm8 (0xC6) — writeb with immediate ---

    #[test]
    fn test_mov_byte_ptr_imm8() {
        // mov byte [rdi], 0xAB  →  C6 07 AB
        let bytes = [0xC6, 0x07, 0xAB];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 1);
        assert_eq!(insn.data, 0xAB);
        assert_eq!(insn.len, 3);
    }

    // --- MOVZX reg, r/m8 (0x0F 0xB6) — readb ---

    #[test]
    fn test_movzx_eax_byte_ptr() {
        // movzx eax, byte [rdi]  →  0F B6 07
        let bytes = [0x0F, 0xB6, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(!insn.is_write);
        assert_eq!(insn.access_size, 1);
        assert_eq!(insn.gpr_index, Some(0)); // EAX
        assert_eq!(insn.len, 3);
    }

    // --- MOVZX reg, r/m16 (0x0F 0xB7) — readw ---

    #[test]
    fn test_movzx_eax_word_ptr() {
        // movzx eax, word [rdi]  →  0F B7 07
        let bytes = [0x0F, 0xB7, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(!insn.is_write);
        assert_eq!(insn.access_size, 2);
        assert_eq!(insn.gpr_index, Some(0)); // EAX
        assert_eq!(insn.len, 3);
    }

    // --- REX.R extended registers ---

    #[test]
    fn test_mov_dword_ptr_r8d() {
        // mov dword [rdi], r8d  →  44 89 07
        // REX.R=1, reg=000 → reg=8 (R8)
        let bytes = [0x44, 0x89, 0x07];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.data, regs.r8 & 0xFFFF_FFFF);
        assert_eq!(insn.len, 3);
    }

    #[test]
    fn test_mov_r10d_dword_ptr() {
        // mov r10d, dword [rdi]  →  44 8B 17
        // REX.R=1, reg=010 → reg=10 (R10)
        let bytes = [0x44, 0x8B, 0x17];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(!insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.gpr_index, Some(10)); // R10
        assert_eq!(insn.len, 3);
    }

    // --- Error cases ---

    #[test]
    fn test_empty_bytes_error() {
        let regs = make_regs();
        assert!(decode_mmio_insn(&[], &regs).is_err());
    }

    #[test]
    fn test_unrecognized_opcode_error() {
        let regs = make_regs();
        let bytes = [0xFF, 0x07]; // Not a MOV
        assert!(decode_mmio_insn(&bytes, &regs).is_err());
    }

    // --- disp32 addressing ---

    #[test]
    fn test_mov_dword_ptr_disp32() {
        // mov dword [rdi+0x100], eax  →  89 87 00 01 00 00
        // ModRM: mod=10, reg=000(eax), r/m=111(rdi) → disp32
        let bytes = [0x89, 0x87, 0x00, 0x01, 0x00, 0x00];
        let regs = make_regs();
        let insn = decode_mmio_insn(&bytes, &regs).unwrap();
        assert!(insn.is_write);
        assert_eq!(insn.access_size, 4);
        assert_eq!(insn.data, regs.rax & 0xFFFF_FFFF);
        assert_eq!(insn.len, 6);
    }

    // --- read_gpr coverage ---

    #[test]
    fn test_read_gpr_all_registers() {
        let regs = make_regs();
        assert_eq!(read_gpr(&regs, 0), regs.rax);
        assert_eq!(read_gpr(&regs, 1), regs.rcx);
        assert_eq!(read_gpr(&regs, 2), regs.rdx);
        assert_eq!(read_gpr(&regs, 3), regs.rbx);
        assert_eq!(read_gpr(&regs, 4), regs.rsp);
        assert_eq!(read_gpr(&regs, 5), regs.rbp);
        assert_eq!(read_gpr(&regs, 6), regs.rsi);
        assert_eq!(read_gpr(&regs, 7), regs.rdi);
        assert_eq!(read_gpr(&regs, 8), regs.r8);
        assert_eq!(read_gpr(&regs, 9), regs.r9);
        assert_eq!(read_gpr(&regs, 10), regs.r10);
        assert_eq!(read_gpr(&regs, 11), regs.r11);
        assert_eq!(read_gpr(&regs, 12), regs.r12);
        assert_eq!(read_gpr(&regs, 13), regs.r13);
        assert_eq!(read_gpr(&regs, 14), regs.r14);
        assert_eq!(read_gpr(&regs, 15), regs.r15);
        assert_eq!(read_gpr(&regs, 16), 0); // Out of range
    }
}
