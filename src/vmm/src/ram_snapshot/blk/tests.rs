// SPDX-License-Identifier: Apache-2.0

//! Stage-3 block snapshot tests. The real-mode guest fixture is produced by
//! the hand-written byte emitter below (assembler execution is not permitted
//! for this change): every instruction is annotated with its encoding, and
//! branch targets are patched from symbolic labels. The guest enters unreal
//! mode (4 GiB cached data-segment limits) so a32-prefixed 32-bit
//! displacements reach the 0xd0000000 MMIO window and the IOAPIC.

use super::*;
use crate::ram_snapshot::RestoreResources;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vm_memory::{Bytes, GuestAddress};

// Every test name contains "snapshot" so `make snapshot-test` selects them
// through the cargo filter.

// Guest layout (guest RAM): code 0x1000, handler 0x1400, GDT 0x500, IVT
// entry 0x100, request header 0xA000, data buffer 0xB000 (512), status byte
// 0xB700, counters: requests 0xB800, boot marker 0xB802, interrupts 0xB804,
// capacity 0xB806 (u32), phase 0xB810, failure marker 0xB812, barrier
// marker 0xB814, barrier release 0xB815. Virtqueue: descriptor table
// 0xC000, avail ring 0xD100, used ring 0xD200; queue size 4 with one
// 3-descriptor chain (header, data, status). MMIO transport at 0xd0000000.
// Interrupts: IOAPIC GSI 16 -> vector 0x40 via IVT, x2APIC EOI in handler.

/// Guest physical address where `emit_guest` places the code.
const GUEST_CODE_BASE: usize = 0x1000;

/// Real-mode byte emitter with symbolic labels, rel16 branch fixups and
/// absolute far-jump fixups.
struct GuestEmitter {
    code: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    /// (patch at, next instruction, target) for rel16 branches.
    fixups: Vec<(usize, usize, &'static str)>,
    /// (patch at, target) for absolute 16-bit far-jump offsets.
    far_fixups: Vec<(usize, &'static str)>,
}

impl GuestEmitter {
    fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
            far_fixups: Vec::new(),
        }
    }

    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.code.len());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    /// Conditional jump `0f 8x rel16` (cc low nibble) to a label. The
    /// instruction is 4 bytes long, so the next instruction is at+4.
    fn jcc(&mut self, cc: u8, target: &'static str) {
        let at = self.code.len();
        self.bytes(&[0x0f, 0x80 | cc]);
        self.fixups.push((at + 2, at + 4, target));
        self.bytes(&[0, 0]);
    }

    /// Near jump `e9 rel16` to a label.
    fn jmp(&mut self, target: &'static str) {
        let at = self.code.len();
        self.bytes(&[0xe9]);
        self.fixups.push((at + 1, at + 3, target));
        self.bytes(&[0, 0]);
    }

    /// Far jump `ea off16 seg16`; the offset is patched to the absolute
    /// guest address of the target label.
    fn jmp_far(&mut self, segment: u16, target: &'static str) {
        let at = self.code.len();
        self.bytes(&[0xea, 0, 0]);
        self.bytes(&segment.to_le_bytes());
        self.far_fixups.push((at + 1, target));
    }

    /// `mov dword [a32 disp32], imm32` — MMIO/register stores by address.
    fn store32(&mut self, address: u32, value: u32) {
        let mut instruction = vec![0x67, 0x66, 0xc7, 0x05];
        instruction.extend_from_slice(&address.to_le_bytes());
        instruction.extend_from_slice(&value.to_le_bytes());
        self.bytes(&instruction);
    }

    /// `mov byte [a32 disp32], imm8`.
    fn store8(&mut self, address: u32, value: u8) {
        let mut instruction = vec![0x67, 0xc6, 0x05];
        instruction.extend_from_slice(&address.to_le_bytes());
        instruction.push(value);
        self.bytes(&instruction);
    }

    /// `mov word [disp16], imm16` for the low-memory GDT build.
    fn store_word16(&mut self, address: u16, value: u16) {
        self.bytes(&[0xc7, 0x06]);
        self.bytes(&address.to_le_bytes());
        self.bytes(&value.to_le_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let fixes = std::mem::take(&mut self.fixups);
        let far_fixes = std::mem::take(&mut self.far_fixups);
        let labels = &self.labels;
        for (patch, next, target) in fixes {
            let to = labels[target];
            let rel = (to as i64 - next as i64) as i16;
            self.code[patch..patch + 2].copy_from_slice(&rel.to_le_bytes());
        }
        for (patch, target) in far_fixes {
            let absolute = GUEST_CODE_BASE + labels[target];
            self.code[patch..patch + 2].copy_from_slice(&(absolute as u16).to_le_bytes());
        }
        self.code
    }
}

// MMIO register addresses derived from the fixed internal window.
const MMIO: u32 = 0xd000_0000;
const IOAPIC_REGSEL: u32 = 0xfec0_0000;
const IOAPIC_WIN: u32 = 0xfec0_0010;

// Fixed guest addresses used by the program.
const HEADER: u32 = 0xA000;
/// Descriptor 1 words at 0xC010: flags at +12, next at +14; one aligned
/// 32-bit store packs both (next << 16) | flags.
const DATA_DESC_WORDS: u32 = 0xC000 + 16 + 12;
/// Packed (next=2 << 16) | flags for each request type: read data is
/// device-writable (NEXT|WRITE), write/flush data is device-readable.
const FLAGS_READ: u32 = (2 << 16) | 0x3;
const FLAGS_WRITE: u32 = (2 << 16) | 0x1;
const DATA_BUFFER: u32 = 0xB000;
const STATUS_BYTE: u32 = 0xB700;
const AVAIL_IDX: u32 = 0xD102;
const USED_IDX: u32 = 0xD202;
const REQUESTS: u32 = 0xB800;
const BOOT_MARKER: u32 = 0xB802;
const INTERRUPTS: u32 = 0xB804;
const CAPACITY: u32 = 0xB806;
const PHASE: u32 = 0xB810;
const FAIL_MARKER: u32 = 0xB812;
const BARRIER_MARKER: u32 = 0xB814;
const BARRIER_RELEASE: u32 = 0xB815;
const BARRIER_DELIVERED: u32 = 0xB816;
/// The barrier parks once this many requests have COMPLETED; the request
/// that produces the pending IRQ is index BARRIER_REQUEST-1 (a WRITE,
/// phase (BARRIER_REQUEST-1) % 3 == 1), submitted only after the guest
/// cleared IF. The host observes the park marker and cuts with IF=0.
const BARRIER_REQUEST: u8 = 11;

/// Emit the whole driver. The test initializes the static rings so the
/// guest only sets up unreal mode, negotiates, submits, verifies and
/// interrupts. Requests cycle read (sector 1, expecting 0xC7), write
/// (sector 0, pattern 0x41 + request counter) and flush; each status byte
/// is reset to a 0xEE sentinel before submitting so a lost status write
/// fails the request instead of passing on stale data.
fn emit_guest() -> Vec<u8> {
    let mut e = GuestEmitter::new();

    e.label("start");
    e.bytes(&[0xfa]); // cli
    e.bytes(&[0x31, 0xc0]); // xor ax, ax
    e.bytes(&[0x8e, 0xd8]); // mov ds, ax
    e.bytes(&[0x8e, 0xd0]); // mov ss, ax
    e.bytes(&[0x8e, 0xc0]); // mov es, ax
    e.bytes(&[0xbc, 0x00, 0x70]); // mov sp, 0x7000
    e.bytes(&[0xff, 0x06, 0x02, 0xb8]); // inc word [boot marker]
                                        // Unreal-mode setup, exactly: the GDTR record sits at 0x500 (limit 23,
                                        // base 0x520); the GDT at 0x520 holds a null entry, a 16-bit 4 GiB
                                        // code descriptor (D=0 so the 16-bit code stays 16-bit, G=1) at
                                        // selector 8, and a 4 GiB data descriptor at selector 0x10. PE is
                                        // entered only long enough to cache DS/ES; after returning to real
                                        // mode the data selectors are NOT reloaded (a reload would replace the
                                        // cached 4 GiB limits with real-mode 64 KiB ones).
    e.store_word16(0x500, 23); // GDTR limit: 3 entries * 8 - 1
    e.store_word16(0x502, 0x520); // GDTR base low word
    e.store_word16(0x504, 0); // GDTR base high
                              // Null entry 0x520..0x527 stays zero (fresh RAM).
                              // Code @0x528: ff ff 00 00 00 9a 8f 00
    e.store_word16(0x528, 0xffff);
    e.store_word16(0x52a, 0x0000);
    e.store_word16(0x52c, 0x9a00);
    e.store_word16(0x52e, 0x008f);
    // Data @0x530: ff ff 00 00 00 92 cf 00
    e.store_word16(0x530, 0xffff);
    e.store_word16(0x532, 0x0000);
    e.store_word16(0x534, 0x9200);
    e.store_word16(0x536, 0x00cf);
    e.bytes(&[0x0f, 0x01, 0x16, 0x00, 0x05]); // lgdt [0x500]
    e.bytes(&[0x66, 0x0f, 0x20, 0xc0]); // mov eax, cr0
    e.bytes(&[0x66, 0x0d, 0x01, 0x00, 0x00, 0x00]); // or eax, 1 (PE)
    e.bytes(&[0x66, 0x0f, 0x22, 0xc0]); // mov cr0, eax
    e.jmp_far(0x0008, "pe_next"); // jmp far 0x08:pe_next (16-bit code)
    e.label("pe_next");
    e.bytes(&[0xb8, 0x10, 0x00]); // mov ax, 0x10 (flat data selector)
    e.bytes(&[0x8e, 0xd8]); // mov ds, ax
    e.bytes(&[0x8e, 0xc0]); // mov es, ax
    e.bytes(&[0x66, 0x0f, 0x20, 0xc0]); // mov eax, cr0
    e.bytes(&[0x66, 0x25, 0xfe, 0xff, 0xff, 0xff]); // and eax, ~1
    e.bytes(&[0x66, 0x0f, 0x22, 0xc0]); // mov cr0, eax
    e.jmp_far(0x0000, "rm_next"); // jmp far 0x0000:rm_next
    e.label("rm_next");
    // DS/ES deliberately keep the cached 4 GiB descriptors: no reload.
    // Status machine: reset, ACKNOWLEDGE, +DRIVER, FEATURES_OK, DRIVER_OK.
    e.store32(MMIO + 0x70, 0);
    e.store32(MMIO + 0x70, 1);
    e.store32(MMIO + 0x70, 3);
    // Ack FLUSH (page 0, bit 9) and VERSION_1 (page 1, bit 0).
    e.store32(MMIO + 0x24, 0);
    e.store32(MMIO + 0x20, 0x200);
    e.store32(MMIO + 0x24, 1);
    e.store32(MMIO + 0x20, 1);
    e.store32(MMIO + 0x70, 0xb);
    // One queue of size 4 at the fixed ring addresses.
    e.store32(MMIO + 0x30, 0);
    e.store32(MMIO + 0x38, 4);
    e.store32(MMIO + 0x80, 0xC000);
    e.store32(MMIO + 0x84, 0);
    e.store32(MMIO + 0x90, 0xD100);
    e.store32(MMIO + 0x94, 0);
    e.store32(MMIO + 0xa0, 0xD200);
    e.store32(MMIO + 0xa4, 0);
    e.store32(MMIO + 0x44, 1);
    e.store32(MMIO + 0x70, 0xf);
    // IOAPIC redirection-table entry 16: selector 0x10+2*16 = 0x30.
    e.store32(IOAPIC_REGSEL, 0x30);
    e.store32(IOAPIC_WIN, 0x40); // vector 0x40, unmasked
    e.store32(IOAPIC_REGSEL, 0x31);
    e.store32(IOAPIC_WIN, 0); // physical destination APIC 0
                              // IVT vector 0x40 -> handler at 0x1400.
    e.bytes(&[0xc7, 0x06, 0x00, 0x01, 0x00, 0x14]); // mov word [0x100], 0x1400
    e.bytes(&[0xc7, 0x06, 0x02, 0x01, 0x00, 0x00]); // mov word [0x102], 0
                                                    // x2APIC enable + spurious vector (32-bit ops carry 0x66 in 16-bit).
    e.bytes(&[0x66, 0xb9, 0x1b, 0x00, 0x00, 0x00]); // mov ecx, 0x1b
    e.bytes(&[0x0f, 0x32]); // rdmsr
    e.bytes(&[0x66, 0x0d, 0x00, 0x0c, 0x00, 0x00]); // or eax, 0xc00
    e.bytes(&[0x0f, 0x30]); // wrmsr
    e.bytes(&[0x66, 0xb9, 0x0f, 0x08, 0x00, 0x00]); // mov ecx, 0x80f
    e.bytes(&[0x66, 0xb8, 0xff, 0x01, 0x00, 0x00]); // mov eax, 0x1ff
    e.bytes(&[0x66, 0x31, 0xd2]); // xor edx, edx
    e.bytes(&[0x0f, 0x30]); // wrmsr
    e.bytes(&[0xfb]); // sti

    e.label("loop");
    // Clear IF BEFORE the barrier request is submitted: request index
    // BARRIER_REQUEST-1 is still to run (the completed count is one less),
    // so its device IRQ provably stays pending (in the irqchip IRR) through
    // the completion poll, the cut and the restore.
    e.bytes(&[0xa0]); // mov al, [requests]
    e.bytes(&REQUESTS.to_le_bytes()[..2]);
    e.bytes(&[0x3c]); // cmp al, BARRIER_REQUEST-1
    e.bytes(&[BARRIER_REQUEST - 1]);
    e.jcc(0x85, "no_barrier_cli"); // jne no_barrier_cli
    e.bytes(&[0xfa]); // cli
    e.label("no_barrier_cli");
    // Dispatch on the phase byte: 0 read, 1 write, otherwise flush.
    e.bytes(&[0xa0]); // mov al, [phase]
    e.bytes(&PHASE.to_le_bytes()[..2]);
    e.bytes(&[0x3c, 0x00]); // cmp al, 0
    e.jcc(0x85, "write"); // jne write
    e.store32(HEADER, 0); // type IN
    e.store32(HEADER + 8, 1); // sector 1
    e.store32(DATA_DESC_WORDS, FLAGS_READ);
    e.jmp("submit");
    e.label("write");
    e.bytes(&[0x3c, 0x01]); // cmp al, 1
    e.jcc(0x85, "flush"); // jne flush
    e.store32(HEADER, 1); // type OUT
    e.store32(HEADER + 8, 0); // sector 0
    e.store32(DATA_DESC_WORDS, FLAGS_WRITE);
    e.bytes(&[0xa0]); // mov al, [requests]
    e.bytes(&REQUESTS.to_le_bytes()[..2]);
    e.bytes(&[0x04, 0x41]); // add al, 0x41
    e.bytes(&[0xb9, 0x00, 0x02]); // mov cx, 512
    e.bytes(&[0xbf]); // mov di, DATA_BUFFER
    e.bytes(&DATA_BUFFER.to_le_bytes()[..2]);
    e.bytes(&[0xf3, 0xaa]); // rep stosb
    e.jmp("submit");
    e.label("flush");
    e.store32(HEADER, 4); // type FLUSH
    e.store32(HEADER + 8, 0);
    e.store32(DATA_DESC_WORDS, FLAGS_WRITE); // readable data keeps the chain
    e.label("submit");
    e.store32(HEADER + 4, 0);
    e.store32(HEADER + 12, 0);
    e.store8(STATUS_BYTE, 0xee); // sentinel: a missing status write fails
    e.bytes(&[0xff, 0x06]); // inc word [avail_idx]
    e.bytes(&AVAIL_IDX.to_le_bytes()[..2]);
    e.store32(MMIO + 0x50, 0); // notify queue 0 (ioeventfd)
    e.label("wait");
    e.bytes(&[0x8b, 0x1e]); // mov bx, [used_idx]
    e.bytes(&USED_IDX.to_le_bytes()[..2]);
    e.bytes(&[0x3b, 0x1e]); // cmp bx, [avail_idx]
    e.bytes(&AVAIL_IDX.to_le_bytes()[..2]);
    e.jcc(0x82, "wait"); // jb wait
    e.bytes(&[0x80, 0x3e]); // cmp byte [status], 0
    e.bytes(&STATUS_BYTE.to_le_bytes()[..2]);
    e.bytes(&[0x00]);
    e.jcc(0x85, "fail"); // jne fail
    e.bytes(&[0x80, 0x3e]); // cmp byte [status], 0xee
    e.bytes(&STATUS_BYTE.to_le_bytes()[..2]);
    e.bytes(&[0xee]);
    e.jcc(0x84, "fail"); // je fail (status write never happened)
                         // Read phases verify the data content of sector 1.
    e.bytes(&[0x80, 0x3e]); // cmp byte [phase], 0
    e.bytes(&PHASE.to_le_bytes()[..2]);
    e.bytes(&[0x00]);
    e.jcc(0x85, "skip"); // jne skip
    e.bytes(&[0x80, 0x3e, 0x00, 0xb0, 0xc7]); // cmp byte [0xb000], 0xc7
    e.jcc(0x85, "fail"); // jne fail
    e.label("skip");
    // Publish the guest-visible capacity for the test to compare.
    e.bytes(&[0x67, 0x66, 0xa1, 0x00, 0x01, 0x00, 0xd0]); // mov eax, [mmio+0x100]
    e.bytes(&[0x66, 0xa3]); // mov [capacity], eax
    e.bytes(&CAPACITY.to_le_bytes()[..2]);
    e.store32(MMIO + 0x64, 3); // ack both interrupt causes
    e.bytes(&[0xff, 0x06]); // inc word [requests]
    e.bytes(&REQUESTS.to_le_bytes()[..2]);
    e.bytes(&[0xfe, 0x06]); // inc byte [phase]
    e.bytes(&PHASE.to_le_bytes()[..2]);
    e.bytes(&[0x80, 0x3e]); // cmp byte [phase], 3
    e.bytes(&PHASE.to_le_bytes()[..2]);
    e.bytes(&[0x03]);
    e.jcc(0x82, "park_check"); // jb park_check
    e.store32(PHASE, 0);
    e.label("park_check");
    // Park only after the barrier request itself completed with IF=0: the
    // completed count now equals BARRIER_REQUEST.
    e.bytes(&[0xa0]); // mov al, [requests]
    e.bytes(&REQUESTS.to_le_bytes()[..2]);
    e.bytes(&[0x3c]); // cmp al, BARRIER_REQUEST
    e.bytes(&[BARRIER_REQUEST]);
    e.jcc(0x85, "loop"); // jne loop
                         // The barrier round's device IRQ is pending: IF has been 0 since before
                         // its submission. A byte store marks the park (word-wide stores would
                         // clobber the adjacent release byte).
    e.store8(BARRIER_MARKER, 1);
    e.label("barrier");
    e.bytes(&[0x80, 0x3e]); // cmp byte [release], 1
    e.bytes(&BARRIER_RELEASE.to_le_bytes()[..2]);
    e.bytes(&[0x01]);
    e.jcc(0x85, "barrier"); // jne barrier
    e.bytes(&[0xfb]); // sti: the pending IRQ is delivered now
                      // Post-STI proof stage: wait until the interrupt counter moves — only
                      // the handler writes it and no new request exists yet — then set the
                      // delivered marker. A lost pending IRQ can never reach this marker.
    e.bytes(&[0x8b, 0x1e]); // mov bx, [interrupts]
    e.bytes(&INTERRUPTS.to_le_bytes()[..2]);
    e.label("delivered_wait");
    e.bytes(&[0x3b, 0x1e]); // cmp bx, [interrupts]
    e.bytes(&INTERRUPTS.to_le_bytes()[..2]);
    e.jcc(0x84, "delivered_wait"); // je delivered_wait
    e.store8(BARRIER_DELIVERED, 1);
    e.jmp("loop");
    e.label("fail");
    e.store32(FAIL_MARKER, 1);
    e.label("halt");
    e.bytes(&[0xf4]); // hlt
    e.jmp("halt");

    let mut code = e.finish();
    assert!(
        code.len() <= 0x400,
        "guest code overlaps the handler slot (len {})",
        code.len()
    );
    code.resize(0x400, 0);
    // Handler at 0x1400: count the interrupt, x2APIC EOI, preserve all
    // touched registers (32-bit ops carry the 0x66 prefix in 16-bit mode).
    code.extend_from_slice(&[
        0x66,
        0x50, // push eax
        0x66,
        0x51, // push ecx
        0x66,
        0x52, // push edx
        0xff,
        0x06,
        INTERRUPTS as u8,
        (INTERRUPTS >> 8) as u8, // inc word [0xB804]
        0x66,
        0xb9,
        0x0b,
        0x08,
        0x00,
        0x00, // mov ecx, 0x80b (EOI)
        0x66,
        0x31,
        0xc0, // xor eax, eax
        0x66,
        0x31,
        0xd2, // xor edx, edx
        0x0f,
        0x30, // wrmsr
        0x66,
        0x5a, // pop edx
        0x66,
        0x59, // pop ecx
        0x66,
        0x58, // pop eax
        0xcf, // iret
    ]);
    code
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krun-blk-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn raw_disk(path: &Path, bytes: u64, fill: impl Fn(&mut [u8])) {
    let mut image = vec![0u8; bytes as usize];
    fill(&mut image);
    fs::write(path, &image).unwrap();
}

/// Hand-built minimal qcow2 v3 image (64 KiB clusters, one L1 entry,
/// everything unallocated) whose reads fall through to a raw backing file.
/// Header extensions sit between the 104-byte v3 header and the backing
/// file name at 0x400, per the qcow2 layout.
fn qcow2_with_raw_backing(path: &Path, backing: &Path, virtual_size: u64) {
    const CLUSTER: u64 = 0x10000;
    let mut image = vec![0u8; (CLUSTER * 4) as usize];
    let be32 = |image: &mut Vec<u8>, offset: usize, value: u32| {
        image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    };
    let be64 = |image: &mut Vec<u8>, offset: usize, value: u64| {
        image[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    };
    image[0..4].copy_from_slice(b"QFI\xfb"); // magic
    be32(&mut image, 4, 3); // version 3
    be64(&mut image, 8, 0x400); // backing_file_offset (after extensions)
    let name = backing.as_os_str().as_encoded_bytes();
    be32(&mut image, 16, name.len() as u32); // backing_file_size (u32)
    be32(&mut image, 20, 16); // cluster_bits: 64 KiB clusters
    be64(&mut image, 24, virtual_size); // virtual size
    be32(&mut image, 36, 1); // l1_size (one entry covers 512 MiB)
    be64(&mut image, 40, CLUSTER * 2); // l1_table_offset
    be64(&mut image, 48, CLUSTER); // refcount_table_offset
    be32(&mut image, 56, 1); // refcount_table_clusters
    be32(&mut image, 100, 4); // refcount_order: 16-bit refcounts
    be32(&mut image, 104, 112); // header_length (v3)
                                // Backing-format extension "raw", then the zero terminator, both 8-byte
                                // aligned, before the backing name area at 0x400.
    be32(&mut image, 112, 0xE2792ACA); // ext: backing file format
    be32(&mut image, 116, 3); // length "raw"
    image[120..123].copy_from_slice(b"raw");
    be32(&mut image, 128, 0); // terminator extension
    be32(&mut image, 132, 0);
    image[0x400..0x400 + name.len()].copy_from_slice(name);
    // refcount table entry 0 -> refcount block at cluster 3; refcounts for
    // the four metadata clusters are 1 (16-bit big endian each).
    be64(&mut image, CLUSTER as usize, CLUSTER * 3);
    for cluster in 0..4u64 {
        let at = (CLUSTER * 3) as usize + (cluster * 2) as usize;
        image[at..at + 2].copy_from_slice(&1u16.to_be_bytes());
    }
    fs::write(path, &image).unwrap();
}

/// Initialize the static virtqueue contents the guest program relies on.
fn initialize_rings(vm: &RamSnapshotVm) {
    let mem = &vm.memory;
    // Descriptor chain 0..2: header (readable, next), data (direction set
    // per request at 0xC00C), status byte (writable).
    let descriptors = [
        (0xC000u64, 0xA000u64, 16u32, 1u16, 1u16), // hdr: flags NEXT, next 1
        (0xC010, 0xB000, 512, 2, 2),               // data: WRITE (read phase default), next 2
        (0xC020, 0xB700, 1, 2, 0),                 // status: WRITE, no next
    ];
    for (desc_addr, buffer, len, flags, next) in descriptors {
        mem.write_obj(buffer, GuestAddress(desc_addr)).unwrap();
        mem.write_obj(len, GuestAddress(desc_addr + 8)).unwrap();
        mem.write_obj(flags, GuestAddress(desc_addr + 12)).unwrap();
        mem.write_obj(next, GuestAddress(desc_addr + 14)).unwrap();
    }
    // avail ring: flags, idx, ring[0] = chain head 0.
    mem.write_obj(0u16, GuestAddress(0xD100)).unwrap();
    mem.write_obj(0u16, GuestAddress(0xD102)).unwrap();
    mem.write_obj(0u16, GuestAddress(0xD104)).unwrap();
    // used ring: flags, idx.
    mem.write_obj(0u16, GuestAddress(0xD200)).unwrap();
    mem.write_obj(0u16, GuestAddress(0xD202)).unwrap();
}

/// Build a running one-vCPU guest with the given disks attached. With
/// `park_at_barrier == false` the release byte is pre-set so the guest
/// never parks at the request-10 barrier (ordinary progress/recovery
/// tests); explicit barrier tests pass true and keep it 0.
fn guest_vm(disks: &[(PathBuf, ImageType, bool)], park_at_barrier: bool) -> RamSnapshotVm {
    let mut vm = crate::builder::build_ram_snapshot_vm(
        4,
        &Default::default(),
        &crate::builder::Payload::Empty,
    )
    .unwrap();
    vm.memory
        .write_slice(&emit_guest(), GuestAddress(GUEST_CODE_BASE as u64))
        .unwrap();
    initialize_rings(&vm);
    if !park_at_barrier {
        vm.memory.write_obj(1u8, GuestAddress(0xB815)).unwrap();
    }
    for (path, format, read_only) in disks {
        vm.attach_disk(path, format.clone(), *read_only, false)
            .unwrap();
    }
    vm.start_vcpus(1, GUEST_CODE_BASE as u16).unwrap();
    vm
}

fn read_u16(vm: &RamSnapshotVm, address: u64) -> u16 {
    vm.memory.read_obj::<u16>(GuestAddress(address)).unwrap()
}

fn wait_requests(vm: &RamSnapshotVm, at_least: u16) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let current = read_u16(vm, 0xB800);
        assert_eq!(read_u16(vm, 0xB812), 0, "guest reported a request failure");
        if current >= at_least {
            return current;
        }
        assert!(
            Instant::now() < deadline,
            "guest request counter did not reach {at_least}; stuck at {current}"
        );
        std::thread::yield_now();
    }
}

/// Wait until the guest sits inside the deterministic pending-interrupt
/// barrier: marker set, CPU spinning with IF=0.
fn wait_barrier(vm: &RamSnapshotVm) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert_eq!(read_u16(vm, 0xB812), 0, "guest reported a request failure");
        if read_u16(vm, 0xB814) == 1 {
            return read_u16(vm, 0xB800);
        }
        assert!(
            Instant::now() < deadline,
            "guest never entered the pending-interrupt barrier"
        );
        std::thread::yield_now();
    }
}

fn snapshot_disks(dir: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let raw = dir.path("d0.raw");
    raw_disk(&raw, 512 * 2048, |image| image[512..1024].fill(0xC7));
    let backing = dir.path("d2-backing.raw");
    raw_disk(&backing, 512 * 2048, |image| image.fill(0x77));
    let qcow2 = dir.path("d2.qcow2");
    qcow2_with_raw_backing(&qcow2, &backing, 512 * 2048);
    (raw, qcow2, backing)
}

/// Preserve guest block-I/O and pending-IRQ assertions through direct QCOW2 restore.
#[test]
fn blk_snapshot_v9_pending_interrupt_and_qcow2_io_continue() {
    use crate::snapshot_vm::checkpoint::{ExportMetadata, ImportBindings};
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TempDir::new();
    let disk = dir.path("source.qcow2");
    assert!(std::process::Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&disk)
        .arg("1M")
        .status()
        .unwrap()
        .success());
    // The original guest fixture checks sector 1 for 0xc7 before its write/flush loop.
    assert!(std::process::Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "write -P 0xc7 512 512"])
        .arg(&disk)
        .status()
        .unwrap()
        .success());
    let mut vm = guest_vm(&[(disk.clone(), ImageType::Qcow2, false)], true);
    let at_barrier = wait_barrier(&vm);
    assert!(at_barrier >= BARRIER_REQUEST as u16);
    let interrupts_before = read_u16(&vm, 0xB804);
    vm.pause().unwrap();
    let cut_requests = read_u16(&vm, 0xB800);
    let cut_interrupts = read_u16(&vm, 0xB804);
    assert_eq!(cut_interrupts, interrupts_before);
    assert_eq!(read_u16(&vm, 0xB815), 0);
    for name in ["checkpoint", "again"] {
        vm.prepare_checkpoint().unwrap();
        let memory = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path(name))
            .unwrap();
        fs::copy(&disk, dir.path(&format!("{name}.qcow2"))).unwrap();
        let qcow2 = File::open(dir.path(&format!("{name}.qcow2"))).unwrap();
        vm.export_fd(
            memory,
            qcow2,
            ExportMetadata {
                application_schema: 1,
                application: serde_json::Value::Null,
                objects: vec![],
            },
        )
        .unwrap();
        assert_eq!(read_u16(&vm, 0xB800), cut_requests);
    }
    // Mutated metadata comes from the actual activated device boundary.
    let regions = vm.topology.regions(&vm.memory).unwrap();
    let captured = capture_disks(&vm, &vm.pause.as_ref().unwrap().disks, &regions).unwrap();
    let original = serde_json::to_value(&captured).unwrap();
    for (path, replacement) in [
        ("/0/irq", serde_json::json!(0)),
        ("/0/mmio_addr", serde_json::json!(0)),
        ("/0/mmio_len", serde_json::json!(1)),
        ("/0/device_id", serde_json::json!("")),
        ("/0/disk_bytes", serde_json::json!(0)),
        ("/0/config/0", serde_json::json!(1)),
        ("/0/image_id", serde_json::json!([])),
        ("/0/device/avail_features", serde_json::json!(0)),
        ("/0/device/queues/0/max_size", serde_json::json!(1024)),
        ("/0/transport/device_status", serde_json::json!(0)),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let bad: Vec<DiskMeta> = serde_json::from_value(value).unwrap();
        assert!(
            validate_disk_metadata(&bad, &regions).is_err(),
            "accepted bad {path}"
        );
    }
    let mut bad: Vec<DiskMeta> = serde_json::from_value(original).unwrap();
    bad[0].device.queues[0].desc_table = 1 << 40;
    validate_disk_metadata(&bad, &regions).unwrap();
    assert!(
        validate_disk_rings(&bad, &vm.memory).is_err(),
        "block ring outside RAM accepted"
    );
    let mut bad: Vec<DiskMeta> =
        serde_json::from_value(serde_json::to_value(&captured).unwrap()).unwrap();
    for size in [3, 7, 1024] {
        bad[0].device.queues[0].size = size;
        assert!(
            validate_disk_rings(&bad, &vm.memory).is_err(),
            "invalid size {size} accepted at loaded RAM boundary"
        );
    }
    drop(vm);
    fs::remove_file(&disk).unwrap();
    fs::copy(dir.path("checkpoint.qcow2"), dir.path("owned.qcow2")).unwrap();
    let qcow2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path("owned.qcow2"))
        .unwrap();
    let mut restored = RamSnapshotVm::import_fd(
        File::open(dir.path("checkpoint")).unwrap(),
        ImportBindings {
            disks: vec![qcow2],
            shares: vec![],
        },
        RestoreResources::default(),
    )
    .unwrap();
    assert_eq!(read_u16(&restored, 0xB800), cut_requests);
    assert_eq!(read_u16(&restored, 0xB804), cut_interrupts);
    assert_eq!(read_u16(&restored, 0xB814), 1);
    assert_eq!(read_u16(&restored, 0xB815), 0);
    assert_eq!(read_u16(&restored, 0xB816), 0);
    restored
        .memory
        .write_obj(1u8, GuestAddress(0xB815))
        .unwrap();
    restored.resume().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_u16(&restored, 0xB816) == 0 {
        assert!(
            Instant::now() < deadline,
            "pending interrupt lost across checkpoint"
        );
        std::thread::yield_now();
    }
    assert!(read_u16(&restored, 0xB804) > cut_interrupts);
    wait_requests(&restored, cut_requests + 9);
    restored.pause().unwrap();
}
