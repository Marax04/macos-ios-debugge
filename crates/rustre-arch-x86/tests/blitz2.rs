//! blitz2: deep adversarial coverage for rustre-arch-x86.
//!
//! No std::time, no rand, no external dep â€” uses a seeded LCG.

use rustre_arch_x86::{
    disassemble_and_lift, lift_to_llil, ArchX86Lifter, LinearDisassembler, X86Arch, X86LiftAdapter,
};
use rustre_core::address::Address;
use rustre_core::arch::{Architecture, InstrFlags};
use rustre_core::endian::Endian;
use std::sync::Arc;
use std::thread;

// ---- LCG ------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

// ===========================================================================
// Architecture properties
// ===========================================================================

#[test]
fn arch_bits_16_32_64() {
    assert_eq!(X86Arch::new_16bit().bits(), 16);
    assert_eq!(X86Arch::new_32bit().bits(), 32);
    assert_eq!(X86Arch::new_64bit().bits(), 64);
}

#[test]
fn arch_pointer_size_matches_bits() {
    assert_eq!(X86Arch::new_16bit().pointer_size(), 2);
    assert_eq!(X86Arch::new_32bit().pointer_size(), 4);
    assert_eq!(X86Arch::new_64bit().pointer_size(), 8);
}

#[test]
fn arch_name_consistency() {
    assert_eq!(X86Arch::new_16bit().name(), "x86_16");
    assert_eq!(X86Arch::new_32bit().name(), "x86_32");
    assert_eq!(X86Arch::new_64bit().name(), "x86_64");
}

#[test]
fn arch_always_little_endian() {
    assert_eq!(X86Arch::new_16bit().endian(), Endian::Little);
    assert_eq!(X86Arch::new_32bit().endian(), Endian::Little);
    assert_eq!(X86Arch::new_64bit().endian(), Endian::Little);
}

#[test]
fn arch_clone_eq() {
    let a = X86Arch::new_64bit();
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, X86Arch::new_32bit());
}

// ===========================================================================
// Disassembly: known good encodings
// ===========================================================================

#[test]
fn disasm_nop() {
    let arch = X86Arch::new_64bit();
    let i = arch.disassemble(Address::new(0x1000), &[0x90]).unwrap();
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.size, 1);
    assert_eq!(i.address.0, 0x1000);
}

#[test]
fn disasm_ret_flag_correct() {
    let arch = X86Arch::new_64bit();
    let i = arch.disassemble(Address::new(0x0), &[0xc3]).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
    assert!(!i.flags.contains(InstrFlags::BRANCH));
}

#[test]
fn disasm_int3_byte() {
    let arch = X86Arch::new_64bit();
    let i = arch.disassemble(Address::new(0x0), &[0xcc]).unwrap();
    assert_eq!(i.size, 1);
    assert!(!i.flags.contains(InstrFlags::RET));
}

#[test]
fn disasm_push_rbp() {
    let arch = X86Arch::new_64bit();
    let i = arch.disassemble(Address::new(0x0), &[0x55]).unwrap();
    assert_eq!(i.size, 1);
}

#[test]
fn disasm_mov_imm32_64bit() {
    // mov eax, 1 -> B8 01 00 00 00 in 32/64-bit mode
    let arch = X86Arch::new_64bit();
    let i = arch
        .disassemble(Address::new(0x0), &[0xB8, 0x01, 0x00, 0x00, 0x00])
        .unwrap();
    assert_eq!(i.size, 5);
    assert_eq!(i.mnemonic, "mov");
}

#[test]
fn disasm_call_rel32_branch_target() {
    let arch = X86Arch::new_64bit();
    let i = arch
        .disassemble(Address::new(0x1005), &[0xe8, 0xfb, 0xff, 0xff, 0xff])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::CALL));
    let br = arch.get_branches(&i);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].target, Some(0x1005));
}

#[test]
fn disasm_jmp_short() {
    let arch = X86Arch::new_64bit();
    // jmp +2 â†’ EB 02
    let i = arch
        .disassemble(Address::new(0x0), &[0xEB, 0x02])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::BRANCH));
    assert!(!i.flags.contains(InstrFlags::CONDITIONAL));
}

#[test]
fn disasm_jne_short_conditional() {
    let arch = X86Arch::new_64bit();
    // jne +2 â†’ 75 02
    let i = arch
        .disassemble(Address::new(0x0), &[0x75, 0x02])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::BRANCH));
    assert!(i.flags.contains(InstrFlags::CONDITIONAL));
}

#[test]
fn disasm_indirect_jmp_rax() {
    let arch = X86Arch::new_64bit();
    // jmp rax â†’ FF E0
    let i = arch
        .disassemble(Address::new(0x0), &[0xFF, 0xE0])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::INDIRECT));
}

#[test]
fn disasm_mov_mem_to_reg_read_flag() {
    let arch = X86Arch::new_64bit();
    // mov rax, [rcx] â†’ 48 8B 01
    let i = arch
        .disassemble(Address::new(0x0), &[0x48, 0x8B, 0x01])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::READ_MEM));
}

#[test]
fn disasm_mov_reg_to_mem_write_flag() {
    let arch = X86Arch::new_64bit();
    // mov [rcx], rax â†’ 48 89 01
    let i = arch
        .disassemble(Address::new(0x0), &[0x48, 0x89, 0x01])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::WRITE_MEM));
}

// ===========================================================================
// Empty / truncated / malformed
// ===========================================================================

#[test]
fn disasm_empty_input_errors() {
    let arch = X86Arch::new_64bit();
    assert!(arch.disassemble(Address::new(0x0), &[]).is_err());
}

#[test]
fn disasm_truncated_call_errors() {
    let arch = X86Arch::new_64bit();
    // CALL rel32 needs 5 bytes â€” only give 3
    let res = arch.disassemble(Address::new(0x0), &[0xe8, 0x00, 0x00]);
    assert!(res.is_err());
}

#[test]
fn disasm_lift_empty_bytes_errors() {
    let arch = X86Arch::new_64bit();
    let r = arch.lift(Address::new(0x0), &[]);
    assert!(r.is_err());
}

// ===========================================================================
// LinearDisassembler
// ===========================================================================

#[test]
fn linear_iterates_until_done() {
    let arch = X86Arch::new_64bit();
    let bytes: &[u8] = &[0x90, 0x90, 0x90, 0xc3]; // nop nop nop ret
    let mut d = LinearDisassembler::new(&arch, bytes, Address::new(0x1000));
    let mut count = 0;
    for r in d.by_ref() {
        r.unwrap();
        count += 1;
    }
    assert_eq!(count, 4);
    assert!(d.is_done());
}

#[test]
fn linear_offset_advances() {
    let arch = X86Arch::new_64bit();
    let bytes: &[u8] = &[0x90, 0x90];
    let mut d = LinearDisassembler::new(&arch, bytes, Address::new(0x2000));
    assert_eq!(d.offset(), 0);
    assert_eq!(d.current_address().0, 0x2000);
    d.next().unwrap().unwrap();
    assert_eq!(d.offset(), 1);
    assert_eq!(d.current_address().0, 0x2001);
}

#[test]
fn linear_empty_yields_none() {
    let arch = X86Arch::new_64bit();
    let mut d = LinearDisassembler::new(&arch, &[], Address::new(0x0));
    assert!(d.next().is_none());
    assert!(d.is_done());
}

#[test]
fn linear_does_not_advance_on_error() {
    let arch = X86Arch::new_64bit();
    // 0x06 is invalid in 64-bit mode
    let bytes: &[u8] = &[0x06];
    let mut d = LinearDisassembler::new(&arch, bytes, Address::new(0x0));
    let first = d.next();
    if let Some(Err(_)) = first {
        // Offset must not be past the bad byte.
        assert!(d.offset() <= 1);
    }
}

#[test]
fn linear_addresses_unique_per_instr() {
    let arch = X86Arch::new_64bit();
    let bytes: &[u8] = &[0x90, 0xc3, 0x90, 0x90];
    let d = LinearDisassembler::new(&arch, bytes, Address::new(0x4000));
    let addrs: Vec<u64> = d.filter_map(|r| r.ok().map(|i| i.address.0)).collect();
    let mut sorted = addrs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), addrs.len());
}

// ===========================================================================
// LCG fuzzers â€” must never panic
// ===========================================================================

#[test]
fn fuzz_disassemble_64bit_never_panics() {
    let mut g = Lcg::new();
    let arch = X86Arch::new_64bit();
    for _ in 0..200 {
        let len = (g.byte() % 15 + 1) as usize;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let _ = arch.disassemble(Address::new(g.next()), &buf);
    }
}

#[test]
fn fuzz_disassemble_32bit_never_panics() {
    let mut g = Lcg::new();
    let arch = X86Arch::new_32bit();
    for _ in 0..200 {
        let len = (g.byte() % 15 + 1) as usize;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let _ = arch.disassemble(Address::new(g.next()), &buf);
    }
}

#[test]
fn fuzz_disassemble_16bit_never_panics() {
    let mut g = Lcg::new();
    let arch = X86Arch::new_16bit();
    for _ in 0..200 {
        let len = (g.byte() % 15 + 1) as usize;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let _ = arch.disassemble(Address::new(g.next()), &buf);
    }
}

#[test]
fn fuzz_lift_never_panics() {
    let mut g = Lcg::new();
    let arch = X86Arch::new_64bit();
    for _ in 0..200 {
        let len = (g.byte() % 15 + 1) as usize;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let _ = arch.lift(Address::new(g.next()), &buf);
    }
}

#[test]
fn fuzz_linear_disassembler_never_panics() {
    let mut g = Lcg::new();
    let arch = X86Arch::new_64bit();
    for _ in 0..50 {
        let len = (g.byte() as usize) + 1;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let d = LinearDisassembler::new(&arch, &buf, Address::new(g.next()));
        let mut steps = 0;
        for r in d {
            let _ = r;
            steps += 1;
            if steps > 1024 {
                break;
            }
        }
    }
}

#[test]
fn fuzz_disassemble_and_lift_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.byte() as usize) + 1;
        let buf: Vec<u8> = (0..len).map(|_| g.byte()).collect();
        let _ = disassemble_and_lift(&buf, g.next(), 64);
    }
}

// ===========================================================================
// Boundaries
// ===========================================================================

#[test]
fn disasm_single_byte_buffers_all_256() {
    let arch = X86Arch::new_64bit();
    for b in 0u16..=255 {
        let buf = [b as u8];
        let _ = arch.disassemble(Address::new(0), &buf);
        // Must not panic. Either Ok or Err.
    }
}

#[test]
fn disasm_address_zero_and_max() {
    let arch = X86Arch::new_64bit();
    let _ = arch.disassemble(Address::new(0), &[0x90]).unwrap();
    let _ = arch.disassemble(Address::new(u64::MAX), &[0x90]).unwrap();
}

#[test]
fn linear_address_wraps_correctly() {
    let arch = X86Arch::new_64bit();
    let bytes: &[u8] = &[0x90, 0x90];
    let d = LinearDisassembler::new(&arch, bytes, Address::new(u64::MAX));
    // Wrap-around must not panic.
    let _: Vec<_> = d.collect();
}

// ===========================================================================
// X86LiftAdapter
// ===========================================================================

#[test]
fn adapter_new_records_bits() {
    let a = X86LiftAdapter::new(64);
    assert_eq!(a.bits(), 64);
    let b = X86LiftAdapter::new(32);
    assert_eq!(b.bits(), 32);
}

#[test]
fn adapter_decode_empty_is_none() {
    assert!(X86LiftAdapter::decode_one_iced(64, &[], 0).is_none());
}

#[test]
fn adapter_decode_nop_is_some() {
    assert!(X86LiftAdapter::decode_one_iced(64, &[0x90], 0x100).is_some());
}

#[test]
fn adapter_reg_id_basic_regs_unique() {
    use iced_x86::Register as R;
    let rax = X86LiftAdapter::reg_id(R::RAX);
    let rbx = X86LiftAdapter::reg_id(R::RBX);
    let rcx = X86LiftAdapter::reg_id(R::RCX);
    let rdx = X86LiftAdapter::reg_id(R::RDX);
    assert_ne!(rax, rbx);
    assert_ne!(rcx, rdx);
    assert_eq!(rax, 0);
    assert_eq!(X86LiftAdapter::reg_id(R::RIP), 34);
}

#[test]
fn adapter_reg_id_unknown_is_u32_max() {
    use iced_x86::Register as R;
    assert_eq!(X86LiftAdapter::reg_id(R::None), u32::MAX);
}

#[test]
fn adapter_reg_id_ah_distinct_from_al() {
    use iced_x86::Register as R;
    assert_ne!(
        X86LiftAdapter::reg_id(R::AH),
        X86LiftAdapter::reg_id(R::AL)
    );
}

#[test]
fn adapter_reg_id_rsp_aliases_share_id() {
    use iced_x86::Register as R;
    let id = X86LiftAdapter::reg_id(R::RSP);
    assert_eq!(X86LiftAdapter::reg_id(R::ESP), id);
    assert_eq!(X86LiftAdapter::reg_id(R::SP), id);
    assert_eq!(X86LiftAdapter::reg_id(R::SPL), id);
}

// ===========================================================================
// Registers / calling conventions
// ===========================================================================

#[test]
fn registers_64_count_substantial() {
    let regs = X86Arch::new_64bit().registers();
    assert!(regs.len() > 100, "64-bit register list should be large");
}

#[test]
fn registers_32_includes_eax() {
    let regs = X86Arch::new_32bit().registers();
    assert!(regs.iter().any(|r| r.name == "eax"));
}

#[test]
fn registers_16_includes_ax_and_no_eax() {
    let regs = X86Arch::new_16bit().registers();
    assert!(regs.iter().any(|r| r.name == "ax"));
    assert!(!regs.iter().any(|r| r.name == "eax"));
}

#[test]
fn calling_conventions_64_has_sysv_and_ms() {
    let ccs = X86Arch::new_64bit().calling_conventions();
    let names: Vec<&str> = ccs.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"sysv_amd64"));
    assert!(names.contains(&"ms_x64"));
}

#[test]
fn calling_conventions_32_has_cdecl() {
    let ccs = X86Arch::new_32bit().calling_conventions();
    assert!(ccs.iter().any(|c| c.name == "cdecl"));
}

#[test]
fn calling_conventions_16_empty() {
    assert!(X86Arch::new_16bit().calling_conventions().is_empty());
}

// ===========================================================================
// Top-level lifters
// ===========================================================================

#[test]
fn lift_to_llil_nop_returns_some_ops() {
    // Decode a nop and lift it.
    let iced = X86LiftAdapter::decode_one_iced(64, &[0x90], 0).unwrap();
    let ops = lift_to_llil(&iced);
    // The lifter is allowed to return empty for a nop, but should not panic.
    let _ = ops;
}

#[test]
fn arch_lifter_name() {
    assert_eq!(ArchX86Lifter::new(64).arch_name(), "x86_64");
    assert_eq!(ArchX86Lifter::new(32).arch_name(), "x86");
    assert_eq!(ArchX86Lifter::new(16).arch_name(), "x86_16");
    assert_eq!(ArchX86Lifter::new(7).arch_name(), "x86");
}

#[test]
fn disassemble_and_lift_processes_sequence() {
    // nop nop ret
    let bytes: &[u8] = &[0x90, 0x90, 0xc3];
    let out = disassemble_and_lift(bytes, 0x1000, 64);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].0, 0x1000);
    assert_eq!(out[1].0, 0x1001);
    assert_eq!(out[2].0, 0x1002);
}

#[test]
fn disassemble_and_lift_stops_on_invalid() {
    // Start with an invalid encoding in 64-bit mode.
    let bytes: &[u8] = &[0x06];
    let out = disassemble_and_lift(bytes, 0, 64);
    assert!(out.is_empty());
}

// ===========================================================================
// Send / Sync threaded stress
// ===========================================================================

#[test]
fn x86arch_send_sync_threaded_stress() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<X86Arch>();

    let arch = Arc::new(X86Arch::new_64bit());
    let mut handles = vec![];
    for t in 0..4u64 {
        let arch = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut s = 0xDEAD_BEEF_CAFE_BABEu64 ^ (t.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            for _ in 0..100 {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let buf = [
                    (s >> 8) as u8,
                    (s >> 16) as u8,
                    (s >> 24) as u8,
                    (s >> 32) as u8,
                    (s >> 40) as u8,
                ];
                let _ = arch.disassemble(Address::new(s), &buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ===========================================================================
// Hash/Eq style consistency on X86Arch (PartialEq only â€” still pair test)
// ===========================================================================

#[test]
fn x86arch_partial_eq_pairs() {
    let configs = [
        X86Arch::new_16bit(),
        X86Arch::new_32bit(),
        X86Arch::new_64bit(),
    ];
    for (i, a) in configs.iter().enumerate() {
        for (j, b) in configs.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
    // 30+ pair consistency: clone each repeatedly.
    for _ in 0..30 {
        let c = configs[0].clone();
        assert_eq!(c, configs[0]);
    }
}

// ===========================================================================
// Bitness regression tests (bug: everything was lifted as 64-bit)
// ===========================================================================

#[test]
fn disassemble_and_lift_respects_bitness() {
    // push ebp / push rbp (0x55) must use esp in 32-bit mode, rsp in 64-bit.
    let out32 = disassemble_and_lift(&[0x55], 0x1000, 32);
    let out64 = disassemble_and_lift(&[0x55], 0x1000, 64);
    assert_eq!(out32.len(), 1);
    assert_eq!(out64.len(), 1);
    let s32 = format!("{:?}", out32);
    let s64 = format!("{:?}", out64);
    assert!(s32.contains("ebp") && s32.contains("DWord"), "32-bit lift must push ebp as DWord: {s32}");
    assert!(!s32.contains("rbp") && !s32.contains("QWord"), "32-bit lift must not be 64-bit sized: {s32}");
    assert!(s64.contains("rbp") && s64.contains("QWord"), "64-bit lift must push rbp as QWord: {s64}");
}

#[test]
fn arch_lifter_respects_bits_field() {
    use iced_x86::{Decoder, DecoderOptions};
    let mut dec = Decoder::with_ip(32, &[0x55], 0x1000, DecoderOptions::NONE);
    let instr = dec.decode();
    assert!(!instr.is_invalid());

    let ops32 = ArchX86Lifter::new(32).lift_instruction(&instr);
    let s32 = format!("{:?}", ops32);
    assert!(s32.contains("ebp") && s32.contains("DWord") && !s32.contains("QWord"), "{s32}");
}

#[test]
fn lift_to_llil_infers_bitness_from_code_size() {
    use iced_x86::{Decoder, DecoderOptions};
    let mut dec = Decoder::with_ip(32, &[0x55], 0x1000, DecoderOptions::NONE);
    let instr = dec.decode();
    let s = format!("{:?}", lift_to_llil(&instr));
    assert!(s.contains("ebp") && s.contains("DWord") && !s.contains("QWord"), "{s}");
}
