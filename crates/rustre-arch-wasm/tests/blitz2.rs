//! Deep adversarial tests for rustre-arch-wasm public surface.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_wasm::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn arch() -> WasmArch {
    WasmArch::new()
}

fn dis(bytes: &[u8]) -> rustre_core::arch::Instruction {
    arch().disassemble(Address::new(0x100), bytes).unwrap()
}

// LCG helper for fuzz tests
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ─── Round-trip tests ─────────────────────────────────────────────

#[test]
fn rt_value_type_byte() {
    for vt in [
        WasmValueType::I32,
        WasmValueType::I64,
        WasmValueType::F32,
        WasmValueType::F64,
        WasmValueType::V128,
        WasmValueType::FuncRef,
        WasmValueType::ExternRef,
    ] {
        let b = vt.byte();
        assert_eq!(WasmValueType::from_byte(b), Some(vt));
    }
}

#[test]
fn rt_section_id_byte() {
    for id in 0u8..=12 {
        let s = WasmSectionId::from_byte(id).unwrap();
        assert_eq!(s as u8, id);
    }
}

#[test]
fn rt_external_kind() {
    for k in 0u8..=3 {
        let e = WasmExternalKind::from_byte(k).unwrap();
        assert_eq!(e as u8, k);
    }
}

#[test]
fn rt_mutability() {
    for k in 0u8..=1 {
        let m = WasmMutability::from_byte(k).unwrap();
        assert_eq!(m as u8, k);
    }
}

// ─── Boundaries ────────────────────────────────────────────────────

#[test]
fn value_type_invalid_bytes() {
    for b in 0u8..=255u8 {
        let ok = matches!(b, 0x6F | 0x70 | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F);
        assert_eq!(WasmValueType::from_byte(b).is_some(), ok, "byte 0x{b:02x}");
    }
}

#[test]
fn section_id_invalid_bytes() {
    for b in 13u8..=255u8 {
        assert!(WasmSectionId::from_byte(b).is_none());
    }
}

#[test]
fn external_kind_invalid_bytes() {
    for b in 4u8..=255u8 {
        assert!(WasmExternalKind::from_byte(b).is_none());
    }
}

#[test]
fn mutability_invalid_bytes() {
    for b in 2u8..=255u8 {
        assert!(WasmMutability::from_byte(b).is_none());
    }
}

// ─── Header parsing ────────────────────────────────────────────────

#[test]
fn header_valid_8_bytes() {
    let bytes = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let h = WasmModuleHeader::parse(&bytes).unwrap();
    assert_eq!(h.magic, WASM_MAGIC);
    assert_eq!(h.version, WASM_VERSION);
}

#[test]
fn header_truncated_returns_err() {
    for n in 0..8 {
        let buf = vec![0u8; n];
        assert!(WasmModuleHeader::parse(&buf).is_err());
    }
}

#[test]
fn header_bad_magic_each_byte() {
    for i in 0..4 {
        let mut bytes: [u8; 8] = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        bytes[i] = bytes[i].wrapping_add(1);
        assert!(WasmModuleHeader::parse(&bytes).is_err());
    }
}

#[test]
fn header_bad_version_returns_err() {
    let bytes = [0x00, 0x61, 0x73, 0x6D, 0x99, 0x00, 0x00, 0x00];
    assert!(WasmModuleHeader::parse(&bytes).is_err());
}

#[test]
fn header_extra_bytes_ok() {
    let bytes = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB];
    assert!(WasmModuleHeader::parse(&bytes).is_ok());
}

// ─── Limits ────────────────────────────────────────────────────────

#[test]
fn limits_empty_err() {
    assert!(WasmLimits::decode(&[]).is_err());
}

#[test]
fn limits_min_only_many_values() {
    for v in [0u64, 1, 127, 128, 16383, 16384] {
        let mut buf = vec![0u8];
        // write uleb128
        let mut x = v;
        loop {
            let mut b = (x & 0x7f) as u8;
            x >>= 7;
            if x != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if x == 0 {
                break;
            }
        }
        let (lim, _) = WasmLimits::decode(&buf).unwrap();
        assert_eq!(lim.min, v);
        assert!(lim.max.is_none());
    }
}

#[test]
fn limits_min_max() {
    let bytes = [0x01, 0x05, 0x10];
    let (lim, n) = WasmLimits::decode(&bytes).unwrap();
    assert_eq!(lim.min, 5);
    assert_eq!(lim.max, Some(16));
    assert_eq!(n, 3);
}

#[test]
fn limits_unknown_kind() {
    let bytes = [0x05, 0x01];
    assert!(WasmLimits::decode(&bytes).is_err());
}

#[test]
fn limits_truncated_min() {
    let bytes = [0x00, 0x80]; // continuation but no more bytes
    assert!(WasmLimits::decode(&bytes).is_err());
}

#[test]
fn limits_truncated_max() {
    let bytes = [0x01, 0x02]; // kind=1 but no max
    assert!(WasmLimits::decode(&bytes).is_err());
}

// ─── Function type ──────────────────────────────────────────────────

#[test]
fn functype_basic() {
    let bytes = [0x60, 0x02, 0x7f, 0x7e, 0x01, 0x7d];
    let ft = WasmFuncType::decode(&bytes).unwrap();
    assert_eq!(ft.params, vec![WasmValueType::I32, WasmValueType::I64]);
    assert_eq!(ft.results, vec![WasmValueType::F32]);
    assert_eq!(ft.arity(), (2, 1));
}

#[test]
fn functype_no_marker() {
    let bytes = [0x61, 0x00, 0x00];
    assert!(WasmFuncType::decode(&bytes).is_err());
}

#[test]
fn functype_empty() {
    assert!(WasmFuncType::decode(&[]).is_err());
}

#[test]
fn functype_zero_args() {
    let bytes = [0x60, 0x00, 0x00];
    let ft = WasmFuncType::decode(&bytes).unwrap();
    assert_eq!(ft.arity(), (0, 0));
}

#[test]
fn functype_truncated_param() {
    let bytes = [0x60, 0x02, 0x7f];
    assert!(WasmFuncType::decode(&bytes).is_err());
}

#[test]
fn functype_unknown_valtype() {
    let bytes = [0x60, 0x01, 0x55, 0x00];
    assert!(WasmFuncType::decode(&bytes).is_err());
}

// ─── Global / table / memory types ─────────────────────────────────

#[test]
fn global_type_decode_ok() {
    let bytes = [0x7F, 0x01];
    let (g, n) = WasmGlobalType::decode(&bytes).unwrap();
    assert_eq!(g.content_type, WasmValueType::I32);
    assert_eq!(g.mutability, WasmMutability::Mutable);
    assert_eq!(n, 2);
}

#[test]
fn global_type_truncated() {
    assert!(WasmGlobalType::decode(&[0x7F]).is_err());
    assert!(WasmGlobalType::decode(&[]).is_err());
}

#[test]
fn global_type_bad_mut() {
    assert!(WasmGlobalType::decode(&[0x7F, 0x05]).is_err());
}

#[test]
fn table_type_decode() {
    let bytes = [0x70, 0x00, 0x01];
    let (t, n) = WasmTableType::decode(&bytes).unwrap();
    assert_eq!(t.element_type, WasmValueType::FuncRef);
    assert_eq!(t.limits.min, 1);
    assert_eq!(n, 3);
}

#[test]
fn table_type_empty_err() {
    assert!(WasmTableType::decode(&[]).is_err());
}

#[test]
fn memory_type_decode() {
    let bytes = [0x01, 0x01, 0x02];
    let (m, n) = WasmMemoryType::decode(&bytes).unwrap();
    assert_eq!(m.limits.min, 1);
    assert_eq!(m.limits.max, Some(2));
    assert_eq!(n, 3);
}

// ─── Disassembler ──────────────────────────────────────────────────

#[test]
fn disasm_arch_basics() {
    let a = arch();
    assert_eq!(a.name(), "wasm");
    assert_eq!(a.pointer_size(), 4);
    assert_eq!(a.endian(), Endian::Little);
    assert!(a.registers().is_empty());
}

#[test]
fn disasm_empty_err() {
    assert!(arch().disassemble(Address::new(0), &[]).is_err());
}

#[test]
fn disasm_all_simple_arith_opcodes() {
    // Opcodes that take no operands and should succeed.
    for op in [
        0x00u8, 0x01, 0x0b, 0x0f, 0x1a, 0x1b, 0x45, 0x46, 0x6a, 0x6b, 0x6c, 0x7c, 0x92, 0xa0, 0xa7,
        0xac, 0xc0, 0xc4,
    ] {
        let i = arch().disassemble(Address::new(0), &[op]).unwrap();
        assert_eq!(i.size, 1, "opcode 0x{op:02x}");
    }
}

#[test]
fn disasm_truncated_call_err() {
    // 0x10 needs uleb operand
    assert!(arch().disassemble(Address::new(0), &[0x10]).is_err());
}

#[test]
fn disasm_truncated_f32_const() {
    assert!(arch()
        .disassemble(Address::new(0), &[0x43, 0x00, 0x00])
        .is_err());
}

#[test]
fn disasm_truncated_f64_const() {
    let buf = vec![0x44u8; 5]; // op + 4 bytes (need 8)
    assert!(arch().disassemble(Address::new(0), &buf).is_err());
}

#[test]
fn disasm_unknown_opcode() {
    for op in [0xFFu8, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF] {
        let r = arch().disassemble(Address::new(0), &[op]);
        assert!(r.is_err(), "expected err for 0x{op:02x}");
    }
}

#[test]
fn disasm_br_table_minimal() {
    // br_table 0 default
    let i = dis(&[0x0e, 0x00, 0x05]);
    assert_eq!(i.mnemonic, "br_table");
    assert_eq!(i.size, 3);
}

#[test]
fn disasm_br_table_truncated() {
    assert!(arch().disassemble(Address::new(0), &[0x0e, 0x02]).is_err());
}

#[test]
fn disasm_ref_null_truncated() {
    assert!(arch().disassemble(Address::new(0), &[0xD0]).is_err());
}

#[test]
fn disasm_branches_flags() {
    let br = dis(&[0x0c, 0x00]);
    let bs = arch().get_branches(&br);
    assert_eq!(bs.len(), 1);
    let ret = dis(&[0x0f]);
    assert!(arch().get_branches(&ret).is_empty());
    let cond = dis(&[0x0d, 0x01]);
    assert_eq!(arch().get_branches(&cond).len(), 1);
    let tbl = dis(&[0x0e, 0x00, 0x00]);
    assert_eq!(arch().get_branches(&tbl).len(), 1);
}

// ─── Memory load/store ops sweep ──────────────────────────────────

#[test]
fn disasm_all_loads_have_read_mem_flag() {
    for op in 0x28u8..=0x35u8 {
        let i = dis(&[op, 0x02, 0x00]);
        assert!(
            i.flags.contains(InstrFlags::READ_MEM),
            "op 0x{op:02x} mnemonic={}",
            i.mnemonic
        );
    }
}

#[test]
fn disasm_all_stores_have_write_mem_flag() {
    for op in 0x36u8..=0x3Eu8 {
        let i = dis(&[op, 0x02, 0x00]);
        assert!(
            i.flags.contains(InstrFlags::WRITE_MEM),
            "op 0x{op:02x} mnemonic={}",
            i.mnemonic
        );
    }
}

#[test]
fn disasm_load_truncated() {
    for op in 0x28u8..=0x35u8 {
        assert!(arch().disassemble(Address::new(0), &[op]).is_err());
        assert!(arch().disassemble(Address::new(0), &[op, 0x02]).is_err());
    }
}

// ─── 0xFC prefix ──────────────────────────────────────────────────

#[test]
fn fc_trunc_sat_variants() {
    for sub in 0u8..=7 {
        let i = dis(&[0xFC, sub]);
        assert!(i.mnemonic.contains("trunc_sat"));
    }
}

#[test]
fn fc_memory_copy() {
    let i = dis(&[0xFC, 0x0A, 0x00, 0x00]);
    assert_eq!(i.mnemonic, "memory.copy");
}

#[test]
fn fc_truncated() {
    assert!(decode_fc_prefix(&[0xFC]).is_err());
}

// ─── Hash/Eq consistency ──────────────────────────────────────────

#[test]
fn hash_eq_value_type() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    for vt in [
        WasmValueType::I32,
        WasmValueType::I64,
        WasmValueType::F32,
        WasmValueType::F64,
        WasmValueType::V128,
        WasmValueType::FuncRef,
        WasmValueType::ExternRef,
    ] {
        assert!(s.insert(vt));
    }
    assert_eq!(s.len(), 7);
    for vt in [WasmValueType::I32, WasmValueType::FuncRef] {
        assert!(s.contains(&vt));
    }
}

#[test]
fn hash_eq_section_external() {
    use std::collections::HashSet;
    let mut s: HashSet<WasmSectionId> = HashSet::new();
    for id in 0u8..=12 {
        s.insert(WasmSectionId::from_byte(id).unwrap());
    }
    assert_eq!(s.len(), 13);
    let mut e: HashSet<WasmExternalKind> = HashSet::new();
    for k in 0u8..=3 {
        e.insert(WasmExternalKind::from_byte(k).unwrap());
    }
    assert_eq!(e.len(), 4);
}

#[test]
fn eq_limits_funtype_struct() {
    let a = WasmLimits {
        min: 1,
        max: Some(2),
    };
    let b = WasmLimits {
        min: 1,
        max: Some(2),
    };
    let c = WasmLimits { min: 1, max: None };
    assert_eq!(a, b);
    assert_ne!(a, c);
    let ft1 = WasmFuncType {
        params: vec![WasmValueType::I32],
        results: vec![],
    };
    let ft2 = ft1.clone();
    assert_eq!(ft1, ft2);
}

// ─── Value type predicates ────────────────────────────────────────

#[test]
fn value_type_predicates() {
    assert!(WasmValueType::I32.is_numeric());
    assert!(WasmValueType::I64.is_numeric());
    assert!(WasmValueType::F32.is_numeric());
    assert!(WasmValueType::F64.is_numeric());
    assert!(!WasmValueType::V128.is_numeric());
    assert!(!WasmValueType::FuncRef.is_numeric());
    assert!(WasmValueType::FuncRef.is_reference());
    assert!(WasmValueType::ExternRef.is_reference());
    assert!(!WasmValueType::I32.is_reference());
}

#[test]
fn section_id_name_unique() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    for id in 0u8..=12 {
        s.insert(WasmSectionId::from_byte(id).unwrap().name());
    }
    assert_eq!(s.len(), 13);
}

// ─── Send/Sync threaded stress on WasmArch ────────────────────────

#[test]
fn arch_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WasmArch>();

    use std::sync::Arc;
    use std::thread;
    let a = Arc::new(WasmArch::new());
    let mut handles = vec![];
    for t in 0..4u8 {
        let aa = Arc::clone(&a);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let op = (t.wrapping_add(i as u8) & 0x7) | 0x6a; // arith ops 0x6a..0x71 range
                let opcode = match op {
                    o if o >= 0x6a && o <= 0x78 => o,
                    _ => 0x6a,
                };
                let _ = aa.disassemble(Address::new(0), &[opcode]);
                let _ = aa.disassemble(Address::new(0), &[0x6a]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── LCG fuzz on disassembler — must never panic ──────────────────

#[test]
fn fuzz_disasm_never_panics() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() as usize) % 16) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = arch().disassemble(Address::new(0), &buf);
    }
}

#[test]
fn fuzz_limits_never_panics() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() as usize) % 8) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = WasmLimits::decode(&buf);
    }
}

#[test]
fn fuzz_functype_never_panics() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() as usize) % 12) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = WasmFuncType::decode(&buf);
    }
}

#[test]
fn fuzz_header_never_panics() {
    let mut g = lcg();
    for _ in 0..500 {
        let len = ((g() as usize) % 12) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = WasmModuleHeader::parse(&buf);
    }
}

#[test]
fn fuzz_global_type_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = ((g() as usize) % 5) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = WasmGlobalType::decode(&buf);
    }
}

#[test]
fn fuzz_table_type_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = ((g() as usize) % 6) + 1;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((g() & 0xff) as u8);
        }
        let _ = WasmTableType::decode(&buf);
    }
}

// ─── Constants ─────────────────────────────────────────────────────

#[test]
fn const_magic_and_version() {
    assert_eq!(WASM_MAGIC, [0x00, 0x61, 0x73, 0x6D]);
    assert_eq!(WASM_VERSION, [0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn calling_convention_present() {
    let cc = arch().calling_conventions();
    assert!(!cc.is_empty());
    assert_eq!(cc[0].name, "wasm");
}

// ─── i32.const SLEB sign extension ────────────────────────────────

#[test]
fn i32_const_negative() {
    // -1 in sleb128 is 0x7f
    let i = dis(&[0x41, 0x7f]);
    assert_eq!(i.mnemonic, "i32.const");
    assert_eq!(i.operands, "-1");
}

#[test]
fn i32_const_positive_multibyte() {
    // 624485 sleb128 = 0xE5 0x8E 0x26
    let i = dis(&[0x41, 0xE5, 0x8E, 0x26]);
    assert_eq!(i.mnemonic, "i32.const");
    assert_eq!(i.operands, "624485");
}

// ─── Mutability matrix ────────────────────────────────────────────

#[test]
fn mutability_distinct() {
    assert_ne!(WasmMutability::Const, WasmMutability::Mutable);
}

// ─── Atomic / SIMD coverage smoke ─────────────────────────────────

#[test]
fn atomic_i32_load() {
    let i = dis(&[0xFE, 0x10, 0x02, 0x00]);
    assert_eq!(i.mnemonic, "i32.atomic.load");
    assert!(i.flags.contains(InstrFlags::READ_MEM));
}

#[test]
fn simd_v128_const_decodes() {
    let mut buf = vec![0xFDu8, 0x0C];
    buf.extend_from_slice(&[0u8; 16]);
    let i = dis(&buf);
    assert_eq!(i.mnemonic, "v128.const");
    assert_eq!(i.size, 18);
}

#[test]
fn external_kind_names_distinct() {
    let names: Vec<&str> = (0..=3)
        .map(|k| WasmExternalKind::from_byte(k).unwrap().name())
        .collect();
    let set: std::collections::HashSet<_> = names.iter().copied().collect();
    assert_eq!(set.len(), 4);
}
