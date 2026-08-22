//! Exhaustive blitz tests for rustre-loader-wasm.

use rustre_loader_wasm::*;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn unsigned_leb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn signed_leb128(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut more = true;
    while more {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
            more = false;
            out.push(byte);
        } else {
            out.push(byte | 0x80);
        }
    }
    out
}

fn minimal_header() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
}

/// Build a Wasm module with: one type `() -> ()`, one function, one code body `end`,
/// and an export of that function as `f`.
fn build_simple_module() -> Vec<u8> {
    let mut bin = minimal_header();

    // Type section: 1 type, () -> ()
    let mut sec = Vec::new();
    sec.extend(unsigned_leb128(1)); // count
    sec.push(0x60);
    sec.extend(unsigned_leb128(0)); // params
    sec.extend(unsigned_leb128(0)); // results
    bin.push(1);
    bin.extend(unsigned_leb128(sec.len() as u64));
    bin.extend(sec);

    // Function section: 1 function, type 0
    let mut sec = Vec::new();
    sec.extend(unsigned_leb128(1));
    sec.extend(unsigned_leb128(0));
    bin.push(3);
    bin.extend(unsigned_leb128(sec.len() as u64));
    bin.extend(sec);

    // Export section: export function 0 as "f"
    let mut sec = Vec::new();
    sec.extend(unsigned_leb128(1));
    let name = b"f";
    sec.extend(unsigned_leb128(name.len() as u64));
    sec.extend(name);
    sec.push(0x00); // function
    sec.extend(unsigned_leb128(0));
    bin.push(7);
    bin.extend(unsigned_leb128(sec.len() as u64));
    bin.extend(sec);

    // Code section: 1 body: locals=0, body=[end]
    let mut body = Vec::new();
    body.extend(unsigned_leb128(0)); // local decl count
    body.push(0x0B); // end
    let mut sec = Vec::new();
    sec.extend(unsigned_leb128(1)); // count
    sec.extend(unsigned_leb128(body.len() as u64));
    sec.extend(body);
    bin.push(10);
    bin.extend(unsigned_leb128(sec.len() as u64));
    bin.extend(sec);

    bin
}

// ─── LEB128 decoder ──────────────────────────────────────────────────────────

#[test]
fn leb128_u32_basic() {
    let mut d = Leb128Decoder::new(&[0x00]);
    assert_eq!(d.read_u32().unwrap(), 0);
    assert!(d.is_done());
}

#[test]
fn leb128_u32_127() {
    let mut d = Leb128Decoder::new(&[0x7F]);
    assert_eq!(d.read_u32().unwrap(), 127);
}

#[test]
fn leb128_u32_128() {
    let mut d = Leb128Decoder::new(&[0x80, 0x01]);
    assert_eq!(d.read_u32().unwrap(), 128);
}

#[test]
fn leb128_u32_max() {
    let bytes = unsigned_leb128(u64::from(u32::MAX));
    let mut d = Leb128Decoder::new(&bytes);
    assert_eq!(d.read_u32().unwrap(), u32::MAX);
}

#[test]
fn leb128_u32_overflow() {
    // 6 bytes all with continuation set → overflow
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    let mut d = Leb128Decoder::new(&bytes);
    assert!(d.read_u32().is_err());
}

#[test]
fn leb128_u32_eof() {
    let bytes = [0x80]; // continuation but no more bytes
    let mut d = Leb128Decoder::new(&bytes);
    assert!(matches!(
        d.read_u32().unwrap_err(),
        WasmError::UnexpectedEof(_)
    ));
}

#[test]
fn leb128_i32_negative_one() {
    let mut d = Leb128Decoder::new(&[0x7F]);
    assert_eq!(d.read_i32().unwrap(), -1);
}

#[test]
fn leb128_i32_min() {
    let bytes = signed_leb128(i64::from(i32::MIN));
    let mut d = Leb128Decoder::new(&bytes);
    assert_eq!(d.read_i32().unwrap(), i32::MIN);
}

#[test]
fn leb128_i32_max() {
    let bytes = signed_leb128(i64::from(i32::MAX));
    let mut d = Leb128Decoder::new(&bytes);
    assert_eq!(d.read_i32().unwrap(), i32::MAX);
}

#[test]
fn leb128_i64_negative() {
    let bytes = signed_leb128(-12345);
    let mut d = Leb128Decoder::new(&bytes);
    assert_eq!(d.read_i64().unwrap(), -12345);
}

#[test]
fn leb128_u64_max() {
    let bytes = unsigned_leb128(u64::MAX);
    let mut d = Leb128Decoder::new(&bytes);
    assert_eq!(d.read_u64().unwrap(), u64::MAX);
}

#[test]
fn leb128_remaining_offset() {
    let d = Leb128Decoder::new(&[1, 2, 3]);
    assert_eq!(d.remaining(), 3);
    assert_eq!(d.offset(), 0);
    assert!(!d.is_done());
}

#[test]
fn leb128_read_bytes_too_many() {
    let mut d = Leb128Decoder::new(&[1, 2]);
    assert!(d.read_bytes(5).is_err());
}

#[test]
fn leb128_read_name_invalid_utf8() {
    let mut data = Vec::new();
    data.push(0x02);
    data.push(0xFF);
    data.push(0xFE);
    let mut d = Leb128Decoder::new(&data);
    assert!(matches!(d.read_name().unwrap_err(), WasmError::InvalidUtf8));
}

#[test]
fn leb128_read_name_ok() {
    let mut data = Vec::new();
    data.push(0x05);
    data.extend(b"hello");
    let mut d = Leb128Decoder::new(&data);
    assert_eq!(d.read_name().unwrap(), "hello");
}

// ─── WasmValType ─────────────────────────────────────────────────────────────

#[test]
fn valtype_from_byte_all_known() {
    for (b, name) in [
        (0x7F, "i32"),
        (0x7E, "i64"),
        (0x7D, "f32"),
        (0x7C, "f64"),
        (0x7B, "v128"),
        (0x70, "funcref"),
        (0x6F, "externref"),
    ] {
        let t = WasmValType::from_byte(b).unwrap();
        assert_eq!(t.name(), name);
        assert_eq!(format!("{t}"), name);
    }
}

#[test]
fn valtype_from_byte_unknown() {
    assert!(WasmValType::from_byte(0x00).is_none());
    assert!(WasmValType::from_byte(0xFF).is_none());
}

#[test]
fn valtype_byte_sizes() {
    assert_eq!(WasmValType::I32.byte_size(), 4);
    assert_eq!(WasmValType::F32.byte_size(), 4);
    assert_eq!(WasmValType::I64.byte_size(), 8);
    assert_eq!(WasmValType::F64.byte_size(), 8);
    assert_eq!(WasmValType::V128.byte_size(), 16);
    assert_eq!(WasmValType::FuncRef.byte_size(), 0);
    assert_eq!(WasmValType::ExternRef.byte_size(), 0);
}

// ─── WasmFuncType Display ────────────────────────────────────────────────────

#[test]
fn functype_display_no_results() {
    let t = WasmFuncType {
        params: vec![WasmValType::I32, WasmValType::F64],
        results: vec![],
    };
    assert_eq!(format!("{t}"), "(i32, f64) -> ()");
}

#[test]
fn functype_display_single_result() {
    let t = WasmFuncType {
        params: vec![],
        results: vec![WasmValType::I32],
    };
    assert_eq!(format!("{t}"), "() -> i32");
}

#[test]
fn functype_display_multi_results() {
    let t = WasmFuncType {
        params: vec![WasmValType::I32],
        results: vec![WasmValType::I32, WasmValType::I64],
    };
    assert_eq!(format!("{t}"), "(i32) -> (i32, i64)");
}

// ─── WasmParser: header validation ───────────────────────────────────────────

#[test]
fn parser_rejects_short() {
    let e = WasmParser::parse(&[]).err().unwrap();
    assert!(matches!(e, WasmError::InvalidMagic));
    let e = WasmParser::parse(&[0x00, 0x61, 0x73]).err().unwrap();
    assert!(matches!(e, WasmError::InvalidMagic));
}

#[test]
fn parser_rejects_bad_magic() {
    let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00];
    let e = WasmParser::parse(&bytes).err().unwrap();
    assert!(matches!(e, WasmError::InvalidMagic));
}

#[test]
fn parser_rejects_bad_version() {
    let bytes = [0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00];
    let e = WasmParser::parse(&bytes).err().unwrap();
    assert!(matches!(e, WasmError::UnsupportedVersion(2)));
}

#[test]
fn parser_accepts_minimal_header_only() {
    let m = WasmParser::parse(&minimal_header()).unwrap();
    assert_eq!(m.version, 1);
    assert_eq!(m.types.len(), 0);
    assert_eq!(m.functions.len(), 0);
    assert_eq!(m.total_function_count, 0);
}

#[test]
fn parser_rejects_oversized_section() {
    // Header + section id 0 + huge length
    let mut bin = minimal_header();
    bin.push(0); // custom section
    // LEB128 encoding of (MAX_SECTION_SIZE + 1) = 256*1024*1024 + 1
    let big = (256u64 * 1024 * 1024) + 1;
    bin.extend(unsigned_leb128(big));
    let err = WasmParser::parse(&bin).err().unwrap();
    assert!(matches!(err, WasmError::SectionTooLarge(_)));
}

#[test]
fn parser_rejects_truncated_section() {
    let mut bin = minimal_header();
    bin.push(1); // type section
    bin.extend(unsigned_leb128(100)); // claims 100 bytes
    bin.push(0x01); // only 1 actual byte
    let e = WasmParser::parse(&bin).err().unwrap();
    assert!(matches!(e, WasmError::UnexpectedEof(_)));
}

// ─── WasmParser: full simple module ──────────────────────────────────────────

#[test]
fn parser_full_simple_module() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    assert_eq!(m.types.len(), 1);
    assert_eq!(m.functions.len(), 1);
    assert_eq!(m.exports.len(), 1);
    assert_eq!(m.exports[0].name, "f");
    assert!(matches!(m.exports[0].desc, WasmExportDesc::Function(0)));
    assert_eq!(m.total_function_count, 1);
    assert_eq!(m.defined_function_count, 1);
    assert_eq!(m.import_function_count, 0);
}

#[test]
fn parser_function_name_from_export() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    assert_eq!(m.functions[0].name.as_deref(), Some("f"));
}

#[test]
fn parser_unknown_section_id_skipped() {
    let mut bin = build_simple_module();
    // Append a fictional section id 99 with 3 bytes of body
    bin.push(99);
    bin.extend(unsigned_leb128(3));
    bin.extend([1, 2, 3]);
    let m = WasmParser::parse(&bin).unwrap();
    assert_eq!(m.functions.len(), 1);
}

// ─── WasmModule helpers ──────────────────────────────────────────────────────

#[test]
fn module_exported_function_lookup() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    let f = m.exported_function("f").unwrap();
    assert_eq!(f.index, 0);
    assert!(m.exported_function("missing").is_none());
}

#[test]
fn module_exported_function_names() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    assert_eq!(m.exported_function_names(), vec!["f"]);
}

#[test]
fn module_function_name_via_export() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    assert_eq!(m.function_name(0), Some("f"));
    assert_eq!(m.function_name(99), None);
}

#[test]
fn module_function_type_lookup() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    let ft = m.function_type(0).unwrap();
    assert!(ft.params.is_empty());
    assert!(ft.results.is_empty());
    assert!(m.function_type(50).is_none());
}

#[test]
fn module_memory_and_start() {
    let m = WasmParser::parse(&minimal_header()).unwrap();
    assert_eq!(m.memory_pages_min(), 0);
    assert!(!m.has_start_function());
}

#[test]
fn module_imports_from_empty() {
    let m = WasmParser::parse(&minimal_header()).unwrap();
    assert!(m.imports_from("env").is_empty());
}

// ─── WasmStats ────────────────────────────────────────────────────────────────

#[test]
fn stats_simple_module() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    let s = WasmStats::compute(&m);
    assert_eq!(s.function_count, 1);
    assert_eq!(s.import_count, 0);
    assert_eq!(s.export_count, 1);
    assert_eq!(s.global_count, 0);
    assert_eq!(s.memory_count, 0);
    assert_eq!(s.table_count, 0);
    assert!(!s.has_name_section);
    assert!(!s.has_dwarf);
    assert_eq!(s.most_complex_function, Some(0));
    // Code size = body bytes after locals decl = just the `end` byte
    assert_eq!(s.code_size, 1);
}

// ─── WasmCustomSection helpers ────────────────────────────────────────────────

#[test]
fn customsection_is_name() {
    let cs = WasmCustomSection {
        name: "name".to_string(),
        data: vec![],
    };
    assert!(cs.is_name());
    assert!(!cs.is_dwarf());
}

#[test]
fn customsection_is_dwarf() {
    let cs = WasmCustomSection {
        name: ".debug_info".to_string(),
        data: vec![],
    };
    assert!(cs.is_dwarf());
    assert!(!cs.is_name());
}

// ─── WasmNameSection ─────────────────────────────────────────────────────────

#[test]
fn name_section_module_subsection() {
    // subsection 0: module name "mymod"
    let inner = {
        let mut v = unsigned_leb128(5);
        v.extend(b"mymod");
        v
    };
    let mut data = Vec::new();
    data.push(0x00);
    data.extend(unsigned_leb128(inner.len() as u64));
    data.extend(inner);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert_eq!(ns.module_name.as_deref(), Some("mymod"));
}

#[test]
fn name_section_function_names() {
    // subsection 1: 1 entry, idx=3, name="foo"
    let inner = {
        let mut v = unsigned_leb128(1); // count
        v.extend(unsigned_leb128(3)); // idx
        v.extend(unsigned_leb128(3)); // name len
        v.extend(b"foo");
        v
    };
    let mut data = Vec::new();
    data.push(0x01);
    data.extend(unsigned_leb128(inner.len() as u64));
    data.extend(inner);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert_eq!(ns.function_names.get(&3).map(String::as_str), Some("foo"));
}

#[test]
fn name_section_unknown_subsection_skipped() {
    let mut data = Vec::new();
    data.push(0x42); // unknown
    data.extend(unsigned_leb128(3));
    data.extend([1, 2, 3]);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert!(ns.module_name.is_none());
    assert!(ns.function_names.is_empty());
}

// ─── WasmOpcode ──────────────────────────────────────────────────────────────

#[test]
fn opcode_mnemonics() {
    assert_eq!(WasmOpcode(0x00).mnemonic(), "unreachable");
    assert_eq!(WasmOpcode(0x10).mnemonic(), "call");
    assert_eq!(WasmOpcode(0x41).mnemonic(), "i32.const");
    assert_eq!(WasmOpcode(0xEE).mnemonic(), "<unknown>");
    assert_eq!(format!("{}", WasmOpcode(0x01)), "nop");
}

#[test]
fn opcode_classifications() {
    assert!(WasmOpcode(0x00).is_unreachable());
    assert!(WasmOpcode(0x00).is_control_flow());
    assert!(!WasmOpcode(0x6A).is_control_flow());
    assert!(WasmOpcode(0x10).is_call());
    assert!(WasmOpcode(0x11).is_call());
    assert!(!WasmOpcode(0x01).is_call());
    assert!(WasmOpcode(0x28).is_memory_access());
    assert!(WasmOpcode(0x3E).is_memory_access());
    assert!(!WasmOpcode(0x27).is_memory_access());
    assert!(!WasmOpcode(0x3F).is_memory_access());
    assert!(WasmOpcode(0x45).is_numeric());
    assert!(WasmOpcode(0xC4).is_numeric());
    assert!(!WasmOpcode(0x44).is_numeric());
}

#[test]
fn opcode_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(WasmOpcode(0x10));
    assert!(s.contains(&WasmOpcode(0x10)));
    assert!(!s.contains(&WasmOpcode(0x11)));
}

// ─── WasmDisassembler ────────────────────────────────────────────────────────

#[test]
fn disasm_just_end() {
    let mut d = WasmDisassembler::new(&[0x0B]);
    let instrs = d.disassemble_all().unwrap();
    assert_eq!(instrs.len(), 1);
    assert_eq!(instrs[0].opcode.0, 0x0B);
    assert_eq!(instrs[0].size, 1);
}

#[test]
fn disasm_i32_const() {
    // i32.const 42, end
    let body = [0x41, 42, 0x0B];
    let mut d = WasmDisassembler::new(&body);
    let instrs = d.disassemble_all().unwrap();
    assert_eq!(instrs.len(), 2);
    assert!(matches!(instrs[0].immediate, WasmImmediate::I32(42)));
}

#[test]
fn disasm_call() {
    let body = [0x10, 0x05, 0x0B];
    let mut d = WasmDisassembler::new(&body);
    let instrs = d.disassemble_all().unwrap();
    assert!(matches!(instrs[0].immediate, WasmImmediate::U32(5)));
}

#[test]
fn disasm_br_table() {
    // br_table [1,2] default=3, end
    let body = [0x0E, 0x02, 0x01, 0x02, 0x03, 0x0B];
    let mut d = WasmDisassembler::new(&body);
    let instrs = d.disassemble_all().unwrap();
    match &instrs[0].immediate {
        WasmImmediate::BrTable { labels, default } => {
            assert_eq!(labels, &vec![1u32, 2]);
            assert_eq!(*default, 3);
        }
        _ => panic!("expected BrTable"),
    }
}

#[test]
fn disasm_memarg() {
    // i32.load align=2 offset=0, end
    let body = [0x28, 0x02, 0x00, 0x0B];
    let mut d = WasmDisassembler::new(&body);
    let instrs = d.disassemble_all().unwrap();
    assert!(matches!(
        instrs[0].immediate,
        WasmImmediate::MemArg {
            align: 2,
            offset: 0
        }
    ));
}

#[test]
fn disasm_instruction_terminator() {
    let instr = WasmInstruction {
        offset: 0,
        opcode: WasmOpcode(0x0F),
        immediate: WasmImmediate::None,
        size: 1,
    };
    assert!(instr.is_terminator());
    assert_eq!(instr.mnemonic(), "return");
}

#[test]
fn disasm_empty_body_disassembles_nothing() {
    let mut d = WasmDisassembler::new(&[]);
    let instrs = d.disassemble_all().unwrap();
    assert!(instrs.is_empty());
}

#[test]
fn disasm_truncated_errors() {
    // i32.const followed by truncated LEB128
    let body = [0x41, 0x80];
    let mut d = WasmDisassembler::new(&body);
    assert!(d.disassemble_all().is_err());
}

// ─── WasmValidator ───────────────────────────────────────────────────────────

#[test]
fn validator_simple_ok() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    assert!(WasmValidator::is_valid(&m));
    assert!(WasmValidator::validate(&m).is_empty());
}

#[test]
fn validator_empty_module_ok() {
    let m = WasmParser::parse(&minimal_header()).unwrap();
    assert!(WasmValidator::is_valid(&m));
}

// ─── WasmCallGraph ───────────────────────────────────────────────────────────

#[test]
fn callgraph_empty() {
    let m = WasmParser::parse(&minimal_header()).unwrap();
    let cg = WasmCallGraph::build(&m);
    assert_eq!(cg.edge_count(), 0);
    assert!(cg.callees_of(0).is_empty());
    assert!(cg.callers_of(0).is_empty());
    assert!(cg.root_functions(&m).is_empty());
}

#[test]
fn callgraph_simple_module_no_calls() {
    let bin = build_simple_module();
    let m = WasmParser::parse(&bin).unwrap();
    let cg = WasmCallGraph::build(&m);
    assert_eq!(cg.edge_count(), 0);
    // The defined function has no callers — it's a root.
    assert_eq!(cg.root_functions(&m), vec![0]);
}

// ─── ResolvedImport ──────────────────────────────────────────────────────────

#[test]
fn resolved_import_predicates() {
    let r = ResolvedImport {
        module: "env".into(),
        field: "x".into(),
        desc: WasmImportDesc::Function(0),
        resolved: false,
    };
    assert!(r.is_function());
    assert!(!r.is_global());

    let r2 = ResolvedImport {
        module: "env".into(),
        field: "g".into(),
        desc: WasmImportDesc::Global(WasmGlobalType {
            val_type: WasmValType::I32,
            mutable: false,
        }),
        resolved: true,
    };
    assert!(r2.is_global());
    assert!(!r2.is_function());
}

// ─── WasmError display ───────────────────────────────────────────────────────

#[test]
fn error_display() {
    assert_eq!(format!("{}", WasmError::InvalidMagic), "invalid magic bytes");
    assert_eq!(
        format!("{}", WasmError::UnsupportedVersion(2)),
        "unsupported version 2"
    );
}

// ─── WasmLoader ──────────────────────────────────────────────────────────────

#[test]
fn loader_can_load_detects_magic() {
    use rustre_core::loader::{Loader, LoaderInput};
    let loader = WasmLoader;
    let good = LoaderInput {
        uri: "test://x".to_string(),
        data: minimal_header(),
        hints: Default::default(),
        options: Default::default(),
    };
    assert!(loader.can_load(&good));

    let bad = LoaderInput {
        uri: "test://x".to_string(),
        data: vec![0xDE, 0xAD],
        hints: Default::default(),
        options: Default::default(),
    };
    assert!(!loader.can_load(&bad));
}

#[test]
fn loader_name() {
    use rustre_core::loader::Loader;
    assert_eq!(WasmLoader.name(), "wasm");
}
