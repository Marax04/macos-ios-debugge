//! Adversarial hardening tests: attacker-controlled counts/lengths must fail
//! fast with an error (or a bounded result), never OOM, wrap, or panic.

use rustre_loader_wasm::*;

fn leb(mut v: u64) -> Vec<u8> {
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

/// Build a minimal wasm module with one section `(id, payload)`.
fn module_with_section(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    m.push(id);
    m.extend(leb(payload.len() as u64));
    m.extend_from_slice(payload);
    m
}

// ── Alloc-DoS: giant LEB128 counts with tiny payloads ────────────────────────

#[test]
fn huge_type_count_no_oom() {
    // count = u32::MAX but no entries follow
    let payload = leb(u64::from(u32::MAX));
    let bin = module_with_section(1, &payload);
    assert!(WasmParser::parse(&bin).is_err());
}

#[test]
fn huge_param_count_no_oom() {
    let mut payload = leb(1); // one type
    payload.push(0x60);
    payload.extend(leb(u64::from(u32::MAX))); // param count
    let bin = module_with_section(1, &payload);
    assert!(WasmParser::parse(&bin).is_err());
}

#[test]
fn huge_counts_all_sections_no_oom() {
    // import(2), function(3), export(7), code(10), data(11), global(6)
    for id in [2u8, 3, 6, 7, 10, 11] {
        let payload = leb(u64::from(u32::MAX));
        let bin = module_with_section(id, &payload);
        assert!(
            WasmParser::parse(&bin).is_err(),
            "section id {id} should reject truncated giant count"
        );
    }
}

#[test]
fn huge_local_decl_count_no_oom() {
    // code section: 1 entry, body declares u32::MAX local decls
    let mut body = leb(u64::from(u32::MAX));
    body.push(0x0B);
    let mut payload = leb(1);
    payload.extend(leb(body.len() as u64));
    payload.extend_from_slice(&body);
    let bin = module_with_section(10, &payload);
    assert!(WasmParser::parse(&bin).is_err());
}

#[test]
fn br_table_huge_label_count_no_oom() {
    // 0x0E br_table with label count u32::MAX, then nothing
    let mut code = vec![0x0E];
    code.extend(leb(u64::from(u32::MAX)));
    let mut d = WasmDisassembler::new(&code);
    assert!(d.disassemble_all().is_err());
}

#[test]
fn producers_huge_field_count_no_oom() {
    let payload = leb(u64::from(u32::MAX));
    assert!(WasmProducersSection::parse(&payload).is_err());
}

#[test]
fn binary_parser_huge_counts_no_oom() {
    use wasm_binary_parser::BinaryParser;
    for id in [1u8, 2, 3, 4, 5, 6, 7, 9, 10, 11] {
        let payload = leb(u64::from(u32::MAX));
        let bin = module_with_section(id, &payload);
        assert!(
            BinaryParser::parse(&bin).is_err(),
            "binary_parser section {id} should reject giant count"
        );
    }
}

#[test]
fn module_loader_huge_counts_no_oom() {
    use wasm_module_loader::WasmLoader;
    let loader = WasmLoader::new();
    for id in [1u8, 3, 7, 9, 10] {
        let payload = leb(u64::from(u32::MAX));
        let bin = module_with_section(id, &payload);
        assert!(
            loader.load(&bin).is_err(),
            "module_loader section {id} should reject giant count"
        );
    }
}

#[test]
fn import_export_huge_counts_no_oom() {
    use wasm_import_export::WasmImportExport;
    let payload = leb(u64::from(u32::MAX));
    assert!(WasmImportExport::parse_imports(&payload).is_err());
    assert!(WasmImportExport::parse_exports(&payload).is_err());
}

#[test]
fn type_decoder_huge_count_no_oom() {
    use wasm_type_decoder::WasmTypeDecoder;
    let payload = leb(u64::from(u32::MAX));
    assert!(WasmTypeDecoder::decode_type_section(&payload).is_err());
}

// ── Cursor overflow: u64 lengths in the component-model parser ───────────────

#[test]
fn component_name_len_overflow_no_panic() {
    use wasm_component_model::detect_component_model;
    // custom section whose name length is u64::MAX → pos + len must not wrap
    let mut payload = leb(u64::MAX);
    payload.extend_from_slice(b"x");
    let mut bin = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    bin.push(0); // custom section
    bin.extend(leb(payload.len() as u64));
    bin.extend_from_slice(&payload);
    assert!(detect_component_model(&bin).is_err());
}

#[test]
fn component_section_len_overflow_no_panic() {
    use wasm_component_model::detect_component_model;
    // section length u64::MAX → pos + section_len must not wrap
    let mut bin = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    bin.push(0);
    bin.extend(leb(u64::MAX));
    assert!(detect_component_model(&bin).is_err());
}

// ── Time/alloc DoS in analysis helpers ───────────────────────────────────────

#[test]
fn analyze_locals_huge_total_locals_terminates() {
    use std::time::Instant;
    use wasm_optimization_hints::WasmOptAnalyzer;
    let a = WasmOptAnalyzer::new();
    let t = Instant::now();
    let r = a.analyze_locals(&[0x20, 0x00, 0x0B], u32::MAX);
    assert!(t.elapsed().as_secs() < 5, "analyze_locals must not iterate 4G locals");
    assert_eq!(r.total_locals, u32::MAX);
    assert_eq!(r.used_locals, 1);
}
