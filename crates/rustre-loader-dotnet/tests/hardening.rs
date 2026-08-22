//! Adversarial hardening tests: attacker-controlled .NET metadata must not
//! cause unbounded allocation, stack overflow, or cursor overflow.

use rustre_loader_dotnet::cil_decoder::decode_method_body;
use rustre_loader_dotnet::cil_disasm::CilDisassembler;
use rustre_loader_dotnet::dotnet_method_loader::LocalVarSig;
use rustre_loader_dotnet::dotnet_type_system::{decode_method_sig, decode_type_sig};
use rustre_loader_dotnet::{parse_tables_stream, read_method_sig, read_type_sig, TypeSig};

/// Encode the 4-byte CLR compressed uint `0x1FFF_FFFF` (the maximum).
const MAX_CUINT: [u8; 4] = [0xDF, 0xFF, 0xFF, 0xFF];

// ── Alloc-DoS: #~ tables stream row counts ───────────────────────────────────

#[test]
fn tables_stream_huge_row_counts_no_oom() {
    // Header: 24 bytes, valid mask claims many tables, each with the maximum
    // row count the header sanity check allows (stream length). The parser
    // must clamp per-table counts to the remaining bytes instead of pushing
    // millions of zero rows.
    let mut s = vec![0u8; 24];
    // valid mask: tables 0x00,0x01,0x02,0x04,0x06 present
    let valid: u64 = (1 << 0x00) | (1 << 0x01) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06);
    s[8..16].copy_from_slice(&valid.to_le_bytes());
    let total_len: u32 = 24 + 5 * 4 + 64; // header + row counts + small tail
    for _ in 0..5 {
        s.extend_from_slice(&(total_len - 1).to_le_bytes());
    }
    s.extend_from_slice(&[0u8; 64]);
    let r = parse_tables_stream(&s);
    if let Ok(t) = r {
        // Every table's rows must be bounded by the stream size.
        assert!(t.modules.len() <= s.len());
        assert!(t.type_refs.len() <= s.len());
        assert!(t.type_defs.len() <= s.len());
        assert!(t.fields.len() <= s.len());
        assert!(t.method_defs.len() <= s.len());
    }
}

#[test]
fn tables_stream_row_count_beyond_stream_rejected() {
    let mut s = vec![0u8; 24];
    s[8..16].copy_from_slice(&(1u64 << 0x02).to_le_bytes()); // TypeDef only
    s.extend_from_slice(&u32::MAX.to_le_bytes()); // absurd row count
    assert!(parse_tables_stream(&s).is_err());
}

// ── Recursion: nested type signatures ────────────────────────────────────────

#[test]
fn read_type_sig_deeply_nested_ptr_no_stack_overflow() {
    // 200k nested ELEMENT_TYPE_PTR (0x0F): without a depth limit this
    // overflows the stack.
    let blob = vec![0x0Fu8; 200_000];
    let mut off = 0usize;
    let _ = read_type_sig(&blob, &mut off);
}

#[test]
fn decode_type_sig_deeply_nested_no_stack_overflow() {
    // Same via the dotnet_type_system decoder (Ptr = 0x0F, ByRef = 0x10).
    let blob = vec![0x10u8; 200_000];
    let _ = decode_type_sig(&blob);
}

#[test]
fn read_type_sig_nested_modifiers_no_depth_reset() {
    // CModReqd (0x1F)/Pinned (0x45) chains must also count against the depth
    // limit rather than recursing through the depth-0 wrapper.
    let blob = vec![0x45u8; 200_000];
    let _ = decode_type_sig(&blob);
}

// ── Alloc-DoS: claimed counts in signature blobs ─────────────────────────────

#[test]
fn method_sig_huge_param_count_no_oom() {
    // calling_conv 0x00, param_count = 0x1FFFFFFF, ret = I4, then EOF.
    let mut blob = vec![0x00u8];
    blob.extend_from_slice(&MAX_CUINT);
    blob.push(0x08);
    let sig = read_method_sig(&blob);
    assert!(sig.params.len() <= blob.len());
}

#[test]
fn generic_inst_huge_arg_count_no_oom() {
    // GENERICINST class token=1 argc=0x1FFFFFFF then EOF.
    let mut blob = vec![0x15u8, 0x12, 0x01];
    blob.extend_from_slice(&MAX_CUINT);
    let mut off = 0usize;
    let sig = read_type_sig(&blob, &mut off);
    if let TypeSig::GenericInst(_, _, args) = sig {
        assert!(args.len() <= blob.len());
    }
}

#[test]
fn decode_method_sig_huge_param_count_no_oom() {
    let mut blob = vec![0x00u8];
    blob.extend_from_slice(&MAX_CUINT);
    blob.push(0x08);
    if let Some(sig) = decode_method_sig(&blob) {
        assert!(sig.params.len() <= blob.len());
    }
}

#[test]
fn local_var_sig_huge_count_no_oom() {
    // LOCAL_SIG 0x07, count = 0x1FFFFFFF, one I4 local, then EOF.
    let mut blob = vec![0x07u8];
    blob.extend_from_slice(&MAX_CUINT);
    blob.push(0x08);
    let sig = LocalVarSig::parse(&blob, 0).expect("parse");
    assert!(sig.local_count() <= blob.len());
}

// ── Alloc-DoS: CIL switch instruction ────────────────────────────────────────

#[test]
fn cil_decoder_switch_huge_count_no_oom() {
    // switch (0x45) with count u32::MAX and no targets.
    let mut code = vec![0x45u8];
    code.extend_from_slice(&u32::MAX.to_le_bytes());
    let _ = decode_method_body(&code);
}

#[test]
fn cil_disasm_switch_huge_count_no_oom() {
    let mut code = vec![0x45u8];
    code.extend_from_slice(&u32::MAX.to_le_bytes());
    let _ = CilDisassembler::disassemble(&code);
}
