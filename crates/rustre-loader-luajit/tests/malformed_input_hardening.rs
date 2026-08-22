//! Regressions for integer-overflow guards on attacker-controlled LuaJIT bytecode.
//!
//! Each test FAILS when the corresponding guard is removed — verified by
//! reintroducing the defect and re-running.

use rustre_loader_luajit::luajit_parser::LjParser;
use rustre_loader_luajit::{LjProto, is_luajit};

/// ULEB128 encoding of `v`.
fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `bc_count = 2^62`, chosen so that `bc_count * 4` overflows a 64-bit `usize`.
const OVERFLOWING_BC_COUNT: u64 = 1u64 << 62;

/// A proto body whose bytecode count overflows the address space.
///
/// The old guard was `p + bc_count.saturating_mul(4) > pd.len()`. The
/// multiplication saturates to `usize::MAX` and `p + usize::MAX` then WRAPS
/// (release builds have `overflow-checks` off), producing a small number that
/// passes the bound check — so the check believed itself while permitting a
/// `Vec::with_capacity(2^62)` reservation right after it.
fn proto_body_with_overflowing_bc_count() -> Vec<u8> {
    let mut body = vec![
        0x00, // proto flags
        0x00, // num_params
        0x02, // frame_size
        0x00, // num_upvalues
    ];
    body.extend(uleb(0)); // num_kgc
    body.extend(uleb(0)); // num_kn
    body.extend(uleb(OVERFLOWING_BC_COUNT)); // bc_count
    body.extend(uleb(0)); // dbg_info_size
    body
}

/// Stripped LuaJIT 2.1 bcdump containing that one proto.
fn bcdump_with_overflowing_bc_count() -> Vec<u8> {
    let body = proto_body_with_overflowing_bc_count();
    let mut out = vec![0x1B, b'L', b'J', 0x02];
    out.extend(uleb(0x02)); // flags: stripped
    out.extend(uleb(body.len() as u64)); // proto size
    out.extend_from_slice(&body);
    out.push(0x00); // end of proto list
    out
}

#[test]
fn header_is_recognised_so_the_test_reaches_the_proto_parser() {
    let data = bcdump_with_overflowing_bc_count();
    assert!(is_luajit(&data), "fixture must look like LuaJIT bytecode");
    assert!(LjParser::is_luajit(&data));
}

#[test]
fn parser_rejects_bc_count_whose_byte_span_overflows() {
    let data = bcdump_with_overflowing_bc_count();
    let err = LjParser::parse(&data)
        .expect_err("a bytecode count of 2^62 must be rejected, not reserved");
    let msg = err.to_string();
    assert!(
        msg.contains("overflows the address space") || msg.contains("out of bounds"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ljproto_parse_rejects_bc_count_whose_byte_span_overflows() {
    let body = proto_body_with_overflowing_bc_count();
    let mut data = uleb(body.len() as u64);
    data.extend_from_slice(&body);
    assert!(
        LjProto::parse(&data, 0, false).is_none(),
        "a bytecode count of 2^62 must be rejected, not reserved"
    );
}

#[test]
fn an_honest_proto_still_parses() {
    // Same shape, with a truthful bc_count of 1 and one instruction word.
    let mut body = vec![0x00, 0x00, 0x02, 0x00];
    body.extend(uleb(0));
    body.extend(uleb(0));
    body.extend(uleb(1));
    body.extend(uleb(0));
    body.extend_from_slice(&[0x4B, 0x00, 0x01, 0x00]);
    let mut data = vec![0x1B, b'L', b'J', 0x02];
    data.extend(uleb(0x02));
    data.extend(uleb(body.len() as u64));
    data.extend_from_slice(&body);
    data.push(0x00);
    let (_, protos) = LjParser::parse(&data).expect("well-formed bcdump must parse");
    assert_eq!(protos.len(), 1);
    assert_eq!(protos[0].instructions.len(), 1);
}
