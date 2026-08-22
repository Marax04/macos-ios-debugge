//! Regressions for allocation and recursion limits on malformed Lua bytecode.
//!
//! Each test FAILS when the corresponding guard is removed — verified by
//! reintroducing the defect and re-running.

use std::io::Cursor;

use rustre_loader_lua::lua50_format::{Lua50Header, decode_lua50_proto};
use rustre_loader_lua::lua51_format::decode_lua51_proto;
use rustre_loader_lua::lua52_53_format::{decode_lua52_proto, decode_lua53_proto};
use rustre_loader_lua::parse_limits::MAX_PROTO_DEPTH;

// ── Lua 5.0: count fields are `sizeof(int)`-wide, so they can be 64-bit ───────

fn lua50_header_with_wide_ints() -> Lua50Header {
    Lua50Header {
        little_endian: true,
        int_size: 8,
        size_t_size: 1,
        instruction_size: 4,
        number_size: 8,
        is_integer_num: false,
    }
}

fn lua50_header_compact() -> Lua50Header {
    Lua50Header {
        little_endian: true,
        int_size: 1,
        size_t_size: 1,
        instruction_size: 4,
        number_size: 8,
        is_integer_num: false,
    }
}

/// A Lua 5.0 prototype claiming 2^62 instructions in a 32-byte file.
///
/// `Vec::with_capacity(code_size)` was called with the raw field, reserving
/// `2^62 * 4` bytes — past `isize::MAX`, so the parser died in the allocator
/// before reading one instruction byte. The reservation is now clamped to what
/// the remaining bytes could hold.
#[test]
fn lua50_absurd_code_size_does_not_reserve_the_address_space() {
    let hdr = lua50_header_with_wide_ints();
    let mut body = vec![0u8]; // source name: size_t length 0
    body.extend_from_slice(&0u64.to_le_bytes()); // line_defined
    body.extend_from_slice(&[0, 0, 0, 2]); // upvalues, params, vararg, max_stack
    body.extend_from_slice(&(1u64 << 62).to_le_bytes()); // code_size
    let mut offset = 0usize;
    // Must return an error, not die reserving memory.
    assert!(decode_lua50_proto(&body, &mut offset, &hdr).is_err());
}

/// One Lua 5.0 prototype nested `levels` deep, ~7 bytes per level.
fn lua50_nested(levels: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..levels {
        out.push(0); // source name length 0
        out.push(0); // line_defined (int_size 1)
        out.extend_from_slice(&[0, 0, 0, 2]); // upvalues, params, vararg, max_stack
        out.push(0); // code_size
        out.push(0); // constant count
        out.push(0); // line-info count
        out.push(0); // local count
        out.push(0); // upvalue-name count
        out.push(1); // one inner proto follows
    }
    // Innermost prototype: same shape, but no inner protos.
    out.push(0);
    out.push(0);
    out.extend_from_slice(&[0, 0, 0, 2]);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    out
}

#[test]
fn lua50_deep_nesting_errors_instead_of_exhausting_the_stack() {
    let data = lua50_nested(200_000);
    let hdr = lua50_header_compact();
    let mut offset = 0usize;
    assert!(
        decode_lua50_proto(&data, &mut offset, &hdr).is_err(),
        "200k nesting levels must be refused"
    );
}

#[test]
fn lua50_nesting_within_the_cap_still_parses() {
    let levels = 4;
    assert!(levels < MAX_PROTO_DEPTH);
    let data = lua50_nested(levels);
    let hdr = lua50_header_compact();
    let mut offset = 0usize;
    let proto = decode_lua50_proto(&data, &mut offset, &hdr).expect("4 levels are legitimate");
    assert_eq!(proto.protos.len(), 1);
}

// ── Lua 5.1 / 5.2 / 5.3: 32-bit counts, still far beyond the buffer ──────────

/// Prototype header claiming `n_const` constants with no constant bytes.
fn lua51_body_with_constant_count(n_const: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0); // source name: length byte 0 (absent)
    body.extend_from_slice(&0i32.to_le_bytes()); // line_defined
    body.extend_from_slice(&0i32.to_le_bytes()); // last_line_defined
    body.extend_from_slice(&[0, 0, 0, 2]); // upvalues, params, vararg, max_stack
    body.extend_from_slice(&0u32.to_le_bytes()); // n_code
    body.extend_from_slice(&n_const.to_le_bytes());
    body
}

/// `n_const = 0xFFFF_FFFF` with an empty constant section.
///
/// The reservation was `Vec::with_capacity(0xFFFF_FFFF)` of a 32-byte enum —
/// about 137 GiB requested before reading a single constant tag.
#[test]
fn lua51_absurd_constant_count_does_not_reserve_the_address_space() {
    let body = lua51_body_with_constant_count(u32::MAX);
    let mut cur = Cursor::new(&body[..]);
    assert!(decode_lua51_proto(&mut cur).is_err());
}

/// Nest `levels` Lua 5.1 prototypes.
///
/// A 5.1 prototype stores its sub-prototypes in the MIDDLE of the body, so each
/// level contributes a prefix before the child and a tail after it.
fn lua51_nested(levels: usize) -> Vec<u8> {
    fn prefix(out: &mut Vec<u8>, n_proto: u32) {
        out.push(0); // source name: length byte 0 (absent)
        out.extend_from_slice(&0i32.to_le_bytes()); // line_defined
        out.extend_from_slice(&0i32.to_le_bytes()); // last_line_defined
        out.extend_from_slice(&[0, 0, 0, 2]); // upvalues, params, vararg, max_stack
        out.extend_from_slice(&0u32.to_le_bytes()); // n_code
        out.extend_from_slice(&0u32.to_le_bytes()); // n_const
        out.extend_from_slice(&n_proto.to_le_bytes()); // n_proto
    }
    fn tail(out: &mut Vec<u8>) {
        out.extend_from_slice(&0u32.to_le_bytes()); // n_lines
        out.extend_from_slice(&0u32.to_le_bytes()); // n_locals
        out.extend_from_slice(&0u32.to_le_bytes()); // n_upvals
    }
    let mut out = Vec::new();
    for _ in 0..levels {
        prefix(&mut out, 1);
    }
    prefix(&mut out, 0); // innermost
    for _ in 0..=levels {
        tail(&mut out);
    }
    out
}

#[test]
fn lua51_deep_nesting_errors_instead_of_exhausting_the_stack() {
    let data = lua51_nested(100_000);
    let mut cur = Cursor::new(&data[..]);
    let err = decode_lua51_proto(&mut cur).expect_err("100k nesting levels must be refused");
    assert!(err.contains("depth"), "unexpected error: {err}");
}

#[test]
fn lua51_nesting_within_the_cap_still_parses() {
    let data = lua51_nested(4);
    let mut cur = Cursor::new(&data[..]);
    let proto = decode_lua51_proto(&mut cur).expect("4 levels are legitimate");
    assert_eq!(proto.protos.len(), 1);
}

/// Shared 5.2/5.3 prototype header claiming `n_const` constants.
fn lua52_body_with_constant_count(n_const: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0); // source name: length byte 0 (absent)
    body.extend_from_slice(&0i32.to_le_bytes()); // line_defined
    body.extend_from_slice(&0i32.to_le_bytes()); // last_line_defined
    body.extend_from_slice(&[0, 0, 2]); // params, vararg, max_stack
    body.extend_from_slice(&0u32.to_le_bytes()); // n_code
    body.extend_from_slice(&n_const.to_le_bytes());
    body
}

#[test]
fn lua52_absurd_constant_count_does_not_reserve_the_address_space() {
    let body = lua52_body_with_constant_count(u32::MAX);
    let mut cur = Cursor::new(&body[..]);
    assert!(decode_lua52_proto(&mut cur).is_err());
}

#[test]
fn lua53_absurd_constant_count_does_not_reserve_the_address_space() {
    let body = lua52_body_with_constant_count(u32::MAX);
    let mut cur = Cursor::new(&body[..]);
    assert!(decode_lua53_proto(&mut cur).is_err());
}
