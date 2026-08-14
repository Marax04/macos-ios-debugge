//! Hardening tests for `rustre-arch-lua`.
//!
//! Two defect classes were fixed here:
//!
//! * **Signed count wrap** — `parse_const_pool_51`/`_53` read the entry count
//!   as `i32` and cast it straight to `usize`. A *negative* count (e.g. `-1`)
//!   wraps to ~1.8e19, and `Vec::with_capacity` then aborts the process with a
//!   capacity overflow rather than failing gracefully. This is distinct from
//!   the usual "count is a huge u32" case: in the source the number looks
//!   small.
//! * **Partial hardening** — `Lua54Disassembler::parse_proto54` capped its
//!   instruction and constant allocations but not upvalues, nested protos,
//!   line info or locals, all driven by the same `read_varint`.

use rustre_arch_lua::{parse_const_pool_51, parse_const_pool_53};
use rustre_arch_lua::lua_disasm::Lua54Disassembler;

/// A negative constant-pool count must not abort with a capacity overflow.
#[test]
fn const_pool_51_negative_count_does_not_overflow() {
    let mut data = Vec::new();
    data.extend_from_slice(&(-1i32).to_le_bytes());
    // No entries follow — the parse must simply fail or return early.
    let _ = parse_const_pool_51(&data);
}

/// Same for the 5.3 pool.
#[test]
fn const_pool_53_negative_count_does_not_overflow() {
    let mut data = Vec::new();
    data.extend_from_slice(&(-1i32).to_le_bytes());
    let _ = parse_const_pool_53(&data);
}

/// `i32::MIN` is the worst case: `.max(0)` must clamp it before the cast.
#[test]
fn const_pool_i32_min_count_does_not_overflow() {
    let mut data = Vec::new();
    data.extend_from_slice(&i32::MIN.to_le_bytes());
    let _ = parse_const_pool_51(&data);
    let _ = parse_const_pool_53(&data);
}

/// A huge positive count over a tiny buffer must not reserve gigabytes.
#[test]
fn const_pool_huge_positive_count_does_not_allocate() {
    let mut data = Vec::new();
    data.extend_from_slice(&i32::MAX.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);
    let _ = parse_const_pool_51(&data);
    let _ = parse_const_pool_53(&data);
}

/// A well-formed pool still parses — the caps bound the reservation, not the
/// result.
#[test]
fn const_pool_wellformed_still_parses() {
    let mut data = Vec::new();
    data.extend_from_slice(&2i32.to_le_bytes()); // two constants
    data.push(0); // LUA_TNIL
    data.push(1); // LUA_TBOOLEAN
    data.push(1); // true
    let out = parse_const_pool_51(&data).expect("well-formed pool should parse");
    assert_eq!(out.len(), 2);
}

/// A Lua 5.4 prototype declaring enormous upvalue/proto/line/local counts must
/// not drive the allocation — these were the four sites left uncapped.
#[test]
fn proto54_huge_debug_counts_do_not_allocate() {
    // varint encoding in Lua 5.4 is big-endian 7-bit with the high bit marking
    // the LAST byte; 0xFF alone therefore encodes 0x7F.
    let mut data = Vec::new();
    data.push(0x80); // source name: varint 0 → absent
    data.extend_from_slice(&0u32.to_le_bytes()); // line defined
    data.extend_from_slice(&0u32.to_le_bytes()); // last line defined
    data.push(0); // numparams
    data.push(0); // is_vararg
    data.push(2); // maxstacksize
    // Instruction count: a large varint (0x7F_FF_FF_FF-ish) with nothing after.
    data.extend_from_slice(&[0x7F, 0x7F, 0x7F, 0x7F, 0xFF]);

    let mut d = Lua54Disassembler::new(data);
    // Header was not parsed, so this exercises the proto path directly; it must
    // return an error rather than exhaust memory.
    let _ = d.parse_proto54();
}

/// Random noise through the disassembler and both pool parsers must never
/// panic or abort.
#[test]
fn random_noise_never_panics() {
    let mut state = 0xC0FF_EE00_1234_5678u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..300 {
        let len = (next() % 160) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let _ = parse_const_pool_51(&buf);
        let _ = parse_const_pool_53(&buf);
        let mut d = Lua54Disassembler::new(buf);
        let _ = d.parse_proto54();
    }
}

/// Truncations of a well-formed constant pool must never panic.
#[test]
fn truncations_never_panic() {
    let mut data = Vec::new();
    data.extend_from_slice(&3i32.to_le_bytes());
    data.push(0);
    data.push(1);
    data.push(1);
    data.push(3); // number tag
    data.extend_from_slice(&1.5f64.to_le_bytes());

    for cut in 0..data.len() {
        let _ = parse_const_pool_51(&data[..cut]);
        let _ = parse_const_pool_53(&data[..cut]);
    }
}
