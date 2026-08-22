//! Hardening tests for `rustre-loader-lua`.
//!
//! Lua bytecode (`.luac`) prefixes every variable-length table — instructions,
//! constants, nested protos, line info, locals, upvalues — with a count read
//! straight from the file. Those counts were previously handed to
//! `Vec::with_capacity` *before* any element was read, so a few dozen bytes
//! could request a multi-gigabyte reservation.
//!
//! Each test asserts the parser survives the input; what a malformed chunk
//! decodes to is deliberately not pinned down, only that it does not abort the
//! process.

use rustre_loader_lua::{LuaBytecode, LUA_MAGIC};

/// Build a Lua 5.1 header (12 bytes) followed by `body`.
fn lua51(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(LUA_MAGIC);
    v.push(0x51); // version 5.1
    v.push(0); // format = official
    v.push(1); // endian = little
    v.push(4); // int size
    v.push(8); // size_t size
    v.push(4); // instruction size
    v.push(8); // lua_Number size
    v.push(0); // is integral
    v.extend_from_slice(body);
    v
}

/// Build a Lua 5.4 header (20 bytes, includes the `LUAC_DATA` block) plus `body`.
fn lua54(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(LUA_MAGIC);
    v.push(0x54); // version 5.4
    v.push(0); // format
    v.push(1); // endian
    v.push(4); // int size
    v.push(8); // size_t size
    v.push(4); // instruction size
    v.push(8); // number size
    v.push(0); // is integral
    v.extend_from_slice(&[0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A]); // LUAC_DATA
    v.push(8); // lua_Integer size
    v.push(8); // lua_Float size
    v.extend_from_slice(body);
    v
}

/// A 5.1 prototype claiming ~4 billion instructions in a tiny file.
///
/// Before the alloc cap this reserved `inst_count * 4` bytes.
#[test]
fn huge_instruction_count_does_not_allocate() {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // source name: length 0
    body.extend_from_slice(&0u32.to_le_bytes()); // first line
    body.extend_from_slice(&0u32.to_le_bytes()); // last line
    body.push(0); // num_params
    body.push(0); // is_vararg
    body.push(2); // max_stack
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // instruction count

    let data = lua51(&body);
    // Must fail cleanly (truncated), not exhaust memory.
    assert!(LuaBytecode::parse(&data).is_err());
}

/// A 5.4 prototype claiming ~4 billion constants.
#[test]
fn huge_constant_count_does_not_allocate() {
    let mut body = Vec::new();
    body.push(0); // source name: 5.4 string, size 0 = absent
    body.extend_from_slice(&0u32.to_le_bytes()); // first line
    body.extend_from_slice(&0u32.to_le_bytes()); // last line
    body.push(0); // num_params
    body.push(0); // is_vararg
    body.push(2); // max_stack
    body.push(0); // preliminary upvalue count
    body.extend_from_slice(&0u32.to_le_bytes()); // instruction count = 0
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // constant count

    let data = lua54(&body);
    assert!(LuaBytecode::parse(&data).is_err());
}

/// A 5.4 prototype claiming ~4 billion nested prototypes.
#[test]
fn huge_proto_count_does_not_allocate() {
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0);
    body.push(0);
    body.push(2);
    body.push(0); // preliminary upvalue count
    body.extend_from_slice(&0u32.to_le_bytes()); // instructions
    body.extend_from_slice(&0u32.to_le_bytes()); // constants
    body.extend_from_slice(&0u32.to_le_bytes()); // upvalues
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nested protos

    let data = lua54(&body);
    assert!(LuaBytecode::parse(&data).is_err());
}

/// A 5.4 prototype claiming ~4 billion line-info entries and locals.
#[test]
fn huge_debug_counts_do_not_allocate() {
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0);
    body.push(0);
    body.push(2);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes()); // instructions
    body.extend_from_slice(&0u32.to_le_bytes()); // constants
    body.extend_from_slice(&0u32.to_le_bytes()); // upvalues
    body.extend_from_slice(&0u32.to_le_bytes()); // protos
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // line info count

    let data = lua54(&body);
    assert!(LuaBytecode::parse(&data).is_err());
}

/// A well-formed, minimal 5.4 chunk must still parse — the caps bound the
/// allocation, they must not truncate legitimate input.
#[test]
fn wellformed_chunk_still_parses() {
    let mut body = Vec::new();
    body.push(0); // source name absent
    body.extend_from_slice(&1u32.to_le_bytes()); // first line
    body.extend_from_slice(&2u32.to_le_bytes()); // last line
    body.push(0); // num_params
    body.push(1); // is_vararg
    body.push(2); // max_stack
    body.push(0); // preliminary upvalue count
    body.extend_from_slice(&2u32.to_le_bytes()); // 2 instructions
    body.extend_from_slice(&0x0000_0026u32.to_le_bytes());
    body.extend_from_slice(&0x0080_0027u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // constants
    body.extend_from_slice(&0u32.to_le_bytes()); // upvalues
    body.extend_from_slice(&0u32.to_le_bytes()); // protos
    body.extend_from_slice(&0u32.to_le_bytes()); // line info
    body.extend_from_slice(&0u32.to_le_bytes()); // locals
    body.extend_from_slice(&0u32.to_le_bytes()); // upvalue names

    let data = lua54(&body);
    let chunk = LuaBytecode::parse(&data).expect("well-formed chunk should parse");
    assert_eq!(chunk.top_level.instructions.len(), 2);
    assert_eq!(chunk.top_level.max_stack, 2);
}

/// Random noise behind a valid magic must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..300 {
        let len = (next() % 200) as usize;
        let body: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let _ = LuaBytecode::parse(&lua51(&body));
        let _ = LuaBytecode::parse(&lua54(&body));
        // Also feed it as a raw buffer with no valid header at all.
        let _ = LuaBytecode::parse(&body);
    }
}

/// Every truncation of a well-formed chunk must fail cleanly, never panic.
#[test]
fn truncations_never_panic() {
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    body.push(0);
    body.push(1);
    body.push(2);
    body.push(0);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0x0000_0026u32.to_le_bytes());
    for _ in 0..5 {
        body.extend_from_slice(&0u32.to_le_bytes());
    }
    let data = lua54(&body);

    for cut in 0..data.len() {
        let _ = LuaBytecode::parse(&data[..cut]);
    }
}
