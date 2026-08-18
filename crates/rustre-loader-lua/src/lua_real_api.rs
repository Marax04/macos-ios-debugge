//! Byte-driven ("real") entry points for the Lua bytecode loader.
//!
//! Every function in this module takes the **actual chunk bytes** and reports
//! only what the parser found in them. Nothing here invents a prototype, a
//! constant, an instruction or a string: when the input cannot be parsed the
//! function returns a [`LuaLoaderError`] naming precisely what is wrong
//! (bad magic, LuaJIT container, unsupported version byte, truncation).
//!
//! These are the functions the MCP layer must call instead of the `*::mock`
//! constructors, which exist only for unit tests.

use crate::{
    LuaBytecode, LuaBytecodeLoader, LuaChunk, LuaLoaderError, LuaModule, LuaProto, LuaVersion,
    ModuleDisasm, ProtoStats, disassemble_proto,
};

/// LuaJIT container magic (`\x1bLJ`), which the Lua 5.x loader cannot parse.
pub const LUAJIT_MAGIC: &[u8; 3] = b"\x1bLJ";

/// Lua versions whose prototype layout this crate implements.
pub const SUPPORTED_VERSION_BYTES: [u8; 4] = [0x51, 0x52, 0x53, 0x54];

/// Validate the container of `data` and return the version it actually declares.
///
/// This is the version gate the byte-driven API uses before handing bytes to a
/// prototype parser, so an unknown version byte is *reported* rather than
/// silently parsed with the Lua 5.3/5.4 layout.
///
/// # Errors
/// * [`LuaLoaderError::TruncatedData`] – fewer than 5 bytes, so the version byte is absent.
/// * [`LuaLoaderError::ParseError`] – the data is a LuaJIT chunk (`\x1bLJ`); the message
///   names the LuaJIT bytecode version and the crate that can read it.
/// * [`LuaLoaderError::InvalidMagic`] – the first four bytes are not `\x1bLua`.
/// * [`LuaLoaderError::UnsupportedVersion`] – the version byte is not one of
///   [`SUPPORTED_VERSION_BYTES`] (this includes Lua 5.0, `0x50`, whose prototype
///   layout differs and is not reachable from this entry point).
pub fn detect_chunk_version(data: &[u8]) -> Result<LuaVersion, LuaLoaderError> {
    if data.len() < 5 {
        return Err(LuaLoaderError::TruncatedData);
    }
    if data.starts_with(LUAJIT_MAGIC.as_ref()) {
        return Err(LuaLoaderError::ParseError(format!(
            "LuaJIT bytecode container (magic \\x1bLJ, bc version 0x{:02x}); \
             parse it with rustre-loader-luajit, the Lua 5.x layout does not apply",
            data[3]
        )));
    }
    if !data.starts_with(crate::LUA_MAGIC.as_ref()) {
        return Err(LuaLoaderError::InvalidMagic);
    }
    let vb = data[4];
    if !SUPPORTED_VERSION_BYTES.contains(&vb) {
        return Err(LuaLoaderError::UnsupportedVersion(vb));
    }
    Ok(LuaVersion::from_byte(vb))
}

/// Parse `data` into a [`LuaModule`], refusing version bytes whose layout is
/// not implemented instead of guessing one.
///
/// # Errors
/// Propagates [`detect_chunk_version`] and the header/prototype parsers.
pub fn parse_chunk_strict(data: &[u8]) -> Result<LuaModule, LuaLoaderError> {
    detect_chunk_version(data)?;
    LuaBytecodeLoader::load(data)
}

/// Parse `data` into a [`LuaBytecode`] (header + top-level prototype), strictly.
///
/// # Errors
/// Same as [`parse_chunk_strict`].
pub fn parse_bytecode_strict(data: &[u8]) -> Result<LuaBytecode, LuaLoaderError> {
    detect_chunk_version(data)?;
    LuaBytecode::parse(data)
}

impl LuaProto {
    /// Parse the **top-level prototype of real chunk bytes**.
    ///
    /// This is the honest counterpart of [`LuaProto::mock`]: every field of the
    /// returned prototype comes from `data`.
    ///
    /// # Errors
    /// Propagates [`parse_bytecode_strict`].
    pub fn from_chunk_bytes(data: &[u8]) -> Result<Self, LuaLoaderError> {
        parse_bytecode_strict(data).map(|bc| bc.top_level)
    }
}

impl LuaChunk {
    /// Summarise the top-level prototype of real chunk bytes.
    ///
    /// Honest counterpart of [`LuaChunk::mock`].
    ///
    /// # Errors
    /// Propagates [`parse_bytecode_strict`].
    pub fn from_chunk_bytes(data: &[u8]) -> Result<Self, LuaLoaderError> {
        LuaProto::from_chunk_bytes(data).map(|p| Self::from_proto(&p))
    }
}

impl ProtoStats {
    /// Compute prototype statistics over real chunk bytes.
    ///
    /// # Errors
    /// Propagates [`parse_bytecode_strict`].
    pub fn from_chunk_bytes(data: &[u8]) -> Result<Self, LuaLoaderError> {
        LuaProto::from_chunk_bytes(data).map(|p| Self::from_proto(&p))
    }
}

impl ModuleDisasm {
    /// Disassemble every prototype found in real chunk bytes.
    ///
    /// # Errors
    /// Propagates [`parse_chunk_strict`].
    pub fn from_chunk_bytes(data: &[u8]) -> Result<Self, LuaLoaderError> {
        parse_chunk_strict(data).map(|m| Self::from_module(&m))
    }
}

/// Disassemble the top-level prototype of real chunk bytes, using the version
/// byte the header actually contains.
///
/// # Errors
/// Propagates [`parse_bytecode_strict`].
pub fn disassemble_chunk_bytes(data: &[u8]) -> Result<Vec<String>, LuaLoaderError> {
    let bc = parse_bytecode_strict(data)?;
    let vb = bc.header.version.as_byte();
    Ok(disassemble_proto(&bc.top_level, vb))
}

/// Collect the deduplicated string constants of real chunk bytes, walking every
/// nested prototype.
///
/// # Errors
/// Propagates [`parse_chunk_strict`].
pub fn all_strings_from_chunk_bytes(data: &[u8]) -> Result<Vec<String>, LuaLoaderError> {
    let module = parse_chunk_strict(data)?;
    Ok(LuaBytecodeLoader::all_strings(&module))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but structurally real Lua 5.1 chunk: header + one prototype with
    /// a single RETURN instruction, one string constant, no nested protos and
    /// no debug info. Built byte by byte so the test asserts against the bytes.
    fn lua51_chunk() -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"\x1bLua");
        d.push(0x51); // version
        d.push(0x00); // format
        d.push(0x01); // little endian
        d.push(4); // int size
        d.push(8); // size_t
        d.push(4); // instruction size
        d.push(8); // lua_Number size
        d.push(0); // not integral
        // ── top-level prototype ──
        let name = b"@real.lua";
        d.extend_from_slice(&((name.len() + 1) as u64).to_le_bytes()); // size_t length
        d.extend_from_slice(name);
        d.push(0); // NUL terminator
        d.extend_from_slice(&0u32.to_le_bytes()); // first line
        d.extend_from_slice(&7u32.to_le_bytes()); // last line
        d.push(0); // nups
        d.push(1); // numparams
        d.push(2); // is_vararg
        d.push(3); // maxstacksize
        d.extend_from_slice(&1u32.to_le_bytes()); // 1 instruction
        d.extend_from_slice(&0x0080_001Eu32.to_le_bytes()); // RETURN
        d.extend_from_slice(&1u32.to_le_bytes()); // 1 constant
        d.push(4); // LUA_TSTRING
        let s = b"greetings";
        d.extend_from_slice(&((s.len() + 1) as u64).to_le_bytes());
        d.extend_from_slice(s);
        d.push(0);
        d.extend_from_slice(&0u32.to_le_bytes()); // 0 nested protos
        d.extend_from_slice(&0u32.to_le_bytes()); // 0 line info
        d.extend_from_slice(&0u32.to_le_bytes()); // 0 locals
        d.extend_from_slice(&0u32.to_le_bytes()); // 0 upvalue names
        d
    }

    #[test]
    fn detect_version_reads_the_header_byte() {
        assert_eq!(detect_chunk_version(&lua51_chunk()).unwrap(), LuaVersion::Lua51);
    }

    #[test]
    fn unsupported_version_is_named_not_guessed() {
        let mut d = lua51_chunk();
        d[4] = 0x50;
        match detect_chunk_version(&d) {
            Err(LuaLoaderError::UnsupportedVersion(0x50)) => {}
            other => panic!("expected UnsupportedVersion(0x50), got {other:?}"),
        }
    }

    #[test]
    fn luajit_container_is_reported_as_luajit() {
        let d = b"\x1bLJ\x02\x00rest".to_vec();
        match detect_chunk_version(&d) {
            Err(LuaLoaderError::ParseError(msg)) => assert!(msg.contains("LuaJIT")),
            other => panic!("expected LuaJIT ParseError, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_and_truncation_are_distinguished() {
        assert!(matches!(
            detect_chunk_version(b"not lua at all"),
            Err(LuaLoaderError::InvalidMagic)
        ));
        assert!(matches!(
            detect_chunk_version(b"\x1bLu"),
            Err(LuaLoaderError::TruncatedData)
        ));
    }

    #[test]
    fn proto_fields_come_from_the_bytes() {
        let p = LuaProto::from_chunk_bytes(&lua51_chunk()).unwrap();
        assert_eq!(p.name.as_deref(), Some("@real.lua"));
        assert_eq!(p.num_params, 1);
        assert_eq!(p.max_stack, 3);
        assert_eq!(p.last_line, 7);
        assert_eq!(p.instructions.len(), 1);
        assert_eq!(p.constants.len(), 1);
        // Nothing from LuaProto::mock survived.
        assert_ne!(p.name.as_deref(), Some("@test.lua"));
    }

    #[test]
    fn chunk_stats_and_strings_come_from_the_bytes() {
        let data = lua51_chunk();
        let c = LuaChunk::from_chunk_bytes(&data).unwrap();
        assert_eq!(c.name, "@real.lua");
        assert_eq!(c.instructions_count, 1);
        assert_eq!(c.constants_count, 1);
        assert_eq!(c.functions_count, 0);

        let s = ProtoStats::from_chunk_bytes(&data).unwrap();
        assert_eq!(s.proto_count, 1);
        assert_eq!(s.instruction_count, 1);
        assert_eq!(s.string_count, 1);

        let strings = all_strings_from_chunk_bytes(&data).unwrap();
        assert_eq!(strings, vec!["greetings".to_string()]);
    }

    #[test]
    fn disassembly_has_one_line_per_real_instruction() {
        let data = lua51_chunk();
        let lines = disassemble_chunk_bytes(&data).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("RETURN"), "got {:?}", lines[0]);

        let md = ModuleDisasm::from_chunk_bytes(&data).unwrap();
        assert_eq!(md.version, LuaVersion::Lua51);
        assert_eq!(md.protos.len(), 1);
        assert_eq!(md.protos[0].lines.len(), 1);
    }

    #[test]
    fn every_real_entry_point_rejects_garbage() {
        let junk = b"\x1bLua\x99garbagegarbage";
        assert!(LuaProto::from_chunk_bytes(junk).is_err());
        assert!(LuaChunk::from_chunk_bytes(junk).is_err());
        assert!(ProtoStats::from_chunk_bytes(junk).is_err());
        assert!(ModuleDisasm::from_chunk_bytes(junk).is_err());
        assert!(disassemble_chunk_bytes(junk).is_err());
        assert!(all_strings_from_chunk_bytes(junk).is_err());
    }
}
