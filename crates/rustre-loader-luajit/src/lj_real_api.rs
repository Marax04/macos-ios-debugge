//! Byte-driven ("real") entry points for the `LuaJIT` bytecode loader.
//!
//! Counterpart of `rustre_loader_lua::lua_real_api`: every function here takes
//! the actual dump bytes and reports only what was parsed out of them. A dump
//! whose bytecode version this crate does not implement is *named* in the error
//! rather than parsed with a guessed layout.

use crate::{LJ_MAGIC, LjBytecode, LjLoaderError, LjModule, LjProto, LjVersion, LuaJitLoader};

/// `LuaJIT` bytecode versions whose prototype layout this crate implements.
pub const SUPPORTED_BC_VERSIONS: [u8; 2] = [1, 2];

/// Validate the container of `data` and return the bytecode version it declares.
///
/// # Errors
/// * [`LjLoaderError::TruncatedData`] – fewer than 4 bytes, so the version byte is absent.
/// * [`LjLoaderError::ParseError`] – the data is a Lua 5.x chunk (`\x1bLua`); the message
///   names the Lua version byte and the crate that can read it.
/// * [`LjLoaderError::InvalidMagic`] – the first three bytes are not `\x1bLJ`.
/// * [`LjLoaderError::UnsupportedVersion`] – the bytecode version is not in
///   [`SUPPORTED_BC_VERSIONS`].
pub fn detect_dump_version(data: &[u8]) -> Result<LjVersion, LjLoaderError> {
    if data.len() < 4 {
        return Err(LjLoaderError::TruncatedData);
    }
    if data.starts_with(b"\x1bLua") {
        return Err(LjLoaderError::ParseError(format!(
            "Lua 5.x bytecode chunk (magic \\x1bLua, version 0x{:02x}); \
             parse it with rustre-loader-lua, the LuaJIT layout does not apply",
            data[4.min(data.len() - 1)]
        )));
    }
    if !data.starts_with(&LJ_MAGIC) {
        return Err(LjLoaderError::InvalidMagic);
    }
    let vb = data[3];
    if !SUPPORTED_BC_VERSIONS.contains(&vb) {
        return Err(LjLoaderError::UnsupportedVersion(vb));
    }
    Ok(LjVersion::from_byte(vb))
}

/// Parse `data` into an [`LjModule`], refusing unimplemented bytecode versions.
///
/// # Errors
/// Propagates [`detect_dump_version`] and [`LuaJitLoader::load`].
pub fn parse_dump_strict(data: &[u8]) -> Result<LjModule, LjLoaderError> {
    detect_dump_version(data)?;
    LuaJitLoader::load(data)
}

/// Parse every prototype in `data`, refusing unimplemented bytecode versions.
///
/// # Errors
/// Propagates [`detect_dump_version`] and [`LjBytecode::parse`].
pub fn parse_all_protos_strict(data: &[u8]) -> Result<LjBytecode, LjLoaderError> {
    detect_dump_version(data)?;
    LjBytecode::parse(data)
}

impl LjProto {
    /// Parse the root prototype out of real `LuaJIT` dump bytes.
    ///
    /// Honest counterpart of [`LjProto::mock`]: every field comes from `data`.
    ///
    /// # Errors
    /// Propagates [`parse_dump_strict`].
    pub fn from_dump_bytes(data: &[u8]) -> Result<Self, LjLoaderError> {
        parse_dump_strict(data).map(|m| m.root_proto)
    }
}

/// Collect the deduplicated string constants of a real `LuaJIT` dump.
///
/// # Errors
/// Propagates [`parse_all_protos_strict`].
pub fn all_strings_from_dump_bytes(data: &[u8]) -> Result<Vec<String>, LjLoaderError> {
    let bc = parse_all_protos_strict(data)?;
    Ok(bc.all_strings().into_iter().map(str::to_owned).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua5x_chunk_is_reported_as_lua_not_luajit() {
        match detect_dump_version(b"\x1bLua\x54rest") {
            Err(LjLoaderError::ParseError(m)) => assert!(m.contains("rustre-loader-lua")),
            other => panic!("expected Lua ParseError, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_bc_version_is_named() {
        match detect_dump_version(b"\x1bLJ\x09\x02") {
            Err(LjLoaderError::UnsupportedVersion(9)) => {}
            other => panic!("expected UnsupportedVersion(9), got {other:?}"),
        }
    }

    #[test]
    fn known_versions_pass_the_gate() {
        assert_eq!(detect_dump_version(b"\x1bLJ\x01\x02").unwrap(), LjVersion::Lj20);
        assert_eq!(detect_dump_version(b"\x1bLJ\x02\x02").unwrap(), LjVersion::Lj21);
    }

    #[test]
    fn magic_and_truncation_are_distinguished() {
        assert!(matches!(
            detect_dump_version(b"MZ\x00\x00"),
            Err(LjLoaderError::InvalidMagic)
        ));
        assert!(matches!(
            detect_dump_version(b"\x1bLJ"),
            Err(LjLoaderError::TruncatedData)
        ));
    }

    #[test]
    fn empty_dump_yields_an_error_not_an_invented_proto() {
        // Valid header (stripped), no prototypes at all.
        let data = b"\x1bLJ\x02\x02";
        assert!(LjProto::from_dump_bytes(data).is_err());
        assert_eq!(all_strings_from_dump_bytes(data).unwrap(), Vec::<String>::new());
    }
}
