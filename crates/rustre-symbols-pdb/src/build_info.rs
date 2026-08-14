//! `build_info` — build information records (`S_BUILDINFO` / `LF_BUILDINFO`).
//!
//! The build-info symbol records store the compiler/linker command line,
//! source file paths and the `PDB` path that was current at build time.
//! They are found in each module's symbol stream.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::stream_reader::StreamReader;

// ── BuildInfo ─────────────────────────────────────────────────────────────────

/// Metadata about the compiler/linker invocation that produced a module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Directory from which the compiler was invoked.
    pub current_directory: Option<String>,
    /// Compiler or linker tool path.
    pub build_tool: Option<String>,
    /// Primary source file for this translation unit.
    pub source_file: Option<String>,
    /// The `PDB` file path recorded at build time.
    pub pdb_file: Option<String>,
    /// The full compiler command-line arguments.
    pub command_arguments: Option<String>,
}

impl BuildInfo {
    /// True when at least one field has been populated.
    #[must_use]
    pub const fn is_populated(&self) -> bool {
        self.current_directory.is_some()
            || self.build_tool.is_some()
            || self.source_file.is_some()
            || self.pdb_file.is_some()
            || self.command_arguments.is_some()
    }

    /// Return the source file name (file stem only, without directory).
    #[must_use]
    pub fn source_file_name(&self) -> Option<&str> {
        self.source_file
            .as_deref()
            .map(|p| p.rfind(['/', '\\']).map_or(p, |i| &p[i + 1..]))
    }

    /// Return the compiler name (last path component of `build_tool`).
    #[must_use]
    pub fn compiler_name(&self) -> Option<&str> {
        self.build_tool
            .as_deref()
            .map(|p| p.rfind(['/', '\\']).map_or(p, |i| &p[i + 1..]))
    }
}

// ── Symbol record type codes ──────────────────────────────────────────────────

const S_BUILDINFO: u16 = 0x114C;
const S_COMPILE3: u16 = 0x113C;
const S_ENVBLOCK: u16 = 0x113D;

// ── parse_build_info ──────────────────────────────────────────────────────────

/// Parse all build-info records from a raw module symbol stream.
///
/// Looks for `S_BUILDINFO`, `S_COMPILE3`, and `S_ENVBLOCK` records.
///
/// # Errors
/// Returns an error if parsing/reading fails.
pub fn parse_build_info(module_stream: &[u8]) -> Result<Vec<BuildInfo>> {
    let mut infos: Vec<BuildInfo> = Vec::new();
    let mut rdr = StreamReader::new(module_stream);

    while rdr.remaining() >= 4 {
        let start = rdr.pos();
        let length = rdr.read_u16()? as usize;
        if length < 2 {
            break;
        }
        let rec_type = rdr.read_u16()?;
        let payload_end = start + 2 + length;

        match rec_type {
            S_BUILDINFO => {
                // S_BUILDINFO payload: id(4) — a type index into the IPI stream.
                // The actual strings are in the IPI LF_BUILDINFO record.
                // Since we don't have a full IPI parser here we just note the record.
                if rdr.remaining() >= 4 {
                    let _id = rdr.read_u32()?;
                }
                infos.push(BuildInfo::default());
            }
            S_COMPILE3 => {
                // S_COMPILE3 fixed header (18 bytes): flags(4) followed by seven
                // u16 fields — machine, then the front-end and back-end version
                // quadruple — before the NUL-terminated compiler version string.
                // flags(4) + machine(2) + ver_fe_major(2) + ver_fe_minor(2)
                // + ver_fe_build(2) + ver_major(2) + ver_minor(2) + ver_build(2)
                // + version_string(nul)
                if rdr.remaining() >= 18 {
                    let _flags = rdr.read_u32()?;
                    let _machine = rdr.read_u16()?;
                    let _ver_fe_major = rdr.read_u16()?;
                    let _ver_fe_minor = rdr.read_u16()?;
                    let _ver_fe_build = rdr.read_u16()?;
                    let _ver_major = rdr.read_u16()?;
                    let _ver_minor = rdr.read_u16()?;
                    let _ver_build = rdr.read_u16()?;
                    let version_string = rdr.read_cstring().unwrap_or_default();
                    infos.push(BuildInfo {
                        build_tool: Some(version_string),
                        ..Default::default()
                    });
                }
            }
            S_ENVBLOCK
                // S_ENVBLOCK: flags(1) then alternating NUL-terminated key / value pairs.
                // Keys of interest: "cwd", "cl", "src", "pdb", "cmd".
                if rdr.remaining() >= 1 => {
                    let _flags = rdr.read_u8()?;
                    let mut info = BuildInfo::default();
                    loop {
                        let key = rdr.read_cstring().unwrap_or_default();
                        if key.is_empty() {
                            break;
                        }
                        let value = rdr.read_cstring().unwrap_or_default();
                        match key.to_lowercase().as_str() {
                            "cwd" => info.current_directory = Some(value),
                            "cl" | "link" => info.build_tool = Some(value),
                            "src" => info.source_file = Some(value),
                            "pdb" => info.pdb_file = Some(value),
                            "cmd" => info.command_arguments = Some(value),
                            _ => {}
                        }
                        if rdr.pos() >= payload_end {
                            break;
                        }
                    }
                    if info.is_populated() {
                        infos.push(info);
                    }
                }
            _ => {}
        }

        // Advance to next 4-byte aligned record.
        let aligned = (2 + length + 3) & !3;
        rdr.seek(start + aligned);
    }

    Ok(infos)
}

// ── CompilerInfo ──────────────────────────────────────────────────────────────

/// Compact summary of compiler/linker info for one module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    /// Name of the module this info belongs to.
    pub module_name: String,
    /// Compiler version string, if recorded.
    pub compiler: Option<String>,
    /// Primary source file, if recorded.
    pub source_file: Option<String>,
    /// Build command line, if recorded.
    pub command_line: Option<String>,
}

impl CompilerInfo {
    /// Build from a `BuildInfo` and a module name.
    #[must_use]
    pub fn from_build_info(module_name: impl Into<String>, bi: &BuildInfo) -> Self {
        Self {
            module_name: module_name.into(),
            compiler: bi.build_tool.clone(),
            source_file: bi.source_file.clone(),
            command_line: bi.command_arguments.clone(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_record(rec_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&rec_type.to_le_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn make_compile3_payload(ver: &str) -> Vec<u8> {
        let mut p = vec![0u8; 18]; // flags(4) + 7×u16
        p.extend_from_slice(ver.as_bytes());
        p.push(0);
        p
    }

    fn make_envblock_payload(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut p = vec![0u8]; // flags
        for (k, v) in pairs {
            p.extend_from_slice(k.as_bytes());
            p.push(0);
            p.extend_from_slice(v.as_bytes());
            p.push(0);
        }
        p.push(0); // terminating empty key
        p
    }

    #[test]
    fn test_parse_compile3() {
        let stream = frame_record(S_COMPILE3, &make_compile3_payload("MSVC 19.29"));
        let infos = parse_build_info(&stream).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].build_tool, Some("MSVC 19.29".into()));
    }

    #[test]
    fn test_parse_envblock_cwd_src() {
        let pairs = [("cwd", "C:\\src"), ("src", "main.cpp"), ("pdb", "app.pdb")];
        let stream = frame_record(S_ENVBLOCK, &make_envblock_payload(&pairs));
        let infos = parse_build_info(&stream).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].current_directory, Some("C:\\src".into()));
        assert_eq!(infos[0].source_file, Some("main.cpp".into()));
        assert_eq!(infos[0].pdb_file, Some("app.pdb".into()));
    }

    #[test]
    fn test_build_info_is_populated() {
        let mut b = BuildInfo::default();
        assert!(!b.is_populated());
        b.source_file = Some("foo.c".into());
        assert!(b.is_populated());
    }

    #[test]
    fn test_source_file_name() {
        let b = BuildInfo {
            source_file: Some("C:\\projects\\app\\main.cpp".into()),
            ..Default::default()
        };
        assert_eq!(b.source_file_name(), Some("main.cpp"));
    }

    #[test]
    fn test_compiler_name() {
        let b = BuildInfo {
            build_tool: Some("C:\\Program Files\\MSVC\\cl.exe".into()),
            ..Default::default()
        };
        assert_eq!(b.compiler_name(), Some("cl.exe"));
    }

    #[test]
    fn test_empty_stream() {
        let infos = parse_build_info(&[]).unwrap();
        assert!(infos.is_empty());
    }

    #[test]
    fn test_compiler_info_from_build_info() {
        let bi = BuildInfo {
            build_tool: Some("cl.exe".into()),
            source_file: Some("main.c".into()),
            ..Default::default()
        };
        let ci = CompilerInfo::from_build_info("module", &bi);
        assert_eq!(ci.module_name, "module");
        assert_eq!(ci.compiler, Some("cl.exe".into()));
    }

    #[test]
    fn test_parse_buildinfo_record() {
        let p = vec![0u8; 4]; // id = 0
        let stream = frame_record(S_BUILDINFO, &p);
        let infos = parse_build_info(&stream).unwrap();
        // Should produce one (default) BuildInfo entry.
        assert_eq!(infos.len(), 1);
    }
}
