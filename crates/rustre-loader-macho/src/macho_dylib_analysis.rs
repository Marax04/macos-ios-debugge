//! `macho_dylib_analysis` — Mach-O dynamic-library dependency analysis.
//!
//! Provides [`MachoDylibAnalysis`] which parses `LC_LOAD_DYLIB`,
//! `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, binding opcodes (two-level
//! namespace) and lazy/weak bindings.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from [`MachoDylibAnalysis`].
#[derive(Debug, Error)]
pub enum DylibAnalysisError {
    /// Not a recognised Mach-O file.
    #[error("not a Mach-O file: bad magic {0:#010x}")]
    NotMachO(u32),
    /// Buffer too short.
    #[error("buffer too short: {0} bytes")]
    TooShort(usize),
    /// A load command was malformed.
    #[error("malformed load command at offset {0}")]
    BadLoadCommand(usize),
    /// String table offset out of range.
    #[error("string offset {0} out of range")]
    BadStringOffset(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// Version types
// ─────────────────────────────────────────────────────────────────────────────

/// Packed Mach-O `X.Y.Z` version (stored as `(X << 16) | (Y << 8) | Z`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DylibVersion {
    pub major: u16,
    pub minor: u8,
    pub patch: u8,
}

impl DylibVersion {
    /// Decode from the raw `uint32_t` stored in `LC_LOAD_DYLIB`.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            major: (raw >> 16) as u16,
            minor: ((raw >> 8) & 0xFF) as u8,
            patch: (raw & 0xFF) as u8,
        }
    }
    /// Encode back to the raw `uint32_t` form.
    #[must_use]
    pub fn to_raw(self) -> u32 {
        (u32::from(self.major) << 16) | (u32::from(self.minor) << 8) | u32::from(self.patch)
    }
}

impl fmt::Display for DylibVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The `compatibility_version` field of an `LC_LOAD_DYLIB` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylibCompatVersion(pub DylibVersion);

/// The `current_version` field of an `LC_LOAD_DYLIB` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylibCurrentVersion(pub DylibVersion);

// ─────────────────────────────────────────────────────────────────────────────
// DylibDependency
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of dynamic-library dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DylibKind {
    /// Regular `LC_LOAD_DYLIB` — must be present at launch.
    Regular,
    /// `LC_LOAD_WEAK_DYLIB` — absence is tolerated at launch.
    Weak,
    /// `LC_REEXPORT_DYLIB` — symbols are re-exported to callers.
    Reexport,
    /// `LC_LAZY_LOAD_DYLIB` — loaded on first use.
    Lazy,
    /// `LC_LOAD_UPWARD_DYLIB` — for umbrella frameworks.
    Upward,
}

impl fmt::Display for DylibKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::Weak => write!(f, "weak"),
            Self::Reexport => write!(f, "reexport"),
            Self::Lazy => write!(f, "lazy"),
            Self::Upward => write!(f, "upward"),
        }
    }
}

/// A single dynamic-library dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylibDependency {
    /// Install name (e.g. `/usr/lib/libSystem.B.dylib`).
    pub name: String,
    /// Dependency kind.
    pub kind: DylibKind,
    /// Compatibility version.
    pub compat_version: DylibCompatVersion,
    /// Current version of the dylib.
    pub current_version: DylibCurrentVersion,
    /// Timestamp field from the load command.
    pub timestamp: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Two-level namespace
// ─────────────────────────────────────────────────────────────────────────────

/// Two-level namespace: each symbol bind records the ordinal of the source
/// dylib so the dynamic linker need not search all libraries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoLevelNamespace {
    /// `true` if `MH_TWOLEVEL` flag (0x80) is set in the Mach-O header.
    pub enabled: bool,
    /// Ordinal→dylib-name mapping derived from the dependency list.
    pub ordinal_map: HashMap<u8, String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Binding opcodes
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded binding opcode from the `LC_DYLD_INFO` bind stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingOpcode {
    /// Opcode byte (high nibble).
    pub opcode: u8,
    /// Immediate value (low nibble).
    pub immediate: u8,
    /// Optional string argument (symbol name for `BIND_OPCODE_SET_SYMBOL`).
    pub symbol: Option<String>,
    /// Dylib ordinal (for `BIND_OPCODE_SET_DYLIB_ORDINAL`).
    pub dylib_ordinal: Option<u8>,
    /// Bind type (1=pointer, 2=text abs, 3=text pcrel32).
    pub bind_type: Option<u8>,
    /// Address being bound.
    pub address: Option<u64>,
}

/// Decode a sequence of BIND opcodes from `stream`, returning up to
/// `max_entries` [`BindingOpcode`]s.
#[must_use] 
pub fn decode_bind_opcodes(stream: &[u8], max_entries: usize) -> Vec<BindingOpcode> {
    let mut result = Vec::new();
    let mut i = 0;
    let mut current_sym: Option<String> = None;
    let mut current_ordinal: Option<u8> = None;
    let mut current_type: Option<u8> = None;
    let current_addr: Option<u64> = None;

    while i < stream.len() && result.len() < max_entries {
        let byte = stream[i];
        let opcode = byte & 0xF0;
        let imm = byte & 0x0F;
        i += 1;

        let entry = match opcode {
            0x00 => break, // BIND_OPCODE_DONE
            0x10 => {
                // SET_DYLIB_ORDINAL_IMM
                current_ordinal = Some(imm);
                BindingOpcode {
                    opcode,
                    immediate: imm,
                    symbol: current_sym.clone(),
                    dylib_ordinal: Some(imm),
                    bind_type: current_type,
                    address: current_addr,
                }
            }
            0x20 => {
                // SET_DYLIB_ORDINAL_ULEB
                current_ordinal = Some(imm);
                BindingOpcode {
                    opcode,
                    immediate: imm,
                    symbol: current_sym.clone(),
                    dylib_ordinal: Some(imm),
                    bind_type: current_type,
                    address: current_addr,
                }
            }
            0x40 => {
                // SET_SYMBOL_TRAILING_FLAGS_IMM
                // Read NUL-terminated string
                let start = i;
                while i < stream.len() && stream[i] != 0 {
                    i += 1;
                }
                let sym = String::from_utf8_lossy(&stream[start..i]).to_string();
                if i < stream.len() {
                    i += 1;
                } // skip NUL
                current_sym = Some(sym.clone());
                BindingOpcode {
                    opcode,
                    immediate: imm,
                    symbol: Some(sym),
                    dylib_ordinal: current_ordinal,
                    bind_type: current_type,
                    address: current_addr,
                }
            }
            0x50 => {
                // SET_TYPE_IMM
                current_type = Some(imm);
                BindingOpcode {
                    opcode,
                    immediate: imm,
                    symbol: current_sym.clone(),
                    dylib_ordinal: current_ordinal,
                    bind_type: Some(imm),
                    address: current_addr,
                }
            }
            0x90 => {
                // DO_BIND
                BindingOpcode {
                    opcode,
                    immediate: imm,
                    symbol: current_sym.clone(),
                    dylib_ordinal: current_ordinal,
                    bind_type: current_type,
                    address: current_addr,
                }
            }
            _ => BindingOpcode {
                opcode,
                immediate: imm,
                symbol: current_sym.clone(),
                dylib_ordinal: current_ordinal,
                bind_type: current_type,
                address: current_addr,
            },
        };
        result.push(entry);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// WeakBinding / LazyBinding
// ─────────────────────────────────────────────────────────────────────────────

/// A single weak-binding entry (from the `weak_bind_off` stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakBinding {
    /// Symbol name.
    pub symbol: String,
    /// Virtual address of the fixup site.
    pub address: u64,
    /// Bind type.
    pub bind_type: u8,
    /// Non-weak definition flag.
    pub non_weak_definition: bool,
}

/// A single lazy-binding entry (from the `lazy_bind_off` stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazyBinding {
    /// Symbol name.
    pub symbol: String,
    /// Dylib ordinal.
    pub dylib_ordinal: u8,
    /// Virtual address of the stub pointer.
    pub address: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoDylibAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Complete dylib analysis result for a Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoDylibAnalysis {
    /// All dynamic library dependencies.
    pub dependencies: Vec<DylibDependency>,
    /// Two-level namespace status.
    pub two_level_ns: TwoLevelNamespace,
    /// Decoded regular binding opcodes (up to 256).
    pub bind_opcodes: Vec<BindingOpcode>,
    /// Weak bindings.
    pub weak_bindings: Vec<WeakBinding>,
    /// Lazy bindings.
    pub lazy_bindings: Vec<LazyBinding>,
    /// Whether the binary itself is a dylib.
    pub is_dylib: bool,
    /// Install name of this binary (if it is a dylib).
    pub own_install_name: Option<String>,
}

impl MachoDylibAnalysis {
    /// Analyse the Mach-O binary in `data`.
    ///
    /// # Errors
    /// Returns [`DylibAnalysisError`] if the data is not a valid Mach-O.
    pub fn analyse(data: &[u8]) -> Result<Self, DylibAnalysisError> {
        if data.len() < 28 {
            return Err(DylibAnalysisError::TooShort(data.len()));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let (is64, swap) = match magic {
            0xFEED_FACE => (false, false),
            0xCEFA_EDFE => (false, true),
            0xFEED_FACF => (true, false),
            0xCFFA_EDFE => (true, true),
            _ => return Err(DylibAnalysisError::NotMachO(magic)),
        };

        let read32 = |off: usize| -> u32 {
            if off + 4 > data.len() {
                return 0;
            }
            let raw = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or_default());
            if swap { raw.swap_bytes() } else { raw }
        };
        let read64 = |off: usize| -> u64 {
            if off + 8 > data.len() {
                return 0;
            }
            let raw = u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or_default());
            if swap { raw.swap_bytes() } else { raw }
        };
        let _ = read64;

        let mh_filetype = read32(12);
        let ncmds = read32(16) as usize;
        let mh_flags = read32(24);

        let is_dylib = mh_filetype == 6 || mh_filetype == 8; // MH_DYLIB or MH_DYLIB_STUB
        let two_level = mh_flags & 0x80 != 0;

        let lc_base: usize = if is64 { 32 } else { 28 };
        let mut offset = lc_base;
        let mut dependencies: Vec<DylibDependency> = Vec::new();
        let mut own_install_name: Option<String> = None;
        let mut bind_off: Option<usize> = None;
        let mut bind_sz: Option<usize> = None;
        let mut weak_bind_off: Option<usize> = None;
        let mut weak_bind_sz: Option<usize> = None;
        let mut lazy_bind_off: Option<usize> = None;
        let mut lazy_bind_sz: Option<usize> = None;

        for _ in 0..ncmds {
            if offset + 8 > data.len() {
                break;
            }
            let cmd = read32(offset);
            let cmdsize = read32(offset + 4) as usize;
            if cmdsize < 8 || offset + cmdsize > data.len() {
                return Err(DylibAnalysisError::BadLoadCommand(offset));
            }

            match cmd {
                // LC_LOAD_DYLIB = 0xC
                // LC_LOAD_WEAK_DYLIB = 0x18
                // LC_REEXPORT_DYLIB = 0x2000001F
                // LC_LAZY_LOAD_DYLIB = 0x20
                // LC_LOAD_UPWARD_DYLIB = 0x23
                0x0C | 0x18 | 0x2000_001F | 0x20 | 0x23 => {
                    if offset + 24 > data.len() {
                        offset += cmdsize;
                        continue;
                    }
                    let name_off = read32(offset + 8) as usize;
                    let timestamp = read32(offset + 12);
                    let cur_ver_raw = read32(offset + 16);
                    let compat_raw = read32(offset + 20);
                    let name_abs = offset + name_off;
                    let name = read_cstring(data, name_abs);
                    let kind = match cmd {
                        0x18 => DylibKind::Weak,
                        0x2000_001F => DylibKind::Reexport,
                        0x20 => DylibKind::Lazy,
                        0x23 => DylibKind::Upward,
                        _ => DylibKind::Regular,
                    };
                    dependencies.push(DylibDependency {
                        name,
                        kind,
                        compat_version: DylibCompatVersion(DylibVersion::from_raw(compat_raw)),
                        current_version: DylibCurrentVersion(DylibVersion::from_raw(cur_ver_raw)),
                        timestamp,
                    });
                }
                // LC_ID_DYLIB = 0xD
                0x0D => {
                    if offset + 24 > data.len() {
                        offset += cmdsize;
                        continue;
                    }
                    let name_off = read32(offset + 8) as usize;
                    let name_abs = offset + name_off;
                    own_install_name = Some(read_cstring(data, name_abs));
                }
                // LC_DYLD_INFO or LC_DYLD_INFO_ONLY = 0x22 / 0x8000_0022
                0x22 | 0x8000_0022 => {
                    if offset + 48 > data.len() {
                        offset += cmdsize;
                        continue;
                    }
                    bind_off = Some(read32(offset + 16) as usize);
                    bind_sz = Some(read32(offset + 20) as usize);
                    weak_bind_off = Some(read32(offset + 24) as usize);
                    weak_bind_sz = Some(read32(offset + 28) as usize);
                    lazy_bind_off = Some(read32(offset + 32) as usize);
                    lazy_bind_sz = Some(read32(offset + 36) as usize);
                }
                _ => {}
            }
            offset += cmdsize;
        }

        // Decode bind opcodes
        let bind_opcodes = if let (Some(off), Some(sz)) = (bind_off, bind_sz) {
            let end = (off + sz).min(data.len());
            if off < data.len() {
                decode_bind_opcodes(&data[off..end], 256)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let weak_bindings = if let (Some(off), Some(sz)) = (weak_bind_off, weak_bind_sz) {
            let end = (off + sz).min(data.len());
            if off < data.len() {
                decode_weak_bindings(&data[off..end])
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let lazy_bindings = if let (Some(off), Some(sz)) = (lazy_bind_off, lazy_bind_sz) {
            let end = (off + sz).min(data.len());
            if off < data.len() {
                decode_lazy_bindings(&data[off..end])
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // Build ordinal map
        let mut ordinal_map: HashMap<u8, String> = HashMap::new();
        for (i, dep) in dependencies.iter().enumerate() {
            ordinal_map.insert((i + 1) as u8, dep.name.clone());
        }

        let two_level_ns = TwoLevelNamespace {
            enabled: two_level,
            ordinal_map,
        };

        Ok(Self {
            dependencies,
            two_level_ns,
            bind_opcodes,
            weak_bindings,
            lazy_bindings,
            is_dylib,
            own_install_name,
        })
    }

    /// Returns all regular dependencies.
    #[must_use]
    pub fn regular_deps(&self) -> Vec<&DylibDependency> {
        self.dependencies
            .iter()
            .filter(|d| d.kind == DylibKind::Regular)
            .collect()
    }

    /// Returns all weak dependencies.
    #[must_use]
    pub fn weak_deps(&self) -> Vec<&DylibDependency> {
        self.dependencies
            .iter()
            .filter(|d| d.kind == DylibKind::Weak)
            .collect()
    }

    /// Returns all re-export dependencies.
    #[must_use]
    pub fn reexport_deps(&self) -> Vec<&DylibDependency> {
        self.dependencies
            .iter()
            .filter(|d| d.kind == DylibKind::Reexport)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_cstring(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len() - off, |p| p);
    String::from_utf8_lossy(&data[off..off + end]).to_string()
}

fn decode_weak_bindings(stream: &[u8]) -> Vec<WeakBinding> {
    let opcodes = decode_bind_opcodes(stream, 256);
    opcodes
        .into_iter()
        .filter_map(|op| {
            op.symbol.map(|sym| WeakBinding {
                symbol: sym,
                address: op.address.unwrap_or(0),
                bind_type: op.bind_type.unwrap_or(1),
                non_weak_definition: op.opcode == 0xB0,
            })
        })
        .collect()
}

fn decode_lazy_bindings(stream: &[u8]) -> Vec<LazyBinding> {
    let opcodes = decode_bind_opcodes(stream, 256);
    opcodes
        .into_iter()
        .filter_map(|op| {
            op.symbol.map(|sym| LazyBinding {
                symbol: sym,
                dylib_ordinal: op.dylib_ordinal.unwrap_or(0),
                address: op.address.unwrap_or(0),
            })
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mach-O builder ───────────────────────────────────────────────────────

    struct MachOBuilder {
        data: Vec<u8>,
        ncmds_off: usize,
        sizeofcmds_off: usize,
        lc_data: Vec<u8>,
    }

    impl MachOBuilder {
        fn new_64(filetype: u32, flags: u32) -> Self {
            let mut data = vec![0u8; 32];
            // magic
            data[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
            // cputype x86_64
            data[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
            // cpusubtype
            data[8..12].copy_from_slice(&3u32.to_le_bytes());
            // filetype
            data[12..16].copy_from_slice(&filetype.to_le_bytes());
            // ncmds — placeholder at 16
            // sizeofcmds — placeholder at 20
            data[24..28].copy_from_slice(&flags.to_le_bytes());
            Self {
                ncmds_off: 16,
                sizeofcmds_off: 20,
                data,
                lc_data: Vec::new(),
            }
        }

        fn add_load_dylib(&mut self, name: &str, kind: u32, compat: u32, current: u32) {
            let name_off: u32 = 24; // offset within load command to name
            let name_bytes = name.as_bytes();
            // cmdsize must be 4-byte aligned
            let raw_size = 24 + name_bytes.len() + 1;
            let cmdsize = (raw_size + 3) & !3;
            let mut lc = vec![0u8; cmdsize];
            lc[0..4].copy_from_slice(&kind.to_le_bytes());
            lc[4..8].copy_from_slice(&(cmdsize as u32).to_le_bytes());
            lc[8..12].copy_from_slice(&name_off.to_le_bytes());
            lc[12..16].copy_from_slice(&1u32.to_le_bytes()); // timestamp
            lc[16..20].copy_from_slice(&current.to_le_bytes());
            lc[20..24].copy_from_slice(&compat.to_le_bytes());
            lc[24..24 + name_bytes.len()].copy_from_slice(name_bytes);
            self.lc_data.extend_from_slice(&lc);
        }

        fn build(mut self) -> Vec<u8> {
            let ncmds = count_lcs(&self.lc_data);
            let sizeofcmds = self.lc_data.len();
            let n = ncmds as u32;
            let s = sizeofcmds as u32;
            self.data[self.ncmds_off..self.ncmds_off + 4].copy_from_slice(&n.to_le_bytes());
            self.data[self.sizeofcmds_off..self.sizeofcmds_off + 4]
                .copy_from_slice(&s.to_le_bytes());
            self.data.extend_from_slice(&self.lc_data);
            self.data
        }
    }

    fn count_lcs(lc_data: &[u8]) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i + 8 <= lc_data.len() {
            let sz =
                u32::from_le_bytes(lc_data[i + 4..i + 8].try_into().unwrap_or_default()) as usize;
            if sz == 0 {
                break;
            }
            count += 1;
            i += sz;
        }
        count
    }

    // ── Error paths ──────────────────────────────────────────────────────────

    #[test]
    fn error_too_short() {
        let err = MachoDylibAnalysis::analyse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, DylibAnalysisError::TooShort(_)));
    }

    #[test]
    fn error_not_macho() {
        let mut data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        data.extend(std::iter::repeat_n(0u8, 28));
        let err = MachoDylibAnalysis::analyse(&data).unwrap_err();
        assert!(matches!(err, DylibAnalysisError::NotMachO(_)));
    }

    // ── Basic parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_no_load_commands() {
        let b = MachOBuilder::new_64(2, 0); // MH_EXECUTE
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert!(analysis.dependencies.is_empty());
    }

    #[test]
    fn parse_single_load_dylib() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/usr/lib/libSystem.B.dylib", 0x0C, 0x0001_0000, 0x0001_0000);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies.len(), 1);
        assert_eq!(analysis.dependencies[0].kind, DylibKind::Regular);
    }

    #[test]
    fn dependency_name_correct() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/usr/lib/libSystem.B.dylib", 0x0C, 0x0001_0000, 0x0001_0000);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies[0].name, "/usr/lib/libSystem.B.dylib");
    }

    #[test]
    fn weak_dylib_kind() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/opt/lib/libfoo.dylib", 0x18, 0x0001_0000, 0x0001_0000);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies[0].kind, DylibKind::Weak);
    }

    #[test]
    fn reexport_dylib_kind() {
        let mut b = MachOBuilder::new_64(6, 0); // MH_DYLIB
        b.add_load_dylib(
            "/usr/lib/libCore.dylib",
            0x2000_001F,
            0x0001_0000,
            0x0001_0000,
        );
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies[0].kind, DylibKind::Reexport);
    }

    // ── DylibVersion ─────────────────────────────────────────────────────────

    #[test]
    fn dylib_version_from_raw() {
        let v = DylibVersion::from_raw(0x0001_0203);
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn dylib_version_round_trip() {
        let v = DylibVersion {
            major: 5,
            minor: 3,
            patch: 1,
        };
        assert_eq!(DylibVersion::from_raw(v.to_raw()), v);
    }

    #[test]
    fn dylib_version_display() {
        let v = DylibVersion {
            major: 1,
            minor: 2,
            patch: 3,
        };
        assert_eq!(format!("{v}"), "1.2.3");
    }

    #[test]
    fn dylib_version_zero() {
        let v = DylibVersion::from_raw(0);
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    // ── is_dylib flag ────────────────────────────────────────────────────────

    #[test]
    fn is_dylib_true_for_mh_dylib() {
        let b = MachOBuilder::new_64(6, 0); // MH_DYLIB = 6
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert!(analysis.is_dylib);
    }

    #[test]
    fn is_dylib_false_for_executable() {
        let b = MachOBuilder::new_64(2, 0); // MH_EXECUTE = 2
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert!(!analysis.is_dylib);
    }

    // ── Two-level namespace ──────────────────────────────────────────────────

    #[test]
    fn two_level_ns_enabled_when_flag_set() {
        let b = MachOBuilder::new_64(2, 0x80); // MH_TWOLEVEL flag
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert!(analysis.two_level_ns.enabled);
    }

    #[test]
    fn two_level_ns_disabled_when_flag_absent() {
        let b = MachOBuilder::new_64(2, 0);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert!(!analysis.two_level_ns.enabled);
    }

    #[test]
    fn ordinal_map_populated() {
        let mut b = MachOBuilder::new_64(2, 0x80);
        b.add_load_dylib("/usr/lib/libSystem.B.dylib", 0x0C, 0x0001_0000, 0x0001_0000);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(
            analysis
                .two_level_ns
                .ordinal_map
                .get(&1)
                .map(std::string::String::as_str),
            Some("/usr/lib/libSystem.B.dylib")
        );
    }

    // ── regular_deps / weak_deps / reexport_deps ─────────────────────────────

    #[test]
    fn regular_deps_filter() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/a", 0x0C, 0, 0);
        b.add_load_dylib("/b", 0x18, 0, 0);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.regular_deps().len(), 1);
    }

    #[test]
    fn weak_deps_filter() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/a", 0x0C, 0, 0);
        b.add_load_dylib("/b", 0x18, 0, 0);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.weak_deps().len(), 1);
    }

    // ── Bind opcodes ─────────────────────────────────────────────────────────

    #[test]
    fn decode_bind_opcode_done_stops() {
        let stream = &[0x00u8]; // BIND_OPCODE_DONE
        let ops = decode_bind_opcodes(stream, 100);
        assert!(ops.is_empty());
    }

    #[test]
    fn decode_set_dylib_ordinal() {
        let stream = &[0x12u8, 0x00]; // SET_DYLIB_ORDINAL_IMM imm=2, then DONE
        let ops = decode_bind_opcodes(stream, 100);
        assert!(!ops.is_empty());
        assert_eq!(ops[0].dylib_ordinal, Some(2));
    }

    #[test]
    fn decode_set_type() {
        let stream = &[0x51u8, 0x00]; // SET_TYPE_IMM type=1, DONE
        let ops = decode_bind_opcodes(stream, 100);
        assert_eq!(ops[0].bind_type, Some(1));
    }

    #[test]
    fn decode_set_symbol() {
        let mut stream = vec![0x40u8]; // SET_SYMBOL_TRAILING_FLAGS_IMM
        stream.extend_from_slice(b"_printf");
        stream.push(0x00); // NUL
        stream.push(0x00); // DONE
        let ops = decode_bind_opcodes(&stream, 100);
        assert_eq!(ops[0].symbol.as_deref(), Some("_printf"));
    }

    // ── Serialisation ────────────────────────────────────────────────────────

    #[test]
    fn dylib_kind_serialises() {
        let j = serde_json::to_string(&DylibKind::Weak).unwrap();
        assert!(j.contains("Weak"));
    }

    #[test]
    fn dylib_dependency_round_trip() {
        let dep = DylibDependency {
            name: "/usr/lib/libfoo.dylib".into(),
            kind: DylibKind::Regular,
            compat_version: DylibCompatVersion(DylibVersion {
                major: 1,
                minor: 0,
                patch: 0,
            }),
            current_version: DylibCurrentVersion(DylibVersion {
                major: 2,
                minor: 3,
                patch: 0,
            }),
            timestamp: 12345,
        };
        let j = serde_json::to_string(&dep).unwrap();
        let back: DylibDependency = serde_json::from_str(&j).unwrap();
        assert_eq!(back.name, dep.name);
    }

    // ── DylibKind Display ────────────────────────────────────────────────────

    #[test]
    fn dylib_kind_display_regular() {
        assert_eq!(format!("{}", DylibKind::Regular), "regular");
    }

    #[test]
    fn dylib_kind_display_weak() {
        assert_eq!(format!("{}", DylibKind::Weak), "weak");
    }

    #[test]
    fn dylib_kind_display_reexport() {
        assert_eq!(format!("{}", DylibKind::Reexport), "reexport");
    }

    // ── Multiple deps ────────────────────────────────────────────────────────

    #[test]
    fn multiple_load_dylib_commands() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/usr/lib/libSystem.B.dylib", 0x0C, 0, 0);
        b.add_load_dylib("/usr/lib/libc++.1.dylib", 0x0C, 0, 0);
        b.add_load_dylib("/opt/weak.dylib", 0x18, 0, 0);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies.len(), 3);
    }

    #[test]
    fn timestamp_stored() {
        let mut b = MachOBuilder::new_64(2, 0);
        b.add_load_dylib("/lib/x.dylib", 0x0C, 0, 0);
        let data = b.build();
        let analysis = MachoDylibAnalysis::analyse(&data).unwrap();
        assert_eq!(analysis.dependencies[0].timestamp, 1);
    }
}
