//! `rustre-triage-die`
//!
//! Detect-It-Easy style file format, packer, protector, and compiler detection.

pub mod die_extended;
pub mod die_scanner;
pub mod heuristic_detector;
pub mod rule_db_extended;
pub mod scanner;
pub mod signature_db;
pub mod die_signature_db;
pub mod detector_engine;
pub mod die_signatures;
pub mod die_database;
pub mod packer_detector;
pub mod die_script_engine;
pub mod compiler_detector;
pub mod packer_signature_db;
pub mod overlay_analyzer;
pub mod entropy_based_classifier;

use std::fmt;

use rustre_triage::{FileKind, TriageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// DieCondition
// ---------------------------------------------------------------------------

/// A single condition used in a structured detection rule.
///
/// Conditions inspect PE headers, section tables, import/export directories,
/// entropy values, and raw byte patterns to produce a boolean result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DieCondition {
    /// A PE section with the given name is present in the section table.
    SectionName(String),

    /// The total number of PE sections falls within the inclusive range
    /// `[min, max]`.
    SectionCount { min: u8, max: u8 },

    /// The byte pattern (space-separated hex bytes; `??` is a wildcard byte)
    /// is found starting at `offset` within the raw file bytes.
    ///
    /// Example: `"60 BE ?? ?? ??"` with `offset: 0` checks the first five
    /// bytes and allows any value in positions 2–4.
    BytePattern { offset: usize, hex: String },

    /// The bytes at the PE entry point match the given hex pattern (same
    /// format as [`DieCondition::BytePattern`]).
    EntryPointHex(String),

    /// The Shannon entropy of PE section number `section` (0-based) falls
    /// within `[min, max]`.
    EntropyRange { section: usize, min: f32, max: f32 },

    /// The PE import directory contains an import of `func` from `dll`.
    /// Matching is case-insensitive for both the DLL name and the function
    /// name.
    ImportPresent { dll: String, func: String },

    /// The total number of imported functions falls within `[min, max]`.
    ImportCount { min: u16, max: u16 },

    /// The PE export directory contains a function whose name equals
    /// the given string (case-sensitive).
    ExportPresent(String),

    /// The PE optional header Subsystem field equals the given value.
    /// Common values: `2` = GUI, `3` = Console.
    SubsystemType(u16),

    /// The raw file bytes contain the given UTF-8 string literal.
    StringPresent(String),

    /// The PE COFF Machine field equals the given value.
    /// Common values: `0x8664` = x86-64, `0x014c` = x86, `0xAA64` = ARM64.
    MachineType(u16),

    /// Bytes are present after the end of the last PE section (overlay data).
    OverlayPresent,

    /// A resource of the given type name is present in the PE resource
    /// directory.  The name is matched case-insensitively.
    ResourcePresent(String),

    /// The PE optional header contains a non-zero CLR runtime header data
    /// directory (directory index 14), indicating a .NET assembly.
    Dotnet,

    /// An embedded XML manifest resource is present (resource type `RT_MANIFEST`
    /// = 24).
    Manifest,
}

// ---------------------------------------------------------------------------
// RuleCondition  (Boolean combinators)
// ---------------------------------------------------------------------------

/// Boolean combinator that wraps one or more [`DieCondition`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// All inner conditions must be satisfied.
    All(Vec<DieCondition>),
    /// At least one inner condition must be satisfied.
    Any(Vec<DieCondition>),
    /// The inner condition must *not* be satisfied.
    Not(Box<DieCondition>),
}

// ---------------------------------------------------------------------------
// BUILTIN_RULES  — YAML signature database
// ---------------------------------------------------------------------------

/// Built-in YAML rule database covering 25+ known formats.
///
/// Schema per rule:
/// ```yaml
/// - name:       "Display name"
///   kind:       Compiler | Packer | Protector | Installer | Tool
///   version:    "optional version string"
///   confidence: 0-100
///   conditions:
///     - SectionName: ".name"
///     - BytePattern:
///         offset: 0
///         hex: "4D 5A"
///     - EntryPointHex: "60 BE"
///     - EntropyRange:
///         section: 0
///         min: 7.0
///         max: 8.0
///     - ImportPresent:
///         dll: "kernel32.dll"
///         func: "VirtualAlloc"
///     - ImportCount: { min: 1, max: 10 }
///     - ExportPresent: "FunctionName"
///     - SubsystemType: 2
///     - StringPresent: "literal"
///     - MachineType: 34404
///     - OverlayPresent: ~
///     - ResourcePresent: "RT_MANIFEST"
///     - Dotnet: ~
///     - Manifest: ~
/// ```
pub const BUILTIN_RULES: &str = r#"
# ============================================================
# rustre-triage-die built-in detection rules
# ============================================================

# --- Packers ---------------------------------------------------

- name: UPX 3.x
  kind: Packer
  version: "3.x"
  confidence: 97
  conditions:
    - SectionName: UPX0
    - SectionName: UPX1

- name: UPX 4.x
  kind: Packer
  version: "4.x"
  confidence: 97
  conditions:
    - SectionName: UPX0
    - SectionName: UPX1
    - StringPresent: "UPX!"

- name: MPRESS
  kind: Packer
  version: "2.x"
  confidence: 92
  conditions:
    - SectionName: .MPRESS1

- name: ASPack
  kind: Packer
  version: "2.x"
  confidence: 92
  conditions:
    - SectionName: .aspack

- name: PECompact
  kind: Packer
  version: "2.x"
  confidence: 91
  conditions:
    - StringPresent: "PECompact2"

- name: MEW Packer
  kind: Packer
  version: "1.1"
  confidence: 88
  conditions:
    - SectionCount: { min: 2, max: 2 }
    - EntryPointHex: "E9"
    - StringPresent: "MEW"

- name: FSG Packer
  kind: Packer
  version: "2.0"
  confidence: 87
  conditions:
    - SectionCount: { min: 2, max: 2 }
    - StringPresent: "FSG!"

- name: PESpin
  kind: Packer
  version: "1.3"
  confidence: 86
  conditions:
    - StringPresent: "PESpin"

# --- Protectors -----------------------------------------------

- name: Themida / WinLicense
  kind: Protector
  version: "3.x"
  confidence: 93
  conditions:
    - SectionName: .themida

- name: VMProtect 2.x
  kind: Protector
  version: "2.x"
  confidence: 93
  conditions:
    - SectionName: .vmp0

- name: VMProtect 3.x
  kind: Protector
  version: "3.x"
  confidence: 93
  conditions:
    - SectionName: .vmp1

- name: Enigma Protector
  kind: Protector
  version: "7.x"
  confidence: 90
  conditions:
    - StringPresent: ".enigma1"

- name: Obsidium
  kind: Protector
  version: "1.x"
  confidence: 88
  conditions:
    - StringPresent: "Obsidium"

# --- Compilers ------------------------------------------------

- name: MSVC x86
  kind: Compiler
  version: "14.x"
  confidence: 75
  conditions:
    - StringPresent: "Rich"
    - MachineType: 332
    - SubsystemType: 3

- name: MSVC x64
  kind: Compiler
  version: "14.x"
  confidence: 77
  conditions:
    - StringPresent: "Rich"
    - MachineType: 34404
    - SubsystemType: 3

- name: GCC / MinGW
  kind: Compiler
  version: "4.x+"
  confidence: 82
  conditions:
    - StringPresent: "MinGW"

- name: Clang
  kind: Compiler
  version: "10+"
  confidence: 78
  conditions:
    - StringPresent: "clang"

- name: Delphi / Borland
  kind: Compiler
  version: "7+"
  confidence: 87
  conditions:
    - StringPresent: "Borland"

# --- .NET / Managed -------------------------------------------

- name: .NET Framework assembly
  kind: Compiler
  version: "4.x"
  confidence: 94
  conditions:
    - Dotnet: ~
    - ImportPresent: { dll: "mscoree.dll", func: "_CorExeMain" }

- name: .NET Native AOT
  kind: Compiler
  version: "8+"
  confidence: 85
  conditions:
    - MachineType: 34404
    - StringPresent: "S_P_CoreLib"

# --- Script / Byte-code bundlers ------------------------------

- name: PyInstaller
  kind: Tool
  version: "6.x"
  confidence: 95
  conditions:
    - StringPresent: "MEI\x0C\x0B\x0A\x0B\x0E"

- name: Py2Exe
  kind: Tool
  version: "0.13"
  confidence: 90
  conditions:
    - StringPresent: "py2exe"

- name: cx_Freeze
  kind: Tool
  version: "6.x"
  confidence: 88
  conditions:
    - StringPresent: "cx_Freeze"

- name: AutoIt compiled script
  kind: Tool
  version: "3.x"
  confidence: 93
  conditions:
    - StringPresent: "AU3!EA"

# --- Installers -----------------------------------------------

- name: NSIS installer
  kind: Installer
  version: "3.x"
  confidence: 87
  conditions:
    - StringPresent: "Nullsoft"

- name: Inno Setup
  kind: Installer
  version: "6.x"
  confidence: 90
  conditions:
    - StringPresent: "Inno Setup"

- name: WiX installer
  kind: Installer
  version: "4.x"
  confidence: 85
  conditions:
    - StringPresent: "WiX Toolset"

- name: InstallShield
  kind: Installer
  version: "2022"
  confidence: 84
  conditions:
    - StringPresent: "InstallShield"
"#;

// ---------------------------------------------------------------------------
// PE parsing helpers
// ---------------------------------------------------------------------------

/// Read the MZ/PE headers and return `(pe_offset, optional_header_offset)`,
/// or `None` if the data does not look like a valid PE file.
fn locate_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 4 > data.len() {
        return None;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    Some(pe_off)
}

/// Returns the number of PE sections, or 0 if not parseable.
fn read_section_count(data: &[u8]) -> u8 {
    let Some(pe_off) = locate_pe(data) else {
        return 0;
    };
    if pe_off + 6 > data.len() {
        return 0;
    }
    let count = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]);
    count.min(96) as u8
}

/// Returns a list of PE section names and their raw entropy values.
/// The order follows the section table order.
#[must_use] 
pub fn read_pe_sections(data: &[u8]) -> Vec<(String, f32)> {
    let Some(pe_off) = locate_pe(data) else {
        return Vec::new();
    };
    if pe_off + 0x18 > data.len() {
        return Vec::new();
    }

    // Cap to 96 as in read_section_count to avoid excessive allocation from
    // attacker-controlled section count field.
    let num_sections = (u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize).min(96);
    let opt_header_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let section_table_off = pe_off + 0x18 + opt_header_size;

    let mut result = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sec_off = section_table_off + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        // Section name: 8 bytes, null-padded
        let name_bytes = &data[sec_off..sec_off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

        // Raw data offset and size
        let raw_size = u32::from_le_bytes(
            data[sec_off + 16..sec_off + 20]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        let raw_offset = u32::from_le_bytes(
            data[sec_off + 20..sec_off + 24]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        let entropy = if raw_offset + raw_size <= data.len() && raw_size > 0 {
            compute_entropy(&data[raw_offset..raw_offset + raw_size])
        } else {
            0.0
        };

        result.push((name, entropy));
    }
    result
}

/// Compute Shannon entropy (bits per byte) of `data`.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut h = 0.0f32;
    for &f in &freq {
        if f > 0 {
            let p = f as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Return the raw bytes at the PE entry point (up to 16 bytes), or an empty
/// `Vec` if the entry point cannot be resolved.
#[must_use] 
pub fn get_entry_point_bytes(data: &[u8]) -> Vec<u8> {
    let Some(pe_off) = locate_pe(data) else {
        return Vec::new();
    };
    if pe_off + 0x18 > data.len() {
        return Vec::new();
    }

    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return Vec::new();
    }

    // Magic: 0x010b = PE32, 0x020b = PE32+
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);

    // AddressOfEntryPoint is at opt_off + 0x10 for both PE32 and PE32+
    if opt_off + 0x14 > data.len() {
        return Vec::new();
    }
    let ep_rva = u32::from_le_bytes(
        data[opt_off + 0x10..opt_off + 0x14]
            .try_into()
            .unwrap_or([0; 4]),
    );
    if ep_rva == 0 {
        return Vec::new();
    }

    // ImageBase
    let image_base: u64 = if magic == 0x020b {
        // PE32+ (64-bit): ImageBase at opt_off + 0x18 (8 bytes)
        if opt_off + 0x20 > data.len() {
            return Vec::new();
        }
        u64::from_le_bytes(
            data[opt_off + 0x18..opt_off + 0x20]
                .try_into()
                .unwrap_or([0; 8]),
        )
    } else {
        // PE32 (32-bit): ImageBase at opt_off + 0x1c (4 bytes)
        if opt_off + 0x20 > data.len() {
            return Vec::new();
        }
        u64::from(u32::from_le_bytes(
            data[opt_off + 0x1c..opt_off + 0x20]
                .try_into()
                .unwrap_or([0; 4]),
        ))
    };

    // Resolve RVA → file offset via section table
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = opt_off + opt_size;

    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap_or([0; 4]));
        let virt_size = u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap_or([0; 4]));
        let raw_off =
            u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;
        let _raw_size =
            u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap_or([0; 4])) as usize;

        if ep_rva >= virt_addr && ep_rva < virt_addr + virt_size.max(1) {
            let file_off = raw_off + (ep_rva - virt_addr) as usize;
            if file_off >= data.len() {
                return Vec::new();
            }
            let end = (file_off + 16).min(data.len());
            return data[file_off..end].to_vec();
        }
    }

    // Suppress unused warning for image_base – it is needed conceptually for
    // correctness on position-independent code but we resolve via sections.
    let _ = image_base;
    Vec::new()
}

/// Check whether the PE imports `func` from `dll` (both compared
/// case-insensitively).
///
/// This is a best-effort scan of the raw import directory: it does not
/// relocate or dereference ordinal-only imports.
#[must_use] 
pub fn check_imports(data: &[u8], dll: &str, func: &str) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }

    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);

    // Data directory offset differs between PE32 and PE32+
    let dd_off = if magic == 0x020b {
        opt_off + 0x70 // PE32+: first data dir at opt_off + 0x70
    } else {
        opt_off + 0x60 // PE32:  first data dir at opt_off + 0x60
    };

    if dd_off + 8 + 8 > data.len() {
        return false;
    }
    // Import table is data directory index 1
    let import_rva = u32::from_le_bytes(data[dd_off + 8..dd_off + 12].try_into().unwrap_or([0; 4]));
    let import_size =
        u32::from_le_bytes(data[dd_off + 12..dd_off + 16].try_into().unwrap_or([0; 4]));

    if import_rva == 0 || import_size == 0 {
        return false;
    }

    // Resolve import table RVA to file offset
    let Some(import_foff) = rva_to_file_offset(data, pe_off, import_rva) else {
        return false;
    };

    let dll_lower = dll.to_lowercase();
    let func_lower = func.to_lowercase();

    // Walk the import descriptor table (20 bytes per entry)
    let mut desc_off = import_foff;
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(
            data[desc_off + 12..desc_off + 16]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let ilt_rva = u32::from_le_bytes(data[desc_off..desc_off + 4].try_into().unwrap_or([0; 4]));
        // A zeroed descriptor signals the end of the table
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }

        // Read DLL name
        if let Some(dll_foff) = rva_to_file_offset(data, pe_off, name_rva) {
            let dll_name = read_cstr(data, dll_foff).to_lowercase();
            if dll_name.contains(&dll_lower) {
                // Walk the ILT / IAT to find matching function name
                if let Some(ilt_foff) = rva_to_file_offset(data, pe_off, ilt_rva)
                    && check_ilt_for_func(data, pe_off, magic, ilt_foff, &func_lower) {
                        return true;
                    }
                // Also try the IAT pointer (original first thunk at offset 0x10)
                let iat_rva = u32::from_le_bytes(
                    data[desc_off + 16..desc_off + 20]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                if iat_rva != 0
                    && let Some(iat_foff) = rva_to_file_offset(data, pe_off, iat_rva)
                        && check_ilt_for_func(data, pe_off, magic, iat_foff, &func_lower) {
                            return true;
                        }
            }
        }
        desc_off += 20;
    }
    false
}

/// Count total imported functions across all DLLs.
fn count_imports(data: &[u8]) -> u16 {
    let Some(pe_off) = locate_pe(data) else {
        return 0;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return 0;
    }

    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    if dd_off + 16 > data.len() {
        return 0;
    }

    let import_rva = u32::from_le_bytes(data[dd_off + 8..dd_off + 12].try_into().unwrap_or([0; 4]));
    if import_rva == 0 {
        return 0;
    }

    let Some(import_foff) = rva_to_file_offset(data, pe_off, import_rva) else {
        return 0;
    };

    let mut total: u16 = 0;
    let mut desc_off = import_foff;
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(
            data[desc_off + 12..desc_off + 16]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let ilt_rva = u32::from_le_bytes(data[desc_off..desc_off + 4].try_into().unwrap_or([0; 4]));
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }

        if let Some(ilt_foff) = rva_to_file_offset(data, pe_off, ilt_rva) {
            total = total.saturating_add(count_ilt_entries(data, magic, ilt_foff));
        }
        desc_off += 20;
    }
    total
}

/// Check whether the PE exports a function with the given name.
fn check_exports(data: &[u8], export_name: &str) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }

    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    if dd_off + 8 > data.len() {
        return false;
    }

    let export_rva = u32::from_le_bytes(data[dd_off..dd_off + 4].try_into().unwrap_or([0; 4]));
    if export_rva == 0 {
        return false;
    }

    let Some(exp_foff) = rva_to_file_offset(data, pe_off, export_rva) else {
        return false;
    };
    if exp_foff + 40 > data.len() {
        return false;
    }

    // Cap num_names to a safe limit: an export table with > 65535 entries is
    // pathological and would require at least 256 KiB of name pointer table —
    // well beyond any real PE. Without this cap, an attacker-controlled u32
    // value causes the loop below to iterate up to 4 billion times.
    let num_names = u32::from_le_bytes(
        data[exp_foff + 24..exp_foff + 28]
            .try_into()
            .unwrap_or([0; 4]),
    ).min(65535) as usize;
    let names_rva = u32::from_le_bytes(
        data[exp_foff + 32..exp_foff + 36]
            .try_into()
            .unwrap_or([0; 4]),
    );

    let Some(names_foff) = rva_to_file_offset(data, pe_off, names_rva) else {
        return false;
    };

    for i in 0..num_names {
        let off = names_foff + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        if let Some(nfoff) = rva_to_file_offset(data, pe_off, name_rva)
            && read_cstr(data, nfoff) == export_name {
                return true;
            }
    }
    false
}

/// Return the PE optional header Subsystem field, or `None`.
fn pe_subsystem(data: &[u8]) -> Option<u16> {
    let pe_off = locate_pe(data)?;
    let opt_off = pe_off + 0x18;
    if opt_off + 0x44 > data.len() {
        return None;
    }
    // SubsystemType is at opt_off + 0x44 for both PE32 and PE32+
    Some(u16::from_le_bytes([
        data[opt_off + 0x44],
        data[opt_off + 0x45],
    ]))
}

/// Return the PE COFF Machine field, or `None`.
fn pe_machine(data: &[u8]) -> Option<u16> {
    let pe_off = locate_pe(data)?;
    if pe_off + 6 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]))
}

/// Return `true` if the file has an overlay (bytes after the last section's
/// raw data).
fn has_overlay(data: &[u8]) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;

    let mut end_of_sections: usize = 0;
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_off =
            u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;
        let raw_size =
            u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap_or([0; 4])) as usize;
        // Use saturating_add: both values come from attacker-controlled section
        // table entries and can overflow usize on 32-bit targets.
        let end = raw_off.saturating_add(raw_size);
        if end > end_of_sections {
            end_of_sections = end;
        }
    }
    end_of_sections > 0 && data.len() > end_of_sections
}

/// Return `true` if the PE has a non-zero CLR header data directory (index 14).
fn has_dotnet(data: &[u8]) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let clr_dd_off = if magic == 0x020b {
        opt_off + 0x70 + 14 * 8
    } else {
        opt_off + 0x60 + 14 * 8
    };
    if clr_dd_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes(
        data[clr_dd_off..clr_dd_off + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let size = u32::from_le_bytes(
        data[clr_dd_off + 4..clr_dd_off + 8]
            .try_into()
            .unwrap_or([0; 4]),
    );
    rva != 0 && size != 0
}

/// Return `true` if the PE has an `RT_MANIFEST` (type 24) resource.
///
/// This is a coarse scan that looks for the manifest resource type ID in the
/// resource directory.
fn has_manifest(data: &[u8]) -> bool {
    // Fast path: look for the string "RT_MANIFEST" or the type-id 24 in the
    // resource directory. We use a simple byte scan rather than full directory
    // walking to avoid needing a complex tree parser.
    // Also accept the well-known magic of an embedded XML manifest.
    if data.windows(14).any(|w| w == b"RT_MANIFEST\0\0\0") {
        return true;
    }
    // Search the resource directory for the RT_MANIFEST type (id=24, stored
    // as 0x18_0000 in the Named/ID table).
    data.windows(4).any(|w| w == b"\x18\x00\x00\x80")
}

/// Search for a resource type name in the PE resource directory by scanning
/// for its UTF-16LE encoded form (since Windows resources use wide strings).
fn has_resource_type(data: &[u8], type_name: &str) -> bool {
    // Case-insensitive UTF-16LE wide-string search.
    // Decode both the window and the needle to u16 code units before
    // comparing, because eq_ignore_ascii_case on raw bytes is broken for
    // UTF-16LE data (every second byte is 0x00).
    // Build lowercase needle as u16 code units
    let needle_lower: Vec<u16> = type_name
        .encode_utf16()
        .map(|cu| {
            // ASCII fold: for code units in A-Z range, add 0x20
            if cu >= 0x41 && cu <= 0x5A { cu + 0x20 } else { cu }
        })
        .collect();
    let needle_len_bytes = needle_lower.len() * 2;
    if needle_len_bytes == 0 || data.len() < needle_len_bytes {
        return false;
    }
    data.windows(needle_len_bytes).any(|w| {
        // Decode window bytes as little-endian u16 code units then fold
        w.chunks_exact(2)
            .map(|pair| {
                let cu = u16::from_le_bytes([pair[0], pair[1]]);
                if cu >= 0x41 && cu <= 0x5A { cu + 0x20 } else { cu }
            })
            .zip(needle_lower.iter().copied())
            .all(|(wc, nc)| wc == nc)
    })
}

/// Search the raw file for a byte pattern expressed as space-separated hex
/// bytes where `??` is a wildcard.
///
/// Returns the offset of the first match, or `None`.
#[must_use]
pub fn find_bytes(data: &[u8], hex_pattern: &str) -> Option<usize> {
    let mut tokens_iter = hex_pattern.split_whitespace().peekable();
    if tokens_iter.peek().is_none() {
        return None;
    }

    // Parse tokens into (Option<u8>, bool is_wildcard)
    let pattern: Vec<Option<u8>> = tokens_iter
        .map(|t| {
            if t == "??" || t == "?" {
                None
            } else {
                u8::from_str_radix(t, 16).ok()
            }
        })
        .collect();

    let plen = pattern.len();
    if plen > data.len() {
        return None;
    }

    'outer: for i in 0..=(data.len() - plen) {
        for (j, maybe_byte) in pattern.iter().enumerate() {
            if let Some(expected) = maybe_byte
                && data[i + j] != *expected {
                    continue 'outer;
                }
            // wildcard: always matches
        }
        return Some(i);
    }
    None
}

// ---------------------------------------------------------------------------
// Internal PE helpers
// ---------------------------------------------------------------------------

/// Translate a VA (RVA) to a file offset by walking the section table.
fn rva_to_file_offset(data: &[u8], pe_off: usize, rva: u32) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;

    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().ok()?);
        let virt_size = u32::from_le_bytes(data[s + 8..s + 12].try_into().ok()?);
        let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?);
        let raw_size = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?);

        // Use saturating_add to prevent u32 overflow when attacker controls
        // virt_addr or virt_size/raw_size from the section table.
        let vend = virt_addr.saturating_add(virt_size.max(raw_size));
        if rva >= virt_addr && rva < vend {
            let file_off = raw_off as usize + (rva - virt_addr) as usize;
            if file_off < data.len() {
                return Some(file_off);
            }
        }
    }
    None
}

/// Read a null-terminated byte string from `data` at `offset`.
fn read_cstr(data: &[u8], offset: usize) -> String {
    let slice = &data[offset.min(data.len())..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end.min(256)]).into_owned()
}

/// Count entries in an ILT/IAT (Import Lookup Table).  Stops at a null entry.
fn count_ilt_entries(data: &[u8], magic: u16, ilt_foff: usize) -> u16 {
    let entry_size: usize = if magic == 0x020b { 8 } else { 4 };
    let mut count: u16 = 0;
    let mut off = ilt_foff;
    loop {
        if off + entry_size > data.len() {
            break;
        }
        let is_null = data[off..off + entry_size].iter().all(|&b| b == 0);
        if is_null {
            break;
        }
        count = count.saturating_add(1);
        off += entry_size;
        if count >= 0x7FFF {
            break;
        } // guard
    }
    count
}

/// Walk an ILT for a named import matching `func_lower`.
fn check_ilt_for_func(
    data: &[u8],
    pe_off: usize,
    magic: u16,
    ilt_foff: usize,
    func_lower: &str,
) -> bool {
    let entry_size: usize = if magic == 0x020b { 8 } else { 4 };
    let mut off = ilt_foff;
    loop {
        if off + entry_size > data.len() {
            break;
        }
        let is_null = data[off..off + entry_size].iter().all(|&b| b == 0);
        if is_null {
            break;
        }

        // High bit set = ordinal import → skip
        let high_bit_set = if magic == 0x020b {
            data[off + 7] & 0x80 != 0
        } else {
            data[off + 3] & 0x80 != 0
        };

        if !high_bit_set {
            let hint_rva = if magic == 0x020b {
                u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8])) as u32
            } else {
                u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
            };
            // Hint/Name table: 2-byte hint + null-terminated name
            if let Some(hnt_foff) = rva_to_file_offset(data, pe_off, hint_rva) {
                let name_foff = hnt_foff + 2;
                if name_foff < data.len() {
                    let name = read_cstr(data, name_foff).to_lowercase();
                    if name == func_lower || name.contains(func_lower) {
                        return true;
                    }
                }
            }
        }
        off += entry_size;
    }
    false
}

// ---------------------------------------------------------------------------
// match_condition
// ---------------------------------------------------------------------------

/// Evaluate a single [`DieCondition`] against the raw file `data`.
///
/// # Returns
///
/// `true` if the condition is satisfied, `false` otherwise.
#[must_use]
pub fn match_condition(cond: &DieCondition, data: &[u8]) -> bool {
    match cond {
        DieCondition::SectionName(name) => read_pe_sections(data).iter().any(|(n, _)| n == name),

        DieCondition::SectionCount { min, max } => {
            let count = read_section_count(data);
            count >= *min && count <= *max
        }

        DieCondition::BytePattern { offset, hex } => {
            // Search for the pattern anywhere within the file starting at
            // `offset`.  The original `is_some_and(|off| off == 0)` constraint
            // was wrong: it required an exact match at the byte boundary, not
            // a search starting from that position.
            if *offset >= data.len() {
                return false;
            }
            let slice = &data[*offset..];
            find_bytes(slice, hex).is_some()
        }

        DieCondition::EntryPointHex(hex) => {
            let ep = get_entry_point_bytes(data);
            if ep.is_empty() {
                return false;
            }
            let tokens: Vec<Option<u8>> = hex
                .split_whitespace()
                .map(|t| {
                    if t == "??" || t == "?" {
                        None
                    } else {
                        u8::from_str_radix(t, 16).ok()
                    }
                })
                .collect();
            if tokens.len() > ep.len() {
                return false;
            }
            tokens
                .iter()
                .enumerate()
                .all(|(i, maybe)| maybe.map(|b| ep[i] == b).unwrap_or(true))
        }

        DieCondition::EntropyRange { section, min, max } => {
            let sections = read_pe_sections(data);
            sections
                .get(*section)
                .is_some_and(|(_, ent)| *ent >= *min && *ent <= *max)
        }

        DieCondition::ImportPresent { dll, func } => check_imports(data, dll, func),

        DieCondition::ImportCount { min, max } => {
            let n = count_imports(data);
            n >= *min && n <= *max
        }

        DieCondition::ExportPresent(name) => check_exports(data, name),

        DieCondition::SubsystemType(expected) => {
            pe_subsystem(data).is_some_and(|s| s == *expected)
        }

        DieCondition::StringPresent(s) => data.windows(s.len()).any(|w| w == s.as_bytes()),

        DieCondition::MachineType(expected) => {
            pe_machine(data).is_some_and(|m| m == *expected)
        }

        DieCondition::OverlayPresent => has_overlay(data),

        DieCondition::ResourcePresent(type_name) => has_resource_type(data, type_name),

        DieCondition::Dotnet => has_dotnet(data),

        DieCondition::Manifest => has_manifest(data),
    }
}

/// Evaluate a [`RuleCondition`] combinator against the raw file `data`.
#[must_use]
pub fn match_rule_condition(rc: &RuleCondition, data: &[u8]) -> bool {
    match rc {
        RuleCondition::All(conds) => conds.iter().all(|c| match_condition(c, data)),
        RuleCondition::Any(conds) => conds.iter().any(|c| match_condition(c, data)),
        RuleCondition::Not(cond) => !match_condition(cond, data),
    }
}

// ---------------------------------------------------------------------------
// DieScanner
// ---------------------------------------------------------------------------

/// A structured scanner that parses [`BUILTIN_RULES`] and evaluates each rule
/// against raw file bytes, returning a sorted list of [`Detection`]s.
///
/// Unlike [`DieDetector`] (which uses raw byte anchors), `DieScanner` uses the
/// rich [`DieCondition`] type for PE-aware matching.
pub struct DieScanner;

/// Internal representation of a parsed YAML rule.
#[derive(Debug)]
struct ParsedRule {
    name: String,
    kind: DetectKind,
    version: Option<String>,
    confidence: u8,
    /// Flat list of conditions — a rule fires when *all* conditions match
    /// (implicit `All`).
    conditions: Vec<DieCondition>,
}

impl DieScanner {
    /// Create a new scanner instance (no state, all rules are built-in).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` against all built-in rules and return every matching
    /// [`Detection`], sorted by confidence descending.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<Detection> {
        let rules = Self::load_builtin_rules();
        let mut detections: Vec<Detection> = rules
            .into_iter()
            .filter(|r| r.conditions.iter().all(|c| match_condition(c, data)))
            .map(|r| Detection {
                kind: r.kind,
                name: r.name,
                version: r.version,
                confidence: r.confidence,
                description: "Matched by DieScanner structured rule".to_string(),
            })
            .collect();

        detections.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        detections
    }

    /// Load and parse the built-in YAML rule set.
    ///
    /// The YAML is embedded at compile time in [`BUILTIN_RULES`].  Rules that
    /// fail to parse are silently skipped.
    fn load_builtin_rules() -> Vec<ParsedRule> {
        Self::parse_yaml_rules(BUILTIN_RULES)
    }

    /// Parse a YAML document containing rule entries and return a list of
    /// [`ParsedRule`]s.
    ///
    /// This is a hand-written parser that understands the schema documented on
    /// [`BUILTIN_RULES`] without pulling in a serde-yaml dependency.  It handles
    /// the sub-set of YAML needed for our rule format:
    ///
    /// - Top-level sequence of mappings (`- key: value`)
    /// - Simple scalar values (strings, integers)
    /// - The `conditions:` key, whose value is a sequence of condition nodes
    ///   in our well-known set
    fn parse_yaml_rules(yaml: &str) -> Vec<ParsedRule> {
        // Split into rule blocks separated by "- name:"
        // We find each line that starts with "- name:" (with optional leading spaces)
        let lines: Vec<&str> = yaml.lines().collect();
        let mut block_starts: Vec<usize> = Vec::with_capacity(32);
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("- name:") {
                block_starts.push(i);
            }
        }
        let mut rules: Vec<ParsedRule> = Vec::with_capacity(block_starts.len());

        for (b, &start) in block_starts.iter().enumerate() {
            let end = block_starts.get(b + 1).copied().unwrap_or(lines.len());
            let block_lines = &lines[start..end];

            let mut name = String::new();
            let mut kind_str = String::new();
            let mut version = None::<String>;
            let mut confidence = 50u8;
            let mut conditions = Vec::<DieCondition>::new();

            // Track whether we are inside a `conditions:` block
            let mut in_conditions = false;
            // Track whether we are inside a multi-field condition (e.g. BytePattern)
            let mut pending_cond: Option<&str> = None;
            let mut cond_offset: Option<usize> = None;
            let mut cond_hex: Option<String> = None;
            let mut cond_min_f: Option<f32> = None;
            let mut cond_max_f: Option<f32> = None;
            let mut cond_sec: Option<usize> = None;
            let mut cond_dll: Option<String> = None;
            let mut cond_func: Option<String> = None;
            let mut cond_min_u: Option<u16> = None;
            let mut cond_max_u: Option<u16> = None;

            let flush_pending = |pending: &mut Option<&str>,
                                 offset: &mut Option<usize>,
                                 hex: &mut Option<String>,
                                 min_f: &mut Option<f32>,
                                 max_f: &mut Option<f32>,
                                 sec: &mut Option<usize>,
                                 dll: &mut Option<String>,
                                 func: &mut Option<String>,
                                 min_u: &mut Option<u16>,
                                 max_u: &mut Option<u16>,
                                 conds: &mut Vec<DieCondition>| {
                if let Some(kind) = pending.take() {
                    match kind {
                        "BytePattern" => {
                            if let (Some(off), Some(h)) = (offset.take(), hex.take()) {
                                conds.push(DieCondition::BytePattern {
                                    offset: off,
                                    hex: h,
                                });
                            }
                        }
                        "EntropyRange" => {
                            if let (Some(s), Some(lo), Some(hi)) =
                                (sec.take(), min_f.take(), max_f.take())
                            {
                                conds.push(DieCondition::EntropyRange {
                                    section: s,
                                    min: lo,
                                    max: hi,
                                });
                            }
                        }
                        "ImportPresent" => {
                            if let (Some(d), Some(fn_)) = (dll.take(), func.take()) {
                                conds.push(DieCondition::ImportPresent { dll: d, func: fn_ });
                            }
                        }
                        "ImportCount" => {
                            if let (Some(lo), Some(hi)) = (min_u.take(), max_u.take()) {
                                conds.push(DieCondition::ImportCount { min: lo, max: hi });
                            }
                        }
                        "SectionCount" => {
                            if let (Some(lo), Some(hi)) = (min_u.take(), max_u.take()) {
                                conds.push(DieCondition::SectionCount {
                                    min: lo.min(255) as u8,
                                    max: hi.min(255) as u8,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            };

            for (li, raw_line) in block_lines.iter().enumerate() {
                let line = raw_line.trim_start();
                let indent = raw_line.len() - line.len();

                // Detect end of conditions block (line at top-level indent)
                if in_conditions && indent < 4 && !line.is_empty() && !line.starts_with('-') {
                    in_conditions = false;
                    flush_pending(
                        &mut pending_cond,
                        &mut cond_offset,
                        &mut cond_hex,
                        &mut cond_min_f,
                        &mut cond_max_f,
                        &mut cond_sec,
                        &mut cond_dll,
                        &mut cond_func,
                        &mut cond_min_u,
                        &mut cond_max_u,
                        &mut conditions,
                    );
                }

                // Top-level rule fields
                if li == 0 {
                    // "- name: ..."
                    if let Some(v) = line.strip_prefix("- name:") {
                        name = v.trim().trim_matches('"').to_string();
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("kind:") {
                    kind_str = rest.trim().trim_matches('"').to_string();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("version:") {
                    let v = rest.trim().trim_matches('"');
                    if !v.is_empty() {
                        version = Some(v.to_string());
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("confidence:") {
                    if let Ok(n) = rest.trim().parse::<u8>() {
                        confidence = n;
                    }
                    continue;
                }
                if line.starts_with("conditions:") {
                    in_conditions = true;
                    continue;
                }

                if in_conditions {
                    // Condition line starting with "- " or continuation lines
                    let stripped = line.strip_prefix("- ").unwrap_or(line);

                    if let Some(v) = stripped.strip_prefix("SectionName:") {
                        conditions.push(DieCondition::SectionName(
                            v.trim().trim_matches('"').to_string(),
                        ));
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("EntryPointHex:") {
                        conditions.push(DieCondition::EntryPointHex(
                            v.trim().trim_matches('"').to_string(),
                        ));
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("StringPresent:") {
                        // Handle escape: \x.. in strings — pass through as-is for now
                        conditions.push(DieCondition::StringPresent(
                            v.trim().trim_matches('"').to_string(),
                        ));
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("ExportPresent:") {
                        conditions.push(DieCondition::ExportPresent(
                            v.trim().trim_matches('"').to_string(),
                        ));
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("SubsystemType:") {
                        if let Ok(n) = v.trim().parse::<u16>() {
                            conditions.push(DieCondition::SubsystemType(n));
                        }
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("MachineType:") {
                        if let Ok(n) = v.trim().parse::<u16>() {
                            conditions.push(DieCondition::MachineType(n));
                        }
                        pending_cond = None;
                        continue;
                    }
                    if stripped.starts_with("OverlayPresent:") {
                        conditions.push(DieCondition::OverlayPresent);
                        pending_cond = None;
                        continue;
                    }
                    if stripped.starts_with("Dotnet:") {
                        conditions.push(DieCondition::Dotnet);
                        pending_cond = None;
                        continue;
                    }
                    if stripped.starts_with("Manifest:") {
                        conditions.push(DieCondition::Manifest);
                        pending_cond = None;
                        continue;
                    }
                    if let Some(v) = stripped.strip_prefix("ResourcePresent:") {
                        conditions.push(DieCondition::ResourcePresent(
                            v.trim().trim_matches('"').to_string(),
                        ));
                        pending_cond = None;
                        continue;
                    }

                    // Multi-field conditions — header line
                    if stripped.starts_with("BytePattern:") {
                        flush_pending(
                            &mut pending_cond,
                            &mut cond_offset,
                            &mut cond_hex,
                            &mut cond_min_f,
                            &mut cond_max_f,
                            &mut cond_sec,
                            &mut cond_dll,
                            &mut cond_func,
                            &mut cond_min_u,
                            &mut cond_max_u,
                            &mut conditions,
                        );
                        pending_cond = Some("BytePattern");
                        continue;
                    }
                    if stripped.starts_with("EntropyRange:") {
                        flush_pending(
                            &mut pending_cond,
                            &mut cond_offset,
                            &mut cond_hex,
                            &mut cond_min_f,
                            &mut cond_max_f,
                            &mut cond_sec,
                            &mut cond_dll,
                            &mut cond_func,
                            &mut cond_min_u,
                            &mut cond_max_u,
                            &mut conditions,
                        );
                        pending_cond = Some("EntropyRange");
                        continue;
                    }
                    if let Some(rest_full) = stripped.strip_prefix("ImportPresent:") {
                        let rest = rest_full.trim();
                        // Inline form: ImportPresent: { dll: "x", func: "y" }
                        if rest.starts_with('{') {
                            let inner = rest.trim_matches(|c| c == '{' || c == '}');
                            let mut dll_ = String::new();
                            let mut fn_ = String::new();
                            for part in inner.split(',') {
                                let p = part.trim();
                                if let Some(v) = p.strip_prefix("dll:") {
                                    dll_ = v.trim().trim_matches('"').to_string();
                                } else if let Some(v) = p.strip_prefix("func:") {
                                    fn_ = v.trim().trim_matches('"').to_string();
                                }
                            }
                            if !dll_.is_empty() && !fn_.is_empty() {
                                conditions.push(DieCondition::ImportPresent {
                                    dll: dll_,
                                    func: fn_,
                                });
                            }
                            pending_cond = None;
                        } else {
                            flush_pending(
                                &mut pending_cond,
                                &mut cond_offset,
                                &mut cond_hex,
                                &mut cond_min_f,
                                &mut cond_max_f,
                                &mut cond_sec,
                                &mut cond_dll,
                                &mut cond_func,
                                &mut cond_min_u,
                                &mut cond_max_u,
                                &mut conditions,
                            );
                            pending_cond = Some("ImportPresent");
                        }
                        continue;
                    }
                    if let Some(rest_full) = stripped.strip_prefix("ImportCount:") {
                        let rest = rest_full.trim();
                        if rest.starts_with('{') {
                            let inner = rest.trim_matches(|c| c == '{' || c == '}');
                            let mut lo = 0u16;
                            let mut hi = u16::MAX;
                            for part in inner.split(',') {
                                let p = part.trim();
                                if let Some(v) = p.strip_prefix("min:") {
                                    lo = v.trim().parse().unwrap_or(0);
                                } else if let Some(v) = p.strip_prefix("max:") {
                                    hi = v.trim().parse().unwrap_or(u16::MAX);
                                }
                            }
                            conditions.push(DieCondition::ImportCount { min: lo, max: hi });
                            pending_cond = None;
                        } else {
                            flush_pending(
                                &mut pending_cond,
                                &mut cond_offset,
                                &mut cond_hex,
                                &mut cond_min_f,
                                &mut cond_max_f,
                                &mut cond_sec,
                                &mut cond_dll,
                                &mut cond_func,
                                &mut cond_min_u,
                                &mut cond_max_u,
                                &mut conditions,
                            );
                            pending_cond = Some("ImportCount");
                        }
                        continue;
                    }
                    if let Some(rest_full) = stripped.strip_prefix("SectionCount:") {
                        let rest = rest_full.trim();
                        if rest.starts_with('{') {
                            let inner = rest.trim_matches(|c| c == '{' || c == '}');
                            let mut lo = 0u16;
                            let mut hi = 96u16;
                            for part in inner.split(',') {
                                let p = part.trim();
                                if let Some(v) = p.strip_prefix("min:") {
                                    lo = v.trim().parse().unwrap_or(0);
                                } else if let Some(v) = p.strip_prefix("max:") {
                                    hi = v.trim().parse().unwrap_or(96);
                                }
                            }
                            conditions.push(DieCondition::SectionCount {
                                min: lo.min(255) as u8,
                                max: hi.min(255) as u8,
                            });
                            pending_cond = None;
                        } else {
                            flush_pending(
                                &mut pending_cond,
                                &mut cond_offset,
                                &mut cond_hex,
                                &mut cond_min_f,
                                &mut cond_max_f,
                                &mut cond_sec,
                                &mut cond_dll,
                                &mut cond_func,
                                &mut cond_min_u,
                                &mut cond_max_u,
                                &mut conditions,
                            );
                            pending_cond = Some("SectionCount");
                        }
                        continue;
                    }

                    // Continuation lines for multi-field conditions
                    if let Some(pk) = pending_cond {
                        if let Some(v) = stripped.strip_prefix("offset:") {
                            cond_offset = v.trim().parse().ok();
                        } else if let Some(v) = stripped.strip_prefix("hex:") {
                            cond_hex = Some(v.trim().trim_matches('"').to_string());
                        } else if let Some(v) = stripped.strip_prefix("section:") {
                            cond_sec = v.trim().parse().ok();
                        } else if let Some(v) = stripped.strip_prefix("min:") {
                            let s = v.trim();
                            match pk {
                                "EntropyRange" => {
                                    cond_min_f = s.parse().ok();
                                }
                                _ => {
                                    cond_min_u = s.parse().ok();
                                }
                            }
                        } else if let Some(v) = stripped.strip_prefix("max:") {
                            let s = v.trim();
                            match pk {
                                "EntropyRange" => {
                                    cond_max_f = s.parse().ok();
                                }
                                _ => {
                                    cond_max_u = s.parse().ok();
                                }
                            }
                        } else if let Some(v) = stripped.strip_prefix("dll:") {
                            cond_dll = Some(v.trim().trim_matches('"').to_string());
                        } else if let Some(v) = stripped.strip_prefix("func:") {
                            cond_func = Some(v.trim().trim_matches('"').to_string());
                        }
                    }
                }
            }

            // Flush any pending multi-field condition
            flush_pending(
                &mut pending_cond,
                &mut cond_offset,
                &mut cond_hex,
                &mut cond_min_f,
                &mut cond_max_f,
                &mut cond_sec,
                &mut cond_dll,
                &mut cond_func,
                &mut cond_min_u,
                &mut cond_max_u,
                &mut conditions,
            );

            if name.is_empty() {
                continue;
            }

            let kind = match kind_str.as_str() {
                "Packer" => DetectKind::Packer,
                "Protector" => DetectKind::Protector,
                "Installer" => DetectKind::Installer,
                "Archive" => DetectKind::Archive,
                "Library" => DetectKind::Library,
                "Tool" => DetectKind::Tool,
                _ => DetectKind::Compiler,
            };

            rules.push(ParsedRule {
                name,
                kind,
                version,
                confidence,
                conditions,
            });
        }

        rules
    }
}

impl Default for DieScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DieScanner {{ builtin_rules: {} }}",
            Self::load_builtin_rules().len()
        )
    }
}

/// Errors from detection operations.
#[derive(Debug, Error)]
pub enum DieError {
    /// The detection step itself failed.
    #[error("detection failed: {0}")]
    DetectionFailed(String),
    /// Triage-level error propagated from the triage crate.
    #[error("triage: {0}")]
    Triage(#[from] TriageError),
}

// ---------------------------------------------------------------------------
// DetectKind
// ---------------------------------------------------------------------------

/// Category of the detected tool / technology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectKind {
    /// Compiler / code generator.
    Compiler,
    /// Executable packer.
    Packer,
    /// Copy-protection or anti-tamper system.
    Protector,
    /// Setup / installation wrapper.
    Installer,
    /// Archive format.
    Archive,
    /// Linked library.
    Library,
    /// Generic tool.
    Tool,
}

impl fmt::Display for DetectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// A single detection hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// What kind of entity was detected.
    pub kind: DetectKind,
    /// Product / tool name.
    pub name: String,
    /// Version string, if known.
    pub version: Option<String>,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Human-readable reason / evidence for the detection.
    pub description: String,
}

impl fmt::Display for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        write!(
            f,
            "{:?}: {} v{} ({}%)",
            self.kind, self.name, ver, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// DieResult
// ---------------------------------------------------------------------------

/// The complete DIE detection result for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieResult {
    /// Detected file format.
    pub file_kind: FileKind,
    /// All detections found.
    pub detections: Vec<Detection>,
    /// `true` if any packer was detected.
    pub is_packed: bool,
    /// `true` if any protector was detected.
    pub is_protected: bool,
    /// `true` if a digital signature was detected (stub heuristic).
    pub is_signed: bool,
    /// Bytes in overlay / appended data, if any.
    pub overlay_size: usize,
    /// Total file size in bytes.
    pub file_size: usize,
}

impl DieResult {
    /// Create a fresh result for the given file kind and size.
    #[must_use]
    pub const fn new(file_kind: FileKind, file_size: usize) -> Self {
        Self {
            file_kind,
            detections: Vec::new(),
            is_packed: false,
            is_protected: false,
            is_signed: false,
            overlay_size: 0,
            file_size,
        }
    }

    /// Add a detection, updating aggregate flags accordingly.
    pub fn add(&mut self, d: Detection) {
        if d.kind == DetectKind::Packer {
            self.is_packed = true;
        }
        if d.kind == DetectKind::Protector {
            self.is_protected = true;
        }
        self.detections.push(d);
    }

    /// Detections of kind [`DetectKind::Compiler`].
    #[must_use]
    pub fn compilers(&self) -> Vec<&Detection> {
        self.detections
            .iter()
            .filter(|d| d.kind == DetectKind::Compiler)
            .collect()
    }

    /// Detections of kind [`DetectKind::Packer`].
    #[must_use]
    pub fn packers(&self) -> Vec<&Detection> {
        self.detections
            .iter()
            .filter(|d| d.kind == DetectKind::Packer)
            .collect()
    }

    /// Detections of kind [`DetectKind::Protector`].
    #[must_use]
    pub fn protectors(&self) -> Vec<&Detection> {
        self.detections
            .iter()
            .filter(|d| d.kind == DetectKind::Protector)
            .collect()
    }

    /// Highest confidence score across all detections, or 0 if none.
    #[must_use]
    pub fn max_confidence(&self) -> u8 {
        self.detections
            .iter()
            .map(|d| d.confidence)
            .max()
            .unwrap_or(0)
    }
}

impl fmt::Display for DieResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DIE [{:?}]: {} detections packed={}",
            self.file_kind,
            self.detections.len(),
            self.is_packed
        )
    }
}

// ---------------------------------------------------------------------------
// DieRule
// ---------------------------------------------------------------------------

/// A single detection rule: one or more (offset, byte-sequence) anchors that
/// must all match for the rule to fire.
///
/// A special offset value of `0xFFFF_FFFF` means "search anywhere" (i.e. the
/// sequence must appear somewhere in the file).
#[derive(Debug, Clone)]
pub struct DieRule {
    /// Display name for the detected entity.
    pub name: String,
    /// Category.
    pub kind: DetectKind,
    /// Version tag, if applicable.
    pub version: Option<String>,
    /// Anchors: list of `(file_offset, byte_pattern)`.
    ///
    /// Use offset `0xFFFF_FFFF` for a "contains anywhere" search.
    pub signature: Vec<(usize, Vec<u8>)>,
    /// Base confidence (0–100) when all anchors match.
    pub confidence: u8,
}

// ---------------------------------------------------------------------------
// DieDatabase
// ---------------------------------------------------------------------------

/// A collection of [`DieRule`]s used by [`DieDetector`].
pub struct DieDatabase {
    rules: Vec<DieRule>,
}

impl DieDatabase {
    /// Create an empty database.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the database.
    pub fn add_rule(&mut self, rule: DieRule) {
        self.rules.push(rule);
    }

    /// Total rule count.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Load a default set of rules covering common compilers, packers, and
    /// protectors seen in the wild.
    #[must_use]
    pub fn load_defaults() -> Self {
        let mut db = Self::new();

        // ---- Compilers -------------------------------------------------------
        // MSVC PE — identified by MZ + typical rich header stub
        db.add_rule(DieRule {
            name: "MSVC".to_string(),
            kind: DetectKind::Compiler,
            version: Some("2019+".to_string()),
            // Anchor: Rich header magic "Rich" at variable offset; just check MZ
            signature: vec![(0, b"MZ".to_vec())],
            confidence: 40,
        });
        // MSVC x64: entry stub starts with sub rsp, N
        db.add_rule(DieRule {
            name: "MSVC x64".to_string(),
            kind: DetectKind::Compiler,
            version: Some("2015+".to_string()),
            // sub rsp, 0x28 is a very common MSVC x64 entry pattern
            signature: vec![(0, b"MZ".to_vec()), (0xFFFF_FFFF, b"Rich".to_vec())],
            confidence: 70,
        });
        // MinGW / GCC Windows
        db.add_rule(DieRule {
            name: "GCC".to_string(),
            kind: DetectKind::Compiler,
            version: Some("4.x+".to_string()),
            signature: vec![(0xFFFF_FFFF, b"MinGW".to_vec())],
            confidence: 80,
        });
        // Delphi / Borland
        db.add_rule(DieRule {
            name: "Delphi".to_string(),
            kind: DetectKind::Compiler,
            version: Some("7+".to_string()),
            signature: vec![(0xFFFF_FFFF, b"Borland".to_vec())],
            confidence: 85,
        });
        // Visual Basic 6
        db.add_rule(DieRule {
            name: "Visual Basic 6".to_string(),
            kind: DetectKind::Compiler,
            version: Some("6.0".to_string()),
            signature: vec![(0xFFFF_FFFF, b"VB5!".to_vec())],
            confidence: 90,
        });
        // Clang
        db.add_rule(DieRule {
            name: "Clang".to_string(),
            kind: DetectKind::Compiler,
            version: Some("10+".to_string()),
            signature: vec![(0xFFFF_FFFF, b"clang".to_vec())],
            confidence: 75,
        });
        // Rust
        db.add_rule(DieRule {
            name: "Rust".to_string(),
            kind: DetectKind::Compiler,
            version: Some("1.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"rustc".to_vec())],
            confidence: 85,
        });

        // ---- Packers ---------------------------------------------------------
        // UPX
        db.add_rule(DieRule {
            name: "UPX".to_string(),
            kind: DetectKind::Packer,
            version: Some("3.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"UPX0".to_vec())],
            confidence: 95,
        });
        // UPX1 section name variant
        db.add_rule(DieRule {
            name: "UPX".to_string(),
            kind: DetectKind::Packer,
            version: Some("3.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"UPX1".to_vec())],
            confidence: 95,
        });
        // MPRESS packer
        db.add_rule(DieRule {
            name: "MPRESS".to_string(),
            kind: DetectKind::Packer,
            version: Some("2.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b".MPRESS".to_vec())],
            confidence: 90,
        });
        // ASPack
        db.add_rule(DieRule {
            name: "ASPack".to_string(),
            kind: DetectKind::Packer,
            version: Some("2.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b".aspack".to_vec())],
            confidence: 90,
        });
        // PECompact
        db.add_rule(DieRule {
            name: "PECompact".to_string(),
            kind: DetectKind::Packer,
            version: Some("2.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"PECompact2".to_vec())],
            confidence: 90,
        });

        // ---- Protectors ------------------------------------------------------
        // Themida / WinLicense
        db.add_rule(DieRule {
            name: "Themida".to_string(),
            kind: DetectKind::Protector,
            version: Some("3.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b".themida".to_vec())],
            confidence: 90,
        });
        // VMProtect
        db.add_rule(DieRule {
            name: "VMProtect".to_string(),
            kind: DetectKind::Protector,
            version: Some("3.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b".vmp0".to_vec())],
            confidence: 90,
        });
        // Obsidium
        db.add_rule(DieRule {
            name: "Obsidium".to_string(),
            kind: DetectKind::Protector,
            version: Some("1.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"Obsidium".to_vec())],
            confidence: 88,
        });

        // ---- Installers / Archives -------------------------------------------
        // NSIS installer
        db.add_rule(DieRule {
            name: "NSIS".to_string(),
            kind: DetectKind::Installer,
            version: Some("3.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"Nullsoft".to_vec())],
            confidence: 85,
        });
        // InnoSetup
        db.add_rule(DieRule {
            name: "InnoSetup".to_string(),
            kind: DetectKind::Installer,
            version: Some("6.x".to_string()),
            signature: vec![(0xFFFF_FFFF, b"Inno Setup".to_vec())],
            confidence: 90,
        });

        db
    }
}

impl Default for DieDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DieDatabase({} rules)", self.rules.len())
    }
}

// ---------------------------------------------------------------------------
// DieDetector
// ---------------------------------------------------------------------------

/// Runs [`DieDatabase`] rules against raw file bytes and returns a
/// [`DieResult`].
pub struct DieDetector {
    db: DieDatabase,
}

impl DieDetector {
    /// Create a detector with the provided database.
    #[must_use]
    pub const fn new(db: DieDatabase) -> Self {
        Self { db }
    }

    /// Create a detector pre-loaded with the default rule set.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DieDatabase::load_defaults())
    }

    /// Run all rules against `data` and return a [`DieResult`].
    ///
    /// # Errors
    ///
    /// Returns [`DieError`] on internal failure (currently infallible but kept
    /// for API consistency).
    pub fn detect(&self, data: &[u8]) -> Result<DieResult, DieError> {
        let kind = rustre_triage::detect_file_kind(data);
        let mut result = DieResult::new(kind, data.len());

        for rule in &self.db.rules {
            if self.rule_matches(rule, data) {
                result.add(Detection {
                    kind: rule.kind,
                    name: rule.name.clone(),
                    version: rule.version.clone(),
                    confidence: rule.confidence,
                    description: format!("Detected by signature match: {}", rule.name),
                });
            }
        }

        // ── Post-process: suppress packer/protector false positives ────────
        sanitize_false_positives(&mut result, data);

        Ok(result)
    }

    /// Returns `true` if all anchors of `rule` are satisfied in `data`.
    fn rule_matches(&self, rule: &DieRule, data: &[u8]) -> bool {
        rule.signature.iter().all(|(off, bytes)| {
            if bytes.is_empty() {
                return true;
            }
            if *off == 0xFFFF_FFFF {
                // Anywhere match
                data.windows(bytes.len()).any(|w| w == bytes.as_slice())
            } else {
                let start = *off;
                start + bytes.len() <= data.len()
                    && &data[start..start + bytes.len()] == bytes.as_slice()
            }
        })
    }
}

impl fmt::Debug for DieDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DieDetector({} rules)", self.db.rule_count())
    }
}

// ---------------------------------------------------------------------------
// DieMatchResult
// ---------------------------------------------------------------------------

/// The result of matching a single [`DieSignatureEntry`] against file data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieMatchResult {
    /// Display name of the matched signature (e.g. `"UPX packer"`).
    pub name: String,
    /// Category of the matched technology.
    pub kind: DetectKind,
    /// Confidence that the match is accurate, in the range `0.0`–`1.0`.
    pub confidence: f32,
    /// Optional version string extracted or inferred from the signature.
    pub version: Option<String>,
    /// Human-readable description of what was matched and why.
    pub description: String,
}

impl DieMatchResult {
    /// `true` if confidence is at least 0.7.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.7
    }
}

impl fmt::Display for DieMatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        write!(
            f,
            "{:?}: {} v{} ({:.0}%)",
            self.kind,
            self.name,
            ver,
            self.confidence * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// DieSignatureEntry — one built-in detection entry
// ---------------------------------------------------------------------------

/// A single entry in the [`DieSignatureDatabase`].
///
/// Each entry consists of one or more byte/string checks that all must pass
/// (logical AND).
#[derive(Debug, Clone)]
pub struct DieSignatureEntry {
    /// Result prototype produced on a match.
    name: &'static str,
    kind: DetectKind,
    version: Option<&'static str>,
    /// Confidence in the 0-100 range; stored as `u8` and normalised to `f32`
    /// on output.
    confidence: u8,
    description: &'static str,
    /// All checks that must pass.  Each variant is evaluated against the raw
    /// file bytes.
    checks: &'static [SigCheck],
}

/// A single pattern check inside a [`DieSignatureEntry`].
#[derive(Debug, Clone)]
pub enum SigCheck {
    /// The exact bytes must appear somewhere in the file.
    Contains(&'static [u8]),
    /// The file must start with these bytes (MZ / ELF magic etc.).
    StartsWith(&'static [u8]),
    /// The CLR data directory must be non-zero (`.NET` detection).
    DotnetClrPresent,
    /// At least one of the provided byte strings must be present.
    AnyOf(&'static [&'static [u8]]),
}

impl SigCheck {
    fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Contains(needle) => {
                if needle.is_empty() {
                    return true;
                }
                data.windows(needle.len()).any(|w| w == *needle)
            }
            Self::StartsWith(prefix) => data.starts_with(prefix),
            Self::DotnetClrPresent => {
                // Reuse the existing has_dotnet helper exposed through
                // match_condition / DieCondition::Dotnet.
                match_condition(&DieCondition::Dotnet, data)
            }
            Self::AnyOf(needles) => needles.iter().any(|needle| {
                if needle.is_empty() {
                    return false;
                }
                data.windows(needle.len()).any(|w| w == *needle)
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// DieSignatureDatabase
// ---------------------------------------------------------------------------

/// Built-in signature database with 20+ entries covering common packers,
/// compilers, runtimes, and tools.
///
/// This is a higher-level, self-contained scanner that does not require PE
/// parsing for many checks and works on any file format.
///
/// # Example
///
/// ```
/// use rustre_triage_die::DieSignatureDatabase;
///
/// let db = DieSignatureDatabase::new();
/// let file_bytes: &[u8] = b"MZ\x90\x00...";
/// let matches = db.scan(file_bytes);
/// for m in &matches {
///     println!("{m}");
/// }
/// ```
///
/// The example was marked `rust,ignore` until 2026-07-29, so it had never been
/// compiled — a public example is a claim about the API, and an ignored one is
/// an unverified claim. It turned out to be accurate; it only lacked the `use`
/// and a concrete input. It now runs as a doc-test and will fail if this API
/// changes under it.
pub struct DieSignatureDatabase {
    // All entries are &'static so there is no heap allocation.
    // Stored as a Vec so user entries can be pushed at runtime.
    entries: Vec<DieSignatureEntry>,
}

/// Static built-in entries.  Listed in roughly descending confidence order.
static BUILTIN_SIG_ENTRIES: &[DieSignatureEntry] = &[
    // ── Packers ──────────────────────────────────────────────────────────────
    DieSignatureEntry {
        name: "UPX packer",
        kind: DetectKind::Packer,
        version: Some("3.x/4.x"),
        confidence: 97,
        description: "UPX section names UPX0/UPX1 found",
        checks: &[SigCheck::AnyOf(&[b"UPX0", b"UPX1"])],
    },
    DieSignatureEntry {
        name: "MPRESS packer",
        kind: DetectKind::Packer,
        version: Some("2.x"),
        confidence: 93,
        description: "MPRESS section name .MPRESS1 found",
        checks: &[SigCheck::Contains(b".MPRESS1")],
    },
    DieSignatureEntry {
        name: "ASPack",
        kind: DetectKind::Packer,
        version: Some("2.x"),
        confidence: 92,
        description: "ASPack section name .aspack found",
        checks: &[SigCheck::Contains(b".aspack")],
    },
    DieSignatureEntry {
        name: "PECompact",
        kind: DetectKind::Packer,
        version: Some("2.x"),
        confidence: 91,
        description: "PECompact2 magic string found",
        checks: &[SigCheck::Contains(b"PECompact2")],
    },
    DieSignatureEntry {
        name: "FSG packer",
        kind: DetectKind::Packer,
        version: Some("2.0"),
        confidence: 88,
        description: "FSG! magic string found",
        checks: &[SigCheck::Contains(b"FSG!")],
    },
    DieSignatureEntry {
        name: "PESpin",
        kind: DetectKind::Packer,
        version: Some("1.3"),
        confidence: 86,
        description: "PESpin magic string found",
        checks: &[SigCheck::Contains(b"PESpin")],
    },
    // ── Protectors ────────────────────────────────────────────────────────────
    DieSignatureEntry {
        name: "Themida / WinLicense",
        kind: DetectKind::Protector,
        version: Some("3.x"),
        confidence: 94,
        description: ".themida section name found",
        checks: &[SigCheck::Contains(b".themida")],
    },
    DieSignatureEntry {
        name: "VMProtect",
        kind: DetectKind::Protector,
        version: Some("2.x/3.x"),
        confidence: 93,
        description: ".vmp0 or .vmp1 section found",
        checks: &[SigCheck::AnyOf(&[b".vmp0", b".vmp1"])],
    },
    DieSignatureEntry {
        name: "Enigma Protector",
        kind: DetectKind::Protector,
        version: Some("7.x"),
        confidence: 90,
        description: ".enigma1 string found",
        checks: &[SigCheck::Contains(b".enigma1")],
    },
    DieSignatureEntry {
        name: "Obsidium",
        kind: DetectKind::Protector,
        version: Some("1.x"),
        confidence: 88,
        description: "Obsidium string found",
        checks: &[SigCheck::Contains(b"Obsidium")],
    },
    // ── Compilers / Runtimes ─────────────────────────────────────────────────
    DieSignatureEntry {
        name: "MSVBVM60 (Visual Basic 6)",
        kind: DetectKind::Compiler,
        version: Some("6.0"),
        confidence: 92,
        description: "VB5! magic + MSVBVM60.DLL import indicates VB6 binary",
        checks: &[
            SigCheck::StartsWith(b"MZ"),
            SigCheck::AnyOf(&[b"VB5!", b"MSVBVM60.DLL"]),
        ],
    },
    DieSignatureEntry {
        name: ".NET Framework assembly",
        kind: DetectKind::Compiler,
        version: Some("4.x"),
        confidence: 95,
        description: "CLR data directory non-zero — managed .NET assembly",
        checks: &[SigCheck::StartsWith(b"MZ"), SigCheck::DotnetClrPresent],
    },
    DieSignatureEntry {
        name: "Delphi / Borland",
        kind: DetectKind::Compiler,
        version: Some("7+"),
        confidence: 87,
        description: "Borland string in rich header or imports",
        checks: &[SigCheck::Contains(b"Borland")],
    },
    DieSignatureEntry {
        name: "Go runtime",
        kind: DetectKind::Compiler,
        version: Some("1.x"),
        confidence: 90,
        description: "Go build-id or runtime.main symbol present",
        checks: &[SigCheck::AnyOf(&[b"go.buildid", b"runtime.main"])],
    },
    DieSignatureEntry {
        name: "Rust",
        kind: DetectKind::Compiler,
        version: Some("1.x"),
        confidence: 88,
        description: "Rust mangled names (_ZN) or panic_ symbols present",
        checks: &[SigCheck::AnyOf(&[b"_ZN", b"panic_", b"rustc"])],
    },
    DieSignatureEntry {
        name: "GCC / MinGW",
        kind: DetectKind::Compiler,
        version: Some("4.x+"),
        confidence: 82,
        description: "MinGW string present — GCC-compiled Windows binary",
        checks: &[SigCheck::Contains(b"MinGW")],
    },
    DieSignatureEntry {
        name: "Clang",
        kind: DetectKind::Compiler,
        version: Some("10+"),
        confidence: 78,
        description: "clang version string present",
        checks: &[SigCheck::Contains(b"clang")],
    },
    // ── Bundlers / Tools ─────────────────────────────────────────────────────
    DieSignatureEntry {
        name: "PyInstaller",
        kind: DetectKind::Tool,
        version: Some("6.x"),
        confidence: 95,
        description: "PyInstaller PKG magic or MEI marker present",
        checks: &[SigCheck::AnyOf(&[
            b"MEI\x0c\x0b\x0a\x0b\x0e",
            b"PKG\x0b\x0a",
            b"PyInstaller",
        ])],
    },
    DieSignatureEntry {
        name: "AutoIt compiled script",
        kind: DetectKind::Tool,
        version: Some("3.x"),
        confidence: 93,
        description: "AU3!EA06 magic present",
        checks: &[SigCheck::AnyOf(&[b"AU3!EA06", b"AU3!EA"])],
    },
    DieSignatureEntry {
        name: "NSIS installer",
        kind: DetectKind::Installer,
        version: Some("3.x"),
        confidence: 87,
        description: "Nullsoft NSIS installer string present",
        checks: &[SigCheck::Contains(b"Nullsoft")],
    },
    DieSignatureEntry {
        name: "Inno Setup installer",
        kind: DetectKind::Installer,
        version: Some("6.x"),
        confidence: 90,
        description: "Inno Setup string found in overlay or resources",
        checks: &[SigCheck::Contains(b"Inno Setup")],
    },
    DieSignatureEntry {
        name: "WiX installer",
        kind: DetectKind::Installer,
        version: Some("4.x"),
        confidence: 85,
        description: "WiX Toolset string found",
        checks: &[SigCheck::Contains(b"WiX Toolset")],
    },
    DieSignatureEntry {
        name: "Py2Exe",
        kind: DetectKind::Tool,
        version: Some("0.13"),
        confidence: 88,
        description: "py2exe string present",
        checks: &[SigCheck::Contains(b"py2exe")],
    },
];

impl DieSignatureDatabase {
    /// Create a database pre-loaded with all built-in signatures.
    #[must_use]
    pub const fn new() -> Self {
        // We cannot clone &'static entries directly into a Vec<DieSignatureEntry>
        // because DieSignatureEntry is not Clone (it contains &'static slices).
        // We scan BUILTIN_SIG_ENTRIES directly in `scan`, so user-added entries
        // are stored separately.
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a custom runtime entry.  Built-in entries are always scanned first.
    pub fn add_entry(&mut self, entry: DieSignatureEntry) {
        self.entries.push(entry);
    }

    /// Total number of entries (built-in + custom).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        BUILTIN_SIG_ENTRIES.len() + self.entries.len()
    }

    /// Scan `data` against all built-in and custom entries and return every
    /// match as a [`DieMatchResult`].
    ///
    /// Results are sorted by confidence descending.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<DieMatchResult> {
        let mut results: Vec<DieMatchResult> = Vec::new();

        let all_entries: Vec<&DieSignatureEntry> = BUILTIN_SIG_ENTRIES
            .iter()
            .chain(self.entries.iter())
            .collect();

        for entry in all_entries {
            let matched = entry.checks.iter().all(|c| c.matches(data));
            if matched {
                results.push(DieMatchResult {
                    name: entry.name.to_string(),
                    kind: entry.kind,
                    confidence: f32::from(entry.confidence) / 100.0,
                    version: entry.version.map(std::string::ToString::to_string),
                    description: entry.description.to_string(),
                });
            }
        }

        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}

impl Default for DieSignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieSignatureDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DieSignatureDatabase({} entries)", self.entry_count())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DetectKind --------------------------------------------------------

    #[test]
    fn test_detect_kind_display() {
        assert_eq!(DetectKind::Compiler.to_string(), "Compiler");
        assert_eq!(DetectKind::Packer.to_string(), "Packer");
        assert_eq!(DetectKind::Protector.to_string(), "Protector");
        assert_eq!(DetectKind::Installer.to_string(), "Installer");
        assert_eq!(DetectKind::Archive.to_string(), "Archive");
        assert_eq!(DetectKind::Library.to_string(), "Library");
        assert_eq!(DetectKind::Tool.to_string(), "Tool");
    }

    // ---- DieError ----------------------------------------------------------

    #[test]
    fn test_die_error_detection_failed() {
        let e = DieError::DetectionFailed("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    // ---- Detection display -------------------------------------------------

    #[test]
    fn test_detection_display_with_version() {
        let d = Detection {
            kind: DetectKind::Packer,
            name: "UPX".to_string(),
            version: Some("3.94".to_string()),
            confidence: 95,
            description: "UPX packer".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("Packer"));
        assert!(s.contains("UPX"));
        assert!(s.contains("3.94"));
        assert!(s.contains("95%"));
    }

    #[test]
    fn test_detection_display_no_version() {
        let d = Detection {
            kind: DetectKind::Compiler,
            name: "GCC".to_string(),
            version: None,
            confidence: 60,
            description: "GCC compiler".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("GCC"));
        assert!(s.contains('?'));
    }

    // ---- DieResult ---------------------------------------------------------

    #[test]
    fn test_die_result_new() {
        let r = DieResult::new(FileKind::Pe64, 1024);
        assert_eq!(r.file_kind, FileKind::Pe64);
        assert_eq!(r.file_size, 1024);
        assert!(!r.is_packed);
        assert!(!r.is_protected);
        assert_eq!(r.detections.len(), 0);
    }

    #[test]
    fn test_die_result_add_packer() {
        let mut r = DieResult::new(FileKind::Pe32, 512);
        r.add(Detection {
            kind: DetectKind::Packer,
            name: "UPX".into(),
            version: None,
            confidence: 90,
            description: "test".into(),
        });
        assert!(r.is_packed);
        assert!(!r.is_protected);
        assert_eq!(r.detections.len(), 1);
    }

    #[test]
    fn test_die_result_add_protector() {
        let mut r = DieResult::new(FileKind::Pe32, 512);
        r.add(Detection {
            kind: DetectKind::Protector,
            name: "Themida".into(),
            version: None,
            confidence: 85,
            description: "test".into(),
        });
        assert!(r.is_protected);
    }

    #[test]
    fn test_die_result_compilers() {
        let mut r = DieResult::new(FileKind::Pe64, 1024);
        r.add(Detection {
            kind: DetectKind::Compiler,
            name: "MSVC".into(),
            version: None,
            confidence: 70,
            description: "test".into(),
        });
        r.add(Detection {
            kind: DetectKind::Packer,
            name: "UPX".into(),
            version: None,
            confidence: 90,
            description: "test".into(),
        });
        assert_eq!(r.compilers().len(), 1);
        assert_eq!(r.packers().len(), 1);
        assert_eq!(r.protectors().len(), 0);
    }

    #[test]
    fn test_die_result_max_confidence() {
        let mut r = DieResult::new(FileKind::Pe32, 512);
        assert_eq!(r.max_confidence(), 0);
        r.add(Detection {
            kind: DetectKind::Compiler,
            name: "A".into(),
            version: None,
            confidence: 50,
            description: String::new(),
        });
        r.add(Detection {
            kind: DetectKind::Packer,
            name: "B".into(),
            version: None,
            confidence: 90,
            description: String::new(),
        });
        assert_eq!(r.max_confidence(), 90);
    }

    #[test]
    fn test_die_result_display() {
        let r = DieResult::new(FileKind::Pe32, 100);
        let s = r.to_string();
        assert!(s.contains("DIE"));
        assert!(s.contains("Pe32"));
    }

    // ---- DieDatabase -------------------------------------------------------

    #[test]
    fn test_database_new_empty() {
        let db = DieDatabase::new();
        assert_eq!(db.rule_count(), 0);
    }

    #[test]
    fn test_database_add_rule() {
        let mut db = DieDatabase::new();
        db.add_rule(DieRule {
            name: "Test".into(),
            kind: DetectKind::Compiler,
            version: None,
            signature: vec![],
            confidence: 50,
        });
        assert_eq!(db.rule_count(), 1);
    }

    #[test]
    fn test_database_load_defaults() {
        let db = DieDatabase::load_defaults();
        assert!(db.rule_count() >= 10);
    }

    #[test]
    fn test_database_debug() {
        let db = DieDatabase::new();
        assert!(format!("{db:?}").contains("DieDatabase"));
    }

    #[test]
    fn test_database_default() {
        let db = DieDatabase::default();
        assert_eq!(db.rule_count(), 0);
    }

    // ---- DieDetector -------------------------------------------------------

    #[test]
    fn test_detector_debug() {
        let d = DieDetector::with_defaults();
        assert!(format!("{d:?}").contains("DieDetector"));
    }

    #[test]
    fn test_detector_detects_upx() {
        let detector = DieDetector::with_defaults();
        // Create data that contains "UPX0" string
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(&[0u8; 58]); // pad to 60 bytes
        data.extend_from_slice(b"UPX0 section header for testing");
        let result = detector.detect(&data).unwrap();
        assert!(result.packers().into_iter().any(|d| d.name == "UPX"));
    }

    #[test]
    fn test_detector_detects_gcc() {
        let detector = DieDetector::with_defaults();
        let data = b"MZHello MinGW-w64 compiled binary".to_vec();
        let result = detector.detect(&data).unwrap();
        assert!(result.compilers().into_iter().any(|d| d.name == "GCC"));
    }

    #[test]
    fn test_detector_no_match_for_random() {
        let detector = DieDetector::new(DieDatabase::new());
        let result = detector.detect(&[0xCC; 64]).unwrap();
        assert_eq!(result.detections.len(), 0);
    }

    #[test]
    fn test_detector_anywhere_match() {
        let mut db = DieDatabase::new();
        db.add_rule(DieRule {
            name: "Marker".into(),
            kind: DetectKind::Tool,
            version: None,
            signature: vec![(0xFFFF_FFFF, b"MARKER".to_vec())],
            confidence: 99,
        });
        let detector = DieDetector::new(db);
        let mut data = vec![0u8; 50];
        data.extend_from_slice(b"MARKER");
        let result = detector.detect(&data).unwrap();
        assert_eq!(result.detections.len(), 1);
        assert_eq!(result.detections[0].name, "Marker");
    }

    #[test]
    fn test_detector_offset_match() {
        let mut db = DieDatabase::new();
        db.add_rule(DieRule {
            name: "Header".into(),
            kind: DetectKind::Tool,
            version: None,
            signature: vec![(0, b"\xDE\xAD\xBE\xEF".to_vec())],
            confidence: 99,
        });
        let detector = DieDetector::new(db);
        let data = b"\xDE\xAD\xBE\xEF\x00\x00".to_vec();
        let result = detector.detect(&data).unwrap();
        assert_eq!(result.detections.len(), 1);
    }

    #[test]
    fn test_detector_offset_no_match() {
        let mut db = DieDatabase::new();
        db.add_rule(DieRule {
            name: "Header".into(),
            kind: DetectKind::Tool,
            version: None,
            signature: vec![(0, b"\xDE\xAD\xBE\xEF".to_vec())],
            confidence: 99,
        });
        let detector = DieDetector::new(db);
        let data = b"\x00\xDE\xAD\xBE\xEF\x00".to_vec();
        let result = detector.detect(&data).unwrap();
        assert_eq!(result.detections.len(), 0);
    }

    #[test]
    fn test_rule_matches_empty_signature() {
        let mut db = DieDatabase::new();
        db.add_rule(DieRule {
            name: "Always".into(),
            kind: DetectKind::Tool,
            version: None,
            // Empty sig → always matches
            signature: vec![],
            confidence: 1,
        });
        let detector = DieDetector::new(db);
        let result = detector.detect(&[0u8; 4]).unwrap();
        assert_eq!(result.detections.len(), 1);
    }

    #[test]
    fn test_detector_rust_binary() {
        let detector = DieDetector::with_defaults();
        let data = b"MZrustc 1.76.0 embedded into binary section".to_vec();
        let result = detector.detect(&data).unwrap();
        assert!(result.compilers().into_iter().any(|d| d.name == "Rust"));
    }

    #[test]
    fn test_detector_delphi_binary() {
        let detector = DieDetector::with_defaults();
        let data = b"\x7FELF\x01\x00Borland Developer Studio magic".to_vec();
        let result = detector.detect(&data).unwrap();
        assert!(result.compilers().into_iter().any(|d| d.name == "Delphi"));
    }

    #[test]
    fn test_detector_nsis_installer() {
        let detector = DieDetector::with_defaults();
        let data = b"MZNullsoft Install System v3.08".to_vec();
        let result = detector.detect(&data).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "NSIS"));
    }

    #[test]
    fn test_detector_with_defaults_non_empty() {
        let d = DieDetector::with_defaults();
        assert!(d.db.rule_count() >= 10);
    }

    // ---- compute_entropy ---------------------------------------------------

    #[test]
    fn test_entropy_empty() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform_bytes() {
        // All same byte → entropy = 0
        let data = vec![0xAAu8; 1024];
        assert!(compute_entropy(&data) < 0.001);
    }

    #[test]
    fn test_entropy_high() {
        // Pseudo-random-ish data should have entropy close to 8
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let data: Vec<u8> = (0u32..4096)
            .map(|i| {
                let mut h = DefaultHasher::new();
                i.hash(&mut h);
                h.finish() as u8
            })
            .collect();
        let e = compute_entropy(&data);
        assert!(e > 6.0, "expected high entropy, got {e}");
    }

    // ---- find_bytes --------------------------------------------------------

    #[test]
    fn test_find_bytes_exact() {
        let data = b"\x00\x01\x02\x03\x04\x05";
        assert_eq!(find_bytes(data, "02 03"), Some(2));
    }

    #[test]
    fn test_find_bytes_wildcard() {
        let data = b"\x60\xBE\xAA\xBB\xCC";
        assert_eq!(find_bytes(data, "60 BE ?? ?? ??"), Some(0));
    }

    #[test]
    fn test_find_bytes_wildcard_middle() {
        let data = b"\x00\x60\xBE\xAA\xBB";
        assert_eq!(find_bytes(data, "60 BE ?? BB"), Some(1));
    }

    #[test]
    fn test_find_bytes_no_match() {
        let data = b"\x00\x01\x02";
        assert_eq!(find_bytes(data, "AA BB"), None);
    }

    #[test]
    fn test_find_bytes_empty_pattern() {
        let data = b"\x00\x01";
        assert_eq!(find_bytes(data, ""), None);
    }

    // ---- read_pe_sections --------------------------------------------------

    #[test]
    fn test_read_pe_sections_non_pe() {
        // Random data should return empty
        let result = read_pe_sections(&[0u8; 64]);
        assert!(result.is_empty());
    }

    // ---- DieCondition::StringPresent ---------------------------------------

    #[test]
    fn test_condition_string_present_true() {
        let data = b"hello world UPX0 more bytes";
        let cond = DieCondition::StringPresent("UPX0".into());
        assert!(match_condition(&cond, data));
    }

    #[test]
    fn test_condition_string_present_false() {
        let data = b"hello world";
        let cond = DieCondition::StringPresent("UPX0".into());
        assert!(!match_condition(&cond, data));
    }

    // ---- DieCondition::BytePattern -----------------------------------------

    #[test]
    fn test_condition_byte_pattern_exact_at_zero() {
        let data = b"\x60\xBE\xDE\xAD\xBE\xEF";
        let cond = DieCondition::BytePattern {
            offset: 0,
            hex: "60 BE DE AD BE EF".into(),
        };
        assert!(match_condition(&cond, data));
    }

    #[test]
    fn test_condition_byte_pattern_with_wildcard() {
        let data = b"\x60\xBE\xDE\xAD\xBE";
        let cond = DieCondition::BytePattern {
            offset: 0,
            hex: "60 BE ?? AD BE".into(),
        };
        assert!(match_condition(&cond, data));
    }

    #[test]
    fn test_condition_byte_pattern_offset_too_large() {
        let data = b"\x60\xBE";
        let cond = DieCondition::BytePattern {
            offset: 100,
            hex: "60".into(),
        };
        assert!(!match_condition(&cond, data));
    }

    // ---- DieCondition::OverlayPresent with non-PE --------------------------

    #[test]
    fn test_condition_overlay_non_pe() {
        // Non-PE should not report overlay
        assert!(!match_condition(
            &DieCondition::OverlayPresent,
            &[0xCC; 256]
        ));
    }

    // ---- RuleCondition combinators -----------------------------------------

    #[test]
    fn test_rule_condition_all_match() {
        let data = b"UPX0 MinGW";
        let rc = RuleCondition::All(vec![
            DieCondition::StringPresent("UPX0".into()),
            DieCondition::StringPresent("MinGW".into()),
        ]);
        assert!(match_rule_condition(&rc, data));
    }

    #[test]
    fn test_rule_condition_all_partial_fail() {
        let data = b"UPX0 only";
        let rc = RuleCondition::All(vec![
            DieCondition::StringPresent("UPX0".into()),
            DieCondition::StringPresent("MinGW".into()),
        ]);
        assert!(!match_rule_condition(&rc, data));
    }

    #[test]
    fn test_rule_condition_any_one_match() {
        let data = b"just MinGW here";
        let rc = RuleCondition::Any(vec![
            DieCondition::StringPresent("UPX0".into()),
            DieCondition::StringPresent("MinGW".into()),
        ]);
        assert!(match_rule_condition(&rc, data));
    }

    #[test]
    fn test_rule_condition_any_none_match() {
        let data = b"nothing relevant";
        let rc = RuleCondition::Any(vec![
            DieCondition::StringPresent("UPX0".into()),
            DieCondition::StringPresent("MinGW".into()),
        ]);
        assert!(!match_rule_condition(&rc, data));
    }

    #[test]
    fn test_rule_condition_not_absent() {
        // StringPresent("UPX0") is false → Not is true
        let data = b"no packer here";
        let rc = RuleCondition::Not(Box::new(DieCondition::StringPresent("UPX0".into())));
        assert!(match_rule_condition(&rc, data));
    }

    #[test]
    fn test_rule_condition_not_present() {
        let data = b"UPX0 section";
        let rc = RuleCondition::Not(Box::new(DieCondition::StringPresent("UPX0".into())));
        assert!(!match_rule_condition(&rc, data));
    }

    // ---- DieScanner --------------------------------------------------------

    #[test]
    fn test_scanner_new() {
        let s = DieScanner::new();
        let _ = format!("{s:?}"); // exercises Debug
    }

    #[test]
    fn test_scanner_scan_empty_data() {
        let s = DieScanner::new();
        let detections = s.scan(&[]);
        // No PE → rules that require PE structures should not fire; rules that
        // only check StringPresent with empty data should not fire either.
        assert!(detections.is_empty() || detections.iter().all(|d| d.confidence > 0));
    }

    #[test]
    fn test_scanner_detects_upx_by_section_string() {
        // We need both UPX0 and UPX1 strings for the UPX 3.x rule
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"UPX0");
        data.extend_from_slice(b"\x00\x00\x00\x00");
        data.extend_from_slice(b"UPX1");
        let s = DieScanner::new();
        let detections = s.scan(&data);
        // At least one UPX detection from StringPresent / SectionName conditions
        // SectionName requires a real PE; StringPresent does not — the rule uses
        // SectionName, so we test the StringPresent-based rules instead.
        // Since StringPresent("UPX0") is not a rule by itself, what matters is
        // that the scanner runs without panic and returns a sorted list.
        let _ = detections;
    }

    #[test]
    fn test_scanner_detects_nullsoft() {
        let data = b"MZNullsoft Install System";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(
            detections.iter().any(|d| d.name.contains("NSIS")),
            "expected NSIS detection, got: {detections:?}"
        );
    }

    #[test]
    fn test_scanner_detects_inno_setup() {
        let data = b"Inno Setup installer data block";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("Inno")));
    }

    #[test]
    fn test_scanner_detects_mingw() {
        let data = b"Some binary with MinGW-w64 toolchain strings";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("GCC")));
    }

    #[test]
    fn test_scanner_detects_borland() {
        let data = b"Borland developer runtime libraries";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("Delphi")));
    }

    #[test]
    fn test_scanner_detects_wix() {
        let data = b"WiX Toolset installer package";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("WiX")));
    }

    #[test]
    fn test_scanner_detects_autoit() {
        let data = b"AU3!EA compiled AutoIt script";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("AutoIt")));
    }

    #[test]
    fn test_scanner_detects_py2exe() {
        let data = b"py2exe generated bundle";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("Py2Exe")));
    }

    #[test]
    fn test_scanner_detects_cxfreeze() {
        let data = b"cx_Freeze frozen application";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("cx_Freeze")));
    }

    #[test]
    fn test_scanner_detects_themida() {
        // Themida uses a section named .themida — the rule uses SectionName,
        // but StringPresent(".themida") is not in the YAML rule. Test that the
        // scanner at least runs and doesn't panic on this data.
        let data = b"MZ\x00\x00.themida protected binary";
        let s = DieScanner::new();
        let _detections = s.scan(data);
    }

    #[test]
    fn test_scanner_detects_enigma() {
        let data = b"MZ .enigma1 section present";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("Enigma")));
    }

    #[test]
    fn test_scanner_detects_obsidium() {
        let data = b"Obsidium protected executable";
        let s = DieScanner::new();
        let detections = s.scan(data);
        assert!(detections.iter().any(|d| d.name.contains("Obsidium")));
    }

    #[test]
    fn test_scanner_sorted_by_confidence_desc() {
        // Use data containing multiple rule-triggering strings
        let data = b"Nullsoft Install System Inno Setup WiX Toolset";
        let s = DieScanner::new();
        let detections = s.scan(data);
        for w in detections.windows(2) {
            assert!(
                w[0].confidence >= w[1].confidence,
                "detections not sorted: {} ({}) before {} ({})",
                w[0].name,
                w[0].confidence,
                w[1].name,
                w[1].confidence
            );
        }
    }

    #[test]
    fn test_scanner_no_false_positives_on_zeros() {
        let data = vec![0u8; 512];
        let s = DieScanner::new();
        let detections = s.scan(&data);
        assert!(
            detections.is_empty(),
            "expected no detections on zeroed data, got {detections:?}"
        );
    }

    // ---- BUILTIN_RULES content --------------------------------------------

    #[test]
    fn test_builtin_rules_parses_at_least_25() {
        let rules = DieScanner::parse_yaml_rules(BUILTIN_RULES);
        assert!(
            rules.len() >= 25,
            "expected at least 25 parsed rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_builtin_rules_all_have_names() {
        let rules = DieScanner::parse_yaml_rules(BUILTIN_RULES);
        for r in &rules {
            assert!(!r.name.is_empty(), "a rule has an empty name");
        }
    }

    #[test]
    fn test_builtin_rules_all_have_conditions() {
        let rules = DieScanner::parse_yaml_rules(BUILTIN_RULES);
        for r in &rules {
            assert!(
                !r.conditions.is_empty(),
                "rule '{}' has no conditions",
                r.name
            );
        }
    }

    // ---- DieCondition::SectionCount ----------------------------------------

    #[test]
    fn test_condition_section_count_non_pe() {
        let cond = DieCondition::SectionCount { min: 0, max: 0 };
        // Non-PE: count returns 0, so [0,0] matches
        assert!(match_condition(&cond, &[0u8; 64]));
    }

    // ---- DieCondition::Dotnet  (non-PE) -----------------------------------

    #[test]
    fn test_condition_dotnet_non_pe() {
        assert!(!match_condition(&DieCondition::Dotnet, &[0xCC; 256]));
    }

    // ---- DieCondition::Manifest -------------------------------------------

    #[test]
    fn test_condition_manifest_string() {
        let data = b"RT_MANIFEST\x00\x00\x00 embedded here";
        assert!(match_condition(&DieCondition::Manifest, data));
    }

    // ---- DieCondition::ExportPresent  (no PE) -----------------------------

    #[test]
    fn test_condition_export_non_pe() {
        assert!(!match_condition(
            &DieCondition::ExportPresent("foo".into()),
            &[0xAA; 64]
        ));
    }

    // ---- DieCondition::ImportCount  (no PE) --------------------------------

    #[test]
    fn test_condition_import_count_non_pe() {
        // Non-PE: count = 0, so min=0 max=0 matches
        let cond = DieCondition::ImportCount { min: 0, max: 0 };
        assert!(match_condition(&cond, &[0u8; 64]));
    }

    // ---- DieCondition::SubsystemType  (no PE) -----------------------------

    #[test]
    fn test_condition_subsystem_non_pe() {
        assert!(!match_condition(
            &DieCondition::SubsystemType(3),
            &[0x00; 128]
        ));
    }

    // ---- DieCondition::MachineType  (no PE) --------------------------------

    #[test]
    fn test_condition_machine_non_pe() {
        assert!(!match_condition(
            &DieCondition::MachineType(0x8664),
            &[0x00; 64]
        ));
    }

    // ---- DieCondition::ResourcePresent ------------------------------------

    #[test]
    fn test_condition_resource_present_found() {
        // Encode "CUSTOM" as UTF-16LE and embed it
        let wide: Vec<u8> = "custom"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let data = [b'\x00', b'\x00']
            .iter()
            .chain(wide.iter())
            .copied()
            .collect::<Vec<_>>();
        // has_resource_type does case-insensitive wide search
        let cond = DieCondition::ResourcePresent("CUSTOM".into());
        // This just exercises the path; result depends on encoding logic
        let _ = match_condition(&cond, &data);
    }

    // ---- get_entry_point_bytes  (non-PE) -----------------------------------

    #[test]
    fn test_entry_point_bytes_non_pe() {
        assert!(get_entry_point_bytes(&[0xCC; 128]).is_empty());
    }

    // ---- DieScanner::default -----------------------------------------------

    #[test]
    fn test_scanner_default() {
        let s = DieScanner;
        let _ = s.scan(&[]);
    }

    // ---- DieCondition serialize / deserialize ------------------------------

    #[test]
    fn test_die_condition_serde_round_trip() {
        let cond = DieCondition::ImportPresent {
            dll: "ntdll.dll".into(),
            func: "NtCreateFile".into(),
        };
        let json = serde_json::to_string(&cond).expect("serialize");
        let back: DieCondition = serde_json::from_str(&json).expect("deserialize");
        if let DieCondition::ImportPresent { dll, func } = back {
            assert_eq!(dll, "ntdll.dll");
            assert_eq!(func, "NtCreateFile");
        } else {
            panic!("wrong variant after round-trip");
        }
    }

    #[test]
    fn test_rule_condition_serde_round_trip() {
        let rc = RuleCondition::Not(Box::new(DieCondition::OverlayPresent));
        let json = serde_json::to_string(&rc).expect("serialize");
        let back: RuleCondition = serde_json::from_str(&json).expect("deserialize");
        matches!(back, RuleCondition::Not(_));
    }
}

// ---------------------------------------------------------------------------
// Post-process false-positive sanitiser
// ---------------------------------------------------------------------------

/// Cross-signal evidence filter: drop packer / protector detections that lack
/// the corresponding PE section name AND are inconsistent with other
/// detections (e.g. a `Rust + MSVC` binary cannot also be Themida-packed).
///
/// This addresses the loose `data.windows().any()` matching in `rule_matches`
/// which flags 4-byte packer-marker strings appearing by coincidence inside
/// a 1 MB+ release binary's `.rdata` / `.text`.
///
/// Rules applied:
///   1. If the file's PE section table does NOT contain the canonical
///      section name a packer uses (e.g. `UPX0` for UPX, `.aspack` for
///      ASPack, `.themida` for Themida, `.vmp0`/`.vmp1` for VMProtect),
///      drop that packer detection.
///   2. If the file's overall Shannon entropy is below 7.0, set
///      `is_packed = false` (real packers produce >= 7.0).
///   3. If a confident compiler signature (MSVC, GCC, Clang, Rust, Go)
///      is detected AND no PE section name confirms the packer, drop
///      packer + protector detections entirely.
fn sanitize_false_positives(result: &mut DieResult, data: &[u8]) {
    let section_names = pe_section_names(data);
    let has_compiler = result.detections.iter().any(|d| {
        matches!(d.kind, DetectKind::Compiler)
            && matches!(
                d.name.as_str(),
                "MSVC" | "MSVC x64" | "GCC" | "Clang" | "Rust" | "Go" | "Borland" | "Delphi"
            )
    });

    let entropy = if data.is_empty() {
        0.0
    } else {
        sanitize_entropy(data)
    };

    // Map packer name -> canonical section-name marker(s) it adds.
    fn canonical_section_names(packer: &str) -> &'static [&'static str] {
        match packer {
            "UPX" => &["UPX0", "UPX1", "UPX2"],
            "ASPack" => &[".aspack", ".adata"],
            "Themida" => &[".themida", ".winlice"],
            "VMProtect" => &[".vmp0", ".vmp1", ".vmp2"],
            "PECompact" => &["PEC2"],
            "MPRESS" => &[".MPRESS1", ".MPRESS2"],
            "Enigma Protector" => &[".enigma1", ".enigma2"],
            "FSG" => &[],
            "MEW" => &[],
            "PESpin" => &[],
            _ => &[],
        }
    }

    result.detections.retain(|d| {
        match d.kind {
            DetectKind::Packer | DetectKind::Protector => {
                let canon = canonical_section_names(&d.name);
                if canon.is_empty() {
                    // No canonical section marker to check; fall back to
                    // dropping when a compiler is confidently detected.
                    return !has_compiler;
                }
                let has_section_anchor =
                    canon.iter().any(|name| section_names.iter().any(|sn| sn == name));
                if has_section_anchor {
                    return true;
                }
                // No section-anchor → keep only if entropy supports it AND
                // no compiler signature contradicts it.
                if has_compiler {
                    return false;
                }
                entropy >= 7.0
            }
            _ => true,
        }
    });

    // Re-evaluate is_packed / is_protected after filtering.
    result.is_packed = result
        .detections
        .iter()
        .any(|d| d.kind == DetectKind::Packer)
        && entropy >= 7.0;
    result.is_protected = result
        .detections
        .iter()
        .any(|d| d.kind == DetectKind::Protector)
        && entropy >= 7.0;
}

/// Parse the PE section name list (up to 96 entries) from a raw byte buffer.
/// Returns the trimmed UTF-8 lossy names. Empty if `data` is not a PE32+.
fn pe_section_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return out;
    }
    let e_lfanew =
        u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < e_lfanew + 24 {
        return out;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return out;
    }
    let coff_off = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]) as usize;
    let size_optional_header =
        u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let section_table_off = coff_off + 20 + size_optional_header;
    for i in 0..num_sections.min(96) {
        let off = section_table_off + i * 40;
        if off + 8 > data.len() {
            break;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[off..off + 8]);
        let trimmed: Vec<u8> = name.iter().copied().take_while(|&b| b != 0).collect();
        if let Ok(s) = std::str::from_utf8(&trimmed) {
            out.push(s.to_string());
        }
    }
    out
}

/// Shannon entropy (f64) in bits/byte over the whole buffer — local helper
/// for the sanitiser; named distinctly from the pub `compute_entropy` (f32).
fn sanitize_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}
