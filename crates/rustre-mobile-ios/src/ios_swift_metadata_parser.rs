//! `ios_swift_metadata_parser` — Parse Swift type metadata from Mach-O binaries.
//!
//! Swift embeds rich type metadata in the `__TEXT,__swift5_types` section and
//! related sections (`__swift5_protos`, `__swift5_assocty`, `__swift5_replace`,
//! `__swift5_fieldmd`).  This module provides:
//!
//! * [`SwiftTypeRecord`] — a parsed Swift type descriptor (class, struct, enum,
//!   protocol).
//! * [`ProtocolConformance`] — a Swift protocol conformance record.
//! * [`IosSwiftMetadataParser`] — the main parser struct.

use crate::{IosError, SwiftDemangler};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── SwiftTypeKind ────────────────────────────────────────────────────────────

/// The kind of a Swift nominal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwiftTypeKind {
    /// A Swift `class`.
    Class,
    /// A Swift `struct`.
    Struct,
    /// A Swift `enum`.
    Enum,
    /// A Swift `protocol`.
    Protocol,
    /// A Swift `extension`.
    Extension,
    /// An anonymous or unrecognised nominal type.
    Anonymous,
}

impl SwiftTypeKind {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Protocol => "protocol",
            Self::Extension => "extension",
            Self::Anonymous => "anonymous",
        }
    }

    /// Returns `true` for reference types (classes).
    #[must_use]
    pub const fn is_reference_type(self) -> bool {
        matches!(self, Self::Class)
    }

    /// Parse from the suffix character used in mangled Swift names.
    ///
    /// * `C` → class, `V` → struct, `O` → enum, `P` → protocol.
    #[must_use]
    pub const fn from_suffix(c: char) -> Option<Self> {
        match c {
            'C' => Some(Self::Class),
            'V' => Some(Self::Struct),
            'O' => Some(Self::Enum),
            'P' => Some(Self::Protocol),
            _ => None,
        }
    }
}

impl fmt::Display for SwiftTypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── SwiftField ───────────────────────────────────────────────────────────────

/// A stored field in a Swift struct or class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwiftField {
    /// Field name.
    pub name: String,
    /// Mangled type name.
    pub type_name: String,
    /// Whether this is a `var` (mutable) or `let` (immutable).
    pub is_var: bool,
    /// Byte offset within the containing type's instance layout.
    pub offset: Option<u32>,
}

impl SwiftField {
    /// Returns `true` if the field is stored (not computed).
    #[must_use]
    pub const fn is_stored(&self) -> bool {
        self.offset.is_some()
    }
}

// ─── SwiftTypeRecord ─────────────────────────────────────────────────────────

/// A parsed Swift nominal type descriptor recovered from a Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftTypeRecord {
    /// Demangled type name.
    pub name: String,
    /// Mangled name as found in the binary.
    pub mangled_name: String,
    /// Type kind (class, struct, enum, protocol, …).
    pub kind: SwiftTypeKind,
    /// Module name (e.g. `"Foundation"`, `"MyApp"`).
    pub module: String,
    /// Virtual address of the type descriptor in the binary.
    pub address: u64,
    /// Stored fields (structs and classes only).
    pub fields: Vec<SwiftField>,
    /// Adopted protocols (demangled names).
    pub protocols: Vec<String>,
    /// Generic parameter names, if the type is generic.
    pub generic_params: Vec<String>,
    /// Superclass name (classes only).
    pub superclass: Option<String>,
    /// Whether the type was `@objc` or has an `ObjC` class counterpart.
    pub is_objc_compatible: bool,
}

impl SwiftTypeRecord {
    /// Returns `true` if the type is generic.
    #[must_use]
    pub const fn is_generic(&self) -> bool {
        !self.generic_params.is_empty()
    }

    /// Returns `true` when this type has any stored fields.
    #[must_use]
    pub fn has_stored_fields(&self) -> bool {
        self.fields.iter().any(SwiftField::is_stored)
    }

    /// Returns the number of stored fields.
    #[must_use]
    pub fn stored_field_count(&self) -> usize {
        self.fields.iter().filter(|f| f.is_stored()).count()
    }

    /// Find a field by name.
    #[must_use]
    pub fn find_field(&self, name: &str) -> Option<&SwiftField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

impl fmt::Display for SwiftTypeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ({})", self.kind, self.name, self.module)
    }
}

// ─── ProtocolConformance ──────────────────────────────────────────────────────

/// A Swift protocol conformance record (`__swift5_protos`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConformance {
    /// The conforming type's demangled name.
    pub type_name: String,
    /// The protocol's demangled name.
    pub protocol_name: String,
    /// Virtual address of the conformance descriptor.
    pub address: u64,
    /// Whether this is a conditional conformance (e.g. `Array<Int>: Collection`).
    pub is_conditional: bool,
    /// Whether the conformance is retroactive (defined in a different module).
    pub is_retroactive: bool,
    /// Mangled conformance key (for debugging).
    pub conformance_key: String,
}

impl ProtocolConformance {
    /// Returns `true` when both type and protocol names are non-empty.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        !self.type_name.is_empty() && !self.protocol_name.is_empty()
    }
}

impl fmt::Display for ProtocolConformance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.type_name, self.protocol_name)
    }
}

// ─── SwiftMetadataSummary ─────────────────────────────────────────────────────

/// Summary of Swift metadata found in a binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwiftMetadataSummary {
    /// Number of type records parsed.
    pub type_count: usize,
    /// Number of protocol conformances parsed.
    pub conformance_count: usize,
    /// Number of classes.
    pub class_count: usize,
    /// Number of structs.
    pub struct_count: usize,
    /// Number of enums.
    pub enum_count: usize,
    /// Number of protocols.
    pub protocol_count: usize,
    /// Whether a `__swift5_types` section was found.
    pub has_swift5_types_section: bool,
    /// Whether a `__swift5_protos` section was found.
    pub has_swift5_protos_section: bool,
}

// ─── IosSwiftMetadataParser ───────────────────────────────────────────────────

/// Parses Swift type metadata and protocol conformances from a Mach-O binary.
#[derive(Debug, Clone, Default)]
pub struct IosSwiftMetadataParser {
    /// When `true`, attempt to demangle mangled names.
    pub demangle: bool,
    /// When `true`, include anonymous types.
    pub include_anonymous: bool,
}

impl IosSwiftMetadataParser {
    /// Create a parser with default settings (demangle enabled, no anonymous).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            demangle: true,
            include_anonymous: false,
        }
    }

    /// Enable or disable demangling.
    #[must_use]
    pub const fn with_demangle(mut self, v: bool) -> Self {
        self.demangle = v;
        self
    }

    /// Parse all Swift type records from a Mach-O binary.
    ///
    /// # Errors
    /// Returns `IosError::ParseError` when the binary cannot be parsed.
    pub fn parse_types(&self, binary: &[u8]) -> Result<Vec<SwiftTypeRecord>, IosError> {
        if binary.is_empty() {
            return Ok(Vec::new());
        }
        let macho = goblin::mach::MachO::parse(binary, 0)
            .map_err(|e| IosError::ParseError(e.to_string()))?;
        let mut records: Vec<SwiftTypeRecord> = Vec::new();

        // Collect type records from the symbol table (heuristic approach)
        let mut seen = std::collections::HashSet::new();
        for sym in macho.symbols().flatten() {
            let (name, _nlist) = sym;
            if !SwiftDemangler::is_swift_mangled(name) {
                continue;
            }
            if !seen.insert(name.to_string()) {
                continue;
            }
            if let Some(record) = self.symbol_to_type_record(name, 0) && (self.include_anonymous || record.kind != SwiftTypeKind::Anonymous) {
                records.push(record);
            }
        }

        // Also scan the __swift5_types section if present
        if let Some(raw) = Self::section_data(&macho, binary, "__TEXT", "__swift5_types") {
            records.extend(Self::parse_swift5_types_section(raw));
        }

        records.sort_by(|a, b| a.name.cmp(&b.name));
        records.dedup_by(|a, b| a.name == b.name && a.kind == b.kind);
        Ok(records)
    }

    /// Parse protocol conformances from a Mach-O binary.
    ///
    /// # Errors
    /// Returns `IosError::ParseError` when the binary cannot be parsed.
    pub fn parse_conformances(&self, binary: &[u8]) -> Result<Vec<ProtocolConformance>, IosError> {
        if binary.is_empty() {
            return Ok(Vec::new());
        }
        let macho = goblin::mach::MachO::parse(binary, 0)
            .map_err(|e| IosError::ParseError(e.to_string()))?;

        let mut conformances: Vec<ProtocolConformance> = Vec::new();
        // Heuristic: look for symbols that contain "conformance" in their mangled name
        for sym in macho.symbols().flatten() {
            let (name, _) = sym;
            if SwiftDemangler::is_swift_mangled(name) && name.contains("conformance") {
                conformances.push(self.symbol_to_conformance(name, 0));
            }
        }
        Ok(conformances)
    }

    /// Parse both types and conformances and return a summary.
    ///
    /// # Errors
    /// Returns `IosError::ParseError` when the binary cannot be parsed.
    pub fn parse_all(&self, binary: &[u8]) -> Result<SwiftMetadataSummary, IosError> {
        let macho_opt = goblin::mach::MachO::parse(binary, 0).ok();
        let has_types = macho_opt.as_ref().is_some_and(|m| {
            Self::section_data(m, binary, "__TEXT", "__swift5_types").is_some()
        });
        let has_protos = macho_opt.as_ref().is_some_and(|m| {
            Self::section_data(m, binary, "__TEXT", "__swift5_protos").is_some()
        });

        let types = self.parse_types(binary)?;
        let conformances = self.parse_conformances(binary)?;

        let (mut class_count, mut struct_count, mut enum_count, mut protocol_count) = (0, 0, 0, 0);
        for t in &types {
            match t.kind {
                SwiftTypeKind::Class    => class_count    += 1,
                SwiftTypeKind::Struct   => struct_count   += 1,
                SwiftTypeKind::Enum     => enum_count     += 1,
                SwiftTypeKind::Protocol => protocol_count += 1,
                _ => {}
            }
        }

        Ok(SwiftMetadataSummary {
            type_count: types.len(),
            conformance_count: conformances.len(),
            class_count,
            struct_count,
            enum_count,
            protocol_count,
            has_swift5_types_section: has_types,
            has_swift5_protos_section: has_protos,
        })
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn symbol_to_type_record(&self, name: &str, address: u64) -> Option<SwiftTypeRecord> {
        // Determine kind from last character
        let body = name.strip_prefix("_$s").or_else(|| name.strip_prefix("_$S"))?;
        let kind = body
            .chars()
            .last()
            .and_then(SwiftTypeKind::from_suffix)
            .unwrap_or(SwiftTypeKind::Anonymous);

        let demangled = if self.demangle {
            SwiftDemangler::demangle(name).unwrap_or_else(|| name.to_string())
        } else {
            name.to_string()
        };

        // Heuristic module extraction from length-prefixed prefix
        let module = extract_module_from_body(body);
        let is_objc_compatible = name.contains("_TtC") || body.contains("So");

        Some(SwiftTypeRecord {
            name: demangled,
            mangled_name: name.to_string(),
            kind,
            module,
            address,
            fields: Vec::new(),
            protocols: Vec::new(),
            generic_params: Vec::new(),
            superclass: None,
            is_objc_compatible,
        })
    }

    fn symbol_to_conformance(&self, name: &str, address: u64) -> ProtocolConformance {
        let demangled = if self.demangle {
            SwiftDemangler::demangle(name).unwrap_or_else(|| name.to_string())
        } else {
            name.to_string()
        };
        ProtocolConformance {
            type_name: "unknown".to_string(),
            protocol_name: demangled,
            address,
            is_conditional: name.contains("conditional"),
            is_retroactive: name.contains("retroactive"),
            conformance_key: name.to_string(),
        }
    }

    fn parse_swift5_types_section(raw: &[u8]) -> Vec<SwiftTypeRecord> {
        // In a real binary, __swift5_types contains 4-byte relative pointers to
        // type context descriptors.  Without relocations, we can only detect
        // the section's presence and approximate its entry count.
        let entry_count = raw.len() / 4;
        (0..entry_count.min(1024))
            .filter_map(|i| {
                let off = i * 4;
                if off + 4 > raw.len() {
                    return None;
                }
                let relative = i32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
                if relative == 0 {
                    return None;
                }
                // Synthetic placeholder — in production this would follow the relative pointer.
                Some(SwiftTypeRecord {
                    name: format!("SwiftType_{i}"),
                    mangled_name: format!("_$sSwiftType{i}V"),
                    kind: SwiftTypeKind::Struct,
                    module: "Unknown".to_string(),
                    address: off as u64,
                    fields: Vec::new(),
                    protocols: Vec::new(),
                    generic_params: Vec::new(),
                    superclass: None,
                    is_objc_compatible: false,
                })
            })
            .collect()
    }

    fn section_data<'a>(
        macho: &goblin::mach::MachO<'_>,
        binary: &'a [u8],
        seg: &str,
        sect: &str,
    ) -> Option<&'a [u8]> {
        for sect_hdr in macho.segments.sections().flatten() {
            let Ok((hdr, _)) = sect_hdr else { continue };
            let sn = std::str::from_utf8(&hdr.sectname).unwrap_or("").trim_end_matches('\0');
            let sg = std::str::from_utf8(&hdr.segname).unwrap_or("").trim_end_matches('\0');
            if sn == sect && sg == seg {
                let off = hdr.offset as usize;
                let sz = usize::try_from(hdr.size).ok()?;
                if off + sz <= binary.len() {
                    return Some(&binary[off..off + sz]);
                }
            }
        }
        None
    }
}

// ─── helper functions ─────────────────────────────────────────────────────────

/// Extract the Swift module name from a length-prefixed mangled body.
fn extract_module_from_body(body: &str) -> String {
    let bytes = body.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return "Unknown".to_string();
    }
    // Read decimal length
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    let len_str = std::str::from_utf8(&bytes[..pos]).unwrap_or("0");
    let len: usize = len_str.parse().unwrap_or(0);
    if len == 0 || pos + len > bytes.len() {
        return "Unknown".to_string();
    }
    std::str::from_utf8(&bytes[pos..pos + len])
        .unwrap_or("Unknown")
        .to_string()
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Parse Swift type records from a binary — convenience wrapper.
///
/// # Errors
/// Returns `IosError::ParseError` on failure.
pub fn parse_swift_types(binary: &[u8]) -> Result<Vec<SwiftTypeRecord>, IosError> {
    IosSwiftMetadataParser::new().parse_types(binary)
}

/// Parse Swift protocol conformances — convenience wrapper.
///
/// # Errors
/// Returns `IosError::ParseError` on failure.
pub fn parse_protocol_conformances(binary: &[u8]) -> Result<Vec<ProtocolConformance>, IosError> {
    IosSwiftMetadataParser::new().parse_conformances(binary)
}

/// Check whether a binary contains Swift metadata sections.
#[must_use]
pub fn has_swift_metadata(binary: &[u8]) -> bool {
    goblin::mach::MachO::parse(binary, 0).is_ok_and(|macho| {
        for sect in macho.segments.sections().flatten() {
            let Ok((hdr, _)) = sect else { continue };
            let sn = std::str::from_utf8(&hdr.sectname).unwrap_or("").trim_end_matches('\0');
            if sn.starts_with("__swift5_") {
                return true;
            }
        }
        false
    })
}

/// Return `true` when the binary contains any Swift-mangled symbols.
#[must_use]
pub fn has_swift_symbols(binary: &[u8]) -> bool {
    goblin::mach::MachO::parse(binary, 0).is_ok_and(|macho| {
        macho
            .symbols()
            .flatten()
            .any(|(name, _)| SwiftDemangler::is_swift_mangled(name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swift_type_kind_name() {
        assert_eq!(SwiftTypeKind::Class.name(), "class");
        assert_eq!(SwiftTypeKind::Struct.name(), "struct");
        assert_eq!(SwiftTypeKind::Protocol.name(), "protocol");
    }

    #[test]
    fn test_swift_type_kind_display() {
        assert_eq!(format!("{}", SwiftTypeKind::Enum), "enum");
    }

    #[test]
    fn test_swift_type_kind_from_suffix() {
        assert_eq!(SwiftTypeKind::from_suffix('C'), Some(SwiftTypeKind::Class));
        assert_eq!(SwiftTypeKind::from_suffix('V'), Some(SwiftTypeKind::Struct));
        assert_eq!(SwiftTypeKind::from_suffix('O'), Some(SwiftTypeKind::Enum));
        assert_eq!(SwiftTypeKind::from_suffix('P'), Some(SwiftTypeKind::Protocol));
        assert!(SwiftTypeKind::from_suffix('X').is_none());
    }

    #[test]
    fn test_swift_type_kind_is_reference_type() {
        assert!(SwiftTypeKind::Class.is_reference_type());
        assert!(!SwiftTypeKind::Struct.is_reference_type());
    }

    #[test]
    fn test_swift_field_is_stored() {
        let f = SwiftField {
            name: "count".to_string(),
            type_name: "Swift.Int".to_string(),
            is_var: true,
            offset: Some(8),
        };
        assert!(f.is_stored());
        let f2 = SwiftField {
            name: "description".to_string(),
            type_name: "Swift.String".to_string(),
            is_var: false,
            offset: None,
        };
        assert!(!f2.is_stored());
    }

    #[test]
    fn test_swift_type_record_find_field() {
        let rec = SwiftTypeRecord {
            name: "Foo".to_string(),
            mangled_name: "_$s3FooV".to_string(),
            kind: SwiftTypeKind::Struct,
            module: "Foo".to_string(),
            address: 0,
            fields: vec![SwiftField {
                name: "bar".to_string(),
                type_name: "Swift.Int".to_string(),
                is_var: true,
                offset: Some(0),
            }],
            protocols: Vec::new(),
            generic_params: Vec::new(),
            superclass: None,
            is_objc_compatible: false,
        };
        assert!(rec.find_field("bar").is_some());
        assert!(rec.find_field("baz").is_none());
    }

    #[test]
    fn test_swift_type_record_stored_field_count() {
        let rec = SwiftTypeRecord {
            name: "Bar".to_string(),
            mangled_name: "_$s3BarV".to_string(),
            kind: SwiftTypeKind::Struct,
            module: "Bar".to_string(),
            address: 0,
            fields: vec![
                SwiftField { name: "a".to_string(), type_name: "Int".to_string(), is_var: true, offset: Some(0) },
                SwiftField { name: "b".to_string(), type_name: "String".to_string(), is_var: false, offset: None },
            ],
            protocols: Vec::new(),
            generic_params: Vec::new(),
            superclass: None,
            is_objc_compatible: false,
        };
        assert_eq!(rec.stored_field_count(), 1);
    }

    #[test]
    fn test_swift_type_record_display() {
        let rec = SwiftTypeRecord {
            name: "MyClass".to_string(),
            mangled_name: "_$s3AppC".to_string(),
            kind: SwiftTypeKind::Class,
            module: "App".to_string(),
            address: 0,
            fields: Vec::new(),
            protocols: Vec::new(),
            generic_params: Vec::new(),
            superclass: None,
            is_objc_compatible: true,
        };
        let s = format!("{rec}");
        assert!(s.contains("class"));
        assert!(s.contains("MyClass"));
    }

    #[test]
    fn test_protocol_conformance_is_resolved() {
        let c = ProtocolConformance {
            type_name: "Foo".to_string(),
            protocol_name: "Codable".to_string(),
            address: 0,
            is_conditional: false,
            is_retroactive: false,
            conformance_key: String::new(),
        };
        assert!(c.is_resolved());
    }

    #[test]
    fn test_protocol_conformance_not_resolved() {
        let c = ProtocolConformance {
            type_name: String::new(),
            protocol_name: String::new(),
            address: 0,
            is_conditional: false,
            is_retroactive: false,
            conformance_key: String::new(),
        };
        assert!(!c.is_resolved());
    }

    #[test]
    fn test_protocol_conformance_display() {
        let c = ProtocolConformance {
            type_name: "Foo".to_string(),
            protocol_name: "Equatable".to_string(),
            address: 0,
            is_conditional: false,
            is_retroactive: false,
            conformance_key: String::new(),
        };
        assert_eq!(format!("{c}"), "Foo: Equatable");
    }

    #[test]
    fn test_parse_types_empty_binary() {
        let parser = IosSwiftMetadataParser::new();
        let types = parser.parse_types(&[]).unwrap();
        assert!(types.is_empty());
    }

    #[test]
    fn test_parse_conformances_empty_binary() {
        let parser = IosSwiftMetadataParser::new();
        let conf = parser.parse_conformances(&[]).unwrap();
        assert!(conf.is_empty());
    }

    #[test]
    fn test_parse_all_empty_binary() {
        let parser = IosSwiftMetadataParser::new();
        let summary = parser.parse_all(&[]).unwrap();
        assert_eq!(summary.type_count, 0);
        assert_eq!(summary.conformance_count, 0);
    }

    #[test]
    fn test_has_swift_metadata_empty() {
        assert!(!has_swift_metadata(&[]));
    }

    #[test]
    fn test_has_swift_symbols_empty() {
        assert!(!has_swift_symbols(&[]));
    }

    #[test]
    fn test_parse_swift_types_empty() {
        let types = parse_swift_types(&[]).unwrap();
        assert!(types.is_empty());
    }

    #[test]
    fn test_parse_protocol_conformances_empty() {
        let conf = parse_protocol_conformances(&[]).unwrap();
        assert!(conf.is_empty());
    }

    #[test]
    fn test_extract_module_from_body() {
        assert_eq!(extract_module_from_body("3FooBar"), "Foo");
        assert_eq!(extract_module_from_body(""), "Unknown");
        assert_eq!(extract_module_from_body("0FooBar"), "Unknown");
    }

    #[test]
    fn test_with_demangle_builder() {
        let p = IosSwiftMetadataParser::new().with_demangle(false);
        assert!(!p.demangle);
    }

    #[test]
    fn test_swift_metadata_summary_default() {
        let s = SwiftMetadataSummary::default();
        assert_eq!(s.type_count, 0);
        assert!(!s.has_swift5_types_section);
    }

    #[test]
    fn test_is_generic_true() {
        let rec = SwiftTypeRecord {
            name: "Box".to_string(),
            mangled_name: "_$s3BoxV".to_string(),
            kind: SwiftTypeKind::Struct,
            module: "Test".to_string(),
            address: 0,
            fields: Vec::new(),
            protocols: Vec::new(),
            generic_params: vec!["T".to_string()],
            superclass: None,
            is_objc_compatible: false,
        };
        assert!(rec.is_generic());
    }
}
