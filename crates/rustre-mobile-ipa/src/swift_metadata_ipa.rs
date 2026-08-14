//! Swift metadata analysis for IPA binaries.
//!
//! Extracts and parses Swift reflection metadata from Mach-O binaries:
//! * Type metadata (class, struct, enum descriptors).
//! * Protocol witness tables.
//! * Swift mangled name demangling.
//! * Class hierarchy reconstruction.
//! * `swift_once` initializer symbols.
//!
//! The Swift runtime embeds metadata in several Mach-O sections:
//! * `__TEXT,__swift5_types` — type descriptors.
//! * `__TEXT,__swift5_proto` — protocol conformances.
//! * `__TEXT,__swift5_protos` — protocol descriptors.
//! * `__DATA,__objc_classlist` — `ObjC` class list (for `@objc` Swift classes).
//! * `__DATA,__swift_hooks` — Swift runtime hooks.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// SwiftError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from Swift metadata extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwiftError {
    NoSwiftMetadata,
    ParseError(String),
    DemanglingFailed(String),
    Truncated,
}

impl std::fmt::Display for SwiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSwiftMetadata => write!(f, "no Swift metadata sections found"),
            Self::ParseError(s) => write!(f, "Swift metadata parse error: {s}"),
            Self::DemanglingFailed(s) => write!(f, "demangling failed: {s}"),
            Self::Truncated => write!(f, "Swift metadata truncated"),
        }
    }
}

impl std::error::Error for SwiftError {}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of a Swift type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiftKind {
    Class,
    Struct,
    Enum,
    Protocol,
    Extension,
    OpaqueType,
    Unknown(u8),
}

impl SwiftKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x1F {
            1 => Self::Struct,
            2 => Self::Enum,
            3 => Self::Class,
            14 => Self::Protocol,
            16 => Self::Extension,
            _ => Self::Unknown((flags & 0x1F) as u8),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Protocol => "protocol",
            Self::Extension => "extension",
            Self::OpaqueType => "opaque",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftType
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Swift type descriptor.
#[derive(Debug, Clone)]
pub struct SwiftType {
    /// Fully qualified mangled name (e.g. `$s6MyApp9MyStructV`).
    pub mangled_name: String,
    /// Demangled name (e.g. `MyApp.MyStruct`).
    pub demangled_name: String,
    /// Module name.
    pub module: String,
    /// Base name (without module).
    pub base_name: String,
    /// Type kind.
    pub kind: SwiftKind,
    /// Virtual address of the descriptor in the binary.
    pub descriptor_va: u64,
    /// Number of fields (struct members / enum cases / class ivars).
    pub n_fields: u32,
    /// Filed names, if available.
    pub fields: Vec<String>,
    /// Superclass mangled name (for classes).
    pub superclass: Option<String>,
    /// Whether the class is `@objc`.
    pub is_objc: bool,
    /// Whether the type is generic.
    pub is_generic: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftConformance
// ─────────────────────────────────────────────────────────────────────────────

/// A protocol conformance entry.
#[derive(Debug, Clone)]
pub struct SwiftConformance {
    pub type_mangled: String,
    pub protocol_mangled: String,
    pub witness_table_va: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftOnceSymbol
// ─────────────────────────────────────────────────────────────────────────────

/// A `swift_once` initializer record.
#[derive(Debug, Clone)]
pub struct SwiftOnceSymbol {
    /// Virtual address of the token.
    pub token_va: u64,
    /// Virtual address of the initializer function.
    pub init_va: u64,
    /// Associated type name (heuristic, may be empty).
    pub associated_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Swift name demangler (lightweight, no external dep)
// ─────────────────────────────────────────────────────────────────────────────

/// Demangle a Swift symbol name.
///
/// Handles the `$s` (Swift 5) and `_T` (Swift 3/4) prefixes and performs
/// a best-effort decoding of the most common patterns.
///
/// For a full implementation a separate demangling library (e.g. `swift-demangle`)
/// would be required.
#[must_use]
pub fn demangle_swift(symbol: &str) -> String {
    let sym = symbol.trim_start_matches('_');

    // Swift 5 prefix: $s
    let rest = if let Some(r) = sym.strip_prefix("$s") {
        r
    } else if let Some(r) = sym.strip_prefix("_T0") {
        r
    } else if let Some(r) = sym.strip_prefix("_T") {
        r
    } else {
        return symbol.to_string();
    };

    // Parse module name: first sequence of length-prefixed identifier.
    let mut result = String::new();
    let mut pos = 0usize;
    let bytes = rest.as_bytes();

    // Read module name.
    if let Some((module, new_pos)) = read_length_prefixed(bytes, pos) {
        result.push_str(&module);
        pos = new_pos;

        // Read type name segments.
        while pos < bytes.len() {
            if let Some((name, new_pos)) = read_length_prefixed(bytes, pos) {
                if !result.is_empty() { result.push('.'); }
                result.push_str(&name);
                pos = new_pos;
            } else {
                break;
            }
        }
    }

    // Append suffix hints.
    let suffix = rest.get(pos..).unwrap_or("");
    let type_hint = match suffix {
        s if s.starts_with('V') => " (struct)",
        s if s.starts_with('C') => " (class)",
        s if s.starts_with('O') => " (enum)",
        s if s.starts_with('P') => " (protocol)",
        s if s.starts_with('F') || s.starts_with("fi") => " (func)",
        s if s.starts_with("vg") => " (getter)",
        s if s.starts_with("vs") => " (setter)",
        _ => "",
    };

    if result.is_empty() {
        format!("{symbol}{type_hint}")
    } else {
        format!("{result}{type_hint}")
    }
}

/// Parse a Swift length-prefixed identifier starting at `pos`.
/// Returns `(identifier, new_pos)`.
fn read_length_prefixed(bytes: &[u8], mut pos: usize) -> Option<(String, usize)> {
    // Read digits.
    let len_start = pos;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos == len_start { return None; }
    let len_str = std::str::from_utf8(&bytes[len_start..pos]).ok()?;
    let len = len_str.parse::<usize>().ok()?;
    if pos + len > bytes.len() { return None; }
    let name = std::str::from_utf8(&bytes[pos..pos+len]).ok()?.to_string();
    Some((name, pos + len))
}

// ─────────────────────────────────────────────────────────────────────────────
// Mach-O section locator
// ─────────────────────────────────────────────────────────────────────────────

/// Known Swift metadata section names and their significance.
pub const SWIFT_SECTIONS: &[(&str, &str, &str)] = &[
    ("__TEXT", "__swift5_types",    "Type descriptors"),
    ("__TEXT", "__swift5_proto",    "Protocol conformances"),
    ("__TEXT", "__swift5_protos",   "Protocol descriptors"),
    ("__TEXT", "__swift5_fieldmd",  "Field metadata"),
    ("__TEXT", "__swift5_reflstr",  "Reflection strings"),
    ("__TEXT", "__swift5_assocty",  "Associated type records"),
    ("__TEXT", "__swift5_builtin",  "Builtin type records"),
    ("__TEXT", "__swift5_capture",  "Capture descriptors"),
    ("__DATA", "__swift_hooks",     "Swift runtime hooks"),
    ("__DATA", "__objc_classlist",  "ObjC class list"),
    ("__DATA", "__objc_protolist",  "ObjC protocol list"),
];

/// Locate a Mach-O section by segment + section name.
///
/// Returns `(offset, size)` in the file, or `None` if not found.
/// This is a heuristic scan — a full Mach-O parser is in the `binary_extractor` module.
#[must_use] 
pub fn find_section(data: &[u8], segment: &str, section: &str) -> Option<(usize, usize)> {
    // Search for the section name string in the binary as a heuristic.
    let sect_bytes = section.as_bytes();
    let seg_bytes = segment.as_bytes();

    let mut i = 0usize;
    while i + sect_bytes.len() + seg_bytes.len() + 16 < data.len() {
        // Look for segment name match followed shortly by section name match.
        if &data[i..i+seg_bytes.len()] == seg_bytes {
            let seg_end = i + 16; // segment name field is 16 bytes in Mach-O
            if seg_end + sect_bytes.len() <= data.len()
                && &data[seg_end..seg_end+sect_bytes.len()] == sect_bytes
            {
                // Try to read section offset and size from the section64 struct.
                // Layout: [16] segname, [16] sectname, [8] addr, [8] size, [4] offset, ...
                // For 64-bit: addr at +32, size at +40, offset at +48.
                let offset_field = seg_end + 16 + 8 + 8;
                if offset_field + 12 <= data.len() {
                    let _addr = u64::from_le_bytes(data[seg_end+16..seg_end+24].try_into().ok()?);
                    let size = usize::try_from(u64::from_le_bytes(data[seg_end+24..seg_end+32].try_into().ok()?)).ok()?;
                    let file_offset = u32::from_le_bytes(data[seg_end+32..seg_end+36].try_into().ok()?) as usize;
                    if file_offset > 0 && file_offset + size <= data.len() && size > 0 {
                        return Some((file_offset, size));
                    }
                }
            }
        }
        i += 1;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftMetadataExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts Swift type metadata from a Mach-O binary.
pub struct SwiftMetadataExtractor<'a> {
    data: &'a [u8],
    /// VM base address (for relative-offset resolution).
    base_va: u64,
}

impl<'a> SwiftMetadataExtractor<'a> {
    /// Create an extractor for a Mach-O binary blob.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        // Heuristic: assume base VA = 0x100000000 for arm64 iOS binaries.
        Self { data, base_va: 0x0001_0000_0000 }
    }

    /// Set the base VA.
    #[must_use]
    pub const fn with_base_va(mut self, va: u64) -> Self {
        self.base_va = va;
        self
    }

    /// Return a list of all Swift metadata sections found.
    #[must_use]
    pub fn list_sections(&self) -> Vec<(&'static str, &'static str, &'static str, usize, usize)> {
        let mut found = Vec::new();
        for &(seg, sect, desc) in SWIFT_SECTIONS {
            if let Some((off, sz)) = find_section(self.data, seg, sect) {
                found.push((seg, sect, desc, off, sz));
            }
        }
        found
    }

    /// Check if this binary contains any Swift metadata.
    #[must_use]
    pub fn has_swift_metadata(&self) -> bool {
        SWIFT_SECTIONS.iter().any(|(seg, sect, _)| find_section(self.data, seg, sect).is_some())
            || !self.scan_swift_symbols().is_empty()
    }

    /// Scan the binary for `$s`-prefixed Swift symbols.
    #[must_use]
    pub fn scan_swift_symbols(&self) -> Vec<String> {
        let mut results = Vec::new();
        let prefix = b"$s";
        let mut i = 0usize;
        while i + 2 < self.data.len() {
            if &self.data[i..i+2] == prefix {
                // Read up to 128 printable ASCII chars.
                let start = i;
                let mut end = i + 2;
                while end < self.data.len() && end - start < 128
                    && (self.data[end].is_ascii_alphanumeric() || matches!(self.data[end], b'_' | b'$')) {
                    end += 1;
                }
                if end - start >= 4 {
                    let sym = String::from_utf8_lossy(&self.data[start..end]).into_owned();
                    results.push(sym);
                }
                i = end;
            } else {
                i += 1;
            }
        }
        results
    }

    /// Demangle all Swift symbols found in the binary.
    #[must_use]
    pub fn demangled_symbols(&self) -> Vec<(String, String)> {
        self.scan_swift_symbols().into_iter()
            .map(|sym| {
                let demangled = demangle_swift(&sym);
                (sym, demangled)
            })
            .collect()
    }

    /// Build a class hierarchy from demangled Swift class names.
    ///
    /// Returns `parent_name → Vec<child_name>` map.
    #[must_use]
    pub fn class_hierarchy(&self) -> HashMap<String, Vec<String>> {
        let mut hierarchy: HashMap<String, Vec<String>> = HashMap::new();
        let symbols = self.demangled_symbols();

        for (_, demangled) in &symbols {
            if !demangled.contains("(class)") { continue; }
            let clean = demangled.trim_end_matches(" (class)");
            // Infer parent from common Swift naming: "Module.Child: Parent" or similar.
            // Without DWARF/type metadata we can only group by module.
            let module = clean.find('.').map_or("", |p| &clean[..p]);
            if !module.is_empty() {
                hierarchy.entry(module.to_string()).or_default().push(clean.to_string());
            }
        }
        hierarchy
    }

    /// Extract and analyse all protocol witness tables.
    #[must_use]
    pub fn protocol_witness_table_symbols(&self) -> Vec<String> {
        self.scan_swift_symbols().into_iter()
            .filter(|s| s.contains("WP") || s.contains("_witness_table"))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of Swift metadata analysis for an IPA binary.
#[derive(Debug, Clone, Default)]
pub struct SwiftReport {
    pub is_swift_binary: bool,
    pub swift_symbol_count: usize,
    pub class_count: usize,
    pub struct_count: usize,
    pub enum_count: usize,
    pub protocol_count: usize,
    pub witness_table_count: usize,
    /// Modules identified in the binary.
    pub modules: Vec<String>,
    /// Sample of demangled class names.
    pub sample_classes: Vec<String>,
}

impl SwiftReport {
    /// Build a report from an extractor.
    #[must_use]
    pub fn build(extractor: &SwiftMetadataExtractor<'_>) -> Self {
        let mut report = Self::default();
        let demangled = extractor.demangled_symbols();
        report.is_swift_binary = extractor.has_swift_metadata();
        report.swift_symbol_count = demangled.len();

        let mut modules: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (_, d) in &demangled {
            if d.contains("(class)") { report.class_count += 1; }
            else if d.contains("(struct)") { report.struct_count += 1; }
            else if d.contains("(enum)") { report.enum_count += 1; }
            else if d.contains("(protocol)") { report.protocol_count += 1; }
        }

        report.witness_table_count = extractor.protocol_witness_table_symbols().len();

        let hierarchy = extractor.class_hierarchy();
        for (module, classes) in &hierarchy {
            modules.insert(module.clone());
            if report.sample_classes.len() < 20 {
                report.sample_classes.extend(classes.iter().take(5).cloned());
            }
        }
        report.modules = modules.into_iter().collect();
        report.modules.sort();
        report
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangle_swift_class() {
        // Swift mangling prefixes each identifier with its LENGTH:
        // "MyApp" is 5 characters and "MyClass" is 7, so the module
        // prefix must be 5. It read 6, which made the demangler consume
        // the next length digit as part of the name ("MyApp7") — the
        // demangler was right, the fixture was not.
        let sym = "$s5MyApp7MyClassC";
        let d = demangle_swift(sym);
        assert!(d.contains("MyApp"), "expected MyApp in {d}");
        assert!(d.contains("MyClass"), "expected MyClass in {d}");
    }

    #[test]
    fn test_demangle_swift_struct() {
        // "MyApp" is 5 characters, "MyStruct" is 8.
        let sym = "$s5MyApp8MyStructV";
        let d = demangle_swift(sym);
        assert!(d.contains("MyApp"));
        assert!(d.contains("MyStruct"));
        assert!(d.contains("struct"));
    }

    #[test]
    fn test_demangle_non_swift() {
        let sym = "_objc_msgSend";
        let d = demangle_swift(sym);
        assert_eq!(d, "_objc_msgSend");
    }

    #[test]
    fn test_swift_kind_from_flags() {
        assert_eq!(SwiftKind::from_flags(1), SwiftKind::Struct);
        assert_eq!(SwiftKind::from_flags(2), SwiftKind::Enum);
        assert_eq!(SwiftKind::from_flags(3), SwiftKind::Class);
        assert_eq!(SwiftKind::from_flags(14), SwiftKind::Protocol);
    }

    #[test]
    fn test_scan_swift_symbols_in_data() {
        // Embed a fake Swift symbol in a byte buffer.
        let mut data = vec![0u8; 64];
        let sym = b"$s6MyApp7GreeterC";
        data[10..10+sym.len()].copy_from_slice(sym);
        let extractor = SwiftMetadataExtractor::new(&data);
        let syms = extractor.scan_swift_symbols();
        assert!(!syms.is_empty());
        assert!(syms.iter().any(|s| s.contains("MyApp")));
    }

    #[test]
    fn test_demangled_symbols_round_trip() {
        let mut data = vec![0u8; 128];
        // "MyApp" is 5 characters, "SomeStructure" is 13.
        let sym = b"$s5MyApp13SomeStructureV";
        data[20..20+sym.len()].copy_from_slice(sym);
        let extractor = SwiftMetadataExtractor::new(&data);
        let pairs = extractor.demangled_symbols();
        assert!(!pairs.is_empty());
        let (raw, dem) = &pairs[0];
        assert!(raw.starts_with("$s"));
        assert!(dem.contains("SomeStructure"));
    }

    #[test]
    fn test_swift_report_build() {
        let mut data = vec![0u8; 256];
        let syms: &[&[u8]] = &[
            b"$s6MyApp5AlphaC",   // class
            b"$s6MyApp4BetaV",    // struct
            b"$s6MyApp5GammaO",   // enum
        ];
        let mut off = 10usize;
        for s in syms {
            data[off..off+s.len()].copy_from_slice(s);
            data[off + s.len()] = 0; // NUL separator
            off += s.len() + 4;
        }
        let extractor = SwiftMetadataExtractor::new(&data);
        let report = SwiftReport::build(&extractor);
        assert!(report.swift_symbol_count >= 3);
    }
}
