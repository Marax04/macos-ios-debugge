//! Deep Mach-O analysis: load commands, code signature, entitlements,
//! fat binary, `ObjC` runtime, imports/exports.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MachoAnalyzerError {
    #[error("not a Mach-O file: {0}")]
    NotMacho(String),
    #[error("truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("unsupported magic: {0:#010x}")]
    UnsupportedMagic(u32),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── CodeSignature ────────────────────────────────────────────────────────────

/// Parsed code-signature blob from `LC_CODE_SIGNATURE`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeSignature {
    /// Whether a CMS blob is present.
    pub has_cms: bool,
    /// Whether requirements blob is present.
    pub has_requirements: bool,
    /// Whether a `CodeDirectory` is present.
    pub has_code_directory: bool,
    /// Raw entitlements XML plist (if present).
    pub entitlements_xml: Option<String>,
    /// `CodeDirectory` flags.
    pub flags: u32,
    /// Team identifier from the `CodeDirectory`.
    pub team_id: Option<String>,
    /// Bundle identifier from the `CodeDirectory`.
    pub identifier: Option<String>,
    /// Page size as power of 2 (typically 12 = 4 KiB).
    pub page_size: u8,
    /// Hash type (1=SHA-1, 2=SHA-256).
    pub hash_type: u8,
    /// Number of code hash slots.
    pub code_slots: u32,
}

impl CodeSignature {
    /// Returns `true` if the binary is signed with CMS (distribution cert).
    #[must_use]
    pub const fn is_cms_signed(&self) -> bool {
        self.has_cms
    }

    /// Returns `true` if SHA-256 hashing is used.
    #[must_use]
    pub const fn uses_sha256(&self) -> bool {
        self.hash_type == 2
    }

    /// Returns `true` if the `get-task-allow` entitlement is set.
    #[must_use]
    pub fn get_task_allow(&self) -> bool {
        self.entitlements_xml
            .as_deref()
            .is_some_and(|e| e.contains("get-task-allow") && e.contains("<true/>"))
    }
}

// ─── Entitlements ─────────────────────────────────────────────────────────────

/// Parsed entitlements from the code signature.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Entitlements {
    pub raw_xml: String,
    pub keys: HashMap<String, String>,
}

impl Entitlements {
    /// Parse simple key-value pairs from an XML plist string.
    #[must_use]
    pub fn from_xml(xml: &str) -> Self {
        let mut keys = HashMap::new();
        let mut remaining = xml;
        while let Some(ks) = remaining.find("<key>") {
            remaining = &remaining[ks + 5..];
            let ke = remaining.find("</key>").unwrap_or(remaining.len());
            let key = remaining[..ke].trim().to_string();
            remaining = &remaining[ke + 6..];
            let tr = remaining.trim_start();
            let val = if tr.starts_with("<string>") {
                tr.find("</string>")
                    .map(|e| tr[8..e].to_string())
                    .unwrap_or_default()
            } else if tr.starts_with("<true/>") {
                "true".into()
            } else if tr.starts_with("<false/>") {
                "false".into()
            } else {
                String::new()
            };
            keys.insert(key, val);
        }
        Self {
            raw_xml: xml.to_string(),
            keys,
        }
    }

    /// Return the value for an entitlement key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.keys.get(key).map(String::as_str)
    }

    /// Returns `true` if the `get-task-allow` entitlement is set to `true`.
    #[must_use]
    pub fn is_debuggable(&self) -> bool {
        self.get("get-task-allow") == Some("true")
    }
}

// ─── LoadCommandSummary ───────────────────────────────────────────────────────

/// High-level summary of a load command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadCommandSummary {
    /// Raw command value.
    pub cmd: u32,
    /// Human-readable name.
    pub name: String,
    /// Size in bytes.
    pub size: u32,
    /// Payload summary (varies by command).
    pub payload: String,
}

impl LoadCommandSummary {
    #[must_use]
    pub const fn cmd_name(cmd: u32) -> &'static str {
        match cmd {
            0x1 => "LC_SEGMENT",
            0x19 => "LC_SEGMENT_64",
            0x2 => "LC_SYMTAB",
            0xB => "LC_DYSYMTAB",
            0xC => "LC_LOAD_DYLIB",
            0xD => "LC_ID_DYLIB",
            0x21 => "LC_ENCRYPTION_INFO",
            0x2C => "LC_ENCRYPTION_INFO_64",
            0x1D => "LC_CODE_SIGNATURE",
            0x1B => "LC_UUID",
            0x8000_0028 => "LC_MAIN",
            0x5 => "LC_UNIX_THREAD",
            0x22 => "LC_DYLD_INFO",
            0x8000_0022 => "LC_DYLD_INFO_ONLY",
            0x26 => "LC_FUNCTION_STARTS",
            0x29 => "LC_DATA_IN_CODE",
            0x24 => "LC_VERSION_MIN_MACOSX",
            0x25 => "LC_VERSION_MIN_IPHONEOS",
            0x32 => "LC_BUILD_VERSION",
            0x8000_001C => "LC_RPATH",
            _ => "LC_UNKNOWN",
        }
    }
}

// ─── EncryptionInfo ──────────────────────────────────────────────────────────

/// `FairPlay` / DRM encryption info from `LC_ENCRYPTION_INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// File offset of the encrypted region.
    pub crypt_offset: u32,
    /// Size of the encrypted region.
    pub crypt_size: u32,
    /// Encryption ID (0 = not encrypted, 1 = `FairPlay`).
    pub crypt_id: u32,
    /// Whether 64-bit variant (`LC_ENCRYPTION_INFO_64`).
    pub is_64bit: bool,
}

impl EncryptionInfo {
    /// Returns `true` if the binary is FairPlay-encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.crypt_id != 0
    }
}

// ─── ObjcMethod ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcMethod {
    pub name: String,
    pub type_encoding: String,
    pub imp: u64,
}

// ─── ObjcClass ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClass {
    pub name: String,
    pub superclass: Option<String>,
    pub protocols: Vec<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<String>,
    /// Virtual address of the class structure, if known.
    #[serde(default)]
    pub address: u64,
    /// True for the metaclass (class-method receiver) rather than the instance class.
    #[serde(default)]
    pub is_meta: bool,
}

impl ObjcClass {
    #[must_use]
    pub const fn total_methods(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }

    #[must_use]
    pub fn implements_protocol(&self, proto: &str) -> bool {
        self.protocols.iter().any(|p| p == proto)
    }
}

// ─── ObjcRuntime ─────────────────────────────────────────────────────────────

/// Objective-C runtime metadata extracted from the binary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObjcRuntime {
    pub classes: Vec<ObjcClass>,
    pub protocols: Vec<String>,
    pub selectors: Vec<String>,
    pub categories: Vec<(String, String)>, // (category_name, class_name)
}

impl ObjcRuntime {
    /// Find a class by name.
    #[must_use]
    pub fn find_class(&self, name: &str) -> Option<&ObjcClass> {
        self.classes.iter().find(|c| c.name == name)
    }

    /// All classes that conform to a given protocol.
    #[must_use]
    pub fn classes_for_protocol(&self, proto: &str) -> Vec<&ObjcClass> {
        self.classes
            .iter()
            .filter(|c| c.implements_protocol(proto))
            .collect()
    }

    /// Total selector count.
    #[must_use]
    pub const fn selector_count(&self) -> usize {
        self.selectors.len()
    }
}

// ─── FatBinary ────────────────────────────────────────────────────────────────

/// A slice in a fat/universal binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatSlice {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub offset: u32,
    pub size: u32,
    pub arch_name: String,
}

/// Fat/universal binary structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FatBinary {
    pub slices: Vec<FatSlice>,
}

impl FatBinary {
    /// Returns `true` if the binary is fat/universal.
    #[must_use]
    pub const fn is_fat(&self) -> bool {
        !self.slices.is_empty()
    }

    /// Find the slice for `arch_name`.
    #[must_use]
    pub fn find_arch(&self, arch: &str) -> Option<&FatSlice> {
        self.slices.iter().find(|s| s.arch_name == arch)
    }
}

// ─── ImportedSymbol ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSymbol {
    pub name: String,
    pub dylib: String,
    pub weak: bool,
    pub address: u64,
}

// ─── ExportedSymbol ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub address: u64,
    pub flags: u64,
    pub is_reexport: bool,
}

// ─── MachoAnalysisResult ──────────────────────────────────────────────────────

/// Full deep-analysis result for a Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoAnalysisResult {
    pub arch: String,
    pub cpu_subtype: u32,
    pub file_type: String,
    pub image_base: u64,
    pub entry_point: Option<u64>,
    pub is_64bit: bool,
    pub is_pie: bool,
    pub uuid: Option<String>,
    pub min_os_version: Option<String>,
    pub platform: Option<String>,
    pub load_commands: Vec<LoadCommandSummary>,
    pub code_signature: Option<CodeSignature>,
    pub entitlements: Option<Entitlements>,
    pub encryption_info: Option<EncryptionInfo>,
    pub objc_runtime: ObjcRuntime,
    pub fat_binary: FatBinary,
    pub imports: Vec<ImportedSymbol>,
    pub exports: Vec<ExportedSymbol>,
    pub dylibs: Vec<String>,
    pub rpaths: Vec<String>,
    pub function_starts: Vec<u64>,
    pub has_debug_info: bool,
    pub is_swift: bool,
    pub bitcode: bool,
}

impl MachoAnalysisResult {
    /// Build a mock result for testing.
    #[must_use]
    pub fn mock() -> Self {
        let cs = CodeSignature {
            has_cms: true,
            has_requirements: true,
            has_code_directory: true,
            entitlements_xml: Some(
                "<?xml version=\"1.0\"?>\n<plist>\n<dict>\n\
                 <key>get-task-allow</key><false/>\n\
                 <key>application-identifier</key><string>ABCD.com.example.App</string>\n\
                 </dict></plist>"
                    .into(),
            ),
            flags: 0,
            team_id: Some("ABCD1234".into()),
            identifier: Some("com.example.App".into()),
            page_size: 12,
            hash_type: 2,
            code_slots: 128,
        };
        let ents = Entitlements::from_xml(cs.entitlements_xml.as_deref().unwrap_or(""));
        let enc = EncryptionInfo {
            crypt_offset: 0x4000,
            crypt_size: 0x80000,
            crypt_id: 0,
            is_64bit: true,
        };
        let objc = ObjcRuntime {
            classes: vec![ObjcClass {
                name: "AppDelegate".into(),
                superclass: Some("UIResponder".into()),
                protocols: vec!["UIApplicationDelegate".into()],
                instance_methods: vec![ObjcMethod {
                    name: "application:didFinishLaunchingWithOptions:".into(),
                    type_encoding: "c36@0:8@16@24".into(),
                    imp: 0x0001_0000_1000,
                }],
                class_methods: vec![],
                ivars: vec!["_window".into()],
                address: 0,
                is_meta: false,
            }],
            protocols: vec!["UIApplicationDelegate".into()],
            selectors: vec![
                "application:didFinishLaunchingWithOptions:".into(),
                "viewDidLoad".into(),
            ],
            categories: vec![("UIViewController+Logging".into(), "UIViewController".into())],
        };
        let lc = vec![
            LoadCommandSummary {
                cmd: 0x19,
                name: "LC_SEGMENT_64".into(),
                size: 72,
                payload: "__TEXT".into(),
            },
            LoadCommandSummary {
                cmd: 0x1D,
                name: "LC_CODE_SIGNATURE".into(),
                size: 16,
                payload: "off=0x200000 size=0x4000".into(),
            },
        ];
        let imports = vec![
            ImportedSymbol {
                name: "_objc_msgSend".into(),
                dylib: "/usr/lib/libobjc.A.dylib".into(),
                weak: false,
                address: 0,
            },
            ImportedSymbol {
                name: "_malloc".into(),
                dylib: "/usr/lib/libSystem.B.dylib".into(),
                weak: false,
                address: 0,
            },
        ];
        let exports = vec![ExportedSymbol {
            name: "_main".into(),
            address: 0x0001_0000_1000,
            flags: 0,
            is_reexport: false,
        }];
        Self {
            arch: "arm64".into(),
            cpu_subtype: 0,
            file_type: "MH_EXECUTE".into(),
            image_base: 0x0001_0000_0000,
            entry_point: Some(0x0001_0000_1000),
            is_64bit: true,
            is_pie: true,
            uuid: Some("12345678-1234-1234-1234-123456789ABC".into()),
            min_os_version: Some("14.0".into()),
            platform: Some("iOS".into()),
            load_commands: lc,
            code_signature: Some(cs),
            entitlements: Some(ents),
            encryption_info: Some(enc),
            objc_runtime: objc,
            fat_binary: FatBinary::default(),
            imports,
            exports,
            dylibs: vec![
                "/usr/lib/libobjc.A.dylib".into(),
                "/usr/lib/libSystem.B.dylib".into(),
            ],
            rpaths: vec![],
            function_starts: vec![0x0001_0000_1000, 0x0001_0000_1200],
            has_debug_info: false,
            is_swift: false,
            bitcode: false,
        }
    }

    /// Returns `true` when the binary is FairPlay-encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encryption_info
            .as_ref()
            .is_some_and(EncryptionInfo::is_encrypted)
    }

    /// Returns `true` when the app is debuggable via `get-task-allow`.
    #[must_use]
    pub fn is_debuggable(&self) -> bool {
        self.entitlements
            .as_ref()
            .is_some_and(Entitlements::is_debuggable)
    }
}

impl fmt::Display for MachoAnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Mach-O {} {} pie={} encrypted={} objc_classes={}",
            self.arch,
            self.file_type,
            self.is_pie,
            self.is_encrypted(),
            self.objc_runtime.classes.len(),
        )
    }
}

// ─── MachoAnalyzer ────────────────────────────────────────────────────────────

/// Deep Mach-O analysis engine.
#[derive(Debug, Default)]
pub struct MachoAnalyzer;

impl MachoAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Quick check: returns `true` if `data` has a known Mach-O magic.
    #[must_use]
    pub fn is_macho(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4]));
        matches!(
            magic,
            0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE | 0xCAFE_BABE | 0xBEBA_FECA
        )
    }

    /// Detect architecture from `cputype` field.
    #[must_use]
    pub const fn arch_name(cputype: u32) -> &'static str {
        match cputype {
            7 => "x86",
            0x0100_0007 => "x86_64",
            12 => "arm",
            0x0100_000C => "arm64",
            0x0200_000C => "arm64_32",
            18 => "ppc",
            0x0100_0012 => "ppc64",
            _ => "unknown",
        }
    }

    /// Detect file type from `filetype` field.
    #[must_use]
    pub const fn file_type_name(filetype: u32) -> &'static str {
        match filetype {
            1 => "MH_OBJECT",
            2 => "MH_EXECUTE",
            3 => "MH_FVMLIB",
            4 => "MH_CORE",
            5 => "MH_PRELOAD",
            6 => "MH_DYLIB",
            7 => "MH_DYLINKER",
            8 => "MH_BUNDLE",
            9 => "MH_DYLIB_STUB",
            10 => "MH_DSYM",
            11 => "MH_KEXT_BUNDLE",
            _ => "MH_UNKNOWN",
        }
    }

    /// Scan `data` for `ObjC` class name strings from `__objc_classnames`.
    #[must_use]
    pub fn scan_objc_class_names(data: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        // Look for sequences starting with an uppercase letter (ObjC convention)
        let mut i = 0;
        while i < data.len() {
            if data[i].is_ascii_uppercase() {
                let start = i;
                let end = data[i..]
                    .iter()
                    .take(128)
                    .position(|&b| b == 0)
                    .map_or(i + 64, |p| i + p);
                if end > start + 2 && let Ok(s) = std::str::from_utf8(&data[start..end]) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    names.push(s.to_string());
                }
                i = end + 1;
            } else {
                i += 1;
            }
        }
        names
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MachoAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_macho_le() {
        let magic = 0xFEED_FACFu32.to_le_bytes();
        assert!(MachoAnalyzer::is_macho(&magic));
    }

    #[test]
    fn test_is_macho_be() {
        let magic = 0xCFFA_EDFEu32.to_le_bytes();
        assert!(MachoAnalyzer::is_macho(&magic));
    }

    #[test]
    fn test_is_macho_fat() {
        let magic = 0xCAFE_BABEu32.to_le_bytes();
        assert!(MachoAnalyzer::is_macho(&magic));
    }

    #[test]
    fn test_is_not_macho() {
        assert!(!MachoAnalyzer::is_macho(b"PK\x03\x04"));
    }

    #[test]
    fn test_arch_name_arm64() {
        assert_eq!(MachoAnalyzer::arch_name(0x0100_000C), "arm64");
    }

    #[test]
    fn test_arch_name_x86_64() {
        assert_eq!(MachoAnalyzer::arch_name(0x0100_0007), "x86_64");
    }

    #[test]
    fn test_file_type_name_execute() {
        assert_eq!(MachoAnalyzer::file_type_name(2), "MH_EXECUTE");
    }

    #[test]
    fn test_file_type_name_dylib() {
        assert_eq!(MachoAnalyzer::file_type_name(6), "MH_DYLIB");
    }

    // ── CodeSignature ─────────────────────────────────────────────────────────

    #[test]
    fn test_cs_is_cms_signed() {
        let r = MachoAnalysisResult::mock();
        assert!(r.code_signature.as_ref().unwrap().is_cms_signed());
    }

    #[test]
    fn test_cs_uses_sha256() {
        let r = MachoAnalysisResult::mock();
        assert!(r.code_signature.as_ref().unwrap().uses_sha256());
    }

    #[test]
    fn test_cs_get_task_allow_false() {
        let r = MachoAnalysisResult::mock();
        assert!(!r.code_signature.as_ref().unwrap().get_task_allow());
    }

    // ── Entitlements ──────────────────────────────────────────────────────────

    #[test]
    fn test_entitlements_from_xml() {
        let xml = "<plist><dict><key>get-task-allow</key><true/></dict></plist>";
        let e = Entitlements::from_xml(xml);
        assert_eq!(e.get("get-task-allow"), Some("true"));
    }

    #[test]
    fn test_entitlements_is_debuggable_false() {
        let r = MachoAnalysisResult::mock();
        assert!(!r.is_debuggable());
    }

    #[test]
    fn test_entitlements_application_identifier() {
        let r = MachoAnalysisResult::mock();
        let e = r.entitlements.as_ref().unwrap();
        assert_eq!(
            e.get("application-identifier"),
            Some("ABCD.com.example.App")
        );
    }

    // ── ObjcClass ─────────────────────────────────────────────────────────────

    #[test]
    fn test_objc_class_total_methods() {
        let r = MachoAnalysisResult::mock();
        let c = &r.objc_runtime.classes[0];
        assert_eq!(c.total_methods(), 1);
    }

    #[test]
    fn test_objc_class_implements_protocol() {
        let r = MachoAnalysisResult::mock();
        let c = &r.objc_runtime.classes[0];
        assert!(c.implements_protocol("UIApplicationDelegate"));
        assert!(!c.implements_protocol("NSCoding"));
    }

    // ── ObjcRuntime ───────────────────────────────────────────────────────────

    #[test]
    fn test_objc_runtime_find_class() {
        let r = MachoAnalysisResult::mock();
        assert!(r.objc_runtime.find_class("AppDelegate").is_some());
        assert!(r.objc_runtime.find_class("Nonexistent").is_none());
    }

    #[test]
    fn test_objc_runtime_classes_for_protocol() {
        let r = MachoAnalysisResult::mock();
        let classes = r.objc_runtime.classes_for_protocol("UIApplicationDelegate");
        assert_eq!(classes.len(), 1);
    }

    #[test]
    fn test_objc_runtime_selector_count() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.objc_runtime.selector_count(), 2);
    }

    // ── EncryptionInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_encryption_info_not_encrypted_when_id_zero() {
        let r = MachoAnalysisResult::mock();
        assert!(!r.is_encrypted());
    }

    #[test]
    fn test_encryption_info_encrypted_when_id_nonzero() {
        let enc = EncryptionInfo {
            crypt_offset: 0,
            crypt_size: 0,
            crypt_id: 1,
            is_64bit: true,
        };
        assert!(enc.is_encrypted());
    }

    // ── FatBinary ─────────────────────────────────────────────────────────────

    #[test]
    fn test_fat_binary_not_fat_when_empty() {
        let f = FatBinary::default();
        assert!(!f.is_fat());
    }

    #[test]
    fn test_fat_binary_find_arch() {
        let mut fb = FatBinary::default();
        fb.slices.push(FatSlice {
            cpu_type: 0x0100_000C,
            cpu_subtype: 0,
            offset: 0,
            size: 0x0010_0000,
            arch_name: "arm64".into(),
        });
        assert!(fb.find_arch("arm64").is_some());
        assert!(fb.find_arch("x86_64").is_none());
    }

    // ── MachoAnalysisResult ───────────────────────────────────────────────────

    #[test]
    fn test_result_mock_arch() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.arch, "arm64");
    }

    #[test]
    fn test_result_mock_is_pie() {
        let r = MachoAnalysisResult::mock();
        assert!(r.is_pie);
    }

    #[test]
    fn test_result_mock_imports() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.imports.len(), 2);
    }

    #[test]
    fn test_result_mock_exports() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.exports.len(), 1);
    }

    #[test]
    fn test_result_display() {
        let r = MachoAnalysisResult::mock();
        let s = format!("{r}");
        assert!(s.contains("arm64"));
    }

    #[test]
    fn test_result_serialization() {
        let r = MachoAnalysisResult::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: MachoAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.arch, r.arch);
    }

    #[test]
    fn test_load_command_summary_name() {
        assert_eq!(LoadCommandSummary::cmd_name(0x19), "LC_SEGMENT_64");
        assert_eq!(LoadCommandSummary::cmd_name(0x1D), "LC_CODE_SIGNATURE");
    }
    #[test]
    fn test_cs_code_slots() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.code_signature.as_ref().unwrap().code_slots, 128);
    }
    #[test]
    fn test_cs_page_size() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.code_signature.as_ref().unwrap().page_size, 12);
    }
    #[test]
    fn test_entitlements_get_none() {
        let e = Entitlements::default();
        assert!(e.get("missing").is_none());
    }
    #[test]
    fn test_objc_class_no_superclass() {
        let c = ObjcClass {
            name: "Root".into(),
            superclass: None,
            protocols: vec![],
            instance_methods: vec![],
            class_methods: vec![],
            ivars: vec![],
            address: 0,
            is_meta: false,
        };
        assert!(c.superclass.is_none());
    }
    #[test]
    fn test_objc_runtime_default_empty() {
        let r = ObjcRuntime::default();
        assert!(r.classes.is_empty());
    }
    #[test]
    fn test_fat_binary_is_fat_with_slices() {
        let mut fb = FatBinary::default();
        fb.slices.push(FatSlice {
            cpu_type: 0,
            cpu_subtype: 0,
            offset: 0,
            size: 0,
            arch_name: "arm64".into(),
        });
        assert!(fb.is_fat());
    }
    #[test]
    fn test_result_mock_uuid() {
        let r = MachoAnalysisResult::mock();
        assert!(r.uuid.is_some());
    }
    #[test]
    fn test_result_mock_platform() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.platform.as_deref(), Some("iOS"));
    }
    #[test]
    fn test_result_mock_min_os() {
        let r = MachoAnalysisResult::mock();
        assert_eq!(r.min_os_version.as_deref(), Some("14.0"));
    }
    #[test]
    fn test_analyzer_arch_name_arm() {
        assert_eq!(MachoAnalyzer::arch_name(12), "arm");
    }
    #[test]
    fn test_analyzer_file_type_dsym() {
        assert_eq!(MachoAnalyzer::file_type_name(10), "MH_DSYM");
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_arch_name_unknown_value() {
        assert_eq!(MachoAnalyzer::arch_name(0xDEAD_BEEF), "unknown");
        assert_eq!(MachoAnalyzer::arch_name(0), "unknown");
    }

    #[test]
    fn test_arch_name_x86_and_x86_64() {
        assert_eq!(MachoAnalyzer::arch_name(7), "x86");
        assert_eq!(MachoAnalyzer::arch_name(0x0100_0007), "x86_64");
        assert_eq!(MachoAnalyzer::arch_name(0x0100_000C), "arm64");
    }

    #[test]
    fn test_file_type_name_unknown() {
        assert_eq!(MachoAnalyzer::file_type_name(0), "MH_UNKNOWN");
        assert_eq!(MachoAnalyzer::file_type_name(u32::MAX), "MH_UNKNOWN");
    }

    #[test]
    fn test_file_type_name_all_known() {
        for (k, expected) in [
            (1, "MH_OBJECT"),
            (2, "MH_EXECUTE"),
            (6, "MH_DYLIB"),
            (8, "MH_BUNDLE"),
            (11, "MH_KEXT_BUNDLE"),
        ] {
            assert_eq!(MachoAnalyzer::file_type_name(k), expected);
        }
    }

    #[test]
    fn test_cmd_name_unknown_returns_label() {
        // Unknown commands should produce a non-empty string (likely "LC_UNKNOWN" or hex).
        let s = LoadCommandSummary::cmd_name(0x0BAD_F00D);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_scan_objc_class_names_empty() {
        assert!(MachoAnalyzer::scan_objc_class_names(&[]).is_empty());
    }

    #[test]
    fn test_scan_objc_class_names_lowercase_only() {
        // No uppercase start → no matches.
        let data = b"foobar\0baz\0";
        assert!(MachoAnalyzer::scan_objc_class_names(data).is_empty());
    }

    #[test]
    fn test_scan_objc_class_names_simple() {
        let data = b"NSObject\0NSString\0";
        let names = MachoAnalyzer::scan_objc_class_names(data);
        assert!(names.iter().any(|n| n == "NSObject"));
        assert!(names.iter().any(|n| n == "NSString"));
    }

    #[test]
    fn test_fat_binary_default_not_fat() {
        let fb = FatBinary::default();
        assert!(!fb.is_fat());
    }
}
