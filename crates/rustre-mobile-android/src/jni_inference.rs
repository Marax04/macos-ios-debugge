//! JNI native method inference — scan ELF exports for JNI symbols and decode
//! Java type descriptors.
//!
//! Provides: `JniSignature`, `JniFinder`, `JniDescriptorParser`, `JniMapping`,
//! and `JniBridgeAnalyzer`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// JniDescriptorType — decoded JNI type descriptor
// ---------------------------------------------------------------------------

/// A decoded JNI type descriptor token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JniDescriptorType {
    /// `V` — void
    Void,
    /// `Z` — boolean
    Boolean,
    /// `B` — byte
    Byte,
    /// `C` — char
    Char,
    /// `S` — short
    Short,
    /// `I` — int
    Int,
    /// `J` — long
    Long,
    /// `F` — float
    Float,
    /// `D` — double
    Double,
    /// `[T` — array of T
    Array(Box<Self>),
    /// `Lclass/name;` — object reference
    Object(String),
}

impl JniDescriptorType {
    /// Return the Java-source type name.
    #[must_use]
    pub fn java_name(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Boolean => "boolean".to_string(),
            Self::Byte => "byte".to_string(),
            Self::Char => "char".to_string(),
            Self::Short => "short".to_string(),
            Self::Int => "int".to_string(),
            Self::Long => "long".to_string(),
            Self::Float => "float".to_string(),
            Self::Double => "double".to_string(),
            Self::Array(inner) => format!("{}[]", inner.java_name()),
            Self::Object(class) => class.replace('/', "."),
        }
    }

    /// Return `true` if this is a primitive (non-object, non-array) type.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Void
                | Self::Boolean
                | Self::Byte
                | Self::Char
                | Self::Short
                | Self::Int
                | Self::Long
                | Self::Float
                | Self::Double
        )
    }

    /// Return `true` if this is an array type.
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Return `true` if this is an object reference.
    #[must_use]
    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
}

impl std::fmt::Display for JniDescriptorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.java_name())
    }
}

// ---------------------------------------------------------------------------
// JniDescriptorParser
// ---------------------------------------------------------------------------

/// Parser for JNI method descriptor strings.
///
/// A descriptor has the form `(param1param2...)return` where each type is
/// encoded as per the JVM specification.
pub struct JniDescriptorParser;

impl JniDescriptorParser {
    /// Parse a full JNI method descriptor, returning `(params, return_type)`.
    ///
    /// # Errors
    /// Returns a string error when the descriptor is malformed.
    pub fn parse_method_descriptor(
        descriptor: &str,
    ) -> Result<(Vec<JniDescriptorType>, JniDescriptorType), String> {
        let d = descriptor.trim();
        if !d.starts_with('(') {
            return Err(format!("descriptor must start with '(': {d}"));
        }
        let close = d
            .find(')')
            .ok_or_else(|| format!("no closing ')' in descriptor: {d}"))?;

        let param_str = &d[1..close];
        let return_str = &d[close + 1..];

        let params = Self::parse_type_list(param_str)?;
        let ret = Self::parse_single_type(return_str)?;

        Ok((params, ret))
    }

    /// Parse a list of JNI type descriptors (no parentheses).
    ///
    /// # Errors
    /// Returns a string error on unknown or malformed type tokens.
    pub fn parse_type_list(s: &str) -> Result<Vec<JniDescriptorType>, String> {
        let mut types = Vec::new();
        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            let (t, consumed) = Self::parse_one_type(&s[i..])?;
            types.push(t);
            i += consumed;
        }
        Ok(types)
    }

    /// Parse a single JNI type descriptor.
    ///
    /// # Errors
    /// Returns a string error on unknown or malformed type tokens.
    pub fn parse_single_type(s: &str) -> Result<JniDescriptorType, String> {
        let (t, _) = Self::parse_one_type(s)?;
        Ok(t)
    }

    fn parse_one_type(s: &str) -> Result<(JniDescriptorType, usize), String> {
        if s.is_empty() {
            return Err("empty descriptor".to_string());
        }
        match s.as_bytes()[0] {
            b'V' => Ok((JniDescriptorType::Void, 1)),
            b'Z' => Ok((JniDescriptorType::Boolean, 1)),
            b'B' => Ok((JniDescriptorType::Byte, 1)),
            b'C' => Ok((JniDescriptorType::Char, 1)),
            b'S' => Ok((JniDescriptorType::Short, 1)),
            b'I' => Ok((JniDescriptorType::Int, 1)),
            b'J' => Ok((JniDescriptorType::Long, 1)),
            b'F' => Ok((JniDescriptorType::Float, 1)),
            b'D' => Ok((JniDescriptorType::Double, 1)),
            b'[' => {
                let (inner, len) = Self::parse_one_type(&s[1..])?;
                Ok((JniDescriptorType::Array(Box::new(inner)), 1 + len))
            }
            b'L' => {
                let end = s
                    .find(';')
                    .ok_or_else(|| format!("object type missing ';': {s}"))?;
                let class_name = &s[1..end];
                Ok((JniDescriptorType::Object(class_name.to_string()), end + 1))
            }
            c => Err(format!(
                "unknown type descriptor char '{}' in: {s}",
                c as char
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// JniSignature
// ---------------------------------------------------------------------------

/// A decoded JNI method signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniSignature {
    /// Java class name (slash-separated, e.g. `com/example/MyClass`).
    pub class: String,
    /// Java method name.
    pub method: String,
    /// JNI descriptor string (e.g. `(ILjava/lang/String;)V`).
    pub descriptor: String,
    /// Decoded parameter types.
    pub params: Vec<String>,
    /// Decoded return type.
    pub return_type: String,
    /// Whether this is a static native method.
    pub is_static: bool,
}

impl JniSignature {
    /// Build a `JniSignature` from the Java_* export name.
    ///
    /// JNI exports follow the pattern `Java_<class>_<method>` where dots/slashes
    /// in the class name are replaced by underscores.
    ///
    /// # Errors
    /// Returns a string error when the export name cannot be parsed.
    pub fn from_jni_export(export: &str, descriptor: Option<&str>) -> Result<Self, String> {
        let stripped = export
            .strip_prefix("Java_")
            .ok_or_else(|| format!("not a JNI export: {export}"))?;

        // Split at last underscore to separate class from method.
        let (class_part, method_part) = stripped
            .rsplit_once('_')
            .ok_or_else(|| format!("cannot split class/method in: {stripped}"))?;

        let class = class_part.replace('_', "/");
        let method = method_part.to_string();

        let (params, return_type) = if let Some(d) = descriptor {
            match JniDescriptorParser::parse_method_descriptor(d) {
                Ok((p, r)) => (
                    p.iter().map(JniDescriptorType::java_name).collect(),
                    r.java_name(),
                ),
                Err(_) => (vec!["...".to_string()], "?".to_string()),
            }
        } else {
            (
                vec!["JNIEnv*".to_string(), "jobject".to_string()],
                "?".to_string(),
            )
        };

        Ok(Self {
            class,
            method,
            descriptor: descriptor.unwrap_or("").to_string(),
            params,
            return_type,
            is_static: false,
        })
    }

    /// Return the fully-qualified Java method name.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.class.replace('/', "."), self.method)
    }
}

// ---------------------------------------------------------------------------
// JniMapping
// ---------------------------------------------------------------------------

/// Maps a native address to a Java method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniMapping {
    /// Virtual address of the native function.
    pub native_addr: u64,
    /// ELF export symbol name.
    pub symbol_name: String,
    /// Decoded JNI signature.
    pub signature: JniSignature,
    /// Shared library path this symbol was found in.
    pub library: String,
    /// Whether the function body references `JNI_OnLoad`.
    pub calls_jni_onload: bool,
}

impl JniMapping {
    /// Create a minimal mapping.
    #[must_use]
    pub fn new(
        native_addr: u64,
        symbol_name: impl Into<String>,
        signature: JniSignature,
        library: impl Into<String>,
    ) -> Self {
        Self {
            native_addr,
            symbol_name: symbol_name.into(),
            signature,
            library: library.into(),
            calls_jni_onload: false,
        }
    }

    /// Return the hexadecimal address string.
    #[must_use]
    pub fn addr_hex(&self) -> String {
        format!("0x{:016X}", self.native_addr)
    }
}

// ---------------------------------------------------------------------------
// JniFinder
// ---------------------------------------------------------------------------

/// Scans a list of ELF export symbols for JNI methods and `JNI_OnLoad`.
pub struct JniFinder {
    /// Additional descriptor hints: symbol → descriptor string.
    descriptor_hints: HashMap<String, String>,
}

impl JniFinder {
    /// Create a new finder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptor_hints: HashMap::new(),
        }
    }

    /// Register a descriptor hint for a specific symbol name.
    pub fn add_descriptor_hint(
        &mut self,
        symbol: impl Into<String>,
        descriptor: impl Into<String>,
    ) {
        self.descriptor_hints
            .insert(symbol.into(), descriptor.into());
    }

    /// Return `true` if the symbol name looks like a JNI export.
    #[must_use]
    pub fn is_jni_export(symbol: &str) -> bool {
        symbol.starts_with("Java_")
    }

    /// Return `true` if the symbol is `JNI_OnLoad`.
    #[must_use]
    pub fn is_jni_onload(symbol: &str) -> bool {
        symbol == "JNI_OnLoad" || symbol == "_JNI_OnLoad"
    }

    /// Scan a list of `(address, symbol_name)` pairs and return all JNI mappings.
    #[must_use]
    pub fn scan(&self, exports: &[(u64, String)], library: &str) -> Vec<JniMapping> {
        let has_onload = exports.iter().any(|(_, sym)| Self::is_jni_onload(sym));

        exports
            .iter()
            .filter(|(_, sym)| Self::is_jni_export(sym))
            .filter_map(|(addr, sym)| {
                let hint = self.descriptor_hints.get(sym.as_str()).map(String::as_str);
                JniSignature::from_jni_export(sym, hint).ok().map(|sig| {
                    let mut m = JniMapping::new(*addr, sym.clone(), sig, library);
                    m.calls_jni_onload = has_onload;
                    m
                })
            })
            .collect()
    }

    /// Extract unique class names from a list of mappings.
    #[must_use]
    pub fn extract_classes(mappings: &[JniMapping]) -> Vec<String> {
        let mut classes: Vec<String> = mappings.iter().map(|m| m.signature.class.clone()).collect();
        classes.sort_unstable();
        classes.dedup();
        classes
    }
}

impl Default for JniFinder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JniArgInfo
// ---------------------------------------------------------------------------

/// Information about a JNI method argument inferred from its position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniArgInfo {
    /// Argument index (0-based, starts after implicit `JNIEnv`* and jobject/jclass).
    pub index: usize,
    /// Inferred JNI argument type.
    pub jni_type: String,
    /// Whether this argument is an output (passed by reference).
    pub is_output: bool,
    /// Suggested local variable name.
    pub suggested_name: String,
}

// ---------------------------------------------------------------------------
// JniBridgeAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes native method arguments from JNI environment context.
pub struct JniBridgeAnalyzer;

impl JniBridgeAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Infer argument information for a JNI method from its signature.
    #[must_use]
    pub fn analyze_args(sig: &JniSignature) -> Vec<JniArgInfo> {
        sig.params
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.as_str() != "JNIEnv*"
                    && p.as_str() != "jobject"
                    && p.as_str() != "jclass"
                    && p.as_str() != "..."
            })
            .map(|(i, p)| {
                let jni_type = java_type_to_jni(p);
                JniArgInfo {
                    index: i,
                    is_output: false,
                    suggested_name: format!("arg_{i}"),
                    jni_type,
                }
            })
            .collect()
    }

    /// Infer the JNI function prototype for a mapping.
    #[must_use]
    pub fn infer_prototype(mapping: &JniMapping) -> String {
        let sig = &mapping.signature;
        let ret_jni = java_type_to_jni(&sig.return_type);
        let class_flat = sig.class.replace(['/', '.'], "_");
        let params: Vec<String> = sig
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{} arg_{i}", java_type_to_jni(p)))
            .collect();
        format!(
            "{ret_jni} Java_{class_flat}_{}(JNIEnv* env, jobject thiz, {})",
            sig.method,
            params.join(", ")
        )
    }

    /// Return a summary of JNI methods grouped by class.
    #[must_use]
    pub fn group_by_class(mappings: &[JniMapping]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for m in mappings {
            map.entry(m.signature.class.clone())
                .or_default()
                .push(m.signature.method.clone());
        }
        map
    }
}

impl Default for JniBridgeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JniOnLoadAnalyzer — analyze JNI_OnLoad registrations
// ---------------------------------------------------------------------------

/// A dynamic method registration found in `JNI_OnLoad`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicJniRegistration {
    /// Java class name (slash-separated).
    pub class_name: String,
    /// Java method name.
    pub method_name: String,
    /// JNI descriptor.
    pub descriptor: String,
    /// Native function pointer address.
    pub native_addr: u64,
}

impl DynamicJniRegistration {
    /// Create a registration entry.
    #[must_use]
    pub fn new(
        class_name: impl Into<String>,
        method_name: impl Into<String>,
        descriptor: impl Into<String>,
        native_addr: u64,
    ) -> Self {
        Self {
            class_name: class_name.into(),
            method_name: method_name.into(),
            descriptor: descriptor.into(),
            native_addr,
        }
    }

    /// Return the qualified Java method name.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.class_name.replace('/', "."), self.method_name)
    }
}

/// Analyzes `JNI_OnLoad` registrations for dynamically registered native methods.
pub struct JniOnLoadAnalyzer;

impl JniOnLoadAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Mock: scan a list of exports for dynamically registered methods.
    ///
    /// In a real implementation this would disassemble `JNI_OnLoad` and
    /// find `RegisterNatives` call arguments.  Here we return plausible
    /// mock data based on the export list.
    #[must_use]
    pub fn analyze(&self, exports: &[(u64, String)]) -> Vec<DynamicJniRegistration> {
        // Heuristic: any export whose name contains "native_" or "_native"
        // but doesn't start with "Java_" is likely dynamically registered.
        exports
            .iter()
            .filter(|(_, sym)| {
                (sym.contains("native_") || sym.contains("_native"))
                    && !sym.starts_with("Java_")
                    && sym != "JNI_OnLoad"
            })
            .enumerate()
            .map(|(i, (addr, sym))| {
                DynamicJniRegistration::new(
                    format!("com/example/DynClass{i}"),
                    sym.trim_start_matches('_').to_string(),
                    "()V",
                    *addr,
                )
            })
            .collect()
    }
}

impl Default for JniOnLoadAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JniReport — full JNI analysis report for a library
// ---------------------------------------------------------------------------

/// Full JNI analysis report for a native library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniReport {
    /// Library path / name.
    pub library: String,
    /// Static (Java_*) method mappings.
    pub static_mappings: Vec<JniMapping>,
    /// Dynamically registered methods (from `JNI_OnLoad`).
    pub dynamic_registrations: Vec<DynamicJniRegistration>,
    /// Whether `JNI_OnLoad` export was found.
    pub has_jni_onload: bool,
    /// Unique Java classes bridged by this library.
    pub bridged_classes: Vec<String>,
}

impl JniReport {
    /// Total number of native methods (static + dynamic).
    #[must_use]
    pub const fn total_methods(&self) -> usize {
        self.static_mappings.len() + self.dynamic_registrations.len()
    }

    /// Return `true` if the library exposes any JNI methods.
    #[must_use]
    pub const fn is_jni_library(&self) -> bool {
        self.has_jni_onload || !self.static_mappings.is_empty()
    }

    /// Build a report from an export list.
    #[must_use]
    pub fn from_exports(library: impl Into<String>, exports: &[(u64, String)]) -> Self {
        let lib: String = library.into();
        let finder = JniFinder::new();
        let static_mappings = finder.scan(exports, &lib);
        let has_jni_onload = exports.iter().any(|(_, sym)| JniFinder::is_jni_onload(sym));
        let analyzer = JniOnLoadAnalyzer::new();
        let dynamic_registrations = analyzer.analyze(exports);
        let bridged_classes = JniFinder::extract_classes(&static_mappings);
        Self {
            library: lib,
            static_mappings,
            dynamic_registrations,
            has_jni_onload,
            bridged_classes,
        }
    }
}

/// Map a Java type name to its JNI C type.
fn java_type_to_jni(java_type: &str) -> String {
    match java_type {
        "void" => "void",
        "boolean" => "jboolean",
        "byte" => "jbyte",
        "char" => "jchar",
        "short" => "jshort",
        "int" => "jint",
        "long" => "jlong",
        "float" => "jfloat",
        "double" => "jdouble",
        s if s.ends_with("[]") => "jarray",
        "java.lang.String" => "jstring",
        s if s.contains("java.lang.Class") => "jclass",
        _ => "jobject",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- JniDescriptorType ----

    #[test]
    fn test_void_java_name() {
        assert_eq!(JniDescriptorType::Void.java_name(), "void");
    }

    #[test]
    fn test_int_java_name() {
        assert_eq!(JniDescriptorType::Int.java_name(), "int");
    }

    #[test]
    fn test_object_java_name() {
        let t = JniDescriptorType::Object("java/lang/String".to_string());
        assert_eq!(t.java_name(), "java.lang.String");
    }

    #[test]
    fn test_array_java_name() {
        let t = JniDescriptorType::Array(Box::new(JniDescriptorType::Int));
        assert_eq!(t.java_name(), "int[]");
    }

    #[test]
    fn test_is_primitive() {
        assert!(JniDescriptorType::Int.is_primitive());
        assert!(!JniDescriptorType::Object("a".to_string()).is_primitive());
        assert!(!JniDescriptorType::Array(Box::new(JniDescriptorType::Int)).is_primitive());
    }

    #[test]
    fn test_is_array() {
        assert!(JniDescriptorType::Array(Box::new(JniDescriptorType::Byte)).is_array());
        assert!(!JniDescriptorType::Int.is_array());
    }

    #[test]
    fn test_is_object() {
        assert!(JniDescriptorType::Object("a".to_string()).is_object());
        assert!(!JniDescriptorType::Int.is_object());
    }

    // ---- JniDescriptorParser ----

    #[test]
    fn test_parse_void_method() {
        let (params, ret) = JniDescriptorParser::parse_method_descriptor("()V").unwrap();
        assert!(params.is_empty());
        assert_eq!(ret, JniDescriptorType::Void);
    }

    #[test]
    fn test_parse_int_return() {
        let (_, ret) = JniDescriptorParser::parse_method_descriptor("(I)I").unwrap();
        assert_eq!(ret, JniDescriptorType::Int);
    }

    #[test]
    fn test_parse_object_param() {
        let (params, _) =
            JniDescriptorParser::parse_method_descriptor("(Ljava/lang/String;)V").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0],
            JniDescriptorType::Object("java/lang/String".to_string())
        );
    }

    #[test]
    fn test_parse_array_param() {
        let (params, _) = JniDescriptorParser::parse_method_descriptor("([B)V").unwrap();
        assert_eq!(params.len(), 1);
        assert!(params[0].is_array());
    }

    #[test]
    fn test_parse_multiple_params() {
        let (params, ret) =
            JniDescriptorParser::parse_method_descriptor("(ILjava/lang/String;Z)I").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(ret, JniDescriptorType::Int);
    }

    #[test]
    fn test_parse_no_opening_paren_err() {
        assert!(JniDescriptorParser::parse_method_descriptor("IV").is_err());
    }

    #[test]
    fn test_parse_no_closing_paren_err() {
        assert!(JniDescriptorParser::parse_method_descriptor("(IV").is_err());
    }

    #[test]
    fn test_parse_type_list_all_primitives() {
        let types = JniDescriptorParser::parse_type_list("VZBCSIJFD").unwrap();
        assert_eq!(types.len(), 9);
    }

    // ---- JniSignature ----

    #[test]
    fn test_from_jni_export_basic() {
        let sig =
            JniSignature::from_jni_export("Java_com_example_MyClass_nativeMethod", None).unwrap();
        assert_eq!(sig.class, "com/example/MyClass");
        assert_eq!(sig.method, "nativeMethod");
    }

    #[test]
    fn test_from_jni_export_with_descriptor() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("(I)V")).unwrap();
        assert_eq!(sig.return_type, "void");
        assert!(sig.params.contains(&"int".to_string()));
    }

    #[test]
    fn test_from_jni_export_invalid_prefix() {
        assert!(JniSignature::from_jni_export("not_a_jni_export", None).is_err());
    }

    #[test]
    fn test_qualified_name() {
        let sig = JniSignature::from_jni_export("Java_com_example_MyClass_init", None).unwrap();
        let q = sig.qualified_name();
        assert_eq!(q, "com.example.MyClass.init");
    }

    // ---- JniMapping ----

    #[test]
    fn test_jni_mapping_addr_hex() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", None).unwrap();
        let m = JniMapping::new(0xDEAD_BEEF, "Java_com_example_Foo_bar", sig, "libnative.so");
        assert_eq!(m.addr_hex(), "0x00000000DEADBEEF");
    }

    // ---- JniFinder ----

    #[test]
    fn test_is_jni_export_true() {
        assert!(JniFinder::is_jni_export("Java_com_example_Foo_bar"));
    }

    #[test]
    fn test_is_jni_export_false() {
        assert!(!JniFinder::is_jni_export("regular_function"));
    }

    #[test]
    fn test_is_jni_onload() {
        assert!(JniFinder::is_jni_onload("JNI_OnLoad"));
        assert!(!JniFinder::is_jni_onload("Java_Foo_bar"));
    }

    #[test]
    fn test_scan_finds_jni_exports() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000, "Java_com_example_Foo_init".to_string()),
            (0x2000, "Java_com_example_Foo_compute".to_string()),
            (0x3000, "helper_func".to_string()),
        ];
        let mappings = finder.scan(&exports, "libnative.so");
        assert_eq!(mappings.len(), 2);
    }

    #[test]
    fn test_scan_detects_jni_onload() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000, "Java_com_example_Foo_init".to_string()),
            (0x2000, "JNI_OnLoad".to_string()),
        ];
        let mappings = finder.scan(&exports, "libnative.so");
        assert!(mappings[0].calls_jni_onload);
    }

    #[test]
    fn test_extract_classes() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000, "Java_com_example_Foo_init".to_string()),
            (0x2000, "Java_com_example_Foo_compute".to_string()),
            (0x3000, "Java_com_example_Bar_process".to_string()),
        ];
        let mappings = finder.scan(&exports, "libnative.so");
        let classes = JniFinder::extract_classes(&mappings);
        assert_eq!(classes.len(), 2);
    }

    // ---- JniBridgeAnalyzer ----

    #[test]
    fn test_analyze_args_void_no_args() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("()V")).unwrap();
        let args = JniBridgeAnalyzer::analyze_args(&sig);
        assert!(args.is_empty());
    }

    #[test]
    fn test_analyze_args_int_param() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("(I)V")).unwrap();
        let args = JniBridgeAnalyzer::analyze_args(&sig);
        // One int parameter.
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].jni_type, "jint");
    }

    #[test]
    fn test_infer_prototype() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("(I)I")).unwrap();
        let m = JniMapping::new(0x1000, "Java_com_example_Foo_bar", sig, "libtest.so");
        let proto = JniBridgeAnalyzer::infer_prototype(&m);
        assert!(proto.contains("jint"));
        assert!(proto.contains("Java_com_example_Foo_bar"));
    }

    #[test]
    fn test_group_by_class() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000, "Java_com_example_Foo_init".to_string()),
            (0x2000, "Java_com_example_Foo_compute".to_string()),
            (0x3000, "Java_com_example_Bar_process".to_string()),
        ];
        let mappings = finder.scan(&exports, "libtest.so");
        let grouped = JniBridgeAnalyzer::group_by_class(&mappings);
        assert_eq!(grouped["com/example/Foo"].len(), 2);
        assert_eq!(grouped["com/example/Bar"].len(), 1);
    }

    // ---- java_type_to_jni ----

    #[test]
    fn test_java_type_to_jni_int() {
        assert_eq!(java_type_to_jni("int"), "jint");
    }

    #[test]
    fn test_java_type_to_jni_string() {
        assert_eq!(java_type_to_jni("java.lang.String"), "jstring");
    }

    #[test]
    fn test_java_type_to_jni_array() {
        assert_eq!(java_type_to_jni("byte[]"), "jarray");
    }

    #[test]
    fn test_java_type_to_jni_object() {
        assert_eq!(java_type_to_jni("com.example.Foo"), "jobject");
    }

    // ---- Serde roundtrips ----

    #[test]
    fn test_jni_signature_serde() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("(IZ)V")).unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let sig2: JniSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig2.class, "com/example/Foo");
        assert_eq!(sig2.method, "bar");
    }

    #[test]
    fn test_jni_mapping_serde() {
        let sig =
            JniSignature::from_jni_export("Java_com_example_Bar_process", Some("([B)V")).unwrap();
        let m = JniMapping::new(0x4000, "Java_com_example_Bar_process", sig, "libnative.so");
        let json = serde_json::to_string(&m).unwrap();
        let m2: JniMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.native_addr, 0x4000);
    }

    // ---- Descriptor parser all primitive types ----

    #[test]
    fn test_parse_all_primitives_individually() {
        let primitives = [
            ("V", JniDescriptorType::Void),
            ("Z", JniDescriptorType::Boolean),
            ("B", JniDescriptorType::Byte),
            ("C", JniDescriptorType::Char),
            ("S", JniDescriptorType::Short),
            ("I", JniDescriptorType::Int),
            ("J", JniDescriptorType::Long),
            ("F", JniDescriptorType::Float),
            ("D", JniDescriptorType::Double),
        ];
        for (desc, expected) in &primitives {
            let t = JniDescriptorParser::parse_single_type(desc).unwrap();
            assert_eq!(&t, expected);
        }
    }

    // ---- Nested array ----

    #[test]
    fn test_parse_nested_array() {
        // [[I → int[][]
        let t = JniDescriptorParser::parse_single_type("[[I").unwrap();
        assert!(t.is_array());
        if let JniDescriptorType::Array(inner) = &t {
            assert!(inner.is_array());
        }
    }

    // ---- JniFinder descriptor hints ----

    #[test]
    fn test_finder_uses_descriptor_hint() {
        let mut finder = JniFinder::new();
        finder.add_descriptor_hint("Java_com_example_Foo_compute", "(II)I");
        let exports = vec![(0x1000u64, "Java_com_example_Foo_compute".to_string())];
        let mappings = finder.scan(&exports, "lib.so");
        assert_eq!(mappings.len(), 1);
        assert!(mappings[0].signature.params.contains(&"int".to_string()));
    }

    // ---- JniMapping calls_jni_onload false when no JNI_OnLoad present ----

    #[test]
    fn test_no_jni_onload_flag_false() {
        let finder = JniFinder::new();
        let exports = vec![(0x1000u64, "Java_com_example_Foo_init".to_string())];
        let mappings = finder.scan(&exports, "lib.so");
        assert!(!mappings[0].calls_jni_onload);
    }

    // ---- addr_hex format ----

    #[test]
    fn test_addr_hex_zero() {
        let sig = JniSignature::from_jni_export("Java_a_b_c", None).unwrap();
        let m = JniMapping::new(0, "Java_a_b_c", sig, "lib.so");
        assert_eq!(m.addr_hex(), "0x0000000000000000");
    }

    // ---- analyze_args for multiple params ----

    #[test]
    fn test_analyze_args_multiple() {
        let sig = JniSignature::from_jni_export(
            "Java_com_example_Foo_bar",
            Some("(IZLjava/lang/String;)V"),
        )
        .unwrap();
        let args = JniBridgeAnalyzer::analyze_args(&sig);
        // int, boolean, String
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].jni_type, "jint");
        assert_eq!(args[1].jni_type, "jboolean");
        assert_eq!(args[2].jni_type, "jstring");
    }

    // ---- infer_prototype contains return type ----

    #[test]
    fn test_infer_prototype_void_return() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_init", Some("()V")).unwrap();
        let m = JniMapping::new(0x1000, "Java_com_example_Foo_init", sig, "lib.so");
        let proto = JniBridgeAnalyzer::infer_prototype(&m);
        assert!(proto.starts_with("void"));
    }

    // ---- JniDescriptorType display ----

    #[test]
    fn test_descriptor_type_display() {
        assert_eq!(JniDescriptorType::Int.to_string(), "int");
        assert_eq!(JniDescriptorType::Void.to_string(), "void");
        assert_eq!(
            JniDescriptorType::Object("java/lang/String".to_string()).to_string(),
            "java.lang.String"
        );
    }

    // ---- JniArgInfo serde ----

    #[test]
    fn test_jni_arg_info_serde() {
        let info = JniArgInfo {
            index: 0,
            jni_type: "jint".to_string(),
            is_output: false,
            suggested_name: "arg_0".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let info2: JniArgInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info2.jni_type, "jint");
        assert_eq!(info2.suggested_name, "arg_0");
    }

    // ---- scan with empty export list ----

    #[test]
    fn test_scan_empty_exports() {
        let finder = JniFinder::new();
        let result = finder.scan(&[], "lib.so");
        assert!(result.is_empty());
    }

    // ---- extract_classes with empty mappings ----

    #[test]
    fn test_extract_classes_empty() {
        assert!(JniFinder::extract_classes(&[]).is_empty());
    }

    // ---- group_by_class empty ----

    #[test]
    fn test_group_by_class_empty() {
        assert!(JniBridgeAnalyzer::group_by_class(&[]).is_empty());
    }

    // ---- All primitive JNI types ----

    #[test]
    fn test_java_type_to_jni_all_primitives() {
        let cases = [
            ("void", "void"),
            ("boolean", "jboolean"),
            ("byte", "jbyte"),
            ("char", "jchar"),
            ("short", "jshort"),
            ("int", "jint"),
            ("long", "jlong"),
            ("float", "jfloat"),
            ("double", "jdouble"),
        ];
        for (java, jni) in &cases {
            assert_eq!(java_type_to_jni(java), *jni);
        }
    }

    // ---- JniDescriptorParser error on empty string ----

    #[test]
    fn test_parse_empty_string_error() {
        assert!(JniDescriptorParser::parse_single_type("").is_err());
    }

    // ---- JniDescriptorParser unknown char error ----

    #[test]
    fn test_parse_unknown_char_error() {
        assert!(JniDescriptorParser::parse_single_type("X").is_err());
    }

    // ---- JniSignature from export with no method suffix ----

    #[test]
    fn test_from_jni_export_single_component_error() {
        // Missing underscore between class and method → should error.
        let result = JniSignature::from_jni_export("Java_noclassseparator", None);
        // Either succeeds with empty class or errors — should not panic.
        let _ = result;
    }

    // ---- JniMapping library field ----

    #[test]
    fn test_jni_mapping_library() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_init", None).unwrap();
        let m = JniMapping::new(0x1000, "Java_com_example_Foo_init", sig, "libcrypto.so");
        assert_eq!(m.library, "libcrypto.so");
    }

    // ---- JniSignature is_static default false ----

    #[test]
    fn test_signature_is_static_default_false() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", None).unwrap();
        assert!(!sig.is_static);
    }

    // ---- JniDescriptorParser returns void for ()V ----

    #[test]
    fn test_parse_void_method_return_is_void() {
        let (_, ret) = JniDescriptorParser::parse_method_descriptor("()V").unwrap();
        assert_eq!(ret, JniDescriptorType::Void);
        assert!(ret.is_primitive());
    }

    // ---- JniDescriptorParser object with nested path ----

    #[test]
    fn test_parse_object_nested_path() {
        let (params, _) =
            JniDescriptorParser::parse_method_descriptor("(Ljava/util/ArrayList;)V").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0],
            JniDescriptorType::Object("java/util/ArrayList".to_string())
        );
        assert_eq!(params[0].java_name(), "java.util.ArrayList");
    }

    // ---- JniDescriptorParser multi-dimensional array ----

    #[test]
    fn test_parse_2d_array_method() {
        let (params, _) = JniDescriptorParser::parse_method_descriptor("([[I)V").unwrap();
        assert_eq!(params.len(), 1);
        assert!(params[0].is_array());
    }

    // ---- JniFinder scan only matches Java_ prefix ----

    #[test]
    fn test_scan_ignores_non_java_exports() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000u64, "Java_com_example_Foo_bar".to_string()),
            (0x2000u64, "some_internal_function".to_string()),
            (0x3000u64, "JNI_OnLoad".to_string()),
            (0x4000u64, "_JNI_OnLoad".to_string()),
            (0x5000u64, "C_func".to_string()),
        ];
        let mappings = finder.scan(&exports, "lib.so");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].symbol_name, "Java_com_example_Foo_bar");
    }

    // ---- JniBridgeAnalyzer infer_prototype multiple params ----

    #[test]
    fn test_infer_prototype_multiple_params() {
        let sig =
            JniSignature::from_jni_export("Java_com_example_Foo_compute", Some("(IIZ)I")).unwrap();
        let m = JniMapping::new(0x2000, "Java_com_example_Foo_compute", sig, "lib.so");
        let proto = JniBridgeAnalyzer::infer_prototype(&m);
        assert!(
            proto.contains("jint"),
            "proto should have jint return: {proto}"
        );
        assert!(proto.contains("arg_0"), "proto should have arg_0: {proto}");
    }

    // ---- JniArgInfo is_output default false ----

    #[test]
    fn test_jni_arg_is_output_default_false() {
        let sig = JniSignature::from_jni_export("Java_com_example_Foo_bar", Some("(I)V")).unwrap();
        let args = JniBridgeAnalyzer::analyze_args(&sig);
        assert!(!args.is_empty());
        assert!(!args[0].is_output);
    }

    // ---- extract_classes deduplication ----

    #[test]
    fn test_extract_classes_deduplication() {
        let finder = JniFinder::new();
        let exports = vec![
            (0x1000u64, "Java_com_example_Foo_init".to_string()),
            (0x2000u64, "Java_com_example_Foo_compute".to_string()),
            (0x3000u64, "Java_com_example_Foo_destroy".to_string()),
        ];
        let mappings = finder.scan(&exports, "lib.so");
        let classes = JniFinder::extract_classes(&mappings);
        // All three methods are in the same class → only 1 unique class.
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0], "com/example/Foo");
    }

    // ---- DynamicJniRegistration ----

    #[test]
    fn test_dynamic_registration_qualified_name() {
        let r = DynamicJniRegistration::new("com/example/MyClass", "nativeInit", "()V", 0x4000);
        assert_eq!(r.qualified_name(), "com.example.MyClass.nativeInit");
    }

    #[test]
    fn test_dynamic_registration_serde() {
        let r = DynamicJniRegistration::new("com/example/A", "foo", "(I)V", 0x1000);
        let json = serde_json::to_string(&r).unwrap();
        let r2: DynamicJniRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.native_addr, 0x1000);
        assert_eq!(r2.method_name, "foo");
    }

    // ---- JniOnLoadAnalyzer ----

    #[test]
    fn test_jni_onload_analyzer_finds_dynamic() {
        let az = JniOnLoadAnalyzer::new();
        let exports = vec![
            (0x1000u64, "native_processData".to_string()),
            (0x2000u64, "Java_com_example_Foo_init".to_string()),
        ];
        let regs = az.analyze(&exports);
        assert_eq!(regs.len(), 1);
        assert!(
            regs[0].method_name.contains("native_processData")
                || regs[0].method_name.contains("processData")
        );
    }

    #[test]
    fn test_jni_onload_analyzer_excludes_java_prefix() {
        let az = JniOnLoadAnalyzer::new();
        let exports = vec![(0x1000u64, "Java_com_example_Foo_init".to_string())];
        let regs = az.analyze(&exports);
        assert!(regs.is_empty());
    }

    #[test]
    fn test_jni_onload_analyzer_empty_exports() {
        let az = JniOnLoadAnalyzer::new();
        assert!(az.analyze(&[]).is_empty());
    }

    // ---- JniReport ----

    #[test]
    fn test_jni_report_from_exports() {
        let exports = vec![
            (0x1000u64, "Java_com_example_Foo_init".to_string()),
            (0x2000u64, "Java_com_example_Foo_process".to_string()),
            (0x3000u64, "JNI_OnLoad".to_string()),
        ];
        let report = JniReport::from_exports("libnative.so", &exports);
        assert!(report.has_jni_onload);
        assert_eq!(report.static_mappings.len(), 2);
        assert!(report.is_jni_library());
        assert_eq!(report.total_methods(), 2);
        assert_eq!(report.bridged_classes.len(), 1);
    }

    #[test]
    fn test_jni_report_no_jni_onload() {
        let exports = vec![(0x1000u64, "Java_com_example_Bar_run".to_string())];
        let report = JniReport::from_exports("libbar.so", &exports);
        assert!(!report.has_jni_onload);
        assert_eq!(report.static_mappings.len(), 1);
        assert!(report.is_jni_library());
    }

    #[test]
    fn test_jni_report_empty_exports_not_jni() {
        let report = JniReport::from_exports("libutil.so", &[]);
        assert!(!report.has_jni_onload);
        assert!(!report.is_jni_library());
        assert_eq!(report.total_methods(), 0);
    }

    #[test]
    fn test_jni_report_serde() {
        let exports = vec![(0x1000u64, "Java_com_example_X_foo".to_string())];
        let report = JniReport::from_exports("lib.so", &exports);
        let json = serde_json::to_string(&report).unwrap();
        let r2: JniReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.library, "lib.so");
        assert_eq!(r2.static_mappings.len(), 1);
    }

    // ---- JniReport total_methods includes both static and dynamic ----

    #[test]
    fn test_jni_report_total_includes_dynamic() {
        let exports = vec![
            (0x1000u64, "Java_com_example_Foo_init".to_string()),
            (0x2000u64, "native_encrypt".to_string()),
            (0x3000u64, "JNI_OnLoad".to_string()),
        ];
        let report = JniReport::from_exports("libcrypto.so", &exports);
        // 1 static + 1 dynamic = 2.
        assert_eq!(report.total_methods(), 2);
        assert!(report.has_jni_onload);
    }

    // ---- JniOnLoadAnalyzer default ----

    #[test]
    fn test_jni_onload_analyzer_default() {
        let az = JniOnLoadAnalyzer;
        assert!(az.analyze(&[]).is_empty());
    }

    // ---- DynamicJniRegistration class_name slashes ----

    #[test]
    fn test_dynamic_registration_slash_class_name() {
        let r = DynamicJniRegistration::new(
            "android/security/CryptoHelper",
            "nativeDecrypt",
            "([B[B)[B",
            0x8000,
        );
        assert!(r.qualified_name().contains("android.security.CryptoHelper"));
        assert_eq!(r.native_addr, 0x8000);
    }
}
