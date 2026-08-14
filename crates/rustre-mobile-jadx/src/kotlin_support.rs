//! Kotlin support for JADX decompiler output analysis.
//!
//! `KotlinMetadata` annotation parsing, data/sealed class recognition,
//! companion object, inline/extension functions, lambda lifting,
//! coroutine state machine detection.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KotlinError {
    #[error("missing kotlin.Metadata annotation")]
    MissingMetadata,
    #[error("unsupported metadata kind: {0}")]
    UnsupportedKind(i32),
    #[error("proto decode error: {0}")]
    ProtoDecode(String),
}

pub type KotlinResult<T> = Result<T, KotlinError>;

// ── Metadata kind ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataKind {
    Class,
    File,
    SyntheticClass,
    MultiFileClassFacade,
    MultiFileClassPart,
    Unknown(i32),
}

impl From<i32> for MetadataKind {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Class,
            2 => Self::File,
            3 => Self::SyntheticClass,
            4 => Self::MultiFileClassFacade,
            5 => Self::MultiFileClassPart,
            n => Self::Unknown(n),
        }
    }
}

impl MetadataKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::File => "file",
            Self::SyntheticClass => "synthetic class",
            Self::MultiFileClassFacade => "multi-file class facade",
            Self::MultiFileClassPart => "multi-file class part",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ── Kotlin class flags (from proto) ──────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KotlinClassFlags: u32 {
        const IS_INTERFACE          = 0x0020;
        const IS_ENUM_CLASS         = 0x0080;
        const IS_ENUM_ENTRY         = 0x0100;
        const IS_ANNOTATION_CLASS   = 0x0200;
        const IS_OBJECT             = 0x0400;
        const IS_COMPANION_OBJECT   = 0x0800;
        const IS_INNER              = 0x1000;
        const IS_DATA               = 0x2000;
        const IS_EXTERNAL           = 0x4000;
        const IS_EXPECT             = 0x8000;
        const IS_INLINE             = 0x0001_0000;
        const IS_FUN_INTERFACE      = 0x0002_0000;
        const IS_VALUE              = 0x0004_0000;
        // Visibility bits [0..2]
        const VISIBILITY_INTERNAL   = 0x0000;
        const VISIBILITY_PRIVATE    = 0x0001;
        const VISIBILITY_PROTECTED  = 0x0002;
        const VISIBILITY_PUBLIC     = 0x0003;
        // Modality bits [3..4]
        const MODALITY_FINAL        = 0x0000;
        const MODALITY_OPEN         = 0x0008;
        const MODALITY_ABSTRACT     = 0x0010;
        const MODALITY_SEALED       = 0x0018;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KotlinFunctionFlags: u32 {
        const IS_OPERATOR           = 0x0200;
        const IS_INFIX              = 0x0400;
        const IS_INLINE             = 0x0800;
        const IS_TAILREC            = 0x1000;
        const IS_EXTERNAL           = 0x2000;
        const IS_SUSPEND            = 0x4000;
        const IS_EXPECT             = 0x8000;
        // Visibility
        const VISIBILITY_INTERNAL   = 0x0000;
        const VISIBILITY_PRIVATE    = 0x0001;
        const VISIBILITY_PROTECTED  = 0x0002;
        const VISIBILITY_PUBLIC     = 0x0003;
        // Modality
        const MODALITY_FINAL        = 0x0000;
        const MODALITY_OPEN         = 0x0008;
        const MODALITY_ABSTRACT     = 0x0010;
        const MODALITY_OPEN_MEMBER  = 0x0018;
    }
}

// ── Kotlin type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinType {
    pub class_name: String,
    pub nullable: bool,
    pub type_arguments: Vec<Self>,
}

impl KotlinType {
    pub fn simple(name: impl Into<String>) -> Self {
        Self { class_name: name.into(), nullable: false, type_arguments: Vec::new() }
    }

    pub fn nullable(name: impl Into<String>) -> Self {
        Self { class_name: name.into(), nullable: true, type_arguments: Vec::new() }
    }
}

// Note: `simple` / `nullable` cannot be `const fn` because `Into::into` is not const.

// ── Kotlin function ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinFunction {
    pub name: String,
    pub jvm_signature: Option<String>,
    pub flags: KotlinFunctionFlags,
    pub receiver_type: Option<KotlinType>,
    pub return_type: KotlinType,
    pub value_parameters: Vec<KotlinValueParameter>,
    pub type_parameters: Vec<KotlinTypeParameter>,
}

impl KotlinFunction {
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        self.receiver_type.is_some()
    }

    #[must_use]
    pub const fn is_suspend(&self) -> bool {
        self.flags.contains(KotlinFunctionFlags::IS_SUSPEND)
    }

    #[must_use]
    pub const fn is_inline(&self) -> bool {
        self.flags.contains(KotlinFunctionFlags::IS_INLINE)
    }

    #[must_use]
    pub const fn is_operator(&self) -> bool {
        self.flags.contains(KotlinFunctionFlags::IS_OPERATOR)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinValueParameter {
    pub name: String,
    pub type_: KotlinType,
    pub has_default: bool,
    pub is_vararg: bool,
    pub is_noinline: bool,
    pub is_crossinline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinTypeParameter {
    pub name: String,
    pub index: i32,
    pub variance: Variance,
    pub upper_bounds: Vec<KotlinType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Variance {
    In,
    Out,
    Invariant,
}

// ── Kotlin property ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinProperty {
    pub name: String,
    pub return_type: KotlinType,
    pub is_var: bool,
    pub is_delegated: bool,
    pub getter_jvm_signature: Option<String>,
    pub setter_jvm_signature: Option<String>,
    pub field_jvm_signature: Option<String>,
}

// ── Constructor ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinConstructor {
    pub is_secondary: bool,
    pub jvm_signature: Option<String>,
    pub value_parameters: Vec<KotlinValueParameter>,
}

// ── Kotlin class ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinClass {
    pub name: String,
    pub flags: KotlinClassFlags,
    pub kind: MetadataKind,
    pub super_types: Vec<KotlinType>,
    pub nested_classes: Vec<String>,
    pub functions: Vec<KotlinFunction>,
    pub properties: Vec<KotlinProperty>,
    pub constructors: Vec<KotlinConstructor>,
    pub companion_object_name: Option<String>,
    pub sealed_subclasses: Vec<String>,
    pub enum_entries: Vec<String>,
    pub type_parameters: Vec<KotlinTypeParameter>,
    pub version_requirement: Option<String>,
    /// JVM internal name, e.g. "com/example/MyClass"
    pub jvm_class_name: String,
}

impl KotlinClass {
    #[must_use]
    pub const fn is_data_class(&self) -> bool {
        self.flags.contains(KotlinClassFlags::IS_DATA)
    }

    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags.bits() & KotlinClassFlags::MODALITY_SEALED.bits() == KotlinClassFlags::MODALITY_SEALED.bits()
    }

    #[must_use]
    pub const fn is_companion(&self) -> bool {
        self.flags.contains(KotlinClassFlags::IS_COMPANION_OBJECT)
    }

    #[must_use]
    pub const fn is_object(&self) -> bool {
        self.flags.contains(KotlinClassFlags::IS_OBJECT)
    }

    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags.contains(KotlinClassFlags::IS_INTERFACE)
    }

    #[must_use]
    pub const fn has_companion(&self) -> bool {
        self.companion_object_name.is_some()
    }

    #[must_use]
    pub fn suspend_functions(&self) -> Vec<&KotlinFunction> {
        self.functions.iter().filter(|f| f.is_suspend()).collect()
    }

    #[must_use]
    pub fn extension_functions(&self) -> Vec<&KotlinFunction> {
        self.functions.iter().filter(|f| f.is_extension()).collect()
    }

    #[must_use]
    pub fn inline_functions(&self) -> Vec<&KotlinFunction> {
        self.functions.iter().filter(|f| f.is_inline()).collect()
    }
}

// ── KotlinMetadata annotation ─────────────────────────────────────────────────

/// Raw kotlin.Metadata annotation values as found in the DEX constant pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinMetadataAnnotation {
    pub kind: i32,
    pub metadata_version: Vec<i32>,
    pub data1: Vec<String>,
    pub data2: Vec<String>,
    pub extra_string: String,
    pub package_name: String,
    pub extra_int: i32,
}

impl KotlinMetadataAnnotation {
    #[must_use]
    pub fn metadata_kind(&self) -> MetadataKind {
        MetadataKind::from(self.kind)
    }

    #[must_use]
    pub fn kotlin_version(&self) -> String {
        self.metadata_version
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

// ── Coroutine state machine detection ────────────────────────────────────────

/// Indicators that a class is a Kotlin coroutine state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoroutineStateMachine {
    pub class_name: String,
    pub parent_function: Option<String>,
    /// Number of states (label values) detected.
    pub state_count: usize,
    pub has_continuation_field: bool,
    pub has_result_field: bool,
    pub has_label_field: bool,
    pub suspension_points: Vec<String>,
}

impl CoroutineStateMachine {
    /// Heuristically detect coroutine state machines from class metadata.
    #[must_use]
    pub fn detect(class: &KotlinClass) -> Option<Self> {
        // Coroutine continuations: implement kotlin.coroutines.Continuation
        // and have a synthetic `invokeSuspend` method
        let has_invoke_suspend = class.functions.iter().any(|f| f.name == "invokeSuspend");
        let has_continuation_super = class
            .super_types
            .iter()
            .any(|t| t.class_name.contains("ContinuationImpl") || t.class_name.contains("BaseContinuationImpl"));

        if !has_invoke_suspend && !has_continuation_super {
            return None;
        }

        // Estimate state count from number of suspend calls in invokeSuspend
        let state_count = class.functions.iter()
            .filter(|f| f.name == "invokeSuspend")
            .count()
            .max(1);

        let suspension_points = class
            .functions
            .iter()
            .filter(|f| f.is_suspend() && f.name != "invokeSuspend")
            .map(|f| f.name.clone())
            .collect();

        Some(Self {
            class_name: class.name.clone(),
            parent_function: None,
            state_count,
            has_continuation_field: class.properties.iter().any(|p| p.name.contains("continuation")),
            has_result_field: class.properties.iter().any(|p| p.name == "result"),
            has_label_field: class.properties.iter().any(|p| p.name == "label"),
            suspension_points,
        })
    }
}

// ── Lambda lifting detector ───────────────────────────────────────────────────

/// A lambda lifted to a synthetic class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedLambda {
    pub synthetic_class_name: String,
    pub arity: usize,
    pub capturing_class: Option<String>,
    pub is_suspend: bool,
}

impl LiftedLambda {
    #[must_use]
    pub fn detect(class: &KotlinClass) -> Option<Self> {
        // Lambda classes: MetadataKind::SyntheticClass, implement FunctionN
        if !matches!(class.kind, MetadataKind::SyntheticClass) {
            return None;
        }
        let function_arity = class
            .super_types
            .iter()
            .find(|t| t.class_name.starts_with("kotlin.jvm.functions.Function"))
            .and_then(|t| {
                t.class_name
                    .trim_start_matches("kotlin.jvm.functions.Function")
                    .parse::<usize>()
                    .ok()
            });

        let is_suspend = class
            .super_types
            .iter()
            .any(|t| t.class_name.contains("SuspendFunction"));

        function_arity.map(|arity| Self {
            synthetic_class_name: class.name.clone(),
            arity,
            capturing_class: None,
            is_suspend,
        })
    }
}

// ── Sealed class hierarchy ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedHierarchy {
    pub sealed_class: String,
    pub subclasses: Vec<String>,
    pub is_exhaustive_when_possible: bool,
}

impl SealedHierarchy {
    #[must_use]
    pub fn collect_from(classes: &[KotlinClass]) -> Vec<Self> {
        classes
            .iter()
            .filter(|c| c.is_sealed() && !c.sealed_subclasses.is_empty())
            .map(|c| Self {
                sealed_class: c.name.clone(),
                subclasses: c.sealed_subclasses.clone(),
                is_exhaustive_when_possible: true,
            })
            .collect()
    }
}

// ── Kotlin module analysis ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KotlinModuleAnalysis {
    pub classes: Vec<KotlinClass>,
    pub state_machines: Vec<CoroutineStateMachine>,
    pub lifted_lambdas: Vec<LiftedLambda>,
    pub sealed_hierarchies: Vec<SealedHierarchy>,
    pub data_classes: Vec<String>,
    pub companion_objects: Vec<String>,
    pub extension_functions: Vec<(String, String)>,
    pub total_suspend_functions: usize,
    pub total_inline_functions: usize,
    pub kotlin_version: Option<String>,
}

impl KotlinModuleAnalysis {
    #[must_use]
    pub fn from_classes(classes: Vec<KotlinClass>) -> Self {
        let mut analysis = Self::default();

        for cls in &classes {
            if cls.is_data_class() {
                analysis.data_classes.push(cls.name.clone());
            }
            if cls.is_companion() {
                analysis.companion_objects.push(cls.name.clone());
            }
            for ext in cls.extension_functions() {
                analysis.extension_functions.push((cls.name.clone(), ext.name.clone()));
            }
            analysis.total_suspend_functions += cls.suspend_functions().len();
            analysis.total_inline_functions += cls.inline_functions().len();

            if let Some(sm) = CoroutineStateMachine::detect(cls) {
                analysis.state_machines.push(sm);
            }
            if let Some(ll) = LiftedLambda::detect(cls) {
                analysis.lifted_lambdas.push(ll);
            }
        }

        analysis.sealed_hierarchies = SealedHierarchy::collect_from(&classes);
        analysis.classes = classes;
        analysis
    }
}

// ── String-based heuristic scanner ───────────────────────────────────────────

/// Detect Kotlin class patterns from a list of class descriptors (no proto).
#[must_use]
pub fn detect_kotlin_classes_heuristic(descriptors: &[String]) -> Vec<String> {
    descriptors
        .iter()
        .filter(|d| {
            // Kotlin classes often: contain $, end with Kt, or have DefaultImpls
            d.contains('$')
                || d.ends_with("Kt;")
                || d.contains("DefaultImpls")
                || d.contains("WhenMappings")
                || d.contains("Companion")
        })
        .cloned()
        .collect()
}

/// Detect coroutine-related classes by descriptor pattern.
#[must_use]
pub fn detect_coroutine_classes(descriptors: &[String]) -> Vec<String> {
    descriptors
        .iter()
        .filter(|d| {
            d.contains("$suspendImpl")
                || d.contains("ContinuationImpl")
                || d.contains("$1") // common lambda/continuation suffix
                || d.contains("invokeSuspend")
        })
        .cloned()
        .collect()
}

// ── Minimal proto reader ──────────────────────────────────────────────────────

/// Ultra-minimal protobuf reader for `KotlinMetadata` d1/d2 fields.
/// Only reads field tags and skips/reads varint/length-delimited fields.
pub struct ProtoReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_varint(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.data.len() {
                return None;
            }
            let b = u64::from(self.data[self.pos]);
            self.pos += 1;
            result |= (b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }

    pub fn read_tag(&mut self) -> Option<(u32, u8)> {
        let v = self.read_varint()?;
        let field_number = u32::try_from(v >> 3).unwrap_or(u32::MAX);
        let wire_type = u8::try_from(v & 0x7).unwrap_or(0);
        Some((field_number, wire_type))
    }

    pub fn skip_field(&mut self, wire_type: u8) -> Option<()> {
        match wire_type {
            0 => { self.read_varint()?; }
            1 => { self.pos += 8; }
            2 => {
                let len = u64_to_usize_lossy(self.read_varint()?);
                self.pos += len;
            }
            5 => { self.pos += 4; }
            _ => return None,
        }
        Some(())
    }

    pub fn read_length_delimited(&mut self) -> Option<&'a [u8]> {
        let len = u64_to_usize_lossy(self.read_varint()?);
        if self.pos + len > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(s)
    }

    pub fn read_string(&mut self) -> Option<String> {
        let bytes = self.read_length_delimited()?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    #[must_use]
    pub const fn remaining(&self) -> bool {
        self.pos < self.data.len()
    }
}

/// Cast `u64` to `usize`. Helper isolates the lossy cast.
fn u64_to_usize_lossy(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

// ── KotlinMetadata proto parser ───────────────────────────────────────────────

/// Parse a minimal subset of `KotlinMetadata` d1 proto bytes to extract class name.
#[must_use]
pub fn parse_class_name_from_proto(d1_bytes: &[u8]) -> Option<String> {
    let mut reader = ProtoReader::new(d1_bytes);
    while reader.remaining() {
        let (field, wire) = reader.read_tag()?;
        if field == 3 && wire == 2 {
            // field 3 = name in proto
            return reader.read_string();
        }
        reader.skip_field(wire)?;
    }
    None
}

// ── Summary ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KotlinSupportSummary {
    pub total_kotlin_classes: usize,
    pub data_classes: usize,
    pub sealed_classes: usize,
    pub companion_objects: usize,
    pub coroutine_state_machines: usize,
    pub lifted_lambdas: usize,
    pub suspend_functions: usize,
    pub inline_functions: usize,
    pub extension_functions: usize,
}

impl KotlinSupportSummary {
    #[must_use]
    pub const fn from_analysis(analysis: &KotlinModuleAnalysis) -> Self {
        Self {
            total_kotlin_classes: analysis.classes.len(),
            data_classes: analysis.data_classes.len(),
            sealed_classes: analysis.sealed_hierarchies.len(),
            companion_objects: analysis.companion_objects.len(),
            coroutine_state_machines: analysis.state_machines.len(),
            lifted_lambdas: analysis.lifted_lambdas.len(),
            suspend_functions: analysis.total_suspend_functions,
            inline_functions: analysis.total_inline_functions,
            extension_functions: analysis.extension_functions.len(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_class(name: &str, flags: KotlinClassFlags) -> KotlinClass {
        KotlinClass {
            name: name.to_owned(),
            flags,
            kind: MetadataKind::Class,
            super_types: Vec::new(),
            nested_classes: Vec::new(),
            functions: Vec::new(),
            properties: Vec::new(),
            constructors: Vec::new(),
            companion_object_name: None,
            sealed_subclasses: Vec::new(),
            enum_entries: Vec::new(),
            type_parameters: Vec::new(),
            version_requirement: None,
            jvm_class_name: name.replace('.', "/"),
        }
    }

    #[test]
    fn test_data_class_detection() {
        let cls = make_class("Person", KotlinClassFlags::IS_DATA | KotlinClassFlags::VISIBILITY_PUBLIC);
        assert!(cls.is_data_class());
    }

    #[test]
    fn test_companion_detection() {
        let cls = make_class("Companion", KotlinClassFlags::IS_COMPANION_OBJECT);
        assert!(cls.is_companion());
    }

    #[test]
    fn test_is_object() {
        let cls = make_class("MySingleton", KotlinClassFlags::IS_OBJECT);
        assert!(cls.is_object());
    }

    #[test]
    fn test_extension_function() {
        let mut cls = make_class("StringExtensions", KotlinClassFlags::empty());
        cls.functions.push(KotlinFunction {
            name: "toCamelCase".to_owned(),
            jvm_signature: None,
            flags: KotlinFunctionFlags::empty(),
            receiver_type: Some(KotlinType::simple("kotlin.String")),
            return_type: KotlinType::simple("kotlin.String"),
            value_parameters: Vec::new(),
            type_parameters: Vec::new(),
        });
        assert_eq!(cls.extension_functions().len(), 1);
    }

    #[test]
    fn test_suspend_function() {
        let mut cls = make_class("Fetcher", KotlinClassFlags::empty());
        cls.functions.push(KotlinFunction {
            name: "fetchData".to_owned(),
            jvm_signature: None,
            flags: KotlinFunctionFlags::IS_SUSPEND,
            receiver_type: None,
            return_type: KotlinType::simple("kotlin.Unit"),
            value_parameters: Vec::new(),
            type_parameters: Vec::new(),
        });
        assert_eq!(cls.suspend_functions().len(), 1);
    }

    #[test]
    fn test_detect_kotlin_heuristic() {
        let descs = vec![
            "Lcom/example/MainActivityKt;".to_owned(),
            "Lcom/example/Foo$Companion;".to_owned(),
            "Lcom/example/Normal;".to_owned(),
        ];
        let kotlin = detect_kotlin_classes_heuristic(&descs);
        assert_eq!(kotlin.len(), 2);
    }

    #[test]
    fn test_metadata_annotation_version() {
        let ann = KotlinMetadataAnnotation {
            kind: 1,
            metadata_version: vec![1, 9, 0],
            data1: Vec::new(),
            data2: Vec::new(),
            extra_string: String::new(),
            package_name: "com.example".to_owned(),
            extra_int: 0,
        };
        assert_eq!(ann.kotlin_version(), "1.9.0");
        assert_eq!(ann.metadata_kind(), MetadataKind::Class);
    }

    #[test]
    fn test_proto_reader_varint() {
        let data = &[0x01u8]; // varint 1
        let mut r = ProtoReader::new(data);
        assert_eq!(r.read_varint(), Some(1));
    }

    #[test]
    fn test_module_analysis() {
        let cls = make_class("Data", KotlinClassFlags::IS_DATA);
        let analysis = KotlinModuleAnalysis::from_classes(vec![cls]);
        assert_eq!(analysis.data_classes.len(), 1);
        let summary = KotlinSupportSummary::from_analysis(&analysis);
        assert_eq!(summary.data_classes, 1);
    }
}
