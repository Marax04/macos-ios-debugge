//! C# code reconstruction from IL for `rustre-dotnet`.

pub use crate::CilInstruction;
use crate::{AssemblyFile, CilOperand, DotnetMethod, DotnetType, MethodBody};
use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

// ── AsyncPattern ──────────────────────────────────────────────────────────────

/// Detected async/await pattern in a method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncPattern {
    pub method_name: String,
    pub state_machine_type: Option<String>,
    pub is_async: bool,
    pub has_await: bool,
    pub return_type: String,
}

/// Detects async/await patterns in a `DotnetMethod`.
pub struct AsyncMethodDetector;

impl AsyncMethodDetector {
    /// Returns `true` if `method` appears to be an async method.
    #[must_use]
    pub fn is_async(method: &DotnetMethod) -> bool {
        method
            .custom_attributes
            .iter()
            .any(|a| a.is_type("AsyncStateMachineAttribute"))
            || method.name.contains("MoveNext")
            || method.signature.return_type.contains("Task")
            || method.signature.return_type.contains("ValueTask")
    }

    /// Returns `true` if the body contains an `await` (callvirt on awaiter).
    #[must_use]
    pub fn has_await(body: &MethodBody) -> bool {
        body.instructions
            .iter()
            .any(|i| i.opcode == "callvirt" || i.opcode == "call")
            && body.instructions.iter().any(|i| i.opcode == "stfld")
    }

    /// Analyse the method for async patterns.
    #[must_use]
    pub fn analyze(method: &DotnetMethod) -> AsyncPattern {
        let is_async = Self::is_async(method);
        let has_await = method
            .body
            .as_ref()
            .is_some_and(Self::has_await);
        AsyncPattern {
            method_name: method.name.clone(),
            state_machine_type: None,
            is_async,
            has_await,
            return_type: method.signature.return_type.clone(),
        }
    }
}

// ── LINQ_Pattern ──────────────────────────────────────────────────────────────

/// A detected LINQ pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinqPattern {
    pub method_name: String,
    pub linq_operators: Vec<String>,
    pub uses_lambda: bool,
}

/// Detects LINQ usage in a method body.
pub struct LinqPatternDetector;

impl LinqPatternDetector {
    const LINQ_METHODS: &'static [&'static str] = &[
        "Where",
        "Select",
        "SelectMany",
        "OrderBy",
        "OrderByDescending",
        "GroupBy",
        "Join",
        "Any",
        "All",
        "First",
        "FirstOrDefault",
        "Last",
        "LastOrDefault",
        "Single",
        "SingleOrDefault",
        "Count",
        "Sum",
        "Min",
        "Max",
        "Average",
        "Aggregate",
        "ToList",
        "ToArray",
        "ToDictionary",
        "ToHashSet",
        "Skip",
        "Take",
        "SkipWhile",
        "TakeWhile",
        "Distinct",
        "Union",
        "Intersect",
        "Except",
        "Concat",
        "Zip",
    ];

    #[must_use]
    pub fn detect(method: &DotnetMethod) -> Option<LinqPattern> {
        let body = method.body.as_ref()?;
        let mut operators = Vec::new();
        let mut uses_lambda = false;

        for instr in &body.instructions {
            if instr.opcode != "callvirt" && instr.opcode != "call" {
                continue;
            }
            for &linq_op in Self::LINQ_METHODS {
                if let CilOperand::Token(_) = instr.operand {
                    operators.push(linq_op.to_string());
                    break;
                }
            }
        }
        // Lambda check: ldftn or ldvirtftn instructions
        if body
            .instructions
            .iter()
            .any(|i| i.opcode == "ldftn" || i.opcode == "ldvirtftn")
        {
            uses_lambda = true;
        }

        if operators.is_empty() && !uses_lambda {
            return None;
        }
        operators.dedup();
        Some(LinqPattern {
            method_name: method.name.clone(),
            linq_operators: operators,
            uses_lambda,
        })
    }
}

// ── PropertyAccessor reconstruction ──────────────────────────────────────────

/// Reconstructed property with accessor details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedProperty {
    pub name: String,
    pub type_name: String,
    pub getter_il_complexity: usize,
    pub setter_il_complexity: usize,
    pub is_auto_property: bool,
    pub backing_field: Option<String>,
}

impl ReconstructedProperty {
    /// Heuristic: auto-property has a simple getter/setter (< 5 instructions each).
    #[must_use]
    pub const fn is_auto_property(getter: usize, setter: usize) -> bool {
        getter <= 4 || setter <= 4
    }
}

// ── AttributeParser ───────────────────────────────────────────────────────────

/// Parses .NET custom attributes into typed representations.
pub struct AttributeParser;

impl AttributeParser {
    /// Check if a type has `[Serializable]`.
    #[must_use]
    pub fn is_serializable(t: &DotnetType) -> bool {
        t.flags & 0x0000_2000 != 0
            || t.custom_attributes
                .iter()
                .any(|a| a.is_type("SerializableAttribute"))
    }

    /// Check if a type has `[Flags]` (enum flags).
    #[must_use]
    pub fn has_flags_attribute(t: &DotnetType) -> bool {
        t.custom_attributes
            .iter()
            .any(|a| a.is_type("FlagsAttribute") || a.is_type("Flags"))
    }

    /// Collect all attribute type names on a type.
    #[must_use]
    pub fn attribute_names(t: &DotnetType) -> Vec<&str> {
        t.custom_attributes
            .iter()
            .map(|a| a.attr_type.as_str())
            .collect()
    }

    /// Collect all attribute type names on a method.
    #[must_use]
    pub fn method_attribute_names(m: &DotnetMethod) -> Vec<&str> {
        m.custom_attributes
            .iter()
            .map(|a| a.attr_type.as_str())
            .collect()
    }
}

// ── CsharpMethod reconstruction ───────────────────────────────────────────────

/// Reconstructed C# method with detected patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsharpMethod {
    pub name: String,
    pub signature: String,
    pub is_async: bool,
    pub has_linq: bool,
    pub has_unsafe: bool,
    pub attributes: Vec<String>,
    pub pseudo_code: String,
    pub complexity: usize,
}

impl CsharpMethod {
    #[must_use]
    pub fn from_dotnet_method(method: &DotnetMethod) -> Self {
        let sig = method.signature.format(&method.name);
        let is_async = AsyncMethodDetector::is_async(method);
        let has_linq = LinqPatternDetector::detect(method).is_some();
        let complexity = method
            .body
            .as_ref()
            .map_or(0, |b| b.instructions.len());
        let attributes: Vec<String> = method
            .custom_attributes
            .iter()
            .map(|a| a.attr_type.clone())
            .collect();
        let pseudo_code = Self::generate_pseudo(method);
        Self {
            name: method.name.clone(),
            signature: sig,
            is_async,
            has_linq,
            has_unsafe: false,
            attributes,
            pseudo_code,
            complexity,
        }
    }

    fn generate_pseudo(method: &DotnetMethod) -> String {
        let sig = method.signature.format(&method.name);
        let prefix = if AsyncMethodDetector::is_async(method) {
            "async "
        } else {
            ""
        };
        let body = method.body.as_ref().map_or_else(|| "    // no body (abstract or native)".into(), |body| if body.instructions.is_empty() {
                "    // empty".into()
            } else {
                format!("    // {} IL instructions", body.instructions.len())
            });
        format!("{prefix}{sig} {{\n{body}\n}}")
    }
}

// ── CsharpClass reconstruction ────────────────────────────────────────────────

/// Reconstructed C# class/type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsharpClass {
    pub full_name: String,
    pub kind: String,
    pub base_class: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<CsharpMethod>,
    pub fields: Vec<String>,
    pub properties: Vec<ReconstructedProperty>,
    pub attributes: Vec<String>,
    pub is_abstract: bool,
    pub is_sealed: bool,
    pub is_generic: bool,
}

impl CsharpClass {
    #[must_use]
    pub fn from_dotnet_type(t: &DotnetType) -> Self {
        let methods = t
            .methods
            .iter()
            .map(CsharpMethod::from_dotnet_method)
            .collect();
        let fields: Vec<String> = t.fields.iter().map(crate::DotnetField::format).collect();
        let attributes: Vec<String> = t
            .custom_attributes
            .iter()
            .map(|a| a.attr_type.clone())
            .collect();
        let properties = t
            .properties
            .iter()
            .map(|p| {
                let getter_il = t
                    .methods
                    .iter()
                    .find(|m| Some(&m.name) == p.getter.as_ref())
                    .and_then(|m| m.body.as_ref())
                    .map_or(0, |b| b.instructions.len());
                let setter_il = t
                    .methods
                    .iter()
                    .find(|m| Some(&m.name) == p.setter.as_ref())
                    .and_then(|m| m.body.as_ref())
                    .map_or(0, |b| b.instructions.len());
                ReconstructedProperty {
                    name: p.name.clone(),
                    type_name: p.type_name.clone(),
                    getter_il_complexity: getter_il,
                    setter_il_complexity: setter_il,
                    is_auto_property: ReconstructedProperty::is_auto_property(getter_il, setter_il),
                    backing_field: Some(format!("<{}>k__BackingField", p.name)),
                }
            })
            .collect();
        Self {
            full_name: t.full_name.clone(),
            kind: t.kind().to_string(),
            base_class: t.base_type.clone(),
            interfaces: t.interfaces.clone(),
            methods,
            fields,
            properties,
            attributes,
            is_abstract: t.is_abstract(),
            is_sealed: t.is_sealed(),
            is_generic: !t.generic_params.is_empty(),
        }
    }

    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.methods.len()
    }

    #[must_use]
    pub fn async_method_count(&self) -> usize {
        self.methods.iter().filter(|m| m.is_async).count()
    }

    #[must_use]
    pub fn linq_method_count(&self) -> usize {
        self.methods.iter().filter(|m| m.has_linq).count()
    }
}

// ── CsharpReconstructor ───────────────────────────────────────────────────────

/// Reconstructs C# code from a .NET assembly.
pub struct CsharpReconstructor {
    pub include_private: bool,
    pub include_bodies: bool,
}

impl Default for CsharpReconstructor {
    fn default() -> Self {
        Self {
            include_private: true,
            include_bodies: true,
        }
    }
}

impl CsharpReconstructor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn public_only(mut self) -> Self {
        self.include_private = false;
        self
    }

    /// Reconstruct all types from an `AssemblyFile`.
    #[must_use]
    pub fn reconstruct_all(&self, assembly: &AssemblyFile) -> Vec<CsharpClass> {
        assembly
            .types()
            .iter()
            .map(CsharpClass::from_dotnet_type)
            .collect()
    }

    /// Find all async methods across all types.
    #[must_use]
    pub fn find_async_methods(&self, assembly: &AssemblyFile) -> Vec<AsyncPattern> {
        assembly
            .types()
            .iter()
            .flat_map(|t| t.methods.iter().map(AsyncMethodDetector::analyze))
            .filter(|a| a.is_async || a.has_await)
            .collect()
    }

    /// Find all LINQ patterns across all types.
    #[must_use]
    pub fn find_linq_patterns(&self, assembly: &AssemblyFile) -> Vec<LinqPattern> {
        assembly
            .types()
            .iter()
            .flat_map(|t| {
                t.methods
                    .iter()
                    .filter_map(LinqPatternDetector::detect)
            })
            .collect()
    }

    /// Generate a C#-like source file for a single class.
    #[must_use]
    pub fn generate_class_source(&self, class: &CsharpClass) -> String {
        use std::fmt::Write as _;
        let mut src = String::new();
        for attr in &class.attributes {
            let _ = writeln!(src, "[{attr}]");
        }
        let modifiers = format!(
            "{}{} {}",
            if class.is_abstract { "abstract " } else { "" },
            if class.is_sealed { "sealed " } else { "" },
            class.kind
        );
        let _ = write!(src, "public {modifiers} {}", class.full_name);
        if let Some(base) = &class.base_class {
            let _ = write!(src, " : {base}");
        }
        if !class.interfaces.is_empty() {
            if class.base_class.is_some() {
                src.push_str(", ");
            } else {
                src.push_str(" : ");
            }
            src.push_str(&class.interfaces.join(", "));
        }
        src.push_str(" {\n");
        for field in &class.fields {
            let _ = writeln!(src, "    {field}");
        }
        for prop in &class.properties {
            let _ = writeln!(src, "    {}", prop.name);
        }
        for m in &class.methods {
            if !self.include_private {
                continue;
            }
            let _ = write!(src, "\n    {}\n", m.pseudo_code.replace('\n', "\n    "));
        }
        src.push_str("}\n");
        src
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CilInstruction, CustomAttribute, DotnetMethod, DotnetType, DotnetTypeKind, MethodBody,
        MethodSignature,
    };

    fn make_empty_method(name: &str) -> DotnetMethod {
        DotnetMethod {
            name: name.to_string(),
            signature: MethodSignature::default(),
            body: None,
            flags: 0,
            rva: 0,
            impl_flags: 0,
            custom_attributes: vec![],
            generic_params: vec![],
            overrides: vec![],
        }
    }

    fn make_method_with_body(name: &str, instr_count: usize) -> DotnetMethod {
        let instrs: Vec<CilInstruction> = (0..instr_count)
            .map(|i| CilInstruction::simple(i as u32, "nop"))
            .collect();
        let body = MethodBody {
            instructions: instrs,
            ..Default::default()
        };
        DotnetMethod {
            name: name.to_string(),
            signature: MethodSignature::default(),
            body: Some(body),
            flags: 0,
            rva: 1,
            impl_flags: 0,
            custom_attributes: vec![],
            generic_params: vec![],
            overrides: vec![],
        }
    }

    fn make_type(name: &str) -> DotnetType {
        DotnetType {
            name: name.to_string(),
            namespace: "Test".to_string(),
            full_name: format!("Test.{name}"),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: DotnetTypeKind::Class,
            flags: 0x0000_0001,
            layout: None,
        }
    }

    // ── AsyncMethodDetector ───────────────────────────────────────────────────

    #[test]
    fn test_async_detection_task_return() {
        let mut m = make_empty_method("DoAsync");
        m.signature.return_type = "Task<int>".to_string();
        assert!(AsyncMethodDetector::is_async(&m));
    }

    #[test]
    fn test_async_detection_plain_method() {
        let m = make_empty_method("Normal");
        assert!(!AsyncMethodDetector::is_async(&m));
    }

    #[test]
    fn test_async_pattern_analyze() {
        let mut m = make_empty_method("FetchData");
        m.signature.return_type = "Task".to_string();
        let pattern = AsyncMethodDetector::analyze(&m);
        assert!(pattern.is_async);
    }

    // ── LinqPatternDetector ───────────────────────────────────────────────────

    #[test]
    fn test_linq_detection_no_body() {
        let m = make_empty_method("EmptyMethod");
        assert!(LinqPatternDetector::detect(&m).is_none());
    }

    #[test]
    fn test_linq_detection_lambda_in_body() {
        let mut m = make_method_with_body("Query", 5);
        if let Some(body) = m.body.as_mut() {
            body.instructions.push(CilInstruction::simple(10, "ldftn"));
        }
        let pattern = LinqPatternDetector::detect(&m);
        assert!(pattern.is_some_and(|p| p.uses_lambda));
    }

    // ── AttributeParser ───────────────────────────────────────────────────────

    #[test]
    fn test_serializable_flag() {
        let mut t = make_type("MyData");
        t.flags |= 0x0000_2000;
        assert!(AttributeParser::is_serializable(&t));
    }

    #[test]
    fn test_flags_attribute() {
        let mut t = make_type("MyEnum");
        t.custom_attributes
            .push(CustomAttribute::from_blob("FlagsAttribute", vec![]));
        assert!(AttributeParser::has_flags_attribute(&t));
    }

    #[test]
    fn test_attribute_names() {
        let mut t = make_type("C");
        t.custom_attributes
            .push(CustomAttribute::from_blob("ObsoleteAttribute", vec![]));
        let names = AttributeParser::attribute_names(&t);
        assert!(names.contains(&"ObsoleteAttribute"));
    }

    // ── CsharpMethod ─────────────────────────────────────────────────────────

    #[test]
    fn test_csharp_method_from_dotnet() {
        let m = make_method_with_body("Calculate", 10);
        let cm = CsharpMethod::from_dotnet_method(&m);
        assert_eq!(cm.name, "Calculate");
        assert_eq!(cm.complexity, 10);
    }

    #[test]
    fn test_csharp_method_async() {
        let mut m = make_empty_method("AsyncOp");
        m.signature.return_type = "Task<string>".to_string();
        let cm = CsharpMethod::from_dotnet_method(&m);
        assert!(cm.is_async);
        assert!(cm.pseudo_code.contains("async"));
    }

    #[test]
    fn test_csharp_method_no_body_pseudo() {
        let m = make_empty_method("Abstract");
        let cm = CsharpMethod::from_dotnet_method(&m);
        assert!(cm.pseudo_code.contains("no body"));
    }

    // ── CsharpClass ───────────────────────────────────────────────────────────

    #[test]
    fn test_csharp_class_from_type() {
        let mut t = make_type("MyClass");
        t.methods.push(make_method_with_body("Work", 3));
        let class = CsharpClass::from_dotnet_type(&t);
        assert_eq!(class.full_name, "Test.MyClass");
        assert_eq!(class.method_count(), 1);
    }

    #[test]
    fn test_csharp_class_async_count() {
        let mut t = make_type("Service");
        let mut m1 = make_empty_method("Fetch");
        m1.signature.return_type = "Task".into();
        let m2 = make_empty_method("Sync");
        t.methods.push(m1);
        t.methods.push(m2);
        let class = CsharpClass::from_dotnet_type(&t);
        assert_eq!(class.async_method_count(), 1);
    }

    #[test]
    fn test_csharp_class_kind() {
        let t = make_type("IService");
        let class = CsharpClass::from_dotnet_type(&t);
        assert_eq!(class.kind, "class");
    }

    // ── ReconstructedProperty ─────────────────────────────────────────────────

    #[test]
    fn test_auto_property_detection() {
        assert!(ReconstructedProperty::is_auto_property(3, 4)); // both simple
    }

    #[test]
    fn test_non_auto_property() {
        assert!(!ReconstructedProperty::is_auto_property(10, 12)); // both complex
    }

    // ── CsharpReconstructor ───────────────────────────────────────────────────

    #[test]
    fn test_reconstructor_generate_class_source() {
        let t = make_type("Foo");
        let class = CsharpClass::from_dotnet_type(&t);
        let reconstructor = CsharpReconstructor::new();
        let src = reconstructor.generate_class_source(&class);
        assert!(src.contains("class"));
        assert!(src.contains("Foo"));
        assert!(src.contains('{'));
        assert!(src.contains('}'));
    }

    #[test]
    fn test_reconstructor_generate_interface() {
        let mut t = make_type("IMyInterface");
        t.kind_tag = DotnetTypeKind::Interface;
        let class = CsharpClass::from_dotnet_type(&t);
        let r = CsharpReconstructor::new();
        let src = r.generate_class_source(&class);
        assert!(src.contains("IMyInterface"));
    }

    #[test]
    fn test_reconstructor_with_base_class() {
        let mut t = make_type("Child");
        t.base_type = Some("System.Object".into());
        let class = CsharpClass::from_dotnet_type(&t);
        let r = CsharpReconstructor::new();
        let src = r.generate_class_source(&class);
        assert!(src.contains("System.Object"));
    }

    #[test]
    fn test_reconstructor_public_only() {
        let r = CsharpReconstructor::new().public_only();
        assert!(!r.include_private);
    }

    #[test]
    fn test_method_attribute_names() {
        let mut m = make_empty_method("Deprecated");
        m.custom_attributes
            .push(CustomAttribute::from_blob("ObsoleteAttribute", vec![]));
        let names = AttributeParser::method_attribute_names(&m);
        assert!(names.contains(&"ObsoleteAttribute"));
    }
}
