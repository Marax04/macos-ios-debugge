//! `dex_to_java` — DEX class → Java source conversion pipeline.
//!
//! This is the top-level entry point that ties together:
//!
//! 1. `dalvik_lift` — Dalvik bytecode → SSA
//! 2. `java_ast`   — Java AST types
//! 3. `java_emitter` — AST → source text
//! 4. `lambda_recovery` — SAM / lambda pattern recovery

use super::JadxError;
use super::dalvik_lift::{DalvikInsn, SsaBuilder, lift_to_java};
use super::java_ast::{
    AccessLevel, AstClass, AstField, AstMethod, ClassKind, CompilationUnit, FieldFlags, JavaType,
    MethodFlags, Modifiers, ScopeFlags, Statement,
};

// ─────────────────────────────────────────────────────────────────────────────
// DexClass — raw input
// ─────────────────────────────────────────────────────────────────────────────

/// A raw DEX class as extracted from a `.dex` or `.apk` file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DexClass {
    /// Dalvik type descriptor, e.g. `"Lcom/example/Foo;"`.
    pub descriptor: String,
    /// Access flags (DEX format).
    pub access_flags: u32,
    /// Descriptor of the superclass.
    pub superclass: Option<String>,
    /// Implemented interface descriptors.
    pub interfaces: Vec<String>,
    /// Source file annotation.
    pub source_file: Option<String>,
    /// Direct (static/private/constructor) methods.
    pub direct_methods: Vec<DexMethod>,
    /// Virtual methods.
    pub virtual_methods: Vec<DexMethod>,
    /// Instance fields.
    pub instance_fields: Vec<DexField>,
    /// Static fields.
    pub static_fields: Vec<DexField>,
}

impl DexClass {
    /// Returns the simple (unqualified) class name.
    #[must_use]
    pub fn simple_name(&self) -> &str {
        // "Lcom/example/Foo;" → "Foo"
        // Strip the marker exactly once: `trim_start_matches` repeats, so `LL;`
        // (a class named `L`, routine after R8 renaming) would come out empty.
        let inner = self.descriptor.strip_prefix('L').unwrap_or(&self.descriptor);
        let inner = inner.strip_suffix(';').unwrap_or(inner);
        inner.rsplit('/').next().unwrap_or(inner)
    }

    /// Returns the Java package name.
    #[must_use]
    pub fn package(&self) -> String {
        // Strip the descriptor marker exactly once — see `simple_name`.
        let inner = self.descriptor.strip_prefix('L').unwrap_or(&self.descriptor);
        let inner = inner.strip_suffix(';').unwrap_or(inner);
        let parts: Vec<&str> = inner.split('/').collect();
        if parts.len() > 1 {
            parts[..parts.len() - 1].join(".")
        } else {
            String::new()
        }
    }

    /// Returns all methods (direct + virtual).
    pub fn all_methods(&self) -> impl Iterator<Item = &DexMethod> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
    }

    /// Returns `true` if the class is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Returns `true` if the class is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns `true` if the class is an enum.
    #[must_use]
    pub const fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }
}

/// A raw DEX method.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DexMethod {
    pub name: String,
    pub proto: String,
    pub access_flags: u32,
    pub code: Vec<DalvikInsn>,
}

impl DexMethod {
    /// Returns `true` if the method is static.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns `true` if the method is native.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        self.access_flags & 0x0100 != 0
    }

    /// Returns `true` if the method is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Parse the return type from a Dalvik method prototype string.
    #[must_use]
    pub fn return_type(&self) -> JavaType {
        // Proto: "(params)ReturnType"
        self.proto.rfind(')').map_or(JavaType::Unknown, |close| {
            JavaType::from_descriptor(&self.proto[close + 1..])
        })
    }

    /// Parse the parameter types from a proto string.
    #[must_use]
    pub fn param_types(&self) -> Vec<JavaType> {
        let paren_open = self.proto.find('(').unwrap_or(0);
        let paren_close = self.proto.find(')').unwrap_or(self.proto.len());
        let params_str = &self.proto[paren_open + 1..paren_close];
        parse_params(params_str)
    }
}

/// A raw DEX field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DexField {
    pub name: String,
    pub type_desc: String,
    pub access_flags: u32,
}

impl DexField {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.access_flags & 0x0002 != 0
    }
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversion
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a `DexClass` to a `CompilationUnit`.
///
/// # Errors
///
/// Returns a `JadxError` if the DEX class cannot be lowered into a Java
/// compilation unit (e.g. malformed type descriptors).
pub fn dex_class_to_java(dex: &DexClass) -> Result<CompilationUnit, JadxError> {
    let package = dex.package();
    let simple = dex.simple_name().to_owned();

    let mut cu = CompilationUnit::new(package.clone());

    // Add common imports.
    add_auto_imports(dex, &mut cu);

    let kind = if dex.is_interface() {
        ClassKind::Interface
    } else if dex.is_enum() {
        ClassKind::Enum
    } else {
        ClassKind::Class
    };

    let mods = access_flags_to_modifiers(dex.access_flags, false);
    let mut cls = AstClass::new(simple.clone(), package);
    cls.kind = kind;
    cls.modifiers = mods;

    if let Some(sup) = &dex.superclass
        && sup != "Ljava/lang/Object;"
    {
        cls.super_class = Some(descriptor_to_java_name(sup));
    }

    for iface in &dex.interfaces {
        cls.interfaces.push(descriptor_to_java_name(iface));
    }

    // Convert fields.
    for field in dex.instance_fields.iter().chain(dex.static_fields.iter()) {
        let ast_field = convert_field(field);
        cls.fields.push(ast_field);
    }

    // Convert methods.  Failures are folded into stub bodies so callers always
    // see a method entry — keeps interface diffs against `jadx`-style output
    // small when individual instruction lifts go wrong.
    for method in dex.all_methods() {
        let converted = convert_method(method, &simple);
        if converted.body.as_ref().is_some_and(Vec::is_empty)
            && !method.is_native()
            && !method.is_abstract()
            && !method.code.is_empty()
        {
            cls.methods.push(stub_method(method, &simple));
        } else {
            cls.methods.push(converted);
        }
    }

    // Lambda recovery pass.
    super::lambda_recovery::recover_lambdas(&mut cls);

    cu.add_class(cls);
    Ok(cu)
}

// ─────────────────────────────────────────────────────────────────────────────
// Field conversion
// ─────────────────────────────────────────────────────────────────────────────

fn convert_field(field: &DexField) -> AstField {
    let ty = JavaType::from_descriptor(&field.type_desc);
    let access = if field.is_public() {
        AccessLevel::Public
    } else if field.is_private() {
        AccessLevel::Private
    } else {
        AccessLevel::Package
    };
    let mods = Modifiers {
        access,
        scope: ScopeFlags {
            is_static: field.is_static(),
            is_final: field.is_final(),
            ..ScopeFlags::default()
        },
        ..Modifiers::default()
    };
    AstField {
        modifiers: mods,
        ty,
        name: field.name.clone(),
        init: None,
        annotations: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Method conversion
// ─────────────────────────────────────────────────────────────────────────────

fn convert_method(method: &DexMethod, class_simple: &str) -> AstMethod {
    let mods = access_flags_to_modifiers(method.access_flags, false);
    let return_type = method.return_type();
    let param_types = method.param_types();

    // Build parameter names.
    let params: Vec<(String, JavaType)> = param_types
        .into_iter()
        .enumerate()
        .map(|(i, ty)| (format!("p{i}"), ty))
        .collect();

    if method.is_native() || method.is_abstract() || method.code.is_empty() {
        return AstMethod {
            modifiers: mods,
            name: if method.name == "<init>" {
                class_simple.to_owned()
            } else {
                method.name.clone()
            },
            params,
            return_type,
            body: if method.is_native() || method.is_abstract() {
                None
            } else {
                Some(vec![])
            },
            throws: vec![],
            annotations: vec![],
            locals: vec![],
        };
    }

    // Lift via SSA.
    let mut builder = SsaBuilder::new();
    let ssa = builder.build(&method.name, class_simple, &method.code);
    let mut ast_method = lift_to_java(&ssa, mods, params, return_type);

    // Rename <init> to the class name.
    if ast_method.name == "<init>" {
        class_simple.clone_into(&mut ast_method.name);
    }

    ast_method
}

fn stub_method(method: &DexMethod, class_simple: &str) -> AstMethod {
    let mods = access_flags_to_modifiers(method.access_flags, false);
    let return_type = method.return_type();
    AstMethod {
        modifiers: mods,
        name: if method.name == "<init>" {
            class_simple.to_owned()
        } else {
            method.name.clone()
        },
        params: vec![],
        return_type,
        body: Some(vec![Statement::Unknown(
            "/* decompile failed */".to_owned(),
        )]),
        throws: vec![],
        annotations: vec![],
        locals: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Import auto-generation
// ─────────────────────────────────────────────────────────────────────────────

fn add_auto_imports(dex: &DexClass, cu: &mut CompilationUnit) {
    // Collect all type references from methods.
    let mut seen = std::collections::HashSet::new();
    for method in dex.all_methods() {
        for ty in method.param_types() {
            if let JavaType::Reference(s) = ty
                && s.contains('.')
                && !s.starts_with("java.lang.")
            {
                seen.insert(s);
            }
        }
    }
    // Also add superclass and interfaces.
    if let Some(sup) = &dex.superclass {
        let name = descriptor_to_java_name(sup);
        if name.contains('.') && !name.starts_with("java.lang.") {
            seen.insert(name);
        }
    }
    for iface in &dex.interfaces {
        let name = descriptor_to_java_name(iface);
        if name.contains('.') && !name.starts_with("java.lang.") {
            seen.insert(name);
        }
    }
    for imp in seen {
        cu.add_import(imp);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn descriptor_to_java_name(desc: &str) -> String {
    // `trim_start_matches` strips the prefix REPEATEDLY, but a descriptor has
    // exactly one 'L' marker and one ';' terminator. On `LList;` it would eat
    // both leading 'L's and yield "ist", and on `LL;` — a class literally named
    // `L`, which R8/ProGuard output makes common — it yields the empty string.
    let inner = desc.strip_prefix('L').unwrap_or(desc);
    let inner = inner.strip_suffix(';').unwrap_or(inner);
    inner.replace('/', ".")
}

const fn access_flags_to_modifiers(flags: u32, is_method: bool) -> Modifiers {
    let access = if flags & 0x0001 != 0 {
        AccessLevel::Public
    } else if flags & 0x0002 != 0 {
        AccessLevel::Private
    } else if flags & 0x0004 != 0 {
        AccessLevel::Protected
    } else {
        AccessLevel::Package
    };
    Modifiers {
        access,
        scope: ScopeFlags {
            is_static: flags & 0x0008 != 0,
            is_final: flags & 0x0010 != 0,
            is_abstract: flags & 0x0400 != 0,
        },
        method_flags: MethodFlags {
            is_synchronized: flags & 0x0020 != 0 && is_method,
            is_native: flags & 0x0100 != 0,
        },
        field_flags: FieldFlags {
            is_transient: flags & 0x0080 != 0 && !is_method,
            is_volatile: flags & 0x0040 != 0 && !is_method,
        },
    }
}

fn parse_params(params_str: &str) -> Vec<JavaType> {
    let mut types = Vec::with_capacity(params_str.len() / 4 + 1);
    let bytes = params_str.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                let start = i;
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                let desc = &params_str[start..=i];
                types.push(JavaType::from_descriptor(desc));
            }
            b'[' => {
                let start = i;
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                }
                let desc = &params_str[start..=i];
                types.push(JavaType::from_descriptor(desc));
            }
            _ => {
                let desc = &params_str[i..=i];
                types.push(JavaType::from_descriptor(desc));
            }
        }
        i += 1;
    }
    types
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock DEX class builder (for tests)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a minimal mock `DexClass` for testing the conversion pipeline.
#[must_use]
/// NOTE: a hand-written fixture for this crate's own tests. It is not
/// derived from any input and is not reachable from the MCP tool surface;
/// never report it to a user as the analysis of a real file.
pub fn mock_dex_class(descriptor: &str) -> DexClass {
    DexClass {
        descriptor: descriptor.to_owned(),
        access_flags: 0x0001, // public
        superclass: Some("Ljava/lang/Object;".to_owned()),
        interfaces: vec![],
        source_file: Some("Foo.java".to_owned()),
        direct_methods: vec![DexMethod {
            name: "<init>".to_owned(),
            proto: "()V".to_owned(),
            access_flags: 0x10001, // public constructor
            code: vec![
                DalvikInsn {
                    offset: 0,
                    mnemonic: "invoke-direct".to_owned(),
                    dest: None,
                    srcs: vec![0],
                    lit: None,
                    string: None,
                    type_ref: None,
                    method_ref: Some("Ljava/lang/Object;-><init>()V".to_owned()),
                    field_ref: None,
                    branch_target: None,
                },
                DalvikInsn {
                    offset: 6,
                    mnemonic: "return-void".to_owned(),
                    dest: None,
                    srcs: vec![],
                    lit: None,
                    string: None,
                    type_ref: None,
                    method_ref: None,
                    field_ref: None,
                    branch_target: None,
                },
            ],
        }],
        virtual_methods: vec![],
        instance_fields: vec![DexField {
            name: "value".to_owned(),
            type_desc: "I".to_owned(),
            access_flags: 0x0002,
        }],
        static_fields: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::java_ast::Primitive;

    #[test]
    fn test_dex_class_simple_name() {
        let dex = mock_dex_class("Lcom/example/Foo;");
        assert_eq!(dex.simple_name(), "Foo");
    }

    #[test]
    fn test_dex_class_package() {
        let dex = mock_dex_class("Lcom/example/Foo;");
        assert_eq!(dex.package(), "com.example");
    }

    #[test]
    fn test_dex_class_root_package() {
        let dex = mock_dex_class("LFoo;");
        assert_eq!(dex.package(), "");
        assert_eq!(dex.simple_name(), "Foo");
    }

    #[test]
    fn test_dex_method_return_type() {
        let method = DexMethod {
            name: "bar".to_owned(),
            proto: "(I)Ljava/lang/String;".to_owned(),
            access_flags: 0x0001,
            code: vec![],
        };
        let ty = method.return_type();
        assert_eq!(ty, JavaType::Reference("java.lang.String".to_owned()));
    }

    #[test]
    fn test_dex_method_param_types() {
        let method = DexMethod {
            name: "foo".to_owned(),
            proto: "(ILjava/lang/String;Z)V".to_owned(),
            access_flags: 0x0001,
            code: vec![],
        };
        let params = method.param_types();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], JavaType::Primitive(Primitive::Int));
        assert_eq!(
            params[1],
            JavaType::Reference("java.lang.String".to_owned())
        );
        assert_eq!(params[2], JavaType::Primitive(Primitive::Boolean));
    }

    #[test]
    fn test_dex_method_is_static() {
        let m = DexMethod {
            name: "f".to_owned(),
            proto: "()V".to_owned(),
            access_flags: 0x0009,
            code: vec![],
        };
        assert!(m.is_static());
    }

    #[test]
    fn test_dex_method_is_native() {
        let m = DexMethod {
            name: "f".to_owned(),
            proto: "()V".to_owned(),
            access_flags: 0x0101,
            code: vec![],
        };
        assert!(m.is_native());
    }

    #[test]
    fn test_convert_dex_class_to_java() {
        let dex = mock_dex_class("Lcom/example/Foo;");
        let cu = dex_class_to_java(&dex).expect("convert");
        assert_eq!(cu.package, "com.example");
        let cls = cu.primary_class().expect("primary");
        assert_eq!(cls.simple_name(), "Foo");
    }

    #[test]
    fn test_convert_has_methods() {
        let dex = mock_dex_class("Lcom/example/Foo;");
        let cu = dex_class_to_java(&dex).expect("convert");
        let cls = cu.primary_class().expect("primary");
        assert!(!cls.methods.is_empty());
    }

    #[test]
    fn test_convert_has_fields() {
        let dex = mock_dex_class("Lcom/example/Foo;");
        let cu = dex_class_to_java(&dex).expect("convert");
        let cls = cu.primary_class().expect("primary");
        assert!(!cls.fields.is_empty());
    }

    #[test]
    fn test_access_flags_public() {
        let m = access_flags_to_modifiers(0x0001, false);
        assert!(m.is_public());
        assert!(!m.is_private());
    }

    #[test]
    fn test_access_flags_static_final() {
        let m = access_flags_to_modifiers(0x0018, false);
        assert!(m.is_static());
        assert!(m.is_final());
    }

    #[test]
    fn test_descriptor_to_java_name() {
        assert_eq!(
            descriptor_to_java_name("Ljava/lang/String;"),
            "java.lang.String"
        );
        assert_eq!(
            descriptor_to_java_name("Ljava/util/List;"),
            "java.util.List"
        );
        // The 'L' marker must be stripped exactly once: a class whose own name
        // starts with 'L' would otherwise lose its first letter, and a class
        // named `L` (routine after R8/ProGuard renaming) would vanish entirely.
        assert_eq!(descriptor_to_java_name("LList;"), "List");
        assert_eq!(descriptor_to_java_name("LL;"), "L");
        assert_eq!(descriptor_to_java_name("Lcom/x/LinkedList;"), "com.x.LinkedList");
    }

    #[test]
    fn test_parse_params_empty() {
        let types = parse_params("");
        assert!(types.is_empty());
    }

    #[test]
    fn test_parse_params_single_int() {
        let types = parse_params("I");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], JavaType::Primitive(Primitive::Int));
    }

    #[test]
    fn test_is_interface_flag() {
        let mut dex = mock_dex_class("Lfoo;");
        dex.access_flags = 0x0201; // public interface
        assert!(dex.is_interface());
    }

    #[test]
    fn test_is_enum_flag() {
        let mut dex = mock_dex_class("Lfoo;");
        dex.access_flags = 0x4001; // public enum
        assert!(dex.is_enum());
    }
}
