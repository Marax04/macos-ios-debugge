//! `java_ast` — Java abstract syntax tree (AST) nodes.
//!
//! This module defines the AST used by the JADX lifting pipeline.  The AST is
//! intentionally simplified: it covers the Java constructs that appear after
//! Dalvik→SSA→Java lifting, not all of Java.
//!
//! The AST is the intermediate form between `dalvik_lift` (Dalvik→SSA) and
//! `java_emitter` (AST→source text).

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// A Java type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JavaType {
    /// Primitive: `void`, `int`, `long`, `float`, `double`, `boolean`, `byte`, `char`, `short`.
    Primitive(Primitive),
    /// Reference type: fully-qualified class name, e.g. `"java.lang.String"`.
    Reference(String),
    /// Array of another type.
    Array(Box<Self>),
    /// Generic type with type arguments, e.g. `List<String>`.
    Generic(String, Vec<Self>),
    /// Unknown / unresolved type (used during lifting).
    Unknown,
}

/// Java primitive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Primitive {
    Void,
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Void => "void",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Char => "char",
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
        };
        f.write_str(s)
    }
}

impl fmt::Display for JavaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primitive(p) => write!(f, "{p}"),
            Self::Reference(s) => f.write_str(s),
            Self::Array(inner) => write!(f, "{inner}[]"),
            Self::Generic(name, args) => {
                write!(f, "{name}<")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{a}")?;
                }
                f.write_str(">")
            }
            Self::Unknown => f.write_str("/*?*/"),
        }
    }
}

impl JavaType {
    /// Parse a Dalvik type descriptor into a `JavaType`.
    #[must_use]
    pub fn from_descriptor(desc: &str) -> Self {
        match desc {
            "V" => Self::Primitive(Primitive::Void),
            "Z" => Self::Primitive(Primitive::Boolean),
            "B" => Self::Primitive(Primitive::Byte),
            "S" => Self::Primitive(Primitive::Short),
            "C" => Self::Primitive(Primitive::Char),
            "I" => Self::Primitive(Primitive::Int),
            "J" => Self::Primitive(Primitive::Long),
            "F" => Self::Primitive(Primitive::Float),
            "D" => Self::Primitive(Primitive::Double),
            s if s.starts_with('[') => Self::Array(Box::new(Self::from_descriptor(&s[1..]))),
            s if s.starts_with('L') && s.ends_with(';') => {
                let name = &s[1..s.len() - 1];
                Self::Reference(name.replace('/', "."))
            }
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if the type is a reference or array type.
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        matches!(
            self,
            Self::Reference(_) | Self::Array(_) | Self::Generic(_, _)
        )
    }

    /// Returns `true` for `void`.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Primitive(Primitive::Void))
    }

    /// Returns the simple class name (last component) for reference types.
    #[must_use]
    pub fn simple_name(&self) -> Option<&str> {
        if let Self::Reference(s) = self {
            s.rsplit('.').next()
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Modifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Java access level (mutually exclusive access modifier).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AccessLevel {
    /// Package-private (the default when no access modifier is present).
    #[default]
    Package,
    /// `public` access.
    Public,
    /// `private` access.
    Private,
    /// `protected` access.
    Protected,
}

/// Scope-related flags (static / final / abstract).
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct ScopeFlags {
    pub is_static: bool,
    pub is_final: bool,
    pub is_abstract: bool,
}

/// Method-only flags (synchronized / native).
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct MethodFlags {
    pub is_synchronized: bool,
    pub is_native: bool,
}

/// Field-only flags (transient / volatile).
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct FieldFlags {
    pub is_transient: bool,
    pub is_volatile: bool,
}

/// Java access and other modifiers.
///
/// The flag fields are grouped into sub-structs so that no single struct
/// declares more than three boolean fields.  Convenience accessor methods
/// expose each flag by its Java name (e.g. [`Modifiers::is_public`]) so
/// callers may treat the modifier set as a flat property bag.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Modifiers {
    pub access: AccessLevel,
    pub scope: ScopeFlags,
    pub method_flags: MethodFlags,
    pub field_flags: FieldFlags,
}

impl Modifiers {
    /// Construct a `Modifiers` set with only the `public` access level set.
    #[must_use]
    pub fn public() -> Self {
        Self {
            access: AccessLevel::Public,
            ..Self::default()
        }
    }

    /// Construct a `Modifiers` set with only the `private` access level set.
    #[must_use]
    pub fn private() -> Self {
        Self {
            access: AccessLevel::Private,
            ..Self::default()
        }
    }

    /// Returns true if the `public` access level is set.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self.access, AccessLevel::Public)
    }

    /// Returns true if the `private` access level is set.
    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(self.access, AccessLevel::Private)
    }

    /// Returns true if the `protected` access level is set.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        matches!(self.access, AccessLevel::Protected)
    }

    /// Returns true if the `static` flag is set.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.scope.is_static
    }

    /// Returns true if the `final` flag is set.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.scope.is_final
    }

    /// Returns true if the `abstract` flag is set.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.scope.is_abstract
    }

    /// Returns true if the `synchronized` flag is set.
    #[must_use]
    pub const fn is_synchronized(&self) -> bool {
        self.method_flags.is_synchronized
    }

    /// Returns true if the `native` flag is set.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        self.method_flags.is_native
    }

    /// Returns true if the `transient` flag is set.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        self.field_flags.is_transient
    }

    /// Returns true if the `volatile` flag is set.
    #[must_use]
    pub const fn is_volatile(&self) -> bool {
        self.field_flags.is_volatile
    }
}

impl std::fmt::Display for Modifiers {
    /// Build a modifier string like `"public static final"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.is_public() {
            parts.push("public");
        }
        if self.is_private() {
            parts.push("private");
        }
        if self.is_protected() {
            parts.push("protected");
        }
        if self.is_static() {
            parts.push("static");
        }
        if self.is_final() {
            parts.push("final");
        }
        if self.is_abstract() {
            parts.push("abstract");
        }
        if self.is_synchronized() {
            parts.push("synchronized");
        }
        if self.is_native() {
            parts.push("native");
        }
        if self.is_transient() {
            parts.push("transient");
        }
        if self.is_volatile() {
            parts.push("volatile");
        }
        f.write_str(&parts.join(" "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expressions
// ─────────────────────────────────────────────────────────────────────────────

/// A Java expression node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Expr {
    // Literals
    IntLit(i64),
    LongLit(i64),
    FloatLit(f64),
    DoubleLit(f64),
    BoolLit(bool),
    StringLit(String),
    NullLit,

    // Variables / names
    Var(String),
    This,
    Super,

    // Field access
    FieldGet {
        object: Box<Self>,
        field: String,
        field_type: JavaType,
    },
    StaticFieldGet {
        class: String,
        field: String,
        field_type: JavaType,
    },

    // Method calls
    InvokeVirtual {
        object: Box<Self>,
        method: String,
        args: Vec<Self>,
        ret: JavaType,
    },
    InvokeStatic {
        class: String,
        method: String,
        args: Vec<Self>,
        ret: JavaType,
    },
    InvokeDirect {
        object: Box<Self>,
        method: String,
        args: Vec<Self>,
        ret: JavaType,
    },
    InvokeInterface {
        object: Box<Self>,
        method: String,
        args: Vec<Self>,
        ret: JavaType,
    },
    InvokeSuper {
        method: String,
        args: Vec<Self>,
        ret: JavaType,
    },

    // Array operations
    ArrayGet {
        array: Box<Self>,
        index: Box<Self>,
        elem_type: JavaType,
    },
    ArrayLen(Box<Self>),
    NewArray {
        elem_type: JavaType,
        size: Box<Self>,
    },

    // Object creation
    NewObject {
        class: String,
        args: Vec<Self>,
    },

    // Casts and type checks
    Cast {
        expr: Box<Self>,
        target: JavaType,
    },
    InstanceOf {
        expr: Box<Self>,
        class: String,
    },

    // Operators
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    UnaryOp {
        op: UnaryOp,
        expr: Box<Self>,
    },

    // Ternary
    Ternary {
        cond: Box<Self>,
        then: Box<Self>,
        else_: Box<Self>,
    },

    // Lambda
    Lambda(Box<LambdaExpr>),

    // Unknown / placeholder (used for unlifted regions)
    Unknown(String),
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    UShr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LogAnd,
    LogOr,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::UShr => ">>>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::LogAnd => "&&",
            Self::LogOr => "||",
        })
    }
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Neg => "-",
            Self::Not => "!",
            Self::BitNot => "~",
        })
    }
}

/// Lambda expression (simplified — used for SAM conversions).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LambdaExpr {
    /// Parameter names.
    pub params: Vec<(String, JavaType)>,
    /// Body — either a single expression or a block.
    pub body: LambdaBody,
    /// Functional interface type this lambda satisfies.
    pub interface_type: Option<String>,
    /// If this lambda was detected as a method reference (`ClassName::method`),
    /// the reference syntax is stored here for the emitter to use.
    pub method_ref_syntax: Option<String>,
}

/// Body of a lambda expression.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LambdaBody {
    Expr(Expr),
    Block(Vec<Statement>),
}

// ─────────────────────────────────────────────────────────────────────────────
// Statements
// ─────────────────────────────────────────────────────────────────────────────

/// A Java statement node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Statement {
    // Declarations
    LocalDecl {
        ty: JavaType,
        name: String,
        init: Option<Expr>,
    },

    // Assignments
    Assign {
        target: Expr,
        value: Expr,
    },

    // Expression statement
    Expr(Expr),

    // Control flow
    Return(Option<Expr>),
    Throw(Expr),
    Break(Option<String>),
    Continue(Option<String>),

    // Blocks
    Block(Vec<Self>),
    Labeled(String, Box<Self>),

    // If / switch
    If {
        cond: Expr,
        then: Box<Self>,
        else_: Option<Box<Self>>,
    },
    Switch {
        expr: Expr,
        cases: Vec<SwitchCase>,
    },

    // Loops
    While {
        cond: Expr,
        body: Box<Self>,
    },
    DoWhile {
        body: Box<Self>,
        cond: Expr,
    },
    For {
        init: Option<Box<Self>>,
        cond: Option<Expr>,
        update: Option<Expr>,
        body: Box<Self>,
    },
    ForEach {
        elem_type: JavaType,
        var: String,
        iter: Expr,
        body: Box<Self>,
    },

    // Exception handling
    TryCatch {
        body: Box<Self>,
        catches: Vec<CatchClause>,
        finally: Option<Box<Self>>,
    },

    // Synchronization
    Synchronized {
        lock: Expr,
        body: Box<Self>,
    },

    // Placeholder
    Unknown(String),

    // Empty statement
    Empty,
}

/// One case of a `switch` statement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwitchCase {
    /// `None` = `default:`.
    pub label: Option<Expr>,
    pub body: Vec<Statement>,
}

/// One `catch` clause.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CatchClause {
    pub exception_types: Vec<String>,
    pub var: String,
    pub body: Vec<Statement>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Class members
// ─────────────────────────────────────────────────────────────────────────────

/// A Java field declaration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AstField {
    pub modifiers: Modifiers,
    pub ty: JavaType,
    pub name: String,
    pub init: Option<Expr>,
    pub annotations: Vec<String>,
}

/// A Java method declaration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AstMethod {
    pub modifiers: Modifiers,
    pub name: String,
    pub params: Vec<(String, JavaType)>,
    pub return_type: JavaType,
    pub body: Option<Vec<Statement>>,
    pub throws: Vec<String>,
    pub annotations: Vec<String>,
    /// Local variables declared in this method.
    pub locals: Vec<(String, JavaType)>,
}

impl AstMethod {
    /// Returns `true` for constructor methods.
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == "<init>"
    }

    /// Returns the number of statements in the method body.
    #[must_use]
    pub fn body_size(&self) -> usize {
        self.body.as_ref().map_or(0, std::vec::Vec::len)
    }

    /// Returns `true` if the method body is empty.
    #[must_use]
    pub fn is_empty_body(&self) -> bool {
        self.body.as_ref().is_none_or(std::vec::Vec::is_empty)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Class declaration
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of class declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClassKind {
    Class,
    Interface,
    Enum,
    Annotation,
    Record,
}

impl fmt::Display for ClassKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Enum => "enum",
            Self::Annotation => "@interface",
            Self::Record => "record",
        })
    }
}

/// A top-level or inner class declaration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AstClass {
    /// Fully-qualified class name (`"com.example.Foo"`).
    pub name: String,
    pub kind: ClassKind,
    pub modifiers: Modifiers,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<AstField>,
    pub methods: Vec<AstMethod>,
    pub inner_classes: Vec<Self>,
    pub annotations: Vec<String>,
    pub package: String,
}

impl AstClass {
    /// Create an empty class.
    #[must_use]
    pub fn new(name: impl Into<String>, package: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: ClassKind::Class,
            modifiers: Modifiers::public(),
            super_class: None,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            inner_classes: Vec::new(),
            annotations: Vec::new(),
            package: package.into(),
        }
    }

    /// Simple (unqualified) class name.
    #[must_use]
    pub fn simple_name(&self) -> &str {
        self.name.rsplit('.').next().unwrap_or(&self.name)
    }

    /// Find a method by name.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<&AstMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// All native methods.
    #[must_use]
    pub fn native_methods(&self) -> Vec<&AstMethod> {
        self.methods
            .iter()
            .filter(|m| m.modifiers.is_native())
            .collect()
    }

    /// All static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&AstMethod> {
        self.methods
            .iter()
            .filter(|m| m.modifiers.is_static())
            .collect()
    }

    /// All constructors.
    #[must_use]
    pub fn constructors(&self) -> Vec<&AstMethod> {
        self.methods.iter().filter(|m| m.is_constructor()).collect()
    }

    /// Returns `true` if the class extends or implements any security-relevant
    /// framework type.
    #[must_use]
    pub fn is_security_relevant(&self) -> bool {
        const SECURITY_TYPES: &[&str] = &[
            "javax.net.ssl.X509TrustManager",
            "javax.net.ssl.HostnameVerifier",
            "java.security.cert.X509Certificate",
            "android.security.keystore",
        ];
        for ty in &self.interfaces {
            if SECURITY_TYPES.iter().any(|s| ty.contains(s)) {
                return true;
            }
        }
        if let Some(sup) = &self.super_class
            && SECURITY_TYPES.iter().any(|s| sup.contains(s))
        {
            return true;
        }
        false
    }

    /// Build a mock `AstClass` for testing.
    #[must_use]
    /// NOTE: a hand-written fixture for this crate's own tests. It is not
    /// derived from any input and is not reachable from the MCP tool surface;
    /// never report it to a user as the analysis of a real file.
    pub fn mock(name: &str, package: &str) -> Self {
        let mut cls = Self::new(name, package);
        cls.super_class = Some("java.lang.Object".to_owned());

        let init_method = AstMethod {
            modifiers: Modifiers::public(),
            name: "<init>".to_owned(),
            params: vec![],
            return_type: JavaType::Primitive(Primitive::Void),
            body: Some(vec![Statement::Return(None)]),
            throws: vec![],
            annotations: vec![],
            locals: vec![],
        };

        let static_method = AstMethod {
            modifiers: Modifiers {
                access: AccessLevel::Public,
                scope: ScopeFlags {
                    is_static: true,
                    ..ScopeFlags::default()
                },
                ..Modifiers::default()
            },
            name: "getInstance".to_owned(),
            params: vec![],
            return_type: JavaType::Reference(format!("{package}.{name}")),
            body: Some(vec![Statement::Return(Some(Expr::NullLit))]),
            throws: vec![],
            annotations: vec![],
            locals: vec![],
        };

        cls.methods = vec![init_method, static_method];
        cls.fields = vec![AstField {
            modifiers: Modifiers {
                access: AccessLevel::Private,
                scope: ScopeFlags {
                    is_static: true,
                    ..ScopeFlags::default()
                },
                ..Modifiers::default()
            },
            ty: JavaType::Reference(format!("{package}.{name}")),
            name: "instance".to_owned(),
            init: Some(Expr::NullLit),
            annotations: vec![],
        }];
        cls
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compilation unit
// ─────────────────────────────────────────────────────────────────────────────

/// A complete compilation unit (one `.java` file).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompilationUnit {
    pub package: String,
    pub imports: Vec<String>,
    pub classes: Vec<AstClass>,
}

impl CompilationUnit {
    /// Create a new empty compilation unit.
    #[must_use]
    pub fn new(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            imports: Vec::new(),
            classes: Vec::new(),
        }
    }

    /// Add a class.
    pub fn add_class(&mut self, class: AstClass) {
        self.classes.push(class);
    }

    /// Add an import.
    pub fn add_import(&mut self, import: impl Into<String>) {
        self.imports.push(import.into());
    }

    /// Returns the primary class (first top-level class).
    #[must_use]
    pub fn primary_class(&self) -> Option<&AstClass> {
        self.classes.first()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_display() {
        assert_eq!(Primitive::Int.to_string(), "int");
        assert_eq!(Primitive::Void.to_string(), "void");
        assert_eq!(Primitive::Long.to_string(), "long");
    }

    #[test]
    fn test_java_type_display_primitive() {
        assert_eq!(JavaType::Primitive(Primitive::Int).to_string(), "int");
    }

    #[test]
    fn test_java_type_display_reference() {
        assert_eq!(
            JavaType::Reference("java.lang.String".to_owned()).to_string(),
            "java.lang.String"
        );
    }

    #[test]
    fn test_java_type_display_array() {
        let ty = JavaType::Array(Box::new(JavaType::Primitive(Primitive::Int)));
        assert_eq!(ty.to_string(), "int[]");
    }

    #[test]
    fn test_java_type_display_generic() {
        let ty = JavaType::Generic(
            "java.util.List".to_owned(),
            vec![JavaType::Reference("java.lang.String".to_owned())],
        );
        assert_eq!(ty.to_string(), "java.util.List<java.lang.String>");
    }

    #[test]
    fn test_java_type_from_descriptor_primitive() {
        assert_eq!(
            JavaType::from_descriptor("I"),
            JavaType::Primitive(Primitive::Int)
        );
        assert_eq!(
            JavaType::from_descriptor("V"),
            JavaType::Primitive(Primitive::Void)
        );
        assert_eq!(
            JavaType::from_descriptor("Z"),
            JavaType::Primitive(Primitive::Boolean)
        );
    }

    #[test]
    fn test_java_type_from_descriptor_reference() {
        let ty = JavaType::from_descriptor("Ljava/lang/String;");
        assert_eq!(ty, JavaType::Reference("java.lang.String".to_owned()));
    }

    #[test]
    fn test_java_type_from_descriptor_array() {
        let ty = JavaType::from_descriptor("[I");
        assert_eq!(
            ty,
            JavaType::Array(Box::new(JavaType::Primitive(Primitive::Int)))
        );
    }

    #[test]
    fn test_java_type_is_reference() {
        assert!(JavaType::Reference("Foo".to_owned()).is_reference());
        assert!(!JavaType::Primitive(Primitive::Int).is_reference());
    }

    #[test]
    fn test_java_type_simple_name() {
        let ty = JavaType::Reference("com.example.Foo".to_owned());
        assert_eq!(ty.simple_name(), Some("Foo"));
    }

    #[test]
    fn test_modifiers_to_string() {
        let m = Modifiers {
            access: AccessLevel::Public,
            scope: ScopeFlags {
                is_static: true,
                ..ScopeFlags::default()
            },
            ..Modifiers::default()
        };
        let s = m.to_string();
        assert!(s.contains("public"), "s={s}");
        assert!(s.contains("static"), "s={s}");
    }

    #[test]
    fn test_binop_display() {
        assert_eq!(BinOp::Add.to_string(), "+");
        assert_eq!(BinOp::Eq.to_string(), "==");
        assert_eq!(BinOp::LogAnd.to_string(), "&&");
    }

    #[test]
    fn test_ast_class_mock() {
        let cls = AstClass::mock("Foo", "com.example");
        assert_eq!(cls.simple_name(), "Foo");
        assert!(!cls.methods.is_empty());
        assert!(!cls.fields.is_empty());
    }

    #[test]
    fn test_ast_class_find_method() {
        let cls = AstClass::mock("Foo", "com.example");
        assert!(cls.find_method("<init>").is_some());
        assert!(cls.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_ast_class_constructors() {
        let cls = AstClass::mock("Foo", "com.example");
        let ctors = cls.constructors();
        assert_eq!(ctors.len(), 1);
    }

    #[test]
    fn test_ast_class_static_methods() {
        let cls = AstClass::mock("Foo", "com.example");
        assert!(!cls.static_methods().is_empty());
    }

    #[test]
    fn test_ast_method_body_size() {
        let cls = AstClass::mock("Foo", "com.example");
        let m = cls.find_method("<init>").unwrap();
        assert_eq!(m.body_size(), 1);
    }

    #[test]
    fn test_compilation_unit_primary_class() {
        let mut cu = CompilationUnit::new("com.example");
        cu.add_class(AstClass::mock("Foo", "com.example"));
        assert_eq!(cu.primary_class().unwrap().name, "Foo");
    }

    #[test]
    fn test_class_kind_display() {
        assert_eq!(ClassKind::Class.to_string(), "class");
        assert_eq!(ClassKind::Interface.to_string(), "interface");
        assert_eq!(ClassKind::Enum.to_string(), "enum");
    }

    #[test]
    fn test_security_relevant_interface() {
        let mut cls = AstClass::new("Foo", "com.example");
        cls.interfaces
            .push("javax.net.ssl.X509TrustManager".to_owned());
        assert!(cls.is_security_relevant());
    }

    #[test]
    fn test_not_security_relevant() {
        let cls = AstClass::new("Foo", "com.example");
        assert!(!cls.is_security_relevant());
    }
}
