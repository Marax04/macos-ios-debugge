//! Complete `invokedynamic` handling for the JVM.
//!
//! Covers:
//! - [`BootstrapMethod`] — bootstrap method entry from the `BootstrapMethods` attribute
//! - [`MethodHandle`] — all method handle kinds
//! - [`CallSite`] — call site (static / mutable)
//! - [`LambdaMetafactory`] — java.lang.invoke.LambdaMetafactory semantics
//! - [`StringConcatFactory`] — java.lang.invoke.StringConcatFactory semantics
//! - [`JvmInvokeDynamic`] — top-level invokedynamic resolution engine

// ---------------------------------------------------------------------------
// MethodHandleKind
// ---------------------------------------------------------------------------

/// Method handle reference kind (as defined in the JVM spec §5.4.3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodHandleKind {
    GetField = 1,
    GetStatic = 2,
    PutField = 3,
    PutStatic = 4,
    InvokeVirtual = 5,
    InvokeStatic = 6,
    InvokeSpecial = 7,
    NewInvokeSpecial = 8,
    InvokeInterface = 9,
}

impl MethodHandleKind {
    /// Parse from a raw byte.
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::GetField),
            2 => Some(Self::GetStatic),
            3 => Some(Self::PutField),
            4 => Some(Self::PutStatic),
            5 => Some(Self::InvokeVirtual),
            6 => Some(Self::InvokeStatic),
            7 => Some(Self::InvokeSpecial),
            8 => Some(Self::NewInvokeSpecial),
            9 => Some(Self::InvokeInterface),
            _ => None,
        }
    }

    /// `true` if this handle invokes a method.
    #[must_use] 
    pub const fn is_invoke(self) -> bool {
        matches!(
            self,
            Self::InvokeVirtual
                | Self::InvokeStatic
                | Self::InvokeSpecial
                | Self::NewInvokeSpecial
                | Self::InvokeInterface
        )
    }

    /// `true` if this handle accesses a field.
    #[must_use] 
    pub const fn is_field(self) -> bool {
        matches!(
            self,
            Self::GetField | Self::GetStatic | Self::PutField | Self::PutStatic
        )
    }
}

impl std::fmt::Display for MethodHandleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::GetField => "getfield",
            Self::GetStatic => "getstatic",
            Self::PutField => "putfield",
            Self::PutStatic => "putstatic",
            Self::InvokeVirtual => "invokevirtual",
            Self::InvokeStatic => "invokestatic",
            Self::InvokeSpecial => "invokespecial",
            Self::NewInvokeSpecial => "newinvokespecial",
            Self::InvokeInterface => "invokeinterface",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MethodHandle
// ---------------------------------------------------------------------------

/// A JVM method handle descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodHandle {
    /// Reference kind.
    pub kind: MethodHandleKind,
    /// Owner class (binary name, e.g. "java/lang/Object").
    pub owner: String,
    /// Member name.
    pub name: String,
    /// Method descriptor or field descriptor.
    pub descriptor: String,
    /// `true` if this handle is for an interface method.
    pub is_interface: bool,
}

impl MethodHandle {
    /// Create a new method handle.
    #[must_use] 
    pub fn new(kind: MethodHandleKind, owner: &str, name: &str, descriptor: &str) -> Self {
        Self {
            kind,
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            is_interface: false,
        }
    }

    /// Create an interface method handle.
    #[must_use] 
    pub fn interface(kind: MethodHandleKind, owner: &str, name: &str, descriptor: &str) -> Self {
        Self {
            kind,
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            is_interface: true,
        }
    }

    /// `true` if this handle accesses a field.
    #[must_use]
    pub const fn is_field(&self) -> bool {
        self.kind.is_field()
    }

    /// `true` if this handle invokes a method.
    #[must_use]
    pub const fn is_invoke(&self) -> bool {
        self.kind.is_invoke()
    }

    /// Pretty-print (e.g. "`REF_invokeStatic` `java/lang/Math::abs:(I)I`").
    #[must_use]
    pub fn pretty(&self) -> String {
        format!(
            "REF_{} {}::{}:{}",
            self.kind, self.owner, self.name, self.descriptor
        )
    }

    /// `true` if this is an invokestatic handle.
    #[must_use] 
    pub fn is_invoke_static(&self) -> bool {
        self.kind == MethodHandleKind::InvokeStatic
    }
}

// ---------------------------------------------------------------------------
// BootstrapMethod
// ---------------------------------------------------------------------------

/// A bootstrap method entry from the `BootstrapMethods` class attribute.
#[derive(Debug, Clone)]
pub struct BootstrapMethod {
    /// Bootstrap method handle.
    pub method_ref: MethodHandle,
    /// Static bootstrap arguments (constant pool entries).
    pub static_args: Vec<BootstrapArg>,
}

/// A bootstrap argument (can be a constant pool entry of various types).
#[derive(Debug, Clone, PartialEq)]
pub enum BootstrapArg {
    /// String constant.
    String(String),
    /// Integer constant.
    Int(i32),
    /// Long constant.
    Long(i64),
    /// Float constant.
    Float(f32),
    /// Double constant.
    Double(f64),
    /// Class reference.
    Class(String),
    /// Method handle reference.
    MethodHandle(MethodHandle),
    /// Method type (descriptor string).
    MethodType(String),
}

impl BootstrapMethod {
    /// Create a new bootstrap method.
    #[must_use] 
    pub const fn new(method_ref: MethodHandle, static_args: Vec<BootstrapArg>) -> Self {
        Self {
            method_ref,
            static_args,
        }
    }

    /// `true` if this bootstrap method is LambdaMetafactory.metafactory.
    #[must_use] 
    pub fn is_lambda_metafactory(&self) -> bool {
        self.method_ref.owner == "java/lang/invoke/LambdaMetafactory"
            && (self.method_ref.name == "metafactory" || self.method_ref.name == "altMetafactory")
    }

    /// `true` if this bootstrap is StringConcatFactory.makeConcatWithConstants.
    #[must_use] 
    pub fn is_string_concat(&self) -> bool {
        self.method_ref.owner == "java/lang/invoke/StringConcatFactory"
    }

    /// Number of static arguments.
    #[must_use] 
    pub const fn static_arg_count(&self) -> usize {
        self.static_args.len()
    }
}

// ---------------------------------------------------------------------------
// CallSite
// ---------------------------------------------------------------------------

/// A resolved call site (static).
#[derive(Debug, Clone)]
pub struct CallSite {
    /// The bootstrap method that produced this call site.
    pub bootstrap: BootstrapMethod,
    /// Invocation name (the name operand of `invokedynamic`).
    pub name: String,
    /// Dynamic method descriptor (the type operand of `invokedynamic`).
    pub descriptor: String,
    /// Whether the call site is constant (`ConstantCallSite`) or mutable.
    pub is_constant: bool,
    /// Resolved target handle (if resolved).
    pub target: Option<MethodHandle>,
}

impl CallSite {
    /// Create an unresolved call site.
    #[must_use] 
    pub fn new(bootstrap: BootstrapMethod, name: &str, descriptor: &str) -> Self {
        Self {
            bootstrap,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            is_constant: true,
            target: None,
        }
    }

    /// Resolve this call site to a target.
    pub fn resolve(&mut self, target: MethodHandle) {
        self.target = Some(target);
    }

    /// `true` if a target has been resolved.
    #[must_use] 
    pub const fn is_resolved(&self) -> bool {
        self.target.is_some()
    }

    /// Return the resolved method handle, or `None`.
    #[must_use] 
    pub const fn get_target(&self) -> Option<&MethodHandle> {
        self.target.as_ref()
    }
}

// ---------------------------------------------------------------------------
// LambdaMetafactory
// ---------------------------------------------------------------------------

/// Decoded `LambdaMetafactory` call site.
#[derive(Debug, Clone)]
pub struct LambdaMetafactory {
    /// Functional interface class (e.g. "java/util/function/Function").
    pub functional_interface_class: String,
    /// Functional interface method name (e.g. "apply").
    pub functional_interface_method: String,
    /// Functional interface method descriptor.
    pub functional_interface_desc: String,
    /// The actual implementation method handle.
    pub impl_method: MethodHandle,
    /// Instantiated method type (erased functional interface method descriptor).
    pub instantiated_type: String,
    /// `true` if this uses altMetafactory (serializable lambda, etc.).
    pub is_alt: bool,
    /// Lambda flags (bit flags for serializable, markers, bridges).
    pub flags: u32,
}

impl LambdaMetafactory {
    /// Parse from a [`BootstrapMethod`] and the invokedynamic operands.
    #[must_use] 
    pub fn from_bootstrap(
        bsm: &BootstrapMethod,
        invoke_name: &str,
        invoke_desc: &str,
    ) -> Option<Self> {
        if !bsm.is_lambda_metafactory() {
            return None;
        }
        if bsm.static_args.len() < 3 {
            return None;
        }

        // static args: 0=samMethodType(MethodType), 1=implMethod(MH), 2=instantiatedType(MethodType)
        let sam_method_type = match &bsm.static_args[0] {
            BootstrapArg::MethodType(s) => s.clone(),
            _ => return None,
        };
        let impl_method = match &bsm.static_args[1] {
            BootstrapArg::MethodHandle(mh) => mh.clone(),
            _ => return None,
        };
        let instantiated_type = match &bsm.static_args[2] {
            BootstrapArg::MethodType(s) => s.clone(),
            _ => return None,
        };

        // Derive functional interface class from invoke descriptor (returns the interface type)
        // For simplicity: parse "()Ljava/util/function/Function;" → "java/util/function/Function"
        let fi_class =
            Self::parse_return_class(invoke_desc).unwrap_or_else(|| "java/lang/Object".to_string());

        let is_alt = bsm.method_ref.name == "altMetafactory";
        let flags = if is_alt {
            match bsm.static_args.get(3) {
                Some(BootstrapArg::Int(f)) => (*f).cast_unsigned(),
                _ => 0,
            }
        } else {
            0
        };

        Some(Self {
            functional_interface_class: fi_class,
            functional_interface_method: invoke_name.to_string(),
            functional_interface_desc: sam_method_type,
            impl_method,
            instantiated_type,
            is_alt,
            flags,
        })
    }

    fn parse_return_class(descriptor: &str) -> Option<String> {
        // Parse "(...)Lclass/name;" → "class/name"
        descriptor.rfind('L').and_then(|start| {
            descriptor[start + 1..]
                .find(';')
                .map(|end| descriptor[start + 1..start + 1 + end].to_string())
        })
    }

    /// `true` if this lambda is serializable.
    #[must_use] 
    pub const fn is_serializable(&self) -> bool {
        self.flags & 1 != 0
    }

    /// `true` if this lambda is a method reference (impl method is public, non-synthetic).
    #[must_use] 
    pub fn is_method_ref(&self) -> bool {
        !self.impl_method.name.starts_with("lambda$")
    }
}

// ---------------------------------------------------------------------------
// StringConcatFactory
// ---------------------------------------------------------------------------

/// Decoded `StringConcatFactory` call site (JDK 9+).
#[derive(Debug, Clone)]
pub struct StringConcatFactory {
    /// The recipe pattern string.
    pub recipe: Option<String>,
    /// Argument types for the concatenation.
    pub arg_types: Vec<String>,
    /// `true` if this is `makeConcatWithConstants` (has a recipe string).
    pub has_recipe: bool,
}

impl StringConcatFactory {
    /// Parse from a [`BootstrapMethod`].
    #[must_use] 
    pub fn from_bootstrap(bsm: &BootstrapMethod, invoke_desc: &str) -> Option<Self> {
        if !bsm.is_string_concat() {
            return None;
        }

        let has_recipe = bsm.method_ref.name == "makeConcatWithConstants";
        let recipe = if has_recipe {
            bsm.static_args.iter().find_map(|a| {
                if let BootstrapArg::String(s) = a {
                    Some(s.clone())
                } else {
                    None
                }
            })
        } else {
            None
        };

        // Parse argument types from descriptor
        let arg_types = Self::parse_arg_types(invoke_desc);

        Some(Self {
            recipe,
            arg_types,
            has_recipe,
        })
    }

    fn parse_arg_types(descriptor: &str) -> Vec<String> {
        let inner = descriptor.trim_start_matches('(');
        let Some(end) = inner.find(')') else {
            return Vec::new();
        };
        {
            let params = &inner[..end];
            // Simplified: split on known primitive types
            let mut types = Vec::new();
            let mut chars = params.chars();
            // A run of '[' is a PREFIX on the type that follows, not a
            // parameter of its own: "[I" is one argument (int[]), not two.
            let mut array_depth = 0usize;
            while let Some(c) = chars.next() {
                let base = match c {
                    'I' => "int".to_string(),
                    'J' => "long".to_string(),
                    'D' => "double".to_string(),
                    'F' => "float".to_string(),
                    'Z' => "boolean".to_string(),
                    'B' => "byte".to_string(),
                    'C' => "char".to_string(),
                    'S' => "short".to_string(),
                    'L' => {
                        let mut cls = String::new();
                        for c2 in chars.by_ref() {
                            if c2 == ';' {
                                break;
                            }
                            cls.push(c2);
                        }
                        cls
                    }
                    '[' => {
                        array_depth += 1;
                        continue;
                    }
                    _ => continue,
                };
                let mut ty = base;
                for _ in 0..array_depth {
                    ty.push_str("[]");
                }
                array_depth = 0;
                types.push(ty);
            }
            types
        }
    }

    /// Count of constant parts (in the recipe: everything except '' and '').
    #[must_use] 
    pub fn constant_count(&self) -> usize {
        self.recipe
            .as_ref()
            .map_or(0, |r| {
                r.chars()
                    .filter(|c| *c != '\u{0001}' && *c != '\u{0002}')
                    .count()
            })
    }

    /// Count of dynamic argument slots in the recipe.
    #[must_use] 
    pub fn dynamic_count(&self) -> usize {
        self.recipe
            .as_ref()
            .map_or(0, |r| r.chars().filter(|c| *c == '\u{0001}').count())
    }
}

// ---------------------------------------------------------------------------
// JvmInvokeDynamic — the main resolver
// ---------------------------------------------------------------------------

/// Result of resolving an `invokedynamic` instruction.
#[derive(Debug, Clone)]
pub enum InvokeDynamicResult {
    /// Lambda or method reference via `LambdaMetafactory`.
    Lambda(LambdaMetafactory),
    /// String concatenation via `StringConcatFactory`.
    StringConcat(StringConcatFactory),
    /// Another (custom) bootstrap method.
    Custom {
        bootstrap_owner: String,
        bootstrap_name: String,
    },
    /// Resolution failed.
    Failed { reason: String },
}

/// Top-level invokedynamic resolution engine.
#[derive(Debug, Default)]
pub struct JvmInvokeDynamic;

impl JvmInvokeDynamic {
    /// Resolve an `invokedynamic` instruction.
    #[must_use] 
    pub fn resolve(
        bootstrap: &BootstrapMethod,
        name: &str,
        descriptor: &str,
    ) -> InvokeDynamicResult {
        if bootstrap.is_lambda_metafactory() {
            LambdaMetafactory::from_bootstrap(bootstrap, name, descriptor).map_or_else(
                || InvokeDynamicResult::Failed {
                    reason: "LambdaMetafactory parse error".to_string(),
                },
                InvokeDynamicResult::Lambda,
            )
        } else if bootstrap.is_string_concat() {
            StringConcatFactory::from_bootstrap(bootstrap, descriptor).map_or_else(
                || InvokeDynamicResult::Failed {
                    reason: "StringConcatFactory parse error".to_string(),
                },
                InvokeDynamicResult::StringConcat,
            )
        } else {
            InvokeDynamicResult::Custom {
                bootstrap_owner: bootstrap.method_ref.owner.clone(),
                bootstrap_name: bootstrap.method_ref.name.clone(),
            }
        }
    }

    /// Create a simple lambda bootstrap method for testing.
    #[must_use] 
    pub fn lambda_bootstrap(
        impl_owner: &str,
        impl_name: &str,
        impl_desc: &str,
        sam_type: &str,
        instantiated_type: &str,
    ) -> BootstrapMethod {
        let bsm_mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/invoke/LambdaMetafactory",
            "metafactory",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
        );
        let impl_mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            impl_owner,
            impl_name,
            impl_desc,
        );
        BootstrapMethod::new(
            bsm_mh,
            vec![
                BootstrapArg::MethodType(sam_type.to_string()),
                BootstrapArg::MethodHandle(impl_mh),
                BootstrapArg::MethodType(instantiated_type.to_string()),
            ],
        )
    }

    /// Create a `StringConcatFactory` bootstrap for testing.
    #[must_use] 
    pub fn string_concat_bootstrap(recipe: &str) -> BootstrapMethod {
        let bsm_mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
        );
        BootstrapMethod::new(bsm_mh, vec![BootstrapArg::String(recipe.to_string())])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// InvokeDynamicSite — analysis helper
// ---------------------------------------------------------------------------

/// Classification of an invokedynamic site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeDynamicClass {
    /// Lambda or method reference.
    Lambda,
    /// String concatenation.
    StringConcat,
    /// Groovy runtime.
    Groovy,
    /// Kotlin runtime.
    Kotlin,
    /// Scala runtime.
    Scala,
    /// Custom / unknown.
    Custom,
}

/// A single resolved invokedynamic site with analysis metadata.
#[derive(Debug, Clone)]
pub struct InvokeDynamicSite {
    /// Bytecode offset of the instruction.
    pub bytecode_offset: u32,
    /// Symbolic name from the instruction operand.
    pub name: String,
    /// Descriptor from the instruction operand.
    pub descriptor: String,
    /// Classification.
    pub class: InvokeDynamicClass,
    /// Resolved call site (if available).
    pub call_site: Option<CallSite>,
}

impl InvokeDynamicSite {
    /// Create a new invokedynamic site.
    #[must_use] 
    pub fn new(offset: u32, name: &str, descriptor: &str, bootstrap: BootstrapMethod) -> Self {
        let class = Self::classify_bootstrap(&bootstrap);
        let cs = CallSite::new(bootstrap, name, descriptor);
        Self {
            bytecode_offset: offset,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            class,
            call_site: Some(cs),
        }
    }

    fn classify_bootstrap(bsm: &BootstrapMethod) -> InvokeDynamicClass {
        let owner = &bsm.method_ref.owner;
        if owner.contains("LambdaMetafactory") {
            InvokeDynamicClass::Lambda
        } else if owner.contains("StringConcatFactory") {
            InvokeDynamicClass::StringConcat
        } else if owner.contains("groovy") || owner.contains("Groovy") {
            InvokeDynamicClass::Groovy
        } else if owner.contains("kotlin") || owner.contains("Kotlin") {
            InvokeDynamicClass::Kotlin
        } else if owner.contains("scala") || owner.contains("Scala") {
            InvokeDynamicClass::Scala
        } else {
            InvokeDynamicClass::Custom
        }
    }

    /// `true` if this is a lambda or method reference.
    #[must_use] 
    pub fn is_lambda(&self) -> bool {
        self.class == InvokeDynamicClass::Lambda
    }

    /// `true` if this is string concatenation.
    #[must_use] 
    pub fn is_string_concat(&self) -> bool {
        self.class == InvokeDynamicClass::StringConcat
    }
}

/// Aggregates all invokedynamic sites in a class/method.
#[derive(Debug, Default)]
pub struct InvokeDynamicAnalysis {
    sites: Vec<InvokeDynamicSite>,
}

impl InvokeDynamicAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a site.
    pub fn add(&mut self, site: InvokeDynamicSite) {
        self.sites.push(site);
    }

    /// Count of all sites.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.sites.len()
    }

    /// Count of lambda sites.
    #[must_use] 
    pub fn lambda_count(&self) -> usize {
        self.sites.iter().filter(|s| s.is_lambda()).count()
    }

    /// Count of string-concat sites.
    #[must_use] 
    pub fn string_concat_count(&self) -> usize {
        self.sites.iter().filter(|s| s.is_string_concat()).count()
    }

    /// All sites classified as `Custom`.
    #[must_use] 
    pub fn custom_sites(&self) -> Vec<&InvokeDynamicSite> {
        self.sites
            .iter()
            .filter(|s| s.class == InvokeDynamicClass::Custom)
            .collect()
    }

    /// Iterate all sites.
    pub fn iter(&self) -> impl Iterator<Item = &InvokeDynamicSite> {
        self.sites.iter()
    }

    /// `true` if any site is a Kotlin lambda.
    #[must_use] 
    pub fn has_kotlin(&self) -> bool {
        self.sites
            .iter()
            .any(|s| s.class == InvokeDynamicClass::Kotlin)
    }

    /// `true` if any site is Groovy.
    #[must_use] 
    pub fn has_groovy(&self) -> bool {
        self.sites
            .iter()
            .any(|s| s.class == InvokeDynamicClass::Groovy)
    }

    /// Summary string for reporting.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "{} sites: {} lambda, {} string-concat, {} custom",
            self.count(),
            self.lambda_count(),
            self.string_concat_count(),
            self.custom_sites().len()
        )
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lambda_bsm() -> BootstrapMethod {
        JvmInvokeDynamic::lambda_bootstrap(
            "com/example/Foo",
            "lambda$0",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
        )
    }

    fn concat_bsm() -> BootstrapMethod {
        JvmInvokeDynamic::string_concat_bootstrap("\u{0001}x\u{0001}")
    }

    // ── 1. MethodHandleKind ──────────────────────────────────────────────────
    #[test]
    fn test_mhk_from_u8() {
        assert_eq!(
            MethodHandleKind::from_u8(1),
            Some(MethodHandleKind::GetField)
        );
        assert_eq!(
            MethodHandleKind::from_u8(9),
            Some(MethodHandleKind::InvokeInterface)
        );
        assert_eq!(MethodHandleKind::from_u8(0), None);
    }

    #[test]
    fn test_mhk_is_invoke() {
        assert!(MethodHandleKind::InvokeStatic.is_invoke());
        assert!(MethodHandleKind::InvokeVirtual.is_invoke());
        assert!(!MethodHandleKind::GetField.is_invoke());
    }

    #[test]
    fn test_mhk_is_field() {
        assert!(MethodHandleKind::GetField.is_field());
        assert!(MethodHandleKind::PutStatic.is_field());
        assert!(!MethodHandleKind::InvokeStatic.is_field());
    }

    #[test]
    fn test_mhk_display() {
        assert_eq!(
            format!("{}", MethodHandleKind::InvokeStatic),
            "invokestatic"
        );
        assert_eq!(
            format!("{}", MethodHandleKind::NewInvokeSpecial),
            "newinvokespecial"
        );
    }

    // ── 2. MethodHandle ──────────────────────────────────────────────────────
    #[test]
    fn test_method_handle_new() {
        let mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/Math",
            "abs",
            "(I)I",
        );
        assert_eq!(mh.owner, "java/lang/Math");
        assert_eq!(mh.name, "abs");
        assert!(!mh.is_interface);
    }

    #[test]
    fn test_method_handle_is_invoke_static() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "A", "b", "()V");
        assert!(mh.is_invoke_static());
        let mh2 = MethodHandle::new(MethodHandleKind::GetField, "A", "f", "I");
        assert!(!mh2.is_invoke_static());
    }

    #[test]
    fn test_method_handle_pretty() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "A", "m", "()V");
        let p = mh.pretty();
        assert!(p.contains("REF_invokestatic"));
        assert!(p.contains("A::m:()V"));
    }

    #[test]
    fn test_method_handle_interface() {
        let mh = MethodHandle::interface(MethodHandleKind::InvokeInterface, "I", "m", "()V");
        assert!(mh.is_interface);
    }

    // ── 3. BootstrapMethod ───────────────────────────────────────────────────
    #[test]
    fn test_bsm_is_lambda_metafactory() {
        let bsm = lambda_bsm();
        assert!(bsm.is_lambda_metafactory());
    }

    #[test]
    fn test_bsm_is_string_concat() {
        let bsm = concat_bsm();
        assert!(bsm.is_string_concat());
    }

    #[test]
    fn test_bsm_not_lambda() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "com/Foo", "bar", "()V");
        let bsm = BootstrapMethod::new(mh, vec![]);
        assert!(!bsm.is_lambda_metafactory());
    }

    #[test]
    fn test_bsm_static_arg_count() {
        let bsm = lambda_bsm();
        assert_eq!(bsm.static_arg_count(), 3);
    }

    // ── 4. CallSite ──────────────────────────────────────────────────────────
    #[test]
    fn test_callsite_unresolved() {
        let bsm = lambda_bsm();
        let cs = CallSite::new(bsm, "apply", "(Ljava/lang/Object;)Ljava/lang/Object;");
        assert!(!cs.is_resolved());
        assert!(cs.get_target().is_none());
    }

    #[test]
    fn test_callsite_resolve() {
        let bsm = lambda_bsm();
        let mut cs = CallSite::new(bsm, "apply", "()V");
        let target = MethodHandle::new(MethodHandleKind::InvokeStatic, "A", "b", "()V");
        cs.resolve(target);
        assert!(cs.is_resolved());
        assert_eq!(cs.get_target().unwrap().name, "b");
    }

    // ── 5. LambdaMetafactory ────────────────────────────────────────────────
    #[test]
    fn test_lambda_parse() {
        let bsm = lambda_bsm();
        let lm = LambdaMetafactory::from_bootstrap(
            &bsm,
            "apply",
            "(Ljava/util/function/Function;)Ljava/util/function/Function;",
        );
        assert!(lm.is_some());
        let lm = lm.unwrap();
        assert_eq!(lm.functional_interface_method, "apply");
        assert!(!lm.is_serializable());
    }

    #[test]
    fn test_lambda_is_method_ref() {
        let bsm =
            JvmInvokeDynamic::lambda_bootstrap("com/Foo", "realMethod", "(I)V", "(I)V", "(I)V");
        let lm = LambdaMetafactory::from_bootstrap(&bsm, "accept", "()V");
        if let Some(l) = lm {
            assert!(l.is_method_ref()); // "realMethod" does not start with "lambda$"
        }
    }

    #[test]
    fn test_lambda_not_method_ref() {
        let bsm = JvmInvokeDynamic::lambda_bootstrap("com/Foo", "lambda$0", "(I)V", "(I)V", "(I)V");
        let lm = LambdaMetafactory::from_bootstrap(&bsm, "accept", "()V");
        if let Some(l) = lm {
            assert!(!l.is_method_ref());
        }
    }

    // ── 6. StringConcatFactory ──────────────────────────────────────────────
    #[test]
    fn test_string_concat_parse() {
        let bsm = concat_bsm();
        let sc =
            StringConcatFactory::from_bootstrap(&bsm, "(ILjava/lang/String;)Ljava/lang/String;");
        assert!(sc.is_some());
        let sc = sc.unwrap();
        assert!(sc.has_recipe);
    }

    /// A '[' in a descriptor is an array PREFIX on the type that follows,
    /// not an argument of its own. Before this was fixed, "([I)V" parsed as
    /// two arguments ["array", "int"] instead of one ["int[]"], inflating the
    /// arity of every method taking an array.
    #[test]
    fn array_descriptors_are_one_argument_with_a_suffix() {
        let bsm = concat_bsm();
        let cases: [(&str, &[&str]); 5] = [
            ("([I)Ljava/lang/String;", &["int[]"]),
            ("([[I)Ljava/lang/String;", &["int[][]"]),
            ("([Ljava/lang/String;)Ljava/lang/String;", &["java/lang/String[]"]),
            ("(I[JLjava/lang/String;)Ljava/lang/String;", &["int", "long[]", "java/lang/String"]),
            ("(II)Ljava/lang/String;", &["int", "int"]),
        ];
        for (desc, want) in cases {
            let sc = StringConcatFactory::from_bootstrap(&bsm, desc).unwrap();
            assert_eq!(sc.arg_types, want, "descriptor {desc}");
        }
    }

    #[test]
    fn test_string_concat_recipe() {
        let bsm = concat_bsm();
        let sc = StringConcatFactory::from_bootstrap(&bsm, "(I)Ljava/lang/String;").unwrap();
        assert!(sc.recipe.is_some());
    }

    #[test]
    fn test_string_concat_dynamic_count() {
        let recipe = "\u{0001}x\u{0001}"; // two dynamic slots
        let bsm = JvmInvokeDynamic::string_concat_bootstrap(recipe);
        let sc = StringConcatFactory::from_bootstrap(&bsm, "()Ljava/lang/String;").unwrap();
        assert_eq!(sc.dynamic_count(), 2);
    }

    #[test]
    fn test_string_concat_arg_types() {
        let bsm = concat_bsm();
        let sc =
            StringConcatFactory::from_bootstrap(&bsm, "(ILjava/lang/String;)Ljava/lang/String;")
                .unwrap();
        assert_eq!(sc.arg_types.len(), 2);
        assert_eq!(sc.arg_types[0], "int");
        assert_eq!(sc.arg_types[1], "java/lang/String");
    }

    // ── 7. JvmInvokeDynamic resolve ─────────────────────────────────────────
    #[test]
    fn test_resolve_lambda() {
        let bsm = lambda_bsm();
        let result = JvmInvokeDynamic::resolve(
            &bsm,
            "apply",
            "(Ljava/util/function/Function;)Ljava/util/function/Function;",
        );
        assert!(matches!(result, InvokeDynamicResult::Lambda(_)));
    }

    #[test]
    fn test_resolve_string_concat() {
        let bsm = concat_bsm();
        let result =
            JvmInvokeDynamic::resolve(&bsm, "makeConcatWithConstants", "(I)Ljava/lang/String;");
        assert!(matches!(result, InvokeDynamicResult::StringConcat(_)));
    }

    #[test]
    fn test_resolve_custom() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "com/Foo", "bsm", "()V");
        let bsm = BootstrapMethod::new(mh, vec![]);
        let result = JvmInvokeDynamic::resolve(&bsm, "foo", "()V");
        assert!(matches!(result, InvokeDynamicResult::Custom { .. }));
    }

    #[test]
    fn test_resolve_lambda_too_few_args_fails() {
        let mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/invoke/LambdaMetafactory",
            "metafactory",
            "()V",
        );
        let bsm = BootstrapMethod::new(mh, vec![]); // no static args
        let result = JvmInvokeDynamic::resolve(&bsm, "apply", "()V");
        assert!(matches!(result, InvokeDynamicResult::Failed { .. }));
    }

    // ── 8. BootstrapArg variants ─────────────────────────────────────────────
    #[test]
    fn test_bootstrap_arg_variants() {
        let _ = BootstrapArg::String("hello".into());
        let _ = BootstrapArg::Int(42);
        let _ = BootstrapArg::Long(100);
        let _ = BootstrapArg::Float(1.0);
        let _ = BootstrapArg::Double(2.0);
        let _ = BootstrapArg::Class("java/lang/Object".into());
        let _ = BootstrapArg::MethodType("()V".into());
    }

    // ── 9. MethodHandleKind all values ───────────────────────────────────────
    #[test]
    fn test_mhk_all_values() {
        for i in 1u8..=9 {
            let k = MethodHandleKind::from_u8(i);
            assert!(k.is_some(), "kind {i} must be parseable");
        }
    }

    // ── 10. CallSite is_constant default ─────────────────────────────────────
    #[test]
    fn test_callsite_is_constant_default() {
        let bsm = lambda_bsm();
        let cs = CallSite::new(bsm, "x", "()V");
        assert!(cs.is_constant);
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_mhk_from_u8_all() {
        for i in 1u8..=9 {
            assert!(MethodHandleKind::from_u8(i).is_some());
        }
        assert!(MethodHandleKind::from_u8(0).is_none());
        assert!(MethodHandleKind::from_u8(10).is_none());
    }

    #[test]
    fn test_bootstrap_arg_eq() {
        assert_eq!(BootstrapArg::Int(5), BootstrapArg::Int(5));
        assert_ne!(BootstrapArg::Int(5), BootstrapArg::Int(6));
    }

    #[test]
    fn test_lambda_metafactory_flags_zero() {
        let bsm = lambda_bsm();
        let lm = LambdaMetafactory::from_bootstrap(&bsm, "apply", "()V");
        if let Some(l) = lm {
            assert_eq!(l.flags, 0);
        }
    }

    #[test]
    fn test_string_concat_no_recipe() {
        let mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/invoke/StringConcatFactory",
            "makeConcat",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
        );
        let bsm = BootstrapMethod::new(mh, vec![]);
        let sc = StringConcatFactory::from_bootstrap(&bsm, "(I)Ljava/lang/String;").unwrap();
        assert!(!sc.has_recipe);
        assert!(sc.recipe.is_none());
    }

    #[test]
    fn test_callsite_name_and_descriptor() {
        let bsm = lambda_bsm();
        let cs = CallSite::new(bsm, "accept", "(I)V");
        assert_eq!(cs.name, "accept");
        assert_eq!(cs.descriptor, "(I)V");
    }

    #[test]
    fn test_invoke_dynamic_result_custom_fields() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "com/Foo", "bsm", "()V");
        let bsm = BootstrapMethod::new(mh, vec![]);
        let result = JvmInvokeDynamic::resolve(&bsm, "test", "()V");
        match result {
            InvokeDynamicResult::Custom {
                bootstrap_owner,
                bootstrap_name,
            } => {
                assert_eq!(bootstrap_owner, "com/Foo");
                assert_eq!(bootstrap_name, "bsm");
            }
            _ => panic!("expected Custom"),
        }
    }

    #[test]
    fn test_method_handle_descriptor() {
        let mh = MethodHandle::new(MethodHandleKind::InvokeVirtual, "A", "m", "(I)Z");
        assert_eq!(mh.descriptor, "(I)Z");
    }

    #[test]
    fn test_method_handle_get_field() {
        let mh = MethodHandle::new(MethodHandleKind::GetField, "A", "f", "I");
        assert!(mh.is_field());
        assert!(!mh.is_invoke());
    }

    #[test]
    fn test_lambda_metafactory_functional_interface_class() {
        let bsm = lambda_bsm();
        let lm = LambdaMetafactory::from_bootstrap(
            &bsm,
            "apply",
            "(Ljava/util/function/Function;)Ljava/util/function/Function;",
        );
        if let Some(l) = lm {
            assert!(!l.functional_interface_class.is_empty());
        }
    }

    #[test]
    fn test_string_concat_factory_constant_count_empty_recipe() {
        let bsm = JvmInvokeDynamic::string_concat_bootstrap("abc");
        let sc = StringConcatFactory::from_bootstrap(&bsm, "()Ljava/lang/String;").unwrap();
        // "abc" has no dynamic slots and no U+0001/U+0002 chars
        assert_eq!(sc.dynamic_count(), 0);
    }

    #[test]
    fn test_bsm_is_alt_metafactory() {
        let mh = MethodHandle::new(
            MethodHandleKind::InvokeStatic,
            "java/lang/invoke/LambdaMetafactory",
            "altMetafactory",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
        );
        let impl_mh = MethodHandle::new(MethodHandleKind::InvokeStatic, "A", "f", "()V");
        let bsm = BootstrapMethod::new(
            mh,
            vec![
                BootstrapArg::MethodType("()V".into()),
                BootstrapArg::MethodHandle(impl_mh),
                BootstrapArg::MethodType("()V".into()),
                BootstrapArg::Int(1), // SERIALIZABLE flag
            ],
        );
        assert!(bsm.is_lambda_metafactory());
        let lm = LambdaMetafactory::from_bootstrap(&bsm, "run", "()V");
        if let Some(l) = lm {
            assert!(l.is_alt);
            assert!(l.is_serializable()); // flags & 1 = 1
        }
    }
}
