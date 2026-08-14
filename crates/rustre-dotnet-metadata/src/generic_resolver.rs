// generic_resolver.rs — .NET generic type and method instantiation resolver
// Instantiates generic types/methods, resolves type parameters, handles constraints.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Element types (subset matching ECMA-335 §II.23.1.16) ────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ElementType {
    Void,
    Boolean,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    String,
    Ptr(Box<Self>),
    ByRef(Box<Self>),
    ValueType(TypeRef),
    Class(TypeRef),
    Var(u32),         // generic type parameter (T, U, ...)
    MVar(u32),        // generic method parameter (M, ...)
    Array(Box<Self>, ArrayShape),
    GenericInst(Box<Self>, Vec<Self>),
    TypedByRef,
    IntPtr,
    UIntPtr,
    FnPtr(Box<MethodSig>),
    Object,
    SzArray(Box<Self>),
    Pinned(Box<Self>),
    Sentinel,
    End,
}

impl ElementType {
    pub fn is_reference_type(&self) -> bool {
        matches!(self, Self::Class(_) | Self::Object | Self::String | Self::Array(_, _) | Self::SzArray(_))
    }

    pub fn is_value_type(&self) -> bool {
        matches!(self, Self::ValueType(_) | Self::I1 | Self::U1 | Self::I2 | Self::U2 |
            Self::I4 | Self::U4 | Self::I8 | Self::U8 | Self::R4 | Self::R8 |
            Self::Boolean | Self::Char | Self::IntPtr | Self::UIntPtr)
    }

    pub fn is_generic_param(&self) -> bool {
        matches!(self, Self::Var(_) | Self::MVar(_))
    }

    pub fn contains_generic_params(&self) -> bool {
        match self {
            Self::Var(_) | Self::MVar(_) => true,
            Self::Ptr(inner) | Self::ByRef(inner) | Self::SzArray(inner) | Self::Pinned(inner) => inner.contains_generic_params(),
            Self::Array(inner, _) => inner.contains_generic_params(),
            Self::GenericInst(base, args) => base.contains_generic_params() || args.iter().any(|a| a.contains_generic_params()),
            _ => false,
        }
    }

    pub fn var_indices(&self) -> Vec<u32> {
        let mut result = Vec::new();
        self.collect_var_indices(&mut result);
        result
    }

    fn collect_var_indices(&self, out: &mut Vec<u32>) {
        match self {
            Self::Var(i) | Self::MVar(i) => out.push(*i),
            Self::Ptr(inner) | Self::ByRef(inner) | Self::SzArray(inner) | Self::Pinned(inner) => inner.collect_var_indices(out),
            Self::Array(inner, _) => inner.collect_var_indices(out),
            Self::GenericInst(base, args) => {
                base.collect_var_indices(out);
                for a in args { a.collect_var_indices(out); }
            }
            _ => {}
        }
    }
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Boolean => write!(f, "bool"),
            Self::Char => write!(f, "char"),
            Self::I1 => write!(f, "sbyte"),
            Self::U1 => write!(f, "byte"),
            Self::I2 => write!(f, "short"),
            Self::U2 => write!(f, "ushort"),
            Self::I4 => write!(f, "int"),
            Self::U4 => write!(f, "uint"),
            Self::I8 => write!(f, "long"),
            Self::U8 => write!(f, "ulong"),
            Self::R4 => write!(f, "float"),
            Self::R8 => write!(f, "double"),
            Self::String => write!(f, "string"),
            Self::Object => write!(f, "object"),
            Self::IntPtr => write!(f, "IntPtr"),
            Self::UIntPtr => write!(f, "UIntPtr"),
            Self::Ptr(inner) => write!(f, "{inner}*"),
            Self::ByRef(inner) => write!(f, "ref {inner}"),
            Self::SzArray(inner) => write!(f, "{inner}[]"),
            Self::ValueType(r) | Self::Class(r) => write!(f, "{r}"),
            Self::Var(i) => write!(f, "!{i}"),
            Self::MVar(i) => write!(f, "!!{i}"),
            Self::GenericInst(base, args) => {
                write!(f, "{base}<")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ">")
            }
            Self::Array(inner, shape) => write!(f, "{inner}[{shape}]"),
            Self::TypedByRef => write!(f, "typedref"),
            Self::Sentinel => write!(f, "..."),
            Self::End => write!(f, "end"),
            Self::Pinned(inner) => write!(f, "pinned {inner}"),
            Self::FnPtr(_) => write!(f, "method*"),
        }
    }
}

// ─── Array shape ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArrayShape {
    pub rank: u32,
    pub sizes: Vec<u32>,
    pub lower_bounds: Vec<i32>,
}

impl fmt::Display for ArrayShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dims: Vec<String> = (0..self.rank as usize).map(|i| {
            let lb = self.lower_bounds.get(i).copied().unwrap_or(0);
            let sz = self.sizes.get(i).copied().unwrap_or(0);
            if sz > 0 { format!("{sz}") } else if lb != 0 { format!("{lb}...") } else { String::new() }
        }).collect();
        write!(f, "{}", dims.join(","))
    }
}

// ─── Type reference ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeRef {
    pub namespace: String,
    pub name: String,
    pub scope: TypeScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeScope {
    CurrentModule,
    AssemblyRef(String),
    ModuleRef(String),
    Nested(Box<TypeRef>),
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.namespace.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}.{}", self.namespace, self.name)
        }
    }
}

// ─── Method signature ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodSig {
    pub calling_convention: CallingConvention,
    pub generic_param_count: u32,
    pub return_type: ElementType,
    pub params: Vec<ElementType>,
    pub vararg_params: Vec<ElementType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    Default,
    C,
    StdCall,
    ThisCall,
    FastCall,
    VarArg,
    Field,
    LocalSig,
    Property,
    Generic,
}

// ─── Generic parameter ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParam {
    pub index: u32,
    pub flags: GenericParamFlags,
    pub name: String,
    pub owner: GenericParamOwner,
    pub constraints: Vec<GenericParamConstraint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericParamFlags(pub u16);

impl GenericParamFlags {
    pub const NONE: Self = Self(0x0000);
    pub const COVARIANT: Self = Self(0x0001);
    pub const CONTRAVARIANT: Self = Self(0x0002);
    pub const REFERENCE_TYPE_CONSTRAINT: Self = Self(0x0004);
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: Self = Self(0x0008);
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: Self = Self(0x0010);

    pub fn is_covariant(self) -> bool { self.0 & 0x0001 != 0 }
    pub fn is_contravariant(self) -> bool { self.0 & 0x0002 != 0 }
    pub fn requires_reference_type(self) -> bool { self.0 & 0x0004 != 0 }
    pub fn requires_value_type(self) -> bool { self.0 & 0x0008 != 0 }
    pub fn requires_default_constructor(self) -> bool { self.0 & 0x0010 != 0 }
    pub fn variance_str(self) -> &'static str {
        if self.is_covariant() { "out" } else if self.is_contravariant() { "in" } else { "" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenericParamOwner {
    TypeDef(u32),
    MethodDef(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParamConstraint {
    pub owner_index: u32,
    pub constraint_type: ElementType,
}

// ─── Type context for substitution ───────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TypeSubstitution {
    /// Type-level generic arguments (replaces !N / Var(N))
    pub type_args: Vec<ElementType>,
    /// Method-level generic arguments (replaces !!N / MVar(N))
    pub method_args: Vec<ElementType>,
}

impl TypeSubstitution {
    pub fn new(type_args: Vec<ElementType>, method_args: Vec<ElementType>) -> Self {
        Self { type_args, method_args }
    }

    pub fn type_only(type_args: Vec<ElementType>) -> Self {
        Self { type_args, method_args: Vec::new() }
    }

    pub fn method_only(method_args: Vec<ElementType>) -> Self {
        Self { type_args: Vec::new(), method_args }
    }

    pub fn is_identity(&self) -> bool {
        self.type_args.is_empty() && self.method_args.is_empty()
    }

    pub fn get_type_arg(&self, index: u32) -> Option<&ElementType> {
        self.type_args.get(index as usize)
    }

    pub fn get_method_arg(&self, index: u32) -> Option<&ElementType> {
        self.method_args.get(index as usize)
    }
}

// ─── Generic instantiation ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericInstantiation {
    pub base_type: TypeRef,
    pub type_arguments: Vec<ElementType>,
}

impl GenericInstantiation {
    pub fn new(base_type: TypeRef, type_arguments: Vec<ElementType>) -> Self {
        Self { base_type, type_arguments }
    }

    pub fn arity(&self) -> usize {
        self.type_arguments.len()
    }

    pub fn is_open(&self) -> bool {
        self.type_arguments.iter().any(|a| a.contains_generic_params())
    }

    pub fn is_closed(&self) -> bool {
        !self.is_open()
    }
}

impl fmt::Display for GenericInstantiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}<", self.base_type)?;
        for (i, a) in self.type_arguments.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{a}")?;
        }
        write!(f, ">")
    }
}

// ─── Constraint checker ───────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ConstraintChecker {
    type_definitions: HashMap<String, TypeDefinitionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinitionInfo {
    pub full_name: String,
    pub is_value_type: bool,
    pub is_sealed: bool,
    pub has_default_ctor: bool,
    pub interfaces: Vec<String>,
    pub base_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintViolation {
    ReferenceTypeRequired { param: String, provided: String },
    ValueTypeRequired { param: String, provided: String },
    DefaultConstructorRequired { param: String, provided: String },
    TypeConstraintViolated { param: String, required: String, provided: String },
    InterfaceConstraintViolated { param: String, required: String, provided: String },
}

impl ConstraintChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_type(&mut self, info: TypeDefinitionInfo) {
        self.type_definitions.insert(info.full_name.clone(), info);
    }

    pub fn check_substitution(&self, params: &[GenericParam], args: &[ElementType]) -> Vec<ConstraintViolation> {
        let mut violations = Vec::with_capacity(params.len());
        for (param, arg) in params.iter().zip(args.iter()) {
            let flags = param.flags;

            if flags.requires_reference_type() && arg.is_value_type() {
                violations.push(ConstraintViolation::ReferenceTypeRequired {
                    param: param.name.clone(),
                    provided: arg.to_string(),
                });
            }

            if flags.requires_value_type() && arg.is_reference_type() {
                violations.push(ConstraintViolation::ValueTypeRequired {
                    param: param.name.clone(),
                    provided: arg.to_string(),
                });
            }

            if flags.requires_default_constructor()
                && let ElementType::Class(tref) = arg
                && let Some(info) = self.type_definitions.get(&tref.to_string())
                && !info.has_default_ctor
            {
                violations.push(ConstraintViolation::DefaultConstructorRequired {
                    param: param.name.clone(),
                    provided: arg.to_string(),
                });
            }

            for constraint in &param.constraints {
                if let ConstraintViolation::TypeConstraintViolated { .. } = self.check_type_constraint(param, arg, &constraint.constraint_type) {
                    violations.extend(Some(self.check_type_constraint(param, arg, &constraint.constraint_type)));
                }
            }
        }
        violations
    }

    fn check_type_constraint(&self, param: &GenericParam, arg: &ElementType, constraint: &ElementType) -> ConstraintViolation {
        // simplified: check that the arg's type name is assignable to the constraint type
        let arg_name = arg.to_string();
        let constraint_name = constraint.to_string();

        if arg_name == constraint_name {
            // self-referential, produce no violation by returning a dummy that won't be pushed
            return ConstraintViolation::TypeConstraintViolated {
                param: param.name.clone(),
                required: constraint_name,
                provided: arg_name,
            };
        }

        if let ElementType::Class(tref) = arg
            && let Some(info) = self.type_definitions.get(&tref.to_string())
        {
            let satisfies = info.base_type.as_deref() == Some(&constraint_name)
                || info.interfaces.iter().any(|i| i == &constraint_name);
            if satisfies {
                return ConstraintViolation::TypeConstraintViolated {
                    param: param.name.clone(),
                    required: constraint_name,
                    provided: arg_name,
                };
            }
        }

        ConstraintViolation::TypeConstraintViolated {
            param: param.name.clone(),
            required: constraint_name,
            provided: arg_name,
        }
    }
}

// ─── Type substitution engine ─────────────────────────────────────────────────

pub struct SubstitutionEngine;

impl SubstitutionEngine {
    pub fn substitute(ty: &ElementType, subst: &TypeSubstitution) -> ElementType {
        if subst.is_identity() {
            return ty.clone();
        }
        match ty {
            ElementType::Var(i) => {
                subst.get_type_arg(*i).cloned().unwrap_or_else(|| ty.clone())
            }
            ElementType::MVar(i) => {
                subst.get_method_arg(*i).cloned().unwrap_or_else(|| ty.clone())
            }
            ElementType::Ptr(inner) => ElementType::Ptr(Box::new(Self::substitute(inner, subst))),
            ElementType::ByRef(inner) => ElementType::ByRef(Box::new(Self::substitute(inner, subst))),
            ElementType::SzArray(inner) => ElementType::SzArray(Box::new(Self::substitute(inner, subst))),
            ElementType::Pinned(inner) => ElementType::Pinned(Box::new(Self::substitute(inner, subst))),
            ElementType::Array(inner, shape) => ElementType::Array(Box::new(Self::substitute(inner, subst)), shape.clone()),
            ElementType::GenericInst(base, args) => {
                let new_base = Self::substitute(base, subst);
                let new_args: Vec<_> = args.iter().map(|a| Self::substitute(a, subst)).collect();
                ElementType::GenericInst(Box::new(new_base), new_args)
            }
            ElementType::FnPtr(sig) => {
                let new_sig = Self::substitute_method_sig(sig, subst);
                ElementType::FnPtr(Box::new(new_sig))
            }
            _ => ty.clone(),
        }
    }

    pub fn substitute_method_sig(sig: &MethodSig, subst: &TypeSubstitution) -> MethodSig {
        MethodSig {
            calling_convention: sig.calling_convention,
            generic_param_count: sig.generic_param_count,
            return_type: Self::substitute(&sig.return_type, subst),
            params: sig.params.iter().map(|p| Self::substitute(p, subst)).collect(),
            vararg_params: sig.vararg_params.iter().map(|p| Self::substitute(p, subst)).collect(),
        }
    }

    pub fn compose(outer: &TypeSubstitution, inner: &TypeSubstitution) -> TypeSubstitution {
        let new_type_args = outer.type_args.iter().map(|t| Self::substitute(t, inner)).collect();
        let new_method_args = outer.method_args.iter().map(|t| Self::substitute(t, inner)).collect();
        TypeSubstitution { type_args: new_type_args, method_args: new_method_args }
    }
}

// ─── Generic instantiation cache ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct InstantiationCache {
    cache: HashMap<InstCacheKey, ResolvedInstantiation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstCacheKey {
    pub base_token: u32,
    pub args: Vec<String>, // serialized ElementType strings as key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedInstantiation {
    pub base_token: u32,
    pub args: Vec<ElementType>,
    pub resolved_fields: Vec<(String, ElementType)>,
    pub resolved_methods: Vec<ResolvedMethodSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedMethodSig {
    pub name: String,
    pub token: u32,
    pub sig: MethodSig,
}

impl InstantiationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, base_token: u32, args: &[ElementType]) -> Option<&ResolvedInstantiation> {
        let key = InstCacheKey { base_token, args: args.iter().map(|a| a.to_string()).collect() };
        self.cache.get(&key)
    }

    pub fn insert(&mut self, inst: ResolvedInstantiation) {
        let key = InstCacheKey {
            base_token: inst.base_token,
            args: inst.args.iter().map(|a| a.to_string()).collect(),
        };
        self.cache.insert(key, inst);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// ─── Generic resolver ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct GenericResolver {
    type_params: HashMap<u32, Vec<GenericParam>>,    // TypeDef token → params
    method_params: HashMap<u32, Vec<GenericParam>>,  // MethodDef token → params
    cache: InstantiationCache,
    checker: ConstraintChecker,
}

impl GenericResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_type_params(&mut self, type_token: u32, params: Vec<GenericParam>) {
        self.type_params.insert(type_token, params);
    }

    pub fn register_method_params(&mut self, method_token: u32, params: Vec<GenericParam>) {
        self.method_params.insert(method_token, params);
    }

    pub fn type_param_count(&self, type_token: u32) -> usize {
        self.type_params.get(&type_token).map_or(0, |p| p.len())
    }

    pub fn method_param_count(&self, method_token: u32) -> usize {
        self.method_params.get(&method_token).map_or(0, |p| p.len())
    }

    pub fn resolve_type_instantiation(
        &mut self,
        base_token: u32,
        args: Vec<ElementType>,
        fields: &[(String, ElementType)],
        methods: &[(String, u32, MethodSig)],
    ) -> Result<ResolvedInstantiation> {
        if let Some(cached) = self.cache.get(base_token, &args) {
            return Ok(cached.clone());
        }

        let params = self.type_params.get(&base_token).cloned().unwrap_or_default();
        if !params.is_empty() && args.len() != params.len() {
            bail!("type 0x{:08x}: expected {} type args, got {}", base_token, params.len(), args.len());
        }

        let violations = self.checker.check_substitution(&params, &args);
        if !violations.is_empty() {
            // Non-fatal: log violations but proceed
        }

        let subst = TypeSubstitution::type_only(args.clone());

        let resolved_fields = fields.iter()
            .map(|(name, ty)| (name.clone(), SubstitutionEngine::substitute(ty, &subst)))
            .collect();

        let resolved_methods = methods.iter()
            .map(|(name, token, sig)| ResolvedMethodSig {
                name: name.clone(),
                token: *token,
                sig: SubstitutionEngine::substitute_method_sig(sig, &subst),
            })
            .collect();

        let inst = ResolvedInstantiation { base_token, args, resolved_fields, resolved_methods };
        self.cache.insert(inst.clone());
        Ok(inst)
    }

    pub fn resolve_method_instantiation(
        &self,
        method_token: u32,
        base_sig: &MethodSig,
        type_args: Vec<ElementType>,
        method_args: Vec<ElementType>,
    ) -> Result<MethodSig> {
        let type_param_count = self.method_params.get(&method_token).map_or(0, |p| p.len());
        if type_param_count > 0 && method_args.len() != type_param_count {
            bail!("method 0x{:08x}: expected {} method args, got {}", method_token, type_param_count, method_args.len());
        }

        let subst = TypeSubstitution::new(type_args, method_args);
        Ok(SubstitutionEngine::substitute_method_sig(base_sig, &subst))
    }

    pub fn instantiate_nested(
        &mut self,
        _outer_token: u32,
        outer_args: &[ElementType],
        inner_token: u32,
        inner_args: Vec<ElementType>,
        fields: &[(String, ElementType)],
        methods: &[(String, u32, MethodSig)],
    ) -> Result<ResolvedInstantiation> {
        let outer_subst = TypeSubstitution::type_only(outer_args.to_vec());
        let substituted_inner_args: Vec<_> = inner_args.iter()
            .map(|a| SubstitutionEngine::substitute(a, &outer_subst))
            .collect();
        self.resolve_type_instantiation(inner_token, substituted_inner_args, fields, methods)
    }

    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), self.type_params.len() + self.method_params.len())
    }

    pub fn substitute_type(&self, ty: &ElementType, subst: &TypeSubstitution) -> ElementType {
        SubstitutionEngine::substitute(ty, subst)
    }

    pub fn format_instantiation(base_name: &str, args: &[ElementType]) -> String {
        if args.is_empty() {
            return base_name.to_string();
        }
        let arg_strs: Vec<_> = args.iter().map(|a| a.to_string()).collect();
        format!("{}<{}>", base_name, arg_strs.join(", "))
    }
}

// ─── Generic method spec ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSpec {
    pub method_token: u32,
    pub type_args: Vec<ElementType>,
}

impl MethodSpec {
    pub fn new(method_token: u32, type_args: Vec<ElementType>) -> Self {
        Self { method_token, type_args }
    }

    pub fn arity(&self) -> usize {
        self.type_args.len()
    }

    pub fn is_open(&self) -> bool {
        self.type_args.iter().any(|a| a.contains_generic_params())
    }
}

// ─── Utility: parse compact generic signature blob ────────────────────────────

pub struct BlobDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BlobDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("BlobDecoder: unexpected end at offset {}", self.pos);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Decode ECMA-335 compressed unsigned integer.
    pub fn read_compressed_uint(&mut self) -> Result<u32> {
        let b0 = self.read_byte()? as u32;
        if b0 & 0x80 == 0 {
            return Ok(b0);
        }
        if b0 & 0xC0 == 0x80 {
            let b1 = self.read_byte()? as u32;
            return Ok(((b0 & 0x3F) << 8) | b1);
        }
        if b0 & 0xE0 == 0xC0 {
            let b1 = self.read_byte()? as u32;
            let b2 = self.read_byte()? as u32;
            let b3 = self.read_byte()? as u32;
            return Ok(((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3);
        }
        bail!("BlobDecoder: invalid compressed uint first byte 0x{b0:02x}");
    }

    /// Decode ECMA-335 compressed signed integer.
    pub fn read_compressed_int(&mut self) -> Result<i32> {
        let u = self.read_compressed_uint()?;
        // rotate right by 1 to recover the sign bit
        let signed = if u & 1 == 0 { (u >> 1) as i32 } else { -((u >> 1) as i32) - 1 };
        Ok(signed)
    }

    pub fn decode_element_type(&mut self) -> Result<ElementType> {
        let tag = self.read_byte()?;
        Ok(match tag {
            0x01 => ElementType::Void,
            0x02 => ElementType::Boolean,
            0x03 => ElementType::Char,
            0x04 => ElementType::I1,
            0x05 => ElementType::U1,
            0x06 => ElementType::I2,
            0x07 => ElementType::U2,
            0x08 => ElementType::I4,
            0x09 => ElementType::U4,
            0x0A => ElementType::I8,
            0x0B => ElementType::U8,
            0x0C => ElementType::R4,
            0x0D => ElementType::R8,
            0x0E => ElementType::String,
            0x0F => {
                let inner = self.decode_element_type()?;
                ElementType::Ptr(Box::new(inner))
            }
            0x10 => {
                let inner = self.decode_element_type()?;
                ElementType::ByRef(Box::new(inner))
            }
            0x11 => {
                let tok = self.read_compressed_uint()?;
                ElementType::ValueType(TypeRef {
                    namespace: String::new(),
                    name: format!("type:0x{tok:08x}"),
                    scope: TypeScope::CurrentModule,
                })
            }
            0x12 => {
                let tok = self.read_compressed_uint()?;
                ElementType::Class(TypeRef {
                    namespace: String::new(),
                    name: format!("type:0x{tok:08x}"),
                    scope: TypeScope::CurrentModule,
                })
            }
            0x13 => {
                let idx = self.read_compressed_uint()?;
                ElementType::Var(idx)
            }
            0x14 => {
                let inner = self.decode_element_type()?;
                let rank = self.read_compressed_uint()?;
                let num_sizes = self.read_compressed_uint()?;
                let mut sizes = Vec::new();
                for _ in 0..num_sizes { sizes.push(self.read_compressed_uint()?); }
                let num_lbs = self.read_compressed_uint()?;
                let mut lbs = Vec::new();
                for _ in 0..num_lbs { lbs.push(self.read_compressed_int()?); }
                ElementType::Array(Box::new(inner), ArrayShape { rank, sizes, lower_bounds: lbs })
            }
            0x15 => {
                let base = self.decode_element_type()?;
                let count = self.read_compressed_uint()?;
                let mut args = Vec::new();
                for _ in 0..count { args.push(self.decode_element_type()?); }
                ElementType::GenericInst(Box::new(base), args)
            }
            0x16 => ElementType::TypedByRef,
            0x18 => ElementType::IntPtr,
            0x19 => ElementType::UIntPtr,
            0x1C => ElementType::Object,
            0x1D => {
                let inner = self.decode_element_type()?;
                ElementType::SzArray(Box::new(inner))
            }
            0x1E => {
                let idx = self.read_compressed_uint()?;
                ElementType::MVar(idx)
            }
            0x45 => {
                let inner = self.decode_element_type()?;
                ElementType::Pinned(Box::new(inner))
            }
            0x41 => ElementType::Sentinel,
            other => bail!("BlobDecoder: unknown element type tag 0x{other:02x}"),
        })
    }

    pub fn decode_method_sig(&mut self) -> Result<MethodSig> {
        let flags = self.read_byte()?;
        let calling_convention = match flags & 0x0F {
            0x00 => CallingConvention::Default,
            0x01 => CallingConvention::C,
            0x02 => CallingConvention::StdCall,
            0x03 => CallingConvention::ThisCall,
            0x04 => CallingConvention::FastCall,
            0x05 => CallingConvention::VarArg,
            0x06 => CallingConvention::Field,
            0x07 => CallingConvention::LocalSig,
            0x08 => CallingConvention::Property,
            _ => CallingConvention::Default,
        };
        let is_generic = flags & 0x10 != 0;
        let generic_param_count = if is_generic { self.read_compressed_uint()? } else { 0 };
        let param_count = self.read_compressed_uint()?;
        let return_type = self.decode_element_type()?;
        let mut params = Vec::new();
        let mut vararg_params = Vec::new();
        let mut in_vararg = false;
        for _ in 0..param_count {
            let ty = self.decode_element_type()?;
            if ty == ElementType::Sentinel {
                in_vararg = true;
                continue;
            }
            if in_vararg { vararg_params.push(ty); } else { params.push(ty); }
        }
        Ok(MethodSig { calling_convention, generic_param_count, return_type, params, vararg_params })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_element_type_display() {
        let t = ElementType::GenericInst(
            Box::new(ElementType::Class(TypeRef { namespace: "System.Collections.Generic".into(), name: "List`1".into(), scope: TypeScope::CurrentModule })),
            vec![ElementType::I4],
        );
        assert!(t.to_string().contains("List`1"));
    }

    #[test]
    fn test_substitution_var() {
        let ty = ElementType::Var(0);
        let subst = TypeSubstitution::type_only(vec![ElementType::String]);
        let result = SubstitutionEngine::substitute(&ty, &subst);
        assert_eq!(result, ElementType::String);
    }

    #[test]
    fn test_substitution_nested() {
        // SzArray<Var(0)> → SzArray<int>
        let ty = ElementType::SzArray(Box::new(ElementType::Var(0)));
        let subst = TypeSubstitution::type_only(vec![ElementType::I4]);
        let result = SubstitutionEngine::substitute(&ty, &subst);
        assert_eq!(result, ElementType::SzArray(Box::new(ElementType::I4)));
    }

    #[test]
    fn test_substitution_identity() {
        let ty = ElementType::I4;
        let subst = TypeSubstitution::default();
        let result = SubstitutionEngine::substitute(&ty, &subst);
        assert_eq!(result, ElementType::I4);
    }

    #[test]
    fn test_blob_decoder_compressed_uint() {
        // single byte: 0x07 → 7
        let mut dec = BlobDecoder::new(&[0x07]);
        assert_eq!(dec.read_compressed_uint().unwrap(), 7);
        // two bytes: 0x80, 0x80 → 128
        let mut dec2 = BlobDecoder::new(&[0x80, 0x80]);
        assert_eq!(dec2.read_compressed_uint().unwrap(), 128);
    }

    #[test]
    fn test_blob_decoder_element_type() {
        // I4 tag = 0x08
        let mut dec = BlobDecoder::new(&[0x08]);
        assert_eq!(dec.decode_element_type().unwrap(), ElementType::I4);
    }

    #[test]
    fn test_resolver_type_instantiation() {
        let mut resolver = GenericResolver::new();
        resolver.register_type_params(0x02000001, vec![
            GenericParam { index: 0, flags: GenericParamFlags::NONE, name: "T".into(), owner: GenericParamOwner::TypeDef(0x02000001), constraints: vec![] },
        ]);
        let inst = resolver.resolve_type_instantiation(
            0x02000001,
            vec![ElementType::I4],
            &[("Value".into(), ElementType::Var(0))],
            &[],
        ).unwrap();
        assert_eq!(inst.resolved_fields[0].1, ElementType::I4);
    }

    #[test]
    fn test_contains_generic_params() {
        let open = ElementType::GenericInst(Box::new(ElementType::Class(TypeRef { namespace: String::new(), name: "C".into(), scope: TypeScope::CurrentModule })), vec![ElementType::Var(0)]);
        assert!(open.contains_generic_params());
        let closed = ElementType::GenericInst(Box::new(ElementType::Class(TypeRef { namespace: String::new(), name: "C".into(), scope: TypeScope::CurrentModule })), vec![ElementType::I4]);
        assert!(!closed.contains_generic_params());
    }
}
