//! `type_inference_engine` — Hindley-Milner style type inference for binary RE.
//!
//! Provides:
//! * [`TypeInferenceEngine`]  — top-level coordinator.
//! * [`InferenceRule`]        — 50+ rule set for inferring types.
//! * [`TypeVariable`]         — unification type variable.
//! * [`Unification`]          — union-find unifier.
//! * [`UnificationError`]     — mismatch / occurs-check error.
//! * [`TypeEnv`]              — environment mapping names → types.
//! * [`Substitution`]         — finite mapping of type vars to types.
//! * [`GeneralizedType`]      — quantified type scheme.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};

// ─────────────────────────────────────────────────────────────────────────────
// BaseType
// ─────────────────────────────────────────────────────────────────────────────

/// A ground (monomorphic) type in the binary's type system.
///
/// `Clone`/`PartialEq`/`Hash`/`Debug`/`Display`/`Drop` are hand-written
/// iterative implementations: the derived (or compiler-generated) versions
/// recurse once per `Ptr`/`Array` layer and overflow the stack on very deep
/// chains, which are constructible from the public API (`ptr_to`/`array_of`).
/// Semantics are identical to the derived impls.
pub enum BaseType {
    /// Unsigned integer of given bit width.
    UInt(u8),
    /// Signed integer of given bit width.
    Int(u8),
    /// Floating-point of given bit width.
    Float(u8),
    /// Boolean (1-bit logical).
    Bool,
    /// Pointer to a type.
    Ptr(Box<Self>),
    /// Array: element type × count.
    Array(Box<Self>, usize),
    /// Struct with named fields.
    Struct(String, Vec<(String, Self)>),
    /// Function type: parameters × return type.
    Func(Vec<Self>, Box<Self>),
    /// Void / unit.
    Void,
    /// Unknown (bottom of the lattice).
    Unknown,
}

/// Spine wrapper descriptor used by the iterative `BaseType` impls.
enum BaseWrap {
    Ptr,
    Array(usize),
}

impl BaseType {
    /// Peel the `Ptr`/`Array` spine iteratively, recording each wrapper.
    /// Returns the terminal (non-`Ptr`, non-`Array`) node.
    fn peel_spine<'a>(mut cur: &'a Self, spine: &mut Vec<BaseWrap>) -> &'a Self {
        loop {
            match cur {
                Self::Ptr(inner) => {
                    spine.push(BaseWrap::Ptr);
                    cur = inner;
                }
                Self::Array(inner, n) => {
                    spine.push(BaseWrap::Array(*n));
                    cur = inner;
                }
                _ => return cur,
            }
        }
    }
}

/// Manual iterative `Clone`: peels the `Ptr`/`Array` spine in a loop, clones
/// the terminal node, then rewraps. Only `Struct`/`Func` (bounded nesting in
/// practice) recurse.
impl Clone for BaseType {
    fn clone(&self) -> Self {
        let mut spine = Vec::new();
        let cur = Self::peel_spine(self, &mut spine);
        let mut out = match cur {
            Self::UInt(w) => Self::UInt(*w),
            Self::Int(w) => Self::Int(*w),
            Self::Float(w) => Self::Float(*w),
            Self::Bool => Self::Bool,
            Self::Struct(n, fs) => Self::Struct(n.clone(), fs.clone()),
            Self::Func(p, r) => Self::Func(p.clone(), r.clone()),
            Self::Void => Self::Void,
            Self::Unknown => Self::Unknown,
            Self::Ptr(_) | Self::Array(..) => unreachable!("spine fully peeled above"),
        };
        while let Some(w) = spine.pop() {
            out = match w {
                BaseWrap::Ptr => Self::Ptr(Box::new(out)),
                BaseWrap::Array(n) => Self::Array(Box::new(out), n),
            };
        }
        out
    }
}

/// Manual iterative `Drop`: the compiler-generated drop glue recurses once per
/// `Box` layer and overflows the stack on very deep `Ptr`/`Array` chains.
impl Drop for BaseType {
    fn drop(&mut self) {
        // Fast path: leaf variants need no worklist.
        if matches!(
            self,
            Self::UInt(_) | Self::Int(_) | Self::Float(_) | Self::Bool | Self::Void | Self::Unknown
        ) {
            return;
        }
        const LEAF: BaseType = BaseType::Void;
        fn detach(t: &mut BaseType, stack: &mut Vec<BaseType>) {
            match t {
                BaseType::Ptr(inner) | BaseType::Array(inner, _) => {
                    stack.push(std::mem::replace(&mut **inner, LEAF));
                }
                BaseType::Struct(_, fields) => stack.extend(fields.drain(..).map(|(_, v)| v)),
                BaseType::Func(params, ret) => {
                    stack.extend(params.drain(..));
                    stack.push(std::mem::replace(&mut **ret, LEAF));
                }
                BaseType::UInt(_)
                | BaseType::Int(_)
                | BaseType::Float(_)
                | BaseType::Bool
                | BaseType::Void
                | BaseType::Unknown => {}
            }
        }
        let mut stack: Vec<Self> = Vec::new();
        detach(self, &mut stack);
        while let Some(mut t) = stack.pop() {
            detach(&mut t, &mut stack);
            // `t` drops here with all children already detached — O(1) depth.
        }
    }
}

/// Manual iterative `PartialEq`: walks both `Ptr`/`Array` spines in lockstep.
/// Semantics identical to the derived impl.
impl PartialEq for BaseType {
    fn eq(&self, other: &Self) -> bool {
        let (mut a, mut b) = (self, other);
        loop {
            match (a, b) {
                (Self::Ptr(x), Self::Ptr(y)) => {
                    a = x;
                    b = y;
                }
                (Self::Array(x, n), Self::Array(y, m)) => {
                    if n != m {
                        return false;
                    }
                    a = x;
                    b = y;
                }
                (Self::UInt(x), Self::UInt(y))
                | (Self::Int(x), Self::Int(y))
                | (Self::Float(x), Self::Float(y)) => return x == y,
                (Self::Bool, Self::Bool) | (Self::Void, Self::Void) | (Self::Unknown, Self::Unknown) => {
                    return true
                }
                (Self::Struct(n1, f1), Self::Struct(n2, f2)) => return n1 == n2 && f1 == f2,
                (Self::Func(p1, r1), Self::Func(p2, r2)) => return p1 == p2 && r1 == r2,
                _ => return false,
            }
        }
    }
}

impl Eq for BaseType {}

/// Manual iterative `Hash`: emits the exact same byte stream as the derived
/// impl (discriminant, then fields in declaration order — array lengths are
/// deferred until after their element's stream, matching derived field order).
impl Hash for BaseType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut cur = self;
        let mut pending_lens: Vec<usize> = Vec::new();
        loop {
            std::mem::discriminant(cur).hash(state);
            match cur {
                Self::Ptr(inner) => cur = inner,
                Self::Array(inner, n) => {
                    pending_lens.push(*n);
                    cur = inner;
                }
                Self::UInt(w) | Self::Int(w) | Self::Float(w) => {
                    w.hash(state);
                    break;
                }
                Self::Bool | Self::Void | Self::Unknown => break,
                Self::Struct(n, fs) => {
                    n.hash(state);
                    fs.hash(state);
                    break;
                }
                Self::Func(p, r) => {
                    p.hash(state);
                    r.hash(state);
                    break;
                }
            }
        }
        // Innermost array length first: the inner element's stream completes
        // before the enclosing array's length, exactly like the derived impl.
        while let Some(n) = pending_lens.pop() {
            n.hash(state);
        }
    }
}

/// Manual iterative `Debug`: writes the `Ptr`/`Array` spine as prefixes/
/// suffixes in a loop. Output matches the derived (non-alternate) format.
impl fmt::Debug for BaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut spine = Vec::new();
        let cur = Self::peel_spine(self, &mut spine);
        for w in &spine {
            match w {
                BaseWrap::Ptr => f.write_str("Ptr(")?,
                BaseWrap::Array(_) => f.write_str("Array(")?,
            }
        }
        match cur {
            Self::UInt(w) => write!(f, "UInt({w})")?,
            Self::Int(w) => write!(f, "Int({w})")?,
            Self::Float(w) => write!(f, "Float({w})")?,
            Self::Bool => f.write_str("Bool")?,
            Self::Struct(n, fs) => f.debug_tuple("Struct").field(n).field(fs).finish()?,
            Self::Func(p, r) => f.debug_tuple("Func").field(p).field(r).finish()?,
            Self::Void => f.write_str("Void")?,
            Self::Unknown => f.write_str("Unknown")?,
            Self::Ptr(_) | Self::Array(..) => unreachable!("spine fully peeled above"),
        }
        while let Some(w) = spine.pop() {
            match w {
                BaseWrap::Ptr => f.write_str(")")?,
                BaseWrap::Array(n) => write!(f, ", {n})")?,
            }
        }
        Ok(())
    }
}

impl fmt::Display for BaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Iterative spine walk: the naive `write!(f, "*{t}")` recursion
        // overflows the stack on very deep `Ptr`/`Array` chains.
        let mut spine = Vec::new();
        let cur = Self::peel_spine(self, &mut spine);
        for w in &spine {
            match w {
                BaseWrap::Ptr => f.write_str("*")?,
                BaseWrap::Array(_) => f.write_str("[")?,
            }
        }
        match cur {
            Self::UInt(w) => write!(f, "u{w}")?,
            Self::Int(w) => write!(f, "i{w}")?,
            Self::Float(w) => write!(f, "f{w}")?,
            Self::Bool => f.write_str("bool")?,
            Self::Struct(n, _) => write!(f, "struct {n}")?,
            Self::Func(p, r) => write!(
                f,
                "fn({}) -> {r}",
                p.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?,
            Self::Void => f.write_str("void")?,
            Self::Unknown => f.write_str("?")?,
            Self::Ptr(_) | Self::Array(..) => unreachable!("spine fully peeled above"),
        }
        while let Some(w) = spine.pop() {
            match w {
                BaseWrap::Ptr => {}
                BaseWrap::Array(n) => write!(f, "; {n}]")?,
            }
        }
        Ok(())
    }
}

impl BaseType {
    #[must_use] 
    pub fn ptr_to(inner: Self) -> Self {
        Self::Ptr(Box::new(inner))
    }

    #[must_use] 
    pub fn array_of(elem: Self, len: usize) -> Self {
        Self::Array(Box::new(elem), len)
    }

    #[must_use] 
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::UInt(_) | Self::Int(_) | Self::Float(_))
    }

    #[must_use] 
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr(_))
    }

    #[must_use] 
    pub const fn bit_width(&self) -> Option<u8> {
        match self {
            Self::UInt(w) | Self::Int(w) | Self::Float(w) => Some(*w),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeVariable
// ─────────────────────────────────────────────────────────────────────────────

/// A type variable used in unification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeVariable(pub u32);

impl TypeVariable {
    #[must_use] 
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for TypeVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "α{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type term (monotype)
// ─────────────────────────────────────────────────────────────────────────────

/// A monomorphic type term (ground type or type variable).
///
/// `PartialEq`/`Hash`/`Debug` (like `Clone`/`Drop` below) are hand-written
/// iterative implementations that walk the `Ptr` spine in a loop: the derived
/// versions recurse once per layer and overflow the stack on very deep
/// `Ptr(Ptr(...))` chains. Semantics are identical to the derived impls.
pub enum TypeTerm {
    Var(TypeVariable),
    Base(BaseType),
    Ptr(Box<Self>),
    Func(Vec<Self>, Box<Self>),
}

/// Manual `Clone`: the derived impl recurses once per `Ptr` layer and blows
/// the stack on very deep `Ptr(Ptr(...))` chains. The `Ptr` spine is cloned
/// iteratively; only `Func` (whose nesting is bounded in practice) recurses.
impl Clone for TypeTerm {
    fn clone(&self) -> Self {
        let mut depth = 0usize;
        let mut cur = self;
        while let Self::Ptr(inner) = cur {
            depth += 1;
            cur = inner;
        }
        let mut out = match cur {
            Self::Var(v) => Self::Var(v.clone()),
            Self::Base(b) => Self::Base(b.clone()),
            Self::Func(params, ret) => Self::Func(params.clone(), ret.clone()),
            Self::Ptr(_) => unreachable!("Ptr spine fully peeled above"),
        };
        for _ in 0..depth {
            out = Self::Ptr(Box::new(out));
        }
        out
    }
}

/// Manual iterative `Drop`: the compiler-generated drop glue recurses once
/// per `Box` layer, overflowing the stack when a very deep `Ptr(Ptr(...))`
/// term is dropped. Children are detached onto an explicit worklist so drop
/// depth is O(1) regardless of term depth.
impl Drop for TypeTerm {
    fn drop(&mut self) {
        // Fast path: leaf terms need no worklist.
        if matches!(self, Self::Var(_) | Self::Base(_)) {
            return;
        }
        const LEAF: TypeTerm = TypeTerm::Var(TypeVariable(0));
        let mut stack: Vec<Self> = Vec::new();
        match self {
            Self::Ptr(inner) => stack.push(std::mem::replace(&mut **inner, LEAF)),
            Self::Func(params, ret) => {
                stack.extend(params.drain(..));
                stack.push(std::mem::replace(&mut **ret, LEAF));
            }
            Self::Var(_) | Self::Base(_) => {}
        }
        while let Some(mut t) = stack.pop() {
            match &mut t {
                Self::Ptr(inner) => stack.push(std::mem::replace(&mut **inner, LEAF)),
                Self::Func(params, ret) => {
                    stack.extend(params.drain(..));
                    stack.push(std::mem::replace(&mut **ret, LEAF));
                }
                Self::Var(_) | Self::Base(_) => {}
            }
            // `t` drops here with all children already detached — O(1) depth.
        }
    }
}

/// Manual iterative `PartialEq`: walks both `Ptr` spines in lockstep.
impl PartialEq for TypeTerm {
    fn eq(&self, other: &Self) -> bool {
        let (mut a, mut b) = (self, other);
        loop {
            match (a, b) {
                (Self::Ptr(x), Self::Ptr(y)) => {
                    a = x;
                    b = y;
                }
                (Self::Var(x), Self::Var(y)) => return x == y,
                (Self::Base(x), Self::Base(y)) => return x == y,
                (Self::Func(p1, r1), Self::Func(p2, r2)) => return p1 == p2 && r1 == r2,
                _ => return false,
            }
        }
    }
}

impl Eq for TypeTerm {}

/// Manual iterative `Hash`: emits the exact same byte stream as the derived
/// impl (discriminant then fields), but walks the `Ptr` spine in a loop.
impl Hash for TypeTerm {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut cur = self;
        loop {
            std::mem::discriminant(cur).hash(state);
            match cur {
                Self::Ptr(inner) => cur = inner,
                Self::Var(v) => {
                    v.hash(state);
                    return;
                }
                Self::Base(b) => {
                    b.hash(state);
                    return;
                }
                Self::Func(p, r) => {
                    p.hash(state);
                    r.hash(state);
                    return;
                }
            }
        }
    }
}

/// Manual iterative `Debug`: writes the `Ptr` spine as `Ptr(` prefixes and
/// `)` suffixes in a loop. Output matches the derived (non-alternate) format.
impl fmt::Debug for TypeTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut depth = 0usize;
        let mut cur = self;
        while let Self::Ptr(inner) = cur {
            depth += 1;
            cur = inner;
        }
        for _ in 0..depth {
            f.write_str("Ptr(")?;
        }
        match cur {
            Self::Var(v) => f.debug_tuple("Var").field(v).finish()?,
            Self::Base(b) => f.debug_tuple("Base").field(b).finish()?,
            Self::Func(p, r) => f.debug_tuple("Func").field(p).field(r).finish()?,
            Self::Ptr(_) => unreachable!("Ptr spine fully peeled above"),
        }
        for _ in 0..depth {
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl fmt::Display for TypeTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Iterative Ptr-spine walk: `write!(f, "*{t}")` recursion overflows
        // the stack on very deep Ptr(Ptr(...)) chains.
        let mut cur = self;
        while let Self::Ptr(inner) = cur {
            f.write_str("*")?;
            cur = inner;
        }
        match cur {
            Self::Var(v) => write!(f, "{v}"),
            Self::Base(b) => write!(f, "{b}"),
            Self::Ptr(_) => unreachable!("Ptr spine fully peeled above"),
            Self::Func(p, r) => write!(
                f,
                "fn({}) -> {r}",
                p.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl TypeTerm {
    #[must_use] 
    pub fn free_vars(&self) -> HashSet<TypeVariable> {
        // Iterative worklist traversal: the naive recursion overflows the
        // stack on very deep Ptr(Ptr(...)) nesting.
        let mut fv = HashSet::new();
        let mut work: Vec<&Self> = vec![self];
        while let Some(t) = work.pop() {
            match t {
                Self::Var(v) => {
                    fv.insert(v.clone());
                }
                Self::Base(_) => {}
                Self::Ptr(inner) => work.push(inner),
                Self::Func(params, ret) => {
                    work.extend(params.iter());
                    work.push(ret);
                }
            }
        }
        fv
    }

    #[must_use]
    pub fn apply(&self, subst: &Substitution) -> Self {
        // Peel the Ptr spine iteratively (deep Ptr nesting must not recurse),
        // apply to the core, then rewrap. Func nesting is bounded in practice
        // and still recurses one frame per Func layer.
        let mut depth = 0usize;
        let mut cur = self;
        while let Self::Ptr(inner) = cur {
            depth += 1;
            cur = inner;
        }
        let mut out = match cur {
            Self::Var(v) => subst.get(v).cloned().unwrap_or_else(|| cur.clone()),
            Self::Base(_) => cur.clone(),
            Self::Func(params, ret) => Self::Func(
                params.iter().map(|p| p.apply(subst)).collect(),
                Box::new(ret.apply(subst)),
            ),
            Self::Ptr(_) => unreachable!("Ptr spine fully peeled above"),
        };
        for _ in 0..depth {
            out = Self::Ptr(Box::new(out));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Substitution
// ─────────────────────────────────────────────────────────────────────────────

/// A finite mapping from type variables to type terms.
#[derive(Debug, Clone, Default)]
pub struct Substitution {
    map: HashMap<TypeVariable, TypeTerm>,
}

impl Substitution {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn singleton(v: TypeVariable, t: TypeTerm) -> Self {
        let mut s = Self::new();
        s.map.insert(v, t);
        s
    }

    #[must_use] 
    pub fn get(&self, v: &TypeVariable) -> Option<&TypeTerm> {
        self.map.get(v)
    }

    pub fn insert(&mut self, v: TypeVariable, t: TypeTerm) {
        self.map.insert(v, t);
    }

    /// Compose `self` after `other`: `(self ∘ other)[v] = self(other(v))`.
    #[must_use] 
    pub fn compose(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for (v, t) in &other.map {
            result.insert(v.clone(), t.apply(self));
        }
        for (v, t) in &self.map {
            result.map.entry(v.clone()).or_insert_with(|| t.clone());
        }
        result
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnificationError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors during type unification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnificationError {
    /// Type mismatch: the two types cannot be unified.
    Mismatch(TypeTerm, TypeTerm),
    /// Occurs check failure: the variable appears in the type.
    OccursCheck(TypeVariable, TypeTerm),
    /// Arity mismatch in function types.
    ArityMismatch(usize, usize),
}

impl fmt::Display for UnificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch(a, b) => write!(f, "type mismatch: {a} vs {b}"),
            Self::OccursCheck(v, t) => write!(f, "occurs check: {v} occurs in {t}"),
            Self::ArityMismatch(a, b) => write!(f, "arity mismatch: {a} vs {b}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unification
// ─────────────────────────────────────────────────────────────────────────────

/// Hindley-Milner style Robinson unification.
pub struct Unification;

impl Unification {
    /// Unify two [`TypeTerm`]s, producing a most-general unifier.
    ///
    /// # Errors
    ///
    /// Returns a [`UnificationError`] if the two terms cannot be unified
    /// (base-type mismatch, arity mismatch, or occurs-check failure).
    pub fn unify(t1: &TypeTerm, t2: &TypeTerm) -> Result<Substitution, UnificationError> {
        match (t1, t2) {
            (TypeTerm::Base(a), TypeTerm::Base(b)) if a == b => Ok(Substitution::new()),
            (TypeTerm::Base(a), TypeTerm::Base(b)) => Err(UnificationError::Mismatch(
                TypeTerm::Base(a.clone()),
                TypeTerm::Base(b.clone()),
            )),
            (TypeTerm::Var(v), t) | (t, TypeTerm::Var(v)) => {
                if let TypeTerm::Var(v2) = t && v == v2 {
                    return Ok(Substitution::new());
                }
                if t.free_vars().contains(v) {
                    return Err(UnificationError::OccursCheck(v.clone(), t.clone()));
                }
                Ok(Substitution::singleton(v.clone(), t.clone()))
            }
            (TypeTerm::Ptr(_), TypeTerm::Ptr(_)) => {
                // Descend matched Ptr spines iteratively: recursing once per
                // layer overflows the stack on very deep Ptr(Ptr(...)) terms.
                let (mut a, mut b) = (t1, t2);
                while let (TypeTerm::Ptr(ia), TypeTerm::Ptr(ib)) = (a, b) {
                    a = ia;
                    b = ib;
                }
                Self::unify(a, b)
            }
            (TypeTerm::Func(p1, r1), TypeTerm::Func(p2, r2)) => {
                if p1.len() != p2.len() {
                    return Err(UnificationError::ArityMismatch(p1.len(), p2.len()));
                }
                let mut subst = Self::unify(r1, r2)?;
                for (a, b) in p1.iter().zip(p2.iter()) {
                    let s = Self::unify(&a.apply(&subst), &b.apply(&subst))?;
                    subst = s.compose(&subst);
                }
                Ok(subst)
            }
            _ => Err(UnificationError::Mismatch(t1.clone(), t2.clone())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEnv
// ─────────────────────────────────────────────────────────────────────────────

/// A type environment mapping names to [`TypeTerm`]s.
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    bindings: HashMap<String, TypeTerm>,
}

impl TypeEnv {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, t: TypeTerm) {
        self.bindings.insert(name.into(), t);
    }

    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&TypeTerm> {
        self.bindings.get(name)
    }

    #[must_use] 
    pub fn contains(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }

    #[must_use] 
    pub fn apply(&self, subst: &Substitution) -> Self {
        Self {
            bindings: self
                .bindings
                .iter()
                .map(|(k, v)| (k.clone(), v.apply(subst)))
                .collect(),
        }
    }

    /// Free type variables across all bindings.
    #[must_use] 
    pub fn free_vars(&self) -> HashSet<TypeVariable> {
        self.bindings.values().flat_map(TypeTerm::free_vars).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GeneralizedType (type scheme)
// ─────────────────────────────────────────────────────────────────────────────

/// A quantified type scheme `∀ α₁...αₙ. T`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralizedType {
    pub quantified: Vec<TypeVariable>,
    pub body: TypeTerm,
}

impl GeneralizedType {
    /// Monomorphic type (no quantification).
    #[must_use] 
    pub const fn mono(t: TypeTerm) -> Self {
        Self {
            quantified: Vec::new(),
            body: t,
        }
    }

    /// Generalize `t` over all free variables not in `env`.
    #[must_use] 
    pub fn generalize(env: &TypeEnv, t: TypeTerm) -> Self {
        let env_fv = env.free_vars();
        let mut free: Vec<TypeVariable> = t.free_vars().difference(&env_fv).cloned().collect();
        // Sort so the quantifier order (which drives fresh-variable numbering
        // in `instantiate` and scheme equality) does not depend on HashSet
        // iteration order.
        free.sort();
        Self {
            quantified: free,
            body: t,
        }
    }

    /// Instantiate a fresh copy of the scheme with new type variables.
    pub fn instantiate(&self, counter: &mut u32) -> TypeTerm {
        let mut subst = Substitution::new();
        for v in &self.quantified {
            let fresh = TypeVariable::new(*counter);
            *counter += 1;
            subst.insert(v.clone(), TypeTerm::Var(fresh));
        }
        self.body.apply(&subst)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InferenceRule
// ─────────────────────────────────────────────────────────────────────────────

/// A type-inference rule that produces a type constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceRule {
    // ── Arithmetic operations ─────────────────────────────────────────────────
    /// `a + b → typeof(a) = typeof(b) = result`.
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    /// Bitwise operations preserve integer type.
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    // ── Comparison ────────────────────────────────────────────────────────────
    /// Comparison: both operands same type, result is bool.
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    // ── Memory access ─────────────────────────────────────────────────────────
    /// Load: `result = *ptr` → ptr is pointer to result type.
    Load,
    /// Store: `*ptr = val` → ptr is pointer to val type.
    Store,
    /// Address-of: `ptr = &var` → ptr is pointer to var type.
    AddressOf,
    /// Field access on a struct pointer.
    FieldAccess {
        field: String,
    },
    /// Array element access.
    ArrayIndex,
    // ── Control flow ──────────────────────────────────────────────────────────
    /// Conditional branch: condition must be bool.
    CondBranch,
    /// Phi: all sources must have the same type.
    Phi,
    // ── Function calls ────────────────────────────────────────────────────────
    /// Call: argument types must match function signature.
    Call,
    /// Return: return type must match function return type.
    Ret,
    // ── Casts ─────────────────────────────────────────────────────────────────
    ZeroExtend {
        from: u8,
        to: u8,
    },
    SignExtend {
        from: u8,
        to: u8,
    },
    Truncate {
        from: u8,
        to: u8,
    },
    IntToPtr,
    PtrToInt,
    Bitcast,
    // ── Constant propagation ──────────────────────────────────────────────────
    /// A constant integer literal provides type information.
    ConstInt {
        width: u8,
        signed: bool,
    },
    ConstFloat {
        width: u8,
    },
    ConstNull,
    ConstBool,
    // ── ABI / calling convention ──────────────────────────────────────────────
    ArgRegister {
        register: String,
    },
    ReturnRegister {
        register: String,
    },
    StackArgOffset {
        offset: i64,
    },
    CalleeSaved {
        register: String,
    },
    // ── Object-oriented patterns ──────────────────────────────────────────────
    /// `this` pointer dereference for C++ method calls.
    ThisPointer,
    VirtualDispatch,
    // ── String operations ─────────────────────────────────────────────────────
    StringLiteral,
    StringLength,
    StringCopy,
    StringCompare,
    // ── Size and alignment ────────────────────────────────────────────────────
    SizeOf {
        bytes: usize,
    },
    AlignOf {
        bytes: usize,
    },
    // ── Pointer arithmetic ────────────────────────────────────────────────────
    PtrAdd,
    PtrSub,
    PtrDiff,
    // ── Derived / custom ──────────────────────────────────────────────────────
    Custom(String),
}

impl InferenceRule {
    /// Apply this rule to produce a type constraint on `TypeTerm`s.
    #[must_use] 
    pub fn apply(&self, operands: &[TypeTerm], result: &TypeTerm) -> Option<(TypeTerm, TypeTerm)> {
        match self {
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod => {
                operands.first().map(|op| (op.clone(), result.clone()))
            }
            Self::Load => operands
                .first()
                .map(|ptr| (ptr.clone(), TypeTerm::Ptr(Box::new(result.clone())))),
            Self::CondBranch => operands
                .first()
                .map(|cond| (cond.clone(), TypeTerm::Base(BaseType::Bool))),
            Self::ConstInt { width, signed } => {
                let base = if *signed {
                    BaseType::Int(*width)
                } else {
                    BaseType::UInt(*width)
                };
                Some((result.clone(), TypeTerm::Base(base)))
            }
            Self::ConstNull => Some((
                result.clone(),
                TypeTerm::Ptr(Box::new(TypeTerm::Base(BaseType::Void))),
            )),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// A unification constraint between two type terms.
#[derive(Debug, Clone)]
pub struct TypeConstraint {
    pub lhs: TypeTerm,
    pub rhs: TypeTerm,
    pub origin: InferenceRule,
}

impl TypeConstraint {
    #[must_use] 
    pub const fn new(lhs: TypeTerm, rhs: TypeTerm, origin: InferenceRule) -> Self {
        Self { lhs, rhs, origin }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeInferenceEngine — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Type-inference result.
#[derive(Debug, Clone, Default)]
pub struct InferenceResult {
    pub substitution: Substitution,
    pub env: TypeEnv,
    pub errors: Vec<UnificationError>,
    pub constraints_solved: usize,
}

/// Top-level type inference engine.
pub struct TypeInferenceEngine {
    var_counter: u32,
    constraints: Vec<TypeConstraint>,
    env: TypeEnv,
}

impl TypeInferenceEngine {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            var_counter: 0,
            constraints: Vec::new(),
            env: TypeEnv::new(),
        }
    }

    /// Allocate a fresh type variable.
    pub const fn fresh_var(&mut self) -> TypeVariable {
        let v = TypeVariable::new(self.var_counter);
        self.var_counter += 1;
        v
    }

    /// Allocate a fresh type term (Var).
    pub const fn fresh(&mut self) -> TypeTerm {
        TypeTerm::Var(self.fresh_var())
    }

    /// Add a constraint `lhs = rhs`.
    pub fn constrain(&mut self, lhs: TypeTerm, rhs: TypeTerm, rule: InferenceRule) {
        self.constraints.push(TypeConstraint::new(lhs, rhs, rule));
    }

    /// Bind a name to a type in the environment.
    pub fn bind(&mut self, name: impl Into<String>, t: TypeTerm) {
        self.env.insert(name, t);
    }

    /// Apply a rule given operands and result variable.
    pub fn apply_rule(&mut self, rule: InferenceRule, operands: &[TypeTerm], result: &TypeTerm) {
        if let Some((lhs, rhs)) = rule.apply(operands, result) {
            self.constrain(lhs, rhs, rule);
        }
    }

    /// Solve all accumulated constraints via Robinson unification.
    #[must_use] 
    pub fn solve(self) -> InferenceResult {
        let Self {
            constraints, env, ..
        } = self;
        let mut subst = Substitution::new();
        let mut errors: Vec<UnificationError> = Vec::new();
        let mut solved = 0;

        for c in &constraints {
            let lhs = c.lhs.apply(&subst);
            let rhs = c.rhs.apply(&subst);
            match Unification::unify(&lhs, &rhs) {
                Ok(s) => {
                    subst = s.compose(&subst);
                    solved += 1;
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        let final_env = env.apply(&subst);

        InferenceResult {
            substitution: subst,
            env: final_env,
            errors,
            constraints_solved: solved,
        }
    }
}

impl Default for TypeInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(id: u32) -> TypeTerm {
        TypeTerm::Var(TypeVariable::new(id))
    }

    fn u64_ty() -> TypeTerm {
        TypeTerm::Base(BaseType::UInt(64))
    }
    fn i32_ty() -> TypeTerm {
        TypeTerm::Base(BaseType::Int(32))
    }
    fn bool_ty() -> TypeTerm {
        TypeTerm::Base(BaseType::Bool)
    }
    fn void_ty() -> TypeTerm {
        TypeTerm::Base(BaseType::Void)
    }

    // 1. TypeVariable display.
    #[test]
    fn test_type_var_display() {
        assert_eq!(TypeVariable::new(5).to_string(), "α5");
    }

    // 2. BaseType display.
    #[test]
    fn test_base_type_display() {
        assert_eq!(BaseType::UInt(64).to_string(), "u64");
        assert_eq!(BaseType::Int(32).to_string(), "i32");
        assert_eq!(BaseType::Bool.to_string(), "bool");
        assert_eq!(BaseType::Void.to_string(), "void");
    }

    // 3. BaseType::is_numeric.
    #[test]
    fn test_base_type_is_numeric() {
        assert!(BaseType::UInt(32).is_numeric());
        assert!(BaseType::Float(64).is_numeric());
        assert!(!BaseType::Bool.is_numeric());
    }

    // 4. BaseType::bit_width.
    #[test]
    fn test_bit_width() {
        assert_eq!(BaseType::Int(16).bit_width(), Some(16));
        assert_eq!(BaseType::Bool.bit_width(), None);
    }

    // 5. TypeTerm free_vars.
    #[test]
    fn test_free_vars() {
        let t = TypeTerm::Func(vec![var(0), var(1)], Box::new(var(2)));
        let fv = t.free_vars();
        assert_eq!(fv.len(), 3);
    }

    // 6. TypeTerm free_vars ground type → empty.
    #[test]
    fn test_free_vars_ground() {
        assert!(u64_ty().free_vars().is_empty());
    }

    // 7. Substitution singleton.
    #[test]
    fn test_substitution_singleton() {
        let s = Substitution::singleton(TypeVariable::new(0), u64_ty());
        assert_eq!(s.get(&TypeVariable::new(0)), Some(&u64_ty()));
        assert_eq!(s.len(), 1);
    }

    // 8. TypeTerm apply substitution.
    #[test]
    fn test_apply_subst() {
        let s = Substitution::singleton(TypeVariable::new(0), u64_ty());
        let t = var(0);
        assert_eq!(t.apply(&s), u64_ty());
    }

    // 9. Unification: same var → empty subst.
    #[test]
    fn test_unify_same_var() {
        let result = Unification::unify(&var(0), &var(0));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // 10. Unification: var = ground type.
    #[test]
    fn test_unify_var_ground() {
        let s = Unification::unify(&var(0), &u64_ty()).unwrap();
        assert_eq!(s.get(&TypeVariable::new(0)), Some(&u64_ty()));
    }

    // 11. Unification: ground = ground same.
    #[test]
    fn test_unify_ground_same() {
        let s = Unification::unify(&u64_ty(), &u64_ty()).unwrap();
        assert!(s.is_empty());
    }

    // 12. Unification: ground mismatch.
    #[test]
    fn test_unify_ground_mismatch() {
        let r = Unification::unify(&u64_ty(), &i32_ty());
        assert!(matches!(r, Err(UnificationError::Mismatch(_, _))));
    }

    // 13. Unification: occurs check.
    #[test]
    fn test_occurs_check() {
        // α0 = *α0 (infinite type)
        let t = TypeTerm::Ptr(Box::new(var(0)));
        let r = Unification::unify(&var(0), &t);
        assert!(matches!(r, Err(UnificationError::OccursCheck(_, _))));
    }

    // 14. Unification: pointer types.
    #[test]
    fn test_unify_ptr() {
        let ptr_u64 = TypeTerm::Ptr(Box::new(u64_ty()));
        let ptr_var = TypeTerm::Ptr(Box::new(var(0)));
        let s = Unification::unify(&ptr_u64, &ptr_var).unwrap();
        assert_eq!(s.get(&TypeVariable::new(0)), Some(&u64_ty()));
    }

    // 15. Unification: function types.
    #[test]
    fn test_unify_func() {
        let f1 = TypeTerm::Func(vec![var(0)], Box::new(u64_ty()));
        let f2 = TypeTerm::Func(vec![i32_ty()], Box::new(var(1)));
        let s = Unification::unify(&f1, &f2).unwrap();
        assert_eq!(s.get(&TypeVariable::new(0)), Some(&i32_ty()));
        assert_eq!(s.get(&TypeVariable::new(1)), Some(&u64_ty()));
    }

    // 16. Unification: arity mismatch.
    #[test]
    fn test_unify_arity_mismatch() {
        let f1 = TypeTerm::Func(vec![var(0)], Box::new(u64_ty()));
        let f2 = TypeTerm::Func(vec![var(0), var(1)], Box::new(u64_ty()));
        assert!(matches!(
            Unification::unify(&f1, &f2),
            Err(UnificationError::ArityMismatch(1, 2))
        ));
    }

    // 17. Substitution compose.
    #[test]
    fn test_substitution_compose() {
        // s1: α0 → i32, s2: α1 → α0
        let s1 = Substitution::singleton(TypeVariable::new(0), i32_ty());
        let s2 = Substitution::singleton(TypeVariable::new(1), var(0));
        let composed = s1.compose(&s2);
        // α1 should map to i32 via α0.
        assert_eq!(
            composed
                .get(&TypeVariable::new(1))
                .map(|t| t.apply(&composed)),
            Some(i32_ty())
        );
    }

    // 18. TypeEnv insert / get.
    #[test]
    fn test_type_env() {
        let mut env = TypeEnv::new();
        env.insert("x", u64_ty());
        assert_eq!(env.get("x"), Some(&u64_ty()));
        assert!(env.contains("x"));
        assert!(!env.contains("y"));
    }

    // 19. TypeEnv free_vars.
    #[test]
    fn test_type_env_free_vars() {
        let mut env = TypeEnv::new();
        env.insert("x", var(5));
        env.insert("y", var(10));
        let fv = env.free_vars();
        assert!(fv.contains(&TypeVariable::new(5)));
        assert!(fv.contains(&TypeVariable::new(10)));
    }

    // 20. GeneralizedType::mono.
    #[test]
    fn test_generalized_type_mono() {
        let gt = GeneralizedType::mono(u64_ty());
        assert!(gt.quantified.is_empty());
        assert_eq!(gt.body, u64_ty());
    }

    // 21. GeneralizedType::generalize.
    #[test]
    fn test_generalize() {
        let env = TypeEnv::new();
        let t = TypeTerm::Func(vec![var(0)], Box::new(var(1)));
        let gt = GeneralizedType::generalize(&env, t);
        assert_eq!(gt.quantified.len(), 2);
    }

    // 22. GeneralizedType::instantiate.
    #[test]
    fn test_instantiate() {
        let gt = GeneralizedType {
            quantified: vec![TypeVariable::new(0)],
            body: var(0),
        };
        let mut ctr = 10;
        let inst = gt.instantiate(&mut ctr);
        // Should produce a fresh variable (α10).
        assert_eq!(inst, TypeTerm::Var(TypeVariable::new(10)));
        assert_eq!(ctr, 11);
    }

    // 23. TypeInferenceEngine fresh_var.
    #[test]
    fn test_engine_fresh_var() {
        let mut engine = TypeInferenceEngine::new();
        let v0 = engine.fresh_var();
        let v1 = engine.fresh_var();
        assert_ne!(v0, v1);
    }

    // 24. TypeInferenceEngine solve simple constraint.
    #[test]
    fn test_engine_solve_simple() {
        let mut engine = TypeInferenceEngine::new();
        let t0 = engine.fresh();
        engine.constrain(
            t0,
            u64_ty(),
            InferenceRule::ConstInt {
                width: 64,
                signed: false,
            },
        );
        let result = engine.solve();
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.constraints_solved, 1);
    }

    // 25. TypeInferenceEngine solve conflict.
    #[test]
    fn test_engine_solve_conflict() {
        let mut engine = TypeInferenceEngine::new();
        engine.constrain(u64_ty(), i32_ty(), InferenceRule::Add);
        let result = engine.solve();
        assert!(!result.errors.is_empty());
    }

    // 26. TypeInferenceEngine bind + solve.
    #[test]
    fn test_engine_bind_and_solve() {
        let mut engine = TypeInferenceEngine::new();
        let t = engine.fresh();
        engine.bind("x", t.clone());
        engine.constrain(
            t,
            u64_ty(),
            InferenceRule::ConstInt {
                width: 64,
                signed: false,
            },
        );
        let result = engine.solve();
        let t_x = result.env.get("x").unwrap();
        assert_eq!(*t_x, u64_ty());
    }

    // 27. InferenceRule::ConstNull produces pointer to void.
    #[test]
    fn test_rule_const_null() {
        let result = TypeTerm::Var(TypeVariable::new(0));
        let (lhs, rhs) = InferenceRule::ConstNull.apply(&[], &result).unwrap();
        assert_eq!(lhs, result);
        assert_eq!(rhs, TypeTerm::Ptr(Box::new(void_ty())));
    }

    // 28. InferenceRule::CondBranch produces bool constraint.
    #[test]
    fn test_rule_cond_branch() {
        let cond = var(0);
        let result = var(1);
        let (lhs, rhs) = InferenceRule::CondBranch
            .apply(std::slice::from_ref(&cond), &result)
            .unwrap();
        assert_eq!(lhs, cond);
        assert_eq!(rhs, bool_ty());
    }

    // 29. InferenceRule::Load produces ptr constraint.
    #[test]
    fn test_rule_load() {
        let ptr = var(0);
        let result = u64_ty();
        let (lhs, rhs) = InferenceRule::Load.apply(std::slice::from_ref(&ptr), &result).unwrap();
        assert_eq!(lhs, ptr);
        assert_eq!(rhs, TypeTerm::Ptr(Box::new(u64_ty())));
    }

    // 30. InferenceRule::Add propagates type.
    #[test]
    fn test_rule_add() {
        let op = u64_ty();
        let result = var(0);
        let (lhs, rhs) = InferenceRule::Add.apply(std::slice::from_ref(&op), &result).unwrap();
        assert_eq!(lhs, op);
        assert_eq!(rhs, result);
    }

    // 31. BaseType::is_pointer.
    #[test]
    fn test_base_type_is_pointer() {
        assert!(BaseType::Ptr(Box::new(BaseType::UInt(64))).is_pointer());
        assert!(!BaseType::UInt(64).is_pointer());
    }

    // 32. TypeTerm::apply nested.
    #[test]
    fn test_apply_nested() {
        let mut s = Substitution::new();
        s.insert(TypeVariable::new(0), u64_ty());
        let t = TypeTerm::Ptr(Box::new(TypeTerm::Func(vec![var(0)], Box::new(var(1)))));
        let applied = t.apply(&s);
        if let TypeTerm::Ptr(ref inner) = applied {
            if let TypeTerm::Func(ref params, _) = **inner {
                assert_eq!(params[0], u64_ty());
            } else {
                panic!("expected Func");
            }
        } else {
            panic!("expected Ptr");
        }
    }

    // 33. UnificationError display.
    #[test]
    fn test_error_display() {
        let e = UnificationError::Mismatch(u64_ty(), i32_ty());
        let s = e.to_string();
        assert!(s.contains("mismatch"));
    }

    // 34. InferenceRule variants compile.
    #[test]
    fn test_rule_variants() {
        let rules = vec![
            InferenceRule::Add,
            InferenceRule::Sub,
            InferenceRule::Mul,
            InferenceRule::Load,
            InferenceRule::Store,
            InferenceRule::CondBranch,
            InferenceRule::ZeroExtend { from: 8, to: 64 },
            InferenceRule::ConstInt {
                width: 32,
                signed: true,
            },
            InferenceRule::ThisPointer,
            InferenceRule::VirtualDispatch,
            InferenceRule::Custom("custom_rule".into()),
        ];
        assert_eq!(rules.len(), 11);
    }

    // 35. Engine: multiple constraints solved in order.
    #[test]
    fn test_engine_multiple_constraints() {
        let mut engine = TypeInferenceEngine::new();
        let a = engine.fresh();
        let b = engine.fresh();
        engine.constrain(
            a.clone(),
            u64_ty(),
            InferenceRule::ConstInt {
                width: 64,
                signed: false,
            },
        );
        engine.constrain(b, a, InferenceRule::Add);
        let result = engine.solve();
        assert_eq!(result.errors.len(), 0);
        assert!(result.constraints_solved >= 2);
    }

    // 36. GeneralizedType instantiate multiple vars.
    #[test]
    fn test_instantiate_multiple() {
        let gt = GeneralizedType {
            quantified: vec![TypeVariable::new(0), TypeVariable::new(1)],
            body: TypeTerm::Func(vec![var(0)], Box::new(var(1))),
        };
        let mut ctr = 20;
        let inst = gt.instantiate(&mut ctr);
        assert_eq!(ctr, 22);
        // Body should have fresh vars 20 and 21.
        let fv = inst.free_vars();
        assert!(fv.contains(&TypeVariable::new(20)));
        assert!(fv.contains(&TypeVariable::new(21)));
    }

    /// Regression: `GeneralizedType::generalize` collected quantified vars
    /// from a `HashSet` in randomized order, so the quantifier list (which
    /// drives fresh-variable numbering in `instantiate` and scheme equality)
    /// was nondeterministic. It must now be sorted ascending.
    #[test]
    fn generalize_quantifier_order_is_deterministic() {
        let env = TypeEnv::new();
        // A function type over many free vars, listed out of order.
        let t = TypeTerm::Func(
            vec![var(7), var(3), var(11), var(1), var(9), var(5)],
            Box::new(var(2)),
        );
        let schemes: Vec<GeneralizedType> = (0..20)
            .map(|_| GeneralizedType::generalize(&env, t.clone()))
            .collect();
        let expected: Vec<TypeVariable> =
            [1, 2, 3, 5, 7, 9, 11].iter().map(|&i| TypeVariable::new(i)).collect();
        for s in &schemes {
            assert_eq!(s.quantified, expected, "quantifiers must be sorted");
            assert_eq!(s, &schemes[0], "schemes must compare equal across runs");
        }
        // Instantiation numbering must therefore also be deterministic.
        let mut c1 = 100;
        let mut c2 = 100;
        assert_eq!(
            schemes[0].instantiate(&mut c1),
            schemes[1].instantiate(&mut c2)
        );
    }

    /// Regression: ~100k-deep `Ptr(Ptr(...))` nesting must not overflow the
    /// stack in `free_vars`, `apply`, `clone`, `unify`, or (crucially) the
    /// drop glue — all of these used to recurse once per layer.
    #[test]
    fn deep_ptr_nesting_does_not_overflow_stack() {
        const DEPTH: usize = 100_000;
        let deep = |core: TypeTerm| {
            let mut t = core;
            for _ in 0..DEPTH {
                t = TypeTerm::Ptr(Box::new(t));
            }
            t
        };

        // free_vars: iterative traversal.
        let t = deep(TypeTerm::Var(TypeVariable::new(7)));
        let fv = t.free_vars();
        assert_eq!(fv.len(), 1);
        assert!(fv.contains(&TypeVariable::new(7)));

        // clone + apply: iterative spine peel/rewrap. The substitution maps
        // the core variable, so the result must keep the full depth.
        let subst = Substitution::singleton(
            TypeVariable::new(7),
            TypeTerm::Base(BaseType::Int(32)),
        );
        let applied = t.apply(&subst);
        let cloned = applied.clone();

        // unify: matched Ptr spines are descended iteratively.
        let s = Unification::unify(&applied, &cloned).expect("identical deep terms unify");
        assert!(s.is_empty());

        // Verify depth survived apply/clone (iteratively, of course).
        let mut d = 0usize;
        let mut cur = &cloned;
        while let TypeTerm::Ptr(inner) = cur {
            d += 1;
            cur = inner;
        }
        assert_eq!(d, DEPTH);
        assert_eq!(cur, &TypeTerm::Base(BaseType::Int(32)));

        // Drop: all deep terms fall out of scope here; the custom iterative
        // Drop must not overflow.
        drop(t);
        drop(applied);
        drop(cloned);
    }

    /// Regression: 100k-deep `Ptr` chains must not overflow the stack in the
    /// manual `PartialEq`, `Hash`, `Debug`, or `Display` impls of `TypeTerm`.
    #[test]
    fn deep_ptr_eq_hash_debug_do_not_overflow_stack() {
        use std::collections::hash_map::DefaultHasher;
        const DEPTH: usize = 100_000;
        let deep = |core: TypeTerm| {
            let mut t = core;
            for _ in 0..DEPTH {
                t = TypeTerm::Ptr(Box::new(t));
            }
            t
        };
        let a = deep(TypeTerm::Var(TypeVariable::new(1)));
        let b = deep(TypeTerm::Var(TypeVariable::new(1)));
        let c = deep(TypeTerm::Var(TypeVariable::new(2)));

        // eq: lockstep spine walk.
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Different depth: one chain longer.
        let d = TypeTerm::Ptr(Box::new(deep(TypeTerm::Var(TypeVariable::new(1)))));
        assert_ne!(a, d);

        // hash: equal terms hash equal, spine walked iteratively.
        let h = |t: &TypeTerm| {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        };
        assert_eq!(h(&a), h(&b));

        // Debug + Display: spine written iteratively.
        let dbg = format!("{a:?}");
        assert!(dbg.starts_with("Ptr(Ptr("));
        assert!(dbg.ends_with("))"));
        assert!(dbg.contains("Var"));
        let disp = format!("{a}");
        assert!(disp.starts_with("**"));
        assert_eq!(disp.matches('*').count(), DEPTH);
    }

    /// Regression: 100k-deep `BaseType::Ptr` / `Array` chains (constructible
    /// via the public `ptr_to`/`array_of`) must not overflow the stack in
    /// `Clone`, `PartialEq`, `Hash`, `Debug`, `Display`, or the drop glue.
    #[test]
    fn deep_base_type_ptr_nesting_does_not_overflow_stack() {
        use std::collections::hash_map::DefaultHasher;
        const DEPTH: usize = 100_000;
        let deep_ptr = |core: BaseType| {
            let mut t = core;
            for _ in 0..DEPTH {
                t = BaseType::ptr_to(t);
            }
            t
        };
        let a = deep_ptr(BaseType::Int(32));
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, deep_ptr(BaseType::UInt(32)));

        let h = |t: &BaseType| {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        };
        assert_eq!(h(&a), h(&b));

        let dbg = format!("{a:?}");
        assert!(dbg.starts_with("Ptr(Ptr("));
        assert!(dbg.contains("Int(32)"));
        assert_eq!(format!("{a}").matches('*').count(), DEPTH);

        // Deep Array spine gets the same treatment.
        let mut arr = BaseType::Bool;
        for _ in 0..DEPTH {
            arr = BaseType::array_of(arr, 2);
        }
        let arr2 = arr.clone();
        assert_eq!(arr, arr2);
        assert_eq!(h(&arr), h(&arr2));
        assert!(format!("{arr:?}").starts_with("Array(Array("));
        assert!(format!("{arr}").starts_with("[["));

        // Deep BaseType embedded in a TypeTerm leaf: TypeTerm's Drop treats
        // Base as a leaf, so BaseType's own iterative Drop must kick in.
        let wrapped = TypeTerm::Base(deep_ptr(BaseType::Void));
        drop(wrapped);
        drop(a);
        drop(b);
        drop(arr);
        drop(arr2);
    }

    /// Property test: on random shallow terms the manual iterative
    /// `PartialEq`/`Hash` must agree with a recursive reference impl
    /// (structural equality), and equal terms must hash identically.
    #[test]
    fn iterative_eq_hash_match_reference_on_random_terms() {
        use std::collections::hash_map::DefaultHasher;

        // Recursive reference structural equality (safe: shallow terms only).
        fn ref_eq_base(a: &BaseType, b: &BaseType) -> bool {
            match (a, b) {
                (BaseType::UInt(x), BaseType::UInt(y))
                | (BaseType::Int(x), BaseType::Int(y))
                | (BaseType::Float(x), BaseType::Float(y)) => x == y,
                (BaseType::Bool, BaseType::Bool)
                | (BaseType::Void, BaseType::Void)
                | (BaseType::Unknown, BaseType::Unknown) => true,
                (BaseType::Ptr(x), BaseType::Ptr(y)) => ref_eq_base(x, y),
                (BaseType::Array(x, n), BaseType::Array(y, m)) => n == m && ref_eq_base(x, y),
                (BaseType::Struct(n1, f1), BaseType::Struct(n2, f2)) => {
                    n1 == n2
                        && f1.len() == f2.len()
                        && f1
                            .iter()
                            .zip(f2)
                            .all(|((k1, v1), (k2, v2))| k1 == k2 && ref_eq_base(v1, v2))
                }
                (BaseType::Func(p1, r1), BaseType::Func(p2, r2)) => {
                    p1.len() == p2.len()
                        && p1.iter().zip(p2).all(|(x, y)| ref_eq_base(x, y))
                        && ref_eq_base(r1, r2)
                }
                _ => false,
            }
        }
        fn ref_eq_term(a: &TypeTerm, b: &TypeTerm) -> bool {
            match (a, b) {
                (TypeTerm::Var(x), TypeTerm::Var(y)) => x == y,
                (TypeTerm::Base(x), TypeTerm::Base(y)) => ref_eq_base(x, y),
                (TypeTerm::Ptr(x), TypeTerm::Ptr(y)) => ref_eq_term(x, y),
                (TypeTerm::Func(p1, r1), TypeTerm::Func(p2, r2)) => {
                    p1.len() == p2.len()
                        && p1.iter().zip(p2).all(|(x, y)| ref_eq_term(x, y))
                        && ref_eq_term(r1, r2)
                }
                _ => false,
            }
        }

        // Deterministic LCG so the test is reproducible.
        let mut seed = 0x243F_6A88_85A3_08D3_u64;
        let mut rng = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        fn gen_base(rng: &mut impl FnMut() -> u32, depth: u32) -> BaseType {
            let choice = if depth == 0 { rng() % 5 } else { rng() % 9 };
            match choice {
                0 => BaseType::UInt(8 << (rng() % 4)),
                1 => BaseType::Int(8 << (rng() % 4)),
                2 => BaseType::Float(if rng().is_multiple_of(2) { 32 } else { 64 }),
                3 => BaseType::Bool,
                4 => {
                    if rng().is_multiple_of(2) {
                        BaseType::Void
                    } else {
                        BaseType::Unknown
                    }
                }
                5 => BaseType::ptr_to(gen_base(rng, depth - 1)),
                6 => BaseType::array_of(gen_base(rng, depth - 1), (rng() % 4) as usize),
                7 => BaseType::Struct(
                    format!("s{}", rng() % 3),
                    (0..rng() % 3)
                        .map(|i| (format!("f{i}"), gen_base(rng, depth - 1)))
                        .collect(),
                ),
                _ => BaseType::Func(
                    (0..rng() % 3).map(|_| gen_base(rng, depth - 1)).collect(),
                    Box::new(gen_base(rng, depth - 1)),
                ),
            }
        }
        fn gen_term(rng: &mut impl FnMut() -> u32, depth: u32) -> TypeTerm {
            let choice = if depth == 0 { rng() % 2 } else { rng() % 4 };
            match choice {
                0 => TypeTerm::Var(TypeVariable::new(rng() % 4)),
                1 => TypeTerm::Base(gen_base(rng, depth.min(2))),
                2 => TypeTerm::Ptr(Box::new(gen_term(rng, depth - 1))),
                _ => TypeTerm::Func(
                    (0..rng() % 3).map(|_| gen_term(rng, depth - 1)).collect(),
                    Box::new(gen_term(rng, depth - 1)),
                ),
            }
        }
        let hash_of = |t: &TypeTerm| {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        };
        let hash_of_base = |t: &BaseType| {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        };

        for _ in 0..500 {
            let a = gen_term(&mut rng, 4);
            let b = gen_term(&mut rng, 4);
            // Iterative eq must agree with the recursive reference.
            assert_eq!(a == b, ref_eq_term(&a, &b), "a={a:?} b={b:?}");
            // Reflexivity via clone, and Eq ⇒ equal hashes.
            let ac = a.clone();
            assert!(a == ac && ref_eq_term(&a, &ac));
            assert_eq!(hash_of(&a), hash_of(&ac));
            if a == b {
                assert_eq!(hash_of(&a), hash_of(&b));
            }
            // Same properties for BaseType directly.
            let ba = gen_base(&mut rng, 3);
            let bb = gen_base(&mut rng, 3);
            assert_eq!(ba == bb, ref_eq_base(&ba, &bb), "ba={ba:?} bb={bb:?}");
            let bac = ba.clone();
            assert!(ba == bac);
            assert_eq!(hash_of_base(&ba), hash_of_base(&bac));
            if ba == bb {
                assert_eq!(hash_of_base(&ba), hash_of_base(&bb));
            }
            // Debug of equal terms must render identically.
            assert_eq!(format!("{a:?}"), format!("{ac:?}"));
            assert_eq!(format!("{ba:?}"), format!("{bac:?}"));
        }
    }
}
