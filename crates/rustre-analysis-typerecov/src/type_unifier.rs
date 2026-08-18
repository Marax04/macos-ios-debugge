//! Type unification via union-find (Hindley-Milner style).
//!
//! Takes the set of [`TypeConstraint`]s produced by
//! [`crate::type_constraint_generator::TypeConstraintGenerator`] and solves
//! them, producing a mapping from [`TypeVar`] to [`RecoveredType`].
//!
//! # Algorithm
//! A standard union-find structure tracks which type variables are equivalent.
//! `Equal` constraints directly union two roots.  `HasType` and `IsInteger`
//! constraints attach concrete type information to a root.  Conflicts produce
//! [`UnifyError`].
//!
//! # Key types
//! - [`TypeUnifier`]       — the solver state.
//! - [`UnificationResult`] — per-variable type map after solving.
//! - [`UnifyError`]        — error from an unsatisfiable constraint.

use std::collections::BTreeMap;

use crate::{RecoveredType, TypeVar};
use crate::type_constraint_generator::{ConstraintKind, TypeConstraint};

// ─────────────────────────────────────────────────────────────────────────────
// UnifyError
// ─────────────────────────────────────────────────────────────────────────────

/// Error from an unsatisfiable type constraint.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UnifyError {
    /// Two concrete types that are not compatible were forced to unify.
    #[error("type conflict: cannot unify {a} with {b} (at constraint {constraint_id})")]
    TypeConflict {
        a: String,
        b: String,
        constraint_id: u32,
    },
    /// A variable was required to be a pointer but is already known to be
    /// a non-pointer type.
    #[error("pointer conflict: {var} required to be pointer but is {found}")]
    PointerConflict { var: TypeVar, found: String },
    /// More type variables were requested than the unifier will allocate.
    ///
    /// `var_count` is derived from the analysed binary, so an adversarial input
    /// can ask for an arbitrary number. The cap exists to prevent OOM; returning
    /// it as an error rather than panicking is what lets a caller survive a
    /// hostile file instead of taking the process down with it.
    #[error("too many type variables: {requested} requested, maximum is {max}")]
    TooManyVariables { requested: u32, max: u32 },
    /// Integer width conflict.
    #[error("integer width conflict: {var} requires ≥{required}B but is already {found}B")]
    WidthConflict {
        var: TypeVar,
        required: u8,
        found: u8,
    },
    /// Signedness conflict.
    #[error("signedness conflict on {var}: signed={a} vs signed={b}")]
    SignednessConflict { var: TypeVar, a: bool, b: bool },
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeInfo — partial type information attached to a union-find node
// ─────────────────────────────────────────────────────────────────────────────

/// Partial type information gathered for a union-find equivalence class.
#[derive(Debug, Clone, Default)]
struct TypeInfo {
    /// Concrete type if one has been assigned.
    concrete: Option<RecoveredType>,
    /// Minimum integer width (bytes) if known to be integer.
    int_min_width: Option<u8>,
    /// Signedness if known.
    int_signed: Option<bool>,
    /// Whether this variable is known to be a pointer.
    is_pointer: bool,
    /// The type variable this one points to (if `is_pointer` is set).
    pointee: Option<TypeVar>,
    /// Whether this variable is known to be a float and its width.
    float_width: Option<u8>,
}

/// Return `true` if a concrete type is compatible with the `is_pointer`
/// flag (plain pointers and function pointers both live in pointer
/// registers).
const fn ptr_compatible(t: &RecoveredType) -> bool {
    t.is_pointer() || matches!(t, RecoveredType::FnPtr { .. })
}

impl TypeInfo {
    /// Merge `other` into `self`.  Returns `Err` on conflict.
    fn merge(&mut self, other: &Self, var: TypeVar, cid: u32) -> Result<(), UnifyError> {
        // Merge integer width.
        if let Some(w) = other.int_min_width {
            let current = self.int_min_width.unwrap_or(0);
            self.int_min_width = Some(current.max(w));
        }
        // Merge signedness.
        if let Some(s) = other.int_signed {
            match self.int_signed {
                None => self.int_signed = Some(s),
                Some(existing) if existing == s => {}
                Some(existing) => {
                    return Err(UnifyError::SignednessConflict {
                        var,
                        a: existing,
                        b: s,
                    });
                }
            }
        }
        // Merge float width.
        if let Some(fw) = other.float_width {
            match self.float_width {
                None => self.float_width = Some(fw),
                Some(existing) if existing == fw => {}
                Some(existing) => {
                    return Err(UnifyError::TypeConflict {
                        a: format!("f{}", existing * 8),
                        b: format!("f{}", fw * 8),
                        constraint_id: cid,
                    });
                }
            }
        }
        // Pointer flag (and pointee, if the merged-in side knows one).
        if other.is_pointer {
            if self.concrete.as_ref().is_some_and(|t| !ptr_compatible(t)) {
                return Err(UnifyError::PointerConflict {
                    var,
                    found: self.concrete.as_ref().map(super::RecoveredType::display_name).unwrap_or_default(),
                });
            }
            self.is_pointer = true;
            if self.pointee.is_none() {
                self.pointee = other.pointee;
            }
        }
        // Merge concrete types.  Adopting the other side's concrete type must
        // apply the same pointer-compatibility guard as the branch above,
        // otherwise merge(a, b) errors while merge(b, a) silently accepts an
        // inconsistent {is_pointer, concrete: non-pointer} state (soundness
        // bug: which operand's data survived depended on merge direction).
        match (&self.concrete, &other.concrete) {
            (None, Some(t)) => {
                if self.is_pointer && !ptr_compatible(t) {
                    return Err(UnifyError::PointerConflict {
                        var,
                        found: t.display_name(),
                    });
                }
                self.concrete = Some(t.clone());
            }
            (Some(a), Some(b)) if a != b => {
                return Err(UnifyError::TypeConflict {
                    a: a.display_name(),
                    b: b.display_name(),
                    constraint_id: cid,
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Derive a [`RecoveredType`] from the accumulated information.
    fn recover(&self) -> RecoveredType {
        // Concrete type wins if set.
        if let Some(ref t) = self.concrete {
            return t.clone();
        }
        // Float.
        if let Some(w) = self.float_width {
            return RecoveredType::Float { width: w };
        }
        // Pointer.
        if self.is_pointer {
            let inner = self
                .pointee
                .map_or(RecoveredType::Unknown, RecoveredType::Var);
            return RecoveredType::Pointer(Box::new(inner));
        }
        // Integer.
        if let Some(w) = self.int_min_width {
            return RecoveredType::Int {
                width: w,
                signed: self.int_signed.unwrap_or(false),
            };
        }
        RecoveredType::Unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnionFind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct UnionFind {
    parent: Vec<u32>,
    rank: Vec<u8>,
    info: Vec<TypeInfo>,
}

impl UnionFind {
    fn new(n: u32) -> Self {
        // Guard against OOM from an adversarially large var_count.
        const MAX_NODES: u32 = 1 << 24;
        assert!(
            n <= MAX_NODES,
            "UnionFind::new({n}) exceeds maximum capacity ({MAX_NODES})"
        );
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n as usize],
            info: (0..n).map(|_| TypeInfo::default()).collect(),
        }
    }

    fn ensure(&mut self, v: TypeVar) {
        // Hard cap: reject TypeVar ids at or above 16 M to prevent OOM.
        const MAX_NODES: usize = 1 << 24;
        // DOS-amplification guard: a single adversarial TypeVar with id near
        // MAX_NODES would cause up to 16 M entries to be allocated in one
        // call, consuming hundreds of MB of RAM.  Limit per-call growth to
        // at most 4096 new nodes; callers that need more must call ensure()
        // incrementally (which the constraint generator always does, since it
        // allocates TypeVars sequentially from 0).
        const MAX_GROWTH_PER_CALL: usize = 4096;

        let id = v.0 as usize;
        assert!(
            id < MAX_NODES,
            "TypeVar id {id} exceeds maximum union-find capacity ({MAX_NODES})"
        );
        let current_len = self.parent.len();
        if id >= current_len {
            let needed = id + 1 - current_len;
            assert!(
                needed <= MAX_GROWTH_PER_CALL,
                "TypeVar id {id} would grow union-find by {needed} nodes in one call \
                 (max {MAX_GROWTH_PER_CALL}); ids must be allocated sequentially"
            );
        }
        while id >= self.parent.len() {
            let next = u32::try_from(self.parent.len())
                .expect("union-find parent length exceeds u32::MAX (bounded by MAX_NODES)");
            self.parent.push(next);
            self.rank.push(0);
            self.info.push(TypeInfo::default());
        }
    }

    /// Grow capacity to hold `max_id` without ever asking `ensure` for more than
    /// it allows in one call.
    ///
    /// `ensure` caps growth per call (an anti-amplification guard) with an
    /// `assert!`, so a constraint carrying a large-but-legal id used to abort the
    /// process. Growing here in bounded steps keeps that guard an internal
    /// invariant instead of a reachable panic.
    fn reserve_len(&mut self, target: usize) {
        while self.parent.len() < target {
            let next_id = u32::try_from(self.parent.len().min(u32::MAX as usize)).unwrap_or(u32::MAX);
            let step = (target - self.parent.len()).min(4096);
            let upto = next_id.saturating_add(u32::try_from(step).unwrap_or(1)).saturating_sub(1);
            self.ensure(TypeVar::new(upto));
        }
    }

    fn find(&mut self, v: TypeVar) -> TypeVar {
        self.ensure(v);
        let mut x = v.0 as usize;
        while self.parent[x] as usize != x {
            let p = self.parent[x] as usize;
            self.parent[x] = self.parent[p]; // path compression
            x = self.parent[x] as usize;
        }
        TypeVar::new(u32::try_from(x).expect("union-find index exceeds u32::MAX"))
    }

    fn union(&mut self, a: TypeVar, b: TypeVar, cid: u32) -> Result<(), UnifyError> {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return Ok(());
        }
        // Union by rank.
        let (winner, loser) = if self.rank[ra.0 as usize] >= self.rank[rb.0 as usize] {
            (ra, rb)
        } else {
            (rb, ra)
        };
        // Move the loser's info out instead of cloning: after the parent
        // redirect below the loser is never a root again, so its slot is dead.
        // On merge failure the info is restored so the error path leaves the
        // structure exactly as before.
        let loser_info = std::mem::take(&mut self.info[loser.0 as usize]);
        let winner_pointee = self.info[winner.0 as usize].pointee;
        let winner_var = winner;
        if let Err(e) = self.info[winner.0 as usize].merge(&loser_info, winner_var, cid) {
            self.info[loser.0 as usize] = loser_info;
            return Err(e);
        }
        self.parent[loser.0 as usize] = winner.0;
        if self.rank[winner.0 as usize] == self.rank[loser.0 as usize] {
            self.rank[winner.0 as usize] =
                self.rank[winner.0 as usize].saturating_add(1);
        }
        // If both classes knew a pointee, the tie-break in `merge` kept only
        // the winner's — but the two pointees describe the *same* pointed-to
        // storage, so they must be unified rather than one being dropped
        // (dropping made the result depend on union order / rank tie-breaks).
        // Recursion terminates: every union strictly reduces the class count.
        if let (Some(p1), Some(p2)) = (winner_pointee, loser_info.pointee) {
            if p1 != p2 {
                self.union(p1, p2, cid)?;
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnificationResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of unifying a constraint set.
///
/// `types` uses [`BTreeMap`] rather than [`HashMap`] so that
/// attacker-controlled [`TypeVar`] keys cannot trigger hash-collision `DoS`.
#[derive(Debug, Clone)]
pub struct UnificationResult {
    /// Map from type variable to recovered type.
    pub types: BTreeMap<TypeVar, RecoveredType>,
    /// Number of distinct equivalence classes.
    pub class_count: usize,
    /// Type variables that could not be resolved beyond Unknown.
    pub unresolved: Vec<TypeVar>,
}

impl UnificationResult {
    /// Look up the recovered type for a variable.
    #[must_use]
    pub fn get(&self, var: TypeVar) -> &RecoveredType {
        self.types.get(&var).unwrap_or(&RecoveredType::Unknown)
    }

    /// Return all variables that were resolved to a concrete type.
    #[must_use]
    pub fn resolved_vars(&self) -> Vec<TypeVar> {
        let mut v: Vec<TypeVar> = self
            .types
            .iter()
            .filter(|(_, t)| !matches!(t, RecoveredType::Unknown | RecoveredType::Var(_)))
            .map(|(v, _)| *v)
            .collect();
        v.sort();
        v
    }

    /// Return all pointer variables and their pointee types.
    #[must_use]
    pub fn pointers(&self) -> Vec<(TypeVar, &RecoveredType)> {
        self.types
            .iter()
            .filter(|(_, t)| t.is_pointer())
            .map(|(v, t)| (*v, t))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeUnifier
// ─────────────────────────────────────────────────────────────────────────────

/// Solves a set of type constraints via union-find.
///
/// # Usage
/// ```no_run
/// use rustre_analysis_typerecov::type_unifier::TypeUnifier;
/// let mut unifier = TypeUnifier::new(16);
/// // ... add constraints ...
/// let result = unifier.solve(&[]).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TypeUnifier {
    uf: UnionFind,
    /// Number of type variables allocated.
    pub var_count: u32,
}

impl TypeUnifier {
    /// Largest number of type variables the unifier will allocate.
    ///
    /// The bound guards against OOM from an adversarially large `var_count`.
    pub const MAX_VARIABLES: u32 = 1 << 24;

    /// Every `TypeVar` mentioned by a constraint.
    ///
    /// Used to validate ids before they reach the union-find; a missed variant
    /// here would let an unvalidated id through, so it lists them explicitly
    /// rather than falling back to a wildcard.
    fn constraint_vars(kind: &ConstraintKind) -> Vec<TypeVar> {
        match kind {
            ConstraintKind::Equal { lhs, rhs } => vec![*lhs, *rhs],
            ConstraintKind::IsPointerTo { ptr, pointee } => vec![*ptr, *pointee],
            ConstraintKind::HasType { var, .. }
            | ConstraintKind::IsInteger { var, .. }
            | ConstraintKind::IsFloat { var, .. } => vec![*var],
            ConstraintKind::PointerArithmetic { result, base, offset } => {
                vec![*result, *base, *offset]
            }
            ConstraintKind::FieldAccess { struct_var, field_var, .. } => {
                vec![*struct_var, *field_var]
            }
            ConstraintKind::IsCallable { callee, .. } => vec![*callee],
            ConstraintKind::IsReturnOf { var, func } => vec![*var, *func],
            ConstraintKind::IsArray { arr, elem, .. } => vec![*arr, *elem],
        }
    }

    /// Create a unifier for `var_count` type variables, or report that the
    /// count exceeds [`Self::MAX_VARIABLES`].
    ///
    /// Prefer this over [`Self::new`] on any path fed by a binary: `var_count`
    /// comes from the analysed file, so a crafted input can request more
    /// variables than the cap allows. `new` panics in that case — which turns a
    /// hostile file into a process kill — while this returns an error the caller
    /// can handle.
    ///
    /// # Errors
    /// Returns [`UnifyError::TooManyVariables`] when `var_count` exceeds the cap.
    pub fn try_new(var_count: u32) -> Result<Self, UnifyError> {
        if var_count > Self::MAX_VARIABLES {
            return Err(UnifyError::TooManyVariables {
                requested: var_count,
                max: Self::MAX_VARIABLES,
            });
        }
        Ok(Self::new(var_count))
    }

    /// Create a new unifier for `var_count` type variables.
    ///
    /// # Panics
    /// Panics if `var_count` exceeds [`Self::MAX_VARIABLES`]. Use
    /// [`Self::try_new`] when the count comes from an untrusted binary.
    #[must_use]
    pub fn new(var_count: u32) -> Self {
        Self {
            uf: UnionFind::new(var_count),
            var_count,
        }
    }

    /// Solve all constraints and return the [`UnificationResult`].
    ///
    /// Constraints are processed in order.  Equality constraints are handled
    /// first (single pass), then type-attachment constraints.
    ///
    /// # Errors
    /// Returns [`UnifyError`] if the constraint set is inconsistent
    /// (e.g. conflicting concrete types unified into the same equivalence
    /// class, or a non-pointer marked as a pointer).
    ///
    /// # Panics
    /// Panics if the union-find grows past `u32::MAX` entries (an internal
    /// invariant — bounded above by `MAX_NODES = 1 << 24`).
    pub fn solve(&mut self, constraints: &[TypeConstraint]) -> Result<UnificationResult, UnifyError> {
        // Validate before touching the union-find. Constraints are built from the
        // analysed binary, so their TypeVar ids are attacker-influenced: measured
        // before this check, a single constraint carrying `TypeVar(16_777_215)`
        // aborted the process inside `ensure`'s growth guard — and that id is
        // *below* the capacity cap, so even a legal-looking one did it.
        let mut needed: usize = self.var_count as usize;
        for c in constraints {
            for v in Self::constraint_vars(&c.kind) {
                if v.0 >= Self::MAX_VARIABLES {
                    return Err(UnifyError::TooManyVariables {
                        requested: v.0.saturating_add(1),
                        max: Self::MAX_VARIABLES,
                    });
                }
                needed = needed.max(v.0 as usize + 1);
            }
        }
        // Reserve a *length*, not an id: `TypeUnifier::new(0).solve(&[])` needs
        // zero nodes, and reasoning in ids allocated one.
        self.uf.reserve_len(needed);

        // Phase 1: process equality constraints (union type vars).
        for c in constraints {
            if let ConstraintKind::Equal { lhs, rhs } = &c.kind {
                self.uf.ensure(*lhs);
                self.uf.ensure(*rhs);
                self.uf.union(*lhs, *rhs, c.id)?;
            }
        }

        // Phase 2: attach concrete type information.
        for c in constraints {
            self.apply_constraint(c)?;
        }

        // Phase 3: build the result map.
        // Use BTreeMap so attacker-controlled TypeVar keys cannot trigger
        // hash-collision denial-of-service.
        let mut types: BTreeMap<TypeVar, RecoveredType> = BTreeMap::new();
        let n = self.uf.parent.len();
        // Collect representatives.
        let mut roots: BTreeMap<TypeVar, Vec<TypeVar>> = BTreeMap::new();
        for i in 0..n {
            // Safety: TypeVar ids are u32; ensure() already caps the vec length
            // at 1 << 24, so this cast cannot overflow.
            let v = TypeVar::new(u32::try_from(i).expect("union-find index exceeds u32::MAX"));
            let root = self.uf.find(v);
            roots.entry(root).or_default().push(v);
        }

        for (root, members) in &roots {
            let recovered = self.uf.info[root.0 as usize].recover();
            for &member in members {
                types.insert(member, recovered.clone());
            }
        }

        let class_count = roots.len();
        let unresolved: Vec<TypeVar> = types
            .iter()
            .filter(|(_, t)| matches!(t, RecoveredType::Unknown))
            .map(|(v, _)| *v)
            .collect();

        Ok(UnificationResult {
            types,
            class_count,
            unresolved,
        })
    }

    fn apply_constraint(&mut self, c: &TypeConstraint) -> Result<(), UnifyError> {
        match &c.kind {
            ConstraintKind::Equal { .. } => {} // already handled in phase 1

            ConstraintKind::HasType { var, ty } => {
                self.uf.ensure(*var);
                let root = self.uf.find(*var);
                Self::set_concrete(&mut self.uf.info[root.0 as usize], ty.clone(), c.id)?;
            }

            ConstraintKind::IsInteger { var, min_width, signed } => {
                self.uf.ensure(*var);
                let root = self.uf.find(*var);
                let info = &mut self.uf.info[root.0 as usize];
                let current_w = info.int_min_width.unwrap_or(0);
                info.int_min_width = Some(current_w.max(*min_width));
                if let Some(s) = signed {
                    match info.int_signed {
                        None => info.int_signed = Some(*s),
                        Some(existing) if existing == *s => {}
                        Some(existing) => {
                            return Err(UnifyError::SignednessConflict {
                                var: *var,
                                a: existing,
                                b: *s,
                            });
                        }
                    }
                }
            }

            ConstraintKind::IsFloat { var, width } => {
                self.uf.ensure(*var);
                let root = self.uf.find(*var);
                let info = &mut self.uf.info[root.0 as usize];
                match info.float_width {
                    None => info.float_width = Some(*width),
                    Some(w) if w == *width => {}
                    Some(w) => {
                        return Err(UnifyError::TypeConflict {
                            a: format!("f{}", w * 8),
                            b: format!("f{}", width * 8),
                            constraint_id: c.id,
                        });
                    }
                }
            }

            ConstraintKind::IsPointerTo { ptr, pointee } => {
                self.uf.ensure(*ptr);
                self.uf.ensure(*pointee);
                let ptr_root = self.uf.find(*ptr);
                self.mark_pointer(ptr_root, *ptr)?;
                match self.uf.info[ptr_root.0 as usize].pointee {
                    None => self.uf.info[ptr_root.0 as usize].pointee = Some(*pointee),
                    Some(existing) if existing == *pointee => {}
                    Some(existing) => {
                        // Two pointee variables observed for the same pointer
                        // class describe the same pointed-to storage: unify
                        // them instead of dropping one (dropping made the
                        // recovered pointee depend on constraint order).
                        self.uf.union(existing, *pointee, c.id)?;
                    }
                }
            }

            ConstraintKind::PointerArithmetic { result, base, .. } => {
                // Heuristic: result has the same type as base (pointer).
                self.uf.ensure(*result);
                self.uf.ensure(*base);
                // We don't union here — just note pointer origin.
                let base_root = self.uf.find(*base);
                self.mark_pointer(base_root, *base)?;
            }

            ConstraintKind::FieldAccess { struct_var, field_var: _, byte_offset: _ } => {
                self.uf.ensure(*struct_var);
                let root = self.uf.find(*struct_var);
                self.mark_pointer(root, *struct_var)?;
            }

            ConstraintKind::IsCallable { callee, param_count } => {
                self.uf.ensure(*callee);
                let root = self.uf.find(*callee);
                Self::set_concrete(
                    &mut self.uf.info[root.0 as usize],
                    RecoveredType::FnPtr { param_count: *param_count },
                    c.id,
                )?;
            }

            ConstraintKind::IsReturnOf { var, func: _ } => {
                self.uf.ensure(*var);
                // We don't have enough info to pin down the return type here.
            }

            ConstraintKind::IsArray { arr, elem: _, min_count } => {
                self.uf.ensure(*arr);
                let root = self.uf.find(*arr);
                Self::set_concrete(
                    &mut self.uf.info[root.0 as usize],
                    RecoveredType::Array {
                        element: Box::new(RecoveredType::Unknown),
                        count: *min_count,
                    },
                    c.id,
                )?;
            }
        }
        Ok(())
    }

    /// Mark a class as a pointer, erroring if it already carries a concrete
    /// non-pointer type.  Centralised so that every producer of `is_pointer`
    /// (`IsPointerTo`, `PointerArithmetic`, `FieldAccess`) applies the same
    /// conflict check that `set_concrete`/`merge` apply in the other
    /// direction — otherwise Ok/Err depended on constraint order.
    fn mark_pointer(&mut self, root: TypeVar, var: TypeVar) -> Result<(), UnifyError> {
        let info = &mut self.uf.info[root.0 as usize];
        if info.concrete.as_ref().is_some_and(|t| !ptr_compatible(t)) {
            return Err(UnifyError::PointerConflict {
                var,
                found: info
                    .concrete
                    .as_ref()
                    .map(super::RecoveredType::display_name)
                    .unwrap_or_default(),
            });
        }
        info.is_pointer = true;
        Ok(())
    }

    /// Attach a concrete type to a class's info, erroring on a conflict with an
    /// already-attached, different concrete type. Centralises the guard so that
    /// `IsCallable`/`IsArray` behave consistently with `HasType`/`IsFloat`
    /// instead of silently overwriting (which made `solve` order-dependent).
    fn set_concrete(
        info: &mut TypeInfo,
        ty: RecoveredType,
        constraint_id: u32,
    ) -> Result<(), UnifyError> {
        match &info.concrete {
            None => {
                // Same guard as TypeInfo::merge: a class already known to be
                // a pointer cannot adopt a non-pointer concrete type.  Without
                // this, `[IsPointerTo, HasType(int)]` silently succeeded while
                // `[HasType(int), IsPointerTo]` errored — an order-dependent
                // solve.
                if info.is_pointer && !ptr_compatible(&ty) {
                    return Err(UnifyError::TypeConflict {
                        a: "pointer".to_string(),
                        b: ty.display_name(),
                        constraint_id,
                    });
                }
                info.concrete = Some(ty);
                Ok(())
            }
            Some(existing) if *existing == ty => Ok(()),
            Some(existing) => Err(UnifyError::TypeConflict {
                a: existing.display_name(),
                b: ty.display_name(),
                constraint_id,
            }),
        }
    }
}

/// Convenience wrapper: generate and immediately solve constraints.
///
/// # Errors
/// Returns [`UnifyError::TooManyVariables`] if `var_count` exceeds
/// [`TypeUnifier::MAX_VARIABLES`], or [`UnifyError`] if the constraint set is
/// inconsistent. See [`TypeUnifier::solve`] for the other failure modes.
pub fn unify_types(
    constraints: &[TypeConstraint],
    var_count: u32,
) -> Result<UnificationResult, UnifyError> {
    // `var_count` comes from the analysed binary. Going through `try_new` means
    // an adversarial count is reported as an error instead of aborting the
    // process — measured before the change: `TypeUnifier::new(16_777_217)`
    // panicked.
    let mut unifier = TypeUnifier::try_new(var_count)?;
    unifier.solve(constraints)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_constraint_generator::Provenance;

    fn tv(n: u32) -> TypeVar {
        TypeVar::new(n)
    }

    fn eq(lhs: u32, rhs: u32) -> TypeConstraint {
        TypeConstraint::certain(
            lhs * 100 + rhs,
            ConstraintKind::Equal { lhs: tv(lhs), rhs: tv(rhs) },
            Provenance::new(0, ""),
        )
    }

    fn has_int(var: u32, w: u8, signed: bool) -> TypeConstraint {
        TypeConstraint::certain(
            var,
            ConstraintKind::IsInteger { var: tv(var), min_width: w, signed: Some(signed) },
            Provenance::new(0, ""),
        )
    }

    fn is_ptr(ptr: u32, pointee: u32) -> TypeConstraint {
        TypeConstraint::certain(
            ptr,
            ConstraintKind::IsPointerTo { ptr: tv(ptr), pointee: tv(pointee) },
            Provenance::new(0, ""),
        )
    }

    fn callable(var: u32, params: usize) -> TypeConstraint {
        TypeConstraint::certain(
            var,
            ConstraintKind::IsCallable { callee: tv(var), param_count: params },
            Provenance::new(0, ""),
        )
    }

    fn is_array(var: u32, count: usize) -> TypeConstraint {
        TypeConstraint::certain(
            var,
            ConstraintKind::IsArray { arr: tv(var), elem: tv(var + 1), min_count: count },
            Provenance::new(0, ""),
        )
    }

    /// `solve` takes a *set* of constraints; its result must not depend on the
    /// order they are listed in. `IsCallable`/`IsArray` used to overwrite
    /// `concrete` unconditionally (unlike `HasType`/`IsFloat`, which conflict-
    /// check), so a var with two conflicting concrete constraints resolved to
    /// whichever appeared last — an order-dependent (and silently
    /// conflict-swallowing) result.
    #[test]
    fn solve_is_order_independent_for_conflicting_concrete_constraints() {
        let mut a = TypeUnifier::new(4);
        let ra = a.solve(&[callable(0, 2), is_array(0, 5)]);
        let mut b = TypeUnifier::new(4);
        let rb = b.solve(&[is_array(0, 5), callable(0, 2)]);
        match (&ra, &rb) {
            (Ok(x), Ok(y)) => assert_eq!(
                x.get(tv(0)),
                y.get(tv(0)),
                "solve result depends on constraint order"
            ),
            (Err(_), Err(_)) => {} // consistently rejected — also fine
            _ => panic!("solve outcome (Ok vs Err) depends on constraint order: {ra:?} vs {rb:?}"),
        }
    }

    #[test]
    fn test_simple_equality() {
        let mut u = TypeUnifier::new(3);
        let cs = vec![eq(0, 1), has_int(1, 4, true)];
        let result = u.solve(&cs).unwrap();
        // Both 0 and 1 should be i32.
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Int { width: 4, signed: true }
        ));
    }

    #[test]
    fn test_pointer_constraint() {
        let mut u = TypeUnifier::new(2);
        let cs = vec![is_ptr(0, 1), has_int(1, 8, false)];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
    }

    #[test]
    fn test_transitive_equality() {
        let mut u = TypeUnifier::new(4);
        let cs = vec![eq(0, 1), eq(1, 2), eq(2, 3), has_int(3, 1, false)];
        let result = u.solve(&cs).unwrap();
        for i in 0..=3u32 {
            assert!(
                matches!(result.get(tv(i)), RecoveredType::Int { width: 1, .. }),
                "var {i} should be u8"
            );
        }
    }

    #[test]
    fn test_float_constraint() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::IsFloat { var: tv(0), width: 8 },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(result.get(tv(0)), RecoveredType::Float { width: 8 }));
    }

    #[test]
    fn test_callable_constraint() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::IsCallable { callee: tv(0), param_count: 3 },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::FnPtr { param_count: 3 }
        ));
    }

    #[test]
    fn test_width_accumulation() {
        // v0 ≥ 1B then ≥ 4B → should be ≥ 4B.
        let mut u = TypeUnifier::new(1);
        let cs = vec![has_int(0, 1, false), has_int(0, 4, false)];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Int { width: 4, .. }
        ));
    }

    #[test]
    fn test_unify_types_convenience() {
        let cs = vec![has_int(0, 8, true)];
        let result = unify_types(&cs, 2).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Int { width: 8, signed: true }
        ));
    }

    #[test]
    fn test_resolved_vars() {
        let mut u = TypeUnifier::new(3);
        let cs = vec![has_int(0, 4, false), has_int(1, 8, true)];
        let result = u.solve(&cs).unwrap();
        let resolved = result.resolved_vars();
        assert!(resolved.contains(&tv(0)));
        assert!(resolved.contains(&tv(1)));
    }

    #[test]
    fn test_unresolved_vars() {
        let mut u = TypeUnifier::new(3);
        let cs = vec![has_int(0, 4, false)]; // var 1 and 2 unresolved
        let result = u.solve(&cs).unwrap();
        // Vars 1 and 2 should be in the unresolved set.
        assert!(result.unresolved.contains(&tv(1)) || result.unresolved.contains(&tv(2)));
    }

    #[test]
    fn test_empty_constraints() {
        let mut u = TypeUnifier::new(5);
        let result = u.solve(&[]).unwrap();
        // All vars should be Unknown.
        for i in 0..5u32 {
            assert!(matches!(result.get(tv(i)), RecoveredType::Unknown));
        }
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn test_zero_vars() {
        let mut u = TypeUnifier::new(0);
        let result = u.solve(&[]).unwrap();
        assert!(result.resolved_vars().is_empty());
    }

    #[test]
    fn test_max_int_width_wins() {
        // Two integer constraints with different min widths: the larger should win.
        let mut u = TypeUnifier::new(1);
        let cs = vec![has_int(0, 1, false), has_int(0, 8, false)];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Int { width: 8, signed: false }
        ));
    }

    #[test]
    fn test_signedness_conflict_is_error() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![has_int(0, 4, true), has_int(0, 4, false)];
        let err = u.solve(&cs).unwrap_err();
        assert!(matches!(err, UnifyError::SignednessConflict { .. }));
    }

    #[test]
    fn test_self_equality_is_noop() {
        let mut u = TypeUnifier::new(2);
        let cs = vec![eq(0, 0), has_int(0, 4, true)];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Int { width: 4, signed: true }
        ));
    }

    #[test]
    fn test_unioned_chain_with_pointer_at_end() {
        // 0 == 1 == 2; 2 is pointer to 3 which is int.
        let mut u = TypeUnifier::new(4);
        let cs = vec![eq(0, 1), eq(1, 2), is_ptr(2, 3), has_int(3, 4, true)];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
        assert!(result.get(tv(1)).is_pointer());
    }

    #[test]
    fn test_get_out_of_bounds_typevar_returns_unknown() {
        let mut u = TypeUnifier::new(2);
        let result = u.solve(&[]).unwrap();
        // Querying within range works.
        assert!(matches!(result.get(tv(0)), RecoveredType::Unknown));
        // Querying out-of-range should return Unknown gracefully (no panic).
        assert!(matches!(result.get(tv(99)), RecoveredType::Unknown));
    }

    // ── Additional coverage: constraint kinds with weak/zero coverage ───────

    #[test]
    fn test_pointer_arithmetic_marks_base_as_pointer() {
        let mut u = TypeUnifier::new(2);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::PointerArithmetic { result: tv(1), base: tv(0), offset: tv(0) },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
    }

    #[test]
    fn test_field_access_constraint_marks_struct_var_as_pointer() {
        let mut u = TypeUnifier::new(2);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::FieldAccess { struct_var: tv(0), field_var: tv(1), byte_offset: 8 },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
    }

    #[test]
    fn test_is_return_of_does_not_panic_and_stays_unknown() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::IsReturnOf { var: tv(0), func: tv(1) },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(result.get(tv(0)), RecoveredType::Unknown));
    }

    #[test]
    fn test_is_array_constraint() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![TypeConstraint::certain(
            0,
            ConstraintKind::IsArray { arr: tv(0), elem: tv(0), min_count: 10 },
            Provenance::new(0, ""),
        )];
        let result = u.solve(&cs).unwrap();
        assert!(matches!(
            result.get(tv(0)),
            RecoveredType::Array { count: 10, .. }
        ));
    }

    #[test]
    fn test_concrete_type_conflict_is_error() {
        let mut u = TypeUnifier::new(1);
        let cs = vec![
            TypeConstraint::certain(
                0,
                ConstraintKind::HasType { var: tv(0), ty: RecoveredType::Int { width: 4, signed: true } },
                Provenance::new(0, ""),
            ),
            TypeConstraint::certain(
                1,
                ConstraintKind::HasType { var: tv(0), ty: RecoveredType::Float { width: 8 } },
                Provenance::new(0, ""),
            ),
        ];
        let err = u.solve(&cs).unwrap_err();
        assert!(matches!(err, UnifyError::TypeConflict { .. }));
    }

    #[test]
    fn test_pointee_survives_union_by_rank_when_loser_holds_it() {
        // Regression test: TypeInfo::merge previously never copied `pointee`
        // from the merged-in side, so if the equivalence class that already
        // knows its pointee ends up as the *loser* of a union-by-rank merge,
        // that pointee info was silently dropped even though `is_pointer`
        // survived. Build enough extra members on var 3's class so it wins
        // the rank tie-break over var 0's (freshly created) class, forcing
        // var 0's class to be the "winner" that must inherit var 3's pointee.
        let mut u = TypeUnifier::new(6);
        let cs = vec![
            is_ptr(3, 4),
            has_int(4, 4, true),
            eq(3, 5), // grow {3,4,5} so its root has higher rank
            eq(0, 3), // union var0's fresh singleton class into {3,4,5}'s class
        ];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
        match result.get(tv(0)) {
            RecoveredType::Pointer(inner) => {
                assert!(
                    !matches!(**inner, RecoveredType::Unknown),
                    "pointee information was lost during union-by-rank merge"
                );
            }
            other => panic!("expected pointer type, got {other:?}"),
        }
    }

    // ── Randomized property tests (lattice/oracle angle) ─────────────────────

    use crate::test_prng::xorshift as xs;

    /// Generate a random, *internally consistent* TypeInfo (no
    /// pointer-flag/concrete contradictions, which merge is entitled to
    /// assume were rejected when the info was built).
    fn random_info(s: &mut u64) -> TypeInfo {
        let mut info = TypeInfo::default();
        if xs(s) % 2 == 0 {
            info.int_min_width = Some([1u8, 2, 4, 8][(xs(s) % 4) as usize]);
        }
        if xs(s) % 3 == 0 {
            info.int_signed = Some(xs(s) % 2 == 0);
        }
        if xs(s) % 4 == 0 {
            info.float_width = Some(if xs(s) % 2 == 0 { 4 } else { 8 });
        }
        match xs(s) % 6 {
            0 => info.concrete = Some(RecoveredType::Int { width: 4, signed: true }),
            1 => info.concrete = Some(RecoveredType::Float { width: 8 }),
            2 => info.concrete = Some(RecoveredType::Pointer(Box::new(RecoveredType::Unknown))),
            3 => info.concrete = Some(RecoveredType::FnPtr { param_count: 2 }),
            _ => {}
        }
        // is_pointer only if consistent with concrete.
        if xs(s) % 2 == 0 && info.concrete.as_ref().is_none_or(ptr_compatible) {
            info.is_pointer = true;
            if xs(s) % 2 == 0 {
                info.pointee = Some(TypeVar::new((xs(s) % 8) as u32));
            }
        }
        info
    }

    /// merge(a,b) and merge(b,a) must carry the same information in every
    /// field — is_pointer, pointee, int width, signedness, float width,
    /// concrete — and must agree on Ok vs Err. The only documented tie-break
    /// is `pointee` when BOTH sides already know one (the union layer then
    /// unifies the two pointee vars, see `union`).
    #[test]
    fn prop_typeinfo_merge_is_commutative_in_all_fields() {
        let mut s = 0x1234_5678_9abc_def1u64;
        for i in 0..2000 {
            let a = random_info(&mut s);
            let b = random_info(&mut s);
            let mut ab = a.clone();
            let rab = ab.merge(&b, TypeVar::new(0), 0);
            let mut ba = b.clone();
            let rba = ba.merge(&a, TypeVar::new(0), 0);
            assert_eq!(
                rab.is_ok(),
                rba.is_ok(),
                "iter {i}: Ok/Err disagrees: a={a:?} b={b:?} -> {rab:?} vs {rba:?}"
            );
            if rab.is_ok() {
                assert_eq!(ab.is_pointer, ba.is_pointer, "iter {i}: is_pointer: a={a:?} b={b:?}");
                assert_eq!(ab.int_min_width, ba.int_min_width, "iter {i}: width: a={a:?} b={b:?}");
                assert_eq!(ab.int_signed, ba.int_signed, "iter {i}: signed: a={a:?} b={b:?}");
                assert_eq!(ab.float_width, ba.float_width, "iter {i}: float: a={a:?} b={b:?}");
                assert_eq!(ab.concrete, ba.concrete, "iter {i}: concrete: a={a:?} b={b:?}");
                if a.pointee.is_none() || b.pointee.is_none() {
                    assert_eq!(ab.pointee, ba.pointee, "iter {i}: pointee: a={a:?} b={b:?}");
                }
            }
        }
    }

    /// Regression (found by prop_typeinfo_merge_is_commutative_in_all_fields,
    /// seed 0x1234_5678_9abc_def1): merging a concrete non-pointer INTO a
    /// pointer-flagged info silently succeeded, while the reverse direction
    /// correctly returned PointerConflict.
    #[test]
    fn regression_merge_pointer_vs_concrete_symmetric_error() {
        let ptr_info = TypeInfo { is_pointer: true, ..TypeInfo::default() };
        let int_info = TypeInfo {
            concrete: Some(RecoveredType::Int { width: 4, signed: true }),
            ..TypeInfo::default()
        };
        let mut a = ptr_info.clone();
        let r1 = a.merge(&int_info, tv(0), 0);
        let mut b = int_info;
        let r2 = b.merge(&ptr_info, tv(0), 0);
        assert!(r1.is_err(), "pointer.merge(int) must conflict");
        assert!(r2.is_err(), "int.merge(pointer) must conflict");
    }

    /// Regression: `[IsPointerTo, HasType(int)]` silently succeeded (yielding
    /// an int for a pointer-marked class) while `[HasType(int), IsPointerTo]`
    /// errored — solve's outcome depended on constraint order.
    #[test]
    fn regression_hastype_after_ispointerto_conflicts_in_both_orders() {
        let has_int_ty = |id| {
            TypeConstraint::certain(
                id,
                ConstraintKind::HasType { var: tv(0), ty: RecoveredType::Int { width: 4, signed: true } },
                Provenance::new(0, ""),
            )
        };
        let mut u1 = TypeUnifier::new(2);
        let r1 = u1.solve(&[is_ptr(0, 1), has_int_ty(9)]);
        let mut u2 = TypeUnifier::new(2);
        let r2 = u2.solve(&[has_int_ty(9), is_ptr(0, 1)]);
        assert!(r1.is_err() && r2.is_err(), "expected conflict both orders: {r1:?} vs {r2:?}");
    }

    /// Regression: two `IsPointerTo` constraints with different pointee vars
    /// on the same pointer class dropped the second pointee entirely; the
    /// pointees must instead be unified so both carry the pointed-to type.
    #[test]
    fn regression_two_pointees_are_unified_not_dropped() {
        let mut u = TypeUnifier::new(4);
        let r = u.solve(&[is_ptr(0, 1), is_ptr(0, 2), has_int(1, 4, true)]).unwrap();
        // Var 2 is the same storage as var 1 → must resolve to i32 too.
        assert!(
            matches!(r.get(tv(2)), RecoveredType::Int { width: 4, signed: true }),
            "second pointee lost the unified type: {:?}",
            r.get(tv(2))
        );
    }

    /// Regression: `FieldAccess`/`PointerArithmetic` set `is_pointer` without
    /// checking an existing concrete non-pointer type, so
    /// `[IsArray, FieldAccess]` succeeded while `[FieldAccess, IsArray]`
    /// errored.
    #[test]
    fn regression_fieldaccess_vs_array_symmetric() {
        let fa = |id| {
            TypeConstraint::certain(
                id,
                ConstraintKind::FieldAccess { struct_var: tv(0), field_var: tv(1), byte_offset: 8 },
                Provenance::new(0, ""),
            )
        };
        let mut u1 = TypeUnifier::new(3);
        let r1 = u1.solve(&[is_array(0, 4), fa(9)]);
        let mut u2 = TypeUnifier::new(3);
        let r2 = u2.solve(&[fa(9), is_array(0, 4)]);
        assert_eq!(r1.is_ok(), r2.is_ok(), "order-dependent outcome: {r1:?} vs {r2:?}");
    }

    /// Resolve `Var` indirections (bounded depth) so results from different
    /// constraint orders — which pick different class representatives — can
    /// be compared structurally.
    fn normalize(t: &RecoveredType, res: &UnificationResult, depth: u8) -> RecoveredType {
        if depth == 0 {
            return RecoveredType::Unknown;
        }
        match t {
            RecoveredType::Var(v) => {
                let inner = res.get(*v);
                if matches!(inner, RecoveredType::Var(w) if w == v) {
                    RecoveredType::Unknown
                } else {
                    normalize(inner, res, depth - 1)
                }
            }
            RecoveredType::Pointer(inner) => {
                RecoveredType::Pointer(Box::new(normalize(inner, res, depth - 1)))
            }
            other => other.clone(),
        }
    }

    fn random_constraints(s: &mut u64, nvars: u32, n: usize) -> Vec<TypeConstraint> {
        let mut cs = Vec::new();
        for i in 0..n {
            let v1 = (xs(s) % u64::from(nvars)) as u32;
            let v2 = (xs(s) % u64::from(nvars)) as u32;
            let kind = match xs(s) % 8 {
                0 => ConstraintKind::Equal { lhs: tv(v1), rhs: tv(v2) },
                1 => ConstraintKind::IsInteger {
                    var: tv(v1),
                    min_width: [1u8, 2, 4, 8][(xs(s) % 4) as usize],
                    signed: match xs(s) % 3 {
                        0 => None,
                        1 => Some(true),
                        _ => Some(false),
                    },
                },
                2 => ConstraintKind::IsFloat { var: tv(v1), width: if xs(s) % 2 == 0 { 4 } else { 8 } },
                3 => ConstraintKind::IsPointerTo { ptr: tv(v1), pointee: tv(v2) },
                4 => ConstraintKind::IsCallable { callee: tv(v1), param_count: (xs(s) % 4) as usize },
                5 => ConstraintKind::IsArray { arr: tv(v1), elem: tv(v2), min_count: 1 + (xs(s) % 8) as usize },
                6 => ConstraintKind::FieldAccess { struct_var: tv(v1), field_var: tv(v2), byte_offset: (xs(s) % 64) as u32 },
                _ => ConstraintKind::PointerArithmetic { result: tv(v1), base: tv(v2), offset: tv((xs(s) % u64::from(nvars)) as u32) },
            };
            cs.push(TypeConstraint::certain(
                u32::try_from(i).unwrap(),
                kind,
                Provenance::new(0, ""),
            ));
        }
        cs
    }

    fn shuffle(cs: &mut [TypeConstraint], s: &mut u64) {
        for i in (1..cs.len()).rev() {
            let j = (xs(s) % (i as u64 + 1)) as usize;
            cs.swap(i, j);
        }
    }

    /// Union-find solve() must be a function of the constraint *set*, not the
    /// insertion order: for random constraint sets, a random permutation must
    /// agree on Ok/Err, and on Ok yield the same normalized type per var.
    #[test]
    fn prop_solve_is_permutation_invariant() {
        let mut s = 0xdead_beef_cafe_f00du64;
        for iter in 0..500 {
            let nvars = 6;
            let cs = random_constraints(&mut s, nvars, 8);
            let mut permuted = cs.clone();
            shuffle(&mut permuted, &mut s);

            let r1 = TypeUnifier::new(nvars).solve(&cs);
            let r2 = TypeUnifier::new(nvars).solve(&permuted);
            match (&r1, &r2) {
                (Ok(a), Ok(b)) => {
                    for v in 0..nvars {
                        let ta = normalize(a.get(tv(v)), a, 8);
                        let tb = normalize(b.get(tv(v)), b, 8);
                        assert_eq!(
                            ta, tb,
                            "iter {iter}: var {v} differs under permutation\norig: {cs:?}\nperm: {permuted:?}"
                        );
                    }
                }
                (Err(_), Err(_)) => {}
                _ => panic!(
                    "iter {iter}: Ok/Err depends on constraint order: {r1:?} vs {r2:?}\norig: {cs:?}\nperm: {permuted:?}"
                ),
            }
        }
    }

    #[test]
    fn test_class_count_and_pointers() {
        let mut u = TypeUnifier::new(3);
        let cs = vec![eq(0, 1), is_ptr(1, 2), has_int(2, 4, true)];
        let result = u.solve(&cs).unwrap();
        // {0,1} form one class, {2} forms another => 2 classes.
        assert_eq!(result.class_count, 2);
        let ptrs = result.pointers();
        assert!(ptrs.iter().any(|(v, _)| *v == tv(0) || *v == tv(1)));
    }

    #[test]
    fn test_pointee_preserved_through_union_of_pointer_class() {
        // Regression test: a variable unified (via Equal) with a pointer
        // whose pointee is already known must retain the pointee, not just
        // the bare `is_pointer` flag, once solved.
        let mut u = TypeUnifier::new(3);
        let cs = vec![
            is_ptr(1, 2),
            has_int(2, 4, true),
            eq(0, 1),
        ];
        let result = u.solve(&cs).unwrap();
        assert!(result.get(tv(0)).is_pointer());
        assert!(result.get(tv(1)).is_pointer());
        // The pointee should resolve through to the concrete int type,
        // not collapse to Pointer(Unknown).
        match result.get(tv(0)) {
            RecoveredType::Pointer(inner) => {
                assert!(
                    !matches!(**inner, RecoveredType::Unknown),
                    "pointee information was lost during union merge"
                );
            }
            other => panic!("expected pointer type, got {other:?}"),
        }
    }
}
