//! Interprocedural type propagation.
//!
//! Single-function recovery leaves many types at their weak defaults (`int`,
//! `void`). Across a whole program we can do better: the *arguments* a function
//! is called with at every call site constrain its parameter types, and a
//! callee's *return* type constrains the variable a caller assigns the result
//! to. This module holds a pure, side-effect-free core that collects those
//! cross-function observations and unifies them into refined types.
//!
//! It is deliberately independent of the decompiler pipeline: callers feed it
//! [`FunctionTypeSummary`] rows plus observed call-argument types, then read
//! back [`TypeRefinement`]s to apply. Wiring into the batch decompiler is a
//! separate step.

use std::collections::HashMap;

/// How specific a type string is. Higher wins during unification.
///
/// The weak defaults produced by single-function recovery (`void`, `int`,
/// unknown/empty) rank low so that any concrete evidence from a call site can
/// override them, while already-specific types (pointers, named types) rank
/// high and are not clobbered by a weaker guess.
#[must_use]
pub fn type_specificity(ty: &str) -> u8 {
    let t = ty.trim();
    if t.is_empty() || t == "void" || t == "unknown" {
        0
    } else if t == "int" || t == "int32_t" || t == "unsigned" || t == "uint32_t" {
        1
    } else {
        // Pointers, char*, named structs, sized/typed values: concrete evidence.
        2
    }
}

/// Pick the more specific of two types. On a tie in specificity the first
/// (incumbent) wins, so already-recovered types are conservative anchors.
#[must_use]
pub fn unify_type(incumbent: &str, candidate: &str) -> String {
    if type_specificity(candidate) > type_specificity(incumbent) {
        candidate.trim().to_string()
    } else {
        incumbent.trim().to_string()
    }
}

/// A per-function type summary as recovered by single-function analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionTypeSummary {
    /// Function entry address (the interprocedural key).
    pub address: u64,
    /// Function name (for diagnostics / by-name lookup).
    pub name: String,
    /// Recovered return type (`"void"`, `"int"`, `"char *"`, …).
    pub return_type: String,
    /// Recovered parameter types in source order.
    pub param_types: Vec<String>,
}

/// A refinement the caller should apply after propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRefinement {
    /// Address of the function whose signature is refined.
    pub function: u64,
    /// `Some(i)` = parameter `i`; `None` = the return type.
    pub param_index: Option<usize>,
    /// The type before refinement.
    pub from: String,
    /// The refined (more specific) type.
    pub to: String,
}

/// Collects cross-function type observations and unifies them.
#[derive(Debug, Default)]
pub struct InterprocTypeTable {
    fns: HashMap<u64, FunctionTypeSummary>,
    /// Argument types observed at call sites, keyed by `(callee_addr, arg_idx)`.
    observed_args: HashMap<(u64, usize), Vec<String>>,
    /// Return types observed for the destination of a callee's result, keyed by
    /// callee address (a caller that assigns `x = callee()` where `x` already
    /// has a concrete type constrains the return type upward).
    observed_returns: HashMap<u64, Vec<String>>,
}

impl InterprocTypeTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function's recovered signature.
    pub fn add_function(&mut self, summary: FunctionTypeSummary) {
        self.fns.insert(summary.address, summary);
    }

    /// Record the type of the `arg_idx`-th argument passed to `callee` at some
    /// call site.
    pub fn record_call_arg(&mut self, callee: u64, arg_idx: usize, ty: impl Into<String>) {
        self.observed_args
            .entry((callee, arg_idx))
            .or_default()
            .push(ty.into());
    }

    /// Record the type of a variable that receives `callee`'s return value.
    pub fn record_return_use(&mut self, callee: u64, ty: impl Into<String>) {
        self.observed_returns.entry(callee).or_default().push(ty.into());
    }

    /// The recovered return type of `callee`, if known.
    #[must_use]
    pub fn return_type_of(&self, callee: u64) -> Option<&str> {
        self.fns.get(&callee).map(|f| f.return_type.as_str())
    }

    /// Resolve parameter `idx` of `callee` by unifying its recovered type with
    /// every argument type observed at its call sites.
    #[must_use]
    pub fn resolved_param_type(&self, callee: u64, idx: usize) -> Option<String> {
        let recovered = self.fns.get(&callee)?.param_types.get(idx)?;
        let mut ty = recovered.clone();
        if let Some(observed) = self.observed_args.get(&(callee, idx)) {
            for obs in observed {
                ty = unify_type(&ty, obs);
            }
        }
        Some(ty)
    }

    /// Compute every refinement implied by the collected observations. Only
    /// entries that actually change a type are returned.
    #[must_use]
    pub fn propagate(&self) -> Vec<TypeRefinement> {
        let mut out = Vec::new();
        for (&addr, f) in &self.fns {
            // Parameters: unify with observed call arguments.
            for (idx, recovered) in f.param_types.iter().enumerate() {
                if let Some(resolved) = self.resolved_param_type(addr, idx)
                    && &resolved != recovered
                {
                    out.push(TypeRefinement {
                        function: addr,
                        param_index: Some(idx),
                        from: recovered.clone(),
                        to: resolved,
                    });
                }
            }
            // Return type: unify with types of variables receiving the result.
            if let Some(observed) = self.observed_returns.get(&addr) {
                let mut ret = f.return_type.clone();
                for obs in observed {
                    ret = unify_type(&ret, obs);
                }
                if ret != f.return_type {
                    out.push(TypeRefinement {
                        function: addr,
                        param_index: None,
                        from: f.return_type.clone(),
                        to: ret,
                    });
                }
            }
        }
        // Deterministic order: by function address, then params before return.
        out.sort_by(|a, b| {
            a.function
                .cmp(&b.function)
                .then(param_key(a.param_index).cmp(&param_key(b.param_index)))
        });
        out
    }
}

/// Sort key placing parameters (0,1,2,…) before the return type.
const fn param_key(idx: Option<usize>) -> usize {
    match idx {
        Some(i) => i,
        None => usize::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summ(addr: u64, ret: &str, params: &[&str]) -> FunctionTypeSummary {
        FunctionTypeSummary {
            address: addr,
            name: format!("sub_{addr:x}"),
            return_type: ret.to_string(),
            param_types: params.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn specificity_ordering() {
        assert!(type_specificity("char *") > type_specificity("int"));
        assert!(type_specificity("int") > type_specificity("void"));
        assert_eq!(type_specificity(""), 0);
    }

    #[test]
    fn unify_prefers_specific() {
        assert_eq!(unify_type("int", "char *"), "char *");
        assert_eq!(unify_type("char *", "int"), "char *"); // incumbent stronger
        assert_eq!(unify_type("void", "int"), "int");
    }

    #[test]
    fn param_refined_from_call_args() {
        let mut t = InterprocTypeTable::new();
        t.add_function(summ(0x1000, "void", &["int"]));
        // Two callers pass a pointer as the first argument.
        t.record_call_arg(0x1000, 0, "char *");
        t.record_call_arg(0x1000, 0, "char *");
        assert_eq!(t.resolved_param_type(0x1000, 0).as_deref(), Some("char *"));

        let refs = t.propagate();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].function, 0x1000);
        assert_eq!(refs[0].param_index, Some(0));
        assert_eq!(refs[0].to, "char *");
    }

    #[test]
    fn return_type_propagates_to_caller_lookup() {
        let mut t = InterprocTypeTable::new();
        t.add_function(summ(0x2000, "char *", &[]));
        assert_eq!(t.return_type_of(0x2000), Some("char *"));
        assert_eq!(t.return_type_of(0x9999), None);
    }

    #[test]
    fn return_type_refined_from_use() {
        let mut t = InterprocTypeTable::new();
        t.add_function(summ(0x3000, "int", &[]));
        t.record_return_use(0x3000, "void *");
        let refs = t.propagate();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].param_index, None);
        assert_eq!(refs[0].to, "void *");
    }

    #[test]
    fn no_refinement_when_already_specific() {
        let mut t = InterprocTypeTable::new();
        t.add_function(summ(0x4000, "char *", &["char *"]));
        t.record_call_arg(0x4000, 0, "int"); // weaker — must not clobber
        t.record_return_use(0x4000, "int");
        assert!(t.propagate().is_empty());
    }
}
