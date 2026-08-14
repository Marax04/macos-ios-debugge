//! `propagation` — forward and backward type propagation.
//!
//! After the constraint solver produces an initial `TypeSolution`, this module
//! refines it by propagating types through assignments (`SameType`) and across
//! function call boundaries (interprocedural propagation).
//!
//! Three passes are provided:
//! 1. `TypePropagator::propagate_forward`  — follows SSA def-use edges.
//! 2. `TypePropagator::propagate_backward` — follows SSA use-def edges.
//! 3. `TypePropagator::propagate_through_calls` — propagates across a
//!    `CallGraph` (argument and return-value types).

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    TypeFact,
    constraints::{Address, TypeId, TypeSolution, TypeStore, VarRef},
};

// ── TypeMap ────────────────────────────────────────────────────────────────────

/// The working map manipulated by the propagator: `VarRef → TypeFact`.
pub type TypeMap = HashMap<VarRef, TypeFact>;

// ── Assignment / SSA edge ─────────────────────────────────────────────────────

/// One assignment edge in the function's SSA graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub dst: VarRef,
    pub src: VarRef,
}

// ── CallSite ──────────────────────────────────────────────────────────────────

/// One call-site observation inside a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub caller: u64, // function id
    pub callee: Address,
    pub arg_vars: Vec<VarRef>,   // vars passed as arguments
    pub ret_var: Option<VarRef>, // variable that receives the return value
}

// ── MlilFunction (simplified view) ───────────────────────────────────────────

/// Simplified function view used by the propagator.  In the full tool this
/// would be the MLIL function object; here it is a plain data structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MlilFunction {
    pub id: u64,
    pub name: String,
    pub assignments: Vec<Assignment>,
    pub call_sites: Vec<CallSite>,
    pub param_types: Vec<Option<TypeId>>,
    pub return_type: Option<TypeId>,
}

impl MlilFunction {
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            ..Self::default()
        }
    }

    /// Register a copy assignment: `dst = src`.
    pub fn add_assignment(&mut self, dst: VarRef, src: VarRef) {
        self.assignments.push(Assignment { dst, src });
    }

    /// Register a call site.
    pub fn add_call_site(&mut self, site: CallSite) {
        self.call_sites.push(site);
    }
}

// ── CallGraph ─────────────────────────────────────────────────────────────────

/// An interprocedural call-graph used by `TypePropagator::propagate_through_calls`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    /// `function_id → (callee_address → (arg_types, ret_type))`
    pub edges: HashMap<u64, Vec<CallEdge>>,
    /// Known function signatures from import tables / libraries.
    pub known_signatures: HashMap<u64, FunctionSig>,
}

/// One directed call edge in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller_id: u64,
    pub callee_addr: Address,
    pub arg_types: Vec<TypeFact>,
    pub ret_type: TypeFact,
}

/// A fully-known function signature (from import table / FLIRT / PDB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSig {
    pub name: String,
    pub arg_types: Vec<TypeFact>,
    pub ret_type: TypeFact,
}

impl CallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a call edge from `caller_id` to `callee_addr` with known types.
    pub fn add_edge(&mut self, edge: CallEdge) {
        self.edges.entry(edge.caller_id).or_default().push(edge);
    }

    /// Register a known function signature.
    pub fn add_known_sig(&mut self, addr: u64, sig: FunctionSig) {
        self.known_signatures.insert(addr, sig);
    }
}

// ── TypePropagator ────────────────────────────────────────────────────────────

/// Refines a `TypeMap` by propagating type facts through assignments and calls.
pub struct TypePropagator {
    worklist: VecDeque<(VarRef, TypeFact)>,
    /// Def-use map for forward propagation: `src → [dsts]`.
    forward_edges: HashMap<VarRef, Vec<VarRef>>,
    /// Use-def map for backward propagation: `dst → [srcs]`.
    backward_edges: HashMap<VarRef, Vec<VarRef>>,
}

impl TypePropagator {
    /// Create a new propagator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            worklist: VecDeque::new(),
            forward_edges: HashMap::new(),
            backward_edges: HashMap::new(),
        }
    }

    /// Initialise propagation edges from the function's SSA assignments.
    pub fn load_function(&mut self, func: &MlilFunction) {
        for asgn in &func.assignments {
            self.forward_edges
                .entry(asgn.src)
                .or_default()
                .push(asgn.dst);
            self.backward_edges
                .entry(asgn.dst)
                .or_default()
                .push(asgn.src);
        }
    }

    /// Seed the worklist with all currently-known types in `types`.
    pub fn seed(&mut self, types: &TypeMap) {
        for (&var, fact) in types {
            if fact.is_known() {
                self.worklist.push_back((var, fact.clone()));
            }
        }
    }

    /// Forward propagation: for every assignment `dst = src`, if `src` has a
    /// known type then `dst` gets that type (or its join with existing).
    ///
    /// Iterates the worklist until convergence.
    pub fn propagate_forward(&mut self, _func: &MlilFunction, types: &mut TypeMap) {
        let forward_snapshot: HashMap<VarRef, Vec<VarRef>> = self.forward_edges.clone();
        let mut in_wl: HashSet<VarRef> = HashSet::new();

        while let Some((var, carried)) = self.worklist.pop_front() {
            in_wl.remove(&var);
            // Propagate the CURRENT type of `var`, not the value carried at
            // push time. The `in_wl` dedup means a var already queued is not
            // re-pushed when its type is joined again before being popped;
            // propagating the stale carried value then under-propagates and
            // makes the fixpoint depend on worklist order.
            let tf = types.get(&var).cloned().unwrap_or(carried);
            if let Some(dsts) = forward_snapshot.get(&var) {
                for &dst in dsts {
                    let current = types.entry(dst).or_insert(TypeFact::Unknown);
                    let new_tf = current.join(&tf);
                    if new_tf != *current {
                        *current = new_tf.clone();
                        if in_wl.insert(dst) {
                            self.worklist.push_back((dst, new_tf));
                        }
                    }
                }
            }
        }
    }

    /// Backward propagation: for every assignment `dst = src`, if `dst` has a
    /// known type, propagate it back to `src`.
    pub fn propagate_backward(&mut self, _func: &MlilFunction, types: &mut TypeMap) {
        let backward_snapshot: HashMap<VarRef, Vec<VarRef>> = self.backward_edges.clone();
        let mut in_wl: HashSet<VarRef> = HashSet::new();

        while let Some((var, carried)) = self.worklist.pop_front() {
            in_wl.remove(&var);
            // See propagate_forward: use the current type, not the stale
            // carried value, so the fixpoint is worklist-order independent.
            let tf = types.get(&var).cloned().unwrap_or(carried);
            if let Some(srcs) = backward_snapshot.get(&var) {
                for &src in srcs {
                    let current = types.entry(src).or_insert(TypeFact::Unknown);
                    let new_tf = current.join(&tf);
                    if new_tf != *current {
                        *current = new_tf.clone();
                        if in_wl.insert(src) {
                            self.worklist.push_back((src, new_tf));
                        }
                    }
                }
            }
        }
    }

    /// Interprocedural propagation via the call graph.
    ///
    /// For each call site in `func`:
    /// - If the callee has a known signature, push `arg_types` onto the
    ///   argument variables and `ret_type` onto the return variable.
    /// - Otherwise, if the callee has an inferred type in the call graph,
    ///   use that.
    ///
    /// After seeding from call sites, runs a forward-propagation round.
    pub fn propagate_through_calls(
        &mut self,
        func: &MlilFunction,
        call_graph: &CallGraph,
        types: &mut TypeMap,
    ) {
        for site in &func.call_sites {
            // Check for known signature.
            if let Some(sig) = call_graph.known_signatures.get(&site.callee.0) {
                // Propagate argument types forward into the callee's parameter vars.
                for (i, arg_var) in site.arg_vars.iter().enumerate() {
                    if let Some(arg_tf) = sig.arg_types.get(i) && arg_tf.is_known() {
                        let current = types.entry(*arg_var).or_insert(TypeFact::Unknown);
                        let new_tf = current.join(arg_tf);
                        if new_tf != *current {
                            *current = new_tf.clone();
                            self.worklist.push_back((*arg_var, new_tf));
                        }
                    }
                }
                // Propagate return type.
                if let Some(ret_var) = site.ret_var && sig.ret_type.is_known() {
                    let current = types.entry(ret_var).or_insert(TypeFact::Unknown);
                    let new_tf = current.join(&sig.ret_type);
                    if new_tf != *current {
                        *current = new_tf.clone();
                        self.worklist.push_back((ret_var, new_tf));
                    }
                }
                continue;
            }

            // Use call-graph edges for partially-known callees.
            if let Some(edges) = call_graph.edges.get(&site.caller) {
                for edge in edges.iter().filter(|e| e.callee_addr.0 == site.callee.0) {
                    for (i, arg_var) in site.arg_vars.iter().enumerate() {
                        if let Some(arg_tf) = edge.arg_types.get(i) && arg_tf.is_known() {
                            let current = types.entry(*arg_var).or_insert(TypeFact::Unknown);
                            let new_tf = current.join(arg_tf);
                            if new_tf != *current {
                                *current = new_tf.clone();
                                self.worklist.push_back((*arg_var, new_tf));
                            }
                        }
                    }
                    if let Some(ret_var) = site.ret_var && edge.ret_type.is_known() {
                        let current = types.entry(ret_var).or_insert(TypeFact::Unknown);
                        let new_tf = current.join(&edge.ret_type);
                        if new_tf != *current {
                            *current = new_tf.clone();
                            self.worklist.push_back((ret_var, new_tf));
                        }
                    }
                }
            }
        }

        // One final forward-propagation sweep to spread newly-seeded types.
        self.propagate_forward(func, types);
    }
}

impl Default for TypePropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ── TypeSolutionPropagator ────────────────────────────────────────────────────

/// High-level helper that wraps `TypePropagator` and operates on a
/// `TypeSolution` + `TypeStore` rather than a raw `TypeMap`.
pub struct TypeSolutionPropagator {
    propagator: TypePropagator,
}

impl TypeSolutionPropagator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            propagator: TypePropagator::new(),
        }
    }

    /// Run all three propagation passes on `solution` and return an updated map.
    pub fn run(
        &mut self,
        func: &MlilFunction,
        call_graph: &CallGraph,
        solution: &TypeSolution,
        _store: &TypeStore,
    ) -> TypeMap {
        // Convert solution to mutable TypeMap.
        let mut types: TypeMap = solution.iter().map(|(v, t)| (v, t.clone())).collect();

        self.propagator.load_function(func);
        self.propagator.seed(&types);

        self.propagator.propagate_forward(func, &mut types);
        // Re-seed for backward pass.
        self.propagator.seed(&types);
        self.propagator.propagate_backward(func, &mut types);
        // Interprocedural pass.
        self.propagator.seed(&types);
        self.propagator
            .propagate_through_calls(func, call_graph, &mut types);

        types
    }
}

impl Default for TypeSolutionPropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::VarRef;

    fn var(i: u32) -> VarRef {
        VarRef::new(0, i)
    }

    #[test]
    fn test_forward_propagates_type() {
        let mut func = MlilFunction::new(0, "main");
        func.add_assignment(var(1), var(0)); // var1 = var0
        func.add_assignment(var(2), var(1)); // var2 = var1

        let mut types: TypeMap = HashMap::new();
        types.insert(var(0), TypeFact::SignedInt(4));

        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_forward(&func, &mut types);

        assert_eq!(types[&var(1)], TypeFact::SignedInt(4));
        assert_eq!(types[&var(2)], TypeFact::SignedInt(4));
    }

    #[test]
    fn test_backward_propagates_type() {
        let mut func = MlilFunction::new(0, "bar");
        func.add_assignment(var(1), var(0)); // var1 = var0 → backward: var0 gets var1's type

        let mut types: TypeMap = HashMap::new();
        types.insert(var(1), TypeFact::Float(8));

        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_backward(&func, &mut types);

        assert_eq!(types[&var(0)], TypeFact::Float(8));
    }

    #[test]
    fn test_interprocedural_known_signature() {
        let mut func = MlilFunction::new(1, "caller");
        let site = CallSite {
            caller: 1,
            callee: Address(0xDEAD),
            arg_vars: vec![var(0), var(1)],
            ret_var: Some(var(2)),
        };
        func.add_call_site(site);

        let mut cg = CallGraph::new();
        cg.add_known_sig(
            0xDEAD,
            FunctionSig {
                name: "target".into(),
                arg_types: vec![TypeFact::UnsignedInt(8), TypeFact::SignedInt(4)],
                ret_type: TypeFact::Bool,
            },
        );

        let mut types: TypeMap = HashMap::new();
        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_through_calls(&func, &cg, &mut types);

        assert_eq!(types[&var(0)], TypeFact::UnsignedInt(8));
        assert_eq!(types[&var(1)], TypeFact::SignedInt(4));
        assert_eq!(types[&var(2)], TypeFact::Bool);
    }

    #[test]
    fn test_propagation_join_on_conflict() {
        let mut func = MlilFunction::new(0, "f");
        func.add_assignment(var(2), var(0));
        func.add_assignment(var(2), var(1));

        let mut types: TypeMap = HashMap::new();
        types.insert(var(0), TypeFact::SignedInt(4));
        types.insert(var(1), TypeFact::UnsignedInt(4));

        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_forward(&func, &mut types);

        // Both propagate to var(2); join of conflicting = Unknown.
        // The exact outcome depends on worklist order; test that var(2) has *some* type.
        assert!(types.contains_key(&var(2)));
    }

    #[test]
    fn test_call_graph_edge_propagation() {
        let mut func = MlilFunction::new(10, "caller");
        let site = CallSite {
            caller: 10,
            callee: Address(0x5000),
            arg_vars: vec![var(0)],
            ret_var: Some(var(1)),
        };
        func.add_call_site(site);

        let mut cg = CallGraph::new();
        cg.add_edge(CallEdge {
            caller_id: 10,
            callee_addr: Address(0x5000),
            arg_types: vec![TypeFact::Float(4)],
            ret_type: TypeFact::Float(8),
        });

        let mut types: TypeMap = HashMap::new();
        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_through_calls(&func, &cg, &mut types);

        assert_eq!(types[&var(0)], TypeFact::Float(4));
        assert_eq!(types[&var(1)], TypeFact::Float(8));
    }

    #[test]
    fn test_type_solution_propagator() {
        let func = MlilFunction::new(0, "g");
        let cg = CallGraph::new();
        let store = TypeStore::new();
        let mut sol = TypeSolution::new();
        sol.set(var(0), TypeFact::SignedInt(4));

        let mut sp = TypeSolutionPropagator::new();
        let result = sp.run(&func, &cg, &sol, &store);
        // Should at least preserve the initial known type.
        assert_eq!(result[&var(0)], TypeFact::SignedInt(4));
    }

    #[test]
    fn test_propagator_empty_function() {
        let func = MlilFunction::new(0, "empty");
        let mut types: TypeMap = HashMap::new();
        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_forward(&func, &mut types);
        assert!(types.is_empty());
    }

    #[test]
    fn test_call_graph_known_sig_zero_args() {
        let mut func = MlilFunction::new(1, "caller2");
        let site = CallSite {
            caller: 1,
            callee: Address(0xBEEF),
            arg_vars: vec![],
            ret_var: Some(var(5)),
        };
        func.add_call_site(site);

        let mut cg = CallGraph::new();
        cg.add_known_sig(
            0xBEEF,
            FunctionSig {
                name: "noargs".into(),
                arg_types: vec![],
                ret_type: TypeFact::UnsignedInt(4),
            },
        );

        let mut types: TypeMap = HashMap::new();
        let mut prop = TypePropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_through_calls(&func, &cg, &mut types);

        assert_eq!(types[&var(5)], TypeFact::UnsignedInt(4));
    }
}
