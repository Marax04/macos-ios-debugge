//! `upvalue_analysis` â€” Upvalue analysis across prototype boundaries.
//!
//! This module provides:
//! - [`UpvalDef`]         â€” enriched upvalue definition with closure kind
//! - [`ClosureKind`]      â€” whether an upvalue is stack-local or from a parent uv
//! - [`UpvalGraph`]       â€” cross-prototype upvalue dependency graph
//! - [`SharedUpval`]      â€” an upvalue shared among multiple prototypes
//! - [`print_upvalue_tree`] â€” pretty-print the upvalue tree for all protos
//! - [`analyze_upvalues`]  â€” analyze a flat list of protos into an `UpvalGraph`
//!
//! # Background
//! `LuaJIT` upvalues come in two kinds:
//! 1. **Stack-based (OPEN)**: The captured variable still lives on the enclosing
//!    function's stack frame.  `UpvalDescriptor::is_stack() == true`.
//! 2. **Parent-upvalue (CLOSED/INHERITED)**: The variable was already closed
//!    over by an ancestor and the child inherits it by index.
//!    `UpvalDescriptor::is_stack() == false`.
//!
//! Upvalue sharing occurs when multiple nested functions capture the same
//! variable â€” they share a single `UpValue` GC object so mutations are visible
//! to all closures.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bytecode_format::UpvalDescriptor;
use crate::{LjProto, LjUpvalue};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ClosureKind
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// How an upvalue is captured from the enclosing scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureKind {
    /// The upvalue is closed over a live stack local of the **direct parent**
    /// function (i.e. the variable was not yet closed when this closure was
    /// created).  `UpvalDescriptor::is_stack() == true`.
    Stack,
    /// The upvalue is inherited from the **parent's upvalue list**.  The slot
    /// field names the index into the parent's upvalue array.
    /// `UpvalDescriptor::is_stack() == false`.
    ParentUv,
    /// Upvalue added synthetically (e.g. `_ENV` at the top-level chunk).
    Synthetic,
}

impl fmt::Display for ClosureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Stack => "stack",
            Self::ParentUv => "parent-uv",
            Self::Synthetic => "synthetic",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UpvalDef â€” enriched upvalue definition
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Enriched upvalue definition, combining the raw `LjUpvalue` with analysis
/// results computed from the enclosing prototype chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpvalDef {
    /// Zero-based upvalue index within this prototype's upvalue list.
    pub index: usize,
    /// Slot field from the raw descriptor:
    /// - If `kind == Stack`: stack slot of the captured local.
    /// - If `kind == ParentUv`: upvalue index in the parent's upvalue list.
    pub slot: u8,
    /// How this upvalue is captured.
    pub kind: ClosureKind,
    /// True if the upvalue descriptor marks this as immutable (never written).
    pub is_immutable: bool,
    /// Declared name, if available from debug info.
    pub name: Option<String>,
    /// Index of the parent prototype in the flat proto list (`None` for the
    /// root prototype or when the parent is unknown).
    pub parent_proto_index: Option<usize>,
    /// If `kind == ParentUv`, the `UpvalDef` index in the parent this refers to.
    pub parent_upval_index: Option<usize>,
}

impl UpvalDef {
    /// Construct from a raw `LjUpvalue` descriptor for an anonymous upvalue.
    #[must_use]
    pub fn from_raw(index: usize, uv: &LjUpvalue) -> Self {
        let kind = if uv.is_local {
            ClosureKind::Stack
        } else {
            ClosureKind::ParentUv
        };
        Self {
            index,
            slot: uv.slot,
            kind,
            is_immutable: false,
            name: uv.name.clone(),
            parent_proto_index: None,
            parent_upval_index: None,
        }
    }

    /// Construct from a raw `UpvalDescriptor`.
    #[must_use]
    pub const fn from_descriptor(index: usize, desc: &UpvalDescriptor, name: Option<String>) -> Self {
        let kind = if desc.is_stack() {
            ClosureKind::Stack
        } else {
            ClosureKind::ParentUv
        };
        Self {
            index,
            slot: desc.slot(),
            kind,
            is_immutable: desc.is_immutable(),
            name,
            parent_proto_index: None,
            parent_upval_index: None,
        }
    }

    /// True if this upvalue closes over a live stack local.
    #[must_use]
    pub fn is_stack_local(&self) -> bool {
        self.kind == ClosureKind::Stack
    }

    /// True if this upvalue inherits from a parent's upvalue.
    #[must_use]
    pub fn is_inherited(&self) -> bool {
        self.kind == ClosureKind::ParentUv
    }

    /// Display name: the `name` field if present, otherwise `"uv[N]"`.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("uv[{}]", self.index))
    }
}

impl fmt::Display for UpvalDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} kind={} slot={} immutable={}",
            self.index,
            self.display_name(),
            self.kind,
            self.slot,
            self.is_immutable
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ProtoUpvalInfo â€” all upvalue info for one prototype
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Upvalue analysis results for a single prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoUpvalInfo {
    /// Index of this prototype in the flat proto list.
    pub proto_index: usize,
    /// Display name / source identifier for this prototype.
    pub name: Option<String>,
    /// Upvalue definitions for this prototype.
    pub upvals: Vec<UpvalDef>,
    /// Indices of child prototypes (inner closures defined within this one).
    pub children: Vec<usize>,
    /// Index of the parent prototype, if any.
    pub parent: Option<usize>,
}

impl ProtoUpvalInfo {
    /// Number of stack-local upvalues in this prototype.
    #[must_use]
    pub fn stack_count(&self) -> usize {
        self.upvals.iter().filter(|u| u.is_stack_local()).count()
    }

    /// Number of inherited upvalues.
    #[must_use]
    pub fn inherited_count(&self) -> usize {
        self.upvals.iter().filter(|u| u.is_inherited()).count()
    }

    /// Find an upvalue by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&UpvalDef> {
        self.upvals.iter().find(|u| u.name.as_deref() == Some(name))
    }
}

impl fmt::Display for ProtoUpvalInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        write!(
            f,
            "Proto#{} [{}] uvs={} (stack={} inherit={})",
            self.proto_index,
            name,
            self.upvals.len(),
            self.stack_count(),
            self.inherited_count()
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SharedUpval â€” an upvalue shared among multiple prototypes
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Identifies a single logical variable that is captured by more than one
/// nested closure (i.e. a shared `UpValue` GC object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedUpval {
    /// Human-readable variable name (from debug info).
    pub name: Option<String>,
    /// The prototype indices and their local upvalue indices that share this var.
    pub references: Vec<(usize, usize)>,
}

impl SharedUpval {
    /// Number of prototypes sharing this upvalue.
    #[must_use]
    pub const fn share_count(&self) -> usize {
        self.references.len()
    }
}

impl fmt::Display for SharedUpval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        write!(f, "Shared({}) refs={}", name, self.references.len())?;
        for (pi, ui) in &self.references {
            write!(f, " [proto{pi}.uv{ui}]")?;
        }
        Ok(())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UpvalGraph â€” cross-prototype upvalue dependency graph
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Cross-prototype upvalue analysis graph.
///
/// After calling [`analyze_upvalues`], the graph contains per-prototype upvalue
/// info, the parentâ€“child relationship between prototypes, and detected shared
/// upvalues.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpvalGraph {
    /// Per-prototype upvalue info, indexed by proto position in the dump.
    pub protos: Vec<ProtoUpvalInfo>,
    /// Upvalues that are shared between at least two prototypes.
    pub shared: Vec<SharedUpval>,
    /// Total number of upvalue definitions across all prototypes.
    pub total_upvals: usize,
}

impl UpvalGraph {
    /// Return the `ProtoUpvalInfo` for proto `index`, if present.
    #[must_use]
    pub fn proto_info(&self, index: usize) -> Option<&ProtoUpvalInfo> {
        self.protos.get(index)
    }

    /// Collect all upvalue names that appear in **any** prototype.
    #[must_use]
    pub fn all_upval_names(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.protos
            .iter()
            .flat_map(|p| p.upvals.iter())
            .filter_map(|u| u.name.as_deref())
            .filter(|n| seen.insert(*n))
            .collect()
    }

    /// Total number of shared upvalue groups.
    #[must_use]
    pub const fn shared_count(&self) -> usize {
        self.shared.len()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// analyze_upvalues â€” build the UpvalGraph from a flat proto list
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Analyse the upvalue structure of all prototypes in `protos`.
///
/// `LuaJIT` dumps protos in reverse-dependency order (children first), so the
/// last proto is typically the root chunk.  This function reconstructs the
/// parentâ€“child relationships by tracking `FNEW` instructions and propagates
/// upvalue names.
#[must_use]
pub fn analyze_upvalues(protos: &[LjProto]) -> UpvalGraph {
    let mut graph = UpvalGraph::default();

    // Build per-prototype info
    for (idx, proto) in protos.iter().enumerate() {
        let upvals: Vec<UpvalDef> = proto
            .upvalues
            .iter()
            .enumerate()
            .map(|(i, uv)| UpvalDef::from_raw(i, uv))
            .collect();
        let name = proto
            .source_name
            .clone()
            .or_else(|| proto.upvalue_names.first().cloned());
        graph.total_upvals += upvals.len();
        graph.protos.push(ProtoUpvalInfo {
            proto_index: idx,
            name,
            upvals,
            children: vec![],
            parent: None,
        });
    }

    // Detect parentâ€“child relationships via FNEW instructions
    // FNEW: op=0x33, A=dst, D=child-proto index in KGC
    for (parent_idx, proto) in protos.iter().enumerate() {
        for instr in &proto.instructions {
            if instr.opcode() == 0x33 {
                // D field = KGC index of child proto
                let d = instr.d() as usize;
                // Child protos are stored in the KGC table in reverse order
                // (innermost first), but we need to map KGC index â†’ flat index.
                // In LuaJIT the KGC[0..num_children-1] at the *front* of the KGC
                // table are the child protos, in the order they appear as children.
                // The child proto at KGC[d] corresponds to proto[child_flat_index].
                // We perform a heuristic: assume protos before `parent_idx` are
                // candidates for children of this proto (they come first in the
                // linear dump).
                if d < parent_idx {
                    let child_flat_idx = d; // simplified 1-to-1 mapping
                    if child_flat_idx < graph.protos.len() && parent_idx < graph.protos.len() {
                        graph.protos[parent_idx].children.push(child_flat_idx);
                        graph.protos[child_flat_idx].parent = Some(parent_idx);
                    }
                }
            }
        }
    }

    // Detect shared upvalues: two protos sharing the same named upvalue that
    // traces back to the same stack slot in a common ancestor
    detect_shared_upvals(&mut graph);

    graph
}

/// Heuristic shared-upvalue detection: group upvalue defs by name across
/// all protos and mark any group with >1 member as "shared".
fn detect_shared_upvals(graph: &mut UpvalGraph) {
    // key = upvalue name, value = list of (proto_idx, upval_idx)
    let mut by_name: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

    for pinfo in &graph.protos {
        for udef in &pinfo.upvals {
            if let Some(name) = &udef.name
                && !name.is_empty() {
                    by_name
                        .entry(name.clone())
                        .or_default()
                        .push((pinfo.proto_index, udef.index));
                }
        }
    }

    for (name, refs) in by_name {
        if refs.len() > 1 {
            graph.shared.push(SharedUpval {
                name: Some(name),
                references: refs,
            });
        }
    }

    // Sort for determinism
    graph.shared.sort_by(|a, b| a.name.cmp(&b.name));
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// print_upvalue_tree â€” pretty-print upvalue tree
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Return a human-readable multi-line description of the upvalue tree.
///
/// Formats each prototype with its upvalue list, indented according to the
/// parentâ€“child depth.  If `graph.protos` is empty, returns an empty string.
#[must_use]
pub fn print_upvalue_tree(graph: &UpvalGraph) -> String {
    if graph.protos.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    // Find root protos (no parent)
    let roots: Vec<usize> = graph
        .protos
        .iter()
        .filter(|p| p.parent.is_none())
        .map(|p| p.proto_index)
        .collect();

    for root in roots {
        print_proto_node(graph, root, 0, &mut out);
    }

    // Append shared upvalue summary if any exist
    if !graph.shared.is_empty() {
        out.push_str("\nShared upvalues:\n");
        for s in &graph.shared {
            out.push_str(&format!("  {s}\n"));
        }
    }

    out
}

fn print_proto_node(graph: &UpvalGraph, idx: usize, depth: usize, out: &mut String) {
    let Some(pinfo) = graph.proto_info(idx) else {
        return;
    };
    let indent = "  ".repeat(depth);
    let name = pinfo.name.as_deref().unwrap_or("?");
    out.push_str(&format!(
        "{indent}Proto#{idx} [{name}]  upvals={}\n",
        pinfo.upvals.len()
    ));
    for udef in &pinfo.upvals {
        out.push_str(&format!("{indent}  {udef}\n"));
    }
    for &child in &pinfo.children {
        print_proto_node(graph, child, depth + 1, out);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UpvalUsage â€” per-instruction upvalue usage analysis
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Records which instructions in a prototype read or write each upvalue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpvalUsage {
    /// Upvalue index (0-based).
    pub uv_index: usize,
    /// PCs of UGET (read) instructions referencing this upvalue.
    pub reads: Vec<usize>,
    /// PCs of USET* (write) instructions referencing this upvalue.
    pub writes: Vec<usize>,
}

impl UpvalUsage {
    /// Number of reads.
    #[must_use]
    pub const fn read_count(&self) -> usize {
        self.reads.len()
    }
    /// Number of writes.
    #[must_use]
    pub const fn write_count(&self) -> usize {
        self.writes.len()
    }
    /// True if the upvalue is ever written to.
    #[must_use]
    pub const fn is_mutated(&self) -> bool {
        !self.writes.is_empty()
    }
    /// True if the upvalue is read at least once.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        !self.reads.is_empty()
    }
}

impl fmt::Display for UpvalUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "uv[{}] reads={} writes={}",
            self.uv_index,
            self.read_count(),
            self.write_count()
        )
    }
}

/// Compute per-upvalue read/write usage for all instructions in `proto`.
#[must_use]
pub fn compute_upval_usage(proto: &LjProto) -> Vec<UpvalUsage> {
    let n = proto.num_upvalues as usize;
    let mut usages: Vec<UpvalUsage> = (0..n)
        .map(|i| UpvalUsage {
            uv_index: i,
            reads: vec![],
            writes: vec![],
        })
        .collect();

    for (pc, instr) in proto.instructions.iter().enumerate() {
        let op = instr.opcode();
        let a = instr.a() as usize;
        let d = instr.d() as usize;
        match op {
            // UGET: A = upvalue[D]
            0x2D => {
                if d < n {
                    usages[d].reads.push(pc);
                }
            }
            // USETV, USETS, USETN, USETP: upvalue[A] = ...
            0x2E..=0x31 => {
                if a < n {
                    usages[a].writes.push(pc);
                }
            }
            // UCLO: close upvalues up to A
            0x32 => {
                for __item in usages.iter_mut().take(a.min(n.saturating_sub(1)) + 1) {
                    __item.writes.push(pc);
                }
            }
            _ => {}
        }
    }

    usages
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LjInstr, LjProtoFlags};

    fn make_proto(upvalues: Vec<LjUpvalue>, instrs: Vec<LjInstr>) -> LjProto {
        let ic = instrs.len() as u32;
        let uv_names: Vec<String> = upvalues
            .iter()
            .map(|u| u.name.clone().unwrap_or_default())
            .collect();
        LjProto {
            flags: LjProtoFlags::empty(),
            num_params: 0,
            frame_size: 4,
            num_upvalues: upvalues.len() as u8,
            is_vararg: false,
            instructions: instrs,
            upvalues: upvalues,
            kgc: vec![],
            kn: vec![],
            constants: vec![],
            instruction_count: ic,
            debug_info: None,
            source_name: None,
            first_line: 0,
            num_lines: 0,
            line_info: vec![],
            local_vars: vec![],
            upvalue_names: uv_names,
        }
    }

    fn env_upvalue() -> LjUpvalue {
        LjUpvalue {
            slot: 0,
            is_local: false,
            name: Some("_ENV".to_string()),
        }
    }

    // â”€â”€ ClosureKind â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_closure_kind_display() {
        assert_eq!(ClosureKind::Stack.to_string(), "stack");
        assert_eq!(ClosureKind::ParentUv.to_string(), "parent-uv");
        assert_eq!(ClosureKind::Synthetic.to_string(), "synthetic");
    }

    // â”€â”€ UpvalDef â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_upval_def_from_raw_local() {
        let uv = LjUpvalue {
            slot: 3,
            is_local: true,
            name: Some("x".to_string()),
        };
        let def = UpvalDef::from_raw(0, &uv);
        assert_eq!(def.kind, ClosureKind::Stack);
        assert_eq!(def.slot, 3);
        assert!(def.is_stack_local());
        assert!(!def.is_inherited());
        assert_eq!(def.display_name(), "x");
    }

    #[test]
    fn test_upval_def_from_raw_parent() {
        let uv = LjUpvalue {
            slot: 1,
            is_local: false,
            name: None,
        };
        let def = UpvalDef::from_raw(2, &uv);
        assert_eq!(def.kind, ClosureKind::ParentUv);
        assert!(def.is_inherited());
        assert_eq!(def.display_name(), "uv[2]");
    }

    #[test]
    fn test_upval_def_from_descriptor() {
        let desc = UpvalDescriptor::from_raw(0x8005); // stack, slot=5
        let def = UpvalDef::from_descriptor(0, &desc, Some("z".to_string()));
        assert_eq!(def.kind, ClosureKind::Stack);
        assert_eq!(def.slot, 5);
        assert_eq!(def.name.as_deref(), Some("z"));
    }

    #[test]
    fn test_upval_def_display() {
        let uv = LjUpvalue {
            slot: 0,
            is_local: false,
            name: Some("_ENV".to_string()),
        };
        let def = UpvalDef::from_raw(0, &uv);
        let s = def.to_string();
        assert!(s.contains("_ENV"));
        assert!(s.contains("parent-uv"));
    }

    // â”€â”€ ProtoUpvalInfo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_proto_upval_info_counts() {
        let upvals = vec![
            UpvalDef {
                index: 0,
                slot: 0,
                kind: ClosureKind::Stack,
                is_immutable: false,
                name: Some("x".into()),
                parent_proto_index: None,
                parent_upval_index: None,
            },
            UpvalDef {
                index: 1,
                slot: 0,
                kind: ClosureKind::ParentUv,
                is_immutable: false,
                name: Some("y".into()),
                parent_proto_index: None,
                parent_upval_index: None,
            },
        ];
        let pinfo = ProtoUpvalInfo {
            proto_index: 0,
            name: None,
            upvals,
            children: vec![],
            parent: None,
        };
        assert_eq!(pinfo.stack_count(), 1);
        assert_eq!(pinfo.inherited_count(), 1);
    }

    #[test]
    fn test_proto_upval_info_find_by_name() {
        let upvals = vec![UpvalDef {
            index: 0,
            slot: 0,
            kind: ClosureKind::Synthetic,
            is_immutable: false,
            name: Some("_ENV".into()),
            parent_proto_index: None,
            parent_upval_index: None,
        }];
        let pinfo = ProtoUpvalInfo {
            proto_index: 0,
            name: None,
            upvals,
            children: vec![],
            parent: None,
        };
        assert!(pinfo.find_by_name("_ENV").is_some());
        assert!(pinfo.find_by_name("missing").is_none());
    }

    #[test]
    fn test_proto_upval_info_display() {
        let pinfo = ProtoUpvalInfo {
            proto_index: 1,
            name: Some("foo".into()),
            upvals: vec![],
            children: vec![],
            parent: None,
        };
        assert!(pinfo.to_string().contains("Proto#1"));
    }

    // â”€â”€ analyze_upvalues â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_analyze_single_proto_no_uvs() {
        let proto = make_proto(vec![], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[proto]);
        assert_eq!(graph.protos.len(), 1);
        assert_eq!(graph.total_upvals, 0);
    }

    #[test]
    fn test_analyze_single_proto_env_uv() {
        let proto = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[proto]);
        assert_eq!(graph.total_upvals, 1);
        assert_eq!(graph.protos[0].upvals[0].name.as_deref(), Some("_ENV"));
    }

    #[test]
    fn test_analyze_shared_upvalue_detection() {
        // Two protos both capturing "_ENV"
        let p0 = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let p1 = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[p0, p1]);
        assert_eq!(graph.shared.len(), 1);
        assert_eq!(graph.shared[0].name.as_deref(), Some("_ENV"));
        assert_eq!(graph.shared[0].share_count(), 2);
    }

    #[test]
    fn test_analyze_no_shared_if_unique_names() {
        let uv_a = LjUpvalue {
            slot: 0,
            is_local: true,
            name: Some("a".into()),
        };
        let uv_b = LjUpvalue {
            slot: 1,
            is_local: true,
            name: Some("b".into()),
        };
        let p0 = make_proto(vec![uv_a], vec![LjInstr(0x0000_004B)]);
        let p1 = make_proto(vec![uv_b], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[p0, p1]);
        assert_eq!(graph.shared.len(), 0);
    }

    // â”€â”€ print_upvalue_tree â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_print_upvalue_tree_empty() {
        let graph = UpvalGraph::default();
        assert_eq!(print_upvalue_tree(&graph), "");
    }

    #[test]
    fn test_print_upvalue_tree_single_proto() {
        let proto = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[proto]);
        let output = print_upvalue_tree(&graph);
        assert!(output.contains("Proto#0"), "got: {output}");
        assert!(output.contains("_ENV"), "got: {output}");
    }

    #[test]
    fn test_print_upvalue_tree_shared_section() {
        let p0 = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let p1 = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[p0, p1]);
        let output = print_upvalue_tree(&graph);
        assert!(output.contains("Shared upvalues:"), "got: {output}");
        assert!(output.contains("_ENV"), "got: {output}");
    }

    // â”€â”€ compute_upval_usage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_upval_usage_uget_read() {
        // UGET A=0 D=0: read upvalue 0
        let raw = 0x2Du32; // op=UGET, a=0, d=0
        let proto = make_proto(
            vec![env_upvalue()],
            vec![LjInstr(raw), LjInstr(0x0000_004B)],
        );
        let usage = compute_upval_usage(&proto);
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].reads, vec![0usize]);
        assert!(usage[0].is_read());
        assert!(!usage[0].is_mutated());
    }

    #[test]
    fn test_upval_usage_usetv_write() {
        // USETV A=0 D=1: write upvalue 0
        let raw = 0x0001_002Eu32; // op=0x2E a=0 d=1
        let proto = make_proto(vec![env_upvalue()], vec![LjInstr(raw)]);
        let usage = compute_upval_usage(&proto);
        assert!(usage[0].is_mutated());
        assert_eq!(usage[0].writes, vec![0usize]);
    }

    #[test]
    fn test_upval_usage_no_uvs() {
        let proto = make_proto(vec![], vec![LjInstr(0x0000_004B)]);
        let usage = compute_upval_usage(&proto);
        assert!(usage.is_empty());
    }

    #[test]
    fn test_upval_usage_display() {
        let u = UpvalUsage {
            uv_index: 2,
            reads: vec![0, 3],
            writes: vec![1],
        };
        let s = u.to_string();
        assert!(s.contains("uv[2]"));
        assert!(s.contains("reads=2"));
        assert!(s.contains("writes=1"));
    }

    // â”€â”€ SharedUpval â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_shared_upval_display() {
        let s = SharedUpval {
            name: Some("x".into()),
            references: vec![(0, 1), (2, 0)],
        };
        let text = s.to_string();
        assert!(text.contains("Shared(x)"));
        assert!(text.contains("refs=2"));
    }

    #[test]
    fn test_upval_graph_all_names() {
        let p0 = make_proto(vec![env_upvalue()], vec![LjInstr(0x0000_004B)]);
        let uv_x = LjUpvalue {
            slot: 1,
            is_local: true,
            name: Some("x".into()),
        };
        let p1 = make_proto(vec![uv_x], vec![LjInstr(0x0000_004B)]);
        let graph = analyze_upvalues(&[p0, p1]);
        let names = graph.all_upval_names();
        assert!(names.contains(&"_ENV"));
        assert!(names.contains(&"x"));
    }
}
