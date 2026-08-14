//! `lua_upvalue_analyzer` — Upvalue capture analysis for Lua closures.
//!
//! Analyses upvalue descriptors across a [`crate::LuaProto`] tree to determine
//! which closures capture which locals or outer upvalues, detect shared state,
//! and summarise capture chains.

use std::collections::HashMap;
use std::fmt;

// ── Upvalue ───────────────────────────────────────────────────────────────────

/// A fully-resolved upvalue descriptor, enriched with context from the analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upvalue {
    /// Name (from debug info), if available.
    pub name: Option<String>,
    /// Whether the upvalue is captured from the enclosing frame's register
    /// (true) or from the enclosing function's upvalue list (false).
    pub in_stack: bool,
    /// Raw index: either a stack slot (if `in_stack`) or an upvalue index in
    /// the parent function's upvalue array.
    pub idx: u8,
    /// Index of this upvalue within its own closure's upvalue array.
    pub self_idx: usize,
    /// Human-readable capture kind string.
    pub capture_kind: CaptureKind,
}

impl Upvalue {
    /// Return the upvalue name or a generated placeholder.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("_uv{}", self.self_idx))
    }
}

impl fmt::Display for Upvalue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval[{}] {} {:?} idx={}",
            self.self_idx,
            self.display_name(),
            self.capture_kind,
            self.idx
        )
    }
}

// ── CaptureKind ───────────────────────────────────────────────────────────────

/// Describes how an upvalue is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureKind {
    /// Captured directly from a stack register of the enclosing function.
    StackCapture,
    /// Captured via a chain of upvalue references (outer upvalue → inner).
    UpvalueChain,
    /// Refers to the module-level `_ENV` pseudo-upvalue.
    Environment,
    /// Unknown capture kind (encountered in malformed or stripped bytecode).
    Unknown,
}

impl fmt::Display for CaptureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackCapture => write!(f, "stack-capture"),
            Self::UpvalueChain => write!(f, "upvalue-chain"),
            Self::Environment => write!(f, "environment"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── UpvalueRef ────────────────────────────────────────────────────────────────

/// A cross-prototype reference: closure `from_proto` captures upvalue
/// `upvalue_idx` which ultimately comes from `source_proto` at `source_slot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpvalueRef {
    /// Depth-first proto index of the capturing closure.
    pub from_proto: usize,
    /// Upvalue index within that closure.
    pub upvalue_idx: usize,
    /// Depth-first proto index of the source (where the variable lives).
    pub source_proto: usize,
    /// Stack slot or upvalue slot in the source.
    pub source_slot: u8,
    /// Resolved upvalue name.
    pub name: Option<String>,
}

impl fmt::Display for UpvalueRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proto[{}].uv[{}] <- proto[{}].slot[{}] ({})",
            self.from_proto,
            self.upvalue_idx,
            self.source_proto,
            self.source_slot,
            self.name.as_deref().unwrap_or("?")
        )
    }
}

// ── ClosureAnalysis ───────────────────────────────────────────────────────────

/// Complete upvalue analysis result for a single proto (closure).
#[derive(Debug, Clone)]
pub struct ClosureAnalysis {
    /// Depth-first proto index.
    pub proto_id: usize,
    /// Proto source name.
    pub proto_name: Option<String>,
    /// Resolved upvalue descriptors for this closure.
    pub upvalues: Vec<Upvalue>,
    /// Cross-proto upvalue references originating from this closure's children.
    pub child_refs: Vec<UpvalueRef>,
    /// Whether this closure captures `_ENV` (global table access).
    pub captures_env: bool,
    /// Whether this closure is itself used as an upvalue source by any child.
    pub is_upvalue_source: bool,
    /// Number of unique variables shared with sibling/parent closures.
    pub shared_var_count: usize,
}

impl ClosureAnalysis {
    /// Return the `_ENV` upvalue, if captured.
    #[must_use]
    pub fn env_upvalue(&self) -> Option<&Upvalue> {
        self.upvalues.iter().find(|uv| {
            uv.name.as_deref() == Some("_ENV")
        })
    }

    /// Return upvalues captured directly from the enclosing stack frame.
    #[must_use]
    pub fn stack_captures(&self) -> Vec<&Upvalue> {
        self.upvalues
            .iter()
            .filter(|uv| uv.capture_kind == CaptureKind::StackCapture)
            .collect()
    }

    /// Return upvalues propagated via an upvalue chain.
    #[must_use]
    pub fn chained_captures(&self) -> Vec<&Upvalue> {
        self.upvalues
            .iter()
            .filter(|uv| uv.capture_kind == CaptureKind::UpvalueChain)
            .collect()
    }
}

impl fmt::Display for ClosureAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Closure[{}] '{}' upvalues={} captures_env={} shared={}",
            self.proto_id,
            self.proto_name.as_deref().unwrap_or("?"),
            self.upvalues.len(),
            self.captures_env,
            self.shared_var_count
        )
    }
}

// ── LuaUpvalueAnalyzer ────────────────────────────────────────────────────────

/// Analyses the upvalue capture graph of an entire Lua module.
///
/// Walks the prototype tree depth-first, resolving upvalue descriptors,
/// tracking capture chains, and identifying shared state between closures.
pub struct LuaUpvalueAnalyzer {
    /// Completed analysis per proto (depth-first index).
    pub analyses: Vec<ClosureAnalysis>,
    /// Flat list of all resolved cross-proto refs.
    pub all_refs: Vec<UpvalueRef>,
    /// Proto index → parent proto index (root has `None`).
    parent_map: HashMap<usize, usize>,
    /// Naive (counter-based) child proto ids recorded during the walk, keyed by
    /// `(parent_id, child_idx)`. Useful for cross-validating the depth-first
    /// estimate against the linear counter view.
    pub naive_child_ids: HashMap<(usize, usize), usize>,
}

impl LuaUpvalueAnalyzer {
    /// Look up the naive (linear counter) child id recorded for a
    /// `(parent_id, child_idx)` pair.
    #[must_use]
    pub fn naive_child_id(&self, parent_id: usize, child_idx: usize) -> Option<usize> {
        self.naive_child_ids.get(&(parent_id, child_idx)).copied()
    }
}

impl LuaUpvalueAnalyzer {
    /// Run a complete analysis on a module's root proto.
    #[must_use]
    pub fn analyze(root: &crate::LuaProto) -> Self {
        let mut analyzer = Self {
            analyses: Vec::new(),
            all_refs: Vec::new(),
            parent_map: HashMap::new(),
            naive_child_ids: HashMap::new(),
        };
        let mut counter = 0usize;
        analyzer.walk(root, None, &mut counter);
        analyzer.resolve_shared_vars();
        analyzer
    }

    fn walk(
        &mut self,
        proto: &crate::LuaProto,
        parent_id: Option<usize>,
        counter: &mut usize,
    ) {
        let my_id = *counter;
        *counter += 1;

        if let Some(pid) = parent_id {
            self.parent_map.insert(my_id, pid);
        }

        // Build resolved upvalue list.
        let mut upvalues: Vec<Upvalue> = Vec::new();
        let mut captures_env = false;

        for (self_idx, raw_uv) in proto.upvalues.iter().enumerate() {
            let capture_kind = if raw_uv.name.as_deref() == Some("_ENV") {
                captures_env = true;
                CaptureKind::Environment
            } else if raw_uv.in_stack {
                CaptureKind::StackCapture
            } else {
                CaptureKind::UpvalueChain
            };

            let uv = Upvalue {
                name: raw_uv.name.clone(),
                in_stack: raw_uv.in_stack,
                idx: raw_uv.idx,
                self_idx,
                capture_kind,
            };
            upvalues.push(uv);
        }

        // Build child refs: for each child closure, resolve where its upvalues
        // originate.
        let mut child_refs: Vec<UpvalueRef> = Vec::new();

        for (child_idx, child_proto) in proto.protos.iter().enumerate() {
            let child_proto_id = *counter + child_idx;
            self.naive_child_ids
                .insert((my_id, child_idx), child_proto_id);
            // Calculate child's proto id from its position in the walk.
            // We do a preliminary count to get the ids right.
            let child_id_est = Self::estimate_child_id(*counter, child_idx, proto);
            for (uv_idx, child_uv) in child_proto.upvalues.iter().enumerate() {
                if child_uv.in_stack {
                    // Captured from this proto's stack.
                    let uref = UpvalueRef {
                        from_proto: child_id_est,
                        upvalue_idx: uv_idx,
                        source_proto: my_id,
                        source_slot: child_uv.idx,
                        name: child_uv.name.clone(),
                    };
                    child_refs.push(uref.clone());
                    self.all_refs.push(uref);
                } else {
                    // Propagated from this proto's upvalue list.
                    let source_name = upvalues
                        .get(child_uv.idx as usize)
                        .and_then(|uv| uv.name.clone());
                    let uref = UpvalueRef {
                        from_proto: child_id_est,
                        upvalue_idx: uv_idx,
                        source_proto: my_id,
                        source_slot: child_uv.idx,
                        name: source_name.or_else(|| child_uv.name.clone()),
                    };
                    child_refs.push(uref.clone());
                    self.all_refs.push(uref);
                }
            }
        }

        let analysis = ClosureAnalysis {
            proto_id: my_id,
            proto_name: proto.name.clone(),
            upvalues,
            child_refs,
            captures_env,
            is_upvalue_source: !proto.protos.is_empty(),
            shared_var_count: 0, // filled in after full walk
        };

        self.analyses.push(analysis);

        for child_proto in &proto.protos {
            self.walk(child_proto, Some(my_id), counter);
        }
    }

    /// Estimate the depth-first id of the nth child in a proto's children list.
    /// This is a simple linear sum; accurate only for prototypes without deeply
    /// nested children (the post-walk pass corrects things via `all_refs`).
    fn estimate_child_id(
        base_counter: usize,
        child_idx: usize,
        proto: &crate::LuaProto,
    ) -> usize {
        let mut offset = 0usize;
        for (i, p) in proto.protos.iter().enumerate() {
            if i == child_idx {
                break;
            }
            offset += Self::subtree_size(p);
        }
        base_counter + offset
    }

    fn subtree_size(proto: &crate::LuaProto) -> usize {
        1 + proto.protos.iter().map(Self::subtree_size).sum::<usize>()
    }

    /// Post-pass: count shared variables (upvalues shared with a sibling or child).
    fn resolve_shared_vars(&mut self) {
        // Build a map: source_proto → how many closures capture from it.
        let mut capture_from: HashMap<usize, usize> = HashMap::new();
        for uref in &self.all_refs {
            *capture_from.entry(uref.source_proto).or_insert(0) += 1;
        }
        for analysis in &mut self.analyses {
            analysis.shared_var_count =
                capture_from.get(&analysis.proto_id).copied().unwrap_or(0);
            analysis.is_upvalue_source =
                capture_from.contains_key(&analysis.proto_id);
        }
    }

    /// Return the analysis for a given proto id.
    #[must_use]
    pub fn analysis_for(&self, proto_id: usize) -> Option<&ClosureAnalysis> {
        self.analyses.iter().find(|a| a.proto_id == proto_id)
    }

    /// All closures that capture `_ENV`.
    #[must_use]
    pub fn closures_with_env(&self) -> Vec<&ClosureAnalysis> {
        self.analyses.iter().filter(|a| a.captures_env).collect()
    }

    /// All closures that act as upvalue sources for at least one child.
    #[must_use]
    pub fn upvalue_sources(&self) -> Vec<&ClosureAnalysis> {
        self.analyses
            .iter()
            .filter(|a| a.is_upvalue_source)
            .collect()
    }

    /// All upvalue references that form a chain (upvalue-captured-from-upvalue).
    #[must_use]
    pub fn chained_refs(&self) -> Vec<&UpvalueRef> {
        let stack_sources: std::collections::HashSet<usize> = self
            .all_refs
            .iter()
            .filter(|r| {
                self.analyses
                    .iter()
                    .find(|a| a.proto_id == r.from_proto)
                    .and_then(|a| a.upvalues.get(r.upvalue_idx))
                    .is_some_and(|uv| uv.capture_kind == CaptureKind::UpvalueChain)
            })
            .map(|r| r.from_proto)
            .collect();
        self.all_refs
            .iter()
            .filter(|r| stack_sources.contains(&r.from_proto))
            .collect()
    }

    /// Named variable capture map: variable name → list of proto ids that capture it.
    #[must_use]
    pub fn named_capture_map(&self) -> HashMap<String, Vec<usize>> {
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for uref in &self.all_refs {
            if let Some(name) = &uref.name {
                map.entry(name.clone()).or_default().push(uref.from_proto);
            }
        }
        for ids in map.values_mut() {
            ids.sort_unstable();
            ids.dedup();
        }
        map
    }

    /// Generate a textual capture-graph report.
    #[must_use]
    pub fn capture_graph_report(&self) -> String {
        let mut lines: Vec<String> = vec![format!(
            "Upvalue Capture Graph: {} closures, {} cross-proto refs",
            self.analyses.len(),
            self.all_refs.len()
        )];
        for analysis in &self.analyses {
            lines.push(format!("  {analysis}"));
            for uv in &analysis.upvalues {
                lines.push(format!("    {uv}"));
            }
        }
        if !self.all_refs.is_empty() {
            lines.push("Cross-proto upvalue references:".to_string());
            for r in &self.all_refs {
                lines.push(format!("  {r}"));
            }
        }
        lines.join("\n")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LuaProto, LuaUpvalue, LuaVersion};

    fn make_proto_with_upvalues(
        name: Option<String>,
        upvalues: Vec<LuaUpvalue>,
        protos: Vec<LuaProto>,
        version: LuaVersion,
    ) -> LuaProto {
        LuaProto {
            name,
            first_line: 0,
            last_line: 10,
            num_params: 0,
            is_vararg: false,
            max_stack: 4,
            instructions: vec![],
            constants: vec![],
            upvalues,
            protos,
            line_info: vec![],
            locals: vec![],
            version,
        }
    }

    #[test]
    fn test_basic_env_capture() {
        let root = make_proto_with_upvalues(
            Some("@test.lua".into()),
            vec![LuaUpvalue {
                in_stack: false,
                idx: 0,
                name: Some("_ENV".into()),
            }],
            vec![],
            LuaVersion::Lua54,
        );
        let analyzer = LuaUpvalueAnalyzer::analyze(&root);
        assert_eq!(analyzer.analyses.len(), 1);
        let a = &analyzer.analyses[0];
        assert!(a.captures_env);
        assert_eq!(a.upvalues.len(), 1);
        assert_eq!(a.upvalues[0].capture_kind, CaptureKind::Environment);
    }

    #[test]
    fn test_stack_capture() {
        let child = make_proto_with_upvalues(
            Some("@inner".into()),
            vec![LuaUpvalue {
                in_stack: true,
                idx: 2,
                name: Some("x".into()),
            }],
            vec![],
            LuaVersion::Lua54,
        );
        let root = make_proto_with_upvalues(
            Some("@root".into()),
            vec![],
            vec![child],
            LuaVersion::Lua54,
        );
        let analyzer = LuaUpvalueAnalyzer::analyze(&root);
        assert_eq!(analyzer.all_refs.len(), 1);
        assert_eq!(analyzer.all_refs[0].source_slot, 2);
        assert_eq!(analyzer.all_refs[0].name.as_deref(), Some("x"));
    }

    #[test]
    fn test_named_capture_map() {
        let child = make_proto_with_upvalues(
            None,
            vec![
                LuaUpvalue { in_stack: true, idx: 0, name: Some("a".into()) },
                LuaUpvalue { in_stack: true, idx: 1, name: Some("b".into()) },
            ],
            vec![],
            LuaVersion::Lua54,
        );
        let root = make_proto_with_upvalues(None, vec![], vec![child], LuaVersion::Lua54);
        let analyzer = LuaUpvalueAnalyzer::analyze(&root);
        let map = analyzer.named_capture_map();
        assert!(map.contains_key("a"));
        assert!(map.contains_key("b"));
    }

    #[test]
    fn test_mock_proto_analysis() {
        let proto = crate::LuaProto::mock(LuaVersion::Lua54);
        let analyzer = LuaUpvalueAnalyzer::analyze(&proto);
        assert!(!analyzer.analyses.is_empty());
        // Mock proto has _ENV upvalue.
        let env_closures = analyzer.closures_with_env();
        assert_eq!(env_closures.len(), 1);
    }

    #[test]
    fn test_capture_graph_report() {
        let proto = crate::LuaProto::mock(LuaVersion::Lua54);
        let analyzer = LuaUpvalueAnalyzer::analyze(&proto);
        let report = analyzer.capture_graph_report();
        assert!(report.contains("Upvalue Capture Graph"));
    }

    #[test]
    fn test_display_name_fallback() {
        let uv = Upvalue {
            name: None,
            in_stack: true,
            idx: 3,
            self_idx: 2,
            capture_kind: CaptureKind::StackCapture,
        };
        assert_eq!(uv.display_name(), "_uv2");
    }
}
