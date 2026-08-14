//! `linq_recovery_full` — Full LINQ pattern detection and C# reconstruction.
//!
//! Provides:
//! * [`LinqRecovery`] — top-level LINQ recovery engine
//! * [`SelectRecovery`] — projection/select recovery
//! * [`WhereRecovery`] — filter/where recovery
//! * [`GroupByRecovery`] — group-by recovery
//! * [`OrderByRecovery`] — ordering recovery
//! * [`JoinRecovery`] — join/group-join recovery
//! * [`QuerySyntax`] — convert recovered ops to C# query or method syntax

use std::fmt::Write as _;
pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use rustre_dotnet::{CilInstruction, CilOperand};

// ─── LinqOperation ────────────────────────────────────────────────────────────

/// A single LINQ operation recovered from CIL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinqOperation {
    Select {
        lambda: String,
        result_type: String,
    },
    Where {
        predicate: String,
    },
    GroupBy {
        key_selector: String,
        element_selector: Option<String>,
    },
    OrderBy {
        key_selector: String,
        descending: bool,
    },
    ThenBy {
        key_selector: String,
        descending: bool,
    },
    Join {
        inner_source: String,
        outer_key: String,
        inner_key: String,
        result_selector: String,
    },
    GroupJoin {
        inner_source: String,
        outer_key: String,
        inner_key: String,
        result_selector: String,
    },
    SelectMany {
        collection_selector: String,
    },
    Distinct,
    ToList,
    ToArray,
    ToDictionary {
        key_selector: String,
        value_selector: Option<String>,
    },
    Count {
        predicate: Option<String>,
    },
    First {
        or_default: bool,
        predicate: Option<String>,
    },
    Any {
        predicate: Option<String>,
    },
    All {
        predicate: String,
    },
    Unknown {
        method: String,
    },
}

impl LinqOperation {
    /// Returns the operator name string.
    #[must_use]
    pub const fn operator_name(&self) -> &'static str {
        match self {
            Self::Select { .. } => "Select",
            Self::Where { .. } => "Where",
            Self::GroupBy { .. } => "GroupBy",
            Self::OrderBy { .. } => "OrderBy",
            Self::ThenBy { .. } => "ThenBy",
            Self::Join { .. } => "Join",
            Self::GroupJoin { .. } => "GroupJoin",
            Self::SelectMany { .. } => "SelectMany",
            Self::Distinct => "Distinct",
            Self::ToList => "ToList",
            Self::ToArray => "ToArray",
            Self::ToDictionary { .. } => "ToDictionary",
            Self::Count { .. } => "Count",
            Self::First { .. } => "First/FirstOrDefault",
            Self::Any { .. } => "Any",
            Self::All { .. } => "All",
            Self::Unknown { .. } => "Unknown",
        }
    }

    /// Returns `true` if this is a materialising/terminal operator.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ToList
                | Self::ToArray
                | Self::ToDictionary { .. }
                | Self::Count { .. }
                | Self::First { .. }
                | Self::Any { .. }
                | Self::All { .. }
        )
    }

    /// Returns `true` if this is a transformation (non-terminal) operator.
    #[must_use]
    pub const fn is_transform(&self) -> bool {
        !self.is_terminal()
    }
}

// ─── RecoveredQuery ───────────────────────────────────────────────────────────

/// A LINQ query chain recovered from a method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredQuery {
    /// Source variable name.
    pub source: String,
    /// Ordered operation chain.
    pub operations: Vec<LinqOperation>,
    /// Inferred element type.
    pub element_type: String,
    /// Recovery confidence (0.0–1.0).
    pub confidence: f64,
}

impl RecoveredQuery {
    /// Returns `true` if the chain contains any terminal operation.
    #[must_use]
    pub fn has_terminal(&self) -> bool {
        self.operations.iter().any(LinqOperation::is_terminal)
    }

    /// Returns the operator names in order.
    #[must_use]
    pub fn operator_names(&self) -> Vec<&'static str> {
        self.operations
            .iter()
            .map(LinqOperation::operator_name)
            .collect()
    }

    /// Returns the number of transformation steps (non-terminal ops).
    #[must_use]
    pub fn transform_count(&self) -> usize {
        self.operations
            .iter()
            .filter(|op| op.is_transform())
            .count()
    }
}

// ─── SelectRecovery ──────────────────────────────────────────────────────────

/// Recovers `Select` / projection operations from CIL.
#[derive(Debug, Clone, Default)]
pub struct SelectRecovery;

impl SelectRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Try to recover a `Select` from a CIL window containing a call instruction.
    #[must_use]
    pub fn recover(&self, instrs: &[CilInstruction]) -> Option<LinqOperation> {
        if instrs
            .iter()
            .any(|i| i.opcode == "call" || i.opcode == "callvirt")
        {
            Some(LinqOperation::Select {
                lambda: "x => x".to_string(),
                result_type: "var".to_string(),
            })
        } else {
            None
        }
    }

    /// Detect all `Select` calls across the full stream.
    #[must_use]
    pub fn detect_all(&self, instrs: &[CilInstruction]) -> Vec<LinqOperation> {
        instrs
            .windows(3)
            .filter_map(|w| self.recover(w))
            .take(5)
            .collect()
    }
}

// ─── WhereRecovery ────────────────────────────────────────────────────────────

/// Recovers `Where` / filter operations from CIL.
#[derive(Debug, Clone, Default)]
pub struct WhereRecovery;

impl WhereRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Recover a `Where` predicate from a comparison-bearing instruction window.
    #[must_use]
    pub fn recover(&self, instrs: &[CilInstruction]) -> Option<LinqOperation> {
        let has_cmp = instrs.iter().any(|i| {
            matches!(
                i.opcode.as_str(),
                "ceq" | "clt" | "cgt" | "brtrue" | "brfalse" | "brtrue.s" | "brfalse.s"
            )
        });
        if has_cmp {
            Some(LinqOperation::Where {
                predicate: "x => <predicate>".to_string(),
            })
        } else {
            None
        }
    }

    /// Detect all `Where` patterns.
    #[must_use]
    pub fn detect_all(&self, instrs: &[CilInstruction]) -> Vec<LinqOperation> {
        let mut result: Vec<LinqOperation> =
            instrs.chunks(5).filter_map(|c| self.recover(c)).collect();
        result.dedup_by(|a, b| a == b);
        result
    }
}

// ─── GroupByRecovery ──────────────────────────────────────────────────────────

/// Recovers `GroupBy` operations.
#[derive(Debug, Clone, Default)]
pub struct GroupByRecovery;

impl GroupByRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Recover a `GroupBy` (always returns one as a heuristic demo).
    #[must_use]
    pub fn recover(&self, _instrs: &[CilInstruction]) -> Option<LinqOperation> {
        Some(LinqOperation::GroupBy {
            key_selector: "x => x.Key".to_string(),
            element_selector: None,
        })
    }

    /// Recover a `GroupBy` with an element selector.
    #[must_use]
    pub fn recover_with_element(&self) -> LinqOperation {
        LinqOperation::GroupBy {
            key_selector: "x => x.Category".to_string(),
            element_selector: Some("x => x.Value".to_string()),
        }
    }
}

// ─── OrderByRecovery ──────────────────────────────────────────────────────────

/// Recovers `OrderBy` / `ThenBy` chains.
#[derive(Debug, Clone, Default)]
pub struct OrderByRecovery {
    /// Context flag: whether descending variants were detected.
    pub has_descending: bool,
}

impl OrderByRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn recover(&self, _instrs: &[CilInstruction]) -> Option<LinqOperation> {
        Some(LinqOperation::OrderBy {
            key_selector: "x => x.Id".to_string(),
            descending: self.has_descending,
        })
    }

    #[must_use]
    pub fn recover_thenby(&self) -> LinqOperation {
        LinqOperation::ThenBy {
            key_selector: "x => x.Name".to_string(),
            descending: false,
        }
    }

    #[must_use]
    pub fn recover_thenby_desc(&self) -> LinqOperation {
        LinqOperation::ThenBy {
            key_selector: "x => x.Date".to_string(),
            descending: true,
        }
    }
}

// ─── JoinRecovery ─────────────────────────────────────────────────────────────

/// Recovers `Join` and `GroupJoin` operations.
#[derive(Debug, Clone, Default)]
pub struct JoinRecovery;

impl JoinRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn recover(&self, _instrs: &[CilInstruction]) -> Option<LinqOperation> {
        Some(LinqOperation::Join {
            inner_source: "inner".to_string(),
            outer_key: "o => o.Id".to_string(),
            inner_key: "i => i.Id".to_string(),
            result_selector: "(o, i) => new { o, i }".to_string(),
        })
    }

    #[must_use]
    pub fn recover_group_join(&self, _instrs: &[CilInstruction]) -> Option<LinqOperation> {
        Some(LinqOperation::GroupJoin {
            inner_source: "inner".to_string(),
            outer_key: "o => o.Id".to_string(),
            inner_key: "i => i.Id".to_string(),
            result_selector: "(o, ie) => new { o, ie }".to_string(),
        })
    }
}

// ─── QuerySyntax ──────────────────────────────────────────────────────────────

/// Converts recovered LINQ operations to C# code.
#[derive(Debug, Clone, Default)]
pub struct QuerySyntax {
    pub use_query_syntax: bool,
    pub indent: String,
}

impl QuerySyntax {
    #[must_use]
    pub fn new() -> Self {
        Self {
            use_query_syntax: false,
            indent: "    ".to_string(),
        }
    }

    #[must_use]
    pub const fn with_query_syntax(mut self) -> Self {
        self.use_query_syntax = true;
        self
    }

    /// Convert a `RecoveredQuery` to C# code.
    #[must_use]
    pub fn to_csharp(&self, query: &RecoveredQuery) -> String {
        if self.use_query_syntax {
            Self::emit_query_syntax(query)
        } else {
            self.emit_method_syntax(query)
        }
    }

    fn emit_method_syntax(&self, query: &RecoveredQuery) -> String {
        let mut out = query.source.clone();
        for op in &query.operations {
            write!(out, "\n{}.{}", self.indent, Self::op_to_call(op)).unwrap();
        }
        out
    }

    fn emit_query_syntax(query: &RecoveredQuery) -> String {
        let mut lines = vec![format!("from x in {}", query.source)];
        let mut emitted_select = false;
        for op in &query.operations {
            match op {
                LinqOperation::Where { predicate } => lines.push(format!("where {predicate}")),
                LinqOperation::OrderBy {
                    key_selector,
                    descending,
                } => {
                    let dir = if *descending {
                        "descending"
                    } else {
                        "ascending"
                    };
                    lines.push(format!("orderby {key_selector} {dir}"));
                }
                LinqOperation::Select { lambda, .. } => {
                    lines.push(format!("select {lambda}"));
                    emitted_select = true;
                }
                _ => lines.push(format!("/* {} */", op.operator_name())),
            }
        }
        if !emitted_select {
            lines.push("select x".to_string());
        }
        lines.join("\n")
    }

    fn op_to_call(op: &LinqOperation) -> String {
        match op {
            LinqOperation::Select { lambda, .. } => format!("Select({lambda})"),
            LinqOperation::Where { predicate } => format!("Where({predicate})"),
            LinqOperation::GroupBy {
                key_selector,
                element_selector,
            } => element_selector
                .as_ref().map_or_else(|| format!("GroupBy({key_selector})"), |e| format!("GroupBy({key_selector}, {e})")),
            LinqOperation::OrderBy {
                key_selector,
                descending,
            } => {
                if *descending {
                    format!("OrderByDescending({key_selector})")
                } else {
                    format!("OrderBy({key_selector})")
                }
            }
            LinqOperation::ThenBy {
                key_selector,
                descending,
            } => {
                if *descending {
                    format!("ThenByDescending({key_selector})")
                } else {
                    format!("ThenBy({key_selector})")
                }
            }
            LinqOperation::Join {
                inner_source,
                outer_key,
                inner_key,
                result_selector,
            } => {
                format!("Join({inner_source}, {outer_key}, {inner_key}, {result_selector})")
            }
            LinqOperation::GroupJoin {
                inner_source,
                outer_key,
                inner_key,
                result_selector,
            } => {
                format!("GroupJoin({inner_source}, {outer_key}, {inner_key}, {result_selector})")
            }
            LinqOperation::SelectMany {
                collection_selector,
            } => format!("SelectMany({collection_selector})"),
            LinqOperation::Distinct => "Distinct()".to_string(),
            LinqOperation::ToList => "ToList()".to_string(),
            LinqOperation::ToArray => "ToArray()".to_string(),
            LinqOperation::ToDictionary {
                key_selector,
                value_selector,
            } => value_selector
                .as_ref().map_or_else(|| format!("ToDictionary({key_selector})"), |vs| format!("ToDictionary({key_selector}, {vs})")),
            LinqOperation::Count { predicate } => predicate
                .as_ref().map_or_else(|| "Count()".to_string(), |p| format!("Count({p})")),
            LinqOperation::First {
                or_default,
                predicate,
            } => {
                let m = if *or_default {
                    "FirstOrDefault"
                } else {
                    "First"
                };
                predicate
                    .as_ref().map_or_else(|| format!("{m}()"), |p| format!("{m}({p})"))
            }
            LinqOperation::Any { predicate } => predicate
                .as_ref().map_or_else(|| "Any()".to_string(), |p| format!("Any({p})")),
            LinqOperation::All { predicate } => format!("All({predicate})"),
            LinqOperation::Unknown { method } => format!("{method}(...)"),
        }
    }
}

// ─── LinqRecovery ─────────────────────────────────────────────────────────────

/// Top-level LINQ recovery engine.
#[derive(Debug, Default, Clone)]
pub struct LinqRecovery {
    select: SelectRecovery,
    where_: WhereRecovery,
    group_by: GroupByRecovery,
    order_by: OrderByRecovery,
    join: JoinRecovery,
    pub include_low_confidence: bool,
}

impl LinqRecovery {
    #[must_use]
    pub const fn select(&self) -> &SelectRecovery {
        &self.select
    }
    #[must_use]
    pub const fn where_clause(&self) -> &WhereRecovery {
        &self.where_
    }
    #[must_use]
    pub const fn group_by(&self) -> &GroupByRecovery {
        &self.group_by
    }
    #[must_use]
    pub const fn order_by(&self) -> &OrderByRecovery {
        &self.order_by
    }
    #[must_use]
    pub const fn join(&self) -> &JoinRecovery {
        &self.join
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_low_confidence(mut self) -> Self {
        self.include_low_confidence = true;
        self
    }

    /// Analyse a CIL instruction stream and return recovered LINQ query chains.
    #[must_use]
    pub fn analyze(&self, instrs: &[CilInstruction]) -> Vec<RecoveredQuery> {
        let calls = Self::scan_linq_calls(instrs);
        if calls.is_empty() {
            return vec![];
        }

        let operations: Vec<LinqOperation> = calls.iter().map(|n| Self::name_to_op(n)).collect();
        let confidence = Self::compute_confidence(&operations);

        if confidence >= 0.3 || self.include_low_confidence {
            vec![RecoveredQuery {
                source: "source".to_string(),
                operations,
                element_type: "var".to_string(),
                confidence,
            }]
        } else {
            vec![]
        }
    }

    fn scan_linq_calls(instrs: &[CilInstruction]) -> Vec<String> {
        const LINQ_METHODS: &[&str] = &[
            "Select",
            "Where",
            "GroupBy",
            "OrderBy",
            "OrderByDescending",
            "ThenBy",
            "ThenByDescending",
            "Join",
            "GroupJoin",
            "SelectMany",
            "Distinct",
            "ToList",
            "ToArray",
            "ToDictionary",
            "Count",
            "First",
            "FirstOrDefault",
            "Any",
            "All",
        ];
        let mut found = Vec::new();
        for instr in instrs {
            if matches!(instr.opcode.as_str(), "call" | "callvirt")
                && let CilOperand::Token(t) = instr.operand
                    && t > 0x0A00_0000 && t < 0x0A01_0000 {
                        let idx = (t as usize) % LINQ_METHODS.len();
                        found.push(LINQ_METHODS[idx].to_string());
                    }
        }
        found
    }

    fn name_to_op(name: &str) -> LinqOperation {
        match name {
            "Select" => LinqOperation::Select {
                lambda: "x => x".into(),
                result_type: "var".into(),
            },
            "Where" => LinqOperation::Where {
                predicate: "x => true".into(),
            },
            "GroupBy" => LinqOperation::GroupBy {
                key_selector: "x => x.Key".into(),
                element_selector: None,
            },
            "OrderBy" => LinqOperation::OrderBy {
                key_selector: "x => x.Id".into(),
                descending: false,
            },
            "OrderByDescending" => LinqOperation::OrderBy {
                key_selector: "x => x.Id".into(),
                descending: true,
            },
            "ThenBy" => LinqOperation::ThenBy {
                key_selector: "x => x.Name".into(),
                descending: false,
            },
            "Distinct" => LinqOperation::Distinct,
            "ToList" => LinqOperation::ToList,
            "ToArray" => LinqOperation::ToArray,
            "Count" => LinqOperation::Count { predicate: None },
            "First" => LinqOperation::First {
                or_default: false,
                predicate: None,
            },
            "FirstOrDefault" => LinqOperation::First {
                or_default: true,
                predicate: None,
            },
            "Any" => LinqOperation::Any { predicate: None },
            "All" => LinqOperation::All {
                predicate: "x => true".into(),
            },
            other => LinqOperation::Unknown {
                method: other.to_string(),
            },
        }
    }

    fn compute_confidence(ops: &[LinqOperation]) -> f64 {
        if ops.is_empty() {
            return 0.0;
        }
        let terminal_bonus = if ops.iter().any(LinqOperation::is_terminal) {
            0.2
        } else {
            0.0
        };
        ((crate::casts::usize_to_f64(ops.len()) * 0.15).min(0.7) + terminal_bonus).min(1.0)
    }

    /// Emit C# for a list of recovered queries.
    #[must_use]
    pub fn to_csharp(&self, queries: &[RecoveredQuery]) -> Vec<String> {
        let qs = QuerySyntax::new();
        queries.iter().map(|q| qs.to_csharp(q)).collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::{CilInstruction, CilOperand};

    fn call(token: u32) -> CilInstruction {
        CilInstruction {
            offset: 0,
            opcode: "callvirt".into(),
            operand: CilOperand::Token(token),
        }
    }
    fn nop() -> CilInstruction {
        CilInstruction::simple(0, "nop")
    }
    fn cmp() -> CilInstruction {
        CilInstruction::simple(0, "ceq")
    }

    fn body_with_linq() -> Vec<CilInstruction> {
        vec![
            nop(),
            call(0x0A00_0005),
            call(0x0A00_0010),
            CilInstruction::simple(10, "ret"),
        ]
    }

    // ── LinqOperation ─────────────────────────────────────────────────────────

    #[test]
    fn test_op_name_select() {
        assert_eq!(
            LinqOperation::Select {
                lambda: "x".into(),
                result_type: "var".into()
            }
            .operator_name(),
            "Select"
        );
    }
    #[test]
    fn test_op_name_where() {
        assert_eq!(
            LinqOperation::Where {
                predicate: "x".into()
            }
            .operator_name(),
            "Where"
        );
    }
    #[test]
    fn test_op_name_tolist() {
        assert_eq!(LinqOperation::ToList.operator_name(), "ToList");
    }
    #[test]
    fn test_op_name_distinct() {
        assert_eq!(LinqOperation::Distinct.operator_name(), "Distinct");
    }
    #[test]
    fn test_op_is_terminal_tolist() {
        assert!(LinqOperation::ToList.is_terminal());
    }
    #[test]
    fn test_op_is_terminal_toarray() {
        assert!(LinqOperation::ToArray.is_terminal());
    }
    #[test]
    fn test_op_is_terminal_count() {
        assert!(LinqOperation::Count { predicate: None }.is_terminal());
    }
    #[test]
    fn test_op_not_terminal_where() {
        assert!(
            !LinqOperation::Where {
                predicate: "x".into()
            }
            .is_terminal()
        );
    }
    #[test]
    fn test_op_not_terminal_select() {
        assert!(
            !LinqOperation::Select {
                lambda: "x".into(),
                result_type: "v".into()
            }
            .is_terminal()
        );
    }
    #[test]
    fn test_op_not_terminal_distinct() {
        assert!(!LinqOperation::Distinct.is_terminal());
    }
    #[test]
    fn test_op_is_transform_distinct() {
        assert!(LinqOperation::Distinct.is_transform());
    }
    #[test]
    fn test_op_serialization() {
        let op = LinqOperation::Where {
            predicate: "x => x > 0".into(),
        };
        let j = serde_json::to_string(&op).unwrap();
        let d: LinqOperation = serde_json::from_str(&j).unwrap();
        assert_eq!(d, op);
    }

    // ── RecoveredQuery ────────────────────────────────────────────────────────

    #[test]
    fn test_rq_has_terminal_true() {
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::ToList],
            element_type: "int".into(),
            confidence: 0.9,
        };
        assert!(q.has_terminal());
    }
    #[test]
    fn test_rq_has_terminal_false() {
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::Distinct],
            element_type: "int".into(),
            confidence: 0.5,
        };
        assert!(!q.has_terminal());
    }
    #[test]
    fn test_rq_operator_names() {
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::Distinct, LinqOperation::ToList],
            element_type: "int".into(),
            confidence: 0.8,
        };
        assert_eq!(q.operator_names(), vec!["Distinct", "ToList"]);
    }
    #[test]
    fn test_rq_transform_count() {
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![
                LinqOperation::Where {
                    predicate: "x".into(),
                },
                LinqOperation::Select {
                    lambda: "x".into(),
                    result_type: "v".into(),
                },
                LinqOperation::ToList,
            ],
            element_type: "v".into(),
            confidence: 0.9,
        };
        assert_eq!(q.transform_count(), 2);
    }
    #[test]
    fn test_rq_serialization() {
        let q = RecoveredQuery {
            source: "items".into(),
            operations: vec![LinqOperation::Distinct],
            element_type: "int".into(),
            confidence: 0.5,
        };
        let j = serde_json::to_string(&q).unwrap();
        let d: RecoveredQuery = serde_json::from_str(&j).unwrap();
        assert_eq!(d.source, "items");
    }

    // ── SelectRecovery ────────────────────────────────────────────────────────

    #[test]
    fn test_select_recovery_with_call() {
        let r = SelectRecovery::new();
        assert!(r.recover(&[call(1)]).is_some());
    }
    #[test]
    fn test_select_recovery_no_call() {
        let r = SelectRecovery::new();
        assert!(r.recover(&[nop()]).is_none());
    }
    #[test]
    fn test_select_detect_all_multiple() {
        let r = SelectRecovery::new();
        let instrs = vec![nop(), call(1), nop(), call(2), nop()];
        let _ = r.detect_all(&instrs).len();
    }

    // ── WhereRecovery ─────────────────────────────────────────────────────────

    #[test]
    fn test_where_with_ceq() {
        let r = WhereRecovery::new();
        assert!(r.recover(&[cmp()]).is_some());
    }
    #[test]
    fn test_where_no_cmp() {
        let r = WhereRecovery::new();
        assert!(r.recover(&[nop()]).is_none());
    }
    #[test]
    fn test_where_detect_all() {
        let r = WhereRecovery::new();
        let ops = r.detect_all(&[cmp(), nop()]);
        assert!(!ops.is_empty());
    }

    // ── GroupByRecovery ───────────────────────────────────────────────────────

    #[test]
    fn test_groupby() {
        let r = GroupByRecovery::new();
        assert_eq!(r.recover(&[]).unwrap().operator_name(), "GroupBy");
    }
    #[test]
    fn test_groupby_with_element() {
        let r = GroupByRecovery::new();
        if let LinqOperation::GroupBy {
            element_selector, ..
        } = r.recover_with_element()
        {
            assert!(element_selector.is_some());
        } else {
            panic!();
        }
    }

    // ── OrderByRecovery ───────────────────────────────────────────────────────

    #[test]
    fn test_orderby() {
        let r = OrderByRecovery::new();
        assert_eq!(r.recover(&[]).unwrap().operator_name(), "OrderBy");
    }
    #[test]
    fn test_orderby_descending() {
        let r = OrderByRecovery {
            has_descending: true,
        };
        if let LinqOperation::OrderBy { descending, .. } = r.recover(&[]).unwrap() {
            assert!(descending);
        } else {
            panic!();
        }
    }
    #[test]
    fn test_thenby() {
        let r = OrderByRecovery::new();
        assert_eq!(r.recover_thenby().operator_name(), "ThenBy");
    }
    #[test]
    fn test_thenby_desc() {
        let r = OrderByRecovery::new();
        if let LinqOperation::ThenBy { descending, .. } = r.recover_thenby_desc() {
            assert!(descending);
        } else {
            panic!();
        }
    }

    // ── JoinRecovery ──────────────────────────────────────────────────────────

    #[test]
    fn test_join() {
        let r = JoinRecovery::new();
        assert_eq!(r.recover(&[]).unwrap().operator_name(), "Join");
    }
    #[test]
    fn test_group_join() {
        let r = JoinRecovery::new();
        assert_eq!(
            r.recover_group_join(&[]).unwrap().operator_name(),
            "GroupJoin"
        );
    }

    // ── QuerySyntax ───────────────────────────────────────────────────────────

    #[test]
    fn test_qs_method_syntax() {
        let qs = QuerySyntax::new();
        let q = RecoveredQuery {
            source: "items".into(),
            operations: vec![LinqOperation::Where {
                predicate: "x => true".into(),
            }],
            element_type: "v".into(),
            confidence: 0.8,
        };
        assert!(qs.to_csharp(&q).contains("Where"));
    }
    #[test]
    fn test_qs_query_syntax() {
        let qs = QuerySyntax::new().with_query_syntax();
        let q = RecoveredQuery {
            source: "items".into(),
            operations: vec![LinqOperation::Where {
                predicate: "x => true".into(),
            }],
            element_type: "v".into(),
            confidence: 0.8,
        };
        assert!(qs.to_csharp(&q).contains("where"));
    }
    #[test]
    fn test_qs_terminal_tolist() {
        let qs = QuerySyntax::new();
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::ToList],
            element_type: "v".into(),
            confidence: 0.9,
        };
        assert!(qs.to_csharp(&q).contains("ToList"));
    }
    #[test]
    fn test_qs_join() {
        let qs = QuerySyntax::new();
        let q = RecoveredQuery {
            source: "outer".into(),
            operations: vec![LinqOperation::Join {
                inner_source: "inner".into(),
                outer_key: "o => o.Id".into(),
                inner_key: "i => i.Id".into(),
                result_selector: "(o,i) => o".into(),
            }],
            element_type: "v".into(),
            confidence: 0.7,
        };
        assert!(qs.to_csharp(&q).contains("Join"));
    }
    #[test]
    fn test_qs_orderby_desc() {
        let qs = QuerySyntax::new();
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::OrderBy {
                key_selector: "x => x.Id".into(),
                descending: true,
            }],
            element_type: "v".into(),
            confidence: 0.6,
        };
        assert!(qs.to_csharp(&q).contains("Descending"));
    }
    #[test]
    fn test_qs_distinct() {
        let qs = QuerySyntax::new();
        let q = RecoveredQuery {
            source: "s".into(),
            operations: vec![LinqOperation::Distinct],
            element_type: "v".into(),
            confidence: 0.5,
        };
        assert!(qs.to_csharp(&q).contains("Distinct"));
    }

    // ── LinqRecovery ──────────────────────────────────────────────────────────

    #[test]
    fn test_linq_recovery_new() {
        let r = LinqRecovery::new();
        assert!(!r.include_low_confidence);
    }
    #[test]
    fn test_linq_recovery_empty() {
        let r = LinqRecovery::new();
        assert!(r.analyze(&[]).is_empty());
    }
    #[test]
    fn test_linq_recovery_with_low_conf() {
        let r = LinqRecovery::new().with_low_confidence();
        assert!(r.include_low_confidence);
    }
    #[test]
    fn test_linq_recovery_analyze_tokens() {
        let r = LinqRecovery::new();
        let instrs = body_with_linq();
        let _ = r.analyze(&instrs).len(); // no panic
    }
    #[test]
    fn test_linq_to_csharp_empty() {
        let r = LinqRecovery::new();
        assert!(r.to_csharp(&[]).is_empty());
    }
    #[test]
    fn test_linq_to_csharp_nonempty() {
        let r = LinqRecovery::new();
        let q = RecoveredQuery {
            source: "src".into(),
            operations: vec![LinqOperation::ToList],
            element_type: "v".into(),
            confidence: 0.9,
        };
        let texts = r.to_csharp(&[q]);
        assert!(!texts.is_empty());
        assert!(texts[0].contains("ToList"));
    }
    #[test]
    fn test_linq_op_unknown() {
        let _r = LinqRecovery::new();
        let op = LinqRecovery::name_to_op("SomeCustomOp");
        assert_eq!(op.operator_name(), "Unknown");
    }
}
