//! TTD query optimizer: translates logical queries into physical execution plans.

use std::collections::HashMap;
use std::fmt;

use crate::Query;

// ── PlanNode ──────────────────────────────────────────────────────────────────

/// A node in a physical query plan tree.
#[derive(Debug, Clone)]
pub enum PlanNode {
    /// Full sequential scan of all events.
    Scan { estimated_rows: u64 },
    /// Index-based scan for a specific address.
    IndexScan {
        index: IndexType,
        key: u64,
        estimated_rows: u64,
    },
    /// Range scan on an index.
    IndexRangeScan {
        index: IndexType,
        lo: u64,
        hi: u64,
        estimated_rows: u64,
    },
    /// Filter applied to the output of a child plan.
    Filter {
        predicate: Predicate,
        child: Box<Self>,
        estimated_rows: u64,
    },
    /// Sort by trace position.
    Sort {
        order: SortOrder,
        child: Box<Self>,
        estimated_rows: u64,
    },
    /// Limit the number of output rows.
    Limit {
        count: u64,
        child: Box<Self>,
        estimated_rows: u64,
    },
    /// Hash join two sub-plans on matching trace positions.
    Join {
        join_type: JoinType,
        left: Box<Self>,
        right: Box<Self>,
        estimated_rows: u64,
    },
    /// Aggregation (count, min, max) grouped by a field.
    Aggregate {
        agg: AggregateKind,
        group_by: Option<GroupByField>,
        child: Box<Self>,
        estimated_rows: u64,
    },
}

impl PlanNode {
    /// Return the estimated number of output rows for this node.
    #[must_use]
    pub const fn estimated_rows(&self) -> u64 {
        match self {
            Self::Scan { estimated_rows } | Self::IndexScan { estimated_rows, .. } | Self::IndexRangeScan { estimated_rows, .. } | Self::Filter { estimated_rows, .. } | Self::Sort { estimated_rows, .. } | Self::Limit { estimated_rows, .. } | Self::Join { estimated_rows, .. } | Self::Aggregate { estimated_rows, .. } => *estimated_rows,
        }
    }

    /// Estimate the cost of executing this node (unit: "operations").
    #[must_use]
    pub fn estimated_cost(&self) -> f64 {
        match self {
            Self::Scan { estimated_rows } => *estimated_rows as f64 * 1.0,
            Self::IndexScan { estimated_rows, .. } => (*estimated_rows as f64).mul_add(0.1, 100.0),
            Self::IndexRangeScan { estimated_rows, .. } => {
                (*estimated_rows as f64).mul_add(0.15, 200.0)
            }
            Self::Filter {
                child,
                estimated_rows,
                ..
            } => (*estimated_rows as f64).mul_add(0.2, child.estimated_cost()),
            Self::Sort {
                child,
                estimated_rows,
                ..
            } => (*estimated_rows as f64).mul_add(
                (*estimated_rows as f64).log2().max(1.0),
                child.estimated_cost(),
            ),
            Self::Limit { child, .. } => child.estimated_cost() * 0.1,
            Self::Join {
                left,
                right,
                estimated_rows,
                ..
            } => (*estimated_rows as f64)
                .mul_add(0.5, left.estimated_cost() + right.estimated_cost()),
            Self::Aggregate { child, .. } => child.estimated_cost() * 1.2,
        }
    }

    /// Return `true` if this plan node or any descendant uses an index.
    #[must_use]
    pub fn uses_index(&self) -> bool {
        match self {
            Self::IndexScan { .. } | Self::IndexRangeScan { .. } => true,
            Self::Filter { child, .. } | Self::Sort { child, .. } | Self::Limit { child, .. } | Self::Aggregate { child, .. } => child.uses_index(),
            Self::Join { left, right, .. } => left.uses_index() || right.uses_index(),
            Self::Scan { .. } => false,
        }
    }

    /// Depth of the plan tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Scan { .. } | Self::IndexScan { .. } | Self::IndexRangeScan { .. } => 1,
            Self::Filter { child, .. }
            | Self::Sort { child, .. }
            | Self::Limit { child, .. }
            | Self::Aggregate { child, .. } => 1 + child.depth(),
            Self::Join { left, right, .. } => 1 + left.depth().max(right.depth()),
        }
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexType {
    Address,
    Thread,
    Syscall,
    CallTarget,
    CallSource,
    Position,
}

impl fmt::Display for IndexType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub enum Predicate {
    AddressEquals(u64),
    AddressRange { lo: u64, hi: u64 },
    ThreadEquals(u32),
    SyscallNumber(u32),
    EventKind(String),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
    True,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinType {
    Inner,
    LeftOuter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateKind {
    Count,
    Min,
    Max,
    Sum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupByField {
    Thread,
    EventKind,
    Address,
}

// ── QueryPlan ─────────────────────────────────────────────────────────────────

/// A complete physical query plan.
#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub root: PlanNode,
    pub query_description: String,
    pub optimizer_notes: Vec<String>,
}

impl QueryPlan {
    pub fn new(root: PlanNode, description: impl Into<String>) -> Self {
        Self {
            root,
            query_description: description.into(),
            optimizer_notes: Vec::new(),
        }
    }

    #[must_use]
    pub fn estimated_cost(&self) -> f64 {
        self.root.estimated_cost()
    }
    #[must_use]
    pub fn uses_index(&self) -> bool {
        self.root.uses_index()
    }
    #[must_use]
    pub const fn estimated_rows(&self) -> u64 {
        self.root.estimated_rows()
    }
}

impl fmt::Display for QueryPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QueryPlan[{}] rows~{} cost~{:.0} index={}",
            self.query_description,
            self.estimated_rows(),
            self.estimated_cost(),
            self.uses_index()
        )
    }
}

// ── CostModel ─────────────────────────────────────────────────────────────────

/// Provides cost estimates for planning decisions.
pub struct CostModel {
    pub total_events: u64,
    pub index_selectivity: f64,
}

impl CostModel {
    #[must_use]
    pub const fn new(total_events: u64) -> Self {
        Self {
            total_events,
            index_selectivity: 0.01,
        }
    }

    /// Estimate rows returned by an index scan for one key.
    #[must_use]
    pub fn index_scan_rows(&self) -> u64 {
        (self.total_events as f64 * self.index_selectivity).ceil() as u64
    }

    /// Estimate rows returned by a range scan.
    #[must_use]
    pub fn range_scan_rows(&self, range_fraction: f64) -> u64 {
        (self.total_events as f64 * range_fraction.clamp(0.0, 1.0)).ceil() as u64
    }

    /// Estimate cost of a hash join given left and right row counts.
    #[must_use]
    pub fn join_cost(&self, left_rows: u64, right_rows: u64) -> f64 {
        (left_rows + right_rows) as f64 * 0.5
    }

    #[must_use]
    pub const fn scan_cost(&self) -> f64 {
        self.total_events as f64
    }
}

// ── QueryOptimizer ────────────────────────────────────────────────────────────

/// Transforms a logical [`Query`] into a physical [`QueryPlan`].
pub struct QueryOptimizer {
    cost_model: CostModel,
}

impl QueryOptimizer {
    #[must_use]
    pub const fn new(total_events: u64) -> Self {
        Self {
            cost_model: CostModel::new(total_events),
        }
    }

    /// Optimize a logical query into a physical plan.
    #[must_use]
    pub fn optimize(&self, query: &Query) -> QueryPlan {
        let description = format!("{query}");
        let root = self.plan_node(query);
        let mut plan = QueryPlan::new(root, description);
        self.add_optimizer_notes(&mut plan, query);
        plan
    }

    fn plan_node(&self, query: &Query) -> PlanNode {
        match query {
            Query::AllEvents => PlanNode::Scan {
                estimated_rows: self.cost_model.total_events,
            },

            Query::Pattern(p) => {
                let desc = format!("{p}");
                // Use index for address-specific patterns.
                if desc.contains("At(") || desc.contains("CallTo") || desc.contains("CallFrom") {
                    // Try to extract key from pattern description.
                    let rows = self.cost_model.index_scan_rows();
                    PlanNode::IndexScan {
                        index: IndexType::Address,
                        key: 0,
                        estimated_rows: rows,
                    }
                } else {
                    PlanNode::Filter {
                        predicate: Predicate::True,
                        child: Box::new(PlanNode::Scan {
                            estimated_rows: self.cost_model.total_events,
                        }),
                        estimated_rows: self.cost_model.total_events / 10,
                    }
                }
            }

            Query::EventsOfKind(kind) => {
                let kind_str = format!("{kind:?}");
                PlanNode::Filter {
                    predicate: Predicate::EventKind(kind_str),
                    child: Box::new(PlanNode::Scan {
                        estimated_rows: self.cost_model.total_events,
                    }),
                    estimated_rows: self.cost_model.total_events / 8,
                }
            }

            Query::EventsInRange { start, end, .. } => {
                let range_rows = self.cost_model.range_scan_rows(0.05);
                PlanNode::IndexRangeScan {
                    index: IndexType::Address,
                    lo: *start,
                    hi: *end,
                    estimated_rows: range_rows,
                }
            }

            Query::Thread(tid) => {
                let rows = self.cost_model.range_scan_rows(0.25);
                PlanNode::IndexScan {
                    index: IndexType::Thread,
                    key: u64::from(*tid),
                    estimated_rows: rows,
                }
            }

            Query::InTimeRange(_) => PlanNode::Filter {
                predicate: Predicate::True,
                child: Box::new(PlanNode::Scan {
                    estimated_rows: self.cost_model.total_events,
                }),
                estimated_rows: self.cost_model.total_events / 4,
            },

            Query::CallChain { from, to } => {
                let from_rows = self.cost_model.index_scan_rows();
                let to_rows = self.cost_model.index_scan_rows();
                PlanNode::Join {
                    join_type: JoinType::Inner,
                    left: Box::new(PlanNode::IndexScan {
                        index: IndexType::CallSource,
                        key: *from,
                        estimated_rows: from_rows,
                    }),
                    right: Box::new(PlanNode::IndexScan {
                        index: IndexType::CallTarget,
                        key: *to,
                        estimated_rows: to_rows,
                    }),
                    estimated_rows: from_rows.min(to_rows),
                }
            }

            Query::DataFlow {
                source_addr,
                sink_addr,
            } => {
                let src_rows = self.cost_model.index_scan_rows();
                let snk_rows = self.cost_model.index_scan_rows();
                PlanNode::Join {
                    join_type: JoinType::Inner,
                    left: Box::new(PlanNode::IndexScan {
                        index: IndexType::Address,
                        key: *source_addr,
                        estimated_rows: src_rows,
                    }),
                    right: Box::new(PlanNode::IndexScan {
                        index: IndexType::Address,
                        key: *sink_addr,
                        estimated_rows: snk_rows,
                    }),
                    estimated_rows: src_rows.min(snk_rows),
                }
            }

            Query::Loops { .. } => PlanNode::Aggregate {
                agg: AggregateKind::Count,
                group_by: Some(GroupByField::Address),
                child: Box::new(PlanNode::Filter {
                    predicate: Predicate::EventKind("Call".to_string()),
                    child: Box::new(PlanNode::Scan {
                        estimated_rows: self.cost_model.total_events,
                    }),
                    estimated_rows: self.cost_model.total_events / 5,
                }),
                estimated_rows: self.cost_model.total_events / 100,
            },

            Query::Sequence(patterns) => PlanNode::Filter {
                predicate: Predicate::True,
                child: Box::new(PlanNode::Scan {
                    estimated_rows: self.cost_model.total_events,
                }),
                estimated_rows: self.cost_model.total_events / (patterns.len() as u64 + 1),
            },

            Query::And(qs) => {
                if qs.is_empty() {
                    return PlanNode::Scan { estimated_rows: 0 };
                }
                let left = self.plan_node(&qs[0]);
                let right = self.plan_node(&qs[1.min(qs.len() - 1)]);
                let left_rows = left.estimated_rows();
                let right_rows = right.estimated_rows();
                PlanNode::Join {
                    join_type: JoinType::Inner,
                    left: Box::new(left),
                    right: Box::new(right),
                    estimated_rows: left_rows.min(right_rows),
                }
            }

            Query::Or(qs) => {
                if qs.is_empty() {
                    return PlanNode::Scan { estimated_rows: 0 };
                }
                let total: u64 = qs.iter().map(|q| self.plan_node(q).estimated_rows()).sum();
                PlanNode::Sort {
                    order: SortOrder::Ascending,
                    child: Box::new(PlanNode::Scan {
                        estimated_rows: total,
                    }),
                    estimated_rows: total,
                }
            }

            Query::Not(inner) => {
                let inner_rows = self.plan_node(inner).estimated_rows();
                let remaining = self.cost_model.total_events.saturating_sub(inner_rows);
                PlanNode::Filter {
                    predicate: Predicate::True,
                    child: Box::new(PlanNode::Scan {
                        estimated_rows: self.cost_model.total_events,
                    }),
                    estimated_rows: remaining,
                }
            }

            Query::Before { a, b } | Query::After { a, b } => {
                let a_rows = self.plan_node(a).estimated_rows();
                let b_rows = self.plan_node(b).estimated_rows();
                PlanNode::Filter {
                    predicate: Predicate::True,
                    child: Box::new(PlanNode::Scan {
                        estimated_rows: self.cost_model.total_events,
                    }),
                    estimated_rows: u64::midpoint(a_rows, b_rows),
                }
            }
        }
    }

    fn add_optimizer_notes(&self, plan: &mut QueryPlan, query: &Query) {
        if plan.uses_index() {
            plan.optimizer_notes.push("Index scan applied".to_string());
        }
        if plan.estimated_cost() > self.cost_model.scan_cost() * 2.0 {
            plan.optimizer_notes
                .push("Consider adding an index for this workload".to_string());
        }
        match query {
            Query::Thread(_) => plan
                .optimizer_notes
                .push("Thread filter uses thread index".to_string()),
            Query::CallChain { .. } => plan
                .optimizer_notes
                .push("CallChain uses call-site indexes".to_string()),
            _ => {}
        }
    }

    /// Return the cheaper of two plans.
    #[must_use]
    pub fn choose_cheaper(&self, a: QueryPlan, b: QueryPlan) -> QueryPlan {
        if a.estimated_cost() <= b.estimated_cost() {
            a
        } else {
            b
        }
    }
}

// ── IndexScan helper ──────────────────────────────────────────────────────────

/// Represents the result of an index scan (offsets into the event array).
#[derive(Debug, Clone, Default)]
pub struct IndexScanResult {
    pub index_type: Option<IndexType>,
    pub key: u64,
    pub event_indices: Vec<usize>,
}

impl IndexScanResult {
    #[must_use]
    pub const fn new(index_type: IndexType, key: u64) -> Self {
        Self {
            index_type: Some(index_type),
            key,
            event_indices: Vec::new(),
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.event_indices.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.event_indices.is_empty()
    }
}

// ── PlanExplainer ─────────────────────────────────────────────────────────────

/// Produces human-readable explain output for a query plan.
pub struct PlanExplainer;

impl PlanExplainer {
    /// Format a query plan as a multi-line explain string.
    #[must_use]
    pub fn explain(plan: &QueryPlan) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Query: {}", plan.query_description));
        lines.push(format!("Estimated cost: {:.1}", plan.estimated_cost()));
        lines.push(format!("Estimated rows: {}", plan.estimated_rows()));
        lines.push(format!("Uses index: {}", plan.uses_index()));
        if !plan.optimizer_notes.is_empty() {
            lines.push("Optimizer notes:".to_string());
            for note in &plan.optimizer_notes {
                lines.push(format!("  - {note}"));
            }
        }
        lines.push(String::new());
        lines.push("Plan tree:".to_string());
        Self::explain_node(&plan.root, 0, &mut lines);
        lines.join("\n")
    }

    fn explain_node(node: &PlanNode, indent: usize, lines: &mut Vec<String>) {
        let pad = "  ".repeat(indent);
        match node {
            PlanNode::Scan { estimated_rows } => {
                lines.push(format!("{pad}Scan (rows~{estimated_rows})"));
            }
            PlanNode::IndexScan {
                index,
                key,
                estimated_rows,
            } => lines.push(format!(
                "{pad}IndexScan[{index}={key:#x}] (rows~{estimated_rows})"
            )),
            PlanNode::IndexRangeScan {
                index,
                lo,
                hi,
                estimated_rows,
            } => lines.push(format!(
                "{pad}RangeScan[{index} {lo:#x}..{hi:#x}] (rows~{estimated_rows})"
            )),
            PlanNode::Filter {
                predicate,
                child,
                estimated_rows,
            } => {
                lines.push(format!(
                    "{pad}Filter[{predicate:?}] (rows~{estimated_rows})"
                ));
                Self::explain_node(child, indent + 1, lines);
            }
            PlanNode::Sort {
                order,
                child,
                estimated_rows,
            } => {
                lines.push(format!("{pad}Sort[{order:?}] (rows~{estimated_rows})"));
                Self::explain_node(child, indent + 1, lines);
            }
            PlanNode::Limit {
                count,
                child,
                estimated_rows,
            } => {
                lines.push(format!("{pad}Limit[{count}] (rows~{estimated_rows})"));
                Self::explain_node(child, indent + 1, lines);
            }
            PlanNode::Join {
                join_type,
                left,
                right,
                estimated_rows,
            } => {
                lines.push(format!("{pad}Join[{join_type:?}] (rows~{estimated_rows})"));
                Self::explain_node(left, indent + 1, lines);
                Self::explain_node(right, indent + 1, lines);
            }
            PlanNode::Aggregate {
                agg,
                group_by,
                child,
                estimated_rows,
            } => {
                lines.push(format!(
                    "{pad}Aggregate[{agg:?} by {group_by:?}] (rows~{estimated_rows})"
                ));
                Self::explain_node(child, indent + 1, lines);
            }
        }
    }
}

// ── QueryExecutor (physical) ──────────────────────────────────────────────────

/// Executes physical query plans against a flat event list.
///
/// In production this would drive actual index lookups; here it wraps the
/// logical query engine for correctness and uses the plan only for metadata.
pub struct QueryExecutor {
    pub total_events: u64,
}

impl QueryExecutor {
    #[must_use]
    pub const fn new(total_events: u64) -> Self {
        Self { total_events }
    }

    /// Estimate how many events the plan will touch (scan fraction).
    #[must_use]
    pub fn estimate_scan_fraction(&self, plan: &QueryPlan) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }
        (plan.estimated_rows() as f64 / self.total_events as f64).min(1.0)
    }

    /// Return a cost-tier label for the plan.
    #[must_use]
    pub fn cost_tier(&self, plan: &QueryPlan) -> &'static str {
        let cost = plan.estimated_cost();
        let scan = self.total_events as f64;
        if cost < scan * 0.1 {
            "cheap"
        } else if cost < scan * 0.5 {
            "moderate"
        } else {
            "expensive"
        }
    }

    /// Build an execution summary (metadata only, no actual event iteration).
    #[must_use]
    pub fn build_summary(&self, plan: &QueryPlan) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(
            "estimated_rows".to_string(),
            serde_json::json!(plan.estimated_rows()),
        );
        m.insert(
            "estimated_cost".to_string(),
            serde_json::json!(plan.estimated_cost() as u64),
        );
        m.insert(
            "uses_index".to_string(),
            serde_json::json!(plan.uses_index()),
        );
        m.insert(
            "cost_tier".to_string(),
            serde_json::json!(self.cost_tier(plan)),
        );
        m.insert(
            "scan_fraction".to_string(),
            serde_json::json!(self.estimate_scan_fraction(plan)),
        );
        m.insert(
            "plan_depth".to_string(),
            serde_json::json!(plan.root.depth()),
        );
        m
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemAccessKind;
    

    fn optimizer(n: u64) -> QueryOptimizer {
        QueryOptimizer::new(n)
    }

    // ── CostModel ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cost_model_index_rows() {
        let cm = CostModel::new(10_000);
        assert!(cm.index_scan_rows() < 1000);
    }

    #[test]
    fn test_cost_model_range_rows() {
        let cm = CostModel::new(10_000);
        let rows = cm.range_scan_rows(0.1);
        assert_eq!(rows, 1000);
    }

    #[test]
    fn test_cost_model_join_cost() {
        let cm = CostModel::new(10_000);
        let cost = cm.join_cost(100, 200);
        assert_eq!(cost, 150.0);
    }

    // ── PlanNode ──────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_estimated_rows() {
        let node = PlanNode::Scan {
            estimated_rows: 500,
        };
        assert_eq!(node.estimated_rows(), 500);
    }

    #[test]
    fn test_index_scan_uses_index() {
        let node = PlanNode::IndexScan {
            index: IndexType::Address,
            key: 0x1000,
            estimated_rows: 10,
        };
        assert!(node.uses_index());
    }

    #[test]
    fn test_scan_no_index() {
        let node = PlanNode::Scan {
            estimated_rows: 100,
        };
        assert!(!node.uses_index());
    }

    #[test]
    fn test_filter_depth() {
        let node = PlanNode::Filter {
            predicate: Predicate::True,
            child: Box::new(PlanNode::Scan {
                estimated_rows: 100,
            }),
            estimated_rows: 50,
        };
        assert_eq!(node.depth(), 2);
    }

    #[test]
    fn test_join_depth() {
        let node = PlanNode::Join {
            join_type: JoinType::Inner,
            left: Box::new(PlanNode::Scan { estimated_rows: 10 }),
            right: Box::new(PlanNode::Scan { estimated_rows: 10 }),
            estimated_rows: 5,
        };
        assert_eq!(node.depth(), 2);
    }

    #[test]
    fn test_index_scan_cost_lower_than_scan() {
        let scan = PlanNode::Scan {
            estimated_rows: 10_000,
        };
        let idx = PlanNode::IndexScan {
            index: IndexType::Address,
            key: 0,
            estimated_rows: 10,
        };
        assert!(idx.estimated_cost() < scan.estimated_cost());
    }

    // ── QueryOptimizer ────────────────────────────────────────────────────────

    #[test]
    fn test_optimize_all_events_is_scan() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::AllEvents);
        assert!(!plan.uses_index());
        assert_eq!(plan.estimated_rows(), 1000);
    }

    #[test]
    fn test_optimize_thread_uses_index() {
        let opt = optimizer(5000);
        let plan = opt.optimize(&Query::Thread(42));
        assert!(plan.uses_index());
    }

    #[test]
    fn test_optimize_events_in_range_uses_index() {
        let opt = optimizer(5000);
        let plan = opt.optimize(&Query::EventsInRange {
            start: 0x1000,
            end: 0x2000,
            kind: MemAccessKind::Any,
        });
        assert!(plan.uses_index());
    }

    #[test]
    fn test_optimize_call_chain_join() {
        let opt = optimizer(10_000);
        let plan = opt.optimize(&Query::CallChain {
            from: 0x1000,
            to: 0x2000,
        });
        assert!(matches!(plan.root, PlanNode::Join { .. }));
        assert!(plan.uses_index());
    }

    #[test]
    fn test_optimize_loops_aggregate() {
        let opt = optimizer(10_000);
        let plan = opt.optimize(&Query::Loops { min_iterations: 5 });
        assert!(matches!(plan.root, PlanNode::Aggregate { .. }));
    }

    #[test]
    fn test_optimize_and_is_join() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::And(vec![Query::AllEvents, Query::Thread(1)]));
        assert!(matches!(plan.root, PlanNode::Join { .. }));
    }

    #[test]
    fn test_optimize_or_is_sort() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::Or(vec![Query::Thread(1), Query::Thread(2)]));
        assert!(matches!(plan.root, PlanNode::Sort { .. }));
    }

    #[test]
    fn test_optimize_not_is_filter() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::Not(Box::new(Query::Thread(0))));
        assert!(matches!(plan.root, PlanNode::Filter { .. }));
    }

    #[test]
    fn test_optimizer_notes_for_thread() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::Thread(5));
        assert!(plan.optimizer_notes.iter().any(|n| n.contains("thread")));
    }

    #[test]
    fn test_choose_cheaper() {
        let opt = optimizer(1000);
        let cheap = QueryPlan::new(
            PlanNode::IndexScan {
                index: IndexType::Address,
                key: 0,
                estimated_rows: 5,
            },
            "cheap",
        );
        let expensive = QueryPlan::new(
            PlanNode::Scan {
                estimated_rows: 1000,
            },
            "expensive",
        );
        let winner = opt.choose_cheaper(cheap, expensive);
        assert!(winner.estimated_cost() < 1000.0);
    }

    // ── PlanExplainer ─────────────────────────────────────────────────────────

    #[test]
    fn test_explain_contains_query() {
        let opt = optimizer(500);
        let plan = opt.optimize(&Query::AllEvents);
        let s = PlanExplainer::explain(&plan);
        assert!(s.contains("Query:"));
        assert!(s.contains("Scan"));
    }

    #[test]
    fn test_explain_contains_index_info() {
        let opt = optimizer(500);
        let plan = opt.optimize(&Query::Thread(1));
        let s = PlanExplainer::explain(&plan);
        assert!(s.contains("Index") || s.contains("index"));
    }

    #[test]
    fn test_explain_join_shows_both_children() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::CallChain {
            from: 0x100,
            to: 0x200,
        });
        let s = PlanExplainer::explain(&plan);
        assert!(s.contains("Join"));
    }

    // ── QueryExecutor ─────────────────────────────────────────────────────────

    #[test]
    fn test_executor_scan_fraction() {
        let opt = optimizer(10_000);
        let plan = opt.optimize(&Query::Thread(1));
        let exec = QueryExecutor::new(10_000);
        let frac = exec.estimate_scan_fraction(&plan);
        assert!((0.0..=1.0).contains(&frac));
    }

    #[test]
    fn test_executor_cost_tier_cheap() {
        let exec = QueryExecutor::new(10_000);
        let plan = QueryPlan::new(
            PlanNode::IndexScan {
                index: IndexType::Address,
                key: 0,
                estimated_rows: 1,
            },
            "q",
        );
        assert_eq!(exec.cost_tier(&plan), "cheap");
    }

    #[test]
    fn test_executor_cost_tier_expensive() {
        let exec = QueryExecutor::new(10);
        let plan = QueryPlan::new(PlanNode::Scan { estimated_rows: 10 }, "full");
        let tier = exec.cost_tier(&plan);
        assert_eq!(tier, "expensive");
    }

    #[test]
    fn test_executor_build_summary() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::AllEvents);
        let exec = QueryExecutor::new(1000);
        let summary = exec.build_summary(&plan);
        assert!(summary.contains_key("estimated_rows"));
        assert!(summary.contains_key("uses_index"));
        assert!(summary.contains_key("cost_tier"));
        assert!(summary.contains_key("plan_depth"));
    }

    #[test]
    fn test_index_scan_result_empty() {
        let r = IndexScanResult::new(IndexType::Address, 0x1000);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_query_plan_display() {
        let plan = QueryPlan::new(
            PlanNode::Scan {
                estimated_rows: 100,
            },
            "AllEvents",
        );
        let s = plan.to_string();
        assert!(s.contains("QueryPlan"));
    }

    #[test]
    fn test_optimize_data_flow_join() {
        let opt = optimizer(5000);
        let plan = opt.optimize(&Query::DataFlow {
            source_addr: 0xAAA,
            sink_addr: 0xBBB,
        });
        assert!(matches!(plan.root, PlanNode::Join { .. }));
    }

    #[test]
    fn test_optimize_empty_and() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::And(vec![]));
        assert_eq!(plan.estimated_rows(), 0);
    }

    #[test]
    fn test_optimize_empty_or() {
        let opt = optimizer(1000);
        let plan = opt.optimize(&Query::Or(vec![]));
        assert_eq!(plan.estimated_rows(), 0);
    }
}
