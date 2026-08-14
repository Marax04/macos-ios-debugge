//! Dependency-ordered analysis-pass runner.
//!
//! [`AnalysisPipeline`](crate::AnalysisPipeline) runs passes in registration
//! order, and [`PassScheduler`](crate::PassScheduler) computes a topological
//! order from declared dependencies — but nothing ties them together to
//! actually *execute* passes in dependency order while reporting per-pass
//! status.  This module provides [`DependencyRunner`], which:
//!
//! * registers passes together with their dependency lists,
//! * topologically schedules them (failing fast on cycles),
//! * executes them in order against a [`BinaryView`], and
//! * skips any pass whose dependency failed, recording the reason.
//!
//! It is additive: it composes the existing [`AnalysisPass`], [`PassScheduler`],
//! and [`AnalysisResult`] types without changing them.

use crate::{AnalysisConfig, AnalysisPass, AnalysisResult, PassDescriptor, PassScheduler};
use rustre_core::binary_view::BinaryView;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// The outcome of a single pass within a dependency run.
#[derive(Debug, Clone)]
pub enum PassOutcome {
    /// The pass ran and produced a result.
    Completed(AnalysisResult),
    /// The pass failed with an error message.
    Failed(String),
    /// The pass was skipped because a dependency did not complete.
    Skipped {
        /// Name of the dependency that caused the skip.
        blocked_by: String,
    },
}

impl PassOutcome {
    /// Whether the pass completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// The result, if completed.
    #[must_use]
    pub const fn result(&self) -> Option<&AnalysisResult> {
        match self {
            Self::Completed(r) => Some(r),
            _ => None,
        }
    }
}

/// A pass plus its declared dependencies, held by the runner.
struct RunnerEntry {
    pass: Arc<dyn AnalysisPass>,
    deps: Vec<String>,
}

/// Executes registered passes in dependency order.
#[derive(Default)]
pub struct DependencyRunner {
    entries: HashMap<String, RunnerEntry>,
    order_hint: Vec<String>,
}

impl std::fmt::Debug for DependencyRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyRunner")
            .field("pass_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl DependencyRunner {
    /// Create an empty runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass with no dependencies.
    pub fn add(&mut self, pass: Arc<dyn AnalysisPass>) {
        self.add_with_deps(pass, Vec::new());
    }

    /// Register a pass that depends on the named passes.
    pub fn add_with_deps(&mut self, pass: Arc<dyn AnalysisPass>, deps: Vec<String>) {
        let name = pass.name().to_string();
        self.order_hint.push(name.clone());
        self.entries.insert(name, RunnerEntry { pass, deps });
    }

    /// Number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the dependency-respecting execution order.
    ///
    /// # Errors
    /// Returns an error string if the dependency graph contains a cycle or
    /// references an unknown pass.
    pub fn schedule(&self) -> Result<Vec<String>, String> {
        let mut scheduler = PassScheduler::new();
        for name in &self.order_hint {
            let entry = &self.entries[name];
            let mut desc = PassDescriptor::new(name.clone()).with_priority(entry.pass.priority());
            for dep in &entry.deps {
                if !self.entries.contains_key(dep) {
                    return Err(format!("pass '{name}' depends on unknown pass '{dep}'"));
                }
                desc = desc.with_dep(dep.clone());
            }
            scheduler.add(desc);
        }
        scheduler.schedule()
    }

    /// Execute all passes in dependency order against `view`.
    ///
    /// A pass is skipped (and its transitive dependents skipped) when any of its
    /// dependencies failed or was itself skipped.  Returns the per-pass outcome
    /// map plus the execution order actually used.
    ///
    /// # Errors
    /// Returns an error if scheduling fails (cycle / unknown dependency).
    pub async fn run(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<RunReport, String> {
        let order = self.schedule()?;
        let mut outcomes: HashMap<String, PassOutcome> = HashMap::new();
        let mut failed_or_skipped: HashSet<String> = HashSet::new();

        for name in &order {
            let entry = &self.entries[name];

            // If any dependency failed/skipped, skip this pass too.
            if let Some(bad) = entry.deps.iter().find(|d| failed_or_skipped.contains(*d)) {
                outcomes.insert(
                    name.clone(),
                    PassOutcome::Skipped {
                        blocked_by: bad.clone(),
                    },
                );
                failed_or_skipped.insert(name.clone());
                continue;
            }

            match entry.pass.run(view, config).await {
                Ok(result) => {
                    outcomes.insert(name.clone(), PassOutcome::Completed(result));
                }
                Err(e) => {
                    outcomes.insert(name.clone(), PassOutcome::Failed(e.to_string()));
                    failed_or_skipped.insert(name.clone());
                }
            }
        }

        Ok(RunReport { order, outcomes })
    }
}

/// The full report of a dependency run.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// The execution order used.
    pub order: Vec<String>,
    /// Per-pass outcomes.
    pub outcomes: HashMap<String, PassOutcome>,
}

impl RunReport {
    /// Outcome for a named pass.
    #[must_use]
    pub fn outcome(&self, name: &str) -> Option<&PassOutcome> {
        self.outcomes.get(name)
    }

    /// Number of passes that completed successfully.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.outcomes.values().filter(|o| o.is_completed()).count()
    }

    /// Number of passes that failed.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| matches!(o, PassOutcome::Failed(_)))
            .count()
    }

    /// Number of passes that were skipped.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| matches!(o, PassOutcome::Skipped { .. }))
            .count()
    }

    /// Whether every pass completed successfully.
    #[must_use]
    pub fn all_completed(&self) -> bool {
        self.failed_count() == 0 && self.skipped_count() == 0
    }

    /// Total functions discovered across all completed passes.
    #[must_use]
    pub fn total_functions(&self) -> usize {
        self.outcomes
            .values()
            .filter_map(PassOutcome::result)
            .map(|r| r.functions_found)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalysisError, AnalysisKind, CountingAnalysisPass};
    use async_trait::async_trait;
    use rustre_core::{
        address::{Address, AddressRange},
        arch::{
            Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
        },
        binary_view::{BinaryView, Memory, Segment},
        endian::Endian,
        errors::CoreError,
        ids::ViewId,
        permissions::Permissions,
    };

    #[derive(Debug)]
    struct DummyArch;

    impl Architecture for DummyArch {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
            Ok(Instruction {
                address,
                size: 1,
                mnemonic: "nop".into(),
                operands: String::new(),
                operand_list: Vec::new(),
                flags: InstrFlags::NONE,
                bytes: vec![0x90],
                comment: None,
            })
        }
        fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }

    fn make_view() -> BinaryView {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: vec![0x90; 0x1000],
        });
        BinaryView::new(
            ViewId::new(1).expect("non-zero view id"),
            "test://dummy".into(),
            Arc::new(DummyArch),
            Endian::Little,
            64,
            vec![Address::new(0x1000)],
            mem,
        )
    }

    /// A pass that always fails, for testing skip propagation.
    struct FailingPass {
        name: String,
    }

    #[async_trait]
    impl AnalysisPass for FailingPass {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> AnalysisKind {
            AnalysisKind::Custom("fail".into())
        }
        fn description(&self) -> &'static str {
            "always fails"
        }
        async fn run(
            &self,
            _view: &BinaryView,
            _config: &AnalysisConfig,
        ) -> Result<AnalysisResult, AnalysisError> {
            Err(AnalysisError::Failed("boom".into()))
        }
    }

    #[test]
    fn schedule_respects_dependencies() {
        let mut runner = DependencyRunner::new();
        runner.add(Arc::new(CountingAnalysisPass::new(
            "sweep",
            AnalysisKind::LinearSweep,
            1,
            0,
        )));
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "xref",
                AnalysisKind::XrefRecovery,
                0,
                0,
            )),
            vec!["sweep".into()],
        );
        let order = runner.schedule().unwrap();
        let sweep_pos = order.iter().position(|n| n == "sweep").unwrap();
        let xref_pos = order.iter().position(|n| n == "xref").unwrap();
        assert!(sweep_pos < xref_pos);
    }

    #[test]
    fn schedule_detects_cycle() {
        let mut runner = DependencyRunner::new();
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "a",
                AnalysisKind::LinearSweep,
                0,
                0,
            )),
            vec!["b".into()],
        );
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "b",
                AnalysisKind::LinearSweep,
                0,
                0,
            )),
            vec!["a".into()],
        );
        assert!(runner.schedule().is_err());
    }

    #[test]
    fn schedule_rejects_unknown_dependency() {
        let mut runner = DependencyRunner::new();
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "a",
                AnalysisKind::LinearSweep,
                0,
                0,
            )),
            vec!["ghost".into()],
        );
        assert!(runner.schedule().is_err());
    }

    #[tokio::test]
    async fn run_executes_all_passes() {
        let view = make_view();
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let mut runner = DependencyRunner::new();
        runner.add(Arc::new(CountingAnalysisPass::new(
            "sweep",
            AnalysisKind::LinearSweep,
            5,
            0,
        )));
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "xref",
                AnalysisKind::XrefRecovery,
                3,
                0,
            )),
            vec!["sweep".into()],
        );
        let report = runner.run(&view, &cfg).await.unwrap();
        assert_eq!(report.completed_count(), 2);
        assert!(report.all_completed());
        assert_eq!(report.total_functions(), 8);
    }

    #[tokio::test]
    async fn run_skips_dependents_of_failed_pass() {
        let view = make_view();
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let mut runner = DependencyRunner::new();
        runner.add(Arc::new(FailingPass {
            name: "base".into(),
        }));
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "dependent",
                AnalysisKind::XrefRecovery,
                1,
                0,
            )),
            vec!["base".into()],
        );
        let report = runner.run(&view, &cfg).await.unwrap();
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.skipped_count(), 1);
        assert!(matches!(
            report.outcome("dependent"),
            Some(PassOutcome::Skipped { blocked_by }) if blocked_by == "base"
        ));
    }

    #[tokio::test]
    async fn run_transitive_skip() {
        let view = make_view();
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let mut runner = DependencyRunner::new();
        runner.add(Arc::new(FailingPass { name: "a".into() }));
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new("b", AnalysisKind::DataFlow, 0, 0)),
            vec!["a".into()],
        );
        runner.add_with_deps(
            Arc::new(CountingAnalysisPass::new(
                "c",
                AnalysisKind::TypeRecovery,
                0,
                0,
            )),
            vec!["b".into()],
        );
        let report = runner.run(&view, &cfg).await.unwrap();
        // a fails, b skipped (dep a), c skipped (dep b).
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.skipped_count(), 2);
    }

    #[test]
    fn empty_runner() {
        let runner = DependencyRunner::new();
        assert!(runner.is_empty());
        assert_eq!(runner.schedule().unwrap().len(), 0);
    }
}
