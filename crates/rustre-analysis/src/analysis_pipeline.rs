/// Analysis pipeline — re-exported from `rustre-core`.
///
/// The canonical implementation lives in `rustre_core::analysis_pipeline`.
/// This module re-exports all public items so that crates which already
/// import `rustre_analysis::analysis_pipeline::*` continue to compile.
///
/// Note: `AnalysisPipeline` is re-exported as `CoreAnalysisPipeline` to
/// avoid shadowing the async-based `AnalysisPipeline` defined in the crate
/// root of `rustre-analysis`.
pub use rustre_core::{
    AnalysisPassImpl,
    AnalysisPipeline as CoreAnalysisPipeline,
    AnalysisProgress,
    AutoAnalysis,
    BuiltinPassKind,
    PassFinding,
    PassInfo,
    PassScheduler,
    PassStatus as CorePassStatus,
    PipelinePassResult,
};
