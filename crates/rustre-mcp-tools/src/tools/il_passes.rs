//! MCP wrappers for the rustre-il_passes crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct IlPassesCountInstrsTool;

pub struct IlPassesCountConstantsTool;

pub struct IlPassesCollectCallSitesTool;

pub struct IlPassesDetectLoopsTool;

pub struct IlPassesInliningScoreTool;

pub struct IlPassesRunGvnPassTool;

pub struct IlPassesIntegerRangeAnalysisTool;

pub struct IlPassesLoopBoundAnalysisTool;

pub struct IlPassesPassStatsNewTool;

pub struct IlPassesPassContextNewTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IlPassesCountInstrsTool::definition(), Box::new(IlPassesCountInstrsTool)),
        (IlPassesCountConstantsTool::definition(), Box::new(IlPassesCountConstantsTool)),
        (IlPassesCollectCallSitesTool::definition(), Box::new(IlPassesCollectCallSitesTool)),
        (IlPassesDetectLoopsTool::definition(), Box::new(IlPassesDetectLoopsTool)),
        (IlPassesInliningScoreTool::definition(), Box::new(IlPassesInliningScoreTool)),
        (IlPassesRunGvnPassTool::definition(), Box::new(IlPassesRunGvnPassTool)),
        (IlPassesIntegerRangeAnalysisTool::definition(), Box::new(IlPassesIntegerRangeAnalysisTool)),
        (IlPassesLoopBoundAnalysisTool::definition(), Box::new(IlPassesLoopBoundAnalysisTool)),
        (IlPassesPassStatsNewTool::definition(), Box::new(IlPassesPassStatsNewTool)),
        (IlPassesPassContextNewTool::definition(), Box::new(IlPassesPassContextNewTool)),
    ]
}
