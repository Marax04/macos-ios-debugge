//! MCP wrappers for the rustre-demangle crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct DemangleIsConstructorTool;

pub struct DemangleIsDestructorTool;

pub struct DemangleIsVtableTool;

pub struct DemangleIsTypeinfoTool;

pub struct DemangleStandardSubstitutionTool;

pub struct DemangleAutoTool;

pub struct DemangleNormalizeTypeTool;

pub struct DemangleBatchTool;

pub struct DemangleMsvcRttiTool;

pub struct DemangleBatchParallelTool;

pub struct DemangleResultDisplayTool;

pub struct DemangleDispatchTool;

pub struct DemangleClassifyTool;

pub struct DemangleItaniumNativeTool;

pub struct DemangleAutoWireTool;

pub struct DemangleAutoDemanglerWireTool;

pub struct DemangleItaniumDetectWireTool;

pub struct DemangleMsvcDetectWireTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DemangleIsConstructorTool::definition(), Box::new(DemangleIsConstructorTool)),
        (DemangleIsDestructorTool::definition(), Box::new(DemangleIsDestructorTool)),
        (DemangleIsVtableTool::definition(), Box::new(DemangleIsVtableTool)),
        (DemangleIsTypeinfoTool::definition(), Box::new(DemangleIsTypeinfoTool)),
        (DemangleStandardSubstitutionTool::definition(), Box::new(DemangleStandardSubstitutionTool)),
        (DemangleAutoTool::definition(), Box::new(DemangleAutoTool)),
        (DemangleNormalizeTypeTool::definition(), Box::new(DemangleNormalizeTypeTool)),
        (DemangleBatchTool::definition(), Box::new(DemangleBatchTool)),
        (DemangleMsvcRttiTool::definition(), Box::new(DemangleMsvcRttiTool)),
        (DemangleBatchParallelTool::definition(), Box::new(DemangleBatchParallelTool)),
        (DemangleResultDisplayTool::definition(), Box::new(DemangleResultDisplayTool)),
        (DemangleDispatchTool::definition(), Box::new(DemangleDispatchTool)),
        (DemangleClassifyTool::definition(), Box::new(DemangleClassifyTool)),
        (DemangleItaniumNativeTool::definition(), Box::new(DemangleItaniumNativeTool)),
        (DemangleAutoWireTool::definition(), Box::new(DemangleAutoWireTool)),
        (DemangleAutoDemanglerWireTool::definition(), Box::new(DemangleAutoDemanglerWireTool)),
        (DemangleItaniumDetectWireTool::definition(), Box::new(DemangleItaniumDetectWireTool)),
        (DemangleMsvcDetectWireTool::definition(), Box::new(DemangleMsvcDetectWireTool)),
    ]
}
