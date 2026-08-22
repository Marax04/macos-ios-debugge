//! MCP wrappers for the rustre-forensics crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct ForensicsComputeMd5Tool;

pub struct ForensicsComputeSha1Tool;

pub struct ForensicsComputeSha256Tool;

pub struct ForensicsComputeSha512Tool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ForensicsComputeMd5Tool::definition(), Box::new(ForensicsComputeMd5Tool)),
        (ForensicsComputeSha1Tool::definition(), Box::new(ForensicsComputeSha1Tool)),
        (ForensicsComputeSha256Tool::definition(), Box::new(ForensicsComputeSha256Tool)),
        (ForensicsComputeSha512Tool::definition(), Box::new(ForensicsComputeSha512Tool)),
    ]
}
