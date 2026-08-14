//! MCP wrappers for the rustre-net_dns crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct NetDnsTypeNameV2Tool;
impl NetDnsTypeNameV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_dns_type_name_v2".to_string(), description: "Return the name for a DNS record type.".to_string(), input_schema: json!({"type":"object","properties":{"rtype":{"type":"integer"}},"required":["rtype"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetDnsTypeNameV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("rtype").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rtype'".into()))? as u16; Ok(ToolResult::text(json!({"name":rustre_net::dns_type_name(t),"source":"rustre_net::dns_type_name"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetDnsTypeNameV2Tool::definition(), Box::new(NetDnsTypeNameV2Tool)),
    ]
}
