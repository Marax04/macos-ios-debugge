//! MCP wrappers for the rustre-threatintel_ioc crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{ti_parse_ioc_type_v2};

pub struct ThreatintelIocTypeDisplayW3Tool;
impl ThreatintelIocTypeDisplayW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_ioc_type_display_w3".to_string(),
            description: "Display an IocType via rustre_threatintel::IocType.".to_string(),
            input_schema: json!({"type":"object","properties":{"ioc_type":{"type":"string"}},"required":["ioc_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocTypeDisplayW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("ioc_type").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'ioc_type'".into()))?;
        let t = ti_parse_ioc_type_v2(s)?;
        Ok(ToolResult::text(json!({"input": s, "display": t.to_string(),
            "source": "rustre_threatintel::IocType::Display"}).to_string()))
    }
}

pub struct ThreatintelIocIsConfidentW3Tool;
impl ThreatintelIocIsConfidentW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_ioc_is_confident_w3".to_string(),
            description: "Build a ThreatIoc and check confidence >= 0.8 via rustre_threatintel::ThreatIoc.".to_string(),
            input_schema: json!({"type":"object","properties":{"confidence":{"type":"number"}},"required":["confidence"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocIsConfidentW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let c32 = crate::confidence_arg(&args, "confidence")?;
        let ioc = rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Md5, "x", "n", c32, "s");
        Ok(ToolResult::text(json!({"confidence": ioc.confidence,
            "is_confident": ioc.confidence >= 0.8,
            "source": "rustre_threatintel::ThreatIoc"}).to_string()))
    }
}

pub struct ThreatintelIocTypeDisplayTool;
impl ThreatintelIocTypeDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_ioc_type_display".to_string(),
            description:
                "Return the human-readable label of a rustre_threatintel::IocType variant."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "variant": { "type": "string" } },
                "required": ["variant"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocTypeDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let variant = args.get("variant").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'variant'".to_string()))?;
        let ty = match variant.to_ascii_lowercase().as_str() {
            "md5" => rustre_threatintel::IocType::Md5,
            "sha1" => rustre_threatintel::IocType::Sha1,
            "sha256" => rustre_threatintel::IocType::Sha256,
            "sha512" => rustre_threatintel::IocType::Sha512,
            "ip" => rustre_threatintel::IocType::Ip,
            "domain" => rustre_threatintel::IocType::Domain,
            "url" => rustre_threatintel::IocType::Url,
            "email" => rustre_threatintel::IocType::Email,
            "registry" => rustre_threatintel::IocType::Registry,
            "filename" => rustre_threatintel::IocType::Filename,
            "mutex" => rustre_threatintel::IocType::Mutex,
            "yara" => rustre_threatintel::IocType::Yara,
            other => return Err(McpError::InvalidParams(format!("unknown variant '{other}'"))),
        };
        Ok(ToolResult::text(json!({
            "variant": variant,
            "display": ty.to_string(),
            "source": "rustre_threatintel::IocType::fmt",
        }).to_string()))
    }
}

pub struct ThreatintelIocIdValueTool;
impl ThreatintelIocIdValueTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_ioc_id_value".to_string(),
            description: "Insert one IOC into a fresh ThreatIndicatorDatabase and return the raw u64 of the assigned IocId.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "value": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocIdValueTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let value = args.get("value").and_then(Value::as_str).unwrap_or("deadbeef");
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Sha256, value, "wire", 0.5, "wire",
        ));
        Ok(ToolResult::text(json!({
            "id": id.0,
            "source": "rustre_threatintel::ThreatIndicatorDatabase::add_ioc",
        }).to_string()))
    }
}

pub struct ThreatintelIocTypeAllDisplayTool;
impl ThreatintelIocTypeAllDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_ioc_type_all_display".to_string(),
            description: "List Display for every IocType variant.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocTypeAllDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_threatintel::IocType as T;
        let all = [T::Md5, T::Sha1, T::Sha256, T::Sha512, T::Ip, T::Domain,
                   T::Url, T::Email, T::Registry, T::Filename, T::Mutex, T::Yara];
        let list: Vec<String> = all.iter().map(|t| t.to_string()).collect();
        Ok(ToolResult::text(json!({
            "variants": list,
            "count": list.len(),
            "source": "rustre_threatintel::IocType::fmt",
        }).to_string()))
    }
}

pub struct ThreatintelIocTypeFromKeyTool;
impl ThreatintelIocTypeFromKeyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ioc_type_from_key".to_string(), description: "Parse an IoCType from its storage key via IoCType::from_key.".to_string(), input_schema: json!({"type":"object","required":["key"],"properties":{"key":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelIocTypeFromKeyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let k = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing key".into()))?; let t = rustre_threatintel::IoCType::from_key(k); Ok(ToolResult::text(json!({"key":k,"matched":t.is_some(),"display":t.as_ref().map(std::string::ToString::to_string),"as_str":t.map(|t| t.as_str().to_string()),"source":"rustre_threatintel::IoCType::from_key"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ThreatintelIocTypeDisplayW3Tool::definition(), Box::new(ThreatintelIocTypeDisplayW3Tool)),
        (ThreatintelIocIsConfidentW3Tool::definition(), Box::new(ThreatintelIocIsConfidentW3Tool)),
        (ThreatintelIocTypeDisplayTool::definition(), Box::new(ThreatintelIocTypeDisplayTool)),
        (ThreatintelIocIdValueTool::definition(), Box::new(ThreatintelIocIdValueTool)),
        (ThreatintelIocTypeAllDisplayTool::definition(), Box::new(ThreatintelIocTypeAllDisplayTool)),
        (ThreatintelIocTypeFromKeyTool::definition(), Box::new(ThreatintelIocTypeFromKeyTool)),
    ]
}
