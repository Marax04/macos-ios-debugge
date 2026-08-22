//! MCP wrappers for the rustre-crypto crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct CryptoIdFunctionPatternScanTool;
impl CryptoIdFunctionPatternScanTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "crypto_id_function_pattern_scan".to_string(),
            description: "Scan a raw byte slice (function body, hex) for crypto algorithmic patterns (XOR/rotate density, XCHG for RC4 KSA, MUL for modexp).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "hex": { "type": "string" } },
                "required": ["hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CryptoIdFunctionPatternScanTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        let hits = rustre_crypto_id::FunctionScanner::analyze(&bytes);
        let out: Vec<Value> = hits.iter().map(|h| json!({
            "algorithm": h.algorithm.to_string(),
            "description": h.description,
            "confidence": h.confidence,
        })).collect();
        Ok(ToolResult::text(json!({ "hits": out }).to_string()))
    }
}

pub struct CryptoIdSignatureDbListTool;
impl CryptoIdSignatureDbListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "crypto_id_signature_db_list".to_string(),
            description: "List the built-in crypto constant signatures known to rustre-crypto-id (name, algorithm, size).".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CryptoIdSignatureDbListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let db = rustre_crypto_id::SignatureDatabase::new();
        let out: Vec<Value> = db.constants().iter().map(|c| json!({
            "name": c.name,
            "algorithm": c.algorithm.to_string(),
            "size": c.size,
        })).collect();
        Ok(ToolResult::text(json!({ "count": out.len(), "constants": out }).to_string()))
    }
}

pub struct CryptoIdActivePlanTool;
impl CryptoIdActivePlanTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "crypto_id_active_plan".to_string(),
            description: "Run CryptoScanner::identify_active on a hex byte blob and return deterministic ranked assessments + active probes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": { "type": "string" },
                    "min_confidence": { "type": "number" },
                    "max_probes_per_algorithm": { "type": "integer" }
                },
                "required": ["hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for CryptoIdActivePlanTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        let mut cfg = rustre_crypto_id::IdentificationConfig::default();
        if let Some(v) = args.get("min_confidence").and_then(Value::as_f64) {
            cfg.min_confidence = v;
        }
        if let Some(v) = args.get("max_probes_per_algorithm").and_then(Value::as_u64) {
            cfg.max_probes_per_algorithm = v as usize;
        }
        let scanner = rustre_crypto_id::CryptoScanner::new();
        let plan = scanner
            .identify_active(&bytes, cfg)
            .map_err(|e| McpError::InternalError(format!("identify_active: {e}")))?;
        let assessments: Vec<Value> = plan.assessments.iter().map(|a| json!({
            "algorithm": a.algorithm.to_string(),
            "confidence": a.confidence,
            "level": format!("{:?}", a.level),
            "evidence_count": a.evidence_count,
        })).collect();
        let probes: Vec<Value> = plan.probes.iter().map(|p| json!({
            "id": p.id,
            "kind": format!("{:?}", p.kind),
            "payload_len": p.payload.len(),
            "expected_observation": p.expected_observation,
        })).collect();
        Ok(ToolResult::text(json!({
            "assessments": assessments,
            "probes": probes
        }).to_string()))
    }
}

pub struct CryptoIdScanBinaryConstantsTool;

pub struct CryptoIdScanAndSummarizeTool;

pub struct CryptoIdScanDesSboxTool;

pub struct CryptoIdScanAesSboxTool;

pub struct CryptoIdScanSha256ConstantsTool;

pub struct CryptoIdScanCrc32TableTool;

pub struct CryptoIdScanChachaMagicTool;

pub struct CryptoIdScanTeaDeltaTool;

pub struct CryptoIdScanBlowfishPTool;

pub struct CryptoIdShannonEntropyTool;

pub struct CryptoIdIdentifyInBinaryTool;

pub struct CryptoIdAesRconTool;

pub struct CryptoIdCrc32PolyTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (CryptoIdFunctionPatternScanTool::definition(), Box::new(CryptoIdFunctionPatternScanTool)),
        (CryptoIdSignatureDbListTool::definition(), Box::new(CryptoIdSignatureDbListTool)),
        (CryptoIdActivePlanTool::definition(), Box::new(CryptoIdActivePlanTool)),
        (CryptoIdScanBinaryConstantsTool::definition(), Box::new(CryptoIdScanBinaryConstantsTool)),
        (CryptoIdScanAndSummarizeTool::definition(), Box::new(CryptoIdScanAndSummarizeTool)),
        (CryptoIdScanDesSboxTool::definition(), Box::new(CryptoIdScanDesSboxTool)),
        (CryptoIdScanAesSboxTool::definition(), Box::new(CryptoIdScanAesSboxTool)),
        (CryptoIdScanSha256ConstantsTool::definition(), Box::new(CryptoIdScanSha256ConstantsTool)),
        (CryptoIdScanCrc32TableTool::definition(), Box::new(CryptoIdScanCrc32TableTool)),
        (CryptoIdScanChachaMagicTool::definition(), Box::new(CryptoIdScanChachaMagicTool)),
        (CryptoIdScanTeaDeltaTool::definition(), Box::new(CryptoIdScanTeaDeltaTool)),
        (CryptoIdScanBlowfishPTool::definition(), Box::new(CryptoIdScanBlowfishPTool)),
        (CryptoIdShannonEntropyTool::definition(), Box::new(CryptoIdShannonEntropyTool)),
        (CryptoIdIdentifyInBinaryTool::definition(), Box::new(CryptoIdIdentifyInBinaryTool)),
        (CryptoIdAesRconTool::definition(), Box::new(CryptoIdAesRconTool)),
        (CryptoIdCrc32PolyTool::definition(), Box::new(CryptoIdCrc32PolyTool)),
    ]
}
