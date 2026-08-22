//! MCP wrappers for the rustre-fuzz_libfuzzer crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct FuzzLibfuzzerBucketBitmapTool;

pub struct FuzzLibfuzzerCountNewBitsBucketedTool;

pub struct FuzzLibfuzzerParseSanitizerOutputTool;

pub struct FuzzLibfuzzerStructuredSerializeTool;
impl FuzzLibfuzzerStructuredSerializeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_structured_serialize".to_string(),
            description: "Serialize named byte fields into a StructuredInput blob (u16-LE length prefixed).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fields": { "type": "array", "items": {
                        "type": "object",
                        "properties": { "name": {"type":"string"}, "hex": {"type":"string"} },
                        "required": ["name","hex"]
                    } }
                },
                "required": ["fields"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerStructuredSerializeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("fields").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'fields'".into()))?;
        let mut si = rustre_fuzz_libfuzzer::StructuredInput::new();
        for f in arr {
            let name = f.get("name").and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams("field.name required".into()))?;
            let hex = f.get("hex").and_then(Value::as_str).unwrap_or("");
            let bytes = if hex.is_empty() { Vec::new() } else {
                crate::hex_decode(hex)?
            };
            si.insert(name.to_string(), bytes);
        }
        let out = si.serialize().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "hex": hex_encode(&out),
            "len": out.len(),
            "field_count": si.field_count(),
            "source": "rustre_fuzz_libfuzzer::StructuredInput::serialize"
        }).to_string()))
    }
}

pub struct FuzzLibfuzzerStructuredDeserializeTool;
impl FuzzLibfuzzerStructuredDeserializeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_structured_deserialize".to_string(),
            description: "Deserialize StructuredInput blob (u16-LE prefixed fields) and return field count.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "hex": {"type":"string"}, "bytes": {"type":"array"} }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerStructuredDeserializeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw = args_to_bytes(&args)?;
        match rustre_fuzz_libfuzzer::StructuredInput::deserialize(&raw) {
            Ok(si) => Ok(ToolResult::text(json!({
                "ok": true,
                "field_count": si.field_count(),
                "is_empty": si.is_empty(),
                "source": "rustre_fuzz_libfuzzer::StructuredInput::deserialize"
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({
                "ok": false,
                "error": e.to_string(),
                "source": "rustre_fuzz_libfuzzer::StructuredInput::deserialize"
            }).to_string())),
        }
    }
}

pub struct FuzzLibfuzzerInputSpliceTool;
impl FuzzLibfuzzerInputSpliceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_input_splice".to_string(),
            description: "Splice two byte buffers at seeded random cut points (InputSplicer).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "a_hex": {"type":"string"}, "b_hex": {"type":"string"}, "seed": {"type":"integer"}
                },
                "required": ["a_hex","b_hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerInputSpliceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a_hex = args.get("a_hex").and_then(Value::as_str).unwrap_or("");
        let b_hex = args.get("b_hex").and_then(Value::as_str).unwrap_or("");
        let a = if a_hex.is_empty() { Vec::new() } else { crate::hex_decode(a_hex)? };
        let b = if b_hex.is_empty() { Vec::new() } else { crate::hex_decode(b_hex)? };
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(0xDEAD_BEEF);
        let mut rng = rustre_fuzz_afl::XorShiftRng::new(seed);
        let splicer = rustre_fuzz_libfuzzer::InputSplicer::new();
        let out = splicer.splice(&a, &b, &mut rng);
        Ok(ToolResult::text(json!({
            "hex": hex_encode(&out),
            "len": out.len(),
            "source": "rustre_fuzz_libfuzzer::InputSplicer::splice"
        }).to_string()))
    }
}

pub struct FuzzLibfuzzerSimpleRngTool;
impl FuzzLibfuzzerSimpleRngTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_simple_rng".to_string(),
            description: "Generate N xorshift64 values from a seed via SimpleRng.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "seed": {"type":"integer"}, "count": {"type":"integer"} },
                "required": ["seed","count"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerSimpleRngTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(1);
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(4).min(1024) as usize;
        let mut rng = rustre_fuzz_libfuzzer::SimpleRng::new(seed);
        let vals: Vec<u64> = (0..count).map(|_| rng.next_u64()).collect();
        Ok(ToolResult::text(json!({
            "values": vals,
            "count": count,
            "source": "rustre_fuzz_libfuzzer::SimpleRng::next_u64"
        }).to_string()))
    }
}

pub struct FuzzLibfuzzerHavocMutateTool;
impl FuzzLibfuzzerHavocMutateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_havoc_mutate".to_string(),
            description: "Mutate input via DefaultHavocMutator with size cap.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": {"type":"string"}, "seed": {"type":"integer"}, "max_size": {"type":"integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerHavocMutateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw = args_to_bytes(&args)?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(1);
        let max_size = args.get("max_size").and_then(Value::as_u64).unwrap_or(1024) as usize;
        use rustre_fuzz_libfuzzer::CustomMutator;
        let mut m = rustre_fuzz_libfuzzer::DefaultHavocMutator::new();
        let out = m.mutate(&raw, seed, max_size)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "hex": hex_encode(&out),
            "len": out.len(),
            "mutator": m.name(),
            "source": "rustre_fuzz_libfuzzer::DefaultHavocMutator::mutate"
        }).to_string()))
    }
}

pub struct FuzzLibfuzzerCrashHandlerInjectTool;
impl FuzzLibfuzzerCrashHandlerInjectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_crash_handler_inject".to_string(),
            description: "Simulate crash signals against CrashSignalHandler and report state.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "signals": {"type":"array","items":{"type":"integer"}} },
                "required": ["signals"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerCrashHandlerInjectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let signals: Vec<i32> = args.get("signals").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_i64().map(|n| n as i32)).collect())
            .unwrap_or_default();
        let h = rustre_fuzz_libfuzzer::CrashSignalHandler::new();
        for s in &signals { h.inject_crash(*s); }
        Ok(ToolResult::text(json!({
            "total_crashes": h.total_crashes(),
            "last_signal": h.last_signal(),
            "is_crashed": h.is_crashed(),
            "source": "rustre_fuzz_libfuzzer::CrashSignalHandler"
        }).to_string()))
    }
}

pub struct FuzzLibfuzzerPersistentHarnessRunTool;
impl FuzzLibfuzzerPersistentHarnessRunTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_libfuzzer_persistent_harness_run".to_string(),
            description: "Run PersistentModeHarness for N advance() calls and report progress.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "max_iterations": {"type":"integer"}, "advances": {"type":"integer"} },
                "required": ["max_iterations"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzLibfuzzerPersistentHarnessRunTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max_it = args.get("max_iterations").and_then(Value::as_u64).unwrap_or(10);
        let advances = args.get("advances").and_then(Value::as_u64).unwrap_or(max_it).min(1_000_000);
        let mut h = rustre_fuzz_libfuzzer::PersistentModeHarness::new(max_it);
        h.start();
        let mut kept_going = 0u64;
        for _ in 0..advances { if h.advance() { kept_going += 1; } else { break; } }
        let progress = h.progress();
        let is_active = h.is_active();
        h.stop();
        Ok(ToolResult::text(json!({
            "iterations": h.iterations,
            "kept_going_count": kept_going,
            "progress": progress,
            "was_active": is_active,
            "source": "rustre_fuzz_libfuzzer::PersistentModeHarness"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzLibfuzzerBucketBitmapTool::definition(), Box::new(FuzzLibfuzzerBucketBitmapTool)),
        (FuzzLibfuzzerCountNewBitsBucketedTool::definition(), Box::new(FuzzLibfuzzerCountNewBitsBucketedTool)),
        (FuzzLibfuzzerParseSanitizerOutputTool::definition(), Box::new(FuzzLibfuzzerParseSanitizerOutputTool)),
        (FuzzLibfuzzerStructuredSerializeTool::definition(), Box::new(FuzzLibfuzzerStructuredSerializeTool)),
        (FuzzLibfuzzerStructuredDeserializeTool::definition(), Box::new(FuzzLibfuzzerStructuredDeserializeTool)),
        (FuzzLibfuzzerInputSpliceTool::definition(), Box::new(FuzzLibfuzzerInputSpliceTool)),
        (FuzzLibfuzzerSimpleRngTool::definition(), Box::new(FuzzLibfuzzerSimpleRngTool)),
        (FuzzLibfuzzerHavocMutateTool::definition(), Box::new(FuzzLibfuzzerHavocMutateTool)),
        (FuzzLibfuzzerCrashHandlerInjectTool::definition(), Box::new(FuzzLibfuzzerCrashHandlerInjectTool)),
        (FuzzLibfuzzerPersistentHarnessRunTool::definition(), Box::new(FuzzLibfuzzerPersistentHarnessRunTool)),
    ]
}
