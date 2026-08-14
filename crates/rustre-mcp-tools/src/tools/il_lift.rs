//! MCP wrappers for the rustre-il_lift crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes_named};
use crate::wire_tools::{_il_n5_mk_instr, _il_o1_mk_instr, _il_o1_mk_lifted};

pub struct IlLiftSupportedArchesTool;

pub struct IlLiftArchCountTool;

pub struct IlLiftSupportsTool;

pub struct IlLiftIsEmptyTool;

pub struct IlLiftArchDescriptionTool;

pub struct IlLiftRegistryNewLenTool;

pub struct IlLiftCacheDefaultCapacityLenTool;

pub struct IlLiftRegisterAllCountTool;

pub struct IlLiftRegisterAllLiftersTool;

pub struct IlLiftDiffAddressMapsTool;

pub struct IlLiftLevelAtLeastTool;
impl IlLiftLevelAtLeastTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_level_at_least".to_string(),
            description: "Return whether LiftLevel `a` is at least as high as `b` (Raw<Llil<MlilSsa<Hlil).".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["a", "b"],
                "properties": {
                    "a": { "type": "string", "enum": ["Raw","Llil","MlilSsa","Hlil"] },
                    "b": { "type": "string", "enum": ["Raw","Llil","MlilSsa","Hlil"] }
                }
            }),
            parameters: Value::Null,
        }
    }
}
fn parse_lift_level(s: &str) -> Result<rustre_il_lift::LiftLevel, McpError> {
    match s {
        "Raw" => Ok(rustre_il_lift::LiftLevel::Raw),
        "Llil" => Ok(rustre_il_lift::LiftLevel::Llil),
        "MlilSsa" => Ok(rustre_il_lift::LiftLevel::MlilSsa),
        "Hlil" => Ok(rustre_il_lift::LiftLevel::Hlil),
        _ => Err(McpError::InvalidParams(format!("unknown LiftLevel: {s}"))),
    }
}
#[async_trait]
impl ToolHandler for IlLiftLevelAtLeastTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let la = parse_lift_level(a)?;
        let lb = parse_lift_level(b)?;
        Ok(ToolResult::text(json!({"a": a, "b": b, "at_least": la.at_least(lb)}).to_string()))
    }
}

pub struct IlLiftLevelAllTool;
impl IlLiftLevelAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_level_all".to_string(),
            description: "List all LiftLevel variants in ascending order.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLevelAllTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let levels: Vec<String> = rustre_il_lift::LiftLevel::all().iter().map(|l| format!("{l:?}")).collect();
        Ok(ToolResult::text(json!({"levels": levels}).to_string()))
    }
}

pub struct IlLiftX86LiftBytesTool;
impl IlLiftX86LiftBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_x86_lift_bytes".to_string(),
            description: "Decode and lift a single x86 instruction from hex bytes to LLIL ops.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["bytes_hex"],
                "properties": {
                    "bytes_hex": { "type": "string", "description": "hex-encoded instruction bytes" },
                    "bits": { "type": "integer", "enum": [16, 32, 64], "default": 64 },
                    "ip": { "type": "integer", "default": 0 }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftX86LiftBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = crate::args_to_bytes_named(&args, "bytes_hex")?;
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(64) as u8;
        let ip = args.get("ip").and_then(Value::as_u64).unwrap_or(0);
        let lifter = rustre_il_lift::X86Lifter::new(bits);
        match lifter.lift_instruction(&bytes, ip) {
            Ok(ops) => Ok(ToolResult::text(json!({
                "ok": true,
                "op_count": ops.len(),
                "ops": ops,
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({
                "ok": false,
                "error": format!("{e}"),
            }).to_string())),
        }
    }
}

pub struct IlLiftX86CacheStateTool;
impl IlLiftX86CacheStateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_x86_cache_state".to_string(),
            description: "Report initial state (len, is_empty, hits, misses, hit_rate) of a fresh X86LiftCache.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftX86CacheStateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_il_lift::X86LiftCache::new();
        Ok(ToolResult::text(json!({
            "len": c.len(),
            "is_empty": c.is_empty(),
            "hits": c.hits(),
            "misses": c.misses(),
            "hit_rate": c.hit_rate(),
        }).to_string()))
    }
}

pub struct IlLiftAddressMapNewStateTool;
impl IlLiftAddressMapNewStateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_address_map_new_state".to_string(),
            description: "Return len/is_empty of a newly-constructed AddressMap (both should be 0/true).".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftAddressMapNewStateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let m = rustre_il_lift::AddressMap::new();
        Ok(ToolResult::text(json!({
            "len": m.len(),
            "is_empty": m.is_empty(),
        }).to_string()))
    }
}

pub struct IlLiftDiffEmptyMapsTool;
impl IlLiftDiffEmptyMapsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_diff_empty_maps".to_string(),
            description: "Diff two empty AddressMaps; returns diff_count (must be 0).".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftDiffEmptyMapsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let l = rustre_il_lift::AddressMap::new();
        let r = rustre_il_lift::AddressMap::new();
        let d = rustre_il_lift::diff_address_maps(&l, &r);
        Ok(ToolResult::text(json!({
            "diff_count": d.diff_count(),
        }).to_string()))
    }
}

pub struct IlLiftPipelineDefaultStagesTool;
impl IlLiftPipelineDefaultStagesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_pipeline_default_stages".to_string(),
            description: "Return the number and names of stages in a freshly-constructed LiftPipeline.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftPipelineDefaultStagesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_il_lift::LiftPipeline::new();
        let names: Vec<String> = p.stage_names().into_iter().map(str::to_string).collect();
        Ok(ToolResult::text(json!({
            "count": names.len(),
            "names": names,
        }).to_string()))
    }
}

pub struct IlLiftX86RegIdTool;
impl IlLiftX86RegIdTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_x86_reg_id".to_string(),
            description: "Return the canonical LLIL register id for an iced-x86 register (e.g. RAX, EAX, XMM0).".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["reg"],
                "properties": { "reg": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftX86RegIdTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reg_name = args.get("reg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?;
        // Iterate all known iced_x86 registers to find matching name (case-insensitive).
        use iced_x86::Register;
        let up = reg_name.to_ascii_uppercase();
        let mut found: Option<Register> = None;
        for r in Register::values() {
            if format!("{r:?}").eq_ignore_ascii_case(&up) {
                found = Some(r);
                break;
            }
        }
        match found {
            Some(r) => {
                let id = rustre_il_lift::X86Lifter::reg_id(r);
                Ok(ToolResult::text(json!({
                    "reg": reg_name,
                    "canonical": format!("{r:?}"),
                    "id": id,
                    "known": id != u32::MAX,
                }).to_string()))
            }
            None => Ok(ToolResult::text(json!({
                "reg": reg_name,
                "known": false,
                "error": "unknown register name",
            }).to_string())),
        }
    }
}

pub struct IlLiftLiftCacheInitStateTool;
impl IlLiftLiftCacheInitStateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lift_cache_init_state".to_string(),
            description: "Construct a LiftCache with a given capacity and report len/is_empty/hits/misses/hit_rate.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["capacity"],
                "properties":{"capacity":{"type":"integer","minimum":0}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftCacheInitStateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize;
        let c = rustre_il_lift::LiftCache::new(cap);
        Ok(ToolResult::text(json!({
            "len": c.len(),
            "is_empty": c.is_empty(),
            "hits": c.hits(),
            "misses": c.misses(),
            "hit_rate": c.hit_rate(),
        }).to_string()))
    }
}

pub struct IlLiftLruCacheInitStateTool;
impl IlLiftLruCacheInitStateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lru_cache_init_state".to_string(),
            description: "Construct an LruLiftCache with a given capacity and report len/is_empty/hits/misses/hit_rate.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["capacity"],
                "properties":{"capacity":{"type":"integer","minimum":0}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLruCacheInitStateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize;
        let c = rustre_il_lift::LruLiftCache::new(cap);
        Ok(ToolResult::text(json!({
            "len": c.len(),
            "is_empty": c.is_empty(),
            "hits": c.hits(),
            "misses": c.misses(),
            "hit_rate": c.hit_rate(),
        }).to_string()))
    }
}

pub struct IlLiftLiftStatsRatesTool;
impl IlLiftLiftStatsRatesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lift_stats_rates".to_string(),
            description: "Compute LiftStats::success_rate and cache_hit_rate from raw counters.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "total_instructions":{"type":"integer","minimum":0},
                    "succeeded":{"type":"integer","minimum":0},
                    "failed":{"type":"integer","minimum":0},
                    "cache_hits":{"type":"integer","minimum":0},
                    "cache_misses":{"type":"integer","minimum":0}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftStatsRatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let g = |k: &str| args.get(k).and_then(Value::as_u64).unwrap_or(0);
        let s = rustre_il_lift::LiftStats {
            total_instructions: g("total_instructions"),
            succeeded: g("succeeded"),
            failed: g("failed"),
            cache_hits: g("cache_hits"),
            cache_misses: g("cache_misses"),
            lift_time_us: 0,
            recovery_count: 0,
            partial_lifts: 0,
        };
        Ok(ToolResult::text(json!({
            "success_rate": s.success_rate(),
            "cache_hit_rate": s.cache_hit_rate(),
        }).to_string()))
    }
}

pub struct IlLiftLiftStatsMergeTool;
impl IlLiftLiftStatsMergeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lift_stats_merge".to_string(),
            description: "Merge two LiftStats using LiftStats::merge and return the combined counters.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "a_total":{"type":"integer"},"a_succeeded":{"type":"integer"},"a_failed":{"type":"integer"},
                    "b_total":{"type":"integer"},"b_succeeded":{"type":"integer"},"b_failed":{"type":"integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftStatsMergeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let g = |k: &str| args.get(k).and_then(Value::as_u64).unwrap_or(0);
        let mut a = rustre_il_lift::LiftStats::new();
        a.total_instructions = g("a_total"); a.succeeded = g("a_succeeded"); a.failed = g("a_failed");
        let mut b = rustre_il_lift::LiftStats::new();
        b.total_instructions = g("b_total"); b.succeeded = g("b_succeeded"); b.failed = g("b_failed");
        a.merge(&b);
        Ok(ToolResult::text(json!({
            "total_instructions": a.total_instructions,
            "succeeded": a.succeeded,
            "failed": a.failed,
            "success_rate": a.success_rate(),
        }).to_string()))
    }
}

pub struct IlLiftEmptyLiftDiffTool;
impl IlLiftEmptyLiftDiffTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_empty_lift_diff".to_string(),
            description: "Construct a default LiftDiff and expose its is_empty and diff_count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftEmptyLiftDiffTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_il_lift::LiftDiff::default();
        Ok(ToolResult::text(json!({
            "is_empty": d.is_empty(),
            "diff_count": d.diff_count(),
        }).to_string()))
    }
}

pub struct IlLiftLevelDisplayTool;
impl IlLiftLevelDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_level_display".to_string(),
            description: "Return the Display string for every LiftLevel variant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLevelDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<String> = rustre_il_lift::LiftLevel::all().iter().map(|l| format!("{l}")).collect();
        Ok(ToolResult::text(json!({"variants": names}).to_string()))
    }
}

pub struct IlLiftX86LifterNewTool;
impl IlLiftX86LifterNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_x86_lifter_new".to_string(),
            description: "Construct rustre_il_lift::X86Lifter::new(bits) and echo the stored bits field.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["bits"],
                "properties":{"bits":{"type":"integer","enum":[16,32,64]}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftX86LifterNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as u8;
        let l = rustre_il_lift::X86Lifter::new(bits);
        Ok(ToolResult::text(json!({"bits": l.bits}).to_string()))
    }
}

pub struct IlLiftArm64LifterNewTool;
impl IlLiftArm64LifterNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_arm64_lifter_new".to_string(),
            description: "Construct rustre_il_lift::Arm64Lifter::new() and confirm instantiation.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftArm64LifterNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let _l = rustre_il_lift::Arm64Lifter::new();
        Ok(ToolResult::text(json!({"ok": true, "arch": "aarch64"}).to_string()))
    }
}

pub struct IlLiftMetadataBuildTool;
impl IlLiftMetadataBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_metadata_build".to_string(),
            description: "Build LiftMetadata::new(arch, level).with_hash().with_version() plus notes, return the resulting fields.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["arch"],
                "properties":{
                    "arch":{"type":"string"},
                    "level":{"type":"string","enum":["Raw","Llil","MlilSsa","Hlil"]},
                    "hash":{"type":"string"},
                    "version":{"type":"string"},
                    "notes":{"type":"array","items":{"type":"string"}}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftMetadataBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let level = match args.get("level").and_then(Value::as_str).unwrap_or("Llil") {
            "Raw" => rustre_il_lift::LiftLevel::Raw,
            "MlilSsa" => rustre_il_lift::LiftLevel::MlilSsa,
            "Hlil" => rustre_il_lift::LiftLevel::Hlil,
            _ => rustre_il_lift::LiftLevel::Llil,
        };
        let mut m = rustre_il_lift::LiftMetadata::new(arch, level);
        if let Some(h) = args.get("hash").and_then(Value::as_str) { m = m.with_hash(h); }
        if let Some(v) = args.get("version").and_then(Value::as_str) { m = m.with_version(v); }
        if let Some(ns) = args.get("notes").and_then(Value::as_array) {
            for n in ns { if let Some(s) = n.as_str() { m.add_note(s); } }
        }
        Ok(ToolResult::text(json!({
            "arch": m.source_arch,
            "level": format!("{}", m.target_level),
            "hash": m.binary_hash,
            "version": m.lifter_version,
            "notes_count": m.notes.len(),
        }).to_string()))
    }
}

pub struct IlLiftAddressMapEmptyProbeTool;
impl IlLiftAddressMapEmptyProbeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_address_map_empty_probe".to_string(),
            description: "Build an empty AddressMap and probe get/contains/addresses for a given address.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["address"],
                "properties":{"address":{"type":"integer","minimum":0}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftAddressMapEmptyProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let m = rustre_il_lift::AddressMap::new();
        Ok(ToolResult::text(json!({
            "contains": m.contains(addr),
            "has_value": m.get(addr).is_some(),
            "addresses_len": m.addresses().len(),
        }).to_string()))
    }
}

pub struct IlLiftFilterTerminatorsEmptyTool;
impl IlLiftFilterTerminatorsEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_filter_terminators_empty".to_string(),
            description: "Invoke LiftFilter::terminators on an empty slice and return the count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftFilterTerminatorsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let v: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
        let out = rustre_il_lift::LiftFilter::terminators(&v);
        Ok(ToolResult::text(json!({"count": out.len()}).to_string()))
    }
}

pub struct IlLiftFilterWithSideEffectsEmptyTool;
impl IlLiftFilterWithSideEffectsEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_filter_with_side_effects_empty".to_string(),
            description: "Invoke LiftFilter::with_side_effects on an empty slice and return the count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftFilterWithSideEffectsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let v: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
        let out = rustre_il_lift::LiftFilter::with_side_effects(&v);
        Ok(ToolResult::text(json!({"count": out.len()}).to_string()))
    }
}

pub struct IlLiftFilterAtLevelEmptyTool;
impl IlLiftFilterAtLevelEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_filter_at_level_empty".to_string(),
            description: "Invoke LiftFilter::at_level on an empty slice for the given LiftLevel.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"level":{"type":"string","enum":["Raw","Llil","MlilSsa","Hlil"]}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftFilterAtLevelEmptyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let level = match args.get("level").and_then(Value::as_str).unwrap_or("Llil") {
            "Raw" => rustre_il_lift::LiftLevel::Raw,
            "MlilSsa" => rustre_il_lift::LiftLevel::MlilSsa,
            "Hlil" => rustre_il_lift::LiftLevel::Hlil,
            _ => rustre_il_lift::LiftLevel::Llil,
        };
        let v: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
        let out = rustre_il_lift::LiftFilter::at_level(&v, level);
        Ok(ToolResult::text(json!({"count": out.len()}).to_string()))
    }
}

pub struct IlLiftFilterCountStubsEmptyTool;
impl IlLiftFilterCountStubsEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_filter_count_stubs_empty".to_string(),
            description: "Invoke LiftFilter::count_stubs on an empty slice.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftFilterCountStubsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let v: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
        Ok(ToolResult::text(json!({"count": rustre_il_lift::LiftFilter::count_stubs(&v)}).to_string()))
    }
}

pub struct IlLiftFilterPartitionEffectsEmptyTool;
impl IlLiftFilterPartitionEffectsEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_filter_partition_effects_empty".to_string(),
            description: "Invoke LiftFilter::partition_by_effects on an empty slice; return (pure, effectful) counts.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftFilterPartitionEffectsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let v: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
        let (a, b) = rustre_il_lift::LiftFilter::partition_by_effects(&v);
        Ok(ToolResult::text(json!({"pure": a.len(), "effectful": b.len()}).to_string()))
    }
}

pub struct IlLiftReportSummaryEmptyTool;
impl IlLiftReportSummaryEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_report_summary_empty".to_string(),
            description: "Build a LiftReport from an empty LiftResult and return its summary string.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["arch"],
                "properties":{
                    "arch":{"type":"string"},
                    "level":{"type":"string","enum":["Raw","Llil","MlilSsa","Hlil"]}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftReportSummaryEmptyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let level = match args.get("level").and_then(Value::as_str).unwrap_or("Llil") {
            "Raw" => rustre_il_lift::LiftLevel::Raw,
            "MlilSsa" => rustre_il_lift::LiftLevel::MlilSsa,
            "Hlil" => rustre_il_lift::LiftLevel::Hlil,
            _ => rustre_il_lift::LiftLevel::Llil,
        };
        let md = rustre_il_lift::LiftMetadata::new(arch, level);
        let result = rustre_il_lift::LiftResult::default();
        let report = rustre_il_lift::LiftReport::from_result(&result, md);
        Ok(ToolResult::text(json!({
            "summary": report.summary(),
            "complete": report.complete,
            "failed": report.failed_addresses.len(),
        }).to_string()))
    }
}

pub struct IlLiftRegistryWithDefaultsTool;
impl IlLiftRegistryWithDefaultsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_registry_with_defaults".to_string(),
            description: "Construct LifterRegistry::with_defaults() and return its length and registered arch names.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftRegistryWithDefaultsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_il_lift::LifterRegistry::with_defaults();
        Ok(ToolResult::text(json!({
            "len": reg.len(),
            "is_empty": reg.is_empty(),
            "arches": reg.arch_names(),
        }).to_string()))
    }
}

pub struct IlLiftRegistryDefaultsSupportsTool;
impl IlLiftRegistryDefaultsSupportsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_registry_defaults_supports".to_string(),
            description: "Check LifterRegistry::with_defaults().supports(arch) for a supplied arch name.".to_string(),
            input_schema: json!({
                "type":"object",
                "required":["arch"],
                "properties":{"arch":{"type":"string"}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftRegistryDefaultsSupportsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let reg = rustre_il_lift::LifterRegistry::with_defaults();
        Ok(ToolResult::text(json!({
            "arch": arch,
            "supports": reg.supports(arch),
        }).to_string()))
    }
}

pub struct IlLiftPartialBuilderEmptyTool;
impl IlLiftPartialBuilderEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_partial_builder_empty".to_string(),
            description: "Build a PartialLiftResult, immediately snapshot, and report LiftResult counters.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftPartialBuilderEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let b = rustre_il_lift::PartialLiftResult::new();
        let snap = b.snapshot();
        Ok(ToolResult::text(json!({
            "total": snap.stats.total_instructions,
            "succeeded": snap.stats.succeeded,
            "failed": snap.stats.failed,
            "complete": snap.is_complete(),
        }).to_string()))
    }
}

pub struct IlLiftPipelineEmptyStagesTool;
impl IlLiftPipelineEmptyStagesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_pipeline_empty_stages".to_string(),
            description: "Construct LiftPipeline::new() and confirm it starts with zero stages.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftPipelineEmptyStagesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_il_lift::LiftPipeline::new();
        Ok(ToolResult::text(json!({
            "stage_count": p.stage_names().len(),
            "stage_names": p.stage_names(),
        }).to_string()))
    }
}

pub struct IlLiftDiffCountTool;
impl IlLiftDiffCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_diff_count".to_string(),
            description: "Return LiftDiff::diff_count() and is_empty() for a default (empty) LiftDiff.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftDiffCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_il_lift::LiftDiff::default();
        Ok(ToolResult::text(json!({"diff_count":d.diff_count(),"is_empty":d.is_empty()}).to_string()))
    }
}

pub struct IlLiftMetadataHasHashTool;
impl IlLiftMetadataHasHashTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lift_metadata_has_hash".to_string(),
            description: "Build LiftMetadata::new(arch, Llil), optionally chain with_hash, report has_hash.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"hash":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftMetadataHasHashTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
        let mut m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Llil);
        let before = m.has_hash();
        if let Some(h) = args.get("hash").and_then(Value::as_str) {
            m = m.with_hash(h);
        }
        Ok(ToolResult::text(json!({"has_hash_before":before,"has_hash_after":m.has_hash(),"binary_hash":m.binary_hash,"arch":m.source_arch}).to_string()))
    }
}

pub struct IlLiftMetadataWithTimestampTool;
impl IlLiftMetadataWithTimestampTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_metadata_with_timestamp".to_string(),
            description: "LiftMetadata::new(arch, Hlil).with_timestamp(ts).with_version(v) roundtrip.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"ts":{"type":"integer"},"version":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftMetadataWithTimestampTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("arm64");
        let ts = args.get("ts").and_then(Value::as_u64).unwrap_or(1234);
        let ver = args.get("version").and_then(Value::as_str).unwrap_or("test");
        let m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Hlil).with_timestamp(ts).with_version(ver);
        Ok(ToolResult::text(json!({"timestamp":m.lift_timestamp,"version":m.lifter_version,"arch":m.source_arch}).to_string()))
    }
}

pub struct IlLiftLiftStatsNewTool;
impl IlLiftLiftStatsNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lift_stats_new".to_string(),
            description: "LiftStats::new() default rates via cache_hit_rate/success_rate.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftStatsNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_il_lift::LiftStats::new();
        Ok(ToolResult::text(json!({"total":s.total_instructions,"cache_hit_rate":s.cache_hit_rate(),"success_rate":s.success_rate()}).to_string()))
    }
}

pub struct IlLiftAddressMapRangeTool;
impl IlLiftAddressMapRangeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_address_map_range".to_string(),
            description: "AddressMap::new() then range(start,end) count on an empty map.".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftAddressMapRangeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(0x10000);
        let m = rustre_il_lift::AddressMap::new();
        let r = m.range(start, end);
        Ok(ToolResult::text(json!({"len":m.len(),"is_empty":m.is_empty(),"range_count":r.len()}).to_string()))
    }
}

pub struct IlLiftAddressMapMergeTool;
impl IlLiftAddressMapMergeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_address_map_merge".to_string(),
            description: "AddressMap::merge_from between two empty maps preserves emptiness.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftAddressMapMergeTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut a = rustre_il_lift::AddressMap::new();
        let b = rustre_il_lift::AddressMap::new();
        a.merge_from(&b);
        Ok(ToolResult::text(json!({"len":a.len(),"is_empty":a.is_empty(),"addresses":a.addresses()}).to_string()))
    }
}

pub struct IlLiftLifterRegistryArchNamesTool;
impl IlLiftLifterRegistryArchNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lifter_registry_arch_names".to_string(),
            description: "LifterRegistry::with_defaults().arch_names() listing.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLifterRegistryArchNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_il_lift::LifterRegistry::with_defaults();
        let names: Vec<String> = reg.arch_names().into_iter().map(|s| s.to_string()).collect();
        Ok(ToolResult::text(json!({"len":reg.len(),"names":names}).to_string()))
    }
}

pub struct IlLiftLifterRegistryLenTool;
impl IlLiftLifterRegistryLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_lifter_registry_len".to_string(),
            description: "LifterRegistry::new() reports len=0 and is_empty=true.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLifterRegistryLenTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_il_lift::LifterRegistry::new();
        Ok(ToolResult::text(json!({"len":reg.len(),"is_empty":reg.is_empty()}).to_string()))
    }
}

pub struct IlLiftLiftcacheOpsTool;
impl IlLiftLiftcacheOpsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_liftcache_ops".to_string(),
            description: "LiftCache::new(capacity) initial hits/misses/hit_rate/len/is_empty.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftcacheOpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(128) as usize;
        let c = rustre_il_lift::LiftCache::new(cap);
        Ok(ToolResult::text(json!({"hits":c.hits(),"misses":c.misses(),"hit_rate":c.hit_rate(),"len":c.len(),"is_empty":c.is_empty()}).to_string()))
    }
}

pub struct IlLiftLiftlevelDisplayAllTool;
impl IlLiftLiftlevelDisplayAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "il_lift_liftlevel_display_all".to_string(),
            description: "LiftLevel::all() formatted via Display for each variant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for IlLiftLiftlevelDisplayAllTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<String> = rustre_il_lift::LiftLevel::all().iter().map(|l| format!("{l}")).collect();
        Ok(ToolResult::text(json!({"count":names.len(),"names":names}).to_string()))
    }
}

pub struct IlLiftLiftResultSuccessRateEmptyN5Tool;
impl IlLiftLiftResultSuccessRateEmptyN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_result_success_rate_empty_n5".to_string(), description: "LiftResult::new() → is_complete/total_count/success_rate/failed_addresses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftResultSuccessRateEmptyN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let r = rustre_il_lift::LiftResult::new();
    Ok(ToolResult::text(json!({"is_complete": r.is_complete(), "total": r.total_count(), "rate": r.success_rate(), "failed": r.failed_addresses(), "source":"rustre_il_lift::LiftResult"}).to_string()))
} }

pub struct IlLiftLiftStatsHitRateN5Tool;
impl IlLiftLiftStatsHitRateN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_stats_hit_rate_n5".to_string(), description: "LiftStats cache_hit_rate + success_rate with supplied counters.".to_string(), input_schema: json!({"type":"object","properties":{"hits":{"type":"integer"},"misses":{"type":"integer"},"succeeded":{"type":"integer"},"total":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftStatsHitRateN5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut s = rustre_il_lift::LiftStats::new();
    s.cache_hits = args.get("hits").and_then(Value::as_u64).unwrap_or(3);
    s.cache_misses = args.get("misses").and_then(Value::as_u64).unwrap_or(1);
    s.succeeded = args.get("succeeded").and_then(Value::as_u64).unwrap_or(4);
    s.total_instructions = args.get("total").and_then(Value::as_u64).unwrap_or(5);
    Ok(ToolResult::text(json!({"cache_hit_rate": s.cache_hit_rate(), "success_rate": s.success_rate(), "source":"rustre_il_lift::LiftStats"}).to_string()))
} }

pub struct IlLiftLiftedInstrTerminatorN5Tool;
impl IlLiftLiftedInstrTerminatorN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifted_instr_terminator_n5".to_string(), description: "LiftedInstr with empty effects: is_terminator / has_side_effects / effect_count.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"mnem":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftedInstrTerminatorN5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
    let mnem = args.get("mnem").and_then(Value::as_str).unwrap_or("nop");
    let li = _il_n5_mk_instr(addr, mnem);
    Ok(ToolResult::text(json!({"is_terminator": li.is_terminator(), "has_side_effects": li.has_side_effects(), "effect_count": li.effect_count(), "written": li.written_registers(), "read": li.read_registers(), "source":"rustre_il_lift::LiftedInstr"}).to_string()))
} }

pub struct IlLiftLiftCacheEvictN5Tool;
impl IlLiftLiftCacheEvictN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_cache_evict_n5".to_string(), description: "LiftCache::new(1): insert two entries and observe eviction and hits/misses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftCacheEvictN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let c = rustre_il_lift::LiftCache::new(1);
    c.insert(0x10, _il_n5_mk_instr(0x10, "a"));
    let len_after_first = c.len();
    c.insert(0x20, _il_n5_mk_instr(0x20, "b"));
    let _ = c.get(0x20);
    let _ = c.get(0xFFFF);
    Ok(ToolResult::text(json!({"len_after_first": len_after_first, "len_final": c.len(), "hits": c.hits(), "misses": c.misses(), "hit_rate": c.hit_rate(), "source":"rustre_il_lift::LiftCache"}).to_string()))
} }

pub struct IlLiftAddressMapMergeFromN5Tool;
impl IlLiftAddressMapMergeFromN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_merge_from_n5".to_string(), description: "Build two AddressMaps, merge_from, check total addresses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftAddressMapMergeFromN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut a = rustre_il_lift::AddressMap::new();
    a.insert(0x10, _il_n5_mk_instr(0x10, "a"));
    let mut b = rustre_il_lift::AddressMap::new();
    b.insert(0x20, _il_n5_mk_instr(0x20, "b"));
    b.insert(0x30, _il_n5_mk_instr(0x30, "c"));
    a.merge_from(&b);
    Ok(ToolResult::text(json!({"len": a.addresses().len(), "contains_20": a.contains(0x20), "contains_30": a.contains(0x30), "source":"rustre_il_lift::AddressMap::merge_from"}).to_string()))
} }

pub struct IlLiftAddressMapRangeN5Tool;
impl IlLiftAddressMapRangeN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_range_n5".to_string(), description: "AddressMap::range with three addresses, count within window.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftAddressMapRangeN5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let start = args.get("start").and_then(Value::as_u64).unwrap_or(0x15);
    let end = args.get("end").and_then(Value::as_u64).unwrap_or(0x35);
    let mut m = rustre_il_lift::AddressMap::new();
    m.insert(0x10, _il_n5_mk_instr(0x10, "a"));
    m.insert(0x20, _il_n5_mk_instr(0x20, "b"));
    m.insert(0x30, _il_n5_mk_instr(0x30, "c"));
    let r = m.range(start, end);
    Ok(ToolResult::text(json!({"range_count": r.len(), "total": m.addresses().len(), "source":"rustre_il_lift::AddressMap::range"}).to_string()))
} }

pub struct IlLiftLifterRegistryLiftInstrUnsupportedN5Tool;
impl IlLiftLifterRegistryLiftInstrUnsupportedN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifter_registry_lift_instr_unsupported_n5".to_string(), description: "LifterRegistry::with_defaults + lift_instr on unknown arch → UnsupportedArch.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLifterRegistryLiftInstrUnsupportedN5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arch = args.get("arch").and_then(Value::as_str).unwrap_or("madeup-arch-xyz");
    let reg = rustre_il_lift::LifterRegistry::with_defaults();
    let instr = rustre_core::arch::Instruction::new(rustre_core::Address::new(0x1000), 1_usize, "nop", vec![0x90]);
    let err = reg.lift_instr(arch, &instr).is_err();
    Ok(ToolResult::text(json!({"is_err": err, "supports": reg.supports(arch), "arch_count": reg.len(), "source":"rustre_il_lift::LifterRegistry::lift_instr"}).to_string()))
} }

pub struct IlLiftLiftDiffEmptyN5Tool;
impl IlLiftLiftDiffEmptyN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_diff_empty_n5".to_string(), description: "diff_address_maps between two empty maps: LiftDiff::is_empty + diff_count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftDiffEmptyN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_il_lift::AddressMap::new();
    let b = rustre_il_lift::AddressMap::new();
    let d = rustre_il_lift::diff_address_maps(&a, &b);
    Ok(ToolResult::text(json!({"is_empty": d.is_empty(), "diff_count": d.diff_count(), "identical": d.identical.len(), "source":"rustre_il_lift::diff_address_maps"}).to_string()))
} }

pub struct IlLiftX86LifterRegIdRaxN5Tool;
impl IlLiftX86LifterRegIdRaxN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lifter_reg_id_rax_n5".to_string(), description: "X86Lifter::reg_id for RAX / RCX / XMM0 / RIP.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftX86LifterRegIdRaxN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let rax = rustre_il_lift::X86Lifter::reg_id(iced_x86::Register::RAX);
    let rcx = rustre_il_lift::X86Lifter::reg_id(iced_x86::Register::RCX);
    let xmm0 = rustre_il_lift::X86Lifter::reg_id(iced_x86::Register::XMM0);
    let rip = rustre_il_lift::X86Lifter::reg_id(iced_x86::Register::RIP);
    Ok(ToolResult::text(json!({"rax": rax, "rcx": rcx, "xmm0": xmm0, "rip": rip, "source":"rustre_il_lift::X86Lifter::reg_id"}).to_string()))
} }

pub struct IlLiftLiftStatsMergeN5Tool;
impl IlLiftLiftStatsMergeN5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_stats_merge_n5".to_string(), description: "LiftStats::merge sums totals/succeeded/failed.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftStatsMergeN5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut a = rustre_il_lift::LiftStats::new();
    a.total_instructions = 10; a.succeeded = 7; a.failed = 3;
    let mut b = rustre_il_lift::LiftStats::new();
    b.total_instructions = 5; b.succeeded = 5; b.cache_hits = 2;
    a.merge(&b);
    Ok(ToolResult::text(json!({"total": a.total_instructions, "succeeded": a.succeeded, "failed": a.failed, "cache_hits": a.cache_hits, "source":"rustre_il_lift::LiftStats::merge"}).to_string()))
} }

pub struct IlLiftLifterRegistryEmptyN6Tool;
impl IlLiftLifterRegistryEmptyN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifter_registry_empty_n6".to_string(), description: "LifterRegistry::new: is_empty/len/arch_names before defaults.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLifterRegistryEmptyN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let r = rustre_il_lift::LifterRegistry::new();
    Ok(ToolResult::text(json!({"is_empty": r.is_empty(), "len": r.len(), "arch_names": r.arch_names(), "source":"rustre_il_lift::LifterRegistry::new"}).to_string()))
} }

pub struct IlLiftLiftMetadataBuilderN6Tool;
impl IlLiftLiftMetadataBuilderN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_metadata_builder_n6".to_string(), description: "LiftMetadata::new + with_hash + with_version + add_note.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"hash":{"type":"string"},"version":{"type":"string"},"note":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftMetadataBuilderN6Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
    let hash = args.get("hash").and_then(Value::as_str).unwrap_or("deadbeef");
    let version = args.get("version").and_then(Value::as_str).unwrap_or("9.9.9");
    let note = args.get("note").and_then(Value::as_str).unwrap_or("hi");
    let mut m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Llil)
        .with_hash(hash)
        .with_version(version);
    m.add_note(note);
    Ok(ToolResult::text(json!({"arch": m.source_arch, "hash": m.binary_hash, "version": m.lifter_version, "notes": m.notes, "has_hash": m.has_hash(), "source":"rustre_il_lift::LiftMetadata"}).to_string()))
} }

pub struct IlLiftAddressMapIterN6Tool;
impl IlLiftAddressMapIterN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_iter_n6".to_string(), description: "AddressMap::iter + instructions() length after inserts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftAddressMapIterN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut m = rustre_il_lift::AddressMap::new();
    m.insert(0x10, _il_n5_mk_instr(0x10, "a"));
    m.insert(0x20, _il_n5_mk_instr(0x20, "b"));
    let iter_count = m.iter().count();
    let instr_count = m.instructions().len();
    Ok(ToolResult::text(json!({"iter_count": iter_count, "instr_count": instr_count, "addresses": m.addresses(), "source":"rustre_il_lift::AddressMap::iter"}).to_string()))
} }

pub struct IlLiftLiftCacheDefaultCapacityN6Tool;
impl IlLiftLiftCacheDefaultCapacityN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_cache_default_capacity_n6".to_string(), description: "LiftCache::default_capacity: initial len/is_empty; then clear().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftLiftCacheDefaultCapacityN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let c = rustre_il_lift::LiftCache::default_capacity();
    c.insert(0x1, _il_n5_mk_instr(0x1, "n"));
    let len_before = c.len();
    c.clear();
    Ok(ToolResult::text(json!({"len_before": len_before, "len_after_clear": c.len(), "is_empty": c.is_empty(), "source":"rustre_il_lift::LiftCache::default_capacity"}).to_string()))
} }

pub struct IlLiftPartialLiftResultN6Tool;
impl IlLiftPartialLiftResultN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_partial_lift_result_n6".to_string(), description: "PartialLiftResult::new + push_ok + push_err + snapshot totals.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftPartialLiftResultN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut p = rustre_il_lift::PartialLiftResult::new();
    p.push_ok(_il_n5_mk_instr(0x10, "a"));
    p.push_ok(_il_n5_mk_instr(0x20, "b"));
    p.push_err(0x30);
    let snap = p.snapshot();
    Ok(ToolResult::text(json!({"total": snap.total_count(), "success_rate": snap.success_rate(), "failed": snap.failed_addresses(), "source":"rustre_il_lift::PartialLiftResult"}).to_string()))
} }

pub struct IlLiftArm64LiftMovN6Tool;
impl IlLiftArm64LiftMovN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_mov_n6".to_string(), description: "Arm64Lifter::lift_mov(&[dst,src]) returns Vec<LlilOp>.".to_string(), input_schema: json!({"type":"object","properties":{"dst":{"type":"string"},"src":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftArm64LiftMovN6Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let dst = args.get("dst").and_then(Value::as_str).unwrap_or("x0");
    let src = args.get("src").and_then(Value::as_str).unwrap_or("x1");
    let ops = rustre_il_lift::Arm64Lifter::lift_mov(&[dst, src]);
    Ok(ToolResult::text(json!({"ops_count": ops.len(), "dst": dst, "src": src, "source":"rustre_il_lift::Arm64Lifter::lift_mov"}).to_string()))
} }

pub struct IlLiftArm64LiftAddN6Tool;
impl IlLiftArm64LiftAddN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_add_n6".to_string(), description: "Arm64Lifter::lift_add(&[dst,src1,src2]) returns Vec<LlilOp>.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftArm64LiftAddN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let ops = rustre_il_lift::Arm64Lifter::lift_add(&["x0", "x1", "x2"]);
    let bad = rustre_il_lift::Arm64Lifter::lift_add(&["x0"]);
    Ok(ToolResult::text(json!({"ok_count": ops.len(), "bad_count": bad.len(), "source":"rustre_il_lift::Arm64Lifter::lift_add"}).to_string()))
} }

pub struct IlLiftArm64LiftRetN6Tool;
impl IlLiftArm64LiftRetN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_ret_n6".to_string(), description: "Arm64Lifter::lift_ret returns Vec<LlilOp> (terminator).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftArm64LiftRetN6Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let ops = rustre_il_lift::Arm64Lifter::lift_ret(&[]);
    Ok(ToolResult::text(json!({"ops_count": ops.len(), "source":"rustre_il_lift::Arm64Lifter::lift_ret"}).to_string()))
} }

pub struct IlLiftFiltersWritingRegisterN6Tool;
impl IlLiftFiltersWritingRegisterN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_filters_writing_register_n6".to_string(), description: "filters::writing_register over empty slice: expect empty result.".to_string(), input_schema: json!({"type":"object","properties":{"reg":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftFiltersWritingRegisterN6Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let reg = args.get("reg").and_then(Value::as_str).unwrap_or("rax");
    let empty: Vec<rustre_il_lift::LiftedInstr> = Vec::new();
    let hits = rustre_il_lift::LiftFilter::writing_register(&empty, reg);
    Ok(ToolResult::text(json!({"reg": reg, "hits": hits.len(), "source":"rustre_il_lift::LiftFilter::writing_register"}).to_string()))
} }

pub struct IlLiftReportFromResultN6Tool;
impl IlLiftReportFromResultN6Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_report_from_result_n6".to_string(), description: "LiftReport::from_result on empty LiftResult with LiftMetadata; check summary length.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for IlLiftReportFromResultN6Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
    let meta = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Llil);
    let res = rustre_il_lift::LiftResult::new();
    let rep = rustre_il_lift::LiftReport::from_result(&res, meta);
    let sum = rep.summary();
    Ok(ToolResult::text(json!({"summary_len": sum.len(), "arch": arch, "source":"rustre_il_lift::LiftReport::from_result"}).to_string()))
} }

pub struct IlLiftLevelAtLeastReflexiveN3Tool;
impl IlLiftLevelAtLeastReflexiveN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_level_at_least_reflexive_n3".to_string(), description: "LiftLevel::at_least reflexive.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLevelAtLeastReflexiveN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let all = rustre_il_lift::LiftLevel::all(); let results: Vec<bool> = all.iter().map(|l| l.at_least(*l)).collect(); Ok(ToolResult::text(json!({"count":all.len(),"all_reflexive":results.iter().all(|b| *b),"source":"rustre_il_lift::LiftLevel::at_least"}).to_string())) } }

pub struct IlLiftResultNewEmptyN3Tool;
impl IlLiftResultNewEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_result_new_empty_n3".to_string(), description: "LiftResult::new counts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftResultNewEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LiftResult::new(); Ok(ToolResult::text(json!({"is_complete":r.is_complete(),"total_count":r.total_count(),"lifted":r.lifted.len(),"errors":r.errors.len(),"source":"rustre_il_lift::LiftResult::new"}).to_string())) } }

pub struct IlLiftResultSuccessRateEmptyN3Tool;
impl IlLiftResultSuccessRateEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_result_success_rate_empty_n3".to_string(), description: "LiftResult empty success_rate.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftResultSuccessRateEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LiftResult::new(); Ok(ToolResult::text(json!({"success_rate":r.success_rate(),"source":"rustre_il_lift::LiftResult::success_rate"}).to_string())) } }

pub struct IlLiftResultFailedAddressesEmptyN3Tool;
impl IlLiftResultFailedAddressesEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_result_failed_addresses_empty_n3".to_string(), description: "LiftResult failed_addresses empty.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftResultFailedAddressesEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LiftResult::new(); let addrs = r.failed_addresses(); Ok(ToolResult::text(json!({"failed_count":addrs.len(),"is_empty":addrs.is_empty(),"source":"rustre_il_lift::LiftResult::failed_addresses"}).to_string())) } }

pub struct IlLiftStatsCacheHitRateEmptyN3Tool;
impl IlLiftStatsCacheHitRateEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_stats_cache_hit_rate_empty_n3".to_string(), description: "LiftStats empty cache_hit_rate.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftStatsCacheHitRateEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_il_lift::LiftStats::new(); Ok(ToolResult::text(json!({"cache_hit_rate":s.cache_hit_rate(),"source":"rustre_il_lift::LiftStats::cache_hit_rate"}).to_string())) } }

pub struct IlLiftStatsSuccessRateEmptyN3Tool;
impl IlLiftStatsSuccessRateEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_stats_success_rate_empty_n3".to_string(), description: "LiftStats empty success_rate.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftStatsSuccessRateEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_il_lift::LiftStats::new(); Ok(ToolResult::text(json!({"success_rate":s.success_rate(),"source":"rustre_il_lift::LiftStats::success_rate"}).to_string())) } }

pub struct IlLiftCacheDefaultCapacityOpsN3Tool;
impl IlLiftCacheDefaultCapacityOpsN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_cache_default_capacity_ops_n3".to_string(), description: "LiftCache::default_capacity ops.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftCacheDefaultCapacityOpsN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::LiftCache::default_capacity(); Ok(ToolResult::text(json!({"hits":c.hits(),"misses":c.misses(),"hit_rate":c.hit_rate(),"len":c.len(),"is_empty":c.is_empty(),"source":"rustre_il_lift::LiftCache::default_capacity"}).to_string())) } }

pub struct IlLiftMetadataAddNoteN3Tool;
impl IlLiftMetadataAddNoteN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_metadata_add_note_n3".to_string(), description: "LiftMetadata add_note.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"note":{"type":"string"}},"required":["arch","note"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftMetadataAddNoteN3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing arch".into()))?; let note = args.get("note").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing note".into()))?; let mut m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Llil); m.add_note(note); Ok(ToolResult::text(json!({"notes":m.notes.len(),"arch":m.source_arch,"source":"rustre_il_lift::LiftMetadata::add_note"}).to_string())) } }

pub struct IlLiftMetadataWithHashN3Tool;
impl IlLiftMetadataWithHashN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_metadata_with_hash_n3".to_string(), description: "LiftMetadata with_hash.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"hash":{"type":"string"}},"required":["arch","hash"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftMetadataWithHashN3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing arch".into()))?; let hash = args.get("hash").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing hash".into()))?; let m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Raw).with_hash(hash); Ok(ToolResult::text(json!({"has_hash":m.has_hash(),"binary_hash":m.binary_hash,"source":"rustre_il_lift::LiftMetadata::with_hash"}).to_string())) } }

pub struct IlLiftX86LiftCacheEmptyStateN3Tool;
impl IlLiftX86LiftCacheEmptyStateN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_empty_state_n3".to_string(), description: "X86LiftCache empty state.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheEmptyStateN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::X86LiftCache::new(); Ok(ToolResult::text(json!({"hits":c.hits(),"misses":c.misses(),"len":c.len(),"is_empty":c.is_empty(),"hit_rate":c.hit_rate(),"source":"rustre_il_lift::X86LiftCache::new"}).to_string())) } }

pub struct IlLiftX86CachedAddressesEmptyN3Tool;
impl IlLiftX86CachedAddressesEmptyN3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_cached_addresses_empty_n3".to_string(), description: "X86LiftCache cached_addresses empty.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86CachedAddressesEmptyN3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::X86LiftCache::new(); let addrs = c.cached_addresses(); Ok(ToolResult::text(json!({"count":addrs.len(),"addresses":addrs,"source":"rustre_il_lift::X86LiftCache::cached_addresses"}).to_string())) } }

pub struct IlLiftRegistrySupportsX8664N3Tool;
impl IlLiftRegistrySupportsX8664N3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_registry_supports_x86_64_n3".to_string(), description: "LifterRegistry with_defaults supports.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftRegistrySupportsX8664N3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing arch".into()))?; let r = rustre_il_lift::LifterRegistry::with_defaults(); Ok(ToolResult::text(json!({"arch":arch,"supported":r.supports(arch),"total_arches":r.len(),"source":"rustre_il_lift::LifterRegistry::supports"}).to_string())) } }

pub struct IlLiftLevelAtLeastPairR7Tool;
impl IlLiftLevelAtLeastPairR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_level_at_least_pair_r7".to_string(), description: "LiftLevel::at_least(a,b) for two named levels.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
fn __il_lift_parse_level_r7(s: &str) -> Result<rustre_il_lift::LiftLevel, McpError> { match s { "Raw"|"raw" => Ok(rustre_il_lift::LiftLevel::Raw), "Llil"|"llil" => Ok(rustre_il_lift::LiftLevel::Llil), "MlilSsa"|"mlil_ssa"|"mlil" => Ok(rustre_il_lift::LiftLevel::MlilSsa), "Hlil"|"hlil" => Ok(rustre_il_lift::LiftLevel::Hlil), other => Err(McpError::InvalidParams(format!("unknown level {other}"))) } }
#[async_trait] impl ToolHandler for IlLiftLevelAtLeastPairR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __il_lift_parse_level_r7(args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing a".into()))?)?; let b = __il_lift_parse_level_r7(args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing b".into()))?)?; Ok(ToolResult::text(json!({"a":a.to_string(),"b":b.to_string(),"a_at_least_b":a.at_least(b),"source":"rustre_il_lift::LiftLevel::at_least"}).to_string())) } }

pub struct IlLiftLevelAllVariantsR7Tool;
impl IlLiftLevelAllVariantsR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_level_all_variants_r7".to_string(), description: "LiftLevel::all() variants and displays.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLevelAllVariantsR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let all = rustre_il_lift::LiftLevel::all(); let names: Vec<String> = all.iter().map(|l| l.to_string()).collect(); Ok(ToolResult::text(json!({"count":all.len(),"variants":names,"source":"rustre_il_lift::LiftLevel::all"}).to_string())) } }

pub struct IlLiftCacheNewCapacityR7Tool;
impl IlLiftCacheNewCapacityR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_cache_new_capacity_r7".to_string(), description: "LiftCache::new(capacity) initial state.".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer","minimum":1}},"required":["capacity"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftCacheNewCapacityR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing capacity".into()))? as usize; let c = rustre_il_lift::LiftCache::new(cap); Ok(ToolResult::text(json!({"capacity":cap,"len":c.len(),"is_empty":c.is_empty(),"hits":c.hits(),"misses":c.misses(),"hit_rate":c.hit_rate(),"source":"rustre_il_lift::LiftCache::new"}).to_string())) } }

pub struct IlLiftCacheClearR7Tool;
impl IlLiftCacheClearR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_cache_clear_r7".to_string(), description: "LiftCache::default_capacity + clear roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftCacheClearR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::LiftCache::default_capacity(); let before_len = c.len(); c.clear(); Ok(ToolResult::text(json!({"before_len":before_len,"after_len":c.len(),"is_empty":c.is_empty(),"source":"rustre_il_lift::LiftCache::clear"}).to_string())) } }

pub struct IlLiftLifterRegistryNewEmptyR7Tool;
impl IlLiftLifterRegistryNewEmptyR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifter_registry_new_empty_r7".to_string(), description: "LifterRegistry::new() empty state.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLifterRegistryNewEmptyR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LifterRegistry::new(); Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"arch_names":r.arch_names(),"source":"rustre_il_lift::LifterRegistry::new"}).to_string())) } }

pub struct IlLiftLifterRegistrySupportsGetR7Tool;
impl IlLiftLifterRegistrySupportsGetR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifter_registry_supports_get_r7".to_string(), description: "LifterRegistry::with_defaults + supports + get(arch).".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLifterRegistrySupportsGetR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing arch".into()))?; let r = rustre_il_lift::LifterRegistry::with_defaults(); Ok(ToolResult::text(json!({"arch":arch,"supported":r.supports(arch),"got":r.get(arch).is_some(),"total":r.len(),"source":"rustre_il_lift::LifterRegistry::get"}).to_string())) } }

pub struct IlLiftAddressMapContainsR7Tool;
impl IlLiftAddressMapContainsR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_contains_r7".to_string(), description: "AddressMap::new + contains(addr) probe.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer","minimum":0}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftAddressMapContainsR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing addr".into()))?; let m = rustre_il_lift::AddressMap::new(); Ok(ToolResult::text(json!({"addr":addr,"contains":m.contains(addr),"len":m.len(),"is_empty":m.is_empty(),"source":"rustre_il_lift::AddressMap::contains"}).to_string())) } }

pub struct IlLiftAddressMapAddressesEmptyR7Tool;
impl IlLiftAddressMapAddressesEmptyR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_addresses_empty_r7".to_string(), description: "AddressMap::new + addresses() empty.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftAddressMapAddressesEmptyR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let m = rustre_il_lift::AddressMap::new(); let addrs = m.addresses(); Ok(ToolResult::text(json!({"count":addrs.len(),"addresses":addrs,"is_empty":m.is_empty(),"source":"rustre_il_lift::AddressMap::addresses"}).to_string())) } }

pub struct IlLiftAddressMapInstructionsEmptyR7Tool;
impl IlLiftAddressMapInstructionsEmptyR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_instructions_empty_r7".to_string(), description: "AddressMap::new + instructions() empty view.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftAddressMapInstructionsEmptyR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let m = rustre_il_lift::AddressMap::new(); let ins = m.instructions(); Ok(ToolResult::text(json!({"count":ins.len(),"source":"rustre_il_lift::AddressMap::instructions"}).to_string())) } }

pub struct IlLiftX86LiftCacheClearR7Tool;
impl IlLiftX86LiftCacheClearR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_clear_r7".to_string(), description: "X86LiftCache::new + clear.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheClearR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut c = rustre_il_lift::X86LiftCache::new(); c.clear(); Ok(ToolResult::text(json!({"len":c.len(),"is_empty":c.is_empty(),"source":"rustre_il_lift::X86LiftCache::clear"}).to_string())) } }

pub struct IlLiftX86LiftCacheInvalidateR7Tool;
impl IlLiftX86LiftCacheInvalidateR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_invalidate_r7".to_string(), description: "X86LiftCache::new + invalidate(addr).".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer","minimum":0}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheInvalidateR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing addr".into()))?; let mut c = rustre_il_lift::X86LiftCache::new(); c.invalidate(addr); Ok(ToolResult::text(json!({"invalidated":addr,"len":c.len(),"is_empty":c.is_empty(),"source":"rustre_il_lift::X86LiftCache::invalidate"}).to_string())) } }

pub struct IlLiftLiftMetadataWithVersionR7Tool;
impl IlLiftLiftMetadataWithVersionR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_metadata_with_version_r7".to_string(), description: "LiftMetadata::new + with_version.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"},"version":{"type":"string"}},"required":["arch","version"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftMetadataWithVersionR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing arch".into()))?; let ver = args.get("version").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing version".into()))?; let m = rustre_il_lift::LiftMetadata::new(arch, rustre_il_lift::LiftLevel::Llil).with_version(ver); Ok(ToolResult::text(json!({"arch":m.source_arch,"version":m.lifter_version,"level":m.target_level.to_string(),"source":"rustre_il_lift::LiftMetadata::with_version"}).to_string())) } }

pub struct IlLiftDiffAddressMapsEmptyR7Tool;
impl IlLiftDiffAddressMapsEmptyR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_diff_address_maps_empty_r7".to_string(), description: "diff_address_maps(left,right) on two empty maps.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftDiffAddressMapsEmptyR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let a = rustre_il_lift::AddressMap::new(); let b = rustre_il_lift::AddressMap::new(); let d = rustre_il_lift::diff_address_maps(&a, &b); Ok(ToolResult::text(json!({"only_in_left":d.only_in_left.len(),"only_in_right":d.only_in_right.len(),"changed":d.changed.len(),"identical":d.identical.len(),"is_empty":d.is_empty(),"source":"rustre_il_lift::diff_address_maps"}).to_string())) } }

pub struct IlLiftPartialResultPushErrR7Tool;
impl IlLiftPartialResultPushErrR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_partial_result_push_err_r7".to_string(), description: "PartialLiftResult::new + push_err(addr) + snapshot.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}}},"required":["addrs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftPartialResultPushErrR7Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing addrs".into()))?; let mut p = rustre_il_lift::PartialLiftResult::new(); for v in arr { if let Some(a) = v.as_u64() { p.push_err(a); } } p.finalize(); let snap = p.snapshot(); Ok(ToolResult::text(json!({"errors":snap.errors.len(),"lifted":snap.lifted.len(),"total_count":snap.total_count(),"is_complete":snap.is_complete(),"finalized":p.finalized,"source":"rustre_il_lift::PartialLiftResult::snapshot"}).to_string())) } }

pub struct IlLiftMetadataDefaultR7Tool;
impl IlLiftMetadataDefaultR7Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_metadata_default_r7".to_string(), description: "LiftMetadata::default() base fields.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftMetadataDefaultR7Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let m = rustre_il_lift::LiftMetadata::default(); Ok(ToolResult::text(json!({"arch":m.source_arch,"level":m.target_level.to_string(),"version":m.lifter_version,"has_hash":m.has_hash(),"notes":m.notes.len(),"source":"rustre_il_lift::LiftMetadata::default"}).to_string())) } }

pub struct IlLiftLiftLevelNamesO1Tool;
impl IlLiftLiftLevelNamesO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_level_names_o1".to_string(), description: "LiftLevel::names() enumerates all IL level variant names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftLevelNamesO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let all = rustre_il_lift::LiftLevel::all(); let names: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"names": names, "count": all.len(), "source":"rustre_il_lift::LiftLevel::all"}).to_string())) } }

pub struct IlLiftLiftedInstrNodeCountEmptyO1Tool;
impl IlLiftLiftedInstrNodeCountEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifted_instr_node_count_empty_o1".to_string(), description: "IrExpr::node_count on Const/Reg/Add compound.".to_string(), input_schema: json!({"type":"object","properties":{"c":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftedInstrNodeCountEmptyO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("c").and_then(Value::as_u64).unwrap_or(7); let e = rustre_il_lift::IrExpr::Add(Box::new(rustre_il_lift::IrExpr::Const(c)), Box::new(rustre_il_lift::IrExpr::Reg("rax".to_string()))); Ok(ToolResult::text(json!({"node_count": e.node_count(), "source":"rustre_il_lift::IrExpr::node_count"}).to_string())) } }

pub struct IlLiftLiftedInstrRegistersUsedEmptyO1Tool;
impl IlLiftLiftedInstrRegistersUsedEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifted_instr_registers_used_empty_o1".to_string(), description: "IrExpr::registers_used on Add(Reg, Reg) expression.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftedInstrRegistersUsedEmptyO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("a").and_then(Value::as_str).unwrap_or("rax").to_string(); let b = args.get("b").and_then(Value::as_str).unwrap_or("rbx").to_string(); let e = rustre_il_lift::IrExpr::Add(Box::new(rustre_il_lift::IrExpr::Reg(a)), Box::new(rustre_il_lift::IrExpr::Reg(b))); let r = e.registers_used(); Ok(ToolResult::text(json!({"regs": r, "count": r.len(), "source":"rustre_il_lift::IrExpr::registers_used"}).to_string())) } }

pub struct IlLiftLiftedInstrWrittenRegistersEmptyO1Tool;
impl IlLiftLiftedInstrWrittenRegistersEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifted_instr_written_registers_empty_o1".to_string(), description: "LiftedInstr::written_registers on empty-effects instr.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftedInstrWrittenRegistersEmptyO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let li = _il_o1_mk_lifted(0x1000); let r = li.written_registers(); Ok(ToolResult::text(json!({"regs": r, "count": r.len(), "source":"rustre_il_lift::LiftedInstr::written_registers"}).to_string())) } }

pub struct IlLiftLiftedInstrReadRegistersEmptyO1Tool;
impl IlLiftLiftedInstrReadRegistersEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifted_instr_read_registers_empty_o1".to_string(), description: "LiftedInstr::read_registers on empty-effects instr.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftedInstrReadRegistersEmptyO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let li = _il_o1_mk_lifted(0x1000); let r = li.read_registers(); Ok(ToolResult::text(json!({"regs": r, "count": r.len(), "source":"rustre_il_lift::LiftedInstr::read_registers"}).to_string())) } }

pub struct IlLiftX86LifterNewBitsO1Tool;
impl IlLiftX86LifterNewBitsO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lifter_new_bits_o1".to_string(), description: "X86Lifter::new(bits) records the bitness field.".to_string(), input_schema: json!({"type":"object","properties":{"bits":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LifterNewBitsO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bits = u8::try_from(args.get("bits").and_then(Value::as_u64).unwrap_or(64)).unwrap_or(64); let l = rustre_il_lift::X86Lifter::new(bits); Ok(ToolResult::text(json!({"bits": l.bits, "source":"rustre_il_lift::X86Lifter::new"}).to_string())) } }

pub struct IlLiftX86LifterLiftNopO1Tool;
impl IlLiftX86LifterLiftNopO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lifter_lift_nop_o1".to_string(), description: "X86Lifter::lift_instruction on a single-byte NOP (0x90).".to_string(), input_schema: json!({"type":"object","properties":{"ip":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LifterLiftNopO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ip = args.get("ip").and_then(Value::as_u64).unwrap_or(0x1000); let l = rustre_il_lift::X86Lifter::new(64); let ops = l.lift_instruction(&[0x90], ip).map_err(|e| McpError::InternalError(format!("lift_instruction: {e:?}")))?; Ok(ToolResult::text(json!({"op_count": ops.len(), "ip": ip, "source":"rustre_il_lift::X86Lifter::lift_instruction"}).to_string())) } }

pub struct IlLiftX86LifterDecodeAndLiftNopO1Tool;
impl IlLiftX86LifterDecodeAndLiftNopO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lifter_decode_and_lift_nop_o1".to_string(), description: "X86Lifter::decode_and_lift on a single-byte NOP (0x90).".to_string(), input_schema: json!({"type":"object","properties":{"ip":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LifterDecodeAndLiftNopO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ip = args.get("ip").and_then(Value::as_u64).unwrap_or(0x1000); let l = rustre_il_lift::X86Lifter::new(64); let ops = l.decode_and_lift(&[0x90], ip); Ok(ToolResult::text(json!({"decoded": ops.is_some(), "op_count": ops.as_ref().map(Vec::len).unwrap_or(0), "source":"rustre_il_lift::X86Lifter::decode_and_lift"}).to_string())) } }

pub struct IlLiftX86LiftCacheNewEmptyO1Tool;
impl IlLiftX86LiftCacheNewEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_new_empty_o1".to_string(), description: "X86LiftCache::new() empty state: len/is_empty/hits/misses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheNewEmptyO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::X86LiftCache::new(); Ok(ToolResult::text(json!({"len": c.len(), "is_empty": c.is_empty(), "hits": c.hits(), "misses": c.misses(), "source":"rustre_il_lift::X86LiftCache::new"}).to_string())) } }

pub struct IlLiftX86LiftCacheInvalidateO1Tool;
impl IlLiftX86LiftCacheInvalidateO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_invalidate_o1".to_string(), description: "X86LiftCache::invalidate removes an address; verify via len before/after.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheInvalidateO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let mut c = rustre_il_lift::X86LiftCache::new(); let l = rustre_il_lift::X86Lifter::new(64); let _ = c.lift_with_cache(&l, addr, &[0x90]).len(); let before = c.len(); c.invalidate(addr); Ok(ToolResult::text(json!({"before": before, "after": c.len(), "source":"rustre_il_lift::X86LiftCache::invalidate"}).to_string())) } }

pub struct IlLiftX86LiftCacheHitRateO1Tool;
impl IlLiftX86LiftCacheHitRateO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_x86_lift_cache_hit_rate_o1".to_string(), description: "X86LiftCache::hit_rate after miss+hit sequence at same address.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftX86LiftCacheHitRateO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let mut c = rustre_il_lift::X86LiftCache::new(); let l = rustre_il_lift::X86Lifter::new(64); let _ = c.lift_with_cache(&l, addr, &[0x90]).len(); let _ = c.lift_with_cache(&l, addr, &[0x90]).len(); Ok(ToolResult::text(json!({"hits": c.hits(), "misses": c.misses(), "hit_rate": c.hit_rate(), "source":"rustre_il_lift::X86LiftCache::hit_rate"}).to_string())) } }

pub struct IlLiftBatchLifterForArchO1Tool;
impl IlLiftBatchLifterForArchO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_batch_lifter_for_arch_o1".to_string(), description: "LiftCoordinator::for_arch(name) exposes arch_name/lift_level.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftBatchLifterForArchO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"); let b = rustre_il_lift::LiftCoordinator::for_arch(arch); Ok(ToolResult::text(json!({"arch_name": b.arch_name(), "lift_level": b.lift_level().to_string(), "source":"rustre_il_lift::LiftCoordinator::for_arch"}).to_string())) } }

pub struct IlLiftBatchLifterRecoveryO1Tool;
impl IlLiftBatchLifterRecoveryO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_batch_lifter_recovery_o1".to_string(), description: "LiftCoordinator::for_arch_with_recovery yields a coordinator.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftBatchLifterRecoveryO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"); let b = rustre_il_lift::LiftCoordinator::for_arch_with_recovery(arch); Ok(ToolResult::text(json!({"arch_name": b.arch_name(), "lift_level": b.lift_level().to_string(), "source":"rustre_il_lift::LiftCoordinator::for_arch_with_recovery"}).to_string())) } }

pub struct IlLiftBatchLifterLiftBlockEmptyO1Tool;
impl IlLiftBatchLifterLiftBlockEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_batch_lifter_lift_block_empty_o1".to_string(), description: "LiftCoordinator::lift_block with an empty slice returns an empty vec.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftBatchLifterLiftBlockEmptyO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let b = rustre_il_lift::LiftCoordinator::for_arch("x86_64"); let v = b.lift_block(&[]); Ok(ToolResult::text(json!({"len": v.len(), "source":"rustre_il_lift::LiftCoordinator::lift_block"}).to_string())) } }

pub struct IlLiftStreamingLifterSnapshotO1Tool;
impl IlLiftStreamingLifterSnapshotO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_streaming_lifter_snapshot_o1".to_string(), description: "StreamingLifter::for_arch + feed(nop) + snapshot totals.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftStreamingLifterSnapshotO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"); let mut sl = rustre_il_lift::StreamingLifter::for_arch(arch); let instr = _il_o1_mk_instr(); let _ = sl.feed(&instr); let snap = sl.snapshot(); Ok(ToolResult::text(json!({"total": snap.total_count(), "is_complete": snap.is_complete(), "lifted": snap.lifted.len(), "source":"rustre_il_lift::StreamingLifter::snapshot"}).to_string())) } }

pub struct IlLiftLiftPipelineNewO1Tool;
impl IlLiftLiftPipelineNewO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_pipeline_new_o1".to_string(), description: "LiftPipeline::new() has zero stages.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftPipelineNewO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let p = rustre_il_lift::LiftPipeline::new(); let names = p.stage_names(); Ok(ToolResult::text(json!({"stage_count": names.len(), "stage_names": names, "source":"rustre_il_lift::LiftPipeline::new"}).to_string())) } }

pub struct IlLiftLiftSessionNewO1Tool;
impl IlLiftLiftSessionNewO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_session_new_o1".to_string(), description: "LiftSession::new(arch) empty session lifted_count/total_stats.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftSessionNewO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64"); let s = rustre_il_lift::LiftSession::new(arch); let stats = s.total_stats(); Ok(ToolResult::text(json!({"lifted_count": s.lifted_count(), "total_instructions": stats.total_instructions, "source":"rustre_il_lift::LiftSession::new"}).to_string())) } }

pub struct IlLiftLiftVerifierAllEquivalentO1Tool;
impl IlLiftLiftVerifierAllEquivalentO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_verifier_all_equivalent_o1".to_string(), description: "LiftVerifier::new + all_equivalent on an empty batch is trivially true.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftVerifierAllEquivalentO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = rustre_il_lift::LiftVerifier::new(); let all = v.all_equivalent(&[]); Ok(ToolResult::text(json!({"all_equivalent": all, "intrinsics_are_wildcards": v.intrinsics_are_wildcards, "source":"rustre_il_lift::LiftVerifier::all_equivalent"}).to_string())) } }

pub struct IlLiftLruLiftCacheEmptyO1Tool;
impl IlLiftLruLiftCacheEmptyO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lru_lift_cache_empty_o1".to_string(), description: "LruLiftCache::new(cap) empty state: len/is_empty/hits/misses/hit_rate.".to_string(), input_schema: json!({"type":"object","properties":{"cap":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLruLiftCacheEmptyO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = usize::try_from(args.get("cap").and_then(Value::as_u64).unwrap_or(16)).unwrap_or(16); let c = rustre_il_lift::LruLiftCache::new(cap); Ok(ToolResult::text(json!({"len": c.len(), "is_empty": c.is_empty(), "hits": c.hits(), "misses": c.misses(), "hit_rate": c.hit_rate(), "source":"rustre_il_lift::LruLiftCache::new"}).to_string())) } }

pub struct IlLiftLruLiftCacheInsertGetO1Tool;
impl IlLiftLruLiftCacheInsertGetO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lru_lift_cache_insert_get_o1".to_string(), description: "LruLiftCache::insert then get returns cached LiftedInstr (miss+hit).".to_string(), input_schema: json!({"type":"object","properties":{"cap":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLruLiftCacheInsertGetO1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = usize::try_from(args.get("cap").and_then(Value::as_u64).unwrap_or(16)).unwrap_or(16); let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let c = rustre_il_lift::LruLiftCache::new(cap); c.insert(addr, _il_o1_mk_lifted(addr)); let hit = c.get(addr).is_some(); let miss = c.get(addr.wrapping_add(1)).is_none(); Ok(ToolResult::text(json!({"hit": hit, "miss_absent": miss, "len": c.len(), "hits": c.hits(), "misses": c.misses(), "source":"rustre_il_lift::LruLiftCache::get"}).to_string())) } }

pub struct IlLiftRegisterAllLiftersO1Tool;
impl IlLiftRegisterAllLiftersO1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_register_all_lifters_o1".to_string(), description: "register_all_lifters populates a fresh LifterRegistry.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftRegisterAllLiftersO1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut reg = rustre_il_lift::LifterRegistry::new(); rustre_il_lift::register_all_lifters(&mut reg); Ok(ToolResult::text(json!({"len": reg.len(), "is_empty": reg.is_empty(), "arch_names": reg.arch_names(), "source":"rustre_il_lift::register_all_lifters"}).to_string())) } }

pub struct IlLiftArm64LiftMovJ30Tool;
impl IlLiftArm64LiftMovJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_mov_j30".to_string(), description: "Arm64Lifter::lift_mov([dst,src]).".to_string(), input_schema: json!({"type":"object","properties":{"dst":{"type":"string"},"src":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftMovJ30Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let d = args.get("dst").and_then(Value::as_str).unwrap_or("x0"); let s = args.get("src").and_then(Value::as_str).unwrap_or("x1"); let ops = rustre_il_lift::Arm64Lifter::lift_mov(&[d, s]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_mov"}).to_string())) } }

pub struct IlLiftArm64LiftAddJ30Tool;
impl IlLiftArm64LiftAddJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_add_j30".to_string(), description: "Arm64Lifter::lift_add([dst,a,b]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftAddJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_add(&["x0","x1","x2"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_add"}).to_string())) } }

pub struct IlLiftArm64LiftSubJ30Tool;
impl IlLiftArm64LiftSubJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_sub_j30".to_string(), description: "Arm64Lifter::lift_sub([dst,a,b]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftSubJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_sub(&["x0","x1","x2"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_sub"}).to_string())) } }

pub struct IlLiftArm64LiftAndJ30Tool;
impl IlLiftArm64LiftAndJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_and_j30".to_string(), description: "Arm64Lifter::lift_and([dst,a,b]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftAndJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_and(&["x0","x1","x2"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_and"}).to_string())) } }

pub struct IlLiftArm64LiftOrrJ30Tool;
impl IlLiftArm64LiftOrrJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_orr_j30".to_string(), description: "Arm64Lifter::lift_orr([dst,a,b]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftOrrJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_orr(&["x0","x1","x2"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_orr"}).to_string())) } }

pub struct IlLiftArm64LiftEorJ30Tool;
impl IlLiftArm64LiftEorJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_eor_j30".to_string(), description: "Arm64Lifter::lift_eor([dst,a,b]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftEorJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_eor(&["x0","x1","x2"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_eor"}).to_string())) } }

pub struct IlLiftArm64LiftLdrJ30Tool;
impl IlLiftArm64LiftLdrJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_ldr_j30".to_string(), description: "Arm64Lifter::lift_ldr([dst,mem]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftLdrJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_ldr(&["x0","[x1]"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_ldr"}).to_string())) } }

pub struct IlLiftArm64LiftStrJ30Tool;
impl IlLiftArm64LiftStrJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_str_j30".to_string(), description: "Arm64Lifter::lift_str([src,mem]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftStrJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_str(&["x0","[x1]"], "str"); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_str"}).to_string())) } }

pub struct IlLiftArm64LiftBJ30Tool;
impl IlLiftArm64LiftBJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_b_j30".to_string(), description: "Arm64Lifter::lift_b([target]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftBJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_b(&["0x1000"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_b"}).to_string())) } }

pub struct IlLiftArm64LiftBlJ30Tool;
impl IlLiftArm64LiftBlJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_bl_j30".to_string(), description: "Arm64Lifter::lift_bl([target]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftBlJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_bl(&["0x2000"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_bl"}).to_string())) } }

pub struct IlLiftArm64LiftBlrJ30Tool;
impl IlLiftArm64LiftBlrJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_blr_j30".to_string(), description: "Arm64Lifter::lift_blr([reg]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftBlrJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_blr(&["x9"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_blr"}).to_string())) } }

pub struct IlLiftArm64LiftRetJ30Tool;
impl IlLiftArm64LiftRetJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_ret_j30".to_string(), description: "Arm64Lifter::lift_ret([]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftRetJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_ret(&[]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_ret"}).to_string())) } }

pub struct IlLiftArm64LiftSvcJ30Tool;
impl IlLiftArm64LiftSvcJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_svc_j30".to_string(), description: "Arm64Lifter::lift_svc([]).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftSvcJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = rustre_il_lift::Arm64Lifter::lift_svc(&[]); Ok(ToolResult::text(json!({"op_count":ops.len(),"source":"rustre_il_lift::Arm64Lifter::lift_svc"}).to_string())) } }

pub struct IlLiftArm64LiftBcondEqJ30Tool;
impl IlLiftArm64LiftBcondEqJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lift_bcond_eq_j30".to_string(), description: "Arm64Lifter::lift_bcond(cond, [target]).".to_string(), input_schema: json!({"type":"object","properties":{"cond":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LiftBcondEqJ30Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("cond").and_then(Value::as_str).unwrap_or("EQ"); let ops = rustre_il_lift::Arm64Lifter::lift_bcond(c, &["0x3000"]); Ok(ToolResult::text(json!({"op_count":ops.len(),"cond":c,"source":"rustre_il_lift::Arm64Lifter::lift_bcond"}).to_string())) } }

pub struct IlLiftArm64LifterNewJ30Tool;
impl IlLiftArm64LifterNewJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_arm64_lifter_new_j30".to_string(), description: "Arm64Lifter::new() constructor smoke test.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftArm64LifterNewJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let _ = rustre_il_lift::Arm64Lifter::new(); Ok(ToolResult::text(json!({"ok":true,"source":"rustre_il_lift::Arm64Lifter::new"}).to_string())) } }

pub struct IlLiftLiftLevelAtLeastDisasmJ30Tool;
impl IlLiftLiftLevelAtLeastDisasmJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_liftlevel_at_least_disasm_j30".to_string(), description: "LiftLevel::Disasm.at_least(Llil) etc.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftLevelAtLeastDisasmJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_il_lift::LiftLevel as L; Ok(ToolResult::text(json!({"disasm_ge_disasm": L::Raw.at_least(L::Raw), "disasm_ge_llil": L::Raw.at_least(L::Llil), "llil_ge_disasm": L::Llil.at_least(L::Raw), "source":"rustre_il_lift::LiftLevel::at_least"}).to_string())) } }

pub struct IlLiftLiftLevelDisplayDisasmJ30Tool;
impl IlLiftLiftLevelDisplayDisasmJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_liftlevel_display_disasm_j30".to_string(), description: "Display strings for LiftLevel variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftLevelDisplayDisasmJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_il_lift::LiftLevel as L; Ok(ToolResult::text(json!({"disasm": L::Raw.to_string(), "llil": L::Llil.to_string(), "source":"rustre_il_lift::LiftLevel::Display"}).to_string())) } }

pub struct IlLiftLiftCacheDefaultLenJ30Tool;
impl IlLiftLiftCacheDefaultLenJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_cache_default_len_j30".to_string(), description: "LiftCache::default_capacity() then len/is_empty/hits/misses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftCacheDefaultLenJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::LiftCache::default_capacity(); Ok(ToolResult::text(json!({"len":c.len(),"empty":c.is_empty(),"hits":c.hits(),"misses":c.misses(),"source":"rustre_il_lift::LiftCache::default_capacity"}).to_string())) } }

pub struct IlLiftLiftCacheGetMissJ30Tool;
impl IlLiftLiftCacheGetMissJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_cache_get_miss_j30".to_string(), description: "LiftCache::new(4): get() on unknown address increments misses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftCacheGetMissJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_il_lift::LiftCache::new(4); let hit = c.get(0xDEAD).is_some(); Ok(ToolResult::text(json!({"hit":hit,"hits":c.hits(),"misses":c.misses(),"hit_rate":c.hit_rate(),"source":"rustre_il_lift::LiftCache::get"}).to_string())) } }

pub struct IlLiftLiftReportSummaryDefaultJ30Tool;
impl IlLiftLiftReportSummaryDefaultJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_report_summary_default_j30".to_string(), description: "LiftReport::from_result(&LiftResult::new(), LiftMetadata::default()).summary().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftReportSummaryDefaultJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LiftResult::new(); let m = rustre_il_lift::LiftMetadata::default(); let rep = rustre_il_lift::LiftReport::from_result(&r, m); Ok(ToolResult::text(json!({"summary":rep.summary(),"source":"rustre_il_lift::LiftReport::summary"}).to_string())) } }

pub struct IlLiftLifterRegistryDefaultsLenJ30Tool;
impl IlLiftLifterRegistryDefaultsLenJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lifter_registry_defaults_len_j30".to_string(), description: "LifterRegistry::with_defaults() then len/is_empty.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLifterRegistryDefaultsLenJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_il_lift::LifterRegistry::with_defaults(); Ok(ToolResult::text(json!({"len":r.len(),"empty":r.is_empty(),"has_aarch64":r.supports("aarch64"),"has_x86_64":r.supports("x86_64"),"source":"rustre_il_lift::LifterRegistry::with_defaults"}).to_string())) } }

pub struct IlLiftLiftMetadataAddNoteJ30Tool;
impl IlLiftLiftMetadataAddNoteJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_metadata_add_note_j30".to_string(), description: "LiftMetadata::new+add_note+with_hash+with_version.".to_string(), input_schema: json!({"type":"object","properties":{"note":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftMetadataAddNoteJ30Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("note").and_then(Value::as_str).unwrap_or("hello"); let mut m = rustre_il_lift::LiftMetadata::new("x86_64", rustre_il_lift::LiftLevel::Llil); m.add_note(n); let m = m.with_hash("abcd").with_version("1.0"); Ok(ToolResult::text(json!({"arch":m.source_arch,"version":m.lifter_version,"note_count":m.notes.len(),"source":"rustre_il_lift::LiftMetadata"}).to_string())) } }

pub struct IlLiftLiftFilterTerminatorsJ30Tool;
impl IlLiftLiftFilterTerminatorsJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_filter_terminators_j30".to_string(), description: "LiftFilter::terminators on single mocked instr.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftFilterTerminatorsJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = vec![_il_o1_mk_lifted(0x1000)]; let t = rustre_il_lift::LiftFilter::terminators(&v); Ok(ToolResult::text(json!({"count":t.len(),"input":v.len(),"source":"rustre_il_lift::LiftFilter::terminators"}).to_string())) } }

pub struct IlLiftLiftFilterSideEffectsJ30Tool;
impl IlLiftLiftFilterSideEffectsJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_filter_side_effects_j30".to_string(), description: "LiftFilter::with_side_effects on single mocked instr.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftFilterSideEffectsJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = vec![_il_o1_mk_lifted(0x1000)]; let r = rustre_il_lift::LiftFilter::with_side_effects(&v); Ok(ToolResult::text(json!({"count":r.len(),"source":"rustre_il_lift::LiftFilter::with_side_effects"}).to_string())) } }

pub struct IlLiftLiftFilterWritingRegJ30Tool;
impl IlLiftLiftFilterWritingRegJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_filter_writing_reg_j30".to_string(), description: "LiftFilter::writing_register(&v, reg).".to_string(), input_schema: json!({"type":"object","properties":{"reg":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftFilterWritingRegJ30Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let reg = args.get("reg").and_then(Value::as_str).unwrap_or("rax"); let v = vec![_il_o1_mk_lifted(0x1000)]; let r = rustre_il_lift::LiftFilter::writing_register(&v, reg); Ok(ToolResult::text(json!({"count":r.len(),"reg":reg,"source":"rustre_il_lift::LiftFilter::writing_register"}).to_string())) } }

pub struct IlLiftLiftFilterCountStubsJ30Tool;
impl IlLiftLiftFilterCountStubsJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_filter_count_stubs_j30".to_string(), description: "LiftFilter::count_stubs(&v).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftFilterCountStubsJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = vec![_il_o1_mk_lifted(0x1000)]; let c = rustre_il_lift::LiftFilter::count_stubs(&v); Ok(ToolResult::text(json!({"stubs":c,"source":"rustre_il_lift::LiftFilter::count_stubs"}).to_string())) } }

pub struct IlLiftLiftFilterPartitionJ30Tool;
impl IlLiftLiftFilterPartitionJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_filter_partition_j30".to_string(), description: "LiftFilter::partition_by_effects(&v).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftFilterPartitionJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = vec![_il_o1_mk_lifted(0x1000)]; let (a, b) = rustre_il_lift::LiftFilter::partition_by_effects(&v); Ok(ToolResult::text(json!({"with":a.len(),"without":b.len(),"source":"rustre_il_lift::LiftFilter::partition_by_effects"}).to_string())) } }

pub struct IlLiftPartialSnapshotJ30Tool;
impl IlLiftPartialSnapshotJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_partial_snapshot_j30".to_string(), description: "PartialLiftResult::new+push_ok+snapshot.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftPartialSnapshotJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut p = rustre_il_lift::PartialLiftResult::new(); p.push_ok(_il_o1_mk_lifted(0x1000)); p.push_err(0x2000); let snap = p.snapshot(); Ok(ToolResult::text(json!({"total":snap.total_count(),"rate":snap.success_rate(),"failed":snap.failed_addresses().len(),"source":"rustre_il_lift::PartialLiftResult::snapshot"}).to_string())) } }

pub struct IlLiftAddressMapContainsJ30Tool;
impl IlLiftAddressMapContainsJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_address_map_contains_j30".to_string(), description: "AddressMap::insert+contains+get+addresses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftAddressMapContainsJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut m = rustre_il_lift::AddressMap::new(); m.insert(0x100, _il_o1_mk_lifted(0x100)); let has = m.contains(0x100); let get_some = m.get(0x100).is_some(); let addrs = m.addresses(); Ok(ToolResult::text(json!({"contains":has,"get_some":get_some,"addr_count":addrs.len(),"source":"rustre_il_lift::AddressMap"}).to_string())) } }

pub struct IlLiftLiftSessionResetJ30Tool;
impl IlLiftLiftSessionResetJ30Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_lift_lift_session_reset_j30".to_string(), description: "LiftSession::new+total_stats+reset.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for IlLiftLiftSessionResetJ30Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut s = rustre_il_lift::LiftSession::new("x86_64"); let ts0 = s.total_stats(); s.reset(); let ts1 = s.total_stats(); Ok(ToolResult::text(json!({"total0":ts0.total_instructions,"total1":ts1.total_instructions,"source":"rustre_il_lift::LiftSession::reset"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IlLiftSupportedArchesTool::definition(), Box::new(IlLiftSupportedArchesTool)),
        (IlLiftArchCountTool::definition(), Box::new(IlLiftArchCountTool)),
        (IlLiftSupportsTool::definition(), Box::new(IlLiftSupportsTool)),
        (IlLiftIsEmptyTool::definition(), Box::new(IlLiftIsEmptyTool)),
        (IlLiftArchDescriptionTool::definition(), Box::new(IlLiftArchDescriptionTool)),
        (IlLiftRegistryNewLenTool::definition(), Box::new(IlLiftRegistryNewLenTool)),
        (IlLiftCacheDefaultCapacityLenTool::definition(), Box::new(IlLiftCacheDefaultCapacityLenTool)),
        (IlLiftRegisterAllCountTool::definition(), Box::new(IlLiftRegisterAllCountTool)),
        (IlLiftRegisterAllLiftersTool::definition(), Box::new(IlLiftRegisterAllLiftersTool)),
        (IlLiftDiffAddressMapsTool::definition(), Box::new(IlLiftDiffAddressMapsTool)),
        (IlLiftLevelAtLeastTool::definition(), Box::new(IlLiftLevelAtLeastTool)),
        (IlLiftLevelAllTool::definition(), Box::new(IlLiftLevelAllTool)),
        (IlLiftX86LiftBytesTool::definition(), Box::new(IlLiftX86LiftBytesTool)),
        (IlLiftX86CacheStateTool::definition(), Box::new(IlLiftX86CacheStateTool)),
        (IlLiftAddressMapNewStateTool::definition(), Box::new(IlLiftAddressMapNewStateTool)),
        (IlLiftDiffEmptyMapsTool::definition(), Box::new(IlLiftDiffEmptyMapsTool)),
        (IlLiftPipelineDefaultStagesTool::definition(), Box::new(IlLiftPipelineDefaultStagesTool)),
        (IlLiftX86RegIdTool::definition(), Box::new(IlLiftX86RegIdTool)),
        (IlLiftLiftCacheInitStateTool::definition(), Box::new(IlLiftLiftCacheInitStateTool)),
        (IlLiftLruCacheInitStateTool::definition(), Box::new(IlLiftLruCacheInitStateTool)),
        (IlLiftLiftStatsRatesTool::definition(), Box::new(IlLiftLiftStatsRatesTool)),
        (IlLiftLiftStatsMergeTool::definition(), Box::new(IlLiftLiftStatsMergeTool)),
        (IlLiftEmptyLiftDiffTool::definition(), Box::new(IlLiftEmptyLiftDiffTool)),
        (IlLiftLevelDisplayTool::definition(), Box::new(IlLiftLevelDisplayTool)),
        (IlLiftX86LifterNewTool::definition(), Box::new(IlLiftX86LifterNewTool)),
        (IlLiftArm64LifterNewTool::definition(), Box::new(IlLiftArm64LifterNewTool)),
        (IlLiftMetadataBuildTool::definition(), Box::new(IlLiftMetadataBuildTool)),
        (IlLiftAddressMapEmptyProbeTool::definition(), Box::new(IlLiftAddressMapEmptyProbeTool)),
        (IlLiftFilterTerminatorsEmptyTool::definition(), Box::new(IlLiftFilterTerminatorsEmptyTool)),
        (IlLiftFilterWithSideEffectsEmptyTool::definition(), Box::new(IlLiftFilterWithSideEffectsEmptyTool)),
        (IlLiftFilterAtLevelEmptyTool::definition(), Box::new(IlLiftFilterAtLevelEmptyTool)),
        (IlLiftFilterCountStubsEmptyTool::definition(), Box::new(IlLiftFilterCountStubsEmptyTool)),
        (IlLiftFilterPartitionEffectsEmptyTool::definition(), Box::new(IlLiftFilterPartitionEffectsEmptyTool)),
        (IlLiftReportSummaryEmptyTool::definition(), Box::new(IlLiftReportSummaryEmptyTool)),
        (IlLiftRegistryWithDefaultsTool::definition(), Box::new(IlLiftRegistryWithDefaultsTool)),
        (IlLiftRegistryDefaultsSupportsTool::definition(), Box::new(IlLiftRegistryDefaultsSupportsTool)),
        (IlLiftPartialBuilderEmptyTool::definition(), Box::new(IlLiftPartialBuilderEmptyTool)),
        (IlLiftPipelineEmptyStagesTool::definition(), Box::new(IlLiftPipelineEmptyStagesTool)),
        (IlLiftDiffCountTool::definition(), Box::new(IlLiftDiffCountTool)),
        (IlLiftMetadataHasHashTool::definition(), Box::new(IlLiftMetadataHasHashTool)),
        (IlLiftMetadataWithTimestampTool::definition(), Box::new(IlLiftMetadataWithTimestampTool)),
        (IlLiftLiftStatsNewTool::definition(), Box::new(IlLiftLiftStatsNewTool)),
        (IlLiftAddressMapRangeTool::definition(), Box::new(IlLiftAddressMapRangeTool)),
        (IlLiftAddressMapMergeTool::definition(), Box::new(IlLiftAddressMapMergeTool)),
        (IlLiftLifterRegistryArchNamesTool::definition(), Box::new(IlLiftLifterRegistryArchNamesTool)),
        (IlLiftLifterRegistryLenTool::definition(), Box::new(IlLiftLifterRegistryLenTool)),
        (IlLiftLiftcacheOpsTool::definition(), Box::new(IlLiftLiftcacheOpsTool)),
        (IlLiftLiftlevelDisplayAllTool::definition(), Box::new(IlLiftLiftlevelDisplayAllTool)),
        (IlLiftLiftResultSuccessRateEmptyN5Tool::definition(), Box::new(IlLiftLiftResultSuccessRateEmptyN5Tool)),
        (IlLiftLiftStatsHitRateN5Tool::definition(), Box::new(IlLiftLiftStatsHitRateN5Tool)),
        (IlLiftLiftedInstrTerminatorN5Tool::definition(), Box::new(IlLiftLiftedInstrTerminatorN5Tool)),
        (IlLiftLiftCacheEvictN5Tool::definition(), Box::new(IlLiftLiftCacheEvictN5Tool)),
        (IlLiftAddressMapMergeFromN5Tool::definition(), Box::new(IlLiftAddressMapMergeFromN5Tool)),
        (IlLiftAddressMapRangeN5Tool::definition(), Box::new(IlLiftAddressMapRangeN5Tool)),
        (IlLiftLifterRegistryLiftInstrUnsupportedN5Tool::definition(), Box::new(IlLiftLifterRegistryLiftInstrUnsupportedN5Tool)),
        (IlLiftLiftDiffEmptyN5Tool::definition(), Box::new(IlLiftLiftDiffEmptyN5Tool)),
        (IlLiftX86LifterRegIdRaxN5Tool::definition(), Box::new(IlLiftX86LifterRegIdRaxN5Tool)),
        (IlLiftLiftStatsMergeN5Tool::definition(), Box::new(IlLiftLiftStatsMergeN5Tool)),
        (IlLiftLifterRegistryEmptyN6Tool::definition(), Box::new(IlLiftLifterRegistryEmptyN6Tool)),
        (IlLiftLiftMetadataBuilderN6Tool::definition(), Box::new(IlLiftLiftMetadataBuilderN6Tool)),
        (IlLiftAddressMapIterN6Tool::definition(), Box::new(IlLiftAddressMapIterN6Tool)),
        (IlLiftLiftCacheDefaultCapacityN6Tool::definition(), Box::new(IlLiftLiftCacheDefaultCapacityN6Tool)),
        (IlLiftPartialLiftResultN6Tool::definition(), Box::new(IlLiftPartialLiftResultN6Tool)),
        (IlLiftArm64LiftMovN6Tool::definition(), Box::new(IlLiftArm64LiftMovN6Tool)),
        (IlLiftArm64LiftAddN6Tool::definition(), Box::new(IlLiftArm64LiftAddN6Tool)),
        (IlLiftArm64LiftRetN6Tool::definition(), Box::new(IlLiftArm64LiftRetN6Tool)),
        (IlLiftFiltersWritingRegisterN6Tool::definition(), Box::new(IlLiftFiltersWritingRegisterN6Tool)),
        (IlLiftReportFromResultN6Tool::definition(), Box::new(IlLiftReportFromResultN6Tool)),
        (IlLiftLevelAtLeastReflexiveN3Tool::definition(), Box::new(IlLiftLevelAtLeastReflexiveN3Tool)),
        (IlLiftResultNewEmptyN3Tool::definition(), Box::new(IlLiftResultNewEmptyN3Tool)),
        (IlLiftResultSuccessRateEmptyN3Tool::definition(), Box::new(IlLiftResultSuccessRateEmptyN3Tool)),
        (IlLiftResultFailedAddressesEmptyN3Tool::definition(), Box::new(IlLiftResultFailedAddressesEmptyN3Tool)),
        (IlLiftStatsCacheHitRateEmptyN3Tool::definition(), Box::new(IlLiftStatsCacheHitRateEmptyN3Tool)),
        (IlLiftStatsSuccessRateEmptyN3Tool::definition(), Box::new(IlLiftStatsSuccessRateEmptyN3Tool)),
        (IlLiftCacheDefaultCapacityOpsN3Tool::definition(), Box::new(IlLiftCacheDefaultCapacityOpsN3Tool)),
        (IlLiftMetadataAddNoteN3Tool::definition(), Box::new(IlLiftMetadataAddNoteN3Tool)),
        (IlLiftMetadataWithHashN3Tool::definition(), Box::new(IlLiftMetadataWithHashN3Tool)),
        (IlLiftX86LiftCacheEmptyStateN3Tool::definition(), Box::new(IlLiftX86LiftCacheEmptyStateN3Tool)),
        (IlLiftX86CachedAddressesEmptyN3Tool::definition(), Box::new(IlLiftX86CachedAddressesEmptyN3Tool)),
        (IlLiftRegistrySupportsX8664N3Tool::definition(), Box::new(IlLiftRegistrySupportsX8664N3Tool)),
        (IlLiftLevelAtLeastPairR7Tool::definition(), Box::new(IlLiftLevelAtLeastPairR7Tool)),
        (IlLiftLevelAllVariantsR7Tool::definition(), Box::new(IlLiftLevelAllVariantsR7Tool)),
        (IlLiftCacheNewCapacityR7Tool::definition(), Box::new(IlLiftCacheNewCapacityR7Tool)),
        (IlLiftCacheClearR7Tool::definition(), Box::new(IlLiftCacheClearR7Tool)),
        (IlLiftLifterRegistryNewEmptyR7Tool::definition(), Box::new(IlLiftLifterRegistryNewEmptyR7Tool)),
        (IlLiftLifterRegistrySupportsGetR7Tool::definition(), Box::new(IlLiftLifterRegistrySupportsGetR7Tool)),
        (IlLiftAddressMapContainsR7Tool::definition(), Box::new(IlLiftAddressMapContainsR7Tool)),
        (IlLiftAddressMapAddressesEmptyR7Tool::definition(), Box::new(IlLiftAddressMapAddressesEmptyR7Tool)),
        (IlLiftAddressMapInstructionsEmptyR7Tool::definition(), Box::new(IlLiftAddressMapInstructionsEmptyR7Tool)),
        (IlLiftX86LiftCacheClearR7Tool::definition(), Box::new(IlLiftX86LiftCacheClearR7Tool)),
        (IlLiftX86LiftCacheInvalidateR7Tool::definition(), Box::new(IlLiftX86LiftCacheInvalidateR7Tool)),
        (IlLiftLiftMetadataWithVersionR7Tool::definition(), Box::new(IlLiftLiftMetadataWithVersionR7Tool)),
        (IlLiftDiffAddressMapsEmptyR7Tool::definition(), Box::new(IlLiftDiffAddressMapsEmptyR7Tool)),
        (IlLiftPartialResultPushErrR7Tool::definition(), Box::new(IlLiftPartialResultPushErrR7Tool)),
        (IlLiftMetadataDefaultR7Tool::definition(), Box::new(IlLiftMetadataDefaultR7Tool)),
        (IlLiftLiftLevelNamesO1Tool::definition(), Box::new(IlLiftLiftLevelNamesO1Tool)),
        (IlLiftLiftedInstrNodeCountEmptyO1Tool::definition(), Box::new(IlLiftLiftedInstrNodeCountEmptyO1Tool)),
        (IlLiftLiftedInstrRegistersUsedEmptyO1Tool::definition(), Box::new(IlLiftLiftedInstrRegistersUsedEmptyO1Tool)),
        (IlLiftLiftedInstrWrittenRegistersEmptyO1Tool::definition(), Box::new(IlLiftLiftedInstrWrittenRegistersEmptyO1Tool)),
        (IlLiftLiftedInstrReadRegistersEmptyO1Tool::definition(), Box::new(IlLiftLiftedInstrReadRegistersEmptyO1Tool)),
        (IlLiftX86LifterNewBitsO1Tool::definition(), Box::new(IlLiftX86LifterNewBitsO1Tool)),
        (IlLiftX86LifterLiftNopO1Tool::definition(), Box::new(IlLiftX86LifterLiftNopO1Tool)),
        (IlLiftX86LifterDecodeAndLiftNopO1Tool::definition(), Box::new(IlLiftX86LifterDecodeAndLiftNopO1Tool)),
        (IlLiftX86LiftCacheNewEmptyO1Tool::definition(), Box::new(IlLiftX86LiftCacheNewEmptyO1Tool)),
        (IlLiftX86LiftCacheInvalidateO1Tool::definition(), Box::new(IlLiftX86LiftCacheInvalidateO1Tool)),
        (IlLiftX86LiftCacheHitRateO1Tool::definition(), Box::new(IlLiftX86LiftCacheHitRateO1Tool)),
        (IlLiftBatchLifterForArchO1Tool::definition(), Box::new(IlLiftBatchLifterForArchO1Tool)),
        (IlLiftBatchLifterRecoveryO1Tool::definition(), Box::new(IlLiftBatchLifterRecoveryO1Tool)),
        (IlLiftBatchLifterLiftBlockEmptyO1Tool::definition(), Box::new(IlLiftBatchLifterLiftBlockEmptyO1Tool)),
        (IlLiftStreamingLifterSnapshotO1Tool::definition(), Box::new(IlLiftStreamingLifterSnapshotO1Tool)),
        (IlLiftLiftPipelineNewO1Tool::definition(), Box::new(IlLiftLiftPipelineNewO1Tool)),
        (IlLiftLiftSessionNewO1Tool::definition(), Box::new(IlLiftLiftSessionNewO1Tool)),
        (IlLiftLiftVerifierAllEquivalentO1Tool::definition(), Box::new(IlLiftLiftVerifierAllEquivalentO1Tool)),
        (IlLiftLruLiftCacheEmptyO1Tool::definition(), Box::new(IlLiftLruLiftCacheEmptyO1Tool)),
        (IlLiftLruLiftCacheInsertGetO1Tool::definition(), Box::new(IlLiftLruLiftCacheInsertGetO1Tool)),
        (IlLiftRegisterAllLiftersO1Tool::definition(), Box::new(IlLiftRegisterAllLiftersO1Tool)),
        (IlLiftArm64LiftMovJ30Tool::definition(), Box::new(IlLiftArm64LiftMovJ30Tool)),
        (IlLiftArm64LiftAddJ30Tool::definition(), Box::new(IlLiftArm64LiftAddJ30Tool)),
        (IlLiftArm64LiftSubJ30Tool::definition(), Box::new(IlLiftArm64LiftSubJ30Tool)),
        (IlLiftArm64LiftAndJ30Tool::definition(), Box::new(IlLiftArm64LiftAndJ30Tool)),
        (IlLiftArm64LiftOrrJ30Tool::definition(), Box::new(IlLiftArm64LiftOrrJ30Tool)),
        (IlLiftArm64LiftEorJ30Tool::definition(), Box::new(IlLiftArm64LiftEorJ30Tool)),
        (IlLiftArm64LiftLdrJ30Tool::definition(), Box::new(IlLiftArm64LiftLdrJ30Tool)),
        (IlLiftArm64LiftStrJ30Tool::definition(), Box::new(IlLiftArm64LiftStrJ30Tool)),
        (IlLiftArm64LiftBJ30Tool::definition(), Box::new(IlLiftArm64LiftBJ30Tool)),
        (IlLiftArm64LiftBlJ30Tool::definition(), Box::new(IlLiftArm64LiftBlJ30Tool)),
        (IlLiftArm64LiftBlrJ30Tool::definition(), Box::new(IlLiftArm64LiftBlrJ30Tool)),
        (IlLiftArm64LiftRetJ30Tool::definition(), Box::new(IlLiftArm64LiftRetJ30Tool)),
        (IlLiftArm64LiftSvcJ30Tool::definition(), Box::new(IlLiftArm64LiftSvcJ30Tool)),
        (IlLiftArm64LiftBcondEqJ30Tool::definition(), Box::new(IlLiftArm64LiftBcondEqJ30Tool)),
        (IlLiftArm64LifterNewJ30Tool::definition(), Box::new(IlLiftArm64LifterNewJ30Tool)),
        (IlLiftLiftLevelAtLeastDisasmJ30Tool::definition(), Box::new(IlLiftLiftLevelAtLeastDisasmJ30Tool)),
        (IlLiftLiftLevelDisplayDisasmJ30Tool::definition(), Box::new(IlLiftLiftLevelDisplayDisasmJ30Tool)),
        (IlLiftLiftCacheDefaultLenJ30Tool::definition(), Box::new(IlLiftLiftCacheDefaultLenJ30Tool)),
        (IlLiftLiftCacheGetMissJ30Tool::definition(), Box::new(IlLiftLiftCacheGetMissJ30Tool)),
        (IlLiftLiftReportSummaryDefaultJ30Tool::definition(), Box::new(IlLiftLiftReportSummaryDefaultJ30Tool)),
        (IlLiftLifterRegistryDefaultsLenJ30Tool::definition(), Box::new(IlLiftLifterRegistryDefaultsLenJ30Tool)),
        (IlLiftLiftMetadataAddNoteJ30Tool::definition(), Box::new(IlLiftLiftMetadataAddNoteJ30Tool)),
        (IlLiftLiftFilterTerminatorsJ30Tool::definition(), Box::new(IlLiftLiftFilterTerminatorsJ30Tool)),
        (IlLiftLiftFilterSideEffectsJ30Tool::definition(), Box::new(IlLiftLiftFilterSideEffectsJ30Tool)),
        (IlLiftLiftFilterWritingRegJ30Tool::definition(), Box::new(IlLiftLiftFilterWritingRegJ30Tool)),
        (IlLiftLiftFilterCountStubsJ30Tool::definition(), Box::new(IlLiftLiftFilterCountStubsJ30Tool)),
        (IlLiftLiftFilterPartitionJ30Tool::definition(), Box::new(IlLiftLiftFilterPartitionJ30Tool)),
        (IlLiftPartialSnapshotJ30Tool::definition(), Box::new(IlLiftPartialSnapshotJ30Tool)),
        (IlLiftAddressMapContainsJ30Tool::definition(), Box::new(IlLiftAddressMapContainsJ30Tool)),
        (IlLiftLiftSessionResetJ30Tool::definition(), Box::new(IlLiftLiftSessionResetJ30Tool)),
    ]
}
