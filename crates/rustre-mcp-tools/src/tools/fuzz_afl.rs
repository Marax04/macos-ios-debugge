//! MCP wrappers for the rustre-fuzz_afl crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct FuzzAflDictLoadTool;

pub struct FuzzAflStatsParseTool;

pub struct FuzzAflStageBitFlip2Tool;
impl FuzzAflStageBitFlip2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_bit_flip_2".to_string(),
            description: "Generate the AFL bit-flip-2 stage mutations for the given input via rustre_fuzz_afl::stage_bit_flip_2.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageBitFlip2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_bit_flip_2(&data);
        Ok(ToolResult::text(json!({
            "count": out.len(),
            "source": "rustre_fuzz_afl::stage_bit_flip_2",
        }).to_string()))
    }
}

pub struct FuzzAflStageByteFlip1Tool;
impl FuzzAflStageByteFlip1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_byte_flip_1".to_string(),
            description: "Generate the AFL byte-flip-1 stage mutations via rustre_fuzz_afl::stage_byte_flip_1.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageByteFlip1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_byte_flip_1(&data);
        Ok(ToolResult::text(json!({
            "count": out.len(),
            "source": "rustre_fuzz_afl::stage_byte_flip_1",
        }).to_string()))
    }
}

pub struct FuzzAflStageInteresting8Tool;
impl FuzzAflStageInteresting8Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_interesting_8".to_string(),
            description: "Generate AFL interesting-8 stage mutations via rustre_fuzz_afl::stage_interesting_8.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageInteresting8Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_interesting_8(&data);
        Ok(ToolResult::text(json!({
            "count": out.len(),
            "source": "rustre_fuzz_afl::stage_interesting_8",
        }).to_string()))
    }
}

pub struct FuzzAflStageBitFlip1Tool;
impl FuzzAflStageBitFlip1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_bit_flip_1".to_string(),
            description: "Generate AFL bit-flip-1 stage mutations via rustre_fuzz_afl::stage_bit_flip_1.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageBitFlip1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let mut rng = rustre_fuzz_afl::SimpleRng::new(0xdead_beef);
        let out = rustre_fuzz_afl::stage_bit_flip_1(&data, &mut rng);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_bit_flip_1"}).to_string()))
    }
}

pub struct FuzzAflStageBitFlip4Tool;
impl FuzzAflStageBitFlip4Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_bit_flip_4".to_string(),
            description: "Generate AFL bit-flip-4 stage mutations via rustre_fuzz_afl::stage_bit_flip_4.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageBitFlip4Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_bit_flip_4(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_bit_flip_4"}).to_string()))
    }
}

pub struct FuzzAflStageArith8Tool;
impl FuzzAflStageArith8Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_arith_8".to_string(),
            description: "Generate AFL 8-bit arithmetic stage mutations via rustre_fuzz_afl::stage_arith_8.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageArith8Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_arith_8(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_arith_8"}).to_string()))
    }
}

pub struct FuzzAflStageArith16Tool;
impl FuzzAflStageArith16Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_arith_16".to_string(),
            description: "Generate AFL 16-bit arithmetic stage mutations via rustre_fuzz_afl::stage_arith_16.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageArith16Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_arith_16(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_arith_16"}).to_string()))
    }
}

pub struct FuzzAflStageArith32Tool;
impl FuzzAflStageArith32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_arith_32".to_string(),
            description: "Generate AFL 32-bit arithmetic stage mutations via rustre_fuzz_afl::stage_arith_32.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageArith32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_arith_32(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_arith_32"}).to_string()))
    }
}

pub struct FuzzAflStageInteresting16Tool;
impl FuzzAflStageInteresting16Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_interesting_16".to_string(),
            description: "Generate AFL interesting-16 stage mutations via rustre_fuzz_afl::stage_interesting_16.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageInteresting16Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_interesting_16(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_interesting_16"}).to_string()))
    }
}

pub struct FuzzAflStageInteresting32Tool;
impl FuzzAflStageInteresting32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_interesting_32".to_string(),
            description: "Generate AFL interesting-32 stage mutations via rustre_fuzz_afl::stage_interesting_32.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageInteresting32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_afl::stage_interesting_32(&data);
        Ok(ToolResult::text(json!({"count":out.len(),"source":"rustre_fuzz_afl::stage_interesting_32"}).to_string()))
    }
}

pub struct FuzzAflStageSpliceTool;
impl FuzzAflStageSpliceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stage_splice".to_string(),
            description: "Splice two inputs at a random crossover via rustre_fuzz_afl::SpliceMutator::splice.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"},"seed":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStageSpliceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // Ricondotto al decoder canonico. La guardia `while i + 1 < s.len()`
        // SCARTAVA IN SILENZIO l'ultimo nibble su lunghezza dispari: "abc"
        // decodificava `ab` e restituiva Ok, cioe' un successo su input
        // malformato. `crate::hex_decode` restituisce Err, come gli altri 22
        // decoder gia' ricondotti. Ultimo residuo della famiglia hex.
        // NIENTE `?`: la firma di `hx` e' identica a quella di hex_decode
        // (Result<Vec<u8>, McpError>) — espressione di coda, non srotolare.
        fn hx(s: &str) -> Result<Vec<u8>, McpError> {
            crate::hex_decode(s)
        }
        let a = hx(args.get("a_hex").and_then(Value::as_str).unwrap_or(""))?;
        let b = hx(args.get("b_hex").and_then(Value::as_str).unwrap_or(""))?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(0xdead_beef);
        let mut rng = rustre_fuzz_afl::XorShiftRng::new(seed);
        let out = rustre_fuzz_afl::SpliceMutator::splice(&a, &b, &mut rng);
        Ok(ToolResult::text(json!({"len":out.len(),"hex":hex_encode(&out),"source":"rustre_fuzz_afl::SpliceMutator::splice"}).to_string()))
    }
}

pub struct FuzzAflBitmapSummaryTool;
impl FuzzAflBitmapSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_bitmap_summary".to_string(),
            description: "Load AFL coverage bitmap and report non-zero count/hash/size via rustre_fuzz_afl::AflShmCoverage.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflBitmapSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let mut cov = rustre_fuzz_afl::AflShmCoverage::new(data.len().max(1));
        for (i, b) in data.iter().enumerate() { cov.bitmap[i] = *b; }
        let bucketed = cov.bucketed();
        Ok(ToolResult::text(json!({
            "size":cov.size,"count_non_zero":cov.count_non_zero(),"hash":cov.hash(),
            "bucketed_non_zero":bucketed.iter().filter(|&&b| b != 0).count(),
            "source":"rustre_fuzz_afl::AflShmCoverage"
        }).to_string()))
    }
}

pub struct FuzzAflStatsSerializeTool;
impl FuzzAflStatsSerializeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_stats_serialize".to_string(),
            description: "Round-trip parse and re-serialize AFL fuzzer_stats via rustre_fuzz_afl::AflStats.".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflStatsSerializeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let stats = rustre_fuzz_afl::AflStats::parse(text).map_err(|e| McpError::InternalError(format!("{e}")))?;
        Ok(ToolResult::text(json!({
            "serialized":stats.serialize(),"execs_done":stats.execs_done,"crashes_found":stats.crashes_found,
            "source":"rustre_fuzz_afl::AflStats::serialize"
        }).to_string()))
    }
}

pub struct FuzzAflDictInfoTool;
impl FuzzAflDictInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_dict_info".to_string(),
            description: "Load AFL-format dictionary and report token counts via rustre_fuzz_afl::Dictionary.".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflDictInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let mut dict = rustre_fuzz_afl::Dictionary::new();
        let count = dict.load_afl_format(text).map_err(|e| McpError::InternalError(format!("{e}")))?;
        let (min_len, max_len) = dict.entries.iter().fold((usize::MAX, 0usize), |(mn, mx), e| (mn.min(e.len()), mx.max(e.len())));
        Ok(ToolResult::text(json!({
            "count":count,"total_tokens":dict.len(),
            "min_len": if dict.is_empty() { 0 } else { min_len },
            "max_len":max_len,
            "source":"rustre_fuzz_afl::Dictionary"
        }).to_string()))
    }
}

pub struct FuzzAflCmplogColorizeTool;
impl FuzzAflCmplogColorizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_cmplog_colorize".to_string(),
            description: "Generate CMPLOG colorize mutations via rustre_fuzz_afl::CmplogMap::colorize_mutations.".to_string(),
            input_schema: json!({"type":"object","required":["entries"],"properties":{"bytes":{"type":"array"},"hex":{"type":"string"},"entries":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflCmplogColorizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let mut map = rustre_fuzz_afl::CmplogMap::new();
        let entries = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'entries'".into()))?;
        for e in entries {
            let addr = e.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let v0 = e.get("v0").and_then(Value::as_u64).unwrap_or(0);
            let v1 = e.get("v1").and_then(Value::as_u64).unwrap_or(0);
            let size = e.get("size").and_then(Value::as_u64).unwrap_or(4) as u8;
            map.record(addr, v0, v1, size);
        }
        let cands = map.colorize_mutations(&data);
        Ok(ToolResult::text(json!({
            "candidate_count":cands.len(),"entry_count":map.len(),"unequal_count":map.unequal_entries().len(),
            "source":"rustre_fuzz_afl::CmplogMap::colorize_mutations"
        }).to_string()))
    }
}

pub struct FuzzAflQueueScoreTool;
impl FuzzAflQueueScoreTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_queue_score".to_string(),
            description: "Compute AFL power-schedule score via rustre_fuzz_afl::AflQueueEntry::score.".to_string(),
            input_schema: json!({"type":"object","properties":{"coverage_bits":{"type":"integer"},"exec_time_us":{"type":"integer"},"selected_count":{"type":"integer"},"interesting_count":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflQueueScoreTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let coverage_bits = args.get("coverage_bits").and_then(Value::as_u64).unwrap_or(1) as u32;
        let mut e = rustre_fuzz_afl::AflQueueEntry::new(0, vec![], coverage_bits);
        e.exec_time_us = args.get("exec_time_us").and_then(Value::as_u64).unwrap_or(0);
        e.selected_count = args.get("selected_count").and_then(Value::as_u64).unwrap_or(0);
        e.interesting_count = args.get("interesting_count").and_then(Value::as_u64).unwrap_or(0);
        let score = e.score();
        Ok(ToolResult::text(json!({
            "score": if score.is_finite() { serde_json::Value::from(score) } else { serde_json::Value::from("inf") },
            "coverage_bits":coverage_bits,
            "source":"rustre_fuzz_afl::AflQueueEntry::score"
        }).to_string()))
    }
}

pub struct FuzzAflHavocMutateTool;
impl FuzzAflHavocMutateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_havoc_mutate".to_string(),
            description: "Apply AFL HavocMutator via rustre_fuzz_afl::HavocMutator.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"},"seed":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflHavocMutateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_fuzz_afl::Mutator;
        let data = args_to_bytes(&args)?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(0xdead_beef);
        let mut rng = rustre_fuzz_afl::XorShiftRng::new(seed);
        let out = rustre_fuzz_afl::HavocMutator.mutate(&data, &mut rng);
        Ok(ToolResult::text(json!({"len":out.len(),"hex":hex_encode(&out),"source":"rustre_fuzz_afl::HavocMutator"}).to_string()))
    }
}

pub struct FuzzAflBitFlipMutateTool;
impl FuzzAflBitFlipMutateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_bit_flip_mutate".to_string(),
            description: "Apply AFL BitFlipMutator via rustre_fuzz_afl::BitFlipMutator.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"},"seed":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflBitFlipMutateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_fuzz_afl::Mutator;
        let data = args_to_bytes(&args)?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(1);
        let mut rng = rustre_fuzz_afl::XorShiftRng::new(seed);
        let out = rustre_fuzz_afl::BitFlipMutator.mutate(&data, &mut rng);
        Ok(ToolResult::text(json!({"hex":hex_encode(&out),"source":"rustre_fuzz_afl::BitFlipMutator"}).to_string()))
    }
}

pub struct FuzzAflArithMutateTool;
impl FuzzAflArithMutateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_arith_mutate".to_string(),
            description: "Apply AFL ArithmeticMutator via rustre_fuzz_afl::ArithmeticMutator.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"},"seed":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflArithMutateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_fuzz_afl::Mutator;
        let data = args_to_bytes(&args)?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(1);
        let mut rng = rustre_fuzz_afl::XorShiftRng::new(seed);
        let out = rustre_fuzz_afl::ArithmeticMutator.mutate(&data, &mut rng);
        Ok(ToolResult::text(json!({"hex":hex_encode(&out),"source":"rustre_fuzz_afl::ArithmeticMutator"}).to_string()))
    }
}

pub struct FuzzAflBucketTool;
impl FuzzAflBucketTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_afl_bucket_hits".to_string(),
            description: "Apply AFL hit-count bucketing via rustre_fuzz_afl::AflShmCoverage::bucketed.".to_string(),
            input_schema: json!({"type":"object","required":["counts"],"properties":{"counts":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzAflBucketTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("counts").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'counts'".into()))?;
        let bytes: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|n| n.min(255) as u8)).collect();
        let mut cov = rustre_fuzz_afl::AflShmCoverage::new(bytes.len().max(1));
        for (i, b) in bytes.iter().enumerate() { cov.bitmap[i] = *b; }
        let bucketed = cov.bucketed();
        Ok(ToolResult::text(json!({"bucketed":bucketed,"source":"rustre_fuzz_afl::AflShmCoverage::bucketed"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzAflDictLoadTool::definition(), Box::new(FuzzAflDictLoadTool)),
        (FuzzAflStatsParseTool::definition(), Box::new(FuzzAflStatsParseTool)),
        (FuzzAflStageBitFlip2Tool::definition(), Box::new(FuzzAflStageBitFlip2Tool)),
        (FuzzAflStageByteFlip1Tool::definition(), Box::new(FuzzAflStageByteFlip1Tool)),
        (FuzzAflStageInteresting8Tool::definition(), Box::new(FuzzAflStageInteresting8Tool)),
        (FuzzAflStageBitFlip1Tool::definition(), Box::new(FuzzAflStageBitFlip1Tool)),
        (FuzzAflStageBitFlip4Tool::definition(), Box::new(FuzzAflStageBitFlip4Tool)),
        (FuzzAflStageArith8Tool::definition(), Box::new(FuzzAflStageArith8Tool)),
        (FuzzAflStageArith16Tool::definition(), Box::new(FuzzAflStageArith16Tool)),
        (FuzzAflStageArith32Tool::definition(), Box::new(FuzzAflStageArith32Tool)),
        (FuzzAflStageInteresting16Tool::definition(), Box::new(FuzzAflStageInteresting16Tool)),
        (FuzzAflStageInteresting32Tool::definition(), Box::new(FuzzAflStageInteresting32Tool)),
        (FuzzAflStageSpliceTool::definition(), Box::new(FuzzAflStageSpliceTool)),
        (FuzzAflBitmapSummaryTool::definition(), Box::new(FuzzAflBitmapSummaryTool)),
        (FuzzAflStatsSerializeTool::definition(), Box::new(FuzzAflStatsSerializeTool)),
        (FuzzAflDictInfoTool::definition(), Box::new(FuzzAflDictInfoTool)),
        (FuzzAflCmplogColorizeTool::definition(), Box::new(FuzzAflCmplogColorizeTool)),
        (FuzzAflQueueScoreTool::definition(), Box::new(FuzzAflQueueScoreTool)),
        (FuzzAflHavocMutateTool::definition(), Box::new(FuzzAflHavocMutateTool)),
        (FuzzAflBitFlipMutateTool::definition(), Box::new(FuzzAflBitFlipMutateTool)),
        (FuzzAflArithMutateTool::definition(), Box::new(FuzzAflArithMutateTool)),
        (FuzzAflBucketTool::definition(), Box::new(FuzzAflBucketTool)),
    ]
}
