//! MCP wrappers for the rustre-fuzz crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};
use crate::wire_tools::pe_editor_hex_decode;

pub struct FuzzFnv1aTool;

pub struct FuzzRankSeedsByPriorityTool;

pub struct FuzzComputePriorityTool;

pub struct FuzzXorshift64Tool;

pub struct FuzzGenerateCorpusTool;

pub struct FuzzFnv1aHashV2Tool;
impl FuzzFnv1aHashV2Tool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_fnv1a_hash_v2".to_string(),
            description: "Compute FNV-1a 64-bit hash of a hex-encoded byte buffer via rustre_fuzz::fnv1a.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzFnv1aHashV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..(i+2).min(hex.len())],16).ok()).collect();
        let h = rustre_fuzz::fnv1a(&data);
        Ok(ToolResult::text(json!({"hash":h,"hash_hex":format!("{:016x}",h),"len":data.len(),"source":"rustre_fuzz::fnv1a"}).to_string()))
    }
}

pub struct FuzzMutationStrategiesListTool;
impl FuzzMutationStrategiesListTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_mutation_strategies_list".to_string(),
            description: "List all rustre_fuzz::MutationStrategy variants by name.".to_string(),
            input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzMutationStrategiesListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<&'static str> = rustre_fuzz::MutationStrategy::all().iter().map(|s| s.name()).collect();
        Ok(ToolResult::text(json!({"strategies":names,"count":names.len(),"source":"rustre_fuzz::MutationStrategy::all"}).to_string()))
    }
}

pub struct FuzzMutateInputTool;
impl FuzzMutateInputTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_mutate_input".to_string(),
            description: "Apply a rustre_fuzz::MutationStrategy to a hex input and return the mutated bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"strategy":{"type":"string"},"seed":{"type":"integer"}},"required":["data_hex","strategy"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzMutateInputTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..(i+2).min(hex.len())],16).ok()).collect();
        let strategy_str = args.get("strategy").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'strategy'".into()))?;
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(0xdead_beef);
        use rustre_fuzz::MutationStrategy as M;
        let strat = match strategy_str {
            "bit_flip" => M::BitFlip, "byte_flip" => M::ByteFlip, "arithmetic" => M::Arithmetic,
            "interesting_value" => M::InterestingValue, "dictionary" => M::Dictionary,
            "splice" => M::Splice, "havoc" => M::Havoc, "insert" => M::Insert,
            "delete" => M::Delete, "shuffle" => M::Shuffle, "repeat" => M::Repeat,
            "xor_block" => M::XorBlock, "reverse" => M::Reverse,
            _ => return Err(McpError::InvalidParams(format!("unknown strategy: {strategy_str}"))),
        };
        let mut engine = rustre_fuzz::MutationEngine::with_seed(seed);
        let out = engine.mutate(&data, strat);
        Ok(ToolResult::text(json!({"strategy":strat.name(),"input_len":data.len(),"output_len":out.len(),"output_hex":hex_encode(&out),"source":"rustre_fuzz::MutationEngine::mutate"}).to_string()))
    }
}

pub struct FuzzSpliceInputsTool;
impl FuzzSpliceInputsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_splice_inputs".to_string(),
            description: "Splice two hex inputs at a random crossover point via rustre_fuzz::MutationEngine::splice_two.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"},"seed":{"type":"integer"}},"required":["a_hex","b_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzSpliceInputsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a_hex = args.get("a_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("a_hex".into()))?;
        let b_hex = args.get("b_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("b_hex".into()))?;
        let a: Vec<u8> = (0..a_hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&a_hex[i..(i+2).min(a_hex.len())],16).ok()).collect();
        let b: Vec<u8> = (0..b_hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&b_hex[i..(i+2).min(b_hex.len())],16).ok()).collect();
        let seed = args.get("seed").and_then(Value::as_u64).unwrap_or(0x1234_5678);
        let mut eng = rustre_fuzz::MutationEngine::with_seed(seed);
        let out = eng.splice_two(&a, &b);
        Ok(ToolResult::text(json!({"a_len":a.len(),"b_len":b.len(),"output_len":out.len(),"output_hex":hex_encode(&out),"source":"rustre_fuzz::MutationEngine::splice_two"}).to_string()))
    }
}

pub struct FuzzDictionaryLoadTextTool;
impl FuzzDictionaryLoadTextTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_dictionary_load_text".to_string(),
            description: "Parse a dictionary text (bare/quoted/x\"..\" hex lines) via rustre_fuzz::Dictionary::load_from_text.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzDictionaryLoadTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let mut dict = rustre_fuzz::Dictionary::new();
        let n = dict.load_from_text(text).map_err(|e| McpError::InvalidParams(format!("{e}")))?;
        let tokens: Vec<String> = dict.entries.iter().map(|t| hex_encode(t)).collect();
        Ok(ToolResult::text(json!({"count":n,"tokens_hex":tokens,"source":"rustre_fuzz::Dictionary::load_from_text"}).to_string()))
    }
}

pub struct FuzzCoverageMapUpdateTool;
impl FuzzCoverageMapUpdateTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_coverage_map_update".to_string(),
            description: "Create a rustre_fuzz::CoverageMap, merge a hex bitmap, return new-bit stats.".to_string(),
            input_schema: json!({"type":"object","properties":{"size":{"type":"integer"},"bits_hex":{"type":"string"}},"required":["bits_hex"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzCoverageMapUpdateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("bits_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'bits_hex'".into()))?;
        let bits: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..(i+2).min(hex.len())],16).ok()).collect();
        let size = args.get("size").and_then(Value::as_u64).map(|v| v as usize).unwrap_or(bits.len().max(1));
        let mut map = rustre_fuzz::CoverageMap::new(size);
        let newly = map.update(&bits);
        Ok(ToolResult::text(json!({
            "newly_set":newly,"total_bits_set":map.total_bits_set(),"hot_edges":map.hot_edges(),
            "coverage_hash":format!("{:016x}",map.hash()),"source":"rustre_fuzz::CoverageMap::update"
        }).to_string()))
    }
}

pub struct FuzzRngGenerateTool;
impl FuzzRngGenerateTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_rng_generate".to_string(),
            description: "Generate N u64 values from rustre_fuzz::FuzzRng (xorshift-64) with a seed.".to_string(),
            input_schema: json!({"type":"object","properties":{"seed":{"type":"integer"},"count":{"type":"integer"}},"required":["seed"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzRngGenerateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seed = args.get("seed").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seed'".into()))?;
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(8).min(1024) as usize;
        let mut rng = rustre_fuzz::FuzzRng::new(seed);
        let values: Vec<u64> = (0..count).map(|_| rng.next_u64()).collect();
        Ok(ToolResult::text(json!({"seed":seed,"count":count,"values":values,"source":"rustre_fuzz::FuzzRng::next_u64"}).to_string()))
    }
}

pub struct FuzzCrashDeduplicatorSubmitTool;
impl FuzzCrashDeduplicatorSubmitTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_crash_dedup_submit".to_string(),
            description: "Submit a list of crashes to rustre_fuzz::CrashDeduplicator and return unique count and records.".to_string(),
            input_schema: json!({"type":"object","properties":{"crashes":{"type":"array"}},"required":["crashes"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzCrashDeduplicatorSubmitTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("crashes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("crashes".into()))?;
        let mut dedup = rustre_fuzz::CrashDeduplicator::new();
        let mut submitted = 0usize;
        for c in arr {
            let input_hex = c.get("input_hex").and_then(Value::as_str).unwrap_or("");
            let input: Vec<u8> = (0..input_hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&input_hex[i..(i+2).min(input_hex.len())],16).ok()).collect();
            let signal = c.get("signal").and_then(Value::as_i64).unwrap_or(11) as i32;
            let fault = c.get("fault_addr").and_then(Value::as_u64);
            let cov = c.get("coverage_hash").and_then(Value::as_u64).unwrap_or(0);
            if dedup.submit(input, signal, fault, cov) { submitted += 1; }
        }
        let records: Vec<Value> = dedup.iter().map(|r| json!({"id":r.id,"signal":r.signal,"occurrences":r.occurrence_count,"description":r.description})).collect();
        Ok(ToolResult::text(json!({"submitted":arr.len(),"new_unique":submitted,"total_unique":dedup.unique_count(),"records":records,"source":"rustre_fuzz::CrashDeduplicator"}).to_string()))
    }
}

pub struct FuzzCorpusPruneTool;
impl FuzzCorpusPruneTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_corpus_prune".to_string(),
            description: "Build a rustre_fuzz::Corpus from inputs with coverage_bits and prune below threshold.".to_string(),
            input_schema: json!({"type":"object","properties":{"inputs":{"type":"array"},"min_coverage_bits":{"type":"integer"}},"required":["inputs","min_coverage_bits"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzCorpusPruneTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("inputs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("inputs".into()))?;
        let min_bits = args.get("min_coverage_bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'min_coverage_bits'".into()))? as u32;
        let mut corpus = rustre_fuzz::Corpus::new();
        for (i, v) in arr.iter().enumerate() {
            let bits = v.get("coverage_bits").and_then(Value::as_u64).unwrap_or(0) as u32;
            let hash = v.get("hash").and_then(Value::as_u64).unwrap_or(i as u64);
            let parent = v.get("parent").and_then(Value::as_u64);
            let mut inp = rustre_fuzz::FuzzInput::new(i as u64, vec![]);
            inp.parent = parent;
            let meta = rustre_fuzz::CorpusMeta::new(hash, bits, std::time::Duration::from_micros(0));
            corpus.add_input(inp, meta);
        }
        let before = corpus.len();
        let removed = corpus.prune(min_bits);
        Ok(ToolResult::text(json!({"before":before,"removed":removed,"after":corpus.len(),"unique_hashes":corpus.unique_coverage_hashes(),"source":"rustre_fuzz::Corpus::prune"}).to_string()))
    }
}

pub struct FuzzStatsCrashRateTool;
impl FuzzStatsCrashRateTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "fuzz_stats_crash_rate".to_string(),
            description: "Compute crash_rate for given executions/crashes using rustre_fuzz::FuzzerStats.".to_string(),
            input_schema: json!({"type":"object","properties":{"executions":{"type":"integer"},"crashes":{"type":"integer"}},"required":["executions","crashes"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for FuzzStatsCrashRateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let execs = args.get("executions").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'executions'".into()))?;
        let crashes = args.get("crashes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'crashes'".into()))?;
        let mut s = rustre_fuzz::FuzzerStats::new();
        s.executions = execs;
        s.crashes = crashes;
        Ok(ToolResult::text(json!({"executions":execs,"crashes":crashes,"crash_rate":s.crash_rate(),"source":"rustre_fuzz::FuzzerStats::crash_rate"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzFnv1aTool::definition(), Box::new(FuzzFnv1aTool)),
        (FuzzRankSeedsByPriorityTool::definition(), Box::new(FuzzRankSeedsByPriorityTool)),
        (FuzzComputePriorityTool::definition(), Box::new(FuzzComputePriorityTool)),
        (FuzzXorshift64Tool::definition(), Box::new(FuzzXorshift64Tool)),
        (FuzzGenerateCorpusTool::definition(), Box::new(FuzzGenerateCorpusTool)),
        (FuzzFnv1aHashV2Tool::definition(), Box::new(FuzzFnv1aHashV2Tool)),
        (FuzzMutationStrategiesListTool::definition(), Box::new(FuzzMutationStrategiesListTool)),
        (FuzzMutateInputTool::definition(), Box::new(FuzzMutateInputTool)),
        (FuzzSpliceInputsTool::definition(), Box::new(FuzzSpliceInputsTool)),
        (FuzzDictionaryLoadTextTool::definition(), Box::new(FuzzDictionaryLoadTextTool)),
        (FuzzCoverageMapUpdateTool::definition(), Box::new(FuzzCoverageMapUpdateTool)),
        (FuzzRngGenerateTool::definition(), Box::new(FuzzRngGenerateTool)),
        (FuzzCrashDeduplicatorSubmitTool::definition(), Box::new(FuzzCrashDeduplicatorSubmitTool)),
        (FuzzCorpusPruneTool::definition(), Box::new(FuzzCorpusPruneTool)),
        (FuzzStatsCrashRateTool::definition(), Box::new(FuzzStatsCrashRateTool)),
    ]
}

pub struct FuzzNetDecodeFrameU32BeToolExt;
impl FuzzNetDecodeFrameU32BeToolExt {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_decode_frame_u32_be_ext".to_string(),
            description: "Decode a u32-BE length-prefixed frame via rustre_fuzz_net::decode_frame_u32_be.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {"data_hex": {"type": "string"}},
                "required": ["data_hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetDecodeFrameU32BeToolExt {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data_hex = args.get("data_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(data_hex)?;
        match rustre_fuzz_net::decode_frame_u32_be(&data) {
            Some((consumed, payload)) => Ok(ToolResult::text(json!({
                "consumed": consumed,
                "payload_len": payload.len(),
                "source": "rustre_fuzz_net::decode_frame_u32_be",
            }).to_string())),
            None => Ok(ToolResult::text(json!({
                "consumed": 0, "payload_len": 0, "incomplete": true,
                "source": "rustre_fuzz_net::decode_frame_u32_be",
            }).to_string())),
        }
    }
}
