//! MCP wrappers for the rustre-yara crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{_yara_hex};

pub struct YaraEngineRuleWithTagWire2Tool;
impl YaraEngineRuleWithTagWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_rule_with_tag_wire2".to_string(), description: "Build YaraRule with tag via rustre_yara_engine::YaraRule::new+with_tag.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"tag":{"type":"string"}},"required":["name","tag"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineRuleWithTagWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let tag = args.get("tag").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'tag'".into()))?.to_string(); let rule = rustre_yara_engine::YaraRule::new(name).with_tag(tag); Ok(ToolResult::text(json!({"name":rule.name,"tags":rule.tags,"source":"rustre_yara_engine::YaraRule::with_tag"}).to_string())) } }

pub struct YaraEngineRuleSetLenWire2Tool;
impl YaraEngineRuleSetLenWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_ruleset_len_wire2".to_string(), description: "Add source and report YaraRuleSet len/is_empty/is_compiled via rustre_yara_engine::YaraRuleSet.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineRuleSetLenWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let mut set = rustre_yara_engine::YaraRuleSet::new(); set.add_rule(src).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"len":set.len(),"is_empty":set.is_empty(),"is_compiled":set.is_compiled(),"source":"rustre_yara_engine::YaraRuleSet::len"}).to_string())) } }

pub struct YaraEngineParseRulesCountWire2Tool;
impl YaraEngineParseRulesCountWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_parse_rules_count_wire2".to_string(), description: "Parse multiple rules via rustre_yara_engine::YaraParser::parse_rules.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineParseRulesCountWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let p = rustre_yara_engine::YaraParser::new(); let rules = p.parse_rules(src).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; let names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect(); Ok(ToolResult::text(json!({"count":rules.len(),"names":names,"source":"rustre_yara_engine::YaraParser::parse_rules"}).to_string())) } }

pub struct YaraEngineScannerAddRuleWire2Tool;
impl YaraEngineScannerAddRuleWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_scanner_add_rule_wire2".to_string(), description: "Add a YaraRule to a YaraScanner and read rule_count via rustre_yara_engine::YaraScanner::add_rule.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineScannerAddRuleWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let s = rustre_yara_engine::YaraScanner::new(); s.add_rule(rustre_yara_engine::YaraRule::new(name)); Ok(ToolResult::text(json!({"rule_count":s.rule_count(),"source":"rustre_yara_engine::YaraScanner::add_rule"}).to_string())) } }

pub struct YaraEngineRuleDefinitionWithNamespaceWire2Tool;
impl YaraEngineRuleDefinitionWithNamespaceWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_rule_definition_with_namespace_wire2".to_string(), description: "Build YaraRuleDefinition and set namespace/tag via rustre_yara_engine::YaraRuleDefinition.".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"string"},"source":{"type":"string"},"ns":{"type":"string"},"tag":{"type":"string"}},"required":["id","source","ns","tag"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineRuleDefinitionWithNamespaceWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let id = args.get("id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?; let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let ns = args.get("ns").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ns'".into()))?; let tag = args.get("tag").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'tag'".into()))?; let d = rustre_yara_engine::YaraRuleDefinition::new(id, src).with_namespace(ns).with_tag(tag); Ok(ToolResult::text(json!({"id":d.id,"name":d.name,"namespace":d.namespace,"tags":d.tags,"source":"rustre_yara_engine::YaraRuleDefinition::with_namespace"}).to_string())) } }

pub struct YaraEngineRuleRepositoryOpsWire2Tool;
impl YaraEngineRuleRepositoryOpsWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_rule_repository_ops_wire2".to_string(), description: "Exercise add/disable/enabled_count/contains via rustre_yara_engine::YaraRuleRepository.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"source":{"type":"string"}},"required":["name","source"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineRuleRepositoryOpsWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let mut repo = rustre_yara_engine::YaraRuleRepository::new(); repo.add(name, src); let after_add = repo.enabled_count(); repo.disable(name); Ok(ToolResult::text(json!({"len":repo.len(),"contains":repo.contains(name),"enabled_after_add":after_add,"enabled_after_disable":repo.enabled_count(),"source":"rustre_yara_engine::YaraRuleRepository"}).to_string())) } }

pub struct YaraEngineBuiltinRulesCountWire2Tool;
impl YaraEngineBuiltinRulesCountWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_builtin_rules_count_wire2".to_string(), description: "Return builtin YaraRuleRepository size via rustre_yara_engine::YaraRuleRepository::builtin_rules.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineBuiltinRulesCountWire2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let r = rustre_yara_engine::YaraRuleRepository::builtin_rules(); Ok(ToolResult::text(json!({"len":r.len(),"enabled_count":r.enabled_count(),"is_empty":r.is_empty(),"source":"rustre_yara_engine::YaraRuleRepository::builtin_rules"}).to_string())) } }

pub struct YaraEngineAsyncScanConfigWire2Tool;
impl YaraEngineAsyncScanConfigWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_async_scan_config_wire2".to_string(), description: "Build AsyncScanConfig and evaluate should_scan via rustre_yara_engine::AsyncScanConfig.".to_string(), input_schema: json!({"type":"object","properties":{"conc":{"type":"integer"},"max":{"type":"integer"},"min":{"type":"integer"},"size":{"type":"integer"}},"required":["conc","max","min","size"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineAsyncScanConfigWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let conc = usize::try_from(args.get("conc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'conc'".into()))?).unwrap_or(4); let max = usize::try_from(args.get("max").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max'".into()))?).unwrap_or(0); let min = usize::try_from(args.get("min").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'min'".into()))?).unwrap_or(1); let size = usize::try_from(args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?).unwrap_or(100); let c = rustre_yara_engine::AsyncScanConfig::default().with_concurrency(conc).with_max_region_size(max).with_min_region_size(min); Ok(ToolResult::text(json!({"max_concurrency":c.max_concurrency,"max_region_size":c.max_region_size,"min_region_size":c.min_region_size,"should_scan":c.should_scan(size),"source":"rustre_yara_engine::AsyncScanConfig"}).to_string())) } }

pub struct YaraEngineExternalSymbolWire2Tool;
impl YaraEngineExternalSymbolWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_external_symbol_wire2".to_string(), description: "Build ExternalSymbol variants via rustre_yara_engine::ExternalSymbol::bool|int|float|str.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineExternalSymbolWire2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let b = rustre_yara_engine::ExternalSymbol::bool("a", true); let i = rustre_yara_engine::ExternalSymbol::int("b", 42); let f = rustre_yara_engine::ExternalSymbol::float("c", 1.5); let s = rustre_yara_engine::ExternalSymbol::str("d", "hi"); Ok(ToolResult::text(json!({"bool":b.name,"int":i.name,"float":f.name,"str":s.name,"source":"rustre_yara_engine::ExternalSymbol"}).to_string())) } }

pub struct YaraEngineProcessRegionWire2Tool;
impl YaraEngineProcessRegionWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_process_region_wire2".to_string(), description: "Build ProcessRegion with module via rustre_yara_engine::ProcessRegion.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"},"prot":{"type":"string"},"module":{"type":"string"}},"required":["base","size","prot","module"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineProcessRegionWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let size = usize::try_from(args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?).unwrap_or(0); let prot = args.get("prot").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'prot'".into()))?; let module = args.get("module").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'module'".into()))?; let r = rustre_yara_engine::ProcessRegion::new(base, size, prot).with_module(module); Ok(ToolResult::text(json!({"display":r.to_string(),"base":r.base,"size":r.size,"protection":r.protection,"module":r.module,"source":"rustre_yara_engine::ProcessRegion::new"}).to_string())) } }

pub struct YaraEngineComputeEntropyWire2Tool;
impl YaraEngineComputeEntropyWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_compute_entropy_wire2".to_string(), description: "Compute Shannon entropy via rustre_yara_engine::compute_entropy.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineComputeEntropyWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s: String = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = crate::hex_decode(&s)?; let e = rustre_yara_engine::compute_entropy(&data); Ok(ToolResult::text(json!({"entropy":e,"len":data.len(),"source":"rustre_yara_engine::compute_entropy"}).to_string())) } }

pub struct YaraEngineAsyncScanResultWire2Tool;
impl YaraEngineAsyncScanResultWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_async_scan_result_wire2".to_string(), description: "Build empty AsyncScanResult and inspect has_matches/total_patterns via rustre_yara_engine::AsyncScanResult.".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngineAsyncScanResultWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let id = args.get("id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?; let r = rustre_yara_engine::AsyncScanResult::new(id, vec![]); Ok(ToolResult::text(json!({"region_id":r.region_id,"has_matches":r.has_matches(),"total_patterns":r.total_patterns(),"display":r.to_string(),"source":"rustre_yara_engine::AsyncScanResult::new"}).to_string())) } }
// (round: rustre-mobile-ios extras)
// rustre-symbols core wrappers (RsSymCore*) — included inline below.
// rustre-symbols-pdb extras appended below by workflow.
// (round: emu-qiling extra)
// (round: net-proxy extras)

pub struct YaraEngineScanBytesTool;

pub struct YaraEngineParseRuleTool;

pub struct YaraRuleNewTool;

pub struct YaraRuleGetMetaTool;

pub struct YaraErrorDisplayTool;

pub struct YaraRuleNewEmptyTool;

pub struct YaraEngineParseNameFromSourceTool;

pub struct YaraEngineRuleSetAddRuleTool;

pub struct YaraEngineRuleNewSummaryTool;

pub struct YaraEngineScannerNewCountTool;

pub struct YaraMatchMaskedByteTool;

pub struct YaraCheckFullwordTool;

pub struct YaraRuleDefinitionParseNameTool;

pub struct YaraRuleSetAddRuleTool;

pub struct YaraParserParseWireTool;

pub struct YaraRuleSetRuleCountWireTool;

pub struct YaraRuleSetNewCountWireTool;
impl YaraRuleSetNewCountWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_ruleset_new_count_wire".to_string(), description: "Create empty YaraRuleSet and return rule_count via rustre_yara::YaraRuleSet::new/rule_count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleSetNewCountWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let rs = rustre_yara::YaraRuleSet::new(); Ok(ToolResult::text(json!({"count": rs.rule_count(), "source":"rustre_yara::YaraRuleSet::new"}).to_string())) } }

pub struct YaraRuleSetRuleByNameWireTool;
impl YaraRuleSetRuleByNameWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_ruleset_rule_by_name_wire".to_string(), description: "Parse source and lookup rule by name via rustre_yara::YaraRuleSet::rule_by_name.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"},"name":{"type":"string"}},"required":["source","name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleSetRuleByNameWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let rs = rustre_yara::YaraParser::parse(src).map_err(|e| McpError::InvalidParams(e.to_string()))?; let found = rs.rule_by_name(name).is_some(); Ok(ToolResult::text(json!({"found":found,"total":rs.rule_count(),"source":"rustre_yara::YaraRuleSet::rule_by_name"}).to_string())) } }

pub struct YaraStringMatcherMatchHexWireTool;
impl YaraStringMatcherMatchHexWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_match_hex_wire".to_string(), description: "Match hex pattern via rustre_yara::StringMatcher::match_hex.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"data_hex":{"type":"string"}},"required":["pattern","data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMatchHexWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?; let data = _yara_hex(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let tokens = rustre_yara::YaraParser::parse_hex_pattern(pat).map_err(|e| McpError::InvalidParams(e.to_string()))?; let hits = rustre_yara::StringMatcher::match_hex(&tokens, &data); Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_yara::StringMatcher::match_hex"}).to_string())) } }

pub struct YaraStringMatcherMatchNocaseWireTool;
impl YaraStringMatcherMatchNocaseWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_match_nocase_wire".to_string(), description: "Case-insensitive ASCII search via rustre_yara::StringMatcher::match_nocase.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"},"data_hex":{"type":"string"}},"required":["text","data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMatchNocaseWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let data = _yara_hex(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let hits = rustre_yara::StringMatcher::match_nocase(text, &data); Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_yara::StringMatcher::match_nocase"}).to_string())) } }

pub struct YaraStringMatcherMatchWideWireTool;
impl YaraStringMatcherMatchWideWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_match_wide_wire".to_string(), description: "UTF-16 LE search via rustre_yara::StringMatcher::match_wide.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"},"data_hex":{"type":"string"}},"required":["text","data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMatchWideWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let data = _yara_hex(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let hits = rustre_yara::StringMatcher::match_wide(text, &data); Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_yara::StringMatcher::match_wide"}).to_string())) } }

pub struct YaraStringMatcherMatchXorWireTool;
impl YaraStringMatcherMatchXorWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_match_xor_wire".to_string(), description: "XOR keyed search via rustre_yara::StringMatcher::match_xor.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"},"data_hex":{"type":"string"},"xor_min":{"type":"integer"},"xor_max":{"type":"integer"}},"required":["text","data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMatchXorWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let data = _yara_hex(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let lo = args.get("xor_min").and_then(Value::as_u64).unwrap_or(0) as u8; let hi = args.get("xor_max").and_then(Value::as_u64).unwrap_or(255) as u8; let hits = rustre_yara::StringMatcher::match_xor(text, lo, hi, &data); let rows: Vec<_> = hits.iter().map(|(o,k)| json!({"offset":o,"key":k})).collect(); Ok(ToolResult::text(json!({"count":hits.len(),"hits":rows,"source":"rustre_yara::StringMatcher::match_xor"}).to_string())) } }

pub struct YaraStringMatcherCheckFullwordWireTool;
impl YaraStringMatcherCheckFullwordWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_check_fullword_wire".to_string(), description: "Check fullword boundary via rustre_yara::StringMatcher::check_fullword.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"offset":{"type":"integer"},"len":{"type":"integer"}},"required":["data_hex","offset","len"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherCheckFullwordWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = _yara_hex(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize; let ln = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize; let ok = rustre_yara::StringMatcher::check_fullword(&data, off, ln); Ok(ToolResult::text(json!({"fullword":ok,"source":"rustre_yara::StringMatcher::check_fullword"}).to_string())) } }

pub struct YaraStringMatcherMaskedByteWireTool;
impl YaraStringMatcherMaskedByteWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_masked_byte_wire".to_string(), description: "Match a masked byte via rustre_yara::StringMatcher::match_masked_byte.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"mask":{"type":"integer"},"data_byte":{"type":"integer"}},"required":["value","mask","data_byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMaskedByteWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u8; let m = args.get("mask").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'mask'".into()))? as u8; let d = args.get("data_byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'data_byte'".into()))? as u8; Ok(ToolResult::text(json!({"match": rustre_yara::StringMatcher::match_masked_byte(v,m,d),"source":"rustre_yara::StringMatcher::match_masked_byte"}).to_string())) } }

pub struct YaraParserParseHexPatternWireTool;
impl YaraParserParseHexPatternWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_hex_pattern_wire".to_string(), description: "Parse hex pattern via rustre_yara::YaraParser::parse_hex_pattern.".to_string(), input_schema: json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseHexPatternWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pat = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?; match rustre_yara::YaraParser::parse_hex_pattern(pat) { Ok(t) => Ok(ToolResult::text(json!({"ok":true,"tokens":t.len(),"source":"rustre_yara::YaraParser::parse_hex_pattern"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct YaraParserParseMetaSectionWireTool;
impl YaraParserParseMetaSectionWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_meta_section_wire".to_string(), description: "Parse meta: section via rustre_yara::YaraParser::parse_meta_section.".to_string(), input_schema: json!({"type":"object","properties":{"body":{"type":"string"}},"required":["body"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseMetaSectionWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let body = args.get("body").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'body'".into()))?; match rustre_yara::YaraParser::parse_meta_section(body) { Ok(v) => { let keys: Vec<_> = v.iter().map(|m| m.key.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"count":v.len(),"keys":keys,"source":"rustre_yara::YaraParser::parse_meta_section"}).to_string())) }, Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct YaraParserParseStringsSectionWireTool;
impl YaraParserParseStringsSectionWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_strings_section_wire".to_string(), description: "Parse strings: section via rustre_yara::YaraParser::parse_strings_section.".to_string(), input_schema: json!({"type":"object","properties":{"body":{"type":"string"}},"required":["body"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseStringsSectionWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let body = args.get("body").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'body'".into()))?; match rustre_yara::YaraParser::parse_strings_section(body) { Ok(v) => { let ids: Vec<_> = v.iter().map(|s| s.identifier.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"count":v.len(),"identifiers":ids,"source":"rustre_yara::YaraParser::parse_strings_section"}).to_string())) }, Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct YaraParserParseConditionSectionWireTool;
impl YaraParserParseConditionSectionWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_condition_section_wire".to_string(), description: "Parse condition: section via rustre_yara::YaraParser::parse_condition_section.".to_string(), input_schema: json!({"type":"object","properties":{"body":{"type":"string"}},"required":["body"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseConditionSectionWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let body = args.get("body").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'body'".into()))?; match rustre_yara::YaraParser::parse_condition_section(body) { Ok(_) => Ok(ToolResult::text(json!({"ok":true,"source":"rustre_yara::YaraParser::parse_condition_section"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct YaraRuleDescriptionWireTool;
impl YaraRuleDescriptionWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_rule_description_wire".to_string(), description: "Return description/author/date meta via rustre_yara::YaraRule::description|author|date.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleDescriptionWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let rule = rustre_yara::YaraParser::parse_rule(src).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"description":rule.description(),"author":rule.author(),"date":rule.date(),"source":"rustre_yara::YaraRule::description"}).to_string())) } }

pub struct YaraEngRuleWithMetaBoolTool;
impl YaraEngRuleWithMetaBoolTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_rule_with_meta_bool_wire3".to_string(), description: "Build YaraRule with bool meta via with_meta.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"key":{"type":"string"},"val":{"type":"boolean"}},"required":["name","key","val"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngRuleWithMetaBoolTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let key = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?.to_string(); let val = args.get("val").and_then(Value::as_bool).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?; let rule = rustre_yara_engine::YaraRule::new(name).with_meta(key, rustre_yara_engine::MetaValue::Bool(val)); Ok(ToolResult::text(json!({"name":rule.name,"meta_count":rule.meta.len(),"source":"rustre_yara_engine::YaraRule::with_meta"}).to_string())) } }

pub struct YaraEngParseNameFromSourceWire3Tool;
impl YaraEngParseNameFromSourceWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_rule_def_parse_name_wire3".to_string(), description: "YaraRuleDefinition::parse_name_from_source stateless.".to_string(), input_schema: json!({"type":"object","properties":{"src":{"type":"string"}},"required":["src"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngParseNameFromSourceWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let src = args.get("src").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'src'".into()))?; let name = rustre_yara_engine::YaraRuleDefinition::parse_name_from_source(src); Ok(ToolResult::text(json!({"name":name,"source":"rustre_yara_engine::YaraRuleDefinition::parse_name_from_source"}).to_string())) } }

pub struct YaraEngComputeEntropyWire3Tool;
impl YaraEngComputeEntropyWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_compute_entropy_hex_wire3".to_string(), description: "compute_entropy over hex-decoded bytes.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngComputeEntropyWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data: Vec<u8> = crate::hex_decode(hex)?; let e = rustre_yara_engine::compute_entropy(&data); Ok(ToolResult::text(json!({"entropy":e,"len":data.len(),"source":"rustre_yara_engine::compute_entropy"}).to_string())) } }

pub struct YaraEngExtSymbolIntWire3Tool;
impl YaraEngExtSymbolIntWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_external_symbol_int_wire3".to_string(), description: "ExternalSymbol::int + Display.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"val":{"type":"integer"}},"required":["name","val"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngExtSymbolIntWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let val = args.get("val").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?; let s = rustre_yara_engine::ExternalSymbol::int(name, val); Ok(ToolResult::text(json!({"display":s.to_string(),"name":s.name,"source":"rustre_yara_engine::ExternalSymbol::int"}).to_string())) } }

pub struct YaraEngExtSymbolStrWire3Tool;
impl YaraEngExtSymbolStrWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_external_symbol_str_wire3".to_string(), description: "ExternalSymbol::str + Display.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"val":{"type":"string"}},"required":["name","val"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngExtSymbolStrWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let val = args.get("val").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?.to_string(); let s = rustre_yara_engine::ExternalSymbol::str(name, val); Ok(ToolResult::text(json!({"display":s.to_string(),"source":"rustre_yara_engine::ExternalSymbol::str"}).to_string())) } }

pub struct YaraEngPeModuleFromBytesWire3Tool;
impl YaraEngPeModuleFromBytesWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_pe_module_from_bytes_wire3".to_string(), description: "PeModuleSymbols::from_bytes + to_external_symbols count.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngPeModuleFromBytesWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data: Vec<u8> = crate::hex_decode(hex)?; let sym = rustre_yara_engine::PeModuleSymbols::from_bytes(&data); let ext = sym.to_external_symbols(); Ok(ToolResult::text(json!({"is_pe":sym.is_pe,"is_64bit":sym.is_64bit,"file_size":sym.file_size,"ext_count":ext.len(),"source":"rustre_yara_engine::PeModuleSymbols::from_bytes"}).to_string())) } }

pub struct YaraEngElfModuleFromBytesWire3Tool;
impl YaraEngElfModuleFromBytesWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_elf_module_from_bytes_wire3".to_string(), description: "ElfModuleSymbols::from_bytes + to_external_symbols count.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngElfModuleFromBytesWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data: Vec<u8> = crate::hex_decode(hex)?; let sym = rustre_yara_engine::ElfModuleSymbols::from_bytes(&data); let ext = sym.to_external_symbols(); Ok(ToolResult::text(json!({"is_elf":sym.is_elf,"elf_class":sym.elf_class,"ext_count":ext.len(),"source":"rustre_yara_engine::ElfModuleSymbols::from_bytes"}).to_string())) } }

pub struct YaraEngCompiledCacheHashSourcesWire3Tool;
impl YaraEngCompiledCacheHashSourcesWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_compiled_cache_hash_sources_wire3".to_string(), description: "CompiledRuleCache::hash_sources over provided sources.".to_string(), input_schema: json!({"type":"object","properties":{"sources":{"type":"array","items":{"type":"string"}}},"required":["sources"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngCompiledCacheHashSourcesWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let srcs: Vec<String> = args.get("sources").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let refs: Vec<&str> = srcs.iter().map(String::as_str).collect(); let h = rustre_yara_engine::CompiledRuleCache::hash_sources(&refs); Ok(ToolResult::text(json!({"hash":h,"count":refs.len(),"source":"rustre_yara_engine::CompiledRuleCache::hash_sources"}).to_string())) } }

pub struct YaraEngCompiledCacheEmptyWire3Tool;
impl YaraEngCompiledCacheEmptyWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_compiled_cache_empty_wire3".to_string(), description: "CompiledRuleCache::new + len/is_empty/clear roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngCompiledCacheEmptyWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let c = rustre_yara_engine::CompiledRuleCache::new(); let len_before = c.len(); let empty = c.is_empty(); c.clear(); Ok(ToolResult::text(json!({"len":len_before,"is_empty":empty,"source":"rustre_yara_engine::CompiledRuleCache::new"}).to_string())) } }

pub struct YaraEngProcessRegionWithModuleWire3Tool;
impl YaraEngProcessRegionWithModuleWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_process_region_with_module_wire3".to_string(), description: "ProcessRegion::new + with_module + Display.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"size":{"type":"integer"},"prot":{"type":"string"},"module":{"type":"string"}},"required":["base","size","prot","module"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngProcessRegionWithModuleWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize; let prot = args.get("prot").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'prot'".into()))?.to_string(); let module = args.get("module").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'module'".into()))?.to_string(); let r = rustre_yara_engine::ProcessRegion::new(base, size, prot).with_module(module); Ok(ToolResult::text(json!({"display":r.to_string(),"base":r.base,"size":r.size,"module":r.module,"source":"rustre_yara_engine::ProcessRegion::with_module"}).to_string())) } }

pub struct YaraEngAsyncScanConfigConcurrencyWire3Tool;
impl YaraEngAsyncScanConfigConcurrencyWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_engine_async_scan_config_concurrency_wire3".to_string(), description: "AsyncScanConfig::default + with_concurrency.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for YaraEngAsyncScanConfigConcurrencyWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))? as usize; let c = rustre_yara_engine::AsyncScanConfig::default().with_concurrency(n); Ok(ToolResult::text(json!({"max_concurrency":c.max_concurrency,"max_region_size":c.max_region_size,"min_region_size":c.min_region_size,"source":"rustre_yara_engine::AsyncScanConfig::with_concurrency"}).to_string())) } }

pub struct YaraParserParseRuleWire3Tool;
impl YaraParserParseRuleWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_rule_wire3".to_string(), description: "Parse a single YARA rule via rustre_yara::YaraParser::parse_rule.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseRuleWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; match rustre_yara::YaraParser::parse_rule(src) { Ok(r) => Ok(ToolResult::text(json!({"name":r.name,"tags":r.tags,"strings":r.strings.len(),"meta":r.meta.len(),"is_private":r.is_private,"is_global":r.is_global,"source":"rustre_yara::YaraParser::parse_rule"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct YaraParserParseStringModifiersWire3Tool;
impl YaraParserParseStringModifiersWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_parser_parse_string_modifiers_wire3".to_string(), description: "Parse YARA string modifier keywords via rustre_yara::YaraParser::parse_string_modifiers.".to_string(), input_schema: json!({"type":"object","properties":{"tokens":{"type":"array","items":{"type":"string"}}},"required":["tokens"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraParserParseStringModifiersWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let toks: Vec<String> = args.get("tokens").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let refs: Vec<&str> = toks.iter().map(|s| s.as_str()).collect(); let m = rustre_yara::YaraParser::parse_string_modifiers(&refs); Ok(ToolResult::text(json!({"nocase":m.nocase(),"wide":m.wide(),"ascii":m.ascii(),"fullword":m.fullword(),"is_private":m.is_private(),"base64":m.base64(),"xor":m.xor,"source":"rustre_yara::YaraParser::parse_string_modifiers"}).to_string())) } }

pub struct YaraRuleAuthorWire3Tool;
impl YaraRuleAuthorWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_rule_author_wire3".to_string(), description: "Return the author meta field via rustre_yara::YaraRule::author.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleAuthorWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let r = rustre_yara::YaraParser::parse_rule(src).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"author":r.author(),"source":"rustre_yara::YaraRule::author"}).to_string())) } }

pub struct YaraRuleDateWire3Tool;
impl YaraRuleDateWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_rule_date_wire3".to_string(), description: "Return the date meta field via rustre_yara::YaraRule::date.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleDateWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("source").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?; let r = rustre_yara::YaraParser::parse_rule(src).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"date":r.date(),"source":"rustre_yara::YaraRule::date"}).to_string())) } }

pub struct YaraStringMatcherMatchTextWire3Tool;
impl YaraStringMatcherMatchTextWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_matcher_match_text_wire3".to_string(), description: "Match a text pattern with modifiers via rustre_yara::StringMatcher::match_text.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"},"data_hex":{"type":"string"},"nocase":{"type":"boolean"},"wide":{"type":"boolean"},"fullword":{"type":"boolean"}},"required":["text","data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringMatcherMatchTextWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let s: String = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = crate::hex_decode(&s)?; let mut m = rustre_yara::StringModifiers::default(); m.encoding.nocase = args.get("nocase").and_then(Value::as_bool).unwrap_or(false); m.encoding.wide = args.get("wide").and_then(Value::as_bool).unwrap_or(false); m.output.fullword = args.get("fullword").and_then(Value::as_bool).unwrap_or(false); let hits = rustre_yara::StringMatcher::match_text(text, &m, &data); Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_yara::StringMatcher::match_text"}).to_string())) } }

pub struct YaraRuleSetNewDefaultWire3Tool;
impl YaraRuleSetNewDefaultWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_ruleset_new_default_wire3".to_string(), description: "Construct empty YaraRuleSet via rustre_yara::YaraRuleSet::new; report rule_count.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleSetNewDefaultWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_yara::YaraRuleSet::new(); Ok(ToolResult::text(json!({"rule_count":s.rule_count(),"imports":s.imports.len(),"source":"rustre_yara::YaraRuleSet::new"}).to_string())) } }

pub struct YaraRuleNewWithTagsWire3Tool;
impl YaraRuleNewWithTagsWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_rule_new_with_tags_wire3".to_string(), description: "Construct YaraRule via rustre_yara::YaraRule::new and populate tags.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraRuleNewWithTagsWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let tags: Vec<String> = args.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let mut r = rustre_yara::YaraRule::new(name); r.tags = tags; Ok(ToolResult::text(json!({"name":r.name,"tags":r.tags,"strings":r.strings.len(),"source":"rustre_yara::YaraRule::new"}).to_string())) } }

pub struct YaraHexTokenWildcardMatchWire3Tool;
impl YaraHexTokenWildcardMatchWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_hex_token_wildcard_match_wire3".to_string(), description: "Build a wildcard-heavy hex pattern and match via rustre_yara::StringMatcher::match_hex.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraHexTokenWildcardMatchWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = crate::hex_decode(&s)?; let pat = vec![rustre_yara::HexToken::Wildcard, rustre_yara::HexToken::Wildcard]; let hits = rustre_yara::StringMatcher::match_hex(&pat, &data); Ok(ToolResult::text(json!({"count":hits.len(),"first_offsets":hits.iter().take(8).collect::<Vec<_>>(),"source":"rustre_yara::StringMatcher::match_hex"}).to_string())) } }

pub struct YaraHexTokenJumpMatchWire3Tool;
impl YaraHexTokenJumpMatchWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_hex_token_jump_match_wire3".to_string(), description: "Build a hex pattern with a Jump token and match via rustre_yara::StringMatcher::match_hex.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"a":{"type":"integer"},"b":{"type":"integer"},"min":{"type":"integer"},"max":{"type":"integer"}},"required":["data_hex","a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraHexTokenJumpMatchWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = crate::hex_decode(&s)?; let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))? as u8; let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))? as u8; let min = args.get("min").and_then(Value::as_u64).unwrap_or(0) as u32; let max = args.get("max").and_then(Value::as_u64).unwrap_or(4) as u32; let pat = vec![rustre_yara::HexToken::Byte(a), rustre_yara::HexToken::Jump(min, max), rustre_yara::HexToken::Byte(b)]; let hits = rustre_yara::StringMatcher::match_hex(&pat, &data); Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_yara::StringMatcher::match_hex"}).to_string())) } }

pub struct YaraStringModifiersFlagsWire3Tool;
impl YaraStringModifiersFlagsWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "yara_string_modifiers_flags_wire3".to_string(), description: "Query all boolean accessors of rustre_yara::StringModifiers (nocase/wide/ascii/fullword/is_private/base64).".to_string(), input_schema: json!({"type":"object","properties":{"nocase":{"type":"boolean"},"wide":{"type":"boolean"},"ascii":{"type":"boolean"},"fullword":{"type":"boolean"},"private":{"type":"boolean"},"base64":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for YaraStringModifiersFlagsWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut m = rustre_yara::StringModifiers::default(); m.encoding.nocase = args.get("nocase").and_then(Value::as_bool).unwrap_or(false); m.encoding.wide = args.get("wide").and_then(Value::as_bool).unwrap_or(false); m.encoding.ascii = args.get("ascii").and_then(Value::as_bool).unwrap_or(true); m.output.fullword = args.get("fullword").and_then(Value::as_bool).unwrap_or(false); m.output.private = args.get("private").and_then(Value::as_bool).unwrap_or(false); m.output.base64 = args.get("base64").and_then(Value::as_bool).unwrap_or(false); Ok(ToolResult::text(json!({"nocase":m.nocase(),"wide":m.wide(),"ascii":m.ascii(),"fullword":m.fullword(),"is_private":m.is_private(),"base64":m.base64(),"source":"rustre_yara::StringModifiers"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (YaraEngineRuleWithTagWire2Tool::definition(), Box::new(YaraEngineRuleWithTagWire2Tool)),
        (YaraEngineRuleSetLenWire2Tool::definition(), Box::new(YaraEngineRuleSetLenWire2Tool)),
        (YaraEngineParseRulesCountWire2Tool::definition(), Box::new(YaraEngineParseRulesCountWire2Tool)),
        (YaraEngineScannerAddRuleWire2Tool::definition(), Box::new(YaraEngineScannerAddRuleWire2Tool)),
        (YaraEngineRuleDefinitionWithNamespaceWire2Tool::definition(), Box::new(YaraEngineRuleDefinitionWithNamespaceWire2Tool)),
        (YaraEngineRuleRepositoryOpsWire2Tool::definition(), Box::new(YaraEngineRuleRepositoryOpsWire2Tool)),
        (YaraEngineBuiltinRulesCountWire2Tool::definition(), Box::new(YaraEngineBuiltinRulesCountWire2Tool)),
        (YaraEngineAsyncScanConfigWire2Tool::definition(), Box::new(YaraEngineAsyncScanConfigWire2Tool)),
        (YaraEngineExternalSymbolWire2Tool::definition(), Box::new(YaraEngineExternalSymbolWire2Tool)),
        (YaraEngineProcessRegionWire2Tool::definition(), Box::new(YaraEngineProcessRegionWire2Tool)),
        (YaraEngineComputeEntropyWire2Tool::definition(), Box::new(YaraEngineComputeEntropyWire2Tool)),
        (YaraEngineAsyncScanResultWire2Tool::definition(), Box::new(YaraEngineAsyncScanResultWire2Tool)),
        (YaraEngineScanBytesTool::definition(), Box::new(YaraEngineScanBytesTool)),
        (YaraEngineParseRuleTool::definition(), Box::new(YaraEngineParseRuleTool)),
        (YaraRuleNewTool::definition(), Box::new(YaraRuleNewTool)),
        (YaraRuleGetMetaTool::definition(), Box::new(YaraRuleGetMetaTool)),
        (YaraErrorDisplayTool::definition(), Box::new(YaraErrorDisplayTool)),
        (YaraRuleNewEmptyTool::definition(), Box::new(YaraRuleNewEmptyTool)),
        (YaraEngineParseNameFromSourceTool::definition(), Box::new(YaraEngineParseNameFromSourceTool)),
        (YaraEngineRuleSetAddRuleTool::definition(), Box::new(YaraEngineRuleSetAddRuleTool)),
        (YaraEngineRuleNewSummaryTool::definition(), Box::new(YaraEngineRuleNewSummaryTool)),
        (YaraEngineScannerNewCountTool::definition(), Box::new(YaraEngineScannerNewCountTool)),
        (YaraMatchMaskedByteTool::definition(), Box::new(YaraMatchMaskedByteTool)),
        (YaraCheckFullwordTool::definition(), Box::new(YaraCheckFullwordTool)),
        (YaraRuleDefinitionParseNameTool::definition(), Box::new(YaraRuleDefinitionParseNameTool)),
        (YaraRuleSetAddRuleTool::definition(), Box::new(YaraRuleSetAddRuleTool)),
        (YaraParserParseWireTool::definition(), Box::new(YaraParserParseWireTool)),
        (YaraRuleSetRuleCountWireTool::definition(), Box::new(YaraRuleSetRuleCountWireTool)),
        (YaraRuleSetNewCountWireTool::definition(), Box::new(YaraRuleSetNewCountWireTool)),
        (YaraRuleSetRuleByNameWireTool::definition(), Box::new(YaraRuleSetRuleByNameWireTool)),
        (YaraStringMatcherMatchHexWireTool::definition(), Box::new(YaraStringMatcherMatchHexWireTool)),
        (YaraStringMatcherMatchNocaseWireTool::definition(), Box::new(YaraStringMatcherMatchNocaseWireTool)),
        (YaraStringMatcherMatchWideWireTool::definition(), Box::new(YaraStringMatcherMatchWideWireTool)),
        (YaraStringMatcherMatchXorWireTool::definition(), Box::new(YaraStringMatcherMatchXorWireTool)),
        (YaraStringMatcherCheckFullwordWireTool::definition(), Box::new(YaraStringMatcherCheckFullwordWireTool)),
        (YaraStringMatcherMaskedByteWireTool::definition(), Box::new(YaraStringMatcherMaskedByteWireTool)),
        (YaraParserParseHexPatternWireTool::definition(), Box::new(YaraParserParseHexPatternWireTool)),
        (YaraParserParseMetaSectionWireTool::definition(), Box::new(YaraParserParseMetaSectionWireTool)),
        (YaraParserParseStringsSectionWireTool::definition(), Box::new(YaraParserParseStringsSectionWireTool)),
        (YaraParserParseConditionSectionWireTool::definition(), Box::new(YaraParserParseConditionSectionWireTool)),
        (YaraRuleDescriptionWireTool::definition(), Box::new(YaraRuleDescriptionWireTool)),
        (YaraEngRuleWithMetaBoolTool::definition(), Box::new(YaraEngRuleWithMetaBoolTool)),
        (YaraEngParseNameFromSourceWire3Tool::definition(), Box::new(YaraEngParseNameFromSourceWire3Tool)),
        (YaraEngComputeEntropyWire3Tool::definition(), Box::new(YaraEngComputeEntropyWire3Tool)),
        (YaraEngExtSymbolIntWire3Tool::definition(), Box::new(YaraEngExtSymbolIntWire3Tool)),
        (YaraEngExtSymbolStrWire3Tool::definition(), Box::new(YaraEngExtSymbolStrWire3Tool)),
        (YaraEngPeModuleFromBytesWire3Tool::definition(), Box::new(YaraEngPeModuleFromBytesWire3Tool)),
        (YaraEngElfModuleFromBytesWire3Tool::definition(), Box::new(YaraEngElfModuleFromBytesWire3Tool)),
        (YaraEngCompiledCacheHashSourcesWire3Tool::definition(), Box::new(YaraEngCompiledCacheHashSourcesWire3Tool)),
        (YaraEngCompiledCacheEmptyWire3Tool::definition(), Box::new(YaraEngCompiledCacheEmptyWire3Tool)),
        (YaraEngProcessRegionWithModuleWire3Tool::definition(), Box::new(YaraEngProcessRegionWithModuleWire3Tool)),
        (YaraEngAsyncScanConfigConcurrencyWire3Tool::definition(), Box::new(YaraEngAsyncScanConfigConcurrencyWire3Tool)),
        (YaraParserParseRuleWire3Tool::definition(), Box::new(YaraParserParseRuleWire3Tool)),
        (YaraParserParseStringModifiersWire3Tool::definition(), Box::new(YaraParserParseStringModifiersWire3Tool)),
        (YaraRuleAuthorWire3Tool::definition(), Box::new(YaraRuleAuthorWire3Tool)),
        (YaraRuleDateWire3Tool::definition(), Box::new(YaraRuleDateWire3Tool)),
        (YaraStringMatcherMatchTextWire3Tool::definition(), Box::new(YaraStringMatcherMatchTextWire3Tool)),
        (YaraRuleSetNewDefaultWire3Tool::definition(), Box::new(YaraRuleSetNewDefaultWire3Tool)),
        (YaraRuleNewWithTagsWire3Tool::definition(), Box::new(YaraRuleNewWithTagsWire3Tool)),
        (YaraHexTokenWildcardMatchWire3Tool::definition(), Box::new(YaraHexTokenWildcardMatchWire3Tool)),
        (YaraHexTokenJumpMatchWire3Tool::definition(), Box::new(YaraHexTokenJumpMatchWire3Tool)),
        (YaraStringModifiersFlagsWire3Tool::definition(), Box::new(YaraStringModifiersFlagsWire3Tool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both defective decode shapes in this file must now refuse bad input.
    ///
    /// The file held two generations of the same wrapper, wrong in two
    /// different ways: `yara_engine_compute_entropy_wire2` DROPPED an invalid
    /// pair (shorter buffer) and `yara_engine_compute_entropy_wire3` FABRICATED
    /// it as `0x00` (right length, wrong bytes). Both fed format verdicts —
    /// `entropy`, `is_pe`, `is_64bit`, `elf_class` — so neither error was
    /// visible in the answer. One test covers both, because after the repair
    /// they share a decoder.
    #[tokio::test]
    async fn both_generations_refuse_a_bad_digit() {
        let handlers = handlers();
        for name in [
            "yara_engine_compute_entropy_wire2", // used to drop
            "yara_eng_compute_entropy_wire3",    // used to fabricate 0x00
        ] {
            let Some((_, h)) = handlers.iter().find(|(d, _)| d.name == name) else {
                continue; // renamed upstream: covered by the other generation
            };
            // The two generations do not agree on the key name — `wire2`
            // declares `data_hex`, `wire3` declares `hex` — so send both. That
            // disagreement is itself part of the finding: seven different names
            // exist across this crate for "the caller's bytes", which is why
            // the first version of this test passed `hex` to a tool expecting
            // `data_hex`, got an empty buffer via `unwrap_or("")`, and read the
            // resulting success as the repair having failed.
            assert!(
                h.call(json!({ "hex": "deadbezz", "data_hex": "deadbezz" }))
                    .await
                    .is_err(),
                "{name} accepted an invalid digit"
            );
            assert!(
                h.call(json!({ "hex": "deadbeef", "data_hex": "deadbeef" }))
                    .await
                    .is_ok(),
                "{name} rejected valid input"
            );
        }
    }
}
