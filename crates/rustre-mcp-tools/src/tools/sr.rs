//! MCP wrappers for the rustre-sr crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SrIocCollectionMockV4Tool;
impl SrIocCollectionMockV4Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_ioc_collection_mock_v4".to_string(),
            description: "Counts over an IocCollection from a real analysis, supplied as the \
                          `iocs` argument: total, is_empty, and per-kind (ips, domains, urls, \
                          hashes)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "iocs": {
                        "type": "object",
                        "description": "An IocCollection from a real analysis"
                    },
                    "use_synthetic_fixture": {
                        "type": "boolean",
                        "description": "Count the built-in fixture instead. The response is labelled is_synthetic_fixture and its IOCs were extracted from nothing."
                    }
                },
                "required": ["iocs"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for SrIocCollectionMockV4Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        // ⚠ This took no arguments and counted `IocCollection::mock()`, so the
        // per-kind totals it reported were the fixture's — IOCs extracted from
        // nothing, presented as though something had been analysed.
        let (c, is_synthetic_fixture) =
            if args.get("use_synthetic_fixture").and_then(Value::as_bool) == Some(true) {
                (rustre_sandbox_report::IocCollection::mock(), true)
            } else {
                let raw = args.get("iocs").ok_or_else(|| {
                    rustre_mcp_server::McpError::InvalidParams(
                        "'iocs' is required: an IocCollection from a real analysis. Pass \
                         \"use_synthetic_fixture\": true for the built-in fixture."
                            .to_string(),
                    )
                })?;
                let parsed: rustre_sandbox_report::IocCollection =
                    serde_json::from_value(raw.clone()).map_err(|e| {
                        rustre_mcp_server::McpError::ToolError(format!(
                            "'iocs' is not an IocCollection: {e}"
                        ))
                    })?;
                (parsed, false)
            };
        Ok(ToolResult::text(json!({
            "total": c.total(),
            "is_empty": c.is_empty(),
            "ips": c.ips.len(),
            "domains": c.domains.len(),
            "urls": c.urls.len(),
            "hashes": c.hashes.len(),
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_sandbox_report::IocCollection (supplied by the caller)"
        }).to_string()))
    }
}

pub struct SrIocCollectionSummaryTextV4Tool;
impl SrIocCollectionSummaryTextV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_collection_summary_text_v4".to_string(), description: "IocCollection::mock().summary_text length + preview.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrIocCollectionSummaryTextV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = rustre_sandbox_report::IocCollection::mock().summary_text(); Ok(ToolResult::text(json!({"len":s.len(),"preview":s.chars().take(200).collect::<String>(),"source":"rustre_sandbox_report::IocCollection::summary_text"}).to_string())) } }

pub struct SrIocCollectionToCsvV4Tool;
impl SrIocCollectionToCsvV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_collection_to_csv_v4".to_string(), description: "IocCollection::mock().to_csv: total rows + byte length.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrIocCollectionToCsvV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let csv = rustre_sandbox_report::IocCollection::mock().to_csv(); let lines = csv.lines().count(); Ok(ToolResult::text(json!({"lines":lines,"bytes":csv.len(),"source":"rustre_sandbox_report::IocCollection::to_csv"}).to_string())) } }

pub struct SrBehaviorTimelineBuildV4Tool;
impl SrBehaviorTimelineBuildV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_behavior_timeline_build_v4".to_string(), description: "BehaviorTimeline::build from three synthetic SandboxEvents (net/reg/proc); returns len, start/end/duration ms.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrBehaviorTimelineBuildV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_sandbox_report::{SandboxEvent, SandboxEventKind, BehaviorTimeline}; let evts = vec![ SandboxEvent::new(3000, 1, SandboxEventKind::NetworkConn, "n"), SandboxEvent::new(1000, 1, SandboxEventKind::RegistryOp, "r"), SandboxEvent::new(2000, 1, SandboxEventKind::ProcessSpawn, "p"), ]; let t = BehaviorTimeline::build(&evts); Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"start_ms":t.start_ms(),"end_ms":t.end_ms(),"duration_ms":t.duration_ms(),"source":"rustre_sandbox_report::BehaviorTimeline::build"}).to_string())) } }

pub struct SrBehaviorTimelineSummaryV4Tool;
impl SrBehaviorTimelineSummaryV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_behavior_timeline_summary_v4".to_string(), description: "BehaviorTimeline::summary on two synthetic events.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrBehaviorTimelineSummaryV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_sandbox_report::{SandboxEvent, SandboxEventKind, BehaviorTimeline}; let evts = vec![ SandboxEvent::new(500, 1, SandboxEventKind::MutexCreate, "m"), SandboxEvent::new(600, 1, SandboxEventKind::NetworkConn, "n"), ]; let s = BehaviorTimeline::build(&evts).summary(); Ok(ToolResult::text(json!({"summary":s,"source":"rustre_sandbox_report::BehaviorTimeline::summary"}).to_string())) } }

pub struct SrReportSectionNewV4Tool;
impl SrReportSectionNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_section_new_v4".to_string(), description: "ReportSection::new(title, content, order) constructor smoke test.".to_string(), input_schema: json!({"type":"object","properties":{"title":{"type":"string"},"content":{"type":"string"},"order":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrReportSectionNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let t = args.get("title").and_then(Value::as_str).unwrap_or("Summary"); let c = args.get("content").and_then(Value::as_str).unwrap_or("body"); let o = args.get("order").and_then(Value::as_u64).unwrap_or(1) as u32; let s = rustre_sandbox_report::ReportSection::new(t, c, o); Ok(ToolResult::text(json!({"title":s.title,"content_len":s.content.len(),"order":s.order,"source":"rustre_sandbox_report::ReportSection::new"}).to_string())) } }

pub struct SrAttackMappingTechniqueIdsV4Tool;
impl SrAttackMappingTechniqueIdsV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_mapping_technique_ids_v4".to_string(), description: "AttackMapping::from_behaviors + technique_ids for tags.".to_string(), input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrAttackMappingTechniqueIdsV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let tags: Vec<String> = args.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["injection".into(), "persistence".into(), "c2".into()]); let refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect(); let m = rustre_sandbox_report::AttackMapping::from_behaviors(&refs); let ids: Vec<String> = m.technique_ids().iter().map(|s| s.to_string()).collect(); Ok(ToolResult::text(json!({"count":ids.len(),"ids":ids,"source":"rustre_sandbox_report::AttackMapping::technique_ids"}).to_string())) } }

pub struct SrReportFormatFromExtensionV4Tool;
impl SrReportFormatFromExtensionV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_format_from_extension_v4".to_string(), description: "ReportFormat::from_extension parse + extension roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"ext":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrReportFormatFromExtensionV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let e = args.get("ext").and_then(Value::as_str).unwrap_or("json"); let f = rustre_sandbox_report::ReportFormat::from_extension(e).map_err(|err| rustre_mcp_server::McpError::InvalidParams(err.to_string()))?; Ok(ToolResult::text(json!({"input":e,"display":f.to_string(),"extension":f.extension(),"source":"rustre_sandbox_report::ReportFormat::from_extension"}).to_string())) } }

pub struct SrSandboxReportBuildAttackMappingV4Tool;
impl SrSandboxReportBuildAttackMappingV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_sandbox_report_build_attack_mapping_v4".to_string(), description: "SandboxReport::mock + add_tag + build_attack_mapping + infer_family: counts tags/ttps/tactics.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrSandboxReportBuildAttackMappingV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut r = rustre_sandbox_report::SandboxReport::mock(); r.add_tag("injection"); r.add_tag("persistence"); r.add_ttp("T1055"); r.build_attack_mapping(); r.infer_family(); Ok(ToolResult::text(json!({"tags":r.tags.len(),"ttps":r.ttps.len(),"tactics":r.attack.tactics_present().len(),"techniques":r.attack.technique_ids().len(),"family":r.family,"source":"rustre_sandbox_report::SandboxReport::build_attack_mapping"}).to_string())) } }

pub struct SrIocSetAddV4Tool;
impl SrIocSetAddV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_set_add_v4".to_string(), description: "IocSet::add + len roundtrip with a fresh Ioc.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"confidence":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for SrIocSetAddV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let val = args.get("value").and_then(Value::as_str).unwrap_or("1.2.3.4"); let conf = args.get("confidence").and_then(Value::as_u64).unwrap_or(80) as u8; let mut set = rustre_sandbox_report::IocSet::default(); let before = set.len(); set.add(rustre_sandbox_report::Ioc::new(rustre_sandbox_report::IocKind::Ip, val, conf, "test")); Ok(ToolResult::text(json!({"before":before,"after":set.len(),"is_empty":set.is_empty(),"source":"rustre_sandbox_report::IocSet::add"}).to_string())) } }

pub struct SrSeverityScoreAllV3Tool;
impl SrSeverityScoreAllV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_severity_score_all_v3".to_string(), description: "rustre_sandbox_report::Severity::score for all variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrSeverityScoreAllV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::Severity; Ok(ToolResult::text(json!({"info":Severity::Info.score(),"low":Severity::Low.score(),"medium":Severity::Medium.score(),"high":Severity::High.score(),"critical":Severity::Critical.score(),"source":"rustre_sandbox_report::Severity::score"}).to_string())) } }

pub struct SrIocKindDisplayAllV3Tool;
impl SrIocKindDisplayAllV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_kind_display_all_v3".to_string(), description: "IocKind Display all variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocKindDisplayAllV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::IocKind; let all = [IocKind::Ip, IocKind::Domain, IocKind::Url, IocKind::FilePath, IocKind::FileHash, IocKind::RegistryKey, IocKind::Mutex, IocKind::Email]; let names: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"kinds":names,"source":"rustre_sandbox_report::IocKind::fmt"}).to_string())) } }

pub struct SrIocIsConfidentV3Tool;
impl SrIocIsConfidentV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_is_confident_v3".to_string(), description: "Ioc::new + is_confident.".to_string(), input_schema: json!({"type":"object","properties":{"confidence":{"type":"integer"},"threshold":{"type":"integer"}},"required":["confidence","threshold"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocIsConfidentV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{Ioc, IocKind}; let c = args.get("confidence").and_then(Value::as_u64).unwrap_or(0) as u8; let t = args.get("threshold").and_then(Value::as_u64).unwrap_or(0) as u8; let ioc = Ioc::new(IocKind::Ip, "1.2.3.4", c, "t"); Ok(ToolResult::text(json!({"confidence":ioc.confidence,"threshold":t,"is_confident":ioc.is_confident(t),"source":"rustre_sandbox_report::Ioc::is_confident"}).to_string())) } }

pub struct SrIocSetByKindV3Tool;
impl SrIocSetByKindV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_iocset_by_kind_v3".to_string(), description: "IocSet::mock + by_kind counts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocSetByKindV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{IocSet, IocKind}; let set = IocSet::mock(); Ok(ToolResult::text(json!({"ip":set.by_kind(&IocKind::Ip).len(),"domain":set.by_kind(&IocKind::Domain).len(),"filepath":set.by_kind(&IocKind::FilePath).len(),"filehash":set.by_kind(&IocKind::FileHash).len(),"registry_key":set.by_kind(&IocKind::RegistryKey).len(),"mutex":set.by_kind(&IocKind::Mutex).len(),"total":set.len(),"is_empty":set.is_empty(),"source":"rustre_sandbox_report::IocSet::by_kind"}).to_string())) } }

pub struct SrAttackTacticListV3Tool;
impl SrAttackTacticListV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_tactic_list_v3".to_string(), description: "AttackTactic Display 12 MITRE.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrAttackTacticListV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::AttackTactic::*; let all = [InitialAccess, Execution, Persistence, PrivilegeEscalation, DefenseEvasion, CredentialAccess, Discovery, LateralMovement, Collection, CommandAndControl, Exfiltration, Impact]; let names: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"tactics":names,"count":names.len(),"source":"rustre_sandbox_report::AttackTactic::fmt"}).to_string())) } }

pub struct SrAttackMappingByTacticV3Tool;
impl SrAttackMappingByTacticV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_mapping_by_tactic_v3".to_string(), description: "AttackMapping::from_behaviors + by_tactic counts.".to_string(), input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}},"required":["tags"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrAttackMappingByTacticV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{AttackMapping, AttackTactic}; let tags_v = args.get("tags").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'tags'".into()))?; let tags: Vec<String> = tags_v.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let refs: Vec<&str> = tags.iter().map(String::as_str).collect(); let m = AttackMapping::from_behaviors(&refs); Ok(ToolResult::text(json!({"persistence":m.by_tactic(&AttackTactic::Persistence).len(),"defense_evasion":m.by_tactic(&AttackTactic::DefenseEvasion).len(),"command_and_control":m.by_tactic(&AttackTactic::CommandAndControl).len(),"collection":m.by_tactic(&AttackTactic::Collection).len(),"impact":m.by_tactic(&AttackTactic::Impact).len(),"lateral_movement":m.by_tactic(&AttackTactic::LateralMovement).len(),"total":m.techniques.len(),"source":"rustre_sandbox_report::AttackMapping::by_tactic"}).to_string())) } }

pub struct SrVerdictAllDisplayV3Tool;
impl SrVerdictAllDisplayV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_verdict_all_display_v3".to_string(), description: "Verdict Display all 5.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrVerdictAllDisplayV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::Verdict; let all = [Verdict::Clean, Verdict::Low, Verdict::Suspicious, Verdict::Malicious, Verdict::Unknown]; let names: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"verdicts":names,"source":"rustre_sandbox_report::Verdict::fmt"}).to_string())) } }

pub struct SrScoreEngineVerdictSweepV3Tool;
impl SrScoreEngineVerdictSweepV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_score_engine_verdict_sweep_v3".to_string(), description: "ScoreEngine::verdict on 0/15/50/85.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrScoreEngineVerdictSweepV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let e = rustre_sandbox_report::ScoreEngine::new(); Ok(ToolResult::text(json!({"s0":e.verdict(0).to_string(),"s15":e.verdict(15).to_string(),"s50":e.verdict(50).to_string(),"s85":e.verdict(85).to_string(),"source":"rustre_sandbox_report::ScoreEngine::verdict"}).to_string())) } }

pub struct SrReportFormatExtensionAllV3Tool;
impl SrReportFormatExtensionAllV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_format_extension_all_v3".to_string(), description: "ReportFormat::extension all 5.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrReportFormatExtensionAllV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::ReportFormat; let all = [ReportFormat::Json, ReportFormat::Html, ReportFormat::Pdf, ReportFormat::Csv, ReportFormat::Markdown]; let items: Vec<Value> = all.iter().map(|f| json!({"format":f.to_string(),"ext":f.extension()})).collect(); Ok(ToolResult::text(json!({"formats":items,"source":"rustre_sandbox_report::ReportFormat::extension"}).to_string())) } }

pub struct SrReportFormatFromExtensionV3Tool;
impl SrReportFormatFromExtensionV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_format_from_extension_v3".to_string(), description: "ReportFormat::from_extension parse.".to_string(), input_schema: json!({"type":"object","properties":{"ext":{"type":"string"}},"required":["ext"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrReportFormatFromExtensionV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ext = args.get("ext").and_then(Value::as_str).unwrap_or(""); match rustre_sandbox_report::ReportFormat::from_extension(ext) { Ok(f) => Ok(ToolResult::text(json!({"ok":true,"format":f.to_string(),"extension":f.extension(),"source":"rustre_sandbox_report::ReportFormat::from_extension"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_sandbox_report::ReportFormat::from_extension"}).to_string())), } } }

pub struct SrClassifierInferFamilyV3Tool;
impl SrClassifierInferFamilyV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_classifier_infer_family_v3".to_string(), description: "BehaviorClassifier::classify + infer_family.".to_string(), input_schema: json!({"type":"object","properties":{"apis":{"type":"array","items":{"type":"string"}}},"required":["apis"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrClassifierInferFamilyV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::BehaviorClassifier; let a = args.get("apis").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'apis'".into()))?; let apis: Vec<String> = a.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let refs: Vec<&str> = apis.iter().map(String::as_str).collect(); let c = BehaviorClassifier::new(); let (ind, beh) = c.classify(&refs); let family = BehaviorClassifier::infer_family(&ind); Ok(ToolResult::text(json!({"indicator_count":ind.len(),"behavior_count":beh.len(),"family":family,"source":"rustre_sandbox_report::BehaviorClassifier"}).to_string())) } }

pub struct SrScoreEngineHasCriticalV3Tool;
impl SrScoreEngineHasCriticalV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_score_engine_has_critical_v3".to_string(), description: "ScoreEngine::has_critical on mock report.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrScoreEngineHasCriticalV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{ScoreEngine, SandboxReport}; let r = SandboxReport::mock(); Ok(ToolResult::text(json!({"has_critical":ScoreEngine::has_critical(&r.indicators),"indicator_count":r.indicators.len(),"source":"rustre_sandbox_report::ScoreEngine::has_critical"}).to_string())) } }

pub struct SrSeverityParseV5Tool;
impl SrSeverityParseV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_severity_parse_v5".to_string(), description: "Severity::parse case-insensitive with error path.".to_string(), input_schema: json!({"type":"object","properties":{"s":{"type":"string"}},"required":["s"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrSeverityParseV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("s").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 's'".into()))?; match rustre_sandbox_report::Severity::parse(s) { Ok(v) => Ok(ToolResult::text(json!({"ok":true,"severity":v.to_string(),"score":v.score(),"source":"rustre_sandbox_report::Severity::parse"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_sandbox_report::Severity::parse"}).to_string())) } } }

pub struct SrIocNewClampV5Tool;
impl SrIocNewClampV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_ioc_new_clamp_v5".to_string(), description: "Ioc::new clamps confidence to 100.".to_string(), input_schema: json!({"type":"object","properties":{"confidence":{"type":"integer"}},"required":["confidence"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocNewClampV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{Ioc, IocKind}; let c = args.get("confidence").and_then(Value::as_u64).unwrap_or(0).min(255) as u8; let ioc = Ioc::new(IocKind::Domain, "x.com", c, "ctx"); Ok(ToolResult::text(json!({"input":c,"stored":ioc.confidence,"clamped":ioc.confidence < c || c <= 100 && ioc.confidence == c,"kind":ioc.kind.to_string(),"source":"rustre_sandbox_report::Ioc::new"}).to_string())) } }

pub struct SrIocSetDedupeV5Tool;
impl SrIocSetDedupeV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_iocset_dedupe_v5".to_string(), description: "IocSet::deduplicate collapses duplicates.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocSetDedupeV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{IocSet, Ioc, IocKind}; let mut s = IocSet::new(); s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 90, "a")); s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 80, "b")); s.add(Ioc::new(IocKind::Domain, "x.com", 70, "c")); let before = s.len(); s.deduplicate(); Ok(ToolResult::text(json!({"before":before,"after":s.len(),"is_empty":s.is_empty(),"source":"rustre_sandbox_report::IocSet::deduplicate"}).to_string())) } }

pub struct SrIocSetConfidentV5Tool;
impl SrIocSetConfidentV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_iocset_confident_v5".to_string(), description: "IocSet::mock + confident(threshold).".to_string(), input_schema: json!({"type":"object","properties":{"threshold":{"type":"integer"}},"required":["threshold"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIocSetConfidentV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("threshold").and_then(Value::as_u64).unwrap_or(0).min(255) as u8; let s = rustre_sandbox_report::IocSet::mock(); Ok(ToolResult::text(json!({"threshold":t,"confident":s.confident(t).len(),"total":s.len(),"source":"rustre_sandbox_report::IocSet::confident"}).to_string())) } }

pub struct SrAttackFullIdV5Tool;
impl SrAttackFullIdV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_full_id_v5".to_string(), description: "AttackTechnique::full_id uses sub_id if present.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrAttackFullIdV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{AttackTechnique, AttackTactic}; let a = AttackTechnique { id: "T1055".into(), sub_id: Some("T1055.001".into()), name: "n".into(), tactic: AttackTactic::DefenseEvasion, evidence: vec![], confidence: 90 }; let b = AttackTechnique { id: "T1497".into(), sub_id: None, name: "n".into(), tactic: AttackTactic::DefenseEvasion, evidence: vec![], confidence: 80 }; Ok(ToolResult::text(json!({"with_sub":a.full_id(),"without_sub":b.full_id(),"source":"rustre_sandbox_report::AttackTechnique::full_id"}).to_string())) } }

pub struct SrAttackTacticsPresentV5Tool;
impl SrAttackTacticsPresentV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_tactics_present_v5".to_string(), description: "AttackMapping::tactics_present unique sorted list.".to_string(), input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}},"required":["tags"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrAttackTacticsPresentV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("tags").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'tags'".into()))?; let tags: Vec<String> = a.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let refs: Vec<&str> = tags.iter().map(String::as_str).collect(); let m = rustre_sandbox_report::AttackMapping::from_behaviors(&refs); Ok(ToolResult::text(json!({"tactics":m.tactics_present(),"total":m.techniques.len(),"source":"rustre_sandbox_report::AttackMapping::tactics_present"}).to_string())) } }

pub struct SrAttackHighConfidenceV5Tool;
impl SrAttackHighConfidenceV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_attack_high_confidence_v5".to_string(), description: "AttackMapping::high_confidence (>=80).".to_string(), input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}},"required":["tags"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrAttackHighConfidenceV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("tags").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'tags'".into()))?; let tags: Vec<String> = a.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let refs: Vec<&str> = tags.iter().map(String::as_str).collect(); let m = rustre_sandbox_report::AttackMapping::from_behaviors(&refs); Ok(ToolResult::text(json!({"high":m.high_confidence().len(),"total":m.techniques.len(),"ids":m.technique_ids(),"source":"rustre_sandbox_report::AttackMapping::high_confidence"}).to_string())) } }

pub struct SrIndicatorCategoryDisplayV5Tool;
impl SrIndicatorCategoryDisplayV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_indicator_category_display_v5".to_string(), description: "IndicatorCategory Display all variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIndicatorCategoryDisplayV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::IndicatorCategory::*; let all = [Injection, Network, Persistence, Evasion, Crypto, Dropper, Keylogging, Ransomware, Reconnaissance, Other]; let names: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"categories":names,"count":names.len(),"source":"rustre_sandbox_report::IndicatorCategory::fmt"}).to_string())) } }

pub struct SrIndicatorWithIocV5Tool;
impl SrIndicatorWithIocV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_indicator_with_ioc_v5".to_string(), description: "Indicator::new + with_ioc + with_technique builder chain.".to_string(), input_schema: json!({"type":"object","properties":{"ioc":{"type":"string"},"tid":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrIndicatorWithIocV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_sandbox_report::{Indicator, IndicatorCategory, Severity}; let ioc = args.get("ioc").and_then(Value::as_str).unwrap_or("pid:1"); let tid = args.get("tid").and_then(Value::as_str).unwrap_or("T1055"); let i = Indicator::new("n","d",Severity::High,IndicatorCategory::Injection).with_ioc(ioc).with_technique(tid); Ok(ToolResult::text(json!({"name":i.name,"severity":i.severity.to_string(),"ioc":i.ioc,"tids":i.technique_ids,"category":i.category.to_string(),"source":"rustre_sandbox_report::Indicator"}).to_string())) } }

pub struct SrReportRendererJsonV5Tool;
impl SrReportRendererJsonV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_renderer_json_v5".to_string(), description: "ReportRenderer::render_json on mock SandboxReport.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrReportRendererJsonV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_sandbox_report::SandboxReport::mock(); let s = rustre_sandbox_report::ReportRenderer::new().render_json(&r).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"bytes":s.len(),"starts_with_brace":s.starts_with('{'),"source":"rustre_sandbox_report::ReportRenderer::render_json"}).to_string())) } }

pub struct SrReportRendererMarkdownV5Tool;
impl SrReportRendererMarkdownV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_report_renderer_markdown_v5".to_string(), description: "ReportRenderer::render_markdown on mock SandboxReport.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrReportRendererMarkdownV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_sandbox_report::SandboxReport::mock(); let s = rustre_sandbox_report::ReportRenderer::new().render_markdown(&r); Ok(ToolResult::text(json!({"bytes":s.len(),"has_title":s.contains("# Sandbox Report"),"has_iocs":s.contains("## IOCs"),"source":"rustre_sandbox_report::ReportRenderer::render_markdown"}).to_string())) } }

pub struct SrReportCriticalIndicatorsV5Tool;
impl SrReportCriticalIndicatorsV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "sandbox_report_critical_indicators_v5".to_string(), description: "SandboxReport::critical_indicators on mock report.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for SrReportCriticalIndicatorsV5Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_sandbox_report::SandboxReport::mock(); Ok(ToolResult::text(json!({"critical":r.critical_indicators().len(),"total":r.indicators.len(),"verdict":r.verdict.to_string(),"score":r.score,"family":r.family,"source":"rustre_sandbox_report::SandboxReport::critical_indicators"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SrIocCollectionMockV4Tool::definition(), Box::new(SrIocCollectionMockV4Tool)),
        (SrIocCollectionSummaryTextV4Tool::definition(), Box::new(SrIocCollectionSummaryTextV4Tool)),
        (SrIocCollectionToCsvV4Tool::definition(), Box::new(SrIocCollectionToCsvV4Tool)),
        (SrBehaviorTimelineBuildV4Tool::definition(), Box::new(SrBehaviorTimelineBuildV4Tool)),
        (SrBehaviorTimelineSummaryV4Tool::definition(), Box::new(SrBehaviorTimelineSummaryV4Tool)),
        (SrReportSectionNewV4Tool::definition(), Box::new(SrReportSectionNewV4Tool)),
        (SrAttackMappingTechniqueIdsV4Tool::definition(), Box::new(SrAttackMappingTechniqueIdsV4Tool)),
        (SrReportFormatFromExtensionV4Tool::definition(), Box::new(SrReportFormatFromExtensionV4Tool)),
        (SrSandboxReportBuildAttackMappingV4Tool::definition(), Box::new(SrSandboxReportBuildAttackMappingV4Tool)),
        (SrIocSetAddV4Tool::definition(), Box::new(SrIocSetAddV4Tool)),
        (SrSeverityScoreAllV3Tool::definition(), Box::new(SrSeverityScoreAllV3Tool)),
        (SrIocKindDisplayAllV3Tool::definition(), Box::new(SrIocKindDisplayAllV3Tool)),
        (SrIocIsConfidentV3Tool::definition(), Box::new(SrIocIsConfidentV3Tool)),
        (SrIocSetByKindV3Tool::definition(), Box::new(SrIocSetByKindV3Tool)),
        (SrAttackTacticListV3Tool::definition(), Box::new(SrAttackTacticListV3Tool)),
        (SrAttackMappingByTacticV3Tool::definition(), Box::new(SrAttackMappingByTacticV3Tool)),
        (SrVerdictAllDisplayV3Tool::definition(), Box::new(SrVerdictAllDisplayV3Tool)),
        (SrScoreEngineVerdictSweepV3Tool::definition(), Box::new(SrScoreEngineVerdictSweepV3Tool)),
        (SrReportFormatExtensionAllV3Tool::definition(), Box::new(SrReportFormatExtensionAllV3Tool)),
        (SrReportFormatFromExtensionV3Tool::definition(), Box::new(SrReportFormatFromExtensionV3Tool)),
        (SrClassifierInferFamilyV3Tool::definition(), Box::new(SrClassifierInferFamilyV3Tool)),
        (SrScoreEngineHasCriticalV3Tool::definition(), Box::new(SrScoreEngineHasCriticalV3Tool)),
        (SrSeverityParseV5Tool::definition(), Box::new(SrSeverityParseV5Tool)),
        (SrIocNewClampV5Tool::definition(), Box::new(SrIocNewClampV5Tool)),
        (SrIocSetDedupeV5Tool::definition(), Box::new(SrIocSetDedupeV5Tool)),
        (SrIocSetConfidentV5Tool::definition(), Box::new(SrIocSetConfidentV5Tool)),
        (SrAttackFullIdV5Tool::definition(), Box::new(SrAttackFullIdV5Tool)),
        (SrAttackTacticsPresentV5Tool::definition(), Box::new(SrAttackTacticsPresentV5Tool)),
        (SrAttackHighConfidenceV5Tool::definition(), Box::new(SrAttackHighConfidenceV5Tool)),
        (SrIndicatorCategoryDisplayV5Tool::definition(), Box::new(SrIndicatorCategoryDisplayV5Tool)),
        (SrIndicatorWithIocV5Tool::definition(), Box::new(SrIndicatorWithIocV5Tool)),
        (SrReportRendererJsonV5Tool::definition(), Box::new(SrReportRendererJsonV5Tool)),
        (SrReportRendererMarkdownV5Tool::definition(), Box::new(SrReportRendererMarkdownV5Tool)),
        (SrReportCriticalIndicatorsV5Tool::definition(), Box::new(SrReportCriticalIndicatorsV5Tool)),
    ]
}
