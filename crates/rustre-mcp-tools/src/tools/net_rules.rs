//! MCP wrappers for the rustre-net_rules crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct NetRulesFindBytesNocaseTool;

pub struct NetRulesExportRulesJsonTool;

pub struct NetRulesImportRulesJsonTool;

pub struct NetRulesExportRulesSnortTool;

pub struct NetRulesDiffRulesTool;

pub struct NetRulesParseSingleTool;
impl NetRulesParseSingleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_parse_single".to_string(), description: "Parse a single Snort rule string.".to_string(), input_schema: json!({"type":"object","required":["rule"],"properties":{"rule":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesParseSingleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("rule").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("rule".into()))?; match rustre_net_rules::RuleParser::parse(s) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"id":r.id,"msg":r.msg,"action":r.action.to_string(),"proto":r.proto.to_string(),"conditions":r.conditions.len(),"source":"rustre_net_rules::RuleParser::parse"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())) } } }

pub struct NetRulesParseManyTool;
impl NetRulesParseManyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_parse_many".to_string(), description: "Parse many rules from multi-line Snort text.".to_string(), input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesParseManyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?; let rs = rustre_net_rules::RuleParser::parse_many(s); let ok = rs.iter().filter(|r| r.is_ok()).count(); Ok(ToolResult::text(json!({"total":rs.len(),"ok":ok,"errors":rs.len()-ok,"source":"rustre_net_rules::RuleParser::parse_many"}).to_string())) } }

pub struct NetRulesEngineEvaluateTool;
impl NetRulesEngineEvaluateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_engine_evaluate".to_string(), description: "Evaluate rules against a synthetic PacketContext.".to_string(), input_schema: json!({"type":"object","required":["rules_text"],"properties":{"rules_text":{"type":"string"},"payload_hex":{"type":"string"},"src_port":{"type":"integer"},"dst_port":{"type":"integer"},"ip_proto":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesEngineEvaluateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let text = args.get("rules_text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("rules_text".into()))?;
    let payload = args.get("payload_hex").and_then(Value::as_str).map(|h| (0..h.len()).step_by(2).filter_map(|i| u8::from_str_radix(h.get(i..i+2)?, 16).ok()).collect::<Vec<u8>>()).unwrap_or_default();
    let src_port = args.get("src_port").and_then(Value::as_u64).unwrap_or(0) as u16;
    let dst_port = args.get("dst_port").and_then(Value::as_u64).unwrap_or(80) as u16;
    let ip_proto = args.get("ip_proto").and_then(Value::as_u64).unwrap_or(6) as u8;
    let eng = rustre_net_rules::RuleEngine::new();
    for r in rustre_net_rules::RuleParser::parse_many(text).into_iter().flatten() { eng.add_rule(r); }
    let ctx = rustre_net_rules::PacketContext { src_ip: "1.1.1.1".parse().unwrap(), dst_ip: "2.2.2.2".parse().unwrap(), src_port, dst_port, ip_proto, ttl: 64, payload, tcp_flags: rustre_net::TcpFlags::empty() };
    let all = eng.evaluate_all(&ctx);
    Ok(ToolResult::text(json!({"rule_count":eng.rules().len(),"match_count":all.len(),"source":"rustre_net_rules::RuleEngine::evaluate_all"}).to_string()))
} }

pub struct NetRulesAhoCorasickBuildTool;
impl NetRulesAhoCorasickBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_aho_corasick_build".to_string(), description: "Build an Aho-Corasick automaton, return state count.".to_string(), input_schema: json!({"type":"object","required":["patterns"],"properties":{"patterns":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesAhoCorasickBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pats: Vec<Vec<u8>> = args.get("patterns").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.as_bytes().to_vec())).collect()).unwrap_or_default(); let refs: Vec<&[u8]> = pats.iter().map(|v| v.as_slice()).collect(); let ac = rustre_net_rules::AhoCorasick::build(&refs); Ok(ToolResult::text(json!({"state_count":ac.state_count(),"pattern_count":pats.len(),"source":"rustre_net_rules::AhoCorasick::build"}).to_string())) } }

pub struct NetRulesAhoCorasickFindAllTool;
impl NetRulesAhoCorasickFindAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_aho_corasick_find_all".to_string(), description: "Aho-Corasick find_all matches.".to_string(), input_schema: json!({"type":"object","required":["patterns","text"],"properties":{"patterns":{"type":"array","items":{"type":"string"}},"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesAhoCorasickFindAllTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pats: Vec<Vec<u8>> = args.get("patterns").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.as_bytes().to_vec())).collect()).unwrap_or_default(); let refs: Vec<&[u8]> = pats.iter().map(|v| v.as_slice()).collect(); let text = args.get("text").and_then(Value::as_str).unwrap_or("").as_bytes(); let ac = rustre_net_rules::AhoCorasick::build(&refs); let ms = ac.find_all(text); Ok(ToolResult::text(json!({"match_count":ms.len(),"source":"rustre_net_rules::AhoCorasick::find_all"}).to_string())) } }

pub struct NetRulesAhoCorasickContainsAnyTool;
impl NetRulesAhoCorasickContainsAnyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_aho_corasick_contains_any".to_string(), description: "Aho-Corasick contains_any check.".to_string(), input_schema: json!({"type":"object","required":["patterns","text"],"properties":{"patterns":{"type":"array","items":{"type":"string"}},"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesAhoCorasickContainsAnyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pats: Vec<Vec<u8>> = args.get("patterns").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.as_bytes().to_vec())).collect()).unwrap_or_default(); let refs: Vec<&[u8]> = pats.iter().map(|v| v.as_slice()).collect(); let text = args.get("text").and_then(Value::as_str).unwrap_or("").as_bytes(); let ac = rustre_net_rules::AhoCorasick::build(&refs); Ok(ToolResult::text(json!({"contains_any":ac.contains_any(text),"source":"rustre_net_rules::AhoCorasick::contains_any"}).to_string())) } }

pub struct NetRulesIpSpecMatchesTool;
impl NetRulesIpSpecMatchesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_ip_spec_matches".to_string(), description: "Parse a Snort IP spec and match an address.".to_string(), input_schema: json!({"type":"object","required":["spec","addr"],"properties":{"spec":{"type":"string"},"addr":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesIpSpecMatchesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let spec = args.get("spec").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("spec".into()))?; let addr_s = args.get("addr").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let dsl = format!("alert tcp {} any -> any any (msg:\"p\"; sid:1;)", spec); let r = rustre_net_rules::RuleParser::parse(&dsl).map_err(|e| McpError::InvalidParams(e.to_string()))?; let addr: std::net::IpAddr = addr_s.parse().map_err(|_| McpError::InvalidParams("bad addr".into()))?; Ok(ToolResult::text(json!({"matches":r.src.addr.matches(addr),"source":"rustre_net_rules::IpSpec::matches"}).to_string())) } }

pub struct NetRulesPortSpecMatchesTool;
impl NetRulesPortSpecMatchesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_port_spec_matches".to_string(), description: "Parse a Snort port spec and match a port.".to_string(), input_schema: json!({"type":"object","required":["spec","port"],"properties":{"spec":{"type":"string"},"port":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesPortSpecMatchesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let spec = args.get("spec").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("spec".into()))?; let port = args.get("port").and_then(Value::as_u64).unwrap_or(0) as u16; let dsl = format!("alert tcp any {} -> any any (msg:\"p\"; sid:1;)", spec); let r = rustre_net_rules::RuleParser::parse(&dsl).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"matches":r.src.port.matches(port),"source":"rustre_net_rules::PortSpec::matches"}).to_string())) } }

pub struct NetRulesRuleStoreRoundtripTool;
impl NetRulesRuleStoreRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_rule_store_roundtrip".to_string(), description: "In-memory SQLite RuleStore roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"rules_text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesRuleStoreRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("rules_text").and_then(Value::as_str).unwrap_or("alert tcp any any -> any 80 (msg:\"t\"; sid:1;)"); let store = rustre_net_rules::RuleStore::in_memory().map_err(|e| McpError::InternalError(e.to_string()))?; let mut saved = 0usize; for r in rustre_net_rules::RuleParser::parse_many(text).into_iter().flatten() { store.save_rule(&r).map_err(|e| McpError::InternalError(e.to_string()))?; saved += 1; } let loaded = store.load_all().map_err(|e| McpError::InternalError(e.to_string()))?; let count = store.count().map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"saved":saved,"loaded":loaded.len(),"count":count,"source":"rustre_net_rules::RuleStore"}).to_string())) } }

pub struct NetRulesPacketContextFromIpv4Tool;
impl NetRulesPacketContextFromIpv4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_packet_context_from_ipv4".to_string(), description: "Parse hex IPv4 packet into PacketContext summary.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesPacketContextFromIpv4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let data: Vec<u8> = (0..h.len()).step_by(2).filter_map(|i| u8::from_str_radix(h.get(i..i+2)?, 16).ok()).collect(); match rustre_net_rules::PacketContext::from_ipv4(&data) { Some(c) => Ok(ToolResult::text(json!({"ok":true,"src_ip":c.src_ip.to_string(),"dst_ip":c.dst_ip.to_string(),"src_port":c.src_port,"dst_port":c.dst_port,"ip_proto":c.ip_proto,"ttl":c.ttl,"payload_len":c.payload.len(),"source":"rustre_net_rules::PacketContext::from_ipv4"}).to_string())), None => Ok(ToolResult::text(json!({"ok":false}).to_string())) } } }

pub struct NetRulesSpecEngineMatchTool;
impl NetRulesSpecEngineMatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_spec_engine_match".to_string(), description: "SpecRuleEngine match against MatchPacket.".to_string(), input_schema: json!({"type":"object","required":["content","payload_hex"],"properties":{"content":{"type":"string"},"payload_hex":{"type":"string"},"sid":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesSpecEngineMatchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let content = args.get("content").and_then(Value::as_str).unwrap_or("").as_bytes().to_vec();
    let sid = args.get("sid").and_then(Value::as_u64).unwrap_or(1) as u32;
    let h = args.get("payload_hex").and_then(Value::as_str).unwrap_or("");
    let payload: Vec<u8> = (0..h.len()).step_by(2).filter_map(|i| u8::from_str_radix(h.get(i..i+2)?, 16).ok()).collect();
    let mut rs = rustre_net_rules::RuleSet::new();
    rs.add(rustre_net_rules::SpecRule { action: rustre_net_rules::RuleAction::Alert, proto: rustre_net_rules::RuleProtocol::Any, src: "any".into(), src_port: "any".into(), dir: rustre_net_rules::RuleDir::Unidirectional, dst: "any".into(), dst_port: "any".into(), options: vec![rustre_net_rules::RuleOption::Msg("p".into()), rustre_net_rules::RuleOption::Sid(sid), rustre_net_rules::RuleOption::Content(content)] });
    let eng = rustre_net_rules::SpecRuleEngine::new(rs);
    let pkt = rustre_net_rules::MatchPacket { src_ip: "1.1.1.1".into(), dst_ip: "2.2.2.2".into(), src_port: 1234, dst_port: 80, proto: rustre_net_rules::RuleProtocol::Tcp, payload };
    let ms = eng.match_packet(&pkt);
    Ok(ToolResult::text(json!({"match_count":ms.len(),"source":"rustre_net_rules::SpecRuleEngine::match_packet"}).to_string()))
} }

pub struct NetRulesCompiledRuleSetEvalTool;
impl NetRulesCompiledRuleSetEvalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_rules_compiled_ruleset_eval".to_string(), description: "CompiledRuleSet AC-backed evaluation.".to_string(), input_schema: json!({"type":"object","required":["rules_text"],"properties":{"rules_text":{"type":"string"},"payload_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for NetRulesCompiledRuleSetEvalTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let text = args.get("rules_text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("rules_text".into()))?;
    let h = args.get("payload_hex").and_then(Value::as_str).unwrap_or("");
    let payload: Vec<u8> = (0..h.len()).step_by(2).filter_map(|i| u8::from_str_radix(h.get(i..i+2)?, 16).ok()).collect();
    let rules: Vec<rustre_net_rules::Rule> = rustre_net_rules::RuleParser::parse_many(text).into_iter().flatten().collect();
    let n = rules.len();
    let compiled = rustre_net_rules::CompiledRuleSet::compile(rules);
    let ctx = rustre_net_rules::PacketContext { src_ip: "1.1.1.1".parse().unwrap(), dst_ip: "2.2.2.2".parse().unwrap(), src_port: 1234, dst_port: 80, ip_proto: 6, ttl: 64, payload, tcp_flags: rustre_net::TcpFlags::empty() };
    let ms = compiled.evaluate(&ctx);
    Ok(ToolResult::text(json!({"rule_count":n,"match_count":ms.len(),"source":"rustre_net_rules::CompiledRuleSet::evaluate"}).to_string()))
} }

pub struct NetRulesAhoCorasickStateCountTool;
impl NetRulesAhoCorasickStateCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_ahocorasick_state_count".to_string(),
            description: "Build an Aho-Corasick automaton and return its state count.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "patterns": { "type": "array", "items": { "type": "string" } } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesAhoCorasickStateCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pats: Vec<String> = args.get("patterns").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["he".to_string(), "she".to_string(), "his".to_string()]);
        let refs: Vec<&[u8]> = pats.iter().map(|s| s.as_bytes()).collect();
        let ac = rustre_net_rules::AhoCorasick::build(&refs);
        Ok(ToolResult::text(json!({"state_count": ac.state_count(), "patterns": pats.len(),
            "source": "rustre_net_rules::AhoCorasick::state_count"}).to_string()))
    }
}

pub struct NetRulesAhoCorasickFindFirstTool;
impl NetRulesAhoCorasickFindFirstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_ahocorasick_find_first".to_string(),
            description: "Return the first Aho-Corasick match in a text.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "patterns": { "type": "array" }, "text": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesAhoCorasickFindFirstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pats: Vec<String> = args.get("patterns").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["cat".to_string(), "dog".to_string()]);
        let text = args.get("text").and_then(Value::as_str).unwrap_or("the dog barks");
        let refs: Vec<&[u8]> = pats.iter().map(|s| s.as_bytes()).collect();
        let ac = rustre_net_rules::AhoCorasick::build(&refs);
        let m = ac.find_first(text.as_bytes());
        Ok(ToolResult::text(json!({
            "match": m.as_ref().map(|x| json!({"pattern_idx": x.pattern_idx, "start": x.start, "end": x.end})),
            "source": "rustre_net_rules::AhoCorasick::find_first"
        }).to_string()))
    }
}

pub struct NetRulesNetworkSpecAnyTool;
impl NetRulesNetworkSpecAnyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_network_spec_any".to_string(),
            description: "Build NetworkSpec::any() and check that it matches any addr/port.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "addr": { "type": "string" }, "port": { "type": "integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesNetworkSpecAnyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr_s = args.get("addr").and_then(Value::as_str).unwrap_or("10.0.0.1");
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(443) as u16;
        let addr: std::net::IpAddr = addr_s.parse()
            .map_err(|e: std::net::AddrParseError| McpError::InvalidParams(e.to_string()))?;
        let ns = rustre_net_rules::NetworkSpec::any();
        Ok(ToolResult::text(json!({"matches": ns.matches(addr, port),
            "source": "rustre_net_rules::NetworkSpec::any"}).to_string()))
    }
}

pub struct NetRulesRuleSetNewAddCountTool;
impl NetRulesRuleSetNewAddCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_ruleset_new_add_count".to_string(),
            description: "RuleSet::new + add + count roundtrip.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesRuleSetNewAddCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut rs = rustre_net_rules::RuleSet::new();
        let r = rustre_net_rules::SpecRule {
            action: rustre_net_rules::RuleAction::Alert,
            proto: rustre_net_rules::RuleProtocol::Tcp,
            src: "any".into(), src_port: "any".into(),
            dir: rustre_net_rules::RuleDir::Unidirectional,
            dst: "any".into(), dst_port: "80".into(),
            options: vec![rustre_net_rules::RuleOption::Sid(42), rustre_net_rules::RuleOption::Msg("hi".into())],
        };
        rs.add(r);
        Ok(ToolResult::text(json!({"count": rs.count(),
            "source": "rustre_net_rules::RuleSet::{new,add,count}"}).to_string()))
    }
}

pub struct NetRulesRuleSetBySidTool;
impl NetRulesRuleSetBySidTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_ruleset_by_sid".to_string(),
            description: "Look up a rule in a RuleSet by SID.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "sid": { "type": "integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesRuleSetBySidTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sid = args.get("sid").and_then(Value::as_u64).unwrap_or(42) as u32;
        let mut rs = rustre_net_rules::RuleSet::new();
        rs.add(rustre_net_rules::SpecRule {
            action: rustre_net_rules::RuleAction::Alert,
            proto: rustre_net_rules::RuleProtocol::Any,
            src: "any".into(), src_port: "any".into(),
            dir: rustre_net_rules::RuleDir::Unidirectional,
            dst: "any".into(), dst_port: "any".into(),
            options: vec![rustre_net_rules::RuleOption::Sid(42)],
        });
        let found = rs.by_sid(sid).is_some();
        Ok(ToolResult::text(json!({"sid": sid, "found": found,
            "source": "rustre_net_rules::RuleSet::by_sid"}).to_string()))
    }
}

pub struct NetRulesSpecRuleSidMsgTool;
impl NetRulesSpecRuleSidMsgTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_specrule_sid_msg".to_string(),
            description: "Extract sid + msg from SpecRule options.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "sid": { "type": "integer" }, "msg": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesSpecRuleSidMsgTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sid = args.get("sid").and_then(Value::as_u64).unwrap_or(7) as u32;
        let msg = args.get("msg").and_then(Value::as_str).unwrap_or("test").to_string();
        let r = rustre_net_rules::SpecRule {
            action: rustre_net_rules::RuleAction::Log,
            proto: rustre_net_rules::RuleProtocol::Tcp,
            src: "any".into(), src_port: "any".into(),
            dir: rustre_net_rules::RuleDir::Unidirectional,
            dst: "any".into(), dst_port: "any".into(),
            options: vec![rustre_net_rules::RuleOption::Sid(sid), rustre_net_rules::RuleOption::Msg(msg.clone())],
        };
        Ok(ToolResult::text(json!({
            "sid": r.sid(), "msg": r.msg(),
            "source": "rustre_net_rules::SpecRule::{sid,msg}"
        }).to_string()))
    }
}

pub struct NetRulesSpecRuleContentPatternsTool;
impl NetRulesSpecRuleContentPatternsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_specrule_content_patterns".to_string(),
            description: "Collect Content byte-patterns from a SpecRule.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesSpecRuleContentPatternsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_net_rules::SpecRule {
            action: rustre_net_rules::RuleAction::Alert,
            proto: rustre_net_rules::RuleProtocol::Any,
            src: "any".into(), src_port: "any".into(),
            dir: rustre_net_rules::RuleDir::Unidirectional,
            dst: "any".into(), dst_port: "any".into(),
            options: vec![
                rustre_net_rules::RuleOption::Content(b"GET ".to_vec()),
                rustre_net_rules::RuleOption::Content(b"HTTP".to_vec()),
                rustre_net_rules::RuleOption::Nocase,
            ],
        };
        let pats: Vec<String> = r.content_patterns().iter()
            .map(|b| String::from_utf8_lossy(b).into_owned()).collect();
        Ok(ToolResult::text(json!({"patterns": pats,
            "source": "rustre_net_rules::SpecRule::content_patterns"}).to_string()))
    }
}

pub struct NetRulesEngineAddRemoveTool;
impl NetRulesEngineAddRemoveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_engine_add_remove".to_string(),
            description: "RuleEngine add/remove/rules roundtrip.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesEngineAddRemoveTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let eng = rustre_net_rules::RuleEngine::new();
        let r = rustre_net_rules::Rule::new(
            1, rustre_net_rules::RuleAction::Alert, rustre_net_rules::Proto::Tcp,
            rustre_net_rules::NetworkSpec::any(), rustre_net_rules::NetworkSpec::any(),
            "hello",
        );
        eng.add_rule(r);
        let before = eng.rules().len();
        eng.remove_rule(1);
        let after = eng.rules().len();
        Ok(ToolResult::text(json!({"before": before, "after": after,
            "source": "rustre_net_rules::RuleEngine::{add_rule,remove_rule,rules}"}).to_string()))
    }
}

pub struct NetRulesRuleDirDisplayTool;
impl NetRulesRuleDirDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_ruledir_display".to_string(),
            description: "Display strings for RuleDir + RuleProtocol variants.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesRuleDirDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_net_rules::{RuleDir, RuleProtocol};
        let dirs: Vec<String> = [RuleDir::Unidirectional, RuleDir::Bidirectional]
            .iter().map(std::string::ToString::to_string).collect();
        let protos: Vec<String> = [RuleProtocol::Tcp, RuleProtocol::Udp, RuleProtocol::Icmp, RuleProtocol::Any]
            .iter().map(std::string::ToString::to_string).collect();
        Ok(ToolResult::text(json!({"dirs": dirs, "protos": protos,
            "source": "rustre_net_rules::{RuleDir,RuleProtocol}::Display"}).to_string()))
    }
}

pub struct NetRulesProtoDisplayTool;
impl NetRulesProtoDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_rules_proto_display".to_string(),
            description: "Display string for every Proto and RuleAction variant.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetRulesProtoDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_net_rules::{Proto, RuleAction};
        let protos: Vec<String> = [Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::Any]
            .iter().map(std::string::ToString::to_string).collect();
        let actions: Vec<String> = [RuleAction::Alert, RuleAction::Pass, RuleAction::Drop, RuleAction::Log, RuleAction::Reject]
            .iter().map(std::string::ToString::to_string).collect();
        Ok(ToolResult::text(json!({"protos": protos, "actions": actions,
            "source": "rustre_net_rules::{Proto,RuleAction}::Display"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetRulesFindBytesNocaseTool::definition(), Box::new(NetRulesFindBytesNocaseTool)),
        (NetRulesExportRulesJsonTool::definition(), Box::new(NetRulesExportRulesJsonTool)),
        (NetRulesImportRulesJsonTool::definition(), Box::new(NetRulesImportRulesJsonTool)),
        (NetRulesExportRulesSnortTool::definition(), Box::new(NetRulesExportRulesSnortTool)),
        (NetRulesDiffRulesTool::definition(), Box::new(NetRulesDiffRulesTool)),
        (NetRulesParseSingleTool::definition(), Box::new(NetRulesParseSingleTool)),
        (NetRulesParseManyTool::definition(), Box::new(NetRulesParseManyTool)),
        (NetRulesEngineEvaluateTool::definition(), Box::new(NetRulesEngineEvaluateTool)),
        (NetRulesAhoCorasickBuildTool::definition(), Box::new(NetRulesAhoCorasickBuildTool)),
        (NetRulesAhoCorasickFindAllTool::definition(), Box::new(NetRulesAhoCorasickFindAllTool)),
        (NetRulesAhoCorasickContainsAnyTool::definition(), Box::new(NetRulesAhoCorasickContainsAnyTool)),
        (NetRulesIpSpecMatchesTool::definition(), Box::new(NetRulesIpSpecMatchesTool)),
        (NetRulesPortSpecMatchesTool::definition(), Box::new(NetRulesPortSpecMatchesTool)),
        (NetRulesRuleStoreRoundtripTool::definition(), Box::new(NetRulesRuleStoreRoundtripTool)),
        (NetRulesPacketContextFromIpv4Tool::definition(), Box::new(NetRulesPacketContextFromIpv4Tool)),
        (NetRulesSpecEngineMatchTool::definition(), Box::new(NetRulesSpecEngineMatchTool)),
        (NetRulesCompiledRuleSetEvalTool::definition(), Box::new(NetRulesCompiledRuleSetEvalTool)),
        (NetRulesAhoCorasickStateCountTool::definition(), Box::new(NetRulesAhoCorasickStateCountTool)),
        (NetRulesAhoCorasickFindFirstTool::definition(), Box::new(NetRulesAhoCorasickFindFirstTool)),
        (NetRulesNetworkSpecAnyTool::definition(), Box::new(NetRulesNetworkSpecAnyTool)),
        (NetRulesRuleSetNewAddCountTool::definition(), Box::new(NetRulesRuleSetNewAddCountTool)),
        (NetRulesRuleSetBySidTool::definition(), Box::new(NetRulesRuleSetBySidTool)),
        (NetRulesSpecRuleSidMsgTool::definition(), Box::new(NetRulesSpecRuleSidMsgTool)),
        (NetRulesSpecRuleContentPatternsTool::definition(), Box::new(NetRulesSpecRuleContentPatternsTool)),
        (NetRulesEngineAddRemoveTool::definition(), Box::new(NetRulesEngineAddRemoveTool)),
        (NetRulesRuleDirDisplayTool::definition(), Box::new(NetRulesRuleDirDisplayTool)),
        (NetRulesProtoDisplayTool::definition(), Box::new(NetRulesProtoDisplayTool)),
    ]
}
