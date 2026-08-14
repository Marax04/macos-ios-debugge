//! `tool_aggregator` — Aggregation of tools from multiple MCP servers.
//!
//! Provides namespace isolation (`server_name::tool_name`), conflict resolution,
//! tool forwarding with context injection, result merging, and streaming aggregation.

use std::collections::HashMap;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::FederationError;

// ─────────────────────────────────────────────────────────────────────────────
// NamespacePolicy
// ─────────────────────────────────────────────────────────────────────────────

/// How to handle namespace collisions when multiple servers export the same tool name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictPolicy {
    /// Use the server with highest priority; shadow the rest.
    Priority,
    /// Always use the fully-qualified `server::tool` name — no shadowing.
    FullyQualified,
    /// Expose both qualified and unqualified; unqualified routes to the first server.
    FirstWins,
    /// Refuse to aggregate — return an error on conflict.
    Reject,
    /// Expose all variants, unqualified returns merged results.
    MergeAll,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self::FirstWins
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AggregatedTool
// ─────────────────────────────────────────────────────────────────────────────

/// A single aggregated tool descriptor, possibly backed by multiple servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedTool {
    /// Bare tool name (no server prefix).
    pub name: String,
    /// Fully-qualified name: `server_name::tool_name`.
    pub qualified_name: String,
    /// Human-readable description (from primary server).
    pub description: String,
    /// Combined JSON Schema for input parameters.
    pub input_schema: Value,
    /// Primary server that owns this tool.
    pub primary_server: String,
    /// All servers that provide a tool with this bare name.
    pub server_providers: Vec<String>,
    /// Tool priority (higher = preferred when conflicts exist).
    pub priority: u32,
    /// Whether this tool has a conflict (same bare name on multiple servers).
    pub has_conflict: bool,
}

impl AggregatedTool {
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        schema: Value,
        priority: u32,
    ) -> Self {
        let server = server.into();
        let name = name.into();
        let qualified = format!("{server}::{name}");
        Self {
            qualified_name: qualified,
            primary_server: server.clone(),
            server_providers: vec![server],
            name,
            description: description.into(),
            input_schema: schema,
            priority,
            has_conflict: false,
        }
    }

    /// Add an alternative server provider for this tool name.
    pub fn add_provider(&mut self, server: impl Into<String>) {
        let s = server.into();
        if !self.server_providers.contains(&s) {
            self.server_providers.push(s);
            self.has_conflict = true;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ForwardContext
// ─────────────────────────────────────────────────────────────────────────────

/// Additional context injected into a forwarded tool call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardContext {
    /// Session identifier.
    pub session_id: Option<String>,
    /// Caller identity.
    pub caller: Option<String>,
    /// Binary path being analysed (if relevant).
    pub binary_path: Option<String>,
    /// Any extra metadata to inject.
    pub extra: HashMap<String, Value>,
}

impl ForwardContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_session(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Inject context fields into `params` under a `"__rustre_ctx"` key.
    #[must_use]
    pub fn inject_into(&self, mut params: Value) -> Value {
        if let Value::Object(ref mut map) = params {
            let mut ctx = serde_json::Map::new();
            if let Some(ref s) = self.session_id {
                ctx.insert("session_id".into(), Value::String(s.clone()));
            }
            if let Some(ref c) = self.caller {
                ctx.insert("caller".into(), Value::String(c.clone()));
            }
            if let Some(ref b) = self.binary_path {
                ctx.insert("binary_path".into(), Value::String(b.clone()));
            }
            for (k, v) in &self.extra {
                ctx.insert(k.clone(), v.clone());
            }
            if !ctx.is_empty() {
                map.insert("__rustre_ctx".into(), Value::Object(ctx));
            }
        }
        params
    }

    /// Strip context fields from params (before forwarding to server that doesn't expect them).
    #[must_use]
    pub fn strip_from(mut params: Value) -> Value {
        if let Value::Object(ref mut map) = params {
            map.remove("__rustre_ctx");
        }
        params
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AggregationResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result from one server during aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub server: String,
    pub result: Result<Value, String>,
    pub latency_ms: u64,
}

impl ServerResult {
    #[must_use]
    pub fn success(server: impl Into<String>, result: Value, latency_ms: u64) -> Self {
        Self { server: server.into(), result: Ok(result), latency_ms }
    }

    #[must_use]
    pub fn error(server: impl Into<String>, err: impl Into<String>, latency_ms: u64) -> Self {
        Self { server: server.into(), result: Err(err.into()), latency_ms }
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

/// Merged result from multiple servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub tool_name: String,
    pub server_results: Vec<ServerResult>,
    pub merge_strategy: MergeStrategy,
    pub merged: Value,
}

impl AggregationResult {
    /// Build an `AggregationResult` from raw server results.
    #[must_use]
    pub fn build(
        tool_name: impl Into<String>,
        server_results: Vec<ServerResult>,
        strategy: MergeStrategy,
    ) -> Self {
        let merged = strategy.apply(&server_results);
        Self {
            tool_name: tool_name.into(),
            server_results,
            merge_strategy: strategy,
            merged,
        }
    }

    /// Returns `true` when at least one server returned a success.
    #[must_use]
    pub fn any_success(&self) -> bool {
        self.server_results.iter().any(|r| r.is_ok())
    }

    /// Returns `true` when all servers returned success.
    #[must_use]
    pub fn all_success(&self) -> bool {
        self.server_results.iter().all(|r| r.is_ok())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MergeStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// How to merge results from multiple servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Return the first successful result.
    FirstSuccess,
    /// Return all results in an array, attributed by server.
    All,
    /// Concatenate array results from all servers.
    ConcatArrays,
    /// Merge JSON objects (later servers override earlier).
    MergeObjects,
    /// Return only the primary server's result.
    PrimaryOnly,
}

impl MergeStrategy {
    /// Apply the merge strategy to a list of server results.
    #[must_use]
    pub fn apply(&self, results: &[ServerResult]) -> Value {
        match self {
            Self::FirstSuccess => {
                results
                    .iter()
                    .find(|r| r.is_ok())
                    .and_then(|r| r.result.as_ref().ok())
                    .cloned()
                    .unwrap_or(Value::Null)
            }
            Self::All => {
                let arr: Vec<Value> = results
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "server": r.server,
                            "latency_ms": r.latency_ms,
                            "result": match &r.result {
                                Ok(v) => serde_json::json!({"ok": v}),
                                Err(e) => serde_json::json!({"error": e}),
                            }
                        })
                    })
                    .collect();
                serde_json::json!({ "results": arr, "count": arr.len() })
            }
            Self::ConcatArrays => {
                let mut combined: Vec<Value> = Vec::new();
                for r in results {
                    if let Ok(v) = &r.result {
                        match v {
                            Value::Array(arr) => combined.extend(arr.iter().cloned()),
                            other => {
                                for key in &["items", "results", "data"] {
                                    if let Some(arr) = other.get(key).and_then(Value::as_array) {
                                        combined.extend(arr.iter().cloned());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                let n = combined.len();
                serde_json::json!({ "items": combined, "count": n })
            }
            Self::MergeObjects => {
                let mut merged = serde_json::Map::new();
                for r in results {
                    if let Ok(Value::Object(map)) = &r.result {
                        merged.extend(map.iter().map(|(k, v)| (k.clone(), v.clone())));
                    }
                }
                Value::Object(merged)
            }
            Self::PrimaryOnly => {
                results.first().and_then(|r| r.result.as_ref().ok()).cloned().unwrap_or(Value::Null)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamChunk
// ─────────────────────────────────────────────────────────────────────────────

/// A single chunk from a streaming tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub server: String,
    pub sequence: u64,
    pub data: Value,
    pub is_final: bool,
}

impl StreamChunk {
    #[must_use]
    pub fn new(server: impl Into<String>, sequence: u64, data: Value, is_final: bool) -> Self {
        Self { server: server.into(), sequence, data, is_final }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamAggregator
// ─────────────────────────────────────────────────────────────────────────────

/// Collects streaming chunks from multiple servers and merges them in order.
pub struct StreamAggregator {
    chunks: Vec<StreamChunk>,
    server_cursors: HashMap<String, u64>,
}

impl StreamAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            server_cursors: HashMap::new(),
        }
    }

    /// Ingest a new chunk.
    pub fn push(&mut self, chunk: StreamChunk) {
        *self.server_cursors.entry(chunk.server.clone()).or_default() = chunk.sequence;
        self.chunks.push(chunk);
    }

    /// Return all chunks sorted by (sequence, server).
    #[must_use]
    pub fn ordered_chunks(&self) -> Vec<&StreamChunk> {
        let mut sorted: Vec<&StreamChunk> = self.chunks.iter().collect();
        sorted.sort_by_key(|c| (c.sequence, c.server.as_str()));
        sorted
    }

    /// Collect all final data into a JSON array.
    #[must_use]
    pub fn collect_all(&self) -> Value {
        let data: Vec<Value> = self
            .ordered_chunks()
            .iter()
            .map(|c| c.data.clone())
            .collect();
        serde_json::json!({ "chunks": data, "count": data.len() })
    }

    /// Returns `true` when all servers have sent their final chunk.
    #[must_use]
    pub fn is_complete(&self, expected_servers: &[String]) -> bool {
        expected_servers.iter().all(|s| {
            self.chunks.iter().any(|c| &c.server == s && c.is_final)
        })
    }

    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

impl Default for StreamAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolAggregator
// ─────────────────────────────────────────────────────────────────────────────

/// Central aggregator: builds a unified tool surface from multiple servers.
pub struct ToolAggregator {
    /// Tool map: bare name → AggregatedTool.
    tools: DashMap<String, AggregatedTool>,
    /// Qualified name map: "server::tool" → AggregatedTool.
    qualified: DashMap<String, AggregatedTool>,
    /// Conflict resolution policy.
    conflict_policy: ConflictPolicy,
    /// Default forward context injected into every call.
    default_ctx: ForwardContext,
    /// Per-server priorities (higher = preferred).
    server_priorities: HashMap<String, u32>,
}

impl ToolAggregator {
    #[must_use]
    pub fn new(conflict_policy: ConflictPolicy) -> Self {
        Self {
            tools: DashMap::new(),
            qualified: DashMap::new(),
            conflict_policy,
            default_ctx: ForwardContext::new(),
            server_priorities: HashMap::new(),
        }
    }

    /// Set the priority for a server (higher = preferred in conflict resolution).
    pub fn set_server_priority(&mut self, server: impl Into<String>, priority: u32) {
        self.server_priorities.insert(server.into(), priority);
    }

    /// Set the default forward context.
    pub fn set_default_context(&mut self, ctx: ForwardContext) {
        self.default_ctx = ctx;
    }

    /// Register all tools from a server.
    pub fn register_server_tools(
        &self,
        server_name: &str,
        tools: &[(String, String, Value)], // (name, description, schema)
        priority: u32,
    ) -> Result<Vec<String>, FederationError> {
        let mut registered = Vec::new();
        for (name, desc, schema) in tools {
            let tool = AggregatedTool::new(server_name, name, desc, schema.clone(), priority);
            let qualified_key = tool.qualified_name.clone();

            // Register by qualified name unconditionally
            self.qualified.insert(qualified_key.clone(), tool.clone());

            // Register by bare name according to conflict policy
            match &self.conflict_policy {
                ConflictPolicy::FullyQualified => {
                    // Only qualified names accessible
                }
                ConflictPolicy::Reject => {
                    if self.tools.contains_key(name.as_str()) {
                        return Err(FederationError::ToolNotFound(format!(
                            "conflict: tool '{name}' already registered (policy=Reject)"
                        )));
                    }
                    self.tools.insert(name.clone(), tool);
                }
                ConflictPolicy::Priority => {
                    let should_insert = match self.tools.get(name.as_str()) {
                        None => true,
                        Some(existing) => priority > existing.priority,
                    };
                    if should_insert {
                        let mut t = tool.clone();
                        if let Some(existing) = self.tools.get(name.as_str()) {
                            for s in &existing.server_providers {
                                t.add_provider(s.clone());
                            }
                        }
                        self.tools.insert(name.clone(), t);
                    } else if let Some(mut existing) = self.tools.get_mut(name.as_str()) {
                        existing.add_provider(server_name);
                    }
                }
                ConflictPolicy::FirstWins => {
                    if !self.tools.contains_key(name.as_str()) {
                        self.tools.insert(name.clone(), tool);
                    } else if let Some(mut existing) = self.tools.get_mut(name.as_str()) {
                        existing.add_provider(server_name);
                    }
                }
                ConflictPolicy::MergeAll => {
                    if let Some(mut existing) = self.tools.get_mut(name.as_str()) {
                        existing.add_provider(server_name);
                    } else {
                        self.tools.insert(name.clone(), tool);
                    }
                }
            }
            registered.push(qualified_key);
        }
        Ok(registered)
    }

    /// Remove all tools from a server (e.g. on disconnect).
    pub fn deregister_server(&self, server_name: &str) {
        // Remove from qualified map
        self.qualified.retain(|k, _| !k.starts_with(&format!("{server_name}::")));
        // Remove or update bare-name map
        let to_remove: Vec<String> = self
            .tools
            .iter()
            .filter(|e| e.value().primary_server == server_name)
            .map(|e| e.key().clone())
            .collect();
        for key in to_remove {
            if let Some(mut entry) = self.tools.get_mut(&key) {
                entry.server_providers.retain(|s| s != server_name);
                if entry.server_providers.is_empty() {
                    drop(entry);
                    self.tools.remove(&key);
                } else {
                    entry.primary_server = entry.server_providers[0].clone();
                    entry.qualified_name =
                        format!("{}::{}", entry.primary_server, entry.name);
                }
            }
        }
    }

    /// Lookup a tool by bare or qualified name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<AggregatedTool> {
        // Try qualified first
        if let Some(t) = self.qualified.get(name) {
            return Some(t.clone());
        }
        // Try bare name
        self.tools.get(name).map(|t| t.clone())
    }

    /// List all tools (bare-name surface).
    #[must_use]
    pub fn list_tools(&self) -> Vec<AggregatedTool> {
        self.tools.iter().map(|e| e.value().clone()).collect()
    }

    /// List all qualified tools across all servers.
    #[must_use]
    pub fn list_qualified(&self) -> Vec<AggregatedTool> {
        self.qualified.iter().map(|e| e.value().clone()).collect()
    }

    /// List conflicting tools (same bare name, multiple servers).
    #[must_use]
    pub fn conflicts(&self) -> Vec<AggregatedTool> {
        self.tools
            .iter()
            .filter(|e| e.value().has_conflict)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Build forwarding params for a tool call (injects context).
    #[must_use]
    pub fn build_forward_params(&self, params: Value, extra_ctx: Option<&ForwardContext>) -> Value {
        let ctx = extra_ctx.unwrap_or(&self.default_ctx);
        ctx.inject_into(params)
    }

    /// Total number of unique tool names (bare surface).
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Total number of qualified tool registrations.
    #[must_use]
    pub fn qualified_count(&self) -> usize {
        self.qualified.len()
    }

    /// Which servers provide the given bare tool name?
    #[must_use]
    pub fn servers_for_tool(&self, name: &str) -> Vec<String> {
        self.tools
            .get(name)
            .map(|t| t.server_providers.clone())
            .unwrap_or_default()
    }

    /// Determine the target server for a call, applying conflict resolution.
    #[must_use]
    pub fn resolve_target(&self, tool_name: &str) -> Option<String> {
        // Qualified name → direct lookup
        if let Some(t) = self.qualified.get(tool_name) {
            return Some(t.primary_server.clone());
        }
        // Bare name
        self.tools.get(tool_name).map(|t| t.primary_server.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResultMerger (standalone helper)
// ─────────────────────────────────────────────────────────────────────────────

/// Standalone helper to merge heterogeneous results.
pub struct ResultMerger;

impl ResultMerger {
    /// Merge results using the given strategy.
    #[must_use]
    pub fn merge(results: Vec<ServerResult>, strategy: &MergeStrategy) -> Value {
        strategy.apply(&results)
    }

    /// Deduplicate items in a JSON array by a key field.
    #[must_use]
    pub fn deduplicate(values: Vec<Value>, key_field: &str) -> Vec<Value> {
        let mut seen = std::collections::HashSet::new();
        values
            .into_iter()
            .filter(|v| {
                if let Some(k) = v.get(key_field) {
                    seen.insert(k.to_string())
                } else {
                    true // keep items with no key
                }
            })
            .collect()
    }

    /// Rank results by a numeric score field (descending).
    #[must_use]
    pub fn rank_by_score(mut values: Vec<Value>, score_field: &str) -> Vec<Value> {
        values.sort_by(|a, b| {
            let sa = a.get(score_field).and_then(Value::as_f64).unwrap_or(0.0);
            let sb = b.get(score_field).and_then(Value::as_f64).unwrap_or(0.0);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
        values
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(names: &[&str]) -> Vec<(String, String, Value)> {
        names
            .iter()
            .map(|n| (n.to_string(), format!("desc {n}"), serde_json::json!({})))
            .collect()
    }

    #[test]
    fn test_register_and_lookup_bare() {
        let agg = ToolAggregator::new(ConflictPolicy::FirstWins);
        agg.register_server_tools("ghidra", &tools(&["decompile"]), 10).unwrap();
        let t = agg.lookup("decompile").unwrap();
        assert_eq!(t.primary_server, "ghidra");
    }

    #[test]
    fn test_register_and_lookup_qualified() {
        let agg = ToolAggregator::new(ConflictPolicy::FirstWins);
        agg.register_server_tools("ghidra", &tools(&["decompile"]), 10).unwrap();
        let t = agg.lookup("ghidra::decompile").unwrap();
        assert_eq!(t.name, "decompile");
    }

    #[test]
    fn test_conflict_first_wins() {
        let agg = ToolAggregator::new(ConflictPolicy::FirstWins);
        agg.register_server_tools("ghidra", &tools(&["disasm"]), 10).unwrap();
        agg.register_server_tools("ida", &tools(&["disasm"]), 10).unwrap();
        let t = agg.lookup("disasm").unwrap();
        assert_eq!(t.primary_server, "ghidra");
        assert!(t.has_conflict);
        assert_eq!(agg.conflicts().len(), 1);
    }

    #[test]
    fn test_conflict_priority() {
        let agg = ToolAggregator::new(ConflictPolicy::Priority);
        agg.register_server_tools("ghidra", &tools(&["disasm"]), 5).unwrap();
        agg.register_server_tools("ida", &tools(&["disasm"]), 20).unwrap();
        let t = agg.lookup("disasm").unwrap();
        assert_eq!(t.primary_server, "ida");
    }

    #[test]
    fn test_conflict_reject() {
        let agg = ToolAggregator::new(ConflictPolicy::Reject);
        agg.register_server_tools("ghidra", &tools(&["disasm"]), 10).unwrap();
        let err = agg.register_server_tools("ida", &tools(&["disasm"]), 10);
        assert!(err.is_err());
    }

    #[test]
    fn test_deregister_server() {
        let agg = ToolAggregator::new(ConflictPolicy::FirstWins);
        agg.register_server_tools("ghidra", &tools(&["decompile"]), 10).unwrap();
        agg.deregister_server("ghidra");
        assert!(agg.lookup("decompile").is_none());
        assert!(agg.lookup("ghidra::decompile").is_none());
    }

    #[test]
    fn test_merge_first_success() {
        let results = vec![
            ServerResult::error("s1", "fail", 10),
            ServerResult::success("s2", serde_json::json!({"ok": true}), 20),
        ];
        let v = MergeStrategy::FirstSuccess.apply(&results);
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn test_merge_concat_arrays() {
        let results = vec![
            ServerResult::success("s1", serde_json::json!([1, 2]), 10),
            ServerResult::success("s2", serde_json::json!([3, 4]), 10),
        ];
        let v = MergeStrategy::ConcatArrays.apply(&results);
        assert_eq!(v["count"], 4);
    }

    #[test]
    fn test_merge_objects() {
        let results = vec![
            ServerResult::success("s1", serde_json::json!({"a": 1}), 10),
            ServerResult::success("s2", serde_json::json!({"b": 2}), 10),
        ];
        let v = MergeStrategy::MergeObjects.apply(&results);
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn test_forward_context_inject() {
        let ctx = ForwardContext::new().with_session("sess-1").with_binary("/bin/foo");
        let params = serde_json::json!({"address": "0x1000"});
        let injected = ctx.inject_into(params);
        assert_eq!(injected["__rustre_ctx"]["session_id"], "sess-1");
        assert_eq!(injected["__rustre_ctx"]["binary_path"], "/bin/foo");
    }

    #[test]
    fn test_forward_context_strip() {
        let params = serde_json::json!({"x": 1, "__rustre_ctx": {"session_id": "s"}});
        let stripped = ForwardContext::strip_from(params);
        assert!(stripped.get("__rustre_ctx").is_none());
        assert_eq!(stripped["x"], 1);
    }

    #[test]
    fn test_stream_aggregator() {
        let mut agg = StreamAggregator::new();
        agg.push(StreamChunk::new("s1", 0, serde_json::json!({"a": 1}), false));
        agg.push(StreamChunk::new("s1", 1, serde_json::json!({"b": 2}), true));
        assert_eq!(agg.chunk_count(), 2);
        assert!(agg.is_complete(&["s1".into()]));
        assert!(!agg.is_complete(&["s1".into(), "s2".into()]));
    }

    #[test]
    fn test_result_merger_deduplicate() {
        let items = vec![
            serde_json::json!({"addr": "0x100", "name": "foo"}),
            serde_json::json!({"addr": "0x100", "name": "foo"}),
            serde_json::json!({"addr": "0x200", "name": "bar"}),
        ];
        let deduped = ResultMerger::deduplicate(items, "addr");
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_result_merger_rank() {
        let items = vec![
            serde_json::json!({"name": "b", "score": 0.5}),
            serde_json::json!({"name": "a", "score": 0.9}),
            serde_json::json!({"name": "c", "score": 0.1}),
        ];
        let ranked = ResultMerger::rank_by_score(items, "score");
        assert_eq!(ranked[0]["name"], "a");
        assert_eq!(ranked[2]["name"], "c");
    }

    #[test]
    fn test_aggregation_result_any_success() {
        let results = vec![
            ServerResult::error("s1", "fail", 5),
            ServerResult::success("s2", serde_json::json!({}), 10),
        ];
        let ar = AggregationResult::build("tool", results, MergeStrategy::FirstSuccess);
        assert!(ar.any_success());
        assert!(!ar.all_success());
    }

    #[test]
    fn test_conflict_policy_fully_qualified_no_bare() {
        let agg = ToolAggregator::new(ConflictPolicy::FullyQualified);
        agg.register_server_tools("srv", &tools(&["ping"]), 10).unwrap();
        // Bare name should not be accessible
        assert!(agg.lookup("ping").is_none());
        // Qualified name should work
        assert!(agg.lookup("srv::ping").is_some());
    }
}
