//! MCP wrappers for the rustre-rs_sym crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct RsSymCoreBackendsRegistryTool;
impl RsSymCoreBackendsRegistryTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_backends_registry".to_string(),
            description: "List all wired symbol-backend sub-crates.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {}}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreBackendsRegistryTool {
    async fn call(&self, _args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let regs = rustre_symbols::backends::registry();
        let items: Vec<_> = regs.iter().map(|b| serde_json::json!({
            "crate_name": b.crate_name, "format": b.format, "provider_type": b.provider_type,
        })).collect();
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "count": items.len(), "backends": items,
            "source": "rustre_symbols::backends::registry" }).to_string()))
    }
}

pub struct RsSymCoreSymbolSourcePriorityTool;
impl RsSymCoreSymbolSourcePriorityTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_symbol_source_priority".to_string(),
            description: "Return the trust-priority of a SymbolSource variant.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "source": { "type": "string" }}}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreSymbolSourcePriorityTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let s = args.get("source").and_then(serde_json::Value::as_str).unwrap_or("Manual");
        let src = match s {
            "Pdb" => rustre_symbols::SymbolSource::Pdb,
            "Dwarf" => rustre_symbols::SymbolSource::Dwarf,
            "CodeView" => rustre_symbols::SymbolSource::CodeView,
            "Stabs" => rustre_symbols::SymbolSource::Stabs,
            "Flirt" => rustre_symbols::SymbolSource::Flirt,
            "Manual" => rustre_symbols::SymbolSource::Manual,
            "Inferred" => rustre_symbols::SymbolSource::Inferred,
            "Import" => rustre_symbols::SymbolSource::Import,
            "Export" => rustre_symbols::SymbolSource::Export,
            "Elf" => rustre_symbols::SymbolSource::Elf,
            "Pe" => rustre_symbols::SymbolSource::Pe,
            "Ai" => rustre_symbols::SymbolSource::Ai,
            _ => return Err(rustre_mcp_server::McpError::InvalidParams(format!("unknown source: {s}"))),
        };
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "source": s, "priority": src.priority(),
            "impl": "rustre_symbols::SymbolSource::priority" }).to_string()))
    }
}

pub struct RsSymCoreSyntheticNamesTool;
impl RsSymCoreSyntheticNamesTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_synthetic_names".to_string(),
            description: "Compute synthetic sub_/byte_/loc_/dword_/qword_ names for an address.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "addr": { "type": "integer" }}}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreSyntheticNamesTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let addr = args.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
        use rustre_symbols::SyntheticSymbolGen as G;
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "function": G::function_name(addr), "data": G::data_name(addr),
            "label": G::label_name(addr), "dword": G::dword_name(addr),
            "qword": G::qword_name(addr),
            "source": "rustre_symbols::SyntheticSymbolGen"
        }).to_string()))
    }
}

pub struct RsSymCoreFunctionBoundaryTool;
impl RsSymCoreFunctionBoundaryTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_function_boundary".to_string(),
            description: "Compute size + contains + overlap for a FunctionBoundary.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "start": { "type": "integer" }, "end": { "type": "integer" },
                "probe": { "type": "integer" },
                "other_start": { "type": "integer" }, "other_end": { "type": "integer" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreFunctionBoundaryTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let s = args.get("start").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let e = args.get("end").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let probe = args.get("probe").and_then(serde_json::Value::as_u64).unwrap_or(s);
        let os = args.get("other_start").and_then(serde_json::Value::as_u64).unwrap_or(e);
        let oe = args.get("other_end").and_then(serde_json::Value::as_u64).unwrap_or(e);
        let a = rustre_symbols::FunctionBoundary::new(s, e, "a".into());
        let b = rustre_symbols::FunctionBoundary::new(os, oe, "b".into());
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "size": a.size(), "contains_probe": a.contains(probe),
            "overlaps_other": a.overlaps(&b),
            "source": "rustre_symbols::FunctionBoundary"
        }).to_string()))
    }
}

pub struct RsSymCoreStoreRoundtripTool;
impl RsSymCoreStoreRoundtripTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_store_roundtrip".to_string(),
            description: "Insert symbols into SymbolStore and return CSV/MAP exports.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "symbols": { "type": "array", "items": { "type": "object" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreStoreRoundtripTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut store = rustre_symbols::SymbolStore::new();
        let mut inserted = 0usize;
        if let Some(arr) = args.get("symbols").and_then(serde_json::Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(serde_json::Value::as_str).unwrap_or("s").to_string();
                let addr = v.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let sym = rustre_symbols::Symbol::new(name, addr, rustre_symbols::SymKind::Function);
                if store.insert(sym).is_ok() { inserted += 1; }
            }
        }
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "inserted": inserted, "len": store.len(),
            "csv": store.export_as_csv(), "map": store.export_as_map(),
            "source": "rustre_symbols::SymbolStore"
        }).to_string()))
    }
}

pub struct RsSymCoreCacheLruTool;
impl RsSymCoreCacheLruTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_cache_lru".to_string(),
            description: "Exercise SymbolCache LRU with the given capacity and address sequence.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "capacity": { "type": "integer" },
                "addrs": { "type": "array", "items": { "type": "integer" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreCacheLruTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let cap = args.get("capacity").and_then(serde_json::Value::as_u64).unwrap_or(4) as usize;
        let mut cache = rustre_symbols::SymbolCache::new(cap);
        let mut inserted = 0usize;
        if let Some(arr) = args.get("addrs").and_then(serde_json::Value::as_array) {
            for v in arr {
                let a = v.as_u64().unwrap_or(0);
                let sym = rustre_symbols::Symbol::new(format!("f_{a:x}"), a, rustre_symbols::SymKind::Function);
                cache.insert(a, sym);
                inserted += 1;
            }
        }
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "capacity": cache.capacity(), "len": cache.len(),
            "inserted": inserted, "is_empty": cache.is_empty(),
            "source": "rustre_symbols::SymbolCache"
        }).to_string()))
    }
}

pub struct RsSymCoreTryDemangleTool;
impl RsSymCoreTryDemangleTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_try_demangle".to_string(),
            description: "Try try_demangle heuristics on a name.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "name": { "type": "string" }}}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreTryDemangleTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let n = args.get("name").and_then(serde_json::Value::as_str).unwrap_or("");
        let r = rustre_symbols::try_demangle(n);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "name": n, "demangled": r,
            "source": "rustre_symbols::try_demangle" }).to_string()))
    }
}

pub struct RsSymCorePdbUrlBuildTool;
impl RsSymCorePdbUrlBuildTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_pdb_url_build".to_string(),
            description: "Build a Microsoft symbol-server URL via PdbSymbolServer.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "pdb": { "type": "string" }, "guid": { "type": "string" },
                "age": { "type": "integer" }, "base": { "type": "string" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCorePdbUrlBuildTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let pdb = args.get("pdb").and_then(serde_json::Value::as_str).unwrap_or("ntdll.pdb");
        let guid = args.get("guid").and_then(serde_json::Value::as_str).unwrap_or("AABBCCDD-1122-3344-5566-778899AABBCC");
        let age = args.get("age").and_then(serde_json::Value::as_u64).unwrap_or(1) as u32;
        let srv = if let Some(b) = args.get("base").and_then(serde_json::Value::as_str) {
            rustre_symbols::PdbSymbolServer::new(b)
        } else { rustre_symbols::PdbSymbolServer::msdl() };
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "url": srv.pdb_url(pdb, guid, age), "base": srv.base_url,
            "source": "rustre_symbols::PdbSymbolServer"
        }).to_string()))
    }
}

pub struct RsSymCoreXrefIndexTool;
impl RsSymCoreXrefIndexTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_xref_index".to_string(),
            description: "Insert edges into CrossReferenceIndex and query refs_to/refs_from.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "edges": { "type": "array", "items": { "type": "array", "items": { "type": "integer" }}},
                "query": { "type": "integer" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreXrefIndexTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut idx = rustre_symbols::CrossReferenceIndex::new();
        if let Some(arr) = args.get("edges").and_then(serde_json::Value::as_array) {
            for e in arr {
                let pair = e.as_array().cloned().unwrap_or_default();
                let f = pair.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
                let t = pair.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0);
                idx.add_xref(f, t);
            }
        }
        let q = args.get("query").and_then(serde_json::Value::as_u64).unwrap_or(0);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "query": q, "refs_to": idx.refs_to(q), "refs_from": idx.refs_from(q),
            "ref_count_to": idx.ref_count_to(q),
            "source": "rustre_symbols::CrossReferenceIndex"
        }).to_string()))
    }
}

pub struct RsSymCoreExporterAllTool;
impl RsSymCoreExporterAllTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_exporter_all".to_string(),
            description: "Serialize a list of symbols to JSON/CSV/IDC/MAP via SymbolExporter.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "symbols": { "type": "array", "items": { "type": "object" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreExporterAllTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("symbols").and_then(serde_json::Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(serde_json::Value::as_str).unwrap_or("s").to_string();
                let addr = v.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
                syms.push(rustre_symbols::Symbol::new(name, addr, rustre_symbols::SymKind::Function));
            }
        }
        let json_s = rustre_symbols::SymbolExporter::to_json(&syms)
            .map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?;
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "json": json_s,
            "csv": rustre_symbols::SymbolExporter::to_csv(&syms),
            "idc": rustre_symbols::SymbolExporter::to_idc(&syms),
            "map": rustre_symbols::SymbolExporter::to_map(&syms),
            "count": syms.len(),
            "source": "rustre_symbols::SymbolExporter"
        }).to_string()))
    }
}

pub struct RsSymCoreStatsTool;
impl RsSymCoreStatsTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_stats".to_string(),
            description: "Compute SymbolStats from a list of {name,addr,kind}.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "symbols": { "type": "array", "items": { "type": "object" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreStatsTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("symbols").and_then(serde_json::Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(serde_json::Value::as_str).unwrap_or("s").to_string();
                let addr = v.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let kind = match v.get("kind").and_then(serde_json::Value::as_str).unwrap_or("Function") {
                    "Function" => rustre_symbols::SymKind::Function,
                    "Data" => rustre_symbols::SymKind::Data,
                    "Label" => rustre_symbols::SymKind::Label,
                    "Section" => rustre_symbols::SymKind::Section,
                    "File" => rustre_symbols::SymKind::File,
                    "Type" => rustre_symbols::SymKind::Type,
                    "Namespace" => rustre_symbols::SymKind::Namespace,
                    "TLS" => rustre_symbols::SymKind::TLS,
                    "IFunc" => rustre_symbols::SymKind::IFunc,
                    "Common" => rustre_symbols::SymKind::Common,
                    _ => rustre_symbols::SymKind::Unknown,
                };
                syms.push(rustre_symbols::Symbol::new(name, addr, kind));
            }
        }
        let s = rustre_symbols::SymbolStats::from_symbols(&syms);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "total": s.total, "functions": s.functions, "data": s.data,
            "labels": s.labels, "sections": s.sections, "files": s.files,
            "types": s.types, "tls": s.tls, "ifunc": s.ifunc,
            "common": s.common, "unknown": s.unknown,
            "display": s.to_string(),
            "source": "rustre_symbols::SymbolStats"
        }).to_string()))
    }
}

pub struct RsSymCoreSymbolFilterTool;
impl RsSymCoreSymbolFilterTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_symbol_filter_apply".to_string(),
            description: "Apply a SymbolFilter (name_prefix) to a set of symbols.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "names": { "type": "array", "items": { "type": "string" }},
                "prefix": { "type": "string" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreSymbolFilterTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("names").and_then(serde_json::Value::as_array) {
            for (i, v) in arr.iter().enumerate() {
                let n = v.as_str().unwrap_or("s").to_string();
                syms.push(rustre_symbols::Symbol::new(n, i as u64 * 16, rustre_symbols::SymKind::Function));
            }
        }
        let prefix = args.get("prefix").and_then(serde_json::Value::as_str).unwrap_or("");
        let filt = rustre_symbols::SymbolFilter::new().name_prefix(prefix);
        let out = filt.apply(&syms);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "input_count": syms.len(), "output_count": out.len(),
            "matched": out.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            "source": "rustre_symbols::SymbolFilter"
        }).to_string()))
    }
}

pub struct RsSymCoreAddrMapTool;
impl RsSymCoreAddrMapTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_address_map_lookup".to_string(),
            description: "AddressToSymbolMap lookup_exact / lookup_floor.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "addrs": { "type": "array", "items": { "type": "integer" }},
                "query": { "type": "integer" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreAddrMapTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("addrs").and_then(serde_json::Value::as_array) {
            for v in arr {
                let a = v.as_u64().unwrap_or(0);
                syms.push(rustre_symbols::Symbol::new(format!("f_{a:x}"), a, rustre_symbols::SymKind::Function));
            }
        }
        let map = rustre_symbols::AddressToSymbolMap::from_symbols(&syms);
        let q = args.get("query").and_then(serde_json::Value::as_u64).unwrap_or(0);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "query": q,
            "exact": map.lookup_exact(q).map(|s| s.name.clone()),
            "floor": map.lookup_floor(q).map(|s| s.name.clone()),
            "total": map.all_symbols().len(),
            "source": "rustre_symbols::AddressToSymbolMap"
        }).to_string()))
    }
}

pub struct RsSymCoreImportTableTool;
impl RsSymCoreImportTableTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_import_table_group".to_string(),
            description: "Build ImportTable and group by module.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "imports": { "type": "array", "items": { "type": "string" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreImportTableTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("imports").and_then(serde_json::Value::as_array) {
            for (i, v) in arr.iter().enumerate() {
                let n = v.as_str().unwrap_or("f").to_string();
                syms.push(rustre_symbols::Symbol::new(n, i as u64 * 8, rustre_symbols::SymKind::Function));
            }
        }
        let t = rustre_symbols::ImportTable::from_symbols(&syms);
        let modules: Vec<String> = t.grouped_by_module().keys().cloned().collect();
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "count": t.imports().len(), "modules": modules,
            "source": "rustre_symbols::ImportTable"
        }).to_string()))
    }
}

pub struct RsSymCoreExportTableTool;
impl RsSymCoreExportTableTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_export_table_by_name".to_string(),
            description: "Build ExportTable and query by name.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "exports": { "type": "array", "items": { "type": "string" }},
                "query": { "type": "string" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreExportTableTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("exports").and_then(serde_json::Value::as_array) {
            for (i, v) in arr.iter().enumerate() {
                let n = v.as_str().unwrap_or("e").to_string();
                syms.push(rustre_symbols::Symbol::new(n, (i as u64 + 1) * 16, rustre_symbols::SymKind::Function));
            }
        }
        let t = rustre_symbols::ExportTable::from_symbols(&syms);
        let q = args.get("query").and_then(serde_json::Value::as_str).unwrap_or("");
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "count": t.exports().len(),
            "found": t.by_name(q).map(|s| s.address),
            "source": "rustre_symbols::ExportTable"
        }).to_string()))
    }
}

pub struct RsSymCoreConflictResolveTool;
impl RsSymCoreConflictResolveTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_conflict_resolver".to_string(),
            description: "SymbolConflictResolver.resolve.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "symbols": { "type": "array", "items": { "type": "object" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreConflictResolveTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut syms: Vec<rustre_symbols::Symbol> = Vec::new();
        if let Some(arr) = args.get("symbols").and_then(serde_json::Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(serde_json::Value::as_str).unwrap_or("s").to_string();
                let addr = v.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
                syms.push(rustre_symbols::Symbol::new(name, addr, rustre_symbols::SymKind::Function));
            }
        }
        let input = syms.len();
        let r = rustre_symbols::SymbolConflictResolver::new(rustre_symbols::ConflictStrategy::KeepFirst);
        let out = r.resolve(syms);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "input": input, "resolved": out.len(),
            "source": "rustre_symbols::SymbolConflictResolver"
        }).to_string()))
    }
}

pub struct RsSymCoreDebugMergerTool;
impl RsSymCoreDebugMergerTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_debug_merger".to_string(),
            description: "DebugSymbolMerger.merge/finish.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "batches": { "type": "array", "items": { "type": "array", "items": { "type": "string" }}}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreDebugMergerTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut merger = rustre_symbols::DebugSymbolMerger::new();
        let mut counter = 0u64;
        if let Some(arr) = args.get("batches").and_then(serde_json::Value::as_array) {
            for batch in arr {
                let mut group: Vec<rustre_symbols::Symbol> = Vec::new();
                if let Some(a) = batch.as_array() {
                    for v in a {
                        let n = v.as_str().unwrap_or("s").to_string();
                        counter += 16;
                        group.push(rustre_symbols::Symbol::new(n, counter, rustre_symbols::SymKind::Function));
                    }
                }
                merger.merge(group);
            }
        }
        let is_empty = merger.is_empty();
        let len = merger.len();
        let finished = merger.finish();
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "len": len, "is_empty": is_empty, "finished": finished.len(),
            "source": "rustre_symbols::DebugSymbolMerger"
        }).to_string()))
    }
}

pub struct RsSymCoreUnifiedTableTool;
impl RsSymCoreUnifiedTableTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_unified_table_ops".to_string(),
            description: "UnifiedSymbolTable fill/iter_by_address.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "addrs": { "type": "array", "items": { "type": "integer" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreUnifiedTableTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut table = rustre_symbols::UnifiedSymbolTable::new();
        let addrs: Vec<u64> = args.get("addrs").and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();
        rustre_symbols::SyntheticSymbolGen::fill_functions(&mut table, &addrs);
        let ordered: Vec<u64> = table.iter_by_address().map(|s| s.address).collect();
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "len": table.len(), "is_empty": table.is_empty(),
            "ordered_addrs": ordered,
            "source": "rustre_symbols::UnifiedSymbolTable"
        }).to_string()))
    }
}

pub struct RsSymCoreDemanglerPipelineTool;
impl RsSymCoreDemanglerPipelineTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_demangler_pipeline".to_string(),
            description: "DemanglerPipeline batch demangle.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "names": { "type": "array", "items": { "type": "string" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreDemanglerPipelineTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut pipe = rustre_symbols::DemanglerPipeline::new();
        let names: Vec<String> = args.get("names").and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let mut results = Vec::new();
        for n in &names {
            results.push(serde_json::json!({ "name": n, "demangled": pipe.demangle(n) }));
        }
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "count": names.len(), "results": results,
            "source": "rustre_symbols::DemanglerPipeline"
        }).to_string()))
    }
}

pub struct RsSymCoreSymbolStoreExportTool;
impl RsSymCoreSymbolStoreExportTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_store_export_map".to_string(),
            description: "SymbolStore export_as_map / export_as_csv.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "symbols": { "type": "array", "items": { "type": "object" }}
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreSymbolStoreExportTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut store = rustre_symbols::SymbolStore::new();
        if let Some(arr) = args.get("symbols").and_then(serde_json::Value::as_array) {
            for v in arr {
                let name = v.get("name").and_then(serde_json::Value::as_str).unwrap_or("s").to_string();
                let addr = v.get("addr").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let sym = rustre_symbols::Symbol::new(name, addr, rustre_symbols::SymKind::Function);
                store.upsert(sym);
            }
        }
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "map": store.export_as_map(),
            "csv": store.export_as_csv(),
            "source": "rustre_symbols::SymbolStore"
        }).to_string()))
    }
}

pub struct RsSymCoreInMemoryProviderTool;
impl RsSymCoreInMemoryProviderTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "rustre_symbols_core_in_memory_provider".to_string(),
            description: "InMemorySymbolProvider ops.".to_string(),
            input_schema: serde_json::json!({ "type": "object", "properties": {
                "names": { "type": "array", "items": { "type": "string" }},
                "rename_from": { "type": "string" },
                "rename_to": { "type": "string" },
                "remove": { "type": "string" }
            }}),
            parameters: serde_json::Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for RsSymCoreInMemoryProviderTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut prov = rustre_symbols::InMemorySymbolProvider::new();
        if let Some(arr) = args.get("names").and_then(serde_json::Value::as_array) {
            for (i, v) in arr.iter().enumerate() {
                let n = v.as_str().unwrap_or("s").to_string();
                prov.add(rustre_symbols::Symbol::new(n, (i as u64 + 1) * 16, rustre_symbols::SymKind::Function));
            }
        }
        prov.sort_by_address();
        let renamed = if let (Some(a), Some(b)) = (
            args.get("rename_from").and_then(serde_json::Value::as_str),
            args.get("rename_to").and_then(serde_json::Value::as_str),
        ) { prov.rename(a, b.to_string()) } else { false };
        let removed = args.get("remove").and_then(serde_json::Value::as_str)
            .map(|n| prov.remove_by_name(n)).unwrap_or(false);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "renamed": renamed, "removed": removed,
            "source": "rustre_symbols::InMemorySymbolProvider"
        }).to_string()))
    }
}
// TTD_RECORDER_EXTRA_TOOLS_MARK
// EMU_QILING_EXTRA_TOOLS_MARK
// TTD_QUERY_EXTRA_TOOLS_MARK
// (elf wrappers added, triage-entropy shannon wrappers added)
//
// Each tool here exposes a previously-implemented analysis primitive
// (gap A / D / F / G / H / I / J / K) as a structured-output MCP tool.
// Handlers are thin wrappers that delegate to the underlying analysis
// crate and return JSON suitable for direct consumption by external
// clients (Claude, IDE plugins, agents).

pub struct RsSymV3SymbolNewTool;
impl RsSymV3SymbolNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_symbol_new".to_string(), description: "Build a Symbol via rustre_symbols::Symbol::new and report display_name.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"address":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3SymbolNewTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("sym").to_string(); let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let s = rustre_symbols::Symbol::new(name.clone(), addr, rustre_symbols::SymKind::Function); Ok(ToolResult::text(json!({"name":name,"address":addr,"display_name":s.display_name(),"kind":format!("{:?}",s.kind),"source":"rustre_symbols::Symbol::new"}).to_string())) } }

pub struct RsSymV3SymbolContainsTool;
impl RsSymV3SymbolContainsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_symbol_contains".to_string(), description: "Set size on a Symbol and test contains(addr) and end_address.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"size":{"type":"integer"},"probe":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3SymbolContainsTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x10); let probe = args.get("probe").and_then(Value::as_u64).unwrap_or(addr); let mut s = rustre_symbols::Symbol::new("s".to_string(), addr, rustre_symbols::SymKind::Function); s.size = Some(size); Ok(ToolResult::text(json!({"contains":s.contains(probe),"end_address":s.end_address(),"source":"rustre_symbols::Symbol::contains"}).to_string())) } }

pub struct RsSymV3SymbolTableAddRemoveTool;
impl RsSymV3SymbolTableAddRemoveTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_symbol_table_add_remove".to_string(), description: "SymbolTable: add two symbols, remove one by name, return counts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3SymbolTableAddRemoveTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut p = rustre_symbols::InMemorySymbolProvider::new(); p.add(rustre_symbols::Symbol::new("a".into(), 0x1000, rustre_symbols::SymKind::Function)); p.add(rustre_symbols::Symbol::new("b".into(), 0x2000, rustre_symbols::SymKind::Data)); let before = p.len(); let removed = p.remove_by_name("a"); Ok(ToolResult::text(json!({"before":before,"removed":removed,"after":p.len(),"source":"rustre_symbols::InMemorySymbolProvider::remove_by_name"}).to_string())) } }

pub struct RsSymV3SymbolCacheOpsTool;
impl RsSymV3SymbolCacheOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_symbol_cache_ops".to_string(), description: "SymbolCache insert/get/clear round-trip.".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3SymbolCacheOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(4) as usize; let mut c = rustre_symbols::SymbolCache::new(cap); let s = rustre_symbols::Symbol::new("x".into(), 0x1000, rustre_symbols::SymKind::Function); c.insert(0x1000, s); let hit = c.get(0x1000).is_some(); let miss = c.get(0x9999).is_some(); c.clear(); let after = c.get(0x1000).is_some(); Ok(ToolResult::text(json!({"hit":hit,"miss":miss,"after_clear":after,"source":"rustre_symbols::SymbolCache"}).to_string())) } }

pub struct RsSymV3StoreFindOpsTool;
impl RsSymV3StoreFindOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_store_find_ops".to_string(), description: "SymbolStore: insert two symbols and query find_by_prefix + find_in_range.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3StoreFindOpsTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut st = rustre_symbols::SymbolStore::new(); st.upsert(rustre_symbols::Symbol::new("foo_a".into(), 0x1000, rustre_symbols::SymKind::Function)); st.upsert(rustre_symbols::Symbol::new("foo_b".into(), 0x2000, rustre_symbols::SymKind::Function)); st.upsert(rustre_symbols::Symbol::new("bar".into(), 0x3000, rustre_symbols::SymKind::Data)); let prefix = st.find_by_prefix("foo_").len(); let range = st.find_in_range(0x1000, 0x2500).len(); Ok(ToolResult::text(json!({"prefix_count":prefix,"range_count":range,"source":"rustre_symbols::SymbolStore::find_by_prefix"}).to_string())) } }

pub struct RsSymV3StoreExportCsvTool;
impl RsSymV3StoreExportCsvTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_store_export_csv".to_string(), description: "Export a small SymbolStore to CSV via export_as_csv.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3StoreExportCsvTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut st = rustre_symbols::SymbolStore::new(); st.upsert(rustre_symbols::Symbol::new("main".into(), 0x1000, rustre_symbols::SymKind::Function)); let csv = st.export_as_csv(); let lines = csv.lines().count(); Ok(ToolResult::text(json!({"lines":lines,"len":csv.len(),"source":"rustre_symbols::SymbolStore::export_as_csv"}).to_string())) } }

pub struct RsSymV3CrossRefIndexOpsTool;
impl RsSymV3CrossRefIndexOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_cross_ref_index_ops".to_string(), description: "CrossReferenceIndex: add xrefs and query refs_to/refs_from/ref_count_to.".to_string(), input_schema: json!({"type":"object","properties":{"to":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3CrossRefIndexOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let to = args.get("to").and_then(Value::as_u64).unwrap_or(0x4000); let mut x = rustre_symbols::CrossReferenceIndex::new(); x.add_xref(0x1000, to); x.add_xref(0x2000, to); Ok(ToolResult::text(json!({"refs_to":x.refs_to(to),"refs_from":x.refs_from(0x1000),"ref_count_to":x.ref_count_to(to),"source":"rustre_symbols::CrossReferenceIndex"}).to_string())) } }

pub struct RsSymV3PdbServerUrlTool;
impl RsSymV3PdbServerUrlTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_pdb_server_url".to_string(), description: "Build a symbol-server PDB URL with PdbSymbolServer::pdb_url.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"string"},"pdb":{"type":"string"},"guid":{"type":"string"},"age":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3PdbServerUrlTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_str).unwrap_or("https://msdl.microsoft.com/download/symbols"); let pdb = args.get("pdb").and_then(Value::as_str).unwrap_or("ntdll.pdb"); let guid = args.get("guid").and_then(Value::as_str).unwrap_or("ABCDEF0123456789ABCDEF0123456789"); let age = args.get("age").and_then(Value::as_u64).unwrap_or(1) as u32; let srv = rustre_symbols::PdbSymbolServer::new(base); Ok(ToolResult::text(json!({"url":srv.pdb_url(pdb, guid, age),"source":"rustre_symbols::PdbSymbolServer::pdb_url"}).to_string())) } }

pub struct RsSymV3SyntheticGenAllTool;
impl RsSymV3SyntheticGenAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_synthetic_gen_all".to_string(), description: "SyntheticSymbolGen: function/data/label/dword/qword name at addr.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3SyntheticGenAllTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let a = args.get("addr").and_then(Value::as_u64).unwrap_or(0x401000); Ok(ToolResult::text(json!({"function":rustre_symbols::SyntheticSymbolGen::function_name(a),"data":rustre_symbols::SyntheticSymbolGen::data_name(a),"label":rustre_symbols::SyntheticSymbolGen::label_name(a),"dword":rustre_symbols::SyntheticSymbolGen::dword_name(a),"qword":rustre_symbols::SyntheticSymbolGen::qword_name(a),"source":"rustre_symbols::SyntheticSymbolGen"}).to_string())) } }

pub struct RsSymV3ExporterAllFormatsTool;
impl RsSymV3ExporterAllFormatsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_exporter_all_formats".to_string(), description: "SymbolExporter: emit JSON/CSV/IDC/MAP for a small symbol set and return sizes.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3ExporterAllFormatsTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let syms = vec![rustre_symbols::Symbol::new("main".into(), 0x1000, rustre_symbols::SymKind::Function), rustre_symbols::Symbol::new("g_state".into(), 0x2000, rustre_symbols::SymKind::Data)]; let j = rustre_symbols::SymbolExporter::to_json(&syms).map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?; let c = rustre_symbols::SymbolExporter::to_csv(&syms); let i = rustre_symbols::SymbolExporter::to_idc(&syms); let m = rustre_symbols::SymbolExporter::to_map(&syms); Ok(ToolResult::text(json!({"json_len":j.len(),"csv_len":c.len(),"idc_len":i.len(),"map_len":m.len(),"source":"rustre_symbols::SymbolExporter"}).to_string())) } }

pub struct RsSymV3TryDemangleTopTool;
impl RsSymV3TryDemangleTopTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_try_demangle_top".to_string(), description: "Top-level rustre_symbols::try_demangle wrapper.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3TryDemangleTopTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("_ZN3foo3barEv"); let out = rustre_symbols::try_demangle(name); Ok(ToolResult::text(json!({"input":name,"demangled":out,"source":"rustre_symbols::try_demangle"}).to_string())) } }

pub struct RsSymV3UnifiedTablePdbUrlListTool;
impl RsSymV3UnifiedTablePdbUrlListTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_v3_unified_table_pdb_url_list".to_string(), description: "UnifiedSymbolTable::pdb_url_list with a fresh (empty) table.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymV3UnifiedTablePdbUrlListTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let base = args.get("base").and_then(Value::as_str).unwrap_or("https://msdl.microsoft.com/download/symbols"); let t = rustre_symbols::UnifiedSymbolTable::new(); Ok(ToolResult::text(json!({"count":t.pdb_url_list(base).len(),"is_empty":t.is_empty(),"source":"rustre_symbols::UnifiedSymbolTable::pdb_url_list"}).to_string())) } }

pub struct RsSymExtTryDemangleTool;
impl RsSymExtTryDemangleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_try_demangle".to_string(), description: "rustre_symbols::try_demangle stateless heuristic.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtTryDemangleTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing name".into()))?; let r = rustre_symbols::try_demangle(name); Ok(ToolResult::text(json!({"input":name,"demangled":r,"ok":r.is_some(),"source":"rustre_symbols::try_demangle"}).to_string())) } }

pub struct RsSymExtDemanglerPipelineTool;
impl RsSymExtDemanglerPipelineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_demangler_pipeline".to_string(), description: "rustre_symbols::DemanglerPipeline::demangle w/ cache.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtDemanglerPipelineTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing name".into()))?; let mut p = rustre_symbols::DemanglerPipeline::new(); let r = p.demangle(name); Ok(ToolResult::text(json!({"input":name,"demangled":r,"ok":r.is_some(),"source":"rustre_symbols::DemanglerPipeline::demangle"}).to_string())) } }

pub struct RsSymExtPdbServerMsdlUrlTool;
impl RsSymExtPdbServerMsdlUrlTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_pdb_server_msdl_url".to_string(), description: "rustre_symbols::PdbSymbolServer::msdl base_url.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtPdbServerMsdlUrlTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = rustre_symbols::PdbSymbolServer::msdl(); Ok(ToolResult::text(json!({"base_url":s.base_url,"source":"rustre_symbols::PdbSymbolServer::msdl"}).to_string())) } }

pub struct RsSymExtPdbServerPdbUrlTool;
impl RsSymExtPdbServerPdbUrlTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_pdb_server_pdb_url".to_string(), description: "rustre_symbols::PdbSymbolServer::pdb_url builder.".to_string(), input_schema: json!({"type":"object","properties":{"pdb_name":{"type":"string"},"guid":{"type":"string"},"age":{"type":"integer"}},"required":["pdb_name","guid","age"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtPdbServerPdbUrlTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let pdb = args.get("pdb_name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing pdb_name".into()))?; let guid = args.get("guid").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing guid".into()))?; let age = u32::try_from(args.get("age").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing age".into()))?).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; let s = rustre_symbols::PdbSymbolServer::msdl(); let url = s.pdb_url(pdb, guid, age); Ok(ToolResult::text(json!({"url":url,"source":"rustre_symbols::PdbSymbolServer::pdb_url"}).to_string())) } }

pub struct RsSymExtSourcePriorityAllTool;
impl RsSymExtSourcePriorityAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_source_priority_all".to_string(), description: "rustre_symbols::SymbolSource::priority for all variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSourcePriorityAllTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_symbols::SymbolSource as S; let all = [S::Pdb, S::Dwarf, S::CodeView, S::Stabs, S::Flirt, S::Manual, S::Inferred, S::Import, S::Export, S::Elf, S::Pe, S::Ai]; let items: Vec<Value> = all.iter().map(|s| json!({"source":s.to_string(),"priority":s.priority()})).collect(); Ok(ToolResult::text(json!({"count":items.len(),"items":items,"source":"rustre_symbols::SymbolSource::priority"}).to_string())) } }

pub struct RsSymExtSyntheticNameFunctionTool;
impl RsSymExtSyntheticNameFunctionTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_synthetic_name_function".to_string(), description: "rustre_symbols::SyntheticSymbolGen::function_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSyntheticNameFunctionTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let n = rustre_symbols::SyntheticSymbolGen::function_name(addr); Ok(ToolResult::text(json!({"name":n,"addr":addr,"source":"rustre_symbols::SyntheticSymbolGen::function_name"}).to_string())) } }

pub struct RsSymExtSyntheticNameDataTool;
impl RsSymExtSyntheticNameDataTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_synthetic_name_data".to_string(), description: "rustre_symbols::SyntheticSymbolGen::data_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSyntheticNameDataTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let n = rustre_symbols::SyntheticSymbolGen::data_name(addr); Ok(ToolResult::text(json!({"name":n,"addr":addr,"source":"rustre_symbols::SyntheticSymbolGen::data_name"}).to_string())) } }

pub struct RsSymExtSyntheticNameLabelTool;
impl RsSymExtSyntheticNameLabelTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_synthetic_name_label".to_string(), description: "rustre_symbols::SyntheticSymbolGen::label_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSyntheticNameLabelTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let n = rustre_symbols::SyntheticSymbolGen::label_name(addr); Ok(ToolResult::text(json!({"name":n,"addr":addr,"source":"rustre_symbols::SyntheticSymbolGen::label_name"}).to_string())) } }

pub struct RsSymExtSyntheticNameDwordTool;
impl RsSymExtSyntheticNameDwordTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_synthetic_name_dword".to_string(), description: "rustre_symbols::SyntheticSymbolGen::dword_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSyntheticNameDwordTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let n = rustre_symbols::SyntheticSymbolGen::dword_name(addr); Ok(ToolResult::text(json!({"name":n,"addr":addr,"source":"rustre_symbols::SyntheticSymbolGen::dword_name"}).to_string())) } }

pub struct RsSymExtSyntheticNameQwordTool;
impl RsSymExtSyntheticNameQwordTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_synthetic_name_qword".to_string(), description: "rustre_symbols::SyntheticSymbolGen::qword_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtSyntheticNameQwordTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let n = rustre_symbols::SyntheticSymbolGen::qword_name(addr); Ok(ToolResult::text(json!({"name":n,"addr":addr,"source":"rustre_symbols::SyntheticSymbolGen::qword_name"}).to_string())) } }

pub struct RsSymExtCrossRefIndexOpsTool;
impl RsSymExtCrossRefIndexOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_cross_ref_index_ops".to_string(), description: "rustre_symbols::CrossReferenceIndex add_xref+refs_to+refs_from+ref_count_to.".to_string(), input_schema: json!({"type":"object","properties":{"edges":{"type":"array","items":{"type":"array","items":{"type":"integer"},"minItems":2,"maxItems":2}},"query":{"type":"integer"}},"required":["edges","query"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtCrossRefIndexOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let edges = args.get("edges").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing edges".into()))?; let q = args.get("query").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing query".into()))?; let mut idx = rustre_symbols::CrossReferenceIndex::new(); for e in edges { if let Some(arr) = e.as_array() { if arr.len() >= 2 { let f = arr[0].as_u64().unwrap_or(0); let t = arr[1].as_u64().unwrap_or(0); idx.add_xref(f, t); } } } Ok(ToolResult::text(json!({"refs_to":idx.refs_to(q),"refs_from":idx.refs_from(q),"ref_count_to":idx.ref_count_to(q),"source":"rustre_symbols::CrossReferenceIndex"}).to_string())) } }

pub struct RsSymExtUnifiedTableAddLookupTool;
impl RsSymExtUnifiedTableAddLookupTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_symbols_ext_unified_table_add_lookup".to_string(), description: "rustre_symbols::UnifiedSymbolTable add + lookup_addr + lookup_name + len.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"addr":{"type":"integer"}},"required":["name","addr"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for RsSymExtUnifiedTableAddLookupTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_symbols::{UnifiedSymbolTable, UnifiedSymbol, SymbolKind, SymbolSource}; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing name".into()))?; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing addr".into()))?; let mut t = UnifiedSymbolTable::new(); t.add(UnifiedSymbol::new(name.to_string(), addr, SymbolKind::Function, SymbolSource::Manual)); let by_addr = t.lookup_addr(addr).map(|s| s.name.clone()); let by_name = t.lookup_name(name).len(); Ok(ToolResult::text(json!({"len":t.len(),"lookup_addr_name":by_addr,"lookup_name_count":by_name,"source":"rustre_symbols::UnifiedSymbolTable"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RsSymCoreBackendsRegistryTool::definition(), Box::new(RsSymCoreBackendsRegistryTool)),
        (RsSymCoreSymbolSourcePriorityTool::definition(), Box::new(RsSymCoreSymbolSourcePriorityTool)),
        (RsSymCoreSyntheticNamesTool::definition(), Box::new(RsSymCoreSyntheticNamesTool)),
        (RsSymCoreFunctionBoundaryTool::definition(), Box::new(RsSymCoreFunctionBoundaryTool)),
        (RsSymCoreStoreRoundtripTool::definition(), Box::new(RsSymCoreStoreRoundtripTool)),
        (RsSymCoreCacheLruTool::definition(), Box::new(RsSymCoreCacheLruTool)),
        (RsSymCoreTryDemangleTool::definition(), Box::new(RsSymCoreTryDemangleTool)),
        (RsSymCorePdbUrlBuildTool::definition(), Box::new(RsSymCorePdbUrlBuildTool)),
        (RsSymCoreXrefIndexTool::definition(), Box::new(RsSymCoreXrefIndexTool)),
        (RsSymCoreExporterAllTool::definition(), Box::new(RsSymCoreExporterAllTool)),
        (RsSymCoreStatsTool::definition(), Box::new(RsSymCoreStatsTool)),
        (RsSymCoreSymbolFilterTool::definition(), Box::new(RsSymCoreSymbolFilterTool)),
        (RsSymCoreAddrMapTool::definition(), Box::new(RsSymCoreAddrMapTool)),
        (RsSymCoreImportTableTool::definition(), Box::new(RsSymCoreImportTableTool)),
        (RsSymCoreExportTableTool::definition(), Box::new(RsSymCoreExportTableTool)),
        (RsSymCoreConflictResolveTool::definition(), Box::new(RsSymCoreConflictResolveTool)),
        (RsSymCoreDebugMergerTool::definition(), Box::new(RsSymCoreDebugMergerTool)),
        (RsSymCoreUnifiedTableTool::definition(), Box::new(RsSymCoreUnifiedTableTool)),
        (RsSymCoreDemanglerPipelineTool::definition(), Box::new(RsSymCoreDemanglerPipelineTool)),
        (RsSymCoreSymbolStoreExportTool::definition(), Box::new(RsSymCoreSymbolStoreExportTool)),
        (RsSymCoreInMemoryProviderTool::definition(), Box::new(RsSymCoreInMemoryProviderTool)),
        (RsSymV3SymbolNewTool::definition(), Box::new(RsSymV3SymbolNewTool)),
        (RsSymV3SymbolContainsTool::definition(), Box::new(RsSymV3SymbolContainsTool)),
        (RsSymV3SymbolTableAddRemoveTool::definition(), Box::new(RsSymV3SymbolTableAddRemoveTool)),
        (RsSymV3SymbolCacheOpsTool::definition(), Box::new(RsSymV3SymbolCacheOpsTool)),
        (RsSymV3StoreFindOpsTool::definition(), Box::new(RsSymV3StoreFindOpsTool)),
        (RsSymV3StoreExportCsvTool::definition(), Box::new(RsSymV3StoreExportCsvTool)),
        (RsSymV3CrossRefIndexOpsTool::definition(), Box::new(RsSymV3CrossRefIndexOpsTool)),
        (RsSymV3PdbServerUrlTool::definition(), Box::new(RsSymV3PdbServerUrlTool)),
        (RsSymV3SyntheticGenAllTool::definition(), Box::new(RsSymV3SyntheticGenAllTool)),
        (RsSymV3ExporterAllFormatsTool::definition(), Box::new(RsSymV3ExporterAllFormatsTool)),
        (RsSymV3TryDemangleTopTool::definition(), Box::new(RsSymV3TryDemangleTopTool)),
        (RsSymV3UnifiedTablePdbUrlListTool::definition(), Box::new(RsSymV3UnifiedTablePdbUrlListTool)),
        (RsSymExtTryDemangleTool::definition(), Box::new(RsSymExtTryDemangleTool)),
        (RsSymExtDemanglerPipelineTool::definition(), Box::new(RsSymExtDemanglerPipelineTool)),
        (RsSymExtPdbServerMsdlUrlTool::definition(), Box::new(RsSymExtPdbServerMsdlUrlTool)),
        (RsSymExtPdbServerPdbUrlTool::definition(), Box::new(RsSymExtPdbServerPdbUrlTool)),
        (RsSymExtSourcePriorityAllTool::definition(), Box::new(RsSymExtSourcePriorityAllTool)),
        (RsSymExtSyntheticNameFunctionTool::definition(), Box::new(RsSymExtSyntheticNameFunctionTool)),
        (RsSymExtSyntheticNameDataTool::definition(), Box::new(RsSymExtSyntheticNameDataTool)),
        (RsSymExtSyntheticNameLabelTool::definition(), Box::new(RsSymExtSyntheticNameLabelTool)),
        (RsSymExtSyntheticNameDwordTool::definition(), Box::new(RsSymExtSyntheticNameDwordTool)),
        (RsSymExtSyntheticNameQwordTool::definition(), Box::new(RsSymExtSyntheticNameQwordTool)),
        (RsSymExtCrossRefIndexOpsTool::definition(), Box::new(RsSymExtCrossRefIndexOpsTool)),
        (RsSymExtUnifiedTableAddLookupTool::definition(), Box::new(RsSymExtUnifiedTableAddLookupTool)),
    ]
}
