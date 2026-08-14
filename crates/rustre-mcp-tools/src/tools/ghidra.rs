//! MCP wrappers for the rustre-ghidra crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct GhidraServerConfigDefaultTool;
impl GhidraServerConfigDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_server_config_default".to_string(),
            description: "Return the default rustre_decompiler_ghidra::GhidraServerConfig \
                          (host, port, timeout_ms, use_tls)."
                .to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraServerConfigDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let cfg = rustre_decompiler_ghidra::GhidraServerConfig::default();
        Ok(ToolResult::text(json!({
            "host": cfg.host,
            "port": cfg.port,
            "timeout_ms": cfg.timeout_ms,
            "use_tls": cfg.use_tls,
            "source": "rustre_decompiler_ghidra::GhidraServerConfig::default",
        }).to_string()))
    }
}

pub struct GhidraScriptCommandLineTool;
impl GhidraScriptCommandLineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_script_command_line".to_string(),
            description: "Build a GhidraScript command line via \
                          rustre_decompiler_ghidra::GhidraScript::command_line."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["name"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraScriptCommandLineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".to_string()))?;
        let mut script = rustre_decompiler_ghidra::GhidraScript::new(name);
        if let Some(arr) = args.get("args").and_then(Value::as_array) {
            for a in arr {
                if let Some(s) = a.as_str() {
                    script = script.arg(s);
                }
            }
        }
        Ok(ToolResult::text(json!({
            "name": name,
            "command_line": script.command_line(),
            "source": "rustre_decompiler_ghidra::GhidraScript::command_line",
        }).to_string()))
    }
}

pub struct GhidraDecompileResponseStubTool;
impl GhidraDecompileResponseStubTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_decompile_response_stub".to_string(),
            description: "Build a stub GhidraDecompileResponse via \
                          rustre_decompiler_ghidra::GhidraDecompileResponse::stub."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "integer" },
                    "name": { "type": "string" }
                },
                "required": ["address", "name"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDecompileResponseStubTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args
            .get("address")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".to_string()))?;
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".to_string()))?;
        let resp = rustre_decompiler_ghidra::GhidraDecompileResponse::stub(addr, name);
        Ok(ToolResult::text(json!({
            "function_address": resp.function_address,
            "c_code": resp.c_code,
            "confidence": resp.confidence,
            "source": "rustre_decompiler_ghidra::GhidraDecompileResponse::stub",
        }).to_string()))
    }
}

pub struct GhidraAstPrinterModuleTool;

pub struct GhidraBridgeModuleTool;

pub struct GhidraMemoryMapSegmentLookupTool;
impl GhidraMemoryMapSegmentLookupTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_memory_map_segment_lookup".to_string(),
            description: "Add two segments to GhidraMemoryMap and look up a segment by address.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraMemoryMapSegmentLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let mut m = rustre_decompiler_ghidra::GhidraMemoryMap::new();
        m.add_segment(rustre_decompiler_ghidra::GhidraSegment{name:".text".into(),start:0x1000,size:0x1000,readable:true,writable:false,executable:true});
        m.add_segment(rustre_decompiler_ghidra::GhidraSegment{name:".data".into(),start:0x3000,size:0x1000,readable:true,writable:true,executable:false});
        let seg = m.segment_at(addr).map(|s| s.name.clone());
        Ok(ToolResult::text(json!({"count":m.segment_count(),"exec":m.executable_segments().len(),"hit":seg,"source":"rustre_decompiler_ghidra::GhidraMemoryMap::segment_at"}).to_string()))
    }
}

pub struct GhidraSymbolImporterResolveTool;
impl GhidraSymbolImporterResolveTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_symbol_importer_resolve".to_string(),
            description: "Add symbols/imports/exports to GhidraSymbolImporter and resolve an address.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraSymbolImporterResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let mut si = rustre_decompiler_ghidra::GhidraSymbolImporter::new();
        si.add_symbol(0x1000, "main");
        si.add_import(0x2000, "printf");
        si.add_export(0x3000, "my_export");
        let name = si.resolve(addr).map(str::to_string);
        Ok(ToolResult::text(json!({"symbols":si.symbol_count(),"imports":si.import_count(),"exports":si.export_count(),"resolved":name,"source":"rustre_decompiler_ghidra::GhidraSymbolImporter::resolve"}).to_string()))
    }
}

pub struct GhidraTypeImporterWindowsTool;
impl GhidraTypeImporterWindowsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_type_importer_windows".to_string(),
            description: "Import Windows types and look up a C typedef.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraTypeImporterWindowsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let mut ti = rustre_decompiler_ghidra::GhidraTypeImporter::new();
        ti.import_windows_types();
        let decl = ti.get_c_decl(name).map(str::to_string);
        Ok(ToolResult::text(json!({"types":ti.type_count(),"decl":decl,"source":"rustre_decompiler_ghidra::GhidraTypeImporter::get_c_decl"}).to_string()))
    }
}

pub struct GhidraRpcClientDecompileTool;
impl GhidraRpcClientDecompileTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_rpc_client_decompile".to_string(),
            description: "Send a mock decompile request via rustre_decompiler_ghidra::GhidraRpcClient.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}},"required":["addr","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraRpcClientDecompileTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string();
        let cfg = rustre_decompiler_ghidra::GhidraServerConfig::default();
        let mut c = rustre_decompiler_ghidra::GhidraRpcClient::new(cfg);
        let req = rustre_decompiler_ghidra::GhidraDecompileRequest{function_address:addr,function_name:name,simplify:true,include_types:false};
        let resp = c.decompile(req).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"endpoint":c.endpoint(),"requests":c.request_count(),"confidence":resp.confidence,"code":resp.c_code,"source":"rustre_decompiler_ghidra::GhidraRpcClient::decompile"}).to_string()))
    }
}

pub struct GhidraProjectFileTool;
impl GhidraProjectFileTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_project_file".to_string(),
            description: "Compute the .gpr project file path for a GhidraProject.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"path":{"type":"string"}},"required":["name","path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraProjectFileTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let p = rustre_decompiler_ghidra::GhidraProject::new(name, std::path::PathBuf::from(path)).with_binary(std::path::PathBuf::from("bin.exe"));
        Ok(ToolResult::text(json!({"file":p.project_file().display().to_string(),"binary":p.binary_path.as_ref().map(|b| b.display().to_string()),"source":"rustre_decompiler_ghidra::GhidraProject::project_file"}).to_string()))
    }
}

pub struct GhidraScriptBuilderTool;
impl GhidraScriptBuilderTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_script_builder".to_string(),
            description: "Build a GhidraScript with args/timeout and return its command line.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"args":{"type":"array"},"timeout_ms":{"type":"integer"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraScriptBuilderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let timeout = args.get("timeout_ms").and_then(Value::as_u64).unwrap_or(30_000);
        let arg_list: Vec<String> = args.get("args").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let mut s = rustre_decompiler_ghidra::GhidraScript::new(name).timeout(timeout);
        for a in &arg_list { s = s.arg(a.clone()); }
        Ok(ToolResult::text(json!({"cmd":s.command_line(),"argc":s.args.len(),"timeout_ms":s.timeout_ms,"source":"rustre_decompiler_ghidra::GhidraScript::command_line"}).to_string()))
    }
}

pub struct GhidraDataTypeDbLookupTool;
impl GhidraDataTypeDbLookupTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_data_type_db_lookup".to_string(),
            description: "Load builtins into GhidraDataTypeDb and look up a type by name.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDataTypeDbLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new();
        db.load_builtins();
        let hit = db.get(name).map(|t| json!({"name":t.name,"category":t.category,"size":t.size_bytes,"c":t.c_representation}));
        Ok(ToolResult::text(json!({"count":db.count(),"type":hit,"source":"rustre_decompiler_ghidra::GhidraDataTypeDb::get"}).to_string()))
    }
}

pub struct GhidraServerConnectTool;
impl GhidraServerConnectTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_server_connect".to_string(),
            description: "Simulate connect/disconnect on rustre_decompiler_ghidra::GhidraServer.".to_string(),
            input_schema: json!({"type":"object","properties":{"port":{"type":"integer"}},"required":["port"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraServerConnectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let port = args.get("port").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'port'".into()))? as u16;
        let mut s = rustre_decompiler_ghidra::GhidraServer::localhost(port);
        let before = s.is_connected();
        s.connect().map_err(|e| McpError::InternalError(e.to_string()))?;
        let after = s.is_connected();
        s.disconnect();
        Ok(ToolResult::text(json!({"before":before,"after":after,"final":s.is_connected(),"host":s.config().host,"port":s.config().port,"source":"rustre_decompiler_ghidra::GhidraServer::connect"}).to_string()))
    }
}

pub struct GhidraRpcClientRequestCountTool;
impl GhidraRpcClientRequestCountTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_rpc_client_request_count".to_string(), description: "GhidraRpcClient request_count after N decompiles.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraRpcClientRequestCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(3);
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x401000);
        let cfg = rustre_decompiler_ghidra::GhidraServerConfig::default();
        let mut c = rustre_decompiler_ghidra::GhidraRpcClient::new(cfg);
        for _ in 0..n { let req = rustre_decompiler_ghidra::GhidraDecompileRequest { function_address: addr, function_name: "f".into(), simplify: true, include_types: false }; c.decompile(req).map_err(|e| McpError::InternalError(format!("{e:?}")))?; }
        Ok(ToolResult::text(json!({"requests":c.request_count(),"endpoint":c.endpoint(),"source":"rustre_decompiler_ghidra::GhidraRpcClient::request_count"}).to_string()))
    }
}

pub struct GhidraServerConnectDisconnectTool;
impl GhidraServerConnectDisconnectTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_server_connect_disconnect".to_string(), description: "GhidraServer connect/disconnect transitions.".to_string(), input_schema: json!({"type":"object","properties":{"port":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraServerConnectDisconnectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16;
        let mut s = rustre_decompiler_ghidra::GhidraServer::localhost(port);
        let before = s.is_connected();
        s.connect().map_err(|e| McpError::InternalError(format!("{e:?}")))?;
        let after_connect = s.is_connected();
        s.disconnect();
        let after_disconnect = s.is_connected();
        Ok(ToolResult::text(json!({"port":port,"before":before,"after_connect":after_connect,"after_disconnect":after_disconnect,"source":"rustre_decompiler_ghidra::GhidraServer::connect"}).to_string()))
    }
}

pub struct GhidraMemoryMapAddSegmentTool;
impl GhidraMemoryMapAddSegmentTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_memory_map_add_segment".to_string(), description: "Add segment to GhidraMemoryMap.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"start":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraMemoryMapAddSegmentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or(".text").to_string();
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0x400000);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000);
        let mut m = rustre_decompiler_ghidra::GhidraMemoryMap::new();
        m.add_segment(rustre_decompiler_ghidra::GhidraSegment { name: name.clone(), start, size, readable: true, writable: false, executable: true });
        let hit = m.segment_at(start + 4).map(|s| s.name.clone());
        Ok(ToolResult::text(json!({"exec_count":m.executable_segments().len(),"lookup":hit,"seg":name,"source":"rustre_decompiler_ghidra::GhidraMemoryMap::add_segment"}).to_string()))
    }
}

pub struct GhidraSymbolImporterImportExportTool;
impl GhidraSymbolImporterImportExportTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_symbol_importer_import_export".to_string(), description: "GhidraSymbolImporter symbol/import/export.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraSymbolImporterImportExportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let name = args.get("name").and_then(Value::as_str).unwrap_or("main").to_string();
        let mut si = rustre_decompiler_ghidra::GhidraSymbolImporter::new();
        si.add_symbol(addr, name.clone()); si.add_import(addr + 0x10, "puts"); si.add_export(addr + 0x20, "start");
        let resolved = si.resolve(addr).map(String::from);
        Ok(ToolResult::text(json!({"count":si.symbol_count(),"resolved":resolved,"source":"rustre_decompiler_ghidra::GhidraSymbolImporter::resolve"}).to_string()))
    }
}

pub struct GhidraTypeImporterAddLookupTool;
impl GhidraTypeImporterAddLookupTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_type_importer_add_lookup".to_string(), description: "GhidraTypeImporter add/get c_decl.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"c_decl":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraTypeImporterAddLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("MyStruct").to_string();
        let c_decl = args.get("c_decl").and_then(Value::as_str).unwrap_or("struct MyStruct { int a; };").to_string();
        let mut ti = rustre_decompiler_ghidra::GhidraTypeImporter::new();
        ti.add_type(name.clone(), c_decl.clone());
        let got = ti.get_c_decl(&name).map(String::from);
        Ok(ToolResult::text(json!({"count":ti.type_count(),"c_decl":got,"source":"rustre_decompiler_ghidra::GhidraTypeImporter::get_c_decl"}).to_string()))
    }
}

pub struct GhidraDataTypeDbAddGetTool;
impl GhidraDataTypeDbAddGetTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_data_type_db_add_get".to_string(), description: "GhidraDataTypeDb custom add/get.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraDataTypeDbAddGetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("word").to_string();
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(2) as usize;
        let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new();
        db.add(rustre_decompiler_ghidra::GhidraDataType { name: name.clone(), category: "custom".into(), size_bytes: size, c_representation: format!("uint{}_t", size * 8) });
        let got = db.get(&name).map(|t| json!({"c":t.c_representation,"size":t.size_bytes,"cat":t.category}));
        Ok(ToolResult::text(json!({"count":db.count(),"info":got,"source":"rustre_decompiler_ghidra::GhidraDataTypeDb::add"}).to_string()))
    }
}

pub struct GhidraScriptChainArgsTool;
impl GhidraScriptChainArgsTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_script_chain_args".to_string(), description: "GhidraScript multiple args + timeout.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraScriptChainArgsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("Decomp.java").to_string();
        let timeout = args.get("timeout").and_then(Value::as_u64).unwrap_or(30_000);
        let argv: Vec<String> = args.get("args").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["0x401000".into(),"main".into()]);
        let mut s = rustre_decompiler_ghidra::GhidraScript::new(name.clone()).timeout(timeout);
        for a in &argv { s = s.arg(a.clone()); }
        Ok(ToolResult::text(json!({"name":s.name,"n_args":s.args.len(),"timeout_ms":s.timeout_ms,"cmd":s.command_line(),"source":"rustre_decompiler_ghidra::GhidraScript::command_line"}).to_string()))
    }
}

pub struct GhidraDecompileResponseStubBatchTool;
impl GhidraDecompileResponseStubBatchTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_decompile_response_stub_batch".to_string(), description: "Batch GhidraDecompileResponse::stub.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraDecompileResponseStubBatchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x400000);
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(4).min(64);
        let mut total: u64 = 0;
        let mut addrs: Vec<u64> = Vec::new();
        for i in 0..n { let addr = base + i * 0x100; let r = rustre_decompiler_ghidra::GhidraDecompileResponse::stub(addr, &format!("f_{i}")); total += u64::from(r.confidence); addrs.push(r.function_address); }
        Ok(ToolResult::text(json!({"n":n,"sum_confidence":total,"addrs":addrs,"source":"rustre_decompiler_ghidra::GhidraDecompileResponse::stub"}).to_string()))
    }
}

pub struct GhidraServerLocalhostConnectWire3Tool;
impl GhidraServerLocalhostConnectWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_server_localhost_connect_wire3".to_string(), description: "GhidraServer::localhost connect/disconnect via rustre_decompiler_ghidra::GhidraServer.".to_string(), input_schema: json!({"type":"object","properties":{"port":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraServerLocalhostConnectWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let port = u16::try_from(args.get("port").and_then(Value::as_u64).unwrap_or(18001)).unwrap_or(18001); let mut s = rustre_decompiler_ghidra::GhidraServer::localhost(port); let before = s.is_connected(); s.connect().map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?; let after = s.is_connected(); s.disconnect(); Ok(ToolResult::text(json!({"before":before,"after":after,"after_disc":s.is_connected(),"port":s.config().port,"source":"rustre_decompiler_ghidra::GhidraServer::connect"}).to_string())) } }

pub struct GhidraMemoryMapExecutableWire3Tool;
impl GhidraMemoryMapExecutableWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_memory_map_executable_wire3".to_string(), description: "GhidraMemoryMap segments/executable via rustre_decompiler_ghidra::GhidraMemoryMap.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraMemoryMapExecutableWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut m = rustre_decompiler_ghidra::GhidraMemoryMap::new(); m.add_segment(rustre_decompiler_ghidra::GhidraSegment { name: ".text".to_string(), start: 0x1000, size: 0x1000, readable: true, writable: false, executable: true }); m.add_segment(rustre_decompiler_ghidra::GhidraSegment { name: ".data".to_string(), start: 0x2000, size: 0x1000, readable: true, writable: true, executable: false }); let hit = m.segment_at(0x1500).map(|s| s.name.clone()); Ok(ToolResult::text(json!({"count":m.segment_count(),"exec":m.executable_segments().len(),"seg_at_1500":hit,"source":"rustre_decompiler_ghidra::GhidraMemoryMap"}).to_string())) } }

pub struct GhidraSymbolImporterFullWire3Tool;
impl GhidraSymbolImporterFullWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_symbol_importer_full_wire3".to_string(), description: "GhidraSymbolImporter add symbol/import/export via rustre_decompiler_ghidra::GhidraSymbolImporter.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraSymbolImporterFullWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut si = rustre_decompiler_ghidra::GhidraSymbolImporter::new(); si.add_symbol(0x1000, "sym_a"); si.add_import(0x2000, "kernel32!CreateFile"); si.add_export(0x3000, "exported_fn"); Ok(ToolResult::text(json!({"sym_count":si.symbol_count(),"imports":si.import_count(),"exports":si.export_count(),"resolve":si.resolve(0x2000),"source":"rustre_decompiler_ghidra::GhidraSymbolImporter"}).to_string())) } }

pub struct GhidraXmlParserTypesWire3Tool;
impl GhidraXmlParserTypesWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_xml_parser_types_wire3".to_string(), description: "Parse XML FUNCTION/TYPE_DEF via rustre_decompiler_ghidra::GhidraXmlParser::parse.".to_string(), input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraXmlParserTypesWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let default_xml = "<FUNCTION NAME=\"foo\"/><TYPE_DEF NAME=\"MYINT\"/><TYPE_DEF NAME=\"MYPTR\"/>".to_string(); let xml = args.get("xml").and_then(Value::as_str).map(str::to_string).unwrap_or(default_xml); let mut p = rustre_decompiler_ghidra::GhidraXmlParser::new(); p.parse(&xml).map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"funcs":p.function_count(),"types":p.type_count(),"type_names":p.parsed_types(),"funcs_list":p.functions(),"source":"rustre_decompiler_ghidra::GhidraXmlParser::parse"}).to_string())) } }

pub struct GhidraDataTypeDbBuiltinsWire3Tool;
impl GhidraDataTypeDbBuiltinsWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_data_type_db_builtins_wire3".to_string(), description: "Load builtins + get via rustre_decompiler_ghidra::GhidraDataTypeDb.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraDataTypeDbBuiltinsWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("int"); let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new(); let before = db.count(); db.load_builtins(); let after = db.count(); let hit = db.get(name).map(|t| json!({"name":t.name,"size":t.size_bytes,"c":t.c_representation})); Ok(ToolResult::text(json!({"before":before,"after":after,"hit":hit,"source":"rustre_decompiler_ghidra::GhidraDataTypeDb::load_builtins"}).to_string())) } }

pub struct GhidraRpcClientDecompileWire3Tool;
impl GhidraRpcClientDecompileWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_rpc_client_decompile_wire3".to_string(), description: "Mock decompile via rustre_decompiler_ghidra::GhidraRpcClient::decompile.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraRpcClientDecompileWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x4000); let name = args.get("name").and_then(Value::as_str).unwrap_or("main").to_string(); let mut c = rustre_decompiler_ghidra::GhidraRpcClient::new(rustre_decompiler_ghidra::GhidraServerConfig::default()); let req = rustre_decompiler_ghidra::GhidraDecompileRequest { function_address: addr, function_name: name, simplify: true, include_types: true }; let resp = c.decompile(req).map_err(|e| rustre_mcp_server::McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"addr":resp.function_address,"confidence":resp.confidence,"c_code_len":resp.c_code.len(),"req_count":c.request_count(),"endpoint":c.endpoint(),"source":"rustre_decompiler_ghidra::GhidraRpcClient::decompile"}).to_string())) } }

pub struct GhidraMemoryMapSegmentCountGhidfixp1Tool;
impl GhidraMemoryMapSegmentCountGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_memory_map_segment_count_ghidfixp1".to_string(), description: "GhidraMemoryMap::segment_count after N adds via rustre_decompiler_ghidra::GhidraMemoryMap.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraMemoryMapSegmentCountGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize; let mut mm = rustre_decompiler_ghidra::GhidraMemoryMap::new(); for i in 0..n { mm.add_segment(rustre_decompiler_ghidra::GhidraSegment { name: format!("seg_{i}"), start: (i as u64)*0x1000, size: 0x1000, readable: true, writable: false, executable: i%2==0 }); } Ok(ToolResult::text(json!({"segment_count":mm.segment_count(),"executable":mm.executable_segments().len(),"source":"rustre_decompiler_ghidra::GhidraMemoryMap::segment_count"}).to_string())) } }

pub struct GhidraSymbolImporterSymbolCountGhidfixp1Tool;
impl GhidraSymbolImporterSymbolCountGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_symbol_importer_symbol_count_ghidfixp1".to_string(), description: "GhidraSymbolImporter::symbol_count via rustre_decompiler_ghidra::GhidraSymbolImporter.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraSymbolImporterSymbolCountGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(5) as u64; let mut si = rustre_decompiler_ghidra::GhidraSymbolImporter::new(); for i in 0..n { si.add_symbol(0x1000+i*8, format!("sym_{i}")); } Ok(ToolResult::text(json!({"symbol_count":si.symbol_count(),"import_count":si.import_count(),"export_count":si.export_count(),"source":"rustre_decompiler_ghidra::GhidraSymbolImporter::symbol_count"}).to_string())) } }

pub struct GhidraTypeImporterTypeCountGhidfixp1Tool;
impl GhidraTypeImporterTypeCountGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_type_importer_type_count_ghidfixp1".to_string(), description: "GhidraTypeImporter::type_count after import_windows_types via rustre_decompiler_ghidra::GhidraTypeImporter.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraTypeImporterTypeCountGhidfixp1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut ti = rustre_decompiler_ghidra::GhidraTypeImporter::new(); ti.import_windows_types(); Ok(ToolResult::text(json!({"type_count":ti.type_count(),"has_dword":ti.get_c_decl("DWORD").is_some(),"source":"rustre_decompiler_ghidra::GhidraTypeImporter::type_count"}).to_string())) } }

pub struct GhidraDataTypeDbCountGhidfixp1Tool;
impl GhidraDataTypeDbCountGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_data_type_db_count_ghidfixp1".to_string(), description: "GhidraDataTypeDb::count after load_builtins via rustre_decompiler_ghidra::GhidraDataTypeDb.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraDataTypeDbCountGhidfixp1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new(); db.load_builtins(); Ok(ToolResult::text(json!({"count":db.count(),"has_int":db.get("int").is_some(),"source":"rustre_decompiler_ghidra::GhidraDataTypeDb::count"}).to_string())) } }

pub struct GhidraXmlParserFunctionCountGhidfixp1Tool;
impl GhidraXmlParserFunctionCountGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_xml_parser_function_count_ghidfixp1".to_string(), description: "GhidraXmlParser::function_count via rustre_decompiler_ghidra::GhidraXmlParser::parse.".to_string(), input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}},"required":["xml"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraXmlParserFunctionCountGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let xml = args.get("xml").and_then(Value::as_str).unwrap_or(""); let mut p = rustre_decompiler_ghidra::GhidraXmlParser::new(); p.parse(xml).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"function_count":p.function_count(),"type_count":p.type_count(),"source":"rustre_decompiler_ghidra::GhidraXmlParser::function_count"}).to_string())) } }

pub struct GhidraRpcClientConfigPortGhidfixp1Tool;
impl GhidraRpcClientConfigPortGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_rpc_client_config_port_ghidfixp1".to_string(), description: "GhidraRpcClient::config via rustre_decompiler_ghidra::GhidraRpcClient.".to_string(), input_schema: json!({"type":"object","properties":{"port":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraRpcClientConfigPortGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16; let cfg = rustre_decompiler_ghidra::GhidraServerConfig { port, ..Default::default() }; let c = rustre_decompiler_ghidra::GhidraRpcClient::new(cfg); Ok(ToolResult::text(json!({"port":c.config().port,"host":c.config().host,"endpoint":c.endpoint(),"source":"rustre_decompiler_ghidra::GhidraRpcClient::config"}).to_string())) } }

pub struct GhidraServerConfigAccessGhidfixp1Tool;
impl GhidraServerConfigAccessGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_server_config_access_ghidfixp1".to_string(), description: "GhidraServer::config via rustre_decompiler_ghidra::GhidraServer::localhost.".to_string(), input_schema: json!({"type":"object","properties":{"port":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraServerConfigAccessGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16; let s = rustre_decompiler_ghidra::GhidraServer::localhost(port); Ok(ToolResult::text(json!({"port":s.config().port,"host":s.config().host,"use_tls":s.config().use_tls,"timeout_ms":s.config().timeout_ms,"is_connected":s.is_connected(),"source":"rustre_decompiler_ghidra::GhidraServer::config"}).to_string())) } }

pub struct GhidraProjectNameGhidfixp1Tool;
impl GhidraProjectNameGhidfixp1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_project_name_ghidfixp1".to_string(), description: "GhidraProject::new + project_file via rustre_decompiler_ghidra::GhidraProject.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"path":{"type":"string"}},"required":["name","path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraProjectNameGhidfixp1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string(); let p = rustre_decompiler_ghidra::GhidraProject::new(name.clone(), std::path::PathBuf::from(&path)); Ok(ToolResult::text(json!({"name":p.name,"path":p.path.display().to_string(),"project_file":p.project_file().display().to_string(),"source":"rustre_decompiler_ghidra::GhidraProject::new"}).to_string())) } }

pub struct GhidraVarnodeRamDisplayGwx4Tool;
impl GhidraVarnodeRamDisplayGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_varnode_ram_display_gwx4".to_string(), description: "Build a ram Varnode and read is_ram + Display via rustre_decompiler_ghidra::Varnode.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraVarnodeRamDisplayGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0x4000); let size = u8::try_from(args.get("size").and_then(Value::as_u64).unwrap_or(8)).unwrap_or(8); let v = rustre_decompiler_ghidra::Varnode { space: "ram".to_string(), offset, size }; Ok(ToolResult::text(json!({"display":v.to_string(),"is_ram":v.is_ram(),"is_const":v.is_const(),"is_register":v.is_register(),"is_unique":v.is_unique(),"source":"rustre_decompiler_ghidra::Varnode"}).to_string())) } }

pub struct GhidraVarnodeUniqueFlagsGwx4Tool;
impl GhidraVarnodeUniqueFlagsGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_varnode_unique_flags_gwx4".to_string(), description: "Build a unique Varnode and check is_unique/is_ram flags via rustre_decompiler_ghidra::Varnode.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraVarnodeUniqueFlagsGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0x100); let v = rustre_decompiler_ghidra::Varnode { space: "unique".to_string(), offset, size: 4 }; Ok(ToolResult::text(json!({"display":v.to_string(),"is_unique":v.is_unique(),"is_ram":v.is_ram(),"is_const":v.is_const(),"is_register":v.is_register(),"source":"rustre_decompiler_ghidra::Varnode::is_unique"}).to_string())) } }

pub struct GhidraVarnodeConstFlagsGwx4Tool;
impl GhidraVarnodeConstFlagsGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_varnode_const_flags_gwx4".to_string(), description: "Build a const Varnode and check is_const flag via rustre_decompiler_ghidra::Varnode.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraVarnodeConstFlagsGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let val = args.get("value").and_then(Value::as_u64).unwrap_or(0x2a); let v = rustre_decompiler_ghidra::Varnode { space: "const".to_string(), offset: val, size: 8 }; Ok(ToolResult::text(json!({"display":v.to_string(),"is_const":v.is_const(),"is_ram":v.is_ram(),"is_unique":v.is_unique(),"is_register":v.is_register(),"source":"rustre_decompiler_ghidra::Varnode::is_const"}).to_string())) } }

pub struct GhidraXmlParserParseTool;
impl GhidraXmlParserParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_xml_parser_parse".to_string(),
            description: "Parse a Ghidra XML export via rustre_decompiler_ghidra::GhidraXmlParser::parse and return function and type counts.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "xml": { "type": "string" } },
                "required": ["xml"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraXmlParserParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'xml'".to_string()))?;
        let mut parser = rustre_decompiler_ghidra::GhidraXmlParser::new();
        parser.parse(xml).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "function_count": parser.function_count(),
            "functions": parser.functions(),
            "type_count": parser.type_count(),
            "types": parser.parsed_types(),
            "source": "rustre_decompiler_ghidra::GhidraXmlParser::parse",
        }).to_string()))
    }
}

pub struct GhidraDataTypeDbLoadBuiltinsTool;
impl GhidraDataTypeDbLoadBuiltinsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_data_type_db_load_builtins".to_string(),
            description: "Load Ghidra primitive types via rustre_decompiler_ghidra::GhidraDataTypeDb::load_builtins and return the catalog count.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDataTypeDbLoadBuiltinsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new();
        db.load_builtins();
        let names: Vec<&str> = ["void","char","uchar","short","ushort","int","uint","long","ulong","longlong","ulonglong","float","double","pointer"].to_vec();
        let mut present = Vec::new();
        for n in &names {
            if db.get(n).is_some() { present.push(*n); }
        }
        Ok(ToolResult::text(json!({
            "count": db.count(),
            "types": present,
            "source": "rustre_decompiler_ghidra::GhidraDataTypeDb::load_builtins",
        }).to_string()))
    }
}

pub struct GhidraServerLocalhostTool;
impl GhidraServerLocalhostTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_server_localhost".to_string(),
            description: "Build a GhidraServer bound to localhost via rustre_decompiler_ghidra::GhidraServer::localhost.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "port": { "type": "integer" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraServerLocalhostTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16;
        let s = rustre_decompiler_ghidra::GhidraServer::localhost(port);
        Ok(ToolResult::text(json!({
            "host": s.config().host,
            "port": s.config().port,
            "connected": s.is_connected(),
            "source": "rustre_decompiler_ghidra::GhidraServer::localhost",
        }).to_string()))
    }
}

pub struct GhidraProjectWithBinaryTool;
impl GhidraProjectWithBinaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_project_with_binary".to_string(),
            description: "Construct a GhidraProject with a binary via rustre_decompiler_ghidra::GhidraProject::with_binary.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "name": {"type":"string"}, "path": {"type":"string"}, "binary": {"type":"string"} },
                "required": ["name","path","binary"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraProjectWithBinaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string();
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string();
        let binary = args.get("binary").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'binary'".into()))?.to_string();
        let p = rustre_decompiler_ghidra::GhidraProject::new(name, std::path::PathBuf::from(path))
            .with_binary(std::path::PathBuf::from(&binary));
        Ok(ToolResult::text(json!({
            "project_file": p.project_file().display().to_string(),
            "binary": p.binary_path.as_ref().map(|b| b.display().to_string()),
            "source": "rustre_decompiler_ghidra::GhidraProject::with_binary",
        }).to_string()))
    }
}

pub struct GhidraWriteScriptToTempTool;
impl GhidraWriteScriptToTempTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_write_script_to_temp".to_string(),
            description: "Write a Ghidra script to a temp file via rustre_decompiler_ghidra::write_script_to_temp.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "script": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraWriteScriptToTempTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str).unwrap_or("// stub");
        let p = rustre_decompiler_ghidra::write_script_to_temp(script)
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        let path_str = p.display().to_string();
        let exists = p.exists();
        let _ = std::fs::remove_file(&p);
        Ok(ToolResult::text(json!({
            "path": path_str,
            "existed": exists,
            "source": "rustre_decompiler_ghidra::write_script_to_temp",
        }).to_string()))
    }
}

pub struct GhidraAvailabilityCheckTool;
impl GhidraAvailabilityCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_availability_check".to_string(),
            description: "Probe Ghidra availability via rustre_decompiler_ghidra::GhidraAvailability::check.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraAvailabilityCheckTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let status = rustre_decompiler_ghidra::GhidraAvailability::check();
        let variant = match &status {
            rustre_decompiler_ghidra::GhidraStatus::Available(_) => "Available",
            rustre_decompiler_ghidra::GhidraStatus::NotFound => "NotFound",
            rustre_decompiler_ghidra::GhidraStatus::InvalidInstall(_) => "InvalidInstall",
        };
        Ok(ToolResult::text(json!({
            "status": variant,
            "debug": format!("{status:?}"),
            "source": "rustre_decompiler_ghidra::GhidraAvailability::check",
        }).to_string()))
    }
}

pub struct GhidraConfigFromHomeTool;
impl GhidraConfigFromHomeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_config_from_home".to_string(),
            description: "Attempt to build a GhidraConfig from a home path via rustre_decompiler_ghidra::GhidraConfig::from_home.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "home": { "type": "string" } },
                "required": ["home"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraConfigFromHomeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let home = args.get("home").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'home'".into()))?;
        let cfg = rustre_decompiler_ghidra::GhidraConfig::from_home(std::path::Path::new(home));
        Ok(ToolResult::text(json!({
            "found": cfg.is_some(),
            "headless": cfg.as_ref().map(|c| c.headless_binary.display().to_string()),
            "source": "rustre_decompiler_ghidra::GhidraConfig::from_home",
        }).to_string()))
    }
}

pub struct GhidraVarnodeClassifyTool;
impl GhidraVarnodeClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_varnode_classify".to_string(),
            description: "Classify a Varnode using is_const/is_register/is_unique/is_ram from rustre_decompiler_ghidra::Varnode.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "space": {"type":"string"}, "offset": {"type":"integer"}, "size": {"type":"integer"} },
                "required": ["space"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraVarnodeClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let space = args.get("space").and_then(Value::as_str).unwrap_or("register").to_string();
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(8) as u8;
        let v = rustre_decompiler_ghidra::Varnode { space, offset, size };
        Ok(ToolResult::text(json!({
            "display": v.to_string(),
            "is_const": v.is_const(),
            "is_register": v.is_register(),
            "is_unique": v.is_unique(),
            "is_ram": v.is_ram(),
            "source": "rustre_decompiler_ghidra::Varnode",
        }).to_string()))
    }
}

pub struct GhidraDecompileScriptTemplateTool;
impl GhidraDecompileScriptTemplateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_decompile_script_template".to_string(),
            description: "Return metadata for rustre_decompiler_ghidra::DECOMPILE_SCRIPT built-in template.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDecompileScriptTemplateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_decompiler_ghidra::DECOMPILE_SCRIPT;
        Ok(ToolResult::text(json!({
            "len": s.len(),
            "contains_class": s.contains("DecompileToJSON"),
            "source": "rustre_decompiler_ghidra::DECOMPILE_SCRIPT",
        }).to_string()))
    }
}

pub struct GhidraListFunctionsScriptTemplateTool;
impl GhidraListFunctionsScriptTemplateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_list_functions_script_template".to_string(),
            description: "Return metadata for rustre_decompiler_ghidra::LIST_FUNCTIONS_SCRIPT built-in template.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraListFunctionsScriptTemplateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_decompiler_ghidra::LIST_FUNCTIONS_SCRIPT;
        Ok(ToolResult::text(json!({
            "len": s.len(),
            "contains_class": s.contains("ListFunctionsJSON"),
            "source": "rustre_decompiler_ghidra::LIST_FUNCTIONS_SCRIPT",
        }).to_string()))
    }
}

pub struct GhidraDataTypeDbAddTool;
impl GhidraDataTypeDbAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_data_type_db_add".to_string(),
            description: "Add a custom type to GhidraDataTypeDb via rustre_decompiler_ghidra::GhidraDataTypeDb::add.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type":"string"}, "category": {"type":"string"},
                    "size_bytes": {"type":"integer"}, "c_repr": {"type":"string"}
                },
                "required": ["name"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDataTypeDbAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("MyType").to_string();
        let category = args.get("category").and_then(Value::as_str).unwrap_or("struct").to_string();
        let size_bytes = args.get("size_bytes").and_then(Value::as_u64).unwrap_or(4) as usize;
        let c_repr = args.get("c_repr").and_then(Value::as_str).unwrap_or("struct MyType {};").to_string();
        let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new();
        db.add(rustre_decompiler_ghidra::GhidraDataType {
            name: name.clone(), category, size_bytes, c_representation: c_repr,
        });
        let hit = db.get(&name).map(|d| d.c_representation.clone());
        Ok(ToolResult::text(json!({
            "count": db.count(),
            "c_representation": hit,
            "source": "rustre_decompiler_ghidra::GhidraDataTypeDb::add",
        }).to_string()))
    }
}

pub struct GhidraMemoryMapExecSegmentsTool;
impl GhidraMemoryMapExecSegmentsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_memory_map_exec_segments".to_string(),
            description: "Add a segment to a GhidraMemoryMap and count executable segments.".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"size":{"type":"integer"},"exec":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraMemoryMapExecSegmentsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0x1000);
        let exec = args.get("exec").and_then(Value::as_bool).unwrap_or(true);
        let mut m = rustre_decompiler_ghidra::GhidraMemoryMap::new();
        m.add_segment(rustre_decompiler_ghidra::GhidraSegment {
            name: ".text".to_string(), start, size, readable: true, writable: false, executable: exec,
        });
        let exec_count = m.executable_segments().len();
        let hit = m.segment_at(start).map(|s| s.name.clone());
        Ok(ToolResult::text(json!({"segments":m.segment_count(),"exec":exec_count,"at_start":hit,"source":"rustre_decompiler_ghidra::GhidraMemoryMap"}).to_string()))
    }
}

pub struct GhidraSymbolImporterCountsTool;
impl GhidraSymbolImporterCountsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_symbol_importer_counts".to_string(),
            description: "Add symbols/imports/exports to GhidraSymbolImporter and return the counts.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraSymbolImporterCountsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut si = rustre_decompiler_ghidra::GhidraSymbolImporter::new();
        si.add_symbol(0x1000, "main");
        si.add_import(0x2000, "printf");
        si.add_export(0x3000, "my_export");
        Ok(ToolResult::text(json!({
            "symbols":si.symbol_count(),"imports":si.import_count(),"exports":si.export_count(),
            "resolved_main":si.resolve(0x1000),
            "source":"rustre_decompiler_ghidra::GhidraSymbolImporter"
        }).to_string()))
    }
}

pub struct GhidraTypeImporterGetTool;
impl GhidraTypeImporterGetTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_type_importer_get".to_string(),
            description: "Look up a Windows typedef from GhidraTypeImporter.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraTypeImporterGetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("DWORD");
        let mut ti = rustre_decompiler_ghidra::GhidraTypeImporter::new();
        ti.import_windows_types();
        Ok(ToolResult::text(json!({
            "count":ti.type_count(),"name":name,"c_decl":ti.get_c_decl(name),
            "source":"rustre_decompiler_ghidra::GhidraTypeImporter"
        }).to_string()))
    }
}

pub struct GhidraXmlParserFunctionsTool;
impl GhidraXmlParserFunctionsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_xml_parser_functions".to_string(),
            description: "Parse Ghidra XML and return function count + names.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraXmlParserFunctionsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str)
            .unwrap_or("<FUNCTION NAME=\"main\"/><FUNCTION NAME=\"init\"/><TYPE_DEF NAME=\"DWORD\"/>");
        let mut p = rustre_decompiler_ghidra::GhidraXmlParser::new();
        p.parse(xml).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "function_count":p.function_count(),"functions":p.functions(),
            "type_count":p.type_count(),"types":p.parsed_types(),
            "source":"rustre_decompiler_ghidra::GhidraXmlParser::parse"
        }).to_string()))
    }
}

pub struct GhidraRpcClientEndpointTool;
impl GhidraRpcClientEndpointTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_rpc_client_endpoint".to_string(),
            description: "Build a GhidraRpcClient and return endpoint + request count after a stub decompile.".to_string(),
            input_schema: json!({"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraRpcClientEndpointTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let host = args.get("host").and_then(Value::as_str).unwrap_or("127.0.0.1").to_string();
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16;
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let cfg = rustre_decompiler_ghidra::GhidraServerConfig { host, port, timeout_ms: 30_000, use_tls: false };
        let mut c = rustre_decompiler_ghidra::GhidraRpcClient::new(cfg);
        let req = rustre_decompiler_ghidra::GhidraDecompileRequest {
            function_address: addr, function_name: "target".to_string(), simplify: true, include_types: false,
        };
        let resp = c.decompile(req).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "endpoint":c.endpoint(),"requests":c.request_count(),
            "resp_addr":resp.function_address,"resp_conf":resp.confidence,
            "source":"rustre_decompiler_ghidra::GhidraRpcClient"
        }).to_string()))
    }
}

pub struct GhidraDecompileResponseStubBuildTool;
impl GhidraDecompileResponseStubBuildTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_decompile_response_stub_build".to_string(),
            description: "Build a GhidraDecompileResponse::stub and return its fields.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDecompileResponseStubBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let name = args.get("name").and_then(Value::as_str).unwrap_or("func");
        let s = rustre_decompiler_ghidra::GhidraDecompileResponse::stub(addr, name);
        Ok(ToolResult::text(json!({
            "addr":s.function_address,"c_code":s.c_code,"confidence":s.confidence,
            "source":"rustre_decompiler_ghidra::GhidraDecompileResponse::stub"
        }).to_string()))
    }
}

pub struct GhidraScriptTimeoutTool;
impl GhidraScriptTimeoutTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_script_timeout".to_string(),
            description: "Build a GhidraScript with args + timeout and return the command line.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"arg":{"type":"string"},"timeout":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraScriptTimeoutTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("Decompile.java").to_string();
        let arg = args.get("arg").and_then(Value::as_str).unwrap_or("0x1000").to_string();
        let timeout = args.get("timeout").and_then(Value::as_u64).unwrap_or(120_000);
        let s = rustre_decompiler_ghidra::GhidraScript::new(name).arg(arg).timeout(timeout);
        Ok(ToolResult::text(json!({
            "name":s.name,"args":s.args,"timeout_ms":s.timeout_ms,"cmdline":s.command_line(),
            "source":"rustre_decompiler_ghidra::GhidraScript"
        }).to_string()))
    }
}

pub struct GhidraProjectPathTool;
impl GhidraProjectPathTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_project_path".to_string(),
            description: "Build a GhidraProject with a binary and return the .gpr path.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"dir":{"type":"string"},"bin":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraProjectPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("proj");
        let dir = args.get("dir").and_then(Value::as_str).unwrap_or(".");
        let bin = args.get("bin").and_then(Value::as_str).unwrap_or("/tmp/a.out");
        let p = rustre_decompiler_ghidra::GhidraProject::new(name, dir).with_binary(bin);
        Ok(ToolResult::text(json!({
            "name":p.name,"gpr":p.project_file().display().to_string(),
            "binary":p.binary_path.as_ref().map(|b| b.display().to_string()),
            "source":"rustre_decompiler_ghidra::GhidraProject"
        }).to_string()))
    }
}

pub struct GhidraServerConfigCustomTool;
impl GhidraServerConfigCustomTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_server_config_custom".to_string(),
            description: "Build a GhidraServer with a custom port and inspect its config.".to_string(),
            input_schema: json!({"type":"object","properties":{"port":{"type":"integer"},"tls":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraServerConfigCustomTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(18001) as u16;
        let use_tls = args.get("tls").and_then(Value::as_bool).unwrap_or(false);
        let cfg = rustre_decompiler_ghidra::GhidraServerConfig {
            host: "127.0.0.1".to_string(), port, timeout_ms: 15_000, use_tls,
        };
        let s = rustre_decompiler_ghidra::GhidraServer::new(cfg);
        Ok(ToolResult::text(json!({
            "host":s.config().host,"port":s.config().port,
            "tls":s.config().use_tls,"timeout_ms":s.config().timeout_ms,
            "connected":s.is_connected(),
            "source":"rustre_decompiler_ghidra::GhidraServer::new"
        }).to_string()))
    }
}

pub struct GhidraDataTypeDbBuiltinsListTool;
impl GhidraDataTypeDbBuiltinsListTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_data_type_db_builtins_list".to_string(),
            description: "Load builtins and return the size of a named primitive.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraDataTypeDbBuiltinsListTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("pointer");
        let mut db = rustre_decompiler_ghidra::GhidraDataTypeDb::new();
        db.load_builtins();
        let hit = db.get(name).map(|t| json!({"size":t.size_bytes,"c":t.c_representation,"cat":t.category}));
        Ok(ToolResult::text(json!({
            "count":db.count(),"name":name,"info":hit,
            "source":"rustre_decompiler_ghidra::GhidraDataTypeDb::load_builtins"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (GhidraServerConfigDefaultTool::definition(), Box::new(GhidraServerConfigDefaultTool)),
        (GhidraScriptCommandLineTool::definition(), Box::new(GhidraScriptCommandLineTool)),
        (GhidraDecompileResponseStubTool::definition(), Box::new(GhidraDecompileResponseStubTool)),
        (GhidraAstPrinterModuleTool::definition(), Box::new(GhidraAstPrinterModuleTool)),
        (GhidraBridgeModuleTool::definition(), Box::new(GhidraBridgeModuleTool)),
        (GhidraMemoryMapSegmentLookupTool::definition(), Box::new(GhidraMemoryMapSegmentLookupTool)),
        (GhidraSymbolImporterResolveTool::definition(), Box::new(GhidraSymbolImporterResolveTool)),
        (GhidraTypeImporterWindowsTool::definition(), Box::new(GhidraTypeImporterWindowsTool)),
        (GhidraRpcClientDecompileTool::definition(), Box::new(GhidraRpcClientDecompileTool)),
        (GhidraProjectFileTool::definition(), Box::new(GhidraProjectFileTool)),
        (GhidraScriptBuilderTool::definition(), Box::new(GhidraScriptBuilderTool)),
        (GhidraDataTypeDbLookupTool::definition(), Box::new(GhidraDataTypeDbLookupTool)),
        (GhidraServerConnectTool::definition(), Box::new(GhidraServerConnectTool)),
        (GhidraRpcClientRequestCountTool::definition(), Box::new(GhidraRpcClientRequestCountTool)),
        (GhidraServerConnectDisconnectTool::definition(), Box::new(GhidraServerConnectDisconnectTool)),
        (GhidraMemoryMapAddSegmentTool::definition(), Box::new(GhidraMemoryMapAddSegmentTool)),
        (GhidraSymbolImporterImportExportTool::definition(), Box::new(GhidraSymbolImporterImportExportTool)),
        (GhidraTypeImporterAddLookupTool::definition(), Box::new(GhidraTypeImporterAddLookupTool)),
        (GhidraDataTypeDbAddGetTool::definition(), Box::new(GhidraDataTypeDbAddGetTool)),
        (GhidraScriptChainArgsTool::definition(), Box::new(GhidraScriptChainArgsTool)),
        (GhidraDecompileResponseStubBatchTool::definition(), Box::new(GhidraDecompileResponseStubBatchTool)),
        (GhidraServerLocalhostConnectWire3Tool::definition(), Box::new(GhidraServerLocalhostConnectWire3Tool)),
        (GhidraMemoryMapExecutableWire3Tool::definition(), Box::new(GhidraMemoryMapExecutableWire3Tool)),
        (GhidraSymbolImporterFullWire3Tool::definition(), Box::new(GhidraSymbolImporterFullWire3Tool)),
        (GhidraXmlParserTypesWire3Tool::definition(), Box::new(GhidraXmlParserTypesWire3Tool)),
        (GhidraDataTypeDbBuiltinsWire3Tool::definition(), Box::new(GhidraDataTypeDbBuiltinsWire3Tool)),
        (GhidraRpcClientDecompileWire3Tool::definition(), Box::new(GhidraRpcClientDecompileWire3Tool)),
        (GhidraMemoryMapSegmentCountGhidfixp1Tool::definition(), Box::new(GhidraMemoryMapSegmentCountGhidfixp1Tool)),
        (GhidraSymbolImporterSymbolCountGhidfixp1Tool::definition(), Box::new(GhidraSymbolImporterSymbolCountGhidfixp1Tool)),
        (GhidraTypeImporterTypeCountGhidfixp1Tool::definition(), Box::new(GhidraTypeImporterTypeCountGhidfixp1Tool)),
        (GhidraDataTypeDbCountGhidfixp1Tool::definition(), Box::new(GhidraDataTypeDbCountGhidfixp1Tool)),
        (GhidraXmlParserFunctionCountGhidfixp1Tool::definition(), Box::new(GhidraXmlParserFunctionCountGhidfixp1Tool)),
        (GhidraRpcClientConfigPortGhidfixp1Tool::definition(), Box::new(GhidraRpcClientConfigPortGhidfixp1Tool)),
        (GhidraServerConfigAccessGhidfixp1Tool::definition(), Box::new(GhidraServerConfigAccessGhidfixp1Tool)),
        (GhidraProjectNameGhidfixp1Tool::definition(), Box::new(GhidraProjectNameGhidfixp1Tool)),
        (GhidraVarnodeRamDisplayGwx4Tool::definition(), Box::new(GhidraVarnodeRamDisplayGwx4Tool)),
        (GhidraVarnodeUniqueFlagsGwx4Tool::definition(), Box::new(GhidraVarnodeUniqueFlagsGwx4Tool)),
        (GhidraVarnodeConstFlagsGwx4Tool::definition(), Box::new(GhidraVarnodeConstFlagsGwx4Tool)),
        (GhidraXmlParserParseTool::definition(), Box::new(GhidraXmlParserParseTool)),
        (GhidraDataTypeDbLoadBuiltinsTool::definition(), Box::new(GhidraDataTypeDbLoadBuiltinsTool)),
        (GhidraServerLocalhostTool::definition(), Box::new(GhidraServerLocalhostTool)),
        (GhidraProjectWithBinaryTool::definition(), Box::new(GhidraProjectWithBinaryTool)),
        (GhidraWriteScriptToTempTool::definition(), Box::new(GhidraWriteScriptToTempTool)),
        (GhidraAvailabilityCheckTool::definition(), Box::new(GhidraAvailabilityCheckTool)),
        (GhidraConfigFromHomeTool::definition(), Box::new(GhidraConfigFromHomeTool)),
        (GhidraVarnodeClassifyTool::definition(), Box::new(GhidraVarnodeClassifyTool)),
        (GhidraDecompileScriptTemplateTool::definition(), Box::new(GhidraDecompileScriptTemplateTool)),
        (GhidraListFunctionsScriptTemplateTool::definition(), Box::new(GhidraListFunctionsScriptTemplateTool)),
        (GhidraDataTypeDbAddTool::definition(), Box::new(GhidraDataTypeDbAddTool)),
        (GhidraMemoryMapExecSegmentsTool::definition(), Box::new(GhidraMemoryMapExecSegmentsTool)),
        (GhidraSymbolImporterCountsTool::definition(), Box::new(GhidraSymbolImporterCountsTool)),
        (GhidraTypeImporterGetTool::definition(), Box::new(GhidraTypeImporterGetTool)),
        (GhidraXmlParserFunctionsTool::definition(), Box::new(GhidraXmlParserFunctionsTool)),
        (GhidraRpcClientEndpointTool::definition(), Box::new(GhidraRpcClientEndpointTool)),
        (GhidraDecompileResponseStubBuildTool::definition(), Box::new(GhidraDecompileResponseStubBuildTool)),
        (GhidraScriptTimeoutTool::definition(), Box::new(GhidraScriptTimeoutTool)),
        (GhidraProjectPathTool::definition(), Box::new(GhidraProjectPathTool)),
        (GhidraServerConfigCustomTool::definition(), Box::new(GhidraServerConfigCustomTool)),
        (GhidraDataTypeDbBuiltinsListTool::definition(), Box::new(GhidraDataTypeDbBuiltinsListTool)),
    ]
}
