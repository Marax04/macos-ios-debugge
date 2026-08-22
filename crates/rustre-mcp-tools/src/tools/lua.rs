//! MCP wrappers for the rustre-lua crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{extract_byte_array};

pub struct LuaLoaderIsBytecodeTool;

pub struct LuaLoaderOpcodeNameTool;

pub struct LuaBcVersionFromByteTool;
impl LuaBcVersionFromByteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_version_from_byte".to_string(), description: "Decode Lua version byte (rustre_loader_lua::LuaVersion).".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcVersionFromByteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let v = rustre_loader_lua::LuaVersion::from_byte(b);
        Ok(ToolResult::text(json!({"display": v.to_string(), "major": v.major(), "minor": v.minor(), "is_known": v.is_known(), "as_byte": v.as_byte(), "source": "rustre_loader_lua::LuaVersion::from_byte"}).to_string()))
    }
}

pub struct LuaBcEndianFromByteTool;
impl LuaBcEndianFromByteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_endian_from_byte".to_string(), description: "Decode Lua endian byte (rustre_loader_lua::LuaEndian::from_byte).".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcEndianFromByteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let e = rustre_loader_lua::LuaEndian::from_byte(b);
        Ok(ToolResult::text(json!({"endian": e.to_string(), "is_le": e.is_le(), "source": "rustre_loader_lua::LuaEndian::from_byte"}).to_string()))
    }
}

pub struct LuaBcHeaderParseTool;
impl LuaBcHeaderParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_header_parse".to_string(), description: "Parse Lua bytecode header (rustre_loader_lua::LuaHeader::parse).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcHeaderParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        match rustre_loader_lua::LuaHeader::parse(&data) {
            Ok((h, end)) => Ok(ToolResult::text(json!({"version": h.version.to_string(), "format": h.format, "endian": h.endian.to_string(), "int_size": h.int_size, "ptr_size": h.ptr_size, "inst_size": h.inst_size, "num_size": h.num_size, "is_integer_num": h.is_integer_num, "is_official_format": h.is_official_format(), "header_end": end, "source": "rustre_loader_lua::LuaHeader::parse"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string()}).to_string())),
        }
    }
}

pub struct LuaBcInstrDecodeTool;
impl LuaBcInstrDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_instr_decode".to_string(), description: "Decode 32-bit Lua instruction word (rustre_loader_lua::LuaInstr).".to_string(), input_schema: json!({"type":"object","properties":{"word":{"type":"integer"}},"required":["word"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcInstrDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let w = args.get("word").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'word'".into()))? as u32;
        let i = rustre_loader_lua::LuaInstr(w);
        Ok(ToolResult::text(json!({"opcode": i.opcode(), "a": i.a(), "b": i.b(), "c": i.c(), "bx": i.bx(), "sbx": i.sbx(), "writes_a": i.writes_a(), "source": "rustre_loader_lua::LuaInstr"}).to_string()))
    }
}

pub struct LuaBcOpcodeLayoutTool;
impl LuaBcOpcodeLayoutTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_opcode_layout".to_string(), description: "Return operand layout (rustre_loader_lua::opcode_layout).".to_string(), input_schema: json!({"type":"object","properties":{"version":{"type":"integer"},"opcode":{"type":"integer"}},"required":["version","opcode"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcOpcodeLayoutTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let vb = args.get("version").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'version'".into()))? as u8;
        let op = args.get("opcode").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'opcode'".into()))? as u8;
        let v = rustre_loader_lua::LuaVersion::from_byte(vb);
        let layout = rustre_loader_lua::opcode_layout(v, op);
        Ok(ToolResult::text(json!({"layout": format!("{:?}", layout), "opcode_name": rustre_loader_lua::opcode_name(v, op), "source": "rustre_loader_lua::opcode_layout"}).to_string()))
    }
}

pub struct LuaBcModuleParseTool;
impl LuaBcModuleParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_module_parse".to_string(), description: "Parse full Lua bytecode module (rustre_loader_lua::LuaBytecodeLoader::load).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcModuleParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        match rustre_loader_lua::LuaBytecodeLoader::load(&data) {
            Ok(m) => {
                let strings = rustre_loader_lua::LuaBytecodeLoader::all_strings(&m);
                let protos = rustre_loader_lua::LuaBytecodeLoader::all_protos(&m);
                let stats = rustre_loader_lua::ProtoStats::from_proto(&m.root_proto);
                Ok(ToolResult::text(json!({"version": m.header.version.to_string(), "total_instructions": m.total_instructions(), "proto_count": protos.len(), "unique_strings": strings.len(), "stats": stats.to_string(), "source": "rustre_loader_lua::LuaBytecodeLoader::load"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string()}).to_string())),
        }
    }
}

pub struct LuaBcProtoStatsMockTool;
impl LuaBcProtoStatsMockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_proto_stats_mock".to_string(), description: "ProtoStats over the prototypes parsed from real Lua chunk bytes (rustre_loader_lua::ProtoStats::from_chunk_bytes).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcProtoStatsMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let stats = rustre_loader_lua::ProtoStats::from_chunk_bytes(&data)
            .map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?;
        Ok(ToolResult::text(json!({"proto_count": stats.proto_count, "instruction_count": stats.instruction_count, "constant_count": stats.constant_count, "string_count": stats.string_count, "number_count": stats.number_count, "integer_count": stats.integer_count, "upvalue_count": stats.upvalue_count, "local_count": stats.local_count, "display": stats.to_string(), "source": "rustre_loader_lua::ProtoStats::from_proto"}).to_string()))
    }
}

pub struct LuaBcDisassembleMockTool;
impl LuaBcDisassembleMockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_disassemble_mock".to_string(), description: "Disassemble the top-level prototype of real Lua chunk bytes (rustre_loader_lua::disassemble_chunk_bytes).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcDisassembleMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let lines = rustre_loader_lua::disassemble_chunk_bytes(&data)
            .map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?;
        let count = lines.len();
        Ok(ToolResult::text(json!({"lines": lines, "count": count, "source": "rustre_loader_lua::disassemble_proto"}).to_string()))
    }
}

pub struct LuaBcChunkFromMockTool;
impl LuaBcChunkFromMockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_chunk_from_mock".to_string(), description: "LuaChunk summary of real Lua chunk bytes (rustre_loader_lua::LuaChunk::from_chunk_bytes).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcChunkFromMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let c = rustre_loader_lua::LuaChunk::from_chunk_bytes(&data)
            .map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?;
        Ok(ToolResult::text(json!({"name": c.name, "first_line": c.first_line, "last_line": c.last_line, "num_params": c.num_params, "is_vararg": c.is_vararg, "max_stack": c.max_stack, "constants_count": c.constants_count, "functions_count": c.functions_count, "instructions_count": c.instructions_count, "display": c.to_string(), "source": "rustre_loader_lua::LuaChunk::from_proto"}).to_string()))
    }
}

pub struct LuaBcModuleDisasmMockTool;
impl LuaBcModuleDisasmMockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_module_disasm_mock".to_string(), description: "ModuleDisasm flat listing of real Lua chunk bytes (rustre_loader_lua::ModuleDisasm::from_chunk_bytes).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcModuleDisasmMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let disasm = rustre_loader_lua::ModuleDisasm::from_chunk_bytes(&data)
            .map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?;
        Ok(ToolResult::text(json!({"version": disasm.version.to_string(), "proto_count": disasm.protos.len(), "flat_listing": disasm.flat_listing(), "source": "rustre_loader_lua::ModuleDisasm::from_module"}).to_string()))
    }
}

pub struct LuaBcReadStringTool;
impl LuaBcReadStringTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_read_string".to_string(), description: "Read length-prefixed Lua string (rustre_loader_lua::read_string_lua).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"},"offset":{"type":"integer"},"size_t_size":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcReadStringTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let mut off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let sts = args.get("size_t_size").and_then(Value::as_u64).unwrap_or(4) as u8;
        match rustre_loader_lua::read_string_lua(&data, &mut off, sts) {
            Ok(s) => Ok(ToolResult::text(json!({"value": s, "new_offset": off, "source": "rustre_loader_lua::read_string_lua"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string()}).to_string())),
        }
    }
}

pub struct LuaBcLoaderCanLoadTool;
impl LuaBcLoaderCanLoadTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "lua_bc_loader_can_load".to_string(), description: "Check LuaLoader.can_load (rustre_loader_lua::LuaLoader::can_load).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"},"uri":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for LuaBcLoaderCanLoadTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::{Loader, LoaderInput};
        let data = extract_byte_array(&args, "bytes", "bytes_hex")?;
        let uri = args.get("uri").and_then(Value::as_str).unwrap_or("input.luac");
        let input = LoaderInput::new(uri, data);
        let loader = rustre_loader_lua::LuaLoader::new();
        Ok(ToolResult::text(json!({"name": loader.name(), "can_load": loader.can_load(&input), "source": "rustre_loader_lua::LuaLoader::can_load"}).to_string()))
    }
}

pub struct LuaLoaderLuaVersionFromByteTool;
impl LuaLoaderLuaVersionFromByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_version_from_byte".to_string(), description: "Decode a Lua version byte.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaVersionFromByteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(b); Ok(ToolResult::text(json!({"display": v.to_string(), "is_known": v.is_known(), "as_byte": v.as_byte(), "major": v.major(), "minor": v.minor(), "source": "rustre_loader_lua::LuaVersion::from_byte"}).to_string())) } }

pub struct LuaLoaderLuaVersionIsKnownTool;
impl LuaLoaderLuaVersionIsKnownTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_version_is_known".to_string(), description: "Report if a Lua version byte is one of 0x51..0x54.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaVersionIsKnownTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(b); Ok(ToolResult::text(json!({"byte": b, "is_known": v.is_known(), "source": "rustre_loader_lua::LuaVersion::is_known"}).to_string())) } }

pub struct LuaLoaderLuaVersionMajorMinorTool;
impl LuaLoaderLuaVersionMajorMinorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_version_major_minor".to_string(), description: "Return the major/minor numbers.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaVersionMajorMinorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(b); Ok(ToolResult::text(json!({"major": v.major(), "minor": v.minor(), "source": "rustre_loader_lua::LuaVersion::major/minor"}).to_string())) } }

pub struct LuaLoaderLuaEndianFromByteTool;
impl LuaLoaderLuaEndianFromByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_endian_from_byte".to_string(), description: "Decode Lua endianness byte.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaEndianFromByteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let e = rustre_loader_lua::LuaEndian::from_byte(b); Ok(ToolResult::text(json!({"display": e.to_string(), "is_le": e.is_le(), "source": "rustre_loader_lua::LuaEndian::from_byte"}).to_string())) } }

pub struct LuaLoaderLuaHeaderParseTool;
impl LuaLoaderLuaHeaderParseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_header_parse".to_string(), description: "Parse a Lua bytecode header.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaHeaderParseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; match rustre_loader_lua::LuaHeader::parse(&data) { Ok((h, end)) => Ok(ToolResult::text(json!({"ok": true, "end_pos": end, "display": h.to_string(), "version": h.version.to_string(), "endian": h.endian.to_string(), "int_size": h.int_size, "ptr_size": h.ptr_size, "inst_size": h.inst_size, "num_size": h.num_size, "is_official_format": h.is_official_format(), "source": "rustre_loader_lua::LuaHeader::parse"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string(), "source": "rustre_loader_lua::LuaHeader::parse"}).to_string())) } } }

pub struct LuaLoaderLuaInstrDecodeTool;
impl LuaLoaderLuaInstrDecodeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_instr_decode".to_string(), description: "Decode a 32-bit Lua instruction word.".to_string(), input_schema: json!({"type":"object","required":["word"],"properties":{"word":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaInstrDecodeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let w = args.get("word").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("word".into()))? as u32; let i = rustre_loader_lua::LuaInstr(w); Ok(ToolResult::text(json!({"opcode": i.opcode(), "a": i.a(), "b": i.b(), "c": i.c(), "bx": i.bx(), "sbx": i.sbx(), "writes_a": i.writes_a(), "display": i.to_string(), "source": "rustre_loader_lua::LuaInstr"}).to_string())) } }

pub struct LuaLoaderLuaProtoMockTool;
impl LuaLoaderLuaProtoMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_mock".to_string(), description: "Build a real LuaProto parsed from chunk bytes and report shape.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaProtoMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let counts = p.constant_type_counts(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "display": p.to_string(), "total_instructions": p.total_instructions(), "num_constants": p.constants.len(), "num_upvalues": p.upvalues.len(), "num_locals": p.locals.len(), "constant_type_counts": counts, "source": "rustre_loader_lua::LuaProto::from_chunk_bytes"}).to_string())) } }

pub struct LuaLoaderLuaBytecodeLoaderLoadTool;
impl LuaLoaderLuaBytecodeLoaderLoadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_bytecode_loader_load".to_string(), description: "Parse Lua bytecode into a LuaModule.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaBytecodeLoaderLoadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; match rustre_loader_lua::LuaBytecodeLoader::load(&data) { Ok(m) => Ok(ToolResult::text(json!({"ok": true, "total_instructions": m.total_instructions(), "version": m.header.version.to_string(), "display": m.to_string(), "source": "rustre_loader_lua::LuaBytecodeLoader::load"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string(), "source": "rustre_loader_lua::LuaBytecodeLoader::load"}).to_string())) } } }

pub struct LuaLoaderLuaAllStringsMockTool;
impl LuaLoaderLuaAllStringsMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_all_strings_mock".to_string(), description: "Collect string constants of a real Lua module parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaAllStringsMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let v = rustre_loader_lua::detect_chunk_version(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let strs = rustre_loader_lua::all_strings_from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "count": strs.len(), "strings": strs, "source": "rustre_loader_lua::LuaBytecodeLoader::all_strings"}).to_string())) } }

pub struct LuaLoaderLuaProtoStatsMockTool;
impl LuaLoaderLuaProtoStatsMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_stats_mock".to_string(), description: "Compute ProtoStats for a real LuaProto parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaProtoStatsMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let s = rustre_loader_lua::ProtoStats::from_proto(&p); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "proto_count": s.proto_count, "instruction_count": s.instruction_count, "constant_count": s.constant_count, "string_count": s.string_count, "number_count": s.number_count, "integer_count": s.integer_count, "upvalue_count": s.upvalue_count, "local_count": s.local_count, "display": s.to_string(), "source": "rustre_loader_lua::ProtoStats::from_proto"}).to_string())) } }

pub struct LuaLoaderLuaOpcodeLayoutTool;
impl LuaLoaderLuaOpcodeLayoutTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_opcode_layout".to_string(), description: "Return operand layout for opcode+version.".to_string(), input_schema: json!({"type":"object","required":["version_byte","opcode"],"properties":{"version_byte":{"type":"integer"},"opcode":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaOpcodeLayoutTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vb = args.get("version_byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("version_byte".into()))? as u8; let op = args.get("opcode").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("opcode".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(vb); let layout = rustre_loader_lua::opcode_layout(v, op); Ok(ToolResult::text(json!({"layout": format!("{:?}", layout), "mnemonic": rustre_loader_lua::opcode_name(v, op), "source": "rustre_loader_lua::opcode_layout"}).to_string())) } }

pub struct LuaLoaderLuaDisassembleMockTool;
impl LuaLoaderLuaDisassembleMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_disassemble_mock".to_string(), description: "Disassemble a real LuaProto parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaDisassembleMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let lines = rustre_loader_lua::disassemble_proto(&p, vb); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "line_count": lines.len(), "lines": lines, "source": "rustre_loader_lua::disassemble_proto"}).to_string())) } }

pub struct LuaLoaderLuaChunkMockTool;
impl LuaLoaderLuaChunkMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_chunk_mock".to_string(), description: "Summarise the top-level prototype of real Lua chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaChunkMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let c = rustre_loader_lua::LuaChunk::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; Ok(ToolResult::text(json!({"display": c.to_string(), "name": c.name, "first_line": c.first_line, "last_line": c.last_line, "num_params": c.num_params, "is_vararg": c.is_vararg, "max_stack": c.max_stack, "constants_count": c.constants_count, "functions_count": c.functions_count, "instructions_count": c.instructions_count, "source": "rustre_loader_lua::LuaChunk::from_chunk_bytes"}).to_string())) } }

pub struct LuaLoaderIsLuaBytecodeTool;
impl LuaLoaderIsLuaBytecodeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_is_lua_bytecode".to_string(), description: "Check whether bytes look like Lua bytecode magic.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderIsLuaBytecodeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; let ok = rustre_loader_lua::is_lua_bytecode(&data); Ok(ToolResult::text(json!({"is_lua_bytecode": ok, "len": data.len(), "source":"rustre_loader_lua::is_lua_bytecode"}).to_string())) } }

pub struct LuaLoaderLuaEndianToCoreTool;
impl LuaLoaderLuaEndianToCoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_endian_to_core".to_string(), description: "Convert LuaEndian byte to rustre-core Endian.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaEndianToCoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let e = rustre_loader_lua::LuaEndian::from_byte(b); let core = e.to_core_endian(); Ok(ToolResult::text(json!({"lua_endian": e.to_string(), "core_endian": format!("{:?}", core), "source":"rustre_loader_lua::LuaEndian::to_core_endian"}).to_string())) } }

pub struct LuaLoaderLuaHeaderToEndianTool;
impl LuaLoaderLuaHeaderToEndianTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_header_to_endian".to_string(), description: "Parse Lua header and report core endian.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaHeaderToEndianTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; match rustre_loader_lua::LuaHeader::parse(&data) { Ok((h, _)) => { let e = h.to_endian(); Ok(ToolResult::text(json!({"ok":true, "endian": format!("{:?}", e), "is_official_format": h.is_official_format(), "source":"rustre_loader_lua::LuaHeader::to_endian"}).to_string())) }, Err(e) => Ok(ToolResult::text(json!({"ok":false, "error": e.to_string()}).to_string())) } } }

pub struct LuaLoaderLuaConstIsStringTool;
impl LuaLoaderLuaConstIsStringTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_const_is_string".to_string(), description: "Classify constants of a real LuaProto parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaConstIsStringTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let items: Vec<_> = p.constants.iter().map(|c| json!({"display": c.to_string(), "is_string": c.is_string(), "as_str": c.as_str()})).collect(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "count": items.len(), "constants": items, "source":"rustre_loader_lua::LuaConst::is_string"}).to_string())) } }

pub struct LuaLoaderLuaProtoSourceLineTool;
impl LuaLoaderLuaProtoSourceLineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_source_line".to_string(), description: "Look up source line for a pc in a real LuaProto parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","required":["pc"],"properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"},"pc":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaProtoSourceLineTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("pc".into()))? as usize; let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let line = p.source_line(pc); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "pc": pc, "line": line, "line_info_len": p.line_info.len(), "source":"rustre_loader_lua::LuaProto::source_line"}).to_string())) } }

pub struct LuaLoaderLuaChunkFromProtoTool;
impl LuaLoaderLuaChunkFromProtoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_chunk_from_proto".to_string(), description: "Build a LuaChunk from a real LuaProto parsed from chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaChunkFromProtoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let c = rustre_loader_lua::LuaChunk::from_proto(&p); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "display": c.to_string(), "name": c.name, "num_params": c.num_params, "is_vararg": c.is_vararg, "max_stack": c.max_stack, "constants_count": c.constants_count, "functions_count": c.functions_count, "instructions_count": c.instructions_count, "source":"rustre_loader_lua::LuaChunk::from_proto"}).to_string())) } }

pub struct LuaLoaderLuaBytecodeParseTool;
impl LuaLoaderLuaBytecodeParseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_bytecode_parse".to_string(), description: "Parse Lua bytecode file (LuaBytecode::parse).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaBytecodeParseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; match rustre_loader_lua::LuaBytecode::parse(&data) { Ok(bc) => Ok(ToolResult::text(json!({"ok": true, "total_instructions": bc.total_instructions(), "version": bc.header.version.to_string(), "strings_count": bc.all_strings().len(), "source":"rustre_loader_lua::LuaBytecode::parse"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string()}).to_string())) } } }

pub struct LuaLoaderLuaArchInfoTool;
impl LuaLoaderLuaArchInfoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_arch_info".to_string(), description: "Report LuaArch name/pointer_size/endian for a version byte.".to_string(), input_schema: json!({"type":"object","required":["version_byte"],"properties":{"version_byte":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaArchInfoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::arch::Architecture; let vb = args.get("version_byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("version_byte".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(vb); let a = rustre_loader_lua::LuaArch::new(v); Ok(ToolResult::text(json!({"name": a.name(), "pointer_size": a.pointer_size(), "endian": format!("{:?}", a.endian()), "num_registers": a.registers().len(), "calling_conventions": a.calling_conventions().len(), "source":"rustre_loader_lua::LuaArch"}).to_string())) } }

pub struct LuaLoaderLuaLoaderNameTool;
impl LuaLoaderLuaLoaderNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_loader_name".to_string(), description: "Return the LuaLoader name identifier.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaLoaderNameTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { use rustre_core::Loader; let l = rustre_loader_lua::LuaLoader::new(); Ok(ToolResult::text(json!({"name": l.name(), "source":"rustre_loader_lua::LuaLoader::name"}).to_string())) } }

pub struct LuaLoaderReadStringLuaTool;
impl LuaLoaderReadStringLuaTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_read_string_lua".to_string(), description: "Read a length-prefixed Lua string starting at offset.".to_string(), input_schema: json!({"type":"object","required":["size_t_size"],"properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"},"size_t_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderReadStringLuaTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; let mut off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let sz = args.get("size_t_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("size_t_size".into()))? as u8; match rustre_loader_lua::read_string_lua(&data, &mut off, sz) { Ok(s) => Ok(ToolResult::text(json!({"ok": true, "string": s, "new_offset": off, "source":"rustre_loader_lua::read_string_lua"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string()}).to_string())) } } }

pub struct LuaLoaderUpvalueDescFromUpvalueTool;
impl LuaLoaderUpvalueDescFromUpvalueTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_upvalue_desc_from_upvalue".to_string(), description: "Convert a real LuaProto parsed from chunk bytes's upvalues to UpvalueDesc.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderUpvalueDescFromUpvalueTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let descs: Vec<_> = p.upvalues.iter().map(|u| { let d = rustre_loader_lua::UpvalueDesc::from_upvalue(u); json!({"name": d.name, "in_stack": d.in_stack, "idx": d.idx, "display": d.to_string()}) }).collect(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "count": descs.len(), "upvalues": descs, "source":"rustre_loader_lua::UpvalueDesc::from_upvalue"}).to_string())) } }

pub struct LuaLoaderLuaProtoAllStringsDirectTool;
impl LuaLoaderLuaProtoAllStringsDirectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_all_strings_direct".to_string(), description: "Collect LuaProto::all_strings from the prototype parsed from real chunk bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LuaLoaderLuaProtoAllStringsDirectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let strs: Vec<String> = p.all_strings().iter().map(|s| (*s).to_string()).collect(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "count": strs.len(), "strings": strs, "source":"rustre_loader_lua::LuaProto::all_strings"}).to_string())) } }

pub struct LuaLoaderVersionAsByteWx1Tool;
impl LuaLoaderVersionAsByteWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_version_as_byte_wx1".to_string(), description: "LuaVersion::from_byte + as_byte round-trip via rustre_loader_lua::LuaVersion.".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderVersionAsByteWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(b); Ok(ToolResult::text(json!({"in":b,"as_byte":v.as_byte(),"is_known":v.is_known(),"major":v.major(),"minor":v.minor(),"display":v.to_string(),"source":"rustre_loader_lua::LuaVersion::as_byte"}).to_string())) } }

pub struct LuaLoaderEndianIsLeWx1Tool;
impl LuaLoaderEndianIsLeWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_endian_is_le_wx1".to_string(), description: "LuaEndian::from_byte + is_le via rustre_loader_lua::LuaEndian.".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderEndianIsLeWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8; let e = rustre_loader_lua::LuaEndian::from_byte(b); Ok(ToolResult::text(json!({"in":b,"is_le":e.is_le(),"display":e.to_string(),"source":"rustre_loader_lua::LuaEndian::is_le"}).to_string())) } }

pub struct LuaLoaderHeaderIsOfficialFormatWx1Tool;
impl LuaLoaderHeaderIsOfficialFormatWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_header_is_official_format_wx1".to_string(), description: "Parse Lua header from hex/bytes and report is_official_format via rustre_loader_lua::LuaHeader.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderHeaderIsOfficialFormatWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = args_to_bytes(&args)?; match rustre_loader_lua::LuaHeader::parse(&data) { Ok((hdr, end)) => Ok(ToolResult::text(json!({"is_official_format":hdr.is_official_format(),"format":hdr.format,"header_end":end,"display":hdr.to_string(),"source":"rustre_loader_lua::LuaHeader::is_official_format"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct LuaLoaderConstIsStringWx1Tool;
impl LuaLoaderConstIsStringWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_const_is_string_wx1".to_string(), description: "Classify LuaConst variants via rustre_loader_lua::LuaConst::is_string/as_str.".to_string(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderConstIsStringWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("text").and_then(Value::as_str).unwrap_or("hello").to_string(); let c = rustre_loader_lua::LuaConst::Str(s.clone()); let n = rustre_loader_lua::LuaConst::Nil; Ok(ToolResult::text(json!({"str_is_string":c.is_string(),"str_as_str":c.as_str(),"nil_is_string":n.is_string(),"str_display":c.to_string(),"nil_display":n.to_string(),"source":"rustre_loader_lua::LuaConst::is_string"}).to_string())) } }

pub struct LuaLoaderInstrFieldsWx1Tool;
impl LuaLoaderInstrFieldsWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_instr_fields_wx1".to_string(), description: "Decode a 32-bit Lua instruction via rustre_loader_lua::LuaInstr accessors.".to_string(), input_schema: json!({"type":"object","properties":{"word":{"type":"integer"}},"required":["word"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderInstrFieldsWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let w = args.get("word").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'word'".into()))? as u32; let i = rustre_loader_lua::LuaInstr(w); Ok(ToolResult::text(json!({"opcode":i.opcode(),"a":i.a(),"b":i.b(),"c":i.c(),"bx":i.bx(),"sbx":i.sbx(),"writes_a":i.writes_a(),"display":i.to_string(),"source":"rustre_loader_lua::LuaInstr"}).to_string())) } }

pub struct LuaLoaderProtoTotalInstructionsWx1Tool;
impl LuaLoaderProtoTotalInstructionsWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_total_instructions_wx1".to_string(), description: "Parse real chunk bytes and return total_instructions via rustre_loader_lua::LuaProto::total_instructions.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderProtoTotalInstructionsWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "total_instructions":p.total_instructions(),"strings":p.all_strings(),"source_line_0":p.source_line(0),"source":"rustre_loader_lua::LuaProto::total_instructions"}).to_string())) } }

pub struct LuaLoaderProtoConstTypeCountsWx1Tool;
impl LuaLoaderProtoConstTypeCountsWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_const_type_counts_wx1".to_string(), description: "Report constant_type_counts on a real LuaProto parsed from chunk bytes via rustre_loader_lua::LuaProto::constant_type_counts.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderProtoConstTypeCountsWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let counts = p.constant_type_counts(); let map: std::collections::BTreeMap<String,usize> = counts.iter().map(|(k,v)| ((*k).to_string(), *v)).collect(); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "counts":map,"num_constants":p.constants.len(),"source":"rustre_loader_lua::LuaProto::constant_type_counts"}).to_string())) } }

pub struct LuaLoaderChunkFromProtoFieldsWx1Tool;
impl LuaLoaderChunkFromProtoFieldsWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_chunk_from_proto_fields_wx1".to_string(), description: "Wrap the prototype parsed from real chunk bytes into LuaChunk via rustre_loader_lua::LuaChunk::from_proto.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderChunkFromProtoFieldsWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let c = rustre_loader_lua::LuaChunk::from_proto(&p); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "name":c.name,"first_line":c.first_line,"last_line":c.last_line,"num_params":c.num_params,"is_vararg":c.is_vararg,"max_stack":c.max_stack,"constants_count":c.constants_count,"instructions_count":c.instructions_count,"functions_count":c.functions_count,"display":c.to_string(),"source":"rustre_loader_lua::LuaChunk::from_proto"}).to_string())) } }

pub struct LuaLoaderProtoStatsFromProtoWx1Tool;
impl LuaLoaderProtoStatsFromProtoWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_stats_from_proto_wx1".to_string(), description: "Compute ProtoStats over a real LuaProto parsed from chunk bytes via rustre_loader_lua::ProtoStats::from_proto.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderProtoStatsFromProtoWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let s = rustre_loader_lua::ProtoStats::from_proto(&p); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "proto_count":s.proto_count,"instruction_count":s.instruction_count,"constant_count":s.constant_count,"string_count":s.string_count,"number_count":s.number_count,"integer_count":s.integer_count,"upvalue_count":s.upvalue_count,"local_count":s.local_count,"display":s.to_string(),"source":"rustre_loader_lua::ProtoStats::from_proto"}).to_string())) } }

pub struct LuaLoaderProtoWalkerCountWx1Tool;
impl LuaLoaderProtoWalkerCountWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_proto_walker_count_wx1".to_string(), description: "Walk protos DFS via rustre_loader_lua::ProtoWalker::new and count.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderProtoWalkerCountWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let root = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let count = rustre_loader_lua::ProtoWalker::new(&root).count(); Ok(ToolResult::text(json!({"count":count,"nested":root.protos.len(),"chunk_version":root.version.to_string(),"source":"rustre_loader_lua::ProtoWalker::new"}).to_string())) } }

pub struct LuaLoaderConstantIndexGetWx1Tool;
impl LuaLoaderConstantIndexGetWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_constant_index_get_wx1".to_string(), description: "Look up a constant by ConstantIndex via rustre_loader_lua::ConstantIndex::get.".to_string(), input_schema: json!({"type":"object","required":["index"],"properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"},"index":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderConstantIndexGetWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let idx = args.get("index").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'index'".into()))? as u32; let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let ci = rustre_loader_lua::ConstantIndex(idx); let got = ci.get(&p); Ok(ToolResult::text(json!({"index":idx,"display":ci.to_string(),"found":got.is_some(),"value":got.map(|c| c.to_string()),"source":"rustre_loader_lua::ConstantIndex::get"}).to_string())) } }

pub struct LuaLoaderDisassembleProtoWx1Tool;
impl LuaLoaderDisassembleProtoWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_disassemble_proto_wx1".to_string(), description: "Disassemble a real LuaProto parsed from chunk bytes via rustre_loader_lua::disassemble_proto.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderDisassembleProtoWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "bytes_hex")?; let p = rustre_loader_lua::LuaProto::from_chunk_bytes(&data).map_err(|e| McpError::InvalidParams(format!("cannot parse Lua chunk bytes: {e}")))?; let v = p.version; let vb = v.as_byte(); let lines = rustre_loader_lua::disassemble_proto(&p, vb); Ok(ToolResult::text(json!({"chunk_version": v.to_string(), "chunk_version_byte": vb, "count":lines.len(),"lines":lines,"source":"rustre_loader_lua::disassemble_proto"}).to_string())) } }

pub struct LuaLoaderOpcodeLayoutWx1Tool;
impl LuaLoaderOpcodeLayoutWx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "lua_loader_lua_opcode_layout_wx1".to_string(), description: "Return OpcodeLayout for a version+opcode via rustre_loader_lua::opcode_layout.".to_string(), input_schema: json!({"type":"object","properties":{"version":{"type":"integer"},"opcode":{"type":"integer"}},"required":["version","opcode"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for LuaLoaderOpcodeLayoutWx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vb = args.get("version").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'version'".into()))? as u8; let op = args.get("opcode").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'opcode'".into()))? as u8; let v = rustre_loader_lua::LuaVersion::from_byte(vb); let lay = rustre_loader_lua::opcode_layout(v, op); let name = rustre_loader_lua::opcode_name(v, op); Ok(ToolResult::text(json!({"layout":format!("{:?}", lay),"mnemonic":name,"version":v.to_string(),"opcode":op,"source":"rustre_loader_lua::opcode_layout"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (LuaLoaderIsBytecodeTool::definition(), Box::new(LuaLoaderIsBytecodeTool)),
        (LuaLoaderOpcodeNameTool::definition(), Box::new(LuaLoaderOpcodeNameTool)),
        (LuaBcVersionFromByteTool::definition(), Box::new(LuaBcVersionFromByteTool)),
        (LuaBcEndianFromByteTool::definition(), Box::new(LuaBcEndianFromByteTool)),
        (LuaBcHeaderParseTool::definition(), Box::new(LuaBcHeaderParseTool)),
        (LuaBcInstrDecodeTool::definition(), Box::new(LuaBcInstrDecodeTool)),
        (LuaBcOpcodeLayoutTool::definition(), Box::new(LuaBcOpcodeLayoutTool)),
        (LuaBcModuleParseTool::definition(), Box::new(LuaBcModuleParseTool)),
        (LuaBcProtoStatsMockTool::definition(), Box::new(LuaBcProtoStatsMockTool)),
        (LuaBcDisassembleMockTool::definition(), Box::new(LuaBcDisassembleMockTool)),
        (LuaBcChunkFromMockTool::definition(), Box::new(LuaBcChunkFromMockTool)),
        (LuaBcModuleDisasmMockTool::definition(), Box::new(LuaBcModuleDisasmMockTool)),
        (LuaBcReadStringTool::definition(), Box::new(LuaBcReadStringTool)),
        (LuaBcLoaderCanLoadTool::definition(), Box::new(LuaBcLoaderCanLoadTool)),
        (LuaLoaderLuaVersionFromByteTool::definition(), Box::new(LuaLoaderLuaVersionFromByteTool)),
        (LuaLoaderLuaVersionIsKnownTool::definition(), Box::new(LuaLoaderLuaVersionIsKnownTool)),
        (LuaLoaderLuaVersionMajorMinorTool::definition(), Box::new(LuaLoaderLuaVersionMajorMinorTool)),
        (LuaLoaderLuaEndianFromByteTool::definition(), Box::new(LuaLoaderLuaEndianFromByteTool)),
        (LuaLoaderLuaHeaderParseTool::definition(), Box::new(LuaLoaderLuaHeaderParseTool)),
        (LuaLoaderLuaInstrDecodeTool::definition(), Box::new(LuaLoaderLuaInstrDecodeTool)),
        (LuaLoaderLuaProtoMockTool::definition(), Box::new(LuaLoaderLuaProtoMockTool)),
        (LuaLoaderLuaBytecodeLoaderLoadTool::definition(), Box::new(LuaLoaderLuaBytecodeLoaderLoadTool)),
        (LuaLoaderLuaAllStringsMockTool::definition(), Box::new(LuaLoaderLuaAllStringsMockTool)),
        (LuaLoaderLuaProtoStatsMockTool::definition(), Box::new(LuaLoaderLuaProtoStatsMockTool)),
        (LuaLoaderLuaOpcodeLayoutTool::definition(), Box::new(LuaLoaderLuaOpcodeLayoutTool)),
        (LuaLoaderLuaDisassembleMockTool::definition(), Box::new(LuaLoaderLuaDisassembleMockTool)),
        (LuaLoaderLuaChunkMockTool::definition(), Box::new(LuaLoaderLuaChunkMockTool)),
        (LuaLoaderIsLuaBytecodeTool::definition(), Box::new(LuaLoaderIsLuaBytecodeTool)),
        (LuaLoaderLuaEndianToCoreTool::definition(), Box::new(LuaLoaderLuaEndianToCoreTool)),
        (LuaLoaderLuaHeaderToEndianTool::definition(), Box::new(LuaLoaderLuaHeaderToEndianTool)),
        (LuaLoaderLuaConstIsStringTool::definition(), Box::new(LuaLoaderLuaConstIsStringTool)),
        (LuaLoaderLuaProtoSourceLineTool::definition(), Box::new(LuaLoaderLuaProtoSourceLineTool)),
        (LuaLoaderLuaChunkFromProtoTool::definition(), Box::new(LuaLoaderLuaChunkFromProtoTool)),
        (LuaLoaderLuaBytecodeParseTool::definition(), Box::new(LuaLoaderLuaBytecodeParseTool)),
        (LuaLoaderLuaArchInfoTool::definition(), Box::new(LuaLoaderLuaArchInfoTool)),
        (LuaLoaderLuaLoaderNameTool::definition(), Box::new(LuaLoaderLuaLoaderNameTool)),
        (LuaLoaderReadStringLuaTool::definition(), Box::new(LuaLoaderReadStringLuaTool)),
        (LuaLoaderUpvalueDescFromUpvalueTool::definition(), Box::new(LuaLoaderUpvalueDescFromUpvalueTool)),
        (LuaLoaderLuaProtoAllStringsDirectTool::definition(), Box::new(LuaLoaderLuaProtoAllStringsDirectTool)),
        (LuaLoaderVersionAsByteWx1Tool::definition(), Box::new(LuaLoaderVersionAsByteWx1Tool)),
        (LuaLoaderEndianIsLeWx1Tool::definition(), Box::new(LuaLoaderEndianIsLeWx1Tool)),
        (LuaLoaderHeaderIsOfficialFormatWx1Tool::definition(), Box::new(LuaLoaderHeaderIsOfficialFormatWx1Tool)),
        (LuaLoaderConstIsStringWx1Tool::definition(), Box::new(LuaLoaderConstIsStringWx1Tool)),
        (LuaLoaderInstrFieldsWx1Tool::definition(), Box::new(LuaLoaderInstrFieldsWx1Tool)),
        (LuaLoaderProtoTotalInstructionsWx1Tool::definition(), Box::new(LuaLoaderProtoTotalInstructionsWx1Tool)),
        (LuaLoaderProtoConstTypeCountsWx1Tool::definition(), Box::new(LuaLoaderProtoConstTypeCountsWx1Tool)),
        (LuaLoaderChunkFromProtoFieldsWx1Tool::definition(), Box::new(LuaLoaderChunkFromProtoFieldsWx1Tool)),
        (LuaLoaderProtoStatsFromProtoWx1Tool::definition(), Box::new(LuaLoaderProtoStatsFromProtoWx1Tool)),
        (LuaLoaderProtoWalkerCountWx1Tool::definition(), Box::new(LuaLoaderProtoWalkerCountWx1Tool)),
        (LuaLoaderConstantIndexGetWx1Tool::definition(), Box::new(LuaLoaderConstantIndexGetWx1Tool)),
        (LuaLoaderDisassembleProtoWx1Tool::definition(), Box::new(LuaLoaderDisassembleProtoWx1Tool)),
        (LuaLoaderOpcodeLayoutWx1Tool::definition(), Box::new(LuaLoaderOpcodeLayoutWx1Tool)),
    ]
}
