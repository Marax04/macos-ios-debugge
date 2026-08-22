//! MCP wrappers for the rustre-arch_wasm crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct ArchWasmValueTypeFromByteTool;

pub struct ArchWasmSectionIdFromByteTool;

pub struct ArchWasmExternalKindFromByteTool;

pub struct ArchWasmMutabilityFromByteTool;

pub struct ArchWasmValueTypeNameTool;
impl ArchWasmValueTypeNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_valtype_name".to_string(),
            description: "Return the textual name for a Wasm value type byte (e.g. 0x7F -> \"i32\").".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmValueTypeNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let name = rustre_arch_wasm::WasmValueType::from_byte(b).map(|v| v.name());
        Ok(ToolResult::text(json!({"byte":b,"name":name}).to_string()))
    }
}

pub struct ArchWasmValueTypeIsNumericTool;
impl ArchWasmValueTypeIsNumericTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_valtype_is_numeric".to_string(),
            description: "Return true if the Wasm value type byte represents a numeric type (i32/i64/f32/f64).".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmValueTypeIsNumericTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let vt = rustre_arch_wasm::WasmValueType::from_byte(b);
        let numeric = vt.map(|v| v.is_numeric()).unwrap_or(false);
        Ok(ToolResult::text(json!({"byte":b,"is_numeric":numeric,"valid":vt.is_some()}).to_string()))
    }
}

pub struct ArchWasmValueTypeIsReferenceTool;
impl ArchWasmValueTypeIsReferenceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_valtype_is_reference".to_string(),
            description: "Return true if the Wasm value type byte represents a reference type (funcref/externref).".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmValueTypeIsReferenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let vt = rustre_arch_wasm::WasmValueType::from_byte(b);
        let is_ref = vt.map(|v| v.is_reference()).unwrap_or(false);
        Ok(ToolResult::text(json!({"byte":b,"is_reference":is_ref,"valid":vt.is_some()}).to_string()))
    }
}

pub struct ArchWasmSectionNameTool;
impl ArchWasmSectionNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_section_name".to_string(),
            description: "Return the textual name of a Wasm section id byte (0=custom, 1=type, ...).".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmSectionNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let name = rustre_arch_wasm::WasmSectionId::from_byte(b).map(|s| s.name());
        Ok(ToolResult::text(json!({"byte":b,"name":name}).to_string()))
    }
}

pub struct ArchWasmExternalKindNameTool;
impl ArchWasmExternalKindNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_external_kind_name".to_string(),
            description: "Return the textual name of a Wasm external kind byte (0=func,1=table,2=memory,3=global).".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmExternalKindNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let name = rustre_arch_wasm::WasmExternalKind::from_byte(b).map(|k| k.name());
        Ok(ToolResult::text(json!({"byte":b,"name":name}).to_string()))
    }
}

pub struct ArchWasmLimitsDecodeTool;
impl ArchWasmLimitsDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_limits_decode".to_string(),
            description: "Decode Wasm limits (memory/table) from hex bytes via rustre_arch_wasm::WasmLimits::decode.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmLimitsDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmLimits::decode(&bytes) {
            Ok((lim, n)) => Ok(ToolResult::text(json!({"min":lim.min,"max":lim.max,"consumed":n}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmFuncTypeDecodeTool;
impl ArchWasmFuncTypeDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_functype_decode".to_string(),
            description: "Decode a Wasm function type (signature) from hex bytes; returns param/result value type names.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmFuncTypeDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmFuncType::decode(&bytes) {
            Ok(ft) => {
                let params: Vec<&'static str> = ft.params.iter().map(|v| v.name()).collect();
                let results: Vec<&'static str> = ft.results.iter().map(|v| v.name()).collect();
                let (p, r) = ft.arity();
                Ok(ToolResult::text(json!({"params":params,"results":results,"param_count":p,"result_count":r}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmModuleHeaderParseTool;
impl ArchWasmModuleHeaderParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_module_header_parse".to_string(),
            description: "Parse the 8-byte Wasm module header (magic + version).".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmModuleHeaderParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmModuleHeader::parse(&bytes) {
            Ok(h) => Ok(ToolResult::text(json!({"magic_hex":hex_encode(&h.magic),"version_hex":hex_encode(&h.version),"valid":true}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"valid":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmConstantsTool;
impl ArchWasmConstantsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_constants".to_string(),
            description: "Return Wasm binary format constants: magic bytes and MVP version.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmConstantsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "magic_hex": hex_encode(&rustre_arch_wasm::WASM_MAGIC),
            "version_hex": hex_encode(&rustre_arch_wasm::WASM_VERSION),
        }).to_string()))
    }
}

pub struct ArchWasmSimdMnemonicTool;
impl ArchWasmSimdMnemonicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_simd_mnemonic".to_string(),
            description: "Return the mnemonic for a Wasm SIMD (0xFD-prefixed) sub-opcode.".to_string(),
            input_schema: json!({"type":"object","required":["sub"],"properties":{"sub":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmSimdMnemonicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sub = args.get("sub").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'sub'".into()))? as u32;
        let m = rustre_arch_wasm::simd_opcode_mnemonic(sub);
        Ok(ToolResult::text(json!({"sub":sub,"mnemonic":m}).to_string()))
    }
}

pub struct ArchWasmDisassembleTool;
impl ArchWasmDisassembleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_disassemble".to_string(),
            description: "Disassemble a single Wasm instruction from hex bytes using WasmArch.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"},"address":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmDisassembleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::arch::Architecture;
        let bytes = args_to_bytes(&args)?;
        let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0);
        let arch = rustre_arch_wasm::WasmArch::new();
        match arch.disassemble(rustre_core::address::Address::new(addr), &bytes) {
            Ok(i) => Ok(ToolResult::text(json!({
                "mnemonic": i.mnemonic,
                "operands": i.operands,
                "size": i.size,
                "flags_bits": i.flags.bits(),
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmArchInfoTool;
impl ArchWasmArchInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_arch_info".to_string(),
            description: "Return WasmArch metadata: architecture name, pointer size, endianness.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmArchInfoTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::arch::Architecture;
        let a = rustre_arch_wasm::WasmArch::new();
        Ok(ToolResult::text(json!({
            "name": a.name(),
            "pointer_size": a.pointer_size(),
            "endian": format!("{:?}", a.endian()),
        }).to_string()))
    }
}

pub struct ArchWasmMemoryTypeDecodeTool;
impl ArchWasmMemoryTypeDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_memory_type_decode".to_string(),
            description: "Decode a Wasm memory type from hex bytes via rustre_arch_wasm::WasmMemoryType::decode.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmMemoryTypeDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmMemoryType::decode(&bytes) {
            Ok((mt, n)) => Ok(ToolResult::text(json!({"min":mt.limits.min,"max":mt.limits.max,"consumed":n}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmTableTypeDecodeTool;
impl ArchWasmTableTypeDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_table_type_decode".to_string(),
            description: "Decode a Wasm table type from hex bytes via rustre_arch_wasm::WasmTableType::decode.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmTableTypeDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmTableType::decode(&bytes) {
            Ok((tt, n)) => Ok(ToolResult::text(json!({
                "element_type": tt.element_type.name(),
                "min": tt.limits.min,
                "max": tt.limits.max,
                "consumed": n,
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmGlobalTypeDecodeTool;
impl ArchWasmGlobalTypeDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_global_type_decode".to_string(),
            description: "Decode a Wasm global type from hex bytes via rustre_arch_wasm::WasmGlobalType::decode.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmGlobalTypeDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::WasmGlobalType::decode(&bytes) {
            Ok((gt, n)) => {
                let mutability = match gt.mutability {
                    rustre_arch_wasm::WasmMutability::Const => "const",
                    rustre_arch_wasm::WasmMutability::Mutable => "mutable",
                };
                Ok(ToolResult::text(json!({
                    "content_type": gt.content_type.name(),
                    "mutability": mutability,
                    "consumed": n,
                }).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmValtypeByteTool;
impl ArchWasmValtypeByteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_valtype_byte".to_string(),
            description: "Given a Wasm value type name, return its binary encoding byte via WasmValueType::byte.".to_string(),
            input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmValtypeByteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing name".into()))?;
        use rustre_arch_wasm::WasmValueType;
        let vt = match name {
            "i32" => Some(WasmValueType::I32),
            "i64" => Some(WasmValueType::I64),
            "f32" => Some(WasmValueType::F32),
            "f64" => Some(WasmValueType::F64),
            "v128" => Some(WasmValueType::V128),
            "funcref" => Some(WasmValueType::FuncRef),
            "externref" => Some(WasmValueType::ExternRef),
            _ => None,
        };
        Ok(ToolResult::text(json!({"name": name, "byte": vt.map(|v| v.byte())}).to_string()))
    }
}

pub struct ArchWasmFunctionStatsTool;
impl ArchWasmFunctionStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_function_stats".to_string(),
            description: "Compute Wasm function statistics from hex bytecode via WasmFunctionStats::from_bytes.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmFunctionStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        let arch = rustre_arch_wasm::WasmArch::new();
        match rustre_arch_wasm::WasmFunctionStats::from_bytes(&arch, &bytes) {
            Ok(s) => Ok(ToolResult::text(json!({
                "instruction_count": s.instruction_count,
                "call_count": s.call_count,
                "branch_count": s.branch_count,
                "load_count": s.load_count,
                "store_count": s.store_count,
                "return_count": s.return_count,
                "unreachable_count": s.unreachable_count,
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmNameSubsectionFromByteTool;
impl ArchWasmNameSubsectionFromByteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_name_subsection_from_byte".to_string(),
            description: "Decode a Wasm name-section subsection ID byte via NameSubsectionType::from_byte.".to_string(),
            input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmNameSubsectionFromByteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("byte").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing byte".into()))? as u8;
        let name = rustre_arch_wasm::NameSubsectionType::from_byte(b).map(|s| s.name());
        Ok(ToolResult::text(json!({"byte":b,"name":name}).to_string()))
    }
}

pub struct ArchWasmDecodeFcPrefixTool;
impl ArchWasmDecodeFcPrefixTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_decode_fc_prefix".to_string(),
            description: "Decode a 0xFC-prefixed Wasm instruction from hex bytes.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmDecodeFcPrefixTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::decode_fc_prefix(&bytes) {
            Ok((mn, ops, size, flags)) => Ok(ToolResult::text(json!({
                "mnemonic": mn, "operands": ops, "size": size, "flags_bits": flags.bits(),
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmDecodeFdPrefixTool;
impl ArchWasmDecodeFdPrefixTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_decode_fd_prefix".to_string(),
            description: "Decode a 0xFD-prefixed Wasm SIMD instruction from hex bytes.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmDecodeFdPrefixTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::decode_fd_prefix(&bytes) {
            Ok((mn, ops, size, flags)) => Ok(ToolResult::text(json!({
                "mnemonic": mn, "operands": ops, "size": size, "flags_bits": flags.bits(),
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmDecodeFePrefixTool;
impl ArchWasmDecodeFePrefixTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_decode_fe_prefix".to_string(),
            description: "Decode a 0xFE-prefixed Wasm threads/atomics instruction from hex bytes.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmDecodeFePrefixTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        match rustre_arch_wasm::decode_fe_prefix(&bytes) {
            Ok((mn, ops, size, flags)) => Ok(ToolResult::text(json!({
                "mnemonic": mn, "operands": ops, "size": size, "flags_bits": flags.bits(),
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())),
        }
    }
}

pub struct ArchWasmLinearDisassembleTool;
impl ArchWasmLinearDisassembleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "arch_wasm_linear_disassemble".to_string(),
            description: "Linearly disassemble a Wasm bytecode blob via WasmLinearDisassembler.".to_string(),
            input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"},"limit":{"type":"integer"},"base_address":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ArchWasmLinearDisassembleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args_to_bytes(&args)?;
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(256) as usize;
        let base = args.get("base_address").and_then(Value::as_u64).unwrap_or(0);
        let arch = rustre_arch_wasm::WasmArch::new();
        let mut items = Vec::new();
        let mut errors = 0usize;
        let it = rustre_arch_wasm::WasmLinearDisassembler::new(&arch, &bytes, rustre_core::address::Address::new(base));
        for r in it.take(limit) {
            match r {
                Ok(i) => items.push(json!({
                    "mnemonic": i.mnemonic,
                    "operands": i.operands,
                    "size": i.size,
                })),
                Err(_) => errors += 1,
            }
        }
        Ok(ToolResult::text(json!({
            "count": items.len(),
            "errors": errors,
            "instructions": items,
        }).to_string()))
    }
}

pub struct ArchWasmValueAsI32Tool;
impl ArchWasmValueAsI32Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_as_i32".to_string(), description: "Unwrap Wasm I32 via WasmValue::as_i32.".to_string(), input_schema: json!({"type":"object","required":["v"],"properties":{"v":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueAsI32Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("v".into()))? as i32; let w = rustre_arch_wasm::WasmValue::I32(v); Ok(ToolResult::text(json!({"as_i32": w.as_i32(), "as_i64": w.as_i64(), "source": "rustre_arch_wasm::WasmValue::as_i32"}).to_string())) } }

pub struct ArchWasmValueAsF64Tool;
impl ArchWasmValueAsF64Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_as_f64".to_string(), description: "Unwrap Wasm F64 via WasmValue::as_f64.".to_string(), input_schema: json!({"type":"object","required":["v"],"properties":{"v":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueAsF64Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("v".into()))?; let w = rustre_arch_wasm::WasmValue::F64(v); Ok(ToolResult::text(json!({"as_f64": w.as_f64(), "as_i32": w.as_i32(), "source": "rustre_arch_wasm::WasmValue::as_f64"}).to_string())) } }

pub struct ArchWasmValueTypeTagTool;
impl ArchWasmValueTypeTagTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_type_tag".to_string(), description: "WasmValueType tag via WasmValue::value_type.".to_string(), input_schema: json!({"type":"object","required":["v"],"properties":{"v":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueTypeTagTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("v".into()))?; let w = rustre_arch_wasm::WasmValue::I64(v); Ok(ToolResult::text(json!({"tag": w.value_type().name(), "source": "rustre_arch_wasm::WasmValue::value_type"}).to_string())) } }

pub struct ArchWasmStackOpsTool;
impl ArchWasmStackOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_stack_ops".to_string(), description: "Exercise WasmStack push/pop/peek/depth.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmStackOpsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut s = rustre_arch_wasm::WasmStack::new(); let empty_start = s.is_empty(); s.push(rustre_arch_wasm::WasmValue::I32(1)); s.push(rustre_arch_wasm::WasmValue::I32(2)); let depth = s.depth(); let peek = s.peek().map(|v| v.as_i32()).ok().flatten(); let popped = s.pop().ok().and_then(|v| v.as_i32()); Ok(ToolResult::text(json!({"empty_start": empty_start, "depth_after_push": depth, "peek": peek, "popped": popped, "final_depth": s.depth(), "source": "rustre_arch_wasm::WasmStack"}).to_string())) } }

pub struct ArchWasmStackDrainTool;
impl ArchWasmStackDrainTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_stack_drain".to_string(), description: "Drain WasmStack via WasmStack::drain.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmStackDrainTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize; let mut s = rustre_arch_wasm::WasmStack::new(); for i in 0..n { s.push(rustre_arch_wasm::WasmValue::I32(i as i32)); } let drained = s.drain(); Ok(ToolResult::text(json!({"drained_count": drained.len(), "final_depth": s.depth(), "source": "rustre_arch_wasm::WasmStack::drain"}).to_string())) } }

pub struct ArchWasmDecodeTypeTool;
impl ArchWasmDecodeTypeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_decode_type".to_string(), description: "Decode a valtype byte via decode_type.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer","minimum":0,"maximum":255}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmDecodeTypeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let vt = rustre_arch_wasm::decode_type(b); Ok(ToolResult::text(json!({"recognized": vt.is_some(), "debug": format!("{:?}", vt), "source": "rustre_arch_wasm::decode_type"}).to_string())) } }

pub struct ArchWasmDecodeFuncTypeTool;
impl ArchWasmDecodeFuncTypeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_decode_func_type".to_string(), description: "Decode function type via decode_func_type.".to_string(), input_schema: json!({"type":"object","required":["bytes_hex"],"properties":{"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmDecodeFuncTypeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("bytes_hex".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); match rustre_arch_wasm::decode_func_type(&bytes) { Ok(ft) => Ok(ToolResult::text(json!({"params": ft.params.len(), "results": ft.results.len(), "source": "rustre_arch_wasm::decode_func_type"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"error": e.to_string(), "source": "rustre_arch_wasm::decode_func_type"}).to_string())) } } }

pub struct ArchWasmFuncTypeArityTool;
impl ArchWasmFuncTypeArityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_functype_arity".to_string(), description: "Arity via WasmFuncType::arity.".to_string(), input_schema: json!({"type":"object","required":["bytes_hex"],"properties":{"bytes_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmFuncTypeArityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("bytes_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("bytes_hex".into()))?; let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i+2)?, 16).ok()).collect(); match rustre_arch_wasm::WasmFuncType::decode(&bytes) { Ok(ft) => { let (p, r) = ft.arity(); Ok(ToolResult::text(json!({"params": p, "results": r, "source": "rustre_arch_wasm::WasmFuncType::arity"}).to_string())) }, Err(e) => Ok(ToolResult::text(json!({"error": e.to_string(), "source": "rustre_arch_wasm::WasmFuncType::arity"}).to_string())) } } }

pub struct ArchWasmNameSubsectionNameTool;
impl ArchWasmNameSubsectionNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_name_subsection_name".to_string(), description: "NameSubsectionType::name for a byte.".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer","minimum":0,"maximum":255}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmNameSubsectionNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let name = rustre_arch_wasm::NameSubsectionType::from_byte(b).map(|n| n.name()); Ok(ToolResult::text(json!({"name": name, "source": "rustre_arch_wasm::NameSubsectionType::name"}).to_string())) } }

pub struct ArchWasmMutabilityByteTool;
impl ArchWasmMutabilityByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_mutability_probe".to_string(), description: "Probe WasmMutability::from_byte.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmMutabilityByteTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let c = rustre_arch_wasm::WasmMutability::from_byte(0); let m = rustre_arch_wasm::WasmMutability::from_byte(1); let bad = rustre_arch_wasm::WasmMutability::from_byte(9); Ok(ToolResult::text(json!({"const": format!("{:?}", c), "mutable": format!("{:?}", m), "bad": format!("{:?}", bad), "source": "rustre_arch_wasm::WasmMutability::from_byte"}).to_string())) } }

pub struct ArchWasmValueTypeByteTool;
impl ArchWasmValueTypeByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_valuetype_byte_roundtrip".to_string(), description: "Roundtrip WasmValueType via byte().".to_string(), input_schema: json!({"type":"object","required":["byte"],"properties":{"byte":{"type":"integer","minimum":0,"maximum":255}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueTypeByteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("byte".into()))? as u8; let vt = rustre_arch_wasm::WasmValueType::from_byte(b); let enc = vt.map(|v| v.byte()); Ok(ToolResult::text(json!({"decoded": vt.map(|v| v.name()), "reencoded": enc, "roundtrip_ok": enc == Some(b), "source": "rustre_arch_wasm::WasmValueType::byte"}).to_string())) } }

pub struct ArchWasmValueAsI64Tool;
impl ArchWasmValueAsI64Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_as_i64".to_string(), description: "Unwrap Wasm I64 via WasmValue::as_i64.".to_string(), input_schema: json!({"type":"object","required":["v"],"properties":{"v":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueAsI64Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("v".into()))?; let w = rustre_arch_wasm::WasmValue::I64(v); Ok(ToolResult::text(json!({"as_i64": w.as_i64(), "as_i32": w.as_i32(), "source": "rustre_arch_wasm::WasmValue::as_i64"}).to_string())) } }

pub struct ArchWasmValueAsF32Tool;
impl ArchWasmValueAsF32Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_as_f32".to_string(), description: "Unwrap Wasm F32 via WasmValue::as_f32.".to_string(), input_schema: json!({"type":"object","required":["v"],"properties":{"v":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValueAsF32Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("v".into()))? as f32; let w = rustre_arch_wasm::WasmValue::F32(v); Ok(ToolResult::text(json!({"as_f32": w.as_f32(), "as_f64": w.as_f64(), "source": "rustre_arch_wasm::WasmValue::as_f32"}).to_string())) } }

pub struct ArchWasmCfBasicBlocksTool;
impl ArchWasmCfBasicBlocksTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_cf_basic_blocks".to_string(), description: "Extract basic block ranges via WasmControlFlow::extract_basic_blocks.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCfBasicBlocksTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_arch_wasm::WasmOpcode::*; let instrs = vec![I32Const(1), I32Const(2), I32Add, Br(0), Nop, End, I32Const(3), Return]; let blocks = rustre_arch_wasm::WasmControlFlow::extract_basic_blocks(&instrs); Ok(ToolResult::text(json!({"instr_count": instrs.len(), "block_count": blocks.len(), "source": "rustre_arch_wasm::WasmControlFlow::extract_basic_blocks"}).to_string())) } }

pub struct ArchWasmCfFindBlockEndTool;
impl ArchWasmCfFindBlockEndTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_cf_find_block_end".to_string(), description: "Locate matching End opcode via WasmControlFlow::find_block_end.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCfFindBlockEndTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_arch_wasm::WasmOpcode::*; let start = args.get("start").and_then(Value::as_u64).unwrap_or(0) as usize; let instrs = vec![Nop, I32Const(1), Drop, End, I32Const(2), End]; let end = rustre_arch_wasm::WasmControlFlow::find_block_end(&instrs, start); Ok(ToolResult::text(json!({"start": start, "end_index": end, "instr_count": instrs.len(), "source": "rustre_arch_wasm::WasmControlFlow::find_block_end"}).to_string())) } }

pub struct ArchWasmExecutorNewTool;
impl ArchWasmExecutorNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_executor_new".to_string(), description: "Construct a WasmExecutor and report its initial shape.".to_string(), input_schema: json!({"type":"object","properties":{"memory_size":{"type":"integer","minimum":0},"num_locals":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmExecutorNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mem = args.get("memory_size").and_then(Value::as_u64).unwrap_or(64) as usize; let nloc = args.get("num_locals").and_then(Value::as_u64).unwrap_or(4) as usize; let e = rustre_arch_wasm::WasmExecutor::new(mem, nloc); Ok(ToolResult::text(json!({"memory_bytes": e.memory.len(), "locals": e.locals.len(), "stack_depth": e.stack.depth(), "source": "rustre_arch_wasm::WasmExecutor::new"}).to_string())) } }

pub struct ArchWasmExecutorResetTool;
impl ArchWasmExecutorResetTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_executor_reset".to_string(), description: "Reset a WasmExecutor via WasmExecutor::reset.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmExecutorResetTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut e = rustre_arch_wasm::WasmExecutor::new(32, 2); e.stack.push(rustre_arch_wasm::WasmValue::I32(1)); e.stack.push(rustre_arch_wasm::WasmValue::I32(2)); let before = e.stack.depth(); e.reset(); Ok(ToolResult::text(json!({"depth_before": before, "depth_after": e.stack.depth(), "memory_len": e.memory.len(), "source": "rustre_arch_wasm::WasmExecutor::reset"}).to_string())) } }

pub struct ArchWasmSimdProbeTool;
impl ArchWasmSimdProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_simd_probe".to_string(), description: "Probe simd_opcode_mnemonic across a set of SIMD sub-opcodes.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmSimdProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let subs = [0u32, 1, 12, 13, 0xFFFF]; let hits: usize = subs.iter().filter(|s| rustre_arch_wasm::simd_opcode_mnemonic(**s).is_some()).count(); Ok(ToolResult::text(json!({"probed": subs.len(), "hits": hits, "source": "rustre_arch_wasm::simd_opcode_mnemonic"}).to_string())) } }

pub struct ArchWasmValtypeRefProbeTool;
impl ArchWasmValtypeRefProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_valtype_ref_probe".to_string(), description: "Probe WasmValueType is_reference / is_numeric across a batch of bytes.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmValtypeRefProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0x7Fu8, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F, 0x00]; let mut ref_count = 0; let mut num_count = 0; for b in bytes.iter() { if let Some(vt) = rustre_arch_wasm::WasmValueType::from_byte(*b) { if vt.is_reference() { ref_count += 1; } if vt.is_numeric() { num_count += 1; } } } Ok(ToolResult::text(json!({"probed": bytes.len(), "reference": ref_count, "numeric": num_count, "source": "rustre_arch_wasm::WasmValueType"}).to_string())) } }

pub struct ArchWasmSectionIdProbeTool;
impl ArchWasmSectionIdProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_section_id_probe".to_string(), description: "Probe WasmSectionId::from_byte across the well-known range.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmSectionIdProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let hits: usize = (0u8..=13).filter(|b| rustre_arch_wasm::WasmSectionId::from_byte(*b).is_some()).count(); Ok(ToolResult::text(json!({"probed": 14, "hits": hits, "source": "rustre_arch_wasm::WasmSectionId::from_byte"}).to_string())) } }

pub struct ArchWasmExternalKindProbeTool;
impl ArchWasmExternalKindProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_external_kind_probe".to_string(), description: "Probe WasmExternalKind::from_byte over 0..=4.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmExternalKindProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let hits: usize = (0u8..=4).filter(|b| rustre_arch_wasm::WasmExternalKind::from_byte(*b).is_some()).count(); Ok(ToolResult::text(json!({"probed": 5, "hits": hits, "source": "rustre_arch_wasm::WasmExternalKind::from_byte"}).to_string())) } }

pub struct ArchWasmValueAsV128Tool;
impl ArchWasmValueAsV128Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_value_as_v128".to_string(), description: "Unwrap WasmValue::V128 via as_v128.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmValueAsV128Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = rustre_arch_wasm::WasmValue::V128([0xAB; 16]); let out = v.as_v128().map(|b| b.to_vec()).unwrap_or_default(); let hex: String = out.iter().map(|b| format!("{b:02x}")).collect(); Ok(ToolResult::text(json!({"hex":hex,"len":out.len(),"is_some":!out.is_empty(),"source":"rustre_arch_wasm::WasmValue::as_v128"}).to_string())) } }

pub struct ArchWasmStackNewEmptyTool;
impl ArchWasmStackNewEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_stack_new_empty".to_string(), description: "Construct empty WasmStack and check is_empty/depth.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmStackNewEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_arch_wasm::WasmStack::new(); Ok(ToolResult::text(json!({"is_empty":s.is_empty(),"depth":s.depth(),"source":"rustre_arch_wasm::WasmStack::new"}).to_string())) } }

pub struct ArchWasmLinearDisassemblerNewTool;
impl ArchWasmLinearDisassemblerNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_linear_disassembler_new".to_string(), description: "Construct WasmLinearDisassembler and check initial offset.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmLinearDisassemblerNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).unwrap_or("0141010b").chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let arch = rustre_arch_wasm::WasmArch::new(); let d = rustre_arch_wasm::WasmLinearDisassembler::new(&arch, &data, rustre_core::address::Address::new(0)); Ok(ToolResult::text(json!({"initial_offset":d.offset(),"input_len":data.len(),"source":"rustre_arch_wasm::WasmLinearDisassembler::new"}).to_string())) } }

pub struct ArchWasmFunctionStatsFromBytesTool;
impl ArchWasmFunctionStatsFromBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_function_stats_from_bytes".to_string(), description: "Compute WasmFunctionStats::from_bytes for a byte slice.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmFunctionStatsFromBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let arch = rustre_arch_wasm::WasmArch::new(); match rustre_arch_wasm::WasmFunctionStats::from_bytes(&arch, &data) { Ok(st) => Ok(ToolResult::text(json!({"instruction_count":st.instruction_count,"call_count":st.call_count,"branch_count":st.branch_count,"load_count":st.load_count,"store_count":st.store_count,"return_count":st.return_count,"unreachable_count":st.unreachable_count,"source":"rustre_arch_wasm::WasmFunctionStats::from_bytes"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct ArchWasmNameSubsectionTypeProbeTool;
impl ArchWasmNameSubsectionTypeProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_name_subsection_type_probe".to_string(), description: "Probe NameSubsectionType::from_byte over 0..=10 and report names.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmNameSubsectionTypeProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let names: Vec<Value> = (0u8..=10).map(|b| json!({"byte":b,"name":rustre_arch_wasm::NameSubsectionType::from_byte(b).map(|t| t.name())})).collect(); Ok(ToolResult::text(json!({"probes":names,"source":"rustre_arch_wasm::NameSubsectionType::from_byte"}).to_string())) } }

pub struct ArchWasmExecutorExecuteInstructionTool;
impl ArchWasmExecutorExecuteInstructionTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_executor_execute_instruction".to_string(), description: "Execute i32.const a; i32.const b; i32.add via WasmExecutor::execute_instruction.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmExecutorExecuteInstructionTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = i32::try_from(args.get("a").and_then(Value::as_i64).unwrap_or(0)).unwrap_or(0); let b = i32::try_from(args.get("b").and_then(Value::as_i64).unwrap_or(0)).unwrap_or(0); let mut e = rustre_arch_wasm::WasmExecutor::new(0, 0); e.execute_instruction(&rustre_arch_wasm::WasmOpcode::I32Const(a), None).map_err(|er| McpError::InternalError(er.to_string()))?; e.execute_instruction(&rustre_arch_wasm::WasmOpcode::I32Const(b), None).map_err(|er| McpError::InternalError(er.to_string()))?; e.execute_instruction(&rustre_arch_wasm::WasmOpcode::I32Add, None).map_err(|er| McpError::InternalError(er.to_string()))?; let top = e.stack.peek().ok().and_then(|v| v.as_i32()); Ok(ToolResult::text(json!({"result":top,"depth":e.stack.depth(),"source":"rustre_arch_wasm::WasmExecutor::execute_instruction"}).to_string())) } }

pub struct ArchWasmControlFlowExtractBlocksTool;
impl ArchWasmControlFlowExtractBlocksTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_control_flow_extract_blocks".to_string(), description: "Run WasmControlFlow::extract_basic_blocks on a canned sample.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmControlFlowExtractBlocksTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let ops = vec![rustre_arch_wasm::WasmOpcode::I32Const(0), rustre_arch_wasm::WasmOpcode::BrIf(0), rustre_arch_wasm::WasmOpcode::I32Const(1), rustre_arch_wasm::WasmOpcode::Return]; let blocks = rustre_arch_wasm::WasmControlFlow::extract_basic_blocks(&ops); let out: Vec<Value> = blocks.iter().map(|(s,e)| json!({"start":s,"end":e})).collect(); let n = out.len(); Ok(ToolResult::text(json!({"count":n,"blocks":out,"source":"rustre_arch_wasm::WasmControlFlow::extract_basic_blocks"}).to_string())) } }

pub struct ArchWasmModuleHeaderValidCheckTool;
impl ArchWasmModuleHeaderValidCheckTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_module_header_valid_check".to_string(), description: "Parse a valid Wasm header via WasmModuleHeader::parse.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmModuleHeaderValidCheckTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let good = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]; let bad = [0xFF, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]; let g = rustre_arch_wasm::WasmModuleHeader::parse(&good).is_ok(); let b = rustre_arch_wasm::WasmModuleHeader::parse(&bad).is_ok(); Ok(ToolResult::text(json!({"valid_parses":g,"invalid_parses":b,"source":"rustre_arch_wasm::WasmModuleHeader::parse"}).to_string())) } }

pub struct ArchWasmValtypeAllBytesTool;
impl ArchWasmValtypeAllBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_valtype_all_bytes".to_string(), description: "Enumerate encoding bytes for all WasmValueType variants via byte().".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmValtypeAllBytesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_arch_wasm::WasmValueType as V; let all = [V::I32, V::I64, V::F32, V::F64, V::V128, V::FuncRef, V::ExternRef]; let out: Vec<Value> = all.iter().map(|v| json!({"name":v.name(),"byte":v.byte(),"is_numeric":v.is_numeric(),"is_reference":v.is_reference()})).collect(); Ok(ToolResult::text(json!({"types":out,"count":all.len(),"source":"rustre_arch_wasm::WasmValueType::byte"}).to_string())) } }

pub struct ArchWasmSectionIdAllTool;
impl ArchWasmSectionIdAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_section_id_all".to_string(), description: "Enumerate all WasmSectionId variants 0..=12 and their names.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmSectionIdAllTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let out: Vec<Value> = (0u8..=12).filter_map(|b| rustre_arch_wasm::WasmSectionId::from_byte(b).map(|s| json!({"byte":b,"name":s.name()}))).collect(); let n = out.len(); Ok(ToolResult::text(json!({"sections":out,"count":n,"source":"rustre_arch_wasm::WasmSectionId::from_byte"}).to_string())) } }

pub struct ArchWasmLimitsNoMaxCheckTool;
impl ArchWasmLimitsNoMaxCheckTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_limits_no_max_check".to_string(), description: "Decode min-only limits via WasmLimits::decode and confirm max is None.".to_string(), input_schema: json!({"type":"object","properties":{"min":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ArchWasmLimitsNoMaxCheckTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let min = u8::try_from(args.get("min").and_then(Value::as_u64).unwrap_or(4)).unwrap_or(4); let bytes = [0x00u8, min]; match rustre_arch_wasm::WasmLimits::decode(&bytes) { Ok((lim, n)) => Ok(ToolResult::text(json!({"min":lim.min,"has_max":lim.max.is_some(),"consumed":n,"source":"rustre_arch_wasm::WasmLimits::decode"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct ArchWasmCallGraphEdgeCountTool;
impl ArchWasmCallGraphEdgeCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_call_graph_edge_count".to_string(), description: "FunctionCallGraph::add_call + edge_count.".to_string(), input_schema: json!({"type":"object","properties":{"function_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCallGraphEdgeCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let fc = args.get("function_count").and_then(Value::as_u64).unwrap_or(4) as u32; let mut g = rustre_arch_wasm::wasm_analysis::FunctionCallGraph::new(fc); g.add_call(0, 1); g.add_call(0, 2); g.add_call(1, 3); Ok(ToolResult::text(json!({"edge_count": g.edge_count(), "function_count": g.function_count, "source": "rustre_arch_wasm::wasm_analysis::FunctionCallGraph::edge_count"}).to_string())) } }

pub struct ArchWasmCallGraphCalleesOfTool;
impl ArchWasmCallGraphCalleesOfTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_call_graph_callees_of".to_string(), description: "FunctionCallGraph::callees_of after seeding edges.".to_string(), input_schema: json!({"type":"object","properties":{"caller":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCallGraphCalleesOfTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let caller = args.get("caller").and_then(Value::as_u64).unwrap_or(0) as u32; let mut g = rustre_arch_wasm::wasm_analysis::FunctionCallGraph::new(4); g.add_call(0, 1); g.add_call(0, 2); g.add_call(1, 3); let mut callees: Vec<u32> = g.callees_of(caller).iter().copied().collect(); callees.sort_unstable(); Ok(ToolResult::text(json!({"caller": caller, "callees": callees, "source": "rustre_arch_wasm::wasm_analysis::FunctionCallGraph::callees_of"}).to_string())) } }

pub struct ArchWasmCallGraphReachableFromTool;
impl ArchWasmCallGraphReachableFromTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_call_graph_reachable_from".to_string(), description: "FunctionCallGraph::reachable_from BFS.".to_string(), input_schema: json!({"type":"object","properties":{"root":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCallGraphReachableFromTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let root = args.get("root").and_then(Value::as_u64).unwrap_or(0) as u32; let mut g = rustre_arch_wasm::wasm_analysis::FunctionCallGraph::new(5); g.add_call(0, 1); g.add_call(1, 2); g.add_call(2, 3); let reachable = g.reachable_from(root); Ok(ToolResult::text(json!({"root": root, "reachable_count": reachable.len(), "source": "rustre_arch_wasm::wasm_analysis::FunctionCallGraph::reachable_from"}).to_string())) } }

pub struct ArchWasmCallGraphRootsLeavesTool;
impl ArchWasmCallGraphRootsLeavesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_call_graph_roots_leaves".to_string(), description: "FunctionCallGraph roots() and leaves().".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCallGraphRootsLeavesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut g = rustre_arch_wasm::wasm_analysis::FunctionCallGraph::new(4); g.add_call(0, 1); g.add_call(0, 2); let mut roots = g.roots(); roots.sort_unstable(); let mut leaves = g.leaves(); leaves.sort_unstable(); Ok(ToolResult::text(json!({"roots": roots, "leaves": leaves, "source": "rustre_arch_wasm::wasm_analysis::FunctionCallGraph::roots"}).to_string())) } }

pub struct ArchWasmCallGraphRecursiveTool;
impl ArchWasmCallGraphRecursiveTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_call_graph_recursive".to_string(), description: "FunctionCallGraph::recursive_functions.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmCallGraphRecursiveTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut g = rustre_arch_wasm::wasm_analysis::FunctionCallGraph::new(3); g.add_call(0, 0); g.add_call(1, 2); let mut r = g.recursive_functions(); r.sort_unstable(); Ok(ToolResult::text(json!({"recursive": r, "source": "rustre_arch_wasm::wasm_analysis::FunctionCallGraph::recursive_functions"}).to_string())) } }

pub struct ArchWasmIndirectCallTableResolveTool;
impl ArchWasmIndirectCallTableResolveTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_indirect_call_table_resolve".to_string(), description: "IndirectCallTable::resolve slot lookup.".to_string(), input_schema: json!({"type":"object","properties":{"slot":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmIndirectCallTableResolveTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let slot = args.get("slot").and_then(Value::as_u64).unwrap_or(1) as u32; let mut t = rustre_arch_wasm::wasm_analysis::IndirectCallTable::new(8); t.add_entry(0, 10); t.add_entry(1, 20); t.add_entry(2, 30); let resolved = t.resolve(slot); Ok(ToolResult::text(json!({"slot": slot, "resolved": resolved, "source": "rustre_arch_wasm::wasm_analysis::IndirectCallTable::resolve"}).to_string())) } }

pub struct ArchWasmIndirectCallTableEntryCountTool;
impl ArchWasmIndirectCallTableEntryCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_indirect_call_table_entry_count".to_string(), description: "IndirectCallTable::entry_count + function_indices.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmIndirectCallTableEntryCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as u32; let mut t = rustre_arch_wasm::wasm_analysis::IndirectCallTable::new(16); for i in 0..n { t.add_entry(i, 100 + i); } Ok(ToolResult::text(json!({"entry_count": t.entry_count(), "unique_functions": t.function_indices().len(), "table_size": t.table_size, "source": "rustre_arch_wasm::wasm_analysis::IndirectCallTable::entry_count"}).to_string())) } }

pub struct ArchWasmFunctionRefFuncImportTool;
impl ArchWasmFunctionRefFuncImportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_function_ref_func_import".to_string(), description: "WasmFunctionRef::func vs import constructors.".to_string(), input_schema: json!({"type":"object","properties":{"idx":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmFunctionRefFuncImportTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let idx = args.get("idx").and_then(Value::as_u64).unwrap_or(7) as u32; let f = rustre_arch_wasm::wasm_analysis::WasmFunctionRef::func(idx); let i = rustre_arch_wasm::wasm_analysis::WasmFunctionRef::import(idx); Ok(ToolResult::text(json!({"func_idx": f.index, "func_is_import": f.is_import, "import_idx": i.index, "import_is_import": i.is_import, "source": "rustre_arch_wasm::wasm_analysis::WasmFunctionRef"}).to_string())) } }

pub struct ArchWasmDataFlowStateProbeTool;
impl ArchWasmDataFlowStateProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_data_flow_state_probe".to_string(), description: "DataFlowState push/pop/set_local/get_local roundtrip.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmDataFlowStateProbeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_arch_wasm::wasm_analysis::{DataFlowState, WasmValType}; let mut s = DataFlowState::default(); s.push(WasmValType::I32); s.push(WasmValType::I64); let popped = s.pop().map(|t| t.to_string()); s.set_local(0, WasmValType::F64); let got = s.get_local(0).to_string(); let default_missing = s.get_local(42).to_string(); Ok(ToolResult::text(json!({"popped": popped, "local0": got, "missing_default": default_missing, "stack_depth": s.stack.len(), "source": "rustre_arch_wasm::wasm_analysis::DataFlowState"}).to_string())) } }

pub struct ArchWasmDataFlowAnalysisRecordTool;
impl ArchWasmDataFlowAnalysisRecordTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_data_flow_analysis_record".to_string(), description: "DataFlowAnalysis::record + get for an offset.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmDataFlowAnalysisRecordTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(4) as u32; let mut a = rustre_arch_wasm::wasm_analysis::DataFlowAnalysis::new(); let state = rustre_arch_wasm::wasm_analysis::DataFlowState::default(); a.record(offset, state); let hit = a.get(offset).is_some(); let miss = a.get(offset.wrapping_add(1)).is_some(); Ok(ToolResult::text(json!({"offset": offset, "hit": hit, "miss": miss, "state_count": a.states.len(), "source": "rustre_arch_wasm::wasm_analysis::DataFlowAnalysis::record"}).to_string())) } }

pub struct ArchWasmModuleHeaderMagicOkTool;
impl ArchWasmModuleHeaderMagicOkTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_module_header_magic_ok".to_string(), description: "WasmModuleHeader::parse with canonical MAGIC/VERSION.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmModuleHeaderMagicOkTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut buf = Vec::with_capacity(8); buf.extend_from_slice(&rustre_arch_wasm::WASM_MAGIC); buf.extend_from_slice(&rustre_arch_wasm::WASM_VERSION); let ok = rustre_arch_wasm::WasmModuleHeader::parse(&buf).is_ok(); let bad = rustre_arch_wasm::WasmModuleHeader::parse(&[0xff, 0, 0, 0, 1, 0, 0, 0]).is_ok(); Ok(ToolResult::text(json!({"canonical_ok": ok, "bad_rejected": !bad, "source": "rustre_arch_wasm::WasmModuleHeader::parse"}).to_string())) } }

pub struct ArchWasmLimitsHasMaxTool;
impl ArchWasmLimitsHasMaxTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch_wasm_limits_has_max".to_string(), description: "WasmLimits::decode min-only vs min+max.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for ArchWasmLimitsHasMaxTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let (min_only, n1) = rustre_arch_wasm::WasmLimits::decode(&[0x00, 0x04]).map_err(|e| McpError::InternalError(e.to_string()))?; let (min_max, n2) = rustre_arch_wasm::WasmLimits::decode(&[0x01, 0x02, 0x10]).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"min_only_min": min_only.min, "min_only_max": min_only.max, "min_only_bytes": n1, "min_max_min": min_max.min, "min_max_max": min_max.max, "min_max_bytes": n2, "source": "rustre_arch_wasm::WasmLimits::decode"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchWasmValueTypeFromByteTool::definition(), Box::new(ArchWasmValueTypeFromByteTool)),
        (ArchWasmSectionIdFromByteTool::definition(), Box::new(ArchWasmSectionIdFromByteTool)),
        (ArchWasmExternalKindFromByteTool::definition(), Box::new(ArchWasmExternalKindFromByteTool)),
        (ArchWasmMutabilityFromByteTool::definition(), Box::new(ArchWasmMutabilityFromByteTool)),
        (ArchWasmValueTypeNameTool::definition(), Box::new(ArchWasmValueTypeNameTool)),
        (ArchWasmValueTypeIsNumericTool::definition(), Box::new(ArchWasmValueTypeIsNumericTool)),
        (ArchWasmValueTypeIsReferenceTool::definition(), Box::new(ArchWasmValueTypeIsReferenceTool)),
        (ArchWasmSectionNameTool::definition(), Box::new(ArchWasmSectionNameTool)),
        (ArchWasmExternalKindNameTool::definition(), Box::new(ArchWasmExternalKindNameTool)),
        (ArchWasmLimitsDecodeTool::definition(), Box::new(ArchWasmLimitsDecodeTool)),
        (ArchWasmFuncTypeDecodeTool::definition(), Box::new(ArchWasmFuncTypeDecodeTool)),
        (ArchWasmModuleHeaderParseTool::definition(), Box::new(ArchWasmModuleHeaderParseTool)),
        (ArchWasmConstantsTool::definition(), Box::new(ArchWasmConstantsTool)),
        (ArchWasmSimdMnemonicTool::definition(), Box::new(ArchWasmSimdMnemonicTool)),
        (ArchWasmDisassembleTool::definition(), Box::new(ArchWasmDisassembleTool)),
        (ArchWasmArchInfoTool::definition(), Box::new(ArchWasmArchInfoTool)),
        (ArchWasmMemoryTypeDecodeTool::definition(), Box::new(ArchWasmMemoryTypeDecodeTool)),
        (ArchWasmTableTypeDecodeTool::definition(), Box::new(ArchWasmTableTypeDecodeTool)),
        (ArchWasmGlobalTypeDecodeTool::definition(), Box::new(ArchWasmGlobalTypeDecodeTool)),
        (ArchWasmValtypeByteTool::definition(), Box::new(ArchWasmValtypeByteTool)),
        (ArchWasmFunctionStatsTool::definition(), Box::new(ArchWasmFunctionStatsTool)),
        (ArchWasmNameSubsectionFromByteTool::definition(), Box::new(ArchWasmNameSubsectionFromByteTool)),
        (ArchWasmDecodeFcPrefixTool::definition(), Box::new(ArchWasmDecodeFcPrefixTool)),
        (ArchWasmDecodeFdPrefixTool::definition(), Box::new(ArchWasmDecodeFdPrefixTool)),
        (ArchWasmDecodeFePrefixTool::definition(), Box::new(ArchWasmDecodeFePrefixTool)),
        (ArchWasmLinearDisassembleTool::definition(), Box::new(ArchWasmLinearDisassembleTool)),
        (ArchWasmValueAsI32Tool::definition(), Box::new(ArchWasmValueAsI32Tool)),
        (ArchWasmValueAsF64Tool::definition(), Box::new(ArchWasmValueAsF64Tool)),
        (ArchWasmValueTypeTagTool::definition(), Box::new(ArchWasmValueTypeTagTool)),
        (ArchWasmStackOpsTool::definition(), Box::new(ArchWasmStackOpsTool)),
        (ArchWasmStackDrainTool::definition(), Box::new(ArchWasmStackDrainTool)),
        (ArchWasmDecodeTypeTool::definition(), Box::new(ArchWasmDecodeTypeTool)),
        (ArchWasmDecodeFuncTypeTool::definition(), Box::new(ArchWasmDecodeFuncTypeTool)),
        (ArchWasmFuncTypeArityTool::definition(), Box::new(ArchWasmFuncTypeArityTool)),
        (ArchWasmNameSubsectionNameTool::definition(), Box::new(ArchWasmNameSubsectionNameTool)),
        (ArchWasmMutabilityByteTool::definition(), Box::new(ArchWasmMutabilityByteTool)),
        (ArchWasmValueTypeByteTool::definition(), Box::new(ArchWasmValueTypeByteTool)),
        (ArchWasmValueAsI64Tool::definition(), Box::new(ArchWasmValueAsI64Tool)),
        (ArchWasmValueAsF32Tool::definition(), Box::new(ArchWasmValueAsF32Tool)),
        (ArchWasmCfBasicBlocksTool::definition(), Box::new(ArchWasmCfBasicBlocksTool)),
        (ArchWasmCfFindBlockEndTool::definition(), Box::new(ArchWasmCfFindBlockEndTool)),
        (ArchWasmExecutorNewTool::definition(), Box::new(ArchWasmExecutorNewTool)),
        (ArchWasmExecutorResetTool::definition(), Box::new(ArchWasmExecutorResetTool)),
        (ArchWasmSimdProbeTool::definition(), Box::new(ArchWasmSimdProbeTool)),
        (ArchWasmValtypeRefProbeTool::definition(), Box::new(ArchWasmValtypeRefProbeTool)),
        (ArchWasmSectionIdProbeTool::definition(), Box::new(ArchWasmSectionIdProbeTool)),
        (ArchWasmExternalKindProbeTool::definition(), Box::new(ArchWasmExternalKindProbeTool)),
        (ArchWasmValueAsV128Tool::definition(), Box::new(ArchWasmValueAsV128Tool)),
        (ArchWasmStackNewEmptyTool::definition(), Box::new(ArchWasmStackNewEmptyTool)),
        (ArchWasmLinearDisassemblerNewTool::definition(), Box::new(ArchWasmLinearDisassemblerNewTool)),
        (ArchWasmFunctionStatsFromBytesTool::definition(), Box::new(ArchWasmFunctionStatsFromBytesTool)),
        (ArchWasmNameSubsectionTypeProbeTool::definition(), Box::new(ArchWasmNameSubsectionTypeProbeTool)),
        (ArchWasmExecutorExecuteInstructionTool::definition(), Box::new(ArchWasmExecutorExecuteInstructionTool)),
        (ArchWasmControlFlowExtractBlocksTool::definition(), Box::new(ArchWasmControlFlowExtractBlocksTool)),
        (ArchWasmModuleHeaderValidCheckTool::definition(), Box::new(ArchWasmModuleHeaderValidCheckTool)),
        (ArchWasmValtypeAllBytesTool::definition(), Box::new(ArchWasmValtypeAllBytesTool)),
        (ArchWasmSectionIdAllTool::definition(), Box::new(ArchWasmSectionIdAllTool)),
        (ArchWasmLimitsNoMaxCheckTool::definition(), Box::new(ArchWasmLimitsNoMaxCheckTool)),
        (ArchWasmCallGraphEdgeCountTool::definition(), Box::new(ArchWasmCallGraphEdgeCountTool)),
        (ArchWasmCallGraphCalleesOfTool::definition(), Box::new(ArchWasmCallGraphCalleesOfTool)),
        (ArchWasmCallGraphReachableFromTool::definition(), Box::new(ArchWasmCallGraphReachableFromTool)),
        (ArchWasmCallGraphRootsLeavesTool::definition(), Box::new(ArchWasmCallGraphRootsLeavesTool)),
        (ArchWasmCallGraphRecursiveTool::definition(), Box::new(ArchWasmCallGraphRecursiveTool)),
        (ArchWasmIndirectCallTableResolveTool::definition(), Box::new(ArchWasmIndirectCallTableResolveTool)),
        (ArchWasmIndirectCallTableEntryCountTool::definition(), Box::new(ArchWasmIndirectCallTableEntryCountTool)),
        (ArchWasmFunctionRefFuncImportTool::definition(), Box::new(ArchWasmFunctionRefFuncImportTool)),
        (ArchWasmDataFlowStateProbeTool::definition(), Box::new(ArchWasmDataFlowStateProbeTool)),
        (ArchWasmDataFlowAnalysisRecordTool::definition(), Box::new(ArchWasmDataFlowAnalysisRecordTool)),
        (ArchWasmModuleHeaderMagicOkTool::definition(), Box::new(ArchWasmModuleHeaderMagicOkTool)),
        (ArchWasmLimitsHasMaxTool::definition(), Box::new(ArchWasmLimitsHasMaxTool)),
    ]
}
