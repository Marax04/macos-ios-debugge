//! MCP wrappers for the rustre-vmlift crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{vmlift_hex_to_bytes_wl, vmlift_parse_semantic_wl};

pub struct VmliftDefaultIsaLenTool;
impl VmliftDefaultIsaLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_default_isa_len".to_string(),
            description: "Return the number of handler definitions in VmIsa::default_lifter_isa \
                          (rustre_deobf_vmlift::VmIsa::default_lifter_isa)."
                .to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDefaultIsaLenTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa();
        Ok(ToolResult::text(json!({
            "handlers": isa.len(),
            "source": "rustre_deobf_vmlift::VmIsa::default_lifter_isa",
        }).to_string()))
    }
}

pub struct VmliftDefaultIsaListingTool;
impl VmliftDefaultIsaListingTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_default_isa_listing".to_string(),
            description: "Return the human-readable listing of the default VM lifter ISA \
                          (rustre_deobf_vmlift::VmIsa::listing)."
                .to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDefaultIsaListingTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa();
        Ok(ToolResult::text(json!({
            "listing": isa.listing(),
            "handlers": isa.len(),
            "source": "rustre_deobf_vmlift::VmIsa::listing",
        }).to_string()))
    }
}

pub struct VmliftLiftToPseudoIlTool;
impl VmliftLiftToPseudoIlTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_lift_to_pseudo_il".to_string(),
            description: "Decode a bytecode buffer to guest instructions and emit pseudo-IL \
                          (rustre_deobf_vmlift::VmLifter::lift_to_instructions + to_pseudo_il)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftLiftToPseudoIlTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        match rustre_deobf_vmlift::VmLifter::lift_to_instructions(&data) {
            Ok(instrs) => {
                let pseudo = rustre_deobf_vmlift::VmLifter::to_pseudo_il(&instrs);
                Ok(ToolResult::text(json!({
                    "input_len": data.len(),
                    "instruction_count": instrs.len(),
                    "pseudo_il": pseudo,
                    "source": "rustre_deobf_vmlift::VmLifter::lift_to_instructions",
                }).to_string()))
            }
            Err(e) => Err(McpError::InvalidParams(format!("lift error: {e}"))),
        }
    }
}

pub struct VmliftDetectDispatchersInBytesTool;
impl VmliftDetectDispatchersInBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_detect_dispatchers_in_bytes".to_string(),
            description: "Scan code bytes for VM dispatcher patterns.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" },
                    "base":  { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDetectDispatchersInBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let ds = rustre_deobf_vmlift::VmDispatcherDetector::detect_in_bytes(&data, base);
        Ok(ToolResult::text(json!({
            "input_len": data.len(),
            "base": base,
            "dispatcher_count": ds.len(),
            "dispatchers": ds.iter().map(|d| json!({
                "offset": d.offset,
                "size": d.size,
                "confidence": d.confidence,
                "handler_count": d.handler_count,
                "description": d.description,
            })).collect::<Vec<_>>(),
            "source": "rustre_deobf_vmlift::VmDispatcherDetector::detect_in_bytes",
        }).to_string()))
    }
}

pub struct VmliftExtractJumpTableEntriesTool;
impl VmliftExtractJumpTableEntriesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_extract_jump_table_entries".to_string(),
            description: "Extract jump-table entries from a byte buffer.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" },
                    "table_offset": { "type": "integer" },
                    "count": { "type": "integer" },
                    "addr_size": { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftExtractJumpTableEntriesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let table_offset = args.get("table_offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(16) as usize;
        let addr_size = args.get("addr_size").and_then(Value::as_u64).unwrap_or(8) as u8;
        let entries = rustre_deobf_vmlift::VmDispatcherDetector::extract_jump_table_entries(&data, table_offset, count, addr_size);
        let entry_count = entries.len();
        Ok(ToolResult::text(json!({
            "entries": entries,
            "entry_count": entry_count,
            "source": "rustre_deobf_vmlift::VmDispatcherDetector::extract_jump_table_entries",
        }).to_string()))
    }
}

pub struct VmliftDetectAndReportTool;
impl VmliftDetectAndReportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_detect_and_report".to_string(),
            description: "Run VM dispatcher detection and produce a report.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" },
                    "base":  { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDetectAndReportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        let report = rustre_deobf_vmlift::VmLifterPipeline::detect_and_report(&data, base);
        Ok(ToolResult::text(json!({
            "dispatchers_found": report.dispatchers_found,
            "total_handlers": report.total_handlers,
            "isa_size": report.isa.len(),
            "analysis_notes": report.analysis_notes,
            "source": "rustre_deobf_vmlift::VmLifterPipeline::detect_and_report",
        }).to_string()))
    }
}

pub struct VmliftFullPipelineTool;
impl VmliftFullPipelineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_full_pipeline".to_string(),
            description: "Detect dispatchers, synthesise ISA, and disassemble bytecode to lifted text.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["code_hex", "bytecode_hex"],
                "properties": {
                    "code_hex": { "type": "string" },
                    "bytecode_hex": { "type": "string" },
                    "base": { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftFullPipelineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        fn hex_to_vec(s: &str) -> Result<Vec<u8>, McpError> {
            // panic su lunghezza dispari. Espressione di coda: NIENTE `?`, la `fn`
            // deve restituire il `Result`, non srotolarlo.
            crate::hex_decode(s)
        }
        let code_hex = args.get("code_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'code_hex'".into()))?;
        let bytecode_hex = args.get("bytecode_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytecode_hex'".into()))?;
        let code = hex_to_vec(code_hex)?;
        let bytecode = hex_to_vec(bytecode_hex)?;
        let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
        match rustre_deobf_vmlift::VmLifterPipeline::full_pipeline(&code, base, &bytecode) {
            Ok(lines) => Ok(ToolResult::text(json!({
                "line_count": lines.len(),
                "lines": lines,
                "source": "rustre_deobf_vmlift::VmLifterPipeline::full_pipeline",
            }).to_string())),
            Err(e) => Err(McpError::InvalidParams(format!("pipeline error: {e}"))),
        }
    }
}

pub struct VmliftDisassembleDefaultTool;
impl VmliftDisassembleDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_disassemble_default".to_string(),
            description: "Disassemble a bytecode buffer using the default lifter ISA.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDisassembleDefaultTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa();
        match rustre_deobf_vmlift::VmBytecodeDisassembler::disassemble(&data, &isa) {
            Ok(instrs) => {
                let text = rustre_deobf_vmlift::VmBytecodeDisassembler::to_text(&instrs);
                Ok(ToolResult::text(json!({
                    "input_len": data.len(),
                    "instruction_count": instrs.len(),
                    "text": text,
                    "source": "rustre_deobf_vmlift::VmBytecodeDisassembler::disassemble",
                }).to_string()))
            }
            Err(e) => Err(McpError::InvalidParams(format!("decode error: {e}"))),
        }
    }
}

pub struct VmliftDefaultIsaOpcodesTool;
impl VmliftDefaultIsaOpcodesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_default_isa_opcodes".to_string(),
            description: "Return sorted opcodes with mnemonics for the default lifter ISA.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftDefaultIsaOpcodesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa();
        let entries: Vec<_> = isa.sorted_handlers().iter().map(|d| json!({
            "opcode": d.opcode,
            "mnemonic": d.mnemonic,
            "operand_bytes": d.operand_bytes,
        })).collect();
        Ok(ToolResult::text(json!({
            "handler_count": entries.len(),
            "handlers": entries,
            "source": "rustre_deobf_vmlift::VmIsa::sorted_handlers",
        }).to_string()))
    }
}

pub struct VmliftSuggestMnemonicHaltTool;
impl VmliftSuggestMnemonicHaltTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_suggest_mnemonic_halt".to_string(),
            description: "Return suggested mnemonic for the Halt handler semantic.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftSuggestMnemonicHaltTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let m = rustre_deobf_vmlift::suggest_mnemonic(&rustre_deobf_vmlift::HandlerSemantic::Halt);
        Ok(ToolResult::text(json!({
            "semantic": "Halt",
            "mnemonic": m,
            "source": "rustre_deobf_vmlift::suggest_mnemonic",
        }).to_string()))
    }
}

pub struct VmliftHandlerSemanticFlagsTool;
impl VmliftHandlerSemanticFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_handler_semantic_flags".to_string(),
            description: "Report is_control_flow / accesses_memory for canonical HandlerSemantic variants.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftHandlerSemanticFlagsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_deobf_vmlift::{HandlerSemantic, PushSrc, PopDst, BinOpKind};
        let cases: Vec<(&str, HandlerSemantic)> = vec![
            ("Branch", HandlerSemantic::Branch),
            ("Call", HandlerSemantic::Call),
            ("Ret", HandlerSemantic::Ret),
            ("Halt", HandlerSemantic::Halt),
            ("Load4", HandlerSemantic::Load(4)),
            ("Store4", HandlerSemantic::Store(4)),
            ("PushMem", HandlerSemantic::Push(PushSrc::Memory)),
            ("PopMem", HandlerSemantic::Pop(PopDst::Memory)),
            ("Add", HandlerSemantic::BinOp(BinOpKind::Add)),
            ("Unknown", HandlerSemantic::Unknown),
        ];
        let results: Vec<_> = cases.iter().map(|(name, sem)| json!({
            "name": name,
            "is_control_flow": sem.is_control_flow(),
            "accesses_memory": sem.accesses_memory(),
            "mnemonic": sem.suggest_mnemonic(),
        })).collect();
        Ok(ToolResult::text(json!({
            "results": results,
            "source": "rustre_deobf_vmlift::HandlerSemantic",
        }).to_string()))
    }
}

pub struct VmliftIsaNewEmptyTool;
impl VmliftIsaNewEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_isa_new_empty".to_string(),
            description: "Construct an empty VmIsa and return len/is_empty.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftIsaNewEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let isa = rustre_deobf_vmlift::VmIsa::new();
        Ok(ToolResult::text(json!({
            "len": isa.len(),
            "is_empty": isa.is_empty(),
            "source": "rustre_deobf_vmlift::VmIsa::new",
        }).to_string()))
    }
}

pub struct VmliftIsaLookupOpcodeTool;
impl VmliftIsaLookupOpcodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_isa_lookup_opcode".to_string(),
            description: "Look up a handler definition by opcode in the default lifter ISA.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["opcode"],
                "properties": { "opcode": { "type": "integer" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftIsaLookupOpcodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let opcode = args.get("opcode").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcode'".into()))? as u8;
        let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa();
        match isa.lookup(opcode) {
            Some(def) => Ok(ToolResult::text(json!({
                "opcode": def.opcode,
                "mnemonic": def.mnemonic,
                "operand_bytes": def.operand_bytes,
                "found": true,
                "source": "rustre_deobf_vmlift::VmIsa::lookup",
            }).to_string())),
            None => Ok(ToolResult::text(json!({
                "opcode": opcode,
                "found": false,
                "source": "rustre_deobf_vmlift::VmIsa::lookup",
            }).to_string())),
        }
    }
}

pub struct VmliftRunPassTool;
impl VmliftRunPassTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vmlift_run_pass".to_string(),
            description: "Execute the VMLIFT deobfuscation pass smoke test.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VmliftRunPassTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        rustre_deobf_vmlift::run_pass();
        Ok(ToolResult::text(json!({
            "ok": true,
            "source": "rustre_deobf_vmlift::run_pass",
        }).to_string()))
    }
}

pub struct VmliftHandlerSemanticIsControlFlowTool;
impl VmliftHandlerSemanticIsControlFlowTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_handler_semantic_is_control_flow".to_string(), description: "Return HandlerSemantic::is_control_flow for the given semantic name.".to_string(), input_schema: json!({"type":"object","properties":{"semantic":{"type":"string"}},"required":["semantic"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftHandlerSemanticIsControlFlowTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = args.get("semantic").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'semantic'".into()))?; let sem = vmlift_parse_semantic_wl(s); Ok(ToolResult::text(json!({"is_control_flow": sem.is_control_flow(), "semantic": sem.to_string(), "source":"rustre_deobf_vmlift::HandlerSemantic::is_control_flow"}).to_string())) } }

pub struct VmliftHandlerSemanticAccessesMemoryTool;
impl VmliftHandlerSemanticAccessesMemoryTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_handler_semantic_accesses_memory".to_string(), description: "Return HandlerSemantic::accesses_memory for the given semantic name.".to_string(), input_schema: json!({"type":"object","properties":{"semantic":{"type":"string"}},"required":["semantic"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftHandlerSemanticAccessesMemoryTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = args.get("semantic").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'semantic'".into()))?; let sem = vmlift_parse_semantic_wl(s); Ok(ToolResult::text(json!({"accesses_memory": sem.accesses_memory(), "semantic": sem.to_string(), "source":"rustre_deobf_vmlift::HandlerSemantic::accesses_memory"}).to_string())) } }

pub struct VmliftHandlerSemanticSuggestMnemonicTool;
impl VmliftHandlerSemanticSuggestMnemonicTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_handler_semantic_suggest_mnemonic".to_string(), description: "Return HandlerSemantic::suggest_mnemonic for the given semantic name.".to_string(), input_schema: json!({"type":"object","properties":{"semantic":{"type":"string"}},"required":["semantic"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftHandlerSemanticSuggestMnemonicTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = args.get("semantic").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'semantic'".into()))?; let sem = vmlift_parse_semantic_wl(s); Ok(ToolResult::text(json!({"mnemonic": sem.suggest_mnemonic(), "free_fn": rustre_deobf_vmlift::suggest_mnemonic(&sem), "source":"rustre_deobf_vmlift::HandlerSemantic::suggest_mnemonic"}).to_string())) } }

pub struct VmliftBinopDisplayTool;
impl VmliftBinopDisplayTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_binop_display".to_string(), description: "Display strings for all BinOpKind variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftBinopDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_deobf_vmlift::BinOpKind; let all = [BinOpKind::Add,BinOpKind::Sub,BinOpKind::Mul,BinOpKind::Div,BinOpKind::And,BinOpKind::Or,BinOpKind::Xor,BinOpKind::Shl,BinOpKind::Shr,BinOpKind::Sar,BinOpKind::Rol,BinOpKind::Ror]; let v: Vec<String> = all.iter().map(|k| k.to_string()).collect(); Ok(ToolResult::text(json!({"count": v.len(), "variants": v, "source":"rustre_deobf_vmlift::BinOpKind::fmt"}).to_string())) } }

pub struct VmliftGuestInstructionDisplayTool;
impl VmliftGuestInstructionDisplayTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_guest_instruction_display".to_string(), description: "Lift bytecode and return display strings of GuestInstructions.".to_string(), input_schema: json!({"type":"object","properties":{"bytecode_hex":{"type":"string"}},"required":["bytecode_hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftGuestInstructionDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let h = args.get("bytecode_hex").and_then(Value::as_str).unwrap_or(""); let data = vmlift_hex_to_bytes_wl(h)?; let instrs = rustre_deobf_vmlift::VmLifter::lift_to_instructions(&data).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; let displays: Vec<String> = instrs.iter().map(|i| i.to_string()).collect(); Ok(ToolResult::text(json!({"count": displays.len(), "displays": displays, "source":"rustre_deobf_vmlift::GuestInstruction::fmt"}).to_string())) } }

pub struct VmliftRawDispatcherKindDisplayTool;
impl VmliftRawDispatcherKindDisplayTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_raw_dispatcher_kind_display".to_string(), description: "Return display strings for all RawDispatcherKind variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftRawDispatcherKindDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_deobf_vmlift::RawDispatcherKind; let all = [RawDispatcherKind::IndirectIndexedJmp, RawDispatcherKind::ComputedJmp, RawDispatcherKind::CallPopAddChain]; let v: Vec<String> = all.iter().map(|k| k.to_string()).collect(); Ok(ToolResult::text(json!({"count": v.len(), "variants": v, "source":"rustre_deobf_vmlift::RawDispatcherKind::fmt"}).to_string())) } }

pub struct VmliftLiftInstructionCountTool;
impl VmliftLiftInstructionCountTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_lift_instruction_count".to_string(), description: "Lift bytecode via VmLifter and return only the instruction count.".to_string(), input_schema: json!({"type":"object","properties":{"bytecode_hex":{"type":"string"}},"required":["bytecode_hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftLiftInstructionCountTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let h = args.get("bytecode_hex").and_then(Value::as_str).unwrap_or(""); let data = vmlift_hex_to_bytes_wl(h)?; let instrs = rustre_deobf_vmlift::VmLifter::lift_to_instructions(&data).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"count": instrs.len(), "byte_len": data.len(), "source":"rustre_deobf_vmlift::VmLifter::lift_to_instructions"}).to_string())) } }

pub struct VmliftIsaSortedOpcodesTool;
impl VmliftIsaSortedOpcodesTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_isa_sorted_opcodes".to_string(), description: "Return sorted opcodes of the default lifter ISA via VmIsa::sorted_handlers.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftIsaSortedOpcodesTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa(); let ops: Vec<u8> = isa.sorted_handlers().iter().map(|d| d.opcode).collect(); Ok(ToolResult::text(json!({"count": ops.len(), "opcodes": ops, "source":"rustre_deobf_vmlift::VmIsa::sorted_handlers"}).to_string())) } }

pub struct VmliftIsaRegisterAndLookupTool;
impl VmliftIsaRegisterAndLookupTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_isa_register_and_lookup".to_string(), description: "Register a Halt instruction into an empty ISA and look it up.".to_string(), input_schema: json!({"type":"object","properties":{"opcode":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftIsaRegisterAndLookupTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let op = u8::try_from(args.get("opcode").and_then(Value::as_u64).unwrap_or(0xAA)).unwrap_or(0xAA); let mut isa = rustre_deobf_vmlift::VmIsa::new(); let def = rustre_deobf_vmlift::VmInstructionDef::new(op, rustre_deobf_vmlift::HandlerSemantic::Halt); isa.register(def); let looked = isa.lookup(op).map(|d| d.mnemonic.clone()); Ok(ToolResult::text(json!({"len": isa.len(), "mnemonic": looked, "source":"rustre_deobf_vmlift::VmIsa::register"}).to_string())) } }

pub struct VmliftDisassembleToTextDefaultTool;
impl VmliftDisassembleToTextDefaultTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_disassemble_to_text_default".to_string(), description: "Disassemble bytecode with default ISA and return VmBytecodeDisassembler::to_text output.".to_string(), input_schema: json!({"type":"object","properties":{"bytecode_hex":{"type":"string"}},"required":["bytecode_hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftDisassembleToTextDefaultTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let h = args.get("bytecode_hex").and_then(Value::as_str).unwrap_or(""); let data = vmlift_hex_to_bytes_wl(h)?; let isa = rustre_deobf_vmlift::VmIsa::default_lifter_isa(); let instrs = rustre_deobf_vmlift::VmBytecodeDisassembler::disassemble(&data, &isa).map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?; let text = rustre_deobf_vmlift::VmBytecodeDisassembler::to_text(&instrs); Ok(ToolResult::text(json!({"count": instrs.len(), "text": text, "source":"rustre_deobf_vmlift::VmBytecodeDisassembler::to_text"}).to_string())) } }

pub struct VmliftInstructionDefOperandBytesTool;
impl VmliftInstructionDefOperandBytesTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_instruction_def_operand_bytes".to_string(), description: "Build VmInstructionDef via ::new and return derived operand_bytes.".to_string(), input_schema: json!({"type":"object","properties":{"opcode":{"type":"integer"},"semantic":{"type":"string"}},"required":["semantic"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftInstructionDefOperandBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let op = u8::try_from(args.get("opcode").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0); let s = args.get("semantic").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'semantic'".into()))?; let sem = vmlift_parse_semantic_wl(s); let def = rustre_deobf_vmlift::VmInstructionDef::new(op, sem); Ok(ToolResult::text(json!({"opcode": def.opcode, "mnemonic": def.mnemonic, "operand_bytes": def.operand_bytes, "display": def.to_string(), "source":"rustre_deobf_vmlift::VmInstructionDef::new"}).to_string())) } }

pub struct VmliftIsaLenIsEmptyTool;
impl VmliftIsaLenIsEmptyTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "vmlift_isa_len_is_empty".to_string(), description: "Return len/is_empty for both a fresh empty VmIsa and the default lifter ISA.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for VmliftIsaLenIsEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let e = rustre_deobf_vmlift::VmIsa::new(); let d = rustre_deobf_vmlift::VmIsa::default_lifter_isa(); Ok(ToolResult::text(json!({"empty_len": e.len(), "empty_is_empty": e.is_empty(), "default_len": d.len(), "default_is_empty": d.is_empty(), "source":"rustre_deobf_vmlift::VmIsa::len"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (VmliftDefaultIsaLenTool::definition(), Box::new(VmliftDefaultIsaLenTool)),
        (VmliftDefaultIsaListingTool::definition(), Box::new(VmliftDefaultIsaListingTool)),
        (VmliftLiftToPseudoIlTool::definition(), Box::new(VmliftLiftToPseudoIlTool)),
        (VmliftDetectDispatchersInBytesTool::definition(), Box::new(VmliftDetectDispatchersInBytesTool)),
        (VmliftExtractJumpTableEntriesTool::definition(), Box::new(VmliftExtractJumpTableEntriesTool)),
        (VmliftDetectAndReportTool::definition(), Box::new(VmliftDetectAndReportTool)),
        (VmliftFullPipelineTool::definition(), Box::new(VmliftFullPipelineTool)),
        (VmliftDisassembleDefaultTool::definition(), Box::new(VmliftDisassembleDefaultTool)),
        (VmliftDefaultIsaOpcodesTool::definition(), Box::new(VmliftDefaultIsaOpcodesTool)),
        (VmliftSuggestMnemonicHaltTool::definition(), Box::new(VmliftSuggestMnemonicHaltTool)),
        (VmliftHandlerSemanticFlagsTool::definition(), Box::new(VmliftHandlerSemanticFlagsTool)),
        (VmliftIsaNewEmptyTool::definition(), Box::new(VmliftIsaNewEmptyTool)),
        (VmliftIsaLookupOpcodeTool::definition(), Box::new(VmliftIsaLookupOpcodeTool)),
        (VmliftRunPassTool::definition(), Box::new(VmliftRunPassTool)),
        (VmliftHandlerSemanticIsControlFlowTool::definition(), Box::new(VmliftHandlerSemanticIsControlFlowTool)),
        (VmliftHandlerSemanticAccessesMemoryTool::definition(), Box::new(VmliftHandlerSemanticAccessesMemoryTool)),
        (VmliftHandlerSemanticSuggestMnemonicTool::definition(), Box::new(VmliftHandlerSemanticSuggestMnemonicTool)),
        (VmliftBinopDisplayTool::definition(), Box::new(VmliftBinopDisplayTool)),
        (VmliftGuestInstructionDisplayTool::definition(), Box::new(VmliftGuestInstructionDisplayTool)),
        (VmliftRawDispatcherKindDisplayTool::definition(), Box::new(VmliftRawDispatcherKindDisplayTool)),
        (VmliftLiftInstructionCountTool::definition(), Box::new(VmliftLiftInstructionCountTool)),
        (VmliftIsaSortedOpcodesTool::definition(), Box::new(VmliftIsaSortedOpcodesTool)),
        (VmliftIsaRegisterAndLookupTool::definition(), Box::new(VmliftIsaRegisterAndLookupTool)),
        (VmliftDisassembleToTextDefaultTool::definition(), Box::new(VmliftDisassembleToTextDefaultTool)),
        (VmliftInstructionDefOperandBytesTool::definition(), Box::new(VmliftInstructionDefOperandBytesTool)),
        (VmliftIsaLenIsEmptyTool::definition(), Box::new(VmliftIsaLenIsEmptyTool)),
    ]
}
