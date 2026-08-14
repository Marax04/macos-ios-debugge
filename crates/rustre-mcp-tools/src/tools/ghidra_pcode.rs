//! MCP wrappers for the rustre-ghidra_pcode crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct GhidraPcodeTranslatorRetTool;
impl GhidraPcodeTranslatorRetTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_pcode_translate_ret".to_string(),
            description: "Translate an x86 `ret` instruction to P-Code via rustre_decompiler_ghidra::PCodeTranslator.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraPcodeTranslatorRetTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::{address::Address, arch::Instruction};
        let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string());
        let mut i = Instruction::new(Address::new(0x1000), 1, "ret", vec![0xc3]);
        i.operands = String::new();
        let ops = t.translate(&i);
        Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"arch":t.arch(),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string()))
    }
}

pub struct GhidraPcodeLifterPseudoCTool;
impl GhidraPcodeLifterPseudoCTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_pcode_lifter_pseudo_c".to_string(),
            description: "Lift a small x86 sequence to pseudo-C via rustre_decompiler_ghidra::PCodeLifter.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraPcodeLifterPseudoCTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::{address::Address, arch::Instruction};
        let name = args.get("name").and_then(Value::as_str).unwrap_or("f");
        let lifter = rustre_decompiler_ghidra::PCodeLifter::new("x86_64".to_string());
        let mk = |a: u64, m: &str, o: &str| { let mut i = Instruction::new(Address::new(a), 4, m, vec![0x90]); i.operands = o.to_string(); i };
        let instrs = vec![mk(0x1000,"mov","rax, rdi"), mk(0x1003,"add","rax, 0x1"), mk(0x1006,"ret","")];
        let f = lifter.lift_to_pseudo_c(0x1000, &instrs, name);
        Ok(ToolResult::text(json!({"name":f.name,"addr":f.address,"confidence":f.confidence,"vars":f.variables.len(),"calls":f.call_sites.len(),"source":"rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c"}).to_string()))
    }
}

pub struct GhidraPcodeVarnodeClassifyBatchTool;
impl GhidraPcodeVarnodeClassifyBatchTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_varnode_classify_batch".to_string(), description: "Varnode classify batch.".to_string(), input_schema: json!({"type":"object","properties":{"spaces":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraPcodeVarnodeClassifyBatchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let spaces: Vec<String> = args.get("spaces").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["const".into(),"register".into(),"ram".into(),"unique".into()]);
        let mut c=0u32; let mut r=0u32; let mut u=0u32; let mut m=0u32;
        for sp in &spaces { let vn = rustre_decompiler_ghidra::Varnode { space: sp.clone(), offset: 0, size: 8 }; if vn.is_const() {c+=1;} if vn.is_register() {r+=1;} if vn.is_unique() {u+=1;} if vn.is_ram() {m+=1;} }
        Ok(ToolResult::text(json!({"n":spaces.len(),"const":c,"register":r,"unique":u,"ram":m,"source":"rustre_decompiler_ghidra::Varnode"}).to_string()))
    }
}

pub struct GhidraPcodeLifterVariablesTool;
impl GhidraPcodeLifterVariablesTool { pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_lifter_variables".to_string(), description: "PCodeLifter lift synthetic mov/ret, count vars.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for GhidraPcodeLifterVariablesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_core::{address::Address, arch::Instruction};
        let name = args.get("name").and_then(Value::as_str).unwrap_or("stub");
        let lifter = rustre_decompiler_ghidra::PCodeLifter::new("x86_64".to_string());
        let mut mov = Instruction::new(Address::new(0x1000), 5, "mov", vec![0xb8, 1, 0, 0, 0]);
        mov.operands = "eax, 1".to_string();
        let mut ret = Instruction::new(Address::new(0x1005), 1, "ret", vec![0xc3]);
        ret.operands = String::new();
        let insns = vec![mov, ret];
        let df = lifter.lift_to_pseudo_c(0x1000, &insns, name);
        Ok(ToolResult::text(json!({"name":df.name,"addr":df.address,"confidence":df.confidence,"vars":df.variables.len(),"calls":df.call_sites.len(),"pc_lines":df.pseudo_code.lines().count(),"source":"rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c"}).to_string()))
    }
}

pub struct GhidraPcodeTranslateNopWire3Tool;
impl GhidraPcodeTranslateNopWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_nop_wire3".to_string(), description: "Translate x86 nop via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraPcodeTranslateNopWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_core::{address::Address, arch::Instruction}; let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 1, "nop", vec![0x90]); i.operands = String::new(); let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"arch":t.arch(),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslatePushWire3Tool;
impl GhidraPcodeTranslatePushWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_push_wire3".to_string(), description: "Translate x86 push rbp via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraPcodeTranslatePushWire3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_core::{address::Address, arch::Instruction}; let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 1, "push", vec![0x55]); i.operands = "rbp".to_string(); let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"op1":ops.get(1).map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateMovWire3Tool;
impl GhidraPcodeTranslateMovWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_mov_wire3".to_string(), description: "Translate x86 mov via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraPcodeTranslateMovWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, rbx").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "mov", vec![0x48,0x89,0xd8]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeLifterEmptyWire3Tool;
impl GhidraPcodeLifterEmptyWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_lifter_empty_wire3".to_string(), description: "Lift empty slice via rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for GhidraPcodeLifterEmptyWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("name").and_then(Value::as_str).unwrap_or("f").to_string(); let l = rustre_decompiler_ghidra::PCodeLifter::new("x86_64".to_string()); let f = l.lift_to_pseudo_c(0x2000, &[], &n); Ok(ToolResult::text(json!({"address":f.address,"name":f.name,"confidence":f.confidence,"has_no_ops":f.pseudo_code.contains("no operations"),"source":"rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c"}).to_string())) } }

pub struct GhidraPcodeTranslateAddGwx4Tool;
impl GhidraPcodeTranslateAddGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_add_gwx4".to_string(), description: "Translate x86 add via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateAddGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, rbx").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "add", vec![0x48,0x01,0xd8]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateSubGwx4Tool;
impl GhidraPcodeTranslateSubGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_sub_gwx4".to_string(), description: "Translate x86 sub via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateSubGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, 0x10").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "sub", vec![0x48,0x29,0xd8]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateXorGwx4Tool;
impl GhidraPcodeTranslateXorGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_xor_gwx4".to_string(), description: "Translate x86 xor via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateXorGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, rax").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "xor", vec![0x48,0x31,0xc0]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateAndGwx4Tool;
impl GhidraPcodeTranslateAndGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_and_gwx4".to_string(), description: "Translate x86 and via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateAndGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, rbx").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "and", vec![0x48,0x21,0xd8]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateOrGwx4Tool;
impl GhidraPcodeTranslateOrGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_or_gwx4".to_string(), description: "Translate x86 or via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateOrGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rax, rbx").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 3, "or", vec![0x48,0x09,0xd8]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslatePopGwx4Tool;
impl GhidraPcodeTranslatePopGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_pop_gwx4".to_string(), description: "Translate x86 pop via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslatePopGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let ops_s = args.get("operands").and_then(Value::as_str).unwrap_or("rbp").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 1, "pop", vec![0x5d]); i.operands = ops_s; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"op1":ops.get(1).map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateJmpGwx4Tool;
impl GhidraPcodeTranslateJmpGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_jmp_gwx4".to_string(), description: "Translate x86 jmp via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"target":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateJmpGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let tgt = args.get("target").and_then(Value::as_str).unwrap_or("0x2000").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 2, "jmp", vec![0xeb,0x00]); i.operands = tgt; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateJzGwx4Tool;
impl GhidraPcodeTranslateJzGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_jz_gwx4".to_string(), description: "Translate x86 jz (conditional branch) via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"target":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateJzGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let tgt = args.get("target").and_then(Value::as_str).unwrap_or("0x2000").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let mut i = Instruction::new(Address::new(0x1000), 2, "jz", vec![0x74,0x00]); i.operands = tgt; let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeTranslateUnknownGwx4Tool;
impl GhidraPcodeTranslateUnknownGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_translate_unknown_gwx4".to_string(), description: "Translate an unknown mnemonic (fallback Copy) via rustre_decompiler_ghidra::PCodeTranslator::translate.".to_string(), input_schema: json!({"type":"object","properties":{"mnemonic":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeTranslateUnknownGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let mnem = args.get("mnemonic").and_then(Value::as_str).unwrap_or("cpuid").to_string(); let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string()); let i = Instruction::new(Address::new(0x1000), 2, &mnem, vec![0x0f,0xa2]); let ops = t.translate(&i); Ok(ToolResult::text(json!({"ops":ops.len(),"op0":ops.first().map(|o| o.op.to_string()),"fallback":!ops.is_empty(),"source":"rustre_decompiler_ghidra::PCodeTranslator::translate"}).to_string())) } }

pub struct GhidraPcodeLifterTwoInstsGwx4Tool;
impl GhidraPcodeLifterTwoInstsGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_lifter_two_insts_gwx4".to_string(), description: "Lift push+ret via rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeLifterTwoInstsGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::{address::Address, arch::Instruction}; let n = args.get("name").and_then(Value::as_str).unwrap_or("f2").to_string(); let l = rustre_decompiler_ghidra::PCodeLifter::new("x86_64".to_string()); let mut i0 = Instruction::new(Address::new(0x3000), 1, "push", vec![0x55]); i0.operands = "rbp".to_string(); let i1 = Instruction::new(Address::new(0x3001), 1, "ret", vec![0xc3]); let f = l.lift_to_pseudo_c(0x3000, &[i0, i1], &n); Ok(ToolResult::text(json!({"address":f.address,"name":f.name,"confidence":f.confidence,"vars":f.variables.len(),"calls":f.call_sites.len(),"lines":f.pseudo_code.lines().count(),"source":"rustre_decompiler_ghidra::PCodeLifter::lift_to_pseudo_c"}).to_string())) } }

pub struct GhidraPcodeOpDisplayGwx4Tool;
impl GhidraPcodeOpDisplayGwx4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ghidra_pcode_op_display_gwx4".to_string(), description: "Format a PcodeOp via rustre_decompiler_ghidra::PcodeOp Display impl.".to_string(), input_schema: json!({"type":"object","properties":{"mnemonic":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for GhidraPcodeOpDisplayGwx4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mnem = args.get("mnemonic").and_then(Value::as_str).unwrap_or("INT_ADD").to_string(); let out = rustre_decompiler_ghidra::Varnode { space: "register".to_string(), offset: 0, size: 8 }; let a = rustre_decompiler_ghidra::Varnode { space: "register".to_string(), offset: 8, size: 8 }; let b = rustre_decompiler_ghidra::Varnode { space: "const".to_string(), offset: 1, size: 8 }; let op = rustre_decompiler_ghidra::PcodeOp { mnemonic: mnem, output: Some(out), inputs: vec![a, b] }; Ok(ToolResult::text(json!({"display":op.to_string(),"inputs":op.inputs.len(),"has_output":op.output.is_some(),"source":"rustre_decompiler_ghidra::PcodeOp"}).to_string())) } }

pub struct GhidraPcodeParserParseJsonTool;
impl GhidraPcodeParserParseJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_pcode_parser_parse_json".to_string(),
            description: "Parse a Ghidra P-code JSON dump via rustre_decompiler_ghidra::PcodeParser::parse_pcode_json and return op mnemonics.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "json": { "type": "string" } },
                "required": ["json"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraPcodeParserParseJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("json").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'json'".to_string()))?;
        let ops = rustre_decompiler_ghidra::PcodeParser::parse_pcode_json(s)
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        let mnemonics: Vec<String> = ops.iter().map(|o| o.mnemonic.clone()).collect();
        Ok(ToolResult::text(json!({
            "op_count": ops.len(),
            "mnemonics": mnemonics,
            "source": "rustre_decompiler_ghidra::PcodeParser::parse_pcode_json",
        }).to_string()))
    }
}

pub struct GhidraPcodeTranslatorArchTool;
impl GhidraPcodeTranslatorArchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_pcode_translator_arch".to_string(),
            description: "Return the arch string from rustre_decompiler_ghidra::PCodeTranslator::arch.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "arch": { "type": "string" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraPcodeTranslatorArchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64").to_string();
        let t = rustre_decompiler_ghidra::PCodeTranslator::new(arch);
        Ok(ToolResult::text(json!({
            "arch": t.arch(),
            "source": "rustre_decompiler_ghidra::PCodeTranslator::arch",
        }).to_string()))
    }
}

pub struct GhidraPcodeTranslateCallTool;
impl GhidraPcodeTranslateCallTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ghidra_pcode_translate_call".to_string(),
            description: "Translate a synthetic x86 CALL to P-Code via rustre_decompiler_ghidra::PCodeTranslator.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GhidraPcodeTranslateCallTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("target").and_then(Value::as_str).unwrap_or("0x4000");
        let t = rustre_decompiler_ghidra::PCodeTranslator::new("x86_64".to_string());
        let mut instr = rustre_core::arch::Instruction::new(
            rustre_core::address::Address::new(0x1000), 5, "call", vec![0xe8, 0, 0, 0, 0],
        );
        instr.operands = target.to_string();
        let ops = t.translate(&instr);
        let rendered: Vec<String> = ops.iter().map(|o| o.to_string()).collect();
        Ok(ToolResult::text(json!({
            "arch":t.arch(),"n":ops.len(),"ops":rendered,
            "source":"rustre_decompiler_ghidra::PCodeTranslator::translate"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (GhidraPcodeTranslatorRetTool::definition(), Box::new(GhidraPcodeTranslatorRetTool)),
        (GhidraPcodeLifterPseudoCTool::definition(), Box::new(GhidraPcodeLifterPseudoCTool)),
        (GhidraPcodeVarnodeClassifyBatchTool::definition(), Box::new(GhidraPcodeVarnodeClassifyBatchTool)),
        (GhidraPcodeLifterVariablesTool::definition(), Box::new(GhidraPcodeLifterVariablesTool)),
        (GhidraPcodeTranslateNopWire3Tool::definition(), Box::new(GhidraPcodeTranslateNopWire3Tool)),
        (GhidraPcodeTranslatePushWire3Tool::definition(), Box::new(GhidraPcodeTranslatePushWire3Tool)),
        (GhidraPcodeTranslateMovWire3Tool::definition(), Box::new(GhidraPcodeTranslateMovWire3Tool)),
        (GhidraPcodeLifterEmptyWire3Tool::definition(), Box::new(GhidraPcodeLifterEmptyWire3Tool)),
        (GhidraPcodeTranslateAddGwx4Tool::definition(), Box::new(GhidraPcodeTranslateAddGwx4Tool)),
        (GhidraPcodeTranslateSubGwx4Tool::definition(), Box::new(GhidraPcodeTranslateSubGwx4Tool)),
        (GhidraPcodeTranslateXorGwx4Tool::definition(), Box::new(GhidraPcodeTranslateXorGwx4Tool)),
        (GhidraPcodeTranslateAndGwx4Tool::definition(), Box::new(GhidraPcodeTranslateAndGwx4Tool)),
        (GhidraPcodeTranslateOrGwx4Tool::definition(), Box::new(GhidraPcodeTranslateOrGwx4Tool)),
        (GhidraPcodeTranslatePopGwx4Tool::definition(), Box::new(GhidraPcodeTranslatePopGwx4Tool)),
        (GhidraPcodeTranslateJmpGwx4Tool::definition(), Box::new(GhidraPcodeTranslateJmpGwx4Tool)),
        (GhidraPcodeTranslateJzGwx4Tool::definition(), Box::new(GhidraPcodeTranslateJzGwx4Tool)),
        (GhidraPcodeTranslateUnknownGwx4Tool::definition(), Box::new(GhidraPcodeTranslateUnknownGwx4Tool)),
        (GhidraPcodeLifterTwoInstsGwx4Tool::definition(), Box::new(GhidraPcodeLifterTwoInstsGwx4Tool)),
        (GhidraPcodeOpDisplayGwx4Tool::definition(), Box::new(GhidraPcodeOpDisplayGwx4Tool)),
        (GhidraPcodeParserParseJsonTool::definition(), Box::new(GhidraPcodeParserParseJsonTool)),
        (GhidraPcodeTranslatorArchTool::definition(), Box::new(GhidraPcodeTranslatorArchTool)),
        (GhidraPcodeTranslateCallTool::definition(), Box::new(GhidraPcodeTranslateCallTool)),
    ]
}
