//! MCP wrappers for the rustre-mobile_smali crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct MobileSmaliParseTypeDescriptorTool;

pub struct MobileSmaliParseMethodDescriptorTool;

pub struct MobileSmaliInstrSizeTool;
impl MobileSmaliInstrSizeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_instruction_size_bytes".to_string(), description: "rustre_mobile_smali::instruction_size_bytes for a Dalvik opcode byte".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer","minimum":0,"maximum":255}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliInstrSizeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))?; let byte = u8::try_from(b).map_err(|_| McpError::InvalidParams("byte>255".into()))?; let op = rustre_mobile_smali::DalvikOpcode::from_byte(byte); let sz = rustre_mobile_smali::instruction_size_bytes(op); Ok(ToolResult::text(json!({"byte":byte,"size_bytes":sz,"source":"rustre_mobile_smali::instruction_size_bytes"}).to_string())) } }

pub struct MobileSmaliOpcodeAsByteTool;
impl MobileSmaliOpcodeAsByteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_opcode_as_byte".to_string(), description: "Roundtrip Dalvik opcode byte via from_byte/as_byte".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer","minimum":0,"maximum":255}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliOpcodeAsByteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))?; let byte = u8::try_from(b).map_err(|_| McpError::InvalidParams("byte>255".into()))?; let op = rustre_mobile_smali::DalvikOpcode::from_byte(byte); let round = op.as_byte(); Ok(ToolResult::text(json!({"in":byte,"out":round,"roundtrip":byte==round,"source":"rustre_mobile_smali::DalvikOpcode::as_byte"}).to_string())) } }

pub struct MobileSmaliClassMockTool;
impl MobileSmaliClassMockTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_class_mock".to_string(), description: "rustre_mobile_smali::SmaliClass::mock and report structure".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliClassMockTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let c = rustre_mobile_smali::SmaliClass::mock(name); Ok(ToolResult::text(json!({"name":c.name,"super":c.super_class,"methods":c.methods.len(),"fields":c.fields.len(),"source":"rustre_mobile_smali::SmaliClass::mock"}).to_string())) } }

pub struct MobileSmaliClassFindMethodTool;
impl MobileSmaliClassFindMethodTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_class_find_method".to_string(), description: "SmaliClass::find_method on a mock class".to_string(), input_schema: json!({"type":"object","properties":{"class":{"type":"string"},"method":{"type":"string"}},"required":["class","method"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliClassFindMethodTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cls = args.get("class").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'class'".into()))?.to_string(); let m = args.get("method").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'method'".into()))?.to_string(); let c = rustre_mobile_smali::SmaliClass::mock(cls); let found = c.find_method(&m); Ok(ToolResult::text(json!({"method":m,"found":found.is_some(),"instr_count":found.map(rustre_mobile_smali::SmaliMethod::instr_count).unwrap_or(0),"source":"rustre_mobile_smali::SmaliClass::find_method"}).to_string())) } }

pub struct MobileSmaliClassStaticMethodsTool;
impl MobileSmaliClassStaticMethodsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_class_static_methods".to_string(), description: "SmaliClass::static_methods on a mock class".to_string(), input_schema: json!({"type":"object","properties":{"class":{"type":"string"}},"required":["class"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliClassStaticMethodsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cls = args.get("class").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'class'".into()))?.to_string(); let c = rustre_mobile_smali::SmaliClass::mock(cls); let names: Vec<String> = c.static_methods().iter().map(|m| m.name.clone()).collect(); Ok(ToolResult::text(json!({"count":names.len(),"names":names,"source":"rustre_mobile_smali::SmaliClass::static_methods"}).to_string())) } }

pub struct MobileSmaliMethodIsConstructorTool;
impl MobileSmaliMethodIsConstructorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_method_is_constructor".to_string(), description: "SmaliMethod::is_constructor on a synthesized method".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliMethodIsConstructorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let m = rustre_mobile_smali::SmaliMethod { name: n.clone(), class: "LFoo;".to_string(), signature: "()V".to_string(), access: rustre_mobile_smali::SmaliAccess::PUBLIC, registers: 0, instructions: vec![] }; Ok(ToolResult::text(json!({"name":n,"is_constructor":m.is_constructor(),"source":"rustre_mobile_smali::SmaliMethod::is_constructor"}).to_string())) } }

pub struct MobileSmaliInstrToTextTool;
impl MobileSmaliInstrToTextTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_instr_to_text".to_string(), description: "SmaliInstr::to_text for a return-void instruction".to_string(), input_schema: json!({"type":"object","properties":{"label":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliInstrToTextTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lbl = args.get("label").and_then(Value::as_str).map(String::from); let i = rustre_mobile_smali::SmaliInstr { op: rustre_mobile_smali::SmaliOp::ReturnVoid, operands: vec![], label: lbl }; Ok(ToolResult::text(json!({"text":i.to_text(),"source":"rustre_mobile_smali::SmaliInstr::to_text"}).to_string())) } }

pub struct MobileSmaliOpDisplayTool;
impl MobileSmaliOpDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_op_display".to_string(), description: "Format a Dalvik opcode byte through the SmaliOp Display impl".to_string(), input_schema: json!({"type":"object","properties":{"byte":{"type":"integer","minimum":0,"maximum":255}},"required":["byte"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliOpDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))?; let byte = u8::try_from(b).map_err(|_| McpError::InvalidParams("byte>255".into()))?; let mnem = rustre_mobile_smali::opcode_to_smali(rustre_mobile_smali::DalvikOpcode::from_byte(byte)); let op = rustre_mobile_smali::SmaliOp::Other(mnem.to_string()); Ok(ToolResult::text(json!({"display":op.to_string(),"source":"rustre_mobile_smali::SmaliOp::Display"}).to_string())) } }

pub struct MobileSmaliOperandLiteralTool;
impl MobileSmaliOperandLiteralTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_operand_literal_display".to_string(), description: "SmaliOperand::Literal Display formatting (hex with sign)".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliOperandLiteralTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("value").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let o = rustre_mobile_smali::SmaliOperand::Literal(v); Ok(ToolResult::text(json!({"display":o.to_string(),"source":"rustre_mobile_smali::SmaliOperand::Display"}).to_string())) } }

pub struct MobileSmaliParseTypeDescWireTool;
impl MobileSmaliParseTypeDescWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_parse_type_descriptor_wire".to_string(), description: "rustre_mobile_smali::parse_type_descriptor to Java form".to_string(), input_schema: json!({"type":"object","properties":{"desc":{"type":"string"}},"required":["desc"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliParseTypeDescWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let d = args.get("desc").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'desc'".into()))?.to_string(); let out = rustre_mobile_smali::parse_type_descriptor(&d); Ok(ToolResult::text(json!({"input":d,"java_type":out,"source":"rustre_mobile_smali::parse_type_descriptor"}).to_string())) } }

pub struct MobileSmaliParseMethodDescWireTool;
impl MobileSmaliParseMethodDescWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_smali_parse_method_descriptor_wire".to_string(), description: "rustre_mobile_smali::parse_method_descriptor to (params, return)".to_string(), input_schema: json!({"type":"object","properties":{"desc":{"type":"string"}},"required":["desc"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileSmaliParseMethodDescWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let d = args.get("desc").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'desc'".into()))?.to_string(); let (params, ret) = rustre_mobile_smali::parse_method_descriptor(&d); Ok(ToolResult::text(json!({"input":d,"params":params,"return":ret,"source":"rustre_mobile_smali::parse_method_descriptor"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileSmaliParseTypeDescriptorTool::definition(), Box::new(MobileSmaliParseTypeDescriptorTool)),
        (MobileSmaliParseMethodDescriptorTool::definition(), Box::new(MobileSmaliParseMethodDescriptorTool)),
        (MobileSmaliInstrSizeTool::definition(), Box::new(MobileSmaliInstrSizeTool)),
        (MobileSmaliOpcodeAsByteTool::definition(), Box::new(MobileSmaliOpcodeAsByteTool)),
        (MobileSmaliClassMockTool::definition(), Box::new(MobileSmaliClassMockTool)),
        (MobileSmaliClassFindMethodTool::definition(), Box::new(MobileSmaliClassFindMethodTool)),
        (MobileSmaliClassStaticMethodsTool::definition(), Box::new(MobileSmaliClassStaticMethodsTool)),
        (MobileSmaliMethodIsConstructorTool::definition(), Box::new(MobileSmaliMethodIsConstructorTool)),
        (MobileSmaliInstrToTextTool::definition(), Box::new(MobileSmaliInstrToTextTool)),
        (MobileSmaliOpDisplayTool::definition(), Box::new(MobileSmaliOpDisplayTool)),
        (MobileSmaliOperandLiteralTool::definition(), Box::new(MobileSmaliOperandLiteralTool)),
        (MobileSmaliParseTypeDescWireTool::definition(), Box::new(MobileSmaliParseTypeDescWireTool)),
        (MobileSmaliParseMethodDescWireTool::definition(), Box::new(MobileSmaliParseMethodDescWireTool)),
    ]
}
