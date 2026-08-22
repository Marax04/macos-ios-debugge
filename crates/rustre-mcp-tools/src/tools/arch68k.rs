//! MCP wrappers for the rustre-arch68k crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{arch68k_parse_variant};

pub struct Arch68kSizeBytesTool;

pub struct Arch68kCondCodeMnemonicTool;

pub struct Arch68kSizeSuffixTool;
impl Arch68kSizeSuffixTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_size_suffix".to_string(), description: "Return 68k operand size assembly suffix.".to_string(), input_schema: json!({"type":"object","required":["size"],"properties":{"size":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kSizeSuffixTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("size").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?; let sz = match s { "B"|"b" => rustre_arch_68k::Size::Byte, "W"|"w" => rustre_arch_68k::Size::Word, "L"|"l" => rustre_arch_68k::Size::Long, "Q"|"q" => rustre_arch_68k::Size::Quad, o => return Err(McpError::InvalidParams(format!("unknown size '{o}'"))) }; Ok(ToolResult::text(json!({"size":s,"suffix":sz.suffix(),"source":"rustre_arch_68k::Size::suffix"}).to_string())) } }

pub struct Arch68kSizeFromBits2Tool;
impl Arch68kSizeFromBits2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_size_from_bits2".to_string(), description: "Decode a 2-bit 68k size encoding.".to_string(), input_schema: json!({"type":"object","required":["bits"],"properties":{"bits":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kSizeFromBits2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))?; let sz = rustre_arch_68k::Size::from_bits2(b as u8); Ok(ToolResult::text(json!({"bits":b & 3,"suffix":sz.suffix(),"bytes":sz.bytes(),"source":"rustre_arch_68k::Size::from_bits2"}).to_string())) } }

pub struct Arch68kCondCodeFromBitsTool;
impl Arch68kCondCodeFromBitsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_condcode_from_bits".to_string(), description: "Decode a 4-bit 68k condition code.".to_string(), input_schema: json!({"type":"object","required":["bits"],"properties":{"bits":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kCondCodeFromBitsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))?; let cc = rustre_arch_68k::CondCode::from_bits(b as u8); Ok(ToolResult::text(json!({"bits":b & 0xF,"mnemonic":cc.mnemonic(),"is_unconditional":cc.is_unconditional(),"source":"rustre_arch_68k::CondCode::from_bits"}).to_string())) } }

pub struct Arch68kVariantNameTool;
impl Arch68kVariantNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_name".to_string(), description: "Return display name of a 68k CPU variant.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"input":v,"name":variant.name(),"source":"rustre_arch_68k::Mc68kVariant::name"}).to_string())) } }

pub struct Arch68kVariantHasFpuTool;
impl Arch68kVariantHasFpuTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_has_fpu".to_string(), description: "Whether the 68k variant has an on-chip FPU.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantHasFpuTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"variant":variant.name(),"has_fpu":variant.has_fpu(),"source":"rustre_arch_68k::Mc68kVariant::has_fpu"}).to_string())) } }

pub struct Arch68kVariantHasMmuTool;
impl Arch68kVariantHasMmuTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_has_mmu".to_string(), description: "Whether the 68k variant has an on-chip MMU.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantHasMmuTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"variant":variant.name(),"has_mmu":variant.has_mmu(),"source":"rustre_arch_68k::Mc68kVariant::has_mmu"}).to_string())) } }

pub struct Arch68kVariantIs32BitTool;
impl Arch68kVariantIs32BitTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_is_32bit".to_string(), description: "Whether the 68k variant supports 32-bit ISA extensions.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantIs32BitTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"variant":variant.name(),"is_32bit":variant.is_32bit(),"source":"rustre_arch_68k::Mc68kVariant::is_32bit"}).to_string())) } }

pub struct Arch68kVariantHasBitfieldTool;
impl Arch68kVariantHasBitfieldTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_has_bitfield".to_string(), description: "Whether the 68k variant supports bitfield instructions.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantHasBitfieldTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"variant":variant.name(),"has_bitfield":variant.has_bitfield(),"source":"rustre_arch_68k::Mc68kVariant::has_bitfield"}).to_string())) } }

pub struct Arch68kVariantAddressSpaceBytesTool;
impl Arch68kVariantAddressSpaceBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_variant_address_space_bytes".to_string(), description: "Max addressable bytes for a 68k variant.".to_string(), input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kVariantAddressSpaceBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?; let variant = arch68k_parse_variant(v)?; Ok(ToolResult::text(json!({"variant":variant.name(),"address_space_bytes":variant.address_space_bytes(),"source":"rustre_arch_68k::Mc68kVariant::address_space_bytes"}).to_string())) } }

pub struct Arch68kEaKindDataRegDisplayTool;
impl Arch68kEaKindDataRegDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_eakind_datareg_display".to_string(), description: "Format a data-register-direct EA (Dn).".to_string(), input_schema: json!({"type":"object","required":["reg"],"properties":{"reg":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kEaKindDataRegDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("reg").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?; let ea = rustre_arch_68k::EaKind::DataReg((r & 7) as u8); Ok(ToolResult::text(json!({"reg":r & 7,"display":ea.display(),"is_indirect":ea.is_indirect(),"source":"rustre_arch_68k::EaKind::DataReg"}).to_string())) } }

pub struct Arch68kEaKindAddrRegDisplayTool;
impl Arch68kEaKindAddrRegDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_eakind_addrreg_display".to_string(), description: "Format an address-register-direct EA (An).".to_string(), input_schema: json!({"type":"object","required":["reg"],"properties":{"reg":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kEaKindAddrRegDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("reg").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?; let ea = rustre_arch_68k::EaKind::AddrReg((r & 7) as u8); Ok(ToolResult::text(json!({"reg":r & 7,"display":ea.display(),"is_indirect":ea.is_indirect(),"source":"rustre_arch_68k::EaKind::AddrReg"}).to_string())) } }

pub struct Arch68kEaKindImmediateDisplayTool;
impl Arch68kEaKindImmediateDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "arch68k_eakind_immediate_display".to_string(), description: "Format an immediate-value EA (#$V).".to_string(), input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for Arch68kEaKindImmediateDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let ea = rustre_arch_68k::EaKind::Immediate((v & 0xFFFF_FFFF) as u32); Ok(ToolResult::text(json!({"value":v & 0xFFFF_FFFF,"display":ea.display(),"is_indirect":ea.is_indirect(),"source":"rustre_arch_68k::EaKind::Immediate"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Arch68kSizeBytesTool::definition(), Box::new(Arch68kSizeBytesTool)),
        (Arch68kCondCodeMnemonicTool::definition(), Box::new(Arch68kCondCodeMnemonicTool)),
        (Arch68kSizeSuffixTool::definition(), Box::new(Arch68kSizeSuffixTool)),
        (Arch68kSizeFromBits2Tool::definition(), Box::new(Arch68kSizeFromBits2Tool)),
        (Arch68kCondCodeFromBitsTool::definition(), Box::new(Arch68kCondCodeFromBitsTool)),
        (Arch68kVariantNameTool::definition(), Box::new(Arch68kVariantNameTool)),
        (Arch68kVariantHasFpuTool::definition(), Box::new(Arch68kVariantHasFpuTool)),
        (Arch68kVariantHasMmuTool::definition(), Box::new(Arch68kVariantHasMmuTool)),
        (Arch68kVariantIs32BitTool::definition(), Box::new(Arch68kVariantIs32BitTool)),
        (Arch68kVariantHasBitfieldTool::definition(), Box::new(Arch68kVariantHasBitfieldTool)),
        (Arch68kVariantAddressSpaceBytesTool::definition(), Box::new(Arch68kVariantAddressSpaceBytesTool)),
        (Arch68kEaKindDataRegDisplayTool::definition(), Box::new(Arch68kEaKindDataRegDisplayTool)),
        (Arch68kEaKindAddrRegDisplayTool::definition(), Box::new(Arch68kEaKindAddrRegDisplayTool)),
        (Arch68kEaKindImmediateDisplayTool::definition(), Box::new(Arch68kEaKindImmediateDisplayTool)),
    ]
}
