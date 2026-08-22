//! MCP wrappers for the rustre-deobf crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{dvm_hex_to_bytes};

pub struct DeobfCrc32ChecksumTool;
impl DeobfCrc32ChecksumTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_crc32_checksum".to_string(), description: "CRC-32 (IEEE 802.3) via rustre_deobf::Crc32::checksum.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfCrc32ChecksumTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let c = rustre_deobf::Crc32::checksum(&data); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"crc32":c,"crc32_hex":crate::hex_encode(&c.to_be_bytes()),"bytes":data.len(),"source":"rustre_deobf::Crc32::checksum"}).to_string())) } }

pub struct DeobfCrc32ChecksumTableTool;
impl DeobfCrc32ChecksumTableTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_crc32_checksum_table".to_string(), description: "Table-driven CRC-32 via rustre_deobf::Crc32::checksum_table.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfCrc32ChecksumTableTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let c = rustre_deobf::Crc32::checksum_table(&data); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"crc32":c,"crc32_hex":crate::hex_encode(&c.to_be_bytes()),"bytes":data.len(),"source":"rustre_deobf::Crc32::checksum_table"}).to_string())) } }

pub struct DeobfRc4DecryptTool;
impl DeobfRc4DecryptTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_rc4_decrypt".to_string(), description: "RC4 encrypt/decrypt (symmetric) via rustre_deobf::Rc4Decryptor::decrypt.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"key":{"type":"array","items":{"type":"integer"}},"key_hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfRc4DecryptTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let key: Vec<u8> = if let Some(arr) = args.get("key").and_then(serde_json::Value::as_array) { arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect() } else if let Some(s) = args.get("key_hex").and_then(serde_json::Value::as_str) { let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect(); (0..clean.len()).step_by(2).filter_map(|i| u8::from_str_radix(clean.get(i..i+2)?, 16).ok()).collect() } else { return Err(rustre_mcp_server::McpError::InvalidParams("missing 'key' or 'key_hex'".into())); }; let out = rustre_deobf::Rc4Decryptor::decrypt(&data, &key); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"key_len":key.len(),"source":"rustre_deobf::Rc4Decryptor::decrypt"}).to_string())) } }

pub struct DeobfRc4KsaTool;
impl DeobfRc4KsaTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_rc4_ksa".to_string(), description: "Initialize RC4 S-box via rustre_deobf::Rc4Decryptor::ksa; returns first-16 bytes of state.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"key":{"type":"array","items":{"type":"integer"}},"key_hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfRc4KsaTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let key: Vec<u8> = if let Some(arr) = args.get("key").and_then(serde_json::Value::as_array) { arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect() } else if let Some(s) = args.get("key_hex").and_then(serde_json::Value::as_str) { let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect(); (0..clean.len()).step_by(2).filter_map(|i| u8::from_str_radix(clean.get(i..i+2)?, 16).ok()).collect() } else { return Err(rustre_mcp_server::McpError::InvalidParams("missing 'key' or 'key_hex'".into())); }; let sbox = rustre_deobf::Rc4Decryptor::ksa(&key); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"first16_hex":crate::hex_encode(&sbox[..16]),"key_len":key.len(),"source":"rustre_deobf::Rc4Decryptor::ksa"}).to_string())) } }

pub struct DeobfXorDecryptConstantTool;
impl DeobfXorDecryptConstantTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_xor_decrypt_constant".to_string(), description: "XOR each byte with a constant key via rustre_deobf::XorDecryptor::decrypt_constant.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"key":{"type":"integer"}},"required":["key"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfXorDecryptConstantTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let key = args.get("key").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'key'".into()))? as u8; let out = rustre_deobf::XorDecryptor::decrypt_constant(&data, key); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"source":"rustre_deobf::XorDecryptor::decrypt_constant"}).to_string())) } }

pub struct DeobfXorDecryptCyclicTool;
impl DeobfXorDecryptCyclicTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_xor_decrypt_cyclic".to_string(), description: "XOR with a cyclic (repeating) key via rustre_deobf::XorDecryptor::decrypt_cyclic.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"key":{"type":"array","items":{"type":"integer"}},"key_hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfXorDecryptCyclicTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let key: Vec<u8> = if let Some(arr) = args.get("key").and_then(serde_json::Value::as_array) { arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect() } else if let Some(s) = args.get("key_hex").and_then(serde_json::Value::as_str) { let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect(); (0..clean.len()).step_by(2).filter_map(|i| u8::from_str_radix(clean.get(i..i+2)?, 16).ok()).collect() } else { return Err(rustre_mcp_server::McpError::InvalidParams("missing 'key' or 'key_hex'".into())); }; if key.is_empty() { return Err(rustre_mcp_server::McpError::InvalidParams("empty key".into())); } let out = rustre_deobf::XorDecryptor::decrypt_cyclic(&data, &key); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"key_len":key.len(),"source":"rustre_deobf::XorDecryptor::decrypt_cyclic"}).to_string())) } }

pub struct DeobfXorDecryptRollingTool;
impl DeobfXorDecryptRollingTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_xor_decrypt_rolling".to_string(), description: "XOR with a rolling single-byte key via rustre_deobf::XorDecryptor::decrypt_rolling.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"initial_key":{"type":"integer"}},"required":["initial_key"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfXorDecryptRollingTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let key = args.get("initial_key").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'initial_key'".into()))? as u8; let out = rustre_deobf::XorDecryptor::decrypt_rolling(&data, key); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"source":"rustre_deobf::XorDecryptor::decrypt_rolling"}).to_string())) } }

pub struct DeobfXorRecoverSingleByteKeyTool;
impl DeobfXorRecoverSingleByteKeyTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_xor_recover_single_byte_key".to_string(), description: "Brute-force the best single-byte XOR key via rustre_deobf::XorDecryptor::recover_single_byte_key.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfXorRecoverSingleByteKeyTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let (key, decoded) = rustre_deobf::XorDecryptor::recover_single_byte_key(&data); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"key":key,"decoded_hex":crate::hex_encode(&decoded),"len":decoded.len(),"source":"rustre_deobf::XorDecryptor::recover_single_byte_key"}).to_string())) } }

pub struct DeobfRolrorDecryptRolTool;
impl DeobfRolrorDecryptRolTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_rolror_decrypt_rol".to_string(), description: "Rotate-left decrypt via rustre_deobf::RolRorDecryptor::decrypt_rol.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"rotation":{"type":"integer"}},"required":["rotation"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfRolrorDecryptRolTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let rot = args.get("rotation").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'rotation'".into()))? as u8; let out = rustre_deobf::RolRorDecryptor::decrypt_rol(&data, rot); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"source":"rustre_deobf::RolRorDecryptor::decrypt_rol"}).to_string())) } }

pub struct DeobfRolrorDecryptRorTool;
impl DeobfRolrorDecryptRorTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_rolror_decrypt_ror".to_string(), description: "Rotate-right decrypt via rustre_deobf::RolRorDecryptor::decrypt_ror.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"rotation":{"type":"integer"}},"required":["rotation"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfRolrorDecryptRorTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let rot = args.get("rotation").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'rotation'".into()))? as u8; let out = rustre_deobf::RolRorDecryptor::decrypt_ror(&data, rot); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"out_hex":crate::hex_encode(&out),"len":out.len(),"source":"rustre_deobf::RolRorDecryptor::decrypt_ror"}).to_string())) } }

pub struct DeobfRolrorRecoverRotationTool;
impl DeobfRolrorRecoverRotationTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_rolror_recover_rotation".to_string(), description: "Recover ROL/ROR rotation amount via rustre_deobf::RolRorDecryptor::recover_rotation.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfRolrorRecoverRotationTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let (rot, is_ror, decoded) = rustre_deobf::RolRorDecryptor::recover_rotation(&data); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"rotation":rot,"is_ror":is_ror,"decoded_hex":crate::hex_encode(&decoded),"len":decoded.len(),"source":"rustre_deobf::RolRorDecryptor::recover_rotation"}).to_string())) } }

pub struct DeobfBase64DecodeTool;
impl DeobfBase64DecodeTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_base64_decode".to_string(), description: "Decode a Base-64 string via rustre_deobf::Base64Decoder::decode.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfBase64DecodeTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let text = args.get("text").and_then(serde_json::Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'text'".into()))?; match rustre_deobf::Base64Decoder::decode(text.as_bytes()) { Some(out) => Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"ok":true,"out_hex":crate::hex_encode(&out),"len":out.len(),"source":"rustre_deobf::Base64Decoder::decode"}).to_string())), None => Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"ok":false,"error":"invalid base64","source":"rustre_deobf::Base64Decoder::decode"}).to_string())) } } }

pub struct DeobfBase64FindAllTool;
impl DeobfBase64FindAllTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_base64_find_all".to_string(), description: "Scan bytes for embedded Base-64 blobs via rustre_deobf::Base64Decoder::find_all.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfBase64FindAllTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let hits = rustre_deobf::Base64Decoder::find_all(&data); let items: Vec<serde_json::Value> = hits.iter().map(|h| serde_json::json!({"offset":h.offset,"encoded_len":h.encoded.len(),"decoded_hex":crate::hex_encode(&h.decoded),"decoded_len":h.decoded.len()})).collect(); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"count":items.len(),"hits":items,"source":"rustre_deobf::Base64Decoder::find_all"}).to_string())) } }

pub struct DeobfEntropyScannerScanTool;
impl DeobfEntropyScannerScanTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "deobf_entropy_scanner_scan".to_string(), description: "Sliding-window entropy scan via rustre_deobf::EntropyScanner::scan.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"window":{"type":"integer"},"step":{"type":"integer"},"threshold":{"type":"number"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for DeobfEntropyScannerScanTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let data = crate::args_to_bytes(&args)?; let mut sc = rustre_deobf::EntropyScanner::new(); if let Some(w) = args.get("window").and_then(serde_json::Value::as_u64) { sc.window = w as usize; } if let Some(s) = args.get("step").and_then(serde_json::Value::as_u64) { sc.step = s as usize; } if let Some(t) = args.get("threshold").and_then(serde_json::Value::as_f64) { sc.threshold = t; } let regs = sc.scan(&data); let items: Vec<serde_json::Value> = regs.iter().map(|r| serde_json::json!({"offset":r.offset,"length":r.length,"entropy":r.entropy})).collect(); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"count":items.len(),"regions":items,"window":sc.window,"step":sc.step,"threshold":sc.threshold,"source":"rustre_deobf::EntropyScanner::scan"}).to_string())) } }

pub struct DeobfStringXorBruteforceTop3Tool;

pub struct DeobfStringComputeConfidenceTool;

pub struct DeobfStringCaesarBruteforceTool;

pub struct DeobfStringDetectBase64VariantTool;

pub struct DeobfStringDetectXorKeyLengthIcTool;

pub struct DeobfVmReadU64LeTool;

pub struct DeobfVmReadU32LeTool;

pub struct DeobfVmReadU16LeTool;

pub struct DeobfOpaqueKnownPatternsTool;
impl DeobfOpaqueKnownPatternsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_opaque_known_patterns".to_string(),
            description: "List all built-in opaque-predicate patterns from \
                          rustre_deobf_opaque::build_known_patterns.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfOpaqueKnownPatternsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let pats = rustre_deobf_opaque::build_known_patterns();
        let items: Vec<Value> = pats.iter().map(|p| json!({
            "name": p.name,
            "description": p.description,
            "value": p.value.to_string(),
            "kind": p.kind.to_string(),
        })).collect();
        Ok(ToolResult::text(json!({
            "count": items.len(),
            "patterns": items,
            "source": "rustre_deobf_opaque::build_known_patterns",
        }).to_string()))
    }
}

pub struct DeobfOpaqueClassifyConstTool;
impl DeobfOpaqueClassifyConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_opaque_classify_const".to_string(),
            description: "Classify an integer literal as an opaque predicate \
                          value via TruthTableChecker on OpaqueExpr::Const.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "value": { "type": "integer" } },
                "required": ["value"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfOpaqueClassifyConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let expr = rustre_deobf_opaque::OpaqueExpr::Const(v);
        let checker = rustre_deobf_opaque::TruthTableChecker::new();
        let cls = checker.classify(&expr);
        Ok(ToolResult::text(json!({
            "value": v,
            "classification": cls.to_string(),
            "is_const": expr.is_const(),
            "display": expr.to_string(),
            "source": "rustre_deobf_opaque::TruthTableChecker::classify",
        }).to_string()))
    }
}

pub struct DeobfOpaqueTruthTableDefaultsTool;
impl DeobfOpaqueTruthTableDefaultsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_opaque_truth_table_defaults".to_string(),
            description: "Return default TruthTableChecker configuration \
                          (bits, sample_count, use_random).".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfOpaqueTruthTableDefaultsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_deobf_opaque::TruthTableChecker::default();
        Ok(ToolResult::text(json!({
            "bits": c.bits,
            "sample_count": c.sample_count,
            "use_random": c.use_random,
            "source": "rustre_deobf_opaque::TruthTableChecker::default",
        }).to_string()))
    }
}

pub struct DeobfXorEntropyTool;

pub struct DeobfAdler32Tool;

pub struct DeobfCrc32Tool;

pub struct DeobfSmcShannonEntropyTool;

pub struct DeobfSmcLooksLikeCodeTool;

pub struct DeobfSmcDetectTool;

pub struct DeobfSmcDetectIndicatorsTool;
impl DeobfSmcDetectIndicatorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_detect_indicators".to_string(),
            description: "Detect SMC indicators via rustre_deobf_smc::detect_smc_indicators.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcDetectIndicatorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let indicators = rustre_deobf_smc::detect_smc_indicators(&data);
        let count = indicators.len();
        Ok(ToolResult::text(json!({"indicators":indicators,"count":count,"bytes":data.len(),"source":"rustre_deobf_smc::detect_smc_indicators"}).to_string()))
    }
}

pub struct DeobfSmcXorChainDetectTool;
impl DeobfSmcXorChainDetectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_xor_chain_detect".to_string(),
            description: "Detect multi-round XOR-chain cipher via rustre_deobf_smc::XorChainDetector::detect.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcXorChainDetectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let chain = rustre_deobf_smc::XorChainDetector::new().detect(&data);
        let steps = chain.as_ref().map(rustre_deobf_smc::XorChain::len).unwrap_or(0);
        Ok(ToolResult::text(json!({"chain":chain,"steps":steps,"bytes":data.len(),"source":"rustre_deobf_smc::XorChainDetector::detect"}).to_string()))
    }
}

pub struct DeobfSmcAddRolEncryptTool;
impl DeobfSmcAddRolEncryptTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_addrol_encrypt".to_string(),
            description: "Encrypt bytes with ADD+ROL cipher via rustre_deobf_smc::AddRolCipher::encrypt.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"add_key":{"type":"integer"},"rol_amount":{"type":"integer"},"add_first":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcAddRolEncryptTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let add_key = args.get("add_key").and_then(Value::as_u64).unwrap_or(0) as u8;
        let rol_amount = args.get("rol_amount").and_then(Value::as_u64).unwrap_or(0) as u8;
        let add_first = args.get("add_first").and_then(Value::as_bool).unwrap_or(true);
        let out = rustre_deobf_smc::AddRolCipher::new(add_key, rol_amount, add_first).encrypt(&data);
        Ok(ToolResult::text(json!({"out_hex":hex_encode(&out),"bytes":data.len(),"source":"rustre_deobf_smc::AddRolCipher::encrypt"}).to_string()))
    }
}

pub struct DeobfSmcAddRolDecryptTool;
impl DeobfSmcAddRolDecryptTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_addrol_decrypt".to_string(),
            description: "Decrypt bytes with ADD+ROL cipher via rustre_deobf_smc::AddRolCipher::decrypt.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"add_key":{"type":"integer"},"rol_amount":{"type":"integer"},"add_first":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcAddRolDecryptTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let add_key = args.get("add_key").and_then(Value::as_u64).unwrap_or(0) as u8;
        let rol_amount = args.get("rol_amount").and_then(Value::as_u64).unwrap_or(0) as u8;
        let add_first = args.get("add_first").and_then(Value::as_bool).unwrap_or(true);
        let out = rustre_deobf_smc::AddRolCipher::new(add_key, rol_amount, add_first).decrypt(&data);
        Ok(ToolResult::text(json!({"out_hex":hex_encode(&out),"bytes":data.len(),"source":"rustre_deobf_smc::AddRolCipher::decrypt"}).to_string()))
    }
}

pub struct DeobfSmcStatsFromBytesTool;
impl DeobfSmcStatsFromBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_stats_from_bytes".to_string(),
            description: "Detect SMC regions and aggregate stats via rustre_deobf_smc::SmcStats::from_regions.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcStatsFromBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let regions = rustre_deobf_smc::SmcDetector::new().detect(&data);
        let stats = rustre_deobf_smc::SmcStats::from_regions(&regions);
        Ok(ToolResult::text(json!({"stats":stats,"bytes":data.len(),"source":"rustre_deobf_smc::SmcStats::from_regions"}).to_string()))
    }
}

pub struct DeobfSmcUnpackedRegionsTool;
impl DeobfSmcUnpackedRegionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_unpacked_regions".to_string(),
            description: "Detect unpacked/low-entropy regions via rustre_deobf_smc::UnpackedRegionDetector::detect.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"window_size":{"type":"integer"},"entropy_threshold":{"type":"number"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcUnpackedRegionsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let window_size = args.get("window_size").and_then(Value::as_u64).unwrap_or(256) as usize;
        let entropy_threshold = args.get("entropy_threshold").and_then(Value::as_f64).unwrap_or(6.0);
        let regions = rustre_deobf_smc::UnpackedRegionDetector::new(window_size, entropy_threshold).detect(&data);
        let count = regions.len();
        Ok(ToolResult::text(json!({"regions":regions,"count":count,"bytes":data.len(),"source":"rustre_deobf_smc::UnpackedRegionDetector::detect"}).to_string()))
    }
}

pub struct DeobfSmcPolymorphicAnalyzeTool;
impl DeobfSmcPolymorphicAnalyzeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_polymorphic_analyze".to_string(),
            description: "Diff before/after snapshots via rustre_deobf_smc::PolymorphicEngineAnalyzer::analyze.".to_string(),
            input_schema: json!({"type":"object","properties":{"before_hex":{"type":"string"},"after_hex":{"type":"string"}},"required":["before_hex","after_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcPolymorphicAnalyzeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let before_hex = args.get("before_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'before_hex'".into()))?.to_string();
        let after_hex  = args.get("after_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'after_hex'".into()))?.to_string();
        let before = args_to_bytes(&json!({ "hex": before_hex }))?;
        let after  = args_to_bytes(&json!({ "hex": after_hex  }))?;
        let events = rustre_deobf_smc::PolymorphicEngineAnalyzer::new().analyze(&before, &after);
        let count = events.len();
        Ok(ToolResult::text(json!({"events":events,"count":count,"source":"rustre_deobf_smc::PolymorphicEngineAnalyzer::analyze"}).to_string()))
    }
}

pub struct DeobfSmcMockTraceTool;
impl DeobfSmcMockTraceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_mock_trace".to_string(),
            description: "Deterministic two-stage packer timeline via rustre_deobf_smc::MockSmcTracer::trace_binary.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"entry":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcMockTraceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let entry = args.get("entry").and_then(Value::as_u64).unwrap_or(0);
        let timeline = rustre_deobf_smc::MockSmcTracer::trace_binary(&data, entry);
        Ok(ToolResult::text(json!({"timeline":timeline,"bytes":data.len(),"entry":entry,"source":"rustre_deobf_smc::MockSmcTracer::trace_binary"}).to_string()))
    }
}

pub struct DeobfSmcXorStepApplyTool;
impl DeobfSmcXorStepApplyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_xor_step_apply".to_string(),
            description: "Apply one XorChainStep to a byte via rustre_deobf_smc::XorChainStep::apply.".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"},"key":{"type":"integer"},"pre_op":{"type":"integer"},"rot_amount":{"type":"integer"}},"required":["byte","key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcXorStepApplyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let byte       = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let key        = args.get("key").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))? as u8;
        let pre_op     = args.get("pre_op").and_then(Value::as_u64).unwrap_or(0) as u8;
        let rot_amount = args.get("rot_amount").and_then(Value::as_u64).unwrap_or(0) as u8;
        let step = rustre_deobf_smc::XorChainStep { key, pre_op, rot_amount };
        Ok(ToolResult::text(json!({"in":byte,"out":step.apply(byte),"source":"rustre_deobf_smc::XorChainStep::apply"}).to_string()))
    }
}

pub struct DeobfSmcXorStepReverseTool;
impl DeobfSmcXorStepReverseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_xor_step_reverse".to_string(),
            description: "Reverse one XorChainStep on a byte via rustre_deobf_smc::XorChainStep::reverse.".to_string(),
            input_schema: json!({"type":"object","properties":{"byte":{"type":"integer"},"key":{"type":"integer"},"pre_op":{"type":"integer"},"rot_amount":{"type":"integer"}},"required":["byte","key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcXorStepReverseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let byte       = args.get("byte").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'byte'".into()))? as u8;
        let key        = args.get("key").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))? as u8;
        let pre_op     = args.get("pre_op").and_then(Value::as_u64).unwrap_or(0) as u8;
        let rot_amount = args.get("rot_amount").and_then(Value::as_u64).unwrap_or(0) as u8;
        let step = rustre_deobf_smc::XorChainStep { key, pre_op, rot_amount };
        Ok(ToolResult::text(json!({"in":byte,"out":step.reverse(byte),"source":"rustre_deobf_smc::XorChainStep::reverse"}).to_string()))
    }
}

pub struct DeobfSmcWriteExecDetectTool;
impl DeobfSmcWriteExecDetectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_write_exec_detect".to_string(),
            description: "Detect write-then-execute pairs via rustre_deobf_smc::WriteExecuteDetector.".to_string(),
            input_schema: json!({"type":"object","properties":{"writes":{"type":"array","items":{"type":"object"}},"executions":{"type":"array","items":{"type":"object"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcWriteExecDetectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut det = rustre_deobf_smc::WriteExecuteDetector::new();
        if let Some(arr) = args.get("writes").and_then(Value::as_array) {
            for w in arr {
                let pc   = w.get("pc").and_then(Value::as_u64).unwrap_or(0);
                let addr = w.get("addr").and_then(Value::as_u64).unwrap_or(0);
                let size = w.get("size").and_then(Value::as_u64).unwrap_or(1) as u8;
                det.add_write(pc, addr, size);
            }
        }
        if let Some(arr) = args.get("executions").and_then(Value::as_array) {
            for e in arr {
                let pc     = e.get("pc").and_then(Value::as_u64).unwrap_or(0);
                let target = e.get("target").and_then(Value::as_u64).unwrap_or(0);
                det.add_execution(pc, target);
            }
        }
        let pairs = det.find_write_then_execute();
        let count = pairs.len();
        Ok(ToolResult::text(json!({"pairs":pairs,"count":count,"source":"rustre_deobf_smc::WriteExecuteDetector::find_write_then_execute"}).to_string()))
    }
}

pub struct DeobfSmcXorChainDecryptTool;
impl DeobfSmcXorChainDecryptTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_smc_xor_chain_decrypt".to_string(),
            description: "Decrypt bytes with a multi-round XorChain via rustre_deobf_smc::XorChain::decrypt.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"steps":{"type":"array","items":{"type":"object"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfSmcXorChainDecryptTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let mut chain = rustre_deobf_smc::XorChain::new();
        if let Some(arr) = args.get("steps").and_then(Value::as_array) {
            for s in arr {
                chain.push(rustre_deobf_smc::XorChainStep {
                    key:        s.get("key").and_then(Value::as_u64).unwrap_or(0) as u8,
                    pre_op:     s.get("pre_op").and_then(Value::as_u64).unwrap_or(0) as u8,
                    rot_amount: s.get("rot_amount").and_then(Value::as_u64).unwrap_or(0) as u8,
                });
            }
        }
        let out = chain.decrypt(&data);
        Ok(ToolResult::text(json!({"out_hex":hex_encode(&out),"steps":chain.len(),"bytes":data.len(),"source":"rustre_deobf_smc::XorChain::decrypt"}).to_string()))
    }
}

pub struct DeobfStringRecoverMultibyteXorTool;
impl DeobfStringRecoverMultibyteXorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_recover_multibyte_xor".to_string(),
            description: "Recover multi-byte XOR key using IC and frequency analysis (rustre_deobf_string::recover_multibyte_xor).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"},
                "max_key_len":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringRecoverMultibyteXorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let max_key_len = args.get("max_key_len").and_then(Value::as_u64).unwrap_or(16) as usize;
        let res = rustre_deobf_string::recover_multibyte_xor(&data, max_key_len);
        let out: Vec<Value> = res.iter().map(|r| json!({
            "key_length": r.key_length,
            "key_hex": hex_encode(&r.key),
            "decrypted_hex": hex_encode(&r.decrypted),
            "avg_ic": r.avg_ic,
            "confidence": r.confidence,
        })).collect();
        Ok(ToolResult::text(json!({"results": out, "source": "rustre_deobf_string::recover_multibyte_xor"}).to_string()))
    }
}

pub struct DeobfStringDecodeBase64UrlsafeTool;
impl DeobfStringDecodeBase64UrlsafeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_decode_base64_urlsafe".to_string(),
            description: "Decode a URL-safe Base64 input (rustre_deobf_string::decode_base64_urlsafe).".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringDecodeBase64UrlsafeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        match rustre_deobf_string::decode_base64_urlsafe(text) {
            Ok(bytes) => Ok(ToolResult::text(json!({
                "decoded_hex": hex_encode(&bytes),
                "decoded_utf8": std::str::from_utf8(&bytes).ok(),
                "len": bytes.len(),
                "source": "rustre_deobf_string::decode_base64_urlsafe",
            }).to_string())),
            Err(e) => Err(McpError::InternalError(format!("{e}"))),
        }
    }
}

pub struct DeobfStringRot13Tool;
impl DeobfStringRot13Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_rot13".to_string(),
            description: "Apply ROT-13 (rustre_deobf_string::RotN::rot13).".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringRot13Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let out = rustre_deobf_string::RotN::rot13(text);
        Ok(ToolResult::text(json!({"output": out, "source": "rustre_deobf_string::RotN::rot13"}).to_string()))
    }
}

pub struct DeobfStringRotnDetectTool;
impl DeobfStringRotnDetectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_rotn_detect".to_string(),
            description: "Detect best Caesar rotation (rustre_deobf_string::RotN::detect_rotation).".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringRotnDetectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let n = rustre_deobf_string::RotN::detect_rotation(text);
        let decoded = rustre_deobf_string::RotN::decrypt(text, n);
        Ok(ToolResult::text(json!({"rotation": n, "decoded": decoded, "source": "rustre_deobf_string::RotN::detect_rotation"}).to_string()))
    }
}

pub struct DeobfStringXorDecryptConstantTool;
impl DeobfStringXorDecryptConstantTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_xor_decrypt_constant".to_string(),
            description: "XOR-decrypt bytes with constant single-byte key (rustre_deobf_string::XorDecryptor::decrypt_constant).".to_string(),
            input_schema: json!({"type":"object","required":["key"],"properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"},
                "key":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringXorDecryptConstantTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let key = args.get("key").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))? as u8;
        let out = rustre_deobf_string::XorDecryptor::decrypt_constant(&data, key);
        Ok(ToolResult::text(json!({
            "decrypted_hex": hex_encode(&out),
            "decrypted_utf8": std::str::from_utf8(&out).ok(),
            "source": "rustre_deobf_string::XorDecryptor::decrypt_constant",
        }).to_string()))
    }
}

pub struct DeobfStringXorDecryptCyclicTool;
impl DeobfStringXorDecryptCyclicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_xor_decrypt_cyclic".to_string(),
            description: "XOR-decrypt with cyclic multi-byte key (rustre_deobf_string::XorDecryptor::decrypt_cyclic).".to_string(),
            input_schema: json!({"type":"object","required":["key_hex"],"properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"},
                "key_hex":{"type":"string"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringXorDecryptCyclicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let key_hex = args.get("key_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'key_hex'".into()))?;
        let key = crate::hex_decode(key_hex)?;
        match rustre_deobf_string::XorDecryptor::decrypt_cyclic(&data, &key) {
            Ok(out) => Ok(ToolResult::text(json!({
                "decrypted_hex": hex_encode(&out),
                "decrypted_utf8": std::str::from_utf8(&out).ok(),
                "source": "rustre_deobf_string::XorDecryptor::decrypt_cyclic",
            }).to_string())),
            Err(e) => Err(McpError::InternalError(format!("{e}"))),
        }
    }
}

pub struct DeobfStringXorRecoverKeyTool;
impl DeobfStringXorRecoverKeyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_xor_recover_key".to_string(),
            description: "Recover best single-byte XOR key (rustre_deobf_string::XorDecryptor::recover_key).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringXorRecoverKeyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let (key, dec) = rustre_deobf_string::XorDecryptor::recover_key(&data);
        Ok(ToolResult::text(json!({
            "key": key,
            "decrypted_hex": hex_encode(&dec),
            "decrypted_utf8": std::str::from_utf8(&dec).ok(),
            "source": "rustre_deobf_string::XorDecryptor::recover_key",
        }).to_string()))
    }
}

pub struct DeobfStringXorDetectKeyPeriodTool;
impl DeobfStringXorDetectKeyPeriodTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_xor_detect_key_period".to_string(),
            description: "Detect XOR key period via IC (rustre_deobf_string::XorDecryptor::detect_key_period).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"},
                "max_period":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringXorDetectKeyPeriodTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let max_period = args.get("max_period").and_then(Value::as_u64).unwrap_or(16) as usize;
        let p = rustre_deobf_string::XorDecryptor::detect_key_period(&data, max_period);
        Ok(ToolResult::text(json!({
            "period": p,
            "max_period": max_period,
            "source": "rustre_deobf_string::XorDecryptor::detect_key_period",
        }).to_string()))
    }
}

pub struct DeobfStringRc4DecryptTool;
impl DeobfStringRc4DecryptTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_rc4_decrypt".to_string(),
            description: "RC4 decrypt (rustre_deobf_string::Rc4::decrypt).".to_string(),
            input_schema: json!({"type":"object","required":["key_hex"],"properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"},
                "key_hex":{"type":"string"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringRc4DecryptTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let key_hex = args.get("key_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'key_hex'".into()))?;
        let key = crate::hex_decode(key_hex)?;
        let out = rustre_deobf_string::Rc4::decrypt(&data, &key);
        Ok(ToolResult::text(json!({
            "decrypted_hex": hex_encode(&out),
            "decrypted_utf8": std::str::from_utf8(&out).ok(),
            "source": "rustre_deobf_string::Rc4::decrypt",
        }).to_string()))
    }
}

pub struct DeobfStringBase64EncodeTool;
impl DeobfStringBase64EncodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_base64_encode".to_string(),
            description: "Standard Base64 encode (rustre_deobf_string::Base64Decoder::encode).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},
                "hex":{"type":"string"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringBase64EncodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let s = rustre_deobf_string::Base64Decoder::encode(&data);
        Ok(ToolResult::text(json!({"encoded": s, "source": "rustre_deobf_string::Base64Decoder::encode"}).to_string()))
    }
}

pub struct DeobfStringHexDecodeTool;
impl DeobfStringHexDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_string_hex_decode".to_string(),
            description: "Decode hex string (rustre_deobf_string::HexDecoder::decode).".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DeobfStringHexDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        match rustre_deobf_string::HexDecoder::decode(text) {
            Ok(bytes) => Ok(ToolResult::text(json!({
                "decoded_hex": hex_encode(&bytes),
                "decoded_utf8": std::str::from_utf8(&bytes).ok(),
                "len": bytes.len(),
                "source": "rustre_deobf_string::HexDecoder::decode",
            }).to_string())),
            Err(e) => Err(McpError::InternalError(format!("{e}"))),
        }
    }
}

pub struct DeobfVmDetectDispatcherTool;
impl DeobfVmDetectDispatcherTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_detect_dispatcher".to_string(), description: "Detect VM dispatcher in hex-encoded blocks.".to_string(), input_schema: json!({"type":"object","required":["blocks_hex"],"properties":{"blocks_hex":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmDetectDispatcherTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("blocks_hex").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("blocks_hex".into()))?; let blocks: Vec<Vec<u8>> = arr.iter().filter_map(Value::as_str).map(dvm_hex_to_bytes).collect::<Result<_, McpError>>()?; let res = rustre_deobf_vm::VmDispatcherDetector::detect(&blocks); Ok(ToolResult::text(json!({"found": res.is_some(), "dispatcher": res.map(|d| json!({"entry": d.entry.as_u64(), "handler_table_base": d.handler_table_base.as_u64(), "handler_count": d.handler_count}))}).to_string())) } }

pub struct DeobfVmDetectorAnalyzeTool;
impl DeobfVmDetectorAnalyzeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_detector_analyze".to_string(), description: "Run VmDetector::detect.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmDetectorAnalyzeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let r = rustre_deobf_vm::VmDetector::new().detect(&dvm_hex_to_bytes(hex)?); Ok(ToolResult::text(json!({"confidence": format!("{:?}", r.confidence), "dispatcher_count": r.dispatcher_count, "handler_count": r.handler_count, "arch_hints": r.arch_hints, "dispatcher_offset": r.dispatcher_offset}).to_string())) } }

pub struct DeobfVmBytecodeNewTool;
impl DeobfVmBytecodeNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_bytecode_new".to_string(), description: "Build VmBytecode and return metadata.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmBytecodeNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let start = args.get("start_address").and_then(Value::as_u64).unwrap_or(0); let w = args.get("opcode_width").and_then(Value::as_u64).unwrap_or(1) as u8; let bc = rustre_deobf_vm::VmBytecode::new(dvm_hex_to_bytes(hex)?, start, w); Ok(ToolResult::text(json!({"len": bc.len(), "distinct_opcodes": bc.distinct_opcodes, "entropy": bc.entropy, "looks_encrypted": bc.looks_encrypted()}).to_string())) } }

pub struct DeobfVmLifterLiftTool;
impl DeobfVmLifterLiftTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_lifter_lift".to_string(), description: "Lift hex bytecode to VmSemanticOps.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmLifterLiftTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let ops = rustre_deobf_vm::VmLifter::new().lift(&dvm_hex_to_bytes(hex)?).map_err(|e| McpError::InternalError(e.to_string()))?; let names: Vec<String> = ops.iter().map(|o| format!("{:?}", o)).collect(); Ok(ToolResult::text(json!({"count": names.len(), "ops": names}).to_string())) } }

pub struct DeobfVmSemanticOpStackDeltaTool;
impl DeobfVmSemanticOpStackDeltaTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_semantic_op_stack_delta".to_string(), description: "Stack delta of each VmSemanticOp.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmSemanticOpStackDeltaTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let ops = rustre_deobf_vm::VmLifter::new().lift(&dvm_hex_to_bytes(hex)?).map_err(|e| McpError::InternalError(e.to_string()))?; let info: Vec<_> = ops.iter().map(|o| json!({"op": format!("{:?}", o), "stack_delta": o.stack_delta(), "is_alu": o.is_alu(), "is_control_flow": o.is_control_flow()})).collect(); Ok(ToolResult::text(json!({"count": info.len(), "ops": info}).to_string())) } }

pub struct DeobfVmArchStackMachineTool;
impl DeobfVmArchStackMachineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_arch_stack_machine".to_string(), description: "Build a stack-machine VmArch summary.".to_string(), input_schema: json!({"type":"object","required":["opcode_count"],"properties":{"opcode_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmArchStackMachineTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("opcode_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'opcode_count'".into()))? as usize; let a = rustre_deobf_vm::VmArch::stack_machine(n); Ok(ToolResult::text(json!({"summary": a.summary(), "arch_type": a.arch_type, "complexity_score": a.complexity_score}).to_string())) } }

pub struct DeobfVmArchRegisterMachineTool;
impl DeobfVmArchRegisterMachineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_arch_register_machine".to_string(), description: "Build a register-machine VmArch summary.".to_string(), input_schema: json!({"type":"object","required":["register_count","opcode_count"],"properties":{"register_count":{"type":"integer"},"opcode_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmArchRegisterMachineTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("register_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'register_count'".into()))? as u32; let n = args.get("opcode_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'opcode_count'".into()))? as usize; let a = rustre_deobf_vm::VmArch::register_machine(r, n); Ok(ToolResult::text(json!({"summary": a.summary(), "arch_type": a.arch_type, "complexity_score": a.complexity_score, "register_count": a.register_count}).to_string())) } }

pub struct DeobfVmStateSimulateTool;
impl DeobfVmStateSimulateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_state_simulate".to_string(), description: "Lift and simulate hex bytecode on VirtualMachineState.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmStateSimulateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let l = rustre_deobf_vm::VmLifter::new(); let ops = l.lift(&dvm_hex_to_bytes(hex)?).map_err(|e| McpError::InternalError(e.to_string()))?; let s = l.simulate(&ops, rustre_deobf_vm::VirtualMachineState::new()).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"pc": s.pc, "flags": s.flags, "regs": s.regs, "stack": s.stack, "mem_cells": s.memory.len()}).to_string())) } }

pub struct DeobfVmHandlerPrologueEntropyTool;
impl DeobfVmHandlerPrologueEntropyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_handler_prologue_entropy".to_string(), description: "Shannon entropy of a VmHandler prologue.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmHandlerPrologueEntropyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_deobf_vm::{VmHandler, HandlerKind}; use rustre_core::address::Address; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let bytes = dvm_hex_to_bytes(hex)?; let h = VmHandler::new(0, Address::new(0), bytes.clone(), HandlerKind::Unknown, "", 0, 0); Ok(ToolResult::text(json!({"entropy": h.prologue_entropy(), "prologue_len": bytes.len()}).to_string())) } }

pub struct DeobfVmDeprotectSimpleTool;
impl DeobfVmDeprotectSimpleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_deprotect_simple".to_string(), description: "Run rustre_deobf_vm::deprotect_simple.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmDeprotectSimpleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let r = rustre_deobf_vm::deprotect_simple(&dvm_hex_to_bytes(hex)?); Ok(ToolResult::text(json!({"deprotected": r.is_some(), "output_len": r.as_ref().map(Vec::len).unwrap_or(0)}).to_string())) } }

pub struct DeobfVmPcodeVarnodeSizeTool;
impl DeobfVmPcodeVarnodeSizeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_pcode_varnode_size".to_string(), description: "Size of a PcodeVarnode.".to_string(), input_schema: json!({"type":"object","required":["kind","size"],"properties":{"kind":{"type":"string"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmPcodeVarnodeSizeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_deobf_vm::PcodeVarnode; let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as u8; let val = args.get("value").and_then(Value::as_u64).unwrap_or(0); let name = args.get("name").and_then(Value::as_str).unwrap_or("r0").to_string(); let vn = match kind { "unique" => PcodeVarnode::Unique(val, size), "register" => PcodeVarnode::Register(name, size), "ram" => PcodeVarnode::Ram(val, size), _ => PcodeVarnode::Const(val, size) }; Ok(ToolResult::text(json!({"size": vn.size(), "kind": kind}).to_string())) } }

pub struct DeobfVmStateNewProbeTool;
impl DeobfVmStateNewProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_state_new_probe".to_string(), description: "Create VirtualMachineState, push/pop values.".to_string(), input_schema: json!({"type":"object","properties":{"values":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmStateNewProbeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut s = rustre_deobf_vm::VirtualMachineState::new(); let vs: Vec<u32> = args.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_u64().map(|x| x as u32)).collect()).unwrap_or_default(); for v in &vs { s.push(*v); } let popped = s.pop(); Ok(ToolResult::text(json!({"pushed": vs.len(), "popped": popped, "stack_len": s.stack.len(), "pc": s.pc}).to_string())) } }

pub struct DeobfVmStateMemRoundtripTool;
impl DeobfVmStateMemRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_state_mem_roundtrip".to_string(), description: "Write then read a u32 in VirtualMachineState memory.".to_string(), input_schema: json!({"type":"object","required":["addr","value"],"properties":{"addr":{"type":"integer"},"value":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmStateMemRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("value".into()))? as u32; let mut s = rustre_deobf_vm::VirtualMachineState::new(); s.mem_write_u32(addr, value); let got = s.mem_read_u32(addr); let byte0 = s.mem_read_byte(addr); Ok(ToolResult::text(json!({"read": got, "match": got == value, "byte0": byte0, "cells": s.memory.len()}).to_string())) } }

pub struct DeobfVmStateFlagsTool;
impl DeobfVmStateFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_state_flags".to_string(), description: "Set ZF via result and read zero_flag/carry_flag.".to_string(), input_schema: json!({"type":"object","required":["result"],"properties":{"result":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmStateFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("result").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("result".into()))? as u32; let mut s = rustre_deobf_vm::VirtualMachineState::new(); s.set_zero_flag(r); Ok(ToolResult::text(json!({"zero_flag": s.zero_flag(), "carry_flag": s.carry_flag(), "flags": s.flags}).to_string())) } }

pub struct DeobfVmDispatcherDetectorProbeTool;
impl DeobfVmDispatcherDetectorProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_dispatcher_detector_probe".to_string(), description: "VmDispatcherDetector::new + detect_dispatcher.".to_string(), input_schema: json!({"type":"object","required":["blocks_hex"],"properties":{"blocks_hex":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmDispatcherDetectorProbeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("blocks_hex").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("blocks_hex".into()))?; let blocks: Vec<Vec<u8>> = arr.iter().filter_map(Value::as_str).map(dvm_hex_to_bytes).collect::<Result<_, McpError>>()?; let d = rustre_deobf_vm::VmDispatcherDetector::new(); let res = d.detect_dispatcher(&blocks); Ok(ToolResult::text(json!({"found": res.is_some(), "handler_count": res.map(|d| d.handler_count)}).to_string())) } }

pub struct DeobfVmHandlerClassifyTool;
impl DeobfVmHandlerClassifyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_handler_classify".to_string(), description: "Build a VmHandler and report is_arithmetic/is_control_flow.".to_string(), input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmHandlerClassifyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_deobf_vm::{VmHandler, HandlerKind}; use rustre_core::address::Address; let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?; let k = match kind { "arithmetic" => HandlerKind::Arithmetic, "logic" => HandlerKind::Logic, "load" => HandlerKind::Load, "store" => HandlerKind::Store, "control_flow" => HandlerKind::ControlFlow, "stack_op" => HandlerKind::StackOp, "compare" => HandlerKind::Compare, _ => HandlerKind::Unknown }; let bytes = args.get("hex").and_then(Value::as_str).map(dvm_hex_to_bytes).transpose()?.unwrap_or_default(); let h = VmHandler::new(0, Address::new(0), bytes, k, "", 1, 1); Ok(ToolResult::text(json!({"is_arithmetic": h.is_arithmetic(), "is_control_flow": h.is_control_flow(), "kind": format!("{:?}", h.kind), "entropy": h.prologue_entropy()}).to_string())) } }

pub struct DeobfVmBytecodeInspectTool;
impl DeobfVmBytecodeInspectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_bytecode_inspect".to_string(), description: "VmBytecode len/is_empty/is_non_empty/entropy.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmBytecodeInspectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let bc = rustre_deobf_vm::VmBytecode::new(dvm_hex_to_bytes(hex)?, 0, 1); Ok(ToolResult::text(json!({"len": bc.len(), "is_empty": bc.is_empty(), "is_non_empty": bc.is_non_empty(), "entropy": bc.entropy}).to_string())) } }

pub struct DeobfVmLifterRemapTool;
impl DeobfVmLifterRemapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_lifter_remap".to_string(), description: "VmLifter::with_opcode_map + remap probe.".to_string(), input_schema: json!({"type":"object","required":["from","to","probe"],"properties":{"from":{"type":"integer"},"to":{"type":"integer"},"probe":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmLifterRemapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let from = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("from".into()))? as u8; let to = args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("to".into()))? as u8; let probe = args.get("probe").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("probe".into()))? as u8; let mut map = std::collections::HashMap::new(); map.insert(from, to); let l = rustre_deobf_vm::VmLifter::new().with_opcode_map(map); Ok(ToolResult::text(json!({"remapped": l.remap(probe), "identity": l.remap(probe.wrapping_add(1))}).to_string())) } }

pub struct DeobfVmHandlerClusterTool;
impl DeobfVmHandlerClusterTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_handler_cluster".to_string(), description: "Cluster synthetic handlers via HandlerClusterer.".to_string(), input_schema: json!({"type":"object","required":["kinds"],"properties":{"kinds":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmHandlerClusterTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_deobf_vm::{VmHandler, HandlerKind, HandlerClusterer}; use rustre_core::address::Address; let arr = args.get("kinds").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("kinds".into()))?; let handlers: Vec<VmHandler> = arr.iter().enumerate().map(|(i, v)| { let k = match v.as_str().unwrap_or("unknown") { "arithmetic" => HandlerKind::Arithmetic, "logic" => HandlerKind::Logic, "load" => HandlerKind::Load, "store" => HandlerKind::Store, "control_flow" => HandlerKind::ControlFlow, "stack_op" => HandlerKind::StackOp, "compare" => HandlerKind::Compare, _ => HandlerKind::Unknown }; VmHandler::new(i as u32, Address::new(0), vec![i as u8], k, "", 0, 0) }).collect(); let clusters = HandlerClusterer::new().cluster(&handlers); let out: Vec<_> = clusters.iter().map(|c| json!({"label": c.label, "size": c.size(), "avg_entropy": c.avg_entropy})).collect(); Ok(ToolResult::text(json!({"clusters": out, "total": clusters.len()}).to_string())) } }

pub struct DeobfVmArchSummaryTool;
impl DeobfVmArchSummaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_arch_summary".to_string(), description: "VmArch::summary() for stack+register machines.".to_string(), input_schema: json!({"type":"object","required":["opcode_count"],"properties":{"opcode_count":{"type":"integer"},"register_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmArchSummaryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let oc = args.get("opcode_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'opcode_count'".into()))? as usize; let rc = args.get("register_count").and_then(Value::as_u64).unwrap_or(8) as u32; let s = rustre_deobf_vm::VmArch::stack_machine(oc); let r = rustre_deobf_vm::VmArch::register_machine(rc, oc); Ok(ToolResult::text(json!({"stack": s.summary(), "register": r.summary()}).to_string())) } }

pub struct DeobfVmProtectorDetectTool;
impl DeobfVmProtectorDetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_protector_detect".to_string(), description: "Run VmProtectorDetector::detect on PE bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmProtectorDetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let det = rustre_deobf_vm::VmProtectorDetector::detect(&dvm_hex_to_bytes(hex)?); let out: Vec<_> = det.iter().map(|d| json!({"name": d.protector_name, "confidence": d.confidence, "evidence": d.evidence.len()})).collect(); Ok(ToolResult::text(json!({"count": det.len(), "detections": out}).to_string())) } }

pub struct DeobfVmProtectorSectionsTool;
impl DeobfVmProtectorSectionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_protector_sections".to_string(), description: "VmProtectorDetector::get_section_names for PE bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmProtectorSectionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let names = rustre_deobf_vm::VmProtectorDetector::get_section_names(&dvm_hex_to_bytes(hex)?); Ok(ToolResult::text(json!({"count": names.len(), "names": names}).to_string())) } }

pub struct DeobfVmBytecodeRegionsTool;
impl DeobfVmBytecodeRegionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_bytecode_regions".to_string(), description: "VmBytecodeExtractor::find_bytecode_regions + estimate_opcode_count.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmBytecodeRegionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let bytes = dvm_hex_to_bytes(hex)?; let regions = rustre_deobf_vm::VmBytecodeExtractor::find_bytecode_regions(&bytes); let est = rustre_deobf_vm::VmBytecodeExtractor::estimate_opcode_count(&bytes); let out: Vec<_> = regions.iter().take(16).map(|r| json!({"offset": r.offset, "size": r.size, "entropy": r.entropy, "handlers": r.likely_handler_count})).collect(); Ok(ToolResult::text(json!({"count": regions.len(), "estimated_opcodes": est, "sample": out}).to_string())) } }

pub struct DeobfVmDeobfPipelineAnalyzeTool;
impl DeobfVmDeobfPipelineAnalyzeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_vm_deobf_pipeline_analyze".to_string(), description: "Run VmDeobfPipeline::analyze and return recommendations.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfVmDeobfPipelineAnalyzeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("hex".into()))?; let rep = rustre_deobf_vm::VmDeobfPipeline::analyze(&dvm_hex_to_bytes(hex)?); Ok(ToolResult::text(json!({"detections": rep.detections.len(), "bytecode_regions": rep.bytecode_regions.len(), "estimated_isa_size": rep.estimated_isa_size, "notes": rep.analysis_notes.len(), "recommendations": rep.recommendations()}).to_string())) } }

pub struct DeobfStringRc4InverseKsaV3Tool;
impl DeobfStringRc4InverseKsaV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_rc4_inverse_ksa_v3".to_string(), description: "Attempt to invert RC4 KSA from final S-box (256 bytes). Returns candidate keys.".to_string(), input_schema: json!({ "type":"object", "properties": { "s_final": {"type":"array"} }, "required":["s_final"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringRc4InverseKsaV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("s_final").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 's_final'".into()))?; if arr.len() != 256 { return Err(McpError::InvalidParams("s_final must be 256 bytes".into())); } let mut s = [0u8; 256]; for (i, v) in arr.iter().enumerate() { s[i] = v.as_u64().unwrap_or(0) as u8; } let keys = rustre_deobf_string::rc4_inverse_ksa(&s); Ok(ToolResult::text(json!({ "candidate_count": keys.len(), "source": "rustre_deobf_string::rc4_inverse_ksa" }).to_string())) } }

pub struct DeobfStringDecodeBase64CustomV3Tool;
impl DeobfStringDecodeBase64CustomV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_decode_base64_custom_v3".to_string(), description: "Decode base64 with a custom 64-char alphabet.".to_string(), input_schema: json!({ "type":"object", "properties": { "input_hex": {"type":"string"}, "alphabet": {"type":"string"} }, "required":["input_hex","alphabet"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDecodeBase64CustomV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let input_hex = args.get("input_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'input_hex'".into()))?; let alpha = args.get("alphabet").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'alphabet'".into()))?; if alpha.as_bytes().len() != 64 { return Err(McpError::InvalidParams("alphabet must be 64 bytes".into())); } let input = crate::hex_decode(input_hex)?; let mut ab = [0u8; 64]; ab.copy_from_slice(alpha.as_bytes()); let out = rustre_deobf_string::decode_base64_custom(&input, &ab).map_err(|e| McpError::InternalError(format!("{e}")))?; Ok(ToolResult::text(json!({ "decoded_hex": hex_encode(&out), "len": out.len(), "source": "rustre_deobf_string::decode_base64_custom" }).to_string())) } }

pub struct DeobfStringDetectRc4KsaMlilV3Tool;
impl DeobfStringDetectRc4KsaMlilV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_detect_rc4_ksa_mlil_v3".to_string(), description: "Detect RC4 KSA loop in a MLIL instruction stream (empty stream returns none).".to_string(), input_schema: json!({ "type":"object", "properties": {} }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDetectRc4KsaMlilV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let out = rustre_deobf_string::detect_rc4_ksa_in_mlil(&insts); Ok(ToolResult::text(json!({ "patterns": out.len(), "source": "rustre_deobf_string::detect_rc4_ksa_in_mlil" }).to_string())) } }

pub struct DeobfStringDetectArithObfMlilV3Tool;
impl DeobfStringDetectArithObfMlilV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_detect_arith_obf_mlil_v3".to_string(), description: "Detect ADD/SUB/ROL/ROR/XOR-constant deobfuscation via MLIL scan + brute force.".to_string(), input_schema: json!({ "type":"object", "properties": { "ciphertext_hex": {"type":"string"} }, "required":["ciphertext_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDetectArithObfMlilV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("ciphertext_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ciphertext_hex'".into()))?)?; let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let out = rustre_deobf_string::detect_arith_obf_in_mlil(&insts, &data); let top = out.first().map(|r| json!({ "obf_type": format!("{:?}", r.obf_type), "constant": r.constant, "confidence": r.confidence })); Ok(ToolResult::text(json!({ "count": out.len(), "top": top, "source": "rustre_deobf_string::detect_arith_obf_in_mlil" }).to_string())) } }

pub struct DeobfStringDetectMlilStackStringsV3Tool;
impl DeobfStringDetectMlilStackStringsV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_detect_mlil_stack_strings_v3".to_string(), description: "Reconstruct stack strings from consecutive byte-store instructions in MLIL.".to_string(), input_schema: json!({ "type":"object", "properties": {} }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDetectMlilStackStringsV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let out = rustre_deobf_string::detect_mlil_stack_strings(&insts); Ok(ToolResult::text(json!({ "count": out.len(), "source": "rustre_deobf_string::detect_mlil_stack_strings" }).to_string())) } }

pub struct DeobfStringDetectDecoderHelpersV3Tool;
impl DeobfStringDetectDecoderHelpersV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_detect_decoder_helpers_v3".to_string(), description: "Detect string-decoder helper functions from MLIL (XOR + memory ops, RC4 loops).".to_string(), input_schema: json!({ "type":"object", "properties": { "func_addr": {"type":"integer"} }, "required":["func_addr"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDetectDecoderHelpersV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let fa = args.get("func_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'func_addr'".into()))?; let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let out = rustre_deobf_string::detect_string_decoder_helpers(fa, &insts); Ok(ToolResult::text(json!({ "func_addr": fa, "count": out.len(), "source": "rustre_deobf_string::detect_string_decoder_helpers" }).to_string())) } }

pub struct DeobfStringRecoverStackStringsV3Tool;
impl DeobfStringRecoverStackStringsV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_recover_stack_strings_v3".to_string(), description: "Recover ASCII stack strings from consecutive char stores in MLIL.".to_string(), input_schema: json!({ "type":"object", "properties": {} }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringRecoverStackStringsV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let out = rustre_deobf_string::recover_stack_strings(&insts); Ok(ToolResult::text(json!({ "count": out.len(), "source": "rustre_deobf_string::recover_stack_strings" }).to_string())) } }

pub struct DeobfStringDetectXorEncryptionV3Tool;
impl DeobfStringDetectXorEncryptionV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_detect_xor_encryption_v3".to_string(), description: "Detect presence of XOR-based encryption pattern in MLIL instructions.".to_string(), input_schema: json!({ "type":"object", "properties": {} }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringDetectXorEncryptionV3Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let insts: Vec<rustre_il_llil::LlilInstruction> = Vec::new(); let flag = rustre_deobf_string::detect_xor_encryption(&insts); Ok(ToolResult::text(json!({ "has_xor": flag, "source": "rustre_deobf_string::detect_xor_encryption" }).to_string())) } }

pub struct DeobfStringAsmDetectStackStringsV3Tool;
impl DeobfStringAsmDetectStackStringsV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_asm_detect_stack_strings_v3".to_string(), description: "ASM-level stack-string detection from (addr, mnemonic, operands) triples.".to_string(), input_schema: json!({ "type":"object", "properties": { "instrs": {"type":"array"} } }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringAsmDetectStackStringsV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("instrs").and_then(Value::as_array).cloned().unwrap_or_default(); let insts: Vec<(u64, String, String)> = arr.iter().filter_map(|v| { let a = v.get("addr")?.as_u64()?; let m = v.get("mnem")?.as_str()?.to_string(); let o = v.get("ops")?.as_str()?.to_string(); Some((a, m, o)) }).collect(); let out = rustre_deobf_string::detect_stack_strings(&insts); Ok(ToolResult::text(json!({ "count": out.len(), "source": "rustre_deobf_string::detect_stack_strings" }).to_string())) } }

pub struct DeobfStringXorKeyApplyV3Tool;
impl DeobfStringXorKeyApplyV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_xor_key_apply_v3".to_string(), description: "Apply a rolling XOR key to input bytes via XorKey::apply.".to_string(), input_schema: json!({ "type":"object", "properties": { "data_hex": {"type":"string"}, "key_hex": {"type":"string"} }, "required":["data_hex","key_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringXorKeyApplyV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let key = crate::hex_decode(args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key_hex'".into()))?)?; let k = rustre_deobf_string::xor_string_decoder::XorKey::multi(key); let out = k.apply(&data); Ok(ToolResult::text(json!({ "out_hex": hex_encode(&out), "len": out.len(), "source": "rustre_deobf_string::xor_string_decoder::XorKey::apply" }).to_string())) } }

pub struct DeobfStringScorePlaintextV3Tool;
impl DeobfStringScorePlaintextV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_score_plaintext_v3".to_string(), description: "Score buffer plausibility as printable/text plaintext.".to_string(), input_schema: json!({ "type":"object", "properties": { "data_hex": {"type":"string"} }, "required":["data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringScorePlaintextV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let s = rustre_deobf_string::xor_string_decoder::score_plaintext(&data); Ok(ToolResult::text(json!({ "score": s, "source": "rustre_deobf_string::xor_string_decoder::score_plaintext" }).to_string())) } }

pub struct DeobfStringToDisplayStringV3Tool;
impl DeobfStringToDisplayStringV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_to_display_string_v3".to_string(), description: "Convert raw bytes to a printable display string (control chars escaped).".to_string(), input_schema: json!({ "type":"object", "properties": { "data_hex": {"type":"string"} }, "required":["data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringToDisplayStringV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let s = rustre_deobf_string::xor_string_decoder::to_display_string(&data); Ok(ToolResult::text(json!({ "display": s, "source": "rustre_deobf_string::xor_string_decoder::to_display_string" }).to_string())) } }

pub struct DeobfStringUtfDetectAnomaliesV3Tool;
impl DeobfStringUtfDetectAnomaliesV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_utf_detect_anomalies_v3".to_string(), description: "Detect UTF-8 anomalies (overlong encodings, invalid sequences, control chars).".to_string(), input_schema: json!({ "type":"object", "properties": { "data_hex": {"type":"string"} }, "required":["data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringUtfDetectAnomaliesV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let out = rustre_deobf_string::unicode_deobf::UtfDeobf::detect_anomalies(&data); Ok(ToolResult::text(json!({ "count": out.len(), "source": "rustre_deobf_string::unicode_deobf::UtfDeobf::detect_anomalies" }).to_string())) } }

pub struct DeobfStringHasModifiedUtf8NullV3Tool;
impl DeobfStringHasModifiedUtf8NullV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_string_has_modified_utf8_null_v3".to_string(), description: "Detect the C0 80 modified-UTF-8 encoding of NUL (Java/Dalvik convention).".to_string(), input_schema: json!({ "type":"object", "properties": { "data_hex": {"type":"string"} }, "required":["data_hex"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DeobfStringHasModifiedUtf8NullV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::hex_decode(args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?; let flag = rustre_deobf_string::unicode_deobf::UtfDeobf::has_modified_utf8_null(&data); Ok(ToolResult::text(json!({ "has": flag, "source": "rustre_deobf_string::unicode_deobf::UtfDeobf::has_modified_utf8_null" }).to_string())) } }

pub struct DeobfSmcRegionLenIsEmptyTool;
impl DeobfSmcRegionLenIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_region_len_is_empty".to_string(), description: "SmcRegion::len/is_empty via rustre_deobf_smc::SmcRegion.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcRegionLenIsEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let r = rustre_deobf_smc::SmcRegion { start, end, decryptor_addr: 0, key: rustre_deobf_smc::SmcKey::Constant(0), algorithm: rustre_deobf_smc::SmcAlgorithm::Xor }; Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"source":"rustre_deobf_smc::SmcRegion::len"}).to_string())) } }

pub struct DeobfSmcDecryptorDecryptTool;
impl DeobfSmcDecryptorDecryptTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_decryptor_decrypt".to_string(), description: "Decrypt bytes with a constant-key SmcRegion via rustre_deobf_smc::SmcDecryptor::decrypt.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"key":{"type":"integer"},"algorithm":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcDecryptorDecryptTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let key = args.get("key").and_then(Value::as_u64).unwrap_or(0); let algo = match args.get("algorithm").and_then(Value::as_str).unwrap_or("xor") { "add" => rustre_deobf_smc::SmcAlgorithm::Add, "sub" => rustre_deobf_smc::SmcAlgorithm::Sub, "rol" => rustre_deobf_smc::SmcAlgorithm::Rol, "ror" => rustre_deobf_smc::SmcAlgorithm::Ror, "xor_rolling" => rustre_deobf_smc::SmcAlgorithm::XorRolling, "add_rolling" => rustre_deobf_smc::SmcAlgorithm::AddRolling, _ => rustre_deobf_smc::SmcAlgorithm::Xor }; let region = rustre_deobf_smc::SmcRegion { start: 0, end: data.len() as u64, decryptor_addr: 0, key: rustre_deobf_smc::SmcKey::Constant(key), algorithm: algo }; let out = rustre_deobf_smc::SmcDecryptor::new().decrypt(&data, &region); let hex_out: String = out.iter().map(|b| format!("{:02x}", b)).collect(); Ok(ToolResult::text(json!({"out_hex":hex_out,"len":out.len(),"source":"rustre_deobf_smc::SmcDecryptor::decrypt"}).to_string())) } }

pub struct DeobfSmcLayeredDecryptAllTool;
impl DeobfSmcLayeredDecryptAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_layered_decrypt_all".to_string(), description: "Iteratively strip SMC layers via rustre_deobf_smc::LayeredSmc::decrypt_all.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"max_layers":{"type":"integer"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcLayeredDecryptAllTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let max_layers = usize::try_from(args.get("max_layers").and_then(Value::as_u64).unwrap_or(8)).unwrap_or(8); let (out, layers) = rustre_deobf_smc::LayeredSmc::new(max_layers).decrypt_all(&data); Ok(ToolResult::text(json!({"layers":layers,"len":out.len(),"source":"rustre_deobf_smc::LayeredSmc::decrypt_all"}).to_string())) } }

pub struct DeobfSmcEmulatedTraceTool;
impl DeobfSmcEmulatedTraceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_emulated_trace".to_string(), description: "Trace a decryption loop via rustre_deobf_smc::EmulatedDecrypt::trace.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"max_iter":{"type":"integer"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcEmulatedTraceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let max_iter = usize::try_from(args.get("max_iter").and_then(Value::as_u64).unwrap_or(64)).unwrap_or(64); let t = rustre_deobf_smc::EmulatedDecrypt::new().trace(&data, max_iter); Ok(ToolResult::text(json!({"recovered_key":t.recovered_key,"algorithm":format!("{:?}",t.algorithm),"iterations":t.iterations,"source":"rustre_deobf_smc::EmulatedDecrypt::trace"}).to_string())) } }

pub struct DeobfSmcEmuRegistersRwTool;
impl DeobfSmcEmuRegistersRwTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_emu_registers_rw".to_string(), description: "Write then read register via rustre_deobf_smc::EmuRegisters::read/write.".to_string(), input_schema: json!({"type":"object","properties":{"reg":{"type":"integer"},"value":{"type":"integer"}},"required":["reg","value"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcEmuRegistersRwTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let reg = args.get("reg").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))? as u8; let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let mut r = rustre_deobf_smc::EmuRegisters::default(); r.write(reg, value); Ok(ToolResult::text(json!({"read":r.read(reg),"source":"rustre_deobf_smc::EmuRegisters::write"}).to_string())) } }

pub struct DeobfSmcDynamicDetectorEventsTool;
impl DeobfSmcDynamicDetectorEventsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_dynamic_detector_events".to_string(), description: "Record writes and check SMC exec via rustre_deobf_smc::DynamicSmcDetector.".to_string(), input_schema: json!({"type":"object","properties":{"writes":{"type":"array","items":{"type":"object"}},"exec_pc":{"type":"integer"}},"required":["writes","exec_pc"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcDynamicDetectorEventsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut d = rustre_deobf_smc::DynamicSmcDetector::new(); if let Some(arr) = args.get("writes").and_then(Value::as_array) { for w in arr { let pc = w.get("pc").and_then(Value::as_u64).unwrap_or(0); let addr = w.get("addr").and_then(Value::as_u64).unwrap_or(0); let val = w.get("value").and_then(Value::as_u64).unwrap_or(0) as u8; d.add_write(pc, addr, val); } } let exec_pc = args.get("exec_pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'exec_pc'".into()))?; Ok(ToolResult::text(json!({"events":d.events().len(),"is_smc_execution":d.is_smc_execution(exec_pc),"memory_map_size":d.to_memory_map().len(),"source":"rustre_deobf_smc::DynamicSmcDetector"}).to_string())) } }

pub struct DeobfSmcReconstructorReconstructTool;
impl DeobfSmcReconstructorReconstructTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_reconstructor_reconstruct".to_string(), description: "Overlay dynamic writes on original bytes via rustre_deobf_smc::DynamicSmcReconstructor::reconstruct.".to_string(), input_schema: json!({"type":"object","properties":{"base_addr":{"type":"integer"},"original_hex":{"type":"string"},"writes":{"type":"array","items":{"type":"object"}}},"required":["base_addr","original_hex","writes"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcReconstructorReconstructTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base_addr'".into()))?; let s: String = args.get("original_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'original_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let orig: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let mut d = rustre_deobf_smc::DynamicSmcDetector::new(); if let Some(arr) = args.get("writes").and_then(Value::as_array) { for w in arr { let pc = w.get("pc").and_then(Value::as_u64).unwrap_or(0); let addr = w.get("addr").and_then(Value::as_u64).unwrap_or(0); let val = w.get("value").and_then(Value::as_u64).unwrap_or(0) as u8; d.add_write(pc, addr, val); } } let rec = rustre_deobf_smc::DynamicSmcReconstructor::from_detector(&d); let out = rec.reconstruct(base, &orig); let hex_out: String = out.iter().map(|b| format!("{:02x}", b)).collect(); Ok(ToolResult::text(json!({"out_hex":hex_out,"len":out.len(),"source":"rustre_deobf_smc::DynamicSmcReconstructor::reconstruct"}).to_string())) } }

pub struct DeobfSmcPolymorphicAnalyzeDiffTool;
impl DeobfSmcPolymorphicAnalyzeDiffTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_polymorphic_analyze_diff".to_string(), description: "Compare two snapshots via rustre_deobf_smc::PolymorphicEngineAnalyzer::analyze.".to_string(), input_schema: json!({"type":"object","properties":{"before_hex":{"type":"string"},"after_hex":{"type":"string"}},"required":["before_hex","after_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcPolymorphicAnalyzeDiffTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a: String = args.get("before_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'before_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let before: Vec<u8> = (0..a.len()).step_by(2).filter_map(|i| u8::from_str_radix(a.get(i..i+2)?, 16).ok()).collect(); let b: String = args.get("after_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'after_hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let after: Vec<u8> = (0..b.len()).step_by(2).filter_map(|i| u8::from_str_radix(b.get(i..i+2)?, 16).ok()).collect(); let events = rustre_deobf_smc::PolymorphicEngineAnalyzer::new().analyze(&before, &after); Ok(ToolResult::text(json!({"count":events.len(),"kinds":events.iter().map(|e| format!("{:?}",e.kind)).collect::<Vec<_>>(),"source":"rustre_deobf_smc::PolymorphicEngineAnalyzer::analyze"}).to_string())) } }

pub struct DeobfSmcCodeMutationTrackerTool;
impl DeobfSmcCodeMutationTrackerTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_code_mutation_tracker".to_string(), description: "Track successive snapshots and count mutations via rustre_deobf_smc::CodeMutationTracker.".to_string(), input_schema: json!({"type":"object","properties":{"snapshots_hex":{"type":"array","items":{"type":"string"}}},"required":["snapshots_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcCodeMutationTrackerTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("snapshots_hex").and_then(Value::as_array).cloned().unwrap_or_default(); let to_bytes = |hs: &str| -> Vec<u8> { let s: String = hs.chars().filter(|c| !c.is_whitespace()).collect(); (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect() }; let mut iter = arr.iter().filter_map(|v| v.as_str()); let initial = iter.next().map(to_bytes).unwrap_or_default(); let mut t = rustre_deobf_smc::CodeMutationTracker::new(initial); for hs in iter { t.add_snapshot(to_bytes(hs)); } let counts = t.count_by_type(); Ok(ToolResult::text(json!({"generations":t.generation_count(),"total_mutations":t.all_mutations().len(),"by_type":counts,"source":"rustre_deobf_smc::CodeMutationTracker"}).to_string())) } }

pub struct DeobfSmcUnpackedRegionDetectorTool;
impl DeobfSmcUnpackedRegionDetectorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_unpacked_region_detector".to_string(), description: "Detect low-entropy unpacked regions via rustre_deobf_smc::UnpackedRegionDetector::detect.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"window_size":{"type":"integer"},"entropy_threshold":{"type":"number"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcUnpackedRegionDetectorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let ws = usize::try_from(args.get("window_size").and_then(Value::as_u64).unwrap_or(256)).unwrap_or(256); let thr = args.get("entropy_threshold").and_then(Value::as_f64).unwrap_or(6.0); let regions = rustre_deobf_smc::UnpackedRegionDetector::new(ws, thr).detect(&data); let summary: Vec<Value> = regions.iter().map(|r| json!({"start":r.start,"end":r.end,"entropy":r.entropy,"looks_like_code":r.looks_like_code})).collect(); Ok(ToolResult::text(json!({"count":summary.len(),"regions":summary,"source":"rustre_deobf_smc::UnpackedRegionDetector::detect"}).to_string())) } }

pub struct DeobfSmcXorChainEncryptTool;
impl DeobfSmcXorChainEncryptTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_xor_chain_encrypt".to_string(), description: "Encrypt bytes with a multi-round XorChain via rustre_deobf_smc::XorChain::encrypt.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"steps":{"type":"array","items":{"type":"object"}}},"required":["hex","steps"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcXorChainEncryptTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let mut chain = rustre_deobf_smc::XorChain::new(); if let Some(arr) = args.get("steps").and_then(Value::as_array) { for st in arr { chain.push(rustre_deobf_smc::XorChainStep { key: st.get("key").and_then(Value::as_u64).unwrap_or(0) as u8, pre_op: st.get("pre_op").and_then(Value::as_u64).unwrap_or(0) as u8, rot_amount: st.get("rot_amount").and_then(Value::as_u64).unwrap_or(0) as u8 }); } } let out = chain.encrypt(&data); let hex_out: String = out.iter().map(|b| format!("{:02x}", b)).collect(); Ok(ToolResult::text(json!({"out_hex":hex_out,"steps":chain.len(),"is_empty":chain.is_empty(),"source":"rustre_deobf_smc::XorChain::encrypt"}).to_string())) } }

pub struct DeobfSmcStatsFromRegionsTool;
impl DeobfSmcStatsFromRegionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "deobf_smc_stats_from_regions".to_string(), description: "Aggregate stats via rustre_deobf_smc::SmcStats::from_regions after detection.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DeobfSmcStatsFromRegionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?.chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let regions = rustre_deobf_smc::SmcDetector::new().detect(&data); let stats = rustre_deobf_smc::SmcStats::from_regions(&regions); Ok(ToolResult::text(json!({"regions_detected":stats.regions_detected,"regions_decrypted":stats.regions_decrypted,"bytes_decrypted":stats.bytes_decrypted,"xor_count":stats.xor_count,"add_count":stats.add_count,"rol_count":stats.rol_count,"rolling_count":stats.rolling_count,"derived_key_count":stats.derived_key_count,"source":"rustre_deobf_smc::XorChain::encrypt"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DeobfCrc32ChecksumTool::definition(), Box::new(DeobfCrc32ChecksumTool)),
        (DeobfCrc32ChecksumTableTool::definition(), Box::new(DeobfCrc32ChecksumTableTool)),
        (DeobfRc4DecryptTool::definition(), Box::new(DeobfRc4DecryptTool)),
        (DeobfRc4KsaTool::definition(), Box::new(DeobfRc4KsaTool)),
        (DeobfXorDecryptConstantTool::definition(), Box::new(DeobfXorDecryptConstantTool)),
        (DeobfXorDecryptCyclicTool::definition(), Box::new(DeobfXorDecryptCyclicTool)),
        (DeobfXorDecryptRollingTool::definition(), Box::new(DeobfXorDecryptRollingTool)),
        (DeobfXorRecoverSingleByteKeyTool::definition(), Box::new(DeobfXorRecoverSingleByteKeyTool)),
        (DeobfRolrorDecryptRolTool::definition(), Box::new(DeobfRolrorDecryptRolTool)),
        (DeobfRolrorDecryptRorTool::definition(), Box::new(DeobfRolrorDecryptRorTool)),
        (DeobfRolrorRecoverRotationTool::definition(), Box::new(DeobfRolrorRecoverRotationTool)),
        (DeobfBase64DecodeTool::definition(), Box::new(DeobfBase64DecodeTool)),
        (DeobfBase64FindAllTool::definition(), Box::new(DeobfBase64FindAllTool)),
        (DeobfEntropyScannerScanTool::definition(), Box::new(DeobfEntropyScannerScanTool)),
        (DeobfStringXorBruteforceTop3Tool::definition(), Box::new(DeobfStringXorBruteforceTop3Tool)),
        (DeobfStringComputeConfidenceTool::definition(), Box::new(DeobfStringComputeConfidenceTool)),
        (DeobfStringCaesarBruteforceTool::definition(), Box::new(DeobfStringCaesarBruteforceTool)),
        (DeobfStringDetectBase64VariantTool::definition(), Box::new(DeobfStringDetectBase64VariantTool)),
        (DeobfStringDetectXorKeyLengthIcTool::definition(), Box::new(DeobfStringDetectXorKeyLengthIcTool)),
        (DeobfVmReadU64LeTool::definition(), Box::new(DeobfVmReadU64LeTool)),
        (DeobfVmReadU32LeTool::definition(), Box::new(DeobfVmReadU32LeTool)),
        (DeobfVmReadU16LeTool::definition(), Box::new(DeobfVmReadU16LeTool)),
        (DeobfOpaqueKnownPatternsTool::definition(), Box::new(DeobfOpaqueKnownPatternsTool)),
        (DeobfOpaqueClassifyConstTool::definition(), Box::new(DeobfOpaqueClassifyConstTool)),
        (DeobfOpaqueTruthTableDefaultsTool::definition(), Box::new(DeobfOpaqueTruthTableDefaultsTool)),
        (DeobfXorEntropyTool::definition(), Box::new(DeobfXorEntropyTool)),
        (DeobfAdler32Tool::definition(), Box::new(DeobfAdler32Tool)),
        (DeobfCrc32Tool::definition(), Box::new(DeobfCrc32Tool)),
        (DeobfSmcShannonEntropyTool::definition(), Box::new(DeobfSmcShannonEntropyTool)),
        (DeobfSmcLooksLikeCodeTool::definition(), Box::new(DeobfSmcLooksLikeCodeTool)),
        (DeobfSmcDetectTool::definition(), Box::new(DeobfSmcDetectTool)),
        (DeobfSmcDetectIndicatorsTool::definition(), Box::new(DeobfSmcDetectIndicatorsTool)),
        (DeobfSmcXorChainDetectTool::definition(), Box::new(DeobfSmcXorChainDetectTool)),
        (DeobfSmcAddRolEncryptTool::definition(), Box::new(DeobfSmcAddRolEncryptTool)),
        (DeobfSmcAddRolDecryptTool::definition(), Box::new(DeobfSmcAddRolDecryptTool)),
        (DeobfSmcStatsFromBytesTool::definition(), Box::new(DeobfSmcStatsFromBytesTool)),
        (DeobfSmcUnpackedRegionsTool::definition(), Box::new(DeobfSmcUnpackedRegionsTool)),
        (DeobfSmcPolymorphicAnalyzeTool::definition(), Box::new(DeobfSmcPolymorphicAnalyzeTool)),
        (DeobfSmcMockTraceTool::definition(), Box::new(DeobfSmcMockTraceTool)),
        (DeobfSmcXorStepApplyTool::definition(), Box::new(DeobfSmcXorStepApplyTool)),
        (DeobfSmcXorStepReverseTool::definition(), Box::new(DeobfSmcXorStepReverseTool)),
        (DeobfSmcWriteExecDetectTool::definition(), Box::new(DeobfSmcWriteExecDetectTool)),
        (DeobfSmcXorChainDecryptTool::definition(), Box::new(DeobfSmcXorChainDecryptTool)),
        (DeobfStringRecoverMultibyteXorTool::definition(), Box::new(DeobfStringRecoverMultibyteXorTool)),
        (DeobfStringDecodeBase64UrlsafeTool::definition(), Box::new(DeobfStringDecodeBase64UrlsafeTool)),
        (DeobfStringRot13Tool::definition(), Box::new(DeobfStringRot13Tool)),
        (DeobfStringRotnDetectTool::definition(), Box::new(DeobfStringRotnDetectTool)),
        (DeobfStringXorDecryptConstantTool::definition(), Box::new(DeobfStringXorDecryptConstantTool)),
        (DeobfStringXorDecryptCyclicTool::definition(), Box::new(DeobfStringXorDecryptCyclicTool)),
        (DeobfStringXorRecoverKeyTool::definition(), Box::new(DeobfStringXorRecoverKeyTool)),
        (DeobfStringXorDetectKeyPeriodTool::definition(), Box::new(DeobfStringXorDetectKeyPeriodTool)),
        (DeobfStringRc4DecryptTool::definition(), Box::new(DeobfStringRc4DecryptTool)),
        (DeobfStringBase64EncodeTool::definition(), Box::new(DeobfStringBase64EncodeTool)),
        (DeobfStringHexDecodeTool::definition(), Box::new(DeobfStringHexDecodeTool)),
        (DeobfVmDetectDispatcherTool::definition(), Box::new(DeobfVmDetectDispatcherTool)),
        (DeobfVmDetectorAnalyzeTool::definition(), Box::new(DeobfVmDetectorAnalyzeTool)),
        (DeobfVmBytecodeNewTool::definition(), Box::new(DeobfVmBytecodeNewTool)),
        (DeobfVmLifterLiftTool::definition(), Box::new(DeobfVmLifterLiftTool)),
        (DeobfVmSemanticOpStackDeltaTool::definition(), Box::new(DeobfVmSemanticOpStackDeltaTool)),
        (DeobfVmArchStackMachineTool::definition(), Box::new(DeobfVmArchStackMachineTool)),
        (DeobfVmArchRegisterMachineTool::definition(), Box::new(DeobfVmArchRegisterMachineTool)),
        (DeobfVmStateSimulateTool::definition(), Box::new(DeobfVmStateSimulateTool)),
        (DeobfVmHandlerPrologueEntropyTool::definition(), Box::new(DeobfVmHandlerPrologueEntropyTool)),
        (DeobfVmDeprotectSimpleTool::definition(), Box::new(DeobfVmDeprotectSimpleTool)),
        (DeobfVmPcodeVarnodeSizeTool::definition(), Box::new(DeobfVmPcodeVarnodeSizeTool)),
        (DeobfVmStateNewProbeTool::definition(), Box::new(DeobfVmStateNewProbeTool)),
        (DeobfVmStateMemRoundtripTool::definition(), Box::new(DeobfVmStateMemRoundtripTool)),
        (DeobfVmStateFlagsTool::definition(), Box::new(DeobfVmStateFlagsTool)),
        (DeobfVmDispatcherDetectorProbeTool::definition(), Box::new(DeobfVmDispatcherDetectorProbeTool)),
        (DeobfVmHandlerClassifyTool::definition(), Box::new(DeobfVmHandlerClassifyTool)),
        (DeobfVmBytecodeInspectTool::definition(), Box::new(DeobfVmBytecodeInspectTool)),
        (DeobfVmLifterRemapTool::definition(), Box::new(DeobfVmLifterRemapTool)),
        (DeobfVmHandlerClusterTool::definition(), Box::new(DeobfVmHandlerClusterTool)),
        (DeobfVmArchSummaryTool::definition(), Box::new(DeobfVmArchSummaryTool)),
        (DeobfVmProtectorDetectTool::definition(), Box::new(DeobfVmProtectorDetectTool)),
        (DeobfVmProtectorSectionsTool::definition(), Box::new(DeobfVmProtectorSectionsTool)),
        (DeobfVmBytecodeRegionsTool::definition(), Box::new(DeobfVmBytecodeRegionsTool)),
        (DeobfVmDeobfPipelineAnalyzeTool::definition(), Box::new(DeobfVmDeobfPipelineAnalyzeTool)),
        (DeobfStringRc4InverseKsaV3Tool::definition(), Box::new(DeobfStringRc4InverseKsaV3Tool)),
        (DeobfStringDecodeBase64CustomV3Tool::definition(), Box::new(DeobfStringDecodeBase64CustomV3Tool)),
        (DeobfStringDetectRc4KsaMlilV3Tool::definition(), Box::new(DeobfStringDetectRc4KsaMlilV3Tool)),
        (DeobfStringDetectArithObfMlilV3Tool::definition(), Box::new(DeobfStringDetectArithObfMlilV3Tool)),
        (DeobfStringDetectMlilStackStringsV3Tool::definition(), Box::new(DeobfStringDetectMlilStackStringsV3Tool)),
        (DeobfStringDetectDecoderHelpersV3Tool::definition(), Box::new(DeobfStringDetectDecoderHelpersV3Tool)),
        (DeobfStringRecoverStackStringsV3Tool::definition(), Box::new(DeobfStringRecoverStackStringsV3Tool)),
        (DeobfStringDetectXorEncryptionV3Tool::definition(), Box::new(DeobfStringDetectXorEncryptionV3Tool)),
        (DeobfStringAsmDetectStackStringsV3Tool::definition(), Box::new(DeobfStringAsmDetectStackStringsV3Tool)),
        (DeobfStringXorKeyApplyV3Tool::definition(), Box::new(DeobfStringXorKeyApplyV3Tool)),
        (DeobfStringScorePlaintextV3Tool::definition(), Box::new(DeobfStringScorePlaintextV3Tool)),
        (DeobfStringToDisplayStringV3Tool::definition(), Box::new(DeobfStringToDisplayStringV3Tool)),
        (DeobfStringUtfDetectAnomaliesV3Tool::definition(), Box::new(DeobfStringUtfDetectAnomaliesV3Tool)),
        (DeobfStringHasModifiedUtf8NullV3Tool::definition(), Box::new(DeobfStringHasModifiedUtf8NullV3Tool)),
        (DeobfSmcRegionLenIsEmptyTool::definition(), Box::new(DeobfSmcRegionLenIsEmptyTool)),
        (DeobfSmcDecryptorDecryptTool::definition(), Box::new(DeobfSmcDecryptorDecryptTool)),
        (DeobfSmcLayeredDecryptAllTool::definition(), Box::new(DeobfSmcLayeredDecryptAllTool)),
        (DeobfSmcEmulatedTraceTool::definition(), Box::new(DeobfSmcEmulatedTraceTool)),
        (DeobfSmcEmuRegistersRwTool::definition(), Box::new(DeobfSmcEmuRegistersRwTool)),
        (DeobfSmcDynamicDetectorEventsTool::definition(), Box::new(DeobfSmcDynamicDetectorEventsTool)),
        (DeobfSmcReconstructorReconstructTool::definition(), Box::new(DeobfSmcReconstructorReconstructTool)),
        (DeobfSmcPolymorphicAnalyzeDiffTool::definition(), Box::new(DeobfSmcPolymorphicAnalyzeDiffTool)),
        (DeobfSmcCodeMutationTrackerTool::definition(), Box::new(DeobfSmcCodeMutationTrackerTool)),
        (DeobfSmcUnpackedRegionDetectorTool::definition(), Box::new(DeobfSmcUnpackedRegionDetectorTool)),
        (DeobfSmcXorChainEncryptTool::definition(), Box::new(DeobfSmcXorChainEncryptTool)),
        (DeobfSmcStatsFromRegionsTool::definition(), Box::new(DeobfSmcStatsFromRegionsTool)),
    ]
}

/// Compute Shannon entropy (bits/byte) of a payload using `rustre_deobf::XorDecryptor::entropy`.
pub struct DeobfXorEntropyToolV2;

impl DeobfXorEntropyToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_xor_entropy_v2".to_string(),
            description: "Shannon entropy of bytes via rustre_deobf::XorDecryptor::entropy."
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
impl ToolHandler for DeobfXorEntropyToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let entropy = rustre_deobf::XorDecryptor::entropy(&data);
        Ok(ToolResult::text(
            json!({
                "entropy": entropy,
                "bytes": data.len(),
                "source": "rustre_deobf::XorDecryptor::entropy",
            })
            .to_string(),
        ))
    }
}

/// Compute Adler-32 checksum using `rustre_deobf::Adler32::checksum`.
pub struct DeobfAdler32ChecksumToolV2;

impl DeobfAdler32ChecksumToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "deobf_adler32_checksum_v2".to_string(),
            description: "Adler-32 checksum of bytes via rustre_deobf::Adler32::checksum."
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
impl ToolHandler for DeobfAdler32ChecksumToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let checksum = rustre_deobf::Adler32::checksum(&data);
        Ok(ToolResult::text(
            json!({
                "adler32": checksum,
                "adler32_hex": format!("{checksum:08x}"),
                "bytes": data.len(),
                "source": "rustre_deobf::Adler32::checksum",
            })
            .to_string(),
        ))
    }
}
