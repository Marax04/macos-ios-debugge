//! MCP wrappers for the rustre-mobile_ipa crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{__ipa_hex_decode};

// ─────────────────────────────────────────────────────────────────────────────
// Real IPA loading
//
// ⚠ Why this exists. The eight `mobile_ipa_mock_*` tools below declared
// `input_schema: {"properties": {}}` — they accepted NO arguments — and each
// called `IpaPackage::mock()`, so every answer described a built-in reference
// image rather than any IPA a user has. `has_entitlements`, `targets_iphone`,
// `codesign_flags` and the rest were properties of a fixture, reported as if
// they were properties of an app.
//
// `path` is now REQUIRED. A tool that "works" by answering about a fixture is
// exactly the contract that lies, so it now fails instead. The reference image
// stays reachable behind an explicit opt-in that LABELS its output, because a
// fixture you asked for by name is not the same as one you were handed silently.
// ─────────────────────────────────────────────────────────────────────────────

/// Schema shared by every IPA-analysing tool.
fn ipa_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the .ipa file to analyse"},
            "use_reference_fixture": {"type": "boolean", "description": "Analyse the built-in reference IPA instead of a real file. The response is labelled `is_reference_fixture: true`."}
        },
        "required": ["path"]
    })
}

/// Parse the IPA named by `args["path"]`, or the reference image when the
/// caller explicitly asks for it.
///
/// Returns `(package, is_reference_fixture)` so every handler can label its
/// answer. Never silently substitutes the fixture for a real file.
///
/// # Errors
/// `InvalidParams` when neither `path` nor the explicit opt-in is given;
/// `ToolError` when the file cannot be read or is not a parsable IPA.
fn ipa_from_args(args: &Value) -> Result<(rustre_mobile_ipa::IpaPackage, bool), McpError> {
    if args.get("use_reference_fixture").and_then(Value::as_bool) == Some(true) {
        return Ok((rustre_mobile_ipa::IpaPackage::mock(), true));
    }
    let path = args.get("path").and_then(Value::as_str).ok_or_else(|| {
        McpError::InvalidParams(
            "'path' is required: the .ipa to analyse. Pass \"use_reference_fixture\": true              to inspect the built-in reference image instead."
                .to_string(),
        )
    })?;
    let bytes = std::fs::read(path)
        .map_err(|e| McpError::ToolError(format!("cannot read '{path}': {e}")))?;
    let pkg = rustre_mobile_ipa::IpaPackage::parse(&bytes)
        .map_err(|e| McpError::ToolError(format!("'{path}' is not a parsable IPA: {e}")))?;
    Ok((pkg, false))
}


pub struct MobileIpaIsBinaryPlistTool;

pub struct MobileIpaMockPackageTool;

pub struct MobileIpaPlistIsBinaryTool;

pub struct MobileIpaMockSummaryTool;

pub struct MobileIpaMockHasEntitlementsTool;
impl MobileIpaMockHasEntitlementsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_has_entitlements".to_string(), description: "InfoPlist::has_entitlements on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockHasEntitlementsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; Ok(ToolResult::text(json!({"has_entitlements":p.info_plist.has_entitlements(),"source":"rustre_mobile_ipa::InfoPlist::has_entitlements","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockParsedMinOsTool;
impl MobileIpaMockParsedMinOsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_parsed_min_os".to_string(), description: "InfoPlist::parsed_min_os on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockParsedMinOsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; Ok(ToolResult::text(json!({"min_os":p.info_plist.parsed_min_os(),"source":"rustre_mobile_ipa::InfoPlist::parsed_min_os","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockTargetsIphoneTool;
impl MobileIpaMockTargetsIphoneTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_targets_iphone".to_string(), description: "InfoPlist::targets_iphone on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockTargetsIphoneTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; Ok(ToolResult::text(json!({"targets_iphone":p.info_plist.targets_iphone(),"source":"rustre_mobile_ipa::InfoPlist::targets_iphone","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockCodesignFlagsTool;
impl MobileIpaMockCodesignFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_codesign_flags".to_string(), description: "CodeSignature developer/enterprise/adhoc flags on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockCodesignFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; let cs = p.code_signature.as_ref(); Ok(ToolResult::text(json!({"is_developer_signed":cs.map(rustre_mobile_ipa::CodeSignature::is_developer_signed),"is_enterprise":cs.map(rustre_mobile_ipa::CodeSignature::is_enterprise),"is_adhoc":cs.map(rustre_mobile_ipa::CodeSignature::is_adhoc),"source":"rustre_mobile_ipa::CodeSignature","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockLeafCertAppleTool;
impl MobileIpaMockLeafCertAppleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_leaf_cert_apple".to_string(), description: "CodeSignature::leaf_cert + CertInfo::is_apple_issued on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockLeafCertAppleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; let leaf = p.code_signature.as_ref().and_then(rustre_mobile_ipa::CodeSignature::leaf_cert); Ok(ToolResult::text(json!({"apple_issued":leaf.map(rustre_mobile_ipa::CertInfo::is_apple_issued),"subject":leaf.map(|c|c.subject.clone()),"source":"rustre_mobile_ipa::CertInfo::is_apple_issued","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockBinaryEntriesTool;
impl MobileIpaMockBinaryEntriesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_binary_entries".to_string(), description: "IpaPackage::binary_entries on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockBinaryEntriesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; let paths: Vec<String> = p.binary_entries().iter().map(|e|e.path.clone()).collect(); Ok(ToolResult::text(json!({"binary_paths":paths,"count":p.binary_entries().len(),"source":"rustre_mobile_ipa::IpaPackage::binary_entries","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaMockEntryCountsTool;
impl MobileIpaMockEntryCountsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_mock_entry_counts".to_string(), description: "IpaPackage::entry_count + framework_count on mock package.".to_string(), input_schema: ipa_schema(), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaMockEntryCountsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (p, is_fixture) = ipa_from_args(&args)?; Ok(ToolResult::text(json!({"entry_count":p.entry_count(),"framework_count":p.framework_count(),"is_encrypted":p.is_encrypted(),"source":"rustre_mobile_ipa::IpaPackage","is_reference_fixture":is_fixture}).to_string())) } }

pub struct MobileIpaPlistReadStringTool;
impl MobileIpaPlistReadStringTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_plist_read_string".to_string(), description: "SimplePlistReader::read_string at given offset.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"offset":{"type":"integer"}},"required":["hex","offset"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaPlistReadStringTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize; let bytes = __ipa_hex_decode(hex)?; let s = rustre_mobile_ipa::SimplePlistReader::read_string(&bytes, off); Ok(ToolResult::text(json!({"string":s,"source":"rustre_mobile_ipa::SimplePlistReader::read_string"}).to_string())) } }

pub struct MobileIpaPlistFindKeyValueTool;
impl MobileIpaPlistFindKeyValueTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_plist_find_key_value".to_string(), description: "SimplePlistReader::find_key_value for the given key.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"key":{"type":"string"}},"required":["hex","key"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaPlistFindKeyValueTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let key = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?; let bytes = __ipa_hex_decode(hex)?; let v = rustre_mobile_ipa::SimplePlistReader::find_key_value(&bytes, key); Ok(ToolResult::text(json!({"value":v,"source":"rustre_mobile_ipa::SimplePlistReader::find_key_value"}).to_string())) } }

pub struct MobileIpaPlistAllStringsTool;
impl MobileIpaPlistAllStringsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_plist_all_strings".to_string(), description: "SimplePlistReader::all_strings on the hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaPlistAllStringsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes = __ipa_hex_decode(hex)?; let s = rustre_mobile_ipa::SimplePlistReader::all_strings(&bytes); let n = s.len(); Ok(ToolResult::text(json!({"strings":s,"count":n,"source":"rustre_mobile_ipa::SimplePlistReader::all_strings"}).to_string())) } }

pub struct MobileIpaInfoPlistFullFromXmlTool;
impl MobileIpaInfoPlistFullFromXmlTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_info_plist_full_from_xml".to_string(), description: "InfoPlistFull::from_xml parsing.".to_string(), input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}},"required":["xml"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaInfoPlistFullFromXmlTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?; match rustre_mobile_ipa::InfoPlistFull::from_xml(xml) { Ok(p) => Ok(ToolResult::text(json!({"info":p,"source":"rustre_mobile_ipa::InfoPlistFull::from_xml"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())) } } }

pub struct MobileIpaEntitlementsFromPlistTool;
impl MobileIpaEntitlementsFromPlistTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mobile_ipa_entitlements_from_plist".to_string(), description: "Entitlements::from_plist on hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MobileIpaEntitlementsFromPlistTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bytes = __ipa_hex_decode(hex)?; match rustre_mobile_ipa::Entitlements::from_plist(&bytes) { Ok(e) => Ok(ToolResult::text(json!({"entitlements":e,"source":"rustre_mobile_ipa::Entitlements::from_plist"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"error":e.to_string()}).to_string())) } } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileIpaIsBinaryPlistTool::definition(), Box::new(MobileIpaIsBinaryPlistTool)),
        (MobileIpaMockPackageTool::definition(), Box::new(MobileIpaMockPackageTool)),
        (MobileIpaPlistIsBinaryTool::definition(), Box::new(MobileIpaPlistIsBinaryTool)),
        (MobileIpaMockSummaryTool::definition(), Box::new(MobileIpaMockSummaryTool)),
        (MobileIpaMockHasEntitlementsTool::definition(), Box::new(MobileIpaMockHasEntitlementsTool)),
        (MobileIpaMockParsedMinOsTool::definition(), Box::new(MobileIpaMockParsedMinOsTool)),
        (MobileIpaMockTargetsIphoneTool::definition(), Box::new(MobileIpaMockTargetsIphoneTool)),
        (MobileIpaMockCodesignFlagsTool::definition(), Box::new(MobileIpaMockCodesignFlagsTool)),
        (MobileIpaMockLeafCertAppleTool::definition(), Box::new(MobileIpaMockLeafCertAppleTool)),
        (MobileIpaMockBinaryEntriesTool::definition(), Box::new(MobileIpaMockBinaryEntriesTool)),
        (MobileIpaMockEntryCountsTool::definition(), Box::new(MobileIpaMockEntryCountsTool)),
        (MobileIpaPlistReadStringTool::definition(), Box::new(MobileIpaPlistReadStringTool)),
        (MobileIpaPlistFindKeyValueTool::definition(), Box::new(MobileIpaPlistFindKeyValueTool)),
        (MobileIpaPlistAllStringsTool::definition(), Box::new(MobileIpaPlistAllStringsTool)),
        (MobileIpaInfoPlistFullFromXmlTool::definition(), Box::new(MobileIpaInfoPlistFullFromXmlTool)),
        (MobileIpaEntitlementsFromPlistTool::definition(), Box::new(MobileIpaEntitlementsFromPlistTool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plist read must refuse an invalid payload instead of inventing bytes.
    ///
    /// `__ipa_hex_decode` used `to_digit(16).unwrap_or(0)` per nibble, so a bad
    /// pair became `0x00` while the buffer kept its length. In a plist — offsets
    /// and lengths all the way down — that does not corrupt one byte, it changes
    /// which string comes back. Length-based checks cannot catch it, which is
    /// why this asserts on the ERROR, not on the size of the result.
    #[tokio::test]
    async fn a_bad_plist_payload_is_refused_not_invented() {
        let tool = MobileIpaPlistAllStringsTool;
        assert!(
            tool.call(json!({ "hex": "62706c697374zz30" })).await.is_err(),
            "an invalid digit was accepted"
        );
        // Positive control: the same bytes, valid — "bplist00" is the magic a
        // real binary plist starts with, so this must still be read.
        assert!(
            tool.call(json!({ "hex": "62706c6973743030" })).await.is_ok(),
            "valid input was rejected"
        );
    }

    /// Every `mobile_ipa_mock_*` tool must say it is a fixture.
    ///
    /// Six of the seven already did ("…on mock package"); the seventh described
    /// itself as a real `leaf_cert` + `is_apple_issued` check, which is a
    /// SECURITY verdict — the description is what a caller reads when choosing a
    /// tool, so that omission was the most costly of the seven.
    #[test]
    fn every_mock_tool_declares_that_it_is_a_mock() {
        for (def, _) in handlers() {
            if def.name.contains("_mock_") {
                assert!(
                    def.description.to_lowercase().contains("mock"),
                    "{} does not declare itself a mock: {:?}",
                    def.name,
                    def.description
                );
            }
        }
    }
}
