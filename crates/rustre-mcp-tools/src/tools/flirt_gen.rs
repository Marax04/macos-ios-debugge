//! MCP wrappers for the rustre-flirt_gen crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct FlirtGenScanX86MasksTool;

pub struct FlirtGenCrc16SigHeaderTool;

pub struct FlirtGenElfParseTool;

pub struct FlirtGenPatternGeneratorNewTool;

pub struct FlirtGenPatternGenerateTool;

pub struct FlirtGenPatternWithQualityTool;

pub struct FlirtGenLibraryBuilderDemoTool;

pub struct FlirtGenCrc16SigHeaderEmptyWireTool;
impl FlirtGenCrc16SigHeaderEmptyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_crc16_sig_header_empty_wire".to_string(), description: "CRC-16 of empty slice via rustre_flirt_gen::crc16_sig_header.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenCrc16SigHeaderEmptyWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let crc = rustre_flirt_gen::crc16_sig_header(&[]); Ok(ToolResult::text(json!({"crc16":crc,"source":"rustre_flirt_gen::crc16_sig_header"}).to_string())) } }

pub struct FlirtGenScanX86MasksEmptyWireTool;
impl FlirtGenScanX86MasksEmptyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_empty_wire".to_string(), description: "scan_x86_masks on empty input returns 0 ranges.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksEmptyWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_flirt_gen::scan_x86_masks(&[]); Ok(ToolResult::text(json!({"count":r.len(),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenScanX86MasksCallRel32WireTool;
impl FlirtGenScanX86MasksCallRel32WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_call_rel32_wire".to_string(), description: "scan_x86_masks over E8 CALL rel32 masks the 4-byte displacement.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksCallRel32WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0xE8u8, 0x11, 0x22, 0x33, 0x44, 0xC3]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_offset":r.first().map(|(o,_)|*o),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenPatternGeneratorDefaultWireTool;
impl FlirtGenPatternGeneratorDefaultWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_pattern_generator_default_wire".to_string(), description: "PatternGenerator::default() fields.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenPatternGeneratorDefaultWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator::default(); Ok(ToolResult::text(json!({"initial_length":g.initial_length,"crc_length":g.crc_length,"source":"rustre_flirt_gen::PatternGenerator::default"}).to_string())) } }

pub struct FlirtGenGenerateBatchWireTool;
impl FlirtGenGenerateBatchWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_generate_batch_wire".to_string(), description: "PatternGenerator::generate_batch produces N patterns.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenGenerateBatchWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator::new(); let funcs = vec![("a".to_string(), vec![0x55u8,0x48,0x89,0xE5], vec![]), ("b".to_string(), vec![0x56u8,0x48,0x89,0xE5], vec![])]; let pats = g.generate_batch(funcs); Ok(ToolResult::text(json!({"count":pats.len(),"source":"rustre_flirt_gen::PatternGenerator::generate_batch"}).to_string())) } }

pub struct FlirtGenGenerateFromRangesWireTool;
impl FlirtGenGenerateFromRangesWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_generate_from_ranges_wire".to_string(), description: "PatternGenerator::generate_from_ranges with 2-byte mask.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenGenerateFromRangesWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator::new(); let bytes: Vec<u8> = (0u8..40).collect(); let pat = g.generate_from_ranges(&bytes, &[(2u16, 2u8)], vec![], vec![]).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"initial_len":pat.initial_bytes.len(),"pattern_length":pat.pattern_length,"source":"rustre_flirt_gen::PatternGenerator::generate_from_ranges"}).to_string())) } }

pub struct FlirtGenPatternQualityAsStrWireTool;
impl FlirtGenPatternQualityAsStrWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_pattern_quality_as_str_wire".to_string(), description: "PatternQuality variants labels.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenPatternQualityAsStrWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"high":rustre_flirt_gen::PatternQuality::High.as_str(),"medium":rustre_flirt_gen::PatternQuality::Medium.as_str(),"low":rustre_flirt_gen::PatternQuality::Low.as_str(),"source":"rustre_flirt_gen::PatternQuality::as_str"}).to_string())) } }

pub struct FlirtGenLibraryBuilderDedupWireTool;
impl FlirtGenLibraryBuilderDedupWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_library_builder_dedup_wire".to_string(), description: "LibraryBuilder dedup_patterns removes duplicates.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenLibraryBuilderDedupWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut b = rustre_flirt_gen::LibraryBuilder::new("l", rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); let bytes = vec![0x55u8,0x48,0x89,0xE5,0xC3]; b.add_function("foo".into(), &bytes, vec![]); b.add_function("foo".into(), &bytes, vec![]); b.dedup_patterns(); let (lib, stats) = b.build(); Ok(ToolResult::text(json!({"pattern_count":lib.pattern_count(),"duplicates_removed":stats.duplicates_removed,"source":"rustre_flirt_gen::LibraryBuilder::dedup_patterns"}).to_string())) } }

pub struct FlirtGenSigWriterBuildEmptyWireTool;
impl FlirtGenSigWriterBuildEmptyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_sig_writer_build_empty_wire".to_string(), description: "SigWriter::default().build with no sigs yields IDASGN header.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenSigWriterBuildEmptyWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let w = rustre_flirt_gen::SigWriter::default(); let bytes = w.build(&[], "l"); Ok(ToolResult::text(json!({"len":bytes.len(),"magic_ok":&bytes[..6]==b"IDASGN","version":bytes[6],"source":"rustre_flirt_gen::SigWriter::build"}).to_string())) } }

pub struct FlirtGenElfParseRejectShortWireTool;
impl FlirtGenElfParseRejectShortWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_elf_parse_reject_short_wire".to_string(), description: "ElfObjectParser::parse rejects too-short input.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenElfParseRejectShortWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_flirt_gen::ElfObjectParser::parse(b"short"); Ok(ToolResult::text(json!({"is_err":r.is_err(),"source":"rustre_flirt_gen::ElfObjectParser::parse"}).to_string())) } }

pub struct FlirtGenSigTrieNodeEncodeLeafWireTool;
impl FlirtGenSigTrieNodeEncodeLeafWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_sig_trie_node_encode_leaf_wire".to_string(), description: "SigTrieNode::Leaf::encode length + flag byte.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenSigTrieNodeEncodeLeafWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let node = rustre_flirt_gen::SigTrieNode::Leaf { prefix: vec![0x55,0x48,0x89,0xE5], crc_len: 4, crc16: 0xABCD, module_offset: 0, func_name: "foo".into(), tail: Vec::new(), tail_mask: Vec::new() }; let mut buf = Vec::new(); node.encode(&mut buf); Ok(ToolResult::text(json!({"len":buf.len(),"prefix_len":buf[0],"flag_byte":buf[5],"source":"rustre_flirt_gen::SigTrieNode::encode"}).to_string())) } }

pub struct FlirtGenWriteSigFileWireTool;
impl FlirtGenWriteSigFileWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_write_sig_file_wire".to_string(), description: "write_sig_file to a temp path and re-read magic.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenWriteSigFileWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut b = rustre_flirt_gen::LibraryBuilder::new("l", rustre_flirt::FlirtArch::X64, rustre_flirt::FlirtOs::Linux); b.add_function("f".into(), &[0x55u8,0x48,0x89,0xE5,0xC3], vec![]); let (lib, _) = b.build(); let path = std::env::temp_dir().join("rustre_flirt_gen_wire_test.sig"); let res = rustre_flirt_gen::write_sig_file(&lib.patterns, "l", 75, &path); let data = std::fs::read(&path).ok(); Ok(ToolResult::text(json!({"ok":res.is_ok(),"magic_ok":data.as_ref().map(|d| d.len()>=6 && &d[..6]==b"IDASGN"),"source":"rustre_flirt_gen::write_sig_file"}).to_string())) } }

pub struct FlirtGenGenerateNoRelocsWireTool;
impl FlirtGenGenerateNoRelocsWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_generate_no_relocs_wire".to_string(), description: "flirt_gen_generate_no_relocs_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenGenerateNoRelocsWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator::new(); let bytes: Vec<u8> = (0u8..50).collect(); let pat = g.generate(&bytes, &[], vec![]).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"initial_len":pat.initial_bytes.len(),"pattern_length":pat.pattern_length,"crc_length":pat.crc_length,"source":"rustre_flirt_gen::PatternGenerator::generate"}).to_string())) } }

pub struct FlirtGenGenerateWithRelocsWireTool;
impl FlirtGenGenerateWithRelocsWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_generate_with_relocs_wire".to_string(), description: "flirt_gen_generate_with_relocs_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenGenerateWithRelocsWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator::new(); let bytes: Vec<u8> = (0u8..40).collect(); let relocs = vec![rustre_flirt_gen::RelocationEntry { offset: 4, size: 4 }]; let pat = g.generate(&bytes, &relocs, vec![]).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"initial_len":pat.initial_bytes.len(),"pattern_length":pat.pattern_length,"source":"rustre_flirt_gen::PatternGenerator::generate"}).to_string())) } }

pub struct FlirtGenScanX86MasksJmpRel32WireTool;
impl FlirtGenScanX86MasksJmpRel32WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_jmp_rel32_wire".to_string(), description: "flirt_gen_scan_x86_masks_jmp_rel32_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksJmpRel32WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0xE9u8, 0xAA, 0xBB, 0xCC, 0xDD, 0x90]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_offset":r.first().map(|(o,_)|*o),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenScanX86MasksJccRel32WireTool;
impl FlirtGenScanX86MasksJccRel32WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_jcc_rel32_wire".to_string(), description: "flirt_gen_scan_x86_masks_jcc_rel32_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksJccRel32WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0x0Fu8, 0x84, 0x11, 0x22, 0x33, 0x44, 0x90]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_offset":r.first().map(|(o,_)|*o),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenScanX86MasksJmpRel8WireTool;
impl FlirtGenScanX86MasksJmpRel8WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_jmp_rel8_wire".to_string(), description: "flirt_gen_scan_x86_masks_jmp_rel8_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksJmpRel8WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0xEBu8, 0x10, 0x90]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenScanX86MasksMovImm64WireTool;
impl FlirtGenScanX86MasksMovImm64WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_mov_imm64_wire".to_string(), description: "flirt_gen_scan_x86_masks_mov_imm64_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksMovImm64WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0x48u8, 0xB8, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0xC3]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenScanX86MasksRipRelativeWireTool;
impl FlirtGenScanX86MasksRipRelativeWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_scan_x86_masks_rip_relative_wire".to_string(), description: "flirt_gen_scan_x86_masks_rip_relative_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenScanX86MasksRipRelativeWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bytes = [0x48u8, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xC3]; let r = rustre_flirt_gen::scan_x86_masks(&bytes); Ok(ToolResult::text(json!({"count":r.len(),"first_size":r.first().map(|(_,s)|*s),"source":"rustre_flirt_gen::scan_x86_masks"}).to_string())) } }

pub struct FlirtGenCrc16SigHeaderKnownWireTool;
impl FlirtGenCrc16SigHeaderKnownWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_crc16_sig_header_known_wire".to_string(), description: "flirt_gen_crc16_sig_header_known_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenCrc16SigHeaderKnownWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let a = rustre_flirt_gen::crc16_sig_header(b"hello world"); let b = rustre_flirt_gen::crc16_sig_header(b"hello world"); Ok(ToolResult::text(json!({"crc16":a,"deterministic":a==b,"source":"rustre_flirt_gen::crc16_sig_header"}).to_string())) } }

pub struct FlirtGenPatternGeneratorCustomWireTool;
impl FlirtGenPatternGeneratorCustomWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_pattern_generator_custom_wire".to_string(), description: "flirt_gen_pattern_generator_custom_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenPatternGeneratorCustomWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let g = rustre_flirt_gen::PatternGenerator { initial_length: 8, crc_length: 4 }; let bytes: Vec<u8> = (0u8..20).collect(); let pat = g.generate(&bytes, &[], vec![]).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"initial_len":pat.initial_bytes.len(),"crc_length":pat.crc_length,"source":"rustre_flirt_gen::PatternGenerator::generate"}).to_string())) } }

pub struct FlirtGenLibraryBuilderSkippedWireTool;
impl FlirtGenLibraryBuilderSkippedWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_library_builder_skipped_wire".to_string(), description: "flirt_gen_library_builder_skipped_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenLibraryBuilderSkippedWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut b = rustre_flirt_gen::LibraryBuilder::new("s", rustre_flirt::FlirtArch::X86, rustre_flirt::FlirtOs::Windows); b.add_function("empty".into(), &[], vec![]); let (_lib, stats) = b.build(); Ok(ToolResult::text(json!({"functions_processed":stats.functions_processed,"patterns_generated":stats.patterns_generated,"patterns_skipped":stats.patterns_skipped,"source":"rustre_flirt_gen::LibraryBuilder"}).to_string())) } }

pub struct FlirtGenRelocationEntryWireTool;
impl FlirtGenRelocationEntryWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_relocation_entry_wire".to_string(), description: "flirt_gen_relocation_entry_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenRelocationEntryWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_flirt_gen::RelocationEntry { offset: 4, size: 4 }; Ok(ToolResult::text(json!({"offset":r.offset,"size":r.size,"source":"rustre_flirt_gen::RelocationEntry"}).to_string())) } }

pub struct FlirtGenSigTrieBranchEncodeWireTool;
impl FlirtGenSigTrieBranchEncodeWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_sig_trie_branch_encode_wire".to_string(), description: "flirt_gen_sig_trie_branch_encode_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenSigTrieBranchEncodeWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let node = rustre_flirt_gen::SigTrieNode::Branch { prefix: vec![0x55], children: vec![] }; let mut buf = Vec::new(); node.encode(&mut buf); Ok(ToolResult::text(json!({"len":buf.len(),"prefix_len":buf[0],"prefix_byte":buf[1],"child_sentinel":buf[2],"end_sentinel":buf[3],"source":"rustre_flirt_gen::SigTrieNode::encode"}).to_string())) } }

pub struct FlirtGenSigWriterI386WireTool;
impl FlirtGenSigWriterI386WireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_sig_writer_i386_wire".to_string(), description: "flirt_gen_sig_writer_i386_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenSigWriterI386WireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let w = rustre_flirt_gen::SigWriter { arch: 0, ..rustre_flirt_gen::SigWriter::default() }; let bytes = w.build(&[], "l"); Ok(ToolResult::text(json!({"arch_byte":bytes[7],"version":bytes[6],"source":"rustre_flirt_gen::SigWriter::build"}).to_string())) } }

pub struct FlirtGenGenerationStatsDefaultWireTool;
impl FlirtGenGenerationStatsDefaultWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "flirt_gen_generation_stats_default_wire".to_string(), description: "flirt_gen_generation_stats_default_wire".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FlirtGenGenerationStatsDefaultWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_flirt_gen::GenerationStats::default(); Ok(ToolResult::text(json!({"functions_processed":s.functions_processed,"patterns_generated":s.patterns_generated,"patterns_skipped":s.patterns_skipped,"duplicates_removed":s.duplicates_removed,"source":"rustre_flirt_gen::GenerationStats::default"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FlirtGenScanX86MasksTool::definition(), Box::new(FlirtGenScanX86MasksTool)),
        (FlirtGenCrc16SigHeaderTool::definition(), Box::new(FlirtGenCrc16SigHeaderTool)),
        (FlirtGenElfParseTool::definition(), Box::new(FlirtGenElfParseTool)),
        (FlirtGenPatternGeneratorNewTool::definition(), Box::new(FlirtGenPatternGeneratorNewTool)),
        (FlirtGenPatternGenerateTool::definition(), Box::new(FlirtGenPatternGenerateTool)),
        (FlirtGenPatternWithQualityTool::definition(), Box::new(FlirtGenPatternWithQualityTool)),
        (FlirtGenLibraryBuilderDemoTool::definition(), Box::new(FlirtGenLibraryBuilderDemoTool)),
        (FlirtGenCrc16SigHeaderEmptyWireTool::definition(), Box::new(FlirtGenCrc16SigHeaderEmptyWireTool)),
        (FlirtGenScanX86MasksEmptyWireTool::definition(), Box::new(FlirtGenScanX86MasksEmptyWireTool)),
        (FlirtGenScanX86MasksCallRel32WireTool::definition(), Box::new(FlirtGenScanX86MasksCallRel32WireTool)),
        (FlirtGenPatternGeneratorDefaultWireTool::definition(), Box::new(FlirtGenPatternGeneratorDefaultWireTool)),
        (FlirtGenGenerateBatchWireTool::definition(), Box::new(FlirtGenGenerateBatchWireTool)),
        (FlirtGenGenerateFromRangesWireTool::definition(), Box::new(FlirtGenGenerateFromRangesWireTool)),
        (FlirtGenPatternQualityAsStrWireTool::definition(), Box::new(FlirtGenPatternQualityAsStrWireTool)),
        (FlirtGenLibraryBuilderDedupWireTool::definition(), Box::new(FlirtGenLibraryBuilderDedupWireTool)),
        (FlirtGenSigWriterBuildEmptyWireTool::definition(), Box::new(FlirtGenSigWriterBuildEmptyWireTool)),
        (FlirtGenElfParseRejectShortWireTool::definition(), Box::new(FlirtGenElfParseRejectShortWireTool)),
        (FlirtGenSigTrieNodeEncodeLeafWireTool::definition(), Box::new(FlirtGenSigTrieNodeEncodeLeafWireTool)),
        (FlirtGenWriteSigFileWireTool::definition(), Box::new(FlirtGenWriteSigFileWireTool)),
        (FlirtGenGenerateNoRelocsWireTool::definition(), Box::new(FlirtGenGenerateNoRelocsWireTool)),
        (FlirtGenGenerateWithRelocsWireTool::definition(), Box::new(FlirtGenGenerateWithRelocsWireTool)),
        (FlirtGenScanX86MasksJmpRel32WireTool::definition(), Box::new(FlirtGenScanX86MasksJmpRel32WireTool)),
        (FlirtGenScanX86MasksJccRel32WireTool::definition(), Box::new(FlirtGenScanX86MasksJccRel32WireTool)),
        (FlirtGenScanX86MasksJmpRel8WireTool::definition(), Box::new(FlirtGenScanX86MasksJmpRel8WireTool)),
        (FlirtGenScanX86MasksMovImm64WireTool::definition(), Box::new(FlirtGenScanX86MasksMovImm64WireTool)),
        (FlirtGenScanX86MasksRipRelativeWireTool::definition(), Box::new(FlirtGenScanX86MasksRipRelativeWireTool)),
        (FlirtGenCrc16SigHeaderKnownWireTool::definition(), Box::new(FlirtGenCrc16SigHeaderKnownWireTool)),
        (FlirtGenPatternGeneratorCustomWireTool::definition(), Box::new(FlirtGenPatternGeneratorCustomWireTool)),
        (FlirtGenLibraryBuilderSkippedWireTool::definition(), Box::new(FlirtGenLibraryBuilderSkippedWireTool)),
        (FlirtGenRelocationEntryWireTool::definition(), Box::new(FlirtGenRelocationEntryWireTool)),
        (FlirtGenSigTrieBranchEncodeWireTool::definition(), Box::new(FlirtGenSigTrieBranchEncodeWireTool)),
        (FlirtGenSigWriterI386WireTool::definition(), Box::new(FlirtGenSigWriterI386WireTool)),
        (FlirtGenGenerationStatsDefaultWireTool::definition(), Box::new(FlirtGenGenerationStatsDefaultWireTool)),
    ]
}
