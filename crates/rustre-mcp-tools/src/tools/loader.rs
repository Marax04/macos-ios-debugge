//! MCP wrappers for the rustre-loader crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct LoaderCoreMd5Tool;

pub struct LoaderFormatDetectorTool;

pub struct LoaderAutoLoaderDetectTool;

pub struct LoaderCoreSha256Tool;

pub struct LoaderLuaIsBytecodeTool;

pub struct LoaderLuaOpcodeNameTool;

pub struct LoaderLuaReadStringTool;

pub struct LoaderFirmwareDetectKindTool;

pub struct LoaderFirmwareDetectBinaryArchTool;

pub struct LoaderFirmwareDetectRtosTool;

pub struct LoaderOleIsOleTool;
impl LoaderOleIsOleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_ole_is_ole".to_string(),
            description: "Return true if the input bytes start with the OLE2 compound-file magic (D0 CF 11 E0 A1 B1 1A E1).".to_string(),
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
impl ToolHandler for LoaderOleIsOleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let is_ole = rustre_loader_ole::is_ole(&data);
        Ok(ToolResult::text(
            json!({
                "is_ole": is_ole,
                "bytes": data.len(),
                "source": "rustre_loader_ole::is_ole",
            })
            .to_string(),
        ))
    }
}

pub struct LoaderOleListStreamsTool;
impl LoaderOleListStreamsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_ole_list_streams".to_string(),
            description: "List all stream entries (name, size, start_sector) from an OLE2 compound file's directory sector.".to_string(),
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
impl ToolHandler for LoaderOleListStreamsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let reader = rustre_loader_ole::OleDirectoryReader::new();
        let streams = reader
            .list_streams(&data)
            .map_err(|e| McpError::InvalidParams(format!("{e}")))?;
        let out: Vec<Value> = streams
            .into_iter()
            .map(|s| json!({
                "name": s.name,
                "size": s.size,
                "start_sector": s.start_sector,
            }))
            .collect();
        Ok(ToolResult::text(
            json!({
                "count": out.len(),
                "streams": out,
                "source": "rustre_loader_ole::OleDirectoryReader::list_streams",
            })
            .to_string(),
        ))
    }
}

pub struct LoaderOleExtractMacrosTool;
impl LoaderOleExtractMacrosTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_ole_extract_macros".to_string(),
            description: "Extract VBA macro stream previews from an OLE2 compound file (streams under VBA/ prefix).".to_string(),
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
impl ToolHandler for LoaderOleExtractMacrosTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let extractor = rustre_loader_ole::OleMacroExtractor::new();
        let macros = extractor.extract_macros(&data);
        let out: Vec<Value> = macros
            .into_iter()
            .map(|m| json!({
                "stream_name": m.stream_name,
                "start_sector": m.start_sector,
                "raw_preview_hex": hex_encode(&m.raw_preview),
                "code_excerpt": m.code_excerpt,
            }))
            .collect();
        Ok(ToolResult::text(
            json!({
                "count": out.len(),
                "macros": out,
                "source": "rustre_loader_ole::OleMacroExtractor::extract_macros",
            })
            .to_string(),
        ))
    }
}

pub struct LoaderPdfVersionTool;

pub struct LoaderPdfHasJavascriptTool;

pub struct LoaderPdfHasEmbeddedFilesTool;

pub struct LoaderAndroidIsApkTool;

pub struct LoaderAndroidIsVdexTool;

pub struct LoaderAndroidAdler32Tool;

pub struct LoaderWasmParseTool;
impl LoaderWasmParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_wasm_parse".to_string(),
            description: "Parse a WebAssembly binary via rustre_loader_wasm::WasmParser::parse and return module summary.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderWasmParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let bytes = std::fs::read(path).map_err(|e| McpError::InvalidParams(format!("read {path}: {e}")))?;
        let module = rustre_loader_wasm::WasmParser::parse(&bytes)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "version": module.version,
            "types": module.types.len(),
            "imports": module.imports.len(),
            "functions_defined": module.defined_function_count,
            "functions_total": module.total_function_count,
            "exports": module.exports.len(),
            "memories": module.memories.len(),
            "globals": module.globals.len(),
            "data_segments": module.data_segments.len(),
            "custom_sections": module.custom_sections.len(),
            "has_name_section": module.name_section.is_some(),
            "start_function": module.start_function,
            "source": "rustre_loader_wasm::WasmParser::parse",
        }).to_string()))
    }
}

pub struct LoaderWasmStatsTool;
impl LoaderWasmStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_wasm_stats".to_string(),
            description: "Compute aggregate stats via rustre_loader_wasm::WasmStats::compute.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderWasmStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let bytes = std::fs::read(path).map_err(|e| McpError::InvalidParams(format!("read {path}: {e}")))?;
        let module = rustre_loader_wasm::WasmParser::parse(&bytes)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let s = rustre_loader_wasm::WasmStats::compute(&module);
        Ok(ToolResult::text(json!({
            "function_count": s.function_count,
            "code_size": s.code_size,
            "data_size": s.data_size,
            "has_dwarf": s.has_dwarf,
            "has_name_section": s.has_name_section,
            "most_complex_function": s.most_complex_function,
            "source": "rustre_loader_wasm::WasmStats::compute",
        }).to_string()))
    }
}

pub struct LoaderWasmOpcodeMnemonicTool;
impl LoaderWasmOpcodeMnemonicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_wasm_opcode_mnemonic".to_string(),
            description: "Return the Wasm opcode mnemonic via rustre_loader_wasm::WasmOpcode::mnemonic.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcode":{"type":"integer"}},"required":["opcode"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderWasmOpcodeMnemonicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let op = args.get("opcode").and_then(|v| v.as_u64())
            .ok_or_else(|| McpError::InvalidParams("missing 'opcode'".into()))?;
        let byte = u8::try_from(op).map_err(|_| McpError::InvalidParams("opcode out of range".into()))?;
        let m = rustre_loader_wasm::WasmOpcode(byte).mnemonic();
        Ok(ToolResult::text(json!({
            "opcode": byte,
            "mnemonic": m,
            "source": "rustre_loader_wasm::WasmOpcode::mnemonic",
        }).to_string()))
    }
}

pub struct LoaderLuajitIsLuajitTool;

pub struct LoaderLuajitReadUleb128Tool;

pub struct LoaderLuajitReadSleb128Tool;

pub struct LoaderConsoleDetectFormatTool;

pub struct LoaderConsoleXorChecksumTool;

pub struct LoaderConsoleIsNesTool;

pub struct LoaderDotnetHasClrHeaderTool;

pub struct LoaderDotnetIsDotnetTool;

pub struct LoaderDotnetReadCompressedUintTool;

pub struct LoaderPeIsSignedTool;

pub struct LoaderPePdbPathTool;

pub struct LoaderPeEntryPointsTool;

pub struct LoaderElfGnuHashStrTool;

pub struct LoaderElfGnuHashBytesTool;

pub struct LoaderElfInfoSummaryTool;

pub struct LoaderMachoArchFromCputypeTool;

pub struct LoaderMachoSubtypeNameTool;

pub struct LoaderMachoParseSummaryTool;

pub struct LoaderJavaIsClassTool;
impl LoaderJavaIsClassTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_java_is_class".to_string(),
            description: "Return true if the buffer starts with 0xCAFEBABE.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderJavaIsClassTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let flag = rustre_loader_java::is_class(&data);
        Ok(ToolResult::text(json!({"is_class": flag, "source": "rustre_loader_java::is_class"}).to_string()))
    }
}

pub struct LoaderJavaIsJarTool;
impl LoaderJavaIsJarTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_java_is_jar".to_string(),
            description: "Return true if the buffer is a JAR containing .class entries.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderJavaIsJarTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let flag = rustre_loader_java::is_jar(&data);
        Ok(ToolResult::text(json!({"is_jar": flag, "source": "rustre_loader_java::is_jar"}).to_string()))
    }
}

pub struct LoaderJavaParseClassTool;
impl LoaderJavaParseClassTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_java_parse_class".to_string(),
            description: "Parse a Java class file and return summary.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderJavaParseClassTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        match rustre_loader_java::JavaClass::parse(&data) {
            Ok(cls) => Ok(ToolResult::text(json!({
                "class_name": cls.class_name,
                "super_name": cls.super_name,
                "major": cls.version.major,
                "minor": cls.version.minor,
                "java_release": cls.version.java_release(),
                "interfaces": cls.interfaces.len(),
                "fields": cls.fields.len(),
                "methods": cls.methods.len(),
                "constant_pool": cls.constant_pool.len(),
                "source": "rustre_loader_java::JavaClass::parse",
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string(), "source": "rustre_loader_java::JavaClass::parse"}).to_string())),
        }
    }
}

pub struct LoaderCoordinatorNewTool;

pub struct LoaderCoordinatorNewWithRegistryTool;

pub struct LoaderDotnetHasClrHeaderWireTool;

pub struct LoaderDotnetIsDotnetWireTool;

pub struct LoaderAndroidIsDexTool;

pub struct LoaderAndroidVerifyDexChecksumTool;

pub struct LoaderElfParseInfoTool;

pub struct LoaderElfPltEntriesTool;

pub struct LoaderMachoParseTool;

pub struct LoaderMachoParseFatTool;

pub struct LoaderPeParseInfoTool;

pub struct LoaderPeImportsFromDllTool;

pub struct LoaderIsElfTool;
impl LoaderIsElfTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_is_elf".to_string(),
            description: "Check whether the given bytes are an ELF binary via rustre_loader::FormatDetector::is_elf.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderIsElfTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({"is_elf": d.is_elf(&data),"bytes":data.len(),"source":"rustre_loader::FormatDetector::is_elf"}).to_string()))
    }
}

pub struct LoaderIsPeTool;
impl LoaderIsPeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_is_pe".to_string(),
            description: "Check whether the given bytes are a PE binary via rustre_loader::FormatDetector::is_pe.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderIsPeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({"is_pe": d.is_pe(&data),"bytes":data.len(),"source":"rustre_loader::FormatDetector::is_pe"}).to_string()))
    }
}

pub struct LoaderIsMachoTool;
impl LoaderIsMachoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_is_macho".to_string(),
            description: "Check whether the given bytes are a Mach-O (or fat Mach-O) binary via rustre_loader::FormatDetector::is_macho.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderIsMachoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({"is_macho": d.is_macho(&data),"bytes":data.len(),"source":"rustre_loader::FormatDetector::is_macho"}).to_string()))
    }
}

pub struct LoaderIsJavaClassTool;
impl LoaderIsJavaClassTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_is_java_class".to_string(),
            description: "Check whether the given bytes are a Java class file via rustre_loader::FormatDetector::is_java_class.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderIsJavaClassTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({"is_java_class": d.is_java_class(&data),"bytes":data.len(),"source":"rustre_loader::FormatDetector::is_java_class"}).to_string()))
    }
}

pub struct LoaderHubCoordinatorNewEmptyTool;
impl LoaderHubCoordinatorNewEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_hub_coordinator_new_empty".to_string(),
            description: "Instantiate a fresh empty LoaderCoordinator (hub) and return its loader_count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderHubCoordinatorNewEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_loader::LoaderCoordinator::new();
        Ok(ToolResult::text(json!({"loader_count": c.loader_count(),"source":"rustre_loader::LoaderCoordinator::new"}).to_string()))
    }
}

pub struct LoaderPipelineNewTool;
impl LoaderPipelineNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_pipeline_new".to_string(),
            description: "Construct a LoaderPipeline with the given name and report its metadata.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderPipelineNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("default").to_string();
        let p = rustre_loader::LoaderPipeline::new(name.clone());
        Ok(ToolResult::text(json!({"name": p.name(),"loader_count": p.loader_count(),"source":"rustre_loader::LoaderPipeline::new"}).to_string()))
    }
}

pub struct LoaderPipelineDetectFormatTool;
impl LoaderPipelineDetectFormatTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_pipeline_detect_format".to_string(),
            description: "Detect coarse BinaryFormat using a fresh LoaderPipeline.detect_format.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderPipelineDetectFormatTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let p = rustre_loader::LoaderPipeline::new("wire");
        let fmt = p.detect_format(&data);
        Ok(ToolResult::text(json!({"format": fmt.to_string(),"bytes": data.len(),"source":"rustre_loader::LoaderPipeline::detect_format"}).to_string()))
    }
}

pub struct LoaderMultiFormatRegistryLenTool;
impl LoaderMultiFormatRegistryLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_multi_format_registry_len".to_string(),
            description: "Build the default MultiFormatRegistry and report its loader count and names.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderMultiFormatRegistryLenTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_loader::default_multi_format_registry();
        Ok(ToolResult::text(json!({"len": r.len(),"is_empty": r.is_empty(),"names": r.loader_names(),"source":"rustre_loader::default_multi_format_registry"}).to_string()))
    }
}

pub struct LoaderMultiFormatProbeAllTool;
impl LoaderMultiFormatProbeAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_multi_format_probe_all".to_string(),
            description: "Probe bytes against every loader in the default MultiFormatRegistry and return (name, confidence) tuples sorted descending.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderMultiFormatProbeAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let r = rustre_loader::default_multi_format_registry();
        let results = r.probe_all(&data);
        Ok(ToolResult::text(json!({"results": results,"bytes": data.len(),"source":"rustre_loader::MultiFormatRegistry::probe_all"}).to_string()))
    }
}

pub struct LoaderRichLoadResultAutoTool;
impl LoaderRichLoadResultAutoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_rich_load_result_auto".to_string(),
            description: "Auto-load bytes via the default MultiFormatRegistry and return a summary of the RichLoadResult (format, arch, bits, endian, section/symbol/import/export counts, sha256).".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderRichLoadResultAutoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let r = rustre_loader::default_multi_format_registry();
        match r.auto_load(&data) {
            Ok(res) => Ok(ToolResult::text(json!({
                "format": res.format,
                "arch": res.arch,
                "bits": res.bits,
                "endian": res.endian,
                "entry_point": res.entry_point,
                "base_address": res.base_address,
                "sections": res.sections.len(),
                "symbols": res.symbols.len(),
                "imports": res.imports.len(),
                "exports": res.exports.len(),
                "total_virtual_size": res.total_virtual_size(),
                "sha256": res.sha256(),
                "source": "rustre_loader::MultiFormatRegistry::auto_load",
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string(),"bytes":data.len(),"source":"rustre_loader::MultiFormatRegistry::auto_load"}).to_string())),
        }
    }
}

pub struct LoaderRichLoadResultNewTool;
impl LoaderRichLoadResultNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_rich_load_result_new".to_string(),
            description: "Construct a minimal RichLoadResult from raw bytes and report sha256/md5/data length.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderRichLoadResultNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let r = rustre_loader::RichLoadResult::new(data.clone());
        Ok(ToolResult::text(json!({
            "sha256": r.sha256(),
            "md5": r.md5(),
            "bytes": r.data.len(),
            "total_virtual_size": r.total_virtual_size(),
            "source": "rustre_loader::RichLoadResult::new",
        }).to_string()))
    }
}

pub struct LoaderFormatDetectorNewEmptyTool;
impl LoaderFormatDetectorNewEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_format_detector_new_empty".to_string(), description: "Construct FormatDetector and detect on empty input.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderFormatDetectorNewEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_loader::FormatDetector::new();
        let fmt = d.detect(&[]);
        Ok(ToolResult::text(json!({"format":fmt.to_string(),"source":"rustre_loader::FormatDetector::new+detect"}).to_string()))
    }
}

pub struct LoaderPipelineNameTool;
impl LoaderPipelineNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_pipeline_name".to_string(), description: "Create LoaderPipeline with given name and return its name.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderPipelineNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let p = rustre_loader::LoaderPipeline::new(name);
        Ok(ToolResult::text(json!({"name":p.name(),"source":"rustre_loader::LoaderPipeline::name"}).to_string()))
    }
}

pub struct LoaderPipelineLoaderCountTool;
impl LoaderPipelineLoaderCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_pipeline_loader_count".to_string(), description: "LoaderPipeline::loader_count on a fresh pipeline.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderPipelineLoaderCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("pipeline");
        let p = rustre_loader::LoaderPipeline::new(name);
        Ok(ToolResult::text(json!({"count":p.loader_count(),"name":p.name(),"source":"rustre_loader::LoaderPipeline::loader_count"}).to_string()))
    }
}

pub struct LoaderCoordinatorLoaderCountTool;
impl LoaderCoordinatorLoaderCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_coordinator_loader_count".to_string(), description: "LoaderCoordinator::loader_count on a fresh coordinator.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderCoordinatorLoaderCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_loader::LoaderCoordinator::new();
        Ok(ToolResult::text(json!({"count":c.loader_count(),"source":"rustre_loader::LoaderCoordinator::loader_count"}).to_string()))
    }
}

pub struct LoaderMultiFormatRegistryLoaderNamesTool;
impl LoaderMultiFormatRegistryLoaderNamesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_multi_format_registry_loader_names".to_string(), description: "Return loader_names() from the default MultiFormatRegistry.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderMultiFormatRegistryLoaderNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_loader::default_multi_format_registry();
        let names = r.loader_names();
        Ok(ToolResult::text(json!({"names":names,"len":r.len(),"source":"rustre_loader::MultiFormatRegistry::loader_names"}).to_string()))
    }
}

pub struct LoaderMultiFormatRegistryIsEmptyTool;
impl LoaderMultiFormatRegistryIsEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_multi_format_registry_is_empty".to_string(), description: "Return is_empty() on a fresh MultiFormatRegistry vs the default one.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderMultiFormatRegistryIsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let empty = rustre_loader::MultiFormatRegistry::new();
        let default = rustre_loader::default_multi_format_registry();
        Ok(ToolResult::text(json!({"empty_registry_is_empty":empty.is_empty(),"default_is_empty":default.is_empty(),"default_len":default.len(),"source":"rustre_loader::MultiFormatRegistry::is_empty"}).to_string()))
    }
}

pub struct LoaderMultiFormatRegistryFindTool;
impl LoaderMultiFormatRegistryFindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_multi_format_registry_find".to_string(), description: "Look up a loader by name in the default MultiFormatRegistry.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderMultiFormatRegistryFindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let r = rustre_loader::default_multi_format_registry();
        let found = r.find(name).is_some();
        Ok(ToolResult::text(json!({"name":name,"found":found,"registry_len":r.len(),"source":"rustre_loader::MultiFormatRegistry::find"}).to_string()))
    }
}

pub struct LoaderDefaultMultiFormatRegistryCountTool;
impl LoaderDefaultMultiFormatRegistryCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_default_multi_format_registry_count".to_string(), description: "Count/names of loaders in the default MultiFormatRegistry.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderDefaultMultiFormatRegistryCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_loader::default_multi_format_registry();
        Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"names":r.loader_names(),"source":"rustre_loader::default_multi_format_registry"}).to_string()))
    }
}

pub struct LoaderFormatDetectorProbeAllBoolsTool;
impl LoaderFormatDetectorProbeAllBoolsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_format_detector_probe_all_bools".to_string(), description: "FormatDetector::{is_elf,is_pe,is_macho,is_java_class} for input bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderFormatDetectorProbeAllBoolsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({
            "is_elf":d.is_elf(&data),"is_pe":d.is_pe(&data),"is_macho":d.is_macho(&data),
            "is_java_class":d.is_java_class(&data),"format":d.detect(&data).to_string(),
            "source":"rustre_loader::FormatDetector::{is_elf,is_pe,is_macho,is_java_class}"
        }).to_string()))
    }
}

pub struct LoaderDetectedFormatDisplayTool;
impl LoaderDetectedFormatDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "loader_detected_format_display".to_string(), description: "AutoLoader::detect_format on bytes and return Display form.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for LoaderDetectedFormatDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let fmt = rustre_loader::AutoLoader::detect_format(&data);
        Ok(ToolResult::text(json!({"display":fmt.to_string(),"bytes":data.len(),"source":"rustre_loader::DetectedFormat::Display"}).to_string()))
    }
}

pub struct LoaderSectionInfoNewTool;
impl LoaderSectionInfoNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_section_info_new".to_string(),
            description: "Construct rustre_loader::SectionInfo::new.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"virtual_addr":{"type":"integer"},"virtual_size":{"type":"integer"},
                "raw_offset":{"type":"integer"},"raw_size":{"type":"integer"},"flags":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderSectionInfoNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or(".text").to_string();
        let va = args.get("virtual_addr").and_then(Value::as_u64).unwrap_or(0);
        let vs = args.get("virtual_size").and_then(Value::as_u64).unwrap_or(0);
        let ro = args.get("raw_offset").and_then(Value::as_u64).unwrap_or(0);
        let rs = args.get("raw_size").and_then(Value::as_u64).unwrap_or(0);
        let fl = args.get("flags").and_then(Value::as_u64).unwrap_or(0) as u32;
        let s = rustre_loader::SectionInfo::new(name, va, vs, ro, rs, fl);
        Ok(ToolResult::text(json!({
            "name": s.name, "virtual_addr": s.virtual_addr, "virtual_size": s.virtual_size,
            "raw_offset": s.raw_offset, "raw_size": s.raw_size, "flags": s.flags,
            "source": "rustre_loader::SectionInfo::new"
        }).to_string()))
    }
}

pub struct LoaderSymbolInfoNewTool;
impl LoaderSymbolInfoNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_symbol_info_new".to_string(),
            description: "Construct rustre_loader::SymbolInfo::new.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"addr":{"type":"integer"},"kind":{"type":"string"},"size":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderSymbolInfoNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("sym").to_string();
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let kind = args.get("kind").and_then(Value::as_str).unwrap_or("function").to_string();
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(0);
        let s = rustre_loader::SymbolInfo::new(name, addr, kind, size);
        Ok(ToolResult::text(json!({
            "name": s.name, "addr": s.addr, "kind": s.kind, "size": s.size,
            "source": "rustre_loader::SymbolInfo::new"
        }).to_string()))
    }
}

pub struct LoaderImportInfoNamedTool;
impl LoaderImportInfoNamedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_import_info_named".to_string(),
            description: "Construct rustre_loader::ImportInfo::named.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "dll":{"type":"string"},"name":{"type":"string"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderImportInfoNamedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let dll = args.get("dll").and_then(Value::as_str).unwrap_or("kernel32.dll").to_string();
        let name = args.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let i = rustre_loader::ImportInfo::named(dll, name, addr);
        Ok(ToolResult::text(json!({
            "dll": i.dll, "name": i.name, "addr": i.addr, "ordinal": i.ordinal,
            "source": "rustre_loader::ImportInfo::named"
        }).to_string()))
    }
}

pub struct LoaderImportInfoOrdinalTool;
impl LoaderImportInfoOrdinalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_import_info_ordinal".to_string(),
            description: "Construct rustre_loader::ImportInfo::ordinal.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "dll":{"type":"string"},"ordinal":{"type":"integer"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderImportInfoOrdinalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let dll = args.get("dll").and_then(Value::as_str).unwrap_or("kernel32.dll").to_string();
        let ord = args.get("ordinal").and_then(Value::as_u64).unwrap_or(1) as u16;
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let i = rustre_loader::ImportInfo::ordinal(dll, ord, addr);
        Ok(ToolResult::text(json!({
            "dll": i.dll, "name": i.name, "addr": i.addr, "ordinal": i.ordinal,
            "source": "rustre_loader::ImportInfo::ordinal"
        }).to_string()))
    }
}

pub struct LoaderExportInfoNamedTool;
impl LoaderExportInfoNamedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_export_info_named".to_string(),
            description: "Construct rustre_loader::ExportInfo::named.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"addr":{"type":"integer"},"ordinal":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderExportInfoNamedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("Export").to_string();
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let ord = args.get("ordinal").and_then(Value::as_u64).unwrap_or(1) as u16;
        let e = rustre_loader::ExportInfo::named(name, addr, ord);
        Ok(ToolResult::text(json!({
            "name": e.name, "addr": e.addr, "ordinal": e.ordinal, "forwarded_to": e.forwarded_to,
            "source": "rustre_loader::ExportInfo::named"
        }).to_string()))
    }
}

pub struct LoaderExportInfoForwardedTool;
impl LoaderExportInfoForwardedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_export_info_forwarded".to_string(),
            description: "Construct rustre_loader::ExportInfo::forwarded.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"ordinal":{"type":"integer"},"target":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderExportInfoForwardedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("Fwd").to_string();
        let ord = args.get("ordinal").and_then(Value::as_u64).unwrap_or(1) as u16;
        let target = args.get("target").and_then(Value::as_str).unwrap_or("NTDLL.RtlAllocateHeap").to_string();
        let e = rustre_loader::ExportInfo::forwarded(name, ord, target);
        Ok(ToolResult::text(json!({
            "name": e.name, "addr": e.addr, "ordinal": e.ordinal, "forwarded_to": e.forwarded_to,
            "source": "rustre_loader::ExportInfo::forwarded"
        }).to_string()))
    }
}

pub struct LoaderMultiFormatRegistryNewTool;
impl LoaderMultiFormatRegistryNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_multi_format_registry_new".to_string(),
            description: "Empty MultiFormatRegistry len/is_empty.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderMultiFormatRegistryNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_loader::MultiFormatRegistry::new();
        Ok(ToolResult::text(json!({
            "len": r.len(), "is_empty": r.is_empty(), "loader_names": r.loader_names(),
            "source": "rustre_loader::MultiFormatRegistry::new"
        }).to_string()))
    }
}

pub struct LoaderMultiLoaderInputToBytesTool;
impl LoaderMultiLoaderInputToBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_multi_loader_input_to_bytes".to_string(),
            description: "MultiLoaderInput::Bytes -> to_bytes().".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderMultiLoaderInputToBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let input = rustre_loader::MultiLoaderInput::Bytes(data);
        let out = input.to_bytes().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "len": out.len(),
            "source": "rustre_loader::MultiLoaderInput::to_bytes"
        }).to_string()))
    }
}

pub struct LoaderFormatDetectorAllFlagsTool;
impl LoaderFormatDetectorAllFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_format_detector_all_flags".to_string(),
            description: "FormatDetector detect + is_elf/pe/macho/java in one call.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderFormatDetectorAllFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let d = rustre_loader::FormatDetector::new();
        Ok(ToolResult::text(json!({
            "format": d.detect(&data).to_string(),
            "is_elf": d.is_elf(&data),
            "is_pe": d.is_pe(&data),
            "is_macho": d.is_macho(&data),
            "is_java_class": d.is_java_class(&data),
            "bytes": data.len(),
            "source": "rustre_loader::FormatDetector"
        }).to_string()))
    }
}

pub struct LoaderRichLoadResultTotalVsizeTool;
impl LoaderRichLoadResultTotalVsizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_rich_load_result_total_virtual_size".to_string(),
            description: "RichLoadResult::total_virtual_size over provided sections.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "sections":{"type":"array","items":{"type":"object"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderRichLoadResultTotalVsizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut r = rustre_loader::RichLoadResult::new(Vec::new());
        if let Some(arr) = args.get("sections").and_then(Value::as_array) {
            for s in arr {
                let name = s.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let va = s.get("virtual_addr").and_then(Value::as_u64).unwrap_or(0);
                let vs = s.get("virtual_size").and_then(Value::as_u64).unwrap_or(0);
                r = r.with_section(rustre_loader::SectionInfo::new(name, va, vs, 0, 0, 0));
            }
        }
        Ok(ToolResult::text(json!({
            "total_virtual_size": r.total_virtual_size(),
            "section_count": r.sections.len(),
            "source": "rustre_loader::RichLoadResult::total_virtual_size"
        }).to_string()))
    }
}

pub struct LoaderRichLoadResultSectionAtTool;
impl LoaderRichLoadResultSectionAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_rich_load_result_section_at".to_string(),
            description: "RichLoadResult::section_at(va).".to_string(),
            input_schema: json!({"type":"object","properties":{
                "va":{"type":"integer"},
                "sections":{"type":"array","items":{"type":"object"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderRichLoadResultSectionAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let va = args.get("va").and_then(Value::as_u64).unwrap_or(0);
        let mut r = rustre_loader::RichLoadResult::new(Vec::new());
        if let Some(arr) = args.get("sections").and_then(Value::as_array) {
            for s in arr {
                let name = s.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let sva = s.get("virtual_addr").and_then(Value::as_u64).unwrap_or(0);
                let vs = s.get("virtual_size").and_then(Value::as_u64).unwrap_or(0);
                r = r.with_section(rustre_loader::SectionInfo::new(name, sva, vs, 0, 0, 0));
            }
        }
        let hit = r.section_at(va).map(|s| json!({
            "name": s.name, "virtual_addr": s.virtual_addr, "virtual_size": s.virtual_size
        }));
        Ok(ToolResult::text(json!({
            "va": va, "hit": hit,
            "source": "rustre_loader::RichLoadResult::section_at"
        }).to_string()))
    }
}

pub struct LoaderRichLoadResultHashesTool;
impl LoaderRichLoadResultHashesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "loader_rich_load_result_hashes".to_string(),
            description: "RichLoadResult::sha256 + md5.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for LoaderRichLoadResultHashesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let r = rustre_loader::RichLoadResult::new(data);
        Ok(ToolResult::text(json!({
            "sha256": r.sha256(), "md5": r.md5(), "len": r.data.len(),
            "source": "rustre_loader::RichLoadResult::{sha256,md5}"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (LoaderCoreMd5Tool::definition(), Box::new(LoaderCoreMd5Tool)),
        (LoaderFormatDetectorTool::definition(), Box::new(LoaderFormatDetectorTool)),
        (LoaderAutoLoaderDetectTool::definition(), Box::new(LoaderAutoLoaderDetectTool)),
        (LoaderCoreSha256Tool::definition(), Box::new(LoaderCoreSha256Tool)),
        (LoaderLuaIsBytecodeTool::definition(), Box::new(LoaderLuaIsBytecodeTool)),
        (LoaderLuaOpcodeNameTool::definition(), Box::new(LoaderLuaOpcodeNameTool)),
        (LoaderLuaReadStringTool::definition(), Box::new(LoaderLuaReadStringTool)),
        (LoaderFirmwareDetectKindTool::definition(), Box::new(LoaderFirmwareDetectKindTool)),
        (LoaderFirmwareDetectBinaryArchTool::definition(), Box::new(LoaderFirmwareDetectBinaryArchTool)),
        (LoaderFirmwareDetectRtosTool::definition(), Box::new(LoaderFirmwareDetectRtosTool)),
        (LoaderOleIsOleTool::definition(), Box::new(LoaderOleIsOleTool)),
        (LoaderOleListStreamsTool::definition(), Box::new(LoaderOleListStreamsTool)),
        (LoaderOleExtractMacrosTool::definition(), Box::new(LoaderOleExtractMacrosTool)),
        (LoaderPdfVersionTool::definition(), Box::new(LoaderPdfVersionTool)),
        (LoaderPdfHasJavascriptTool::definition(), Box::new(LoaderPdfHasJavascriptTool)),
        (LoaderPdfHasEmbeddedFilesTool::definition(), Box::new(LoaderPdfHasEmbeddedFilesTool)),
        (LoaderAndroidIsApkTool::definition(), Box::new(LoaderAndroidIsApkTool)),
        (LoaderAndroidIsVdexTool::definition(), Box::new(LoaderAndroidIsVdexTool)),
        (LoaderAndroidAdler32Tool::definition(), Box::new(LoaderAndroidAdler32Tool)),
        (LoaderWasmParseTool::definition(), Box::new(LoaderWasmParseTool)),
        (LoaderWasmStatsTool::definition(), Box::new(LoaderWasmStatsTool)),
        (LoaderWasmOpcodeMnemonicTool::definition(), Box::new(LoaderWasmOpcodeMnemonicTool)),
        (LoaderLuajitIsLuajitTool::definition(), Box::new(LoaderLuajitIsLuajitTool)),
        (LoaderLuajitReadUleb128Tool::definition(), Box::new(LoaderLuajitReadUleb128Tool)),
        (LoaderLuajitReadSleb128Tool::definition(), Box::new(LoaderLuajitReadSleb128Tool)),
        (LoaderConsoleDetectFormatTool::definition(), Box::new(LoaderConsoleDetectFormatTool)),
        (LoaderConsoleXorChecksumTool::definition(), Box::new(LoaderConsoleXorChecksumTool)),
        (LoaderConsoleIsNesTool::definition(), Box::new(LoaderConsoleIsNesTool)),
        (LoaderDotnetHasClrHeaderTool::definition(), Box::new(LoaderDotnetHasClrHeaderTool)),
        (LoaderDotnetIsDotnetTool::definition(), Box::new(LoaderDotnetIsDotnetTool)),
        (LoaderDotnetReadCompressedUintTool::definition(), Box::new(LoaderDotnetReadCompressedUintTool)),
        (LoaderPeIsSignedTool::definition(), Box::new(LoaderPeIsSignedTool)),
        (LoaderPePdbPathTool::definition(), Box::new(LoaderPePdbPathTool)),
        (LoaderPeEntryPointsTool::definition(), Box::new(LoaderPeEntryPointsTool)),
        (LoaderElfGnuHashStrTool::definition(), Box::new(LoaderElfGnuHashStrTool)),
        (LoaderElfGnuHashBytesTool::definition(), Box::new(LoaderElfGnuHashBytesTool)),
        (LoaderElfInfoSummaryTool::definition(), Box::new(LoaderElfInfoSummaryTool)),
        (LoaderMachoArchFromCputypeTool::definition(), Box::new(LoaderMachoArchFromCputypeTool)),
        (LoaderMachoSubtypeNameTool::definition(), Box::new(LoaderMachoSubtypeNameTool)),
        (LoaderMachoParseSummaryTool::definition(), Box::new(LoaderMachoParseSummaryTool)),
        (LoaderJavaIsClassTool::definition(), Box::new(LoaderJavaIsClassTool)),
        (LoaderJavaIsJarTool::definition(), Box::new(LoaderJavaIsJarTool)),
        (LoaderJavaParseClassTool::definition(), Box::new(LoaderJavaParseClassTool)),
        (LoaderCoordinatorNewTool::definition(), Box::new(LoaderCoordinatorNewTool)),
        (LoaderCoordinatorNewWithRegistryTool::definition(), Box::new(LoaderCoordinatorNewWithRegistryTool)),
        (LoaderDotnetHasClrHeaderWireTool::definition(), Box::new(LoaderDotnetHasClrHeaderWireTool)),
        (LoaderDotnetIsDotnetWireTool::definition(), Box::new(LoaderDotnetIsDotnetWireTool)),
        (LoaderAndroidIsDexTool::definition(), Box::new(LoaderAndroidIsDexTool)),
        (LoaderAndroidVerifyDexChecksumTool::definition(), Box::new(LoaderAndroidVerifyDexChecksumTool)),
        (LoaderElfParseInfoTool::definition(), Box::new(LoaderElfParseInfoTool)),
        (LoaderElfPltEntriesTool::definition(), Box::new(LoaderElfPltEntriesTool)),
        (LoaderMachoParseTool::definition(), Box::new(LoaderMachoParseTool)),
        (LoaderMachoParseFatTool::definition(), Box::new(LoaderMachoParseFatTool)),
        (LoaderPeParseInfoTool::definition(), Box::new(LoaderPeParseInfoTool)),
        (LoaderPeImportsFromDllTool::definition(), Box::new(LoaderPeImportsFromDllTool)),
        (LoaderIsElfTool::definition(), Box::new(LoaderIsElfTool)),
        (LoaderIsPeTool::definition(), Box::new(LoaderIsPeTool)),
        (LoaderIsMachoTool::definition(), Box::new(LoaderIsMachoTool)),
        (LoaderIsJavaClassTool::definition(), Box::new(LoaderIsJavaClassTool)),
        (LoaderHubCoordinatorNewEmptyTool::definition(), Box::new(LoaderHubCoordinatorNewEmptyTool)),
        (LoaderPipelineNewTool::definition(), Box::new(LoaderPipelineNewTool)),
        (LoaderPipelineDetectFormatTool::definition(), Box::new(LoaderPipelineDetectFormatTool)),
        (LoaderMultiFormatRegistryLenTool::definition(), Box::new(LoaderMultiFormatRegistryLenTool)),
        (LoaderMultiFormatProbeAllTool::definition(), Box::new(LoaderMultiFormatProbeAllTool)),
        (LoaderRichLoadResultAutoTool::definition(), Box::new(LoaderRichLoadResultAutoTool)),
        (LoaderRichLoadResultNewTool::definition(), Box::new(LoaderRichLoadResultNewTool)),
        (LoaderFormatDetectorNewEmptyTool::definition(), Box::new(LoaderFormatDetectorNewEmptyTool)),
        (LoaderPipelineNameTool::definition(), Box::new(LoaderPipelineNameTool)),
        (LoaderPipelineLoaderCountTool::definition(), Box::new(LoaderPipelineLoaderCountTool)),
        (LoaderCoordinatorLoaderCountTool::definition(), Box::new(LoaderCoordinatorLoaderCountTool)),
        (LoaderMultiFormatRegistryLoaderNamesTool::definition(), Box::new(LoaderMultiFormatRegistryLoaderNamesTool)),
        (LoaderMultiFormatRegistryIsEmptyTool::definition(), Box::new(LoaderMultiFormatRegistryIsEmptyTool)),
        (LoaderMultiFormatRegistryFindTool::definition(), Box::new(LoaderMultiFormatRegistryFindTool)),
        (LoaderDefaultMultiFormatRegistryCountTool::definition(), Box::new(LoaderDefaultMultiFormatRegistryCountTool)),
        (LoaderFormatDetectorProbeAllBoolsTool::definition(), Box::new(LoaderFormatDetectorProbeAllBoolsTool)),
        (LoaderDetectedFormatDisplayTool::definition(), Box::new(LoaderDetectedFormatDisplayTool)),
        (LoaderSectionInfoNewTool::definition(), Box::new(LoaderSectionInfoNewTool)),
        (LoaderSymbolInfoNewTool::definition(), Box::new(LoaderSymbolInfoNewTool)),
        (LoaderImportInfoNamedTool::definition(), Box::new(LoaderImportInfoNamedTool)),
        (LoaderImportInfoOrdinalTool::definition(), Box::new(LoaderImportInfoOrdinalTool)),
        (LoaderExportInfoNamedTool::definition(), Box::new(LoaderExportInfoNamedTool)),
        (LoaderExportInfoForwardedTool::definition(), Box::new(LoaderExportInfoForwardedTool)),
        (LoaderMultiFormatRegistryNewTool::definition(), Box::new(LoaderMultiFormatRegistryNewTool)),
        (LoaderMultiLoaderInputToBytesTool::definition(), Box::new(LoaderMultiLoaderInputToBytesTool)),
        (LoaderFormatDetectorAllFlagsTool::definition(), Box::new(LoaderFormatDetectorAllFlagsTool)),
        (LoaderRichLoadResultTotalVsizeTool::definition(), Box::new(LoaderRichLoadResultTotalVsizeTool)),
        (LoaderRichLoadResultSectionAtTool::definition(), Box::new(LoaderRichLoadResultSectionAtTool)),
        (LoaderRichLoadResultHashesTool::definition(), Box::new(LoaderRichLoadResultHashesTool)),
    ]
}
