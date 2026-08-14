//! Built-in workflow templates for common RE analysis tasks.
//!
//! Each template produces a validated [`WorkflowDef`] ready for execution.
//!
//! Available templates:
//! - `malware_analysis` — Full malware triage pipeline.
//! - `pe_deep_dive` — Detailed PE analysis (imports, exports, sections, FLIRT).
//! - `apk_analysis` — Android APK analysis (smali, dex, manifest).
//! - `network_capture_analysis` — PCAP dissection and IOC extraction.
//! - `crash_triage` — Crash dump analysis with exploitability scoring.
//! - `yara_hunt` — YARA rule generation and corpus scan.
//! - `dotnet_analysis` — .NET assembly inspection.
//! - `shellcode_analysis` — Shellcode disassembly and emulation.

use std::time::Duration;

use serde_json::json;

use crate::workflow_dsl::{
    DslCondition, DslInput, DslStepBuilder, WorkflowBuilder, WorkflowDef,
};
use crate::{ErrorStrategy, WorkflowError};

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn step(id: &str, name: &str, cap: &str) -> DslStepBuilder {
    DslStepBuilder::new(id, name, cap)
}


// ─── malware_analysis ────────────────────────────────────────────────────────

/// Full malware triage workflow.
///
/// Steps:
/// 1. `triage`      — Basic file triage (magic, entropy, hashes).
/// 2. `pe_parse`    — PE header / section / import parsing (conditional on PE).
/// 3. `sandbox`     — Dynamic sandbox execution.
/// 4. `yara_scan`   — YARA scan against known-malware rules.
/// 5. `strings`     — String extraction and clustering.
/// 6. `ioc_extract` — IOC extraction from all prior results.
/// 7. `vt_lookup`   — `VirusTotal` hash lookup.
/// 8. `report`      — Aggregate report generation.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn malware_analysis() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("malware_analysis", "Malware Analysis")
        .version("1.0.0")
        .description("Full malware triage and analysis pipeline")
        .error_strategy(ErrorStrategy::Continue)
        .global_timeout(Duration::from_hours(1))
        .step(
            step("triage", "File Triage", "file.triage")
                .timeout(Duration::from_secs(30))
                .param("compute_hashes", json!(true))
                .param("entropy_blocks", json!(256))
                .build(),
        )
        .then(
            step("pe_parse", "PE Parser", "pe.parse")
                .condition(DslCondition::OutputEquals {
                    step: "triage".into(),
                    key: "file_type".into(),
                    value: json!("PE"),
                })
                .timeout(Duration::from_mins(1))
                .optional()
                .build(),
        )
        .then(
            step("sandbox", "Sandbox Execution", "sandbox.run")
                .retries(1, Duration::from_secs(10))
                .timeout(Duration::from_mins(5))
                .param("timeout_seconds", json!(180))
                .param("network", json!("simulated"))
                .build(),
        )
        .then(
            step("yara_scan", "YARA Scan", "yara.scan")
                .input(DslInput::StepOutput("triage".into()))
                .param("rule_sets", json!(["malware", "apt", "ransomware"]))
                .build(),
        )
        .then(
            step("strings", "String Extraction", "strings.extract")
                .input(DslInput::StepOutput("triage".into()))
                .param("min_length", json!(4))
                .param("encodings", json!(["ascii", "utf16le", "utf16be"]))
                .optional()
                .build(),
        )
        .then(
            step("ioc_extract", "IOC Extraction", "ioc.extract")
                .input(DslInput::Merge(vec![
                    "sandbox".into(),
                    "strings".into(),
                    "yara_scan".into(),
                ]))
                .depends_on("sandbox")
                .depends_on("strings")
                .depends_on("yara_scan")
                .build(),
        )
        .then(
            step("vt_lookup", "VirusTotal Lookup", "ti.virustotal")
                .input(DslInput::StepArtifact {
                    step: "triage".into(),
                    artifact: "sha256".into(),
                })
                .retries(3, Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .optional()
                .build(),
        )
        .then(
            step("report", "Report Generation", "report.generate")
                .input(DslInput::Merge(vec![
                    "triage".into(),
                    "pe_parse".into(),
                    "sandbox".into(),
                    "yara_scan".into(),
                    "ioc_extract".into(),
                    "vt_lookup".into(),
                ]))
                .depends_on("triage")
                .depends_on("ioc_extract")
                .depends_on("vt_lookup")
                .param("formats", json!(["html", "json", "pdf"]))
                .build(),
        )
        .build()
}

// ─── pe_deep_dive ─────────────────────────────────────────────────────────────

/// Detailed PE analysis workflow.
///
/// Steps:
/// 1. `triage`      — Hash + magic check.
/// 2. `pe_header`   — Full PE header dump.
/// 3. `imports`     — Import analysis and suspicious API flagging.
/// 4. `exports`     — Export table analysis.
/// 5. `sections`    — Section analysis (entropy, characteristics).
/// 6. `resources`   — Resource extraction.
/// 7. `flirt_apply` — FLIRT signature application.
/// 8. `pdb_fetch`   — Download / parse PDB if available.
/// 9. `cfg_analysis`— Control-flow graph generation.
/// 10. `report`     — Deep-dive report.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn pe_deep_dive() -> Result<WorkflowDef, WorkflowError> {
    let parallel_analysis = vec![
        step("imports", "Import Analysis", "pe.imports")
            .timeout(Duration::from_mins(1))
            .param("flag_suspicious", json!(true))
            .build(),
        step("exports", "Export Analysis", "pe.exports")
            .timeout(Duration::from_secs(30))
            .build(),
        step("sections", "Section Analysis", "pe.sections")
            .param("entropy_check", json!(true))
            .build(),
        step("resources", "Resource Extraction", "pe.resources")
            .timeout(Duration::from_mins(1))
            .optional()
            .build(),
    ];

    WorkflowBuilder::new("pe_deep_dive", "PE Deep Dive")
        .version("1.0.0")
        .description("Comprehensive PE file analysis")
        .step(
            step("triage", "File Triage", "file.triage")
                .param("compute_hashes", json!(true))
                .build(),
        )
        .then(step("pe_header", "PE Header", "pe.parse").timeout(Duration::from_secs(30)).build())
        .parallel(
            parallel_analysis,
            Some(
                step("analysis_merge", "Analysis Merge", "workflow.merge")
                    .build(),
            ),
        )
        .then(
            step("flirt_apply", "FLIRT Signatures", "flirt.apply")
                .timeout(Duration::from_mins(2))
                .optional()
                .build(),
        )
        .then(
            step("pdb_fetch", "PDB Fetch", "symbols.pdb")
                .input(DslInput::StepArtifact {
                    step: "triage".into(),
                    artifact: "guid_age".into(),
                })
                .retries(2, Duration::from_secs(5))
                .optional()
                .build(),
        )
        .then(
            step("cfg_analysis", "CFG Analysis", "analysis.cfg")
                .timeout(Duration::from_mins(5))
                .param("max_functions", json!(10_000))
                .build(),
        )
        .then(
            step("report", "Deep Dive Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── apk_analysis ─────────────────────────────────────────────────────────────

/// Android APK analysis workflow.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn apk_analysis() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("apk_analysis", "APK Analysis")
        .version("1.0.0")
        .description("Android APK static and dynamic analysis")
        .error_strategy(ErrorStrategy::Continue)
        .step(
            step("unpack", "APK Unpack", "mobile.apk.unpack")
                .timeout(Duration::from_mins(1))
                .build(),
        )
        .then(
            step("manifest", "Manifest Parser", "mobile.android.manifest")
                .timeout(Duration::from_secs(30))
                .build(),
        )
        .parallel(
            vec![
                step("dex_disasm", "DEX Disassembly", "mobile.dex.disasm")
                    .timeout(Duration::from_mins(3))
                    .build(),
                step("smali_decompile", "Smali Decompile", "mobile.smali")
                    .timeout(Duration::from_mins(3))
                    .optional()
                    .build(),
                step("cert_check", "Certificate Check", "mobile.cert")
                    .timeout(Duration::from_secs(30))
                    .build(),
                step("native_libs", "Native Library Analysis", "pe.parse")
                    .timeout(Duration::from_mins(2))
                    .optional()
                    .build(),
            ],
            Some(step("apk_merge", "APK Analysis Merge", "workflow.merge").build()),
        )
        .then(
            step("vuln_scan", "Vulnerability Scan", "analysis.vuln")
                .param("checks", json!(["sql_injection", "hardcoded_secrets", "insecure_crypto"]))
                .build(),
        )
        .then(
            step("yara_scan", "YARA Scan", "yara.scan")
                .param("rule_sets", json!(["android_malware"]))
                .optional()
                .build(),
        )
        .then(
            step("report", "APK Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── network_capture_analysis ─────────────────────────────────────────────────

/// PCAP network capture analysis.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn network_capture_analysis() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("network_capture", "Network Capture Analysis")
        .version("1.0.0")
        .description("PCAP dissection and IOC extraction")
        .step(
            step("pcap_parse", "PCAP Parse", "net.pcap.parse")
                .timeout(Duration::from_mins(2))
                .param("max_packets", json!(1_000_000))
                .build(),
        )
        .then(
            step("flow_reconstruct", "Flow Reconstruction", "net.pcap.flows")
                .timeout(Duration::from_mins(1))
                .build(),
        )
        .parallel(
            vec![
                step("dns_extract", "DNS Extraction", "net.dns")
                    .input(DslInput::StepOutput("pcap_parse".into()))
                    .build(),
                step("http_extract", "HTTP Extraction", "net.http")
                    .input(DslInput::StepOutput("flow_reconstruct".into()))
                    .timeout(Duration::from_mins(2))
                    .build(),
                step("tls_analysis", "TLS Analysis", "net.tls")
                    .input(DslInput::StepOutput("pcap_parse".into()))
                    .optional()
                    .build(),
                step("file_carve", "File Carving", "net.carve")
                    .input(DslInput::StepOutput("flow_reconstruct".into()))
                    .timeout(Duration::from_mins(2))
                    .optional()
                    .build(),
            ],
            Some(step("net_merge", "Network Merge", "workflow.merge").build()),
        )
        .then(
            step("ioc_extract", "IOC Extraction", "ioc.extract")
                .param("ioc_types", json!(["ip", "domain", "url", "hash"]))
                .build(),
        )
        .then(
            step("geo_lookup", "GeoIP Lookup", "ti.geoip")
                .input(DslInput::StepArtifact {
                    step: "ioc_extract".into(),
                    artifact: "ip_addresses".into(),
                })
                .retries(2, Duration::from_secs(3))
                .optional()
                .build(),
        )
        .then(
            step("report", "Network Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── crash_triage ─────────────────────────────────────────────────────────────

/// Crash dump triage workflow.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn crash_triage() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("crash_triage", "Crash Triage")
        .version("1.0.0")
        .description("Crash dump analysis with exploitability scoring")
        .step(
            step("dump_parse", "Dump Parse", "debug.minidump.parse")
                .timeout(Duration::from_secs(30))
                .build(),
        )
        .then(
            step("exception_decode", "Exception Decode", "debug.exception.decode")
                .build(),
        )
        .parallel(
            vec![
                step("stack_trace", "Stack Trace", "debug.stack")
                    .build(),
                step("module_list", "Module List", "debug.modules")
                    .build(),
                step("heap_analysis", "Heap Analysis", "debug.heap")
                    .timeout(Duration::from_mins(1))
                    .optional()
                    .build(),
            ],
            Some(step("crash_merge", "Crash Merge", "workflow.merge").build()),
        )
        .then(
            step("exploitability", "Exploitability", "debug.exploitability")
                .timeout(Duration::from_mins(1))
                .build(),
        )
        .then(
            step("symbol_resolve", "Symbol Resolution", "symbols.resolve")
                .retries(2, Duration::from_secs(5))
                .optional()
                .build(),
        )
        .then(
            step("dedup_check", "Dedup Check", "debug.dedup")
                .param("algorithm", json!("exploitable_hash"))
                .build(),
        )
        .then(
            step("report", "Crash Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── yara_hunt ────────────────────────────────────────────────────────────────

/// YARA rule generation and corpus scan workflow.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn yara_hunt() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("yara_hunt", "YARA Hunt")
        .version("1.0.0")
        .description("Generate YARA rules and scan a corpus")
        .step(
            step("strings_extract", "String Extraction", "strings.extract")
                .param("min_length", json!(6))
                .param("filter_common", json!(true))
                .build(),
        )
        .then(
            step("byte_patterns", "Byte Pattern Mining", "analysis.bytepattern")
                .param("window_size", json!(16))
                .build(),
        )
        .then(
            step("rule_generate", "Rule Generation", "yara.generate")
                .depends_on("strings_extract")
                .depends_on("byte_patterns")
                .input(DslInput::Merge(vec!["strings_extract".into(), "byte_patterns".into()]))
                .param("condition", json!("any of them"))
                .build(),
        )
        .then(
            step("rule_validate", "Rule Validation", "yara.validate")
                .timeout(Duration::from_secs(30))
                .build(),
        )
        .then(
            step("corpus_scan", "Corpus Scan", "yara.scan")
                .timeout(Duration::from_mins(10))
                .retries(1, Duration::from_secs(10))
                .param("parallel", json!(true))
                .build(),
        )
        .then(
            step("report", "Hunt Report", "report.generate")
                .param("format", json!("json"))
                .build(),
        )
        .build()
}

// ─── dotnet_analysis ─────────────────────────────────────────────────────────

/// .NET assembly analysis workflow.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn dotnet_analysis() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("dotnet_analysis", ".NET Analysis")
        .version("1.0.0")
        .description("Full .NET assembly inspection and deobfuscation")
        .step(
            step("metadata_parse", "Metadata Parse", "dotnet.metadata")
                .timeout(Duration::from_secs(30))
                .build(),
        )
        .parallel(
            vec![
                step("il_disasm", "IL Disassembly", "dotnet.il.disasm")
                    .timeout(Duration::from_mins(2))
                    .build(),
                step("resource_extract", "Resource Extract", "dotnet.resources")
                    .timeout(Duration::from_mins(1))
                    .optional()
                    .build(),
                step("strong_name", "Strong Name Check", "dotnet.strongname")
                    .build(),
            ],
            Some(step("dotnet_merge", "Dotnet Merge", "workflow.merge").build()),
        )
        .then(
            step("deobf_detect", "Obfuscation Detection", "deobf.detect")
                .param("methods", json!(["control_flow", "rename", "string_enc"]))
                .build(),
        )
        .then(
            step("deobf_apply", "Deobfuscation", "deobf.apply")
                .condition(DslCondition::PriorSucceeded {
                    step: "deobf_detect".into(),
                })
                .timeout(Duration::from_mins(5))
                .optional()
                .build(),
        )
        .then(
            step("decompile", "Decompilation", "dotnet.decompile")
                .timeout(Duration::from_mins(5))
                .param("language", json!("csharp"))
                .build(),
        )
        .then(
            step("report", "Dotnet Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── shellcode_analysis ──────────────────────────────────────────────────────

/// Shellcode analysis workflow.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn shellcode_analysis() -> Result<WorkflowDef, WorkflowError> {
    WorkflowBuilder::new("shellcode_analysis", "Shellcode Analysis")
        .version("1.0.0")
        .description("Shellcode disassembly, emulation, and deobfuscation")
        .step(
            step("triage", "Shellcode Triage", "file.triage")
                .param("compute_hashes", json!(true))
                .build(),
        )
        .then(
            step("disasm", "Disassembly", "disasm.auto")
                .param("arch_detect", json!(true))
                .param("modes", json!(["x86", "x64", "arm", "arm64"]))
                .timeout(Duration::from_mins(1))
                .build(),
        )
        .then(
            step("emulate", "Unicorn Emulation", "emu.shellcode")
                .timeout(Duration::from_mins(2))
                .param("max_insn", json!(100_000))
                .param("resolve_apis", json!(true))
                .build(),
        )
        .parallel(
            vec![
                step("smc_detect", "Self-Modifying Code", "deobf.smc")
                    .input(DslInput::StepOutput("emulate".into()))
                    .build(),
                step("api_hash_resolve", "API Hash Resolution", "analysis.apihash")
                    .input(DslInput::StepOutput("disasm".into()))
                    .optional()
                    .build(),
                step("strings_extract", "Strings", "strings.extract")
                    .input(DslInput::StepOutput("triage".into()))
                    .build(),
            ],
            Some(step("sc_merge", "Shellcode Merge", "workflow.merge").build()),
        )
        .then(
            step("ioc_extract", "IOC Extraction", "ioc.extract")
                .build(),
        )
        .then(
            step("report", "Shellcode Report", "report.generate")
                .param("format", json!("html"))
                .build(),
        )
        .build()
}

// ─── Template registry ────────────────────────────────────────────────────────

/// Available template names.
pub const TEMPLATE_NAMES: &[&str] = &[
    "malware_analysis",
    "pe_deep_dive",
    "apk_analysis",
    "network_capture_analysis",
    "crash_triage",
    "yara_hunt",
    "dotnet_analysis",
    "shellcode_analysis",
];

/// Instantiate a workflow template by name.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn instantiate(name: &str) -> Result<WorkflowDef, WorkflowError> {
    match name {
        "malware_analysis" => malware_analysis(),
        "pe_deep_dive" => pe_deep_dive(),
        "apk_analysis" => apk_analysis(),
        "network_capture_analysis" => network_capture_analysis(),
        "crash_triage" => crash_triage(),
        "yara_hunt" => yara_hunt(),
        "dotnet_analysis" => dotnet_analysis(),
        "shellcode_analysis" => shellcode_analysis(),
        _ => Err(WorkflowError::InvalidWorkflow(format!(
            "Unknown template: '{}'. Available: {}",
            name,
            TEMPLATE_NAMES.join(", ")
        ))),
    }
}

/// Return metadata for all templates.
#[must_use]
pub fn list_templates() -> Vec<TemplateInfo> {
    TEMPLATE_NAMES
        .iter()
        .filter_map(|&name| {
            let wf = instantiate(name).ok()?;
            Some(TemplateInfo {
                id: wf.id.clone(),
                name: wf.name.clone(),
                version: wf.version.clone(),
                description: wf.description.clone(),
                step_count: wf.steps.len(),
                tags: wf.tags,
            })
        })
        .collect()
}

/// Brief info about a template (no full step list).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub step_count: usize,
    pub tags: Vec<String>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malware_analysis_valid() {
        let wf = malware_analysis().unwrap();
        assert!(wf.steps.len() >= 7);
        wf.validate().unwrap();
    }

    #[test]
    fn test_pe_deep_dive_valid() {
        let wf = pe_deep_dive().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_apk_analysis_valid() {
        let wf = apk_analysis().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_network_capture_valid() {
        let wf = network_capture_analysis().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_crash_triage_valid() {
        let wf = crash_triage().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_yara_hunt_valid() {
        let wf = yara_hunt().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_dotnet_analysis_valid() {
        let wf = dotnet_analysis().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_shellcode_analysis_valid() {
        let wf = shellcode_analysis().unwrap();
        wf.validate().unwrap();
    }

    #[test]
    fn test_instantiate_all() {
        for name in TEMPLATE_NAMES {
            let result = instantiate(name);
            assert!(result.is_ok(), "Template '{}' failed: {:?}", name, result.err());
        }
    }

    #[test]
    fn test_instantiate_unknown() {
        let result = instantiate("nonexistent_template");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_templates() {
        let templates = list_templates();
        assert_eq!(templates.len(), TEMPLATE_NAMES.len());
        for t in &templates {
            assert!(t.step_count > 0);
        }
    }

    #[test]
    fn test_topological_order_all_templates() {
        for name in TEMPLATE_NAMES {
            let wf = instantiate(name).unwrap();
            let order = wf.topological_order();
            assert!(
                order.is_ok(),
                "Template '{}' has cycle: {:?}",
                name,
                order.err()
            );
        }
    }
}
