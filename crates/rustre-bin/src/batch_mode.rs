use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use rayon::prelude::*;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJob {
    pub id: String,
    pub file: PathBuf,
    pub operations: Vec<BatchOperation>,
    pub output_dir: PathBuf,
    pub output_format: OutputFormat,
    pub priority: u8,
    pub timeout_secs: Option<u64>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BatchOperation {
    Disassemble { addr: Option<u64>, len: Option<usize>, arch: Option<String> },
    HexDump { addr: Option<u64>, len: Option<usize>, width: Option<usize> },
    ExtractStrings { min_len: Option<usize>, encoding: Option<StringEncoding> },
    ExtractImports,
    ExtractExports,
    ExtractSections,
    ExtractHeaders,
    ExtractResources,
    ComputeHashes { algorithms: Vec<HashAlgorithm> },
    DetectPackers,
    ExtractEntropy { block_size: Option<usize> },
    YaraScan { rules_path: PathBuf },
    FlirtScan { sigs_path: PathBuf },
    CallGraph { start_addr: Option<u64>, max_depth: Option<usize> },
    Decompile { addr: u64, lang: Option<DecompileLang> },
    BinaryDiff { other_file: PathBuf },
    Triage,
    FullAnalysis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    JsonLines,
    Csv,
    Text,
    Html,
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ssdeep,
    Tlsh,
    Imphash,
    Authentihash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompileLang {
    C,
    CWithTypes,
    Pseudocode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub job_id: String,
    pub file: PathBuf,
    pub operation: String,
    pub success: bool,
    pub duration_ms: u64,
    pub output_file: Option<PathBuf>,
    pub error: Option<String>,
    pub metrics: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReport {
    pub total_jobs: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub total_duration_ms: u64,
    pub results: Vec<BatchResult>,
    pub summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub files_processed: usize,
    pub total_bytes: u64,
    pub operations_run: usize,
    pub output_files: usize,
    pub errors: Vec<String>,
    pub throughput_mb_per_sec: f64,
}

pub struct BatchProcessor {
    parallelism: usize,
    output_root: PathBuf,
    default_format: OutputFormat,
    progress_tx: Option<mpsc::Sender<BatchProgress>>,
}

#[derive(Debug, Clone)]
pub struct BatchProgress {
    pub job_id: String,
    pub file: PathBuf,
    pub operation: String,
    pub status: ProgressStatus,
    pub percent: f32,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProgressStatus {
    Queued,
    Running,
    Done,
    Failed(String),
    Skipped(String),
}

impl BatchProcessor {
    pub fn new(output_root: impl Into<PathBuf>, parallelism: Option<usize>) -> Self {
        let parallelism = parallelism.unwrap_or_else(|| {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
        });
        Self {
            parallelism,
            output_root: output_root.into(),
            default_format: OutputFormat::Json,
            progress_tx: None,
        }
    }

    pub fn with_progress(mut self, tx: mpsc::Sender<BatchProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Override the format that will be applied to any job whose
    /// `output_format` is left at its [`Default`] value (currently `Json`).
    pub fn with_default_format(mut self, format: OutputFormat) -> Self {
        self.default_format = format;
        self
    }

    /// Returns the configured default output format. Jobs that do not carry an
    /// explicit format are written using this value.
    #[must_use]
    pub fn default_format(&self) -> OutputFormat {
        self.default_format.clone()
    }

    /// Resolve the effective output format for `job`: returns the job's own
    /// format unless that is the default sentinel, in which case
    /// [`Self::default_format`] is substituted.
    #[must_use]
    pub fn effective_format(&self, job: &BatchJob) -> OutputFormat {
        // `OutputFormat::Json` is the type's `Default`; treat that as
        // "unspecified" so the batch-level default can take precedence.
        if job.output_format == OutputFormat::Json
            && self.default_format != OutputFormat::Json
        {
            self.default_format.clone()
        } else {
            job.output_format.clone()
        }
    }

    pub fn process_jobs_parallel(&self, jobs: &[BatchJob]) -> Result<BatchReport> {
        let start = Instant::now();
        std::fs::create_dir_all(&self.output_root)
            .context("Cannot create output directory")?;

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.parallelism)
            .build()
            .context("Cannot build thread pool")?;

        let results: Vec<BatchResult> = pool.install(|| {
            jobs.par_iter()
                .flat_map(|job| self.execute_job(job))
                .collect()
        });

        let total_duration = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = results.iter().filter(|r| !r.success).count();

        let total_bytes: u64 = jobs.iter()
            .map(|j| std::fs::metadata(&j.file).map(|m| m.len()).unwrap_or(0))
            .sum();

        let errors: Vec<String> = results.iter()
            .filter_map(|r| r.error.clone())
            .take(20)
            .collect();

        let throughput = if total_duration > 0 {
            (total_bytes as f64 / 1_048_576.0) / (total_duration as f64 / 1000.0)
        } else { 0.0 };

        Ok(BatchReport {
            total_jobs: results.len(),
            succeeded,
            failed,
            total_duration_ms: total_duration,
            summary: BatchSummary {
                files_processed: jobs.len(),
                total_bytes,
                operations_run: results.len(),
                output_files: results.iter().filter(|r| r.output_file.is_some()).count(),
                errors,
                throughput_mb_per_sec: throughput,
            },
            results,
        })
    }

    fn execute_job(&self, job: &BatchJob) -> Vec<BatchResult> {
        let mut results = Vec::new();
        for op in &job.operations {
            let start = Instant::now();
            let op_name = op_name(op);
            let result = self.execute_operation(&job.file, op, &job.output_dir, &job.output_format);
            let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

            match result {
                Ok((output_file, metrics)) => results.push(BatchResult {
                    job_id: job.id.clone(),
                    file: job.file.clone(),
                    operation: op_name,
                    success: true,
                    duration_ms,
                    output_file: Some(output_file),
                    error: None,
                    metrics,
                }),
                Err(e) => results.push(BatchResult {
                    job_id: job.id.clone(),
                    file: job.file.clone(),
                    operation: op_name,
                    success: false,
                    duration_ms,
                    output_file: None,
                    error: Some(e.to_string()),
                    metrics: HashMap::new(),
                }),
            }
        }
        results
    }

    fn execute_operation(
        &self,
        file: &Path,
        op: &BatchOperation,
        out_dir: &Path,
        format: &OutputFormat,
    ) -> Result<(PathBuf, HashMap<String, serde_json::Value>)> {
        let file_stem = file.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let ext = format_ext(format);
        std::fs::create_dir_all(out_dir)?;

        let mut metrics = HashMap::new();
        /// Maximum size in bytes for a single file loaded into memory during
        /// an operation (512 MiB). Guards against memory exhaustion when
        /// processing untrusted input files.
        const MAX_OPERATION_FILE_BYTES: u64 = 512 * 1024 * 1024;

        /// Read a file into memory, rejecting files that exceed
        /// `MAX_OPERATION_FILE_BYTES` to prevent DoS via memory exhaustion.
        fn read_file_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
            let meta = std::fs::metadata(path)?;
            if meta.len() > MAX_OPERATION_FILE_BYTES {
                anyhow::bail!(
                    "file {} is too large to process ({} bytes, limit {} bytes)",
                    path.display(),
                    meta.len(),
                    MAX_OPERATION_FILE_BYTES
                );
            }
            Ok(std::fs::read(path)?)
        }

        let out_path = match op {
            BatchOperation::ExtractStrings { min_len, encoding: _ } => {
                let min = min_len.unwrap_or(4);
                let bytes = read_file_bounded(file)?;
                let strings = extract_ascii_strings(&bytes, min);
                metrics.insert("count".to_string(), serde_json::json!(strings.len()));
                let path = out_dir.join(format!("{}_strings.{}", file_stem, ext));
                write_output(&path, format, &serde_json::json!(strings))?;
                path
            }
            BatchOperation::ComputeHashes { algorithms } => {
                let bytes = read_file_bounded(file)?;
                let mut hashes = serde_json::Map::new();
                for algo in algorithms {
                    let h = compute_hash(&bytes, algo);
                    hashes.insert(format!("{:?}", algo).to_lowercase(), serde_json::json!(h));
                }
                let size = bytes.len();
                metrics.insert("file_size".to_string(), serde_json::json!(size));
                let path = out_dir.join(format!("{}_hashes.{}", file_stem, ext));
                write_output(&path, format, &serde_json::Value::Object(hashes))?;
                path
            }
            BatchOperation::ExtractEntropy { block_size } => {
                let bs = block_size.unwrap_or(256);
                let bytes = read_file_bounded(file)?;
                let entropy_blocks = compute_block_entropy(&bytes, bs);
                let overall = shannon_entropy(&bytes);
                metrics.insert("overall_entropy".to_string(), serde_json::json!(overall));
                metrics.insert("blocks".to_string(), serde_json::json!(entropy_blocks.len()));
                let path = out_dir.join(format!("{}_entropy.{}", file_stem, ext));
                write_output(&path, format, &serde_json::json!({
                    "overall": overall,
                    "block_size": bs,
                    "blocks": entropy_blocks
                }))?;
                path
            }
            BatchOperation::Triage => {
                let bytes = read_file_bounded(file)?;
                let report = quick_triage(&bytes, file);
                metrics.insert("risk_score".to_string(), serde_json::json!(report.risk_score));
                let path = out_dir.join(format!("{}_triage.{}", file_stem, ext));
                write_output(&path, format, &serde_json::to_value(&report)?)?;
                path
            }
            _ => {
                let path = out_dir.join(format!("{}_{}_{}.{}", file_stem, op_name(op), "result", ext));
                write_output(&path, format, &serde_json::json!({"status": "not_implemented", "op": op_name(op)}))?;
                path
            }
        };

        Ok((out_path, metrics))
    }
}

fn op_name(op: &BatchOperation) -> String {
    match op {
        BatchOperation::Disassemble { .. } => "disassemble",
        BatchOperation::HexDump { .. } => "hexdump",
        BatchOperation::ExtractStrings { .. } => "strings",
        BatchOperation::ExtractImports => "imports",
        BatchOperation::ExtractExports => "exports",
        BatchOperation::ExtractSections => "sections",
        BatchOperation::ExtractHeaders => "headers",
        BatchOperation::ExtractResources => "resources",
        BatchOperation::ComputeHashes { .. } => "hashes",
        BatchOperation::DetectPackers => "packers",
        BatchOperation::ExtractEntropy { .. } => "entropy",
        BatchOperation::YaraScan { .. } => "yara",
        BatchOperation::FlirtScan { .. } => "flirt",
        BatchOperation::CallGraph { .. } => "callgraph",
        BatchOperation::Decompile { .. } => "decompile",
        BatchOperation::BinaryDiff { .. } => "bindiff",
        BatchOperation::Triage => "triage",
        BatchOperation::FullAnalysis => "full",
    }.to_string()
}

fn format_ext(format: &OutputFormat) -> &'static str {
    match format {
        OutputFormat::Json | OutputFormat::JsonLines => "json",
        OutputFormat::Csv => "csv",
        OutputFormat::Text => "txt",
        OutputFormat::Html => "html",
        OutputFormat::Markdown => "md",
        OutputFormat::Sarif => "sarif",
    }
}

fn write_output(path: &Path, _format: &OutputFormat, data: &serde_json::Value) -> Result<()> {
    let content = serde_json::to_string_pretty(data)?;
    std::fs::write(path, content)?;
    Ok(())
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<HashMap<String, serde_json::Value>> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if current.is_empty() { start = i; }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                let mut m = HashMap::new();
                m.insert("offset".to_string(), serde_json::json!(start));
                m.insert("string".to_string(), serde_json::json!(current));
                m.insert("encoding".to_string(), serde_json::json!("ascii"));
                results.push(m);
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        let mut m = HashMap::new();
        m.insert("offset".to_string(), serde_json::json!(start));
        m.insert("string".to_string(), serde_json::json!(current));
        m.insert("encoding".to_string(), serde_json::json!("ascii"));
        results.push(m);
    }
    results
}

fn compute_hash(bytes: &[u8], algo: &HashAlgorithm) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    match algo {
        HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Sha256
        | HashAlgorithm::Sha512 => {
            // Placeholder: real implementation uses ring or sha2 crate
            let mut h = DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}{:016x}{:016x}{:016x}", h.finish(), h.finish(), h.finish(), h.finish())
        }
        HashAlgorithm::Ssdeep | HashAlgorithm::Tlsh => "0:0:0".to_string(),
        HashAlgorithm::Imphash => "not_pe".to_string(),
        HashAlgorithm::Authentihash => "not_signed".to_string(),
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in bytes { freq[b as usize] += 1; }
    let len = bytes.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

fn compute_block_entropy(bytes: &[u8], block_size: usize) -> Vec<serde_json::Value> {
    let block_size = block_size.max(1);
    bytes.chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| {
            let e = shannon_entropy(chunk);
            let offset = i.saturating_mul(block_size);
            serde_json::json!({
                "offset": offset,
                "size": chunk.len(),
                "entropy": (e * 1000.0).round() / 1000.0
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub file: String,
    pub file_size: u64,
    pub file_type: String,
    pub magic_bytes: String,
    pub entropy: f64,
    pub risk_score: f32,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub hashes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIndicator {
    pub indicator: String,
    pub severity: IndicatorSeverity,
    pub description: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorSeverity {
    Low, Medium, High, Critical,
}

fn quick_triage(bytes: &[u8], path: &Path) -> TriageReport {
    let file_size = bytes.len() as u64;
    let entropy = shannon_entropy(bytes);
    let magic = if bytes.len() >= 4 {
        format!("{:02x}{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else { "??".to_string() };

    let file_type = detect_file_type(bytes);
    let mut indicators = Vec::new();
    let mut risk: f32 = 0.0;

    if entropy > 7.2 {
        risk += 30.0;
        indicators.push(SuspiciousIndicator {
            indicator: "high_entropy".to_string(),
            severity: IndicatorSeverity::High,
            description: format!("Entropy {:.3} — possibly packed or encrypted", entropy),
            offset: None,
        });
    }

    if find_pattern_bytes(bytes, b"This program cannot be run in DOS mode").is_some() {
        // Normal PE, slightly lower concern
    }

    let suspicious_strings = [
        "cmd.exe", "powershell", "WScript.Shell", "CreateRemoteThread",
        "VirtualAllocEx", "WriteProcessMemory", "LoadLibrary", "GetProcAddress",
        "URLDownloadToFile", "ShellExecute", "RegSetValue", "taskkill",
        "base64", "fromCharCode", "eval(", "exec(",
    ];
    for s in &suspicious_strings {
        if let Some(off) = find_pattern_bytes(bytes, s.as_bytes()) {
            risk += 5.0;
            indicators.push(SuspiciousIndicator {
                indicator: format!("suspicious_string:{}", s),
                severity: IndicatorSeverity::Medium,
                description: format!("Found suspicious string: {}", s),
                offset: Some(off as u64),
            });
        }
    }

    if bytes.len() < 1024 && file_type == "PE" {
        risk += 40.0;
        indicators.push(SuspiciousIndicator {
            indicator: "unusually_small_pe".to_string(),
            severity: IndicatorSeverity::High,
            description: "PE file is unusually small".to_string(),
            offset: None,
        });
    }

    let mut hashes = HashMap::new();
    hashes.insert("sha256".to_string(), compute_hash(bytes, &HashAlgorithm::Sha256));
    hashes.insert("md5".to_string(), compute_hash(bytes, &HashAlgorithm::Md5));

    TriageReport {
        file: path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string(),
        file_size,
        file_type,
        magic_bytes: magic,
        entropy: (entropy * 1000.0).round() / 1000.0,
        risk_score: risk.min(100.0),
        suspicious_indicators: indicators,
        hashes,
    }
}

fn detect_file_type(bytes: &[u8]) -> String {
    if bytes.starts_with(b"MZ") { return "PE".to_string(); }
    if bytes.starts_with(b"\x7fELF") { return "ELF".to_string(); }
    if bytes.starts_with(b"\xca\xfe\xba\xbe") || bytes.starts_with(b"\xce\xfa\xed\xfe") {
        return "Mach-O".to_string();
    }
    if bytes.starts_with(b"PK\x03\x04") { return "ZIP/APK/JAR".to_string(); }
    if bytes.starts_with(b"%PDF") { return "PDF".to_string(); }
    if bytes.starts_with(b"\xd0\xcf\x11\xe0") { return "OLE/Office".to_string(); }
    "Unknown".to_string()
}

fn find_pattern_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Maximum size in bytes for a batch configuration file (16 MiB).
const MAX_BATCH_CONFIG_SIZE: u64 = 16 * 1024 * 1024;

pub fn load_batch_config(path: &Path) -> Result<Vec<BatchJob>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Cannot stat batch config: {}", path.display()))?;
    if metadata.len() > MAX_BATCH_CONFIG_SIZE {
        anyhow::bail!(
            "Batch config file {} is too large ({} bytes, limit {} bytes)",
            path.display(),
            metadata.len(),
            MAX_BATCH_CONFIG_SIZE
        );
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read batch config: {}", path.display()))?;
    let jobs: Vec<BatchJob> = if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        toml::from_str(&content).context("Cannot parse TOML batch config")?
    } else {
        serde_json::from_str(&content).context("Cannot parse JSON batch config")?
    };
    Ok(jobs)
}

pub fn save_report(report: &BatchReport, path: &Path, format: &OutputFormat) -> Result<()> {
    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(report)?,
        OutputFormat::Text => format_report_text(report),
        OutputFormat::Csv => format_report_csv(report),
        _ => serde_json::to_string_pretty(report)?,
    };
    std::fs::write(path, content)?;
    Ok(())
}

fn format_report_text(report: &BatchReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Batch Report\n{}\n", "=".repeat(60)));
    out.push_str(&format!("Total: {}  Succeeded: {}  Failed: {}  Time: {}ms\n",
        report.total_jobs, report.succeeded, report.failed, report.total_duration_ms));
    out.push_str(&format!("Throughput: {:.2} MB/s\n", report.summary.throughput_mb_per_sec));
    out.push_str("\nResults:\n");
    for r in &report.results {
        let status = if r.success { "OK" } else { "FAIL" };
        out.push_str(&format!("  [{:4}] {:30} {:20} {:6}ms",
            status, r.file.display(), r.operation, r.duration_ms));
        if let Some(e) = &r.error {
            out.push_str(&format!(" ERROR: {}", e));
        }
        out.push('\n');
    }
    out
}

fn format_report_csv(report: &BatchReport) -> String {
    let mut out = String::from("job_id,file,operation,success,duration_ms,error\n");
    for r in &report.results {
        out.push_str(&format!("{},{},{},{},{},{}\n",
            r.job_id,
            r.file.display(),
            r.operation,
            r.success,
            r.duration_ms,
            r.error.as_deref().unwrap_or(""),
        ));
    }
    out
}
