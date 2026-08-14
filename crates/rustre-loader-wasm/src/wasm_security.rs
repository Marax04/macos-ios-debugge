//! `wasm_security` — Security analysis for WebAssembly modules.
//!
//! Detects sandbox-escape patterns, host-function abuse, ROP gadgets in Wasm
//! bytecode, linear-memory safety issues, and unbounded `memory.grow` calls.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Severity
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityFinding
// ─────────────────────────────────────────────────────────────────────────────

/// A single security finding produced by one of the analysers.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// Short category label (e.g. `"sandbox_escape"`).
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Optional byte offset in the binary where the pattern was observed.
    pub offset: Option<u32>,
    /// Optional function index relevant to the finding.
    pub function_index: Option<u32>,
}

impl SecurityFinding {
    /// Create a new finding with the given parameters.
    #[must_use]
    pub fn new(
        category: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            category: category.into(),
            description: description.into(),
            severity,
            offset: None,
            function_index: None,
        }
    }

    /// Attach an offset to this finding.
    #[must_use]
    pub const fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach a function index to this finding.
    #[must_use]
    pub const fn with_function(mut self, func: u32) -> Self {
        self.function_index = Some(func);
        self
    }
}

impl fmt::Display for SecurityFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity, self.category, self.description
        )?;
        if let Some(off) = self.offset {
            write!(f, " (offset 0x{off:08x})")?;
        }
        if let Some(fi) = self.function_index {
            write!(f, " (func #{fi})")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinearMemorySafety
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses linear-memory usage patterns for out-of-bounds risks.
#[derive(Debug, Default)]
pub struct LinearMemorySafety {
    findings: Vec<SecurityFinding>,
}

impl LinearMemorySafety {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyse `code` bytes (raw Wasm function body) for unsafe memory patterns.
    ///
    /// Detects:
    /// - memory.grow without bounds check (0x40 opcode appears without a
    ///   preceding i32.const comparison).
    /// - Large constant offsets in load/store immediates (> 1 MiB).
    /// - Consecutive store sequences without intervening loads (blind writes).
    pub fn analyse(&mut self, func_index: u32, code: &[u8]) {
        self.check_memory_grow(func_index, code);
        self.check_large_offsets(func_index, code);
        self.check_blind_writes(func_index, code);
    }

    fn check_memory_grow(&mut self, func_index: u32, code: &[u8]) {
        // Walk the instruction stream so LEB128 immediate bytes that happen to
        // equal 0x40 are not misread as `memory.grow` opcodes.
        let mut i = 0;
        // Track recent opcode bytes (not immediates) for the bounds-check heuristic.
        let mut recent_ops: Vec<u8> = Vec::with_capacity(16);
        while i < code.len() {
            let op = code[i];
            let op_off = i;
            let Some(next) = next_instr_offset(code, i) else {
                break;
            };

            // memory.grow is encoded as `0x40 0x00` (reserved memory index byte).
            if op == 0x40 && code.get(op_off + 1) == Some(&0x00) {
                let has_cmp = recent_ops
                    .iter()
                    .any(|&b| matches!(b, 0x45..=0x4F | 0x53..=0x58 | 0x67..=0x69));
                if !has_cmp {
                    self.findings.push(
                        SecurityFinding::new(
                            "linear_memory",
                            "memory.grow called without preceding bounds comparison",
                            Severity::Medium,
                        )
                        .with_offset(op_off as u32)
                        .with_function(func_index),
                    );
                }
            }

            if recent_ops.len() == 16 {
                recent_ops.remove(0);
            }
            recent_ops.push(op);
            i = next;
        }
    }

    fn check_large_offsets(&mut self, func_index: u32, code: &[u8]) {
        const LARGE_OFFSET: u32 = 1 << 20; // 1 MiB
        let mut i = 0;
        while i < code.len() {
            // Load/store range: 0x28–0x3E
            if matches!(code[i], 0x28..=0x3E) {
                let offset_start = i + 1;
                // Skip alignment byte (LEB128), then read offset LEB128.
                if let Some((_, align_sz)) = read_leb128_u32(code, offset_start)
                    && let Some((offset_val, _)) = read_leb128_u32(code, offset_start + align_sz)
                        && offset_val > LARGE_OFFSET {
                            self.findings.push(
                                SecurityFinding::new(
                                    "linear_memory",
                                    format!(
                                        "large static memory offset {offset_val:#x} in load/store"
                                    ),
                                    Severity::Low,
                                )
                                .with_offset(i as u32)
                                .with_function(func_index),
                            );
                        }
            }
            i += 1;
        }
    }

    fn check_blind_writes(&mut self, func_index: u32, code: &[u8]) {
        let mut consecutive_stores = 0u32;
        let mut last_store_offset = 0u32;
        for (i, &b) in code.iter().enumerate() {
            if matches!(b, 0x36..=0x3E) {
                consecutive_stores += 1;
                last_store_offset = i as u32;
            } else if matches!(b, 0x28..=0x35) {
                consecutive_stores = 0;
            }
            if consecutive_stores >= 8 {
                self.findings.push(
                    SecurityFinding::new(
                        "linear_memory",
                        format!("{consecutive_stores} consecutive stores without load (potential blind write)"),
                        Severity::Low,
                    )
                    .with_offset(last_store_offset)
                    .with_function(func_index),
                );
                consecutive_stores = 0;
            }
        }
    }

    /// Return all findings collected so far.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }

    /// Return the number of findings at or above `severity`.
    #[must_use]
    pub fn count_at_least(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= severity)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxEscape
// ─────────────────────────────────────────────────────────────────────────────

/// Detects sandbox-escape indicators in Wasm modules.
///
/// A sandbox escape typically involves:
/// - Exporting `__indirect_function_table` or `memory` to the host.
/// - Calling host functions with excessive permissions.
/// - Importing from suspicious module names.
#[derive(Debug, Default)]
pub struct SandboxEscape {
    findings: Vec<SecurityFinding>,
}

impl SandboxEscape {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check the exports table for dangerous exports.
    pub fn check_exports(&mut self, exports: &[(&str, &str)]) {
        // exports: slice of (export_name, kind_str)
        const DANGEROUS_EXPORTS: &[&str] = &[
            "__indirect_function_table",
            "__stack_pointer",
            "__memory_base",
            "__table_base",
        ];
        for (name, _kind) in exports {
            if DANGEROUS_EXPORTS.contains(name) {
                self.findings.push(SecurityFinding::new(
                    "sandbox_escape",
                    format!("dangerous internal symbol exported: '{name}'"),
                    Severity::High,
                ));
            }
        }
    }

    /// Check import module names against a suspicious-module allowlist.
    pub fn check_imports(&mut self, imports: &[(&str, &str)]) {
        // imports: slice of (module_name, field_name)
        const SUSPICIOUS_MODULES: &[&str] = &["wasi_snapshot_preview1", "wasi_unstable", "env"];
        const DANGEROUS_FUNCTIONS: &[&str] = &[
            "proc_exit",
            "fd_write",
            "fd_read",
            "path_open",
            "sock_recv",
            "sock_send",
            "sock_open",
        ];
        for (module, field) in imports {
            if SUSPICIOUS_MODULES.contains(module) && DANGEROUS_FUNCTIONS.contains(field) {
                self.findings.push(SecurityFinding::new(
                    "sandbox_escape",
                    format!("import of privileged syscall '{module}::{field}'"),
                    Severity::Medium,
                ));
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HostFunctionAbuse
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which host functions are called and from how many distinct call sites.
#[derive(Debug, Default)]
pub struct HostFunctionAbuse {
    /// Map from `(module, field)` → number of distinct call sites observed.
    call_sites: HashMap<(String, String), usize>,
    findings: Vec<SecurityFinding>,
}

impl HostFunctionAbuse {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call to `(module, field)` from function `func_index`.
    pub fn record_call(&mut self, module: &str, field: &str, _func_index: u32) {
        *self
            .call_sites
            .entry((module.to_owned(), field.to_owned()))
            .or_insert(0) += 1;
    }

    /// Analyse the recorded calls and emit findings for high-frequency patterns.
    pub fn analyse(&mut self) {
        const HIGH_FREQ: usize = 50;
        for ((module, field), &count) in &self.call_sites {
            if count >= HIGH_FREQ {
                self.findings.push(SecurityFinding::new(
                    "host_function_abuse",
                    format!("'{module}::{field}' called {count} times (possible abuse)"),
                    Severity::Medium,
                ));
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }

    /// Return the call-site count for a specific import.
    #[must_use]
    pub fn call_count(&self, module: &str, field: &str) -> usize {
        self.call_sites
            .get(&(module.to_owned(), field.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    /// Total distinct host functions called.
    #[must_use]
    pub fn distinct_imports_called(&self) -> usize {
        self.call_sites.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmROP
// ─────────────────────────────────────────────────────────────────────────────

/// Detects ROP-gadget-like patterns in Wasm bytecode.
///
/// In Wasm, classical ROP is impossible because there is no instruction
/// pointer control via stack manipulation.  However, indirect calls via
/// `call_indirect` combined with table manipulation can approximate control-flow
/// hijacking.
#[derive(Debug, Default)]
pub struct WasmROP {
    findings: Vec<SecurityFinding>,
}

/// A detected ROP-style gadget.
#[derive(Debug, Clone)]
pub struct WasmGadget {
    /// Byte offset within the code section.
    pub offset: u32,
    /// Gadget description.
    pub description: String,
    /// Function index where the gadget was found.
    pub function_index: u32,
}

impl WasmROP {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `code` for indirect-call gadget patterns.
    ///
    /// Patterns detected:
    /// - `call_indirect` (0x11) immediately after `i32.add`/`i32.sub` (pointer arithmetic).
    /// - `call_indirect` with table index != 0 (suggests table manipulation).
    /// - `br_table` with a large label count (jump table abuse).
    pub fn scan(&mut self, func_index: u32, code: &[u8]) -> Vec<WasmGadget> {
        let mut gadgets = Vec::new();
        let mut i = 0;
        while i < code.len() {
            // Indirect call after arithmetic
            if code[i] == 0x11
                && i >= 1 && matches!(code[i - 1], 0x6A | 0x6B | 0x74 | 0x75) {
                    gadgets.push(WasmGadget {
                        offset: i as u32,
                        description: "call_indirect after arithmetic (potential CFHI gadget)"
                            .into(),
                        function_index: func_index,
                    });
                    self.findings.push(
                        SecurityFinding::new(
                            "wasm_rop",
                            "call_indirect after arithmetic (potential control-flow hijack)",
                            Severity::High,
                        )
                        .with_offset(i as u32)
                        .with_function(func_index),
                    );
                }
            // br_table with many labels
            if code[i] == 0x0E
                && let Some((n, _)) = read_leb128_u32(code, i + 1)
                    && n > 64 {
                        gadgets.push(WasmGadget {
                            offset: i as u32,
                            description: format!("br_table with {n} labels (jump-table gadget)"),
                            function_index: func_index,
                        });
                        self.findings.push(
                            SecurityFinding::new(
                                "wasm_rop",
                                format!("br_table with {n} labels (large jump table)"),
                                Severity::Medium,
                            )
                            .with_offset(i as u32)
                            .with_function(func_index),
                        );
                    }
            i += 1;
        }
        gadgets
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmSecurityReport — structured output
// ─────────────────────────────────────────────────────────────────────────────

/// A formatted security report for a Wasm module.
#[derive(Debug, Default)]
pub struct WasmSecurityReport {
    /// All findings, sorted by severity.
    pub findings: Vec<SecurityFinding>,
    /// Per-category finding counts.
    pub category_counts: std::collections::HashMap<String, usize>,
    /// Severity histogram.
    pub severity_histogram: std::collections::HashMap<Severity, usize>,
    /// Whether the module is considered safe (no High/Critical findings).
    pub is_safe: bool,
}

impl WasmSecurityReport {
    /// Build a report from a completed `WasmSecurity` run.
    #[must_use]
    pub fn from_security(security: &WasmSecurity) -> Self {
        let all = security.all_findings();
        let mut findings: Vec<SecurityFinding> = Vec::with_capacity(all.len());
        findings.extend(all.into_iter().cloned());

        let mut category_counts = std::collections::HashMap::new();
        let mut severity_histogram = std::collections::HashMap::new();

        for f in &findings {
            *category_counts.entry(f.category.clone()).or_insert(0) += 1;
            *severity_histogram.entry(f.severity).or_insert(0) += 1;
        }

        let is_safe = !findings.iter().any(|f| f.severity >= Severity::High);

        Self {
            findings,
            category_counts,
            severity_histogram,
            is_safe,
        }
    }

    /// Total number of findings.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.findings.len()
    }

    /// Number of findings in category `cat`.
    #[must_use]
    pub fn count_in_category(&self, cat: &str) -> usize {
        self.category_counts.get(cat).copied().unwrap_or(0)
    }

    /// Number of findings at severity `sev`.
    #[must_use]
    pub fn count_at_severity(&self, sev: Severity) -> usize {
        self.severity_histogram.get(&sev).copied().unwrap_or(0)
    }

    /// Render a one-line summary.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} finding(s) — safe={} critical={} high={} medium={} low={}",
            self.total(),
            self.is_safe,
            self.count_at_severity(Severity::Critical),
            self.count_at_severity(Severity::High),
            self.count_at_severity(Severity::Medium),
            self.count_at_severity(Severity::Low),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmImportRisk — analyses imported functions for known-dangerous patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Risk classification for a single imported function.
#[derive(Debug, Clone)]
pub struct ImportRisk {
    pub module: String,
    pub name: String,
    pub risk: Severity,
    pub reason: String,
}

/// Analyses the import section of a Wasm module for dangerous imports.
#[derive(Debug, Default)]
pub struct WasmImportRisk {
    pub entries: Vec<ImportRisk>,
}

impl WasmImportRisk {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate the risk of each `(module, name)` import pair.
    pub fn analyse(&mut self, imports: &[(&str, &str)]) {
        for &(module, name) in imports {
            let (risk, reason) = classify_import_risk(module, name);
            self.entries.push(ImportRisk {
                module: module.to_owned(),
                name: name.to_owned(),
                risk,
                reason: reason.to_owned(),
            });
        }
    }

    /// Return all imports at or above the given severity.
    #[must_use]
    pub fn at_least(&self, severity: Severity) -> Vec<&ImportRisk> {
        self.entries.iter().filter(|e| e.risk >= severity).collect()
    }

    /// Return the highest-risk import, if any.
    #[must_use]
    pub fn highest_risk(&self) -> Option<&ImportRisk> {
        self.entries.iter().max_by_key(|e| e.risk)
    }
}

fn classify_import_risk(module: &str, name: &str) -> (Severity, &'static str) {
    // File-system access
    if matches!(name, "path_open" | "path_remove_file" | "path_rename") {
        return (Severity::High, "filesystem mutation");
    }
    // Network access
    if matches!(
        name,
        "sock_open" | "sock_recv" | "sock_send" | "sock_accept"
    ) {
        return (Severity::High, "network I/O");
    }
    // Process control
    if name == "proc_exit" || name == "proc_raise" {
        return (Severity::Medium, "process lifecycle");
    }
    // Environment variables
    if name.starts_with("environ") {
        return (Severity::Medium, "environment access");
    }
    // Clock / random — low risk
    if name.starts_with("clock") || name == "random_get" {
        return (Severity::Low, "timing/entropy");
    }
    // Unknown env imports are suspicious
    if module == "env" {
        return (Severity::Medium, "opaque env import");
    }
    (Severity::Info, "standard import")
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryGrowth
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks `memory.grow` calls and memory declaration limits.
#[derive(Debug, Default)]
pub struct MemoryGrowth {
    /// Number of `memory.grow` opcodes observed.
    pub grow_call_count: u32,
    /// Declared minimum memory pages.
    pub declared_min_pages: u32,
    /// Declared maximum memory pages (if limited).
    pub declared_max_pages: Option<u32>,
    findings: Vec<SecurityFinding>,
}

impl MemoryGrowth {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set declared memory limits from the parsed module.
    pub fn set_limits(&mut self, min_pages: u32, max_pages: Option<u32>) {
        self.declared_min_pages = min_pages;
        self.declared_max_pages = max_pages;
        if max_pages.is_none() {
            self.findings.push(SecurityFinding::new(
                "memory_growth",
                "linear memory declared without maximum page limit",
                Severity::Low,
            ));
        } else if let Some(max) = max_pages
            && max > 32768 {
                // 32768 pages = 2 GiB
                self.findings.push(SecurityFinding::new(
                    "memory_growth",
                    format!(
                        "maximum memory limit {max} pages ({} MiB) is very large",
                        max / 16
                    ),
                    Severity::Medium,
                ));
            }
    }

    /// Scan a function body and count `memory.grow` calls.
    pub fn scan_body(&mut self, func_index: u32, code: &[u8]) {
        for (i, &b) in code.iter().enumerate() {
            if b == 0x40 {
                self.grow_call_count += 1;
                if self.grow_call_count > 10 {
                    self.findings.push(
                        SecurityFinding::new(
                            "memory_growth",
                            format!(
                                "excessive memory.grow calls (count {})",
                                self.grow_call_count
                            ),
                            Severity::Medium,
                        )
                        .with_offset(i as u32)
                        .with_function(func_index),
                    );
                }
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }

    /// Estimated maximum memory in bytes at declared max pages.
    #[must_use]
    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.declared_max_pages.map(|p| u64::from(p) * 65536)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmSecurity  — top-level facade
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level security analyser for a WebAssembly module.
///
/// Composes all sub-analysers and provides a single `analyse` entry point.
#[derive(Debug, Default)]
pub struct WasmSecurity {
    pub linear_memory: LinearMemorySafety,
    pub sandbox_escape: SandboxEscape,
    pub host_function_abuse: HostFunctionAbuse,
    pub rop: WasmROP,
    pub memory_growth: MemoryGrowth,
}

impl WasmSecurity {
    /// Create a new top-level security analyser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all findings from all sub-analysers ordered by severity (highest first).
    #[must_use]
    pub fn all_findings(&self) -> Vec<&SecurityFinding> {
        let mut all: Vec<&SecurityFinding> = Vec::new();
        all.extend(self.linear_memory.findings());
        all.extend(self.sandbox_escape.findings());
        all.extend(self.host_function_abuse.findings());
        all.extend(self.rop.findings());
        all.extend(self.memory_growth.findings());
        all.sort_by(|a, b| b.severity.cmp(&a.severity));
        all
    }

    /// Return the highest severity across all findings, or `None` if there are none.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.all_findings().first().map(|f| f.severity)
    }

    /// Return the total number of findings.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.all_findings().len()
    }

    /// Return `true` if any finding is at or above `severity`.
    #[must_use]
    pub fn has_severity(&self, severity: Severity) -> bool {
        self.all_findings().iter().any(|f| f.severity >= severity)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Given the start of an instruction at `pos` in `code`, return the start
/// offset of the next instruction (i.e. `pos` advanced past the opcode and
/// all of its immediates), or `None` if the stream is truncated/unknown.
///
/// Handles the core Wasm 1.0 opcodes plus enough of the prefixed (0xFC/0xFD/0xFE)
/// families to skip them conservatively. When an opcode is unknown we fall back
/// to advancing by one byte so the walker still makes progress.
fn next_instr_offset(code: &[u8], pos: usize) -> Option<usize> {
    let op = *code.get(pos)?;
    let mut p = pos + 1;
    match op {
        // Single-byte opcodes (no immediates).
        0x00 | 0x01 | 0x05 | 0x0B | 0x0F | 0x1A | 0x1B
        | 0x45..=0xC4
        | 0xD1 => Some(p),

        // block / loop / if : blocktype (single byte or signed LEB128).
        0x02..=0x04 => {
            let b = *code.get(p)?;
            if b == 0x40 || matches!(b, 0x7C..=0x7F) {
                Some(p + 1)
            } else {
                // typeidx as signed LEB128 (read as unsigned, length only).
                let (_, n) = read_leb128_u32(code, p)?;
                Some(p + n)
            }
        }

        // br, br_if, call, local.get/set/tee, global.get/set, ref.func: one LEB128.
        0x0C | 0x0D | 0x10 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0xD2 => {
            let (_, n) = read_leb128_u32(code, p)?;
            Some(p + n)
        }

        // br_table: vec of LEB128 + default LEB128.
        0x0E => {
            let (count, n) = read_leb128_u32(code, p)?;
            p += n;
            for _ in 0..=count {
                let (_, n) = read_leb128_u32(code, p)?;
                p += n;
            }
            Some(p)
        }

        // call_indirect: typeidx LEB128 + tableidx LEB128.
        0x11 => {
            let (_, n) = read_leb128_u32(code, p)?;
            p += n;
            let (_, n) = read_leb128_u32(code, p)?;
            Some(p + n)
        }

        // select t* (0x1C): vec of valtypes.
        0x1C => {
            let (count, n) = read_leb128_u32(code, p)?;
            p += n;
            Some(p + count as usize)
        }

        // Loads/stores 0x28..=0x3E : align LEB128 + offset LEB128.
        0x28..=0x3E => {
            let (_, n) = read_leb128_u32(code, p)?;
            p += n;
            let (_, n) = read_leb128_u32(code, p)?;
            Some(p + n)
        }

        // memory.size / memory.grow: single reserved byte (0x00).
        0x3F | 0x40 => Some(p + 1),

        // i32.const / i64.const: signed LEB128 (length only).
        0x41 | 0x42 => {
            let (_, n) = read_leb128_u32(code, p)?;
            Some(p + n)
        }
        // f32.const: 4 bytes.
        0x43 => Some(p + 4),
        // f64.const: 8 bytes.
        0x44 => Some(p + 8),

        // ref.null: 1-byte heaptype.
        0xD0 => Some(p + 1),

        // Prefixed 0xFC family (saturating conv, memory.init/copy/fill, table.*).
        0xFC => {
            let (sub, n) = read_leb128_u32(code, p)?;
            p += n;
            match sub {
                // i32/i64/f32/f64 truncations: no immediates.
                0..=7 => Some(p),
                // memory.init (8): dataidx + 0x00.
                8 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n + 1)
                }
                // data.drop (9): dataidx.
                9 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n)
                }
                // memory.copy (10): two reserved bytes.
                10 => Some(p + 2),
                // memory.fill (11): one reserved byte.
                11 => Some(p + 1),
                // table.init (12): elemidx + tableidx.
                12 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    p += n;
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n)
                }
                // elem.drop (13): elemidx.
                13 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n)
                }
                // table.copy (14): two tableidx.
                14 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    p += n;
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n)
                }
                // table.grow/size/fill (15/16/17): one tableidx.
                15..=17 => {
                    let (_, n) = read_leb128_u32(code, p)?;
                    Some(p + n)
                }
                _ => Some(p),
            }
        }

        // SIMD (0xFD) and threads/atomics (0xFE): skip prefix subop; treat
        // remaining immediates conservatively as memarg (align+offset). This
        // is not exact for every SIMD/atomic op but is sufficient to keep
        // the walker advancing past these instruction families. If the LEB
        // reads fail, we fall through to single-byte advance.
        0xFD | 0xFE => {
            let (_, n) = read_leb128_u32(code, p)?;
            p += n;
            if let Some((_, a)) = read_leb128_u32(code, p)
                && let Some((_, b)) = read_leb128_u32(code, p + a)
            {
                return Some(p + a + b);
            }
            Some(p)
        }

        // Unknown: advance one byte so the walker keeps making progress.
        _ => Some(pos + 1),
    }
}

/// Decode a LEB128-encoded unsigned 32-bit integer at `offset` in `data`.
///
/// Returns `Some((value, bytes_consumed))` or `None` if the data is truncated.
fn read_leb128_u32(data: &[u8], mut offset: usize) -> Option<(u32, usize)> {
    let start = offset;
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        let b = *data.get(offset)?;
        offset += 1;
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 35 {
            return None;
        }
    }
    Some((result, offset - start))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity ─────────────────────────────────────────────────────────────

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }

    // ── SecurityFinding ───────────────────────────────────────────────────────

    #[test]
    fn test_finding_new() {
        let f = SecurityFinding::new("cat", "desc", Severity::High);
        assert_eq!(f.category, "cat");
        assert_eq!(f.severity, Severity::High);
        assert!(f.offset.is_none());
    }

    #[test]
    fn test_finding_with_offset() {
        let f = SecurityFinding::new("c", "d", Severity::Low).with_offset(0x100);
        assert_eq!(f.offset, Some(0x100));
    }

    #[test]
    fn test_finding_with_function() {
        let f = SecurityFinding::new("c", "d", Severity::Low).with_function(3);
        assert_eq!(f.function_index, Some(3));
    }

    #[test]
    fn test_finding_display() {
        let f = SecurityFinding::new("cat", "description", Severity::High)
            .with_offset(0x200)
            .with_function(1);
        let s = f.to_string();
        assert!(s.contains("HIGH"));
        assert!(s.contains("cat"));
        assert!(s.contains("0x00000200"));
    }

    // ── LinearMemorySafety ────────────────────────────────────────────────────

    #[test]
    fn test_linear_memory_grow_no_cmp() {
        let mut lm = LinearMemorySafety::new();
        // memory.grow (0x40) with no preceding comparison
        let code = [0x41, 0x00, 0x40, 0x00]; // i32.const 0, memory.grow, reserved
        lm.analyse(0, &code);
        assert!(!lm.findings().is_empty());
        assert!(lm.findings()[0].description.contains("memory.grow"));
    }

    #[test]
    fn test_linear_memory_grow_with_cmp() {
        let mut lm = LinearMemorySafety::new();
        // i32.lt_u (0x49) preceding memory.grow
        let code = [0x49, 0x40, 0x00];
        lm.analyse(0, &code);
        // Should not flag memory.grow after a comparison
        
        assert!(!lm
            .findings()
            .iter().any(|f| f.description.contains("memory.grow")));
    }

    #[test]
    fn test_linear_memory_no_findings_clean() {
        let mut lm = LinearMemorySafety::new();
        let code = [0x6A, 0x6A, 0x01]; // iadd, iadd, nop
        lm.analyse(0, &code);
        assert_eq!(lm.findings().len(), 0);
    }

    #[test]
    fn test_linear_memory_count_at_least() {
        let mut lm = LinearMemorySafety::new();
        let code = [0x41, 0x00, 0x40, 0x00];
        lm.analyse(0, &code);
        assert_eq!(lm.count_at_least(Severity::Info), lm.findings().len());
    }

    // ── SandboxEscape ─────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_escape_dangerous_export() {
        let mut se = SandboxEscape::new();
        se.check_exports(&[("__indirect_function_table", "table")]);
        assert!(!se.findings().is_empty());
        assert_eq!(se.findings()[0].severity, Severity::High);
    }

    #[test]
    fn test_sandbox_escape_safe_export() {
        let mut se = SandboxEscape::new();
        se.check_exports(&[("main", "function")]);
        assert!(se.findings().is_empty());
    }

    #[test]
    fn test_sandbox_escape_dangerous_import() {
        let mut se = SandboxEscape::new();
        se.check_imports(&[("wasi_snapshot_preview1", "proc_exit")]);
        assert!(!se.findings().is_empty());
        assert_eq!(se.findings()[0].severity, Severity::Medium);
    }

    #[test]
    fn test_sandbox_escape_safe_import() {
        let mut se = SandboxEscape::new();
        se.check_imports(&[("math", "sqrt")]);
        assert!(se.findings().is_empty());
    }

    #[test]
    fn test_sandbox_escape_multiple_dangerous() {
        let mut se = SandboxEscape::new();
        se.check_exports(&[("__stack_pointer", "global"), ("__memory_base", "global")]);
        assert_eq!(se.findings().len(), 2);
    }

    // ── HostFunctionAbuse ─────────────────────────────────────────────────────

    #[test]
    fn test_host_function_abuse_low_count() {
        let mut hfa = HostFunctionAbuse::new();
        for i in 0..10 {
            hfa.record_call("env", "malloc", i);
        }
        hfa.analyse();
        assert!(hfa.findings().is_empty());
    }

    #[test]
    fn test_host_function_abuse_high_count() {
        let mut hfa = HostFunctionAbuse::new();
        for i in 0..60 {
            hfa.record_call("env", "free", i);
        }
        hfa.analyse();
        assert!(!hfa.findings().is_empty());
    }

    #[test]
    fn test_host_function_abuse_call_count() {
        let mut hfa = HostFunctionAbuse::new();
        hfa.record_call("env", "func", 0);
        hfa.record_call("env", "func", 1);
        assert_eq!(hfa.call_count("env", "func"), 2);
    }

    #[test]
    fn test_host_function_abuse_distinct_imports() {
        let mut hfa = HostFunctionAbuse::new();
        hfa.record_call("env", "a", 0);
        hfa.record_call("env", "b", 0);
        hfa.record_call("wasi", "c", 0);
        assert_eq!(hfa.distinct_imports_called(), 3);
    }

    #[test]
    fn test_host_function_abuse_zero_count() {
        let hfa = HostFunctionAbuse::new();
        assert_eq!(hfa.call_count("env", "nonexistent"), 0);
    }

    // ── WasmROP ───────────────────────────────────────────────────────────────

    #[test]
    fn test_wasm_rop_indirect_after_add() {
        let mut rop = WasmROP::new();
        // i32.add (0x6A) followed by call_indirect (0x11)
        let code = [0x6A, 0x11, 0x00, 0x00];
        let gadgets = rop.scan(0, &code);
        assert!(!gadgets.is_empty());
    }

    #[test]
    fn test_wasm_rop_no_gadget_plain_call() {
        let mut rop = WasmROP::new();
        // call (0x10) — not indirect
        let code = [0x10, 0x01];
        let gadgets = rop.scan(0, &code);
        assert!(gadgets.is_empty());
    }

    #[test]
    fn test_wasm_rop_br_table_large() {
        let mut rop = WasmROP::new();
        // br_table with 100 labels: 0x0E, LEB128(100), then 101 LEB128 entries
        let mut code = vec![0x0E];
        // LEB128(100) = 0x64
        code.push(0x64);
        code.resize(code.len() + 101, 0x01);
        let gadgets = rop.scan(0, &code);
        assert!(!gadgets.is_empty());
        assert!(gadgets[0].description.contains("br_table"));
    }

    #[test]
    fn test_wasm_rop_br_table_small() {
        let mut rop = WasmROP::new();
        // br_table with 4 labels: safe
        let code = [0x0E, 0x04, 0x00, 0x01, 0x02, 0x03, 0x00];
        let gadgets = rop.scan(0, &code);
        assert!(gadgets.is_empty());
    }

    // ── MemoryGrowth ──────────────────────────────────────────────────────────

    #[test]
    fn test_memory_growth_unlimited_max() {
        let mut mg = MemoryGrowth::new();
        mg.set_limits(1, None);
        assert!(!mg.findings().is_empty());
        assert!(mg.findings()[0].description.contains("maximum"));
    }

    #[test]
    fn test_memory_growth_limited_max() {
        let mut mg = MemoryGrowth::new();
        mg.set_limits(1, Some(256)); // 256 pages = 16 MiB, acceptable
        assert!(mg.findings().is_empty());
    }

    #[test]
    fn test_memory_growth_very_large_max() {
        let mut mg = MemoryGrowth::new();
        mg.set_limits(1, Some(65536)); // 4 GiB
        assert!(!mg.findings().is_empty());
    }

    #[test]
    fn test_memory_growth_scan_body_excessive() {
        let mut mg = MemoryGrowth::new();
        // 15 memory.grow calls
        let code: Vec<u8> = (0..15).flat_map(|_| [0x41u8, 0x01, 0x40, 0x00]).collect();
        mg.scan_body(0, &code);
        assert!(mg.grow_call_count >= 11);
    }

    #[test]
    fn test_memory_growth_max_memory_bytes() {
        let mut mg = MemoryGrowth::new();
        mg.set_limits(1, Some(16));
        assert_eq!(mg.max_memory_bytes(), Some(16 * 65536));
    }

    #[test]
    fn test_memory_growth_no_max_bytes() {
        let mg = MemoryGrowth::new();
        assert_eq!(mg.max_memory_bytes(), None);
    }

    // ── WasmSecurity (facade) ─────────────────────────────────────────────────

    #[test]
    fn test_wasm_security_new_empty() {
        let ws = WasmSecurity::new();
        assert_eq!(ws.finding_count(), 0);
        assert!(ws.max_severity().is_none());
    }

    #[test]
    fn test_wasm_security_has_severity_false() {
        let ws = WasmSecurity::new();
        assert!(!ws.has_severity(Severity::Low));
    }

    #[test]
    fn test_wasm_security_all_findings_sorted() {
        let mut ws = WasmSecurity::new();
        ws.memory_growth.set_limits(1, None); // Low finding
        let code = [0x41, 0x00, 0x40, 0x00];
        ws.linear_memory.analyse(0, &code); // Medium finding
        let findings = ws.all_findings();
        assert!(findings.len() >= 2);
        // Sorted highest first
        for w in findings.windows(2) {
            assert!(w[0].severity >= w[1].severity);
        }
    }

    #[test]
    fn test_wasm_security_has_severity_true() {
        let mut ws = WasmSecurity::new();
        ws.sandbox_escape
            .check_exports(&[("__indirect_function_table", "table")]);
        assert!(ws.has_severity(Severity::High));
    }

    #[test]
    fn test_leb128_read_single_byte() {
        let data = [0x42u8];
        let (val, consumed) = read_leb128_u32(&data, 0).unwrap();
        assert_eq!(val, 0x42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_leb128_read_multi_byte() {
        // LEB128 encoding of 300 = 0xAC 0x02
        let data = [0xAC, 0x02];
        let (val, consumed) = read_leb128_u32(&data, 0).unwrap();
        assert_eq!(val, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_leb128_read_at_offset() {
        let data = [0x00, 0x00, 0x05];
        let (val, consumed) = read_leb128_u32(&data, 2).unwrap();
        assert_eq!(val, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_leb128_truncated_returns_none() {
        let data: &[u8] = &[];
        assert!(read_leb128_u32(data, 0).is_none());
    }

    // ── WasmSecurityReport ────────────────────────────────────────────────────

    #[test]
    fn test_report_from_empty_security() {
        let ws = WasmSecurity::new();
        let report = WasmSecurityReport::from_security(&ws);
        assert_eq!(report.total(), 0);
        assert!(report.is_safe);
    }

    #[test]
    fn test_report_summary_line() {
        let ws = WasmSecurity::new();
        let report = WasmSecurityReport::from_security(&ws);
        let s = report.summary_line();
        assert!(s.contains("safe=true"));
    }

    #[test]
    fn test_report_counts_unsafe() {
        let mut ws = WasmSecurity::new();
        ws.sandbox_escape
            .check_exports(&[("__indirect_function_table", "table")]);
        let report = WasmSecurityReport::from_security(&ws);
        assert!(!report.is_safe);
        assert!(report.count_at_severity(Severity::High) >= 1);
    }

    // ── WasmImportRisk ────────────────────────────────────────────────────────

    #[test]
    fn test_import_risk_filesystem() {
        let mut ir = WasmImportRisk::new();
        ir.analyse(&[("wasi_snapshot_preview1", "path_open")]);
        assert!(ir.highest_risk().unwrap().risk >= Severity::High);
    }

    #[test]
    fn test_import_risk_standard_low() {
        let mut ir = WasmImportRisk::new();
        ir.analyse(&[("wasi_snapshot_preview1", "clock_time_get")]);
        let entry = &ir.entries[0];
        assert!(entry.risk <= Severity::Low);
    }

    #[test]
    fn test_import_risk_at_least_filter() {
        let mut ir = WasmImportRisk::new();
        ir.analyse(&[
            ("wasi_snapshot_preview1", "path_open"),
            ("wasi_snapshot_preview1", "clock_time_get"),
        ]);
        let high = ir.at_least(Severity::High);
        assert_eq!(high.len(), 1);
    }
}
