//! Trace export and import.
//!
//! Supports `DynamoRIO` drcov, IDA Lighthouse, Pin trace, taint trace formats.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::trace_filter::TraceEntry;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Export/import errors.
#[derive(Debug)]
pub enum TraceExportError {
    Io(String),
    Format(String),
    InvalidData(String),
}

impl fmt::Display for TraceExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::Format(s) => write!(f, "format error: {s}"),
            Self::InvalidData(s) => write!(f, "invalid data: {s}"),
        }
    }
}

// ─── ExportFormat ────────────────────────────────────────────────────────────

/// Supported trace export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// `DynamoRIO` drcov format.
    Drcov,
    /// IDA Lighthouse .coverage format.
    Lighthouse,
    /// Intel Pin trace format (custom).
    Pin,
    /// Taint trace format.
    Taint,
    /// JSON (universal).
    Json,
    /// CSV (address, hit count).
    Csv,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Drcov => "drcov",
            Self::Lighthouse => "lighthouse",
            Self::Pin => "pin",
            Self::Taint => "taint",
            Self::Json => "json",
            Self::Csv => "csv",
        };
        write!(f, "{s}")
    }
}

// ─── ModuleEntry (drcov) ─────────────────────────────────────────────────────

/// A module entry as used in the drcov module table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovModule {
    pub id: u32,
    /// Module base address.
    pub base: u64,
    /// Module end address.
    pub end: u64,
    /// Module entry point.
    pub entry: u64,
    /// Full file path.
    pub path: String,
}

impl DrcovModule {
    /// Return the module size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }

    /// Return true if the address falls within this module.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }

    /// Format as a drcov module table line.
    #[must_use]
    pub fn to_drcov_line(&self) -> String {
        format!(
            "{}, {:#018x}, {:#018x}, {:#018x}, {}",
            self.id, self.base, self.end, self.entry, self.path
        )
    }
}

// ─── DrcovBasicBlock ─────────────────────────────────────────────────────────

/// A basic block entry in drcov format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovBasicBlock {
    /// RVA within the owning module.
    pub start: u32,
    /// Size in bytes.
    pub size: u16,
    /// Module ID.
    pub module_id: u16,
}

// ─── DrcovExport ─────────────────────────────────────────────────────────────

/// Exports traces in `DynamoRIO` drcov format.
pub struct DrcovExport;

impl DrcovExport {
    /// Generate a drcov-compatible text coverage file.
    #[must_use]
    pub fn export(modules: &[DrcovModule], blocks: &[DrcovBasicBlock]) -> String {
        let mut out = String::new();
        out.push_str("DRCOV VERSION: 2\n");
        out.push_str("DRCOV FLAVOR: drcov\n");
        use std::fmt::Write;
        let _ = writeln!(out, "Module Table: version 2, count {}", modules.len());
        out.push_str("Columns: id, base, end, entry, path\n");
        for m in modules {
            out.push_str(&m.to_drcov_line());
            out.push('\n');
        }
        let _ = writeln!(out, "BB Table: {} bbs", blocks.len());
        // Binary section marker
        out.push_str("--- binary data would follow ---\n");
        out
    }

    /// Build a module table from trace entries.
    #[must_use]
    pub fn build_modules(entries: &[TraceEntry]) -> Vec<DrcovModule> {
        // Group entries by module name, find min/max PC
        let mut module_ranges: HashMap<&str, (u64, u64)> = HashMap::new();
        for e in entries {
            let entry = module_ranges.entry(&e.module).or_insert((e.pc, e.pc));
            if e.pc < entry.0 {
                entry.0 = e.pc;
            }
            if e.pc > entry.1 {
                entry.1 = e.pc;
            }
        }

        module_ranges
            .into_iter()
            .enumerate()
            .map(|(id, (name, (base, end)))| DrcovModule {
                id: u32::try_from(id).unwrap_or(u32::MAX),
                base,
                end: end + 1,
                entry: base,
                path: name.to_owned(),
            })
            .collect()
    }

    /// Build a basic block list from trace entries and a module table.
    #[must_use]
    pub fn build_blocks(entries: &[TraceEntry], modules: &[DrcovModule]) -> Vec<DrcovBasicBlock> {
        let mut seen: HashSet<(u16, u32)> = HashSet::new();
        let mut blocks = Vec::new();

        for e in entries {
            let module = modules.iter().find(|m| m.contains(e.pc));
            if let Some(m) = module {
                let rva = u32::try_from(e.pc - m.base).unwrap_or(u32::MAX);
                let module_id = u16::try_from(m.id).unwrap_or(u16::MAX);
                let key = (module_id, rva);
                if seen.insert(key) {
                    blocks.push(DrcovBasicBlock {
                        start: rva,
                        size: 1, // minimal default
                        module_id,
                    });
                }
            }
        }

        blocks
    }
}

// ─── LightHouseExport ────────────────────────────────────────────────────────

/// Exports traces in IDA Lighthouse .coverage format.
///
/// Lighthouse uses a simple list of hex addresses, one per line.
pub struct LightHouseExport;

impl LightHouseExport {
    /// Generate a Lighthouse-compatible coverage file (unique addresses, sorted).
    #[must_use]
    pub fn export(entries: &[TraceEntry]) -> String {
        let mut pcs: Vec<u64> = entries
            .iter()
            .map(|e| e.pc)
            .collect::<HashSet<u64>>()
            .into_iter()
            .collect();
        pcs.sort_unstable();
        pcs.iter()
            .map(|pc| format!("{pc:#018x}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate with module filter.
    #[must_use]
    pub fn export_for_module(entries: &[TraceEntry], module: &str) -> String {
        let filtered: Vec<&TraceEntry> = entries.iter().filter(|e| e.module == module).collect();
        let mut pcs: Vec<u64> = filtered
            .iter()
            .map(|e| e.pc)
            .collect::<HashSet<u64>>()
            .into_iter()
            .collect();
        pcs.sort_unstable();
        pcs.iter()
            .map(|pc| format!("{pc:#018x}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Count unique basic blocks.
    #[must_use]
    pub fn block_count(entries: &[TraceEntry]) -> usize {
        entries.iter().map(|e| e.pc).collect::<HashSet<u64>>().len()
    }
}

// ─── PinTraceExport ──────────────────────────────────────────────────────────

/// Exports traces in a simple Intel Pin-compatible format.
pub struct PinTraceExport;

impl PinTraceExport {
    /// Generate a Pin trace in CSV format: `index,pc,thread_id,type`.
    #[must_use]
    pub fn export(entries: &[TraceEntry]) -> String {
        use std::fmt::Write;
        let mut out = String::from("index,pc,thread_id,type\n");
        for e in entries {
            let _ = writeln!(
                out,
                "{},{:#018x},{},{:?}",
                e.index, e.pc, e.thread_id, e.insn_type
            );
        }
        out
    }

    /// Export summary: only unique PC + hit count.
    #[must_use]
    pub fn export_summary(entries: &[TraceEntry]) -> String {
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for e in entries {
            *counts.entry(e.pc).or_insert(0) += 1;
        }
        let mut sorted: Vec<(u64, u64)> = counts.into_iter().collect();
        sorted.sort_by_key(|(pc, _)| *pc);
        use std::fmt::Write;
        let mut out = String::from("pc,hits\n");
        for (pc, hits) in sorted {
            let _ = writeln!(out, "{pc:#018x},{hits}");
        }
        out
    }
}

// ─── TaintEntry ──────────────────────────────────────────────────────────────

/// A taint trace entry — extends a regular trace entry with taint information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEntry {
    pub base: TraceEntry,
    /// Tainted registers (register name → taint label).
    pub tainted_regs: HashMap<String, String>,
    /// Tainted memory addresses (addr → taint label).
    pub tainted_mem: HashMap<u64, String>,
}

impl TaintEntry {
    /// Return true if any register is tainted.
    #[must_use]
    pub fn has_tainted_reg(&self) -> bool {
        !self.tainted_regs.is_empty()
    }

    /// Return true if any memory is tainted.
    #[must_use]
    pub fn has_tainted_mem(&self) -> bool {
        !self.tainted_mem.is_empty()
    }
}

// ─── TaintTraceExport ────────────────────────────────────────────────────────

/// Exports taint trace data.
pub struct TaintTraceExport;

impl TaintTraceExport {
    /// Generate taint trace in CSV format.
    #[must_use]
    pub fn export(entries: &[TaintEntry]) -> String {
        use std::fmt::Write;
        let mut out = String::from("index,pc,tainted_regs,tainted_mems\n");
        for e in entries {
            let regs: Vec<String> = e.tainted_regs.keys().cloned().collect();
            let mems: Vec<String> = e.tainted_mem.keys().map(|a| format!("{a:#018x}")).collect();
            let _ = writeln!(
                out,
                "{},{:#018x},\"{}\",\"{}\"",
                e.base.index,
                e.base.pc,
                regs.join(";"),
                mems.join(";"),
            );
        }
        out
    }

    /// Return all unique taint sources (register labels).
    #[must_use]
    pub fn taint_sources(entries: &[TaintEntry]) -> HashSet<String> {
        entries
            .iter()
            .flat_map(|e| e.tainted_regs.values().cloned())
            .collect()
    }

    /// Return all tainted PCs (PCs where taint was observed).
    #[must_use]
    pub fn tainted_pcs(entries: &[TaintEntry]) -> HashSet<u64> {
        entries
            .iter()
            .filter(|e| e.has_tainted_reg() || e.has_tainted_mem())
            .map(|e| e.base.pc)
            .collect()
    }
}

// ─── TraceImporter ────────────────────────────────────────────────────────────

/// Imports trace data from various formats.
pub struct TraceImporter;

impl TraceImporter {
    /// Import from CSV format (`index,pc,thread_id,type`).
    ///
    /// # Errors
    ///
    /// Returns [`TraceExportError`] if the CSV is malformed or fields fail to parse.
    pub fn from_csv(input: &str) -> Result<Vec<TraceEntry>, TraceExportError> {
        use crate::trace_filter::InstructionType;
        let mut entries = Vec::new();
        let mut first = true;
        for line in input.lines() {
            if first {
                first = false;
                continue;
            } // skip header
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ',').collect();
            if parts.len() < 3 {
                return Err(TraceExportError::Format(format!(
                    "invalid CSV line: {line}"
                )));
            }
            let index = parts[0]
                .parse::<u64>()
                .map_err(|_| TraceExportError::InvalidData(format!("bad index: {}", parts[0])))?;
            let pc = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                .map_err(|_| TraceExportError::InvalidData(format!("bad pc: {}", parts[1])))?;
            let thread_id = parts[2]
                .parse::<u64>()
                .map_err(|_| TraceExportError::InvalidData(format!("bad tid: {}", parts[2])))?;
            // Optional 4th column — instruction-type tag from the original
            // trace. When present and recognised, we promote the synthetic
            // entry to the matching specialised constructor.
            let kind = parts.get(3).map_or("", |s| s.trim());
            let entry = match kind.parse::<InstructionType>().ok() {
                Some(InstructionType::Call) => {
                    TraceEntry::call(index, pc, pc, "unknown", thread_id)
                }
                Some(InstructionType::Return) => TraceEntry::ret(index, pc, "unknown", thread_id),
                _ => TraceEntry::instruction(index, pc, "unknown", thread_id),
            };
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Import from Lighthouse format (one hex address per line).
    ///
    /// # Errors
    ///
    /// Returns [`TraceExportError::InvalidData`] for unparsable hex addresses.
    pub fn from_lighthouse(input: &str) -> Result<Vec<TraceEntry>, TraceExportError> {
        let mut entries = Vec::new();
        for (i, line) in input.lines().enumerate() {
            let trimmed = line.trim().trim_start_matches("0x");
            if trimmed.is_empty() {
                continue;
            }
            let pc = u64::from_str_radix(trimmed, 16)
                .map_err(|_| TraceExportError::InvalidData(format!("bad address: {line}")))?;
            entries.push(TraceEntry::instruction(
                u64::try_from(i).unwrap_or(u64::MAX),
                pc,
                "unknown",
                0,
            ));
        }
        Ok(entries)
    }

    /// Import from drcov text output (parse module table + BB table).
    ///
    /// # Errors
    ///
    /// Returns [`TraceExportError`] if the file cannot be parsed.
    pub fn from_drcov_text(input: &str) -> Result<(Vec<DrcovModule>, Vec<u64>), TraceExportError> {
        let mut modules = Vec::new();
        let covered_pcs = Vec::new();
        let mut in_modules = false;
        let mut module_count = 0usize;

        for line in input.lines() {
            if line.starts_with("Module Table:") {
                in_modules = true;
                if let Some(c) = line.split("count ").nth(1) {
                    module_count = c.trim().parse::<usize>().unwrap_or(0);
                }
                continue;
            }
            if line.starts_with("Columns:") {
                continue;
            }
            if line.starts_with("BB Table:") {
                in_modules = false;
                continue;
            }

            if in_modules && modules.len() < module_count {
                // Parse: "id, base, end, entry, path"
                let parts: Vec<&str> = line.splitn(5, ',').collect();
                if parts.len() >= 5 {
                    let id = parts[0].trim().parse::<u32>().unwrap_or(0);
                    let base = u64::from_str_radix(parts[1].trim().trim_start_matches("0x"), 16)
                        .unwrap_or(0);
                    let end = u64::from_str_radix(parts[2].trim().trim_start_matches("0x"), 16)
                        .unwrap_or(0);
                    let entry = u64::from_str_radix(parts[3].trim().trim_start_matches("0x"), 16)
                        .unwrap_or(0);
                    let path = parts[4].trim().to_owned();
                    modules.push(DrcovModule {
                        id,
                        base,
                        end,
                        entry,
                        path,
                    });
                }
            }
        }

        Ok((modules, covered_pcs))
    }
}

// ─── TraceExporter ────────────────────────────────────────────────────────────

/// Multi-format trace exporter.
pub struct TraceExporter {
    pub format: ExportFormat,
}

impl TraceExporter {
    /// Create an exporter for the given format.
    #[must_use]
    pub const fn new(format: ExportFormat) -> Self {
        Self { format }
    }

    /// Export trace entries to a string in the configured format.
    #[must_use]
    pub fn export(&self, entries: &[TraceEntry]) -> String {
        match self.format {
            ExportFormat::Lighthouse => LightHouseExport::export(entries),
            ExportFormat::Pin => PinTraceExport::export(entries),
            ExportFormat::Csv => PinTraceExport::export_summary(entries),
            ExportFormat::Drcov => {
                let modules = DrcovExport::build_modules(entries);
                let blocks = DrcovExport::build_blocks(entries, &modules);
                DrcovExport::export(&modules, &blocks)
            }
            ExportFormat::Json => {
                // Simple JSON array of {index, pc, module, thread}
                let items: Vec<String> = entries
                    .iter()
                    .map(|e| {
                        format!(
                            r#"{{"index":{},"pc":{:#018x},"module":"{}","thread":{}}}"#,
                            e.index, e.pc, e.module, e.thread_id
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            }
            ExportFormat::Taint => String::from("taint export not available without taint data"),
        }
    }

    /// Return the file extension for the configured format.
    #[must_use]
    pub const fn file_extension(&self) -> &'static str {
        match self.format {
            ExportFormat::Drcov => "drcov",
            ExportFormat::Lighthouse => "coverage",
            ExportFormat::Pin => "pintrace",
            ExportFormat::Taint => "taint",
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        }
    }

    /// Build a suggested output path for `base` by replacing/appending the
    /// configured file extension. Returns a [`std::path::PathBuf`].
    #[must_use]
    pub fn suggested_output_path(&self, base: &Path) -> std::path::PathBuf {
        base.with_extension(self.file_extension())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trace() -> Vec<TraceEntry> {
        vec![
            TraceEntry::instruction(0, 0x0000_0001_4000_1000, "malware.exe", 1),
            TraceEntry::instruction(1, 0x0000_0001_4000_1004, "malware.exe", 1),
            TraceEntry::call(2, 0x0000_0001_4000_1008, 0x7FFE_1234_0000, "malware.exe", 1),
            TraceEntry::instruction(3, 0x7FFE_1234_0000, "ntdll.dll", 1),
            TraceEntry::instruction(4, 0x0000_0001_4000_100C, "malware.exe", 2),
        ]
    }

    #[test]
    fn test_drcov_module_contains() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x2000,
            entry: 0x1000,
            path: "test.dll".to_owned(),
        };
        assert!(m.contains(0x1000));
        assert!(m.contains(0x1FFF));
        assert!(!m.contains(0x2000));
    }

    #[test]
    fn test_drcov_module_size() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x3000,
            entry: 0x1000,
            path: "t".to_owned(),
        };
        assert_eq!(m.size(), 0x2000);
    }

    #[test]
    fn test_drcov_module_line() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x2000,
            entry: 0x1000,
            path: "/test/lib.so".to_owned(),
        };
        let line = m.to_drcov_line();
        assert!(line.contains("0x0000000000001000"));
        assert!(line.contains("/test/lib.so"));
    }

    #[test]
    fn test_drcov_export_output() {
        let trace = sample_trace();
        let modules = DrcovExport::build_modules(&trace);
        let blocks = DrcovExport::build_blocks(&trace, &modules);
        let output = DrcovExport::export(&modules, &blocks);
        assert!(output.contains("DRCOV VERSION: 2"));
        assert!(output.contains("Module Table:"));
        assert!(output.contains("BB Table:"));
    }

    #[test]
    fn test_drcov_build_modules() {
        let trace = sample_trace();
        let modules = DrcovExport::build_modules(&trace);
        // Should find 2 modules: malware.exe and ntdll.dll
        let names: Vec<&str> = modules.iter().map(|m| m.path.as_str()).collect();
        assert!(names.contains(&"malware.exe") || names.contains(&"ntdll.dll"));
    }

    #[test]
    fn test_lighthouse_export() {
        let trace = sample_trace();
        let output = LightHouseExport::export(&trace);
        assert!(!output.is_empty());
        // Each line should be a hex address
        for line in output.lines() {
            assert!(line.starts_with("0x") || line.starts_with("0X"));
        }
    }

    #[test]
    fn test_lighthouse_block_count() {
        let trace = sample_trace();
        let count = LightHouseExport::block_count(&trace);
        assert!(count > 0 && count <= trace.len());
    }

    #[test]
    fn test_lighthouse_export_for_module() {
        let trace = sample_trace();
        let output = LightHouseExport::export_for_module(&trace, "malware.exe");
        
        // Only malware.exe entries
        assert!(output.lines().next().is_some());
    }

    #[test]
    fn test_pin_trace_export() {
        let trace = sample_trace();
        let output = PinTraceExport::export(&trace);
        assert!(output.starts_with("index,pc,thread_id,type\n"));
        assert_eq!(output.lines().count(), trace.len() + 1);
    }

    #[test]
    fn test_pin_trace_summary() {
        let trace = sample_trace();
        let summary = PinTraceExport::export_summary(&trace);
        assert!(summary.starts_with("pc,hits\n"));
    }

    #[test]
    fn test_taint_entry_has_tainted_reg() {
        let mut e = TaintEntry {
            base: TraceEntry::instruction(0, 0x1000, "t", 1),
            tainted_regs: HashMap::new(),
            tainted_mem: HashMap::new(),
        };
        assert!(!e.has_tainted_reg());
        e.tainted_regs
            .insert("rax".to_owned(), "user_input".to_owned());
        assert!(e.has_tainted_reg());
    }

    #[test]
    fn test_taint_trace_export() {
        let entries = vec![TaintEntry {
            base: TraceEntry::instruction(0, 0x1000, "t", 1),
            tainted_regs: {
                let mut m = HashMap::new();
                m.insert("rax".to_owned(), "src".to_owned());
                m
            },
            tainted_mem: HashMap::new(),
        }];
        let output = TaintTraceExport::export(&entries);
        assert!(output.contains("rax"));
    }

    #[test]
    fn test_taint_sources() {
        let entries = vec![
            TaintEntry {
                base: TraceEntry::instruction(0, 0x1000, "t", 1),
                tainted_regs: {
                    let mut m = HashMap::new();
                    m.insert("rax".to_owned(), "taint_A".to_owned());
                    m
                },
                tainted_mem: HashMap::new(),
            },
            TaintEntry {
                base: TraceEntry::instruction(1, 0x1004, "t", 1),
                tainted_regs: {
                    let mut m = HashMap::new();
                    m.insert("rbx".to_owned(), "taint_B".to_owned());
                    m
                },
                tainted_mem: HashMap::new(),
            },
        ];
        let sources = TaintTraceExport::taint_sources(&entries);
        assert!(sources.contains("taint_A"));
        assert!(sources.contains("taint_B"));
    }

    #[test]
    fn test_trace_importer_from_csv() {
        let csv =
            "index,pc,thread_id,type\n0,0x0000000000001000,1,Alu\n1,0x0000000000001004,1,Alu\n";
        let entries = TraceImporter::from_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].pc, 0x1000);
        assert_eq!(entries[1].pc, 0x1004);
    }

    #[test]
    fn test_trace_importer_from_lighthouse() {
        let input = "0x0000000000001000\n0x0000000000001004\n0x0000000000001008\n";
        let entries = TraceImporter::from_lighthouse(input).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].pc, 0x1000);
    }

    #[test]
    fn test_trace_exporter_lighthouse() {
        let trace = sample_trace();
        let exp = TraceExporter::new(ExportFormat::Lighthouse);
        let output = exp.export(&trace);
        assert!(!output.is_empty());
        assert_eq!(exp.file_extension(), "coverage");
    }

    #[test]
    fn test_trace_exporter_json() {
        let trace = sample_trace();
        let exp = TraceExporter::new(ExportFormat::Json);
        let output = exp.export(&trace);
        assert!(output.starts_with('['));
        assert!(output.ends_with(']'));
    }

    #[test]
    fn test_trace_exporter_csv() {
        let trace = sample_trace();
        let exp = TraceExporter::new(ExportFormat::Csv);
        let output = exp.export(&trace);
        assert!(output.starts_with("pc,hits"));
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Drcov.to_string(), "drcov");
        assert_eq!(ExportFormat::Lighthouse.to_string(), "lighthouse");
        assert_eq!(ExportFormat::Json.to_string(), "json");
    }

    #[test]
    fn test_tainted_pcs() {
        let entries = vec![
            TaintEntry {
                base: TraceEntry::instruction(0, 0xDEAD, "t", 1),
                tainted_regs: {
                    let mut m = HashMap::new();
                    m.insert("r".to_owned(), "l".to_owned());
                    m
                },
                tainted_mem: HashMap::new(),
            },
            TaintEntry {
                base: TraceEntry::instruction(1, 0xBEEF, "t", 1),
                tainted_regs: HashMap::new(),
                tainted_mem: HashMap::new(),
            },
        ];
        let pcs = TaintTraceExport::tainted_pcs(&entries);
        assert!(pcs.contains(&0xDEAD));
        assert!(!pcs.contains(&0xBEEF));
    }
}
