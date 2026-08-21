//! Lighthouse-compatible coverage format I/O.
//!
//! Supports:
//! - Lighthouse JSON (the IDA Pro plugin format used by `lighthouse`).
//! - LCOV `.info` format (line/branch/function coverage).
//! - `DynamoRIO` `drcov` binary and text format.
//! - Frida Stalker output (JSON array of `{pc, count}` objects).
//! - Multi-file merge into a single [`crate::coverage_map::CoverageMap`].

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::coverage_map::CoverageMap;
use crate::CovError;

// ─── Lighthouse JSON ──────────────────────────────────────────────────────────

/// The Lighthouse JSON format: a map of `"module_name+offset"` → `hit_count`
/// or an array of covered offset integers.
///
/// Lighthouse also supports a `coverage` array of `[start, end]` pairs.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LighthouseJson {
    /// Dict form: `{"function_name": hit_count, ...}` or `{"0x1000": 3, ...}`
    Dict(HashMap<String, serde_json::Value>),
    /// Array form: `[0x1000, 0x1008, ...]`
    Offsets(Vec<u64>),
}

/// Load a Lighthouse JSON coverage file and populate a `CoverageMap`.
///
/// # Errors
/// Returns `CovError::ParseError` if the JSON is invalid or has an unexpected structure.
pub fn load_lighthouse_json(json: &str, seed_id: u64, cov: &mut CoverageMap) -> Result<usize, CovError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| CovError::ParseError(e.to_string()))?;

    let mut count = 0usize;

    match &value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                // Key may be hex string "0x1000" or decimal "4096" or symbol name
                let addr = parse_addr_or_offset(key);
                if let Some(a) = addr {
                    let hits = val.as_u64().unwrap_or(1);
                    cov.record_bb(a, seed_id, hits);
                    count += 1;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                let addr = item.as_u64().or_else(|| {
                    item.as_str().and_then(parse_addr_or_offset)
                });
                if let Some(a) = addr {
                    cov.record_bb(a, seed_id, 1);
                    count += 1;
                }
            }
        }
        _ => return Err(CovError::ParseError("unexpected top-level JSON type".into())),
    }

    Ok(count)
}

/// Export a `CoverageMap` to Lighthouse JSON format.
#[must_use] 
pub fn export_lighthouse_json(cov: &CoverageMap) -> serde_json::Value {
    let map: serde_json::Map<String, serde_json::Value> = cov
        .bbs
        .iter()
        .filter(|(_, r)| r.covered)
        .map(|(&addr, r)| (format!("{addr:#x}"), serde_json::Value::Number(r.total_hits.into())))
        .collect();
    serde_json::Value::Object(map)
}

fn parse_addr_or_offset(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
}

// ─── LCOV format ─────────────────────────────────────────────────────────────

/// Represents one source file's coverage in LCOV format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LcovFileRecord {
    pub source_file: String,
    /// Line number → hit count.
    pub lines: HashMap<u32, u64>,
    /// Function name → hit count.
    pub functions: HashMap<String, u64>,
    /// Branch: (line, block, branch) → hit count.
    pub branches: HashMap<(u32, u32, u32), u64>,
}

impl LcovFileRecord {
    pub fn new(source_file: impl Into<String>) -> Self {
        Self { source_file: source_file.into(), lines: HashMap::new(), functions: HashMap::new(), branches: HashMap::new() }
    }
}

/// Parse an LCOV `.info` file into a list of `LcovFileRecord`s.
///
/// # Errors
/// Returns `CovError::ParseError` if the format is invalid.
pub fn parse_lcov(input: &str) -> Result<Vec<LcovFileRecord>, CovError> {
    let mut records = Vec::new();
    let mut current: Option<LcovFileRecord> = None;

    for line in input.lines() {
        let line = line.trim();
        if let Some(sf_path) = line.strip_prefix("SF:") {
            current = Some(LcovFileRecord::new(sf_path));
        } else if line == "end_of_record" {
            if let Some(rec) = current.take() { records.push(rec); }
        } else if let Some(rec) = current.as_mut() {
            if let Some(rest) = line.strip_prefix("DA:") {
                let mut parts = rest.splitn(3, ',');
                let lineno: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let hits: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                rec.lines.insert(lineno, hits);
            } else if let Some(rest) = line.strip_prefix("FN:") {
                let mut parts = rest.splitn(2, ',');
                let _lineno = parts.next();
                if let Some(name) = parts.next() { rec.functions.entry(name.to_string()).or_insert(0); }
            } else if let Some(rest) = line.strip_prefix("FNDA:") {
                let mut parts = rest.splitn(2, ',');
                let hits: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(name) = parts.next() { *rec.functions.entry(name.to_string()).or_insert(0) += hits; }
            } else if let Some(rest) = line.strip_prefix("BRDA:") {
                let parts: Vec<&str> = rest.splitn(4, ',').collect();
                if parts.len() == 4 {
                    let line_n: u32 = parts[0].parse().unwrap_or(0);
                    let block: u32 = parts[1].parse().unwrap_or(0);
                    let branch: u32 = parts[2].parse().unwrap_or(0);
                    let hits: u64 = parts[3].trim_start_matches('-').parse().unwrap_or(0);
                    rec.branches.insert((line_n, block, branch), hits);
                }
            }
        }
    }
    Ok(records)
}

/// Generate LCOV `.info` text from a list of `LcovFileRecord`s.
#[must_use] 
pub fn emit_lcov(records: &[LcovFileRecord]) -> String {
    let mut out = String::new();
    for rec in records {
        writeln!(out, "SF:{}", rec.source_file).ok();
        let mut fns: Vec<_> = rec.functions.iter().collect();
        fns.sort_by_key(|(k, _)| k.as_str());
        for (name, _hits) in &fns {
            writeln!(out, "FN:0,{name}").ok();
        }
        for (name, hits) in &fns {
            writeln!(out, "FNDA:{hits},{name}").ok();
        }
        writeln!(out, "FNF:{}", rec.functions.len()).ok();
        let fn_hit = rec.functions.values().filter(|&&h| h > 0).count();
        writeln!(out, "FNH:{fn_hit}").ok();

        let mut branches: Vec<_> = rec.branches.iter().collect();
        branches.sort_by_key(|&(k, _)| k);
        for ((line, block, branch), hits) in &branches {
            writeln!(out, "BRDA:{line},{block},{branch},{hits}").ok();
        }
        writeln!(out, "BRF:{}", rec.branches.len()).ok();
        let br_hit = rec.branches.values().filter(|&&h| h > 0).count();
        writeln!(out, "BRH:{br_hit}").ok();

        let mut lines: Vec<_> = rec.lines.iter().collect();
        lines.sort_by_key(|(ln, _)| *ln);
        for (lineno, hits) in &lines {
            writeln!(out, "DA:{lineno},{hits}").ok();
        }
        writeln!(out, "LF:{}", rec.lines.len()).ok();
        let line_hit = rec.lines.values().filter(|&&h| h > 0).count();
        writeln!(out, "LH:{line_hit}").ok();
        writeln!(out, "end_of_record").ok();
    }
    out
}

// ─── DRcov text format ────────────────────────────────────────────────────────

/// A module entry from a `DRcov` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovModule {
    pub id: u32,
    pub base: u64,
    pub end: u64,
    pub entry: u64,
    pub path: String,
}

/// A basic block entry from a `DRcov` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovBbEntry {
    /// Offset from module base.
    pub start: u32,
    pub size: u16,
    pub module_id: u16,
}

/// Parse a `DRcov` text-format `.drcov` file.
///
/// # Errors
/// Returns `CovError::ParseError` if the format is invalid.
pub fn parse_drcov_text(input: &str) -> Result<(Vec<DrcovModule>, Vec<DrcovBbEntry>), CovError> {
    let mut modules = Vec::new();
    let mut bbs = Vec::new();
    let mut in_bbs = false;
    let mut in_modules = false;

    for line in input.lines() {
        let line = line.trim();
        if line.starts_with("DRCOV VERSION:") || line.starts_with("DRCOV FLAVOR:") {
            continue;
        }
        if line.starts_with("Module Table:") {
            in_modules = true;
            in_bbs = false;
            continue;
        }
        if line.starts_with("BB Table:") {
            in_modules = false;
            in_bbs = true;
            continue;
        }
        if line.starts_with("Columns:") { continue; }

        if in_modules && !line.is_empty() && !line.starts_with("id") {
            // Format: id, base, end, entry, path
            let parts: Vec<&str> = line.splitn(6, ',').map(str::trim).collect();
            if parts.len() >= 5 {
                let id = parts[0].parse::<u32>().unwrap_or(0);
                let base = parse_hex_or_dec(parts[1]);
                let end = parse_hex_or_dec(parts[2]);
                let entry = parse_hex_or_dec(parts[3]);
                let path = parts.get(4).unwrap_or(&"").trim_matches('"').to_string();
                modules.push(DrcovModule { id, base, end, entry, path });
            }
        }

        if in_bbs && !line.is_empty() {
            // Text format: start, size, module_id
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() >= 3 {
                let start = crate::u64_to_u32_sat(parse_hex_or_dec(parts[0]));
                let size = crate::u64_to_u16_sat(parse_hex_or_dec(parts[1]));
                let module_id = crate::u64_to_u16_sat(parse_hex_or_dec(parts[2]));
                bbs.push(DrcovBbEntry { start, size, module_id });
            }
        }
    }
    Ok((modules, bbs))
}

fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse::<u64>().unwrap_or(0), |hex| u64::from_str_radix(hex, 16).unwrap_or(0))
}

/// Convert `DRcov` data into absolute addresses and ingest into a `CoverageMap`.
pub fn load_drcov_into_map(
    modules: &[DrcovModule],
    bbs: &[DrcovBbEntry],
    seed_id: u64,
    cov: &mut CoverageMap,
) -> usize {
    let mod_map: HashMap<u16, u64> = modules.iter().map(|m| (crate::u32_to_u16_sat(m.id), m.base)).collect();
    let mut count = 0usize;
    for bb in bbs {
        if let Some(&base) = mod_map.get(&bb.module_id) {
            let abs_addr = base + u64::from(bb.start);
            cov.record_bb(abs_addr, seed_id, 1);
            count += 1;
        }
    }
    count
}

// ─── Frida Stalker format ─────────────────────────────────────────────────────

/// Frida Stalker coverage entry.
#[derive(Debug, Deserialize)]
pub struct FridaStalkerEntry {
    pub pc: u64,
    #[serde(default = "default_one")]
    pub count: u64,
}

const fn default_one() -> u64 { 1 }

/// Parse Frida Stalker JSON output: `[{"pc": 0x1000, "count": 3}, ...]`.
///
/// # Errors
/// Returns `CovError::ParseError` if the JSON is invalid.
pub fn load_frida_stalker(json: &str, seed_id: u64, cov: &mut CoverageMap) -> Result<usize, CovError> {
    let entries: Vec<FridaStalkerEntry> =
        serde_json::from_str(json).map_err(|e| CovError::ParseError(e.to_string()))?;
    let count = entries.len();
    for e in entries {
        cov.record_bb(e.pc, seed_id, e.count);
    }
    Ok(count)
}

/// Export coverage to Frida Stalker JSON format.
#[must_use] 
pub fn export_frida_stalker(cov: &CoverageMap) -> serde_json::Value {
    let arr: Vec<_> = cov.bbs.iter().filter(|(_, r)| r.covered).map(|(&pc, r)| {
        serde_json::json!({ "pc": pc, "count": r.total_hits })
    }).collect();
    serde_json::Value::Array(arr)
}

// ─── Multi-file merge ─────────────────────────────────────────────────────────

/// Merge multiple Lighthouse JSON files into one `CoverageMap`.
///
/// # Errors
/// Returns `CovError` if any file fails to load.
pub fn merge_lighthouse_files(json_files: &[&str]) -> Result<CoverageMap, CovError> {
    let mut cov = CoverageMap::new();
    for (i, &json) in json_files.iter().enumerate() {
        load_lighthouse_json(json, i as u64, &mut cov)?;
    }
    Ok(cov)
}

/// Merge multiple `DRcov` text files.
///
/// # Errors
/// Returns `CovError` if any file fails to parse.
pub fn merge_drcov_files(drcov_texts: &[&str]) -> Result<CoverageMap, CovError> {
    let mut cov = CoverageMap::new();
    for (i, &text) in drcov_texts.iter().enumerate() {
        let (modules, bbs) = parse_drcov_text(text)?;
        load_drcov_into_map(&modules, &bbs, i as u64, &mut cov);
    }
    Ok(cov)
}

// ─── HTML report generation ───────────────────────────────────────────────────

/// Generate a self-contained HTML coverage report similar to Lighthouse's output.
#[must_use] 
pub fn generate_html_report(cov: &CoverageMap, title: &str) -> String {
    let covered = cov.covered_bb_count();
    let total = cov.total_known_bbs();
    let pct = cov.bb_coverage_pct();

    // Build colour-coded address list
    let mut body = String::new();
    body.push_str("<table class=\"cov\"><tr><th>Address</th><th>Hits</th><th>Status</th></tr>\n");
    for (&addr, rec) in cov.bbs.iter().take(1000) {
        let status = if rec.covered { "covered" } else { "uncovered" };
        let color = if rec.covered { "#4caf50" } else { "#f44336" };
        writeln!(body,
            "<tr><td style='font-family:monospace'>{:#018x}</td><td>{}</td><td style='color:{color}'>{status}</td></tr>",
            addr, rec.total_hits
        ).ok();
    }
    if cov.bbs.len() > 1000 {
        writeln!(body, "<tr><td colspan=3>... {} more entries ...</td></tr>", cov.bbs.len() - 1000).ok();
    }
    body.push_str("</table>");

    format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; margin: 20px; background: #1a1a1a; color: #ccc; }}
  h1 {{ color: #fff; }}
  .stat {{ font-size: 1.2em; margin: 8px 0; }}
  table.cov {{ border-collapse: collapse; width: 100%; }}
  table.cov th {{ background: #333; padding: 4px 8px; text-align: left; }}
  table.cov td {{ padding: 2px 8px; border-bottom: 1px solid #333; }}
  .progress-bar {{ background: #333; border-radius: 4px; height: 20px; width: 400px; margin: 10px 0; }}
  .progress-fill {{ background: #4caf50; height: 20px; border-radius: 4px; width: {pct:.1}%; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="stat">Covered: <strong>{covered}</strong> / {total} basic blocks</div>
<div class="stat">Coverage: <strong>{pct:.1}%</strong></div>
<div class="progress-bar"><div class="progress-fill"></div></div>
<h2>Basic Blocks</h2>
{body}
</body>
</html>
"#)
}

// ─── Coverage format auto-detection ──────────────────────────────────────────

/// Detected format of a coverage file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageFileFormat {
    LighthouseJson,
    LcovInfo,
    DrcovText,
    FridaStalker,
    Unknown,
}

/// Auto-detect the format of a coverage file from its content.
#[must_use] 
pub fn detect_format(content: &str) -> CoverageFileFormat {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // Could be Lighthouse JSON or Frida Stalker JSON
        if trimmed.contains("\"pc\"") {
            return CoverageFileFormat::FridaStalker;
        }
        return CoverageFileFormat::LighthouseJson;
    }
    if trimmed.starts_with("SF:") || trimmed.contains("\nSF:") {
        return CoverageFileFormat::LcovInfo;
    }
    if trimmed.starts_with("DRCOV") || trimmed.contains("Module Table:") || trimmed.contains("BB Table:") {
        return CoverageFileFormat::DrcovText;
    }
    CoverageFileFormat::Unknown
}

/// Load any supported coverage file format into a `CoverageMap`.
///
/// # Errors
/// Returns `CovError` if the format is unknown or parsing fails.
pub fn load_any(content: &str, seed_id: u64, cov: &mut CoverageMap) -> Result<usize, CovError> {
    match detect_format(content) {
        CoverageFileFormat::LighthouseJson => load_lighthouse_json(content, seed_id, cov),
        CoverageFileFormat::FridaStalker => load_frida_stalker(content, seed_id, cov),
        CoverageFileFormat::DrcovText => {
            let (modules, bbs) = parse_drcov_text(content)?;
            Ok(load_drcov_into_map(&modules, &bbs, seed_id, cov))
        }
        CoverageFileFormat::LcovInfo => {
            let records = parse_lcov(content)?;
            // For LCOV, record each covered line as a synthetic BB address
            let mut count = 0usize;
            for rec in &records {
                for (&lineno, &hits) in &rec.lines {
                    if hits > 0 {
                        // Synthetic address: hash of filename + line number
                        let addr = fnv1a_str_line(&rec.source_file, lineno);
                        cov.record_bb(addr, seed_id, hits);
                        count += 1;
                    }
                }
            }
            Ok(count)
        }
        CoverageFileFormat::Unknown => Err(CovError::ParseError("unknown coverage format".into())),
    }
}

fn fnv1a_str_line(s: &str, line: u32) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() { h ^= u64::from(b); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
    h ^= u64::from(line);
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h
}

// ─── Coverage file writer ─────────────────────────────────────────────────────

/// Write a `CoverageMap` to a file in the specified format.
pub struct CoverageWriter;

impl CoverageWriter {
    /// Write Lighthouse JSON format.
    #[must_use] 
    pub fn write_lighthouse(cov: &CoverageMap) -> String {
        serde_json::to_string_pretty(&export_lighthouse_json(cov)).unwrap_or_default()
    }

    /// Write Frida Stalker JSON format.
    #[must_use] 
    pub fn write_frida(cov: &CoverageMap) -> String {
        serde_json::to_string_pretty(&export_frida_stalker(cov)).unwrap_or_default()
    }

    /// Write a coverage report to a file path, choosing format from extension.
    ///
    /// # Errors
    /// Returns `CovError` if format conversion fails.
    pub fn write_coverage_file(cov: &CoverageMap, path: &str) -> Result<String, CovError> {
        let p = std::path::Path::new(path);
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        if ext == "json" {
            Ok(Self::write_lighthouse(cov))
        } else if ext == "lcov" || ext == "info" {
            // Convert coverage map to synthetic LCOV (address as synthetic line)
            let rec = LcovFileRecord {
                source_file: "coverage.bin".into(),
                lines: cov.bbs.iter().filter(|(_, r)| r.covered)
                    .map(|(&a, r)| (crate::u64_to_u32_sat(a), r.total_hits))
                    .collect(),
                functions: HashMap::new(),
                branches: HashMap::new(),
            };
            Ok(emit_lcov(&[rec]))
        } else if ext == "drcov" {
            Ok(Self::write_drcov_simple(cov))
        } else {
            Ok(Self::write_frida(cov))
        }
    }

/// Write a minimal DRcov-style text file (module-free, for post-processing).
    #[must_use] 
    pub fn write_drcov_simple(cov: &CoverageMap) -> String {
        let mut out = String::new();
        out.push_str("DRCOV VERSION: 2\n");
        out.push_str("DRCOV FLAVOR: rustre\n");
        out.push_str("Module Table: version 2, count 1\n");
        out.push_str("Columns: id, base, end, entry, path\n");
        out.push_str("0, 0x0, 0xffffffffffffffff, 0x0, unknown\n");
        let count = cov.bbs.values().filter(|r| r.covered).count();
        writeln!(out, "BB Table: {count} bbs").ok();
        for (&addr, _rec) in cov.bbs.iter().filter(|(_, r)| r.covered) {
            writeln!(out, "{addr:#x}, 1, 0").ok();
        }
        out
    }
}

// ─── Coverage diff report ────────────────────────────────────────────────────

/// Produce a textual diff between two coverage snapshots (Lighthouse JSON format).
///
/// # Errors
/// Returns `CovError` if either JSON file fails to load.
pub fn diff_lighthouse_files(json_a: &str, json_b: &str) -> Result<String, CovError> {
    let mut cov_a = CoverageMap::new();
    let mut cov_b = CoverageMap::new();
    load_lighthouse_json(json_a, 0, &mut cov_a)?;
    load_lighthouse_json(json_b, 1, &mut cov_b)?;

    let set_a: std::collections::HashSet<u64> = cov_a.bbs.keys().copied().collect();
    let set_b: std::collections::HashSet<u64> = cov_b.bbs.keys().copied().collect();

    let mut only_a: Vec<u64> = set_a.difference(&set_b).copied().collect();
    let mut only_b: Vec<u64> = set_b.difference(&set_a).copied().collect();
    only_a.sort_unstable();
    only_b.sort_unstable();

    let mut out = String::new();
    writeln!(out, "Coverage diff (A vs B):").ok();
    writeln!(out, "  Only in A: {} BBs", only_a.len()).ok();
    writeln!(out, "  Only in B: {} BBs", only_b.len()).ok();
    writeln!(out, "  In both  : {}", set_a.intersection(&set_b).count()).ok();
    for &addr in only_a.iter().take(10) { writeln!(out, "  -A {addr:#x}").ok(); }
    for &addr in only_b.iter().take(10) { writeln!(out, "  +B {addr:#x}").ok(); }
    Ok(out)
}

/// Merge an arbitrary number of coverage files in any supported format.
///
/// # Errors
/// Returns `CovError` if any file fails to load.
pub fn merge_any_files(contents: &[(&str, u64)]) -> Result<CoverageMap, CovError> {
    let mut cov = CoverageMap::new();
    for (content, seed_id) in contents {
        load_any(content, *seed_id, &mut cov)?;
    }
    Ok(cov)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lighthouse_json_dict() {
        let json = r#"{"0x1000": 3, "0x1010": 1}"#;
        let mut cov = CoverageMap::new();
        let n = load_lighthouse_json(json, 1, &mut cov).unwrap();
        assert_eq!(n, 2);
        assert_eq!(cov.bbs[&0x1000].total_hits, 3);
    }

    #[test]
    fn test_lighthouse_json_array() {
        let json = r"[4096, 4112, 4128]";
        let mut cov = CoverageMap::new();
        let n = load_lighthouse_json(json, 1, &mut cov).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_lcov_roundtrip() {
        let lcov = "SF:src/main.c\nFN:10,main\nFNDA:1,main\nDA:10,1\nDA:11,0\nend_of_record\n";
        let records = parse_lcov(lcov).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lines[&10], 1);
        assert_eq!(records[0].lines[&11], 0);
        let emitted = emit_lcov(&records);
        assert!(emitted.contains("DA:10,1"));
        assert!(emitted.contains("SF:src/main.c"));
    }

    #[test]
    fn test_drcov_parse() {
        let text = "DRCOV VERSION: 2\nModule Table: version 2, count 1\nColumns: id, base, end, entry, path\n0, 0x400000, 0x401000, 0x400500, /bin/target\nBB Table: 2 bbs\n0x100, 10, 0\n0x200, 8, 0\n";
        let (mods, bbs) = parse_drcov_text(text).unwrap();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].base, 0x0040_0000);
        assert_eq!(bbs.len(), 2);
        let mut cov = CoverageMap::new();
        let n = load_drcov_into_map(&mods, &bbs, 1, &mut cov);
        assert_eq!(n, 2);
        assert!(cov.bbs.contains_key(&(0x0040_0000 + 0x100)));
    }

    #[test]
    fn test_frida_stalker_load() {
        let json = r#"[{"pc": 4096, "count": 5}, {"pc": 8192, "count": 1}]"#;
        let mut cov = CoverageMap::new();
        let n = load_frida_stalker(json, 1, &mut cov).unwrap();
        assert_eq!(n, 2);
        assert_eq!(cov.bbs[&4096].total_hits, 5);
    }

    #[test]
    fn test_export_lighthouse() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 3);
        let json = export_lighthouse_json(&cov);
        let map = json.as_object().unwrap();
        assert!(map.contains_key("0x1000"));
        assert_eq!(map["0x1000"], 3);
    }
}
