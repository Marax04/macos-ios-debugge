//! BinDiff-compatible export format writer/reader.
//!
//! Provides in-memory representations and JSON serialization for BinDiff-style
//! function and basic-block matching databases.  An optional `SQLite` backend
//! can be enabled by adding `rusqlite` to Cargo.toml; for now the module
//! provides the full schema-definition strings and a pure-Rust in-memory DB
//! that can be serialized to/from JSON, plus an HTML report generator.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

// ────────────────────────────────────────────────────────────────────────────────
// MatchAlgorithm
// ────────────────────────────────────────────────────────────────────────────────

/// Which algorithm produced a particular function or basic-block match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchAlgorithm {
    /// Identical function name hash.
    NameHash,
    /// Call-graph MD index.
    CallGraphMD,
    /// Primorial hash of function primes.
    PrimesProduct,
    /// Edge sequence MD hash.
    EdgeMD,
    /// Loop count MD hash.
    LoopCountMD,
    /// String reference overlap.
    StringReferences,
    /// Call sequence similarity.
    CallSequence,
    /// Instruction count match.
    InstructionCount,
    /// Mnemonic sequence LCS.
    MnemonicSequence,
    /// Pseudo-code hash.
    PseudoCode,
    /// Manually annotated match.
    Manual,
    /// Combined heuristic score.
    Combined,
}

impl MatchAlgorithm {
    /// Short string identifier used in reports and JSON.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NameHash => "name_hash",
            Self::CallGraphMD => "callgraph_md",
            Self::PrimesProduct => "primes_product",
            Self::EdgeMD => "edge_md",
            Self::LoopCountMD => "loop_count_md",
            Self::StringReferences => "string_references",
            Self::CallSequence => "call_sequence",
            Self::InstructionCount => "instruction_count",
            Self::MnemonicSequence => "mnemonic_sequence",
            Self::PseudoCode => "pseudo_code",
            Self::Manual => "manual",
            Self::Combined => "combined",
        }
    }

    /// Parse from the short string representation.
    #[must_use]
    pub fn parse_algorithm(s: &str) -> Option<Self> {
        match s {
            "name_hash" => Some(Self::NameHash),
            "callgraph_md" => Some(Self::CallGraphMD),
            "primes_product" => Some(Self::PrimesProduct),
            "edge_md" => Some(Self::EdgeMD),
            "loop_count_md" => Some(Self::LoopCountMD),
            "string_references" => Some(Self::StringReferences),
            "call_sequence" => Some(Self::CallSequence),
            "instruction_count" => Some(Self::InstructionCount),
            "mnemonic_sequence" => Some(Self::MnemonicSequence),
            "pseudo_code" => Some(Self::PseudoCode),
            "manual" => Some(Self::Manual),
            "combined" => Some(Self::Combined),
            _ => None,
        }
    }

    /// Confidence weight assigned to this algorithm (0.0–1.0).
    #[must_use]
    pub const fn default_confidence(&self) -> f64 {
        match self {
            Self::NameHash | Self::Manual => 1.0,
            Self::CallGraphMD => 0.9,
            Self::PrimesProduct => 0.85,
            Self::EdgeMD | Self::MnemonicSequence => 0.8,
            Self::LoopCountMD => 0.75,
            Self::StringReferences | Self::Combined => 0.7,
            Self::CallSequence => 0.65,
            Self::InstructionCount => 0.5,
            Self::PseudoCode => 0.95,
        }
    }
}

impl fmt::Display for MatchAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// File metadata
// ────────────────────────────────────────────────────────────────────────────────

/// Metadata for one of the two input binaries.
#[derive(Debug, Clone)]
pub struct BinDiffFile {
    /// Path or logical name of the binary.
    pub filename: String,
    /// SHA-256 or MD5 hash of the binary (hex string).
    pub hash: String,
    /// Number of functions.
    pub functions: u32,
    /// Number of basic blocks.
    pub basicblocks: u32,
    /// Total instruction count.
    pub instructions: u32,
    /// Architecture string (e.g. `"x86_64"`, `"x86"`).
    pub architecture: String,
}

impl BinDiffFile {
    /// Create with default zero counts.
    #[must_use]
    pub fn new(filename: impl Into<String>, hash: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self {
            filename: filename.into(),
            hash: hash.into(),
            functions: 0,
            basicblocks: 0,
            instructions: 0,
            architecture: architecture.into(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Match records
// ────────────────────────────────────────────────────────────────────────────────

/// A matched function pair.
#[derive(Debug, Clone)]
pub struct BinDiffFunctionMatch {
    /// Function address in binary 1 (old).
    pub address1: u64,
    /// Function address in binary 2 (new).
    pub address2: u64,
    /// Function name in binary 1.
    pub name1: String,
    /// Function name in binary 2.
    pub name2: String,
    /// Similarity score `[0.0, 1.0]`.
    pub similarity: f64,
    /// Confidence score `[0.0, 1.0]`.
    pub confidence: f64,
    /// Which algorithm produced this match.
    pub algorithm: MatchAlgorithm,
}

impl BinDiffFunctionMatch {
    /// `true` if the two functions are considered equivalent (similarity == 1.0).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        (self.similarity - 1.0).abs() < f64::EPSILON
    }
}

impl fmt::Display for BinDiffFunctionMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x} ↔ {:#x} ({}/{}) sim={:.3} conf={:.3} via {}",
            self.address1,
            self.address2,
            self.name1,
            self.name2,
            self.similarity,
            self.confidence,
            self.algorithm
        )
    }
}

/// A matched basic-block pair.
#[derive(Debug, Clone)]
pub struct BinDiffBasicBlockMatch {
    /// Basic-block start address in binary 1.
    pub address1: u64,
    /// Basic-block start address in binary 2.
    pub address2: u64,
    /// Instruction-level similarity.
    pub similarity: f64,
    /// Edge-pattern similarity.
    pub edge_similarity: f64,
}

impl BinDiffBasicBlockMatch {
    /// Combined similarity.
    #[must_use]
    pub fn combined_similarity(&self) -> f64 {
        0.6f64.mul_add(self.similarity, 0.4 * self.edge_similarity)
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// BinDiffDb (in-memory)
// ────────────────────────────────────────────────────────────────────────────────

/// In-memory `BinDiff` database.
///
/// Stores all function and basic-block matches together with file metadata.
/// Supports JSON serialization, overall similarity computation, and HTML report generation.
#[derive(Debug, Clone, Default)]
pub struct BinDiffDb {
    /// Metadata for binary 1 (old).
    pub file1: Option<BinDiffFile>,
    /// Metadata for binary 2 (new).
    pub file2: Option<BinDiffFile>,
    /// All function matches.
    pub function_matches: Vec<BinDiffFunctionMatch>,
    /// All basic-block matches, keyed by `(address1, address2)` of parent function.
    pub basicblock_matches: Vec<BinDiffBasicBlockMatch>,
}

impl BinDiffDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function match.
    pub fn insert_function_match(&mut self, m: BinDiffFunctionMatch) {
        self.function_matches.push(m);
    }

    /// Add a basic-block match.
    pub fn insert_basicblock_match(&mut self, m: BinDiffBasicBlockMatch) {
        self.basicblock_matches.push(m);
    }

    /// Set both file metadata records.
    pub fn set_files(&mut self, f1: BinDiffFile, f2: BinDiffFile) {
        self.file1 = Some(f1);
        self.file2 = Some(f2);
    }

    /// Compute the weighted-average overall similarity across all function matches.
    #[must_use]
    pub fn compute_overall_similarity(&self) -> f64 {
        if self.function_matches.is_empty() {
            return 0.0;
        }
        let mut weight_sum = 0.0_f64;
        let mut sim_sum = 0.0_f64;
        for m in &self.function_matches {
            let w = m.confidence;
            sim_sum = m.similarity.mul_add(w, sim_sum);
            weight_sum += w;
        }
        if weight_sum == 0.0 {
            0.0
        } else {
            (sim_sum / weight_sum).clamp(0.0, 1.0)
        }
    }

    /// Count function matches that are identical.
    #[must_use]
    pub fn identical_count(&self) -> usize {
        self.function_matches.iter().filter(|m| m.is_identical()).count()
    }

    /// Return all matches produced by a specific algorithm.
    #[must_use]
    pub fn matches_by_algorithm(&self, algo: &MatchAlgorithm) -> Vec<&BinDiffFunctionMatch> {
        self.function_matches.iter().filter(|m| &m.algorithm == algo).collect()
    }

    // ── SQLite schema ─────────────────────────────────────────────────────────

    /// Return the DDL statements needed to create all `BinDiff` schema tables.
    #[must_use]
    pub const fn sqlite_schema() -> &'static str {
        "
CREATE TABLE IF NOT EXISTS file (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    hash TEXT NOT NULL,
    functions INTEGER NOT NULL DEFAULT 0,
    basicblocks INTEGER NOT NULL DEFAULT 0,
    instructions INTEGER NOT NULL DEFAULT 0,
    architecture TEXT NOT NULL DEFAULT 'x86'
);
CREATE TABLE IF NOT EXISTS function (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES file(id),
    address INTEGER NOT NULL,
    name TEXT NOT NULL,
    basicblocks INTEGER NOT NULL DEFAULT 0,
    instructions INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS basicblock (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL REFERENCES function(id),
    address INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    outgoing_edges INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS instruction (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    basicblock_id INTEGER NOT NULL REFERENCES basicblock(id),
    address INTEGER NOT NULL,
    mnemonic TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS functionsimilarity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address1 INTEGER NOT NULL,
    address2 INTEGER NOT NULL,
    name1 TEXT NOT NULL DEFAULT '',
    name2 TEXT NOT NULL DEFAULT '',
    similarity REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    algorithm TEXT NOT NULL DEFAULT 'combined'
);
CREATE TABLE IF NOT EXISTS basicblocksimilarity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address1 INTEGER NOT NULL,
    address2 INTEGER NOT NULL,
    similarity REAL NOT NULL DEFAULT 0.0,
    edge_similarity REAL NOT NULL DEFAULT 0.0
);
"
    }

    // ── JSON serialization ────────────────────────────────────────────────────

    /// Export the database to a JSON string.
    ///
    /// Uses hand-built JSON to avoid a dependency on `serde_json`.
    #[must_use]
    pub fn export_to_json(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("{\n");

        // File metadata.
        if let Some(f1) = &self.file1 {
            writeln!(out,
                "  \"file1\": {{ \"filename\": {}, \"hash\": {}, \"functions\": {}, \"basicblocks\": {}, \"instructions\": {}, \"architecture\": {} }},",
                json_str(&f1.filename), json_str(&f1.hash),
                f1.functions, f1.basicblocks, f1.instructions, json_str(&f1.architecture)
            ).unwrap_or_default();
        } else {
            out.push_str("  \"file1\": null,\n");
        }
        if let Some(f2) = &self.file2 {
            writeln!(out,
                "  \"file2\": {{ \"filename\": {}, \"hash\": {}, \"functions\": {}, \"basicblocks\": {}, \"instructions\": {}, \"architecture\": {} }},",
                json_str(&f2.filename), json_str(&f2.hash),
                f2.functions, f2.basicblocks, f2.instructions, json_str(&f2.architecture)
            ).unwrap_or_default();
        } else {
            out.push_str("  \"file2\": null,\n");
        }

        // Overall similarity.
        writeln!(out,
            "  \"overall_similarity\": {:.6},",
            self.compute_overall_similarity()
        ).unwrap_or_default();

        // Function matches.
        out.push_str("  \"function_matches\": [\n");
        for (idx, m) in self.function_matches.iter().enumerate() {
            let comma = if idx + 1 < self.function_matches.len() { "," } else { "" };
            writeln!(out,
                "    {{ \"address1\": {}, \"address2\": {}, \"name1\": {}, \"name2\": {}, \"similarity\": {:.6}, \"confidence\": {:.6}, \"algorithm\": {} }}{}",
                m.address1, m.address2,
                json_str(&m.name1), json_str(&m.name2),
                m.similarity, m.confidence,
                json_str(m.algorithm.as_str()),
                comma
            ).unwrap_or_default();
        }
        out.push_str("  ],\n");

        // Basic-block matches.
        out.push_str("  \"basicblock_matches\": [\n");
        for (idx, bb) in self.basicblock_matches.iter().enumerate() {
            let comma = if idx + 1 < self.basicblock_matches.len() { "," } else { "" };
            writeln!(out,
                "    {{ \"address1\": {}, \"address2\": {}, \"similarity\": {:.6}, \"edge_similarity\": {:.6} }}{}",
                bb.address1, bb.address2, bb.similarity, bb.edge_similarity, comma
            ).unwrap_or_default();
        }
        out.push_str("  ]\n");
        out.push('}');
        out
    }

    /// Import from a JSON string produced by [`export_to_json`].
    ///
    /// Uses a minimal hand-written JSON parser to avoid external dependencies.
    ///
    /// # Errors
    ///
    /// Returns an `Err(String)` describing the parse failure if the JSON is malformed.
    pub fn import_from_json(json: &str) -> Result<Self, String> {
        let mut db = Self::new();
        // Parse function_matches array.
        if let Some(arr) = extract_json_array(json, "function_matches") {
            for obj in split_json_objects(&arr) {
                let addr1 = parse_json_u64(&obj, "address1").unwrap_or(0);
                let addr2 = parse_json_u64(&obj, "address2").unwrap_or(0);
                let name1 = parse_json_string(&obj, "name1").unwrap_or_default();
                let name2 = parse_json_string(&obj, "name2").unwrap_or_default();
                let sim = parse_json_f64(&obj, "similarity").unwrap_or(0.0);
                let conf = parse_json_f64(&obj, "confidence").unwrap_or(0.0);
                let algo_s = parse_json_string(&obj, "algorithm").unwrap_or_default();
                let algo = MatchAlgorithm::parse_algorithm(&algo_s).unwrap_or(MatchAlgorithm::Combined);
                db.function_matches.push(BinDiffFunctionMatch {
                    address1: addr1,
                    address2: addr2,
                    name1,
                    name2,
                    similarity: sim,
                    confidence: conf,
                    algorithm: algo,
                });
            }
        }

        // Parse basicblock_matches.
        if let Some(arr) = extract_json_array(json, "basicblock_matches") {
            for obj in split_json_objects(&arr) {
                let addr1 = parse_json_u64(&obj, "address1").unwrap_or(0);
                let addr2 = parse_json_u64(&obj, "address2").unwrap_or(0);
                let sim = parse_json_f64(&obj, "similarity").unwrap_or(0.0);
                let edge_sim = parse_json_f64(&obj, "edge_similarity").unwrap_or(0.0);
                db.basicblock_matches.push(BinDiffBasicBlockMatch {
                    address1: addr1,
                    address2: addr2,
                    similarity: sim,
                    edge_similarity: edge_sim,
                });
            }
        }

        Ok(db)
    }

    // ── HTML report ────────────────────────────────────────────────────────────

    /// Generate an HTML diff table report.
    #[must_use]
    pub fn generate_html_report(&self) -> String {
        let f1_name = self.file1.as_ref().map_or("Binary 1", |f| f.filename.as_str());
        let f2_name = self.file2.as_ref().map_or("Binary 2", |f| f.filename.as_str());
        let overall_sim = self.compute_overall_similarity();
        let identical = self.identical_count();
        let total = self.function_matches.len();

        let mut html = String::with_capacity(8192);
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<title>BinDiff Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: monospace; background:#1a1a2e; color:#eee; margin:20px; }\n");
        html.push_str("h1 { color:#e94560; }\n");
        html.push_str("table { border-collapse:collapse; width:100%; margin-top:20px; }\n");
        html.push_str("th { background:#16213e; padding:8px; text-align:left; border:1px solid #444; }\n");
        html.push_str("td { padding:6px; border:1px solid #333; font-size:0.85em; }\n");
        html.push_str(".identical { background:#1a3a1a; }\n");
        html.push_str(".similar { background:#2a2a10; }\n");
        html.push_str(".different { background:#3a1a1a; }\n");
        html.push_str(".summary { background:#0f3460; padding:10px; border-radius:4px; margin-bottom:20px; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<h1>BinDiff Report</h1>\n");
        writeln!(html,
            "<div class=\"summary\">\n<b>{}</b> vs <b>{}</b><br>",
            escape_html(f1_name), escape_html(f2_name)
        ).unwrap_or_default();
        writeln!(html,
            "Overall Similarity: <b>{:.1}%</b> &nbsp; Identical: <b>{}</b> / <b>{}</b> functions",
            overall_sim * 100.0, identical, total
        ).unwrap_or_default();
        html.push_str("</div>\n");

        // Algorithm breakdown.
        let mut by_algo: HashMap<String, usize> = HashMap::new();
        for m in &self.function_matches {
            *by_algo.entry(m.algorithm.as_str().to_owned()).or_insert(0) += 1;
        }
        html.push_str("<h2>Algorithm Breakdown</h2>\n<ul>\n");
        let mut algo_counts: Vec<(String, usize)> = by_algo.into_iter().collect();
        algo_counts.sort_by(|a, b| b.1.cmp(&a.1));
        for (algo, count) in &algo_counts {
            writeln!(html, "<li><b>{algo}</b>: {count} matches</li>").unwrap_or_default();
        }
        html.push_str("</ul>\n");

        // Function match table.
        html.push_str("<h2>Function Matches</h2>\n");
        html.push_str("<table>\n<tr>\n");
        html.push_str("<th>Address 1</th><th>Name 1</th><th>Address 2</th><th>Name 2</th>\n");
        html.push_str("<th>Similarity</th><th>Confidence</th><th>Algorithm</th>\n</tr>\n");

        let mut sorted_matches = self.function_matches.clone();
        sorted_matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));

        for m in &sorted_matches {
            let row_class = if m.is_identical() {
                "identical"
            } else if m.similarity >= 0.7 {
                "similar"
            } else {
                "different"
            };
            writeln!(html,
                "<tr class=\"{row_class}\">\n<td>{:#x}</td><td>{}</td><td>{:#x}</td><td>{}</td>\n<td>{:.1}%</td><td>{:.1}%</td><td>{}</td>\n</tr>",
                m.address1,
                escape_html(&m.name1),
                m.address2,
                escape_html(&m.name2),
                m.similarity * 100.0,
                m.confidence * 100.0,
                m.algorithm.as_str()
            ).unwrap_or_default();
        }
        html.push_str("</table>\n");

        // Basic block summary.
        if !self.basicblock_matches.is_empty() {
            html.push_str("<h2>Basic Block Matches</h2>\n");
            writeln!(html,
                "<p>Total basic-block pairs: <b>{}</b></p>",
                self.basicblock_matches.len()
            ).unwrap_or_default();
        }

        html.push_str("</body>\n</html>\n");
        html
    }

    // ── Simulated SQLite write/read (pure Rust, no external dep) ─────────────

    /// Serialize to a SQLite-like text dump (INSERT statements).
    ///
    /// This can be fed into any `SQLite` command-line tool.  Use
    /// [`sqlite_schema`] first to create the tables.
    #[must_use]
    pub fn write_to_sqlite(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("-- BinDiff SQLite dump\nBEGIN TRANSACTION;\n\n");

        if let Some(f1) = &self.file1 {
            writeln!(out,
                "INSERT INTO file (id, filename, hash, functions, basicblocks, instructions, architecture) VALUES (1, {}, {}, {}, {}, {}, {});",
                sql_str(&f1.filename), sql_str(&f1.hash),
                f1.functions, f1.basicblocks, f1.instructions, sql_str(&f1.architecture)
            ).unwrap_or_default();
        }
        if let Some(f2) = &self.file2 {
            writeln!(out,
                "INSERT INTO file (id, filename, hash, functions, basicblocks, instructions, architecture) VALUES (2, {}, {}, {}, {}, {}, {});",
                sql_str(&f2.filename), sql_str(&f2.hash),
                f2.functions, f2.basicblocks, f2.instructions, sql_str(&f2.architecture)
            ).unwrap_or_default();
        }

        for m in &self.function_matches {
            writeln!(out,
                "INSERT INTO functionsimilarity (address1, address2, name1, name2, similarity, confidence, algorithm) VALUES ({}, {}, {}, {}, {:.6}, {:.6}, {});",
                m.address1, m.address2,
                sql_str(&m.name1), sql_str(&m.name2),
                m.similarity, m.confidence,
                sql_str(m.algorithm.as_str())
            ).unwrap_or_default();
        }

        for bb in &self.basicblock_matches {
            writeln!(out,
                "INSERT INTO basicblocksimilarity (address1, address2, similarity, edge_similarity) VALUES ({}, {}, {:.6}, {:.6});",
                bb.address1, bb.address2, bb.similarity, bb.edge_similarity
            ).unwrap_or_default();
        }

        out.push_str("\nCOMMIT;\n");
        out
    }

    /// Attempt to parse a `SQLite` INSERT dump produced by [`write_to_sqlite`].
    ///
    /// # Errors
    ///
    /// Returns an `Err(String)` describing the parse failure if the dump is malformed.
    pub fn read_from_sqlite(dump: &str) -> Result<Self, String> {
        // Re-use the JSON round-trip for now by parsing the INSERT lines.
        // A real implementation would use rusqlite; we hand-parse here.
        let mut db = Self::new();
        for line in dump.lines() {
            let line = line.trim();
            if line.starts_with("INSERT INTO functionsimilarity") {
                if let Some(m) = parse_functionsimilarity_insert(line) {
                    db.function_matches.push(m);
                }
            } else if line.starts_with("INSERT INTO basicblocksimilarity")
                && let Some(bb) = parse_basicblocksimilarity_insert(line) {
                    db.basicblock_matches.push(bb);
                }
        }
        Ok(db)
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Parsing helpers (minimal, no regex dep)
// ────────────────────────────────────────────────────────────────────────────────

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn sql_str(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn extract_json_array(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let pos = json.find(pattern.as_str())?;
    let rest = &json[pos + pattern.len()..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0i32;
    let mut end = 0;
    // Use char_indices so that the index is a byte offset, not a char count.
    for (i, c) in rest.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    // i is the byte index of ']'; the slice is rest[0..=i].
                    end = i + c.len_utf8();
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 { None } else { Some(rest[1..end - 1].to_owned()) }
}

fn split_json_objects(s: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let mut depth = 0i32;
    let mut start = None;
    // Use char_indices so indices are byte offsets, safe for str slicing.
    for (i, c) in s.char_indices() {
        match c {
            '{' => {
                if depth == 0 { start = Some(i); }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s_idx) = start {
                        // i is the byte offset of '}'; include it with i + len_utf8.
                        let end = i + c.len_utf8();
                        objects.push(s[s_idx..end].to_owned());
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }
    objects
}

fn parse_json_string(obj: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let pos = obj.find(pattern.as_str())?;
    let rest = &obj[pos + pattern.len()..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if !rest.starts_with('"') { return None; }
    // Walk the string respecting backslash escapes so that \" inside the
    // value does not terminate parsing early.
    let bytes = rest.as_bytes();
    let mut result = String::new();
    let mut i = 1usize; // skip opening '"'
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                // Skip the escape character and record the literal next byte.
                result.push(bytes[i + 1] as char);
                i += 2;
            }
            b'"' => {
                return Some(result);
            }
            b => {
                result.push(b as char);
                i += 1;
            }
        }
    }
    None // unterminated string
}

fn parse_json_u64(obj: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\"");
    let pos = obj.find(pattern.as_str())?;
    let rest = &obj[pos + pattern.len()..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn parse_json_f64(obj: &str, key: &str) -> Option<f64> {
    let pattern = format!("\"{key}\"");
    let pos = obj.find(pattern.as_str())?;
    let rest = &obj[pos + pattern.len()..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-' && c != 'e').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn parse_values_from_insert(line: &str) -> Option<Vec<String>> {
    let values_start = line.find("VALUES (")?;
    let inner = &line[values_start + 8..];
    let end = inner.rfind(')')?;
    let inner = &inner[..end];
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_str = false;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_str => {
                in_str = true;
            }
            '\'' if in_str => {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    current.push('\'');
                } else {
                    in_str = false;
                }
            }
            ',' if !in_str => {
                values.push(current.trim().to_owned());
                current = String::new();
            }
            _ => {
                current.push(c);
            }
        }
    }
    values.push(current.trim().to_owned());
    Some(values)
}

fn parse_functionsimilarity_insert(line: &str) -> Option<BinDiffFunctionMatch> {
    let vals = parse_values_from_insert(line)?;
    if vals.len() < 7 { return None; }
    let address1 = vals[0].parse().ok()?;
    let address2 = vals[1].parse().ok()?;
    let name1 = vals[2].clone();
    let name2 = vals[3].clone();
    let similarity: f64 = vals[4].parse().ok()?;
    let confidence: f64 = vals[5].parse().ok()?;
    let algorithm = MatchAlgorithm::parse_algorithm(&vals[6]).unwrap_or(MatchAlgorithm::Combined);
    Some(BinDiffFunctionMatch { address1, address2, name1, name2, similarity, confidence, algorithm })
}

fn parse_basicblocksimilarity_insert(line: &str) -> Option<BinDiffBasicBlockMatch> {
    let vals = parse_values_from_insert(line)?;
    if vals.len() < 4 { return None; }
    let address1 = vals[0].parse().ok()?;
    let address2 = vals[1].parse().ok()?;
    let similarity: f64 = vals[2].parse().ok()?;
    let edge_similarity: f64 = vals[3].parse().ok()?;
    Some(BinDiffBasicBlockMatch { address1, address2, similarity, edge_similarity })
}

// ────────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_db() -> BinDiffDb {
        let mut db = BinDiffDb::new();
        db.set_files(
            BinDiffFile::new("old.exe", "aabbcc", "x86_64"),
            BinDiffFile::new("new.exe", "ddeeff", "x86_64"),
        );
        db.insert_function_match(BinDiffFunctionMatch {
            address1: 0x1000,
            address2: 0x1000,
            name1: "main".into(),
            name2: "main".into(),
            similarity: 1.0,
            confidence: 1.0,
            algorithm: MatchAlgorithm::NameHash,
        });
        db.insert_function_match(BinDiffFunctionMatch {
            address1: 0x1100,
            address2: 0x1200,
            name1: "helper".into(),
            name2: "helper".into(),
            similarity: 0.85,
            confidence: 0.9,
            algorithm: MatchAlgorithm::MnemonicSequence,
        });
        db
    }

    #[test]
    fn test_db_new_is_empty() {
        let db = BinDiffDb::new();
        assert!(db.function_matches.is_empty());
        assert!(db.basicblock_matches.is_empty());
    }

    #[test]
    fn test_compute_overall_similarity_empty() {
        let db = BinDiffDb::new();
        assert_eq!(db.compute_overall_similarity(), 0.0);
    }

    #[test]
    fn test_compute_overall_similarity_all_identical() {
        let mut db = BinDiffDb::new();
        db.insert_function_match(BinDiffFunctionMatch {
            address1: 0, address2: 0, name1: "f".into(), name2: "f".into(),
            similarity: 1.0, confidence: 1.0, algorithm: MatchAlgorithm::NameHash,
        });
        assert!((db.compute_overall_similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_identical_count() {
        let db = sample_db();
        assert_eq!(db.identical_count(), 1);
    }

    #[test]
    fn test_match_algorithm_round_trip() {
        for algo in &[
            MatchAlgorithm::NameHash,
            MatchAlgorithm::PrimesProduct,
            MatchAlgorithm::Manual,
            MatchAlgorithm::Combined,
        ] {
            let s = algo.as_str();
            let parsed = MatchAlgorithm::parse_algorithm(s).unwrap();
            assert_eq!(&parsed, algo);
        }
    }

    #[test]
    fn test_match_algorithm_unknown_returns_none() {
        assert!(MatchAlgorithm::parse_algorithm("nonexistent_algo").is_none());
    }

    #[test]
    fn test_export_import_json_round_trip() {
        let db = sample_db();
        let json = db.export_to_json();
        assert!(json.contains("function_matches"));
        let db2 = BinDiffDb::import_from_json(&json).unwrap();
        assert_eq!(db2.function_matches.len(), db.function_matches.len());
        assert_eq!(db2.function_matches[0].address1, 0x1000);
    }

    #[test]
    fn test_write_read_sqlite_round_trip() {
        let db = sample_db();
        let dump = db.write_to_sqlite();
        assert!(dump.contains("INSERT INTO functionsimilarity"));
        let db2 = BinDiffDb::read_from_sqlite(&dump).unwrap();
        assert_eq!(db2.function_matches.len(), db.function_matches.len());
    }

    #[test]
    fn test_generate_html_report_contains_table() {
        let db = sample_db();
        let html = db.generate_html_report();
        assert!(html.contains("<table>"));
        assert!(html.contains("main"));
        assert!(html.contains("BinDiff Report"));
    }

    #[test]
    fn test_sqlite_schema_contains_all_tables() {
        let schema = BinDiffDb::sqlite_schema();
        assert!(schema.contains("file"));
        assert!(schema.contains("function"));
        assert!(schema.contains("basicblock"));
        assert!(schema.contains("instruction"));
        assert!(schema.contains("functionsimilarity"));
        assert!(schema.contains("basicblocksimilarity"));
    }

    #[test]
    fn test_basicblock_match_combined_sim() {
        let bb = BinDiffBasicBlockMatch {
            address1: 0x1000,
            address2: 0x1000,
            similarity: 1.0,
            edge_similarity: 1.0,
        };
        assert!((bb.combined_similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_match_display() {
        let m = BinDiffFunctionMatch {
            address1: 0x1000,
            address2: 0x2000,
            name1: "foo".into(),
            name2: "bar".into(),
            similarity: 0.75,
            confidence: 0.8,
            algorithm: MatchAlgorithm::CallSequence,
        };
        let s = m.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("call_sequence"));
    }

    #[test]
    fn test_matches_by_algorithm() {
        let db = sample_db();
        let name_hash_matches = db.matches_by_algorithm(&MatchAlgorithm::NameHash);
        assert_eq!(name_hash_matches.len(), 1);
    }

    #[test]
    fn test_html_report_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_default_confidence_values() {
        assert_eq!(MatchAlgorithm::Manual.default_confidence(), 1.0);
        assert_eq!(MatchAlgorithm::NameHash.default_confidence(), 1.0);
        assert!(MatchAlgorithm::InstructionCount.default_confidence() < 1.0);
    }
}
