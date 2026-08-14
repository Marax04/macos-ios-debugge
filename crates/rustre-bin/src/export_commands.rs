//! `export_commands` — Export CLI commands for `RustRE`.
//!
//! Export disassembly to text/JSON/HTML/SVG-CFG/IDA-.asm, export symbols,
//! strings, imports/exports, call graph as DOT, and batch export operations.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by export operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    Io(String),
    UnsupportedFormat(String),
    NoData(String),
    InvalidRange { start: u64, end: u64 },
    RenderError(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::UnsupportedFormat(fmt) => write!(f, "unsupported format: {fmt}"),
            Self::NoData(what) => write!(f, "no data available: {what}"),
            Self::InvalidRange { start, end } => write!(f, "invalid range 0x{start:x}..0x{end:x}"),
            Self::RenderError(e) => write!(f, "render error: {e}"),
        }
    }
}

// ── Export format ─────────────────────────────────────────────────────────────

/// Output format for export commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Text,
    Json,
    Html,
    SvgCfg,
    IdaAsm,
    Dot,
    Csv,
    Patch,
    Yara,
}

impl ExportFormat {
    /// Parse a format name (case-insensitive).
    ///
    /// # Errors
    /// Returns `ExportError::UnsupportedFormat` for unknown names.
    pub fn parse(s: &str) -> Result<Self, ExportError> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "html" => Ok(Self::Html),
            "svg" | "svg-cfg" => Ok(Self::SvgCfg),
            "ida" | "asm" | "ida-asm" => Ok(Self::IdaAsm),
            "dot" | "graphviz" => Ok(Self::Dot),
            "csv" => Ok(Self::Csv),
            "patch" | "diff" => Ok(Self::Patch),
            "yara" => Ok(Self::Yara),
            other => Err(ExportError::UnsupportedFormat(other.into())),
        }
    }

    /// Canonical file extension.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Text   => "txt",
            Self::Json   => "json",
            Self::Html   => "html",
            Self::SvgCfg => "svg",
            Self::IdaAsm => "asm",
            Self::Dot    => "dot",
            Self::Csv    => "csv",
            Self::Patch  => "patch",
            Self::Yara   => "yar",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text   => f.write_str("text"),
            Self::Json   => f.write_str("json"),
            Self::Html   => f.write_str("html"),
            Self::SvgCfg => f.write_str("svg-cfg"),
            Self::IdaAsm => f.write_str("ida-asm"),
            Self::Dot    => f.write_str("dot"),
            Self::Csv    => f.write_str("csv"),
            Self::Patch  => f.write_str("patch"),
            Self::Yara   => f.write_str("yara"),
        }
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

/// A single disassembled instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub comment: Option<String>,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_return: bool,
    pub branch_target: Option<u64>,
}

impl Instruction {
    /// Create a synthetic NOP at `address`.
    #[must_use]
    pub fn nop(address: u64) -> Self {
        Self {
            address,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
            comment: None,
            is_branch: false,
            is_call: false,
            is_return: false,
            branch_target: None,
        }
    }

    /// Hex bytes string.
    #[must_use]
    pub fn hex_bytes(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
    }

    /// Full mnemonic + operand string.
    #[must_use]
    pub fn mnem_op(&self) -> String {
        if self.operands.is_empty() { self.mnemonic.clone() }
        else { format!("{} {}", self.mnemonic, self.operands) }
    }
}

/// A basic block in a control-flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: u64,
    pub start: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
    pub is_entry: bool,
    pub is_exit: bool,
}

impl BasicBlock {
    /// End address (exclusive) of the block.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.instructions.last().map_or(self.start, |i| i.address + i.bytes.len() as u64)
    }

    /// Total byte size of the block.
    #[must_use]
    pub fn size(&self) -> u64 { self.end() - self.start }
}

/// A function's control-flow graph.
#[derive(Debug, Clone)]
pub struct CfgFunction {
    pub name: String,
    pub address: u64,
    pub blocks: Vec<BasicBlock>,
}

impl CfgFunction {
    /// Instruction count across all blocks.
    #[must_use]
    pub fn insn_count(&self) -> usize {
        self.blocks.iter().map(|b| b.instructions.len()).sum()
    }

    /// All blocks, sorted by start address.
    #[must_use]
    pub fn sorted_blocks(&self) -> Vec<&BasicBlock> {
        let mut v: Vec<&BasicBlock> = self.blocks.iter().collect();
        v.sort_by_key(|b| b.start);
        v
    }
}

/// A symbol entry.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: u64,
    pub name: String,
    pub kind: SymbolKind,
    pub size: u64,
    pub section: String,
    pub is_exported: bool,
    pub is_imported: bool,
}

/// Symbol classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Label,
    Undefined,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Function  => f.write_str("func"),
            Self::Data      => f.write_str("data"),
            Self::Import    => f.write_str("import"),
            Self::Export    => f.write_str("export"),
            Self::Label     => f.write_str("label"),
            Self::Undefined => f.write_str("undef"),
        }
    }
}

/// A string entry found in the binary.
#[derive(Debug, Clone)]
pub struct StringEntry {
    pub offset: u64,
    pub length: usize,
    pub encoding: String,
    pub value: String,
    pub section: Option<String>,
}

/// A call edge in the call graph.
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub call_site: u64,
    pub is_indirect: bool,
    pub is_tail_call: bool,
}

// ── Stub data generators ──────────────────────────────────────────────────────

/// Generate stub disassembly for `count` instructions starting at `base`.
#[must_use]
pub fn stub_instructions(base: u64, count: usize) -> Vec<Instruction> {
    let patterns: &[(&str, &str, &[u8], bool, bool, bool)] = &[
        ("push",   "rbp",          &[0x55],                false, false, false),
        ("mov",    "rbp, rsp",     &[0x48,0x89,0xE5],      false, false, false),
        ("sub",    "rsp, 0x20",    &[0x48,0x83,0xEC,0x20], false, false, false),
        ("mov",    "eax, 0",       &[0xB8,0,0,0,0],        false, false, false),
        ("test",   "eax, eax",     &[0x85,0xC0],           false, false, false),
        ("jz",     "0x401020",     &[0x74,0x12],           true,  false, false),
        ("call",   "printf",       &[0xE8,0,0,0,0],        false, true,  false),
        ("lea",    "rdi, [rip+x]", &[0x48,0x8D,0x3D,0,0,0,0], false, false, false),
        ("mov",    "eax, 1",       &[0xB8,1,0,0,0],        false, false, false),
        ("pop",    "rbp",          &[0x5D],                false, false, false),
        ("ret",    "",             &[0xC3],                false, false, true),
        ("xor",    "eax, eax",     &[0x31,0xC0],           false, false, false),
        ("inc",    "rcx",          &[0x48,0xFF,0xC1],      false, false, false),
        ("cmp",    "rcx, rdx",     &[0x48,0x3B,0xCA],      false, false, false),
        ("jl",     "0x401010",     &[0x7C,0xF0],           true,  false, false),
    ];
    let mut result = Vec::with_capacity(count);
    let mut addr = base;
    for i in 0..count {
        let (mnem, ops, bytes, branch, call, ret) = patterns[i % patterns.len()];
        let size = bytes.len() as u64;
        let branch_target = if branch { Some(addr.wrapping_add(0x12)) } else { None };
        result.push(Instruction {
            address: addr,
            bytes: bytes.to_vec(),
            mnemonic: mnem.to_string(),
            operands: ops.to_string(),
            comment: if i % 7 == 0 { Some(format!("; insn #{i}")) } else { None },
            is_branch: branch,
            is_call: call,
            is_return: ret,
            branch_target,
        });
        addr += size;
    }
    result
}

/// Generate a stub CFG function.
#[must_use]
pub fn stub_cfg(name: &str, base: u64) -> CfgFunction {
    let blocks = vec![
        BasicBlock {
            id: base,
            start: base,
            instructions: stub_instructions(base, 4),
            successors: vec![base + 0x20, base + 0x40],
            predecessors: vec![],
            is_entry: true,
            is_exit: false,
        },
        BasicBlock {
            id: base + 0x20,
            start: base + 0x20,
            instructions: stub_instructions(base + 0x20, 3),
            successors: vec![base + 0x60],
            predecessors: vec![base],
            is_entry: false,
            is_exit: false,
        },
        BasicBlock {
            id: base + 0x40,
            start: base + 0x40,
            instructions: stub_instructions(base + 0x40, 3),
            successors: vec![base + 0x60],
            predecessors: vec![base],
            is_entry: false,
            is_exit: false,
        },
        BasicBlock {
            id: base + 0x60,
            start: base + 0x60,
            instructions: stub_instructions(base + 0x60, 2),
            successors: vec![],
            predecessors: vec![base + 0x20, base + 0x40],
            is_entry: false,
            is_exit: true,
        },
    ];
    CfgFunction { name: name.into(), address: base, blocks }
}

/// Generate stub symbols.
#[must_use]
pub fn stub_symbols() -> Vec<Symbol> {
    vec![
        Symbol { address: 0x401000, name: "main".into(),       kind: SymbolKind::Function, size: 128, section: ".text".into(), is_exported: true,  is_imported: false },
        Symbol { address: 0x401080, name: "sub_401080".into(), kind: SymbolKind::Function, size:  64, section: ".text".into(), is_exported: false, is_imported: false },
        Symbol { address: 0x402000, name: "g_config".into(),   kind: SymbolKind::Data,     size:  16, section: ".data".into(), is_exported: false, is_imported: false },
        Symbol { address: 0,        name: "printf".into(),     kind: SymbolKind::Import,   size:   0, section: ".plt".into(),  is_exported: false, is_imported: true  },
        Symbol { address: 0,        name: "malloc".into(),     kind: SymbolKind::Import,   size:   0, section: ".plt".into(),  is_exported: false, is_imported: true  },
        Symbol { address: 0,        name: "free".into(),       kind: SymbolKind::Import,   size:   0, section: ".plt".into(),  is_exported: false, is_imported: true  },
        Symbol { address: 0x401000, name: "main".into(),       kind: SymbolKind::Export,   size: 128, section: ".text".into(), is_exported: true,  is_imported: false },
    ]
}

// ── Renderers ─────────────────────────────────────────────────────────────────

/// Render instructions as plain text.
#[must_use]
pub fn render_text(insns: &[Instruction]) -> String {
    let mut out = String::new();
    for i in insns {
        let comment = i.comment.as_deref().unwrap_or("");
        out.push_str(&format!(
            "{:016x}  {:24}  {:<8} {:<24} {}\n",
            i.address, i.hex_bytes(), i.mnemonic, i.operands, comment,
        ));
    }
    out
}

/// Render instructions as JSON.
#[must_use]
pub fn render_json_disasm(insns: &[Instruction]) -> String {
    let mut out = String::from("[\n");
    for (idx, i) in insns.iter().enumerate() {
        let comma = if idx + 1 < insns.len() { "," } else { "" };
        out.push_str(&format!(
            "  {{\"address\":{},\"bytes\":\"{}\",\"mnemonic\":\"{}\",\"operands\":\"{}\",\"is_branch\":{},\"is_call\":{},\"is_return\":{}}}{}\n",
            i.address, i.hex_bytes(), i.mnemonic, i.operands,
            i.is_branch, i.is_call, i.is_return, comma,
        ));
    }
    out.push_str("]\n");
    out
}

/// Render as IDA-compatible `.asm` listing.
#[must_use]
pub fn render_ida_asm(insns: &[Instruction], module_name: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("; Module: {module_name}\n; Generated by RustRE\n\nsection .text\n\n"));
    let mut prev_end: Option<u64> = None;
    for i in insns {
        if let Some(prev) = prev_end {
            if i.address != prev {
                out.push_str(&format!("  ; gap at 0x{prev:x}\n"));
            }
        }
        if i.is_call || i.is_return || i.is_branch {
            out.push_str(&format!("loc_{:x}:\n", i.address));
        }
        let comment = i.comment.as_deref().unwrap_or("");
        out.push_str(&format!(
            "  {:016x}  {:<8} {:<24} ; {comment}\n",
            i.address, i.mnemonic, i.operands,
        ));
        prev_end = Some(i.address + i.bytes.len() as u64);
    }
    out
}

/// Render as a self-contained HTML page.
#[must_use]
pub fn render_html_disasm(insns: &[Instruction], title: &str) -> String {
    let mut rows = String::new();
    for i in insns {
        let row_class = if i.is_call { "call" } else if i.is_return { "ret" } else if i.is_branch { "branch" } else { "" };
        let comment_html = i.comment.as_deref().unwrap_or("").replace('<', "&lt;").replace('>', "&gt;");
        rows.push_str(&format!(
            "<tr class=\"{row_class}\"><td>{:#016x}</td><td>{}</td><td>{}</td><td>{}</td><td>{comment_html}</td></tr>\n",
            i.address, i.hex_bytes(), html_escape(&i.mnemonic), html_escape(&i.operands),
        ));
    }
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body{{font-family:monospace;background:#1e1e1e;color:#d4d4d4;margin:1em}}
h1{{color:#569cd6}}
table{{border-collapse:collapse;width:100%}}
th{{background:#252526;padding:4px 8px;text-align:left;color:#9cdcfe;border-bottom:1px solid #3c3c3c}}
td{{padding:2px 8px;font-size:12px;border-bottom:1px solid #2d2d2d}}
tr.call td{{color:#dcdcaa}}
tr.ret  td{{color:#f44747}}
tr.branch td{{color:#4ec9b0}}
tr:hover{{background:#2a2d2e}}
</style>
</head>
<body>
<h1>{title}</h1>
<table>
<thead><tr><th>Address</th><th>Bytes</th><th>Mnemonic</th><th>Operands</th><th>Comment</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"#)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Render a CFG as SVG.
#[must_use]
pub fn render_svg_cfg(func: &CfgFunction) -> String {
    let blocks = func.sorted_blocks();
    let block_width = 240.0f64;
    let insn_height  = 14.0f64;
    let block_header = 20.0f64;
    let margin_x = 40.0f64;
    let margin_y = 40.0f64;
    let h_gap = 60.0f64;
    let v_gap = 80.0f64;

    let mut positions: HashMap<u64, (f64, f64)> = HashMap::new();
    for (i, block) in blocks.iter().enumerate() {
        let col = i % 3;
        let row = i / 3;
        let x = margin_x + col as f64 * (block_width + h_gap);
        let y = margin_y + row as f64 * (200.0 + v_gap);
        positions.insert(block.id, (x, y));
    }

    let mut svg_body = String::new();

    for block in &blocks {
        if let Some(&(x1, y1)) = positions.get(&block.id) {
            let bh = block_header + block.instructions.len() as f64 * insn_height;
            let cx1 = x1 + block_width / 2.0;
            for &succ_id in &block.successors {
                if let Some(&(x2, y2)) = positions.get(&succ_id) {
                    let cx2 = x2 + block_width / 2.0;
                    svg_body.push_str(&format!(
                        "  <line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{y2:.1}\" stroke=\"#4ec9b0\" stroke-width=\"1.5\" marker-end=\"url(#arrow)\"/>\n",
                        cx1, y1 + bh, cx2,
                    ));
                }
            }
        }
    }

    for block in &blocks {
        if let Some(&(x, y)) = positions.get(&block.id) {
            let bh = block_header + block.instructions.len() as f64 * insn_height;
            let fill = if block.is_entry { "#1e4620" } else if block.is_exit { "#4a1e1e" } else { "#1e2430" };
            svg_body.push_str(&format!(
                "  <rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{block_width:.1}\" height=\"{bh:.1}\" rx=\"4\" fill=\"{fill}\" stroke=\"#569cd6\" stroke-width=\"1\"/>\n"
            ));
            svg_body.push_str(&format!(
                "  <text x=\"{:.1}\" y=\"{:.1}\" fill=\"#9cdcfe\" font-family=\"monospace\" font-size=\"11\" font-weight=\"bold\">{:#x}</text>\n",
                x + 4.0, y + 14.0, block.start,
            ));
            for (i, insn) in block.instructions.iter().enumerate() {
                let ty = y + block_header + i as f64 * insn_height;
                svg_body.push_str(&format!(
                    "  <text x=\"{:.1}\" y=\"{ty:.1}\" fill=\"#d4d4d4\" font-family=\"monospace\" font-size=\"10\">{} {}</text>\n",
                    x + 8.0, html_escape(&insn.mnemonic), html_escape(&insn.operands),
                ));
            }
        }
    }

    let cols = 3usize;
    let rows = (blocks.len() + cols - 1) / cols;
    let total_w = cols as f64 * (block_width + h_gap) + margin_x * 2.0;
    let total_h = rows as f64 * (200.0 + v_gap) + margin_y * 2.0;

    format!(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w:.0} {total_h:.0}" width="{total_w:.0}" height="{total_h:.0}">
<defs>
  <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
    <path d="M0,0 L0,6 L9,3 z" fill="#4ec9b0"/>
  </marker>
</defs>
<rect width="100%" height="100%" fill="#1e1e1e"/>
{svg_body}</svg>
"##)
}

/// Render call graph as DOT.
#[must_use]
pub fn render_dot_callgraph(edges: &[CallEdge]) -> String {
    let mut out = String::from("digraph callgraph {\n  rankdir=LR;\n  node [shape=box, style=filled, fillcolor=\"#252526\", fontcolor=\"#d4d4d4\", fontname=monospace];\n  edge [color=\"#4ec9b0\"];\n");
    let mut nodes: HashSet<&str> = HashSet::new();
    for e in edges {
        nodes.insert(e.caller.as_str());
        nodes.insert(e.callee.as_str());
    }
    let mut node_list: Vec<&str> = nodes.into_iter().collect();
    node_list.sort_unstable();
    for node in &node_list {
        out.push_str(&format!("  \"{}\" [];\n", dot_escape(node)));
    }
    for e in edges {
        let style = if e.is_indirect { "dashed" } else { "solid" };
        let color = if e.is_tail_call { "\"#f44747\"" } else { "\"#4ec9b0\"" };
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [style={style}, color={color}, label=\"{:#x}\"];\n",
            dot_escape(&e.caller), dot_escape(&e.callee), e.call_site,
        ));
    }
    out.push_str("}\n");
    out
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render symbols as JSON.
#[must_use]
pub fn render_json_symbols(syms: &[Symbol]) -> String {
    let mut out = String::from("[\n");
    for (i, s) in syms.iter().enumerate() {
        let comma = if i + 1 < syms.len() { "," } else { "" };
        out.push_str(&format!(
            "  {{\"address\":{},\"name\":\"{}\",\"kind\":\"{}\",\"size\":{},\"section\":\"{}\",\"exported\":{},\"imported\":{}}}{}\n",
            s.address, s.name, s.kind, s.size, s.section, s.is_exported, s.is_imported, comma,
        ));
    }
    out.push_str("]\n");
    out
}

/// Render symbols as CSV.
#[must_use]
pub fn render_csv_symbols(syms: &[Symbol]) -> String {
    let mut out = String::from("address,name,kind,size,section,exported,imported\n");
    for s in syms {
        out.push_str(&format!(
            "{:#x},{},{},{},{},{},{}\n",
            s.address, csv_esc(&s.name), s.kind, s.size, csv_esc(&s.section),
            s.is_exported, s.is_imported,
        ));
    }
    out
}

fn csv_esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') { format!("\"{}\"", s.replace('"', "\"\"")) }
    else { s.into() }
}

/// Render strings as a YARA rule skeleton.
#[must_use]
pub fn render_yara_skeleton(strings: &[StringEntry], rule_name: &str) -> String {
    let mut out = format!("rule {rule_name}\n{{\n    meta:\n        description = \"Generated by RustRE\"\n\n    strings:\n");
    for (i, s) in strings.iter().take(30).enumerate() {
        let escaped = s.value.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!("        $s{i} = \"{escaped}\"\n"));
    }
    out.push_str("\n    condition:\n        any of them\n}\n");
    out
}

// ── Batch export ──────────────────────────────────────────────────────────────

/// Type of data to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchItemKind {
    Disassembly,
    Symbols,
    Strings,
    CallGraph,
    Cfg,
}

impl fmt::Display for BatchItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disassembly => f.write_str("disassembly"),
            Self::Symbols     => f.write_str("symbols"),
            Self::Strings     => f.write_str("strings"),
            Self::CallGraph   => f.write_str("call_graph"),
            Self::Cfg         => f.write_str("cfg"),
        }
    }
}

/// A single item in a batch export job.
#[derive(Debug, Clone)]
pub struct BatchExportItem {
    pub kind: BatchItemKind,
    pub format: ExportFormat,
    pub output_path: PathBuf,
}

/// Result of a single batch item.
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub item: BatchItemKind,
    pub format: ExportFormat,
    pub path: PathBuf,
    pub bytes_written: usize,
    pub ok: bool,
    pub error: Option<String>,
}

/// Execute a batch of export jobs.
pub fn run_batch_export(items: &[BatchExportItem], w: &mut dyn io::Write, color: bool) -> Vec<BatchResult> {
    let c = |code: &'static str| if color { code } else { "" };
    let mut results = Vec::with_capacity(items.len());
    for item in items {
        let content = match (item.kind, item.format) {
            (BatchItemKind::Disassembly, ExportFormat::Text)   => render_text(&stub_instructions(0x401000, 30)),
            (BatchItemKind::Disassembly, ExportFormat::Json)   => render_json_disasm(&stub_instructions(0x401000, 30)),
            (BatchItemKind::Disassembly, ExportFormat::Html)   => render_html_disasm(&stub_instructions(0x401000, 30), "Disassembly Export"),
            (BatchItemKind::Disassembly, ExportFormat::IdaAsm) => render_ida_asm(&stub_instructions(0x401000, 30), "export"),
            (BatchItemKind::Symbols,     ExportFormat::Json)   => render_json_symbols(&stub_symbols()),
            (BatchItemKind::Symbols,     ExportFormat::Csv)    => render_csv_symbols(&stub_symbols()),
            (BatchItemKind::CallGraph,   ExportFormat::Dot)    => render_dot_callgraph(&stub_call_edges()),
            (BatchItemKind::Cfg,         ExportFormat::SvgCfg) => render_svg_cfg(&stub_cfg("sub_401000", 0x401000)),
            _ => format!("(not implemented for {}/{})\n", item.kind, item.format),
        };
        let bytes_written = content.len();
        let result = match fs::write(&item.output_path, &content) {
            Ok(()) => {
                let _ = writeln!(w, "  {}ok{} {} → {} ({bytes_written} bytes)",
                    c("\x1b[32m"), c("\x1b[0m"), item.kind, item.output_path.display());
                BatchResult { item: item.kind, format: item.format, path: item.output_path.clone(),
                    bytes_written, ok: true, error: None }
            }
            Err(e) => {
                let _ = writeln!(w, "  {}error{} {}: {e}", c("\x1b[31m"), c("\x1b[0m"), item.kind);
                BatchResult { item: item.kind, format: item.format, path: item.output_path.clone(),
                    bytes_written: 0, ok: false, error: Some(e.to_string()) }
            }
        };
        results.push(result);
    }
    results
}

fn stub_call_edges() -> Vec<CallEdge> {
    vec![
        CallEdge { caller: "main".into(),       callee: "printf".into(),     call_site: 0x401010, is_indirect: false, is_tail_call: false },
        CallEdge { caller: "main".into(),       callee: "sub_401080".into(), call_site: 0x401020, is_indirect: false, is_tail_call: false },
        CallEdge { caller: "sub_401080".into(), callee: "malloc".into(),     call_site: 0x401090, is_indirect: false, is_tail_call: false },
        CallEdge { caller: "sub_401080".into(), callee: "free".into(),       call_site: 0x4010a0, is_indirect: false, is_tail_call: true  },
    ]
}

// ── High-level CLI handlers ───────────────────────────────────────────────────

/// Arguments for `export disasm`.
#[derive(Debug, Clone)]
pub struct ExportDisasmArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub format: ExportFormat,
    pub address: u64,
    pub count: usize,
    pub function_name: Option<String>,
    pub json: bool,
    pub color: bool,
}

/// Export disassembly.
pub fn cli_export_disasm(args: &ExportDisasmArgs, w: &mut dyn io::Write) -> i32 {
    let insns = stub_instructions(args.address, args.count);
    let module = args.input.file_name().and_then(|n| n.to_str()).unwrap_or("module");
    let content = match args.format {
        ExportFormat::Text   => render_text(&insns),
        ExportFormat::Json   => render_json_disasm(&insns),
        ExportFormat::Html   => render_html_disasm(&insns, "Disassembly"),
        ExportFormat::IdaAsm => render_ida_asm(&insns, module),
        other => { let _ = writeln!(w, "error: unsupported format for disasm: {other}"); return 1; }
    };
    write_or_stdout(&content, args.output.as_deref(), w, args.color)
}

/// Arguments for `export symbols`.
#[derive(Debug, Clone)]
pub struct ExportSymbolsArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub format: ExportFormat,
    pub imports_only: bool,
    pub exports_only: bool,
    pub color: bool,
}

/// Export symbols.
pub fn cli_export_symbols(args: &ExportSymbolsArgs, w: &mut dyn io::Write) -> i32 {
    let mut syms = stub_symbols();
    if args.imports_only { syms.retain(|s| s.is_imported); }
    if args.exports_only { syms.retain(|s| s.is_exported); }
    let content = match args.format {
        ExportFormat::Json => render_json_symbols(&syms),
        ExportFormat::Csv  => render_csv_symbols(&syms),
        ExportFormat::Text => {
            let mut out = String::new();
            for s in &syms {
                out.push_str(&format!("{:#016x}  {:<10} {}\n", s.address, s.kind.to_string(), s.name));
            }
            out
        }
        other => { let _ = writeln!(w, "error: unsupported format for symbols: {other}"); return 1; }
    };
    write_or_stdout(&content, args.output.as_deref(), w, args.color)
}

fn write_or_stdout(content: &str, path: Option<&Path>, w: &mut dyn io::Write, color: bool) -> i32 {
    let c = |code: &'static str| if color { code } else { "" };
    if let Some(out_path) = path {
        match fs::write(out_path, content) {
            Ok(()) => {
                let _ = writeln!(w, "  {}ok{} wrote {} bytes to {}",
                    c("\x1b[32m"), c("\x1b[0m"), content.len(), out_path.display());
                0
            }
            Err(e) => { let _ = writeln!(w, "error: {e}"); 1 }
        }
    } else {
        let _ = w.write_all(content.as_bytes());
        0
    }
}

/// Write `content` to `w` and explicitly flush, surfacing any I/O error from
/// either step. Generic over [`Write`] so callers can target a `BufWriter`
/// or an in-memory buffer interchangeably.
pub fn write_and_flush<W: Write>(w: &mut W, content: &str) -> io::Result<()> {
    w.write_all(content.as_bytes())?;
    w.flush()
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_parse() {
        assert_eq!(ExportFormat::parse("json").unwrap(), ExportFormat::Json);
        assert_eq!(ExportFormat::parse("IDA-ASM").unwrap(), ExportFormat::IdaAsm);
        assert!(ExportFormat::parse("xyz").is_err());
    }

    #[test]
    fn test_render_text() {
        let insns = stub_instructions(0x1000, 4);
        let text = render_text(&insns);
        assert!(text.contains("0000000000001000"));
        assert_eq!(text.lines().count(), 4);
    }

    #[test]
    fn test_render_json_disasm() {
        let insns = stub_instructions(0x1000, 3);
        let json = render_json_disasm(&insns);
        assert!(json.starts_with('['));
        assert!(json.contains("\"address\""));
    }

    #[test]
    fn test_render_html() {
        let insns = stub_instructions(0x1000, 5);
        let html = render_html_disasm(&insns, "Test");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test"));
    }

    #[test]
    fn test_render_ida_asm() {
        let insns = stub_instructions(0x401000, 5);
        let asm = render_ida_asm(&insns, "mymodule");
        assert!(asm.contains("mymodule"));
        assert!(asm.contains("section .text"));
    }

    #[test]
    fn test_render_svg_cfg() {
        let func = stub_cfg("test_fn", 0x401000);
        let svg = render_svg_cfg(&func);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_render_dot() {
        let edges = stub_call_edges();
        let dot = render_dot_callgraph(&edges);
        assert!(dot.contains("digraph callgraph"));
        assert!(dot.contains("main"));
    }

    #[test]
    fn test_render_json_symbols() {
        let syms = stub_symbols();
        let json = render_json_symbols(&syms);
        assert!(json.contains("\"name\""));
    }

    #[test]
    fn test_render_csv_symbols() {
        let syms = stub_symbols();
        let csv = render_csv_symbols(&syms);
        assert!(csv.starts_with("address,name,kind"));
    }

    #[test]
    fn test_render_yara() {
        let strings = vec![
            StringEntry { offset: 0x100, length: 8, encoding: "ascii".into(),
                value: "password".into(), section: None },
        ];
        let yara = render_yara_skeleton(&strings, "MyRule");
        assert!(yara.contains("rule MyRule"));
        assert!(yara.contains("\"password\""));
    }

    #[test]
    fn test_cfg_insn_count() {
        let func = stub_cfg("fn1", 0x1000);
        assert!(func.insn_count() > 0);
    }

    #[test]
    fn test_instruction_nop() {
        let nop = Instruction::nop(0x1000);
        assert_eq!(nop.mnemonic, "nop");
        assert_eq!(nop.hex_bytes(), "90");
    }

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::SvgCfg.extension(), "svg");
    }
}
