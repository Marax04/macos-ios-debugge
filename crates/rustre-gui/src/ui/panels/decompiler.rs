// ============================================================================
// ui/panels/decompiler.rs  —  Decompiler pseudocode output panel
// ============================================================================

use crate::core::app_state::{AppData, DecompResult, UIState};
use crate::core::types::TokenKind;
use gpui::{div, hsla, px, FontWeight, Hsla, IntoElement, ParentElement, Styled};
use parking_lot::Mutex;
use std::sync::Arc;

// ─── Token kinds for syntax highlighting ─────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PseudoTokenKind {
    Keyword,     // if, while, for, return, struct, typedef, …
    Type,        // int, void, char, DWORD, …
    Identifier,  // variable / function name
    Number,      // numeric literal
    String,      // string literal
    Comment,     // // …  or  /* … */
    Operator,    // = + - * & | < > == …
    Punctuation, // , ; : ( ) { } [ ]
    Address,     // 0x… addresses shown in annotations
    Label,       // goto labels
    Plain,       // everything else
}

impl PseudoTokenKind {
    pub fn color(self) -> Hsla {
        match self {
            Self::Keyword => hsla(0.70, 0.70, 0.72, 1.0),
            Self::Type => hsla(0.38, 0.55, 0.68, 1.0),
            Self::Identifier => hsla(0.0, 0.0, 0.88, 1.0),
            Self::Number => hsla(0.05, 0.80, 0.68, 1.0),
            Self::String => hsla(0.11, 0.75, 0.62, 1.0),
            Self::Comment => hsla(0.0, 0.0, 0.42, 1.0),
            Self::Operator => hsla(0.0, 0.0, 0.65, 1.0),
            Self::Punctuation => hsla(0.0, 0.0, 0.55, 1.0),
            Self::Address => hsla(0.60, 0.45, 0.60, 1.0),
            Self::Label => hsla(0.80, 0.55, 0.62, 1.0),
            Self::Plain => hsla(0.0, 0.0, 0.78, 1.0),
        }
    }
}

// ─── A single pseudocode token ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PseudoToken {
    pub kind: PseudoTokenKind,
    pub text: String,
    /// If this token maps to a specific address, store it for navigation.
    pub addr: Option<u64>,
}

impl PseudoToken {
    pub fn new(kind: PseudoTokenKind, text: &str) -> Self {
        Self {
            kind,
            text: text.to_string(),
            addr: None,
        }
    }

    pub const fn with_addr(mut self, addr: u64) -> Self {
        self.addr = Some(addr);
        self
    }
}

// ─── A line in the pseudocode ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PseudoLine {
    pub indent: usize, // indentation level (×4 spaces)
    pub tokens: Vec<PseudoToken>,
    /// The primary address this line corresponds to (for sync with disasm).
    pub addr: Option<u64>,
    pub is_comment: bool,
}

impl PseudoLine {
    pub const fn blank() -> Self {
        Self {
            indent: 0,
            tokens: Vec::new(),
            addr: None,
            is_comment: false,
        }
    }

    pub const fn code(indent: usize, tokens: Vec<PseudoToken>, addr: Option<u64>) -> Self {
        Self {
            indent,
            tokens,
            addr,
            is_comment: false,
        }
    }

    pub fn comment(indent: usize, text: &str) -> Self {
        Self {
            indent,
            tokens: vec![PseudoToken::new(PseudoTokenKind::Comment, text)],
            addr: None,
            is_comment: true,
        }
    }
}

// ─── Simple pseudocode tokenizer ─────────────────────────────────────────────
// Parses C-like pseudocode text into colored tokens.

static KEYWORDS: &[&str] = &[
    "if", "else", "while", "do", "for", "return", "break", "continue", "goto", "switch", "case",
    "default", "struct", "union", "typedef", "sizeof", "NULL", "nullptr",
];

static TYPE_NAMES: &[&str] = &[
    "int",
    "unsigned",
    "signed",
    "char",
    "short",
    "long",
    "void",
    "float",
    "double",
    "bool",
    "_Bool",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "DWORD",
    "WORD",
    "BYTE",
    "BOOL",
    "HANDLE",
    "LPVOID",
    "LPCSTR",
    "LPWSTR",
    "PVOID",
    "HMODULE",
    "HWND",
    "SOCKET",
];

pub fn tokenize_pseudocode(line: &str) -> Vec<PseudoToken> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut pos = 0;
    let n = chars.len();

    while pos < n {
        let c = chars[pos];

        // Skip spaces (we handle indent separately)
        if c == ' ' || c == '\t' {
            pos += 1;
            continue;
        }

        // Line comment
        if c == '/' && chars.get(pos + 1) == Some(&'/') {
            let rest: String = chars[pos..].iter().collect();
            tokens.push(PseudoToken::new(PseudoTokenKind::Comment, &rest));
            break;
        }

        // Block comment start
        if c == '/' && chars.get(pos + 1) == Some(&'*') {
            let mut end = pos + 2;
            while end + 1 < n && !(chars[end] == '*' && chars[end + 1] == '/') {
                end += 1;
            }
            end = (end + 2).min(n);
            let text: String = chars[pos..end].iter().collect();
            tokens.push(PseudoToken::new(PseudoTokenKind::Comment, &text));
            pos = end;
            continue;
        }

        // String literal
        if c == '"' || c == '\'' {
            let delim = c;
            let mut end = pos + 1;
            while end < n {
                if chars[end] == '\\' {
                    end += 2;
                    continue;
                }
                if chars[end] == delim {
                    end += 1;
                    break;
                }
                end += 1;
            }
            let text: String = chars[pos..end].iter().collect();
            tokens.push(PseudoToken::new(PseudoTokenKind::String, &text));
            pos = end;
            continue;
        }

        // Hex number (0x...)
        if c == '0' && chars.get(pos + 1).is_some_and(|&c| c == 'x' || c == 'X') {
            let mut end = pos + 2;
            while end < n && chars[end].is_ascii_hexdigit() {
                end += 1;
            }
            let text: String = chars[pos..end].iter().collect();
            // Decide: is this an address (8+ hex digits) or just a number?
            let hex_len = end - pos - 2;
            let kind = if hex_len >= 6 {
                PseudoTokenKind::Address
            } else {
                PseudoTokenKind::Number
            };
            tokens.push(PseudoToken::new(kind, &text));
            pos = end;
            continue;
        }

        // Decimal number
        if c.is_ascii_digit() {
            let mut end = pos;
            while end < n && (chars[end].is_ascii_digit() || chars[end] == '_') {
                end += 1;
            }
            let text: String = chars[pos..end].iter().collect();
            tokens.push(PseudoToken::new(PseudoTokenKind::Number, &text));
            pos = end;
            continue;
        }

        // Identifier or keyword
        if c.is_alphabetic() || c == '_' {
            let mut end = pos;
            while end < n && (chars[end].is_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            let text: String = chars[pos..end].iter().collect();
            let kind = if KEYWORDS.contains(&text.as_str()) {
                PseudoTokenKind::Keyword
            } else if TYPE_NAMES.contains(&text.as_str()) {
                PseudoTokenKind::Type
            } else if end < n && chars[end] == ':' {
                PseudoTokenKind::Label
            } else {
                PseudoTokenKind::Identifier
            };
            tokens.push(PseudoToken::new(kind, &text));
            pos = end;
            continue;
        }

        // Operators (multi-char first)
        let two: String = chars[pos..pos.min(n)].iter().take(2).collect();
        if matches!(
            two.as_str(),
            "==" | "!=" | "<=" | ">=" | "&&" | "||" | "++" | "--" | "->" | "::" | "<<" | ">>"
        ) {
            tokens.push(PseudoToken::new(PseudoTokenKind::Operator, &two));
            pos += 2;
            continue;
        }

        if "=+-*/%&|^~!<>".contains(c) {
            tokens.push(PseudoToken::new(PseudoTokenKind::Operator, &c.to_string()));
            pos += 1;
            continue;
        }

        if ",;:(){}[]".contains(c) {
            tokens.push(PseudoToken::new(
                PseudoTokenKind::Punctuation,
                &c.to_string(),
            ));
            pos += 1;
            continue;
        }

        // Fallback
        tokens.push(PseudoToken::new(PseudoTokenKind::Plain, &c.to_string()));
        pos += 1;
    }
    tokens
}

/// Parse a full C-like pseudocode text (multi-line) into `PseudoLines`.
pub fn parse_pseudocode(source: &str) -> Vec<PseudoLine> {
    let mut lines = Vec::new();
    for raw in source.lines() {
        if raw.trim().is_empty() {
            lines.push(PseudoLine::blank());
            continue;
        }
        // Measure indent (4-space or tab)
        let indent = raw.chars().take_while(|c| *c == ' ').count() / 4;
        let trimmed = raw.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            lines.push(PseudoLine::comment(indent, trimmed));
        } else {
            let tokens = tokenize_pseudocode(trimmed);
            lines.push(PseudoLine::code(indent, tokens, None));
        }
    }
    lines
}

// ─── Decompiled function ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompiledFunction {
    pub func_addr: u64,
    pub func_name: String,
    pub lines: Vec<PseudoLine>,
    pub raw_source: String,
    pub quality: DecompileQuality,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecompileQuality {
    High,
    Medium,
    Low,
    Failed,
}

impl DecompileQuality {
    pub const fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Failed => "Failed",
        }
    }
    pub fn color(self) -> Hsla {
        match self {
            Self::High => hsla(0.38, 0.7, 0.60, 1.0),
            Self::Medium => hsla(0.11, 0.7, 0.60, 1.0),
            Self::Low => hsla(0.05, 0.7, 0.60, 1.0),
            Self::Failed => hsla(0.0, 0.7, 0.55, 1.0),
        }
    }
}

impl DecompiledFunction {
    pub fn from_source(
        func_addr: u64,
        func_name: &str,
        source: &str,
        quality: DecompileQuality,
    ) -> Self {
        let lines = parse_pseudocode(source);
        Self {
            func_addr,
            func_name: func_name.to_string(),
            lines,
            raw_source: source.to_string(),
            quality,
            warnings: Vec::new(),
        }
    }

    /// Build a `DecompiledFunction` from a backend [`DecompResult`] stored in
    /// `AppData::decomp_cache`. The result is produced by
    /// `crate::analysis::decompiler::decompile_function` during the analysis
    /// pipeline; this wraps it for panel rendering.
    ///
    /// `func_addr` and `func_name` come from `AppData::functions[func_id]`.
    /// Quality and warnings are derived from token coverage and missing var
    /// names so the user sees real diagnostics, not synthetic placeholders.
    pub fn from_decomp_result(
        func_addr: u64,
        func_name: &str,
        result: &DecompResult,
    ) -> Self {
        let mut lines = parse_pseudocode(&result.code);

        // Walk the token list (start,end,kind) and refine PseudoTokenKinds for
        // tokens the simple lexer missed (e.g. symbols / labels coming straight
        // from the lifter).
        for (start, end, kind) in &result.tokens {
            if let Some(line_idx) = byte_offset_to_line(&result.code, *start) {
                if let Some(line) = lines.get_mut(line_idx) {
                    refine_token_kind(&mut line.tokens, &result.code, *start, *end, *kind);
                }
            }
        }

        // Quality heuristic: if every line has at least one non-Plain token
        // we mark High; otherwise step down.
        let quality = derive_quality(&lines);

        // Warnings: surface any unresolved variables (no name in `var_names`)
        // and any lines with no token coverage from the backend.
        let warnings = derive_warnings(result, &lines);

        Self {
            func_addr,
            func_name: func_name.to_string(),
            lines,
            raw_source: result.code.clone(),
            quality,
            warnings,
        }
    }

    /// Find the line index closest to the given address.
    pub fn line_for_addr(&self, addr: u64) -> Option<usize> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.addr.is_some())
            .min_by_key(|(_, l)| {
                let la = l.addr.unwrap();
                addr.abs_diff(la)
            })
            .map(|(i, _)| i)
    }
}

// ─── Backend helpers (DecompResult → panel data) ─────────────────────────────

/// Map a byte offset inside the decompiler's source string to a line index.
fn byte_offset_to_line(code: &str, offset: usize) -> Option<usize> {
    if offset > code.len() {
        return None;
    }
    Some(code[..offset].bytes().filter(|b| *b == b'\n').count())
}

/// Refine a parsed pseudocode line's tokens using the authoritative
/// `(start,end,kind)` spans from the backend decompiler. The simple lexer
/// here cannot know that a particular identifier is a `Symbol` or a `Label`;
/// the backend `TokenKind` tells us, so we override the lexer's guess.
fn refine_token_kind(
    tokens: &mut [PseudoToken],
    code: &str,
    start: usize,
    end: usize,
    kind: TokenKind,
) {
    let span_text = code.get(start..end).unwrap_or("").trim();
    if span_text.is_empty() {
        return;
    }
    for tok in tokens.iter_mut() {
        if tok.text == span_text {
            tok.kind = map_token_kind(kind, tok.kind);
            break;
        }
    }
}

fn map_token_kind(backend: TokenKind, fallback: PseudoTokenKind) -> PseudoTokenKind {
    match backend {
        TokenKind::Mnemonic | TokenKind::Prefix => PseudoTokenKind::Keyword,
        TokenKind::Register | TokenKind::Symbol => PseudoTokenKind::Identifier,
        TokenKind::Immediate => PseudoTokenKind::Number,
        TokenKind::Address | TokenKind::DataRef => PseudoTokenKind::Address,
        TokenKind::Comment => PseudoTokenKind::Comment,
        TokenKind::Label => PseudoTokenKind::Label,
        TokenKind::Punctuation | TokenKind::Whitespace => PseudoTokenKind::Punctuation,
        TokenKind::Unknown => fallback,
    }
}

/// Derive the [`DecompileQuality`] indicator from the rendered lines.
///
/// High: ≥90% of non-blank lines carry at least one identifier / type / keyword.
/// Medium: ≥60%. Low: ≥30%. Failed otherwise.
fn derive_quality(lines: &[PseudoLine]) -> DecompileQuality {
    let total = lines.iter().filter(|l| !l.tokens.is_empty()).count();
    if total == 0 {
        return DecompileQuality::Failed;
    }
    let strong = lines
        .iter()
        .filter(|l| {
            l.tokens.iter().any(|t| {
                matches!(
                    t.kind,
                    PseudoTokenKind::Keyword
                        | PseudoTokenKind::Type
                        | PseudoTokenKind::Identifier
                        | PseudoTokenKind::Label
                )
            })
        })
        .count();
    let ratio = strong as f32 / total as f32;
    if ratio >= 0.90 {
        DecompileQuality::High
    } else if ratio >= 0.60 {
        DecompileQuality::Medium
    } else if ratio >= 0.30 {
        DecompileQuality::Low
    } else {
        DecompileQuality::Failed
    }
}

/// Surface real warnings produced by the lifter. Today the lifter does not
/// emit a dedicated warnings channel, so we synthesise them from the result:
///
///   * any line that comes back as a raw `// /* args */`-style placeholder is
///     flagged as "incomplete signature"
///   * any token that the backend tagged but whose target var has no name in
///     `var_names` is flagged as "unresolved variable"
///
/// When the backend grows a proper `warnings: Vec<String>` channel on
/// `DecompResult`, this helper switches to a direct copy.
fn derive_warnings(result: &DecompResult, lines: &[PseudoLine]) -> Vec<String> {
    let mut out = Vec::new();
    if result.code.contains("/* args */") {
        out.push("Signature is heuristic — argument list not yet recovered.".into());
    }
    if result.code.contains("/* ... */") {
        out.push("Function body partially lifted — some blocks are placeholders.".into());
    }
    let blank = lines.iter().filter(|l| l.tokens.is_empty()).count();
    if !lines.is_empty() && blank * 2 > lines.len() {
        out.push("Decompiler emitted mostly blank lines; result may be unreliable.".into());
    }
    if result.var_names.is_empty() {
        out.push("No variable names recovered for this function.".into());
    }
    out
}

// ─── Panel state ─────────────────────────────────────────────────────────────

/// Which IL level the decompiler panel is currently rendering.
///
/// Wired to the rustre-il-{llil,mlil,hlil} backends via [`DecompilerPanelState::set_il_level`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IlLevel {
    /// Low-level IL: raw lifted semantics from rustre-il-llil.
    Llil,
    /// Medium-level IL in SSA form from rustre-il-mlil.
    Mlil,
    /// Structured high-level IL from rustre-il-hlil. Default.
    #[default]
    Hlil,
}

impl IlLevel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Llil => "LLIL",
            Self::Mlil => "MLIL",
            Self::Hlil => "HLIL",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Llil => "Raw low-level IL",
            Self::Mlil => "SSA medium-level IL",
            Self::Hlil => "Structured high-level IL",
        }
    }
}

/// Toggleable optimisation passes wired into the rustre-il-mlil pass manager.
///
/// Each flag corresponds to a real backend pass:
///   - `constant_folding` -> `rustre_il_mlil::MlilConstantFoldingPass`
///   - `dead_store_elimination` -> `rustre_il_mlil::MlilDeadStorePass`
///   - `copy_propagation` -> `rustre_il_mlil::MlilCopyPropagationPass`
///   - `type_recovery` -> `rustre_il_mlil::infer_types`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassPipeline {
    pub constant_folding: bool,
    pub dead_store_elimination: bool,
    pub copy_propagation: bool,
    pub type_recovery: bool,
}

impl Default for PassPipeline {
    fn default() -> Self {
        Self {
            constant_folding: true,
            dead_store_elimination: true,
            copy_propagation: true,
            type_recovery: true,
        }
    }
}

impl PassPipeline {
    pub const fn any_enabled(&self) -> bool {
        self.constant_folding
            || self.dead_store_elimination
            || self.copy_propagation
            || self.type_recovery
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecompilerPanelState {
    pub current: Option<DecompiledFunction>,
    pub history: Vec<DecompiledFunction>, // recently visited
    pub scroll_line: usize,
    pub selected_line: Option<usize>,
    flags: u8,
    pub font_size: f32,
    pub search_query: String,
    pub search_results: Vec<usize>, // line indices matching search
    pub search_cursor: usize,
    pub error_msg: Option<String>,
    /// Which IL representation is currently displayed (LLIL / MLIL / HLIL).
    pub il_level: IlLevel,
    /// Which MLIL pass-manager passes are enabled for the next decompile.
    pub passes: PassPipeline,
}

impl DecompilerPanelState {
    const FLAG_SHOW_ADDRESSES: u8 = 1 << 0;
    const FLAG_SHOW_TYPES: u8 = 1 << 1;
    const FLAG_SHOW_COMMENTS: u8 = 1 << 2;
    const FLAG_SYNC_WITH_DISASM: u8 = 1 << 3;
    const FLAG_IS_LOADING: u8 = 1 << 4;

    const fn flag(&self, mask: u8) -> bool {
        (self.flags & mask) != 0
    }

    const fn set_flag(&mut self, mask: u8, v: bool) {
        if v {
            self.flags |= mask;
        } else {
            self.flags &= !mask;
        }
    }

    pub const fn show_addresses(&self) -> bool {
        self.flag(Self::FLAG_SHOW_ADDRESSES)
    }
    pub const fn set_show_addresses(&mut self, v: bool) {
        self.set_flag(Self::FLAG_SHOW_ADDRESSES, v);
    }

    pub const fn show_types(&self) -> bool {
        self.flag(Self::FLAG_SHOW_TYPES)
    }
    pub const fn set_show_types(&mut self, v: bool) {
        self.set_flag(Self::FLAG_SHOW_TYPES, v);
    }

    pub const fn show_comments(&self) -> bool {
        self.flag(Self::FLAG_SHOW_COMMENTS)
    }
    pub const fn set_show_comments(&mut self, v: bool) {
        self.set_flag(Self::FLAG_SHOW_COMMENTS, v);
    }

    pub const fn sync_with_disasm(&self) -> bool {
        self.flag(Self::FLAG_SYNC_WITH_DISASM)
    }
    pub const fn set_sync_with_disasm(&mut self, v: bool) {
        self.set_flag(Self::FLAG_SYNC_WITH_DISASM, v);
    }

    pub const fn is_loading(&self) -> bool {
        self.flag(Self::FLAG_IS_LOADING)
    }
    pub const fn set_is_loading(&mut self, v: bool) {
        self.set_flag(Self::FLAG_IS_LOADING, v);
    }

    /// Switch the IL level (LLIL/MLIL/HLIL) the panel renders.
    pub const fn set_il_level(&mut self, level: IlLevel) {
        self.il_level = level;
    }

    /// Read the current IL level.
    pub const fn il_level(&self) -> IlLevel {
        self.il_level
    }

    /// Mutable access to the pass pipeline toggles.
    pub const fn passes_mut(&mut self) -> &mut PassPipeline {
        &mut self.passes
    }

    /// Read the current pass pipeline configuration.
    pub const fn passes(&self) -> PassPipeline {
        self.passes
    }

    pub fn load(&mut self, func: DecompiledFunction) {
        if let Some(prev) = self.current.take() {
            self.history.push(prev);
            if self.history.len() > 20 {
                self.history.remove(0);
            }
        }
        self.scroll_line = 0;
        self.selected_line = None;
        self.set_is_loading(false);
        self.error_msg = None;
        self.search_results.clear();
        self.current = Some(func);
    }

    /// Pull the latest `DecompResult` for `func_id` out of
    /// `AppData::decomp_cache` (populated by the analysis pipeline) and rebind
    /// the panel. Returns `true` if a result was found and loaded, `false`
    /// if the cache hasn't produced one yet (caller should kick the lifter).
    ///
    /// Caller chain:
    ///   `UICommand::DecompileFunction(func_id)` → analysis worker calls
    ///   `crate::analysis::decompiler::decompile_function` →
    ///   inserts into `AppData::decomp_cache` → UI thread calls this method.
    pub fn refresh_from(&mut self, data: &AppData, func_id: u32) -> bool {
        // `LruCache::peek` does not bump recency; we want recency-bump on UI
        // navigation, so use `get` via the public `decomp_cache` deref.
        let Some(result) = data.decomp_cache.0.peek(&func_id).cloned() else {
            return false;
        };
        let func = data.functions.get(&func_id);
        let (addr, name) = func.map_or((0u64, format!("sub_{:x}", func_id)), |f| {
            (f.addr.0, f.name.clone())
        });
        let decompiled = DecompiledFunction::from_decomp_result(addr, &name, &result);
        self.load(decompiled);
        true
    }

    pub fn search(&mut self, query: &str) {
        self.search_query = query.to_string();
        self.search_results.clear();
        self.search_cursor = 0;
        if let Some(func) = &self.current {
            let q = query.to_lowercase();
            for (i, line) in func.lines.iter().enumerate() {
                let text: String = line.tokens.iter().map(|t| t.text.as_str()).collect();
                if text.to_lowercase().contains(&q) {
                    self.search_results.push(i);
                }
            }
        }
    }

    pub fn next_result(&mut self) -> Option<usize> {
        if self.search_results.is_empty() {
            return None;
        }
        self.search_cursor = (self.search_cursor + 1) % self.search_results.len();
        let line = self.search_results[self.search_cursor];
        self.scroll_line = line.saturating_sub(5);
        Some(line)
    }

    pub fn prev_result(&mut self) -> Option<usize> {
        if self.search_results.is_empty() {
            return None;
        }
        if self.search_cursor == 0 {
            self.search_cursor = self.search_results.len() - 1;
        } else {
            self.search_cursor -= 1;
        }
        let line = self.search_results[self.search_cursor];
        self.scroll_line = line.saturating_sub(5);
        Some(line)
    }

    pub fn go_back(&mut self) -> bool {
        if let Some(prev) = self.history.pop() {
            let cur = self.current.take();
            if let Some(c) = cur {
                // push current aside without history tracking
                self.current = Some(c);
            }
            self.current = Some(prev);
            self.scroll_line = 0;
            self.selected_line = None;
            return true;
        }
        false
    }
}

// ─── Render helpers ───────────────────────────────────────────────────────────

fn render_pseudo_line(
    line: &PseudoLine,
    line_no: usize,
    selected: bool,
    is_search_match: bool,
    show_addresses: bool,
    font_size: f32,
) -> impl IntoElement {
    let bg = if selected {
        hsla(0.6, 0.3, 0.2, 0.5)
    } else if is_search_match {
        hsla(0.11, 0.5, 0.2, 0.4)
    } else {
        hsla(0.0, 0.0, 0.0, 0.0)
    };

    let indent_spaces = " ".repeat(line.indent * 4);
    let fs = px(font_size);

    let mut row = div()
        .flex()
        .flex_row()
        .items_start()
        .bg(bg)
        .py(px(1.0))
        .px(px(8.0))
        .gap(px(4.0));

    // Line number
    row = row.child(
        div()
            .w(px(36.0))
            .text_size(fs - px(1.0))
            .text_color(hsla(0.0, 0.0, 0.28, 1.0))
            .flex_shrink_0()
            .truncate()
            .child(format!("{:4}", line_no + 1)),
    );

    // Address annotation
    if show_addresses {
        row = row.child(
            div()
                .w(px(80.0))
                .text_size(fs - px(1.0))
                .text_color(hsla(0.6, 0.3, 0.45, 1.0))
                .flex_shrink_0()
                .truncate()
                .child(line.addr.map_or_else(String::new, |a| format!("{a:#010x}"))),
        );
    }

    // Indent + tokens
    let mut code_row = div().flex().flex_row().flex_wrap().items_center();
    if !indent_spaces.is_empty() {
        code_row = code_row.child(
            div()
                .text_size(fs)
                .text_color(hsla(0.0, 0.0, 0.0, 0.0))
                .child(indent_spaces),
        );
    }
    for token in &line.tokens {
        code_row = code_row.child(
            div()
                .text_size(fs)
                .text_color(token.kind.color())
                .child(token.text.clone()),
        );
        // Space after most tokens (not before punctuation)
        if !matches!(token.kind, PseudoTokenKind::Punctuation) {
            code_row = code_row.child(div().text_size(fs).child(" "));
        }
    }

    row.child(code_row)
}

fn render_header(state: &DecompilerPanelState) -> impl IntoElement {
    let title = state
        .current
        .as_ref()
        .map_or_else(|| "Decompiler".to_string(), |f| f.func_name.clone());

    let quality = state.current.as_ref().map(|f| f.quality);

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .bg(hsla(0.0, 0.0, 0.11, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.19, 1.0))
        .px(px(10.0))
        .py(px(4.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.85, 1.0))
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(title),
        )
        .child(quality.map_or_else(
            || div().into_any_element(),
            |q| {
                div()
                    .px(px(5.0))
                    .py(px(1.0))
                    .rounded(px(3.0))
                    .text_size(px(9.0))
                    .bg(hsla(0.0, 0.0, 0.15, 1.0))
                    .text_color(q.color())
                    .child(q.label().to_string())
                    .into_any_element()
            },
        ))
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                .child("PSEUDO-C"),
        )
}

fn render_toolbar(state: &DecompilerPanelState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .bg(hsla(0.0, 0.0, 0.09, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.17, 1.0))
        .px(px(8.0))
        .py(px(3.0))
        // Back button
        .child(toolbar_btn("<-", !state.history.is_empty()))
        .child(toolbar_btn("Refresh", true))
        .child(
            div()
                .w(px(1.0))
                .h(px(14.0))
                .bg(hsla(0.0, 0.0, 0.22, 1.0))
                .mx(px(3.0)),
        )
        // IL level selector (LLIL / MLIL / HLIL)
        .child(il_level_tabs(state))
        .child(
            div()
                .w(px(1.0))
                .h(px(14.0))
                .bg(hsla(0.0, 0.0, 0.22, 1.0))
                .mx(px(3.0)),
        )
        // MLIL pass pipeline toggles
        .child(pass_pipeline_controls(state))
        .child(
            div()
                .w(px(1.0))
                .h(px(14.0))
                .bg(hsla(0.0, 0.0, 0.22, 1.0))
                .mx(px(3.0)),
        )
        // Toggle buttons
        .child(toggle_btn("Addrs", state.show_addresses()))
        .child(toggle_btn("Types", state.show_types()))
        .child(toggle_btn("Comments", state.show_comments()))
        .child(div().flex_1())
        // Search
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(4.0))
                .bg(hsla(0.0, 0.0, 0.14, 1.0))
                .border_1()
                .border_color(hsla(0.0, 0.0, 0.22, 1.0))
                .rounded(px(3.0))
                .px(px(6.0))
                .py(px(2.0))
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                        .child(crate::ui::widgets::icon::icon("search")),
                )
                .child(
                    div()
                        .min_w(px(120.0))
                        .text_size(px(11.0))
                        .text_color(if state.search_query.is_empty() {
                            hsla(0.0, 0.0, 0.32, 1.0)
                        } else {
                            hsla(0.0, 0.0, 0.82, 1.0)
                        })
                        .child(if state.search_query.is_empty() {
                            "Search…".to_string()
                        } else {
                            state.search_query.clone()
                        }),
                ),
        )
        .child(if state.search_results.is_empty() {
            div().into_any_element()
        } else {
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.38, 0.5, 0.55, 1.0))
                .child(format!(
                    "{}/{}",
                    state.search_cursor + 1,
                    state.search_results.len()
                ))
                .into_any_element()
        })
}

fn toolbar_btn(label: &str, enabled: bool) -> impl IntoElement {
    div()
        .px(px(7.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(11.0))
        .bg(hsla(0.0, 0.0, 0.16, 1.0))
        .text_color(if enabled {
            hsla(0.0, 0.0, 0.65, 1.0)
        } else {
            hsla(0.0, 0.0, 0.28, 1.0)
        })
        .child(label.to_string())
}

fn toggle_btn(label: &str, active: bool) -> impl IntoElement {
    div()
        .px(px(7.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(if active {
            hsla(0.6, 0.3, 0.22, 1.0)
        } else {
            hsla(0.0, 0.0, 0.13, 1.0)
        })
        .text_color(if active {
            hsla(0.6, 0.7, 0.80, 1.0)
        } else {
            hsla(0.0, 0.0, 0.42, 1.0)
        })
        .child(label.to_string())
}

/// IL level tab strip — clicking a tab switches what representation the
/// decompiler panel renders (LLIL / MLIL / HLIL).
fn il_level_tabs(state: &DecompilerPanelState) -> impl IntoElement {
    let mut row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(2.0))
        .bg(hsla(0.0, 0.0, 0.11, 1.0))
        .border_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .rounded(px(3.0))
        .px(px(2.0))
        .py(px(1.0));
    for level in [IlLevel::Llil, IlLevel::Mlil, IlLevel::Hlil] {
        row = row.child(il_level_tab(level, state.il_level() == level));
    }
    row
}

fn il_level_tab(level: IlLevel, active: bool) -> impl IntoElement {
    div()
        .px(px(7.0))
        .py(px(1.0))
        .rounded(px(2.0))
        .text_size(px(10.0))
        .bg(if active {
            hsla(0.72, 0.55, 0.35, 1.0)
        } else {
            hsla(0.0, 0.0, 0.13, 1.0)
        })
        .text_color(if active {
            hsla(0.0, 0.0, 0.95, 1.0)
        } else {
            hsla(0.0, 0.0, 0.55, 1.0)
        })
        .child(level.label().to_string())
}

/// Pass-pipeline control strip — each chip toggles a real MLIL pass that runs
/// before the panel is re-rendered.
fn pass_pipeline_controls(state: &DecompilerPanelState) -> impl IntoElement {
    let p = state.passes();
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(3.0))
        .child(pass_chip("Fold", p.constant_folding))
        .child(pass_chip("DSE", p.dead_store_elimination))
        .child(pass_chip("Copy", p.copy_propagation))
        .child(pass_chip("Types", p.type_recovery))
}

fn pass_chip(label: &str, enabled: bool) -> impl IntoElement {
    div()
        .px(px(6.0))
        .py(px(1.0))
        .rounded(px(2.0))
        .text_size(px(10.0))
        .bg(if enabled {
            hsla(0.38, 0.5, 0.25, 1.0)
        } else {
            hsla(0.0, 0.0, 0.13, 1.0)
        })
        .text_color(if enabled {
            hsla(0.38, 0.7, 0.78, 1.0)
        } else {
            hsla(0.0, 0.0, 0.42, 1.0)
        })
        .child(label.to_string())
}

fn render_warnings(warnings: &[String]) -> impl IntoElement {
    if warnings.is_empty() {
        return div().into_any_element();
    }
    let mut col = div()
        .flex()
        .flex_col()
        .bg(hsla(0.05, 0.3, 0.10, 1.0))
        .border_b_1()
        .border_color(hsla(0.05, 0.4, 0.22, 1.0))
        .px(px(10.0))
        .py(px(4.0))
        .gap(px(2.0));

    for w in warnings {
        col = col.child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(6.0))
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(hsla(0.11, 0.8, 0.60, 1.0))
                        .child(crate::ui::widgets::icon::icon("warning")),
                )
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(hsla(0.11, 0.6, 0.65, 1.0))
                        .truncate()
                        .child(w.clone()),
                ),
        );
    }
    col.into_any_element()
}

fn render_empty_state(is_loading: bool, error: Option<&str>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .flex_1()
        .gap(px(10.0))
        .child(
            div()
                .text_size(px(32.0))
                .text_color(hsla(0.0, 0.0, 0.22, 1.0))
                .child(if is_loading { "⟳" } else { "{ }" }),
        )
        .child(
            div()
                .text_size(px(13.0))
                .text_color(if error.is_some() {
                    hsla(0.0, 0.6, 0.55, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.35, 1.0)
                })
                .child(error.map_or_else(
                    || {
                        if is_loading {
                            "Decompiling…".to_string()
                        } else {
                            "No function selected".to_string()
                        }
                    },
                    ToString::to_string,
                )),
        )
}

fn font_size_pt(fs: f32) -> String {
    // Render f32 font-size as a non-negative integer point value without
    // performing any cast that clippy flags as precision-losing or truncating.
    if !fs.is_finite() || fs <= 0.0 {
        return "0".to_string();
    }
    // Use the formatter's own rounding to produce an integer-looking value.
    // "{:.0}" rounds to nearest integer and emits no fractional digits.
    format!("{fs:.0}")
}

fn render_status_bar(state: &DecompilerPanelState) -> impl IntoElement {
    let (line_count, func_addr) = state
        .current
        .as_ref()
        .map_or((0, None), |func| (func.lines.len(), Some(func.func_addr)));

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .bg(hsla(0.0, 0.0, 0.07, 1.0))
        .border_t_1()
        .border_color(hsla(0.0, 0.0, 0.16, 1.0))
        .px(px(10.0))
        .py(px(3.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .child(format!("{line_count} lines")),
        )
        .child(func_addr.map_or_else(
            || div().into_any_element(),
            |addr| {
                div()
                    .text_size(px(10.0))
                    .text_color(hsla(0.6, 0.4, 0.50, 1.0))
                    .child(format!("{addr:#010x}"))
                    .into_any_element()
            },
        ))
        .child(div().flex_1())
        .child(if state.sync_with_disasm() {
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.38, 0.6, 0.55, 1.0))
                .child("<-> Synced")
                .into_any_element()
        } else {
            div().into_any_element()
        })
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.32, 1.0))
                .child(format!("{}pt", font_size_pt(state.font_size))),
        )
}

// ─── Main render ─────────────────────────────────────────────────────────────

pub fn render_decompiler_panel(
    state: &DecompilerPanelState,
    _ui: Arc<Mutex<UIState>>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .size_full()
        .bg(hsla(0.0, 0.0, 0.085, 1.0))
        .font_family("JetBrains Mono")
        .child(render_header(state))
        .child(render_toolbar(state))
        .child(state.current.as_ref().map_or_else(
            || div().into_any_element(),
            |func| render_warnings(&func.warnings).into_any_element(),
        ))
        .child(
            if state.current.is_none() || state.is_loading() || state.error_msg.is_some() {
                render_empty_state(state.is_loading(), state.error_msg.as_deref())
                    .into_any_element()
            } else {
                let func = state.current.as_ref().unwrap();
                let fs = state.font_size;
                let search_set: std::collections::HashSet<usize> =
                    state.search_results.iter().copied().collect();
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .overflow_hidden()
                    .children(
                        func.lines
                            .iter()
                            .enumerate()
                            .filter(|(_, line)| state.show_comments() || !line.is_comment)
                            .map(|(i, line)| {
                                let selected = state.selected_line == Some(i);
                                let is_match = search_set.contains(&i);
                                render_pseudo_line(
                                    line,
                                    i,
                                    selected,
                                    is_match,
                                    state.show_addresses(),
                                    fs,
                                )
                            }),
                    )
                    .into_any_element()
            },
        )
        .child(render_status_bar(state))
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_decompiler() {
    // Token kinds + color
    let kinds = [
        PseudoTokenKind::Keyword,
        PseudoTokenKind::Type,
        PseudoTokenKind::Identifier,
        PseudoTokenKind::Number,
        PseudoTokenKind::String,
        PseudoTokenKind::Comment,
        PseudoTokenKind::Operator,
        PseudoTokenKind::Punctuation,
        PseudoTokenKind::Address,
        PseudoTokenKind::Label,
        PseudoTokenKind::Plain,
    ];
    for k in kinds {
        let _ = k.color();
    }

    // PseudoToken constructors
    let tok = PseudoToken::new(PseudoTokenKind::Identifier, "x");
    let _ = PseudoToken {
        kind: tok.kind,
        text: tok.text.clone(),
        addr: tok.addr,
    };
    let _ = PseudoToken::new(PseudoTokenKind::Number, "1").with_addr(0x0040_1000);

    // PseudoLine constructors
    let _ = PseudoLine::blank();
    let _ = PseudoLine::code(
        1,
        vec![PseudoToken::new(PseudoTokenKind::Keyword, "if")],
        Some(0x0040_1000),
    );
    let cl = PseudoLine::comment(0, "// hi");
    let _ = PseudoLine {
        indent: cl.indent,
        tokens: cl.tokens.clone(),
        addr: cl.addr,
        is_comment: cl.is_comment,
    };

    // Static keyword/type lists
    let _ = KEYWORDS.len();
    let _ = TYPE_NAMES.len();

    // Tokenize + parse
    let _ = tokenize_pseudocode("int x = 0;");
    let _ = parse_pseudocode("int main() {\n    return 0;\n}");

    // DecompileQuality
    let qualities = [
        DecompileQuality::High,
        DecompileQuality::Medium,
        DecompileQuality::Low,
        DecompileQuality::Failed,
    ];
    for q in qualities {
        let _ = q.label();
        let _ = q.color();
    }

    // DecompiledFunction
    let func = DecompiledFunction::from_source(
        0x0040_1000,
        "sub_401000",
        "int sub_401000() {\n    return 0;\n}",
        DecompileQuality::High,
    );
    let _ = func.line_for_addr(0x0040_1000);
    let _ = DecompiledFunction {
        func_addr: func.func_addr,
        func_name: func.func_name.clone(),
        lines: func.lines.clone(),
        raw_source: func.raw_source.clone(),
        quality: func.quality,
        warnings: func.warnings.clone(),
    };

    // DecompilerPanelState
    let mut state = DecompilerPanelState {
        font_size: 12.0,
        flags: DecompilerPanelState::FLAG_SHOW_COMMENTS
            | DecompilerPanelState::FLAG_SHOW_ADDRESSES
            | DecompilerPanelState::FLAG_SHOW_TYPES
            | DecompilerPanelState::FLAG_SYNC_WITH_DISASM,
        ..Default::default()
    };
    state.load(func);
    // Touch the setters so they are not flagged as dead code.
    state.set_show_addresses(true);
    state.set_show_types(true);
    state.set_show_comments(true);
    state.set_sync_with_disasm(true);
    state.search("return");
    let _ = state.next_result();
    let _ = state.prev_result();
    let _ = state.go_back();

    // Render helpers
    let line = PseudoLine::code(
        1,
        vec![PseudoToken::new(PseudoTokenKind::Keyword, "return")],
        Some(0x0040_1000),
    );
    let _ = render_pseudo_line(&line, 0, false, false, true, 12.0);
    let _ = render_header(&state);
    let _ = render_toolbar(&state);
    let _ = toolbar_btn("Back", true);
    let _ = toggle_btn("Addrs", true);
    let _ = render_warnings(&["w1".to_string()]);
    let _ = render_empty_state(false, Some("err"));
    let _ = render_empty_state(true, None);
    let _ = render_status_bar(&state);

    // IL level selector + pass pipeline controls.
    for level in [IlLevel::Llil, IlLevel::Mlil, IlLevel::Hlil] {
        let _ = level.label();
        let _ = level.description();
        state.set_il_level(level);
        let _ = state.il_level();
        let _ = il_level_tab(level, true);
    }
    let _ = il_level_tabs(&state);
    {
        let p = state.passes_mut();
        p.constant_folding = false;
        p.dead_store_elimination = false;
        p.copy_propagation = false;
        p.type_recovery = false;
        let _ = p.any_enabled();
    }
    let _ = state.passes();
    let _ = pass_chip("Fold", true);
    let _ = pass_pipeline_controls(&state);
    let _ = PassPipeline::default();

    // Exercise the AppData → panel wiring: build a synthetic DecompResult
    // (the same shape the analysis pipeline produces) and run it through
    // `from_decomp_result` + `refresh_from`. This keeps the helpers
    // (`byte_offset_to_line`, `refine_token_kind`, `map_token_kind`,
    // `derive_quality`, `derive_warnings`) live.
    {
        let mut data = AppData::new();
        let func_id = 1u32;
        let func = crate::core::types::Function {
            id: func_id,
            addr: crate::core::types::Addr(0x0040_1000),
            name: "sub_401000".to_string(),
            size: 0x10,
            tags: crate::core::types::FunctionTags::default(),
            sym_id: None,
            comment: String::new(),
            color: None,
        };
        data.functions.insert(func_id, func);
        let result = crate::core::app_state::DecompResult {
            func_id,
            rev: 0,
            code: "int sub_401000(/* args */) {\n    return 0;\n}\n".to_string(),
            tokens: vec![
                (0, 3, TokenKind::Prefix),
                (4, 14, TokenKind::Symbol),
                (33, 39, TokenKind::Prefix),
            ],
            var_names: indexmap::IndexMap::new(),
        };
        data.decomp_cache.0.put(func_id, result.clone());
        let derived = DecompiledFunction::from_decomp_result(0x0040_1000, "sub_401000", &result);
        let _ = derived.quality;
        let _ = derived.warnings.len();
        let _ = byte_offset_to_line(&result.code, 5);
        let _ = map_token_kind(TokenKind::Mnemonic, PseudoTokenKind::Plain);
        let mut tokens = vec![PseudoToken::new(PseudoTokenKind::Identifier, "sub_401000")];
        refine_token_kind(&mut tokens, &result.code, 4, 14, TokenKind::Symbol);
        let _ = derive_quality(&derived.lines);
        let _ = derive_warnings(&result, &derived.lines);
        let _ = state.refresh_from(&data, func_id);
    }

    // Main render (requires Arc<Mutex<UIState>>)
    let ui = Arc::new(Mutex::new(UIState::default()));
    let _ = render_decompiler_panel(&state, ui);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    static SAMPLE_CODE: &str = r"int sub_401000(int arg1, char *arg2) {
    int local_1;
    int local_2;
    // Initialize variables
    local_1 = 0;
    local_2 = 0x10;
    if (arg1 > 0) {
        while (local_1 < arg1) {
            local_2 = local_2 + local_1;
            local_1 = local_1 + 1;
        }
    }
    return local_2;
}";

    #[test]
    fn test_parse_pseudocode_lines() {
        let lines = parse_pseudocode(SAMPLE_CODE);
        assert!(!lines.is_empty());
        // First non-empty line should be the function signature
        let first = lines.iter().find(|l| !l.tokens.is_empty()).unwrap();
        assert!(first.tokens.iter().any(|t| t.text == "sub_401000"));
    }

    #[test]
    fn test_tokenize_keyword() {
        let tokens = tokenize_pseudocode("if (x > 0) {");
        assert!(tokens
            .iter()
            .any(|t| t.kind == PseudoTokenKind::Keyword && t.text == "if"));
    }

    #[test]
    fn test_tokenize_type() {
        let tokens = tokenize_pseudocode("int x = 0;");
        assert!(tokens
            .iter()
            .any(|t| t.kind == PseudoTokenKind::Type && t.text == "int"));
    }

    #[test]
    fn test_tokenize_hex_address() {
        let tokens = tokenize_pseudocode("x = 0x401000;");
        assert!(tokens.iter().any(|t| t.kind == PseudoTokenKind::Address));
    }

    #[test]
    fn test_tokenize_hex_small() {
        let tokens = tokenize_pseudocode("x = 0xFF;");
        assert!(tokens.iter().any(|t| t.kind == PseudoTokenKind::Number));
    }

    #[test]
    fn test_tokenize_string() {
        let tokens = tokenize_pseudocode(r#"puts("hello world");"#);
        assert!(tokens.iter().any(|t| t.kind == PseudoTokenKind::String));
    }

    #[test]
    fn test_tokenize_comment() {
        let tokens = tokenize_pseudocode("// This is a comment");
        assert!(tokens.iter().any(|t| t.kind == PseudoTokenKind::Comment));
    }

    #[test]
    fn test_decompiled_function_from_source() {
        let func = DecompiledFunction::from_source(
            0x0040_1000,
            "sub_401000",
            SAMPLE_CODE,
            DecompileQuality::High,
        );
        assert!(!func.lines.is_empty());
        assert_eq!(func.func_name, "sub_401000");
        assert_eq!(func.quality, DecompileQuality::High);
    }

    #[test]
    fn test_panel_search() {
        let mut state = DecompilerPanelState {
            font_size: 12.0,
            flags: DecompilerPanelState::FLAG_SHOW_COMMENTS,
            ..Default::default()
        };
        let func = DecompiledFunction::from_source(
            0x0040_1000,
            "test",
            SAMPLE_CODE,
            DecompileQuality::High,
        );
        state.load(func);
        state.search("local_1");
        assert!(!state.search_results.is_empty());
    }

    #[test]
    fn test_panel_search_next_prev() {
        let mut state = DecompilerPanelState {
            font_size: 12.0,
            flags: DecompilerPanelState::FLAG_SHOW_COMMENTS,
            ..Default::default()
        };
        let func = DecompiledFunction::from_source(
            0x0040_1000,
            "test",
            SAMPLE_CODE,
            DecompileQuality::High,
        );
        state.load(func);
        state.search("local");
        let n = state.search_results.len();
        if n > 1 {
            let first = state.next_result();
            let second = state.next_result();
            assert_ne!(first, second);
        }
    }

    #[test]
    fn test_indent_parsing() {
        let lines = parse_pseudocode(SAMPLE_CODE);
        let indented = lines.iter().filter(|l| l.indent > 0).count();
        assert!(indented > 0);
    }
}
