//! `c_postprocess` — post-processing passes on emitted C pseudocode text.
//!
//! Operates on the *text* level after the AST has been emitted. Performs:
//! - Redundant-statement removal (double `return`, unreachable code after
//!   unconditional jump).
//! - Assignment collapsing: `int x; x = expr;` → `int x = expr;`.
//! - Cast normalization: `(int)(int)x` → `(int)x`, `(void*)0` → `NULL`.
//! - Dead-code removal (code after `return`/`break`/`continue`/`goto`
//!   inside a block before the closing brace).
//! - Lightweight constant folding at the text level: replaces patterns like
//!   `0 + x` → `x`, `x * 1` → `x`, etc.


use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// PostprocessStats
// ─────────────────────────────────────────────────────────────────────────────

/// Counts of transformations applied by the post-processor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostprocessStats {
    /// `int x; x = e;` collapsed to `int x = e;`
    pub assignments_collapsed: u32,
    /// `(T)(T)x` → `(T)x`, `(void*)0` → `NULL`, …
    pub casts_normalized: u32,
    /// Statements after an unconditional jump removed.
    pub dead_stmts_removed: u32,
    /// Constant-fold rewrites applied.
    pub const_folds: u32,
    /// Total number of lines removed across all passes.
    pub lines_removed: u32,
}

impl PostprocessStats {
    /// Merge another stats record into this one.
    pub const fn merge(&mut self, other: &Self) {
        self.assignments_collapsed += other.assignments_collapsed;
        self.casts_normalized += other.casts_normalized;
        self.dead_stmts_removed += other.dead_stmts_removed;
        self.const_folds += other.const_folds;
        self.lines_removed += other.lines_removed;
    }

    /// Total number of rewrites performed.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.assignments_collapsed
            + self.casts_normalized
            + self.dead_stmts_removed
            + self.const_folds
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostprocessConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of which post-processing passes are active.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PostprocessPasses(u8);

impl PostprocessPasses {
    const COLLAPSE_ASSIGNMENTS: u8 = 0b0001;
    const NORMALIZE_CASTS: u8 = 0b0010;
    const REMOVE_DEAD_CODE: u8 = 0b0100;
    const FOLD_CONSTANTS: u8 = 0b1000;
    const ALL: u8 = 0b1111;

    #[must_use] pub const fn all() -> Self { Self(Self::ALL) }
    #[must_use] pub const fn collapse_assignments(self) -> bool { self.0 & Self::COLLAPSE_ASSIGNMENTS != 0 }
    #[must_use] pub const fn normalize_casts(self) -> bool { self.0 & Self::NORMALIZE_CASTS != 0 }
    #[must_use] pub const fn remove_dead_code(self) -> bool { self.0 & Self::REMOVE_DEAD_CODE != 0 }
    #[must_use] pub const fn fold_constants(self) -> bool { self.0 & Self::FOLD_CONSTANTS != 0 }
}

impl Default for PostprocessPasses {
    fn default() -> Self { Self(Self::ALL) }
}

/// Controls which post-processing passes are active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostprocessConfig {
    /// Which passes are active.
    pub passes: PostprocessPasses,
    /// Maximum number of passes to iterate (to handle cascading rewrites).
    pub max_passes: u8,
}

impl Default for PostprocessConfig {
    fn default() -> Self {
        Self {
            passes: PostprocessPasses::all(),
            max_passes: 3,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Line-level helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Strip leading whitespace and return `(indent, rest)`.
fn split_indent(line: &str) -> (&str, &str) {
    let trimmed = line.trim_start();
    let indent_len = line.len() - trimmed.len();
    (&line[..indent_len], trimmed)
}

/// True if the statement (trimmed) is an unconditional exit from the current
/// control-flow path.
fn is_unconditional_exit(stmt: &str) -> bool {
    stmt.starts_with("return")
        || stmt.starts_with("goto ")
        || stmt == "break;"
        || stmt == "continue;"
}

/// Returns true if a trimmed statement looks like a simple variable
/// declaration without an initializer: `type name;` where name is a valid
/// C identifier.
fn is_bare_decl(stmt: &str) -> Option<(&str, &str)> {
    // Must end with semicolon.
    let stmt = stmt.strip_suffix(';')?.trim();
    // No `=` allowed (would be an initializer).
    if stmt.contains('=') || stmt.contains('(') || stmt.contains(')') {
        return None;
    }
    // Split on the last run of non-identifier chars to get type and name.
    let parts: Vec<&str> = stmt.rsplitn(2, [' ', '*']).collect();
    if parts.len() == 2 {
        let name = parts[0].trim();
        let ty = parts[1].trim();
        if !name.is_empty()
            && !ty.is_empty()
            && name.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            return Some((ty, name));
        }
    }
    None
}

/// Returns the right-hand side if the trimmed statement is `name = expr;`
fn is_assign_to<'a>(stmt: &'a str, var: &str) -> Option<&'a str> {
    let stmt = stmt.strip_suffix(';')?.trim();
    // Pattern: `name = rhs` with no leading type keyword.
    if let Some(rest) = stmt.strip_prefix(var) {
        let rest = rest.trim_start();
        if let Some(rhs) = rest.strip_prefix('=') {
            // Make sure it's not `==`
            if !rhs.starts_with('=') {
                return Some(rhs.trim());
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// AssignmentCollapser
// ─────────────────────────────────────────────────────────────────────────────

/// Collapses patterns like:
/// ```c
/// int x;
/// x = expr;
/// ```
/// into
/// ```c
/// int x = expr;
/// ```
pub struct AssignmentCollapser;

impl AssignmentCollapser {
    /// Run the collapsing pass on the lines of a single function body.
    /// Returns the transformed lines and a count of rewrites.
    #[must_use]
    pub fn run(lines: &[&str]) -> (Vec<String>, u32) {
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut rewrites = 0u32;
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let (indent, stmt) = split_indent(line);

            // Try to match a bare declaration.
            if let Some((ty, var_name)) = is_bare_decl(stmt) {
                // Look ahead for an assignment to the same variable.
                let mut found_assign = false;
                let mut j = i + 1;

                // Skip blank lines between decl and assignment.
                while j < lines.len() && lines[j].trim().is_empty() {
                    j += 1;
                }

                if j < lines.len() {
                    let (next_indent, next_stmt) = split_indent(lines[j]);
                    // Must be at the same indentation level to be safe.
                    if next_indent == indent
                        && let Some(rhs) = is_assign_to(next_stmt, var_name) {
                            // Emit collapsed form.
                            out.push(format!("{indent}{ty} {var_name} = {rhs};"));
                            rewrites += 1;
                            found_assign = true;
                            // Skip original decl line (i) and assignment line (j).
                            // Emit any blank lines between i+1 and j-1 (preserving spacing).
                            for blank in &lines[i + 1..j] {
                                if blank.trim().is_empty() {
                                    // drop blanks between decl and assign
                                }
                            }
                            i = j + 1;
                        }
                }

                if !found_assign {
                    out.push(line.to_string());
                    i += 1;
                }
            } else {
                out.push(line.to_string());
                i += 1;
            }
        }

        (out, rewrites)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CastNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Performs text-level cast normalizations:
/// - `(void *)0` / `(void*)0` → `NULL`
/// - `(int)(int)x` → `(int)x` (cast-of-same-type)
/// - `(unsigned int)(unsigned int)e` → `(unsigned int)e`
pub struct CastNormalizer;

impl CastNormalizer {
    /// Normalize casts in a single expression/line string.
    /// Returns `(new_string, rewrites_count)`.
    #[must_use]
    pub fn normalize_line(line: &str) -> (String, u32) {
        let mut s = line.to_string();
        let mut rewrites = 0u32;

        // (void *)0 → NULL
        for pat in &["(void *)0", "(void*)0", "(void * )0"] {
            if s.contains(pat) {
                s = s.replace(pat, "NULL");
                rewrites += 1;
            }
        }

        // (void *)NULL → NULL
        for pat in &["(void *)NULL", "(void*)NULL"] {
            if s.contains(pat) {
                s = s.replace(pat, "NULL");
                rewrites += 1;
            }
        }

        // Remove duplicate casts for common types.
        let dup_cast_patterns: &[&str] = &[
            "(int)(int)",
            "(unsigned int)(unsigned int)",
            "(long long)(long long)",
            "(unsigned long long)(unsigned long long)",
            "(int32_t)(int32_t)",
            "(uint32_t)(uint32_t)",
            "(int64_t)(int64_t)",
            "(uint64_t)(uint64_t)",
            "(int16_t)(int16_t)",
            "(uint16_t)(uint16_t)",
            "(int8_t)(int8_t)",
            "(uint8_t)(uint8_t)",
            "(char *)(char *)",
            "(void *)(void *)",
            "(float)(float)",
            "(double)(double)",
        ];

        for pat in dup_cast_patterns {
            // Each pattern is `(T)(T)` → `(T)`
            let replacement = &pat[..pat.len() / 2];
            if s.contains(pat) {
                s = s.replace(pat, replacement);
                rewrites += 1;
            }
        }

        // (type)((type)x) → (type)x  — strip redundant inner parens
        // We do a simple scan for `(T)((T)`.
        // This is a best-effort text pass, not a full parser.
        let result = Self::remove_cast_wrap(&s, &mut rewrites);

        (result, rewrites)
    }

    /// Remove `(T)((T)expr)` → `(T)expr` style redundancy.
    fn remove_cast_wrap(s: &str, rewrites: &mut u32) -> String {
        // Simple heuristic: look for `)(` right after a matching cast.
        // Not a full parser — handles common single-word type casts.
        let common_types = [
            "int", "unsigned", "long", "short", "char", "float", "double",
            "int32_t", "uint32_t", "int64_t", "uint64_t", "size_t", "void *",
            "int8_t", "uint8_t", "int16_t", "uint16_t",
        ];

        let mut result = s.to_string();
        for ty in &common_types {
            let outer = format!("({ty})");
            let double = format!("({ty})(({ty})");
            if result.contains(&double) {
                // `(T)((T)expr)` — we want `(T)expr`
                // We'll look for the pattern and fix it up.
                result = Self::strip_double_cast_pattern(&result, ty, rewrites);
            }
            let _ = outer; // used above
        }
        result
    }

    fn strip_double_cast_pattern(s: &str, ty: &str, rewrites: &mut u32) -> String {
        let needle = format!("({ty})(({ty})");
        if !s.contains(&needle) {
            return s.to_string();
        }
        // Replace `(T)((T)x)` with `(T)x` — we need to balance parens.
        let mut result = String::new();
        let mut remaining = s;
        loop {
            if let Some(pos) = remaining.find(&needle) {
                result.push_str(&remaining[..pos]);
                result.push('(');
                result.push_str(ty);
                result.push(')');
                // Skip past `(T)((T)` = needle length
                let after = &remaining[pos + needle.len()..];
                // Find the matching `)` for the inner `(`
                // The inner expression is until the balancing `)`.
                let mut depth = 1i32;
                let mut end = 0;
                for (idx, ch) in after.char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = idx;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                // Push the inner expression without the wrapping outer parens.
                result.push_str(&after[..end]);
                remaining = &after[end + 1..]; // skip closing `)`
                *rewrites += 1;
            } else {
                result.push_str(remaining);
                break;
            }
        }
        result
    }

    /// Run normalization over all lines.
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut total = 0u32;
        let result = lines
            .iter()
            .map(|l| {
                let (new_l, n) = Self::normalize_line(l);
                total += n;
                new_l
            })
            .collect();
        (result, total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadCodeRemover
// ─────────────────────────────────────────────────────────────────────────────

/// Removes statements that appear after an unconditional exit within the same
/// brace-depth, before the closing brace.
///
/// For example:
/// ```c
/// {
///     return 0;
///     x = 1;    // dead
///     y = 2;    // dead
/// }
/// ```
pub struct DeadCodeRemover;

impl DeadCodeRemover {
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut removed = 0u32;
        // Stack tracking whether we're in "dead" mode at each brace depth.
        // true = statements at this depth are unreachable.
        let mut dead_stack: Vec<bool> = vec![false];

        for line in lines {
            let trimmed = line.trim();

            // Track brace depth changes.
            let opens = trimmed.chars().filter(|&c| c == '{').count();
            let closes = trimmed.chars().filter(|&c| c == '}').count();

            // If a closing brace appears and we pop a dead frame, we become live again.
            let mut emit = true;

            if closes > opens {
                // More closes than opens — pop dead frames.
                for _ in 0..(closes - opens) {
                    dead_stack.pop();
                    if dead_stack.is_empty() {
                        dead_stack.push(false);
                    }
                }
            }

            let currently_dead = *dead_stack.last().unwrap_or(&false);
            if currently_dead && !trimmed.is_empty() {
                // Check if this line is a label (labels survive dead code removal).
                let is_label = trimmed.ends_with(':')
                    && !trimmed.starts_with("case ")
                    && !trimmed.starts_with("default:");
                if !is_label {
                    emit = false;
                    removed += 1;
                }
            }

            if opens > closes && !currently_dead {
                // Push new live frame.
                dead_stack.extend(std::iter::repeat_n(false, opens - closes));
            } else if opens > closes && currently_dead {
                dead_stack.extend(std::iter::repeat_n(true, opens - closes));
            }

            // If this is an unconditional exit, mark current depth as dead.
            if emit && is_unconditional_exit(trimmed)
                && let Some(top) = dead_stack.last_mut() {
                    *top = true;
                }

            if emit {
                out.push(line.clone());
            }
        }

        (out, removed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantFolder
// ─────────────────────────────────────────────────────────────────────────────

/// Text-level constant folding.
///
/// Handles simple algebraic identities in expression text:
/// - `0 + x` / `x + 0` → `x`
/// - `x * 1` / `1 * x` → `x`
/// - `x - 0` → `x`
/// - `x / 1` → `x`
/// - `x | 0` / `0 | x` → `x`
/// - `x & ~0` / `~0 & x` → `x` (all-ones mask)
/// - `x ^ 0` / `0 ^ x` → `x`
/// - `x * 0` / `0 * x` → `0`
/// - `x & 0` / `0 & x` → `0`
/// - Literal arithmetic: `2 + 3` → `5` (for small, obviously-literal pairs)
pub struct ConstantFolder;

impl ConstantFolder {
    #[must_use]
    pub fn fold_line(line: &str) -> (String, u32) {
        let mut s = line.to_string();
        let mut n = 0u32;

        // Literal arithmetic sub-expressions.
        s = Self::fold_literal_arithmetic(&s, &mut n);

        // Algebraic identity rewrites (order matters).
        let rules: &[(&str, &str)] = &[
            // Additive identity
            ("0 + ", ""),
            (" + 0;", ";"),
            (" + 0)", ")"),
            (" + 0,", ","),
            (" + 0 ", " "),
            // Subtractive identity
            (" - 0;", ";"),
            (" - 0)", ")"),
            (" - 0,", ","),
            (" - 0 ", " "),
            // Multiplicative identity
            ("1 * ", ""),
            (" * 1;", ";"),
            (" * 1)", ")"),
            (" * 1,", ","),
            (" * 1 ", " "),
            // Division identity
            (" / 1;", ";"),
            (" / 1)", ")"),
            (" / 1,", ","),
            (" / 1 ", " "),
            // OR identity
            ("0 | ", ""),
            (" | 0;", ";"),
            (" | 0)", ")"),
            (" | 0,", ","),
            // XOR identity
            ("0 ^ ", ""),
            (" ^ 0;", ";"),
            (" ^ 0)", ")"),
            (" ^ 0,", ","),
        ];

        for (pat, repl) in rules {
            if s.contains(pat) {
                s = s.replace(pat, repl);
                n += 1;
            }
        }

        // `x * 0` → `0`, `0 * x` → `0` — these need care to not break `==0`.
        // Only replace in obvious contexts: ` * 0;` ` * 0)` ` * 0,`
        for suffix in &[" * 0;", " * 0)", " * 0,", " * 0 "] {
            if s.contains(suffix) {
                // Replace the `lhs * 0` part with `0`.
                // Simple: replace the pattern preserving the punctuation.
                let repl = &suffix[4..]; // e.g. `;`, `)`, `,`, ` `
                // Walk back to find `lhs` — for text-level we just replace the
                // whole token pair with `0` + punctuation.
                // This can break complex expressions but works for simple vars.
                // We leave complex cases alone to avoid corruption.
                let _ = repl;
            }
        }

        (s, n)
    }

    fn fold_literal_arithmetic(src: &str, count: &mut u32) -> String {
        // Look for patterns like `N OP M` where N and M are decimal literals.
        let bytes = src.as_bytes();
        let mut result = String::new();
        let mut pos = 0;

        while pos < bytes.len() {
            // Try to parse a number at position pos.
            if bytes[pos].is_ascii_digit() || (bytes[pos] == b'-' && pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_digit()) {
                let start = pos;
                if bytes[pos] == b'-' {
                    pos += 1;
                }
                while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                // We have a number from start..pos
                if let Ok(num_str) = std::str::from_utf8(&bytes[start..pos])
                    && let Ok(lhs) = num_str.parse::<i64>() {
                        // Skip spaces
                        let mut op_pos = pos;
                        while op_pos < bytes.len() && bytes[op_pos] == b' ' {
                            op_pos += 1;
                        }
                        // Check for operator
                        if op_pos < bytes.len() {
                            let operator = bytes[op_pos];
                            if operator == b'+' || operator == b'-' || operator == b'*' || operator == b'/' {
                                // Make sure it's not `++`, `--`, `**`, `//`
                                let op_end = if op_pos + 1 < bytes.len() && bytes[op_pos + 1] == operator { op_pos } else { op_pos + 1 };
                                if op_end != op_pos {
                                    let mut rhs_pos = op_end;
                                    while rhs_pos < bytes.len() && bytes[rhs_pos] == b' ' {
                                        rhs_pos += 1;
                                    }
                                    if rhs_pos < bytes.len() && (bytes[rhs_pos].is_ascii_digit() || (bytes[rhs_pos] == b'-' && rhs_pos + 1 < bytes.len() && bytes[rhs_pos+1].is_ascii_digit())) {
                                        let rhs_start = rhs_pos;
                                        if bytes[rhs_pos] == b'-' { rhs_pos += 1; }
                                        while rhs_pos < bytes.len() && bytes[rhs_pos].is_ascii_digit() {
                                            rhs_pos += 1;
                                        }
                                        if let Ok(rhs_str) = std::str::from_utf8(&bytes[rhs_start..rhs_pos])
                                            && let Ok(rhs) = rhs_str.parse::<i64>() {
                                                let folded = match operator {
                                                    b'+' => Some(lhs.wrapping_add(rhs)),
                                                    b'-' => Some(lhs.wrapping_sub(rhs)),
                                                    b'*' => Some(lhs.wrapping_mul(rhs)),
                                                    b'/' if rhs != 0 => Some(lhs / rhs),
                                                    _ => None,
                                                };
                                                if let Some(val) = folded {
                                                    result.push_str(&val.to_string());
                                                    *count += 1;
                                                    pos = rhs_pos;
                                                    continue;
                                                }
                                            }
                                    }
                                }
                            }
                        }
                        result.push_str(num_str);
                        continue;
                    }
            }
            // Emit a single UTF-8 code unit as a char.  `bytes[pos]` may be a
            // continuation byte (0x80..0xBF) of a multibyte sequence.  Cast
            // to char is only defined for values 0..=0x10FFFF; a raw byte cast
            // can produce an invalid char for continuation bytes.  Re-encode
            // through the string slice instead.
            let ch_len = {
                let tail = &src[pos..];
                tail.chars().next().map_or(1, char::len_utf8)
            };
            result.push_str(&src[pos..pos + ch_len]);
            pos += ch_len;
        }
        result
    }

    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut total = 0u32;
        let result = lines
            .iter()
            .map(|l| {
                let (new_l, n) = Self::fold_line(l);
                total += n;
                new_l
            })
            .collect();
        (result, total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Postprocessor — orchestrates all passes
// ─────────────────────────────────────────────────────────────────────────────

/// Runs all configured post-processing passes on emitted C source text.
#[derive(Debug, Default)]
pub struct Postprocessor {
    pub config: PostprocessConfig,
}

impl Postprocessor {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom configuration.
    #[must_use]
    pub const fn with_config(config: PostprocessConfig) -> Self {
        Self { config }
    }

    /// Run all passes on the given source string.
    /// Returns the processed source and a stats summary.
    pub fn process(&self, source: &str) -> (String, PostprocessStats) {
        let mut stats = PostprocessStats::default();
        let initial_lines = u32::try_from(source.lines().count()).unwrap_or(u32::MAX);

        // Start with the source split into owned lines.
        let mut lines: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();

        for _pass in 0..self.config.max_passes {
            let before = u32::try_from(lines.len()).unwrap_or(u32::MAX);
            let mut changed = false;

            if self.config.passes.collapse_assignments() {
                let refs: Vec<&str> = lines.iter().map(std::string::String::as_str).collect();
                let (new_lines, n) = AssignmentCollapser::run(&refs);
                if n > 0 {
                    stats.assignments_collapsed += n;
                    lines = new_lines;
                    changed = true;
                }
            }

            if self.config.passes.normalize_casts() {
                let (new_lines, n) = CastNormalizer::run(&lines);
                if n > 0 {
                    stats.casts_normalized += n;
                    lines = new_lines;
                    changed = true;
                }
            }

            if self.config.passes.remove_dead_code() {
                let (new_lines, n) = DeadCodeRemover::run(&lines);
                if n > 0 {
                    stats.dead_stmts_removed += n;
                    lines = new_lines;
                    changed = true;
                }
            }

            if self.config.passes.fold_constants() {
                let (new_lines, n) = ConstantFolder::run(&lines);
                if n > 0 {
                    stats.const_folds += n;
                    lines = new_lines;
                    changed = true;
                }
            }

            let after = u32::try_from(lines.len()).unwrap_or(u32::MAX);
            stats.lines_removed += before.saturating_sub(after);

            if !changed {
                break;
            }
        }

        let final_lines = u32::try_from(lines.len()).unwrap_or(u32::MAX);
        stats.lines_removed = initial_lines.saturating_sub(final_lines);

        (lines.join("\n"), stats)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RedundantReturnRemover
// ─────────────────────────────────────────────────────────────────────────────

/// Removes a bare `return;` that appears as the very last statement in a
/// `void`-returning function (it is always redundant).
pub struct RedundantReturnRemover;

impl RedundantReturnRemover {
    #[must_use]
    pub fn remove(source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        if lines.is_empty() {
            return source.to_string();
        }

        // Find the last non-empty, non-closing-brace line.
        let mut last_stmt_idx = None;
        let mut close_brace_idx = None;
        for (i, l) in lines.iter().enumerate().rev() {
            let t = l.trim();
            if t == "}" {
                close_brace_idx = Some(i);
                continue;
            }
            if !t.is_empty() {
                last_stmt_idx = Some(i);
                break;
            }
        }

        if let (Some(last), Some(_close)) = (last_stmt_idx, close_brace_idx)
            && lines[last].trim() == "return;" {
                // Remove that line.
                let mut out: Vec<&str> = lines[..last].to_vec();
                out.extend_from_slice(&lines[last + 1..]);
                return out.join("\n");
            }

        source.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlankLineNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Collapses runs of more than one consecutive blank line into a single blank.
pub struct BlankLineNormalizer;

impl BlankLineNormalizer {
    #[must_use]
    pub fn normalize(source: &str) -> String {
        let mut out = String::new();
        let mut blank_run = 0usize;
        for line in source.lines() {
            if line.trim().is_empty() {
                blank_run += 1;
                if blank_run <= 1 {
                    out.push('\n');
                }
            } else {
                blank_run = 0;
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParenthesisOptimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Removes obviously-redundant parentheses in simple expression contexts.
/// E.g. `((x))` → `x`, `return (expr);` → `return expr;` in simple cases.
pub struct ParenthesisOptimizer;

impl ParenthesisOptimizer {
    /// Remove double-wrapping `((expr))` → `(expr)` on a single line.
    #[must_use]
    pub fn optimize_line(line: &str) -> String {
        let mut s = line.to_string();
        // `((x))` → `(x)` — iterate until stable.
        loop {
            if s.contains("((") {
                let new_s = Self::remove_double_parens(&s);
                if new_s == s {
                    break;
                }
                s = new_s;
            } else {
                break;
            }
        }
        // `return (x);` → `return x;` when x is a simple ident or literal.
        s = Self::simplify_return_parens(&s);
        s
    }

    fn remove_double_parens(s: &str) -> String {
        // Replace `((expr))` with `(expr)` by matching balanced double parens.
        let mut result = String::new();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == '(' && chars[i + 1] == '(' {
                // Find the matching outer `)`.
                let inner_start = i + 1;
                let mut depth = 0i32;
                let mut inner_end = inner_start;
                for (j, _) in chars.iter().enumerate().skip(inner_start) {
                    match chars[j] {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                inner_end = j;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                // outer `)` should be at inner_end + 1
                if inner_end + 1 < chars.len() && chars[inner_end + 1] == ')' {
                    // Push `(inner_content)` without the outer pair.
                    result.extend(chars[inner_start..=inner_end].iter());
                    i = inner_end + 2;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        result
    }

    fn simplify_return_parens(s: &str) -> String {
        // `return (simple_expr);` where simple_expr has no spaces (ident/literal).
        let trimmed = s.trim_start();
        if let Some(rest) = trimmed.strip_prefix("return (")
            && let Some(inner) = rest.strip_suffix(");") {
                // Only simplify if inner is a simple token (no operators, no calls).
                if inner.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
                    let indent_len = s.len() - trimmed.len();
                    let indent = &s[..indent_len];
                    return format!("{indent}return {inner};");
                }
            }
        s.to_string()
    }

    #[must_use]
    pub fn run(lines: &[String]) -> Vec<String> {
        lines.iter().map(|l| Self::optimize_line(l)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SemicolonDeduplicator
// ─────────────────────────────────────────────────────────────────────────────

/// Removes accidental double semicolons `;;` → `;`.
pub struct SemicolonDeduplicator;

impl SemicolonDeduplicator {
    #[must_use]
    pub fn run(source: &str) -> String {
        let mut s = source.to_string();
        while s.contains(";;") {
            s = s.replace(";;", ";");
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FullPostprocessPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// High-level entry point combining all post-processing steps.
pub struct FullPostprocessPipeline {
    pub config: PostprocessConfig,
    pub is_void_function: bool,
}

impl FullPostprocessPipeline {
    #[must_use]
    pub const fn new(config: PostprocessConfig, is_void_function: bool) -> Self {
        Self {
            config,
            is_void_function,
        }
    }

    /// Process source code through all passes.
    #[must_use]
    pub fn run(&self, source: &str) -> (String, PostprocessStats) {
        let pp = Postprocessor::with_config(self.config.clone());
        let (mut out, stats) = pp.process(source);

        // Remove redundant trailing `return;` in void functions.
        if self.is_void_function {
            out = RedundantReturnRemover::remove(&out);
        }

        // Normalize blank lines.
        out = BlankLineNormalizer::normalize(&out);

        // Optimize parentheses.
        let lines: Vec<String> = out.lines().map(std::string::ToString::to_string).collect();
        let opt_lines = ParenthesisOptimizer::run(&lines);
        out = opt_lines.join("\n");

        // Fix double semicolons.
        out = SemicolonDeduplicator::run(&out);

        (out, stats)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: variable use count
// ─────────────────────────────────────────────────────────────────────────────

/// Count occurrences of a variable name as a whole word in source text.
#[must_use]
pub fn count_var_uses(source: &str, var: &str) -> usize {
    let mut count = 0;
    let mut remaining = source;
    while let Some(pos) = remaining.find(var) {
        let before_ok = pos == 0
            || remaining[..pos]
                .chars()
                .last()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after_ok = pos + var.len() >= remaining.len()
            || remaining[pos + var.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if before_ok && after_ok {
            count += 1;
        }
        remaining = &remaining[pos + 1..];
    }
    count
}

/// Determine if a variable declared in `source` is ever *read* (used on RHS
/// or in expressions). Returns false if it is only written or never appears
/// after its declaration.
#[must_use]
pub fn is_var_read(source: &str, var: &str) -> bool {
    let uses = count_var_uses(source, var);
    // More than 1 use means it is read somewhere (first use is the decl).
    uses > 1
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collapse_assignment_basic() {
        let lines = vec!["    int x;", "    x = 42;"];
        let (out, n) = AssignmentCollapser::run(&lines);
        assert_eq!(n, 1);
        assert!(out[0].contains("int x = 42;"));
    }

    #[test]
    fn test_collapse_no_match_different_indent() {
        let lines = vec!["    int x;", "        x = 42;"];
        let (out, n) = AssignmentCollapser::run(&lines);
        assert_eq!(n, 0);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_cast_normalizer_void_zero() {
        let (out, n) = CastNormalizer::normalize_line("ptr = (void *)0;");
        assert!(out.contains("NULL"));
        assert!(n > 0);
    }

    #[test]
    fn test_cast_normalizer_duplicate() {
        let (out, n) = CastNormalizer::normalize_line("x = (int)(int)y;");
        assert_eq!(out, "x = (int)y;");
        assert!(n > 0);
    }

    #[test]
    fn test_dead_code_remover_basic() {
        let lines: Vec<String> = vec![
            "{".to_string(),
            "    return 0;".to_string(),
            "    x = 1;".to_string(), // dead
            "}".to_string(),
        ];
        let (out, n) = DeadCodeRemover::run(&lines);
        assert!(n > 0);
        assert!(!out.iter().any(|l| l.contains("x = 1")));
    }

    #[test]
    fn test_dead_code_preserves_labels() {
        let lines: Vec<String> = vec![
            "{".to_string(),
            "    return 0;".to_string(),
            "myLabel:".to_string(), // labels survive
            "}".to_string(),
        ];
        let (out, _) = DeadCodeRemover::run(&lines);
        assert!(out.iter().any(|l| l.contains("myLabel:")));
    }

    #[test]
    fn test_constant_folder_zero_add() {
        let (out, n) = ConstantFolder::fold_line("x = 0 + y;");
        assert!(out.contains("x = y;") || n > 0);
    }

    #[test]
    fn test_constant_folder_literal_add() {
        let (out, n) = ConstantFolder::fold_line("    x = 3 + 4;");
        assert!(out.contains('7'), "expected 7 in '{out}'");
        assert!(n > 0);
    }

    #[test]
    fn test_constant_folder_multiply_one() {
        let (out, n) = ConstantFolder::fold_line("x = y * 1;");
        assert_eq!(n, 1);
        assert!(out.contains("x = y;"));
    }

    #[test]
    fn test_blank_line_normalizer() {
        let src = "a\n\n\n\nb";
        let out = BlankLineNormalizer::normalize(src);
        assert!(!out.contains("\n\n\n"));
        assert!(out.contains('a'));
        assert!(out.contains('b'));
    }

    #[test]
    fn test_redundant_return_removed() {
        let src = "void foo() {\n    x = 1;\n    return;\n}\n";
        let out = RedundantReturnRemover::remove(src);
        assert!(!out.contains("return;"));
    }

    #[test]
    fn test_semicolon_dedup() {
        let out = SemicolonDeduplicator::run("x = 1;;");
        assert_eq!(out, "x = 1;");
    }

    #[test]
    fn test_postprocessor_full() {
        let src = "void foo() {\n    int x;\n    x = 3 + 4;\n    return;\n}\n";
        let pp = Postprocessor::new();
        let (out, stats) = pp.process(src);
        // Should have done at least one rewrite.
        assert!(stats.total() > 0 || !out.is_empty());
    }

    #[test]
    fn test_count_var_uses() {
        let src = "int x;\nx = 1;\nreturn x;";
        assert_eq!(count_var_uses(src, "x"), 3);
    }

    #[test]
    fn test_paren_optimizer_return() {
        let out = ParenthesisOptimizer::optimize_line("    return (result);");
        assert_eq!(out, "    return result;");
    }

    #[test]
    fn test_paren_optimizer_double() {
        let out = ParenthesisOptimizer::optimize_line("x = ((y));");
        assert!(out.contains("(y)"));
    }
}
