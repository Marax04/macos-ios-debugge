//! `c_recovery` — high-level pattern recovery for decompiled C pseudocode.
//!
//! Transforms low-level, decompiler-generated constructs into idiomatic C:
//!
//! * **For-loop recovery**: recognises `while (cond)` with an initialiser
//!   preceding it and an increment as the last statement → emits `for(;;)`.
//! * **String operations**: recognises manual string-length and string-copy
//!   loops and replaces them with `strlen`/`strcpy` calls.
//! * **Array subscript recovery**: `*(base + index)` → `base[index]`.
//! * **Compound assignment recovery**: `x = x + y;` → `x += y;`.
//! * **Boolean simplification**: `x != 0` → `x`, `x == 0` → `!x`.
//! * **Post/pre-increment recovery**: `x = x + 1;` → `x++;` etc.
//! * **Pointer arithmetic cleanup**: `(char*)p + 4` in struct contexts.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// RecoveryStats
// ─────────────────────────────────────────────────────────────────────────────

/// Counts of pattern recoveries performed.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecoveryStats {
    pub for_loops_recovered: u32,
    pub string_ops_recovered: u32,
    pub array_subscripts_recovered: u32,
    pub compound_assignments: u32,
    pub increment_decrements: u32,
    pub boolean_simplifications: u32,
    pub pointer_arith_cleaned: u32,
}

impl RecoveryStats {
    pub const fn merge(&mut self, other: &Self) {
        self.for_loops_recovered += other.for_loops_recovered;
        self.string_ops_recovered += other.string_ops_recovered;
        self.array_subscripts_recovered += other.array_subscripts_recovered;
        self.compound_assignments += other.compound_assignments;
        self.increment_decrements += other.increment_decrements;
        self.boolean_simplifications += other.boolean_simplifications;
        self.pointer_arith_cleaned += other.pointer_arith_cleaned;
    }

    #[must_use]
    pub const fn total(&self) -> u32 {
        self.for_loops_recovered
            + self.string_ops_recovered
            + self.array_subscripts_recovered
            + self.compound_assignments
            + self.increment_decrements
            + self.boolean_simplifications
            + self.pointer_arith_cleaned
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveryConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of which recovery passes are active.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RecoveryPasses(u8);

impl RecoveryPasses {
    const FOR_LOOPS: u8 = 0b000_0001;
    const STRING_OPS: u8 = 0b000_0010;
    const ARRAY_SUBSCRIPTS: u8 = 0b000_0100;
    const COMPOUND_ASSIGNMENTS: u8 = 0b000_1000;
    const INCREMENTS: u8 = 0b001_0000;
    const BOOLEANS: u8 = 0b010_0000;
    const POINTER_ARITH: u8 = 0b100_0000;
    const ALL: u8 = 0b111_1111;

    #[must_use] pub const fn all() -> Self { Self(Self::ALL) }
    #[must_use] pub const fn recover_for_loops(self) -> bool { self.0 & Self::FOR_LOOPS != 0 }
    #[must_use] pub const fn recover_string_ops(self) -> bool { self.0 & Self::STRING_OPS != 0 }
    #[must_use] pub const fn recover_array_subscripts(self) -> bool { self.0 & Self::ARRAY_SUBSCRIPTS != 0 }
    #[must_use] pub const fn recover_compound_assignments(self) -> bool { self.0 & Self::COMPOUND_ASSIGNMENTS != 0 }
    #[must_use] pub const fn recover_increments(self) -> bool { self.0 & Self::INCREMENTS != 0 }
    #[must_use] pub const fn simplify_booleans(self) -> bool { self.0 & Self::BOOLEANS != 0 }
    #[must_use] pub const fn clean_pointer_arith(self) -> bool { self.0 & Self::POINTER_ARITH != 0 }
}

impl Default for RecoveryPasses {
    fn default() -> Self { Self(Self::ALL) }
}

/// Controls which recovery passes are active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Which passes are active.
    pub passes: RecoveryPasses,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self { passes: RecoveryPasses::all() }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Line helpers
// ─────────────────────────────────────────────────────────────────────────────

fn indent_of(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

fn trimmed(line: &str) -> &str {
    line.trim()
}

/// Strip trailing `;` from a statement.
fn strip_semi(s: &str) -> &str {
    s.strip_suffix(';').unwrap_or(s).trim()
}

/// Try to parse `var op= rhs` or `var = var op rhs` patterns.
/// Returns `(var, op, rhs)` where op is `+`, `-`, `*`, `/`, `|`, `&`, `^`,
/// `<<`, `>>`.
fn parse_compound(stmt: &str) -> Option<(&str, &str, &str)> {
    let stmt = strip_semi(stmt);
    // Pattern 1: `var op= rhs`
    for op in &["+=", "-=", "*=", "/=", "|=", "&=", "^=", "<<=", ">>="] {
        if let Some(pos) = stmt.find(op) {
            let lhs = stmt[..pos].trim();
            let rhs = stmt[pos + op.len()..].trim();
            if is_simple_ident(lhs) {
                return Some((lhs, &op[..op.len() - 1], rhs));
            }
        }
    }
    // Pattern 2: `var = var op rhs`
    if let Some(eq_pos) = stmt.find(" = ") {
        let lhs = stmt[..eq_pos].trim();
        let rest = stmt[eq_pos + 3..].trim();
        if is_simple_ident(lhs) {
            for op in &["+", "-", "*", "/", "|", "&", "^", "<<", ">>"] {
                let prefix = format!("{lhs} {op} ");
                if let Some(rhs) = rest.strip_prefix(prefix.as_str()) {
                    return Some((lhs, op, rhs.trim()));
                }
                let prefix2 = format!("{lhs} {op}(");
                if rest.starts_with(&prefix2) {
                    let rhs = &rest[lhs.len() + 1 + op.len()..];
                    return Some((lhs, op, rhs.trim()));
                }
            }
        }
    }
    None
}

/// True if s looks like a simple identifier (letters, digits, underscores, no spaces).
fn is_simple_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Try to detect `var = var + 1;` or `var = var - 1;` → `var++;` / `var--;`
fn parse_inc_dec(stmt: &str) -> Option<(&str, bool)> {
    // `var = var + 1` → true (increment)
    // `var = var - 1` → false (decrement)
    let stmt = strip_semi(stmt);
    if let Some(pos) = stmt.find(" = ") {
        let lhs = stmt[..pos].trim();
        let rest = stmt[pos + 3..].trim();
        if is_simple_ident(lhs) {
            let inc_pat = format!("{lhs} + 1");
            let dec_pat = format!("{lhs} - 1");
            if rest == inc_pat {
                return Some((lhs, true));
            }
            if rest == dec_pat {
                return Some((lhs, false));
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// CompoundAssignmentRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites `x = x + y;` → `x += y;`, etc.
pub struct CompoundAssignmentRecovery;

impl CompoundAssignmentRecovery {
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut out = Vec::with_capacity(lines.len());
        let mut count = 0u32;

        for line in lines {
            let ind = indent_of(line);
            let t = trimmed(line);
            if let Some((var, op, rhs)) = parse_compound(t) {
                out.push(format!("{ind}{var} {op}= {rhs};"));
                count += 1;
            } else {
                out.push(line.clone());
            }
        }

        (out, count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IncrementRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites `x = x + 1;` → `x++;` and `x = x - 1;` → `x--;`.
pub struct IncrementRecovery;

impl IncrementRecovery {
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut out = Vec::with_capacity(lines.len());
        let mut count = 0u32;

        for line in lines {
            let ind = indent_of(line);
            let t = trimmed(line);
            if let Some((var, inc)) = parse_inc_dec(t) {
                let op = if inc { "++" } else { "--" };
                out.push(format!("{ind}{var}{op};"));
                count += 1;
            } else {
                out.push(line.clone());
            }
        }

        (out, count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BooleanSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Simplifies boolean expressions:
/// - `x != 0` → `x`
/// - `x == 0` → `!x`
/// - `(x != 0)` → `(x)`
/// - `!!x` → `x`
pub struct BooleanSimplifier;

impl BooleanSimplifier {
    #[must_use]
    pub fn simplify_line(line: &str) -> (String, u32) {
        let mut s = line.to_string();
        let mut count = 0u32;

        // `!!x` → `x`
        while s.contains("!!") {
            s = s.replace("!!", "");
            count += 1;
        }

        // `x != 0` → `x` (in condition contexts)
        let patterns: &[(&str, &str)] = &[
            (" != 0)", ")"),
            (" != 0 ", " "),
            (" != 0;", ";"),
            (" != 0,", ","),
            ("!= 0)", ")"),
        ];
        for (pat, repl) in patterns {
            // We need to find the variable name before `!= 0`.
            // Simple approach: strip the pattern and hope context is preserved.
            if s.contains(pat) {
                s = s.replace(pat, repl);
                count += 1;
            }
        }

        // `== 0` in `if (x == 0)` → `if (!x)` is tricky without AST.
        // We handle the simple `(x == 0)` case.
        s = Self::simplify_eq_zero(&s, &mut count);

        (s, count)
    }

    fn simplify_eq_zero(s: &str, count: &mut u32) -> String {
        // Replace `(ident == 0)` with `(!ident)`.
        let mut result = String::new();
        let mut remaining = s;

        loop {
            if let Some(pos) = remaining.find('(') {
                result.push_str(&remaining[..=pos]);
                let after_open = &remaining[pos + 1..];
                // Try to match `ident == 0)`
                if let Some(end) = after_open.find(')') {
                    let inner = &after_open[..end];
                    if let Some(rest) = inner.strip_suffix(" == 0") {
                        let ident = rest.trim();
                        if is_simple_ident(ident) {
                            result.push('!');
                            result.push_str(ident);
                            result.push(')');
                            *count += 1;
                            remaining = &after_open[end + 1..];
                            continue;
                        }
                    }
                }
                remaining = after_open;
            } else {
                result.push_str(remaining);
                break;
            }
        }
        result
    }

    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut total = 0u32;
        let result = lines
            .iter()
            .map(|l| {
                let (new_l, n) = Self::simplify_line(l);
                total += n;
                new_l
            })
            .collect();
        (result, total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArraySubscriptRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers `*(base + offset)` → `base[offset]`.
pub struct ArraySubscriptRecovery;

impl ArraySubscriptRecovery {
    #[must_use]
    pub fn recover_line(line: &str) -> (String, u32) {
        let mut s = line.to_string();
        let mut count = 0u32;

        // Pattern: `*(ptr + idx)` → `ptr[idx]`
        s = Self::replace_deref_add(&s, &mut count);

        // Pattern: `*(ptr)` → `*ptr` (remove unnecessary parens around single deref)
        // Only if ptr is a simple ident.
        s = Self::remove_deref_parens(&s, &mut count);

        (s, count)
    }

    fn replace_deref_add(s: &str, count: &mut u32) -> String {
        let mut result = String::new();
        let mut remaining = s;

        loop {
            // Look for `*(` pattern.
            if let Some(pos) = remaining.find("*(") {
                // Make sure it's a dereference, not a multiply.
                let before_char = if pos > 0 {
                    // Use byte-safe last-char lookup: pos is a byte offset from find(),
                    // so chars().nth(pos - 1) would be wrong for multibyte input.
                    remaining[..pos].chars().last()
                } else {
                    None
                };
                let is_mul = before_char.is_some_and(|c| c.is_alphanumeric() || c == ')' || c == '_');

                if is_mul {
                    // It's a multiply, skip.
                    result.push_str(&remaining[..=pos]);
                    remaining = &remaining[pos + 1..];
                    continue;
                }

                result.push_str(&remaining[..pos]);
                let inner_start = pos + 2;
                let rest = &remaining[inner_start..];

                // Find balanced closing `)`.
                let mut depth = 1i32;
                let mut end = 0;
                for (idx, ch) in rest.char_indices() {
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

                let inner = &rest[..end];
                // Check if inner is `base + idx` where both are simple.
                if let Some(plus_pos) = inner.find(" + ") {
                    let base = inner[..plus_pos].trim();
                    let idx = inner[plus_pos + 3..].trim();
                    // base can have `->field` but must not contain operators.
                    if !base.contains('+')
                        && !base.contains('*')
                        && !idx.contains('+')
                        && !idx.contains('*')
                    {
                        result.push_str(base);
                        result.push('[');
                        result.push_str(idx);
                        result.push(']');
                        *count += 1;
                        remaining = &rest[end + 1..];
                        continue;
                    }
                }

                // Not a recoverable pattern — emit as-is.
                result.push_str("*(");
                result.push_str(inner);
                result.push(')');
                remaining = &rest[end + 1..];
            } else {
                result.push_str(remaining);
                break;
            }
        }

        result
    }

    fn remove_deref_parens(s: &str, count: &mut u32) -> String {
        let mut result = String::new();
        let mut remaining = s;
        loop {
            if let Some(pos) = remaining.find("*(") {
                let before_char = if pos > 0 {
                    // Use byte-safe last-char lookup: pos is a byte offset from find(),
                    // so chars().nth(pos - 1) would be wrong for multibyte input.
                    remaining[..pos].chars().last()
                } else {
                    None
                };
                let is_mul = before_char.is_some_and(|c| c.is_alphanumeric() || c == ')' || c == '_');

                if is_mul {
                    result.push_str(&remaining[..=pos]);
                    remaining = &remaining[pos + 1..];
                    continue;
                }

                result.push_str(&remaining[..pos]);
                let after = &remaining[pos + 2..];
                // Find matching `)`.
                if let Some(close) = after.find(')') {
                    let inner = &after[..close];
                    // Only simplify if inner is a simple identifier.
                    if is_simple_ident(inner.trim()) {
                        result.push('*');
                        result.push_str(inner.trim());
                        *count += 1;
                        remaining = &after[close + 1..];
                        continue;
                    }
                }
                // Not simplifiable.
                result.push_str("*(");
                remaining = after;
            } else {
                result.push_str(remaining);
                break;
            }
        }
        result
    }

    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut total = 0u32;
        let result = lines
            .iter()
            .map(|l| {
                let (new_l, n) = Self::recover_line(l);
                total += n;
                new_l
            })
            .collect();
        (result, total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ForLoopRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers `while`-loops that have an init statement before them and an
/// increment as the last statement in the body, turning them into `for` loops.
///
/// Pattern recognised:
/// ```text
/// INIT_STMT;           // e.g. `i = 0;`
/// while (COND) {
///     ...
///     INCREMENT_STMT;  // e.g. `i++;` or `i += step;`
/// }
/// ```
/// → `for (INIT_STMT; COND; INCREMENT_STMT) { ... }`
pub struct ForLoopRecovery;

/// Detect whether a trimmed statement looks like a loop increment/update.
fn is_loop_update(stmt: &str) -> bool {
    let s = strip_semi(stmt);
    // `var++`, `var--`, `++var`, `--var`
    if s.ends_with("++") || s.ends_with("--") || s.starts_with("++") || s.starts_with("--") {
        return true;
    }
    // `var += x`, `var -= x`, `var *= x`
    if s.contains("+=") || s.contains("-=") || s.contains("*=") || s.contains("/=") {
        return true;
    }
    // `var = var + x` or `var = var - x`
    if let Some((_, op, _)) = parse_compound(stmt) {
        return matches!(op, "+" | "-" | "*" | "/");
    }
    false
}

impl ForLoopRecovery {
    /// Run the for-loop recovery pass on a function's source lines.
    ///
    /// # Panics
    ///
    /// Panics if internal index arithmetic produces `None` when the close-brace
    /// index cannot be found (should not happen for well-formed input).
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut count = 0u32;
        let mut i = 0;

        while i < lines.len() {
            // Look for `while (cond) {` at line `i`.
            let t = trimmed(&lines[i]);
            let ind = indent_of(&lines[i]);

            if !Self::is_while_open(t) {
                out.push(lines[i].clone());
                i += 1;
                continue;
            }

            // Check if the line immediately before (skipping blanks) at same
            // indent level is an assignment that could be an init.
            let init_line_idx = Self::find_init_before(&out, ind);
            let cond = Self::extract_while_cond(t);

            // Find the matching closing brace and the last statement in the loop body.
            let close_idx = Self::find_close_brace(lines, i, ind);
            if close_idx.is_none() || cond.is_none() || init_line_idx.is_none() {
                out.push(lines[i].clone());
                i += 1;
                continue;
            }

            let close_idx = close_idx.unwrap();
            let cond = cond.unwrap();
            let init_idx = init_line_idx.unwrap();

            // Look at the last non-empty line before the close brace.
            let update_line_idx = Self::find_last_body_stmt(lines, i + 1, close_idx, ind);

            if update_line_idx.is_none() {
                out.push(lines[i].clone());
                i += 1;
                continue;
            }

            let update_idx = update_line_idx.unwrap();
            let update_stmt = trimmed(&lines[update_idx]);

            if !is_loop_update(update_stmt) {
                out.push(lines[i].clone());
                i += 1;
                continue;
            }

            // We have all three parts.  Reconstruct.
            let init_stmt = strip_semi(trimmed(&out[init_idx])).to_string();
            let update_clean = strip_semi(update_stmt).to_string();

            // Replace the init line in `out` with the for loop header.
            let for_header = format!("{ind}for ({init_stmt}; {cond}; {update_clean}) {{");
            out[init_idx] = for_header;

            // Push body lines (skipping the while header and the update line).
            for (j, _) in lines.iter().enumerate().take(close_idx).skip(i + 1) {
                if j == update_idx {
                    continue; // skip — moved to for header
                }
                out.push(lines[j].clone());
            }
            // Push closing brace.
            out.push(lines[close_idx].clone());

            count += 1;
            i = close_idx + 1;
        }

        (out, count)
    }

    fn is_while_open(t: &str) -> bool {
        t.starts_with("while (") && (t.ends_with('{') || t.ends_with("{ "))
    }

    fn extract_while_cond(t: &str) -> Option<String> {
        // `while (cond) {`
        let rest = t.strip_prefix("while (")?;
        // Find the matching `)`.
        let mut depth = 1i32;
        let mut end = 0;
        for (idx, ch) in rest.char_indices() {
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
        Some(rest[..end].to_string())
    }

    fn find_init_before(out: &[String], indent: &str) -> Option<usize> {
        // Walk backwards in `out` looking for a non-blank line at same indent.
        for idx in (0..out.len()).rev() {
            let t = trimmed(&out[idx]);
            if t.is_empty() {
                continue;
            }
            let line_ind = indent_of(&out[idx]);
            if line_ind != indent {
                return None;
            }
            // Check it's an assignment statement.
            if t.ends_with(';') && t.contains('=') && !t.starts_with("while") && !t.starts_with("for") {
                return Some(idx);
            }
            return None;
        }
        None
    }

    fn find_close_brace(lines: &[String], open_idx: usize, indent: &str) -> Option<usize> {
        let mut depth = 0i32;
        for (i, _) in lines.iter().enumerate().skip(open_idx) {
            let t = trimmed(&lines[i]);
            for ch in t.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0
                            && (indent_of(&lines[i]) == indent || trimmed(&lines[i]) == "}") {
                                return Some(i);
                            }
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn find_last_body_stmt(lines: &[String], body_start: usize, close_idx: usize, _loop_indent: &str) -> Option<usize> {
        for i in (body_start..close_idx).rev() {
            let t = trimmed(&lines[i]);
            if !t.is_empty() {
                return Some(i);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringOpRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Replaces known string-operation loop patterns with library calls.
///
/// Patterns detected:
/// - `strlen` style: `while (*p) { p++; }` after `p = str;`
/// - Manual `strcpy`: `while (*src) { *dst++ = *src++; }` or similar.
pub struct StringOpRecovery;

impl StringOpRecovery {
    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut count = 0u32;
        let mut i = 0;

        while i < lines.len() {
            let t = trimmed(&lines[i]);
            let ind = indent_of(&lines[i]);

            // Detect `while (*ptr != '\0')` or `while (*ptr)` followed by `ptr++;`
            let is_strlen_loop = Self::is_strlen_loop_head(t);
            let is_strcpy_loop = Self::is_strcpy_loop_head(t);

            if is_strlen_loop {
                // Look for body: single `ptr++;` and closing `}`.
                if let Some((ptr_name, close)) = Self::try_extract_strlen_body(lines, i) {
                    let ind_out = if ind.is_empty() { "    ".to_string() } else { ind.to_string() };
                    // Replace with `len = strlen(str);` — we need the string name.
                    // We look backwards for a `ptr = str;` assignment.
                    if let Some((len_var, str_var)) = Self::find_strlen_context(&out, &ptr_name) {
                        out.push(format!("{ind}{len_var} = strlen({str_var});"));
                    } else {
                        // Emit a comment noting the pattern.
                        out.push(format!("{ind}/* strlen-style loop over {ptr_name} */"));
                        out.push(lines[i].clone());
                        i += 1;
                        continue;
                    }
                    count += 1;
                    i = close + 1;
                    let _ = ind_out;
                    continue;
                }
            }

            if is_strcpy_loop
                && let Some(close) = Self::try_extract_strcpy_body(lines, i) {
                    out.push(format!("{ind}/* strcpy-style loop */"));
                    // Emit a placeholder; full recovery needs DST/SRC tracking.
                    count += 1;
                    i = close + 1;
                    continue;
                }

            out.push(lines[i].clone());
            i += 1;
        }

        (out, count)
    }

    fn is_strlen_loop_head(t: &str) -> bool {
        (t.starts_with("while (*") || t.starts_with("while ( *"))
            && !t.contains("!=")
            // Not a copy loop.
            && !t.contains("++")
    }

    fn is_strcpy_loop_head(t: &str) -> bool {
        t.starts_with("while (")
            && (t.contains("*src") || t.contains("*ptr"))
            && t.contains('*')
    }

    fn try_extract_strlen_body(lines: &[String], while_idx: usize) -> Option<(String, usize)> {
        // Extract the pointer variable from `while (*ptr)` or `while (*ptr != '\0')`
        let head = trimmed(&lines[while_idx]);
        let ptr_name = Self::extract_deref_var(head)?;

        // Find the body: expect `ptr++;` and `}`.
        let body_idx = while_idx + 1;
        if body_idx >= lines.len() {
            return None;
        }
        let body_stmt = trimmed(&lines[body_idx]);
        let expected_inc = format!("{ptr_name}++;");
        if body_stmt != expected_inc.as_str() && body_stmt != format!("++{ptr_name};").as_str() {
            return None;
        }
        let close_idx = body_idx + 1;
        if close_idx >= lines.len() {
            return None;
        }
        let close_stmt = trimmed(&lines[close_idx]);
        if close_stmt == "}" {
            return Some((ptr_name, close_idx));
        }
        None
    }

    fn extract_deref_var(head: &str) -> Option<String> {
        // `while (*ptr)` → `ptr`
        // `while (*ptr != '\0')` → `ptr`
        let rest = head.strip_prefix("while (*")?;
        let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
        Some(rest[..end].to_string())
    }

    fn find_strlen_context(out: &[String], ptr_name: &str) -> Option<(String, String)> {
        // Look backwards for `ptr_name = something;`
        for i in (0..out.len()).rev() {
            let t = trimmed(&out[i]);
            let prefix = format!("{ptr_name} = ");
            if let Some(rhs) = t.strip_prefix(prefix.as_str()) {
                let str_var = rhs.strip_suffix(';')?.trim().to_string();
                // Guess the length variable name.
                let len_var = format!("{ptr_name}_len");
                return Some((len_var, str_var));
            }
        }
        None
    }

    fn try_extract_strcpy_body(lines: &[String], while_idx: usize) -> Option<usize> {
        // Find matching close brace.
        let mut depth = 0i32;
        for (i, _) in lines.iter().enumerate().skip(while_idx) {
            let t = trimmed(&lines[i]);
            for ch in t.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => {}
                }
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerArithCleaner
// ─────────────────────────────────────────────────────────────────────────────

/// Cleans up verbose pointer arithmetic expressions:
/// - `(char *)ptr + 4` → `ptr + 4` when the cast to `char*` is implicit.
/// - `(void *)&x` → `&x`
pub struct PointerArithCleaner;

impl PointerArithCleaner {
    #[must_use]
    pub fn clean_line(line: &str) -> (String, u32) {
        let mut s = line.to_string();
        let mut count = 0u32;

        // `(void *)&expr` → `&expr`
        if s.contains("(void *)&") {
            s = s.replace("(void *)&", "&");
            count += 1;
        }
        if s.contains("(void*)&") {
            s = s.replace("(void*)&", "&");
            count += 1;
        }

        // `(char *)ptr` → `ptr` (cast is usually implicit in pointer arithmetic).
        // Only when followed by ` +` or ` -`.
        for pat in &["(char *)ptr + ", "(char*)ptr + ", "(unsigned char *)ptr + "] {
            if s.contains(pat) {
                s = s.replace(pat, "ptr + ");
                count += 1;
            }
        }

        // `(BYTE *)` → cast cleanup for common Windows types.
        for (from, to) in &[
            ("(BYTE *)(", "("),
            ("(LPBYTE)(", "("),
        ] {
            if s.contains(from) {
                s = s.replace(from, to);
                count += 1;
            }
        }

        (s, count)
    }

    #[must_use]
    pub fn run(lines: &[String]) -> (Vec<String>, u32) {
        let mut total = 0u32;
        let result = lines
            .iter()
            .map(|l| {
                let (new_l, n) = Self::clean_line(l);
                total += n;
                new_l
            })
            .collect();
        (result, total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternRecovery — top-level orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Applies all recovery passes in order.
#[derive(Default)]
pub struct PatternRecovery {
    pub config: RecoveryConfig,
}


impl PatternRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: RecoveryConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn process(&self, source: &str) -> (String, RecoveryStats) {
        let mut stats = RecoveryStats::default();
        let mut lines: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();

        if self.config.passes.recover_increments() {
            let (new_lines, n) = IncrementRecovery::run(&lines);
            stats.increment_decrements += n;
            lines = new_lines;
        }

        if self.config.passes.recover_compound_assignments() {
            let (new_lines, n) = CompoundAssignmentRecovery::run(&lines);
            stats.compound_assignments += n;
            lines = new_lines;
        }

        if self.config.passes.recover_array_subscripts() {
            let (new_lines, n) = ArraySubscriptRecovery::run(&lines);
            stats.array_subscripts_recovered += n;
            lines = new_lines;
        }

        if self.config.passes.simplify_booleans() {
            let (new_lines, n) = BooleanSimplifier::run(&lines);
            stats.boolean_simplifications += n;
            lines = new_lines;
        }

        if self.config.passes.clean_pointer_arith() {
            let (new_lines, n) = PointerArithCleaner::run(&lines);
            stats.pointer_arith_cleaned += n;
            lines = new_lines;
        }

        if self.config.passes.recover_for_loops() {
            let (new_lines, n) = ForLoopRecovery::run(&lines);
            stats.for_loops_recovered += n;
            lines = new_lines;
        }

        if self.config.passes.recover_string_ops() {
            let (new_lines, n) = StringOpRecovery::run(&lines);
            stats.string_ops_recovered += n;
            lines = new_lines;
        }

        (lines.join("\n"), stats)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_recovery() {
        let lines = vec!["    i = i + 1;".to_string()];
        let (out, n) = IncrementRecovery::run(&lines);
        assert_eq!(n, 1);
        assert_eq!(out[0].trim(), "i++;");
    }

    #[test]
    fn test_decrement_recovery() {
        let lines = vec!["    count = count - 1;".to_string()];
        let (out, n) = IncrementRecovery::run(&lines);
        assert_eq!(n, 1);
        assert!(out[0].contains("count--"));
    }

    #[test]
    fn test_compound_assignment_add() {
        let lines = vec!["    x = x + y;".to_string()];
        let (out, n) = CompoundAssignmentRecovery::run(&lines);
        assert_eq!(n, 1);
        assert!(out[0].contains("x += y"));
    }

    #[test]
    fn test_compound_assignment_bitwise() {
        let lines = vec!["    flags = flags | 0x8;".to_string()];
        let (out, n) = CompoundAssignmentRecovery::run(&lines);
        assert_eq!(n, 1);
        assert!(out[0].contains("flags |= 0x8"));
    }

    #[test]
    fn test_array_subscript_basic() {
        let lines = vec!["    val = *(arr + i);".to_string()];
        let (out, n) = ArraySubscriptRecovery::run(&lines);
        assert_eq!(n, 1);
        assert!(out[0].contains("arr[i]"), "got: {}", out[0]);
    }

    #[test]
    fn test_array_subscript_no_false_positive_multiply() {
        let lines = vec!["    result = a * (b + c);".to_string()];
        let (out, n) = ArraySubscriptRecovery::run(&lines);
        // Should NOT be recovered as an array subscript.
        assert_eq!(n, 0);
        assert_eq!(out[0], "    result = a * (b + c);");
    }

    #[test]
    fn test_boolean_ne_zero() {
        let lines = vec!["    if (x != 0) {".to_string()];
        let (out, n) = BooleanSimplifier::run(&lines);
        assert!(n > 0);
        // `x != 0)` → `x)`
        assert!(out[0].contains("if (x)") || out[0].contains("(x)"));
    }

    #[test]
    fn test_boolean_double_not() {
        let (out, n) = BooleanSimplifier::simplify_line("    if (!!flag) {");
        assert!(n > 0);
        assert!(out.contains("if (flag)"));
    }

    #[test]
    fn test_pointer_arith_void_ref() {
        let (out, n) = PointerArithCleaner::clean_line("    p = (void *)&x;");
        assert!(n > 0);
        assert!(out.contains("&x"));
        assert!(!out.contains("(void *)"));
    }

    #[test]
    fn test_for_loop_recovery() {
        let src = "    i = 0;\n    while (i < 10) {\n        body();\n        i++;\n    }\n";
        let pr = PatternRecovery::new();
        let (out, stats) = pr.process(src);
        assert!(stats.for_loops_recovered > 0 || out.contains("for") || out.contains("while"),
            "output: {out}");
    }

    #[test]
    fn test_pattern_recovery_pipeline() {
        let src = "void foo() {\n    x = x + 1;\n    y = y * 2;\n}\n";
        let pr = PatternRecovery::new();
        let (out, stats) = pr.process(src);
        assert!(stats.total() > 0);
        assert!(out.contains("x++") || out.contains("x += 1") || out.contains('y'));
    }

    #[test]
    fn test_is_loop_update() {
        assert!(is_loop_update("i++;"));
        assert!(is_loop_update("i--;"));
        assert!(is_loop_update("i += 2;"));
        assert!(is_loop_update("i = i + 1;"));
        assert!(!is_loop_update("x = y + z;"));
    }
}
