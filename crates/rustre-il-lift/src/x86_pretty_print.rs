//! Pretty-printer for lifted x86 IR.
//!
//! Renders `LiftedInstr` / `Vec<LiftedInstr>` to human-readable text in
//! multiple output formats. Used by the `rustre-cli` disassembler view and
//! the decompiler's "LLIL view" pane.
//!
//! ## Output formats
//!
//! | Format | Description |
//! |---|---|
//! | `Text`   | Plain text, one effect per line |
//! | `Color`  | Text with ANSI escape codes (bold/dim/coloured) |
//! | `Html`   | Inline-styled HTML for embedding in reports |
//! | `Json`   | Structured JSON for machine consumption |
//!
//! All formats are written to a `Write` sink (so they can target `String`,
//! `File`, or any other writer without allocation).

use crate::{Effect, IrExpr, LiftedInstr};
use std::fmt::Write as FmtWrite;

// ─────────────────────────────────────────────────────────────────────────────
// OutputFormat
// ─────────────────────────────────────────────────────────────────────────────

/// Requested output format for the pretty-printer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Plain text — no markup.
    #[default]
    Text,
    /// ANSI-coloured text (terminal-friendly).
    Color,
    /// Inline-styled HTML fragment.
    Html,
    /// Machine-readable JSON.
    Json,
}

// ─────────────────────────────────────────────────────────────────────────────
// PrintOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Flags controlling what output fields are shown.
#[derive(Debug, Clone, Copy)]
pub struct DisplayFlags {
    /// Print instruction addresses.
    pub show_addresses: bool,
    /// Print the original mnemonic next to each lifted instruction.
    pub show_mnemonic: bool,
    /// Print IL level tag (e.g. `[LLIL]`).
    pub show_il_level: bool,
}

/// Options for controlling the output of the pretty-printer.
#[derive(Debug, Clone)]
pub struct PrintOptions {
    /// Output format.
    pub format: OutputFormat,
    /// Display flags (addresses, mnemonic, IL level).
    pub display: DisplayFlags,
    /// Indent each effect line.
    pub indent_effects: bool,
    /// Max expression depth before abbreviating with `...`.
    pub max_expr_depth: usize,
    /// Print the number of effects per instruction.
    pub show_effect_count: bool,
    /// Print temporary register names in full (vs. condensed `tN`).
    pub verbose_temps: bool,
}

impl Default for PrintOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            display: DisplayFlags { show_addresses: true, show_mnemonic: true, show_il_level: false },
            indent_effects: true,
            max_expr_depth: 8,
            show_effect_count: false,
            verbose_temps: false,
        }
    }
}

impl PrintOptions {
    /// Minimal options — show only effects, no decoration.
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            format: OutputFormat::Text,
            display: DisplayFlags { show_addresses: false, show_mnemonic: false, show_il_level: false },
            indent_effects: false,
            max_expr_depth: 12,
            show_effect_count: false,
            verbose_temps: false,
        }
    }

    /// Verbose options — show everything.
    #[must_use]
    pub fn verbose() -> Self {
        Self {
            display: DisplayFlags { show_addresses: true, show_mnemonic: true, show_il_level: true },
            indent_effects: true,
            show_effect_count: true,
            verbose_temps: true,
            max_expr_depth: 20,
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrExpr rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Render an `IrExpr` to a string, truncating at `max_depth`.
#[must_use]
pub fn render_expr(expr: &IrExpr, max_depth: usize) -> String {
    if max_depth == 0 {
        return "...".into();
    }
    let d = max_depth - 1;
    match expr {
        IrExpr::Const(v) => format!("{v:#x}"),
        IrExpr::Reg(r) => r.clone(),
        IrExpr::Undef => "⊥".into(),
        IrExpr::Add(a, b) => format!("({} + {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Sub(a, b) => format!("({} - {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Mul(a, b) => format!("({} * {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::And(a, b) => format!("({} & {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Or(a, b) => format!("({} | {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Xor(a, b) => format!("({} ^ {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Shl(a, b) => format!("({} << {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Shr(a, b) => format!("({} >> {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Sar(a, b) => format!("({} >>> {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Not(e) => format!("(!{})", render_expr(e, d)),
        IrExpr::Deref(addr, size) => format!("*{}:{}", render_expr(addr, d), size),
        IrExpr::CmpEqZero(e) => format!("({} == 0)", render_expr(e, d)),
        IrExpr::Parity(e) => format!("parity({})", render_expr(e, d)),
        IrExpr::CmpEq(a, b) | IrExpr::Eq(a, b) => format!("({} == {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::CmpLt(a, b) => format!("({} < {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::CmpLtU(a, b) => format!("({} <u {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::CmpGt(a, b) => format!("({} > {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::Ne(a, b) => format!("({} != {})", render_expr(a, d), render_expr(b, d)),
        IrExpr::IfThenElse(c, t, e) => format!(
            "({} ? {} : {})",
            render_expr(c, d),
            render_expr(t, d),
            render_expr(e, d)
        ),
    }
}

/// Render an `IrExpr` abbreviating temporary register names to `tN`.
#[must_use]
pub fn render_expr_compact(expr: &IrExpr, max_depth: usize) -> String {
    let s = render_expr(expr, max_depth);
    // Replace __tN with just tN.
    s.replace("__t", "t")
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Render a single `Effect` to a string.
#[must_use]
pub fn render_effect(eff: &Effect, opts: &PrintOptions) -> String {
    let d = opts.max_expr_depth;
    let re = |e: &IrExpr| {
        if opts.verbose_temps {
            render_expr(e, d)
        } else {
            render_expr_compact(e, d)
        }
    };
    match eff {
        Effect::RegWrite { reg, value } => {
            let r = if opts.verbose_temps {
                reg.clone()
            } else {
                reg.replace("__t", "t")
            };
            format!("{r} = {}", re(value))
        }
        Effect::MemRead { addr, dest, size } => {
            let d_name = if opts.verbose_temps {
                dest.clone()
            } else {
                dest.replace("__t", "t")
            };
            format!("{d_name} = load.{size}({})", re(addr))
        }
        Effect::MemWrite { addr, value, size } => {
            format!("store.{size}({}, {})", re(addr), re(value))
        }
        Effect::Branch { target, condition } => condition.as_ref().map_or_else(|| format!("goto {}", re(target)), |c| format!("if {} goto {}", re(c), re(target))),
        Effect::Call { target } => format!("call {}", re(target)),
        Effect::Return { value } => value.as_ref().map_or_else(|| "return".into(), |v| format!("return {}", re(v))),
        Effect::Syscall { nr } => format!("syscall({})", re(nr)),
        Effect::Intrinsic { name, args } => {
            let arg_strs: Vec<_> = args.iter().map(&re).collect();
            format!("intrinsic:{}({})", name, arg_strs.join(", "))
        }
        Effect::Trap { vector } => format!("trap({vector})"),
        Effect::ConditionalTrap { condition, vector } => {
            format!("if {} trap({vector})", re(condition))
        }
        Effect::NoReturn => "noreturn".into(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedInstr rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Render a single `LiftedInstr` to a string.
#[must_use]
pub fn render_instr(li: &LiftedInstr, opts: &PrintOptions) -> String {
    let mut out = String::new();

    // Header line.
    if opts.display.show_addresses {
        let _ = write!(out, "{:#010x}", li.address);
    }
    if opts.display.show_mnemonic {
        if !out.is_empty() {
            out.push(' ');
        }
        let _ = write!(out, "{}", li.original_mnemonic);
    }
    if opts.display.show_il_level {
        let _ = write!(out, " [{:?}]", li.il_level);
    }
    if opts.show_effect_count {
        let _ = write!(out, " ({} μops)", li.effects.len());
    }

    // Effects.
    let indent = if opts.indent_effects { "  " } else { "" };
    for eff in &li.effects {
        out.push('\n');
        out.push_str(indent);
        out.push_str(&render_effect(eff, opts));
    }

    out
}

/// Render a stream of lifted instructions to a string.
#[must_use]
pub fn render_block(instrs: &[LiftedInstr], opts: &PrintOptions) -> String {
    instrs
        .iter()
        .map(|li| render_instr(li, opts))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colour helpers
// ─────────────────────────────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const FG_CYAN: &str = "\x1b[36m";
const FG_YELLOW: &str = "\x1b[33m";
const FG_GREEN: &str = "\x1b[32m";
const FG_RED: &str = "\x1b[31m";
const FG_MAGENTA: &str = "\x1b[35m";

fn ansi_addr(addr: u64) -> String {
    format!("{DIM}{addr:#010x}{RESET}")
}

fn ansi_mnemonic(m: &str) -> String {
    format!("{BOLD}{FG_YELLOW}{m}{RESET}")
}

fn ansi_reg(r: &str) -> String {
    format!("{FG_CYAN}{r}{RESET}")
}

fn ansi_const(v: u64) -> String {
    format!("{FG_GREEN}{v:#x}{RESET}")
}

fn ansi_keyword(k: &str) -> String {
    format!("{FG_MAGENTA}{k}{RESET}")
}

fn ansi_intrinsic(name: &str) -> String {
    format!("{FG_RED}{name}{RESET}")
}

/// Render an `IrExpr` with ANSI colours.
#[must_use]
pub fn render_expr_color(expr: &IrExpr, max_depth: usize) -> String {
    if max_depth == 0 {
        return format!("{DIM}...{RESET}");
    }
    let d = max_depth - 1;
    let rc = |e: &IrExpr| render_expr_color(e, d);
    match expr {
        IrExpr::Const(v) => ansi_const(*v),
        IrExpr::Reg(r) => ansi_reg(r),
        IrExpr::Undef => format!("{FG_RED}⊥{RESET}"),
        IrExpr::Add(a, b) => format!("({} + {})", rc(a), rc(b)),
        IrExpr::Sub(a, b) => format!("({} - {})", rc(a), rc(b)),
        IrExpr::Mul(a, b) => format!("({} * {})", rc(a), rc(b)),
        IrExpr::And(a, b) => format!("({} & {})", rc(a), rc(b)),
        IrExpr::Or(a, b) => format!("({} | {})", rc(a), rc(b)),
        IrExpr::Xor(a, b) => format!("({} ^ {})", rc(a), rc(b)),
        IrExpr::Shl(a, b) => format!("({} << {})", rc(a), rc(b)),
        IrExpr::Shr(a, b) => format!("({} >> {})", rc(a), rc(b)),
        IrExpr::Sar(a, b) => format!("({} >>> {})", rc(a), rc(b)),
        IrExpr::Not(e) => format!("(!{})", rc(e)),
        IrExpr::Deref(addr, size) => format!("*{}:{}", rc(addr), size),
        IrExpr::CmpEqZero(e) => format!("({} == {})", rc(e), ansi_const(0)),
        IrExpr::Parity(e) => format!("{}({})", ansi_keyword("parity"), rc(e)),
        IrExpr::CmpEq(a, b) | IrExpr::Eq(a, b) => format!("({} == {})", rc(a), rc(b)),
        IrExpr::CmpLt(a, b) => format!("({} < {})", rc(a), rc(b)),
        IrExpr::CmpLtU(a, b) => format!("({} <u {})", rc(a), rc(b)),
        IrExpr::CmpGt(a, b) => format!("({} > {})", rc(a), rc(b)),
        IrExpr::Ne(a, b) => format!("({} != {})", rc(a), rc(b)),
        IrExpr::IfThenElse(c, t, e) => format!("({} ? {} : {})", rc(c), rc(t), rc(e)),
    }
}

/// Render a single `Effect` with ANSI colours.
#[must_use]
pub fn render_effect_color(eff: &Effect, max_depth: usize) -> String {
    let rc = |e: &IrExpr| render_expr_color(e, max_depth);
    match eff {
        Effect::RegWrite { reg, value } => format!("{} = {}", ansi_reg(reg), rc(value)),
        Effect::MemRead { addr, dest, size } => format!(
            "{} = {}load.{}({}){}",
            ansi_reg(dest),
            FG_CYAN,
            size,
            rc(addr),
            RESET
        ),
        Effect::MemWrite { addr, value, size } => format!(
            "{}store.{}{}({}, {})",
            FG_CYAN,
            size,
            RESET,
            rc(addr),
            rc(value)
        ),
        Effect::Branch { target, condition } => condition.as_ref().map_or_else(|| format!("{} {}", ansi_keyword("goto"), rc(target)), |c| format!(
                "{} {} {} {}",
                ansi_keyword("if"),
                rc(c),
                ansi_keyword("goto"),
                rc(target)
            )),
        Effect::Call { target } => format!("{} {}", ansi_keyword("call"), rc(target)),
        Effect::Return { value } => value.as_ref().map_or_else(|| ansi_keyword("return"), |v| format!("{} {}", ansi_keyword("return"), rc(v))),
        Effect::Syscall { nr } => format!("{}({})", ansi_keyword("syscall"), rc(nr)),
        Effect::Intrinsic { name, args } => {
            let arg_strs: Vec<_> = args.iter().map(&rc).collect();
            format!(
                "{}({})",
                ansi_intrinsic(&format!("intrinsic:{name}")),
                arg_strs.join(", ")
            )
        }
        Effect::Trap { vector } => format!("{}({vector})", ansi_keyword("trap")),
        Effect::ConditionalTrap { condition, vector } => format!(
            "{} {} {}({vector})",
            ansi_keyword("if"),
            rc(condition),
            ansi_keyword("trap")
        ),
        Effect::NoReturn => ansi_keyword("noreturn"),
    }
}

/// Render a single `LiftedInstr` with ANSI colours.
#[must_use]
pub fn render_instr_color(li: &LiftedInstr, opts: &PrintOptions) -> String {
    let mut out = String::new();
    out.push_str(&ansi_addr(li.address));
    out.push(' ');
    out.push_str(&ansi_mnemonic(&li.original_mnemonic));
    let indent = if opts.indent_effects { "  " } else { "" };
    for eff in &li.effects {
        out.push('\n');
        out.push_str(indent);
        out.push_str(&render_effect_color(eff, opts.max_expr_depth));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────

/// Render the IR of a single instruction as a JSON object string.
#[must_use]
pub fn render_instr_json(li: &LiftedInstr) -> String {
    let effects_json: Vec<String> = li
        .effects
        .iter()
        .map(|e| {
            format!(
                "\"{}\"",
                render_effect(e, &PrintOptions::minimal()).replace('"', "\\\"")
            )
        })
        .collect();
    format!(
        "{{\"addr\":{:#x},\"mnemonic\":\"{}\",\"effects\":[{}]}}",
        li.address,
        li.original_mnemonic,
        effects_json.join(","),
    )
}

/// Render a block of instructions as a JSON array.
#[must_use]
pub fn render_block_json(instrs: &[LiftedInstr]) -> String {
    let items: Vec<_> = instrs.iter().map(render_instr_json).collect();
    format!("[{}]", items.join(","))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML output
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render a single effect as an HTML `<span>` row.
#[must_use]
pub fn render_effect_html(eff: &Effect, opts: &PrintOptions) -> String {
    let text = html_escape(&render_effect(eff, opts));
    format!("<span class=\"llil-effect\">{text}</span>")
}

/// Render a single instruction as an HTML `<div>` block.
#[must_use]
pub fn render_instr_html(li: &LiftedInstr, opts: &PrintOptions) -> String {
    let mut out = String::new();
    out.push_str("<div class=\"llil-instr\">");
    if opts.display.show_addresses {
        let _ = write!(
            out,
            "<span class=\"llil-addr\">{:#010x}</span> ",
            li.address
        );
    }
    if opts.display.show_mnemonic {
        let _ = write!(
            out,
            "<span class=\"llil-mnemonic\">{}</span>",
            html_escape(&li.original_mnemonic)
        );
    }
    out.push_str("<ul class=\"llil-effects\">");
    for eff in &li.effects {
        let _ = write!(out, "<li>{}</li>", render_effect_html(eff, opts));
    }
    out.push_str("</ul></div>");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified render entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render a list of instructions using the format specified in `opts`.
#[must_use]
pub fn render(instrs: &[LiftedInstr], opts: &PrintOptions) -> String {
    match opts.format {
        OutputFormat::Text => render_block(instrs, opts),
        OutputFormat::Color => instrs
            .iter()
            .map(|li| render_instr_color(li, opts))
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Html => instrs
            .iter()
            .map(|li| render_instr_html(li, opts))
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Json => render_block_json(instrs),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};

    fn instr(addr: u64, mnemonic: &str, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: mnemonic.to_string(),
            ir_text: mnemonic.to_string(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    // ── render_expr ──────────────────────────────────────────────────────────

    #[test]
    fn render_const() {
        assert_eq!(render_expr(&IrExpr::Const(0x42), 8), "0x42");
    }

    #[test]
    fn render_reg() {
        assert_eq!(render_expr(&IrExpr::Reg("rax".into()), 8), "rax");
    }

    #[test]
    fn render_undef() {
        assert_eq!(render_expr(&IrExpr::Undef, 8), "⊥");
    }

    #[test]
    fn render_add() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Const(1)),
        );
        let s = render_expr(&e, 8);
        assert!(s.contains("rax"), "should contain rax");
        assert!(s.contains('+'), "should contain +");
    }

    #[test]
    fn render_cmp_eq_zero() {
        let e = IrExpr::CmpEqZero(Box::new(IrExpr::Reg("rbx".into())));
        let s = render_expr(&e, 8);
        assert!(s.contains("rbx"));
        assert!(s.contains("=="));
    }

    #[test]
    fn render_parity() {
        let e = IrExpr::Parity(Box::new(IrExpr::Const(5)));
        let s = render_expr(&e, 8);
        assert!(s.contains("parity"));
    }

    #[test]
    fn render_truncates_at_depth_zero() {
        let e = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
        assert_eq!(render_expr(&e, 0), "...");
    }

    #[test]
    fn render_deref() {
        let e = IrExpr::Deref(Box::new(IrExpr::Const(0x1000)), 8);
        let s = render_expr(&e, 8);
        assert!(s.contains("0x1000"));
        assert!(s.contains(":8"));
    }

    #[test]
    fn render_compact_replaces_temp_prefix() {
        let e = IrExpr::Reg("__t0".into());
        let s = render_expr_compact(&e, 8);
        assert_eq!(s, "t0");
    }

    // ── render_effect ────────────────────────────────────────────────────────

    #[test]
    fn render_reg_write() {
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0x42),
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("rax"));
        assert!(s.contains("0x42"));
        assert!(s.contains('='));
    }

    #[test]
    fn render_mem_read() {
        let e = Effect::MemRead {
            addr: IrExpr::Const(0x1000),
            dest: "rbx".into(),
            size: 8,
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("rbx"));
        assert!(s.contains("load"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn render_mem_write() {
        let e = Effect::MemWrite {
            addr: IrExpr::Const(0x2000),
            value: IrExpr::Const(0),
            size: 4,
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("store"));
        assert!(s.contains("0x2000"));
    }

    #[test]
    fn render_unconditional_branch() {
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: None,
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("goto"));
        assert!(s.contains("0x401000"));
    }

    #[test]
    fn render_conditional_branch() {
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: Some(IrExpr::Reg("zf".into())),
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("if"));
        assert!(s.contains("zf"));
    }

    #[test]
    fn render_call() {
        let e = Effect::Call {
            target: IrExpr::Const(0x0040_4000),
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("call"));
    }

    #[test]
    fn render_return_with_value() {
        let e = Effect::Return {
            value: Some(IrExpr::Reg("rax".into())),
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("return"));
        assert!(s.contains("rax"));
    }

    #[test]
    fn render_syscall() {
        let e = Effect::Syscall {
            nr: IrExpr::Const(60),
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("syscall"));
    }

    #[test]
    fn render_intrinsic() {
        let e = Effect::Intrinsic {
            name: "x86.cpuid".into(),
            args: vec![],
        };
        let s = render_effect(&e, &PrintOptions::default());
        assert!(s.contains("x86.cpuid"));
    }

    // ── render_instr ─────────────────────────────────────────────────────────

    #[test]
    fn render_instr_shows_address() {
        let li = instr(0x0040_1000, "nop", vec![]);
        let s = render_instr(&li, &PrintOptions::default());
        assert!(s.contains("0x00401000"), "address not found in: {s}");
    }

    #[test]
    fn render_instr_shows_mnemonic() {
        let li = instr(0x0040_1000, "mov", vec![]);
        let s = render_instr(&li, &PrintOptions::default());
        assert!(s.contains("mov"));
    }

    #[test]
    fn render_instr_indents_effects() {
        let li = instr(
            0x1000,
            "add",
            vec![Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            }],
        );
        let opts = PrintOptions {
            indent_effects: true,
            ..Default::default()
        };
        let s = render_instr(&li, &opts);
        // Should have two spaces before the effect.
        assert!(s.contains("\n  "), "expected indented effect");
    }

    #[test]
    fn render_minimal_no_address() {
        let li = instr(0x1000, "nop", vec![]);
        let opts = PrintOptions::minimal();
        let s = render_instr(&li, &opts);
        assert!(!s.contains("0x00001000"), "minimal should not show address");
    }

    // ── JSON ─────────────────────────────────────────────────────────────────

    #[test]
    fn json_contains_addr() {
        let li = instr(0x0040_1000, "nop", vec![]);
        let j = render_instr_json(&li);
        assert!(j.contains("0x401000"), "JSON should contain address");
    }

    #[test]
    fn json_contains_mnemonic() {
        let li = instr(0x1000, "push", vec![]);
        let j = render_instr_json(&li);
        assert!(j.contains("push"));
    }

    #[test]
    fn json_block_is_array() {
        let instrs = vec![instr(0x1000, "nop", vec![])];
        let j = render_block_json(&instrs);
        assert!(j.starts_with('['));
        assert!(j.ends_with(']'));
    }

    // ── HTML ─────────────────────────────────────────────────────────────────

    #[test]
    fn html_contains_class() {
        let li = instr(
            0x1000,
            "mov",
            vec![Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(0),
            }],
        );
        let h = render_instr_html(&li, &PrintOptions::default());
        assert!(h.contains("llil-instr"), "HTML should have class");
    }

    #[test]
    fn html_escapes_less_than() {
        assert_eq!(html_escape("<foo>"), "&lt;foo&gt;");
    }

    // ── OutputFormat dispatch ─────────────────────────────────────────────────

    #[test]
    fn render_text_format() {
        let instrs = vec![instr(0x1000, "nop", vec![])];
        let opts = PrintOptions {
            format: OutputFormat::Text,
            ..Default::default()
        };
        let s = render(&instrs, &opts);
        assert!(!s.is_empty());
    }

    #[test]
    fn render_json_format() {
        let instrs = vec![instr(0x1000, "nop", vec![])];
        let opts = PrintOptions {
            format: OutputFormat::Json,
            ..Default::default()
        };
        let s = render(&instrs, &opts);
        assert!(s.starts_with('['));
    }

    #[test]
    fn render_html_format() {
        let instrs = vec![instr(0x1000, "nop", vec![])];
        let opts = PrintOptions {
            format: OutputFormat::Html,
            ..Default::default()
        };
        let s = render(&instrs, &opts);
        assert!(s.contains('<'));
    }

    // ── PrintOptions ─────────────────────────────────────────────────────────

    #[test]
    fn default_options_show_address() {
        assert!(PrintOptions::default().display.show_addresses);
    }

    #[test]
    fn minimal_options_no_mnemonic() {
        assert!(!PrintOptions::minimal().display.show_mnemonic);
    }

    #[test]
    fn verbose_options_show_all() {
        let o = PrintOptions::verbose();
        assert!(o.display.show_addresses);
        assert!(o.display.show_mnemonic);
        assert!(o.display.show_il_level);
        assert!(o.show_effect_count);
    }
}
