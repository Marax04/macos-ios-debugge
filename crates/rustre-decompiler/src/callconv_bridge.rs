//! Bridge between the decompiler's `(addr, mnemonic, operands)` and `Instruction`
//! views and the `rustre-analysis-callconv` detector.
//!
//! The decompiler does not depend on a single disassembler representation:
//! `PassContext` stores `raw_mnemonics` as `(u64, String, String)` triples while
//! `function_decompiler::FunctionDecompilerV2` works with `&[Instruction]`.
//! Both paths can be lifted to `Vec<DetectInstr>` and run through the rich
//! `CallingConventionDetector` in `rustre_analysis_callconv`.
//!
//! On success the bridge yields:
//! * the best-matching [`CallingConventionPattern`],
//! * the [`ObservedPattern`] that produced the match,
//! * the inferred [`RecoveredParam`] list (registers + stack overflow slots).

use rustre_analysis_callconv::{
    Arch, CallConvError, CallingConventionDatabase, CallingConventionDetector,
    CallingConventionPattern, CcKey, Compiler, DetectInstr, ObservedPattern, Os,
    propagation::infer_params_from_observed,
};
use rustre_core::arch::Instruction;

use crate::signature_recovery::RecoveredParam;

/// Result of an automatic calling-convention inference.
#[derive(Debug, Clone)]
pub struct CallConvInference {
    /// The detected calling-convention pattern (e.g. `Microsoft x64`).
    pub pattern: CallingConventionPattern,
    /// Raw evidence used for the match.
    pub observed: ObservedPattern,
    /// Ordered list of parameters inferred from the observed register reads
    /// and stack-argument offsets.
    pub params: Vec<RecoveredParam>,
    /// Confidence score (0..=100+) from the detector.
    pub confidence: u32,
}

/// Lift a single `(mnemonic, operands)` pair to one or more `DetectInstr`s.
///
/// The decompiler stores raw mnemonics as flat strings, so we approximate the
/// def/use sets from the operand text.  Register tokens on the LHS of a comma
/// are treated as writes; tokens on the RHS as reads; `push`/`pop`/`ret` are
/// mapped to their dedicated `DetectInstr` variants.
#[must_use]
pub fn lift_mnemonic(mnemonic: &str, operands: &str) -> Vec<DetectInstr> {
    let mnem = mnemonic.trim().to_ascii_lowercase();
    let ops = operands.trim();
    let mut out: Vec<DetectInstr> = Vec::new();

    match mnem.as_str() {
        "push" => {
            let reg = ops.trim().trim_matches(',').to_ascii_lowercase();
            if is_known_register(&reg) {
                out.push(DetectInstr::Push { reg });
            } else {
                // Memory / immediate operand: don't fabricate a register push.
                out.push(DetectInstr::Other);
            }
            return out;
        }
        "pop" => {
            let reg = ops.trim().trim_matches(',').to_ascii_lowercase();
            if is_known_register(&reg) {
                out.push(DetectInstr::Pop { reg });
            } else {
                out.push(DetectInstr::Other);
            }
            return out;
        }
        "ret" | "retn" => {
            let bytes = parse_int_literal(ops).unwrap_or(0);
            out.push(DetectInstr::Ret { stack_bytes: bytes });
            return out;
        }
        "leave" => {
            out.push(DetectInstr::Other);
            return out;
        }
        _ => {}
    }

    // `sub rsp, N` → StackAlloc.
    if mnem == "sub"
        && let Some((dst, src)) = ops.split_once(',')
    {
        let dst = dst.trim().to_ascii_lowercase();
        let src = src.trim();
        if (dst == "rsp" || dst == "esp")
            && let Some(n) = parse_int_literal(src)
        {
            out.push(DetectInstr::StackAlloc { bytes: n });
            return out;
        }
    }

    // `[rsp+N]`, `[rbp+N]` → stack-arg access.
    for off in extract_positive_stack_offsets(ops) {
        out.push(DetectInstr::StackArgAccess { offset: off });
    }

    // Reg writes / reads.
    let (writes, reads) = classify_operands(&mnem, ops);
    for reg in writes {
        // No FpRegWrite in the model — record a write so that later FP reads
        // are not mis-classified as live-in.
        out.push(DetectInstr::RegWrite { reg });
    }
    for reg in reads {
        if is_fp_register(&reg) {
            out.push(DetectInstr::FpRegRead { reg });
        } else {
            out.push(DetectInstr::RegRead { reg });
        }
    }

    if out.is_empty() {
        out.push(DetectInstr::Other);
    }
    out
}

/// Lift a full `(mnemonic, operands)` stream to a `Vec<DetectInstr>`.
#[must_use]
pub fn lift_mnemonic_stream<'a, I>(stream: I) -> Vec<DetectInstr>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = Vec::new();
    for (m, o) in stream {
        out.extend(lift_mnemonic(m, o));
    }
    out
}

/// Lift a slice of `rustre_core::arch::Instruction` to `Vec<DetectInstr>`.
#[must_use]
pub fn lift_instructions(instrs: &[Instruction]) -> Vec<DetectInstr> {
    let mut out = Vec::new();
    for ins in instrs {
        out.extend(lift_mnemonic(&ins.mnemonic, &ins.operands));
    }
    out
}

/// Run the calling-convention detector against a lifted `DetectInstr` stream.
///
/// `arch` and `os` select the candidate set in the built-in database; when no
/// candidates exist for the exact `(arch, os)` pair we fall back to the
/// arch-wide pool.
/// # Errors
/// Returns an error if no calling convention candidates are found for the given arch/os.
pub fn detect(instrs: &[DetectInstr], arch: &Arch, os: &Os) -> Result<CallConvInference, CallConvError> {
    let db = CallingConventionDatabase::with_builtins();
    let mut candidates: Vec<CallingConventionPattern> = {
        let exact: Vec<CallingConventionPattern> = [Compiler::Any, Compiler::Msvc, Compiler::Gcc, Compiler::Clang]
            .iter()
            .flat_map(|c| db.lookup(&CcKey::new(arch.clone(), os.clone(), c.clone())))
            .cloned()
            .collect();
        if exact.is_empty() {
            db.lookup_any_os(arch).into_iter().cloned().collect()
        } else {
            exact
        }
    };
    // The built-in DB registers the same `CallingConventionPattern` under
    // multiple compiler keys; that produces ties in `detect_with_hints`.
    // Dedupe by name before scoring.
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    candidates.dedup_by(|a, b| a.name == b.name);
    if candidates.is_empty() {
        return Err(CallConvError::UnknownKey(format!("{arch}/{os}")));
    }

    let observed = CallingConventionDetector::extract_pattern(instrs, arch.pointer_width());
    let ranked = CallingConventionDetector::rank_candidates(&observed, &candidates);
    let confidence = ranked.first().map_or(0, |(_, s)| *s);
    let pattern = match CallingConventionDetector::detect_with_hints(&observed, &candidates) {
        Ok(p) => p,
        Err(CallConvError::Ambiguous) => {
            // Prefer canonical ABIs over vendor extensions when scoring ties.
            let preferred = ["Microsoft x64", "System V AMD64 ABI", "AAPCS64", "cdecl"];
            let top_score = ranked.first().map_or(0, |(_, s)| *s);
            let tied: Vec<&CallingConventionPattern> = ranked
                .iter()
                .filter(|(_, s)| *s == top_score)
                .map(|(p, _)| p)
                .collect();
            let chosen = preferred
                .iter()
                .find_map(|name| tied.iter().find(|p| p.name == *name))
                .copied()
                .or_else(|| tied.first().copied())
                .ok_or(CallConvError::NoMatch)?;
            chosen.clone()
        }
        Err(e) => return Err(e),
    };

    let args = infer_params_from_observed(&observed, &pattern);
    let mut params: Vec<RecoveredParam> = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        let register = if arg.register.starts_with('[') {
            None
        } else {
            Some(arg.register.clone())
        };
        let stack_offset = if register.is_none() {
            // Extract `[sp+0xNN]` numeric offset.
            extract_sp_offset(&arg.register)
        } else {
            None
        };
        params.push(RecoveredParam {
            name: format!("arg_{idx}"),
            ty: "int".to_string(),
            register,
            stack_offset,
        });
    }

    Ok(CallConvInference {
        pattern,
        observed,
        params,
        confidence,
    })
}

/// Infer the number of STACK-passed arguments from callee-cleanup evidence.
///
/// Unlike the register-liveness heuristics used everywhere else, `ret N` is an
/// EXACT fact read out of the binary: on a callee-cleans ABI (`stdcall`,
/// `thiscall`, `fastcall` overflow) the callee pops exactly the bytes its
/// caller pushed, so `N / pointer_size` is the stack-argument count, not a
/// guess. This delegates to `rustre_analysis_callconv::stack_cleanup_analyzer`,
/// which owns the analysis (and is unit-tested there).
///
/// Returns `None` when the function is not callee-cleanup, when the count is
/// zero, or when `pointer_size` is not a legal pointer width — i.e. the caller
/// gets a value only when there is real evidence.
#[must_use]
pub fn stack_cleanup(instrs: &[DetectInstr], pointer_size: u32) -> Option<u32> {
    use rustre_analysis_callconv::stack_cleanup_analyzer::{
        CleanupKind, StackCleanupAnalyzer, StackInstr,
    };

    // `StackCleanupAnalyzer::new` asserts on other widths; never panic here.
    if !matches!(pointer_size, 2 | 4 | 8) {
        return None;
    }

    let mut stack_instrs: Vec<StackInstr> = Vec::with_capacity(instrs.len());
    for (idx, ins) in instrs.iter().enumerate() {
        // `DetectInstr` carries no addresses; the stream index is a stable
        // stand-in for the byte offset (only used to label ret sites).
        let offset = idx as u64;
        stack_instrs.push(match ins {
            DetectInstr::Push { .. } => StackInstr::Push { size: pointer_size },
            DetectInstr::Pop { .. } => StackInstr::Pop { size: pointer_size },
            DetectInstr::Ret { stack_bytes } => StackInstr::Ret {
                n: *stack_bytes,
                offset,
            },
            DetectInstr::StackAlloc { bytes } => StackInstr::SpDecrement { bytes: *bytes },
            DetectInstr::StackArgAccess { offset: off } => {
                StackInstr::SpRelAccess { offset: *off }
            }
            _ => StackInstr::Other,
        });
    }

    let mut analyzer = StackCleanupAnalyzer::new(pointer_size);
    analyzer.observe_all(&stack_instrs);
    if analyzer.cleanup_kind() != CleanupKind::CalleeCleans {
        return None;
    }
    let count = analyzer.inferred_stack_arg_count();
    if count == 0 { None } else { Some(count) }
}

/// Detect OS hint from the `is_pe` flag.
///
/// PE → Windows; ELF → Linux by convention (System V). This matches the
/// existing `recover_signature` heuristic while letting callers override
/// either component.
#[must_use]
pub const fn os_from_pe_flag(is_pe: bool) -> Os {
    if is_pe { Os::Windows } else { Os::Linux }
}

/// Detect the architecture from a free-form arch string.  The strings used by
/// `FunctionDecompilerOptions::arch` (`"x86_64"`, `"x86-64"`, `"aarch64"`, …)
/// are mapped onto the [`Arch`] enum.
#[must_use]
pub fn arch_from_str(arch: &str) -> Arch {
    let a = arch.to_ascii_lowercase();
    if a.contains("aarch64") || a.contains("arm64") {
        Arch::Arm64
    } else if a.contains("arm") {
        Arch::Arm32
    } else if a.contains("x86_64") || a.contains("x86-64") || a.contains("amd64") {
        Arch::X86_64
    } else if a.contains("x86") || a.contains("i386") || a.contains("i686") {
        Arch::X86
    } else if a.contains("riscv64") {
        Arch::RiscV64
    } else if a.contains("riscv32") {
        Arch::RiscV32
    } else if a.contains("mips64") {
        Arch::Mips64
    } else if a.contains("mips") {
        Arch::Mips32
    } else {
        Arch::X86_64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_int_literal(s: &str) -> Option<u32> {
    let s = s.trim_matches(|c: char| c == ',' || c.is_whitespace());
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    // MASM-style hex: `20h`, `0A0h`.
    if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse::<u32>().ok()
}

fn extract_positive_stack_offsets(operands: &str) -> Vec<i32> {
    let mut out = Vec::new();
    let ops = operands.to_ascii_lowercase();
    for base in ["rbp", "rsp", "ebp", "esp"] {
        let mut rest = ops.as_str();
        while let Some(pos) = rest.find(base) {
            let after = &rest[pos + base.len()..];
            let after = after.trim_start();
            if let Some(num_part) = after.strip_prefix('+') {
                let num_part = num_part.trim_start();
                let end = num_part
                    .find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                    .unwrap_or(num_part.len());
                let tok = &num_part[..end];
                if let Some(n) = parse_int_literal(tok)
                    && let Ok(signed) = i32::try_from(n)
                    && signed >= 16
                {
                    out.push(signed);
                }
            }
            rest = &rest[pos + base.len()..];
        }
    }
    out
}

fn extract_sp_offset(token: &str) -> Option<i32> {
    let s = token.trim_matches(|c| c == '[' || c == ']');
    let pos = s.find('+')?;
    let num = s[pos + 1..].trim();
    let val = if let Some(hex) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        num.parse::<u32>().ok()?
    };
    i32::try_from(val).ok()
}

fn is_fp_register(reg: &str) -> bool {
    let r = reg.to_ascii_lowercase();
    r.starts_with("xmm") || r.starts_with("ymm") || r.starts_with("zmm")
}

/// Heuristically classify an operand string into (writes, reads) register lists.
fn classify_operands(mnem: &str, operands: &str) -> (Vec<String>, Vec<String>) {
    let mut writes: Vec<String> = Vec::new();
    let mut reads: Vec<String> = Vec::new();
    let ops = operands.to_ascii_lowercase();

    // ── AT&T operand order ───────────────────────────────────────────────
    // These sign/zero-extend spellings exist ONLY in AT&T/GAS syntax (Intel
    // writes `movsx`/`movzx`/`movsxd`), so when we see one the operand order
    // is unambiguously AT&T: `src, dst` — the REVERSE of the Intel `dst, src`
    // assumed below.
    //
    // Reading them the Intel way is what produced the phantom parameter this
    // function's comment describes: for `movslq …, %rcx` the write was
    // credited to the SOURCE and `%rcx` was pushed into `reads`, so rcx looked
    // read-before-write and became `a1` in `_GetPEImageBase(__int64 a1)`.
    //
    // Only the unambiguous forms are swapped. `mov`/`add`/`movq`/… are spelled
    // identically in both syntaxes, so their order cannot be inferred from the
    // mnemonic and they keep the existing behaviour.
    const ATT_ONLY_EXTEND: &[&str] = &[
        "movslq", "movsbl", "movsbw", "movsbq", "movswl", "movswq",
        "movzbl", "movzbw", "movzbq", "movzwl", "movzwq",
    ];
    // The mnemonic alone cannot disambiguate `mov`/`add`/`xor`/… — but the
    // OPERAND SYNTAX can, and the disassembler feeding this crate emits AT&T.
    // AT&T marks registers with `%` and immediates with `$`; Intel uses bare
    // names. This is the same sigil test `split_two` in `lib.rs` already uses,
    // and it is what the win64 read-before-write path gets right.
    //
    // Without it, `mov $0x3E8, %ecx` — a pure WRITE of ecx — was read the Intel
    // way, crediting the write to `$0x3E8` and pushing `%ecx` into `reads`. The
    // register then looked read-before-write and became a phantom parameter.
    // Measured: this was the dominant cause of phantom params corpus-wide
    // (2794 of 8350 parameterised functions carried at least one).
    let looks_att = ops.contains('%') || ops.contains('$');
    let att_order = ATT_ONLY_EXTEND.contains(&mnem) || looks_att;
    let (dst_part, src_part) = match ops.split_once(',') {
        Some((a, b)) if att_order => (b.trim(), a.trim()),
        Some((a, b)) => (a.trim(), b.trim()),
        None => (ops.as_str(), ""),
    };

    // `xor %edx, %edx` / `sub %rax, %rax` — the idiomatic zeroing of a register
    // by itself. Architecturally these have NO input dependency (every x86
    // implementation special-cases the same-register form), so they are a pure
    // DEFINE. Counting the dest as a read here invented a parameter for any
    // function that merely zeroed an argument register before using it — which
    // is exactly what `__tmainCRTStartup` does with `xor %r8d, %r8d`.
    // (`win64_param_regs_live_in` and `simplify_xor_self` already model this.)
    if matches!(mnem, "xor" | "sub" | "xorl" | "xorq" | "subl" | "subq")
        && !dst_part.is_empty()
        && dst_part == src_part
    {
        let defined: Vec<String> =
            extract_register_tokens(dst_part).iter().flat_map(|r| write_alias_family(r)).collect();
        return (defined, Vec::new());
    }

    // `cmovCC` and `setCC` have an open-ended suffix set, so they are matched by
    // prefix rather than enumerated. Both WRITE their destination — missing
    // that left the register looking read-before-write, i.e. a phantom
    // parameter. (`setCC` writes only an 8-bit register, which
    // `write_alias_family` correctly refuses to expand to the 64-bit parent.)
    let is_cmov = mnem.starts_with("cmov");
    let is_setcc = mnem.starts_with("set") && mnem.len() <= 6;

    let mnem_writes_dst = is_cmov
        || is_setcc
        || matches!(
        att_size_stem(mnem),
        "mov" | "movq" | "movl" | "movw" | "movb" | "movzx" | "movsx"
            | "lea" | "add" | "sub" | "and" | "or" | "xor" | "shl"
            | "shr" | "imul" | "inc" | "dec" | "neg" | "not"
            | "movss" | "movsd" | "movaps" | "movups"
            // Measured as present in the corpus but absent from this list, each
            // one manufacturing phantom parameters:
            //   `movabs $0x5555555555555555, %rdx` — 64-bit immediate load,
            //   the witness that started this (a Go `OnesCount64` gained a
            //   phantom `a1` from it).
            //   `sar` — arithmetic shift; `shl`/`shr` were listed but not this.
            //   `pop` — writes its destination register.
            //   `rol`/`ror`, `xchg`, and the SSE `xorps`.
            | "movabs" | "sar" | "sal" | "rol" | "ror" | "pop" | "xchg" | "xorps"
            // AT&T sign/zero-extend forms (the disassembler emits these, NOT the
            // Intel `movsx`/`movzx`): all WRITE their register dest. Missing them
            // made a `movslq …, %rcx` temp read as live-in → a phantom parameter
            // (e.g. `_GetPEImageBase(__int64 a1)` with an unused a1). Class-1 bug.
            | "movslq" | "movsxd" | "movsbl" | "movsbw" | "movsbq"
            | "movswl" | "movswq" | "movzbl" | "movzbw" | "movzbq"
            | "movzwl" | "movzwq"
    );

    for tok in extract_register_tokens(dst_part) {
        if mnem_writes_dst {
            // A 32-bit write zero-extends, so it defines the 64-bit parent too
            // (and vice versa). See `write_alias_family`.
            writes.extend(write_alias_family(&tok));
        }
        // Many of the read-modify-write mnemonics also *read* the dest.
        // `cmovCC` belongs here too: when the condition is false the
        // destination keeps its previous value, so it is genuinely read.
        if is_cmov
            || matches!(
                att_size_stem(mnem),
                "add" | "sub" | "and" | "or" | "xor" | "shl" | "shr" | "imul"
                    | "inc" | "dec" | "neg" | "not" | "sar" | "sal" | "rol" | "ror" | "xchg"
            )
        {
            reads.push(tok);
        } else if !mnem_writes_dst {
            // cmp / test / push / call / jmp — operands are all read.
            reads.push(tok);
        }
    }

    for tok in extract_register_tokens(src_part) {
        reads.push(tok);
    }

    (writes, reads)
}

/// Pull register tokens out of an operand fragment.  Memory references like
/// `[rbp - 0x10]` contribute their base/index registers as reads.
/// Strip an AT&T operand-size suffix (`b`/`w`/`l`/`q`) when doing so yields a
/// mnemonic this module already knows.
///
/// GAS spells the same instruction `add`, `addl` or `addq` depending on operand
/// width. Enumerating every combination is error-prone — the corpus contains
/// `addl`, `addq`, `subl`, `incl`, `incq`, `decl` among others, and every one
/// that was missing from the writer list manufactured phantom parameters.
///
/// Only stems that are themselves recognised are accepted, so unrelated
/// mnemonics that merely end in one of those letters (`movsd`, `movsbl`, `mul`)
/// are left alone.
fn att_size_stem(mnem: &str) -> &str {
    const STEMS: &[&str] = &[
        "add", "sub", "and", "or", "xor", "shl", "shr", "sar", "sal", "inc", "dec", "neg", "not",
        "imul", "rol", "ror", "cmp", "test", "push", "pop", "mov", "lea", "xchg",
    ];
    if STEMS.contains(&mnem) {
        return mnem;
    }
    if let Some(stem) = mnem.strip_suffix(['b', 'w', 'l', 'q'])
        && STEMS.contains(&stem)
    {
        return stem;
    }
    mnem
}

/// The full alias family a WRITE to `reg` defines, `reg` itself included.
///
/// On x86-64 a 32-bit write ZERO-EXTENDS into the full 64-bit register, so
/// `xor %edx, %edx` fully defines `rdx`. The calling-convention detector
/// compares register names as plain strings, so without this it recorded only
/// `edx` as defined and then treated a later read of `%rdx` as read-before-
/// write — inventing a parameter. That is exactly how `_GetPEImageBase`, whose
/// published prototype takes VOID, came out taking one.
///
/// 8- and 16-bit writes are deliberately NOT expanded: they leave the upper
/// bits untouched, so they do not define the parent and the incoming value can
/// still be live.
fn write_alias_family(reg: &str) -> Vec<String> {
    const FAMILIES: &[(&str, &str, &str)] = &[
        ("rax", "eax", "ax"),
        ("rbx", "ebx", "bx"),
        ("rcx", "ecx", "cx"),
        ("rdx", "edx", "dx"),
        ("rsi", "esi", "si"),
        ("rdi", "edi", "di"),
        ("rbp", "ebp", "bp"),
        ("rsp", "esp", "sp"),
    ];
    for (q, d, _w) in FAMILIES {
        if reg == *q || reg == *d {
            return vec![(*q).to_string(), (*d).to_string()];
        }
    }
    // r8..r15: `r8d` is the 32-bit half of `r8`.
    if let Some(base) = reg.strip_suffix('d')
        && base.starts_with('r')
        && base[1..].parse::<u8>().is_ok_and(|n| (8..=15).contains(&n))
    {
        return vec![base.to_string(), reg.to_string()];
    }
    if reg.starts_with('r')
        && reg[1..].parse::<u8>().is_ok_and(|n| (8..=15).contains(&n))
    {
        return vec![reg.to_string(), format!("{reg}d")];
    }
    vec![reg.to_string()]
}

fn extract_register_tokens(part: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in part.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if raw.is_empty() {
            continue;
        }
        if is_known_register(raw) {
            out.push(raw.to_ascii_lowercase());
        }
    }
    out
}

fn is_known_register(tok: &str) -> bool {
    let t = tok.to_ascii_lowercase();
    matches!(
        t.as_str(),
        // x86_64 GP
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp"
        | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
        // x86 32-bit
        | "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
        | "r8d" | "r9d" | "r10d" | "r11d" | "r12d" | "r13d" | "r14d" | "r15d"
        // x86 16/8-bit (best-effort: collapse onto parents at later stage)
        | "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp"
        | "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh"
        // ARM64
        | "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7"
        | "x8" | "x9" | "x10" | "x11" | "x12" | "x13" | "x14" | "x15"
        | "x16" | "x17" | "x18" | "x19" | "x20" | "x21" | "x22" | "x23"
        | "x24" | "x25" | "x26" | "x27" | "x28" | "x29" | "x30" | "wsp" | "xzr" | "wzr"
    ) || t.starts_with("xmm")
        || t.starts_with("ymm")
        || t.starts_with("zmm")
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level façade used by passes
// ─────────────────────────────────────────────────────────────────────────────

/// Run inference on a `(mnemonic, operands)` stream and return both the
/// detector verdict and a free-form label compatible with
/// `PassContext::calling_convention`.
#[must_use]
pub fn detect_with_label(
    raw_mnemonics: &[(u64, String, String)],
    is_pe: bool,
    arch: &str,
) -> Option<(String, CallConvInference)> {
    if raw_mnemonics.is_empty() {
        return None;
    }
    let lifted = lift_mnemonic_stream(
        raw_mnemonics
            .iter()
            .map(|(_, m, o)| (m.as_str(), o.as_str())),
    );
    let inference = detect(&lifted, &arch_from_str(arch), &os_from_pe_flag(is_pe)).ok()?;
    let label = label_from_pattern(&inference.pattern);
    Some((label, inference))
}

/// Map a [`CallingConventionPattern`] to the string label used by the
/// downstream `VariableRecoveryPass` (`"Windows_x64"`, `"SysV_AMD64"`, `"ARM64"`,
/// `"Unknown"`).
#[must_use]
pub fn label_from_pattern(pattern: &CallingConventionPattern) -> String {
    let name = pattern.name.to_ascii_lowercase();
    if name.contains("microsoft x64") || name.contains("ms_x64") || name.contains("vectorcall") {
        "Windows_x64".to_string()
    } else if name.contains("system v") || name.contains("sysv") {
        // System V x86-32 and AMD64 share the "system v" name; disambiguate by
        // width so the 32-bit variant maps onto the cdecl-compatible label.
        if name.contains("x86") && !name.contains("64") {
            "Cdecl".to_string()
        } else {
            "SysV_AMD64".to_string()
        }
    } else if name.contains("aapcs64") {
        "ARM64".to_string()
    } else if name.contains("thiscall") {
        "Thiscall".to_string()
    } else if name.contains("fastcall") {
        "Fastcall".to_string()
    } else if name.contains("stdcall") {
        "Stdcall".to_string()
    } else if name.contains("cdecl") {
        "Cdecl".to_string()
    } else {
        pattern.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_push_produces_push() {
        let v = lift_mnemonic("push", "rbp");
        assert!(matches!(v.as_slice(), [DetectInstr::Push { reg }] if reg == "rbp"));
    }

    #[test]
    fn lift_ret_zero() {
        let v = lift_mnemonic("ret", "");
        assert!(matches!(v.as_slice(), [DetectInstr::Ret { stack_bytes: 0 }]));
    }

    #[test]
    fn lift_ret_n() {
        let v = lift_mnemonic("retn", "0x10");
        assert!(matches!(v.as_slice(), [DetectInstr::Ret { stack_bytes: 16 }]));
    }

    #[test]
    fn lift_sub_rsp_stackalloc() {
        let v = lift_mnemonic("sub", "rsp, 0x20");
        assert!(matches!(v.as_slice(), [DetectInstr::StackAlloc { bytes: 32 }]));
    }

    #[test]
    fn lift_mov_writes_dst_reads_src() {
        let v = lift_mnemonic("mov", "rax, rcx");
        let writes_rax = v
            .iter()
            .any(|d| matches!(d, DetectInstr::RegWrite { reg } if reg == "rax"));
        let reads_rcx = v
            .iter()
            .any(|d| matches!(d, DetectInstr::RegRead { reg } if reg == "rcx"));
        assert!(writes_rax);
        assert!(reads_rcx);
    }

    #[test]
    fn ms_x64_two_args_detected() {
        // push rbp ; mov rbp, rsp ; mov [rbp-8], rcx ; mov [rbp-16], rdx ; pop rbp ; ret
        let stream: Vec<(&str, &str)> = vec![
            ("push", "rbp"),
            ("mov", "rbp, rsp"),
            ("mov", "[rbp-8], rcx"),
            ("mov", "[rbp-16], rdx"),
            ("pop", "rbp"),
            ("ret", ""),
        ];
        let lifted = lift_mnemonic_stream(stream.iter().copied());
        let inf = detect(&lifted, &Arch::X86_64, &Os::Windows).expect("detect");
        assert!(inf.pattern.name.to_ascii_lowercase().contains("microsoft"));
        // Expect rcx + rdx as parameter registers.
        assert!(inf.params.iter().any(|p| p.register.as_deref() == Some("rcx")));
        assert!(inf.params.iter().any(|p| p.register.as_deref() == Some("rdx")));
    }

    #[test]
    fn sysv_two_args_detected() {
        let stream: Vec<(&str, &str)> = vec![
            ("push", "rbp"),
            ("mov", "rbp, rsp"),
            ("mov", "[rbp-8], rdi"),
            ("mov", "[rbp-16], rsi"),
            ("pop", "rbp"),
            ("ret", ""),
        ];
        let lifted = lift_mnemonic_stream(stream.iter().copied());
        let inf = detect(&lifted, &Arch::X86_64, &Os::Linux).expect("detect");
        assert!(inf.pattern.name.to_ascii_lowercase().contains("system v"));
        assert!(inf.params.iter().any(|p| p.register.as_deref() == Some("rdi")));
        assert!(inf.params.iter().any(|p| p.register.as_deref() == Some("rsi")));
    }

    #[test]
    fn label_from_msvc() {
        let pat = rustre_analysis_callconv::msvc_x64();
        assert_eq!(label_from_pattern(&pat), "Windows_x64");
    }

    #[test]
    fn label_from_sysv() {
        let pat = rustre_analysis_callconv::sysv_x64();
        assert_eq!(label_from_pattern(&pat), "SysV_AMD64");
    }

    #[test]
    fn label_from_x86_abis() {
        assert_eq!(label_from_pattern(&rustre_analysis_callconv::cdecl_x86()), "Cdecl");
        assert_eq!(label_from_pattern(&rustre_analysis_callconv::stdcall_x86()), "Stdcall");
        assert_eq!(label_from_pattern(&rustre_analysis_callconv::fastcall_x86()), "Fastcall");
        assert_eq!(label_from_pattern(&rustre_analysis_callconv::thiscall_x86()), "Thiscall");
    }

    #[test]
    fn fastcall_x86_detected() {
        // 32-bit fastcall: first two integer args arrive in ecx, edx.
        let stream: Vec<(&str, &str)> = vec![
            ("push", "ebp"),
            ("mov", "ebp, esp"),
            ("mov", "[ebp-4], ecx"),
            ("mov", "[ebp-8], edx"),
            ("pop", "ebp"),
            ("ret", ""),
        ];
        let lifted = lift_mnemonic_stream(stream.iter().copied());
        let inf = detect(&lifted, &Arch::X86, &Os::Windows).expect("detect x86");
        // ecx/edx should surface as parameter registers regardless of which
        // register-based x86 ABI wins the scoring.
        assert!(inf.params.iter().any(|p| p.register.as_deref() == Some("ecx")));
    }

    #[test]
    fn att_immediate_store_is_a_write_not_a_read() {
        // `mov $0x3E8, %ecx` WRITES ecx. Read the Intel way it looked like a
        // read of ecx and invented a phantom `a1`.
        let (writes, reads) = classify_operands("mov", "$0x3E8, %ecx");
        assert!(writes.iter().any(|w| w == "ecx"), "writes={writes:?}");
        assert!(!reads.iter().any(|r| r == "ecx"), "ecx must not be a read: reads={reads:?}");
    }

    #[test]
    fn att_register_move_writes_the_second_operand() {
        let (writes, reads) = classify_operands("mov", "%rax, %rbx");
        assert!(writes.iter().any(|w| w == "rbx"), "writes={writes:?}");
        assert!(reads.iter().any(|r| r == "rax"), "reads={reads:?}");
        assert!(!writes.iter().any(|w| w == "rax"), "source must not be written");
    }

    #[test]
    fn intel_order_still_works_without_sigils() {
        // No `%`/`$` — Intel spelling, destination first. Must not regress.
        let (writes, reads) = classify_operands("mov", "rbx, rax");
        assert!(writes.iter().any(|w| w == "rbx"), "writes={writes:?}");
        assert!(reads.iter().any(|r| r == "rax"), "reads={reads:?}");
    }

    #[test]
    fn self_zeroing_xor_is_a_pure_define() {
        // `xor %r8d, %r8d` has no input dependency — it must not read r8d.
        let (writes, reads) = classify_operands("xor", "%r8d, %r8d");
        assert!(writes.iter().any(|w| w == "r8d"), "writes={writes:?}");
        assert!(reads.is_empty(), "self-zeroing must read nothing: reads={reads:?}");
    }

    #[test]
    fn thirty_two_bit_write_defines_the_sixty_four_bit_parent() {
        // `xor %edx, %edx` zero-extends into rdx, so a LATER read of `%rdx` is
        // not read-before-write. Missing this gave `_GetPEImageBase` — a VOID
        // function — a phantom `a1`.
        let (writes, _r) = classify_operands("xor", "%edx, %edx");
        assert!(writes.iter().any(|w| w == "edx"), "writes={writes:?}");
        assert!(writes.iter().any(|w| w == "rdx"), "must define the parent: {writes:?}");
    }

    #[test]
    fn r8d_write_defines_r8() {
        let (writes, _r) = classify_operands("xor", "%r8d, %r8d");
        assert!(writes.iter().any(|w| w == "r8"), "writes={writes:?}");
    }

    #[test]
    fn movabs_writes_its_destination() {
        // The witness: a Go `OnesCount64` gained a phantom param because
        // `movabs $imm64, %rdx` was not recognised as writing rdx.
        let (writes, reads) = classify_operands("movabs", "$0x5555555555555555, %rdx");
        assert!(writes.iter().any(|w| w == "rdx"), "writes={writes:?}");
        assert!(!reads.iter().any(|r| r == "rdx"), "reads={reads:?}");
    }

    #[test]
    fn att_size_suffixed_arithmetic_is_recognised() {
        assert_eq!(att_size_stem("addl"), "add");
        assert_eq!(att_size_stem("subq"), "sub");
        assert_eq!(att_size_stem("incq"), "inc");
        // Must NOT mangle unrelated mnemonics that happen to end in b/w/l/q.
        assert_eq!(att_size_stem("movsd"), "movsd");
        assert_eq!(att_size_stem("movsbl"), "movsbl");
        assert_eq!(att_size_stem("mul"), "mul");
        let (writes, _r) = classify_operands("addl", "$4, %edx");
        assert!(writes.iter().any(|w| w == "edx"), "writes={writes:?}");
    }

    #[test]
    fn pop_and_cmov_and_setcc_write_their_destination() {
        let (w1, _) = classify_operands("pop", "%rbx");
        assert!(w1.iter().any(|w| w == "rbx"), "pop writes: {w1:?}");

        // cmov writes AND reads its destination.
        let (w2, r2) = classify_operands("cmove", "%rax, %rdx");
        assert!(w2.iter().any(|w| w == "rdx"), "cmov writes: {w2:?}");
        assert!(r2.iter().any(|r| r == "rdx"), "cmov also reads dest: {r2:?}");

        let (w3, _) = classify_operands("sete", "%al");
        assert!(w3.iter().any(|w| w == "al"), "setcc writes: {w3:?}");
        assert!(!w3.iter().any(|w| w == "rax"), "8-bit write must not define rax: {w3:?}");
    }

    #[test]
    fn sar_writes_and_reads_its_destination() {
        let (w, r) = classify_operands("sar", "$2, %rcx");
        assert!(w.iter().any(|x| x == "rcx"), "writes={w:?}");
        assert!(r.iter().any(|x| x == "rcx"), "shift reads its dest: {r:?}");
    }

    #[test]
    fn eight_bit_write_does_not_define_the_parent() {
        // `mov $1, %al` leaves the upper 56 bits of rax intact — the incoming
        // value stays live, so rax must NOT be marked defined.
        let (writes, _r) = classify_operands("mov", "$1, %al");
        assert!(!writes.iter().any(|w| w == "rax"), "partial write must not define rax: {writes:?}");
    }

    #[test]
    fn xor_of_two_different_registers_still_reads_both() {
        let (_writes, reads) = classify_operands("xor", "%rax, %rbx");
        assert!(reads.iter().any(|r| r == "rax"), "reads={reads:?}");
        assert!(reads.iter().any(|r| r == "rbx"), "read-modify-write reads dest: {reads:?}");
    }

    // ── stack_cleanup ────────────────────────────────────────────────────
    // `ret N` is an EXACT fact: N / pointer_size is the stack-argument count.

    #[test]
    fn stack_cleanup_reads_ret_n_as_an_exact_arg_count() {
        // 32-bit stdcall: `ret 0xC` pops three 4-byte stack arguments.
        let instrs = lift_mnemonic_stream([("push", "ebp"), ("pop", "ebp"), ("ret", "0xC")]);
        assert_eq!(stack_cleanup(&instrs, 4), Some(3));
    }

    #[test]
    fn stack_cleanup_is_none_for_plain_ret() {
        // A caller-cleans function (`ret` with no operand) yields no evidence.
        let instrs = lift_mnemonic_stream([("push", "rbp"), ("pop", "rbp"), ("ret", "")]);
        assert_eq!(stack_cleanup(&instrs, 8), None);
    }

    #[test]
    fn stack_cleanup_rejects_illegal_pointer_size() {
        // Must not reach the analyzer's `assert!` on pointer_size.
        let instrs = lift_mnemonic_stream([("ret", "8")]);
        assert_eq!(stack_cleanup(&instrs, 3), None);
        assert_eq!(stack_cleanup(&instrs, 0), None);
    }

    #[test]
    fn stack_cleanup_on_empty_stream_is_none() {
        assert_eq!(stack_cleanup(&[], 8), None);
    }
}
