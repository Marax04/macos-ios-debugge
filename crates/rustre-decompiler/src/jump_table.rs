//! Jump-table (dense `switch`) detection from the classic bounds-checked
//! indirect-jump idiom emitted by C compilers.
//!
//! The canonical shape on x86 is:
//!
//! ```text
//!     cmp   eax, 5            ; index bound check (N = highest case value)
//!     ja    default_label     ; unsigned-above  -> out of range -> default
//!     jmp   [table + eax*4]   ; indirect jump through the table
//! ```
//!
//! On x86-64 the stride is typically 8 and a RIP-relative base is common. This
//! module performs **pure analysis** over an instruction slice: it recognises
//! the idiom and extracts the structured [`JumpTableInfo`]. It does not read the
//! table bytes or mutate any CFG — those steps consume this result downstream.

use rustre_core::arch::Instruction;

/// Structured description of a detected jump table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTableInfo {
    /// Register used as the switch index (e.g. `"eax"`), lower-cased.
    pub index: String,
    /// Number of dense cases: `bound + 1` from the `cmp index, bound`.
    pub case_count: u32,
    /// Absolute address of the table base, when a literal displacement is present.
    pub table_addr: Option<u64>,
    /// Byte stride between table entries, taken from the index scale (`*4` -> 4).
    pub entry_size: u32,
    /// Address of the default branch target (the out-of-range `ja`/`jae`/`jg`).
    pub default_target: Option<u64>,
    /// Address of the indirect `jmp` instruction itself.
    pub jump_addr: u64,
    /// Addresses of the table-arithmetic instructions (`lea` / `mov` / `add`)
    /// that exist only to compute the indirect jump target, and so become dead
    /// once the `switch` is materialized on the raw index register.
    ///
    /// The lifter skips these, which is what keeps the index register holding
    /// the *index* (rather than the computed target address) at the `switch`.
    /// Empty for the memory-indirect `jmp [base+idx*scale]` form, where the
    /// jump reads the table directly and nothing is dead.
    pub arith_addrs: Vec<u64>,
    /// Base address the 4-byte entries are relative to, when it is NOT the
    /// table itself: the `lea code,[rip+d]; add code,tgt` two-lea form (.NET
    /// AOT / MSVC profile-guided layout) computes `target = code_base +
    /// (u32)table[idx]`. `None` for every other encoding.
    pub code_base: Option<u64>,
}

/// Scan `instructions` for the bounds-checked indirect-jump idiom and return the
/// first jump table found, if any.
#[must_use]
pub fn detect_jump_table(instructions: &[Instruction]) -> Option<JumpTableInfo> {
    let view: Vec<(u64, &str, &str)> = instructions
        .iter()
        .map(|ins| (ins.address.as_u64(), ins.mnemonic.as_str(), ins.operands.as_str()))
        .collect();
    detect_core(&view)
}

/// Same as [`detect_jump_table`] but over the decompiler's raw
/// `(address, mnemonic, operands)` triples, as carried on `PassContext`.
#[must_use]
pub fn detect_jump_table_raw(raw: &[(u64, String, String)]) -> Option<JumpTableInfo> {
    let view: Vec<(u64, &str, &str)> = raw
        .iter()
        .map(|(a, m, o)| (*a, m.as_str(), o.as_str()))
        .collect();
    detect_core(&view)
}

/// Scan `instructions` for EVERY bounds-checked indirect-jump idiom, in
/// address order. [`detect_jump_table`] stops at the first hit; real
/// functions can lower several `switch` statements. Each scan resumes just
/// past the previous indirect `jmp`.
#[must_use]
pub fn detect_all_jump_tables(instructions: &[Instruction]) -> Vec<JumpTableInfo> {
    let view: Vec<(u64, &str, &str)> = instructions
        .iter()
        .map(|ins| (ins.address.as_u64(), ins.mnemonic.as_str(), ins.operands.as_str()))
        .collect();
    let mut out = Vec::new();
    let mut from = 0usize;
    while from < view.len() {
        let Some(info) = detect_core(&view[from..]) else {
            // `detect_core` anchors on the FIRST indirect jump in the slice. A
            // miss means THAT jump is not a table (a genuine virtual dispatch
            // such as `jmp *0x18(%rax)`), NOT that the function holds no more
            // tables — so skip past it and keep scanning instead of aborting.
            // Bailing here lost every switch that followed a virtual dispatch.
            let Some(next) = view[from..].iter().position(|&(_, m, o)| is_indirect_jmp(m, o))
            else {
                break;
            };
            from += next + 1;
            continue;
        };
        let Some(pos) = view[from..].iter().position(|&(a, _, _)| a == info.jump_addr) else {
            break;
        };
        from += pos + 1;
        out.push(info);
    }
    out
}


/// Core detection over `(address, mnemonic, operands)` items.
fn detect_core(items: &[(u64, &str, &str)]) -> Option<JumpTableInfo> {
    for (i, &(addr, mnem, ops)) in items.iter().enumerate() {
        if !is_indirect_jmp(mnem, ops) {
            continue;
        }
        // MSVC/x64 register-indirect form: `lea base,[rip+table];
        // movslq (base,idx,4),tgt; add base,tgt; jmp *tgt`. The jump goes
        // through a register, so the table base lives in a preceding `lea`,
        // not the jump operand. Recognised by a dedicated backward match.
        if (att_reg(ops).is_some() || is_register(ops))
            && let Some(info) = detect_reg_indirect_msvc(items, i)
        {
            return Some(info);
        }
        // Go/gc memory-indirect form: `and $MASK,%idx; lea tbl(%rip),%b;
        // jmpq *(%b,%idx,8)` — the jump reads an Abs64 table whose base
        // register comes from a preceding RIP-lea, and the bound is a
        // power-of-two AND mask (no cmp/ja default).
        if let Some(info) = detect_reg_base_mem_indirect(items, i) {
            return Some(info);
        }
        let (mem_index, scale, table_addr) = parse_indirect_target(ops);

        // Walk backwards a short window for the bound check and its branch.
        let mut case_count: Option<u32> = None;
        let mut index: Option<String> = mem_index;
        let mut default_target: Option<u64> = None;
        let start = i.saturating_sub(BOUND_LOOKBACK);
        for &(_, pmnem, pops) in items[start..i].iter().rev() {
            let m = pmnem.trim().to_ascii_lowercase();
            if is_bound_branch(&m) && default_target.is_none() {
                default_target = parse_branch_target(pops);
            }
            if (m == "cmp" || m == "sub") && case_count.is_none()
                && let Some((lhs, bound)) = parse_cmp_bound(pops)
            {
                case_count = bound.checked_add(1);
                // PREFER the bound-check register as the scrutinee, even if a SIB
                // index register was already found. The range check tests the
                // actual switch VALUE (`op`), which is pristine; the SIB index
                // register often IS the same storage that the table load then
                // overwrites (`movslq (%rax,%r9,4), %r9`), so using it makes the
                // scrutinee a clobbered, never-reassigned `v3`
                // (`switch (v3)` — an uninitialised read). Only overwrite with a
                // real register spelling.
                if is_register(&lhs) {
                    index = Some(lhs);
                }
            }
        }

        let index = index?;
        let case_count = case_count?;
        return Some(JumpTableInfo {
            index,
            case_count,
            table_addr,
            entry_size: scale.unwrap_or(DEFAULT_ENTRY_SIZE),
            default_target,
            jump_addr: addr,
            // The `jmp [base+idx*scale]` form reads the table itself; there is
            // no separate arithmetic to retire.
            arith_addrs: Vec::new(),
            code_base: None,
        });
    }
    None
}

/// How many instructions before the indirect jump to search for the bound check.
const BOUND_LOOKBACK: usize = 8;
/// Fallback entry size when the scale cannot be read (x86-32 default).
const DEFAULT_ENTRY_SIZE: u32 = 4;

fn is_indirect_jmp(mnemonic: &str, operands: &str) -> bool {
    let m = mnemonic.trim().to_ascii_lowercase();
    if m != "jmp" && m != "jmpq" {
        return false;
    }
    let ops = operands.trim();
    // Indirect through memory (`jmp [..]`, `jmp (%..)`, `jmp dword ptr [..]`)
    // or through a register (Intel `jmp rax`, AT&T `jmp *%rax`). A direct
    // `jmp 0x401000` / `jmp label` is not a table.
    ops.contains('[')
        || is_register(ops)
        || att_reg(ops).is_some()
        // AT&T memory-indirect through a SIB: `jmpq *(%rdx,%rcx,8)`.
        || (ops.starts_with('*') && ops.contains('('))
}

/// Strip AT&T indirect/register sigils and return the canonical 64-bit
/// register name: `"*%rax"`/`"%rax"`/`"rax"`/`"*%eax"` → `Some("rax")`.
/// Returns `None` for memory operands or non-registers.
fn att_reg(operand: &str) -> Option<String> {
    let t = operand.trim().trim_start_matches('*').trim_start_matches('%').trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if is_register(t) {
        Some(canon_reg(t))
    } else {
        None
    }
}

/// Map a width alias to its canonical 64-bit register name so `eax`/`ax`/`al`
/// all compare equal to `rax`. Unknown tokens pass through lower-cased.
/// #8730 - delega alla FONTE UNICA. La versione locale non conosceva
/// `ah`/`bh`/`ch`/`dh`, che `register_canonical` mappa correttamente.
fn canon_reg(tok: &str) -> String {
    let t = tok.trim().trim_start_matches('%');
    crate::x86_register_width::register_canonical(t)
}

/// Split a two-operand instruction into `(src, dst)` at the top-level comma
/// (commas inside `(...)` memory operands are ignored). AT&T order is
/// `src, dst`, which is what this returns.
fn att_split(operands: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (i, c) in operands.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                return Some((operands[..i].trim(), operands[i + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

/// Parse an AT&T memory operand `disp(%base,%idx,scale)` (disp optional) into
/// `(base_canon, idx_canon, scale)`.
fn att_mem(operand: &str) -> Option<(String, String, u32)> {
    let open = operand.find('(')?;
    let close = operand.rfind(')')?;
    if close <= open {
        return None;
    }
    // A nonzero displacement before the `(` would shift the effective table
    // base away from the `lea` address, silently mis-decoding every entry.
    // Only a bare or explicitly-zero displacement is a clean table load.
    let disp = operand[..open].trim();
    if !disp.is_empty() && disp != "0" && disp != "0x0" {
        return None;
    }
    let inner = &operand[open + 1..close];
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    if parts.len() != 3 {
        return None;
    }
    let base = att_reg(parts[0])?;
    let idx = att_reg(parts[1])?;
    let scale = parts[2].parse::<u32>().ok()?;
    Some((base, idx, scale))
}

/// Parse an AT&T RIP-relative displacement `disp(%rip)` → signed `disp`.
fn att_rip_disp(operand: &str) -> Option<i64> {
    let open = operand.find('(')?;
    let inner = &operand[open + 1..operand.rfind(')')?];
    if inner.trim() != "%rip" {
        return None;
    }
    let disp = operand[..open].trim();
    let (neg, body) = disp
        .strip_prefix('-')
        .map_or((false, disp), |r| (true, r));
    let v = parse_u64_literal(body)? as i64;
    Some(if neg { -v } else { v })
}

/// Parse an AT&T immediate `$0x5` / `$5` → its value.
fn att_imm(operand: &str) -> Option<u64> {
    parse_u64_literal(operand.trim().strip_prefix('$')?)
}

/// Recognise the Go/gc memory-indirect jump-table idiom: `jmpq
/// *(%base,%idx,scale)` where `%base` holds a RIP-lea'd table address and the
/// index is bounded by an AND mask (`and $2^k-1, %idx`) or a `cmp`/`ja` pair.
/// The jump reads the table directly, so only the `lea` is retirable.
fn detect_reg_base_mem_indirect(items: &[(u64, &str, &str)], i: usize) -> Option<JumpTableInfo> {
    let (jump_addr, _, jops) = items[i];
    let (base, index, scale) = att_mem(jops.trim().trim_start_matches('*'))?;
    if scale != 4 && scale != 8 {
        return None;
    }
    let start = i.saturating_sub(REG_INDIRECT_LOOKBACK);

    // `lea disp(%rip), %base` — the table address, before the jump. Reject a
    // clobber of `base` between the lea and the jump.
    let mut table_addr: Option<u64> = None;
    let mut lea_k: Option<usize> = None;
    for k in (start..i).rev() {
        let (_, m, o) = items[k];
        if let Some((_, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(base.as_str())
        {
            if m.trim().eq_ignore_ascii_case("lea")
                && let Some(disp) = att_rip_disp(att_split(o)?.0)
            {
                let next_addr = items.get(k + 1).map_or(jump_addr, |n| n.0);
                table_addr = Some(next_addr.wrapping_add_signed(disp));
                lea_k = Some(k);
            }
            break;
        }
    }
    let table_addr = table_addr?;

    // Bound: nearest `and $M,%idx` with a dense power-of-two mask (Go's
    // preferred guard: the masked index is in-range by construction, no
    // default branch), else a `cmp $N,%idx` + `ja` pair.
    let mut case_count: Option<u32> = None;
    let mut default_target: Option<u64> = None;
    for &(_, m, o) in items[start..i].iter().rev() {
        let ml = m.trim().to_ascii_lowercase();
        if is_bound_branch(&ml) && default_target.is_none() {
            default_target = parse_branch_target(o);
        }
        if case_count.is_none()
            && matches!(ml.as_str(), "and" | "andl" | "andq" | "cmp" | "cmpl" | "cmpq")
            && let Some((s, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(index.as_str())
            && let Some(n) = att_imm(s)
        {
            if ml.starts_with("and") {
                // Mask must be dense (2^k - 1) for `count = mask + 1` to be
                // the exact case count.
                let count = u32::try_from(n).ok()?.checked_add(1)?;
                if !count.is_power_of_two() {
                    return None;
                }
                case_count = Some(count);
            } else {
                case_count = u32::try_from(n).ok().and_then(|v| v.checked_add(1));
            }
        }
    }
    let case_count = case_count?;
    if case_count > MAX_RESOLVED_CASES {
        return None;
    }

    // Only the lea is dead once the switch reads the index directly — and only
    // when nothing after the jump mentions the base register.
    let mut arith_addrs = Vec::new();
    if let Some(k) = lea_k
        && !reg_mentioned_after(items, i, &base)
    {
        arith_addrs.push(items[k].0);
    }

    Some(JumpTableInfo {
        index,
        case_count,
        table_addr: Some(table_addr),
        entry_size: scale,
        default_target,
        jump_addr,
        arith_addrs,
        code_base: None,
    })
}

/// Recognise the MSVC/x64 register-indirect jump-table idiom by walking
/// backward from the indirect `jmp *reg` at `items[i]`:
/// `lea disp(%rip),%base` → `movslq (%base,%idx,4),%tgt` → `add %base,%tgt`
/// → `cmp $N,%idx` / `ja default`. The table base is `next_addr(lea)+disp`
/// and entries are signed 32-bit offsets from that base (Rel32TableBase).
fn detect_reg_indirect_msvc(items: &[(u64, &str, &str)], i: usize) -> Option<JumpTableInfo> {
    let (jump_addr, _, jops) = items[i];
    let jr = att_reg(jops)?;
    let start = i.saturating_sub(REG_INDIRECT_LOOKBACK);

    // `add %base, %jr` (dst == jr) — nearest to the jump. Record its position
    // so the load and the lea are constrained to execute strictly before it.
    let mut add_k: Option<usize> = None;
    let mut base_reg: Option<String> = None;
    for k in (start..i).rev() {
        let (_, m, o) = items[k];
        if m.trim().eq_ignore_ascii_case("add")
            && let Some((s, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(jr.as_str())
        {
            base_reg = att_reg(s);
            add_k = Some(k);
            break;
        }
    }
    let base = base_reg?;
    let add_k = add_k?;

    // `mov*/movslq (%base, %idx, scale), %jr` — the table load, BEFORE the add
    // (else the add's result is dead and the jump target is the raw load).
    let mut mov_k: Option<usize> = None;
    let mut idx: Option<String> = None;
    let mut scale: Option<u32> = None;
    // Register the table load indexes through. In the classic form it is the
    // `add` source (`base`); in the two-lea form (`lea tbl,[rip+d]; mov
    // (tbl,idx,4),tgt; lea code,[rip+d2]; add code,tgt`) the load's base is
    // the jump register itself, clobbered by its own load.
    let mut load_base: Option<String> = None;
    for k in (start..add_k).rev() {
        let (_, m, o) = items[k];
        let ml = m.trim().to_ascii_lowercase();
        if (ml.starts_with("mov") || ml == "movslq" || ml == "movsxd")
            && let Some((s, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(jr.as_str())
            && let Some((mb, mi, ms)) = att_mem(s)
            && (mb == base || mb == jr)
        {
            idx = Some(mi);
            scale = Some(ms);
            load_base = Some(mb);
            mov_k = Some(k);
            break;
        }
    }
    let index = idx.clone()?;
    let entry_size = scale?;
    let mov_k = mov_k?;
    let load_base = load_base?;

    // Two-lea form: the `add` source is a separate RIP-lea'd CODE base and the
    // table lives in a lea to the load's own base register. Resolve both; the
    // entries are then u32 offsets from `code_base`, not from the table.
    let mut code_base: Option<u64> = None;
    if load_base != base {
        for k in (mov_k..i).rev() {
            let (_, m, o) = items[k];
            if m.trim().eq_ignore_ascii_case("lea")
                && let Some((s, d)) = att_split(o)
                && att_reg(d).as_deref() == Some(base.as_str())
                && let Some(disp) = att_rip_disp(s)
            {
                let next_addr = items.get(k + 1).map_or(items[i].0, |n| n.0);
                code_base = Some(next_addr.wrapping_add_signed(disp));
                break;
            }
        }
        // Without a resolvable code base the entries cannot be decoded.
        code_base?;
    }

    // `lea disp(%rip), %load_base` — the table base, BEFORE the load. (In the
    // classic form `load_base == base`; in the two-lea form it is `jr`.)
    let mut table_addr: Option<u64> = None;
    let mut lea_k: Option<usize> = None;
    for k in (start..mov_k).rev() {
        let (_, m, o) = items[k];
        if m.trim().eq_ignore_ascii_case("lea")
            && let Some((s, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(load_base.as_str())
            && let Some(disp) = att_rip_disp(s)
        {
            // RIP value = address of the instruction AFTER the lea.
            let next_addr = items.get(k + 1).map_or(items[i].0, |n| n.0);
            table_addr = Some(next_addr.wrapping_add_signed(disp));
            lea_k = Some(k);
            break;
        }
    }

    // Bound check + the `ja`/`jae` default. The compared register must be the
    // switch index (or a stack reg is explicitly excluded): a bare "nearest
    // cmp/sub-imm" would match an unrelated `sub $0x28,%rsp` stack adjust or a
    // sibling loop's compare, silently fabricating the case count. Prefer a
    // `cmp $N,%idx`; fall back to the nearest non-stack `cmp` (covers the
    // `mov %r8,%rbx; cmp $N,%r8` copy case where the compared reg was later
    // copied into the table index).
    let idx_canon = index.as_str();
    let mut case_from_idx: Option<u32> = None;
    let mut case_fallback: Option<u32> = None;
    // Register named by the fallback `cmp $N, %reg` bound check. When the SIB
    // index register is the SAME as the jump register (`movslq (%b,%idx,4),
    // %idx` — the load overwrites its own index), the pristine switch value
    // lives in this bound-checked register instead, and using it as the
    // scrutinee avoids the clobbered `switch (v3)`.
    let mut fallback_reg: Option<String> = None;
    // `cmp $N, MEM` (memory-operand bound check): GCC frequently compares the
    // switch value in memory and then reloads it into the index register, so the
    // bound never names the index register directly. Recorded with the compared
    // memory operand for correlation below.
    let mut case_mem: Option<(u32, String)> = None;
    // `and $2^k-1,%idx` mask bound. The masked index is in range by
    // construction, so this form carries NO default branch and no `cmp` — the
    // reason every masked switch fell through to `JUMPOUT`. Same rule already
    // used by `detect_reg_base_mem_indirect`: only a DENSE mask gives an exact
    // count, a sparse one is rejected rather than guessed at.
    let mut case_from_mask: Option<u32> = None;
    let mut default_target: Option<u64> = None;
    for &(_, m, o) in items[start..i].iter().rev() {
        let ml = m.trim().to_ascii_lowercase();
        if is_bound_branch(&ml) && default_target.is_none() {
            default_target = parse_branch_target(o);
        }
        if case_from_mask.is_none()
            && matches!(ml.as_str(), "and" | "andl" | "andq")
            && let Some((s, d)) = att_split(o)
            && att_reg(d).as_deref() == Some(idx_canon)
            && let Some(n) = att_imm(s)
            && let Some(count) = u32::try_from(n).ok().and_then(|v| v.checked_add(1))
            && count.is_power_of_two()
        {
            case_from_mask = Some(count);
        }
        // Accept AT&T size-suffixed spellings (`cmpl`/`cmpq`/`cmpb`/`cmpw`);
        // the assembler adds the suffix whenever an operand size is ambiguous,
        // which it always is for the memory-operand bound check `cmpl $N,(%r)`.
        if matches!(ml.as_str(), "cmp" | "cmpl" | "cmpq" | "cmpb" | "cmpw")
            && let Some((s, d)) = att_split(o)
            && let Some(n) = att_imm(s)
            && let Some(count) = u32::try_from(n).ok().and_then(|v| v.checked_add(1))
        {
            let creg = att_reg(d);
            if creg.as_deref() == Some(idx_canon) && case_from_idx.is_none() {
                case_from_idx = Some(count);
            } else if creg.is_none() && d.contains('(') && case_mem.is_none() {
                case_mem = Some((count, d.trim().to_string()));
            } else if creg.as_deref().is_some_and(|r| r != "rsp" && r != "rbp")
                && case_fallback.is_none()
            {
                case_fallback = Some(count);
                fallback_reg = creg;
            }
        }
    }
    // Correlate a memory-operand bound check with the index: accept it only if
    // the index register was loaded from that exact memory operand before the
    // table load (`cmp $N,(%rcx)` … `mov (%rcx),%idx`). Sound because the bound
    // then provably constrains the switch index. Preferred over the register
    // fallback; a direct `cmp $N,%idx` still wins.
    let case_from_mem = case_mem.and_then(|(count, mem)| {
        items[start..mov_k]
            .iter()
            .any(|&(_, m, o)| {
                m.trim().to_ascii_lowercase().starts_with("mov")
                    && att_split(o).is_some_and(|(s, d)| {
                        s.trim() == mem && att_reg(d).as_deref() == Some(idx_canon)
                    })
            })
            .then_some(count)
    });
    // A direct `cmp $N,%idx` still wins; the mask is preferred over the looser
    // `cmp` fallbacks (memory-operand correlation, then any non-stack register)
    // because it names the index register exactly, like `case_from_idx` does.
    let case_count = case_from_idx
        .or(case_from_mask)
        .or(case_from_mem)
        .or(case_fallback)?;
    if case_count > MAX_RESOLVED_CASES {
        return None;
    }

    // The table load and the `add` exist solely to compute the indirect jump
    // target: `add %base,%jr` feeding `jmp *%jr` proves `jr` holds the target
    // and is dead at the jump. Retiring them is what lets the `switch` read the
    // *index* register, which the load would otherwise clobber (in the MSVC
    // idiom `jr` and `idx` are frequently the same register).
    //
    // The `lea` is different: `base` is an ordinary register that a case body
    // may legitimately reuse. Retire it only when no later instruction so much
    // as mentions it — a deliberately over-conservative test whose failure mode
    // is a harmless surviving `base = &off_X;` line, never a stale read.
    let mut arith_addrs = Vec::with_capacity(3);
    if let Some(k) = lea_k
        && !reg_mentioned_after(items, i, &base)
    {
        arith_addrs.push(items[k].0);
    }
    arith_addrs.push(items[mov_k].0);
    arith_addrs.push(items[add_k].0);

    // When the table load overwrites its own index register (`movslq
    // (%b,%jr,4), %jr` — `index == jr`), that register no longer holds the
    // switch value after the load; retiring the load leaves it a copy that
    // downstream naming renders as an uninitialised `switch (v3)`. The
    // bound-checked register still holds the pristine value, so prefer it.
    let index = if index == jr {
        fallback_reg.unwrap_or(index)
    } else {
        index
    };

    Some(JumpTableInfo {
        index,
        case_count,
        table_addr,
        entry_size,
        default_target,
        jump_addr,
        arith_addrs,
        code_base,
    })
}

/// Does any instruction strictly after `i` mention register family `reg`?
///
/// Operands are scanned token-wise and canonicalized, so `%eax` matches `rax`.
/// Used as a liveness over-approximation: a register nobody names again cannot
/// be read again.
fn reg_mentioned_after(items: &[(u64, &str, &str)], i: usize, reg: &str) -> bool {
    items[i + 1..].iter().any(|&(_, _, ops)| {
        ops.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .any(|t| is_register(t) && canon_reg(t) == reg)
    })
}

/// Backward window for the register-indirect idiom (lea → mov → add → jmp,
/// plus the bound check a few instructions earlier).
const REG_INDIRECT_LOOKBACK: usize = 14;

fn is_bound_branch(m: &str) -> bool {
    // Unsigned-above / signed-greater branches guard the out-of-range default.
    matches!(m, "ja" | "jae" | "jnbe" | "jnb" | "jg" | "jge" | "jnle" | "jnl")
}

/// Parse `[base + index*scale]` style targets. Returns `(index_reg, scale, base_addr)`.
fn parse_indirect_target(operands: &str) -> (Option<String>, Option<u32>, Option<u64>) {
    let inside = match (operands.find('['), operands.rfind(']')) {
        (Some(a), Some(b)) if b > a => &operands[a + 1..b],
        _ => return (None, None, None),
    };
    let lower = inside.to_ascii_lowercase();

    // Scale + index register: look for `reg*N` or `N*reg`.
    let mut index = None;
    let mut scale = None;
    if let Some(star) = lower.find('*') {
        let before = lower[..star].trim();
        let after = lower[star + 1..].trim();
        let before_tok = last_token(before);
        let after_tok = first_token(after);
        if let Ok(n) = after_tok.parse::<u32>() {
            scale = Some(n);
            if is_register(before_tok) {
                index = Some(before_tok.to_string());
            }
        } else if let Ok(n) = before_tok.parse::<u32>() {
            scale = Some(n);
            if is_register(after_tok) {
                index = Some(after_tok.to_string());
            }
        }
    }

    // Base: the first hex/decimal literal that is not the scale.
    let mut base = None;
    for tok in lower.split(['+', ' ', ']', '[']) {
        let tok = tok.trim();
        if tok.contains('*') {
            continue;
        }
        if let Some(v) = parse_u64_literal(tok) {
            base = Some(v);
            break;
        }
    }
    (index, scale, base)
}

/// Parse a `cmp` bound into `(compared_operand_lowercased, immediate)`.
///
/// **Order-agnostic on purpose.** Intel spells this `cmp eax, 0x10` (register
/// first) while AT&T spells it `cmp $0x10, %eax` (immediate first), and `cmp`
/// is written identically in both syntaxes — so the mnemonic cannot tell us
/// which we are looking at. Assuming Intel made the AT&T form parse the
/// immediate side as the register, `parse_u64_literal` then failed on the
/// register side, and the function returned `None`: the jump-table bound was
/// silently LOST rather than mis-parsed.
///
/// Instead of guessing the syntax, let the operands classify themselves —
/// whichever side parses as an integer literal IS the immediate. When both
/// sides parse (`cmp $1, $2`, which real code does not emit) we keep the
/// historical Intel reading so nothing that works today changes.
///
/// **MEASURED: currently inert — switch recovery stays at 153 and the corpus
/// at 11144/0.** Kept as a correct-by-construction guard, not claimed as a
/// fix. The reason it is inert is worth knowing, because it is the rule for
/// this whole codebase: **operand order tracks the MNEMONIC SPELLING.** An
/// AT&T-only spelling (`movslq`, `movzbl`, …) comes with AT&T `src, dst`
/// order — fixing exactly that in `callconv_bridge.rs` moved 54 files and
/// took `fidelity.sh` from 15/16 to 16/16. A spelling shared by both syntaxes
/// (`cmp`, `mov`, `add`) arrives in Intel `dst, src` order, so the AT&T arm
/// here never fires today.
fn parse_cmp_bound(operands: &str) -> Option<(String, u32)> {
    let (a, b) = operands.split_once(',')?;
    let (a, b) = (a.trim(), b.trim());
    let (reg, imm) = match (parse_u64_literal(a), parse_u64_literal(b)) {
        // Intel `cmp reg, imm` — and the both-parse tie-break.
        (_, Some(imm)) => (a, imm),
        // AT&T `cmp $imm, %reg`.
        (Some(imm), None) => (b, imm),
        (None, None) => return None,
    };
    Some((reg.to_ascii_lowercase(), u32::try_from(imm).ok()?))
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    parse_u64_literal(operands.trim())
}

fn parse_u64_literal(s: &str) -> Option<u64> {
    let s = s.trim().trim_matches(|c: char| c == ',' || c.is_whitespace());
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

fn first_token(s: &str) -> &str {
    s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|t| !t.is_empty())
        .unwrap_or("")
}

fn last_token(s: &str) -> &str {
    s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .rfind(|t| !t.is_empty())
        .unwrap_or("")
}

// #8730 - FONTE UNICA. Prima questo file aveva la PROPRIA lista di registri,
// e le mancavano tutte le forme a 8 bit: un limite di switch scritto come
// `cmp $3, %r8b` non veniva riconosciuto e la tabella restava non rilevata
// (#8680: +21 siti distinti una volta aggiunte a mano). Il difetto non era la
// lista sbagliata: era che ESISTESSE una seconda lista. `lib.rs::is_register`
// delegava gia' a `x86_register_width`, che il suo commento chiama
// «single source of truth»; qui no.
fn is_register(tok: &str) -> bool {
    let t = tok.trim().trim_start_matches('%');
    crate::x86_register_width::register_width_bytes(t).is_some()
}

// ── Table-entry resolution (pure decode over raw table bytes) ────────────────

/// Upper bound on `case_count` we are willing to materialize. Detection can
/// mis-read a `cmp` bound; anything above this is treated as implausible
/// rather than resolved into a giant `switch`.
pub const MAX_RESOLVED_CASES: u32 = 512;

/// How the raw table entries encode their targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpTableEncoding {
    /// 8-byte little-endian absolute virtual addresses.
    Abs64,
    /// 4-byte little-endian absolute virtual addresses (classic x86-32 form).
    Abs32,
    /// 4-byte little-endian signed offsets added to the table base address
    /// (the clang/GCC PIC form: `entry = target - table_base`).
    Rel32TableBase,
    /// 4-byte little-endian RVAs added to the image base (the MSVC x64 form:
    /// `entry = target - __ImageBase`).
    Rva32ImageBase,
    /// 4-byte little-endian unsigned offsets added to a separate RIP-lea'd
    /// code base (the two-lea .NET AOT/MSVC form: `entry = target -
    /// code_base`, with `code_base` carried in [`JumpTableInfo::code_base`]).
    Rel32CodeBase,
}

/// A jump table whose entries have been read from the image and validated:
/// one concrete target VA per dense case index, plus the out-of-range default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedJumpTable {
    /// Register used as the switch index (e.g. `"eax"`), lower-cased —
    /// forwarded from [`JumpTableInfo::index`], used as the `switch (…)` scrutinee.
    pub index: String,
    /// Address of the indirect `jmp` this table feeds — forwarded from
    /// [`JumpTableInfo::jump_addr`]; used to match the table to its jump site.
    pub jump_addr: u64,
    /// Virtual address where the table BYTES live — forwarded from
    /// [`JumpTableInfo::table_addr`].
    ///
    /// Perche' esiste (#4590): l'emissione dichiara `extern __int64 off_<VA>;`
    /// per ogni simbolo dati referenziato e mai definito, e **5503 file su
    /// 11144 non linkano** per questo. Per DEFINIRE quelli che sono tabelle di
    /// salto serve riconoscerle, e l'unico aggancio possibile fra il nome
    /// `off_140004000` e la sua tabella e' l'**indirizzo**: senza questo campo
    /// il dato si perdeva fra `JumpTableInfo` (che ce l'ha) e qui.
    /// L'alternativa — dedurre l'indirizzo dal NOME del simbolo — sarebbe un
    /// aggancio sul testo, fragile e contrario al resto del crate.
    pub table_base: u64,
    /// `(case_index, target_va)` for each case `0..case_count`, in order.
    pub cases: Vec<(u32, u64)>,
    /// Default branch target, forwarded from [`JumpTableInfo::default_target`].
    pub default_target: Option<u64>,
    /// The entry encoding that validated.
    pub encoding: JumpTableEncoding,
    /// Forwarded from [`JumpTableInfo::arith_addrs`]: the table-arithmetic
    /// instructions the lifter must skip so `index` still holds the index.
    pub arith_addrs: Vec<u64>,
}

/// Decode and validate the raw jump-table bytes for `info`.
///
/// `table_bytes` must start at `info.table_addr` (e.g. the slice returned by
/// `binary_entry::slice_at_va`); `image_base` is the load image base (0 when
/// unknown), used for the RVA interpretation; `is_code_target` decides
/// whether a candidate VA is a plausible branch target (typically: it falls
/// inside an executable section).
///
/// For `entry_size == 8` only [`JumpTableEncoding::Abs64`] is tried. For
/// `entry_size == 4` each 4-byte interpretation is decoded, and an
/// interpretation is accepted only when **every** case target passes
/// `is_code_target`. If several interpretations validate but disagree on the
/// targets, the table is ambiguous and `None` is returned — this function
/// never guesses.
///
/// Returns `None` (callers keep their `goto` fallback) when:
/// * `info.table_addr` is `None`, `case_count` is 0 or exceeds
///   [`MAX_RESOLVED_CASES`], or `entry_size` is not 4 or 8;
/// * `table_bytes` holds fewer than `case_count * entry_size` bytes;
/// * no interpretation validates, or the validating interpretations disagree.
#[must_use]
pub fn resolve_table_targets(
    info: &JumpTableInfo,
    table_bytes: &[u8],
    image_base: u64,
    is_code_target: impl Fn(u64) -> bool,
) -> Option<ResolvedJumpTable> {
    let table_addr = info.table_addr?;
    if info.case_count == 0 || info.case_count > MAX_RESOLVED_CASES {
        return None;
    }
    let count = usize::try_from(info.case_count).ok()?;
    let stride = usize::try_from(info.entry_size).ok()?;
    if stride != 4 && stride != 8 {
        return None;
    }
    let needed = count.checked_mul(stride)?;
    if table_bytes.len() < needed {
        return None;
    }

    let candidates: &[JumpTableEncoding] = if info.code_base.is_some() {
        // The detection proved the add-a-separate-code-base shape; no other
        // interpretation is plausible.
        &[JumpTableEncoding::Rel32CodeBase]
    } else if stride == 8 {
        &[JumpTableEncoding::Abs64]
    } else if image_base == 0 {
        // With no image base an RVA is indistinguishable from an absolute
        // address, so only two 4-byte interpretations remain.
        &[JumpTableEncoding::Abs32, JumpTableEncoding::Rel32TableBase]
    } else {
        &[
            JumpTableEncoding::Abs32,
            JumpTableEncoding::Rel32TableBase,
            JumpTableEncoding::Rva32ImageBase,
        ]
    };

    let mut validated: Option<ResolvedJumpTable> = None;
    for &encoding in candidates {
        let Some(cases) =
            decode_entries(table_bytes, count, encoding, table_addr, image_base, info.code_base)
        else {
            continue;
        };
        if !cases.iter().all(|&(_, target)| is_code_target(target)) {
            continue;
        }
        match &validated {
            None => {
                validated = Some(ResolvedJumpTable {
                    index: info.index.clone(),
                    jump_addr: info.jump_addr,
                    table_base: table_addr,
                    cases,
                    default_target: info.default_target,
                    encoding,
                    arith_addrs: info.arith_addrs.clone(),
                });
            }
            // Two interpretations both validate: acceptable only when they
            // agree on every target (degenerate identical decodings).
            Some(prev) if prev.cases == cases => {}
            Some(_) => return None,
        }
    }
    validated
}

/// Decode `count` table entries under one `encoding`. Returns `None` when an
/// entry decodes to 0 or the address arithmetic overflows — both mark the
/// interpretation as invalid.
fn decode_entries(
    bytes: &[u8],
    count: usize,
    encoding: JumpTableEncoding,
    table_addr: u64,
    image_base: u64,
    code_base: Option<u64>,
) -> Option<Vec<(u32, u64)>> {
    let stride = if encoding == JumpTableEncoding::Abs64 {
        8
    } else {
        4
    };
    let mut cases = Vec::with_capacity(count);
    for (i, entry) in bytes.chunks_exact(stride).take(count).enumerate() {
        let target = match encoding {
            JumpTableEncoding::Abs64 => u64::from_le_bytes(entry.try_into().ok()?),
            JumpTableEncoding::Abs32 => u64::from(u32::from_le_bytes(entry.try_into().ok()?)),
            JumpTableEncoding::Rel32TableBase => {
                let offset = i64::from(i32::from_le_bytes(entry.try_into().ok()?));
                table_addr.checked_add_signed(offset)?
            }
            JumpTableEncoding::Rva32ImageBase => {
                image_base.checked_add(u64::from(u32::from_le_bytes(entry.try_into().ok()?)))?
            }
            JumpTableEncoding::Rel32CodeBase => {
                // The real machine sequence zero-extends the dword load
                // (`mov (%tbl,%idx,4),%e_tgt`) before the 64-bit add.
                code_base?.checked_add(u64::from(u32::from_le_bytes(entry.try_into().ok()?)))?
            }
        };
        if target == 0 {
            return None;
        }
        cases.push((u32::try_from(i).ok()?, target));
    }
    if cases.len() == count {
        Some(cases)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Switch rendering
// ─────────────────────────────────────────────────────────────────────────────

impl ResolvedJumpTable {
    /// Render this table as a pseudo-C `switch` at the given base indent (the
    /// indentation of the `goto` line being replaced).
    #[must_use]
    pub fn render_switch(&self, base_indent: &str) -> String {
        render_jump_table_switch(&self.index, &self.cases, self.default_target, base_indent)
    }
}

/// Render a dense `switch` from resolved `(case_index, target_va)` pairs.
///
/// * Cases are sorted by index so output is deterministic.
/// * A run of *consecutive* indices sharing one target collapses to stacked
///   `case` labels (fallthrough).
/// * `default` is appended when present.
///
/// Each case body is the resolved target address as a `/* -> loc_<VA> */`
/// comment rather than a `goto`: the case-target blocks are unreachable in the
/// text CFG (the only edge was the indirect jump we replace here), so the
/// structurer's label-elimination drops their `loc_<VA>:` labels — a real
/// `goto` would dangle. The comment form is valid C and still surfaces every
/// resolved target (IDA-level information). No trailing newline; 4 spaces/level.
#[must_use]
pub fn render_jump_table_switch(
    index: &str,
    cases: &[(u32, u64)],
    default: Option<u64>,
    base_indent: &str,
) -> String {
    use std::fmt::Write as _;
    let one = format!("{base_indent}    ");

    let mut sorted: Vec<(u32, u64)> = cases.to_vec();
    sorted.sort_by_key(|&(idx, _)| idx);

    let mut out = String::new();
    let _ = write!(out, "{base_indent}switch ({index}) {{");
    let mut i = 0;
    while i < sorted.len() {
        let target = sorted[i].1;
        let mut j = i;
        while j + 1 < sorted.len()
            && sorted[j + 1].1 == target
            && sorted[j].0.checked_add(1) == Some(sorted[j + 1].0)
        {
            j += 1;
        }
        for &(idx, _) in &sorted[i..=j] {
            let _ = write!(out, "\n{one}case {idx}:");
        }
        let _ = write!(out, " /* -> loc_{target:X} */");
        i = j + 1;
    }
    if let Some(def) = default {
        let _ = write!(out, "\n{one}default: /* -> loc_{def:X} */");
    }
    let _ = write!(out, "\n{base_indent}}}");
    out
}

/// The marker the lifter emits in place of a resolved indirect jump.
///
/// The jump-site VA is embedded so expansion is keyed by address rather than by
/// textual order — a function may mix resolved and unresolved indirect jumps.
///
/// It deliberately keeps the `goto /* … */;` shape of an unresolved leak: the C
/// printer re-appends a `;` to every `Statement::Raw`, and every downstream
/// text pass already tolerates that shape.
#[must_use]
pub fn switch_marker(jump_addr: u64) -> String {
    format!("goto /* __JT_{jump_addr:X}__ */;")
}

/// Recover the jump-site VA from a [`switch_marker`] line.
#[must_use]
pub fn parse_switch_marker(line: &str) -> Option<u64> {
    let inner = line
        .trim()
        .trim_end_matches(';')
        .strip_prefix("goto /*")?
        .strip_suffix("*/")?
        .trim();
    let hex = inner.strip_prefix("__JT_")?.strip_suffix("__")?;
    u64::from_str_radix(hex, 16).ok()
}

/// Expand each [`switch_marker`] line in `code` into the real `switch` recovered
/// for that jump site.
///
/// The scrutinee is the table's *index* register (raw, e.g. `rax`), not the
/// jump register: the jump register holds the computed target address, so
/// switching on it would be nonsense. Emitting the raw register name is what
/// lets the later width-alias-aware renaming passes rewrite the scrutinee into
/// the same local/parameter name the rest of the body uses.
///
/// A marker with no matching table is left untouched (defensive; cannot happen
/// while the lifter only emits markers for resolved tables).
#[must_use]
pub fn apply_jump_tables(code: &str, tables: &[ResolvedJumpTable]) -> String {
    if tables.is_empty() {
        return code.to_string();
    }
    let mut out: Vec<String> = Vec::with_capacity(code.lines().count() + 8);
    for line in code.lines() {
        if let Some(va) = parse_switch_marker(line)
            && let Some(jt) = tables.iter().find(|t| t.jump_addr == va)
        {
            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out.push(render_jump_table_switch(&jt.index, &jt.cases, jt.default_target, &indent));
            continue;
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::{InstrFlags, Instruction};

    fn mk(addr: u64, mnem: &str, ops: &str) -> Instruction {
        Instruction {
            address: Address::from(addr),
            size: 1,
            mnemonic: mnem.to_string(),
            operands: ops.to_string(),
            operand_list: Vec::new(),
            flags: InstrFlags::empty(),
            bytes: Vec::new(),
            comment: None,
        }
    }

    #[test]
    fn detects_msvc_x64_reg_indirect_idiom() {
        // Real rustre-cli.exe sub_140001D90 tail (AT&T), verbatim addresses.
        let insns = vec![
            mk(0x140001dba, "cmp", "$5, %rax"),
            mk(0x140001dbe, "ja", "0x140001EEF"),
            mk(0x140001dc4, "lea", "0x111FC9(%rip), %rcx"),
            mk(0x140001dcb, "movslq", "(%rcx,%rax,4), %rax"),
            mk(0x140001dcf, "add", "%rcx, %rax"),
            mk(0x140001dd2, "jmp", "*%rax"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table");
        assert_eq!(jt.index, "rax");
        assert_eq!(jt.case_count, 6);
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.default_target, Some(0x1_4000_1EEF));
        assert_eq!(jt.jump_addr, 0x1_4000_1DD2);
        // table base = next_addr(lea) + disp = 0x140001DCB + 0x111FC9.
        assert_eq!(jt.table_addr, Some(0x1_4011_3D94));
        // lea + movslq + add are dead once the switch reads `rax` directly.
        // Nothing follows the jmp here, so the base (`rcx`) is provably dead.
        assert_eq!(jt.arith_addrs, vec![0x1_4000_1DC4, 0x1_4000_1DCB, 0x1_4000_1DCF]);
    }

    #[test]
    fn detects_go_masked_mem_indirect_idiom() {
        // Go/gc form, verbatim from sample4_go.exe @0x14000c94a: AND-masked
        // index, RIP-lea'd Abs64 table, memory-indirect jmp, no default.
        let insns = vec![
            mk(0x14000c96b, "mov", "0x10(%rax), %ecx"),
            mk(0x14000c96e, "shr", "$5, %ecx"),
            mk(0x14000c971, "and", "$0x3F, %ecx"),
            mk(0x14000c974, "lea", "0xBF985(%rip), %rdx"),
            mk(0x14000c97b, "jmpq", "*(%rdx,%rcx,8)"),
        ];
        let jt = detect_jump_table(&insns).expect("go masked jump table");
        assert_eq!(jt.index, "rcx");
        assert_eq!(jt.case_count, 64);
        assert_eq!(jt.entry_size, 8);
        assert_eq!(jt.default_target, None);
        // table = next_addr(lea) + disp = 0x14000C97B + 0xBF985.
        assert_eq!(jt.table_addr, Some(0x1_400C_C300));
        assert_eq!(jt.code_base, None);
    }

    #[test]
    fn rejects_go_mem_indirect_with_sparse_mask() {
        // `and $0x35` is not 2^k-1: mask+1 is not the case count — reject.
        let insns = vec![
            mk(0x100, "and", "$0x35, %ecx"),
            mk(0x104, "lea", "0x1000(%rip), %rdx"),
            mk(0x10b, "jmpq", "*(%rdx,%rcx,8)"),
        ];
        assert_eq!(detect_jump_table(&insns), None);
    }

    #[test]
    fn scan_survives_a_non_table_indirect_jump() {
        // A virtual dispatch (`jmp *0x18(%rax)`) precedes a real table. The
        // scan must skip the dispatch and still find the table behind it;
        // aborting there lost every switch after a virtual call (58 corpus
        // JUMPOUTs in the C# samples sat behind exactly this).
        let insns = vec![
            mk(0x140005900, "mov", "0x18(%rax), %rax"),
            mk(0x140005904, "jmp", "*0x18(%rax)"),
            mk(0x14000596e, "cmp", "$0xB, %r10d"),
            mk(0x140005972, "ja", "0x140005A8F"),
            mk(0x140005978, "mov", "%r10d, %r10d"),
            mk(0x14000597b, "lea", "0xC478E(%rip), %r9"),
            mk(0x140005982, "mov", "(%r9,%r10,4), %r9d"),
            mk(0x140005986, "lea", "-0xAB(%rip), %r11"),
            mk(0x14000598d, "add", "%r11, %r9"),
            mk(0x140005990, "jmp", "*%r9"),
        ];
        let tables = detect_all_jump_tables(&insns);
        assert_eq!(tables.len(), 1, "table behind the dispatch must be found");
        assert_eq!(tables[0].jump_addr, 0x1_4000_5990);
        assert_eq!(tables[0].case_count, 0xC);
    }

    #[test]
    fn scan_terminates_with_only_non_table_jumps() {
        // No table at all: the scan must terminate, not spin.
        let insns = vec![
            mk(0x140005900, "jmp", "*0x18(%rax)"),
            mk(0x140005904, "jmp", "*%rdx"),
        ];
        assert!(detect_all_jump_tables(&insns).is_empty());
    }

    #[test]
    fn detects_two_lea_with_biased_index() {
        // Same two-lea form, verbatim from sample5_cs.exe @0x140005990, but the
        // index is derived with a BIAS (`lea -3(%r13),%r10d`, i.e. case values
        // start at 3) and the zero-extending copy is self-referential
        // (`mov %r10d,%r10d`). 58 corpus JUMPOUTs sit on this variant.
        let insns = vec![
            mk(0x14000596a, "lea", "-3(%r13), %r10d"),
            mk(0x14000596e, "cmp", "$0xB, %r10d"),
            mk(0x140005972, "ja", "0x140005A8F"),
            mk(0x140005978, "mov", "%r10d, %r10d"),
            mk(0x14000597b, "lea", "0xC478E(%rip), %r9"),
            mk(0x140005982, "mov", "(%r9,%r10,4), %r9d"),
            mk(0x140005986, "lea", "-0xAB(%rip), %r11"),
            mk(0x14000598d, "add", "%r11, %r9"),
            mk(0x140005990, "jmp", "*%r9"),
        ];
        let jt = detect_jump_table(&insns).expect("biased-index two-lea table");
        assert_eq!(jt.case_count, 0xC);
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.default_target, Some(0x1_4000_5A8F));
        // code base = next_addr(lea r11) - 0xAB = 0x14000598D - 0xAB.
        assert_eq!(jt.code_base, Some(0x1_4000_58E2));
    }

    #[test]
    fn detects_reg_indirect_with_mask_bound() {
        // MSVC reg-indirect table whose bound is a MASK, not a `cmp`: the
        // masked index is in range by construction, so there is no `ja`
        // default either. Shape seen behind `JUMPOUT(result)` in sample7_cpp.
        let insns = vec![
            mk(0x140012000, "and", "$0xFF, %eax"),
            mk(0x140012005, "lea", "0x1D68F(%rip), %rcx"),
            mk(0x14001200c, "mov", "(%rcx,%rax,4), %eax"),
            mk(0x14001200f, "add", "%rcx, %rax"),
            mk(0x140012012, "jmp", "*%rax"),
        ];
        let jt = detect_jump_table(&insns).expect("mask-bounded reg-indirect table");
        assert_eq!(jt.case_count, 0x100);
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.default_target, None, "a masked index has no default arm");
    }

    #[test]
    fn rejects_reg_indirect_with_sparse_mask() {
        // `and $0xF0` is NOT 2^k-1: the case count cannot be derived from it,
        // so the table must be REJECTED rather than given a fabricated count.
        let insns = vec![
            mk(0x140012000, "and", "$0xF0, %eax"),
            mk(0x140012005, "lea", "0x1D68F(%rip), %rcx"),
            mk(0x14001200c, "mov", "(%rcx,%rax,4), %eax"),
            mk(0x14001200f, "add", "%rcx, %rax"),
            mk(0x140012012, "jmp", "*%rax"),
        ];
        assert!(detect_jump_table(&insns).is_none());
    }

    #[test]
    fn cmp_bound_still_wins_over_a_nearby_mask() {
        // A mask on the index must not override an explicit `cmp $N,%idx`:
        // the `cmp` is the real case count (the mask here only zero-extends).
        let insns = vec![
            mk(0x140012000, "and", "$0xFF, %eax"),
            mk(0x140012003, "cmp", "$0x5, %eax"),
            mk(0x140012006, "ja", "0x140012100"),
            mk(0x140012008, "lea", "0x1D68F(%rip), %rcx"),
            mk(0x14001200c, "mov", "(%rcx,%rax,4), %eax"),
            mk(0x14001200f, "add", "%rcx, %rax"),
            mk(0x140012012, "jmp", "*%rax"),
        ];
        let jt = detect_jump_table(&insns).expect("table");
        assert_eq!(jt.case_count, 6, "cmp bound must win, not the 0x100 mask");
        assert_eq!(jt.default_target, Some(0x140012100));
    }

    #[test]
    fn detects_two_lea_code_base_idiom() {
        // .NET AOT / MSVC two-lea form, verbatim from sample5_cs.exe
        // @0x14003F4F0: the dword table entries are offsets from a SEPARATE
        // rip-lea'd code base, and the load clobbers its own table register.
        let insns = vec![
            mk(0x14003f4f1, "cmp", "$0x14, %r8d"),
            mk(0x14003f4f4, "ja", "0x14003F557"),
            mk(0x14003f4f6, "mov", "%r8d, %eax"),
            mk(0x14003f4f9, "lea", "0x8B448(%rip), %rdx"),
            mk(0x14003f500, "mov", "(%rdx,%rax,4), %edx"),
            mk(0x14003f503, "lea", "-0x1A(%rip), %r8"),
            mk(0x14003f50a, "add", "%r8, %rdx"),
            mk(0x14003f50d, "jmp", "*%rdx"),
        ];
        let jt = detect_jump_table(&insns).expect("two-lea jump table");
        assert_eq!(jt.case_count, 0x15);
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.default_target, Some(0x1_4003_F557));
        assert_eq!(jt.jump_addr, 0x1_4003_F50D);
        // table = next_addr(lea rdx) + 0x8B448 = 0x14003F500 + 0x8B448.
        assert_eq!(jt.table_addr, Some(0x1_400C_A948));
        // code base = next_addr(lea r8) - 0x1A = 0x14003F50A - 0x1A.
        assert_eq!(jt.code_base, Some(0x1_4003_F4F0));
    }

    #[test]
    fn two_lea_entries_resolve_from_code_base() {
        let info = JumpTableInfo {
            index: "rax".into(),
            case_count: 2,
            table_addr: Some(0x1_400C_A948),
            entry_size: 4,
            default_target: Some(0x1_4003_F557),
            jump_addr: 0x1_4003_F50D,
            arith_addrs: vec![],
            code_base: Some(0x1_4003_F4F0),
        };
        // Entries are ZERO-extended u32 offsets from code_base.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x10u32.to_le_bytes());
        bytes.extend_from_slice(&0x40u32.to_le_bytes());
        let resolved = resolve_table_targets(&info, &bytes, 0x1_4000_0000, |va| {
            (0x1_4003_0000..0x1_4005_0000).contains(&va)
        })
        .expect("resolved");
        assert_eq!(resolved.encoding, JumpTableEncoding::Rel32CodeBase);
        assert_eq!(resolved.cases, vec![(0, 0x1_4003_F500), (1, 0x1_4003_F530)]);
    }

    #[test]
    fn detects_gcc_memory_operand_bound_check() {
        // GCC rel32 idiom where the bound check compares the switch value in
        // MEMORY (`cmpl $6,(%rcx)`) and the index is reloaded from that same
        // memory before the table load. Verbatim from sample6_c.exe @0x140001830.
        let insns = vec![
            mk(0x140001846, "cmpl", "$6, (%rcx)"),
            mk(0x140001849, "ja", "0x14000191C"),
            mk(0x14000184f, "mov", "(%rcx), %eax"),
            mk(0x140001851, "lea", "0x296C(%rip), %rdx"),
            mk(0x140001858, "movslq", "(%rdx,%rax,4), %rax"),
            mk(0x14000185c, "add", "%rdx, %rax"),
            mk(0x14000185f, "jmp", "*%rax"),
        ];
        let jt = detect_jump_table(&insns).expect("memory-operand jump table");
        assert_eq!(jt.index, "rax");
        assert_eq!(jt.case_count, 7); // cmp $6 -> indices 0..=6
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.default_target, Some(0x1_4000_191C));
        assert_eq!(jt.jump_addr, 0x1_4000_185F);
    }

    #[test]
    fn rejects_memory_bound_check_when_index_not_from_that_memory() {
        // Same shape but the index is NOT loaded from the compared memory —
        // the bound cannot be trusted to constrain the index, so no detection.
        let insns = vec![
            mk(0x140001846, "cmpl", "$6, (%rdx)"),
            mk(0x140001849, "ja", "0x14000191C"),
            mk(0x14000184f, "mov", "(%rcx), %eax"),
            mk(0x140001851, "lea", "0x296C(%rip), %rdx"),
            mk(0x140001858, "movslq", "(%rdx,%rax,4), %rax"),
            mk(0x14000185c, "add", "%rdx, %rax"),
            mk(0x14000185f, "jmp", "*%rax"),
        ];
        assert!(detect_jump_table(&insns).is_none());
    }

    #[test]
    fn arith_addrs_keeps_lea_when_base_reused_after_jump() {
        // Identical idiom, but a later instruction names the table base `rcx`.
        // Retiring the `lea` would turn that into a read of an undefined value,
        // so the `lea` must survive; the load and the add still retire (they
        // feed only the jump, and dropping them is what preserves the index).
        let insns = vec![
            mk(0x1_4000_1DBA, "cmp", "$5, %rax"),
            mk(0x1_4000_1DBE, "ja", "0x140001EEF"),
            mk(0x1_4000_1DC4, "lea", "0x111FC9(%rip), %rcx"),
            mk(0x1_4000_1DCB, "movslq", "(%rcx,%rax,4), %rax"),
            mk(0x1_4000_1DCF, "add", "%rcx, %rax"),
            mk(0x1_4000_1DD2, "jmp", "*%rax"),
            mk(0x1_4000_1DD4, "mov", "%rcx, %rdx"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table");
        assert_eq!(jt.arith_addrs, vec![0x1_4000_1DCB, 0x1_4000_1DCF]);
        // A width alias of the base counts as a mention too.
        let mut aliased = insns.clone();
        aliased[6] = mk(0x1_4000_1DD4, "mov", "%ecx, %edx");
        let jt2 = detect_jump_table(&aliased).expect("jump table");
        assert_eq!(jt2.arith_addrs, vec![0x1_4000_1DCB, 0x1_4000_1DCF]);
    }

    #[test]
    fn switch_marker_round_trips_and_expands_on_the_index_register() {
        let marker = switch_marker(0x1_4000_1DD2);
        assert_eq!(parse_switch_marker(&marker), Some(0x1_4000_1DD2));
        // The C printer re-appends `;` to every Raw statement; the bare form and
        // any extra trailing `;` must both parse.
        assert_eq!(parse_switch_marker("    goto /* __JT_140001DD2__ */"), Some(0x1_4000_1DD2));
        assert_eq!(parse_switch_marker("goto /* __JT_140001DD2__ */;;"), Some(0x1_4000_1DD2));
        // An unresolved indirect jump is not a marker.
        assert_eq!(parse_switch_marker("goto /* *%rax */;"), None);

        let table = ResolvedJumpTable {
            // `index` is the switch scrutinee. The *jump* register (which holds
            // the computed target address) must never appear in the output.
            index: "rax".to_string(),
            jump_addr: 0x1_4000_1DD2,
            table_base: 0x1_4000_4000,
            cases: vec![(0, 0x1_4000_1DD4), (1, 0x1_4000_1E8D)],
            default_target: Some(0x1_4000_1EEF),
            encoding: JumpTableEncoding::Rel32TableBase,
            arith_addrs: vec![],
        };
        let code = format!("    {}\n    return 0;", switch_marker(0x1_4000_1DD2));
        let out = apply_jump_tables(&code, std::slice::from_ref(&table));
        assert!(!out.contains("__JT_"), "marker leaked: {out}");
        assert!(out.contains("    switch (rax) {"), "{out}");
        assert!(out.contains("case 0: /* -> loc_140001DD4 */"), "{out}");
        assert!(out.contains("default: /* -> loc_140001EEF */"), "{out}");
        assert!(out.contains("    return 0;"), "{out}");

        // A marker whose VA has no table is left exactly as-is rather than
        // being paired with an unrelated table by position.
        let orphan = format!("    {}", switch_marker(0xDEAD));
        assert_eq!(apply_jump_tables(&orphan, &[table]), orphan);
    }

    #[test]
    fn att_helpers_parse_msvc_operands() {
        assert_eq!(att_reg("*%rax").as_deref(), Some("rax"));
        assert_eq!(att_reg("%ecx").as_deref(), Some("rcx"));
        assert_eq!(att_reg("(%rcx)"), None);
        assert_eq!(att_split("%rcx, %rax"), Some(("%rcx", "%rax")));
        // top-level comma only: the mem operand's inner commas are ignored.
        assert_eq!(att_split("(%rcx,%rax,4), %rax"), Some(("(%rcx,%rax,4)", "%rax")));
        assert_eq!(att_mem("(%rcx,%rax,4)"), Some(("rcx".into(), "rax".into(), 4)));
        assert_eq!(att_rip_disp("0x111FC9(%rip)"), Some(0x11_1FC9));
        assert_eq!(att_rip_disp("-0x10(%rip)"), Some(-0x10));
        assert_eq!(att_imm("$5"), Some(5));
    }

    #[test]
    fn detects_x86_32_jump_table() {
        let insns = vec![
            mk(0x1000, "cmp", "eax, 5"),
            mk(0x1003, "ja", "0x1050"),
            mk(0x1009, "jmp", "[0x401000 + eax*4]"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table");
        assert_eq!(jt.index, "eax");
        assert_eq!(jt.case_count, 6);
        assert_eq!(jt.entry_size, 4);
        assert_eq!(jt.table_addr, Some(0x0040_1000));
        assert_eq!(jt.default_target, Some(0x1050));
        assert_eq!(jt.jump_addr, 0x1009);
    }

    #[test]
    fn detects_x86_64_stride_8() {
        let insns = vec![
            mk(0x2000, "cmp", "rdi, 0x3"),
            mk(0x2004, "ja", "0x20a0"),
            mk(0x200a, "jmp", "qword ptr [rax + rdi*8]"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table");
        assert_eq!(jt.index, "rdi");
        assert_eq!(jt.case_count, 4);
        assert_eq!(jt.entry_size, 8);
        assert_eq!(jt.default_target, Some(0x20a0));
    }

    #[test]
    fn ignores_plain_direct_jump() {
        let insns = vec![
            mk(0x3000, "cmp", "eax, 5"),
            mk(0x3003, "jmp", "0x3100"),
        ];
        assert!(detect_jump_table(&insns).is_none());
    }

    #[test]
    fn no_bound_check_is_not_a_table() {
        // Indirect jump with no preceding cmp bound -> not a recognised dense switch.
        let insns = vec![mk(0x4000, "jmp", "[rax*8 + 0x600000]")];
        assert!(detect_jump_table(&insns).is_none());
    }

    #[test]
    fn register_indirect_with_bound() {
        let insns = vec![
            mk(0x5000, "cmp", "ecx, 0x2"),
            mk(0x5003, "jae", "0x5090"),
            mk(0x5009, "jmp", "eax"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table");
        assert_eq!(jt.case_count, 3);
        // Index falls back to the cmp lhs when the jump has no memory operand.
        assert_eq!(jt.index, "ecx");
        assert_eq!(jt.default_target, Some(0x5090));
    }

    // ── resolve_table_targets ────────────────────────────────────────────

    fn resolver_info(case_count: u32, table_addr: u64, entry_size: u32) -> JumpTableInfo {
        JumpTableInfo {
            index: "eax".to_string(),
            case_count,
            table_addr: Some(table_addr),
            entry_size,
            default_target: Some(0x9999),
            jump_addr: 0x1000,
            arith_addrs: Vec::new(),
            code_base: None,
        }
    }

    fn le32(vals: &[u32]) -> Vec<u8> {
        vals.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn le64(vals: &[u64]) -> Vec<u8> {
        vals.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn resolves_abs32_entries() {
        let bytes = le32(&[0x0040_1010, 0x0040_1020, 0x0040_1030]);
        let jt = resolver_info(3, 0x0040_8000, 4);
        let in_text = |va: u64| (0x0040_1000..0x0040_2000).contains(&va);
        let resolved = resolve_table_targets(&jt, &bytes, 0x0040_0000, in_text).expect("resolved");
        assert_eq!(resolved.encoding, JumpTableEncoding::Abs32);
        assert_eq!(
            resolved.cases,
            vec![(0, 0x0040_1010), (1, 0x0040_1020), (2, 0x0040_1030)]
        );
        assert_eq!(resolved.default_target, Some(0x9999));
    }

    #[test]
    fn resolves_rel32_table_base_entries() {
        // clang/GCC PIC form: entry = target - table_base (negative here:
        // the code precedes the table). Two's-complement little-endian:
        //   0x1400_1010 - 0x1400_8000 = -0x6FF0 -> 0xFFFF_9010
        //   0x1400_1450 - 0x1400_8000 = -0x6BB0 -> 0xFFFF_9450
        let bytes = le32(&[0xFFFF_9010, 0xFFFF_9450]);
        let jt = resolver_info(2, 0x1400_8000, 4);
        let in_text = |va: u64| (0x1400_1000..0x1400_2000).contains(&va);
        let resolved = resolve_table_targets(&jt, &bytes, 0x1400_0000, in_text).expect("resolved");
        assert_eq!(resolved.encoding, JumpTableEncoding::Rel32TableBase);
        assert_eq!(resolved.cases, vec![(0, 0x1400_1010), (1, 0x1400_1450)]);
    }

    #[test]
    fn resolves_rva32_image_base_entries() {
        // MSVC x64 form: entry = target - __ImageBase.
        let bytes = le32(&[0x1010, 0x1200]);
        let jt = resolver_info(2, 0x1_4000_8000, 4);
        let in_text = |va: u64| (0x1_4000_1000..0x1_4000_2000).contains(&va);
        let resolved =
            resolve_table_targets(&jt, &bytes, 0x1_4000_0000, in_text).expect("resolved");
        assert_eq!(resolved.encoding, JumpTableEncoding::Rva32ImageBase);
        assert_eq!(resolved.cases, vec![(0, 0x1_4000_1010), (1, 0x1_4000_1200)]);
    }

    #[test]
    fn resolves_abs64_entries() {
        let bytes = le64(&[0x1_4000_1010, 0x1_4000_1050]);
        let jt = resolver_info(2, 0x1_4000_8000, 8);
        let in_text = |va: u64| (0x1_4000_1000..0x1_4000_2000).contains(&va);
        let resolved =
            resolve_table_targets(&jt, &bytes, 0x1_4000_0000, in_text).expect("resolved");
        assert_eq!(resolved.encoding, JumpTableEncoding::Abs64);
        assert_eq!(resolved.cases, vec![(0, 0x1_4000_1010), (1, 0x1_4000_1050)]);
    }

    #[test]
    fn ambiguous_interpretations_are_rejected() {
        // With a validator that accepts anything, both the absolute and the
        // table-base-relative reading of these entries pass but they yield
        // different targets — the honest answer is None.
        let bytes = le32(&[0x2000, 0x3000]);
        let jt = resolver_info(2, 0x1000, 4);
        assert_eq!(resolve_table_targets(&jt, &bytes, 0, |_| true), None);
    }

    #[test]
    fn agreeing_interpretations_are_accepted() {
        // Degenerate table base 0 makes the absolute and table-relative
        // readings identical; agreement means there is no real ambiguity.
        let bytes = le32(&[0x2000, 0x3000]);
        let jt = resolver_info(2, 0, 4);
        let resolved = resolve_table_targets(&jt, &bytes, 0, |_| true).expect("resolved");
        assert_eq!(resolved.cases, vec![(0, 0x2000), (1, 0x3000)]);
    }

    #[test]
    fn unvalidatable_targets_return_none() {
        let bytes = le32(&[0x0040_1010, 0x0040_1020]);
        let jt = resolver_info(2, 0x0040_8000, 4);
        assert_eq!(
            resolve_table_targets(&jt, &bytes, 0x0040_0000, |_| false),
            None
        );
    }

    #[test]
    fn one_bad_target_rejects_the_interpretation() {
        // Second entry lands outside the code range under every reading.
        let bytes = le32(&[0x0040_1010, 0x00DE_AD00]);
        let jt = resolver_info(2, 0x0040_8000, 4);
        let in_text = |va: u64| (0x0040_1000..0x0040_2000).contains(&va);
        assert_eq!(
            resolve_table_targets(&jt, &bytes, 0x0040_0000, in_text),
            None
        );
    }

    #[test]
    fn truncated_table_bytes_return_none() {
        let bytes = le32(&[0x0040_1010]); // one entry, but two cases claimed
        let jt = resolver_info(2, 0x0040_8000, 4);
        assert_eq!(
            resolve_table_targets(&jt, &bytes, 0x0040_0000, |_| true),
            None
        );
    }

    #[test]
    fn zero_entry_rejects_the_interpretation() {
        // A zero target is never a valid case label under any reading.
        let bytes = le32(&[0x0040_1010, 0]);
        let jt = resolver_info(2, 0x0040_8000, 4);
        let in_text = |va: u64| (0x0040_1000..0x0040_2000).contains(&va);
        assert_eq!(
            resolve_table_targets(&jt, &bytes, 0x0040_0000, in_text),
            None
        );
    }

    #[test]
    fn degenerate_infos_return_none() {
        let bytes = le32(&[0x0040_1010; 4]);
        // No table address.
        let mut no_addr = resolver_info(2, 0x0040_8000, 4);
        no_addr.table_addr = None;
        assert_eq!(resolve_table_targets(&no_addr, &bytes, 0, |_| true), None);
        // Zero cases.
        assert_eq!(
            resolve_table_targets(&resolver_info(0, 0x0040_8000, 4), &bytes, 0, |_| true),
            None
        );
        // Implausibly large case count.
        assert_eq!(
            resolve_table_targets(
                &resolver_info(MAX_RESOLVED_CASES + 1, 0x0040_8000, 4),
                &bytes,
                0,
                |_| true
            ),
            None
        );
        // Unsupported stride.
        assert_eq!(
            resolve_table_targets(&resolver_info(2, 0x0040_8000, 2), &bytes, 0, |_| true),
            None
        );
    }

    /// #8680 - riproduce la sequenza REALE di `rust3_O0/sub_140002410`
    /// (dispatch a 0x14000289a) che il rilevatore NON trova, pur avendo la
    /// forma canonica e il limite 8 istruzioni piu indietro.
    #[test]
    fn dispatch_reale_di_sub_140002410() {
        let raw: Vec<(u64, String, String)> = vec![
            (0x14000286a, "cmp".into(), "%dl, %r8b".into()),
            (0x14000286d, "mov".into(), "%rax, %rcx".into()),
            (0x140002870, "mov".into(), "%rcx, %rdx".into()),
            (0x140002873, "mov".into(), "%rdx, %rax".into()),
            (0x140002876, "mov".into(), "%rax, %rcx".into()),
            (0x14000287a, "cmp".into(), "$3, %r8b".into()),
            (0x14000287e, "ja".into(), "0x140003045".into()),
            (0x140002884, "mov".into(), "0xD0(%rbp), %rdx".into()),
            (0x14000288b, "lea".into(), "(%rdx,%rax), %r10".into()),
            (0x14000288f, "movzbl".into(), "%r8b, %edx".into()),
            (0x140002893, "lea".into(), "0x999C6(%rip), %r8".into()),
            (0x14000289a, "movslq".into(), "(%r8,%rdx,4), %rdx".into()),
            (0x14000289e, "add".into(), "%r8, %rdx".into()),
            (0x1400028a1, "jmp".into(), "*%rdx".into()),
        ];
        // bisezione: la stessa sequenza SENZA il `movzbl` che copia r8 in edx
        let mut senza_copia = raw.clone();
        senza_copia.retain(|(_, m, _)| m != "movzbl");
        eprintln!("[dbg] con movzbl  = {:?}", detect_jump_table_raw(&raw).is_some());
        eprintln!("[dbg] senza copia = {:?}", detect_jump_table_raw(&senza_copia).is_some());
        // e con il cmp direttamente sull indice rdx
        let mut cmp_su_idx = raw.clone();
        for e in cmp_su_idx.iter_mut() { if e.1 == "cmp" && e.2 == "$3, %r8b" { e.2 = "$3, %edx".into(); } }
        eprintln!("[dbg] cmp su edx  = {:?}", detect_jump_table_raw(&cmp_su_idx).is_some());
        let got = detect_jump_table_raw(&raw);
        assert!(got.is_some(), "forma canonica presente e limite a 8 istruzioni: deve trovarla");
    }
}
