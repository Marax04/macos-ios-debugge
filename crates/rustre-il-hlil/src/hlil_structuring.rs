//! HLIL structuring pipeline.
//!
//! Turns raw register-level HLIL (primitive `goto`/`while (1)` output from the
//! MLIL lifter) into readable, structured pseudo-C. The pipeline runs, in
//! order:
//!
//! 1. **Flag folding** — `flag = a < b; if (flag == 0)` → `if (a >= b)`.
//! 2. **Register → variable lifting** — `var_rax`/`rax` style names become
//!    `v1`, `v2`, … (`rsp`→`sp`, `rbp`→`fp`).
//! 3. **Structuring** — forward-`goto` → `if`, backward conditional `goto` →
//!    `do/while`, `while (1) { if (c) break; … }` → `while (!c) { … }`.
//! 4. **Forward expression propagation** — single-use pure assignments are
//!    substituted into the following statement.
//! 5. **Dead store elimination** — post-structuring removal of never-read
//!    pure assignments.
//! 6. **Induction variable detection** — `i = 0; while (i < n) { …; i = i + 1 }`
//!    → `for (i = 0; i < n; i = i + 1)`.
//! 7. **Opportunistic type inference** — `Unknown`-typed locals adopt the type
//!    of what is assigned to them / how they are dereferenced.
//!
//! All passes operate on the canonical [`HlilExpr`] variants produced by the
//! MLIL→HLIL lifter (see the "Duplicate variant families" note in `lib.rs`);
//! alternate optimizer-only variants are traversed but never constructed.

use std::collections::HashMap;

use rustre_core::address::Address;

use crate::{HlilExpr, HlilFunction, HlilStatement, HlilType, HlilVar};

// ── Generic expression traversal ─────────────────────────────────────────────

/// Visit every direct child expression of `e` mutably.
fn for_each_child_mut(e: &mut HlilExpr, f: &mut impl FnMut(&mut HlilExpr)) {
    use HlilExpr as E;
    match e {
        E::Const { .. }
        | E::Float { .. }
        | E::ConstFloat(_)
        | E::Var { .. }
        | E::AddressOf { .. }
        | E::SizeOf { .. }
        | E::Undefined(_) => {}
        E::Deref { addr, .. } => f(addr),
        E::FieldAccess { base, .. } => f(base),
        E::Index { base, idx, .. } => {
            f(base);
            f(idx);
        }
        E::ArrayIndex { array, index } => {
            f(array);
            f(index);
        }
        E::Add(a, b, _)
        | E::Sub(a, b, _)
        | E::Mul(a, b, _)
        | E::Div(a, b, _)
        | E::Mod(a, b, _)
        | E::And(a, b, _)
        | E::Or(a, b, _)
        | E::Xor(a, b, _)
        | E::Shl(a, b, _)
        | E::Shr(a, b, _)
        | E::CmpEq(a, b)
        | E::CmpNe(a, b)
        | E::CmpLt(a, b)
        | E::CmpGt(a, b)
        | E::CmpLe(a, b)
        | E::CmpGe(a, b)
        | E::LogicalAnd(a, b)
        | E::LogicalOr(a, b)
        | E::BitOr(a, b)
        | E::BitAnd(a, b)
        | E::BitXor(a, b)
        | E::BoolAnd(a, b)
        | E::BoolOr(a, b)
        | E::DivU(a, b)
        | E::DivS(a, b)
        | E::ModU(a, b)
        | E::ModS(a, b)
        | E::Sar(a, b)
        | E::CmpSlt(a, b)
        | E::CmpUlt(a, b)
        | E::CmpSle(a, b)
        | E::CmpUle(a, b)
        | E::CmpSgt(a, b)
        | E::CmpUgt(a, b)
        | E::CmpSge(a, b)
        | E::CmpUge(a, b) => {
            f(a);
            f(b);
        }
        E::Neg(x, _) | E::Not(x, _) | E::LogicalNot(x) | E::BoolNot(x) | E::AddrOf(x) => f(x),
        E::Cast { expr, .. } => f(expr),
        E::Call { func, args, .. } => {
            f(func);
            for a in args {
                f(a);
            }
        }
        E::Ternary {
            cond, then, else_, ..
        } => {
            f(cond);
            f(then);
            f(else_);
        }
        E::If {
            cond,
            then_branch,
            else_branch,
        } => {
            f(cond);
            f(then_branch);
            f(else_branch);
        }
    }
}

/// Replace every read of variable `name` in `e` with `rep` (deep).
fn subst_var(e: &mut HlilExpr, name: &str, rep: &HlilExpr) {
    if let HlilExpr::Var { var } = e {
        if var.name == name {
            *e = rep.clone();
            return;
        }
    }
    for_each_child_mut(e, &mut |c| subst_var(c, name, rep));
}

/// Count reads of variable `name` in `e` (deep). `AddressOf` counts as a use.
fn count_reads_expr(e: &HlilExpr, name: &str) -> usize {
    let mut n = 0;
    match e {
        HlilExpr::Var { var } | HlilExpr::AddressOf { var } if var.name == name => n += 1,
        _ => {}
    }
    // SAFETY of clone-free traversal: use an immutable recursive walk.
    let mut e2 = e.clone();
    for_each_child_mut(&mut e2, &mut |c| n += count_reads_expr(c, name));
    n
}

/// Whether `name`'s address is ever taken anywhere in `e`.
fn address_taken_expr(e: &HlilExpr, name: &str) -> bool {
    if let HlilExpr::AddressOf { var } = e {
        if var.name == name {
            return true;
        }
    }
    let mut found = false;
    let mut e2 = e.clone();
    for_each_child_mut(&mut e2, &mut |c| found |= address_taken_expr(c, name));
    found
}

/// All top-level expressions of a statement (immutable helper for read counts).
fn stmt_exprs(stmt: &HlilStatement) -> Vec<&HlilExpr> {
    use HlilStatement as S;
    match stmt {
        S::Expression(e) | S::Expr(e) => vec![e],
        S::Assign { dest, src } => vec![dest, src],
        S::AssignUnpack { src, .. } => vec![src],
        S::VarDeclare { init, .. } | S::VarDecl { init, .. } => {
            init.as_ref().map(|e| vec![e]).unwrap_or_default()
        }
        S::If { cond, .. } | S::While { cond, .. } | S::DoWhile { cond, .. } => vec![cond],
        S::For { cond, step, .. } => {
            let mut v = Vec::new();
            if let Some(c) = cond {
                v.push(c);
            }
            if let Some(s) = step {
                v.push(s);
            }
            v
        }
        S::Switch { value, .. } => vec![value],
        S::Return(es) => es.iter().collect(),
        _ => Vec::new(),
    }
}

/// All nested statement bodies of a statement.
/// Come [`stmt_bodies`], ma visibile al modulo del CFG: serve a
/// `cfg_from_hlil`, che deve percorrere i corpi annidati.
/// Accessore ai corpi annidati di uno statement, per i consumatori fuori dal
/// crate (sonde di `rustre-decompiler`).
pub fn stmt_bodies_pub(stmt: &HlilStatement) -> Vec<&Vec<HlilStatement>> {
    stmt_bodies(stmt)
}

fn stmt_bodies(stmt: &HlilStatement) -> Vec<&Vec<HlilStatement>> {
    use HlilStatement as S;
    match stmt {
        S::If {
            then_body,
            else_body,
            ..
        } => vec![then_body, else_body],
        S::While { body, .. } | S::DoWhile { body, .. } => vec![body],
        S::For { body, .. } => vec![body],
        S::Switch { cases, default, .. } => {
            let mut v: Vec<&Vec<HlilStatement>> = cases.iter().map(|c| &c.body).collect();
            v.push(default);
            v
        }
        S::Block(b) => vec![b],
        _ => Vec::new(),
    }
}

fn stmt_bodies_mut(stmt: &mut HlilStatement) -> Vec<&mut Vec<HlilStatement>> {
    use HlilStatement as S;
    match stmt {
        S::If {
            then_body,
            else_body,
            ..
        } => vec![then_body, else_body],
        S::While { body, .. } | S::DoWhile { body, .. } => vec![body],
        S::For { body, .. } => vec![body],
        S::Switch { cases, default, .. } => {
            let mut v: Vec<&mut Vec<HlilStatement>> =
                cases.iter_mut().map(|c| &mut c.body).collect();
            v.push(default);
            v
        }
        S::Block(b) => vec![b],
        _ => Vec::new(),
    }
}

/// Count reads of `name` in a statement, including nested bodies.
///
/// The `dest` of a plain-variable `Assign`/`VarDeclare` is a write, not a read;
/// a `Deref`/`Index` destination reads its address operands.
fn count_reads_stmt(stmt: &HlilStatement, name: &str) -> usize {
    use HlilStatement as S;
    let mut n = 0;
    match stmt {
        S::Assign { dest, src } => {
            n += count_reads_expr(src, name);
            match dest {
                HlilExpr::Var { .. } => {}
                other => n += count_reads_expr(other, name),
            }
        }
        S::For { init, .. } => {
            if let Some(i) = init {
                n += count_reads_stmt(i, name);
            }
            for e in stmt_exprs(stmt) {
                n += count_reads_expr(e, name);
            }
        }
        other => {
            for e in stmt_exprs(other) {
                n += count_reads_expr(e, name);
            }
        }
    }
    for body in stmt_bodies(stmt) {
        for s in body {
            n += count_reads_stmt(s, name);
        }
    }
    n
}

fn count_reads_stmts(stmts: &[HlilStatement], name: &str) -> usize {
    stmts.iter().map(|s| count_reads_stmt(s, name)).sum()
}

/// Whether any statement (deeply) writes plain variable `name`.
fn writes_var(stmts: &[HlilStatement], name: &str) -> bool {
    stmts.iter().any(|s| {
        let here = match s {
            HlilStatement::Assign {
                dest: HlilExpr::Var { var },
                ..
            } => var.name == name,
            HlilStatement::VarDeclare { var, .. } | HlilStatement::VarDecl { var, .. } => {
                var.name == name
            }
            HlilStatement::AssignUnpack { dests, .. } => dests.iter().any(|v| v.name == name),
            HlilStatement::For {
                init: Some(init), ..
            } => writes_var(std::slice::from_ref(init), name),
            _ => false,
        };
        here || stmt_bodies(s).iter().any(|b| writes_var(b, name))
    })
}

// ── 1. Flag folding ───────────────────────────────────────────────────────────

/// Is `e` a boolean-valued comparison suitable for flag folding?
const fn is_comparison(e: &HlilExpr) -> bool {
    use HlilExpr as E;
    matches!(
        e,
        E::CmpEq(..)
            | E::CmpNe(..)
            | E::CmpLt(..)
            | E::CmpGt(..)
            | E::CmpLe(..)
            | E::CmpGe(..)
            | E::CmpSlt(..)
            | E::CmpUlt(..)
            | E::CmpSle(..)
            | E::CmpUle(..)
            | E::CmpSgt(..)
            | E::CmpUgt(..)
            | E::CmpSge(..)
            | E::CmpUge(..)
            | E::LogicalNot(..)
            | E::BoolNot(..)
            | E::LogicalAnd(..)
            | E::LogicalOr(..)
    )
}

/// Logically negate a condition, flipping comparison operators where possible.
#[must_use]
pub fn negate_cond(e: HlilExpr) -> HlilExpr {
    use HlilExpr as E;
    match e {
        E::CmpEq(a, b) => E::CmpNe(a, b),
        E::CmpNe(a, b) => E::CmpEq(a, b),
        E::CmpLt(a, b) => E::CmpGe(a, b),
        E::CmpGe(a, b) => E::CmpLt(a, b),
        E::CmpGt(a, b) => E::CmpLe(a, b),
        E::CmpLe(a, b) => E::CmpGt(a, b),
        E::CmpSlt(a, b) => E::CmpSge(a, b),
        E::CmpSge(a, b) => E::CmpSlt(a, b),
        E::CmpSgt(a, b) => E::CmpSle(a, b),
        E::CmpSle(a, b) => E::CmpSgt(a, b),
        E::CmpUlt(a, b) => E::CmpUge(a, b),
        E::CmpUge(a, b) => E::CmpUlt(a, b),
        E::CmpUgt(a, b) => E::CmpUle(a, b),
        E::CmpUle(a, b) => E::CmpUgt(a, b),
        E::LogicalNot(inner) => *inner,
        E::BoolNot(inner) => *inner,
        other => E::LogicalNot(Box::new(other)),
    }
}

/// If `cond` is a test of flag variable `flag` (`flag`, `!flag`, `flag == 0`,
/// `flag != 0`), return the folded condition built from `cmp`.
fn fold_flag_cond(cond: &HlilExpr, flag: &str, cmp: &HlilExpr) -> Option<HlilExpr> {
    use HlilExpr as E;
    let is_flag = |e: &HlilExpr| matches!(e, E::Var { var } if var.name == flag);
    match cond {
        e if is_flag(e) => Some(cmp.clone()),
        E::LogicalNot(inner) | E::BoolNot(inner) if is_flag(inner) => {
            Some(negate_cond(cmp.clone()))
        }
        E::CmpEq(a, b) if is_flag(a) && b.is_const_zero() => Some(negate_cond(cmp.clone())),
        E::CmpNe(a, b) if is_flag(a) && b.is_const_zero() => Some(cmp.clone()),
        // `flag == 1` ≡ `flag`, `flag != 1` ≡ `!flag` (the setcc/jcc emits the
        // explicit `== 1` form as often as the bare flag).
        E::CmpEq(a, b) if is_flag(a) && b.is_const() == Some(1) => Some(cmp.clone()),
        E::CmpNe(a, b) if is_flag(a) && b.is_const() == Some(1) => Some(negate_cond(cmp.clone())),
        _ => None,
    }
}

/// Unify flag-variable naming: rename every `var_flag_<x>` to the bare
/// `flag_<x>` used by the condition expressions, so a flag DEFINITION
/// (`var_flag_zf = (tmp == 0)`, named by variable recovery) matches its USE
/// (`if (flag_zf == 1)`, from `MlilExpr::Flag`). Without this the def and use
/// are different variables and neither `fold_flags` nor `propagate_expressions`
/// can connect them. Returns the number of locals renamed.
pub fn normalize_flag_names(func: &mut HlilFunction) -> usize {
    let mut names = Vec::new();
    collect_var_names_in_order(&func.body, &mut names);
    for l in &func.locals {
        if !names.contains(&l.name) {
            names.push(l.name.clone());
        }
    }
    let map: HashMap<String, String> = names
        .iter()
        .filter_map(|n| n.strip_prefix("var_flag_").map(|s| (n.clone(), format!("flag_{s}"))))
        .collect();
    if map.is_empty() {
        return 0;
    }
    rename_in_stmts(&mut func.body, &map);
    for l in &mut func.locals {
        if let Some(n) = map.get(&l.name) {
            l.name = n.clone();
        }
    }
    // Il rename tocca il CORPO e le locali GIA' presenti: un nome che il
    // corpo cita ma che non ha voce fra le locali resterebbe SENZA
    // dichiarazione, e il C emesso non compila (`'v1' undeclared`).
    ensure_locals_cover_body(func);
    map.len()
}

/// Fold `flag = <cmp>; if (flag-test)` into `if (<folded cmp>)`, removing the
/// flag assignment when the flag is not read afterwards. Recurses into nested
/// bodies. Returns the number of folds performed.
pub fn fold_flags(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0;
    // Recurse first.
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            changed += fold_flags(body);
        }
    }
    let mut i = 0;
    while i + 1 < stmts.len() {
        let mut fold: Option<(String, HlilExpr)> = None;
        if let HlilStatement::Assign {
            dest: HlilExpr::Var { var },
            src,
        } = &stmts[i]
        {
            if is_comparison(src) && src.is_pure() {
                if let HlilStatement::If { cond, .. } = &stmts[i + 1] {
                    if let Some(folded) = fold_flag_cond(cond, &var.name, src) {
                        fold = Some((var.name.clone(), folded));
                    }
                }
            }
        }
        if let Some((flag, folded)) = fold {
            if let HlilStatement::If { cond, .. } = &mut stmts[i + 1] {
                *cond = folded;
            }
            changed += 1;
            // Drop the flag assignment when the flag is dead afterwards.
            if count_reads_stmts(&stmts[i + 1..], &flag) == 0
                && count_reads_stmts(&stmts[..i], &flag) == 0
            {
                stmts.remove(i);
                continue;
            }
        }
        i += 1;
    }
    changed
}

/// True if `e` is the flag variable `flag_<suffix>` (or `var_flag_<suffix>`),
/// case-insensitively (the lifter emits `flag_sf`/`flag_ZF` inconsistently).
/// #3750 — sonda diagnostica, sotto il gate di debug gia' esistente. Non tocca
/// MAI il codice emesso: stampa solo su stderr.
fn probe_enabled() -> bool {
    matches!(
        std::env::var("RUSTRE_HLIL_DEBUG").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// #3720 — riconoscere SF dato come ESPRESSIONE (`(tmp < 0)`) e non come
/// variabile `flag_sf`. OPT-IN finche' non e' misurato sul corpus: allarga
/// l'aggancio di `fold_flag_combos`, quindi puo' cambiare il codice emesso.
fn sf_expr_enabled() -> bool {
    matches!(
        std::env::var("RUSTRE_HLIL_SFEXPR").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn is_flag_var(e: &HlilExpr, suffix: &str) -> bool {
    matches!(e, HlilExpr::Var { var }
        if var.name.eq_ignore_ascii_case(&format!("flag_{suffix}"))
        || var.name.eq_ignore_ascii_case(&format!("var_flag_{suffix}")))
}

/// The `(a, b)` of an `Assign { src: Sub(a, b) }` statement — the CMP/SUB that
/// implicitly set the x86 flags a following conditional tests.
fn sub_operands(stmt: &HlilStatement) -> Option<(HlilExpr, HlilExpr)> {
    if let HlilStatement::Assign { src: HlilExpr::Sub(a, b, _), .. } = stmt {
        Some((*a.clone(), *b.clone()))
    } else {
        None
    }
}

/// Operands of the last `tmp = (a - b)` in a loop body — the SUB whose flags a
/// do/while back-edge condition tests.
fn last_sub_operands(body: &[HlilStatement]) -> Option<(HlilExpr, HlilExpr)> {
    body.iter().rev().find_map(sub_operands)
}

/// True for a leftover flag-definition assignment (`flag_zf = (tmp == 0)`, whose
/// LHS carries `flag` in its name) — the dead ZF/SF/… computation that sits
/// between the defining SUB and the conditional.
fn is_flag_def_assign(stmt: &HlilStatement) -> bool {
    matches!(stmt, HlilStatement::Assign { dest: HlilExpr::Var { var }, .. }
        if var.name.contains("flag"))
}

/// #3770 — CLASSE A, misurata in **2921 casi** (43% dei mancati agganci): su x86
/// i flag li posa anche `test`/`and`, che nell'IL arriva come `Assign{src: And}`,
/// mentre `fold_flag_combos` cercava SOLO una SUB. Per `test a, b` vale
/// **ZF = `(a & b) == 0`**, e l'aggancio e' ESATTO per costruzione.
fn and_operands(stmt: &HlilStatement) -> Option<(HlilExpr, HlilExpr)> {
    if let HlilStatement::Assign { src: HlilExpr::And(a, b, _), .. } = stmt {
        Some((*a.clone(), *b.clone()))
    } else {
        None
    }
}

/// #4200 — RECUPERO ZF. Il TEMPORANEO della SUB (`tmp = a - b`) e' calcolato
/// PRIMA di qualunque ridefinizione successiva degli operandi, quindi
/// `ZF` ⟺ `tmp == 0` resta valido **anche quando l'aggancio normale e' stato
/// rifiutato** perche' un operando e' stato riscritto fra la CMP e il salto.
/// Misurati **1315** casi cosi' (#4190).
/// ⚠ Vale SOLO per l'uguaglianza: `SF != OF` dipende dalla LARGHEZZA del `cmp`
/// (bit 31 o 63) e non e' esprimibile sul solo `tmp` — quelle forme (845)
/// restano fuori, deliberatamente.
fn nearest_sub_temp_before(stmts: &[HlilStatement], idx: usize) -> Option<String> {
    let mut j = idx;
    while j > 0 {
        j -= 1;
        if let HlilStatement::Assign { dest: HlilExpr::Var { var }, src: HlilExpr::Sub(..) } =
            &stmts[j]
        {
            return Some(var.name.clone());
        }
        if matches!(
            &stmts[j],
            HlilStatement::Assign { .. } | HlilStatement::Label(_)
        ) {
            continue;
        }
        break;
    }
    None
}

/// Le sole forme di UGUAGLIANZA, riscritte sul temporaneo: `tmp == 0` / `tmp != 0`.
/// Restituisce `None` per ogni condizione che nomini `sf`, `of` o `cf`.
fn zf_only_on_temp(cond: &HlilExpr, temp: &str) -> Option<HlilExpr> {
    use HlilExpr as E;
    if let E::LogicalNot(inner) | E::BoolNot(inner) = cond {
        return zf_only_on_temp(inner, temp).map(negate_cond);
    }
    let d = format!("{cond:?}");
    if d.contains("flag_sf") || d.contains("flag_of") || d.contains("flag_cf") {
        return None;
    }
    let t = || Box::new(E::Var { var: crate::HlilVar::new(temp, HlilType::i64()) });
    let zero = || Box::new(E::Const { value: 0, ty: HlilType::i64() });
    let one = |e: &E| e.is_const() == Some(1);
    match cond {
        E::Var { .. } if is_flag_var(cond, "zf") => Some(E::CmpEq(t(), zero())),
        E::CmpEq(x, k) if is_flag_var(x, "zf") && one(k) => Some(E::CmpEq(t(), zero())),
        E::CmpNe(x, k) if is_flag_var(x, "zf") && k.is_const_zero() => Some(E::CmpEq(t(), zero())),
        E::CmpEq(x, k) if is_flag_var(x, "zf") && k.is_const_zero() => Some(E::CmpNe(t(), zero())),
        E::CmpNe(x, k) if is_flag_var(x, "zf") && one(k) => Some(E::CmpNe(t(), zero())),
        _ => None,
    }
}

/// #4200 — recupero ZF sui rifiuti. DEFAULT-ON dal 2026-08-18 (#6790);
/// si spegne con `RUSTRE_HLIL_ZFTEMP=0`.
///
/// Isolato sul corpus intero (11342 file, unico gate acceso oltre a
/// `RUSTRE_HLIL`): `flag_` 42039 -> 37760 (**−4279, −10,2%**), righe −1601.
/// Costo: `var_tmp*` +1446 (+3,2%) e 12 `var_sp` che riaffiorano.
/// Non e' un guadagno puro ma uno SCAMBIO, e il saldo sui nomi cattivi e'
/// −2833. path A invariato (`diff -rq`, 0 differenze).
fn zf_temp_enabled() -> bool {
    !matches!(
        std::env::var("RUSTRE_HLIL_ZFTEMP").as_deref(),
        Ok("0") | Ok("false")
    )
}

/// Come [`nearest_sub_before`] ma per l'AND di un `test`.
fn nearest_and_before(stmts: &[HlilStatement], idx: usize) -> Option<(HlilExpr, HlilExpr)> {
    let mut j = idx;
    while j > 0 {
        j -= 1;
        if let Some(ops) = and_operands(&stmts[j]) {
            return Some(ops);
        }
        if is_flag_def_assign(&stmts[j]) {
            continue;
        }
        return None;
    }
    None
}

/// Le SOLE forme ZF, riscritte contro `(a & b)`.
///
/// ⚠ Deliberatamente **solo ZF**. Con `test` l'overflow flag e' **0 per
/// definizione**, quindi `jl`/`jg` (`SF != OF`) degenerano in un test di SEGNO
/// puro: e' il caso in cui la LARGHEZZA conta (SF e' il bit 31 per un `test` a
/// 32 bit, il 63 a 64) e la larghezza NON e' nell'espressione (#3690). Tradurli
/// darebbe codice che compila ed e' SBAGLIATO — il difetto peggiore.
fn zf_combo_to_cmp(cond: &HlilExpr, a: &HlilExpr, b: &HlilExpr) -> Option<HlilExpr> {
    use HlilExpr as E;
    if let E::LogicalNot(inner) | E::BoolNot(inner) = cond {
        return zf_combo_to_cmp(inner, a, b).map(negate_cond);
    }
    let masked = E::And(
        Box::new(a.clone()),
        Box::new(b.clone()),
        HlilType::i64(),
    );
    let zero = E::Const { value: 0, ty: HlilType::i64() };
    let mk = |f: fn(Box<E>, Box<E>) -> E| Some(f(Box::new(masked.clone()), Box::new(zero.clone())));
    let one = |e: &E| e.is_const() == Some(1);
    match cond {
        // je = ZF  →  `(a & b) == 0`
        E::Var { .. } if is_flag_var(cond, "zf") => mk(E::CmpEq),
        E::CmpEq(x, k) if is_flag_var(x, "zf") && one(k) => mk(E::CmpEq),
        E::CmpNe(x, k) if is_flag_var(x, "zf") && k.is_const_zero() => mk(E::CmpEq),
        // jne = !ZF  →  `(a & b) != 0`
        E::CmpEq(x, k) if is_flag_var(x, "zf") && k.is_const_zero() => mk(E::CmpNe),
        E::CmpNe(x, k) if is_flag_var(x, "zf") && one(k) => mk(E::CmpNe),
        _ => None,
    }
}

/// #3970 — gate OPT-IN della CLASSE B (istruzioni innocue fra CMP e salto).
fn class_b_enabled() -> bool {
    matches!(
        std::env::var("RUSTRE_HLIL_SKIPINNOCUOUS").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// #3900 — CLASSE C (il `cmov`/ternario). DEFAULT-ON dal 2026-08-18 (#6790);
/// si spegne con `RUSTRE_HLIL_CMOVFOLD=0`.
///
/// Isolato sul corpus intero: `flag_` 42039 -> 40676 (−1363), `var_tmp*` −28,
/// righe −651, tutto il resto identico. Guadagno PURO, nessun contatore
/// peggiora. path A invariato.
fn cmov_fold_enabled() -> bool {
    !matches!(
        std::env::var("RUSTRE_HLIL_CMOVFOLD").as_deref(),
        Ok("0") | Ok("false")
    )
}

/// #3770 — gate OPT-IN della CLASSE A finche' non e' misurata sul corpus.
fn test_flags_enabled() -> bool {
    matches!(
        std::env::var("RUSTRE_HLIL_TESTFLAGS").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Operands of the nearest `tmp = (a - b)` at or before `idx`, skipping only
/// intervening flag-definition assignments (`flag_zf = (tmp == 0)`). Stops at
/// any other statement so a distant, unrelated SUB is never grabbed.
fn nearest_sub_before(stmts: &[HlilStatement], idx: usize) -> Option<(HlilExpr, HlilExpr)> {
    nearest_sub_before_with(stmts, idx, class_b_enabled())
}

/// La LOGICA, col salto delle istruzioni innocue passato come PARAMETRO: il test
/// unitario deve poter provare **il rifiuto**, e una lettura d'ambiente lo
/// renderebbe dipendente dall'ordine di esecuzione (lezione #3650).
fn nearest_sub_before_with(
    stmts: &[HlilStatement],
    idx: usize,
    salta_innocue: bool,
) -> Option<(HlilExpr, HlilExpr)> {
    let mut j = idx;
    // #3970 — CLASSE B: gli indici SALTATI, per poterli poi verificare contro
    // gli operandi della SUB trovata.
    let mut saltati: Vec<usize> = Vec::new();
    while j > 0 {
        j -= 1;
        if let Some((a, b)) = sub_operands(&stmts[j]) {
            // Un'istruzione qualunque fra la CMP e il salto e' innocua SOLO se
            // non ridefinisce un operando della SUB: altrimenti il confronto
            // ricostruito userebbe valori diversi da quelli che hanno posato i
            // flag — codice che compila ed e' SBAGLIATO.
            if !saltati.is_empty() {
                let operandi = format!("{a:?} {b:?}");
                // #4100 — la memoria: un `*(p) = x` fra CMP e salto non puo'
                // ridefinire un REGISTRO, ma potrebbe scrivere proprio la cella
                // che un operando LEGGE. L'aliasing non e' decidibile qui,
                // quindi la regola e' netta: lo si salta **solo se nessuno dei
                // due operandi contiene una lettura di memoria**. Se un operando
                // e' un `Deref`, si rinuncia — meglio non agganciare che
                // agganciare su un valore che nel frattempo puo' essere cambiato.
                let operandi_leggono_memoria = operandi.contains("Deref");
                let sicuro = saltati.iter().all(|&k| match &stmts[k] {
                    HlilStatement::Assign { dest: HlilExpr::Var { var }, .. } => {
                        !operandi.contains(&format!("\"{}\"", var.name))
                    }
                    HlilStatement::Assign { dest: HlilExpr::Deref { .. }, .. } => {
                        !operandi_leggono_memoria
                    }
                    _ => false,
                });
                if !sicuro {
                    return None;
                }
            }
            return Some((a, b));
        }
        if is_flag_def_assign(&stmts[j]) {
            continue;
        }
        // #3970 — misurato: 1272 `Assign/Var` + 1171 `Assign/Cast` + 667 `Label`
        // fra CMP e salto facevano perdere l'aggancio. Saltarli e' lecito solo
        // sotto verifica (sopra) e sotto gate.
        if salta_innocue
            && matches!(
                &stmts[j],
                HlilStatement::Assign { dest: HlilExpr::Var { .. }, .. }
                    | HlilStatement::Assign { dest: HlilExpr::Deref { .. }, .. }
                    | HlilStatement::Label(_)
            )
        {
            saltati.push(j);
            continue;
        }
        return None;
    }
    None
}

/// Map an x86 conditional-jump FLAG-COMBINATION condition to the signed/unsigned
/// comparison of the SUB operands `a`, `b` that set the flags. `fold_flags`
/// only handles a single flag assigned a comparison; the real x86 jcc idioms
/// combine flags (`SF != OF` = signed `<`, etc.) and their defining flag SETs
/// were dropped as dead, so the condition holds bare `flag_*` vars with no
/// nearby `flag = cmp`. Returns `None` for anything not a recognised idiom.
/// The two operands of any And-family node (`want_or == false`) or Or-family
/// node (`want_or == true`) — the compound flag test of a signed `jle`/`jg`.
fn as_and_or_pair(e: &HlilExpr, want_or: bool) -> Option<(&HlilExpr, &HlilExpr)> {
    use HlilExpr as E;
    match e {
        E::Or(x, y, _) | E::LogicalOr(x, y) | E::BitOr(x, y) | E::BoolOr(x, y) if want_or => {
            Some((x, y))
        }
        E::And(x, y, _) | E::LogicalAnd(x, y) | E::BitAnd(x, y) | E::BoolAnd(x, y) if !want_or => {
            Some((x, y))
        }
        _ => None,
    }
}

fn flag_combo_to_cmp(cond: &HlilExpr, a: &HlilExpr, b: &HlilExpr) -> Option<HlilExpr> {
    flag_combo_to_cmp_with(cond, a, b, sf_expr_enabled())
}

/// La LOGICA, col riconoscimento di SF-come-espressione passato come PARAMETRO
/// invece che letto dall'ambiente: cosi' il test unitario prova la logica e non
/// lo stato di una variabile d'ambiente, che e' globale al processo e renderebbe
/// il test dipendente dall'ordine di esecuzione (lezione #3650).
fn flag_combo_to_cmp_with(
    cond: &HlilExpr,
    a: &HlilExpr,
    b: &HlilExpr,
    sf_expr: bool,
) -> Option<HlilExpr> {
    use HlilExpr as E;
    // A negated flag condition (`!(flag_zf == 0)` = `je`) folds its inner form,
    // then negates the resulting comparison.
    if let E::LogicalNot(inner) | E::BoolNot(inner) = cond {
        return flag_combo_to_cmp_with(inner, a, b, sf_expr).map(negate_cond);
    }
    let mk = |f: fn(Box<E>, Box<E>) -> E| Some(f(Box::new(a.clone()), Box::new(b.clone())));
    let one = |e: &E| e.is_const() == Some(1);
    // #3720 — SF puo' arrivare come ESPRESSIONE invece che come variabile:
    // `(tmp < 0)` o `((a - b) < 0)`. Misurato sul corpus (path B): 710 condizioni
    // `if` contengono un test di segno gia' inlinato, e li' `is_flag_var` fallisce
    // ⇒ il fold non aggancia, la condizione resta aritmetica di flag e per giunta
    // su variabili `uintN_t`, dove `x < 0` e' COSTANTEMENTE FALSO (#3670).
    let sf_like = |e: &E| {
        if is_flag_var(e, "sf") {
            return true;
        }
        if !sf_expr {
            return false;
        }
        // Solo il segno del risultato DELLA SUB che ha posato i flag: il temporaneo
        // che la contiene (una `Var`) o la sottrazione stessa con gli stessi
        // operandi. Un `(qualunque_cosa < 0)` NON basta, sarebbe un aggancio cieco.
        match e {
            E::CmpLt(x, z) if z.is_const_zero() => match &**x {
                E::Var { .. } => true,
                E::Sub(p, q, _) => **p == *a && **q == *b,
                _ => false,
            },
            _ => false,
        }
    };
    let sf_of = |x: &E, y: &E| {
        (sf_like(x) && is_flag_var(y, "of")) || (is_flag_var(x, "of") && sf_like(y))
    };
    // `SF != OF` / `SF == OF` sub-terms of a compound signed condition.
    let is_sf_ne_of = |e: &E| matches!(e, E::CmpNe(x, y) if sf_of(x, y));
    let is_sf_eq_of = |e: &E| matches!(e, E::CmpEq(x, y) if sf_of(x, y));
    // `ZF == v` (or bare `flag_zf` ≡ `ZF == 1`); same shape for CF.
    let is_flag_eq = |e: &E, flag: &str, v: i64| {
        matches!(e, E::CmpEq(x, c) if is_flag_var(x, flag) && c.is_const() == Some(v))
            || matches!(e, E::CmpNe(x, c) if is_flag_var(x, flag) && c.is_const() == Some(1 - v))
            || (v == 1 && is_flag_var(e, flag))
    };
    let is_zf = |e: &E, v: i64| is_flag_eq(e, "zf", v);
    let is_cf = |e: &E, v: i64| is_flag_eq(e, "cf", v);
    // A compound test where {p, q} match (in either operand order).
    let both = |x: &E, y: &E, p: &dyn Fn(&E) -> bool, q: &dyn Fn(&E) -> bool| {
        (p(x) && q(y)) || (p(y) && q(x))
    };
    // Compound idioms first (jle/jg signed, jbe/ja unsigned), then simple ones.
    if let Some((x, y)) = as_and_or_pair(cond, true) {
        if both(x, y, &|e| is_zf(e, 1), &is_sf_ne_of) {
            return mk(E::CmpLe); // jle: ZF | (SF != OF)
        }
        if both(x, y, &|e| is_cf(e, 1), &|e| is_zf(e, 1)) {
            return mk(E::CmpLe); // jbe: CF | ZF (unsigned)
        }
    }
    if let Some((x, y)) = as_and_or_pair(cond, false) {
        if both(x, y, &|e| is_zf(e, 0), &is_sf_eq_of) {
            return mk(E::CmpGt); // jg: !ZF & (SF == OF)
        }
        if both(x, y, &|e| is_cf(e, 0), &|e| is_zf(e, 0)) {
            return mk(E::CmpGt); // ja: !CF & !ZF (unsigned)
        }
    }
    match cond {
        // Signed: jl = SF != OF, jge = SF == OF.
        E::CmpNe(x, y) if sf_of(x, y) => mk(E::CmpLt),
        E::CmpEq(x, y) if sf_of(x, y) => mk(E::CmpGe),
        // Equality: je = ZF, jne = !ZF.
        E::Var { .. } if is_flag_var(cond, "zf") => mk(E::CmpEq),
        E::CmpEq(x, c) if is_flag_var(x, "zf") && one(c) => mk(E::CmpEq),
        E::CmpNe(x, c) if is_flag_var(x, "zf") && c.is_const_zero() => mk(E::CmpEq),
        E::CmpEq(x, c) if is_flag_var(x, "zf") && c.is_const_zero() => mk(E::CmpNe),
        E::CmpNe(x, c) if is_flag_var(x, "zf") && one(c) => mk(E::CmpNe),
        // Unsigned: jb = CF → `<`, jae = !CF → `>=` (canonical cmps cover both
        // signed and unsigned per the duplicate-variant note).
        E::Var { .. } if is_flag_var(cond, "cf") => mk(E::CmpLt),
        E::CmpEq(x, c) if is_flag_var(x, "cf") && one(c) => mk(E::CmpLt),
        E::CmpNe(x, c) if is_flag_var(x, "cf") && one(c) => mk(E::CmpGe),
        E::CmpEq(x, c) if is_flag_var(x, "cf") && c.is_const_zero() => mk(E::CmpGe),
        _ => None,
    }
}

/// Fold x86 conditional-jump flag-combination idioms into a real comparison of
/// the operands of the SUB/CMP that set the flags (see [`flag_combo_to_cmp`]).
/// Handles the do/while back-edge (SUB is the last body statement) and the
/// `if`-after-CMP (SUB is the immediately preceding statement). Returns the
/// number of conditions folded. Runs before `eliminate_dead_stores`, which then
/// drops the now-unused `tmp = (a - b)`.
pub fn fold_flag_combos(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0;
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            changed += fold_flag_combos(body);
        }
        match s {
            HlilStatement::DoWhile { body, cond } | HlilStatement::While { body, cond } => {
                if let Some((a, b)) = last_sub_operands(body)
                    && let Some(folded) = flag_combo_to_cmp(cond, &a, &b)
                {
                    *cond = folded;
                    changed += 1;
                }
            }
            _ => {}
        }
    }
    // `if (flag-combo)` whose defining SUB precedes it (possibly with a leftover
    // `flag_zf = (tmp == 0)` assignment in between).
    for i in 1..stmts.len() {
        // #3750 — SONDA (solo `RUSTRE_HLIL_DEBUG=1`, nessun effetto sull'emesso):
        // di ogni `if` la cui condizione MENZIONA un flag, dire se l'aggancio e'
        // fallito per SUB NON TROVATA o perche' la forma non e' riconosciuta.
        // #3740 ha dimostrato che dedurre la causa dal testo emesso non funziona.
        if probe_enabled()
            && let HlilStatement::If { cond, .. } = &stmts[i]
            && format!("{cond:?}").contains("flag_")
        {
            let esito = match nearest_sub_before(stmts, i) {
                None => {
                    // #4160 — la sonda VECCHIA riportava il primo statement
                    // incontrato, cioe' rispondeva alla domanda di PRIMA che
                    // `SKIPINNOCUOUS` esistesse (#4150). Ora distingue i due
                    // casi che contano davvero:
                    //  · `assente`  = camminando all'indietro NON c'e' nessuna
                    //                 SUB (nulla da agganciare);
                    //  · `rifiutata`= la SUB c'e', ma il controllo di sicurezza
                    //                 l'ha scartata perche' uno statement
                    //                 saltato ridefinisce un suo operando.
                    // Solo `rifiutata` misura quanto costa la prudenza.
                    let mut permissiva = None;
                    let mut j2 = i;
                    while j2 > 0 {
                        j2 -= 1;
                        if let Some(ops) = sub_operands(&stmts[j2]) {
                            permissiva = Some(ops);
                            break;
                        }
                        if matches!(
                            &stmts[j2],
                            HlilStatement::Assign { .. } | HlilStatement::Label(_)
                        ) {
                            continue;
                        }
                        break;
                    }
                    // #4190 — dei RIFIUTI, quanti hanno una condizione di sola
                    // UGUAGLIANZA (ZF)? Quelli sono recuperabili in modo esatto
                    // usando il TEMPORANEO della SUB (`tmp == 0`), che non
                    // risente della ridefinizione successiva degli operandi;
                    // le forme con SEGNO no, perche' `SF != OF` dipende dalla
                    // larghezza e non e' esprimibile sul solo `tmp`.
                    let solo_zf = {
                        let d = format!("{cond:?}");
                        d.contains("flag_zf") && !d.contains("flag_sf") && !d.contains("flag_of")
                            && !d.contains("flag_cf")
                    };
                    eprintln!(
                        "FOLDSTOP causa={}{}",
                        if permissiva.is_some() { "rifiutata" } else { "assente" },
                        if permissiva.is_some() && solo_zf { " zf=si" } else { "" }
                    );
                    "no_sub"
                }
                Some((a, b)) => {
                    if flag_combo_to_cmp(cond, &a, &b).is_some() {
                        "fold"
                    } else {
                        "no_forma"
                    }
                }
            };
            eprintln!("FOLDIF esito={esito}");
        }
        if let Some((a, b)) = nearest_sub_before(stmts, i)
            && let HlilStatement::If { cond, .. } = &stmts[i]
            && let Some(folded) = flag_combo_to_cmp(cond, &a, &b)
        {
            if let HlilStatement::If { cond, .. } = &mut stmts[i] {
                *cond = folded;
            }
            changed += 1;
            continue;
        }
        // #3900 — CLASSE C: il `cmov`. Arriva come `Assign` la cui sorgente e'
        // un TERNARIO, forma che i due rami sopra non guardano affatto (toccano
        // solo `While`/`DoWhile`/`If`). Misurati 145 casi sul corpus, ed e'
        // **l'unica classe che riguarda `find_max`**, dove la condizione non
        // agganciata diventa `(x < 0)` su `uintN_t` — costantemente falsa, quindi
        // il massimo non viene mai aggiornato (#3670).
        if cmov_fold_enabled()
            && let Some((a, b)) = nearest_sub_before(stmts, i)
            && let HlilStatement::Assign { src: HlilExpr::Ternary { cond, .. }, .. } = &stmts[i]
            && let Some(folded) = flag_combo_to_cmp(cond, &a, &b)
            && let HlilStatement::Assign { src: HlilExpr::Ternary { cond, .. }, .. } =
                &mut stmts[i]
        {
            *cond = Box::new(folded);
            changed += 1;
            continue;
        }
        // #4200 — l'aggancio normale ha RIFIUTATO (un operando e' stato
        // ridefinito fra la CMP e il salto), ma se la condizione e' di sola
        // UGUAGLIANZA si puo' ancora riscrivere sul TEMPORANEO: `tmp == 0` non
        // dipende dai valori correnti degli operandi. 1315 casi misurati (#4190).
        if zf_temp_enabled()
            && nearest_sub_before(stmts, i).is_none()
            && let Some(temp) = nearest_sub_temp_before(stmts, i)
            && let HlilStatement::If { cond, .. } = &stmts[i]
            && let Some(folded) = zf_only_on_temp(cond, &temp)
        {
            if let HlilStatement::If { cond, .. } = &mut stmts[i] {
                *cond = folded;
            }
            changed += 1;
            continue;
        }
        // #3770 — nessuna SUB: i flag possono venire da un `test` (`Assign{src:
        // And}`). Solo le forme ZF, per la ragione spiegata in `zf_combo_to_cmp`.
        if test_flags_enabled()
            && let Some((a, b)) = nearest_and_before(stmts, i)
            && let HlilStatement::If { cond, .. } = &stmts[i]
            && let Some(folded) = zf_combo_to_cmp(cond, &a, &b)
        {
            if let HlilStatement::If { cond, .. } = &mut stmts[i] {
                *cond = folded;
            }
            changed += 1;
        }
    }
    changed
}

// ── 2. Register → variable lifting ───────────────────────────────────────────

const GP_REGS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ax", "bx", "cx", "dx", "al", "bl", "cl",
    "dl",
];

/// The bare register a variable name stands for, with the `var_`/`reg_` prefix
/// stripped — no width canonicalisation.
fn arg_reg_raw(name: &str) -> Option<&str> {
    let base = name
        .strip_prefix("var_")
        .or_else(|| name.strip_prefix("reg_"))
        .unwrap_or(name);
    (!base.is_empty()).then_some(base)
}

/// The 64-bit Win64 ARGUMENT register a variable name stands for, mapping every
/// narrower view onto its parent: `edx`/`dx`/`dl` all denote `rdx`.
///
/// Deliberately limited to the four argument registers. Widening
/// `register_base`/`GP_REGS` instead would also change how `lift_registers`
/// names every other register, which is a much larger blast radius for no gain
/// here.
fn arg_reg_of(name: &str) -> Option<&'static str> {
    let base = arg_reg_raw(name)?;
    Some(match base {
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        // The four SSE argument slots. In Win64 an integer and a floating-point
        // argument SHARE a position (`f(int, double)` = slot 1 in `rcx`, slot 2
        // in `xmm1`), so a slot the caller flagged in the SSE register file
        // arrives here as `xmm{i}` and must bind the body's `var_xmm{i}` local.
        // Without these arms the caller's parameter was still declared (the
        // "declare even if unused" rule below) while the body kept reading
        // `var_xmm{i}` — a local read and never written, plus a parameter typed
        // from the default instead of from the caller's `cty`.
        // No narrower views: unlike the GP registers, the emitter spells the SSE
        // storage one way only.
        "xmm0" => "xmm0",
        "xmm1" => "xmm1",
        "xmm2" => "xmm2",
        "xmm3" => "xmm3",
        _ => return None,
    })
}

/// The HLIL type a caller-supplied C type name denotes, for the cases where the
/// caller knows the parameter's type better than the body does.
///
/// Deliberately floating-point ONLY. For an integer slot the type is taken from
/// the widest register view present in the body (see `promote_arg_registers`),
/// which is measured behaviour worth keeping; but an SSE slot's local carries
/// the storage type (`unsigned __int128` for `var_xmm3`), not the argument's,
/// so for those the caller's `cty` is the more reliable source.
/// Whether any statement that mentions one of `names` also applies a BITWISE
/// operator, in which case the slot carries a bit pattern and must NOT be typed
/// floating-point.
///
/// Measured: typing every SSE argument slot `double` broke two files with
/// `error: wrong type argument to bit-complement` on `a2 = (~a2 & var_xmm0);`
/// — the `andnps`/`andnpd` mask idiom (`fabs`/`copysign` and friends). The slot
/// really is an incoming argument, so the BINDING is right; only the type was.
///
/// Deliberately COARSE and conservative: it tests the statement's derived
/// `Debug` form, so a bitwise operator anywhere in a statement mentioning the
/// name is enough to decline the float type. Two consequences, both wanted:
/// declining costs only signature prettiness (the slot keeps the storage type
/// and still binds), while a false NEGATIVE would emit code no C compiler
/// accepts. Using `Debug` rather than a hand-written walker also means every
/// present and future statement/expression variant is covered by construction —
/// a walker that missed one variant would silently mistype that shape.
fn bitwise_use_of_any(stmts: &[HlilStatement], names: &[String]) -> bool {
    // Canonical AND alternate variant families both matter here: the lifter
    // emits the canonical ones, the optimizer constructs the alternate ones,
    // and a pass that matches only one family silently no-ops on real input.
    const BITWISE: [&str; 9] = [
        "And(", "Or(", "Xor(", "Not(", "Shl(", "Shr(", "BitAnd(", "BitOr(", "BitXor(",
    ];
    stmts.iter().any(|s| {
        let d = format!("{s:?}");
        names.iter().any(|n| d.contains(n.as_str())) && BITWISE.iter().any(|op| d.contains(op))
    })
}

fn float_type_from_cty(cty: &str) -> Option<HlilType> {
    match cty.trim() {
        "double" => Some(HlilType::Float { bits: 64 }),
        "float" => Some(HlilType::Float { bits: 32 }),
        _ => None,
    }
}

/// If `name` looks like a register-derived variable (`rax`, `var_rax`,
/// `reg_rax`), return the bare register name.
fn register_base(name: &str) -> Option<&str> {
    let base = name
        .strip_prefix("var_")
        .or_else(|| name.strip_prefix("reg_"))
        .unwrap_or(name);
    if base == "rsp" || base == "esp" || base == "rbp" || base == "ebp" {
        return Some(base);
    }
    GP_REGS.contains(&base).then_some(base)
}

/// Collect variable names in first-use order across the function body.
fn collect_var_names_in_order(stmts: &[HlilStatement], out: &mut Vec<String>) {
    fn expr_names(e: &HlilExpr, out: &mut Vec<String>) {
        match e {
            HlilExpr::Var { var } | HlilExpr::AddressOf { var } => {
                if !out.contains(&var.name) {
                    out.push(var.name.clone());
                }
            }
            _ => {}
        }
        let mut e2 = e.clone();
        for_each_child_mut(&mut e2, &mut |c| expr_names(c, out));
    }
    for s in stmts {
        if let HlilStatement::For {
            init: Some(init), ..
        } = s
        {
            collect_var_names_in_order(std::slice::from_ref(init), out);
        }
        if let HlilStatement::VarDeclare { var, .. } | HlilStatement::VarDecl { var, .. } = s {
            if !out.contains(&var.name) {
                out.push(var.name.clone());
            }
        }
        for e in stmt_exprs(s) {
            expr_names(e, out);
        }
        for body in stmt_bodies(s) {
            collect_var_names_in_order(body, out);
        }
    }
}

fn rename_in_expr(e: &mut HlilExpr, map: &HashMap<String, String>) {
    match e {
        HlilExpr::Var { var } | HlilExpr::AddressOf { var } => {
            if let Some(n) = map.get(&var.name) {
                var.name = n.clone();
            }
        }
        _ => {}
    }
    for_each_child_mut(e, &mut |c| rename_in_expr(c, map));
}

fn stmt_exprs_mut(stmt: &mut HlilStatement) -> Vec<&mut HlilExpr> {
    use HlilStatement as S;
    match stmt {
        S::Expression(e) | S::Expr(e) => vec![e],
        S::Assign { dest, src } => vec![dest, src],
        S::AssignUnpack { src, .. } => vec![src],
        S::VarDeclare { init, .. } | S::VarDecl { init, .. } => {
            init.as_mut().map(|e| vec![e]).unwrap_or_default()
        }
        S::If { cond, .. } | S::While { cond, .. } | S::DoWhile { cond, .. } => vec![cond],
        S::For { cond, step, .. } => {
            let mut v = Vec::new();
            if let Some(c) = cond {
                v.push(c);
            }
            if let Some(s) = step {
                v.push(s);
            }
            v
        }
        S::Switch { value, .. } => vec![value],
        S::Return(es) => es.iter_mut().collect(),
        _ => Vec::new(),
    }
}

fn rename_in_stmts(stmts: &mut [HlilStatement], map: &HashMap<String, String>) {
    for s in stmts {
        if let HlilStatement::VarDeclare { var, .. }
        | HlilStatement::VarDecl { var, .. } = s
        {
            if let Some(n) = map.get(&var.name) {
                var.name = n.clone();
            }
        }
        if let HlilStatement::AssignUnpack { dests, .. } = s {
            for v in dests {
                if let Some(n) = map.get(&v.name) {
                    v.name = n.clone();
                }
            }
        }
        if let HlilStatement::For {
            init: Some(init), ..
        } = s
        {
            rename_in_stmts(std::slice::from_mut(&mut **init), map);
        }
        for e in stmt_exprs_mut(s) {
            rename_in_expr(e, map);
        }
        for body in stmt_bodies_mut(s) {
            rename_in_stmts(body, map);
        }
    }
}

/// Promote the caller-supplied argument registers to real parameters.
///
/// `params` is the calling convention's parameter list as
/// `(name, c_type, register)` — the decompiler's `CallConventionInferencePass`
/// produces exactly this, so the ARITY comes from a real ABI analysis and is
/// never guessed here. An earlier attempt derived it inside this crate from
/// "argument register read before written"; validated against the other
/// decompilation path it disagreed on 415 of 994 functions (42%), i.e. it
/// invented and dropped parameters — code that still compiles, so no
/// recompilability check would ever flag it. Hence: caller supplies the arity.
///
/// For each entry whose register has a variable in the body, the variable is
/// renamed to the parameter name, REMOVED from the locals (a local of the same
/// name would shadow the parameter, leaving the parameter unused and the local
/// uninitialised) and appended to `prototype.params`. `lift_registers` then
/// leaves it alone, since it never renames parameters.
///
/// Returns how many parameters were bound to a variable in the body.
pub fn promote_arg_registers(
    func: &mut HlilFunction,
    params: &[(String, String, String)],
) -> usize {
    let mut bound = 0usize;
    for (pname, cty, reg) in params {
        // EVERY variable standing for this argument register, including its
        // narrower views. `cmp $3, %edx` reads the SAME storage as `rdx`, so a
        // body that only ever touches `edx` must still bind to the parameter.
        //
        // Measured before this: matching the 64-bit name alone left the narrow
        // view as a local that is read and never written — `__dyn_tls_dtor`
        // emitted `uint32_t v1; if (v1 != 3)` where the parameter `a2` was
        // meant, and that class was 15.85% of B's locals against A's 9.34%.
        let names: Vec<String> = func
            .locals
            .iter()
            .filter(|l| arg_reg_of(&l.name).is_some_and(|b| b == reg))
            .map(|l| l.name.clone())
            .collect();
        // Type from the widest view present, so binding `edx` alongside `rdx`
        // does not narrow the parameter.
        // A derived `Debug` nests, so testing the top-level statements already
        // covers every nested body.
        let bit_use = bitwise_use_of_any(&func.body, &names);
        let ty = float_type_from_cty(cty)
            .filter(|_| !bit_use)
            .or_else(|| {
            names
                .iter()
                .find(|n| arg_reg_raw(n) == Some(reg.as_str()))
                .or_else(|| names.first())
                .and_then(|v| {
                    func.locals.iter().find(|l| &l.name == v).map(|l| l.ty.clone())
                })
        });
        if !names.is_empty() {
            let map: HashMap<String, String> = names
                .iter()
                .map(|n| (n.clone(), pname.clone()))
                .collect();
            rename_in_stmts(&mut func.body, &map);
            func.locals.retain(|l| !names.contains(&l.name));
            bound += 1;
        }
        // Declare the parameter EVEN IF the body never reads it: the arity is
        // the ABI's, not "however many the body happened to use". Binding only
        // the used ones made the signature disagree with the same analysis it
        // came from (measured: 330 functions declared fewer parameters than the
        // convention says they take).
        func.prototype
            .params
            .push(HlilVar::new(pname.clone(), ty.unwrap_or(HlilType::Int { signed: true, bits: 64 })));
    }
    bound
}

/// Rename register-derived variables to friendly names: `rsp`/`esp` → `sp`,
/// `rbp`/`ebp` → `fp`, other registers → `v1`, `v2`, … in first-use order.
/// Parameters are never renamed. Returns the number of variables renamed.
pub fn lift_registers(func: &mut HlilFunction) -> usize {
    let mut order = Vec::new();
    collect_var_names_in_order(&func.body, &mut order);
    for l in &func.locals {
        if !order.contains(&l.name) {
            order.push(l.name.clone());
        }
    }
    let param_names: Vec<&str> = func
        .prototype
        .params
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    let mut map = HashMap::new();
    let mut next = 1usize;
    let taken: Vec<String> = order.clone();
    for name in &order {
        if param_names.contains(&name.as_str()) {
            continue;
        }
        let Some(base) = register_base(name) else {
            continue;
        };
        let new = match base {
            "rsp" | "esp" => "sp".to_owned(),
            "rbp" | "ebp" => "fp".to_owned(),
            _ => {
                let mut cand = format!("v{next}");
                next += 1;
                while taken.contains(&cand) || map.values().any(|v| *v == cand) {
                    cand = format!("v{next}");
                    next += 1;
                }
                cand
            }
        };
        map.insert(name.clone(), new);
    }
    if map.is_empty() {
        return 0;
    }
    rename_in_stmts(&mut func.body, &map);
    for l in &mut func.locals {
        if let Some(n) = map.get(&l.name) {
            l.name = n.clone();
        }
    }
    // Il rename tocca il CORPO e le locali GIA' presenti: un nome che il
    // corpo cita ma che non ha voce fra le locali resterebbe SENZA
    // dichiarazione, e il C emesso non compila (`'v1' undeclared`).
    ensure_locals_cover_body(func);
    map.len()
}

/// Ogni nome citato dal CORPO deve avere la sua voce fra le locali.
///
/// `func.locals` NON e' derivata dal corpo: e' una lista costruita a monte, e i
/// rename la estendono solo per le voci gia' presenti. Percio' qualunque
/// trasformazione che INTRODUCA un nome nel corpo — fusione di viste di
/// registro, aliasing, merge di famiglie — lascia un riferimento senza
/// dichiarazione, e il C emesso non compila.
///
/// E' la causa, individuata solo ora, del fallimento del tentativo
/// `reg_family` (+25 file con `'v1' undeclared`), allora archiviato come
/// "espressione cambiata".
///
/// Il tipo NON viene inventato: si riusa quello che la variabile ha gia' nel
/// corpo, dato che `HlilExpr::Var` porta con se' il proprio `HlilVar`.
fn ensure_locals_cover_body(func: &mut HlilFunction) {
    let mut names: Vec<String> = Vec::new();
    collect_var_names_in_order(&func.body, &mut names);
    let known: std::collections::HashSet<String> = func
        .locals
        .iter()
        .map(|l| l.name.clone())
        .chain(func.prototype.params.iter().map(|p| p.name.clone()))
        .collect();
    for n in names {
        if known.contains(&n) {
            continue;
        }
        if let Some(mut v) = find_var_in_body(&func.body, &n) {
            // ⚠ Il tipo va preso dal corpo, ma deve essere EMETTIBILE: il C
            // prodotto e' compilato in gnu89 col prelude `ida_defs.h`, che non
            // definisce `bool`. Le altre dichiarazioni di flag escono infatti
            // come `uint8_t`; usare `HlilType::Bool` qui produceva
            // `error: unknown type name 'bool'` su 114 file.
            if matches!(v.ty, HlilType::Bool) {
                v.ty = HlilType::u8();
            }
            // ⚠ Un tipo `void` NON e' dichiarabile come variabile: sono
            // pseudo-nomi del modello (`__trap__` e simili), non locali.
            // Materializzarli dava `error: variable or field '__trap__'
            // declared void` su 31 file. Il criterio e' il TIPO, non il nome:
            // un nome speciale in piu' passerebbe inosservato, `void` no.
            if matches!(v.ty, HlilType::Void) {
                continue;
            }
            func.locals.push(v);
        }
    }
}

/// Prima occorrenza della variabile `name` nel corpo, per riusarne il TIPO.
fn find_var_in_body(stmts: &[HlilStatement], name: &str) -> Option<HlilVar> {
    fn in_expr(e: &HlilExpr, name: &str) -> Option<HlilVar> {
        if let HlilExpr::Var { var } | HlilExpr::AddressOf { var } = e {
            if var.name == name {
                return Some(var.clone());
            }
        }
        let mut e2 = e.clone();
        let mut found = None;
        for_each_child_mut(&mut e2, &mut |c| {
            if found.is_none() {
                found = in_expr(c, name);
            }
        });
        found
    }
    for s in stmts {
        for e in stmt_exprs(s) {
            if let Some(v) = in_expr(e, name) {
                return Some(v);
            }
        }
        for b in stmt_bodies(s) {
            if let Some(v) = find_var_in_body(b, name) {
                return Some(v);
            }
        }
    }
    None
}

// ── 3. Control-flow structuring ──────────────────────────────────────────────

/// Does `label` name the goto target `addr`? Accepts `label_<hex>`, `L<hex>`,
/// `loc_<hex>`, the bare decimal/hex value, or the `Address` display form.
fn label_matches(label: &str, addr: Address) -> bool {
    let val = addr.0;
    let hex = format!("{val:x}");
    let dec = format!("{val}");
    let stripped = label
        .strip_prefix("label_")
        .or_else(|| label.strip_prefix("loc_"))
        .or_else(|| label.strip_prefix("L"))
        .unwrap_or(label)
        .trim_start_matches("0x");
    stripped.eq_ignore_ascii_case(&hex)
        || stripped == dec
        || label == format!("{addr}")
}

fn count_gotos_to(stmts: &[HlilStatement], label: &str) -> usize {
    let mut n = 0;
    for s in stmts {
        if let HlilStatement::Goto(a) = s {
            if label_matches(label, *a) {
                n += 1;
            }
        }
        if let HlilStatement::For {
            init: Some(init), ..
        } = s
        {
            n += count_gotos_to(std::slice::from_ref(init), label);
        }
        for body in stmt_bodies(s) {
            n += count_gotos_to(body, label);
        }
    }
    n
}

fn contains_label(stmts: &[HlilStatement]) -> bool {
    stmts.iter().any(|s| {
        matches!(s, HlilStatement::Label(_)) || stmt_bodies(s).iter().any(|b| contains_label(b))
    })
}

/// Collect all label names declared within `stmts` (deep).
fn collect_labels(stmts: &[HlilStatement], out: &mut Vec<String>) {
    for s in stmts {
        if let HlilStatement::Label(l) = s {
            out.push(l.clone());
        }
        for body in stmt_bodies(s) {
            collect_labels(body, out);
        }
    }
}

/// Return true if any goto in `stmts` (deep) targets one of `labels`.
fn gotos_to_any(stmts: &[HlilStatement], labels: &[String]) -> bool {
    for s in stmts {
        if let HlilStatement::Goto(a) = s {
            if labels.iter().any(|l| label_matches(l, *a)) {
                return true;
            }
        }
        if let HlilStatement::For { init: Some(init), .. } = s {
            if gotos_to_any(std::slice::from_ref(init), labels) {
                return true;
            }
        }
        for body in stmt_bodies(s) {
            if gotos_to_any(body, labels) {
                return true;
            }
        }
    }
    false
}

/// True when hoisting `middle` into a nested if-body is safe: either middle has
/// no labels at all, or every label in middle is only targeted by gotos that are
/// also inside middle (no external goto would dangle after the hoist).
/// True when every label inside the range a forward-goto guard would swallow
/// is the goto's OWN target. Any other label is by construction the target of
/// some other edge; relocating it into the guarded body would let `goto other;`
/// branch INTO the `if` and bypass the `!cond` guard, so the transform must
/// bail out.
fn middle_has_only_target_label(middle: &[HlilStatement], target: Address) -> bool {
    if !contains_label(middle) {
        return true;
    }
    let mut labels = Vec::new();
    collect_labels(middle, &mut labels);
    labels.iter().all(|l| label_matches(l, target))
}

fn middle_is_self_contained(middle: &[HlilStatement], outer: &[HlilStatement]) -> bool {
    if !contains_label(middle) {
        return true;
    }
    let mut labels = Vec::new();
    collect_labels(middle, &mut labels);
    // Check that no goto in the OUTER scope (the full block, which includes
    // stmts before and after the range) targets a label declared inside middle.
    !gotos_to_any(outer, &labels)
}

/// Is this expression a constant "true" (non-zero integer)?
const fn is_const_true(e: &HlilExpr) -> bool {
    matches!(e, HlilExpr::Const { value, .. } if *value != 0)
}

/// `label L: BODY; goto L;` → `while (1) { BODY }` — il salto all'indietro
/// **NUDO**, cioe' senza guardia.
///
/// Perche' (#5300): le due regole esistenti — (b) goto in avanti e (c) goto
/// all'indietro — pretendono **entrambe** la forma
/// `If { cond, then_body: [Goto(a)], else_body: [] }`. Un `goto` nudo non le
/// incontra mai, quindi **non viene nemmeno esaminato**.
/// MISURATO sul corpus: dei 9442 `goto` di path B, **5676 (60,1%) sono NUDI**,
/// e l'**85,2%** del totale salta ALL'INDIETRO, cioe' e' un ciclo non
/// riconosciuto ([[rustre-goto-nudi-mai-guardati]]).
///
/// Perche' la trasformazione e' lecita: il salto e' **incondizionato**, quindi
/// il controllo torna SEMPRE all'etichetta ⇒ e' un ciclo infinito. Le uscite
/// vere stanno dentro il corpo (`return`, `break`), e restano dove sono.
///
/// ⚠ Si richiede **UN SOLO** goto a quell'etichetta (quello all'indietro), come
/// gia' fa la regola (c): con piu' ingressi l'etichetta non si puo' togliere e
/// il `while` non descriverebbe piu' il flusso.
/// ⚠ Il corpo dev'essere **autocontenuto** rispetto alle proprie etichette.
///
/// Il gate arriva come PARAMETRO: un gate letto dall'ambiente qui dentro
/// renderebbe il test una misura della variabile, non della logica.
/// Riscrive in `continue` ogni `goto L` dentro `stmts` (in PROFONDITA'), dove
/// `L` e' l'etichetta di testa del ciclo che si sta formando.
///
/// Serve a [`fold_bare_backward_goto`]: un salto alla testa del ciclo che nasce
/// **dentro** il corpo e' semanticamente un `continue`. Restituisce quanti ne
/// ha riscritti, cosi' il chiamante puo' verificare di averli presi tutti.
fn rewrite_gotos_as_continue(stmts: &mut Vec<HlilStatement>, label: &str) -> usize {
    let mut n = 0;
    for s in stmts.iter_mut() {
        if matches!(s, HlilStatement::Goto(a) if label_matches(label, *a)) {
            *s = HlilStatement::Continue;
            n += 1;
            continue;
        }
        for body in stmt_bodies_mut(s) {
            n += rewrite_gotos_as_continue(body, label);
        }
    }
    n
}

fn fold_bare_backward_goto(stmts: &mut Vec<HlilStatement>, enabled: bool) -> usize {
    if !enabled {
        return 0;
    }
    let mut changed = 0;
    let mut i = 0;
    while i < stmts.len() {
        if let HlilStatement::Label(l) = &stmts[i] {
            let l = l.clone();
            // SONDA #5320 (effetto ZERO se la variabile non e' impostata):
            // quale condizione respinge i candidati? Ipotizzarlo mi ha gia'
            // fatto sbagliare una volta (credevo fosse `count_gotos_to == 1`,
            // vale 7 casi). Qui si CONTA, e si distingue il caso «l'etichetta
            // non ha nessun goto NUDO in questo blocco» (= annidamento) dagli
            // altri due veti.
            let sonda = std::env::var("RUSTRE_DBG_LOOPGUARD").is_ok_and(|v| v != "0");
            // primo `goto L;` NUDO dopo l'etichetta (non dentro un `if`:
            // quelli li tratta gia' la regola (c))
            let back = stmts[i + 1..]
                .iter()
                .position(|s| matches!(s, HlilStatement::Goto(a) if label_matches(&l, *a)));
            if sonda && back.is_none() {
                // Nessun `goto L;` nudo a questo livello. Se pero' un goto a L
                // esiste PIU' IN PROFONDITA', il candidato c'e' ed e' il
                // vincolo di ANNIDAMENTO a farlo cadere.
                let profondo = count_gotos_to(&stmts[i + 1..].to_vec(), &l);
                if profondo > 0 {
                    eprintln!("[loopguard] SCARTATO_ANNIDAMENTO label={l} goto_profondi={profondo}");
                } else {
                    eprintln!("[loopguard] SCARTATO_NESSUN_GOTO label={l}");
                }
            }
            if let Some(rel) = back {
                let j = i + 1 + rel;
                let mut middle: Vec<HlilStatement> = stmts[i + 1..j].to_vec();
                // #5310: la guardia NON e' piu' «un solo salto all'etichetta».
                // Un salto a L che nasce DENTRO il futuro corpo e' un
                // `continue`, non un ostacolo — ed e' la forma normalissima del
                // ciclo con `continue`. Si ammette quindi che gli ALTRI salti
                // stiano tutti dentro `middle`, e li si riscrive.
                // ⚠ Un salto a L da FUORI resta un veto: li' l'etichetta non si
                // puo' togliere e il `while` non descriverebbe piu' il flusso.
                let dentro = count_gotos_to(&middle, &l);
                let totali = count_gotos_to(stmts, &l);
                if sonda {
                    let autoc = middle_is_self_contained(&middle, stmts);
                    if !autoc {
                        eprintln!("[loopguard] SCARTATO_NON_AUTOCONTENUTO label={l}");
                    } else if totali != dentro + 1 {
                        eprintln!(
                            "[loopguard] SCARTATO_GOTO_ESTERNI label={l} totali={totali} dentro={dentro}"
                        );
                    } else {
                        eprintln!("[loopguard] ACCETTATO label={l}");
                    }
                }
                if middle_is_self_contained(&middle, stmts) && totali == dentro + 1 {
                    let riscritti = rewrite_gotos_as_continue(&mut middle, &l);
                    debug_assert_eq!(riscritti, dentro);
                    stmts.splice(
                        i..=j,
                        [HlilStatement::While {
                            cond: HlilExpr::Const {
                                value: 1,
                                ty: HlilType::i64(),
                            },
                            body: middle,
                        }],
                    );
                    changed += 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    changed
}

/// One structuring rewrite over a single statement list. Returns rewrites done.
///
/// Labels are removed only when no goto *within this statement list* (deep)
/// still targets them; a goto in a sibling scope is not visible here, so this
/// is a per-block heuristic — matching the per-block way the lifter emits
/// goto/label pairs.
fn structure_block(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0;

    // (a) `while (1) { if (c) break; rest }` → `while (!c) { rest }`
    for s in stmts.iter_mut() {
        if let HlilStatement::While { cond, body } = s {
            if is_const_true(cond) && !body.is_empty() {
                let head_is_guard = matches!(
                    &body[0],
                    HlilStatement::If { cond: _, then_body, else_body }
                        if else_body.is_empty()
                            && then_body.len() == 1
                            && matches!(then_body[0], HlilStatement::Break)
                );
                if head_is_guard {
                    let HlilStatement::If { cond: c, .. } = body.remove(0) else {
                        unreachable!()
                    };
                    *cond = negate_cond(c);
                    changed += 1;
                }
            }
        }
    }

    // (b) forward goto: `if (c) goto T; S…; label T:` → `if (!c) { S… } label T:`
    let mut i = 0;
    while i < stmts.len() {
        let target = match &stmts[i] {
            HlilStatement::If {
                cond: _,
                then_body,
                else_body,
            } if else_body.is_empty() && then_body.len() == 1 => match &then_body[0] {
                HlilStatement::Goto(a) => Some(*a),
                _ => None,
            },
            _ => None,
        };
        if let Some(addr) = target {
            let label_pos = stmts[i + 1..].iter().position(|s| {
                matches!(s, HlilStatement::Label(l) if label_matches(l, addr))
            });
            if let Some(rel) = label_pos {
                let j = i + 1 + rel;
                let middle: Vec<HlilStatement> = stmts[i + 1..j].to_vec();
                // Only hoist middle into a nested if-body when all labels
                // inside middle are self-contained (no external goto targets
                // them). The old `!contains_label` was too conservative: it
                // blocked restructuring whenever middle had *any* label, even
                // when every goto to that label was also inside middle.
                if middle_has_only_target_label(&middle, addr)
                    && middle_is_self_contained(&middle, stmts)
                {
                    let HlilStatement::If { cond, .. } = stmts[i].clone() else {
                        unreachable!()
                    };
                    // Splice: replace [i..j] with the guarded block, keep label.
                    stmts.splice(
                        i..j,
                        [HlilStatement::If {
                            cond: negate_cond(cond),
                            then_body: middle,
                            else_body: Vec::new(),
                        }],
                    );
                    // Remove the label when nothing else targets it.
                    let label_idx = i + 1;
                    if let HlilStatement::Label(l) = stmts[label_idx].clone() {
                        if count_gotos_to(stmts, &l) == 0 {
                            stmts.remove(label_idx);
                        }
                    }
                    changed += 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    // (d) #5300: goto all'indietro NUDO → `while (1)`. Va PRIMA della (c) solo
    // per chiarezza di lettura: le due forme sono disgiunte (guardata contro
    // nuda), quindi l'ordine non cambia l'esito. Opt-in.
    changed += fold_bare_backward_goto(
        stmts,
        matches!(
            std::env::var("RUSTRE_HLIL_BAREGOTO").as_deref(),
            Ok("1") | Ok("true")
        ),
    );

    // (c) backward goto: `label T: S…; if (c) goto T;` → `do { S… } while (c);`
    let mut i = 0;
    while i < stmts.len() {
        if let HlilStatement::Label(l) = &stmts[i] {
            let l = l.clone();
            let back = stmts[i + 1..].iter().position(|s| {
                matches!(
                    s,
                    HlilStatement::If { cond: _, then_body, else_body }
                        if else_body.is_empty()
                            && then_body.len() == 1
                            && matches!(&then_body[0], HlilStatement::Goto(a) if label_matches(&l, *a))
                )
            });
            if let Some(rel) = back {
                let j = i + 1 + rel;
                let middle: Vec<HlilStatement> = stmts[i + 1..j].to_vec();
                // Require exactly one goto to this label in the whole block —
                // the backward branch itself — so the label can be dropped.
                // Also require middle to be self-contained w.r.t. its labels.
                if middle_is_self_contained(&middle, stmts) && count_gotos_to(stmts, &l) == 1 {
                    let HlilStatement::If { cond, .. } = stmts[j].clone() else {
                        unreachable!()
                    };
                    stmts.splice(
                        i..=j,
                        [HlilStatement::DoWhile {
                            body: middle,
                            cond,
                        }],
                    );
                    changed += 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    changed
}

/// Structure primitive `goto`/`while (1)` control flow into `if`/`do-while`/
/// `while`. Runs to a bounded fixpoint and recurses into nested bodies.
/// Riducibilita' del grafo dei salti: `(nodi, archi, cicli, irriducibile)`.
///
/// Nodi = ENTRY + ogni `Label`; archi = `Goto` espliciti + la caduta da
/// un'etichetta alla successiva. E' il grafo dei **salti**, non il CFG completo
/// (gli `If`/`While` gia' strutturati non producono archi): e' esattamente il
/// sottografo che decide se i `goto` residui sono chiudibili.
///
/// Riducibile ⇔ togliendo i retro-archi **dominanti** (`u → v` con `v` che
/// domina `u`) il grafo resta ACICLICO. Se restano cicli, servono
/// **node splitting** e duplicazione: e' il discrimine sulla taglia del lavoro.
fn cfg_reducibility(body: &[HlilStatement]) -> (usize, usize, usize, bool) {
    // etichette in ordine di apparizione, in profondita'
    // ⚠ `Label` e' una String e `Goto` un `Address`: si normalizza il testo
    // dell'etichetta al suo valore numerico, con la stessa logica di
    // `label_matches` (prefissi `loc_`/`label_`/`L`, esadecimale o decimale).
    fn val_label(l: &str) -> Option<u64> {
        let t = l
            .strip_prefix("label_")
            .or_else(|| l.strip_prefix("loc_"))
            .or_else(|| l.strip_prefix("L"))
            .unwrap_or(l)
            .trim_start_matches("0x");
        u64::from_str_radix(t, 16).ok().or_else(|| t.parse::<u64>().ok())
    }
    fn raccogli(stmts: &[HlilStatement], out: &mut Vec<u64>, archi: &mut Vec<(u64, u64)>, cur: &mut u64) {
        for s in stmts {
            match s {
                HlilStatement::Label(a) => {
                    if let Some(v) = val_label(a) {
                        // caduta dal nodo corrente all'etichetta
                        archi.push((*cur, v));
                        out.push(v);
                        *cur = v;
                    }
                }
                HlilStatement::Goto(a) => archi.push((*cur, a.0)),
                _ => {}
            }
            for b in stmt_bodies(s) {
                raccogli(b, out, archi, cur);
            }
        }
    }
    const ENTRY: u64 = 0;
    let mut nodi = vec![ENTRY];
    let mut archi = Vec::new();
    let mut cur = ENTRY;
    raccogli(body, &mut nodi, &mut archi, &mut cur);
    riducibilita_da_archi(nodi, archi)
}

/// Riducibilita' del CFG di **un solo LIVELLO** di statement.
///
/// Perche' serve: il 7,8% di CFG irriducibili e' stato misurato sul grafo
/// RICORSIVO, ma la riemissione (`structure_loops_from_cfg`) lavora sul grafo
/// di LIVELLO. Una stima fatta su una popolazione non descrive l'altra — errore
/// gia' commesso in questa sessione, da non ripetere prima del node splitting.
#[must_use]
pub fn cfg_reducibility_livello(stmts: &[HlilStatement]) -> (usize, usize, usize, bool) {
    fn val_label(l: &str) -> Option<u64> {
        let t = l
            .strip_prefix("label_")
            .or_else(|| l.strip_prefix("loc_"))
            .or_else(|| l.strip_prefix("L"))
            .unwrap_or(l)
            .trim_start_matches("0x");
        u64::from_str_radix(t, 16).ok().or_else(|| t.parse::<u64>().ok())
    }
    fn goto_annidati(stmts: &[HlilStatement], cur: u64, archi: &mut Vec<(u64, u64)>) {
        for s in stmts {
            if let HlilStatement::Goto(a) = s {
                archi.push((cur, a.0));
            }
            for b in stmt_bodies_pub(s) {
                goto_annidati(b, cur, archi);
            }
        }
    }
    const ENTRY: u64 = 0;
    let mut nodi = vec![ENTRY];
    let mut archi: Vec<(u64, u64)> = Vec::new();
    let mut cur = ENTRY;
    for s in stmts {
        match s {
            HlilStatement::Label(a) => {
                if let Some(v) = val_label(a) {
                    archi.push((cur, v));
                    nodi.push(v);
                    cur = v;
                }
            }
            HlilStatement::Goto(a) => archi.push((cur, a.0)),
            _ => {}
        }
        for b in stmt_bodies_pub(s) {
            goto_annidati(b, cur, &mut archi);
        }
    }
    riducibilita_da_archi(nodi, archi)
}

/// Nucleo condiviso: dominatori iterativi, retro-archi dominanti, Kahn.
fn riducibilita_da_archi(mut nodi: Vec<u64>, archi: Vec<(u64, u64)>) -> (usize, usize, usize, bool) {
    nodi.sort_unstable();
    nodi.dedup();
    let idx: std::collections::HashMap<u64, usize> =
        nodi.iter().enumerate().map(|(i, &n)| (n, i)).collect();
    // archi verso etichette inesistenti: ignorati (non sono nel grafo)
    // ⚠ #5740: NIENTE filtro `a != b`. Un self-loop (`L: … goto L`) **e' un
    // ciclo**, per giunta riducibile (il nodo domina se' stesso). Scartarlo
    // sottostimava i cicli — difetto trovato dal test sul caso noto, non dai
    // numeri: il totale sembrava plausibile lo stesso.
    let e: Vec<(usize, usize)> = archi
        .iter()
        .filter_map(|(a, b)| Some((*idx.get(a)?, *idx.get(b)?)))
        .collect();
    let n = nodi.len();
    if n <= 1 {
        return (n, e.len(), 0, false);
    }
    // dominatori, iterativo su insiemi di bit (n piccolo: le funzioni hanno
    // decine di etichette, non migliaia)
    let mut dom: Vec<Vec<bool>> = vec![vec![true; n]; n];
    dom[0] = (0..n).map(|i| i == 0).collect();
    let mut cambiato = true;
    let mut giri = 0;
    while cambiato && giri < 200 {
        cambiato = false;
        giri += 1;
        for v in 1..n {
            let preds: Vec<usize> = e.iter().filter(|(_, b)| *b == v).map(|(a, _)| *a).collect();
            if preds.is_empty() {
                continue;
            }
            let mut nuovo = dom[preds[0]].clone();
            for &p in &preds[1..] {
                for i in 0..n {
                    nuovo[i] = nuovo[i] && dom[p][i];
                }
            }
            nuovo[v] = true;
            if nuovo != dom[v] {
                dom[v] = nuovo;
                cambiato = true;
            }
        }
    }
    // retro-archi dominanti da togliere
    let residui: Vec<(usize, usize)> =
        e.iter().copied().filter(|&(u, v)| !dom[u][v]).collect();
    let cicli = e.len() - residui.len();
    // il residuo e' aciclico? (Kahn)
    let mut ingressi = vec![0usize; n];
    for &(_, v) in &residui {
        ingressi[v] += 1;
    }
    let mut coda: Vec<usize> = (0..n).filter(|&i| ingressi[i] == 0).collect();
    let mut visti = 0;
    while let Some(u) = coda.pop() {
        visti += 1;
        for &(a, b) in &residui {
            if a == u {
                ingressi[b] -= 1;
                if ingressi[b] == 0 {
                    coda.push(b);
                }
            }
        }
    }
    (n, e.len(), cicli, visti < n)
}

pub fn structure_control_flow(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut total = 0;
    for _ in 0..16 {
        let mut changed = structure_block(stmts);
        for s in stmts.iter_mut() {
            for body in stmt_bodies_mut(s) {
                changed += structure_control_flow(body);
            }
        }
        total += changed;
        if changed == 0 {
            break;
        }
    }
    total
}

/// Algebraic cleanup of the comparisons x86 flag lowering produces:
///   `(x & x)` → `x`            (a `test x, x` self-AND is identity)
///   `(a - b) == 0` → `a == b`  (a `cmp`/`sub` result tested for zero)
///   `(a - b) != 0` → `a != b`
/// Applied bottom-up so `(x & x) == 0` collapses to `x == 0`. Pure identities,
/// safe on any expression.
fn simplify_flag_expr(e: &mut HlilExpr) {
    for_each_child_mut(e, &mut simplify_flag_expr);
    let rep = match e {
        HlilExpr::And(a, b, _) | HlilExpr::BitAnd(a, b) | HlilExpr::BoolAnd(a, b) if a == b => {
            Some((**a).clone())
        }
        HlilExpr::CmpEq(l, r) if r.is_const_zero() => match &**l {
            HlilExpr::Sub(a, b, _) => Some(HlilExpr::CmpEq(a.clone(), b.clone())),
            _ => None,
        },
        HlilExpr::CmpNe(l, r) if r.is_const_zero() => match &**l {
            HlilExpr::Sub(a, b, _) => Some(HlilExpr::CmpNe(a.clone(), b.clone())),
            _ => None,
        },
        _ => None,
    };
    if let Some(rep) = rep {
        *e = rep;
    }
}

/// Apply [`simplify_flag_expr`] to every expression in the function body.
pub fn simplify_flag_conditions(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut n = 0;
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            n += simplify_flag_conditions(body);
        }
        for e in stmt_exprs_mut(s) {
            let before = e.clone();
            simplify_flag_expr(e);
            if *e != before {
                n += 1;
            }
        }
    }
    n
}

/// Flip an `if (C) { } else { BODY }` with an EMPTY then-branch into
/// `if (!C) { BODY }` — negating the condition, promoting the else body, and
/// dropping the empty arm. A setcc/structuring artifact; `if (v1 != 3) {} else
/// {…}` reads as `if (v1 == 3) {…}`. Uses `negate_cond` so a relational guard
/// flips cleanly (`!=`→`==`), never leaving a `!(…)` wrapper for comparisons.
pub fn flip_empty_then_branch(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut n = 0;
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            n += flip_empty_then_branch(body);
        }
        if let HlilStatement::If { cond, then_body, else_body } = s
            && then_body.is_empty()
            && !else_body.is_empty()
        {
            *cond = negate_cond(cond.clone());
            std::mem::swap(then_body, else_body); // then ← BODY, else ← (empty)
            n += 1;
        }
    }
    n
}

/// True when control cannot fall out the bottom of `stmt`: an explicit
/// terminator (`return`/`break`/`continue`/`goto`), or an `if/else` whose BOTH
/// branches themselves terminate.
fn stmt_terminates(stmt: &HlilStatement) -> bool {
    match stmt {
        HlilStatement::Return(_)
        | HlilStatement::Break
        | HlilStatement::Continue
        | HlilStatement::Goto(_) => true,
        HlilStatement::If { then_body, else_body, .. } => {
            !then_body.is_empty()
                && !else_body.is_empty()
                && then_body.last().is_some_and(stmt_terminates)
                && else_body.last().is_some_and(stmt_terminates)
        }
        _ => false,
    }
}

/// Drop unreachable statements: anything after a statement that cannot fall
/// through (see [`stmt_terminates`]) up to the next `Label` (a label may be a
/// `goto` target, so it resets reachability). This removes the dangling
/// `goto Y;` / dead tail the structurer leaves after an `if/else` in which both
/// branches already `return`/`goto` — a common HLIL noise source. Returns the
/// number of statements removed.
/// `stmt` contiene un'etichetta in un corpo annidato? Allora e' un possibile
/// bersaglio di `goto` e non si puo' cancellare come irraggiungibile.
fn contiene_etichetta(stmt: &HlilStatement) -> bool {
    stmt_bodies(stmt).iter().any(|b| {
        b.iter()
            .any(|s| matches!(s, HlilStatement::Label(_)) || contiene_etichetta(s))
    })
}

pub fn remove_unreachable_after_terminator(stmts: &mut Vec<HlilStatement>) -> usize {
    // Interruttore DIAGNOSTICO `RUSTRE_HLIL_NOUNREACH=1` (default: passata
    // attiva). Serve a rispondere per esperimento, non per lettura, alla
    // domanda «e' QUESTA passata a cancellare il codice che
    // `RUSTRE_HLIL_TOPTEST_BREAK` perde?» — le cinque ipotesi del §65 sono
    // state tutte falsificate a monte, quindi la perdita e' a valle
    // dell'emettitore.
    if std::env::var("RUSTRE_HLIL_NOUNREACH").is_ok_and(|v| v != "0") {
        return 0;
    }
    let mut removed = 0;
    // Recurse first so nested branch bodies are cleaned and the termination
    // check on this level sees each branch's real final statement.
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            removed += remove_unreachable_after_terminator(body);
        }
    }
    let mut out = Vec::with_capacity(stmts.len());
    let mut dead = false;
    for s in std::mem::take(stmts) {
        // ⚠ #6770 — un'etichetta ANNIDATA vale quanto una allo stesso livello.
        //
        // La versione precedente azzerava `dead` solo su
        // `HlilStatement::Label` in TESTA alla lista. Ma un `goto` puo'
        // saltare DENTRO un costrutto: se un `while`/`if` contiene
        // un'etichetta nel proprio corpo, quel costrutto e' raggiungibile
        // anche quando lo precede un terminatore, e cancellarlo distrugge
        // codice VIVO.
        //
        // MISURATO su `sample4_go/sub_14001fa32`: questa passata cancellava un
        // `while (1)` intero — 119 righe, 2 chiamate a `runtime_scanConservative`
        // e una a `runtime_putempty` — perche' seguiva un `goto` mentre le sue
        // etichette (`loc_14001fede`, `loc_14001feef`) erano nel corpo.
        // Provato per esperimento con l'interruttore `RUSTRE_HLIL_NOUNREACH`:
        // spegnendo la passata il codice tornava.
        //
        // Il difetto NON e' di `RUSTRE_HLIL_TOPTEST_BREAK`: quel gate produce
        // solo la disposizione che lo espone. Le cinque ipotesi a monte (§65)
        // erano tutte false proprio perche' l'emettitore e' innocente.
        if matches!(s, HlilStatement::Label(_)) || contiene_etichetta(&s) {
            dead = false; // etichetta (anche annidata) = possibile bersaglio
        }
        if dead {
            removed += 1;
            continue;
        }
        let terminates = stmt_terminates(&s);
        out.push(s);
        if terminates {
            dead = true;
        }
    }
    *stmts = out;
    removed
}

// ── 4. Forward expression propagation ────────────────────────────────────────

/// Variables read by `e` (deep, unique-preserving-order).
fn expr_read_vars(e: &HlilExpr, out: &mut Vec<String>) {
    match e {
        HlilExpr::Var { var } | HlilExpr::AddressOf { var } => {
            if !out.contains(&var.name) {
                out.push(var.name.clone());
            }
        }
        _ => {}
    }
    let mut e2 = e.clone();
    for_each_child_mut(&mut e2, &mut |c| expr_read_vars(c, out));
}

/// Substitute reads of `name` with `rep` in a statement's evaluated-first
/// expressions (not loop conditions). Returns true if the statement was a
/// safe propagation target.
fn subst_in_stmt(stmt: &mut HlilStatement, name: &str, rep: &HlilExpr) -> bool {
    use HlilStatement as S;
    match stmt {
        S::Expression(e) | S::Expr(e) => {
            subst_var(e, name, rep);
            true
        }
        S::Assign { dest, src } => {
            subst_var(src, name, rep);
            if !matches!(dest, HlilExpr::Var { .. }) {
                subst_var(dest, name, rep);
            }
            true
        }
        S::VarDeclare { init: Some(e), .. } | S::VarDecl { init: Some(e), .. } => {
            subst_var(e, name, rep);
            true
        }
        S::Return(es) => {
            for e in es {
                subst_var(e, name, rep);
            }
            true
        }
        S::If { cond, .. } | S::Switch { value: cond, .. } => {
            subst_var(cond, name, rep);
            true
        }
        _ => false,
    }
}

/// Forward-propagate single-use pure assignments into the immediately
/// following statement: `v = expr; use(v)` → `use(expr)`. Recurses into
/// nested bodies. Returns the number of propagations.
pub fn propagate_expressions(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0;
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            changed += propagate_expressions(body);
        }
    }
    let mut i = 0;
    while i + 1 < stmts.len() {
        let candidate = match &stmts[i] {
            HlilStatement::Assign {
                dest: HlilExpr::Var { var },
                src,
            } if src.is_pure() && !var.is_param => Some((var.name.clone(), src.clone())),
            _ => None,
        };
        if let Some((name, src)) = candidate {
            // Self-referential assignments (v = v + 1) can't be dropped.
            let self_ref = count_reads_expr(&src, &name) > 0;
            let reads_after = count_reads_stmts(&stmts[i + 1..], &name);
            let reads_next = count_reads_stmt(&stmts[i + 1], &name);
            let reads_before = count_reads_stmts(&stmts[..i], &name);
            let addr_taken = stmts
                .iter()
                .flat_map(|s| stmt_exprs(s))
                .any(|e| address_taken_expr(e, &name));
            // The next statement must not redefine any input of `src` before
            // the use; only accept next statements that read `name` in their
            // first-evaluated expression (guaranteed by subst_in_stmt shapes).
            let mut inputs = Vec::new();
            expr_read_vars(&src, &mut inputs);
            let next_writes_input = inputs
                .iter()
                .any(|n| writes_var(std::slice::from_ref(&stmts[i + 1]), n));
            // Only the *top level* of the next statement may consume the use:
            // a use buried in a nested body could execute conditionally or
            // repeatedly, so require the read to sit in a top-level expr.
            let top_level_reads: usize = stmt_exprs(&stmts[i + 1])
                .iter()
                .map(|e| count_reads_expr(e, &name))
                .sum();
            if !self_ref
                && !addr_taken
                && reads_before == 0
                && reads_after == 1
                && reads_next == 1
                && top_level_reads == 1
                && !next_writes_input
            {
                let mut next = stmts[i + 1].clone();
                if subst_in_stmt(&mut next, &name, &src) {
                    stmts[i + 1] = next;
                    stmts.remove(i);
                    changed += 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    changed
}

// ── 5. Dead store elimination ────────────────────────────────────────────────

fn remove_dead_stores_in(stmts: &mut Vec<HlilStatement>, dead: &dyn Fn(&str) -> bool) -> usize {
    let mut removed = 0;
    stmts.retain(|s| {
        let is_dead = match s {
            HlilStatement::Assign {
                dest: HlilExpr::Var { var },
                src,
            } => src.is_pure() && !var.is_param && dead(&var.name),
            HlilStatement::VarDeclare { var, init } | HlilStatement::VarDecl { var, init, .. } => {
                !var.is_param
                    && dead(&var.name)
                    && init.as_ref().is_none_or(HlilExpr::is_pure)
            }
            _ => false,
        };
        if is_dead {
            removed += 1;
        }
        !is_dead
    });
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            removed += remove_dead_stores_in(body, dead);
        }
    }
    removed
}

/// Remove pure assignments to variables that are never read anywhere in the
/// function (post-structuring dead store elimination). Runs to fixpoint.
// -- Dead flag stores: liveness ALL'INDIETRO, non conteggio di letture -------
//
// `eliminate_dead_stores` decide con `count_reads_stmts(body, n) == 0`, cioe'
// sul TOTALE delle letture nella funzione. Per un `var_...` normale va bene;
// per un flag no: `flag_zf` viene riscritto decine di volte nello stesso corpo
// e una sola lettura in fondo tiene in vita TUTTI i suoi store.
//
// Misurato sul corpus (path B, 143 funzioni, configurazione estesa): 257 store
// su `flag_*` sopravvivono all'emissione e ZERO risulta morto al
// conteggio-letture -- mentre la forma dominante nel testo emesso e'
//
//     var_tmp0 = ((uint32_t)v8 - 1);
//     flag_zf  = (var_tmp0 == 0);      // <- nessuno la legge
//     if (var_tmp0 == 0) { ... }       // <- il ramo usa il temporaneo
//
// cioe' proprio uno store morto. La fusione dei flag ha gia' riscritto la
// condizione del salto sull'espressione; e' la fusione a CREARE la morte, e la
// DCE sul MLIL (`eliminate_dead_flag_writes_cfg`) gira PRIMA di lei, quando il
// flag e' ancora genuinamente letto dal salto. Nessuno ripassa dopo.
//
// Questa passata e' quel ripasso, con la liveness fatta dove si decide.
// Conservativa per costruzione:
// * un `Goto`/`Label` sospende l'ottimizzazione sull'intera funzione -- con
//   flusso non strutturato l'ordine testuale non e' l'ordine d'esecuzione;
// * `Break`/`Continue` rendono vivi TUTTI i flag (il salto esce dalla lista);
// * un ciclo assume vivo tutto cio' che il suo corpo legge (approssimazione dal
//   lato sicuro dell'arco all'indietro, senza punto fisso);
// * si cancella solo un RHS senza `Call`: togliere una lettura di memoria e'
//   lecito, togliere una chiamata no.
//
// Cancellare uno store non e' il solo effetto voluto: `var_tmp0` sopravvive
// perche' ha DUE letture (la riga morta e l'`if`). Tolta la riga morta ne resta
// una, e `inline_adjacent_hlil_temps` -- gia' cablata a valle e in attesa
// esattamente di quel caso -- la assorbe da se'.

/// Le pseudo-variabili di flag che il lifter materializza.
const FLAG_NAMES: [&str; 6] = [
    "flag_zf", "flag_cf", "flag_sf", "flag_of", "flag_pf", "flag_af",
];

/// DEFAULT-ON dal 2026-08-18; si spegne con `RUSTRE_HLIL_FLAGDCE=0`.
///
/// Misurata sul corpus INTERO (11342 file per lato, non i 3 bucket dei primi
/// giri) insieme a `propagate_pure_temps`, che e' la sua meta' complementare:
///   `flag_*`     51397 -> 36713  (−28,6%)
///   `var_tmp*`   59619 -> 36943  (−38,0%)
///   righe        946284 -> 924787
///   `goto`       8913 -> 8912    (−1: nessun costo)
///   `JUMPOUT`    7 -> 7          (invariato)
///   dati materializzati 7937 -> 7937 (invariato)
///   chiamate distinte perse: **0** in **0** file
///   comportamento: 15 AGREE / 4 LINK_FAIL, IDENTICO funzione per funzione
///                  su tutte e 19 le funzioni confrontabili
/// Nessun contatore peggiorato: e' il motivo per cui e' default-ON.
fn flag_dce_enabled() -> bool {
    !matches!(
        std::env::var("RUSTRE_HLIL_FLAGDCE").as_deref(),
        Ok("0") | Ok("false")
    )
}

fn flag_reads_expr(e: &HlilExpr, live: &mut std::collections::BTreeSet<String>) {
    for f in FLAG_NAMES {
        if count_reads_expr(e, f) > 0 {
            live.insert(f.to_string());
        }
    }
}

fn flag_reads_stmts(stmts: &[HlilStatement], live: &mut std::collections::BTreeSet<String>) {
    for f in FLAG_NAMES {
        if count_reads_stmts(stmts, f) > 0 {
            live.insert(f.to_string());
        }
    }
}

fn all_flags_live(live: &mut std::collections::BTreeSet<String>) {
    for f in FLAG_NAMES {
        live.insert(f.to_string());
    }
}

// -- Raggiungibilita' a PUNTO FISSO sull'AST emesso (#6940) ------------------
//
// `remove_unreachable_after_terminator` guarda UN passo: cancella cio' che
// segue un terminatore fino alla prossima etichetta, e si ferma li'. Non vede
// il caso transitivo, che il §90 ha misurato essere quello dominante: un blocco
// E' bersaglio di un `goto`, quindi sembra vivo, ma quel `goto` sta a sua volta
// in codice irraggiungibile.
//
// Misurato: dei 324 statement orfani di sample10_cs, **210 (65%) escono da
// `emit_pending_exits`** e hanno tutti questa forma. Il filtro a un passo del
// #6930 ne ha scartati 33 su 585 e ha lasciato gli orfani a 324.
//
// Qui il calcolo e' un punto fisso DECRESCENTE:
// * si parte OTTIMISTI, con tutte le etichette considerate vive;
// * si percorre l'albero e si raccoglie quali etichette sono davvero
//   raggiunte — per CADUTA da uno statement raggiungibile, oppure da un `goto`
//   che si trova in posizione raggiungibile;
// * l'insieme puo' solo restringersi, quindi termina;
// * si cancella solo alla fine, quando l'insieme e' stabile.
//
// Partire ottimisti e restringere e' la direzione SICURA per una rimozione: si
// toglie solo cio' che e' PROVATAMENTE irraggiungibile. La direzione opposta
// (partire da niente e crescere) toglierebbe codice per mancanza di prove.

/// DEFAULT-ON dal 2026-08-19 (#6940); si spegne con `RUSTRE_HLIL_REACH=0`.
///
/// Misurato sul corpus intero (11342 file per lato), contro il predefinito:
///   codice PERSO        423 -> **54**   (−87,2%)
///   `goto`             9547 -> **8845** (−702, il calo piu' grande dopo TAILDUP)
///   righe            936036 -> 918600   (−17436)
///   `JUMPOUT`             1 -> 1        (invariato)
///   dati               7943 -> 7826     (−117, VERIFICATI coerenti)
///   chiamate di coda perse  0 -> **0**  (la parita' del §103 non si tocca)
///   `path A`                            0 differenze
///   comportamento      15 AGREE / 4 LINK_FAIL, **19 su 19 identiche**
///
/// I 117 dati in meno sono l'unico contatore in calo, ed e' la classe che in
/// questa sessione ha nascosto una perdita reale tre volte. Verificato uno per
/// uno: su 117 definizioni rimosse in 28 file, **ZERO sono ancora usate** —
/// erano riferite solo dal codice estraneo che questa passata toglie (§92 ha
/// stabilito leggendo il disassemblato che quel codice appartiene ad ALTRE
/// funzioni).
///
/// Toglie anche 194 chiamate di coda su 5138, tutte in regioni irraggiungibili:
/// nessuna di quelle che path A emette.
fn reach_fixpoint_enabled() -> bool {
    !matches!(
        std::env::var("RUSTRE_HLIL_REACH").as_deref(),
        Ok("0") | Ok("false")
    )
}

fn tutte_le_etichette(stmts: &[HlilStatement], out: &mut std::collections::HashSet<String>) {
    for s in stmts {
        if let HlilStatement::Label(l) = s {
            out.insert(l.clone());
        }
        for b in stmt_bodies(s) {
            tutte_le_etichette(b, out);
        }
    }
}

/// Percorre marcando la raggiungibilita'; raccoglie le etichette RAGGIUNTE
/// (per caduta) e i bersagli dei `goto` in posizione raggiungibile.
fn scandisci(
    stmts: &[HlilStatement],
    mut raggiungibile: bool,
    vive: &std::collections::HashSet<String>,
    bersagli: &mut std::collections::HashSet<String>,
    raggiunte: &mut std::collections::HashSet<String>,
) {
    for s in stmts {
        if let HlilStatement::Label(l) = s {
            if raggiungibile {
                raggiunte.insert(l.clone());
            }
            if vive.contains(l) {
                raggiungibile = true;
            }
        }
        if raggiungibile {
            if let HlilStatement::Goto(a) = s {
                bersagli.insert(format!("loc_{:x}", a.as_u64()));
            }
            for b in stmt_bodies(s) {
                scandisci(b, true, vive, bersagli, raggiunte);
            }
        }
        if raggiungibile && s.is_terminator() {
            raggiungibile = false;
        }
    }
}

fn conta_profondo(s: &HlilStatement) -> usize {
    1 + stmt_bodies(s)
        .iter()
        .map(|b| b.iter().map(conta_profondo).sum::<usize>())
        .sum::<usize>()
}

fn rimuovi_irraggiungibili(
    stmts: &mut Vec<HlilStatement>,
    mut raggiungibile: bool,
    vive: &std::collections::HashSet<String>,
) -> usize {
    let mut tolti = 0usize;
    let mut out: Vec<HlilStatement> = Vec::with_capacity(stmts.len());
    for mut s in std::mem::take(stmts) {
        if let HlilStatement::Label(l) = &s
            && vive.contains(l)
        {
            raggiungibile = true;
        }
        if !raggiungibile {
            tolti += conta_profondo(&s);
            continue;
        }
        for b in stmt_bodies_mut(&mut s) {
            tolti += rimuovi_irraggiungibili(b, true, vive);
        }
        let termina = s.is_terminator();
        out.push(s);
        if termina {
            raggiungibile = false;
        }
    }
    *stmts = out;
    tolti
}

/// Cancella gli statement provatamente irraggiungibili, con la
/// raggiungibilita' calcolata a punto fisso. Ritorna quanti ne ha tolti.
pub fn remove_unreachable_fixpoint(func: &mut HlilFunction) -> usize {
    if !reach_fixpoint_enabled() {
        return 0;
    }
    let mut vive = std::collections::HashSet::new();
    tutte_le_etichette(&func.body, &mut vive);
    for _ in 0..32 {
        let mut bersagli = std::collections::HashSet::new();
        let mut raggiunte = std::collections::HashSet::new();
        scandisci(&func.body, true, &vive, &mut bersagli, &mut raggiunte);
        let nuove: std::collections::HashSet<String> =
            bersagli.union(&raggiunte).cloned().collect();
        // ⚠ Confrontare le LUNGHEZZE non basta: due insiemi diversi possono
        // avere la stessa cardinalita', e il punto fisso si fermerebbe su un
        // insieme sbagliato. Si confrontano gli INSIEMI.
        if nuove == vive {
            break;
        }
        vive = nuove;
    }
    rimuovi_irraggiungibili(&mut func.body, true, &vive)
}

/// Un `Goto` o una `Label` in qualunque punto sospende la passata.
fn has_goto_or_label(stmts: &[HlilStatement]) -> bool {
    stmts.iter().any(|s| {
        matches!(s, HlilStatement::Goto(_) | HlilStatement::Label(_))
            || stmt_bodies(s).iter().any(|b| has_goto_or_label(b))
    })
}

// -- Copy propagation dei temporanei PURI, a piu' usi ------------------------
//
// `propagate_expressions` propaga solo un'assegnazione a USO SINGOLO e solo
// nello statement IMMEDIATAMENTE successivo. Sul caso che conta rinuncia per
// costruzione: l'abbassamento di un `cmp` produce un temporaneo con TRE
// letture, una per flag.
//
//     var_tmp0 = (a - b);
//     flag_zf  = (var_tmp0 == 0);
//     flag_sf  = ((__int64)var_tmp0 < 0);
//     flag_of  = (...var_tmp0...);
//     if ((flag_zf == 1) | (flag_sf != flag_of)) { ... }     // <= con segno
//
// MISURATO dopo la DCE sui flag (§57): i 237 `flag_*` sopravvissuti sono ora
// genuinamente VIVI e in buona parte COMBINAZIONI come quella sopra, che
// `fold_flag_combos` sa chiudere -- ma solo se vede gli operandi veri. Una riga
// emessa mostra la fusione ferma a meta' strada:
//
//     if (((var_tmp0 == 0) == 1) | (flag_sf != flag_of))
//
// `zf` e' stato assorbito (dopo la DCE era a uso singolo), `sf` e `of` no. Il
// temporaneo non e' piu' un difetto cosmetico: e' il collo di bottiglia.
//
// Duplicare un'espressione PURA in piu' usi e' lecito -- non ha effetti, e il
// solo rischio e' che i suoi operandi cambino nel frattempo. Le condizioni,
// tutte verificate prima di toccare qualcosa:
// * il RHS non contiene `Call`;
// * nella finestra fra definizione e ridefinizione nessuno SCRIVE una delle
//   variabili lette dal RHS (controllo profondo, corpi annidati compresi);
// * la finestra non contiene `Goto`/`Label` -- il flusso potrebbe entrarci in
//   mezzo, e allora la definizione non l'ha preceduta;
// * nessun CICLO nella finestra legge il temporaneo: la' l'espressione sarebbe
//   rivalutata a ogni giro.

/// DEFAULT-ON dal 2026-08-18; si spegne con `RUSTRE_HLIL_TEMPPROP=0`.
/// Numeri e verifiche: vedi `flag_dce_enabled`, misurate insieme.
/// ⚠ L'ORDINE resta vincolante: questa passata gira DOPO `fold_flag_combos`,
/// mai prima — vedi il commento sul sito di chiamata.
fn temp_prop_enabled() -> bool {
    !matches!(
        std::env::var("RUSTRE_HLIL_TEMPPROP").as_deref(),
        Ok("0") | Ok("false")
    )
}

/// Nomi di variabile letti da `e`.
fn vars_read_in_expr(e: &HlilExpr, out: &mut std::collections::HashSet<String>) {
    if let HlilExpr::Var { var } = e {
        out.insert(var.name.clone());
    }
    crate::hlil_optimization::for_each_child_pub(e, &mut |c| vars_read_in_expr(c, out));
}

/// `stmt` ridefinisce la variabile `name`?
fn ridefinisce(stmt: &HlilStatement, name: &str) -> bool {
    matches!(
        stmt,
        HlilStatement::Assign { dest: HlilExpr::Var { var }, .. }
            | HlilStatement::VarDeclare { var, .. }
            | HlilStatement::VarDecl { var, .. }
        if var.name == name
    )
}

/// `Goto`/`Label` in qualunque punto di `stmt`.
fn contiene_salto(stmt: &HlilStatement) -> bool {
    matches!(stmt, HlilStatement::Goto(_) | HlilStatement::Label(_))
        || stmt_bodies(stmt).iter().any(|b| b.iter().any(contiene_salto))
}

/// `stmt` e' (o contiene) un ciclo che legge `name`?
fn ciclo_che_legge(stmt: &HlilStatement, name: &str) -> bool {
    use HlilStatement as S;
    let e_ciclo = matches!(stmt, S::While { .. } | S::DoWhile { .. } | S::For { .. });
    if e_ciclo && count_reads_stmt(stmt, name) > 0 {
        return true;
    }
    stmt_bodies(stmt)
        .iter()
        .any(|b| b.iter().any(|s| ciclo_che_legge(s, name)))
}

/// Sostituisce `name` con `rep` in `stmt` e in TUTTI i suoi corpi annidati.
fn subst_in_stmt_deep(stmt: &mut HlilStatement, name: &str, rep: &HlilExpr) {
    subst_in_stmt(stmt, name, rep);
    for body in stmt_bodies_mut(stmt) {
        for s in body.iter_mut() {
            subst_in_stmt_deep(s, name, rep);
        }
    }
}

/// Propaga i temporanei `var_tmp*` con RHS puro in tutti gli usi del loro live
/// range, poi ne cancella la definizione. Ritorna quante ne ha propagate.
pub fn propagate_pure_temps(stmts: &mut Vec<HlilStatement>) -> usize {
    if !temp_prop_enabled() {
        return 0;
    }
    propagate_pure_temps_in(stmts)
}

fn propagate_pure_temps_in(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0usize;
    // Prima i corpi annidati, cosi' il livello esterno lavora su un albero gia'
    // semplificato.
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            changed += propagate_pure_temps_in(body);
        }
    }
    let mut i = 0usize;
    while i < stmts.len() {
        let (name, src) = match &stmts[i] {
            HlilStatement::Assign {
                dest: HlilExpr::Var { var },
                src,
            } if var.name.starts_with("var_tmp")
                && !crate::hlil_optimization::expr_contains_call(src) =>
            {
                (var.name.clone(), src.clone())
            }
            _ => {
                i += 1;
                continue;
            }
        };
        // Fine del live range: la prossima ridefinizione, esclusa.
        let mut end = stmts.len();
        for j in (i + 1)..stmts.len() {
            if ridefinisce(&stmts[j], &name) {
                end = j;
                break;
            }
        }
        let mut operandi = std::collections::HashSet::new();
        vars_read_in_expr(&src, &mut operandi);
        let finestra = &stmts[(i + 1)..end];
        let usi: usize = finestra.iter().map(|s| count_reads_stmt(s, &name)).sum();
        let sicuro = usi > 0
            && !finestra.iter().any(contiene_salto)
            && !finestra.iter().any(|s| ciclo_che_legge(s, &name))
            && !operandi
                .iter()
                .any(|o| writes_var(finestra, o));
        if !sicuro {
            i += 1;
            continue;
        }
        for j in (i + 1)..end {
            subst_in_stmt_deep(&mut stmts[j], &name, &src);
        }
        stmts.remove(i);
        changed += 1;
        // `i` non avanza: lo statement in posizione `i` e' ora quello dopo.
    }
    changed
}

/// Stato dell'analisi fra un giro e l'altro del punto fisso.
///
/// MISURATO: trattare `Goto`/`Label` come barriere «tutto vivo» era sano ma
/// inerte -- 43 funzioni su 43 arrivano qui ancora piene di goto (li tolgono le
/// passate testuali a valle, quando l'AST non c'e' piu'), e su 143 store se ne
/// cancellavano 3. L'unico punto in cui questa analisi puo' girare e' questo,
/// quindi le etichette vanno trattate davvero.
///
/// `label_live` porta, per ogni etichetta, l'unione degli insiemi vivi
/// osservati in ingresso a essa; un `Goto` legge quell'insieme invece di
/// arrendersi. Si parte OTTIMISTI (insieme vuoto) e si itera finche' nessun
/// insieme cresce -- l'ordine standard per un'analisi all'indietro con archi
/// non strutturati. Le cancellazioni avvengono SOLO nel giro finale, quando il
/// punto fisso e' raggiunto: cancellare durante i giri ottimisti userebbe
/// informazione non ancora sana.
struct FlagCtx {
    /// Etichette presenti nella funzione. Un `Goto` verso un bersaglio che non
    /// c'e' esce dalla funzione: la' e' vivo tutto.
    labels: std::collections::HashSet<String>,
    label_live: HashMap<String, std::collections::BTreeSet<String>>,
    changed: bool,
    apply: bool,
}

impl FlagCtx {
    fn record(&mut self, label: &str, live: &std::collections::BTreeSet<String>) {
        let e = self.label_live.entry(label.to_string()).or_default();
        let before = e.len();
        e.extend(live.iter().cloned());
        if e.len() != before {
            self.changed = true;
        }
    }
}

fn raccogli_etichette(stmts: &[HlilStatement], out: &mut std::collections::HashSet<String>) {
    for s in stmts {
        if let HlilStatement::Label(l) = s {
            out.insert(l.clone());
        }
        for b in stmt_bodies(s) {
            raccogli_etichette(b, out);
        }
    }
}

/// Percorre `stmts` a RITROSO. `live` entra come insieme vivo in USCITA dalla
/// lista ed esce come insieme vivo in INGRESSO.
fn dead_flag_stores_in(
    stmts: &mut Vec<HlilStatement>,
    live: &mut std::collections::BTreeSet<String>,
    ctx: &mut FlagCtx,
) -> usize {
    use HlilStatement as S;
    let mut removed = 0usize;
    let mut i = stmts.len();
    while i > 0 {
        i -= 1;
        let mut drop_it = false;
        match &mut stmts[i] {
            S::Assign {
                dest: HlilExpr::Var { var },
                src,
            } if var.name.starts_with("flag_") => {
                let name = var.name.clone();
                if !live.contains(&name) && !crate::hlil_optimization::expr_contains_call(src) {
                    if ctx.apply {
                        drop_it = true;
                    }
                    // Anche nei giri non-applicativi lo store e' morto: non
                    // rende vivo cio' che legge, altrimenti il punto fisso
                    // convergerebbe su un'informazione piu' grossolana di
                    // quella che il giro finale usera'.
                    live.remove(&name);
                } else {
                    live.remove(&name);
                    flag_reads_expr(src, live);
                }
            }
            S::If {
                cond,
                then_body,
                else_body,
            } => {
                let mut l1 = live.clone();
                removed += dead_flag_stores_in(then_body, &mut l1, ctx);
                let mut l2 = live.clone();
                removed += dead_flag_stores_in(else_body, &mut l2, ctx);
                *live = l1.union(&l2).cloned().collect();
                flag_reads_expr(cond, live);
            }
            S::Switch {
                value,
                cases,
                default,
            } => {
                let mut acc = live.clone();
                for c in cases.iter_mut() {
                    let mut l = live.clone();
                    removed += dead_flag_stores_in(&mut c.body, &mut l, ctx);
                    acc.extend(l);
                }
                let mut l = live.clone();
                removed += dead_flag_stores_in(default, &mut l, ctx);
                acc.extend(l);
                *live = acc;
                flag_reads_expr(value, live);
            }
            S::While { cond, body } | S::DoWhile { body, cond } => {
                // Arco all'indietro: tutto cio' che il corpo o la condizione
                // leggono e' vivo all'ingresso di ogni iterazione.
                let mut lb = live.clone();
                flag_reads_expr(cond, &mut lb);
                flag_reads_stmts(body, &mut lb);
                removed += dead_flag_stores_in(body, &mut lb, ctx);
                *live = lb;
                flag_reads_expr(cond, live);
            }
            S::For {
                init,
                cond,
                step,
                body,
            } => {
                let mut lb = live.clone();
                if let Some(c) = cond {
                    flag_reads_expr(c, &mut lb);
                }
                if let Some(s) = step {
                    flag_reads_expr(s, &mut lb);
                }
                flag_reads_stmts(body, &mut lb);
                removed += dead_flag_stores_in(body, &mut lb, ctx);
                *live = lb;
                if let Some(c) = cond {
                    flag_reads_expr(c, live);
                }
                if let Some(ini) = init {
                    let mut one = vec![(**ini).clone()];
                    removed += dead_flag_stores_in(&mut one, live, ctx);
                    **ini = one.into_iter().next().unwrap_or(S::Nop);
                }
            }
            S::Block(b) => {
                removed += dead_flag_stores_in(b, live, ctx);
            }
            S::Return(exprs) => {
                // Niente segue un `return`.
                live.clear();
                for e in exprs.iter() {
                    flag_reads_expr(e, live);
                }
            }
            S::Goto(a) => {
                // Vivo dopo un salto = vivo all'ingresso della destinazione.
                let l = format!("loc_{:x}", a.as_u64());
                if ctx.labels.contains(&l) {
                    *live = ctx.label_live.get(&l).cloned().unwrap_or_default();
                } else {
                    // Bersaglio fuori dalla funzione: la' e' vivo tutto.
                    all_flags_live(live);
                }
            }
            S::Label(l) => {
                // `live` e' l'insieme vivo in INGRESSO all'etichetta: e' cio'
                // che ogni `goto` che la punta deve vedere.
                let l = l.clone();
                ctx.record(&l, live);
            }
            S::Break | S::Continue => {
                all_flags_live(live);
            }
            other => {
                for e in stmt_exprs(other) {
                    flag_reads_expr(e, live);
                }
            }
        }
        if drop_it {
            stmts.remove(i);
            removed += 1;
        }
    }
    removed
}

/// Elimina gli store su `flag_*` che nessun percorso legge.
///
/// Ritorna quanti ne ha tolti. A vuoto (0) quando il gate e' spento.
pub fn eliminate_dead_flag_stores(func: &mut HlilFunction) -> usize {
    if !flag_dce_enabled() {
        return 0;
    }
    let dbg = std::env::var("RUSTRE_DBG_FLAGDCE").is_ok();
    let mut labels = std::collections::HashSet::new();
    raccogli_etichette(&func.body, &mut labels);
    let mut ctx = FlagCtx {
        labels,
        label_live: HashMap::new(),
        changed: false,
        apply: false,
    };
    // Punto fisso: gli insiemi possono solo crescere e sono limitati da
    // 6 flag x numero di etichette, quindi termina; il tetto e' una rete.
    let mut giri = 0usize;
    for _ in 0..16 {
        giri += 1;
        ctx.changed = false;
        // Nessun flag e' vivo all'uscita: in questo IR i flag non sono un
        // valore di ritorno.
        let mut live = std::collections::BTreeSet::new();
        dead_flag_stores_in(&mut func.body, &mut live, &mut ctx);
        if !ctx.changed {
            break;
        }
    }
    ctx.apply = true;
    let mut store = 0usize;
    conta_store_flag(&func.body, &mut store);
    let mut live = std::collections::BTreeSet::new();
    let n = dead_flag_stores_in(&mut func.body, &mut live, &mut ctx);
    if dbg {
        eprintln!(
            "[flagdce] addr={:#x} store_flag={store} rimossi={n} giri={giri} etichette={} strutturata={}",
            func.address.0,
            ctx.labels.len(),
            !has_goto_or_label(&func.body)
        );
    }
    n
}

/// Conta gli store su `flag_*`, sonde comprese le liste annidate.
fn conta_store_flag(stmts: &[HlilStatement], n: &mut usize) {
    for s in stmts {
        if let HlilStatement::Assign { dest: HlilExpr::Var { var }, .. } = s
            && var.name.starts_with("flag_")
        {
            *n += 1;
        }
        for b in stmt_bodies(s) {
            conta_store_flag(b, n);
        }
    }
}

pub fn eliminate_dead_stores(func: &mut HlilFunction) -> usize {
    let mut total = 0;
    loop {
        // Collect names written anywhere.
        let mut names = Vec::new();
        collect_var_names_in_order(&func.body, &mut names);
        let body = &func.body;
        let dead_names: Vec<String> = names
            .into_iter()
            .filter(|n| count_reads_stmts(body, n) == 0)
            .collect();
        if dead_names.is_empty() {
            break;
        }
        // Sonda diagnostica (effetto ZERO sull'output): dice se e' QUESTA passata
        // a togliere la definizione di un temp di conteggio-shift. Attivare con
        // `RUSTRE_DBG_DEADSTORE=1`. ⚠ Serve perche' leggere il codice ha gia'
        // falsificato due ipotesi su tre: qui si misura, non si deduce.
        if std::env::var("RUSTRE_DBG_DEADSTORE").is_ok() {
            // #3830b — riga SEMPRE stampata: distingue «nessun nome morto» da
            // «la sonda non gira». Un output vuoto non e' uno zero.
            eprintln!("DBG_DEADSTORE_ROUND morti={}", dead_names.len());
            // #3840 — per i `var_tmp*` RACCOLTI, il numero di letture al momento
            // in cui questa passata decide. Distingue «non raccolto» (nessuna
            // riga) da «raccolto ma ancora letto» (letture>0).
            let mut visti = Vec::new();
            collect_var_names_in_order(body, &mut visti);
            for n in visti.iter().filter(|n| n.starts_with("var_tmp")) {
                eprintln!("DBG_VARTMP nome={n} letture={}", count_reads_stmts(body, n));
            }
            // #3830 — anche `var_tmp…`: col filtro `starts_with("tmp")` la sonda
            // NON vedeva il temporaneo dell'AND, che si chiama `var_tmp0`.
            for d in dead_names
                .iter()
                .filter(|d| d.starts_with("tmp") || d.starts_with("var_tmp"))
            {
                eprintln!(
                    "DBG_DEADSTORE {:?} rimuove il temp '{}' (letture contate: 0)",
                    func.address, d
                );
            }
        }
        let removed = remove_dead_stores_in(&mut func.body, &|n| {
            dead_names.iter().any(|d| d == n)
        });
        total += removed;
        if removed == 0 {
            break;
        }
    }
    // Prune locals with no remaining read or write in the body — e.g. flag vars
    // (`var_flag_sf`) whose only uses were folded away by `fold_flag_combos`, or
    // whose defining store was just removed above. Params are always kept.
    let body = &func.body;
    let before = func.locals.len();
    func.locals
        .retain(|l| l.is_param || count_reads_stmts(body, &l.name) > 0 || writes_var(body, &l.name));
    total += before - func.locals.len();
    total
}

// ── 6. Loop induction variables ──────────────────────────────────────────────

/// Is `e` an increment/decrement of `name` by a constant (`name ± c`)?
fn is_step_of(e: &HlilExpr, name: &str) -> bool {
    match e {
        HlilExpr::Add(a, b, _) | HlilExpr::Sub(a, b, _) => {
            matches!(&**a, HlilExpr::Var { var } if var.name == name) && b.is_const().is_some()
        }
        _ => false,
    }
}

/// Detect `i = init; while (i < n) { …; i = i ± c }` and rewrite it as
/// `for (i = init; i < n; i = i ± c) { … }`. Also converts init-less whiles
/// whose body ends in a constant step. Returns the number of loops converted.
pub fn detect_induction_vars(stmts: &mut Vec<HlilStatement>) -> usize {
    let mut changed = 0;
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            changed += detect_induction_vars(body);
        }
    }
    let mut i = 0;
    while i < stmts.len() {
        // Find a While whose condition reads some var stepped at body end.
        let convert = match &stmts[i] {
            HlilStatement::While { cond, body } if !body.is_empty() => {
                match body.last() {
                    Some(HlilStatement::Assign {
                        dest: HlilExpr::Var { var },
                        src,
                    }) if is_step_of(src, &var.name)
                        && count_reads_expr(cond, &var.name) > 0 =>
                    {
                        Some(var.name.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(ivar) = convert {
            let HlilStatement::While { cond, mut body } = stmts[i].clone() else {
                unreachable!()
            };
            let Some(HlilStatement::Assign { src, .. }) = body.pop() else {
                unreachable!()
            };
            // In the original while, `continue` skips the trailing increment,
            // but `continue` in a C `for` still runs the step — so the rewrite
            // is only valid when the body contains no `continue`.
            let (_n_breaks, n_continues) = crate::count_breaks_and_continues(&body);
            if n_continues > 0 {
                i += 1;
                continue;
            }
            // Steal a preceding `ivar = init` as the for-init when adjacent.
            let mut init: Option<Box<HlilStatement>> = None;
            if i > 0 {
                if let HlilStatement::Assign {
                    dest: HlilExpr::Var { var },
                    src: init_src,
                } = &stmts[i - 1]
                {
                    if var.name == ivar && init_src.is_pure() {
                        init = Some(Box::new(stmts[i - 1].clone()));
                    }
                }
            }
            // `For.step` is an expression, so the step is represented by the
            // increment's RHS (`i + 1`-style), matching the For printer.
            let for_stmt = HlilStatement::For {
                init,
                cond: Some(cond),
                step: Some(src),
                body,
            };
            if stmts_prev_is_init(&for_stmt) {
                // init was stolen from stmts[i-1]: replace both.
                stmts.splice(i - 1..=i, [for_stmt]);
                i = i.saturating_sub(1);
            } else {
                stmts[i] = for_stmt;
            }
            changed += 1;
        }
        i += 1;
    }
    changed
}

const fn stmts_prev_is_init(for_stmt: &HlilStatement) -> bool {
    matches!(for_stmt, HlilStatement::For { init: Some(_), .. })
}

// ── 7. Opportunistic type inference ──────────────────────────────────────────

const fn known(ty: &HlilType) -> bool {
    !matches!(ty, HlilType::Unknown)
}

/// Scan for evidence about `name`'s type: assignment sources and derefs.
fn infer_var_type(stmts: &[HlilStatement], name: &str) -> Option<HlilType> {
    for s in stmts {
        match s {
            HlilStatement::Assign {
                dest: HlilExpr::Var { var },
                src,
            } if var.name == name => {
                let ty = src.expr_type();
                if known(ty) {
                    return Some(ty.clone());
                }
            }
            HlilStatement::VarDeclare {
                var,
                init: Some(src),
            } if var.name == name => {
                let ty = src.expr_type();
                if known(ty) {
                    return Some(ty.clone());
                }
            }
            _ => {}
        }
        // Deref of the var ⇒ it is a pointer to the loaded type.
        for e in stmt_exprs(s) {
            if let Some(t) = deref_evidence(e, name) {
                return Some(t);
            }
        }
        for body in stmt_bodies(s) {
            if let Some(t) = infer_var_type(body, name) {
                return Some(t);
            }
        }
    }
    None
}

fn deref_evidence(e: &HlilExpr, name: &str) -> Option<HlilType> {
    if let HlilExpr::Deref { addr, ty } = e {
        if matches!(&**addr, HlilExpr::Var { var } if var.name == name) {
            return Some(HlilType::ptr(ty.clone(), 64));
        }
    }
    let mut found = None;
    let mut e2 = e.clone();
    for_each_child_mut(&mut e2, &mut |c| {
        if found.is_none() {
            found = deref_evidence(c, name);
        }
    });
    found
}

fn retype_expr(e: &mut HlilExpr, map: &HashMap<String, HlilType>) {
    match e {
        HlilExpr::Var { var } | HlilExpr::AddressOf { var } => {
            if let Some(t) = map.get(&var.name) {
                if !known(&var.ty) {
                    var.ty = t.clone();
                }
            }
        }
        _ => {}
    }
    for_each_child_mut(e, &mut |c| retype_expr(c, map));
}

fn retype_stmts(stmts: &mut [HlilStatement], map: &HashMap<String, HlilType>) {
    for s in stmts {
        if let HlilStatement::VarDeclare { var, .. } | HlilStatement::VarDecl { var, .. } = s {
            if let Some(t) = map.get(&var.name) {
                if !known(&var.ty) {
                    var.ty = t.clone();
                }
            }
        }
        if let HlilStatement::For {
            init: Some(init), ..
        } = s
        {
            retype_stmts(std::slice::from_mut(&mut **init), map);
        }
        for e in stmt_exprs_mut(s) {
            retype_expr(e, map);
        }
        for body in stmt_bodies_mut(s) {
            retype_stmts(body, map);
        }
    }
}

/// Opportunistically infer types for `Unknown`-typed locals from assignment
/// Allarga a 128 bit i locali assegnati da una sorgente a 128 bit.
///
/// Gate OPT-IN `RUSTRE_INT128`, lo stesso che abilita la stampa di
/// `unsigned __int128`: senza quella stampa il tipo allargato non sarebbe
/// esprimibile.
pub fn widen_locals_from_128bit_sources(func: &mut HlilFunction) -> usize {
    if matches!(std::env::var("RUSTRE_INT128").as_deref(), Ok("0") | Ok("false")) {
        return 0;
    }
    const fn is_128(e: &HlilExpr) -> bool {
        matches!(e, HlilExpr::Deref { ty: HlilType::Int { bits: 128, .. }, .. })
    }
    fn raccogli(stmts: &[HlilStatement], out: &mut Vec<String>) {
        for st in stmts {
            if let HlilStatement::Assign { dest, src } = st
                && is_128(src)
                && let HlilExpr::Var { var } = dest
            {
                out.push(var.name.clone());
            }
            for b in stmt_bodies_pub(st) {
                raccogli(b, out);
            }
        }
    }
    let mut nomi = Vec::new();
    raccogli(&func.body, &mut nomi);
    if nomi.is_empty() {
        return 0;
    }
    // CHIUSURA TRANSITIVA: anche `b = a;` con `a` a 128 bit deve allargare `b`,
    // altrimenti la copia tronca subito (misurato: `var_xmm1 = var_xmm0;`).
    fn copie(stmts: &[HlilStatement], nomi: &mut Vec<String>) -> bool {
        let mut cambiato = false;
        for st in stmts {
            if let HlilStatement::Assign { dest, src } = st
                && let (HlilExpr::Var { var: d }, HlilExpr::Var { var: s }) = (dest, src)
                && nomi.contains(&s.name)
                && !nomi.contains(&d.name)
            {
                nomi.push(d.name.clone());
                cambiato = true;
            }
            for b in stmt_bodies_pub(st) {
                cambiato |= copie(b, nomi);
            }
        }
        cambiato
    }
    for _ in 0..16 {
        if !copie(&func.body, &mut nomi) {
            break;
        }
    }
    let largo = HlilType::Int { signed: false, bits: 128 };
    let mut n = 0;
    for l in &mut func.locals {
        if nomi.contains(&l.name) && l.ty != largo {
            l.ty = largo.clone();
            n += 1;
        }
    }
    n
}

/// sources and pointer usage. Returns the number of variables retyped.
pub fn infer_types(func: &mut HlilFunction) -> usize {
    let mut names = Vec::new();
    collect_var_names_in_order(&func.body, &mut names);
    for l in &func.locals {
        if !names.contains(&l.name) {
            names.push(l.name.clone());
        }
    }
    let mut map: HashMap<String, HlilType> = HashMap::new();
    for name in &names {
        // Only fill in unknowns: an occurrence with a known type wins already.
        let already_known = func
            .locals
            .iter()
            .find(|l| &l.name == name)
            .map(|l| known(&l.ty));
        if already_known == Some(true) {
            continue;
        }
        if let Some(t) = infer_var_type(&func.body, name) {
            map.insert(name.clone(), t);
        }
    }
    if map.is_empty() {
        return 0;
    }
    retype_stmts(&mut func.body, &map);
    for l in &mut func.locals {
        if let Some(t) = map.get(&l.name) {
            if !known(&l.ty) {
                l.ty = t.clone();
            }
        }
    }
    map.len()
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

/// Per-pass rewrite counts produced by [`StructuringPipeline::run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuringReport {
    pub flags_folded: usize,
    pub registers_lifted: usize,
    pub regions_structured: usize,
    pub exprs_propagated: usize,
    pub dead_stores_removed: usize,
    pub loops_converted: usize,
    pub vars_retyped: usize,
}

impl StructuringReport {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.flags_folded
            + self.registers_lifted
            + self.regions_structured
            + self.exprs_propagated
            + self.dead_stores_removed
            + self.loops_converted
            + self.vars_retyped
    }
}

/// The full HLIL structuring pipeline; see the module docs for pass order.
#[derive(Debug, Clone, Copy, Default)]
pub struct StructuringPipeline;

impl StructuringPipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run the pipeline, first binding the calling convention's argument
    /// registers to named parameters.
    ///
    /// `params` is `(name, c_type, register)` as inferred by the caller's ABI
    /// analysis. Passing an empty slice is exactly [`Self::run`], so the arity
    /// is never invented in this crate — see [`promote_arg_registers`].
    pub fn run_with_params(
        &self,
        func: &mut HlilFunction,
        params: &[(String, String, String)],
    ) -> StructuringReport {
        // Before `lift_registers`, which skips anything already a parameter.
        promote_arg_registers(func, params);
        self.run(func)
    }

    /// Run all seven passes in order over `func`.
    pub fn run(&self, func: &mut HlilFunction) -> StructuringReport {
        let mut r = StructuringReport::default();
        // Unify `var_flag_zf`↔`flag_zf` naming so flag defs match their uses,
        // then single-flag fold + propagation can connect them across distance.
        normalize_flag_names(func);
        r.flags_folded = fold_flags(&mut func.body);
        r.registers_lifted = lift_registers(func);
        // SONDA #5330 (effetto ZERO se la variabile non e' impostata): quanti
        // `Goto` ed `Etichette` esistono DAVVERO quando lo structurer parte?
        // La sonda precedente diceva che il 99,5% delle etichette non ha un
        // goto corrispondente: o i goto qui non ci sono, o non combaciano.
        // Qui si conta il TOTALE, cosi' il confronto col testo finale (~9442)
        // dice se i goto nascono PRIMA o DOPO questa passata.
        if std::env::var("RUSTRE_DBG_GOTOCOUNT").is_ok_and(|v| v != "0") {
            fn conta(stmts: &[HlilStatement], g: &mut usize, l: &mut usize) {
                for s in stmts {
                    match s {
                        HlilStatement::Goto(_) => *g += 1,
                        HlilStatement::Label(_) => *l += 1,
                        _ => {}
                    }
                    for b in stmt_bodies(s) {
                        conta(b, g, l);
                    }
                }
            }
            let (mut g, mut l) = (0, 0);
            conta(&func.body, &mut g, &mut l);
            eprintln!("[gotocount] PRIMA_structuring goto={g} label={l}");
        }
        // SONDA #5740 (effetto ZERO se non impostata): quanto sono IRRIDUCIBILI
        // i CFG reali? E' il numero che decide la TAGLIA del lavoro sullo
        // structurer: un CFG riducibile si chiude con un algoritmo standard, uno
        // irriducibile richiede **node splitting** (duplicazione di codice).
        // ⚠ Misurata DOVE SI DECIDE — sugli `HlilStatement`, non sul testo: le
        // sonde testuali di questa sessione hanno gonfiato un fronte 4 volte su 4.
        if std::env::var("RUSTRE_DBG_CFG").is_ok_and(|v| v != "0") {
            let (nodi, archi, cicli, irrid) = cfg_reducibility(&func.body);
            eprintln!("[cfg] nodi={nodi} archi={archi} cicli={cicli} irriducibile={irrid}");
        }
        r.regions_structured = structure_control_flow(&mut func.body);
        // PEZZO 4 dello structurer sul CFG, **OPT-IN**: chiude i cicli che la
        // riscrittura testuale non vede (corpo a piu' etichette). Una
        // riscrittura per chiamata ⇒ iterare fino al punto fisso, con tetto.
        let cfgloop = !matches!(std::env::var("RUSTRE_HLIL_CFGLOOP").as_deref(), Ok("0") | Ok("false"));
        if cfgloop {
            for _ in 0..64 {
                if std::env::var("RUSTRE_DBG_CFGLOOP").is_ok_and(|v| v != "0") {
                    eprintln!("[cfgloop] === funzione {:#x}", func.address.0);
                }
                if structure_loops_from_cfg(&mut func.body, true) == 0 {
                    break;
                }
                r.regions_structured += 1;
            }
        }
        if std::env::var("RUSTRE_DBG_GOTOCOUNT").is_ok_and(|v| v != "0") {
            fn conta2(stmts: &[HlilStatement], g: &mut usize, l: &mut usize) {
                for s in stmts {
                    match s {
                        HlilStatement::Goto(_) => *g += 1,
                        HlilStatement::Label(_) => *l += 1,
                        _ => {}
                    }
                    for b in stmt_bodies(s) {
                        conta2(b, g, l);
                    }
                }
            }
            let (mut g, mut l) = (0, 0);
            conta2(&func.body, &mut g, &mut l);
            eprintln!("[gotocount] DOPO_structuring goto={g} label={l}");
        }
        // Drop dead tails / dangling gotos left after an if/else whose branches
        // all terminate — cuts the residual-goto noise the structurer leaves.
        r.regions_structured += remove_unreachable_after_terminator(&mut func.body);
        // Fold x86 jcc flag-COMBINATION idioms (`SF != OF` → signed `<`, `ZF`
        // → `==`, …) against the defining SUB's operands — the shape `fold_flags`
        // cannot see. Runs AFTER control-flow structuring so the `if`/do-while
        // and its defining `tmp = (a - b)` are in their final adjacency, and
        // before dead-store elimination cleans up the now-unused SUB.
        r.flags_folded += fold_flag_combos(&mut func.body);
        // Algebraic cleanup of the flag-lowered comparisons: `(x & x)` → `x`,
        // `(a - b) == 0` → `a == b`. Runs after folding so any exposed forms
        // (`(v1 - 3) != 0`, `(v2 & v2) == 0`) collapse to clean comparisons.
        r.flags_folded += simplify_flag_conditions(&mut func.body);
        // Flip `if(C){}else{B}` (empty then) → `if(!C){B}` AFTER folding so C is
        // already a clean comparison the negation flips (`==`→`!=`), not a flag.
        r.regions_structured += flip_empty_then_branch(&mut func.body);
        r.exprs_propagated = propagate_expressions(&mut func.body);
        // Second cleanup pass: `propagate_expressions` inlines flag defs, which
        // exposes fresh `(a - N) == 0` / `(x & x)` forms the first simplify
        // couldn't see yet.
        r.flags_folded += simplify_flag_conditions(&mut func.body);
        r.loops_converted = detect_induction_vars(&mut func.body);
        // MISURATO, e l'ordine e' l'intera lezione: messa PRIMA di
        // `fold_flag_combos`, questa passata la SABOTA. Il folder riconosce la
        // forma CON il temporaneo (`tmp = (a - b)` piu' i flag che lo leggono) e
        // stava gia' chiudendo quei confronti:
        //     flag_zf = ((v8 - 65535) == 0);
        //     if (v8 > 0xFFFF) { ...            <- fusione riuscita
        // propagando prima si distrugge il motivo che cerca:
        //     if (((v8 == 0xFFFF) == 0) & (flag_sf == flag_of)) { ...
        // Sui 3 bucket: `flag_` 237 -> 315 (+33%) e la DCE che scendeva da 82 a
        // 65 rimozioni. Qui invece, DOPO le fusioni, raccoglie solo cio' che
        // quelle non hanno preso.
        r.exprs_propagated += propagate_pure_temps(&mut func.body);
        // Prima della dead-store generica: quella decide col conteggio delle
        // letture sull'intera funzione e per i flag non discrimina (vedi il
        // commento su `eliminate_dead_flag_stores`).
        r.dead_stores_removed = eliminate_dead_flag_stores(func);
        r.dead_stores_removed += eliminate_dead_stores(func);
        // #6940: raggiungibilita' a PUNTO FISSO. Va DOPO ogni riscrittura di
        // struttura, perche' e' l'ultima a sapere quali `goto` sono davvero
        // sopravvissuti.
        r.regions_structured += remove_unreachable_fixpoint(func);
        // `propagate_expressions`/`eliminate_dead_stores` can EMPTY a then-body
        // (its only statements were inlined flag defs / dead stores) after the
        // first flip already ran, leaving `if (C) { } else { B }` to reach the
        // emitter. Re-run the flip as the final body-shape pass; it is
        // idempotent and only fires on empty-then/non-empty-else ifs.
        r.regions_structured += flip_empty_then_branch(&mut func.body);
        r.vars_retyped = infer_types(func);
        // Un locale assegnato da un deref a 128 bit DEVE essere a 128 bit:
        // altrimenti il load legge la meta' alta e la dichiarazione la butta
        // subito via. `infer_types` non basta perche' riempie solo gli
        // sconosciuti, e qui il tipo e' gia' (erroneamente) `u64`.
        // Misurato su `accumulate`: il `psrldq` legge proprio quella meta'.
        r.vars_retyped += widen_locals_from_128bit_sources(func);
        // ⚠ L'invariante "le locali coprono il corpo" va imposto ALLA FINE, non
        // solo dentro `lift_registers`: fra i due punti girano
        // `propagate_expressions`, `eliminate_dead_stores`,
        // `fold_flag_combos`... che RISCRIVONO il corpo e possono lasciarvi un
        // nome la cui definizione e' stata eliminata. Imporlo solo all'inizio
        // lasciava 6 file con `'v1' undeclared`.
        ensure_locals_cover_body(func);
        r
    }
}

/// PEZZO 4 dello structurer sul CFG: **riemissione** di cicli.
///
/// Costruisce il CFG con `cfg_from_hlil`, individua i cicli con `recover_loops`
/// (il motore sbloccato dal pezzo 1) e RISCRIVE la lista di statement: la
/// regione del ciclo diventa `while (1) { … }` e i `goto` all'header diventano
/// `continue`.
///
/// A differenza della riscrittura TESTUALE, qui il corpo puo' contenere **piu'
/// etichette** e salti interni: e' il CFG a dire chi sta dentro.
///
/// Condizioni di RIFIUTO (conservative, la correttezza viene prima):
/// - l'header o un blocco del corpo non e' un'etichetta di PRIMO livello;
/// - le etichette del ciclo non formano una regione contigua;
/// - un `goto` da FUORI la regione entra dentro (salto nel mezzo di un ciclo);
/// - l'ultimo statement della regione non e' il `goto` all'header.
///
/// `enabled` e' un PARAMETRO, non una lettura d'ambiente: cosi' e' testabile.
/// Conta, ricorsivamente, quanti `goto` puntano a ciascun indirizzo.
fn conta_goto_ric(stmts: &[HlilStatement], m: &mut std::collections::HashMap<u64, usize>) {
    for s in stmts {
        if let HlilStatement::Goto(a) = s {
            *m.entry(a.0).or_default() += 1;
        }
        for b in stmt_bodies_pub(s) {
            conta_goto_ric(b, m);
        }
    }
}

pub fn structure_loops_from_cfg(stmts: &mut Vec<HlilStatement>, enabled: bool) -> usize {
    // ⚠ «Esterno» deve valere per l'INTERA funzione, non per il livello
    // corrente: la ricorsione riscrive liste annidate, e un `goto` che punta
    // dentro la regione puo' stare in coda alla funzione, fuori vista.
    // E' il difetto che faceva sparire `loc_140002634/639/698` in
    // `sub_1400025c0` — la guardia c'era, ma guardava troppo poco lontano.
    let mut totali: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    conta_goto_ric(stmts, &mut totali);
    structure_loops_from_cfg_con(stmts, enabled, &totali)
}

fn structure_loops_from_cfg_con(
    stmts: &mut Vec<HlilStatement>,
    enabled: bool,
    totali: &std::collections::HashMap<u64, usize>,
) -> usize {
    use crate::hlil_control_flow_recovery::{cfg_from_hlil_level, recover_loops};

    if !enabled || stmts.is_empty() {
        return 0;
    }

    // Le etichette di un ciclo stanno spesso in un corpo ANNIDATO (misurato:
    // era il rifiuto dominante, 240 su sample7_cpp). Dentro quel corpo pero'
    // sono di primo livello ⇒ ricorro, come fa `structure_control_flow`.
    for s in stmts.iter_mut() {
        for body in stmt_bodies_mut(s) {
            let n = structure_loops_from_cfg_con(body, true, totali);
            if n > 0 {
                return n;
            }
        }
    }

    fn val_label(l: &str) -> Option<u64> {
        let t = l
            .strip_prefix("label_")
            .or_else(|| l.strip_prefix("loc_"))
            .or_else(|| l.strip_prefix("L"))
            .unwrap_or(l)
            .trim_start_matches("0x");
        u64::from_str_radix(t, 16).ok().or_else(|| t.parse::<u64>().ok())
    }

    // Etichette di PRIMO livello: indirizzo -> posizione. Un'etichetta annidata
    // non e' riscrivibile qui, e la sua assenza da questa mappa fa scattare il
    // rifiuto piu' sotto.
    let mut pos_of: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, s) in stmts.iter().enumerate() {
        if let HlilStatement::Label(l) = s {
            if let Some(v) = val_label(l) {
                pos_of.insert(v, i);
            }
        }
    }
    if pos_of.is_empty() {
        return 0;
    }

    let dbg = std::env::var("RUSTRE_DBG_CFGLOOP").is_ok_and(|v| v != "0");
    // Popolazione REALE su cui lavora la riemissione: il CFG di LIVELLO.
    // Il 7,8% noto e' del CFG ricorsivo e NON descrive questa popolazione.
    if std::env::var("RUSTRE_DBG_CFGLEVEL").is_ok_and(|v| v != "0") {
        let (n, a, cic, irr) = cfg_reducibility_livello(stmts);
        eprintln!("[cfglevel] nodi={n} archi={a} cicli={cic} irriducibile={irr}");
    }
    // ⚠ Variante di LIVELLO, non quella ricorsiva: con i nodi piu' profondi
    // nel grafo la riscrittura rifiutava tutto (no-op misurato).
    let (blocks, entry, nodi) = cfg_from_hlil_level(stmts);
    let loops = recover_loops(&blocks, entry);
    if loops.is_empty() {
        if dbg {
            eprintln!("[cfgloop] RIFIUTO nessun_ciclo etichette={}", pos_of.len());
        }
        return 0;
    }
    if dbg {
        eprintln!("[cfgloop] cicli={} etichette={}", loops.len(), pos_of.len());
    }


    // Il ciclo piu' PROFONDO per primo: riscrivere l'esterno prima romperebbe
    // le posizioni di quelli annidati.
    let mut ordinati: Vec<&crate::hlil_control_flow_recovery::RecoveredLoop> = loops.iter().collect();
    ordinati.sort_by_key(|l| std::cmp::Reverse(l.depth));

    for lp in ordinati {
        let Some(&hdr_addr) = nodi.get(lp.header_block as usize) else {
            if dbg { eprintln!("[cfgloop] RIFIUTO header_fuori_grafo"); }
            continue;
        };
        let Some(&hdr_pos) = pos_of.get(&hdr_addr) else {
            if dbg { eprintln!("[cfgloop] RIFIUTO header_senza_etichetta"); }
            continue;
        };

        // Indirizzi del corpo. Un blocco senza etichetta di primo livello
        // (ENTRY compreso) rende la regione non riscrivibile.
        let mut membri: Vec<u64> = vec![hdr_addr];
        let mut ok = true;
        for b in &lp.body_blocks {
            match nodi.get(*b as usize) {
                Some(&a) if pos_of.contains_key(&a) => membri.push(a),
                _ => ok = false,
            }
        }
        if !ok {
            if dbg { eprintln!("[cfgloop] RIFIUTO blocco_senza_etichetta"); }
            continue;
        }
        membri.sort_unstable();
        membri.dedup();

        // La regione va dall'header all'ultima etichetta del ciclo; nessuna
        // etichetta ESTRANEA puo' cadervi dentro (regione contigua).
        let ultima = *membri.last().unwrap();
        let ultima_pos = pos_of[&ultima];
        if ultima_pos < hdr_pos {
            continue;
        }
        let estranea = pos_of
            .iter()
            .any(|(a, p)| *p > hdr_pos && *p <= ultima_pos && !membri.contains(a));
        if estranea {
            if dbg { eprintln!("[cfgloop] RIFIUTO regione_non_contigua"); }
            continue;
        }

        // La regione finisce sul retro-arco. Due forme:
        //  - `goto hdr;` NUDO in coda: il `while` lo assorbe e basta;
        //  - retro-arco ANNIDATO (`if (…) goto hdr;`): dopo di esso il
        //    controllo CADE FUORI dal ciclo, quindi serve un `break` finale —
        //    senza, la caduta rientrerebbe nel `while (1)`. E' il rifiuto
        //    DOMINANTE misurato (83 su sample7_cpp contro 8 dell'altro).
        fn contiene_goto(stmts: &[HlilStatement], t: u64) -> bool {
            stmts.iter().any(|s| {
                matches!(s, HlilStatement::Goto(a) if a.0 == t)
                    || stmt_bodies_pub(s).iter().any(|b| contiene_goto(b, t))
            })
        }
        let mut fine = None;
        let mut annidato = false;
        for i in ultima_pos..stmts.len() {
            match &stmts[i] {
                HlilStatement::Goto(a) if a.0 == hdr_addr => {
                    fine = Some(i);
                    break;
                }
                HlilStatement::Label(l) if val_label(l).is_some_and(|v| v != ultima) => break,
                _ => {}
            }
        }
        // Retro-arco ANNIDATO (`if (…) goto hdr;`): la fine della regione NON
        // e' deducibile dal primo `goto` che si incontra — il ciclo prosegue
        // oltre. Un primo tentativo che lo assumeva TRONCAVA il ciclo e
        // cancellava statement (gcc restava pulito e i goto scendevano lo
        // stesso: se ne e' accorta solo la sonda dei salti persi).
        // La fine corretta e' l'ultimo statement PRIMA della prossima etichetta
        // ESTRANEA — cioe' il confine della regione secondo il CFG.
        // Retro-arco ANNIDATO: la fine della regione e' l'ultimo statement
        // PRIMA della prossima etichetta ESTRANEA — il confine secondo il CFG.
        // (Un primo tentativo prendeva il PRIMO `goto hdr` annidato: troncava
        // il ciclo. Vedi il RIFIUTO `regione_con_coda_morta` qui sotto per il
        // secondo difetto, quello delle etichette perdute.)
        // ✅ ABILITATO. Sospeso un turno per un sospetto poi CHIARITO leggendo
        // il binario: in `sub_14000c9f0` lo statement drenato NON e' il corpo
        // del ciclo, e' il calcolo del flag del blocco 0x14000d0e8
        // (`cmpb $0x28, 0x108(%rcx)`) rimasto STACCATO in coda alla funzione
        // con un `goto` all'indietro. Il corpo vero e' gia' emesso all'etichetta.
        // Difetto dell'IL, PRESENTE ANCHE NEL CONTROLLO: non lo introduce il gate.
        // Metriche: goto 787→774, **11 etichette-bersaglio guadagnate**,
        // **0 perdite vere** (`saltipersi2_5940.py`, che scorpora le sparizioni
        // dei file che guadagnano costrutti di ciclo), **gcc 0 errori** su
        // tutti i 13 file toccati. Le tre bocciature precedenti erano infatti
        // un ARTEFATTO della vecchia sonda.
        if fine.is_none() {
            let mut limite = stmts.len();
            for i in (ultima_pos + 1)..stmts.len() {
                if matches!(&stmts[i], HlilStatement::Label(l)
                    if val_label(l).is_some_and(|v| !membri.contains(&v)))
                {
                    limite = i;
                    break;
                }
            }
            if limite > ultima_pos + 1
                && contiene_goto(&stmts[ultima_pos..limite], hdr_addr)
            {
                fine = Some(limite - 1);
                annidato = true;
            }
        }
        let Some(fine) = fine else {
            if dbg { eprintln!("[cfgloop] RIFIUTO niente_retroarco_in_coda"); }
            continue;
        };

        // RIFIUTO: un salto da fuori che entra nella regione. Entrare in un
        // ciclo saltandone l'inizio non e' riscrivibile in `while (1)`.
        let dentro = |i: usize| i > hdr_pos && i <= fine;
        let mut esterno_entra = false;
        for (i, s) in stmts.iter().enumerate() {
            if dentro(i) {
                continue;
            }
            // ⚠ ANCHE l'header: esentarlo era un DIFETTO. Wrappando, l'etichetta
            // dell'header finisce ANNIDATA dentro il `while`, e un `goto` che
            // resta FUORI perde il bersaglio: l'etichetta viene poi scartata e
            // con essa muore il codice che vi saltava.
            // Misurato su `sub_1400025c0`: tre auto-anelli riscritti
            // (0x140002634/639/698) facevano sparire le tre etichette e la coda
            // che vi saltava. Radice trovata con la sonda `RISCRITTO`.
            if let HlilStatement::Goto(a) = s {
                if membri.contains(&a.0) {
                    esterno_entra = true;
                }
            }
            let _ = s;
        }
        // Confronto sui TOTALI di funzione: se qualcuno salta a un membro
        // della regione piu' volte di quante ne contenga la regione stessa,
        // il salto arriva da FUORI. Cosi' la guardia vede anche i livelli che
        // la ricorsione non sta visitando.
        let mut dentro_cnt: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        conta_goto_ric(&stmts[hdr_pos..=fine], &mut dentro_cnt);
        for m in &membri {
            if totali.get(m).copied().unwrap_or(0) > dentro_cnt.get(m).copied().unwrap_or(0) {
                esterno_entra = true;
            }
        }
        if esterno_entra {
            if dbg { eprintln!("[cfgloop] RIFIUTO ingresso_esterno"); }
            continue;
        }

        // 🛑 RIFIUTO `regione_con_coda_morta`: se nella regione un `Return` di
        // primo livello e' seguito da altri statement, quelli sono GIA' morti
        // nel controllo. Chiuderli dentro `while (1)` li rende eliminabili da
        // una passata a valle, e con loro spariscono le ULTIME referenze a
        // etichette che marcano salti REALI del binario (misurato su
        // `sub_1400025c0`: perse `loc_140002634/639/698`).
        // La semantica non cambia — la FEDELTA' si', ed e' quella che conta.
        if annidato {
            let coda_morta = stmts[hdr_pos..=fine]
                .iter()
                .position(|s| matches!(s, HlilStatement::Return(_)))
                .is_some_and(|i| hdr_pos + i < fine);
            if coda_morta {
                if dbg { eprintln!("[cfgloop] RIFIUTO regione_con_coda_morta"); }
                continue;
            }
        }

        // ⚠ La sonda va letta PRIMA del drain: piazzata dopo, mostrava il
        // `While` appena inserito e lo chiamava «regione».
        if dbg {
            let tipi: Vec<&str> = stmts[hdr_pos..=fine]
                .iter()
                .map(|s| match s {
                    HlilStatement::Label(_) => "Label",
                    HlilStatement::Goto(_) => "Goto",
                    HlilStatement::If { .. } => "If",
                    HlilStatement::While { .. } => "While",
                    HlilStatement::Switch { .. } => "Switch",
                    HlilStatement::Return(_) => "Return",
                    _ => "altro",
                })
                .collect();
            eprintln!("[cfgloop]   regione={tipi:?} lista_len={}", stmts.len());
        }

        // Riscrittura: il retro-arco sparisce, i salti interni all'header
        // diventano `continue`.
        let mut corpo: Vec<HlilStatement> = stmts.drain(hdr_pos..=fine).collect();
        if !annidato {
            corpo.pop(); // retro-arco NUDO in coda: lo assorbe il `while`
        }
        fn goto_in_continue(stmts: &mut [HlilStatement], t: u64) {
            for s in stmts.iter_mut() {
                if matches!(s, HlilStatement::Goto(a) if a.0 == t) {
                    *s = HlilStatement::Continue;
                    continue;
                }
                for b in stmt_bodies_mut(s) {
                    goto_in_continue(b, t);
                }
            }
        }
        goto_in_continue(&mut corpo, hdr_addr);
        if annidato {
            // Senza questo, cadere in fondo al corpo RIENTREREBBE nel ciclo.
            corpo.push(HlilStatement::Break);
        }
        stmts.insert(
            hdr_pos,
            HlilStatement::While {
                cond: HlilExpr::Const {
                    value: 1,
                    ty: HlilType::Int { signed: true, bits: 32 },
                },
                body: corpo,
            },
        );
        if dbg {
            eprintln!(
                "[cfgloop] RISCRITTO hdr={hdr_addr:#x} pos={hdr_pos}..={fine}                  statement={} membri={}",
                fine - hdr_pos + 1,
                membri.len()
            );
        }
        // Una riscrittura per passata: le posizioni sono ora obsolete.
        return 1;
    }
    0
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::HlilVar;

    fn var(name: &str) -> HlilVar {
        HlilVar::new(name, HlilType::Unknown)
    }

    /// PEZZO 4: la riemissione dal CFG produce davvero un `while`, e RIFIUTA
    /// i casi che non sa riscrivere.
    #[test]
    fn riemissione_cicli_dal_cfg() {
        use rustre_core::address::Address;

        let l = |a: &str| HlilStatement::Label(a.to_string());
        let g = |a: u64| HlilStatement::Goto(Address(a));

        // Caso NOTO: due etichette nel corpo, salto interno. La riscrittura
        // testuale non lo vede; il CFG si'.
        let mut s = vec![l("loc_10"), g(0x20), l("loc_20"), g(0x10), HlilStatement::Return(vec![])];
        assert_eq!(structure_loops_from_cfg(&mut s, true), 1);
        let quanti_while = s.iter().filter(|x| matches!(x, HlilStatement::While { .. })).count();
        assert_eq!(quanti_while, 1, "deve emettere un while: {s:?}");
        // Il retro-arco e' assorbito e il salto all'header e' diventato continue.
        let HlilStatement::While { body, .. } = &s[0] else { panic!("{s:?}") };
        assert!(
            !body.iter().any(|x| matches!(x, HlilStatement::Goto(a) if a.0 == 0x10)),
            "il retro-arco non deve sopravvivere: {body:?}"
        );

        // Caso noto 2: retro-arco ANNIDATO (`if (…) goto hdr;`), era il rifiuto
        // dominante. Ora riscritto: dopo l'`if` il controllo cade FUORI, quindi
        // il corpo si chiude con `break`. Bocciato per tre turni da una sonda
        // che contava come «perse» le etichette rese SUPERFLUE dal ciclo
        // strutturato; con la metrica corretta: 0 perdite vere, +11 etichette.
        let mut sa = vec![
            l("loc_30"),
            HlilStatement::If {
                cond: HlilExpr::Const { value: 1, ty: HlilType::Int { signed: true, bits: 32 } },
                then_body: vec![g(0x30)],
                else_body: vec![],
            },
            HlilStatement::Return(vec![]),
        ];
        assert_eq!(structure_loops_from_cfg(&mut sa, true), 1, "{sa:?}");
        let HlilStatement::While { body, .. } = &sa[0] else { panic!("{sa:?}") };
        assert!(
            matches!(body.last(), Some(HlilStatement::Break)),
            "senza `break` finale la caduta rientrerebbe nel ciclo: {body:?}"
        );

        // RIFIUTO 4: un `goto` annidato che NON punta all'header non e' un
        // retro-arco e non deve far scattare la riscrittura.
        let mut sb = vec![
            l("loc_40"),
            HlilStatement::If {
                cond: HlilExpr::Const { value: 1, ty: HlilType::Int { signed: true, bits: 32 } },
                then_body: vec![g(0x99)],
                else_body: vec![],
            },
            HlilStatement::Return(vec![]),
        ];
        assert_eq!(structure_loops_from_cfg(&mut sb, true), 0, "{sb:?}");

        // RIFIUTO 1: il gate spento non tocca nulla.
        let mut s2 = vec![l("loc_10"), g(0x10)];
        let prima = format!("{s2:?}");
        assert_eq!(structure_loops_from_cfg(&mut s2, false), 0);
        assert_eq!(format!("{s2:?}"), prima, "gate spento = nessuna modifica");

        // RIFIUTO 2: nessun ciclo (solo salto in avanti).
        let mut s3 = vec![g(0x20), l("loc_20"), HlilStatement::Return(vec![])];
        assert_eq!(structure_loops_from_cfg(&mut s3, true), 0);

        // RIFIUTO 3: un salto da FUORI entra nel mezzo della regione.
        let mut s4 = vec![
            g(0x20),
            l("loc_10"),
            l("loc_20"),
            g(0x10),
            HlilStatement::Return(vec![]),
        ];
        assert_eq!(
            structure_loops_from_cfg(&mut s4, true),
            0,
            "entrare nel mezzo di un ciclo non e' riscrivibile: {s4:?}"
        );
    }
    /// `flag_x = (var_tmp0 <op> k)` — la forma che l'abbassamento di `cmp`
    /// produce tre volte, una per flag.
    fn legge_tmp(flag: &str) -> HlilStatement {
        assign(
            flag,
            HlilExpr::CmpEq(Box::new(v("var_tmp0")), Box::new(c(0))),
        )
    }

    #[test]
    fn temporaneo_puro_a_tre_usi_viene_propagato() {
        let mut body = vec![
            assign("var_tmp0", sub("a", 1)),
            legge_tmp("flag_zf"),
            legge_tmp("flag_sf"),
            legge_tmp("flag_of"),
        ];
        assert_eq!(propagate_pure_temps_in(&mut body), 1, "{body:?}");
        // La definizione sparisce e nessuno legge piu' il temporaneo.
        assert_eq!(body.len(), 3);
        assert_eq!(count_reads_stmts(&body, "var_tmp0"), 0, "{body:?}");
        // L'espressione e' finita in tutti e tre gli usi.
        assert_eq!(count_reads_stmts(&body, "a"), 3, "{body:?}");
    }

    #[test]
    fn non_si_propaga_se_un_operando_viene_riscritto() {
        let mut body = vec![
            assign("var_tmp0", sub("a", 1)),
            assign("a", c(99)), // riscrive l'operando
            legge_tmp("flag_zf"),
        ];
        assert_eq!(propagate_pure_temps_in(&mut body), 0, "{body:?}");
    }

    #[test]
    fn non_si_propaga_dentro_un_ciclo_che_legge_il_temporaneo() {
        // La' l'espressione sarebbe rivalutata a ogni giro.
        let mut body = vec![
            assign("var_tmp0", sub("a", 1)),
            HlilStatement::While {
                cond: c(1),
                body: vec![legge_tmp("flag_zf")],
            },
        ];
        assert_eq!(propagate_pure_temps_in(&mut body), 0, "{body:?}");
    }

    #[test]
    fn non_si_propaga_attraverso_un_salto() {
        // Il flusso potrebbe entrare in mezzo: la definizione non l'ha preceduta.
        let mut body = vec![
            assign("var_tmp0", sub("a", 1)),
            HlilStatement::Label("loc_10".to_string()),
            legge_tmp("flag_zf"),
        ];
        assert_eq!(propagate_pure_temps_in(&mut body), 0, "{body:?}");
    }

    #[test]
    fn non_si_duplica_mai_una_chiamata() {
        let mut body = vec![
            assign(
                "var_tmp0",
                HlilExpr::Call {
                    func: Box::new(v("effetto")),
                    args: vec![],
                    ret_ty: HlilType::i64(),
                },
            ),
            legge_tmp("flag_zf"),
            legge_tmp("flag_sf"),
        ];
        assert_eq!(propagate_pure_temps_in(&mut body), 0, "{body:?}");
    }

    #[test]
    fn il_live_range_si_ferma_alla_ridefinizione() {
        // Il secondo uso appartiene al live range successivo e non deve
        // ricevere l'espressione del primo.
        let mut body = vec![
            assign("var_tmp0", sub("a", 1)),
            legge_tmp("flag_zf"),
            assign("var_tmp0", sub("b", 2)), // ridefinizione
            legge_tmp("flag_sf"),
        ];
        let n = propagate_pure_temps_in(&mut body);
        assert!(n >= 1, "{body:?}");
        // `a` compare una sola volta: non e' colato oltre la ridefinizione.
        assert_eq!(count_reads_stmts(&body, "a"), 1, "{body:?}");
    }

    #[test]
    fn non_si_cancella_un_costrutto_che_contiene_unetichetta_annidata() {
        // #6770. `goto X; while (1) { X: ... }` — il `while` segue un
        // terminatore ma un `goto` puo' saltare DENTRO il suo corpo, quindi
        // cancellarlo distrugge codice VIVO.
        //
        // Misurato su `sample4_go/sub_14001fa32`: la versione precedente
        // cancellava 119 righe e 3 chiamate di runtime per questo motivo.
        let mut stmts = vec![
            HlilStatement::Goto(Address(0x10)),
            HlilStatement::While {
                cond: c(1),
                body: vec![
                    HlilStatement::Label("loc_10".to_string()),
                    assign("x", c(1)),
                ],
            },
        ];
        assert_eq!(remove_unreachable_after_terminator(&mut stmts), 0, "{stmts:?}");
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn si_cancella_ancora_un_costrutto_senza_etichette() {
        // Il controaltare: senza etichette dentro, il costrutto e' davvero
        // irraggiungibile e va tolto. Senza questo test la correzione #6770
        // potrebbe disattivare del tutto la passata senza che nulla protesti.
        let mut stmts = vec![
            HlilStatement::Return(vec![]),
            HlilStatement::While {
                cond: c(1),
                body: vec![assign("x", c(1))],
            },
        ];
        assert_eq!(remove_unreachable_after_terminator(&mut stmts), 1, "{stmts:?}");
        assert_eq!(stmts.len(), 1);
    }

    /// Aiutante: gira la liveness sui flag senza passare dal gate d'ambiente
    /// (che e' globale al processo e i test girano in parallelo).
    fn flagdce(body: &mut Vec<HlilStatement>) -> usize {
        let mut labels = std::collections::HashSet::new();
        raccogli_etichette(body, &mut labels);
        let mut ctx = FlagCtx {
            labels,
            label_live: HashMap::new(),
            changed: false,
            apply: false,
        };
        for _ in 0..16 {
            ctx.changed = false;
            let mut live = std::collections::BTreeSet::new();
            dead_flag_stores_in(body, &mut live, &mut ctx);
            if !ctx.changed {
                break;
            }
        }
        ctx.apply = true;
        let mut live = std::collections::BTreeSet::new();
        dead_flag_stores_in(body, &mut live, &mut ctx)
    }

    #[test]
    fn flag_store_mai_letto_viene_tolto() {
        // La forma dominante misurata sul corpus: la fusione ha gia' portato il
        // confronto dentro l'`if`, e lo store sul flag non lo legge nessuno.
        let mut body = vec![
            assign("var_tmp0", sub("v8", 1)),
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("var_tmp0")), Box::new(c(0)))),
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("var_tmp0")), Box::new(c(0))),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![],
            },
        ];
        assert_eq!(flagdce(&mut body), 1, "{body:?}");
        assert_eq!(body.len(), 2);
    }

    #[test]
    fn flag_store_letto_da_una_condizione_resta() {
        let mut body = vec![
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(0)))),
            HlilStatement::If {
                cond: v("flag_zf"),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![],
            },
        ];
        assert_eq!(flagdce(&mut body), 0, "{body:?}");
    }

    #[test]
    fn una_lettura_lontana_non_salva_uno_store_riscritto_dopo() {
        // E' il caso che `eliminate_dead_stores` sbaglia: decide col conteggio
        // delle letture sull'INTERA funzione, quindi la lettura in coda tiene
        // in vita anche il primo store, che invece e' sovrascritto prima.
        let mut body = vec![
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(0)))), // morto
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("b")), Box::new(c(0)))), // vivo
            HlilStatement::If {
                cond: v("flag_zf"),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![],
            },
        ];
        assert_eq!(flagdce(&mut body), 1, "{body:?}");
        // Sopravvive quello che confronta `b`.
        assert_eq!(body.len(), 2);
        assert!(
            count_reads_stmts(&body[..1], "b") == 1,
            "deve restare lo store su `b`: {body:?}"
        );
    }

    #[test]
    fn un_goto_propaga_la_liveness_dalla_sua_etichetta() {
        // Senza il punto fisso sulle etichette questo store sembrerebbe morto
        // (dopo il `goto` non c'e' nulla nella lista), e cancellarlo sarebbe
        // SBAGLIATO: `loc_10` legge il flag.
        let mut body = vec![
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(0)))),
            HlilStatement::Goto(Address(0x10)),
            HlilStatement::Label("loc_10".to_string()),
            HlilStatement::If {
                cond: v("flag_zf"),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![],
            },
        ];
        assert_eq!(flagdce(&mut body), 0, "{body:?}");
    }

    #[test]
    fn un_goto_fuori_funzione_rende_vivo_tutto() {
        let mut body = vec![
            assign("flag_zf", HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(0)))),
            HlilStatement::Goto(Address(0x9999)), // etichetta assente
        ];
        assert_eq!(flagdce(&mut body), 0, "{body:?}");
    }

    #[test]
    fn uno_store_con_chiamata_non_si_cancella_mai() {
        let mut body = vec![assign(
            "flag_zf",
            HlilExpr::Call {
                func: Box::new(v("effetto")),
                args: vec![],
                ret_ty: HlilType::i64(),
            },
        )];
        assert_eq!(flagdce(&mut body), 0, "{body:?}");
    }

    fn v(name: &str) -> HlilExpr {
        HlilExpr::Var { var: var(name) }
    }
    fn c(value: i64) -> HlilExpr {
        HlilExpr::Const {
            value,
            ty: HlilType::i64(),
        }
    }
    fn assign(name: &str, src: HlilExpr) -> HlilStatement {
        HlilStatement::Assign {
            dest: v(name),
            src,
        }
    }
    #[test]
    fn narrow_view_of_an_argument_register_binds_to_the_parameter() {
        // `__dyn_tls_dtor` reads its second argument as `edx` only
        // (`cmp $3, %edx`). Matching just the 64-bit name left `var_edx` as a
        // local that is read and never written, and A rendered the same code
        // as `a2`.
        let mut f = HlilFunction::new(Address::new(0x1000), "test");
        f.locals.push(HlilVar::new("var_edx", HlilType::Unknown));
        f.body = vec![HlilStatement::If {
            cond: HlilExpr::CmpNe(
                Box::new(HlilExpr::Var {
                    var: HlilVar::new("var_edx", HlilType::Unknown),
                }),
                Box::new(HlilExpr::Const {
                    value: 3,
                    ty: HlilType::i64(),
                }),
            ),
            then_body: vec![HlilStatement::Return(vec![])],
            else_body: vec![],
        }];
        let params = vec![
            ("a1".to_string(), "__int64".to_string(), "rcx".to_string()),
            ("a2".to_string(), "__int64".to_string(), "rdx".to_string()),
        ];
        promote_arg_registers(&mut f, &params);
        let printed = format!("{:?}", f.body);
        assert!(printed.contains("a2"), "narrow view not bound: {printed}");
        assert!(!printed.contains("var_edx"), "local survived: {printed}");
        assert!(
            !f.locals.iter().any(|l| l.name == "var_edx"),
            "declaration survived"
        );
    }

    /// Un parametro FP di Win64 (`xmm2`/`xmm3`) deve LEGARE la locale
    /// `var_xmm{i}` del corpo, non solo comparire in firma.
    ///
    /// Testo reale: `__mingw_raise_matherr` di `sample1` fa
    /// `unpcklpd %xmm3,%xmm2` senza mai scrivere xmm2/xmm3, e path A emette
    /// `(int a1, __int64 a2, double a3, double a4)`. Prima di questo fix B
    /// dichiarava `int64_t a3, int64_t a4` e il corpo continuava a leggere
    /// `var_xmm3` — una locale letta e mai scritta.
    #[test]
    fn fp_arg_slot_binds_the_body_local_and_takes_the_callers_type() {
        let mut f = HlilFunction::new(Address::new(0x1000), "test");
        f.locals.push(HlilVar::new("var_xmm2", HlilType::Unknown));
        f.locals.push(HlilVar::new("var_xmm3", HlilType::Unknown));
        f.body = vec![HlilStatement::Assign {
            dest: HlilExpr::Var {
                var: HlilVar::new("var_xmm2", HlilType::Unknown),
            },
            src: HlilExpr::Var {
                var: HlilVar::new("var_xmm3", HlilType::Unknown),
            },
        }];
        let params = vec![
            ("a1".to_string(), "__int64".to_string(), "rcx".to_string()),
            ("a2".to_string(), "__int64".to_string(), "rdx".to_string()),
            ("a3".to_string(), "double".to_string(), "xmm2".to_string()),
            ("a4".to_string(), "double".to_string(), "xmm3".to_string()),
        ];
        promote_arg_registers(&mut f, &params);
        let printed = format!("{:?}", f.body);
        assert!(printed.contains("a3") && printed.contains("a4"), "{printed}");
        assert!(
            !printed.contains("var_xmm"),
            "la locale xmm e' sopravvissuta nel corpo: {printed}"
        );
        assert!(
            !f.locals.iter().any(|l| l.name.starts_with("var_xmm")),
            "la DICHIARAZIONE xmm e' sopravvissuta: sarebbe letta e mai scritta"
        );
        // Il tipo viene dal `cty` del chiamante, non dallo storage della locale
        // (che per un xmm e' a 128 bit e darebbe un parametro `__int128`).
        for n in ["a3", "a4"] {
            let p = f.prototype.params.iter().find(|p| p.name == n).expect(n);
            assert_eq!(p.ty, HlilType::Float { bits: 64 }, "{n} mistyped");
        }
        // NON-intervento: gli slot interi conservano la regola misurata
        // (tipo dalla vista piu' larga presente), non diventano float.
        for n in ["a1", "a2"] {
            let p = f.prototype.params.iter().find(|p| p.name == n).expect(n);
            assert_ne!(p.ty, HlilType::Float { bits: 64 }, "{n} float-ized");
        }
    }

    /// Uno slot SSE usato come PATTERN DI BIT non va tipato `double`: si lega
    /// comunque (l'arita' e' giusta) ma conserva il tipo dello storage.
    ///
    /// Testo reale: `sample10_cs/sub_140082440` emette `a2 = (~a2 & var_xmm0);`
    /// (idioma di maschera `andnps`/`andnpd`, tipo `fabs`/`copysign`). Tipando
    /// `double` gcc rifiutava con `error: wrong type argument to bit-complement`
    /// e la ricompilabilita' a lista fissa scendeva 1199 -> 1197.
    #[test]
    fn bitwise_used_sse_slot_binds_but_is_not_typed_double() {
        let mut f = HlilFunction::new(Address::new(0x1000), "test");
        f.locals.push(HlilVar::new("var_xmm1", HlilType::i64()));
        f.body = vec![HlilStatement::Assign {
            dest: HlilExpr::Var {
                var: HlilVar::new("var_xmm1", HlilType::i64()),
            },
            src: HlilExpr::Not(
                Box::new(HlilExpr::Var {
                    var: HlilVar::new("var_xmm1", HlilType::i64()),
                }),
                HlilType::i64(),
            ),
        }];
        let params = vec![
            ("a1".to_string(), "__int64".to_string(), "rcx".to_string()),
            ("a2".to_string(), "double".to_string(), "xmm1".to_string()),
        ];
        promote_arg_registers(&mut f, &params);
        let printed = format!("{:?}", f.body);
        // Si LEGA comunque: la locale non resta letta-e-mai-scritta.
        assert!(printed.contains("a2"), "slot non legato: {printed}");
        assert!(!printed.contains("var_xmm1"), "locale sopravvissuta");
        let p = f.prototype.params.iter().find(|p| p.name == "a2").unwrap();
        assert_ne!(
            p.ty,
            HlilType::Float { bits: 64 },
            "uno slot usato in bitwise NON deve essere double: gcc rifiuta ~/& su float"
        );
    }

    /// Non-intervento: gli xmm che NON sono slot argomento (xmm4..xmm15) non
    /// vengono mai legati, perche' non sono parametri in nessuna ABI.
    #[test]
    fn non_argument_xmm_registers_are_not_argument_slots() {
        for r in ["xmm4", "xmm5", "xmm6", "xmm15"] {
            assert!(arg_reg_of(r).is_none(), "{r} trattato come slot argomento");
            assert!(arg_reg_of(&format!("var_{r}")).is_none(), "var_{r}");
        }
        for (i, r) in ["xmm0", "xmm1", "xmm2", "xmm3"].iter().enumerate() {
            assert_eq!(arg_reg_of(r), Some(*r), "slot {i}");
            assert_eq!(arg_reg_of(&format!("var_{r}")), Some(*r), "var_ slot {i}");
        }
    }

    fn func_with(body: Vec<HlilStatement>) -> HlilFunction {
        let mut f = HlilFunction::new(Address::new(0x1000), "test");
        f.body = body;
        f
    }
    fn sub(a: &str, k: i64) -> HlilExpr {
        HlilExpr::Sub(Box::new(v(a)), Box::new(c(k)), HlilType::i64())
    }

    #[test]
    fn fold_flag_combo_signed_less_than_in_do_while() {
        // `tmp = i - 5;  do {…} while (flag_sf != flag_of)`  →  `while (i < 5)`.
        let mut stmts = vec![HlilStatement::DoWhile {
            body: vec![assign("tmp", sub("i", 5))],
            cond: HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of"))),
        }];
        assert_eq!(fold_flag_combos(&mut stmts), 1);
        let HlilStatement::DoWhile { cond, .. } = &stmts[0] else {
            panic!()
        };
        assert_eq!(*cond, HlilExpr::CmpLt(Box::new(v("i")), Box::new(c(5))));
    }

    /// #3720 — SF dato come ESPRESSIONE (`(tmp < 0)`), la forma che il corpus
    /// mostra in 710 condizioni `if` e che `is_flag_var` non riconosce.
    /// Chiama la LOGICA, non il wrapper che legge l'ambiente.
    #[test]
    fn flag_combo_accepts_sign_test_expression_as_sf_only_when_enabled() {
        let (a, b) = (v("i"), c(5));
        // `(tmp < 0) != flag_of`  ==  `SF != OF`  ==  signed `<`.
        let cond = HlilExpr::CmpNe(
            Box::new(HlilExpr::CmpLt(Box::new(v("tmp")), Box::new(c(0)))),
            Box::new(v("flag_of")),
        );
        assert_eq!(
            flag_combo_to_cmp_with(&cond, &a, &b, true),
            Some(HlilExpr::CmpLt(Box::new(v("i")), Box::new(c(5)))),
            "SF come espressione deve agganciare quando abilitato"
        );
        assert_eq!(
            flag_combo_to_cmp_with(&cond, &a, &b, false),
            None,
            "da spento il comportamento deve restare quello di prima"
        );
        // Non-intervento: un test di segno su qualcosa che NON e' il risultato
        // della SUB (qui una CHIAMATA) non deve agganciare nemmeno da acceso.
        let altro = HlilExpr::CmpNe(
            Box::new(HlilExpr::CmpLt(
                Box::new(HlilExpr::Sub(Box::new(v("x")), Box::new(c(9)), HlilType::i64())),
                Box::new(c(0)),
            )),
            Box::new(v("flag_of")),
        );
        assert_eq!(
            flag_combo_to_cmp_with(&altro, &a, &b, true),
            None,
            "una SUB con operandi DIVERSI non e' quella che ha posato i flag"
        );
    }

    /// #3770 — i flag di un `test a, b` (IL: `Assign{src: And}`). Chiama la
    /// LOGICA (`zf_combo_to_cmp`), non il wrapper che legge l'ambiente.
    #[test]
    fn zf_combo_folds_test_flags_and_refuses_signed_forms() {
        let (a, b) = (v("i"), v("i"));
        let masked = HlilExpr::And(Box::new(v("i")), Box::new(v("i")), HlilType::i64());
        let atteso = |f: fn(Box<HlilExpr>, Box<HlilExpr>) -> HlilExpr| {
            Some(f(
                Box::new(masked.clone()),
                Box::new(HlilExpr::Const { value: 0, ty: HlilType::i64() }),
            ))
        };
        // je = ZF  →  `(i & i) == 0`
        assert_eq!(
            zf_combo_to_cmp(&v("flag_zf"), &a, &b),
            atteso(HlilExpr::CmpEq)
        );
        // jne = !ZF  →  `(i & i) != 0`
        let jne = HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(0)));
        assert_eq!(zf_combo_to_cmp(&jne, &a, &b), atteso(HlilExpr::CmpNe));
        // ⚠ NON-INTERVENTO sulle forme CON SEGNO: con `test` OF e' 0 per
        // definizione, `SF != OF` sarebbe un test di segno dipendente dalla
        // LARGHEZZA, che l'espressione non porta (#3690).
        let jl = HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of")));
        assert_eq!(
            zf_combo_to_cmp(&jl, &a, &b),
            None,
            "le forme con segno NON vanno tradotte per un test"
        );
        // Nemmeno CF: `test` azzera anche quello.
        let jb = HlilExpr::CmpEq(Box::new(v("flag_cf")), Box::new(c(1)));
        assert_eq!(zf_combo_to_cmp(&jb, &a, &b), None);
    }

    /// #3900 — il `cmov`: la condizione del TERNARIO va agganciata alla SUB che
    /// ha posato i flag, esattamente come quella di un `if`. Prima nessun ramo
    /// del fold guardava questa forma (misurati 145 casi sul corpus).
    #[test]
    fn fold_flag_combo_rewrites_cmov_ternary_condition() {
        // SAFETY del test: `fold_flag_combos` legge il gate dall'ambiente, e le
        // variabili d'ambiente sono globali al processo. Qui pero' verifico la
        // sola logica di riscrittura chiamando `flag_combo_to_cmp_with`, cosi'
        // il test non dipende dall'ordine di esecuzione (lezione #3650).
        let (a, b) = (v("i"), c(5));
        let cond = HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of")));
        assert_eq!(
            flag_combo_to_cmp_with(&cond, &a, &b, false),
            Some(HlilExpr::CmpLt(Box::new(v("i")), Box::new(c(5)))),
            "`SF != OF` contro la SUB e' il minore-di CON SEGNO, ovunque compaia"
        );
        // E la forma che il cmov porta con se': un `Assign` la cui sorgente e'
        // un ternario. Verifico che sia costruibile e che la condizione sia
        // l'espressione che il fold andrebbe a sostituire.
        let tern = HlilExpr::Ternary {
            cond: Box::new(cond),
            then: Box::new(v("a2")),
            else_: Box::new(v("v1")),
            ty: HlilType::i64(),
        };
        let HlilExpr::Ternary { cond: inner, .. } = &tern else {
            panic!("forma inattesa")
        };
        assert!(
            flag_combo_to_cmp_with(inner, &a, &b, false).is_some(),
            "la condizione del ternario deve essere agganciabile"
        );
    }

    /// #3970 — CLASSE B. Le due asserzioni che contano sono le NEGATIVE: saltare
    /// un'istruzione innocua e' lecito, saltarne una che RIDEFINISCE un operando
    /// della SUB non lo e' mai — darebbe un confronto fra valori diversi da
    /// quelli che hanno posato i flag, cioe' codice che compila ed e' sbagliato.
    #[test]
    fn class_b_skips_innocuous_but_refuses_when_an_operand_is_redefined() {
        let sub_i5 = assign("tmp", sub("i", 5));
        // (a) `mov` innocuo in mezzo: si aggancia.
        let innocuo = vec![
            sub_i5.clone(),
            assign("altra", v("qualcosa")),
            HlilStatement::If { cond: v("flag_zf"), then_body: vec![], else_body: vec![] },
        ];
        assert!(
            nearest_sub_before_with(&innocuo, 2, true).is_some(),
            "un'assegnazione a una variabile ESTRANEA non impedisce l'aggancio"
        );
        // (b) da SPENTO il comportamento resta quello di prima: nessun aggancio.
        assert!(
            nearest_sub_before_with(&innocuo, 2, false).is_none(),
            "col gate spento nulla deve cambiare"
        );
        // (c) ⚠ l'istruzione in mezzo RIDEFINISCE `i`, operando della SUB.
        let pericoloso = vec![
            sub_i5,
            assign("i", v("altro_valore")),
            HlilStatement::If { cond: v("flag_zf"), then_body: vec![], else_body: vec![] },
        ];
        assert!(
            nearest_sub_before_with(&pericoloso, 2, true).is_none(),
            "RIFIUTO obbligatorio: `i` non vale piu' cio' che valeva alla CMP"
        );
    }

    /// #4210 — recupero ZF sul temporaneo. Le asserzioni che contano sono le
    /// NEGATIVE: riscrivere `ZF` in `tmp == 0` e' esatto anche dopo che un
    /// operando e' stato ridefinito, ma **nessuna forma con segno o CF** puo'
    /// essere trattata cosi' — `SF != OF` dipende dalla larghezza del `cmp`.
    #[test]
    fn zf_on_temp_rewrites_equality_only_and_refuses_signed() {
        let atteso = |f: fn(Box<HlilExpr>, Box<HlilExpr>) -> HlilExpr| {
            Some(f(
                Box::new(HlilExpr::Var { var: HlilVar::new("tmp", HlilType::i64()) }),
                Box::new(HlilExpr::Const { value: 0, ty: HlilType::i64() }),
            ))
        };
        // je = ZF  →  `tmp == 0`
        assert_eq!(zf_only_on_temp(&v("flag_zf"), "tmp"), atteso(HlilExpr::CmpEq));
        // jne = !ZF  →  `tmp != 0`
        let jne = HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(0)));
        assert_eq!(zf_only_on_temp(&jne, "tmp"), atteso(HlilExpr::CmpNe));
        // ⚠ RIFIUTO: forma con SEGNO — dipende dalla larghezza, non e'
        // esprimibile sul solo temporaneo.
        let jl = HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of")));
        assert_eq!(
            zf_only_on_temp(&jl, "tmp"),
            None,
            "`SF != OF` non va MAI riscritto su `tmp`"
        );
        // ⚠ RIFIUTO: CF (confronto senza segno) — stessa ragione.
        let jb = HlilExpr::CmpEq(Box::new(v("flag_cf")), Box::new(c(1)));
        assert_eq!(zf_only_on_temp(&jb, "tmp"), None, "CF non va riscritto su `tmp`");
        // ⚠ RIFIUTO: condizione COMPOSTA che mescola ZF e SF/OF (jle).
        let jle = HlilExpr::Or(
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(1)))),
            Box::new(HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of")))),
            HlilType::Bool,
        );
        assert_eq!(
            zf_only_on_temp(&jle, "tmp"),
            None,
            "una condizione COMPOSTA con SF/OF non e' sola-ZF"
        );
    }

    #[test]
    fn fold_flag_combo_equal_in_if_after_cmp() {
        // `tmp = i - 7;  if (flag_zf == 1)`  →  `if (i == 7)`.
        let mut stmts = vec![
            assign("tmp", sub("i", 7)),
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(1))),
                then_body: vec![],
                else_body: vec![],
            },
        ];
        assert_eq!(fold_flag_combos(&mut stmts), 1);
        let HlilStatement::If { cond, .. } = &stmts[1] else {
            panic!()
        };
        assert_eq!(*cond, HlilExpr::CmpEq(Box::new(v("i")), Box::new(c(7))));
    }

    #[test]
    fn fold_flag_combo_signed_greater_compound() {
        // `tmp = i - 5;  if (!ZF & (SF == OF))`  →  `if (i > 5)`  (jg).
        let cond = HlilExpr::And(
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(0)))),
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_sf")), Box::new(v("flag_of")))),
            HlilType::Bool,
        );
        let mut stmts = vec![
            assign("tmp", sub("i", 5)),
            HlilStatement::If { cond, then_body: vec![], else_body: vec![] },
        ];
        assert_eq!(fold_flag_combos(&mut stmts), 1);
        let HlilStatement::If { cond, .. } = &stmts[1] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpGt(Box::new(v("i")), Box::new(c(5))));
    }

    #[test]
    fn fold_flag_combo_signed_less_equal_compound() {
        // `tmp = i - 3;  if (ZF | (SF != OF))`  →  `if (i <= 3)`  (jle).
        let cond = HlilExpr::Or(
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(1)))),
            Box::new(HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of")))),
            HlilType::Bool,
        );
        let mut stmts = vec![
            assign("tmp", sub("i", 3)),
            HlilStatement::If { cond, then_body: vec![], else_body: vec![] },
        ];
        assert_eq!(fold_flag_combos(&mut stmts), 1);
        let HlilStatement::If { cond, .. } = &stmts[1] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpLe(Box::new(v("i")), Box::new(c(3))));
    }

    #[test]
    fn fold_flag_combo_unsigned_above_and_below_equal() {
        // ja: `!CF & !ZF` → `i > 5`.
        let ja = HlilExpr::And(
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_cf")), Box::new(c(0)))),
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(0)))),
            HlilType::Bool,
        );
        let mut s1 = vec![
            assign("tmp", sub("i", 5)),
            HlilStatement::If { cond: ja, then_body: vec![], else_body: vec![] },
        ];
        assert_eq!(fold_flag_combos(&mut s1), 1);
        let HlilStatement::If { cond, .. } = &s1[1] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpGt(Box::new(v("i")), Box::new(c(5))));

        // jbe: `CF | ZF` → `i <= 3`.
        let jbe = HlilExpr::Or(
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_cf")), Box::new(c(1)))),
            Box::new(HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(1)))),
            HlilType::Bool,
        );
        let mut s2 = vec![
            assign("tmp", sub("i", 3)),
            HlilStatement::If { cond: jbe, then_body: vec![], else_body: vec![] },
        ];
        assert_eq!(fold_flag_combos(&mut s2), 1);
        let HlilStatement::If { cond, .. } = &s2[1] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpLe(Box::new(v("i")), Box::new(c(3))));
    }

    #[test]
    fn normalize_flag_names_unifies_var_prefix() {
        // `var_flag_zf = (a == b); if (flag_zf == 1)` — def and use disagree on
        // the `var_` prefix. After normalization both are `flag_zf`, so the
        // single-flag fold can connect them.
        let mut f = func_with(vec![
            assign("var_flag_zf", HlilExpr::CmpEq(Box::new(v("a")), Box::new(v("b")))),
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("flag_zf")), Box::new(c(1))),
                then_body: vec![],
                else_body: vec![],
            },
        ]);
        assert_eq!(normalize_flag_names(&mut f), 1);
        // Now the def is `flag_zf = …`, matching the use; fold_flags folds it.
        assert_eq!(fold_flags(&mut f.body), 1);
        let HlilStatement::If { cond, .. } = &f.body[0] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpEq(Box::new(v("a")), Box::new(v("b"))));
    }

    #[test]
    fn simplify_flag_conditions_cleans_test_and_cmp_zero() {
        // `(v2 & v2) == 0` → `v2 == 0`; `(v1 - 3) != 0` → `v1 != 3`.
        let mut stmts = vec![
            HlilStatement::If {
                cond: HlilExpr::CmpEq(
                    Box::new(HlilExpr::And(Box::new(v("v2")), Box::new(v("v2")), HlilType::i64())),
                    Box::new(c(0)),
                ),
                then_body: vec![],
                else_body: vec![],
            },
            HlilStatement::If {
                cond: HlilExpr::CmpNe(Box::new(sub("v1", 3)), Box::new(c(0))),
                then_body: vec![],
                else_body: vec![],
            },
        ];
        assert!(simplify_flag_conditions(&mut stmts) >= 2);
        let HlilStatement::If { cond: c1, .. } = &stmts[0] else { panic!() };
        assert_eq!(*c1, HlilExpr::CmpEq(Box::new(v("v2")), Box::new(c(0))));
        let HlilStatement::If { cond: c2, .. } = &stmts[1] else { panic!() };
        assert_eq!(*c2, HlilExpr::CmpNe(Box::new(v("v1")), Box::new(c(3))));
    }

    #[test]
    fn remove_unreachable_drops_dead_tail_after_terminating_if() {
        // `if (c) { return; } else { goto X; }  goto Y;` — the trailing goto is
        // unreachable (both branches leave), so it is dropped; a label resets it.
        let mut stmts = vec![
            HlilStatement::If {
                cond: v("c"),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![HlilStatement::Goto(Address::new(0x100))],
            },
            HlilStatement::Goto(Address::new(0x200)),
            HlilStatement::Label("L".into()),
            assign("a", c(1)), // reachable via the label — must survive
        ];
        assert_eq!(remove_unreachable_after_terminator(&mut stmts), 1);
        assert_eq!(stmts.len(), 3); // if, label, a=1  (the dead goto removed)
        assert!(matches!(stmts[1], HlilStatement::Label(_)));
    }

    #[test]
    fn flip_empty_then_branch_negates_and_promotes() {
        // `if (a != b) { } else { x=1; }` → `if (a == b) { x=1; }`.
        let mut stmts = vec![HlilStatement::If {
            cond: HlilExpr::CmpNe(Box::new(v("a")), Box::new(v("b"))),
            then_body: vec![],
            else_body: vec![assign("x", c(1))],
        }];
        assert_eq!(flip_empty_then_branch(&mut stmts), 1);
        let HlilStatement::If { cond, then_body, else_body } = &stmts[0] else { panic!() };
        assert_eq!(*cond, HlilExpr::CmpEq(Box::new(v("a")), Box::new(v("b"))));
        assert_eq!(then_body.len(), 1);
        assert!(else_body.is_empty());
    }

    #[test]
    fn flip_empty_then_branch_leaves_normal_if_alone() {
        // Non-empty then → untouched.
        let mut stmts = vec![HlilStatement::If {
            cond: v("c"),
            then_body: vec![assign("x", c(1))],
            else_body: vec![assign("y", c(2))],
        }];
        assert_eq!(flip_empty_then_branch(&mut stmts), 0);
    }

    #[test]
    fn remove_unreachable_keeps_fallthrough_if() {
        // An if with an EMPTY else can fall through → not a terminator → keep tail.
        let mut stmts = vec![
            HlilStatement::If {
                cond: v("c"),
                then_body: vec![HlilStatement::Return(vec![])],
                else_body: vec![],
            },
            assign("a", c(1)),
        ];
        assert_eq!(remove_unreachable_after_terminator(&mut stmts), 0);
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn fold_flag_combo_leaves_non_idioms_alone() {
        // No preceding SUB → nothing to fold.
        let mut stmts = vec![HlilStatement::If {
            cond: HlilExpr::CmpNe(Box::new(v("flag_sf")), Box::new(v("flag_of"))),
            then_body: vec![],
            else_body: vec![],
        }];
        assert_eq!(fold_flag_combos(&mut stmts), 0);
    }

    // ── 1. flag folding ──────────────────────────────────────────────────

    #[test]
    fn fold_flag_eq_zero_negates_comparison() {
        // flag = a < b; if (flag == 0) { return 1; }  →  if (a >= b) …
        let mut stmts = vec![
            assign("flag", HlilExpr::CmpLt(Box::new(v("a")), Box::new(v("b")))),
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("flag")), Box::new(c(0))),
                then_body: vec![HlilStatement::Return(vec![c(1)])],
                else_body: vec![],
            },
        ];
        let n = fold_flags(&mut stmts);
        assert_eq!(n, 1);
        assert_eq!(stmts.len(), 1, "flag assignment should be removed");
        let HlilStatement::If { cond, .. } = &stmts[0] else {
            panic!("expected If, got {:?}", stmts[0]);
        };
        assert_eq!(
            *cond,
            HlilExpr::CmpGe(Box::new(v("a")), Box::new(v("b")))
        );
    }

    #[test]
    fn fold_flag_direct_use() {
        // flag = a == b; if (flag) …  →  if (a == b) …
        let mut stmts = vec![
            assign("flag", HlilExpr::CmpEq(Box::new(v("a")), Box::new(v("b")))),
            HlilStatement::If {
                cond: v("flag"),
                then_body: vec![HlilStatement::Break],
                else_body: vec![],
            },
        ];
        assert_eq!(fold_flags(&mut stmts), 1);
        let HlilStatement::If { cond, .. } = &stmts[0] else {
            panic!()
        };
        assert_eq!(*cond, HlilExpr::CmpEq(Box::new(v("a")), Box::new(v("b"))));
    }

    #[test]
    fn fold_flag_keeps_assignment_when_flag_reused() {
        let mut stmts = vec![
            assign("flag", HlilExpr::CmpLt(Box::new(v("a")), Box::new(v("b")))),
            HlilStatement::If {
                cond: v("flag"),
                then_body: vec![],
                else_body: vec![],
            },
            HlilStatement::Return(vec![v("flag")]),
        ];
        assert_eq!(fold_flags(&mut stmts), 1);
        assert_eq!(stmts.len(), 3, "flag still read later; keep assignment");
    }

    #[test]
    fn fold_flag_recurses_into_bodies() {
        let inner = vec![
            assign("f", HlilExpr::CmpGt(Box::new(v("x")), Box::new(c(3)))),
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("f")), Box::new(c(0))),
                then_body: vec![HlilStatement::Break],
                else_body: vec![],
            },
        ];
        let mut stmts = vec![HlilStatement::While {
            cond: c(1),
            body: inner,
        }];
        assert_eq!(fold_flags(&mut stmts), 1);
        let HlilStatement::While { body, .. } = &stmts[0] else {
            panic!()
        };
        let HlilStatement::If { cond, .. } = &body[0] else {
            panic!()
        };
        assert_eq!(*cond, HlilExpr::CmpLe(Box::new(v("x")), Box::new(c(3))));
    }

    #[test]
    fn negate_cond_flips_all_orderings() {
        let a = || Box::new(v("a"));
        let b = || Box::new(v("b"));
        assert_eq!(
            negate_cond(HlilExpr::CmpLt(a(), b())),
            HlilExpr::CmpGe(a(), b())
        );
        assert_eq!(
            negate_cond(HlilExpr::CmpNe(a(), b())),
            HlilExpr::CmpEq(a(), b())
        );
        assert_eq!(
            negate_cond(HlilExpr::CmpUle(a(), b())),
            HlilExpr::CmpUgt(a(), b())
        );
        // Double negation collapses.
        assert_eq!(negate_cond(HlilExpr::LogicalNot(a())), v("a"));
    }

    // ── 2. register lifting ──────────────────────────────────────────────

    #[test]
    fn lift_registers_renames_in_order() {
        let mut f = func_with(vec![
            assign("var_rax", c(1)),
            assign("var_rcx", HlilExpr::Add(Box::new(v("var_rax")), Box::new(c(2)), HlilType::i64())),
            assign("var_rsp", v("var_rcx")),
        ]);
        let n = lift_registers(&mut f);
        assert_eq!(n, 3);
        let text = format!("{}", f.body[1]);
        assert_eq!(text, "v2 = (v1 + 2);");
        let text = format!("{}", f.body[2]);
        assert_eq!(text, "sp = v2;");
    }

    #[test]
    fn lift_registers_maps_frame_regs_and_skips_params() {
        let mut f = func_with(vec![assign("rbp", v("arg1")), assign("nonreg", c(0))]);
        f.prototype.params.push(HlilVar::param("arg1", HlilType::i64()));
        let n = lift_registers(&mut f);
        assert_eq!(n, 1);
        assert_eq!(format!("{}", f.body[0]), "fp = arg1;");
        assert_eq!(format!("{}", f.body[1]), "nonreg = 0;");
    }

    #[test]
    fn every_name_the_body_mentions_ends_up_declared() {
        // Il rename tocca il corpo e le locali GIA' presenti: se un nome entra
        // nel corpo senza avere una voce fra le locali, il C emesso non compila
        // (`'v1' undeclared`). E' cio' che bloccava l'aliasing 8/16 bit e che
        // fece fallire il tentativo `reg_family`.
        let mut f = func_with(vec![assign("rax", c(1))]);
        assert!(f.locals.is_empty(), "il caso ha senso solo partendo da locali vuote");
        lift_registers(&mut f);
        let mut used: Vec<String> = Vec::new();
        collect_var_names_in_order(&f.body, &mut used);
        for n in &used {
            assert!(
                f.locals.iter().any(|l| &l.name == n),
                "il corpo cita `{n}` ma non e' fra le locali: {:?}",
                f.locals.iter().map(|l| &l.name).collect::<Vec<_>>()
            );
        }
        assert!(!used.is_empty(), "il corpo deve citare almeno un nome");
    }

    #[test]
    fn a_void_pseudo_name_is_never_declared() {
        // `__trap__` e simili sono MARCATORI del modello, non variabili: in C
        // `void x;` non esiste (`error: variable or field declared void`, 31
        // file). Il criterio e' il TIPO e non il nome, cosi' un marcatore
        // nuovo non sfugge alla guardia.
        let mut f = func_with(vec![assign("rax", c(1))]);
        let mut t = var("__trap__");
t.ty = HlilType::Void;
        f.body.push(HlilStatement::Expr(HlilExpr::Var { var: t }));
        lift_registers(&mut f);
        assert!(
            !f.locals.iter().any(|l| l.name == "__trap__"),
            "un nome di tipo void non va dichiarato: {:?}",
            f.locals.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
        // ...ma la riconciliazione deve continuare a funzionare per gli altri.
        assert!(!f.locals.is_empty(), "le altre dichiarazioni devono restare");
    }

    #[test]
    fn a_materialised_declaration_uses_an_emittable_type() {
        // Il C emesso e' compilato in gnu89 col prelude `ida_defs.h`, che NON
        // definisce `bool`. Una dichiarazione materializzata con quel tipo da
        // `error: unknown type name` — successo su 114 file. Le altre
        // dichiarazioni di flag escono infatti come `uint8_t`.
        let mut f = func_with(vec![assign("rax", c(1))]);
        // Un nome di tipo Bool citato nel corpo, senza voce fra le locali.
        let mut b = var("flag_df");
        b.ty = HlilType::Bool;
        f.body.push(HlilStatement::Expr(HlilExpr::Var { var: b }));
        lift_registers(&mut f);
        let d = f
            .locals
            .iter()
            .find(|l| l.name == "flag_df")
            .expect("la dichiarazione deve ESSERCI, non basta evitare `bool`");
        assert!(
            !matches!(d.ty, HlilType::Bool),
            "tipo non emettibile in gnu89: {}",
            d.ty
        );
    }

    #[test]
    fn no_declaration_is_invented_for_a_body_that_mentions_nothing_new() {
        // Guardia contro l'eccesso opposto: la riconciliazione non deve
        // aggiungere voci quando il corpo non introduce alcun nome.
        let mut f = func_with(vec![]);
        lift_registers(&mut f);
        assert!(f.locals.is_empty(), "nessuna dichiarazione va inventata: {:?}",
            f.locals.iter().map(|l| &l.name).collect::<Vec<_>>());
    }

    #[test]
    fn a_parameter_mentioned_in_the_body_is_not_added_to_the_locals() {
        // I parametri sono dichiarati nella FIRMA: ri-dichiararli fra le locali
        // sarebbe una doppia definizione.
        let mut f = func_with(vec![assign("rax", v("a1"))]);
        f.prototype.params.push(var("a1"));
        lift_registers(&mut f);
        assert!(
            !f.locals.iter().any(|l| l.name == "a1"),
            "a1 e' un parametro e non deve comparire fra le locali: {:?}",
            f.locals.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn lift_registers_avoids_name_collisions() {
        // A pre-existing `v1` must not be shadowed by the renamer.
        let mut f = func_with(vec![assign("v1", c(9)), assign("rax", c(1))]);
        lift_registers(&mut f);
        assert_eq!(format!("{}", f.body[0]), "v1 = 9;");
        let HlilStatement::Assign { dest: HlilExpr::Var { var }, .. } = &f.body[1] else {
            panic!()
        };
        assert_ne!(var.name, "v1");
        assert!(var.name.starts_with('v'));
    }

    // ── 3. structuring ───────────────────────────────────────────────────

    #[test]
    fn while_true_break_guard_becomes_condition() {
        let mut stmts = vec![HlilStatement::While {
            cond: c(1),
            body: vec![
                HlilStatement::If {
                    cond: HlilExpr::CmpGe(Box::new(v("i")), Box::new(v("n"))),
                    then_body: vec![HlilStatement::Break],
                    else_body: vec![],
                },
                assign("s", HlilExpr::Add(Box::new(v("s")), Box::new(v("i")), HlilType::i64())),
            ],
        }];
        let n = structure_control_flow(&mut stmts);
        assert!(n >= 1);
        let HlilStatement::While { cond, body } = &stmts[0] else {
            panic!()
        };
        assert_eq!(*cond, HlilExpr::CmpLt(Box::new(v("i")), Box::new(v("n"))));
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn forward_goto_becomes_if() {
        // if (c) goto L; x = 1; L:  →  if (!c) { x = 1; }
        let mut stmts = vec![
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(0))),
                then_body: vec![HlilStatement::Goto(Address::new(0x40))],
                else_body: vec![],
            },
            assign("x", c(1)),
            HlilStatement::Label("label_40".into()),
        ];
        let n = structure_control_flow(&mut stmts);
        assert!(n >= 1);
        assert_eq!(stmts.len(), 1, "label removed once unreferenced: {stmts:?}");
        let HlilStatement::If {
            cond, then_body, ..
        } = &stmts[0]
        else {
            panic!("expected If, got {:?}", stmts[0]);
        };
        assert_eq!(*cond, HlilExpr::CmpNe(Box::new(v("a")), Box::new(c(0))));
        assert_eq!(then_body.len(), 1);
    }

    #[test]
    fn cfg_reducibility_su_casi_noti() {
        // ⚠ Sonda VALIDATA prima di credere al 10,7%: tre grafi di cui conosco
        // la risposta. Senza questo il numero non vale nulla.
        //
        // 1) Nessun salto: un solo nodo, nessun ciclo, riducibile.
        let (n, _, cic, irr) = cfg_reducibility(&[assign("x", c(1))]);
        assert_eq!((n, cic, irr), (1, 0, false), "grafo vuoto");

        // 2) Ciclo SEMPLICE: `L: … goto L` — retro-arco DOMINANTE ⇒ RIDUCIBILE.
        let ciclo = vec![
            HlilStatement::Label("loc_10".to_string()),
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        let (_, _, cic2, irr2) = cfg_reducibility(&ciclo);
        assert!(cic2 >= 1, "il retro-arco non e' stato visto");
        assert!(!irr2, "un ciclo a UN ingresso e' riducibile");

        // 3) Ciclo a DUE ingressi (il caso che richiede node splitting):
        //    entry → A, entry → B, A → B, B → A. Nessuno dei due domina l'altro.
        let irrid = vec![
            HlilStatement::Goto(Address::new(0x20)), // entry → B
            HlilStatement::Label("loc_10".to_string()), // A
            HlilStatement::Goto(Address::new(0x20)), // A → B
            HlilStatement::Label("loc_20".to_string()), // B
            HlilStatement::Goto(Address::new(0x10)), // B → A
        ];
        let (_, _, _, irr3) = cfg_reducibility(&irrid);
        assert!(irr3, "un ciclo a DUE ingressi deve risultare IRRIDUCIBILE");
    }

    #[test]
    fn bare_backward_goto_becomes_while_true() {
        // #5300. `L: x = x + 1; goto L;` → `while (1) { x = x + 1; }`
        // E' il 60,1% dei goto del corpus, e le regole (b)/(c) non lo guardano
        // nemmeno perche' pretendono `If { then_body: [Goto] }`.
        let mut stmts = vec![
            HlilStatement::Label("L10".into()),
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        assert_eq!(fold_bare_backward_goto(&mut stmts, true), 1);
        assert_eq!(stmts.len(), 1, "{stmts:?}");
        let HlilStatement::While { cond, body } = &stmts[0] else {
            panic!("atteso While, trovato {:?}", stmts[0]);
        };
        assert!(is_const_true(cond), "la condizione dev'essere costante-vera");
        assert_eq!(body.len(), 1, "il corpo resta intatto");

        // I RIFIUTI — qui sta il valore del test.
        // ⚠ `HlilStatement` non implementa `PartialEq`: si confronta il Debug.
        let dbg = |v: &Vec<HlilStatement>| format!("{v:?}");
        // 1) GATE SPENTO: inerte, byte per byte.
        let mut s1 = vec![
            HlilStatement::Label("L10".into()),
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        let prima1 = dbg(&s1);
        assert_eq!(fold_bare_backward_goto(&mut s1, false), 0);
        assert_eq!(dbg(&s1), prima1);
        // 2) goto in AVANTI (etichetta DOPO): non e' un ciclo, non si tocca.
        let mut s2 = vec![
            HlilStatement::Goto(Address::new(0x20)),
            assign("x", c(1)),
            HlilStatement::Label("L20".into()),
        ];
        let prima2 = dbg(&s2);
        assert_eq!(fold_bare_backward_goto(&mut s2, true), 0);
        assert_eq!(dbg(&s2), prima2, "un goto in avanti non e' un ciclo");
        // 3) DUE ingressi all'etichetta: non si puo' togliere l'etichetta, il
        //    `while` non descriverebbe piu' il flusso.
        let mut s3 = vec![
            HlilStatement::Label("L10".into()),
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        let prima3 = dbg(&s3);
        assert_eq!(fold_bare_backward_goto(&mut s3, true), 0);
        assert_eq!(dbg(&s3), prima3, "con piu' ingressi non si trasforma");
        // 4) goto a un'etichetta ASSENTE: nessuna trasformazione.
        let mut s4 = vec![assign("x", c(1)), HlilStatement::Goto(Address::new(0x99))];
        let prima4 = dbg(&s4);
        assert_eq!(fold_bare_backward_goto(&mut s4, true), 0);
        assert_eq!(dbg(&s4), prima4);
    }

    #[test]
    fn inner_goto_to_head_becomes_continue_outer_one_still_blocks() {
        // #5310. Un salto alla testa che nasce DENTRO il corpo e' un
        // `continue`: la guardia «un solo salto» lo respingeva, ed e' la forma
        // normalissima del ciclo con `continue` (1441 etichette su 7036 hanno
        // piu' di un ingresso).
        let mut stmts = vec![
            HlilStatement::Label("L10".into()),
            HlilStatement::If {
                cond: c(1),
                then_body: vec![HlilStatement::Goto(Address::new(0x10))],
                else_body: Vec::new(),
            },
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        assert_eq!(fold_bare_backward_goto(&mut stmts, true), 1);
        assert_eq!(stmts.len(), 1, "{stmts:?}");
        let HlilStatement::While { cond, body } = &stmts[0] else {
            panic!("atteso While, trovato {:?}", stmts[0]);
        };
        assert!(is_const_true(cond));
        let testo = format!("{body:?}");
        assert!(testo.contains("Continue"), "il salto interno diventa continue: {testo}");
        assert!(
            !testo.contains("Goto"),
            "nessun goto alla testa deve sopravvivere: {testo}"
        );

        // ⚠ IL RIFIUTO CHE PROTEGGE IL FLUSSO: un salto a L da FUORI del corpo
        // non si puo' assorbire — l'etichetta non si potrebbe togliere.
        let mut esterno = vec![
            HlilStatement::Label("L10".into()),
            assign("x", c(1)),
            HlilStatement::Goto(Address::new(0x10)),
            assign("y", c(2)),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        let prima = format!("{esterno:?}");
        assert_eq!(
            fold_bare_backward_goto(&mut esterno, true),
            0,
            "un salto dall'ESTERNO deve bloccare la trasformazione"
        );
        assert_eq!(format!("{esterno:?}"), prima);
    }

    #[test]
    fn backward_goto_becomes_do_while() {
        // L: x = x + 1; if (x < n) goto L;  →  do { x = x + 1; } while (x < n);
        let mut stmts = vec![
            HlilStatement::Label("L10".into()),
            assign("x", HlilExpr::Add(Box::new(v("x")), Box::new(c(1)), HlilType::i64())),
            HlilStatement::If {
                cond: HlilExpr::CmpLt(Box::new(v("x")), Box::new(v("n"))),
                then_body: vec![HlilStatement::Goto(Address::new(0x10))],
                else_body: vec![],
            },
        ];
        let n = structure_control_flow(&mut stmts);
        assert!(n >= 1);
        assert_eq!(stmts.len(), 1);
        let HlilStatement::DoWhile { body, cond } = &stmts[0] else {
            panic!("expected DoWhile, got {:?}", stmts[0]);
        };
        assert_eq!(body.len(), 1);
        assert_eq!(*cond, HlilExpr::CmpLt(Box::new(v("x")), Box::new(v("n"))));
    }

    #[test]
    fn goto_with_intervening_label_not_captured() {
        let mut stmts = vec![
            HlilStatement::If {
                cond: v("a"),
                then_body: vec![HlilStatement::Goto(Address::new(0x40))],
                else_body: vec![],
            },
            HlilStatement::Label("other".into()),
            assign("x", c(1)),
            HlilStatement::Label("label_40".into()),
        ];
        structure_control_flow(&mut stmts);
        // Must not have swallowed the "other" label into a guarded block.
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, HlilStatement::Label(l) if l == "other")),
            "{stmts:?}"
        );
        // ...and it must not have been relocated into ANY nested body either.
        fn label_in_nested(stmts: &[HlilStatement]) -> bool {
            stmts.iter().any(|s| {
                let mut s = s.clone();
                stmt_bodies_mut(&mut s).into_iter().any(|b| {
                    b.iter().any(|n| matches!(n, HlilStatement::Label(l) if l == "other"))
                        || label_in_nested(b)
                })
            })
        }
        assert!(!label_in_nested(&stmts), "relocated into nested body: {stmts:?}");
    }

    #[test]
    fn goto_with_only_target_label_inside_still_transforms() {
        // The swallowed range carries no label other than the goto's own
        // target (which sits at the range end), so the new bail-out must NOT
        // fire — the guarded-block transform still applies exactly as before.
        let mut stmts = vec![
            HlilStatement::If {
                cond: v("a"),
                then_body: vec![HlilStatement::Goto(Address::new(0x40))],
                else_body: vec![],
            },
            assign("x", c(1)),
            assign("y", c(2)),
            HlilStatement::Label("label_40".into()),
        ];
        let n = structure_control_flow(&mut stmts);
        assert!(n >= 1, "expected a rewrite: {stmts:?}");
        assert!(
            matches!(&stmts[0], HlilStatement::If { then_body, .. } if !then_body.is_empty()),
            "expected guarded block, got {stmts:?}"
        );
    }

    #[test]
    fn label_matcher_accepts_common_forms() {
        let a = Address::new(0x40);
        assert!(label_matches("label_40", a));
        assert!(label_matches("L40", a));
        assert!(label_matches("loc_40", a));
        assert!(label_matches("64", a)); // decimal
        assert!(!label_matches("label_41", a));
    }

    // ── 4. forward propagation ───────────────────────────────────────────

    #[test]
    fn propagate_single_use_into_next_statement() {
        // t = a + b; return t;  →  return a + b;
        let mut stmts = vec![
            assign("t", HlilExpr::Add(Box::new(v("a")), Box::new(v("b")), HlilType::i64())),
            HlilStatement::Return(vec![v("t")]),
        ];
        assert_eq!(propagate_expressions(&mut stmts), 1);
        assert_eq!(stmts.len(), 1);
        assert_eq!(format!("{}", stmts[0]), "return (a + b);");
    }

    #[test]
    fn propagate_skips_multi_use() {
        let mut stmts = vec![
            assign("t", HlilExpr::Add(Box::new(v("a")), Box::new(v("b")), HlilType::i64())),
            assign("x", HlilExpr::Add(Box::new(v("t")), Box::new(v("t")), HlilType::i64())),
        ];
        assert_eq!(propagate_expressions(&mut stmts), 0);
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn propagate_skips_impure_source() {
        let call = HlilExpr::Call {
            func: Box::new(v("get")),
            args: vec![],
            ret_ty: HlilType::i64(),
        };
        let mut stmts = vec![assign("t", call), HlilStatement::Return(vec![v("t")])];
        assert_eq!(propagate_expressions(&mut stmts), 0);
    }

    #[test]
    fn propagate_skips_when_next_redefines_input() {
        // t = a; a = 0; x = t;  — cannot substitute a into x = t.
        let mut stmts = vec![
            assign("t", v("a")),
            assign("a", c(0)),
            assign("x", v("t")),
        ];
        assert_eq!(propagate_expressions(&mut stmts), 0);
        assert_eq!(stmts.len(), 3);
    }

    #[test]
    fn propagate_skips_loop_conditions() {
        let mut stmts = vec![
            assign("t", HlilExpr::CmpLt(Box::new(v("i")), Box::new(v("n")))),
            HlilStatement::While {
                cond: v("t"),
                body: vec![HlilStatement::Break],
            },
        ];
        assert_eq!(propagate_expressions(&mut stmts), 0, "loop cond evaluates repeatedly");
    }

    #[test]
    fn propagate_chain_through_reassignment() {
        // t = a + 1; t2 = t; return t2  →  (two passes fold fully)
        let mut stmts = vec![
            assign("t", HlilExpr::Add(Box::new(v("a")), Box::new(c(1)), HlilType::i64())),
            assign("t2", v("t")),
            HlilStatement::Return(vec![v("t2")]),
        ];
        let n1 = propagate_expressions(&mut stmts);
        let n2 = propagate_expressions(&mut stmts);
        assert!(n1 + n2 >= 2, "n1={n1} n2={n2} {stmts:?}");
        assert_eq!(format!("{}", stmts[0]), "return (a + 1);");
    }

    // ── 5. dead store elimination ────────────────────────────────────────

    #[test]
    fn dse_removes_never_read_store() {
        let mut f = func_with(vec![
            assign("dead", c(5)),
            HlilStatement::Return(vec![v("live")]),
        ]);
        assert_eq!(eliminate_dead_stores(&mut f), 1);
        assert_eq!(f.body.len(), 1);
    }

    #[test]
    fn dse_keeps_read_store_and_impure_src() {
        let call = HlilExpr::Call {
            func: Box::new(v("f")),
            args: vec![],
            ret_ty: HlilType::i64(),
        };
        let mut f = func_with(vec![
            assign("x", c(1)),
            assign("unused_but_call", call),
            HlilStatement::Return(vec![v("x")]),
        ]);
        assert_eq!(eliminate_dead_stores(&mut f), 0);
        assert_eq!(f.body.len(), 3);
    }

    #[test]
    fn dse_cascades_to_fixpoint() {
        // b = a; (a only read by dead b)  → both removed.
        let mut f = func_with(vec![
            assign("a", c(1)),
            assign("b", v("a")),
            HlilStatement::Return(vec![c(0)]),
        ]);
        assert_eq!(eliminate_dead_stores(&mut f), 2);
        assert_eq!(f.body.len(), 1);
    }

    #[test]
    fn dse_recurses_into_bodies() {
        let mut f = func_with(vec![HlilStatement::If {
            cond: v("c"),
            then_body: vec![assign("dead", c(1))],
            else_body: vec![],
        }]);
        assert_eq!(eliminate_dead_stores(&mut f), 1);
    }

    #[test]
    fn pipeline_flips_then_branch_emptied_by_dead_store_elim() {
        // The then-body holds ONLY a dead store: the first flip sees a
        // non-empty then, but `eliminate_dead_stores` empties it later. The
        // final flip pass must still rewrite `if (C) {} else {B}` → `if (!C) {B}`.
        let mut f = func_with(vec![
            HlilStatement::If {
                cond: HlilExpr::CmpEq(Box::new(v("a")), Box::new(c(3))),
                then_body: vec![assign("dead", c(5))],
                else_body: vec![HlilStatement::Return(vec![c(1)])],
            },
            HlilStatement::Return(vec![c(0)]),
        ]);
        StructuringPipeline::new().run(&mut f);
        let HlilStatement::If { cond, then_body, else_body } = &f.body[0] else {
            panic!("{:?}", f.body)
        };
        assert_eq!(*cond, HlilExpr::CmpNe(Box::new(v("a")), Box::new(c(3))), "{:?}", f.body);
        assert!(!then_body.is_empty(), "{:?}", f.body);
        assert!(else_body.is_empty(), "{:?}", f.body);
    }

    // ── 6. induction variables ───────────────────────────────────────────

    #[test]
    fn induction_var_makes_for_loop() {
        // i = 0; while (i < n) { s = s + i; i = i + 1; }
        let mut stmts = vec![
            assign("i", c(0)),
            HlilStatement::While {
                cond: HlilExpr::CmpLt(Box::new(v("i")), Box::new(v("n"))),
                body: vec![
                    assign("s", HlilExpr::Add(Box::new(v("s")), Box::new(v("i")), HlilType::i64())),
                    assign("i", HlilExpr::Add(Box::new(v("i")), Box::new(c(1)), HlilType::i64())),
                ],
            },
        ];
        assert_eq!(detect_induction_vars(&mut stmts), 1);
        assert_eq!(stmts.len(), 1);
        let HlilStatement::For {
            init, cond, step, body,
        } = &stmts[0]
        else {
            panic!("expected For, got {:?}", stmts[0]);
        };
        assert!(init.is_some());
        assert!(cond.is_some());
        assert!(step.is_some());
        assert_eq!(body.len(), 1, "step removed from body");
    }

    #[test]
    fn induction_var_without_init_still_converts() {
        let mut stmts = vec![HlilStatement::While {
            cond: HlilExpr::CmpLt(Box::new(v("i")), Box::new(c(10))),
            body: vec![assign(
                "i",
                HlilExpr::Add(Box::new(v("i")), Box::new(c(2)), HlilType::i64()),
            )],
        }];
        assert_eq!(detect_induction_vars(&mut stmts), 1);
        let HlilStatement::For { init, .. } = &stmts[0] else {
            panic!()
        };
        assert!(init.is_none());
    }

    #[test]
    fn induction_var_skips_loops_with_continue() {
        // `continue` in the while skips the increment; a for would not.
        let mut stmts = vec![HlilStatement::While {
            cond: HlilExpr::CmpLt(Box::new(v("i")), Box::new(c(10))),
            body: vec![
                HlilStatement::If {
                    cond: v("skip"),
                    then_body: vec![HlilStatement::Continue],
                    else_body: vec![],
                },
                assign("i", HlilExpr::Add(Box::new(v("i")), Box::new(c(1)), HlilType::i64())),
            ],
        }];
        assert_eq!(detect_induction_vars(&mut stmts), 0);
        assert!(matches!(stmts[0], HlilStatement::While { .. }));
    }

    #[test]
    fn induction_var_skips_when_cond_ignores_var() {
        let mut stmts = vec![HlilStatement::While {
            cond: HlilExpr::CmpLt(Box::new(v("x")), Box::new(c(10))),
            body: vec![assign(
                "i",
                HlilExpr::Add(Box::new(v("i")), Box::new(c(1)), HlilType::i64()),
            )],
        }];
        assert_eq!(detect_induction_vars(&mut stmts), 0);
    }

    // ── 7. type inference ────────────────────────────────────────────────

    #[test]
    fn infer_type_from_assignment_source() {
        let mut f = func_with(vec![
            assign("x", c(5)), // c() is i64-typed
            HlilStatement::Return(vec![v("x")]),
        ]);
        f.locals.push(var("x"));
        assert_eq!(infer_types(&mut f), 1);
        assert_eq!(f.locals[0].ty, HlilType::i64());
        let HlilStatement::Return(es) = &f.body[1] else {
            panic!()
        };
        let HlilExpr::Var { var } = &es[0] else { panic!() };
        assert_eq!(var.ty, HlilType::i64(), "occurrences retyped too");
    }

    #[test]
    fn infer_pointer_type_from_deref() {
        let mut f = func_with(vec![HlilStatement::Return(vec![HlilExpr::Deref {
            addr: Box::new(v("p")),
            ty: HlilType::i32(),
        }])]);
        f.locals.push(var("p"));
        assert_eq!(infer_types(&mut f), 1);
        assert_eq!(f.locals[0].ty, HlilType::ptr(HlilType::i32(), 64));
    }

    #[test]
    fn infer_types_does_not_clobber_known() {
        let mut f = func_with(vec![assign("x", c(5))]);
        f.locals.push(HlilVar::new("x", HlilType::u8()));
        assert_eq!(infer_types(&mut f), 0);
        assert_eq!(f.locals[0].ty, HlilType::u8());
    }

    // ── pipeline end-to-end ──────────────────────────────────────────────

    #[test]
    fn pipeline_end_to_end_counter_loop() {
        // Raw register-level output:
        //   var_rax = 0;
        //   while (1) {
        //     flag = var_rax < arg1;
        //     if (flag == 0) break;   -- encoded as if (flag == 0) { break; }
        //     var_rcx = var_rcx + var_rax;
        //     var_rax = var_rax + 1;
        //   }
        //   return var_rcx;
        let body = vec![
            assign("var_rax", c(0)),
            HlilStatement::While {
                cond: c(1),
                body: vec![
                    assign(
                        "flag",
                        HlilExpr::CmpLt(Box::new(v("var_rax")), Box::new(v("arg1"))),
                    ),
                    HlilStatement::If {
                        cond: HlilExpr::CmpEq(Box::new(v("flag")), Box::new(c(0))),
                        then_body: vec![HlilStatement::Break],
                        else_body: vec![],
                    },
                    assign(
                        "var_rcx",
                        HlilExpr::Add(Box::new(v("var_rcx")), Box::new(v("var_rax")), HlilType::i64()),
                    ),
                    assign(
                        "var_rax",
                        HlilExpr::Add(Box::new(v("var_rax")), Box::new(c(1)), HlilType::i64()),
                    ),
                ],
            },
            HlilStatement::Return(vec![v("var_rcx")]),
        ];
        let mut f = func_with(body);
        f.prototype.params.push(HlilVar::param("arg1", HlilType::i64()));
        let report = StructuringPipeline::new().run(&mut f);

        assert_eq!(report.flags_folded, 1, "{report:?}");
        assert!(report.registers_lifted >= 2, "{report:?}");
        assert!(report.regions_structured >= 1, "{report:?}");
        assert_eq!(report.loops_converted, 1, "{report:?}");

        // Final shape: for (v1 = 0; v1 < arg1; v1 + 1) { v2 = v2 + v1; } return v2;
        assert_eq!(f.body.len(), 2, "{:#?}", f.body);
        let HlilStatement::For {
            init, cond, body, ..
        } = &f.body[0]
        else {
            panic!("expected For, got {:?}", f.body[0]);
        };
        assert!(init.is_some());
        assert_eq!(
            cond.clone().unwrap(),
            HlilExpr::CmpLt(Box::new(v("v1")), Box::new(v("arg1")))
        );
        assert_eq!(body.len(), 1);
        assert_eq!(format!("{}", f.body[1]), "return v2;");
    }

    #[test]
    fn pipeline_is_idempotent_on_structured_code() {
        let mut f = func_with(vec![
            HlilStatement::If {
                cond: HlilExpr::CmpGt(Box::new(v("a")), Box::new(c(0))),
                then_body: vec![HlilStatement::Return(vec![c(1)])],
                else_body: vec![],
            },
            HlilStatement::Return(vec![c(0)]),
        ]);
        let r1 = StructuringPipeline::new().run(&mut f);
        let snapshot = format!("{:?}", f.body);
        let r2 = StructuringPipeline::new().run(&mut f);
        assert_eq!(r2.total(), 0, "second run must be a no-op: {r1:?} {r2:?}");
        assert_eq!(snapshot, format!("{:?}", f.body));
    }
}
