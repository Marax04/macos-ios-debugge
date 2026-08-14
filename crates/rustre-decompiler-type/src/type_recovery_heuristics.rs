//! Type-recovery heuristics.
//!
//! Identifies types from high-level usage patterns such as:
//! - `char *` / `CStr` from `strcmp`, `strlen`, `printf %s` arguments.
//! - `HANDLE` / `SOCKET` / `FILE *` from Windows API patterns.
//! - Enum types from `switch` discriminants.
//! - Struct types from repeated fixed-offset field accesses.
//! - `size_t` from `sizeof`-like patterns and loop bound arithmetic.

use std::collections::{HashMap, HashSet};

use rustre_decompiler_expr::{BinOp, Expr, IntWidth};

use crate::{DecompType, EnumVariant, StructField, StructType, TypeEnvironment};

// ─────────────────────────────────────────────────────────────────────────────
// Evidence accumulator
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence that a variable has a particular type.
#[derive(Debug, Clone)]
pub struct TypeEvidence {
    pub var: String,
    pub ty: DecompType,
    /// Confidence weight (0–100).  Multiple pieces of evidence are combined.
    pub weight: u32,
    pub reason: String,
}

impl TypeEvidence {
    #[must_use]
    pub fn new(
        var: impl Into<String>,
        ty: DecompType,
        weight: u32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            var: var.into(),
            ty,
            weight,
            reason: reason.into(),
        }
    }
}

/// Accumulates type evidence from all heuristics.
#[derive(Debug, Default)]
pub struct EvidenceAccumulator {
    /// Evidence grouped by variable name.
    pub by_var: HashMap<String, Vec<TypeEvidence>>,
}

impl EvidenceAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ev: TypeEvidence) {
        self.by_var.entry(ev.var.clone()).or_default().push(ev);
    }

    /// Return the strongest supported type for `var`, or `None`.
    #[must_use]
    pub fn best_type(&self, var: &str) -> Option<&DecompType> {
        let evs = self.by_var.get(var)?;
        evs.iter()
            .max_by_key(|e| e.weight)
            .map(|e| &e.ty)
    }

    /// Commit the strongest evidence into a `TypeEnvironment`.
    pub fn commit(&self, env: &mut TypeEnvironment) {
        for (var, evs) in &self.by_var {
            if let Some(best) = evs.iter().max_by_key(|e| e.weight) {
                env.set(var.clone(), best.ty.clone());
            }
        }
    }

    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.by_var.values().map(Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringTypeHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Detects string variables (`char *`) from string-manipulation API usage.
///
/// Patterns recognised:
/// * Argument passed to `strcmp`, `stricmp`, `strncmp`, `strcpy`, `strcat`.
/// * Argument passed to `strlen`, `strnlen`.
/// * First argument of `printf`, `fprintf`, `sprintf` (the format string).
/// * Any argument where a `%s` format specifier is used.
/// * Variables initialised from string literal addresses.
pub struct StringTypeHeuristic;

impl StringTypeHeuristic {
    /// The well-known string functions and which argument indices are strings.
    const fn string_functions() -> &'static [(&'static str, &'static [usize])] {
        &[
            ("strcmp",   &[0, 1]),
            ("stricmp",  &[0, 1]),
            ("strncmp",  &[0, 1]),
            ("strcasecmp", &[0, 1]),
            ("strcpy",   &[0, 1]),
            ("strncpy",  &[0, 1]),
            ("strcat",   &[0, 1]),
            ("strncat",  &[0, 1]),
            ("strlen",   &[0]),
            ("strnlen",  &[0]),
            ("printf",   &[0]),
            ("fprintf",  &[1]),
            ("sprintf",  &[1]),
            ("snprintf", &[2]),
            ("puts",     &[0]),
            ("fputs",    &[0]),
            ("atoi",     &[0]),
            ("atol",     &[0]),
            ("atof",     &[0]),
            ("strtol",   &[0]),
            ("strtoul",  &[0]),
            ("strstr",   &[0, 1]),
            ("strchr",   &[0]),
            ("strrchr",  &[0]),
        ]
    }

    /// Run the heuristic over an assignment list, recording evidence.
    pub fn analyse(
        assigns: &[(String, Expr)],
        acc: &mut EvidenceAccumulator,
    ) {
        for (_, expr) in assigns {
            Self::walk_expr(expr, acc);
        }
    }

    fn walk_expr(expr: &Expr, acc: &mut EvidenceAccumulator) {
        if let Expr::Call { callee, args } = expr
            && let Some(name) = callee.as_var() {
                let name_lower = name.to_lowercase();
                for (func_name, arg_indices) in Self::string_functions() {
                    if name_lower == *func_name || name_lower.ends_with(func_name) {
                        for &idx in *arg_indices {
                            if let Some(arg) = args.get(idx)
                                && let Some(var) = arg.as_var() {
                                    acc.add(TypeEvidence::new(
                                        var,
                                        DecompType::CStr,
                                        80,
                                        format!("arg {idx} of {name}"),
                                    ));
                                }
                        }
                    }
                }
            }
        // Recurse into sub-expressions.
        Self::walk_children(expr, acc);
    }

    fn walk_children(expr: &Expr, acc: &mut EvidenceAccumulator) {
        match expr {
            Expr::BinOp(_, a, b) => {
                Self::walk_expr(a, acc);
                Self::walk_expr(b, acc);
            }
            Expr::UnOp(_, e) => Self::walk_expr(e, acc),
            Expr::Ternary { cond, then_expr, else_expr } => {
                Self::walk_expr(cond, acc);
                Self::walk_expr(then_expr, acc);
                Self::walk_expr(else_expr, acc);
            }
            Expr::Index { base, index, .. } => {
                Self::walk_expr(base, acc);
                Self::walk_expr(index, acc);
            }
            Expr::Phi(exprs) => {
                for e in exprs {
                    Self::walk_expr(e, acc);
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WinApiTypeHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Detects Windows-API handle / socket / file types from call patterns.
///
/// Rules:
/// * Return value of `CreateFile*`, `OpenProcess`, `OpenThread`,
///   `OpenMutex`, … → `HANDLE`.
/// * Return value of `socket`, `accept`, `WSASocket` → `SOCKET` (= `void *`).
/// * Return value of `fopen`, `_wfopen` → `FILE *`.
/// * Return value of `GetStdHandle`, `CreateThread` → `HANDLE`.
/// * Argument to `CloseHandle` → `HANDLE`.
/// * Return value of `LoadLibrary*` → `HMODULE`.
/// * Return value of `GetModuleHandle*` → `HMODULE`.
pub struct WinApiTypeHeuristic;

impl WinApiTypeHeuristic {
    fn handle_type() -> DecompType {
        DecompType::Ptr(Box::new(DecompType::Void))
    }

    fn file_ptr_type() -> DecompType {
        // FILE * is modelled as void * until we have a proper FILE struct.
        DecompType::Ptr(Box::new(DecompType::Void))
    }

    /// Check whether a function name suggests its return value is a `HANDLE`.
    fn is_handle_creator(name: &str) -> bool {
        let n = name.to_lowercase();
        n.starts_with("createfile")
            || n.starts_with("openprocess")
            || n.starts_with("openthread")
            || n.starts_with("openmutex")
            || n.starts_with("createmutex")
            || n.starts_with("createevent")
            || n.starts_with("openevent")
            || n.starts_with("createpipe")
            || n.starts_with("createnamedpipe")
            || n.starts_with("createthread")
            || n.starts_with("getstdhandle")
            || n.starts_with("getcurrentprocess")
            || n.starts_with("getcurrentthread")
            || n.starts_with("regcreatekeyex")
            || n.starts_with("regopenkey")
            || n.starts_with("findfirsfile")
            || n.starts_with("findfirstfile")
    }

    fn is_socket_creator(name: &str) -> bool {
        let n = name.to_lowercase();
        matches!(n.as_str(), "socket" | "accept" | "wsasocket" | "wsaaccept")
    }

    fn is_file_opener(name: &str) -> bool {
        let n = name.to_lowercase();
        n.starts_with("fopen") || n == "_wfopen"
    }

    fn is_hmodule_creator(name: &str) -> bool {
        let n = name.to_lowercase();
        n.starts_with("loadlibrary") || n.starts_with("getmodulehandle")
    }

    pub fn analyse(assigns: &[(String, Expr)], acc: &mut EvidenceAccumulator) {
        for (dst, expr) in assigns {
            if let Expr::Call { callee, args } = expr
                && let Some(name) = callee.as_var() {
                    // Return-value typing.
                    if Self::is_handle_creator(name) {
                        acc.add(TypeEvidence::new(
                            dst,
                            Self::handle_type(),
                            90,
                            format!("return of {name}"),
                        ));
                    } else if Self::is_socket_creator(name) {
                        acc.add(TypeEvidence::new(
                            dst,
                            Self::handle_type(),
                            85,
                            format!("socket return of {name}"),
                        ));
                    } else if Self::is_file_opener(name) {
                        acc.add(TypeEvidence::new(
                            dst,
                            Self::file_ptr_type(),
                            90,
                            format!("FILE* return of {name}"),
                        ));
                    } else if Self::is_hmodule_creator(name) {
                        acc.add(TypeEvidence::new(
                            dst,
                            DecompType::Ptr(Box::new(DecompType::Void)),
                            85,
                            format!("HMODULE return of {name}"),
                        ));
                    }

                    // Argument typing for CloseHandle / WSACloseSocket.
                    let name_lc = name.to_lowercase();
                    if (name_lc == "closehandle" || name_lc == "wsaclosesocket")
                        && let Some(arg) = args.first()
                            && let Some(var) = arg.as_var() {
                                acc.add(TypeEvidence::new(
                                    var,
                                    Self::handle_type(),
                                    85,
                                    format!("arg 0 of {name}"),
                                ));
                            }
                }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnumDetectionHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Detects enum types from switch-statement patterns in the assignment stream.
///
/// The heuristic looks for:
/// * A variable compared repeatedly to small distinct integer constants.
/// * The same variable used as the discriminant of multiple equal-comparisons.
///
/// When ≥ 3 distinct constant values are used as comparands, the variable is
/// reported as a candidate enum.
pub struct EnumDetectionHeuristic;

impl EnumDetectionHeuristic {
    /// Minimum number of distinct constants to trigger enum detection.
    const MIN_VARIANTS: usize = 3;

    pub fn analyse(
        assigns: &[(String, Expr)],
        acc: &mut EvidenceAccumulator,
    ) {
        // Map variable → set of comparison constants.
        let mut cmp_map: HashMap<String, HashSet<i64>> = HashMap::new();

        for (_, expr) in assigns {
            Self::walk(expr, &mut cmp_map);
        }

        // Variables with ≥ MIN_VARIANTS distinct integer comparands → enum.
        for (var, values) in &cmp_map {
            if values.len() >= Self::MIN_VARIANTS {
                let mut sorted_values: Vec<i64> = values.iter().copied().collect();
                sorted_values.sort_unstable();
                let variants: Vec<EnumVariant> = sorted_values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| EnumVariant {
                        name: format!("VARIANT_{i}"),
                        value: v,
                    })
                    .collect();

                let enum_ty = DecompType::Enum {
                    name: format!("Enum_{var}"),
                    variants,
                    backing: IntWidth::I32,
                };

                let weight = 50 + (u32::try_from(values.len().min(20)).unwrap_or(20) * 2);
                acc.add(TypeEvidence::new(
                    var,
                    enum_ty,
                    weight,
                    format!("{} distinct enum comparisons", values.len()),
                ));
            }
        }
    }

    fn walk(expr: &Expr, cmp_map: &mut HashMap<String, HashSet<i64>>) {
        match expr {
            Expr::BinOp(BinOp::Eq | BinOp::Ne, a, b) => {
                match (a.as_ref(), b.as_ref()) {
                    (Expr::Var(v), Expr::Const(c, _)) | (Expr::Const(c, _), Expr::Var(v)) => {
                        cmp_map.entry(v.clone()).or_default().insert(*c);
                    }
                    _ => {}
                }
            }
            Expr::BinOp(_, a, b) => {
                Self::walk(a, cmp_map);
                Self::walk(b, cmp_map);
            }
            Expr::UnOp(_, e) => Self::walk(e, cmp_map),
            Expr::Ternary { cond, then_expr, else_expr } => {
                Self::walk(cond, cmp_map);
                Self::walk(then_expr, cmp_map);
                Self::walk(else_expr, cmp_map);
            }
            Expr::Call { args, .. } => {
                for a in args {
                    Self::walk(a, cmp_map);
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructRecoveryHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers struct types from repeated fixed-offset field accesses on the same
/// base variable.
///
/// The heuristic records every `(base_var, offset)` pair from `FieldAccess`
/// and `ptr + const` patterns.  When a base variable has ≥ 2 distinct offsets,
/// it is flagged as a struct pointer and a candidate `StructType` is built.
pub struct StructRecoveryHeuristic;

impl StructRecoveryHeuristic {
    /// Minimum number of distinct offsets to trigger struct detection.
    const MIN_FIELDS: usize = 2;

    pub fn analyse(
        assigns: &[(String, Expr)],
        acc: &mut EvidenceAccumulator,
    ) {
        // Map base_var → sorted set of (offset, access_size) pairs.
        let mut offset_map: HashMap<String, HashMap<u64, u8>> = HashMap::new();

        for (_dst, expr) in assigns {
            Self::walk(expr, &mut offset_map);
            // Also record `*base` (offset 0).
            if let Expr::UnOp(rustre_decompiler_expr::UnOp::Deref, inner) = expr
                && let Some(base_var) = inner.as_var() {
                    offset_map
                        .entry(base_var.to_string())
                        .or_default()
                        .insert(0, 8);
                }
        }

        for (base_var, offsets) in &offset_map {
            if offsets.len() < Self::MIN_FIELDS {
                continue;
            }
            let mut sorted_offsets: Vec<(u64, u8)> =
                offsets.iter().map(|(&o, &s)| (o, s)).collect();
            sorted_offsets.sort_by_key(|&(o, _)| o);

            let fields: Vec<StructField> = sorted_offsets
                .iter()
                .enumerate()
                .map(|(i, &(offset, size))| {
                    let ty = match size {
                        1 => DecompType::Int(IntWidth::U8),
                        2 => DecompType::Int(IntWidth::U16),
                        4 => DecompType::Int(IntWidth::U32),
                        _ => DecompType::Int(IntWidth::U64),
                    };
                    StructField {
                        offset,
                        name: format!("field_{i}"),
                        ty,
                    }
                })
                .collect();

            let total_size = sorted_offsets
                .last()
                .map_or(0, |&(o, s)| o + u64::from(s));

            let st = StructType {
                name: format!("Struct_{base_var}"),
                fields,
                total_size,
            };
            let ptr_ty = DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st))));
            let weight = 40 + (u32::try_from(offsets.len().min(10)).unwrap_or(10) * 5);
            acc.add(TypeEvidence::new(
                base_var,
                ptr_ty,
                weight,
                format!("{} distinct field offsets", offsets.len()),
            ));
        }
    }

    fn walk(expr: &Expr, map: &mut HashMap<String, HashMap<u64, u8>>) {
        match expr {
            Expr::FieldAccess { base, offset } => {
                if let Some(var) = base.as_var() {
                    map.entry(var.to_string()).or_default().insert(*offset, 8);
                }
            }
            Expr::Load { ptr, size } => {
                // `*(ptr + const)` pattern.
                if let Expr::BinOp(BinOp::Add, base, off_expr) = ptr.as_ref()
                    && let (Some(var), Some(off)) = (base.as_var(), off_expr.as_const()) {
                        map.entry(var.to_string())
                            .or_default()
                            .insert(off.cast_unsigned(), *size);
                    }
                Self::walk(ptr, map);
            }
            Expr::BinOp(BinOp::Add, a, b) => {
                // `ptr + const` without explicit Load.
                if let (Some(var), Some(off)) = (a.as_var(), b.as_const()) {
                    map.entry(var.to_string())
                        .or_default()
                        .insert(off.cast_unsigned(), 8);
                }
                Self::walk(a, map);
                Self::walk(b, map);
            }
            Expr::BinOp(_, a, b) => {
                Self::walk(a, map);
                Self::walk(b, map);
            }
            Expr::UnOp(_, e) => Self::walk(e, map),
            Expr::Index { base, index, .. } => {
                Self::walk(base, map);
                Self::walk(index, map);
            }
            Expr::Ternary { cond, then_expr, else_expr } => {
                Self::walk(cond, map);
                Self::walk(then_expr, map);
                Self::walk(else_expr, map);
            }
            Expr::Call { args, .. } => {
                for a in args {
                    Self::walk(a, map);
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SizeTHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Detects `size_t`-like variables from `sizeof`-like usage patterns.
///
/// Patterns:
/// * Variable used as the `size` argument of `malloc`, `calloc`, `realloc`,
///   `memcpy`, `memset`, `memmove`, `new` (operator-new style).
/// * Variable multiplied by a small integer (element-count × size pattern).
/// * Loop counter used to iterate up to a variable of this type.
pub struct SizeTHeuristic;

impl SizeTHeuristic {
    const fn size_arg_functions() -> &'static [(&'static str, usize)] {
        &[
            ("malloc",    0),
            ("calloc",    1),  // calloc(count, size)
            ("realloc",   1),
            ("memcpy",    2),
            ("memmove",   2),
            ("memset",    2),
            ("memcmp",    2),
            ("heapalloc", 2),
            ("virtualalloc", 1),
        ]
    }

    pub fn analyse(assigns: &[(String, Expr)], acc: &mut EvidenceAccumulator) {
        for (_, expr) in assigns {
            if let Expr::Call { callee, args } = expr
                && let Some(name) = callee.as_var() {
                    let name_lc = name.to_lowercase();
                    for (func, idx) in Self::size_arg_functions() {
                        if (name_lc == *func || name_lc.ends_with(func))
                            && let Some(arg) = args.get(*idx)
                                && let Some(var) = arg.as_var() {
                                    acc.add(TypeEvidence::new(
                                        var,
                                        DecompType::Int(IntWidth::U64),
                                        75,
                                        format!("size arg {idx} of {name}"),
                                    ));
                                }
                    }
                }
        }

        // Detect element_count * sizeof pattern:
        //   if x is multiplied by a small power-of-two constant.
        for (dst, expr) in assigns {
            if let Expr::BinOp(BinOp::Mul, a, b) = expr {
                let (Some(var), Some(scale)) = (a.as_var(), b.as_const()) else { continue };
                // Typical element sizes: 1,2,4,8,16,32,64.
                if matches!(scale, 1 | 2 | 4 | 8 | 16 | 32 | 64) {
                    acc.add(TypeEvidence::new(
                        var,
                        DecompType::Int(IntWidth::U64),
                        55,
                        format!("element-count * {scale} pattern"),
                    ));
                    // The result is also size-like.
                    acc.add(TypeEvidence::new(
                        dst,
                        DecompType::Int(IntWidth::U64),
                        55,
                        format!("result of element-count * {scale}"),
                    ));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopCounterHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Detects loop counter variables (index type) and infers `i32` or `i64`.
///
/// Patterns:
/// * Variable initialised to `0` and incremented by `1` in a loop.
/// * Variable compared to an upper bound then used in array indexing.
pub struct LoopCounterHeuristic;

impl LoopCounterHeuristic {
    pub fn analyse(assigns: &[(String, Expr)], acc: &mut EvidenceAccumulator) {
        // Find variables assigned 0.
        let mut init_zero: HashSet<String> = HashSet::new();
        for (dst, expr) in assigns {
            if expr.as_const() == Some(0) {
                init_zero.insert(dst.clone());
            }
        }

        // Find variables that are incremented by `var + 1` or `var + const`.
        let mut incremented: HashSet<String> = HashSet::new();
        for (dst, expr) in assigns {
            if let Expr::BinOp(BinOp::Add, base, off) = expr
                && let Some(src) = base.as_var()
                    && src == dst.as_str() && off.as_const().is_some() {
                        incremented.insert(dst.clone());
                    }
        }

        // Variables that are both init-zero AND incremented → loop counter.
        for var in init_zero.intersection(&incremented) {
            acc.add(TypeEvidence::new(
                var,
                DecompType::Int(IntWidth::I64),
                60,
                "loop counter pattern (init 0, incremented)",
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeuristicOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Runs all heuristics in sequence and merges the evidence into a
/// `TypeEnvironment`.
pub struct HeuristicOrchestrator;

impl HeuristicOrchestrator {
    /// Run all heuristics on the given assignments.
    ///
    /// Returns an accumulator with all gathered evidence.
    #[must_use]
    pub fn run(assigns: &[(String, Expr)]) -> EvidenceAccumulator {
        let mut acc = EvidenceAccumulator::new();
        StringTypeHeuristic::analyse(assigns, &mut acc);
        WinApiTypeHeuristic::analyse(assigns, &mut acc);
        EnumDetectionHeuristic::analyse(assigns, &mut acc);
        StructRecoveryHeuristic::analyse(assigns, &mut acc);
        SizeTHeuristic::analyse(assigns, &mut acc);
        LoopCounterHeuristic::analyse(assigns, &mut acc);
        acc
    }

    /// Run all heuristics and commit results directly into `env`.
    pub fn run_and_commit(assigns: &[(String, Expr)], env: &mut TypeEnvironment) {
        let acc = Self::run(assigns);
        acc.commit(env);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str, args: Vec<&str>) -> Expr {
        Expr::Call {
            callee: Box::new(Expr::Var(name.to_string())),
            args: args.iter().map(|a| Expr::Var(a.to_string())).collect(),
        }
    }

    #[test]
    fn test_string_heuristic_strlen() {
        let assigns = vec![(
            "ret".to_string(),
            call("strlen", vec!["buf"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert!(acc.by_var.contains_key("buf"));
        let best = acc.best_type("buf").unwrap();
        assert_eq!(*best, DecompType::CStr);
    }

    #[test]
    fn test_string_heuristic_strcmp_both_args() {
        let assigns = vec![(
            "res".to_string(),
            call("strcmp", vec!["s1", "s2"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert_eq!(acc.best_type("s1"), Some(&DecompType::CStr));
        assert_eq!(acc.best_type("s2"), Some(&DecompType::CStr));
    }

    #[test]
    fn test_winapi_createfile_handle() {
        let assigns = vec![(
            "hFile".to_string(),
            call("CreateFileA", vec!["path", "access", "share", "sa", "mode", "flags", "template"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        let ty = acc.best_type("hFile").unwrap();
        assert!(ty.is_pointer());
    }

    #[test]
    fn test_winapi_socket() {
        let assigns = vec![(
            "sock".to_string(),
            call("socket", vec!["af", "type", "proto"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert!(acc.best_type("sock").unwrap().is_pointer());
    }

    #[test]
    fn test_enum_detection_three_comparisons() {
        let assigns: Vec<(String, Expr)> = vec![
            ("c1".to_string(), Expr::BinOp(
                BinOp::Eq,
                Box::new(Expr::Var("state".to_string())),
                Box::new(Expr::Const(1, IntWidth::I32)),
            )),
            ("c2".to_string(), Expr::BinOp(
                BinOp::Eq,
                Box::new(Expr::Var("state".to_string())),
                Box::new(Expr::Const(2, IntWidth::I32)),
            )),
            ("c3".to_string(), Expr::BinOp(
                BinOp::Eq,
                Box::new(Expr::Var("state".to_string())),
                Box::new(Expr::Const(3, IntWidth::I32)),
            )),
        ];
        let acc = HeuristicOrchestrator::run(&assigns);
        let ty = acc.best_type("state").unwrap();
        assert!(matches!(ty, DecompType::Enum { .. }));
    }

    #[test]
    fn test_struct_recovery_two_fields() {
        let assigns: Vec<(String, Expr)> = vec![
            ("f0".to_string(), Expr::FieldAccess {
                base: Box::new(Expr::Var("obj".to_string())),
                offset: 0,
            }),
            ("f4".to_string(), Expr::FieldAccess {
                base: Box::new(Expr::Var("obj".to_string())),
                offset: 4,
            }),
        ];
        let acc = HeuristicOrchestrator::run(&assigns);
        let ty = acc.best_type("obj").unwrap();
        assert!(matches!(ty, DecompType::Ptr(_)));
    }

    #[test]
    fn test_size_t_malloc_arg() {
        let assigns = vec![(
            "ptr".to_string(),
            call("malloc", vec!["sz"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert_eq!(acc.best_type("sz"), Some(&DecompType::Int(IntWidth::U64)));
    }

    #[test]
    fn test_loop_counter() {
        let assigns: Vec<(String, Expr)> = vec![
            ("i".to_string(), Expr::Const(0, IntWidth::I32)),
            ("i".to_string(), Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("i".to_string())),
                Box::new(Expr::Const(1, IntWidth::I32)),
            )),
        ];
        let acc = HeuristicOrchestrator::run(&assigns);
        let ty = acc.best_type("i").unwrap();
        assert!(matches!(ty, DecompType::Int(IntWidth::I64)));
    }

    #[test]
    fn test_accumulator_commit() {
        let assigns = vec![(
            "ret".to_string(),
            call("strlen", vec!["s"]),
        )];
        let mut env = TypeEnvironment::new();
        HeuristicOrchestrator::run_and_commit(&assigns, &mut env);
        assert_eq!(env.get("s"), Some(&DecompType::CStr));
    }

    #[test]
    fn test_fopen_returns_file_ptr() {
        let assigns = vec![(
            "fp".to_string(),
            call("fopen", vec!["name", "mode"]),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert!(acc.best_type("fp").unwrap().is_pointer());
    }

    #[test]
    fn test_element_count_mul() {
        let assigns: Vec<(String, Expr)> = vec![(
            "total".to_string(),
            Expr::BinOp(
                BinOp::Mul,
                Box::new(Expr::Var("count".to_string())),
                Box::new(Expr::Const(4, IntWidth::I64)),
            ),
        )];
        let acc = HeuristicOrchestrator::run(&assigns);
        assert_eq!(acc.best_type("count"), Some(&DecompType::Int(IntWidth::U64)));
    }
}
