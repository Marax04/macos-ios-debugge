//! MLIL analysis suite for `rustre-il-mlil`.

use ahash::AHashMap as HashMap;
use std::fmt;

use crate::{MlilExpr, MlilFunction, MlilInstruction, SsaVar};
use rustre_core::address::Address;
use rustre_il_llil::Size;

// ---------------------------------------------------------------------------
// MlilAnalysisError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MlilAnalysisError {
    #[error("missing function")]
    MissingFunction,
    #[error("type mismatch: {0}")]
    TypeMismatch(String),
    #[error("unsupported construct: {0}")]
    Unsupported(String),
}

/// Converge MLIL analysis failures onto the workspace-wide cross-tier error
/// type owned by `rustre-il`, tagged at [`rustre_il::IlTier::Mlil`].
impl From<MlilAnalysisError> for rustre_il::IlError {
    fn from(e: MlilAnalysisError) -> Self {
        match e {
            MlilAnalysisError::Unsupported(s) => Self::Unsupported {
                tier: rustre_il::IlTier::Mlil,
                op: s,
            },
            other => Self::Invalid(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// CallArgumentRecovery
// ---------------------------------------------------------------------------

/// Recovered calling convention information for one call site.
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    pub call_address: Address,
    pub callee: Option<Address>,
    pub callee_name: Option<String>,
    pub argument_count: usize,
    pub arguments: Vec<RecoveredArg>,
    pub return_value: Option<SsaVar>,
}

/// A recovered argument at a call site.
#[derive(Debug, Clone)]
pub struct RecoveredArg {
    pub index: usize,
    pub ssa_var: Option<SsaVar>,
    pub is_constant: bool,
    pub constant_value: Option<i64>,
    pub size: Size,
}

/// Recovers call arguments from MLIL SSA form.
#[derive(Debug, Default)]
pub struct CallArgumentRecovery {
    pub call_sites: Vec<CallSiteInfo>,
}

impl CallArgumentRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `func` for call instructions and recover argument information.
    pub fn analyze(&mut self, func: &MlilFunction) {
        for ai in func.all_instrs() {
            if let MlilInstruction::Call {
                dest: _,
                args,
                ret_vars,
            } = &ai.instr
            {
                let site = CallSiteInfo {
                    call_address: ai.address,
                    callee: None, // would be resolved from `dest` expression
                    callee_name: None,
                    argument_count: args.len(),
                    arguments: args
                        .iter()
                        .enumerate()
                        .map(|(i, arg)| {
                            let (is_const, const_val, size) = Self::classify_arg(arg);
                            RecoveredArg {
                                index: i,
                                ssa_var: None,
                                is_constant: is_const,
                                constant_value: const_val,
                                size,
                            }
                        })
                        .collect(),
                    return_value: ret_vars.first().cloned(),
                };
                self.call_sites.push(site);
            }
        }
    }

    const fn classify_arg(expr: &MlilExpr) -> (bool, Option<i64>, Size) {
        match expr {
            MlilExpr::Const { value, size } => (true, Some(*value as i64), *size),
            MlilExpr::Var { var: _, size } => (false, None, *size),
            _ => (false, None, Size::QWord),
        }
    }

    /// Number of call sites recovered.
    #[must_use]
    pub const fn call_site_count(&self) -> usize {
        self.call_sites.len()
    }
}

// ---------------------------------------------------------------------------
// ReturnValueTracking
// ---------------------------------------------------------------------------

/// Tracks how return values flow through functions.
#[derive(Debug, Default, Clone)]
pub struct ReturnValueInfo {
    pub function_addr: Address,
    pub return_var: Option<SsaVar>,
    pub is_constant: bool,
    pub constant_value: Option<i64>,
    pub callers_using_return: Vec<Address>,
}

/// Tracks return values in MLIL SSA form.
#[derive(Debug, Default)]
pub struct ReturnValueTracking {
    pub info: Vec<ReturnValueInfo>,
}

impl ReturnValueTracking {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze return instructions in `func`.
    pub fn analyze(&mut self, func: &MlilFunction) {
        for ai in func.all_instrs() {
            if let MlilInstruction::Ret { values } = &ai.instr {
                let first = values.first();
                let (is_const, const_val) = match first {
                    Some(MlilExpr::Const { value, .. }) => (true, Some(*value as i64)),
                    _ => (false, None),
                };
                self.info.push(ReturnValueInfo {
                    function_addr: ai.address,
                    return_var: None,
                    is_constant: is_const,
                    constant_value: const_val,
                    callers_using_return: Vec::new(),
                });
            }
        }
    }

    /// Whether the function always returns the same constant.
    #[must_use]
    pub fn is_constant_return(&self) -> bool {
        if self.info.is_empty() {
            return false;
        }
        let first = self.info[0].constant_value;
        self.info
            .iter()
            .all(|r| r.is_constant && r.constant_value == first)
    }
}

// ---------------------------------------------------------------------------
// AliasAnalysis
// ---------------------------------------------------------------------------

/// May-alias set for SSA variables.
#[derive(Debug, Clone, Default)]
pub struct AliasSet {
    pub vars: Vec<SsaVar>,
}

impl AliasSet {
    pub fn add(&mut self, var: SsaVar) {
        if !self.vars.iter().any(|v| v == &var) {
            self.vars.push(var);
        }
    }

    #[must_use]
    pub fn may_alias(&self, var: &SsaVar) -> bool {
        // Alias by name (any version of the same name considered may-alias).
        self.vars.iter().any(|v| v.name == var.name)
    }
}

/// SSA-based alias analysis.
#[derive(Debug, Default)]
pub struct AliasAnalysis {
    pub alias_sets: Vec<AliasSet>,
}

impl AliasAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build alias sets by tracking pointer-type assignments.
    pub fn analyze(&mut self, func: &MlilFunction) {
        for ai in func.all_instrs() {
            if let MlilInstruction::Assign { dest, src, .. } = &ai.instr
                && let MlilExpr::Var { var, .. } = src {
                    // dest may alias var.
                    let mut found = false;
                    for set in &mut self.alias_sets {
                        if set.may_alias(var) {
                            set.add(dest.clone());
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        let mut set = AliasSet::default();
                        set.add(var.clone());
                        set.add(dest.clone());
                        self.alias_sets.push(set);
                    }
                }
        }
    }

    /// Check if two SSA variables may alias.
    #[must_use]
    pub fn may_alias(&self, a: &SsaVar, b: &SsaVar) -> bool {
        self.alias_sets
            .iter()
            .any(|s| s.may_alias(a) && s.may_alias(b))
    }
}

// ---------------------------------------------------------------------------
// SideEffectAnalysis
// ---------------------------------------------------------------------------

/// Side effects of a function or instruction.
#[derive(Debug, Clone, Default)]
pub struct SideEffects {
    pub writes_memory: bool,
    pub reads_memory: bool,
    pub calls_functions: bool,
    pub modifies_globals: bool,
    pub throws_exceptions: bool,
}

impl SideEffects {
    #[must_use]
    pub const fn has_any(&self) -> bool {
        self.writes_memory
            || self.reads_memory
            || self.calls_functions
            || self.modifies_globals
            || self.throws_exceptions
    }

    /// A pure function has no side effects.
    #[must_use]
    pub const fn is_pure(&self) -> bool {
        !self.has_any()
    }
}

/// Analyzes side effects of MLIL functions.
#[derive(Debug, Default)]
pub struct SideEffectAnalysis {
    pub effects: SideEffects,
}

impl SideEffectAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze `func` and collect side effects.
    pub fn analyze(&mut self, func: &MlilFunction) {
        for ai in func.all_instrs() {
            match &ai.instr {
                MlilInstruction::Store { .. } => self.effects.writes_memory = true,
                MlilInstruction::Call { .. }
                | MlilInstruction::TailCall { .. }
                | MlilInstruction::SysCall { .. } => self.effects.calls_functions = true,
                MlilInstruction::Assign { src, .. } => {
                    if expr_reads_memory(src) {
                        self.effects.reads_memory = true;
                    }
                }
                _ => {}
            }
        }
    }
}

fn expr_reads_memory(expr: &MlilExpr) -> bool {
    match expr {
        MlilExpr::Load { .. } => true,
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => expr_reads_memory(l) || expr_reads_memory(r),
        MlilExpr::Neg(e, _)
        | MlilExpr::Not(e, _)
        | MlilExpr::ZeroExtend { expr: e, .. }
        | MlilExpr::SignExtend { expr: e, .. } => expr_reads_memory(e),
        MlilExpr::Call { dest, args, .. } => {
            expr_reads_memory(dest) || args.iter().any(expr_reads_memory)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// PurityAnalysis
// ---------------------------------------------------------------------------

/// Determines whether a function is pure (no observable side effects).
#[derive(Debug, Default)]
pub struct PurityAnalysis {
    pub is_pure: bool,
    pub reasons_for_impurity: Vec<String>,
}

impl PurityAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze `func` for purity.
    pub fn analyze(&mut self, func: &MlilFunction) {
        let mut sea = SideEffectAnalysis::new();
        sea.analyze(func);
        self.is_pure = sea.effects.is_pure();
        if sea.effects.writes_memory {
            self.reasons_for_impurity
                .push("writes to memory".to_string());
        }
        if sea.effects.calls_functions {
            self.reasons_for_impurity
                .push("calls other functions".to_string());
        }
        if sea.effects.modifies_globals {
            self.reasons_for_impurity
                .push("modifies globals".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// ParameterSensitivity
// ---------------------------------------------------------------------------

/// Sensitivity analysis: which outputs depend on which inputs.
#[derive(Debug, Clone, Default)]
pub struct ParameterSensitivity {
    /// `sensitivity[output_idx]` = set of input parameter indices that affect it.
    pub sensitivity: HashMap<usize, Vec<usize>>,
}

impl ParameterSensitivity {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark that output `out_idx` depends on parameter `param_idx`.
    pub fn record_dependency(&mut self, out_idx: usize, param_idx: usize) {
        self.sensitivity.entry(out_idx).or_default().push(param_idx);
    }

    /// Check if output `out_idx` is sensitive to any parameter.
    #[must_use]
    pub fn is_sensitive(&self, out_idx: usize) -> bool {
        self.sensitivity
            .get(&out_idx)
            .is_some_and(|v| !v.is_empty())
    }
}

// ---------------------------------------------------------------------------
// MlilReport
// ---------------------------------------------------------------------------

/// Summary report from the MLIL analysis suite.
#[derive(Debug, Clone, Default)]
pub struct MlilReport {
    pub function_name: String,
    pub function_addr: Address,
    pub instruction_count: usize,
    pub call_sites: usize,
    pub return_count: usize,
    pub is_pure: bool,
    pub alias_sets: usize,
    pub side_effects: SideEffects,
    pub issues: Vec<String>,
}

impl MlilReport {
    #[must_use]
    pub const fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }
}

impl fmt::Display for MlilReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MlilReport({}): {} instrs, {} calls, {} returns, pure={}, aliases={}",
            self.function_name,
            self.instruction_count,
            self.call_sites,
            self.return_count,
            self.is_pure,
            self.alias_sets,
        )
    }
}

// ---------------------------------------------------------------------------
// MlilAnalyzer
// ---------------------------------------------------------------------------

/// Orchestrates all MLIL analysis passes.
pub struct MlilAnalyzer {
    pub call_recovery: CallArgumentRecovery,
    pub return_tracking: ReturnValueTracking,
    pub alias: AliasAnalysis,
    pub side_effects: SideEffectAnalysis,
    pub purity: PurityAnalysis,
    pub sensitivity: ParameterSensitivity,
}

impl MlilAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            call_recovery: CallArgumentRecovery::new(),
            return_tracking: ReturnValueTracking::new(),
            alias: AliasAnalysis::new(),
            side_effects: SideEffectAnalysis::new(),
            purity: PurityAnalysis::new(),
            sensitivity: ParameterSensitivity::new(),
        }
    }

    /// Run all passes and return a report.
    pub fn analyze(&mut self, func: &MlilFunction, func_name: &str) -> MlilReport {
        self.call_recovery.analyze(func);
        self.return_tracking.analyze(func);
        self.alias.analyze(func);
        self.side_effects.analyze(func);
        self.purity.analyze(func);

        MlilReport {
            function_name: func_name.to_string(),
            function_addr: func.entry,
            instruction_count: func.all_instrs().count(),
            call_sites: self.call_recovery.call_site_count(),
            return_count: self.return_tracking.info.len(),
            is_pure: self.purity.is_pure,
            alias_sets: self.alias.alias_sets.len(),
            side_effects: self.side_effects.effects.clone(),
            issues: Vec::new(),
        }
    }
}

impl Default for MlilAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlilAnnotatedInstr, MlilBasicBlock};

    fn make_empty_func() -> MlilFunction {
        MlilFunction::new(Address::new(0x1000))
    }

    fn push_instr(func: &mut MlilFunction, addr: Address, instr: MlilInstruction) {
        if func.blocks.is_empty() {
            func.blocks.push(MlilBasicBlock {
                id: 0,
                start: addr,
                end: Address::new(addr.as_u64() + 16),
                instrs: Vec::new(),
                predecessors: Vec::new(),
                successors: Vec::new(),
            });
        }
        func.blocks[0].instrs.push(MlilAnnotatedInstr {
            address: addr,
            instr,
        });
    }

    fn make_func_with_call() -> MlilFunction {
        let mut func = MlilFunction::new(Address::new(0x2000));
        push_instr(
            &mut func,
            Address::new(0x2000),
            MlilInstruction::Call {
                dest: MlilExpr::Const {
                    value: 0x3000,
                    size: Size::QWord,
                },
                args: vec![MlilExpr::Const {
                    value: 42,
                    size: Size::DWord,
                }],
                ret_vars: vec![],
            },
        );
        func
    }

    fn make_func_with_return() -> MlilFunction {
        let mut func = MlilFunction::new(Address::new(0x4000));
        push_instr(
            &mut func,
            Address::new(0x4000),
            MlilInstruction::Ret {
                values: vec![MlilExpr::Const {
                    value: 0,
                    size: Size::DWord,
                }],
            },
        );
        func
    }

    fn make_func_with_store() -> MlilFunction {
        let mut func = MlilFunction::new(Address::new(0x5000));
        push_instr(
            &mut func,
            Address::new(0x5000),
            MlilInstruction::Store {
                addr: MlilExpr::Const {
                    value: 0x6000,
                    size: Size::QWord,
                },
                src: MlilExpr::Const {
                    value: 1,
                    size: Size::DWord,
                },
                size: Size::DWord,
            },
        );
        func
    }

    // ── CallArgumentRecovery ──────────────────────────────────────────────

    #[test]
    fn call_recovery_empty_func() {
        let mut car = CallArgumentRecovery::new();
        car.analyze(&make_empty_func());
        assert_eq!(car.call_site_count(), 0);
    }

    #[test]
    fn call_recovery_finds_call() {
        let mut car = CallArgumentRecovery::new();
        let func = make_func_with_call();
        car.analyze(&func);
        assert_eq!(car.call_site_count(), 1);
        assert_eq!(car.call_sites[0].argument_count, 1);
    }

    #[test]
    fn call_recovery_const_arg() {
        let mut car = CallArgumentRecovery::new();
        let func = make_func_with_call();
        car.analyze(&func);
        let arg = &car.call_sites[0].arguments[0];
        assert!(arg.is_constant);
        assert_eq!(arg.constant_value, Some(42));
    }

    // ── ReturnValueTracking ───────────────────────────────────────────────

    #[test]
    fn return_tracking_empty_func() {
        let mut rt = ReturnValueTracking::new();
        rt.analyze(&make_empty_func());
        assert!(rt.info.is_empty());
    }

    #[test]
    fn return_tracking_const_return() {
        let mut rt = ReturnValueTracking::new();
        rt.analyze(&make_func_with_return());
        assert_eq!(rt.info.len(), 1);
        assert!(rt.info[0].is_constant);
        assert_eq!(rt.info[0].constant_value, Some(0));
    }

    #[test]
    fn return_tracking_is_constant_return() {
        let mut rt = ReturnValueTracking::new();
        rt.analyze(&make_func_with_return());
        assert!(rt.is_constant_return());
    }

    // ── AliasAnalysis ─────────────────────────────────────────────────────

    #[test]
    fn alias_analysis_empty() {
        let mut aa = AliasAnalysis::new();
        aa.analyze(&make_empty_func());
        assert!(aa.alias_sets.is_empty());
    }

    #[test]
    fn alias_set_add_and_query() {
        let mut set = AliasSet::default();
        let var = SsaVar::new("v1", 0);
        set.add(var.clone());
        assert!(set.may_alias(&var));
        assert!(!set.may_alias(&SsaVar::new("v99", 0)));
    }

    // ── SideEffectAnalysis ────────────────────────────────────────────────

    #[test]
    fn side_effects_pure_func() {
        let mut sea = SideEffectAnalysis::new();
        sea.analyze(&make_empty_func());
        assert!(sea.effects.is_pure());
    }

    #[test]
    fn side_effects_store_detected() {
        let mut sea = SideEffectAnalysis::new();
        sea.analyze(&make_func_with_store());
        assert!(sea.effects.writes_memory);
        assert!(!sea.effects.is_pure());
    }

    #[test]
    fn side_effects_call_detected() {
        let mut sea = SideEffectAnalysis::new();
        sea.analyze(&make_func_with_call());
        assert!(sea.effects.calls_functions);
    }

    // ── PurityAnalysis ────────────────────────────────────────────────────

    #[test]
    fn purity_pure_func() {
        let mut pa = PurityAnalysis::new();
        pa.analyze(&make_empty_func());
        assert!(pa.is_pure);
        assert!(pa.reasons_for_impurity.is_empty());
    }

    #[test]
    fn purity_impure_store() {
        let mut pa = PurityAnalysis::new();
        pa.analyze(&make_func_with_store());
        assert!(!pa.is_pure);
        assert!(!pa.reasons_for_impurity.is_empty());
    }

    // ── ParameterSensitivity ──────────────────────────────────────────────

    #[test]
    fn sensitivity_record_and_query() {
        let mut ps = ParameterSensitivity::new();
        ps.record_dependency(0, 1);
        assert!(ps.is_sensitive(0));
        assert!(!ps.is_sensitive(1));
    }

    // ── MlilAnalyzer ─────────────────────────────────────────────────────

    #[test]
    fn analyzer_empty_func() {
        let mut a = MlilAnalyzer::new();
        let report = a.analyze(&make_empty_func(), "empty");
        assert_eq!(report.instruction_count, 0);
        assert_eq!(report.call_sites, 0);
        assert!(report.is_pure);
    }

    #[test]
    fn analyzer_func_with_call() {
        let mut a = MlilAnalyzer::new();
        let func = make_func_with_call();
        let report = a.analyze(&func, "caller");
        assert_eq!(report.call_sites, 1);
        assert!(!report.is_pure);
    }

    #[test]
    fn analyzer_func_with_store() {
        let mut a = MlilAnalyzer::new();
        let report = a.analyze(&make_func_with_store(), "writer");
        assert!(!report.is_pure);
        assert!(report.side_effects.writes_memory);
    }

    #[test]
    fn mlil_report_display() {
        let r = MlilReport {
            function_name: "test".to_string(),
            ..Default::default()
        };
        let s = r.to_string();
        assert!(s.contains("test"));
    }

    // ── SideEffects ───────────────────────────────────────────────────────

    #[test]
    fn side_effects_has_any() {
        let mut se = SideEffects::default();
        assert!(!se.has_any());
        se.writes_memory = true;
        assert!(se.has_any());
    }

    // ── CallSiteInfo ──────────────────────────────────────────────────────

    #[test]
    fn call_site_address() {
        let mut car = CallArgumentRecovery::new();
        let func = make_func_with_call();
        car.analyze(&func);
        assert_eq!(car.call_sites[0].call_address, Address::new(0x2000));
    }

    #[test]
    fn analyzer_default() {
        let a = MlilAnalyzer::default();
        assert_eq!(a.alias.alias_sets.len(), 0);
    }

    #[test]
    fn mlil_analysis_error_converges_to_il_error() {
        let e: rustre_il::IlError = MlilAnalysisError::Unsupported("phi".to_string()).into();
        assert_eq!(e.to_string(), "unsupported operation `phi` at tier mlil");

        let e: rustre_il::IlError = MlilAnalysisError::MissingFunction.into();
        assert_eq!(e.to_string(), "invalid IL: missing function");

        let e: rustre_il::IlError = MlilAnalysisError::TypeMismatch("u8 vs u64".to_string()).into();
        assert_eq!(e.to_string(), "invalid IL: type mismatch: u8 vs u64");
    }
}
