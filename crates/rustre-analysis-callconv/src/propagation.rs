//! Calling-convention propagation from callee to call-site parameter names.
//!
//! Once the calling convention of a function has been detected, this module
//! propagates that information outward to every *call site* that invokes the
//! function.  At each call site the registers / stack slots that are live
//! immediately before the `CALL` instruction can be matched against the
//! detected callee's argument registers to produce named parameters:
//!
//! ```text
//!   ; call site before propagation:
//!   mov  rdi, rbx        ; arg0 = ?
//!   mov  rsi, rax        ; arg1 = ?
//!   call foo
//!
//!   ; call site after propagation (callee is SysV AMD64):
//!   mov  rdi, rbx        ; arg0 = int param0
//!   mov  rsi, rax        ; arg1 = int param1
//!   call foo
//! ```
//!
//! The main types are:
//!
//! * [`CallSiteArgument`] — a named argument at a call site.
//! * [`CallSite`] — one invocation of a function with resolved argument names.
//! * [`PropagationResult`] — the collection of all annotated call sites for a
//!   callee.
//! * [`CalleePropagator`] — orchestrates the propagation for a single callee.
//! * [`BulkPropagator`] — applies propagation across a whole binary.

use crate::{ArgType, CallingConvDef, CallingConventionPattern, FunctionInfo, ObservedPattern};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// CallSiteArgument — one argument at a call site
// ─────────────────────────────────────────────────────────────────────────────

/// A single argument at a call site after propagation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSiteArgument {
    /// Zero-based parameter position in the callee's signature.
    pub param_index: usize,
    /// The ABI name of this parameter's register (e.g. `"rdi"`, `"xmm0"`).
    pub register: String,
    /// A human-readable name derived from the calling convention
    /// (e.g. `"param0"`, `"this"`, `"float_param0"`).
    pub param_name: String,
    /// The argument type category.
    pub arg_type: ArgType,
    /// Whether this is a floating-point argument.
    pub is_fp: bool,
    /// Whether this is the implicit `this` pointer.
    pub is_this: bool,
}

impl CallSiteArgument {
    /// Build a parameter name from a position and type.
    #[must_use]
    pub fn make_param_name(index: usize, is_fp: bool, is_this: bool) -> String {
        if is_this {
            "this".to_owned()
        } else if is_fp {
            format!("fp_param{index}")
        } else {
            format!("param{index}")
        }
    }
}

impl std::fmt::Display for CallSiteArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}={} ({})",
            self.param_name, self.register, self.arg_type
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSite — one invocation of a function
// ─────────────────────────────────────────────────────────────────────────────

/// One invocation of a callee at a specific address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the `CALL` instruction.
    pub call_address: u64,
    /// Address of the callee being invoked.
    pub callee_address: u64,
    /// Name of the callee (if known).
    pub callee_name: Option<String>,
    /// Resolved arguments at this call site.
    pub arguments: Vec<CallSiteArgument>,
    /// Registers observed to be live (written) immediately before the call.
    pub live_before_call: Vec<String>,
    /// Whether this call site provides a complete argument list (all arg regs
    /// are accounted for, or the last argument is on the stack).
    pub is_complete: bool,
}

impl CallSite {
    /// Create a new call site with no resolved arguments.
    #[must_use]
    pub const fn new(call_address: u64, callee_address: u64) -> Self {
        Self {
            call_address,
            callee_address,
            callee_name: None,
            arguments: Vec::new(),
            live_before_call: Vec::new(),
            is_complete: false,
        }
    }

    /// Attach a callee name.
    #[must_use]
    pub fn with_callee_name(mut self, name: impl Into<String>) -> Self {
        self.callee_name = Some(name.into());
        self
    }

    /// Number of resolved arguments.
    #[must_use]
    pub const fn arg_count(&self) -> usize {
        self.arguments.len()
    }

    /// Whether this call passes a `this` pointer.
    #[must_use]
    pub fn has_this(&self) -> bool {
        self.arguments.iter().any(|a| a.is_this)
    }

    /// Find the argument for a given register name.
    #[must_use]
    pub fn arg_for_register(&self, reg: &str) -> Option<&CallSiteArgument> {
        self.arguments.iter().find(|a| a.register == reg)
    }
}

impl std::fmt::Display for CallSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let callee = self.callee_name.as_deref().unwrap_or("?");
        write!(
            f,
            "{:#x}: call {} ({} args)",
            self.call_address,
            callee,
            self.arguments.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationResult — all annotated call sites for one callee
// ─────────────────────────────────────────────────────────────────────────────

/// All annotated call sites for a single callee function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResult {
    /// Address of the callee.
    pub callee_address: u64,
    /// Name of the callee (if known).
    pub callee_name: Option<String>,
    /// The calling convention used.
    pub cc_name: String,
    /// All resolved call sites.
    pub call_sites: Vec<CallSite>,
}

impl PropagationResult {
    /// Create an empty propagation result.
    #[must_use]
    pub fn new(callee_address: u64, cc_name: impl Into<String>) -> Self {
        Self {
            callee_address,
            callee_name: None,
            cc_name: cc_name.into(),
            call_sites: Vec::new(),
        }
    }

    /// Total number of call sites.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.call_sites.len()
    }

    /// Return call sites with `is_complete == true`.
    #[must_use]
    pub fn complete_call_sites(&self) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|cs| cs.is_complete).collect()
    }

    /// Maximum number of arguments observed across all call sites.
    #[must_use]
    pub fn max_arg_count(&self) -> usize {
        self.call_sites
            .iter()
            .map(CallSite::arg_count)
            .max()
            .unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Simplified call-site instruction model
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified instruction near a call site, used to determine which registers
/// are written (live) immediately before the call.
#[derive(Debug, Clone)]
pub enum CallSiteInstr {
    /// Write (define) a register: `mov rdi, ...`
    RegWrite {
        /// Register name.
        reg: String,
    },
    /// Read a register (but do not define it).
    RegRead {
        /// Register name.
        reg: String,
    },
    /// Write a floating-point register.
    FpWrite {
        /// FP register name.
        reg: String,
    },
    /// The `CALL` instruction itself.
    Call {
        /// Target address.
        target: u64,
    },
    /// Any other instruction.
    Other,
}

// ─────────────────────────────────────────────────────────────────────────────
// CalleePropagator — propagate CC to a single callee's call sites
// ─────────────────────────────────────────────────────────────────────────────

/// Propagates the calling convention of a single callee to all its call sites.
pub struct CalleePropagator<'a> {
    /// The static ABI definition used for the callee.
    pub cc: &'a CallingConvDef,
    /// Whether to include floating-point argument registers.
    pub include_fp: bool,
}

impl<'a> CalleePropagator<'a> {
    /// Create a propagator for the given calling convention.
    #[must_use]
    pub const fn new(cc: &'a CallingConvDef) -> Self {
        Self {
            cc,
            include_fp: true,
        }
    }

    /// Determine which argument registers are live (written) before the call
    /// by scanning backwards through `instrs` (in forward-scan order with the
    /// call at the end).
    ///
    /// Returns registers in the order they appear in the ABI (not the order
    /// they were written in the instruction stream).
    #[must_use]
    pub fn extract_live_before_call(&self, instrs: &[CallSiteInstr]) -> Vec<String> {
        let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
        for instr in instrs {
            match instr {
                CallSiteInstr::RegWrite { reg } | CallSiteInstr::FpWrite { reg } => {
                    written.insert(reg.clone());
                }
                CallSiteInstr::RegRead { .. }
                | CallSiteInstr::Call { .. }
                | CallSiteInstr::Other => {}
            }
        }
        // Return in ABI order.
        let mut live = Vec::new();
        for &reg in self.cc.int_arg_regs {
            if written.contains(reg) {
                live.push(reg.to_owned());
            }
        }
        if self.include_fp {
            for &reg in self.cc.float_arg_regs {
                if written.contains(reg) {
                    live.push(reg.to_owned());
                }
            }
        }
        live
    }

    /// Resolve the named arguments for a call site, given which registers are
    /// live before the call.
    ///
    /// Matches each live register against the ABI's ordered argument register
    /// list to produce `CallSiteArgument` records.
    #[must_use]
    pub fn resolve_arguments(&self, live_regs: &[String]) -> Vec<CallSiteArgument> {
        let mut args = Vec::new();
        let mut int_idx = 0usize;
        let mut fp_idx = 0usize;

        // `this` pointer (thiscall / methods).
        if self.cc.has_this_ptr && !self.cc.int_arg_regs.is_empty() {
            let this_reg = self.cc.int_arg_regs[0];
            if live_regs.iter().any(|r| r == this_reg) {
                args.push(CallSiteArgument {
                    param_index: 0,
                    register: this_reg.to_owned(),
                    param_name: "this".to_owned(),
                    arg_type: ArgType::ThisPtr {
                        reg: this_reg.to_owned(),
                    },
                    is_fp: false,
                    is_this: true,
                });
                int_idx = 1; // skip the `this` register
            }
        }

        // Integer / pointer arguments.
        for (i, &reg) in self.cc.int_arg_regs.iter().enumerate() {
            if i < int_idx {
                continue;
            }
            if live_regs.iter().any(|r| r == reg) {
                let param_idx = args.len();
                args.push(CallSiteArgument {
                    param_index: param_idx,
                    register: reg.to_owned(),
                    param_name: CallSiteArgument::make_param_name(int_idx, false, false),
                    arg_type: ArgType::Integer {
                        reg: reg.to_owned(),
                        position: int_idx,
                    },
                    is_fp: false,
                    is_this: false,
                });
                int_idx += 1;
            }
        }

        // Floating-point arguments.
        if self.include_fp {
            for &reg in self.cc.float_arg_regs {
                if live_regs.iter().any(|r| r == reg) {
                    let param_idx = args.len();
                    args.push(CallSiteArgument {
                        param_index: param_idx,
                        register: reg.to_owned(),
                        param_name: CallSiteArgument::make_param_name(fp_idx, true, false),
                        arg_type: ArgType::Float {
                            reg: reg.to_owned(),
                            position: fp_idx,
                        },
                        is_fp: true,
                        is_this: false,
                    });
                    fp_idx += 1;
                }
            }
        }

        args
    }

    /// Annotate a single call site: extract live registers from `instrs` and
    /// resolve them to named arguments.
    #[must_use]
    pub fn annotate_call_site(
        &self,
        call_address: u64,
        callee_address: u64,
        instrs: &[CallSiteInstr],
    ) -> CallSite {
        let live = self.extract_live_before_call(instrs);
        let arguments = self.resolve_arguments(&live);
        let is_complete = !live.is_empty();
        CallSite {
            call_address,
            callee_address,
            callee_name: None,
            arguments,
            live_before_call: live,
            is_complete,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BulkPropagator — propagate CC across a whole binary
// ─────────────────────────────────────────────────────────────────────────────

/// A record describing a call site for use with [`BulkPropagator`].
#[derive(Debug, Clone)]
pub struct RawCallSite {
    /// Address of the `CALL` instruction.
    pub call_address: u64,
    /// Address of the callee being invoked.
    pub callee_address: u64,
    /// Instructions observed immediately before the call (in order).
    pub pre_call_instrs: Vec<CallSiteInstr>,
}

/// Propagates calling conventions to all call sites in a binary.
///
/// Usage:
/// 1. Build a map of callee-address → `&'static CallingConvDef` from prior
///    detection results.
/// 2. Provide a list of `RawCallSite` records from disassembly.
/// 3. Call [`BulkPropagator::propagate`] to receive `PropagationResult`s.
pub struct BulkPropagator<'a> {
    /// Callee address → calling convention.
    /// Keyed by attacker-supplied addresses from binary analysis — use
    /// `FxHashMap` to prevent hash-collision `DoS` via crafted binaries.
    cc_map: FxHashMap<u64, &'a CallingConvDef>,
    /// Optional callee name map (same threat model as `cc_map`).
    name_map: FxHashMap<u64, String>,
}

impl<'a> BulkPropagator<'a> {
    /// Create a new bulk propagator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cc_map: FxHashMap::default(),
            name_map: FxHashMap::default(),
        }
    }

    /// Register the calling convention for a callee.
    pub fn register_callee(&mut self, callee_addr: u64, cc: &'a CallingConvDef) {
        self.cc_map.insert(callee_addr, cc);
    }

    /// Register a human-readable name for a callee.
    pub fn register_name(&mut self, callee_addr: u64, name: impl Into<String>) {
        self.name_map.insert(callee_addr, name.into());
    }

    /// Propagate calling conventions to all provided call sites.
    ///
    /// For each `RawCallSite`, looks up the callee's CC and annotates the
    /// call site.  Call sites whose callee is unknown are skipped.
    ///
    /// Returns one `PropagationResult` per distinct callee, sorted by address.
    #[must_use]
    pub fn propagate(&self, raw_sites: &[RawCallSite]) -> Vec<PropagationResult> {
        // Group by callee address.
        // Keyed by binary-derived addresses — use FxHashMap to prevent DoS.
        let mut per_callee: FxHashMap<u64, Vec<&RawCallSite>> = FxHashMap::default();
        for site in raw_sites {
            per_callee
                .entry(site.callee_address)
                .or_default()
                .push(site);
        }

        let mut results = Vec::new();

        for (callee_addr, sites) in &per_callee {
            let Some(&cc) = self.cc_map.get(callee_addr) else {
                continue;
            };
            let propagator = CalleePropagator::new(cc);
            let callee_name = self.name_map.get(callee_addr).cloned();

            let mut result = PropagationResult::new(*callee_addr, cc.name);
            result.callee_name.clone_from(&callee_name);

            for raw in sites {
                let mut site = propagator.annotate_call_site(
                    raw.call_address,
                    raw.callee_address,
                    &raw.pre_call_instrs,
                );
                site.callee_name.clone_from(&callee_name);
                result.call_sites.push(site);
            }

            result.call_sites.sort_by_key(|s| s.call_address);
            results.push(result);
        }

        results.sort_by_key(|r| r.callee_address);
        results
    }
}

impl Default for BulkPropagator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Propagation from ObservedPattern / CallingConventionPattern
// ─────────────────────────────────────────────────────────────────────────────

/// Infer named parameters from an [`ObservedPattern`] and a
/// [`CallingConventionPattern`].
///
/// This is a lighter-weight alternative to [`CalleePropagator`] that works
/// with the pattern-matching data structures used by the heuristic detector.
#[must_use]
pub fn infer_params_from_observed(
    observed: &ObservedPattern,
    cc: &CallingConventionPattern,
) -> Vec<CallSiteArgument> {
    let mut args = Vec::new();
    let mut int_idx = 0usize;
    let mut fp_idx = 0usize;

    // This-pointer (thiscall hint).
    if observed.this_ptr_hint && cc.hidden_this_ptr && !cc.arg_registers.is_empty() {
        let reg = &cc.arg_registers[0];
        args.push(CallSiteArgument {
            param_index: 0,
            register: reg.clone(),
            param_name: "this".to_owned(),
            arg_type: ArgType::ThisPtr { reg: reg.clone() },
            is_fp: false,
            is_this: true,
        });
        int_idx = 1;
    }

    // Integer arguments.
    for (i, reg) in cc.arg_registers.iter().enumerate() {
        if i < int_idx {
            continue;
        }
        if observed.read_before_write.contains(reg) {
            let param_idx = args.len();
            args.push(CallSiteArgument {
                param_index: param_idx,
                register: reg.clone(),
                param_name: CallSiteArgument::make_param_name(int_idx, false, false),
                arg_type: ArgType::Integer {
                    reg: reg.clone(),
                    position: int_idx,
                },
                is_fp: false,
                is_this: false,
            });
            int_idx += 1;
        }
    }

    // FP arguments.
    for reg in &cc.fp_arg_registers {
        if observed.fp_read_before_write.contains(reg) {
            let param_idx = args.len();
            args.push(CallSiteArgument {
                param_index: param_idx,
                register: reg.clone(),
                param_name: CallSiteArgument::make_param_name(fp_idx, true, false),
                arg_type: ArgType::Float {
                    reg: reg.clone(),
                    position: fp_idx,
                },
                is_fp: true,
                is_this: false,
            });
            fp_idx += 1;
        }
    }

    // Stack arguments.
    for slot in 0..observed.stack_arg_count {
        let offset = slot.saturating_mul(4); // conservative 4-byte slots
        let param_idx = args.len();
        args.push(CallSiteArgument {
            param_index: param_idx,
            register: format!("[sp+{offset:#x}]"),
            param_name: format!("stack_param{slot}"),
            arg_type: ArgType::Stack { slot, offset },
            is_fp: false,
            is_this: false,
        });
    }

    args
}

/// Build a [`FunctionInfo`] from an [`ObservedPattern`] and a
/// [`CallingConventionPattern`], populating `live_in_regs`, `live_in_fp_regs`,
/// and `has_this_ptr`.
#[must_use]
pub fn function_info_from_observed(
    address: u64,
    observed: &ObservedPattern,
    cc: &CallingConventionPattern,
) -> FunctionInfo {
    FunctionInfo {
        address,
        cc_name: cc.name.clone(),
        live_in_regs: observed.read_before_write.clone(),
        live_in_fp_regs: observed.fp_read_before_write.clone(),
        stack_arg_count: observed.stack_arg_count,
        has_this_ptr: observed.this_ptr_hint || cc.hidden_this_ptr,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a set of propagation results.
#[derive(Debug, Clone, Default)]
pub struct PropagationStats {
    /// Total callees for which propagation was attempted.
    pub callee_count: usize,
    /// Total call sites annotated.
    pub total_call_sites: usize,
    /// Total arguments resolved across all call sites.
    pub total_args_resolved: usize,
    /// Number of call sites with at least one argument.
    pub non_empty_call_sites: usize,
    /// Average number of arguments per non-empty call site.
    pub avg_args_per_site: f64,
    /// Number of call sites with a `this` pointer.
    pub this_ptr_sites: usize,
}

impl PropagationStats {
    /// Compute statistics from a slice of propagation results.
    #[must_use]
    pub fn compute(results: &[PropagationResult]) -> Self {
        let callee_count = results.len();
        let mut total_call_sites = 0;
        let mut total_args = 0;
        let mut non_empty = 0;
        let mut this_ptr_sites = 0;

        for res in results {
            for site in &res.call_sites {
                total_call_sites += 1;
                total_args += site.arg_count();
                if !site.arguments.is_empty() {
                    non_empty += 1;
                }
                if site.has_this() {
                    this_ptr_sites += 1;
                }
            }
        }

        let avg_args_per_site = if non_empty > 0 {
            total_args as f64 / non_empty as f64
        } else {
            0.0
        };

        Self {
            callee_count,
            total_call_sites,
            total_args_resolved: total_args,
            non_empty_call_sites: non_empty,
            avg_args_per_site,
            this_ptr_sites,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObservedPattern;
    use crate::cc_database::{CC_MS_X64, CC_SYSV_AMD64, CC_THISCALL_X86};
    use crate::{sysv_x64, thiscall_x86};

    fn write(reg: &str) -> CallSiteInstr {
        CallSiteInstr::RegWrite { reg: reg.into() }
    }
    fn fp_write(reg: &str) -> CallSiteInstr {
        CallSiteInstr::FpWrite { reg: reg.into() }
    }

    // ── CallSiteArgument ─────────────────────────────────────────────────────

    #[test]
    fn test_make_param_name_this() {
        assert_eq!(CallSiteArgument::make_param_name(0, false, true), "this");
    }

    #[test]
    fn test_make_param_name_int() {
        assert_eq!(CallSiteArgument::make_param_name(2, false, false), "param2");
    }

    #[test]
    fn test_make_param_name_fp() {
        assert_eq!(
            CallSiteArgument::make_param_name(1, true, false),
            "fp_param1"
        );
    }

    // ── CallSite ─────────────────────────────────────────────────────────────

    #[test]
    fn test_call_site_arg_count() {
        let mut cs = CallSite::new(0x1000, 0x2000);
        assert_eq!(cs.arg_count(), 0);
        cs.arguments.push(CallSiteArgument {
            param_index: 0,
            register: "rdi".into(),
            param_name: "param0".into(),
            arg_type: ArgType::Integer {
                reg: "rdi".into(),
                position: 0,
            },
            is_fp: false,
            is_this: false,
        });
        assert_eq!(cs.arg_count(), 1);
    }

    #[test]
    fn test_call_site_has_this() {
        let mut cs = CallSite::new(0x1000, 0x2000);
        cs.arguments.push(CallSiteArgument {
            param_index: 0,
            register: "ecx".into(),
            param_name: "this".into(),
            arg_type: ArgType::ThisPtr { reg: "ecx".into() },
            is_fp: false,
            is_this: true,
        });
        assert!(cs.has_this());
    }

    #[test]
    fn test_call_site_arg_for_register() {
        let mut cs = CallSite::new(0x100, 0x200);
        cs.arguments.push(CallSiteArgument {
            param_index: 0,
            register: "rdi".into(),
            param_name: "param0".into(),
            arg_type: ArgType::Integer {
                reg: "rdi".into(),
                position: 0,
            },
            is_fp: false,
            is_this: false,
        });
        assert!(cs.arg_for_register("rdi").is_some());
        assert!(cs.arg_for_register("rsi").is_none());
    }

    #[test]
    fn test_call_site_display() {
        let cs = CallSite::new(0x1000, 0x2000).with_callee_name("printf");
        let s = format!("{cs}");
        assert!(s.contains("printf"));
        assert!(s.contains("0x1000"));
    }

    // ── CalleePropagator ──────────────────────────────────────────────────────

    #[test]
    fn test_propagator_extract_live_sysv() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let instrs = vec![write("rdi"), write("rsi"), write("rdx")];
        let live = p.extract_live_before_call(&instrs);
        assert_eq!(live, vec!["rdi", "rsi", "rdx"]);
    }

    #[test]
    fn test_propagator_extract_live_none() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let instrs = vec![CallSiteInstr::Other];
        let live = p.extract_live_before_call(&instrs);
        assert!(live.is_empty());
    }

    #[test]
    fn test_propagator_extract_live_ms_x64() {
        let p = CalleePropagator::new(&CC_MS_X64);
        let instrs = vec![write("rcx"), write("rdx")];
        let live = p.extract_live_before_call(&instrs);
        assert!(live.contains(&"rcx".to_owned()));
        assert!(live.contains(&"rdx".to_owned()));
    }

    #[test]
    fn test_propagator_resolve_one_arg() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let live = vec!["rdi".to_owned()];
        let args = p.resolve_arguments(&live);
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].register, "rdi");
        assert_eq!(args[0].param_name, "param0");
        assert!(!args[0].is_fp);
    }

    #[test]
    fn test_propagator_resolve_three_int_args() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let live = vec!["rdi".to_owned(), "rsi".to_owned(), "rdx".to_owned()];
        let args = p.resolve_arguments(&live);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].param_name, "param0");
        assert_eq!(args[1].param_name, "param1");
        assert_eq!(args[2].param_name, "param2");
    }

    #[test]
    fn test_propagator_resolve_fp_arg() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let live = vec!["xmm0".to_owned()];
        let args = p.resolve_arguments(&live);
        assert_eq!(args.len(), 1);
        assert!(args[0].is_fp);
        assert_eq!(args[0].register, "xmm0");
        assert_eq!(args[0].param_name, "fp_param0");
    }

    #[test]
    fn test_propagator_resolve_this_thiscall() {
        let p = CalleePropagator::new(&CC_THISCALL_X86);
        let live = vec!["ecx".to_owned()];
        let args = p.resolve_arguments(&live);
        assert_eq!(args.len(), 1);
        assert!(args[0].is_this);
        assert_eq!(args[0].param_name, "this");
    }

    #[test]
    fn test_propagator_annotate_call_site() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let instrs = vec![write("rdi"), write("rsi")];
        let cs = p.annotate_call_site(0x400, 0x1000, &instrs);
        assert_eq!(cs.call_address, 0x400);
        assert_eq!(cs.callee_address, 0x1000);
        assert_eq!(cs.arg_count(), 2);
        assert!(cs.is_complete);
    }

    #[test]
    fn test_propagator_annotate_empty() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let cs = p.annotate_call_site(0x400, 0x1000, &[]);
        assert_eq!(cs.arg_count(), 0);
        assert!(!cs.is_complete);
    }

    #[test]
    fn test_propagator_fp_live() {
        let p = CalleePropagator::new(&CC_SYSV_AMD64);
        let instrs = vec![fp_write("xmm0"), fp_write("xmm1")];
        let live = p.extract_live_before_call(&instrs);
        assert!(live.contains(&"xmm0".to_owned()));
        assert!(live.contains(&"xmm1".to_owned()));
    }

    // ── BulkPropagator ────────────────────────────────────────────────────────

    #[test]
    fn test_bulk_propagator_basic() {
        let mut bp = BulkPropagator::new();
        bp.register_callee(0x2000, &CC_SYSV_AMD64);
        bp.register_name(0x2000, "my_func");

        let raw = vec![RawCallSite {
            call_address: 0x1000,
            callee_address: 0x2000,
            pre_call_instrs: vec![write("rdi"), write("rsi")],
        }];

        let results = bp.propagate(&raw);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].call_count(), 1);
        assert_eq!(results[0].callee_name.as_deref(), Some("my_func"));
        let cs = &results[0].call_sites[0];
        assert_eq!(cs.arg_count(), 2);
    }

    #[test]
    fn test_bulk_propagator_unknown_callee_skipped() {
        let bp = BulkPropagator::new();
        let raw = vec![RawCallSite {
            call_address: 0x1000,
            callee_address: 0x9999, // not registered
            pre_call_instrs: vec![write("rdi")],
        }];
        let results = bp.propagate(&raw);
        assert!(results.is_empty());
    }

    #[test]
    fn test_bulk_propagator_multiple_callees() {
        let mut bp = BulkPropagator::new();
        bp.register_callee(0x1000, &CC_SYSV_AMD64);
        bp.register_callee(0x2000, &CC_MS_X64);

        let raw = vec![
            RawCallSite {
                call_address: 0x100,
                callee_address: 0x1000,
                pre_call_instrs: vec![write("rdi")],
            },
            RawCallSite {
                call_address: 0x200,
                callee_address: 0x2000,
                pre_call_instrs: vec![write("rcx")],
            },
        ];

        let results = bp.propagate(&raw);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_bulk_propagator_sorted_by_callee_addr() {
        let mut bp = BulkPropagator::new();
        bp.register_callee(0x3000, &CC_SYSV_AMD64);
        bp.register_callee(0x1000, &CC_SYSV_AMD64);

        let raw = vec![
            RawCallSite {
                call_address: 0x50,
                callee_address: 0x3000,
                pre_call_instrs: vec![],
            },
            RawCallSite {
                call_address: 0x40,
                callee_address: 0x1000,
                pre_call_instrs: vec![],
            },
        ];

        let results = bp.propagate(&raw);
        assert!(results[0].callee_address <= results[1].callee_address);
    }

    // ── infer_params_from_observed ────────────────────────────────────────────

    #[test]
    fn test_infer_params_sysv_two_int_args() {
        let cc = sysv_x64();
        let obs = ObservedPattern {
            read_before_write: vec!["rdi".into(), "rsi".into()],
            ..Default::default()
        };
        let args = infer_params_from_observed(&obs, &cc);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].register, "rdi");
        assert_eq!(args[1].register, "rsi");
    }

    #[test]
    fn test_infer_params_this_call() {
        let cc = thiscall_x86();
        let obs = ObservedPattern {
            read_before_write: vec!["ecx".into()],
            this_ptr_hint: true,
            ..Default::default()
        };
        let args = infer_params_from_observed(&obs, &cc);
        assert_eq!(args.len(), 1);
        assert!(args[0].is_this);
    }

    #[test]
    fn test_infer_params_stack_args() {
        let cc = sysv_x64();
        let obs = ObservedPattern {
            stack_arg_count: 2,
            ..Default::default()
        };
        let args = infer_params_from_observed(&obs, &cc);
        assert_eq!(args.len(), 2);
        assert!(
            args.iter()
                .all(|a| matches!(a.arg_type, ArgType::Stack { .. }))
        );
    }

    // ── function_info_from_observed ───────────────────────────────────────────

    #[test]
    fn test_function_info_from_observed() {
        let cc = sysv_x64();
        let obs = ObservedPattern {
            read_before_write: vec!["rdi".into()],
            fp_read_before_write: vec!["xmm0".into()],
            stack_arg_count: 1,
            ..Default::default()
        };
        let info = function_info_from_observed(0x1000, &obs, &cc);
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.cc_name, "System V AMD64 ABI");
        assert_eq!(info.live_in_regs, vec!["rdi".to_owned()]);
        assert_eq!(info.live_in_fp_regs, vec!["xmm0".to_owned()]);
        assert_eq!(info.stack_arg_count, 1);
    }

    // ── PropagationStats ─────────────────────────────────────────────────────

    #[test]
    fn test_propagation_stats_empty() {
        let stats = PropagationStats::compute(&[]);
        assert_eq!(stats.callee_count, 0);
        assert_eq!(stats.total_call_sites, 0);
    }

    #[test]
    fn test_propagation_stats_basic() {
        let mut bp = BulkPropagator::new();
        bp.register_callee(0x1000, &CC_SYSV_AMD64);
        let raw = vec![
            RawCallSite {
                call_address: 0x10,
                callee_address: 0x1000,
                pre_call_instrs: vec![write("rdi")],
            },
            RawCallSite {
                call_address: 0x20,
                callee_address: 0x1000,
                pre_call_instrs: vec![write("rdi"), write("rsi")],
            },
        ];
        let results = bp.propagate(&raw);
        let stats = PropagationStats::compute(&results);
        assert_eq!(stats.callee_count, 1);
        assert_eq!(stats.total_call_sites, 2);
        assert_eq!(stats.total_args_resolved, 3);
        assert_eq!(stats.non_empty_call_sites, 2);
        assert!((stats.avg_args_per_site - 1.5).abs() < 0.01);
    }

    // ── PropagationResult ─────────────────────────────────────────────────────

    #[test]
    fn test_propagation_result_max_arg_count() {
        let mut res = PropagationResult::new(0x1000, "sysv_amd64");
        let mut cs1 = CallSite::new(0x10, 0x1000);
        cs1.arguments.push(CallSiteArgument {
            param_index: 0,
            register: "rdi".into(),
            param_name: "param0".into(),
            arg_type: ArgType::Integer {
                reg: "rdi".into(),
                position: 0,
            },
            is_fp: false,
            is_this: false,
        });
        let mut cs2 = CallSite::new(0x20, 0x1000);
        cs2.arguments.push(CallSiteArgument {
            param_index: 0,
            register: "rdi".into(),
            param_name: "param0".into(),
            arg_type: ArgType::Integer {
                reg: "rdi".into(),
                position: 0,
            },
            is_fp: false,
            is_this: false,
        });
        cs2.arguments.push(CallSiteArgument {
            param_index: 1,
            register: "rsi".into(),
            param_name: "param1".into(),
            arg_type: ArgType::Integer {
                reg: "rsi".into(),
                position: 1,
            },
            is_fp: false,
            is_this: false,
        });
        res.call_sites = vec![cs1, cs2];
        assert_eq!(res.max_arg_count(), 2);
    }
}
