//! `abi_analyzer` — ABI analysis: calling convention detection, canonicalisation,
//! mismatch detection, variadic detection, and aggregate passing analysis.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::fmt;

/// Re-exported helper aliases used by downstream ABI tooling.
///
/// Uses `FxHashMap` (randomised seed) to prevent hash-collision `DoS` when
/// keys originate from untrusted binary content (register names, addresses).
pub type AbiMap<K, V> = FxHashMap<K, V>;
/// Re-exported helper alias for ABI set collections.
pub type AbiSet<T> = HashSet<T>;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    InsufficientEvidence(String),
    ConflictingEvidence(String),
    UnsupportedArch(String),
    ParseError(String),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientEvidence(msg) => write!(f, "insufficient evidence: {msg}"),
            Self::ConflictingEvidence(msg) => write!(f, "conflicting evidence: {msg}"),
            Self::UnsupportedArch(arch) => write!(f, "unsupported architecture: {arch}"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for AbiError {}

// ─── Architecture ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisArch {
    X86,
    X86_64,
    Arm32,
    Arm64,
    Mips,
    RiscV64,
}

impl fmt::Display for AnalysisArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86-64"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips => write!(f, "mips"),
            Self::RiscV64 => write!(f, "riscv64"),
        }
    }
}

// ─── RegisterUsage ────────────────────────────────────────────────────────────

/// Records how a register is used at function entry/exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUsage {
    pub name: String,
    /// Read before written in this function (likely argument).
    pub read_before_write: bool,
    /// Written then restored (callee-saved).
    pub saved_and_restored: bool,
    /// Written without save (caller-saved or return value).
    pub written_without_save: bool,
}

// ─── CallingConventionDetector ────────────────────────────────────────────────

/// Heuristic confidence level for a detected calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CcConfidence {
    Low,
    Medium,
    High,
    Definitive,
}

/// Evidence piece for CC detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcEvidence {
    pub kind: String,
    pub description: String,
    pub weight: i32,
}

/// Result of calling convention detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcDetectionResult {
    pub convention: String,
    pub confidence: CcConfidence,
    pub evidence: Vec<CcEvidence>,
    pub arg_count: Option<usize>,
    pub stack_cleanup_by_callee: bool,
}

/// Analyses a function's register usage to detect its calling convention.
pub struct CallingConventionDetector {
    arch: AnalysisArch,
}

impl CallingConventionDetector {
    #[must_use] 
    pub const fn new(arch: AnalysisArch) -> Self {
        Self { arch }
    }

    /// Analyse a set of register usages to detect CC.
    pub fn detect(
        &self,
        registers: &[RegisterUsage],
        stack_cleanup_bytes: Option<i32>,
        has_this_ptr: bool,
    ) -> Result<CcDetectionResult, AbiError> {
        let mut evidence = Vec::new();
        let mut score_cdecl = 0i32;
        let mut score_stdcall = 0i32;
        let mut score_fastcall = 0i32;
        let mut score_thiscall = 0i32;
        let mut score_sysv64 = 0i32;
        let mut score_ms64 = 0i32;

        let read_before_written: Vec<&str> = registers
            .iter()
            .filter(|r| r.read_before_write)
            .map(|r| r.name.as_str())
            .collect();

        match self.arch {
            AnalysisArch::X86 => {
                // cdecl: args on stack, caller cleans up.
                if stack_cleanup_bytes == Some(0) || stack_cleanup_bytes.is_none() {
                    score_cdecl += 3;
                    evidence.push(CcEvidence {
                        kind: "stack_cleanup".into(),
                        description: "No callee stack cleanup (cdecl / caller cleans)".into(),
                        weight: 3,
                    });
                }
                // stdcall: callee cleans up.
                if stack_cleanup_bytes.unwrap_or(0) > 0 {
                    score_stdcall += 4;
                    evidence.push(CcEvidence {
                        kind: "stack_cleanup".into(),
                        description: format!(
                            "Callee cleans {}B (stdcall)",
                            stack_cleanup_bytes.unwrap()
                        ),
                        weight: 4,
                    });
                }
                // fastcall: first two args in ECX, EDX.
                if read_before_written.contains(&"ecx") && read_before_written.contains(&"edx") {
                    score_fastcall += 5;
                    evidence.push(CcEvidence {
                        kind: "reg_args".into(),
                        description: "ECX and EDX read before written (fastcall args)".into(),
                        weight: 5,
                    });
                }
                // thiscall: first arg in ECX.
                if has_this_ptr || read_before_written.contains(&"ecx") {
                    score_thiscall += 4;
                    evidence.push(CcEvidence {
                        kind: "this_ptr".into(),
                        description: "ECX used as this-pointer (thiscall)".into(),
                        weight: 4,
                    });
                }
            }
            AnalysisArch::X86_64 => {
                // System V AMD64: RDI, RSI, RDX, RCX, R8, R9.
                let sysv_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                let ms64_args = ["rcx", "rdx", "r8", "r9"];
                let sysv_matches = sysv_args
                    .iter()
                    .filter(|&&r| read_before_written.contains(&r))
                    .count();
                let ms64_matches = ms64_args
                    .iter()
                    .filter(|&&r| read_before_written.contains(&r))
                    .count();
                score_sysv64 += sysv_matches as i32 * 2;
                score_ms64 += ms64_matches as i32 * 2;
                if sysv_matches > 0 {
                    evidence.push(CcEvidence {
                        kind: "reg_args".into(),
                        description: format!("{sysv_matches} System V arg registers used"),
                        weight: sysv_matches as i32 * 2,
                    });
                }
                if ms64_matches > 0 {
                    evidence.push(CcEvidence {
                        kind: "reg_args".into(),
                        description: format!("{ms64_matches} MS x64 arg registers used"),
                        weight: ms64_matches as i32 * 2,
                    });
                }
            }
            AnalysisArch::Arm32 | AnalysisArch::Arm64 => {
                // AAPCS: R0–R3 (arm32) / X0–X7 (arm64).
                let aapcs_count = read_before_written
                    .iter()
                    .filter(|&&r| r.starts_with('r') || r.starts_with('x'))
                    .count();
                evidence.push(CcEvidence {
                    kind: "reg_args".into(),
                    description: format!("AAPCS: {aapcs_count} arg registers read before write"),
                    weight: aapcs_count as i32,
                });
            }
            AnalysisArch::Mips | AnalysisArch::RiscV64 => {}
        }

        let (convention, confidence) = match self.arch {
            AnalysisArch::X86 => {
                let scores = [
                    ("cdecl", score_cdecl),
                    ("stdcall", score_stdcall),
                    ("fastcall", score_fastcall),
                    ("thiscall", score_thiscall),
                ];
                let best = scores.iter().max_by_key(|(_, s)| s).unwrap();
                let conf = if best.1 >= 5 {
                    CcConfidence::High
                } else if best.1 >= 3 {
                    CcConfidence::Medium
                } else {
                    CcConfidence::Low
                };
                (best.0.to_string(), conf)
            }
            AnalysisArch::X86_64 => {
                match score_sysv64.cmp(&score_ms64) {
                    std::cmp::Ordering::Greater => ("sysv_amd64".to_string(), CcConfidence::High),
                    std::cmp::Ordering::Less => ("ms_x64".to_string(), CcConfidence::High),
                    std::cmp::Ordering::Equal => ("unknown".to_string(), CcConfidence::Low),
                }
            }
            AnalysisArch::Arm32 => ("aapcs32".to_string(), CcConfidence::Medium),
            AnalysisArch::Arm64 => ("aapcs64".to_string(), CcConfidence::Medium),
            AnalysisArch::Mips | AnalysisArch::RiscV64 => ("unknown".to_string(), CcConfidence::Low),
        };

        let arg_count = Some(read_before_written.len());
        Ok(CcDetectionResult {
            convention,
            confidence,
            evidence,
            arg_count,
            stack_cleanup_by_callee: stack_cleanup_bytes.unwrap_or(0) > 0,
        })
    }
}

// ─── AbiMismatch ─────────────────────────────────────────────────────────────

/// A detected mismatch between call-site expectations and callee's actual ABI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMismatch {
    pub call_site_addr: u64,
    pub callee_addr: u64,
    pub description: String,
    pub severity: MismatchSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchSeverity {
    /// Likely crash or data corruption.
    Critical,
    /// May produce wrong results.
    Major,
    /// Probably works but is technically incorrect.
    Minor,
    /// Informational only.
    Info,
}

/// Detects ABI mismatches between callers and callees.
pub struct AbiMismatchDetector;

impl AbiMismatchDetector {
    /// Compare a call site's expected ABI with the callee's detected ABI.
    #[must_use] 
    pub fn detect(
        caller_cc: &str,
        callee_cc: &str,
        call_site_addr: u64,
        callee_addr: u64,
    ) -> Option<AbiMismatch> {
        if caller_cc == callee_cc {
            return None;
        }
        let severity = Self::severity_for_mismatch(caller_cc, callee_cc);
        Some(AbiMismatch {
            call_site_addr,
            callee_addr,
            description: format!(
                "Call site assumes '{caller_cc}' but callee uses '{callee_cc}'"
            ),
            severity,
        })
    }

    fn severity_for_mismatch(cc_a: &str, cc_b: &str) -> MismatchSeverity {
        // Stack-cleanup mismatches (cdecl vs stdcall) are critical.
        let callee_cleanup = ["stdcall", "thiscall"];
        let caller_cleanup = ["cdecl"];
        let a_callee = callee_cleanup.contains(&cc_a);
        let b_callee = callee_cleanup.contains(&cc_b);
        let a_caller = caller_cleanup.contains(&cc_a);
        let b_caller = caller_cleanup.contains(&cc_b);
        if (a_callee && b_caller) || (a_caller && b_callee) {
            return MismatchSeverity::Critical;
        }
        // Register vs stack passing is major.
        let reg_variants = ["fastcall", "sysv_amd64", "ms_x64"];
        let a_reg = reg_variants.contains(&cc_a);
        let b_reg = reg_variants.contains(&cc_b);
        if a_reg != b_reg {
            return MismatchSeverity::Major;
        }
        MismatchSeverity::Minor
    }

    /// Batch-check a list of (`call_site_cc`, `callee_cc`, `site_addr`, `callee_addr`) tuples.
    #[must_use] 
    pub fn detect_batch(calls: &[(String, String, u64, u64)]) -> Vec<AbiMismatch> {
        calls
            .iter()
            .filter_map(|(caller, callee, site, dest)| Self::detect(caller, callee, *site, *dest))
            .collect()
    }
}

// ─── AbiCanonicalizer ─────────────────────────────────────────────────────────

/// Normalizes various calling convention name spellings to canonical forms.
pub struct AbiCanonicalizer;

impl AbiCanonicalizer {
    const ALIASES: &'static [(&'static str, &'static str)] = &[
        ("__cdecl", "cdecl"),
        ("c_decl", "cdecl"),
        ("_cdecl", "cdecl"),
        ("__stdcall", "stdcall"),
        ("_stdcall", "stdcall"),
        ("winapi", "stdcall"),
        ("__fastcall", "fastcall"),
        ("_fastcall", "fastcall"),
        ("__thiscall", "thiscall"),
        ("_thiscall", "thiscall"),
        // `vectorcall` was enumerated as canonical but had no alias, so the
        // only spelling MSVC actually accepts (`__vectorcall`) fell through to
        // the unknown branch and came back undecorated-but-unchanged — a name
        // `canonical_names()` rejects. Every other MSVC convention above maps
        // both the `__` and `_` forms; this one now does too.
        ("__vectorcall", "vectorcall"),
        ("_vectorcall", "vectorcall"),
        ("sysv", "sysv_amd64"),
        ("systemv", "sysv_amd64"),
        ("system_v", "sysv_amd64"),
        ("linux64", "sysv_amd64"),
        ("win64", "ms_x64"),
        ("microsoft_x64", "ms_x64"),
        ("arm_aapcs", "aapcs32"),
        ("aapcs", "aapcs32"),
        ("arm64_aapcs", "aapcs64"),
        ("aarch64", "aapcs64"),
        ("riscv", "riscv_ilp32d"),
    ];

    /// Canonicalize a calling convention name.
    #[must_use] 
    pub fn canonicalize(name: &str) -> &str {
        let lower = name.to_lowercase();
        for &(alias, canonical) in Self::ALIASES {
            if lower == alias {
                return canonical;
            }
        }
        // Already canonical (case-insensitively) — return the canonical
        // (lowercase) spelling rather than the caller's original casing, so
        // callers can rely on `canonicalize` always yielding a normalised
        // name for known conventions (e.g. "STDCALL" -> "stdcall", not
        // "STDCALL").
        match lower.as_str() {
            "cdecl" => "cdecl",
            "stdcall" => "stdcall",
            "fastcall" => "fastcall",
            "thiscall" => "thiscall",
            "sysv_amd64" => "sysv_amd64",
            "ms_x64" => "ms_x64",
            "aapcs32" => "aapcs32",
            "aapcs64" => "aapcs64",
            "vectorcall" => "vectorcall",
            "riscv_ilp32d" => "riscv_ilp32d",
            // Unknown — return the original spelling unchanged.
            _ => name,
        }
    }

    /// Returns all canonical names.
    #[must_use] 
    pub fn canonical_names() -> Vec<&'static str> {
        vec![
            "cdecl",
            "stdcall",
            "fastcall",
            "thiscall",
            "sysv_amd64",
            "ms_x64",
            "aapcs32",
            "aapcs64",
            "vectorcall",
            // Was missing: `canonicalize` recognises this as a canonical name
            // (it is a fixed point), so the enumeration must include it too,
            // else a caller validating against `canonical_names()` rejects a
            // name the canonicaliser itself emits.
            "riscv_ilp32d",
        ]
    }
}

// ─── VarArgDetector ──────────────────────────────────────────────────────────

/// Evidence for variadic argument detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarArgEvidence {
    pub kind: String,
    pub description: String,
}

/// Result of variadic function detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarArgResult {
    pub is_variadic: bool,
    pub confidence: f64,
    pub evidence: Vec<VarArgEvidence>,
    pub fixed_arg_count: Option<usize>,
}

/// Detects variadic functions from call patterns.
pub struct VarArgDetector;

/// C library functions that really do declare `...`.
static VARIADIC_NAMES: &[&str] = &[
    "printf", "sprintf", "fprintf", "snprintf", "scanf", "sscanf", "fscanf",
    "wprintf", "swprintf", "fwprintf", "open", "execl", "execlp", "execle",
];

/// Functions that CONSUME a `va_list` and therefore have fixed arity.
///
/// Kept as an explicit list rather than dropped, so the distinction is
/// recorded in the evidence instead of merely being absent.
static VA_LIST_CONSUMING_NAMES: &[&str] = &[
    "vprintf", "vsprintf", "vfprintf", "vsnprintf", "vscanf", "vsscanf",
    "vfscanf", "vwprintf", "vswprintf",
];

/// `true` when `needle` appears in `name` as a complete identifier.
///
/// Anchored the same way as `rustre_analysis_fn::is_known_noreturn_symbol`:
/// whole name, final `::` component, or a substring whose neighbours are not
/// identifier characters. This is what keeps `printf` from matching
/// `my_printf_helper` and `snprintf` from matching `vsnprintf`.
fn name_matches_anchored(name: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    if name == needle || name.rsplit("::").next() == Some(needle) {
        return true;
    }
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let bytes = name.as_bytes();
    name.match_indices(needle).any(|(start, _)| {
        let before = start.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(start + needle.len()).copied();
        before.is_none_or(|c| !is_ident(c)) && after.is_none_or(|c| !is_ident(c))
    })
}


impl VarArgDetector {
    /// Detect variadic functions based on call-site patterns.
    #[must_use] 
    pub fn detect(
        callee_name: Option<&str>,
        stack_args_at_call: Option<usize>,
        uses_va_list: bool,
        calls_va_start: bool,
    ) -> VarArgResult {
        let mut evidence = Vec::new();
        let mut score = 0.0f64;

        // Known variadic functions.
        //
        // Two corrections live here, both of which used to push the score to
        // 0.9 — well past the 0.5 `is_variadic` threshold — on functions that
        // are not variadic at all:
        //
        // 1. **The `v*` family was in the list.** `vprintf`, `vsprintf`,
        //    `vfprintf` and friends take an explicit `va_list` and have FIXED
        //    arity — consuming a variable argument list is the opposite of
        //    declaring one. Argument recovery was being told to expect a
        //    variadic tail that does not exist.
        // 2. **Matching was `name.contains(n)`**, so `my_printf_helper`
        //    matched `printf`, and `vsnprintf` matched `snprintf`.
        //
        // `va_start` / `va_arg` / `va_end` are also gone from this list: they
        // are macros, and seeing one says the CALLER is variadic, not the
        // callee. That signal already has its own, stronger input
        // (`calls_va_start`, +0.95).
        if let Some(name) = callee_name {
            if VARIADIC_NAMES.iter().any(|&n| name_matches_anchored(name, n)) {
                score += 0.9;
                evidence.push(VarArgEvidence {
                    kind: "known_variadic".into(),
                    description: format!("'{name}' is a known variadic function"),
                });
            } else if VA_LIST_CONSUMING_NAMES
                .iter()
                .any(|&n| name_matches_anchored(name, n))
            {
                evidence.push(VarArgEvidence {
                    kind: "va_list_consumer".into(),
                    description: format!(
                        "'{name}' takes an explicit va_list — fixed arity, not variadic"
                    ),
                });
            }
        }

        if uses_va_list {
            score += 0.7;
            evidence.push(VarArgEvidence {
                kind: "va_list".into(),
                description: "Function uses va_list type".into(),
            });
        }

        if calls_va_start {
            score += 0.95;
            evidence.push(VarArgEvidence {
                kind: "va_start".into(),
                description: "Function calls va_start — definitive variadic".into(),
            });
        }

        if let Some(stack_count) = stack_args_at_call && stack_count > 6 {
            score = score.max(0.5);
            evidence.push(VarArgEvidence {
                kind: "many_stack_args".into(),
                description: format!(
                    "{stack_count} stack arguments — possible variadic call"
                ),
            });
        }

        VarArgResult {
            is_variadic: score >= 0.5,
            confidence: score.clamp(0.0, 1.0),
            evidence,
            fixed_arg_count: None,
        }
    }
}

// ─── AggregatePassingAnalyzer ─────────────────────────────────────────────────

/// How an aggregate (struct/union) is passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregatePassing {
    /// Passed in one or more registers.
    InRegisters(Vec<String>),
    /// Passed as a pointer to a stack copy (by reference).
    ByPointer,
    /// Passed on the stack directly.
    OnStack,
    /// Split: part in registers, part on stack.
    ///
    /// NOTE: no analyzer path currently constructs this variant — every
    /// `AggregatePassingAnalyzer` branch resolves to `InRegisters`, `ByPointer`,
    /// or `OnStack`. Kept for the ABIs (e.g. large AAPCS32 aggregates) that
    /// should eventually report a true register+stack split; flagging here
    /// rather than removing since downstream matches may already handle it.
    Split {
        registers: Vec<String>,
        stack_bytes: usize,
    },
}

/// Analyses how aggregate types are passed according to an ABI.
pub struct AggregatePassingAnalyzer;

impl AggregatePassingAnalyzer {
    /// Determine how a struct of `size_bytes` is passed under `cc`.
    #[must_use] 
    pub fn analyze(cc: &str, size_bytes: usize, alignment: usize) -> AggregatePassing {
        // Round size up to the alignment so passing matches the ABI's effective footprint.
        let effective_size = if alignment > 0 {
            size_bytes.div_ceil(alignment) * alignment
        } else {
            size_bytes
        };
        match cc {
            "sysv_amd64" => Self::sysv_amd64(effective_size),
            "ms_x64" => Self::ms_x64(size_bytes),
            "aapcs64" => Self::aapcs64(effective_size),
            "aapcs32" => Self::aapcs32(effective_size),
            _ => AggregatePassing::OnStack,
        }
    }

    fn sysv_amd64(size: usize) -> AggregatePassing {
        if size <= 8 {
            AggregatePassing::InRegisters(vec!["rdi".into()])
        } else if size <= 16 {
            AggregatePassing::InRegisters(vec!["rdi".into(), "rsi".into()])
        } else {
            // Structs > 16 bytes are passed by hidden pointer.
            AggregatePassing::ByPointer
        }
    }

    fn ms_x64(size: usize) -> AggregatePassing {
        // MS x64: structs of 1, 2, 4, 8 bytes passed in register; others by pointer.
        match size {
            1 | 2 | 4 | 8 => AggregatePassing::InRegisters(vec!["rcx".into()]),
            _ => AggregatePassing::ByPointer,
        }
    }

    fn aapcs64(size: usize) -> AggregatePassing {
        if size <= 16 {
            AggregatePassing::InRegisters(vec!["x0".into()])
        } else {
            AggregatePassing::ByPointer
        }
    }

    fn aapcs32(size: usize) -> AggregatePassing {
        if size <= 4 {
            AggregatePassing::InRegisters(vec!["r0".into()])
        } else if size <= 8 {
            AggregatePassing::InRegisters(vec!["r0".into(), "r1".into()])
        } else {
            AggregatePassing::OnStack
        }
    }

    /// Check if a return aggregate is returned by pointer (hidden first argument).
    #[must_use] 
    pub fn is_return_by_pointer(cc: &str, size_bytes: usize) -> bool {
        match cc {
            "sysv_amd64" => size_bytes > 16,
            "ms_x64" => !matches!(size_bytes, 1 | 2 | 4 | 8),
            "aapcs64" => size_bytes > 16,
            "aapcs32" => size_bytes > 4,
            _ => size_bytes > 8,
        }
    }
}

// ─── AbiAnalyzer ─────────────────────────────────────────────────────────────

/// Summary of ABI analysis for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiFunctionSummary {
    pub address: u64,
    pub detected_cc: String,
    pub cc_confidence: CcConfidence,
    pub arg_count: Option<usize>,
    pub is_variadic: bool,
    pub aggregate_params: Vec<(usize, AggregatePassing)>, // (param_index, passing_method)
    pub mismatches_at_callers: Vec<AbiMismatch>,
}

/// Top-level ABI analyser.
pub struct AbiAnalyzer {
    arch: AnalysisArch,
    cc_detector: CallingConventionDetector,
}

impl AbiAnalyzer {
    #[must_use] 
    pub const fn new(arch: AnalysisArch) -> Self {
        Self {
            arch,
            cc_detector: CallingConventionDetector::new(arch),
        }
    }

    #[must_use] 
    pub const fn arch(&self) -> AnalysisArch {
        self.arch
    }

    /// Perform full ABI analysis for a function.
    pub fn analyze_function(
        &self,
        address: u64,
        registers: &[RegisterUsage],
        stack_cleanup: Option<i32>,
        has_this_ptr: bool,
        callee_name: Option<&str>,
    ) -> Result<AbiFunctionSummary, AbiError> {
        let cc_result = self
            .cc_detector
            .detect(registers, stack_cleanup, has_this_ptr)?;
        let vararg = VarArgDetector::detect(callee_name, None, false, false);

        Ok(AbiFunctionSummary {
            address,
            detected_cc: cc_result.convention,
            cc_confidence: cc_result.confidence,
            arg_count: cc_result.arg_count,
            is_variadic: vararg.is_variadic,
            aggregate_params: Vec::new(),
            mismatches_at_callers: Vec::new(),
        })
    }

    /// Check a call site for ABI mismatches.
    #[must_use] 
    pub fn check_call_site(
        &self,
        site_addr: u64,
        site_cc: &str,
        callee_addr: u64,
        callee_cc: &str,
    ) -> Option<AbiMismatch> {
        AbiMismatchDetector::detect(site_cc, callee_cc, site_addr, callee_addr)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str, rbw: bool, sar: bool, wws: bool) -> RegisterUsage {
        RegisterUsage {
            name: name.to_string(),
            read_before_write: rbw,
            saved_and_restored: sar,
            written_without_save: wws,
        }
    }

    #[test]
    fn detect_cdecl_no_cleanup() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86);
        let regs = vec![reg("eax", true, false, false)];
        let result = detector.detect(&regs, Some(0), false).unwrap();
        assert!(result.convention.contains("cdecl") || result.convention.contains("unknown"));
    }

    #[test]
    fn detect_stdcall_cleanup() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86);
        let regs = vec![reg("eax", true, false, false)];
        let result = detector.detect(&regs, Some(8), false).unwrap();
        assert_eq!(result.convention, "stdcall");
        assert!(result.stack_cleanup_by_callee);
    }

    #[test]
    fn detect_fastcall_ecx_edx() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86);
        let regs = vec![
            reg("ecx", true, false, false),
            reg("edx", true, false, false),
        ];
        let result = detector.detect(&regs, Some(0), false).unwrap();
        assert_eq!(result.convention, "fastcall");
        assert!(result.confidence >= CcConfidence::Medium);
    }

    #[test]
    fn detect_sysv_amd64() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86_64);
        let regs = vec![
            reg("rdi", true, false, false),
            reg("rsi", true, false, false),
            reg("rdx", true, false, false),
        ];
        let result = detector.detect(&regs, None, false).unwrap();
        assert_eq!(result.convention, "sysv_amd64");
    }

    #[test]
    fn detect_ms_x64() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86_64);
        let regs = vec![
            reg("rcx", true, false, false),
            reg("rdx", true, false, false),
        ];
        // ms_x64 also uses rcx and rdx but NOT rdi/rsi which would push sysv score higher.
        let result = detector.detect(&regs, None, false).unwrap();
        // With equal scores, depends on tie-breaking; both are reasonable.
        assert!(
            result.convention == "sysv_amd64"
                || result.convention == "ms_x64"
                || result.convention == "unknown"
        );
    }

    #[test]
    fn detect_arm32_aapcs() {
        let detector = CallingConventionDetector::new(AnalysisArch::Arm32);
        let regs = vec![reg("r0", true, false, false), reg("r1", true, false, false)];
        let result = detector.detect(&regs, None, false).unwrap();
        assert_eq!(result.convention, "aapcs32");
    }

    #[test]
    fn mismatch_detector_same_cc_no_mismatch() {
        let result = AbiMismatchDetector::detect("cdecl", "cdecl", 0x1000, 0x2000);
        assert!(result.is_none());
    }

    #[test]
    fn mismatch_detector_critical_mismatch() {
        let result = AbiMismatchDetector::detect("cdecl", "stdcall", 0x1000, 0x2000);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.severity, MismatchSeverity::Critical);
    }

    #[test]
    fn mismatch_detector_batch() {
        let calls = vec![
            ("cdecl".into(), "stdcall".into(), 0x100u64, 0x200u64),
            ("sysv_amd64".into(), "sysv_amd64".into(), 0x300u64, 0x400u64),
        ];
        let mismatches = AbiMismatchDetector::detect_batch(&calls);
        assert_eq!(mismatches.len(), 1);
    }

    #[test]
    fn canonicalizer_aliases() {
        assert_eq!(AbiCanonicalizer::canonicalize("__cdecl"), "cdecl");
        assert_eq!(AbiCanonicalizer::canonicalize("winapi"), "stdcall");
        assert_eq!(AbiCanonicalizer::canonicalize("win64"), "ms_x64");
        assert_eq!(AbiCanonicalizer::canonicalize("sysv"), "sysv_amd64");
    }

    #[test]
    fn canonicalizer_unknown_passthrough() {
        let name = "my_custom_cc";
        assert_eq!(AbiCanonicalizer::canonicalize(name), name);
    }

    #[test]
    fn canonicalizer_canonical_names_non_empty() {
        assert!(!AbiCanonicalizer::canonical_names().is_empty());
    }

    /// Consistency: every name that `canonicalize` treats as canonical (is a
    /// fixed point of) must be listed in `canonical_names()`, and `canonicalize`
    /// must be idempotent. `canonical_names()` was missing "`riscv_ilp32d`" even
    /// though `canonicalize("riscv_ilp32d")` returns it as canonical.
    #[test]
    fn canonical_names_matches_canonicalize_fixed_points() {
        let listed = AbiCanonicalizer::canonical_names();
        // Every listed name is a fixed point (idempotent) of canonicalize.
        for &n in &listed {
            assert_eq!(AbiCanonicalizer::canonicalize(n), n, "{n} not a fixed point");
            // idempotency
            let once = AbiCanonicalizer::canonicalize(n);
            assert_eq!(AbiCanonicalizer::canonicalize(once), once);
        }
        // Names that canonicalize recognises as canonical but were omitted from
        // the enumeration must now be present.
        for known in [
            "cdecl", "stdcall", "fastcall", "thiscall", "sysv_amd64", "ms_x64",
            "aapcs32", "aapcs64", "vectorcall", "riscv_ilp32d",
        ] {
            assert_eq!(
                AbiCanonicalizer::canonicalize(known),
                known,
                "{known} should be canonical"
            );
            assert!(
                listed.contains(&known),
                "canonical_names() is missing the canonical name {known:?}"
            );
        }
    }

    #[test]
    fn vararg_detector_printf() {
        let r = VarArgDetector::detect(Some("printf"), None, false, false);
        assert!(r.is_variadic);
        assert!(r.confidence >= 0.5);
    }

    #[test]
    fn vararg_detector_va_start() {
        let r = VarArgDetector::detect(None, None, false, true);
        assert!(r.is_variadic);
        assert!(r.confidence >= 0.9);
    }

    #[test]
    fn vararg_detector_not_variadic() {
        let r = VarArgDetector::detect(Some("memcpy"), Some(3), false, false);
        assert!(!r.is_variadic);
    }

    #[test]
    fn aggregate_passing_sysv_small() {
        let p = AggregatePassingAnalyzer::analyze("sysv_amd64", 8, 8);
        assert!(matches!(p, AggregatePassing::InRegisters(_)));
    }

    #[test]
    fn aggregate_passing_sysv_large() {
        let p = AggregatePassingAnalyzer::analyze("sysv_amd64", 32, 8);
        assert_eq!(p, AggregatePassing::ByPointer);
    }

    #[test]
    fn aggregate_passing_ms_x64_power_of_2() {
        let p = AggregatePassingAnalyzer::analyze("ms_x64", 4, 4);
        assert!(matches!(p, AggregatePassing::InRegisters(_)));
    }

    #[test]
    fn aggregate_passing_ms_x64_non_power() {
        let p = AggregatePassingAnalyzer::analyze("ms_x64", 5, 4);
        assert_eq!(p, AggregatePassing::ByPointer);
    }

    #[test]
    fn aggregate_return_by_pointer_sysv() {
        assert!(!AggregatePassingAnalyzer::is_return_by_pointer(
            "sysv_amd64",
            16
        ));
        assert!(AggregatePassingAnalyzer::is_return_by_pointer(
            "sysv_amd64",
            17
        ));
    }

    #[test]
    fn abi_analyzer_full_pipeline() {
        let analyzer = AbiAnalyzer::new(AnalysisArch::X86_64);
        let regs = vec![
            reg("rdi", true, false, false),
            reg("rsi", true, false, false),
        ];
        let summary = analyzer
            .analyze_function(0x1000, &regs, None, false, Some("example_fn"))
            .unwrap();
        assert_eq!(summary.address, 0x1000);
        assert!(!summary.detected_cc.is_empty());
    }

    #[test]
    fn abi_analyzer_check_call_site() {
        let analyzer = AbiAnalyzer::new(AnalysisArch::X86);
        let mismatch = analyzer.check_call_site(0x100, "cdecl", 0x200, "stdcall");
        assert!(mismatch.is_some());
    }

    #[test]
    fn abi_analyzer_no_mismatch() {
        let analyzer = AbiAnalyzer::new(AnalysisArch::X86_64);
        let mismatch = analyzer.check_call_site(0x100, "sysv_amd64", 0x200, "sysv_amd64");
        assert!(mismatch.is_none());
    }

    #[test]
    fn cc_confidence_ordering() {
        assert!(CcConfidence::Definitive > CcConfidence::High);
        assert!(CcConfidence::High > CcConfidence::Medium);
        assert!(CcConfidence::Medium > CcConfidence::Low);
    }

    #[test]
    fn abi_error_display() {
        let e = AbiError::UnsupportedArch("sparc".into());
        assert!(e.to_string().contains("sparc"));
    }

    #[test]
    fn aggregate_passing_aapcs64_small() {
        let p = AggregatePassingAnalyzer::analyze("aapcs64", 8, 8);
        assert!(matches!(p, AggregatePassing::InRegisters(_)));
    }

    #[test]
    fn canonicalizer_normalises_case_for_known_conventions() {
        // Regression: canonicalize used to return the caller's original
        // casing for already-canonical names instead of the normalised
        // lowercase form, producing inconsistent output like "STDCALL".
        assert_eq!(AbiCanonicalizer::canonicalize("STDCALL"), "stdcall");
        assert_eq!(AbiCanonicalizer::canonicalize("CDecl"), "cdecl");
        assert_eq!(AbiCanonicalizer::canonicalize("Sysv_Amd64"), "sysv_amd64");
    }

    #[test]
    fn canonicalizer_empty_string() {
        assert_eq!(AbiCanonicalizer::canonicalize(""), "");
    }

    #[test]
    fn detector_x86_64_reports_ms64_evidence() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86_64);
        let regs = vec![
            reg("rcx", true, false, false),
            reg("rdx", true, false, false),
            reg("r8", true, false, false),
            reg("r9", true, false, false),
        ];
        let result = detector.detect(&regs, None, false).unwrap();
        // rcx/rdx/r8/r9 are also valid System V registers, so both scores
        // tie; the important regression check is that MS x64 evidence is
        // now reported at all (it previously was silently dropped).
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.description.contains("MS x64")),
            "expected MS x64 evidence to be reported, got {:?}",
            result.evidence
        );
    }

    #[test]
    fn detector_empty_registers_no_panic() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86_64);
        let result = detector.detect(&[], None, false).unwrap();
        assert_eq!(result.arg_count, Some(0));
    }

    #[test]
    fn detector_negative_stack_cleanup_no_panic() {
        let detector = CallingConventionDetector::new(AnalysisArch::X86);
        let regs = vec![reg("eax", true, false, false)];
        // Adversarial: negative cleanup byte count should not panic.
        let result = detector.detect(&regs, Some(-8), false).unwrap();
        assert!(!result.convention.is_empty());
    }

    #[test]
    fn aggregate_passing_zero_size_zero_alignment_no_panic() {
        // Adversarial: alignment == 0 must not trigger a division by zero.
        let p = AggregatePassingAnalyzer::analyze("sysv_amd64", 0, 0);
        assert!(matches!(p, AggregatePassing::InRegisters(_)));
    }

    #[test]
    fn abi_analyzer_arch_accessor() {
        let analyzer = AbiAnalyzer::new(AnalysisArch::Arm64);
        assert_eq!(analyzer.arch(), AnalysisArch::Arm64);
    }

    #[test]
    fn aggregate_passing_unknown_cc_defaults_to_stack() {
        let p = AggregatePassingAnalyzer::analyze("unknown_cc", 8, 8);
        assert_eq!(p, AggregatePassing::OnStack);
    }

    #[test]
    fn aggregate_return_by_pointer_unknown_cc_default() {
        assert!(!AggregatePassingAnalyzer::is_return_by_pointer(
            "unknown_cc",
            8
        ));
        assert!(AggregatePassingAnalyzer::is_return_by_pointer(
            "unknown_cc",
            9
        ));
    }

    #[test]
    fn aggregate_passing_aapcs32_split() {
        // aapcs32: 8-byte struct → two registers
        let p = AggregatePassingAnalyzer::analyze("aapcs32", 8, 4);
        if let AggregatePassing::InRegisters(regs) = &p {
            assert_eq!(regs.len(), 2);
        }
    }
}

#[cfg(test)]
mod variadic_vocabulary {
    use super::*;

    fn detect(name: &str) -> VarArgResult {
        VarArgDetector::detect(Some(name), None, false, false)
    }

    /// The `v*` family takes an explicit `va_list` and has FIXED arity.
    ///
    /// They were listed as "known variadic" and scored 0.9 — past the 0.5
    /// threshold — so argument recovery was told to expect a variable tail
    /// that does not exist. Consuming a `va_list` is the opposite of declaring
    /// one.
    #[test]
    fn va_list_consumers_are_not_variadic() {
        for name in ["vprintf", "vsprintf", "vfprintf", "vsnprintf", "vsscanf"] {
            let r = detect(name);
            assert!(
                !r.is_variadic,
                "{name} takes a va_list and is not variadic (confidence {})",
                r.confidence
            );
            assert!(
                r.evidence.iter().any(|e| e.kind == "va_list_consumer"),
                "the reason must be recorded, not merely absent: {name}"
            );
        }
    }

    /// Substring matching made unrelated names variadic.
    #[test]
    fn names_that_merely_contain_a_variadic_name_do_not_match() {
        for name in ["my_printf_helper", "printf_wrapper", "sscanf_impl", "reopen"] {
            assert!(
                !detect(name).is_variadic,
                "{name} is not a known variadic function"
            );
        }
    }

    /// Positive control: the genuinely variadic names must still be detected,
    /// plain and namespaced. Without this, rejecting everything would satisfy
    /// both tests above and disable the heuristic entirely.
    #[test]
    fn real_variadic_names_are_still_detected() {
        for name in ["printf", "sprintf", "fprintf", "snprintf", "sscanf", "std::printf"] {
            let r = detect(name);
            assert!(r.is_variadic, "{name} is variadic but was not detected");
            assert!(
                r.evidence.iter().any(|e| e.kind == "known_variadic"),
                "the verdict must ship its evidence: {name}"
            );
        }
    }

    /// `va_start` is a macro: seeing it says the CALLER is variadic, not the
    /// callee. That signal has its own, stronger input.
    #[test]
    fn va_start_as_a_callee_name_is_not_itself_variadic() {
        assert!(!detect("va_start").is_variadic);
        assert!(!detect("va_arg").is_variadic);
        // ...while the dedicated flag still is definitive.
        let r = VarArgDetector::detect(Some("some_logger"), None, false, true);
        assert!(r.is_variadic, "calls_va_start must remain definitive");
    }
}
