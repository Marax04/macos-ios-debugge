//! Obfuscation technique classifier: detects control flow flattening, opaque predicates,
//! junk code, instruction substitution, constant encoding, string encryption, API hashing.
//! Scores each technique with confidence and suggests deobfuscation passes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Confidence ───────────────────────────────────────────────────────────────

/// A confidence score in the range [0.0, 1.0].
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    /// Create a confidence value, clamped to [0.0, 1.0].
    ///
    /// A NaN input yields 0.0: `f64::clamp` propagates NaN rather than
    /// sanitising it, so clamping alone would let a NaN into a type whose
    /// documented range is [0.0, 1.0] — and a NaN confidence silently loses
    /// every comparison it takes part in.
    #[must_use]
    pub const fn new(v: f64) -> Self {
        if v.is_nan() {
            return Self(0.0);
        }
        Self(v.clamp(0.0, 1.0))
    }

    /// Return the inner value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }

    /// Return `true` if the confidence is "high" (≥ 0.7).
    #[must_use]
    pub fn is_high(self) -> bool {
        self.0 >= 0.7
    }

    /// Return `true` if the confidence is "medium" (≥ 0.4).
    #[must_use]
    pub fn is_medium(self) -> bool {
        self.0 >= 0.4
    }

    /// Return `true` if the confidence is "low" (< 0.4).
    #[must_use]
    pub fn is_low(self) -> bool {
        self.0 < 0.4
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}%", self.0 * 100.0)
    }
}

impl From<f64> for Confidence {
    fn from(v: f64) -> Self {
        Self::new(v)
    }
}

// ─── DeobfPass ────────────────────────────────────────────────────────────────

/// A suggested deobfuscation pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeobfPass {
    /// Control-flow flattening removal (state machine reconstruction).
    RemoveCflFlattening,
    /// Opaque predicate elimination via symbolic execution.
    EliminateOpaquePredicates,
    /// Junk code removal (dead instruction pruning).
    RemoveJunkCode,
    /// Instruction substitution normalisation (simplify MBA).
    NormalizeInstructionSubstitution,
    /// Constant folding and encoding reversal.
    FoldConstants,
    /// String decryption via emulation.
    DecryptStrings,
    /// API hash resolution (build hash→name table).
    ResolveApiHashes,
    /// Virtualization lifting (recover native IR from VM bytecode).
    LiftVirtualization,
    /// Anti-analysis trick neutralisation (patch anti-debug, anti-VM).
    NeutralizeAntiAnalysis,
    /// Packer unpacking.
    UnpackPacker,
    /// Generic dead-code elimination.
    EliminateDeadCode,
    /// Custom pass with a description.
    Custom(String),
}

impl std::fmt::Display for DeobfPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RemoveCflFlattening => "RemoveCflFlattening",
            Self::EliminateOpaquePredicates => "EliminateOpaquePredicates",
            Self::RemoveJunkCode => "RemoveJunkCode",
            Self::NormalizeInstructionSubstitution => "NormalizeInstructionSubstitution",
            Self::FoldConstants => "FoldConstants",
            Self::DecryptStrings => "DecryptStrings",
            Self::ResolveApiHashes => "ResolveApiHashes",
            Self::LiftVirtualization => "LiftVirtualization",
            Self::NeutralizeAntiAnalysis => "NeutralizeAntiAnalysis",
            Self::UnpackPacker => "UnpackPacker",
            Self::EliminateDeadCode => "EliminateDeadCode",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// ─── ObfuscationTechnique ─────────────────────────────────────────────────────

/// An obfuscation technique identified in a binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationTechnique {
    /// Control flow flattening (state-machine dispatcher).
    ControlFlowFlattening,
    /// Opaque predicates (always-taken/never-taken branches).
    OpaquePredicates,
    /// Junk code insertion (dead instructions).
    JunkCodeInsertion,
    /// Instruction substitution (equivalent but obfuscated operations).
    InstructionSubstitution,
    /// Constant encoding / arithmetic obfuscation.
    ConstantEncoding,
    /// String encryption.
    StringEncryption,
    /// API hashing (dynamic API resolution by hash).
    ApiHashing,
    /// Mixed boolean-arithmetic (MBA) obfuscation.
    MixedBooleanArithmetic,
    /// Virtualization obfuscation (custom VM bytecode).
    Virtualization,
    /// Anti-debug tricks.
    AntiDebug,
    /// Anti-VM tricks.
    AntiVm,
    /// Packer.
    Packer(String),
    /// Code transposition (instruction reordering).
    CodeTransposition,
    /// Return-oriented programming obfuscation.
    RopObfuscation,
}

impl std::fmt::Display for ObfuscationTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ControlFlowFlattening => "ControlFlowFlattening",
            Self::OpaquePredicates => "OpaquePredicates",
            Self::JunkCodeInsertion => "JunkCodeInsertion",
            Self::InstructionSubstitution => "InstructionSubstitution",
            Self::ConstantEncoding => "ConstantEncoding",
            Self::StringEncryption => "StringEncryption",
            Self::ApiHashing => "ApiHashing",
            Self::MixedBooleanArithmetic => "MBA",
            Self::Virtualization => "Virtualization",
            Self::AntiDebug => "AntiDebug",
            Self::AntiVm => "AntiVM",
            Self::Packer(p) => p.as_str(),
            Self::CodeTransposition => "CodeTransposition",
            Self::RopObfuscation => "RopObfuscation",
        };
        write!(f, "{s}")
    }
}

// ─── TechniqueResult ──────────────────────────────────────────────────────────

/// The result of detecting a single obfuscation technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueResult {
    /// The technique detected.
    pub technique: ObfuscationTechnique,
    /// Confidence in the detection.
    pub confidence: Confidence,
    /// Addresses / offsets supporting this detection.
    pub evidence_addresses: Vec<u64>,
    /// Human-readable description of the evidence.
    pub description: String,
    /// Suggested deobfuscation passes, in priority order.
    pub suggested_passes: Vec<DeobfPass>,
}

impl TechniqueResult {
    /// Create a new result.
    #[must_use]
    pub fn new(
        technique: ObfuscationTechnique,
        confidence: Confidence,
        description: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            confidence,
            evidence_addresses: Vec::new(),
            description: description.into(),
            suggested_passes: Vec::new(),
        }
    }

    /// Add an evidence address.
    pub fn add_evidence(&mut self, addr: u64) {
        self.evidence_addresses.push(addr);
    }

    /// Add a suggested pass.
    pub fn suggest(&mut self, pass: DeobfPass) {
        if !self.suggested_passes.contains(&pass) {
            self.suggested_passes.push(pass);
        }
    }
}

// ─── ClassificationResult ─────────────────────────────────────────────────────

/// The full classification result for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// All detected techniques.
    pub techniques: Vec<TechniqueResult>,
    /// Overall obfuscation score (0.0 = clean, 1.0 = heavily obfuscated).
    pub overall_score: f64,
    /// Ordered list of all suggested passes (deduplicated).
    pub recommended_passes: Vec<DeobfPass>,
    /// Whether the binary is likely to require dynamic analysis.
    pub requires_dynamic: bool,
    /// Summary message.
    pub summary: String,
}

impl ClassificationResult {
    /// Create an empty classification result.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            techniques: Vec::new(),
            overall_score: 0.0,
            recommended_passes: Vec::new(),
            requires_dynamic: false,
            summary: String::new(),
        }
    }

    /// Add a technique result.
    pub fn add_technique(&mut self, tr: TechniqueResult) {
        // Collect passes.
        for pass in &tr.suggested_passes {
            if !self.recommended_passes.contains(pass) {
                self.recommended_passes.push(pass.clone());
            }
        }
        self.techniques.push(tr);
        self.recompute();
    }

    fn recompute(&mut self) {
        if self.techniques.is_empty() {
            self.overall_score = 0.0;
            self.requires_dynamic = false;
            self.summary = "No obfuscation detected.".into();
            return;
        }
        // Overall score = weighted average of confidences.
        let total: f64 = self.techniques.iter().map(|t| t.confidence.value()).sum();
        self.overall_score = (total / self.techniques.len() as f64).clamp(0.0, 1.0);

        self.requires_dynamic = self.techniques.iter().any(|t| {
            matches!(
                t.technique,
                ObfuscationTechnique::Virtualization
                    | ObfuscationTechnique::Packer(_)
                    | ObfuscationTechnique::AntiDebug
                    | ObfuscationTechnique::AntiVm
            )
        });

        let count = self.techniques.len();
        self.summary = format!(
            "{count} obfuscation technique(s) detected; overall score {:.1}%",
            self.overall_score * 100.0
        );
    }

    /// Return only high-confidence detections.
    #[must_use]
    pub fn high_confidence_techniques(&self) -> Vec<&TechniqueResult> {
        self.techniques
            .iter()
            .filter(|t| t.confidence.is_high())
            .collect()
    }

    /// Return `true` if a specific technique was detected with any confidence.
    #[must_use]
    pub fn has_technique(&self, tech: &ObfuscationTechnique) -> bool {
        self.techniques.iter().any(|t| &t.technique == tech)
    }
}

impl Default for ClassificationResult {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Binary analysis input ────────────────────────────────────────────────────

/// Structural metrics extracted from a function for classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMetrics {
    /// Function start address.
    pub addr: u64,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Number of edges in the CFG.
    pub edge_count: u32,
    /// Cyclomatic complexity.
    pub cyclomatic: u32,
    /// Number of conditional branches.
    pub cond_branch_count: u32,
    /// Number of unconditional branches.
    pub uncond_branch_count: u32,
    /// Number of instructions.
    pub instr_count: u32,
    /// Number of NOP instructions.
    pub nop_count: u32,
    /// Estimated dispatcher block index (for CFF detection), or 0.
    pub dispatcher_block: u32,
    /// Number of blocks that loop back to the dispatcher.
    pub dispatcher_loop_count: u32,
    /// Number of XOR instructions.
    pub xor_count: u32,
    /// Number of MOVZX/MOVSX widening moves.
    pub widening_mov_count: u32,
    /// Number of unusual bitwise operations (ANDN, BTC, etc.).
    pub unusual_bitwise_count: u32,
    /// Maximum operand constant encountered (0 if none).
    pub max_imm_constant: u64,
    /// Number of constants that look like hash values (many set bits).
    pub hash_constant_count: u32,
    /// Number of encrypted string patterns detected.
    pub encrypted_string_patterns: u32,
    /// Number of small (≤3 instr) basic blocks (trampoline heuristic).
    pub tiny_block_count: u32,
    /// Number of blocks that are dominated by the dispatcher.
    pub dispatcher_dominated_count: u32,
    /// Shannon entropy of the function's bytes (0.0–8.0).
    pub byte_entropy: f64,
}

impl FunctionMetrics {
    /// Create minimal metrics for testing.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self {
            addr,
            block_count: 1,
            edge_count: 0,
            cyclomatic: 1,
            cond_branch_count: 0,
            uncond_branch_count: 0,
            instr_count: 1,
            nop_count: 0,
            dispatcher_block: 0,
            dispatcher_loop_count: 0,
            xor_count: 0,
            widening_mov_count: 0,
            unusual_bitwise_count: 0,
            max_imm_constant: 0,
            hash_constant_count: 0,
            encrypted_string_patterns: 0,
            tiny_block_count: 0,
            dispatcher_dominated_count: 0,
            byte_entropy: 0.0,
        }
    }
}

/// Binary-level statistics used for global classifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryStats {
    /// Total number of functions.
    pub function_count: u32,
    /// Binary size in bytes.
    pub binary_size: u64,
    /// Proportion of functions with high cyclomatic complexity.
    pub high_complexity_ratio: f64,
    /// Mean NOP ratio across all functions.
    pub mean_nop_ratio: f64,
    /// Number of anti-debug API imports detected.
    pub antidebug_import_count: u32,
    /// Number of anti-VM checks detected.
    pub antivm_check_count: u32,
    /// Number of packer signatures found.
    pub packer_signatures: Vec<String>,
    /// Shannon entropy of the `.text` section.
    pub text_entropy: f64,
    /// Number of string decrypt stubs identified.
    pub string_decrypt_stub_count: u32,
    /// Number of unique constants that match known hash values.
    pub api_hash_candidate_count: u32,
    /// Number of functions with very few recognized instructions.
    pub opaque_pred_candidate_count: u32,
    /// Number of direct `JMP` to out-of-range addresses (transposition).
    pub transposition_jump_count: u32,
    /// ROP gadget density (gadgets per 1 KiB of code).
    pub rop_gadget_density: f64,
    /// Number of VM handler patterns found.
    pub vm_handler_count: u32,
}

impl BinaryStats {
    /// Create minimal stats.
    #[must_use]
    pub const fn new(function_count: u32, binary_size: u64) -> Self {
        Self {
            function_count,
            binary_size,
            high_complexity_ratio: 0.0,
            mean_nop_ratio: 0.0,
            antidebug_import_count: 0,
            antivm_check_count: 0,
            packer_signatures: Vec::new(),
            text_entropy: 0.0,
            string_decrypt_stub_count: 0,
            api_hash_candidate_count: 0,
            opaque_pred_candidate_count: 0,
            transposition_jump_count: 0,
            rop_gadget_density: 0.0,
            vm_handler_count: 0,
        }
    }
}

// ─── ObfuscationClassifier ────────────────────────────────────────────────────

/// Classifier configuration.
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    /// Minimum confidence threshold to include a technique in the result.
    pub min_confidence: f64,
    /// CFF: minimum dispatcher-loop count to fire the CFF detector.
    pub cff_min_loop_count: u32,
    /// CFF: minimum dominated block fraction.
    pub cff_min_dominated_fraction: f64,
    /// Junk code: NOP ratio threshold.
    pub junk_nop_ratio: f64,
    /// MBA: unusual bitwise op threshold per function.
    pub mba_unusual_bitwise_threshold: u32,
    /// API hash: minimum candidate count.
    pub api_hash_min_candidates: u32,
    /// String encrypt: minimum stub count.
    pub string_encrypt_min_stubs: u32,
    /// OP: minimum opaque predicate candidates.
    pub opaque_pred_min_candidates: u32,
    /// Virtualization: minimum VM handler count.
    pub vm_handler_min_count: u32,
    /// ROP: minimum gadget density.
    pub rop_min_density: f64,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.30,
            cff_min_loop_count: 3,
            cff_min_dominated_fraction: 0.40,
            junk_nop_ratio: 0.05,
            mba_unusual_bitwise_threshold: 5,
            api_hash_min_candidates: 4,
            string_encrypt_min_stubs: 3,
            opaque_pred_min_candidates: 5,
            vm_handler_min_count: 10,
            rop_min_density: 2.0,
        }
    }
}

/// The main obfuscation classifier.
pub struct ObfuscationClassifier {
    config: ClassifierConfig,
}

impl ObfuscationClassifier {
    /// Create a classifier with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ClassifierConfig::default())
    }

    /// Create a classifier with explicit settings.
    #[must_use]
    pub const fn with_config(config: ClassifierConfig) -> Self {
        Self { config }
    }

    /// Classify a binary given function metrics and binary-level statistics.
    #[must_use]
    pub fn classify(
        &self,
        funcs: &[FunctionMetrics],
        stats: &BinaryStats,
    ) -> ClassificationResult {
        let mut result = ClassificationResult::new();

        // Run each detector.
        if let Some(tr) = self.detect_cff(funcs) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_opaque_predicates(funcs, stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_junk_code(funcs) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_instruction_substitution(funcs) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_constant_encoding(funcs) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_string_encryption(funcs, stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_api_hashing(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_mba(funcs) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_anti_debug(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_anti_vm(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_packer(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_virtualization(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_code_transposition(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        if let Some(tr) = self.detect_rop_obfuscation(stats) {
            if tr.confidence.value() >= self.config.min_confidence {
                result.add_technique(tr);
            }
        }

        result
    }

    // ── Detectors ────────────────────────────────────────────────────────────

    fn detect_cff(&self, funcs: &[FunctionMetrics]) -> Option<TechniqueResult> {
        let candidates: Vec<&FunctionMetrics> = funcs
            .iter()
            .filter(|f| {
                f.dispatcher_loop_count >= self.config.cff_min_loop_count
                    && f.block_count > 0
                    && (f.dispatcher_dominated_count as f64 / f.block_count as f64)
                        >= self.config.cff_min_dominated_fraction
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let ratio = candidates.len() as f64 / funcs.len().max(1) as f64;
        let confidence = Confidence::new(0.50 + ratio.min(0.45));

        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::ControlFlowFlattening,
            confidence,
            format!(
                "{} function(s) show dispatcher-loop patterns consistent with CFF",
                candidates.len()
            ),
        );

        for f in &candidates {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::RemoveCflFlattening);
        tr.suggest(DeobfPass::EliminateDeadCode);

        Some(tr)
    }

    fn detect_opaque_predicates(
        &self,
        funcs: &[FunctionMetrics],
        stats: &BinaryStats,
    ) -> Option<TechniqueResult> {
        let total_candidates = stats.opaque_pred_candidate_count
            + funcs.iter().filter(|f| {
                f.cond_branch_count > 0
                    && f.tiny_block_count as f64 / f.block_count.max(1) as f64 > 0.25
            })
            .count() as u32;

        if total_candidates < self.config.opaque_pred_min_candidates {
            return None;
        }

        let confidence = Confidence::new(
            0.40 + (total_candidates as f64 / 100.0).min(0.50),
        );

        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::OpaquePredicates,
            confidence,
            format!(
                "{total_candidates} opaque predicate candidate(s) identified"
            ),
        );

        for f in funcs.iter().filter(|f| {
            f.tiny_block_count as f64 / f.block_count.max(1) as f64 > 0.25
        }) {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::EliminateOpaquePredicates);
        tr.suggest(DeobfPass::EliminateDeadCode);

        Some(tr)
    }

    fn detect_junk_code(&self, funcs: &[FunctionMetrics]) -> Option<TechniqueResult> {
        let high_nop_funcs: Vec<&FunctionMetrics> = funcs
            .iter()
            .filter(|f| {
                f.instr_count > 0
                    && (f.nop_count as f64 / f.instr_count as f64) >= self.config.junk_nop_ratio
            })
            .collect();

        if high_nop_funcs.is_empty() {
            return None;
        }

        let mean_ratio: f64 = high_nop_funcs
            .iter()
            .map(|f| f.nop_count as f64 / f.instr_count.max(1) as f64)
            .sum::<f64>()
            / high_nop_funcs.len() as f64;

        let confidence = Confidence::new(0.35 + mean_ratio.min(0.60));

        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::JunkCodeInsertion,
            confidence,
            format!(
                "{} function(s) have elevated NOP ratio (mean {:.1}%)",
                high_nop_funcs.len(),
                mean_ratio * 100.0
            ),
        );
        for f in &high_nop_funcs {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::RemoveJunkCode);

        Some(tr)
    }

    fn detect_instruction_substitution(&self, funcs: &[FunctionMetrics]) -> Option<TechniqueResult> {
        // Heuristic: many widening-move instructions combined with many XOR ops.
        let candidates: Vec<&FunctionMetrics> = funcs
            .iter()
            .filter(|f| {
                f.widening_mov_count >= 3
                    && f.xor_count >= 2
                    && f.instr_count > 0
                    && (f.widening_mov_count + f.xor_count) as f64 / f.instr_count as f64 > 0.08
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let confidence = Confidence::new(0.45 + (candidates.len() as f64 / 50.0).min(0.35));
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::InstructionSubstitution,
            confidence,
            format!(
                "{} function(s) exhibit instruction substitution patterns",
                candidates.len()
            ),
        );
        for f in &candidates {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::NormalizeInstructionSubstitution);

        Some(tr)
    }

    fn detect_constant_encoding(&self, funcs: &[FunctionMetrics]) -> Option<TechniqueResult> {
        let total_odd_consts: u32 = funcs.iter().map(|f| f.hash_constant_count).sum();
        if total_odd_consts < 4 {
            return None;
        }
        let confidence = Confidence::new(0.40 + (total_odd_consts as f64 / 80.0).min(0.45));
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::ConstantEncoding,
            confidence,
            format!("{total_odd_consts} constant(s) appear to be encoded/obfuscated"),
        );
        for f in funcs.iter().filter(|f| f.hash_constant_count > 0) {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::FoldConstants);
        Some(tr)
    }

    fn detect_string_encryption(
        &self,
        funcs: &[FunctionMetrics],
        stats: &BinaryStats,
    ) -> Option<TechniqueResult> {
        let total_stubs = stats.string_decrypt_stub_count
            + funcs.iter().map(|f| f.encrypted_string_patterns).sum::<u32>();

        if total_stubs < self.config.string_encrypt_min_stubs {
            return None;
        }

        let confidence = Confidence::new(0.45 + (total_stubs as f64 / 30.0).min(0.45));
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::StringEncryption,
            confidence,
            format!("{total_stubs} string decryption pattern(s) detected"),
        );
        for f in funcs.iter().filter(|f| f.encrypted_string_patterns > 0) {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::DecryptStrings);
        Some(tr)
    }

    fn detect_api_hashing(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.api_hash_candidate_count < self.config.api_hash_min_candidates {
            return None;
        }
        let confidence = Confidence::new(
            0.50 + (stats.api_hash_candidate_count as f64 / 40.0).min(0.40),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::ApiHashing,
            confidence,
            format!(
                "{} API hash candidate(s) found",
                stats.api_hash_candidate_count
            ),
        );
        tr.suggest(DeobfPass::ResolveApiHashes);
        Some(tr)
    }

    fn detect_mba(&self, funcs: &[FunctionMetrics]) -> Option<TechniqueResult> {
        let candidates: Vec<&FunctionMetrics> = funcs
            .iter()
            .filter(|f| f.unusual_bitwise_count >= self.config.mba_unusual_bitwise_threshold)
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let mean_count = candidates.iter().map(|f| f.unusual_bitwise_count).sum::<u32>() as f64
            / candidates.len() as f64;
        let confidence = Confidence::new(0.40 + (mean_count / 30.0).min(0.50));

        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::MixedBooleanArithmetic,
            confidence,
            format!(
                "{} function(s) with heavy mixed-boolean-arithmetic patterns",
                candidates.len()
            ),
        );
        for f in &candidates {
            tr.add_evidence(f.addr);
        }
        tr.suggest(DeobfPass::NormalizeInstructionSubstitution);
        tr.suggest(DeobfPass::FoldConstants);
        Some(tr)
    }

    fn detect_anti_debug(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.antidebug_import_count == 0 {
            return None;
        }
        let confidence = Confidence::new(
            0.60 + (stats.antidebug_import_count as f64 / 10.0).min(0.35),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::AntiDebug,
            confidence,
            format!(
                "{} anti-debug import(s) detected",
                stats.antidebug_import_count
            ),
        );
        tr.suggest(DeobfPass::NeutralizeAntiAnalysis);
        Some(tr)
    }

    fn detect_anti_vm(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.antivm_check_count == 0 {
            return None;
        }
        let confidence = Confidence::new(
            0.55 + (stats.antivm_check_count as f64 / 8.0).min(0.40),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::AntiVm,
            confidence,
            format!("{} anti-VM check(s) detected", stats.antivm_check_count),
        );
        tr.suggest(DeobfPass::NeutralizeAntiAnalysis);
        Some(tr)
    }

    fn detect_packer(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.packer_signatures.is_empty() {
            // High entropy text section also suggests packing.
            if stats.text_entropy < 7.2 {
                return None;
            }
            let confidence = Confidence::new(0.55);
            let mut tr = TechniqueResult::new(
                ObfuscationTechnique::Packer("unknown".to_string()),
                confidence,
                "High .text entropy suggests packed or encrypted code",
            );
            tr.suggest(DeobfPass::UnpackPacker);
            return Some(tr);
        }

        let packer_name = stats.packer_signatures.join(", ");
        let confidence = Confidence::new(0.85);
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::Packer(packer_name.clone()),
            confidence,
            format!("Packer signature(s) detected: {packer_name}"),
        );
        tr.suggest(DeobfPass::UnpackPacker);
        Some(tr)
    }

    fn detect_virtualization(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.vm_handler_count < self.config.vm_handler_min_count {
            return None;
        }
        let confidence = Confidence::new(
            0.50 + (stats.vm_handler_count as f64 / 100.0).min(0.45),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::Virtualization,
            confidence,
            format!("{} VM handler pattern(s) identified", stats.vm_handler_count),
        );
        tr.suggest(DeobfPass::LiftVirtualization);
        Some(tr)
    }

    fn detect_code_transposition(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.transposition_jump_count < 10 {
            return None;
        }
        let confidence = Confidence::new(
            0.40 + (stats.transposition_jump_count as f64 / 200.0).min(0.40),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::CodeTransposition,
            confidence,
            format!(
                "{} long-range jump(s) suggest code transposition",
                stats.transposition_jump_count
            ),
        );
        tr.suggest(DeobfPass::RemoveCflFlattening);
        Some(tr)
    }

    fn detect_rop_obfuscation(&self, stats: &BinaryStats) -> Option<TechniqueResult> {
        if stats.rop_gadget_density < self.config.rop_min_density {
            return None;
        }
        let confidence = Confidence::new(
            0.40 + (stats.rop_gadget_density / 20.0).min(0.50),
        );
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::RopObfuscation,
            confidence,
            format!(
                "ROP gadget density {:.1} gadgets/KiB exceeds threshold",
                stats.rop_gadget_density
            ),
        );
        tr.suggest(DeobfPass::RemoveCflFlattening);
        tr.suggest(DeobfPass::EliminateDeadCode);
        Some(tr)
    }
}

impl Default for ObfuscationClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ObfuscationReport ────────────────────────────────────────────────────────

/// Full analyst-facing report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationReport {
    /// File path or identifier.
    pub target: String,
    /// Classification result.
    pub classification: ClassificationResult,
    /// Per-function summaries (top 20 most complex).
    pub top_functions: Vec<FunctionSummary>,
}

/// A brief summary of a function's obfuscation indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Function address.
    pub addr: u64,
    /// Cyclomatic complexity.
    pub cyclomatic: u32,
    /// Primary suspected technique.
    pub primary_technique: Option<String>,
    /// Confidence for the primary technique.
    pub primary_confidence: f64,
}

impl ObfuscationReport {
    /// Build a report from classification results and function metrics.
    #[must_use]
    pub fn build(
        target: impl Into<String>,
        classification: ClassificationResult,
        funcs: &[FunctionMetrics],
    ) -> Self {
        // Per-function assignment: find highest-confidence technique.
        let addr_to_techniques: HashMap<u64, Vec<(&ObfuscationTechnique, Confidence)>> = {
            let mut map: HashMap<u64, Vec<(&ObfuscationTechnique, Confidence)>> = HashMap::new();
            for tr in &classification.techniques {
                for &addr in &tr.evidence_addresses {
                    map.entry(addr).or_default().push((&tr.technique, tr.confidence));
                }
            }
            map
        };

        let mut top_funcs: Vec<FunctionSummary> = funcs
            .iter()
            .map(|f| {
                let primary = addr_to_techniques
                    .get(&f.addr)
                    // `unwrap_or(Equal)` rather than `unwrap()`: an unordered
                    // pair would panic here. Every other float ranking in this
                    // crate already uses a total comparison.
                    .and_then(|ts| {
                        ts.iter()
                            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                    });
                FunctionSummary {
                    addr: f.addr,
                    cyclomatic: f.cyclomatic,
                    primary_technique: primary.map(|(t, _)| t.to_string()),
                    primary_confidence: primary.map_or(0.0, |(_, c)| c.value()),
                }
            })
            .collect();

        // Sort by cyclomatic complexity descending, take top 20.
        top_funcs.sort_by(|a, b| b.cyclomatic.cmp(&a.cyclomatic));
        top_funcs.truncate(20);

        Self {
            target: target.into(),
            classification,
            top_functions: top_funcs,
        }
    }

    /// Render a human-readable summary.
    #[must_use]
    pub fn summary_text(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("=== Obfuscation Report: {} ===", self.target));
        lines.push(self.classification.summary.clone());
        lines.push(format!(
            "Overall score: {:.1}%",
            self.classification.overall_score * 100.0
        ));
        lines.push(format!(
            "Requires dynamic analysis: {}",
            self.classification.requires_dynamic
        ));
        lines.push("Techniques:".into());
        for tr in &self.classification.techniques {
            lines.push(format!(
                "  - {} ({}): {}",
                tr.technique, tr.confidence, tr.description
            ));
        }
        lines.push("Recommended passes:".into());
        for pass in &self.classification.recommended_passes {
            lines.push(format!("  + {pass}"));
        }
        lines.join("\n")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cff_func() -> FunctionMetrics {
        let mut m = FunctionMetrics::new(0x1000);
        m.block_count = 20;
        m.dispatcher_loop_count = 8;
        m.dispatcher_dominated_count = 12;
        m.instr_count = 200;
        m
    }

    fn junk_func() -> FunctionMetrics {
        let mut m = FunctionMetrics::new(0x2000);
        m.instr_count = 100;
        m.nop_count = 20;
        m
    }

    fn mba_func() -> FunctionMetrics {
        let mut m = FunctionMetrics::new(0x3000);
        m.unusual_bitwise_count = 15;
        m.instr_count = 50;
        m
    }

    fn string_func() -> FunctionMetrics {
        let mut m = FunctionMetrics::new(0x4000);
        m.encrypted_string_patterns = 5;
        m.xor_count = 8;
        m.instr_count = 40;
        m
    }

    fn base_stats() -> BinaryStats {
        BinaryStats::new(50, 0x50000)
    }

    #[test]
    fn test_cff_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![cff_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::ControlFlowFlattening));
    }

    #[test]
    fn test_junk_code_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![junk_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::JunkCodeInsertion));
    }

    #[test]
    fn test_mba_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![mba_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::MixedBooleanArithmetic));
    }

    #[test]
    fn test_string_encryption_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![string_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::StringEncryption));
    }

    #[test]
    fn test_api_hash_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.api_hash_candidate_count = 10;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::ApiHashing));
    }

    #[test]
    fn test_anti_debug_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.antidebug_import_count = 3;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::AntiDebug));
    }

    #[test]
    fn test_packer_detection_by_signature() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.packer_signatures = vec!["UPX".into()];
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::Packer("UPX".into())));
    }

    #[test]
    fn test_packer_detection_by_entropy() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.text_entropy = 7.5;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::Packer("unknown".into())));
    }

    #[test]
    fn test_virtualization_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.vm_handler_count = 50;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::Virtualization));
    }

    #[test]
    fn test_rop_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.rop_gadget_density = 5.0;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::RopObfuscation));
    }

    #[test]
    fn test_overall_score_range() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![cff_func(), junk_func()];
        let mut stats = base_stats();
        stats.antidebug_import_count = 2;
        let result = clf.classify(&funcs, &stats);
        assert!((0.0..=1.0).contains(&result.overall_score));
    }

    #[test]
    fn test_recommended_passes_deduplication() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![cff_func(), junk_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        let passes_set: HashSet<_> = result.recommended_passes.iter().collect();
        assert_eq!(passes_set.len(), result.recommended_passes.len());
    }

    #[test]
    fn test_requires_dynamic_packer() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.packer_signatures = vec!["Themida".into()];
        let result = clf.classify(&funcs, &stats);
        assert!(result.requires_dynamic);
    }

    #[test]
    fn test_no_obfuscation_clean() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![FunctionMetrics::new(0x1000)];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.techniques.is_empty());
        assert!(!result.requires_dynamic);
    }

    #[test]
    fn test_confidence_is_always_in_documented_range() {
        // The type documents the range [0.0, 1.0]. `f64::clamp` propagates NaN
        // instead of sanitising it, so NaN must be handled explicitly.
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -5.0, 5.0, 0.5] {
            let c = Confidence::new(v);
            assert!(
                !c.value().is_nan(),
                "Confidence::new({v}) produced NaN, breaking the documented range"
            );
            assert!(
                (0.0..=1.0).contains(&c.value()),
                "Confidence::new({v}) produced {} which is outside [0.0, 1.0]",
                c.value()
            );
        }
        // A NaN score must not outrank a real one.
        assert!(Confidence::new(f64::NAN) < Confidence::new(0.5));
    }

    #[test]
    fn test_confidence_display() {
        let c = Confidence::new(0.75);
        assert!(c.is_high());
        assert!(!c.is_low());
        assert!(c.to_string().contains('%'));
    }

    #[test]
    fn test_report_build() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![cff_func(), junk_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        let report = ObfuscationReport::build("test.exe", result, &funcs);
        assert_eq!(report.target, "test.exe");
        assert!(!report.summary_text().is_empty());
    }

    #[test]
    fn test_high_confidence_filter() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![cff_func()];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        let hc = result.high_confidence_techniques();
        for t in hc {
            assert!(t.confidence.is_high());
        }
    }

    #[test]
    fn test_deobf_pass_display() {
        assert_eq!(DeobfPass::RemoveCflFlattening.to_string(), "RemoveCflFlattening");
        assert_eq!(DeobfPass::Custom("my_pass".into()).to_string(), "my_pass");
    }

    #[test]
    fn test_technique_result_evidence() {
        let mut tr = TechniqueResult::new(
            ObfuscationTechnique::ControlFlowFlattening,
            Confidence::new(0.8),
            "test",
        );
        tr.add_evidence(0x1000);
        tr.add_evidence(0x2000);
        assert_eq!(tr.evidence_addresses.len(), 2);
    }

    #[test]
    fn test_transposition_detection() {
        let clf = ObfuscationClassifier::new();
        let funcs = vec![];
        let mut stats = base_stats();
        stats.transposition_jump_count = 50;
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::CodeTransposition));
    }

    #[test]
    fn test_constant_encoding_detection() {
        let clf = ObfuscationClassifier::new();
        let mut f = FunctionMetrics::new(0x5000);
        f.hash_constant_count = 6;
        let funcs = vec![f];
        let stats = base_stats();
        let result = clf.classify(&funcs, &stats);
        assert!(result.has_technique(&ObfuscationTechnique::ConstantEncoding));
    }
}
