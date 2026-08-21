//! Lua bytecode pattern analysis: obfuscation detection, string table extraction,
//! and bytecode statistics for all supported Lua versions.

use std::collections::HashMap;
use std::fmt;

use crate::LuaVersion;

// ─── FloatEqHash ──────────────────────────────────────────────────────────────

/// A wrapper around f64 that implements Eq and Hash using `to_bits`.
#[derive(Debug, Clone, Copy)]
pub struct FloatEqHash(pub f64);

impl PartialEq for FloatEqHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for FloatEqHash {}

impl std::hash::Hash for FloatEqHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

// ─── ObfuscationPattern ───────────────────────────────────────────────────────

/// A pattern that may indicate deliberate bytecode obfuscation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObfuscationPattern {
    /// An opcode index that is out of range for the detected Lua version.
    InvalidOpcode {
        /// Offset (in 4-byte words) of the suspicious instruction.
        offset: usize,
        /// The raw opcode value extracted from the word.
        raw_opcode: u8,
    },
    /// An unusually high density of LOADK/LOADKX instructions (> threshold%).
    HighConstantLoad {
        /// Fraction in the range 0.0..=1.0.
        fraction: FloatEqHash,
    },
    /// More upvalue references than the declared upvalue count in the header.
    UpvalueMismatch {
        /// Number of GETUPVAL/SETUPVAL instructions found.
        refs_found: usize,
        /// Maximum index referenced.
        max_index: usize,
        /// Declared upvalue count.
        declared: usize,
    },
    /// A JMP instruction whose target offset places it outside the function body.
    OutOfBoundsJump {
        /// Offset of the JMP instruction.
        offset: usize,
        /// Computed absolute target word index.
        target: i64,
        /// Total word count for this function.
        word_count: usize,
    },
    /// CLOSURE referring to a prototype index that exceeds the declared count.
    InvalidClosure {
        /// Offset of the CLOSURE instruction.
        offset: usize,
        /// Prototype index encoded in the instruction.
        proto_index: usize,
        /// Declared number of sub-prototypes.
        declared_protos: usize,
    },
    /// The bytecode chunk begins without a valid Lua magic header.
    MissingMagic,
    /// Abnormally many CALL/TAILCALL instructions suggest a code flattening pass.
    ExcessiveCalls {
        /// Number of call instructions found.
        count: usize,
        /// Total instructions examined.
        total: usize,
    },
    /// Non-standard instruction alignment or padding words detected.
    AlignmentAnomaly {
        /// Word offset where the anomaly was observed.
        offset: usize,
    },
}

impl fmt::Display for ObfuscationPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOpcode { offset, raw_opcode } => {
                write!(f, "invalid opcode {raw_opcode:#04x} at word offset {offset}")
            }
            Self::HighConstantLoad { fraction } => {
                write!(f, "high LOADK density ({:.1}%)", fraction.0 * 100.0)
            }
            Self::UpvalueMismatch { refs_found, max_index, declared } => write!(
                f,
                "upvalue mismatch: {refs_found} refs (max idx {max_index}), declared {declared}"
            ),
            Self::OutOfBoundsJump { offset, target, word_count } => write!(
                f,
                "out-of-bounds JMP at {offset}: target {target} (words={word_count})"
            ),
            Self::InvalidClosure { offset, proto_index, declared_protos } => write!(
                f,
                "invalid CLOSURE at {offset}: proto {proto_index} >= {declared_protos}"
            ),
            Self::MissingMagic => write!(f, "missing or corrupt Lua magic header"),
            Self::ExcessiveCalls { count, total } => {
                write!(f, "excessive calls: {count}/{total} instructions are CALL/TAILCALL")
            }
            Self::AlignmentAnomaly { offset } => {
                write!(f, "alignment anomaly at word offset {offset}")
            }
        }
    }
}

// ─── StringTableEntry ─────────────────────────────────────────────────────────

/// A string literal recovered from a Lua bytecode constant pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTableEntry {
    /// Zero-based index within the constant pool of this function.
    pub index: usize,
    /// The string value.
    pub value: String,
    /// `true` if the string is referenced at least once by a LOADK/GETTABUP/etc.
    pub referenced: bool,
    /// Number of times this string appears in the raw constant pool.
    pub occurrences: usize,
}

impl StringTableEntry {
    /// Create a new entry with one occurrence.
    pub fn new(index: usize, value: impl Into<String>) -> Self {
        Self {
            index,
            value: value.into(),
            referenced: false,
            occurrences: 1,
        }
    }
}

impl fmt::Display for StringTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ref_flag = if self.referenced { "R" } else { " " };
        write!(
            f,
            "[{:4}] {ref_flag} x{} {:?}",
            self.index, self.occurrences, self.value
        )
    }
}

// ─── BytecodeStats ────────────────────────────────────────────────────────────

/// Aggregate counts extracted from a single Lua function's bytecode.
#[derive(Debug, Clone, Default)]
pub struct BytecodeStats {
    /// Total number of instructions decoded.
    pub instruction_count: usize,
    /// Number of LOADK/LOADKX instructions.
    pub loadk_count: usize,
    /// Number of GETUPVAL/SETUPVAL instructions.
    pub upvalue_ops: usize,
    /// Number of CALL instructions.
    pub call_count: usize,
    /// Number of TAILCALL instructions.
    pub tailcall_count: usize,
    /// Number of RETURN/RETURN0/RETURN1 instructions.
    pub return_count: usize,
    /// Number of CLOSURE instructions.
    pub closure_count: usize,
    /// Number of table-access instructions (GETTABLE, SETTABLE, GETTABUP, SETTABUP).
    pub table_access_count: usize,
    /// Number of arithmetic instructions (ADD, SUB, MUL, DIV, MOD, POW, IDIV).
    pub arithmetic_count: usize,
    /// Number of branch instructions (JMP and comparison ops that skip).
    pub branch_count: usize,
    /// Number of instructions that decoded to an invalid/unknown opcode.
    pub invalid_count: usize,
    /// Histogram: `opcode_index` -> count.
    pub opcode_histogram: HashMap<u8, usize>,
}

impl BytecodeStats {
    /// Create zero-initialised stats.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the fraction of instructions that are LOADK/LOADKX.
    #[must_use] 
    pub fn constant_load_fraction(&self) -> f64 {
        if self.instruction_count == 0 {
            return 0.0;
        }
        crate::count_as_f64(self.loadk_count) / crate::count_as_f64(self.instruction_count)
    }

    /// Return the most common opcode and its hit count.
    #[must_use] 
    pub fn most_common_opcode(&self) -> Option<(u8, usize)> {
        self.opcode_histogram
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&k, &v)| (k, v))
    }

    /// Merge another `BytecodeStats` into `self` (for aggregate reporting).
    pub fn merge(&mut self, other: &Self) {
        self.instruction_count += other.instruction_count;
        self.loadk_count += other.loadk_count;
        self.upvalue_ops += other.upvalue_ops;
        self.call_count += other.call_count;
        self.tailcall_count += other.tailcall_count;
        self.return_count += other.return_count;
        self.closure_count += other.closure_count;
        self.table_access_count += other.table_access_count;
        self.arithmetic_count += other.arithmetic_count;
        self.branch_count += other.branch_count;
        self.invalid_count += other.invalid_count;
        for (&op, &cnt) in &other.opcode_histogram {
            *self.opcode_histogram.entry(op).or_insert(0) += cnt;
        }
    }
}

impl fmt::Display for BytecodeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BytecodeStats {{ instrs={}, loadk={} ({:.1}%), upvals={}, calls={}, \
             tailcalls={}, returns={}, closures={}, table={}, arith={}, branches={}, invalid={} }}",
            self.instruction_count,
            self.loadk_count,
            self.constant_load_fraction() * 100.0,
            self.upvalue_ops,
            self.call_count,
            self.tailcall_count,
            self.return_count,
            self.closure_count,
            self.table_access_count,
            self.arithmetic_count,
            self.branch_count,
            self.invalid_count,
        )
    }
}

// ─── LuaBytecodeAnalyzer ──────────────────────────────────────────────────────

/// Configuration for `LuaBytecodeAnalyzer`.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Fraction of LOADK instructions above which `HighConstantLoad` is flagged.
    pub loadk_threshold: f64,
    /// Fraction of CALL/TAILCALL instructions above which `ExcessiveCalls` fires.
    pub call_density_threshold: f64,
    /// Check for out-of-bounds JMP targets.
    pub check_jump_bounds: bool,
    /// Maximum string length to include in the string table (longer strings
    /// are truncated to this many bytes before storage).
    pub max_string_bytes: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            loadk_threshold: 0.40,
            call_density_threshold: 0.30,
            check_jump_bounds: true,
            max_string_bytes: 4096,
        }
    }
}

/// Result of analyzing one Lua function's bytecode.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Lua version this function was decoded under.
    pub version: LuaVersion,
    /// Aggregate statistics.
    pub stats: BytecodeStats,
    /// Obfuscation patterns detected.
    pub patterns: Vec<ObfuscationPattern>,
    /// String literals found in the constant pool (sorted by index).
    pub string_table: Vec<StringTableEntry>,
    /// Number of declared sub-prototypes (nested functions).
    pub declared_protos: usize,
    /// Number of declared upvalues in the function header.
    pub declared_upvalues: usize,
}

impl AnalysisResult {
    /// Return `true` if any obfuscation patterns were found.
    #[must_use] 
    pub const fn is_obfuscated(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Return a severity score: 0 = clean, 1 = mild, 2 = moderate, 3+ = heavy.
    #[must_use] 
    pub fn obfuscation_score(&self) -> usize {
        self.patterns.iter().map(|p| match p {
            ObfuscationPattern::HighConstantLoad { fraction } if fraction.0 > 0.6 => 2,
            ObfuscationPattern::HighConstantLoad { .. } | ObfuscationPattern::MissingMagic | ObfuscationPattern::ExcessiveCalls { .. } => 1,
            ObfuscationPattern::UpvalueMismatch { .. } | ObfuscationPattern::InvalidClosure { .. } | ObfuscationPattern::AlignmentAnomaly { .. } => 2,
            ObfuscationPattern::InvalidOpcode { .. } | ObfuscationPattern::OutOfBoundsJump { .. } => 3,
            }).sum()
    }
}

impl fmt::Display for AnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnalysisResult {{ version={}, score={}, patterns={}, strings={} }}",
            self.version,
            self.obfuscation_score(),
            self.patterns.len(),
            self.string_table.len(),
        )
    }
}

/// Analyzes a flat buffer of Lua instruction words for obfuscation and
/// extracts the embedded string table.
///
/// The analyzer operates on raw 4-byte instruction words; it does **not**
/// parse the complete binary chunk format.  Callers are expected to locate
/// the instruction array (typically after the function header) and pass it
/// directly.
#[derive(Debug, Clone)]
pub struct LuaBytecodeAnalyzer {
    /// Lua version to use when decoding opcodes.
    pub version: LuaVersion,
    /// Configuration knobs.
    pub config: AnalyzerConfig,
}


/// One instruction's position in the bytecode stream, plus the two whole-chunk
/// facts a classifier needs to bounds-check it.
///
/// ⚠ Introduced because `classify54` and `classify_legacy` each took eleven
/// parameters and needed an `#[allow(clippy::too_many_arguments)]`. Four of
/// them were `usize` in a row — `offset`, `word_count`, `declared_protos` — and
/// transposing any two compiles and silently changes which jumps are reported
/// out of bounds.
#[derive(Debug, Clone, Copy)]
struct InstrCtx {
    /// Opcode byte, already extracted from `word`.
    op: u8,
    /// The raw 32-bit instruction word.
    word: u32,
    /// Index of this word in the chunk.
    offset: usize,
    /// Total words in the chunk, for jump-target bounds checks.
    word_count: usize,
    /// Prototype count the header declares, for closure-index checks.
    declared_protos: usize,
    /// Whether jump targets should be bounds-checked at all.
    check_jumps: bool,
}

/// Everything a classifier accumulates as it walks the chunk.
///
/// Grouped rather than passed as five separate `&mut` parameters: five mutable
/// out-params in a row is the shape where an argument swap type-checks.
struct ClassifySink<'a> {
    stats: &'a mut BytecodeStats,
    patterns: &'a mut Vec<ObfuscationPattern>,
    max_upval: &'a mut usize,
    upval_refs: &'a mut usize,
    string_table: &'a mut Vec<StringTableEntry>,
}

impl LuaBytecodeAnalyzer {
    /// Create an analyzer for the given Lua version with default configuration.
    #[must_use] 
    pub fn new(version: LuaVersion) -> Self {
        Self {
            version,
            config: AnalyzerConfig::default(),
        }
    }

    /// Create an analyzer with explicit configuration.
    #[must_use] 
    pub const fn with_config(version: LuaVersion, config: AnalyzerConfig) -> Self {
        Self { version, config }
    }

    /// Analyze a slice of raw instruction words.
    ///
    /// `declared_upvalues` and `declared_protos` come from the function header
    /// parsed by the caller.  `strings` is the constant pool of this function
    /// (may be empty if not yet decoded).
    #[must_use] 
    pub fn analyze(
        &self,
        words: &[u32],
        declared_upvalues: usize,
        declared_protos: usize,
        strings: &[String],
    ) -> AnalysisResult {
        let mut stats = BytecodeStats::new();
        let mut patterns: Vec<ObfuscationPattern> = Vec::new();

        let opcode_count = opcode_table_len(self.version);

        // Build string table from the supplied constant pool.
        let mut string_table: Vec<StringTableEntry> = strings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // Truncate to a valid UTF-8 boundary to avoid panicking on
                // multibyte codepoints that straddle the byte limit.
                let truncated = if s.len() > self.config.max_string_bytes {
                    let boundary = s.floor_char_boundary(self.config.max_string_bytes);
                    s[..boundary].to_owned()
                } else {
                    s.clone()
                };
                StringTableEntry::new(i, truncated)
            })
            .collect();

        // Track max upvalue index referenced.
        let mut max_upval_index: usize = 0;
        let mut upval_ref_count: usize = 0;

        for (offset, &word) in words.iter().enumerate() {
            let op = extract_opcode(self.version, word);
            stats.instruction_count += 1;

            if (op as usize) >= opcode_count {
                stats.invalid_count += 1;
                patterns.push(ObfuscationPattern::InvalidOpcode {
                    offset,
                    raw_opcode: op,
                });
                continue;
            }

            *stats.opcode_histogram.entry(op).or_insert(0) += 1;

            // Classify by opcode semantics.
            match self.version {
                LuaVersion::Lua54 => Self::classify54(
                    InstrCtx {
                        op,
                        word,
                        offset,
                        word_count: words.len(),
                        declared_protos,
                        check_jumps: self.config.check_jump_bounds,
                    },
                    &mut ClassifySink {
                        stats: &mut stats,
                        patterns: &mut patterns,
                        max_upval: &mut max_upval_index,
                        upval_refs: &mut upval_ref_count,
                        string_table: &mut string_table,
                    },
                ),
                _ => self.classify_legacy(
                    InstrCtx {
                        op,
                        word,
                        offset,
                        word_count: words.len(),
                        declared_protos,
                        check_jumps: self.config.check_jump_bounds,
                    },
                    &mut ClassifySink {
                        stats: &mut stats,
                        patterns: &mut patterns,
                        max_upval: &mut max_upval_index,
                        upval_refs: &mut upval_ref_count,
                        string_table: &mut string_table,
                    },
                ),
            }
        }

        // Post-pass: LOADK density check.
        let frac = stats.constant_load_fraction();
        if frac > self.config.loadk_threshold {
            patterns.push(ObfuscationPattern::HighConstantLoad { fraction: FloatEqHash(frac) });
        }

        // Post-pass: upvalue mismatch check.
        if declared_upvalues > 0 && upval_ref_count > 0 && max_upval_index >= declared_upvalues {
            patterns.push(ObfuscationPattern::UpvalueMismatch {
                refs_found: upval_ref_count,
                max_index: max_upval_index,
                declared: declared_upvalues,
            });
        }

        // Post-pass: excessive call check.
        let total_calls = stats.call_count + stats.tailcall_count;
        if stats.instruction_count > 0 {
            let call_frac =
            crate::count_as_f64(total_calls) / crate::count_as_f64(stats.instruction_count);
            if call_frac > self.config.call_density_threshold {
                patterns.push(ObfuscationPattern::ExcessiveCalls {
                    count: total_calls,
                    total: stats.instruction_count,
                });
            }
        }

        AnalysisResult {
            version: self.version,
            stats,
            patterns,
            string_table,
            declared_protos,
            declared_upvalues,
        }
    }

    // ── Lua 5.4 opcode classifier ────────────────────────────────────────────

    fn classify54(ctx: InstrCtx, sink: &mut ClassifySink<'_>) {
        let InstrCtx { op, word, offset, word_count, declared_protos, check_jumps } = ctx;
        // Reborrowed one by one so each binding has the same `&mut T` type the
        // parameters used to have; destructuring the struct through `&mut`
        // would give `&mut &mut T` and every `*x += 1` in the body would need
        // an extra deref.
        let stats = &mut *sink.stats;
        let patterns = &mut *sink.patterns;
        let max_upval = &mut *sink.max_upval;
        let upval_refs = &mut *sink.upval_refs;
        let string_table = &mut *sink.string_table;
        match op {
            // LOADK / LOADKX
            3 | 4 => {
                stats.loadk_count += 1;
                let a = (word >> 7) & 0xff;
                let bx = (word >> 15) & 0x1_ffff;
                mark_string_referenced(string_table, bx as usize);
                let _ = a;
            }
            // GETUPVAL (7) / SETUPVAL (8)
            7 | 8 => {
                stats.upvalue_ops += 1;
                *upval_refs += 1;
                let b = (word >> 16) & 0xff;
                if b as usize > *max_upval {
                    *max_upval = b as usize;
                }
            }
            // GETTABUP (9) / SETTABUP (13)
            9 | 13 => {
                stats.table_access_count += 1;
                stats.upvalue_ops += 1;
                *upval_refs += 1;
                let b = (word >> 16) & 0xff;
                if b as usize > *max_upval {
                    *max_upval = b as usize;
                }
            }
            // GETTABLE (10) / SETTABLE (14)
            10 | 14 | 11 | 15 | 12 | 16 => stats.table_access_count += 1,
            // ADD..BXOR (32..41), ADDI (19), ADDK..BXORK (20..29), SHRI/SHLI (30/31)
            19..=43 | 47 | 48 => stats.arithmetic_count += 1,
            // UNM (47) / BNOT (48)
            // CALL (66)
            66 => stats.call_count += 1,
            // TAILCALL (67)
            67 => stats.tailcall_count += 1,
            // RETURN / RETURN0 / RETURN1 (68/69/70)
            68..=70 => stats.return_count += 1,
            // JMP (54)
            54 => {
                stats.branch_count += 1;
                if check_jumps {
                    let sj_raw = (word >> 7) & 0x01ff_ffff;
                    let sj = i64::from(sj_raw) - 16_777_215;
                    let target = i64::try_from(offset).unwrap_or(i64::MAX) + 1 + sj;
                    if target < 0 || target >= i64::try_from(word_count).unwrap_or(i64::MAX) {
                        patterns.push(ObfuscationPattern::OutOfBoundsJump {
                            offset,
                            target,
                            word_count,
                        });
                    }
                }
            }
            // EQ..GEI (55..63), TEST (64), TESTSET (65)
            55..=65 | 71..=75 => stats.branch_count += 1,
            // FORLOOP/FORPREP/TFORPREP/TFORCALL/TFORLOOP (71..75)
            // CLOSURE (77)
            77 => {
                stats.closure_count += 1;
                let bx = ((word >> 15) & 0x1_ffff) as usize;
                if declared_protos > 0 && bx >= declared_protos {
                    patterns.push(ObfuscationPattern::InvalidClosure {
                        offset,
                        proto_index: bx,
                        declared_protos,
                    });
                }
            }
            _ => {}
        }
    }

    // ── Legacy (5.1–5.3) opcode classifier ───────────────────────────────────

    fn classify_legacy(&self, ctx: InstrCtx, sink: &mut ClassifySink<'_>) {
        let InstrCtx { op, word, offset, word_count, declared_protos, check_jumps } = ctx;
        // Reborrowed one by one so each binding has the same `&mut T` type the
        // parameters used to have; destructuring the struct through `&mut`
        // would give `&mut &mut T` and every `*x += 1` in the body would need
        // an extra deref.
        let stats = &mut *sink.stats;
        let patterns = &mut *sink.patterns;
        let max_upval = &mut *sink.max_upval;
        let upval_refs = &mut *sink.upval_refs;
        let string_table = &mut *sink.string_table;
        // Extract legacy fields: bits 0..5 = op, 6..13 = A, 23..31 = B, 14..22 = C.
        let b = (word >> 23) & 0x1ff;
        let bx = word >> 14; // 18 bits

        match (self.version, op) {
            // LOADK: Lua51=1, Lua52/53=1
            (_, 1) => {
                stats.loadk_count += 1;
                mark_string_referenced(string_table, bx as usize);
            }
            // LOADKX: Lua52/53=2
            (LuaVersion::Lua52 | LuaVersion::Lua53, 2) => {
                stats.loadk_count += 1;
            }
            // GETUPVAL: Lua51=4, Lua52/53=5
            (LuaVersion::Lua51, 4 | 8) | (LuaVersion::Lua52 | LuaVersion::Lua53, 5 | 9) => {
                stats.upvalue_ops += 1;
                *upval_refs += 1;
                if b as usize > *max_upval {
                    *max_upval = b as usize;
                }
            }
            // SETUPVAL: Lua51=8, Lua52/53=9
            // GETTABUP: Lua52/53=6
            (LuaVersion::Lua52 | LuaVersion::Lua53, 6) => {
                stats.table_access_count += 1;
                stats.upvalue_ops += 1;
                *upval_refs += 1;
                if b as usize > *max_upval {
                    *max_upval = b as usize;
                }
            }
            // GETTABLE/SETTABLE (Lua51: 6/9, Lua52/53: 7/10)
            (LuaVersion::Lua51, 6 | 9) | (LuaVersion::Lua52 | LuaVersion::Lua53, 7 | 10) => stats.table_access_count += 1,
            // Arithmetic: ADD/SUB/MUL/DIV/MOD/POW (Lua51: 12-17, Lua52/53 similar)
            (LuaVersion::Lua51, 12..=17) | (LuaVersion::Lua52, 13..=18) | (LuaVersion::Lua53, 13..=24) => stats.arithmetic_count += 1,
            // CALL (Lua51:28, Lua52:29, Lua53:36)
            (LuaVersion::Lua51, 28) | (LuaVersion::Lua52, 29) | (LuaVersion::Lua53, 36) => {
                stats.call_count += 1;
            }
            // TAILCALL (Lua51:29, Lua52:30, Lua53:37)
            (LuaVersion::Lua51, 29) | (LuaVersion::Lua52, 30) | (LuaVersion::Lua53, 37) => {
                stats.tailcall_count += 1;
            }
            // RETURN (Lua51:30, Lua52:31, Lua53:38)
            (LuaVersion::Lua51, 30) | (LuaVersion::Lua52, 31) | (LuaVersion::Lua53, 38) => {
                stats.return_count += 1;
            }
            // JMP (Lua51:22, Lua52:23, Lua53:30)
            (LuaVersion::Lua51, 22) | (LuaVersion::Lua52, 23) | (LuaVersion::Lua53, 30) => {
                stats.branch_count += 1;
                if check_jumps {
                    const MAXARG_SBX_OLD: i64 = ((1 << 18) - 1) >> 1;
                    let sbx = i64::from(bx) - MAXARG_SBX_OLD;
                    let target = i64::try_from(offset).unwrap_or(i64::MAX) + 1 + sbx;
                    if target < 0 || target >= i64::try_from(word_count).unwrap_or(i64::MAX) {
                        patterns.push(ObfuscationPattern::OutOfBoundsJump {
                            offset,
                            target,
                            word_count,
                        });
                    }
                }
            }
            // CLOSURE (Lua51:36, Lua52:37, Lua53:44)
            (LuaVersion::Lua51, 36) | (LuaVersion::Lua52, 37) | (LuaVersion::Lua53, 44) => {
                stats.closure_count += 1;
                let bx_val = bx as usize;
                if declared_protos > 0 && bx_val >= declared_protos {
                    patterns.push(ObfuscationPattern::InvalidClosure {
                        offset,
                        proto_index: bx_val,
                        declared_protos,
                    });
                }
            }
            // Comparison branches
            (LuaVersion::Lua51, 23..=27 | 31 | 32) |
(LuaVersion::Lua52, 24..=28 | 32 | 33 | 35) |
(LuaVersion::Lua53, 31..=35 | 39 | 40 | 42) => stats.branch_count += 1,
            // FORLOOP/FORPREP (Lua51: 31/32, Lua52: 32/33, Lua53: 39/40)
            _ => {}
        }

        let _ = (string_table, patterns, max_upval, upval_refs);
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Return the number of opcodes for `version`.
const fn opcode_table_len(version: LuaVersion) -> usize {
    match version {
        LuaVersion::Lua51 => 38,
        LuaVersion::Lua52 => 40,
        LuaVersion::Lua53 => 47,
        LuaVersion::Lua54 => 81,
    }
}

/// Extract the raw opcode from a word for the given Lua version.
const fn extract_opcode(version: LuaVersion, word: u32) -> u8 {
    if version.is_legacy() {
        (word & 0x3f) as u8
    } else {
        (word & 0x7f) as u8
    }
}

/// Mark the string table entry at `index` as referenced.
fn mark_string_referenced(table: &mut [StringTableEntry], index: usize) {
    if let Some(entry) = table.get_mut(index) {
        entry.referenced = true;
    }
}

// ─── Convenience top-level function ──────────────────────────────────────────

/// Analyze raw instruction words for a single Lua function and return
/// the combined result.
///
/// This is a convenience wrapper around [`LuaBytecodeAnalyzer`] with default
/// configuration.
#[must_use] 
pub fn analyze_function(
    version: LuaVersion,
    words: &[u32],
    declared_upvalues: usize,
    declared_protos: usize,
    constants: &[String],
) -> AnalysisResult {
    LuaBytecodeAnalyzer::new(version).analyze(words, declared_upvalues, declared_protos, constants)
}

/// Check whether a raw bytecode buffer begins with the Lua magic header
/// `\x1bLua`.  Returns a `MissingMagic` pattern if not.
#[must_use] 
pub fn check_magic(data: &[u8]) -> Option<ObfuscationPattern> {
    if data.len() < 4 || data[0] != 0x1b || data[1] != b'L' || data[2] != b'u' || data[3] != b'a'
    {
        Some(ObfuscationPattern::MissingMagic)
    } else {
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_54_loadk(a: u32, bx: u32) -> u32 {
        // op=3 (LOADK), A in bits 7..14, Bx in bits 15..31
        3u32 | (a << 7) | (bx << 15)
    }

    fn make_54_jmp(sj: i32) -> u32 {
        // op=54 (JMP), sJ encoded with bias 16_777_215
        let uj = (sj + 16_777_215).cast_unsigned();
        0x36u32 | (uj << 7)
    }

    #[test]
    fn test_empty_words_produces_clean_result() {
        let r = analyze_function(LuaVersion::Lua54, &[], 0, 0, &[]);
        assert_eq!(r.stats.instruction_count, 0);
        assert!(!r.is_obfuscated());
    }

    #[test]
    fn test_loadk_density_flagged() {
        // 10 LOADK words → 100% → above 40% threshold.
        let words: Vec<u32> = (0..10).map(|i| make_54_loadk(i, 0)).collect();
        let r = analyze_function(LuaVersion::Lua54, &words, 0, 0, &[]);
        assert!(r
            .patterns
            .iter()
            .any(|p| matches!(p, ObfuscationPattern::HighConstantLoad { .. })));
    }

    #[test]
    fn test_invalid_opcode_flagged() {
        // Opcode 0x7f = 127 is out of range for Lua 5.4 (max 80).
        let word = 127u32; // bits 0..6 = 127
        let r = analyze_function(LuaVersion::Lua54, &[word], 0, 0, &[]);
        assert!(r
            .patterns
            .iter()
            .any(|p| matches!(p, ObfuscationPattern::InvalidOpcode { .. })));
    }

    #[test]
    fn test_oob_jump_flagged() {
        // A JMP that jumps 999 words forward in a 2-word function.
        let jump = make_54_jmp(999);
        let r = analyze_function(LuaVersion::Lua54, &[jump, 0x45], 0, 0, &[]);
        assert!(r
            .patterns
            .iter()
            .any(|p| matches!(p, ObfuscationPattern::OutOfBoundsJump { .. })));
    }

    #[test]
    fn test_magic_check_ok() {
        assert!(check_magic(b"\x1bLuaXXX").is_none());
    }

    #[test]
    fn test_magic_check_fail() {
        assert!(check_magic(b"\x00Lua").is_some());
    }

    #[test]
    fn test_obfuscation_score_empty() {
        let r = analyze_function(LuaVersion::Lua51, &[], 0, 0, &[]);
        assert_eq!(r.obfuscation_score(), 0);
    }
}
