// rustre-analysis-fn/src/function_classifier.rs
//
// Classify functions by purpose: wrapper, thunk, getter/setter, constructor/
// destructor, hash function, encryption/crypto function.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Opcode primitives used by classifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of control transfer for a decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    /// Non-branching instruction.
    Plain,
    /// Unconditional jump.
    Jmp,
    /// Return.
    Ret,
    /// Function call.
    Call,
}

impl InsnKind {
    /// Returns `true` if this is any kind of branch.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        !matches!(self, Self::Plain)
    }
    /// Returns `true` for unconditional jumps.
    #[must_use]
    pub const fn is_jmp(&self) -> bool {
        matches!(self, Self::Jmp)
    }
    /// Returns `true` for return instructions.
    #[must_use]
    pub const fn is_ret(&self) -> bool {
        matches!(self, Self::Ret)
    }
    /// Returns `true` for call instructions.
    #[must_use]
    pub const fn is_call(&self) -> bool {
        matches!(self, Self::Call)
    }
}

/// A decoded x86 / x64 instruction, enough detail for classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    /// Instruction address.
    pub addr: u64,
    /// Mnemonic string (lower-case).
    pub mnemonic: String,
    /// Control-flow kind of this instruction.
    pub kind: InsnKind,
    /// Call or branch target, when known.
    pub target: Option<u64>,
    /// First immediate operand, when present.
    pub imm: Option<u64>,
    /// Byte length of the encoded instruction.
    pub length: usize,
}

// Convenience accessors that match the old field names used throughout the codebase.
impl DecodedInsn {
    /// Returns `true` if this instruction transfers control.
    #[must_use]
    pub const fn is_branch(&self) -> bool { self.kind.is_branch() }
    /// Returns `true` if this is an unconditional jump.
    #[must_use]
    pub const fn is_jmp(&self) -> bool { self.kind.is_jmp() }
    /// Returns `true` if this is a RET.
    #[must_use]
    pub const fn is_ret(&self) -> bool { self.kind.is_ret() }
    /// Returns `true` if this is a CALL.
    #[must_use]
    pub const fn is_call(&self) -> bool { self.kind.is_call() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoder helpers — split out to keep from_bytes under 100 lines
// ─────────────────────────────────────────────────────────────────────────────

fn decode_ret(addr: u64) -> DecodedInsn {
    DecodedInsn { addr, mnemonic: "ret".into(), kind: InsnKind::Ret,
        target: None, imm: None, length: 1 }
}

fn decode_jmp_rel8(addr: u64, bytes: &[u8], off: usize) -> DecodedInsn {
    let disp = bytes.get(off + 1).copied().map(|d| i64::from(d.cast_signed()));
    let target = disp.map(|d| (addr.cast_signed() + 2 + d).cast_unsigned());
    DecodedInsn { addr, mnemonic: "jmp".into(), kind: InsnKind::Jmp,
        target, imm: None, length: 2 }
}

fn decode_jmp_rel32(addr: u64, bytes: &[u8], off: usize) -> DecodedInsn {
    let disp = bytes.get(off + 1..off + 5)
        .map(|s| i64::from(i32::from_le_bytes([s[0], s[1], s[2], s[3]])));
    let target = disp.map(|d| (addr.cast_signed() + 5 + d).cast_unsigned());
    DecodedInsn { addr, mnemonic: "jmp".into(), kind: InsnKind::Jmp,
        target, imm: None, length: 5 }
}

fn decode_call_rel32(addr: u64, bytes: &[u8], off: usize) -> DecodedInsn {
    let disp = bytes.get(off + 1..off + 5)
        .map(|s| i64::from(i32::from_le_bytes([s[0], s[1], s[2], s[3]])));
    let target = disp.map(|d| (addr.cast_signed() + 5 + d).cast_unsigned());
    DecodedInsn { addr, mnemonic: "call".into(), kind: InsnKind::Call,
        target, imm: None, length: 5 }
}

fn plain(addr: u64, mnemonic: &str, imm: Option<u64>, length: usize) -> DecodedInsn {
    DecodedInsn { addr, mnemonic: mnemonic.into(), kind: InsnKind::Plain,
        target: None, imm, length }
}

impl DecodedInsn {
    /// Build a minimal descriptor from a raw byte slice at `addr`.
    ///
    /// This is a lightweight heuristic decoder that recognises only the most
    /// important patterns for classification; it does not attempt full
    /// disassembly.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], addr: u64) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        // REX prefix
        let mut off = 0usize;
        if bytes[0] >= 0x40 && bytes[0] <= 0x4F {
            off += 1;
        }
        if off >= bytes.len() {
            return None;
        }
        let b0 = bytes[off];
        let b1 = bytes.get(off + 1).copied();

        // NOP
        if off == 0 && b0 == 0x90 {
            return Some(plain(addr, "nop", None, 1));
        }
        // RET near/far
        if b0 == 0xC3 || b0 == 0xCB {
            return Some(decode_ret(addr));
        }
        // RET imm16
        if b0 == 0xC2 || b0 == 0xCA {
            let imm = bytes.get(off + 1..off + 3)
                .map(|s| u64::from(u16::from_le_bytes([s[0], s[1]])));
            return Some(Self { addr, mnemonic: "ret".into(), kind: InsnKind::Ret,
                target: None, imm, length: 3 });
        }
        // JMP rel8
        if b0 == 0xEB {
            return Some(decode_jmp_rel8(addr, bytes, off));
        }
        // JMP rel32
        if b0 == 0xE9 {
            return Some(decode_jmp_rel32(addr, bytes, off));
        }
        // JMP r/m (FF /4): ModRM reg field 4 = E4, 5 = EC, 6 = F4, 7 = FC
        // and direct register forms E0..E7
        if b0 == 0xFF && b1.is_some_and(|b| (0xE0..=0xE7).contains(&b)) {
            return Some(Self { addr, mnemonic: "jmp".into(), kind: InsnKind::Jmp,
                target: None, imm: None, length: 2 });
        }
        // CALL rel32
        if b0 == 0xE8 {
            return Some(decode_call_rel32(addr, bytes, off));
        }
        // XOR reg, reg  (31 /r  or  33 /r)
        if b0 == 0x31 || b0 == 0x33 {
            return Some(plain(addr, "xor", None, 2));
        }
        // XOR r/m, imm8  (83 /6 ib)
        if b0 == 0x83 && b1.is_some_and(|b| (b >> 3) & 7 == 6) {
            return Some(plain(addr, "xor",
                bytes.get(off + 2).map(|&b| u64::from(b)), 3));
        }
        // ROL / ROR  (D0/D2/D3  /0 or /1; C1 /0 or /1)
        if (b0 == 0xD0 || b0 == 0xD1 || b0 == 0xD2 || b0 == 0xD3)
            && b1.is_some_and(|b| (b >> 3) & 7 <= 1)
        {
            let mn = if b1.is_some_and(|b| (b >> 3).trailing_zeros() >= 3) { "rol" } else { "ror" };
            return Some(plain(addr, mn, None, 2));
        }
        if b0 == 0xC1 && b1.is_some_and(|b| (b >> 3) & 7 <= 1) {
            let mn = if b1.is_some_and(|b| (b >> 3).trailing_zeros() >= 3) { "rol" } else { "ror" };
            return Some(plain(addr, mn,
                bytes.get(off + 2).map(|&b| u64::from(b)), 3));
        }
        // MOV reg, [mem]  / MOV [mem], reg  (simplified)
        if b0 == 0x8B || b0 == 0x89 {
            return Some(plain(addr, "mov", None, 2));
        }
        // push/pop (50-5F)
        if (0x50..=0x5F).contains(&b0) {
            let mn = if b0 <= 0x57 { "push" } else { "pop" };
            return Some(plain(addr, mn, None, 1));
        }
        // generic fallthrough
        Some(plain(addr, &format!("{b0:#04x}"), None, 1))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionClass — top-level classification
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level classification of a function's purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FunctionClass {
    /// A thin wrapper around a single callee.
    Wrapper(WrapperFunc),
    /// An unconditional jump stub (import thunk / PLT entry).
    Thunk(ThunkFunc),
    /// Reads a field from a struct pointer.
    Getter,
    /// Writes a field to a struct pointer.
    Setter,
    /// Constructs an object (allocates + initialises).
    Constructor,
    /// Destructs / frees an object.
    Destructor,
    /// Computes a hash value.
    Hash(HashFunc),
    /// Contains encryption/decryption logic.
    Crypto(CryptoFunc),
    /// Could not be classified into a known category.
    Unknown,
}

impl FunctionClass {
    /// Human-readable name of this class.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Wrapper(_) => "wrapper",
            Self::Thunk(_) => "thunk",
            Self::Getter => "getter",
            Self::Setter => "setter",
            Self::Constructor => "constructor",
            Self::Destructor => "destructor",
            Self::Hash(_) => "hash",
            Self::Crypto(_) => "crypto",
            Self::Unknown => "unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WrapperFunc
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a wrapper function (one CALL + optional stack adjustment).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WrapperFunc {
    /// The single callee address.
    pub callee: u64,
    /// Total instruction count in the wrapper.
    pub insn_count: usize,
}

impl WrapperFunc {
    /// Detect a wrapper: at most `max_insns` instructions, exactly one CALL, ends with RET.
    #[must_use]
    pub fn detect(insns: &[DecodedInsn], max_insns: usize) -> Option<Self> {
        if insns.is_empty() || insns.len() > max_insns {
            return None;
        }
        let calls: Vec<&DecodedInsn> = insns.iter().filter(|i| i.is_call()).collect();
        let has_ret = insns.iter().any(DecodedInsn::is_ret);
        if calls.len() == 1 && has_ret {
            Some(Self {
                callee: calls[0].target.unwrap_or(0),
                insn_count: insns.len(),
            })
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThunkFunc
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a thunk function (JMP-only stub).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThunkFunc {
    /// Jump target address (0 if indirect / unknown).
    pub target: u64,
    /// Whether the jump is indirect (JMP [mem]).
    pub is_indirect: bool,
}

impl ThunkFunc {
    /// Detect a thunk: ≤ 3 non-NOP instructions, unconditional JMP, no CALL.
    #[must_use]
    pub fn detect(insns: &[DecodedInsn]) -> Option<Self> {
        let real: Vec<&DecodedInsn> = insns.iter().filter(|i| i.mnemonic != "nop").collect();
        if real.is_empty() || real.len() > 3 {
            return None;
        }
        // All non-nop instructions must be JMPs (or push/pop)
        let jmps: Vec<&DecodedInsn> = real.iter().copied().filter(|i| i.is_jmp()).collect();
        if jmps.len() != 1 {
            return None;
        }
        let has_call = real.iter().any(|i| i.is_call());
        if has_call {
            return None;
        }
        let jmp = jmps[0];
        let is_indirect = jmp.target.is_none();
        Some(Self {
            target: jmp.target.unwrap_or(0),
            is_indirect,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HashFunc
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence that a function is a hash computation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashFunc {
    /// XOR instruction count.
    pub xor_count: usize,
    /// Rotate-left/right instruction count.
    pub rotate_count: usize,
    /// Number of large constants (≥ 0x1000) seen.
    pub large_const_count: usize,
    /// Confidence score in [0, 100].
    pub confidence: u8,
}

impl HashFunc {
    /// Known hash magic constants (CRC-32, FNV, `MurmurHash`, xxHash, etc.).
    const KNOWN_HASH_CONSTS: &'static [u64] = &[
        0xEDB8_8320, // CRC-32 poly
        0x04C1_1DB7, // CRC-32 poly (forward)
        0x0100_0193, // FNV prime 32
        0x811C_9DC5, // FNV offset 32
        0xC4AC_CD13, // MurmurHash 3 const
        0xFF51_AFD7, // xxHash prime 1
        0xC4CE_B9FE, // xxHash prime 2
        0x9E37_79B9, // golden ratio / Fibonacci hashing
        0x6150_1E81, // another common hash const
        0xDEAD_BEEF,
        0x1337_1337,
    ];

    /// Analyse instruction list for hash-function patterns.
    #[must_use]
    pub fn detect(insns: &[DecodedInsn]) -> Option<Self> {
        let xor_count = insns.iter().filter(|i| i.mnemonic == "xor").count();
        let rotate_count = insns.iter()
            .filter(|i| i.mnemonic == "rol" || i.mnemonic == "ror")
            .count();
        let large_const_count = insns.iter()
            .filter_map(|i| i.imm)
            .filter(|&v| v >= 0x1000)
            .count();

        let known_const_hits = insns.iter()
            .filter_map(|i| i.imm)
            .filter(|v| Self::KNOWN_HASH_CONSTS.contains(v))
            .count();

        // Scoring
        let mut score = 0u32;
        if xor_count >= 2 { score += 20; }
        if xor_count >= 5 { score += 10; }
        if rotate_count >= 1 { score += 20; }
        if rotate_count >= 3 { score += 10; }
        if large_const_count >= 1 { score += 10; }
        if known_const_hits >= 1 { score += 30; }
        let confidence = (score.min(100)) as u8;
        if confidence < 25 {
            return None;
        }
        Some(Self {
            xor_count,
            rotate_count,
            large_const_count,
            confidence,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CryptoFunc
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence that a function is an encryption/decryption routine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CryptoFunc {
    /// Number of XOR instructions.
    pub xor_count: usize,
    /// Number of rotate instructions.
    pub rotate_count: usize,
    /// Number of recognised S-box / AES magic constants.
    pub magic_const_count: usize,
    /// True if the function uses a loop (back-edge detected).
    pub has_loop: bool,
    /// Confidence score in [0, 100].
    pub confidence: u8,
}

impl CryptoFunc {
    /// AES, DES, Camellia, `ChaCha20` round constants and S-box entries.
    const CRYPTO_CONSTS: &'static [u64] = &[
        0x637C_777B, // AES S-box[0..3]
        0xF26B_6FC5, // AES S-box[4..7]
        0x3001_6767, // AES Rcon
        0x6368_7970, // "chyp" from ChaCha20 sigma
        0x6B20_6574, // "k et" from ChaCha20 sigma
        0x6E64_2033, // "nd 3" from ChaCha20 sigma
        0x322D_3279, // "2-2y" from ChaCha20 sigma
        0x0100_0193, // FNV prime (used inside RC4-derived functions)
        0x5299_9E2A, // SHA-256 K[0]
        0xA4BB_E929, // SHA-256 K[1]
        0x69C4_2B6F, // blowfish P-box
    ];

    /// Detect crypto function patterns.
    #[must_use]
    pub fn detect(insns: &[DecodedInsn]) -> Option<Self> {
        let xor_count = insns.iter().filter(|i| i.mnemonic == "xor").count();
        let rotate_count = insns.iter()
            .filter(|i| i.mnemonic == "rol" || i.mnemonic == "ror")
            .count();
        let magic_const_count = insns.iter()
            .filter_map(|i| i.imm)
            .filter(|v| Self::CRYPTO_CONSTS.contains(v))
            .count();

        // Detect back-edges: a branch target ≤ current address
        let has_loop = insns.windows(2).any(|w| {
            w[0].is_branch() && w[0].target.is_some_and(|t| t <= w[0].addr)
        });

        let mut score = 0u32;
        if xor_count >= 4 { score += 25; }
        if xor_count >= 8 { score += 15; }
        if rotate_count >= 2 { score += 20; }
        if magic_const_count >= 1 { score += 30; }
        if has_loop { score += 10; }
        // High instruction density with XOR/rotate is suspicious.
        // Use integer arithmetic to avoid float precision issues.
        let density_pct = if insns.is_empty() {
            0
        } else {
            (xor_count + rotate_count) * 100 / insns.len()
        };
        if density_pct > 15 { score += 10; }

        let confidence = (score.min(100)) as u8;
        if confidence < 30 {
            return None;
        }
        Some(Self {
            xor_count,
            rotate_count,
            magic_const_count,
            has_loop,
            confidence,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Name-mangling heuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `name` looks like a constructor by mangling conventions.
#[must_use]
pub fn name_looks_like_ctor(name: &str) -> bool {
    // MSVC: `??0ClassName@Namespace@@QEAA` pattern
    if name.starts_with("??0") {
        return true;
    }
    // Itanium: _ZN...C1 / _ZN...C2
    if name.contains("C1E") || name.contains("C2E") || name.contains("C3E") {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("ctor") || lower.contains("constructor") || lower.contains("init")
}

/// Returns `true` if `name` looks like a destructor.
#[must_use]
pub fn name_looks_like_dtor(name: &str) -> bool {
    if name.starts_with("??1") {
        return true;
    }
    if name.contains("D1E") || name.contains("D2E") || name.contains("D0E") {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("dtor") || lower.contains("destructor") || lower.contains("cleanup")
        || lower.contains("destroy") || lower.contains("free")
}

/// Returns `true` if `name` matches a getter pattern.
#[must_use]
pub fn name_looks_like_getter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("get") || lower.starts_with("is_") || lower.starts_with("has_")
        || lower.starts_with("query") || lower.ends_with("_get")
}

/// Returns `true` if `name` matches a setter pattern.
#[must_use]
pub fn name_looks_like_setter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("set") || lower.starts_with("put")
        || lower.ends_with("_set") || lower.ends_with("_put")
}

// ─────────────────────────────────────────────────────────────────────────────
// Getter / Setter detection from instruction patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Detect a getter-shaped function: very small (≤ 6 insns), contains at least
/// one `mov` and a `ret`, and makes no calls.
///
/// NOTE: `DecodedInsn` carries no operand information, so this cannot verify
/// that the `mov` is a *load* (`mov reg, [mem]`) rather than a store. Getters
/// and setters therefore share the same instruction-shape signature and are
/// distinguished here only by the size cap (getters allow one more insn); a
/// caller that needs a true load/store distinction must decode operands.
#[must_use]
pub fn detect_getter(insns: &[DecodedInsn]) -> bool {
    if insns.is_empty() || insns.len() > 8 {
        return false;
    }
    let movs = insns.iter().filter(|i| i.mnemonic == "mov").count();
    let rets = insns.iter().filter(|i| i.is_ret()).count();
    let calls = insns.iter().filter(|i| i.is_call()).count();
    movs >= 1 && rets >= 1 && calls == 0 && insns.len() <= 6
}

/// Detect a setter-shaped function: very small (≤ 5 insns), contains at least
/// one `mov` and a `ret`, and makes no calls.
///
/// NOTE: as with [`detect_getter`], the `mov` cannot be confirmed to be a
/// *store* — `DecodedInsn` has no operand data, so this matches the same shape
/// as a getter (see that function's note).
#[must_use]
pub fn detect_setter(insns: &[DecodedInsn]) -> bool {
    if insns.is_empty() || insns.len() > 8 {
        return false;
    }
    let movs = insns.iter().filter(|i| i.mnemonic == "mov").count();
    let rets = insns.iter().filter(|i| i.is_ret()).count();
    let calls = insns.iter().filter(|i| i.is_call()).count();
    movs >= 1 && rets >= 1 && calls == 0 && insns.len() <= 5
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionClassifier — main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the function classifier.
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    /// Maximum instruction count for a wrapper to be recognised as such.
    pub max_wrapper_insns: usize,
    /// Minimum confidence (0–100) required for hash/crypto classification.
    pub min_confidence: u8,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            max_wrapper_insns: 10,
            min_confidence: 30,
        }
    }
}

/// Classification result for a single function.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Function entry-point address.
    pub addr: u64,
    /// Optional function name.
    pub name: Option<String>,
    /// Assigned class.
    pub class: FunctionClass,
    /// Instruction count.
    pub insn_count: usize,
}

/// Classify a function from its decoded instruction stream and optional name.
#[must_use]
pub fn classify_function(
    addr: u64,
    insns: &[DecodedInsn],
    name: Option<&str>,
    cfg: &ClassifierConfig,
) -> ClassificationResult {
    let insn_count = insns.len();

    // 1. Thunk (highest priority — purely structural).
    if let Some(thunk) = ThunkFunc::detect(insns) {
        return ClassificationResult {
            addr, name: name.map(str::to_owned),
            class: FunctionClass::Thunk(thunk),
            insn_count,
        };
    }

    // 2. Wrapper.
    if let Some(wrapper) = WrapperFunc::detect(insns, cfg.max_wrapper_insns) {
        return ClassificationResult {
            addr, name: name.map(str::to_owned),
            class: FunctionClass::Wrapper(wrapper),
            insn_count,
        };
    }

    // 3. Name-based constructor / destructor.
    if let Some(n) = name {
        if name_looks_like_ctor(n) {
            return ClassificationResult {
                addr, name: Some(n.to_owned()),
                class: FunctionClass::Constructor,
                insn_count,
            };
        }
        if name_looks_like_dtor(n) {
            return ClassificationResult {
                addr, name: Some(n.to_owned()),
                class: FunctionClass::Destructor,
                insn_count,
            };
        }
        if name_looks_like_getter(n) && detect_getter(insns) {
            return ClassificationResult {
                addr, name: Some(n.to_owned()),
                class: FunctionClass::Getter,
                insn_count,
            };
        }
        if name_looks_like_setter(n) && detect_setter(insns) {
            return ClassificationResult {
                addr, name: Some(n.to_owned()),
                class: FunctionClass::Setter,
                insn_count,
            };
        }
    }

    // 4. Structural getter / setter (no name required).
    if detect_getter(insns) {
        return ClassificationResult {
            addr, name: name.map(str::to_owned),
            class: FunctionClass::Getter,
            insn_count,
        };
    }
    if detect_setter(insns) {
        return ClassificationResult {
            addr, name: name.map(str::to_owned),
            class: FunctionClass::Setter,
            insn_count,
        };
    }

    // 5. Crypto (before hash, because crypto is a superset of hash patterns).
    if let Some(crypto) = CryptoFunc::detect(insns)
        && crypto.confidence >= cfg.min_confidence {
            return ClassificationResult {
                addr, name: name.map(str::to_owned),
                class: FunctionClass::Crypto(crypto),
                insn_count,
            };
        }

    // 6. Hash.
    if let Some(hash) = HashFunc::detect(insns)
        && hash.confidence >= cfg.min_confidence {
            return ClassificationResult {
                addr, name: name.map(str::to_owned),
                class: FunctionClass::Hash(hash),
                insn_count,
            };
        }

    ClassificationResult {
        addr, name: name.map(str::to_owned),
        class: FunctionClass::Unknown,
        insn_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch classifier
// ─────────────────────────────────────────────────────────────────────────────

/// Classify a collection of functions, returning a map from address to result.
#[must_use]
pub fn classify_all(
    functions: &[(u64, Vec<DecodedInsn>, Option<String>)],
    cfg: &ClassifierConfig,
) -> HashMap<u64, ClassificationResult> {
    functions
        .iter()
        .map(|(addr, insns, name)| {
            let result = classify_function(*addr, insns, name.as_deref(), cfg);
            (*addr, result)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a set of classification results.
#[derive(Debug, Clone, Default)]
pub struct ClassificationStats {
    pub total: usize,
    pub wrappers: usize,
    pub thunks: usize,
    pub getters: usize,
    pub setters: usize,
    pub constructors: usize,
    pub destructors: usize,
    pub hashes: usize,
    pub cryptos: usize,
    pub unknown: usize,
}

impl ClassificationStats {
    /// Build stats from a slice of results.
    #[must_use]
    pub fn from_results(results: &[ClassificationResult]) -> Self {
        let total = results.len();
        let mut wrappers = 0;
        let mut thunks = 0;
        let mut getters = 0;
        let mut setters = 0;
        let mut constructors = 0;
        let mut destructors = 0;
        let mut hashes = 0;
        let mut cryptos = 0;
        let mut unknown = 0;
        for r in results {
            match &r.class {
                FunctionClass::Wrapper(_) => wrappers += 1,
                FunctionClass::Thunk(_) => thunks += 1,
                FunctionClass::Getter => getters += 1,
                FunctionClass::Setter => setters += 1,
                FunctionClass::Constructor => constructors += 1,
                FunctionClass::Destructor => destructors += 1,
                FunctionClass::Hash(_) => hashes += 1,
                FunctionClass::Crypto(_) => cryptos += 1,
                FunctionClass::Unknown => unknown += 1,
            }
        }
        Self { total, wrappers, thunks, getters, setters, constructors,
               destructors, hashes, cryptos, unknown }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn jmp_insn(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "jmp".into(),
            kind: InsnKind::Jmp,
            target: Some(target), imm: None, length: 5,
        }
    }
    fn call_insn(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "call".into(),
            kind: InsnKind::Call,
            target: Some(target), imm: None, length: 5,
        }
    }
    fn ret_insn(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "ret".into(),
            kind: InsnKind::Ret,
            target: None, imm: None, length: 1,
        }
    }
    fn xor_insn(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "xor".into(),
            kind: InsnKind::Plain,
            target: None, imm: None, length: 2,
        }
    }
    fn rol_insn(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "rol".into(),
            kind: InsnKind::Plain,
            target: None, imm: None, length: 2,
        }
    }
    fn mov_insn(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr, mnemonic: "mov".into(),
            kind: InsnKind::Plain,
            target: None, imm: None, length: 2,
        }
    }

    #[test]
    fn thunk_detection() {
        let insns = vec![jmp_insn(0x1000, 0x2000)];
        let thunk = ThunkFunc::detect(&insns).unwrap();
        assert_eq!(thunk.target, 0x2000);
        assert!(!thunk.is_indirect);
    }

    #[test]
    fn wrapper_detection() {
        let insns = vec![
            mov_insn(0x1000),
            call_insn(0x1002, 0x5000),
            ret_insn(0x1007),
        ];
        let cfg = ClassifierConfig::default();
        let w = WrapperFunc::detect(&insns, cfg.max_wrapper_insns).unwrap();
        assert_eq!(w.callee, 0x5000);
        assert_eq!(w.insn_count, 3);
    }

    #[test]
    fn hash_detection_by_xor_rotate() {
        let mut insns = Vec::new();
        for i in 0..6u64 { insns.push(xor_insn(0x1000 + i * 2)); }
        for i in 0..3u64 { insns.push(rol_insn(0x1010 + i * 2)); }
        insns.push(ret_insn(0x1020));
        let h = HashFunc::detect(&insns).unwrap();
        assert!(h.confidence >= 50);
    }

    #[test]
    fn hash_detection_by_known_const() {
        let insns = vec![
            DecodedInsn {
                addr: 0x1000, mnemonic: "xor".into(),
                kind: InsnKind::Plain,
                target: None, imm: Some(0xEDB8_8320), length: 6,
            },
            ret_insn(0x1006),
        ];
        let h = HashFunc::detect(&insns).unwrap();
        assert!(h.known_const_hit());
    }

    #[test]
    fn getter_detection() {
        let insns = vec![mov_insn(0x1000), ret_insn(0x1002)];
        assert!(detect_getter(&insns));
    }

    #[test]
    fn setter_detection() {
        let insns = vec![mov_insn(0x1000), ret_insn(0x1002)];
        assert!(detect_setter(&insns));
    }

    #[test]
    fn classify_thunk() {
        let insns = vec![jmp_insn(0x1000, 0x2000)];
        let cfg = ClassifierConfig::default();
        let r = classify_function(0x1000, &insns, None, &cfg);
        assert!(matches!(r.class, FunctionClass::Thunk(_)));
    }

    #[test]
    fn classify_wrapper() {
        let insns = vec![call_insn(0x1000, 0x5000), ret_insn(0x1005)];
        let cfg = ClassifierConfig::default();
        let r = classify_function(0x1000, &insns, None, &cfg);
        assert!(matches!(r.class, FunctionClass::Wrapper(_)));
    }

    #[test]
    fn classify_ctor_by_name() {
        let cfg = ClassifierConfig::default();
        let r = classify_function(0x1000, &[ret_insn(0x1000)], Some("??0Foo@@QEAA@XZ"), &cfg);
        assert_eq!(r.class, FunctionClass::Constructor);
    }

    #[test]
    fn classify_dtor_by_name() {
        let cfg = ClassifierConfig::default();
        let r = classify_function(0x1000, &[ret_insn(0x1000)], Some("??1Foo@@QEAA@XZ"), &cfg);
        assert_eq!(r.class, FunctionClass::Destructor);
    }

    #[test]
    fn stats_computed() {
        let cfg = ClassifierConfig::default();
        let funcs: Vec<(u64, Vec<DecodedInsn>, Option<String>)> = vec![
            (0x1000, vec![jmp_insn(0x1000, 0x2000)], None),
            (0x2000, vec![call_insn(0x2000, 0x3000), ret_insn(0x2005)], None),
            (0x3000, vec![ret_insn(0x3000)], Some("??0Foo@@QEAA@XZ".into())),
        ];
        let map = classify_all(&funcs, &cfg);
        let results: Vec<ClassificationResult> = map.into_values().collect();
        let stats = ClassificationStats::from_results(&results);
        assert_eq!(stats.total, 3);
    }
}

// Extra helper for test
impl HashFunc {
    #[cfg(test)]
    const fn known_const_hit(&self) -> bool { self.large_const_count > 0 || self.confidence > 25 }
}
