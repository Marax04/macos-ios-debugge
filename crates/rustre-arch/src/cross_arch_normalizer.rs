//! Cross-architecture instruction normalization.
//!
//! Maps architecture-specific instructions to a generic IR that allows
//! code analysis passes to operate uniformly across multiple ISAs.

use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};

use crate::{Architecture, Instruction, Endian};
use crate::arch_feature_flags::FeatureFlag;

// ---------------------------------------------------------------------------
// Generic operand model
// ---------------------------------------------------------------------------

/// Width of a value in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BitWidth {
    W8,
    W16,
    W32,
    W64,
    W128,
    W256,
    W512,
    Other(u16),
}

impl BitWidth {
    /// Return the number of bits.
    #[must_use]
    pub fn bits(self) -> u32 {
        match self {
            Self::W8       => 8,
            Self::W16      => 16,
            Self::W32      => 32,
            Self::W64      => 64,
            Self::W128     => 128,
            Self::W256     => 256,
            Self::W512     => 512,
            Self::Other(n) => u32::from(n),
        }
    }

    /// Return the number of bytes (rounded up).
    #[must_use]
    pub fn bytes(self) -> u32 {
        self.bits().div_ceil(8)
    }

    /// Construct from a bit count.
    #[must_use]
    pub fn from_bits(n: u32) -> Self {
        match n {
            8   => Self::W8,
            16  => Self::W16,
            32  => Self::W32,
            64  => Self::W64,
            128 => Self::W128,
            256 => Self::W256,
            512 => Self::W512,
            // Clamp values that exceed u16::MAX to avoid a silent truncating
            // cast; the `Other` variant is only intended for unusual widths
            // such as 12-bit or 24-bit, all of which fit comfortably in u16.
            _ => Self::Other(u16::try_from(n).unwrap_or(u16::MAX)),
        }
    }
}

/// A generic operand that abstracts over architecture-specific operand forms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GenericOperand {
    /// An integer immediate value.
    Immediate { value: i64, width: BitWidth },
    /// A floating-point immediate.
    FloatImm { value: f64, width: BitWidth },
    /// A general-purpose register identified by normalized name.
    Register { name: String, width: BitWidth },
    /// A memory reference: `[base + index*scale + disp]`.
    Memory {
        base:  Option<String>,
        index: Option<String>,
        scale: u8,
        disp:  i64,
        width: BitWidth,
        segment: Option<String>,
    },
    /// A PC-relative or absolute branch target address.
    BranchTarget { address: u64, is_relative: bool },
    /// A condition code (e.g., EQ, NE, GT, …).
    Condition(String),
    /// A shift/extend modifier attached to another operand.
    Shifted {
        inner: Box<Self>,
        shift_kind: ShiftKind,
        amount: u8,
    },
    /// Vector/SIMD register lane specifier.
    VecLane {
        register: String,
        lane:     u8,
        lane_width: BitWidth,
    },
    /// An expression not captured by the above forms.
    Raw(String),
}

impl GenericOperand {
    /// Return the bit-width of this operand, if known.
    #[must_use]
    pub fn width(&self) -> Option<BitWidth> {
        match self {
            Self::Immediate { width, .. }
            | Self::FloatImm { width, .. }
            | Self::Register { width, .. }
            | Self::Memory { width, .. } => Some(*width),
            Self::VecLane    { lane_width, .. } => Some(*lane_width),
            Self::Shifted    { inner, .. } => inner.width(),
            _ => None,
        }
    }

    /// Return `true` if this operand reads from memory.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Memory { .. })
    }

    /// Return `true` if this operand is a branch target.
    #[must_use]
    pub const fn is_branch_target(&self) -> bool {
        matches!(self, Self::BranchTarget { .. })
    }
}

/// Shift/rotate kinds used in shifted operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
    Rrx,
    Custom(u8),
}

// ---------------------------------------------------------------------------
// Normalized instruction
// ---------------------------------------------------------------------------

/// A high-level opcode class, independent of ISA.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GenericOpcode {
    // Data movement
    Move,
    Load,
    Store,
    Push,
    Pop,
    Exchange,
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Abs,
    // Bitwise
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    // Comparison
    Compare,
    Test,
    // Control flow
    Jump,
    JumpConditional,
    Call,
    Return,
    Syscall,
    SysReturn,
    Halt,
    Nop,
    // Float
    FAdd,
    FSub,
    FMul,
    FDiv,
    FConvert,
    FCompare,
    // SIMD
    VecAdd,
    VecSub,
    VecMul,
    VecShuffle,
    VecBroadcast,
    VecExtract,
    VecInsert,
    VecCompare,
    // Atomic / memory order
    AtomicLoad,
    AtomicStore,
    AtomicExchange,
    AtomicCompareExchange,
    AtomicAdd,
    // Bit manipulation
    BitScan,
    BitCount,
    Clz,
    Ctz,
    // Crypto
    AesEnc,
    AesDec,
    Sha1,
    Sha256,
    CarrylessMultiply,
    // Other
    Barrier,
    Prefetch,
    Unknown,
    Pseudo(String),
}

/// Normalized instruction — the result of mapping one ISA instruction to the
/// generic IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedInsn {
    /// Virtual address of this instruction.
    pub address: u64,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Original mnemonic as emitted by the arch backend.
    pub raw_mnemonic: String,
    /// Normalized opcode class.
    pub opcode: GenericOpcode,
    /// Operand list in generic form.
    pub operands: Vec<GenericOperand>,
    /// Flags written by this instruction (generic flag names: Z, N, C, V, …).
    pub flags_written: Vec<String>,
    /// Flags read by this instruction.
    pub flags_read: Vec<String>,
    /// Implicit registers written.
    pub implicit_writes: Vec<String>,
    /// Implicit registers read.
    pub implicit_reads: Vec<String>,
    /// True if this instruction may branch (including returns and calls).
    pub is_branch: bool,
    /// True if this instruction terminates a basic block.
    pub terminates_block: bool,
    /// Any feature flags required to execute this instruction.
    pub required_features: Vec<FeatureFlag>,
    /// Whether the instruction has a lock prefix / memory atomicity guarantee.
    pub is_atomic: bool,
    /// Side-channel / security notes (e.g., "Spectre gadget").
    pub security_notes: Vec<String>,
}

impl NormalizedInsn {
    /// Build a minimal normalized instruction with unknown opcode.
    pub fn unknown(address: u64, bytes: Vec<u8>, mnemonic: impl Into<String>) -> Self {
        Self {
            address,
            bytes,
            raw_mnemonic: mnemonic.into(),
            opcode: GenericOpcode::Unknown,
            operands: Vec::new(),
            flags_written: Vec::new(),
            flags_read: Vec::new(),
            implicit_writes: Vec::new(),
            implicit_reads: Vec::new(),
            is_branch: false,
            terminates_block: false,
            required_features: Vec::new(),
            is_atomic: false,
            security_notes: Vec::new(),
        }
    }

    /// Return the destination operand (first operand), if any.
    #[must_use]
    pub fn dst(&self) -> Option<&GenericOperand> {
        self.operands.first()
    }

    /// Return the first source operand (second operand), if any.
    #[must_use]
    pub fn src1(&self) -> Option<&GenericOperand> {
        self.operands.get(1)
    }

    /// Return the second source operand (third operand), if any.
    #[must_use]
    pub fn src2(&self) -> Option<&GenericOperand> {
        self.operands.get(2)
    }

    /// Return all memory operands.
    pub fn memory_operands(&self) -> impl Iterator<Item = &GenericOperand> {
        self.operands.iter().filter(|op| op.is_memory())
    }

    /// Return `true` if this instruction reads from memory.
    #[must_use]
    pub fn reads_memory(&self) -> bool {
        self.operands.iter().any(GenericOperand::is_memory)
    }

    /// Byte length of the encoded instruction.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if this instruction has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Normalizer rule set
// ---------------------------------------------------------------------------

/// A single mapping rule from a raw mnemonic prefix to a generic opcode.
#[derive(Debug, Clone)]
struct MnemonicRule {
    /// The mnemonic prefix to match (case-insensitive).
    prefix: String,
    /// The resulting generic opcode.
    opcode: GenericOpcode,
}

/// Strategy for mapping register names across ISAs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAliasMap {
    /// Source register name → normalized name.
    pub map: HashMap<String, String>,
}

impl RegisterAliasMap {
    #[must_use]
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn insert(&mut self, src: impl Into<String>, normalized: impl Into<String>) {
        self.map.insert(src.into(), normalized.into());
    }

    #[must_use]
    pub fn resolve<'a>(&'a self, name: &'a str) -> &'a str {
        self.map.get(name).map_or(name, String::as_str)
    }
}

impl Default for RegisterAliasMap {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// CrossArchNormalizer
// ---------------------------------------------------------------------------

/// Configuration controlling normalization behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizerConfig {
    /// Attempt to classify all instructions, including unknown ones.
    pub classify_unknown: bool,
    /// Include security annotations (Spectre, etc.).
    pub annotate_security: bool,
    /// Propagate endianness into Memory operands.
    pub annotate_endian: bool,
    /// Pointer size used when widths cannot be inferred from context.
    pub default_ptr_width: BitWidth,
    /// Maximum number of operands to normalize per instruction.
    pub max_operands: usize,
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        Self {
            classify_unknown:  true,
            annotate_security: false,
            annotate_endian:   false,
            default_ptr_width: BitWidth::W64,
            max_operands:      8,
        }
    }
}

/// Statistics accumulated over a normalization pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NormalizerStats {
    pub total_instructions: u32,
    pub successfully_classified: u32,
    pub unknown_opcodes: u32,
    pub branches_found: u32,
    pub memory_accesses: u32,
    pub simd_instructions: u32,
    pub crypto_instructions: u32,
    pub atomic_instructions: u32,
}

impl NormalizerStats {
    fn record(&mut self, insn: &NormalizedInsn) {
        self.total_instructions += 1;
        if insn.opcode == GenericOpcode::Unknown {
            self.unknown_opcodes += 1;
        } else {
            self.successfully_classified += 1;
        }
        if insn.is_branch { self.branches_found += 1; }
        if insn.reads_memory() { self.memory_accesses += 1; }
        if matches!(insn.opcode,
            GenericOpcode::VecAdd | GenericOpcode::VecSub | GenericOpcode::VecMul |
            GenericOpcode::VecShuffle | GenericOpcode::VecBroadcast |
            GenericOpcode::VecExtract | GenericOpcode::VecInsert |
            GenericOpcode::VecCompare) {
            self.simd_instructions += 1;
        }
        if matches!(insn.opcode,
            GenericOpcode::AesEnc | GenericOpcode::AesDec |
            GenericOpcode::Sha1   | GenericOpcode::Sha256 |
            GenericOpcode::CarrylessMultiply) {
            self.crypto_instructions += 1;
        }
        if insn.is_atomic { self.atomic_instructions += 1; }
    }

    /// Classification rate in [0.0, 1.0].
    #[must_use]
    pub fn classification_rate(&self) -> f64 {
        if self.total_instructions == 0 { return 1.0; }
        f64::from(self.successfully_classified) / f64::from(self.total_instructions)
    }
}

/// Maps architecture-specific instructions to the generic [`NormalizedInsn`] IR.
///
/// One `CrossArchNormalizer` instance may be shared across threads via `Arc`.
pub struct CrossArchNormalizer {
    /// Architecture backend used to decode raw bytes.
    arch: Arc<dyn Architecture>,
    /// Mnemonic-based classification rules (checked in order).
    rules: Vec<MnemonicRule>,
    /// Register alias maps keyed by architecture name.
    aliases: HashMap<String, RegisterAliasMap>,
    /// Endianness of the target.
    endian: Endian,
    /// Normalizer configuration.
    config: NormalizerConfig,
    /// Running statistics.
    stats: std::sync::Mutex<NormalizerStats>,
}

impl CrossArchNormalizer {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new normalizer for the given architecture backend.
    pub fn new(arch: Arc<dyn Architecture>, endian: Endian) -> Self {
        let rules = Self::default_rules();
        Self {
            arch,
            rules,
            aliases: HashMap::new(),
            endian,
            config: NormalizerConfig::default(),
            stats: std::sync::Mutex::new(NormalizerStats::default()),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(arch: Arc<dyn Architecture>, endian: Endian, config: NormalizerConfig) -> Self {
        let mut n = Self::new(arch, endian);
        n.config = config;
        n
    }
    /// Endianness of the target.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Add a register alias mapping for the named architecture.
    pub fn add_alias_map(&mut self, arch_name: impl Into<String>, map: RegisterAliasMap) {
        self.aliases.insert(arch_name.into(), map);
    }

    /// Add a custom classification rule at a specific priority position.
    pub fn add_rule_at(&mut self, pos: usize, prefix: impl Into<String>, opcode: GenericOpcode) {
        let rule = MnemonicRule { prefix: prefix.into().to_lowercase(), opcode };
        self.rules.insert(pos.min(self.rules.len()), rule);
    }

    /// Append a custom classification rule at the lowest priority.
    pub fn add_rule(&mut self, prefix: impl Into<String>, opcode: GenericOpcode) {
        self.rules.push(MnemonicRule {
            prefix: prefix.into().to_lowercase(),
            opcode,
        });
    }

    // -----------------------------------------------------------------------
    // Normalization
    // -----------------------------------------------------------------------

    /// Normalize a single instruction at the given virtual address.
    ///
    /// The architecture backend decodes `bytes` and the normalizer maps the
    /// result to a [`NormalizedInsn`].
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is empty or the architecture backend fails
    /// to disassemble the byte slice.
    pub fn normalize_one(
        &self,
        address: u64,
        bytes: &[u8],
        _mode: crate::ArchMode,
    ) -> Result<NormalizedInsn> {
        if bytes.is_empty() {
            bail!("empty byte slice at {address:#x}");
        }
        let insn = self.arch.disassemble(crate::Address::new(address), bytes)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let normalized = self.map_instruction(address, bytes, &insn);
        if let Ok(mut s) = self.stats.lock() { s.record(&normalized); }
        Ok(normalized)
    }

    /// Normalize a contiguous buffer, returning all instructions up to
    /// `max_insns` (or until decoding fails).
    pub fn normalize_buffer(
        &self,
        start_address: u64,
        bytes: &[u8],
        mode: crate::ArchMode,
        max_insns: usize,
    ) -> Vec<NormalizedInsn> {
        let mut result = Vec::new();
        let mut offset = 0usize;
        let mut addr   = start_address;

        while offset < bytes.len() && result.len() < max_insns {
            let slice = &bytes[offset..];
            match self.normalize_one(addr, slice, mode) {
                Ok(norm) => {
                    let len: usize = norm.len().max(1);
                    offset += len;
                    addr = addr.wrapping_add(len as u64);
                    result.push(norm);
                }
                Err(_) => break,
            }
        }
        result
    }

    /// Normalize a pre-decoded instruction list (e.g. from a disassembler).
    pub fn normalize_many(
        &self,
        instructions: &[(u64, Vec<u8>, crate::ArchMode)],
    ) -> Vec<Result<NormalizedInsn>> {
        instructions
            .iter()
            .map(|(addr, bytes, mode)| self.normalize_one(*addr, bytes, *mode))
            .collect()
    }

    /// Return a snapshot of accumulated statistics.
    pub fn stats(&self) -> NormalizerStats {
        self.stats.lock().ok().as_deref().cloned().unwrap_or_default()
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        if let Ok(mut s) = self.stats.lock() { *s = NormalizerStats::default(); }
    }

    // -----------------------------------------------------------------------
    // Internal mapping
    // -----------------------------------------------------------------------

    fn map_instruction(
        &self,
        address: u64,
        bytes: &[u8],
        insn: &Instruction,
    ) -> NormalizedInsn {
        let mnemonic = insn.mnemonic.clone();
        let opcode   = self.classify_mnemonic(&mnemonic);
        let is_branch = matches!(opcode,
            GenericOpcode::Jump | GenericOpcode::JumpConditional |
            GenericOpcode::Call | GenericOpcode::Return |
            GenericOpcode::Syscall | GenericOpcode::SysReturn);

        let operands = self.parse_operands(insn, address);

        // Determine flags written/read from opcode class.
        let (flags_written, flags_read) = Self::infer_flags(&opcode, &mnemonic);

        // Implicit register inference (call/return → SP, RA etc.)
        let (implicit_writes, implicit_reads) = Self::infer_implicit_regs(&opcode);

        let terminates_block = matches!(opcode,
            GenericOpcode::Return | GenericOpcode::Halt |
            GenericOpcode::Jump | GenericOpcode::JumpConditional);

        let is_atomic = matches!(opcode,
            GenericOpcode::AtomicLoad | GenericOpcode::AtomicStore |
            GenericOpcode::AtomicExchange | GenericOpcode::AtomicCompareExchange |
            GenericOpcode::AtomicAdd)
            || mnemonic.starts_with("lock ");

        let security_notes = if self.config.annotate_security {
            Self::security_annotations(&opcode, &mnemonic)
        } else {
            Vec::new()
        };

        NormalizedInsn {
            address,
            bytes: bytes.to_vec(),
            raw_mnemonic: mnemonic,
            opcode,
            operands,
            flags_written,
            flags_read,
            implicit_writes,
            implicit_reads,
            is_branch,
            terminates_block,
            required_features: Vec::new(),
            is_atomic,
            security_notes,
        }
    }

    fn classify_mnemonic(&self, mnemonic: &str) -> GenericOpcode {
        let lower = mnemonic.to_lowercase();
        // Strip common prefixes (rep, lock, …) for matching.
        let stem = lower
            .trim_start_matches("rep ")
            .trim_start_matches("repz ")
            .trim_start_matches("repnz ")
            .trim_start_matches("lock ");

        for rule in &self.rules {
            if stem.starts_with(&rule.prefix) {
                return rule.opcode.clone();
            }
        }
        GenericOpcode::Unknown
    }

    fn parse_operands(&self, insn: &Instruction, _address: u64) -> Vec<GenericOperand> {
        // Decode the operand string from the instruction's operands field.
        let op_str = insn.operands.trim();
        if op_str.is_empty() { return Vec::new(); }

        op_str
            .split(',')
            .take(self.config.max_operands)
            .map(|s: &str| self.parse_single_operand(s.trim()))
            .collect()
    }

    fn parse_single_operand(&self, s: &str) -> GenericOperand {
        // Try immediate.
        if let Some(imm) = Self::try_parse_immediate(s) {
            return GenericOperand::Immediate {
                value: imm,
                width: self.config.default_ptr_width,
            };
        }
        // Try memory reference: starts with '[' or keyword like 'DWORD PTR'.
        if s.contains('[') {
            return self.parse_memory_operand(s);
        }
        // Branch targets (hex address).
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
            && let Ok(addr) = u64::from_str_radix(hex, 16)
        {
            return GenericOperand::BranchTarget { address: addr, is_relative: false };
        }
        // Register (anything else that isn't punctuation-heavy).
        let w = self.config.default_ptr_width;
        GenericOperand::Register { name: s.to_string(), width: w }
    }

    fn try_parse_immediate(s: &str) -> Option<i64> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            // Parse as u64 first to accept the full unsigned range, then
            // reinterpret the bit pattern as i64 (two's-complement semantics
            // are what callers expect for encoded immediates).
            u64::from_str_radix(&s[2..], 16).ok().map(|v| i64::from_ne_bytes(v.to_ne_bytes()))
        } else if s.starts_with('-') {
            s.parse::<i64>().ok()
        } else {
            // Decimal: parse as i64 directly to avoid silently wrapping values
            // larger than i64::MAX back into negative territory.
            s.parse::<i64>().ok()
        }
    }

    fn parse_memory_operand(&self, s: &str) -> GenericOperand {
        // Extract width hint from e.g. "DWORD PTR [...]".
        let width = if s.contains("BYTE")  { BitWidth::W8  }
        else if s.contains("WORD")  { BitWidth::W16 }
        else if s.contains("DWORD") { BitWidth::W32 }
        else if s.contains("QWORD") { BitWidth::W64 }
        else                        { self.config.default_ptr_width };

        // Extract bracket contents.
        let inner = match (s.find('['), s.rfind(']')) {
            (Some(a), Some(b)) if b > a => &s[a + 1..b],
            _ => return GenericOperand::Raw(s.to_string()),
        };

        // Segment override (e.g., "gs:").
        let (segment, inner) = inner.find(':').map_or_else(
            || (None, inner.trim()),
            |pos| (Some(inner[..pos].trim().to_string()), inner[pos + 1..].trim()),
        );

        // Displacement extraction.
        let (base_part, disp) = inner.rfind('+').map_or_else(
            || inner.rfind('-').map_or(
                (inner, 0i64),
                |pos| {
                    let rhs = inner[pos + 1..].trim();
                    Self::try_parse_immediate(rhs).map_or(
                        (inner, 0i64),
                        |d| (inner[..pos].trim(), -d),
                    )
                },
            ),
            |pos| {
                let rhs = inner[pos + 1..].trim();
                Self::try_parse_immediate(rhs).map_or(
                    (inner, 0i64),
                    |d| (inner[..pos].trim(), d),
                )
            },
        );

        GenericOperand::Memory {
            base: if base_part.is_empty() { None } else { Some(base_part.to_string()) },
            index: None,
            scale: 1,
            disp,
            width,
            segment,
        }
    }

    fn infer_flags(opcode: &GenericOpcode, mnemonic: &str) -> (Vec<String>, Vec<String>) {
        let written: Vec<String> = match opcode {
            GenericOpcode::Add | GenericOpcode::Sub | GenericOpcode::Compare
            | GenericOpcode::Test | GenericOpcode::And | GenericOpcode::Or
            | GenericOpcode::Xor => vec!["Z".into(), "N".into(), "C".into(), "V".into()],
            GenericOpcode::Move | GenericOpcode::Load => {
                if mnemonic.contains("flags") { vec!["Z".into(), "N".into(), "C".into(), "V".into()] }
                else { Vec::new() }
            }
            _ => Vec::new(),
        };
        let read: Vec<String> = match opcode {
            GenericOpcode::JumpConditional => vec!["Z".into(), "N".into(), "C".into(), "V".into()],
            _ => Vec::new(),
        };
        (written, read)
    }

    fn infer_implicit_regs(opcode: &GenericOpcode) -> (Vec<String>, Vec<String>) {
        match opcode {
            GenericOpcode::Call => (vec!["SP".into()], vec!["SP".into(), "PC".into()]),
            GenericOpcode::Return => (vec!["PC".into()], vec!["SP".into()]),
            GenericOpcode::Push | GenericOpcode::Pop => (vec!["SP".into()], vec!["SP".into()]),
            GenericOpcode::Syscall | GenericOpcode::SysReturn =>
                (vec!["PC".into()], vec!["PC".into()]),
            _ => (Vec::new(), Vec::new()),
        }
    }

    fn security_annotations(opcode: &GenericOpcode, mnemonic: &str) -> Vec<String> {
        let mut notes = Vec::new();
        // Basic Spectre-v1 gadget heuristic: conditional branch following a load.
        if matches!(opcode, GenericOpcode::JumpConditional) {
            notes.push("potential Spectre-v1 gadget (speculative branch)".into());
        }
        if mnemonic.starts_with("ret") {
            notes.push("potential Spectre-v2/SpectreRSB gadget (return site)".into());
        }
        if matches!(opcode, GenericOpcode::AtomicExchange | GenericOpcode::AtomicCompareExchange) {
            notes.push("atomic RMW — verify lock-free correctness".into());
        }
        notes
    }

    // -----------------------------------------------------------------------
    // Default rule table
    // -----------------------------------------------------------------------

    fn default_rules() -> Vec<MnemonicRule> {
        let mut rules = Self::default_rules_control_flow();
        rules.extend(Self::default_rules_data_and_arith());
        rules.extend(Self::default_rules_simd_and_special());
        rules
    }

    fn default_rules_control_flow() -> Vec<MnemonicRule> {
        macro_rules! rule {
            ($p:expr, $op:expr) => { MnemonicRule { prefix: $p.into(), opcode: $op } };
        }
        vec![
            rule!("ret",     GenericOpcode::Return),
            rule!("bl",      GenericOpcode::Call),
            rule!("call",    GenericOpcode::Call),
            rule!("jmp",     GenericOpcode::Jump),
            rule!("b ",      GenericOpcode::Jump),
            rule!("bx ",     GenericOpcode::Jump),
            rule!("j",       GenericOpcode::JumpConditional),
            rule!("b.",      GenericOpcode::JumpConditional),
            rule!("cbz",     GenericOpcode::JumpConditional),
            rule!("cbnz",    GenericOpcode::JumpConditional),
            rule!("tb",      GenericOpcode::JumpConditional),
            rule!("syscall", GenericOpcode::Syscall),
            rule!("svc",     GenericOpcode::Syscall),
            rule!("int ",    GenericOpcode::Syscall),
            rule!("ecall",   GenericOpcode::Syscall),
            rule!("sysret",  GenericOpcode::SysReturn),
            rule!("eret",    GenericOpcode::SysReturn),
            rule!("hlt",     GenericOpcode::Halt),
            rule!("ud2",     GenericOpcode::Halt),
            rule!("nop",     GenericOpcode::Nop),
            rule!("hint",    GenericOpcode::Nop),
        ]
    }

    fn default_rules_data_and_arith() -> Vec<MnemonicRule> {
        macro_rules! rule {
            ($p:expr, $op:expr) => { MnemonicRule { prefix: $p.into(), opcode: $op } };
        }
        vec![
            rule!("mov",  GenericOpcode::Move),
            rule!("ldr",  GenericOpcode::Load),
            rule!("ldm",  GenericOpcode::Load),
            rule!("ld",   GenericOpcode::Load),
            rule!("str ", GenericOpcode::Store),
            rule!("stm",  GenericOpcode::Store),
            rule!("st",   GenericOpcode::Store),
            rule!("push", GenericOpcode::Push),
            rule!("pop",  GenericOpcode::Pop),
            rule!("xchg", GenericOpcode::Exchange),
            rule!("add",  GenericOpcode::Add),
            rule!("adc",  GenericOpcode::Add),
            rule!("sub",  GenericOpcode::Sub),
            rule!("sbc",  GenericOpcode::Sub),
            rule!("mul",  GenericOpcode::Mul),
            rule!("imul", GenericOpcode::Mul),
            rule!("umul", GenericOpcode::Mul),
            rule!("div",  GenericOpcode::Div),
            rule!("idiv", GenericOpcode::Div),
            rule!("udiv", GenericOpcode::Div),
            rule!("sdiv", GenericOpcode::Div),
            rule!("mod",  GenericOpcode::Mod),
            rule!("rem",  GenericOpcode::Mod),
            rule!("neg",  GenericOpcode::Neg),
            rule!("abs",  GenericOpcode::Abs),
            rule!("and",  GenericOpcode::And),
            rule!("tst",  GenericOpcode::Test),
            rule!("orr",  GenericOpcode::Or),
            rule!("or ",  GenericOpcode::Or),
            rule!("eor",  GenericOpcode::Xor),
            rule!("xor",  GenericOpcode::Xor),
            rule!("not",  GenericOpcode::Not),
            rule!("mvn",  GenericOpcode::Not),
            rule!("shl",  GenericOpcode::Shl),
            rule!("sal",  GenericOpcode::Shl),
            rule!("lsl",  GenericOpcode::Shl),
            rule!("shr",  GenericOpcode::Shr),
            rule!("lsr",  GenericOpcode::Shr),
            rule!("sar",  GenericOpcode::Sar),
            rule!("asr",  GenericOpcode::Sar),
            rule!("rol",  GenericOpcode::Rol),
            rule!("ror",  GenericOpcode::Ror),
            rule!("cmp",  GenericOpcode::Compare),
            rule!("cmn",  GenericOpcode::Compare),
            rule!("test", GenericOpcode::Test),
            rule!("fadd", GenericOpcode::FAdd),
            rule!("fsub", GenericOpcode::FSub),
            rule!("fmul", GenericOpcode::FMul),
            rule!("fdiv", GenericOpcode::FDiv),
            rule!("fcvt", GenericOpcode::FConvert),
            rule!("cvt",  GenericOpcode::FConvert),
            rule!("fcmp", GenericOpcode::FCompare),
        ]
    }

    fn default_rules_simd_and_special() -> Vec<MnemonicRule> {
        macro_rules! rule {
            ($p:expr, $op:expr) => { MnemonicRule { prefix: $p.into(), opcode: $op } };
        }
        vec![
            rule!("vadd",       GenericOpcode::VecAdd),
            rule!("vsub",       GenericOpcode::VecSub),
            rule!("vmul",       GenericOpcode::VecMul),
            rule!("vpshuf",     GenericOpcode::VecShuffle),
            rule!("vbroadcast", GenericOpcode::VecBroadcast),
            rule!("vextract",   GenericOpcode::VecExtract),
            rule!("vinsert",    GenericOpcode::VecInsert),
            rule!("vpcmp",      GenericOpcode::VecCompare),
            rule!("ldrex",      GenericOpcode::AtomicLoad),
            rule!("strex",      GenericOpcode::AtomicStore),
            rule!("ldxr",       GenericOpcode::AtomicLoad),
            rule!("stxr",       GenericOpcode::AtomicStore),
            rule!("xadd",       GenericOpcode::AtomicAdd),
            rule!("cmpxchg",    GenericOpcode::AtomicCompareExchange),
            rule!("sc.",        GenericOpcode::AtomicStore),
            rule!("ll.",        GenericOpcode::AtomicLoad),
            rule!("bsr",        GenericOpcode::BitScan),
            rule!("bsf",        GenericOpcode::BitScan),
            rule!("popcnt",     GenericOpcode::BitCount),
            rule!("cnt",        GenericOpcode::BitCount),
            rule!("lzcnt",      GenericOpcode::Clz),
            rule!("clz",        GenericOpcode::Clz),
            rule!("tzcnt",      GenericOpcode::Ctz),
            rule!("ctz",        GenericOpcode::Ctz),
            rule!("rbit",       GenericOpcode::BitScan),
            rule!("aesenc",     GenericOpcode::AesEnc),
            rule!("aesdec",     GenericOpcode::AesDec),
            rule!("aesimc",     GenericOpcode::AesDec),
            rule!("sha1",       GenericOpcode::Sha1),
            rule!("sha256",     GenericOpcode::Sha256),
            rule!("pclmulqdq",  GenericOpcode::CarrylessMultiply),
            rule!("pmull",      GenericOpcode::CarrylessMultiply),
            rule!("mfence",     GenericOpcode::Barrier),
            rule!("sfence",     GenericOpcode::Barrier),
            rule!("lfence",     GenericOpcode::Barrier),
            rule!("dmb",        GenericOpcode::Barrier),
            rule!("dsb",        GenericOpcode::Barrier),
            rule!("isb",        GenericOpcode::Barrier),
            rule!("fence",      GenericOpcode::Barrier),
            rule!("prefetch",   GenericOpcode::Prefetch),
            rule!("prfm",       GenericOpcode::Prefetch),
            rule!("dcbt",       GenericOpcode::Prefetch),
        ]
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for [`CrossArchNormalizer`].
pub struct NormalizerBuilder {
    arch:    Arc<dyn Architecture>,
    endian:  Endian,
    config:  NormalizerConfig,
    aliases: HashMap<String, RegisterAliasMap>,
    extra_rules: Vec<(String, GenericOpcode)>,
}

impl NormalizerBuilder {
    pub fn new(arch: Arc<dyn Architecture>, endian: Endian) -> Self {
        Self {
            arch,
            endian,
            config: NormalizerConfig::default(),
            aliases: HashMap::new(),
            extra_rules: Vec::new(),
        }
    }

    #[must_use]
    pub const fn config(mut self, c: NormalizerConfig) -> Self { self.config = c; self }

    #[must_use]
    pub fn alias_map(mut self, arch_name: impl Into<String>, map: RegisterAliasMap) -> Self {
        self.aliases.insert(arch_name.into(), map);
        self
    }

    #[must_use]
    pub fn rule(mut self, prefix: impl Into<String>, opcode: GenericOpcode) -> Self {
        self.extra_rules.push((prefix.into(), opcode));
        self
    }

    #[must_use]
    pub fn build(self) -> CrossArchNormalizer {
        let mut n = CrossArchNormalizer::with_config(self.arch, self.endian, self.config);
        n.aliases = self.aliases;
        for (prefix, opcode) in self.extra_rules {
            n.add_rule(prefix, opcode);
        }
        n
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_width_roundtrip() {
        for bits in [8u32, 16, 32, 64, 128, 256, 512] {
            let w = BitWidth::from_bits(bits);
            assert_eq!(w.bits(), bits);
        }
    }

    #[test]
    fn bit_width_bytes() {
        assert_eq!(BitWidth::W8.bytes(), 1);
        assert_eq!(BitWidth::W64.bytes(), 8);
        assert_eq!(BitWidth::Other(12).bytes(), 2);
    }

    #[test]
    fn generic_operand_width() {
        let op = GenericOperand::Immediate { value: 42, width: BitWidth::W32 };
        assert_eq!(op.width(), Some(BitWidth::W32));
        assert!(!op.is_memory());
        assert!(!op.is_branch_target());
    }

    #[test]
    fn normalized_insn_accessors() {
        let insn = NormalizedInsn::unknown(0x1000, vec![0x90], "nop");
        assert_eq!(insn.len(), 1);
        assert!(insn.dst().is_none());
        assert_eq!(insn.opcode, GenericOpcode::Unknown);
    }

    #[test]
    fn normalizer_stats_rate() {
        let s = NormalizerStats {
            total_instructions: 10,
            successfully_classified: 8,
            ..Default::default()
        };
        let rate = s.classification_rate();
        assert!((rate - 0.8).abs() < 1e-9);
    }

    #[test]
    fn try_parse_immediate_hex() {
        assert_eq!(CrossArchNormalizer::try_parse_immediate("0x1a2b"), Some(0x1a2b));
        assert_eq!(CrossArchNormalizer::try_parse_immediate("-5"), Some(-5));
        assert_eq!(CrossArchNormalizer::try_parse_immediate("255"), Some(255));
        assert_eq!(CrossArchNormalizer::try_parse_immediate("rax"), None);
    }

    #[test]
    fn register_alias_map_resolve() {
        let mut m = RegisterAliasMap::new();
        m.insert("x0", "A0");
        assert_eq!(m.resolve("x0"), "A0");
        assert_eq!(m.resolve("x1"), "x1");
    }
}
