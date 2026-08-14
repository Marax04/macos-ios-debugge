//! Virtual ISA Reconstruction
//!
//! Recovers the virtual instruction set architecture (ISA) of a VM-protected binary:
//! - [`VirtualInstruction`] — a decoded virtual instruction with operands
//! - [`VirtualIsa`] — the full recovered ISA (opcode → semantics map)
//! - [`HandlerTableRecovery`] — extracts handler addresses from dispatch tables
//! - [`DispatchTableAnalyzer`] — analyses dispatch table layouts
//! - [`OpcodeFingerprintAnalyzer`] — fingerprints handler prologues to assign opcodes
//! - [`IsaGraphBuilder`] — builds a directed graph of ISA-level relationships

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during ISA reconstruction.
#[derive(Debug, Error)]
pub enum IsaReconstructionError {
    #[error("handler table is too short: need at least {need} bytes, got {got}")]
    TableTooShort { need: usize, got: usize },

    #[error("opcode {opcode:#04x} is already registered with a different semantic")]
    DuplicateOpcode { opcode: u8 },

    #[error("dispatch table base address {addr:#x} is out of range")]
    TableOutOfRange { addr: u64 },

    #[error("no handlers could be extracted from the table")]
    NoHandlers,

    #[error("ISA graph cycle detected at opcode {opcode:#04x}")]
    GraphCycle { opcode: u8 },

    #[error("fingerprint database is empty; cannot classify handlers")]
    EmptyFingerprintDb,
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand / VirtualInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of a virtual instruction operand.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VirtualOperand {
    /// Immediate integer constant (sign-extended to i64).
    Immediate(i64),
    /// Virtual register index.
    Register(u8),
    /// Memory reference via a virtual register.
    MemoryReg(u8),
    /// Memory reference at a fixed virtual address.
    MemoryAddr(u64),
    /// Relative branch offset from the current VIP.
    BranchOffset(i32),
    /// No operand (used for zero-operand instructions).
    None,
}

impl VirtualOperand {
    /// Return `true` if this operand is an immediate.
    #[must_use]
    pub const fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate(_))
    }

    /// Return `true` if this operand references a virtual register.
    #[must_use]
    pub const fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    /// Return the register index if applicable.
    #[must_use]
    pub const fn register_index(&self) -> Option<u8> {
        if let Self::Register(r) = self {
            Some(*r)
        } else {
            None
        }
    }
}

impl std::fmt::Display for VirtualOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Immediate(v) => write!(f, "#{v}"),
            Self::Register(r) => write!(f, "vr{r}"),
            Self::MemoryReg(r) => write!(f, "[vr{r}]"),
            Self::MemoryAddr(a) => write!(f, "[{a:#x}]"),
            Self::BranchOffset(o) => write!(f, "vip{o:+}"),
            Self::None => write!(f, "<none>"),
        }
    }
}

/// Semantic category of a virtual instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VirtualOpCategory {
    /// Stack push operations.
    Push,
    /// Stack pop operations.
    Pop,
    /// Arithmetic operations (add, sub, mul, div).
    Arithmetic,
    /// Bitwise / logical operations (and, or, xor, not, shl, shr).
    Logic,
    /// Memory load.
    Load,
    /// Memory store.
    Store,
    /// Unconditional branch.
    Jump,
    /// Conditional branch.
    CondBranch,
    /// Subroutine call.
    Call,
    /// Return from subroutine.
    Return,
    /// Compare / set-flags.
    Compare,
    /// No-operation.
    Nop,
    /// VM exit / halt.
    Halt,
    /// Unclassified.
    Unknown,
}

impl VirtualOpCategory {
    /// Returns `true` if the category affects control flow.
    #[must_use]
    pub const fn is_control_flow(self) -> bool {
        matches!(
            self,
            Self::Jump | Self::CondBranch | Self::Call | Self::Return | Self::Halt
        )
    }

    /// Returns `true` if the category reads or writes memory.
    #[must_use]
    pub const fn touches_memory(self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Push => "PUSH",
            Self::Pop => "POP",
            Self::Arithmetic => "ARITH",
            Self::Logic => "LOGIC",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Jump => "JMP",
            Self::CondBranch => "JCC",
            Self::Call => "CALL",
            Self::Return => "RET",
            Self::Compare => "CMP",
            Self::Nop => "NOP",
            Self::Halt => "HALT",
            Self::Unknown => "???",
        }
    }
}

/// A single decoded virtual instruction (ISA-level, not native x86).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualInstruction {
    /// Raw opcode byte fetched from the bytecode stream.
    pub opcode: u8,
    /// Semantic category (recovered from handler analysis).
    pub category: VirtualOpCategory,
    /// Operands decoded from the bytecode stream.
    pub operands: Vec<VirtualOperand>,
    /// Virtual instruction pointer (offset into the bytecode blob).
    pub vip: u64,
    /// Total size in bytes of this instruction including operands.
    pub size: u8,
    /// Native address of the VM handler that implements this opcode.
    pub handler_addr: u64,
    /// Human-readable mnemonic (recovered or synthesised).
    pub mnemonic: String,
}

impl VirtualInstruction {
    /// Construct a new virtual instruction.
    pub fn new(
        opcode: u8,
        category: VirtualOpCategory,
        operands: Vec<VirtualOperand>,
        vip: u64,
        size: u8,
        handler_addr: u64,
        mnemonic: impl Into<String>,
    ) -> Self {
        Self {
            opcode,
            category,
            operands,
            vip,
            size,
            handler_addr,
            mnemonic: mnemonic.into(),
        }
    }

    /// Returns `true` if this instruction terminates a virtual basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        self.category.is_control_flow()
    }

    /// Returns `true` if this instruction uses no operands.
    #[must_use]
    pub fn is_zero_operand(&self) -> bool {
        self.operands.is_empty()
            || self
                .operands
                .iter()
                .all(|o| matches!(o, VirtualOperand::None))
    }

    /// Pretty-print as disassembly line.
    #[must_use]
    pub fn display(&self) -> String {
        let ops: Vec<String> = self
            .operands
            .iter()
            .filter(|o| !matches!(o, VirtualOperand::None))
            .map(ToString::to_string)
            .collect();
        if ops.is_empty() {
            format!("{:#x}: {:>8}", self.vip, self.mnemonic)
        } else {
            format!(
                "{:#x}: {:>8}  {}",
                self.vip,
                self.mnemonic,
                ops.join(", ")
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualIsaEntry / VirtualIsa
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the recovered virtual ISA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualIsaEntry {
    /// The opcode byte value.
    pub opcode: u8,
    /// Semantic category.
    pub category: VirtualOpCategory,
    /// Canonical mnemonic string.
    pub mnemonic: String,
    /// Number of operands this opcode takes from the bytecode stream.
    pub operand_count: u8,
    /// Total byte size (1 opcode byte + operand bytes).
    pub total_size: u8,
    /// Native address of the handler implementing this opcode.
    pub handler_addr: u64,
    /// How many times this opcode has been observed in the bytecode stream.
    pub frequency: u32,
    /// Confidence score from fingerprint matching [0.0, 1.0].
    pub confidence: f32,
}

impl VirtualIsaEntry {
    /// Create a new ISA entry.
    pub fn new(
        opcode: u8,
        category: VirtualOpCategory,
        mnemonic: impl Into<String>,
        operand_count: u8,
        total_size: u8,
        handler_addr: u64,
        confidence: f32,
    ) -> Self {
        Self {
            opcode,
            category,
            mnemonic: mnemonic.into(),
            operand_count,
            total_size,
            handler_addr,
            frequency: 0,
            confidence,
        }
    }

    /// Returns `true` if this entry is a control-flow instruction.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        self.category.is_control_flow()
    }
}

/// The full recovered Virtual ISA.
///
/// Maps opcode bytes to their semantic entries. Also tracks metadata such as
/// the total number of handlers observed and the estimated bitness of the VM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualIsa {
    /// Sorted map of opcode → entry.
    pub entries: BTreeMap<u8, VirtualIsaEntry>,
    /// Estimated VM bitness (32 or 64).
    pub vm_bitness: u8,
    /// Whether operands use little-endian byte order.
    pub little_endian: bool,
    /// Name of the detected protector (if known).
    pub protector_hint: Option<String>,
    /// Total instructions decoded during ISA recovery.
    pub total_decoded: u64,
}

impl VirtualIsa {
    /// Create a new empty ISA.
    #[must_use]
    pub const fn new(vm_bitness: u8, little_endian: bool) -> Self {
        Self {
            entries: BTreeMap::new(),
            vm_bitness,
            little_endian,
            protector_hint: None,
            total_decoded: 0,
        }
    }

    /// Register an ISA entry. Returns an error if the opcode is already registered
    /// with a different category.
    ///
    /// # Errors
    /// Returns [`IsaReconstructionError::DuplicateOpcode`] if the opcode is already
    /// registered with a different category.
    pub fn register(&mut self, entry: VirtualIsaEntry) -> Result<(), IsaReconstructionError> {
        if let Some(existing) = self.entries.get(&entry.opcode) {
            if existing.category != entry.category {
                return Err(IsaReconstructionError::DuplicateOpcode {
                    opcode: entry.opcode,
                });
            }
            // Same category — update frequency only.
            return Ok(());
        }
        self.entries.insert(entry.opcode, entry);
        Ok(())
    }

    /// Look up an ISA entry by opcode byte.
    #[must_use]
    pub fn lookup(&self, opcode: u8) -> Option<&VirtualIsaEntry> {
        self.entries.get(&opcode)
    }

    /// Number of distinct opcodes in the ISA.
    #[must_use]
    pub fn opcode_count(&self) -> usize {
        self.entries.len()
    }

    /// Increment the frequency counter for an opcode.
    pub fn inc_frequency(&mut self, opcode: u8) {
        if let Some(e) = self.entries.get_mut(&opcode) {
            e.frequency += 1;
        }
        self.total_decoded += 1;
    }

    /// Return all control-flow opcodes.
    #[must_use]
    pub fn control_flow_opcodes(&self) -> Vec<&VirtualIsaEntry> {
        self.entries
            .values()
            .filter(|e| e.is_control_flow())
            .collect()
    }

    /// Return average confidence across all entries.
    #[must_use]
    pub fn average_confidence(&self) -> f32 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.entries.values().map(|e| e.confidence).sum();
        sum / f32::from(u16::try_from(self.entries.len()).unwrap_or(u16::MAX))
    }

    /// Return a human-readable summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}-bit {} VM, {} opcodes, avg confidence {:.0}%",
            self.vm_bitness,
            if self.little_endian { "LE" } else { "BE" },
            self.opcode_count(),
            self.average_confidence() * 100.0,
        )
    }

    /// Merge another ISA into this one (frequencies accumulate, higher confidence wins).
    pub fn merge(&mut self, other: &Self) {
        for (opcode, entry) in &other.entries {
            if let Some(existing) = self.entries.get_mut(opcode) {
                existing.frequency += entry.frequency;
                if entry.confidence > existing.confidence {
                    existing.confidence = entry.confidence;
                }
            } else {
                self.entries.insert(*opcode, entry.clone());
            }
        }
        self.total_decoded += other.total_decoded;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerTableRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Result of recovering one row from a handler dispatch table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerTableEntry {
    /// Opcode index (row index in the table).
    pub index: usize,
    /// Absolute virtual address of the handler.
    pub handler_va: u64,
    /// Raw bytes of the handler's prologue (up to 32 bytes of code).
    pub prologue_bytes: Vec<u8>,
    /// Whether the entry looks like a valid function pointer (non-null, plausible range).
    pub is_valid: bool,
}

impl HandlerTableEntry {
    fn new(index: usize, handler_va: u64, prologue_bytes: Vec<u8>) -> Self {
        // Heuristic validity: non-zero VA and in a plausible executable address range.
        let is_valid =
            handler_va != 0 && (0x1000..0xFFFF_FFFF_0000_0000u64).contains(&handler_va);
        Self {
            index,
            handler_va,
            prologue_bytes,
            is_valid,
        }
    }
}

/// Recovers a handler dispatch table from raw binary data.
///
/// Supports both 32-bit (4-byte pointer) and 64-bit (8-byte pointer) tables.
#[derive(Debug, Clone)]
pub struct HandlerTableRecovery {
    /// Image base address (added to relative offsets).
    pub image_base: u64,
    /// Pointer size in bytes (4 or 8).
    pub pointer_size: u8,
    /// Maximum plausible number of handlers (sanity cap).
    pub max_handlers: usize,
    /// Minimum plausible handler count before we reject the table.
    pub min_handlers: usize,
    /// Number of prologue bytes to copy from each handler.
    pub prologue_len: usize,
}

impl HandlerTableRecovery {
    /// Create a 64-bit recovery engine.
    #[must_use]
    pub const fn new_64bit(image_base: u64) -> Self {
        Self {
            image_base,
            pointer_size: 8,
            max_handlers: 512,
            min_handlers: 4,
            prologue_len: 32,
        }
    }

    /// Create a 32-bit recovery engine.
    #[must_use]
    pub const fn new_32bit(image_base: u64) -> Self {
        Self {
            image_base,
            pointer_size: 4,
            max_handlers: 512,
            min_handlers: 4,
            prologue_len: 32,
        }
    }

    /// Extract the handler table starting at `table_offset` in `binary`.
    ///
    /// `count` is the expected number of entries. If `None`, the method tries to
    /// auto-detect the count by scanning for valid-looking pointer runs.
    ///
    /// # Errors
    /// Returns [`IsaReconstructionError::TableTooShort`] if `table_offset` is out of bounds,
    /// or [`IsaReconstructionError::NoHandlers`] if fewer than `min_handlers` valid entries
    /// are found.
    pub fn extract(
        &self,
        binary: &[u8],
        table_offset: usize,
        count: Option<usize>,
    ) -> Result<Vec<HandlerTableEntry>, IsaReconstructionError> {
        let ptr_size = self.pointer_size as usize;
        let required = ptr_size;
        if table_offset >= binary.len() || binary.len() - table_offset < required {
            return Err(IsaReconstructionError::TableTooShort {
                need: required,
                got: binary.len().saturating_sub(table_offset),
            });
        }

        let max_count = count.unwrap_or_else(|| self.auto_detect_count(binary, table_offset));
        let max_count = max_count.min(self.max_handlers);

        let mut entries = Vec::with_capacity(max_count);

        for i in 0..max_count {
            let offset = table_offset + i * ptr_size;
            if offset + ptr_size > binary.len() {
                break;
            }

            let raw_va = if ptr_size == 8 {
                u64::from_le_bytes(binary[offset..offset + 8].try_into().unwrap_or([0u8; 8]))
            } else {
                u64::from(u32::from_le_bytes(binary[offset..offset + 4].try_into().unwrap_or([0u8; 4])))
            };

            // Convert from VA to file offset (simplified: assume flat mapping from image_base).
            let prologue = if raw_va >= self.image_base {
                let file_off = usize::try_from(raw_va - self.image_base).unwrap_or(usize::MAX);
                if file_off < binary.len() {
                    let end = (file_off + self.prologue_len).min(binary.len());
                    binary[file_off..end].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            entries.push(HandlerTableEntry::new(i, raw_va, prologue));
        }

        let valid_count = entries.iter().filter(|e| e.is_valid).count();
        if valid_count < self.min_handlers {
            return Err(IsaReconstructionError::NoHandlers);
        }

        Ok(entries)
    }

    /// Auto-detect the number of contiguous valid pointer entries.
    fn auto_detect_count(&self, binary: &[u8], table_offset: usize) -> usize {
        let ptr_size = self.pointer_size as usize;
        let mut count = 0;
        let mut pos = table_offset;
        while pos + ptr_size <= binary.len() && count < self.max_handlers {
            let raw_va = if ptr_size == 8 {
                u64::from_le_bytes(binary[pos..pos + 8].try_into().unwrap_or([0u8; 8]))
            } else {
                u64::from(u32::from_le_bytes(binary[pos..pos + 4].try_into().unwrap_or([0u8; 4])))
            };
            if raw_va < self.image_base || raw_va == 0 {
                break;
            }
            count += 1;
            pos += ptr_size;
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatchTableAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Layout kind of a dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchTableLayout {
    /// Dense array of pointers indexed directly by opcode byte.
    DirectPointerArray,
    /// Sparse table with `(opcode, handler_va)` pairs.
    SparsePairs,
    /// Two-level indirection: outer index → inner table.
    TwoLevel,
    /// Encoded: each entry is a RVA or relative displacement.
    RelativeDisplacement,
    /// Unknown layout.
    Unknown,
}

/// Analysis result for a dispatch table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchTableAnalysis {
    /// Detected layout.
    pub layout: DispatchTableLayout,
    /// Number of valid entries detected.
    pub entry_count: usize,
    /// Address of the first valid entry.
    pub first_entry_va: u64,
    /// Address of the last valid entry.
    pub last_entry_va: u64,
    /// Estimated opcode range covered.
    pub opcode_range: std::ops::RangeInclusive<u8>,
    /// Whether entries appear to be encrypted/obfuscated.
    pub appears_encrypted: bool,
    /// Confidence in the detected layout [0.0, 1.0].
    pub layout_confidence: f32,
}

/// Analyses dispatch table layouts in binary data.
#[derive(Debug, Clone, Default)]
pub struct DispatchTableAnalyzer;

impl DispatchTableAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse the dispatch table starting at `offset` in `binary`.
    #[must_use]
    pub fn analyze(
        &self,
        binary: &[u8],
        offset: usize,
        image_base: u64,
        ptr_size: u8,
    ) -> DispatchTableAnalysis {
        let mut analysis = DispatchTableAnalysis {
            layout: DispatchTableLayout::Unknown,
            entry_count: 0,
            first_entry_va: 0,
            last_entry_va: 0,
            opcode_range: 0..=255,
            appears_encrypted: false,
            layout_confidence: 0.0,
        };

        let psize = ptr_size as usize;
        if psize == 0 || offset >= binary.len() {
            return analysis;
        }

        // Collect raw pointer values from the table.
        let mut vas: Vec<u64> = Vec::new();
        let mut pos = offset;
        while pos + psize <= binary.len() && vas.len() < 512 {
            let va = if psize == 8 {
                u64::from_le_bytes(binary[pos..pos + 8].try_into().unwrap_or([0u8; 8]))
            } else {
                u64::from(u32::from_le_bytes(binary[pos..pos + 4].try_into().unwrap_or([0u8; 4])))
            };
            if va == 0 && vas.len() > 8 {
                break;
            }
            vas.push(va);
            pos += psize;
        }

        if vas.is_empty() {
            return analysis;
        }

        // Filter valid-looking VAs.
        let valid_vas: Vec<u64> = vas
            .iter()
            .copied()
            .filter(|&v| v >= image_base && v < image_base + 0x1000_0000)
            .collect();

        analysis.entry_count = valid_vas.len();
        analysis.first_entry_va = valid_vas.iter().copied().min().unwrap_or(0);
        analysis.last_entry_va = valid_vas.iter().copied().max().unwrap_or(0);

        // Determine layout.
        let total_count = vas.len();
        let valid_ratio = f32::from(u16::try_from(valid_vas.len()).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(total_count.max(1)).unwrap_or(u16::MAX));

        if valid_ratio > 0.85 && total_count <= 256 {
            analysis.layout = DispatchTableLayout::DirectPointerArray;
            analysis.layout_confidence = valid_ratio;
            let n = total_count.min(256);
            analysis.opcode_range = 0..=u8::try_from(n.saturating_sub(1)).unwrap_or(u8::MAX);
        } else if valid_ratio > 0.50 {
            analysis.layout = DispatchTableLayout::SparsePairs;
            analysis.layout_confidence = valid_ratio * 0.8;
        } else {
            analysis.appears_encrypted = true;
            analysis.layout = DispatchTableLayout::Unknown;
            analysis.layout_confidence = 0.2;
        }

        analysis
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeFingerprintAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// A fingerprint for a VM handler prologue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeFingerprint {
    /// Opcode byte this fingerprint maps to.
    pub opcode: u8,
    /// First N bytes of the handler (the "signature").
    pub prologue: Vec<u8>,
    /// Shannon entropy of the prologue.
    pub entropy: f64,
    /// Estimated semantic category from prologue heuristics.
    pub estimated_category: VirtualOpCategory,
    /// Hash of the prologue bytes.
    pub hash: u64,
}

impl OpcodeFingerprint {
    /// Build a fingerprint for a handler at `opcode` with the given prologue bytes.
    #[must_use]
    pub fn build(opcode: u8, prologue: &[u8]) -> Self {
        let entropy = compute_entropy(prologue);
        let hash = fnv1a_64(prologue);
        let estimated_category = classify_prologue(prologue);
        Self {
            opcode,
            prologue: prologue.to_vec(),
            entropy,
            estimated_category,
            hash,
        }
    }

    /// Hamming-distance-like similarity in [0.0, 1.0] against another fingerprint.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f32 {
        if self.prologue.is_empty() || other.prologue.is_empty() {
            return 0.0;
        }
        let len = self.prologue.len().min(other.prologue.len());
        let matching = self.prologue[..len]
            .iter()
            .zip(&other.prologue[..len])
            .filter(|&(&a, &b)| a == b)
            .count();
        f32::from(u16::try_from(matching).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(len).unwrap_or(u16::MAX))
    }
}

/// Analyses opcode fingerprints from a list of handler prologues to assign
/// semantic categories.
#[derive(Debug, Clone, Default)]
pub struct OpcodeFingerprintAnalyzer {
    /// Known good fingerprints (from reference VMProtect/Themida samples).
    pub reference_fingerprints: Vec<OpcodeFingerprint>,
}

impl OpcodeFingerprintAnalyzer {
    /// Create a new analyzer with an empty fingerprint database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reference fingerprint to the database.
    pub fn add_reference(&mut self, fp: OpcodeFingerprint) {
        self.reference_fingerprints.push(fp);
    }

    /// Classify a set of handler prologues into [`VirtualIsaEntry`] items.
    ///
    /// Returns entries sorted by opcode byte.
    #[must_use]
    pub fn classify(&self, handler_entries: &[HandlerTableEntry]) -> Vec<VirtualIsaEntry> {
        handler_entries
            .iter()
            .filter(|e| e.is_valid)
            .map(|entry| {
                let idx_u8 = u8::try_from(entry.index).unwrap_or(u8::MAX);
                let fp = OpcodeFingerprint::build(idx_u8, &entry.prologue_bytes);
                let (category, confidence) = self.match_category(&fp);
                let mnemonic = format!("{}.{:02x}", category.name(), entry.index);

                VirtualIsaEntry::new(
                    idx_u8,
                    category,
                    mnemonic,
                    0, // operand count unknown at this stage
                    1, // minimum size
                    entry.handler_va,
                    confidence,
                )
            })
            .collect()
    }

    /// Match a fingerprint against the reference database and return
    /// the best-matching category and confidence.
    fn match_category(&self, fp: &OpcodeFingerprint) -> (VirtualOpCategory, f32) {
        if self.reference_fingerprints.is_empty() {
            // Fall back to prologue heuristics when no reference DB is loaded.
            return (fp.estimated_category, 0.50);
        }

        let best = self
            .reference_fingerprints
            .iter()
            .map(|ref_fp| (ref_fp.estimated_category, fp.similarity(ref_fp)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        best.unwrap_or((VirtualOpCategory::Unknown, 0.0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IsaGraphBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge in the ISA graph (opcode → opcode flow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsaEdge {
    /// Source opcode.
    pub from: u8,
    /// Destination opcode (successor in observed bytecode stream).
    pub to: u8,
    /// Number of times this transition was observed.
    pub weight: u32,
}

/// A node in the ISA graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsaNode {
    /// Opcode byte.
    pub opcode: u8,
    /// Semantic category.
    pub category: VirtualOpCategory,
    /// Mnemonic.
    pub mnemonic: String,
    /// Number of times this opcode appeared in the bytecode stream.
    pub count: u32,
}

/// Builds a directed graph of ISA-level transitions from a decoded bytecode trace.
///
/// Each node is a distinct opcode; each directed edge represents an observed
/// opcode-to-opcode sequential (not branch-taken) transition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IsaGraph {
    /// Nodes indexed by opcode byte.
    pub nodes: HashMap<u8, IsaNode>,
    /// Directed transition edges.
    pub edges: Vec<IsaEdge>,
}

impl IsaGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or increment) an edge.
    pub fn add_edge(&mut self, from: u8, to: u8) {
        if let Some(edge) = self.edges.iter_mut().find(|e| e.from == from && e.to == to) {
            edge.weight += 1;
        } else {
            self.edges.push(IsaEdge {
                from,
                to,
                weight: 1,
            });
        }
    }

    /// Add (or increment) a node occurrence counter.
    pub fn add_node(&mut self, opcode: u8, category: VirtualOpCategory, mnemonic: &str) {
        let node = self.nodes.entry(opcode).or_insert_with(|| IsaNode {
            opcode,
            category,
            mnemonic: mnemonic.to_owned(),
            count: 0,
        });
        node.count += 1;
    }

    /// Total edge weight across all transitions.
    #[must_use]
    pub fn total_transitions(&self) -> u64 {
        self.edges.iter().map(|e| u64::from(e.weight)).sum()
    }

    /// Find the most commonly observed opcode.
    #[must_use]
    pub fn most_frequent_opcode(&self) -> Option<u8> {
        self.nodes
            .values()
            .max_by_key(|n| n.count)
            .map(|n| n.opcode)
    }

    /// Detect if any cycles exist (control-flow loops in the ISA graph).
    #[must_use]
    pub fn has_cycles(&self) -> bool {
        let all_opcodes: HashSet<u8> = self.nodes.keys().copied().collect();
        for &start in &all_opcodes {
            if self.dfs_has_cycle(start, &mut HashSet::new(), &mut HashSet::new()) {
                return true;
            }
        }
        false
    }

    fn dfs_has_cycle(&self, node: u8, visited: &mut HashSet<u8>, stack: &mut HashSet<u8>) -> bool {
        visited.insert(node);
        stack.insert(node);
        for edge in self.edges.iter().filter(|e| e.from == node) {
            if !visited.contains(&edge.to) {
                if self.dfs_has_cycle(edge.to, visited, stack) {
                    return true;
                }
            } else if stack.contains(&edge.to) {
                return true;
            }
        }
        stack.remove(&node);
        false
    }

    /// Export to DOT format for Graphviz.
    #[must_use]
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::from("digraph isa_graph {\n  rankdir=LR;\n");
        for node in self.nodes.values() {
            let _ = writeln!(
                s,
                "  op_{:02x} [label=\"{} ({})\\nx{}\" shape=box];",
                node.opcode,
                node.mnemonic,
                node.category.name(),
                node.count
            );
        }
        for edge in &self.edges {
            let _ = writeln!(
                s,
                "  op_{:02x} -> op_{:02x} [label=\"{}\"];",
                edge.from, edge.to, edge.weight
            );
        }
        s.push_str("}\n");
        s
    }
}

/// Builds an [`IsaGraph`] from a sequence of decoded [`VirtualInstruction`]s.
#[derive(Debug, Clone, Default)]
pub struct IsaGraphBuilder;

impl IsaGraphBuilder {
    /// Build an ISA transition graph from a decoded instruction stream.
    #[must_use]
    pub fn build(instructions: &[VirtualInstruction]) -> IsaGraph {
        let mut graph = IsaGraph::new();
        for insn in instructions {
            graph.add_node(insn.opcode, insn.category, &insn.mnemonic);
        }
        for pair in instructions.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            // Only add sequential edges; skip after terminators.
            if !a.is_terminator() {
                graph.add_edge(a.opcode, b.opcode);
            }
        }
        graph
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of a byte slice.
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Shannon entropy of a byte slice.
fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

/// Heuristic classification of a VM handler from its prologue bytes.
fn classify_prologue(bytes: &[u8]) -> VirtualOpCategory {
    if bytes.is_empty() {
        return VirtualOpCategory::Unknown;
    }

    // Detect RET-like instructions.
    if bytes.iter().any(|&b| b == 0xC3 || b == 0xC2) {
        return VirtualOpCategory::Return;
    }
    // Detect CALL-like pattern: E8 xx xx xx xx
    if bytes.windows(5).any(|w| w[0] == 0xE8) {
        return VirtualOpCategory::Call;
    }
    // Detect JMP-like: FF E0-E7, EB, E9
    if bytes.iter().any(|&b| b == 0xEB || b == 0xE9)
        || bytes
            .windows(2)
            .any(|w| w[0] == 0xFF && (0xE0..=0xE7).contains(&w[1]))
    {
        return VirtualOpCategory::Jump;
    }
    // Detect PUSH (50-57 or FF /6)
    if bytes.iter().any(|&b| (0x50..=0x57).contains(&b)) {
        return VirtualOpCategory::Push;
    }
    // Detect POP (58-5F)
    if bytes.iter().any(|&b| (0x58..=0x5F).contains(&b)) {
        return VirtualOpCategory::Pop;
    }
    // Detect XOR/AND/OR (logic)
    let logic_opcodes: &[u8] = &[0x31, 0x33, 0x21, 0x23, 0x09, 0x0B, 0xF7];
    if bytes.iter().any(|b| logic_opcodes.contains(b)) {
        return VirtualOpCategory::Logic;
    }
    // Detect ADD/SUB (arithmetic)
    let arith_opcodes: &[u8] = &[0x01, 0x03, 0x29, 0x2B, 0x69, 0xF7];
    if bytes.iter().any(|b| arith_opcodes.contains(b)) {
        return VirtualOpCategory::Arithmetic;
    }
    // Detect CMP (compare)
    if bytes.iter().any(|&b| b == 0x3B || b == 0x3C || b == 0x39) {
        return VirtualOpCategory::Compare;
    }
    // Detect MOV (load/store)
    if bytes.iter().any(|&b| b == 0x8B || b == 0x89) {
        return VirtualOpCategory::Load;
    }
    VirtualOpCategory::Unknown
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_operand_display() {
        assert_eq!(VirtualOperand::Immediate(42).to_string(), "#42");
        assert_eq!(VirtualOperand::Register(3).to_string(), "vr3");
        assert_eq!(VirtualOperand::MemoryReg(1).to_string(), "[vr1]");
        assert_eq!(VirtualOperand::BranchOffset(-8).to_string(), "vip-8");
    }

    #[test]
    fn test_virtual_operand_predicates() {
        assert!(VirtualOperand::Immediate(0).is_immediate());
        assert!(!VirtualOperand::Register(0).is_immediate());
        assert!(VirtualOperand::Register(5).is_register());
        assert_eq!(VirtualOperand::Register(7).register_index(), Some(7));
        assert_eq!(VirtualOperand::Immediate(0).register_index(), None);
    }

    #[test]
    fn test_virtual_op_category() {
        assert!(VirtualOpCategory::Jump.is_control_flow());
        assert!(VirtualOpCategory::Return.is_control_flow());
        assert!(!VirtualOpCategory::Arithmetic.is_control_flow());
        assert!(VirtualOpCategory::Load.touches_memory());
        assert!(!VirtualOpCategory::Arithmetic.touches_memory());
    }

    #[test]
    fn test_virtual_instruction_display() {
        let insn = VirtualInstruction::new(
            0x10,
            VirtualOpCategory::Arithmetic,
            vec![VirtualOperand::Register(0), VirtualOperand::Register(1)],
            0x100,
            1,
            0xDEAD,
            "ADD",
        );
        let d = insn.display();
        assert!(d.contains("ADD"));
        assert!(d.contains("0x100"));
    }

    #[test]
    fn test_virtual_isa_register_lookup() {
        let mut isa = VirtualIsa::new(64, true);
        let entry = VirtualIsaEntry::new(
            0x01,
            VirtualOpCategory::Arithmetic,
            "ADD",
            0,
            1,
            0x1000,
            0.9,
        );
        isa.register(entry).unwrap();
        assert_eq!(isa.opcode_count(), 1);
        let found = isa.lookup(0x01).unwrap();
        assert_eq!(found.mnemonic, "ADD");
    }

    #[test]
    fn test_virtual_isa_duplicate_opcode_same_category() {
        let mut isa = VirtualIsa::new(64, true);
        let e1 = VirtualIsaEntry::new(
            0x01,
            VirtualOpCategory::Arithmetic,
            "ADD",
            0,
            1,
            0x1000,
            0.9,
        );
        let e2 = VirtualIsaEntry::new(
            0x01,
            VirtualOpCategory::Arithmetic,
            "ADD2",
            0,
            1,
            0x1010,
            0.8,
        );
        isa.register(e1).unwrap();
        isa.register(e2).unwrap(); // same category, should not error
        assert_eq!(isa.opcode_count(), 1);
    }

    #[test]
    fn test_virtual_isa_duplicate_opcode_diff_category_errors() {
        let mut isa = VirtualIsa::new(64, true);
        let e1 = VirtualIsaEntry::new(
            0x01,
            VirtualOpCategory::Arithmetic,
            "ADD",
            0,
            1,
            0x1000,
            0.9,
        );
        let e2 = VirtualIsaEntry::new(0x01, VirtualOpCategory::Logic, "XOR", 0, 1, 0x1010, 0.8);
        isa.register(e1).unwrap();
        assert!(isa.register(e2).is_err());
    }

    #[test]
    fn test_virtual_isa_frequency_and_summary() {
        let mut isa = VirtualIsa::new(64, true);
        let e = VirtualIsaEntry::new(0x10, VirtualOpCategory::Logic, "XOR", 0, 1, 0x2000, 0.7);
        isa.register(e).unwrap();
        isa.inc_frequency(0x10);
        isa.inc_frequency(0x10);
        assert_eq!(isa.lookup(0x10).unwrap().frequency, 2);
        assert_eq!(isa.total_decoded, 2);
        let summary = isa.summary();
        assert!(summary.contains("64"));
        assert!(summary.contains("LE"));
    }

    #[test]
    fn test_virtual_isa_merge() {
        let mut isa1 = VirtualIsa::new(64, true);
        let mut isa2 = VirtualIsa::new(64, true);
        isa1.register(VirtualIsaEntry::new(
            0x01,
            VirtualOpCategory::Arithmetic,
            "ADD",
            0,
            1,
            0x1000,
            0.5,
        ))
        .unwrap();
        isa2.register(VirtualIsaEntry::new(
            0x02,
            VirtualOpCategory::Logic,
            "XOR",
            0,
            1,
            0x2000,
            0.8,
        ))
        .unwrap();
        isa1.merge(&isa2);
        assert_eq!(isa1.opcode_count(), 2);
    }

    #[test]
    fn test_handler_table_recovery_too_short() {
        let recovery = HandlerTableRecovery::new_64bit(0x0040_0000);
        let err = recovery.extract(&[], 0, None).unwrap_err();
        assert!(matches!(err, IsaReconstructionError::TableTooShort { .. }));
    }

    #[test]
    fn test_handler_table_recovery_no_valid_handlers() {
        // All zeros → no valid handlers.
        let data = vec![0u8; 256];
        let recovery = HandlerTableRecovery::new_64bit(0x0040_0000);
        let err = recovery.extract(&data, 0, Some(4)).unwrap_err();
        assert!(matches!(err, IsaReconstructionError::NoHandlers));
    }

    #[test]
    fn test_handler_table_recovery_valid_64bit() {
        // Build a fake table with 8 valid 64-bit pointers.
        let image_base: u64 = 0x0001_4000_0000;
        let mut data = vec![0u8; 0x1000 + 8 * 8];
        for i in 0u64..8 {
            let va = image_base + 0x1000 + i * 0x100;
            let bytes = va.to_le_bytes();
            let offset = usize::try_from(i * 8).unwrap_or(usize::MAX);
            data[offset..offset + 8].copy_from_slice(&bytes);
        }
        let recovery = HandlerTableRecovery::new_64bit(image_base);
        let entries = recovery.extract(&data, 0, Some(8)).unwrap();
        assert_eq!(entries.len(), 8);
        assert!(entries.iter().all(|e| e.is_valid));
    }

    #[test]
    fn test_dispatch_table_analyzer() {
        let image_base: u64 = 0x0040_0000;
        let mut data = vec![0u8; 32 * 8];
        for i in 0u64..32 {
            let va = image_base + 0x1000 + i * 0x50;
            let bytes = va.to_le_bytes();
            let offset = usize::try_from(i * 8).unwrap_or(usize::MAX);
            data[offset..offset + 8].copy_from_slice(&bytes);
        }
        let analyzer = DispatchTableAnalyzer::new();
        let result = analyzer.analyze(&data, 0, image_base, 8);
        assert_eq!(result.layout, DispatchTableLayout::DirectPointerArray);
        assert_eq!(result.entry_count, 32);
        assert!(result.layout_confidence > 0.8);
    }

    #[test]
    fn test_opcode_fingerprint_build_and_similarity() {
        let fp1 = OpcodeFingerprint::build(0x10, &[0x50, 0x51, 0x01, 0xC0, 0xFF, 0xE0]);
        let fp2 = OpcodeFingerprint::build(0x11, &[0x50, 0x51, 0x01, 0xC0, 0xFF, 0xE0]);
        assert!((fp1.similarity(&fp2) - 1.0_f32).abs() < f32::EPSILON);

        let fp3 = OpcodeFingerprint::build(0x20, &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        assert!(fp1.similarity(&fp3) < 0.5);
    }

    #[test]
    fn test_isa_graph_builder() {
        let insns: Vec<VirtualInstruction> = vec![
            VirtualInstruction::new(
                0x01,
                VirtualOpCategory::Arithmetic,
                vec![],
                0,
                1,
                0x1000,
                "ADD",
            ),
            VirtualInstruction::new(0x02, VirtualOpCategory::Logic, vec![], 1, 1, 0x1100, "XOR"),
            VirtualInstruction::new(
                0x01,
                VirtualOpCategory::Arithmetic,
                vec![],
                2,
                1,
                0x1000,
                "ADD",
            ),
        ];
        let graph = IsaGraphBuilder::build(&insns);
        assert_eq!(graph.nodes.len(), 2);
        assert!(graph.total_transitions() > 0);
        assert_eq!(graph.most_frequent_opcode(), Some(0x01));
    }

    #[test]
    fn test_isa_graph_to_dot() {
        let insns: Vec<VirtualInstruction> = vec![VirtualInstruction::new(
            0x10,
            VirtualOpCategory::Push,
            vec![],
            0,
            1,
            0x1000,
            "PUSH",
        )];
        let graph = IsaGraphBuilder::build(&insns);
        let dot = graph.to_dot();
        assert!(dot.contains("digraph isa_graph"));
        assert!(dot.contains("PUSH"));
    }

    #[test]
    fn test_fnv1a_consistency() {
        let h1 = fnv1a_64(b"hello");
        let h2 = fnv1a_64(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));
    }

    #[test]
    fn test_classify_prologue_push() {
        let bytes = vec![0x50, 0x51, 0x52]; // PUSH EAX, PUSH ECX, PUSH EDX
        assert_eq!(classify_prologue(&bytes), VirtualOpCategory::Push);
    }

    #[test]
    fn test_classify_prologue_ret() {
        let bytes = vec![0xC3];
        assert_eq!(classify_prologue(&bytes), VirtualOpCategory::Return);
    }

    #[test]
    fn test_classify_prologue_empty() {
        assert_eq!(classify_prologue(&[]), VirtualOpCategory::Unknown);
    }

    #[test]
    fn test_isa_graph_no_cycle_linear() {
        let insns: Vec<VirtualInstruction> = (0u8..5)
            .map(|i| {
                VirtualInstruction::new(i, VirtualOpCategory::Nop, vec![], u64::from(i), 1, 0, "NOP")
            })
            .collect();
        let graph = IsaGraphBuilder::build(&insns);
        // Linear sequence: 0→1→2→3→4, no cycles
        assert!(!graph.has_cycles());
    }
}
