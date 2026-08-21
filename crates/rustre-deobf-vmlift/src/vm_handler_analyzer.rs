//! VM handler analysis — classify handler bodies into semantic categories.
//!
//! [`VmHandlerAnalyzer`] scans a raw code buffer for handler-like code blocks,
//! classifies each one into a [`HandlerKind`], and returns a list of
//! [`VmHandler`] descriptors that downstream passes use for ISA synthesis and
//! bytecode lifting.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// HandlerKind — semantic classification
// ---------------------------------------------------------------------------

/// Semantic category of a VM handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerKind {
    /// Loads an immediate constant onto the VM stack.
    PushImmediate,
    /// Pushes a virtual register value onto the VM stack.
    PushRegister,
    /// Pops the stack top into a virtual register.
    PopRegister,
    /// Pops the stack top to a memory address.
    PopMemory,
    /// Binary arithmetic (ADD, SUB, MUL, …) on the top two stack items.
    Arithmetic,
    /// Binary logical (AND, OR, XOR, …) on the top two stack items.
    Logical,
    /// Memory load — reads `N` bytes from the stack-popped address.
    MemLoad,
    /// Memory store — writes stack top to the stack-popped address.
    MemStore,
    /// Conditional branch based on the VM flags / stack top.
    Branch,
    /// Unconditional jump within the VM bytecode.
    Jump,
    /// VM-level CALL (saves return address on the VM stack).
    Call,
    /// VM-level RETURN.
    Return,
    /// Compares the top two stack items and updates VM flags.
    Compare,
    /// Advances the virtual instruction pointer by a fixed amount.
    IpAdvance,
    /// Moves data between virtual registers without touching the stack.
    RegisterMove,
    /// Handler semantics could not be determined.
    Unknown,
}

impl fmt::Display for HandlerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PushImmediate => "PUSH_IMM",
            Self::PushRegister => "PUSH_REG",
            Self::PopRegister => "POP_REG",
            Self::PopMemory => "POP_MEM",
            Self::Arithmetic => "ARITH",
            Self::Logical => "LOGIC",
            Self::MemLoad => "MEM_LOAD",
            Self::MemStore => "MEM_STORE",
            Self::Branch => "BRANCH",
            Self::Jump => "JUMP",
            Self::Call => "CALL",
            Self::Return => "RETURN",
            Self::Compare => "CMP",
            Self::IpAdvance => "IP_ADV",
            Self::RegisterMove => "REG_MOV",
            Self::Unknown => "UNKNOWN",
        };
        f.write_str(s)
    }
}

impl HandlerKind {
    /// Returns `true` if this kind alters control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(self, Self::Branch | Self::Jump | Self::Call | Self::Return)
    }

    /// Returns `true` if this kind accesses memory.
    #[must_use]
    pub const fn accesses_memory(&self) -> bool {
        matches!(self, Self::MemLoad | Self::MemStore | Self::PopMemory)
    }

    /// Suggest a short mnemonic string for this kind.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::PushImmediate => "VPUSHI",
            Self::PushRegister => "VPUSHR",
            Self::PopRegister => "VPOPR",
            Self::PopMemory => "VPOPM",
            Self::Arithmetic => "VARITH",
            Self::Logical => "VLOGIC",
            Self::MemLoad => "VLOAD",
            Self::MemStore => "VSTORE",
            Self::Branch => "VBRANCH",
            Self::Jump => "VJMP",
            Self::Call => "VCALL",
            Self::Return => "VRET",
            Self::Compare => "VCMP",
            Self::IpAdvance => "VIPA",
            Self::RegisterMove => "VMOV",
            Self::Unknown => "VUNK",
        }
    }
}

// ---------------------------------------------------------------------------
// VmHandler — one entry in the handler table
// ---------------------------------------------------------------------------

/// A single handler entry extracted from a VM binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmHandler {
    /// Opcode byte that dispatches to this handler (0x00–0xFF).
    pub opcode: u8,
    /// File/buffer offset where the handler code starts.
    pub offset: usize,
    /// Length of the handler body in bytes (0 if unknown).
    pub size: usize,
    /// Semantic classification of this handler.
    pub kind: HandlerKind,
    /// Analyst confidence in the classification, 0–100.
    pub confidence: u8,
    /// Number of immediate operand bytes expected after the opcode.
    pub operand_bytes: usize,
    /// Free-form notes produced during classification.
    pub notes: Vec<String>,
}

impl VmHandler {
    /// Create a new handler with default confidence and no notes.
    #[must_use]
    pub const fn new(opcode: u8, offset: usize, size: usize, kind: HandlerKind) -> Self {
        Self {
            opcode,
            offset,
            size,
            kind,
            confidence: 50,
            operand_bytes: 0,
            notes: Vec::new(),
        }
    }

    /// Set the confidence level.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the expected operand width.
    #[must_use]
    pub const fn with_operand_bytes(mut self, n: usize) -> Self {
        self.operand_bytes = n;
        self
    }

    /// Add a classification note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Returns `true` when the handler is classified with at least `min` confidence.
    #[must_use]
    pub const fn is_confident(&self, min: u8) -> bool {
        self.confidence >= min
    }
}

impl fmt::Display for VmHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#04x}] @ {:#x}+{} {} ({}) conf={} ops={}",
            self.opcode,
            self.offset,
            self.size,
            self.kind.mnemonic(),
            self.kind,
            self.confidence,
            self.operand_bytes,
        )
    }
}

// ---------------------------------------------------------------------------
// PatternSignature — byte-pattern fingerprint for a handler class
// ---------------------------------------------------------------------------

/// A byte-pattern signature used to fingerprint a handler class.
#[derive(Debug, Clone)]
pub struct PatternSignature {
    /// Human-readable name.
    pub name: &'static str,
    /// The expected `HandlerKind` when this pattern matches.
    pub kind: HandlerKind,
    /// Byte pattern (None = wildcard).
    pub pattern: Vec<Option<u8>>,
    /// Confidence bonus granted when this pattern matches.
    pub confidence: u8,
    /// Number of immediate operand bytes implied by this pattern.
    pub operand_bytes: usize,
}

impl PatternSignature {
    /// Create a new signature.
    #[must_use]
    pub const fn new(
        name: &'static str,
        kind: HandlerKind,
        pattern: Vec<Option<u8>>,
        confidence: u8,
        operand_bytes: usize,
    ) -> Self {
        Self {
            name,
            kind,
            pattern,
            confidence,
            operand_bytes,
        }
    }

    /// Returns `true` when `data[offset..]` matches this pattern.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        for (i, pat_byte) in self.pattern.iter().enumerate() {
            if let Some(expected) = pat_byte
                && data[offset + i] != *expected {
                    return false;
                }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ClassificationRule — higher-level statistical rule
// ---------------------------------------------------------------------------

/// A statistical rule that scores a handler body for a given [`HandlerKind`].
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    /// Kind this rule targets.
    pub kind: HandlerKind,
    /// Function that evaluates the code bytes and returns a score in [0, 100].
    pub score_fn: fn(&[u8]) -> u8,
}

impl ClassificationRule {
    /// Evaluate the rule against `body`.
    #[must_use]
    pub fn score(&self, body: &[u8]) -> u8 {
        (self.score_fn)(body)
    }
}

// ---------------------------------------------------------------------------
// VmHandlerAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes a binary for VM handler patterns and classifies each handler.
///
/// The analyzer works in three phases:
/// 1. **Segmentation** — split the code into plausible handler-sized chunks.
/// 2. **Pattern matching** — apply byte-pattern signatures against each chunk.
/// 3. **Rule scoring** — run statistical rules to break ties and boost confidence.
pub struct VmHandlerAnalyzer {
    /// Byte-pattern signatures applied during phase 2.
    signatures: Vec<PatternSignature>,
    /// Statistical rules applied during phase 3.
    rules: Vec<ClassificationRule>,
    /// Minimum handler size in bytes (default 4).
    min_handler_size: usize,
    /// Maximum handler size in bytes (default 128).
    max_handler_size: usize,
    /// Minimum confidence required to include a handler in the output (default 40).
    min_confidence: u8,
}

impl Default for VmHandlerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl VmHandlerAnalyzer {
    /// Create a new analyzer with built-in signatures and rules.
    #[must_use]
    pub fn new() -> Self {
        let signatures = Self::default_signatures();
        let rules = Self::default_rules();
        Self {
            signatures,
            rules,
            min_handler_size: 4,
            max_handler_size: 128,
            min_confidence: 40,
        }
    }

    /// Override the minimum handler body size.
    #[must_use]
    pub const fn with_min_size(mut self, n: usize) -> Self {
        self.min_handler_size = n;
        self
    }

    /// Override the maximum handler body size.
    #[must_use]
    pub const fn with_max_size(mut self, n: usize) -> Self {
        self.max_handler_size = n;
        self
    }

    /// Override the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Analyze `code` and return all detected handlers sorted by offset.
    ///
    /// Each handler is assigned an opcode sequentially starting at 0.
    #[must_use]
    pub fn analyze(&self, code: &[u8]) -> Vec<VmHandler> {
        let segments = self.segment(code);
        let mut handlers = Vec::new();

        for (opcode_idx, (offset, size)) in segments.iter().enumerate() {
            let opcode = u8::try_from(opcode_idx & 0xFF).unwrap_or(0xFF);
            let body = &code[*offset..(*offset + size).min(code.len())];

            if let Some(mut handler) = self.classify(opcode, *offset, *size, body) {
                if handler.confidence >= self.min_confidence {
                    handlers.push(handler);
                } else {
                    handler.kind = HandlerKind::Unknown;
                    handler.confidence = 30;
                    handlers.push(handler);
                }
            }
        }

        handlers
    }

    /// Classify a single handler body.
    ///
    /// Returns `None` if the body is too short or zero-length.
    #[must_use]
    pub fn classify(
        &self,
        opcode: u8,
        offset: usize,
        size: usize,
        body: &[u8],
    ) -> Option<VmHandler> {
        if body.is_empty() {
            return None;
        }

        let mut best_kind = HandlerKind::Unknown;
        let mut best_conf: u8 = 0;
        let mut best_ops: usize = 0;
        let mut notes = Vec::new();

        // Phase 2: pattern matching
        for sig in &self.signatures {
            if sig.matches(body, 0) {
                notes.push(format!("pattern '{}' matched at body[0]", sig.name));
                if sig.confidence > best_conf {
                    best_conf = sig.confidence;
                    best_kind = sig.kind.clone();
                    best_ops = sig.operand_bytes;
                }
            }
        }

        // Phase 3: rule scoring
        for rule in &self.rules {
            let score = rule.score(body);
            if score > best_conf {
                best_conf = score;
                best_kind = rule.kind.clone();
                notes.push(format!("rule {:?} scored {}", rule.kind, score));
            }
        }

        let mut h = VmHandler::new(opcode, offset, size, best_kind)
            .with_confidence(best_conf.max(30))
            .with_operand_bytes(best_ops);
        for note in notes {
            h.add_note(note);
        }
        Some(h)
    }

    /// Produce a summary table keyed by [`HandlerKind`].
    #[must_use]
    pub fn summarize(handlers: &[VmHandler]) -> HashMap<HandlerKind, usize> {
        let mut map: HashMap<HandlerKind, usize> = HashMap::new();
        for h in handlers {
            *map.entry(h.kind.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Return only handlers of the given kind.
    #[must_use]
    pub fn filter_by_kind<'a>(handlers: &'a [VmHandler], kind: &HandlerKind) -> Vec<&'a VmHandler> {
        handlers.iter().filter(|h| &h.kind == kind).collect()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Split `code` into (offset, size) segments heuristically.
    ///
    /// The segment count is capped at 65536 to prevent memory exhaustion when
    /// the caller supplies a large binary with many RET-like bytes (0xC3) that
    /// would otherwise produce one segment per `min_handler_size` bytes.
    fn segment(&self, code: &[u8]) -> Vec<(usize, usize)> {
        const MAX_SEGMENTS: usize = 65_536;
        let mut segments = Vec::new();
        let mut i = 0;
        let len = code.len();

        while i < len {
            if segments.len() >= MAX_SEGMENTS {
                break;
            }
            // Find the next RET-like instruction (C3, C2, CB, CA) as segment end.
            let mut j = i + self.min_handler_size;
            while j < len && j - i < self.max_handler_size {
                match code[j] {
                    // RET near / far / with stack pop
                    0xC3 | 0xC2 | 0xCB | 0xCA => {
                        j += 1;
                        break;
                    }
                    _ => j += 1,
                }
            }
            let size = j - i;
            if size >= self.min_handler_size {
                segments.push((i, size));
            }
            i = j;
        }
        segments
    }

    /// Build the built-in byte-pattern signature table.
    fn default_signatures() -> Vec<PatternSignature> {
        // Helper: concrete byte
        let b = |byte: u8| Some(byte);
        // Helper: wildcard
        let w = || None;

        vec![
            // PUSH immediate: PUSH imm32 → 68 xx xx xx xx
            PatternSignature::new(
                "push_imm32",
                HandlerKind::PushImmediate,
                vec![b(0x68), w(), w(), w(), w()],
                80,
                4,
            ),
            // PUSH register: PUSH r64 → 50..57
            PatternSignature::new(
                "push_reg64",
                HandlerKind::PushRegister,
                vec![b(0x50)],
                70,
                0,
            ),
            PatternSignature::new("push_reg64_1", HandlerKind::PushRegister, vec![b(0x51)], 70, 0),
            PatternSignature::new("push_reg64_2", HandlerKind::PushRegister, vec![b(0x52)], 70, 0),
            // POP register: POP r64 → 58..5F
            PatternSignature::new("pop_reg64",   HandlerKind::PopRegister, vec![b(0x58)], 70, 0),
            PatternSignature::new("pop_reg64_1", HandlerKind::PopRegister, vec![b(0x59)], 70, 0),
            // XOR arith: XOR r/m, r or XOR r, r/m: 31 / 33
            PatternSignature::new("xor_rm_r", HandlerKind::Logical, vec![b(0x31)], 75, 0),
            PatternSignature::new("xor_r_rm", HandlerKind::Logical, vec![b(0x33)], 75, 0),
            // ADD arith: ADD r/m, r: 01 or ADD r, r/m: 03
            PatternSignature::new("add_rm_r", HandlerKind::Arithmetic, vec![b(0x01)], 75, 0),
            PatternSignature::new("add_r_rm", HandlerKind::Arithmetic, vec![b(0x03)], 75, 0),
            // SUB: 29 / 2B
            PatternSignature::new("sub_rm_r", HandlerKind::Arithmetic, vec![b(0x29)], 75, 0),
            PatternSignature::new("sub_r_rm", HandlerKind::Arithmetic, vec![b(0x2B)], 75, 0),
            // CALL near: E8 rel32
            PatternSignature::new(
                "call_rel32",
                HandlerKind::Call,
                vec![b(0xE8), w(), w(), w(), w()],
                85,
                4,
            ),
            // RET near: C3
            PatternSignature::new("ret_near", HandlerKind::Return, vec![b(0xC3)], 85, 0),
            // JMP rel8: EB rel8
            PatternSignature::new("jmp_rel8", HandlerKind::Jump, vec![b(0xEB), w()], 80, 1),
            // JMP rel32: E9 rel32
            PatternSignature::new(
                "jmp_rel32",
                HandlerKind::Jump,
                vec![b(0xE9), w(), w(), w(), w()],
                80,
                4,
            ),
            // CMP: 3B / 39
            PatternSignature::new("cmp_r_rm", HandlerKind::Compare, vec![b(0x3B)], 75, 0),
            PatternSignature::new("cmp_rm_r", HandlerKind::Compare, vec![b(0x39)], 75, 0),
            // MOV r, r/m: 8B
            PatternSignature::new("mov_r_rm", HandlerKind::RegisterMove, vec![b(0x8B)], 60, 0),
            // MOV r/m, r: 89
            PatternSignature::new("mov_rm_r", HandlerKind::RegisterMove, vec![b(0x89)], 60, 0),
        ]
    }

    /// Build the built-in statistical classification rules.
    fn default_rules() -> Vec<ClassificationRule> {
        vec![
            ClassificationRule {
                kind: HandlerKind::MemLoad,
                score_fn: |body| {
                    // REX.W MOV r64, [r64+disp]: 48 8B ...
                    let loads = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x8B).count();
                    if loads >= 1 { 72 } else { 0 }
                },
            },
            ClassificationRule {
                kind: HandlerKind::MemStore,
                score_fn: |body| {
                    // REX.W MOV [r64+disp], r64: 48 89 ...
                    let stores = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x89).count();
                    if stores >= 1 { 72 } else { 0 }
                },
            },
            ClassificationRule {
                kind: HandlerKind::Branch,
                score_fn: |body| {
                    // JZ/JNZ rel8: 74/75
                    let branches = body.iter().filter(|&&b| b == 0x74 || b == 0x75).count();
                    if branches >= 1 { 78 } else { 0 }
                },
            },
            ClassificationRule {
                kind: HandlerKind::Arithmetic,
                score_fn: |body| {
                    // Count ADD/SUB/MUL/IMUL bytes
                    let count = body.iter().filter(|&&b| {
                        matches!(b, 0x01 | 0x03 | 0x05 | 0x29 | 0x2B | 0x2D | 0xF7)
                    }).count();
                    if count >= 2 { 68 } else { 0 }
                },
            },
            ClassificationRule {
                kind: HandlerKind::IpAdvance,
                score_fn: |body| {
                    // ADD reg, imm8 + RET: 83 C? imm8 ... C3
                    let has_add_ret = body.windows(2).any(|w| w[0] == 0x83 && (w[1] & 0xF8) == 0xC0)
                        && body.last() == Some(&0xC3);
                    if has_add_ret { 80 } else { 0 }
                },
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// classify_handler — free function API
// ---------------------------------------------------------------------------

/// Classify a single handler body at `offset` in `code`.
///
/// This is a convenience wrapper around [`VmHandlerAnalyzer::classify`] that
/// creates a default analyzer and returns the detected [`HandlerKind`] together
/// with the confidence score.
///
/// Returns `(HandlerKind::Unknown, 0)` when the body is empty or the offset is
/// out of range.
#[must_use]
pub fn classify_handler(code: &[u8], offset: usize, size: usize) -> (HandlerKind, u8) {
    if offset >= code.len() || size == 0 {
        return (HandlerKind::Unknown, 0);
    }
    let body_end = (offset + size).min(code.len());
    let body = &code[offset..body_end];
    let analyzer = VmHandlerAnalyzer::new();
    match analyzer.classify(0x00, offset, size, body) {
        Some(h) => (h.kind, h.confidence),
        None => (HandlerKind::Unknown, 0),
    }
}

// ---------------------------------------------------------------------------
// HandlerTable — all handlers for a VM instance
// ---------------------------------------------------------------------------

/// A table of all handlers detected for a single VM instance.
#[derive(Debug, Default)]
pub struct HandlerTable {
    handlers: Vec<VmHandler>,
}

impl HandlerTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a table from a pre-analyzed list.
    #[must_use]
    pub const fn from_handlers(handlers: Vec<VmHandler>) -> Self {
        Self { handlers }
    }

    /// Add a handler to the table.
    pub fn insert(&mut self, handler: VmHandler) {
        self.handlers.push(handler);
    }

    /// Retrieve a handler by opcode, if present.
    #[must_use]
    pub fn get(&self, opcode: u8) -> Option<&VmHandler> {
        self.handlers.iter().find(|h| h.opcode == opcode)
    }

    /// All handlers sorted by opcode.
    #[must_use]
    pub fn sorted(&self) -> Vec<&VmHandler> {
        let mut v: Vec<&VmHandler> = self.handlers.iter().collect();
        v.sort_by_key(|h| h.opcode);
        v
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Returns `true` when the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Produce a human-readable listing.
    #[must_use]
    pub fn listing(&self) -> String {
        self.sorted()
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Count handlers per kind.
    #[must_use]
    pub fn kind_counts(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for h in &self.handlers {
            *m.entry(h.kind.to_string()).or_insert(0) += 1;
        }
        m
    }

    /// High-confidence handlers (confidence >= 70).
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&VmHandler> {
        self.handlers.iter().filter(|h| h.confidence >= 70).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_kind_display() {
        assert_eq!(HandlerKind::PushImmediate.to_string(), "PUSH_IMM");
        assert_eq!(HandlerKind::Return.to_string(), "RETURN");
        assert_eq!(HandlerKind::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_handler_kind_properties() {
        assert!(HandlerKind::Branch.is_control_flow());
        assert!(HandlerKind::Call.is_control_flow());
        assert!(!HandlerKind::Arithmetic.is_control_flow());
        assert!(HandlerKind::MemLoad.accesses_memory());
        assert!(!HandlerKind::Arithmetic.accesses_memory());
    }

    #[test]
    fn test_vm_handler_display() {
        let h = VmHandler::new(0x01, 0x100, 16, HandlerKind::Arithmetic)
            .with_confidence(80)
            .with_operand_bytes(2);
        let s = h.to_string();
        assert!(s.contains("0x01"));
        assert!(s.contains("VARITH"));
    }

    #[test]
    fn test_pattern_signature_matches() {
        let sig = PatternSignature::new(
            "test",
            HandlerKind::PushImmediate,
            vec![Some(0x68), None, None, None, None],
            80,
            4,
        );
        let code = [0x68, 0x01, 0x02, 0x03, 0x04, 0xC3];
        assert!(sig.matches(&code, 0));
        assert!(!sig.matches(&code, 1));
    }

    #[test]
    fn test_classify_handler_ret() {
        // Single RET instruction
        let code = [0xC3u8];
        let (kind, conf) = classify_handler(&code, 0, 1);
        assert_eq!(kind, HandlerKind::Return);
        assert!(conf > 0);
    }

    #[test]
    fn test_classify_handler_push_imm() {
        // PUSH imm32
        let code = [0x68u8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let (kind, conf) = classify_handler(&code, 0, 6);
        assert_eq!(kind, HandlerKind::PushImmediate);
        assert!(conf >= 80);
    }

    #[test]
    fn test_classify_handler_out_of_range() {
        let code = [0x90u8; 8];
        let (kind, conf) = classify_handler(&code, 100, 4);
        assert_eq!(kind, HandlerKind::Unknown);
        assert_eq!(conf, 0);
    }

    #[test]
    fn test_analyzer_analyze_empty() {
        let code = [];
        let result = VmHandlerAnalyzer::new().analyze(&code);
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyzer_analyze_nop_sled() {
        let code = vec![0x90u8; 64];
        let result = VmHandlerAnalyzer::new().analyze(&code);
        // May or may not find handlers; just no panic
        let _ = result;
    }

    #[test]
    fn test_handler_table_insert_and_get() {
        let mut table = HandlerTable::new();
        let h = VmHandler::new(0xAA, 0, 16, HandlerKind::Logical).with_confidence(75);
        table.insert(h);
        let found = table.get(0xAA);
        assert!(found.is_some());
        assert_eq!(found.unwrap().opcode, 0xAA);
    }

    #[test]
    fn test_handler_table_listing() {
        let mut table = HandlerTable::new();
        table.insert(VmHandler::new(0x01, 0, 8, HandlerKind::Arithmetic).with_confidence(80));
        table.insert(VmHandler::new(0x02, 8, 8, HandlerKind::Logical).with_confidence(75));
        let listing = table.listing();
        assert!(listing.contains("0x01"));
        assert!(listing.contains("0x02"));
    }

    #[test]
    fn test_handler_table_kind_counts() {
        let mut table = HandlerTable::new();
        table.insert(VmHandler::new(0x01, 0, 8, HandlerKind::Arithmetic).with_confidence(80));
        table.insert(VmHandler::new(0x02, 8, 8, HandlerKind::Arithmetic).with_confidence(80));
        table.insert(VmHandler::new(0x03, 16, 8, HandlerKind::Return).with_confidence(85));
        let counts = table.kind_counts();
        assert_eq!(counts.get("ARITH").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("RETURN").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_summarize() {
        let handlers = vec![
            VmHandler::new(0x01, 0, 8, HandlerKind::Arithmetic).with_confidence(80),
            VmHandler::new(0x02, 8, 8, HandlerKind::Arithmetic).with_confidence(80),
            VmHandler::new(0x03, 16, 8, HandlerKind::Return).with_confidence(85),
        ];
        let summary = VmHandlerAnalyzer::summarize(&handlers);
        assert_eq!(summary[&HandlerKind::Arithmetic], 2);
        assert_eq!(summary[&HandlerKind::Return], 1);
    }

    #[test]
    fn test_filter_by_kind() {
        let handlers = vec![
            VmHandler::new(0x01, 0, 8, HandlerKind::Arithmetic).with_confidence(80),
            VmHandler::new(0x02, 8, 8, HandlerKind::Return).with_confidence(85),
        ];
        let arith = VmHandlerAnalyzer::filter_by_kind(&handlers, &HandlerKind::Arithmetic);
        assert_eq!(arith.len(), 1);
    }

    #[test]
    fn test_high_confidence_filter() {
        let mut table = HandlerTable::new();
        table.insert(VmHandler::new(0x01, 0, 8, HandlerKind::Arithmetic).with_confidence(80));
        table.insert(VmHandler::new(0x02, 8, 8, HandlerKind::Unknown).with_confidence(30));
        let high = table.high_confidence();
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn test_handler_is_confident() {
        let h = VmHandler::new(0x00, 0, 4, HandlerKind::Unknown).with_confidence(60);
        assert!(h.is_confident(60));
        assert!(h.is_confident(50));
        assert!(!h.is_confident(61));
    }
}
