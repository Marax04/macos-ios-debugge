//! VM ISA recovery from handler analysis.
//!
//! Provides [`VmIsaRecovery`], [`VirtualOpcode`], [`HandlerSemantics`],
//! [`IsaTable`], [`DispatchTable`], and [`recover_isa`].
//!
//! # Relation to `vm_isa_complete`
//! This module is the **low-level recovery layer**: it parses a raw dispatch
//! table byte slice, performs per-handler byte-pattern heuristics, and
//! constructs an [`IsaTable`] of opcode → [`HandlerSemantics`] mappings.
//!
//! [`crate::vm_isa_complete`] is the **high-level reconstruction layer**: it
//! accepts the recovered opcode definitions and further lifts bytecode buffers
//! into typed basic blocks, a control-flow graph ([`crate::vm_isa_complete::VmCfg`]),
//! and a [`crate::vm_isa_complete::VmIsaReport`].  The two modules form a
//! deliberate pipeline and should **not** be merged.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IsaRecoveryError {
    #[error("dispatch table not found")]
    NoDispatchTable,
    #[error("handler at {0:#x} could not be analysed")]
    HandlerAnalysisFailed(u64),
    #[error("inconsistent opcode width: expected {expected}, got {got}")]
    OpcodeWidthMismatch { expected: u8, got: u8 },
    #[error("too many opcodes ({0}) for recovery budget")]
    TooManyOpcodes(usize),
    #[error("ISA table is empty")]
    EmptyIsaTable,
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerSemantics
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic category of a VM handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerSemanticsKind {
    /// Push a value onto the virtual stack.
    Push,
    /// Pop a value from the virtual stack.
    Pop,
    /// Arithmetic or logical operation (ADD/SUB/MUL/DIV/AND/OR/XOR/NOT/NEG/SHL/SHR).
    Alu,
    /// Load from memory into a virtual register or stack slot.
    MemLoad,
    /// Store a virtual register or stack slot to memory.
    MemStore,
    /// Unconditional branch within VM bytecode.
    Branch,
    /// Conditional branch.
    ConditionalBranch,
    /// Call to a VM sub-procedure.
    Call,
    /// Return from a VM sub-procedure.
    Ret,
    /// Exit the VM and resume native execution.
    VmExit,
    /// Enter the VM from native code.
    VmEnter,
    /// No-operation.
    Nop,
    /// Comparison (sets virtual flags).
    Compare,
    /// Unknown / not yet analysed.
    Unknown,
}

impl std::fmt::Display for HandlerSemanticsKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Push => "PUSH",
            Self::Pop => "POP",
            Self::Alu => "ALU",
            Self::MemLoad => "LOAD",
            Self::MemStore => "STORE",
            Self::Branch => "JMP",
            Self::ConditionalBranch => "JCC",
            Self::Call => "CALL",
            Self::Ret => "RET",
            Self::VmExit => "VMEXIT",
            Self::VmEnter => "VMENTER",
            Self::Nop => "NOP",
            Self::Compare => "CMP",
            Self::Unknown => "???",
        };
        write!(f, "{s}")
    }
}

/// Detailed semantics recovered for a handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSemantics {
    /// Semantic kind.
    pub kind: HandlerSemanticsKind,
    /// Size of operands in bytes (0 = varies).
    pub operand_size: u8,
    /// Number of virtual stack slots consumed.
    pub stack_pops: u8,
    /// Number of virtual stack slots produced.
    pub stack_pushes: u8,
    /// Whether this handler modifies virtual flags.
    pub modifies_flags: bool,
    /// Whether this handler reads the program counter.
    pub reads_vpc: bool,
    /// Whether this handler writes the program counter.
    pub writes_vpc: bool,
    /// Any constant embedded in the handler (e.g. immediate value).
    pub embedded_constant: Option<u64>,
    /// Human-readable description of the semantic.
    pub description: String,
}

impl HandlerSemantics {
    /// Create a minimal semantic entry.
    #[must_use]
    pub fn new(kind: HandlerSemanticsKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            operand_size: 0,
            stack_pops: 0,
            stack_pushes: 0,
            modifies_flags: false,
            reads_vpc: false,
            writes_vpc: false,
            embedded_constant: None,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self.kind,
            HandlerSemanticsKind::Branch
                | HandlerSemanticsKind::ConditionalBranch
                | HandlerSemanticsKind::Call
                | HandlerSemanticsKind::Ret
                | HandlerSemanticsKind::VmExit
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered virtual opcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualOpcode {
    /// Opcode byte value (or extended word for wider opcode spaces).
    pub id: u16,
    /// Address of the handler in the protected binary.
    pub handler_addr: u64,
    /// Recovered semantics.
    pub semantics: HandlerSemantics,
    /// Whether the handler has been fully analysed.
    pub analysed: bool,
    /// Confidence in the semantic assignment (0–100).
    pub confidence: u8,
}

impl VirtualOpcode {
    /// Create an unanalysed opcode entry.
    #[must_use]
    pub fn unanalysed(id: u16, handler_addr: u64) -> Self {
        Self {
            id,
            handler_addr,
            semantics: HandlerSemantics::new(HandlerSemanticsKind::Unknown, ""),
            analysed: false,
            confidence: 0,
        }
    }

    /// Return a display mnemonic.
    #[must_use]
    pub fn mnemonic(&self) -> String {
        if self.analysed {
            format!("v{:02X}:{}", self.id, self.semantics.kind)
        } else {
            format!("v{:02X}:???", self.id)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatchTable
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered dispatch table mapping opcode → handler address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchTable {
    /// Base address of the table in memory.
    pub base_address: u64,
    /// Number of entries.
    pub entry_count: usize,
    /// Pointer size in bytes (4 = 32-bit, 8 = 64-bit).
    pub pointer_size: u8,
    /// Opcode width in bytes (1 or 2).
    pub opcode_width: u8,
    /// Raw entries: opcode id → handler address.
    pub entries: HashMap<u16, u64>,
}

impl DispatchTable {
    /// Parse a dispatch table from a raw byte slice.
    ///
    /// Assumes `pointer_size`-wide function pointers are stored contiguously.
    ///
    /// # Errors
    /// Returns [`IsaRecoveryError::OpcodeWidthMismatch`] if the width is unsupported.
    pub fn parse(
        data: &[u8],
        base_address: u64,
        pointer_size: u8,
        opcode_width: u8,
        max_entries: usize,
    ) -> Result<Self, IsaRecoveryError> {
        if opcode_width != 1 && opcode_width != 2 {
            return Err(IsaRecoveryError::OpcodeWidthMismatch {
                expected: 1,
                got: opcode_width,
            });
        }
        let ptr = pointer_size as usize;
        if ptr == 0 {
            return Err(IsaRecoveryError::OpcodeWidthMismatch { expected: 4, got: 0 });
        }
        let entry_count = data.len() / ptr;
        let entry_count = entry_count.min(max_entries);

        let mut entries = HashMap::new();
        for i in 0..entry_count {
            let offset = i * ptr;
            if offset + ptr > data.len() {
                break;
            }
            let addr = match ptr {
                4 => u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()),
                _ => break,
            };
            entries.insert(i as u16, addr);
        }

        Ok(Self {
            base_address,
            entry_count,
            pointer_size,
            opcode_width,
            entries,
        })
    }

    /// Look up the handler address for a given opcode.
    #[must_use]
    pub fn handler_for(&self, opcode: u16) -> Option<u64> {
        self.entries.get(&opcode).copied()
    }

    /// Return the number of unique handler addresses.
    #[must_use]
    pub fn unique_handler_count(&self) -> usize {
        let mut addrs: Vec<u64> = self.entries.values().copied().collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IsaTable
// ─────────────────────────────────────────────────────────────────────────────

/// Complete recovered ISA table for the virtual machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsaTable {
    /// All known opcodes, keyed by opcode ID.
    pub opcodes: HashMap<u16, VirtualOpcode>,
    /// The dispatch table this was recovered from.
    pub dispatch_table: Option<DispatchTable>,
    /// Whether the ISA is stack-based (vs register-based).
    pub is_stack_based: bool,
    /// Virtual register file size (0 for pure stack machines).
    pub register_count: u8,
    /// Virtual stack pointer register index (if register-based).
    pub stack_pointer_reg: Option<u8>,
    /// Architecture of the protecting VM (x86/x64/arm etc.).
    pub native_arch: String,
}

impl IsaTable {
    /// Create an empty ISA table.
    #[must_use]
    pub fn new(native_arch: impl Into<String>) -> Self {
        Self {
            opcodes: HashMap::new(),
            dispatch_table: None,
            is_stack_based: true,
            register_count: 0,
            stack_pointer_reg: None,
            native_arch: native_arch.into(),
        }
    }

    /// Add or update an opcode.
    pub fn add_opcode(&mut self, opcode: VirtualOpcode) {
        self.opcodes.insert(opcode.id, opcode);
    }

    /// Return the opcode with the given ID.
    #[must_use]
    pub fn get_opcode(&self, id: u16) -> Option<&VirtualOpcode> {
        self.opcodes.get(&id)
    }

    /// Number of opcodes.
    #[must_use]
    pub fn opcode_count(&self) -> usize {
        self.opcodes.len()
    }

    /// Number of fully analysed opcodes.
    #[must_use]
    pub fn analysed_count(&self) -> usize {
        self.opcodes.values().filter(|o| o.analysed).count()
    }

    /// Coverage percentage (analysed / total).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.opcodes.is_empty() {
            return 0.0;
        }
        (self.analysed_count() as f64 / self.opcodes.len() as f64) * 100.0
    }

    /// Return all opcodes sorted by ID.
    #[must_use]
    pub fn sorted_opcodes(&self) -> Vec<&VirtualOpcode> {
        let mut v: Vec<_> = self.opcodes.values().collect();
        v.sort_by_key(|o| o.id);
        v
    }

    /// Return all control-flow opcodes.
    #[must_use]
    pub fn control_flow_opcodes(&self) -> Vec<&VirtualOpcode> {
        self.opcodes
            .values()
            .filter(|o| o.semantics.is_control_flow())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmIsaRecovery — the main recovery engine
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for ISA recovery.
#[derive(Debug, Clone)]
pub struct IsaRecoveryConfig {
    /// Maximum opcodes to process.
    pub max_opcodes: usize,
    /// Pointer size (4 or 8 bytes).
    pub pointer_size: u8,
    /// Expected opcode width (1 or 2 bytes).
    pub opcode_width: u8,
    /// Treat the VM as stack-based until proven otherwise.
    pub assume_stack_based: bool,
    /// Minimum confidence to mark an opcode as analysed.
    pub min_confidence: u8,
}

impl Default for IsaRecoveryConfig {
    fn default() -> Self {
        Self {
            max_opcodes: 256,
            pointer_size: 8,
            opcode_width: 1,
            assume_stack_based: true,
            min_confidence: 50,
        }
    }
}

/// Main ISA recovery engine.
pub struct VmIsaRecovery {
    config: IsaRecoveryConfig,
}

impl VmIsaRecovery {
    /// Create with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: IsaRecoveryConfig::default(),
        }
    }

    /// Create with custom config.
    #[must_use]
    pub fn with_config(config: IsaRecoveryConfig) -> Self {
        Self { config }
    }

    /// Recover the ISA from a dispatch table at the given address.
    ///
    /// `table_data` is the raw bytes of the dispatch table.
    /// `binary` is the full binary for handler analysis.
    ///
    /// # Errors
    /// Returns an error if the dispatch table cannot be parsed.
    pub fn recover(
        &self,
        table_data: &[u8],
        table_address: u64,
        binary: &[u8],
    ) -> Result<IsaTable, IsaRecoveryError> {
        if table_data.is_empty() {
            return Err(IsaRecoveryError::NoDispatchTable);
        }

        let dispatch = DispatchTable::parse(
            table_data,
            table_address,
            self.config.pointer_size,
            self.config.opcode_width,
            self.config.max_opcodes,
        )?;

        if dispatch.entries.is_empty() {
            return Err(IsaRecoveryError::NoDispatchTable);
        }

        if dispatch.entries.len() > self.config.max_opcodes {
            return Err(IsaRecoveryError::TooManyOpcodes(dispatch.entries.len()));
        }

        let mut table = IsaTable::new("x86_64");
        table.dispatch_table = Some(dispatch.clone());
        table.is_stack_based = self.config.assume_stack_based;

        for (&opcode_id, &handler_addr) in &dispatch.entries {
            let semantics = self.analyse_handler(handler_addr, binary);
            let confidence = semantics
                .as_ref()
                .map(|s| {
                    if s.kind == HandlerSemanticsKind::Unknown {
                        0
                    } else {
                        75u8
                    }
                })
                .unwrap_or(0);

            let sem = semantics
                .unwrap_or_else(|| HandlerSemantics::new(HandlerSemanticsKind::Unknown, ""));
            let analysed = sem.kind != HandlerSemanticsKind::Unknown;

            table.add_opcode(VirtualOpcode {
                id: opcode_id,
                handler_addr,
                semantics: sem,
                analysed,
                confidence,
            });
        }

        if table.opcodes.is_empty() {
            return Err(IsaRecoveryError::EmptyIsaTable);
        }

        Ok(table)
    }

    /// Heuristically analyse a handler at the given address.
    fn analyse_handler(&self, handler_addr: u64, binary: &[u8]) -> Option<HandlerSemantics> {
        // Simple pattern matching on first few bytes of handler.
        // In production this would use proper instruction analysis.
        let binary_base = 0u64; // simplification
        let offset = handler_addr.checked_sub(binary_base)? as usize;
        if offset >= binary.len() {
            return None;
        }

        let slice = &binary[offset..std::cmp::min(offset + 32, binary.len())];
        if slice.is_empty() {
            return None;
        }

        // Heuristic classification by first byte patterns.
        let sem = match slice[0] {
            // PUSH EAX / PUSH reg family: 50–57
            0x50..=0x57 => {
                let mut s =
                    HandlerSemantics::new(HandlerSemanticsKind::Push, "Push register/value");
                s.stack_pushes = 1;
                s.operand_size = if self.config.pointer_size == 8 { 8 } else { 4 };
                s
            }
            // POP EAX / POP reg family: 58–5F
            0x58..=0x5F => {
                let mut s = HandlerSemantics::new(HandlerSemanticsKind::Pop, "Pop register");
                s.stack_pops = 1;
                s.operand_size = if self.config.pointer_size == 8 { 8 } else { 4 };
                s
            }
            // ADD/ADC/SUB/SBB/AND/OR/XOR (0x01, 0x03, etc.) — ALU
            0x01 | 0x03 | 0x09 | 0x0B | 0x11 | 0x13 | 0x19 | 0x1B | 0x21 | 0x23 | 0x29 | 0x2B
            | 0x31 | 0x33 => {
                let mut s = HandlerSemantics::new(
                    HandlerSemanticsKind::Alu,
                    "ALU operation (register form)",
                );
                s.stack_pops = 2;
                s.stack_pushes = 1;
                s.modifies_flags = true;
                s
            }
            // MOV [mem], reg / MOV reg, [mem]
            0x89 => {
                let mut s =
                    HandlerSemantics::new(HandlerSemanticsKind::MemStore, "Store to memory");
                s.stack_pops = 2;
                s
            }
            0x8B => {
                let mut s =
                    HandlerSemantics::new(HandlerSemanticsKind::MemLoad, "Load from memory");
                s.stack_pops = 1;
                s.stack_pushes = 1;
                s
            }
            // JMP rel (E9 / EB)
            0xE9 | 0xEB => {
                let mut s =
                    HandlerSemantics::new(HandlerSemanticsKind::Branch, "Unconditional branch");
                s.reads_vpc = true;
                s.writes_vpc = true;
                s
            }
            // CALL (E8)
            0xE8 => {
                let mut s = HandlerSemantics::new(HandlerSemanticsKind::Call, "VM sub-call");
                s.stack_pushes = 1; // return address
                s.writes_vpc = true;
                s
            }
            // RET (C3 / C2)
            0xC3 | 0xC2 => {
                let mut s = HandlerSemantics::new(HandlerSemanticsKind::Ret, "VM return");
                s.stack_pops = 1;
                s.writes_vpc = true;
                s
            }
            // NOP (90)
            0x90 => HandlerSemantics::new(HandlerSemanticsKind::Nop, "No-operation"),
            // CMP
            0x3B | 0x39 => {
                let mut s = HandlerSemantics::new(HandlerSemanticsKind::Compare, "Compare");
                s.stack_pops = 2;
                s.modifies_flags = true;
                s
            }
            _ => return None,
        };
        Some(sem)
    }
}

impl Default for VmIsaRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// recover_isa convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper around [`VmIsaRecovery::recover`].
///
/// # Errors
/// Returns an error if recovery fails.
pub fn recover_isa(
    table_data: &[u8],
    table_address: u64,
    binary: &[u8],
    config: Option<IsaRecoveryConfig>,
) -> Result<IsaTable, IsaRecoveryError> {
    let engine = match config {
        Some(c) => VmIsaRecovery::with_config(c),
        None => VmIsaRecovery::new(),
    };
    engine.recover(table_data, table_address, binary)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dispatch_table_64(handler_addrs: &[u64]) -> Vec<u8> {
        handler_addrs.iter().flat_map(|a| a.to_le_bytes()).collect()
    }

    fn make_binary_with_handlers(handlers: &[(u64, u8)]) -> Vec<u8> {
        // Binary with handler bytes at known positions.
        let mut binary = vec![0u8; 0x10000];
        for &(addr, first_byte) in handlers {
            if (addr as usize) < binary.len() {
                binary[addr as usize] = first_byte;
            }
        }
        binary
    }

    // -- DispatchTable -------------------------------------------------------

    #[test]
    fn test_dispatch_table_parse_64bit() {
        let addrs: Vec<u64> = (0x1000..0x1100u64).step_by(0x10).collect();
        let data = make_dispatch_table_64(&addrs);
        let dt = DispatchTable::parse(&data, 0x5000, 8, 1, 256).unwrap();
        assert_eq!(dt.entry_count, addrs.len());
        assert_eq!(dt.handler_for(0), Some(0x1000));
    }

    #[test]
    fn test_dispatch_table_parse_32bit() {
        let addrs: Vec<u32> = (0x1000..0x1040u32).step_by(4).collect();
        let data: Vec<u8> = addrs.iter().flat_map(|a| a.to_le_bytes()).collect();
        let dt = DispatchTable::parse(&data, 0x5000, 4, 1, 256).unwrap();
        assert!(dt.entry_count > 0);
    }

    #[test]
    fn test_dispatch_table_bad_opcode_width() {
        let data = vec![0u8; 8];
        assert!(DispatchTable::parse(&data, 0, 8, 3, 256).is_err());
    }

    #[test]
    fn test_dispatch_table_unique_handlers() {
        let data = make_dispatch_table_64(&[0x1000, 0x2000, 0x1000, 0x3000]);
        let dt = DispatchTable::parse(&data, 0, 8, 1, 256).unwrap();
        assert_eq!(dt.unique_handler_count(), 3);
    }

    // -- HandlerSemantics ----------------------------------------------------

    #[test]
    fn test_handler_semantics_new() {
        let s = HandlerSemantics::new(HandlerSemanticsKind::Push, "push imm");
        assert_eq!(s.kind, HandlerSemanticsKind::Push);
        assert_eq!(s.description, "push imm");
    }

    #[test]
    fn test_handler_is_control_flow() {
        let mut s = HandlerSemantics::new(HandlerSemanticsKind::Branch, "jmp");
        assert!(s.is_control_flow());
        s.kind = HandlerSemanticsKind::Alu;
        assert!(!s.is_control_flow());
    }

    // -- VirtualOpcode -------------------------------------------------------

    #[test]
    fn test_virtual_opcode_mnemonic_unanalysed() {
        let op = VirtualOpcode::unanalysed(0x0A, 0x401000);
        assert!(op.mnemonic().contains("???"));
    }

    #[test]
    fn test_virtual_opcode_mnemonic_analysed() {
        let mut op = VirtualOpcode::unanalysed(0x01, 0x1000);
        op.semantics = HandlerSemantics::new(HandlerSemanticsKind::Push, "p");
        op.analysed = true;
        assert!(op.mnemonic().contains("PUSH"));
    }

    // -- IsaTable ------------------------------------------------------------

    #[test]
    fn test_isa_table_add_and_get() {
        let mut t = IsaTable::new("x86_64");
        let op = VirtualOpcode::unanalysed(0x05, 0x2000);
        t.add_opcode(op);
        assert!(t.get_opcode(0x05).is_some());
    }

    #[test]
    fn test_isa_table_coverage_pct() {
        let mut t = IsaTable::new("x86");
        let mut op1 = VirtualOpcode::unanalysed(0, 0x1000);
        op1.analysed = true;
        let op2 = VirtualOpcode::unanalysed(1, 0x2000);
        t.add_opcode(op1);
        t.add_opcode(op2);
        assert!((t.coverage_pct() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_isa_table_sorted_opcodes() {
        let mut t = IsaTable::new("x86");
        t.add_opcode(VirtualOpcode::unanalysed(2, 0x2000));
        t.add_opcode(VirtualOpcode::unanalysed(0, 0x1000));
        t.add_opcode(VirtualOpcode::unanalysed(1, 0x1500));
        let sorted = t.sorted_opcodes();
        assert_eq!(sorted[0].id, 0);
        assert_eq!(sorted[1].id, 1);
        assert_eq!(sorted[2].id, 2);
    }

    // -- VmIsaRecovery -------------------------------------------------------

    #[test]
    fn test_recovery_empty_table_error() {
        let engine = VmIsaRecovery::new();
        assert!(matches!(
            engine.recover(&[], 0, &[]),
            Err(IsaRecoveryError::NoDispatchTable)
        ));
    }

    #[test]
    fn test_recovery_push_handler() {
        let binary = make_binary_with_handlers(&[(0x1000, 0x50)]); // PUSH EAX
        let table_data = make_dispatch_table_64(&[0x1000]);
        let engine = VmIsaRecovery::new();
        let table = engine.recover(&table_data, 0x5000, &binary).unwrap();
        let op = table.get_opcode(0).unwrap();
        assert_eq!(op.semantics.kind, HandlerSemanticsKind::Push);
    }

    #[test]
    fn test_recovery_pop_handler() {
        let binary = make_binary_with_handlers(&[(0x2000, 0x58)]); // POP EAX
        let table_data = make_dispatch_table_64(&[0x2000]);
        let engine = VmIsaRecovery::new();
        let table = engine.recover(&table_data, 0, &binary).unwrap();
        let op = table.get_opcode(0).unwrap();
        assert_eq!(op.semantics.kind, HandlerSemanticsKind::Pop);
    }

    #[test]
    fn test_recovery_nop_handler() {
        let binary = make_binary_with_handlers(&[(0x3000, 0x90)]); // NOP
        let table_data = make_dispatch_table_64(&[0x3000]);
        let engine = VmIsaRecovery::new();
        let table = engine.recover(&table_data, 0, &binary).unwrap();
        let op = table.get_opcode(0).unwrap();
        assert_eq!(op.semantics.kind, HandlerSemanticsKind::Nop);
    }

    #[test]
    fn test_recovery_multiple_handlers() {
        let binary = make_binary_with_handlers(&[
            (0x1000, 0x50), // PUSH
            (0x2000, 0x58), // POP
            (0x3000, 0xE9), // JMP
            (0x4000, 0x90), // NOP
        ]);
        let table_data = make_dispatch_table_64(&[0x1000, 0x2000, 0x3000, 0x4000]);
        let engine = VmIsaRecovery::new();
        let table = engine.recover(&table_data, 0, &binary).unwrap();
        assert_eq!(table.opcode_count(), 4);
        assert!(!table.control_flow_opcodes().is_empty());
    }

    #[test]
    fn test_recover_isa_convenience() {
        let binary = make_binary_with_handlers(&[(0x1000, 0x50)]);
        let table_data = make_dispatch_table_64(&[0x1000]);
        let result = recover_isa(&table_data, 0, &binary, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_recovery_unknown_handler() {
        let binary = make_binary_with_handlers(&[(0x1000, 0xFF)]); // unrecognised
        let table_data = make_dispatch_table_64(&[0x1000]);
        let engine = VmIsaRecovery::new();
        let table = engine.recover(&table_data, 0, &binary).unwrap();
        let op = table.get_opcode(0).unwrap();
        assert_eq!(op.semantics.kind, HandlerSemanticsKind::Unknown);
        assert!(!op.analysed);
    }

    #[test]
    fn test_handler_semantics_kind_display() {
        assert_eq!(HandlerSemanticsKind::Push.to_string(), "PUSH");
        assert_eq!(HandlerSemanticsKind::VmExit.to_string(), "VMEXIT");
        assert_eq!(HandlerSemanticsKind::Unknown.to_string(), "???");
    }

    #[test]
    fn test_isa_table_empty_coverage() {
        let t = IsaTable::new("arm");
        assert_eq!(t.coverage_pct(), 0.0);
    }

    #[test]
    fn test_recovery_too_many_opcodes() {
        // Create a config with a very low limit.
        let config = IsaRecoveryConfig {
            max_opcodes: 2,
            ..Default::default()
        };
        let engine = VmIsaRecovery::with_config(config);
        // Table with 3 entries exceeds limit.
        let table_data = make_dispatch_table_64(&[0x1000, 0x2000, 0x3000]);
        // max_entries is respected in parse so no TooManyOpcodes error.
        let binary = make_binary_with_handlers(&[(0x1000, 0x50), (0x2000, 0x58), (0x3000, 0x90)]);
        let result = engine.recover(&table_data, 0, &binary);
        // Should succeed with 2 entries.
        assert!(result.is_ok());
        assert!(result.unwrap().opcode_count() <= 2);
    }
}
