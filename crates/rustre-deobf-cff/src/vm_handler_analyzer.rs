//! VM-based obfuscation handler analyser.
//!
//! Identifies the VM dispatch loop, extracts per-opcode handlers by following
//! the dispatch table, and lifts each handler to a semantic description.

use std::collections::HashMap;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    DispatchLoopNotFound,
    HandlerTableEmpty,
    HandlerAnalysisFailed { opcode: u8, reason: String },
    LiftingFailed(String),
    EmptyBytecodeTrace,
    OpcodeNotFound(u8),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DispatchLoopNotFound => write!(f, "VM dispatch loop not found"),
            Self::HandlerTableEmpty => write!(f, "dispatch table is empty"),
            Self::HandlerAnalysisFailed { opcode, reason } => {
                write!(f, "handler analysis failed for opcode 0x{opcode:02x}: {reason}")
            }
            Self::LiftingFailed(s) => write!(f, "lifting failed: {s}"),
            Self::EmptyBytecodeTrace => write!(f, "bytecode trace is empty"),
            Self::OpcodeNotFound(o) => write!(f, "opcode 0x{o:02x} not in handler table"),
        }
    }
}

impl std::error::Error for VmError {}

// ─── HandlerSemantics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerSemantics {
    Push,
    Pop,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Jmp,
    JmpCond,
    Call,
    Ret,
    LoadMem,
    StoreMem,
    LoadImm,
    Nop,
    Unknown,
}

impl HandlerSemantics {
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(self, Self::Jmp | Self::JmpCond | Self::Call | Self::Ret)
    }

    #[must_use]
    pub const fn is_memory_op(&self) -> bool {
        matches!(self, Self::LoadMem | Self::StoreMem)
    }

    #[must_use]
    pub const fn is_arithmetic(&self) -> bool {
        matches!(
            self,
            Self::Add | Self::Sub | Self::Mul | Self::Div
            | Self::And | Self::Or | Self::Xor | Self::Not
            | Self::Shl | Self::Shr
        )
    }
}

// ─── VmReg ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmReg {
    pub name: String,
    pub offset_in_ctx: i32,
    pub size: u8,
}

impl VmReg {
    pub fn new(name: impl Into<String>, offset: i32, size: u8) -> Self {
        Self { name: name.into(), offset_in_ctx: offset, size }
    }
}

// ─── VmHandler ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VmHandler {
    pub handler_addr: u64,
    pub opcode: u8,
    pub semantics: HandlerSemantics,
    pub reads_regs: Vec<VmReg>,
    pub writes_regs: Vec<VmReg>,
    pub reads_mem: bool,
    pub writes_mem: bool,
    pub advances_pc: bool,
    pub pc_delta: i32,
}

impl VmHandler {
    #[must_use]
    pub const fn new(addr: u64, opcode: u8) -> Self {
        Self {
            handler_addr: addr,
            opcode,
            semantics: HandlerSemantics::Unknown,
            reads_regs: Vec::new(),
            writes_regs: Vec::new(),
            reads_mem: false,
            writes_mem: false,
            advances_pc: true,
            pc_delta: 1,
        }
    }
}

// ─── VmDispatchLoop ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VmDispatchLoop {
    pub fetch_pc_addr: u64,
    pub decode_addr: u64,
    pub dispatch_table_addr: u64,
    pub context_ptr_reg: String,
    pub pc_reg: String,
    pub opcode_reg: String,
}

// ─── LiftedOp ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LiftedOp {
    pub offset: usize,
    pub opcode: u8,
    pub semantics: HandlerSemantics,
    pub operands: Vec<LiftedOperand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftedOperand {
    Immediate(u64),
    VmRegister(String),
    MemAddr(u64),
    Relative(i32),
}

// ─── VmLiftedProgram ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct VmLiftedProgram {
    pub handlers: HashMap<u8, VmHandler>,
    pub bytecode_trace: Vec<u8>,
    pub lifted_ops: Vec<LiftedOp>,
}

impl VmLiftedProgram {
    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.lifted_ops.len()
    }

    #[must_use]
    pub fn unique_opcodes(&self) -> Vec<u8> {
        let mut seen: Vec<u8> = self.lifted_ops.iter().map(|o| o.opcode).collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }

    #[must_use]
    pub fn control_flow_ops(&self) -> Vec<&LiftedOp> {
        self.lifted_ops
            .iter()
            .filter(|o| o.semantics.is_control_flow())
            .collect()
    }
}

// ─── RawInstruction ──────────────────────────────────────────────────────────

/// A mock native instruction used by the analyser to reason about handlers.
#[derive(Debug, Clone)]
pub struct RawInstruction {
    pub addr: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub is_indirect_jmp: bool,
    pub indirect_table_reg: Option<String>,
    pub memory_read: bool,
    pub memory_write: bool,
    pub reads: Vec<String>,  // register names read
    pub writes: Vec<String>, // register names written
}

impl RawInstruction {
    pub fn new(addr: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            addr,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            is_indirect_jmp: false,
            indirect_table_reg: None,
            memory_read: false,
            memory_write: false,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }
}

// ─── VmHandlerAnalyzer ───────────────────────────────────────────────────────

pub struct VmHandlerAnalyzer {
    /// Native instructions per basic block (`block_addr` → instructions)
    code: HashMap<u64, Vec<RawInstruction>>,
    /// The dispatch table: opcode → handler address
    dispatch_table: HashMap<u8, u64>,
    /// The VM context struct layout: `field_name` → (offset, size)
    _context_layout: HashMap<String, (i32, u8)>,
    /// Known VM register names and their context offsets
    vm_regs: Vec<VmReg>,
}

impl VmHandlerAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            code: HashMap::new(),
            dispatch_table: HashMap::new(),
            _context_layout: HashMap::new(),
            vm_regs: Vec::new(),
        }
    }

    pub fn add_block(&mut self, addr: u64, insns: Vec<RawInstruction>) {
        self.code.insert(addr, insns);
    }

    pub fn set_dispatch_table(&mut self, table: HashMap<u8, u64>) {
        self.dispatch_table = table;
    }

    pub fn add_vm_reg(&mut self, reg: VmReg) {
        self.vm_regs.push(reg);
    }

    // ── Dispatch loop detection ──────────────────────────────────────────

    /// Find the dispatch loop by locating an indirect jump through a table
    /// indexed by a byte loaded from memory (the VM bytecode stream).
    pub fn identify_dispatch_loop(&self) -> Result<VmDispatchLoop, VmError> {
        for (&block_addr, insns) in &self.code {
            for insn in insns {
                if insn.is_indirect_jmp
                    && let Some(ref tbl_reg) = insn.indirect_table_reg {
                        // Heuristic: look backwards for a byte-load from a pc-like register
                        let fetch_addr = self.find_pc_fetch(block_addr, insn.addr);
                        return Ok(VmDispatchLoop {
                            fetch_pc_addr: fetch_addr.unwrap_or(block_addr),
                            decode_addr: insn.addr,
                            dispatch_table_addr: self.infer_table_addr(tbl_reg),
                            context_ptr_reg: "rdi".to_string(),
                            pc_reg: "rsi".to_string(),
                            opcode_reg: tbl_reg.clone(),
                        });
                    }
            }
        }
        Err(VmError::DispatchLoopNotFound)
    }

    fn find_pc_fetch(&self, block_addr: u64, before_addr: u64) -> Option<u64> {
        let insns = self.code.get(&block_addr)?;
        for insn in insns {
            if insn.addr < before_addr && insn.memory_read {
                return Some(insn.addr);
            }
        }
        None
    }

    const fn infer_table_addr(&self, _reg: &str) -> u64 {
        // In a real implementation this would trace the register definition
        // back to a LEA or MOV from a known symbol.
        0x0000_0000_0040_5000
    }

    // ── Handler extraction ───────────────────────────────────────────────

    /// Follow each dispatch table entry and analyse up to `max_insns` instructions.
    pub fn extract_handlers(&self, max_insns: usize) -> Result<HashMap<u8, VmHandler>, VmError> {
        if self.dispatch_table.is_empty() {
            return Err(VmError::HandlerTableEmpty);
        }

        let mut handlers = HashMap::new();
        for (&opcode, &handler_addr) in &self.dispatch_table {
            let handler = self
                .analyse_handler(opcode, handler_addr, max_insns)
                .map_err(|e| VmError::HandlerAnalysisFailed {
                    opcode,
                    reason: e.to_string(),
                })?;
            handlers.insert(opcode, handler);
        }
        Ok(handlers)
    }

    fn analyse_handler(
        &self,
        opcode: u8,
        handler_addr: u64,
        max_insns: usize,
    ) -> Result<VmHandler, VmError> {
        let mut h = VmHandler::new(handler_addr, opcode);

        let insns = match self.code.get(&handler_addr) {
            Some(i) => i,
            None => return Ok(h), // No code — leave Unknown
        };

        let mut reads_regs: Vec<String> = Vec::new();
        let mut writes_regs: Vec<String> = Vec::new();

        for insn in insns.iter().take(max_insns) {
            if insn.memory_read {
                h.reads_mem = true;
            }
            if insn.memory_write {
                h.writes_mem = true;
            }
            reads_regs.extend(insn.reads.iter().cloned());
            writes_regs.extend(insn.writes.iter().cloned());
        }

        // Deduplicate
        reads_regs.sort_unstable();
        reads_regs.dedup();
        writes_regs.sort_unstable();
        writes_regs.dedup();

        // Map register names to VmReg
        h.reads_regs = reads_regs
            .iter()
            .filter_map(|r| self.vm_regs.iter().find(|vr| &vr.name == r).cloned())
            .collect();
        h.writes_regs = writes_regs
            .iter()
            .filter_map(|r| self.vm_regs.iter().find(|vr| &vr.name == r).cloned())
            .collect();

        // Lift semantics from pattern
        h.semantics = self.lift_handler_to_semantics(insns, max_insns);

        Ok(h)
    }

    // ── Semantic lifting ─────────────────────────────────────────────────

    /// Pattern-match on register reads/writes and memory operations to
    /// determine the handler's semantics.
    #[must_use]
    pub fn lift_handler_to_semantics(
        &self,
        insns: &[RawInstruction],
        max_insns: usize,
    ) -> HandlerSemantics {
        let limited: Vec<&RawInstruction> = insns.iter().take(max_insns).collect();
        let mnemonics: Vec<&str> = limited.iter().map(|i| i.mnemonic.as_str()).collect();

        // Nop: single nop or empty
        if limited.is_empty() || (limited.len() == 1 && mnemonics[0] == "nop") {
            return HandlerSemantics::Nop;
        }

        // Jmp / JmpCond
        if mnemonics.contains(&"jmp") {
            return HandlerSemantics::Jmp;
        }
        if mnemonics.iter().any(|&m| matches!(m, "je" | "jne" | "jz" | "jnz" | "jl" | "jg")) {
            return HandlerSemantics::JmpCond;
        }
        if mnemonics.contains(&"call") {
            return HandlerSemantics::Call;
        }
        if mnemonics.iter().any(|&m| m == "ret" || m == "retn") {
            return HandlerSemantics::Ret;
        }

        let has_mem_read = limited.iter().any(|i| i.memory_read);
        let has_mem_write = limited.iter().any(|i| i.memory_write);

        // LoadMem / StoreMem
        if has_mem_read && !has_mem_write {
            // Distinguish push-stack (stack write) from generic load
            if mnemonics.contains(&"push") {
                return HandlerSemantics::Push;
            }
            return HandlerSemantics::LoadMem;
        }
        if has_mem_write && !has_mem_read {
            if mnemonics.contains(&"pop") {
                return HandlerSemantics::Pop;
            }
            return HandlerSemantics::StoreMem;
        }
        if has_mem_read && has_mem_write {
            // Could be load+store (e.g. inc [mem]) — default to LoadMem
            return HandlerSemantics::LoadMem;
        }

        // LoadImm: mov reg, imm
        if mnemonics.contains(&"mov") {
            let has_imm = limited
                .iter()
                .any(|i| i.operands.iter().any(|o| o.starts_with("0x") || o.chars().all(|c| c.is_ascii_digit())));
            if has_imm {
                return HandlerSemantics::LoadImm;
            }
        }

        // Arithmetic patterns
        if mnemonics.contains(&"add") { return HandlerSemantics::Add; }
        if mnemonics.contains(&"sub") { return HandlerSemantics::Sub; }
        if mnemonics.iter().any(|&m| m == "imul" || m == "mul") { return HandlerSemantics::Mul; }
        if mnemonics.iter().any(|&m| m == "idiv" || m == "div") { return HandlerSemantics::Div; }
        if mnemonics.contains(&"and") { return HandlerSemantics::And; }
        if mnemonics.contains(&"or") { return HandlerSemantics::Or; }
        if mnemonics.contains(&"xor") { return HandlerSemantics::Xor; }
        if mnemonics.contains(&"not") { return HandlerSemantics::Not; }
        if mnemonics.iter().any(|&m| m == "shl" || m == "sal") { return HandlerSemantics::Shl; }
        if mnemonics.iter().any(|&m| m == "shr" || m == "sar") { return HandlerSemantics::Shr; }

        HandlerSemantics::Unknown
    }

    // ── Full lifting pipeline ────────────────────────────────────────────

    /// Lift a bytecode trace to a `VmLiftedProgram`.
    pub fn lift_bytecode_trace(
        &self,
        trace: &[u8],
        handlers: &HashMap<u8, VmHandler>,
    ) -> Result<VmLiftedProgram, VmError> {
        if trace.is_empty() {
            return Err(VmError::EmptyBytecodeTrace);
        }

        let mut lifted_ops = Vec::new();
        let mut i = 0;

        while i < trace.len() {
            let opcode = trace[i];
            let handler = handlers.get(&opcode).ok_or(VmError::OpcodeNotFound(opcode))?;

            let mut operands = Vec::new();

            // Simple operand extraction based on semantics
            match handler.semantics {
                HandlerSemantics::LoadImm => {
                    // Next 8 bytes = immediate
                    if i + 8 < trace.len() {
                        let imm = u64::from_le_bytes(trace[i + 1..i + 9].try_into().unwrap());
                        operands.push(LiftedOperand::Immediate(imm));
                        i += 9;
                    } else {
                        i += 1;
                    }
                }
                HandlerSemantics::Jmp | HandlerSemantics::JmpCond => {
                    if i + 4 < trace.len() {
                        let rel = i32::from_le_bytes(trace[i + 1..i + 5].try_into().unwrap());
                        operands.push(LiftedOperand::Relative(rel));
                        i += 5;
                    } else {
                        i += 1;
                    }
                }
                HandlerSemantics::LoadMem | HandlerSemantics::StoreMem => {
                    if i + 8 < trace.len() {
                        let addr = u64::from_le_bytes(trace[i + 1..i + 9].try_into().unwrap());
                        operands.push(LiftedOperand::MemAddr(addr));
                        i += 9;
                    } else {
                        i += 1;
                    }
                }
                _ => { i += handler.pc_delta.max(1) as usize; }
            }

            lifted_ops.push(LiftedOp {
                offset: i,
                opcode,
                semantics: handler.semantics.clone(),
                operands,
            });
        }

        Ok(VmLiftedProgram {
            handlers: handlers.clone(),
            bytecode_trace: trace.to_vec(),
            lifted_ops,
        })
    }

    /// Build a complete lifted program from scratch: extract handlers,
    /// then lift the provided bytecode trace.
    pub fn build_lifted_program(
        &self,
        trace: &[u8],
    ) -> Result<VmLiftedProgram, VmError> {
        let handlers = self.extract_handlers(50)?;
        self.lift_bytecode_trace(trace, &handlers)
    }
}

impl Default for VmHandlerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insn(addr: u64, mnemonic: &str) -> RawInstruction {
        RawInstruction::new(addr, mnemonic)
    }

    fn _add_insn(i: &mut RawInstruction, reads: Vec<&str>, writes: Vec<&str>) {
        i.reads = reads.into_iter().map(String::from).collect();
        i.writes = writes.into_iter().map(String::from).collect();
    }

    // 1. identify_dispatch_loop finds indirect jump block
    #[test]
    fn test_identify_dispatch_loop() {
        let mut a = VmHandlerAnalyzer::new();
        let mut insn = make_insn(0x1000, "jmp");
        insn.is_indirect_jmp = true;
        insn.indirect_table_reg = Some("rax".into());
        a.add_block(0x1000, vec![insn]);
        let dl = a.identify_dispatch_loop().unwrap();
        assert_eq!(dl.decode_addr, 0x1000);
        assert_eq!(dl.opcode_reg, "rax");
    }

    // 2. identify_dispatch_loop fails when no indirect jump
    #[test]
    fn test_identify_dispatch_loop_not_found() {
        let mut a = VmHandlerAnalyzer::new();
        a.add_block(0x1000, vec![make_insn(0x1000, "nop")]);
        assert!(matches!(a.identify_dispatch_loop(), Err(VmError::DispatchLoopNotFound)));
    }

    // 3. extract_handlers with empty dispatch table
    #[test]
    fn test_extract_handlers_empty_table() {
        let a = VmHandlerAnalyzer::new();
        assert!(matches!(a.extract_handlers(10), Err(VmError::HandlerTableEmpty)));
    }

    // 4. lift_handler_to_semantics: nop
    #[test]
    fn test_lift_nop() {
        let a = VmHandlerAnalyzer::new();
        let insns = vec![make_insn(0, "nop")];
        assert_eq!(a.lift_handler_to_semantics(&insns, 10), HandlerSemantics::Nop);
    }

    // 5. lift_handler_to_semantics: add
    #[test]
    fn test_lift_add() {
        let a = VmHandlerAnalyzer::new();
        let insns = vec![make_insn(0, "add")];
        assert_eq!(a.lift_handler_to_semantics(&insns, 10), HandlerSemantics::Add);
    }

    // 6. lift_handler_to_semantics: xor
    #[test]
    fn test_lift_xor() {
        let a = VmHandlerAnalyzer::new();
        let insns = vec![make_insn(0, "xor")];
        assert_eq!(a.lift_handler_to_semantics(&insns, 10), HandlerSemantics::Xor);
    }

    // 7. lift_handler_to_semantics: memory read → LoadMem
    #[test]
    fn test_lift_load_mem() {
        let a = VmHandlerAnalyzer::new();
        let mut insn = make_insn(0, "mov");
        insn.memory_read = true;
        assert_eq!(a.lift_handler_to_semantics(&[insn], 10), HandlerSemantics::LoadMem);
    }

    // 8. lift_handler_to_semantics: memory write → StoreMem
    #[test]
    fn test_lift_store_mem() {
        let a = VmHandlerAnalyzer::new();
        let mut insn = make_insn(0, "mov");
        insn.memory_write = true;
        assert_eq!(a.lift_handler_to_semantics(&[insn], 10), HandlerSemantics::StoreMem);
    }

    // 9. lift_handler_to_semantics: conditional jump
    #[test]
    fn test_lift_jmp_cond() {
        let a = VmHandlerAnalyzer::new();
        let insns = vec![make_insn(0, "jne")];
        assert_eq!(a.lift_handler_to_semantics(&insns, 10), HandlerSemantics::JmpCond);
    }

    // 10. lift_handler_to_semantics: ret
    #[test]
    fn test_lift_ret() {
        let a = VmHandlerAnalyzer::new();
        let insns = vec![make_insn(0, "ret")];
        assert_eq!(a.lift_handler_to_semantics(&insns, 10), HandlerSemantics::Ret);
    }

    // 11. extract_handlers produces one entry per dispatch table entry
    #[test]
    fn test_extract_handlers_count() {
        let mut a = VmHandlerAnalyzer::new();
        let mut table = HashMap::new();
        for opcode in 0u8..4 {
            let addr = 0x1000 + u64::from(opcode) * 0x100;
            table.insert(opcode, addr);
            a.add_block(addr, vec![make_insn(addr, "nop")]);
        }
        a.set_dispatch_table(table);
        let handlers = a.extract_handlers(10).unwrap();
        assert_eq!(handlers.len(), 4);
    }

    // 12. VmLiftedProgram unique_opcodes deduplicated
    #[test]
    fn test_unique_opcodes() {
        let mut prog = VmLiftedProgram::default();
        prog.lifted_ops = vec![
            LiftedOp { offset: 0, opcode: 1, semantics: HandlerSemantics::Nop, operands: vec![] },
            LiftedOp { offset: 1, opcode: 1, semantics: HandlerSemantics::Nop, operands: vec![] },
            LiftedOp { offset: 2, opcode: 2, semantics: HandlerSemantics::Add, operands: vec![] },
        ];
        let uniq = prog.unique_opcodes();
        assert_eq!(uniq, vec![1, 2]);
    }

    // 13. VmLiftedProgram control_flow_ops filter
    #[test]
    fn test_control_flow_ops() {
        let mut prog = VmLiftedProgram::default();
        prog.lifted_ops = vec![
            LiftedOp { offset: 0, opcode: 0, semantics: HandlerSemantics::Add, operands: vec![] },
            LiftedOp { offset: 1, opcode: 1, semantics: HandlerSemantics::Jmp, operands: vec![] },
            LiftedOp { offset: 2, opcode: 2, semantics: HandlerSemantics::Ret, operands: vec![] },
        ];
        let cf = prog.control_flow_ops();
        assert_eq!(cf.len(), 2);
    }

    // 14. HandlerSemantics is_arithmetic
    #[test]
    fn test_is_arithmetic() {
        assert!(HandlerSemantics::Add.is_arithmetic());
        assert!(HandlerSemantics::Xor.is_arithmetic());
        assert!(!HandlerSemantics::Jmp.is_arithmetic());
        assert!(!HandlerSemantics::LoadMem.is_arithmetic());
    }

    // 15. lift_bytecode_trace produces lifted ops
    #[test]
    fn test_lift_bytecode_trace() {
        let a = VmHandlerAnalyzer::new();
        let mut handlers = HashMap::new();
        let mut h_nop = VmHandler::new(0x1000, 0x00);
        h_nop.semantics = HandlerSemantics::Nop;
        h_nop.pc_delta = 1;
        handlers.insert(0x00u8, h_nop);

        let mut h_add = VmHandler::new(0x2000, 0x01);
        h_add.semantics = HandlerSemantics::Add;
        h_add.pc_delta = 1;
        handlers.insert(0x01u8, h_add);

        let trace = vec![0x00u8, 0x01, 0x00];
        let prog = a.lift_bytecode_trace(&trace, &handlers).unwrap();
        assert_eq!(prog.op_count(), 3);
        assert_eq!(prog.lifted_ops[1].semantics, HandlerSemantics::Add);
    }
}
