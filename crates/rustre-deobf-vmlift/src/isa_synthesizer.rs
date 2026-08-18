//! VM ISA (Instruction Set Architecture) synthesis.
//!
//! After the handler inferrer has classified each handler, this module
//! assembles the results into a complete description of the virtual machine's
//! instruction set: the [`VmIsa`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::handler_inferrer::{HandlerClass, HandlerSemantic};

// ─────────────────────────────────────────────────────────────────────────────
// BytecodeFormat
// ─────────────────────────────────────────────────────────────────────────────

/// Encoding format of the bytecode consumed by the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BytecodeFormat {
    /// Fixed-size instructions (e.g. all instructions are 4 bytes).
    Fixed(usize),
    /// Variable-size instructions; first byte is the opcode.
    VariableOpcode1,
    /// Variable-size instructions; first two bytes are the opcode.
    VariableOpcode2,
    /// Opcode followed by a fixed-size operand block.
    OpcodeWithOperands {
        opcode_bytes: usize,
        operand_bytes: usize,
    },
    /// Format could not be determined.
    Unknown,
}

impl std::fmt::Display for BytecodeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(n) => write!(f, "fixed-{n}B"),
            Self::VariableOpcode1 => write!(f, "var/1B-opcode"),
            Self::VariableOpcode2 => write!(f, "var/2B-opcode"),
            Self::OpcodeWithOperands {
                opcode_bytes,
                operand_bytes,
            } => {
                write!(f, "opcode({opcode_bytes}B)+operands({operand_bytes}B)")
            }
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmInstructionDef
// ─────────────────────────────────────────────────────────────────────────────

/// Definition of one instruction in the synthesised VM ISA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstructionDef {
    /// Numeric opcode value (as seen in the bytecode stream).
    pub opcode: u32,
    /// Human-readable mnemonic (e.g. `"VADD"`, `"VPUSH"`).
    pub mnemonic: String,
    /// The semantic class inferred for this instruction.
    pub class: HandlerClass,
    /// Offset of the handler code in the binary.
    pub handler_offset: usize,
    /// Size of the handler code in bytes.
    pub handler_size: usize,
    /// Number of operands in the bytecode stream following the opcode.
    pub operand_count: u8,
    /// Width of each operand in bytes (0 = no operands).
    pub operand_width: u8,
    /// Confidence in the instruction definition (0–100).
    pub confidence: u8,
    /// Pseudo-code for this instruction.
    pub pseudo_code: String,
}

impl VmInstructionDef {
    /// Create a new instruction definition.
    #[must_use]
    pub fn from_semantic(opcode: u32, sem: &HandlerSemantic) -> Self {
        let mnemonic = mnemonic_for_class(&sem.class, opcode);
        let operand_count = estimate_operand_count(sem);
        let operand_width = estimate_operand_width(sem);
        Self {
            opcode,
            mnemonic,
            class: sem.class.clone(),
            handler_offset: sem.offset,
            handler_size: sem.size,
            operand_count,
            operand_width,
            confidence: sem.confidence,
            pseudo_code: sem.pseudo_code.clone(),
        }
    }
}

impl std::fmt::Display for VmInstructionDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[0x{:02x}] {} ; {}",
            self.opcode, self.mnemonic, self.pseudo_code
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmIsa
// ─────────────────────────────────────────────────────────────────────────────

/// The synthesised instruction set of the detected virtual machine.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmIsa {
    /// All instruction definitions, keyed by opcode value.
    pub instructions: HashMap<u32, VmInstructionDef>,
    /// Detected bytecode format.
    pub format: Option<BytecodeFormat>,
    /// Number of virtual registers in this VM.
    pub register_count: u8,
    /// Register width in bits.
    pub register_width: u8,
    /// Whether opcodes are encrypted / obfuscated.
    pub encrypted_opcodes: bool,
    /// Confidence that the synthesised ISA is correct (0–100).
    pub overall_confidence: u8,
}

impl VmIsa {
    /// Create an empty ISA.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all instructions sorted by opcode.
    #[must_use]
    pub fn sorted_instructions(&self) -> Vec<&VmInstructionDef> {
        let mut insns: Vec<&VmInstructionDef> = self.instructions.values().collect();
        insns.sort_by_key(|i| i.opcode);
        insns
    }

    /// Return all instructions of a given semantic class.
    #[must_use]
    pub fn instructions_by_class(&self, class: &HandlerClass) -> Vec<&VmInstructionDef> {
        self.instructions
            .values()
            .filter(|i| &i.class == class)
            .collect()
    }

    /// Return `true` when the ISA has a terminal (halt/exit) instruction.
    #[must_use]
    pub fn has_halt(&self) -> bool {
        self.instructions
            .values()
            .any(|i| i.class == HandlerClass::Halt)
    }

    /// Return `true` when the ISA has at least one branch instruction.
    #[must_use]
    pub fn has_branches(&self) -> bool {
        self.instructions.values().any(|i| {
            matches!(
                i.class,
                HandlerClass::Jump
                    | HandlerClass::JmpIfZero
                    | HandlerClass::JmpIfNotZero
                    | HandlerClass::JmpIfLess
                    | HandlerClass::JmpIfGreater
                    | HandlerClass::Call
                    | HandlerClass::Ret
            )
        })
    }

    /// Emit a textual disassembly listing of all instructions.
    #[must_use]
    pub fn disassembly_listing(&self) -> String {
        let sorted = self.sorted_instructions();
        let mut lines = Vec::with_capacity(sorted.len());
        for insn in sorted {
            lines.push(insn.to_string());
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IsaSynthesizer
// ─────────────────────────────────────────────────────────────────────────────

/// Assembles handler semantics into a complete [`VmIsa`].
///
/// ```rust
/// use rustre_deobf_vmlift::isa_synthesizer::IsaSynthesizer;
/// use rustre_deobf_vmlift::handler_inferrer::{HandlerSemanticInferrer};
///
/// let inferrer = HandlerSemanticInferrer::new();
/// let handlers = vec![(0x1000usize, vec![0x50u8, 0xC3]), (0x1010, vec![0x58u8, 0xC3])];
/// let semantics = inferrer.infer_all(&handlers);
///
/// let synth = IsaSynthesizer::new();
/// let isa = synth.synthesize(&semantics);
/// assert_eq!(isa.instructions.len(), 2);
/// ```
#[derive(Debug, Default)]
pub struct IsaSynthesizer {
    /// Starting opcode value for the first handler.
    first_opcode: u32,
    /// Opcode stride (how much each successive opcode increments).
    opcode_stride: u32,
}

impl IsaSynthesizer {
    /// Create a synthesizer with default settings (opcodes start at 0, stride 1).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            first_opcode: 0,
            opcode_stride: 1,
        }
    }

    /// Set the starting opcode value.
    #[must_use]
    pub const fn with_first_opcode(mut self, opcode: u32) -> Self {
        self.first_opcode = opcode;
        self
    }

    /// Set the opcode stride.
    #[must_use]
    pub const fn with_opcode_stride(mut self, stride: u32) -> Self {
        self.opcode_stride = stride;
        self
    }

    /// Synthesise a [`VmIsa`] from a list of handler semantics.
    #[must_use]
    pub fn synthesize(&self, semantics: &[HandlerSemantic]) -> VmIsa {
        let mut isa = VmIsa::new();

        for (i, sem) in semantics.iter().enumerate() {
            let opcode = self.first_opcode + (i as u32) * self.opcode_stride;
            let def = VmInstructionDef::from_semantic(opcode, sem);
            isa.instructions.insert(opcode, def);
        }

        // Infer bytecode format from the instruction distribution
        isa.format = Some(self.infer_format(semantics));
        isa.register_count = self.infer_register_count(semantics);
        isa.register_width = 32; // default; could be refined with deeper analysis
        isa.overall_confidence = self.overall_confidence(semantics);

        isa
    }

    fn infer_format(&self, semantics: &[HandlerSemantic]) -> BytecodeFormat {
        if semantics.is_empty() {
            return BytecodeFormat::Unknown;
        }
        // Count how many handlers have operands
        let with_operands = semantics
            .iter()
            .filter(|s| s.input_count > 0 || s.output_count > 0)
            .count();
        let ratio = with_operands as f64 / semantics.len() as f64;

        if ratio < 0.1 {
            // Almost no operands — likely fixed 1-byte opcode
            BytecodeFormat::Fixed(1)
        } else if ratio < 0.5 {
            BytecodeFormat::VariableOpcode1
        } else {
            BytecodeFormat::OpcodeWithOperands {
                opcode_bytes: 1,
                operand_bytes: 4,
            }
        }
    }

    fn infer_register_count(&self, semantics: &[HandlerSemantic]) -> u8 {
        // Heuristic: count how many handlers that use two operands exist
        let dual_op = semantics.iter().filter(|s| s.input_count >= 2).count();
        // More dual-operand instructions suggests more registers
        if dual_op >= 5 {
            16
        } else if dual_op >= 2 {
            8
        } else {
            4
        }
    }

    fn overall_confidence(&self, semantics: &[HandlerSemantic]) -> u8 {
        if semantics.is_empty() {
            return 0;
        }
        let sum: u32 = semantics.iter().map(|s| u32::from(s.confidence)).sum();
        (sum / semantics.len() as u32).min(100) as u8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn mnemonic_for_class(class: &HandlerClass, opcode: u32) -> String {
    let base = match class {
        HandlerClass::Add => "VADD",
        HandlerClass::Sub => "VSUB",
        HandlerClass::Mul => "VMUL",
        HandlerClass::Div => "VDIV",
        HandlerClass::Mod => "VMOD",
        HandlerClass::Inc => "VINC",
        HandlerClass::Dec => "VDEC",
        HandlerClass::Neg => "VNEG",
        HandlerClass::And => "VAND",
        HandlerClass::Or => "VOR",
        HandlerClass::Xor => "VXOR",
        HandlerClass::Not => "VNOT",
        HandlerClass::Shl => "VSHL",
        HandlerClass::Shr => "VSHR",
        HandlerClass::Sar => "VSAR",
        HandlerClass::Rol => "VROL",
        HandlerClass::Ror => "VROR",
        HandlerClass::Push => "VPUSH",
        HandlerClass::Pop => "VPOP",
        HandlerClass::Mov => "VMOV",
        HandlerClass::Load => "VLOAD",
        HandlerClass::Store => "VSTORE",
        HandlerClass::Jump => "VJMP",
        HandlerClass::JmpIfZero => "VJMPZ",
        HandlerClass::JmpIfNotZero => "VJMPNZ",
        HandlerClass::JmpIfLess => "VJMPL",
        HandlerClass::JmpIfGreater => "VJMPG",
        HandlerClass::Call => "VCALL",
        HandlerClass::Ret => "VRET",
        HandlerClass::Cmp => "VCMP",
        HandlerClass::Enter => "VENTER",
        HandlerClass::Leave => "VLEAVE",
        HandlerClass::In => "VIN",
        HandlerClass::Out => "VOUT",
        HandlerClass::Syscall => "VSYSCALL",
        HandlerClass::Halt => "VHALT",
        HandlerClass::Decrypt => "VDECRYPT",
        HandlerClass::Unknown => "VUNK",
    };
    format!("{base}_{opcode:02X}")
}

const fn estimate_operand_count(sem: &HandlerSemantic) -> u8 {
    match &sem.class {
        HandlerClass::Halt | HandlerClass::Ret => 0,
        HandlerClass::Push
        | HandlerClass::Pop
        | HandlerClass::Not
        | HandlerClass::Neg
        | HandlerClass::Inc
        | HandlerClass::Dec => 1,
        _ if sem.input_count > 0 => sem.input_count,
        _ => 2,
    }
}

const fn estimate_operand_width(sem: &HandlerSemantic) -> u8 {
    if sem.reads_memory || sem.writes_memory {
        4
    } else if sem.input_count > 0 || sem.output_count > 0 {
        1
    } else {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler_inferrer::HandlerSemanticInferrer;

    fn make_semantics() -> Vec<HandlerSemantic> {
        let inf = HandlerSemanticInferrer::new();
        let handlers = vec![
            (0x1000usize, vec![0x50u8, 0xC3]),  // push + ret
            (0x1010, vec![0x58u8, 0xC3]),       // pop + ret
            (0x1020, vec![0x01u8, 0xC8, 0xC3]), // add + ret
            (0x1030, vec![0xF4u8, 0xC3]),       // hlt + ret
            (0x1040, vec![0xEBu8, 0x00, 0xC3]), // jmp + ret
        ];
        inf.infer_all(&handlers)
    }

    #[test]
    fn test_synthesize_count() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        assert_eq!(isa.instructions.len(), 5);
    }

    #[test]
    fn test_synthesize_opcodes() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        assert!(isa.instructions.contains_key(&0));
        assert!(isa.instructions.contains_key(&4));
    }

    #[test]
    fn test_has_halt() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        assert!(isa.has_halt());
    }

    #[test]
    fn test_has_branches() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        assert!(isa.has_branches());
    }

    #[test]
    fn test_sorted_instructions() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        let sorted = isa.sorted_instructions();
        for w in sorted.windows(2) {
            assert!(w[0].opcode <= w[1].opcode);
        }
    }

    #[test]
    fn test_instructions_by_class() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        let halts = isa.instructions_by_class(&HandlerClass::Halt);
        assert!(!halts.is_empty());
    }

    #[test]
    fn test_disassembly_listing() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        let listing = isa.disassembly_listing();
        assert!(listing.contains("VHALT") || listing.contains("VUNK") || !listing.is_empty());
    }

    #[test]
    fn test_bytecode_format_display() {
        assert_eq!(BytecodeFormat::Fixed(4).to_string(), "fixed-4B");
        assert_eq!(BytecodeFormat::VariableOpcode1.to_string(), "var/1B-opcode");
    }

    #[test]
    fn test_instruction_def_display() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new().synthesize(&sems);
        let insn = isa.instructions.values().next().unwrap();
        let s = insn.to_string();
        assert!(s.contains("0x"));
    }

    #[test]
    fn test_custom_opcode_stride() {
        let sems = make_semantics();
        let isa = IsaSynthesizer::new()
            .with_opcode_stride(4)
            .synthesize(&sems);
        assert!(isa.instructions.contains_key(&0));
        assert!(isa.instructions.contains_key(&4));
        assert!(isa.instructions.contains_key(&8));
    }

    #[test]
    fn test_empty_semantics() {
        let isa = IsaSynthesizer::new().synthesize(&[]);
        assert_eq!(isa.instructions.len(), 0);
        assert_eq!(isa.overall_confidence, 0);
    }
}
