//! Motorola 68000 analysis — addressing modes, calling conventions,
//! Mac OS 68k ABI, PC-relative references, and function detection.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Re-exported ordered map type used by 68k symbol tables.
pub type M68kOrderedMap<K, V> = BTreeMap<K, V>;
/// Re-exported set type used by 68k register tracking.
pub type M68kSet<T> = HashSet<T>;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum M68kAnalysisError {
    #[error("unsupported addressing mode 0x{0:02x}")]
    UnsupportedAddressingMode(u8),
    #[error("invalid displacement size {0}")]
    InvalidDisplacement(u8),
    #[error("function not found at 0x{0:08x}")]
    FunctionNotFound(u32),
    #[error("empty instruction list")]
    EmptyFunction,
    #[error("PC-relative fixup overflow at 0x{0:08x}")]
    PcRelativeOverflow(u32),
}

// ─── Addressing Mode Analysis ─────────────────────────────────────────────────

/// M68k effective address modes (EA mode field + register field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressingMode {
    /// Dn — data register direct.
    DataRegDirect(u8),
    /// An — address register direct.
    AddrRegDirect(u8),
    /// (An) — address register indirect.
    AddrRegIndirect(u8),
    /// (An)+ — post-increment.
    PostIncrement(u8),
    /// -(An) — pre-decrement.
    PreDecrement(u8),
    /// (d16,An) — displacement.
    Displacement16(u8, i16),
    /// (d8,An,Xn) — index + 8-bit displacement.
    IndexedDisp8(u8, u8, i8),
    /// (xxx).W — absolute short.
    AbsoluteShort(u16),
    /// (xxx).L — absolute long.
    AbsoluteLong(u32),
    /// (d16,PC) — PC-relative with 16-bit displacement.
    PcRelative16(u32, i16),
    /// (d8,PC,Xn) — PC-relative with index.
    PcRelativeIndex(u32, u8, i8),
    /// #imm — immediate.
    Immediate(u32),
    /// Status register (SR) direct.
    StatusRegDirect,
    /// Unknown / not decoded.
    Unknown(u8),
}

impl AddressingMode {
    /// Whether this mode involves a memory access.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        !matches!(
            self,
            Self::DataRegDirect(_)
                | Self::AddrRegDirect(_)
                | Self::Immediate(_)
                | Self::StatusRegDirect
                | Self::Unknown(_)
        )
    }

    /// Whether this mode is PC-relative.
    #[must_use]
    pub const fn is_pc_relative(&self) -> bool {
        matches!(self, Self::PcRelative16(..) | Self::PcRelativeIndex(..))
    }

    /// Whether this mode modifies a register as a side effect.
    #[must_use]
    pub const fn has_side_effect(&self) -> bool {
        matches!(self, Self::PostIncrement(_) | Self::PreDecrement(_))
    }

    /// Decode from raw EA bits and PC (for PC-relative modes).
    #[must_use]
    pub const fn from_ea(mode: u8, reg: u8, pc: u32, extension: u32) -> Self {
        match mode {
            0 => Self::DataRegDirect(reg),
            1 => Self::AddrRegDirect(reg),
            2 => Self::AddrRegIndirect(reg),
            3 => Self::PostIncrement(reg),
            4 => Self::PreDecrement(reg),
            5 => {
                let d16 = (extension & 0xFFFF) as i16;
                Self::Displacement16(reg, d16)
            }
            6 => {
                let d8 = (extension & 0xFF) as i8;
                let xn = ((extension >> 12) & 0xF) as u8;
                Self::IndexedDisp8(reg, xn, d8)
            }
            7 => match reg {
                0 => Self::AbsoluteShort((extension & 0xFFFF) as u16),
                1 => Self::AbsoluteLong(extension),
                2 => {
                    let d16 = (extension & 0xFFFF) as i16;
                    Self::PcRelative16(pc, d16)
                }
                3 => {
                    let d8 = (extension & 0xFF) as i8;
                    let xn = ((extension >> 12) & 0xF) as u8;
                    Self::PcRelativeIndex(pc, xn, d8)
                }
                4 => Self::Immediate(extension),
                _ => Self::Unknown(reg),
            },
            _ => Self::Unknown(mode),
        }
    }

    /// Human-readable string representation.
    #[must_use]
    pub fn to_asm_string(&self) -> String {
        match *self {
            Self::DataRegDirect(r) => format!("D{r}"),
            Self::AddrRegDirect(r) => format!("A{r}"),
            Self::AddrRegIndirect(r) => format!("(A{r})"),
            Self::PostIncrement(r) => format!("(A{r})+"),
            Self::PreDecrement(r) => format!("-(A{r})"),
            Self::Displacement16(r, d) => format!("({d},A{r})"),
            Self::IndexedDisp8(r, xn, d) => format!("({d},A{r},X{xn})"),
            Self::AbsoluteShort(a) => format!("${a:04X}.W"),
            Self::AbsoluteLong(a) => format!("${a:08X}.L"),
            Self::PcRelative16(pc, d) => {
                let target = pc.wrapping_add_signed(i32::from(d));
                format!("(${target:08X},PC)")
            }
            Self::PcRelativeIndex(pc, xn, d) => {
                let t = pc.wrapping_add_signed(i32::from(d));
                format!("(${t:08X},PC,X{xn})")
            }
            Self::Immediate(v) => format!("#${v:08X}"),
            Self::StatusRegDirect => "SR".to_string(),
            Self::Unknown(x) => format!("?EA({x:02X})"),
        }
    }
}

// ─── M68kCallingConv ──────────────────────────────────────────────────────────

/// Calling convention variant for 68k targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum M68kCallingConvKind {
    /// Classic Mac OS toolbox ABI.
    MacOs,
    /// `AmigaOS` register-passing ABI.
    AmigaOs,
    /// Atari ST / TOS ABI.
    AtariTos,
    /// GCC/SVR4 stack-based ABI.
    SysV,
    /// GNU/Linux `m68k` `SysV` ABI.
    LinuxM68k,
}

/// Full 68k calling convention description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M68kCallingConv {
    pub kind: M68kCallingConvKind,
    pub int_arg_regs: Vec<String>,
    pub fp_arg_regs: Vec<String>,
    pub return_regs: Vec<String>,
    pub caller_saved: Vec<String>,
    pub callee_saved: Vec<String>,
    pub stack_grows: &'static str,
    pub stack_alignment: usize,
}

impl M68kCallingConv {
    /// Mac OS classic toolbox/Pascal ABI.
    #[must_use]
    pub fn mac_os() -> Self {
        Self {
            kind: M68kCallingConvKind::MacOs,
            int_arg_regs: vec![], // Mac OS passes all args on stack
            fp_arg_regs: vec![],
            return_regs: vec!["D0".into(), "D1".into()],
            caller_saved: vec![
                "D0".into(),
                "D1".into(),
                "D2".into(),
                "A0".into(),
                "A1".into(),
            ],
            callee_saved: vec![
                "D3".into(),
                "D4".into(),
                "D5".into(),
                "D6".into(),
                "D7".into(),
                "A2".into(),
                "A3".into(),
                "A4".into(),
                "A5".into(),
                "A6".into(),
            ],
            stack_grows: "downward",
            stack_alignment: 2,
        }
    }

    /// `AmigaOS` library call ABI (args in registers D0–D7, A0–A6).
    #[must_use]
    pub fn amiga_os() -> Self {
        Self {
            kind: M68kCallingConvKind::AmigaOs,
            int_arg_regs: vec![
                "D0".into(),
                "D1".into(),
                "D2".into(),
                "D3".into(),
                "D4".into(),
                "D5".into(),
                "D6".into(),
                "D7".into(),
            ],
            fp_arg_regs: vec![],
            return_regs: vec!["D0".into()],
            caller_saved: vec!["D0".into(), "D1".into(), "A0".into(), "A1".into()],
            callee_saved: vec![
                "D2".into(),
                "D3".into(),
                "D4".into(),
                "D5".into(),
                "D6".into(),
                "D7".into(),
                "A2".into(),
                "A3".into(),
                "A4".into(),
                "A5".into(),
                "A6".into(),
            ],
            stack_grows: "downward",
            stack_alignment: 4,
        }
    }

    /// GCC/SysV stack-based ABI.
    #[must_use]
    pub fn sysv() -> Self {
        Self {
            kind: M68kCallingConvKind::SysV,
            int_arg_regs: vec![], // all on stack
            fp_arg_regs: vec![],
            return_regs: vec!["D0".into(), "D1".into()],
            caller_saved: vec!["D0".into(), "D1".into(), "A0".into(), "A1".into()],
            callee_saved: vec![
                "D2".into(),
                "D3".into(),
                "D4".into(),
                "D5".into(),
                "D6".into(),
                "D7".into(),
                "A2".into(),
                "A3".into(),
                "A4".into(),
                "A5".into(),
                "A6".into(),
            ],
            stack_grows: "downward",
            stack_alignment: 4,
        }
    }

    /// Whether a register is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg)
    }
}

// ─── MacOS68kABI ──────────────────────────────────────────────────────────────

/// Mac OS 68k specific ABI details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOs68kAbi {
    /// A5 world base address (application globals).
    pub a5_world: u32,
    /// Toolbox trap table base address.
    pub trap_table_base: u32,
    /// Whether this binary uses THINK Pascal stack frames.
    pub think_pascal_style: bool,
    /// Detected global variable base offset from A5.
    pub globals_offset: i32,
}

impl MacOs68kAbi {
    /// Default Mac OS ABI context.
    #[must_use]
    pub const fn default_classic() -> Self {
        Self {
            a5_world: 0x0000_0914,
            trap_table_base: 0x0000_0400,
            think_pascal_style: false,
            globals_offset: 0,
        }
    }

    /// Decode a toolbox trap number from a TRAP instruction word.
    #[must_use]
    pub const fn decode_trap(&self, trap_word: u16) -> MacOsTrap {
        // Mac OS convention: bit 11 = 0 → Toolbox trap (0xA000–0xA7FF),
        //                  bit 11 = 1 → OS trap (0xA800–0xAFFF).
        let is_toolbox = (trap_word >> 11) & 1 == 0;
        let number = trap_word & 0x01FF;
        MacOsTrap {
            trap_word,
            number,
            is_toolbox,
        }
    }
}

/// A decoded Mac OS 68k TRAP instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsTrap {
    pub trap_word: u16,
    pub number: u16,
    pub is_toolbox: bool,
}

impl MacOsTrap {
    /// Address in the trap dispatch table for this trap.
    #[must_use]
    pub const fn dispatch_address(&self, base: u32) -> u32 {
        base + (self.number as u32 * 4)
    }
}

// ─── PcRelativeRef ────────────────────────────────────────────────────────────

/// A PC-relative reference found in a 68k instruction stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcRelativeRef {
    /// Address of the instruction containing the PC-relative EA.
    pub instr_addr: u32,
    /// Computed absolute target address.
    pub target_addr: u32,
    /// Displacement value.
    pub displacement: i32,
    /// Size of displacement (8, 16, or 32 bits).
    pub disp_size: u8,
    /// Whether this reference targets code.
    pub is_code_ref: bool,
}

impl PcRelativeRef {
    /// Create from PC, displacement, and size.
    ///
    /// # Errors
    ///
    /// Returns [`M68kAnalysisError::InvalidDisplacement`] if `disp_size` is not 8, 16, or 32.
    pub const fn new(
        instr_addr: u32,
        pc: u32,
        displacement: i32,
        disp_size: u8,
    ) -> Result<Self, M68kAnalysisError> {
        if !matches!(disp_size, 8 | 16 | 32) {
            return Err(M68kAnalysisError::InvalidDisplacement(disp_size));
        }
        let target = pc.wrapping_add_signed(displacement);
        Ok(Self {
            instr_addr,
            target_addr: target,
            displacement,
            disp_size,
            is_code_ref: false,
        })
    }

    /// Mark this as a code reference.
    #[must_use]
    pub const fn as_code(mut self) -> Self {
        self.is_code_ref = true;
        self
    }
}

// ─── M68kFunctionDetector ─────────────────────────────────────────────────────

/// Per-function statistics for M68k code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct M68kFunctionStats {
    pub total_instructions: u32,
    pub load_store_count: u32,
    pub branch_count: u32,
    pub call_count: u32,
    pub trap_count: u32,
    pub movem_count: u32,
    pub link_unlink_depth: i32,
    /// True if at least one LINK instruction was seen (even when balanced by UNLK).
    pub link_seen: bool,
    pub pc_refs: Vec<PcRelativeRef>,
}

impl M68kFunctionStats {
    /// Whether this function uses LINK/UNLK frame setup.
    #[must_use]
    pub const fn uses_frame_setup(&self) -> bool {
        self.link_seen || self.link_unlink_depth != 0
    }

    /// Memory access ratio.
    #[must_use]
    pub fn memory_ratio(&self) -> f64 {
        if self.total_instructions == 0 {
            return 0.0;
        }
        f64::from(self.load_store_count) / f64::from(self.total_instructions)
    }
}

/// Detected M68k function boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M68kFunction {
    pub start_addr: u32,
    pub end_addr: u32,
    pub name: Option<String>,
    pub stats: M68kFunctionStats,
    pub calling_conv: Option<M68kCallingConvKind>,
}

/// Detects and profiles M68k functions from decoded instruction sequences.
#[derive(Debug, Default)]
pub struct M68kFunctionDetector {
    functions: HashMap<u32, M68kFunction>,
}

impl M68kFunctionDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Profile a function from decoded `(addr, mnemonic, flags)` tuples.
    ///
    /// Flags: 0x01=branch, 0x02=call, 0x04=ret, 0x08=mem, 0x10=trap, 0x20=movem
    ///
    /// # Errors
    ///
    /// Returns [`M68kAnalysisError::EmptyFunction`] if `instructions` is empty.
    pub fn profile(
        &mut self,
        start: u32,
        instructions: &[(u32, String, u32)],
    ) -> Result<(), M68kAnalysisError> {
        if instructions.is_empty() {
            return Err(M68kAnalysisError::EmptyFunction);
        }
        let mut stats = M68kFunctionStats::default();
        let mut max_addr = start;

        for &(addr, ref mn, flags) in instructions {
            stats.total_instructions += 1;
            if addr > max_addr {
                max_addr = addr;
            }
            if flags & 0x01 != 0 {
                stats.branch_count += 1;
            }
            if flags & 0x02 != 0 {
                stats.call_count += 1;
            }
            if flags & 0x08 != 0 {
                stats.load_store_count += 1;
            }
            if flags & 0x10 != 0 {
                stats.trap_count += 1;
            }
            if flags & 0x20 != 0 {
                stats.movem_count += 1;
            }
            match mn.as_str() {
                "LINK" => { stats.link_unlink_depth += 1; stats.link_seen = true; }
                "UNLK" => stats.link_unlink_depth -= 1,
                _ => {}
            }
        }
        let end = max_addr + 2;
        let cc = if stats.link_seen || stats.link_unlink_depth.abs() > 0 {
            Some(M68kCallingConvKind::MacOs)
        } else if stats.movem_count > 0 {
            Some(M68kCallingConvKind::SysV)
        } else {
            None
        };
        self.functions.insert(
            start,
            M68kFunction {
                start_addr: start,
                end_addr: end,
                name: None,
                stats,
                calling_conv: cc,
            },
        );
        Ok(())
    }

    /// Retrieve a profiled function.
    #[must_use]
    pub fn get(&self, addr: u32) -> Option<&M68kFunction> {
        self.functions.get(&addr)
    }

    /// All detected functions sorted by start address.
    #[must_use]
    pub fn all_functions(&self) -> Vec<&M68kFunction> {
        let mut v: Vec<_> = Vec::with_capacity(self.functions.len());
        v.extend(self.functions.values());
        v.sort_by_key(|f| f.start_addr);
        v
    }

    /// Functions that appear to use the Mac OS ABI.
    #[must_use]
    pub fn mac_os_functions(&self) -> Vec<&M68kFunction> {
        let mut out = Vec::with_capacity(self.functions.len());
        out.extend(self.functions.values().filter(|f| f.calling_conv == Some(M68kCallingConvKind::MacOs)));
        out
    }
}

// ─── M68kAnalysis ─────────────────────────────────────────────────────────────

/// Top-level M68k analysis object.
#[derive(Debug)]
pub struct M68kAnalysis {
    pub detector: M68kFunctionDetector,
    pub calling_conv: M68kCallingConv,
    pub mac_abi: MacOs68kAbi,
    pub pc_refs: Vec<PcRelativeRef>,
}

impl M68kAnalysis {
    /// Create an analysis context for classic Mac OS targets.
    #[must_use]
    pub fn new_mac_os() -> Self {
        Self {
            detector: M68kFunctionDetector::new(),
            calling_conv: M68kCallingConv::mac_os(),
            mac_abi: MacOs68kAbi::default_classic(),
            pc_refs: Vec::new(),
        }
    }

    /// Create for Amiga OS targets.
    #[must_use]
    pub fn new_amiga_os() -> Self {
        Self {
            detector: M68kFunctionDetector::new(),
            calling_conv: M68kCallingConv::amiga_os(),
            mac_abi: MacOs68kAbi::default_classic(),
            pc_refs: Vec::new(),
        }
    }

    /// Record a discovered PC-relative reference.
    pub fn record_pc_ref(&mut self, r: PcRelativeRef) {
        self.pc_refs.push(r);
    }

    /// All code PC-relative references.
    #[must_use]
    pub fn code_pc_refs(&self) -> Vec<&PcRelativeRef> {
        let mut out = Vec::with_capacity(self.pc_refs.len());
        out.extend(self.pc_refs.iter().filter(|r| r.is_code_ref));
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AddressingMode ──────────────────────────────────────────────────────

    #[test]
    fn test_data_reg_direct_not_memory() {
        let ea = AddressingMode::DataRegDirect(0);
        assert!(!ea.is_memory());
    }

    #[test]
    fn test_addr_reg_indirect_is_memory() {
        let ea = AddressingMode::AddrRegIndirect(0);
        assert!(ea.is_memory());
    }

    #[test]
    fn test_post_increment_has_side_effect() {
        let ea = AddressingMode::PostIncrement(1);
        assert!(ea.has_side_effect());
    }

    #[test]
    fn test_pre_decrement_has_side_effect() {
        let ea = AddressingMode::PreDecrement(2);
        assert!(ea.has_side_effect());
    }

    #[test]
    fn test_pc_relative_is_flagged() {
        let ea = AddressingMode::PcRelative16(0x1000, 10);
        assert!(ea.is_pc_relative());
    }

    #[test]
    fn test_immediate_not_pc_relative() {
        let ea = AddressingMode::Immediate(42);
        assert!(!ea.is_pc_relative());
    }

    #[test]
    fn test_from_ea_data_reg() {
        let ea = AddressingMode::from_ea(0, 3, 0x1000, 0);
        assert_eq!(ea, AddressingMode::DataRegDirect(3));
    }

    #[test]
    fn test_from_ea_absolute_long() {
        let ea = AddressingMode::from_ea(7, 1, 0, 0xDEAD_BEEF);
        assert_eq!(ea, AddressingMode::AbsoluteLong(0xDEAD_BEEF));
    }

    #[test]
    fn test_from_ea_immediate() {
        let ea = AddressingMode::from_ea(7, 4, 0, 42);
        assert_eq!(ea, AddressingMode::Immediate(42));
    }

    #[test]
    fn test_from_ea_pc_relative() {
        let ea = AddressingMode::from_ea(7, 2, 0x1000, 0x0010);
        assert!(ea.is_pc_relative());
    }

    #[test]
    fn test_asm_string_data_reg() {
        assert_eq!(AddressingMode::DataRegDirect(2).to_asm_string(), "D2");
    }

    #[test]
    fn test_asm_string_post_inc() {
        assert_eq!(AddressingMode::PostIncrement(3).to_asm_string(), "(A3)+");
    }

    #[test]
    fn test_asm_string_absolute_short() {
        assert_eq!(
            AddressingMode::AbsoluteShort(0x1234).to_asm_string(),
            "$1234.W"
        );
    }

    // ── M68kCallingConv ─────────────────────────────────────────────────────

    #[test]
    fn test_mac_os_callee_saved() {
        let cc = M68kCallingConv::mac_os();
        assert!(cc.is_callee_saved("D3"));
        assert!(!cc.is_callee_saved("D0"));
    }

    #[test]
    fn test_amiga_os_return_reg() {
        let cc = M68kCallingConv::amiga_os();
        assert!(cc.return_regs.contains(&"D0".to_string()));
    }

    #[test]
    fn test_sysv_stack_alignment() {
        let cc = M68kCallingConv::sysv();
        assert_eq!(cc.stack_alignment, 4);
    }

    #[test]
    fn test_mac_os_stack_alignment() {
        let cc = M68kCallingConv::mac_os();
        assert_eq!(cc.stack_alignment, 2);
    }

    // ── MacOs68kAbi ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_toolbox_trap() {
        let abi = MacOs68kAbi::default_classic();
        // 0xA000 = toolbox trap 0x000
        let t = abi.decode_trap(0xA000);
        assert!(t.is_toolbox);
        assert_eq!(t.number, 0);
    }

    #[test]
    fn test_decode_os_trap() {
        let abi = MacOs68kAbi::default_classic();
        // 0xA800 = OS trap (bit 11 = 0 after masking for OS traps = 0x08xx)
        let t = abi.decode_trap(0xA080);
        assert_eq!(t.number, 0x80);
    }

    #[test]
    fn test_trap_dispatch_address() {
        let abi = MacOs68kAbi::default_classic();
        let t = abi.decode_trap(0xA001);
        let addr = t.dispatch_address(0x400);
        assert_eq!(addr, 0x404); // base + (1 * 4)
    }

    // ── PcRelativeRef ───────────────────────────────────────────────────────

    #[test]
    fn test_pc_ref_forward() {
        let r = PcRelativeRef::new(0x1000, 0x1002, 10, 16).unwrap();
        assert_eq!(r.target_addr, 0x100C);
    }

    #[test]
    fn test_pc_ref_backward() {
        let r = PcRelativeRef::new(0x1020, 0x1022, -0x20, 16).unwrap();
        assert_eq!(r.target_addr, 0x1002);
    }

    #[test]
    fn test_pc_ref_invalid_size() {
        let r = PcRelativeRef::new(0x1000, 0x1000, 0, 4);
        assert!(r.is_err());
    }

    #[test]
    fn test_pc_ref_as_code() {
        let r = PcRelativeRef::new(0x1000, 0x1002, 4, 16).unwrap().as_code();
        assert!(r.is_code_ref);
    }

    // ── M68kFunctionDetector ────────────────────────────────────────────────

    fn make_m68k_instrs(seq: &[(&str, u32)]) -> Vec<(u32, String, u32)> {
        seq.iter()
            .enumerate()
            .map(|(i, (mn, flags))| {
                (
                    0x1000_u32 + u32::try_from(i).unwrap() * 2,
                    mn.to_string(),
                    *flags,
                )
            })
            .collect()
    }

    #[test]
    fn test_detector_basic_profile() {
        let mut d = M68kFunctionDetector::new();
        let instrs = make_m68k_instrs(&[("MOVE", 0x08), ("MOVE", 0x08), ("RTS", 0x04)]);
        d.profile(0x1000, &instrs).unwrap();
        let f = d.get(0x1000).unwrap();
        assert_eq!(f.stats.load_store_count, 2);
    }

    #[test]
    fn test_detector_link_unlk() {
        let mut d = M68kFunctionDetector::new();
        let instrs = make_m68k_instrs(&[("LINK", 0), ("MOVE", 0x08), ("UNLK", 0), ("RTS", 0x04)]);
        d.profile(0x1000, &instrs).unwrap();
        let f = d.get(0x1000).unwrap();
        assert_eq!(f.calling_conv, Some(M68kCallingConvKind::MacOs));
    }

    #[test]
    fn test_detector_trap_counting() {
        let mut d = M68kFunctionDetector::new();
        let instrs = make_m68k_instrs(&[("TRAP", 0x10), ("TRAP", 0x10), ("RTS", 0x04)]);
        d.profile(0x1000, &instrs).unwrap();
        let f = d.get(0x1000).unwrap();
        assert_eq!(f.stats.trap_count, 2);
    }

    #[test]
    fn test_detector_empty_error() {
        let mut d = M68kFunctionDetector::new();
        assert!(d.profile(0x1000, &[]).is_err());
    }

    #[test]
    fn test_detector_all_functions_sorted() {
        let mut d = M68kFunctionDetector::new();
        let i1 = make_m68k_instrs(&[("NOP", 0)]);
        let i2 = make_m68k_instrs(&[("NOP", 0)]);
        d.profile(0x2000, &i1).unwrap();
        d.profile(0x1000, &i2).unwrap();
        let funcs = d.all_functions();
        assert_eq!(funcs[0].start_addr, 0x1000);
        assert_eq!(funcs[1].start_addr, 0x2000);
    }

    // ── M68kAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_mac_os_creation() {
        let a = M68kAnalysis::new_mac_os();
        assert_eq!(a.calling_conv.kind, M68kCallingConvKind::MacOs);
    }

    #[test]
    fn test_analysis_amiga_creation() {
        let a = M68kAnalysis::new_amiga_os();
        assert_eq!(a.calling_conv.kind, M68kCallingConvKind::AmigaOs);
    }

    #[test]
    fn test_analysis_record_pc_ref() {
        let mut a = M68kAnalysis::new_mac_os();
        let r = PcRelativeRef::new(0x1000, 0x1002, 4, 16).unwrap().as_code();
        a.record_pc_ref(r);
        assert_eq!(a.code_pc_refs().len(), 1);
    }

    #[test]
    fn test_analysis_data_pc_ref_not_in_code_refs() {
        let mut a = M68kAnalysis::new_mac_os();
        let r = PcRelativeRef::new(0x1000, 0x1002, 4, 16).unwrap(); // not .as_code()
        a.record_pc_ref(r);
        assert!(a.code_pc_refs().is_empty());
    }
}
