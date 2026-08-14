//! PowerPC calling conventions: `SysV` PPC32, `ELFv1`/`ELFv2` (ppc64), AIX.
//!
//! Covers parameter passing, return locations, callee/caller-saved registers,
//! stack frame layout (back-chain, LR save area, parameter area, local area),
//! and varargs handling.

// â”€â”€ ABI Enum â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Identifies the PowerPC ABI / calling convention variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PpcAbi {
    /// System V PPC 32-bit (most embedded Linux targets, classic PowerPC Linux).
    SysV32,
    /// `ELFv1` â€” ABI used by ppc64 glibc / toolchains until ~2014.
    /// Functions are referenced via function descriptors (.opd section).
    ElfV1,
    /// `ELFv2` â€” modern ppc64le ABI (POWER8+, little-endian, no .opd).
    ElfV2,
    /// AIX 32-bit calling convention.
    Aix32,
    /// AIX 64-bit calling convention.
    Aix64,
    /// EABI (embedded) â€” used by many bare-metal/VxWorks configurations.
    Eabi,
}

impl PpcAbi {
    /// Human-readable ABI name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SysV32 => "sysv-ppc32",
            Self::ElfV1 => "elfv1-ppc64",
            Self::ElfV2 => "elfv2-ppc64le",
            Self::Aix32 => "aix-ppc32",
            Self::Aix64 => "aix-ppc64",
            Self::Eabi => "eabi-ppc",
        }
    }

    /// Return `true` if this ABI is 64-bit.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::ElfV1 | Self::ElfV2 | Self::Aix64)
    }

    /// Return `true` if this is little-endian (`ELFv2` ppc64le).
    #[must_use]
    pub fn is_little_endian(self) -> bool {
        self == Self::ElfV2
    }
}

// â”€â”€ Parameter location â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Classification of a function parameter type for register/stack allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamClass {
    /// Integer or pointer value (fits in one GPR).
    Integer,
    /// 64-bit integer (two GPRs in 32-bit ABI).
    Integer64,
    /// Single-precision float.
    Float,
    /// Double-precision float.
    Double,
    /// Composite/struct passed by value (on stack or split across regs).
    Composite { size_bytes: u32 },
    /// Variable argument (past the named parameters).
    Vararg,
}

/// Where a specific parameter is located at function entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLoc {
    /// In a GPR.
    Gpr(u8),
    /// In a GPR pair (`low_reg`, `high_reg`) for 64-bit value in 32-bit ABI.
    GprPair(u8, u8),
    /// In an FPR.
    Fpr(u8),
    /// On the stack at the given byte offset from the stack pointer on entry.
    Stack { offset: u32, size: u32 },
}

impl ParamLoc {
    /// Return `true` if the parameter lives in a register.
    #[must_use]
    pub const fn is_register(&self) -> bool {
        matches!(self, Self::Gpr(_) | Self::GprPair(..) | Self::Fpr(_))
    }
}

// â”€â”€ Return location â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Where a function return value is placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnLoc {
    /// Single GPR (r3).
    Gpr(u8),
    /// Two GPRs for 64-bit return in 32-bit ABI (r3=hi, r4=lo).
    GprPair(u8, u8),
    /// Single FPR (f1).
    Fpr(u8),
    /// Struct return pointer in r3; actual struct at the address.
    StructPtr,
    /// Void / no return.
    Void,
}

// â”€â”€ Saved registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Set of registers that must be saved by the callee.
#[derive(Debug, Clone)]
pub struct SavedRegs {
    /// GPRs that are callee-saved (by register index).
    pub gprs: Vec<u8>,
    /// FPRs that are callee-saved.
    pub fprs: Vec<u8>,
    /// Whether LR must be saved (always true if the function calls others).
    pub save_lr: bool,
    /// Whether CR fields 2-4 must be saved.
    pub save_cr: bool,
}

impl SavedRegs {
    /// Callee-saved register set for `SysV` PPC32.
    #[must_use]
    pub fn sysv32() -> Self {
        Self {
            gprs: (13u8..=31).collect(),
            fprs: (14u8..=31).collect(),
            save_lr: true,
            save_cr: true,
        }
    }

    /// Callee-saved register set for `ELFv2` ppc64le.
    #[must_use]
    pub fn elfv2() -> Self {
        Self {
            gprs: (14u8..=31).collect(), // r14-r31; r13 = thread pointer, not saved
            fprs: (14u8..=31).collect(),
            save_lr: true,
            save_cr: true,
        }
    }

    /// Callee-saved register set for AIX 32.
    #[must_use]
    pub fn aix32() -> Self {
        Self {
            gprs: (13u8..=31).collect(),
            fprs: (14u8..=31).collect(),
            save_lr: true,
            save_cr: true,
        }
    }
}

// â”€â”€ Stack frame layout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Byte offsets within a standard `SysV` PPC32 stack frame, counted from the
/// caller's stack pointer (the address stored in the back-chain word).
pub mod frame_offsets_sysv32 {
    /// Back-chain word (pointer to previous frame).
    pub const BACK_CHAIN: i32 = 0;
    /// LR save area (return address saved by callee).
    ///
    /// In the `SysV` PPC32 linkage area the layout is:
    ///   [0] `back_chain`, [4] `CR_save`, [8] `LR_save`, [12+] parameter area.
    pub const LR_SAVE: i32 = 8;
    /// CR save area.
    ///
    /// The `SysV` PPC32 ABI does not define a dedicated CR save slot in the
    /// caller-frame linkage area; compilers that save CR use a callee-prolog
    /// slot chosen independently.  This constant is provided for reference
    /// only â€” prefer `FPSCR_SAVE` only in contexts where the compiler places
    /// FPSCR at this offset.
    pub const CR_SAVE: i32 = 8;
    /// FPSCR save area (optional, used by some compilers; same offset
    /// as CR_SAVE on variants that save only one of the two).
    #[doc(hidden)]
    pub const FPSCR_SAVE: i32 = 8;
    /// Parameter area base (first outgoing parameter slot).
    pub const PARAM_AREA: i32 = 8;
    /// Minimum stack frame size in bytes.
    pub const MIN_FRAME: u32 = 8;
}

/// Byte offsets within an `ELFv1` ppc64 stack frame.
pub mod frame_offsets_elfv1 {
    pub const BACK_CHAIN: i32 = 0;
    pub const CR_SAVE: i32 = 8;
    pub const LR_SAVE: i32 = 16;
    pub const TOC_SAVE: i32 = 40;
    pub const PARAM_AREA: i32 = 48;
    pub const MIN_FRAME: u32 = 112;
}

/// Byte offsets within an `ELFv2` ppc64le stack frame.
pub mod frame_offsets_elfv2 {
    pub const BACK_CHAIN: i32 = 0;
    pub const CR_SAVE: i32 = 8;
    pub const LR_SAVE: i32 = 16;
    pub const TOC_SAVE: i32 = 24;
    pub const PARAM_AREA: i32 = 32;
    pub const MIN_FRAME: u32 = 32;
}

/// A fully described stack frame for one calling context.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// The ABI this frame belongs to.
    pub abi: PpcAbi,
    /// Total frame size in bytes (caller's SP âˆ’ callee's SP).
    pub frame_size: u32,
    /// Byte offset from the callee's SP to the LR save slot.
    pub lr_save_offset: i32,
    /// Byte offset from the callee's SP to the CR save slot.
    pub cr_save_offset: i32,
    /// Byte offset from the callee's SP to the TOC pointer save slot.
    pub toc_save_offset: Option<i32>,
    /// Byte offset from the callee's SP to the first parameter slot.
    pub param_area_offset: i32,
    /// Byte offset from the callee's SP to the start of the local variable area.
    pub local_area_offset: i32,
    /// Byte offset from the callee's SP where GPR saves begin.
    pub gpr_save_offset: i32,
    /// Byte offset from the callee's SP where FPR saves begin.
    pub fpr_save_offset: i32,
    /// Registers that must be preserved by the callee.
    pub saved_regs: SavedRegs,
}

impl StackFrame {
    /// Build a minimal frame for `SysV` PPC32.
    #[must_use]
    pub fn minimal_sysv32() -> Self {
        Self {
            abi: PpcAbi::SysV32,
            frame_size: 32,
            lr_save_offset: frame_offsets_sysv32::LR_SAVE,
            cr_save_offset: frame_offsets_sysv32::CR_SAVE,
            toc_save_offset: None,
            param_area_offset: frame_offsets_sysv32::PARAM_AREA,
            local_area_offset: 32,
            gpr_save_offset: -8,  // grows down from top of frame
            fpr_save_offset: -64,
            saved_regs: SavedRegs::sysv32(),
        }
    }

    /// Build a minimal frame for `ELFv2`.
    #[must_use]
    pub fn minimal_elfv2() -> Self {
        Self {
            abi: PpcAbi::ElfV2,
            frame_size: 64,
            lr_save_offset: frame_offsets_elfv2::LR_SAVE,
            cr_save_offset: frame_offsets_elfv2::CR_SAVE,
            toc_save_offset: Some(frame_offsets_elfv2::TOC_SAVE),
            param_area_offset: frame_offsets_elfv2::PARAM_AREA,
            local_area_offset: 64,
            gpr_save_offset: -8,
            fpr_save_offset: -72,
            saved_regs: SavedRegs::elfv2(),
        }
    }

    /// Compute the address of the LR save slot given the callee's SP.
    #[must_use]
    pub fn lr_save_addr(&self, callee_sp: u64) -> u64 {
        callee_sp.wrapping_add_signed(i64::from(self.lr_save_offset))
    }

    /// Compute the address of the back-chain word given the callee's SP.
    #[must_use]
    pub const fn back_chain_addr(&self, callee_sp: u64) -> u64 {
        callee_sp // back-chain is always at offset 0
    }
}

// â”€â”€ Parameter allocator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// State machine that allocates parameter locations for a calling convention.
#[derive(Debug, Clone)]
pub struct ParamAllocator {
    pub abi: PpcAbi,
    /// Next available integer register index (0 = r3, etc.).
    gpr_next: u8,
    /// Next available float register index (0 = f1, etc.).
    fpr_next: u8,
    /// Current stack offset for overflow parameters (from `param_area` base).
    stack_offset: u32,
    /// Whether we are past the last named parameter (varargs mode).
    is_varargs: bool,
}

impl ParamAllocator {
    /// Create a new allocator for the given ABI.
    #[must_use]
    pub const fn new(abi: PpcAbi) -> Self {
        Self {
            abi,
            gpr_next: 0,
            fpr_next: 0,
            stack_offset: 0,
            is_varargs: false,
        }
    }

    /// Maximum number of integer parameter registers.
    const fn max_gpr_params(&self) -> u8 {
        match self.abi {
            PpcAbi::SysV32 | PpcAbi::Eabi | PpcAbi::ElfV1 | PpcAbi::ElfV2 | PpcAbi::Aix32 | PpcAbi::Aix64 => 8,   // r3â€“r10
        }
    }

    /// Maximum number of float parameter registers.
    const fn max_fpr_params(&self) -> u8 {
        match self.abi {
            PpcAbi::SysV32 | PpcAbi::Eabi => 8,  // f1â€“f8
            PpcAbi::ElfV1 | PpcAbi::ElfV2 | PpcAbi::Aix32 | PpcAbi::Aix64 => 13, // f1â€“f13
        }
    }

    /// First GPR used for parameters (r3).
    const fn gpr_base() -> u8 { 3 }
    /// First FPR used for parameters (f1).
    const fn fpr_base() -> u8 { 1 }

    /// Enter varargs mode (all subsequent allocations go to the stack).
    pub const fn enter_varargs(&mut self) {
        self.is_varargs = true;
    }

    /// Allocate the next parameter location.
    pub fn allocate(&mut self, class: ParamClass) -> ParamLoc {
        if self.is_varargs {
            return self.alloc_stack(4);
        }
        match class {
            ParamClass::Integer => {
                if self.gpr_next < self.max_gpr_params() {
                    let r = Self::gpr_base() + self.gpr_next;
                    self.gpr_next += 1;
                    ParamLoc::Gpr(r)
                } else {
                    self.alloc_stack(if self.abi.is_64bit() { 8 } else { 4 })
                }
            }
            ParamClass::Integer64 if !self.abi.is_64bit() => {
                // Need two GPRs; align to even register boundary in SysV PPC32
                if !self.gpr_next.is_multiple_of(2) {
                    self.gpr_next += 1;
                }
                if self.gpr_next + 1 < self.max_gpr_params() {
                    let hi = Self::gpr_base() + self.gpr_next;
                    let lo = hi + 1;
                    self.gpr_next += 2;
                    ParamLoc::GprPair(hi, lo)
                } else {
                    self.gpr_next = self.max_gpr_params(); // exhaust
                    self.alloc_stack(8)
                }
            }
            ParamClass::Integer64 => {
                // 64-bit ABI: same as Integer
                if self.gpr_next < self.max_gpr_params() {
                    let r = Self::gpr_base() + self.gpr_next;
                    self.gpr_next += 1;
                    ParamLoc::Gpr(r)
                } else {
                    self.alloc_stack(8)
                }
            }
            ParamClass::Float | ParamClass::Double => {
                let sz = if class == ParamClass::Float { 4 } else { 8 };
                if self.fpr_next < self.max_fpr_params() {
                    let f = Self::fpr_base() + self.fpr_next;
                    self.fpr_next += 1;
                    // In SysV PPC32, a float parameter still consumes a shadow
                    // GPR slot.
                    if matches!(self.abi, PpcAbi::SysV32 | PpcAbi::Eabi) {
                        let shadow_gprs = if sz == 8 { 2 } else { 1 };
                        self.gpr_next = (self.gpr_next + shadow_gprs).min(self.max_gpr_params());
                    }
                    ParamLoc::Fpr(f)
                } else {
                    self.alloc_stack(sz)
                }
            }
            ParamClass::Composite { size_bytes } => self.alloc_stack(size_bytes),
            ParamClass::Vararg => {
                self.enter_varargs();
                self.alloc_stack(8)
            }
        }
    }

    fn alloc_stack(&mut self, size: u32) -> ParamLoc {
        // Align to `size` bytes (up to 8).
        let align = size.min(8);
        if !self.stack_offset.is_multiple_of(align) {
            self.stack_offset += align - (self.stack_offset % align);
        }
        let off = self.stack_offset;
        self.stack_offset += size;
        ParamLoc::Stack { offset: off, size }
    }
}

// â”€â”€ Return location helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Compute the return location for the given ABI and return type class.
#[must_use]
pub const fn return_location(abi: PpcAbi, class: ParamClass) -> ReturnLoc {
    match class {
        ParamClass::Integer64 if !abi.is_64bit() => ReturnLoc::GprPair(3, 4),
        ParamClass::Integer | ParamClass::Integer64 => ReturnLoc::Gpr(3),
        ParamClass::Float | ParamClass::Double => ReturnLoc::Fpr(1),
        ParamClass::Composite { .. } => ReturnLoc::StructPtr,
        ParamClass::Vararg => ReturnLoc::Void,
    }
}

// â”€â”€ Function signature description â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A named function parameter.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub class: ParamClass,
}

/// A resolved function signature with parameter locations.
#[derive(Debug, Clone)]
pub struct ResolvedSignature {
    pub abi: PpcAbi,
    pub params: Vec<(Param, ParamLoc)>,
    pub return_loc: ReturnLoc,
    pub frame: StackFrame,
}

impl ResolvedSignature {
    /// Build a resolved signature for the given ABI and parameter list.
    #[must_use]
    pub fn resolve(abi: PpcAbi, params: Vec<Param>, return_class: ParamClass) -> Self {
        let mut alloc = ParamAllocator::new(abi);
        let resolved: Vec<(Param, ParamLoc)> = params
            .into_iter()
            .map(|p| {
                let loc = alloc.allocate(p.class);
                (p, loc)
            })
            .collect();
        let frame = match abi {
            PpcAbi::SysV32 | PpcAbi::Eabi | PpcAbi::Aix32 => StackFrame::minimal_sysv32(),
            _ => StackFrame::minimal_elfv2(),
        };
        Self {
            abi,
            params: resolved,
            return_loc: return_location(abi, return_class),
            frame,
        }
    }
}

// â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_names() {
        assert_eq!(PpcAbi::SysV32.name(), "sysv-ppc32");
        assert_eq!(PpcAbi::ElfV2.name(), "elfv2-ppc64le");
        assert!(PpcAbi::ElfV2.is_64bit());
        assert!(!PpcAbi::SysV32.is_64bit());
        assert!(PpcAbi::ElfV2.is_little_endian());
    }

    #[test]
    fn test_sysv32_int_params() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        assert_eq!(alloc.allocate(ParamClass::Integer), ParamLoc::Gpr(3));
        assert_eq!(alloc.allocate(ParamClass::Integer), ParamLoc::Gpr(4));
        assert_eq!(alloc.allocate(ParamClass::Integer), ParamLoc::Gpr(5));
    }

    #[test]
    fn test_sysv32_int_overflow_to_stack() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        for _ in 0..8 {
            alloc.allocate(ParamClass::Integer);
        }
        // 9th parameter goes on stack
        let loc = alloc.allocate(ParamClass::Integer);
        assert!(matches!(loc, ParamLoc::Stack { .. }));
    }

    #[test]
    fn test_sysv32_float_param() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        let loc = alloc.allocate(ParamClass::Float);
        assert_eq!(loc, ParamLoc::Fpr(1));
    }

    #[test]
    fn test_sysv32_64bit_pair() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        // First 64-bit param should be r3:r4
        let loc = alloc.allocate(ParamClass::Integer64);
        assert_eq!(loc, ParamLoc::GprPair(3, 4));
    }

    #[test]
    fn test_elfv2_int_param() {
        let mut alloc = ParamAllocator::new(PpcAbi::ElfV2);
        assert_eq!(alloc.allocate(ParamClass::Integer), ParamLoc::Gpr(3));
    }

    #[test]
    fn test_return_location_int() {
        assert_eq!(return_location(PpcAbi::SysV32, ParamClass::Integer), ReturnLoc::Gpr(3));
    }

    #[test]
    fn test_return_location_int64_32bit() {
        assert_eq!(return_location(PpcAbi::SysV32, ParamClass::Integer64), ReturnLoc::GprPair(3, 4));
    }

    #[test]
    fn test_return_location_float() {
        assert_eq!(return_location(PpcAbi::SysV32, ParamClass::Double), ReturnLoc::Fpr(1));
    }

    #[test]
    fn test_return_location_struct() {
        assert_eq!(return_location(PpcAbi::SysV32, ParamClass::Composite { size_bytes: 16 }), ReturnLoc::StructPtr);
    }

    #[test]
    fn test_stack_frame_sysv32() {
        let f = StackFrame::minimal_sysv32();
        assert_eq!(f.abi, PpcAbi::SysV32);
        assert_eq!(f.lr_save_offset, 8);
        assert!(f.toc_save_offset.is_none());
    }

    #[test]
    fn test_stack_frame_elfv2() {
        let f = StackFrame::minimal_elfv2();
        assert_eq!(f.lr_save_offset, 16);
        assert_eq!(f.toc_save_offset, Some(24));
    }

    #[test]
    fn test_lr_save_addr() {
        let f = StackFrame::minimal_sysv32();
        // SP = 0x1000, LR save = SP + 8
        assert_eq!(f.lr_save_addr(0x1000), 0x1008);
    }

    #[test]
    fn test_varargs() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        alloc.allocate(ParamClass::Integer); // r3
        alloc.enter_varargs();
        // All subsequent params on stack
        let loc = alloc.allocate(ParamClass::Integer);
        assert!(matches!(loc, ParamLoc::Stack { .. }));
    }

    #[test]
    fn test_resolved_signature() {
        let params = vec![
            Param { name: "a".to_string(), class: ParamClass::Integer },
            Param { name: "b".to_string(), class: ParamClass::Double },
        ];
        let sig = ResolvedSignature::resolve(PpcAbi::SysV32, params, ParamClass::Integer);
        assert_eq!(sig.params[0].1, ParamLoc::Gpr(3));
        assert_eq!(sig.params[1].1, ParamLoc::Fpr(1));
        assert_eq!(sig.return_loc, ReturnLoc::Gpr(3));
    }

    #[test]
    fn test_saved_regs_sysv32() {
        let sr = SavedRegs::sysv32();
        assert!(sr.gprs.contains(&14));
        assert!(sr.gprs.contains(&31));
        assert!(!sr.gprs.contains(&3));
        assert!(sr.save_lr);
    }

    #[test]
    fn test_saved_regs_elfv2() {
        let sr = SavedRegs::elfv2();
        assert!(sr.gprs.contains(&14));
        assert!(!sr.gprs.contains(&13)); // r13 = TLS pointer in elfv2
    }

    #[test]
    fn test_param_class_composite_stack() {
        let mut alloc = ParamAllocator::new(PpcAbi::SysV32);
        let loc = alloc.allocate(ParamClass::Composite { size_bytes: 32 });
        assert!(matches!(loc, ParamLoc::Stack { size: 32, .. }));
    }
}

