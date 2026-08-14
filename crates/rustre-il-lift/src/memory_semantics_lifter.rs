//! Memory semantics lifter.
//!
//! Provides [`MemorySemanticsLifter`], [`LoadExpr`], [`StoreExpr`], and
//! [`lift_memory_op()`] for converting memory-access effects in the IL into
//! typed, annotated load and store descriptors that higher-level passes can
//! consume.

use std::collections::HashMap;
use std::fmt;

use crate::{Effect, IrExpr, LiftedInstr, LiftLevel};

// ─────────────────────────────────────────────────────────────────────────────
// MemSize
// ─────────────────────────────────────────────────────────────────────────────

/// Byte width of a single memory operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemSize {
    Byte,
    Word,
    DWord,
    QWord,
    OWord,
    YWord,
    ZWord,
    Other(u8),
}

impl MemSize {
    #[must_use] 
    pub const fn from_bytes(n: u8) -> Self {
        match n {
            1 => Self::Byte,
            2 => Self::Word,
            4 => Self::DWord,
            8 => Self::QWord,
            16 => Self::OWord,
            32 => Self::YWord,
            64 => Self::ZWord,
            other => Self::Other(other),
        }
    }

    #[must_use] 
    pub const fn as_bytes(&self) -> u8 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::DWord => 4,
            Self::QWord => 8,
            Self::OWord => 16,
            Self::YWord => 32,
            Self::ZWord => 64,
            Self::Other(n) => *n,
        }
    }

    #[must_use] 
    pub fn as_bits(&self) -> u16 {
        u16::from(self.as_bytes()) * 8
    }
}

impl fmt::Display for MemSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}b", self.as_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessType
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a memory access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessType {
    Load,
    Store,
    AtomicLoad,
    AtomicStore,
    AtomicReadModifyWrite,
    Prefetch,
    Fence,
}

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Load => "load",
            Self::Store => "store",
            Self::AtomicLoad => "atomic_load",
            Self::AtomicStore => "atomic_store",
            Self::AtomicReadModifyWrite => "atomic_rmw",
            Self::Prefetch => "prefetch",
            Self::Fence => "fence",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressExpr
// ─────────────────────────────────────────────────────────────────────────────

/// Decomposition of an effective address expression.
#[derive(Debug, Clone)]
pub struct AddressExpr {
    /// Base register or constant address.
    pub base: IrExpr,
    /// Optional index register.
    pub index: Option<IrExpr>,
    /// Index scale factor (1, 2, 4, or 8).
    pub scale: u8,
    /// Constant displacement.
    pub displacement: i64,
    /// The fully composed effective address expression.
    pub effective: IrExpr,
}

impl AddressExpr {
    /// Construct from an arbitrary IR expression (no decomposition).
    #[must_use] 
    pub fn opaque(expr: IrExpr) -> Self {
        Self {
            effective: expr.clone(),
            base: expr,
            index: None,
            scale: 1,
            displacement: 0,
        }
    }

    /// Try to decompose `base + index * scale + disp` from nested Add/Mul.
    #[must_use] 
    pub fn decompose(expr: &IrExpr) -> Self {
        let mut result = Self::opaque(expr.clone());
        result.try_decompose(expr);
        result
    }

    fn try_decompose(&mut self, expr: &IrExpr) {
        match expr {
            IrExpr::Add(l, r) => {
                // Check for base + const displacement.
                if let IrExpr::Const(d) = r.as_ref() {
                    self.displacement = (*d).cast_signed();
                    self.base = *l.clone();
                } else {
                    self.base = *l.clone();
                    self.index = Some(*r.clone());
                }
            }
            IrExpr::Reg(_) | IrExpr::Const(_) => {
                self.base = expr.clone();
            }
            _ => {}
        }
    }
}

impl fmt::Display for AddressExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.effective)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadExpr
// ─────────────────────────────────────────────────────────────────────────────

/// A typed, annotated memory load operation.
#[derive(Debug, Clone)]
pub struct LoadExpr {
    /// Address being loaded from.
    pub address: AddressExpr,
    /// Destination register or IR variable name.
    pub dest: String,
    /// Width of the loaded value.
    pub size: MemSize,
    /// Whether the load is sign-extended into `dest`.
    pub sign_extend: bool,
    /// Whether this is an atomic operation.
    pub access_type: AccessType,
    /// Virtual address of the instruction performing the load.
    pub instr_addr: u64,
    /// Optional inferred type tag.
    pub type_hint: Option<String>,
}

impl LoadExpr {
    #[must_use] 
    pub const fn new(address: AddressExpr, dest: String, size: MemSize, instr_addr: u64) -> Self {
        Self {
            address,
            dest,
            size,
            sign_extend: false,
            access_type: AccessType::Load,
            instr_addr,
            type_hint: None,
        }
    }

    #[must_use] 
    pub const fn sign_extended(mut self) -> Self {
        self.sign_extend = true;
        self
    }

    #[must_use]
    pub fn with_type_hint(mut self, hint: impl Into<String>) -> Self {
        self.type_hint = Some(hint.into());
        self
    }

    /// Render as an assignment expression for display.
    #[must_use] 
    pub fn format_expr(&self) -> String {
        let ext = if self.sign_extend { "sx" } else { "zx" };
        format!(
            "{} = {}load{}[{}] ({})",
            self.dest,
            if self.sign_extend { "s" } else { "u" },
            self.size.as_bits(),
            self.address,
            ext,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StoreExpr
// ─────────────────────────────────────────────────────────────────────────────

/// A typed, annotated memory store operation.
#[derive(Debug, Clone)]
pub struct StoreExpr {
    /// Address being stored to.
    pub address: AddressExpr,
    /// The value being written.
    pub value: IrExpr,
    /// Width of the stored value.
    pub size: MemSize,
    /// Whether this is an atomic operation.
    pub access_type: AccessType,
    /// Virtual address of the instruction performing the store.
    pub instr_addr: u64,
    /// Optional inferred type tag.
    pub type_hint: Option<String>,
}

impl StoreExpr {
    #[must_use] 
    pub const fn new(
        address: AddressExpr,
        value: IrExpr,
        size: MemSize,
        instr_addr: u64,
    ) -> Self {
        Self {
            address,
            value,
            size,
            access_type: AccessType::Store,
            instr_addr,
            type_hint: None,
        }
    }

    #[must_use]
    pub fn with_type_hint(mut self, hint: impl Into<String>) -> Self {
        self.type_hint = Some(hint.into());
        self
    }

    #[must_use] 
    pub fn format_expr(&self) -> String {
        format!(
            "store{}[{}] = {}",
            self.size.as_bits(),
            self.address,
            self.value,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryOp — union of load and store
// ─────────────────────────────────────────────────────────────────────────────

/// Either a load or a store.
#[derive(Debug, Clone)]
pub enum MemoryOp {
    Load(LoadExpr),
    Store(StoreExpr),
}

impl MemoryOp {
    #[must_use] 
    pub const fn is_load(&self) -> bool {
        matches!(self, Self::Load(_))
    }

    #[must_use] 
    pub const fn is_store(&self) -> bool {
        matches!(self, Self::Store(_))
    }

    #[must_use] 
    pub const fn address(&self) -> &AddressExpr {
        match self {
            Self::Load(l) => &l.address,
            Self::Store(s) => &s.address,
        }
    }

    #[must_use] 
    pub const fn size(&self) -> MemSize {
        match self {
            Self::Load(l) => l.size,
            Self::Store(s) => s.size,
        }
    }

    #[must_use] 
    pub fn format_expr(&self) -> String {
        match self {
            Self::Load(l) => l.format_expr(),
            Self::Store(s) => s.format_expr(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySemanticsLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Converts raw IL memory effects into typed [`MemoryOp`]s.
#[derive(Debug, Default)]
pub struct MemorySemanticsLifter {
    /// Mnemonic → sign-extend flag.
    sign_extend_mnemonics: HashMap<String, bool>,
    /// Mnemonic → atomic flag.
    atomic_mnemonics: Vec<String>,
}

impl MemorySemanticsLifter {
    #[must_use] 
    pub fn new() -> Self {
        let mut s = Self::default();
        // x86 sign-extending loads.
        for m in &["movsx", "movsxd", "movs", "cbw", "cwd", "cdq", "cqo"] {
            s.sign_extend_mnemonics.insert(m.to_string(), true);
        }
        // x86 atomic instructions.
        for m in &["lock", "xchg", "cmpxchg", "xadd", "bts", "btr", "btc"] {
            s.atomic_mnemonics.push(m.to_string());
        }
        s
    }

    fn is_sign_extend(&self, mnemonic: &str) -> bool {
        self.sign_extend_mnemonics.contains_key(&mnemonic.to_ascii_lowercase())
    }

    fn is_atomic(&self, mnemonic: &str) -> bool {
        let m = mnemonic.to_ascii_lowercase();
        self.atomic_mnemonics.iter().any(|a| m.contains(a.as_str()))
    }

    /// Extract all memory operations from an instruction's effects.
    #[must_use] 
    pub fn extract_ops(&self, instr: &LiftedInstr) -> Vec<MemoryOp> {
        let mut ops = Vec::new();
        let mnem = &instr.original_mnemonic;
        let sign_ext = self.is_sign_extend(mnem);
        let atomic = self.is_atomic(mnem);

        for effect in &instr.effects {
            match effect {
                Effect::MemRead { addr, dest, size } => {
                    let addr_expr = AddressExpr::decompose(&addr.clone());
                    let mut load = LoadExpr::new(
                        addr_expr,
                        dest.clone(),
                        MemSize::from_bytes(*size),
                        instr.address,
                    );
                    if sign_ext {
                        load = load.sign_extended();
                    }
                    if atomic {
                        load.access_type = AccessType::AtomicLoad;
                    }
                    ops.push(MemoryOp::Load(load));
                }
                Effect::MemWrite { addr, value, size } => {
                    let addr_expr = AddressExpr::decompose(&addr.clone());
                    let mut store = StoreExpr::new(
                        addr_expr,
                        value.clone(),
                        MemSize::from_bytes(*size),
                        instr.address,
                    );
                    if atomic {
                        store.access_type = AccessType::AtomicStore;
                    }
                    ops.push(MemoryOp::Store(store));
                }
                _ => {}
            }
        }
        ops
    }

    /// Analyse a batch of instructions and accumulate all memory operations.
    #[must_use] 
    pub fn extract_all(&self, instrs: &[LiftedInstr]) -> Vec<(u64, MemoryOp)> {
        let mut result = Vec::new();
        for instr in instrs {
            for op in self.extract_ops(instr) {
                result.push((instr.address, op));
            }
        }
        result
    }

    /// Count loads and stores separately.
    #[must_use] 
    pub fn stats(&self, instrs: &[LiftedInstr]) -> (usize, usize) {
        let ops = self.extract_all(instrs);
        let loads = ops.iter().filter(|(_, o)| o.is_load()).count();
        let stores = ops.iter().filter(|(_, o)| o.is_store()).count();
        (loads, stores)
    }

    /// Minimum IL [`LiftLevel`] required for memory semantics extraction.
    ///
    /// MemRead/MemWrite effects only carry typed address & size information
    /// once instructions have been lifted to LLIL.
    #[must_use] 
    pub const fn min_supported_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    /// Whether `level` is high enough to feed [`Self::extract_ops`].
    #[must_use] 
    pub fn supports_level(&self, level: LiftLevel) -> bool {
        level.at_least(self.min_supported_level())
    }

    /// Extract memory ops only from instructions lifted to a supported
    /// [`LiftLevel`]. Below-threshold instructions are skipped silently.
    #[must_use] 
    pub fn extract_all_filtered(&self, instrs: &[LiftedInstr]) -> Vec<(u64, MemoryOp)> {
        let mut result = Vec::new();
        for instr in instrs {
            if !self.supports_level(instr.il_level) {
                continue;
            }
            for op in self.extract_ops(instr) {
                result.push((instr.address, op));
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lift_memory_op
// ─────────────────────────────────────────────────────────────────────────────

/// Primary entry point: extract all memory operations from `instr`.
#[must_use] 
pub fn lift_memory_op(
    lifter: &MemorySemanticsLifter,
    instr: &LiftedInstr,
) -> Vec<MemoryOp> {
    lifter.extract_ops(instr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn instr_with_effects(mnemonic: &str, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: 0x1000,
            original_mnemonic: mnemonic.to_string(),
            ir_text: mnemonic.to_string(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    fn make_load_instr(dest: &str, addr: IrExpr, size: u8) -> LiftedInstr {
        instr_with_effects(
            "mov",
            vec![Effect::MemRead { addr, dest: dest.to_string(), size }],
        )
    }

    fn make_store_instr(addr: IrExpr, value: IrExpr, size: u8) -> LiftedInstr {
        instr_with_effects(
            "mov",
            vec![Effect::MemWrite { addr, value, size }],
        )
    }

    #[test]
    fn extracts_load_op() {
        let lifter = MemorySemanticsLifter::new();
        let instr = make_load_instr("rax", IrExpr::Reg("rbp".to_string()), 8);
        let ops = lift_memory_op(&lifter, &instr);
        assert_eq!(ops.len(), 1);
        assert!(ops[0].is_load());
    }

    #[test]
    fn extracts_store_op() {
        let lifter = MemorySemanticsLifter::new();
        let instr = make_store_instr(
            IrExpr::Reg("rsp".to_string()),
            IrExpr::Const(0),
            8,
        );
        let ops = lift_memory_op(&lifter, &instr);
        assert_eq!(ops.len(), 1);
        assert!(ops[0].is_store());
    }

    #[test]
    fn sign_extend_detected_for_movsx() {
        let lifter = MemorySemanticsLifter::new();
        let instr = instr_with_effects(
            "movsx",
            vec![Effect::MemRead {
                addr: IrExpr::Reg("rbp".to_string()),
                dest: "rax".to_string(),
                size: 4,
            }],
        );
        let ops = lift_memory_op(&lifter, &instr);
        if let MemoryOp::Load(l) = &ops[0] {
            assert!(l.sign_extend);
        } else {
            panic!("expected load");
        }
    }

    #[test]
    fn atomic_detected_for_xchg() {
        let lifter = MemorySemanticsLifter::new();
        let instr = instr_with_effects(
            "xchg",
            vec![
                Effect::MemRead {
                    addr: IrExpr::Reg("rbp".to_string()),
                    dest: "rax".to_string(),
                    size: 8,
                },
                Effect::MemWrite {
                    addr: IrExpr::Reg("rbp".to_string()),
                    value: IrExpr::Reg("rbx".to_string()),
                    size: 8,
                },
            ],
        );
        let ops = lift_memory_op(&lifter, &instr);
        assert_eq!(ops.len(), 2);
        if let MemoryOp::Load(l) = &ops[0] {
            assert_eq!(l.access_type, AccessType::AtomicLoad);
        }
        if let MemoryOp::Store(s) = &ops[1] {
            assert_eq!(s.access_type, AccessType::AtomicStore);
        }
    }

    #[test]
    fn mem_size_round_trip() {
        for bytes in [1u8, 2, 4, 8, 16, 32, 64] {
            let sz = MemSize::from_bytes(bytes);
            assert_eq!(sz.as_bytes(), bytes);
            assert_eq!(sz.as_bits(), bytes as u16 * 8);
        }
    }

    #[test]
    fn no_ops_for_pure_reg_instr() {
        let lifter = MemorySemanticsLifter::new();
        let instr = instr_with_effects(
            "add",
            vec![Effect::RegWrite {
                reg: "rax".to_string(),
                value: IrExpr::Const(1),
            }],
        );
        let ops = lift_memory_op(&lifter, &instr);
        assert!(ops.is_empty());
    }

    #[test]
    fn extract_all_aggregates() {
        let lifter = MemorySemanticsLifter::new();
        let instrs = vec![
            make_load_instr("rax", IrExpr::Const(0x1000), 8),
            make_store_instr(IrExpr::Const(0x2000), IrExpr::Reg("rax".to_string()), 8),
        ];
        let all = lifter.extract_all(&instrs);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn stats_counts_loads_and_stores() {
        let lifter = MemorySemanticsLifter::new();
        let instrs = vec![
            make_load_instr("rax", IrExpr::Const(0x1000), 4),
            make_load_instr("rbx", IrExpr::Const(0x1004), 4),
            make_store_instr(IrExpr::Const(0x2000), IrExpr::Reg("rax".to_string()), 4),
        ];
        let (loads, stores) = lifter.stats(&instrs);
        assert_eq!(loads, 2);
        assert_eq!(stores, 1);
    }

    #[test]
    fn address_expr_decomposes_add() {
        let expr = IrExpr::Add(
            Box::new(IrExpr::Reg("rbp".to_string())),
            Box::new(IrExpr::Const(0x10)),
        );
        let ae = AddressExpr::decompose(&expr);
        assert_eq!(ae.displacement, 0x10);
    }

    #[test]
    fn format_load_expr() {
        let ae = AddressExpr::opaque(IrExpr::Reg("rsp".to_string()));
        let load = LoadExpr::new(ae, "rax".to_string(), MemSize::QWord, 0x1000);
        let s = load.format_expr();
        assert!(s.contains("load64"));
    }

    #[test]
    fn format_store_expr() {
        let ae = AddressExpr::opaque(IrExpr::Const(0x8000));
        let store = StoreExpr::new(ae, IrExpr::Reg("rax".to_string()), MemSize::DWord, 0x1000);
        let s = store.format_expr();
        assert!(s.contains("store32"));
    }

    #[test]
    fn mem_op_address_and_size() {
        let ae = AddressExpr::opaque(IrExpr::Const(0x4000));
        let load = LoadExpr::new(ae, "rax".to_string(), MemSize::Word, 0x2000);
        let op = MemoryOp::Load(load);
        assert_eq!(op.size(), MemSize::Word);
    }
}
