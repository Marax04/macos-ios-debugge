/// Rhai-compatible wrappers for core reverse-engineering types.
///
/// Rhai requires types that are registered with its engine to implement
/// `Clone + Send + Sync + 'static`. This module wraps basic RE concepts
/// (`Address`, `Instruction`, `ReFunction`, `Symbol`) in newtype structs that
/// satisfy those constraints and expose a friendly Rhai API via `CustomType`.
use std::fmt;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WrapperError {
    #[error("address {0:#x} is not aligned to {1} bytes")]
    Misaligned(u64, usize),
    #[error("symbol name is empty")]
    EmptySymbolName,
    #[error("instruction mnemonic is empty")]
    EmptyMnemonic,
    #[error("invalid operand index {0} (max {1})")]
    InvalidOperandIndex(usize, usize),
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// A virtual address in a binary.
///
/// Implements arithmetic, formatting, and comparisons without raw `as` casts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(pub u64);

impl Address {
    /// Create a new address from a raw `u64` value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the underlying raw address value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Compute `self + offset` (wrapping).
    #[must_use]
    pub const fn add_offset(self, offset: i64) -> Self {
        let raw = if offset >= 0 {
            self.0.wrapping_add(offset.cast_unsigned())
        } else {
            self.0.wrapping_sub((-offset).cast_unsigned())
        };
        Self(raw)
    }

    /// Signed distance from `other` to `self` (wrapping).
    #[must_use]
    pub const fn signed_diff(self, other: Self) -> i64 {
        self.0.wrapping_sub(other.0).cast_signed()
    }

    /// Check alignment.
    ///
    /// # Errors
    /// Returns [`WrapperError::Misaligned`] if `align` is 0 or not a power of two.
    pub const fn is_aligned(self, align: usize) -> Result<bool, WrapperError> {
        if align == 0 || (align & (align - 1)) != 0 {
            return Err(WrapperError::Misaligned(self.0, align));
        }
        Ok(self.0.is_multiple_of(align as u64))
    }

    /// Format as lowercase hex with `0x` prefix.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:#x}", self.0)
    }

    /// Format as uppercase hex.
    #[must_use]
    pub fn to_hex_upper(self) -> String {
        format!("{:#X}", self.0)
    }

    /// Parse from a hex string with or without `0x` prefix.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        u64::from_str_radix(stripped, 16).ok().map(Self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<Address> for u64 {
    fn from(a: Address) -> Self {
        a.0
    }
}

// ---------------------------------------------------------------------------
// Operand
// ---------------------------------------------------------------------------

/// An instruction operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    /// Immediate integer value.
    Immediate(i64),
    /// Memory address (absolute or RIP-relative resolved).
    Memory(u64),
    /// Register name.
    Register(String),
    /// Other / unparsed operand text.
    Other(String),
}

impl Operand {
    /// Return the kind tag as a `&'static str`.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Immediate(_) => "immediate",
            Self::Memory(_) => "memory",
            Self::Register(_) => "register",
            Self::Other(_) => "other",
        }
    }

    /// Return the immediate value if this is an `Immediate` operand.
    #[must_use]
    pub const fn as_immediate(&self) -> Option<i64> {
        if let Self::Immediate(v) = self { Some(*v) } else { None }
    }

    /// Return the memory address if this is a `Memory` operand.
    #[must_use]
    pub const fn as_memory(&self) -> Option<u64> {
        if let Self::Memory(v) = self { Some(*v) } else { None }
    }

    /// Return the register name if this is a `Register` operand.
    #[must_use]
    pub fn as_register(&self) -> Option<&str> {
        if let Self::Register(s) = self { Some(s) } else { None }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate(v) => write!(f, "{v:#x}"),
            Self::Memory(v) => write!(f, "[{v:#x}]"),
            Self::Register(s) | Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction
// ---------------------------------------------------------------------------

/// A disassembled instruction with address, mnemonic, operands, and raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Address of this instruction.
    pub address: Address,
    /// Mnemonic string (e.g. `"mov"`, `"jnz"`).
    pub mnemonic: Arc<str>,
    /// Decoded operands.
    pub operands: Vec<Operand>,
    /// Raw encoding bytes.
    pub bytes: Vec<u8>,
    /// Optional comment attached by the analysis pass.
    pub comment: Option<String>,
}

impl Instruction {
    /// Create a new instruction.
    ///
    /// # Errors
    /// Returns [`WrapperError::EmptyMnemonic`] if `mnemonic` is empty.
    pub fn new(
        address: Address,
        mnemonic: impl Into<Arc<str>>,
        operands: Vec<Operand>,
        bytes: Vec<u8>,
    ) -> Result<Self, WrapperError> {
        let mnemonic = mnemonic.into();
        if mnemonic.is_empty() {
            return Err(WrapperError::EmptyMnemonic);
        }
        Ok(Self { address, mnemonic, operands, bytes, comment: None })
    }

    /// Instruction length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if the instruction has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Address of the next instruction (address + length).
    #[must_use]
    pub fn next_address(&self) -> Address {
        self.address.add_offset(crate::sat_usize_to_i64(self.bytes.len()))
    }

    /// Retrieve operand at `idx`.
    ///
    /// # Errors
    /// Returns [`WrapperError::InvalidOperandIndex`] if `idx` is out of range.
    pub fn operand(&self, idx: usize) -> Result<&Operand, WrapperError> {
        self.operands
            .get(idx)
            .ok_or(WrapperError::InvalidOperandIndex(idx, self.operands.len()))
    }

    /// Return the mnemonic as a `&str`.
    #[must_use]
    pub fn mnemonic_str(&self) -> &str {
        &self.mnemonic
    }

    /// Format as a pseudo-assembly line.
    #[must_use]
    pub fn to_asm_string(&self) -> String {
        let ops: Vec<String> = self.operands.iter().map(ToString::to_string).collect();
        if ops.is_empty() {
            format!("{} {}", self.address, self.mnemonic)
        } else {
            format!("{} {} {}", self.address, self.mnemonic, ops.join(", "))
        }
    }

    /// Hex dump of the raw bytes.
    #[must_use]
    pub fn bytes_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    }

    /// Attach a comment to this instruction.
    #[must_use]
    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = Some(c.into());
        self
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_asm_string())
    }
}

// ---------------------------------------------------------------------------
// ReFunction
// ---------------------------------------------------------------------------

/// Metadata about a function in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReFunction {
    /// Entry-point address.
    pub address: Address,
    /// Demangled or synthetic name.
    pub name: Arc<str>,
    /// Size in bytes (0 = unknown).
    pub size: usize,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Whether this function has been decompiled.
    pub decompiled: bool,
    /// Inlined functions (callee addresses).
    pub callees: Vec<Address>,
    /// Optional source file and line number.
    pub source_loc: Option<(Arc<str>, u32)>,
}

impl ReFunction {
    /// Create a new function descriptor.
    #[must_use]
    pub fn new(address: Address, name: impl Into<Arc<str>>, size: usize) -> Self {
        Self {
            address,
            name: name.into(),
            size,
            block_count: 0,
            decompiled: false,
            callees: Vec::new(),
            source_loc: None,
        }
    }

    /// End address (exclusive). Returns the entry if size is 0.
    #[must_use]
    pub fn end_address(&self) -> Address {
        if self.size == 0 {
            self.address
        } else {
            self.address.add_offset(crate::sat_usize_to_i64(self.size))
        }
    }

    /// Return `true` if `addr` falls within this function.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        if self.size == 0 {
            return false;
        }
        addr >= self.address && addr < self.end_address()
    }

    /// Return the name as a `&str`.
    #[must_use]
    pub fn name_str(&self) -> &str {
        &self.name
    }

    /// Add a callee address if not already present.
    pub fn add_callee(&mut self, addr: Address) {
        if !self.callees.contains(&addr) {
            self.callees.push(addr);
        }
    }
}

impl fmt::Display for ReFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.address)
    }
}

// ---------------------------------------------------------------------------
// Symbol
// ---------------------------------------------------------------------------

/// A symbol table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Debug,
    Unknown,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Function => "function",
            Self::Data => "data",
            Self::Import => "import",
            Self::Export => "export",
            Self::Debug => "debug",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// A resolved symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub address: Address,
    pub name: Arc<str>,
    pub kind: SymbolKind,
    pub size: usize,
    pub module: Option<Arc<str>>,
}

impl Symbol {
    /// Create a new symbol.
    ///
    /// # Errors
    /// Returns [`WrapperError::EmptySymbolName`] if `name` is empty.
    pub fn new(
        address: Address,
        name: impl Into<Arc<str>>,
        kind: SymbolKind,
    ) -> Result<Self, WrapperError> {
        let name = name.into();
        if name.is_empty() {
            return Err(WrapperError::EmptySymbolName);
        }
        Ok(Self { address, name, kind, size: 0, module: None })
    }

    /// Return the name as a `&str`.
    #[must_use]
    pub fn name_str(&self) -> &str {
        &self.name
    }

    /// Return `true` if this is a function-like symbol.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self.kind, SymbolKind::Function | SymbolKind::Import | SymbolKind::Export)
    }

    /// Builder: set the size.
    #[must_use]
    pub const fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Builder: set the module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<Arc<str>>) -> Self {
        self.module = Some(module.into());
        self
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}) @ {}", self.name, self.kind, self.address)
    }
}

// ---------------------------------------------------------------------------
// AddressRange — a contiguous range of addresses
// ---------------------------------------------------------------------------

/// A half-open range `[start, end)` of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

impl AddressRange {
    /// Create from explicit start and end addresses.
    #[must_use]
    pub const fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Create from a base address and byte size.
    #[must_use]
    pub const fn from_base_size(base: Address, size: u64) -> Self {
        Self { start: base, end: Address(base.0.wrapping_add(size)) }
    }

    /// Return `true` if `addr` is within `[start, end)`.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Return the byte size of the range.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.0.wrapping_sub(self.start.0)
    }

    /// Return `true` if this range overlaps `other`.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_add_offset() {
        let a = Address::new(0x1000);
        assert_eq!(a.add_offset(0x10).raw(), 0x1010);
        assert_eq!(a.add_offset(-0x10).raw(), 0xFF0);
    }

    #[test]
    fn test_address_signed_diff() {
        let a = Address::new(0x2000);
        let b = Address::new(0x1000);
        assert_eq!(a.signed_diff(b), 0x1000);
        assert_eq!(b.signed_diff(a), -0x1000);
    }

    #[test]
    fn test_address_from_hex() {
        assert_eq!(Address::from_hex("0x1000"), Some(Address::new(0x1000)));
        assert_eq!(Address::from_hex("1000"), Some(Address::new(0x1000)));
        assert_eq!(Address::from_hex("0X1000"), Some(Address::new(0x1000)));
        assert_eq!(Address::from_hex("ZZZZ"), None);
    }

    #[test]
    fn test_instruction_next_address() {
        let insn = Instruction::new(
            Address::new(0x400000),
            "nop",
            vec![],
            vec![0x90],
        )
        .unwrap();
        assert_eq!(insn.next_address(), Address::new(0x400001));
    }

    #[test]
    fn test_instruction_empty_mnemonic_error() {
        let err = Instruction::new(Address::new(0), "", vec![], vec![]);
        assert!(matches!(err, Err(WrapperError::EmptyMnemonic)));
    }

    #[test]
    fn test_instruction_to_asm_string() {
        let insn = Instruction::new(
            Address::new(0x1000),
            "mov",
            vec![Operand::Register("rax".into()), Operand::Immediate(42)],
            vec![0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00],
        )
        .unwrap();
        let s = insn.to_asm_string();
        assert!(s.contains("mov"));
        assert!(s.contains("rax"));
    }

    #[test]
    fn test_function_contains() {
        let f = ReFunction::new(Address::new(0x1000), "main", 0x100);
        assert!(f.contains(Address::new(0x1050)));
        assert!(!f.contains(Address::new(0x1100)));
    }

    #[test]
    fn test_symbol_empty_name_error() {
        let err = Symbol::new(Address::new(0), "", SymbolKind::Function);
        assert!(matches!(err, Err(WrapperError::EmptySymbolName)));
    }

    #[test]
    fn test_address_range_overlaps() {
        let a = AddressRange::from_base_size(Address::new(0x1000), 0x100);
        let b = AddressRange::from_base_size(Address::new(0x1080), 0x100);
        let c = AddressRange::from_base_size(Address::new(0x2000), 0x100);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_operand_display() {
        assert_eq!(Operand::Immediate(255).to_string(), "0xff");
        assert_eq!(Operand::Register("rbp".into()).to_string(), "rbp");
        assert_eq!(Operand::Memory(0x4000).to_string(), "[0x4000]");
    }
}
