/// Extended symbol and function analysis stores.
///
/// This module provides standalone, more feature-rich versions of the symbol,
/// function, and cross-reference stores.  Where `binary_view` embeds simplified
/// versions directly in `BinaryView`, the types here are designed for use by
/// analysis passes that need richer querying capabilities.
///
/// Key types:
/// - [`SymbolFlags`] — bitflags for symbol properties.
/// - [`SymbolEntry`] — a full symbol record with demangling, size, and binding.
/// - [`SymbolIndex`] — the primary symbol store (address + name indexed).
/// - [`BasicBlock`] — a basic block within a function (address range + edges).
/// - [`BBEdgeKind`] — edge classification (fall-through, branch, call, …).
/// - [`FunctionRecord`] — a full function record with basic block CFG.
/// - [`FunctionRegistry`] — the primary function store.
/// - [`XrefRecord`] — an extended cross-reference with confidence score.
/// - [`XrefStore`] — bi-directional xref index with filtering support.
use crate::address::{Address, AddressRange};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// SymbolFlags
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Extended per-symbol property flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SymbolFlags: u32 {
        /// Symbol is a function entry point.
        const FUNCTION      = 1 << 0;
        /// Symbol is an exported name.
        const EXPORTED      = 1 << 1;
        /// Symbol is an imported name.
        const IMPORTED      = 1 << 2;
        /// Symbol is `weak` (can be overridden by a strong symbol).
        const WEAK          = 1 << 3;
        /// Symbol has been demangled.
        const DEMANGLED     = 1 << 4;
        /// Symbol was automatically discovered (not user-defined).
        const AUTO          = 1 << 5;
        /// Symbol is a constructor.
        const CONSTRUCTOR   = 1 << 6;
        /// Symbol is a destructor.
        const DESTRUCTOR    = 1 << 7;
        /// Symbol is a virtual function.
        const VIRTUAL       = 1 << 8;
        /// Symbol is a template instantiation.
        const TEMPLATE      = 1 << 9;
        /// Symbol is a thunk / trampoline.
        const THUNK         = 1 << 10;
        /// Symbol originates from a compiler-inserted library stub.
        const COMPILER_RT   = 1 << 11;
        /// Symbol has been user-verified/confirmed.
        const CONFIRMED     = 1 << 12;
    }
}

impl Serialize for SymbolFlags {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for SymbolFlags {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(d)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

impl Default for SymbolFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolBinding — link visibility
// ─────────────────────────────────────────────────────────────────────────────

/// ELF/COFF-style symbol binding / visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolBinding {
    /// Locally-visible (static / internal linkage).
    Local,
    /// Globally visible (default linkage).
    Global,
    /// Weak binding (can be overridden).
    Weak,
    /// GNU hidden visibility.
    Hidden,
    /// GNU protected visibility.
    Protected,
}

impl std::fmt::Display for SymbolBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Global => write!(f, "global"),
            Self::Weak => write!(f, "weak"),
            Self::Hidden => write!(f, "hidden"),
            Self::Protected => write!(f, "protected"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolEntry — the primary symbol record
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-described symbol in the analysis store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// Raw (possibly mangled) name.
    pub name: String,
    /// Demangled / pretty name, if known.
    pub demangled: Option<String>,
    /// Virtual address.
    pub address: Address,
    /// Size in bytes, or 0 if unknown.
    pub size: u64,
    /// Property flags.
    pub flags: SymbolFlags,
    /// Link binding.
    pub binding: SymbolBinding,
    /// Provenance (e.g. `"PDB"`, `"DWARF"`, `"export table"`, `"user"`).
    pub source: Option<String>,
    /// An optional analyst comment.
    pub comment: Option<String>,
}

impl SymbolEntry {
    /// Construct a minimal symbol.
    #[must_use]
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            demangled: None,
            address,
            size: 0,
            flags: SymbolFlags::empty(),
            binding: SymbolBinding::Global,
            source: None,
            comment: None,
        }
    }

    /// Set the demangled name.
    #[must_use]
    pub fn with_demangled(mut self, demangled: impl Into<String>) -> Self {
        self.demangled = Some(demangled.into());
        self.flags |= SymbolFlags::DEMANGLED;
        self
    }

    /// Set the size.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set property flags.
    #[must_use]
    pub const fn with_flags(mut self, flags: SymbolFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the binding.
    #[must_use]
    pub const fn with_binding(mut self, binding: SymbolBinding) -> Self {
        self.binding = binding;
        self
    }

    /// Set the source provenance.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The best display name: demangled if available, else raw.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }

    /// Return the exclusive end address if `size > 0`.
    #[must_use]
    pub fn end_address(&self) -> Option<Address> {
        if self.size > 0 {
            Some(self.address + self.size)
        } else {
            None
        }
    }
}

impl std::fmt::Display for SymbolEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} @ {}", self.display_name(), self.address)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolIndex — the primary symbol store
// ─────────────────────────────────────────────────────────────────────────────

/// A richly indexed, address- and name-keyed symbol store.
#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    /// All entries stored by address.
    addresses: HashMap<u64, Vec<SymbolEntry>>,
    /// Name → list of addresses that have that raw name.
    raw_names: HashMap<String, Vec<u64>>,
    /// Demangled name → list of addresses.
    demangled_names: HashMap<String, Vec<u64>>,
}

impl SymbolIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.  Deduplication is by `(name, address)`.
    pub fn insert(&mut self, sym: SymbolEntry) {
        let addr = sym.address.as_u64();
        let name = sym.name.clone();
        let demangled = sym.demangled.clone();
        let addr_vec = self.addresses.entry(addr).or_default();
        if let Some(existing) = addr_vec.iter_mut().find(|s| s.name == sym.name) {
            // Replace existing entry with same name at this address.
            *existing = sym;
        } else {
            addr_vec.push(sym);
        }
        let name_vec = self.raw_names.entry(name).or_default();
        if !name_vec.contains(&addr) {
            name_vec.push(addr);
        }
        if let Some(dm) = demangled {
            let dm_vec = self.demangled_names.entry(dm).or_default();
            if !dm_vec.contains(&addr) {
                dm_vec.push(addr);
            }
        }
    }

    /// Return all symbols at exactly `addr`.
    #[must_use]
    pub fn at(&self, addr: Address) -> &[SymbolEntry] {
        self.addresses
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return the first symbol at `addr`, if any.
    #[must_use]
    pub fn first_at(&self, addr: Address) -> Option<&SymbolEntry> {
        self.at(addr).first()
    }

    /// Return all symbols with raw name `name`.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&SymbolEntry> {
        let Some(addrs) = self.raw_names.get(name) else {
            return Vec::new();
        };
        addrs
            .iter()
            .flat_map(|a| self.addresses.get(a).map(Vec::as_slice).unwrap_or_default())
            .filter(|s| s.name == name)
            .collect()
    }

    /// Return all symbols with demangled name `name`.
    #[must_use]
    pub fn by_demangled(&self, name: &str) -> Vec<&SymbolEntry> {
        let Some(addrs) = self.demangled_names.get(name) else {
            return Vec::new();
        };
        addrs
            .iter()
            .flat_map(|a| self.addresses.get(a).map(Vec::as_slice).unwrap_or_default())
            .filter(|s| s.demangled.as_deref() == Some(name))
            .collect()
    }

    /// Remove all symbols at `addr`.  Returns the removed entries.
    pub fn remove_at(&mut self, addr: Address) -> Vec<SymbolEntry> {
        let removed = self.addresses.remove(&addr.as_u64()).unwrap_or_default();
        for sym in &removed {
            if let Some(v) = self.raw_names.get_mut(&sym.name) {
                v.retain(|a| *a != addr.as_u64());
                if v.is_empty() {
                    self.raw_names.remove(&sym.name);
                }
            }
            if let Some(ref dm) = sym.demangled
                && let Some(v) = self.demangled_names.get_mut(dm)
            {
                v.retain(|a| *a != addr.as_u64());
                if v.is_empty() {
                    self.demangled_names.remove(dm);
                }
            }
        }
        removed
    }

    /// Iterate over all symbols in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &SymbolEntry> {
        self.addresses.values().flat_map(|v| v.iter())
    }

    /// Iterate over symbols whose flags contain all bits of `flags`.
    pub fn iter_with_flags(&self, flags: SymbolFlags) -> impl Iterator<Item = &SymbolEntry> {
        self.iter().filter(move |s| s.flags.contains(flags))
    }

    /// Total number of symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.values().map(Vec::len).sum()
    }

    /// Return `true` if no symbols are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return all symbols whose address falls within `range`.
    #[must_use]
    pub fn symbols_in_range(&self, range: AddressRange) -> Vec<&SymbolEntry> {
        self.iter().filter(|s| range.contains(s.address)).collect()
    }

    /// Search for symbols whose raw or demangled name contains `query`
    /// (case-insensitive substring match).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&SymbolEntry> {
        let q = query.to_lowercase();
        self.iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&q)
                    || s.demangled
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A typed edge between two basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BBEdgeKind {
    /// Unconditional fall-through (next instruction).
    FallThrough,
    /// Unconditional direct branch.
    Jump,
    /// Taken branch of a conditional.
    ConditionalTaken,
    /// Not-taken branch of a conditional (fall-through to next BB).
    ConditionalNotTaken,
    /// Direct function call edge.
    Call,
    /// Return edge.
    Return,
    /// Indirect branch (target not statically known).
    Indirect,
    /// Exception / trap edge.
    Exception,
}

/// A directed edge from one basic block to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BBEdge {
    /// Start address of the target basic block.
    pub target: Address,
    /// Edge classification.
    pub kind: BBEdgeKind,
}

impl BBEdge {
    /// Construct an edge.
    #[must_use]
    pub const fn new(target: Address, kind: BBEdgeKind) -> Self {
        Self { target, kind }
    }
}

/// A single basic block within a function's control-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Address of the first instruction in the block.
    pub start: Address,
    /// Exclusive end address (start of next instruction after the last in this block).
    pub end: Address,
    /// Outgoing edges (at most 2 for conditional branches).
    pub successors: Vec<BBEdge>,
    /// Incoming predecessor start addresses.
    pub predecessors: Vec<Address>,
    /// `true` if this is the function entry block.
    pub is_entry: bool,
    /// `true` if this block terminates with a return instruction.
    pub is_exit: bool,
}

impl BasicBlock {
    /// Create a minimal basic block.
    #[must_use]
    pub const fn new(start: Address, end: Address) -> Self {
        Self {
            start,
            end,
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_entry: false,
            is_exit: false,
        }
    }

    /// Byte size of the block.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }

    /// Return `true` if `addr` is within this block.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionRecord — a full function record with CFG
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Extended function property flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FnFlags: u32 {
        /// Function never returns.
        const NO_RETURN         = 1 << 0;
        /// Function is variadic.
        const VARIADIC          = 1 << 1;
        /// Function body has been confirmed by user.
        const CONFIRMED         = 1 << 2;
        /// Function was discovered by a library matcher (FLIRT, etc.).
        const LIBRARY           = 1 << 3;
        /// Function is a constructor.
        const CONSTRUCTOR       = 1 << 4;
        /// Function is a destructor.
        const DESTRUCTOR        = 1 << 5;
        /// Function is virtual.
        const VIRTUAL           = 1 << 6;
        /// Function is pure-virtual.
        const PURE_VIRTUAL      = 1 << 7;
        /// Function is inlined at one or more call sites.
        const INLINE            = 1 << 8;
        /// CFG has been fully computed.
        const CFG_COMPLETE      = 1 << 9;
        /// Function contains indirect branches (computed goto, switch).
        const INDIRECT_BRANCHES = 1 << 10;
        /// Function performs system calls.
        const SYSCALL           = 1 << 11;
    }
}

impl Serialize for FnFlags {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for FnFlags {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(d)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

impl Default for FnFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// A complete function record including CFG and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Entry-point address.
    pub address: Address,
    /// Exclusive end address of the function body, if known.
    pub end_address: Option<Address>,
    /// Human-readable name.
    pub name: String,
    /// Demangled name, if available.
    pub demangled: Option<String>,
    /// Prototype string (e.g. `int __cdecl foo(int, char*)`).
    pub prototype: Option<String>,
    /// Calling convention name.
    pub calling_convention: Option<String>,
    /// Property flags.
    pub flags: FnFlags,
    /// Basic blocks, keyed by their start address.
    pub basic_blocks: HashMap<u64, BasicBlock>,
    /// Optional analyst comment.
    pub comment: Option<String>,
}

impl FunctionRecord {
    /// Construct a minimal function record.
    #[must_use]
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            end_address: None,
            name: name.into(),
            demangled: None,
            prototype: None,
            calling_convention: None,
            flags: FnFlags::empty(),
            basic_blocks: HashMap::new(),
            comment: None,
        }
    }

    /// Set the exclusive end address.
    #[must_use]
    pub const fn with_end(mut self, end: Address) -> Self {
        self.end_address = Some(end);
        self
    }

    /// Attach a prototype string.
    #[must_use]
    pub fn with_prototype(mut self, proto: impl Into<String>) -> Self {
        self.prototype = Some(proto.into());
        self
    }

    /// Add a basic block.  Overwrites any existing block at the same start address.
    pub fn add_basic_block(&mut self, bb: BasicBlock) {
        self.basic_blocks.insert(bb.start.as_u64(), bb);
        self.flags |= FnFlags::CFG_COMPLETE;
    }

    /// Return the basic block containing `addr`, if any.
    #[must_use]
    pub fn block_containing(&self, addr: Address) -> Option<&BasicBlock> {
        self.basic_blocks.values().find(|bb| bb.contains(addr))
    }

    /// Byte size of the function body, if `end_address` is known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.end_address
            .map(|e| e.as_u64().saturating_sub(self.address.as_u64()))
    }

    /// Number of basic blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.basic_blocks.len()
    }

    /// The best display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Address-indexed registry of `FunctionRecord` entries.
#[derive(Debug, Clone, Default)]
pub struct FunctionRegistry {
    by_address: HashMap<u64, FunctionRecord>,
    by_name: HashMap<String, Vec<u64>>,
}

impl FunctionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a function record.
    pub fn insert(&mut self, func: FunctionRecord) {
        let addr = func.address.as_u64();
        let name_entry = self.by_name.entry(func.name.clone()).or_default();
        if !name_entry.contains(&addr) {
            name_entry.push(addr);
        }
        self.by_address.insert(addr, func);
    }

    /// Look up the function at exactly `addr`.
    #[must_use]
    pub fn at(&self, addr: Address) -> Option<&FunctionRecord> {
        self.by_address.get(&addr.as_u64())
    }

    /// Mutable access to the function at `addr`.
    pub fn at_mut(&mut self, addr: Address) -> Option<&mut FunctionRecord> {
        self.by_address.get_mut(&addr.as_u64())
    }

    /// Return all functions with the given raw name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&FunctionRecord> {
        self.by_name
            .get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| self.by_address.get(a))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return functions whose name contains `query` (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&FunctionRecord> {
        let q = query.to_lowercase();
        self.by_address
            .values()
            .filter(|f| f.display_name().to_lowercase().contains(&q))
            .collect()
    }

    /// Return all functions whose entry point is in `range`.
    #[must_use]
    pub fn in_range(&self, range: AddressRange) -> Vec<&FunctionRecord> {
        self.by_address
            .values()
            .filter(|f| range.contains(f.address))
            .collect()
    }

    /// Remove the function at `addr`.  Returns it if it existed.
    pub fn remove(&mut self, addr: Address) -> Option<FunctionRecord> {
        let func = self.by_address.remove(&addr.as_u64())?;
        if let Some(addrs) = self.by_name.get_mut(&func.name) {
            addrs.retain(|a| *a != addr.as_u64());
            if addrs.is_empty() {
                self.by_name.remove(&func.name);
            }
        }
        Some(func)
    }

    /// Iterate over all function records in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &FunctionRecord> {
        self.by_address.values()
    }

    /// Number of registered functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Return `true` if no functions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefRecord — extended cross-reference
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic classification of a cross-reference edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// A `call` instruction targeting the destination.
    Call,
    /// An unconditional `jmp` to the destination.
    Jump,
    /// A conditional branch to the destination (taken path).
    CondJump,
    /// A memory read that references the destination as a data address.
    DataRead,
    /// A memory write that references the destination as a data address.
    DataWrite,
    /// An address-taken reference (e.g. `lea rax, [sym]`).
    DataRef,
    /// The destination is used as a string literal (read-only data ref).
    StringRef,
    /// The destination is used as a vtable pointer.
    VtableRef,
    /// Origin of a tail-call jump.
    TailCall,
}

impl std::fmt::Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "CALL"),
            Self::Jump => write!(f, "JMP"),
            Self::CondJump => write!(f, "CJMP"),
            Self::DataRead => write!(f, "READ"),
            Self::DataWrite => write!(f, "WRITE"),
            Self::DataRef => write!(f, "REF"),
            Self::StringRef => write!(f, "STR"),
            Self::VtableRef => write!(f, "VTBL"),
            Self::TailCall => write!(f, "TAIL"),
        }
    }
}

/// A single directional cross-reference with confidence and source metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XrefRecord {
    /// Address of the referencing instruction / data.
    pub from: Address,
    /// Address being referenced.
    pub to: Address,
    /// Semantic category.
    pub kind: XrefKind,
    /// Confidence in [0.0, 1.0] (1.0 = certain, from disassembly; lower for heuristics).
    pub confidence: f32,
    /// Optional source annotation (e.g. `"disasm"`, `"pdb"`, `"heuristic"`).
    pub source: Option<String>,
}

impl XrefRecord {
    /// Construct a certain (confidence = 1.0) xref.
    #[must_use]
    pub const fn certain(from: Address, to: Address, kind: XrefKind) -> Self {
        Self {
            from,
            to,
            kind,
            confidence: 1.0,
            source: None,
        }
    }

    /// Construct an xref with an explicit confidence value.
    #[must_use]
    pub const fn with_confidence(
        from: Address,
        to: Address,
        kind: XrefKind,
        confidence: f32,
    ) -> Self {
        Self {
            from,
            to,
            kind,
            confidence: confidence.clamp(0.0, 1.0),
            source: None,
        }
    }

    /// Attach a source annotation.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefStore — bi-directional xref index
// ─────────────────────────────────────────────────────────────────────────────

/// A bi-directional, richly-queryable cross-reference store.
#[derive(Debug, Clone, Default)]
pub struct XrefStore {
    /// `from → [records]`
    outgoing: HashMap<u64, Vec<XrefRecord>>,
    /// `to → [records]`
    incoming: HashMap<u64, Vec<XrefRecord>>,
}

impl XrefStore {
    /// Create an empty xref store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cross-reference.  Exact duplicates (`from`, `to`, `kind` all equal)
    /// are silently ignored to maintain idempotency.
    pub fn add(&mut self, xref: XrefRecord) {
        let from = xref.from.as_u64();
        let to = xref.to.as_u64();

        let out = self.outgoing.entry(from).or_default();
        if out
            .iter()
            .any(|x| x.from == xref.from && x.to == xref.to && x.kind == xref.kind)
        {
            // Update confidence if this is a re-assertion with higher confidence.
            if let Some(existing) = out
                .iter_mut()
                .find(|x| x.from == xref.from && x.to == xref.to && x.kind == xref.kind)
                && xref.confidence > existing.confidence
            {
                existing.confidence = xref.confidence;
            }
            return;
        }
        out.push(xref.clone());
        let inc = self.incoming.entry(to).or_default();
        if !inc
            .iter()
            .any(|x| x.from == xref.from && x.to == xref.to && x.kind == xref.kind)
        {
            inc.push(xref);
        }
    }

    /// Return all outgoing xrefs from `addr`.
    #[must_use]
    pub fn from(&self, addr: Address) -> &[XrefRecord] {
        self.outgoing
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return all incoming xrefs to `addr`.
    #[must_use]
    pub fn to(&self, addr: Address) -> &[XrefRecord] {
        self.incoming
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return all call sites that call `callee`.
    #[must_use]
    pub fn callers_of(&self, callee: Address) -> Vec<Address> {
        self.to(callee)
            .iter()
            .filter(|x| matches!(x.kind, XrefKind::Call | XrefKind::TailCall))
            .map(|x| x.from)
            .collect()
    }

    /// Return all functions/addresses called by `caller`.
    #[must_use]
    pub fn callees_of(&self, caller: Address) -> Vec<Address> {
        self.from(caller)
            .iter()
            .filter(|x| matches!(x.kind, XrefKind::Call | XrefKind::TailCall))
            .map(|x| x.to)
            .collect()
    }

    /// Return all data references pointing to `addr`.
    #[must_use]
    pub fn data_refs_to(&self, addr: Address) -> Vec<Address> {
        self.to(addr)
            .iter()
            .filter(|x| {
                matches!(
                    x.kind,
                    XrefKind::DataRead
                        | XrefKind::DataWrite
                        | XrefKind::DataRef
                        | XrefKind::StringRef
                        | XrefKind::VtableRef
                )
            })
            .map(|x| x.from)
            .collect()
    }

    /// Remove all outgoing xrefs from `addr`.
    pub fn remove_from(&mut self, addr: Address) {
        if let Some(xrefs) = self.outgoing.remove(&addr.as_u64()) {
            for xref in &xrefs {
                if let Some(inc) = self.incoming.get_mut(&xref.to.as_u64()) {
                    inc.retain(|x| x.from != addr);
                    if inc.is_empty() {
                        self.incoming.remove(&xref.to.as_u64());
                    }
                }
            }
        }
    }

    /// Remove all incoming xrefs targeting `addr`.
    pub fn remove_to(&mut self, addr: Address) {
        if let Some(xrefs) = self.incoming.remove(&addr.as_u64()) {
            for xref in &xrefs {
                if let Some(out) = self.outgoing.get_mut(&xref.from.as_u64()) {
                    out.retain(|x| x.to != addr);
                    if out.is_empty() {
                        self.outgoing.remove(&xref.from.as_u64());
                    }
                }
            }
        }
    }

    /// Total number of xref edges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outgoing.values().map(Vec::len).sum()
    }

    /// Return `true` if no xrefs are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter xrefs by kind across all entries.
    #[must_use]
    pub fn filter_by_kind(&self, kind: XrefKind) -> Vec<&XrefRecord> {
        self.outgoing
            .values()
            .flat_map(|v| v.iter())
            .filter(|x| x.kind == kind)
            .collect()
    }

    /// Return xrefs with confidence above `threshold`.
    #[must_use]
    pub fn high_confidence(&self, threshold: f32) -> Vec<&XrefRecord> {
        self.outgoing
            .values()
            .flat_map(|v| v.iter())
            .filter(|x| x.confidence >= threshold)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SymbolIndex ───────────────────────────────────────────────────────────

    #[test]
    fn symbol_index_insert_and_lookup() {
        let mut idx = SymbolIndex::new();
        let sym = SymbolEntry::new("main", Address::new(0x1000))
            .with_demangled("main")
            .with_size(0x80)
            .with_flags(SymbolFlags::FUNCTION | SymbolFlags::CONFIRMED);
        idx.insert(sym);
        assert_eq!(idx.len(), 1);

        let at = idx.at(Address::new(0x1000));
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].display_name(), "main");

        let by_name = idx.by_name("main");
        assert_eq!(by_name.len(), 1);
    }

    #[test]
    fn symbol_index_search() {
        let mut idx = SymbolIndex::new();
        idx.insert(
            SymbolEntry::new("_ZN3Foo3barEv", Address::new(0x1000)).with_demangled("Foo::bar()"),
        );
        idx.insert(SymbolEntry::new("malloc", Address::new(0x2000)));
        idx.insert(SymbolEntry::new("free", Address::new(0x3000)));

        let results = idx.search("foo");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, Address::new(0x1000));

        let all = idx.search("e");
        assert!(all.len() >= 2); // "malloc" and "free" contain 'e'
    }

    #[test]
    fn symbol_index_remove() {
        let mut idx = SymbolIndex::new();
        idx.insert(SymbolEntry::new("init", Address::new(0xABCD)));
        idx.remove_at(Address::new(0xABCD));
        assert!(idx.is_empty());
    }

    #[test]
    fn symbol_flags() {
        let flags = SymbolFlags::FUNCTION | SymbolFlags::VIRTUAL | SymbolFlags::CONFIRMED;
        assert!(flags.contains(SymbolFlags::VIRTUAL));
        assert!(!flags.contains(SymbolFlags::THUNK));
    }

    // ── FunctionRegistry ──────────────────────────────────────────────────────

    #[test]
    fn function_registry_basic() {
        let mut reg = FunctionRegistry::new();
        let mut func = FunctionRecord::new(Address::new(0x4000), "do_work")
            .with_end(Address::new(0x4100))
            .with_prototype("int do_work(int a, int b)");

        let bb1 = BasicBlock::new(Address::new(0x4000), Address::new(0x4010));
        let mut bb2 = BasicBlock::new(Address::new(0x4010), Address::new(0x4050));
        bb2.is_exit = true;
        func.add_basic_block(bb1);
        func.add_basic_block(bb2);

        reg.insert(func);
        assert_eq!(reg.len(), 1);

        let found = reg.at(Address::new(0x4000)).unwrap();
        assert_eq!(found.block_count(), 2);
        assert_eq!(found.byte_size().unwrap(), 0x100);
        assert!(found.flags.contains(FnFlags::CFG_COMPLETE));
    }

    #[test]
    fn function_block_containing() {
        let mut func = FunctionRecord::new(Address::new(0x1000), "test");
        func.add_basic_block(BasicBlock::new(Address::new(0x1000), Address::new(0x1010)));
        func.add_basic_block(BasicBlock::new(Address::new(0x1010), Address::new(0x1020)));

        let bb = func.block_containing(Address::new(0x1005)).unwrap();
        assert_eq!(bb.start, Address::new(0x1000));

        assert!(func.block_containing(Address::new(0x2000)).is_none());
    }

    #[test]
    fn function_registry_search() {
        let mut reg = FunctionRegistry::new();
        reg.insert(FunctionRecord::new(Address::new(0x100), "str_copy"));
        reg.insert(FunctionRecord::new(Address::new(0x200), "str_len"));
        reg.insert(FunctionRecord::new(Address::new(0x300), "mem_set"));

        let results = reg.search("str");
        assert_eq!(results.len(), 2);
    }

    // ── XrefStore ─────────────────────────────────────────────────────────────

    #[test]
    fn xref_store_add_and_query() {
        let mut store = XrefStore::new();
        store.add(XrefRecord::certain(
            Address::new(0x1000),
            Address::new(0x2000),
            XrefKind::Call,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x1008),
            Address::new(0x2000),
            XrefKind::Call,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x1010),
            Address::new(0x3000),
            XrefKind::DataRead,
        ));

        assert_eq!(store.len(), 3);
        assert_eq!(store.callers_of(Address::new(0x2000)).len(), 2);
        assert_eq!(store.callees_of(Address::new(0x1000)).len(), 1);
        let data = store.data_refs_to(Address::new(0x3000));
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn xref_store_deduplication() {
        let mut store = XrefStore::new();
        let x = XrefRecord::certain(Address::new(0xA), Address::new(0xB), XrefKind::Jump);
        store.add(x.clone());
        store.add(x);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn xref_store_remove_from() {
        let mut store = XrefStore::new();
        store.add(XrefRecord::certain(
            Address::new(0x10),
            Address::new(0x20),
            XrefKind::DataRef,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x30),
            Address::new(0x20),
            XrefKind::DataRead,
        ));
        store.remove_from(Address::new(0x10));
        assert_eq!(store.len(), 1);
        // incoming[0x20] should only have the 0x30 entry remaining.
        assert_eq!(store.to(Address::new(0x20)).len(), 1);
    }

    #[test]
    fn xref_confidence_update() {
        let mut store = XrefStore::new();
        store.add(XrefRecord::with_confidence(
            Address::new(0x1),
            Address::new(0x2),
            XrefKind::Call,
            0.5,
        ));
        // Re-add with higher confidence.
        store.add(XrefRecord::with_confidence(
            Address::new(0x1),
            Address::new(0x2),
            XrefKind::Call,
            0.9,
        ));
        let xrefs = store.from(Address::new(0x1));
        assert_eq!(xrefs.len(), 1);
        assert!((xrefs[0].confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn xref_filter_by_kind() {
        let mut store = XrefStore::new();
        store.add(XrefRecord::certain(
            Address::new(0x1),
            Address::new(0x10),
            XrefKind::Call,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x2),
            Address::new(0x20),
            XrefKind::DataRead,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x3),
            Address::new(0x30),
            XrefKind::Call,
        ));
        let calls = store.filter_by_kind(XrefKind::Call);
        assert_eq!(calls.len(), 2);
    }
}
