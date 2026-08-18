//! Target expression evaluation for Apple targets.
//!
//! This module contains **no** expression parser and **no** evaluator: both
//! live in [`crate::expression_evaluator`] and are shared with the
//! Windows and Linux backends. Duplicating them here would be the third copy
//! of a C expression grammar in this workspace and would guarantee that
//! `p *(uint64_t*)($x0 + 16)` eventually means two different things depending
//! on which backend answered.
//!
//! What is genuinely Apple-specific — and therefore what this module supplies —
//! is the three things the evaluator asks of its host:
//!
//! * [`crate::expression_evaluator::RegisterState`] over the **ARM64** register set (`$x0`..`$x30`, `$sp`,
//!   `$pc`, `$lr`, `$fp`, plus the `w` views, `xzr`, `cpsr`/`nzcv` and the
//!   vector views), resolved through [`crate::ios::arm64::lookup_register`] so the
//!   debugger and the evaluator can never disagree about what `$fp` is.
//! * [`crate::expression_evaluator::MemoryProvider`] backed by a live RSP session (`m` packets), i.e. the
//!   memory of a real iOS/macOS process reached through `debugserver`.
//! * [`crate::expression_evaluator::SymbolTable`] over whatever names symbolication produced.
//!
//! # The target is not trusted
//!
//! Every byte a [`crate::expression_evaluator::MemoryProvider`] here returns came out of a remote process
//! over a socket. Two rules follow, and both are enforced rather than assumed:
//!
//! 1. A read is **exact or an error**. A stub that answers `m` with fewer bytes
//!    than requested gets a [`crate::expression_evaluator::DebugError`], never a silently zero-padded or
//!    truncated buffer — a short read that reads as success is how a debugger
//!    prints a confidently wrong value.
//! 2. A single read is **capped** ([`MAX_READ_LEN`]). An expression is allowed
//!    to be wrong about a length; it is not allowed to make the debugger
//!    allocate gigabytes because a garbage pointer got dereferenced.
//!
//! No `unwrap`, no unchecked indexing, and no panic path exists on any value
//! that originates from the target.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::expression_evaluator::{
    DebugExprEvaluator, EvalContext, EvalError, ExprEvaluator, MemoryProvider, RegisterState,
    SymbolTable, TypeSystem, TypedValue, WatchRegistry, parse_expression, pretty_print,
};
use crate::expression_evaluator::error::{DebugError, DebugResult};

use crate::ios::arm64::{Arm64RegisterFile, NUM_GENERAL, RegClass, lookup_register};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Upper bound on a single [`MemoryProvider::read_bytes`] request, in bytes.
///
/// 1 MiB is far above any legitimate expression read (the largest scalar the
/// evaluator asks for is 16 bytes; `read_cstring` walks byte by byte) and far
/// below anything that could exhaust the debugger's memory. A request beyond
/// it is reported, not clamped: clamping would turn "you asked for nonsense"
/// into a short read the caller might mistake for data.
pub const MAX_READ_LEN: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// ARM64 register names accepted in expressions
// ---------------------------------------------------------------------------

/// The canonical ARM64 register names an expression may use after `$`.
///
/// This is what [`Arm64RegisterView::all_registers`] enumerates and what a UI
/// would offer for completion. It is deliberately the *canonical* set: aliases
/// (`w3`, `xsp`, `nzcv`, `d0`, …) still resolve, they are simply not listed
/// twice.
#[must_use]
pub fn arm64_register_names() -> Vec<String> {
    let mut names = Vec::with_capacity(NUM_GENERAL + 5);
    for i in 0..NUM_GENERAL {
        names.push(format!("x{i}"));
    }
    for extra in ["sp", "pc", "fp", "lr", "cpsr"] {
        names.push((*extra).to_string());
    }
    names
}

/// True if `name` (without the leading `$`) is a register this backend accepts.
///
/// Accepts every alias [`lookup_register`] accepts, which is a superset of
/// [`arm64_register_names`].
#[must_use]
pub fn is_arm64_register(name: &str) -> bool {
    lookup_register(name).is_some()
}

// ---------------------------------------------------------------------------
// RegisterState over an ARM64 register file
// ---------------------------------------------------------------------------

/// A [`crate::expression_evaluator::RegisterState`] view of a stopped thread's ARM64 registers.
///
/// Name resolution is delegated wholesale to [`lookup_register`], so `$fp` is
/// `x29` and `$lr` is `x30` here for exactly the same reason they are in the
/// unwinder — there is one table, not two.
#[derive(Debug, Clone, Default)]
pub struct Arm64RegisterView {
    file: Arm64RegisterFile,
    /// Whether the `v` file of `file` was actually read from the target.
    ///
    /// [`Arm64RegisterFile::new`] starts `v` at all-zero, so without this flag
    /// a view built from a source that cannot carry 128-bit registers (the
    /// [`crate::RegisterSet`] path: `RegisterMap::decode` skips every register
    /// wider than 8 bytes by design) answers `$d0` with a fabricated `0` that
    /// no caller can tell from a real zero. `false` makes every vector view
    /// (`v`/`q`/`d`/`s`/`h`/`b`) *unreadable* instead, which the evaluator
    /// reports as `UndefinedRegister` — the same refusal
    /// `AppleDebugger::get_register("v0")` already emits.
    vectors_read: bool,
    /// Whether `file.fpsr` was actually read from the target.
    ///
    /// Same reasoning as [`Self::vectors_read`], applied to the class the
    /// [`crate::RegisterSet`] path CAN carry: `fpsr`/`fpcr` are 32-bit, so
    /// `RegisterMap::decode` does report them — but a stub that omits them
    /// would otherwise be answered with `Arm64RegisterFile::new`'s zero, which
    /// reads exactly like a real "no FP exception raised".
    fpsr_read: bool,
    /// Whether `file.fpcr` was actually read from the target. See
    /// [`Self::fpsr_read`]; the two are tracked separately because a stub may
    /// report one and not the other.
    fpcr_read: bool,
    /// Per-register witness for the general file: `general_read[i]` is true iff
    /// `x{i}` came from the target. Same fabrication rule as
    /// [`Self::vectors_read`]: `RegisterMap::decode` skips a register whose
    /// `RegisterInfo.offset` is `None`, so a stub can leave holes, and a hole
    /// answered with `Arm64RegisterFile::new`'s zero is indistinguishable from
    /// a real zero.
    general_read: [bool; NUM_GENERAL],
    /// Whether `cpsr`/`nzcv` came from the target. See [`Self::general_read`].
    cpsr_read: bool,
}

impl Arm64RegisterView {
    /// Wrap a register file whose whole contents — vector file included — was
    /// read from the target.
    ///
    /// Use [`Self::without_vectors`] when the source could not carry `v`.
    #[must_use]
    pub const fn new(file: Arm64RegisterFile) -> Self {
        Self { file, vectors_read: true, fpsr_read: true, fpcr_read: true, general_read: [true; NUM_GENERAL], cpsr_read: true }
    }

    /// Wrap a register file whose `v` registers were NEVER read.
    ///
    /// The general registers read normally; every vector view is refused
    /// rather than answered with the zero `Arm64RegisterFile::new` left there.
    #[must_use]
    pub const fn without_vectors(file: Arm64RegisterFile) -> Self {
        Self { file, vectors_read: false, fpsr_read: false, fpcr_read: false, general_read: [true; NUM_GENERAL], cpsr_read: true }
    }

    /// Mark `fpsr` / `fpcr` as having come from the target.
    ///
    /// A `None` leaves that register refused rather than answered with a zero
    /// the caller could not tell from a real one.
    #[must_use]
    pub fn with_fp_control(mut self, fpsr: Option<u32>, fpcr: Option<u32>) -> Self {
        if let Some(v) = fpsr {
            self.file.fpsr = v;
            self.fpsr_read = true;
        }
        if let Some(v) = fpcr {
            self.file.fpcr = v;
            self.fpcr_read = true;
        }
        self
    }

    /// Record which general registers, and whether `cpsr`, came from the
    /// target.
    ///
    /// A `false` entry makes that register *unreadable* (`UndefinedRegister`)
    /// instead of answering the zero `Arm64RegisterFile::new` left there.
    #[must_use]
    pub const fn with_read_mask(mut self, general: [bool; NUM_GENERAL], cpsr: bool) -> Self {
        self.general_read = general;
        self.cpsr_read = cpsr;
        self
    }

    /// Whether `x{index}` of this view came from the target.
    #[must_use]
    pub fn general_read(&self, index: usize) -> bool {
        self.general_read.get(index).copied().unwrap_or(true)
    }

    /// Whether `cpsr` of this view came from the target.
    #[must_use]
    pub const fn cpsr_read(&self) -> bool {
        self.cpsr_read
    }

    /// Whether `fpsr` of this view came from the target.
    #[must_use]
    pub const fn fpsr_read(&self) -> bool {
        self.fpsr_read
    }

    /// Whether `fpcr` of this view came from the target.
    #[must_use]
    pub const fn fpcr_read(&self) -> bool {
        self.fpcr_read
    }

    /// Whether the vector file of this view came from the target.
    #[must_use]
    pub const fn vectors_read(&self) -> bool {
        self.vectors_read
    }

    /// The full 128 bits of a vector register, when they were read.
    ///
    /// This is the accessor the 64-bit [`RegisterState`] API cannot serve:
    /// `Arm64RegisterFile::get` can only hand back the low half of a `q`/`v`,
    /// and silently halving a 128-bit value is the same class of defect as
    /// fabricating a zero.
    #[must_use]
    pub fn vector(&self, name: &str) -> Option<u128> {
        if !self.vectors_read {
            return None;
        }
        let spec = lookup_register(name)?;
        if !matches!(spec.class, RegClass::Vector) {
            return None;
        }
        self.file.v.get(spec.index as usize).copied()
    }

    /// The underlying register file.
    #[must_use]
    pub const fn file(&self) -> &Arm64RegisterFile {
        &self.file
    }

    /// Replace the register file, e.g. after the target stops again.
    pub const fn set_file(&mut self, file: Arm64RegisterFile) {
        self.file = file;
    }

    /// Build a view from the mock debugserver's register block.
    ///
    /// The two structs are intentionally separate types (one is wire state of a
    /// simulator, the other is the architectural model), so the conversion is
    /// explicit rather than a `Deref` that would let them drift.
    #[must_use]
    pub fn from_mock(regs: &crate::ios::mock_debugserver::Arm64Registers) -> Self {
        let mut file = Arm64RegisterFile::new();
        file.x = regs.x;
        file.sp = regs.sp;
        file.pc = regs.pc;
        file.cpsr = regs.cpsr;
        file.v = regs.v;
        file.fpsr = regs.fpsr;
        file.fpcr = regs.fpcr;
        // The mock's block carries the whole `v` file, so vectors are real here.
        Self { file, vectors_read: true, fpsr_read: true, fpcr_read: true, general_read: [true; NUM_GENERAL], cpsr_read: true }
    }
}

impl RegisterState for Arm64RegisterView {
    fn read_register(&self, name: &str) -> Option<u64> {
        // `Arm64RegisterFile::get` already truncates to the width of the *view*
        // that was named, so `$w0` on `x0 = 0x1_0000_0001` is 1, not garbage.
        // Vector views are the exception in two ways, and both end in `None`
        // (which the evaluator turns into `UndefinedRegister`) rather than in a
        // number the caller cannot audit:
        //  * `vectors_read == false` means the `v` file was never read, so any
        //    answer would be `Arm64RegisterFile::new`'s zero;
        //  * a `v`/`q` view is 128 bits and does not fit this u64-shaped API —
        //    `truncate` is a no-op at >= 64 bits, so `get` would hand back the
        //    LOW HALF as if it were the whole register.
        if let Some(spec) = lookup_register(name) {
            if matches!(spec.class, RegClass::Vector) && (!self.vectors_read || spec.bits > 64) {
                return None;
            }
            // The FP control class is fabricated in exactly the same way when
            // it was never read: `Arm64RegisterFile::new` leaves both at 0, and
            // 0 is a perfectly plausible `fpsr` ("no exception raised").
            // A general register or `cpsr` the stub never reported is refused
            // for the same reason. `xzr`/`wzr` carry index 31, outside the
            // mask, and stay architecturally zero.
            if matches!(spec.class, RegClass::General)
                && !self.general_read(spec.index as usize)
            {
                return None;
            }
            if matches!(spec.class, RegClass::Flags) && !self.cpsr_read {
                return None;
            }
            if matches!(spec.class, RegClass::FpControl) {
                let read = if spec.index == 0 { self.fpsr_read } else { self.fpcr_read };
                if !read {
                    return None;
                }
            }
        }
        self.file.get(name).ok()
    }

    fn all_registers(&self) -> Vec<(String, u64)> {
        arm64_register_names()
            .into_iter()
            .filter_map(|n| self.read_register(&n).map(|v| (n, v)))
            .collect()
    }
}

/// Build a register view from the architecture-neutral [`crate::RegisterSet`]
/// a live stop produced.
///
/// Every value comes from the set the stub actually answered with; a register
/// the stub did not report stays zero *only* because `Arm64RegisterFile::new`
/// starts at zero, and the missing-name case is the stub's report, not an
/// invention here. `x29`/`x30` fall back to the generic `fp`/`lr` roles because
/// some stubs name those registers only by role.
#[must_use]
pub fn register_view_from_set(set: &crate::RegisterSet) -> Arm64RegisterView {
    let mut file = Arm64RegisterFile::new();
    let mut general_read = [false; NUM_GENERAL];
    for i in 0..NUM_GENERAL {
        if let Some(v) = set.get(&format!("x{i}")) {
            if let Some(slot) = file.x.get_mut(i) {
                *slot = v;
                general_read[i] = true;
            }
        }
    }
    // Roles win only where the numbered name was absent.
    if set.get("x29").is_none() {
        if let (Some(fp), Some(slot)) = (set.fp, file.x.get_mut(29)) {
            *slot = fp;
            general_read[29] = true;
        }
    }
    if set.get("x30").is_none() {
        if let (Some(lr), Some(slot)) = (set.lr, file.x.get_mut(30)) {
            *slot = lr;
            general_read[30] = true;
        }
    }
    file.sp = set.sp;
    file.pc = set.pc;
    let cpsr = set.get("cpsr");
    file.cpsr = u32::try_from(cpsr.unwrap_or(0) & 0xFFFF_FFFF).unwrap_or(0);
    // A `RegisterSet` is a map of u64: `RegisterMap::decode` skips every
    // register wider than 8 bytes, so `v` was NOT read and must not be
    // answered. See `Arm64RegisterView::without_vectors`.
    // `fpsr`/`fpcr` are 32-bit, so `RegisterMap::decode` DOES carry them: they
    // are read here rather than left at `Arm64RegisterFile::new`'s zero, and a
    // set that lacks them leaves them refused (see `with_fp_control`).
    let narrow = |name: &str| -> Option<u32> {
        set.get(name).map(|v| u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0))
    };
    Arm64RegisterView::without_vectors(file)
        .with_read_mask(general_read, cpsr.is_some())
        .with_fp_control(narrow("fpsr"), narrow("fpcr"))
}

// ---------------------------------------------------------------------------
// Memory: a live RSP session
// ---------------------------------------------------------------------------

/// Anything that can read the target's memory for expression evaluation.
///
/// This exists because the two RSP clients in this crate ([`crate::ios::rsp`] and
/// [`crate::ios::mock_client`]) have identical capability but different error types,
/// and because a caller may want to evaluate against a core file or a recorded
/// snapshot instead of a live process.
pub trait TargetMemoryReader {
    /// Read exactly `len` bytes at `addr`.
    ///
    /// # Errors
    /// Any transport or stub failure, as a human-readable string. Implementors
    /// must NOT return a short buffer to signal partial success.
    fn read_target_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, String>;
}

impl<T: crate::ios::rsp::RspTransport> TargetMemoryReader for crate::ios::rsp::RspClient<T> {
    fn read_target_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        self.read_memory(addr, len).map_err(|e| e.to_string())
    }
}

impl<T: crate::ios::mock_client::AppleTransport> TargetMemoryReader for crate::ios::mock_client::RspClient<T> {
    fn read_target_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        self.read_memory(addr, len).map_err(|e| e.to_string())
    }
}

/// A borrowed reader is a reader.
///
/// This exists so a caller that only has `&mut RspClient` — which is the shape
/// the live session hands out, since the client lives inside the debugger's
/// session mutex and cannot be moved out — can still build a
/// [`TargetMemory`] over it for the duration of one expression.
impl<R: TargetMemoryReader + ?Sized> TargetMemoryReader for &mut R {
    fn read_target_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        (**self).read_target_memory(addr, len)
    }
}

/// A [`crate::expression_evaluator::MemoryProvider`] that answers every read from a live target.
///
/// The [`Mutex`] is not for concurrency: [`MemoryProvider::read_bytes`] takes
/// `&self` while an RSP request needs `&mut` (it writes a packet and blocks on
/// the reply), and interior mutability is the only way to bridge the two
/// without copying the whole address space up front.
pub struct TargetMemory<R: TargetMemoryReader> {
    reader: Mutex<R>,
}

impl<R: TargetMemoryReader> TargetMemory<R> {
    /// Wrap a reader (typically an [`crate::ios::rsp::RspClient`]).
    pub const fn new(reader: R) -> Self {
        Self { reader: Mutex::new(reader) }
    }

    /// Recover the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }
}

impl<R: TargetMemoryReader> MemoryProvider for TargetMemory<R> {
    fn read_bytes(&self, addr: u64, len: usize) -> DebugResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_READ_LEN {
            return Err(DebugError(format!(
                "refusing {len}-byte read at {addr:#x}: exceeds MAX_READ_LEN ({MAX_READ_LEN})"
            )));
        }
        // Overflowing the address space is a bug in the expression, not a
        // reason to wrap around and read somewhere unrelated.
        if addr.checked_add(len as u64).is_none() {
            return Err(DebugError(format!(
                "read of {len} bytes at {addr:#x} overflows the address space"
            )));
        }
        let bytes = self
            .reader
            .lock()
            .read_target_memory(addr, len)
            .map_err(|e| DebugError(format!("target read at {addr:#x} ({len} bytes) failed: {e}")))?;
        if bytes.len() != len {
            return Err(DebugError(format!(
                "short read at {addr:#x}: stub returned {} of {len} bytes",
                bytes.len()
            )));
        }
        Ok(bytes)
    }
}

/// A [`crate::expression_evaluator::MemoryProvider`] over a flat, already-captured buffer based at `base`.
///
/// Used for evaluating against a snapshot and by the tests; the bounds check is
/// the same "exact or error" contract as the live path.
#[derive(Debug, Clone)]
pub struct SnapshotMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl SnapshotMemory {
    /// Wrap `bytes` as the contents of `[base, base + bytes.len())`.
    #[must_use]
    pub const fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }
}

impl MemoryProvider for SnapshotMemory {
    fn read_bytes(&self, addr: u64, len: usize) -> DebugResult<Vec<u8>> {
        if len > MAX_READ_LEN {
            return Err(DebugError(format!("refusing {len}-byte read at {addr:#x}")));
        }
        let out_of_range = || {
            DebugError(format!(
                "address {addr:#x}+{len} outside snapshot [{:#x}, {:#x})",
                self.base,
                self.base.saturating_add(self.bytes.len() as u64)
            ))
        };
        let off = usize::try_from(addr.checked_sub(self.base).ok_or_else(out_of_range)?)
            .map_err(|_| out_of_range())?;
        let end = off.checked_add(len).ok_or_else(out_of_range)?;
        self.bytes.get(off..end).map(<[u8]>::to_vec).ok_or_else(out_of_range)
    }
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

/// A [`crate::expression_evaluator::SymbolTable`] built from name/address pairs (e.g. from
/// [`crate::ios::symbolication`] or `jGetLoadedDynamicLibrariesInfos`).
#[derive(Debug, Clone, Default)]
pub struct AppleSymbols {
    by_name: HashMap<String, u64>,
    by_addr: HashMap<u64, String>,
}

impl AppleSymbols {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol. A duplicate name keeps the *first* address rather than
    /// silently rebinding it, because two different addresses for one name is a
    /// symbolication conflict the caller should resolve, not one this table
    /// should paper over.
    pub fn insert(&mut self, name: impl Into<String>, addr: u64) {
        let name = name.into();
        self.by_addr.entry(addr).or_insert_with(|| name.clone());
        self.by_name.entry(name).or_insert(addr);
    }

    /// Build from an iterator of pairs.
    #[must_use]
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, u64)>,
        S: Into<String>,
    {
        let mut t = Self::new();
        for (n, a) in pairs {
            t.insert(n, a);
        }
        t
    }

    /// Number of distinct symbol names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// True when no symbols are known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

impl SymbolTable for AppleSymbols {
    fn lookup_symbol(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    fn reverse_lookup(&self, addr: u64) -> Option<String> {
        self.by_addr.get(&addr).cloned()
    }
}

/// Build an expression symbol table out of the images a live target reported.
///
/// Addresses are **runtime** addresses: each image's ASLR slide is applied
/// through [`crate::ios::symbolication::ImageSymbols::runtime_of`], because a
/// static address handed to an expression would dereference the wrong page in
/// a PIE process — the precise "confidently wrong" failure this crate keeps
/// paying for elsewhere.
///
/// A Mach-O name keeps its leading `_`; the C spelling without it is also
/// registered so `p main` works, and `AppleSymbols::insert` keeps the first
/// binding rather than letting a later image silently rebind a name.
#[must_use]
pub fn symbols_from_symbolicator(
    engine: &crate::ios::symbolication::Symbolicator,
) -> AppleSymbols {
    let mut out = AppleSymbols::new();
    for image in engine.images() {
        for sym in image.symbols() {
            let addr = image.runtime_of(sym.static_address);
            out.insert(sym.name.clone(), addr);
            if let Some(stripped) = sym.name.strip_prefix('_') {
                if !stripped.is_empty() {
                    out.insert(stripped.to_string(), addr);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// Everything the shared evaluator needs, bound to one Apple target stop.
///
/// Owns the pieces (registers, memory, symbols, types, watches) so a caller can
/// hold it across many `evaluate` calls; the borrowed [`EvalContext`] is built
/// per call because the evaluator only needs it for the duration of one
/// expression.
pub struct AppleExprSession<M: MemoryProvider> {
    registers: Arm64RegisterView,
    memory: M,
    symbols: AppleSymbols,
    types: TypeSystem,
    watches: WatchRegistry,
}

impl<M: MemoryProvider> AppleExprSession<M> {
    /// Build a session over `memory`, with C primitives (including the
    /// `<stdint.h>` spellings) already registered.
    #[must_use]
    pub fn new(registers: Arm64RegisterView, memory: M, symbols: AppleSymbols) -> Self {
        Self {
            registers,
            memory,
            symbols,
            types: TypeSystem::with_primitives(),
            watches: WatchRegistry::new(),
        }
    }

    /// Mutable access to the type registry, for declaring target structs whose
    /// fields `->` should resolve.
    pub const fn types_mut(&mut self) -> &mut TypeSystem {
        &mut self.types
    }

    /// The type registry.
    #[must_use]
    pub const fn types(&self) -> &TypeSystem {
        &self.types
    }

    /// Mutable access to the symbol table.
    pub const fn symbols_mut(&mut self) -> &mut AppleSymbols {
        &mut self.symbols
    }

    /// Refresh the register snapshot after the target stops again.
    pub const fn set_registers(&mut self, file: Arm64RegisterFile) {
        self.registers.set_file(file);
    }

    /// The current register view.
    #[must_use]
    pub const fn registers(&self) -> &Arm64RegisterView {
        &self.registers
    }

    /// Borrowed evaluation context for one expression.
    fn context(&self) -> EvalContext<'_> {
        EvalContext::new(&self.registers, &self.memory, &self.symbols, &self.types)
    }

    /// Evaluate `expr` against the target.
    ///
    /// # Errors
    /// [`EvalError`] on lex/parse failure, an unknown register or symbol, or a
    /// failed target memory read.
    pub fn evaluate(&self, expr: &str) -> Result<TypedValue, EvalError> {
        let ast = parse_expression(expr)?;
        ExprEvaluator::eval(&ast, &self.context())
    }

    /// Evaluate `expr` and format the result the way a debugger prints it.
    ///
    /// # Errors
    /// As [`Self::evaluate`].
    pub fn evaluate_pretty(&self, expr: &str) -> Result<String, EvalError> {
        let val = self.evaluate(expr)?;
        Ok(pretty_print(&val, &self.context()))
    }

    /// Register a watch expression, returning its id.
    ///
    /// # Errors
    /// [`EvalError::ParseFailed`] if the expression does not parse, or
    /// [`EvalError::WatchLimit`].
    pub fn watch(&mut self, expr: &str) -> Result<u32, EvalError> {
        self.watches.register(expr)
    }

    /// Re-evaluate every registered watch, reporting those whose value changed.
    pub fn poll_watches(&mut self) -> Vec<crate::expression_evaluator::WatchChange> {
        // `DebugExprEvaluator` is the shared crate's own driver for this; going
        // through it keeps watch semantics identical across backends.
        let ctx_registers = &self.registers;
        let ctx_memory = &self.memory;
        let ctx_symbols = &self.symbols;
        let ctx_types = &self.types;
        let mut ev = DebugExprEvaluator::new(
            ctx_registers,
            ctx_memory,
            ctx_symbols,
            ctx_types,
            &mut self.watches,
        );
        ev.poll_watches()
    }
}

/// Convenience alias for the common case: a session over a live RSP client.
pub type LiveExprSession<R> = AppleExprSession<TargetMemory<R>>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ios::mock_client::{LoopbackTransport, RspClient as MockRspClient};
    use crate::ios::mock_debugserver::{MemoryRegion, MockDebugserver, Perms};

    fn regs_with(x: &[(usize, u64)], sp: u64, pc: u64) -> Arm64RegisterFile {
        let mut f = Arm64RegisterFile::new();
        for (i, v) in x {
            if let Some(slot) = f.x.get_mut(*i) {
                *slot = *v;
            }
        }
        f.sp = sp;
        f.pc = pc;
        f
    }

    fn session(file: Arm64RegisterFile, base: u64, bytes: Vec<u8>) -> AppleExprSession<SnapshotMemory> {
        AppleExprSession::new(
            Arm64RegisterView::new(file),
            SnapshotMemory::new(base, bytes),
            AppleSymbols::new(),
        )
    }

    // -- register set ------------------------------------------------------

    #[test]
    fn every_documented_register_name_resolves() {
        for i in 0..31 {
            assert!(is_arm64_register(&format!("x{i}")), "x{i}");
        }
        for n in ["sp", "pc", "lr", "fp", "cpsr", "nzcv", "w0", "xzr", "d5"] {
            assert!(is_arm64_register(n), "{n}");
        }
        assert!(!is_arm64_register("rax"), "x86 names must not resolve here");
        assert!(!is_arm64_register("x31"), "x31 is not a general register");
        assert!(!is_arm64_register(""));
    }

    #[test]
    fn canonical_name_list_is_x0_through_x30_plus_five() {
        let names = arm64_register_names();
        assert_eq!(names.len(), 31 + 5);
        assert_eq!(names[0], "x0");
        assert_eq!(names[30], "x30");
        for n in ["sp", "pc", "fp", "lr", "cpsr"] {
            assert!(names.iter().any(|x| x == n), "{n} missing");
        }
    }

    #[test]
    fn fp_and_lr_alias_x29_and_x30() {
        let f = regs_with(&[(29, 0xAAAA), (30, 0xBBBB)], 0, 0);
        let view = Arm64RegisterView::new(f);
        assert_eq!(view.read_register("fp"), Some(0xAAAA));
        assert_eq!(view.read_register("x29"), Some(0xAAAA));
        assert_eq!(view.read_register("lr"), Some(0xBBBB));
        assert_eq!(view.read_register("x30"), Some(0xBBBB));
        assert_eq!(view.read_register("nope"), None);
    }

    /// `fpsr`/`fpcr` are 32-bit, so `RegisterMap::decode` DOES carry them in a
    /// [`crate::RegisterSet`]. They must reach the evaluator with the target's
    /// value, and — when the stub did not report them — must be refused rather
    /// than answered with `Arm64RegisterFile::new`'s zero.
    #[test]
    fn a_view_from_a_register_set_carries_fpsr_and_fpcr() {
        let mut set = crate::RegisterSet::new();
        set.set("x0", 1);
        set.set("fpsr", 0x0000_0010);
        set.set("fpcr", 0x0008_0000);
        let view = register_view_from_set(&set);
        assert_eq!(view.read_register("fpsr"), Some(0x0000_0010), "fpsr thrown away");
        assert_eq!(view.read_register("fpcr"), Some(0x0008_0000), "fpcr thrown away");

        // Not reported by the stub => refused, not fabricated.
        let mut bare = crate::RegisterSet::new();
        bare.set("x0", 1);
        let bare_view = register_view_from_set(&bare);
        assert_eq!(bare_view.read_register("fpsr"), None, "fabricated fpsr zero");
        assert_eq!(bare_view.read_register("fpcr"), None, "fabricated fpcr zero");
    }

    /// The general file and `cpsr` get the same treatment as the vector file:
    /// a register the stub never reported must be REFUSED, not answered with
    /// `Arm64RegisterFile::new`'s zero.
    ///
    /// This case is not hypothetical: `RegisterInfo.offset` is `Option<u32>`
    /// and `RegisterMap::decode` skips a register that has none, so a stub whose
    /// `qRegisterInfo` describes `cpsr` without an `offset:` produces exactly
    /// this `RegisterSet`. Answering `p $nzcv` with 0 there reads as "the last
    /// compare was not equal" when the truth is "the flags were never read".
    #[test]
    fn a_view_from_a_register_set_refuses_general_and_flag_registers_the_stub_omitted() {
        let mut set = crate::RegisterSet::new();
        set.set("x0", 0xABCD);
        set.set("x5", 0x1234);
        set.set("cpsr", 0x6000_0000);
        set.pc = 0x4000;
        set.sp = 0x8000;
        let view = register_view_from_set(&set);
        assert_eq!(view.read_register("x0"), Some(0xABCD));
        assert_eq!(view.read_register("x5"), Some(0x1234));
        assert_eq!(view.read_register("w5"), Some(0x1234));
        assert_eq!(view.read_register("cpsr"), Some(0x6000_0000));
        assert_eq!(view.read_register("nzcv"), Some(0x6000_0000));

        // Reported by the stub for neither name.
        let mut bare = crate::RegisterSet::new();
        bare.set("x0", 7);
        bare.pc = 0x4000;
        bare.sp = 0x8000;
        let bare_view = register_view_from_set(&bare);
        assert_eq!(bare_view.read_register("x0"), Some(7));
        for n in ["x5", "w5", "x1", "x28"] {
            assert_eq!(bare_view.read_register(n), None, "{n} was never read from the target");
        }
        for n in ["cpsr", "nzcv"] {
            assert_eq!(bare_view.read_register(n), None, "{n} was never read from the target");
        }
        // `xzr`/`wzr` are architecturally zero, not unreported.
        assert_eq!(bare_view.read_register("xzr"), Some(0));
        // sp/pc are carried by dedicated fields, not by the name map.
        assert_eq!(bare_view.read_register("sp"), Some(0x8000));
        assert_eq!(bare_view.read_register("pc"), Some(0x4000));
        let all = bare_view.all_registers();
        assert!(all.iter().all(|(n, _)| n != "x5" && n != "cpsr"), "{all:?}");
    }

    /// A view built from a [`crate::RegisterSet`] has no vector data, and says
    /// so instead of handing back `Arm64RegisterFile::new`'s zero.
    #[test]
    fn a_view_from_a_register_set_refuses_vector_registers() {
        let mut set = crate::RegisterSet::new();
        set.set("x0", 0xABCD);
        set.pc = 0x4000;
        set.sp = 0x8000;
        let view = register_view_from_set(&set);
        assert!(!view.vectors_read());
        assert_eq!(view.read_register("x0"), Some(0xABCD));
        for n in ["v0", "q0", "d0", "s0", "h0", "b0", "d7"] {
            assert_eq!(view.read_register(n), None, "{n} was never read from the target");
            assert_eq!(view.vector(n), None, "{n}");
        }
        assert!(view.all_registers().iter().all(|(n, _)| !n.starts_with('d')));
    }

    /// End to end, through the live `AppleDebugger` API: `evaluate("$d0")` must
    /// not answer `Ok(0)` for a vector register the register-set decode never
    /// read. The mock's thread really holds the bits of `100.0f64`, so a `0`
    /// here is fabricated, not observed — and `get_register("v0")` already
    /// refuses the same register, so answering would make the two API doors
    /// contradict each other.
    ///
    /// This test lives here rather than beside `evaluate` because
    /// [`crate::ios::apple_debugger::LoopbackFactory`] is public API.
    #[tokio::test]
    async fn evaluate_refuses_a_vector_register_instead_of_answering_zero() {
        use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
        use crate::{DebugError, Debugger, ProcessId};
        use std::sync::Arc;

        let mut srv = MockDebugserver::new(4242);
        srv.threads_mut()[0].regs.v[0] = 0x4059_0000_0000_0000; // 100.0f64
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");

        for expr in ["$d0", "$q0", "$v0", "$s0"] {
            match dbg.evaluate(tid, expr).await {
                Ok(v) => panic!(
                    "{expr} evaluated to {:#x}: a vector register that was never read from the target must not answer at all",
                    v.value
                ),
                Err(DebugError::RegisterError(_) | DebugError::Unsupported(_)) => {}
                Err(other) => panic!("{expr}: expected a register refusal, got {other:?}"),
            }
        }
        // The refusal is specific: general registers still evaluate.
        dbg.evaluate(tid, "$x0 + 1").await.expect("general registers still evaluate");
    }

    /// Even with the vector file read, the 64-bit `RegisterState` API refuses
    /// the 128-bit views rather than silently returning their low half.
    #[test]
    fn a_128_bit_vector_view_is_refused_not_halved() {
        let mut f = Arm64RegisterFile::new();
        f.v[2] = 0x1111_2222_3333_4444_5555_6666_7777_8888;
        let view = Arm64RegisterView::new(f);
        assert_eq!(view.read_register("d2"), Some(0x5555_6666_7777_8888));
        assert_eq!(view.read_register("q2"), None);
        assert_eq!(view.read_register("v2"), None);
        assert_eq!(view.vector("q2"), Some(0x1111_2222_3333_4444_5555_6666_7777_8888));
    }

    #[test]
    fn w_view_truncates_to_32_bits() {
        let f = regs_with(&[(0, 0x1_0000_0001)], 0, 0);
        let view = Arm64RegisterView::new(f);
        assert_eq!(view.read_register("x0"), Some(0x1_0000_0001));
        assert_eq!(view.read_register("w0"), Some(1));
    }

    #[test]
    fn all_registers_enumerates_values() {
        let f = regs_with(&[(3, 7)], 0x1000, 0x4000);
        let all = Arm64RegisterView::new(f).all_registers();
        assert_eq!(all.len(), 36);
        assert!(all.contains(&("x3".to_string(), 7)));
        assert!(all.contains(&("sp".to_string(), 0x1000)));
        assert!(all.contains(&("pc".to_string(), 0x4000)));
    }

    // -- evaluation against a snapshot -------------------------------------

    #[test]
    fn register_arithmetic() {
        let s = session(regs_with(&[(0, 0x100)], 0x200, 0), 0, vec![]);
        assert_eq!(s.evaluate("$x0 + 16").unwrap().value, 0x110);
        assert_eq!(s.evaluate("$sp - 8").unwrap().value, 0x1F8);
        assert_eq!(s.evaluate("$x0 * 2 + 1").unwrap().value, 0x201);
    }

    #[test]
    fn the_headline_expression_reads_the_target() {
        // 0x1000..: 16 bytes of filler then the payload we expect to read.
        let mut mem = vec![0xEEu8; 16];
        mem.extend_from_slice(&0xDEAD_BEEF_1234_5678u64.to_le_bytes());
        let s = session(regs_with(&[(0, 0x1000)], 0, 0), 0x1000, mem);

        let v = s.evaluate("*(uint64_t*)($x0 + 16)").unwrap();
        assert_eq!(v.value, 0xDEAD_BEEF_1234_5678);
    }

    #[test]
    fn stdint_pointer_casts_use_the_right_width() {
        // Distinct bytes so a wrong width is visible rather than coincidental.
        let mem: Vec<u8> = (0..16u8).collect();
        let s = session(regs_with(&[(1, 0x2000)], 0, 0), 0x2000, mem);
        assert_eq!(s.evaluate("*(uint8_t*)$x1").unwrap().value, 0x00);
        assert_eq!(s.evaluate("*(uint16_t*)$x1").unwrap().value, 0x0100);
        assert_eq!(s.evaluate("*(uint32_t*)$x1").unwrap().value, 0x0302_0100);
        assert_eq!(
            s.evaluate("*(uint64_t*)$x1").unwrap().value,
            0x0706_0504_0302_0100
        );
    }

    #[test]
    fn unknown_register_is_reported_not_zero() {
        let s = session(Arm64RegisterFile::new(), 0, vec![]);
        match s.evaluate("$rax + 1") {
            Err(EvalError::UndefinedRegister(r)) => assert_eq!(r, "rax"),
            other => panic!("expected UndefinedRegister, got {other:?}"),
        }
    }

    #[test]
    fn unmapped_read_is_an_error_not_a_zero() {
        let s = session(regs_with(&[(0, 0xDEAD_0000)], 0, 0), 0x1000, vec![0; 8]);
        assert!(matches!(
            s.evaluate("*(uint64_t*)$x0"),
            Err(EvalError::MemoryReadError { .. })
        ));
    }

    #[test]
    fn partial_read_at_the_end_of_a_snapshot_is_rejected() {
        // 4 bytes mapped, an 8-byte read must fail rather than pad.
        let s = session(regs_with(&[(0, 0x3000)], 0, 0), 0x3000, vec![1, 2, 3, 4]);
        assert_eq!(s.evaluate("*(uint32_t*)$x0").unwrap().value, 0x0403_0201);
        assert!(s.evaluate("*(uint64_t*)$x0").is_err());
    }

    #[test]
    fn oversized_read_is_refused() {
        let m = SnapshotMemory::new(0, vec![0; 8]);
        assert!(m.read_bytes(0, MAX_READ_LEN + 1).is_err());
    }

    #[test]
    fn address_overflow_is_refused_by_target_memory() {
        struct Never;
        impl TargetMemoryReader for Never {
            fn read_target_memory(&mut self, _a: u64, _l: usize) -> Result<Vec<u8>, String> {
                panic!("must not reach the target");
            }
        }
        let m = TargetMemory::new(Never);
        assert!(m.read_bytes(u64::MAX - 2, 16).is_err());
        assert!(m.read_bytes(0, MAX_READ_LEN + 1).is_err());
        assert_eq!(m.read_bytes(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn short_reply_from_a_lying_stub_is_rejected() {
        struct ShortReader;
        impl TargetMemoryReader for ShortReader {
            fn read_target_memory(&mut self, _a: u64, len: usize) -> Result<Vec<u8>, String> {
                Ok(vec![0xAA; len.saturating_sub(1)])
            }
        }
        let m = TargetMemory::new(ShortReader);
        let err = m.read_bytes(0x1000, 8).unwrap_err();
        assert!(err.0.contains("short read"), "{}", err.0);
    }

    #[test]
    fn symbols_resolve_and_reverse() {
        let mut syms = AppleSymbols::from_pairs([("main", 0x4000u64)]);
        syms.insert("helper", 0x4100);
        assert_eq!(syms.len(), 2);
        assert!(!syms.is_empty());
        assert_eq!(syms.lookup_symbol("main"), Some(0x4000));
        assert_eq!(syms.reverse_lookup(0x4100).as_deref(), Some("helper"));
        // A duplicate name must not silently rebind.
        syms.insert("main", 0x9999);
        assert_eq!(syms.lookup_symbol("main"), Some(0x4000));
    }

    #[test]
    fn symbol_plus_offset_evaluates() {
        let mut s = session(Arm64RegisterFile::new(), 0x4000, vec![0; 32]);
        s.symbols_mut().insert("g_counter", 0x4008);
        assert_eq!(s.evaluate("g_counter + 4").unwrap().value, 0x400C);
    }

    #[test]
    fn struct_fields_declared_by_the_caller_resolve() {
        use crate::expression_evaluator::StructField;
        let mut mem = vec![0u8; 32];
        mem[8..16].copy_from_slice(&0x1122_3344u64.to_le_bytes());
        let mut s = session(regs_with(&[(0, 0x5000)], 0, 0), 0x5000, mem);
        let u64_id = s.types().lookup_name("u64").unwrap();
        s.types_mut().define_struct(
            "Obj",
            vec![
                StructField { name: "isa".into(), ty: u64_id, offset: 0 },
                StructField { name: "value".into(), ty: u64_id, offset: 8 },
            ],
        );
        assert_eq!(s.evaluate("((Obj*)$x0)->value").unwrap().value, 0x1122_3344);
    }

    #[test]
    fn watches_report_changes_across_stops() {
        let mut s = session(regs_with(&[(0, 1)], 0, 0), 0, vec![]);
        let id = s.watch("$x0").unwrap();
        assert!(id > 0 || id == 0);
        let first = s.poll_watches();
        assert_eq!(first.len(), 1, "first evaluation reports the initial value");
        assert!(s.poll_watches().is_empty(), "unchanged value is not reported");
        s.set_registers(regs_with(&[(0, 2)], 0, 0));
        let changed = s.poll_watches();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].new_value.value, 2);
    }

    #[test]
    fn pretty_print_round_trips() {
        let s = session(regs_with(&[(0, 0x2A)], 0, 0), 0, vec![]);
        let out = s.evaluate_pretty("$x0").unwrap();
        assert!(out.contains("42") || out.contains("2a") || out.contains("2A"), "{out}");
    }

    // -- against the mock debugserver, end to end --------------------------

    /// The real point of the module: an expression evaluated against a process
    /// reached over RSP, not against a `Vec<u8>`.
    #[test]
    fn evaluates_against_the_mock_debugserver_over_rsp() {
        const BASE: u64 = 0x1_0000_0000;

        let mut server = MockDebugserver::new(4242);
        // Lay out: [BASE .. BASE+16) filler, then the qword the expression wants.
        let mut payload = vec![0x11u8; 16];
        payload.extend_from_slice(&0x0BAD_F00D_CAFE_BABEu64.to_le_bytes());
        assert!(
            server
                .memory
                .map(MemoryRegion::new(BASE, payload, Perms::rw(), "TestData")),
            "test region must map"
        );
        let t = server.thread_mut_for_test(1).expect("thread 1 exists");
        t.regs.x[0] = BASE;
        t.regs.sp = BASE;

        let mut client = MockRspClient::new(LoopbackTransport::new(server));
        client.handshake().expect("handshake");
        let tid = *client.threads().expect("threads").first().expect("one thread");
        let regs = client.read_registers(tid).expect("g packet");

        let view = Arm64RegisterView::from_mock(&regs);
        assert_eq!(view.read_register("x0"), Some(BASE));

        let session = AppleExprSession::new(view, TargetMemory::new(client), AppleSymbols::new());

        let v = session
            .evaluate("*(uint64_t*)($x0 + 16)")
            .expect("evaluate against live target");
        assert_eq!(v.value, 0x0BAD_F00D_CAFE_BABE);

        // A byte-width read through the same session, to prove the width comes
        // from the cast and not from a fixed 8.
        assert_eq!(session.evaluate("*(uint8_t*)$x0").unwrap().value, 0x11);

        // And an unmapped address must fail loudly.
        assert!(matches!(
            session.evaluate("*(uint64_t*)0x4000000000000000"),
            Err(EvalError::MemoryReadError { .. })
        ));
    }

    #[test]
    fn mock_register_file_conversion_is_faithful() {
        let mut regs = crate::ios::mock_debugserver::Arm64Registers::default();
        regs.x[5] = 0x5555;
        regs.sp = 0x7000;
        regs.pc = 0x8000;
        regs.v[1] = 0x1234_5678;
        let view = Arm64RegisterView::from_mock(&regs);
        assert_eq!(view.read_register("x5"), Some(0x5555));
        assert_eq!(view.read_register("sp"), Some(0x7000));
        assert_eq!(view.read_register("pc"), Some(0x8000));
        assert_eq!(view.read_register("d1"), Some(0x1234_5678));
        assert_eq!(view.file().cpsr, regs.cpsr);
    }

    #[test]
    fn reg_class_is_reachable_from_here() {
        // Guards the lookup table this module depends on: `sp` must not decay
        // into a general register, which is the classic AArch64 aliasing bug.
        let spec = lookup_register("sp").expect("sp resolves");
        assert!(matches!(spec.class, RegClass::StackPointer));
    }
}
