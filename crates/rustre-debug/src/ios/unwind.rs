//! ARM64 stack unwinding for Apple targets (macOS / iOS / arm64e).
//!
//! Three strategies, tried in cascade for every frame, mirroring what LLDB
//! does when it has no better information:
//!
//! 1. [`FramePointerChain`](FrameProvenance::FramePointerChain) — AAPCS64
//!    says `x29` points at a two-word record `[saved x29, saved x30]`, so
//!    `[fp] -> caller fp` and `[fp+8] -> caller lr`.
//! 2. [`CompactUnwind`](FrameProvenance::CompactUnwind) — Apple's
//!    `__TEXT,__unwind_info` compact-unwind tables. On arm64 the *majority*
//!    of functions ship only this, which is why it cannot be skipped.
//! 3. [`EhFrame`](FrameProvenance::EhFrame) — DWARF CFI from
//!    `__TEXT,__eh_frame`, delegated to [`crate::dwarf_cfi`].
//!
//! # Why the frame-pointer strategy runs *first*
//!
//! It is the cheapest and, on Apple platforms specifically, the most
//! reliable: `-fomit-frame-pointer` is not permitted on arm64 Darwin, so a
//! valid `x29` chain is the platform ABI rather than a lucky accident. It is
//! nonetheless *validated* (alignment, monotonicity, readability, non-null
//! result) instead of trusted, so genuinely frameless leaf functions and
//! hand-written assembly fall through to the table-driven strategies rather
//! than producing a plausible-looking wrong answer. [`UnwindOrder`] lets a
//! caller invert this to the "tables first" policy if it prefers.
//!
//! # Honesty contract
//!
//! Every produced frame records *which* strategy produced it in
//! [`UnwindFrame::provenance`], and every strategy that cannot answer
//! returns a typed [`UnwindError`] rather than a guess. A backtrace built
//! from frame-pointer walking must never be mistaken for one built from
//! CFI: they have very different failure modes, and the caller can only
//! weigh them if it is told them.
//!
//! Nothing here panics on malformed input — every buffer access is bounds
//! checked and every arithmetic step is wrapping/checked. This is parser
//! code fed by a possibly-hostile target process.

use crate::dwarf_cfi;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a single unwind step (or a parse feeding one) failed.
///
/// These are deliberately distinct: "there is no unwind table" and "the
/// unwind table says to use DWARF but there is no `__eh_frame`" are
/// different defects with different fixes, and collapsing them into a
/// generic failure is how a debugger ends up confidently wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnwindError {
    /// A read of the target's memory failed or was short.
    #[error("memory read failed at {addr:#x} ({len} bytes)")]
    MemoryRead { addr: u64, len: usize },

    /// A section buffer was truncated relative to what its own header claims.
    #[error("{what} truncated: need {need} bytes at offset {offset}, have {have}")]
    Truncated { what: &'static str, offset: usize, need: usize, have: usize },

    /// `__unwind_info` header did not carry the expected version.
    #[error("unsupported __unwind_info version {0} (expected 1)")]
    UnsupportedUnwindInfoVersion(u32),

    /// A second-level page carried a `kind` that is neither regular (2) nor
    /// compressed (3).
    #[error("unknown second-level page kind {0}")]
    UnknownSecondLevelKind(u32),

    /// The PC is outside every range the table describes.
    #[error("no unwind entry covers pc offset {0:#x}")]
    NoEntryForPc(u32),

    /// The compact encoding selects DWARF, but no `__eh_frame` was supplied
    /// (or the offset it names is outside it).
    #[error("compact encoding defers to DWARF at __eh_frame offset {0:#x}, unavailable")]
    DwarfDeferralUnavailable(u32),

    /// A compact encoding mode that exists in the format but cannot be
    /// turned into a frame here — named explicitly rather than silently
    /// treated as "no info".
    #[error("compact encoding mode unsupported for unwinding: {0}")]
    UnsupportedEncoding(&'static str),

    /// Frameless compact encodings recover the return address from the live
    /// `lr`, which is only trustworthy in the innermost frame.
    #[error("frameless encoding needs a live lr, unavailable at frame depth {0}")]
    FramelessWithoutLiveLr(usize),

    /// `.eh_frame` had no FDE covering the PC.
    #[error("no FDE covers pc {0:#x}")]
    NoFdeForPc(u64),

    /// CIE/FDE parse or CFI execution bailed. `dwarf_cfi` deliberately
    /// refuses opcodes whose operand shape it cannot skip safely, so this is
    /// a normal, expected degrade path rather than corruption.
    #[error("CFI evaluation failed for pc {pc:#x}: {reason}")]
    CfiFailed { pc: u64, reason: &'static str },

    /// The computed next frame failed a sanity invariant (see
    /// [`AppleUnwinder`] docs) — a cycle, a shrinking stack, a null PC.
    #[error("frame rejected: {0}")]
    ImplausibleFrame(&'static str),

    /// No strategy produced a frame. Carries what each one said, so a caller
    /// can tell "leaf function, stack ended" from "our tables are broken".
    #[error("all unwind strategies failed")]
    AllStrategiesFailed(Vec<(FrameProvenance, Self)>),
}

// ---------------------------------------------------------------------------
// Memory access
// ---------------------------------------------------------------------------

/// Read-only access to the unwound process's memory.
///
/// Kept as a trait (rather than taking a debugger handle) for two reasons:
/// the unwinder must work equally over a live process, a core file and a
/// test fixture, and none of those may drag an OS dependency into a crate
/// that has to compile on Windows.
pub trait MemoryReader {
    /// Fill `buf` from `addr`. Must be all-or-nothing: a partial read is an
    /// error, never silently zero-padded.
    ///
    /// # Errors
    /// [`UnwindError::MemoryRead`] if the range is not fully readable.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), UnwindError>;

    /// Read one little-endian 64-bit word. ARM64 Apple targets are always
    /// little-endian; big-endian PowerPC is out of scope for this crate.
    ///
    /// # Errors
    /// Propagates [`MemoryReader::read`].
    fn read_u64(&self, addr: u64) -> Result<u64, UnwindError> {
        let mut buf = [0u8; 8];
        self.read(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

/// A flat in-memory stand-in for a process address space.
///
/// This is not a test-only convenience: core files and cached stack
/// snapshots have exactly this shape, and having it in the public API is
/// what makes the unwinder testable on a non-Apple host.
#[derive(Debug, Clone)]
pub struct SliceMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl SliceMemory {
    /// Map `bytes` at virtual address `base`.
    #[must_use]
    pub const fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }

    /// Overwrite the 8 bytes at virtual address `addr`, if in range.
    pub fn write_u64(&mut self, addr: u64, value: u64) {
        let Some(off) = addr.checked_sub(self.base).and_then(|o| usize::try_from(o).ok()) else {
            return;
        };
        if let Some(dst) = self.bytes.get_mut(off..off + 8) {
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }
}

impl MemoryReader for SliceMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), UnwindError> {
        let err = || UnwindError::MemoryRead { addr, len: buf.len() };
        let off = addr.checked_sub(self.base).and_then(|o| usize::try_from(o).ok()).ok_or_else(err)?;
        let end = off.checked_add(buf.len()).ok_or_else(err)?;
        let src = self.bytes.get(off..end).ok_or_else(err)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Registers / frames
// ---------------------------------------------------------------------------

/// The ARM64 register subset an unwinder actually needs.
///
/// `lr` is `Option` on purpose: after the first step the caller's `x30` is
/// only known if the strategy that produced the frame recovered it, and
/// pretending otherwise is what makes frameless-encoding handling silently
/// wrong at depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Arm64UnwindRegs {
    /// Program counter.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer, `x29`.
    pub fp: u64,
    /// Link register, `x30` — `None` once it is no longer known to be live.
    pub lr: Option<u64>,
}

impl Arm64UnwindRegs {
    /// Registers for the innermost frame, where `lr` is by definition live.
    #[must_use]
    pub const fn new(pc: u64, sp: u64, fp: u64, lr: u64) -> Self {
        Self { pc, sp, fp, lr: Some(lr) }
    }
}

impl From<&crate::RegisterSet> for Arm64UnwindRegs {
    /// Bridge from the hub crate's register bag.
    ///
    /// `RegisterSet::fp`/`lr` are `Option` because they are meaningless on
    /// x86; on ARM64 they are populated, but we still fall back to the
    /// named `x29`/`x30` entries because a register map built from
    /// `qRegisterInfo` may only have tagged one of the two spellings.
    fn from(rs: &crate::RegisterSet) -> Self {
        Self {
            pc: rs.pc,
            sp: rs.sp,
            fp: rs.fp.or_else(|| rs.get("x29")).or_else(|| rs.get("fp")).unwrap_or(0),
            lr: rs.lr.or_else(|| rs.get("x30")).or_else(|| rs.get("lr")),
        }
    }
}

/// Which strategy produced a frame. Recorded per frame, and logged, so a
/// heuristic walk is never mistaken for a CFI-derived one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameProvenance {
    /// Frame 0 — the registers the caller supplied, not unwound at all.
    Initial,
    /// Walked `x29`'s saved-pair chain.
    FramePointerChain,
    /// Applied a `__unwind_info` compact encoding.
    CompactUnwind,
    /// Ran DWARF CFI from `__eh_frame`.
    EhFrame,
}

impl core::fmt::Display for FrameProvenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Initial => "initial",
            Self::FramePointerChain => "fp-chain",
            Self::CompactUnwind => "compact-unwind",
            Self::EhFrame => "eh-frame",
        })
    }
}

/// One recovered stack frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindFrame {
    /// 0 = innermost.
    pub index: usize,
    /// Register state *in* this frame.
    pub regs: Arm64UnwindRegs,
    /// How this frame's registers were obtained.
    pub provenance: FrameProvenance,
}

impl UnwindFrame {
    /// Convert to the hub crate's `StackFrame` for reporting. Symbolication
    /// is left to a `FrameSymbolResolver`; this crate never invents names.
    #[must_use]
    pub const fn to_stack_frame(&self) -> crate::StackFrame {
        use rustre_core::address::Address;
        crate::StackFrame {
            index: self.index,
            pc: Address::new(self.regs.pc),
            sp: Address::new(self.regs.sp),
            fp: Some(Address::new(self.regs.fp)),
            function_name: None,
            module: None,
            offset: None,
            source_file: None,
            source_line: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Pointer authentication (arm64e)
// ---------------------------------------------------------------------------

/// Number of significant bits in a Darwin arm64 user-space virtual address.
///
/// arm64e signs the unused top bits of return addresses with a PAC. Those
/// bits are garbage to an unwinder and must be cleared before the address is
/// used as a PC or dereferenced.
pub const DARWIN_ARM64_VA_BITS: u32 = 47;

/// Strip an arm64e pointer-authentication code.
///
/// Kernel addresses (top bit set) are sign-extended back to all-ones so a
/// kernel PC survives the round trip; user addresses are masked to
/// [`DARWIN_ARM64_VA_BITS`]. On non-PAC arm64 this is the identity for every
/// legal address, so it is safe to apply unconditionally.
#[must_use]
pub const fn strip_pac(addr: u64) -> u64 {
    let mask = (1u64 << DARWIN_ARM64_VA_BITS) - 1;
    if addr & (1u64 << 63) != 0 { addr | !mask } else { addr & mask }
}

// ---------------------------------------------------------------------------
// Little-endian bounds-checked scalar reads
// ---------------------------------------------------------------------------

fn rd_u16(b: &[u8], off: usize, what: &'static str) -> Result<u16, UnwindError> {
    let s = b
        .get(off..off + 2)
        .ok_or(UnwindError::Truncated { what, offset: off, need: 2, have: b.len() })?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize, what: &'static str) -> Result<u32, UnwindError> {
    let s = b
        .get(off..off + 4)
        .ok_or(UnwindError::Truncated { what, offset: off, need: 4, have: b.len() })?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

// ---------------------------------------------------------------------------
// Compact unwind: encodings
// ---------------------------------------------------------------------------

/// Mask selecting the mode nibble of a compact encoding word.
pub const UNWIND_ARM64_MODE_MASK: u32 = 0x0F00_0000;
/// arm64: no frame pointer; fixed-size stack frame; return address in `lr`.
pub const UNWIND_ARM64_MODE_FRAMELESS: u32 = 0x0200_0000;
/// arm64: defer to `__eh_frame` at the offset in the low 24 bits.
pub const UNWIND_ARM64_MODE_DWARF: u32 = 0x0300_0000;
/// arm64: standard `x29` frame record.
pub const UNWIND_ARM64_MODE_FRAME: u32 = 0x0400_0000;

/// arm64 frameless: stack size in 16-byte units, bits 12..24.
pub const UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK: u32 = 0x00FF_F000;
/// arm64/`x86_64` DWARF mode: `__eh_frame` section offset, low 24 bits.
pub const UNWIND_ARM64_DWARF_SECTION_OFFSET: u32 = 0x00FF_FFFF;

/// arm64 FRAME mode: `x19`/`x20` pair saved.
pub const UNWIND_ARM64_FRAME_X19_X20_PAIR: u32 = 0x0000_0001;
/// arm64 FRAME mode: `x21`/`x22` pair saved.
pub const UNWIND_ARM64_FRAME_X21_X22_PAIR: u32 = 0x0000_0002;
/// arm64 FRAME mode: `x23`/`x24` pair saved.
pub const UNWIND_ARM64_FRAME_X23_X24_PAIR: u32 = 0x0000_0004;
/// arm64 FRAME mode: `x25`/`x26` pair saved.
pub const UNWIND_ARM64_FRAME_X25_X26_PAIR: u32 = 0x0000_0008;
/// arm64 FRAME mode: `x27`/`x28` pair saved.
pub const UNWIND_ARM64_FRAME_X27_X28_PAIR: u32 = 0x0000_0010;
/// arm64 FRAME mode: `d8`/`d9` pair saved.
pub const UNWIND_ARM64_FRAME_D8_D9_PAIR: u32 = 0x0000_0100;
/// arm64 FRAME mode: `d10`/`d11` pair saved.
pub const UNWIND_ARM64_FRAME_D10_D11_PAIR: u32 = 0x0000_0200;
/// arm64 FRAME mode: `d12`/`d13` pair saved.
pub const UNWIND_ARM64_FRAME_D12_D13_PAIR: u32 = 0x0000_0400;
/// arm64 FRAME mode: `d14`/`d15` pair saved.
pub const UNWIND_ARM64_FRAME_D14_D15_PAIR: u32 = 0x0000_0800;

/// `x86_64` mode: classic `rbp` frame.
pub const UNWIND_X86_64_MODE_RBP_FRAME: u32 = 0x0100_0000;
/// `x86_64` mode: frameless, immediate stack size.
pub const UNWIND_X86_64_MODE_STACK_IMMD: u32 = 0x0200_0000;
/// `x86_64` mode: frameless, stack size read indirectly from the prologue.
pub const UNWIND_X86_64_MODE_STACK_IND: u32 = 0x0300_0000;
/// `x86_64` mode: defer to `__eh_frame`.
pub const UNWIND_X86_64_MODE_DWARF: u32 = 0x0400_0000;

/// A decoded arm64 compact-unwind encoding word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64Encoding {
    /// Standard `x29` frame record at `[x29]`/`[x29+8]`; `saved_registers`
    /// is the callee-saved pair bitmask (informational for unwinding the
    /// CFA, required if a caller wants to restore those registers).
    Frame { saved_registers: u32 },
    /// Fixed-size frame, no `x29` record; return address stays in `lr`.
    Frameless { stack_size: u64 },
    /// Defer to `__eh_frame` at this section-relative offset.
    Dwarf { eh_frame_offset: u32 },
    /// Encoding word is all zero: the linker's marker for "this range has
    /// no unwind information", which is information in itself.
    None,
}

impl Arm64Encoding {
    /// Decode a raw arm64 encoding word.
    ///
    /// # Errors
    /// [`UnwindError::UnsupportedEncoding`] for a mode nibble that is not
    /// one of the four arm64 modes — a reserved value, not a guessable one.
    pub const fn decode(encoding: u32) -> Result<Self, UnwindError> {
        if encoding == 0 {
            return Ok(Self::None);
        }
        match encoding & UNWIND_ARM64_MODE_MASK {
            UNWIND_ARM64_MODE_FRAME => Ok(Self::Frame { saved_registers: encoding & 0x0000_0FFF }),
            UNWIND_ARM64_MODE_FRAMELESS => {
                // The field counts 16-byte units, so the widest legal value
                // (0xFFF) is a 64 KiB frame — no overflow concern.
                let units = (encoding & UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK) >> 12;
                Ok(Self::Frameless { stack_size: (units as u64) * 16 })
            }
            UNWIND_ARM64_MODE_DWARF => {
                Ok(Self::Dwarf { eh_frame_offset: encoding & UNWIND_ARM64_DWARF_SECTION_OFFSET })
            }
            _ => Err(UnwindError::UnsupportedEncoding("reserved arm64 compact-unwind mode")),
        }
    }

    /// Whether this encoding names a callee-saved pair as spilled. Not used
    /// by CFA recovery, but a register-restoring unwinder needs it and it
    /// would otherwise be silently dropped on decode.
    #[must_use]
    pub const fn saves_pair(&self, pair_mask: u32) -> bool {
        match self {
            Self::Frame { saved_registers } => *saved_registers & pair_mask != 0,
            _ => false,
        }
    }
}

/// `x86_64` compact-unwind modes, decoded but **not** applied here.
///
/// Present so an `x86_64` slice of a universal binary is *rejected with a
/// reason* instead of looking like a corrupt table. Implementing `x86_64`
/// frame recovery is a separate, honest piece of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64EncodingMode {
    /// `rbp`-based frame.
    RbpFrame,
    /// Frameless, immediate stack size.
    StackImmediate,
    /// Frameless, indirect stack size.
    StackIndirect,
    /// Defer to `__eh_frame`.
    Dwarf,
}

impl X86_64EncodingMode {
    /// Classify an `x86_64` encoding word's mode nibble.
    #[must_use]
    pub const fn classify(encoding: u32) -> Option<Self> {
        match encoding & UNWIND_ARM64_MODE_MASK {
            UNWIND_X86_64_MODE_RBP_FRAME => Some(Self::RbpFrame),
            UNWIND_X86_64_MODE_STACK_IMMD => Some(Self::StackImmediate),
            UNWIND_X86_64_MODE_STACK_IND => Some(Self::StackIndirect),
            UNWIND_X86_64_MODE_DWARF => Some(Self::Dwarf),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Compact unwind: __unwind_info section
// ---------------------------------------------------------------------------

const UNWIND_SECTION_VERSION: u32 = 1;
const SECOND_LEVEL_REGULAR: u32 = 2;
const SECOND_LEVEL_COMPRESSED: u32 = 3;

/// One resolved compact-unwind entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactEntry {
    /// Image-relative offset of the function this entry starts covering.
    pub function_offset: u32,
    /// Raw encoding word, before architecture decoding.
    pub encoding: u32,
}

/// Parsed `__TEXT,__unwind_info`.
///
/// Only the header and first-level index are eagerly validated; second-level
/// pages are parsed on lookup. That keeps construction cheap for the common
/// case of a large system framework whose table is mostly never consulted,
/// and it means a single corrupt page cannot make the whole image
/// un-unwindable.
#[derive(Debug, Clone)]
pub struct CompactUnwindInfo {
    data: Vec<u8>,
    common_encodings_offset: u32,
    common_encodings_count: u32,
    index_offset: u32,
    index_count: u32,
}

impl CompactUnwindInfo {
    /// Parse the section header and validate the first-level index bounds.
    ///
    /// # Errors
    /// [`UnwindError::Truncated`] or
    /// [`UnwindError::UnsupportedUnwindInfoVersion`].
    pub fn parse(data: &[u8]) -> Result<Self, UnwindError> {
        const W: &str = "__unwind_info header";
        let version = rd_u32(data, 0, W)?;
        if version != UNWIND_SECTION_VERSION {
            return Err(UnwindError::UnsupportedUnwindInfoVersion(version));
        }
        let common_encodings_offset = rd_u32(data, 4, W)?;
        let common_encodings_count = rd_u32(data, 8, W)?;
        // Offsets 12/16 are the personality array; it selects a personality
        // routine for exception handling, which does not affect the CFA, so
        // it is deliberately not retained.
        let index_offset = rd_u32(data, 20, W)?;
        let index_count = rd_u32(data, 24, W)?;

        // Validate the whole index up-front: a lookup binary-searches it, and
        // a search over a truncated array is exactly the shape of bug that
        // returns a plausible wrong entry instead of an error.
        let index_bytes = (index_count as usize).checked_mul(12).ok_or(UnwindError::Truncated {
            what: "__unwind_info index",
            offset: index_offset as usize,
            need: usize::MAX,
            have: data.len(),
        })?;
        let index_end =
            (index_offset as usize).checked_add(index_bytes).ok_or(UnwindError::Truncated {
                what: "__unwind_info index",
                offset: index_offset as usize,
                need: index_bytes,
                have: data.len(),
            })?;
        if index_end > data.len() {
            return Err(UnwindError::Truncated {
                what: "__unwind_info index",
                offset: index_offset as usize,
                need: index_bytes,
                have: data.len().saturating_sub(index_offset as usize),
            });
        }

        Ok(Self {
            data: data.to_vec(),
            common_encodings_offset,
            common_encodings_count,
            index_offset,
            index_count,
        })
    }

    /// Number of first-level index entries, including the terminating
    /// sentinel.
    #[must_use]
    pub const fn index_count(&self) -> u32 {
        self.index_count
    }

    fn index_entry(&self, i: u32) -> Result<(u32, u32), UnwindError> {
        let off = self.index_offset as usize + (i as usize) * 12;
        let function_offset = rd_u32(&self.data, off, "__unwind_info index entry")?;
        let page_offset = rd_u32(&self.data, off + 4, "__unwind_info index entry")?;
        Ok((function_offset, page_offset))
    }

    fn common_encoding(&self, i: u32) -> Result<u32, UnwindError> {
        if i >= self.common_encodings_count {
            return Err(UnwindError::Truncated {
                what: "__unwind_info common encodings",
                offset: i as usize,
                need: 4,
                have: self.common_encodings_count as usize,
            });
        }
        rd_u32(
            &self.data,
            self.common_encodings_offset as usize + (i as usize) * 4,
            "__unwind_info common encodings",
        )
    }

    /// Look up the entry covering an image-relative function offset.
    ///
    /// # Errors
    /// [`UnwindError::NoEntryForPc`] if outside every covered range, or a
    /// parse error from the selected second-level page.
    pub fn lookup(&self, function_offset: u32) -> Result<CompactEntry, UnwindError> {
        // The index needs at least one real entry plus the sentinel, whose
        // `page_offset == 0` marks the end of the last function's range.
        if self.index_count < 2 {
            return Err(UnwindError::NoEntryForPc(function_offset));
        }

        // Largest i with index[i].function_offset <= function_offset.
        let mut lo = 0u32;
        let mut hi = self.index_count - 1;
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if self.index_entry(mid)?.0 <= function_offset {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        let (first_level_fn, page_offset) = self.index_entry(lo)?;
        if first_level_fn > function_offset {
            return Err(UnwindError::NoEntryForPc(function_offset));
        }
        // `page_offset == 0` is the sentinel entry: `function_offset` is at
        // or past the end of the last described function.
        if page_offset == 0 || lo + 1 >= self.index_count {
            return Err(UnwindError::NoEntryForPc(function_offset));
        }
        // The next index entry bounds this page's coverage.
        if function_offset >= self.index_entry(lo + 1)?.0 {
            return Err(UnwindError::NoEntryForPc(function_offset));
        }

        self.lookup_in_page(page_offset, first_level_fn, function_offset)
    }

    fn lookup_in_page(
        &self,
        page_offset: u32,
        first_level_fn: u32,
        function_offset: u32,
    ) -> Result<CompactEntry, UnwindError> {
        const W: &str = "__unwind_info second-level page";
        let page = page_offset as usize;
        match rd_u32(&self.data, page, W)? {
            SECOND_LEVEL_REGULAR => {
                let entry_page_offset = rd_u16(&self.data, page + 4, W)? as usize;
                let entry_count = u32::from(rd_u16(&self.data, page + 6, W)?);
                if entry_count == 0 {
                    return Err(UnwindError::NoEntryForPc(function_offset));
                }
                let base = page + entry_page_offset;
                // Regular entries carry absolute (image-relative) offsets.
                let get = |i: u32| -> Result<u32, UnwindError> {
                    rd_u32(&self.data, base + (i as usize) * 8, W)
                };
                let idx = binary_search_last_le(entry_count, function_offset, get)?
                    .ok_or(UnwindError::NoEntryForPc(function_offset))?;
                let off = base + (idx as usize) * 8;
                Ok(CompactEntry {
                    function_offset: rd_u32(&self.data, off, W)?,
                    encoding: rd_u32(&self.data, off + 4, W)?,
                })
            }
            SECOND_LEVEL_COMPRESSED => {
                let entry_page_offset = rd_u16(&self.data, page + 4, W)? as usize;
                let entry_count = u32::from(rd_u16(&self.data, page + 6, W)?);
                let encodings_page_offset = rd_u16(&self.data, page + 8, W)? as usize;
                // The page-local encodings array is bounded by its own count,
                // sitting right after the offset in the page header. Without
                // it an index past the end reads whatever bytes follow the
                // array — in a real table, the NEXT second-level page — and
                // hands them back as a perfectly well-formed encoding word.
                let encodings_count = u32::from(rd_u16(&self.data, page + 10, W)?);
                if entry_count == 0 {
                    return Err(UnwindError::NoEntryForPc(function_offset));
                }
                let base = page + entry_page_offset;
                // Compressed entries pack a 24-bit function offset *relative
                // to the first-level entry* with an 8-bit encoding index.
                let Some(relative) = function_offset.checked_sub(first_level_fn) else {
                    return Err(UnwindError::NoEntryForPc(function_offset));
                };
                let get = |i: u32| -> Result<u32, UnwindError> {
                    Ok(rd_u32(&self.data, base + (i as usize) * 4, W)? & 0x00FF_FFFF)
                };
                let idx = binary_search_last_le(entry_count, relative, get)?
                    .ok_or(UnwindError::NoEntryForPc(function_offset))?;
                let raw = rd_u32(&self.data, base + (idx as usize) * 4, W)?;
                let entry_fn = first_level_fn.wrapping_add(raw & 0x00FF_FFFF);
                let encoding_index = raw >> 24;
                let encoding = if encoding_index < self.common_encodings_count {
                    self.common_encoding(encoding_index)?
                } else {
                    let local = encoding_index - self.common_encodings_count;
                    if local >= encodings_count {
                        return Err(UnwindError::Truncated {
                            what: "__unwind_info second-level page encodings",
                            offset: local as usize,
                            need: 4,
                            have: encodings_count as usize,
                        });
                    }
                    rd_u32(&self.data, page + encodings_page_offset + (local as usize) * 4, W)?
                };
                Ok(CompactEntry { function_offset: entry_fn, encoding })
            }
            other => Err(UnwindError::UnknownSecondLevelKind(other)),
        }
    }
}

/// Largest `i < count` whose key is `<= target`, or `None`.
///
/// Written as a helper because both page kinds need it with different key
/// extraction, and an off-by-one here silently attributes a PC to the
/// neighbouring function — the classic compact-unwind bug.
fn binary_search_last_le<F>(count: u32, target: u32, get: F) -> Result<Option<u32>, UnwindError>
where
    F: Fn(u32) -> Result<u32, UnwindError>,
{
    if count == 0 || get(0)? > target {
        return Ok(None);
    }
    let mut lo = 0u32;
    let mut hi = count - 1;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if get(mid)? <= target {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(Some(lo))
}

// ---------------------------------------------------------------------------
// __eh_frame
// ---------------------------------------------------------------------------

/// `__TEXT,__eh_frame` bytes plus the virtual address they are mapped at.
///
/// The VA is mandatory, not optional: FDE `initial_location` fields are
/// PC-relative, so a section parsed without knowing where it lives resolves
/// every function to the wrong address. (`DwarfUnwinder::from_sections` in
/// `rustre-symbols-dwarf` hardcodes a base of 0 and has exactly that bug,
/// which is why this crate talks to `dwarf_cfi` directly.)
#[derive(Debug, Clone)]
pub struct EhFrameSection {
    data: Vec<u8>,
    vmaddr: u64,
}

/// A CIE/FDE pair located for a PC, with the byte ranges already resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FdeMatch {
    cie_body: (usize, usize),
    fde_body: (usize, usize),
    fde_body_vaddr: u64,
    info: dwarf_cfi::FdeInfo,
    cie: dwarf_cfi::CieInfo,
}

impl EhFrameSection {
    /// Wrap section bytes mapped at `vmaddr` (already slid for ASLR).
    #[must_use]
    pub const fn new(data: Vec<u8>, vmaddr: u64) -> Self {
        Self { data, vmaddr }
    }

    /// The CFA rule in effect at `pc`, per DWARF CFI.
    ///
    /// # Errors
    /// [`UnwindError::NoFdeForPc`] if nothing covers `pc`, or
    /// [`UnwindError::CfiFailed`] if the CIE/FDE or its instruction stream
    /// is one `dwarf_cfi` declines to interpret.
    pub fn cfa_rule_at(&self, pc: u64) -> Result<dwarf_cfi::CfaRule, UnwindError> {
        let m = self.find_fde(pc).ok_or(UnwindError::NoFdeForPc(pc))?;
        let cie_bytes = &self.data[m.cie_body.0..m.cie_body.1];
        let fde_bytes = &self.data[m.fde_body.0..m.fde_body.1];
        let init = cie_bytes
            .get(m.cie.initial_instructions.0..m.cie.initial_instructions.1)
            .ok_or(UnwindError::CfiFailed { pc, reason: "CIE initial instructions out of range" })?;
        let fde_instrs = fde_bytes
            .get(m.info.instructions.0..m.info.instructions.1)
            .ok_or(UnwindError::CfiFailed { pc, reason: "FDE instructions out of range" })?;
        let target_offset = pc.wrapping_sub(m.info.initial_location);
        dwarf_cfi::run_cfi_to_offset(
            init,
            fde_instrs,
            m.cie.code_alignment_factor,
            m.cie.data_alignment_factor,
            target_offset,
        )
        .ok_or(UnwindError::CfiFailed { pc, reason: "unsupported CFI opcode or no CFA rule" })
    }

    /// Walk the section's CIE/FDE records looking for one covering `pc`.
    ///
    /// A linear walk is correct and, importantly, cannot desynchronise: the
    /// `.eh_frame` search table (`__eh_frame_hdr`) that would make this
    /// logarithmic is an ELF construct with no Mach-O counterpart.
    fn find_fde(&self, pc: u64) -> Option<FdeMatch> {
        let mut pos = 0usize;
        // Guard against a zero-length record making this loop non-terminating
        // on crafted input.
        while pos + 8 <= self.data.len() {
            let length = rd_u32(&self.data, pos, "eh_frame record").ok()? as usize;
            if length == 0 {
                // Terminator record.
                return None;
            }
            if length == 0xFFFF_FFFF {
                // 64-bit extended length: not emitted by Apple toolchains for
                // __eh_frame. Bail rather than misparse the rest.
                return None;
            }
            let body_start = pos + 4;
            let body_end = body_start.checked_add(length)?;
            if body_end > self.data.len() {
                return None;
            }
            let id = rd_u32(&self.data, body_start, "eh_frame record id").ok()?;
            if id != 0 {
                // FDE. `id` is the distance backwards from this field to the
                // owning CIE's length field.
                let cie_len_pos = body_start.checked_sub(id as usize)?;
                if let Some(m) = self.parse_fde_at(pc, cie_len_pos, body_start + 4, body_end) {
                    return Some(m);
                }
            }
            pos = body_end;
        }
        None
    }

    fn parse_fde_at(
        &self,
        pc: u64,
        cie_len_pos: usize,
        fde_body_start: usize,
        fde_body_end: usize,
    ) -> Option<FdeMatch> {
        let cie_len = rd_u32(&self.data, cie_len_pos, "eh_frame cie").ok()? as usize;
        // CIE body starts after its 4-byte length and 4-byte CIE_id.
        let cie_body_start = cie_len_pos.checked_add(8)?;
        let cie_body_end = cie_len_pos.checked_add(4)?.checked_add(cie_len)?;
        if cie_body_end > self.data.len() || cie_body_start > cie_body_end {
            return None;
        }
        let cie = dwarf_cfi::parse_cie(self.data.get(cie_body_start..cie_body_end)?)?;
        let encoding = cie.fde_pointer_encoding?;

        let fde_bytes = self.data.get(fde_body_start..fde_body_end)?;
        // The vaddr of the `initial_location` field itself, which is what
        // resolves its pc-relative encoding.
        let fde_body_vaddr = self.vmaddr.wrapping_add(fde_body_start as u64);
        let info = dwarf_cfi::parse_fde(fde_bytes, fde_body_vaddr, encoding)?;
        if pc < info.initial_location || pc >= info.initial_location.wrapping_add(info.address_range)
        {
            return None;
        }
        Some(FdeMatch {
            cie_body: (cie_body_start, cie_body_end),
            fde_body: (fde_body_start, fde_body_end),
            fde_body_vaddr,
            info,
            cie,
        })
    }
}

/// DWARF register number of `sp` on ARM64 (`x31` in the CFA role).
const DWARF_ARM64_SP: u8 = 31;
/// DWARF register number of `x29` (frame pointer) on ARM64.
const DWARF_ARM64_FP: u8 = 29;

// ---------------------------------------------------------------------------
// The unwinder
// ---------------------------------------------------------------------------

/// Order in which the three strategies are attempted per frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnwindOrder {
    /// Frame pointer, then compact unwind, then `__eh_frame`. The default:
    /// on arm64 Darwin `x29` is ABI-mandated, and the fp step is validated
    /// hard enough that a frameless function still falls through.
    #[default]
    FramePointerFirst,
    /// Compact unwind, then `__eh_frame`, then frame pointer. Prefer this
    /// when unwinding through hand-written assembly or JIT code where the
    /// tables, if present, are more trustworthy than the register.
    TablesFirst,
}

impl UnwindOrder {
    const fn sequence(self) -> [FrameProvenance; 3] {
        match self {
            Self::FramePointerFirst => [
                FrameProvenance::FramePointerChain,
                FrameProvenance::CompactUnwind,
                FrameProvenance::EhFrame,
            ],
            Self::TablesFirst => [
                FrameProvenance::CompactUnwind,
                FrameProvenance::EhFrame,
                FrameProvenance::FramePointerChain,
            ],
        }
    }
}

/// A loaded image's unwind tables plus where it is mapped.
#[derive(Debug, Clone, Default)]
pub struct ImageUnwindTables {
    /// Runtime base address of the Mach-O header (static base + ASLR slide).
    pub image_base: u64,
    /// Runtime end of the image's executable range, used to decide whether a
    /// PC belongs to this image at all.
    pub image_end: u64,
    /// Parsed `__TEXT,__unwind_info`, if the image has one.
    pub compact: Option<CompactUnwindInfo>,
    /// `__TEXT,__eh_frame`, if the image has one.
    pub eh_frame: Option<EhFrameSection>,
}

impl ImageUnwindTables {
    /// Whether `pc` falls inside this image's mapped range.
    #[must_use]
    pub const fn contains(&self, pc: u64) -> bool {
        pc >= self.image_base && pc < self.image_end
    }
}

/// Build the per-image unwind tables for the images a live target reports.
///
/// `read(addr, len)` fetches bytes from the target; an image the reader
/// cannot supply is simply skipped. Pure over an injected reader so the real
/// logic is testable on any host — the debugger passes an RSP-backed closure,
/// tests pass synthetic Mach-O bytes.
///
/// Why this exists: [`AppleUnwinder::new`] starts with no images, and nothing
/// ever called [`AppleUnwinder::with_image`], so the CompactUnwind and EhFrame
/// strategies could never run against a real target — only the frame-pointer
/// walk did. On arm64 the majority of functions carry compact unwind and no
/// frame pointer chain worth following, so that was precisely the case left
/// uncovered.
///
/// An image with no `__TEXT,__unwind_info` still yields an entry with
/// `compact: None`: the *range* alone is worth having, because the unwinder
/// uses it to stop a walk that leaves every known image instead of running on
/// into garbage.
pub fn unwind_images_from_modules<R>(modules: &[crate::ModuleInfo], read: R) -> Vec<ImageUnwindTables>
where
    R: Fn(u64, usize) -> Option<Vec<u8>>,
{
    use rustre_loader_macho::MachoParser;

    let mut images = Vec::new();
    for m in modules {
        let base = m.base.as_u64();
        let Ok(len) = usize::try_from(m.size) else { continue };
        if len == 0 {
            continue;
        }
        let Some(bytes) = read(base, len) else { continue };
        let Ok(info) = MachoParser::parse_single(&bytes) else { continue };

        // Anchor the image's extent on __TEXT, the segment the loader maps
        // first. Without it there is no honest end address, and a wrong one
        // would make the unwinder either truncate valid walks or accept
        // garbage PCs as "inside the image".
        let Some(text) = info.segments.iter().find(|s| s.name == "__TEXT") else { continue };
        // How far the image moved from where it was linked. `__eh_frame`
        // needs it: its FDEs are matched against RUNTIME pcs, so the section
        // must be told its slid address. (`__unwind_info` does not — its
        // entries are offsets relative to the image itself.)
        let slide = base.wrapping_sub(text.vm_addr);

        let compact = info
            .segments
            .iter()
            .flat_map(|seg| seg.sections.iter())
            .find(|sec| sec.segment == "__TEXT" && sec.name == "__unwind_info")
            .and_then(|sec| {
                let off = usize::try_from(sec.offset).ok()?;
                let size = usize::try_from(sec.size).ok()?;
                let raw = bytes.get(off..off.checked_add(size)?)?;
                CompactUnwindInfo::parse(raw).ok()
            });

        // Prefer `__TEXT,__eh_frame`, the placement every Apple toolchain
        // emits and the one the `__unwind_info` lookup above already demands.
        // The name-only fallback is kept deliberately — `__eh_frame` living
        // outside `__TEXT` is unusual but not impossible, and dropping such an
        // image's DWARF tables entirely would be a worse failure than using
        // them. What must NOT happen is the previous behaviour: matching on
        // the section name alone, so that a section named `__eh_frame` in ANY
        // segment could win purely by appearing first in iteration order and
        // silently shadow the real one.
        let sections = || info.segments.iter().flat_map(|seg| seg.sections.iter());
        let eh_frame = sections()
            .find(|sec| sec.segment == "__TEXT" && sec.name == "__eh_frame")
            .or_else(|| sections().find(|sec| sec.name == "__eh_frame"))
            .and_then(|sec| {
                let off = usize::try_from(sec.offset).ok()?;
                let size = usize::try_from(sec.size).ok()?;
                let raw = bytes.get(off..off.checked_add(size)?)?;
                Some(EhFrameSection::new(raw.to_vec(), sec.addr.wrapping_add(slide)))
            });

        images.push(ImageUnwindTables {
            image_base: base,
            image_end: base.wrapping_add(text.vm_size.max(m.size)),
            compact,
            eh_frame,
        });
    }
    images
}

/// Cascading ARM64 unwinder.
///
/// # Termination
///
/// A walk stops when any of the following holds, because each of them means
/// the next "frame" would be fabricated rather than recovered:
/// * `max_depth` frames have been produced;
/// * the next PC is zero (the conventional end of a Darwin thread stack);
/// * the next SP does not strictly exceed the current SP (stacks grow down,
///   so a non-increasing SP is a cycle or a corrupt frame);
/// * the next PC lies in no known image *and* the caller supplied images —
///   with no images the check is skipped rather than silently truncating.
#[derive(Debug, Clone)]
pub struct AppleUnwinder {
    images: Vec<ImageUnwindTables>,
    order: UnwindOrder,
    max_depth: usize,
}

impl Default for AppleUnwinder {
    fn default() -> Self {
        Self::new()
    }
}

impl AppleUnwinder {
    /// An unwinder with no images: only the frame-pointer strategy can
    /// succeed, and it will say so via provenance.
    #[must_use]
    pub const fn new() -> Self {
        Self { images: Vec::new(), order: UnwindOrder::FramePointerFirst, max_depth: 128 }
    }

    /// Register an image's unwind tables.
    #[must_use]
    pub fn with_image(mut self, image: ImageUnwindTables) -> Self {
        self.images.push(image);
        self
    }

    /// Override the strategy order.
    #[must_use]
    pub const fn with_order(mut self, order: UnwindOrder) -> Self {
        self.order = order;
        self
    }

    /// Override the frame cap (default 128).
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    fn image_for(&self, pc: u64) -> Option<&ImageUnwindTables> {
        self.images.iter().find(|i| i.contains(pc))
    }

    /// Produce a backtrace starting from `regs`.
    ///
    /// Never returns `Err`: a failure to unwind further is the *end* of a
    /// backtrace, not an error, and the frames already recovered are real.
    /// Frame 0 is always present with [`FrameProvenance::Initial`]. Use
    /// [`AppleUnwinder::step`] when the reason the walk stopped matters.
    #[must_use]
    pub fn backtrace(&self, regs: Arm64UnwindRegs, mem: &dyn MemoryReader) -> Vec<UnwindFrame> {
        let mut frames =
            vec![UnwindFrame { index: 0, regs, provenance: FrameProvenance::Initial }];
        let mut current = regs;
        while frames.len() < self.max_depth {
            let index = frames.len();
            let Ok((next, provenance)) = self.step(current, index, mem) else { break };
            if self.validate(current, next).is_err() {
                break;
            }
            frames.push(UnwindFrame { index, regs: next, provenance });
            current = next;
        }
        frames
    }

    /// Reject a candidate frame that cannot be a real caller.
    ///
    /// # Errors
    /// [`UnwindError::ImplausibleFrame`] with the specific invariant broken.
    fn validate(&self, prev: Arm64UnwindRegs, next: Arm64UnwindRegs) -> Result<(), UnwindError> {
        if next.pc == 0 {
            return Err(UnwindError::ImplausibleFrame("null return address (end of stack)"));
        }
        if next.sp <= prev.sp {
            return Err(UnwindError::ImplausibleFrame("stack pointer did not grow upward"));
        }
        if !self.images.is_empty() && self.image_for(next.pc).is_none() {
            return Err(UnwindError::ImplausibleFrame("return address in no known image"));
        }
        Ok(())
    }

    /// Unwind exactly one frame, trying each strategy in [`UnwindOrder`].
    ///
    /// `depth` is the index of the frame being *produced*; it matters
    /// because frameless compact encodings are only usable while `lr` is
    /// still live, i.e. when unwinding out of frame 0.
    ///
    /// # Errors
    /// [`UnwindError::AllStrategiesFailed`] carrying each strategy's own
    /// reason — the diagnostic that distinguishes "clean end of stack" from
    /// "our tables are wrong".
    pub fn step(
        &self,
        regs: Arm64UnwindRegs,
        depth: usize,
        mem: &dyn MemoryReader,
    ) -> Result<(Arm64UnwindRegs, FrameProvenance), UnwindError> {
        let mut failures = Vec::new();
        for strategy in self.order.sequence() {
            let attempt = match strategy {
                FrameProvenance::FramePointerChain => unwind_frame_pointer(regs, mem),
                FrameProvenance::CompactUnwind => self.unwind_compact(regs, depth, mem),
                FrameProvenance::EhFrame => self.unwind_eh_frame(regs, depth, mem),
                FrameProvenance::Initial => continue,
            };
            match attempt {
                Ok(next) => return Ok((next, strategy)),
                Err(e) => failures.push((strategy, e)),
            }
        }
        Err(UnwindError::AllStrategiesFailed(failures))
    }

    fn unwind_compact(
        &self,
        regs: Arm64UnwindRegs,
        depth: usize,
        mem: &dyn MemoryReader,
    ) -> Result<Arm64UnwindRegs, UnwindError> {
        // Beyond the innermost frame `regs.pc` is a RETURN address, pointing at
        // the instruction after the `bl`. When that call is the last
        // instruction of its function, the return address lands one byte past
        // the function — inside the NEXT one — and the table then hands back
        // that function's encoding. Subtracting one puts the key back inside
        // the call instruction, hence inside the calling function; libunwind,
        // LLVM and GDB all do exactly this. Only the LOOKUP key is adjusted,
        // the reported pc stays exact.
        let lookup_pc = if depth > 1 { regs.pc.wrapping_sub(1) } else { regs.pc };
        let image = self
            .image_for(lookup_pc)
            .ok_or(UnwindError::ImplausibleFrame("pc in no known image"))?;
        let compact = image
            .compact
            .as_ref()
            .ok_or(UnwindError::UnsupportedEncoding("image has no __unwind_info"))?;
        // The lookup key is the *static* offset from the Mach-O header, so
        // the ASLR slide must come off before searching and never after.
        let fn_offset = u32::try_from(lookup_pc.wrapping_sub(image.image_base))
            .map_err(|_| UnwindError::ImplausibleFrame("pc offset exceeds 4 GiB image range"))?;
        let entry = compact.lookup(fn_offset)?;

        match Arm64Encoding::decode(entry.encoding)? {
            Arm64Encoding::Frame { .. } => frame_record_step(regs, mem),
            Arm64Encoding::Frameless { stack_size } => {
                // `lr` is only the return address until the callee spills it.
                // Beyond frame 0 we do not know it, and guessing is exactly
                // the failure this crate refuses to ship.
                if depth != 1 {
                    return Err(UnwindError::FramelessWithoutLiveLr(depth));
                }
                let lr = regs.lr.ok_or(UnwindError::FramelessWithoutLiveLr(depth))?;
                Ok(Arm64UnwindRegs {
                    pc: strip_pac(lr),
                    sp: regs.sp.wrapping_add(stack_size),
                    // A frameless function never touched x29, so the caller's
                    // frame pointer is still in the register.
                    fp: regs.fp,
                    lr: None,
                })
            }
            Arm64Encoding::Dwarf { eh_frame_offset } => {
                // The encoding names an FDE offset, but resolving *by pc* over
                // the same section is equivalent and reuses one code path;
                // the offset is only used to report a precise error.
                if image.eh_frame.is_none() {
                    return Err(UnwindError::DwarfDeferralUnavailable(eh_frame_offset));
                }
                self.unwind_eh_frame(regs, depth, mem)
            }
            Arm64Encoding::None => {
                Err(UnwindError::UnsupportedEncoding("entry explicitly has no unwind info"))
            }
        }
    }

    fn unwind_eh_frame(
        &self,
        regs: Arm64UnwindRegs,
        depth: usize,
        mem: &dyn MemoryReader,
    ) -> Result<Arm64UnwindRegs, UnwindError> {
        // Same return-address adjustment as `unwind_compact`: an FDE covers
        // [start, end), so a return address one byte past the end of its
        // function selects the NEXT function's FDE — or none at all.
        let lookup_pc = if depth > 1 { regs.pc.wrapping_sub(1) } else { regs.pc };
        let image = self
            .image_for(lookup_pc)
            .ok_or(UnwindError::ImplausibleFrame("pc in no known image"))?;
        let eh = image
            .eh_frame
            .as_ref()
            .ok_or(UnwindError::UnsupportedEncoding("image has no __eh_frame"))?;
        let rule = eh.cfa_rule_at(lookup_pc)?;

        let base = match rule.register {
            DWARF_ARM64_SP => regs.sp,
            DWARF_ARM64_FP => regs.fp,
            // `dwarf_cfi` only ever tracks the CFA register, so an exotic
            // base register cannot be resolved from the four registers we
            // model. Say so instead of substituting sp.
            _ => {
                return Err(UnwindError::CfiFailed {
                    pc: regs.pc,
                    reason: "CFA register is not sp or x29",
                });
            }
        };
        let cfa = base.wrapping_add_signed(rule.offset);

        // AAPCS64 places the frame record immediately below the CFA:
        // [CFA-16] = caller x29, [CFA-8] = caller x30. `dwarf_cfi` does not
        // interpret DW_CFA_offset, so the *rules* for x29/x30 are not
        // available and this convention is assumed. It holds for every
        // clang/gcc-generated arm64 Darwin frame that has a frame record;
        // a function that spills lr elsewhere will produce a frame this
        // unwinder then rejects in `validate` rather than reporting wrongly.
        let lr = strip_pac(mem.read_u64(cfa.wrapping_sub(8))?);
        // Propagated, never defaulted. `regs.fp` is the CURRENT frame's x29,
        // so substituting it here does not produce a merely-incomplete frame:
        // the next step walks the same frame record a second time and emits a
        // duplicate frame that passes `validate` (pc in an image, sp grew).
        // A missing caller x29 is unknown information, and this module's
        // contract is to say so.
        let caller_fp = mem.read_u64(cfa.wrapping_sub(16))?;
        Ok(Arm64UnwindRegs { pc: lr, sp: cfa, fp: caller_fp, lr: None })
    }
}

/// Walk one link of the `x29` chain, with validation.
///
/// Validation is the whole point: an unchecked `[fp]`/`[fp+8]` read always
/// "succeeds" on a mapped stack, so without these tests the fp strategy
/// would never degrade and the other two would be dead code.
fn unwind_frame_pointer(
    regs: Arm64UnwindRegs,
    mem: &dyn MemoryReader,
) -> Result<Arm64UnwindRegs, UnwindError> {
    if regs.fp == 0 {
        return Err(UnwindError::ImplausibleFrame("frame pointer is null"));
    }
    if !regs.fp.is_multiple_of(16) {
        // AAPCS64 requires 16-byte stack alignment; an unaligned x29 means
        // it is holding something other than a frame record.
        return Err(UnwindError::ImplausibleFrame("frame pointer not 16-byte aligned"));
    }
    if regs.fp < regs.sp {
        return Err(UnwindError::ImplausibleFrame("frame pointer below stack pointer"));
    }
    frame_record_step(regs, mem)
}

/// The shared `[x29] -> caller fp`, `[x29+8] -> caller lr` step used by both
/// the fp-chain strategy and the compact `FRAME` encoding.
fn frame_record_step(
    regs: Arm64UnwindRegs,
    mem: &dyn MemoryReader,
) -> Result<Arm64UnwindRegs, UnwindError> {
    let caller_fp = mem.read_u64(regs.fp)?;
    let caller_lr = strip_pac(mem.read_u64(regs.fp.wrapping_add(8))?);
    Ok(Arm64UnwindRegs {
        pc: caller_lr,
        // The frame record occupies the two words at [x29]; the caller's sp
        // is immediately above them.
        sp: regs.fp.wrapping_add(16),
        fp: caller_fp,
        lr: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers -----------------------------------------------------------

    const STACK_BASE: u64 = 0x7000_0000_0000;
    const IMAGE_BASE: u64 = 0x1_0000_0000;

    /// Build a stack containing a chain of `x29` frame records.
    ///
    /// `frames` is `(fp_address, return_address)`; each record's "caller fp"
    /// is the next entry's fp, with 0 terminating the chain.
    fn build_fp_stack(frames: &[(u64, u64)]) -> SliceMemory {
        let mut mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);
        for (i, &(fp, ra)) in frames.iter().enumerate() {
            let caller_fp = frames.get(i + 1).map_or(0, |n| n.0);
            mem.write_u64(fp, caller_fp);
            mem.write_u64(fp + 8, ra);
        }
        mem
    }

    fn push_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn push_u16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Synthesise a whole `__unwind_info` section.
    ///
    /// One first-level index entry per page plus the mandatory sentinel.
    /// `pages` is `(first_level_function_offset, page_bytes)`.
    /// A minimal but valid arm64 Mach-O with a `__TEXT` segment carrying a
    /// real `__unwind_info` section holding `unwind_bytes`.
    fn build_macho_with_unwind_info(text_vmaddr: u64, unwind_bytes: &[u8]) -> Vec<u8> {
        build_macho_sections(text_vmaddr, unwind_bytes, &[])
    }

    /// Same, but also carrying an `__eh_frame` section when `eh_bytes` is
    /// non-empty.
    fn build_macho_sections(text_vmaddr: u64, unwind_bytes: &[u8], eh_bytes: &[u8]) -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xFEED_FACF;
        const CPU_TYPE_ARM64: u32 = 0x0100_000C;
        const LC_SEGMENT_64: u32 = 0x19;

        fn n16(name: &str) -> [u8; 16] {
            let mut out = [0u8; 16];
            let b = name.as_bytes();
            out[..b.len()].copy_from_slice(b);
            out
        }

        let has_eh = !eh_bytes.is_empty();
        let nsects: u32 = if has_eh { 3 } else { 2 };
        let seg_cmdsize: u32 = 72 + 80 * nsects;
        let header_size: u32 = 32;
        let unwind_off = header_size + seg_cmdsize;
        let eh_off = unwind_off + u32::try_from(unwind_bytes.len()).unwrap();
        let text_size =
            u64::from(eh_off) + if has_eh { eh_bytes.len() as u64 } else { 0 };

        let mut b = Vec::new();
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&n16("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&nsects.to_le_bytes()); // nsects
        b.extend_from_slice(&0u32.to_le_bytes());

        // __text
        b.extend_from_slice(&n16("__text"));
        b.extend_from_slice(&n16("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&64u64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        // align, reloff, nreloc, flags, reserved1..3 — section_64 is 80 bytes.
        for _ in 0..7 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        // __unwind_info
        b.extend_from_slice(&n16("__unwind_info"));
        b.extend_from_slice(&n16("__TEXT"));
        b.extend_from_slice(&(text_vmaddr + u64::from(unwind_off)).to_le_bytes());
        b.extend_from_slice(&(unwind_bytes.len() as u64).to_le_bytes());
        b.extend_from_slice(&unwind_off.to_le_bytes());
        for _ in 0..7 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        if has_eh {
            b.extend_from_slice(&n16("__eh_frame"));
            b.extend_from_slice(&n16("__TEXT"));
            b.extend_from_slice(&(text_vmaddr + u64::from(eh_off)).to_le_bytes());
            b.extend_from_slice(&(eh_bytes.len() as u64).to_le_bytes());
            b.extend_from_slice(&eh_off.to_le_bytes());
            for _ in 0..7 {
                b.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        assert_eq!(b.len(), unwind_off as usize, "load commands must end where the section starts");
        b.extend_from_slice(unwind_bytes);
        if has_eh {
            assert_eq!(b.len(), eh_off as usize, "__eh_frame must start where its offset says");
            b.extend_from_slice(eh_bytes);
        }
        b
    }

    fn build_unwind_info(
        common_encodings: &[u32],
        pages: &[(u32, Vec<u8>)],
        sentinel_offset: u32,
    ) -> Vec<u8> {
        const HEADER_LEN: usize = 28;
        let common_off = HEADER_LEN;
        let index_off = common_off + common_encodings.len() * 4;
        let index_count = pages.len() + 1; // + sentinel
        let pages_off = index_off + index_count * 12;

        let mut page_offsets = Vec::new();
        let mut cursor = pages_off;
        for (_, body) in pages {
            page_offsets.push(cursor);
            cursor += body.len();
        }

        let mut out = Vec::new();
        push_u32(&mut out, 1); // version
        push_u32(&mut out, u32::try_from(common_off).unwrap());
        push_u32(&mut out, u32::try_from(common_encodings.len()).unwrap());
        push_u32(&mut out, 0); // personality array offset
        push_u32(&mut out, 0); // personality array count
        push_u32(&mut out, u32::try_from(index_off).unwrap());
        push_u32(&mut out, u32::try_from(index_count).unwrap());
        assert_eq!(out.len(), HEADER_LEN);

        for &e in common_encodings {
            push_u32(&mut out, e);
        }
        for (i, (fn_off, _)) in pages.iter().enumerate() {
            push_u32(&mut out, *fn_off);
            push_u32(&mut out, u32::try_from(page_offsets[i]).unwrap());
            push_u32(&mut out, 0); // lsda index array offset
        }
        // Sentinel: page offset 0 marks the end of coverage.
        push_u32(&mut out, sentinel_offset);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);

        for (_, body) in pages {
            out.extend_from_slice(body);
        }
        out
    }

    /// A regular second-level page: absolute (image-relative) offsets.
    fn regular_page(entries: &[(u32, u32)]) -> Vec<u8> {
        let mut p = Vec::new();
        push_u32(&mut p, SECOND_LEVEL_REGULAR);
        push_u16(&mut p, 8); // entries begin right after this 8-byte header
        push_u16(&mut p, u16::try_from(entries.len()).unwrap());
        for &(f, e) in entries {
            push_u32(&mut p, f);
            push_u32(&mut p, e);
        }
        p
    }

    /// A compressed second-level page: 24-bit relative offset + 8-bit index.
    fn compressed_page(entries: &[(u32, u8)], local_encodings: &[u32]) -> Vec<u8> {
        let header = 12usize;
        let entries_off = header;
        let encodings_off = header + entries.len() * 4;
        let mut p = Vec::new();
        push_u32(&mut p, SECOND_LEVEL_COMPRESSED);
        push_u16(&mut p, u16::try_from(entries_off).unwrap());
        push_u16(&mut p, u16::try_from(entries.len()).unwrap());
        push_u16(&mut p, u16::try_from(encodings_off).unwrap());
        push_u16(&mut p, u16::try_from(local_encodings.len()).unwrap());
        for &(rel, idx) in entries {
            assert!(rel <= 0x00FF_FFFF);
            push_u32(&mut p, (rel & 0x00FF_FFFF) | (u32::from(idx) << 24));
        }
        for &e in local_encodings {
            push_u32(&mut p, e);
        }
        p
    }

    fn uleb(v: &mut Vec<u8>, mut x: u64) {
        loop {
            let mut b = u8::try_from(x & 0x7F).unwrap();
            x >>= 7;
            if x != 0 {
                b |= 0x80;
            }
            v.push(b);
            if x == 0 {
                break;
            }
        }
    }
    fn sleb(v: &mut Vec<u8>, mut x: i64) {
        loop {
            let byte = u8::try_from(x & 0x7F).unwrap();
            x >>= 7;
            let sign_bit = byte & 0x40 != 0;
            let done = (x == 0 && !sign_bit) || (x == -1 && sign_bit);
            v.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
    }

    /// Build an `__eh_frame` with one `zR` CIE and one FDE.
    ///
    /// The FDE's CFI sets `CFA = sp + 16` after the prologue, which is what
    /// a real `stp x29, x30, [sp, #-16]!` produces.
    fn build_eh_frame(section_vmaddr: u64, fn_start: u64, fn_len: u32) -> EhFrameSection {
        // --- CIE ---
        let mut cie_body = Vec::new();
        cie_body.push(1u8); // version
        cie_body.extend_from_slice(b"zR\0"); // augmentation
        uleb(&mut cie_body, 1); // code alignment factor
        sleb(&mut cie_body, -8); // data alignment factor
        uleb(&mut cie_body, 30); // return address register = x30
        uleb(&mut cie_body, 1); // augmentation data length
        cie_body.push(dwarf_cfi::DW_EH_PE_PCREL_SDATA4);
        // Initial instructions: DW_CFA_def_cfa(sp, 0).
        cie_body.push(0x0C);
        uleb(&mut cie_body, u64::from(DWARF_ARM64_SP));
        uleb(&mut cie_body, 0);
        while (cie_body.len() + 8) % 8 != 0 {
            cie_body.push(0x00); // DW_CFA_nop padding
        }

        let mut out = Vec::new();
        // length covers CIE_id + body.
        push_u32(&mut out, u32::try_from(4 + cie_body.len()).unwrap());
        push_u32(&mut out, 0); // CIE_id
        out.extend_from_slice(&cie_body);

        // --- FDE ---
        let cie_len_pos = 0usize;
        let fde_len_pos = out.len();
        let fde_id = u32::try_from(fde_len_pos + 4 - cie_len_pos).unwrap();
        // vaddr of the initial_location field = section vmaddr + its offset.
        let init_loc_vaddr = section_vmaddr + (fde_len_pos as u64) + 8;
        let pcrel = i32::try_from(fn_start.wrapping_sub(init_loc_vaddr).cast_signed()).unwrap();

        let mut fde_body = Vec::new();
        fde_body.extend_from_slice(&pcrel.to_le_bytes());
        fde_body.extend_from_slice(&fn_len.to_le_bytes());
        // Augmentation data length 0 — byte-identical to DW_CFA_nop, which
        // is exactly why dwarf_cfi's "no FDE augmentation" simplification
        // works against real zR output.
        fde_body.push(0x00);
        // DW_CFA_advance_loc(4), then DW_CFA_def_cfa_offset(16).
        fde_body.push(0x40 | 4);
        fde_body.push(0x0E);
        uleb(&mut fde_body, 16);

        push_u32(&mut out, u32::try_from(4 + fde_body.len()).unwrap());
        push_u32(&mut out, fde_id);
        out.extend_from_slice(&fde_body);
        push_u32(&mut out, 0); // terminator

        EhFrameSection::new(out, section_vmaddr)
    }

    /// The same bytes `build_eh_frame` wraps, for embedding into a Mach-O.
    ///
    /// `section_vmaddr` is NOT cosmetic: an FDE stores `initial_location` as
    /// a 32-bit pc-relative delta from its own field, so the bytes only
    /// encode correctly when built for the address the section will occupy.
    fn build_eh_frame_bytes(section_vmaddr: u64, fn_start: u64, fn_len: u32) -> Vec<u8> {
        build_eh_frame(section_vmaddr, fn_start, fn_len).data
    }

    /// File offset at which `build_macho_sections` places `__eh_frame`.
    fn eh_frame_file_offset(unwind_len: usize) -> u64 {
        // header(32) + segment_command_64(72) + 3 * section_64(80) + unwind
        32 + 72 + 80 * 3 + unwind_len as u64
    }

    // -- strip_pac ---------------------------------------------------------

    #[test]
    fn strip_pac_clears_signature_bits_of_user_pointers() {
        let real = 0x0000_0001_0000_4000u64;
        let signed = real | 0x00A5_0000_0000_0000;
        assert_eq!(strip_pac(signed), real);
        assert_eq!(strip_pac(real), real, "identity on an unsigned pointer");
    }

    #[test]
    fn strip_pac_preserves_kernel_addresses() {
        let kernel = 0xFFFF_FF80_0010_0000u64;
        assert_eq!(strip_pac(kernel), kernel);
    }

    // -- frame pointer chain ----------------------------------------------

    #[test]
    fn fp_chain_walks_three_frames() {
        let mem = build_fp_stack(&[
            (STACK_BASE + 0x100, 0x1_0000_1000),
            (STACK_BASE + 0x200, 0x1_0000_2000),
            (STACK_BASE + 0x300, 0x1_0000_3000),
        ]);
        let unw = AppleUnwinder::new();
        let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE + 0x080, STACK_BASE + 0x100, 0);
        let frames = unw.backtrace(regs, &mem);

        assert_eq!(frames.len(), 4, "initial + 3 unwound: {frames:?}");
        assert_eq!(frames[0].provenance, FrameProvenance::Initial);
        assert_eq!(frames[1].regs.pc, 0x1_0000_1000);
        assert_eq!(frames[2].regs.pc, 0x1_0000_2000);
        assert_eq!(frames[3].regs.pc, 0x1_0000_3000);
        assert!(frames[1..].iter().all(|f| f.provenance == FrameProvenance::FramePointerChain));
        // Chain terminates on the null caller-fp, not on max_depth.
        assert!(frames.len() < unw.max_depth);
    }

    #[test]
    fn fp_chain_rejects_unaligned_and_null_frame_pointers() {
        let mem = build_fp_stack(&[(STACK_BASE + 0x100, 0x1_0000_1000)]);
        for bad_fp in [0u64, STACK_BASE + 0x104] {
            let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE, bad_fp, 0);
            let err = unwind_frame_pointer(regs, &mem).unwrap_err();
            assert!(matches!(err, UnwindError::ImplausibleFrame(_)), "{bad_fp:#x} -> {err:?}");
        }
    }

    #[test]
    fn fp_chain_stops_rather_than_looping_on_a_self_referential_frame() {
        let mut mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);
        // A record whose caller-fp points at itself: sp would never grow.
        mem.write_u64(STACK_BASE + 0x100, STACK_BASE + 0x100);
        mem.write_u64(STACK_BASE + 0x108, 0x1_0000_1000);
        let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE, STACK_BASE + 0x100, 0);
        let frames = AppleUnwinder::new().backtrace(regs, &mem);
        assert_eq!(frames.len(), 2, "one real frame then rejection: {frames:?}");
    }

    #[test]
    fn fp_chain_strips_pac_from_the_return_address() {
        let mut mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);
        mem.write_u64(STACK_BASE + 0x100, 0);
        mem.write_u64(STACK_BASE + 0x108, 0x1_0000_1000 | 0x0033_0000_0000_0000);
        let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE, STACK_BASE + 0x100, 0);
        let frames = AppleUnwinder::new().backtrace(regs, &mem);
        assert_eq!(frames[1].regs.pc, 0x1_0000_1000);
    }

    #[test]
    fn unreadable_stack_degrades_instead_of_panicking() {
        let mem = SliceMemory::new(STACK_BASE, vec![0u8; 16]);
        let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE, STACK_BASE + 0x800, 0);
        let frames = AppleUnwinder::new().backtrace(regs, &mem);
        assert_eq!(frames.len(), 1, "only the initial frame survives");
    }

    // -- compact encoding decoding ----------------------------------------

    #[test]
    fn decode_arm64_frame_encoding_and_saved_pairs() {
        let enc = UNWIND_ARM64_MODE_FRAME
            | UNWIND_ARM64_FRAME_X19_X20_PAIR
            | UNWIND_ARM64_FRAME_D8_D9_PAIR;
        let d = Arm64Encoding::decode(enc).unwrap();
        assert_eq!(d, Arm64Encoding::Frame { saved_registers: 0x101 });
        assert!(d.saves_pair(UNWIND_ARM64_FRAME_X19_X20_PAIR));
        assert!(d.saves_pair(UNWIND_ARM64_FRAME_D8_D9_PAIR));
        assert!(!d.saves_pair(UNWIND_ARM64_FRAME_X27_X28_PAIR));
    }

    #[test]
    fn decode_arm64_frameless_stack_size_is_in_16_byte_units() {
        // 3 units == 48 bytes.
        let enc = UNWIND_ARM64_MODE_FRAMELESS | (3 << 12);
        assert_eq!(Arm64Encoding::decode(enc).unwrap(), Arm64Encoding::Frameless { stack_size: 48 });
        // Widest legal field.
        let enc_max = UNWIND_ARM64_MODE_FRAMELESS | UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK;
        assert_eq!(
            Arm64Encoding::decode(enc_max).unwrap(),
            Arm64Encoding::Frameless { stack_size: 0xFFF * 16 }
        );
    }

    #[test]
    fn decode_arm64_dwarf_and_zero_and_reserved() {
        assert_eq!(
            Arm64Encoding::decode(UNWIND_ARM64_MODE_DWARF | 0x1234).unwrap(),
            Arm64Encoding::Dwarf { eh_frame_offset: 0x1234 }
        );
        assert_eq!(Arm64Encoding::decode(0).unwrap(), Arm64Encoding::None);
        // Mode nibble 0x0A is not an arm64 mode: an explicit error, never a
        // silent "no info".
        assert!(matches!(
            Arm64Encoding::decode(0x0A00_0000),
            Err(UnwindError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn x86_64_modes_are_classified_not_silently_misread_as_arm64() {
        assert_eq!(
            X86_64EncodingMode::classify(UNWIND_X86_64_MODE_RBP_FRAME),
            Some(X86_64EncodingMode::RbpFrame)
        );
        assert_eq!(
            X86_64EncodingMode::classify(UNWIND_X86_64_MODE_STACK_IND),
            Some(X86_64EncodingMode::StackIndirect)
        );
        assert_eq!(X86_64EncodingMode::classify(0x0F00_0000), None);
    }

    // -- __unwind_info parsing --------------------------------------------

    #[test]
    fn unwind_info_rejects_wrong_version_and_truncation() {
        let mut good = build_unwind_info(&[], &[(0, regular_page(&[(0, 1)]))], 0x1000);
        assert!(CompactUnwindInfo::parse(&good).is_ok());

        good[0] = 9; // version
        assert!(matches!(
            CompactUnwindInfo::parse(&good),
            Err(UnwindError::UnsupportedUnwindInfoVersion(9))
        ));

        assert!(matches!(CompactUnwindInfo::parse(&[]), Err(UnwindError::Truncated { .. })));
        assert!(matches!(CompactUnwindInfo::parse(&[1, 0, 0, 0]), Err(UnwindError::Truncated { .. })));
    }

    /// Builds a Mach-O whose `__TEXT` segment carries TWO sections named
    /// `__eh_frame`: a decoy whose `segname` field says `__DATA_CONST`,
    /// placed FIRST, and the real `__TEXT,__eh_frame` after it. `segname` is
    /// a per-section field, so this is a shape a linker or a hand-crafted /
    /// hostile image can genuinely produce.
    fn build_macho_with_decoy_eh_frame(
        text_vmaddr: u64,
        decoy_bytes: &[u8],
        real_eh_bytes: &[u8],
    ) -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xFEED_FACF;
        const CPU_TYPE_ARM64: u32 = 0x0100_000C;
        const LC_SEGMENT_64: u32 = 0x19;

        fn n16(name: &str) -> [u8; 16] {
            let mut out = [0u8; 16];
            let b = name.as_bytes();
            out[..b.len()].copy_from_slice(b);
            out
        }

        let nsects: u32 = 3; // __text, decoy __eh_frame, real __eh_frame
        let seg_cmdsize: u32 = 72 + 80 * nsects;
        let header_size: u32 = 32;
        let decoy_off = header_size + seg_cmdsize;
        let real_off = decoy_off + u32::try_from(decoy_bytes.len()).unwrap();
        let text_size = u64::from(real_off) + real_eh_bytes.len() as u64;

        let mut b = Vec::new();
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&n16("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&nsects.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        let mut section = |name: &str, segname: &str, off: u32, len: usize| {
            b.extend_from_slice(&n16(name));
            b.extend_from_slice(&n16(segname));
            b.extend_from_slice(&(text_vmaddr + u64::from(off)).to_le_bytes());
            b.extend_from_slice(&(len as u64).to_le_bytes());
            b.extend_from_slice(&off.to_le_bytes());
            for _ in 0..7 {
                b.extend_from_slice(&0u32.to_le_bytes());
            }
        };
        section("__text", "__TEXT", 0, 64);
        section("__eh_frame", "__DATA_CONST", decoy_off, decoy_bytes.len());
        section("__eh_frame", "__TEXT", real_off, real_eh_bytes.len());

        assert_eq!(b.len(), decoy_off as usize, "load commands must end where the first section starts");
        b.extend_from_slice(decoy_bytes);
        assert_eq!(b.len(), real_off as usize, "the real __eh_frame must start where its offset says");
        b.extend_from_slice(real_eh_bytes);
        b
    }

    /// The `__unwind_info` lookup is qualified by segment
    /// (`sec.segment == "__TEXT" && sec.name == …`) but the `__eh_frame`
    /// lookup was matched on the SECTION NAME ALONE. `segname` is a
    /// per-section field, so a section named `__eh_frame` sitting in another
    /// segment was accepted — and because the search is a plain `find`, the
    /// winner was decided by iteration order, not by correctness.
    ///
    /// This image carries a decoy `__DATA_CONST,__eh_frame` FIRST and the
    /// real `__TEXT,__eh_frame` second. Under the name-only predicate the
    /// decoy wins and every DWARF CFI walk in the image silently resolves
    /// against the wrong bytes: not an error, just wrong frames.
    #[test]
    fn a_decoy_eh_frame_outside_text_does_not_shadow_the_real_one() {
        use crate::{Address, ModuleInfo};

        const LINKED_AT: u64 = 0x1_0000_0000;
        const LOADED_AT: u64 = 0x1_8000_0000;
        const FN_STATIC: u64 = LINKED_AT + 0x40;

        // Decoy content that parses as a section but covers no pc.
        let decoy = vec![0u8; 64];
        // Real FDE, placed after the decoy: header(32) + seg(72) + 3*80 + decoy.
        let real_off = 32 + 72 + 80 * 3 + decoy.len() as u64;
        let real_eh = build_eh_frame_bytes(LINKED_AT + real_off, FN_STATIC, 0x40);
        let image = build_macho_with_decoy_eh_frame(LINKED_AT, &decoy, &real_eh);

        let modules = vec![ModuleInfo {
            is_main: true,
            name: "a.dylib".into(),
            path: "/usr/lib/a.dylib".into(),
            base: Address(LOADED_AT),
            size: image.len() as u64,
            entry_point: None,
        }];
        let images = unwind_images_from_modules(&modules, |addr, len| {
            (addr == LOADED_AT && len == image.len()).then(|| image.clone())
        });
        assert_eq!(images.len(), 1);

        let eh = images[0]
            .eh_frame
            .as_ref()
            .expect("an __eh_frame must still be found");
        let slide = LOADED_AT - LINKED_AT;
        eh.cfa_rule_at(FN_STATIC + slide + 8).expect(
            "the REAL __TEXT,__eh_frame must be the one loaded — a name-only match \
             picks the __DATA_CONST decoy that appears first and resolves nothing",
        );
    }

    /// `eh_frame` stayed `None` even when the image carried a
    /// `__TEXT,__eh_frame`: only the compact table was loaded, so the DWARF
    /// CFI strategy — the fallback for every function the compact table does
    /// not cover — still had nothing to work with.
    ///
    /// The slide matters here in a way it does not for compact unwind: FDEs
    /// are matched against RUNTIME pcs, so the section must be told its slid
    /// address. The image below is linked at one address and loaded at
    /// another, and the assertion is that the rule resolves at the RUNTIME pc.
    #[test]
    fn unwind_images_load_eh_frame_at_its_slid_address() {
        use crate::{Address, ModuleInfo};

        const LINKED_AT: u64 = 0x1_0000_0000;
        const LOADED_AT: u64 = 0x1_8000_0000;
        const FN_STATIC: u64 = LINKED_AT + 0x40;

        let page = regular_page(&[(0x1000, UNWIND_ARM64_MODE_FRAME)]);
        let unwind_bytes = build_unwind_info(&[], &[(0x1000, page)], 0x3000);
        let eh_off = eh_frame_file_offset(unwind_bytes.len());
        let eh_bytes = build_eh_frame_bytes(LINKED_AT + eh_off, FN_STATIC, 0x40);
        let image = build_macho_sections(LINKED_AT, &unwind_bytes, &eh_bytes);

        let modules = vec![ModuleInfo {
            is_main: true,
            name: "a.dylib".into(),
            path: "/usr/lib/a.dylib".into(),
            base: Address(LOADED_AT),
            size: image.len() as u64,
            entry_point: None,
        }];

        let images = unwind_images_from_modules(&modules, |addr, len| {
            (addr == LOADED_AT && len == image.len()).then(|| image.clone())
        });
        assert_eq!(images.len(), 1);

        let eh = images[0]
            .eh_frame
            .as_ref()
            .expect("the __TEXT,__eh_frame section must be found and wrapped");

        let slide = LOADED_AT - LINKED_AT;
        eh.cfa_rule_at(FN_STATIC + slide + 8)
            .expect("the FDE must cover the RUNTIME pc — a missing slide would break this");
        // ...and the un-slid address must NOT resolve, which is what proves
        // the slide was applied rather than the section wrapped at 0.
        assert!(eh.cfa_rule_at(FN_STATIC + 8).is_err());
    }

    /// `AppleUnwinder::new()` starts with no images and nothing ever called
    /// `with_image`, so CompactUnwind and EhFrame — the strategies that matter
    /// on arm64, where most functions have no frame-pointer chain worth
    /// following — could never run against a real target.
    ///
    /// This builds the images the way a live session does: module list in,
    /// Mach-O bytes from an injected reader, parsed tables out.
    #[test]
    fn unwind_images_are_built_from_the_targets_reported_modules() {
        use crate::{Address, ModuleInfo};

        const LOADED_AT: u64 = 0x1_8000_0000;
        let page = regular_page(&[(0x1000, UNWIND_ARM64_MODE_FRAME)]);
        let unwind_bytes = build_unwind_info(&[], &[(0x1000, page)], 0x3000);
        let image = build_macho_with_unwind_info(0x1_0000_0000, &unwind_bytes);

        let modules = vec![
            ModuleInfo {
                is_main: true,
                name: "a.dylib".into(),
                path: "/usr/lib/a.dylib".into(),
                base: Address(LOADED_AT),
                size: image.len() as u64,
                entry_point: None,
            },
            // Unreadable image: skipped, never fatal.
            ModuleInfo {
                is_main: false,
                name: "gone.dylib".into(),
                path: "/usr/lib/gone.dylib".into(),
                base: Address(0x3_0000_0000),
                size: 0x1000,
                entry_point: None,
            },
        ];

        let images = unwind_images_from_modules(&modules, |addr, len| {
            (addr == LOADED_AT && len == image.len()).then(|| image.clone())
        });

        assert_eq!(images.len(), 1, "the unreadable image must be skipped, not fatal");
        let img = &images[0];
        assert_eq!(img.image_base, LOADED_AT);
        assert!(img.contains(LOADED_AT), "the image must claim its own base");
        let compact = img
            .compact
            .as_ref()
            .expect("the __TEXT,__unwind_info section must be found and parsed");
        assert_eq!(
            compact.lookup(0x1000).unwrap().encoding,
            UNWIND_ARM64_MODE_FRAME,
            "the parsed table must be the one the image actually carries"
        );

        // And the unwinder accepts them, which is the whole point.
        let unw = images
            .into_iter()
            .fold(AppleUnwinder::new(), AppleUnwinder::with_image);
        assert!(unw.image_for(LOADED_AT).is_some(), "the unwinder must accept them");
    }

    #[test]
    fn unwind_info_regular_page_lookup() {
        let enc_a = UNWIND_ARM64_MODE_FRAME;
        let enc_b = UNWIND_ARM64_MODE_FRAMELESS | (2 << 12);
        let page = regular_page(&[(0x1000, enc_a), (0x2000, enc_b)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x3000);
        let info = CompactUnwindInfo::parse(&data).unwrap();

        assert_eq!(info.lookup(0x1000).unwrap().encoding, enc_a);
        assert_eq!(info.lookup(0x1FFF).unwrap().encoding, enc_a, "inside the first function");
        assert_eq!(info.lookup(0x2000).unwrap().encoding, enc_b);
        assert_eq!(info.lookup(0x2500).unwrap().function_offset, 0x2000);
        // Before the first entry, and at/after the sentinel.
        assert!(matches!(info.lookup(0x0FFF), Err(UnwindError::NoEntryForPc(_))));
        assert!(matches!(info.lookup(0x3000), Err(UnwindError::NoEntryForPc(_))));
    }

    #[test]
    fn unwind_info_compressed_page_uses_common_and_local_encodings() {
        let common = [UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS | (1 << 12)];
        let local = [UNWIND_ARM64_MODE_DWARF | 0x40];
        // index 0,1 -> common; index 2 -> local[0].
        let page = compressed_page(&[(0, 0), (0x100, 1), (0x200, 2)], &local);
        let data = build_unwind_info(&common, &[(0x8000, page)], 0x9000);
        let info = CompactUnwindInfo::parse(&data).unwrap();

        assert_eq!(info.lookup(0x8000).unwrap().encoding, common[0]);
        assert_eq!(info.lookup(0x80FF).unwrap().encoding, common[0], "still the first entry");
        assert_eq!(info.lookup(0x8100).unwrap().encoding, common[1]);
        let e = info.lookup(0x8200).unwrap();
        assert_eq!(e.encoding, local[0]);
        assert_eq!(e.function_offset, 0x8200, "relative offset rebased onto the index entry");
        assert!(matches!(info.lookup(0x7FFF), Err(UnwindError::NoEntryForPc(_))));
    }

    /// A compressed entry's top byte indexes the common table first and the
    /// page-local table after it. `common_encoding` bounds-checks its half;
    /// the page-local half was not checked against the page's own
    /// `encodingsCount`, so an index past the end read whatever bytes follow
    /// the array and returned them as a valid encoding.
    ///
    /// This page is followed immediately by another second-level page, so the
    /// over-read lands inside it and yields a well-formed-looking `u32`
    /// (`SECOND_LEVEL_REGULAR`) instead of a short read — i.e. the failure
    /// mode is a silently wrong encoding, not a truncation error.
    #[test]
    fn unwind_info_compressed_page_rejects_an_out_of_range_local_encoding_index() {
        let common = [UNWIND_ARM64_MODE_FRAME];
        let local = [UNWIND_ARM64_MODE_DWARF | 0x40];
        // index 0 -> common[0]; index 1 -> local[0]; index 2 -> PAST THE END.
        let bad = compressed_page(&[(0, 2)], &local);
        let next_page = regular_page(&[(0x9000, UNWIND_ARM64_MODE_FRAME)]);
        let data =
            build_unwind_info(&common, &[(0x8000, bad), (0x9000, next_page)], 0xA000);
        let info = CompactUnwindInfo::parse(&data).unwrap();

        let got = info.lookup(0x8000);
        assert!(
            matches!(
                got,
                Err(UnwindError::Truncated { what, .. })
                    if what.contains("encodings")
            ),
            "an encoding index past encodingsCount must be reported, not read \
             from the neighbouring page: {got:?}"
        );

        // The in-range indices must keep working, so the bound is not a blunt
        // rejection of local encodings.
        let ok = compressed_page(&[(0, 1)], &local);
        let data = build_unwind_info(&common, &[(0x8000, ok)], 0x9000);
        let info = CompactUnwindInfo::parse(&data).unwrap();
        assert_eq!(info.lookup(0x8000).unwrap().encoding, local[0]);
    }

    #[test]
    fn unwind_info_unknown_page_kind_is_reported() {
        let mut page = regular_page(&[(0x1000, 1)]);
        page[0] = 7; // kind
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x2000);
        let info = CompactUnwindInfo::parse(&data).unwrap();
        assert!(matches!(info.lookup(0x1000), Err(UnwindError::UnknownSecondLevelKind(7))));
    }

    #[test]
    fn unwind_info_truncated_page_body_never_panics() {
        let page = regular_page(&[(0x1000, 1), (0x2000, 2)]);
        let full = build_unwind_info(&[], &[(0x1000, page)], 0x3000);
        // Chop bytes off the tail one at a time; every prefix must either
        // parse-and-error or fail to parse, but never panic.
        for cut in 1..=24usize.min(full.len()) {
            let truncated = &full[..full.len() - cut];
            if let Ok(info) = CompactUnwindInfo::parse(truncated) {
                let _ = info.lookup(0x1000);
                let _ = info.lookup(0x2000);
                let _ = info.lookup(0xFFFF_FFFF);
            }
        }
    }

    #[test]
    fn unwind_info_fuzz_lite_random_mutations_never_panic() {
        let page = compressed_page(&[(0, 0), (0x100, 1)], &[UNWIND_ARM64_MODE_FRAME]);
        let base = build_unwind_info(&[UNWIND_ARM64_MODE_FRAMELESS | (1 << 12)], &[(0x1000, page)], 0x2000);
        // Deterministic xorshift: a reproducible failure beats a random one.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut d = base.clone();
            let n = (next() % 6) + 1;
            for _ in 0..n {
                let idx = usize::try_from(next() % (d.len() as u64)).unwrap();
                d[idx] = u8::try_from(next() & 0xFF).unwrap();
            }
            if let Ok(info) = CompactUnwindInfo::parse(&d) {
                for probe in [0u32, 0x1000, 0x1100, 0x1FFF, 0x2000, u32::MAX] {
                    let _ = info.lookup(probe);
                }
            }
        }
    }

    // -- compact unwind applied -------------------------------------------

    fn image_with_compact(data: &[u8]) -> ImageUnwindTables {
        ImageUnwindTables {
            image_base: IMAGE_BASE,
            image_end: IMAGE_BASE + 0x10_0000,
            compact: Some(CompactUnwindInfo::parse(data).unwrap()),
            eh_frame: None,
        }
    }

    #[test]
    fn compact_frame_encoding_unwinds_via_the_frame_record() {
        let page = regular_page(&[(0x1000, UNWIND_ARM64_MODE_FRAME)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x2000);
        let unw = AppleUnwinder::new()
            .with_order(UnwindOrder::TablesFirst)
            .with_image(image_with_compact(&data));

        let mem = build_fp_stack(&[(STACK_BASE + 0x100, IMAGE_BASE + 0x1500)]);
        let regs = Arm64UnwindRegs::new(IMAGE_BASE + 0x1010, STACK_BASE, STACK_BASE + 0x100, 0);
        let (next, prov) = unw.step(regs, 1, &mem).unwrap();

        assert_eq!(prov, FrameProvenance::CompactUnwind, "tables must win over fp here");
        assert_eq!(next.pc, IMAGE_BASE + 0x1500);
        assert_eq!(next.sp, STACK_BASE + 0x110);
    }

    /// A return address is looked up as `pc - 1`, not `pc`.
    ///
    /// Beyond the innermost frame, `regs.pc` is a RETURN address: it points at
    /// the instruction after the `bl`. When that `bl` is the last instruction
    /// of its function — a call in tail position, or any function ending in a
    /// call — the return address lands one byte past the function's range, i.e.
    /// inside the NEXT function. Looking it up unadjusted selects that
    /// function's compact encoding and unwinds the caller with the wrong rule,
    /// so every frame from there on is wrong; if it falls past the last
    /// described function, the walk stops early instead.
    ///
    /// libunwind, LLVM and GDB all subtract one for exactly this reason. Only
    /// the lookup key is adjusted — the reported pc stays the real one.
    ///
    /// Iter 320 left a note to check this property first in any third unwinder;
    /// this is that unwinder.
    #[test]
    fn a_return_address_at_a_function_boundary_resolves_to_the_calling_function() {
        // Two adjacent functions: A at 0x1000, B at 0x2000. A ends with a call,
        // so the return address into A is exactly 0x2000 — B's first byte.
        let a_enc = UNWIND_ARM64_MODE_FRAME;
        let b_enc = UNWIND_ARM64_MODE_FRAMELESS | (4 << 12);
        let page = regular_page(&[(0x1000, a_enc), (0x2000, b_enc)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x3000);
        let unw = AppleUnwinder::new()
            .with_order(UnwindOrder::TablesFirst)
            .with_image(image_with_compact(&data));

        // A frame record for A's caller, so the frame-based encoding can step.
        let mut stack = vec![0u8; 0x200];
        let fp = STACK_BASE + 0x80;
        stack[0x80..0x88].copy_from_slice(&(STACK_BASE + 0x100).to_le_bytes());
        stack[0x88..0x90].copy_from_slice(&(IMAGE_BASE + 0x1234).to_le_bytes());
        let mem = SliceMemory::new(STACK_BASE, stack);

        let regs = Arm64UnwindRegs {
            pc: IMAGE_BASE + 0x2000, // return address, one past the end of A
            sp: STACK_BASE + 0x40,
            fp,
            lr: None,
        };

        // Probe the compact strategy directly: `step` would fall back to the
        // frame-pointer chain and hide which entry the table picked.
        //
        // depth >= 2: a return address, so the key is `pc - 1` and lands in A,
        // whose frame-based encoding steps through the frame record.
        let next = unw
            .unwind_compact(regs, 2, &mem)
            .expect("the return address must resolve to A, which has a usable encoding");
        assert_eq!(next.pc, IMAGE_BASE + 0x1234, "stepped through A's frame record");

        // depth 1 is a real pc, so 0x2000 genuinely IS B: its frameless
        // encoding needs a live lr, and there is none here. This is what keeps
        // the fix from degenerating into "always subtract one".
        assert_eq!(
            unw.unwind_compact(regs, 1, &mem).unwrap_err(),
            UnwindError::FramelessWithoutLiveLr(1),
            "an innermost pc must be looked up unadjusted"
        );
    }

    #[test]
    fn compact_frameless_uses_lr_only_at_depth_one() {
        let enc = UNWIND_ARM64_MODE_FRAMELESS | (4 << 12); // 64-byte frame
        let page = regular_page(&[(0x1000, enc)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x2000);
        let unw = AppleUnwinder::new()
            .with_order(UnwindOrder::TablesFirst)
            .with_image(image_with_compact(&data));
        let mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);

        let regs = Arm64UnwindRegs {
            pc: IMAGE_BASE + 0x1004,
            sp: STACK_BASE + 0x40,
            fp: 0, // genuinely frameless: no frame record at all
            lr: Some(IMAGE_BASE + 0x2222),
        };
        let (next, prov) = unw.step(regs, 1, &mem).unwrap();
        assert_eq!(prov, FrameProvenance::CompactUnwind);
        assert_eq!(next.pc, IMAGE_BASE + 0x2222);
        assert_eq!(next.sp, STACK_BASE + 0x80, "sp += 4 * 16");
        assert_eq!(next.lr, None, "lr is no longer known to be live");

        // At depth 2 the same encoding must refuse, not reuse a stale lr.
        let err = unw.step(regs, 2, &mem).unwrap_err();
        let UnwindError::AllStrategiesFailed(fails) = err else { panic!("{err:?}") };
        assert!(
            fails.iter().any(|(p, e)| *p == FrameProvenance::CompactUnwind
                && matches!(e, UnwindError::FramelessWithoutLiveLr(2))),
            "{fails:?}"
        );
    }

    #[test]
    fn compact_dwarf_deferral_without_eh_frame_is_an_explicit_error() {
        let page = regular_page(&[(0x1000, UNWIND_ARM64_MODE_DWARF | 0x99)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x2000);
        let unw = AppleUnwinder::new().with_image(image_with_compact(&data));
        let mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x100]);
        let regs = Arm64UnwindRegs::new(IMAGE_BASE + 0x1000, STACK_BASE, 0, 0);

        let err = unw.unwind_compact(regs, 1, &mem).unwrap_err();
        assert_eq!(err, UnwindError::DwarfDeferralUnavailable(0x99));
    }

    #[test]
    fn compact_zero_encoding_reports_absence_rather_than_guessing() {
        let page = regular_page(&[(0x1000, 0)]);
        let data = build_unwind_info(&[], &[(0x1000, page)], 0x2000);
        let unw = AppleUnwinder::new().with_image(image_with_compact(&data));
        let mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x100]);
        let regs = Arm64UnwindRegs::new(IMAGE_BASE + 0x1000, STACK_BASE, 0, 0);
        assert!(matches!(
            unw.unwind_compact(regs, 1, &mem),
            Err(UnwindError::UnsupportedEncoding(_))
        ));
    }

    // -- __eh_frame --------------------------------------------------------

    const EH_VMADDR: u64 = IMAGE_BASE + 0x8000;
    const EH_FN: u64 = IMAGE_BASE + 0x1000;

    #[test]
    fn eh_frame_recovers_the_cfa_rule() {
        let eh = build_eh_frame(EH_VMADDR, EH_FN, 0x100);
        // Before the prologue advance, CFA is still sp+0.
        let r0 = eh.cfa_rule_at(EH_FN).unwrap();
        assert_eq!(r0, dwarf_cfi::CfaRule { register: DWARF_ARM64_SP, offset: 0 });
        // After it, sp+16.
        let r1 = eh.cfa_rule_at(EH_FN + 0x20).unwrap();
        assert_eq!(r1, dwarf_cfi::CfaRule { register: DWARF_ARM64_SP, offset: 16 });
    }

    #[test]
    fn eh_frame_reports_no_fde_outside_the_covered_range() {
        let eh = build_eh_frame(EH_VMADDR, EH_FN, 0x100);
        assert!(matches!(eh.cfa_rule_at(EH_FN - 1), Err(UnwindError::NoFdeForPc(_))));
        assert!(matches!(eh.cfa_rule_at(EH_FN + 0x100), Err(UnwindError::NoFdeForPc(_))));
    }

    #[test]
    fn eh_frame_unwinds_a_frame_using_the_aapcs64_frame_record() {
        let eh = build_eh_frame(EH_VMADDR, EH_FN, 0x100);
        let image = ImageUnwindTables {
            image_base: IMAGE_BASE,
            image_end: IMAGE_BASE + 0x10_0000,
            compact: None,
            eh_frame: Some(eh),
        };
        let unw = AppleUnwinder::new().with_order(UnwindOrder::TablesFirst).with_image(image);

        // sp = STACK_BASE+0x100 => CFA = +0x110; [CFA-8] = lr, [CFA-16] = fp.
        let mut mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);
        let cfa = STACK_BASE + 0x110;
        mem.write_u64(cfa - 8, IMAGE_BASE + 0x4444);
        mem.write_u64(cfa - 16, STACK_BASE + 0x300);

        let regs = Arm64UnwindRegs::new(EH_FN + 0x20, STACK_BASE + 0x100, 0, 0);
        let (next, prov) = unw.step(regs, 1, &mem).unwrap();
        assert_eq!(prov, FrameProvenance::EhFrame);
        assert_eq!(next.pc, IMAGE_BASE + 0x4444);
        assert_eq!(next.sp, cfa);
        assert_eq!(next.fp, STACK_BASE + 0x300);
    }

    /// `[CFA-16]` holds the CALLER's `x29`. When that word cannot be read the
    /// caller's frame pointer is simply unknown, and substituting the CURRENT
    /// frame's `x29` produces a frame that is not merely incomplete but
    /// actively wrong: the very next step walks the same frame record again
    /// and emits a duplicate frame that passes `validate` (its pc is in an
    /// image, its sp grew), i.e. a plausible-looking backtrace that never
    /// happened.
    ///
    /// The line above reads `[CFA-8]` with `?`. This one must too — the
    /// module's contract is a typed [`UnwindError`], not a guess.
    #[test]
    fn eh_frame_refuses_to_substitute_the_current_fp_when_the_caller_fp_is_unreadable() {
        let eh = build_eh_frame(EH_VMADDR, EH_FN, 0x100);
        let image = ImageUnwindTables {
            image_base: IMAGE_BASE,
            image_end: IMAGE_BASE + 0x10_0000,
            compact: None,
            eh_frame: Some(eh),
        };
        let unw = AppleUnwinder::new().with_order(UnwindOrder::TablesFirst).with_image(image);

        // Map EXACTLY the 8 bytes at [CFA-8]: the return address is readable,
        // the saved caller x29 one word below it is not.
        let cfa = STACK_BASE + 0x110;
        let mut mem = SliceMemory::new(cfa - 8, vec![0u8; 8]);
        mem.write_u64(cfa - 8, IMAGE_BASE + 0x4444);

        let regs = Arm64UnwindRegs {
            pc: EH_FN + 0x20,
            sp: STACK_BASE + 0x100,
            // Aligned and above sp, so it looks entirely plausible — exactly
            // the value that would be silently copied into the caller frame.
            fp: STACK_BASE + 0x200,
            lr: None,
        };

        let err = unw
            .unwind_eh_frame(regs, 1, &mem)
            .expect_err("an unreadable caller x29 must be an error, not the current x29");
        assert!(
            matches!(err, UnwindError::MemoryRead { addr, .. } if addr == cfa - 16),
            "the failure must name the word that could not be read: {err:?}"
        );

        // And the cascade must degrade rather than hand back the bogus frame:
        // fp is unreadable too, so every strategy has to fail.
        let step = unw.step(regs, 1, &mem).unwrap_err();
        let UnwindError::AllStrategiesFailed(fails) = step else { panic!("{step:?}") };
        assert!(
            fails.iter().any(|(p, e)| *p == FrameProvenance::EhFrame
                && matches!(e, UnwindError::MemoryRead { addr, .. } if *addr == cfa - 16)),
            "eh-frame must report why it could not answer: {fails:?}"
        );
    }

    #[test]
    fn eh_frame_corrupt_bytes_never_panic() {
        let good = build_eh_frame(EH_VMADDR, EH_FN, 0x100);
        let bytes = good.data;
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut d = bytes.clone();
            for _ in 0..=(next() % 4) {
                let idx = usize::try_from(next() % (d.len() as u64)).unwrap();
                d[idx] = u8::try_from(next() & 0xFF).unwrap();
            }
            let eh = EhFrameSection::new(d, EH_VMADDR);
            let _ = eh.cfa_rule_at(EH_FN);
            let _ = eh.cfa_rule_at(EH_FN + 0x20);
            let _ = eh.cfa_rule_at(0);
        }
        // Truncation at every length must also be safe.
        for n in 0..bytes.len() {
            let eh = EhFrameSection::new(bytes[..n].to_vec(), EH_VMADDR);
            let _ = eh.cfa_rule_at(EH_FN + 0x20);
        }
    }

    // -- cascade -----------------------------------------------------------

    #[test]
    fn cascade_degrades_from_compact_to_eh_frame_to_fp() {
        // The compact table covers a *different* function, so compact
        // lookup misses; __eh_frame covers the pc; fp is deliberately
        // garbage so only the middle strategy can answer.
        let page = regular_page(&[(0x7000, UNWIND_ARM64_MODE_FRAME)]);
        let data = build_unwind_info(&[], &[(0x7000, page)], 0x7100);
        let image = ImageUnwindTables {
            image_base: IMAGE_BASE,
            image_end: IMAGE_BASE + 0x10_0000,
            compact: Some(CompactUnwindInfo::parse(&data).unwrap()),
            eh_frame: Some(build_eh_frame(EH_VMADDR, EH_FN, 0x100)),
        };
        let unw = AppleUnwinder::new().with_order(UnwindOrder::TablesFirst).with_image(image);

        let mut mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x1000]);
        let cfa = STACK_BASE + 0x110;
        mem.write_u64(cfa - 8, IMAGE_BASE + 0x5555);
        mem.write_u64(cfa - 16, STACK_BASE + 0x400);

        let regs = Arm64UnwindRegs {
            pc: EH_FN + 0x20,
            sp: STACK_BASE + 0x100,
            fp: 0x7, // unaligned and below sp: fp strategy must refuse
            lr: None,
        };
        let (next, prov) = unw.step(regs, 1, &mem).unwrap();
        assert_eq!(prov, FrameProvenance::EhFrame);
        assert_eq!(next.pc, IMAGE_BASE + 0x5555);
    }

    #[test]
    fn all_strategies_failing_reports_every_reason() {
        let unw = AppleUnwinder::new().with_order(UnwindOrder::TablesFirst);
        let mem = SliceMemory::new(STACK_BASE, vec![0u8; 0x100]);
        let regs = Arm64UnwindRegs::new(0xDEAD_0000, STACK_BASE, 0, 0);
        let err = unw.step(regs, 1, &mem).unwrap_err();
        let UnwindError::AllStrategiesFailed(fails) = err else { panic!("{err:?}") };
        assert_eq!(fails.len(), 3, "one reason per strategy: {fails:?}");
        let names: Vec<_> = fails.iter().map(|(p, _)| *p).collect();
        assert!(names.contains(&FrameProvenance::CompactUnwind));
        assert!(names.contains(&FrameProvenance::EhFrame));
        assert!(names.contains(&FrameProvenance::FramePointerChain));
    }

    #[test]
    fn backtrace_honours_max_depth() {
        // A chain long enough to exceed the cap.
        let frames: Vec<_> =
            (1..40u64).map(|i| (STACK_BASE + i * 0x20, 0x1_0000_0000 + i * 0x10)).collect();
        let mem = build_fp_stack(&frames);
        let unw = AppleUnwinder::new().with_max_depth(5);
        let regs = Arm64UnwindRegs::new(0x1_0000_0000, STACK_BASE, STACK_BASE + 0x20, 0);
        assert_eq!(unw.backtrace(regs, &mem).len(), 5);
    }

    #[test]
    fn frames_outside_every_known_image_are_rejected() {
        let mem = build_fp_stack(&[(STACK_BASE + 0x100, 0xBADD_0000_0000)]);
        let image = ImageUnwindTables {
            image_base: IMAGE_BASE,
            image_end: IMAGE_BASE + 0x1000,
            compact: None,
            eh_frame: None,
        };
        let unw = AppleUnwinder::new().with_image(image);
        let regs = Arm64UnwindRegs::new(IMAGE_BASE + 0x10, STACK_BASE, STACK_BASE + 0x100, 0);
        let frames = unw.backtrace(regs, &mem);
        assert_eq!(frames.len(), 1, "the out-of-image return address is not reported");
    }

    // -- interop -----------------------------------------------------------

    #[test]
    fn register_set_bridge_prefers_tagged_fields_then_named_ones() {
        let mut rs = crate::RegisterSet::new();
        rs.pc = 0x1000;
        rs.sp = 0x2000;
        rs.set("x29", 0x3000);
        rs.set("x30", 0x4000);
        let r = Arm64UnwindRegs::from(&rs);
        assert_eq!((r.pc, r.sp, r.fp, r.lr), (0x1000, 0x2000, 0x3000, Some(0x4000)));

        rs.fp = Some(0x9000);
        rs.lr = Some(0xA000);
        let r2 = Arm64UnwindRegs::from(&rs);
        assert_eq!((r2.fp, r2.lr), (0x9000, Some(0xA000)));
    }

    #[test]
    fn frames_convert_to_hub_stack_frames() {
        let f = UnwindFrame {
            index: 3,
            regs: Arm64UnwindRegs::new(0x1000, 0x2000, 0x3000, 0x4000),
            provenance: FrameProvenance::EhFrame,
        };
        let sf = f.to_stack_frame();
        assert_eq!(sf.index, 3);
        assert_eq!(sf.pc.as_u64(), 0x1000);
        assert_eq!(sf.fp.map(rustre_core::address::Address::as_u64), Some(0x3000));
        assert!(sf.function_name.is_none(), "this crate never invents symbol names");
        assert_eq!(f.provenance.to_string(), "eh-frame");
    }
}
