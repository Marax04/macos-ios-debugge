//! Address → (module, symbol, offset) symbolication for Apple images.
//!
//! Why this module exists in this shape:
//!
//! * The workspace already owns exactly one real Mach-O container parser
//!   (`rustre_loader_macho`). Everything here is a *consumer* of it; no nlist
//!   or segment decoding is re-derived. A fourth Mach-O parser was an explicit
//!   non-goal. The single exception is the 64-bit universal header
//!   (`FAT_MAGIC_64`), whose 32-byte `fat_arch_64` records that parser does not
//!   know: only the slice table is read here, and every slice is still handed
//!   to the shared thin parser.
//! * A debugger sees **runtime** addresses, a Mach-O file describes **static**
//!   ones. The single invariant that connects them is
//!   `static_addr + slide == runtime_addr`, so the slide is a first-class field
//!   of [`ImageSymbols`] rather than something callers are expected to subtract
//!   themselves at every call site.
//! * The *provenance* of a resolution ([`Symbolication`]) is part of the return
//!   type, not a log line. A name recovered from `LC_FUNCTION_STARTS` is a
//!   synthetic `sub_…` with a trustworthy boundary; a name from the symbol
//!   table is a real name. Callers that cannot tell those apart end up
//!   confidently wrong, which this repository punishes.
//! * Everything is byte-slice driven and therefore compiles and unit-tests on
//!   Windows. No `cfg(target_os = "macos")` anywhere.
//!
//! Deliberate limitations, surfaced as typed errors rather than empty results:
//! DWARF/dSYM line information is *not* consulted here (that is
//! `symbols/resolver.rs`'s job); this module answers from `LC_SYMTAB` and
//! `LC_FUNCTION_STARTS` only.

use rustre_demangle::ObjCDemangler;
use rustre_demangle::swift_demangler::{SwiftDemangler, swift_demangle};
use rustre_loader_macho::{
    MachoArch, MachoInfo, MachoLoadCommandEnum, MachoParser, MachoSymbolType, UniversalBinaryEntry,
};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failure modes of the symbolication engine.
///
/// Each variant names a *distinct* defect on purpose: "no arm64 slice" and
/// "malformed Mach-O" demand different fixes from the caller, and collapsing
/// them into one string would hide that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SymbolicationError {
    /// The container could not be parsed as a Mach-O image at all.
    #[error("mach-o parse failed: {0}")]
    Macho(String),

    /// A fat/universal binary was supplied but holds no slice for the requested
    /// architecture. Both sides are reported so the caller can retry with an
    /// architecture that is actually present.
    #[error("no {requested} slice in universal binary (available: {available})")]
    NoSliceForArch {
        /// Architecture that was asked for.
        requested: &'static str,
        /// Comma-separated list of architectures actually present.
        available: String,
    },

    /// A fat header was present but contained zero usable slices.
    #[error("universal binary contains no usable slices")]
    EmptyUniversalBinary,

    /// The image has no `__TEXT` segment, so it has no code range to anchor
    /// slide arithmetic or containment checks on.
    #[error("image has no __TEXT segment")]
    NoTextSegment,

    /// Big-endian (PPC) images are out of scope. Reported explicitly instead of
    /// silently producing garbage addresses.
    #[error("big-endian mach-o (PowerPC) is not supported by the apple debugger")]
    BigEndianUnsupported,
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture selection
// ─────────────────────────────────────────────────────────────────────────────

/// Which slice of a universal binary to symbolicate against.
///
/// The default is [`ArchPreference::Arm64`]: every current Apple platform ships
/// arm64, and `MachoParser::select_best_slice` prefers `x86_64`, which is the
/// wrong answer for a debugger attached to an Apple-silicon process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArchPreference {
    /// Require an arm64 (or arm64e) slice.
    #[default]
    Arm64,
    /// Require an `x86_64` slice.
    X86_64,
    /// Take whichever slice the container lists first.
    First,
}

impl ArchPreference {
    const fn wanted(self) -> Option<MachoArch> {
        match self {
            Self::Arm64 => Some(MachoArch::Arm64),
            Self::X86_64 => Some(MachoArch::X86_64),
            Self::First => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X86_64 => "x86_64",
            Self::First => "any",
        }
    }
}

/// Pick the slice of a universal binary matching `pref`.
///
/// Returned by reference so the caller keeps ownership of the entry list; the
/// slice bytes are already owned by the entry.
fn select_slice(
    entries: &[UniversalBinaryEntry],
    pref: ArchPreference,
) -> Result<&UniversalBinaryEntry, SymbolicationError> {
    if entries.is_empty() {
        return Err(SymbolicationError::EmptyUniversalBinary);
    }
    match pref.wanted() {
        None => Ok(&entries[0]),
        Some(want) => entries.iter().find(|e| e.arch == want).ok_or_else(|| {
            let available = entries
                .iter()
                .map(|e| e.arch.name())
                .collect::<Vec<_>>()
                .join(", ");
            SymbolicationError::NoSliceForArch {
                requested: pref.label(),
                available,
            }
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

/// Where a resolved name came from — i.e. how much it can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbolication {
    /// Name came from an `LC_SYMTAB` nlist entry.
    Nlist,
    /// No name existed; the boundary came from `LC_FUNCTION_STARTS` and the
    /// name is synthetic (`sub_<addr>`).
    FunctionStart,
    /// The address fell inside a known image but no symbol or function start
    /// covered it; only the module and its offset are meaningful.
    ModuleOnly,
}

/// One resolved runtime address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddress {
    /// Module (image) name this address belongs to.
    pub module: String,
    /// Raw, possibly mangled symbol name.
    pub symbol: String,
    /// Human-readable name when the raw one was Swift/ObjC/C mangled.
    pub demangled: Option<String>,
    /// Byte offset from the start of `symbol`.
    pub offset: u64,
    /// Runtime address of the symbol itself (`symbol_static + slide`).
    pub symbol_address: u64,
    /// How the name was recovered.
    pub source: Symbolication,
}

impl ResolvedAddress {
    /// Best display name: the demangled form when available, else the raw one.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.symbol)
    }
}

/// The `LC_SYMTAB` command as it appeared in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymtabCommand {
    /// File offset of the nlist array.
    pub symoff: u32,
    /// Number of nlist entries.
    pub nsyms: u32,
    /// File offset of the string table.
    pub stroff: u32,
    /// Byte size of the string table.
    pub strsize: u32,
}

/// The subset of `LC_DYSYMTAB` that matters for symbolication: which ranges of
/// the symbol table are local, externally defined, and undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DysymtabCommand {
    /// Index of the first local symbol.
    pub ilocalsym: u32,
    /// Count of local symbols.
    pub nlocalsym: u32,
    /// Index of the first externally-defined symbol.
    pub iextdefsym: u32,
    /// Count of externally-defined symbols.
    pub nextdefsym: u32,
    /// Index of the first undefined symbol.
    pub iundefsym: u32,
    /// Count of undefined symbols.
    pub nundefsym: u32,
}

/// A single symbol retained for address lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolEntry {
    /// Raw name as stored in the string table (leading `_` included).
    pub name: String,
    /// Static virtual address (pre-slide).
    pub static_address: u64,
    /// `true` when the `N_EXT` bit was set.
    pub is_external: bool,
}

/// A loaded image's static symbol data plus its runtime slide.
#[derive(Debug, Clone)]
pub struct ImageSymbols {
    name: String,
    arch: MachoArch,
    uuid: Option<[u8; 16]>,
    slide: u64,
    /// Segments as `(name, static vm_addr, vm_size)`.
    segments: Vec<(String, u64, u64)>,
    /// Sorted, de-duplicated, address-bearing symbols.
    symbols: Vec<SymbolEntry>,
    /// Sorted `LC_FUNCTION_STARTS` addresses (static).
    function_starts: Vec<u64>,
    symtab: Option<SymtabCommand>,
    dysymtab: Option<DysymtabCommand>,
}

impl ImageSymbols {
    /// Parse `bytes` (thin or fat Mach-O) and build a symbol index for it.
    ///
    /// `name` is the module name reported in [`ResolvedAddress::module`] — for a
    /// real target this is the dyld install name or file basename.
    pub fn from_bytes(
        name: impl Into<String>,
        bytes: &[u8],
        pref: ArchPreference,
    ) -> Result<Self, SymbolicationError> {
        // Fat containers must have their slice chosen *before* parsing: the
        // "best" slice according to the loader is x86_64-first, which is the
        // wrong default for an Apple-silicon debug session.
        let thin_owned;
        let thin: &[u8] = if is_fat(bytes) {
            let entries =
                MachoParser::parse_fat(bytes).map_err(|e| SymbolicationError::Macho(e.to_string()))?;
            thin_owned = select_slice(&entries, pref)?.data.clone();
            &thin_owned
        } else if is_fat64(bytes) {
            let entries = parse_fat64(bytes);
            thin_owned = select_slice(&entries, pref)?.data.clone();
            &thin_owned
        } else {
            bytes
        };

        if is_big_endian_macho(thin) {
            return Err(SymbolicationError::BigEndianUnsupported);
        }

        let info =
            MachoParser::parse_single(thin).map_err(|e| SymbolicationError::Macho(e.to_string()))?;
        let mut img = Self::from_info(name, &info)?;
        // `MachoInfo` keeps the *decoded* symbols but not the raw `LC_SYMTAB`
        // offsets, and a debugger that wants to re-read the table out of live
        // target memory needs them — so they are recovered from the raw slice.
        let (symtab, dysymtab) = parse_symtab_commands(thin);
        img.symtab = symtab;
        img.dysymtab = dysymtab;
        Ok(img)
    }

    /// Build an index from an already-parsed thin image.
    ///
    /// [`Self::symtab`] and [`Self::dysymtab`] stay `None` on this path:
    /// `MachoInfo` does not retain the raw command offsets, and inventing them
    /// would be worse than reporting their absence. Use [`Self::from_bytes`]
    /// when those offsets matter.
    pub fn from_info(
        name: impl Into<String>,
        info: &MachoInfo,
    ) -> Result<Self, SymbolicationError> {
        if info.text_segment().is_none() {
            return Err(SymbolicationError::NoTextSegment);
        }

        // Only symbols that name an address are useful for lookup:
        //  - stabs (`is_debug`) carry debug-map data, not code addresses;
        //  - undefined symbols live in another image entirely;
        //  - value 0 in a PIE image is the Mach-O header, never a function.
        let mut symbols: Vec<SymbolEntry> = info
            .symbols
            .iter()
            .filter(|s| {
                !s.is_debug
                    && !s.is_undefined
                    && s.sym_type == MachoSymbolType::Section
                    && s.value != 0
                    && !s.name.is_empty()
            })
            .map(|s| SymbolEntry {
                name: s.name.clone(),
                static_address: s.value,
                is_external: s.is_external,
            })
            .collect();

        // Sort by address; on ties prefer the external symbol, because the
        // public name is the one a user recognises (`_malloc` over a local
        // alias at the same address).
        symbols.sort_by(|a, b| {
            a.static_address
                .cmp(&b.static_address)
                .then_with(|| b.is_external.cmp(&a.is_external))
        });
        symbols.dedup_by_key(|s| s.static_address);

        let mut function_starts = info.function_starts.clone();
        function_starts.sort_unstable();
        function_starts.dedup();

        let segments = info
            .segments
            .iter()
            // __PAGEZERO is a guard mapping, never contains code or data.
            .filter(|s| s.name != "__PAGEZERO" && s.vm_size != 0)
            .map(|s| (s.name.clone(), s.vm_addr, s.vm_size))
            .collect();

        Ok(Self {
            name: name.into(),
            arch: info.arch,
            uuid: info.uuid,
            slide: 0,
            segments,
            symbols,
            function_starts,
            symtab: None,
            dysymtab: None,
        })
    }

    /// Set the ASLR slide reported by the target (`static + slide == runtime`).
    #[must_use]
    pub const fn with_slide(mut self, slide: u64) -> Self {
        self.slide = slide;
        self
    }

    /// Derive and set the slide from an observed runtime load address of the
    /// image's first mapped segment (typically `__TEXT`).
    ///
    /// Returns `None` when the image has no mapped segment to anchor against,
    /// rather than silently assuming a zero slide.
    #[must_use]
    pub fn with_runtime_base(mut self, runtime_base: u64) -> Option<Self> {
        let static_base = self.preferred_base()?;
        self.slide = runtime_base.wrapping_sub(static_base);
        Some(self)
    }

    /// Module name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Architecture of the slice this index was built from.
    #[must_use]
    pub const fn arch(&self) -> MachoArch {
        self.arch
    }

    /// `LC_UUID` value, used to match a dSYM to this image.
    #[must_use]
    pub const fn uuid(&self) -> Option<[u8; 16]> {
        self.uuid
    }

    /// Current ASLR slide.
    #[must_use]
    pub const fn slide(&self) -> u64 {
        self.slide
    }

    /// Parsed `LC_SYMTAB`, if the image had one.
    #[must_use]
    pub const fn symtab(&self) -> Option<SymtabCommand> {
        self.symtab
    }

    /// Parsed `LC_DYSYMTAB`, if the image had one.
    #[must_use]
    pub const fn dysymtab(&self) -> Option<DysymtabCommand> {
        self.dysymtab
    }

    /// Number of address-bearing symbols retained.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Address-sorted view of the retained symbols.
    #[must_use]
    pub fn symbols(&self) -> &[SymbolEntry] {
        &self.symbols
    }

    /// Lowest static virtual address among mapped segments.
    #[must_use]
    pub fn preferred_base(&self) -> Option<u64> {
        self.segments.iter().map(|(_, addr, _)| *addr).min()
    }

    /// `true` when `runtime_addr` falls inside one of this image's segments.
    #[must_use]
    pub fn contains(&self, runtime_addr: u64) -> bool {
        self.static_of(runtime_addr)
            .is_some_and(|s| self.segment_containing(s).is_some())
    }

    /// Convert a runtime address to the image's static address space.
    ///
    /// `None` when the address is below the slide, which cannot belong here.
    #[must_use]
    pub const fn static_of(&self, runtime_addr: u64) -> Option<u64> {
        runtime_addr.checked_sub(self.slide)
    }

    /// Convert a static address to the runtime address space.
    #[must_use]
    pub const fn runtime_of(&self, static_addr: u64) -> u64 {
        static_addr.wrapping_add(self.slide)
    }

    fn segment_containing(&self, static_addr: u64) -> Option<&(String, u64, u64)> {
        self.segments
            .iter()
            .find(|(_, addr, size)| static_addr >= *addr && static_addr < addr.saturating_add(*size))
    }

    /// Exclusive end of the segment that contains `static_addr`.
    ///
    /// `None` when the address is in no mapped segment — which for a *symbol*
    /// means the symbol cannot legitimately cover anything, so callers stop
    /// trusting it rather than falling back to a wider bound.
    fn segment_end_of(&self, static_addr: u64) -> Option<u64> {
        self.segment_containing(static_addr)
            .map(|(_, addr, size)| addr.saturating_add(*size))
    }

    /// Resolve a runtime address inside this image.
    ///
    /// Cascade, most trustworthy first: symbol table → function starts →
    /// module-only. The chosen rung is reported in
    /// [`ResolvedAddress::source`]; a synthetic `sub_…` must never be mistaken
    /// for a real name.
    #[must_use]
    pub fn resolve(&self, runtime_addr: u64) -> Option<ResolvedAddress> {
        let static_addr = self.static_of(runtime_addr)?;
        // Containment in *some* mapped segment is what makes the address ours.
        self.segment_containing(static_addr)?;

        if let Some(idx) = index_of_last_le(
            self.symbols.len(),
            static_addr,
            |i| self.symbols[i].static_address,
        ) {
            let sym = &self.symbols[idx];
            // A symbol only covers up to the next symbol, or the end of the
            // segment **the symbol itself** lives in — whichever comes first.
            //
            // The bound must come from the symbol's segment, not the queried
            // address's: an address past every symbol has no successor to cap
            // it, so bounding by the queried address's segment lets the last
            // symbol of `__TEXT` claim a `__DATA` address thousands of bytes
            // beyond the end of its own segment.
            if let Some(sym_seg_end) = self.segment_end_of(sym.static_address) {
                let next = self
                    .symbols
                    .get(idx + 1)
                    .map_or(sym_seg_end, |s| s.static_address.min(sym_seg_end));
                if static_addr < next {
                    return Some(ResolvedAddress {
                        module: self.name.clone(),
                        symbol: sym.name.clone(),
                        demangled: demangle_symbol(&sym.name),
                        offset: static_addr - sym.static_address,
                        symbol_address: self.runtime_of(sym.static_address),
                        source: Symbolication::Nlist,
                    });
                }
            }
        }

        if let Some(idx) = index_of_last_le(self.function_starts.len(), static_addr, |i| {
            self.function_starts[i]
        }) {
            let start = self.function_starts[idx];
            // Same rule for a synthetic boundary: it ends with the segment the
            // function start lies in, never with the segment being queried.
            let fn_seg_end = self.segment_end_of(start);
            let next = fn_seg_end.map_or(start, |end| {
                self.function_starts
                    .get(idx + 1)
                    .map_or(end, |a| (*a).min(end))
            });
            if static_addr < next {
                let runtime_start = self.runtime_of(start);
                return Some(ResolvedAddress {
                    module: self.name.clone(),
                    symbol: format!("sub_{runtime_start:x}"),
                    demangled: None,
                    offset: static_addr - start,
                    symbol_address: runtime_start,
                    source: Symbolication::FunctionStart,
                });
            }
        }

        let base = self.preferred_base()?;
        Some(ResolvedAddress {
            module: self.name.clone(),
            symbol: self.name.clone(),
            demangled: None,
            offset: static_addr.saturating_sub(base),
            symbol_address: self.runtime_of(base),
            source: Symbolication::ModuleOnly,
        })
    }

    /// Look up a symbol by exact name, trying the C convention (`_name`) too.
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<&SymbolEntry> {
        let underscored = format!("_{name}");
        self.symbols
            .iter()
            .find(|s| s.name == name || s.name == underscored)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-image engine
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolicates addresses across every image loaded in a target.
#[derive(Debug, Clone, Default)]
pub struct Symbolicator {
    images: Vec<ImageSymbols>,
}

/// Build a [`Symbolicator`] from the images a live target reports.
///
/// `read(addr, len)` fetches bytes from the target; returning `None` for an
/// image simply skips it. Kept as a pure function over an injected reader so
/// the logic is testable on any host — the debugger passes an RSP-backed
/// closure, tests pass synthetic Mach-O bytes.
///
/// Every step degrades to "skip this image" rather than failing the whole
/// build: one stripped or unreadable dylib must not cost you the symbols of
/// every other image. An image whose static base cannot be determined is
/// skipped too, because [`ImageSymbols::with_runtime_base`] refuses to guess
/// a zero slide — a wrong slide resolves every address to the wrong symbol,
/// which is worse than no name at all.
pub fn symbolicator_from_modules<R>(modules: &[crate::ModuleInfo], read: R) -> Symbolicator
where
    R: Fn(u64, usize) -> Option<Vec<u8>>,
{
    let mut engine = Symbolicator::new();
    for m in modules {
        let base = m.base.as_u64();
        let Ok(len) = usize::try_from(m.size) else { continue };
        if len == 0 {
            continue;
        }
        let Some(bytes) = read(base, len) else { continue };
        let Ok(image) = ImageSymbols::from_bytes(m.name.clone(), &bytes, ArchPreference::Arm64)
        else {
            continue;
        };
        let Some(image) = image.with_runtime_base(base) else { continue };
        engine.add_image(image);
    }
    engine
}

/// Plug the Apple symbolicator into the generic frame-enrichment path.
///
/// `backtrace()` enriches its frames through
/// [`crate::symbol_resolver::FrameSymbolResolver`], but only `CodeViewProvider`
/// (Windows PDB) and `SourceMap` (DWARF) implemented it. This engine — Mach-O
/// symbol tables, ASLR slide handling, fat-binary slices, Swift/ObjC
/// demangling — therefore could not be handed to
/// [`crate::Debugger::set_symbol_resolver`] at all: a caller who built one
/// simply had nowhere to put it, and every Apple backtrace came back with
/// `function_name: None`.
///
/// `file`/`line` stay `None` on purpose: a Mach-O symbol table carries names
/// and addresses, not source coordinates. Those come from a `.dSYM` through
/// the DWARF path, and inventing them here would be worse than absent.
impl crate::symbol_resolver::FrameSymbolResolver for Symbolicator {
    fn resolve_frame(&self, pc: u64) -> Option<crate::symbol_resolver::ResolvedFrameSymbol> {
        let resolved = self.resolve(pc)?;
        Some(crate::symbol_resolver::ResolvedFrameSymbol {
            function: Some(resolved.display_name().to_string()),
            file: None,
            line: None,
            // `Symbolicator::resolve` bounds every match by the next symbol or
            // the end of the segment, whichever comes first, so a hit here is
            // real containment rather than nearest-preceding.
            bounded: true,
            // The symbol table knows where each symbol starts, so the frame can
            // be rendered as `func+0x1c` instead of just `func`.
            start: Some(resolved.symbol_address),
        })
    }
}

impl Symbolicator {
    /// Empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self { images: Vec::new() }
    }

    /// Register an image (already carrying its slide).
    pub fn add_image(&mut self, image: ImageSymbols) {
        self.images.push(image);
    }

    /// Number of registered images.
    #[must_use]
    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Registered images.
    #[must_use]
    pub fn images(&self) -> &[ImageSymbols] {
        &self.images
    }

    /// Image whose mapped range covers `runtime_addr`.
    #[must_use]
    pub fn image_for(&self, runtime_addr: u64) -> Option<&ImageSymbols> {
        self.images.iter().find(|i| i.contains(runtime_addr))
    }

    /// Resolve one runtime address across all registered images.
    #[must_use]
    pub fn resolve(&self, runtime_addr: u64) -> Option<ResolvedAddress> {
        self.image_for(runtime_addr)
            .and_then(|i| i.resolve(runtime_addr))
    }

    /// Resolve a whole backtrace. Positions with no owning image stay `None`
    /// rather than being dropped, so frame indices are preserved.
    #[must_use]
    pub fn resolve_all(&self, addrs: &[u64]) -> Vec<Option<ResolvedAddress>> {
        addrs.iter().map(|a| self.resolve(*a)).collect()
    }

    /// Find an image by its `LC_UUID` — the only correct way to pair an image
    /// with a debug bundle.
    #[must_use]
    pub fn image_by_uuid(&self, uuid: [u8; 16]) -> Option<&ImageSymbols> {
        self.images.iter().find(|i| i.uuid == Some(uuid))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_CIGAM: u32 = 0xBEBA_FECA;
/// 64-bit universal header. On disk the bytes are `CA FE BA BF`; read
/// little-endian (as [`magic_of`] does) that is [`FAT_CIGAM_64`], so both
/// spellings are accepted exactly as for the 32-bit pair above.
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
const FAT_CIGAM_64: u32 = 0xBFBA_FECA;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;

/// Size of one `fat_arch_64` record: cputype, cpusubtype, offset(u64),
/// size(u64), align, reserved.
const FAT_ARCH_64_SIZE: usize = 32;

fn magic_of(bytes: &[u8]) -> Option<u32> {
    bytes
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn is_fat(bytes: &[u8]) -> bool {
    matches!(magic_of(bytes), Some(FAT_MAGIC | FAT_CIGAM))
}

/// `true` for a 64-bit universal container (`FAT_MAGIC_64`).
///
/// `lipo` emits this form once a slice offset or size no longer fits in the
/// 32-bit `fat_arch` fields, and Apple ships such containers.
fn is_fat64(bytes: &[u8]) -> bool {
    matches!(magic_of(bytes), Some(FAT_MAGIC_64 | FAT_CIGAM_64))
}

/// Decode the slice table of a 64-bit universal container.
///
/// This is the one place the module does decode a Mach-O structure itself, and
/// only because it must: `MachoParser::parse_fat` walks 20-byte `fat_arch`
/// records, while a `FAT_MAGIC_64` container stores 32-byte `fat_arch_64`
/// records with 64-bit `offset`/`size`. Nothing below the fat header is
/// touched — every slice is still handed to the shared thin parser, so this
/// does not become a second Mach-O implementation.
///
/// Every field of a fat header is big-endian regardless of slice endianness.
/// Slices whose extent escapes the buffer are skipped rather than truncated,
/// and an empty result is reported by [`select_slice`] as
/// [`SymbolicationError::EmptyUniversalBinary`].
fn parse_fat64(bytes: &[u8]) -> Vec<UniversalBinaryEntry> {
    let nfat = bytes
        .get(4..8)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
    // Cap by what the buffer can actually hold: nfat is attacker-controlled.
    let nfat = nfat.min(bytes.len().saturating_sub(8) / FAT_ARCH_64_SIZE);

    let mut entries = Vec::with_capacity(nfat);
    for i in 0..nfat {
        let base = 8 + i * FAT_ARCH_64_SIZE;
        let Some(rec) = bytes.get(base..base + FAT_ARCH_64_SIZE) else {
            break;
        };
        let be32 = |o: usize| u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
        let be64 = |o: usize| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&rec[o..o + 8]);
            u64::from_be_bytes(v)
        };

        let cputype = be32(0);
        let offset = be64(8);
        let size = be64(16);
        let align = be32(24);

        let (Ok(start), Ok(len)) = (usize::try_from(offset), usize::try_from(size)) else {
            continue;
        };
        let end = start.saturating_add(len);
        if end > bytes.len() {
            continue;
        }

        entries.push(UniversalBinaryEntry {
            arch: MachoArch::from_cputype(cputype),
            // `UniversalBinaryEntry` carries 32-bit offset/size fields; a slice
            // that genuinely exceeds them is reported saturated rather than
            // wrapped, and `data` below is always the exact bytes.
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
            size: u32::try_from(size).unwrap_or(u32::MAX),
            align,
            data: bytes[start..end].to_vec(),
        });
    }
    entries
}

/// A byte-swapped Mach-O magic means the header is big-endian relative to us,
/// i.e. a PowerPC image. Detected here so the caller gets
/// [`SymbolicationError::BigEndianUnsupported`] instead of nonsense addresses.
fn is_big_endian_macho(bytes: &[u8]) -> bool {
    matches!(magic_of(bytes), Some(MH_CIGAM | MH_CIGAM_64))
}

/// Binary search for the greatest index whose key is `<= target`.
///
/// Generic over an accessor so the same routine serves both the symbol array
/// and the function-starts array without cloning either into a common shape.
fn index_of_last_le(len: usize, target: u64, key: impl Fn(usize) -> u64) -> Option<usize> {
    if len == 0 || key(0) > target {
        return None;
    }
    let (mut lo, mut hi) = (0usize, len - 1);
    while lo < hi {
        let mid = hi - (hi - lo) / 2; // upper mid: converges on the last match
        if key(mid) <= target { lo = mid; } else { hi = mid - 1; }
    }
    Some(lo)
}

/// Re-decode `LC_SYMTAB` / `LC_DYSYMTAB` from a thin Mach-O slice.
///
/// The strongly-typed `MachoLoadCommandEnum` walker is reused rather than
/// re-implementing load-command iteration here.
fn parse_symtab_commands(bytes: &[u8]) -> (Option<SymtabCommand>, Option<DysymtabCommand>) {
    let is_64 = matches!(magic_of(bytes), Some(MH_MAGIC_64));
    let hdr_size = if is_64 { 32 } else { 28 };
    let Some(ncmds) = bytes
        .get(16..20)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    else {
        return (None, None);
    };

    let mut symtab = None;
    let mut dysymtab = None;
    for lc in MachoLoadCommandEnum::parse_all(bytes, hdr_size, ncmds, false) {
        match lc {
            MachoLoadCommandEnum::Symtab {
                symoff,
                nsyms,
                stroff,
                strsize,
            } => {
                symtab = Some(SymtabCommand {
                    symoff,
                    nsyms,
                    stroff,
                    strsize,
                });
            }
            MachoLoadCommandEnum::Dysymtab {
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                ..
            } => {
                dysymtab = Some(DysymtabCommand {
                    ilocalsym,
                    nlocalsym,
                    iextdefsym,
                    nextdefsym,
                    iundefsym,
                    nundefsym,
                });
            }
            _ => {}
        }
    }
    (symtab, dysymtab)
}

/// Demangle a Mach-O symbol name, delegating to the workspace demanglers.
///
/// Returns `None` when the name is already human-readable, so callers can tell
/// "not mangled" from "demangling failed" instead of comparing strings.
#[must_use]
pub fn demangle_symbol(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }

    // ObjC method names (`-[NSObject init]`) are not mangled in the C sense,
    // but they are the form users search for, so normalise them first.
    if ObjCDemangler::detect(raw) {
        return ObjCDemangler::demangle(raw);
    }

    // Mach-O prefixes every C symbol with `_`; Swift's own prefix is `$s`, so
    // the linker-level name is `_$s…`. Strip exactly one leading underscore
    // before asking the Swift demangler.
    let stripped = raw.strip_prefix('_').unwrap_or(raw);
    if SwiftDemangler::detect(stripped) {
        let out = swift_demangle(stripped);
        if out != stripped && !out.is_empty() {
            return Some(out);
        }
    }

    // A plain C symbol: the only "demangling" is dropping the underscore, and
    // that is only worth reporting when it actually changed something.
    if stripped != raw && !stripped.is_empty() {
        return Some(stripped.to_string());
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — every fixture is a hand-built Mach-O byte buffer, so they run on
// Windows with no Apple artifact present.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000C;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x02;
    const LC_DYSYMTAB: u32 = 0x0B;
    const LC_UUID: u32 = 0x1B;
    const N_SECT: u8 = 0x0E;
    const N_EXT: u8 = 0x01;

    /// One symbol to place into the synthetic image.
    struct Sym {
        name: &'static str,
        value: u64,
        external: bool,
    }

    fn seg_name(name: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let b = name.as_bytes();
        out[..b.len()].copy_from_slice(b);
        out
    }

    /// Build a minimal but *valid* 64-bit Mach-O with one `__TEXT` segment
    /// (containing a `__text` section), an `LC_SYMTAB`, an `LC_DYSYMTAB` and an
    /// `LC_UUID`.
    fn build_macho64(cputype: u32, text_vmaddr: u64, text_size: u64, syms: &[Sym]) -> Vec<u8> {
        // ── string table ────────────────────────────────────────────────────
        // Index 0 must be a NUL so strx==0 means "no name".
        let mut strtab = vec![0u8];
        let mut strx = Vec::new();
        for s in syms {
            strx.push(u32::try_from(strtab.len()).unwrap());
            strtab.extend_from_slice(s.name.as_bytes());
            strtab.push(0);
        }

        let seg_cmdsize: u32 = 72 + 80; // segment_command_64 + one section_64
        let symtab_cmdsize: u32 = 24;
        let dysymtab_cmdsize: u32 = 80;
        let uuid_cmdsize: u32 = 24;
        let sizeofcmds = seg_cmdsize + symtab_cmdsize + dysymtab_cmdsize + uuid_cmdsize;
        let header_size: u32 = 32;

        let symoff = header_size + sizeofcmds;
        let nsyms = u32::try_from(syms.len()).unwrap();
        let stroff = symoff + nsyms * 16;
        let strsize = u32::try_from(strtab.len()).unwrap();

        let mut b = Vec::new();
        // ── mach_header_64 ─────────────────────────────────────────────────
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&cputype.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&4u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes()); // flags incl. MH_PIE
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // ── LC_SEGMENT_64 __TEXT ───────────────────────────────────────────
        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&seg_name("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // fileoff
        b.extend_from_slice(&text_size.to_le_bytes()); // filesize
        b.extend_from_slice(&7u32.to_le_bytes()); // maxprot rwx
        b.extend_from_slice(&5u32.to_le_bytes()); // initprot r-x
        b.extend_from_slice(&1u32.to_le_bytes()); // nsects
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        // section_64 __text
        b.extend_from_slice(&seg_name("__text"));
        b.extend_from_slice(&seg_name("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // offset
        b.extend_from_slice(&4u32.to_le_bytes()); // align
        b.extend_from_slice(&0u32.to_le_bytes()); // reloff
        b.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        b.extend_from_slice(&0x8000_0400u32.to_le_bytes()); // PURE_INSTRUCTIONS
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        // ── LC_SYMTAB ──────────────────────────────────────────────────────
        b.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        b.extend_from_slice(&symtab_cmdsize.to_le_bytes());
        b.extend_from_slice(&symoff.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&stroff.to_le_bytes());
        b.extend_from_slice(&strsize.to_le_bytes());

        // ── LC_DYSYMTAB ────────────────────────────────────────────────────
        b.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
        b.extend_from_slice(&dysymtab_cmdsize.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // ilocalsym
        b.extend_from_slice(&0u32.to_le_bytes()); // nlocalsym
        b.extend_from_slice(&0u32.to_le_bytes()); // iextdefsym
        b.extend_from_slice(&nsyms.to_le_bytes()); // nextdefsym
        b.extend_from_slice(&nsyms.to_le_bytes()); // iundefsym
        b.extend_from_slice(&0u32.to_le_bytes()); // nundefsym
        for _ in 0..12 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        // ── LC_UUID ────────────────────────────────────────────────────────
        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&uuid_cmdsize.to_le_bytes());
        b.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);

        assert_eq!(b.len(), symoff as usize, "load commands must end at symoff");

        // ── nlist_64 array ─────────────────────────────────────────────────
        for (s, sx) in syms.iter().zip(&strx) {
            b.extend_from_slice(&sx.to_le_bytes());
            b.push(N_SECT | if s.external { N_EXT } else { 0 });
            b.push(1); // n_sect (1-based: __text)
            b.extend_from_slice(&0u16.to_le_bytes()); // n_desc
            b.extend_from_slice(&s.value.to_le_bytes());
        }

        assert_eq!(b.len(), stroff as usize, "nlist array must end at stroff");
        b.extend_from_slice(&strtab);
        b
    }

    /// One segment (each carrying exactly one section) of a synthetic image.
    struct SegSpec {
        seg: &'static str,
        sect: &'static str,
        vmaddr: u64,
        vmsize: u64,
    }

    /// Like [`build_macho64`] but with an arbitrary number of segments, so a
    /// test can place a symbol in one segment and probe an address in another.
    fn build_macho64_segs(cputype: u32, segs: &[SegSpec], syms: &[Sym]) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut strx = Vec::new();
        for s in syms {
            strx.push(u32::try_from(strtab.len()).unwrap());
            strtab.extend_from_slice(s.name.as_bytes());
            strtab.push(0);
        }

        let seg_cmdsize: u32 = 72 + 80;
        let symtab_cmdsize: u32 = 24;
        let dysymtab_cmdsize: u32 = 80;
        let uuid_cmdsize: u32 = 24;
        let nsegs = u32::try_from(segs.len()).unwrap();
        let sizeofcmds =
            seg_cmdsize * nsegs + symtab_cmdsize + dysymtab_cmdsize + uuid_cmdsize;
        let header_size: u32 = 32;

        let symoff = header_size + sizeofcmds;
        let nsyms = u32::try_from(syms.len()).unwrap();
        let stroff = symoff + nsyms * 16;
        let strsize = u32::try_from(strtab.len()).unwrap();

        let mut b = Vec::new();
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&cputype.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&(nsegs + 3).to_le_bytes()); // ncmds
        b.extend_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        for s in segs {
            b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
            b.extend_from_slice(&seg_cmdsize.to_le_bytes());
            b.extend_from_slice(&seg_name(s.seg));
            b.extend_from_slice(&s.vmaddr.to_le_bytes());
            b.extend_from_slice(&s.vmsize.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes()); // fileoff
            b.extend_from_slice(&0u64.to_le_bytes()); // filesize
            b.extend_from_slice(&7u32.to_le_bytes());
            b.extend_from_slice(&5u32.to_le_bytes());
            b.extend_from_slice(&1u32.to_le_bytes()); // nsects
            b.extend_from_slice(&0u32.to_le_bytes());
            // section_64
            b.extend_from_slice(&seg_name(s.sect));
            b.extend_from_slice(&seg_name(s.seg));
            b.extend_from_slice(&s.vmaddr.to_le_bytes());
            b.extend_from_slice(&s.vmsize.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0x8000_0400u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        b.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        b.extend_from_slice(&symtab_cmdsize.to_le_bytes());
        b.extend_from_slice(&symoff.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&stroff.to_le_bytes());
        b.extend_from_slice(&strsize.to_le_bytes());

        b.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
        b.extend_from_slice(&dysymtab_cmdsize.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..12 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&uuid_cmdsize.to_le_bytes());
        b.extend_from_slice(&[
            0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);

        assert_eq!(b.len(), symoff as usize, "load commands must end at symoff");

        for (s, sx) in syms.iter().zip(&strx) {
            b.extend_from_slice(&sx.to_le_bytes());
            b.push(N_SECT | if s.external { N_EXT } else { 0 });
            b.push(1);
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&s.value.to_le_bytes());
        }

        assert_eq!(b.len(), stroff as usize, "nlist array must end at stroff");
        b.extend_from_slice(&strtab);
        b
    }

    /// Wrap the given thin slices into a fat/universal container.
    fn build_fat(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let nfat = u32::try_from(slices.len()).unwrap();
        let header_len = 8 + 20 * slices.len();
        // Every slice is page-aligned, as `lipo` produces.
        let mut offsets = Vec::new();
        let mut cursor = header_len.next_multiple_of(0x4000);
        for (_, data) in slices {
            offsets.push(cursor);
            cursor = (cursor + data.len()).next_multiple_of(0x4000);
        }

        let mut b = Vec::new();
        b.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        b.extend_from_slice(&nfat.to_be_bytes());
        for (i, (cputype, data)) in slices.iter().enumerate() {
            b.extend_from_slice(&cputype.to_be_bytes());
            b.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            b.extend_from_slice(&u32::try_from(offsets[i]).unwrap().to_be_bytes());
            b.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            b.extend_from_slice(&14u32.to_be_bytes()); // align 2^14
        }
        for (i, (_, data)) in slices.iter().enumerate() {
            b.resize(offsets[i], 0);
            b.extend_from_slice(data);
        }
        b
    }

    /// Wrap the given thin slices into a **64-bit** fat/universal container
    /// (`FAT_MAGIC_64`, 32-byte `fat_arch_64` records with 64-bit offsets).
    fn build_fat64(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let nfat = u32::try_from(slices.len()).unwrap();
        let header_len = 8 + 32 * slices.len();
        let mut offsets = Vec::new();
        let mut cursor = header_len.next_multiple_of(0x4000);
        for (_, data) in slices {
            offsets.push(cursor);
            cursor = (cursor + data.len()).next_multiple_of(0x4000);
        }

        let mut b = Vec::new();
        b.extend_from_slice(&0xCAFE_BABFu32.to_be_bytes()); // FAT_MAGIC_64
        b.extend_from_slice(&nfat.to_be_bytes());
        for (i, (cputype, data)) in slices.iter().enumerate() {
            b.extend_from_slice(&cputype.to_be_bytes());
            b.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            b.extend_from_slice(&(offsets[i] as u64).to_be_bytes()); // offset (u64)
            b.extend_from_slice(&(data.len() as u64).to_be_bytes()); // size   (u64)
            b.extend_from_slice(&14u32.to_be_bytes()); // align
            b.extend_from_slice(&0u32.to_be_bytes()); // reserved
        }
        for (i, (_, data)) in slices.iter().enumerate() {
            b.resize(offsets[i], 0);
            b.extend_from_slice(data);
        }
        b
    }

    fn sample_syms() -> Vec<Sym> {
        vec![
            Sym { name: "_start", value: 0x1_0000_4000, external: true },
            Sym { name: "_middle", value: 0x1_0000_4100, external: true },
            Sym { name: "_last", value: 0x1_0000_4200, external: false },
        ]
    }

    fn sample_image() -> ImageSymbols {
        let bytes = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        ImageSymbols::from_bytes("sample", &bytes, ArchPreference::Arm64).expect("parse")
    }

    // ── parsing ─────────────────────────────────────────────────────────────

    #[test]
    fn parses_thin_arm64_image() {
        let img = sample_image();
        assert_eq!(img.arch(), MachoArch::Arm64);
        assert_eq!(img.symbol_count(), 3);
        assert_eq!(img.preferred_base(), Some(0x1_0000_0000));
        assert_eq!(img.uuid().unwrap()[0], 0x01);
    }

    #[test]
    fn symtab_command_is_recovered() {
        let img = sample_image();
        let st = img.symtab().expect("LC_SYMTAB present");
        assert_eq!(st.nsyms, 3);
        assert!(st.symoff > 32);
        assert!(st.stroff > st.symoff);
        let dst = img.dysymtab().expect("LC_DYSYMTAB present");
        assert_eq!(dst.nextdefsym, 3);
        assert_eq!(dst.nundefsym, 0);
    }

    #[test]
    fn symbols_are_sorted_by_address() {
        let img = sample_image();
        let addrs: Vec<u64> = img.symbols().iter().map(|s| s.static_address).collect();
        let mut sorted = addrs.clone();
        sorted.sort_unstable();
        assert_eq!(addrs, sorted);
    }

    // ── slide arithmetic ────────────────────────────────────────────────────

    #[test]
    fn zero_slide_resolves_static_addresses() {
        let img = sample_image();
        let r = img.resolve(0x1_0000_4108).expect("inside _middle");
        assert_eq!(r.symbol, "_middle");
        assert_eq!(r.offset, 8);
        assert_eq!(r.source, Symbolication::Nlist);
    }

    #[test]
    fn slide_is_applied_to_lookups() {
        const SLIDE: u64 = 0x4000;
        let img = sample_image().with_slide(SLIDE);
        let r = img.resolve(0x1_0000_4100 + SLIDE).expect("slid _middle");
        assert_eq!(r.symbol, "_middle");
        assert_eq!(r.offset, 0);
        assert_eq!(r.symbol_address, 0x1_0000_4100 + SLIDE);
        // The unslid address must now NOT resolve to _middle at offset 0.
        let unslid = img.resolve(0x1_0000_4100).expect("still inside the image");
        assert_ne!(unslid.offset, 0);
    }

    #[test]
    fn runtime_base_derives_the_slide() {
        let img = sample_image()
            .with_runtime_base(0x1_1000_0000)
            .expect("has a base");
        assert_eq!(img.slide(), 0x1000_0000);
        let r = img.resolve(0x1_1000_4000).unwrap();
        assert_eq!(r.symbol, "_start");
        assert_eq!(r.offset, 0);
    }

    #[test]
    fn addresses_below_the_slide_are_rejected() {
        let img = sample_image().with_slide(0x1_0000_0000);
        assert!(img.static_of(0x100).is_none());
        assert!(img.resolve(0x100).is_none());
    }

    // ── containment and bounds ──────────────────────────────────────────────

    #[test]
    fn address_outside_every_segment_is_not_contained() {
        let img = sample_image();
        assert!(img.contains(0x1_0000_4000));
        assert!(!img.contains(0x2_0000_0000));
        assert!(img.resolve(0x2_0000_0000).is_none());
    }

    #[test]
    fn last_symbol_does_not_claim_past_the_segment() {
        // __TEXT is [0x1_0000_0000, +0x8000). 0x1_0000_9000 is outside it, so
        // even though it is above `_last` no symbol may claim it.
        let img = sample_image();
        assert!(img.resolve(0x1_0000_9000).is_none());
    }

    /// A symbol's upper bound is the end of the segment **the symbol** lives
    /// in, not the end of the segment the *queried address* happens to fall in.
    ///
    /// Image: `__TEXT` [0x1_0000_0000, +0x4000) holding the only symbol, then a
    /// disjoint `__DATA` [0x1_0001_0000, +0x4000). An address inside `__DATA`
    /// is above every symbol, so the last symbol has no successor and the bound
    /// degenerates to "end of the queried address's segment" — which is the end
    /// of `__DATA`. The `__TEXT` symbol then claims a `__DATA` address 0xF100
    /// bytes past the end of its own segment.
    #[test]
    fn a_symbol_may_not_claim_an_address_in_another_segment() {
        let bytes = build_macho64_segs(
            CPU_TYPE_ARM64,
            &[
                SegSpec { seg: "__TEXT", sect: "__text", vmaddr: 0x1_0000_0000, vmsize: 0x4000 },
                SegSpec { seg: "__DATA", sect: "__data", vmaddr: 0x1_0001_0000, vmsize: 0x4000 },
            ],
            &[Sym { name: "_fn", value: 0x1_0000_1000, external: true }],
        );
        let img = ImageSymbols::from_bytes("two_segs", &bytes, ArchPreference::Arm64).unwrap();

        // Sanity: the fixture really does have both segments and the symbol.
        assert!(img.contains(0x1_0000_1000), "__TEXT must be mapped");
        assert!(img.contains(0x1_0001_0100), "__DATA must be mapped");
        assert_eq!(img.symbol_count(), 1);

        // The __TEXT symbol ends with __TEXT at 0x1_0000_4000. Nothing may name
        // an address in __DATA.
        let r = img.resolve(0x1_0001_0100).expect("inside __DATA");
        assert_eq!(
            r.source,
            Symbolication::ModuleOnly,
            "a __TEXT symbol claimed a __DATA address as {} +{:#x}",
            r.symbol,
            r.offset
        );
        // And an address still inside __TEXT, past the symbol, is unaffected.
        let inside = img.resolve(0x1_0000_1004).expect("inside __TEXT");
        assert_eq!(inside.symbol, "_fn");
        assert_eq!(inside.offset, 4);
        assert_eq!(inside.source, Symbolication::Nlist);
    }

    #[test]
    fn address_before_the_first_symbol_falls_back_to_module_only() {
        let img = sample_image();
        let r = img.resolve(0x1_0000_0010).expect("inside __TEXT");
        assert_eq!(r.source, Symbolication::ModuleOnly);
        assert_eq!(r.offset, 0x10);
    }

    #[test]
    fn symbol_offsets_are_relative_to_the_symbol() {
        let img = sample_image();
        for delta in [0u64, 1, 0x40, 0xFF] {
            let r = img.resolve(0x1_0000_4000 + delta).unwrap();
            assert_eq!(r.symbol, "_start");
            assert_eq!(r.offset, delta);
        }
    }

    // ── fat binaries ────────────────────────────────────────────────────────

    #[test]
    fn fat_binary_selects_the_arm64_slice() {
        let x86 = build_macho64(CPU_TYPE_X86_64, 0x1_0000_0000, 0x8000, &sample_syms());
        let arm = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let fat = build_fat(&[(CPU_TYPE_X86_64, x86), (CPU_TYPE_ARM64, arm)]);

        let img = ImageSymbols::from_bytes("fat", &fat, ArchPreference::Arm64).unwrap();
        assert_eq!(img.arch(), MachoArch::Arm64);

        let img = ImageSymbols::from_bytes("fat", &fat, ArchPreference::X86_64).unwrap();
        assert_eq!(img.arch(), MachoArch::X86_64);

        // First-listed slice, whatever it is.
        let img = ImageSymbols::from_bytes("fat", &fat, ArchPreference::First).unwrap();
        assert_eq!(img.arch(), MachoArch::X86_64);
    }

    /// 64-bit universal containers (`FAT_MAGIC_64`, 0xCAFEBABF) carry 32-byte
    /// `fat_arch_64` records with 64-bit offsets. They are what `lipo` emits
    /// once a slice crosses the 4 GiB mark, and Apple ships them; a container
    /// that is not recognised as fat is handed to the thin parser whole, which
    /// can only report an unknown magic.
    #[test]
    fn fat64_universal_containers_are_recognised() {
        let x86 = build_macho64(CPU_TYPE_X86_64, 0x1_0000_0000, 0x8000, &sample_syms());
        let arm = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let fat = build_fat64(&[(CPU_TYPE_X86_64, x86), (CPU_TYPE_ARM64, arm)]);

        let img = ImageSymbols::from_bytes("fat64", &fat, ArchPreference::Arm64)
            .expect("a FAT_MAGIC_64 container must be sliced, not rejected");
        assert_eq!(img.arch(), MachoArch::Arm64);
        assert_eq!(img.symbol_count(), 3);
        assert_eq!(img.resolve(0x1_0000_4100).unwrap().symbol, "_middle");

        let img = ImageSymbols::from_bytes("fat64", &fat, ArchPreference::X86_64).unwrap();
        assert_eq!(img.arch(), MachoArch::X86_64);

        let img = ImageSymbols::from_bytes("fat64", &fat, ArchPreference::First).unwrap();
        assert_eq!(img.arch(), MachoArch::X86_64);
    }

    #[test]
    fn fat64_missing_slice_is_the_same_typed_error_as_fat32() {
        let x86 = build_macho64(CPU_TYPE_X86_64, 0x1_0000_0000, 0x8000, &sample_syms());
        let fat = build_fat64(&[(CPU_TYPE_X86_64, x86)]);
        let err = ImageSymbols::from_bytes("fat64", &fat, ArchPreference::Arm64).unwrap_err();
        match err {
            SymbolicationError::NoSliceForArch { requested, available } => {
                assert_eq!(requested, "arm64");
                assert!(available.contains("x86_64"));
            }
            other => panic!("expected NoSliceForArch, got {other:?}"),
        }
    }

    #[test]
    fn missing_slice_is_a_typed_error_not_a_silent_fallback() {
        let x86 = build_macho64(CPU_TYPE_X86_64, 0x1_0000_0000, 0x8000, &sample_syms());
        let fat = build_fat(&[(CPU_TYPE_X86_64, x86)]);
        let err = ImageSymbols::from_bytes("fat", &fat, ArchPreference::Arm64).unwrap_err();
        match err {
            SymbolicationError::NoSliceForArch { requested, available } => {
                assert_eq!(requested, "arm64");
                assert!(available.contains("x86_64"));
            }
            other => panic!("expected NoSliceForArch, got {other:?}"),
        }
    }

    #[test]
    fn garbage_input_is_rejected() {
        let err = ImageSymbols::from_bytes("junk", b"not a macho at all", ArchPreference::Arm64)
            .unwrap_err();
        assert!(matches!(err, SymbolicationError::Macho(_)));
    }

    #[test]
    fn big_endian_macho_is_rejected_explicitly() {
        let mut bytes = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        bytes[..4].copy_from_slice(&MH_CIGAM_64.to_le_bytes());
        let err = ImageSymbols::from_bytes("ppc", &bytes, ArchPreference::Arm64).unwrap_err();
        assert_eq!(err, SymbolicationError::BigEndianUnsupported);
    }

    // ── multi-image engine ──────────────────────────────────────────────────

    /// Nothing ever BUILT a symbolicator from a live target: the engine was
    /// reachable in principle but a caller had to assemble every image by
    /// hand, so `backtrace()` frames stayed nameless in practice.
    ///
    /// The builder is a pure function over an injected reader, so this proves
    /// the real logic — module list in, resolvable engine out — on any host.
    #[test]
    fn symbolicator_is_built_from_the_targets_reported_modules() {
        use crate::{Address, ModuleInfo};

        // The image is LOADED at a different address than it was linked at,
        // so a correct build must derive the slide, not assume zero.
        const LINKED_AT: u64 = 0x1_0000_0000;
        const LOADED_AT: u64 = 0x1_8000_0000;
        let image = build_macho64(CPU_TYPE_ARM64, LINKED_AT, 0x8000, &sample_syms());

        let modules = vec![
            ModuleInfo {
                is_main: true,
                name: "a.dylib".into(),
                path: "/usr/lib/a.dylib".into(),
                base: Address(LOADED_AT),
                size: image.len() as u64,
                entry_point: None,
            },
            // An image the reader cannot fetch must be skipped, not fatal.
            ModuleInfo {
                is_main: false,
                name: "unreadable.dylib".into(),
                path: "/usr/lib/unreadable.dylib".into(),
                base: Address(0x3_0000_0000),
                size: 0x1000,
                entry_point: None,
            },
        ];

        let engine = symbolicator_from_modules(&modules, |addr, len| {
            (addr == LOADED_AT && len == image.len()).then(|| image.clone())
        });

        assert_eq!(engine.image_count(), 1, "the unreadable image must be skipped, not fatal");

        // An address inside the LOADED image resolves through the derived slide.
        let probe = LOADED_AT + 0x4100;
        let resolved = engine
            .resolve(probe)
            .expect("a loaded image must resolve addresses at its runtime base");
        assert!(!resolved.display_name().is_empty());
        // The statically-linked address must NOT resolve: that would mean the
        // slide was ignored and every name would be attributed wrongly.
        assert!(engine.resolve(LINKED_AT + 0x4100).is_none());
    }

    /// The engine could not be plugged into the debugger at all: `backtrace()`
    /// enriches frames through `FrameSymbolResolver`, which only
    /// `CodeViewProvider` and `SourceMap` implemented. A caller who built a
    /// `Symbolicator` had nowhere to put it, so every Apple backtrace came
    /// back with `function_name: None` — ~1200 tested lines with no live path.
    ///
    /// Before the `impl`, this test does not COMPILE (`Arc<Symbolicator>`
    /// cannot coerce to `Arc<dyn FrameSymbolResolver>`), which is the
    /// strongest possible evidence the capability was missing.
    #[test]
    fn symbolicator_can_be_used_as_a_frame_symbol_resolver() {
        use crate::symbol_resolver::{enrich_frames, FrameSymbolResolver};
        use crate::{Address, StackFrame};
        use std::sync::Arc;

        let image = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let mut s = Symbolicator::new();
        s.add_image(ImageSymbols::from_bytes("a.dylib", &image, ArchPreference::Arm64).unwrap());
        // The address the engine resolves on its own...
        let expected = s.resolve(0x1_0000_4100).expect("engine resolves it").display_name().to_string();

        // ...must reach a stack frame through the generic resolver path.
        let resolver: Arc<dyn FrameSymbolResolver> = Arc::new(s);
        let mut frames = vec![StackFrame {
            index: 0,
            pc: Address(0x1_0000_4100),
            sp: Address(0),
            fp: None,
            function_name: None,
            module: None,
            offset: None,
            source_file: None,
            source_line: None,
        }];
        enrich_frames(&mut frames, resolver.as_ref());

        assert_eq!(
            frames[0].function_name.as_deref(),
            Some(expected.as_str()),
            "the Apple symbolicator did not reach the frame through FrameSymbolResolver"
        );
        // Mach-O symbol tables carry no source coordinates: absent, not invented.
        assert!(frames[0].source_file.is_none() && frames[0].source_line.is_none());
    }

    #[test]
    fn symbolicator_routes_to_the_owning_image() {
        let a = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let b = build_macho64(
            CPU_TYPE_ARM64,
            0x2_0000_0000,
            0x8000,
            &[Sym { name: "_other", value: 0x2_0000_1000, external: true }],
        );

        let mut s = Symbolicator::new();
        s.add_image(ImageSymbols::from_bytes("a.dylib", &a, ArchPreference::Arm64).unwrap());
        s.add_image(ImageSymbols::from_bytes("b.dylib", &b, ArchPreference::Arm64).unwrap());
        assert_eq!(s.image_count(), 2);

        let r = s.resolve(0x1_0000_4100).unwrap();
        assert_eq!(r.module, "a.dylib");
        assert_eq!(r.symbol, "_middle");

        let r = s.resolve(0x2_0000_1004).unwrap();
        assert_eq!(r.module, "b.dylib");
        assert_eq!(r.symbol, "_other");
        assert_eq!(r.offset, 4);

        assert!(s.resolve(0x9_0000_0000).is_none());
    }

    #[test]
    fn backtrace_positions_are_preserved() {
        let a = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let mut s = Symbolicator::new();
        s.add_image(ImageSymbols::from_bytes("a", &a, ArchPreference::Arm64).unwrap());

        let out = s.resolve_all(&[0x1_0000_4000, 0xDEAD_BEEF, 0x1_0000_4200]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].as_ref().unwrap().symbol, "_start");
        assert!(out[1].is_none());
        assert_eq!(out[2].as_ref().unwrap().symbol, "_last");
    }

    #[test]
    fn image_lookup_by_uuid() {
        let a = build_macho64(CPU_TYPE_ARM64, 0x1_0000_0000, 0x8000, &sample_syms());
        let mut s = Symbolicator::new();
        s.add_image(ImageSymbols::from_bytes("a", &a, ArchPreference::Arm64).unwrap());
        let uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        assert!(s.image_by_uuid(uuid).is_some());
        assert!(s.image_by_uuid([0xFF; 16]).is_none());
    }

    #[test]
    fn lookup_by_name_handles_the_underscore_convention() {
        let img = sample_image();
        assert_eq!(img.lookup_name("start").unwrap().static_address, 0x1_0000_4000);
        assert_eq!(img.lookup_name("_start").unwrap().static_address, 0x1_0000_4000);
        assert!(img.lookup_name("nope").is_none());
    }

    // ── demangling ──────────────────────────────────────────────────────────

    #[test]
    fn objc_method_names_are_demangled() {
        let d = demangle_symbol("-[NSObject dealloc]").expect("objc handled");
        assert!(d.contains("NSObject"));
        assert!(d.contains("dealloc"));
    }

    #[test]
    fn swift_symbols_go_through_the_shared_demangler() {
        // `_$s` is the Mach-O-prefixed form of Swift's `$s`.
        let raw = "_$s4main3fooyyF";
        assert!(SwiftDemangler::detect(raw.strip_prefix('_').unwrap()));
        let d = demangle_symbol(raw).expect("swift handled");
        assert!(!d.is_empty());
        assert_ne!(d, raw);
    }

    #[test]
    fn plain_c_symbols_lose_only_the_underscore() {
        assert_eq!(demangle_symbol("_malloc").as_deref(), Some("malloc"));
        assert_eq!(demangle_symbol("malloc"), None);
        assert_eq!(demangle_symbol(""), None);
        // A lone underscore must not become an empty name.
        assert_eq!(demangle_symbol("_"), None);
    }

    #[test]
    fn resolved_addresses_carry_the_demangled_name() {
        let bytes = build_macho64(
            CPU_TYPE_ARM64,
            0x1_0000_0000,
            0x8000,
            &[Sym { name: "_malloc", value: 0x1_0000_2000, external: true }],
        );
        let img = ImageSymbols::from_bytes("libc", &bytes, ArchPreference::Arm64).unwrap();
        let r = img.resolve(0x1_0000_2004).unwrap();
        assert_eq!(r.symbol, "_malloc");
        assert_eq!(r.demangled.as_deref(), Some("malloc"));
        assert_eq!(r.display_name(), "malloc");
    }

    // ── binary-search helper ────────────────────────────────────────────────

    #[test]
    fn index_of_last_le_edge_cases() {
        let v = [10u64, 20, 20, 30];
        let key = |i: usize| v[i];
        assert_eq!(index_of_last_le(v.len(), 9, key), None);
        assert_eq!(index_of_last_le(v.len(), 10, key), Some(0));
        assert_eq!(index_of_last_le(v.len(), 20, key), Some(2));
        assert_eq!(index_of_last_le(v.len(), 29, key), Some(2));
        assert_eq!(index_of_last_le(v.len(), 1000, key), Some(3));
        assert_eq!(index_of_last_le(0, 5, |_| 0), None);
    }
}
