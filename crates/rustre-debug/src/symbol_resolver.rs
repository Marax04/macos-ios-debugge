//! Frame symbolication: turn a raw program counter into a function name and
//! source file/line so a live [`crate::StackFrame`] reads like a real
//! backtrace instead of a column of hex.
//!
//! The OS backends (`windows_debugger` / `linux_debugger`)
//! unwind the stack into `StackFrame`s whose `function_name`/`source_file`/
//! `source_line` are all `None` — they know addresses, not symbols. This module
//! defines the small [`FrameSymbolResolver`] seam a backend holds optionally,
//! plus [`enrich_frames`], which fills those fields in place. Any symbol source
//! (DWARF line tables via [`crate::source_map::SourceMap`], and later CodeView/
//! PDB) implements the trait, keeping the backends free of debug-format parsing.

use crate::codeview::{CodeViewProvider, SymbolProvider};
use crate::source_map::SourceMap;
use crate::StackFrame;

/// Appended by [`enrich_frames`] to a function name that is the NEAREST
/// preceding symbol rather than one demonstrably containing the pc.
///
/// A backtrace is read as a statement of fact, and an unbounded nearest match
/// is a guess: it names the last symbol below the pc even when the pc belongs
/// to another module entirely, which is what a corrupted return address looks
/// like. Marking it costs one suffix and stops the guess from being read as a
/// measurement — the same reason `time_travel_debug` prefixes an unmeasured
/// stop reason with `simulated_`.
pub const NEAREST_SYMBOL_MARKER: &str = " (nearest)";

/// A symbol lookup result for a single program counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedFrameSymbol {
    /// Function/symbol name containing the PC, if known.
    pub function: Option<String>,
    /// Source file path, if known.
    pub file: Option<String>,
    /// 1-based source line, if known.
    pub line: Option<u32>,
    /// Whether `function` is *demonstrably* the symbol containing the pc, as
    /// opposed to merely the nearest one below it.
    ///
    /// A nearest-preceding lookup with nothing bounding the symbol from above
    /// cannot tell "inside the last function" from "in another module entirely"
    /// — and a corrupted return address lands in the second case while being
    /// reported exactly like the first. That distinction was previously not
    /// representable, so every answer looked equally certain; callers rendering
    /// a backtrace can now mark or drop the unbounded ones instead of
    /// presenting a guess as a measurement.
    pub bounded: bool,
    /// Address the named function STARTS at, when the source knows it.
    ///
    /// Without it `StackFrame::offset` — "byte offset from the start of the
    /// function", a documented public field — could never be filled by anyone:
    /// the resolver knew the symbol's address and threw it away, so every frame
    /// read `main` with no way to tell which part of `main`. `func+0x1c` is how
    /// every other debugger renders a frame, and it is the difference between
    /// naming a function and locating a call site.
    pub start: Option<u64>,
}

impl ResolvedFrameSymbol {
    /// True when nothing was resolved — used to skip pointless frame writes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.function.is_none() && self.file.is_none() && self.line.is_none()
    }
}

/// A source of per-address symbol information a debugger backend can consult
/// while building a backtrace. `Send + Sync` so a backend can hold one behind
/// an `Arc` shared across its dedicated debug-loop thread and callers.
pub trait FrameSymbolResolver: Send + Sync {
    /// Resolve the function/file/line for `pc`, or `None` if unknown.
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol>;
}

impl FrameSymbolResolver for CodeViewProvider {
    /// `lookup_nearest` is *nearest preceding* and completely unbounded — it
    /// has no size to consult (every CodeView `Symbol` here is built with
    /// `size: None`) and no module extent. Handing its answer straight back as
    /// "the function containing `pc`" is a claim it cannot support: a `pc` past
    /// the last symbol — another module, a corrupted return address, data
    /// mistaken for code — was confidently named after that last symbol, and
    /// every frame of a bad unwind read as a real function.
    ///
    /// Containment is only *demonstrable* when something bounds the symbol
    /// above, and two such bounds are real data rather than a guessed
    /// threshold:
    /// * a recorded `size`, when a provider supplies one, or
    /// * the existence of a later symbol — `lookup_nearest` picks the closest
    ///   preceding one, so `pc` necessarily sits below that successor.
    ///
    /// That leaves exactly one unbounded case: the last symbol with no size.
    /// There, a line-table row for `pc` is independent measured evidence that
    /// `pc` is compiled code in this module, so the name stands. With neither a
    /// bound nor a row, nothing is claimed.
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        let sym = self.lookup_nearest(pc)?;
        let (file, line) = self
            .source_line_for_address(pc)
            .map(|loc| (Some(loc.file), Some(loc.line)))
            .unwrap_or((None, None));
        let bounded = match sym.size {
            Some(n) if n > 0 => pc - sym.address < n,
            // No size: a later symbol bounds this one, because
            // `lookup_nearest` returns the CLOSEST preceding symbol — so `pc`
            // necessarily sits below that successor. A line-table row for `pc`
            // is independent measured evidence of the same thing.
            _ => {
                self.highest_symbol_address().is_some_and(|hi| hi > sym.address)
                    || line.is_some()
            }
        };
        Some(ResolvedFrameSymbol {
            function: Some(sym.name),
            file,
            line,
            bounded,
            start: Some(sym.address),
        })
    }
}

/// Several resolvers, consulted in order until one answers.
///
/// A process is many images, each loaded at its own address and each with its own
/// symbol source. A backend can install exactly ONE resolver, so without a way to
/// compose them a backtrace crossing two modules could only ever name the frames
/// of one of them — and the frames from the other would come back bare, looking
/// exactly like frames with no symbols at all.
///
/// First ANSWER wins, not first resolver: a source that returns `None`, or a
/// result with nothing in it, has not answered and the next one is asked. That
/// distinction is what lets a per-image resolver be handed an address outside its
/// image without silently shadowing the resolver that owns it.
#[derive(Default)]
pub struct MultiResolver {
    sources: Vec<Box<dyn FrameSymbolResolver>>,
}

impl MultiResolver {
    /// An empty chain, which resolves nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a source. Order is consultation order.
    pub fn push(&mut self, source: Box<dyn FrameSymbolResolver>) {
        self.sources.push(source);
    }

    /// How many sources are in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether the chain can resolve anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

impl FrameSymbolResolver for MultiResolver {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        self.sources
            .iter()
            .find_map(|s| s.resolve_frame(pc).filter(|r| !r.is_empty()))
    }
}

/// A resolver whose symbols are FILE addresses, seen through a load slide.
///
/// Every on-disk symbol source — an ELF `.symtab`, a PDB, a Mach-O nlist —
/// records addresses as the linker laid them out. The target loaded that image
/// somewhere else: with ASLR, somewhere different on every run. Handing a runtime
/// `pc` straight to such a source asks it about an address it has never heard of,
/// and `lookup_nearest` answers anyway — with whatever symbol happens to precede
/// that number. The name looks exactly like a real one.
///
/// This wrapper is the translation both ways, and both directions matter:
/// * the `pc` goes DOWN by the slide before the lookup, so the question is asked
///   in the coordinates the file uses;
/// * the answer's `start` comes back UP by the slide, so it is in the same
///   coordinates as the `pc` the caller holds. Without that second half,
///   `enrich_frames` would compute `pc - static_start` — a number in the
///   billions, printed as a function offset.
pub struct SlidResolver<R> {
    inner: R,
    slide: i64,
}

impl<R> SlidResolver<R> {
    /// Wrap `inner`, whose addresses are file addresses, for an image loaded
    /// `slide` bytes away from where it was linked.
    pub const fn new(inner: R, slide: i64) -> Self {
        Self { inner, slide }
    }
}

impl<R: FrameSymbolResolver> FrameSymbolResolver for SlidResolver<R> {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        // A `pc` below the image's load address is not in this image at all.
        // Wrapping would turn it into a huge file address and the lookup would
        // answer about some unrelated symbol, so this must be a miss.
        let file_pc = pc.checked_add_signed(-self.slide)?;
        let mut sym = self.inner.resolve_frame(file_pc)?;
        sym.start = sym.start.and_then(|s| s.checked_add_signed(self.slide));
        Some(sym)
    }
}

/// Any [`rustre_symbols::SymbolTable`] is a frame resolver.
///
/// The generic door the native backends were missing. `CodeViewProvider` covers
/// PDBs and `SourceMap` covers DWARF line tables, but a plain symbol table — PE
/// exports, an ELF `.symtab`, a `.dSYM` nlist, anything that fills a
/// `SymbolTable` — had no way in, so a backend holding one still produced
/// backtraces of bare addresses.
///
/// Containment here is MEASURED, not guessed: `Symbol::contains` uses the
/// symbol's own recorded size. `lookup_nearest` is consulted only as a fallback,
/// and its answer is reported as unbounded — which is what makes
/// `enrich_frames` mark the name and withhold the offset.
impl FrameSymbolResolver for rustre_symbols::SymbolTable {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        let sym = self.lookup_nearest(pc)?;
        // `contains` is true only when the symbol records a size that covers
        // `pc`. Without a size there is nothing bounding the symbol above, and a
        // pc past the end of the last function — another module, a corrupted
        // return address, data read as code — would otherwise be named after it
        // with the same confidence as a real hit.
        let bounded = sym.contains(pc);
        Some(ResolvedFrameSymbol {
            function: Some(sym.display_name().to_string()),
            file: None,
            line: None,
            bounded,
            // Only for a demonstrated hit: an offset from a nearest-preceding
            // guess is a distance from an arbitrary landmark (iteration 423).
            start: bounded.then_some(sym.address),
        })
    }
}

impl FrameSymbolResolver for SourceMap {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        let loc = self.addr_to_source(pc)?;
        // `function_at` can name the enclosing symbol even when the line-table
        // row itself carried no function attribute, so prefer the location's
        // function and fall back to the address→function index.
        let function = loc
            .function
            .clone()
            .or_else(|| self.function_at(pc).map(str::to_string));
        Some(ResolvedFrameSymbol {
            function,
            file: Some(loc.file.to_string_lossy().into_owned()),
            line: Some(loc.line),
            // A line-table row exists for this exact pc, so the pc really is
            // inside compiled code this map describes.
            bounded: true,
            // A line table locates the pc but does not say where its function
            // BEGINS, and the address->function index answers containment, not
            // extent. No start means no offset, which is the honest outcome:
            // subtracting from a landmark this map cannot name would produce a
            // number that looks like a function offset and is not one.
            start: None,
        })
    }
}

/// Fill each frame's `function_name`/`source_file`/`source_line` from
/// `resolver`, in place. Only overwrites fields that are currently `None`, so a
/// backend that already knows some symbol data (e.g. a module name) keeps it.
pub fn enrich_frames(frames: &mut [StackFrame], resolver: &dyn FrameSymbolResolver) {
    for frame in frames.iter_mut() {
        let Some(sym) = resolver.resolve_frame(frame.pc.as_u64()) else {
            continue;
        };
        if sym.is_empty() {
            continue;
        }
        if frame.function_name.is_none() {
            // `bounded` was computed but nothing consumed it, so a nearest-
            // preceding guess reached the caller looking exactly like a
            // measured symbol. Rendering is the right place to draw that line:
            // the resolver reports facts (`function` plus whether containment
            // is demonstrable), and only here is it decided how to show them.
            frame.function_name = sym.function.map(|f| {
                if sym.bounded {
                    f
                } else {
                    f + NEAREST_SYMBOL_MARKER
                }
            });
        }
        // Offset within the function, from the same lookup that named it.
        //
        // Only when the name was actually TAKEN from this resolution and the
        // symbol is demonstrably the containing one: an offset measured from a
        // nearest-preceding guess is a distance from an arbitrary landmark, and
        // it would print as if it located the call site.
        if frame.offset.is_none()
            && sym.bounded
            && let Some(start) = sym.start
            && frame.pc.as_u64() >= start
        {
            frame.offset = Some(frame.pc.as_u64() - start);
        }
        if frame.source_file.is_none() {
            frame.source_file = sym.file;
        }
        if frame.source_line.is_none() {
            frame.source_line = sym.line;
        }
    }
}

#[cfg(test)]
mod tests {
    /// A backtrace crossing two images must name the frames of BOTH.
    ///
    /// A backend installs exactly one resolver, and a process is many images —
    /// each at its own address, each with its own symbol source. Without a way to
    /// compose them, the frames belonging to the second image came back bare,
    /// indistinguishable from frames that genuinely have no symbols.
    ///
    /// First ANSWER wins, not first source: a per-image resolver handed an
    /// address outside its own image must not shadow the one that owns it. That
    /// is what the middle assertion checks — the chain is deliberately ordered
    /// with the WRONG image first.
    #[test]
    fn a_chain_of_resolvers_answers_for_whichever_image_owns_the_address() {
        struct Only(u64, &'static str);
        impl FrameSymbolResolver for Only {
            fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
                (pc >= self.0 && pc < self.0 + 0x100).then(|| ResolvedFrameSymbol {
                    function: Some(self.1.to_string()),
                    file: None,
                    line: None,
                    bounded: true,
                    start: Some(self.0),
                })
            }
        }

        let mut chain = MultiResolver::new();
        chain.push(Box::new(Only(0x1000, "in_exe")));
        chain.push(Box::new(Only(0x9000, "in_lib")));
        assert_eq!(chain.len(), 2);

        assert_eq!(
            chain.resolve_frame(0x1010).and_then(|r| r.function).as_deref(),
            Some("in_exe")
        );
        assert_eq!(
            chain.resolve_frame(0x9010).and_then(|r| r.function).as_deref(),
            Some("in_lib"),
            "the second image's frames were left unresolved: the first source in the chain shadowed it"
        );
        assert!(
            chain.resolve_frame(0x5000).is_none(),
            "an address in neither image was answered anyway"
        );

        // A source that answers with NOTHING has not answered: the next one must
        // still be consulted, or an empty result would shadow a real one.
        struct Blank;
        impl FrameSymbolResolver for Blank {
            fn resolve_frame(&self, _pc: u64) -> Option<ResolvedFrameSymbol> {
                Some(ResolvedFrameSymbol::default())
            }
        }
        let mut shadowed = MultiResolver::new();
        shadowed.push(Box::new(Blank));
        shadowed.push(Box::new(Only(0x1000, "in_exe")));
        assert_eq!(
            shadowed.resolve_frame(0x1010).and_then(|r| r.function).as_deref(),
            Some("in_exe"),
            "an empty answer counted as an answer and hid the source that knew"
        );
    }
    /// File-address symbols must be read through the image's load slide.
    ///
    /// Every on-disk symbol source records addresses as the linker laid them
    /// out, and the target loaded the image somewhere else — with ASLR,
    /// somewhere different every run. Asking such a source about a runtime `pc`
    /// asks about an address it never heard of, and `lookup_nearest` answers
    /// anyway, with whatever symbol precedes that number. The wrong name looks
    /// exactly like a right one.
    ///
    /// The return trip matters just as much: if `start` comes back in FILE
    /// coordinates while `pc` is a runtime address, `enrich_frames` computes a
    /// difference in the billions and prints it as a function offset.
    #[test]
    fn symbols_are_read_through_the_images_load_slide_in_both_directions() {
        // Knows one function at file address 0x1000, 0x40 long.
        struct File;
        impl FrameSymbolResolver for File {
            fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
                (0x1000..0x1040).contains(&pc).then(|| ResolvedFrameSymbol {
                    function: Some("work".to_string()),
                    file: None,
                    line: None,
                    bounded: true,
                    start: Some(0x1000),
                })
            }
        }

        const SLIDE: i64 = 0x7F00_0000_0000;
        let slid = SlidResolver::new(File, SLIDE);

        // Unslid, the runtime pc means nothing to the file resolver.
        assert!(
            File.resolve_frame(0x7F00_0000_1020).is_none(),
            "the fixture must not answer a runtime address by accident"
        );

        let hit = slid
            .resolve_frame(0x7F00_0000_1020)
            .expect("a runtime pc inside the loaded function must resolve");
        assert_eq!(hit.function.as_deref(), Some("work"));
        assert_eq!(
            hit.start,
            Some(0x7F00_0000_1000),
            "the function start came back in FILE coordinates: the offset computed from it would be in the billions and printed as a function offset"
        );

        // And the offset that `enrich_frames` derives is then the real one.
        let mut frames = vec![StackFrame {
            index: 0,
            pc: rustre_core::address::Address::new(0x7F00_0000_1020),
            sp: rustre_core::address::Address::new(0),
            fp: None,
            function_name: None,
            module: None,
            offset: None,
            source_file: None,
            source_line: None,
        }];
        enrich_frames(&mut frames, &slid);
        assert_eq!(frames[0].offset, Some(0x20));

        // A pc BELOW the image base is not in this image; it must not wrap into
        // a huge file address and be answered by an unrelated symbol.
        assert!(
            slid.resolve_frame(0x10).is_none(),
            "an address below the load base was translated by wrapping and answered anyway"
        );
    }
    /// A plain symbol table must be usable as a frame resolver.
    ///
    /// `CodeViewProvider` covers PDBs and `SourceMap` covers DWARF line tables,
    /// but a bare `SymbolTable` — PE exports, an ELF `.symtab`, a `.dSYM` nlist —
    /// had no way in. A backend holding one still produced backtraces of bare
    /// addresses, which is the state all three native backends are in.
    ///
    /// Containment must be MEASURED here, not assumed: a symbol with a recorded
    /// size bounds itself, and a pc past its end belongs to nobody. That
    /// distinction is what decides whether the name is marked as a guess and
    /// whether an offset may be reported at all.
    #[test]
    fn a_symbol_table_resolves_frames_and_only_claims_what_it_can_prove() {
        use rustre_symbols::{SymKind, Symbol, SymbolProvider, SymbolTable};

        #[derive(Debug)]
        struct Two;
        fn sym(name: &str, address: u64, size: Option<u64>) -> Symbol {
            let mut s = Symbol::new(name.to_string(), address, SymKind::Function);
            s.size = size;
            s
        }
        impl SymbolProvider for Two {
            fn name(&self) -> &str { "fixture" }
            fn lookup_name(&self, _n: &str) -> Option<Symbol> { None }
            fn lookup_address(&self, _a: u64) -> Option<Symbol> { None }
            fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
                // `sized` covers [0x1000, 0x1040); `tail` has no size at all.
                if addr >= 0x2000 {
                    Some(sym("tail", 0x2000, None))
                } else if addr >= 0x1000 {
                    Some(sym("sized", 0x1000, Some(0x40)))
                } else {
                    None
                }
            }
            fn all_symbols(&self) -> Vec<Symbol> { Vec::new() }
            fn all_functions(&self) -> Vec<Symbol> { Vec::new() }
            fn source_line_for_address(&self, _a: u64) -> Option<rustre_symbols::SourceLocation> { None }
        }

        let table = SymbolTable::new();
        table.add_provider(Box::new(Two));

        // Inside a sized symbol: named, bounded, and the offset follows.
        let hit = table.resolve_frame(0x1020).expect("an address inside a sized symbol resolves");
        assert_eq!(hit.function.as_deref(), Some("sized"));
        assert!(hit.bounded, "a recorded size covering the pc IS containment");
        assert_eq!(hit.start, Some(0x1000));

        // Past its end: the nearest symbol is still `sized`, but nothing bounds
        // the pc inside it — that must not be reported as a hit.
        let past = table.resolve_frame(0x1100).expect("nearest still answers");
        assert_eq!(past.function.as_deref(), Some("sized"));
        assert!(
            !past.bounded,
            "an address beyond the symbol's recorded size was reported as contained"
        );
        assert_eq!(
            past.start, None,
            "an offset would be measured from a symbol that does not contain the pc"
        );

        // A symbol with no size can never bound anything.
        let unsized_hit = table.resolve_frame(0x2004).expect("nearest answers");
        assert!(!unsized_hit.bounded, "a symbol with no recorded size cannot demonstrate containment");

        // Below every symbol: nothing at all.
        assert!(table.resolve_frame(0x10).is_none());
    }
    /// A named frame must say WHERE in the function it is.
    ///
    /// `StackFrame::offset` is a documented public field — "byte offset from the
    /// start of the function" — and nothing could ever fill it: the resolver knew
    /// the symbol's address and dropped it on the way out, so every frame inside
    /// `main` read `main`, with no way to tell a call site from the prologue.
    /// `func+0x1c` is how every other debugger renders a frame, and it is the
    /// difference between naming a function and locating a call.
    ///
    /// The offset must NOT be produced from an unbounded (nearest-preceding)
    /// match: that is a distance from an arbitrary landmark, and it would print
    /// exactly like a measured one.
    #[test]
    fn a_resolved_frame_carries_its_offset_into_the_function() {
        struct At(u64, bool);
        impl FrameSymbolResolver for At {
            fn resolve_frame(&self, _pc: u64) -> Option<ResolvedFrameSymbol> {
                Some(ResolvedFrameSymbol {
                    function: Some("work".to_string()),
                    file: None,
                    line: None,
                    bounded: self.1,
                    start: Some(self.0),
                })
            }
        }
        fn frame_at(pc: u64) -> StackFrame {
            StackFrame {
                index: 0,
                pc: rustre_core::address::Address::new(pc),
                sp: rustre_core::address::Address::new(0),
                fp: None,
                function_name: None,
                module: None,
                offset: None,
                source_file: None,
                source_line: None,
            }
        }

        // Bounded: the offset is the distance from the function start.
        let mut frames = vec![frame_at(0x1000 + 0x1C)];
        enrich_frames(&mut frames, &At(0x1000, true));
        assert_eq!(frames[0].function_name.as_deref(), Some("work"));
        assert_eq!(
            frames[0].offset,
            Some(0x1C),
            "a named frame still cannot say where inside the function it is"
        );

        // Unbounded: the name is marked as a guess, and the offset must not be
        // reported at all.
        let mut frames = vec![frame_at(0x1000 + 0x1C)];
        enrich_frames(&mut frames, &At(0x1000, false));
        assert!(frames[0].function_name.as_deref().is_some_and(|n| n.ends_with(NEAREST_SYMBOL_MARKER)));
        assert_eq!(
            frames[0].offset, None,
            "an offset was measured from a nearest-preceding guess and printed like a real one"
        );

        // A pc BELOW the claimed start is a contradiction; no offset from it.
        let mut frames = vec![frame_at(0x0FF0)];
        enrich_frames(&mut frames, &At(0x1000, true));
        assert_eq!(frames[0].offset, None, "a negative offset was invented");
    }
    use super::*;
    use crate::source_map::{
        FileEntry, LineRowFlags, LineTableHeader, LineTableRow, SourceMap, SourceRootMapper,
    };
    use crate::Address;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn frame_at(pc: u64) -> StackFrame {
        StackFrame {
            index: 0,
            pc: Address(pc),
            sp: Address(0),
            fp: None,
            function_name: None,
            module: None,
            offset: None,
            source_file: None,
            source_line: None,
        }
    }

    // Mirrors `source_map::tests::make_simple_map`: two functions, `main` at
    // 0x1000-range and `foo` at 0x2000, so a PC inside either resolves.
    fn sample_map() -> SourceMap {
        let mapper = SourceRootMapper::new();
        let mut functions = HashMap::new();
        functions.insert(0x1000, "main".to_string());
        functions.insert(0x2000, "foo".to_string());

        let rows = vec![
            LineTableRow { address: 0x1000, op_index: 0, file_index: 1, line: 10, column: 0,
                is_stmt: true, row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
            LineTableRow { address: 0x1010, op_index: 0, file_index: 1, line: 11, column: 0,
                is_stmt: true, row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
            LineTableRow { address: 0x2000, op_index: 0, file_index: 1, line: 42, column: 0,
                is_stmt: true, row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
        ];

        let header = LineTableHeader {
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
            standard_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
            include_directories: vec![],
            file_names: vec![FileEntry {
                name: PathBuf::from("main.c"),
                dir_index: 0,
                modification: 0,
                length: 0,
            }],
            address_size: 8,
            is_64bit: false,
            version: 4,
        };

        SourceMap::from_line_table(&rows, &header, Path::new("/src"), mapper, &functions)
    }

    #[test]
    fn resolver_maps_pc_to_function_file_line() {
        let map = sample_map();
        let sym = map.resolve_frame(0x1014).expect("pc within main should resolve");
        assert_eq!(sym.function.as_deref(), Some("main"));
        assert!(sym.file.as_deref().is_some_and(|f| f.ends_with("main.c")));
        assert_eq!(sym.line, Some(11));
    }

    #[test]
    fn unknown_pc_resolves_to_none() {
        let map = sample_map();
        // Far past the last entry (>0x1000 away) → no location.
        assert!(map.resolve_frame(0x9_0000).is_none());
    }

    #[test]
    fn enrich_fills_only_empty_fields() {
        let map = sample_map();
        let mut frames = vec![frame_at(0x2000), frame_at(0x1000)];
        // Pre-seed one frame's function to prove enrich doesn't clobber it.
        frames[0].function_name = Some("preset".to_string());

        enrich_frames(&mut frames, &map);

        // frame 0: function kept, but file/line filled from the map.
        assert_eq!(frames[0].function_name.as_deref(), Some("preset"));
        assert_eq!(frames[0].source_line, Some(42));
        assert!(frames[0].source_file.is_some());
        // frame 1: fully resolved.
        assert_eq!(frames[1].function_name.as_deref(), Some("main"));
        assert_eq!(frames[1].source_line, Some(10));
        assert!(frames[1].source_file.is_some());
    }

    /// `CodeViewProvider` implements `FrameSymbolResolver`: a function symbol
    /// at a known address must resolve its name via `resolve_frame`.
    #[test]
    fn codeview_provider_resolves_frame_name() {
        use crate::codeview::build_test_gproc32;

        // Build a GPROC32 record for "my_fn" at section-relative offset 0x100,
        // rebased by image_base=0x1000 → VA 0x1100.
        let data = build_test_gproc32("my_fn", 0x100, 1, 0);
        let provider = CodeViewProvider::from_bytes(&data, 0x1000)
            .expect("should parse a well-formed GPROC32");

        // resolve_frame at the exact start address.
        let sym = provider
            .resolve_frame(0x1100)
            .expect("should resolve the function");
        assert_eq!(sym.function.as_deref(), Some("my_fn"));

        // resolve_frame a few bytes inside the function — lookup_nearest still
        // returns the enclosing symbol.
        let sym_inside = provider
            .resolve_frame(0x1108)
            .expect("should resolve inside the function");
        assert_eq!(sym_inside.function.as_deref(), Some("my_fn"));
    }

    /// A backtrace must not present a nearest-preceding guess the same way it
    /// presents a verified symbol.
    ///
    /// `bounded` was introduced in iter 276 and then consumed by nobody:
    /// `enrich_frames` wrote `function_name` identically either way, so the
    /// distinction existed in the type and nowhere the user could see it.
    /// Honest information that never reaches the reader is not honesty.
    #[test]
    fn an_unbounded_symbol_is_marked_in_the_frame_it_names() {
        use crate::codeview::build_test_gproc32;

        // One symbol: nothing bounds it above, so any pc past it is a guess.
        let lone = CodeViewProvider::from_bytes(&build_test_gproc32("only_fn", 0x100, 1, 0), 0x1000)
            .expect("well-formed GPROC32");
        let mut frames = vec![frame_at(0x9_0000)];
        enrich_frames(&mut frames, &lone);
        assert_eq!(
            frames[0].function_name.as_deref(),
            Some(&*format!("only_fn{NEAREST_SYMBOL_MARKER}")),
            "an unbounded match must say so where the reader will see it"
        );

        // A successor bounds the first symbol, so this one is containment.
        let mut two = build_test_gproc32("first", 0x100, 1, 0);
        two.extend_from_slice(&build_test_gproc32("second", 0x200, 1, 0));
        let provider = CodeViewProvider::from_bytes(&two, 0x1000).expect("two GPROC32 records");
        let mut inside = vec![frame_at(0x1108)];
        enrich_frames(&mut inside, &provider);
        assert_eq!(
            inside[0].function_name.as_deref(),
            Some("first"),
            "a bounded match must NOT be marked — the marker has to stay meaningful"
        );
    }

    /// `lookup_nearest` is nearest-preceding and unbounded, so a pc in another
    /// module gets named after the last symbol of this one. The provider cannot
    /// tell that apart from a pc genuinely inside that last function — nothing
    /// in its data bounds the symbol above. What it CAN do is stop presenting
    /// the two as equally certain, which is what `bounded` records.
    #[test]
    fn an_unbounded_nearest_match_is_not_reported_as_containment() {
        use crate::codeview::build_test_gproc32;

        // One symbol only: nothing bounds it from above, no line table.
        let one = CodeViewProvider::from_bytes(&build_test_gproc32("only_fn", 0x100, 1, 0), 0x1000)
            .expect("well-formed GPROC32");
        let far = one
            .resolve_frame(0x9_0000)
            .expect("nearest-preceding still answers");
        assert_eq!(far.function.as_deref(), Some("only_fn"));
        assert!(
            !far.bounded,
            "a pc 0x8ef00 past a size-less last symbol cannot be claimed as containment"
        );

        // A successor bounds the first symbol, so a pc below it IS contained.
        let mut two = build_test_gproc32("first", 0x100, 1, 0);
        two.extend_from_slice(&build_test_gproc32("second", 0x200, 1, 0));
        let provider = CodeViewProvider::from_bytes(&two, 0x1000).expect("two GPROC32 records");
        let inside = provider.resolve_frame(0x1108).expect("inside `first`");
        assert_eq!(inside.function.as_deref(), Some("first"));
        assert!(inside.bounded, "a later symbol bounds `first`, so this is containment");
    }
}
