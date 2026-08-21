//! Joining the two halves of an Apple backtrace: **names** from the Mach-O
//! symbol table and **`file:line`** from a `.dSYM`.
//!
//! Neither source is sufficient alone, and that is a property of the formats,
//! not of this crate:
//!
//! * [`crate::ios::symbolication::Symbolicator`] reads `LC_SYMTAB` /
//!   `LC_FUNCTION_STARTS`. Those carry addresses and names and *nothing else* —
//!   its `FrameSymbolResolver` impl documents that it deliberately leaves
//!   `file`/`line` as `None` rather than inventing them.
//! * [`crate::ios::dsym::DsymLineMapper`] reads the DWARF line program out of a
//!   `.dSYM` bundle. That gives exact `file:line` rows but no function symbol
//!   for a stripped release build, because the dSYM's `.debug_info` describes
//!   compile units, not the linker's symbol table.
//!
//! So an Apple frame enriched by the symbolicator alone reads
//! `MyApp`swift_fn` (no file, no line)`, and one enriched by the dSYM alone
//! reads `main.swift:42 (no name)`. [`AppleFrameResolver`] holds both and emits
//! one complete [`crate::symbol_resolver::ResolvedFrameSymbol`].
//!
//! # What this module refuses to do
//!
//! A dSYM is paired to an image **by `LC_UUID` and by nothing else**. Two
//! builds of the same source produce byte-identical file names and wildly
//! different addresses, so a dSYM attached to the wrong image yields line
//! numbers that are plausible, precise, and wrong — the single most misleading
//! failure a debugger can have. [`AppleFrameResolver::attach_dsym`] therefore
//! rejects, as hard errors:
//!
//! * a dSYM with no `LC_UUID` (cannot be verified, so it is not trusted),
//! * a dSYM whose UUID matches no loaded image (nothing to anchor its slide to),
//! * a second dSYM for an image that already has one.
//!
//! At lookup time the mapper consulted is the one registered for the UUID of
//! the image that *contains* the `pc`. A `pc` in an image with no dSYM gets a
//! name and no coordinates, which is the honest answer.

use std::collections::HashMap;

use crate::ios::dsym::{DsymBundle, DsymLineMapper, format_uuid};
use crate::ios::symbolication::{ResolvedAddress, Symbolication, Symbolicator};
use crate::StackFrame;
use crate::source_map::SourceRootMapper;
use crate::symbol_resolver::{FrameSymbolResolver, ResolvedFrameSymbol, enrich_frames};

/// Why a dSYM could not be attached to a symbolicator.
///
/// Each variant is a different user action — fetch symbols, rebuild, fix the
/// call site — which is why they are not one opaque string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameResolverError {
    /// The dSYM payload has no `LC_UUID`, so it cannot be proven to belong to
    /// any image. Accepting it would mean trusting the file name.
    #[error("dSYM {path} has no LC_UUID, so it cannot be matched to an image")]
    DsymHasNoUuid {
        /// Payload path, for the diagnostic.
        path: String,
    },

    /// No loaded image carries this dSYM's UUID. Without the owning image there
    /// is no ASLR slide to apply, and static line addresses would be reported
    /// as if the image had loaded at its link-time base.
    #[error("no loaded image has UUID {uuid} (dSYM {path}); it belongs to a different build")]
    NoImageWithUuid {
        /// The dSYM's UUID.
        uuid: String,
        /// Payload path.
        path: String,
    },

    /// A dSYM is already registered for that image.
    #[error("image {module} (UUID {uuid}) already has a dSYM attached")]
    DuplicateDsym {
        /// Module name of the image.
        module: String,
        /// The image UUID.
        uuid: String,
    },

    /// Building the line index out of the DWARF failed.
    #[error("dSYM {path}: {source}")]
    Dsym {
        /// Payload path.
        path: String,
        /// Underlying dSYM/DWARF error.
        #[source]
        source: crate::ios::dsym::DsymError,
    },
}

/// A [`crate::symbol_resolver::FrameSymbolResolver`] that answers with names *and* source coordinates.
///
/// Built from a [`Symbolicator`] (one or more loaded images with their slides)
/// plus zero or more dSYMs attached by UUID.
#[derive(Debug)]
pub struct AppleFrameResolver {
    symbols: Symbolicator,
    /// Line mappers keyed by the `LC_UUID` of the image they were verified
    /// against. Keying by UUID rather than by module name or index is the whole
    /// safety property: a name collision between two loaded dylibs cannot cause
    /// one image's dSYM to be consulted for another's addresses.
    mappers: HashMap<[u8; 16], DsymLineMapper>,
}

impl AppleFrameResolver {
    /// Wrap a symbolicator with no dSYMs yet: behaves exactly like the plain
    /// [`Symbolicator`] resolver (names, no coordinates) until one is attached.
    #[must_use]
    pub fn new(symbols: Symbolicator) -> Self {
        Self {
            symbols,
            mappers: HashMap::new(),
        }
    }

    /// Attach a dSYM, verifying it against a loaded image by `LC_UUID` and
    /// adopting that image's ASLR slide.
    ///
    /// Returns the UUID the bundle was bound to, so a caller that walked a
    /// directory of bundles can report which image each one served.
    pub fn attach_dsym(
        &mut self,
        bundle: &DsymBundle,
        source_roots: &SourceRootMapper,
    ) -> Result<[u8; 16], FrameResolverError> {
        let path = bundle.dwarf_path.display().to_string();
        let Some(uuid) = bundle.uuid else {
            return Err(FrameResolverError::DsymHasNoUuid { path });
        };
        let Some(image) = self.symbols.image_by_uuid(uuid) else {
            return Err(FrameResolverError::NoImageWithUuid {
                uuid: format_uuid(&uuid),
                path,
            });
        };
        if self.mappers.contains_key(&uuid) {
            return Err(FrameResolverError::DuplicateDsym {
                module: image.name().to_string(),
                uuid: format_uuid(&uuid),
            });
        }
        // The slide comes from the image, never from the dSYM: the dSYM knows
        // only link-time addresses.
        let slide = image.slide();
        let mapper = DsymLineMapper::from_bundle(bundle, source_roots)
            .map_err(|source| FrameResolverError::Dsym { path, source })?
            .with_slide(slide);
        self.mappers.insert(uuid, mapper);
        Ok(uuid)
    }

    /// Number of dSYMs successfully attached.
    #[must_use]
    pub fn dsym_count(&self) -> usize {
        self.mappers.len()
    }

    /// `true` when the image with this UUID has line information available.
    #[must_use]
    pub fn has_dsym_for_uuid(&self, uuid: [u8; 16]) -> bool {
        self.mappers.contains_key(&uuid)
    }

    /// The wrapped symbolicator.
    #[must_use]
    pub const fn symbolicator(&self) -> &Symbolicator {
        &self.symbols
    }

    /// The line mapper registered for an image UUID, if any.
    #[must_use]
    pub fn mapper_for_uuid(&self, uuid: [u8; 16]) -> Option<&DsymLineMapper> {
        self.mappers.get(&uuid)
    }

    /// Full symbol-table answer for `pc` (module, raw + demangled name, offset).
    #[must_use]
    pub fn resolve_address(&self, pc: u64) -> Option<ResolvedAddress> {
        self.symbols.resolve(pc)
    }

    /// Line mapper belonging to the image that *contains* `pc`.
    ///
    /// The containment test is the point: it is what stops one image's dSYM
    /// from being asked about another image's addresses.
    fn mapper_containing(&self, pc: u64) -> Option<&DsymLineMapper> {
        let uuid = self.symbols.image_for(pc)?.uuid()?;
        self.mappers.get(&uuid)
    }

    /// The combined name + coordinates answer for one lookup key.
    ///
    /// `lookup_pc` is the address the tables are *asked about*, which is not
    /// always the address being reported — see [`Self::resolve_return_address`].
    fn resolve_at(&self, lookup_pc: u64) -> Option<ResolvedFrameSymbol> {
        // `bounded` is a claim about *containment*, and Mach-O supports it
        // exactly twice: `ImageSymbols::resolve` only returns `Nlist` or
        // `FunctionStart` when `pc` lies below the next symbol/function start
        // *and* inside a mapped segment, so both are demonstrated containment.
        // `ModuleOnly` is the third rung — no symbol covered the address and the
        // "name" returned is the module's own — so it must not be reported as a
        // containing function.
        let resolved_addr = self.symbols.resolve(lookup_pc);
        let bounded = resolved_addr
            .as_ref()
            .is_some_and(|r| !matches!(r.source, Symbolication::ModuleOnly));
        // The symbol's own runtime address, kept so the frame can be rendered
        // as `func+0x1c`. Only for a BOUNDED match: a module-only "name" would
        // otherwise yield an offset measured from the image base and printed as
        // if it were a function offset.
        let start = bounded.then(|| resolved_addr.as_ref().map(|r| r.symbol_address)).flatten();
        let function = resolved_addr.map(|r| r.display_name().to_string());
        let (file, line) = self
            .mapper_containing(lookup_pc)
            .and_then(|m| m.runtime_addr_to_source(lookup_pc))
            .map_or((None, None), |loc| {
                (
                    Some(loc.file.to_string_lossy().into_owned()),
                    Some(loc.line),
                )
            });
        let resolved = ResolvedFrameSymbol {
            function,
            file,
            // A dSYM line row exists only for an address the line table
            // actually covers, so it is independent evidence of containment.
            bounded: bounded || line.is_some(),
            line,
            start,
        };
        (!resolved.is_empty()).then_some(resolved)
    }

    /// Symbolicate frame `frame_index` of a backtrace, whose stored pc is
    /// `pc`.
    ///
    /// Only frame 0 is stopped *at* its pc. Every outer frame's pc is a
    /// **return address**: the address of the instruction after the `bl`. When
    /// that call is the last instruction of its function the return address is
    /// the first byte of the NEXT function, so looking it up verbatim names a
    /// function the thread was never inside — and, worse, reports it with
    /// `bounded: true`, the demonstrated-containment claim this module exists
    /// to keep honest.
    ///
    /// [`crate::ios::unwind::AppleUnwinder`] already applies exactly this
    /// correction to its own table lookups (`unwind.rs`: `let lookup_pc = if
    /// depth > 1 { regs.pc.wrapping_sub(1) } else { regs.pc }`). The
    /// symbolicator has to agree with the unwinder about which function a pc
    /// belongs to, or the same frame is attributed to two different functions
    /// by two halves of the same backtrace.
    ///
    /// Only the LOOKUP key moves; the reported pc, and therefore the
    /// `func+0x1c` offset derived from `start`, still refer to the exact
    /// return address.
    #[must_use]
    pub fn resolve_frame_at(&self, pc: u64, frame_index: usize) -> Option<ResolvedFrameSymbol> {
        if frame_index == 0 {
            self.resolve_at(pc)
        } else {
            self.resolve_return_address(pc)
        }
    }

    /// Symbolicate a pc that is known to be a **return address**, i.e. the
    /// value a `bl` pushed, not an address the thread ever executed.
    ///
    /// The frame index is not always to hand (a caller may hold a single
    /// return address recovered from `lr` or from a frame record), so this is
    /// the index-free spelling of [`Self::resolve_frame_at`] with a non-zero
    /// index.
    #[must_use]
    pub fn resolve_return_address(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        // `wrapping_sub` and not a saturating/checked form on purpose: a pc of
        // 0 is not a return address any call could have produced, and
        // `u64::MAX` lies in no mapped image, so it resolves to nothing —
        // which is the honest answer for a corrupt frame.
        self.resolve_at(pc.wrapping_sub(1))
    }

    /// Runtime addresses a `file:line` breakpoint should be planted at, across
    /// every attached dSYM. Each mapper already applies its own image's slide.
    #[must_use]
    pub fn source_to_runtime_addrs(&self, file: &str, line: u32) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .mappers
            .values()
            .flat_map(|m| m.source_to_runtime_addrs(file, line))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// The combined answer.
///
/// `function` comes from the symbol table, `file`/`line` from the dSYM of the
/// containing image. Either half may be absent — a stripped image yields no
/// name, an image with no dSYM yields no coordinates — and the result is
/// whatever was actually established, never a filled-in guess.
///
/// The trait carries a bare `pc` and no frame index, so this impl can only
/// answer for the **innermost** frame, the one the thread is actually stopped
/// at. A caller walking a whole backtrace must use [`enrich_apple_backtrace`]
/// (or [`AppleFrameResolver::resolve_frame_at`] for a single frame) instead,
/// or every outer frame is symbolicated at its return address — which, for a
/// call in tail position, names the following function.
impl FrameSymbolResolver for AppleFrameResolver {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        self.resolve_at(pc)
    }
}

/// Any [`FrameSymbolResolver`], seen as one that answers for **return
/// addresses**.
///
/// [`AppleFrameResolver::resolve_return_address`] is the same correction
/// spelled on the concrete type; this is the form that survives the
/// `Arc<dyn FrameSymbolResolver>` a backend actually stores, which erases
/// every method except [`FrameSymbolResolver::resolve_frame`]. That erasure is
/// why the correction could not previously reach a live backtrace: the
/// resolver installed by `AppleDebugger::load_symbols_from_target` is a
/// trait object, and half the time it is not an [`AppleFrameResolver`] at all
/// but the bare [`Symbolicator`] installed when no dSYM is present. Wrapping
/// the trait object fixes both.
pub struct ReturnAddressResolver<'a> {
    inner: &'a dyn FrameSymbolResolver,
}

impl<'a> ReturnAddressResolver<'a> {
    /// Wrap `inner` so every lookup is moved back into the calling
    /// instruction.
    #[must_use]
    pub const fn new(inner: &'a dyn FrameSymbolResolver) -> Self {
        Self { inner }
    }
}

impl FrameSymbolResolver for ReturnAddressResolver<'_> {
    /// `wrapping_sub` and not a saturating/checked form on purpose: a pc of 0
    /// is not a return address any call could have produced, and `u64::MAX`
    /// lies in no mapped image, so it resolves to nothing — the honest answer
    /// for a corrupt frame.
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        self.inner.resolve_frame(pc.wrapping_sub(1))
    }
}

/// Fill in a whole Apple backtrace, applying the return-address correction to
/// every frame that needs it.
///
/// This is [`crate::symbol_resolver::enrich_frames`] with the one piece of
/// knowledge that function cannot have: only frame 0 is stopped *at* its pc.
/// Every outer frame's pc is the address of the instruction after a `bl`, and
/// when that `bl` is the last instruction of its function the return address
/// is the first byte of the NEXT function. Looking it up verbatim names a
/// function the thread was never inside, reports it `bounded`, and measures
/// the `func+0x1c` offset from that stranger's entry.
///
/// [`crate::ios::unwind::AppleUnwinder`] already applies exactly this
/// correction to its own table lookups — `unwind.rs` computes
/// `let lookup_pc = if depth > 1 { regs.pc.wrapping_sub(1) } else { regs.pc }`.
/// The symbolicator has to agree with the unwinder about which function a pc
/// belongs to, or the two halves of one backtrace attribute the same frame to
/// two different functions.
///
/// Only the LOOKUP key moves: the frame's stored pc is untouched, so the
/// reported address is still the exact return address.
pub fn enrich_apple_backtrace(frames: &mut [StackFrame], resolver: &dyn FrameSymbolResolver) {
    // `min(1)` and not a bare `1`: an empty backtrace is a legitimate outcome
    // (a thread whose registers could not be read), and `split_at_mut(1)`
    // would panic on it.
    let (innermost, outer) = frames.split_at_mut(frames.len().min(1));
    enrich_frames(innermost, resolver);
    enrich_frames(outer, &ReturnAddressResolver::new(resolver));
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::symbolication::{ArchPreference, ImageSymbols};
    use crate::symbol_resolver::enrich_frames;
    use crate::{Address, StackFrame};
    use std::path::Path;

    // ── DWARF/Mach-O fixture builders ───────────────────────────────────────
    //
    // Deliberately local rather than shared with `dsym::tests` /
    // `symbolication::tests`: this module's whole job is to make two
    // *independently produced* artefacts agree, so the test must be able to
    // produce them with mismatched UUIDs and mismatched addresses on purpose.

    fn uleb(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return;
            }
        }
    }

    fn sleb(mut v: i64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            let sign = b & 0x40 != 0;
            if (v == 0 && !sign) || (v == -1 && sign) {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn cstr(s: &str, out: &mut Vec<u8>) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    /// A DWARF 4 line program over `[base, base+8)` in `main.swift`:
    /// row at `base` → line 10, row at `base+4` → line 11, end at `base+8`.
    fn build_debug_line_v4(base: u64) -> Vec<u8> {
        let mut header_tail = Vec::new();
        header_tail.push(1); // minimum_instruction_length
        header_tail.push(1); // maximum_ops_per_instruction
        header_tail.push(1); // default_is_stmt
        header_tail.push(0xFB); // line_base = -5
        header_tail.push(14); // line_range
        header_tail.push(13); // opcode_base
        header_tail.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        header_tail.push(0); // no include_directories
        cstr("main.swift", &mut header_tail);
        uleb(0, &mut header_tail); // dir 0 == comp dir
        uleb(0, &mut header_tail);
        uleb(0, &mut header_tail);
        header_tail.push(0); // end of file names

        let mut prog = Vec::new();
        prog.push(0); // DW_LNE_set_address
        uleb(9, &mut prog);
        prog.push(0x02);
        prog.extend_from_slice(&base.to_le_bytes());
        prog.push(0x03); // advance_line +9 → 10
        sleb(9, &mut prog);
        prog.push(0x01); // copy
        prog.push(0x02); // advance_pc 4
        uleb(4, &mut prog);
        prog.push(0x03); // advance_line +1 → 11
        sleb(1, &mut prog);
        prog.push(0x01); // copy
        prog.push(0x02); // advance_pc 4
        uleb(4, &mut prog);
        prog.push(0); // DW_LNE_end_sequence
        uleb(1, &mut prog);
        prog.push(0x01);

        let mut out = Vec::new();
        let header_len = u32::try_from(header_tail.len()).unwrap();
        let unit_len = 2 + 4 + header_len + u32::try_from(prog.len()).unwrap();
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header_tail);
        out.extend_from_slice(&prog);
        out
    }

    /// One abbreviation: a compile unit with `name/comp_dir/low_pc/stmt_list`.
    fn build_debug_abbrev() -> Vec<u8> {
        let mut out = Vec::new();
        uleb(1, &mut out); // code
        uleb(0x11, &mut out); // DW_TAG_compile_unit
        out.push(0); // no children
        uleb(0x03, &mut out); // DW_AT_name
        uleb(0x08, &mut out); // DW_FORM_string
        uleb(0x1b, &mut out); // DW_AT_comp_dir
        uleb(0x08, &mut out);
        uleb(0x11, &mut out); // DW_AT_low_pc
        uleb(0x01, &mut out); // DW_FORM_addr
        uleb(0x10, &mut out); // DW_AT_stmt_list
        uleb(0x17, &mut out); // DW_FORM_sec_offset
        uleb(0, &mut out);
        uleb(0, &mut out); // end of attributes
        uleb(0, &mut out); // end of table
        out
    }

    fn build_debug_info(low_pc: u64, stmt_list: u32) -> Vec<u8> {
        let mut die = Vec::new();
        uleb(1, &mut die);
        cstr("main.swift", &mut die);
        cstr("/build/proj", &mut die);
        die.extend_from_slice(&low_pc.to_le_bytes());
        die.extend_from_slice(&stmt_list.to_le_bytes());

        let mut out = Vec::new();
        let unit_len = 2 + 4 + 1 + u32::try_from(die.len()).unwrap();
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
        out.push(8); // address size
        out.extend_from_slice(&die);
        out
    }

    const LC_UUID: u32 = 0x1B;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x02;
    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const CPU_TYPE_ARM64: u32 = 0x0100_000C;
    const N_SECT: u8 = 0x0E;
    const N_EXT: u8 = 0x01;

    fn fixed16(name: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let b = name.as_bytes();
        let n = b.len().min(16);
        out[..n].copy_from_slice(&b[..n]);
        out
    }

    /// `MH_DSYM` Mach-O holding a `__DWARF` segment with the given sections.
    fn build_dsym_macho(uuid: [u8; 16], sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let seg_cmd_size = 72 + 80 * sections.len();
        let uuid_cmd_size = 24usize;
        let sizeofcmds = seg_cmd_size + uuid_cmd_size;
        let data_start = 32 + sizeofcmds;

        let mut offsets = Vec::new();
        let mut cursor = data_start;
        for (_, body) in sections {
            offsets.push(cursor);
            cursor += body.len();
        }
        let total_data = cursor - data_start;

        let mut out = Vec::with_capacity(cursor);
        out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        out.extend_from_slice(&10u32.to_le_bytes()); // MH_DSYM
        out.extend_from_slice(&2u32.to_le_bytes()); // ncmds
        out.extend_from_slice(&u32::try_from(sizeofcmds).unwrap().to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved

        let segname = fixed16("__DWARF");
        out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        out.extend_from_slice(&u32::try_from(seg_cmd_size).unwrap().to_le_bytes());
        out.extend_from_slice(&segname);
        out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        out.extend_from_slice(&(total_data as u64).to_le_bytes());
        out.extend_from_slice(&(data_start as u64).to_le_bytes());
        out.extend_from_slice(&(total_data as u64).to_le_bytes());
        out.extend_from_slice(&7u32.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&u32::try_from(sections.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());

        for (i, (name, body)) in sections.iter().enumerate() {
            out.extend_from_slice(&fixed16(name));
            out.extend_from_slice(&segname);
            out.extend_from_slice(&0u64.to_le_bytes()); // addr
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&u32::try_from(offsets[i]).unwrap().to_le_bytes());
            // align, reloff, nreloc, flags, reserved1..3 — seven more u32 to
            // complete the 80-byte `section_64`.
            for _ in 0..7 {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        out.extend_from_slice(&LC_UUID.to_le_bytes());
        out.extend_from_slice(&u32::try_from(uuid_cmd_size).unwrap().to_le_bytes());
        out.extend_from_slice(&uuid);

        assert_eq!(out.len(), data_start, "load commands must end where data starts");
        for (_, body) in sections {
            out.extend_from_slice(body);
        }
        out
    }

    /// Executable Mach-O: one `__TEXT` segment, an `LC_SYMTAB`, an `LC_UUID`.
    fn build_exec_macho(
        uuid: [u8; 16],
        text_vmaddr: u64,
        text_size: u64,
        syms: &[(&str, u64)],
    ) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut strx = Vec::new();
        for (name, _) in syms {
            strx.push(u32::try_from(strtab.len()).unwrap());
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let seg_cmdsize: u32 = 72 + 80;
        let symtab_cmdsize: u32 = 24;
        let uuid_cmdsize: u32 = 24;
        let sizeofcmds = seg_cmdsize + symtab_cmdsize + uuid_cmdsize;
        let symoff = 32 + sizeofcmds;
        let nsyms = u32::try_from(syms.len()).unwrap();
        let stroff = symoff + nsyms * 16;

        let mut b = Vec::new();
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&3u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&fixed16("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // nsects
        b.extend_from_slice(&0u32.to_le_bytes());
        // section_64 __text
        b.extend_from_slice(&fixed16("__text"));
        b.extend_from_slice(&fixed16("__TEXT"));
        b.extend_from_slice(&text_vmaddr.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // offset
        b.extend_from_slice(&4u32.to_le_bytes()); // align
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0x8000_0400u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        b.extend_from_slice(&symtab_cmdsize.to_le_bytes());
        b.extend_from_slice(&symoff.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&stroff.to_le_bytes());
        b.extend_from_slice(&u32::try_from(strtab.len()).unwrap().to_le_bytes());

        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&uuid_cmdsize.to_le_bytes());
        b.extend_from_slice(&uuid);

        assert_eq!(b.len(), symoff as usize, "load commands must end at symoff");
        for ((_, value), sx) in syms.iter().zip(&strx) {
            b.extend_from_slice(&sx.to_le_bytes());
            b.push(N_SECT | N_EXT);
            b.push(1); // n_sect
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(b.len(), stroff as usize, "nlist array must end at stroff");
        b.extend_from_slice(&strtab);
        b
    }

    const APP_UUID: [u8; 16] = [
        0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const OTHER_UUID: [u8; 16] = [
        0xBB, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];

    /// Static layout shared by the fixtures: `__TEXT` at `0x1_0000_0000`,
    /// `_main` at `0x1_0000_1000`, line rows over `0x1_0000_1000..0x1_0000_1008`.
    const STATIC_BASE: u64 = 0x1_0000_0000;
    const STATIC_FN: u64 = 0x1_0000_1000;

    fn dwarf_sections(low_pc: u64) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("__debug_line", build_debug_line_v4(low_pc)),
            ("__debug_abbrev", build_debug_abbrev()),
            ("__debug_info", build_debug_info(low_pc, 0)),
            ("__debug_str", b"\0".to_vec()),
        ]
    }

    fn app_dsym(uuid: [u8; 16], low_pc: u64) -> DsymBundle {
        let macho = build_dsym_macho(uuid, &dwarf_sections(low_pc));
        DsymBundle::from_payload_bytes(Path::new("MyApp.dSYM/.../MyApp"), &macho)
            .expect("synthetic dSYM payload should parse")
    }

    /// The image as the target reports it: loaded at `runtime_base`, so the
    /// slide is `runtime_base - STATIC_BASE`.
    fn app_image(uuid: [u8; 16], runtime_base: u64) -> ImageSymbols {
        let macho = build_exec_macho(uuid, STATIC_BASE, 0x4000, &[("_main", STATIC_FN)]);
        ImageSymbols::from_bytes("MyApp", &macho, ArchPreference::Arm64)
            .expect("synthetic executable should parse")
            .with_runtime_base(runtime_base)
            .expect("image has a mapped segment to anchor the slide")
    }

    fn resolver_with_slide(slide: u64) -> AppleFrameResolver {
        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE + slide));
        let mut r = AppleFrameResolver::new(sym);
        r.attach_dsym(&app_dsym(APP_UUID, STATIC_FN), &SourceRootMapper::new())
            .expect("matching UUID must attach");
        r
    }

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

    // ── the fixtures themselves must be sound ───────────────────────────────

    /// If either half of the fixture is broken the combination tests below
    /// would pass or fail for the wrong reason, so both halves are asserted
    /// separately first.
    #[test]
    fn fixtures_produce_a_name_and_a_line_independently() {
        let image = app_image(APP_UUID, STATIC_BASE);
        let resolved = image
            .resolve(STATIC_FN + 4)
            .expect("symbol table alone must name the address");
        assert_eq!(resolved.symbol, "_main", "got {resolved:?}");

        let mapper =
            DsymLineMapper::from_bundle(&app_dsym(APP_UUID, STATIC_FN), &SourceRootMapper::new())
                .expect("dSYM alone must build a line index");
        let loc = mapper
            .static_addr_to_source(STATIC_FN + 4)
            .expect("dSYM alone must give a line");
        assert_eq!(loc.line, 11, "got {loc:?}");
    }

    /// The gap this module exists to close: the symbolicator names the frame
    /// but reports no coordinates at all.
    #[test]
    fn symbolicator_alone_has_no_file_or_line() {
        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE));
        let got = sym
            .resolve_frame(STATIC_FN + 4)
            .expect("symbolicator resolves the name");
        assert_eq!(got.function.as_deref(), Some("main"));
        assert_eq!(
            (got.file.as_deref(), got.line),
            (None, None),
            "symtab has no source coordinates; got {got:?}"
        );
    }

    // ── the combination ─────────────────────────────────────────────────────

    #[test]
    fn combined_resolver_reports_name_and_line() {
        let r = resolver_with_slide(0);
        let got = r
            .resolve_frame(STATIC_FN + 4)
            .expect("pc inside the image must resolve");
        assert_eq!(got.function.as_deref(), Some("main"), "got {got:?}");
        assert_eq!(got.line, Some(11), "got {got:?}");
        assert!(
            got.file.as_deref().is_some_and(|f| f.ends_with("main.swift")),
            "file should come from the dSYM; got {got:?}"
        );
    }

    /// The reason the slide lives on the image and not on the dSYM: with the
    /// image loaded `0x10_0000` above its link-time base, the *runtime* pc must
    /// still land on the same source line, and the static pc must resolve to
    /// nothing at all.
    #[test]
    fn slide_is_applied_from_the_image_not_the_dsym() {
        const SLIDE: u64 = 0x10_0000;
        let r = resolver_with_slide(SLIDE);

        let got = r
            .resolve_frame(STATIC_FN + SLIDE + 4)
            .expect("runtime pc must resolve");
        assert_eq!(
            (got.function.as_deref(), got.line),
            (Some("main"), Some(11)),
            "got {got:?}"
        );

        assert!(
            r.resolve_frame(STATIC_FN + 4).is_none(),
            "the unslid static address is outside the loaded image and must \
             resolve to nothing, not to line 11"
        );
    }

    #[test]
    fn line_rows_map_to_the_right_lines_across_the_function() {
        let r = resolver_with_slide(0);
        for (pc, want) in [
            (STATIC_FN, 10u32),
            (STATIC_FN + 2, 10),
            (STATIC_FN + 4, 11),
            (STATIC_FN + 6, 11),
        ] {
            let got = r.resolve_frame(pc).expect("pc in range resolves");
            assert_eq!(got.line, Some(want), "pc {pc:#x} gave {got:?}");
        }
    }

    #[test]
    fn enrich_frames_fills_a_backtrace_end_to_end() {
        let r = resolver_with_slide(0);
        let mut frames = vec![frame_at(STATIC_FN), frame_at(STATIC_FN + 4)];
        enrich_frames(&mut frames, &r);

        assert_eq!(frames[0].function_name.as_deref(), Some("main"));
        assert_eq!(frames[0].source_line, Some(10), "got {:?}", frames[0]);
        assert_eq!(frames[1].source_line, Some(11), "got {:?}", frames[1]);
        assert!(
            frames.iter().all(|f| f.source_file.is_some()),
            "every frame should carry a file: {frames:?}"
        );
    }

    // ── refusals ────────────────────────────────────────────────────────────

    /// A dSYM from a different build must be rejected outright. It parses
    /// fine and its line numbers look reasonable — which is exactly why
    /// accepting it would be the worst possible outcome.
    #[test]
    fn dsym_for_another_build_is_rejected() {
        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE));
        let mut r = AppleFrameResolver::new(sym);

        let err = r
            .attach_dsym(&app_dsym(OTHER_UUID, STATIC_FN), &SourceRootMapper::new())
            .expect_err("a foreign UUID must not attach");
        match &err {
            FrameResolverError::NoImageWithUuid { uuid, .. } => {
                assert_eq!(uuid, &format_uuid(&OTHER_UUID), "got {err}");
            }
            other => panic!("expected NoImageWithUuid, got {other:?}"),
        }
        assert_eq!(r.dsym_count(), 0, "nothing may be registered after a refusal");

        // And the consequence: still a name, still no invented line.
        let got = r.resolve_frame(STATIC_FN + 4).expect("name still resolves");
        assert_eq!(got.function.as_deref(), Some("main"));
        assert_eq!((got.file, got.line), (None, None), "no line may be invented");
    }

    #[test]
    fn dsym_without_uuid_is_rejected() {
        // A payload with no LC_UUID at all: `build_dsym_macho` always writes
        // one, so build the sections and drop the command by hand.
        let sections = dwarf_sections(STATIC_FN);
        let macho = build_dsym_macho([0u8; 16], &sections);
        let bundle = DsymBundle::from_payload_bytes(Path::new("NoUuid"), &macho)
            .expect("payload parses");
        // Simulate "no LC_UUID" through the parsed struct, which is the state
        // a real stripped payload lands in.
        let bundle = DsymBundle { uuid: None, ..bundle };

        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE));
        let mut r = AppleFrameResolver::new(sym);
        let err = r
            .attach_dsym(&bundle, &SourceRootMapper::new())
            .expect_err("an unverifiable dSYM must not attach");
        assert!(
            matches!(err, FrameResolverError::DsymHasNoUuid { .. }),
            "got {err:?}"
        );
        assert_eq!(r.dsym_count(), 0);
    }

    #[test]
    fn attaching_the_same_dsym_twice_is_an_error_not_a_silent_replace() {
        let mut r = resolver_with_slide(0);
        let err = r
            .attach_dsym(&app_dsym(APP_UUID, STATIC_FN), &SourceRootMapper::new())
            .expect_err("second attach for the same image must fail");
        assert!(
            matches!(err, FrameResolverError::DuplicateDsym { .. }),
            "got {err:?}"
        );
        assert_eq!(r.dsym_count(), 1);
    }

    /// Two images loaded, one dSYM: the dSYM must serve only its own image.
    /// Both images share the same static layout here on purpose — that is the
    /// scenario where keying by anything other than UUID goes wrong.
    #[test]
    fn a_dsym_never_answers_for_another_image() {
        const SLIDE_B: u64 = 0x2000_0000;
        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE));
        sym.add_image(app_image(OTHER_UUID, STATIC_BASE + SLIDE_B));
        let mut r = AppleFrameResolver::new(sym);
        r.attach_dsym(&app_dsym(APP_UUID, STATIC_FN), &SourceRootMapper::new())
            .expect("attach for image A");

        assert!(r.has_dsym_for_uuid(APP_UUID));
        assert!(!r.has_dsym_for_uuid(OTHER_UUID));

        let in_a = r.resolve_frame(STATIC_FN + 4).expect("A resolves");
        assert_eq!(in_a.line, Some(11), "got {in_a:?}");

        let in_b = r
            .resolve_frame(STATIC_FN + SLIDE_B + 4)
            .expect("B still gets a name");
        assert_eq!(in_b.function.as_deref(), Some("main"), "got {in_b:?}");
        assert_eq!(
            (in_b.file.as_deref(), in_b.line),
            (None, None),
            "image B has no dSYM, so it must have no coordinates; got {in_b:?}"
        );
    }

    /// `bounded` must be a measurement, not a formality. An address inside the
    /// image's `__TEXT` but *below* its only symbol falls to
    /// [`Symbolication::ModuleOnly`]: the "name" handed back is the module's
    /// own, no function was shown to contain the pc, and there is no line row
    /// either. Reporting that as bounded would be exactly the "confidently
    /// wrong" claim `bounded` was added to prevent.
    #[test]
    fn a_module_only_answer_is_not_reported_as_containment() {
        let r = resolver_with_slide(0);
        let got = r
            .resolve_frame(STATIC_BASE + 0x10)
            .expect("the address is inside a mapped segment, so the module is known");
        assert_eq!(
            got.function.as_deref(),
            Some("MyApp"),
            "module-only fallback names the module; got {got:?}"
        );
        assert_eq!((got.file.as_deref(), got.line), (None, None), "got {got:?}");
        assert!(
            !got.bounded,
            "no symbol and no line row cover this pc, so it is not containment: {got:?}"
        );

        // Contrast: a pc that a symbol *and* a line row both cover.
        let inside = r.resolve_frame(STATIC_FN + 4).expect("resolves");
        assert!(inside.bounded, "got {inside:?}");
    }

    #[test]
    fn address_outside_every_image_resolves_to_nothing() {
        let r = resolver_with_slide(0);
        assert!(r.resolve_frame(0xDEAD_BEEF).is_none());
        assert!(r.resolve_frame(0).is_none());
    }

    #[test]
    fn no_dsym_attached_behaves_like_the_plain_symbolicator() {
        let mut sym = Symbolicator::new();
        sym.add_image(app_image(APP_UUID, STATIC_BASE));
        let r = AppleFrameResolver::new(sym);
        assert_eq!(r.dsym_count(), 0);
        let got = r.resolve_frame(STATIC_FN + 4).expect("name resolves");
        assert_eq!(got.function.as_deref(), Some("main"));
        assert_eq!((got.file, got.line), (None, None));
    }

    // ── reverse direction ───────────────────────────────────────────────────

    #[test]
    fn source_to_runtime_addrs_applies_the_slide() {
        const SLIDE: u64 = 0x10_0000;
        let r = resolver_with_slide(SLIDE);
        let addrs = r.source_to_runtime_addrs("main.swift", 10);
        assert!(
            addrs.contains(&(STATIC_FN + SLIDE)),
            "expected {:#x} in {addrs:#x?}",
            STATIC_FN + SLIDE
        );
        assert!(
            r.source_to_runtime_addrs("main.swift", 9999).is_empty(),
            "a line with no row must yield no address"
        );
    }

    // ── the live session path ───────────────────────────────────────────────
    //
    // Everything above proves the JOIN works in isolation. It was unreachable
    // from a session: `AppleDebugger::load_symbols_from_target` installed the
    // bare `Symbolicator`, whose `FrameSymbolResolver` impl documents that it
    // returns `file: None, line: None` — so no live backtrace could ever carry
    // source coordinates no matter how many dSYMs were on disk.

    /// Build a mock target whose `__TEXT` region really is a Mach-O image:
    /// header at the image base, executable bytes at `+0x1000`, so the
    /// symbolicator can parse it out of target memory the way it does on a
    /// device.
    fn mock_target_image(uuid: [u8; 16]) -> Vec<u8> {
        let mut img = build_exec_macho(uuid, STATIC_BASE, 0x4000, &[("_main", STATIC_FN)]);
        assert!(img.len() < 0x1000, "load commands must fit below the code");
        img.resize(0x1000, 0);
        // `ret` — the interpreter is never stepped here; the bytes only need to
        // be inside the image's `__text`.
        img.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        img.resize(0x4000, 0);
        img
    }

    /// A debugger attached to a target holding that image, stopped at
    /// `STATIC_FN + slide + 4` (the pc that the dSYM maps to line 11).
    async fn live_debugger_stopped_in_main(
        slide: u64,
    ) -> (crate::ios::apple_debugger::AppleDebugger, crate::ThreadId) {
        use crate::Debugger;
        use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
        use crate::ios::mock_debugserver::{LoadedImage, MemoryRegion, MockDebugserver, Perms};

        let runtime_base = STATIC_BASE + slide;
        let mut srv = MockDebugserver::new(4242);
        assert!(srv.memory.map(MemoryRegion::new(
            runtime_base,
            mock_target_image(APP_UUID),
            Perms::rx(),
            "__TEXT",
        )));
        const STACK_BASE: u64 = 0x1_6f00_0000;
        assert!(srv.memory.map(MemoryRegion::zeroed(
            STACK_BASE,
            64 * 1024,
            Perms::rw(),
            "Stack"
        )));
        srv.add_image(LoadedImage {
            path: "/usr/lib/MyApp".to_string(),
            load_address: runtime_base,
            slide,
            uuid: APP_UUID,
        });
        {
            let t = srv.thread_mut_for_test(1).expect("mock has thread 1");
            t.regs.pc = STATIC_FN + slide + 4;
            t.regs.sp = STACK_BASE + 64 * 1024 - 16;
            // No caller frame: this test is about frame 0's coordinates, and a
            // fabricated chain would only add noise.
            t.regs.x[29] = 0;
            t.regs.x[30] = 0;
        }
        let dbg = AppleDebugger::new(std::sync::Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(crate::ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");
        (dbg, tid)
    }

    /// THE GAP: with a matching dSYM offered, a live backtrace must carry
    /// `file:line`. Before the wiring this failed with `source_line: None`,
    /// because the session installed the symbol table alone.
    #[tokio::test]
    async fn live_backtrace_carries_file_and_line_from_a_matching_dsym() {
        use crate::Debugger;
        const SLIDE: u64 = 0x10_0000;
        let (dbg, tid) = live_debugger_stopped_in_main(SLIDE).await;
        dbg.add_dsym(app_dsym(APP_UUID, STATIC_FN));

        let frames = dbg.backtrace(tid).await.expect("backtrace");
        assert!(!frames.is_empty(), "the mock stack must yield frame 0");
        assert_eq!(frames[0].pc.as_u64(), STATIC_FN + SLIDE + 4);
        assert_eq!(
            frames[0].function_name.as_deref(),
            Some("main"),
            "symbol table half; got {:?}",
            frames[0]
        );
        assert_eq!(
            frames[0].source_line,
            Some(11),
            "dSYM half: the pc must carry its source line; got {:?}",
            frames[0]
        );
        assert!(
            frames[0]
                .source_file
                .as_deref()
                .is_some_and(|f| f.ends_with("main.swift")),
            "got {:?}",
            frames[0]
        );
        assert!(
            dbg.dsym_attach_errors().is_empty(),
            "a matching dSYM must attach cleanly: {:?}",
            dbg.dsym_attach_errors()
        );
    }

    /// The refusal, on the live path. A dSYM from another build parses, indexes
    /// and would answer with precise, plausible, WRONG lines. The frame must
    /// come back named and coordinate-less, and the reason must be reportable.
    #[tokio::test]
    async fn live_backtrace_refuses_a_uuid_mismatched_dsym() {
        use crate::Debugger;
        let (dbg, tid) = live_debugger_stopped_in_main(0).await;
        // Same source, same addresses, different build.
        dbg.add_dsym(app_dsym(OTHER_UUID, STATIC_FN));

        let frames = dbg.backtrace(tid).await.expect("backtrace");
        assert_eq!(
            frames[0].function_name.as_deref(),
            Some("main"),
            "the name half must survive the refusal; got {:?}",
            frames[0]
        );
        assert_eq!(
            (frames[0].source_file.as_deref(), frames[0].source_line),
            (None, None),
            "a mismatched dSYM must yield NO coordinates, not near-miss ones; got {:?}",
            frames[0]
        );
        let errs = dbg.dsym_attach_errors();
        assert_eq!(errs.len(), 1, "the refusal must be reported: {errs:?}");
        assert!(
            errs[0].contains(&format_uuid(&OTHER_UUID)),
            "the error must name the offending UUID: {errs:?}"
        );
    }

    /// No dSYM at all is not an error and must not degrade the name path.
    #[tokio::test]
    async fn live_backtrace_without_a_dsym_is_names_only() {
        use crate::Debugger;
        let (dbg, tid) = live_debugger_stopped_in_main(0).await;
        let frames = dbg.backtrace(tid).await.expect("backtrace");
        assert_eq!(frames[0].function_name.as_deref(), Some("main"));
        assert_eq!((frames[0].source_file.as_deref(), frames[0].source_line), (None, None));
        assert!(dbg.dsym_attach_errors().is_empty());
    }

    // ── return addresses ────────────────────────────────────────────────────

    /// `_callee` starts exactly where the line rows for `_caller` end, so the
    /// return address pushed by a call in tail position is the first byte of
    /// the next function.
    const STATIC_CALLEE: u64 = STATIC_FN + 8;

    /// Two adjacent functions in one image, with the dSYM covering only the
    /// first: `_caller` spans `[STATIC_FN, STATIC_CALLEE)` and its last
    /// instruction is the `bl`, so the pushed return address is exactly
    /// `STATIC_CALLEE`.
    fn caller_callee_symbolicator() -> Symbolicator {
        let macho = build_exec_macho(
            APP_UUID,
            STATIC_BASE,
            0x4000,
            &[("_caller", STATIC_FN), ("_callee", STATIC_CALLEE)],
        );
        let image = ImageSymbols::from_bytes("MyApp", &macho, ArchPreference::Arm64)
            .expect("synthetic executable should parse")
            .with_runtime_base(STATIC_BASE)
            .expect("image has a mapped segment to anchor the slide");
        let mut sym = Symbolicator::new();
        sym.add_image(image);
        sym
    }

    fn caller_callee_resolver() -> AppleFrameResolver {
        let mut r = AppleFrameResolver::new(caller_callee_symbolicator());
        r.attach_dsym(&app_dsym(APP_UUID, STATIC_FN), &SourceRootMapper::new())
            .expect("matching UUID must attach");
        r
    }

    /// The fixture must really put the boundary where the test claims, or the
    /// assertions below would pass for the wrong reason.
    #[test]
    fn caller_callee_fixture_really_is_adjacent() {
        let r = caller_callee_resolver();
        let last_byte_of_caller = r
            .resolve_address(STATIC_CALLEE - 1)
            .expect("the byte before the boundary is inside `_caller`");
        assert_eq!(last_byte_of_caller.symbol, "_caller", "got {last_byte_of_caller:?}");
        let boundary = r
            .resolve_address(STATIC_CALLEE)
            .expect("the boundary byte is the first byte of `_callee`");
        assert_eq!(boundary.symbol, "_callee", "got {boundary:?}");
    }

    /// Beyond the innermost frame the stored pc is a RETURN address: it points
    /// at the instruction *after* the `bl`. When the call is the last
    /// instruction of its function that address is the first byte of the NEXT
    /// function, and symbolicating it verbatim attributes the frame to a
    /// function the thread was never in — while stamping it `bounded`.
    ///
    /// The unwinder already corrects this for its own table lookups
    /// (`unwind.rs`: `let lookup_pc = if depth > 1 { pc.wrapping_sub(1) } else
    /// { pc }`); the symbolicator must agree with it on the same pc.
    #[test]
    fn a_return_address_at_a_function_boundary_names_the_caller() {
        let r = caller_callee_resolver();

        // Frame 0 stopped AT this pc, so it really is inside `_callee`.
        let innermost = r
            .resolve_frame_at(STATIC_CALLEE, 0)
            .expect("frame 0 resolves");
        assert_eq!(
            innermost.function.as_deref(),
            Some("callee"),
            "a pc the thread is stopped at is inside the function that starts there; got {innermost:?}"
        );

        // Frame 1 holds the same value as a RETURN address: the call it came
        // back from lives in `_caller`.
        let outer = r
            .resolve_frame_at(STATIC_CALLEE, 1)
            .expect("frame 1 resolves");
        assert_eq!(
            outer.function.as_deref(),
            Some("caller"),
            "a return address belongs to the function containing the call; got {outer:?}"
        );
        assert_eq!(
            outer.line,
            Some(11),
            "the source line must be the call site in `_caller`, not `_callee`'s first row; got {outer:?}"
        );
        assert_eq!(
            outer.start,
            Some(STATIC_FN),
            "the offset landmark must be `_caller`'s entry; got {outer:?}"
        );
        assert!(outer.bounded, "containment in `_caller` is demonstrated; got {outer:?}");
    }

    /// The correction must not disturb the ordinary case. A return address in
    /// the middle of its caller is already inside the right function and the
    /// right line row, so moving the lookup key back one byte must change
    /// nothing at all.
    #[test]
    fn a_mid_function_return_address_is_unchanged_by_the_correction() {
        let r = caller_callee_resolver();
        // Inside `_caller`, and inside the row that covers [+4, +8) → line 11.
        let mid = STATIC_FN + 6;
        let stopped = r.resolve_frame_at(mid, 0).expect("frame 0 resolves");
        let returned = r.resolve_frame_at(mid, 2).expect("frame 2 resolves");
        assert_eq!(
            returned, stopped,
            "a return address that is not at a function boundary must symbolicate \
             exactly like a stopped-at pc"
        );
        assert_eq!(
            (returned.function.as_deref(), returned.line),
            (Some("caller"), Some(11)),
            "got {returned:?}"
        );
    }

    /// Every non-zero index means the same thing — "this pc is a return
    /// address" — and [`AppleFrameResolver::resolve_return_address`] is the
    /// spelling for a caller that holds one without knowing its depth.
    #[test]
    fn resolve_return_address_is_the_index_free_spelling() {
        let r = caller_callee_resolver();
        let want = r
            .resolve_return_address(STATIC_CALLEE)
            .expect("a return address at the boundary resolves");
        assert_eq!(want.function.as_deref(), Some("caller"), "got {want:?}");
        for index in [1usize, 2, 7] {
            assert_eq!(
                r.resolve_frame_at(STATIC_CALLEE, index).as_ref(),
                Some(&want),
                "frame index {index} must agree with resolve_return_address"
            );
        }
        // A corrupt/absent return address must not wrap into some image.
        assert!(
            r.resolve_return_address(0).is_none(),
            "0 is not an address any `bl` could have pushed"
        );
    }

    /// The entry point the backend calls, driven directly. Frame 0 keeps its
    /// stopped-at meaning; every frame beyond it holds a return address, no
    /// matter how deep.
    #[test]
    fn enrich_apple_backtrace_corrects_every_frame_but_the_innermost() {
        let r = caller_callee_resolver();
        let mut frames = vec![
            frame_at(STATIC_CALLEE),
            frame_at(STATIC_CALLEE),
            frame_at(STATIC_CALLEE),
        ];
        enrich_apple_backtrace(&mut frames, &r);
        assert_eq!(
            frames[0].function_name.as_deref(),
            Some("callee"),
            "frame 0 stopped at this pc; got {:?}",
            frames[0]
        );
        for outer in &frames[1..] {
            assert_eq!(
                outer.function_name.as_deref(),
                Some("caller"),
                "an outer frame's pc is a return address; got {outer:?}"
            );
            assert_eq!(outer.source_line, Some(11), "got {outer:?}");
            assert_eq!(
                outer.offset,
                Some(STATIC_CALLEE - STATIC_FN),
                "the offset landmark must be `_caller`'s entry; got {outer:?}"
            );
        }
        assert!(
            frames.iter().all(|f| f.pc.as_u64() == STATIC_CALLEE),
            "only the LOOKUP key moves; the reported pc must be untouched: {frames:?}"
        );
    }

    /// With no dSYM the backend installs the bare [`Symbolicator`], not an
    /// [`AppleFrameResolver`] — so the correction must be a property of the
    /// enrichment step, not of one resolver type.
    #[test]
    fn the_correction_reaches_the_no_dsym_symbolicator_too() {
        let sym = caller_callee_symbolicator();
        let mut frames = vec![frame_at(STATIC_CALLEE), frame_at(STATIC_CALLEE)];
        enrich_apple_backtrace(&mut frames, &sym);
        assert_eq!(frames[0].function_name.as_deref(), Some("callee"));
        assert_eq!(
            frames[1].function_name.as_deref(),
            Some("caller"),
            "got {:?}",
            frames[1]
        );
    }

    /// A thread whose registers could not be read yields no frames at all, and
    /// `split_at_mut(1)` on that would panic.
    #[test]
    fn enriching_an_empty_backtrace_is_not_a_panic() {
        let r = caller_callee_resolver();
        let mut frames: Vec<StackFrame> = Vec::new();
        enrich_apple_backtrace(&mut frames, &r);
        assert!(frames.is_empty());
    }

    // ── the correction, on the path the debugger actually runs ──────────────
    //
    // Everything above resolves ONE address through a method a caller has to
    // choose. A backtrace is produced by `AppleDebugger::backtrace`, which
    // enriches the whole vector through a single entry point, so that entry
    // point is what the correction has to live in — a method nothing calls
    // fixes nothing.

    /// The same adjacent `_caller`/`_callee` pair as
    /// [`caller_callee_resolver`], laid out as a Mach-O image the target
    /// really maps, so a LIVE backtrace can cross the same boundary.
    fn mock_caller_callee_image(uuid: [u8; 16]) -> Vec<u8> {
        let mut img = build_exec_macho(
            uuid,
            STATIC_BASE,
            0x4000,
            &[("_caller", STATIC_FN), ("_callee", STATIC_CALLEE)],
        );
        assert!(img.len() < 0x1000, "load commands must fit below the code");
        img.resize(0x1000, 0);
        // `ret` — never executed; the bytes only need to be inside `__text`.
        img.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        img.resize(0x4000, 0);
        img
    }

    /// A debugger attached to a target stopped INSIDE `_callee`, whose frame
    /// record holds a saved return address of exactly `STATIC_CALLEE` — the
    /// value a `bl` in tail position pushes when the call is `_caller`'s last
    /// instruction.
    ///
    /// The unwinder is left on its default fp-chain strategy, so frame 1 is
    /// produced from `[x29+8]` exactly as it is on a device.
    async fn live_debugger_returning_into_caller()
    -> (crate::ios::apple_debugger::AppleDebugger, crate::ThreadId) {
        use crate::Debugger;
        use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
        use crate::ios::mock_debugserver::{LoadedImage, MemoryRegion, MockDebugserver, Perms};

        let mut srv = MockDebugserver::new(4242);
        assert!(srv.memory.map(MemoryRegion::new(
            STATIC_BASE,
            mock_caller_callee_image(APP_UUID),
            Perms::rx(),
            "__TEXT",
        )));
        const STACK_BASE: u64 = 0x1_6f00_0000;
        const STACK_SIZE: usize = 64 * 1024;
        const FRAME_RECORD: u64 = STACK_BASE + 0x2000;
        let mut stack = vec![0u8; STACK_SIZE];
        // [x29] = caller's fp — null, so the walk stops after frame 1.
        // [x29+8] = the saved return address.
        let lr_slot = usize::try_from(FRAME_RECORD - STACK_BASE).unwrap() + 8;
        stack[lr_slot..lr_slot + 8].copy_from_slice(&STATIC_CALLEE.to_le_bytes());
        assert!(srv.memory.map(MemoryRegion::new(
            STACK_BASE,
            stack,
            Perms::rw(),
            "Stack"
        )));
        srv.add_image(LoadedImage {
            path: "/usr/lib/MyApp".to_string(),
            load_address: STATIC_BASE,
            slide: 0,
            uuid: APP_UUID,
        });
        {
            let t = srv.thread_mut_for_test(1).expect("mock has thread 1");
            // Stopped one instruction into `_callee`.
            t.regs.pc = STATIC_CALLEE + 4;
            t.regs.sp = STACK_BASE + 0x1000;
            t.regs.x[29] = FRAME_RECORD;
            t.regs.x[30] = STATIC_CALLEE;
        }
        let dbg = AppleDebugger::new(std::sync::Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(crate::ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");
        (dbg, tid)
    }

    /// THE PRODUCT PATH. Frame 1's pc is a return address, and here it is the
    /// first byte of the NEXT function, so symbolicating it verbatim names a
    /// function the thread was never inside — and stamps it with `_callee`'s
    /// entry as the offset landmark.
    ///
    /// The unwinder already looks its own tables up at `pc - 1` for every
    /// frame beyond the innermost (`unwind.rs`: `if depth > 1 {
    /// regs.pc.wrapping_sub(1) }`). Until the same correction reaches the
    /// enrichment step the two halves of one backtrace disagree about which
    /// function a single frame belongs to.
    #[tokio::test]
    async fn a_live_backtrace_names_the_outer_frame_after_the_calling_function() {
        use crate::Debugger;
        let (dbg, tid) = live_debugger_returning_into_caller().await;
        dbg.add_dsym(app_dsym(APP_UUID, STATIC_FN));

        let frames = dbg.backtrace(tid).await.expect("backtrace");
        assert!(
            frames.len() >= 2,
            "the frame record must yield a caller frame; got {frames:?}"
        );
        assert_eq!(
            frames[1].pc.as_u64(),
            STATIC_CALLEE,
            "the fixture's whole point is a return address AT the boundary; got {:?}",
            frames[1]
        );

        // Frame 0 is stopped AT its pc and must NOT be moved.
        assert_eq!(
            frames[0].function_name.as_deref(),
            Some("callee"),
            "the innermost frame is inside the function it stopped in; got {:?}",
            frames[0]
        );

        assert_eq!(
            frames[1].function_name.as_deref(),
            Some("caller"),
            "the frame the debugger actually produces is still named after the \
             function that STARTS at the return address; got {:?}",
            frames[1]
        );
        assert_eq!(
            frames[1].source_line,
            Some(11),
            "the call site's line in `_caller`, not `_callee`'s first row; got {:?}",
            frames[1]
        );
        assert_eq!(
            frames[1].offset,
            Some(STATIC_CALLEE - STATIC_FN),
            "the offset must be measured from `_caller`'s entry; got {:?}",
            frames[1]
        );
    }

    #[test]
    fn accessors_expose_the_underlying_engines() {
        let r = resolver_with_slide(0);
        assert_eq!(r.symbolicator().image_count(), 1);
        let mapper = r.mapper_for_uuid(APP_UUID).expect("mapper registered");
        assert!(mapper.entry_count() > 0, "line index must not be empty");
        assert_eq!(mapper.uuid(), Some(APP_UUID));
        assert!(r.mapper_for_uuid(OTHER_UUID).is_none());
        let full = r
            .resolve_address(STATIC_FN + 4)
            .expect("full symbol-table answer");
        assert_eq!(full.module, "MyApp");
        assert_eq!(full.offset, 4, "got {full:?}");
    }
}
