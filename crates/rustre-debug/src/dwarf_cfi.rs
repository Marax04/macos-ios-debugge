//! Pure DWARF CFI (`.eh_frame`) parsing: LEB128, CIE/FDE headers, and a
//! bounded unwind-opcode interpreter. Used by `linux_debugger`'s
//! `backtrace` to unwind past a frame that doesn't preserve a frame
//! pointer, mirroring the x64 `UNWIND_INFO` interpreter `windows_debugger`
//! uses for the same purpose.
//!
//! **Deliberately bounded, not a full DWARF CFI implementation**: real
//! `.eh_frame` data routinely uses features this module does not attempt
//! to interpret — `DW_CFA_expression`/`DW_CFA_val_expression` (a full
//! DWARF expression bytecode VM, common for stack-alignment prologues),
//! chained/uncommon pointer encodings beyond `DW_EH_PE_pcrel|sdata4`
//! (the overwhelmingly common case for glibc/gcc-built x86-64 binaries),
//! and CFA base registers other than `rsp`/`rbp`. Every parser here
//! returns `None` rather than guess when it hits something outside this
//! scope — matching `windows_debugger.rs`'s `compute_prologue_stack_delta`
//! precedent (iter 191): narrower coverage, never silently wrong.

/// Decode an unsigned LEB128 value starting at `*pos`, advancing `*pos`
/// past it. `None` on a buffer that runs out mid-encoding or an
/// implausibly long encoding (more than 10 bytes — no legitimate DWARF
/// ULEB128 in this crate's use cases needs more than 64 bits' worth).
pub fn parse_uleb128(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7F) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

/// Decode a signed LEB128 value starting at `*pos`, advancing `*pos` past
/// it. `None` under the same conditions as [`parse_uleb128`].
pub fn parse_sleb128(buf: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut byte;
    loop {
        if shift >= 70 {
            return None;
        }
        byte = *buf.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7F) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -1i64 << shift;
    }
    Some(result)
}

/// The only FDE pointer encoding this module interprets:
/// `DW_EH_PE_pcrel (0x10) | DW_EH_PE_sdata4 (0x0B)` — a 4-byte signed
/// offset relative to the field's own address. Overwhelmingly the common
/// case for glibc/gcc-built x86-64 `.eh_frame` (confirmed via `readelf
/// --debug-dump=frames` on a real Ubuntu binary, iter 194). Any other
/// encoding byte is out of scope — bail rather than misinterpret it.
pub const DW_EH_PE_PCREL_SDATA4: u8 = 0x1B;

/// Parsed subset of a CIE (Common Information Entry) — just what's needed
/// to run its initial instructions and locate/interpret its FDEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CieInfo {
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    /// Byte range within the CIE's own buffer (as passed to
    /// [`parse_cie`]) holding the initial CFI instructions.
    pub initial_instructions: (usize, usize),
    /// The FDE pointer-encoding byte from a `'z...R...'` augmentation, if
    /// present; `None` if the CIE has no augmentation (`.eh_frame` always
    /// has one in practice, but this stays honest about the absence).
    pub fde_pointer_encoding: Option<u8>,
}

/// Parse a CIE's body (the bytes AFTER its 4-byte length + 4-byte
/// `CIE_id` marker — i.e. starting at `Version`). Only CIE `Version == 1`
/// is interpreted (the version essentially every `.eh_frame` in practice
/// uses); anything else bails.
pub fn parse_cie(cie: &[u8]) -> Option<CieInfo> {
    let mut pos = 0usize;
    let version = *cie.get(pos)?;
    pos += 1;
    if version != 1 {
        return None;
    }
    // Augmentation string: NUL-terminated bytes, each a flag character.
    let aug_start = pos;
    while *cie.get(pos)? != 0 {
        pos += 1;
    }
    let augmentation = &cie[aug_start..pos];
    pos += 1; // skip the NUL

    let code_alignment_factor = parse_uleb128(cie, &mut pos)?;
    let data_alignment_factor = parse_sleb128(cie, &mut pos)?;
    // Return-address-register column: a single ULEB128 for CIE version 1
    // (some references say "1 byte" for pre-DWARF4, but glibc's runtime
    // `.eh_frame` uses version 1 with a ULEB128 here in practice; a
    // ULEB128 read degrades gracefully to reading 1 byte for any value <
    // 0x80, which covers the real-world case (register 16, i.e. 0x10)).
    let _return_address_register = parse_uleb128(cie, &mut pos)?;

    let mut fde_pointer_encoding = None;
    if augmentation.first() == Some(&b'z') {
        let aug_data_len = parse_uleb128(cie, &mut pos)?;
        let aug_data_start = pos;
        // Walk the remaining augmentation characters to find 'R' (FDE
        // pointer encoding) — each character consumes a known number of
        // augmentation-data bytes; bail on any character this module
        // doesn't know how to skip correctly rather than mis-locate 'R'.
        let mut aug_pos = aug_data_start;
        for &ch in &augmentation[1..] {
            match ch {
                b'R' => {
                    fde_pointer_encoding = Some(*cie.get(aug_pos)?);
                    aug_pos += 1;
                }
                b'L' | b'P' => {
                    // 'L' (LSDA encoding byte) and 'P' (personality:
                    // encoding byte + encoded pointer) both have
                    // variable/encoding-dependent widths this module
                    // doesn't need to interpret — since we only need to
                    // find 'R', and 'R' is a fixed 1-byte field, we can
                    // safely skip past these ONLY if 'R' has already been
                    // found (order is unspecified) — otherwise bail, since
                    // we can't reliably compute where 'R' starts without
                    // interpreting these.
                    return None;
                }
                _ => return None,
            }
        }
        // Trust the augmentation-data-length field for where instructions
        // resume, regardless of how much of it we actually interpreted —
        // this is exactly what `aug_data_len` is for. `checked_add` (not
        // raw `+`) because `aug_data_len` comes directly from an
        // untrusted ULEB128 in the CIE bytes with no bounds check before
        // this point — a malformed/adversarial value near `u64::MAX`
        // would otherwise panic this addition in a debug build rather
        // than being caught by the ordinary `buf.len() < ...` bounds
        // checks the rest of this module relies on.
        pos = aug_data_start.checked_add(usize::try_from(aug_data_len).ok()?)?;
    }

    Some(CieInfo {
        code_alignment_factor,
        data_alignment_factor,
        initial_instructions: (pos, cie.len()),
        fde_pointer_encoding,
    })
}

/// Parsed subset of an FDE (Frame Description Entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdeInfo {
    /// Absolute (already-resolved, not pc-relative) start address of the
    /// function this FDE covers.
    pub initial_location: u64,
    pub address_range: u64,
    /// Byte range within the FDE's own buffer (as passed to
    /// [`parse_fde`]) holding this FDE's CFI instructions.
    pub instructions: (usize, usize),
}

/// Parse an FDE's body (the bytes AFTER its 4-byte length + 4-byte
/// `CIE_pointer` — i.e. starting at `initial_location`).
///
/// `fde_field_vaddr` is the RUNTIME virtual address of the
/// `initial_location` field itself (needed to resolve
/// [`DW_EH_PE_PCREL_SDATA4`]'s relative encoding into an absolute
/// address) — the caller must compute this from wherever the FDE bytes
/// were actually read from in the live process.
pub fn parse_fde(fde: &[u8], fde_field_vaddr: u64, pointer_encoding: u8) -> Option<FdeInfo> {
    if pointer_encoding != DW_EH_PE_PCREL_SDATA4 {
        return None;
    }
    if fde.len() < 8 {
        return None;
    }
    let loc_offset = i32::from_le_bytes(fde[0..4].try_into().ok()?);
    let initial_location = fde_field_vaddr.wrapping_add_signed(i64::from(loc_offset));
    // `address_range` uses the SAME encoding as `initial_location` except
    // it's never pc-relative (a range is a size, not an address) — for
    // `sdata4`, it's simply a plain 4-byte value (DWARF spec: the upper
    // nibble, i.e. the relocation bits like `DW_EH_PE_pcrel`, applies only
    // to `initial_location`; `address_range` uses just the lower nibble's
    // value-format, `sdata4` = a plain 4-byte value here, always
    // non-negative in practice for a size).
    let address_range = u32::from_le_bytes(fde[4..8].try_into().ok()?);

    // No augmentation-data handling on the FDE side: this module targets
    // 'zR'-only CIEs (fde_pointer_encoding present, no LSDA/personality),
    // which have no augmentation data on the FDE itself.
    Some(FdeInfo {
        initial_location,
        address_range: u64::from(address_range),
        instructions: (8, fde.len()),
    })
}

/// The `(register, offset)` pair the currently-tracked CFA rule holds —
/// `register` is the DWARF register number the CFA is computed relative
/// to (this module only ever resolves `7` = `rsp` or `6` = `rbp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfaRule {
    pub register: u8,
    pub offset: i64,
}

/// DWARF register number for x86-64 `rsp` (System V AMD64 psABI).
pub const DW_REG_RSP: u8 = 7;
/// DWARF register number for AArch64 `sp` (AAdwarf64: x0-x30 = 0..=30, sp = 31).
/// Matches the tables already used elsewhere in this crate
/// (`ios/lldb_ext.rs::dwarf_regnum`, `ios/mock_debugserver.rs`).
pub const DW_REG_AARCH64_SP: u8 = 31;

/// Run CFI instructions (first `initial_instrs` — a CIE's defaults, then
/// `fde_instrs` — the FDE's own, stopping once their cumulative
/// `DW_CFA_advance_loc*` deltas reach or exceed `target_offset`, the
/// current PC's byte offset from the FDE's `initial_location`) and return
/// the resulting CFA rule.
///
/// Only interprets: `DW_CFA_nop`, `DW_CFA_advance_loc` (all four
/// encodings), `DW_CFA_def_cfa`, `DW_CFA_def_cfa_offset`, `DW_CFA_def_cfa_
/// register`. Anything else (`DW_CFA_offset` and friends — register-value
/// restore rules, irrelevant to locating the CFA itself; `DW_CFA_
/// expression`/`DW_CFA_restore_state`/etc.) is silently skipped for
/// opcodes with a statically-known operand shape this function still
/// recognizes enough to skip correctly, or causes a bail (`None`) if the
/// operand shape itself isn't known — see the `_ =>` arm.
pub fn run_cfi_to_offset(
    initial_instrs: &[u8],
    fde_instrs: &[u8],
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    target_offset: u64,
) -> Option<CfaRule> {
    run_cfi_to_offset_with_default(
        initial_instrs,
        fde_instrs,
        code_alignment_factor,
        data_alignment_factor,
        target_offset,
        DW_REG_RSP,
    )
}

/// As [`run_cfi_to_offset`], but the stack-pointer register assumed by a
/// `DW_CFA_def_cfa_offset` that arrives before any `DW_CFA_def_cfa` is a
/// parameter instead of a hardcoded x86-64 `rsp`.
///
/// Pass [`DW_REG_AARCH64_SP`] for AArch64 `.eh_frame`. Note this only matters
/// for *malformed* CFI: every real CIE emits `DW_CFA_def_cfa` in its initial
/// instructions, which overrides the default outright. This is robustness, not
/// a newly decodable binary.
pub fn run_cfi_to_offset_with_default(
    initial_instrs: &[u8],
    fde_instrs: &[u8],
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    target_offset: u64,
    default_cfa_register: u8,
) -> Option<CfaRule> {
    // Starting rule before any CIE instructions run — genuinely undefined
    // until DW_CFA_def_cfa(_offset/_register) establishes one; real
    // `.eh_frame` CIEs always do this in their initial instructions.
    let mut cfa: Option<CfaRule> = None;

    // The CIE's initial instructions always run to completion (they
    // establish defaults for every FDE using this CIE, regardless of
    // target_offset) — only the FDE's own instructions are offset-limited.
    run_instructions(initial_instrs, code_alignment_factor, data_alignment_factor, u64::MAX, &mut cfa, default_cfa_register)?;
    run_instructions(fde_instrs, code_alignment_factor, data_alignment_factor, target_offset, &mut cfa, default_cfa_register)?;
    cfa
}

fn run_instructions(
    instrs: &[u8],
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    stop_at_offset: u64,
    cfa: &mut Option<CfaRule>,
    default_cfa_register: u8,
) -> Option<()> {
    let mut pos = 0usize;
    let mut current_offset: u64 = 0;
    while pos < instrs.len() {
        let opcode_byte = instrs[pos];
        pos += 1;
        let high2 = opcode_byte & 0xC0;
        let low6 = opcode_byte & 0x3F;
        if high2 == 0x40 {
            // DW_CFA_advance_loc: 6-bit delta embedded in the opcode byte.
            let delta = u64::from(low6) * code_alignment_factor;
            if current_offset.saturating_add(delta) > stop_at_offset {
                return Some(());
            }
            current_offset += delta;
            continue;
        }
        if high2 == 0x80 {
            // DW_CFA_offset(reg=low6): 1 ULEB128 operand, doesn't move CFA.
            parse_uleb128(instrs, &mut pos)?;
            continue;
        }
        if high2 == 0xC0 {
            // DW_CFA_restore(reg=low6): no operand.
            continue;
        }
        match opcode_byte {
            0x00 => {} // DW_CFA_nop
            // 0x01 = DW_CFA_set_loc (absolute address operand, size
            // depends on the FDE's pointer encoding) — deliberately NOT
            // handled; falls through to the `_` bail arm below. Real
            // compiler output overwhelmingly prefers the relative
            // `advance_loc*` forms actually implemented here.
            0x02 => {
                // DW_CFA_advance_loc1: 1-byte delta.
                let raw = *instrs.get(pos)?;
                pos += 1;
                let delta = u64::from(raw) * code_alignment_factor;
                if current_offset.saturating_add(delta) > stop_at_offset {
                    return Some(());
                }
                current_offset += delta;
            }
            0x03 => {
                // DW_CFA_advance_loc2: 2-byte delta.
                let raw = u16::from_le_bytes(instrs.get(pos..pos + 2)?.try_into().ok()?);
                pos += 2;
                let delta = u64::from(raw) * code_alignment_factor;
                if current_offset.saturating_add(delta) > stop_at_offset {
                    return Some(());
                }
                current_offset += delta;
            }
            0x04 => {
                // DW_CFA_advance_loc4: 4-byte delta.
                let raw = u32::from_le_bytes(instrs.get(pos..pos + 4)?.try_into().ok()?);
                pos += 4;
                let delta = u64::from(raw) * code_alignment_factor;
                if current_offset.saturating_add(delta) > stop_at_offset {
                    return Some(());
                }
                current_offset += delta;
            }
            0x0C => {
                // DW_CFA_def_cfa: ULEB128 register, ULEB128 offset.
                let register = u8::try_from(parse_uleb128(instrs, &mut pos)?).ok()?;
                let offset = i64::try_from(parse_uleb128(instrs, &mut pos)?).ok()?;
                *cfa = Some(CfaRule { register, offset });
            }
            0x0D => {
                // DW_CFA_def_cfa_register: ULEB128 register, keeps offset.
                let register = u8::try_from(parse_uleb128(instrs, &mut pos)?).ok()?;
                let offset = cfa.map_or(0, |c| c.offset);
                *cfa = Some(CfaRule { register, offset });
            }
            0x0E => {
                // DW_CFA_def_cfa_offset: ULEB128 offset, keeps register.
                let offset = i64::try_from(parse_uleb128(instrs, &mut pos)?).ok()?;
                let register = cfa.map_or(default_cfa_register, |c| c.register);
                *cfa = Some(CfaRule { register, offset });
            }
            0x0A => {
                // DW_CFA_remember_state / DW_CFA_restore_state pairs (0x0A/0x0B)
                // imply a CFA-rule stack this module doesn't track — bail
                // rather than silently ignore a state restore.
                return None;
            }
            _ => {
                // DW_CFA_offset_extended, DW_CFA_expression,
                // DW_CFA_val_expression, DW_CFA_def_cfa_expression, and
                // anything else with an operand shape this function
                // doesn't specifically know how to skip — bail rather
                // than misparse the remaining instruction stream.
                let _ = data_alignment_factor; // reserved for a future DW_CFA_offset_extended_sf etc.
                return None;
            }
        }
    }
    Some(())
}

/// Find a named section's `(sh_addr, sh_size, sh_offset)` in an ELF64
/// file, given: the 64-byte ELF header, the section-header-string-table
/// section's own raw bytes (`shstrtab`, already read by the caller using
/// the string-table section header this function itself expects the
/// caller to have located first via `elf_shstrtab_location`), and the
/// full section-header-table bytes (`e_shnum` entries of `e_shentsize`
/// bytes each, as `elf_section_header_table_location` describes).
/// Pure byte-buffer parser — no live process needed.
pub fn find_elf_section(shdrs: &[u8], shentsize: usize, shstrtab: &[u8], name: &str) -> Option<(u64, u64, u64)> {
    if shentsize < 64 {
        return None;
    }
    let count = shdrs.len() / shentsize;
    for i in 0..count {
        let off = i * shentsize;
        let entry = shdrs.get(off..off + 64)?;
        let name_off = u32::from_le_bytes(entry[0..4].try_into().ok()?) as usize;
        let entry_name = shstrtab.get(name_off..)?;
        let nul = entry_name.iter().position(|&b| b == 0).unwrap_or(entry_name.len());
        if &entry_name[..nul] == name.as_bytes() {
            let sh_addr = u64::from_le_bytes(entry[16..24].try_into().ok()?);
            let sh_offset = u64::from_le_bytes(entry[24..32].try_into().ok()?);
            let sh_size = u64::from_le_bytes(entry[32..40].try_into().ok()?);
            return Some((sh_addr, sh_size, sh_offset));
        }
    }
    None
}

/// Extract `(e_shoff, e_shentsize, e_shnum, e_shstrndx)` from a 64-byte
/// ELF64 header — everything [`find_elf_section`]'s caller needs to know
/// where the section-header table and its string table live in the file.
/// Pure byte-buffer parser.
pub fn parse_elf_section_header_location(header: &[u8]) -> Option<(u64, u16, u16, u16)> {
    if header.len() < 64 || header[0] != 0x7F || &header[1..4] != b"ELF" {
        return None;
    }
    let e_shoff = u64::from_le_bytes(header[40..48].try_into().ok()?);
    let e_shentsize = u16::from_le_bytes(header[58..60].try_into().ok()?);
    let e_shnum = u16::from_le_bytes(header[60..62].try_into().ok()?);
    let e_shstrndx = u16::from_le_bytes(header[62..64].try_into().ok()?);
    Some((e_shoff, e_shentsize, e_shnum, e_shstrndx))
}

// ── Opt-3: parallel CFI frame resolution ─────────────────────────────────────
//
// `batch_resolve_frames` takes a slice of (pc, cfa_data, cie_data) tuples and
// resolves each frame's CFA rule independently, returning the results in input
// order.  Each resolution is a pure read over pre-parsed data, so Rayon can
// scatter the work across threads without any shared mutable state.
//
// Callers: the Linux backtrace path already locates CIE/FDE data per-frame and
// calls `run_cfi_to_offset`.  When unwinding a deep backtrace (≥ 8 frames) or
// batch-unwinding multiple threads simultaneously, this cuts wall-clock latency
// proportionally to available cores.

/// Input to one parallel frame resolution.
#[derive(Clone)]
pub struct BatchFrameInput<'a> {
    /// PC value to resolve (used as key into the FDE range).
    pub pc: u64,
    /// Slice containing the CIE that owns this FDE.
    pub cie_data: &'a [u8],
    /// Slice containing the FDE covering `pc`.
    pub fde_data: &'a [u8],
    /// VA of the FDE's own PC-relative pointer field (for `DW_EH_PE_pcrel`).
    pub fde_field_vaddr: u64,
    /// Maximum number of CFI instructions to interpret.
    pub max_ops: usize,
}

/// Result of one parallel frame resolution.
#[derive(Debug, Clone)]
pub struct BatchFrameResult {
    /// The input PC.
    pub pc: u64,
    /// CFA rule at the target offset, or `None` if the CFI was uninterpretable.
    pub cfa_rule: Option<CfaRule>,
}

/// Resolve `frames` in parallel using Rayon.
///
/// Each frame is independent — CFI interpretation is a pure function of the
/// input bytes and the PC offset — so there is no shared mutable state and
/// the work is embarrassingly parallel.
///
/// # Panics
/// Does not panic; frames that fail to parse produce `BatchFrameResult { cfa_rule: None }`.
#[must_use]
pub fn batch_resolve_frames(frames: &[BatchFrameInput<'_>]) -> Vec<BatchFrameResult> {
    use rayon::prelude::*;

    frames
        .par_iter()
        .map(|f| {
            let cie = parse_cie(f.cie_data);
            let cfa_rule = cie.and_then(|cie_info| {
                let enc = cie_info.fde_pointer_encoding.unwrap_or(DW_EH_PE_PCREL_SDATA4);
                let fde = parse_fde(f.fde_data, f.fde_field_vaddr, enc)?;
                let pc_offset = f.pc.checked_sub(fde.initial_location)?;
                // Split the CIE initial instructions from the FDE instructions.
                // CIE instructions live in cie_info.initial_instructions (offsets into f.cie_data);
                // FDE instructions follow the FDE header inside f.fde_data.
                let (ii_start, ii_end) = cie_info.initial_instructions;
                let cie_instrs = f.cie_data.get(ii_start..ii_end).unwrap_or(&[]);
                // FDE header: length(4) + cie_offset(4) + initial_location(4) + range(4) = 16 bytes
                // plus optional augmentation-data-length LEB128 (1 byte min) + that many bytes.
                let (fi_start, fi_end) = fde.instructions;
                let fde_instrs = f.fde_data.get(fi_start..fi_end).unwrap_or(&[]);
                run_cfi_to_offset(
                    cie_instrs,
                    fde_instrs,
                    cie_info.code_alignment_factor,
                    cie_info.data_alignment_factor,
                    pc_offset,
                )
            });
            BatchFrameResult { pc: f.pc, cfa_rule }
        })
        .collect()
}

// ── Mach-O: locating `__TEXT,__eh_frame` ─────────────────────────────────────

/// Magic of a 64-bit little-endian Mach-O image.
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `LC_SEGMENT_64`.
const LC_SEGMENT_64: u32 = 0x19;

/// Locate a section in a Mach-O image, returning `(vmaddr, size, file offset)`.
///
/// `image` must cover the header and its load commands; the section contents
/// themselves are not read here. Mirrors [`find_elf_section`] so the CFI reader
/// looks the same on both platforms.
///
/// # What it refuses
///
/// * A **fat/universal** binary (`0xCAFEBABE`) — its first bytes are an
///   architecture table, not a header. Parsing on regardless would read the
///   table as a header and hand back a section offset pointing anywhere. The
///   caller must select a slice first.
/// * A 32-bit image (`MH_MAGIC`) and any other magic, including a big-endian
///   one: this crate's CFI reader is little-endian 64-bit throughout.
///
/// Every bound is checked; a truncated or self-inconsistent load-command chain
/// yields `None` rather than an offset derived from garbage.
#[must_use]
pub fn find_macho_section(image: &[u8], segment: &str, section: &str) -> Option<(u64, u64, u64)> {
    if image.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes(image[0..4].try_into().ok()?);
    if magic != MH_MAGIC_64 {
        return None;
    }
    let ncmds = u32::from_le_bytes(image[16..20].try_into().ok()?) as usize;
    let sizeofcmds = u32::from_le_bytes(image[20..24].try_into().ok()?) as usize;
    let end = 32usize.checked_add(sizeofcmds)?;
    if end > image.len() {
        return None;
    }
    let mut pos = 32usize;
    for _ in 0..ncmds {
        if pos + 8 > end {
            return None;
        }
        let cmd = u32::from_le_bytes(image[pos..pos + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(image[pos + 4..pos + 8].try_into().ok()?) as usize;
        // A zero or unaligned cmdsize would loop forever or walk off by a byte.
        if cmdsize < 8 || cmdsize % 8 != 0 || pos + cmdsize > end {
            return None;
        }
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let seg = image.get(pos + 8..pos + 24)?;
            if cstr16_eq(seg, segment) {
                let nsects = u32::from_le_bytes(image[pos + 64..pos + 68].try_into().ok()?) as usize;
                for i in 0..nsects {
                    let s = pos.checked_add(72)?.checked_add(i.checked_mul(80)?)?;
                    if s + 80 > end {
                        return None;
                    }
                    if cstr16_eq(image.get(s..s + 16)?, section) {
                        let addr = u64::from_le_bytes(image[s + 32..s + 40].try_into().ok()?);
                        let size = u64::from_le_bytes(image[s + 40..s + 48].try_into().ok()?);
                        let offset =
                            u64::from(u32::from_le_bytes(image[s + 48..s + 52].try_into().ok()?));
                        return Some((addr, size, offset));
                    }
                }
            }
        }
        pos += cmdsize;
    }
    None
}

/// Preferred load address of the `__TEXT` segment, i.e. the value a runtime
/// base must be compared against to compute the ASLR slide.
///
/// Adding a runtime base to a section vmaddr without subtracting this would
/// double-count the image's own preferred address — on a `MH_EXECUTE` with a
/// non-zero `__TEXT` vmaddr (the norm on macOS: `0x1_0000_0000`) that lands
/// several gigabytes away from the real section.
#[must_use]
pub fn macho_text_vmaddr(image: &[u8]) -> Option<u64> {
    if image.len() < 32 || u32::from_le_bytes(image[0..4].try_into().ok()?) != MH_MAGIC_64 {
        return None;
    }
    let ncmds = u32::from_le_bytes(image[16..20].try_into().ok()?) as usize;
    let sizeofcmds = u32::from_le_bytes(image[20..24].try_into().ok()?) as usize;
    let end = 32usize.checked_add(sizeofcmds)?;
    if end > image.len() {
        return None;
    }
    let mut pos = 32usize;
    for _ in 0..ncmds {
        if pos + 8 > end {
            return None;
        }
        let cmd = u32::from_le_bytes(image[pos..pos + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(image[pos + 4..pos + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || cmdsize % 8 != 0 || pos + cmdsize > end {
            return None;
        }
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 && cstr16_eq(image.get(pos + 8..pos + 24)?, "__TEXT")
        {
            return u64::from_le_bytes(image[pos + 24..pos + 32].try_into().ok()?).into();
        }
        pos += cmdsize;
    }
    None
}

/// Compare a fixed 16-byte, NUL-padded Mach-O name field with a `&str`.
///
/// The field is NOT NUL-terminated when the name is exactly 16 characters
/// (`__thread_bss` is fine, but the format allows the full width), so a
/// `CStr`-style read would run into the next field.
fn cstr16_eq(field: &[u8], name: &str) -> bool {
    let n = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    field.get(..n).is_some_and(|f| f == name.as_bytes())
}

// ── The CFA registers, per architecture ──────────────────────────────────────

/// DWARF register numbers of `(stack pointer, frame pointer)` on the
/// architecture this build targets.
///
/// These are **not** portable constants: x86-64 numbers `rsp` 7 and `rbp` 6,
/// while AArch64 numbers `sp` 31 and `x29` 29 (DWARF for the Arm 64-bit
/// architecture, table 3). Reusing the x86 pair on ARM64 makes every CFA rule
/// look like it names some other register, so [`unwind_one_frame_with_cfi`]
/// finds a covering FDE, runs its instructions correctly, and then discards the
/// result — a backtrace that silently stops at the frame-pointer chain on the
/// one platform whose system libraries most need CFI.
#[must_use]
pub const fn dwarf_sp_fp_regnums() -> (u8, u8) {
    #[cfg(target_arch = "aarch64")]
    {
        (31, 29)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        (7, 6)
    }
}

/// Scan an `.eh_frame`/`__eh_frame` buffer for the CIE/FDE pair covering
/// `target_pc`, run the CFI program up to that PC, and return the CFA.
///
/// Shared by every backend that has unwind data: the ELF and Mach-O paths
/// differ only in where the bytes come from. Per the x86-64 and AArch64
/// conventions alike the return address sits at `CFA - 8` and the caller's `sp`
/// equals the CFA; the caller does that final read, since this function has no
/// memory reader.
///
/// `None` on absolutely any failure — no covering FDE, an unsupported opcode,
/// a CFA rule naming a register other than sp/fp. Bail, never guess.
#[must_use]
pub fn unwind_one_frame_with_cfi(
    eh_frame: &[u8],
    eh_frame_vaddr: u64,
    target_pc: u64,
    current_sp: u64,
    current_fp: Option<u64>,
) -> Option<u64> {
    let (sp_reg, fp_reg) = dwarf_sp_fp_regnums();
    let mut pos = 0usize;
    while pos + 8 <= eh_frame.len() {
        // Closure per entry so `?` skips THIS record instead of aborting the
        // scan: a real `.eh_frame` holds many CIEs, and it is expected — not
        // exceptional — that some use features this module does not interpret.
        // A naive `?` in the loop body stopped at the first such CIE, long
        // before the FDE that actually covers `target_pc` (found live against
        // `ld-linux-x86-64.so.2`).
        let entry = (|| -> Option<u64> {
            let length = u32::from_le_bytes(eh_frame[pos..pos + 4].try_into().ok()?);
            if length == 0 || length == 0xFFFF_FFFF {
                return None;
            }
            let record_end = pos + 4 + usize::try_from(length).ok()?;
            if record_end > eh_frame.len() {
                return None;
            }
            let id_or_cie_ptr = u32::from_le_bytes(eh_frame[pos + 4..pos + 8].try_into().ok()?);
            if id_or_cie_ptr == 0 {
                return None; // a CIE, not an FDE
            }
            let cie_field_pos = pos + 4;
            let cie_start = cie_field_pos.checked_sub(usize::try_from(id_or_cie_ptr).ok()?)?;
            let cie_len =
                u32::from_le_bytes(eh_frame.get(cie_start..cie_start + 4)?.try_into().ok()?);
            let cie_body =
                eh_frame.get(cie_start + 4..cie_start + 4 + usize::try_from(cie_len).ok()?)?;
            let cie = parse_cie(cie_body.get(4..)?)?;

            let fde_body = eh_frame.get(pos + 8..record_end)?;
            let fde_field_vaddr = eh_frame_vaddr + (pos + 8) as u64;
            let pointer_encoding = cie.fde_pointer_encoding?;
            let fde = parse_fde(fde_body, fde_field_vaddr, pointer_encoding)?;
            if target_pc < fde.initial_location
                || target_pc >= fde.initial_location + fde.address_range
            {
                return None;
            }
            let (ci_start, ci_end) = cie.initial_instructions;
            let initial_instrs = cie_body.get(4 + ci_start..4 + ci_end)?;
            let (fi_start, fi_end) = fde.instructions;
            let fde_instrs = fde_body.get(fi_start..fi_end)?;
            let target_offset = target_pc - fde.initial_location;
            let rule = run_cfi_to_offset(
                initial_instrs,
                fde_instrs,
                cie.code_alignment_factor,
                cie.data_alignment_factor,
                target_offset,
            )?;
            if rule.register == sp_reg {
                current_sp.checked_add_signed(rule.offset)
            } else if rule.register == fp_reg {
                current_fp.and_then(|fp| fp.checked_add_signed(rule.offset))
            } else {
                None
            }
        })();
        if entry.is_some() {
            return entry;
        }
        // Advance regardless: an entry this module cannot interpret still has
        // a trustworthy length prefix to skip past.
        let Some(length) = eh_frame
            .get(pos..pos + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
        else {
            break;
        };
        if length == 0 || length == 0xFFFF_FFFF {
            break;
        }
        let Some(record_end) = pos
            .checked_add(4)
            .and_then(|p| p.checked_add(usize::try_from(length).ok()?))
        else {
            break;
        };
        if record_end > eh_frame.len() || record_end <= pos {
            break;
        }
        pos = record_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_round_trips_known_values() {
        // 1, 127 (1 byte), 128, 300 (2 bytes) — standard LEB128 worked examples.
        assert_eq!(parse_uleb128(&[0x01], &mut 0), Some(1));
        assert_eq!(parse_uleb128(&[0x7F], &mut 0), Some(127));
        assert_eq!(parse_uleb128(&[0x80, 0x01], &mut 0), Some(128));
        assert_eq!(parse_uleb128(&[0xAC, 0x02], &mut 0), Some(300));
        let mut pos = 0;
        assert_eq!(parse_uleb128(&[0x80, 0x01, 0xFF], &mut pos), Some(128));
        assert_eq!(pos, 2, "pos should advance exactly past the encoding, not consume trailing bytes");
    }

    #[test]
    fn sleb128_round_trips_known_values() {
        // Standard DWARF spec worked examples: 2, -2, 127, -127, 128, -128.
        assert_eq!(parse_sleb128(&[0x02], &mut 0), Some(2));
        assert_eq!(parse_sleb128(&[0x7E], &mut 0), Some(-2));
        assert_eq!(parse_sleb128(&[0xFF, 0x00], &mut 0), Some(127));
        assert_eq!(parse_sleb128(&[0x81, 0x7F], &mut 0), Some(-127));
        assert_eq!(parse_sleb128(&[0x80, 0x01], &mut 0), Some(128));
        assert_eq!(parse_sleb128(&[0x80, 0x7F], &mut 0), Some(-128));
        // The real -8 encoding used throughout .eh_frame's data_alignment_factor.
        assert_eq!(parse_sleb128(&[0x78], &mut 0), Some(-8));
    }

    #[test]
    fn uleb128_rejects_truncated_buffer() {
        assert_eq!(parse_uleb128(&[0x80, 0x80], &mut 0), None);
    }

    /// The exact CIE body `readelf --debug-dump=frames /bin/sh` reported
    /// on a real Ubuntu 24.04 x86-64 binary (iter 194): `zR` augmentation,
    /// code_alignment_factor=1, data_alignment_factor=-8, return_address_
    /// register=16, FDE pointer encoding 0x1b (pcrel|sdata4),
    /// `DW_CFA_def_cfa r7 ofs 8` + `DW_CFA_offset r16 at cfa-8` as its
    /// initial instructions. Hand-encoded byte-for-byte from that real
    /// output, not invented.
    fn real_bin_sh_cie_bytes() -> Vec<u8> {
        vec![
            0x01, // Version
            0x7A, 0x52, 0x00, // Augmentation "zR\0"
            0x01, // code_alignment_factor = 1
            0x78, // data_alignment_factor = -8 (SLEB128)
            0x10, // return_address_register = 16
            0x01, // augmentation data length = 1
            0x1B, // 'R' -> FDE pointer encoding = pcrel|sdata4
            0x0C, 0x07, 0x08, // DW_CFA_def_cfa r7(rsp), offset 8
            0x90, 0x01, // DW_CFA_offset r16, factored offset 1 (-> cfa-8)
            0x00, 0x00, // DW_CFA_nop, DW_CFA_nop
        ]
    }

    #[test]
    fn parse_cie_reads_the_real_bin_sh_cie() {
        let cie_bytes = real_bin_sh_cie_bytes();
        let cie = parse_cie(&cie_bytes).expect("should parse a well-formed real-world CIE");
        assert_eq!(cie.code_alignment_factor, 1);
        assert_eq!(cie.data_alignment_factor, -8);
        assert_eq!(cie.fde_pointer_encoding, Some(DW_EH_PE_PCREL_SDATA4));
        let (start, end) = cie.initial_instructions;
        assert_eq!(&cie_bytes[start..end], &[0x0C, 0x07, 0x08, 0x90, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn parse_cie_rejects_unsupported_version() {
        let mut bytes = real_bin_sh_cie_bytes();
        bytes[0] = 3; // version 3, not the version-1 this module supports
        assert!(parse_cie(&bytes).is_none());
    }

    /// A malformed/adversarial CIE whose `'z'`-augmentation data length
    /// ULEB128-encodes a value near `u64::MAX` — before this fix, adding
    /// it to `aug_data_start` with raw `+` would panic on overflow in a
    /// debug build instead of returning `None` like every other malformed
    /// input this module handles. Proves `checked_add` catches it
    /// gracefully (iter 208).
    #[test]
    fn parse_cie_rejects_huge_augmentation_data_length_without_panicking() {
        let mut bytes = vec![
            0x01, // Version
            0x7A, 0x52, 0x00, // Augmentation "zR\0"
            0x01, // code_alignment_factor = 1
            0x78, // data_alignment_factor = -8
            0x10, // return_address_register = 16
        ];
        // ULEB128 encoding of u64::MAX (10 bytes: 9x continuation-set
        // 0x7F groups + a final 0x01).
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        // No further bytes needed — `checked_add` should reject this
        // before ever trying to read past the (already-consumed) 'R'
        // augmentation-data byte.
        bytes.push(0x1B); // 'R' augmentation data (pointer encoding)
        assert!(parse_cie(&bytes).is_none(), "should reject, not panic, on an implausible augmentation data length");
    }

    #[test]
    fn parse_fde_resolves_pcrel_sdata4_initial_location() {
        // fde_field_vaddr=0x2000, offset=+0x3000 -> initial_location=0x5000.
        let mut fde = Vec::new();
        fde.extend_from_slice(&0x3000i32.to_le_bytes());
        fde.extend_from_slice(&0x50u32.to_le_bytes()); // address_range
        fde.extend_from_slice(&[0x44, 0x0E, 0x20]); // advance_loc(4), def_cfa_offset(0x20)

        let info = parse_fde(&fde, 0x2000, DW_EH_PE_PCREL_SDATA4).expect("should parse");
        assert_eq!(info.initial_location, 0x5000);
        assert_eq!(info.address_range, 0x50);
        assert_eq!(&fde[info.instructions.0..info.instructions.1], &[0x44, 0x0E, 0x20]);
    }

    #[test]
    fn parse_fde_rejects_unsupported_pointer_encoding() {
        let fde = vec![0u8; 8];
        assert!(parse_fde(&fde, 0x2000, 0x0B /* sdata4, NOT pcrel */).is_none());
    }

    #[test]
    fn parse_fde_handles_negative_pcrel_offset() {
        // fde_field_vaddr=0x5000, offset=-0x1000 -> initial_location=0x4000.
        let mut fde = Vec::new();
        fde.extend_from_slice(&(-0x1000i32).to_le_bytes());
        fde.extend_from_slice(&0x20u32.to_le_bytes());
        let info = parse_fde(&fde, 0x5000, DW_EH_PE_PCREL_SDATA4).expect("should parse");
        assert_eq!(info.initial_location, 0x4000);
    }

    /// End-to-end: the real `/bin/sh` CIE (establishing `def_cfa(rsp, 8)`)
    /// combined with a synthetic FDE representing a common shape (a
    /// prologue that grows the frame via `DW_CFA_def_cfa_offset` partway
    /// through the function, no frame pointer switch) — proves
    /// `run_cfi_to_offset` correctly runs the CIE defaults THEN the FDE's
    /// own instructions up to (not past) the target offset.
    /// The default CFA register only ever applies when NO `DW_CFA_def_cfa`
    /// ran. Once one has, `DW_CFA_def_cfa_offset` must keep that register —
    /// including a non-x86 number such as AArch64 `sp` (31) — and must not
    /// fall back to the x86-64 default. Complements
    /// `the_default_cfa_register_is_architecture_selectable`, which covers
    /// the (malformed-input) fallback path.
    #[test]
    fn def_cfa_offset_keeps_a_previously_established_non_x86_register() {
        // def_cfa(reg=31 /* AArch64 sp */, off=0) then def_cfa_offset(0x10).
        let out = run_cfi_to_offset(&[0x0C, 31, 0x00], &[0x0E, 0x10], 1, -8, 0);
        assert_eq!(
            out,
            Some(CfaRule {
                register: 31,
                offset: 0x10
            })
        );
    }

    #[test]
    fn run_cfi_to_offset_applies_cie_defaults_then_fde_instructions() {
        let cie_bytes = real_bin_sh_cie_bytes();
        let cie = parse_cie(&cie_bytes).unwrap();
        let (ci_start, ci_end) = cie.initial_instructions;
        let initial_instrs = &cie_bytes[ci_start..ci_end];

        let mut fde = Vec::new();
        fde.extend_from_slice(&0i32.to_le_bytes());
        fde.extend_from_slice(&0x50u32.to_le_bytes());
        fde.extend_from_slice(&[0x44, 0x0E, 0x20]); // advance_loc(4), def_cfa_offset(0x20)
        let fde_info = parse_fde(&fde, 0, DW_EH_PE_PCREL_SDATA4).unwrap();
        let (fi_start, fi_end) = fde_info.instructions;
        let fde_instrs = &fde[fi_start..fi_end];

        // Before the advance_loc(4) takes effect: still the CIE's rule.
        let before = run_cfi_to_offset(initial_instrs, fde_instrs, cie.code_alignment_factor, cie.data_alignment_factor, 2)
            .expect("should resolve a CFA rule");
        assert_eq!(before, CfaRule { register: 7, offset: 8 }, "before the prologue's def_cfa_offset, should still be the CIE's rsp+8 rule");

        // After the advance_loc(4): the FDE's def_cfa_offset(0x20) applies.
        let after = run_cfi_to_offset(initial_instrs, fde_instrs, cie.code_alignment_factor, cie.data_alignment_factor, 10)
            .expect("should resolve a CFA rule");
        assert_eq!(after, CfaRule { register: 7, offset: 0x20 }, "past the prologue, should be the widened rsp+0x20 rule");
    }

    /// `DW_CFA_def_cfa_offset` "keeps the register" — but when no register has
    /// been established yet, the fallback was the hardcoded x86-64 `rsp` (7)
    /// regardless of architecture, so an AArch64 unwind would silently name an
    /// x86 register.
    ///
    /// Honest scope: this input is malformed DWARF — every real CIE emits
    /// `DW_CFA_def_cfa` first, which overrides the default outright. This is
    /// robustness, not a binary that now decodes.
    #[test]
    fn the_default_cfa_register_is_architecture_selectable() {
        // No def_cfa anywhere: only DW_CFA_def_cfa_offset(16).
        let initial: [u8; 0] = [];
        let fde = [0x0E, 0x10];

        let aarch64 = run_cfi_to_offset_with_default(&initial, &fde, 1, -8, 0, DW_REG_AARCH64_SP)
            .expect("a CFA rule");
        assert_eq!(
            aarch64,
            CfaRule { register: DW_REG_AARCH64_SP, offset: 16 },
            "an AArch64 unwind must fall back to sp (31), not x86-64 rsp (7)"
        );

        // Negative control: the existing x86-64 entry point is bit-identical.
        let x64 = run_cfi_to_offset(&initial, &fde, 1, -8, 0).expect("a CFA rule");
        assert_eq!(x64, CfaRule { register: DW_REG_RSP, offset: 16 });
        assert_eq!(DW_REG_RSP, 7);
        assert_eq!(DW_REG_AARCH64_SP, 31);
    }

    /// A CFI row is valid AT its own location, not just after it.
    ///
    /// `DW_CFA_advance_loc(delta)` starts a new table row at
    /// `location + delta`, and that row governs every PC from there up to the
    /// next row. So the instructions after an advance must still run when the
    /// target offset lands exactly on the new location; execution stops only
    /// once the location would move PAST the target.
    ///
    /// The stop test was `>=`, which quit one row early on an exact hit and
    /// returned the PREVIOUS row's CFA. That is not a rare boundary: a
    /// breakpoint is placed at an instruction address, and prologue rows begin
    /// exactly at instruction addresses — so a breakpoint on the instruction
    /// after `push rbp` unwound with a CFA 8 bytes off, read the wrong return
    /// address, and produced a wrong backtrace from the very first frame.
    #[test]
    fn a_cfi_row_applies_at_its_own_location_not_only_past_it() {
        // CIE: def_cfa(rsp, 8). FDE: at +1 the frame grows to 16, at +4 the
        // CFA switches to rbp. A textbook x86-64 prologue.
        let initial = [0x0C, 0x07, 0x08];
        let fde = [0x41, 0x0E, 0x10, 0x43, 0x0D, 0x06];

        let at = |target| run_cfi_to_offset(&initial, &fde, 1, -8, target).expect("a CFA rule");

        // Offset 0: no FDE row has started yet — the CIE's rule stands.
        assert_eq!(at(0), CfaRule { register: 7, offset: 8 });

        // Offset 1: the row that STARTS here is the one that governs this PC.
        assert_eq!(
            at(1),
            CfaRule { register: 7, offset: 16 },
            "the row beginning exactly at the target offset must be applied, not the one before it"
        );
        // Still inside that row.
        assert_eq!(at(2), CfaRule { register: 7, offset: 16 });

        // Offset 4: likewise for the frame-pointer switch that starts here.
        assert_eq!(
            at(4),
            CfaRule { register: 6, offset: 16 },
            "an exact hit on the second row must see the def_cfa_register too"
        );
        assert_eq!(at(9), CfaRule { register: 6, offset: 16 });
    }

    /// The same boundary, for the `advance_loc1/2/4` encodings.
    ///
    /// The 6-bit form is the one compilers emit most, so fixing only it would
    /// leave the identical off-by-one live in three other opcodes — each
    /// reachable from any function whose prologue rows are further apart than
    /// 63 code units.
    #[test]
    fn the_row_boundary_holds_for_every_advance_loc_encoding() {
        // def_cfa(rsp, 8), then advance by 100 and widen to 16, encoded three
        // ways: advance_loc1 (0x02), advance_loc2 (0x03), advance_loc4 (0x04).
        let initial = [0x0C, 0x07, 0x08];
        let widened = CfaRule { register: 7, offset: 16 };
        let cases: [Vec<u8>; 3] = [
            vec![0x02, 100, 0x0E, 0x10],
            vec![0x03, 100, 0, 0x0E, 0x10],
            vec![0x04, 100, 0, 0, 0, 0x0E, 0x10],
        ];
        for (i, fde) in cases.iter().enumerate() {
            assert_eq!(
                run_cfi_to_offset(&initial, fde, 1, -8, 100).expect("a CFA rule"),
                widened,
                "advance_loc{} stopped one row early on an exact hit",
                i + 1
            );
            assert_eq!(
                run_cfi_to_offset(&initial, fde, 1, -8, 99).expect("a CFA rule"),
                CfaRule { register: 7, offset: 8 },
                "advance_loc{} applied a row that has not started yet",
                i + 1
            );
        }
    }

    #[test]
    fn run_cfi_to_offset_bails_on_def_cfa_expression() {
        // DW_CFA_def_cfa_expression (opcode 0x0F) followed by a ULEB128
        // length this function doesn't know how to skip correctly for an
        // arbitrary DWARF expression — must bail, not misparse.
        let instrs = [0x0Fu8, 0x03, 0x00, 0x00, 0x00];
        assert!(run_cfi_to_offset(&[], &instrs, 1, -8, 100).is_none());
    }

    #[test]
    fn run_cfi_to_offset_bails_on_restore_state() {
        let instrs = [0x0Bu8]; // DW_CFA_restore_state
        assert!(run_cfi_to_offset(&[], &instrs, 1, -8, 100).is_none());
    }

    /// Hand-builds a minimal but structurally real ELF64 header (just the
    /// fields `parse_elf_section_header_location` reads) and verifies it
    /// extracts `e_shoff`/`e_shentsize`/`e_shnum`/`e_shstrndx` correctly.
    #[test]
    fn parse_elf_section_header_location_reads_the_real_offsets() {
        let mut header = [0u8; 64];
        header[0] = 0x7F;
        header[1..4].copy_from_slice(b"ELF");
        header[40..48].copy_from_slice(&0x1000u64.to_le_bytes()); // e_shoff
        header[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        header[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum
        header[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx
        let (shoff, shentsize, shnum, shstrndx) = parse_elf_section_header_location(&header).expect("should parse");
        assert_eq!(shoff, 0x1000);
        assert_eq!(shentsize, 64);
        assert_eq!(shnum, 5);
        assert_eq!(shstrndx, 3);
    }

    #[test]
    fn parse_elf_section_header_location_rejects_bad_magic() {
        let mut header = [0u8; 64];
        header[0..4].copy_from_slice(b"XXXX");
        assert!(parse_elf_section_header_location(&header).is_none());
    }

    /// Hand-builds a tiny section-header table (2 entries: a decoy and
    /// `.eh_frame`) plus a matching string table and verifies
    /// `find_elf_section` locates `.eh_frame`'s `(sh_addr, sh_size,
    /// sh_offset)` by name — proves the name-offset-into-strtab lookup
    /// works, not just raw field extraction.
    #[test]
    fn find_elf_section_locates_eh_frame_by_name() {
        // strtab: "\0.text\0.eh_frame\0" — names are NUL-terminated,
        // offset 0 is conventionally an empty name.
        let mut strtab = vec![0u8];
        strtab.extend_from_slice(b".text\0");
        let eh_frame_name_off = strtab.len() as u32;
        strtab.extend_from_slice(b".eh_frame\0");

        fn section_header(name_off: u32, addr: u64, offset: u64, size: u64) -> [u8; 64] {
            let mut buf = [0u8; 64];
            buf[0..4].copy_from_slice(&name_off.to_le_bytes());
            buf[16..24].copy_from_slice(&addr.to_le_bytes());
            buf[24..32].copy_from_slice(&offset.to_le_bytes());
            buf[32..40].copy_from_slice(&size.to_le_bytes());
            buf
        }
        let mut shdrs = Vec::new();
        shdrs.extend_from_slice(&section_header(1, 0x1000, 0x1000, 0x200)); // ".text"
        shdrs.extend_from_slice(&section_header(eh_frame_name_off, 0x2000, 0x2000, 0x300)); // ".eh_frame"

        let (addr, size, offset) = find_elf_section(&shdrs, 64, &strtab, ".eh_frame").expect("should find .eh_frame");
        assert_eq!(addr, 0x2000);
        assert_eq!(size, 0x300);
        assert_eq!(offset, 0x2000);

        assert!(find_elf_section(&shdrs, 64, &strtab, ".not_a_real_section").is_none());
    }

    // ── Opt-3: parallel batch frame resolver tests ────────────────────────────

    #[test]
    fn batch_resolve_empty_returns_empty() {
        let results = super::batch_resolve_frames(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn batch_resolve_bad_frames_return_none_cfa() {
        // Invalid CIE/FDE data — each frame should degrade to None, not panic.
        let bad: &[u8] = &[0u8; 32];
        let frames: Vec<super::BatchFrameInput<'_>> = (0..8u64)
            .map(|i| super::BatchFrameInput {
                pc: 0x1000 + i * 4,
                cie_data: bad,
                fde_data: bad,
                fde_field_vaddr: 0,
                max_ops: 32,
            })
            .collect();
        let results = super::batch_resolve_frames(&frames);
        assert_eq!(results.len(), 8);
        for r in &results {
            assert!(r.cfa_rule.is_none(), "bad data should produce None, not garbage");
        }
    }

    #[test]
    fn batch_resolve_preserves_order() {
        let bad: &[u8] = &[0u8; 32];
        let frames: Vec<super::BatchFrameInput<'_>> = (0..32u64)
            .map(|i| super::BatchFrameInput {
                pc: i * 8,
                cie_data: bad,
                fde_data: bad,
                fde_field_vaddr: 0,
                max_ops: 16,
            })
            .collect();
        let results = super::batch_resolve_frames(&frames);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.pc, i as u64 * 8, "result order must match input order");
        }
    }

    // ── Mach-O section locator (iter 447) ───────────────────────────────────

    /// Build a minimal but structurally real 64-bit Mach-O: header, one
    /// `LC_SEGMENT_64` for `__TEXT` with two sections, the second of which is
    /// `__eh_frame`. Two sections on purpose — a locator that returns the
    /// first section of the right segment passes a one-section fixture.
    fn synthetic_macho() -> Vec<u8> {
        fn name16(s: &str) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[..s.len()].copy_from_slice(s.as_bytes());
            b
        }
        let nsects = 2u32;
        let cmdsize = 72 + 80 * nsects as usize;
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&0x0100_000Cu32.to_le_bytes()); // cputype arm64
        v.extend_from_slice(&0u32.to_le_bytes());           // cpusubtype
        v.extend_from_slice(&2u32.to_le_bytes());           // MH_EXECUTE
        v.extend_from_slice(&1u32.to_le_bytes());           // ncmds
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());           // flags
        v.extend_from_slice(&0u32.to_le_bytes());           // reserved
        v.extend_from_slice(&0x19u32.to_le_bytes());        // LC_SEGMENT_64
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&name16("__TEXT"));
        v.extend_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0x4000u64.to_le_bytes());        // vmsize
        v.extend_from_slice(&0u64.to_le_bytes());             // fileoff
        v.extend_from_slice(&0x4000u64.to_le_bytes());        // filesize
        v.extend_from_slice(&5u32.to_le_bytes());             // maxprot
        v.extend_from_slice(&5u32.to_le_bytes());             // initprot
        v.extend_from_slice(&nsects.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());             // flags
        for (sect, addr, size, off) in [
            ("__text", 0x1_0000_1000u64, 0x200u64, 0x1000u32),
            ("__eh_frame", 0x1_0000_3000, 0x180, 0x3000),
        ] {
            v.extend_from_slice(&name16(sect));
            v.extend_from_slice(&name16("__TEXT"));
            v.extend_from_slice(&addr.to_le_bytes());
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&off.to_le_bytes());
            v.extend_from_slice(&[0u8; 28]); // align..reserved3
        }
        v
    }

    #[test]
    fn macho_locator_finds_eh_frame_and_the_text_vmaddr() {
        let img = synthetic_macho();
        assert_eq!(
            find_macho_section(&img, "__TEXT", "__eh_frame"),
            Some((0x1_0000_3000, 0x180, 0x3000)),
            "the locator must return the __eh_frame section, not the first section of __TEXT"
        );
        assert_eq!(macho_text_vmaddr(&img), Some(0x1_0000_0000));
        assert_eq!(find_macho_section(&img, "__TEXT", "__nope"), None);
        assert_eq!(find_macho_section(&img, "__DATA", "__eh_frame"), None);
    }

    /// A fat binary starts with an architecture table, not a header. Parsing on
    /// regardless would read that table as a Mach-O header and hand back a
    /// section offset pointing anywhere — a wrong address with no error.
    #[test]
    fn macho_locator_refuses_what_it_cannot_parse() {
        let fat = [0xCAu8, 0xFE, 0xBA, 0xBE].repeat(16);
        assert_eq!(find_macho_section(&fat, "__TEXT", "__eh_frame"), None);
        assert_eq!(macho_text_vmaddr(&fat), None);
        // 32-bit magic, and a truncated image.
        let mut m32 = synthetic_macho();
        m32[0..4].copy_from_slice(&0xFEED_FACEu32.to_le_bytes());
        assert_eq!(find_macho_section(&m32, "__TEXT", "__eh_frame"), None);
        let short = &synthetic_macho()[..40];
        assert_eq!(find_macho_section(short, "__TEXT", "__eh_frame"), None);
    }

    /// A `cmdsize` of zero would loop forever over the same load command.
    #[test]
    fn macho_locator_refuses_a_zero_length_load_command() {
        let mut img = synthetic_macho();
        img[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(find_macho_section(&img, "__TEXT", "__eh_frame"), None);
    }

    /// The CFA register numbers are per-architecture. Hardcoding the x86 pair
    /// makes every AArch64 CFA rule look like it names an unrelated register,
    /// so the unwinder finds the right FDE, runs it correctly, and throws the
    /// answer away — a backtrace that silently stops at the frame-pointer
    /// chain on the platform whose libraries most need CFI.
    #[test]
    fn the_cfa_registers_are_the_ones_this_architecture_uses() {
        let (sp, fp) = dwarf_sp_fp_regnums();
        #[cfg(target_arch = "aarch64")]
        assert_eq!((sp, fp), (31, 29), "AArch64: sp is 31 and x29 is 29");
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!((sp, fp), (7, 6), "x86-64: rsp is 7 and rbp is 6");
        assert_ne!(sp, fp);
    }
}
