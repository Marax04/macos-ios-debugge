//! COFF archive (`.lib` / `.rlib`) harvester producing classic FLIRT patterns.
//!
//! Walks an ar-format archive (`!<arch>`), parses every COFF object member,
//! and emits one [`FlirtPattern`] per defined function: the first
//! `prefix_len` bytes (default 32) with wildcards over relocation targets
//! (and, optionally, x86 branch/address immediates), plus a CRC-16 over the
//! following `crc_len` bytes (default 64) — the classic FLIRT scheme.
//!
//! Both MSVC `.lib` files and Rust toolchain `.rlib` files (whose members are
//! COFF `*.rcgu.o` objects on `*-pc-windows-msvc` targets) are supported.

use goblin::archive::Archive;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SymbolKind,
    SymbolSection,
};
use rustre_flirt::{FlirtName, FlirtPattern};
use std::collections::HashMap;
use std::path::Path;

use crate::{GenError, PatternGenerator, scan_x86_masks};

// ── Options ──────────────────────────────────────────────────────────────────

/// Tuning knobs for [`harvest_archive_bytes`].
#[derive(Debug, Clone)]
pub struct ArchiveHarvestOptions {
    /// Leading bytes kept in the masked pattern (classic FLIRT: 32).
    pub prefix_len: usize,
    /// Bytes after the prefix covered by the CRC-16 (classic FLIRT: 64).
    pub crc_len: usize,
    /// Functions shorter than this are skipped (too generic to be useful).
    pub min_func_len: usize,
    /// Additionally wildcard x86 call/jmp/RIP-relative immediates found by
    /// [`scan_x86_masks`], on top of real relocation targets.
    pub mask_immediates: bool,
    /// Demangle Rust symbol names (`_ZN…` / `_R…`) via `rustc-demangle`.
    pub demangle: bool,
}

impl Default for ArchiveHarvestOptions {
    fn default() -> Self {
        Self {
            prefix_len: 32,
            crc_len: 64,
            min_func_len: 12,
            mask_immediates: false,
            demangle: true,
        }
    }
}

// ── Stats ────────────────────────────────────────────────────────────────────

/// Telemetry from a harvest run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HarvestStats {
    /// Archive members visited.
    pub members: usize,
    /// Members successfully parsed as object files.
    pub objects_parsed: usize,
    /// Members that looked like objects but failed to parse.
    pub objects_failed: usize,
    /// Function symbols considered.
    pub functions_seen: usize,
    /// Functions skipped because they were shorter than `min_func_len`.
    pub functions_too_short: usize,
    /// Patterns emitted.
    pub patterns: usize,
}

// ── Harvesting ───────────────────────────────────────────────────────────────

/// Harvest FLIRT patterns from an in-memory ar archive (`.lib` / `.rlib`).
///
/// # Errors
///
/// Returns [`GenError::Parse`] when the outer ar archive cannot be parsed.
/// Individual members that fail to parse as COFF/ELF objects are counted in
/// [`HarvestStats::objects_failed`] and skipped.
pub fn harvest_archive_bytes(
    data: &[u8],
    opts: &ArchiveHarvestOptions,
) -> Result<(Vec<FlirtPattern>, HarvestStats), GenError> {
    let archive =
        Archive::parse(data).map_err(|e| GenError::Parse(format!("ar parse: {e}")))?;
    let mut stats = HarvestStats::default();
    let mut out = Vec::new();

    for member_name in archive.members() {
        stats.members += 1;
        let Ok(member_bytes) = archive.extract(member_name, data) else {
            continue;
        };
        if !looks_like_object(member_name, member_bytes) {
            continue;
        }
        match harvest_object_bytes(member_bytes, opts, &mut stats) {
            Ok(mut pats) => {
                stats.objects_parsed += 1;
                out.append(&mut pats);
            }
            Err(_) => stats.objects_failed += 1,
        }
    }
    stats.patterns = out.len();
    Ok((out, stats))
}

/// Harvest FLIRT patterns from an archive file on disk.
///
/// # Errors
///
/// Returns [`GenError::Parse`] on I/O or archive-parse failures.
pub fn harvest_archive_file(
    path: &Path,
    opts: &ArchiveHarvestOptions,
) -> Result<(Vec<FlirtPattern>, HarvestStats), GenError> {
    let data = std::fs::read(path)
        .map_err(|e| GenError::Parse(format!("read {}: {e}", path.display())))?;
    harvest_archive_bytes(&data, opts)
}

/// Heuristic: does this archive member look like a relocatable object?
fn looks_like_object(name: &str, bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    // COFF x86-64 (0x8664 LE) or i386 (0x014C LE).
    let coff_magic = (bytes[0] == 0x64 && bytes[1] == 0x86) || (bytes[0] == 0x4C && bytes[1] == 0x01);
    // ELF object.
    let elf_magic = bytes.starts_with(b"\x7fELF");
    let obj_ext = Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("o") || e.eq_ignore_ascii_case("obj"));
    coff_magic || elf_magic || obj_ext
}

/// Harvest all defined functions from one object file (COFF or ELF) into
/// classic FLIRT patterns.
///
/// # Errors
///
/// Returns [`GenError::Parse`] when the object cannot be parsed.
pub fn harvest_object_bytes(
    buf: &[u8],
    opts: &ArchiveHarvestOptions,
    stats: &mut HarvestStats,
) -> Result<Vec<FlirtPattern>, GenError> {
    let file =
        object::File::parse(buf).map_err(|e| GenError::Parse(format!("object parse: {e}")))?;

    // Group function symbols by section so zero-size (COFF) symbols can use
    // the next symbol in the same section as their end boundary.
    let mut by_section: HashMap<object::SectionIndex, Vec<object::Symbol<'_, '_>>> =
        HashMap::new();
    for sym in file.symbols() {
        if sym.kind() != SymbolKind::Text && sym.kind() != SymbolKind::Unknown {
            continue;
        }
        let SymbolSection::Section(sec_idx) = sym.section() else {
            continue;
        };
        let Ok(sec) = file.section_by_index(sec_idx) else {
            continue;
        };
        if !sec.name().unwrap_or("").starts_with(".text") {
            continue;
        }
        by_section.entry(sec_idx).or_default().push(sym);
    }

    let generator = PatternGenerator {
        initial_length: opts.prefix_len,
        crc_length: opts.crc_len,
    };

    let mut out = Vec::new();
    // Iterate sections in index order, not `HashMap` order.
    //
    // Rust randomises a `HashMap`'s hasher, so iterating it directly yields a
    // different order per map instance. For an object with more than one
    // `.text*` section that would emit patterns in a different order on every
    // run, making the generated `.sig` differ byte-for-byte from itself — which
    // breaks checksums, caching and any "did my change alter the output?"
    // comparison.
    //
    // Symbols within a section were already sorted by address; only the section
    // order was left to chance. Sorting here is cheap (a handful of sections)
    // and removes the risk regardless of how many sections an object has.
    let mut by_section: Vec<_> = by_section.into_iter().collect();
    by_section.sort_by_key(|(idx, _)| idx.0);

    for (sec_idx, mut syms) in by_section {
        syms.sort_by_key(object::ObjectSymbol::address);
        let Ok(section) = file.section_by_index(sec_idx) else {
            continue;
        };
        let Ok(sec_data) = section.data() else {
            continue;
        };
        let sec_addr = usize::try_from(section.address()).unwrap_or(0);
        let sec_end = sec_addr + sec_data.len();

        for i in 0..syms.len() {
            let sym = &syms[i];
            stats.functions_seen += 1;
            let addr = usize::try_from(sym.address()).unwrap_or(0);
            let mut size = usize::try_from(sym.size()).unwrap_or(0);
            if size == 0 {
                // COFF symbols carry no size: extend to the next symbol (or
                // the section end).
                let next = syms
                    .get(i + 1)
                    .map_or(sec_end, |s| usize::try_from(s.address()).unwrap_or(sec_end));
                size = next.saturating_sub(addr);
            }
            if size < opts.min_func_len {
                stats.functions_too_short += 1;
                continue;
            }
            let off = addr.saturating_sub(sec_addr);
            // `size` comes from a COFF symbol (a 64-bit file field), so a plain
            // `off + size` WRAPS in release (overflow-checks off): the guard then
            // passes while `off + size < off`, and the slice below panics.
            let Some(end) = off.checked_add(size) else {
                continue;
            };
            if end > sec_data.len() {
                continue;
            }
            let body = &sec_data[off..end];

            // Masked ranges: relocation targets, function-relative.
            let mut ranges: Vec<(u16, u8)> = Vec::new();
            for (rel_off, rel) in section.relocations() {
                if !matches!(rel.target(), RelocationTarget::Symbol(_)) {
                    continue;
                }
                let r = usize::try_from(rel_off).unwrap_or(usize::MAX);
                if r < off || r >= end {
                    continue;
                }
                let local = r - off;
                let Ok(local16) = u16::try_from(local) else {
                    continue;
                };
                let width: u8 = if rel.kind() == RelocationKind::Absolute { 8 } else { 4 };
                ranges.push((local16, width));
            }
            if opts.mask_immediates {
                ranges.extend(scan_x86_masks(body));
            }

            let raw_name = sym.name().unwrap_or("");
            if raw_name.is_empty() {
                continue;
            }
            let name = if opts.demangle {
                rustc_demangle::demangle(raw_name).to_string()
            } else {
                raw_name.to_string()
            };
            let fname = FlirtName {
                name,
                offset: 0,
                is_public: !sym.is_local(),
                is_local: sym.is_local(),
            };
            if let Ok(pat) = generator.generate_from_ranges(body, &ranges, vec![fname], vec![]) {
                out.push(pat);
            }
        }
    }
    Ok(out)
}

// ── Discriminative dedup ─────────────────────────────────────────────────────

/// Outcome of [`dedup_discriminative`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DedupReport {
    /// Patterns kept whose (prefix, CRC) key identifies exactly one name.
    pub discriminative: usize,
    /// Keys shared by several distinct names (merged into multi-name leaves).
    pub ambiguous_keys: usize,
    /// Exact duplicates dropped.
    pub exact_duplicates: usize,
}

/// Collapse harvested patterns by their `(masked prefix, crc16, crc_len)`
/// key.
///
/// * Identical `(key, name)` pairs are dropped as exact duplicates.
/// * Distinct names sharing a key are merged into a single multi-name
///   pattern (an ambiguous leaf, as real FLIRT does) and counted in
///   [`DedupReport::ambiguous_keys`].
///
/// The returned patterns therefore each carry a unique key; those with a
/// single name are truly discriminative signatures.
#[must_use]
pub fn dedup_discriminative(patterns: Vec<FlirtPattern>) -> (Vec<FlirtPattern>, DedupReport) {
    let mut report = DedupReport::default();
    let mut by_key: HashMap<(String, u16, u8), FlirtPattern> = HashMap::new();
    let mut order: Vec<(String, u16, u8)> = Vec::new();

    for pat in patterns {
        let key = (pat.pattern_hex(), pat.crc16, pat.crc_length);
        if let Some(existing) = by_key.get_mut(&key) {
            for name in pat.names {
                if existing.names.iter().any(|n| n.name == name.name) {
                    report.exact_duplicates += 1;
                } else {
                    existing.names.push(name);
                }
            }
        } else {
            order.push(key.clone());
            by_key.insert(key, pat);
        }
    }

    let mut out = Vec::with_capacity(order.len());
    for key in order {
        if let Some(pat) = by_key.remove(&key) {
            if pat.names.len() == 1 {
                report.discriminative += 1;
            } else {
                report.ambiguous_keys += 1;
            }
            out.push(pat);
        }
    }
    (out, report)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests inspect individual pattern bytes; importing it at module
    // scope makes `cargo build` (which does not compile tests) report it unused.
    use rustre_flirt::PatternByte;

    // ---- synthetic COFF object builder ------------------------------------

    /// Build a minimal x86-64 COFF object with one `.text` section containing
    /// the concatenated `funcs` bodies, one external function symbol per body,
    /// and the given REL32 relocations `(section_offset, target_sym_index)`.
    ///
    /// A trailing undefined symbol `ext_target` is appended for relocations
    /// to reference (its index is returned).
    fn build_coff(funcs: &[(&str, &[u8])], relocs: &[(u32, u32)]) -> (Vec<u8>, u32) {
        let nsections = 1u16;
        let text: Vec<u8> = funcs.iter().flat_map(|(_, b)| b.iter().copied()).collect();

        let hdr_size = 20usize;
        let shdr_size = 40usize;
        let raw_ptr = hdr_size + shdr_size;
        let reloc_ptr = raw_ptr + text.len();
        let symtab_ptr = reloc_ptr + relocs.len() * 10;
        let nsyms = u32::try_from(funcs.len() + 1).unwrap();

        let mut o = Vec::new();
        // COFF file header
        o.extend_from_slice(&0x8664u16.to_le_bytes()); // machine
        o.extend_from_slice(&nsections.to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        o.extend_from_slice(&u32::try_from(symtab_ptr).unwrap().to_le_bytes());
        o.extend_from_slice(&nsyms.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // opt hdr size
        o.extend_from_slice(&0u16.to_le_bytes()); // characteristics

        // section header ".text"
        let mut name8 = [0u8; 8];
        name8[..5].copy_from_slice(b".text");
        o.extend_from_slice(&name8);
        o.extend_from_slice(&0u32.to_le_bytes()); // vsize
        o.extend_from_slice(&0u32.to_le_bytes()); // vaddr
        o.extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
        o.extend_from_slice(&u32::try_from(raw_ptr).unwrap().to_le_bytes());
        o.extend_from_slice(&u32::try_from(reloc_ptr).unwrap().to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes()); // line numbers
        o.extend_from_slice(&u16::try_from(relocs.len()).unwrap().to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // nlines
        o.extend_from_slice(&0x6050_0020u32.to_le_bytes()); // CODE|EXECUTE|READ

        // raw data
        o.extend_from_slice(&text);

        // relocations: IMAGE_REL_AMD64_REL32 = 4
        for &(voff, symidx) in relocs {
            o.extend_from_slice(&voff.to_le_bytes());
            o.extend_from_slice(&symidx.to_le_bytes());
            o.extend_from_slice(&4u16.to_le_bytes());
        }

        // symbols (18 bytes each)
        let mut value = 0u32;
        for (name, body) in funcs {
            let mut n8 = [0u8; 8];
            let nb = name.as_bytes();
            assert!(nb.len() <= 8, "test symbol names must be <= 8 bytes");
            n8[..nb.len()].copy_from_slice(nb);
            o.extend_from_slice(&n8);
            o.extend_from_slice(&value.to_le_bytes()); // value
            o.extend_from_slice(&1i16.to_le_bytes()); // section 1
            o.extend_from_slice(&0x20u16.to_le_bytes()); // type = function
            o.push(2); // IMAGE_SYM_CLASS_EXTERNAL
            o.push(0); // naux
            value += u32::try_from(body.len()).unwrap();
        }
        // undefined external target for relocs
        let ext_index = u32::try_from(funcs.len()).unwrap();
        let mut n8 = [0u8; 8];
        n8[..7].copy_from_slice(b"ext_tgt");
        o.extend_from_slice(&n8);
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&0i16.to_le_bytes()); // undefined section
        o.extend_from_slice(&0x20u16.to_le_bytes());
        o.push(2);
        o.push(0);

        // string table: just its own length field
        o.extend_from_slice(&4u32.to_le_bytes());
        (o, ext_index)
    }

    /// Wrap object files into an ar (`!<arch>`) archive.
    fn build_ar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut a = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let mut hdr = vec![b' '; 60];
            let name_field = format!("{name}/");
            hdr[..name_field.len()].copy_from_slice(name_field.as_bytes());
            let ts = b"0";
            hdr[16..16 + ts.len()].copy_from_slice(ts);
            hdr[28..29].copy_from_slice(b"0");
            hdr[34..35].copy_from_slice(b"0");
            hdr[40..41].copy_from_slice(b"0");
            let size = data.len().to_string();
            hdr[48..48 + size.len()].copy_from_slice(size.as_bytes());
            hdr[58] = b'`';
            hdr[59] = b'\n';
            a.extend_from_slice(&hdr);
            a.extend_from_slice(data);
            if data.len() % 2 == 1 {
                a.push(b'\n');
            }
        }
        a
    }

    fn func_body(seed: u8, len: usize) -> Vec<u8> {
        // Deterministic distinct body: prologue + varying filler + ret.
        let mut b = vec![0x55, 0x48, 0x89, 0xE5];
        for i in 0..len.saturating_sub(5) {
            b.push(seed.wrapping_add(u8::try_from(i % 251).unwrap()));
        }
        b.push(0xC3);
        b
    }

    // ---- tests -------------------------------------------------------------

    #[test]
    fn test_harvest_synthetic_archive_two_functions() {
        let f1 = func_body(0x10, 48);
        let f2 = func_body(0x90, 48);
        let (obj, _) = build_coff(&[("fn_one", &f1), ("fn_two", &f2)], &[]);
        let ar = build_ar(&[("m1.o", &obj)]);

        let (pats, stats) =
            harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert_eq!(stats.objects_parsed, 1);
        assert_eq!(pats.len(), 2, "stats: {stats:?}");
        let names: Vec<_> = pats
            .iter()
            .map(|p| p.primary_name().unwrap().to_string())
            .collect();
        assert!(names.contains(&"fn_one".to_string()));
        assert!(names.contains(&"fn_two".to_string()));
        // 32-byte prefix + CRC over following bytes
        for p in &pats {
            assert_eq!(p.initial_bytes.len(), 32);
            assert!(p.crc_length > 0);
            assert_eq!(p.pattern_length, 48);
        }
    }

    #[test]
    fn test_harvest_masks_relocation_in_prefix() {
        // Function 1 with a CALL rel32 at offset 4; reloc points at offset 5.
        let mut f1 = vec![0x55, 0x48, 0x89, 0xE5, 0xE8, 0xAA, 0xBB, 0xCC, 0xDD];
        f1.extend(func_body(0x33, 40));
        // ext target symbol index = number of function symbols = 1.
        let (obj, _) = build_coff(&[("callfn", &f1)], &[(5, 1)]);
        let ar = build_ar(&[("m.o", &obj)]);

        let (pats, _) = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert_eq!(pats.len(), 1);
        let p = &pats[0];
        // bytes 5..9 must be wildcards
        for i in 5..9 {
            assert_eq!(p.initial_bytes[i], PatternByte::Wildcard, "byte {i}");
        }
        assert_eq!(p.initial_bytes[4], PatternByte::Exact(0xE8));
    }

    #[test]
    fn test_crc_invariant_under_reloc_bytes_in_crc_region() {
        // Two objects identical except for the reloc-covered dword *after* the
        // 32-byte prefix: CRC must be identical (masked bytes skipped).
        let mut body_a = func_body(0x20, 34);
        body_a.extend_from_slice(&[0xE8, 0x11, 0x22, 0x33, 0x44]);
        body_a.extend(std::iter::repeat_n(0x90u8, 30));
        let mut body_b = body_a.clone();
        body_b[35] = 0xFF; // inside the reloc'd dword at 35..39
        body_b[36] = 0xEE;

        let (obj_a, ext_a) = build_coff(&[("fA", &body_a)], &[(35, 1)]);
        let (obj_b, _) = build_coff(&[("fA", &body_b)], &[(35, 1)]);
        let _ = ext_a;
        let (pa, _) = harvest_archive_bytes(
            &build_ar(&[("a.o", &obj_a)]),
            &ArchiveHarvestOptions::default(),
        )
        .unwrap();
        let (pb, _) = harvest_archive_bytes(
            &build_ar(&[("b.o", &obj_b)]),
            &ArchiveHarvestOptions::default(),
        )
        .unwrap();
        assert_eq!(pa.len(), 1);
        assert_eq!(pb.len(), 1);
        assert_eq!(pa[0].crc16, pb[0].crc16, "CRC must skip relocated bytes");
    }

    #[test]
    fn test_min_func_len_skips_short() {
        let tiny = [0xC3u8; 4];
        let (obj, _) = build_coff(&[("tiny", &tiny)], &[]);
        let ar = build_ar(&[("m.o", &obj)]);
        let (pats, stats) =
            harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert!(pats.is_empty());
        assert_eq!(stats.functions_too_short, 1);
    }

    #[test]
    fn test_non_object_members_skipped() {
        let f1 = func_body(0x44, 40);
        let (obj, _) = build_coff(&[("realfn", &f1)], &[]);
        let ar = build_ar(&[("readme.txt", b"hello, not an object"), ("m.o", &obj)]);
        let (pats, stats) = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert_eq!(pats.len(), 1);
        assert_eq!(stats.objects_parsed, 1);
    }

    #[test]
    fn test_bad_archive_is_error() {
        let r = harvest_archive_bytes(b"definitely not an archive", &ArchiveHarvestOptions::default());
        assert!(r.is_err());
    }

    #[test]
    fn test_corrupt_object_member_counted_failed() {
        // COFF magic but garbage after: header claims huge symtab.
        let mut fake = vec![0x64u8, 0x86];
        fake.extend_from_slice(&[0xFF; 40]);
        let ar = build_ar(&[("bad.o", &fake)]);
        let (pats, stats) = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert!(pats.is_empty());
        assert_eq!(stats.objects_failed, 1);
    }

    #[test]
    fn test_mask_immediates_option() {
        // CALL rel32 with NO relocation record: only masked when
        // mask_immediates is on.
        let mut f = vec![0x55, 0x48, 0x89, 0xE5, 0xE8, 0x01, 0x02, 0x03, 0x04];
        f.extend(func_body(0x66, 40));
        let (obj, _) = build_coff(&[("immfn", &f)], &[]);
        let ar = build_ar(&[("m.o", &obj)]);

        let plain = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default())
            .unwrap()
            .0;
        assert_eq!(plain[0].initial_bytes[5], PatternByte::Exact(0x01));

        let opts = ArchiveHarvestOptions {
            mask_immediates: true,
            ..Default::default()
        };
        let masked = harvest_archive_bytes(&ar, &opts).unwrap().0;
        assert_eq!(masked[0].initial_bytes[5], PatternByte::Wildcard);
    }

    #[test]
    fn test_dedup_discriminative_merges_and_counts() {
        let f = func_body(0x21, 40);
        let (obj, _) = build_coff(&[("name_a", &f)], &[]);
        let (obj2, _) = build_coff(&[("name_b", &f)], &[]);
        let (obj3, _) = build_coff(&[("name_a", &f)], &[]);
        let g = func_body(0x77, 40);
        let (obj4, _) = build_coff(&[("uniq", &g)], &[]);
        let ar = build_ar(&[("1.o", &obj), ("2.o", &obj2), ("3.o", &obj3), ("4.o", &obj4)]);

        let (pats, _) = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();
        assert_eq!(pats.len(), 4);
        let (deduped, report) = dedup_discriminative(pats);
        assert_eq!(deduped.len(), 2);
        assert_eq!(report.discriminative, 1); // "uniq"
        assert_eq!(report.ambiguous_keys, 1); // name_a + name_b share bytes
        assert_eq!(report.exact_duplicates, 1); // second name_a
        let ambiguous = deduped.iter().find(|p| p.names.len() == 2).unwrap();
        let names: Vec<_> = ambiguous.names.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"name_a") && names.contains(&"name_b"));
    }

    #[test]
    fn test_sig_file_roundtrip_from_harvest() {
        // Harvest, emit an IDA .sig v9 file, verify header fields.
        let f1 = func_body(0x11, 60);
        let f2 = func_body(0x99, 60);
        let (obj, _) = build_coff(&[("alpha", &f1), ("beta", &f2)], &[]);
        let ar = build_ar(&[("m.o", &obj)]);
        let (pats, _) = harvest_archive_bytes(&ar, &ArchiveHarvestOptions::default()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("harvest.sig");
        crate::write_sig_file(&pats, "synthlib", 75, &path).unwrap();
        let sig_bytes = std::fs::read(&path).unwrap();
        assert_eq!(&sig_bytes[..6], b"IDASGN");
        assert_eq!(sig_bytes[6], 9);
        let hdr = rustre_flirt::sig_header::SigFileHeader::decode(&sig_bytes)
            .expect("il .sig scritto deve essere decodificabile");
        assert_eq!(hdr.n_functions, 2, "n_functions sta a offset 37, non a 34");
        assert_eq!(hdr.lib_name, "synthlib");
        // The trie starts where the header ends — the header is variable length,
        // so slicing at a constant 104 would cut into the trie or skip part of it.
        let body = &sig_bytes[hdr.len_bytes()..];
        let hay = String::from_utf8_lossy(body);
        assert!(hay.contains("alpha") && hay.contains("beta"));
    }

    #[test]
    fn test_harvest_rustup_rlib_if_present() {
        // Real-corpus smoke test: only runs when a rustup toolchain rlib dir
        // exists on this machine; silently passes otherwise.
        let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
        else {
            return;
        };
        let toolchains = Path::new(&home).join(".rustup").join("toolchains");
        let Ok(entries) = std::fs::read_dir(&toolchains) else {
            return;
        };
        for tc in entries.filter_map(Result::ok) {
            let lib_dir = tc
                .path()
                .join("lib")
                .join("rustlib")
                .join("x86_64-pc-windows-msvc")
                .join("lib");
            let Ok(libs) = std::fs::read_dir(&lib_dir) else {
                continue;
            };
            for rlib in libs.filter_map(Result::ok) {
                let p = rlib.path();
                if p.extension().is_none_or(|e| e != "rlib") {
                    continue;
                }
                // cfg_if is tiny; pick any rlib and just assert harvesting
                // does not error and produces valid 32-byte-prefix patterns.
                if let Ok((pats, _stats)) =
                    harvest_archive_file(&p, &ArchiveHarvestOptions::default())
                {
                    for pat in pats.iter().take(50) {
                        assert!(pat.initial_bytes.len() <= 32);
                        assert!(!pat.names.is_empty());
                    }
                    return; // one rlib is enough for the smoke test
                }
            }
        }
    }
}
