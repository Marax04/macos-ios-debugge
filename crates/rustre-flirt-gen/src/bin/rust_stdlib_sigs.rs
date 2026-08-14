//! Generate a Rust standard-library fingerprint database (FLIRT-style) for
//! use by zyphora's `recover_library_names` pass.
//!
//! Reads every `*.rlib` file under a Rust toolchain's
//! `lib/rustlib/<triple>/lib/` directory, parses each member as a COFF object
//! via the `object` crate, and emits a single combined `.sig` file containing
//! a `FlirtPattern` per defined function (with relocated bytes replaced by
//! wildcards in the leading window).
//!
//! Usage:
//!     rust-stdlib-sigs --input <rustlib-lib-dir> --output <out-path.sig>

use anyhow::{anyhow, Context, Result};
use goblin::archive::Archive;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SymbolKind,
    SymbolSection,
};
use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};
use std::io::Write;
use std::path::PathBuf;

/// Write a `Vec<FlirtPattern>` to a compact custom binary format the GUI side
/// can read back without going through the IDA `.sig` trie.
///
/// ```text
/// "RFLIRTBIN\0" magic (10 bytes)
/// [u32 count]
/// per-pattern:
///   [u16 prefix_len][prefix_bytes][u16 mask_len][mask_bytes]
///   [u16 crc16][u8 crc_length][u16 pattern_length]
///   [u8 name_count]
///   per-name:
///     [u8 flags] (bit0=is_public, bit1=is_local)
///     [u16 offset]
///     [u16 name_len][name_bytes]
/// ```
fn write_custom(dest: &std::path::Path, patterns: &[FlirtPattern]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(dest)?;
    f.write_all(b"RFLIRTBIN\0")?;
    f.write_all(&u32::try_from(patterns.len()).unwrap_or(u32::MAX).to_le_bytes())?;
    for p in patterns {
        let mut prefix = Vec::with_capacity(p.initial_bytes.len());
        let mut mask = Vec::with_capacity(p.initial_bytes.len());
        for b in &p.initial_bytes {
            match b {
                PatternByte::Exact(v) => {
                    prefix.push(*v);
                    mask.push(0xff);
                }
                PatternByte::Wildcard => {
                    prefix.push(0);
                    mask.push(0);
                }
            }
        }
        f.write_all(&u16::try_from(prefix.len()).unwrap_or(u16::MAX).to_le_bytes())?;
        f.write_all(&prefix)?;
        f.write_all(&u16::try_from(mask.len()).unwrap_or(u16::MAX).to_le_bytes())?;
        f.write_all(&mask)?;
        f.write_all(&p.crc16.to_le_bytes())?;
        f.write_all(&[p.crc_length])?;
        f.write_all(&p.pattern_length.to_le_bytes())?;
        f.write_all(&[u8::try_from(p.names.len().min(255)).unwrap_or(255)])?;
        for n in &p.names {
            let mut flags = 0u8;
            if n.is_public {
                flags |= 0x01;
            }
            if n.is_local {
                flags |= 0x02;
            }
            f.write_all(&[flags])?;
            f.write_all(&n.offset.to_le_bytes())?;
            let nb = n.name.as_bytes();
            let nb_len = nb.len().min(usize::from(u16::MAX));
            f.write_all(&u16::try_from(nb_len).unwrap_or(u16::MAX).to_le_bytes())?;
            f.write_all(&nb[..nb_len])?;
        }
    }
    Ok(())
}

const PREFIX_LEN: usize = 32;
const CRC_LEN: usize = 256;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut lib_name: String = "rust-stdlib".to_string();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--input" => {
                if let Some(v) = args.next() {
                    inputs.push(PathBuf::from(v));
                }
            }
            "--output" => output = args.next().map(PathBuf::from),
            "--name" => lib_name = args.next().unwrap_or(lib_name),
            "-h" | "--help" => {
                eprintln!("usage: rust-stdlib-sigs [--input <rlib-dir>]+ --output <out.sig> [--name <libname>]");
                return Ok(());
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }
    if inputs.is_empty() {
        return Err(anyhow!("at least one --input <rlib-dir> required"));
    }
    let output = output.ok_or_else(|| anyhow!("--output <out.sig> required"))?;

    let mut rlibs: Vec<PathBuf> = Vec::new();
    for input in &inputs {
        let here: Vec<PathBuf> = std::fs::read_dir(input)
            .with_context(|| format!("read_dir {}", input.display()))?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "rlib"))
            .collect();
        eprintln!("[sigs] {} rlibs found in {}", here.len(), input.display());
        rlibs.extend(here);
    }

    let mut patterns: Vec<FlirtPattern> = Vec::new();
    for rlib in &rlibs {
        match harvest_rlib(rlib) {
            Ok(mut pats) => {
                eprintln!(
                    "[sigs]   {} -> {} patterns",
                    rlib.file_name().unwrap().to_string_lossy(),
                    pats.len()
                );
                patterns.append(&mut pats);
            }
            Err(e) => {
                eprintln!(
                    "[sigs]   {} skipped: {e}",
                    rlib.file_name().unwrap().to_string_lossy()
                );
            }
        }
    }
    eprintln!("[sigs] total raw patterns: {}", patterns.len());
    // Dedup by (prefix-bytes-with-mask, crc16, primary-name).
    let mut seen: std::collections::HashSet<(Vec<u8>, Vec<u8>, u16, String)> =
        std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(patterns.len());
    for p in patterns {
        let prefix: Vec<u8> = p
            .initial_bytes
            .iter()
            .map(|b| match b {
                PatternByte::Exact(v) => *v,
                PatternByte::Wildcard => 0,
            })
            .collect();
        let mask: Vec<u8> = p
            .initial_bytes
            .iter()
            .map(|b| match b {
                PatternByte::Exact(_) => 0xff,
                PatternByte::Wildcard => 0,
            })
            .collect();
        let name = p.names.first().map(|n| n.name.clone()).unwrap_or_default();
        let key = (prefix, mask, p.crc16, name);
        if seen.insert(key) {
            deduped.push(p);
        }
    }
    let patterns = deduped;
    eprintln!("[sigs] deduped patterns: {}", patterns.len());

    write_custom(&output, &patterns[..])
        .with_context(|| format!("write_custom {}", output.display()))?;
    let bytes_written = std::fs::metadata(&output)?.len();
    eprintln!(
        "[sigs] wrote {} ({} bytes)",
        output.display(),
        bytes_written
    );

    // Also emit a SignaturePack text pack next to the .sig binary so the
    // PE loader's flirt-autoname hook can ingest it without going through
    // the IDA trie reader.
    let pack_path = output.with_extension("sigpack");
    write_sigpack(&pack_path, &lib_name, &patterns[..])
        .with_context(|| format!("write_sigpack {}", pack_path.display()))?;
    eprintln!("[sigs] wrote sigpack {}", pack_path.display());
    Ok(())
}

/// Convert the harvested [`FlirtPattern`]s into the text `SignaturePack`
/// format consumed by `rustre-flirt-apply`'s loader hook.
fn write_sigpack(
    dest: &std::path::Path,
    lib_name: &str,
    patterns: &[FlirtPattern],
) -> std::io::Result<()> {
    use std::fmt::Write as FmtWrite;
    let mut out = String::new();
    out.push_str("SIGPACK 1\n");
    out.push_str("pack ");
    out.push_str(lib_name);
    out.push('\n');
    out.push_str("---\n");

    for p in patterns {
        let primary = p
            .names
            .iter()
            .find(|n| n.is_public)
            .or_else(|| p.names.first());
        let Some(name) = primary else { continue };

        // Hex pattern with `..` for wildcards.
        let mut hex = String::with_capacity(p.initial_bytes.len() * 2);
        for b in &p.initial_bytes {
            match b {
                PatternByte::Exact(v) => { let _ = write!(hex, "{v:02X}"); }
                PatternByte::Wildcard => hex.push_str(".."),
            }
        }

        // Sanitize free-text fields for the `|`-delimited format.
        let safe_lib = sigpack_escape(lib_name);
        let safe_name = sigpack_escape(&name.name);

        let _ = writeln!(out,
            "{hex} | 0 {crc_len} {crc:04X} {tot} | {safe_lib} | {safe_name}",
            crc_len = p.crc_length,
            crc = p.crc16,
            tot = p.pattern_length,
        );
    }

    std::fs::write(dest, out)
}

/// Sigpack escape (mirrors `sig_pack::escape_field` in rustre-flirt-apply).
fn sigpack_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\p")
        .replace('\n', "\\n")
}

fn harvest_rlib(path: &std::path::Path) -> Result<Vec<FlirtPattern>> {
    let buf = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let arch =
        Archive::parse(&buf).with_context(|| format!("parse archive {}", path.display()))?;
    let members: Vec<&str> = arch.members().into_iter().collect();
    let mut obj_count = 0usize;
    let mut parse_ok = 0usize;
    let mut parse_err = 0usize;
    let mut out = Vec::new();
    for member_name in &members {
        let Ok(member_bytes) = arch.extract(member_name, &buf) else {
            continue;
        };
        // Rust rlibs contain .o COFF objects as members named like
        // "<crate>-<hash>.<hash>-cgu.0.rcgu.o" — accept any member that
        // starts with the COFF magic instead of relying on the filename.
        if member_bytes.len() < 4 {
            continue;
        }
        // COFF x86-64: machine = 0x8664 little-endian -> first 2 bytes 0x64 0x86.
        let looks_coff = member_bytes[0] == 0x64 && member_bytes[1] == 0x86;
        let has_obj_ext = std::path::Path::new(member_name).extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("o") || e.eq_ignore_ascii_case("obj"));
        if !looks_coff && !has_obj_ext {
            continue;
        }
        obj_count += 1;
        match harvest_object(member_bytes) {
            Ok(mut new_pats) => {
                parse_ok += 1;
                out.append(&mut new_pats);
            }
            Err(_) => {
                parse_err += 1;
            }
        }
    }
    eprintln!(
        "[sigs]     {} members, {} objects, {} parsed, {} parse-err",
        members.len(),
        obj_count,
        parse_ok,
        parse_err,
    );
    Ok(out)
}

/// Build a wildcard mask for `body` (size `size`) using section relocations
/// in the range `[off, off+size)`. Only symbol-referencing relocations are masked.
fn build_wildcard_mask(
    section: &object::Section<'_, '_>,
    off: usize,
    size: usize,
) -> Vec<bool> {
    let mut mask = vec![false; size];
    for (rel_off, rel) in section.relocations() {
        if !matches!(rel.target(), RelocationTarget::Symbol(_)) { continue; }
        let r_off = usize::try_from(rel_off).unwrap_or(0);
        if r_off < off || r_off >= off + size { continue; }
        let local = r_off - off;
        let width = if rel.kind() == RelocationKind::Absolute { 8usize } else { 4usize };
        for w in 0..width { if local + w < size { mask[local + w] = true; } }
    }
    mask
}

fn harvest_object(buf: &[u8]) -> Result<Vec<FlirtPattern>> {
    let file = object::File::parse(buf).map_err(|e| anyhow!("object::parse: {e}"))?;
    let mut by_section: std::collections::HashMap<object::SectionIndex, Vec<(u64, object::Symbol<'_, '_>)>> =
        std::collections::HashMap::new();
    for sym in file.symbols() {
        if sym.kind() != SymbolKind::Text && sym.kind() != SymbolKind::Unknown { continue; }
        let SymbolSection::Section(sec_idx) = sym.section() else { continue; };
        let Ok(sec) = file.section_by_index(sec_idx) else { continue };
        if !sec.name().unwrap_or("").starts_with(".text") { continue; }
        by_section.entry(sec_idx).or_default().push((sym.address(), sym));
    }
    let mut out = Vec::new();
    for (sec_idx, mut entries) in by_section {
        entries.sort_by_key(|(a, _)| *a);
        let Ok(section) = file.section_by_index(sec_idx) else { continue };
        let Ok(sec_data) = section.data() else { continue };
        let sec_addr = usize::try_from(section.address()).unwrap_or(0);
        let sec_end = sec_addr + sec_data.len();
        for i in 0..entries.len() {
            let sym = &entries[i].1;
            let addr = usize::try_from(sym.address()).unwrap_or(0);
            let mut size = usize::try_from(sym.size()).unwrap_or(0);
            if size == 0 {
                let next_addr = entries.get(i + 1)
                    .map_or(sec_end, |(a, _)| usize::try_from(*a).unwrap_or(0));
                size = next_addr.saturating_sub(addr);
            }
            if size < 16 { continue; }
            let off = addr.saturating_sub(sec_addr);
            if off + size > sec_data.len() { continue; }
            let body = &sec_data[off..off + size];
            let wildcard_mask = build_wildcard_mask(&section, off, size);

            let prefix_end = body.len().min(PREFIX_LEN);
            let initial_bytes: Vec<PatternByte> = (0..prefix_end)
                .map(|i| if wildcard_mask[i] { PatternByte::Wildcard } else { PatternByte::Exact(body[i]) })
                .collect();
            let crc_start = prefix_end;
            let crc_end_max = (crc_start + CRC_LEN).min(body.len());
            let mut crc_end = crc_start;
            while crc_end < crc_end_max && !wildcard_mask[crc_end] { crc_end += 1; }
            let crc_len = crc_end - crc_start;
            let crc16 = rustre_flirt_gen::crc16_sig_header(&body[crc_start..crc_end]);

            let mangled = sym.name().unwrap_or("");
            if mangled.is_empty() { continue; }
            let demangled = rustc_demangle::demangle(mangled).to_string();
            let pat = FlirtPattern {
                initial_bytes,
                crc16,
                crc_length: u8::try_from(crc_len.min(255)).unwrap_or(255),
                pattern_length: u16::try_from(size.min(usize::from(u16::MAX))).unwrap_or(u16::MAX),
                names: vec![FlirtName { name: demangled, offset: 0,
                    is_public: !sym.is_local(), is_local: sym.is_local() }],
                tail_bytes: Vec::new(),
                referenced_names: Vec::new(),
            };
            out.push(pat);
        }
    }
    Ok(out)
}
