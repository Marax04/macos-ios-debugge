//! Generate a `SignaturePack` of MSVC CRT routines by walking one or more
//! `.lib` archives from a Visual Studio installation.
//!
//! Usage:
//!     msvcrt-sigs --input <path-to-libcmt.lib>+ --output <out.sigpack> [--name <libname>]
//!
//! Each `.lib` archive member is parsed as a COFF object via the `object`
//! crate. For every text-symbol with a usable size, the leading bytes are
//! captured (relocations become wildcards) and emitted as a `SignaturePack`
//! pattern line consumable by `rustre-flirt-apply`.

use anyhow::{Context, Result, anyhow};
use goblin::archive::Archive;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationKind, SymbolKind, SymbolSection,
};
use std::io::Write;
use std::path::PathBuf;

const PREFIX_LEN: usize = 32;

struct Pattern {
    bytes: Vec<Option<u8>>, // None = wildcard
    name: String,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut lib_name: String = "msvcrt".to_string();
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
                eprintln!(
                    "usage: msvcrt-sigs --input <archive.lib>+ --output <out.sigpack> [--name <libname>]"
                );
                return Ok(());
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }
    if inputs.is_empty() {
        return Err(anyhow!("at least one --input <archive.lib> required"));
    }
    let output = output.ok_or_else(|| anyhow!("--output <out.sigpack> required"))?;

    let mut all_patterns: Vec<Pattern> = Vec::new();
    for lib_path in &inputs {
        let buf = std::fs::read(lib_path).with_context(|| format!("read {}", lib_path.display()))?;
        let arch = match Archive::parse(&buf) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[msvcrt-sigs] skip {}: {e}", lib_path.display());
                continue;
            }
        };
        let members: Vec<&str> = arch.members().into_iter().collect();
        eprintln!(
            "[msvcrt-sigs] {} ({} members)",
            lib_path.display(),
            members.len()
        );
        for m in &members {
            let Ok(bytes) = arch.extract(m, &buf) else {
                continue;
            };
            if bytes.len() < 4 {
                continue;
            }
            if let Ok(mut pats) = harvest_object(bytes) {
                all_patterns.append(&mut pats);
            }
        }
    }

    eprintln!("[msvcrt-sigs] total patterns: {}", all_patterns.len());

    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<Pattern> = Vec::new();
    for p in all_patterns {
        let key = (p.bytes.clone(), p.name.clone());
        if seen.insert(key) {
            deduped.push(p);
        }
    }
    eprintln!("[msvcrt-sigs] deduped patterns: {}", deduped.len());

    write_sigpack(&output, &lib_name, &deduped[..])
        .with_context(|| format!("write {}", output.display()))?;
    eprintln!("[msvcrt-sigs] wrote {}", output.display());
    Ok(())
}

fn harvest_object(buf: &[u8]) -> Result<Vec<Pattern>> {
    let file = object::File::parse(buf).map_err(|e| anyhow!("object::parse: {e}"))?;

    let mut by_section: std::collections::HashMap<
        object::SectionIndex,
        Vec<(u64, object::Symbol<'_, '_>)>,
    > = std::collections::HashMap::new();
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
        let sec_name = sec.name().unwrap_or("");
        if !sec_name.starts_with(".text") {
            continue;
        }
        by_section
            .entry(sec_idx)
            .or_default()
            .push((sym.address(), sym));
    }

    let mut out = Vec::new();
    for (sec_idx, mut entries) in by_section {
        entries.sort_by_key(|(a, _)| *a);
        let Ok(section) = file.section_by_index(sec_idx) else {
            continue;
        };
        let Ok(sec_data) = section.data() else { continue };
        let sec_addr = usize::try_from(section.address()).unwrap_or(0);
        let sec_end = sec_addr + sec_data.len();

        for i in 0..entries.len() {
            let sym = &entries[i].1;
            let addr = usize::try_from(sym.address()).unwrap_or(0);
            let mut size = usize::try_from(sym.size()).unwrap_or(0);
            if size == 0 {
                let next_addr = entries
                    .get(i + 1)
                    .map_or(sec_end, |(a, _)| usize::try_from(*a).unwrap_or(0));
                size = next_addr.saturating_sub(addr);
            }
            if size < 8 {
                continue;
            }
            let off = addr.saturating_sub(sec_addr);
            if off + size > sec_data.len() {
                continue;
            }

            let body = &sec_data[off..off + size];
            let mut wildcard_mask = vec![false; size];
            for (rel_off, rel) in section.relocations() {
                let r_off = usize::try_from(rel_off).unwrap_or(0);
                if r_off < off || r_off >= off + size {
                    continue;
                }
                let local = r_off - off;
                let width = match rel.kind() {
                    RelocationKind::Absolute => 8usize,
                    _ => 4usize,
                };
                for w in 0..width {
                    let idx = local + w;
                    if idx < size {
                        wildcard_mask[idx] = true;
                    }
                }
            }

            let prefix_end = body.len().min(PREFIX_LEN);
            let bytes: Vec<Option<u8>> = (0..prefix_end)
                .map(|i| {
                    if wildcard_mask[i] {
                        None
                    } else {
                        Some(body[i])
                    }
                })
                .collect();

            let name = sym.name().unwrap_or("");
            if name.is_empty() {
                continue;
            }

            out.push(Pattern {
                bytes,
                name: name.to_string(),
            });
        }
    }
    Ok(out)
}

fn write_sigpack(dest: &std::path::Path, lib_name: &str, patterns: &[Pattern]) -> std::io::Result<()> {
    use std::fmt::Write as FmtWrite;
    let mut f = std::fs::File::create(dest)?;
    writeln!(f, "SIGPACK 1")?;
    writeln!(f, "pack {lib_name}")?;
    writeln!(f, "---")?;
    for p in patterns {
        let mut hex = String::with_capacity(p.bytes.len() * 2);
        for b in &p.bytes {
            match b {
                Some(v) => { let _ = write!(hex, "{v:02X}"); }
                None => hex.push_str(".."),
            }
        }
        let safe_lib = escape(lib_name);
        let safe_name = escape(&p.name);
        writeln!(
            f,
            "{hex} | 0 0 0000 {tot} | {safe_lib} | {safe_name}",
            tot = p.bytes.len()
        )?;
    }
    Ok(())
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\p")
        .replace('\n', "\\n")
}
