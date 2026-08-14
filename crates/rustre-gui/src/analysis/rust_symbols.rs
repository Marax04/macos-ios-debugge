// ============================================================================
// analysis/rust_symbols.rs — Rust mangled-name recovery for stripped PEs
//
// Stripped Rust release binaries have no COFF symbol table and no PDB, so
// `object`-driven symbol enumeration returns near-zero entries. This pass mines
// the embedded `.rdata` mangled-name table that rustc emits for the panic /
// backtrace machinery:
//
//   1. Mangled-name strings (`_ZN…E`, `_R…`, bare `core::`/`alloc::`/`std::`/
//      `compiler_builtins::` namespaces). Each name is preceded in many cases
//      by a pointer-sized word pointing back into `.text` (the file/loc
//      descriptor tables emit `(fn_ptr, name_ptr, name_len, …)` tuples). We
//      resolve those address→name links opportunistically.
//
//   2. As a fallback, any mangled-name string whose surrounding bytes did not
//      contain a pointer back into `.text` is recorded as a public-name symbol
//      pinned at the string's VA, so the demangled label still surfaces in
//      the Symbols panel.
//
// IMPORTANT: this pass is *names only*. It must NEVER call
// `data.functions.insert()` — function-start discovery is the job of
// `discover_functions` + `sweep_executable_sections`, which run AFTER this
// pass in `load_binary`. The `.pdata` exception directory is deliberately NOT
// scanned here: MSVC and the LLVM linker emit `RUNTIME_FUNCTION` entries for
// jump trampolines, SEH personality routines, and BOLT-style chunk splits
// that are not real function starts and would inflate the function count.
//
// When a recovered (address, name) lands on an address that already has a
// `Function` entry, we rename that function in place to the demangled name
// (or the mangled name if demangling fails) — we still don't insert anything
// into `data.functions`.
//
// The pass mutates `AppData.symbols`, `AppData.sym_by_addr`, and
// `AppData.functions[*].name` only. It is invoked from
// `AnalysisEngine::load_binary` after the initial `extract_symbols` pass and
// BEFORE `discover_functions`.
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::types::{Addr, Segment, SegmentFlags, SegmentKind, Symbol, SymbolKind};

/// One recovered (address → name) pairing produced by the scan.
#[derive(Debug, Clone)]
struct Recovered {
    addr: u64,
    name: String,
    /// `true` when the address comes from a pointer that lands inside an
    /// executable segment (a real `.text` VA). `false` when we only know the
    /// name's string VA (fallback).
    is_function: bool,
}

/// Public entry point — runs the name-recovery scan and merges into `AppData`.
///
/// Returns `(name_strings_found, renamed_functions, symbols_added)` so the
/// caller can log per-pass counts. The second slot used to be a `.pdata` entry
/// count; it is now repurposed for "existing functions renamed in place".
pub fn recover_rust_symbols(data: &mut AppData) -> (usize, usize, usize) {
    let Some(binary) = data.binary_data.clone() else {
        eprintln!("[rust_symbols] no binary_data");
        return (0, 0, 0);
    };
    let segments = data.segments.clone();

    let mut name_hits = 0usize;
    let mut recovered: Vec<Recovered> = Vec::new();
    let ptr_size = pointer_size(data);
    let exec_ranges = executable_ranges(&segments);
    eprintln!(
        "[rust_symbols] binary_len={} segments={} exec_ranges={} ptr_size={}",
        binary.len(),
        segments.len(),
        exec_ranges.len(),
        ptr_size,
    );

    let mut scanned_segs = 0usize;
    for seg in &segments {
        if !seg.flags.contains(SegmentFlags::READ) {
            continue;
        }
        if seg.flags.contains(SegmentFlags::EXECUTE) {
            // Skip code sections; mangled-name string tables live in rodata.
            continue;
        }
        if matches!(seg.kind, SegmentKind::Bss) {
            // BSS has no on-disk bytes; the loader records mapped_offset=0 for
            // such sections which would otherwise alias to the PE header.
            continue;
        }
        let Some(bytes) = segment_bytes(&binary, seg) else {
            eprintln!(
                "[rust_symbols] skip seg name={} mapped_offset={} va_size={} (out of file bounds)",
                seg.name,
                seg.mapped_offset,
                seg.size(),
            );
            continue;
        };
        scanned_segs += 1;
        let before = name_hits;
        scan_section_for_names(
            bytes,
            seg.start.0,
            ptr_size,
            &exec_ranges,
            |hit| {
                name_hits += 1;
                recovered.push(hit);
            },
        );
        eprintln!(
            "[rust_symbols] seg={} bytes={} hits=+{}",
            seg.name,
            bytes.len(),
            name_hits - before,
        );
    }

    // Merge into AppData (symbols + sym_by_addr + opportunistic function
    // rename). No function insertion.
    let recovered_count = recovered.len();
    let (added, renamed) = merge_recovered(data, recovered);
    eprintln!(
        "[rust_symbols] scanned_segs={scanned_segs} scanned_names={name_hits} recovered={recovered_count} inserted_symbols={added} renamed_functions={renamed}",
    );

    (name_hits, renamed, added)
}

/// Walk a single section's bytes looking for ASCII mangled-name runs. For
/// every match, check the eight bytes immediately before the string start for
/// a pointer landing in `.text`; if found, emit a `(fn_addr → name)` pair,
/// otherwise emit a string-VA-pinned fallback so the name still surfaces.
fn scan_section_for_names<F: FnMut(Recovered)>(
    bytes: &[u8],
    section_va: u64,
    ptr_size: usize,
    exec_ranges: &[(u64, u64)],
    mut emit: F,
) {
    let mut i = 0usize;
    while i < bytes.len() {
        let prefix_len = match bytes.get(i..) {
            Some(r) if r.starts_with(b"_ZN") => 3,
            Some(r) if r.starts_with(b"_R") && r.len() > 2 && is_rust_v0_body(r[2]) => 2,
            Some(r) if r.starts_with(b"core::") => 0,
            Some(r) if r.starts_with(b"alloc::") => 0,
            Some(r) if r.starts_with(b"std::") => 0,
            Some(r) if r.starts_with(b"compiler_builtins::") => 0,
            _ => {
                i += 1;
                continue;
            }
        };

        let start = i;
        let mut j = i + prefix_len;
        while j < bytes.len() {
            let b = bytes[j];
            if b == 0 {
                break;
            }
            if !is_mangled_byte(b) {
                break;
            }
            j += 1;
        }

        let len = j.saturating_sub(start);
        if len >= 8 {
            if let Ok(name) = std::str::from_utf8(&bytes[start..j]) {
                // Require at least one `::` or trailing `E` so we don't ingest
                // every ASCII run with `_ZN` as a substring of unrelated data.
                if name.contains("::") || name.ends_with('E') {
                    let fn_addr = lookup_back_pointer(bytes, start, ptr_size, exec_ranges);
                    let str_va = section_va.wrapping_add(start as u64);
                    if let Some(faddr) = fn_addr {
                        emit(Recovered {
                            addr: faddr,
                            name: name.to_owned(),
                            is_function: true,
                        });
                    } else {
                        emit(Recovered {
                            addr: str_va,
                            name: name.to_owned(),
                            is_function: false,
                        });
                    }
                }
            }
        }
        i = j.saturating_add(1).max(start + 1);
    }
}

/// Check the 8 bytes immediately before `str_off` for a pointer-sized word
/// (u64 LE on 64-bit, u32 LE on 32-bit) whose value lands inside any
/// executable segment.
fn lookup_back_pointer(
    bytes: &[u8],
    str_off: usize,
    ptr_size: usize,
    exec_ranges: &[(u64, u64)],
) -> Option<u64> {
    if str_off < ptr_size {
        return None;
    }
    let p = str_off - ptr_size;
    let slice = bytes.get(p..p + ptr_size)?;
    let v = match ptr_size {
        8 => u64::from_le_bytes(slice.try_into().ok()?),
        4 => u64::from(u32::from_le_bytes(slice.try_into().ok()?)),
        _ => return None,
    };
    if exec_ranges.iter().any(|(s, e)| v >= *s && v < *e) {
        Some(v)
    } else {
        None
    }
}

/// Push recovered pairs into `AppData`. Returns `(symbols_added,
/// functions_renamed)`.
///
/// Rules (per spec — every recovered tuple becomes a Symbol):
///   * For EVERY (addr, mangled, demangled) tuple, insert a fresh `Symbol`
///     with `kind = SymbolKind::Function`, `name = demangled` (falling back
///     to the mangled string when demangling fails), and record
///     `data.sym_by_addr[addr] = sym_id`. If an entry already exists at that
///     address, overwrite the name/demangled/kind in place rather than
///     leaking a duplicate id.
///   * If a `Function` already exists at `addr` (i.e. `data.func_by_addr`
///     has the address), rename it in place to the demangled/pretty name —
///     unconditionally, not just when the current name is a `sub_*`
///     placeholder. Do NOT insert new `Function` entries.
///   * Deduplicate within this batch by `(addr, name)` so the same
///     mangled-name string referenced from multiple `.rdata` tuples doesn't
///     burn symbol ids.
fn merge_recovered(data: &mut AppData, recovered: Vec<Recovered>) -> (usize, usize) {
    let mut next_id = data
        .symbols
        .keys()
        .copied()
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut added = 0usize;
    let mut renamed = 0usize;

    // Deduplicate within this batch by (addr, name).
    let mut seen: std::collections::HashSet<(u64, String)> = std::collections::HashSet::new();

    for rec in recovered {
        if !seen.insert((rec.addr, rec.name.clone())) {
            continue;
        }
        // A back-pointer landed in `.text` → this is a real function start.
        // Without a back-pointer we only know the string VA, so the recovered
        // entry is a public/label name pinned at the rodata string itself.
        let kind = if rec.is_function {
            SymbolKind::Function
        } else {
            SymbolKind::Label
        };
        let demangled = try_demangle(&rec.name);
        let pretty_name = demangled.clone().unwrap_or_else(|| rec.name.clone());

        // Opportunistic function rename: if this address already has a
        // Function entry, replace its name with the demangled/pretty form.
        // Per spec we rename unconditionally — the recovered Rust name is
        // always more informative than the synthetic `sub_*` label, and
        // when the existing name was already real we still want to surface
        // the demangled form.
        if let Some(&fid) = data.func_by_addr.get(&rec.addr) {
            if let Some(f) = data.functions.get_mut(&fid) {
                f.name.clone_from(&pretty_name);
                renamed += 1;
            }
        }

        if let Some(existing_id) = data.sym_by_addr.get(&rec.addr).copied() {
            // Address already has a symbol — overwrite the slot in place so
            // the demangled Rust name wins, but reuse the existing id so we
            // never leak a duplicate `sym_by_addr` entry.
            if let Some(sym) = data.symbols.get_mut(&existing_id) {
                sym.name.clone_from(&rec.name);
                sym.demangled.clone_from(&demangled);
                sym.kind = kind;
                added += 1;
            }
            continue;
        }

        let sym = Symbol {
            id: next_id,
            addr: Addr(rec.addr),
            name: rec.name.clone(),
            demangled,
            kind,
            size: 0,
            is_public: true,
            is_import: false,
            module: None,
            ordinal: None,
            forwarded_to: None,
            flirt_library: None,
            resolved_target: None,
        };
        data.sym_by_addr.insert(rec.addr, next_id);
        data.symbols.insert(next_id, sym);
        next_id = next_id.saturating_add(1);
        added += 1;
    }
    (added, renamed)
}

fn try_demangle(name: &str) -> Option<String> {
    rustre_demangle::demangle(name).map(|d| d.demangled)
}

const fn pointer_size(data: &AppData) -> usize {
    match data.arch {
        crate::core::types::Architecture::X86_64
        | crate::core::types::Architecture::Arm64
        | crate::core::types::Architecture::Riscv64
        | crate::core::types::Architecture::Mips64
        | crate::core::types::Architecture::PowerPc64 => 8,
        _ => 4,
    }
}

fn executable_ranges(segments: &[Segment]) -> Vec<(u64, u64)> {
    segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.start.0.saturating_add(s.size())))
        .collect()
}

fn segment_bytes<'a>(binary: &'a [u8], seg: &Segment) -> Option<&'a [u8]> {
    let fo = usize::try_from(seg.mapped_offset).ok()?;
    if fo >= binary.len() {
        return None;
    }
    let va_len = usize::try_from(seg.size()).ok()?;
    // Clamp to actual file size — sections often have a larger VA size than
    // their raw on-disk size (BSS-style tail padding). Returning `None` for
    // those would skip the entire section, including the populated portion
    // that holds the mangled-name table.
    let end = fo.saturating_add(va_len).min(binary.len());
    binary.get(fo..end)
}

/// Byte allowed inside a Rust mangled name body.
const fn is_mangled_byte(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'_' | b'$' | b'.' | b':' | b'<' | b'>'
        | b'(' | b')' | b',' | b' ' | b'&' | b'*'
        | b'[' | b']' | b';' | b'\'' | b'-' | b'+'
        | b'/' | b'=' | b'!' | b'?' | b'@' | b'#'
    )
}

/// A Rust v0 mangled name (`_R…`) starts with an alphanumeric path component
/// or a special tag byte.
const fn is_rust_v0_body(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
}
