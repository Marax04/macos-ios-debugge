// ============================================================================
// analysis/rust_type_recovery.rs — Recover Rust type information from .rdata
//
// Three independent passes, all working on the raw binary buffer plus the
// resolved segment list:
//
//   1. `extract_rust_panic_sites`   — scan `.rdata` for embedded panic-site
//                                     strings (filename + line + col).
//   2. `extract_rust_type_mentions` — scan `.rdata` for embedded type-path
//                                     strings (`core::option::Option<…>` etc.).
//   3. `detect_rust_vtables`        — heuristic Rust trait-object vtable scan
//                                     looking for [drop_in_place, size, align,
//                                     method_0, …] aligned arrays.
//
// All three are surfaced via the [`recover_rust_types`] entrypoint.
// ============================================================================

use crate::core::types::{
    Addr, RustPanicSite, RustTypeMention, RustTypeRecovery, RustVtable, Segment, SegmentFlags,
    SegmentKind,
};

const MAX_TYPE_NAME_LEN: usize = 512;
const MIN_TYPE_NAME_LEN: usize = 4;
const MAX_VTABLE_METHODS: usize = 256;

// ── helpers ───────────────────────────────────────────────────────────────────

fn rdata_range(binary: &[u8], segments: &[Segment]) -> Option<(usize, usize, u64)> {
    // Prefer a segment named ".rdata" or kind Rodata; fall back to any
    // read-only data segment.
    let pick = segments
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(".rdata"))
        .or_else(|| segments.iter().find(|s| s.kind == SegmentKind::Rodata))
        .or_else(|| {
            segments
                .iter()
                .find(|s| s.flags.contains(SegmentFlags::READ) && !s.flags.contains(SegmentFlags::EXECUTE))
        })?;
    let start = usize::try_from(pick.mapped_offset).ok()?;
    let size = usize::try_from(pick.size()).ok()?;
    let end = start.saturating_add(size).min(binary.len());
    if start >= end {
        return None;
    }
    Some((start, end, pick.start.0))
}

fn text_ranges(segments: &[Segment]) -> Vec<(u64, u64)> {
    segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.end.0))
        .collect()
}

fn is_text_addr(ranges: &[(u64, u64)], addr: u64) -> bool {
    ranges.iter().any(|(s, e)| addr >= *s && addr < *e)
}

fn read_u64_le(slice: &[u8], at: usize) -> Option<u64> {
    slice.get(at..at + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

fn read_u32_le(slice: &[u8], at: usize) -> Option<u32> {
    slice.get(at..at + 4).map(|b| {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// Scan the readable byte slice for the start of a UTF-8 run of ASCII printable
/// characters at `pos`, returning the slice if it's at least `min_len` long.
fn ascii_run(slice: &[u8], pos: usize, min_len: usize) -> Option<&str> {
    let mut end = pos;
    while end < slice.len() {
        let b = slice[end];
        if !(0x20..0x7f).contains(&b) {
            break;
        }
        end += 1;
    }
    if end.saturating_sub(pos) < min_len {
        return None;
    }
    std::str::from_utf8(&slice[pos..end]).ok()
}

// ── 1. Panic-site extraction ──────────────────────────────────────────────────

/// Scan `.rdata` for embedded Rust panic strings — filenames ending in `.rs`.
/// We do not require an immediately adjacent (line, col) tuple in the bytes
/// because the actual `Location` struct lives in a separate read-only slot
/// near the call site; the filename run is the durable anchor.
pub fn extract_rust_panic_sites(binary: &[u8], segments: &[Segment]) -> Vec<RustPanicSite> {
    let Some((start, end, base_va)) = rdata_range(binary, segments) else {
        return Vec::new();
    };
    let slice = &binary[start..end];
    let mut out: Vec<RustPanicSite> = Vec::new();
    let mut i = 0usize;
    while i < slice.len() {
        // Find next ASCII run.
        if slice[i] < 0x20 || slice[i] >= 0x7f {
            i += 1;
            continue;
        }
        let Some(run) = ascii_run(slice, i, 6) else {
            i += 1;
            continue;
        };
        let run_len = run.len();
        // Filename heuristic: ends in `.rs`, contains `/` or `\`, doesn't
        // contain spaces.
        if std::path::Path::new(run).extension().is_some_and(|e| e.eq_ignore_ascii_case("rs"))
            && !run.contains(' ')
            && (run.contains('/') || run.contains('\\') || run.contains("src"))
            && run_len < 256
        {
            let addr_off = i;
            // Look for a (line, col) pair in the next 32 bytes — typical Rust
            // panic-info layouts emit `ptr,len,line,col` immediately after.
            let mut line: u32 = 0;
            let mut col: u32 = 0;
            let after = i + run_len + 1; // skip NUL pad
            if let Some(window) = slice.get(after..after.saturating_add(32)) {
                for off in (0..window.len().saturating_sub(8)).step_by(4) {
                    let l = read_u32_le(window, off).unwrap_or(0);
                    let c = read_u32_le(window, off + 4).unwrap_or(0);
                    if (1..100_000).contains(&l) && (1..1000).contains(&c) {
                        line = l;
                        col = c;
                        break;
                    }
                }
            }
            out.push(RustPanicSite {
                addr: Addr(base_va.saturating_add(addr_off as u64)),
                file: run.to_string(),
                line,
                col,
                message: None,
            });
        }
        i += run_len.max(1);
    }
    // Dedupe by (file, line) keeping first.
    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out.dedup_by(|a, b| a.file == b.file && a.line == b.line);
    out
}

// ── 2. Type-mention extraction ────────────────────────────────────────────────

/// Anchor prefixes used to detect Rust type-path strings. Cheap to extend.
const TYPE_ANCHORS: &[&str] = &[
    "core::",
    "alloc::",
    "std::",
    "hashbrown::",
    "serde::",
    "tokio::",
    "anyhow::",
    "futures::",
];

/// Scan `.rdata` for embedded Rust type-path strings starting with one of
/// [`TYPE_ANCHORS`]. The parser is a balanced-bracket state machine:
/// opens on `<`, increments on every `<`, decrements on every `>`,
/// terminates when balance returns to zero (or the string ends).
pub fn extract_rust_type_mentions(
    binary: &[u8],
    segments: &[Segment],
) -> Vec<RustTypeMention> {
    let Some((start, end, base_va)) = rdata_range(binary, segments) else {
        return Vec::new();
    };
    let slice = &binary[start..end];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<RustTypeMention> = Vec::new();

    let mut i = 0usize;
    while i < slice.len() {
        let b = slice[i];
        if !(0x20..0x7f).contains(&b) {
            i += 1;
            continue;
        }
        let mut matched: Option<&str> = None;
        for anchor in TYPE_ANCHORS {
            let abytes = anchor.as_bytes();
            if slice.len().saturating_sub(i) >= abytes.len()
                && &slice[i..i + abytes.len()] == abytes
            {
                matched = Some(anchor);
                break;
            }
        }
        if let Some(_anchor) = matched {
            // Greedy lex: consume identifier chars + `:` + `<>` until we hit a
            // non-type-path byte. Balanced-bracket counter.
            let mut j = i;
            let mut balance: i32 = 0;
            let mut last_nonbracket_end = i;
            while j < slice.len() {
                let c = slice[j];
                let ok = matches!(c,
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b':' | b'<' | b'>' | b','
                    | b' ' | b'&' | b'*' | b'(' | b')' | b'[' | b']' | b'\'' | b'-'
                );
                if !ok {
                    break;
                }
                if c == b'<' {
                    balance += 1;
                } else if c == b'>' {
                    if balance == 0 {
                        break;
                    }
                    balance -= 1;
                }
                j += 1;
                if balance == 0 {
                    last_nonbracket_end = j;
                }
                if j - i > MAX_TYPE_NAME_LEN {
                    break;
                }
            }
            if balance != 0 {
                // Unbalanced; trim back to last balanced position.
                j = last_nonbracket_end;
            }
            if j - i >= MIN_TYPE_NAME_LEN {
                let raw = &slice[i..j];
                if let Ok(s) = std::str::from_utf8(raw) {
                    let trimmed = s.trim_end_matches([',', ' ', '<']);
                    if !trimmed.is_empty()
                        && seen.insert(trimmed.to_string())
                        && trimmed.len() <= MAX_TYPE_NAME_LEN
                    {
                        out.push(RustTypeMention {
                            addr: Addr(base_va.saturating_add(i as u64)),
                            type_path: trimmed.to_string(),
                        });
                    }
                }
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    out
}

// ── 3. Vtable detection ───────────────────────────────────────────────────────

/// Heuristic Rust trait-object vtable detector. Looks for aligned pointer-sized
/// slots in `.rdata` matching the canonical layout
/// `[drop_in_place, size, align, method_0, method_1, …]`.
///
/// Recognition rules:
/// * slot 0 is a pointer landing in an executable segment (`drop_in_place`),
/// * slot 1 is a positive size between 1 and `0x0010_0000` (avoid the ptr value),
/// * slot 2 is a power-of-two align between 1 and 0x1000,
/// * slots 3.. are pointers into an executable segment (method table).
pub fn detect_rust_vtables(binary: &[u8], segments: &[Segment]) -> Vec<RustVtable> {
    let Some((start, end, base_va)) = rdata_range(binary, segments) else {
        return Vec::new();
    };
    let slice = &binary[start..end];
    let text_segs = text_ranges(segments);
    if text_segs.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<RustVtable> = Vec::new();
    let step = 8usize;
    let mut i = 0usize;
    while i + step * 4 <= slice.len() {
        let Some(drop_ptr) = read_u64_le(slice, i) else {
            break;
        };
        let Some(size_word) = read_u64_le(slice, i + 8) else {
            break;
        };
        let Some(align_word) = read_u64_le(slice, i + 16) else {
            break;
        };
        let valid_drop = is_text_addr(&text_segs, drop_ptr);
        let valid_size = (1..=0x0010_0000).contains(&size_word);
        let valid_align = align_word > 0
            && align_word <= 0x1000
            && align_word.is_power_of_two();
        if !(valid_drop && valid_size && valid_align) {
            i += step;
            continue;
        }
        // Collect methods.
        let mut methods: Vec<Addr> = Vec::new();
        let mut j = i + 24;
        let mut consecutive_non_text = 0usize;
        while j + 8 <= slice.len() && methods.len() < MAX_VTABLE_METHODS {
            let Some(p) = read_u64_le(slice, j) else {
                break;
            };
            if is_text_addr(&text_segs, p) {
                methods.push(Addr(p));
                consecutive_non_text = 0;
            } else {
                consecutive_non_text += 1;
                if consecutive_non_text >= 1 {
                    break;
                }
            }
            j += 8;
        }
        if methods.is_empty() {
            i += step;
        } else {
            out.push(RustVtable {
                addr: Addr(base_va.saturating_add(i as u64)),
                type_name: None,
                methods,
            });
            i = j;
        }
    }
    out
}

// ── public entrypoint ─────────────────────────────────────────────────────────

/// Run all three Rust type-recovery passes and bundle the result.
pub fn recover_rust_types(binary: &[u8], segments: &[Segment]) -> RustTypeRecovery {
    RustTypeRecovery {
        panic_sites: extract_rust_panic_sites(binary, segments),
        type_mentions: extract_rust_type_mentions(binary, segments),
        vtables: detect_rust_vtables(binary, segments),
    }
}

// ── prod ensure-used ──────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_rust_type_recovery() {
    let buf: Vec<u8> = vec![0u8; 16];
    let segs: Vec<Segment> = Vec::new();
    let r = recover_rust_types(&buf, &segs);
    let _ = (
        r.panic_sites.len(),
        r.type_mentions.len(),
        r.vtables.len(),
    );
    let _ = extract_rust_panic_sites(&buf, &segs);
    let _ = extract_rust_type_mentions(&buf, &segs);
    let _ = detect_rust_vtables(&buf, &segs);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_segments(rdata_off: u64, rdata_size: u64, text_va: u64) -> Vec<Segment> {
        vec![
            Segment {
                id: 0,
                name: ".text".into(),
                start: Addr(text_va),
                end: Addr(text_va.saturating_add(0x1000)),
                flags: SegmentFlags::READ | SegmentFlags::EXECUTE,
                kind: SegmentKind::Code,
                mapped_offset: 0,
            },
            Segment {
                id: 1,
                name: ".rdata".into(),
                start: Addr(0x100_0000),
                end: Addr(0x100_0000_u64.saturating_add(rdata_size)),
                flags: SegmentFlags::READ,
                kind: SegmentKind::Rodata,
                mapped_offset: rdata_off,
            },
        ]
    }

    #[test]
    fn finds_panic_filename() {
        let mut buf = vec![0u8; 4096];
        let s = b"src/lib.rs\0";
        buf[100..100 + s.len()].copy_from_slice(s);
        let segs = synthetic_segments(0, 4096, 0x40_0000);
        let sites = extract_rust_panic_sites(&buf, &segs);
        assert!(sites.iter().any(|p| p.file == "src/lib.rs"));
    }

    #[test]
    fn finds_type_mention() {
        let mut buf = vec![0u8; 4096];
        let s = b"core::option::Option<u32>\0";
        buf[200..200 + s.len()].copy_from_slice(s);
        let segs = synthetic_segments(0, 4096, 0x40_0000);
        let m = extract_rust_type_mentions(&buf, &segs);
        assert!(m.iter().any(|t| t.type_path.starts_with("core::option::Option")));
    }
}
