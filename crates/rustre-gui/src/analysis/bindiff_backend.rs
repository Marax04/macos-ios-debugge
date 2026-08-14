// ============================================================================
// analysis/bindiff_backend.rs — Two-binary bindiff backend
//
// Self-contained backend producing a [`BinDiffReport`] from two already-loaded
// binaries. The matching strategy intentionally mirrors the order documented
// in the project plan:
//
//   1. byte-identical pairs  → `functions_identical`
//   2. matched-by-name pairs (size-weighted similarity) → identical or changed
//   3. CFG-hash matched pairs (size/byte similarity)    → identical or changed
//   4. anything left over    → `functions_added` / `functions_removed`
//
// The actual function-body extraction reuses the `BinaryLoader` pipeline
// already used at GUI load-time, so the bindiff backend does not require
// pulling the heavyweight `rustre-diff-bindiff` crate into the GUI graph.
// ============================================================================

use crate::core::types::{Addr, BinDiffFuncSummary, BinDiffReport, Function, Segment};
use crate::formats::loader::BinaryLoader;
use std::collections::HashSet;
use std::sync::Arc;

/// Compact internal handle paired alongside a [`BinDiffFuncSummary`] so we can
/// pull the function body bytes when computing similarity.
struct FuncWithBody {
    summary: BinDiffFuncSummary,
    body: Vec<u8>,
}

impl FuncWithBody {
    fn byte_hash(&self) -> u64 {
        // Deterministic order-sensitive FNV-1a 64.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in &self.body {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

fn extract_function_bodies(
    binary: &[u8],
    segments: &[Segment],
    functions: &[Function],
) -> Vec<FuncWithBody> {
    let mut out = Vec::with_capacity(functions.len());
    for f in functions {
        let seg = segments.iter().find(|s| s.contains(f.addr));
        let body = seg
            .and_then(|s| {
                let off = f
                    .addr
                    .0
                    .checked_sub(s.start.0)?
                    .checked_add(s.mapped_offset)?;
                let off = usize::try_from(off).ok()?;
                let size = if f.size > 0 {
                    usize::try_from(f.size).ok()?.min(64 * 1024)
                } else {
                    256
                };
                binary
                    .get(off..off.saturating_add(size).min(binary.len()))
                    .map(<[u8]>::to_vec)
            })
            .unwrap_or_default();
        out.push(FuncWithBody {
            summary: BinDiffFuncSummary {
                addr: f.addr,
                name: f.name.clone(),
                size: f.size,
            },
            body,
        });
    }
    out
}

/// Byte-level similarity: 1.0 on equality, then a normalized longest-common
/// length proxy (size-aware) capped to the smaller body. Cheap enough to run
/// on every candidate pair without quadratic blow-up because we only ever
/// score pairs already filtered by name or CFG hash.
fn body_similarity(a: &[u8], b: &[u8]) -> f32 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let min_len = a.len().min(b.len());
    let max_len = a.len().max(b.len());
    let mut equal_prefix = 0usize;
    while equal_prefix < min_len && a[equal_prefix] == b[equal_prefix] {
        equal_prefix += 1;
    }
    let mut equal_suffix = 0usize;
    while equal_suffix < min_len.saturating_sub(equal_prefix)
        && a[a.len() - 1 - equal_suffix] == b[b.len() - 1 - equal_suffix]
    {
        equal_suffix += 1;
    }
    let common = equal_prefix + equal_suffix;
    let raw = common as f32 / max_len as f32;
    raw.clamp(0.0, 1.0)
}

/// Computed inputs needed to diff one binary.
struct Side {
    binary: Arc<crate::core::binary_buffer::BinaryBuffer>,
    segments: Vec<Segment>,
    functions: Vec<Function>,
}

fn load_side(bytes: Arc<crate::core::binary_buffer::BinaryBuffer>) -> anyhow::Result<Side> {
    let loader = BinaryLoader::new(Arc::clone(&bytes));
    let info = loader.parse()?;
    // The bindiff backend only needs a function list; we approximate it by
    // promoting every function-kind symbol so we don't drag the whole
    // analysis pipeline (sweep, FLIRT, …) for a diff that will run on two
    // already-analysed images most of the time. Callers that want a richer
    // function set can hand us a pre-analysed `AppData` snapshot directly via
    // [`diff_appdata_snapshots`] below.
    let mut next_id: u32 = 1;
    let mut funcs: Vec<Function> = Vec::new();
    for s in loader.symbols() {
        if matches!(s.kind, crate::core::types::SymbolKind::Function) && s.size > 0 {
            funcs.push(Function {
                id: next_id,
                addr: s.addr,
                name: s.display_name().to_owned(),
                size: s.size,
                tags: crate::core::types::FunctionTags::AUTO,
                sym_id: Some(s.id),
                comment: String::new(),
                color: None,
            });
            next_id = next_id.saturating_add(1);
        }
    }
    if !info.entry_point.is_valid() {
        // Edge case: stripped binary with no functions. Still return a Side
        // so caller can produce a coherent (mostly added/removed) report.
    }
    Ok(Side {
        binary: bytes,
        segments: info.segments,
        functions: funcs,
    })
}

/// Top-level: diff two raw binary buffers and produce a [`BinDiffReport`].
pub fn diff_binaries(binary_a: &[u8], binary_b: &[u8]) -> BinDiffReport {
    let ba = crate::core::binary_buffer::shared_from_vec(binary_a.to_vec());
    let bb = crate::core::binary_buffer::shared_from_vec(binary_b.to_vec());
    let Ok(a) = load_side(ba) else {
        return BinDiffReport::default();
    };
    let Ok(b) = load_side(bb) else {
        return BinDiffReport::default();
    };
    diff_sides(&a, &b)
}

/// Diff two already-loaded `AppData` snapshots — used by the GUI's
/// `BindiffOpenSecond` handler so we can reuse the analysed function set
/// (which is much richer than the symbol-only fallback in `load_side`).
pub fn diff_appdata_snapshots(
    binary_a: Arc<crate::core::binary_buffer::BinaryBuffer>,
    segments_a: Vec<Segment>,
    functions_a: Vec<Function>,
    binary_b: Arc<crate::core::binary_buffer::BinaryBuffer>,
    segments_b: Vec<Segment>,
    functions_b: Vec<Function>,
) -> BinDiffReport {
    let a = Side {
        binary: binary_a,
        segments: segments_a,
        functions: functions_a,
    };
    let b = Side {
        binary: binary_b,
        segments: segments_b,
        functions: functions_b,
    };
    diff_sides(&a, &b)
}

fn diff_sides(a: &Side, b: &Side) -> BinDiffReport {
    let bodies_a = extract_function_bodies(&a.binary, &a.segments, &a.functions);
    let bodies_b = extract_function_bodies(&b.binary, &b.segments, &b.functions);

    let mut matched_a: HashSet<usize> = HashSet::new();
    let mut matched_b: HashSet<usize> = HashSet::new();
    let mut report = BinDiffReport::default();

    // ── Phase 1: exact byte-hash match ────────────────────────────────────────
    let mut by_hash: std::collections::HashMap<u64, Vec<usize>> = std::collections::HashMap::new();
    for (i, fb) in bodies_b.iter().enumerate() {
        if fb.body.is_empty() {
            continue;
        }
        by_hash.entry(fb.byte_hash()).or_default().push(i);
    }
    for (i, fa) in bodies_a.iter().enumerate() {
        if fa.body.is_empty() {
            continue;
        }
        if let Some(candidates) = by_hash.get(&fa.byte_hash()) {
            for &j in candidates {
                if matched_b.contains(&j) {
                    continue;
                }
                if bodies_b[j].body == fa.body {
                    matched_a.insert(i);
                    matched_b.insert(j);
                    report.functions_identical.push((
                        fa.summary.clone(),
                        bodies_b[j].summary.clone(),
                    ));
                    break;
                }
            }
        }
    }

    // ── Phase 2: name match for anything not yet paired ───────────────────────
    let mut by_name: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (j, fb) in bodies_b.iter().enumerate() {
        if matched_b.contains(&j) {
            continue;
        }
        if fb.summary.name.starts_with("sub_") {
            continue;
        }
        by_name.entry(fb.summary.name.as_str()).or_default().push(j);
    }
    for (i, fa) in bodies_a.iter().enumerate() {
        if matched_a.contains(&i) || fa.summary.name.starts_with("sub_") {
            continue;
        }
        if let Some(candidates) = by_name.get(fa.summary.name.as_str()) {
            for &j in candidates {
                if matched_b.contains(&j) {
                    continue;
                }
                let sim = body_similarity(&fa.body, &bodies_b[j].body);
                matched_a.insert(i);
                matched_b.insert(j);
                if sim >= 0.999 {
                    report.functions_identical.push((
                        fa.summary.clone(),
                        bodies_b[j].summary.clone(),
                    ));
                } else {
                    report.functions_changed.push((
                        fa.summary.clone(),
                        bodies_b[j].summary.clone(),
                        sim,
                    ));
                }
                break;
            }
        }
    }

    // ── Phase 3: cheap CFG-hash proxy (length + first 64 bytes) ───────────────
    // The full WL-hash lives in `rustre-diff-bindiff` and is intentionally not
    // pulled in here. The proxy is good enough for stripped releases where
    // the only ground truth is "same-shape body of the same length".
    let body_sig = |fb: &FuncWithBody| -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in fb.body.iter().take(64) {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h ^= fb.body.len() as u64;
        h
    };
    let mut by_sig: std::collections::HashMap<u64, Vec<usize>> = std::collections::HashMap::new();
    for (j, fb) in bodies_b.iter().enumerate() {
        if matched_b.contains(&j) || fb.body.is_empty() {
            continue;
        }
        by_sig.entry(body_sig(fb)).or_default().push(j);
    }
    for (i, fa) in bodies_a.iter().enumerate() {
        if matched_a.contains(&i) || fa.body.is_empty() {
            continue;
        }
        if let Some(candidates) = by_sig.get(&body_sig(fa)) {
            for &j in candidates {
                if matched_b.contains(&j) {
                    continue;
                }
                let sim = body_similarity(&fa.body, &bodies_b[j].body);
                if sim >= 0.5 {
                    matched_a.insert(i);
                    matched_b.insert(j);
                    if sim >= 0.999 {
                        report.functions_identical.push((
                            fa.summary.clone(),
                            bodies_b[j].summary.clone(),
                        ));
                    } else {
                        report.functions_changed.push((
                            fa.summary.clone(),
                            bodies_b[j].summary.clone(),
                            sim,
                        ));
                    }
                    break;
                }
            }
        }
    }

    // ── Phase 4: leftovers ───────────────────────────────────────────────────
    for (i, fa) in bodies_a.iter().enumerate() {
        if !matched_a.contains(&i) {
            report.functions_removed.push(fa.summary.clone());
        }
    }
    for (j, fb) in bodies_b.iter().enumerate() {
        if !matched_b.contains(&j) {
            report.functions_added.push(fb.summary.clone());
        }
    }

    // Stable ordering for downstream renderers.
    report.functions_identical.sort_by_key(|(a, _)| a.addr);
    report.functions_changed.sort_by(|(a1, _, s1), (a2, _, s2)| {
        s1.partial_cmp(s2).unwrap_or(std::cmp::Ordering::Equal).then(a1.addr.cmp(&a2.addr))
    });
    report.functions_added.sort_by_key(|s| s.addr);
    report.functions_removed.sort_by_key(|s| s.addr);
    let _ = Addr(0); // touch Addr import
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_fwb(addr: u64, name: &str, body: &[u8]) -> FuncWithBody {
        FuncWithBody {
            summary: BinDiffFuncSummary {
                addr: Addr(addr),
                name: name.into(),
                size: body.len() as u64,
            },
            body: body.to_vec(),
        }
    }

    #[test]
    fn identical_bodies() {
        let a = fake_fwb(0x1000, "f", b"\x90\x90\xc3");
        let b = fake_fwb(0x2000, "f", b"\x90\x90\xc3");
        assert!((body_similarity(&a.body, &b.body) - 1.0).abs() < f32::EPSILON);
        assert_eq!(a.byte_hash(), b.byte_hash());
    }

    #[test]
    fn similarity_decays_with_diff() {
        let a = fake_fwb(0x1000, "f", b"\x90\x90\xc3");
        let b = fake_fwb(0x2000, "f", b"\x90\x55\xc3");
        let s = body_similarity(&a.body, &b.body);
        assert!(s < 1.0 && s > 0.0);
    }
}

// ── prod ensure-used ──────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_bindiff_backend() {
    let _ = diff_binaries(&[], &[]);
    let _ = body_similarity(b"abc", b"abd");
}
