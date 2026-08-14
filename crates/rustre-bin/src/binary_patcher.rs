//! Binary patcher — apply, revert and diff patches against raw binary data.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Core types
// ─────────────────────────────────────────────────────────────────────────────

/// A single patch entry describing one contiguous byte replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    pub offset: u64,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub comment: String,
    pub applied: bool,
}

impl PatchEntry {
    pub fn new(offset: u64, original: Vec<u8>, patched: Vec<u8>) -> Self {
        assert_eq!(
            original.len(),
            patched.len(),
            "patch original and patched must have the same length"
        );
        Self {
            offset,
            original,
            patched,
            comment: String::new(),
            applied: false,
        }
    }

    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = c.into();
        self
    }

    pub fn byte_count(&self) -> usize {
        self.patched.len()
    }
}

impl fmt::Display for PatchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "@{:#010x} [{} bytes] {}",
            self.offset,
            self.patched.len(),
            self.comment
        )
    }
}

/// A named, versioned collection of patches.
#[derive(Debug, Clone)]
pub struct PatchSet {
    pub name: String,
    pub description: String,
    pub patches: Vec<PatchEntry>,
    pub version: String,
}

impl PatchSet {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            patches: Vec::new(),
            version: "1.0".into(),
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = v.into();
        self
    }

    pub fn add(mut self, entry: PatchEntry) -> Self {
        self.patches.push(entry);
        self
    }

    pub fn total_bytes_changed(&self) -> u64 {
        self.patches.iter().map(|p| p.patched.len() as u64).sum()
    }

    pub fn stats(&self, data_len: usize) -> PatchStats {
        let total_bytes_changed: u64 = self.total_bytes_changed();
        let patch_count = self.patches.len() as u32;
        let coverage_percent = if data_len == 0 {
            0.0
        } else {
            (total_bytes_changed as f64 / data_len as f64) * 100.0
        };
        PatchStats {
            total_bytes_changed,
            patch_count,
            coverage_percent,
        }
    }
}

/// Summary statistics for a PatchSet applied against a buffer.
#[derive(Debug, Clone)]
pub struct PatchStats {
    pub total_bytes_changed: u64,
    pub patch_count: u32,
    pub coverage_percent: f64,
}

/// Result of applying an entire PatchSet.
#[derive(Debug, Clone, Default)]
pub struct PatchSetResult {
    pub applied_count: u32,
    pub failed_count: u32,
    pub errors: Vec<String>,
}

impl PatchSetResult {
    pub fn success(&self) -> bool {
        self.failed_count == 0
    }
}

/// Outcome of validating a single patch against a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Patch can be applied — original bytes match.
    Applicable,
    /// Patch is already applied — patched bytes are already in place.
    AlreadyApplied,
    /// Neither original nor patched bytes match — mismatch.
    Mismatch { found: Vec<u8> },
    /// Patch extends beyond end of buffer.
    OutOfBounds,
}

// ─────────────────────────────────────────────────────────────────────────────
// Core functions
// ─────────────────────────────────────────────────────────────────────────────

/// Check that `patch.original` bytes match at `patch.offset` in `data`,
/// then write `patch.patched` bytes. Returns `true` on success.
pub fn apply_patch(data: &mut Vec<u8>, patch: &PatchEntry) -> bool {
    let start = match usize::try_from(patch.offset) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let end = match start.checked_add(patch.original.len()) {
        Some(e) => e,
        None => return false,
    };
    if end > data.len() {
        return false;
    }
    if &data[start..end] != patch.original.as_slice() {
        return false;
    }
    data[start..end].copy_from_slice(&patch.patched);
    true
}

/// Revert: check that `patch.patched` bytes are currently in place, then
/// write back `patch.original`. Returns `true` on success.
pub fn revert_patch(data: &mut Vec<u8>, patch: &PatchEntry) -> bool {
    let start = match usize::try_from(patch.offset) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let end = match start.checked_add(patch.patched.len()) {
        Some(e) => e,
        None => return false,
    };
    if end > data.len() {
        return false;
    }
    if &data[start..end] != patch.patched.as_slice() {
        return false;
    }
    data[start..end].copy_from_slice(&patch.original);
    true
}

/// Validate a patch against data without modifying it.
pub fn validate_patch(data: &[u8], patch: &PatchEntry) -> ValidationResult {
    let start = match usize::try_from(patch.offset) {
        Ok(s) => s,
        Err(_) => return ValidationResult::OutOfBounds,
    };
    let end = match start.checked_add(patch.original.len()) {
        Some(e) => e,
        None => return ValidationResult::OutOfBounds,
    };
    if end > data.len() {
        return ValidationResult::OutOfBounds;
    }
    let slice = &data[start..end];
    if slice == patch.original.as_slice() {
        ValidationResult::Applicable
    } else if slice == patch.patched.as_slice() {
        ValidationResult::AlreadyApplied
    } else {
        ValidationResult::Mismatch {
            found: slice.to_vec(),
        }
    }
}

/// Apply all patches in a PatchSet sequentially.
pub fn apply_patchset(data: &mut Vec<u8>, set: &PatchSet) -> PatchSetResult {
    let mut result = PatchSetResult::default();
    for patch in &set.patches {
        if apply_patch(data, patch) {
            result.applied_count += 1;
        } else {
            result.failed_count += 1;
            result.errors.push(format!(
                "failed to apply patch at offset {:#x}: {}",
                patch.offset, patch.comment
            ));
        }
    }
    result
}

/// Diff two equal-length byte slices and produce a PatchSet grouping
/// contiguous changed regions into individual PatchEntry records.
pub fn diff_to_patchset(original: &[u8], patched: &[u8]) -> PatchSet {
    assert_eq!(
        original.len(),
        patched.len(),
        "diff_to_patchset: slices must be the same length"
    );
    let mut set = PatchSet::new("diff", "generated by diff_to_patchset");
    let mut i = 0usize;
    while i < original.len() {
        if original[i] == patched[i] {
            i += 1;
            continue;
        }
        // start of a differing run
        let run_start = i;
        while i < original.len() && original[i] != patched[i] {
            i += 1;
        }
        let entry = PatchEntry::new(
            run_start as u64,
            original[run_start..i].to_vec(),
            patched[run_start..i].to_vec(),
        )
        .with_comment(format!("diff@{run_start:#x}"));
        set.patches.push(entry);
    }
    set
}

// ─────────────────────────────────────────────────────────────────────────────
// Fluent builder
// ─────────────────────────────────────────────────────────────────────────────

/// Intermediate builder state when `at()` has been called.
pub struct PatchAtBuilder {
    offset: u64,
}

/// Intermediate builder state when `at().replace()` has been called.
pub struct PatchReplaceBuilder {
    offset: u64,
    original: Vec<u8>,
    patched: Vec<u8>,
}

impl PatchReplaceBuilder {
    pub fn comment(self, c: impl Into<String>) -> PatchEntry {
        PatchEntry::new(self.offset, self.original, self.patched).with_comment(c)
    }

    pub fn build(self) -> PatchEntry {
        PatchEntry::new(self.offset, self.original, self.patched)
    }
}

/// Fluent patch builder.
pub struct PatchBuilder;

impl PatchBuilder {
    pub fn at(offset: u64) -> PatchAtBuilder {
        PatchAtBuilder { offset }
    }
}

impl PatchAtBuilder {
    pub fn replace(self, old: Vec<u8>, new: Vec<u8>) -> PatchReplaceBuilder {
        assert_eq!(old.len(), new.len(), "replace: slices must be same length");
        PatchReplaceBuilder {
            offset: self.offset,
            original: old,
            patched: new,
        }
    }

    pub fn nop_out(self, count: usize) -> PatchEntry {
        // x86 NOP is 0x90; for generic use we fill with 0x90.
        let original = vec![0u8; count];
        let patched = vec![0x90u8; count];
        PatchEntry::new(self.offset, original, patched).with_comment("NOP out")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialisation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Serialise a PatchSet to a minimal JSON string (no external crate).
pub fn serialize_patchset_json(set: &PatchSet) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"name\": \"{}\",\n", json_escape(&set.name)));
    out.push_str(&format!(
        "  \"description\": \"{}\",\n",
        json_escape(&set.description)
    ));
    out.push_str(&format!("  \"version\": \"{}\",\n", json_escape(&set.version)));
    out.push_str("  \"patches\": [\n");
    for (i, p) in set.patches.iter().enumerate() {
        let orig_hex = bytes_to_hex(&p.original);
        let patched_hex = bytes_to_hex(&p.patched);
        out.push_str("    {\n");
        out.push_str(&format!("      \"offset\": {},\n", p.offset));
        out.push_str(&format!("      \"original\": \"{orig_hex}\",\n"));
        out.push_str(&format!("      \"patched\": \"{patched_hex}\",\n"));
        out.push_str(&format!(
            "      \"comment\": \"{}\",\n",
            json_escape(&p.comment)
        ));
        out.push_str(&format!("      \"applied\": {}\n", p.applied));
        if i + 1 < set.patches.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
    }
    out.push_str("  ]\n}");
    out
}

/// Deserialise a PatchSet from the minimal JSON format produced by
/// `serialize_patchset_json`. Returns `Err` with a description on failure.
pub fn deserialize_patchset_json(json: &str) -> Result<PatchSet, String> {
    // Minimal hand-rolled parser sufficient for our own format.
    let name = extract_json_str(json, "name").unwrap_or_default();
    let description = extract_json_str(json, "description").unwrap_or_default();
    let version = extract_json_str(json, "version").unwrap_or_default();

    let mut set = PatchSet::new(name, description).with_version(version);

    // Find the patches array by scanning for offset/original/patched blocks.
    let mut pos = 0usize;
    while let Some(off_start) = find_field(json, "\"offset\":", pos) {
        let offset = parse_u64_at(json, off_start + 9).ok_or("bad offset")?;
        let orig_hex =
            extract_json_str_from(json, "\"original\":", off_start).ok_or("missing original")?;
        let patched_hex =
            extract_json_str_from(json, "\"patched\":", off_start).ok_or("missing patched")?;
        let comment = extract_json_str_from(json, "\"comment\":", off_start).unwrap_or_default();

        let original = hex_to_bytes(&orig_hex).map_err(|e| format!("bad original hex: {e}"))?;
        let patched_bytes =
            hex_to_bytes(&patched_hex).map_err(|e| format!("bad patched hex: {e}"))?;
        let entry = PatchEntry::new(offset, original, patched_bytes).with_comment(comment);
        set.patches.push(entry);

        // Advance past this object to find the next one.
        pos = off_start + 9;
    }
    Ok(set)
}

/// Produce a simplified IDA-compatible patch-info text that resembles the
/// `.idb` patch section output (hex lines: `offset: original -> patched`).
pub fn serialize_patchset_idb(set: &PatchSet) -> String {
    let mut out = format!("; PatchSet: {} v{}\n", set.name, set.version);
    out.push_str(&format!("; {}\n", set.description));
    for p in &set.patches {
        for (i, (&orig, &patch)) in p.original.iter().zip(p.patched.iter()).enumerate() {
            let addr = p.offset + i as u64;
            out.push_str(&format!("{addr:#010x}: {orig:02X} -> {patch:02X}\n"));
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryPatcher facade
// ─────────────────────────────────────────────────────────────────────────────

/// High-level binary patcher that owns a data buffer and an ordered set of
/// named PatchSets.
pub struct BinaryPatcher {
    data: Vec<u8>,
    sets: HashMap<String, PatchSet>,
}

impl BinaryPatcher {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            sets: HashMap::new(),
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn register_set(&mut self, set: PatchSet) {
        self.sets.insert(set.name.clone(), set);
    }

    pub fn apply_set(&mut self, name: &str) -> Option<PatchSetResult> {
        let set = self.sets.get(name)?.clone();
        Some(apply_patchset(&mut self.data, &set))
    }

    pub fn revert_set(&mut self, name: &str) -> Option<u32> {
        let set = self.sets.get(name)?.clone();
        let mut count = 0u32;
        for patch in &set.patches {
            if revert_patch(&mut self.data, patch) {
                count += 1;
            }
        }
        Some(count)
    }

    pub fn validate_set(&self, name: &str) -> Option<Vec<(usize, ValidationResult)>> {
        let set = self.sets.get(name)?;
        let results = set
            .patches
            .iter()
            .enumerate()
            .map(|(i, p)| (i, validate_patch(&self.data, p)))
            .collect();
        Some(results)
    }

    pub fn export_json(&self, name: &str) -> Option<String> {
        self.sets.get(name).map(serialize_patchset_json)
    }

    pub fn diff_from(&self, original: &[u8]) -> PatchSet {
        diff_to_patchset(original, &self.data)
    }

    pub fn stats(&self, name: &str) -> Option<PatchStats> {
        self.sets.get(name).map(|s| s.stats(self.data.len()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() {
        return Err("hex string contains non-ASCII characters".into());
    }
    if s.len() % 2 != 0 {
        return Err("odd length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\": \"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].replace("\\\"", "\"").replace("\\n", "\n"))
}

fn extract_json_str_from(json: &str, key: &str, from: usize) -> Option<String> {
    let slice = &json[from..];
    let pat = key;
    let kstart = slice.find(pat)? + pat.len();
    // skip whitespace then opening quote
    let after_key = slice[kstart..].trim_start();
    if !after_key.starts_with('"') {
        return None;
    }
    let content = &after_key[1..];
    let end = content.find('"')?;
    Some(content[..end].replace("\\\"", "\"").replace("\\n", "\n"))
}

fn find_field(json: &str, field: &str, from: usize) -> Option<usize> {
    json[from..].find(field).map(|p| p + from)
}

fn parse_u64_at(json: &str, from: usize) -> Option<u64> {
    let s = json[from..].trim_start();
    let end = s
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(s.len());
    s[..end].parse().ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _sample_data() -> Vec<u8> {
        (0u8..=255).collect()
    }

    #[test]
    fn test_apply_patch_basic() {
        let mut data = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let p = PatchEntry::new(1, vec![0x01, 0x02], vec![0xAA, 0xBB]);
        assert!(apply_patch(&mut data, &p));
        assert_eq!(data, vec![0x00, 0xAA, 0xBB, 0x03, 0x04]);
    }

    #[test]
    fn test_apply_patch_wrong_original() {
        let mut data = vec![0x00, 0xFF, 0x02];
        let p = PatchEntry::new(1, vec![0x01], vec![0xAA]);
        assert!(!apply_patch(&mut data, &p));
        assert_eq!(data[1], 0xFF); // unchanged
    }

    #[test]
    fn test_apply_patch_out_of_bounds() {
        let mut data = vec![0x00, 0x01];
        let p = PatchEntry::new(1, vec![0x01, 0x02], vec![0xAA, 0xBB]);
        assert!(!apply_patch(&mut data, &p));
    }

    #[test]
    fn test_revert_patch() {
        let mut data = vec![0x00, 0xAA, 0xBB, 0x03];
        let p = PatchEntry::new(1, vec![0x01, 0x02], vec![0xAA, 0xBB]);
        assert!(revert_patch(&mut data, &p));
        assert_eq!(data, vec![0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_revert_patch_not_applied() {
        let mut data = vec![0x00, 0x01, 0x02, 0x03];
        let p = PatchEntry::new(1, vec![0x01, 0x02], vec![0xAA, 0xBB]);
        assert!(!revert_patch(&mut data, &p));
    }

    #[test]
    fn test_validate_applicable() {
        let data = vec![0x00, 0x01, 0x02];
        let p = PatchEntry::new(1, vec![0x01], vec![0xFF]);
        assert_eq!(validate_patch(&data, &p), ValidationResult::Applicable);
    }

    #[test]
    fn test_validate_already_applied() {
        let data = vec![0x00, 0xFF, 0x02];
        let p = PatchEntry::new(1, vec![0x01], vec![0xFF]);
        assert_eq!(validate_patch(&data, &p), ValidationResult::AlreadyApplied);
    }

    #[test]
    fn test_validate_mismatch() {
        let data = vec![0x00, 0xAB, 0x02];
        let p = PatchEntry::new(1, vec![0x01], vec![0xFF]);
        assert!(matches!(
            validate_patch(&data, &p),
            ValidationResult::Mismatch { .. }
        ));
    }

    #[test]
    fn test_validate_out_of_bounds() {
        let data = vec![0x00, 0x01];
        let p = PatchEntry::new(1, vec![0x01, 0x02], vec![0xFF, 0xFF]);
        assert_eq!(validate_patch(&data, &p), ValidationResult::OutOfBounds);
    }

    #[test]
    fn test_apply_patchset() {
        let mut data = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let set = PatchSet::new("test", "test set")
            .add(PatchEntry::new(0, vec![0x00], vec![0xAA]))
            .add(PatchEntry::new(4, vec![0x04], vec![0xBB]));
        let result = apply_patchset(&mut data, &set);
        assert_eq!(result.applied_count, 2);
        assert_eq!(result.failed_count, 0);
        assert_eq!(data[0], 0xAA);
        assert_eq!(data[4], 0xBB);
    }

    #[test]
    fn test_patchset_stats() {
        let set = PatchSet::new("s", "d")
            .add(PatchEntry::new(0, vec![0x00; 10], vec![0xFF; 10]));
        let stats = set.stats(100);
        assert_eq!(stats.total_bytes_changed, 10);
        assert_eq!(stats.patch_count, 1);
        assert!((stats.coverage_percent - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_patch_builder_fluent() {
        let entry = PatchBuilder::at(0x10)
            .replace(vec![0x01, 0x02], vec![0xAA, 0xBB])
            .comment("test patch");
        assert_eq!(entry.offset, 0x10);
        assert_eq!(entry.original, vec![0x01, 0x02]);
        assert_eq!(entry.patched, vec![0xAA, 0xBB]);
        assert_eq!(entry.comment, "test patch");
    }

    #[test]
    fn test_diff_to_patchset_single_run() {
        let orig = vec![0x00, 0x01, 0x02, 0x03];
        let new = vec![0x00, 0xFF, 0xFE, 0x03];
        let set = diff_to_patchset(&orig, &new);
        assert_eq!(set.patches.len(), 1);
        assert_eq!(set.patches[0].offset, 1);
        assert_eq!(set.patches[0].original, vec![0x01, 0x02]);
        assert_eq!(set.patches[0].patched, vec![0xFF, 0xFE]);
    }

    #[test]
    fn test_diff_to_patchset_multiple_runs() {
        let orig = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let new  = vec![0xAA, 0x02, 0xBB, 0x04, 0xCC];
        let set = diff_to_patchset(&orig, &new);
        assert_eq!(set.patches.len(), 3);
    }

    #[test]
    fn test_diff_to_patchset_no_change() {
        let orig = vec![0x01, 0x02];
        let set = diff_to_patchset(&orig, &orig.clone());
        assert_eq!(set.patches.len(), 0);
    }

    #[test]
    fn test_serialize_json_round_trip() {
        let set = PatchSet::new("mypatch", "testing json")
            .with_version("2.0")
            .add(PatchEntry::new(0x100, vec![0xDE, 0xAD], vec![0xBE, 0xEF]).with_comment("sig"));
        let json = serialize_patchset_json(&set);
        assert!(json.contains("mypatch"));
        assert!(json.contains("dead"));
        assert!(json.contains("beef"));
    }

    #[test]
    fn test_serialize_idb() {
        let set = PatchSet::new("p", "d")
            .add(PatchEntry::new(0x1000, vec![0x90], vec![0xC3]).with_comment("ret"));
        let idb = serialize_patchset_idb(&set);
        assert!(idb.contains("0x00001000"));
        assert!(idb.contains("90 -> C3"));
    }

    #[test]
    fn test_binary_patcher_facade() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let mut patcher = BinaryPatcher::new(data);
        let set = PatchSet::new("fix", "desc")
            .add(PatchEntry::new(0, vec![0x00], vec![0xFF]));
        patcher.register_set(set);
        let result = patcher.apply_set("fix").unwrap();
        assert_eq!(result.applied_count, 1);
        assert_eq!(patcher.data()[0], 0xFF);
    }

    #[test]
    fn test_hex_round_trip() {
        let orig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = bytes_to_hex(&orig);
        let back = hex_to_bytes(&hex).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn test_patch_entry_display() {
        let p = PatchEntry::new(0x400, vec![0x01], vec![0x02]).with_comment("nop");
        let s = format!("{p}");
        assert!(s.contains("0x00000400"));
    }
}
