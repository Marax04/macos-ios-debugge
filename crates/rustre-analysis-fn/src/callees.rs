//! Callee enumeration for a single function.
//!
//! Given a function's start address and a [`MemorySlice`], [`callees`] scans
//! the function body for CALL / BL instructions and classifies each target as:
//!
//! * [`CalleeKind::Internal`] — target is a known function in the same binary.
//! * [`CalleeKind::External`] — target falls outside the binary's code range.
//! * [`CalleeKind::Thunk`]   — target is a single-JMP trampoline (stub that
//!   immediately unconditionally jumps elsewhere; common for IAT wrappers and
//!   PLT stubs).

use serde::{Deserialize, Serialize};

use crate::{Address, DetectedArch, FunctionBoundary, MemorySlice};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a call edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalleeKind {
    /// Target is a known function within the same binary image.
    Internal,
    /// Target falls outside the binary's code range (IAT, PLT, external image).
    External,
    /// Target is a single-JMP trampoline / stub.
    Thunk,
}

/// A single callee discovered inside a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalleeRecord {
    /// Absolute address of the callee's entry point.
    pub target_addr: u64,
    /// How the callee was classified.
    pub kind: CalleeKind,
    /// Optional name (forwarded from the [`FunctionBoundary`] if present).
    pub name: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Thunk detection
// ─────────────────────────────────────────────────────────────────────────────

/// Return `true` if the bytes at `addr` look like a single-JMP trampoline.
///
/// Recognised patterns (x86-64 / x86-32):
/// * `E9 imm32`   — JMP rel32
/// * `EB imm8`    — JMP rel8
/// * `FF 25 ...`  — JMP [mem] (indirect, typical IAT thunk)
/// * `FF E0..E7`  — JMP rAX..rDI (register-indirect, rare but valid)
///
/// ARM64:
/// * `B imm26`    — unconditional branch (bits[31:26] == 0b000101)
///
/// We also skip up to 4 bytes of `NOP` / `INT3` / `endbr64` preamble before
/// the jump to handle compiler-emitted padding.
#[must_use]
fn is_thunk(addr: Address, mem: &MemorySlice<'_>, arch: DetectedArch) -> bool {
    // Maximum number of bytes to inspect for the thunk pattern.
    const MAX_THUNK_BYTES: u64 = 16;

    let mut cur = addr;
    let limit = Address::new(addr.as_u64().saturating_add(MAX_THUNK_BYTES));

    // Skip known preambles (endbr64, NOP, INT3).
    while cur.as_u64() < limit.as_u64() {
        match mem.read_u8(cur) {
            // NOP (0x90) or INT3 (0xCC)
            Some(0x90 | 0xCC) => {
                cur += 1;
            }
            // endbr64 / endbr32  (F3 0F 1E FA / FB)
            Some(0xF3) => {
                if let Some(slice) = mem.slice_at(cur, 4)
                    && matches!(slice, [0xF3, 0x0F, 0x1E, 0xFA | 0xFB])
                {
                    cur += 4;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }

    match arch {
        DetectedArch::X86_64 | DetectedArch::X86_32 | DetectedArch::Unknown => {
            match mem.read_u8(cur) {
                // JMP rel32 or JMP rel8
                Some(0xE9 | 0xEB) => true,
                // JMP [mem] or JMP r/m
                Some(0xFF) => matches!(
                    mem.read_u8(cur + 1),
                    // ModRM: reg field == 4 (JMP r/m) covers indirect and register variants
                    Some(b) if (b >> 3) & 0x7 == 4
                ),
                _ => false,
            }
        }
        DetectedArch::Arm64 => {
            // ARM64: B imm26 — bits [31:26] == 0b000101
            mem.read_u32_le(cur).is_some_and(|word| (word >> 26) == 0b00_0101)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Call-site scanning helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `body` for x86 `CALL rel32` (`E8 imm32`) instructions and return
/// absolute target addresses.
fn scan_x86_calls(body: &[u8], body_base: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let limit = body.len().saturating_sub(4);
    let mut i = 0usize;
    while i < limit {
        if body[i] == 0xE8 {
            let disp = i32::from_le_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]);
            let next_pc = body_base.wrapping_add(i as u64).wrapping_add(5);
            let next_pc_i64 = i64::from_ne_bytes(next_pc.to_ne_bytes());
            let target = u64::from_ne_bytes(next_pc_i64.wrapping_add(i64::from(disp)).to_ne_bytes());
            out.push(target);
            i += 5;
        } else {
            i += 1;
        }
    }
    out
}

/// Scan `body` for ARM64 `BL imm26` instructions and return absolute target
/// addresses.
fn scan_arm64_calls(body: &[u8], body_base: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let limit = body.len().saturating_sub(3);
    let mut i = 0usize;
    while i < limit {
        if !i.is_multiple_of(4) {
            i += 1;
            continue;
        }
        let word = u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        // BL: bits[31:26] == 0b100101
        if (word >> 26) == 0b10_0101 {
            let imm26 = word & 0x03FF_FFFF;
            let extended = u32::from_ne_bytes(
                i32::from_ne_bytes((imm26 << 6).to_ne_bytes())
                    .wrapping_shr(6)
                    .to_ne_bytes(),
            );
            let offset_instr = i32::from_ne_bytes(extended.to_ne_bytes());
            let byte_offset = i64::from(offset_instr) * 4;
            let pc = body_base.wrapping_add(i as u64);
            let pc_i64 = i64::from_ne_bytes(pc.to_ne_bytes());
            let target = u64::from_ne_bytes(pc_i64.wrapping_add(byte_offset).to_ne_bytes());
            out.push(target);
        }
        i += 4;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Return all callees reachable from the function starting at `addr`.
///
/// # Parameters
/// * `addr`    — entry-point address of the function to inspect.
/// * `mem`     — address-aware byte slice covering the binary image.
/// * `arch`    — architecture for call-instruction decoding.
/// * `known`   — function boundaries produced by a prior detection pass;
///   used to decide Internal vs External and to detect thunks.
///
/// # Classification
/// 1. If the target is known to be a single-JMP trampoline → [`CalleeKind::Thunk`].
/// 2. Otherwise, if the target is the start of any entry in `known` → [`CalleeKind::Internal`].
/// 3. Otherwise → [`CalleeKind::External`].
///
/// # JSON shape
/// ```json
/// [
///   { "target_addr": 4198912, "kind": "internal", "name": "some_fn" },
///   { "target_addr": 4294967040, "kind": "external", "name": null },
///   { "target_addr": 4199424, "kind": "thunk", "name": null }
/// ]
/// ```
#[must_use]
pub fn callees(
    addr: u64,
    mem: &MemorySlice<'_>,
    arch: DetectedArch,
    known: &[FunctionBoundary],
) -> Vec<CalleeRecord> {
    let index = KnownIndex::build(known);
    callees_with_index(addr, mem, arch, &index)
}

/// Precomputed index over a `known` boundary list, shared across many
/// [`callees_with_index`] calls to avoid rebuilding `O(known.len())`
/// lookup structures (sorted starts, a starts `HashSet`, and a name
/// `HashMap`) on every single-function query. Building this once and
/// reusing it turns an `O(functions × known)` batch scan (as done by
/// multi-hop callee tracing over a whole binary) into `O(known log known)`
/// build + `O(functions × calls_per_function)` lookups.
#[derive(Debug, Default)]
pub struct KnownIndex {
    /// Function start addresses, sorted ascending, for `body_end` lookups.
    sorted_starts: Vec<u64>,
    /// Stored `end` address per known function start (if any).
    ends: std::collections::HashMap<u64, u64>,
    /// Fast membership test for "is this a known function start".
    starts_set: std::collections::HashSet<u64>,
    /// Name lookup by function start.
    name_map: std::collections::HashMap<u64, Option<String>>,
}

impl KnownIndex {
    /// Build an index from a `known` boundary slice. `O(known.len() log
    /// known.len())`.
    #[must_use]
    pub fn build(known: &[FunctionBoundary]) -> Self {
        let mut sorted_starts: Vec<u64> = known.iter().map(|fb| fb.start.as_u64()).collect();
        sorted_starts.sort_unstable();
        sorted_starts.dedup();

        let ends = known
            .iter()
            .filter_map(|fb| fb.end.map(|e| (fb.start.as_u64(), e.as_u64())))
            .collect();
        let starts_set = known.iter().map(|fb| fb.start.as_u64()).collect();
        let name_map = known
            .iter()
            .map(|fb| (fb.start.as_u64(), fb.name.clone()))
            .collect();

        Self { sorted_starts, ends, starts_set, name_map }
    }

    /// Determine the exclusive end of the function body starting at `addr`,
    /// via the stored `end` if present, else the nearest known start after
    /// `addr` (binary search over the sorted starts), else `mem_end`.
    fn body_end(&self, addr: u64, mem_end: u64) -> u64 {
        if let Some(&e) = self.ends.get(&addr) {
            return e;
        }
        // First start strictly greater than `addr`.
        let idx = self.sorted_starts.partition_point(|&s| s <= addr);
        self.sorted_starts.get(idx).copied().unwrap_or(mem_end)
    }
}

/// Same as [`callees`] but takes a prebuilt [`KnownIndex`] instead of a raw
/// `known` slice, avoiding repeated index construction when scanning many
/// functions (e.g. multi-hop callee tracing). Prefer this over calling
/// [`callees`] in a loop.
#[must_use]
pub fn callees_with_index(
    addr: u64,
    mem: &MemorySlice<'_>,
    arch: DetectedArch,
    index: &KnownIndex,
) -> Vec<CalleeRecord> {
    let start = Address::new(addr);

    let body_end = index.body_end(addr, mem.end().as_u64());

    // Extract body bytes.
    let body_len = usize::try_from(body_end.saturating_sub(addr)).unwrap_or(usize::MAX);
    let Some(body_bytes) = mem.slice_at(start, body_len) else { return Vec::new(); };

    // Collect raw call targets from the body.
    let raw_targets: Vec<u64> = match arch {
        DetectedArch::Arm64 => scan_arm64_calls(body_bytes, addr),
        DetectedArch::X86_64 | DetectedArch::X86_32 | DetectedArch::Unknown => {
            scan_x86_calls(body_bytes, addr)
        }
    };

    let known_starts = &index.starts_set;
    let name_map = &index.name_map;

    // Classify and deduplicate.
    let mut seen = std::collections::HashSet::new();
    let mut records: Vec<CalleeRecord> = Vec::new();

    for target in raw_targets {
        if !seen.insert(target) {
            continue;
        }

        let target_addr_obj = Address::new(target);

        let kind = if is_thunk(target_addr_obj, mem, arch) {
            CalleeKind::Thunk
        } else if known_starts.contains(&target) {
            CalleeKind::Internal
        } else {
            CalleeKind::External
        };

        let name = name_map.get(&target).cloned().flatten();

        records.push(CalleeRecord { target_addr: target, kind, name });
    }

    records
}

/// Compute callees for every address in `addrs`, building the [`KnownIndex`]
/// exactly once. Equivalent to calling [`callees`] per address but avoids
/// the `O(known.len())` index rebuild on each call, turning what would be
/// `O(addrs.len() * known.len())` into `O(known.len() log known.len() +
/// addrs.len() * calls_per_function)`.
#[must_use]
pub fn callees_batch(
    addrs: &[u64],
    mem: &MemorySlice<'_>,
    arch: DetectedArch,
    known: &[FunctionBoundary],
) -> std::collections::HashMap<u64, Vec<CalleeRecord>> {
    let index = KnownIndex::build(known);
    addrs
        .iter()
        .map(|&addr| (addr, callees_with_index(addr, mem, arch, &index)))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, DetectionSource, FunctionBoundary};

    fn boundary(addr: u64) -> FunctionBoundary {
        FunctionBoundary::new(
            Address::new(addr),
            Confidence::High,
            DetectionSource::ProloguePattern,
        )
    }

    fn boundary_named(addr: u64, name: &str) -> FunctionBoundary {
        FunctionBoundary::new(
            Address::new(addr),
            Confidence::Certain,
            DetectionSource::SymbolTable,
        )
        .with_name(name)
    }

    // ── is_thunk ──────────────────────────────────────────────────────────────

    #[test]
    fn thunk_jmp_rel32() {
        // E9 xx xx xx xx
        let code: &[u8] = &[0xE9, 0x10, 0x00, 0x00, 0x00];
        let mem = MemorySlice::new(Address::new(0x1000), code);
        assert!(is_thunk(Address::new(0x1000), &mem, DetectedArch::X86_64));
    }

    #[test]
    fn thunk_jmp_rel8() {
        let code: &[u8] = &[0xEB, 0x05];
        let mem = MemorySlice::new(Address::new(0x2000), code);
        assert!(is_thunk(Address::new(0x2000), &mem, DetectedArch::X86_64));
    }

    #[test]
    fn thunk_jmp_indirect_ff25() {
        // FF 25 xx xx xx xx  — JMP [rip+disp32]
        let code: &[u8] = &[0xFF, 0x25, 0x00, 0x10, 0x00, 0x00];
        let mem = MemorySlice::new(Address::new(0x3000), code);
        assert!(is_thunk(Address::new(0x3000), &mem, DetectedArch::X86_64));
    }

    #[test]
    fn not_a_thunk_normal_prologue() {
        // push rbp; mov rbp, rsp — clearly not a thunk
        let code: &[u8] = &[0x55, 0x48, 0x89, 0xE5, 0x90];
        let mem = MemorySlice::new(Address::new(0x4000), code);
        assert!(!is_thunk(Address::new(0x4000), &mem, DetectedArch::X86_64));
    }

    #[test]
    fn thunk_with_nop_preamble() {
        // NOP NOP JMP rel32
        let code: &[u8] = &[0x90, 0x90, 0xE9, 0x00, 0x10, 0x00, 0x00];
        let mem = MemorySlice::new(Address::new(0x5000), code);
        assert!(is_thunk(Address::new(0x5000), &mem, DetectedArch::X86_64));
    }

    #[test]
    fn thunk_arm64_b_instruction() {
        // B #8 — unconditional branch, encoding: bits[31:26]==0b000101, imm26=2
        // word = (0b000101 << 26) | 2 = 0x1400_0002
        let word: u32 = 0x1400_0002;
        let code = word.to_le_bytes();
        let mem = MemorySlice::new(Address::new(0x6000), &code);
        assert!(is_thunk(Address::new(0x6000), &mem, DetectedArch::Arm64));
    }

    // ── callees ───────────────────────────────────────────────────────────────

    #[test]
    fn callees_internal_classification() {
        // Function at 0x1000 calls 0x1020 (which is a known internal function).
        // Layout: CALL rel32 at offset 0 → next_pc=0x1005, disp=0x1B → target=0x1020
        let disp: i32 = 0x1B;
        let db = disp.to_le_bytes();
        let mut code = vec![0x90u8; 64];
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        code[5] = 0xC3; // RET (to close first fn)
        // 0x1020 = offset 0x20: push rbp
        code[0x20] = 0x55;
        code[0x21] = 0x48;
        code[0x22] = 0x89;
        code[0x23] = 0xE5;
        code[0x28] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![
            boundary(0x1000).with_end(Address::new(0x1006)),
            boundary(0x1020),
        ];

        let result = callees(0x1000, &mem, DetectedArch::X86_64, &known);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_addr, 0x1020);
        assert_eq!(result[0].kind, CalleeKind::Internal);
    }

    #[test]
    fn callees_external_classification() {
        // Function calls into an address outside the memory slice (external).
        // CALL rel32 with large displacement pointing way outside [0x1000, 0x1040).
        let target: u64 = 0x0000_0000_7FFF_0000;
        let next_pc: i64 = 0x1005;
        let target_i64 = i64::from_ne_bytes(target.to_ne_bytes());
        let disp = (target_i64 - next_pc) as i32;
        let db = disp.to_le_bytes();

        let mut code = vec![0x90u8; 64];
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        code[5] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![boundary(0x1000)];

        let result = callees(0x1000, &mem, DetectedArch::X86_64, &known);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, CalleeKind::External);
    }

    #[test]
    fn callees_thunk_classification() {
        // Function at 0x1000 calls 0x1020. At 0x1020 there is a JMP rel32 (thunk).
        let disp_to_thunk: i32 = 0x1B;
        let db = disp_to_thunk.to_le_bytes();
        let mut code = vec![0x90u8; 64];
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        code[5] = 0xC3;
        // 0x1020 is a thunk: JMP rel32
        code[0x20] = 0xE9;
        code[0x21] = 0x00;
        code[0x22] = 0x10;
        code[0x23] = 0x00;
        code[0x24] = 0x00;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![
            FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::ProloguePattern)
                .with_end(Address::new(0x1006)),
            boundary(0x1020),
        ];

        let result = callees(0x1000, &mem, DetectedArch::X86_64, &known);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_addr, 0x1020);
        assert_eq!(result[0].kind, CalleeKind::Thunk);
    }

    #[test]
    fn callees_name_propagated() {
        // Known function named "bar" is called from "foo".
        let disp: i32 = 0x1B;
        let db = disp.to_le_bytes();
        let mut code = vec![0x90u8; 64];
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        code[5] = 0xC3;
        code[0x20] = 0x55;
        code[0x21] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![
            boundary_named(0x1000, "foo").with_end(Address::new(0x1006)),
            boundary_named(0x1020, "bar"),
        ];

        let result = callees(0x1000, &mem, DetectedArch::X86_64, &known);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_deref(), Some("bar"));
    }

    #[test]
    fn callees_deduplicates_repeated_calls() {
        // Two CALL instructions pointing to the same target.
        let disp: i32 = 0x0A; // next_pc=0x1005, target=0x100F
        let db = disp.to_le_bytes();
        let mut code = vec![0x90u8; 64];
        // First call at offset 0
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        // Second call at offset 5: next_pc=0x100A, disp=5 → target=0x100F
        let disp2: i32 = 0x05;
        let db2 = disp2.to_le_bytes();
        code[5] = 0xE8;
        code[6] = db2[0];
        code[7] = db2[1];
        code[8] = db2[2];
        code[9] = db2[3];
        code[10] = 0xC3;

        // target 0x100F = 0x1000 + 0xF
        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![boundary(0x1000), boundary(0x100F)];

        let result = callees(0x1000, &mem, DetectedArch::X86_64, &known);
        // Despite two calls to the same target, only one record expected.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_addr, 0x100F);
    }

    #[test]
    fn callees_batch_matches_per_call_results() {
        // Same layout as `callees_internal_classification`: fn at 0x1000
        // calls internal fn at 0x1020; also probe a second start address
        // (0x1020 itself, which just RETs, so no callees) to exercise the
        // shared-index batch path across multiple addresses.
        let disp: i32 = 0x1B;
        let db = disp.to_le_bytes();
        let mut code = vec![0x90u8; 64];
        code[0] = 0xE8;
        code[1] = db[0];
        code[2] = db[1];
        code[3] = db[2];
        code[4] = db[3];
        code[5] = 0xC3;
        code[0x20] = 0x55;
        code[0x21] = 0x48;
        code[0x22] = 0x89;
        code[0x23] = 0xE5;
        code[0x28] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let known = vec![
            boundary(0x1000).with_end(Address::new(0x1006)),
            boundary(0x1020),
        ];

        let addrs = [0x1000u64, 0x1020u64];
        let batch = callees_batch(&addrs, &mem, DetectedArch::X86_64, &known);

        for &addr in &addrs {
            let expected = callees(addr, &mem, DetectedArch::X86_64, &known);
            assert_eq!(batch.get(&addr).cloned().unwrap_or_default(), expected);
        }
        assert_eq!(batch[&0x1000].len(), 1);
        assert_eq!(batch[&0x1000][0].target_addr, 0x1020);
        assert!(batch[&0x1020].is_empty());
    }

    #[test]
    fn known_index_body_end_uses_next_start_when_no_stored_end() {
        // No stored `end` for 0x1000; nearest known start after it is 0x1020,
        // so the body should be bounded at 0x1020 (offset 0x20 bytes).
        let known = vec![boundary(0x1000), boundary(0x1020)];
        let index = KnownIndex::build(&known);
        assert_eq!(index.body_end(0x1000, 0x9999), 0x1020);
        // No known start after 0x1020 → falls back to `mem_end`.
        assert_eq!(index.body_end(0x1020, 0x9999), 0x9999);
    }

    #[test]
    fn callees_serde_roundtrip() {
        let rec = CalleeRecord {
            target_addr: 0xDEAD_BEEF,
            kind: CalleeKind::Internal,
            name: Some("foo".to_owned()),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: CalleeRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, back);
    }

    #[test]
    fn callee_kind_serde_names() {
        assert_eq!(
            serde_json::to_string(&CalleeKind::Internal).unwrap(),
            r#""internal""#
        );
        assert_eq!(
            serde_json::to_string(&CalleeKind::External).unwrap(),
            r#""external""#
        );
        assert_eq!(
            serde_json::to_string(&CalleeKind::Thunk).unwrap(),
            r#""thunk""#
        );
    }
}
