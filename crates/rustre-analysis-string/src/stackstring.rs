//! Stack-string reconstruction and string xref linkage.
//!
//! Obfuscated and statically-linked binaries frequently build strings *on the
//! stack* one chunk at a time:
//!
//! ```text
//!   mov dword [rbp-0x20], 0x6c6c6568   ; "hell"
//!   mov dword [rbp-0x1c], 0x6f77206f   ; "o wo"
//!   mov word  [rbp-0x18], 0x6c72       ; "rl"
//!   mov byte  [rbp-0x16], 0x64         ; "d"
//! ```
//!
//! These never appear as a contiguous literal in any data section, so the
//! ordinary scanner misses them.  This module reconstructs them from a stream
//! of *constant stores to adjacent stack offsets*.
//!
//! It also provides [`link_string_xrefs`] which folds a set of code references
//! into the `xref_count` field of recovered [`FoundString`]s.

use crate::{FoundString, StringEncoding};
use rustre_core::address::Address;
use rustre_core::endian::Endian;
use rustre_il_llil::{LlilExpr, LlilInstruction};
use std::collections::BTreeMap;

/// A single constant store to a stack slot, as observed in the instruction
/// stream.  `offset` is the (signed) frame offset, e.g. `-0x20` for
/// `[rbp-0x20]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackStore {
    /// Address of the storing instruction (used for xref linkage).
    pub instr_addr: Address,
    /// Signed frame offset of the destination slot.
    pub offset: i64,
    /// Number of bytes written (1, 2, 4, or 8).
    pub size: u8,
    /// The constant value being written.
    pub value: u64,
}

impl StackStore {
    /// Construct a stack store.
    #[must_use]
    pub const fn new(instr_addr: Address, offset: i64, size: u8, value: u64) -> Self {
        Self {
            instr_addr,
            offset,
            size,
            value,
        }
    }

    /// The little-endian bytes this store writes.
    #[must_use]
    pub fn bytes(self, endian: Endian) -> Vec<u8> {
        let n = self.size as usize;
        let le = self.value.to_le_bytes();
        match endian {
            Endian::Little => le[..n].to_vec(),
            Endian::Big => {
                let mut v: Vec<u8> = le[..n].to_vec();
                v.reverse();
                v
            }
        }
    }
}

/// A reconstructed stack string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackString {
    /// Frame offset of the first byte.
    pub start_offset: i64,
    /// Raw reconstructed bytes.
    pub bytes: Vec<u8>,
    /// Decoded value (lossy for non-UTF-8).
    pub value: String,
    /// Detected encoding.
    pub encoding: StringEncoding,
    /// Addresses of the storing instructions that contributed.
    pub contributing_instrs: Vec<Address>,
}

impl StackString {
    /// Number of bytes in the reconstructed buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the reconstructed buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Configuration for stack-string reconstruction.
#[derive(Debug, Clone)]
pub struct StackStringConfig {
    /// Minimum number of printable characters to accept a reconstruction.
    pub min_length: usize,
    /// Endianness of the target.
    pub endian: Endian,
    /// Whether a NUL byte ends the current run.
    pub stop_on_nul: bool,
}

impl Default for StackStringConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            endian: Endian::Little,
            stop_on_nul: true,
        }
    }
}

/// Reconstruct stack strings from a list of constant stack stores.
///
/// Stores are bucketed by *contiguity*: a chain extends while each store's
/// offset equals the previous store's offset plus its size.  Stores need not be
/// supplied in offset order; they are sorted first (preserving instruction
/// addresses for xref linkage).
#[must_use]
pub fn reconstruct_stack_strings(
    stores: &[StackStore],
    config: &StackStringConfig,
) -> Vec<StackString> {
    if stores.is_empty() {
        return Vec::new();
    }
    // Map offset -> store (last writer wins on duplicate offset).
    let mut by_offset: BTreeMap<i64, StackStore> = BTreeMap::new();
    for s in stores {
        by_offset.insert(s.offset, *s);
    }

    let mut out = Vec::new();
    let offsets: Vec<i64> = by_offset.keys().copied().collect();

    let mut i = 0usize;
    while i < offsets.len() {
        let start = offsets[i];
        let mut buf: Vec<u8> = Vec::new();
        let mut instrs: Vec<Address> = Vec::new();
        let mut expected = start;
        let mut j = i;
        while j < offsets.len() {
            let off = offsets[j];
            if off != expected {
                break;
            }
            let store = by_offset[&off];
            buf.extend_from_slice(&store.bytes(config.endian));
            instrs.push(store.instr_addr);
            expected = off + i64::from(store.size);
            j += 1;
        }

        // Optionally trim at the first NUL.
        if config.stop_on_nul
            && let Some(pos) = buf.iter().position(|&b| b == 0)
        {
            buf.truncate(pos);
        }

        let printable = buf.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
        if printable >= config.min_length && printable == buf.len() {
            let value = String::from_utf8_lossy(&buf).into_owned();
            out.push(StackString {
                start_offset: start,
                bytes: buf,
                value,
                encoding: StringEncoding::Ascii,
                contributing_instrs: instrs,
            });
        }

        i = j.max(i + 1);
    }
    out
}

/// A code reference to a string (from disassembly): a `(from, to)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringRef {
    /// Instruction address that references the string.
    pub from: Address,
    /// Address of the referenced string.
    pub to: Address,
}

/// Fold a set of string references into the `xref_count` of each matching
/// [`FoundString`], returning the number of references that matched a string.
///
/// References whose target does not match a known string start are ignored.
pub fn link_string_xrefs(strings: &mut [FoundString], refs: &[StringRef]) -> usize {
    // Index strings by start address.
    let mut index: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, s) in strings.iter().enumerate() {
        index.insert(s.address.as_u64(), i);
    }
    // Reset counts before linking so the operation is idempotent.
    for s in strings.iter_mut() {
        s.xref_count = 0;
    }
    let mut matched = 0usize;
    for r in refs {
        if let Some(&idx) = index.get(&r.to.as_u64()) {
            strings[idx].xref_count += 1;
            matched += 1;
        }
    }
    matched
}

/// Return references to strings that have at least `min` incoming xrefs,
/// sorted by descending xref count.
#[must_use]
pub fn most_referenced(strings: &[FoundString], min: usize) -> Vec<&FoundString> {
    let mut v: Vec<&FoundString> = strings.iter().filter(|s| s.xref_count >= min).collect();
    v.sort_by(|a, b| b.xref_count.cmp(&a.xref_count));
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// LLIL-based stack string reconstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Extract [`StackStore`]s from a stream of [`LlilInstruction`]s.
///
/// Recognises the pattern:
/// ```text
/// Store { addr: Sub(Register(sp/rbp/…), Const(offset)), size, src: Const(value) }
/// ```
/// The `instr_addr` of every produced [`StackStore`] is set to `Address::new(0)`
/// because [`LlilInstruction`] does not carry its own address; callers that need
/// accurate xref linkage should use [`reconstruct_stack_strings`] directly with
/// pre-built [`StackStore`]s.
///
/// Frame-pointer relative addressing is heuristically detected: the base
/// register name must be one of `rsp`, `rbp`, `esp`, `ebp`, or `sp`.
fn extract_stack_stores_from_llil(instructions: &[LlilInstruction]) -> Vec<StackStore> {
    const FRAME_REGS: &[&str] = &["rsp", "rbp", "esp", "ebp", "sp", "fp"];

    let mut stores = Vec::new();

    for instr in instructions {
        // We are interested in: Store { addr: Sub(Register(frame_reg), Const(offset)), size, src: Const(value) }
        if let LlilInstruction::Store {
            addr,
            size,
            value: src,
        } = instr
        {
            // Addr must be Sub(Register(frame_reg), Const(offset)) or Add(Register, Const(offset))
            let frame_offset: Option<i64> = match addr {
                LlilExpr::Sub {
                    left: base,
                    right: offset_expr,
                    ..
                } => {
                    if let (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value: off, .. }) =
                        (base.as_ref(), offset_expr.as_ref())
                    {
                        let name = reg.name().to_ascii_lowercase();
                        if FRAME_REGS
                            .iter()
                            .any(|&fr| name == fr || name.starts_with(fr))
                        {
                            Some(-(*off).cast_signed())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                LlilExpr::Add {
                    left: base,
                    right: offset_expr,
                    ..
                } => {
                    if let (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value: off, .. }) =
                        (base.as_ref(), offset_expr.as_ref())
                    {
                        let name = reg.name().to_ascii_lowercase();
                        if FRAME_REGS
                            .iter()
                            .any(|&fr| name == fr || name.starts_with(fr))
                        {
                            Some((*off).cast_signed())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(offset) = frame_offset {
                // Source must be a constant.
                if let LlilExpr::Const { value, .. } = src {
                    stores.push(StackStore {
                        instr_addr: Address::new(0),
                        offset,
                        size: u8::try_from(size.bytes()).unwrap_or(8),
                        value: *value,
                    });
                }
            }
        }
    }

    stores
}

/// Reconstruct stack strings from a stream of [`LlilInstruction`]s.
///
/// This is a convenience wrapper over [`reconstruct_stack_strings`] that
/// first extracts [`StackStore`]s from Store instructions with frame-relative
/// constant addresses and constant values.
///
/// See [`extract_stack_stores_from_llil`] for detection details.
#[must_use]
pub fn reconstruct_stack_strings_from_llil(
    instructions: &[LlilInstruction],
    config: &StackStringConfig,
) -> Vec<StackString> {
    let stores = extract_stack_stores_from_llil(instructions);
    reconstruct_stack_strings(&stores, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(addr: u64, off: i64, size: u8, val: u64) -> StackStore {
        StackStore::new(Address::new(addr), off, size, val)
    }

    #[test]
    fn store_bytes_little_endian() {
        let s = store(0, -0x10, 4, 0x6c6c_6568); // "hell"
        assert_eq!(s.bytes(Endian::Little), b"hell");
    }

    #[test]
    fn reconstruct_hello_world() {
        // Build "hello world" across stores at adjacent offsets.
        let stores = vec![
            store(0x10, -0x20, 4, 0x6c6c_6568), // "hell"
            store(0x18, -0x1c, 4, 0x6f77_206f), // "o wo"
            store(0x20, -0x18, 2, 0x6c72),      // "rl"
            store(0x28, -0x16, 1, 0x64),        // "d"
        ];
        let cfg = StackStringConfig::default();
        let strings = reconstruct_stack_strings(&stores, &cfg);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
        assert_eq!(strings[0].contributing_instrs.len(), 4);
        assert_eq!(strings[0].start_offset, -0x20);
    }

    #[test]
    fn reconstruct_stops_at_nul() {
        // "abcd\0gh" — should stop at NUL, dropping the trailing chunk.
        let stores = vec![
            store(0x10, -0x10, 4, 0x6463_6261), // "abcd"
            store(0x14, -0x0c, 4, 0x0068_6700), // \0 g h \0  (LE: 00 67 68 00)
        ];
        let cfg = StackStringConfig {
            min_length: 3,
            ..Default::default()
        };
        let strings = reconstruct_stack_strings(&stores, &cfg);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "abcd");
    }

    #[test]
    fn reconstruct_rejects_too_short() {
        let stores = vec![store(0x10, -0x10, 2, 0x6261)]; // "ab"
        let cfg = StackStringConfig::default(); // min 4
        assert!(reconstruct_stack_strings(&stores, &cfg).is_empty());
    }

    #[test]
    fn reconstruct_two_separate_runs() {
        // Two non-contiguous runs -> two strings.
        let stores = vec![
            store(0x10, -0x20, 4, 0x6463_6261), // "abcd" at -0x20..-0x1c
            store(0x20, -0x10, 4, 0x6867_6665), // "efgh" at -0x10..-0x0c
        ];
        let cfg = StackStringConfig::default();
        let strings = reconstruct_stack_strings(&stores, &cfg);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "abcd");
        assert_eq!(strings[1].value, "efgh");
    }

    #[test]
    fn reconstruct_unordered_stores() {
        // Same as hello but supplied out of order.
        let stores = vec![
            store(0x28, -0x16, 1, 0x64),
            store(0x10, -0x20, 4, 0x6c6c_6568),
            store(0x20, -0x18, 2, 0x6c72),
            store(0x18, -0x1c, 4, 0x6f77_206f),
        ];
        let strings = reconstruct_stack_strings(&stores, &StackStringConfig::default());
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
    }

    fn found(addr: u64, value: &str) -> FoundString {
        FoundString {
            address: Address::new(addr),
            length: value.len(),
            encoding: StringEncoding::Ascii,
            value: value.to_string(),
            char_count: value.chars().count(),
            is_null_terminated: true,
            xref_count: 0,
        }
    }

    #[test]
    fn link_xrefs_counts() {
        let mut strings = vec![found(0x1000, "hello"), found(0x2000, "world")];
        let refs = vec![
            StringRef {
                from: Address::new(0x10),
                to: Address::new(0x1000),
            },
            StringRef {
                from: Address::new(0x20),
                to: Address::new(0x1000),
            },
            StringRef {
                from: Address::new(0x30),
                to: Address::new(0x2000),
            },
            StringRef {
                from: Address::new(0x40),
                to: Address::new(0x9999),
            }, // no match
        ];
        let matched = link_string_xrefs(&mut strings, &refs);
        assert_eq!(matched, 3);
        assert_eq!(strings[0].xref_count, 2);
        assert_eq!(strings[1].xref_count, 1);
    }

    #[test]
    fn link_xrefs_idempotent() {
        let mut strings = vec![found(0x1000, "hi")];
        let refs = vec![StringRef {
            from: Address::new(0x10),
            to: Address::new(0x1000),
        }];
        link_string_xrefs(&mut strings, &refs);
        link_string_xrefs(&mut strings, &refs);
        assert_eq!(strings[0].xref_count, 1);
    }

    #[test]
    fn most_referenced_filters_and_sorts() {
        let mut strings = vec![found(0x1000, "a"), found(0x2000, "b"), found(0x3000, "c")];
        strings[0].xref_count = 5;
        strings[1].xref_count = 1;
        strings[2].xref_count = 0;
        let hot = most_referenced(&strings, 1);
        assert_eq!(hot.len(), 2);
        assert_eq!(hot[0].value, "a"); // highest first
    }
}
