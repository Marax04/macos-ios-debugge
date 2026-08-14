//! Jump-table (switch) detection and validation.
//!
//! Compilers lower dense `switch` statements into an indirect jump through a
//! table of code pointers (or offsets).  Recovering the table lets the CFG
//! builder add the correct set of out-edges to an otherwise opaque indirect
//! jump.
//!
//! This module recognises the canonical lowering patterns:
//!
//! * **Absolute pointer table** — `jmp [base + index*ptr_size]`.  Each entry is
//!   an absolute code address.
//! * **Relative offset table** — `target = base + table[index]` where each entry
//!   is a (signed) displacement added to a known base (common on PIC x86-64 and
//!   ARM).
//!
//! A bounds check (`cmp index, N; ja default`) usually precedes the jump; when
//! present it gives the exact entry count, otherwise a heuristic upper bound is
//! used.

use rustre_core::address::Address;
use rustre_core::endian::Endian;

/// How the entries of a recovered jump table are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum JumpTableKind {
    /// Each entry is an absolute target address of `entry_size` bytes.
    AbsolutePointers,
    /// Each entry is a signed displacement added to `base` to form the target.
    RelativeOffsets,
}

/// A recovered jump table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JumpTable {
    /// Address of the indirect-jump instruction that consults this table.
    pub jump_site: Address,
    /// Address in memory where the table data begins.
    pub table_addr: Address,
    /// Size of each table entry in bytes (2, 4, or 8 typically).
    pub entry_size: u8,
    /// Number of entries in the table.
    pub entry_count: usize,
    /// Encoding of the entries.
    pub kind: JumpTableKind,
    /// For [`JumpTableKind::RelativeOffsets`], the base added to each entry.
    /// For absolute tables this is ignored (set to `Address::NULL`).
    pub base: Address,
    /// The resolved set of distinct target addresses (the switch case bodies).
    pub targets: Vec<Address>,
}

impl JumpTable {
    /// Number of distinct case targets after de-duplication.
    #[must_use]
    pub const fn distinct_target_count(&self) -> usize {
        self.targets.len()
    }

    /// Whether `addr` is one of this table's targets.
    #[must_use]
    pub fn has_target(&self, addr: Address) -> bool {
        self.targets.contains(&addr)
    }

    /// Total size of the table data region in bytes.
    #[must_use]
    pub const fn table_byte_size(&self) -> usize {
        self.entry_count * self.entry_size as usize
    }
}

/// Configuration / bounds used while validating a candidate jump table.
#[derive(Debug, Clone)]
pub struct JumpTableConfig {
    /// Minimum number of entries before a candidate is accepted.
    pub min_entries: usize,
    /// Maximum number of entries (guards against runaway scans).
    pub max_entries: usize,
    /// Lowest valid code address (targets below this are rejected).
    pub code_low: Address,
    /// One-past-highest valid code address (targets at or above are rejected).
    pub code_high: Address,
    /// Endianness used to decode multi-byte entries.
    pub endian: Endian,
}

impl JumpTableConfig {
    /// Construct a config bounding targets to `[code_low, code_high)`.
    #[must_use]
    pub const fn new(code_low: Address, code_high: Address, endian: Endian) -> Self {
        Self {
            min_entries: 2,
            max_entries: 4096,
            code_low,
            code_high,
            endian,
        }
    }

    /// Whether `addr` is a plausible in-range code target.
    #[must_use]
    pub const fn target_in_range(&self, addr: Address) -> bool {
        addr.as_u64() >= self.code_low.as_u64() && addr.as_u64() < self.code_high.as_u64()
    }
}

/// Read a little/big-endian unsigned integer of `size` bytes from `data` at `off`.
fn read_uint(data: &[u8], off: usize, size: u8, endian: Endian) -> Option<u64> {
    let size = size as usize;
    // Entries wider than 8 bytes can't be decoded into a `u64` (and would
    // panic below when copied into the fixed 8-byte buffer): reject up
    // front instead of trusting the caller-supplied `entry_size`.
    if size == 0 || size > 8 {
        return None;
    }
    if off.checked_add(size).is_none_or(|end| end > data.len()) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(&data[off..off + size]);
    let raw = u64::from_le_bytes(buf);
    Some(match endian {
        Endian::Little => raw,
        Endian::Big => {
            // Re-read in big-endian order.
            let mut v = 0u64;
            for &b in &data[off..off + size] {
                v = (v << 8) | u64::from(b);
            }
            v
        }
    })
}

/// Sign-extend an `size`-byte value held in the low bits of `raw`.
fn sign_extend(raw: u64, size: u8) -> i64 {
    let bits = u32::from(size) * 8;
    if bits >= 64 {
        return raw as i64;
    }
    let shift = 64 - bits;
    ((raw << shift) as i64) >> shift
}

/// Decode an **absolute-pointer** jump table living at `table_off` inside
/// `data` (whose first byte corresponds to address `data_base`).
///
/// Entries are decoded until one falls out of the valid code range, the
/// `max_entries` limit is reached, or a known `count` is exhausted.
#[must_use]
pub fn decode_absolute_table(
    data: &[u8],
    data_base: Address,
    table_addr: Address,
    entry_size: u8,
    known_count: Option<usize>,
    cfg: &JumpTableConfig,
    jump_site: Address,
) -> Option<JumpTable> {
    if entry_size == 0 || table_addr.as_u64() < data_base.as_u64() {
        return None;
    }
    let offset_u64 = table_addr.as_u64() - data_base.as_u64();
    let start = usize::try_from(offset_u64).ok()?;
    // Reject immediately if the table start is already past the buffer.
    if start >= data.len() {
        return None;
    }
    let limit = known_count.unwrap_or(cfg.max_entries).min(cfg.max_entries);

    let mut targets = Vec::new();
    let mut i = 0usize;
    while i < limit {
        let step = i.checked_mul(entry_size as usize)?;
        let off = start.checked_add(step)?;
        let Some(raw) = read_uint(data, off, entry_size, cfg.endian) else {
            break;
        };
        let target = Address::new(raw);
        if !cfg.target_in_range(target) {
            // With an explicit count we keep the (out-of-range) slot as a hole
            // only when within count; otherwise stop scanning.
            if known_count.is_some() {
                i += 1;
                continue;
            }
            break;
        }
        targets.push(target);
        i += 1;
    }

    finalize_table(
        jump_site,
        table_addr,
        entry_size,
        i,
        JumpTableKind::AbsolutePointers,
        Address::NULL,
        targets,
        cfg,
    )
}

/// Decode a **relative-offset** jump table. Each entry is sign-extended and
/// added to `base` to produce the target address.
#[must_use]
pub fn decode_relative_table(
    data: &[u8],
    data_base: Address,
    table_addr: Address,
    entry_size: u8,
    base: Address,
    known_count: Option<usize>,
    cfg: &JumpTableConfig,
    jump_site: Address,
) -> Option<JumpTable> {
    if entry_size == 0 || table_addr.as_u64() < data_base.as_u64() {
        return None;
    }
    let offset_u64 = table_addr.as_u64() - data_base.as_u64();
    let start = usize::try_from(offset_u64).ok()?;
    // Reject immediately if the table start is already past the buffer.
    if start >= data.len() {
        return None;
    }
    let limit = known_count.unwrap_or(cfg.max_entries).min(cfg.max_entries);

    let mut targets = Vec::new();
    let mut i = 0usize;
    while i < limit {
        let step = i.checked_mul(entry_size as usize)?;
        let off = start.checked_add(step)?;
        let Some(raw) = read_uint(data, off, entry_size, cfg.endian) else {
            break;
        };
        let disp = sign_extend(raw, entry_size);
        let target = Address::new(base.as_u64().wrapping_add_signed(disp));
        if !cfg.target_in_range(target) {
            if known_count.is_some() {
                i += 1;
                continue;
            }
            break;
        }
        targets.push(target);
        i += 1;
    }

    finalize_table(
        jump_site,
        table_addr,
        entry_size,
        i,
        JumpTableKind::RelativeOffsets,
        base,
        targets,
        cfg,
    )
}

/// Shared validation + de-duplication step used by both decoders.
fn finalize_table(
    jump_site: Address,
    table_addr: Address,
    entry_size: u8,
    entry_count: usize,
    kind: JumpTableKind,
    base: Address,
    mut targets: Vec<Address>,
    cfg: &JumpTableConfig,
) -> Option<JumpTable> {
    if entry_count < cfg.min_entries {
        return None;
    }
    targets.sort_unstable_by_key(|a| a.as_u64());
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    Some(JumpTable {
        jump_site,
        table_addr,
        entry_size,
        entry_count,
        kind,
        base,
        targets,
    })
}

/// A bounds check recovered from the instructions preceding a switch jump,
/// e.g. `cmp index, 7 ; ja default`.  The number of valid cases is `bound + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchBound {
    /// Inclusive upper bound on the switch index.
    pub max_index: u64,
    /// The default-case address taken when the index exceeds `max_index`.
    pub default_target: Address,
}

impl SwitchBound {
    /// Number of in-range cases (`max_index + 1`, saturating).
    #[must_use]
    pub fn case_count(&self) -> usize {
        usize::try_from(self.max_index.saturating_add(1)).unwrap_or(usize::MAX)
    }
}

/// A fully-recovered switch construct: the table plus its guard.
#[derive(Debug, Clone)]
pub struct SwitchStatement {
    /// The recovered jump table.
    pub table: JumpTable,
    /// The bounds guard, when one was detected.
    pub bound: Option<SwitchBound>,
}

impl SwitchStatement {
    /// All control-flow successors of the switch jump, including the default
    /// case (if a guard was recovered).
    #[must_use]
    pub fn all_successors(&self) -> Vec<Address> {
        let mut succ = self.table.targets.clone();
        if let Some(b) = self.bound && !succ.contains(&b.default_target) {
            succ.push(b.default_target);
        }
        succ.sort_unstable_by_key(|a| a.as_u64());
        succ.dedup();
        succ
    }

    /// Whether the recovered table size is consistent with the guard bound.
    /// A mismatch is a strong signal that recovery went wrong.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        match self.bound {
            None => true,
            Some(b) => self.table.entry_count == b.case_count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDIAN: Endian = Endian::Little;

    fn cfg() -> JumpTableConfig {
        JumpTableConfig::new(Address::new(0x1000), Address::new(0x2000), ENDIAN)
    }

    #[test]
    fn read_uint_le_and_be() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_uint(&data, 0, 4, Endian::Little), Some(0x0403_0201));
        assert_eq!(read_uint(&data, 0, 4, Endian::Big), Some(0x0102_0304));
        assert_eq!(read_uint(&data, 0, 2, Endian::Little), Some(0x0201));
        assert_eq!(read_uint(&data, 3, 4, Endian::Little), None); // OOB
    }

    #[test]
    fn sign_extend_negative() {
        assert_eq!(sign_extend(0xFFFF_FFFF, 4), -1);
        assert_eq!(sign_extend(0x8000_0000, 4), i64::from(i32::MIN));
        assert_eq!(sign_extend(0x7F, 1), 127);
        assert_eq!(sign_extend(0x80, 1), -128);
        assert_eq!(sign_extend(0x0000_0010, 4), 16);
    }

    #[test]
    fn decode_absolute_dense_table() {
        // 4 absolute 4-byte pointers at data_base 0x4000.
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x1300, 0x1400] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(4),
            &cfg(),
            Address::new(0x1500),
        )
        .expect("table recovered");
        assert_eq!(jt.kind, JumpTableKind::AbsolutePointers);
        assert_eq!(jt.entry_count, 4);
        assert_eq!(jt.distinct_target_count(), 4);
        assert!(jt.has_target(Address::new(0x1300)));
        assert_eq!(jt.table_byte_size(), 16);
    }

    #[test]
    fn decode_absolute_stops_at_out_of_range_without_count() {
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x9999, 0x1400] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            None,
            &cfg(),
            Address::new(0x1500),
        )
        .expect("two valid entries");
        assert_eq!(jt.entry_count, 2);
        assert!(!jt.has_target(Address::new(0x1400)));
    }

    #[test]
    fn decode_relative_offsets_signed() {
        // base = 0x1500, offsets {-0x400, -0x300, +0x100} -> 0x1100,0x1200,0x1600
        let offs: [i32; 3] = [-0x400, -0x300, 0x100];
        let mut data = Vec::new();
        for o in offs {
            data.extend_from_slice(&o.to_le_bytes());
        }
        let jt = decode_relative_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Address::new(0x1500),
            Some(3),
            &cfg(),
            Address::new(0x1700),
        )
        .expect("relative table recovered");
        assert_eq!(jt.kind, JumpTableKind::RelativeOffsets);
        assert!(jt.has_target(Address::new(0x1100)));
        assert!(jt.has_target(Address::new(0x1200)));
        assert!(jt.has_target(Address::new(0x1600)));
    }

    #[test]
    fn rejects_table_below_min_entries() {
        let data = 0x1100u32.to_le_bytes().to_vec();
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(1),
            &cfg(),
            Address::new(0x1500),
        );
        assert!(jt.is_none(), "single-entry table should be rejected");
    }

    #[test]
    fn switch_bound_case_count() {
        let b = SwitchBound {
            max_index: 7,
            default_target: Address::new(0x1FF0),
        };
        assert_eq!(b.case_count(), 8);
    }

    #[test]
    fn switch_statement_successors_and_consistency() {
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x1300] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let table = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(3),
            &cfg(),
            Address::new(0x1500),
        )
        .unwrap();
        let stmt = SwitchStatement {
            table,
            bound: Some(SwitchBound {
                max_index: 2,
                default_target: Address::new(0x1FF0),
            }),
        };
        assert!(stmt.is_consistent());
        let succ = stmt.all_successors();
        assert!(succ.contains(&Address::new(0x1FF0)));
        assert_eq!(succ.len(), 4); // 3 cases + default
    }

    #[test]
    fn switch_statement_inconsistent_when_count_mismatch() {
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x1300] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let table = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(3),
            &cfg(),
            Address::new(0x1500),
        )
        .unwrap();
        let stmt = SwitchStatement {
            table,
            bound: Some(SwitchBound {
                max_index: 9, // claims 10 cases but table only has 3
                default_target: Address::new(0x1FF0),
            }),
        };
        assert!(!stmt.is_consistent());
    }

    #[test]
    fn read_uint_rejects_oversized_entry_without_panicking() {
        // entry_size > 8 must be rejected gracefully rather than panicking
        // when copied into the fixed 8-byte decode buffer.
        let data = [0u8; 32];
        assert_eq!(read_uint(&data, 0, 9, Endian::Little), None);
        assert_eq!(read_uint(&data, 0, 255, Endian::Little), None);
        assert_eq!(read_uint(&data, 0, 0, Endian::Little), None);
    }

    #[test]
    fn decode_absolute_table_rejects_oversized_entry_size() {
        // An adversarial/corrupt entry_size (e.g. mis-decoded from the
        // binary) must not panic; it should simply fail to recover a table.
        let data = [0u8; 64];
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            200,
            Some(4),
            &cfg(),
            Address::new(0x1500),
        );
        assert!(jt.is_none());
    }

    #[test]
    fn decode_relative_stops_at_out_of_range_without_count() {
        // Symmetric to `decode_absolute_stops_at_out_of_range_without_count`
        // but for the relative-offset decoder: base 0x1500, offsets
        // {+0x100 -> 0x1600 (in range), +0x100 -> 0x1600, then a huge
        // displacement that lands out of [0x1000, 0x2000)}.
        let offs: [i32; 3] = [-0x400, -0x300, 0x0500_0000];
        let mut data = Vec::new();
        for o in offs {
            data.extend_from_slice(&o.to_le_bytes());
        }
        let jt = decode_relative_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Address::new(0x1500),
            None,
            &cfg(),
            Address::new(0x1700),
        )
        .expect("two valid entries before out-of-range stop");
        assert_eq!(jt.entry_count, 2);
        assert_eq!(jt.distinct_target_count(), 2);
        assert!(jt.has_target(Address::new(0x1100)));
        assert!(jt.has_target(Address::new(0x1200)));
    }

    #[test]
    fn decode_absolute_known_count_keeps_holes_out_of_targets() {
        // With an explicit `known_count`, an out-of-range slot is retained as
        // a "hole" in `entry_count` but must NOT show up in `targets`.
        let mut data = Vec::new();
        for t in [0x1100u32, 0x9999 /* out of range */, 0x1300, 0x1400] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(4),
            &cfg(),
            Address::new(0x1500),
        )
        .expect("table recovered despite one hole");
        assert_eq!(jt.entry_count, 4, "hole still counts as a scanned slot");
        assert_eq!(
            jt.distinct_target_count(),
            3,
            "the out-of-range hole must not appear as a target"
        );
        assert!(!jt.has_target(Address::new(0x9999)));
    }

    #[test]
    fn decode_relative_known_count_keeps_holes_out_of_targets() {
        let offs: [i32; 3] = [-0x400, 0x0500_0000 /* out of range */, 0x100];
        let mut data = Vec::new();
        for o in offs {
            data.extend_from_slice(&o.to_le_bytes());
        }
        let jt = decode_relative_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Address::new(0x1500),
            Some(3),
            &cfg(),
            Address::new(0x1700),
        )
        .expect("table recovered despite one hole");
        assert_eq!(jt.entry_count, 3);
        assert_eq!(jt.distinct_target_count(), 2);
    }

    #[test]
    fn decode_absolute_rejects_table_addr_below_data_base() {
        let data = [0u8; 32];
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x3000), // below data_base
            4,
            Some(4),
            &cfg(),
            Address::new(0x1500),
        );
        assert!(jt.is_none());
    }

    #[test]
    fn decode_relative_rejects_table_addr_below_data_base() {
        let data = [0u8; 32];
        let jt = decode_relative_table(
            &data,
            Address::new(0x4000),
            Address::new(0x3000), // below data_base
            4,
            Address::new(0x1500),
            Some(4),
            &cfg(),
            Address::new(0x1500),
        );
        assert!(jt.is_none());
    }

    #[test]
    fn decode_absolute_rejects_zero_entry_size() {
        let data = [0u8; 32];
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            0,
            Some(4),
            &cfg(),
            Address::new(0x1500),
        );
        assert!(jt.is_none());
    }

    #[test]
    fn decode_known_count_capped_by_max_entries() {
        // A `known_count` far exceeding cfg.max_entries must be clamped, not
        // trusted verbatim (guards against a corrupt/huge count causing a
        // runaway scan or an out-of-bounds read attempt).
        let mut c = cfg();
        c.max_entries = 2;
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x1300, 0x1400] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let jt = decode_absolute_table(
            &data,
            Address::new(0x4000),
            Address::new(0x4000),
            4,
            Some(1_000_000),
            &c,
            Address::new(0x1500),
        )
        .expect("clamped scan still recovers entries");
        assert_eq!(jt.entry_count, 2, "scan must be clamped to max_entries");
    }

    #[test]
    fn target_range_check() {
        let c = cfg();
        assert!(c.target_in_range(Address::new(0x1000)));
        assert!(c.target_in_range(Address::new(0x1FFF)));
        assert!(!c.target_in_range(Address::new(0x2000)));
        assert!(!c.target_in_range(Address::new(0x0FFF)));
    }
}
