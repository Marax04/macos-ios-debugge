//! Shared CU-relative `.stabstr` string resolution.
//!
//! In a linker-merged `.stab` section every compilation unit's run of records
//! is introduced by a synthetic `N_UNDF` (0x00) header record:
//!
//! * `n_desc`  — number of stab records that follow for this CU;
//! * `n_value` — byte size of *this CU's* slice of the `.stabstr` table;
//! * `n_strx`  — offset (relative to the running base) of the CU name.
//!
//! Every subsequent record's `n_strx` is relative to a running base that is the
//! sum of the `n_value` fields of all preceding `N_UNDF` headers. Treating
//! `n_strx` as an absolute `.stabstr` offset therefore resolves the first CU
//! correctly and silently lands mid-string for every CU after it.
//!
//! This module is the single implementation every string resolver in the crate
//! delegates to, so the little-endian and big-endian paths — and the four
//! parser modules — cannot drift apart.
//!
//! The accumulation order follows GDB's `read_dbx_symtab`: two counters,
//! `base` (the current CU's slice start) and `next_base` (the running total).
//! On an `N_UNDF` header, `base` becomes `next_base` and `next_base` advances
//! by `n_value` — so the header's *own* name and every record that follows it
//! resolve against the CU it introduces, not the one before it. Reading the
//! header at the old base and advancing afterwards would shift every CU's
//! records forward by one slice, which is a different flavour of wrong.
//!
//! Robustness rules (mirroring GDB's leniency):
//!
//! * No leading `N_UNDF` (a non-merged, single-CU `.stab`) leaves the base at
//!   0, which makes CU-relative resolution byte-identical to the old absolute
//!   behaviour.
//! * A header whose `n_value` would push the base past the end of `.stabstr`
//!   is malformed: the base is left untouched (and counted) rather than
//!   desyncing every following record.
//! * If `base + n_strx` lands out of range but the bare `n_strx` is in range,
//!   the bare offset is used. Some producers and linkers pre-merge the string
//!   table and emit absolute indices alongside the headers.

/// `N_UNDF` — the CU header record type used to delimit string-table slices.
pub const N_UNDF: u8 = 0x00;

/// Running `.stabstr` base tracking `N_UNDF` compilation-unit headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CuStringBase {
    base: u64,
    next_base: u64,
    malformed_headers: u32,
}

impl CuStringBase {
    /// A fresh base positioned at the start of `.stabstr`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: 0,
            next_base: 0,
            malformed_headers: 0,
        }
    }

    /// Start offset in `.stabstr` of the CU currently being read.
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// Start offset of the *next* CU (running total of header sizes).
    #[must_use]
    pub const fn next_base(&self) -> u64 {
        self.next_base
    }

    /// Number of `N_UNDF` headers rejected as malformed (out-of-range size).
    #[must_use]
    pub const fn malformed_headers(&self) -> u32 {
        self.malformed_headers
    }

    /// Byte offset into `.stabstr` for `n_strx` under the current base.
    ///
    /// Returns `None` when neither the CU-relative nor the absolute
    /// interpretation is in range.
    #[must_use]
    pub fn offset(&self, stabstr_len: usize, n_strx: u32) -> Option<usize> {
        let abs = usize::try_from(n_strx).ok()?;
        if let Some(rel) = self.base.checked_add(u64::from(n_strx))
            && let Ok(rel) = usize::try_from(rel)
            && rel < stabstr_len
        {
            return Some(rel);
        }
        // Fall back to an absolute index (pre-merged string table).
        if abs < stabstr_len { Some(abs) } else { None }
    }

    /// Account for a record *before* its own string is resolved.
    ///
    /// Only `N_UNDF` moves the base; everything else is a no-op. Must be
    /// called ahead of [`Self::offset`] for the same record, so a CU header's
    /// own name is read from the slice it introduces.
    pub fn observe(&mut self, n_type: u8, n_value: u32, stabstr_len: usize) {
        if n_type != N_UNDF {
            return;
        }
        let start = self.next_base;
        let start_ok = usize::try_from(start).is_ok_and(|s| s <= stabstr_len);
        if start_ok {
            self.base = start;
        }
        match start.checked_add(u64::from(n_value)) {
            Some(end) if start_ok && usize::try_from(end).is_ok_and(|e| e <= stabstr_len) => {
                self.next_base = end;
            }
            _ => {
                // Malformed / out-of-range size. Do not let it push the
                // running total past the table: park `next_base` at this CU's
                // start so following records degrade to this slice (or to the
                // absolute fallback) rather than desyncing everything after.
                self.malformed_headers = self.malformed_headers.saturating_add(1);
                if start_ok {
                    self.next_base = start;
                }
            }
        }
    }

    /// Advance past an `N_UNDF` header if needed, then resolve the record's
    /// string. This is the single operation the record loops want.
    pub fn resolve<'a>(
        &mut self,
        stabstr: &'a [u8],
        n_type: u8,
        n_strx: u32,
        n_value: u32,
    ) -> &'a str {
        std::str::from_utf8(self.resolve_bytes(stabstr, n_type, n_strx, n_value)).unwrap_or("")
    }

    /// Like [`Self::resolve`] but returning the raw bytes, for callers that
    /// want a lossy UTF-8 conversion rather than dropping non-UTF-8 names.
    pub fn resolve_bytes<'a>(
        &mut self,
        stabstr: &'a [u8],
        n_type: u8,
        n_strx: u32,
        n_value: u32,
    ) -> &'a [u8] {
        self.observe(n_type, n_value, stabstr.len());
        self.offset(stabstr.len(), n_strx)
            .map_or(&[][..], |off| read_cstr_bytes(stabstr, off))
    }
}

/// Read the NUL-terminated byte run starting at `off` (empty when out of range).
#[must_use]
pub fn read_cstr_bytes(stabstr: &[u8], off: usize) -> &[u8] {
    let Some(slice) = stabstr.get(off..) else {
        return &[];
    };
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    slice.get(..end).unwrap_or(&[])
}

/// Read a NUL-terminated string starting at `off`, without indexing raw buffers.
///
/// Returns `""` when the offset is out of range or the bytes are not UTF-8.
#[must_use]
pub fn read_cstr(stabstr: &[u8], off: usize) -> &str {
    std::str::from_utf8(read_cstr_bytes(stabstr, off)).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_undf_header_behaves_as_absolute() {
        let strs = b"\0alpha\0beta\0";
        let mut b = CuStringBase::new();
        assert_eq!(b.resolve(strs, 0x24, 1, 0), "alpha");
        assert_eq!(b.resolve(strs, 0x24, 7, 0), "beta");
        assert_eq!(b.base(), 0);
    }

    #[test]
    fn header_name_and_records_resolve_in_the_cu_the_header_opens() {
        // CU1 slice "\0a.c\0" (5 bytes), CU2 slice "\0b.c\0" (5 bytes).
        let strs = b"\0a.c\0\0b.c\0";
        let mut b = CuStringBase::new();
        // CU1 header: base stays 0, next_base -> 5.
        assert_eq!(b.resolve(strs, N_UNDF, 1, 5), "a.c");
        assert_eq!((b.base(), b.next_base()), (0, 5));
        // A CU1 record still resolves inside CU1's slice.
        assert_eq!(b.resolve(strs, 0x24, 1, 0), "a.c");
        // CU2 header: base -> 5, and its own name comes from CU2's slice.
        assert_eq!(b.resolve(strs, N_UNDF, 1, 5), "b.c");
        assert_eq!((b.base(), b.next_base()), (5, 10));
        assert_eq!(b.resolve(strs, 0x24, 1, 0), "b.c");
    }

    #[test]
    fn malformed_size_is_rejected_not_desyncing() {
        let strs = b"\0a.c\0";
        let mut b = CuStringBase::new();
        assert_eq!(b.resolve(strs, N_UNDF, 1, u32::MAX), "a.c");
        assert_eq!((b.base(), b.next_base()), (0, 0));
        assert_eq!(b.malformed_headers(), 1);
        assert_eq!(b.resolve(strs, 0x24, 1, 0), "a.c");
    }

    #[test]
    fn out_of_range_relative_falls_back_to_absolute() {
        let strs = b"\0alpha\0";
        let mut b = CuStringBase::new();
        b.next_base = 5;
        b.observe(N_UNDF, 0, strs.len());
        assert_eq!(b.base(), 5);
        // base + 4 == 9 is out of range, so the absolute index 4 wins.
        assert_eq!(b.offset(strs.len(), 4), Some(4));
        assert_eq!(read_cstr(strs, 4), "ha");
    }

    #[test]
    fn offset_out_of_range_everywhere_is_none() {
        let b = CuStringBase::new();
        assert_eq!(b.offset(4, 99), None);
        assert_eq!(read_cstr(b"abc", 99), "");
    }
}
