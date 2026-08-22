//! Shared bounds for parsing attacker-controlled Lua bytecode headers.
//!
//! Two defect classes are closed here, both reachable from a malformed `.luac`
//! file:
//!
//! * **Unbounded reservation.** Every array in a Lua chunk is introduced by a
//!   count field read from the file. `Vec::with_capacity(count)` with
//!   `count = 0xFFFF_FFFF` reserves gigabytes *before* a single element byte is
//!   read. [`capped_capacity`] clamps the reservation to what the remaining
//!   bytes of the buffer could possibly hold, so the buffer itself — not an
//!   arbitrary constant — is the limit. The decoders still read (and fail) the
//!   same way; only the up-front reservation changes.
//!
//! * **Unbounded recursion.** Nested prototypes cost about five bytes per level
//!   in the file and one native stack frame per level while decoding, so a small
//!   input can exhaust the stack. [`MAX_PROTO_DEPTH`] bounds the nesting and the
//!   decoders return a normal error past it.

use std::io::Cursor;

/// Maximum nesting depth for prototypes inside prototypes.
///
/// Real Lua compilers nest a handful of levels; 128 is far above anything a
/// legitimate chunk produces and far below what exhausts the stack.
pub const MAX_PROTO_DEPTH: usize = 128;

/// Error text returned when [`MAX_PROTO_DEPTH`] is exceeded.
pub fn depth_exceeded_msg() -> String {
    format!("nested prototype depth exceeds {MAX_PROTO_DEPTH}")
}

/// Clamp a count field to the number of elements the remaining bytes could hold.
///
/// `elem_size` is the *minimum* number of bytes one element occupies on the
/// wire; pass 1 when elements are variable-length. `remaining` is the number of
/// bytes left in the buffer.
#[must_use]
pub fn capped_capacity(count: u64, elem_size: usize, remaining: usize) -> usize {
    let max_elems = remaining / elem_size.max(1);
    usize::try_from(count).unwrap_or(usize::MAX).min(max_elems)
}

/// Bytes left after the cursor position.
#[must_use]
pub fn cursor_remaining(cur: &Cursor<&[u8]>) -> usize {
    let len = cur.get_ref().len() as u64;
    usize::try_from(len.saturating_sub(cur.position())).unwrap_or(0)
}

/// [`capped_capacity`] against the bytes left in a cursor.
#[must_use]
pub fn cursor_capacity(cur: &Cursor<&[u8]>, count: u64, elem_size: usize) -> usize {
    capped_capacity(count, elem_size, cursor_remaining(cur))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_absurd_count_to_buffer() {
        // 0xFFFF_FFFF u32 instructions claimed, 16 bytes of buffer left.
        assert_eq!(capped_capacity(0xFFFF_FFFF, 4, 16), 4);
    }

    #[test]
    fn honest_count_survives() {
        assert_eq!(capped_capacity(3, 4, 4096), 3);
    }

    #[test]
    fn zero_elem_size_does_not_divide_by_zero() {
        assert_eq!(capped_capacity(10, 0, 4), 4);
    }

    #[test]
    fn cursor_remaining_is_bytes_after_position() {
        let data = [0u8; 32];
        let mut cur = Cursor::new(&data[..]);
        cur.set_position(8);
        assert_eq!(cursor_remaining(&cur), 24);
        cur.set_position(100);
        assert_eq!(cursor_remaining(&cur), 0);
    }
}
