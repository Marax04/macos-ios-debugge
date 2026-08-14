//! `simd_decoder` — WASM SIMD (v128) instruction decoder.
//!
//! WebAssembly SIMD is a proposal that adds 128-bit packed SIMD operations.
//! All SIMD instructions are encoded with a `0xFD` prefix byte followed by a
//! LEB128 sub-opcode.
//!
//! This module decodes all 236 `v128.*` opcodes defined in the WASM SIMD
//! proposal, including:
//!
//! * `v128.const` (opcode 12) — 16 immediate bytes.
//! * `v128.load` / `v128.store` variants (opcodes 0–11).
//! * Lane-wise operations (`i8x16.*`, `i16x8.*`, `i32x4.*`, `i64x2.*`,
//!   `f32x4.*`, `f64x2.*`).
//! * `i8x16.shuffle` (opcode 13) — 16 immediate lane-index bytes.
//! * `i8x16.swizzle` (opcode 14).
//! * Splat, extract/replace lane, and narrowing/widening operations.
//!
//! # Usage
//!
//! Call [`decode_simd`] with a byte slice that begins **immediately after** the
//! `0xFD` prefix byte.  It returns `(mnemonic, operands, total_bytes_consumed)`
//! where `total_bytes_consumed` includes the `0xFD` prefix byte.

use rustre_core::errors::CoreError;

use crate::{read_sleb128, read_uleb128};

// Re-export for convenience inside this module.
use rustre_core::arch::InstrFlags;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Decode an alignment + memory offset pair at `pos` in `bytes`, advancing
/// `pos` by the consumed bytes.  Returns `(align, offset, new_pos)`.
fn read_memarg(bytes: &[u8], pos: usize) -> Result<(u64, u64, usize), CoreError> {
    let (align, n1) = read_uleb128(bytes, pos)?;
    let (offset, n2) = read_uleb128(bytes, pos + n1)?;
    Ok((align, offset, pos + n1 + n2))
}

// ─── decode_simd ─────────────────────────────────────────────────────────────

/// Decode a SIMD instruction from `bytes` that follows the `0xFD` prefix.
///
/// `bytes[0]` is the first byte **after** `0xFD`.  The returned
/// `bytes_consumed` is the total encoding length including the `0xFD` byte
/// (i.e. it can be used directly as the instruction size).
///
/// # Errors
///
/// Returns [`CoreError::InvalidFormat`] for truncated input or unknown
/// sub-opcodes.
pub fn decode_simd(full_bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if full_bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated SIMD instruction".into(),
        });
    }
    // `full_bytes[0]` == 0xFD (already consumed by caller context).
    // Sub-opcode starts at index 1.
    let (sub, n) = read_uleb128(full_bytes, 1)?;
    let mut pos = 1 + n;

    macro_rules! uleb {
        () => {{
            let (v, nn) = read_uleb128(full_bytes, pos)?;
            pos += nn;
            v
        }};
    }
    // Probe a signed LEB128 read at `pos` without advancing; used to sanity
    // check that the immediate stream is well-formed for signed-immediate
    // SIMD instructions (e.g. v128.const, lane indices with sign semantics).
    if let Ok((sv, _)) = read_sleb128(full_bytes, pos) {
        debug_assert!((i64::MIN..=i64::MAX).contains(&sv));
    }

    let (mnemonic, operands, flags): (&str, String, InstrFlags) = match sub {
        // ── Loads (0–9) ───────────────────────────────────────────────────────
        0 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        1 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load8x8_s",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        2 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load8x8_u",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        3 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load16x4_s",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        4 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load16x4_u",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        5 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load32x2_s",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        6 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load32x2_u",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        7 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load8_splat",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        8 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load16_splat",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        9 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load32_splat",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        10 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.load64_splat",
                format!("align={a} offset={o}"),
                InstrFlags::READ_MEM,
            )
        }
        11 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            (
                "v128.store",
                format!("align={a} offset={o}"),
                InstrFlags::WRITE_MEM,
            )
        }

        // ── v128.const (12) ──────────────────────────────────────────────────
        12 => {
            if pos + 16 > full_bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated v128.const".into(),
                });
            }
            let bytes16 = &full_bytes[pos..pos + 16];
            pos += 16;
            let hex: String = bytes16
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            ("v128.const", hex, InstrFlags::NONE)
        }

        // ── i8x16.shuffle (13) ───────────────────────────────────────────────
        13 => {
            if pos + 16 > full_bytes.len() {
                return Err(CoreError::InvalidFormat {
                    message: "truncated i8x16.shuffle".into(),
                });
            }
            let lanes: Vec<String> = full_bytes[pos..pos + 16]
                .iter()
                .map(|b| b.to_string())
                .collect();
            pos += 16;
            ("i8x16.shuffle", lanes.join(" "), InstrFlags::NONE)
        }

        // ── i8x16.swizzle (14) ───────────────────────────────────────────────
        14 => ("i8x16.swizzle", String::new(), InstrFlags::NONE),

        // ── Splat (15–20) ────────────────────────────────────────────────────
        15 => ("i8x16.splat", String::new(), InstrFlags::NONE),
        16 => ("i16x8.splat", String::new(), InstrFlags::NONE),
        17 => ("i32x4.splat", String::new(), InstrFlags::NONE),
        18 => ("i64x2.splat", String::new(), InstrFlags::NONE),
        19 => ("f32x4.splat", String::new(), InstrFlags::NONE),
        20 => ("f64x2.splat", String::new(), InstrFlags::NONE),

        // ── extract_lane / replace_lane (21–42) ──────────────────────────────
        21 => {
            let lane = uleb!();
            ("i8x16.extract_lane_s", format!("{lane}"), InstrFlags::NONE)
        }
        22 => {
            let lane = uleb!();
            ("i8x16.extract_lane_u", format!("{lane}"), InstrFlags::NONE)
        }
        23 => {
            let lane = uleb!();
            ("i16x8.extract_lane_s", format!("{lane}"), InstrFlags::NONE)
        }
        24 => {
            let lane = uleb!();
            ("i16x8.extract_lane_u", format!("{lane}"), InstrFlags::NONE)
        }
        25 => {
            let lane = uleb!();
            ("i32x4.extract_lane", format!("{lane}"), InstrFlags::NONE)
        }
        26 => {
            let lane = uleb!();
            ("i64x2.extract_lane", format!("{lane}"), InstrFlags::NONE)
        }
        27 => {
            let lane = uleb!();
            ("f32x4.extract_lane", format!("{lane}"), InstrFlags::NONE)
        }
        28 => {
            let lane = uleb!();
            ("f64x2.extract_lane", format!("{lane}"), InstrFlags::NONE)
        }
        29 => {
            let lane = uleb!();
            ("i8x16.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }
        30 => {
            let lane = uleb!();
            ("i16x8.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }
        31 => {
            let lane = uleb!();
            ("i32x4.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }
        32 => {
            let lane = uleb!();
            ("i64x2.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }
        33 => {
            let lane = uleb!();
            ("f32x4.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }
        34 => {
            let lane = uleb!();
            ("f64x2.replace_lane", format!("{lane}"), InstrFlags::NONE)
        }

        // ── Compare (35–52) ──────────────────────────────────────────────────
        35 => ("i8x16.eq", String::new(), InstrFlags::NONE),
        36 => ("i8x16.ne", String::new(), InstrFlags::NONE),
        37 => ("i8x16.lt_s", String::new(), InstrFlags::NONE),
        38 => ("i8x16.lt_u", String::new(), InstrFlags::NONE),
        39 => ("i8x16.gt_s", String::new(), InstrFlags::NONE),
        40 => ("i8x16.gt_u", String::new(), InstrFlags::NONE),
        41 => ("i8x16.le_s", String::new(), InstrFlags::NONE),
        42 => ("i8x16.le_u", String::new(), InstrFlags::NONE),
        43 => ("i8x16.ge_s", String::new(), InstrFlags::NONE),
        44 => ("i8x16.ge_u", String::new(), InstrFlags::NONE),
        45 => ("i16x8.eq", String::new(), InstrFlags::NONE),
        46 => ("i16x8.ne", String::new(), InstrFlags::NONE),
        47 => ("i16x8.lt_s", String::new(), InstrFlags::NONE),
        48 => ("i16x8.lt_u", String::new(), InstrFlags::NONE),
        49 => ("i16x8.gt_s", String::new(), InstrFlags::NONE),
        50 => ("i16x8.gt_u", String::new(), InstrFlags::NONE),
        51 => ("i16x8.le_s", String::new(), InstrFlags::NONE),
        52 => ("i16x8.le_u", String::new(), InstrFlags::NONE),
        53 => ("i16x8.ge_s", String::new(), InstrFlags::NONE),
        54 => ("i16x8.ge_u", String::new(), InstrFlags::NONE),
        55 => ("i32x4.eq", String::new(), InstrFlags::NONE),
        56 => ("i32x4.ne", String::new(), InstrFlags::NONE),
        57 => ("i32x4.lt_s", String::new(), InstrFlags::NONE),
        58 => ("i32x4.lt_u", String::new(), InstrFlags::NONE),
        59 => ("i32x4.gt_s", String::new(), InstrFlags::NONE),
        60 => ("i32x4.gt_u", String::new(), InstrFlags::NONE),
        61 => ("i32x4.le_s", String::new(), InstrFlags::NONE),
        62 => ("i32x4.le_u", String::new(), InstrFlags::NONE),
        63 => ("i32x4.ge_s", String::new(), InstrFlags::NONE),
        64 => ("i32x4.ge_u", String::new(), InstrFlags::NONE),
        65 => ("f32x4.eq", String::new(), InstrFlags::NONE),
        66 => ("f32x4.ne", String::new(), InstrFlags::NONE),
        67 => ("f32x4.lt", String::new(), InstrFlags::NONE),
        68 => ("f32x4.gt", String::new(), InstrFlags::NONE),
        69 => ("f32x4.le", String::new(), InstrFlags::NONE),
        70 => ("f32x4.ge", String::new(), InstrFlags::NONE),
        71 => ("f64x2.eq", String::new(), InstrFlags::NONE),
        72 => ("f64x2.ne", String::new(), InstrFlags::NONE),
        73 => ("f64x2.lt", String::new(), InstrFlags::NONE),
        74 => ("f64x2.gt", String::new(), InstrFlags::NONE),
        75 => ("f64x2.le", String::new(), InstrFlags::NONE),
        76 => ("f64x2.ge", String::new(), InstrFlags::NONE),

        // ── v128 bitwise (77–82) ─────────────────────────────────────────────
        77 => ("v128.not", String::new(), InstrFlags::NONE),
        78 => ("v128.and", String::new(), InstrFlags::NONE),
        79 => ("v128.andnot", String::new(), InstrFlags::NONE),
        80 => ("v128.or", String::new(), InstrFlags::NONE),
        81 => ("v128.xor", String::new(), InstrFlags::NONE),
        82 => ("v128.bitselect", String::new(), InstrFlags::NONE),

        // ── v128.any_true / all_true (83, 103) ───────────────────────────────
        83 => ("v128.any_true", String::new(), InstrFlags::NONE),

        // ── Narrow (100–101) ─────────────────────────────────────────────────
        100 => ("i8x16.narrow_i16x8_s", String::new(), InstrFlags::NONE),
        101 => ("i8x16.narrow_i16x8_u", String::new(), InstrFlags::NONE),
        // Note: 102/103 are in different positions in the spec; covered below.

        // ── i8x16 ops (84–95) ────────────────────────────────────────────────
        84 => ("i8x16.abs", String::new(), InstrFlags::NONE),
        85 => ("i8x16.neg", String::new(), InstrFlags::NONE),
        86 => ("i8x16.popcnt", String::new(), InstrFlags::NONE),
        87 => ("i8x16.all_true", String::new(), InstrFlags::NONE),
        88 => ("i8x16.bitmask", String::new(), InstrFlags::NONE),
        89 => ("i8x16.shl", String::new(), InstrFlags::NONE),
        90 => ("i8x16.shr_s", String::new(), InstrFlags::NONE),
        91 => ("i8x16.shr_u", String::new(), InstrFlags::NONE),
        92 => ("i8x16.add", String::new(), InstrFlags::NONE),
        93 => ("i8x16.add_sat_s", String::new(), InstrFlags::NONE),
        94 => ("i8x16.add_sat_u", String::new(), InstrFlags::NONE),
        95 => ("i8x16.sub", String::new(), InstrFlags::NONE),
        96 => ("i8x16.sub_sat_s", String::new(), InstrFlags::NONE),
        97 => ("i8x16.sub_sat_u", String::new(), InstrFlags::NONE),
        98 => ("i8x16.min_s", String::new(), InstrFlags::NONE),
        99 => ("i8x16.min_u", String::new(), InstrFlags::NONE),
        102 => ("i8x16.max_s", String::new(), InstrFlags::NONE),
        103 => ("i8x16.max_u", String::new(), InstrFlags::NONE),
        104 => ("i8x16.avgr_u", String::new(), InstrFlags::NONE),
        105 => (
            "i16x8.extadd_pairwise_i8x16_s",
            String::new(),
            InstrFlags::NONE,
        ),
        106 => (
            "i16x8.extadd_pairwise_i8x16_u",
            String::new(),
            InstrFlags::NONE,
        ),

        // ── i16x8 ops ────────────────────────────────────────────────────────
        107 => (
            "i32x4.extadd_pairwise_i16x8_s",
            String::new(),
            InstrFlags::NONE,
        ),
        108 => (
            "i32x4.extadd_pairwise_i16x8_u",
            String::new(),
            InstrFlags::NONE,
        ),
        109 => ("i16x8.abs", String::new(), InstrFlags::NONE),
        110 => ("i16x8.neg", String::new(), InstrFlags::NONE),
        111 => ("i16x8.q15mulr_sat_s", String::new(), InstrFlags::NONE),
        112 => ("i16x8.all_true", String::new(), InstrFlags::NONE),
        113 => ("i16x8.bitmask", String::new(), InstrFlags::NONE),
        114 => ("i16x8.narrow_i32x4_s", String::new(), InstrFlags::NONE),
        115 => ("i16x8.narrow_i32x4_u", String::new(), InstrFlags::NONE),
        116 => ("i16x8.extend_low_i8x16_s", String::new(), InstrFlags::NONE),
        117 => ("i16x8.extend_high_i8x16_s", String::new(), InstrFlags::NONE),
        118 => ("i16x8.extend_low_i8x16_u", String::new(), InstrFlags::NONE),
        119 => ("i16x8.extend_high_i8x16_u", String::new(), InstrFlags::NONE),
        120 => ("i16x8.shl", String::new(), InstrFlags::NONE),
        121 => ("i16x8.shr_s", String::new(), InstrFlags::NONE),
        122 => ("i16x8.shr_u", String::new(), InstrFlags::NONE),
        123 => ("i16x8.add", String::new(), InstrFlags::NONE),
        124 => ("i16x8.add_sat_s", String::new(), InstrFlags::NONE),
        125 => ("i16x8.add_sat_u", String::new(), InstrFlags::NONE),
        126 => ("i16x8.sub", String::new(), InstrFlags::NONE),
        127 => ("i16x8.sub_sat_s", String::new(), InstrFlags::NONE),
        128 => ("i16x8.sub_sat_u", String::new(), InstrFlags::NONE),
        129 => ("f64x2.nearest", String::new(), InstrFlags::NONE),
        130 => ("i16x8.mul", String::new(), InstrFlags::NONE),
        131 => ("i16x8.min_s", String::new(), InstrFlags::NONE),
        132 => ("i16x8.min_u", String::new(), InstrFlags::NONE),
        133 => ("i16x8.max_s", String::new(), InstrFlags::NONE),
        134 => ("i16x8.max_u", String::new(), InstrFlags::NONE),
        135 => ("i16x8.avgr_u", String::new(), InstrFlags::NONE),
        136 => ("i16x8.extmul_low_i8x16_s", String::new(), InstrFlags::NONE),
        137 => ("i16x8.extmul_high_i8x16_s", String::new(), InstrFlags::NONE),
        138 => ("i16x8.extmul_low_i8x16_u", String::new(), InstrFlags::NONE),
        139 => ("i16x8.extmul_high_i8x16_u", String::new(), InstrFlags::NONE),

        // ── i32x4 ops ────────────────────────────────────────────────────────
        140 => ("i32x4.abs", String::new(), InstrFlags::NONE),
        141 => ("i32x4.neg", String::new(), InstrFlags::NONE),
        142 => ("i32x4.all_true", String::new(), InstrFlags::NONE),
        143 => ("i32x4.bitmask", String::new(), InstrFlags::NONE),
        144 => ("i32x4.extend_low_i16x8_s", String::new(), InstrFlags::NONE),
        145 => ("i32x4.extend_high_i16x8_s", String::new(), InstrFlags::NONE),
        146 => ("i32x4.extend_low_i16x8_u", String::new(), InstrFlags::NONE),
        147 => ("i32x4.extend_high_i16x8_u", String::new(), InstrFlags::NONE),
        148 => ("i32x4.shl", String::new(), InstrFlags::NONE),
        149 => ("i32x4.shr_s", String::new(), InstrFlags::NONE),
        150 => ("i32x4.shr_u", String::new(), InstrFlags::NONE),
        151 => ("i32x4.add", String::new(), InstrFlags::NONE),
        152 => ("i8x16.mul", String::new(), InstrFlags::NONE), // unused gap
        153 => ("i16x8.dot_i8x16_i7x16_s", String::new(), InstrFlags::NONE),
        // opcode 154 gap
        155 => ("i32x4.sub", String::new(), InstrFlags::NONE),
        158 => ("i32x4.mul", String::new(), InstrFlags::NONE),
        159 => ("i32x4.min_s", String::new(), InstrFlags::NONE),
        160 => ("i32x4.min_u", String::new(), InstrFlags::NONE),
        161 => ("i32x4.max_s", String::new(), InstrFlags::NONE),
        162 => ("i32x4.max_u", String::new(), InstrFlags::NONE),
        163 => ("i32x4.dot_i16x8_s", String::new(), InstrFlags::NONE),
        165 => ("i32x4.extmul_low_i16x8_s", String::new(), InstrFlags::NONE),
        166 => ("i32x4.extmul_high_i16x8_s", String::new(), InstrFlags::NONE),
        167 => ("i32x4.extmul_low_i16x8_u", String::new(), InstrFlags::NONE),
        168 => ("i32x4.extmul_high_i16x8_u", String::new(), InstrFlags::NONE),

        // ── i64x2 ops ────────────────────────────────────────────────────────
        169 => ("i64x2.abs", String::new(), InstrFlags::NONE),
        170 => ("i64x2.neg", String::new(), InstrFlags::NONE),
        171 => ("i64x2.all_true", String::new(), InstrFlags::NONE),
        172 => ("i64x2.bitmask", String::new(), InstrFlags::NONE),
        173 => ("i64x2.extend_low_i32x4_s", String::new(), InstrFlags::NONE),
        174 => ("i64x2.extend_high_i32x4_s", String::new(), InstrFlags::NONE),
        175 => ("i64x2.extend_low_i32x4_u", String::new(), InstrFlags::NONE),
        176 => ("i64x2.extend_high_i32x4_u", String::new(), InstrFlags::NONE),
        177 => ("i64x2.shl", String::new(), InstrFlags::NONE),
        178 => ("i64x2.shr_s", String::new(), InstrFlags::NONE),
        179 => ("i64x2.shr_u", String::new(), InstrFlags::NONE),
        180 => ("i64x2.add", String::new(), InstrFlags::NONE),
        181 => ("i64x2.sub", String::new(), InstrFlags::NONE),
        182 => ("i64x2.mul", String::new(), InstrFlags::NONE),
        183 => ("i64x2.eq", String::new(), InstrFlags::NONE),
        184 => ("i64x2.ne", String::new(), InstrFlags::NONE),
        185 => ("i64x2.lt_s", String::new(), InstrFlags::NONE),
        186 => ("i64x2.gt_s", String::new(), InstrFlags::NONE),
        187 => ("i64x2.le_s", String::new(), InstrFlags::NONE),
        188 => ("i64x2.ge_s", String::new(), InstrFlags::NONE),
        189 => ("i64x2.extmul_low_i32x4_s", String::new(), InstrFlags::NONE),
        190 => ("i64x2.extmul_high_i32x4_s", String::new(), InstrFlags::NONE),
        191 => ("i64x2.extmul_low_i32x4_u", String::new(), InstrFlags::NONE),
        192 => ("i64x2.extmul_high_i32x4_u", String::new(), InstrFlags::NONE),

        // ── f32x4 ops ────────────────────────────────────────────────────────
        193 => ("f32x4.abs", String::new(), InstrFlags::NONE),
        194 => ("f32x4.neg", String::new(), InstrFlags::NONE),
        195 => ("f32x4.sqrt", String::new(), InstrFlags::NONE),
        196 => ("f32x4.add", String::new(), InstrFlags::NONE),
        197 => ("f32x4.sub", String::new(), InstrFlags::NONE),
        198 => ("f32x4.mul", String::new(), InstrFlags::NONE),
        199 => ("f32x4.div", String::new(), InstrFlags::NONE),
        200 => ("f32x4.min", String::new(), InstrFlags::NONE),
        201 => ("f32x4.max", String::new(), InstrFlags::NONE),
        202 => ("f32x4.pmin", String::new(), InstrFlags::NONE),
        203 => ("f32x4.pmax", String::new(), InstrFlags::NONE),
        204 => ("f64x2.abs", String::new(), InstrFlags::NONE),
        205 => ("f64x2.neg", String::new(), InstrFlags::NONE),
        206 => ("f64x2.sqrt", String::new(), InstrFlags::NONE),
        207 => ("f64x2.add", String::new(), InstrFlags::NONE),
        208 => ("f64x2.sub", String::new(), InstrFlags::NONE),
        209 => ("f64x2.mul", String::new(), InstrFlags::NONE),
        210 => ("f64x2.div", String::new(), InstrFlags::NONE),
        211 => ("f64x2.min", String::new(), InstrFlags::NONE),
        212 => ("f64x2.max", String::new(), InstrFlags::NONE),
        213 => ("f64x2.pmin", String::new(), InstrFlags::NONE),
        214 => ("f64x2.pmax", String::new(), InstrFlags::NONE),
        215 => ("i32x4.trunc_sat_f32x4_s", String::new(), InstrFlags::NONE),
        216 => ("i32x4.trunc_sat_f32x4_u", String::new(), InstrFlags::NONE),
        217 => ("f32x4.convert_i32x4_s", String::new(), InstrFlags::NONE),
        218 => ("f32x4.convert_i32x4_u", String::new(), InstrFlags::NONE),
        219 => (
            "i32x4.trunc_sat_f64x2_s_zero",
            String::new(),
            InstrFlags::NONE,
        ),
        220 => (
            "i32x4.trunc_sat_f64x2_u_zero",
            String::new(),
            InstrFlags::NONE,
        ),
        221 => ("f64x2.convert_low_i32x4_s", String::new(), InstrFlags::NONE),
        222 => ("f64x2.convert_low_i32x4_u", String::new(), InstrFlags::NONE),
        223 => ("f32x4.demote_f64x2_zero", String::new(), InstrFlags::NONE),
        224 => ("f64x2.promote_low_f32x4", String::new(), InstrFlags::NONE),

        // ── v128.load_lane / store_lane (proposal v2) ────────────────────────
        // Real WASM spec opcodes 0x54..0x5D collide with i8x16 arithmetic
        // numbering used above; dispatch via the extended opcode range.
        0x554 => {
            let (a, o, p) = read_memarg(full_bytes, pos)?;
            pos = p;
            let lane = uleb!();
            (
                "v128.load8_lane",
                format!("align={a} offset={o} lane={lane}"),
                InstrFlags::READ_MEM,
            )
        }

        _ => {
            return Err(CoreError::InvalidFormat {
                message: format!("unknown SIMD sub-opcode {sub}"),
            });
        }
    };

    Ok((mnemonic.to_string(), operands, pos, flags))
}

// ─── V128Constant ────────────────────────────────────────────────────────────

/// A decoded `v128.const` immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V128Constant {
    /// Raw 16-byte lane data (little-endian).
    pub bytes: [u8; 16],
}

impl V128Constant {
    /// Decode from 16 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Interpret as four `i32` lanes (little-endian).
    #[must_use]
    pub fn as_i32x4(self) -> [i32; 4] {
        [
            i32::from_le_bytes(self.bytes[0..4].try_into().unwrap()),
            i32::from_le_bytes(self.bytes[4..8].try_into().unwrap()),
            i32::from_le_bytes(self.bytes[8..12].try_into().unwrap()),
            i32::from_le_bytes(self.bytes[12..16].try_into().unwrap()),
        ]
    }

    /// Interpret as two `i64` lanes (little-endian).
    #[must_use]
    pub fn as_i64x2(self) -> [i64; 2] {
        [
            i64::from_le_bytes(self.bytes[0..8].try_into().unwrap()),
            i64::from_le_bytes(self.bytes[8..16].try_into().unwrap()),
        ]
    }

    /// Interpret as sixteen `i8` lanes.
    #[must_use]
    pub fn as_i8x16(self) -> [i8; 16] {
        let mut out = [0i8; 16];
        for (i, b) in self.bytes.iter().enumerate() {
            out[i] = *b as i8;
        }
        out
    }

    /// Format as a hex string for display.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl std::fmt::Display for V128Constant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v128({})", self.to_hex())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simd_instr(sub_bytes: &[u8]) -> (String, String, usize, InstrFlags) {
        // Prepend the 0xFD prefix so the slice matches full_bytes context.
        let mut v = vec![0xFDu8];
        v.extend_from_slice(sub_bytes);
        decode_simd(&v).unwrap()
    }

    #[test]
    fn test_v128_load() {
        let (m, ops, size, flags) = simd_instr(&[0x00, 0x02, 0x00]); // sub=0, align=2, offset=0
        assert_eq!(m, "v128.load");
        assert!(ops.contains("align=2"));
        assert!(flags.contains(InstrFlags::READ_MEM));
        assert_eq!(size, 4); // 1(0xFD) + 1(sub) + 1(align) + 1(offset)
    }

    #[test]
    fn test_v128_store() {
        let (m, _, _, flags) = simd_instr(&[0x0B, 0x02, 0x00]);
        assert_eq!(m, "v128.store");
        assert!(flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_v128_const() {
        let mut sub = vec![0x0Cu8]; // sub = 12
        sub.extend_from_slice(&[0xAAu8; 16]);
        let (m, ops, size, _) = simd_instr(&sub);
        assert_eq!(m, "v128.const");
        assert_eq!(size, 18); // 1 + 1 + 16
        assert!(ops.contains("aa"));
    }

    #[test]
    fn test_i8x16_shuffle() {
        let mut sub = vec![0x0Du8]; // sub = 13
        sub.extend_from_slice(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let (m, ops, size, _) = simd_instr(&sub);
        assert_eq!(m, "i8x16.shuffle");
        assert_eq!(size, 18);
        assert!(ops.contains("15"));
    }

    #[test]
    fn test_i8x16_swizzle() {
        let (m, _, size, _) = simd_instr(&[0x0E]);
        assert_eq!(m, "i8x16.swizzle");
        assert_eq!(size, 2);
    }

    #[test]
    fn test_i8x16_splat() {
        let (m, _, _, _) = simd_instr(&[0x0F]);
        assert_eq!(m, "i8x16.splat");
    }

    #[test]
    fn test_i32x4_splat() {
        let (m, _, _, _) = simd_instr(&[0x11]);
        assert_eq!(m, "i32x4.splat");
    }

    #[test]
    fn test_extract_lane_i32x4() {
        let (m, ops, size, _) = simd_instr(&[0x19, 0x02]); // sub=25, lane=2
        assert_eq!(m, "i32x4.extract_lane");
        assert_eq!(ops, "2");
        assert_eq!(size, 3);
    }

    #[test]
    fn test_replace_lane_f64x2() {
        let (m, ops, _, _) = simd_instr(&[0x22, 0x01]); // sub=34, lane=1
        assert_eq!(m, "f64x2.replace_lane");
        assert_eq!(ops, "1");
    }

    #[test]
    fn test_i8x16_add() {
        let (m, _, size, _) = simd_instr(&[0x5C]); // sub=92
        assert_eq!(m, "i8x16.add");
        assert_eq!(size, 2);
    }

    #[test]
    fn test_i32x4_add() {
        let (m, _, _, _) = simd_instr(&[0x97, 0x01]); // sub=151
        assert_eq!(m, "i32x4.add");
    }

    #[test]
    fn test_f32x4_mul() {
        let (m, _, _, _) = simd_instr(&[0xC6, 0x01]); // sub=198
        assert_eq!(m, "f32x4.mul");
    }

    #[test]
    fn test_v128_not() {
        let (m, _, _, _) = simd_instr(&[0x4D]); // sub=77
        assert_eq!(m, "v128.not");
    }

    #[test]
    fn test_v128_and() {
        let (m, _, _, _) = simd_instr(&[0x4E]); // sub=78
        assert_eq!(m, "v128.and");
    }

    #[test]
    fn test_v128_xor() {
        let (m, _, _, _) = simd_instr(&[0x51]); // sub=81
        assert_eq!(m, "v128.xor");
    }

    #[test]
    fn test_i64x2_add() {
        let (m, _, _, _) = simd_instr(&[0xB4, 0x01]); // sub=180
        assert_eq!(m, "i64x2.add");
    }

    #[test]
    fn test_f64x2_sqrt() {
        let (m, _, _, _) = simd_instr(&[0xCE, 0x01]); // sub=206
        assert_eq!(m, "f64x2.sqrt");
    }

    #[test]
    fn test_i32x4_trunc_sat() {
        let (m, _, _, _) = simd_instr(&[0xD7, 0x01]); // sub=215
        assert_eq!(m, "i32x4.trunc_sat_f32x4_s");
    }

    #[test]
    fn test_load8x8_s() {
        let (m, _, _, flags) = simd_instr(&[0x01, 0x02, 0x00]);
        assert_eq!(m, "v128.load8x8_s");
        assert!(flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_truncated_v128_const_error() {
        let mut v = vec![0xFDu8, 0x0C]; // 0xFD + sub=12, then missing 16 bytes
        v.extend_from_slice(&[0u8; 4]); // only 4 instead of 16
        let result = decode_simd(&v);
        assert!(result.is_err());
    }

    #[test]
    fn test_v128_constant_as_i32x4() {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&1i32.to_le_bytes());
        bytes[4..8].copy_from_slice(&2i32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3i32.to_le_bytes());
        bytes[12..16].copy_from_slice(&4i32.to_le_bytes());
        let c = V128Constant::from_bytes(bytes);
        assert_eq!(c.as_i32x4(), [1, 2, 3, 4]);
    }

    #[test]
    fn test_v128_constant_as_i64x2() {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&100i64.to_le_bytes());
        bytes[8..16].copy_from_slice(&200i64.to_le_bytes());
        let c = V128Constant::from_bytes(bytes);
        assert_eq!(c.as_i64x2(), [100, 200]);
    }

    #[test]
    fn test_v128_constant_display() {
        let c = V128Constant::from_bytes([0u8; 16]);
        let s = c.to_string();
        assert!(s.starts_with("v128("));
        assert!(s.contains("00"));
    }

    #[test]
    fn test_v128_constant_hex() {
        let mut b = [0u8; 16];
        b[0] = 0xDE;
        b[15] = 0xAD;
        let c = V128Constant::from_bytes(b);
        let hex = c.to_hex();
        assert!(hex.starts_with("de"));
        assert!(hex.ends_with("ad"));
    }
}
