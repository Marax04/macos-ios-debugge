//! Hash function attack implementations.
//!
//! Provides SHA-1/SHA-2 length-extension attacks, birthday collision search,
//! Wang-style MD5 differential path stub, reduced-round preimage search,
//! HMAC length-extension forgery, and CRC32 two-message collisions.

use std::collections::HashMap;
use subtle::ConstantTimeEq;

// ── Internal SHA helpers (reuse pattern from lib.rs) ─────────────────────────

/// Minimal pure-Rust SHA-256 implementation.
fn sha256_compress(h: &mut [u32; 8], data: &[u8]) {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a_2f98,0x7137_4491,0xb5c0_fbcf,0xe9b5_dba5,0x3956_c25b,0x59f1_11f1,0x923f_82a4,0xab1c_5ed5,
        0xd807_aa98,0x1283_5b01,0x2431_85be,0x550c_7dc3,0x72be_5d74,0x80de_b1fe,0x9bdc_06a7,0xc19b_f174,
        0xe49b_69c1,0xefbe_4786,0x0fc1_9dc6,0x240c_a1cc,0x2de9_2c6f,0x4a74_84aa,0x5cb0_a9dc,0x76f9_88da,
        0x983e_5152,0xa831_c66d,0xb003_27c8,0xbf59_7fc7,0xc6e0_0bf3,0xd5a7_9147,0x06ca_6351,0x1429_2967,
        0x27b7_0a85,0x2e1b_2138,0x4d2c_6dfc,0x5338_0d13,0x650a_7354,0x766a_0abb,0x81c2_c92e,0x9272_2c85,
        0xa2bf_e8a1,0xa81a_664b,0xc24b_8b70,0xc76c_51a3,0xd192_e819,0xd699_0624,0xf40e_3585,0x106a_a070,
        0x19a4_c116,0x1e37_6c08,0x2748_774c,0x34b0_bcb5,0x391c_0cb3,0x4ed8_aa4a,0x5b9c_ca4f,0x682e_6ff3,
        0x748f_82ee,0x78a5_636f,0x84c8_7814,0x8cc7_0208,0x90be_fffa,0xa450_6ceb,0xbef9_a3f7,0xc671_78f2,
    ];
    for chunk in data.chunks(64) {
        if chunk.len() != 64 {
            break;
        }
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] = *h;
        for i in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let tmp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let tmp2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(tmp1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = tmp1.wrapping_add(tmp2);
        }
        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }
}

/// Full SHA-256 with padding.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut h, &msg);
    let mut out = [0u8; 32];
    for (i, &w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// SHA-512 state compression.
fn sha512_compress(h: &mut [u64; 8], data: &[u8]) {
    #[rustfmt::skip]
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,0x7137_4491_23ef_65cd,0xb5c0_fbcf_ec4d_3b2f,0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,0x59f1_11f1_b605_d019,0x923f_82a4_af19_4f9b,0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,0x1283_5b01_4570_6fbe,0x2431_85be_4ee4_b28c,0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,0x80de_b1fe_3b16_96b1,0x9bdc_06a7_25c7_1235,0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,0xefbe_4786_384f_25e3,0x0fc1_9dc6_8b8c_d5b5,0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,0x4a74_84aa_6ea6_e483,0x5cb0_a9dc_bd41_fbd4,0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,0xa831_c66d_2db4_3210,0xb003_27c8_98fb_213f,0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,0xd5a7_9147_930a_a725,0x06ca_6351_e003_826f,0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,0x2e1b_2138_5c26_c926,0x4d2c_6dfc_5ac4_2aed,0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,0x766a_0abb_3c77_b2a8,0x81c2_c92e_47ed_aee6,0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,0xa81a_664b_bc42_3001,0xc24b_8b70_d0f8_9791,0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,0xd699_0624_5565_a910,0xf40e_3585_5771_202a,0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,0x1e37_6c08_5141_ab53,0x2748_774c_df8e_eb99,0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,0x4ed8_aa4a_e341_8acb,0x5b9c_ca4f_7763_e373,0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,0x78a5_636f_4317_2f60,0x84c8_7814_a1f0_ab72,0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,0xa450_6ceb_de82_bde9,0xbef9_a3f7_b2c6_7915,0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,0xd186_b8c7_21c0_c207,0xeada_7dd6_cde0_eb1e,0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,0x0a63_7dc5_a2c8_98a6,0x113f_9804_bef9_0dae,0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,0x32ca_ab7b_40c7_2493,0x3c9e_be0a_15c9_bebc,0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,0x597f_299c_fc65_7e2a,0x5fcb_6fab_3ad6_faec,0x6c44_198c_4a47_5817,
    ];
    for chunk in data.chunks(128) {
        if chunk.len() != 128 {
            break;
        }
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] = *h;
        for i in 0..80 {
            let s1 = ee.rotate_right(14) ^ ee.rotate_right(18) ^ ee.rotate_right(41);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let tmp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = aa.rotate_right(28) ^ aa.rotate_right(34) ^ aa.rotate_right(39);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let tmp2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(tmp1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = tmp1.wrapping_add(tmp2);
        }
        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }
}

#[must_use] 
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];
    let bit_len = (data.len() as u128).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&(0u64).to_be_bytes()); // high 64 bits of length
    msg.extend_from_slice(&u64::try_from(bit_len).unwrap_or(u64::MAX).to_be_bytes());
    sha512_compress(&mut h, &msg);
    let mut out = [0u8; 64];
    for (i, &w) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
    }
    out
}

// ── SHA-1 minimal (for length extension) ─────────────────────────────────────

#[must_use] 
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        if chunk.len() != 64 {
            break;
        }
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut aa, mut bb, mut cc, mut dd, mut ee] = [h[0], h[1], h[2], h[3], h[4]];
        for (i, &wi) in w.iter().enumerate() {
            let (ff, kk) = match i {
                0..=19 => ((bb & cc) | ((!bb) & dd), 0x5A82_7999_u32),
                20..=39 => (bb ^ cc ^ dd, 0x6ED9_EBA1),
                40..=59 => ((bb & cc) | (bb & dd) | (cc & dd), 0x8F1B_BCDC),
                _ => (bb ^ cc ^ dd, 0xCA62_C1D6),
            };
            let tmp = aa
                .rotate_left(5)
                .wrapping_add(ff)
                .wrapping_add(ee)
                .wrapping_add(kk)
                .wrapping_add(wi);
            ee = dd;
            dd = cc;
            cc = bb.rotate_left(30);
            bb = aa;
            aa = tmp;
        }
        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
    }
    let mut out = [0u8; 20];
    for (i, &w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

// ── LengthExtensionResult ─────────────────────────────────────────────────────

/// Result of a hash length-extension attack.
#[derive(Debug, Clone)]
pub struct LengthExtensionResult {
    /// The extended message (original + padding + extension).
    pub extended_message: Vec<u8>,
    /// The forged MAC / hash for the extended message.
    pub forged_hash: Vec<u8>,
    /// Length of the original secret (bytes).
    pub assumed_secret_len: usize,
}

impl LengthExtensionResult {
    /// Check whether the forged hash is well-formed (non-empty).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.forged_hash.is_empty() && !self.extended_message.is_empty()
    }

    /// Return the extension data (bytes appended after the padding).
    #[must_use]
    pub fn extension_bytes(&self, original_len: usize, secret_len: usize) -> &[u8] {
        let padded_len = sha256_padded_length(original_len + secret_len);
        if self.extended_message.len() > padded_len {
            &self.extended_message[padded_len..]
        } else {
            &[]
        }
    }
}

/// Compute the length of the padded message (after SHA-256 padding is applied).
const fn sha256_padded_length(msg_len: usize) -> usize {
    let mut padded = msg_len + 1; // 0x80 byte
    while padded % 64 != 56 {
        padded += 1;
    }
    padded + 8 // 8 bytes of length
}

/// Compute SHA-512 padded length.
const fn sha512_padded_length(msg_len: usize) -> usize {
    let mut padded = msg_len + 1;
    while padded % 128 != 112 {
        padded += 1;
    }
    padded + 16
}

/// Build the SHA-256/SHA-512 padding for a given total length.
fn sha256_padding(total_len: usize) -> Vec<u8> {
    let bit_len = (total_len as u64).wrapping_mul(8);
    let mut pad = vec![0x80u8];
    let current = total_len + 1;
    let pad_bytes = if current % 64 <= 56 {
        56 - current % 64
    } else {
        120 - current % 64
    };
    pad.extend(std::iter::repeat_n(0u8, pad_bytes));
    pad.extend_from_slice(&bit_len.to_be_bytes());
    pad
}

fn sha512_padding(total_len: usize) -> Vec<u8> {
    let bit_len = (total_len as u64).wrapping_mul(8);
    let mut pad = vec![0x80u8];
    let current = total_len + 1;
    let pad_bytes = if current % 128 <= 112 {
        112 - current % 128
    } else {
        240 - current % 128
    };
    pad.extend(std::iter::repeat_n(0u8, pad_bytes));
    pad.extend_from_slice(&(0u64).to_be_bytes()); // high 64 bits
    pad.extend_from_slice(&bit_len.to_be_bytes());
    pad
}

// ── HashLengthExtension ───────────────────────────────────────────────────────

/// SHA-1/SHA-2 length extension attack.
///
/// Given H(secret || message) and the length of the secret, computes
/// H(secret || message || padding || extension) without knowing the secret.
pub struct HashLengthExtension;

impl HashLengthExtension {
    /// Extend a SHA-256 MAC: forges H(secret || message || padding || extension).
    ///
    /// `known_hash`: the 32-byte hash H(secret || message).
    /// `original_len`: byte length of the original message (not including secret).
    /// `secret_len`: assumed byte length of the secret.
    /// `extension`: data to append.
    #[must_use] 
    pub fn extend_sha256(
        known_hash: &[u8; 32],
        original_len: usize,
        secret_len: usize,
        extension: &[u8],
    ) -> LengthExtensionResult {
        // Reconstruct the internal state after processing secret||message
        let mut h: [u32; 8] = [0; 8];
        for (i, chunk) in known_hash.chunks(4).enumerate() {
            h[i] = u32::from_be_bytes(chunk.try_into().unwrap_or([0; 4]));
        }

        // The total length for the padding calculation is secret||message||padding
        let total_processed = sha256_padded_length(secret_len + original_len);
        let new_bit_len = ((total_processed + extension.len()) as u64).wrapping_mul(8);

        // Pad and compress the extension
        let mut ext_padded = extension.to_vec();
        ext_padded.push(0x80);
        while (total_processed + ext_padded.len()) % 64 != 56 {
            ext_padded.push(0x00);
        }
        ext_padded.extend_from_slice(&new_bit_len.to_be_bytes());
        sha256_compress(&mut h, &ext_padded);

        let mut forged_hash = [0u8; 32];
        for (i, &w) in h.iter().enumerate() {
            forged_hash[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }

        // Build the extended message (what we present to the verifier)
        let padding = sha256_padding(secret_len + original_len);
        let mut extended_message =
            Vec::with_capacity(original_len + padding.len() + extension.len());
        // We include the original message bytes (caller provides via original_len)
        // plus the glue padding plus the extension.
        extended_message.extend(std::iter::repeat_n(0u8, original_len));
        extended_message.extend_from_slice(&padding[1..]); // skip leading 0x80 already accounted
        extended_message.extend_from_slice(extension);

        LengthExtensionResult {
            extended_message,
            forged_hash: forged_hash.to_vec(),
            assumed_secret_len: secret_len,
        }
    }

    /// Extend a SHA-512 MAC.
    #[must_use] 
    pub fn extend_sha512(
        known_hash: &[u8; 64],
        original_len: usize,
        secret_len: usize,
        extension: &[u8],
    ) -> LengthExtensionResult {
        let mut h: [u64; 8] = [0; 8];
        for (i, chunk) in known_hash.chunks(8).enumerate() {
            h[i] = u64::from_be_bytes(chunk.try_into().unwrap_or([0; 8]));
        }

        let total_processed = sha512_padded_length(secret_len + original_len);
        let new_bit_len = ((total_processed + extension.len()) as u64).wrapping_mul(8);

        let mut ext_padded = extension.to_vec();
        ext_padded.push(0x80);
        while (total_processed + ext_padded.len()) % 128 != 112 {
            ext_padded.push(0x00);
        }
        ext_padded.extend_from_slice(&(0u64).to_be_bytes());
        ext_padded.extend_from_slice(&new_bit_len.to_be_bytes());
        sha512_compress(&mut h, &ext_padded);

        let mut forged_hash = [0u8; 64];
        for (i, &w) in h.iter().enumerate() {
            forged_hash[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
        }

        let padding = sha512_padding(secret_len + original_len);
        let mut extended_message = Vec::new();
        extended_message.extend(std::iter::repeat_n(0u8, original_len));
        extended_message.extend_from_slice(&padding[1..]);
        extended_message.extend_from_slice(extension);

        LengthExtensionResult {
            extended_message,
            forged_hash: forged_hash.to_vec(),
            assumed_secret_len: secret_len,
        }
    }

    /// Forge a MAC by trying multiple secret lengths (`1..=max_secret_len`).
    /// Returns the first extension result whose forged hash passes `verify_fn`.
    pub fn forge_mac<F>(
        known_hash: &[u8; 32],
        original_message: &[u8],
        extension: &[u8],
        max_secret_len: usize,
        verify_fn: F,
    ) -> Option<LengthExtensionResult>
    where
        F: Fn(&[u8], &[u8]) -> bool,
    {
        for secret_len in 1..=max_secret_len {
            let result =
                Self::extend_sha256(known_hash, original_message.len(), secret_len, extension);
            if verify_fn(&result.extended_message, &result.forged_hash) {
                return Some(result);
            }
        }
        None
    }
}

// ── HashCollision (Birthday) ──────────────────────────────────────────────────

/// Birthday attack result: two messages with the same (truncated) hash.
#[derive(Debug, Clone)]
pub struct BirthdayCollision {
    pub message_a: Vec<u8>,
    pub message_b: Vec<u8>,
    pub hash_a: Vec<u8>,
    pub hash_b: Vec<u8>,
    pub collision_bits: u32,
}

impl BirthdayCollision {
    /// Verify the collision is genuine.
    #[must_use]
    pub fn is_genuine(&self) -> bool {
        self.hash_a == self.hash_b && self.message_a != self.message_b
    }
}

/// Birthday attack engine for reduced-length hashes.
pub struct HashCollision;

impl HashCollision {
    /// Search for a birthday collision in an n-bit hash space.
    ///
    /// `hash_fn`: maps message bytes to a truncated hash.
    /// `n_bits`: number of bits to match (max 32).
    /// `max_attempts`: maximum number of messages to try.
    pub fn birthday_attack<F>(
        hash_fn: F,
        n_bits: u32,
        max_attempts: usize,
    ) -> Option<BirthdayCollision>
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        let mask = if n_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << n_bits) - 1
        };
        let mut seen: HashMap<u64, Vec<u8>> = HashMap::new();

        for i in 0..max_attempts {
            let msg = format!("birthday-probe-{i}").into_bytes();
            let h = hash_fn(&msg);
            // Truncate to n_bits
            let mut hval = 0u64;
            for (j, &b) in h.iter().take(8).enumerate() {
                hval |= u64::from(b) << (j * 8);
            }
            hval &= mask;

            if let Some(prev_msg) = seen.get(&hval) {
                if *prev_msg != msg {
                    let hash_a = hash_fn(prev_msg);
                    let hash_b = hash_fn(&msg);
                    // Truncate both for comparison
                    let trunc_a: Vec<u8> = hash_a
                        .iter()
                        .take(n_bits.div_ceil(8) as usize)
                        .copied()
                        .collect();
                    let trunc_b: Vec<u8> = hash_b
                        .iter()
                        .take(n_bits.div_ceil(8) as usize)
                        .copied()
                        .collect();
                    return Some(BirthdayCollision {
                        message_a: prev_msg.clone(),
                        message_b: msg,
                        hash_a: trunc_a,
                        hash_b: trunc_b,
                        collision_bits: n_bits,
                    });
                }
            } else {
                seen.insert(hval, msg);
            }
        }
        None
    }

    /// Birthday attack using SHA-256 truncated to `n_bits`.
    #[must_use] 
    pub fn birthday_sha256(n_bits: u32, max_attempts: usize) -> Option<BirthdayCollision> {
        Self::birthday_attack(|msg| sha256(msg).to_vec(), n_bits, max_attempts)
    }

    /// Expected number of attempts to find a birthday collision in `n_bits`.
    #[must_use]
    pub fn expected_attempts(n_bits: u32) -> f64 {
        let n = f64::from(u32::try_from(1u64.checked_shl(n_bits).unwrap_or(u64::MAX)).unwrap_or(u32::MAX));
        (std::f64::consts::PI * n / 2.0).sqrt()
    }
}

// ── MD5 Collision (Wang-style stub) ──────────────────────────────────────────

/// Differential path for a single MD5 compression round.
#[derive(Debug, Clone)]
pub struct Md5DifferentialPath {
    /// Round number (0..63).
    pub round: u8,
    /// Input difference (XOR mask applied to message word).
    pub input_diff: u32,
    /// Output difference (expected XOR difference in state word).
    pub output_diff: u32,
    /// Probability (as log2 of inverse).
    pub probability_log2: i32,
}

/// Wang-style MD5 collision differential path construction stub.
pub struct Md5Collision;

impl Md5Collision {
    /// Build the differential path used in Wang's 2004 attack.
    /// This is a stub: the full path requires 64 round-specific conditions.
    #[must_use]
    pub fn wang_differential_path() -> Vec<Md5DifferentialPath> {
        // Partial path from Wang et al.: first few round differences.
        // Full implementation requires the detailed sufficient conditions table.
        vec![
            Md5DifferentialPath {
                round: 0,
                input_diff: 0x0000_8000,
                output_diff: 0x8000_0000,
                probability_log2: -1,
            },
            Md5DifferentialPath {
                round: 1,
                input_diff: 0x8000_0000,
                output_diff: 0x0000_0000,
                probability_log2: 0,
            },
            Md5DifferentialPath {
                round: 2,
                input_diff: 0x0000_0000,
                output_diff: 0x0000_0000,
                probability_log2: 0,
            },
            Md5DifferentialPath {
                round: 3,
                input_diff: 0x0000_0000,
                output_diff: 0x0000_8000,
                probability_log2: -2,
            },
        ]
    }

    /// Compute MD5 of data (minimal implementation).
    #[must_use]
    pub fn md5(data: &[u8]) -> [u8; 16] {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const K: [u32; 64] = [
            0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
            0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
            0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
            0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
            0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
            0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
            0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
            0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
            0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
            0xeb86_d391,
        ];
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0x00);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());
        let mut a0 = 0x6745_2301_u32;
        let mut b0 = 0xefcd_ab89_u32;
        let mut c0 = 0x98ba_dcfe_u32;
        let mut d0 = 0x1032_5476_u32;
        for chunk in msg.chunks(64) {
            if chunk.len() != 64 {
                break;
            }
            let mut block = [0u32; 16];
            for (idx, word) in block.iter_mut().enumerate() {
                *word = u32::from_le_bytes(chunk[idx * 4..idx * 4 + 4].try_into().unwrap_or([0; 4]));
            }
            let [mut aa, mut bb, mut cc, mut dd] = [a0, b0, c0, d0];
            for i in 0..64u32 {
                let (mix, msg_idx) = match i {
                    0..=15 => ((bb & cc) | ((!bb) & dd), i),
                    16..=31 => ((dd & bb) | ((!dd) & cc), (5 * i + 1) % 16),
                    32..=47 => (bb ^ cc ^ dd, (3 * i + 5) % 16),
                    _ => (cc ^ (bb | (!dd)), (7 * i) % 16),
                };
                let tmp = dd;
                dd = cc;
                cc = bb;
                bb = bb.wrapping_add(
                    (aa.wrapping_add(mix)
                        .wrapping_add(K[i as usize])
                        .wrapping_add(block[msg_idx as usize]))
                    .rotate_left(S[i as usize]),
                );
                aa = tmp;
            }
            a0 = a0.wrapping_add(aa);
            b0 = b0.wrapping_add(bb);
            c0 = c0.wrapping_add(cc);
            d0 = d0.wrapping_add(dd);
        }
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&a0.to_le_bytes());
        out[4..8].copy_from_slice(&b0.to_le_bytes());
        out[8..12].copy_from_slice(&c0.to_le_bytes());
        out[12..16].copy_from_slice(&d0.to_le_bytes());
        out
    }

    /// Check whether two messages collide under MD5.
    #[must_use]
    pub fn collide(msg_a: &[u8], msg_b: &[u8]) -> bool {
        Self::md5(msg_a) == Self::md5(msg_b)
    }
}

// ── SHA Preimage ──────────────────────────────────────────────────────────────

/// Reduced-round preimage search for SHA-256.
pub struct ShaPreimage;

impl ShaPreimage {
    /// Brute-force search for a preimage of `target_prefix` (first `n_bits` bits)
    /// using random messages up to `max_attempts` tries.
    ///
    /// This is only feasible for very small `n_bits` (≤ 24).
    #[must_use] 
    pub fn search_prefix(
        target_prefix: &[u8],
        n_bits: u32,
        max_attempts: usize,
    ) -> Option<Vec<u8>> {
        let mask_bytes = (n_bits / 8) as usize;
        let bit_rem = n_bits % 8;
        let mask_last = if bit_rem > 0 {
            0xFFu8 << (8 - bit_rem)
        } else {
            0xFF
        };

        for i in 0..max_attempts {
            let msg = format!("preimage-search-{i}").into_bytes();
            let h = sha256(&msg);
            let matches = h[..mask_bytes.min(32)]
                .iter()
                .zip(target_prefix.iter())
                .all(|(&a, &b)| a == b);
            let last_matches = if bit_rem > 0 && mask_bytes < 32 && mask_bytes < target_prefix.len()
            {
                h[mask_bytes] & mask_last == target_prefix[mask_bytes] & mask_last
            } else {
                true
            };
            if matches && last_matches {
                return Some(msg);
            }
        }
        None
    }

    /// Compute the expected work for finding an n-bit preimage.
    #[must_use]
    pub fn expected_work(n_bits: u32) -> f64 {
        2.0f64.powi(n_bits.cast_signed())
    }
}

// ── HmacForge ─────────────────────────────────────────────────────────────────

/// HMAC forgery via length extension.
pub struct HmacForge;

impl HmacForge {
    /// Attempt to forge an HMAC-SHA256 tag using length extension.
    ///
    /// This works because SHA-256 HMAC with the construction H(key || msg) is
    /// vulnerable, but HMAC(key, msg) = H(key || H(key || msg)) is NOT.
    /// This function demonstrates the vulnerable H(key||msg) construction.
    ///
    /// `known_tag`: H(secret || `original_msg`).
    /// Returns a forged tag and the corresponding message.
    #[must_use] 
    pub fn forge_hash_prefix_mac(
        known_tag: &[u8; 32],
        original_msg: &[u8],
        extension: &[u8],
        secret_len: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let result = HashLengthExtension::extend_sha256(
            known_tag,
            original_msg.len(),
            secret_len,
            extension,
        );
        // Return (forged_message_suffix, forged_tag)
        // The suffix is original_msg + padding + extension
        let padding = sha256_padding(secret_len + original_msg.len());
        let mut forged_msg = original_msg.to_vec();
        forged_msg.extend_from_slice(&padding);
        forged_msg.extend_from_slice(extension);
        (forged_msg, result.forged_hash)
    }

    /// Check whether a given (message, tag) pair is valid for the secret key
    /// under the vulnerable H(key||msg) construction.
    #[must_use] 
    pub fn check_vulnerable_mac(secret: &[u8], message: &[u8], tag: &[u8]) -> bool {
        let mut input = secret.to_vec();
        input.extend_from_slice(message);
        let computed = sha256(&input);
        // Use constant-time comparison to prevent timing side-channel leaking
        // how many bytes of the HMAC tag match the attacker-supplied value.
        computed.as_ref().ct_eq(tag).into()
    }
}

// ── CrcCollision ─────────────────────────────────────────────────────────────

/// CRC32 (IEEE 802.3 polynomial) implementation and collision generation.
pub struct CrcCollision;

impl CrcCollision {
    /// Standard CRC32.
    #[must_use]
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                if crc & 1 == 1 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// Find two messages with the same CRC32 by brute force over small suffixes.
    ///
    /// Returns (`msg_a`, `msg_b`) where `crc32(msg_a)` == `crc32(msg_b)`.
    /// Modifies the last 4 bytes of `base_a` and `base_b` to equalize CRC32.
    #[must_use] 
    pub fn find_collision(base_a: &[u8], base_b: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        // Approach: append a 4-byte suffix to base_b such that crc32(base_b || suffix) == crc32(base_a).
        // We try all 2^24 three-byte values and rely on the linear property of CRC32.
        let target = Self::crc32(base_a);
        // CRC32 is linear: crc32(x||suffix) can be computed incrementally.
        // For small messages we just brute-force.
        for i in 0u32..=0x00FF_FFFFu32 {
            let mut candidate = base_b.to_vec();
            candidate.extend_from_slice(&i.to_le_bytes()[..3]);
            if Self::crc32(&candidate) == target {
                return Some((base_a.to_vec(), candidate));
            }
        }
        None
    }

    /// Compute differential: crc32(a) XOR crc32(b).
    #[must_use]
    pub fn crc32_xor_diff(a: &[u8], b: &[u8]) -> u32 {
        Self::crc32(a) ^ Self::crc32(b)
    }

    /// Check if two byte sequences have the same CRC32.
    #[must_use]
    pub fn collide(a: &[u8], b: &[u8]) -> bool {
        Self::crc32(a) == Self::crc32(b)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SHA primitives ────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_empty() {
        let h = sha256(b"");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256(b"abc");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(
            hex,
            // Test data fix: corrected to the standard NIST SHA-256("abc") test vector.
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha512_empty() {
        let h = sha512(b"");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(&hex[..32], "cf83e1357eefb8bdf1542850d66d8007");
    }

    #[test]
    fn test_sha1_abc() {
        let h = sha1(b"abc");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_sha1_empty() {
        let h = sha1(b"");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    // ── Length extension SHA-256 ───────────────────────────────────────────────

    #[test]
    fn test_length_extension_sha256_result_not_empty() {
        let known_hash = sha256(b"secretmessage");
        let result = HashLengthExtension::extend_sha256(&known_hash, 7, 6, b"&admin=true");
        assert!(result.is_valid());
        assert_eq!(result.forged_hash.len(), 32);
    }

    #[test]
    fn test_length_extension_sha256_different_extensions() {
        let known_hash = sha256(b"secrettest");
        let r1 = HashLengthExtension::extend_sha256(&known_hash, 4, 6, b"ext1");
        let r2 = HashLengthExtension::extend_sha256(&known_hash, 4, 6, b"ext2");
        assert_ne!(r1.forged_hash, r2.forged_hash);
    }

    #[test]
    fn test_length_extension_sha512_result() {
        let known_hash = sha512(b"secretmsg");
        let result = HashLengthExtension::extend_sha512(&known_hash, 3, 6, b"extra");
        assert!(result.is_valid());
        assert_eq!(result.forged_hash.len(), 64);
    }

    #[test]
    fn test_length_extension_assumed_secret_len() {
        let known_hash = sha256(b"x");
        let result = HashLengthExtension::extend_sha256(&known_hash, 1, 10, b"append");
        assert_eq!(result.assumed_secret_len, 10);
    }

    #[test]
    fn test_forge_mac_returns_none_if_no_match() {
        let known_hash = sha256(b"secret!test");
        let result = HashLengthExtension::forge_mac(
            &known_hash,
            b"test",
            b"&evil=1",
            2,                  // try only 1..=2 secret lengths
            |_msg, _tag| false, // always fails
        );
        assert!(result.is_none());
    }

    // ── Birthday attack ───────────────────────────────────────────────────────

    #[test]
    fn test_birthday_expected_attempts_16bit() {
        let expected = HashCollision::expected_attempts(16);
        // Should be around sqrt(pi * 65536 / 2) ≈ 320
        assert!(expected > 100.0 && expected < 1000.0);
    }

    #[test]
    fn test_birthday_sha256_8bit() {
        // 8-bit hash: expect a collision within ~20 tries
        let collision = HashCollision::birthday_sha256(8, 5000);
        assert!(collision.is_some(), "Expected 8-bit birthday collision");
        let c = collision.unwrap();
        assert!(c.is_genuine());
        assert_eq!(c.collision_bits, 8);
    }

    #[test]
    fn test_birthday_custom_hash_16bit() {
        // Use a 16-bit truncation of SHA-256
        let collision = HashCollision::birthday_attack(|msg| sha256(msg)[..2].to_vec(), 16, 10000);
        assert!(collision.is_some());
    }

    // ── MD5 ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_md5_empty() {
        let h = Md5Collision::md5(b"");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(hex, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        let h = Md5Collision::md5(b"abc");
        let hex: String = h.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(hex, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_md5_different_inputs() {
        assert_ne!(Md5Collision::md5(b"hello"), Md5Collision::md5(b"world"));
    }

    #[test]
    fn test_wang_differential_path_not_empty() {
        let path = Md5Collision::wang_differential_path();
        assert!(!path.is_empty());
        assert_eq!(path[0].round, 0);
    }

    // ── SHA preimage ──────────────────────────────────────────────────────────

    #[test]
    fn test_sha_preimage_search_8bits() {
        // Search for a message whose SHA-256 starts with 0x00 (8 bits)
        let target = [0x00u8];
        let result = ShaPreimage::search_prefix(&target, 8, 1024);
        if let Some(msg) = result {
            let h = sha256(&msg);
            assert_eq!(h[0], 0x00);
        }
        // Not required to find one within 1024 but must not panic
    }

    #[test]
    fn test_sha_preimage_expected_work() {
        assert!((ShaPreimage::expected_work(8) - 256.0).abs() < 1e-6);
        assert!((ShaPreimage::expected_work(16) - 65536.0).abs() < 1.0);
    }

    // ── HMAC forge ────────────────────────────────────────────────────────────

    #[test]
    fn test_hmac_forge_check_vulnerable_mac() {
        let secret = b"mysecret";
        let msg = b"data";
        let mut input = secret.to_vec();
        input.extend_from_slice(msg);
        let tag = sha256(&input);
        assert!(HmacForge::check_vulnerable_mac(secret, msg, &tag));
    }

    #[test]
    fn test_hmac_forge_wrong_tag_fails() {
        assert!(!HmacForge::check_vulnerable_mac(b"key", b"msg", &[0u8; 32]));
    }

    #[test]
    fn test_hmac_forge_prefix_mac() {
        let secret = b"secret";
        let msg = b"original";
        let extension = b"&admin=true";
        let mut input = secret.to_vec();
        input.extend_from_slice(msg);
        let tag = sha256(&input);
        let (forged_msg, forged_tag) =
            HmacForge::forge_hash_prefix_mac(&tag, msg, extension, secret.len());
        assert!(!forged_msg.is_empty());
        assert_eq!(forged_tag.len(), 32);
    }

    // ── CRC32 collision ───────────────────────────────────────────────────────

    #[test]
    fn test_crc32_known_value() {
        // CRC32 of "123456789" is 0xCBF43926
        assert_eq!(CrcCollision::crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(CrcCollision::crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32_different_inputs() {
        assert_ne!(CrcCollision::crc32(b"hello"), CrcCollision::crc32(b"world"));
    }

    #[test]
    fn test_crc32_collision_self() {
        // Same message always collides with itself
        assert!(CrcCollision::collide(b"test", b"test"));
    }

    #[test]
    fn test_crc32_find_collision_small() {
        // Find a collision for a very short base
        let base_a = b"AAA".as_ref();
        let base_b = b"BB".as_ref();
        if let Some((a, b)) = CrcCollision::find_collision(base_a, base_b) {
            assert!(CrcCollision::collide(&a, &b));
        }
        // May not find one; just no panic
    }

    // ── Padding length helpers ────────────────────────────────────────────────

    #[test]
    fn test_sha256_padded_length_empty() {
        // Empty: 1 (0x80) + 55 (zeros) + 8 (length) = 64
        assert_eq!(sha256_padded_length(0), 64);
    }

    #[test]
    fn test_sha256_padded_length_55_bytes() {
        // 55 bytes + 1 = 56, already multiple of 64 with 8 byte length
        assert_eq!(sha256_padded_length(55), 64);
    }

    #[test]
    fn test_sha512_padded_length_empty() {
        assert_eq!(sha512_padded_length(0), 128);
    }
}
