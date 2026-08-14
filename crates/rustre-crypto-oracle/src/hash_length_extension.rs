// rustre-crypto-oracle/src/hash_length_extension.rs
// Hash length extension attack for MD5, SHA-1, and SHA-256 (Merkle-Damgård construction).

/// Supported hash algorithms for length extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    #[must_use]
    pub const fn output_size(self) -> usize {
        match self { Self::Md5 => 16, Self::Sha1 => 20, Self::Sha256 => 32 }
    }

    #[must_use]
    pub const fn block_size(self) -> usize {
        64 // MD5, SHA-1, and SHA-256 all use 512-bit (64-byte) blocks
    }
}

/// Result of a length extension attack.
#[derive(Debug, Clone)]
pub struct ExtensionResult {
    /// The extended message (`original_message` || padding || extension).
    pub extended_message: Vec<u8>,
    /// The forged MAC valid for the extended message.
    pub forged_mac: Vec<u8>,
    /// The padding appended after the original message.
    pub padding: Vec<u8>,
}

/// Length extension attacker.
pub struct LengthExtensionAttacker {
    pub algorithm: HashAlgorithm,
}

impl LengthExtensionAttacker {
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm) -> Self { Self { algorithm } }

    /// Forge a MAC for `secret || original_message || extension` given:
    /// - `original_message`: the known message.
    /// - `original_mac`: `MAC(secret || original_message)` = `H(secret || original_message)`.
    /// - `secret_len`: length of the secret key in bytes.
    /// - `extension`: bytes to append.
    ///
    /// Returns (`extended_message`, `forged_mac`) where:
    ///   `forged_mac` = `H(secret || extended_message)`
    #[must_use]
    pub fn attack(
        &self,
        original_message: &[u8],
        original_mac: &[u8],
        secret_len: usize,
        extension: &[u8],
    ) -> ExtensionResult {
        // Compute the padding that was appended to (secret || original_message).
        let inner_len = secret_len + original_message.len();
        let padding = md_padding(inner_len, self.algorithm);

        // The extended message from the attacker's perspective (without the secret).
        let mut extended_message = original_message.to_vec();
        extended_message.extend_from_slice(&padding);
        extended_message.extend_from_slice(extension);

        // Forge the MAC by continuing the hash from the known state.
        // The "total length" processed so far = secret_len + original_message.len() + padding.len().
        let state_len = secret_len + original_message.len() + padding.len();

        let forged_mac = match self.algorithm {
            HashAlgorithm::Md5 => Self::extend_md5(original_mac, extension, state_len),
            HashAlgorithm::Sha1 => Self::extend_sha1(original_mac, extension, state_len),
            HashAlgorithm::Sha256 => Self::extend_sha256(original_mac, extension, state_len),
        };

        ExtensionResult { extended_message, forged_mac, padding }
    }

    fn extend_md5(mac: &[u8], extension: &[u8], state_len: usize) -> Vec<u8> {
        // Load internal state from the known MAC (MD5 uses little-endian 32-bit words).
        let mut state = [0u32; 4];
        for i in 0..4 {
            state[i] = u32::from_le_bytes(mac[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        md5_continue(state, extension, state_len)
    }

    fn extend_sha1(mac: &[u8], extension: &[u8], state_len: usize) -> Vec<u8> {
        // SHA-1 uses big-endian 32-bit words.
        let mut state = [0u32; 5];
        for i in 0..5 {
            state[i] = u32::from_be_bytes(mac[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        sha1_continue(state, extension, state_len)
    }

    fn extend_sha256(mac: &[u8], extension: &[u8], state_len: usize) -> Vec<u8> {
        // SHA-256 uses big-endian 32-bit words.
        let mut state = [0u32; 8];
        for i in 0..8 {
            state[i] = u32::from_be_bytes(mac[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        sha256_continue(state, extension, state_len)
    }
}

/// Compute the Merkle-Damgård padding for a message of length `msg_len`.
/// Appends 0x80, then zeros, then the 64-bit big-endian bit count.
#[must_use]
pub fn md_padding(msg_len: usize, algo: HashAlgorithm) -> Vec<u8> {
    let block = algo.block_size();
    // Saturate rather than wrap: a 2^61-byte message is already pathological.
    let bit_len = u64::try_from(msg_len).unwrap_or(u64::MAX).saturating_mul(8);
    let mut pad = vec![0x80u8];
    let current_len = msg_len + 1;
    let zeros = (block - ((current_len + 8) % block)) % block;
    pad.extend(std::iter::repeat_n(0u8, zeros));
    match algo {
        HashAlgorithm::Md5 => pad.extend_from_slice(&bit_len.to_le_bytes()),
        HashAlgorithm::Sha1 | HashAlgorithm::Sha256 => pad.extend_from_slice(&bit_len.to_be_bytes()),
    }
    pad
}

// ─── MD5 ────────────────────────────────────────────────────────────────────

fn md5_continue(state: [u32; 4], extension: &[u8], processed_len: usize) -> Vec<u8> {
    // Pad and process the extension blocks, starting from the given state.
    let padding = md_padding(processed_len + extension.len(), HashAlgorithm::Md5);
    let mut data = extension.to_vec();
    data.extend_from_slice(&padding);

    let mut ha = state[0]; let mut hb = state[1];
    let mut hc = state[2]; let mut hd = state[3];

    for chunk in data.chunks(64) {
        if chunk.len() < 64 { break; }
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        md5_block(&mut ha, &mut hb, &mut hc, &mut hd, &m);
    }

    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&ha.to_le_bytes());
    out.extend_from_slice(&hb.to_le_bytes());
    out.extend_from_slice(&hc.to_le_bytes());
    out.extend_from_slice(&hd.to_le_bytes());
    out
}

fn md5_block(wa: &mut u32, wb: &mut u32, wc: &mut u32, wd: &mut u32, m: &[u32; 16]) {
    const T: [u32; 64] = [
        0xd76a_a478,0xe8c7_b756,0x2420_70db,0xc1bd_ceee,0xf57c_0faf,0x4787_c62a,0xa830_4613,0xfd46_9501,
        0x6980_98d8,0x8b44_f7af,0xffff_5bb1,0x895c_d7be,0x6b90_1122,0xfd98_7193,0xa679_438e,0x49b4_0821,
        0xf61e_2562,0xc040_b340,0x265e_5a51,0xe9b6_c7aa,0xd62f_105d,0x0244_1453,0xd8a1_e681,0xe7d3_fbc8,
        0x21e1_cde6,0xc337_07d6,0xf4d5_0d87,0x455a_14ed,0xa9e3_e905,0xfcef_a3f8,0x676f_02d9,0x8d2a_4c8a,
        0xfffa_3942,0x8771_f681,0x6d9d_6122,0xfde5_380c,0xa4be_ea44,0x4bde_cfa9,0xf6bb_4b60,0xbebf_bc70,
        0x289b_7ec6,0xeaa1_27fa,0xd4ef_3085,0x0488_1d05,0xd9d4_d039,0xe6db_99e5,0x1fa2_7cf8,0xc4ac_5665,
        0xf429_2244,0x432a_ff97,0xab94_23a7,0xfc93_a039,0x655b_59c3,0x8f0c_cc92,0xffef_f47d,0x8584_5dd1,
        0x6fa8_7e4f,0xfe2c_e6e0,0xa301_4314,0x4e08_11a1,0xf753_7e82,0xbd3a_f235,0x2ad7_d2bb,0xeb86_d391,
    ];
    const S: [[u32; 4]; 4] = [
        [7,12,17,22], [5,9,14,20], [4,11,16,23], [6,10,15,21],
    ];

    let (mut aa, mut bb, mut cc, mut dd) = (*wa, *wb, *wc, *wd);

    for i in 0usize..64 {
        let (mix, g): (u32, usize) = match i / 16 {
            0 => ((bb & cc) | (!bb & dd), i),
            1 => ((dd & bb) | (!dd & cc), (5 * i + 1) % 16),
            2 => (bb ^ cc ^ dd, (3 * i + 5) % 16),
            _ => (cc ^ (bb | !dd), (7 * i) % 16),
        };
        let temp = dd;
        dd = cc;
        cc = bb;
        let shift = S[i / 16][i % 4];
        bb = bb.wrapping_add((aa.wrapping_add(mix).wrapping_add(T[i]).wrapping_add(m[g])).rotate_left(shift));
        aa = temp;
    }

    *wa = wa.wrapping_add(aa);
    *wb = wb.wrapping_add(bb);
    *wc = wc.wrapping_add(cc);
    *wd = wd.wrapping_add(dd);
}

// ─── SHA-1 ──────────────────────────────────────────────────────────────────

fn sha1_continue(state: [u32; 5], extension: &[u8], processed_len: usize) -> Vec<u8> {
    let padding = md_padding(processed_len + extension.len(), HashAlgorithm::Sha1);
    let mut data = extension.to_vec();
    data.extend_from_slice(&padding);

    let [mut h0, mut h1, mut h2, mut h3, mut h4] = state;

    for chunk in data.chunks(64) {
        if chunk.len() < 64 { break; }
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let (mut sa, mut sb, mut sc, mut sd, mut se) = (h0, h1, h2, h3, h4);

        for (i, &wi) in w.iter().enumerate() {
            let (mix, kk): (u32, u32) = match i {
                0..=19  => ((sb & sc) | (!sb & sd), 0x5a82_7999_u32),
                20..=39 => (sb ^ sc ^ sd, 0x6ed9_eba1),
                40..=59 => ((sb & sc) | (sb & sd) | (sc & sd), 0x8f1b_bcdc),
                _       => (sb ^ sc ^ sd, 0xca62_c1d6),
            };
            let temp = sa.rotate_left(5).wrapping_add(mix).wrapping_add(se).wrapping_add(kk).wrapping_add(wi);
            se = sd; sd = sc; sc = sb.rotate_left(30); sb = sa; sa = temp;
        }

        h0 = h0.wrapping_add(sa); h1 = h1.wrapping_add(sb);
        h2 = h2.wrapping_add(sc); h3 = h3.wrapping_add(sd);
        h4 = h4.wrapping_add(se);
    }

    let mut out = Vec::with_capacity(20);
    for h in [h0, h1, h2, h3, h4] { out.extend_from_slice(&h.to_be_bytes()); }
    out
}

// ─── SHA-256 ────────────────────────────────────────────────────────────────

fn sha256_continue(state: [u32; 8], extension: &[u8], processed_len: usize) -> Vec<u8> {
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

    let padding = md_padding(processed_len + extension.len(), HashAlgorithm::Sha256);
    let mut data = extension.to_vec();
    data.extend_from_slice(&padding);

    let mut h = state;

    for chunk in data.chunks(64) {
        if chunk.len() < 64 { break; }
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] = h;

        for i in 0..64 {
            let sig1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ (!ee & gg);
            let temp1 = hh.wrapping_add(sig1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let sig0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let temp2 = sig0.wrapping_add(maj);

            hh = gg; gg = ff; ff = ee; ee = dd.wrapping_add(temp1);
            dd = cc; cc = bb; bb = aa; aa = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(aa); h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc); h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee); h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = Vec::with_capacity(32);
    for word in h { out.extend_from_slice(&word.to_be_bytes()); }
    out
}

/// Standalone MD5 hash.
#[must_use]
pub fn md5(data: &[u8]) -> Vec<u8> {
    let state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    md5_continue(state, data, 0)
}

/// Standalone SHA-1 hash.
#[must_use]
pub fn sha1(data: &[u8]) -> Vec<u8> {
    let state: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    sha1_continue(state, data, 0)
}

/// Standalone SHA-256 hash.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let state: [u32; 8] = [
        0x6a09_e667,0xbb67_ae85,0x3c6e_f372,0xa54f_f53a,
        0x510e_527f,0x9b05_688c,0x1f83_d9ab,0x5be0_cd19,
    ];
    sha256_continue(state, data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut data = key.to_vec();
        data.extend_from_slice(msg);
        sha256(&data)
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afb...
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
        assert_eq!(hash[2], 0xc4);
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256(b"abc");
        // ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469049e182811c36
        assert_eq!(hash[0], 0xba);
        assert_eq!(hash[1], 0x78);
    }

    #[test]
    fn md5_empty() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let hash = md5(b"");
        assert_eq!(hash[0], 0xd4);
        assert_eq!(hash[1], 0x1d);
    }

    #[test]
    fn sha1_empty() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1(b"");
        assert_eq!(hash[0], 0xda);
        assert_eq!(hash[1], 0x39);
    }

    #[test]
    fn md_padding_length() {
        let pad = md_padding(0, HashAlgorithm::Sha256);
        // After padding, total length should be 64.
        assert_eq!(0 + pad.len(), 64);
        assert_eq!(pad[0], 0x80);
        assert!(pad[1..pad.len()-8].iter().all(|&b| b == 0));
    }

    #[test]
    fn length_extension_sha256() {
        let secret = b"secret_key";
        let message = b"amount=100&user=alice";
        let extension = b"&admin=true";

        let original_mac = sha256_mac(secret, message);

        let attacker = LengthExtensionAttacker::new(HashAlgorithm::Sha256);
        let result = attacker.attack(message, &original_mac, secret.len(), extension);

        // Compute what the server would compute for the extended message.
        let server_mac = sha256_mac(secret, &result.extended_message);

        assert_eq!(result.forged_mac, server_mac,
            "Forged MAC does not match server MAC for extended message");
    }

    #[test]
    fn length_extension_md5() {
        let secret = b"key";
        let message = b"data";
        let extension = b"injected";

        let mac: Vec<u8> = {
            let mut d = secret.to_vec();
            d.extend_from_slice(message);
            md5(&d)
        };

        let attacker = LengthExtensionAttacker::new(HashAlgorithm::Md5);
        let result = attacker.attack(message, &mac, secret.len(), extension);

        let server_mac = {
            let mut d = secret.to_vec();
            d.extend_from_slice(&result.extended_message);
            md5(&d)
        };

        assert_eq!(result.forged_mac, server_mac);
    }
}
