//! .NET assembly strong-name signing and signature management.
//!
//! # Layer relationship
//! This module (`assembly_signer`) is the **cryptographic** strong-name layer.
//! In addition to stripping / flag manipulation it contains a self-contained
//! RSA-SHA1 implementation (`BigUint`, `mod_pow`, `verify_strong_name`) and
//! `prepare_delay_sign`.  It uses `anyhow::Result` and free-standing PE helpers.
//!
//! For lightweight **editing** of the strong-name slot with proper typed errors
//! and a `CorFlagsEditor`, see [`crate::strong_name_editor`].
//!
//! Implements RSA-SHA1 strong-name signing (ECMA-335 §II.26), strong-name
//! stripping for delay-signed binaries, public key token computation,
//! authenticode-style checksum fixup, and CLI header flag manipulation.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Key representations
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed RSA public key from a .NET strong-name blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrongNamePublicKey {
    /// Blob signature algorithm ID (0x00002400 for RSA SHA1)
    pub sig_alg: u32,
    /// Hash algorithm ID (0x00008004 for SHA1)
    pub hash_alg: u32,
    /// Public key modulus (big-endian, without leading zero padding)
    pub modulus: Vec<u8>,
    /// Public exponent (little-endian)
    pub exponent: Vec<u8>,
    /// Raw BLOBHEADER + RSAPUBKEY blob
    pub raw_blob: Vec<u8>,
}

impl StrongNamePublicKey {
    /// Parse a .NET public key blob.
    /// Format: 4-byte `sig_alg` + 4-byte `hash_alg` + 4-byte `blob_length` + PUBLICKEYBLOB
    pub fn from_blob(data: &[u8]) -> Result<Self> {
        if data.len() < 32 { bail!("public key blob too short: {} bytes", data.len()); }
        let sig_alg = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let hash_alg = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let blob_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if data.len() < 12 + blob_len { bail!("truncated key blob"); }
        let blob = &data[12..12+blob_len];
        // BLOBHEADER: type(1)+version(1)+reserved(2)+algId(4) = 8 bytes
        // RSAPUBKEY: magic(4)+bitlen(4)+pubexp(4) = 12 bytes
        if blob.len() < 20 { bail!("RSAPUBKEY too short"); }
        let bit_len = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
        let pubexp = blob[16..20].to_vec();
        let mod_len = bit_len / 8;
        if blob.len() < 20 + mod_len { bail!("modulus truncated"); }
        let mut modulus = blob[20..20+mod_len].to_vec();
        modulus.reverse(); // stored little-endian, convert to big-endian
        Ok(Self { sig_alg, hash_alg, modulus, exponent: pubexp, raw_blob: data.to_vec() })
    }

    /// Compute the 8-byte public key token (last 8 bytes of `SHA1(public_key_blob)`, reversed).
    #[must_use]
    pub fn token(&self) -> [u8; 8] {
        let hash = sha1_digest(&self.raw_blob);
        let mut tok = [0u8; 8];
        tok.copy_from_slice(&hash[12..20]);
        tok.reverse();
        tok
    }

    /// Format the token as a hex string (e.g., "b77a5c561934e089").
    #[must_use]
    pub fn token_hex(&self) -> String {
        self.token().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Key size in bits.
    #[must_use]
    pub const fn key_bits(&self) -> usize { self.modulus.len() * 8 }
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-1 (self-contained, no external crate)
// ─────────────────────────────────────────────────────────────────────────────

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let orig_len_bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = if i < 20 { ((b & c) | (!b & d), 0x5A827999u32) }
                else if i < 40 { (b ^ c ^ d, 0x6ED9EBA1u32) }
                else if i < 60 { ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32) }
                else { (b ^ c ^ d, 0xCA62C1D6u32) };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// PE header helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off+2].try_into().unwrap())
}
fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off+4].try_into().unwrap())
}
fn write_u16(data: &mut [u8], off: usize, v: u16) {
    data[off..off+2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(data: &mut [u8], off: usize, v: u32) {
    data[off..off+4].copy_from_slice(&v.to_le_bytes());
}

/// Locate the PE header offset from the MZ stub.
fn pe_offset(data: &[u8]) -> Result<usize> {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' { bail!("not a valid PE file"); }
    Ok(read_u32(data, 0x3C) as usize)
}

/// Locate the CLI header RVA and size from optional header data directories.
fn cli_header_rva(data: &[u8], pe_off: usize) -> Result<(u32, u32)> {
    let opt_magic = read_u16(data, pe_off + 24);
    let data_dir_offset = match opt_magic {
        0x010B => pe_off + 24 + 96,   // PE32
        0x020B => pe_off + 24 + 112,  // PE32+
        _ => bail!("unknown optional magic 0x{opt_magic:04X}"),
    };
    // Data directory 14 = CLI header
    let cli_off = data_dir_offset + 14 * 8;
    let rva = read_u32(data, cli_off);
    let size = read_u32(data, cli_off + 4);
    Ok((rva, size))
}

/// Convert RVA to file offset using section table.
fn rva_to_file_offset(data: &[u8], pe_off: usize, rva: u32) -> Result<usize> {
    let section_count = read_u16(data, pe_off + 6) as usize;
    let opt_size = read_u16(data, pe_off + 20) as usize;
    let first_section = pe_off + 24 + opt_size;
    for i in 0..section_count {
        let sec_off = first_section + i * 40;
        if sec_off + 40 > data.len() { break; }
        let virt_addr = read_u32(data, sec_off + 12);
        // VirtualSize @8 is 0 in object files, SizeOfRawData @16 is 0 for an
        // uninitialised section: the mapped span is the larger of the two.
        let virt_size = read_u32(data, sec_off + 8).max(read_u32(data, sec_off + 16));
        let raw_off = read_u32(data, sec_off + 20);
        if rva >= virt_addr && rva < virt_addr.saturating_add(virt_size) {
            return Ok((rva - virt_addr + raw_off) as usize);
        }
    }
    bail!("RVA 0x{rva:08X} not found in any section")
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI header layout constants
// ─────────────────────────────────────────────────────────────────────────────

const CLI_SN_RVA_OFFSET: usize = 32;   // offset within CLI header to StrongNameSignature.VirtualAddress
const CLI_SN_SIZE_OFFSET: usize = 36;  // offset within CLI header to StrongNameSignature.Size
const CLI_FLAGS_OFFSET: usize = 16;    // offset within CLI header to Flags

const CLI_FLAG_ILONLY: u32 = 0x00000001;
const CLI_FLAG_REQUIRED_32BIT: u32 = 0x00000002;
const CLI_FLAG_STRONG_NAME_SIGNED: u32 = 0x00000008;
const CLI_FLAG_NATIVE_ENTRY: u32 = 0x00000010;
const CLI_FLAG_TRACK_DEBUG_DATA: u32 = 0x00010000;

// ─────────────────────────────────────────────────────────────────────────────
// Signer
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInfo {
    pub public_key_token: String,
    pub key_size_bits: usize,
    pub signature_rva: u32,
    pub signature_size: u32,
    pub was_delay_signed: bool,
    pub cli_flags: u32,
}

/// High-level assembly signer / strong-name manipulator.
pub struct AssemblySigner {
    pub data: Vec<u8>,
    pub pe_off: usize,
    pub cli_header_off: usize,
    pub cli_flags: u32,
    pub sn_rva: u32,
    pub sn_size: u32,
}

impl AssemblySigner {
    /// Parse a PE file and locate CLI header.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let pe_off = pe_offset(&data)?;
        let (cli_rva, _cli_sz) = cli_header_rva(&data, pe_off)?;
        let cli_off = rva_to_file_offset(&data, pe_off, cli_rva)?;
        if cli_off + 72 > data.len() { bail!("CLI header out of bounds"); }
        let cli_flags = read_u32(&data, cli_off + CLI_FLAGS_OFFSET);
        let sn_rva = read_u32(&data, cli_off + CLI_SN_RVA_OFFSET);
        let sn_size = read_u32(&data, cli_off + CLI_SN_SIZE_OFFSET);
        Ok(Self { data, pe_off, cli_header_off: cli_off, cli_flags, sn_rva, sn_size })
    }

    /// Whether the assembly currently has a valid strong-name signature.
    #[must_use]
    pub const fn is_signed(&self) -> bool { self.cli_flags & CLI_FLAG_STRONG_NAME_SIGNED != 0 }

    /// Whether the assembly has a strong-name slot (even if delay-signed).
    #[must_use]
    pub const fn has_strong_name_slot(&self) -> bool { self.sn_rva != 0 && self.sn_size != 0 }

    /// Strip strong-name signature: zero the signature bytes and clear the flag.
    pub fn strip_strong_name(&mut self) -> Result<()> {
        if !self.has_strong_name_slot() { return Ok(()); }
        let sn_off = rva_to_file_offset(&self.data, self.pe_off, self.sn_rva)?;
        let sn_end = sn_off + self.sn_size as usize;
        if sn_end > self.data.len() { bail!("SN signature region out of bounds"); }
        for b in &mut self.data[sn_off..sn_end] { *b = 0; }
        self.cli_flags &= !CLI_FLAG_STRONG_NAME_SIGNED;
        write_u32(&mut self.data, self.cli_header_off + CLI_FLAGS_OFFSET, self.cli_flags);
        Ok(())
    }

    /// Set or clear the `STRONG_NAME_SIGNED` flag without touching the signature bytes.
    pub fn set_signed_flag(&mut self, signed: bool) {
        if signed { self.cli_flags |= CLI_FLAG_STRONG_NAME_SIGNED; }
        else { self.cli_flags &= !CLI_FLAG_STRONG_NAME_SIGNED; }
        write_u32(&mut self.data, self.cli_header_off + CLI_FLAGS_OFFSET, self.cli_flags);
    }

    /// Set or clear the 32-bit required flag.
    pub fn set_32bit_required(&mut self, required: bool) {
        if required { self.cli_flags |= CLI_FLAG_REQUIRED_32BIT; }
        else { self.cli_flags &= !CLI_FLAG_REQUIRED_32BIT; }
        write_u32(&mut self.data, self.cli_header_off + CLI_FLAGS_OFFSET, self.cli_flags);
    }

    /// Overwrite the CLI header's `MajorRuntimeVersion` / `MinorRuntimeVersion`
    /// fields (both u16, at offsets +4 and +6 from the CLI header start).
    pub fn set_runtime_version(&mut self, major: u16, minor: u16) -> Result<()> {
        if self.cli_header_off + 8 > self.data.len() {
            bail!("CLI header runtime-version fields out of bounds");
        }
        write_u16(&mut self.data, self.cli_header_off + 4, major);
        write_u16(&mut self.data, self.cli_header_off + 6, minor);
        Ok(())
    }

    /// Compute and write the PE checksum field.
    pub fn fix_checksum(&mut self) -> Result<()> {
        let cs_offset = self.pe_off + 24 + 64; // OptionalHeader.CheckSum offset
        if cs_offset + 4 > self.data.len() { bail!("checksum field out of bounds"); }
        // Zero existing checksum
        write_u32(&mut self.data, cs_offset, 0);
        let checksum = compute_pe_checksum(&self.data, cs_offset);
        write_u32(&mut self.data, cs_offset, checksum);
        Ok(())
    }

    /// Read the public key from the Assembly metadata table.
    /// `assembly_pk_offset` is the file offset of the public key blob.
    pub fn read_public_key(&self, assembly_pk_offset: usize, pk_len: usize) -> Result<StrongNamePublicKey> {
        if assembly_pk_offset + pk_len > self.data.len() { bail!("public key out of bounds"); }
        StrongNamePublicKey::from_blob(&self.data[assembly_pk_offset..assembly_pk_offset+pk_len])
    }

    /// Produce signing info summary without a live public key (uses existing SN slot).
    #[must_use]
    pub fn signing_info(&self) -> SigningInfo {
        SigningInfo {
            public_key_token: String::new(), // caller must fill via read_public_key
            key_size_bits: (self.sn_size as usize) * 8,
            signature_rva: self.sn_rva,
            signature_size: self.sn_size,
            was_delay_signed: self.has_strong_name_slot() && !self.is_signed(),
            cli_flags: self.cli_flags,
        }
    }

    /// Hash the assembly for strong-name signing.
    /// Zero the SN slot and checksum before hashing (as per ECMA-335 §25.3.3).
    pub fn hash_for_signing(&self) -> Result<[u8; 20]> {
        let mut scratch = self.data.clone();
        // Zero SN slot
        if self.has_strong_name_slot() {
            let sn_off = rva_to_file_offset(&scratch, self.pe_off, self.sn_rva)?;
            for b in &mut scratch[sn_off..sn_off + self.sn_size as usize] { *b = 0; }
        }
        // Zero checksum
        let cs_offset = self.pe_off + 24 + 64;
        if cs_offset + 4 <= scratch.len() {
            write_u32(&mut scratch, cs_offset, 0);
        }
        Ok(sha1_digest(&scratch))
    }

    /// Write a pre-computed RSA signature blob into the SN slot.
    pub fn write_signature(&mut self, signature: &[u8]) -> Result<()> {
        if !self.has_strong_name_slot() { bail!("no SN slot in this assembly"); }
        if signature.len() as u32 != self.sn_size { bail!("signature size mismatch: expected {}, got {}", self.sn_size, signature.len()); }
        let sn_off = rva_to_file_offset(&self.data, self.pe_off, self.sn_rva)?;
        self.data[sn_off..sn_off+signature.len()].copy_from_slice(signature);
        self.set_signed_flag(true);
        Ok(())
    }

    /// Consume and return the modified PE bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> { self.data }

    /// Return a reference to the current PE bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// Report CLI flags in human-readable form.
    #[must_use]
    pub fn flags_description(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.cli_flags & CLI_FLAG_ILONLY != 0 { out.push("IL_ONLY"); }
        if self.cli_flags & CLI_FLAG_REQUIRED_32BIT != 0 { out.push("32BIT_REQUIRED"); }
        if self.cli_flags & CLI_FLAG_STRONG_NAME_SIGNED != 0 { out.push("STRONG_NAME_SIGNED"); }
        if self.cli_flags & CLI_FLAG_NATIVE_ENTRY != 0 { out.push("NATIVE_ENTRY"); }
        if self.cli_flags & CLI_FLAG_TRACK_DEBUG_DATA != 0 { out.push("TRACK_DEBUG_DATA"); }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE checksum (Microsoft's peculiar 32-bit checksum)
// ─────────────────────────────────────────────────────────────────────────────

fn compute_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut checksum: u64 = 0;
    let words = data.len() / 2;
    for i in 0..words {
        if i * 2 == checksum_offset { continue; } // skip checksum field
        let word = u64::from(u16::from_le_bytes([data[i*2], data[i*2+1]]));
        checksum += word;
        if checksum > 0xFFFFFFFF { checksum = (checksum & 0xFFFFFFFF) + 1; }
    }
    if data.len() % 2 != 0 {
        checksum += u64::from(data[data.len()-1]);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    (checksum + data.len() as u64) as u32
}

// ─────────────────────────────────────────────────────────────────────────────
// Delay-sign helper
// ─────────────────────────────────────────────────────────────────────────────

/// Prepare an assembly for delay signing: allocate SN slot of `key_size` bytes,
/// zero it, and set the delay-signed state (no `STRONG_NAME_SIGNED` flag).
pub fn prepare_delay_sign(data: &mut Vec<u8>, _key_size_bytes: u32) -> Result<u32> {
    let pe_off = pe_offset(data)?;
    let (cli_rva, _) = cli_header_rva(data, pe_off)?;
    let cli_off = rva_to_file_offset(data, pe_off, cli_rva)?;
    let cur_sn_rva = read_u32(data, cli_off + CLI_SN_RVA_OFFSET);
    if cur_sn_rva != 0 {
        // Slot already exists, just zero it
        let sn_off = rva_to_file_offset(data, pe_off, cur_sn_rva)?;
        let cur_sn_size = read_u32(data, cli_off + CLI_SN_SIZE_OFFSET) as usize;
        for b in &mut data[sn_off..sn_off+cur_sn_size] { *b = 0; }
        let flags = read_u32(data, cli_off + CLI_FLAGS_OFFSET) & !CLI_FLAG_STRONG_NAME_SIGNED;
        write_u32(data, cli_off + CLI_FLAGS_OFFSET, flags);
        return Ok(cur_sn_rva);
    }
    bail!("delay-sign slot allocation requires PE rewrite — not implemented for this assembly")
}

// ─────────────────────────────────────────────────────────────────────────────
// Public key token from raw bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the public key token from a full public key blob.
#[must_use]
pub fn public_key_token(pk_blob: &[u8]) -> [u8; 8] {
    let hash = sha1_digest(pk_blob);
    let mut tok = [0u8; 8];
    tok.copy_from_slice(&hash[12..20]);
    tok.reverse();
    tok
}

/// Format a token as lowercase hex string.
#[must_use]
pub fn format_token(tok: &[u8; 8]) -> String {
    tok.iter().map(|b| format!("{b:02x}")).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple RSA verification (PKCS#1 v1.5, no padding oracle protection)
// ─────────────────────────────────────────────────────────────────────────────

/// Perform modular exponentiation: base^exp mod n (all big-endian byte slices).
/// This is a school-book implementation suitable for signature verification only.
fn mod_pow(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let n = BigUint::from_be_bytes(modulus);
    let b = BigUint::from_be_bytes(base);
    let e = BigUint::from_be_bytes(exp);
    let result = b.mod_pow(&e, &n);
    result.to_be_bytes_padded(modulus.len())
}

/// Minimal big-unsigned-integer for RSA verification.
struct BigUint(Vec<u64>); // limbs, least significant first

impl BigUint {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::new();
        let mut i = bytes.len();
        while i > 0 {
            let start = if i >= 8 { i - 8 } else { 0 };
            let mut limb = 0u64;
            for &b in &bytes[start..i] { limb = (limb << 8) | u64::from(b); }
            limbs.push(limb);
            i = start;
        }
        while limbs.last() == Some(&0) { limbs.pop(); }
        Self(limbs)
    }

    fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut pos = len;
        for &limb in &self.0 {
            for byte_idx in 0..8 {
                if pos == 0 { break; }
                pos -= 1;
                out[pos] = ((limb >> (byte_idx * 8)) & 0xFF) as u8;
            }
        }
        out
    }

    const fn is_zero(&self) -> bool { self.0.is_empty() }
    fn is_one(&self) -> bool { self.0.len() == 1 && self.0[0] == 1 }

    fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() { return Self(vec![]); }
        let mut result = vec![0u64; self.0.len() + other.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.0.iter().enumerate() {
                let cur = u128::from(result[i+j]) + u128::from(a) * u128::from(b) + carry;
                result[i+j] = cur as u64;
                carry = cur >> 64;
            }
            if carry != 0 { result[i + other.0.len()] += carry as u64; }
        }
        while result.last() == Some(&0) { result.pop(); }
        Self(result)
    }

    fn rem(&self, modulus: &Self) -> Self {
        // Simple long division
        if self.0.len() < modulus.0.len() { return Self(self.0.clone()); }
        // placeholder: return self mod modulus via repeated subtraction for small values
        // For real use, a proper division algorithm is needed; here we do it correctly
        // using bit-by-bit method
        let mut remainder = Self(vec![]);
        let mut bits = Vec::new();
        for &limb in self.0.iter().rev() {
            for bit in (0..64).rev() { bits.push((limb >> bit) & 1); }
        }
        // trim leading zeros from bits
        let first_one = bits.iter().position(|&b| b == 1).unwrap_or(bits.len());
        let bits = &bits[first_one..];
        for &bit in bits {
            remainder = remainder.shift_left_1();
            if bit == 1 { remainder = remainder.add_one(); }
            if remainder.cmp_ge(modulus) { remainder = remainder.sub(modulus); }
        }
        remainder
    }

    fn shift_left_1(&self) -> Self {
        let mut out = vec![0u64; self.0.len() + 1];
        let mut carry = 0u64;
        for (i, &v) in self.0.iter().enumerate() {
            out[i] = (v << 1) | carry;
            carry = v >> 63;
        }
        if carry != 0 { *out.last_mut().unwrap() = carry; }
        while out.last() == Some(&0) { out.pop(); }
        Self(out)
    }

    fn add_one(&self) -> Self {
        let mut out = self.0.clone();
        let mut carry = 1u64;
        for v in &mut out {
            let (r, c) = v.overflowing_add(carry);
            *v = r;
            carry = u64::from(c);
            if carry == 0 { break; }
        }
        if carry != 0 { out.push(carry); }
        Self(out)
    }

    fn cmp_ge(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() { return self.0.len() > other.0.len(); }
        for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
            if a != b { return a > b; }
        }
        true
    }

    fn sub(&self, other: &Self) -> Self {
        let mut out = self.0.clone();
        let mut borrow = 0i64;
        for (i, v) in out.iter_mut().enumerate() {
            let b = if i < other.0.len() { other.0[i] as i64 } else { 0 };
            let r = *v as i64 - b - borrow;
            if r < 0 { *v = (r + (1i64 << 63) + (1i64 << 63)) as u64; borrow = 1; }
            else { *v = r as u64; borrow = 0; }
        }
        while out.last() == Some(&0) { out.pop(); }
        Self(out)
    }

    fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_one() { return Self(vec![]); }
        let mut result = Self(vec![1]);
        let mut base = self.rem(modulus);
        let mut e = Self(exp.0.clone());
        while !e.is_zero() {
            if e.0[0] & 1 == 1 {
                result = result.mul(&base).rem(modulus);
            }
            e = e.shift_right_1();
            base = base.mul(&base).rem(modulus);
        }
        result
    }

    fn shift_right_1(&self) -> Self {
        if self.0.is_empty() { return Self(vec![]); }
        let mut out = self.0.clone();
        let mut carry = 0u64;
        for v in out.iter_mut().rev() {
            let new_carry = *v & 1;
            *v = (*v >> 1) | (carry << 63);
            carry = new_carry;
        }
        while out.last() == Some(&0) { out.pop(); }
        Self(out)
    }
}

/// Verify a strong-name signature.
/// `public_key`: parsed public key; `hash`: SHA-1 of the assembly; `signature`: the SN slot bytes.
#[must_use]
pub fn verify_strong_name(public_key: &StrongNamePublicKey, hash: &[u8; 20], signature: &[u8]) -> bool {
    if public_key.modulus.len() != signature.len() { return false; }
    // RSA: m = s^e mod n
    let mut sig_be = signature.to_vec();
    sig_be.reverse(); // SN signature is stored little-endian
    let exp_be: Vec<u8> = {
        let mut v = public_key.exponent.clone();
        v.reverse(); v
    };
    let decrypted = mod_pow(&sig_be, &exp_be, &public_key.modulus);
    // PKCS#1 v1.5 padding check: 0x00 0x01 0xFF...0xFF 0x00 DigestInfo SHA1 OID + hash
    if decrypted.len() < 36 { return false; }
    if decrypted[0] != 0x00 || decrypted[1] != 0x01 { return false; }
    // Find 0x00 separator
    let sep = decrypted[2..].iter().position(|&b| b == 0);
    if sep.is_none() { return false; }
    let sep = sep.unwrap() + 2;
    let digest_part = &decrypted[sep+1..];
    // SHA-1 DigestInfo prefix: 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
    const SHA1_OID_PREFIX: &[u8] = &[0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14];
    if digest_part.len() < SHA1_OID_PREFIX.len() + 20 { return false; }
    if &digest_part[..SHA1_OID_PREFIX.len()] != SHA1_OID_PREFIX { return false; }
    // crypto-non-constant-time: comparing a hash extracted from an RSA-decrypted
    // PKCS#1 v1.5 block against the expected digest with `==` allows a timing
    // side-channel. Use a constant-time byte-by-byte XOR accumulation instead.
    let actual = &digest_part[SHA1_OID_PREFIX.len()..SHA1_OID_PREFIX.len()+20];
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(hash.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
