//! `rustre-loader-dotnet::strongname`
//!
//! .NET strong-name signing utilities: public key blobs, public key tokens,
//! assembly identity, signature verification stubs, and GAC resolution.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced by strong-name operations.
#[derive(Debug, thiserror::Error)]
pub enum StrongNameError {
    /// The blob is too short to be a valid public key.
    #[error("blob too short")]
    BlobTooShort,
    /// The blob does not start with the expected PUBLICKEYBLOB header.
    #[error("invalid public key blob header")]
    InvalidBlobHeader,
    /// The signature length is unexpected.
    #[error("invalid signature length: {0}")]
    InvalidSignatureLength(usize),
    /// The public key token has wrong length.
    #[error("invalid public key token length: expected 8, got {0}")]
    InvalidTokenLength(usize),
    /// Assembly identity field is missing or malformed.
    #[error("malformed assembly identity: {0}")]
    MalformedIdentity(String),
    /// The assembly could not be found in the GAC.
    #[error("assembly not found in GAC: {0}")]
    NotFoundInGac(String),
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),
}

// ─── PublicKeyBlob ────────────────────────────────────────────────────────────

/// A .NET PUBLICKEYBLOB (BLOBHEADER + RSAPUBKEY + modulus bytes).
///
/// Layout (little-endian):
/// ```text
/// BLOBHEADER (8 bytes): bType=0x06, bVersion=0x02, reserved=0, aiKeyAlg=0x2400
/// RSAPUBKEY  (12 bytes): magic="RSA1", bitlen, pubexp
/// modulus    (bitlen/8 bytes)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrongNameSignature {
    /// Raw public key blob bytes (PUBLICKEYBLOB format).
    pub public_key_blob: Vec<u8>,
    /// RSA signature bytes (big-endian, same length as modulus).
    pub rsa_signature: Vec<u8>,
    /// Bit length of the RSA key.
    pub key_bits: u32,
    /// Public exponent.
    pub public_exponent: u32,
}

impl StrongNameSignature {
    /// Minimum valid blob size: 8 (BLOBHEADER) + 12 (RSAPUBKEY) = 20 bytes.
    pub const MIN_BLOB_SIZE: usize = 20;

    /// Expected BLOBHEADER bType for a public key blob.
    pub const BLOB_TYPE_PUBKEY: u8 = 0x06;

    /// Expected AI key algorithm for RSA.
    pub const ALG_RSA: u32 = 0x0000_2400;

    /// RSAPUBKEY magic for a public key.
    pub const RSA1_MAGIC: u32 = 0x3141_5352; // "RSA1"

    /// Parse a public-key blob.
    ///
    /// # Errors
    /// Returns [`StrongNameError::BlobTooShort`] or
    /// [`StrongNameError::InvalidBlobHeader`] on parse failure.
    pub fn parse_public_key(blob: &[u8]) -> Result<Self, StrongNameError> {
        if blob.len() < Self::MIN_BLOB_SIZE {
            return Err(StrongNameError::BlobTooShort);
        }
        // BLOBHEADER: bType (1), bVersion (1), reserved (2), aiKeyAlg (4)
        let b_type = blob[0];
        if b_type != Self::BLOB_TYPE_PUBKEY {
            return Err(StrongNameError::InvalidBlobHeader);
        }
        let alg = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        if alg != Self::ALG_RSA && alg != 0 {
            // Tolerate 0 (stripped assemblies sometimes have 0)
        }

        // RSAPUBKEY starts at byte 8
        let magic = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        if magic != Self::RSA1_MAGIC {
            return Err(StrongNameError::InvalidBlobHeader);
        }
        let key_bits = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]);
        let public_exponent = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]);

        // Modulus follows at byte 20
        let modulus_bytes = (key_bits / 8) as usize;
        let _modulus = if 20 + modulus_bytes <= blob.len() {
            blob[20..20 + modulus_bytes].to_vec()
        } else {
            blob[20..].to_vec()
        };

        Ok(Self {
            public_key_blob: blob.to_vec(),
            rsa_signature: Vec::new(),
            key_bits,
            public_exponent,
        })
    }

    /// Build a synthetic public key blob for testing (4096-bit RSA, e=65537).
    #[must_use]
    pub fn mock(key_bits: u32) -> Self {
        let modulus_len = (key_bits / 8) as usize;
        let mut blob = Vec::with_capacity(20 + modulus_len);
        // BLOBHEADER
        blob.push(0x06); // bType
        blob.push(0x02); // bVersion
        blob.extend_from_slice(&[0x00, 0x00]); // reserved
        blob.extend_from_slice(&0x0000_2400u32.to_le_bytes()); // aiKeyAlg
        // RSAPUBKEY
        blob.extend_from_slice(&Self::RSA1_MAGIC.to_le_bytes());
        blob.extend_from_slice(&key_bits.to_le_bytes());
        blob.extend_from_slice(&65537u32.to_le_bytes());
        // Modulus (all 0xFF for mock)
        blob.extend(std::iter::repeat_n(0xFF_u8, modulus_len));

        Self {
            public_key_blob: blob,
            rsa_signature: vec![0xAB; modulus_len],
            key_bits,
            public_exponent: 65537,
        }
    }

    /// Return the modulus bytes extracted from the blob, or empty if unavailable.
    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        let modulus_len = (self.key_bits / 8) as usize;
        let start = 20usize;
        let end = (start + modulus_len).min(self.public_key_blob.len());
        if start < self.public_key_blob.len() {
            &self.public_key_blob[start..end]
        } else {
            &[]
        }
    }

    /// Return the key size in bits.
    #[must_use]
    pub const fn key_size_bits(&self) -> u32 {
        self.key_bits
    }

    /// Return `true` if this is a 2048-bit or larger key.
    #[must_use]
    pub const fn is_strong_key(&self) -> bool {
        self.key_bits >= 2048
    }
}

impl fmt::Display for StrongNameSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StrongNameSignature {{ key_bits={}, exp={}, sig_len={} }}",
            self.key_bits,
            self.public_exponent,
            self.rsa_signature.len()
        )
    }
}

// ─── PublicKeyToken ───────────────────────────────────────────────────────────

/// A .NET strong-name public key token: the last 8 bytes of the SHA-1 hash of
/// the public key blob, reversed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKeyToken(pub [u8; 8]);

impl PublicKeyToken {
    /// Well-known token for `mscorlib` / `System.Runtime` (Microsoft).
    pub const MSCORLIB: Self = Self([0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89]);

    /// Well-known token for `System.*` assemblies.
    pub const SYSTEM: Self = Self([0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a]);

    /// Parse from an 8-byte slice.
    ///
    /// # Errors
    /// Returns [`StrongNameError::InvalidTokenLength`] if `bytes.len() != 8`.
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, StrongNameError> {
        if bytes.len() != 8 {
            return Err(StrongNameError::InvalidTokenLength(bytes.len()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Parse from a hex string like `"b77a5c561934e089"`.
    ///
    /// # Errors
    /// Returns [`StrongNameError::InvalidTokenLength`] on wrong length.
    /// Returns [`StrongNameError::MalformedIdentity`] if not valid hex.
    pub fn from_hex(s: &str) -> Result<Self, StrongNameError> {
        let s = s.trim();
        if s.len() != 16 {
            return Err(StrongNameError::InvalidTokenLength(s.len() / 2));
        }
        let mut arr = [0u8; 8];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0])
                .ok_or_else(|| StrongNameError::MalformedIdentity(format!("bad hex: {s}")))?;
            let lo = hex_nibble(chunk[1])
                .ok_or_else(|| StrongNameError::MalformedIdentity(format!("bad hex: {s}")))?;
            arr[i] = (hi << 4) | lo;
        }
        Ok(Self(arr))
    }

    /// Compute the public key token from a full public key blob.
    ///
    /// Uses a deterministic hash stub (real implementation would use SHA-1).
    #[must_use]
    pub fn from_public_key_blob(blob: &[u8]) -> Self {
        // Compute a deterministic 8-byte fingerprint of the blob.
        // In production this would be last 8 bytes of SHA-1(blob), reversed.
        let mut hash = [0u8; 8];
        for (i, &b) in blob.iter().enumerate() {
            hash[i % 8] ^= b.wrapping_add((i as u8).wrapping_mul(17));
        }
        // Reverse (to match .NET convention).
        hash.reverse();
        Self(hash)
    }

    /// Return as a lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    /// Return the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Return `true` if this is a known Microsoft system token.
    #[must_use]
    pub fn is_microsoft(&self) -> bool {
        *self == Self::MSCORLIB || *self == Self::SYSTEM
    }
}

impl fmt::Display for PublicKeyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── StrongNameVerifier ───────────────────────────────────────────────────────

/// Verifies strong-name signatures on .NET assemblies.
///
/// The actual cryptographic verification (RSA PKCS#1 v1.5 + SHA-1) is
/// implemented as a stub that accepts all structurally-valid signatures.
#[derive(Debug, Default)]
pub struct StrongNameVerifier {
    /// Trusted public key tokens.  If non-empty, only these tokens are accepted.
    trusted_tokens: Vec<PublicKeyToken>,
    /// Whether to bypass signature verification (test mode).
    bypass_verification: bool,
}

impl StrongNameVerifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verifier that accepts all signatures without checking (test mode).
    #[must_use]
    pub fn bypass() -> Self {
        Self {
            bypass_verification: true,
            ..Self::default()
        }
    }

    /// Add a trusted public key token.
    pub fn trust(&mut self, token: PublicKeyToken) {
        self.trusted_tokens.push(token);
    }

    /// Verify the strong-name signature in `sn`.
    ///
    /// The `hash_bytes` should be the SHA-1 of the relevant parts of the PE file
    /// (with the strong-name blob zeroed).
    ///
    /// In this stub implementation the cryptographic check is replaced by a
    /// structural sanity check.
    ///
    /// # Errors
    /// Returns [`StrongNameError::VerificationFailed`] if the structural check
    /// fails and bypass mode is not active.
    pub fn verify(
        &self,
        sn: &StrongNameSignature,
        hash_bytes: &[u8],
    ) -> Result<(), StrongNameError> {
        if self.bypass_verification {
            return Ok(());
        }
        // Structural check: signature length should equal key size / 8.
        let expected_len = (sn.key_bits / 8) as usize;
        if !sn.rsa_signature.is_empty() && sn.rsa_signature.len() != expected_len {
            return Err(StrongNameError::VerificationFailed(format!(
                "sig len {} != expected {}",
                sn.rsa_signature.len(),
                expected_len
            )));
        }
        // Check that hash_bytes is non-empty.
        if hash_bytes.is_empty() {
            return Err(StrongNameError::VerificationFailed(
                "empty hash bytes".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify by checking only the public key token.
    ///
    /// # Errors
    /// Returns [`StrongNameError::VerificationFailed`] if the token is not trusted.
    pub fn verify_token(&self, token: &PublicKeyToken) -> Result<(), StrongNameError> {
        if self.bypass_verification {
            return Ok(());
        }
        if self.trusted_tokens.is_empty() {
            return Ok(()); // No restriction
        }
        if self.trusted_tokens.contains(token) {
            Ok(())
        } else {
            Err(StrongNameError::VerificationFailed(format!(
                "untrusted token: {token}"
            )))
        }
    }

    /// Return `true` if `token` is in the trusted list (or no list is set).
    #[must_use]
    pub fn is_trusted(&self, token: &PublicKeyToken) -> bool {
        self.trusted_tokens.is_empty() || self.trusted_tokens.contains(token)
    }
}

// ─── AssemblyIdentity ─────────────────────────────────────────────────────────

/// The four-part identity of a .NET assembly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssemblyIdentity {
    /// Simple assembly name (e.g. `"mscorlib"`).
    pub name: String,
    /// Four-part version string (e.g. `"4.0.0.0"`).
    pub version: String,
    /// Culture string (e.g. `"neutral"` or `"en-US"`).
    pub culture: String,
    /// Public key token (8 hex bytes), or `None` for delay-signed assemblies.
    pub public_key_token: Option<PublicKeyToken>,
}

impl AssemblyIdentity {
    /// Create a new identity.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        culture: impl Into<String>,
        token: Option<PublicKeyToken>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            culture: culture.into(),
            public_key_token: token,
        }
    }

    /// Create an identity without a strong-name token.
    #[must_use]
    pub fn unsigned(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(name, version, "neutral", None)
    }

    /// Parse an assembly identity from a fully-qualified name string, e.g.:
    /// `"mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"`
    ///
    /// # Errors
    /// Returns [`StrongNameError::MalformedIdentity`] if the string is malformed.
    pub fn parse(s: &str) -> Result<Self, StrongNameError> {
        let parts: Vec<&str> = s.splitn(5, ',').collect();
        if parts.is_empty() {
            return Err(StrongNameError::MalformedIdentity(s.to_string()));
        }
        let name = parts[0].trim().to_string();
        let mut version = String::from("0.0.0.0");
        let mut culture = String::from("neutral");
        let mut public_key_token: Option<PublicKeyToken> = None;

        for part in &parts[1..] {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            let key = kv[0].trim().to_ascii_lowercase();
            let val = kv[1].trim();
            match key.as_str() {
                "version" => version = val.to_string(),
                "culture" => culture = val.to_string(),
                "publickeytoken"
                    if !val.eq_ignore_ascii_case("null") => {
                        public_key_token = Some(PublicKeyToken::from_hex(val)?);
                    }
                _ => {}
            }
        }

        Ok(Self {
            name,
            version,
            culture,
            public_key_token,
        })
    }

    /// Format as a fully-qualified assembly name string.
    #[must_use]
    pub fn to_qualified_name(&self) -> String {
        let token = self
            .public_key_token
            .as_ref().map_or_else(|| "null".to_string(), PublicKeyToken::to_hex);
        format!(
            "{}, Version={}, Culture={}, PublicKeyToken={}",
            self.name, self.version, self.culture, token
        )
    }

    /// Return `true` if this assembly is strong-named.
    #[must_use]
    pub const fn is_strong_named(&self) -> bool {
        self.public_key_token.is_some()
    }

    /// Return `true` if the versions match (exact string comparison).
    #[must_use]
    pub fn version_matches(&self, other: &Self) -> bool {
        self.version == other.version
    }

    /// Return the major version number, or `0` if unparseable.
    #[must_use]
    pub fn major_version(&self) -> u16 {
        self.version
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Return `true` if this is a .NET 4.x assembly.
    #[must_use]
    pub fn is_net4(&self) -> bool {
        self.major_version() == 4
    }
}

impl fmt::Display for AssemblyIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_qualified_name())
    }
}

// ─── GacResolver ──────────────────────────────────────────────────────────────

/// Simulates resolution of assemblies in the Global Assembly Cache (GAC).
///
/// The real GAC is a file-system directory structure under
/// `%WINDIR%\Microsoft.NET\assembly\`.  This resolver operates against an
/// in-memory registry of known assemblies, suitable for offline analysis.
#[derive(Debug, Default)]
pub struct GacResolver {
    /// Registry: qualified name → file path.
    registry: HashMap<String, String>,
    /// Whether to fall back to a version-agnostic match.
    allow_version_wildcard: bool,
}

impl GacResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a resolver pre-populated with the standard .NET 4.x framework assemblies.
    #[must_use]
    pub fn with_dotnet4_defaults() -> Self {
        let mut r = Self::new();
        let assemblies = [
            (
                "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll",
            ),
            (
                "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll",
            ),
            (
                "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Core.dll",
            ),
            (
                "System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Runtime.dll",
            ),
            (
                "System.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Linq.dll",
            ),
        ];
        for (id, path) in assemblies {
            r.register(id.to_string(), path.to_string());
        }
        r.allow_version_wildcard = true;
        r
    }

    /// Register an assembly path.
    pub fn register(&mut self, qualified_name: String, path: String) {
        self.registry.insert(qualified_name, path);
    }

    /// Resolve an assembly identity to a file path.
    ///
    /// # Errors
    /// Returns [`StrongNameError::NotFoundInGac`] if the assembly is not registered.
    pub fn resolve(&self, identity: &AssemblyIdentity) -> Result<&str, StrongNameError> {
        let key = identity.to_qualified_name();
        if let Some(path) = self.registry.get(&key) {
            return Ok(path.as_str());
        }
        // Version-wildcard fallback: match by name only.
        if self.allow_version_wildcard {
            let name_prefix = format!("{},", identity.name);
            if let Some((_k, v)) = self
                .registry
                .iter()
                .find(|(k, _)| k.starts_with(&name_prefix))
            {
                return Ok(v.as_str());
            }
        }
        Err(StrongNameError::NotFoundInGac(key))
    }

    /// List all registered assembly names.
    #[must_use]
    pub fn list_assemblies(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.registry.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return the number of registered assemblies.
    #[must_use]
    pub fn count(&self) -> usize {
        self.registry.len()
    }

    /// Check if an assembly is registered.
    #[must_use]
    pub fn contains(&self, identity: &AssemblyIdentity) -> bool {
        self.resolve(identity).is_ok()
    }

    /// Remove an assembly from the registry.
    pub fn unregister(&mut self, identity: &AssemblyIdentity) -> bool {
        self.registry
            .remove(&identity.to_qualified_name())
            .is_some()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StrongNameSignature ───────────────────────────────────────────────────

    #[test]
    fn parse_mock_blob() {
        let sn = StrongNameSignature::mock(2048);
        assert_eq!(sn.key_bits, 2048);
        assert_eq!(sn.public_exponent, 65537);
        assert!(sn.is_strong_key());
    }

    #[test]
    fn parse_valid_blob() {
        let sn = StrongNameSignature::mock(1024);
        let blob = sn.public_key_blob;
        let parsed = StrongNameSignature::parse_public_key(&blob).unwrap();
        assert_eq!(parsed.key_bits, 1024);
        assert_eq!(parsed.public_exponent, 65537);
    }

    #[test]
    fn parse_blob_too_short() {
        let err = StrongNameSignature::parse_public_key(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, StrongNameError::BlobTooShort));
    }

    #[test]
    fn parse_blob_bad_header() {
        let mut blob = StrongNameSignature::mock(2048).public_key_blob;
        blob[0] = 0x07; // wrong bType
        let err = StrongNameSignature::parse_public_key(&blob).unwrap_err();
        assert!(matches!(err, StrongNameError::InvalidBlobHeader));
    }

    #[test]
    fn parse_blob_bad_magic() {
        let mut blob = StrongNameSignature::mock(2048).public_key_blob;
        blob[8] = 0xFF; // corrupt RSA1 magic
        let err = StrongNameSignature::parse_public_key(&blob).unwrap_err();
        assert!(matches!(err, StrongNameError::InvalidBlobHeader));
    }

    #[test]
    fn strong_key_threshold() {
        assert!(StrongNameSignature::mock(2048).is_strong_key());
        assert!(StrongNameSignature::mock(4096).is_strong_key());
        assert!(!StrongNameSignature::mock(1024).is_strong_key());
    }

    #[test]
    fn modulus_bytes_present() {
        let sn = StrongNameSignature::mock(1024);
        assert_eq!(sn.modulus().len(), 128); // 1024 / 8
    }

    // ── PublicKeyToken ────────────────────────────────────────────────────────

    #[test]
    fn token_from_hex_roundtrip() {
        let hex = "b77a5c561934e089";
        let token = PublicKeyToken::from_hex(hex).unwrap();
        assert_eq!(token.to_hex(), hex);
    }

    #[test]
    fn token_from_hex_wrong_length() {
        let err = PublicKeyToken::from_hex("b77a5c56").unwrap_err();
        assert!(matches!(err, StrongNameError::InvalidTokenLength(_)));
    }

    #[test]
    fn token_from_bytes() {
        let bytes = [0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89];
        let token = PublicKeyToken::from_bytes(&bytes).unwrap();
        assert_eq!(token, PublicKeyToken::MSCORLIB);
    }

    #[test]
    fn token_from_bytes_wrong_length() {
        let err = PublicKeyToken::from_bytes(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, StrongNameError::InvalidTokenLength(4)));
    }

    #[test]
    fn token_is_microsoft_mscorlib() {
        assert!(PublicKeyToken::MSCORLIB.is_microsoft());
        assert!(PublicKeyToken::SYSTEM.is_microsoft());
    }

    #[test]
    fn token_from_public_key_blob_deterministic() {
        let sn = StrongNameSignature::mock(2048);
        let t1 = PublicKeyToken::from_public_key_blob(&sn.public_key_blob);
        let t2 = PublicKeyToken::from_public_key_blob(&sn.public_key_blob);
        assert_eq!(t1, t2);
    }

    #[test]
    fn token_display() {
        let t = PublicKeyToken::MSCORLIB;
        assert_eq!(t.to_string(), "b77a5c561934e089");
    }

    // ── StrongNameVerifier ────────────────────────────────────────────────────

    #[test]
    fn verifier_bypass_always_ok() {
        let v = StrongNameVerifier::bypass();
        let sn = StrongNameSignature::mock(2048);
        assert!(v.verify(&sn, &[]).is_ok());
    }

    #[test]
    fn verifier_rejects_empty_hash() {
        let v = StrongNameVerifier::new();
        let sn = StrongNameSignature::mock(2048);
        let err = v.verify(&sn, &[]).unwrap_err();
        assert!(matches!(err, StrongNameError::VerificationFailed(_)));
    }

    #[test]
    fn verifier_accepts_valid_hash() {
        let v = StrongNameVerifier::new();
        let sn = StrongNameSignature::mock(2048);
        assert!(v.verify(&sn, &[0xAB; 20]).is_ok());
    }

    #[test]
    fn verifier_trusted_token_accepted() {
        let mut v = StrongNameVerifier::new();
        v.trust(PublicKeyToken::MSCORLIB);
        assert!(v.verify_token(&PublicKeyToken::MSCORLIB).is_ok());
    }

    #[test]
    fn verifier_untrusted_token_rejected() {
        let mut v = StrongNameVerifier::new();
        v.trust(PublicKeyToken::MSCORLIB);
        let other = PublicKeyToken([0; 8]);
        let err = v.verify_token(&other).unwrap_err();
        assert!(matches!(err, StrongNameError::VerificationFailed(_)));
    }

    #[test]
    fn verifier_is_trusted_empty_list_accepts_all() {
        let v = StrongNameVerifier::new();
        assert!(v.is_trusted(&PublicKeyToken([0; 8])));
    }

    // ── AssemblyIdentity ──────────────────────────────────────────────────────

    #[test]
    fn identity_parse_full() {
        let s = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        let id = AssemblyIdentity::parse(s).unwrap();
        assert_eq!(id.name, "mscorlib");
        assert_eq!(id.version, "4.0.0.0");
        assert_eq!(id.culture, "neutral");
        assert_eq!(id.public_key_token.unwrap(), PublicKeyToken::MSCORLIB);
    }

    #[test]
    fn identity_parse_no_token() {
        let s = "MyLib, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
        let id = AssemblyIdentity::parse(s).unwrap();
        assert!(!id.is_strong_named());
    }

    #[test]
    fn identity_roundtrip() {
        let id = AssemblyIdentity::new(
            "TestLib",
            "2.0.0.0",
            "neutral",
            Some(PublicKeyToken::MSCORLIB),
        );
        let s = id.to_qualified_name();
        let parsed = AssemblyIdentity::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn identity_major_version() {
        let id = AssemblyIdentity::unsigned("Foo", "4.5.6.7");
        assert_eq!(id.major_version(), 4);
        assert!(id.is_net4());
    }

    #[test]
    fn identity_unsigned_constructor() {
        let id = AssemblyIdentity::unsigned("Bar", "1.0.0.0");
        assert!(!id.is_strong_named());
        assert_eq!(id.culture, "neutral");
    }

    #[test]
    fn identity_version_matches() {
        let a = AssemblyIdentity::unsigned("X", "4.0.0.0");
        let b = AssemblyIdentity::unsigned("X", "4.0.0.0");
        let c = AssemblyIdentity::unsigned("X", "3.0.0.0");
        assert!(a.version_matches(&b));
        assert!(!a.version_matches(&c));
    }

    // ── GacResolver ───────────────────────────────────────────────────────────

    #[test]
    fn gac_dotnet4_defaults_contain_mscorlib() {
        let gac = GacResolver::with_dotnet4_defaults();
        let id = AssemblyIdentity::parse(
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        )
        .unwrap();
        assert!(gac.resolve(&id).is_ok());
    }

    #[test]
    fn gac_dotnet4_defaults_count() {
        let gac = GacResolver::with_dotnet4_defaults();
        assert!(gac.count() >= 5);
    }

    #[test]
    fn gac_not_found_error() {
        let gac = GacResolver::new();
        let id = AssemblyIdentity::unsigned("Unknown", "1.0.0.0");
        assert!(matches!(
            gac.resolve(&id),
            Err(StrongNameError::NotFoundInGac(_))
        ));
    }

    #[test]
    fn gac_register_and_resolve() {
        let mut gac = GacResolver::new();
        let id = AssemblyIdentity::unsigned("MyLib", "1.0.0.0");
        gac.register(id.to_qualified_name(), "/path/to/mylib.dll".to_string());
        let path = gac.resolve(&id).unwrap();
        assert_eq!(path, "/path/to/mylib.dll");
    }

    #[test]
    fn gac_contains_check() {
        let mut gac = GacResolver::new();
        let id = AssemblyIdentity::unsigned("X", "1.0.0.0");
        assert!(!gac.contains(&id));
        gac.register(id.to_qualified_name(), "x.dll".to_string());
        assert!(gac.contains(&id));
    }

    #[test]
    fn gac_unregister() {
        let mut gac = GacResolver::new();
        let id = AssemblyIdentity::unsigned("Y", "1.0.0.0");
        gac.register(id.to_qualified_name(), "y.dll".to_string());
        assert!(gac.unregister(&id));
        assert!(!gac.contains(&id));
    }

    #[test]
    fn gac_list_assemblies_sorted() {
        let gac = GacResolver::with_dotnet4_defaults();
        let names = gac.list_assemblies();
        for w in names.windows(2) {
            assert!(w[0] <= w[1], "not sorted");
        }
    }

    #[test]
    fn gac_version_wildcard_fallback() {
        let mut gac = GacResolver::with_dotnet4_defaults();
        gac.allow_version_wildcard = true;
        let id = AssemblyIdentity::parse(
            "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        )
        .unwrap();
        // Should fall back to the 4.0 version.
        assert!(gac.resolve(&id).is_ok());
    }
}
