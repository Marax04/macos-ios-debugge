//! `rustre-loader-android::signing_v4`
//!
//! APK Signature Scheme v4 (`.idsig` sidecar file) parser and verifier stub.
//!
//! APK Signature Scheme v4 was introduced in Android 11.  It stores a compact
//! per-block Merkle tree built from SHA-256 digests of 4 KiB chunks of the APK
//! data, along with the v2/v3 APK digest, in a `.idsig` sidecar file that sits
//! alongside the APK on the filesystem.
//!
//! # References
//! - AOSP `tools/apksig/src/main/java/com/android/apksig/internal/apk/v4/`
//! - Android developer docs: APK Signature Scheme v4

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// V4SignatureError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the v4 signature parser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum V4SignatureError {
    #[error("truncated v4 signature file")]
    Truncated,
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// V4SignatureFile
// ─────────────────────────────────────────────────────────────────────────────

/// The parsed `.idsig` file that accompanies an APK for v4 signing.
///
/// File layout:
/// ```text
/// [0..4]    version          — LE u32 (current = 2)
/// [4..8]    hash_tree_size   — LE u32
/// [8..12]   signing_info_size — LE u32
/// [12..12+hash_tree_size]  hash tree bytes
/// [12+hash_tree_size .. +signing_info_size]  signing info bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4SignatureFile {
    /// File format version (currently 2).
    pub version: u32,
    /// Parsed hash tree (Merkle tree of 4 KiB chunk digests).
    pub hash_tree: MerkleTree,
    /// Parsed v4 integrity metadata (contains the APK digest).
    pub signing_info: V4IntegrityMetadata,
}

impl V4SignatureFile {
    /// Current `.idsig` format version.
    pub const CURRENT_VERSION: u32 = 2;

    /// Parse a `.idsig` file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`V4SignatureError`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, V4SignatureError> {
        if data.len() < 12 {
            return Err(V4SignatureError::Truncated);
        }
        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if version != Self::CURRENT_VERSION {
            return Err(V4SignatureError::UnsupportedVersion(version));
        }
        let hash_tree_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let signing_info_size = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;

        let ht_start = 12usize;
        let ht_end = ht_start + hash_tree_size;
        let si_end = ht_end + signing_info_size;

        if si_end > data.len() {
            return Err(V4SignatureError::Truncated);
        }

        let hash_tree = MerkleTree::parse(&data[ht_start..ht_end])?;
        let signing_info = V4IntegrityMetadata::parse(&data[ht_end..si_end])?;

        Ok(Self {
            version,
            hash_tree,
            signing_info,
        })
    }

    /// Total file size that was parsed.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        12 + self.hash_tree.raw.len() + self.signing_info.raw.len()
    }
}

impl fmt::Display for V4SignatureFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "V4SignatureFile v{} tree_nodes={} apk_digest_len={}",
            self.version,
            self.hash_tree.node_count(),
            self.signing_info.apk_digest.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MerkleTree
// ─────────────────────────────────────────────────────────────────────────────

/// A SHA-256 Merkle tree built from 4 KiB data chunks of the APK.
///
/// The tree is stored in the `.idsig` file in bottom-up order (leaves first).
/// Each leaf is SHA-256( 0x00 || `chunk_data`[4096 bytes] ).  Internal nodes are
/// SHA-256( 0x01 || `left_hash` || `right_hash` ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// SHA-256 hash of the Merkle tree root (32 bytes).
    pub root_hash: Vec<u8>,
    /// All hash nodes in bottom-up order, 32 bytes each.
    pub nodes: Vec<[u8; 32]>,
    /// Raw bytes as stored in the `.idsig` file.
    pub raw: Vec<u8>,
}

impl MerkleTree {
    /// SHA-256 digest size in bytes.
    pub const HASH_SIZE: usize = 32;
    /// Data chunk size used to build leaves (4 KiB).
    pub const CHUNK_SIZE: usize = 4096;

    /// Parse a Merkle tree from the hash-tree section bytes.
    ///
    /// # Errors
    ///
    /// Returns [`V4SignatureError::Parse`] when the byte length is not a
    /// multiple of 32.
    pub fn parse(data: &[u8]) -> Result<Self, V4SignatureError> {
        if !data.len().is_multiple_of(Self::HASH_SIZE) {
            return Err(V4SignatureError::Parse(format!(
                "hash tree length {} is not a multiple of 32",
                data.len()
            )));
        }
        let nodes: Vec<[u8; 32]> = data
            .chunks_exact(Self::HASH_SIZE)
            .map(|c| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(c);
                arr
            })
            .collect();

        // The root is the last node in the bottom-up ordering.
        let root_hash = nodes.last().map(|n| n.to_vec()).unwrap_or_default();

        Ok(Self {
            root_hash,
            nodes,
            raw: data.to_vec(),
        })
    }

    /// Build a `MerkleTree` from raw APK data by hashing 4 KiB chunks.
    ///
    /// This is a pure-Rust implementation of the v4 tree construction.
    /// Note: this uses a placeholder hash (all-zeros) since we don't depend on
    /// a SHA-256 crate here.  In production, replace `sha256_chunk` with a real
    /// SHA-256 call.
    #[must_use]
    pub fn build_from_data(apk_data: &[u8]) -> Self {
        let chunk_count = apk_data.len().div_ceil(Self::CHUNK_SIZE).max(1);
        let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(chunk_count * 2);

        // Leaf hashes (placeholder — real impl would call SHA-256)
        for i in 0..chunk_count {
            let start = i * Self::CHUNK_SIZE;
            let end = (start + Self::CHUNK_SIZE).min(apk_data.len());
            let chunk = &apk_data[start..end];
            nodes.push(placeholder_hash(chunk));
        }

        // Build internal nodes until only root remains.
        let mut level_start = 0usize;
        let mut level_count = nodes.len();
        while level_count > 1 {
            let next_level_start = nodes.len();
            let mut i = level_start;
            while i < level_start + level_count {
                let left = nodes[i];
                let right = if i + 1 < level_start + level_count {
                    nodes[i + 1]
                } else {
                    left
                };
                nodes.push(combine_hashes(&left, &right));
                i += 2;
            }
            level_start = next_level_start;
            level_count = nodes.len() - next_level_start;
        }

        let root_hash = nodes.last().map(|n| n.to_vec()).unwrap_or(vec![0u8; 32]);
        let mut raw: Vec<u8> = Vec::with_capacity(nodes.len() * 32);
        for n in &nodes {
            raw.extend_from_slice(n);
        }
        Self {
            root_hash,
            nodes,
            raw,
        }
    }

    /// Number of nodes in the tree (leaves + internal nodes).
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of leaf nodes (one per 4 KiB chunk).
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        if self.nodes.is_empty() {
            0
        } else {
            // Leaves are approximately ceil(n+1) / 2 but for display we just
            // report the stored node count.
            self.nodes.len().div_ceil(2)
        }
    }

    /// Return the root hash as a hex string.
    #[must_use]
    pub fn root_hash_hex(&self) -> String {
        self.root_hash.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }
}

/// Placeholder (non-cryptographic) hash for testing/build purposes.
fn placeholder_hash(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    let mut acc: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        acc = acc.wrapping_add(u64::from(b)).wrapping_mul(0x1000003D);
        h[i % 32] ^= (acc & 0xFF) as u8;
    }
    h
}

fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for i in 0..32 {
        h[i] = left[i] ^ right[i] ^ 0x01;
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// V4Signature
// ─────────────────────────────────────────────────────────────────────────────

/// A single v4 signature entry (one per signing certificate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4Signature {
    /// The v2/v3 APK digest this signature covers (length-prefixed bytes).
    pub apk_digest: Vec<u8>,
    /// The hash tree root hash.
    pub raw_root_hash: Vec<u8>,
    /// Additional signing info (certificate chain, etc.) as raw bytes.
    pub additional_data: Vec<u8>,
}

impl V4Signature {
    /// Parse a `V4Signature` from `data` at `offset`, returning `(sig, bytes_read)`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let digest_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if 4 + digest_len > data.len() {
            return None;
        }
        let apk_digest = data[4..4 + digest_len].to_vec();
        let mut off = 4 + digest_len;

        if off + 4 > data.len() {
            return None;
        }
        let root_len = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
        off += 4;
        if off + root_len > data.len() {
            return None;
        }
        let raw_root_hash = data[off..off + root_len].to_vec();
        off += root_len;

        let additional_data = data[off..].to_vec();
        let consumed = data.len(); // consume all
        Some((
            Self {
                apk_digest,
                raw_root_hash,
                additional_data,
            },
            consumed,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V4IntegrityMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// Integrity metadata in the `.idsig` signing-info section.
///
/// Contains the APK content digest (from v2/v3 signing) and additional
/// attributes needed for Incremental FS block-level verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4IntegrityMetadata {
    /// APK content digest matching the v2/v3 signing block (SHA-256).
    pub apk_digest: Vec<u8>,
    /// V4 signature list (one per signer).
    pub signatures: Vec<V4Signature>,
    /// Additional attributes as raw bytes.
    pub attributes: Vec<u8>,
    /// Raw bytes as stored in the file.
    pub raw: Vec<u8>,
}

impl V4IntegrityMetadata {
    /// Parse the signing-info section of a `.idsig` file.
    ///
    /// # Errors
    ///
    /// Returns [`V4SignatureError::Parse`] when the data is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, V4SignatureError> {
        // Minimal: first 4 bytes = digest length, then digest bytes.
        let raw = data.to_vec();
        if data.len() < 4 {
            return Ok(Self {
                apk_digest: vec![],
                signatures: vec![],
                attributes: vec![],
                raw,
            });
        }
        let digest_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let apk_digest = if 4 + digest_len <= data.len() {
            data[4..4 + digest_len].to_vec()
        } else {
            vec![]
        };

        Ok(Self {
            apk_digest,
            signatures: vec![],
            attributes: vec![],
            raw,
        })
    }

    /// Return the APK digest as a hex string.
    #[must_use]
    pub fn apk_digest_hex(&self) -> String {
        self.apk_digest.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_v4_signature / verify_v4_signature
// ─────────────────────────────────────────────────────────────────────────────

/// Detect whether `data` is a v4 `.idsig` file.
///
/// The detection is based on the file structure: version u32 at offset 0 must
/// be 2 (the only known version), and the length fields must be consistent with
/// the available data.
#[must_use]
pub fn detect_v4_signature(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
    if version != V4SignatureFile::CURRENT_VERSION {
        return false;
    }
    let ht_size = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])) as usize;
    let si_size = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;
    12usize.checked_add(ht_size).and_then(|n| n.checked_add(si_size)).is_some_and(|total| total <= data.len())
}

/// Stub for v4 signature verification.
///
/// A real implementation would:
/// 1. Parse the `.idsig` file.
/// 2. Compute the Merkle tree from the APK data and compare the root.
/// 3. Verify the v2/v3 APK digest embedded in the signing info.
/// 4. Validate the certificate chain.
///
/// Returns `Ok(true)` when the structure is consistent (no digest verification
/// since we don't depend on a crypto crate).
pub fn verify_v4_signature(idsig_data: &[u8], _apk_data: &[u8]) -> Result<bool, V4SignatureError> {
    if !detect_v4_signature(idsig_data) {
        return Err(V4SignatureError::InvalidMagic);
    }
    let sig_file = V4SignatureFile::parse(idsig_data)?;
    // Stub: structural validity only.
    Ok(!sig_file.hash_tree.nodes.is_empty() || sig_file.hash_tree.raw.is_empty())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_idsig(hash_tree: &[u8], signing_info: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2_u32.to_le_bytes()); // version
        v.extend_from_slice(&(hash_tree.len() as u32).to_le_bytes());
        v.extend_from_slice(&(signing_info.len() as u32).to_le_bytes());
        v.extend_from_slice(hash_tree);
        v.extend_from_slice(signing_info);
        v
    }

    // ── detect_v4_signature ───────────────────────────────────────────────────

    #[test]
    fn test_detect_v4_empty_tree() {
        let data = make_idsig(&[], &[]);
        assert!(detect_v4_signature(&data));
    }

    #[test]
    fn test_detect_v4_with_tree() {
        let tree = [0u8; 32]; // one node
        let data = make_idsig(&tree, &[]);
        assert!(detect_v4_signature(&data));
    }

    #[test]
    fn test_detect_v4_too_short() {
        assert!(!detect_v4_signature(&[0u8; 11]));
    }

    #[test]
    fn test_detect_v4_wrong_version() {
        let mut data = make_idsig(&[], &[]);
        data[0..4].copy_from_slice(&1_u32.to_le_bytes()); // version=1
        assert!(!detect_v4_signature(&data));
    }

    // ── V4SignatureFile parsing ────────────────────────────────────────────────

    #[test]
    fn test_parse_v4_empty_sections() {
        let data = make_idsig(&[], &[]);
        let sf = V4SignatureFile::parse(&data).unwrap();
        assert_eq!(sf.version, 2);
        assert_eq!(sf.hash_tree.node_count(), 0);
    }

    #[test]
    fn test_parse_v4_one_node_tree() {
        let tree = [0xab_u8; 32];
        let data = make_idsig(&tree, &[]);
        let sf = V4SignatureFile::parse(&data).unwrap();
        assert_eq!(sf.hash_tree.node_count(), 1);
        assert_eq!(sf.hash_tree.root_hash, &[0xab_u8; 32]);
    }

    #[test]
    fn test_parse_v4_unsupported_version() {
        let mut data = make_idsig(&[], &[]);
        data[0..4].copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            V4SignatureFile::parse(&data),
            Err(V4SignatureError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn test_parse_v4_truncated() {
        let data = [0x02, 0x00, 0x00, 0x00]; // version only
        assert!(matches!(
            V4SignatureFile::parse(&data),
            Err(V4SignatureError::Truncated)
        ));
    }

    #[test]
    fn test_v4_file_display() {
        let data = make_idsig(&[0u8; 32], &[]);
        let sf = V4SignatureFile::parse(&data).unwrap();
        let s = sf.to_string();
        assert!(s.contains("V4SignatureFile"));
        assert!(s.contains("tree_nodes=1"));
    }

    // ── MerkleTree ────────────────────────────────────────────────────────────

    #[test]
    fn test_merkle_tree_parse_single_node() {
        let node = [0x55_u8; 32];
        let tree = MerkleTree::parse(&node).unwrap();
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.root_hash, &[0x55_u8; 32]);
    }

    #[test]
    fn test_merkle_tree_parse_two_nodes() {
        let nodes = [0u8; 64]; // 2 nodes
        let tree = MerkleTree::parse(&nodes).unwrap();
        assert_eq!(tree.node_count(), 2);
    }

    #[test]
    fn test_merkle_tree_parse_bad_length() {
        let bad = [0u8; 33]; // not multiple of 32
        assert!(MerkleTree::parse(&bad).is_err());
    }

    #[test]
    fn test_merkle_tree_root_hash_hex() {
        let node = [0xAB_u8; 32];
        let tree = MerkleTree::parse(&node).unwrap();
        let hex = tree.root_hash_hex();
        assert_eq!(hex, "ab".repeat(32));
    }

    #[test]
    fn test_merkle_tree_build_empty() {
        let tree = MerkleTree::build_from_data(&[]);
        assert!(!tree.nodes.is_empty()); // at least one leaf for empty data
    }

    #[test]
    fn test_merkle_tree_build_single_chunk() {
        let data = vec![0u8; 1024];
        let tree = MerkleTree::build_from_data(&data);
        assert_eq!(tree.node_count(), 1); // 1 leaf = 1 root
    }

    #[test]
    fn test_merkle_tree_build_two_chunks() {
        let data = vec![0u8; MerkleTree::CHUNK_SIZE + 100];
        let tree = MerkleTree::build_from_data(&data);
        // 2 leaves + 1 root = 3 nodes
        assert_eq!(tree.node_count(), 3);
    }

    // ── V4IntegrityMetadata ───────────────────────────────────────────────────

    #[test]
    fn test_v4_integrity_metadata_empty() {
        let meta = V4IntegrityMetadata::parse(&[]).unwrap();
        assert!(meta.apk_digest.is_empty());
        assert_eq!(meta.apk_digest_hex(), "");
    }

    #[test]
    fn test_v4_integrity_metadata_with_digest() {
        let mut data = Vec::new();
        data.extend_from_slice(&32_u32.to_le_bytes()); // digest len
        data.extend_from_slice(&[0xAB_u8; 32]); // digest
        let meta = V4IntegrityMetadata::parse(&data).unwrap();
        assert_eq!(meta.apk_digest, &[0xAB_u8; 32]);
        assert_eq!(meta.apk_digest_hex(), "ab".repeat(32));
    }

    // ── verify_v4_signature ───────────────────────────────────────────────────

    #[test]
    fn test_verify_v4_empty_tree() {
        let data = make_idsig(&[], &[]);
        let result = verify_v4_signature(&data, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_v4_invalid_data() {
        let result = verify_v4_signature(&[0u8; 12], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_v4_with_node() {
        let tree = [0u8; 32];
        let data = make_idsig(&tree, &[]);
        let result = verify_v4_signature(&data, b"fake apk data");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
