//! `sig_file_loader` — Load FLIRT `.sig` binary files into structured form.
//!
//! Provides [`SigFileLoader`] which parses the IDASGN binary format into a
//! list of [`SigNode`] records ready for use by the recognition engine.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::FlirtError;

// ─── SigHeader ───────────────────────────────────────────────────────────────

/// Magic bytes at the start of every IDA `.sig` file.
pub const SIG_MAGIC: &[u8; 6] = b"IDASGN";

/// Minimum supported `.sig` format version.
pub const SIG_VERSION_MIN: u8 = 5;

/// Maximum supported `.sig` format version.
pub const SIG_VERSION_MAX: u8 = 10;

/// Decoded fixed header of an IDA `.sig` file.
///
/// The header layout (all fields little-endian unless noted):
///
/// ```text
/// [0..6]   magic         b"IDASGN"
/// [6]      version       u8
/// [7]      arch          u8   (processor family)
/// [8..12]  file_types    u32
/// [12..14] os_types      u16
/// [14..16] app_types     u16
/// [16..18] feature_flags u16
/// [18..20] old_n_funcs   u16
/// [20..22] crc16         u16
/// [22..34] ctype_crc     [u8; 12]
/// [34..38] n_funcs       u32
/// [38..40] pattern_size  u16
/// [40..104] lib_name     [u8; 64] (null-terminated)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigHeader {
    /// Format version byte (5–10).
    pub version: u8,
    /// CPU architecture code (0 = x86, 75 = x86-64, …).
    pub arch: u8,
    /// Supported file-type bitmask.
    pub file_types: u32,
    /// Supported OS bitmask.
    pub os_types: u16,
    /// Application-type bitmask.
    pub app_types: u16,
    /// Feature flags.
    pub feature_flags: u16,
    /// Number of functions (legacy 16-bit field).
    pub old_n_funcs: u16,
    /// Header CRC-16 (covers bytes 0..20).
    pub crc16: u16,
    /// CRC of the C-type information.
    pub ctype_crc: [u8; 12],
    /// Number of functions (32-bit, v9+).
    pub n_funcs: u32,
    /// Leading pattern byte count used in trie keys.
    pub pattern_size: u16,
    /// Human-readable library name (null-terminated, up to 64 bytes).
    pub lib_name: String,
}

impl SigHeader {
    /// Smallest possible header: the fixed part up to and including
    /// `pattern_size`, with a zero-length library name.
    ///
    /// The IDA header is **variable length** — the library name follows the
    /// fixed fields — so this is a lower bound, not "the" size. Use
    /// [`SigHeader::header_len`] for the actual end of the header, which is
    /// where the pattern trie begins.
    pub const MIN_SIZE: usize = 43;

    /// Byte offset of `library_name_len` in the published layout.
    const OFF_NAME_LEN: usize = 34;
    /// Byte offset of `alt_ctype_crc`.
    const OFF_ALT_CTYPE_CRC: usize = 35;
    /// Byte offset of the 32-bit function count (v6+).
    const OFF_N_FUNCTIONS: usize = 37;
    /// Byte offset of `pattern_size` (v8+).
    const OFF_PATTERN_SIZE: usize = 41;
    /// Byte offset where the library name starts.
    const OFF_NAME: usize = 43;

    /// Deprecated alias kept so existing call sites keep compiling.
    ///
    /// It is **not** the real header size: the header is variable length.
    /// Prefer [`SigHeader::header_len`].
    #[deprecated(note = "the IDA header is variable length; use header_len()")]
    pub const SIZE: usize = 104;

    /// Total header length in bytes, i.e. the offset at which the pattern trie
    /// starts: the fixed fields plus the library name.
    #[must_use]
    pub fn header_len(&self) -> usize {
        Self::OFF_NAME + self.lib_name.len()
    }

    /// Parse a `SigHeader` from the first [`SigHeader::SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::InvalidSigFile`] when the buffer is too short or
    /// the magic bytes do not match, and [`FlirtError::Parse`] for unsupported
    /// version numbers.
    ///
    /// # Panics
    ///
    /// Panics if the byte slices cannot be converted to fixed-size arrays (cannot
    /// occur given the length checks at the start of this function).
    pub fn parse(raw: &[u8]) -> Result<Self, FlirtError> {
        // Layout below follows IDA's published `.sig` header (flair):
        //
        //   off size field
        //     0    6 magic "IDASGN"
        //     6    1 version
        //     7    1 processor / arch
        //     8    4 file_types
        //    12    2 os_types
        //    14    2 app_types
        //    16    2 feature_flags
        //    18    2 old_n_functions
        //    20    2 crc16
        //    22   12 ctype
        //    34    1 library_name_len       <-- one BYTE
        //    35    2 alt_ctype_crc
        //    37    4 n_functions            (v6+)
        //    41    2 pattern_size           (v8+)
        //    43   .. library name
        //
        // This parser previously read `n_funcs` as a u32 at offset 34 and took
        // the library name from a fixed 40..104 window. That layout is not IDA's
        // and did not match this project's own writer either
        // (`rustre_flirt::FlirtSigSerializer::write_header`), so a `.sig` from
        // flair — or from our own serializer — could never be read. The defect
        // was invisible because the parser was perfectly self-consistent.
        if raw.len() < Self::MIN_SIZE {
            return Err(FlirtError::InvalidSigFile);
        }
        if &raw[0..6] != SIG_MAGIC {
            return Err(FlirtError::InvalidSigFile);
        }
        let version = raw[6];
        if !(SIG_VERSION_MIN..=SIG_VERSION_MAX).contains(&version) {
            return Err(FlirtError::Parse(format!(
                "unsupported .sig version: {version}"
            )));
        }
        let arch = raw[7];
        let file_types = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let os_types = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let app_types = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        let feature_flags = u16::from_le_bytes(raw[16..18].try_into().unwrap());
        let old_n_funcs = u16::from_le_bytes(raw[18..20].try_into().unwrap());
        let crc16 = u16::from_le_bytes(raw[20..22].try_into().unwrap());
        let mut ctype_crc = [0u8; 12];
        ctype_crc.copy_from_slice(&raw[22..34]);

        let name_len = usize::from(raw[Self::OFF_NAME_LEN]);
        let _alt_ctype_crc = u16::from_le_bytes(
            raw[Self::OFF_ALT_CTYPE_CRC..Self::OFF_ALT_CTYPE_CRC + 2]
                .try_into()
                .unwrap(),
        );
        // `n_functions` is v6+ and `pattern_size` v8+; older files simply do not
        // carry them, and inventing a value would be worse than reporting zero.
        let n_funcs = if version >= 6 {
            u32::from_le_bytes(
                raw[Self::OFF_N_FUNCTIONS..Self::OFF_N_FUNCTIONS + 4]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from(old_n_funcs)
        };
        let pattern_size = if version >= 8 {
            u16::from_le_bytes(
                raw[Self::OFF_PATTERN_SIZE..Self::OFF_PATTERN_SIZE + 2]
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };

        // A declared name length that runs past the buffer is a malformed file,
        // not something to clamp silently: a `.sig` is untrusted third-party
        // input, and a truncated name would produce a plausible-looking library
        // identity that is simply wrong.
        let name_end = Self::OFF_NAME
            .checked_add(name_len)
            .ok_or(FlirtError::InvalidSigFile)?;
        if name_end > raw.len() {
            return Err(FlirtError::Parse(format!(
                "library_name_len {name_len} runs past the end of a {}-byte file",
                raw.len()
            )));
        }
        let name_bytes = &raw[Self::OFF_NAME..name_end];
        // IDA writes the name without a terminator, but tolerate one.
        let name_bytes = name_bytes
            .split(|&b| b == 0)
            .next()
            .unwrap_or(name_bytes);
        let lib_name = String::from_utf8_lossy(name_bytes).into_owned();
        Ok(Self {
            version,
            arch,
            file_types,
            os_types,
            app_types,
            feature_flags,
            old_n_funcs,
            crc16,
            ctype_crc,
            n_funcs,
            pattern_size,
            lib_name,
        })
    }

    /// Verify the header CRC-16 (covers bytes `[0..20]`).
    #[must_use]
    pub fn verify_crc(&self, raw: &[u8]) -> bool {
        if raw.len() < 22 {
            return false;
        }
        let computed = crate::crc16_flirt(&raw[0..20]);
        computed == self.crc16
    }

    /// Human-readable architecture name.
    #[must_use]
    pub const fn arch_name(&self) -> &'static str {
        match self.arch {
            0 => "x86",
            75 => "x86-64",
            _ => "unknown",
        }
    }
}

impl fmt::Display for SigHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigHeader(v{} {} lib={:?} n_funcs={} pattern_size={})",
            self.version,
            self.arch_name(),
            self.lib_name,
            self.n_funcs,
            self.pattern_size,
        )
    }
}

// ─── SigNodeKind ─────────────────────────────────────────────────────────────

/// Whether a `SigNode` is an internal trie node or a leaf carrying metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigNodeKind {
    /// Internal node — trie split point, no function metadata.
    Internal,
    /// Leaf node carrying CRC and function name data.
    Leaf {
        /// CRC offset (bytes after the pattern body).
        crc_offset: u16,
        /// CRC region length in bytes.
        crc_len: u16,
        /// Expected CRC-16 value.
        crc: u16,
        /// Primary function name for this pattern.
        primary_name: String,
        /// Additional public names `(offset_into_func, name)`.
        public_names: Vec<(u32, String)>,
    },
}

// ─── SigLeafParams ───────────────────────────────────────────────────────────

/// Parameters for constructing a [`SigNode`] leaf, bundled to avoid
/// exceeding the `clippy::too_many_arguments` limit.
pub struct SigLeafParams {
    /// Byte sequence stored at this trie depth.
    pub bytes: Vec<u8>,
    /// Per-byte mask.
    pub mask: Vec<u8>,
    /// Full pattern accumulated from root.
    pub full_pattern: Vec<u8>,
    /// Full mask accumulated from root.
    pub full_mask: Vec<u8>,
    /// Library name.
    pub lib_name: String,
    /// Depth in the trie.
    pub depth: u32,
    /// CRC offset.
    pub crc_offset: u16,
    /// CRC region length.
    pub crc_len: u16,
    /// Expected CRC-16.
    pub crc: u16,
    /// Primary function name.
    pub primary_name: String,
    /// Additional public names.
    pub public_names: Vec<(u32, String)>,
}

// ─── SigNode ─────────────────────────────────────────────────────────────────

/// A decoded node in the FLIRT signature trie.
///
/// Each node carries a byte sequence (the pattern fragment at this depth) and
/// is either an internal branch or a leaf with function identity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigNode {
    /// Byte sequence stored at this trie depth.
    pub bytes: Vec<u8>,
    /// Per-byte mask: `0xFF` = exact match required, `0x00` = wildcard.
    pub mask: Vec<u8>,
    /// Full pattern (accumulated from root to this node).
    pub full_pattern: Vec<u8>,
    /// Full mask (accumulated from root to this node).
    pub full_mask: Vec<u8>,
    /// Whether this node is a leaf with metadata.
    pub kind: SigNodeKind,
    /// Library name inherited from the file header.
    pub lib_name: String,
    /// Depth in the trie (0 = root children).
    pub depth: u32,
}

impl SigNode {
    /// Create an internal node.
    #[must_use]
    pub const fn internal(
        bytes: Vec<u8>,
        mask: Vec<u8>,
        full_pattern: Vec<u8>,
        full_mask: Vec<u8>,
        lib_name: String,
        depth: u32,
    ) -> Self {
        Self {
            bytes,
            mask,
            full_pattern,
            full_mask,
            kind: SigNodeKind::Internal,
            lib_name,
            depth,
        }
    }

    /// Create a leaf node.
    #[must_use]
    pub fn leaf(params: SigLeafParams) -> Self {
        Self {
            bytes: params.bytes,
            mask: params.mask,
            full_pattern: params.full_pattern,
            full_mask: params.full_mask,
            kind: SigNodeKind::Leaf {
                crc_offset: params.crc_offset,
                crc_len: params.crc_len,
                crc: params.crc,
                primary_name: params.primary_name,
                public_names: params.public_names,
            },
            lib_name: params.lib_name,
            depth: params.depth,
        }
    }

    /// Return the primary function name if this is a leaf.
    #[must_use]
    pub fn primary_name(&self) -> Option<&str> {
        match &self.kind {
            SigNodeKind::Leaf { primary_name, .. } => Some(primary_name),
            SigNodeKind::Internal => None,
        }
    }

    /// Returns `true` if this node is a trie leaf.
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        matches!(self.kind, SigNodeKind::Leaf { .. })
    }

    /// Pattern length in bytes.
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        self.full_pattern.len()
    }
}

impl fmt::Display for SigNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SigNodeKind::Leaf { primary_name, .. } => {
                write!(f, "SigNode::Leaf({primary_name} depth={})", self.depth)
            }
            SigNodeKind::Internal => {
                write!(f, "SigNode::Internal(depth={})", self.depth)
            }
        }
    }
}

// ─── SigFileLoader ───────────────────────────────────────────────────────────

/// Configuration controlling how the loader behaves.
#[derive(Debug, Clone)]
pub struct LoaderOptions {
    /// Maximum trie depth to traverse (prevents stack overflow on corrupt files).
    pub max_depth: u32,
    /// If `true`, silently skip nodes that fail to parse.
    pub lenient: bool,
    /// If `true`, verify the header CRC-16 and reject mismatches.
    pub verify_header_crc: bool,
}

impl Default for LoaderOptions {
    fn default() -> Self {
        Self {
            max_depth: 512,
            lenient: true,
            verify_header_crc: false,
        }
    }
}

/// Loads and decodes IDA FLIRT `.sig` binary files.
///
/// Exposes both the decoded [`SigHeader`] and a flat list of [`SigNode`] leaf
/// nodes extracted by traversing the pattern trie.
pub struct SigFileLoader {
    /// Configuration.
    pub options: LoaderOptions,
}

impl SigFileLoader {
    /// Create a loader with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: LoaderOptions::default(),
        }
    }

    /// Create a loader with custom options.
    #[must_use]
    pub const fn with_options(options: LoaderOptions) -> Self {
        Self { options }
    }

    /// Load a `.sig` file from `path`.
    ///
    /// Returns the decoded [`SigHeader`] and all leaf [`SigNode`]s.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::Io`] when the file cannot be read, and
    /// [`FlirtError::InvalidSigFile`] or [`FlirtError::Parse`] for malformed
    /// files.
    pub fn load(&self, path: &Path) -> Result<LoadedSigFile, FlirtError> {
        let raw = std::fs::read(path)?;
        self.load_from_bytes(&raw, Some(path.to_path_buf()))
    }

    /// Load a `.sig` file from an in-memory byte slice.
    ///
    /// # Errors
    ///
    /// Same as [`SigFileLoader::load`].
    pub fn load_from_bytes(
        &self,
        raw: &[u8],
        path: Option<PathBuf>,
    ) -> Result<LoadedSigFile, FlirtError> {
        let header = SigHeader::parse(raw)?;
        if self.options.verify_header_crc && !header.verify_crc(raw) {
            return Err(FlirtError::Parse(
                "header CRC-16 mismatch in .sig file".to_owned(),
            ));
        }
        // The header is variable length — the library name is the last field —
        // so the trie starts where the header actually ends, not at a constant.
        // Using a fixed 104 meant the trie was read from the wrong offset for
        // every library whose name is not exactly 61 bytes.
        let trie_start = header.header_len();
        let mut nodes: Vec<SigNode> = Vec::new();
        let mut pos = trie_start;
        let ctx = TrieCtx {
            data: raw,
            lib_name: &header.lib_name,
            max_depth: self.options.max_depth,
            lenient: self.options.lenient,
        };
        decode_trie(&ctx, &mut pos, &mut Vec::new(), &mut Vec::new(), 0, &mut nodes);
        let leaf_count = nodes.iter().filter(|n| n.is_leaf()).count();
        Ok(LoadedSigFile {
            header,
            nodes,
            leaf_count,
            source_path: path,
            raw_size: raw.len(),
        })
    }
}

impl Default for SigFileLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SigFileLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigFileLoader(lenient={})", self.options.lenient)
    }
}

// ─── LoadedSigFile ────────────────────────────────────────────────────────────

/// Result of loading a `.sig` file.
pub struct LoadedSigFile {
    /// Parsed header.
    pub header: SigHeader,
    /// All trie nodes (both internal and leaf).
    pub nodes: Vec<SigNode>,
    /// Number of leaf nodes (= distinct functions).
    pub leaf_count: usize,
    /// Source path, if the file was loaded from disk.
    pub source_path: Option<PathBuf>,
    /// Raw file size in bytes.
    pub raw_size: usize,
}

impl LoadedSigFile {
    /// Iterator over leaf nodes only.
    pub fn leaves(&self) -> impl Iterator<Item = &SigNode> {
        self.nodes.iter().filter(|n| n.is_leaf())
    }

    /// All primary function names found in the file.
    #[must_use]
    pub fn function_names(&self) -> Vec<&str> {
        self.leaves()
            .filter_map(|n| n.primary_name())
            .collect()
    }

    /// Build a flat list of [`crate::FlirtSignature`]s from the leaf nodes.
    #[must_use]
    pub fn to_signatures(&self) -> Vec<crate::FlirtSignature> {
        self.leaves()
            .filter_map(|n| {
                if let SigNodeKind::Leaf {
                    crc_offset,
                    crc_len,
                    crc,
                    primary_name,
                    ..
                } = &n.kind
                {
                    Some(crate::FlirtSignature {
                        bytes: n.full_pattern.clone(),
                        mask: n.full_mask.clone(),
                        name: primary_name.clone(),
                        lib_name: n.lib_name.clone(),
                        crc_offset: *crc_offset,
                        crc_len: *crc_len,
                        crc: *crc,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Total number of nodes (internal + leaf).
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl fmt::Debug for LoadedSigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoadedSigFile(lib={:?} leaves={} raw={} bytes)",
            self.header.lib_name, self.leaf_count, self.raw_size
        )
    }
}

impl fmt::Display for LoadedSigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} functions, {} bytes)",
            self.header.lib_name, self.leaf_count, self.raw_size
        )
    }
}

// ─── Trie decoder (private) ───────────────────────────────────────────────────

/// Immutable context threaded through the recursive trie decoder to keep the
/// argument count within `clippy::too_many_arguments` limits.
struct TrieCtx<'a> {
    data: &'a [u8],
    lib_name: &'a str,
    max_depth: u32,
    lenient: bool,
}

/// Decoded CRC and name payload from a FLIRT trie leaf node.
struct LeafPayload {
    crc_offset: u16,
    crc_len: u16,
    crc: u16,
    primary_name: String,
    public_names: Vec<(u32, String)>,
}

/// Read the CRC fields and names for a leaf node.
/// Returns `None` when the data is too short.
fn read_leaf_payload(
    ctx: &TrieCtx<'_>,
    pos: &mut usize,
) -> Option<LeafPayload> {
    let data = ctx.data;
    if *pos + 5 > data.len() { return None; }
    let crc_offset = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    let crc_len = u16::from(data[*pos + 2]);
    let crc = u16::from_be_bytes([data[*pos + 3], data[*pos + 4]]);
    *pos += 5;
    let (primary_name, ok) = read_length_prefixed_name(data, pos);
    if !ok && !ctx.lenient { return None; }
    let mut public_names: Vec<(u32, String)> = Vec::new();
    while *pos < data.len() {
        let extra_len = data[*pos] as usize;
        if extra_len == 0 { *pos += 1; break; }
        if *pos + 1 + 4 + extra_len > data.len() { break; }
        *pos += 1;
        let offset = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
        *pos += 4;
        let name = String::from_utf8_lossy(&data[*pos..*pos + extra_len]).into_owned();
        *pos += extra_len;
        public_names.push((offset, name));
    }
    Some(LeafPayload { crc_offset, crc_len, crc, primary_name, public_names })
}

/// Recursive trie decoder.  `pattern` / `mask` are the cumulative byte
/// sequences from the root to the current node.
fn decode_trie(
    ctx: &TrieCtx<'_>,
    pos: &mut usize,
    pattern: &mut Vec<u8>,
    mask: &mut Vec<u8>,
    depth: u32,
    out: &mut Vec<SigNode>,
) {
    if depth > ctx.max_depth { return; }
    let data = ctx.data;
    while *pos < data.len() {
        let node_byte_count = data[*pos] as usize;
        *pos += 1;
        if node_byte_count == 0 { return; }
        let initial_depth = pattern.len();
        let mut node_bytes = Vec::with_capacity(node_byte_count);
        let mut node_mask = Vec::with_capacity(node_byte_count);
        for _ in 0..node_byte_count {
            if *pos >= data.len() {
                pattern.truncate(initial_depth); mask.truncate(initial_depth); return;
            }
            let b = data[*pos]; *pos += 1;
            node_bytes.push(b); node_mask.push(0xff);
            pattern.push(b); mask.push(0xff);
        }
        if *pos >= data.len() {
            pattern.truncate(initial_depth); mask.truncate(initial_depth); return;
        }
        let ctrl = data[*pos];
        *pos += 1; // consume ctrl byte (shared by both branches)
        if ctrl == 0 {
            out.push(SigNode::internal(
                node_bytes, node_mask,
                pattern.clone(), mask.clone(),
                ctx.lib_name.to_owned(), depth,
            ));
            decode_trie(ctx, pos, pattern, mask, depth + 1, out);
        } else {
            // ctrl == 2: the leaf carries a masked tail — the pattern bytes that
            // follow the trie key, with `0x00` in the mask marking a wildcard.
            // The trie is keyed on concrete bytes, so wildcards cannot live in
            // the key; before this existed the writer discarded them, and a
            // 16-byte pattern reached the scanner as a 3-byte one.
            // ctrl == 1 is the older leaf with no tail and still parses here
            // unchanged, so previously written files keep working.
            let mut node_bytes = node_bytes;
            let mut node_mask = node_mask;
            if ctrl == 2 {
                if *pos >= data.len() {
                    pattern.truncate(initial_depth); mask.truncate(initial_depth); return;
                }
                let tlen = data[*pos] as usize;
                *pos += 1;
                if *pos + tlen * 2 > data.len() {
                    pattern.truncate(initial_depth); mask.truncate(initial_depth); return;
                }
                let tail = &data[*pos..*pos + tlen];
                let tmask = &data[*pos + tlen..*pos + tlen * 2];
                *pos += tlen * 2;
                node_bytes.extend_from_slice(tail);
                node_mask.extend_from_slice(tmask);
                pattern.extend_from_slice(tail);
                mask.extend_from_slice(tmask);
            }
            match read_leaf_payload(ctx, pos) {
                None => { pattern.truncate(initial_depth); mask.truncate(initial_depth); return; }
                Some(leaf) => {
                    out.push(SigNode::leaf(SigLeafParams {
                        bytes: node_bytes, mask: node_mask,
                        full_pattern: pattern.clone(), full_mask: mask.clone(),
                        lib_name: ctx.lib_name.to_owned(), depth,
                        crc_offset: leaf.crc_offset,
                        crc_len: leaf.crc_len,
                        crc: leaf.crc,
                        primary_name: leaf.primary_name,
                        public_names: leaf.public_names,
                    }));
                }
            }
        }
        pattern.truncate(initial_depth); mask.truncate(initial_depth);
    }
}

/// Read a length-prefixed name string from `data` at `*pos`.
/// Returns `(name, success)`.
fn read_length_prefixed_name(data: &[u8], pos: &mut usize) -> (String, bool) {
    if *pos >= data.len() {
        return (String::new(), false);
    }
    let len = data[*pos] as usize;
    *pos += 1;
    if *pos + len > data.len() {
        return (String::new(), false);
    }
    let name = String::from_utf8_lossy(&data[*pos..*pos + len]).into_owned();
    *pos += len;
    (name, true)
}

// ─── Public convenience function ─────────────────────────────────────────────

/// Load a FLIRT `.sig` file and return `(header, leaf_nodes)`.
///
/// Uses default [`LoaderOptions`].
///
/// # Errors
///
/// See [`SigFileLoader::load`].
pub fn load_sig_file(path: &Path) -> Result<(SigHeader, Vec<SigNode>), FlirtError> {
    let loader = SigFileLoader::new();
    let file = loader.load(path)?;
    Ok((file.header, file.nodes))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header in the **published IDA layout**: `library_name_len` is a
    /// single byte at offset 34 and the name itself starts at 43.
    ///
    /// This used to write the name into a fixed 40..104 window, which is the
    /// layout the old parser invented; no real `.sig` — nor this project's own
    /// serializer — ever looked like that.
    fn make_minimal_header_bytes(version: u8) -> Vec<u8> {
        let name = b"testlib";
        let mut raw = vec![0u8; 43 + name.len()];
        raw[0..6].copy_from_slice(SIG_MAGIC);
        raw[6] = version;
        raw[7] = 0; // arch = x86
        raw[34] = u8::try_from(name.len()).unwrap(); // library_name_len
        raw[43..43 + name.len()].copy_from_slice(name);
        raw
    }

    #[test]
    fn test_sig_header_parse_valid() {
        let raw = make_minimal_header_bytes(9);
        let hdr = SigHeader::parse(&raw).unwrap();
        assert_eq!(hdr.version, 9);
        assert_eq!(hdr.arch, 0);
        assert_eq!(hdr.lib_name, "testlib");
    }

    #[test]
    fn test_sig_header_parse_too_short() {
        let raw = vec![0u8; 10];
        assert!(SigHeader::parse(&raw).is_err());
    }

    #[test]
    fn test_sig_header_bad_magic() {
        let mut raw = make_minimal_header_bytes(9);
        raw[0] = b'X';
        assert!(matches!(SigHeader::parse(&raw), Err(FlirtError::InvalidSigFile)));
    }

    #[test]
    fn test_sig_header_unsupported_version() {
        let mut raw = make_minimal_header_bytes(4);
        raw[6] = 4;
        assert!(matches!(SigHeader::parse(&raw), Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_sig_header_display() {
        let raw = make_minimal_header_bytes(9);
        let hdr = SigHeader::parse(&raw).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("testlib"));
        assert!(s.contains("v9"));
    }

    #[test]
    fn test_sig_header_arch_name_x86() {
        let raw = make_minimal_header_bytes(9);
        let hdr = SigHeader::parse(&raw).unwrap();
        assert_eq!(hdr.arch_name(), "x86");
    }

    #[test]
    fn test_sig_header_arch_name_x64() {
        let mut raw = make_minimal_header_bytes(9);
        raw[7] = 75;
        let hdr = SigHeader::parse(&raw).unwrap();
        assert_eq!(hdr.arch_name(), "x86-64");
    }

    #[test]
    fn test_sig_header_verify_crc_zero() {
        let raw = make_minimal_header_bytes(9);
        let hdr = SigHeader::parse(&raw).unwrap();
        // CRC of all-zero header won't match stored 0 (unless by coincidence)
        // Just ensure it doesn't panic.
        let _ = hdr.verify_crc(&raw);
    }

    #[test]
    fn test_sig_node_internal_creation() {
        let node = SigNode::internal(
            vec![0x55, 0x8B],
            vec![0xff, 0xff],
            vec![0x55, 0x8B],
            vec![0xff, 0xff],
            "lib".into(),
            0,
        );
        assert!(!node.is_leaf());
        assert!(node.primary_name().is_none());
        assert_eq!(node.depth, 0);
    }

    #[test]
    fn test_sig_node_leaf_creation() {
        let node = SigNode::leaf(SigLeafParams {
            bytes: vec![0x55],
            mask: vec![0xff],
            full_pattern: vec![0x55],
            full_mask: vec![0xff],
            lib_name: "lib".into(),
            depth: 1,
            crc_offset: 0,
            crc_len: 4,
            crc: 0xABCD,
            primary_name: "my_func".into(),
            public_names: vec![],
        });
        assert!(node.is_leaf());
        assert_eq!(node.primary_name(), Some("my_func"));
        assert_eq!(node.pattern_len(), 1);
    }

    #[test]
    fn test_sig_node_display_leaf() {
        let node = SigNode::leaf(SigLeafParams {
            bytes: vec![],
            mask: vec![],
            full_pattern: vec![],
            full_mask: vec![],
            lib_name: "lib".into(),
            depth: 2,
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
            primary_name: "strlen".into(),
            public_names: vec![],
        });
        let s = node.to_string();
        assert!(s.contains("strlen"));
        assert!(s.contains("Leaf"));
    }

    #[test]
    fn test_sig_node_display_internal() {
        let node = SigNode::internal(vec![], vec![], vec![], vec![], "lib".into(), 3);
        let s = node.to_string();
        assert!(s.contains("Internal"));
    }

    #[test]
    fn test_loader_empty_trie_body() {
        // A valid header with no trie body (just a single 0x00 sentinel).
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00); // end-of-trie
        let loader = SigFileLoader::new();
        let result = loader.load_from_bytes(&raw, None).unwrap();
        assert_eq!(result.leaf_count, 0);
    }

    #[test]
    fn test_loader_options_lenient_default() {
        let loader = SigFileLoader::new();
        assert!(loader.options.lenient);
        assert!(!loader.options.verify_header_crc);
    }

    #[test]
    fn test_loaded_file_function_names_empty() {
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00);
        let loader = SigFileLoader::new();
        let file = loader.load_from_bytes(&raw, None).unwrap();
        let names = file.function_names();
        assert!(names.is_empty());
    }

    #[test]
    fn test_loaded_file_to_signatures_empty() {
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00);
        let loader = SigFileLoader::new();
        let file = loader.load_from_bytes(&raw, None).unwrap();
        let sigs = file.to_signatures();
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_loaded_file_debug() {
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00);
        let loader = SigFileLoader::new();
        let file = loader.load_from_bytes(&raw, None).unwrap();
        let s = format!("{file:?}");
        assert!(s.contains("LoadedSigFile"));
    }

    #[test]
    fn test_loaded_file_display() {
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00);
        let loader = SigFileLoader::new();
        let file = loader.load_from_bytes(&raw, None).unwrap();
        let s = file.to_string();
        assert!(s.contains("testlib"));
    }

    #[test]
    fn test_loader_debug() {
        let l = SigFileLoader::new();
        assert!(!format!("{l:?}").is_empty());
    }

    #[test]
    fn test_loader_nonexistent_file() {
        let loader = SigFileLoader::new();
        let result = loader.load(Path::new("nonexistent_xyzzy.sig"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_sig_file_fn_nonexistent() {
        let r = load_sig_file(Path::new("nonexistent_abc.sig"));
        assert!(r.is_err());
    }

    #[test]
    fn test_sig_node_kind_eq() {
        assert_eq!(SigNodeKind::Internal, SigNodeKind::Internal);
    }

    #[test]
    fn test_loader_options_custom() {
        let opts = LoaderOptions {
            max_depth: 16,
            lenient: false,
            verify_header_crc: true,
        };
        let loader = SigFileLoader::with_options(opts);
        assert!(!loader.options.lenient);
        assert_eq!(loader.options.max_depth, 16);
    }

    #[test]
    fn test_loaded_file_node_count_zero() {
        let mut raw = make_minimal_header_bytes(9);
        raw.push(0x00);
        let loader = SigFileLoader::new();
        let file = loader.load_from_bytes(&raw, None).unwrap();
        // 0 nodes (trie immediately ends)
        assert_eq!(file.node_count(), 0);
    }
}
