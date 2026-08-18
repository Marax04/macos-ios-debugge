//! Canonical `IDASGN` header codec — one encoder, one decoder.
//!
//! # Why this module exists
//!
//! The stack grew **four** independent `.sig` header writers and three readers,
//! and they did not agree:
//!
//! | site | `n_functions` | library name |
//! |---|---|---|
//! | `rustre_flirt::FlirtSigSerializer` | after the name | right after `name_len` |
//! | `flirt_gen::pat_sig_format::SigFileHeader` | `u32` @34 | fixed window 40..104 |
//! | `flirt_gen::sig_writer::SigHeader` | `u32` @34 | fixed window 40..104 |
//! | `flirt_apply::sig_file_loader` (old) | `u32` @34 | fixed window 40..104 |
//! | **IDA (flair), i.e. this module** | `u32` @37 | @43, `name_len` bytes |
//!
//! Offset 34 is a **one-byte** `library_name_len`, so every "u32 at 34" reader
//! was consuming the length byte plus three bytes of something else. The layouts
//! were self-consistent within each island, which is exactly why the mismatch
//! survived: each writer round-tripped happily through its own reader.
//!
//! This is the same defect shape as the CRC split, and it gets the same fix: a
//! single definition that everyone delegates to.
//!
//! # The published v9 layout
//!
//! ```text
//! off  size  field
//!   0     6  magic "IDASGN"
//!   6     1  version
//!   7     1  processor / arch
//!   8     4  file_types
//!  12     2  os_types
//!  14     2  app_types
//!  16     2  feature_flags
//!  18     2  old_n_functions
//!  20     2  crc16
//!  22    12  ctype
//!  34     1  library_name_len
//!  35     2  alt_ctype_crc
//!  37     4  n_functions      (v6+)
//!  41     2  pattern_size     (v8+)
//!  43    ..  library name
//! ```
//!
//! The header is therefore **variable length**: it ends at
//! `43 + library_name_len`, which is where the pattern trie begins.

/// Magic bytes that open every IDA `.sig` file.
pub const MAGIC: &[u8; 6] = b"IDASGN";

/// Lowest `.sig` version this codec understands.
pub const VERSION_MIN: u8 = 5;
/// Highest `.sig` version this codec understands.
pub const VERSION_MAX: u8 = 10;

/// Offset of `library_name_len` — a single byte, not the start of a `u32`.
pub const OFF_NAME_LEN: usize = 34;
/// Offset of `alt_ctype_crc`.
pub const OFF_ALT_CTYPE_CRC: usize = 35;
/// Offset of the 32-bit `n_functions` (v6+).
pub const OFF_N_FUNCTIONS: usize = 37;
/// Offset of `pattern_size` (v8+).
pub const OFF_PATTERN_SIZE: usize = 41;
/// Offset at which the library name starts.
pub const OFF_NAME: usize = 43;

/// Smallest valid header: the fixed fields with an empty library name.
pub const MIN_SIZE: usize = OFF_NAME;

/// FLIRT's standard number of leading pattern bytes used as the trie key.
pub const DEFAULT_PATTERN_SIZE: u16 = 32;

/// A decoded `.sig` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigFileHeader {
    /// Format version (5–10).
    pub version: u8,
    /// Processor / architecture code.
    pub arch: u8,
    /// Supported file-type bitmask.
    pub file_types: u32,
    /// Supported OS bitmask.
    pub os_types: u16,
    /// Application-type bitmask.
    pub app_types: u16,
    /// Feature flags.
    pub feature_flags: u16,
    /// Legacy 16-bit function count.
    pub old_n_functions: u16,
    /// Header CRC-16.
    pub crc16: u16,
    /// C-type information CRC.
    pub ctype: [u8; 12],
    /// Alternate C-type CRC.
    pub alt_ctype_crc: u16,
    /// Function count (v6+; falls back to `old_n_functions` below v6).
    pub n_functions: u32,
    /// Leading pattern byte count (v8+; `0` below v8).
    pub pattern_size: u16,
    /// Library name.
    pub lib_name: String,
}

impl Default for SigFileHeader {
    fn default() -> Self {
        Self {
            version: 9,
            arch: 0,
            file_types: 0,
            os_types: 0,
            app_types: 0,
            feature_flags: 0,
            old_n_functions: 0,
            crc16: 0,
            ctype: [0; 12],
            alt_ctype_crc: 0,
            n_functions: 0,
            pattern_size: DEFAULT_PATTERN_SIZE,
            lib_name: String::new(),
        }
    }
}

/// Why a header could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// Buffer shorter than the fixed part of a header.
    TooShort {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// Magic bytes are not `IDASGN`.
    BadMagic,
    /// Version outside [`VERSION_MIN`]..=[`VERSION_MAX`].
    UnsupportedVersion(u8),
    /// `library_name_len` runs past the end of the buffer.
    NameOutOfBounds {
        /// Declared length.
        declared: usize,
        /// Buffer length.
        available: usize,
    },
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { got, need } => {
                write!(f, ".sig header truncated: {got} bytes, need at least {need}")
            }
            Self::BadMagic => write!(f, "not an IDASGN .sig file"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported .sig version: {v}"),
            Self::NameOutOfBounds { declared, available } => write!(
                f,
                "library_name_len {declared} runs past the end of a {available}-byte file"
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

impl SigFileHeader {
    /// Total header length: the fixed fields plus the library name.
    ///
    /// This is where the pattern trie begins. It is **not** a constant — using
    /// a fixed 104 meant the trie was read from the wrong offset for every
    /// library whose name was not exactly 61 bytes long.
    #[must_use]
    pub const fn len_bytes(&self) -> usize {
        OFF_NAME + self.lib_name.len()
    }

    /// Encode this header in the published layout.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name = self.lib_name.as_bytes();
        let name_len = name.len().min(usize::from(u8::MAX));
        let mut out = Vec::with_capacity(OFF_NAME + name_len);
        out.extend_from_slice(MAGIC);
        out.push(self.version);
        out.push(self.arch);
        out.extend_from_slice(&self.file_types.to_le_bytes());
        out.extend_from_slice(&self.os_types.to_le_bytes());
        out.extend_from_slice(&self.app_types.to_le_bytes());
        out.extend_from_slice(&self.feature_flags.to_le_bytes());
        out.extend_from_slice(&self.old_n_functions.to_le_bytes());
        out.extend_from_slice(&self.crc16.to_le_bytes());
        out.extend_from_slice(&self.ctype);
        debug_assert_eq!(out.len(), OFF_NAME_LEN);
        out.push(u8::try_from(name_len).unwrap_or(u8::MAX));
        out.extend_from_slice(&self.alt_ctype_crc.to_le_bytes());
        out.extend_from_slice(&self.n_functions.to_le_bytes());
        out.extend_from_slice(&self.pattern_size.to_le_bytes());
        debug_assert_eq!(out.len(), OFF_NAME);
        out.extend_from_slice(&name[..name_len]);
        out
    }

    /// Decode a header from the start of `raw`.
    ///
    /// # Errors
    /// Returns [`HeaderError`] when the buffer is too short, the magic is wrong,
    /// the version is unsupported, or the declared library-name length runs past
    /// the end of the buffer.
    ///
    /// A `.sig` is untrusted third-party input, so an over-long name is an
    /// error rather than something to clamp: a truncated name would produce a
    /// plausible-looking library identity that is simply wrong.
    pub fn decode(raw: &[u8]) -> Result<Self, HeaderError> {
        if raw.len() < MIN_SIZE {
            return Err(HeaderError::TooShort { got: raw.len(), need: MIN_SIZE });
        }
        if &raw[0..6] != MAGIC {
            return Err(HeaderError::BadMagic);
        }
        let version = raw[6];
        if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
            return Err(HeaderError::UnsupportedVersion(version));
        }

        let le16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);
        let le32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);

        let old_n_functions = le16(18);
        let mut ctype = [0u8; 12];
        ctype.copy_from_slice(&raw[22..34]);

        let name_len = usize::from(raw[OFF_NAME_LEN]);
        let name_end = OFF_NAME + name_len;
        if name_end > raw.len() {
            return Err(HeaderError::NameOutOfBounds {
                declared: name_len,
                available: raw.len(),
            });
        }

        // `n_functions` is v6+ and `pattern_size` v8+. Below those versions the
        // fields are absent; reporting a fabricated value would be worse than
        // reporting what the file actually carries.
        let n_functions = if version >= 6 {
            le32(OFF_N_FUNCTIONS)
        } else {
            u32::from(old_n_functions)
        };
        let pattern_size = if version >= 8 { le16(OFF_PATTERN_SIZE) } else { 0 };

        // IDA writes the name unterminated; tolerate a stray NUL.
        let name_bytes = &raw[OFF_NAME..name_end];
        let name_bytes = name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes);

        Ok(Self {
            version,
            arch: raw[7],
            file_types: le32(8),
            os_types: le16(12),
            app_types: le16(14),
            feature_flags: le16(16),
            old_n_functions,
            crc16: le16(20),
            ctype,
            alt_ctype_crc: le16(OFF_ALT_CTYPE_CRC),
            n_functions,
            pattern_size,
            lib_name: String::from_utf8_lossy(name_bytes).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> SigFileHeader {
        SigFileHeader {
            version: 9,
            arch: 0x06,
            file_types: 0x0000_0003,
            os_types: 2,
            app_types: 1,
            feature_flags: 0,
            old_n_functions: 7,
            crc16: 0xABCD,
            ctype: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            alt_ctype_crc: 0x1234,
            n_functions: 7,
            pattern_size: 32,
            lib_name: name.to_string(),
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        for name in ["", "a", "libgcc", "msvcrt-x64", &"n".repeat(200)] {
            let h = sample(name);
            let bytes = h.encode();
            let back = SigFileHeader::decode(&bytes).expect("round-trip");
            assert_eq!(back, h, "nome {:?}", &name[..name.len().min(20)]);
        }
    }

    #[test]
    fn field_offsets_match_the_published_layout() {
        let bytes = sample("libgcc").encode();
        assert_eq!(&bytes[0..6], MAGIC);
        assert_eq!(bytes[OFF_NAME_LEN], 6, "library_name_len è UN byte a offset 34");
        assert_eq!(
            u16::from_le_bytes([bytes[OFF_ALT_CTYPE_CRC], bytes[OFF_ALT_CTYPE_CRC + 1]]),
            0x1234
        );
        assert_eq!(
            u32::from_le_bytes(bytes[OFF_N_FUNCTIONS..OFF_N_FUNCTIONS + 4].try_into().unwrap()),
            7,
            "n_functions sta a 37, non a 34"
        );
        assert_eq!(&bytes[OFF_NAME..], b"libgcc");
    }

    #[test]
    fn header_length_is_variable_and_marks_the_trie_start() {
        for name in ["", "x", "a-longer-library-name"] {
            let h = sample(name);
            let bytes = h.encode();
            assert_eq!(h.len_bytes(), OFF_NAME + name.len());
            assert_eq!(bytes.len(), h.len_bytes(), "l'header consuma esattamente len_bytes");
        }
    }

    /// The old layout put `n_functions` as a u32 at 34. Decoding such a buffer
    /// with this codec must not silently produce a plausible header: the length
    /// byte it finds there is whatever the low byte of the count happened to be.
    #[test]
    fn an_old_layout_buffer_does_not_decode_as_if_it_were_valid() {
        let mut raw = vec![0u8; 104];
        raw[0..6].copy_from_slice(MAGIC);
        raw[6] = 9;
        raw[7] = 0;
        raw[34..38].copy_from_slice(&300u32.to_le_bytes()); // n_funcs @34, vecchio
        raw[40..46].copy_from_slice(b"oldlib"); // nome in finestra fissa

        let h = SigFileHeader::decode(&raw).expect("magic e versione sono validi");
        // 300 = 0x12C -> low byte 0x2C = 44 -> nome preso da 43..87, non "oldlib"
        assert_ne!(h.lib_name, "oldlib", "il vecchio layout non deve sembrare valido");
        assert_ne!(h.n_functions, 300);
    }

    #[test]
    fn rejects_bad_magic_short_buffers_and_bad_versions() {
        let good = sample("lib").encode();

        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(SigFileHeader::decode(&bad), Err(HeaderError::BadMagic));

        assert!(matches!(
            SigFileHeader::decode(&good[..10]),
            Err(HeaderError::TooShort { .. })
        ));

        let mut v = good.clone();
        v[6] = 4;
        assert_eq!(SigFileHeader::decode(&v), Err(HeaderError::UnsupportedVersion(4)));

        let mut v = good.clone();
        v[6] = 11;
        assert_eq!(SigFileHeader::decode(&v), Err(HeaderError::UnsupportedVersion(11)));
    }

    #[test]
    fn rejects_a_name_length_past_the_end() {
        let mut raw = sample("lib").encode();
        raw[OFF_NAME_LEN] = 200;
        assert!(matches!(
            SigFileHeader::decode(&raw),
            Err(HeaderError::NameOutOfBounds { declared: 200, .. })
        ));
    }

    #[test]
    fn truncation_never_panics() {
        let full = sample("libgcc").encode();
        for cut in 0..=full.len() {
            let _ = SigFileHeader::decode(&full[..cut]);
        }
    }

    #[test]
    fn pre_v6_and_pre_v8_do_not_invent_absent_fields() {
        let mut h = sample("lib");
        h.version = 5;
        let bytes = h.encode();
        let back = SigFileHeader::decode(&bytes).unwrap();
        assert_eq!(back.pattern_size, 0, "pattern_size è v8+");
        assert_eq!(
            back.n_functions,
            u32::from(h.old_n_functions),
            "prima della v6 il conteggio viene dal campo legacy a 16 bit"
        );
    }
}
