//! `PDB` Global Symbol Index (`GSI`) and Public Symbol Index (`PSI`) stream parsers.
//!
//! The `GSI` stream stores a hash table that maps symbol names to their byte
//! offset in the symbol records stream.  The `PSI` stream is a specialisation
//! of the `GSI` that carries the public (exported) symbol table plus a sorted
//! address → symbol mapping used for address-based lookup.
//!
//! References:
//! * Microsoft LLVM `PDB` documentation
//! * `pdb` crate source (for cross-checking constants)

// ── GsiHeader ─────────────────────────────────────────────────────────────────

/// The fixed-size header at the start of the `GSI` stream.
#[derive(Debug, Clone)]
pub struct GsiHeader {
    /// Version signature (0xEFFEEFFE for the modern format).
    pub version_signature: u32,
    /// Version value (usually 0xF12EBA2D for `PDB` 7.0).
    pub version: u32,
    /// Size in bytes of the hash records area that follows.
    pub hr_len: u32,
    /// Size in bytes of the hash bucket bitmap that follows the hash records.
    pub num_buckets: u32,
}

/// Expected `GSI` version signature.
pub const GSI_VERSION_SIGNATURE: u32 = 0xEFFE_EFFE;
/// Expected `GSI` version value for `PDB` 7.0.
pub const GSI_VERSION_70: u32 = 0xF12E_BA2D;

impl GsiHeader {
    /// Parse a [`GsiHeader`] from the first 16 bytes of the `GSI` stream.
    ///
    /// # Errors
    /// Returns `None` if the slice is too short.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let version_signature = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let hr_len = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let num_buckets = u32::from_le_bytes(data[12..16].try_into().ok()?);
        Some(Self {
            version_signature,
            version,
            hr_len,
            num_buckets,
        })
    }

    /// Return `true` if the version signature matches the expected `GSI` value.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.version_signature == GSI_VERSION_SIGNATURE
    }

    /// Return `true` if this is a `PDB` 7.0 `GSI` stream.
    #[must_use]
    pub const fn is_v70(&self) -> bool {
        self.is_valid() && self.version == GSI_VERSION_70
    }
}

// ── GsiHashRecord ─────────────────────────────────────────────────────────────

/// One entry in the `GSI` hash table — maps a hash bucket to a symbol record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GsiHashRecord {
    /// Byte offset of the symbol record in the symbol records stream
    /// (relative to the start of that stream).  The low bit is always 1
    /// (set by the linker) and must be masked out when seeking.
    pub offset: u32,
    /// Reference count (unused in most modern toolchains; usually 1).
    pub cref: u32,
}

impl GsiHashRecord {
    /// Size of one serialised hash record in bytes.
    pub const SIZE: usize = 8;

    /// Parse a single hash record from `data` at `offset`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let offset = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let cref = u32::from_le_bytes(data[4..8].try_into().ok()?);
        Some(Self { offset, cref })
    }

    /// Return the actual symbol record stream offset (low bit cleared).
    #[must_use]
    pub const fn symbol_offset(&self) -> u32 {
        self.offset & !1u32
    }
}

// ── GsiHashTable ─────────────────────────────────────────────────────────────

/// The hash bucket array from the `GSI` stream.
#[derive(Debug, Clone)]
pub struct GsiHashTable {
    /// All hash records, in order.
    pub records: Vec<GsiHashRecord>,
}

impl GsiHashTable {
    /// Parse all hash records from a byte slice (after the `GSI` header).
    ///
    /// `hr_len` is taken from [`GsiHeader::hr_len`].
    #[must_use]
    pub fn parse(data: &[u8], hr_len: u32) -> Self {
        let len = hr_len as usize;
        let available = data.len().min(len);
        let mut records = Vec::new();
        let mut pos = 0;
        while pos + GsiHashRecord::SIZE <= available {
            if let Some(rec) = GsiHashRecord::parse(&data[pos..]) {
                records.push(rec);
            }
            pos += GsiHashRecord::SIZE;
        }
        Self { records }
    }

    /// Return the number of hash records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` if the table has no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return all unique symbol offsets (deduplicated, with the tag bit cleared).
    #[must_use]
    pub fn symbol_offsets(&self) -> Vec<u32> {
        let mut offsets: Vec<u32> = self
            .records
            .iter()
            .map(GsiHashRecord::symbol_offset)
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

// ── PublicSymbolFlags ─────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags for a public symbol (`S_PUB32`) record.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PublicSymbolFlags: u32 {
        /// The symbol is a function / code symbol.
        const CODE = 0x0001;
        /// The symbol is a managed code symbol.
        const MANAGED = 0x0002;
        /// The symbol is a MSIL (managed IL) symbol.
        const MSIL = 0x0004;
    }
}

// ── PsiPublicSymbol ───────────────────────────────────────────────────────────

/// A single public symbol entry from the `PSI` stream.
#[derive(Debug, Clone)]
pub struct PsiPublicSymbol {
    /// Symbol flags.
    pub flags: PublicSymbolFlags,
    /// Relative virtual address (section offset + section base).
    pub offset: u32,
    /// Section index (1-based).
    pub segment: u16,
    /// Mangled/decorated symbol name.
    pub name: String,
}

impl PsiPublicSymbol {
    /// Minimum size of a serialised public symbol record (before the name).
    pub const MIN_SIZE: usize = 10; // 4 flags + 4 offset + 2 segment

    /// Parse a public symbol from a raw `S_PUB32` symbol record body.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }
        let flags_raw = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let flags = PublicSymbolFlags::from_bits_retain(flags_raw);
        let offset = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let segment = u16::from_le_bytes(data[8..10].try_into().ok()?);
        let name_bytes = &data[10..];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        Some(Self {
            flags,
            offset,
            segment,
            name,
        })
    }

    /// Return `true` if this is a code symbol.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.flags.contains(PublicSymbolFlags::CODE)
    }
}

// ── PsiStream ─────────────────────────────────────────────────────────────────

/// The Public Symbol Index stream — wraps a `GSI` plus an address-sorted table.
pub struct PsiStream {
    /// The underlying `GSI` hash table.
    pub hash_table: GsiHashTable,
    /// Address-sorted public symbols (populated after a parse pass).
    pub symbols: Vec<PsiPublicSymbol>,
}

impl PsiStream {
    /// Create a new `PSI` stream from a raw hash table and symbol list.
    #[must_use]
    pub const fn new(hash_table: GsiHashTable, symbols: Vec<PsiPublicSymbol>) -> Self {
        Self {
            hash_table,
            symbols,
        }
    }

    /// Find a symbol by name (exact, case-sensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&PsiPublicSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Find all code symbols.
    #[must_use]
    pub fn code_symbols(&self) -> Vec<&PsiPublicSymbol> {
        self.symbols.iter().filter(|s| s.is_code()).collect()
    }

    /// Find a symbol closest to `offset` in `segment` (nearest preceding symbol).
    #[must_use]
    pub fn find_by_address(&self, segment: u16, offset: u32) -> Option<&PsiPublicSymbol> {
        let mut best: Option<&PsiPublicSymbol> = None;
        for sym in &self.symbols {
            if sym.segment == segment && sym.offset <= offset {
                match best {
                    None => best = Some(sym),
                    Some(b) if sym.offset > b.offset => best = Some(sym),
                    _ => {}
                }
            }
        }
        best
    }

    /// Return all symbol names.
    #[must_use]
    pub fn symbol_names(&self) -> Vec<&str> {
        self.symbols.iter().map(|s| s.name.as_str()).collect()
    }

    /// Number of symbols.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gsi_header_bytes(
        signature: u32,
        version: u32,
        hr_len: u32,
        num_buckets: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&signature.to_le_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&hr_len.to_le_bytes());
        buf.extend_from_slice(&num_buckets.to_le_bytes());
        buf
    }

    #[test]
    fn test_gsi_header_parse_valid() {
        let buf = make_gsi_header_bytes(GSI_VERSION_SIGNATURE, GSI_VERSION_70, 0x100, 0x200);
        let hdr = GsiHeader::parse(&buf).unwrap();
        assert!(hdr.is_valid());
        assert!(hdr.is_v70());
        assert_eq!(hdr.hr_len, 0x100);
    }

    #[test]
    fn test_gsi_header_too_short() {
        assert!(GsiHeader::parse(&[0u8; 8]).is_none());
    }

    #[test]
    fn test_gsi_header_bad_signature() {
        let buf = make_gsi_header_bytes(0xDEAD_BEEF, GSI_VERSION_70, 0, 0);
        let hdr = GsiHeader::parse(&buf).unwrap();
        assert!(!hdr.is_valid());
        assert!(!hdr.is_v70());
    }

    #[test]
    fn test_gsi_hash_record_parse() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0000_1001_u32.to_le_bytes()); // offset with low bit set
        buf.extend_from_slice(&1_u32.to_le_bytes()); // cref
        let rec = GsiHashRecord::parse(&buf).unwrap();
        assert_eq!(rec.offset, 0x1001);
        assert_eq!(rec.symbol_offset(), 0x1000); // low bit cleared
    }

    #[test]
    fn test_gsi_hash_table_parse() {
        let mut buf = Vec::new();
        for i in 0u32..4 {
            buf.extend_from_slice(&(i * 8 + 1).to_le_bytes()); // offset
            buf.extend_from_slice(&1u32.to_le_bytes()); // cref
        }
        let table = GsiHashTable::parse(&buf, 32);
        assert_eq!(table.len(), 4);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_gsi_hash_table_symbol_offsets_dedup() {
        let mut buf = Vec::new();
        // Two records with same symbol offset
        for _ in 0..2 {
            buf.extend_from_slice(&0x1001_u32.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes());
        }
        let table = GsiHashTable::parse(&buf, 16);
        let offsets = table.symbol_offsets();
        assert_eq!(offsets.len(), 1); // deduplicated
        assert_eq!(offsets[0], 0x1000); // tag bit cleared
    }

    #[test]
    fn test_psi_public_symbol_parse() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(PublicSymbolFlags::CODE.bits()).to_le_bytes()); // flags
        buf.extend_from_slice(&0x1000_u32.to_le_bytes()); // offset
        buf.extend_from_slice(&1_u16.to_le_bytes()); // segment
        buf.extend_from_slice(b"_my_function\0");
        let sym = PsiPublicSymbol::parse(&buf).unwrap();
        assert_eq!(sym.name, "_my_function");
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert!(sym.is_code());
    }

    #[test]
    fn test_psi_stream_find_by_name() {
        let syms = vec![
            PsiPublicSymbol {
                flags: PublicSymbolFlags::CODE,
                offset: 0x1000,
                segment: 1,
                name: "_foo".to_string(),
            },
            PsiPublicSymbol {
                flags: PublicSymbolFlags::empty(),
                offset: 0x2000,
                segment: 1,
                name: "_bar".to_string(),
            },
        ];
        let psi = PsiStream::new(GsiHashTable { records: vec![] }, syms);
        assert!(psi.find_by_name("_foo").is_some());
        assert!(psi.find_by_name("_baz").is_none());
    }

    #[test]
    fn test_psi_stream_find_by_address() {
        let syms = vec![
            PsiPublicSymbol {
                flags: PublicSymbolFlags::CODE,
                offset: 0x1000,
                segment: 1,
                name: "_a".to_string(),
            },
            PsiPublicSymbol {
                flags: PublicSymbolFlags::CODE,
                offset: 0x2000,
                segment: 1,
                name: "_b".to_string(),
            },
        ];
        let psi = PsiStream::new(GsiHashTable { records: vec![] }, syms);
        // Address 0x1500 in segment 1 should resolve to "_a"
        let sym = psi.find_by_address(1, 0x1500).unwrap();
        assert_eq!(sym.name, "_a");
    }

    #[test]
    fn test_public_symbol_flags_bits() {
        let f = PublicSymbolFlags::CODE | PublicSymbolFlags::MANAGED;
        assert!(f.contains(PublicSymbolFlags::CODE));
        assert!(f.contains(PublicSymbolFlags::MANAGED));
        assert!(!f.contains(PublicSymbolFlags::MSIL));
    }
}
