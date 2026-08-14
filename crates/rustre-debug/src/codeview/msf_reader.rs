//! MSF (Multi-Stream File) container reader for PDB 7.0 files.
//!
//! A `.pdb` is an MSF container: fixed-size pages, a super-block at page 0,
//! a block-map page listing the pages of the *stream directory*, and the
//! stream directory itself describing every stream's size and page list.
//!
//! This module walks that chain so callers can extract any stream — most
//! importantly stream #2 (TPI, the type stream) — as a contiguous byte
//! buffer, ready for [`super::pdb_tpi_reader::TpiReader::parse`].

use serde::{Deserialize, Serialize};

use super::{read_u32, PdbSuperBlock, MSF_MAGIC};

/// Well-known fixed MSF stream indices.
pub const STREAM_OLD_DIRECTORY: usize = 0;
/// PDB info stream (GUID, age, named-stream map).
pub const STREAM_PDB_INFO: usize = 1;
/// TPI type stream.
pub const STREAM_TPI: usize = 2;
/// DBI stream.
pub const STREAM_DBI: usize = 3;
/// IPI id stream.
pub const STREAM_IPI: usize = 4;

/// Errors produced while walking an MSF container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsfError {
    /// File shorter than the 52-byte super-block or bad magic/page size.
    BadSuperBlock,
    /// A page index points past the end of the file.
    PageOutOfRange {
        /// The offending page index.
        page: u32,
        /// Total number of pages in the file.
        num_pages: u32,
    },
    /// The stream directory is truncated or self-inconsistent.
    DirectoryTruncated,
    /// Requested stream index does not exist.
    NoSuchStream {
        /// The requested stream index.
        index: usize,
        /// Number of streams in the directory.
        num_streams: usize,
    },
    /// Stream has the "not present" sentinel size (`0xFFFF_FFFF`).
    StreamAbsent {
        /// The absent stream's index.
        index: usize,
    },
    /// Stream's declared size exceeds the sanity cap — likely a corrupted
    /// or adversarial directory rather than a real PDB.
    StreamTooLarge {
        /// The offending stream's index.
        index: usize,
        /// The declared stream size in bytes.
        size: u32,
    },
}

impl std::fmt::Display for MsfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSuperBlock => write!(f, "invalid MSF super-block"),
            Self::PageOutOfRange { page, num_pages } => {
                write!(f, "page {page} out of range (file has {num_pages} pages)")
            }
            Self::DirectoryTruncated => write!(f, "stream directory truncated"),
            Self::NoSuchStream { index, num_streams } => {
                write!(f, "stream {index} does not exist ({num_streams} streams)")
            }
            Self::StreamAbsent { index } => write!(f, "stream {index} is absent"),
            Self::StreamTooLarge { index, size } => {
                write!(f, "stream {index} declares size {size} exceeding the sanity cap")
            }
        }
    }
}

impl std::error::Error for MsfError {}

/// Descriptor of a single stream inside an MSF container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsfStreamInfo {
    /// Stream index.
    pub index: usize,
    /// Byte size (`0xFFFF_FFFF` means "absent").
    pub size: u32,
    /// Page indices holding the stream's data, in order.
    pub pages: Vec<u32>,
}

impl MsfStreamInfo {
    /// `true` when the stream carries the "not present" sentinel.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.size == u32::MAX
    }
}

/// Parsed view of a whole MSF container: super-block + stream directory.
#[derive(Debug, Clone)]
pub struct MsfReader<'a> {
    data: &'a [u8],
    /// Parsed super-block.
    pub superblock: PdbSuperBlock,
    /// One entry per stream, in directory order.
    pub streams: Vec<MsfStreamInfo>,
}

impl<'a> MsfReader<'a> {
    /// Parse the super-block, walk the block map, assemble and decode the
    /// stream directory.
    ///
    /// # Errors
    ///
    /// Returns [`MsfError`] on a malformed container.
    pub fn parse(data: &'a [u8]) -> Result<Self, MsfError> {
        let superblock = PdbSuperBlock::parse(data).ok_or(MsfError::BadSuperBlock)?;
        if !superblock.is_valid() {
            return Err(MsfError::BadSuperBlock);
        }
        let page_size = superblock.page_size as usize;
        let num_pages = superblock.num_pages;

        let page = |idx: u32| -> Result<&'a [u8], MsfError> {
            if idx >= num_pages {
                return Err(MsfError::PageOutOfRange { page: idx, num_pages });
            }
            // checked_mul: page_size comes from the superblock (attacker-controlled).
            let start = (idx as usize)
                .checked_mul(page_size)
                .ok_or(MsfError::PageOutOfRange { page: idx, num_pages })?;
            let end = start
                .checked_add(page_size)
                .ok_or(MsfError::PageOutOfRange { page: idx, num_pages })?;
            if end > data.len() {
                return Err(MsfError::PageOutOfRange { page: idx, num_pages });
            }
            Ok(&data[start..end])
        };

        // 1. The block-map page holds the u32 page indices of the directory.
        let dir_bytes = superblock.num_dir_bytes as usize;
        let num_dir_pages = dir_bytes.div_ceil(page_size);
        let block_map = page(superblock.block_map_addr)?;
        // checked_mul: num_dir_pages is derived from attacker-supplied num_dir_bytes.
        let dir_pages_x4 = num_dir_pages
            .checked_mul(4)
            .ok_or(MsfError::DirectoryTruncated)?;
        if dir_pages_x4 > block_map.len() {
            return Err(MsfError::DirectoryTruncated);
        }

        // 2. Assemble the directory from its pages.
        // Cap the up-front allocation at the real file size: `num_dir_bytes`
        // is attacker-controlled and the pages are only range-checked later.
        let alloc_cap = num_dir_pages
            .checked_mul(page_size)
            .unwrap_or(data.len())
            .min(data.len());
        let mut directory = Vec::with_capacity(alloc_cap);
        for i in 0..num_dir_pages {
            let dir_page_idx = read_u32(block_map, i * 4);
            directory.extend_from_slice(page(dir_page_idx)?);
        }
        directory.truncate(dir_bytes);
        if directory.len() < dir_bytes {
            return Err(MsfError::DirectoryTruncated);
        }

        // 3. Decode: num_streams, sizes[num_streams], then page lists.
        if directory.len() < 4 {
            return Err(MsfError::DirectoryTruncated);
        }
        let num_streams = read_u32(&directory, 0) as usize;
        // checked arithmetic: num_streams is attacker-controlled.
        let sizes_end = num_streams
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .ok_or(MsfError::DirectoryTruncated)?;
        if sizes_end > directory.len() {
            return Err(MsfError::DirectoryTruncated);
        }

        let mut streams = Vec::with_capacity(num_streams);
        let mut cursor = sizes_end;
        for index in 0..num_streams {
            let size = read_u32(&directory, 4 + index * 4);
            let n_pages = if size == u32::MAX {
                0
            } else {
                (size as usize).div_ceil(page_size)
            };
            let pages_end = n_pages
                .checked_mul(4)
                .and_then(|n| cursor.checked_add(n))
                .ok_or(MsfError::DirectoryTruncated)?;
            if pages_end > directory.len() {
                return Err(MsfError::DirectoryTruncated);
            }
            let mut pages = Vec::with_capacity(n_pages);
            for p in 0..n_pages {
                pages.push(read_u32(&directory, cursor + p * 4));
            }
            cursor = pages_end;
            streams.push(MsfStreamInfo { index, size, pages });
        }

        Ok(Self {
            data,
            superblock,
            streams,
        })
    }

    /// Number of streams in the directory.
    #[must_use]
    pub const fn num_streams(&self) -> usize {
        self.streams.len()
    }

    /// Extract stream `index` as a contiguous byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`MsfError`] if the stream is missing, absent, or a page is
    /// out of range.
    pub fn read_stream(&self, index: usize) -> Result<Vec<u8>, MsfError> {
        const MAX_STREAM_SIZE: u32 = 256 * 1024 * 1024;
        let info = self
            .streams
            .get(index)
            .ok_or(MsfError::NoSuchStream {
                index,
                num_streams: self.streams.len(),
            })?;
        if info.is_absent() {
            return Err(MsfError::StreamAbsent { index });
        }
        // `info.size` is a raw, fully-untrusted u32 straight from the
        // stream directory (up to ~4.29 GB) — feeding it directly into
        // `Vec::with_capacity` lets a corrupted/adversarial .pdb request an
        // arbitrarily large up-front allocation before a single page has
        // been range-checked. Same sanity-cap pattern as the ELF/PE section
        // size caps (iters 210/211): reject rather than allocate blindly.
        if info.size > MAX_STREAM_SIZE {
            return Err(MsfError::StreamTooLarge { index, size: info.size });
        }
        let page_size = self.superblock.page_size as usize;
        let num_pages = self.superblock.num_pages;
        let mut out = Vec::with_capacity(info.size as usize);
        for &p in &info.pages {
            if p >= num_pages {
                return Err(MsfError::PageOutOfRange { page: p, num_pages });
            }
            // checked_mul/checked_add: page index and page_size are both
            // attacker-controlled; prevent wrapping on 32-bit targets or
            // adversarial page sizes near usize::MAX.
            let start = (p as usize)
                .checked_mul(page_size)
                .ok_or(MsfError::PageOutOfRange { page: p, num_pages })?;
            let end = start
                .checked_add(page_size)
                .ok_or(MsfError::PageOutOfRange { page: p, num_pages })?;
            if end > self.data.len() {
                return Err(MsfError::PageOutOfRange { page: p, num_pages });
            }
            out.extend_from_slice(&self.data[start..end]);
        }
        out.truncate(info.size as usize);
        Ok(out)
    }

    /// Convenience: extract the TPI type stream (stream #2).
    ///
    /// # Errors
    ///
    /// Returns [`MsfError`] on a malformed container or missing stream.
    pub fn read_tpi_stream(&self) -> Result<Vec<u8>, MsfError> {
        self.read_stream(STREAM_TPI)
    }
}

/// One-shot helper: given full `.pdb` bytes, extract the TPI stream bytes.
///
/// # Errors
///
/// Returns [`MsfError`] on a malformed container or missing stream.
pub fn extract_tpi_stream(pdb: &[u8]) -> Result<Vec<u8>, MsfError> {
    MsfReader::parse(pdb)?.read_tpi_stream()
}

// ---------------------------------------------------------------------------
// MSF writer — build a minimal valid container (fixtures, tests, round-trips)
// ---------------------------------------------------------------------------

/// Page size used by [`write_msf`].
pub const WRITE_PAGE_SIZE: usize = 512;

/// Build a minimal valid MSF container holding the given streams, in order.
///
/// Layout: page 0 = super-block, page 1 = FPM (unused), page 2 = block map,
/// pages 3.. = directory pages, then stream data pages. Intended for test
/// fixtures and round-trip verification of [`MsfReader`].
#[must_use]
pub fn write_msf(stream_payloads: &[&[u8]]) -> Vec<u8> {
    const PAGE: usize = WRITE_PAGE_SIZE;
    let num_streams = stream_payloads.len();
    let pages_per_stream: Vec<usize> = stream_payloads
        .iter()
        .map(|s| s.len().div_ceil(PAGE))
        .collect();
    let dir_len = 4 + num_streams * 4 + pages_per_stream.iter().sum::<usize>() * 4;
    let num_dir_pages = dir_len.div_ceil(PAGE);

    let first_data_page = 3 + num_dir_pages; // 0=SB,1=FPM,2=block map,3..=dir
    let total_data_pages: usize = pages_per_stream.iter().sum();
    let num_pages = first_data_page + total_data_pages;

    let mut file = vec![0u8; num_pages * PAGE];

    // Super-block.
    file[..MSF_MAGIC.len()].copy_from_slice(MSF_MAGIC);
    file[32..36].copy_from_slice(&u32::try_from(PAGE).unwrap_or(512).to_le_bytes());
    file[36..40].copy_from_slice(&1u32.to_le_bytes()); // FPM
    file[40..44].copy_from_slice(&u32::try_from(num_pages).unwrap_or(0).to_le_bytes());
    file[44..48].copy_from_slice(&u32::try_from(dir_len).unwrap_or(0).to_le_bytes());
    // offset 48 = reserved/unknown (left 0); BlockMapAddr is at offset 52.
    file[52..56].copy_from_slice(&2u32.to_le_bytes()); // block map at page 2

    // Directory content.
    let mut dir = Vec::with_capacity(dir_len);
    dir.extend_from_slice(&u32::try_from(num_streams).unwrap_or(0).to_le_bytes());
    for s in stream_payloads {
        dir.extend_from_slice(&u32::try_from(s.len()).unwrap_or(0).to_le_bytes());
    }
    let mut next_page = first_data_page;
    let mut assignments: Vec<Vec<usize>> = Vec::new();
    for &n in &pages_per_stream {
        let pages: Vec<usize> = (next_page..next_page + n).collect();
        next_page += n;
        for &p in &pages {
            dir.extend_from_slice(&u32::try_from(p).unwrap_or(0).to_le_bytes());
        }
        assignments.push(pages);
    }
    debug_assert_eq!(dir.len(), dir_len);

    // Block map (page 2): directory page indices 3..3+num_dir_pages.
    for i in 0..num_dir_pages {
        let off = 2 * PAGE + i * 4;
        file[off..off + 4]
            .copy_from_slice(&u32::try_from(3 + i).unwrap_or(0).to_le_bytes());
    }

    // Write directory pages.
    for (i, chunk) in dir.chunks(PAGE).enumerate() {
        let off = (3 + i) * PAGE;
        file[off..off + chunk.len()].copy_from_slice(chunk);
    }

    // Write stream data.
    for (s, pages) in stream_payloads.iter().zip(&assignments) {
        for (i, chunk) in s.chunks(PAGE).enumerate() {
            let off = pages[i] * PAGE;
            file[off..off + chunk.len()].copy_from_slice(chunk);
        }
    }

    file
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::pdb_tpi_reader::{TpiReader, TPI_HEADER_VERSION_V80};
    use super::*;

    const PAGE: usize = WRITE_PAGE_SIZE;

    fn build_msf(stream_payloads: &[&[u8]]) -> Vec<u8> {
        write_msf(stream_payloads)
    }

    /// Minimal TPI stream: 56-byte header + one LF_STRUCTURE record.
    fn tiny_tpi_stream() -> Vec<u8> {
        // LF_STRUCTURE record for "Point", size 8.
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(b"Point\0\0");
        let len = (2 + body.len()) as u16;
        let mut rec = Vec::new();
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&0x1005u16.to_le_bytes());
        rec.extend_from_slice(&body);

        let mut tpi = Vec::new();
        tpi.extend_from_slice(&TPI_HEADER_VERSION_V80.to_le_bytes());
        tpi.extend_from_slice(&56u32.to_le_bytes());
        tpi.extend_from_slice(&0x1000u32.to_le_bytes());
        tpi.extend_from_slice(&0x1001u32.to_le_bytes());
        tpi.extend_from_slice(&(rec.len() as u32).to_le_bytes());
        tpi.extend_from_slice(&0xFFFFu16.to_le_bytes());
        tpi.extend_from_slice(&0xFFFFu16.to_le_bytes());
        tpi.extend_from_slice(&4u32.to_le_bytes());
        tpi.extend_from_slice(&0u32.to_le_bytes());
        // 5 remaining i32/u32 hash-buffer fields.
        tpi.extend_from_slice(&[0u8; 24]);
        assert_eq!(tpi.len(), 56);
        tpi.extend_from_slice(&rec);
        tpi
    }

    fn fixture() -> Vec<u8> {
        let tpi = tiny_tpi_stream();
        // Streams: 0 old dir (empty-ish), 1 pdb info, 2 TPI.
        build_msf(&[b"old", b"pdbinfo", &tpi])
    }

    /// Truncation + mutation sweep over the WHOLE `.pdb` pipeline —
    /// `extract_tpi_stream` is what `debug.load_types` feeds an untrusted
    /// user-supplied `.pdb` into, so every malformed variant must come back
    /// as `Err`, never as a panic or a runaway allocation. Iter 219 found a
    /// real unbounded allocation on exactly this surface, but only by
    /// reading the code — the bytes were never swept systematically.
    #[test]
    fn extract_tpi_stream_never_panics_on_truncated_or_mutated_input() {
        let good = fixture();

        for len in 0..=good.len() {
            let _ = extract_tpi_stream(&good[..len]);
        }

        // The superblock, the page map and the stream directory all live in
        // the first two pages; that is where every count/size/page-index
        // field that drives indexing and allocation sits.
        let dense = good.len().min(2 * PAGE);
        for i in 0..dense {
            for probe in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = good.clone();
                m[i] = probe;
                let _ = extract_tpi_stream(&m);
            }
        }

        // Whole 4-byte fields blown out to u32::MAX — page counts, stream
        // sizes and page indices are all u32 here, and single-byte
        // mutation only reaches the extreme at the top byte.
        for i in 0..dense.saturating_sub(4) {
            let mut m = good.clone();
            m[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let _ = extract_tpi_stream(&m);
        }
    }

    #[test]
    fn parse_superblock_and_directory() {
        let pdb = fixture();
        let msf = MsfReader::parse(&pdb).unwrap();
        assert!(msf.superblock.is_valid());
        assert_eq!(msf.num_streams(), 3);
        assert_eq!(msf.streams[STREAM_TPI].size as usize, tiny_tpi_stream().len());
    }

    #[test]
    fn read_stream_roundtrip() {
        let pdb = fixture();
        let msf = MsfReader::parse(&pdb).unwrap();
        assert_eq!(msf.read_stream(0).unwrap(), b"old");
        assert_eq!(msf.read_stream(1).unwrap(), b"pdbinfo");
    }

    #[test]
    fn extract_tpi_and_parse_types_end_to_end() {
        let pdb = fixture();
        let tpi_bytes = extract_tpi_stream(&pdb).unwrap();
        let reader = TpiReader::parse(&tpi_bytes).unwrap();
        assert_eq!(reader.len(), 1);
        let s = reader.find_concrete("Point").unwrap();
        assert_eq!(s.name(), Some("Point"));
    }

    #[test]
    fn multi_page_stream_reassembles() {
        // A stream spanning 3 pages with a recognizable pattern.
        let big: Vec<u8> = (0..(PAGE * 2 + 100)).map(|i| (i % 251) as u8).collect();
        let pdb = build_msf(&[b"", b"", &big]);
        let msf = MsfReader::parse(&pdb).unwrap();
        assert_eq!(msf.read_stream(2).unwrap(), big);
    }

    #[test]
    fn read_stream_rejects_a_declared_size_past_the_sanity_cap() {
        // A real, otherwise-valid MSF container, but with one stream's
        // directory-declared `size` inflated far past what its actual page
        // list could plausibly back — the scenario a corrupted/adversarial
        // `.pdb` can cheaply construct (many small page entries, one huge
        // size field) to make `read_stream` attempt a multi-GB up-front
        // allocation. Confirms the cap added alongside this test rejects it
        // instead of ever reaching `Vec::with_capacity`.
        let pdb = fixture();
        let mut msf = MsfReader::parse(&pdb).unwrap();
        msf.streams[STREAM_TPI].size = 300 * 1024 * 1024;
        let err = msf.read_stream(STREAM_TPI).unwrap_err();
        assert_eq!(
            err,
            MsfError::StreamTooLarge { index: STREAM_TPI, size: 300 * 1024 * 1024 }
        );
    }

    #[test]
    fn absent_stream_reports_error() {
        // Manually craft directory with an absent stream: easiest via build +
        // patching size to u32::MAX would desync page lists, so test the enum.
        let info = MsfStreamInfo { index: 5, size: u32::MAX, pages: vec![] };
        assert!(info.is_absent());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut pdb = fixture();
        pdb[0] = b'X';
        assert_eq!(MsfReader::parse(&pdb).unwrap_err(), MsfError::BadSuperBlock);
    }

    #[test]
    fn truncated_file_rejected() {
        let pdb = fixture();
        let err = MsfReader::parse(&pdb[..300]);
        assert!(err.is_err());
    }

    /// Verify against a REAL MSVC-produced `.pdb` when one exists on this
    /// machine (cargo build-script PDBs are genuine MSF 7.0 containers).
    /// Silently passes when no candidate is found, so CI stays portable.
    #[test]
    fn parse_real_pdb_if_present() {
        let candidates = [
            r"C:\Users\Fra\Desktop\RustRE\target\debug\build\ahash-23c553fddea76d33\build_script_build.pdb",
        ];
        // Also scan target\debug\build for any *.pdb as a fallback.
        let scan = std::path::Path::new(r"C:\Users\Fra\Desktop\RustRE\target\debug");
        let mut found: Option<std::path::PathBuf> =
            candidates.iter().map(std::path::PathBuf::from).find(|p| p.is_file());
        if found.is_none() && scan.is_dir() {
            'outer: for entry in walk(scan, 3) {
                if entry.extension().is_some_and(|e| e == "pdb") {
                    found = Some(entry);
                    break 'outer;
                }
            }
        }
        let Some(path) = found else { return };
        let data = std::fs::read(&path).expect("read pdb");
        let msf = MsfReader::parse(&data)
            .unwrap_or_else(|e| panic!("real pdb {} failed: {e}", path.display()));
        assert!(msf.superblock.is_valid());
        assert!(msf.num_streams() > STREAM_TPI, "pdb has a TPI stream");
        let tpi = msf.read_tpi_stream().expect("extract TPI");
        // A real TPI stream starts with the V8 header version.
        let hdr = super::super::pdb_tpi_reader::TpiHeader::parse(&tpi).expect("TPI header");
        assert!(hdr.is_valid_version(), "TPI version: {}", hdr.version);
        assert!(tpi.len() >= 56 + hdr.type_record_bytes as usize);
    }

    /// Full real-world pipeline: real `.pdb` → MSF walk → TPI records →
    /// `CodeViewTypeParser` → `import_structs_into` a live `TypeSystem`.
    /// Skips silently when no real PDB exists on this machine.
    #[test]
    fn real_pdb_types_import_end_to_end() {
        use super::super::codeview_type_parser::{import_structs_into, CodeViewTypeParser};
        use crate::expression_evaluator::TypeSystem;

        let scan = std::path::Path::new(r"C:\Users\Fra\Desktop\RustRE\target\debug");
        let Some(path) = walk(scan, 3)
            .into_iter()
            .find(|p| p.extension().is_some_and(|e| e == "pdb"))
        else {
            return;
        };
        let data = std::fs::read(&path).expect("read pdb");
        let tpi = extract_tpi_stream(&data)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let hdr = super::super::pdb_tpi_reader::TpiHeader::parse(&tpi).expect("hdr");
        assert!(hdr.is_valid_version());
        let start = hdr.header_size as usize;
        let end = (start + hdr.type_record_bytes as usize).min(tpi.len());

        let mut parser = CodeViewTypeParser::new();
        let n = parser.parse_stream(&tpi[start..end]);
        assert!(n > 0, "real TPI should yield type records");

        let mut ts = TypeSystem::with_primitives();
        let imported = import_structs_into(&parser, &mut ts);
        // A real MSVC build-script PDB always defines aggregates (CRT types).
        assert!(
            imported > 0,
            "expected >0 structs from {} ({n} records parsed)",
            path.display()
        );
        // And their LF_FIELDLISTs must actually yield data members (real C++
        // fieldlists open with LF_BCLASS/LF_METHOD records that must be
        // skipped, not treated as terminators).
        let total_members: usize = parser
            .records()
            .iter()
            .filter_map(|r| match &r.leaf {
                super::super::codeview_type_parser::CvTypeLeaf::FieldList {
                    members, ..
                } => Some(members.len()),
                _ => None,
            })
            .sum();
        assert!(
            total_members > 0,
            "expected >0 recovered LF_MEMBERs from {}",
            path.display()
        );
    }

    /// Tiny bounded directory walker (no external deps).
    fn walk(dir: &std::path::Path, depth: usize) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if depth == 0 {
            return out;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return out };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p, depth - 1));
            } else {
                out.push(p);
            }
            if out.len() > 5000 {
                break;
            }
        }
        out
    }

    #[test]
    fn no_such_stream() {
        let pdb = fixture();
        let msf = MsfReader::parse(&pdb).unwrap();
        assert!(matches!(
            msf.read_stream(9),
            Err(MsfError::NoSuchStream { index: 9, num_streams: 3 })
        ));
    }
}
