//! `xref_database` — persistent cross-reference database with fast lookup.
//!
//! Stores (`from_addr`, `to_addr`, `xref_type`, context) records, supports bidirectional
//! lookup by source or destination, merge of xref sets, and binary serialisation.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};

// ---------------------------------------------------------------------------
// XrefType

/// Discriminant for what kind of reference a cross-reference represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum XrefType {
    /// Direct call instruction (e.g. CALL rel32).
    Call,
    /// Indirect call through register or memory operand.
    IndirectCall,
    /// Unconditional jump.
    Jump,
    /// Conditional jump (branch taken).
    CondJump,
    /// Read of data (MOV reg, [addr]).
    DataRead,
    /// Write to data address.
    DataWrite,
    /// Load of address as an immediate (LEA / MOV imm64).
    AddressOf,
    /// Entry in a switch/jump table.
    JumpTable,
    /// Reference found inside a data structure.
    DataPointer,
    /// Import thunk reference.
    Import,
    /// Reference to a string literal.
    StringRef,
    /// Unknown / heuristically inferred.
    Unknown,
}

impl fmt::Display for XrefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call         => "CALL",
            Self::IndirectCall => "ICALL",
            Self::Jump         => "JMP",
            Self::CondJump     => "CJMP",
            Self::DataRead     => "DR",
            Self::DataWrite    => "DW",
            Self::AddressOf    => "ADDROF",
            Self::JumpTable    => "JTBL",
            Self::DataPointer  => "DPTR",
            Self::Import       => "IMP",
            Self::StringRef    => "STR",
            Self::Unknown      => "UNK",
        };
        f.write_str(s)
    }
}

impl XrefType {
    /// `true` if this xref represents a control-flow edge.
    #[must_use] 
    pub const fn is_code(&self) -> bool {
        matches!(
            self,
            Self::Call
                | Self::IndirectCall
                | Self::Jump
                | Self::CondJump
                | Self::JumpTable
        )
    }

    /// `true` if this xref represents a data reference.
    #[must_use] 
    pub const fn is_data(&self) -> bool {
        !self.is_code()
    }

    /// Encode to a single byte for binary serialisation.
    #[must_use] 
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from byte (returns `None` on unknown value).
    #[must_use] 
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0  => Some(Self::Call),
            1  => Some(Self::IndirectCall),
            2  => Some(Self::Jump),
            3  => Some(Self::CondJump),
            4  => Some(Self::DataRead),
            5  => Some(Self::DataWrite),
            6  => Some(Self::AddressOf),
            7  => Some(Self::JumpTable),
            8  => Some(Self::DataPointer),
            9  => Some(Self::Import),
            10 => Some(Self::StringRef),
            11 => Some(Self::Unknown),
            _  => None,
        }
    }
}

// ---------------------------------------------------------------------------
// XrefContext

/// Optional payload that provides extra context for an xref record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Default)]
pub struct XrefContext {
    /// Human-readable annotation (e.g. symbol name, string content).
    pub annotation: Option<String>,
    /// The raw instruction bytes at `from_addr` (up to 15 bytes for x86).
    pub insn_bytes: Vec<u8>,
    /// Module/section index carrying the source address.
    pub module_id: u32,
}


// ---------------------------------------------------------------------------
// XrefRecord

/// A single cross-reference record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XrefRecord {
    /// Address of the instruction / datum that contains the reference.
    pub from_addr: u64,
    /// Target address being referenced.
    pub to_addr: u64,
    /// Nature of the reference.
    pub xref_type: XrefType,
    /// Optional richer context.
    pub context: XrefContext,
}

impl XrefRecord {
    /// Construct a minimal record with no context.
    #[must_use] 
    pub fn new(from_addr: u64, to_addr: u64, xref_type: XrefType) -> Self {
        Self {
            from_addr,
            to_addr,
            xref_type,
            context: XrefContext::default(),
        }
    }

    /// Attach an annotation string and return `self`.
    #[must_use]
    pub fn with_annotation(mut self, ann: impl Into<String>) -> Self {
        self.context.annotation = Some(ann.into());
        self
    }

    /// Attach raw instruction bytes and return `self`.
    #[must_use] 
    pub fn with_insn_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.context.insn_bytes = bytes;
        self
    }

    /// Serialise to bytes: [from:8][to:8][type:1][ann_len:4][ann:*][insn_len:1][insn:*][mod:4]
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.from_addr.to_le_bytes());
        buf.extend_from_slice(&self.to_addr.to_le_bytes());
        buf.push(self.xref_type.to_byte());
        let ann = self.context.annotation.as_deref().unwrap_or("");
        let ann_bytes = ann.as_bytes();
        buf.extend_from_slice(&u32::try_from(ann_bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(ann_bytes);
        let insn = &self.context.insn_bytes;
        buf.push(u8::try_from(insn.len()).unwrap_or(u8::MAX));
        buf.extend_from_slice(insn);
        buf.extend_from_slice(&self.context.module_id.to_le_bytes());
        buf
    }

    /// Deserialise from a `Read` source. Returns `None` on malformed data.
    pub fn from_reader<R: Read>(r: &mut R) -> Option<Self> {
        // Guard against maliciously large annotation lengths (cap at 1 MiB).
        const MAX_ANN_LEN: usize = 1024 * 1024;
        let mut u64_buf = [0u8; 8];
        let mut u32_buf = [0u8; 4];

        r.read_exact(&mut u64_buf).ok()?;
        let from_addr = u64::from_le_bytes(u64_buf);
        r.read_exact(&mut u64_buf).ok()?;
        let to_addr = u64::from_le_bytes(u64_buf);

        let mut type_buf = [0u8; 1];
        r.read_exact(&mut type_buf).ok()?;
        let xref_type = XrefType::from_byte(type_buf[0])?;

        r.read_exact(&mut u32_buf).ok()?;
        let ann_len = u32::from_le_bytes(u32_buf) as usize;
        if ann_len > MAX_ANN_LEN {
            return None;
        }
        let annotation = if ann_len == 0 {
            None
        } else {
            let mut ann_buf = vec![0u8; ann_len];
            r.read_exact(&mut ann_buf).ok()?;
            Some(String::from_utf8(ann_buf).ok()?)
        };

        let mut insn_len_buf = [0u8; 1];
        r.read_exact(&mut insn_len_buf).ok()?;
        let insn_len = insn_len_buf[0] as usize;
        let mut insn_bytes = vec![0u8; insn_len];
        if insn_len > 0 {
            r.read_exact(&mut insn_bytes).ok()?;
        }

        r.read_exact(&mut u32_buf).ok()?;
        let module_id = u32::from_le_bytes(u32_buf);

        Some(Self {
            from_addr,
            to_addr,
            xref_type,
            context: XrefContext { annotation, insn_bytes, module_id },
        })
    }
}

// ---------------------------------------------------------------------------
// XrefQuery

/// Structured filter for querying the database.
#[derive(Debug, Clone, Default)]
pub struct XrefQuery {
    /// If set, only return records with this source address.
    pub from_addr: Option<u64>,
    /// If set, only return records with this destination address.
    pub to_addr: Option<u64>,
    /// If set, only return records of these types.
    pub xref_types: Option<Vec<XrefType>>,
    /// If set, only return records with annotation containing this substring.
    pub annotation_contains: Option<String>,
    /// If set, only return records from this module.
    pub module_id: Option<u32>,
    /// Maximum number of results (0 = no limit).
    pub limit: usize,
}

impl XrefQuery {
    #[must_use] 
    pub fn new() -> Self { Self::default() }
    #[must_use] 
    pub const fn from(mut self, addr: u64) -> Self { self.from_addr = Some(addr); self }
    #[must_use] 
    pub const fn to(mut self, addr: u64) -> Self { self.to_addr = Some(addr); self }
    #[must_use] 
    pub fn types(mut self, types: Vec<XrefType>) -> Self { self.xref_types = Some(types); self }
    #[must_use]
    pub fn annotation(mut self, s: impl Into<String>) -> Self { self.annotation_contains = Some(s.into()); self }
    #[must_use] 
    pub const fn module(mut self, id: u32) -> Self { self.module_id = Some(id); self }
    #[must_use] 
    pub const fn limit(mut self, n: usize) -> Self { self.limit = n; self }

    fn matches(&self, rec: &XrefRecord) -> bool {
        if let Some(fa) = self.from_addr
            && rec.from_addr != fa { return false; }
        if let Some(ta) = self.to_addr
            && rec.to_addr != ta { return false; }
        if let Some(ref types) = self.xref_types
            && !types.contains(&rec.xref_type) { return false; }
        if let Some(ref ann) = self.annotation_contains {
            let has = rec.context.annotation.as_deref()
                .is_some_and(|a| a.contains(ann.as_str()));
            if !has { return false; }
        }
        if let Some(mid) = self.module_id
            && rec.context.module_id != mid { return false; }
        true
    }
}

// ---------------------------------------------------------------------------
// XrefMerge

/// Strategy for merging two xref databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefMerge {
    /// Keep all records from both; duplicates are unified.
    Union,
    /// Keep only records present in both (same from/to/type).
    Intersection,
    /// Keep records in `self` that are not in `other`.
    Difference,
    /// Overwrite: records in `other` replace those in `self` for the same key.
    Overwrite,
}

// ---------------------------------------------------------------------------
// XrefDb

/// In-memory cross-reference database.
///
/// Maintains:
/// * a flat vector of all records (the ground truth)
/// * an index from `from_addr` → record indices
/// * an index from `to_addr` → record indices
/// * a deduplication set keyed by (from, to, type)
#[derive(Debug, Clone, Default)]
pub struct XrefDb {
    records: Vec<XrefRecord>,
    from_index: HashMap<u64, Vec<usize>>,
    to_index:   HashMap<u64, Vec<usize>>,
    dedup: HashSet<(u64, u64, u8)>,
}

impl XrefDb {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Total number of xref records.
    #[must_use] 
    pub const fn len(&self) -> usize { self.records.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.records.is_empty() }

    /// Insert a single xref record. Silently ignores duplicates (same from/to/type).
    pub fn insert(&mut self, rec: XrefRecord) -> bool {
        let key = (rec.from_addr, rec.to_addr, rec.xref_type.to_byte());
        if !self.dedup.insert(key) {
            return false;
        }
        let idx = self.records.len();
        self.from_index.entry(rec.from_addr).or_default().push(idx);
        self.to_index.entry(rec.to_addr).or_default().push(idx);
        self.records.push(rec);
        true
    }

    /// Insert many records at once.
    pub fn insert_many(&mut self, recs: impl IntoIterator<Item = XrefRecord>) {
        for r in recs { self.insert(r); }
    }

    /// Return all xrefs that originate from `addr`.
    #[must_use] 
    pub fn xrefs_from(&self, addr: u64) -> Vec<&XrefRecord> {
        self.from_index.get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.records[i]).collect())
            .unwrap_or_default()
    }

    /// Return all xrefs that target `addr`.
    #[must_use] 
    pub fn xrefs_to(&self, addr: u64) -> Vec<&XrefRecord> {
        self.to_index.get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.records[i]).collect())
            .unwrap_or_default()
    }

    /// Return the set of unique addresses referenced from `addr`.
    #[must_use] 
    pub fn targets_of(&self, addr: u64) -> HashSet<u64> {
        self.xrefs_from(addr).iter().map(|r| r.to_addr).collect()
    }

    /// Return the set of unique addresses that reference `addr`.
    #[must_use] 
    pub fn sources_of(&self, addr: u64) -> HashSet<u64> {
        self.xrefs_to(addr).iter().map(|r| r.from_addr).collect()
    }

    /// Execute a structured query and return matching records.
    #[must_use] 
    pub fn query(&self, q: &XrefQuery) -> Vec<&XrefRecord> {
        // Use an index when possible to avoid a full scan.
        let candidates: Vec<&XrefRecord> = match (q.from_addr, q.to_addr) {
            (Some(fa), None) => self.xrefs_from(fa),
            (None, Some(ta)) => self.xrefs_to(ta),
            _ => self.records.iter().collect(),
        };

        let mut results: Vec<&XrefRecord> = candidates
            .into_iter()
            .filter(|r| q.matches(r))
            .collect();

        if q.limit > 0 && results.len() > q.limit {
            results.truncate(q.limit);
        }
        results
    }

    /// Merge another database into `self` according to the given strategy.
    pub fn merge(&mut self, other: &Self, strategy: XrefMerge) {
        match strategy {
            XrefMerge::Union => {
                for rec in &other.records {
                    self.insert(rec.clone());
                }
            }
            XrefMerge::Intersection => {
                let other_keys: HashSet<(u64, u64, u8)> = other.dedup.clone();
                self.records.retain(|r| {
                    let k = (r.from_addr, r.to_addr, r.xref_type.to_byte());
                    other_keys.contains(&k)
                });
                self.rebuild_indices();
            }
            XrefMerge::Difference => {
                let other_keys: HashSet<(u64, u64, u8)> = other.dedup.clone();
                self.records.retain(|r| {
                    let k = (r.from_addr, r.to_addr, r.xref_type.to_byte());
                    !other_keys.contains(&k)
                });
                self.rebuild_indices();
            }
            XrefMerge::Overwrite => {
                // Remove self records whose key exists in other, then union.
                let other_keys: HashSet<(u64, u64, u8)> = other.dedup.clone();
                self.records.retain(|r| {
                    let k = (r.from_addr, r.to_addr, r.xref_type.to_byte());
                    !other_keys.contains(&k)
                });
                self.rebuild_indices();
                for rec in &other.records {
                    self.insert(rec.clone());
                }
            }
        }
    }

    /// Rebuild the internal indices from the `records` vector (used after filtering).
    fn rebuild_indices(&mut self) {
        self.from_index.clear();
        self.to_index.clear();
        self.dedup.clear();
        for (idx, rec) in self.records.iter().enumerate() {
            self.from_index.entry(rec.from_addr).or_default().push(idx);
            self.to_index.entry(rec.to_addr).or_default().push(idx);
            self.dedup.insert((rec.from_addr, rec.to_addr, rec.xref_type.to_byte()));
        }
    }

    /// Serialise the entire database to a `Write` sink.
    ///
    /// Format: magic(4) + version(1) + count(8) + records…
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if writing to `w` fails.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(b"XRDB")?; // magic
        w.write_all(&[1u8])?;  // version
        w.write_all(&(self.records.len() as u64).to_le_bytes())?;
        for rec in &self.records {
            let bytes = rec.to_bytes();
            w.write_all(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes())?;
            w.write_all(&bytes)?;
        }
        Ok(())
    }

    /// Deserialise a database from a `Read` source.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if reading fails or data is malformed.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        // Guard: reject implausibly large record counts to prevent pre-allocation DoS.
        const MAX_RECORDS: u64 = 50_000_000;
        // Guard against per-record blob sizes that would exhaust memory
        // (each serialised record is at most ~1 MiB annotation + 15-byte
        // instruction + fixed fields, so 2 MiB is a generous cap).
        const MAX_RECORD_BLOB: usize = 2 * 1024 * 1024;
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != b"XRDB" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let mut ver = [0u8; 1];
        r.read_exact(&mut ver)?;
        if ver[0] != 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported version"));
        }
        let mut count_buf = [0u8; 8];
        r.read_exact(&mut count_buf)?;
        let count_raw = u64::from_le_bytes(count_buf);
        if count_raw > MAX_RECORDS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "record count exceeds limit"));
        }
        let count = usize::try_from(count_raw).unwrap_or(usize::MAX);

        let mut db = Self::new();
        for _ in 0..count {
            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_RECORD_BLOB {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record blob size exceeds limit",
                ));
            }
            let mut blob = vec![0u8; len];
            r.read_exact(&mut blob)?;
            let mut cursor = blob.as_slice();
            if let Some(rec) = XrefRecord::from_reader(&mut cursor) {
                db.insert(rec);
            }
        }
        Ok(db)
    }

    /// Return basic statistics.
    #[must_use] 
    pub fn stats(&self) -> XrefDbStats {
        let mut by_type: HashMap<XrefType, usize> = HashMap::new();
        for r in &self.records {
            *by_type.entry(r.xref_type).or_insert(0) += 1;
        }
        XrefDbStats {
            total: self.records.len(),
            unique_sources: self.from_index.len(),
            unique_targets: self.to_index.len(),
            by_type,
        }
    }
}

/// Aggregate statistics for an [`XrefDb`].
#[derive(Debug, Clone)]
pub struct XrefDbStats {
    pub total: usize,
    pub unique_sources: usize,
    pub unique_targets: usize,
    pub by_type: HashMap<XrefType, usize>,
}

impl fmt::Display for XrefDbStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "XrefDb: {} records, {} sources, {} targets",
            self.total, self.unique_sources, self.unique_targets)?;
        let mut pairs: Vec<_> = self.by_type.iter().collect();
        pairs.sort_by_key(|(t, _)| t.to_byte());
        for (t, n) in pairs {
            writeln!(f, "  {t}: {n}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Architecture-aware path-based builder

/// Architecture selector for [`build_xref_db_from_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 64-bit x86.
    X86_64,
    /// 32-bit x86.
    X86_32,
    /// Detect from the PE machine field.
    Auto,
}

/// Build an [`XrefDb`] by reading a PE binary from disk and scanning its
/// executable segments for direct CALL / JMP / branch instructions and
/// RIP-relative data operands.
///
/// Records emitted:
/// * `CALL rel32` (`E8 imm32`) → [`XrefType::Call`]
/// * `JMP rel32` (`E9 imm32`) → [`XrefType::Jump`]
/// * `JMP rel8`  (`EB imm8`)  → [`XrefType::Jump`]
/// * `Jcc rel8`  (`70..7F imm8`) → [`XrefType::CondJump`]
/// * `Jcc rel32` (`0F 80..8F imm32`) → [`XrefType::CondJump`]
/// * RIP-relative LEA / MOV r64, [rip+disp32] → [`XrefType::AddressOf`]
///
/// # Errors
/// Returns an `io::Error` on file read failure or PE parse failure.
pub fn build_xref_db_from_path(
    path: &std::path::Path,
    arch: Architecture,
) -> io::Result<XrefDb> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let data = std::fs::read(path)?;
    let info = rustre_loader_pe::PeInfo::parse(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let is_64 = match arch {
        Architecture::X86_64 => true,
        Architecture::X86_32 => false,
        Architecture::Auto => matches!(info.machine, rustre_loader_pe::Machine::X64),
    };
    let mut db = XrefDb::new();
    for sec in &info.sections {
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let raw_start = sec.raw_offset as usize;
        let raw_end = raw_start
            .saturating_add(sec.raw_size as usize)
            .min(data.len());
        if raw_start >= raw_end {
            continue;
        }
        let bytes = &data[raw_start..raw_end];
        scan_x86_segment(bytes, sec.virtual_address, is_64, &mut db);
    }
    Ok(db)
}

/// Linear scan of one executable segment for direct branches and RIP-relative
/// data operands. Conservative — uses opcode-only matching, not a full
/// decoder, so length disambiguation for `0F 8x` Jcc forms is handled
/// explicitly but obscure prefixes are skipped.
fn scan_x86_segment(bytes: &[u8], base_va: u64, is_64: bool, db: &mut XrefDb) {
    let mut i = 0usize;
    let len = bytes.len();
    while i < len {
        let op = bytes[i];
        let cur_va = base_va.wrapping_add(i as u64);

        // E8 imm32 — CALL rel32
        if op == 0xE8 && i + 4 < len {
            let disp = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
            let next = cur_va.wrapping_add(5);
            let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
            db.insert(XrefRecord::new(cur_va, target, XrefType::Call));
            i += 5;
            continue;
        }
        // E9 imm32 — JMP rel32
        if op == 0xE9 && i + 4 < len {
            let disp = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
            let next = cur_va.wrapping_add(5);
            let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
            db.insert(XrefRecord::new(cur_va, target, XrefType::Jump));
            i += 5;
            continue;
        }
        // EB imm8 — JMP rel8
        if op == 0xEB && i + 1 < len {
            let disp = bytes[i + 1].cast_signed();
            let next = cur_va.wrapping_add(2);
            let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
            db.insert(XrefRecord::new(cur_va, target, XrefType::Jump));
            i += 2;
            continue;
        }
        // 70..7F imm8 — Jcc rel8
        if (0x70..=0x7F).contains(&op) && i + 1 < len {
            let disp = bytes[i + 1].cast_signed();
            let next = cur_va.wrapping_add(2);
            let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
            db.insert(XrefRecord::new(cur_va, target, XrefType::CondJump));
            i += 2;
            continue;
        }
        // 0F 80..8F imm32 — Jcc rel32
        if op == 0x0F && i + 5 < len && (0x80..=0x8F).contains(&bytes[i + 1]) {
            let disp = i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
            let next = cur_va.wrapping_add(6);
            let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
            db.insert(XrefRecord::new(cur_va, target, XrefType::CondJump));
            i += 6;
            continue;
        }
        // 64-bit only: REX.W + 8D /5 (LEA r64, [rip+disp32]) and similar RIP-relative
        // operand forms. Detect ModR/M mod=00, rm=101 (RIP-relative in 64-bit mode).
        if is_64 {
            // Skip optional REX prefix
            let mut p = i;
            if p < len && (bytes[p] & 0xF0) == 0x40 {
                p += 1;
            }
            if p < len && p + 5 < len {
                let opc = bytes[p];
                // 8D = LEA, 8B = MOV r,r/m
                if opc == 0x8D || opc == 0x8B {
                    let modrm = bytes[p + 1];
                    if modrm & 0xC7 == 0x05 {
                        // mod=00, rm=101 → RIP-relative
                        let disp = i32::from_le_bytes([
                            bytes[p + 2],
                            bytes[p + 3],
                            bytes[p + 4],
                            bytes[p + 5],
                        ]);
                        let insn_len = (p + 6) - i;
                        let next = cur_va.wrapping_add(insn_len as u64);
                        let target = next.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
                        db.insert(XrefRecord::new(cur_va, target, XrefType::AddressOf));
                        i += insn_len;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db() -> XrefDb {
        let mut db = XrefDb::new();
        db.insert(XrefRecord::new(0x1000, 0x2000, XrefType::Call));
        db.insert(XrefRecord::new(0x1005, 0x2000, XrefType::Call));
        db.insert(XrefRecord::new(0x1010, 0x3000, XrefType::DataRead));
        db.insert(XrefRecord::new(0x2000, 0x4000, XrefType::Jump));
        db
    }

    #[test]
    fn test_scan_x86_segment_call_and_jmp() {
        // Layout starting at VA 0x1000:
        //   0x1000: E8 0B 00 00 00   CALL +11  -> 0x1010
        //   0x1005: EB 02             JMP rel8 +2 -> 0x1009
        //   0x1007: 74 03             JE  rel8 +3 -> 0x100C
        //   0x1009: 90 90 90          NOP NOP NOP
        let bytes: Vec<u8> = vec![
            0xE8, 0x0B, 0x00, 0x00, 0x00, // CALL
            0xEB, 0x02,                   // JMP
            0x74, 0x03,                   // JE
            0x90, 0x90, 0x90,             // padding
        ];
        let mut db = XrefDb::new();
        scan_x86_segment(&bytes, 0x1000, true, &mut db);
        // Must contain a CALL from 0x1000 to 0x1010
        let calls: Vec<_> = db.query(&XrefQuery::new().from(0x1000).types(vec![XrefType::Call]));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].to_addr, 0x1010);

        // Must contain a JMP from 0x1005 to 0x1009
        let jumps: Vec<_> = db.query(&XrefQuery::new().from(0x1005).types(vec![XrefType::Jump]));
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].to_addr, 0x1009);

        // Must contain a CondJump from 0x1007 to 0x100C
        let cj: Vec<_> = db.query(&XrefQuery::new().from(0x1007).types(vec![XrefType::CondJump]));
        assert_eq!(cj.len(), 1);
        assert_eq!(cj[0].to_addr, 0x100C);
    }

    #[test]
    fn test_scan_x86_segment_rip_relative_lea() {
        // 48 8D 05 10 00 00 00   LEA RAX, [rip+0x10]
        let bytes: Vec<u8> = vec![0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let mut db = XrefDb::new();
        scan_x86_segment(&bytes, 0x2000, true, &mut db);
        let q: Vec<_> = db.query(&XrefQuery::new().types(vec![XrefType::AddressOf]));
        assert_eq!(q.len(), 1);
        // next IP = 0x2007; target = 0x2007 + 0x10 = 0x2017
        assert_eq!(q[0].to_addr, 0x2017);
    }

    #[test]
    fn test_insert_dedup() {
        let mut db = XrefDb::new();
        assert!(db.insert(XrefRecord::new(0x100, 0x200, XrefType::Call)));
        assert!(!db.insert(XrefRecord::new(0x100, 0x200, XrefType::Call)));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_from_to_lookup() {
        let db = make_db();
        assert_eq!(db.xrefs_from(0x1000).len(), 1);
        assert_eq!(db.xrefs_to(0x2000).len(), 2);
        assert_eq!(db.xrefs_from(0x9999).len(), 0);
    }

    #[test]
    fn test_query_by_type() {
        let db = make_db();
        let q = XrefQuery::new().types(vec![XrefType::Call]);
        let res = db.query(&q);
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_merge_union() {
        let db1 = make_db();
        let mut db2 = XrefDb::new();
        db2.insert(XrefRecord::new(0x5000, 0x6000, XrefType::Jump));
        db2.insert(XrefRecord::new(0x1000, 0x2000, XrefType::Call)); // dup

        let mut merged = db1.clone();
        merged.merge(&db2, XrefMerge::Union);
        assert_eq!(merged.len(), db1.len() + 1);
    }

    #[test]
    fn test_merge_intersection() {
        let mut db1 = XrefDb::new();
        db1.insert(XrefRecord::new(0x100, 0x200, XrefType::Call));
        db1.insert(XrefRecord::new(0x300, 0x400, XrefType::Jump));

        let mut db2 = XrefDb::new();
        db2.insert(XrefRecord::new(0x100, 0x200, XrefType::Call));

        db1.merge(&db2, XrefMerge::Intersection);
        assert_eq!(db1.len(), 1);
    }

    #[test]
    fn test_serialisation_roundtrip() {
        let db = make_db();
        let mut buf = Vec::new();
        db.write_to(&mut buf).unwrap();
        let db2 = XrefDb::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(db2.len(), db.len());
    }

    #[test]
    fn test_stats() {
        let db = make_db();
        let s = db.stats();
        assert_eq!(s.total, 4);
        assert_eq!(*s.by_type.get(&XrefType::Call).unwrap(), 2);
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn test_xref_type_byte_roundtrip() {
        for ty in [
            XrefType::Call, XrefType::IndirectCall, XrefType::Jump,
            XrefType::CondJump, XrefType::DataRead, XrefType::DataWrite,
            XrefType::AddressOf, XrefType::JumpTable, XrefType::DataPointer,
            XrefType::Import, XrefType::StringRef, XrefType::Unknown,
        ] {
            let b = ty.to_byte();
            assert_eq!(XrefType::from_byte(b), Some(ty));
        }
        // Out-of-range byte returns None.
        assert_eq!(XrefType::from_byte(255), None);
        assert_eq!(XrefType::from_byte(12), None);
    }

    #[test]
    fn test_is_code_vs_is_data() {
        assert!(XrefType::Call.is_code());
        assert!(XrefType::JumpTable.is_code());
        assert!(!XrefType::Call.is_data());
        assert!(XrefType::DataRead.is_data());
        assert!(XrefType::StringRef.is_data());
        assert!(!XrefType::StringRef.is_code());
    }

    #[test]
    fn test_insert_dedup_silently_ignores_duplicate() {
        let mut db = XrefDb::new();
        assert!(db.insert(XrefRecord::new(1, 2, XrefType::Call)));
        assert!(!db.insert(XrefRecord::new(1, 2, XrefType::Call)));
        // Different type at same from/to is NOT a dup.
        assert!(db.insert(XrefRecord::new(1, 2, XrefType::Jump)));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn test_empty_db_queries() {
        let db = XrefDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.xrefs_from(0).is_empty());
        assert!(db.xrefs_to(u64::MAX).is_empty());
    }

    #[test]
    fn test_xref_record_roundtrip_with_annotation_and_bytes() {
        let rec = XrefRecord::new(0xdead, 0xbeef, XrefType::Call)
            .with_annotation("malloc")
            .with_insn_bytes(vec![0xE8, 0x00, 0x00, 0x00, 0x00]);
        let bytes = rec.to_bytes();
        let decoded = XrefRecord::from_reader(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.from_addr, 0xdead);
        assert_eq!(decoded.to_addr, 0xbeef);
        assert_eq!(decoded.xref_type, XrefType::Call);
        assert_eq!(decoded.context.annotation.as_deref(), Some("malloc"));
        assert_eq!(decoded.context.insn_bytes, vec![0xE8, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_xref_record_truncated_bytes_returns_none() {
        let rec = XrefRecord::new(1, 2, XrefType::Call);
        let bytes = rec.to_bytes();
        // Truncate; should fail to deserialise.
        for cut in 0..bytes.len() {
            assert!(XrefRecord::from_reader(&mut &bytes[..cut]).is_none());
        }
    }

    #[test]
    fn test_xref_record_malformed_type_byte() {
        // Hand-construct a malformed buffer with invalid type byte.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.push(99); // invalid xref type byte
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0);
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(XrefRecord::from_reader(&mut buf.as_slice()).is_none());
    }

    #[test]
    fn test_xref_record_extreme_address_values() {
        let rec = XrefRecord::new(0, u64::MAX, XrefType::AddressOf);
        let bytes = rec.to_bytes();
        let decoded = XrefRecord::from_reader(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.from_addr, 0);
        assert_eq!(decoded.to_addr, u64::MAX);
    }

    #[test]
    fn test_query_with_limit_zero_is_unlimited() {
        let db = make_db();
        let q = XrefQuery::new().limit(0);
        let res = db.query(&q);
        assert_eq!(res.len(), db.len());
    }
}
