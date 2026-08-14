//! ELF note section (`.note.*`) parser.
//!
//! ELF note sections store auxiliary metadata blobs, each described by a
//! `namesz/descsz/type` header followed by the name string (NUL-padded to 4
//! bytes) and the descriptor bytes.
//!
//! This module decodes the most common note types:
//! - `NT_GNU_BUILD_ID`   (type 3 in the "GNU" namespace) — build-ID hash
//! - `NT_GNU_ABI_TAG`    (type 1 in the "GNU" namespace) — min kernel ABI
//! - `NT_GNU_GOLD_VERSION` (type 4 in the "GNU" namespace) — linker version
//! - `NT_PRSTATUS`       (type 1 in the "CORE" namespace) — process status
//! - `NT_PRPSINFO`       (type 3 in the "CORE" namespace) — process info
//! - `NT_FILE`           (type 0x46494c45 in the "CORE" namespace) — mapped files

// ─────────────────────────────────────────────────────────────────────────────
// NoteType & GnuNoteType
// ─────────────────────────────────────────────────────────────────────────────

/// Raw note type (the `n_type` field in the note header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteType {
    /// GNU-namespace note type.
    Gnu(GnuNoteType),
    /// Core-dump note type.
    Core(CoreNoteType),
    /// Any other note type from any other namespace.
    Unknown { namespace: String, raw_type: u32 },
}

/// Note types used in the `"GNU"` namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GnuNoteType {
    /// Minimum kernel ABI required to run (`n_type` = 1).
    AbiTag,
    /// Hardware capability information (`n_type` = 2).
    HwCap,
    /// Build-ID (`n_type` = 3).
    BuildId,
    /// Gold linker version string (`n_type` = 4).
    GoldVersion,
    /// Other GNU note (`n_type` = anything else).
    Other(u32),
}

impl GnuNoteType {
    /// Convert a raw `n_type` integer to a [`GnuNoteType`].
    #[must_use]
    pub const fn from_raw(n_type: u32) -> Self {
        match n_type {
            1 => Self::AbiTag,
            2 => Self::HwCap,
            3 => Self::BuildId,
            4 => Self::GoldVersion,
            other => Self::Other(other),
        }
    }

    /// Return the raw integer for this note type.
    #[must_use]
    pub const fn as_raw(&self) -> u32 {
        match self {
            Self::AbiTag => 1,
            Self::HwCap => 2,
            Self::BuildId => 3,
            Self::GoldVersion => 4,
            Self::Other(n) => *n,
        }
    }
}

/// Note types used in the `"CORE"` namespace (Linux core dumps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreNoteType {
    /// Process status (`struct elf_prstatus`).  `n_type` = 1.
    PrStatus,
    /// Process info (`struct elf_prpsinfo`).  `n_type` = 3.
    PrPsInfo,
    /// Auxiliary vector.  `n_type` = 6.
    Auxv,
    /// Mapped files list.  `n_type` = 0x46494c45 (`"FILE"` as BE u32).
    File,
    /// Other core note type.
    Other(u32),
}

impl CoreNoteType {
    /// Convert a raw `n_type` integer to a [`CoreNoteType`].
    #[must_use]
    pub const fn from_raw(n_type: u32) -> Self {
        match n_type {
            1 => Self::PrStatus,
            3 => Self::PrPsInfo,
            6 => Self::Auxv,
            0x4649_4c45 => Self::File,
            other => Self::Other(other),
        }
    }

    /// Return the raw integer for this core note type.
    #[must_use]
    pub const fn as_raw(&self) -> u32 {
        match self {
            Self::PrStatus => 1,
            Self::PrPsInfo => 3,
            Self::Auxv => 6,
            Self::File => 0x4649_4c45,
            Self::Other(n) => *n,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ElfNote
// ─────────────────────────────────────────────────────────────────────────────

/// A single ELF note entry.
#[derive(Debug, Clone)]
pub struct ElfNote {
    /// The note namespace (e.g. `"GNU"`, `"CORE"`, `"Android"`).
    pub namespace: String,
    /// The interpreted note type.
    pub note_type: NoteType,
    /// The raw descriptor bytes.
    pub descriptor: Vec<u8>,
}

impl ElfNote {
    /// Return the byte length of the descriptor.
    #[must_use]
    pub const fn desc_len(&self) -> usize {
        self.descriptor.len()
    }

    /// Attempt to interpret this note as a GNU build-ID.
    ///
    /// Returns `Some(GnuBuildId)` if the namespace is `"GNU"` and the type is
    /// `NT_GNU_BUILD_ID`, otherwise `None`.
    #[must_use]
    pub fn as_build_id(&self) -> Option<GnuBuildId> {
        if self.namespace == "GNU" && matches!(&self.note_type, NoteType::Gnu(GnuNoteType::BuildId)) {
            return Some(GnuBuildId {
                bytes: self.descriptor.clone(),
            });
        }
        None
    }

    /// Attempt to interpret this note as a `NT_PRSTATUS` record.
    ///
    /// Returns `Some(Prstatus)` if the namespace is `"CORE"` and parsing
    /// succeeds; `None` otherwise.
    #[must_use]
    pub fn as_prstatus(&self) -> Option<Prstatus> {
        if self.namespace == "CORE" && matches!(&self.note_type, NoteType::Core(CoreNoteType::PrStatus)) {
            return Prstatus::parse(&self.descriptor);
        }
        None
    }

    /// Attempt to interpret this note as a `NT_PRPSINFO` record.
    ///
    /// Returns `Some(Prpsinfo)` if the namespace is `"CORE"` and parsing
    /// succeeds; `None` otherwise.
    #[must_use]
    pub fn as_prpsinfo(&self) -> Option<Prpsinfo> {
        if self.namespace == "CORE" && matches!(&self.note_type, NoteType::Core(CoreNoteType::PrPsInfo)) {
            return Prpsinfo::parse(&self.descriptor);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GnuBuildId
// ─────────────────────────────────────────────────────────────────────────────

/// GNU build-ID blob extracted from a `NT_GNU_BUILD_ID` note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuBuildId {
    /// Raw bytes of the build-ID (usually SHA-1, 20 bytes; or MD5, 16 bytes).
    pub bytes: Vec<u8>,
}

impl GnuBuildId {
    /// Format the build-ID as a lowercase hex string.
    #[must_use]
    pub fn as_hex(&self) -> String {
        self.bytes.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    /// Return the byte length of the build-ID.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if the build-ID is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return the algorithm guess based on the length.
    ///
    /// - 20 bytes → SHA-1
    /// - 16 bytes → MD5
    /// - other → unknown
    #[must_use]
    pub const fn algorithm_hint(&self) -> &'static str {
        match self.bytes.len() {
            20 => "sha1",
            16 => "md5",
            _ => "unknown",
        }
    }
}

impl std::fmt::Display for GnuBuildId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Prstatus  (NT_PRSTATUS)
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified parsed `NT_PRSTATUS` from a Linux core dump.
///
/// Only the fields that can be decoded portably (without arch-specific register
/// arrays) are extracted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prstatus {
    /// Signal info: pending signal number.
    pub si_signo: i32,
    /// Signal info: signal code.
    pub si_code: i32,
    /// Signal info: `errno` at the time of the signal.
    pub si_errno: i32,
    /// Current signal number.
    pub pr_cursig: i16,
    /// Process ID.
    pub pr_pid: i32,
    /// Parent PID.
    pub pr_ppid: i32,
    /// Process group.
    pub pr_pgrp: i32,
    /// Session ID.
    pub pr_sid: i32,
}

impl Prstatus {
    /// Parse a `NT_PRSTATUS` descriptor (little-endian, 64-bit layout).
    ///
    /// Returns `None` if the descriptor is too short.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_endian(data, true)
    }

    /// Endianness-aware variant of [`Prstatus::parse`]; pass `le = false` for
    /// big-endian core dumps.
    ///
    /// Returns `None` if the descriptor is too short.
    #[must_use]
    pub fn parse_endian(data: &[u8], le: bool) -> Option<Self> {
        // Minimum size to read through pr_sid: ~76 bytes in the 64-bit layout.
        if data.len() < 76 {
            return None;
        }
        let read_i32 = |off: usize| -> i32 {
            let b = data[off..off + 4].try_into().unwrap_or([0u8; 4]);
            if le {
                i32::from_le_bytes(b)
            } else {
                i32::from_be_bytes(b)
            }
        };
        let read_i16 = |off: usize| -> i16 {
            let b = data[off..off + 2].try_into().unwrap_or([0u8; 2]);
            if le {
                i16::from_le_bytes(b)
            } else {
                i16::from_be_bytes(b)
            }
        };

        Some(Self {
            si_signo: read_i32(0),
            si_code: read_i32(4),
            si_errno: read_i32(8),
            pr_cursig: read_i16(12),
            // offset 14: padding
            // offset 16: pr_sigpend (8 bytes) — skipped
            // offset 24: pr_sighold (8 bytes) — skipped
            pr_pid: read_i32(32),
            pr_ppid: read_i32(36),
            pr_pgrp: read_i32(40),
            pr_sid: read_i32(44),
            // offsets 48..76: utime/stime/cutime/cstime timeval pairs — skipped
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Prpsinfo  (NT_PRPSINFO)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `NT_PRPSINFO` from a Linux core dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prpsinfo {
    /// Process state character (e.g. `R`, `S`, `Z`).
    pub pr_state: u8,
    /// Process name (up to 16 bytes, NUL-terminated).
    pub pr_fname: String,
    /// Full command-line arguments (up to 80 bytes, NUL-terminated).
    pub pr_psargs: String,
    /// Process UID.
    pub pr_uid: u32,
    /// Process GID.
    pub pr_gid: u32,
    /// Process ID.
    pub pr_pid: i32,
    /// Parent PID.
    pub pr_ppid: i32,
    /// Process group.
    pub pr_pgrp: i32,
    /// Session ID.
    pub pr_sid: i32,
}

impl Prpsinfo {
    /// Parse a `NT_PRPSINFO` descriptor (64-bit Linux layout, little-endian).
    ///
    /// Returns `None` if the descriptor is too short.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_endian(data, true)
    }

    /// Endianness-aware variant of [`Prpsinfo::parse`]; pass `le = false` for
    /// big-endian core dumps.
    ///
    /// Returns `None` if the descriptor is too short.
    #[must_use]
    pub fn parse_endian(data: &[u8], le: bool) -> Option<Self> {
        // 64-bit prpsinfo: state(1) + sname(1) + zombie(1) + nice(1) + flag(8) +
        //                  uid(4) + gid(4) + pid(4) + ppid(4) + pgrp(4) + sid(4) +
        //                  fname(16) + psargs(80) = 136 bytes
        if data.len() < 136 {
            return None;
        }
        let fetch_signed = |off: usize| -> i32 {
            let b = data[off..off + 4].try_into().unwrap_or([0u8; 4]);
            if le {
                i32::from_le_bytes(b)
            } else {
                i32::from_be_bytes(b)
            }
        };
        let fetch_unsigned = |off: usize| -> u32 {
            let b = data[off..off + 4].try_into().unwrap_or([0u8; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };

        let pr_state = data[0];
        let user_id = fetch_unsigned(12);
        let group_id = fetch_unsigned(16);
        let proc_id = fetch_signed(20);
        let parent_id = fetch_signed(24);
        let pgrp_id = fetch_signed(28);
        let sess_id = fetch_signed(32);

        let fname_bytes = &data[36..52];
        let pr_fname = cstr_to_string(fname_bytes);

        let psargs_bytes = &data[52..132];
        let pr_psargs = cstr_to_string(psargs_bytes);

        Some(Self {
            pr_state,
            pr_fname,
            pr_psargs,
            pr_uid: user_id,
            pr_gid: group_id,
            pr_pid: proc_id,
            pr_ppid: parent_id,
            pr_pgrp: pgrp_id,
            pr_sid: sess_id,
        })
    }
}

/// Convert a fixed-size NUL-terminated byte slice to a `String`.
fn cstr_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// ElfNoteSection  — the collection of notes from one note section
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed ELF note section: all notes extracted from a single `.note.*`
/// section (or a `PT_NOTE` segment).
#[derive(Debug, Clone)]
pub struct ElfNoteSection {
    /// All notes in the order they appeared in the section.
    pub notes: Vec<ElfNote>,
}

impl ElfNoteSection {
    /// Create an empty note section.
    #[must_use]
    pub const fn new() -> Self {
        Self { notes: Vec::new() }
    }

    /// Number of notes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.notes.len()
    }

    /// Return `true` if there are no notes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Find the first GNU build-ID note, if present.
    #[must_use]
    pub fn build_id(&self) -> Option<GnuBuildId> {
        self.notes.iter().find_map(ElfNote::as_build_id)
    }

    /// Find all notes with a given namespace.
    #[must_use]
    pub fn notes_for_namespace<'a>(&'a self, ns: &str) -> Vec<&'a ElfNote> {
        self.notes.iter().filter(|n| n.namespace == ns).collect()
    }

    /// Find all GNU notes.
    #[must_use]
    pub fn gnu_notes(&self) -> Vec<&ElfNote> {
        self.notes_for_namespace("GNU")
    }

    /// Find all CORE notes.
    #[must_use]
    pub fn core_notes(&self) -> Vec<&ElfNote> {
        self.notes_for_namespace("CORE")
    }

    /// Return the first `NT_PRSTATUS` note, if present.
    #[must_use]
    pub fn prstatus(&self) -> Option<Prstatus> {
        self.notes.iter().find_map(ElfNote::as_prstatus)
    }

    /// Return the first `NT_PRPSINFO` note, if present.
    #[must_use]
    pub fn prpsinfo(&self) -> Option<Prpsinfo> {
        self.notes.iter().find_map(ElfNote::as_prpsinfo)
    }
}

impl Default for ElfNoteSection {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_note_section
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw ELF note section / segment (little-endian byte order).
///
/// The note format is:
/// ```text
/// [namesz: u32][descsz: u32][type: u32][name: namesz bytes, padded to 4][desc: descsz bytes, padded to 4]
/// ```
///
/// # Errors
///
/// Returns `Err(String)` if the data is malformed (out-of-bounds reads,
/// invalid UTF-8 in namespace, etc.).
pub fn parse_note_section(data: &[u8]) -> Result<ElfNoteSection, String> {
    parse_note_section_endian(data, true)
}

/// Endianness-aware variant of [`parse_note_section`].
///
/// Pass `le = false` for big-endian ELF objects, where `namesz`, `descsz` and
/// `type` in each note header are stored most-significant byte first. The
/// descriptor payload itself is returned verbatim in both cases.
///
/// # Errors
///
/// Returns `Err(String)` if the data is malformed (out-of-bounds reads,
/// invalid UTF-8 in namespace, etc.).
pub fn parse_note_section_endian(data: &[u8], le: bool) -> Result<ElfNoteSection, String> {
    let mut offset = 0usize;
    let mut notes = Vec::new();

    while offset + 12 <= data.len() {
        let namesz = read_u32(data, offset, le)? as usize;
        let descsz = read_u32(data, offset + 4, le)? as usize;
        let n_type = read_u32(data, offset + 8, le)?;
        offset += 12;

        // Read name (NUL-terminated, padded to 4-byte alignment)
        if namesz == 0 {
            // No name — skip padded blocks and continue
            offset += align4(descsz);
            continue;
        }
        if offset + namesz > data.len() {
            return Err(format!("note namesz {namesz} overflows at offset {offset}"));
        }
        let name_bytes = &data[offset..offset + namesz];
        // Strip trailing NUL
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(namesz);
        let namespace = std::str::from_utf8(&name_bytes[..name_end])
            .map_err(|e| format!("note name not UTF-8: {e}"))?
            .to_owned();
        offset += align4(namesz);

        // Read descriptor
        if offset + descsz > data.len() {
            return Err(format!("note descsz {descsz} overflows at offset {offset}"));
        }
        let descriptor = data[offset..offset + descsz].to_vec();
        offset += align4(descsz);

        // Classify note type
        let note_type = match namespace.as_str() {
            "GNU" => NoteType::Gnu(GnuNoteType::from_raw(n_type)),
            "CORE" => NoteType::Core(CoreNoteType::from_raw(n_type)),
            _ => NoteType::Unknown {
                namespace: namespace.clone(),
                raw_type: n_type,
            },
        };

        notes.push(ElfNote {
            namespace,
            note_type,
            descriptor,
        });
    }

    Ok(ElfNoteSection { notes })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Round `n` up to the next multiple of 4.
#[inline]
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read a `u32` from `data` at `offset` with the given byte order.
fn read_u32(data: &[u8], offset: usize, le: bool) -> Result<u32, String> {
    let b: [u8; 4] = data
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("read_u32_le out of bounds at {offset}"))?;
    Ok(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// AbiTag
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `NT_GNU_ABI_TAG` note descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuAbiTag {
    /// OS identifier: 0 = Linux, 1 = Hurd, 2 = Solaris, 3 = FreeBSD.
    pub os: u32,
    /// Major kernel version.
    pub major: u32,
    /// Minor kernel version.
    pub minor: u32,
    /// Patch kernel version.
    pub patch: u32,
}

impl GnuAbiTag {
    /// Parse from a 16-byte `NT_GNU_ABI_TAG` descriptor.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 16 bytes.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (cannot happen when data is at least 16 bytes).
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_endian(data, true)
    }

    /// Endianness-aware variant of [`GnuAbiTag::parse`]; pass `le = false` for
    /// big-endian ELF objects.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 16 bytes.
    pub fn parse_endian(data: &[u8], le: bool) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!("NT_GNU_ABI_TAG too short: {} bytes", data.len()));
        }
        let os = read_u32(data, 0, le)?;
        let major = read_u32(data, 4, le)?;
        let minor = read_u32(data, 8, le)?;
        let patch = read_u32(data, 12, le)?;
        Ok(Self {
            os,
            major,
            minor,
            patch,
        })
    }

    /// Return a human-readable OS name.
    #[must_use]
    pub const fn os_name(&self) -> &'static str {
        match self.os {
            0 => "Linux",
            1 => "Hurd",
            2 => "Solaris",
            3 => "FreeBSD",
            _ => "Unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NT_FILE  (mapped-files list in a core dump)
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the `NT_FILE` note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtFileEntry {
    /// Start virtual address of the mapping.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// File offset in pages.
    pub offset: u64,
    /// File path name.
    pub filename: String,
}

/// Parsed `NT_FILE` note from a Linux core dump.
#[derive(Debug, Clone)]
pub struct NtFile {
    /// All file mappings.
    pub entries: Vec<NtFileEntry>,
    /// Page size used when interpreting offsets.
    pub page_size: u64,
}

impl NtFile {
    /// Parse a little-endian 64-bit `NT_FILE` descriptor.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if parsing fails.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (cannot happen when data is at least 16 bytes).
    pub fn parse64(data: &[u8]) -> Result<Self, String> {
        Self::parse64_endian(data, true)
    }

    /// Endianness-aware variant of [`NtFile::parse64`]; pass `le = false` for
    /// big-endian ELF core dumps.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if parsing fails.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (cannot happen after the
    /// length checks above).
    pub fn parse64_endian(data: &[u8], le: bool) -> Result<Self, String> {
        let rd64 = |b: &[u8]| -> u64 {
            let a: [u8; 8] = b.try_into().unwrap_or([0u8; 8]);
            if le {
                u64::from_le_bytes(a)
            } else {
                u64::from_be_bytes(a)
            }
        };
        if data.len() < 16 {
            return Err("NT_FILE too short".into());
        }
        let count_raw = rd64(&data[0..8]);
        // Guard against absurdly large counts (each entry needs at least 24 bytes for the
        // triplet, so the section data length is a tight upper bound).
        let count = usize::try_from(count_raw)
            .map_err(|_| format!("NT_FILE count {count_raw} overflows usize"))?;
        let page_size = rd64(&data[8..16]);

        // The next `count * 3 * 8` bytes are the start/end/offset triplets.
        let triplets_size = count
            .checked_mul(24)
            .ok_or_else(|| format!("NT_FILE: triplets_size overflows for count={count}"))?;
        if triplets_size
            .checked_add(16)
            .is_none_or(|need| data.len() < need)
        {
            return Err(format!("NT_FILE: too short for {count} entries"));
        }

        let mut entries = Vec::with_capacity(count);
        let mut off = 16usize;

        let mut starts = Vec::with_capacity(count);
        let mut ends = Vec::with_capacity(count);
        let mut offsets = Vec::with_capacity(count);

        for _ in 0..count {
            starts.push(rd64(&data[off..off + 8]));
            off += 8;
            ends.push(rd64(&data[off..off + 8]));
            off += 8;
            offsets.push(rd64(&data[off..off + 8]));
            off += 8;
        }

        // After the triplets comes a sequence of NUL-terminated filenames.
        for i in 0..count {
            let name_end = data[off..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| format!("NT_FILE: missing NUL for entry {i}"))?;
            let filename = String::from_utf8_lossy(&data[off..off + name_end]).into_owned();
            off += name_end + 1;
            entries.push(NtFileEntry {
                start: starts[i],
                end: ends[i],
                offset: offsets[i],
                filename,
            });
        }

        Ok(Self { entries, page_size })
    }

    /// Look up all mappings that contain the given virtual address.
    #[must_use]
    pub fn mappings_for_addr(&self, addr: u64) -> Vec<&NtFileEntry> {
        self.entries
            .iter()
            .filter(|e| addr >= e.start && addr < e.end)
            .collect()
    }

    /// Look up all entries for the given filename (exact match).
    #[must_use]
    pub fn entries_for_file<'a>(&'a self, path: &str) -> Vec<&'a NtFileEntry> {
        self.entries.iter().filter(|e| e.filename == path).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal GNU build-ID note section in little-endian.
    fn make_gnu_build_id_note(build_id: &[u8]) -> Vec<u8> {
        let name = b"GNU\0"; // 4 bytes (namesz = 4, already aligned)
        let namesz: u32 = 4;
        let descsz: u32 = build_id.len() as u32;
        let n_type: u32 = 3; // NT_GNU_BUILD_ID
        let mut data = Vec::new();
        data.extend_from_slice(&namesz.to_le_bytes());
        data.extend_from_slice(&descsz.to_le_bytes());
        data.extend_from_slice(&n_type.to_le_bytes());
        data.extend_from_slice(name);
        data.extend_from_slice(build_id);
        // Pad descriptor to 4-byte alignment
        let pad = (4 - (build_id.len() % 4)) % 4;
        data.extend(std::iter::repeat_n(0u8, pad));
        data
    }

    #[test]
    fn test_parse_gnu_build_id_note() {
        let build_id: [u8; 20] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
            0xba, 0xbe, 0x11, 0x22, 0x33, 0x44,
        ];
        let raw = make_gnu_build_id_note(&build_id);
        let sec = parse_note_section(&raw).unwrap();
        assert_eq!(sec.len(), 1);
        let bid = sec.build_id().unwrap();
        assert_eq!(bid.bytes, build_id);
        assert_eq!(bid.algorithm_hint(), "sha1");
    }

    #[test]
    fn test_gnu_build_id_hex() {
        let bid = GnuBuildId {
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(bid.as_hex(), "deadbeef");
    }

    #[test]
    fn test_gnu_build_id_display() {
        let bid = GnuBuildId {
            bytes: vec![0xca, 0xfe],
        };
        assert_eq!(format!("{bid}"), "cafe");
    }

    #[test]
    fn test_gnu_build_id_algorithm_hint_md5() {
        let bid = GnuBuildId {
            bytes: vec![0u8; 16],
        };
        assert_eq!(bid.algorithm_hint(), "md5");
    }

    #[test]
    fn test_gnu_build_id_algorithm_hint_unknown() {
        let bid = GnuBuildId {
            bytes: vec![0u8; 8],
        };
        assert_eq!(bid.algorithm_hint(), "unknown");
    }

    #[test]
    fn test_parse_note_section_too_short() {
        // Less than 12 bytes — should produce an empty section, not an error.
        let sec = parse_note_section(&[0u8; 8]).unwrap();
        assert!(sec.is_empty());
    }

    #[test]
    fn test_parse_note_section_empty() {
        let sec = parse_note_section(&[]).unwrap();
        assert!(sec.is_empty());
    }

    #[test]
    fn test_note_type_gnu_from_raw() {
        assert_eq!(GnuNoteType::from_raw(1), GnuNoteType::AbiTag);
        assert_eq!(GnuNoteType::from_raw(3), GnuNoteType::BuildId);
        assert_eq!(GnuNoteType::from_raw(99), GnuNoteType::Other(99));
    }

    #[test]
    fn test_note_type_gnu_as_raw() {
        assert_eq!(GnuNoteType::BuildId.as_raw(), 3);
        assert_eq!(GnuNoteType::AbiTag.as_raw(), 1);
    }

    #[test]
    fn test_core_note_type_from_raw() {
        assert_eq!(CoreNoteType::from_raw(1), CoreNoteType::PrStatus);
        assert_eq!(CoreNoteType::from_raw(3), CoreNoteType::PrPsInfo);
        assert_eq!(CoreNoteType::from_raw(0x4649_4c45), CoreNoteType::File);
    }

    #[test]
    fn test_gnu_abi_tag_parse() {
        let mut data = vec![0u8; 16];
        // OS = 0 (Linux), major = 3, minor = 10, patch = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..8].copy_from_slice(&3u32.to_le_bytes());
        data[8..12].copy_from_slice(&10u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        let tag = GnuAbiTag::parse(&data).unwrap();
        assert_eq!(tag.os_name(), "Linux");
        assert_eq!(tag.major, 3);
        assert_eq!(tag.minor, 10);
    }

    #[test]
    fn test_gnu_abi_tag_too_short() {
        assert!(GnuAbiTag::parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    #[test]
    fn test_prstatus_parse_too_short() {
        assert!(Prstatus::parse(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_prstatus_parse_minimal() {
        let data = vec![0u8; 76];
        let ps = Prstatus::parse(&data).unwrap();
        assert_eq!(ps.si_signo, 0);
        assert_eq!(ps.pr_pid, 0);
    }

    #[test]
    fn test_prpsinfo_parse_too_short() {
        assert!(Prpsinfo::parse(&[0u8; 100]).is_none());
    }

    #[test]
    fn test_prpsinfo_parse_minimal() {
        let mut data = vec![0u8; 136];
        // Write "bash" into fname field at offset 36
        data[36..40].copy_from_slice(b"bash");
        let pi = Prpsinfo::parse(&data).unwrap();
        assert_eq!(pi.pr_fname, "bash");
    }

    #[test]
    fn test_elf_note_section_notes_for_namespace() {
        let raw = make_gnu_build_id_note(&[0xabu8; 20]);
        let sec = parse_note_section(&raw).unwrap();
        let gnu = sec.gnu_notes();
        assert_eq!(gnu.len(), 1);
        let core = sec.core_notes();
        assert!(core.is_empty());
    }

    #[test]
    fn test_elf_note_section_default() {
        let sec = ElfNoteSection::default();
        assert!(sec.is_empty());
        assert_eq!(sec.len(), 0);
    }

    #[test]
    fn test_nt_file_parse64_minimal() {
        // Build a minimal NT_FILE: count=1, page_size=4096, one entry
        let mut data = Vec::new();
        data.extend_from_slice(&1u64.to_le_bytes()); // count
        data.extend_from_slice(&4096u64.to_le_bytes()); // page_size
        // triplet: start=0x7fff0000, end=0x7fff1000, offset=0
        data.extend_from_slice(&0x7fff_0000_u64.to_le_bytes());
        data.extend_from_slice(&0x7fff_1000_u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        // filename
        data.extend_from_slice(b"/lib/libc.so\0");
        let nt = NtFile::parse64(&data).unwrap();
        assert_eq!(nt.entries.len(), 1);
        assert_eq!(nt.entries[0].filename, "/lib/libc.so");
        assert_eq!(nt.entries[0].start, 0x7fff_0000);
    }

    #[test]
    fn test_nt_file_mappings_for_addr() {
        let entry = NtFileEntry {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            filename: "/foo".to_string(),
        };
        let nt = NtFile {
            entries: vec![entry],
            page_size: 4096,
        };
        assert_eq!(nt.mappings_for_addr(0x1500).len(), 1);
        assert!(nt.mappings_for_addr(0x3000).is_empty());
    }

    #[test]
    fn test_nt_file_entries_for_file() {
        let entry = NtFileEntry {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            filename: "/usr/lib/libfoo.so".to_string(),
        };
        let nt = NtFile {
            entries: vec![entry],
            page_size: 4096,
        };
        assert_eq!(nt.entries_for_file("/usr/lib/libfoo.so").len(), 1);
        assert!(nt.entries_for_file("/other").is_empty());
    }

    #[test]
    fn test_cstr_to_string_no_nul() {
        let s = cstr_to_string(b"hello");
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_cstr_to_string_with_nul() {
        let s = cstr_to_string(b"hello\0world");
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_gnu_build_id_is_empty() {
        let empty = GnuBuildId { bytes: vec![] };
        assert!(empty.is_empty());
        let nonempty = GnuBuildId { bytes: vec![1] };
        assert!(!nonempty.is_empty());
    }

    // ── Big-endian support ────────────────────────────────────────────────────

    /// Build one note with big-endian header fields.
    fn be_note(namespace: &[u8], n_type: u32, desc: &[u8]) -> Vec<u8> {
        let namesz = namespace.len() as u32 + 1; // include the NUL
        let mut out = Vec::new();
        out.extend_from_slice(&namesz.to_be_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_be_bytes());
        out.extend_from_slice(&n_type.to_be_bytes());
        out.extend_from_slice(namespace);
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(desc);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    #[test]
    fn test_parse_note_section_big_endian() {
        let desc = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let data = be_note(b"GNU", 3, &desc); // NT_GNU_BUILD_ID
        let section = parse_note_section_endian(&data, false).unwrap();
        assert_eq!(section.notes.len(), 1);
        assert_eq!(section.notes[0].namespace, "GNU");
        assert!(matches!(
            section.notes[0].note_type,
            NoteType::Gnu(GnuNoteType::BuildId)
        ));
        assert_eq!(section.notes[0].as_build_id().unwrap().as_hex(), "deadbeef");
    }

    #[test]
    fn test_parse_note_section_le_reader_misreads_be_data() {
        // Guard on the bug this pass fixes: BE note headers read with the LE
        // reader must not silently produce the same, correct result.
        let data = be_note(b"GNU", 3, &[0x01, 0x02, 0x03, 0x04]);

        let be = parse_note_section_endian(&data, false).unwrap();
        assert_eq!(be.notes.len(), 1);
        assert_eq!(be.notes[0].namespace, "GNU");
        assert!(be.notes[0].as_build_id().is_some());

        // Reading the same bytes as LE turns namesz=3 into 0x03000000, so the
        // parse either errors out or fails to recognise the GNU build-ID note.
        let le_ok = parse_note_section(&data).is_ok_and(|s| {
            s.notes.len() == 1 && s.notes[0].as_build_id().is_some()
        });
        assert!(!le_ok, "LE reader must not decode BE notes correctly");
    }

    #[test]
    fn test_gnu_abi_tag_big_endian() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&0u32.to_be_bytes()); // os = Linux
        desc.extend_from_slice(&2u32.to_be_bytes()); // major
        desc.extend_from_slice(&6u32.to_be_bytes()); // minor
        desc.extend_from_slice(&32u32.to_be_bytes()); // patch
        let tag = GnuAbiTag::parse_endian(&desc, false).unwrap();
        assert_eq!(tag.os, 0);
        assert_eq!(tag.major, 2);
        assert_eq!(tag.minor, 6);
        assert_eq!(tag.patch, 32);
        // Same bytes read as LE are byte-swapped.
        assert_eq!(GnuAbiTag::parse(&desc).unwrap().major, 2u32.swap_bytes());
    }

    #[test]
    fn test_nt_file_parse64_big_endian() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u64.to_be_bytes()); // count
        data.extend_from_slice(&0x1000u64.to_be_bytes()); // page_size
        data.extend_from_slice(&0x4000_0000u64.to_be_bytes()); // start
        data.extend_from_slice(&0x4000_1000u64.to_be_bytes()); // end
        data.extend_from_slice(&0u64.to_be_bytes()); // file offset
        data.extend_from_slice(b"/lib/libc.so.6\0");

        let nt = NtFile::parse64_endian(&data, false).unwrap();
        assert_eq!(nt.page_size, 0x1000);
        assert_eq!(nt.entries.len(), 1);
        assert_eq!(nt.entries[0].start, 0x4000_0000);
        assert_eq!(nt.entries[0].end, 0x4000_1000);
        assert_eq!(nt.entries[0].filename, "/lib/libc.so.6");
    }

    #[test]
    fn test_le_wrappers_delegate_unchanged() {
        // The historical LE entry points must stay equivalent to the endian-aware
        // ones invoked with le = true.
        let mut desc = Vec::new();
        desc.extend_from_slice(&0u32.to_le_bytes());
        desc.extend_from_slice(&2u32.to_le_bytes());
        desc.extend_from_slice(&6u32.to_le_bytes());
        desc.extend_from_slice(&32u32.to_le_bytes());
        assert_eq!(
            GnuAbiTag::parse(&desc).unwrap(),
            GnuAbiTag::parse_endian(&desc, true).unwrap()
        );
        assert_eq!(
            Prstatus::parse(&[0u8; 80]),
            Prstatus::parse_endian(&[0u8; 80], true)
        );
        assert_eq!(
            Prpsinfo::parse(&[0u8; 140]),
            Prpsinfo::parse_endian(&[0u8; 140], true)
        );
    }
}
