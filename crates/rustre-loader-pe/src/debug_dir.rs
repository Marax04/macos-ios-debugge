//! PE debug directory parser — `IMAGE_DEBUG_DIRECTORY`, PDB paths, GUID/age.

use crate::imports::RvaSection;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const IMAGE_DEBUG_TYPE_UNKNOWN: u32 = 0;
pub const IMAGE_DEBUG_TYPE_COFF: u32 = 1;
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const IMAGE_DEBUG_TYPE_FPO: u32 = 3;
pub const IMAGE_DEBUG_TYPE_MISC: u32 = 4;
pub const IMAGE_DEBUG_TYPE_EXCEPTION: u32 = 5;
pub const IMAGE_DEBUG_TYPE_FIXUP: u32 = 6;
pub const IMAGE_DEBUG_TYPE_OMAP_TO_SRC: u32 = 7;
pub const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: u32 = 8;
pub const IMAGE_DEBUG_TYPE_BORLAND: u32 = 9;
pub const IMAGE_DEBUG_TYPE_RESERVED10: u32 = 10;
pub const IMAGE_DEBUG_TYPE_CLSID: u32 = 11;
pub const IMAGE_DEBUG_TYPE_VC_FEATURE: u32 = 12;
pub const IMAGE_DEBUG_TYPE_POGO: u32 = 13;
pub const IMAGE_DEBUG_TYPE_ILTCG: u32 = 14;
pub const IMAGE_DEBUG_TYPE_MPX: u32 = 15;
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
pub const IMAGE_DEBUG_TYPE_SPGO: u32 = 18;
pub const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;

// CodeView signatures
const CV_SIGNATURE_RSDS: u32 = 0x5344_5352; // "RSDS"
const CV_SIGNATURE_NB10: u32 = 0x3031_424E; // "NB10"

/// Human-readable name for a debug type.
#[must_use]
pub const fn debug_type_name(t: u32) -> &'static str {
    match t {
        IMAGE_DEBUG_TYPE_UNKNOWN => "UNKNOWN",
        IMAGE_DEBUG_TYPE_COFF => "COFF",
        IMAGE_DEBUG_TYPE_CODEVIEW => "CODEVIEW",
        IMAGE_DEBUG_TYPE_FPO => "FPO",
        IMAGE_DEBUG_TYPE_MISC => "MISC",
        IMAGE_DEBUG_TYPE_EXCEPTION => "EXCEPTION",
        IMAGE_DEBUG_TYPE_FIXUP => "FIXUP",
        IMAGE_DEBUG_TYPE_OMAP_TO_SRC => "OMAP_TO_SRC",
        IMAGE_DEBUG_TYPE_OMAP_FROM_SRC => "OMAP_FROM_SRC",
        IMAGE_DEBUG_TYPE_BORLAND => "BORLAND",
        IMAGE_DEBUG_TYPE_VC_FEATURE => "VC_FEATURE",
        IMAGE_DEBUG_TYPE_POGO => "POGO",
        IMAGE_DEBUG_TYPE_ILTCG => "ILTCG",
        IMAGE_DEBUG_TYPE_MPX => "MPX",
        IMAGE_DEBUG_TYPE_REPRO => "REPRO",
        IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS => "EX_DLLCHARACTERISTICS",
        _ => "UNKNOWN_TYPE",
    }
}

// ---------------------------------------------------------------------------
// IMAGE_DEBUG_DIRECTORY
// ---------------------------------------------------------------------------

/// One entry in the debug directory (28 bytes each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugDirectoryEntry {
    /// Characteristics (reserved, 0).
    pub characteristics: u32,
    /// Timestamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Type of debug information stored (`IMAGE_DEBUG_TYPE_*`).
    pub debug_type: u32,
    /// Size of the debug data.
    pub size_of_data: u32,
    /// RVA of the debug data.
    pub address_of_raw_data: u32,
    /// File offset of the debug data.
    pub pointer_to_raw_data: u32,
}

impl DebugDirectoryEntry {
    /// Parse one 28-byte entry from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `data` is too short to hold a complete entry at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 28 > data.len() {
            return Err(format!(
                "Debug directory entry truncated at offset {offset}"
            ));
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;
        Ok(Self {
            characteristics: r32(b),
            time_date_stamp: r32(b + 4),
            major_version: r16(b + 8),
            minor_version: r16(b + 10),
            debug_type: r32(b + 12),
            size_of_data: r32(b + 16),
            address_of_raw_data: r32(b + 20),
            pointer_to_raw_data: r32(b + 24),
        })
    }

    /// Return `true` if this is a `CodeView` entry.
    #[must_use]
    pub const fn is_codeview(&self) -> bool {
        self.debug_type == IMAGE_DEBUG_TYPE_CODEVIEW
    }

    /// Return a human-readable type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        debug_type_name(self.debug_type)
    }
}

// ---------------------------------------------------------------------------
// CodeView PDB info
// ---------------------------------------------------------------------------

/// A GUID from the `RSDS` `CodeView` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl PdbGuid {
    /// Format GUID + age as the symbol server hash used in the .pdb path.
    #[must_use]
    pub fn symbol_server_key(&self, age: u32) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
            age,
        )
    }
}

impl std::fmt::Display for PdbGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

/// Parsed `RSDS` (PDB 7.0) `CodeView` record.
#[derive(Debug, Clone)]
pub struct RsdsRecord {
    /// PDB GUID.
    pub guid: PdbGuid,
    /// PDB age (incremented on each relink).
    pub age: u32,
    /// Path to the PDB file.
    pub pdb_path: String,
}

impl RsdsRecord {
    /// Parse an RSDS record from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if data is too short or the signature is invalid.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 24 {
            return Err(format!("RSDS record too short: {} bytes", data.len()));
        }
        let sig = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if sig != CV_SIGNATURE_RSDS {
            return Err(format!("Not an RSDS record (sig=0x{sig:08X})"));
        }
        let data1 = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        let data2 = u16::from_le_bytes(data[8..10].try_into().unwrap_or([0; 2]));
        let data3 = u16::from_le_bytes(data[10..12].try_into().unwrap_or([0; 2]));
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&data[12..20]);
        let age = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));

        let path_bytes = &data[24..];
        let nul = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let pdb_path = String::from_utf8_lossy(&path_bytes[..nul]).into_owned();

        Ok(Self {
            guid: PdbGuid {
                data1,
                data2,
                data3,
                data4,
            },
            age,
            pdb_path,
        })
    }

    /// The relative pdb path (just the filename, not the full path).
    #[must_use]
    pub fn pdb_filename(&self) -> &str {
        self.pdb_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.pdb_path)
    }
}

/// Parsed `NB10` (PDB 2.0) `CodeView` record.
#[derive(Debug, Clone)]
pub struct Nb10Record {
    /// File offset of the PDB within the stream.
    pub offset: u32,
    /// Signature / timestamp.
    pub signature: u32,
    /// PDB age.
    pub age: u32,
    /// Path to the PDB file.
    pub pdb_path: String,
}

impl Nb10Record {
    /// Parse an NB10 record from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if data is too short or the signature is invalid.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!("NB10 record too short: {} bytes", data.len()));
        }
        let sig = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if sig != CV_SIGNATURE_NB10 {
            return Err(format!("Not an NB10 record (sig=0x{sig:08X})"));
        }
        let offset = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        let signature = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
        let age = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));

        let path_bytes = &data[16..];
        let nul = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let pdb_path = String::from_utf8_lossy(&path_bytes[..nul]).into_owned();

        Ok(Self {
            offset,
            signature,
            age,
            pdb_path,
        })
    }
}

// ---------------------------------------------------------------------------
// Parsed debug information
// ---------------------------------------------------------------------------

/// The `CodeView` debug info extracted from the debug directory.
#[derive(Debug, Clone)]
pub enum CodeViewInfo {
    /// PDB 7.0 (RSDS).
    Rsds(RsdsRecord),
    /// PDB 2.0 (NB10).
    Nb10(Nb10Record),
}

impl CodeViewInfo {
    /// Return the PDB path string.
    #[must_use]
    pub fn pdb_path(&self) -> &str {
        match self {
            Self::Rsds(r) => &r.pdb_path,
            Self::Nb10(r) => &r.pdb_path,
        }
    }

    /// Return the PDB filename only.
    #[must_use]
    pub fn pdb_filename(&self) -> &str {
        match self {
            Self::Rsds(r) => r.pdb_filename(),
            Self::Nb10(r) => r.pdb_path.rsplit(['\\', '/']).next().unwrap_or(&r.pdb_path),
        }
    }

    /// Return the GUID, if this is an RSDS record.
    #[must_use]
    pub const fn guid(&self) -> Option<&PdbGuid> {
        if let Self::Rsds(r) = self {
            Some(&r.guid)
        } else {
            None
        }
    }

    /// Return the age.
    #[must_use]
    pub const fn age(&self) -> u32 {
        match self {
            Self::Rsds(r) => r.age,
            Self::Nb10(r) => r.age,
        }
    }
}

// ---------------------------------------------------------------------------
// Parse debug directory
// ---------------------------------------------------------------------------

/// Parse all debug directory entries from the PE debug data directory.
#[must_use]
pub fn parse_debug_directory(
    data: &[u8],
    sections: &[RvaSection],
    debug_dir_rva: u32,
    debug_dir_size: u32,
) -> Vec<DebugDirectoryEntry> {
    use crate::imports::rva_to_file_offset;

    let Some(dir_off) = rva_to_file_offset(debug_dir_rva, sections) else {
        return Vec::new();
    };

    // `debug_dir_size` is a raw u32 from the data directory: cap by the bytes
    // actually remaining in the buffer (each entry is 28 bytes).
    let num_entries = (debug_dir_size as usize / 28).min(data.len().saturating_sub(dir_off) / 28);
    let mut entries = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let off = dir_off + i * 28;
        if off + 28 > data.len() {
            break;
        }
        if let Ok(entry) = DebugDirectoryEntry::parse(data, off) {
            entries.push(entry);
        }
    }

    entries
}

/// Extract the first `CodeView` debug info from the debug directory.
#[must_use]
pub fn extract_codeview_info(data: &[u8], entries: &[DebugDirectoryEntry]) -> Option<CodeViewInfo> {
    for entry in entries {
        if !entry.is_codeview() {
            continue;
        }
        let raw_off = entry.pointer_to_raw_data as usize;
        let raw_size = entry.size_of_data as usize;
        if raw_off == 0 || raw_size < 4 || raw_off + raw_size > data.len() {
            continue;
        }
        let cv_data = &data[raw_off..raw_off + raw_size];
        let sig = u32::from_le_bytes(cv_data[0..4].try_into().unwrap_or([0; 4]));
        match sig {
            s if s == CV_SIGNATURE_RSDS => {
                if let Ok(rsds) = RsdsRecord::parse(cv_data) {
                    return Some(CodeViewInfo::Rsds(rsds));
                }
            }
            s if s == CV_SIGNATURE_NB10 => {
                if let Ok(nb10) = Nb10Record::parse(cv_data) {
                    return Some(CodeViewInfo::Nb10(nb10));
                }
            }
            _ => {}
        }
    }
    None
}

/// Detect if the binary appears to be a .NET managed assembly.
///
/// The .NET CLI header lives in data directory entry 14 (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`).
/// Returns `true` if that directory entry has a non-zero virtual address.
#[must_use]
pub const fn detect_dotnet(optional_header_dotnet_rva: u32) -> bool {
    optional_header_dotnet_rva != 0
}

// ---------------------------------------------------------------------------
// VC_FEATURE debug record
// ---------------------------------------------------------------------------

/// Parsed VC++ feature debug record (present in recent MSVC binaries).
#[derive(Debug, Clone)]
pub struct VcFeatureRecord {
    /// Count of pre-C-runtime calls or guard features.
    pub pre_vc_plus_plus_count: u32,
    /// Number of C++ functions with cookie-based security.
    pub c_plus_plus_count: u32,
    /// Guard stack count (/GS).
    pub gs_count: u32,
    /// SDL count.
    pub sdl_count: u32,
}

impl VcFeatureRecord {
    /// Parse a `VC_FEATURE` record (minimum 16 bytes).
    ///
    /// # Errors
    ///
    /// Returns `Err` if data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!("VC_FEATURE record too short: {} bytes", data.len()));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            pre_vc_plus_plus_count: r32(0),
            c_plus_plus_count: r32(4),
            gs_count: r32(8),
            sdl_count: r32(12),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rsds_record(pdb_path: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CV_SIGNATURE_RSDS.to_le_bytes()); // sig
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // data1
        buf.extend_from_slice(&0xCAFEu16.to_le_bytes()); // data2
        buf.extend_from_slice(&0x1234u16.to_le_bytes()); // data3
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // data4
        buf.extend_from_slice(&1u32.to_le_bytes()); // age
        buf.extend_from_slice(pdb_path.as_bytes());
        buf.push(0); // NUL
        buf
    }

    #[test]
    fn test_rsds_record_parse() {
        let data = make_rsds_record("C:\\Symbols\\test.pdb");
        let rec = RsdsRecord::parse(&data).unwrap();
        assert_eq!(rec.pdb_path, "C:\\Symbols\\test.pdb");
        assert_eq!(rec.age, 1);
        assert_eq!(rec.guid.data1, 0xDEAD_BEEF);
    }

    #[test]
    fn test_rsds_record_pdb_filename() {
        let data = make_rsds_record("C:\\Symbols\\mylib.pdb");
        let rec = RsdsRecord::parse(&data).unwrap();
        assert_eq!(rec.pdb_filename(), "mylib.pdb");
    }

    #[test]
    fn test_rsds_record_too_short() {
        assert!(RsdsRecord::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_rsds_bad_sig() {
        let mut data = vec![0u8; 30];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(RsdsRecord::parse(&data).is_err());
    }

    #[test]
    fn test_pdb_guid_display() {
        let guid = PdbGuid {
            data1: 0x1234_5678,
            data2: 0x9ABC,
            data3: 0xDEF0,
            data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
        };
        let s = guid.to_string();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert!(s.contains("12345678"));
    }

    #[test]
    fn test_pdb_guid_symbol_server_key() {
        let guid = PdbGuid {
            data1: 0x1234_5678,
            data2: 0x9ABC,
            data3: 0xDEF0,
            data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
        };
        let key = guid.symbol_server_key(2);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_debug_directory_entry_parse() {
        let mut buf = vec![0u8; 28];
        buf[12..16].copy_from_slice(&IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes());
        buf[16..20].copy_from_slice(&100u32.to_le_bytes()); // size
        buf[24..28].copy_from_slice(&0x400u32.to_le_bytes()); // file offset
        let entry = DebugDirectoryEntry::parse(&buf, 0).unwrap();
        assert!(entry.is_codeview());
        assert_eq!(entry.type_name(), "CODEVIEW");
        assert_eq!(entry.size_of_data, 100);
    }

    #[test]
    fn test_debug_directory_entry_too_short() {
        assert!(DebugDirectoryEntry::parse(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn test_debug_type_name() {
        assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_CODEVIEW), "CODEVIEW");
        assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_FPO), "FPO");
        assert_eq!(debug_type_name(999), "UNKNOWN_TYPE");
    }

    #[test]
    fn test_vc_feature_parse() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&10u32.to_le_bytes());
        buf[4..8].copy_from_slice(&20u32.to_le_bytes());
        buf[8..12].copy_from_slice(&30u32.to_le_bytes());
        let vc = VcFeatureRecord::parse(&buf).unwrap();
        assert_eq!(vc.pre_vc_plus_plus_count, 10);
        assert_eq!(vc.c_plus_plus_count, 20);
        assert_eq!(vc.gs_count, 30);
    }

    #[test]
    fn test_detect_dotnet_false() {
        assert!(!detect_dotnet(0));
    }

    #[test]
    fn test_detect_dotnet_true() {
        assert!(detect_dotnet(0x1000));
    }

    #[test]
    fn test_nb10_record_too_short() {
        assert!(Nb10Record::parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_nb10_bad_sig() {
        let data = vec![0u8; 20];
        assert!(Nb10Record::parse(&data).is_err());
    }

    #[test]
    fn test_codeview_info_rsds() {
        let data = make_rsds_record("test.pdb");
        let rec = RsdsRecord::parse(&data).unwrap();
        let cv = CodeViewInfo::Rsds(rec);
        assert_eq!(cv.pdb_path(), "test.pdb");
        assert!(cv.guid().is_some());
        assert_eq!(cv.age(), 1);
    }

    #[test]
    fn test_extract_codeview_info_empty() {
        let result = extract_codeview_info(&[], &[]);
        assert!(result.is_none());
    }
}
