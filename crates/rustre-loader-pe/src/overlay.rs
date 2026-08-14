//! PE overlay detection: data appended after the last section.
//!
//! Common uses for overlays:
//! - Authenticode signatures (`WIN_CERTIFICATE` in Security data directory)
//! - Self-extracting archives (`NSIS`, `WinRAR`, 7-Zip, `Inno Setup`, etc.)
//! - Packed/protected executable payload
//! - Installer resource blobs

use crate::imports::RvaSection;

// ---------------------------------------------------------------------------
// WIN_CERTIFICATE revision and type constants
// ---------------------------------------------------------------------------

pub const WIN_CERT_REVISION_1_0: u16 = 0x0100;
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;

pub const WIN_CERT_TYPE_X509: u16 = 0x0001;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_RESERVED_1: u16 = 0x0003;
pub const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 0x0004;

/// Human-readable name for a `WIN_CERTIFICATE` type.
#[must_use]
pub const fn cert_type_name(t: u16) -> &'static str {
    match t {
        WIN_CERT_TYPE_X509 => "X.509",
        WIN_CERT_TYPE_PKCS_SIGNED_DATA => "PKCS#7 SignedData (Authenticode)",
        WIN_CERT_TYPE_RESERVED_1 => "Reserved",
        WIN_CERT_TYPE_TS_STACK_SIGNED => "Terminal Server Stack Signed",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// SFX archive magic signatures (first bytes of the overlay payload)
// ---------------------------------------------------------------------------

/// Known self-extracting archive formats detected by overlay magic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfxKind {
    /// NSIS (Nullsoft Installer): `NullsoftInst` header or common magic.
    Nsis,
    /// `WinRAR` self-extracting archive (`Rar!` magic = `0x52 0x61 0x72 0x21 0x1A 0x07`).
    WinRar,
    /// 7-Zip self-extracting archive (`7z\xBC\xAF\x27\x1C`).
    SevenZip,
    /// Zip archive (`PK\x03\x04`).
    Zip,
    /// `Inno Setup` installer — `ISRS`/`ISCC` marker.
    InnoSetup,
    /// `InstallShield` cabinet (`MSCF` or `ISc`).
    InstallShield,
    /// `WiX` / MSI cabinet stream (`MSCF`).
    Cabinet,
    /// `AutoIt` compiled script (`AU3!EA06` marker).
    AutoIt,
    /// Unknown / generic overlay data.
    Unknown,
}

impl SfxKind {
    /// Return a human-readable label for display.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Nsis => "NSIS Installer",
            Self::WinRar => "WinRAR SFX",
            Self::SevenZip => "7-Zip SFX",
            Self::Zip => "ZIP Archive",
            Self::InnoSetup => "Inno Setup Installer",
            Self::InstallShield => "InstallShield",
            Self::Cabinet => "Microsoft Cabinet (CAB)",
            Self::AutoIt => "AutoIt Compiled Script",
            Self::Unknown => "Unknown Overlay",
        }
    }
}

/// Detect archive type from up to the first 16 bytes of a buffer.
#[must_use]
pub fn detect_sfx_kind(bytes: &[u8]) -> SfxKind {
    if bytes.len() >= 7 && &bytes[0..7] == b"Rar!\x1A\x07\x00"
        || bytes.len() >= 8 && &bytes[0..8] == b"Rar!\x1A\x07\x01\x00"
    {
        return SfxKind::WinRar;
    }
    if bytes.len() >= 6 && &bytes[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return SfxKind::SevenZip;
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
        return SfxKind::Zip;
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"MSCF" {
        return SfxKind::Cabinet;
    }
    // Inno Setup: payload starts with Inno Setup setup data marker
    if bytes.len() >= 12 && bytes[0..12].windows(6).any(|w| w == b"Inno S") {
        return SfxKind::InnoSetup;
    }
    // AutoIt: AU3! or AU3!EA06
    if bytes.len() >= 4 && &bytes[0..4] == b"AU3!" {
        return SfxKind::AutoIt;
    }
    // NSIS: look for common NullsoftInst or nsis.sfx markers
    if bytes.len() >= 4 && &bytes[0..4] == b"\xEF\xBE\xAD\xDE" {
        return SfxKind::Nsis;
    }
    SfxKind::Unknown
}

// ---------------------------------------------------------------------------
// WIN_CERTIFICATE structure
// ---------------------------------------------------------------------------

/// Parsed `WIN_CERTIFICATE` header (variable-length structure).
#[derive(Debug, Clone)]
pub struct WinCertificate {
    /// Total size in bytes including the header and certificate data.
    pub length: u32,
    /// Certificate revision (1.0 or 2.0).
    pub revision: u16,
    /// Certificate type (see `WIN_CERT_TYPE_*`).
    pub certificate_type: u16,
    /// Certificate data (DER-encoded for X.509, `PKCS#7` blob for Authenticode).
    pub data: Vec<u8>,
}

impl WinCertificate {
    /// Parse one `WIN_CERTIFICATE` from `data` starting at `offset`.
    ///
    /// `WIN_CERTIFICATE` layout:
    /// - `DWORD`  `dwLength`         (4)
    /// - `WORD`   `wRevision`        (2)
    /// - `WORD`   `wCertificateType` (2)
    /// - `BYTE[]` `bCertificate`     (`dwLength - 8`)
    ///
    /// # Errors
    ///
    /// Returns `Err` if `data` is truncated or the length field is inconsistent.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 8 > data.len() {
            return Err(format!(
                "WIN_CERTIFICATE header truncated at offset {offset:#x}"
            ));
        }
        let length = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let revision =
            u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
        let certificate_type =
            u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap_or([0; 2]));

        if (length as usize) < 8 {
            return Err(format!(
                "WIN_CERTIFICATE length {length} too small at offset {offset:#x}"
            ));
        }
        let data_len = (length as usize) - 8;
        let data_end = offset + 8 + data_len;
        if data_end > data.len() {
            return Err(format!(
                "WIN_CERTIFICATE data truncated: need {data_end} bytes, have {}",
                data.len()
            ));
        }

        Ok(Self {
            length,
            revision,
            certificate_type,
            data: data[offset + 8..data_end].to_vec(),
        })
    }

    /// Returns a human-readable type description.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        cert_type_name(self.certificate_type)
    }

    /// Returns `true` for Authenticode `PKCS#7` signatures.
    #[must_use]
    pub const fn is_authenticode(&self) -> bool {
        self.certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA
    }

    /// Round `length` up to an 8-byte boundary (as the PE spec requires).
    #[must_use]
    pub const fn padded_length(&self) -> usize {
        ((self.length as usize) + 7) & !7
    }
}

/// Parse all `WIN_CERTIFICATE` entries from the Security data directory.
///
/// `cert_dir_offset` is the **file offset** (not RVA) of the Security
/// data directory (`DataDirectory[4]`); `cert_dir_size` is its size.
#[must_use]
pub fn parse_security_directory(
    data: &[u8],
    cert_dir_offset: u32,
    cert_dir_size: u32,
) -> Vec<WinCertificate> {
    let mut certs = Vec::new();
    let start = cert_dir_offset as usize;
    let Some(end) = start.checked_add(cert_dir_size as usize) else {
        return certs;
    };

    if start >= data.len() || end > data.len() {
        return certs;
    }

    let mut off = start;
    while off + 8 <= end && off + 8 <= data.len() {
        match WinCertificate::parse(data, off) {
            Ok(cert) => {
                let step = cert.padded_length().max(8);
                certs.push(cert);
                off += step;
            }
            Err(_) => break,
        }
    }
    certs
}

// ---------------------------------------------------------------------------
// Overlay calculation
// ---------------------------------------------------------------------------

/// Find the file offset at which the PE overlay begins (i.e., after all
/// sections and the optional security certificate table).
///
/// Returns `None` if there is no overlay.
#[must_use]
pub fn find_overlay_offset(
    data: &[u8],
    sections: &[RvaSection],
    cert_dir_file_offset: u32,
    cert_dir_size: u32,
) -> Option<usize> {
    // The overlay starts after the last byte occupied by any section or the
    // security directory (whichever is furthest into the file).
    let mut last = 0usize;

    for sec in sections {
        if let Some(end) = (sec.raw_offset as usize).checked_add(sec.raw_size as usize) && end > last {
            last = end;
        }
    }

    // Security directory (file offset-based, not RVA) may extend beyond sections.
    if cert_dir_file_offset != 0 && cert_dir_size != 0 && let Some(cert_end) = (cert_dir_file_offset as usize).checked_add(cert_dir_size as usize) && cert_end > last {
        last = cert_end;
    }

    if last > 0 && last < data.len() {
        Some(last)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Overlay information
// ---------------------------------------------------------------------------

/// Information about the overlay region of a PE file.
#[derive(Debug, Clone)]
pub struct OverlayInfo {
    /// File offset where the overlay begins.
    pub offset: usize,
    /// Size of the overlay in bytes.
    pub size: usize,
    /// Detected `SFX`/archive format, if any.
    pub sfx_kind: SfxKind,
    /// `WIN_CERTIFICATE` entries found in the Security data directory.
    pub certificates: Vec<WinCertificate>,
    /// `true` if the overlay contains certificate data (Authenticode).
    pub is_signed: bool,
}

impl OverlayInfo {
    /// Analyse the overlay region of a PE file.
    ///
    /// * `data` — raw PE file bytes
    /// * `sections` — section table (`raw_offset` + `raw_size` needed)
    /// * `cert_dir_file_offset` — Security data directory file offset
    ///   (0 if absent); **not** an RVA — PE spec says Security dir uses
    ///   file offsets.
    /// * `cert_dir_size` — size of the Security data directory
    pub fn analyze(
        data: &[u8],
        sections: &[RvaSection],
        cert_dir_file_offset: u32,
        cert_dir_size: u32,
    ) -> Option<Self> {
        let offset = find_overlay_offset(data, sections, cert_dir_file_offset, cert_dir_size)?;
        let size = data.len() - offset;
        if size == 0 {
            return None;
        }
        let overlay_bytes = &data[offset..];
        let sfx_kind = detect_sfx_kind(overlay_bytes);

        let certificates = if cert_dir_file_offset != 0 && cert_dir_size != 0 {
            parse_security_directory(data, cert_dir_file_offset, cert_dir_size)
        } else {
            Vec::new()
        };

        let is_signed = certificates.iter().any(WinCertificate::is_authenticode);

        Some(Self {
            offset,
            size,
            sfx_kind,
            certificates,
            is_signed,
        })
    }

    /// Returns `true` if the overlay data does NOT look like certificate data only.
    #[must_use]
    pub fn has_extra_data(&self) -> bool {
        // Overlay larger than covered by all certificates
        let cert_bytes: usize = self.certificates.iter().map(WinCertificate::padded_length).sum();
        self.size > cert_bytes
    }

    /// Returns `true` if any known SFX signature was found.
    #[must_use]
    pub fn is_sfx(&self) -> bool {
        self.sfx_kind != SfxKind::Unknown
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert_entry(cert_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(8 + payload.len()).unwrap_or(u32::MAX);
        let mut buf = Vec::new();
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
        buf.extend_from_slice(&cert_type.to_le_bytes());
        buf.extend_from_slice(payload);
        // Pad to 8-byte boundary
        let pad = (8 - (buf.len() % 8)) % 8;
        buf.extend(std::iter::repeat_n(0u8, pad));
        buf
    }

    #[test]
    fn test_cert_type_name() {
        assert_eq!(
            cert_type_name(WIN_CERT_TYPE_PKCS_SIGNED_DATA),
            "PKCS#7 SignedData (Authenticode)"
        );
        assert_eq!(cert_type_name(WIN_CERT_TYPE_X509), "X.509");
        assert_eq!(cert_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_win_certificate_parse_basic() {
        let payload = b"fakesig";
        let buf = make_cert_entry(WIN_CERT_TYPE_PKCS_SIGNED_DATA, payload);
        let cert = WinCertificate::parse(&buf, 0).unwrap();
        assert_eq!(cert.certificate_type, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
        assert_eq!(cert.revision, WIN_CERT_REVISION_2_0);
        assert_eq!(&cert.data, payload);
        assert!(cert.is_authenticode());
    }

    #[test]
    fn test_win_certificate_parse_truncated() {
        assert!(WinCertificate::parse(&[0u8; 4], 0).is_err());
    }

    #[test]
    fn test_parse_security_directory_two_entries() {
        let mut buf = make_cert_entry(WIN_CERT_TYPE_PKCS_SIGNED_DATA, b"aaa");
        buf.extend_from_slice(&make_cert_entry(WIN_CERT_TYPE_X509, b"bbb"));
        let certs = parse_security_directory(&buf, 0, u32::try_from(buf.len()).unwrap_or(u32::MAX));
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].certificate_type, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
        assert_eq!(certs[1].certificate_type, WIN_CERT_TYPE_X509);
    }

    #[test]
    fn test_detect_sfx_zip() {
        let bytes = b"PK\x03\x04extradata";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::Zip);
    }

    #[test]
    fn test_detect_sfx_7zip() {
        let bytes = b"7z\xBC\xAF\x27\x1C\x00\x04";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::SevenZip);
    }

    #[test]
    fn test_detect_sfx_winrar() {
        let bytes = b"Rar!\x1A\x07\x00trailing";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::WinRar);
    }

    #[test]
    fn test_detect_sfx_cabinet() {
        let bytes = b"MSCFextradata00";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::Cabinet);
    }

    #[test]
    fn test_detect_sfx_autoit() {
        let bytes = b"AU3!EA06somedata";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::AutoIt);
    }

    #[test]
    fn test_detect_sfx_unknown() {
        let bytes = b"\x00\x00\x00\x00garbage";
        assert_eq!(detect_sfx_kind(bytes), SfxKind::Unknown);
    }

    #[test]
    fn test_find_overlay_offset_no_sections() {
        let data = vec![0u8; 0x200];
        // No sections, no cert dir → no overlay
        let result = find_overlay_offset(&data, &[], 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_overlay_offset_with_section_and_overlay() {
        use crate::imports::RvaSection;
        // Section occupies raw bytes 0..0x100 in a 0x180-byte file → 0x80-byte overlay
        let sections = vec![RvaSection {
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x100,
            raw_offset: 0,
        }];
        let data = vec![0u8; 0x180];
        let off = find_overlay_offset(&data, &sections, 0, 0);
        assert_eq!(off, Some(0x100));
    }

    #[test]
    fn test_overlay_info_sfx_detection() {
        use crate::imports::RvaSection;
        // Build a fake PE-like buffer: 0x100 bytes "sections" + ZIP magic overlay
        let mut data = vec![0u8; 0x100];
        data.extend_from_slice(b"PK\x03\x04");
        data.extend(std::iter::repeat_n(0u8, 0x20));

        let sections = vec![RvaSection {
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x100,
            raw_offset: 0,
        }];

        let info = OverlayInfo::analyze(&data, &sections, 0, 0).unwrap();
        assert_eq!(info.offset, 0x100);
        assert_eq!(info.sfx_kind, SfxKind::Zip);
        assert!(info.is_sfx());
        assert!(!info.is_signed);
        assert!(info.has_extra_data());
    }

    #[test]
    fn test_overlay_info_no_overlay() {
        use crate::imports::RvaSection;
        let data = vec![0u8; 0x100];
        let sections = vec![RvaSection {
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x100,
            raw_offset: 0,
        }];
        let info = OverlayInfo::analyze(&data, &sections, 0, 0);
        assert!(info.is_none());
    }
}
