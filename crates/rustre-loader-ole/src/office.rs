//! Microsoft Office format detection and metadata extraction from OLE2 files.

use super::OleFile;

// ── OfficeFormat ──────────────────────────────────────────────────────────────

/// Identified Office application format stored in the OLE container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfficeFormat {
    /// Microsoft Word 97-2003 (.doc).
    Word97,
    /// Microsoft Excel 97-2003 (.xls).
    Excel97,
    /// Microsoft `PowerPoint` 97-2003 (.ppt).
    PowerPoint97,
    /// Microsoft Visio (.vsd).
    Visio,
    /// Microsoft Project (.mpp).
    Project,
    /// Microsoft Publisher (.pub).
    Publisher,
    /// Microsoft Access (.mdb).
    Access,
    /// Microsoft Installer (.msi).
    MsiInstaller,
    /// Microsoft `OneNote` (.one).
    OneNote,
    /// Unrecognised format; contains the best available hint string.
    Unknown(String),
}

impl OfficeFormat {
    /// Short human-readable label.
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::Word97 => "Word97",
            Self::Excel97 => "Excel97",
            Self::PowerPoint97 => "PowerPoint97",
            Self::Visio => "Visio",
            Self::Project => "Project",
            Self::Publisher => "Publisher",
            Self::Access => "Access",
            Self::MsiInstaller => "MsiInstaller",
            Self::OneNote => "OneNote",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ── OfficeMeta ────────────────────────────────────────────────────────────────

/// High-level metadata extracted from an Office OLE2 document.
#[derive(Debug, Clone)]
pub struct OfficeMeta {
    /// Detected Office format.
    pub format: OfficeFormat,
    /// Document title from summary information, if present.
    pub title: Option<String>,
    /// Author from summary information, if present.
    pub author: Option<String>,
    /// Whether VBA macros are embedded.
    pub has_macros: bool,
    /// Whether embedded OLE objects are present.
    pub has_embedded_objects: bool,
    /// Names of all streams and storages in the directory.
    pub stream_names: Vec<String>,
}

// ── Detection functions ───────────────────────────────────────────────────────

/// Detect the Office application format by inspecting stream names.
#[must_use]
pub fn detect_office_format(ole: &OleFile) -> OfficeFormat {
    let names: Vec<&str> = ole.directory.iter().map(|e| e.name.as_str()).collect();

    // Primary stream-name heuristics
    if names.contains(&"WordDocument") {
        return OfficeFormat::Word97;
    }
    if names.contains(&"Workbook") || names.contains(&"Book") {
        return OfficeFormat::Excel97;
    }
    if names.contains(&"PowerPoint Document") {
        return OfficeFormat::PowerPoint97;
    }
    if names.contains(&"VisioDocument") || names.iter().any(|n| n.starts_with("Visio")) {
        return OfficeFormat::Visio;
    }
    if names.contains(&"MSProject") || names.contains(&"147") {
        return OfficeFormat::Project;
    }
    if names.contains(&"Quill") || names.iter().any(|n| n.contains("Publisher")) {
        return OfficeFormat::Publisher;
    }
    if names.contains(&"MSysObjects") || names.contains(&"MSysQueries") {
        return OfficeFormat::Access;
    }
    if names.iter().any(|n| n.contains("OneNote")) {
        return OfficeFormat::OneNote;
    }
    // MSI: contains a stream named "\x05SummaryInformation" and "!_Tables"
    if names.contains(&"!_Tables") || names.iter().any(|n| n.contains("_Tables")) {
        return OfficeFormat::MsiInstaller;
    }

    // Fall back to first non-root, non-summary stream name
    let hint = ole
        .directory
        .iter()
        .filter(|e| e.entry_type == 2 || e.entry_type == 1)
        .filter(|e| !e.name.starts_with('\x05'))
        .map(|e| e.name.clone())
        .next()
        .unwrap_or_else(|| "OLE2".to_string());

    OfficeFormat::Unknown(hint)
}

/// Extract office metadata from an OLE2 compound file.
#[must_use]
pub fn extract_office_meta(ole: &OleFile) -> OfficeMeta {
    let format = detect_office_format(ole);
    let has_macros = detect_macros(ole);
    let has_embedded_objects = detect_embedded_objects(ole);
    let stream_names = ole
        .directory
        .iter()
        .map(|e| e.name.clone())
        .filter(|n| !n.is_empty())
        .collect();

    // Title and author would normally come from the SummaryInformation stream.
    // Without parsing the property-set stream we return None for them.
    OfficeMeta {
        format,
        title: None,
        author: None,
        has_macros,
        has_embedded_objects,
        stream_names,
    }
}

/// Returns `true` if the OLE file contains VBA macros.
///
/// Checks for the presence of a `VBA` storage or a `Macros` storage.
#[must_use]
pub fn detect_macros(ole: &OleFile) -> bool {
    ole.directory.iter().any(|e| {
        let name = e.name.as_str();
        (name == "VBA" || name == "Macros" || name == "_VBA_PROJECT_CUR" || name == "VBAProject")
            && (e.is_storage() || e.is_stream())
    })
}

/// Returns `true` if the OLE file contains embedded OLE objects.
///
/// Checks for `ObjectPool` storage or `Ole10Native` stream.
#[must_use]
pub fn detect_embedded_objects(ole: &OleFile) -> bool {
    ole.directory.iter().any(|e| {
        let name = e.name.as_str();
        name == "ObjectPool" || name == "\x01Ole10Native" || name == "Ole10Native"
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OleDirectoryEntry, OleFile, OleHeader};

    const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    fn make_header() -> Vec<u8> {
        let mut d = vec![0u8; 512];
        d[..8].copy_from_slice(&OLE_MAGIC);
        d[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        d[26..28].copy_from_slice(&3u16.to_le_bytes());
        d[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        d[30..32].copy_from_slice(&9u16.to_le_bytes());
        d[32..34].copy_from_slice(&6u16.to_le_bytes());
        d[44..48].copy_from_slice(&2u32.to_le_bytes());
        d[48..52].copy_from_slice(&1u32.to_le_bytes());
        d[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        d[64..68].copy_from_slice(&0u32.to_le_bytes());
        d
    }

    fn dir_entry(name: &str, kind: u8) -> OleDirectoryEntry {
        OleDirectoryEntry {
            name: name.to_string(),
            entry_type: kind,
            color: 1,
            child_sid: 0xFFFF_FFFF,
            left_sid: 0xFFFF_FFFF,
            right_sid: 0xFFFF_FFFF,
            start_sector: 0,
            size: 0,
            created: 0,
            modified: 0,
        }
    }

    fn make_ole(entries: Vec<OleDirectoryEntry>) -> OleFile {
        let header = OleHeader::parse(&make_header()).unwrap();
        OleFile {
            header,
            directory: entries,
        }
    }

    // ── detect_office_format ──────────────────────────────────────────────────

    #[test]
    fn test_detect_word97() {
        let ole = make_ole(vec![dir_entry("WordDocument", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::Word97);
    }

    #[test]
    fn test_detect_excel97() {
        let ole = make_ole(vec![dir_entry("Workbook", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::Excel97);
    }

    #[test]
    fn test_detect_excel97_book() {
        let ole = make_ole(vec![dir_entry("Book", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::Excel97);
    }

    #[test]
    fn test_detect_powerpoint97() {
        let ole = make_ole(vec![dir_entry("PowerPoint Document", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::PowerPoint97);
    }

    #[test]
    fn test_detect_visio() {
        let ole = make_ole(vec![dir_entry("VisioDocument", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::Visio);
    }

    #[test]
    fn test_detect_unknown() {
        let ole = make_ole(vec![dir_entry("CustomStream", 2)]);
        assert!(matches!(
            detect_office_format(&ole),
            OfficeFormat::Unknown(_)
        ));
    }

    #[test]
    fn test_detect_msi() {
        let ole = make_ole(vec![dir_entry("!_Tables", 2)]);
        assert_eq!(detect_office_format(&ole), OfficeFormat::MsiInstaller);
    }

    // ── detect_macros ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_macros_false() {
        let ole = make_ole(vec![dir_entry("WordDocument", 2)]);
        assert!(!detect_macros(&ole));
    }

    #[test]
    fn test_detect_macros_vba_storage() {
        let ole = make_ole(vec![dir_entry("WordDocument", 2), dir_entry("VBA", 1)]);
        assert!(detect_macros(&ole));
    }

    #[test]
    fn test_detect_macros_vbaproject_stream() {
        let ole = make_ole(vec![dir_entry("Workbook", 2), dir_entry("VBAProject", 2)]);
        assert!(detect_macros(&ole));
    }

    #[test]
    fn test_detect_macros_macros_storage() {
        let ole = make_ole(vec![dir_entry("Macros", 1)]);
        assert!(detect_macros(&ole));
    }

    // ── detect_embedded_objects ───────────────────────────────────────────────

    #[test]
    fn test_detect_embedded_objects_false() {
        let ole = make_ole(vec![dir_entry("WordDocument", 2)]);
        assert!(!detect_embedded_objects(&ole));
    }

    #[test]
    fn test_detect_embedded_objects_object_pool() {
        let ole = make_ole(vec![
            dir_entry("WordDocument", 2),
            dir_entry("ObjectPool", 1),
        ]);
        assert!(detect_embedded_objects(&ole));
    }

    #[test]
    fn test_detect_embedded_objects_ole10native() {
        let ole = make_ole(vec![dir_entry("Ole10Native", 2)]);
        assert!(detect_embedded_objects(&ole));
    }

    // ── extract_office_meta ───────────────────────────────────────────────────

    #[test]
    fn test_extract_office_meta_stream_names() {
        let ole = make_ole(vec![dir_entry("WordDocument", 2), dir_entry("VBA", 1)]);
        let meta = extract_office_meta(&ole);
        assert!(meta.stream_names.contains(&"WordDocument".to_string()));
        assert!(meta.has_macros);
        assert!(!meta.has_embedded_objects);
    }

    #[test]
    fn test_extract_office_meta_format_excel() {
        let ole = make_ole(vec![dir_entry("Workbook", 2)]);
        let meta = extract_office_meta(&ole);
        assert_eq!(meta.format, OfficeFormat::Excel97);
    }

    // ── OfficeFormat::label ───────────────────────────────────────────────────

    #[test]
    fn test_office_format_label_word() {
        assert_eq!(OfficeFormat::Word97.label(), "Word97");
    }

    #[test]
    fn test_office_format_label_unknown() {
        let f = OfficeFormat::Unknown("Custom".to_string());
        assert_eq!(f.label(), "Custom");
    }

    #[test]
    fn test_office_format_label_excel() {
        assert_eq!(OfficeFormat::Excel97.label(), "Excel97");
    }

    #[test]
    fn test_office_format_powerpoint_label() {
        assert_eq!(OfficeFormat::PowerPoint97.label(), "PowerPoint97");
    }
}
