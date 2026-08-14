//! Full DEX file parser — strings, types, protos, fields, methods, class defs.

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by the DEX parser.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DexError {
    #[error("invalid DEX magic")]
    InvalidMagic,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("truncated DEX file")]
    Truncated,
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("invalid index {0}")]
    InvalidIndex(u32),
}

// ── Magic constants ───────────────────────────────────────────────────────────

pub const DEX_MAGIC_035: &[u8] = b"dex\n035\0";
pub const DEX_MAGIC_036: &[u8] = b"dex\n036\0";
pub const DEX_MAGIC_037: &[u8] = b"dex\n037\0";
pub const DEX_MAGIC_038: &[u8] = b"dex\n038\0";
pub const DEX_MAGIC_039: &[u8] = b"dex\n039\0";

// ── Header ────────────────────────────────────────────────────────────────────

/// Parsed DEX file header (all 23 fields from the DEX spec).
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub sha1: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    fn parse(data: &[u8]) -> Result<Self, DexError> {
        if data.len() < 112 {
            return Err(DexError::Truncated);
        }
        let magic: [u8; 8] = data[0..8].try_into().map_err(|_| DexError::Truncated)?;
        if !matches!(
            &magic,
            m if m == DEX_MAGIC_035 || m == DEX_MAGIC_036 || m == DEX_MAGIC_037
              || m == DEX_MAGIC_038 || m == DEX_MAGIC_039
        ) {
            return Err(DexError::InvalidMagic);
        }
        let sha1: [u8; 20] = data[12..32].try_into().map_err(|_| DexError::Truncated)?;
        Ok(Self {
            magic,
            checksum: le_u32(data, 8),
            sha1,
            file_size: le_u32(data, 32),
            header_size: le_u32(data, 36),
            endian_tag: le_u32(data, 40),
            link_size: le_u32(data, 44),
            link_off: le_u32(data, 48),
            map_off: le_u32(data, 52),
            string_ids_size: le_u32(data, 56),
            string_ids_off: le_u32(data, 60),
            type_ids_size: le_u32(data, 64),
            type_ids_off: le_u32(data, 68),
            proto_ids_size: le_u32(data, 72),
            proto_ids_off: le_u32(data, 76),
            field_ids_size: le_u32(data, 80),
            field_ids_off: le_u32(data, 84),
            method_ids_size: le_u32(data, 88),
            method_ids_off: le_u32(data, 92),
            class_defs_size: le_u32(data, 96),
            class_defs_off: le_u32(data, 100),
            data_size: le_u32(data, 104),
            data_off: le_u32(data, 108),
        })
    }
}

// ── ID structures ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DexProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[derive(Debug, Clone)]
pub struct DexFieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexMethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

// ── ULEB128 ───────────────────────────────────────────────────────────────────

/// Decode an unsigned LEB128 value, advancing `pos`.
pub fn read_uleb128(data: &[u8], pos: &mut usize) -> u32 {
    let mut result = 0u32;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return result;
        }
        let byte = data[*pos];
        *pos += 1;
        result |= u32::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    result
}

// ── String reading ────────────────────────────────────────────────────────────

/// Read a DEX string from the string data section given a `string_ids` offset table.
#[must_use] 
pub fn read_string(data: &[u8], string_ids: &[u32], idx: u32) -> String {
    let idx = idx as usize;
    if idx >= string_ids.len() {
        return String::new();
    }
    let off = string_ids[idx] as usize;
    if off >= data.len() {
        return String::new();
    }
    let mut pos = off;
    let _utf16_len = read_uleb128(data, &mut pos);
    // Read MUTF-8 until NUL
    let start = pos;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    // Basic lossy conversion from MUTF-8 (mostly identical to UTF-8 for ASCII)
    String::from_utf8_lossy(&data[start..pos]).into_owned()
}

// ── DEX file ──────────────────────────────────────────────────────────────────

/// A fully parsed DEX file.
#[derive(Debug, Clone)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_descs: Vec<String>,
    pub protos: Vec<DexProtoId>,
    pub fields: Vec<DexFieldId>,
    pub methods: Vec<DexMethodId>,
    pub class_defs: Vec<DexClassDef>,
    pub raw: Vec<u8>,
}

impl DexFile {
    /// Parse a DEX file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, DexError> {
        let header = DexHeader::parse(data)?;

        if header.endian_tag != 0x1234_5678 {
            return Err(DexError::ParseError("big-endian DEX not supported".into()));
        }

        // Read string ID list (array of u32 offsets).
        let string_ids = read_u32_array(
            data,
            header.string_ids_off as usize,
            header.string_ids_size as usize,
        )?;

        // Decode each string.
        let strings: Vec<String> = (0..header.string_ids_size)
            .map(|i| read_string(data, &string_ids, i))
            .collect();

        // Read type IDs (array of u32 string indices).
        let type_id_indices = read_u32_array(
            data,
            header.type_ids_off as usize,
            header.type_ids_size as usize,
        )?;
        let type_descs: Vec<String> = type_id_indices
            .iter()
            .map(|&idx| strings.get(idx as usize).cloned().unwrap_or_default())
            .collect();

        // Read proto IDs (12 bytes each).
        let protos = read_proto_ids(data, header.proto_ids_off, header.proto_ids_size)?;

        // Read field IDs (8 bytes each).
        let fields = read_field_ids(data, header.field_ids_off, header.field_ids_size)?;

        // Read method IDs (8 bytes each).
        let methods = read_method_ids(data, header.method_ids_off, header.method_ids_size)?;

        // Read class defs (32 bytes each).
        let class_defs = read_class_defs(data, header.class_defs_off, header.class_defs_size)?;

        Ok(Self {
            header,
            strings,
            type_descs,
            protos,
            fields,
            methods,
            class_defs,
            raw: data.to_vec(),
        })
    }

    /// Return the descriptor string for a class definition.
    pub fn class_name<'a>(&'a self, def: &DexClassDef) -> &'a str {
        self.type_descs
            .get(def.class_idx as usize)
            .map_or("", String::as_str)
    }

    /// Return the descriptor string for a superclass (None if java.lang.Object).
    pub fn superclass_name<'a>(&'a self, def: &DexClassDef) -> Option<&'a str> {
        if def.superclass_idx == 0xFFFF_FFFF {
            return None;
        }
        self.type_descs
            .get(def.superclass_idx as usize)
            .map(String::as_str)
    }

    /// Return the source file name for a class def.
    pub fn source_file<'a>(&'a self, def: &DexClassDef) -> Option<&'a str> {
        if def.source_file_idx == 0xFFFF_FFFF {
            return None;
        }
        self.strings
            .get(def.source_file_idx as usize)
            .map(String::as_str)
    }

    /// Return a method descriptor like `Lcom/example/Foo;->bar(II)V`.
    pub fn method_descriptor(&self, idx: u32) -> String {
        let m = match self.methods.get(idx as usize) {
            Some(m) => m,
            None => return format!("<method#{idx}>"),
        };
        let class_name = self
            .type_descs
            .get(m.class_idx as usize)
            .map_or("?", String::as_str);
        let name = self
            .strings
            .get(m.name_idx as usize)
            .map_or("?", String::as_str);
        let proto = match self.protos.get(m.proto_idx as usize) {
            Some(p) => p,
            None => return format!("{class_name}->{name}(?)"),
        };
        let ret = self
            .type_descs
            .get(proto.return_type_idx as usize)
            .map_or("?", String::as_str);
        let shorty = self
            .strings
            .get(proto.shorty_idx as usize)
            .map_or("", String::as_str);
        format!("{class_name}->{name}({shorty}){ret}")
    }

    /// Return all class descriptor strings.
    #[must_use] 
    pub fn class_names(&self) -> Vec<&str> {
        self.class_defs.iter().map(|d| self.class_name(d)).collect()
    }
}

// ── Access flag helpers ───────────────────────────────────────────────────────

#[must_use] 
pub const fn is_public(flags: u32) -> bool {
    flags & 0x0001 != 0
}
#[must_use] 
pub const fn is_private(flags: u32) -> bool {
    flags & 0x0002 != 0
}
#[must_use] 
pub const fn is_static(flags: u32) -> bool {
    flags & 0x0008 != 0
}
#[must_use] 
pub const fn is_final(flags: u32) -> bool {
    flags & 0x0010 != 0
}
#[must_use] 
pub const fn is_interface(flags: u32) -> bool {
    flags & 0x0200 != 0
}
#[must_use] 
pub const fn is_abstract(flags: u32) -> bool {
    flags & 0x0400 != 0
}
#[must_use] 
pub const fn is_annotation(flags: u32) -> bool {
    flags & 0x2000 != 0
}
#[must_use] 
pub const fn is_enum(flags: u32) -> bool {
    flags & 0x4000 != 0
}

/// Build a human-readable access flags string.
#[must_use] 
pub fn access_flags_string(flags: u32) -> String {
    let mut parts = Vec::new();
    if is_public(flags) {
        parts.push("public");
    }
    if is_private(flags) {
        parts.push("private");
    }
    if is_static(flags) {
        parts.push("static");
    }
    if is_final(flags) {
        parts.push("final");
    }
    if is_interface(flags) {
        parts.push("interface");
    }
    if is_abstract(flags) {
        parts.push("abstract");
    }
    if is_annotation(flags) {
        parts.push("annotation");
    }
    if is_enum(flags) {
        parts.push("enum");
    }
    parts.join(" ")
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32_array(data: &[u8], off: usize, count: usize) -> Result<Vec<u32>, DexError> {
    let end = off.checked_add(count.checked_mul(4).ok_or(DexError::Truncated)?).ok_or(DexError::Truncated)?;
    if end > data.len() {
        return Err(DexError::Truncated);
    }
    Ok((0..count).map(|i| le_u32(data, off + i * 4)).collect())
}

fn read_proto_ids(data: &[u8], off: u32, count: u32) -> Result<Vec<DexProtoId>, DexError> {
    let off = off as usize;
    let count = count as usize;
    let end = off.checked_add(count.checked_mul(12).ok_or(DexError::Truncated)?).ok_or(DexError::Truncated)?;
    if end > data.len() {
        return Err(DexError::Truncated);
    }
    Ok((0..count)
        .map(|i| DexProtoId {
            shorty_idx: le_u32(data, off + i * 12),
            return_type_idx: le_u32(data, off + i * 12 + 4),
            parameters_off: le_u32(data, off + i * 12 + 8),
        })
        .collect())
}

fn read_field_ids(data: &[u8], off: u32, count: u32) -> Result<Vec<DexFieldId>, DexError> {
    let off = off as usize;
    let count = count as usize;
    let end = off.checked_add(count.checked_mul(8).ok_or(DexError::Truncated)?).ok_or(DexError::Truncated)?;
    if end > data.len() {
        return Err(DexError::Truncated);
    }
    Ok((0..count)
        .map(|i| DexFieldId {
            class_idx: le_u16(data, off + i * 8),
            type_idx: le_u16(data, off + i * 8 + 2),
            name_idx: le_u32(data, off + i * 8 + 4),
        })
        .collect())
}

fn read_method_ids(data: &[u8], off: u32, count: u32) -> Result<Vec<DexMethodId>, DexError> {
    let off = off as usize;
    let count = count as usize;
    let end = off.checked_add(count.checked_mul(8).ok_or(DexError::Truncated)?).ok_or(DexError::Truncated)?;
    if end > data.len() {
        return Err(DexError::Truncated);
    }
    Ok((0..count)
        .map(|i| DexMethodId {
            class_idx: le_u16(data, off + i * 8),
            proto_idx: le_u16(data, off + i * 8 + 2),
            name_idx: le_u32(data, off + i * 8 + 4),
        })
        .collect())
}

fn read_class_defs(data: &[u8], off: u32, count: u32) -> Result<Vec<DexClassDef>, DexError> {
    let off = off as usize;
    let count = count as usize;
    let end = off.checked_add(count.checked_mul(32).ok_or(DexError::Truncated)?).ok_or(DexError::Truncated)?;
    if end > data.len() {
        return Err(DexError::Truncated);
    }
    Ok((0..count)
        .map(|i| DexClassDef {
            class_idx: le_u32(data, off + i * 32),
            access_flags: le_u32(data, off + i * 32 + 4),
            superclass_idx: le_u32(data, off + i * 32 + 8),
            interfaces_off: le_u32(data, off + i * 32 + 12),
            source_file_idx: le_u32(data, off + i * 32 + 16),
            annotations_off: le_u32(data, off + i * 32 + 20),
            class_data_off: le_u32(data, off + i * 32 + 24),
            static_values_off: le_u32(data, off + i * 32 + 28),
        })
        .collect())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_dex() -> Vec<u8> {
        let mut v = vec![0u8; 112];
        v[0..8].copy_from_slice(DEX_MAGIC_035);
        v[32..36].copy_from_slice(&112_u32.to_le_bytes()); // file_size
        v[36..40].copy_from_slice(&112_u32.to_le_bytes()); // header_size
        v[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes()); // endian_tag
        v
    }

    // ── DEX magic constants ───────────────────────────────────────────────────

    #[test]
    fn test_magic_constants_len() {
        assert_eq!(DEX_MAGIC_035.len(), 8);
        assert_eq!(DEX_MAGIC_039.len(), 8);
    }

    #[test]
    fn test_magic_035_starts_with_dex() {
        assert!(DEX_MAGIC_035.starts_with(b"dex\n"));
    }

    // ── read_uleb128 ──────────────────────────────────────────────────────────

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 5);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_uleb128_two_bytes() {
        // 300 = 0x12C → bytes: 0xAC 0x02
        let data = [0xACu8, 0x02];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 300);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_uleb128_zero() {
        let data = [0x00u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 0);
    }

    #[test]
    fn test_uleb128_empty_returns_zero() {
        let mut pos = 0;
        assert_eq!(read_uleb128(&[], &mut pos), 0);
    }

    // ── DexHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_header_parse_ok() {
        let data = make_minimal_dex();
        let hdr = DexHeader::parse(&data).unwrap();
        assert_eq!(&hdr.magic, DEX_MAGIC_035);
        assert_eq!(hdr.endian_tag, 0x1234_5678);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut data = make_minimal_dex();
        data[0..4].copy_from_slice(b"ELF\x7f");
        assert!(matches!(
            DexHeader::parse(&data),
            Err(DexError::InvalidMagic)
        ));
    }

    #[test]
    fn test_header_truncated() {
        assert!(matches!(
            DexHeader::parse(&[0u8; 10]),
            Err(DexError::Truncated)
        ));
    }

    #[test]
    fn test_header_all_versions() {
        for magic in [
            DEX_MAGIC_035,
            DEX_MAGIC_036,
            DEX_MAGIC_037,
            DEX_MAGIC_038,
            DEX_MAGIC_039,
        ] {
            let mut data = make_minimal_dex();
            data[0..8].copy_from_slice(magic);
            assert!(DexHeader::parse(&data).is_ok());
        }
    }

    // ── Access flags ──────────────────────────────────────────────────────────

    #[test]
    fn test_access_flags_public() {
        assert!(is_public(0x0001));
        assert!(!is_public(0x0000));
    }

    #[test]
    fn test_access_flags_static_final() {
        let flags = 0x0001 | 0x0008 | 0x0010;
        assert!(is_public(flags));
        assert!(is_static(flags));
        assert!(is_final(flags));
        assert!(!is_abstract(flags));
    }

    #[test]
    fn test_access_flags_string() {
        let s = access_flags_string(0x0001 | 0x0008);
        assert!(s.contains("public"));
        assert!(s.contains("static"));
    }

    #[test]
    fn test_access_flags_interface() {
        assert!(is_interface(0x0200));
    }

    #[test]
    fn test_access_flags_enum() {
        assert!(is_enum(0x4000));
    }

    // ── DexFile::parse ────────────────────────────────────────────────────────

    #[test]
    fn test_dex_file_parse_minimal() {
        let data = make_minimal_dex();
        let dex = DexFile::parse(&data).unwrap();
        assert_eq!(dex.strings.len(), 0);
        assert_eq!(dex.class_defs.len(), 0);
    }

    #[test]
    fn test_dex_file_wrong_endian() {
        let mut data = make_minimal_dex();
        data[40..44].copy_from_slice(&0x7856_3412_u32.to_le_bytes()); // reversed
        assert!(matches!(
            DexFile::parse(&data),
            Err(DexError::ParseError(_))
        ));
    }

    // ── DexFile with strings ──────────────────────────────────────────────────

    fn make_dex_with_one_string(s: &[u8]) -> Vec<u8> {
        // Layout: [header=112] [string_id_off pointing at 116] [len_uleb128 + s + NUL]
        let string_data_off: u32 = 116; // right after header
        let mut data = make_minimal_dex();
        data[56..60].copy_from_slice(&1_u32.to_le_bytes()); // string_ids_size = 1
        data[60..64].copy_from_slice(&112_u32.to_le_bytes()); // string_ids_off = 112
        // String ID array: offset = string_data_off
        data.extend_from_slice(&string_data_off.to_le_bytes());
        // String data: uleb128(len) + bytes + NUL
        let slen = s.len() as u8;
        data.push(slen); // uleb128 length (single byte ok for small strings)
        data.extend_from_slice(s);
        data.push(0x00); // NUL terminator
        // Fix file_size
        let fsz = data.len() as u32;
        data[32..36].copy_from_slice(&fsz.to_le_bytes());
        data
    }

    #[test]
    fn test_dex_file_reads_string() {
        let data = make_dex_with_one_string(b"Hello");
        let dex = DexFile::parse(&data).unwrap();
        assert_eq!(dex.strings.len(), 1);
        assert_eq!(dex.strings[0], "Hello");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn test_class_names_empty() {
        let data = make_minimal_dex();
        let dex = DexFile::parse(&data).unwrap();
        assert!(dex.class_names().is_empty());
    }

    #[test]
    fn test_method_descriptor_out_of_bounds() {
        let data = make_minimal_dex();
        let dex = DexFile::parse(&data).unwrap();
        let desc = dex.method_descriptor(999);
        assert!(desc.contains("method#999"));
    }

    #[test]
    fn test_access_flags_annotation() {
        assert!(is_annotation(0x2000));
    }

    #[test]
    fn test_access_flags_private() {
        assert!(is_private(0x0002));
    }

    #[test]
    fn test_access_flags_string_empty() {
        assert_eq!(access_flags_string(0), "");
    }
}
