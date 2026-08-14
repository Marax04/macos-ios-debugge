//! Android binary loader: detect APK/DEX/OAT/VDEX/ODEX format;
//! extract and load the appropriate component.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ── Format detection constants ────────────────────────────────────────────────

/// Magic bytes: raw DEX file `dex\n0xy\0`
pub const DEX_MAGIC: &[u8; 4] = b"dex\n";
/// Magic bytes: VDEX container
pub const VDEX_MAGIC: &[u8; 4] = b"vdex";
/// Magic bytes: OAT compiled-methods container
pub const OAT_MAGIC: &[u8; 4] = b"oat\n";
/// Magic bytes: ODEX (old pre-ART format) – identical to DEX with odex-extended header
pub const ODEX_MAGIC: &[u8; 4] = b"dey\n";
/// ZIP / APK local file header signature
pub const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
/// ART image file magic
pub const ART_MAGIC: &[u8; 4] = b"art\n";

// ── Android format enum ───────────────────────────────────────────────────────

/// Identified Android binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AndroidFormat {
    /// ZIP-based APK (contains classes*.dex, AndroidManifest.xml, etc.)
    Apk,
    /// Raw Dalvik Executable (versions 035–039)
    Dex,
    /// ODEX (optimised DEX from older ART / Dalvik runtimes)
    Odex,
    /// ART VDEX container (wraps one or more DEX files + quicken info)
    Vdex,
    /// OAT compiled-methods archive
    Oat,
    /// ART boot/app image
    ArtImage,
    /// Unknown / not an Android binary
    Unknown,
}

impl fmt::Display for AndroidFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apk => write!(f, "APK"),
            Self::Dex => write!(f, "DEX"),
            Self::Odex => write!(f, "ODEX"),
            Self::Vdex => write!(f, "VDEX"),
            Self::Oat => write!(f, "OAT"),
            Self::ArtImage => write!(f, "ART"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ── Detect format ─────────────────────────────────────────────────────────────

/// Detect the Android binary format by inspecting magic bytes and file structure.
///
/// The heuristics used:
/// 1. `PK\x03\x04` → check for `classes.dex` inside (APK) or fall through (plain ZIP).
/// 2. `dex\n` → DEX.
/// 3. `dey\n` → ODEX.
/// 4. `vdex` → VDEX.
/// 5. `oat\n` → OAT.
/// 6. `art\n` → ART image.
#[must_use]
pub fn detect_format(data: &[u8]) -> AndroidFormat {
    if data.len() < 4 {
        return AndroidFormat::Unknown;
    }
    // APK / ZIP
    if data.starts_with(b"PK\x03\x04") {
        if data.windows(11).any(|w| w == b"classes.dex") {
            return AndroidFormat::Apk;
        }
        // Could still be a plain ZIP or APK without pre-existing DEX
        return AndroidFormat::Apk;
    }
    // DEX (standard)
    if data.starts_with(DEX_MAGIC) {
        return AndroidFormat::Dex;
    }
    // ODEX (optimised DEX)
    if data.starts_with(ODEX_MAGIC) {
        return AndroidFormat::Odex;
    }
    // VDEX
    if data.starts_with(VDEX_MAGIC) {
        return AndroidFormat::Vdex;
    }
    // OAT (ELF containing oat\n in .rodata; heuristic: look for `oat\n` in first 64 bytes)
    if data.windows(4).take(16).any(|w| w == OAT_MAGIC) {
        return AndroidFormat::Oat;
    }
    // ART image
    if data.starts_with(ART_MAGIC) {
        return AndroidFormat::ArtImage;
    }
    // OAT embedded in ELF: check ELF magic + look for oat in .rodata section header name
    if data.starts_with(b"\x7fELF") {
        // Scan first 8 KiB for OAT magic as an embedded marker
        let scan_end = data.len().min(8192);
        if data[..scan_end].windows(4).any(|w| w == OAT_MAGIC) {
            return AndroidFormat::Oat;
        }
    }
    AndroidFormat::Unknown
}

// ── Loaded component descriptor ───────────────────────────────────────────────

/// High-level descriptor of what was loaded from an Android binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidLoadedComponent {
    /// Source format detected.
    pub format: AndroidFormat,
    /// Logical name (package name for APK, chunk name for DEX, etc.)
    pub name: String,
    /// File offset at which the primary payload starts.
    pub payload_offset: usize,
    /// Byte length of the primary payload.
    pub payload_size: usize,
    /// Version string extracted from the format header.
    pub version: String,
    /// Map from component name to byte range `(offset, size)` within the binary.
    pub components: HashMap<String, (usize, usize)>,
    /// Any warnings or non-fatal issues encountered during loading.
    pub warnings: Vec<String>,
}

impl AndroidLoadedComponent {
    /// Build an empty component for `format`.
    fn new(format: AndroidFormat) -> Self {
        Self {
            format,
            name: String::new(),
            payload_offset: 0,
            payload_size: 0,
            version: String::new(),
            components: HashMap::new(),
            warnings: Vec::new(),
        }
    }
}

impl fmt::Display for AndroidLoadedComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} '{}' v={} payload_off={:#x} payload_size={} components={}",
            self.format,
            self.name,
            self.version,
            self.payload_offset,
            self.payload_size,
            self.components.len(),
        )
    }
}

// ── Main loader entry point ───────────────────────────────────────────────────

/// Load an Android binary and extract the primary component for analysis.
///
/// Returns an [`AndroidLoadedComponent`] describing what was found, along
/// with the raw bytes of the primary payload (e.g. the DEX file inside an APK).
///
/// # Errors
/// Returns an error if the data cannot be parsed or is too short.
pub fn load_android_binary(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    let fmt = detect_format(data);
    match fmt {
        AndroidFormat::Apk => load_apk(data),
        AndroidFormat::Dex => load_dex(data),
        AndroidFormat::Odex => load_odex(data),
        AndroidFormat::Vdex => load_vdex(data),
        AndroidFormat::Oat => load_oat(data),
        AndroidFormat::ArtImage => load_art_image(data),
        AndroidFormat::Unknown => bail!("unrecognised Android binary format"),
    }
}

// ── APK loader ────────────────────────────────────────────────────────────────

fn load_apk(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::Apk);

    // Find the End-of-Central-Directory record.
    let eocd_off = find_eocd(data).context("missing EOCD in APK")?;
    if eocd_off + 22 > data.len() {
        bail!("EOCD truncated");
    }

    let cd_count = u16::from_le_bytes([data[eocd_off + 8], data[eocd_off + 9]]) as usize;
    let cd_off = u32::from_le_bytes(data[eocd_off + 16..eocd_off + 20].try_into()?) as usize;

    // Walk central directory; collect class*.dex entries.
    let mut dex_entries: Vec<(String, usize, usize)> = Vec::new(); // (name, offset, size)
    let mut pos = cd_off;

    for _ in 0..cd_count {
        if pos + 46 > data.len() {
            break;
        }
        if data[pos..pos + 4] != [0x50, 0x4B, 0x01, 0x02] {
            break;
        }
        let method = u16::from_le_bytes([data[pos + 10], data[pos + 11]]);
        let compressed = u32::from_le_bytes(data[pos + 20..pos + 24].try_into()?) as usize;
        let uncompressed = u32::from_le_bytes(data[pos + 24..pos + 28].try_into()?) as usize;
        let fname_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 30], data[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;
        let lhoff = u32::from_le_bytes(data[pos + 42..pos + 46].try_into()?) as usize;

        let name_end = pos + 46 + fname_len;
        if name_end > data.len() {
            break;
        }
        let fname = String::from_utf8_lossy(&data[pos + 46..name_end]).into_owned();

        // Compute the actual data start from the local file header.
        if lhoff + 30 <= data.len() {
            let lfn_len = u16::from_le_bytes([data[lhoff + 26], data[lhoff + 27]]) as usize;
            let lext_len = u16::from_le_bytes([data[lhoff + 28], data[lhoff + 29]]) as usize;
            let data_start = lhoff + 30 + lfn_len + lext_len;
            let data_size = if method == 0 { uncompressed } else { compressed };
            comp.components.insert(fname.clone(), (data_start, data_size));

            // Collect uncompressed DEX files.
            if fname.starts_with("classes") && fname.ends_with(".dex") && method == 0 {
                dex_entries.push((fname, data_start, uncompressed));
            }
        }

        pos = name_end + extra_len + comment_len;
    }

    // Primary payload: first classes.dex
    if dex_entries.is_empty() {
        comp.warnings.push("No uncompressed DEX found in APK".to_string());
        comp.version = "APK".to_string();
        return Ok((comp, Vec::new()));
    }

    dex_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let (primary_name, off, size) = &dex_entries[0];
    let end = (*off + size).min(data.len());
    let dex_bytes = data[*off..end].to_vec();

    // Extract version from DEX header.
    let version = if dex_bytes.len() >= 8 {
        std::str::from_utf8(&dex_bytes[4..7]).unwrap_or("???").to_string()
    } else {
        "???".to_string()
    };

    comp.name = primary_name.clone();
    comp.payload_offset = *off;
    comp.payload_size = *size;
    comp.version = format!("DEX-{version}");

    // Log all DEX files as sub-components.
    for (name, doff, dsz) in &dex_entries[1..] {
        comp.components.insert(name.clone(), (*doff, *dsz));
    }

    Ok((comp, dex_bytes))
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let sig = [0x50, 0x4B, 0x05, 0x06];
    data.windows(4).rposition(|w| w == sig)
}

// ── DEX loader ─────────────────────────────────────────────────────────────────

fn load_dex(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    if data.len() < 112 {
        bail!("DEX file too short");
    }
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::Dex);

    // Parse version from magic.
    let version = std::str::from_utf8(&data[4..7]).unwrap_or("???").to_string();
    let file_size = u32::from_le_bytes(data[32..36].try_into()?) as usize;
    let actual_size = file_size.min(data.len());

    // Extract key table offsets as sub-components.
    let string_ids_size = u32::from_le_bytes(data[56..60].try_into()?) as usize;
    let string_ids_off = u32::from_le_bytes(data[60..64].try_into()?) as usize;
    let type_ids_size = u32::from_le_bytes(data[64..68].try_into()?) as usize;
    let type_ids_off = u32::from_le_bytes(data[68..72].try_into()?) as usize;
    let method_ids_size = u32::from_le_bytes(data[88..92].try_into()?) as usize;
    let method_ids_off = u32::from_le_bytes(data[92..96].try_into()?) as usize;
    let class_defs_size = u32::from_le_bytes(data[96..100].try_into()?) as usize;
    let class_defs_off = u32::from_le_bytes(data[100..104].try_into()?) as usize;

    comp.components.insert("string_ids".to_string(), (string_ids_off, string_ids_size * 4));
    comp.components.insert("type_ids".to_string(), (type_ids_off, type_ids_size * 4));
    comp.components.insert("method_ids".to_string(), (method_ids_off, method_ids_size * 8));
    comp.components.insert("class_defs".to_string(), (class_defs_off, class_defs_size * 32));

    comp.version = format!("DEX-{version}");
    comp.payload_offset = 0;
    comp.payload_size = actual_size;
    comp.name = format!("classes_dex_v{version}");

    Ok((comp, data[..actual_size].to_vec()))
}

// ── ODEX loader ───────────────────────────────────────────────────────────────

fn load_odex(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    // ODEX has an 8-byte magic + version + optional dependency info followed by a DEX.
    if data.len() < 40 {
        bail!("ODEX file too short");
    }
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::Odex);

    let version = std::str::from_utf8(&data[4..7]).unwrap_or("???").to_string();

    // ODEX header (40 bytes):
    // [0..8]   magic + version
    // [8..12]  dex_offset (u32 LE)
    // [12..16] dex_length (u32 LE)
    // [16..20] deps_offset (u32 LE)
    // [20..24] deps_length (u32 LE)
    // [24..28] opt_offset (u32 LE)
    // [28..32] opt_length (u32 LE)
    // [32..36] flags (u32 LE)
    // [36..40] checksum (u32 LE)
    let dex_off = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let dex_len = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    let deps_off = u32::from_le_bytes(data[16..20].try_into()?) as usize;
    let deps_len = u32::from_le_bytes(data[20..24].try_into()?) as usize;
    let opt_off = u32::from_le_bytes(data[24..28].try_into()?) as usize;
    let opt_len = u32::from_le_bytes(data[28..32].try_into()?) as usize;

    comp.components.insert("dex".to_string(), (dex_off, dex_len));
    comp.components.insert("deps".to_string(), (deps_off, deps_len));
    comp.components.insert("opt".to_string(), (opt_off, opt_len));

    let dex_end = (dex_off + dex_len).min(data.len());
    let dex_bytes = if dex_off < dex_end {
        data[dex_off..dex_end].to_vec()
    } else {
        Vec::new()
    };

    comp.version = format!("ODEX-{version}");
    comp.payload_offset = dex_off;
    comp.payload_size = dex_len;
    comp.name = format!("odex_v{version}");

    Ok((comp, dex_bytes))
}

// ── VDEX loader ───────────────────────────────────────────────────────────────

fn load_vdex(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    if data.len() < 28 {
        bail!("VDEX file too short");
    }
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::Vdex);

    let version = std::str::from_utf8(&data[4..7]).unwrap_or("???").to_string();

    // VDEX header (28 bytes minimum):
    // [0..4]   magic ("vdex")
    // [4..8]   version
    // [8..12]  number_of_dex_files (u32 LE)
    // [12..16] dex_section_size (u32 LE)
    // [16..20] dex_shared_data_size (u32 LE)
    // [20..24] verifier_deps_size (u32 LE)
    // [24..28] quicken_info_size (u32 LE)
    let n_dex = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let dex_section_size = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    let verifier_deps_size = u32::from_le_bytes(data[20..24].try_into()?) as usize;
    let quicken_info_size = u32::from_le_bytes(data[24..28].try_into()?) as usize;

    // Checksum array: n_dex * 4 bytes after the header.
    let checksums_off = 28usize;
    let checksums_size = n_dex * 4;
    let dex_data_start = checksums_off + checksums_size;

    comp.components.insert("dex_checksums".to_string(), (checksums_off, checksums_size));
    comp.components.insert("dex_section".to_string(), (dex_data_start, dex_section_size));

    // Locate verifier deps and quicken info after dex section.
    let verifier_off = dex_data_start + dex_section_size;
    let quicken_off = verifier_off + verifier_deps_size;
    comp.components.insert("verifier_deps".to_string(), (verifier_off, verifier_deps_size));
    comp.components.insert("quicken_info".to_string(), (quicken_off, quicken_info_size));

    // Extract first embedded DEX as primary payload.
    let mut dex_offset = dex_data_start;
    let mut dex_bytes = Vec::new();

    for i in 0..n_dex {
        if dex_offset + 4 > data.len() {
            break;
        }
        if !data[dex_offset..].starts_with(b"dex\n") {
            comp.warnings.push(format!("DEX {i} at {dex_offset:#x} has invalid magic"));
            break;
        }
        if dex_offset + 36 > data.len() {
            break;
        }
        let file_size = u32::from_le_bytes(data[dex_offset + 32..dex_offset + 36].try_into()?) as usize;
        let end = (dex_offset + file_size).min(data.len());

        comp.components.insert(
            format!("dex_{i}"),
            (dex_offset, file_size),
        );

        if dex_bytes.is_empty() {
            // Primary payload = first DEX.
            dex_bytes = data[dex_offset..end].to_vec();
            comp.payload_offset = dex_offset;
            comp.payload_size = file_size;
        }
        dex_offset = end;
    }

    comp.version = format!("VDEX-{version}");
    comp.name = format!("vdex_v{version}_{n_dex}dex");

    Ok((comp, dex_bytes))
}

// ── OAT loader ────────────────────────────────────────────────────────────────

fn load_oat(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::Oat);

    // OAT is typically embedded in an ELF .rodata section. Find the oat\n magic.
    let oat_sig_pos = data.windows(4)
        .position(|w| w == OAT_MAGIC)
        .context("OAT magic not found")?;

    if oat_sig_pos + 8 > data.len() {
        bail!("OAT header truncated");
    }

    let version = std::str::from_utf8(&data[oat_sig_pos + 4..oat_sig_pos + 8])
        .unwrap_or("????")
        .trim_end_matches('\0')
        .to_string();

    // OAT header begins at oat_sig_pos. Key fields after the 8-byte magic+version:
    // [+0x08] adler32_checksum (u32)
    // [+0x0C] instruction_set  (u32): 1=Arm, 2=Arm64, 3=Thumb2, 6=X86, 7=X86_64
    // [+0x10] instruction_set_features_bitmap (u32)
    // [+0x14] dex_file_count (u32)
    // [+0x18] oat_dex_files_offset_from_oat_begin (u32)
    // [+0x1C] executable_offset (u32)  — offset to native compiled code
    // [+0x20] interpreter_to_interpreter_bridge_offset (u32)
    // ... many more fields, version-dependent

    let hdr = oat_sig_pos;

    let read_u32 = |off: usize| -> Option<u32> {
        data.get(hdr + off..hdr + off + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };

    let checksum = read_u32(0x08).unwrap_or(0);
    let isa = read_u32(0x0C).unwrap_or(0);
    let dex_file_count = read_u32(0x14).unwrap_or(0);
    let oat_dex_files_off = read_u32(0x18).unwrap_or(0) as usize;
    let executable_off = read_u32(0x1C).unwrap_or(0) as usize;

    comp.components.insert("oat_header".to_string(), (hdr, 0x80));
    comp.components.insert(
        "oat_dex_files".to_string(),
        (hdr + oat_dex_files_off, dex_file_count as usize * 0x40),
    );
    comp.components.insert(
        "executable".to_string(),
        (hdr + executable_off, data.len().saturating_sub(hdr + executable_off)),
    );

    let isa_name = match isa {
        1 => "arm",
        2 => "arm64",
        3 => "thumb2",
        6 => "x86",
        7 => "x86_64",
        _ => "unknown",
    };

    comp.version = format!("OAT-{version}");
    comp.name = format!("oat_{isa_name}_v{version}_{dex_file_count}dex");
    comp.payload_offset = hdr;
    comp.payload_size = data.len().saturating_sub(hdr);

    comp.components.insert("checksum".to_string(), (hdr + 8, 4));
    if checksum == 0 {
        comp.warnings.push("OAT checksum is zero".to_string());
    }

    // Return OAT bytes as primary payload.
    let payload = data[hdr..].to_vec();
    Ok((comp, payload))
}

// ── ART image loader ──────────────────────────────────────────────────────────

fn load_art_image(data: &[u8]) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    if data.len() < 64 {
        bail!("ART image too short");
    }
    let mut comp = AndroidLoadedComponent::new(AndroidFormat::ArtImage);

    let version = std::str::from_utf8(&data[4..8])
        .unwrap_or("????")
        .trim_end_matches('\0')
        .to_string();

    // ART image header (simplified):
    // [0..4]   magic ("art\n")
    // [4..8]   version string
    // [8..12]  image_begin (u32) — load address
    // [12..16] image_size (u32)
    // [16..20] oat_checksum (u32)
    // [20..24] oat_file_begin (u32)
    // [24..28] oat_file_end (u32)
    // [28..32] oat_data_begin (u32)
    // [32..36] oat_data_end (u32)
    // [36..40] patch_delta (u32)
    // [40..44] image_roots (u32)
    // [44..48] pointer_size (u32)
    // [48..52] compile_pic (u32)

    let read_u32 = |off: usize| -> u32 {
        data.get(off..off + 4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };

    let image_begin = read_u32(8);
    let image_size = read_u32(12) as usize;
    let oat_file_begin = read_u32(20);
    let oat_file_end = read_u32(24);
    let oat_data_begin = read_u32(28);
    let oat_data_end = read_u32(32);
    let image_roots = read_u32(40);
    let pointer_size = read_u32(44);

    comp.components.insert("art_header".to_string(), (0, 64));
    comp.components.insert(
        "image_data".to_string(),
        (64, image_size.saturating_sub(64).min(data.len())),
    );

    comp.version = format!("ART-{version}");
    comp.name = format!(
        "art_{version}_img@{image_begin:#010x}_oat@{oat_data_begin:#010x}..{oat_data_end:#010x}"
    );
    comp.payload_offset = 0;
    comp.payload_size = image_size.min(data.len());

    // Emit metadata as warnings (informational).
    comp.warnings.push(format!("image_begin={image_begin:#010x}"));
    comp.warnings.push(format!("oat_file={oat_file_begin:#010x}..{oat_file_end:#010x}"));
    comp.warnings.push(format!("image_roots={image_roots:#010x}"));
    comp.warnings.push(format!("pointer_size={pointer_size}"));

    let payload = data[..comp.payload_size].to_vec();
    Ok((comp, payload))
}

// ── From-file helpers ─────────────────────────────────────────────────────────

/// Load an Android binary from `path`.
///
/// # Errors
/// Returns errors from I/O or parsing.
pub fn load_android_file(path: &Path) -> Result<(AndroidLoadedComponent, Vec<u8>)> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    load_android_binary(&data)
}

/// Return the default output directory name for extracting `comp` to disk.
#[must_use]
pub fn default_output_dir(comp: &AndroidLoadedComponent) -> PathBuf {
    let safe_name: String = comp.name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    PathBuf::from(format!("rustre_android_out_{safe_name}"))
}

// ── Batch extraction ──────────────────────────────────────────────────────────

/// Extraction result for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    /// Component name.
    pub name: String,
    /// Byte offset in the source file.
    pub offset: usize,
    /// Byte count.
    pub size: usize,
    /// Whether extraction succeeded.
    pub ok: bool,
    /// Error message if extraction failed.
    pub error: Option<String>,
}

/// Extract all named sub-components of `comp` into `output_dir`.
///
/// # Errors
/// Returns I/O errors if the directory cannot be created.
pub fn extract_all_components(
    data: &[u8],
    comp: &AndroidLoadedComponent,
    output_dir: &Path,
) -> Result<Vec<ExtractionResult>> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output dir {}", output_dir.display()))?;

    let mut results = Vec::with_capacity(comp.components.len());

    for (name, &(off, size)) in &comp.components {
        let end = (off + size).min(data.len());
        let slice = &data[off..end];
        let out_path = output_dir.join(name);
        let ok = std::fs::write(&out_path, slice).is_ok();
        results.push(ExtractionResult {
            name: name.clone(),
            offset: off,
            size,
            ok,
            error: if ok { None } else { Some(format!("write failed: {}", out_path.display())) },
        });
    }

    Ok(results)
}

// ── Summary report ────────────────────────────────────────────────────────────

/// Human-readable summary report for a loaded Android binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidLoadSummary {
    /// Detected format.
    pub format: String,
    /// Total file size in bytes.
    pub total_size: usize,
    /// Identified version string.
    pub version: String,
    /// Component count.
    pub component_count: usize,
    /// Warning count.
    pub warning_count: usize,
    /// Key component names and their sizes.
    pub key_components: Vec<(String, usize)>,
}

/// Generate a summary report from a loaded component.
#[must_use]
pub fn summarise(data: &[u8], comp: &AndroidLoadedComponent) -> AndroidLoadSummary {
    let mut key_components: Vec<(String, usize)> = comp
        .components
        .iter()
        .map(|(k, &(_, sz))| (k.clone(), sz))
        .collect();
    key_components.sort_by(|a, b| b.1.cmp(&a.1));
    key_components.truncate(10);

    AndroidLoadSummary {
        format: comp.format.to_string(),
        total_size: data.len(),
        version: comp.version.clone(),
        component_count: comp.components.len(),
        warning_count: comp.warnings.len(),
        key_components,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_dex() {
        let mut d = vec![0u8; 200];
        d[..4].copy_from_slice(b"dex\n");
        d[4..7].copy_from_slice(b"035");
        d[7] = 0;
        assert_eq!(detect_format(&d), AndroidFormat::Dex);
    }

    #[test]
    fn detect_vdex() {
        let mut d = vec![0u8; 32];
        d[..4].copy_from_slice(b"vdex");
        assert_eq!(detect_format(&d), AndroidFormat::Vdex);
    }

    #[test]
    fn detect_art() {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"art\n");
        assert_eq!(detect_format(&d), AndroidFormat::ArtImage);
    }

    #[test]
    fn detect_unknown() {
        let d = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(detect_format(&d), AndroidFormat::Unknown);
    }

    #[test]
    fn detect_odex() {
        let mut d = vec![0u8; 50];
        d[..4].copy_from_slice(b"dey\n");
        assert_eq!(detect_format(&d), AndroidFormat::Odex);
    }

    #[test]
    fn load_binary_unknown_fails() {
        let err = load_android_binary(b"\xDE\xAD\xBE\xEF").unwrap_err();
        assert!(err.to_string().contains("unrecognised"));
    }

    #[test]
    fn dex_load_too_short_fails() {
        let mut d = vec![0u8; 50];
        d[..4].copy_from_slice(b"dex\n");
        let err = load_android_binary(&d).unwrap_err();
        assert!(err.to_string().contains("short"));
    }

    #[test]
    fn summarise_format_name() {
        let comp = AndroidLoadedComponent::new(AndroidFormat::Dex);
        let summary = summarise(&[], &comp);
        assert_eq!(summary.format, "DEX");
    }
}
