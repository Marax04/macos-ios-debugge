//! `uboot_parser` — Comprehensive U-Boot image format parser.
//!
//! Supports:
//! - **U-Boot legacy uImage** (`magic = 0x27051956`), 64-byte header.
//! - **U-Boot FIT image** (Flattened Image Tree, DTB-encoded `0xD00DFEED`):
//!   parses the FDT structure to locate images, configurations, and
//!   kernel/ramdisk/dtb nodes.
//!
//! All multi-byte fields in the legacy header are big-endian.
//!
//! # Usage
//! ```rust
//! use rustre_loader_firmware::uboot_parser::{UBootImage, IhType};
//! let data: Vec<u8> = vec![0u8; 64]; // incomplete for illustration
//! // UBootImage::parse(&data) returns None on invalid magic
//! ```

use crate::FirmwareError;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Legacy uImage magic.
pub const IH_MAGIC: u32 = 0x2705_1956;
/// FIT image magic (also DTB magic).
pub const FIT_MAGIC: u32 = 0xD00D_FEED;

/// U-Boot legacy image header size in bytes.
pub const IH_HEADER_SIZE: usize = 64;
/// Maximum image name length.
pub const IH_NMLEN: usize = 32;

// ─────────────────────────────────────────────────────────────────────────────
// IH_OS — Operating system types
// ─────────────────────────────────────────────────────────────────────────────

/// Operating system type stored in `ih_os`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IhOs {
    Invalid = 0,
    OpenBsd = 1,
    NetBsd = 2,
    FreeBsd = 3,
    Bsd44 = 4,
    Linux = 5,
    Svr4 = 6,
    Esix = 7,
    Solaris = 8,
    Irix = 9,
    Sco = 10,
    Dell = 11,
    Ncr = 12,
    LynxOs = 13,
    VxWorks = 14,
    Psos = 15,
    Qnx = 16,
    UBoot = 17,
    Rtems = 18,
    Artos = 19,
    Unity = 20,
    Integrity = 21,
    Ose = 22,
    Plan9 = 23,
    OpenRtos = 24,
    Unknown = 255,
}

impl IhOs {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Invalid,
            1 => Self::OpenBsd,
            2 => Self::NetBsd,
            3 => Self::FreeBsd,
            4 => Self::Bsd44,
            5 => Self::Linux,
            6 => Self::Svr4,
            7 => Self::Esix,
            8 => Self::Solaris,
            9 => Self::Irix,
            10 => Self::Sco,
            11 => Self::Dell,
            12 => Self::Ncr,
            13 => Self::LynxOs,
            14 => Self::VxWorks,
            15 => Self::Psos,
            16 => Self::Qnx,
            17 => Self::UBoot,
            18 => Self::Rtems,
            19 => Self::Artos,
            20 => Self::Unity,
            21 => Self::Integrity,
            22 => Self::Ose,
            23 => Self::Plan9,
            24 => Self::OpenRtos,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::OpenBsd => "openbsd",
            Self::NetBsd => "netbsd",
            Self::FreeBsd => "freebsd",
            Self::Bsd44 => "4.4bsd",
            Self::Linux => "linux",
            Self::Svr4 => "svr4",
            Self::Esix => "esix",
            Self::Solaris => "solaris",
            Self::Irix => "irix",
            Self::Sco => "sco",
            Self::Dell => "dell",
            Self::Ncr => "ncr",
            Self::LynxOs => "lynxos",
            Self::VxWorks => "vxworks",
            Self::Psos => "psos",
            Self::Qnx => "qnx",
            Self::UBoot => "u-boot",
            Self::Rtems => "rtems",
            Self::Artos => "artos",
            Self::Unity => "unity",
            Self::Integrity => "integrity",
            Self::Ose => "ose",
            Self::Plan9 => "plan9",
            Self::OpenRtos => "openrtos",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for IhOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IH_ARCH — CPU architecture types
// ─────────────────────────────────────────────────────────────────────────────

/// CPU architecture stored in `ih_arch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IhArch {
    Invalid = 0,
    Alpha = 1,
    Arm = 2,
    X86 = 3,
    Ia64 = 4,
    Mips = 5,
    Mips64 = 6,
    Ppc = 7,
    S390 = 8,
    Sh = 9,
    Sparc = 10,
    Sparc64 = 11,
    M68k = 12,
    Nios = 13,
    MicroBlaze = 14,
    Nios2 = 15,
    Blackfin = 16,
    Avr32 = 17,
    St200 = 18,
    Sandbox = 19,
    Nds32 = 20,
    OpenRisc = 21,
    Arm64 = 22,
    Arc = 23,
    X86_64 = 24,
    Xtensa = 25,
    RiscV = 26,
    Unknown = 255,
}

impl IhArch {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Invalid,
            1 => Self::Alpha,
            2 => Self::Arm,
            3 => Self::X86,
            4 => Self::Ia64,
            5 => Self::Mips,
            6 => Self::Mips64,
            7 => Self::Ppc,
            8 => Self::S390,
            9 => Self::Sh,
            10 => Self::Sparc,
            11 => Self::Sparc64,
            12 => Self::M68k,
            13 => Self::Nios,
            14 => Self::MicroBlaze,
            15 => Self::Nios2,
            16 => Self::Blackfin,
            17 => Self::Avr32,
            18 => Self::St200,
            19 => Self::Sandbox,
            20 => Self::Nds32,
            21 => Self::OpenRisc,
            22 => Self::Arm64,
            23 => Self::Arc,
            24 => Self::X86_64,
            25 => Self::Xtensa,
            26 => Self::RiscV,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Alpha => "alpha",
            Self::Arm => "arm",
            Self::X86 => "x86",
            Self::Ia64 => "ia64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Ppc => "ppc",
            Self::S390 => "s390",
            Self::Sh => "sh",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::M68k => "m68k",
            Self::Nios => "nios",
            Self::MicroBlaze => "microblaze",
            Self::Nios2 => "nios2",
            Self::Blackfin => "blackfin",
            Self::Avr32 => "avr32",
            Self::St200 => "st200",
            Self::Sandbox => "sandbox",
            Self::Nds32 => "nds32",
            Self::OpenRisc => "openrisc",
            Self::Arm64 => "aarch64",
            Self::Arc => "arc",
            Self::X86_64 => "x86_64",
            Self::Xtensa => "xtensa",
            Self::RiscV => "riscv",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for IhArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IH_TYPE — Image types
// ─────────────────────────────────────────────────────────────────────────────

/// Image type stored in `ih_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IhType {
    Invalid = 0,
    Standalone = 1,
    Kernel = 2,
    Ramdisk = 3,
    Multi = 4,
    Firmware = 5,
    Script = 6,
    Filesystem = 7,
    FlatDt = 8,
    KernelNoload = 9,
    KvmArmZimage = 10,
    ImxImage = 11,
    StandaloneApp = 12,
    Fpga = 13,
    Gpimage = 14,
    Unknown = 255,
}

impl IhType {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Invalid,
            1 => Self::Standalone,
            2 => Self::Kernel,
            3 => Self::Ramdisk,
            4 => Self::Multi,
            5 => Self::Firmware,
            6 => Self::Script,
            7 => Self::Filesystem,
            8 => Self::FlatDt,
            9 => Self::KernelNoload,
            10 => Self::KvmArmZimage,
            11 => Self::ImxImage,
            12 => Self::StandaloneApp,
            13 => Self::Fpga,
            14 => Self::Gpimage,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Standalone => "standalone",
            Self::Kernel => "kernel",
            Self::Ramdisk => "ramdisk",
            Self::Multi => "multi",
            Self::Firmware => "firmware",
            Self::Script => "script",
            Self::Filesystem => "filesystem",
            Self::FlatDt => "flat_dt",
            Self::KernelNoload => "kernel_noload",
            Self::KvmArmZimage => "kvm_arm_zimage",
            Self::ImxImage => "imx_image",
            Self::StandaloneApp => "standalone_app",
            Self::Fpga => "fpga",
            Self::Gpimage => "gpimage",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for IhType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IH_COMP — Compression types
// ─────────────────────────────────────────────────────────────────────────────

/// Compression algorithm stored in `ih_comp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IhComp {
    None = 0,
    Gzip = 1,
    Bzip2 = 2,
    Lzma = 3,
    Lzo = 4,
    Lz4 = 5,
    Zstd = 6,
    Unknown = 255,
}

impl IhComp {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::None,
            1 => Self::Gzip,
            2 => Self::Bzip2,
            3 => Self::Lzma,
            4 => Self::Lzo,
            5 => Self::Lz4,
            6 => Self::Zstd,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "lzma",
            Self::Lzo => "lzo",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for IhComp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UBootLegacyHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed U-Boot legacy uImage header (64 bytes, all fields big-endian).
///
/// Field layout mirrors `include/image.h` `image_header_t`:
/// ```text
/// offset  size  field
///  0       4    ih_magic   (0x27051956)
///  4       4    ih_hcrc
///  8       4    ih_time
/// 12       4    ih_size    (payload size)
/// 16       4    ih_load
/// 20       4    ih_ep
/// 24       4    ih_dcrc
/// 28       1    ih_os
/// 29       1    ih_arch
/// 30       1    ih_type
/// 31       1    ih_comp
/// 32      32    ih_name    (null-terminated)
/// ```
#[derive(Debug, Clone)]
pub struct UBootLegacyHeader {
    /// Magic number (must equal [`IH_MAGIC`]).
    pub ih_magic: u32,
    /// CRC32 of header (computed with this field set to 0).
    pub ih_hcrc: u32,
    /// Creation timestamp (Unix epoch seconds).
    pub ih_time: u32,
    /// Uncompressed payload size in bytes.
    pub ih_size: u32,
    /// Load address.
    pub ih_load: u32,
    /// Entry point address.
    pub ih_ep: u32,
    /// CRC32 of the payload.
    pub ih_dcrc: u32,
    /// OS type.
    pub ih_os: IhOs,
    /// CPU architecture.
    pub ih_arch: IhArch,
    /// Image type.
    pub ih_type: IhType,
    /// Compression algorithm.
    pub ih_comp: IhComp,
    /// Image name (up to 32 bytes, null-terminated).
    pub ih_name: String,
}

impl UBootLegacyHeader {
    /// Parse a legacy header from the start of `data`.
    /// Returns `Err` if magic is wrong or data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        if data.len() < IH_HEADER_SIZE {
            return Err(FirmwareError::TruncatedData);
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != IH_MAGIC {
            return Err(FirmwareError::InvalidMagic(format!(
                "expected {IH_MAGIC:#010x}, got {magic:#010x}"
            )));
        }
        let nul = data[32..64].iter().position(|&b| b == 0).unwrap_or(32);
        let ih_name = String::from_utf8_lossy(&data[32..32 + nul]).to_string();
        Ok(Self {
            ih_magic: magic,
            ih_hcrc: u32::from_be_bytes(data[4..8].try_into().unwrap()),
            ih_time: u32::from_be_bytes(data[8..12].try_into().unwrap()),
            ih_size: u32::from_be_bytes(data[12..16].try_into().unwrap()),
            ih_load: u32::from_be_bytes(data[16..20].try_into().unwrap()),
            ih_ep: u32::from_be_bytes(data[20..24].try_into().unwrap()),
            ih_dcrc: u32::from_be_bytes(data[24..28].try_into().unwrap()),
            ih_os: IhOs::from_byte(data[28]),
            ih_arch: IhArch::from_byte(data[29]),
            ih_type: IhType::from_byte(data[30]),
            ih_comp: IhComp::from_byte(data[31]),
            ih_name,
        })
    }

    /// Extract payload bytes (raw, possibly compressed).
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let end = IH_HEADER_SIZE + self.ih_size as usize;
        if end <= data.len() {
            Some(&data[IH_HEADER_SIZE..end])
        } else {
            None
        }
    }

    /// Total image size: header + payload.
    #[must_use]
    pub fn total_size(&self) -> usize {
        IH_HEADER_SIZE + self.ih_size as usize
    }
}

impl fmt::Display for UBootLegacyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "uImage name='{}' os={} arch={} type={} comp={} load={:#010x} ep={:#010x} size={}",
            self.ih_name,
            self.ih_os,
            self.ih_arch,
            self.ih_type,
            self.ih_comp,
            self.ih_load,
            self.ih_ep,
            self.ih_size,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FDT / FIT image parser
// ─────────────────────────────────────────────────────────────────────────────

/// Token types in a Flattened Device Tree (FDT / DTB).
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;

/// A property extracted from an FDT node.
#[derive(Debug, Clone)]
pub struct FdtProperty {
    /// Property name (from the string block).
    pub name: String,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl FdtProperty {
    /// Try to interpret the value as a null-terminated UTF-8 string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        let s = std::str::from_utf8(&self.value).ok()?;
        Some(s.trim_end_matches('\0'))
    }

    /// Try to interpret the value as a big-endian u32.
    #[must_use]
    pub fn as_u32_be(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            Some(u32::from_be_bytes(self.value[..4].try_into().ok()?))
        } else {
            None
        }
    }

    /// Try to interpret the value as a big-endian u64.
    #[must_use]
    pub fn as_u64_be(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            Some(u64::from_be_bytes(self.value[..8].try_into().ok()?))
        } else {
            None
        }
    }
}

/// One node from an FDT tree.
#[derive(Debug, Clone)]
pub struct FdtNode {
    /// Node name (unit-name part before `@`).
    pub name: String,
    /// Unit address suffix (the part after `@`, empty if not present).
    pub unit_addr: String,
    /// Properties of this node.
    pub props: Vec<FdtProperty>,
    /// Child nodes.
    pub children: Vec<FdtNode>,
}

impl FdtNode {
    /// Look up a property by name.
    #[must_use]
    pub fn prop(&self, name: &str) -> Option<&FdtProperty> {
        self.props.iter().find(|p| p.name == name)
    }

    /// Return the first `data` property value as raw bytes.
    #[must_use]
    pub fn data_prop(&self) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|p| p.name == "data")
            .map(|p| p.value.as_slice())
    }

    /// Find a direct child by name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&FdtNode> {
        self.children
            .iter()
            .find(|c| c.name == name || c.full_name() == name)
    }

    /// Full name: `name@unit_addr` or just `name` if no unit address.
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.unit_addr.is_empty() {
            self.name.clone()
        } else {
            format!("{}@{}", self.name, self.unit_addr)
        }
    }
}

/// Low-level FDT blob parser.
pub struct FdtParser<'a> {
    data: &'a [u8],
    struct_off: usize,
    struct_size: usize,
    strings_off: usize,
    strings_size: usize,
}

impl<'a> FdtParser<'a> {
    /// Parse the FDT header and validate magic.
    pub fn new(data: &'a [u8]) -> Result<Self, FirmwareError> {
        if data.len() < 40 {
            return Err(FirmwareError::TruncatedData);
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != FIT_MAGIC {
            return Err(FirmwareError::InvalidMagic(format!("{magic:#010x}")));
        }
        let struct_off = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        let strings_off = u32::from_be_bytes(data[12..16].try_into().unwrap()) as usize;
        let struct_size = u32::from_be_bytes(data[32..36].try_into().unwrap()) as usize;
        let strings_size = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;
        if struct_off + struct_size > data.len() || strings_off + strings_size > data.len() {
            return Err(FirmwareError::TruncatedData);
        }
        Ok(Self {
            data,
            struct_off,
            struct_size,
            strings_off,
            strings_size,
        })
    }

    fn read_u32_at(&self, off: usize) -> Option<u32> {
        if off + 4 <= self.data.len() {
            Some(u32::from_be_bytes(self.data[off..off + 4].try_into().ok()?))
        } else {
            None
        }
    }

    fn string_at(&self, name_off: usize) -> String {
        let start = self.strings_off + name_off;
        if start >= self.data.len() {
            return String::new();
        }
        let nul = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.strings_size);
        let end = (start + nul).min(self.data.len());
        String::from_utf8_lossy(&self.data[start..end]).to_string()
    }

    /// Parse the structure block into a tree of [`FdtNode`]s.
    pub fn parse_tree(&self) -> Result<FdtNode, FirmwareError> {
        let mut pos = self.struct_off;
        let end = self.struct_off + self.struct_size;
        let (node, _) = self.parse_node(&mut pos, end, "")?;
        Ok(node)
    }

    fn parse_node(
        &self,
        pos: &mut usize,
        end: usize,
        initial_name: &str,
    ) -> Result<(FdtNode, bool), FirmwareError> {
        let mut node = FdtNode {
            name: initial_name.to_string(),
            unit_addr: String::new(),
            props: Vec::new(),
            children: Vec::new(),
        };
        // Split name@addr
        if let Some(at) = initial_name.find('@') {
            node.name = initial_name[..at].to_string();
            node.unit_addr = initial_name[at + 1..].to_string();
        }

        loop {
            if *pos + 4 > end {
                break;
            }
            let token = match self.read_u32_at(*pos) {
                Some(t) => t,
                None => break,
            };
            *pos += 4;
            match token {
                FDT_BEGIN_NODE => {
                    // Read node name (null-terminated, then padded to 4 bytes)
                    let name_start = *pos;
                    let nul = self.data[name_start..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(0);
                    let name = String::from_utf8_lossy(&self.data[name_start..name_start + nul])
                        .to_string();
                    *pos = name_start + nul + 1;
                    *pos = (*pos + 3) & !3; // align to 4
                    let (child, ended) = self.parse_node(pos, end, &name)?;
                    node.children.push(child);
                    if ended {
                        break;
                    }
                }
                FDT_END_NODE => {
                    return Ok((node, false));
                }
                FDT_PROP => {
                    if *pos + 8 > end {
                        break;
                    }
                    let val_len =
                        u32::from_be_bytes(self.data[*pos..*pos + 4].try_into().unwrap()) as usize;
                    let name_off =
                        u32::from_be_bytes(self.data[*pos + 4..*pos + 8].try_into().unwrap())
                            as usize;
                    *pos += 8;
                    let val_end = *pos + val_len;
                    if val_end > self.data.len() {
                        break;
                    }
                    let value = self.data[*pos..val_end].to_vec();
                    *pos = (val_end + 3) & !3;
                    let name = self.string_at(name_off);
                    node.props.push(FdtProperty { name, value });
                }
                FDT_NOP => {}
                FDT_END | _ => {
                    return Ok((node, true));
                }
            }
        }
        Ok((node, true))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIT image high-level view
// ─────────────────────────────────────────────────────────────────────────────

/// An image component extracted from a FIT image.
#[derive(Debug, Clone)]
pub struct FitImage {
    /// Node name (e.g. `"kernel@1"`).
    pub node_name: String,
    /// Value of the `type` property (e.g. `"kernel"`, `"ramdisk"`, `"fdt"`).
    pub image_type: String,
    /// Value of the `description` property.
    pub description: String,
    /// Value of the `compression` property.
    pub compression: String,
    /// Load address (from `load` property), if present.
    pub load_addr: Option<u64>,
    /// Entry point (from `entry` property), if present.
    pub entry: Option<u64>,
    /// Raw image data (from `data` property).
    pub data: Vec<u8>,
}

/// A FIT configuration extracted from the `/configurations` subtree.
#[derive(Debug, Clone)]
pub struct FitConfig {
    pub node_name: String,
    pub description: String,
    pub kernel_ref: Option<String>,
    pub ramdisk_ref: Option<String>,
    pub fdt_ref: Option<String>,
}

/// Parsed FIT image (U-Boot Flattened Image Tree).
#[derive(Debug, Clone)]
pub struct FitImageFile {
    /// Description from `/` `description` property.
    pub description: String,
    /// All image nodes from `/images`.
    pub images: Vec<FitImage>,
    /// All configuration nodes from `/configurations`.
    pub configs: Vec<FitConfig>,
    /// The default configuration name.
    pub default_config: Option<String>,
}

impl FitImageFile {
    /// Parse a FIT image from `data`.
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        let parser = FdtParser::new(data)?;
        let root = parser.parse_tree()?;

        let description = root
            .prop("description")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();

        let mut images = Vec::new();
        if let Some(images_node) = root.child("images") {
            for child in &images_node.children {
                let image_type = child
                    .prop("type")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                let desc = child
                    .prop("description")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                let compression = child
                    .prop("compression")
                    .and_then(|p| p.as_str())
                    .unwrap_or("none")
                    .to_string();
                let load_addr = child
                    .prop("load")
                    .and_then(|p| p.as_u32_be())
                    .map(|v| v as u64);
                let entry = child
                    .prop("entry")
                    .and_then(|p| p.as_u32_be())
                    .map(|v| v as u64);
                let raw_data = child.data_prop().map(|d| d.to_vec()).unwrap_or_default();
                images.push(FitImage {
                    node_name: child.full_name(),
                    image_type,
                    description: desc,
                    compression,
                    load_addr,
                    entry,
                    data: raw_data,
                });
            }
        }

        let mut configs = Vec::new();
        let mut default_config = None;
        if let Some(cfg_node) = root.child("configurations") {
            default_config = cfg_node
                .prop("default")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string());
            for child in &cfg_node.children {
                let cfg = FitConfig {
                    node_name: child.full_name(),
                    description: child
                        .prop("description")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string(),
                    kernel_ref: child
                        .prop("kernel")
                        .and_then(|p| p.as_str())
                        .map(|s| s.to_string()),
                    ramdisk_ref: child
                        .prop("ramdisk")
                        .and_then(|p| p.as_str())
                        .map(|s| s.to_string()),
                    fdt_ref: child
                        .prop("fdt")
                        .and_then(|p| p.as_str())
                        .map(|s| s.to_string()),
                };
                configs.push(cfg);
            }
        }

        Ok(Self {
            description,
            images,
            configs,
            default_config,
        })
    }

    /// Find the first kernel image.
    #[must_use]
    pub fn kernel(&self) -> Option<&FitImage> {
        self.images
            .iter()
            .find(|i| i.image_type == "kernel" || i.image_type == "kernel_noload")
    }

    /// Find the first ramdisk image.
    #[must_use]
    pub fn ramdisk(&self) -> Option<&FitImage> {
        self.images.iter().find(|i| i.image_type == "ramdisk")
    }

    /// Find the first FDT image.
    #[must_use]
    pub fn fdt(&self) -> Option<&FitImage> {
        self.images
            .iter()
            .find(|i| i.image_type == "flat_dt" || i.image_type == "fdt")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified UBootImage enum
// ─────────────────────────────────────────────────────────────────────────────

/// Either a U-Boot legacy uImage or a FIT image.
#[derive(Debug, Clone)]
pub enum UBootImage {
    Legacy(UBootLegacyHeader),
    Fit(FitImageFile),
}

impl UBootImage {
    /// Try to parse `data` as either a legacy or FIT image.
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        if data.len() >= 4 {
            let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match magic {
                IH_MAGIC => return Ok(Self::Legacy(UBootLegacyHeader::parse(data)?)),
                FIT_MAGIC => return Ok(Self::Fit(FitImageFile::parse(data)?)),
                _ => {}
            }
        }
        Err(FirmwareError::InvalidMagic(
            "not a U-Boot image".to_string(),
        ))
    }

    /// Return `true` if this is a FIT image.
    #[must_use]
    pub fn is_fit(&self) -> bool {
        matches!(self, Self::Fit(_))
    }

    /// Return `true` if this is a legacy uImage.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    /// Return the entry point address, if available.
    #[must_use]
    pub fn entry_point(&self) -> Option<u64> {
        match self {
            Self::Legacy(h) => Some(h.ih_ep as u64),
            Self::Fit(f) => f.kernel().and_then(|k| k.entry),
        }
    }

    /// Return the load address, if available.
    #[must_use]
    pub fn load_address(&self) -> Option<u64> {
        match self {
            Self::Legacy(h) => Some(h.ih_load as u64),
            Self::Fit(f) => f.kernel().and_then(|k| k.load_addr),
        }
    }
}

impl fmt::Display for UBootImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(h) => write!(f, "{h}"),
            Self::Fit(fit) => write!(
                f,
                "FIT '{}' images={} configs={}",
                fit.description,
                fit.images.len(),
                fit.configs.len(),
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_legacy(load: u32, ep: u32, arch: u8, ih_type: u8, comp: u8, name: &[u8]) -> Vec<u8> {
        let mut hdr = vec![0u8; 64];
        hdr[0..4].copy_from_slice(&IH_MAGIC.to_be_bytes());
        hdr[12..16].copy_from_slice(&256_u32.to_be_bytes()); // ih_size
        hdr[16..20].copy_from_slice(&load.to_be_bytes());
        hdr[20..24].copy_from_slice(&ep.to_be_bytes());
        hdr[28] = 5; // IH_OS = linux
        hdr[29] = arch;
        hdr[30] = ih_type;
        hdr[31] = comp;
        let nlen = name.len().min(31);
        hdr[32..32 + nlen].copy_from_slice(&name[..nlen]);
        hdr
    }

    // ── IhOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_ih_os_linux() {
        assert_eq!(IhOs::from_byte(5), IhOs::Linux);
    }

    #[test]
    fn test_ih_os_display() {
        assert_eq!(IhOs::Linux.to_string(), "linux");
    }

    #[test]
    fn test_ih_os_unknown() {
        assert_eq!(IhOs::from_byte(200), IhOs::Unknown);
        assert_eq!(IhOs::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_ih_os_all_str() {
        for b in 0u8..25 {
            let os = IhOs::from_byte(b);
            assert!(!os.as_str().is_empty());
        }
    }

    // ── IhArch ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ih_arch_arm() {
        assert_eq!(IhArch::from_byte(2), IhArch::Arm);
    }

    #[test]
    fn test_ih_arch_aarch64() {
        assert_eq!(IhArch::from_byte(22), IhArch::Arm64);
        assert_eq!(IhArch::Arm64.as_str(), "aarch64");
    }

    #[test]
    fn test_ih_arch_riscv() {
        assert_eq!(IhArch::from_byte(26).as_str(), "riscv");
    }

    #[test]
    fn test_ih_arch_unknown() {
        assert_eq!(IhArch::from_byte(200).as_str(), "unknown");
    }

    // ── IhType ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ih_type_kernel() {
        assert_eq!(IhType::from_byte(2), IhType::Kernel);
    }

    #[test]
    fn test_ih_type_ramdisk() {
        assert_eq!(IhType::Ramdisk.as_str(), "ramdisk");
    }

    #[test]
    fn test_ih_type_firmware() {
        assert_eq!(IhType::from_byte(5), IhType::Firmware);
    }

    #[test]
    fn test_ih_type_display() {
        assert_eq!(IhType::Script.to_string(), "script");
    }

    // ── IhComp ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ih_comp_none() {
        assert_eq!(IhComp::from_byte(0), IhComp::None);
    }

    #[test]
    fn test_ih_comp_gzip() {
        assert_eq!(IhComp::Gzip.as_str(), "gzip");
    }

    #[test]
    fn test_ih_comp_zstd() {
        assert_eq!(IhComp::from_byte(6), IhComp::Zstd);
    }

    #[test]
    fn test_ih_comp_unknown() {
        assert_eq!(IhComp::from_byte(99), IhComp::Unknown);
    }

    // ── UBootLegacyHeader ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_legacy_ok() {
        let hdr = make_legacy(0x8000_0000, 0x8000_0100, 2, 2, 1, b"test-image");
        let parsed = UBootLegacyHeader::parse(&hdr).unwrap();
        assert_eq!(parsed.ih_magic, IH_MAGIC);
        assert_eq!(parsed.ih_load, 0x8000_0000);
        assert_eq!(parsed.ih_ep, 0x8000_0100);
        assert_eq!(parsed.ih_arch, IhArch::Arm);
        assert_eq!(parsed.ih_type, IhType::Kernel);
        assert_eq!(parsed.ih_comp, IhComp::Gzip);
        assert_eq!(parsed.ih_name, "test-image");
    }

    #[test]
    fn test_parse_legacy_too_short() {
        assert!(UBootLegacyHeader::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_parse_legacy_wrong_magic() {
        let data = vec![0u8; 64];
        assert!(UBootLegacyHeader::parse(&data).is_err());
    }

    #[test]
    fn test_legacy_payload() {
        let mut data = make_legacy(0, 0, 2, 2, 0, b"img");
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // ih_size set to 4 in make_legacy? No, it was 256. Let's override:
        data[12..16].copy_from_slice(&4_u32.to_be_bytes());
        let parsed = UBootLegacyHeader::parse(&data).unwrap();
        let payload = parsed.payload(&data).unwrap();
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_legacy_total_size() {
        let hdr = make_legacy(0, 0, 2, 2, 0, b"x");
        let parsed = UBootLegacyHeader::parse(&hdr).unwrap();
        assert_eq!(parsed.total_size(), 64 + 256);
    }

    #[test]
    fn test_legacy_display() {
        let hdr = make_legacy(0x8000_0000, 0x8000_0000, 2, 2, 0, b"fw");
        let parsed = UBootLegacyHeader::parse(&hdr).unwrap();
        let s = parsed.to_string();
        assert!(s.contains("fw"));
        assert!(s.contains("arm"));
        assert!(s.contains("kernel"));
    }

    #[test]
    fn test_ih_name_no_null_overflow() {
        let mut data = make_legacy(0, 0, 2, 2, 0, b"");
        // Fill the name field with non-null bytes
        for i in 32..64 {
            data[i] = b'A';
        }
        let parsed = UBootLegacyHeader::parse(&data).unwrap();
        assert_eq!(parsed.ih_name.len(), 32);
    }

    // ── UBootImage enum ───────────────────────────────────────────────────────

    #[test]
    fn test_uboot_image_parse_legacy() {
        let data = make_legacy(0x4000_0000, 0x4000_0100, 5, 2, 1, b"kern");
        let img = UBootImage::parse(&data).unwrap();
        assert!(img.is_legacy());
        assert_eq!(img.entry_point(), Some(0x4000_0100));
        assert_eq!(img.load_address(), Some(0x4000_0000));
    }

    #[test]
    fn test_uboot_image_parse_wrong_magic() {
        let data = vec![0u8; 64];
        assert!(UBootImage::parse(&data).is_err());
    }

    #[test]
    fn test_uboot_image_too_short() {
        assert!(UBootImage::parse(&[0u8; 2]).is_err());
    }

    // ── FdtProperty helpers ───────────────────────────────────────────────────

    #[test]
    fn test_fdt_property_as_str() {
        let p = FdtProperty {
            name: "desc".to_string(),
            value: b"hello\0".to_vec(),
        };
        assert_eq!(p.as_str(), Some("hello"));
    }

    #[test]
    fn test_fdt_property_as_u32_be() {
        let p = FdtProperty {
            name: "load".to_string(),
            value: 0x8000_0000_u32.to_be_bytes().to_vec(),
        };
        assert_eq!(p.as_u32_be(), Some(0x8000_0000));
    }

    #[test]
    fn test_fdt_property_as_u32_short() {
        let p = FdtProperty {
            name: "x".to_string(),
            value: vec![0x01, 0x02],
        };
        assert_eq!(p.as_u32_be(), None);
    }

    // ── FdtNode helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_fdt_node_full_name_no_addr() {
        let n = FdtNode {
            name: "images".to_string(),
            unit_addr: String::new(),
            props: vec![],
            children: vec![],
        };
        assert_eq!(n.full_name(), "images");
    }

    #[test]
    fn test_fdt_node_full_name_with_addr() {
        let n = FdtNode {
            name: "kernel".to_string(),
            unit_addr: "1".to_string(),
            props: vec![],
            children: vec![],
        };
        assert_eq!(n.full_name(), "kernel@1");
    }

    #[test]
    fn test_fdt_node_prop_lookup() {
        let n = FdtNode {
            name: "test".to_string(),
            unit_addr: String::new(),
            props: vec![FdtProperty {
                name: "hello".to_string(),
                value: b"world".to_vec(),
            }],
            children: vec![],
        };
        assert!(n.prop("hello").is_some());
        assert!(n.prop("missing").is_none());
    }
}
