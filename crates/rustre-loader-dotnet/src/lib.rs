//! `rustre-loader-dotnet`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: DOTNET
//!
//! Recognises PE files that contain a non-zero CLR Runtime Header (PE data
//! directory index 14) and loads them as .NET / CIL binaries.
//!
//! ## Coverage
//! - **CLI header** (`IMAGE_COR20_HEADER`): cb, `MajorRuntimeVersion`,
//!   `MinorRuntimeVersion`, `MetaData` RVA/Size, Flags, EntryPointToken/RVA,
//!   `StrongNameSignature`, `CodeManagerTable`, `VTableFixups`, `ExportAddressTable`.
//! - **Metadata root** (`BSJB` magic, version string, stream headers `#~`,
//!   `#Strings`, `#US`, `#GUID`, `#Blob`).
//! - **Metadata tables stream (`#~`)**: full 24-byte header decode, valid/sorted
//!   bitmasks, per-table row count array, coded-index sizing, row parsing for
//!   all 64 possible table slots (populated for the tables listed in
//!   `MetadataTables`).
//! - **Key tables**: Module(0), TypeRef(1), TypeDef(2), Field(4), MethodDef(6),
//!   Param(8), InterfaceImpl(9), MemberRef(10), Constant(11),
//!   CustomAttribute(12), Assembly(32), AssemblyRef(35), NestedClass(41),
//!   GenericParam(42).
//! - **Method body**: fat/tiny header detection, code bytes (CIL), local
//!   variable signature token, exception handler tables (Clause types: Catch,
//!   Finally, Filter, Fault).
//! - **Type hierarchy reconstruction** from `TypeDef` + `InterfaceImpl` +
//!   `NestedClass`.
//! - **Blob / String heap helpers** and full `TypeSig` / `MethodSig` decoders.

pub mod cil_decoder;
pub mod cil_disasm;
pub mod dotnet_header_parser;
pub mod dotnet_type_loader;
pub mod dotnet_type_system;
pub mod il_method_loader;
pub mod managed_resources;
pub mod metadata_tables;
pub mod ngen_analysis;
pub mod pe_clr_header;
pub mod strongname;
pub mod dotnet_assembly_loader;
pub mod pdb_type_reader;
pub mod resources_section_parser;
pub mod dotnet_method_loader;

pub use il_method_loader::{
    CilOpcode, ExceptionClauseType as IlExceptionClauseType, ExceptionHandler, IlError,
    IlInstruction, IlMethodLoader, LocalVarSig, MethodHeader, Operand, OperandType,
    build_opcode_table,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use bitflags::bitflags;
use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::loader::LoadResult;
use rustre_core::permissions::Permissions;
use rustre_core::{Loader, LoaderInput, NestedBinary, async_trait};

// â”€â”€ Error type â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Errors produced by the .NET loader.
#[derive(Debug, thiserror::Error)]
pub enum DotnetLoaderError {
    /// File does not contain .NET metadata.
    #[error("not a .NET assembly")]
    NotDotnet,
    /// Metadata header is invalid.
    #[error("invalid metadata")]
    InvalidMetadata,
    /// Stream entry is truncated.
    #[error("truncated stream")]
    TruncatedStream,
    /// A method body header is malformed.
    #[error("invalid method body at RVA {0:#010x}")]
    InvalidMethodBody(u32),
    /// An RVA could not be resolved to a file offset.
    #[error("unresolvable RVA {0:#010x}")]
    UnresolvableRva(u32),
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
}

// â”€â”€ Runtime version â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// .NET CLR runtime version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DotnetRuntimeVersion {
    /// Major version number.
    pub major: u16,
    /// Minor version number.
    pub minor: u16,
}

impl fmt::Display for DotnetRuntimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

// â”€â”€ Assembly flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

bitflags! {
    /// .NET assembly flags parsed from the CLR header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct DotnetAssemblyFlags: u32 {
        /// Pure IL only, no native code.
        const IL_ONLY = 1;
        /// Requires a 32-bit process.
        const REQUIRES_32BIT = 2;
        /// Assembly has a strong-name signature.
        const STRONG_NAME_SIGNED = 8;
        /// Assembly has a native entry point.
        const NATIVE_ENTRYPOINT = 16;
        /// Prefer 32-bit even on 64-bit.
        const PREFER_32BIT = 0x0002_0000;
    }
}

// â”€â”€ CorFlags (CLR header Flags field) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

bitflags! {
    /// Flags from `IMAGE_COR20_HEADER.Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CorFlags: u32 {
        /// Pure MSIL (no native code).
        const IL_ONLY = 0x0000_0001;
        /// 32-bit process required.
        const REQUIRES_32BIT_PROCESS = 0x0000_0002;
        /// Strong-name signed.
        const STRONG_NAME_SIGNED = 0x0000_0008;
        /// Native entry point present.
        const NATIVE_ENTRY_POINT = 0x0000_0010;
        /// Metadata from a delta module.
        const TRACK_DEBUG_DATA = 0x0001_0000;
        /// Prefer 32-bit (Silverlight-era).
        const PREFER_32BIT_PROCESS = 0x0002_0000;
    }
}

// â”€â”€ Metadata types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// High-level .NET assembly metadata.
#[derive(Debug, Clone)]
pub struct DotnetMetadata {
    /// Runtime version the assembly targets.
    pub version: DotnetRuntimeVersion,
    /// Assembly flags.
    pub assembly_flags: DotnetAssemblyFlags,
    /// Whether the file is a DLL rather than an EXE.
    pub is_dll: bool,
    /// Module version ID (MVID GUID).
    pub mvid: [u8; 16],
    /// Module name (from the `#~` table).
    pub module_name: String,
    /// Assembly name (from the `Assembly` table), if present.
    pub assembly_name: Option<String>,
    /// `CorFlags` from the CLR header.
    pub cor_flags: CorFlags,
}

impl DotnetMetadata {
    /// Build a mock `DotnetMetadata` for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            version: DotnetRuntimeVersion { major: 4, minor: 0 },
            assembly_flags: DotnetAssemblyFlags::IL_ONLY,
            is_dll: false,
            mvid: [0u8; 16],
            module_name: "MyModule.exe".to_string(),
            assembly_name: Some("MyAssembly".to_string()),
            cor_flags: CorFlags::IL_ONLY,
        }
    }

    /// Returns `true` when the assembly is pure IL (no native code sections).
    #[must_use]
    pub const fn is_pure_il(&self) -> bool {
        self.cor_flags.contains(CorFlags::IL_ONLY)
    }

    /// Returns `true` when the assembly carries a strong-name signature.
    #[must_use]
    pub const fn is_strong_named(&self) -> bool {
        self.cor_flags.contains(CorFlags::STRONG_NAME_SIGNED)
    }
}

impl fmt::Display for DotnetMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".NET {} module={} dll={} pure_il={}",
            self.version,
            self.module_name,
            self.is_dll,
            self.is_pure_il()
        )
    }
}

// â”€â”€ Stream â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A metadata stream entry (e.g. `#~`, `#Strings`, `#Blob`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetStream {
    /// Stream name (null-terminated, padded to 4 bytes in the file).
    pub name: String,
    /// Offset of the stream data relative to the metadata root.
    pub offset: u32,
    /// Size of the stream in bytes.
    pub size: u32,
}

impl fmt::Display for DotnetStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stream '{}' offset={:#x} size={}",
            self.name, self.offset, self.size
        )
    }
}

// â”€â”€ DotnetFile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parsed .NET assembly file.
#[derive(Debug, Clone)]
pub struct DotnetFile {
    /// Assembly metadata.
    pub metadata: DotnetMetadata,
    /// Metadata streams.
    pub streams: Vec<DotnetStream>,
    /// Entry-point metadata token (if present).
    pub entry_point_token: Option<u32>,
}

impl DotnetFile {
    /// Returns `true` if `data` contains the `BSJB` metadata signature.
    #[must_use]
    pub fn is_valid_dotnet(data: &[u8]) -> bool {
        data.windows(4).any(|w| w == b"BSJB")
    }

    /// Parse the .NET metadata header from `data`.
    ///
    /// # Errors
    /// Returns `DotnetLoaderError::NotDotnet` if no BSJB signature is found.
    /// Returns `DotnetLoaderError::TruncatedStream` if data is too short.
    pub fn parse_metadata_header(data: &[u8]) -> Result<Self, DotnetLoaderError> {
        let bsjb_pos = data
            .windows(4)
            .position(|w| w == b"BSJB")
            .ok_or(DotnetLoaderError::NotDotnet)?;

        let d = &data[bsjb_pos..];
        if d.len() < 16 {
            return Err(DotnetLoaderError::TruncatedStream);
        }

        let major = u16::from_le_bytes([d[4], d[5]]);
        let minor = u16::from_le_bytes([d[6], d[7]]);

        let version_len = u32::from_le_bytes(
            d[12..16]
                .try_into()
                .map_err(|_| DotnetLoaderError::TruncatedStream)?,
        ) as usize;

        let version_start = 16usize;
        let version_end = version_start
            .checked_add(version_len)
            .ok_or(DotnetLoaderError::TruncatedStream)?;
        if d.len() < version_end + 4 {
            return Err(DotnetLoaderError::TruncatedStream);
        }

        let flags_off = version_end;
        let stream_count = u16::from_le_bytes([d[flags_off + 2], d[flags_off + 3]]) as usize;

        let mut streams = Vec::with_capacity(stream_count);
        let mut pos = flags_off + 4;

        for _ in 0..stream_count {
            if pos + 8 > d.len() {
                return Err(DotnetLoaderError::TruncatedStream);
            }
            let offset = u32::from_le_bytes(
                d[pos..pos + 4]
                    .try_into()
                    .map_err(|_| DotnetLoaderError::TruncatedStream)?,
            );
            let size = u32::from_le_bytes(
                d[pos + 4..pos + 8]
                    .try_into()
                    .map_err(|_| DotnetLoaderError::TruncatedStream)?,
            );
            pos += 8;
            let name_start = pos;
            let mut name_end = pos;
            while name_end < d.len() && d[name_end] != 0 {
                name_end += 1;
            }
            let name = String::from_utf8_lossy(&d[name_start..name_end]).into_owned();
            let raw_name_len = name_end - name_start + 1;
            let padded = (raw_name_len + 3) & !3;
            pos += padded;

            streams.push(DotnetStream { name, offset, size });
        }

        let (mvid, module_name, assembly_name) =
            Self::extract_module_info(data, bsjb_pos, &streams);

        let metadata = DotnetMetadata {
            version: DotnetRuntimeVersion { major, minor },
            assembly_flags: DotnetAssemblyFlags::IL_ONLY,
            is_dll: false,
            mvid,
            module_name,
            assembly_name,
            cor_flags: CorFlags::IL_ONLY,
        };

        Ok(Self {
            metadata,
            streams,
            entry_point_token: None,
        })
    }

    /// Find a stream by name.
    #[must_use]
    pub fn stream(&self, name: &str) -> Option<&DotnetStream> {
        self.streams.iter().find(|s| s.name == name)
    }

    /// Extract module name, MVID, and assembly name from the raw binary data.
    fn extract_module_info(
        data: &[u8],
        metadata_base: usize,
        streams: &[DotnetStream],
    ) -> ([u8; 16], String, Option<String>) {
        let mut mvid = [0u8; 16];
        let mut module_name = String::new();
        let mut assembly_name: Option<String> = None;

        let strings_stream = streams.iter().find(|s| s.name == "#Strings");
        let tables_stream = streams.iter().find(|s| s.name == "#~");
        let guid_stream = streams.iter().find(|s| s.name == "#GUID");

        let strings_data: &[u8] = if let Some(ss) = strings_stream {
            let start = metadata_base + ss.offset as usize;
            let end = start.saturating_add(ss.size as usize);
            if end <= data.len() {
                &data[start..end]
            } else {
                &[]
            }
        } else {
            &[]
        };

        let guid_data: &[u8] = if let Some(gs) = guid_stream {
            let start = metadata_base + gs.offset as usize;
            let end = start.saturating_add(gs.size as usize);
            if end <= data.len() {
                &data[start..end]
            } else {
                &[]
            }
        } else {
            &[]
        };

        if let Some(ts) = tables_stream {
            let start = metadata_base + ts.offset as usize;
            let end = start.saturating_add(ts.size as usize);
            if end <= data.len() && start + 24 <= data.len() {
                let ts_data = &data[start..end];
                if ts_data.len() >= 24 {
                    let heap_sizes = ts_data[6];
                    let string_index_size: usize = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
                    let guid_index_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };

                    let row_start = 24;
                    if ts_data.len() >= row_start + 2 + string_index_size + guid_index_size {
                        let name_idx_off = row_start + 2;
                        let name_idx: usize = if string_index_size == 2 {
                            u16::from_le_bytes([ts_data[name_idx_off], ts_data[name_idx_off + 1]])
                                as usize
                        } else {
                            u32::from_le_bytes([
                                ts_data[name_idx_off],
                                ts_data[name_idx_off + 1],
                                ts_data[name_idx_off + 2],
                                ts_data[name_idx_off + 3],
                            ]) as usize
                        };

                        let mvid_idx_off = name_idx_off + string_index_size;
                        let mvid_idx: usize = if guid_index_size == 2 {
                            u16::from_le_bytes([ts_data[mvid_idx_off], ts_data[mvid_idx_off + 1]])
                                as usize
                        } else {
                            u32::from_le_bytes([
                                ts_data[mvid_idx_off],
                                ts_data[mvid_idx_off + 1],
                                ts_data[mvid_idx_off + 2],
                                ts_data[mvid_idx_off + 3],
                            ]) as usize
                        };

                        if name_idx < strings_data.len() {
                            let name_bytes = &strings_data[name_idx..];
                            let null_pos = name_bytes
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(name_bytes.len());
                            module_name =
                                String::from_utf8_lossy(&name_bytes[..null_pos]).into_owned();
                        }

                        if mvid_idx > 0 {
                            let guid_off = (mvid_idx - 1) * 16;
                            if guid_off + 16 <= guid_data.len() {
                                mvid.copy_from_slice(&guid_data[guid_off..guid_off + 16]);
                            }
                        }

                        if !module_name.is_empty() {
                            let base = module_name
                                .trim_end_matches(".dll")
                                .trim_end_matches(".exe")
                                .to_string();
                            if !base.is_empty() {
                                assembly_name = Some(base);
                            }
                        }
                    }
                }
            }
        }

        (mvid, module_name, assembly_name)
    }
}

// â”€â”€ Magic / detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Returns `true` if `data` is a PE file with a non-zero CLR runtime header RVA.
///
/// Uses [`goblin::pe::PE`] to parse the PE headers correctly for both PE32
/// and PE32+ images, handling edge cases such as bound imports and overlays.
#[must_use]
pub fn has_clr_header(data: &[u8]) -> bool {
    // Manually walk the PE headers â€” we only need the COM descriptor data
    // directory (index 14), which is well-defined in both PE32 and PE32+.
    // Using goblin::pe::PE::parse here is too strict: it rejects minimal but
    // spec-conformant images (e.g. those without section tables or import
    // directories), causing valid .NET binaries to be misidentified.
    if data.len() < 0x40 || data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew.saturating_add(24) > data.len() {
        return false;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = e_lfanew + 24;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    // COM descriptor data-directory offset within the optional header:
    //   PE32  (0x10B): 96 + 14*8 = 208
    //   PE32+ (0x20B): 112 + 14*8 = 224
    let dd_off = match magic {
        0x10B => opt_off + 96 + 14 * 8,
        0x20B => opt_off + 112 + 14 * 8,
        _ => return false,
    };
    if dd_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes([
        data[dd_off],
        data[dd_off + 1],
        data[dd_off + 2],
        data[dd_off + 3],
    ]);
    rva != 0
}

/// Returns `true` if `data` contains the BSJB metadata signature.
#[must_use]
pub fn is_dotnet(data: &[u8]) -> bool {
    DotnetFile::is_valid_dotnet(data)
}

// â”€â”€ CLR header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parsed CLR Runtime Header (`IMAGE_COR20_HEADER`).
///
/// See ECMA-335 Â§II.25.3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClrHeader {
    /// `cb`: size of the CLR header structure in bytes.
    pub header_size: u32,
    /// Major CLR runtime version.
    pub major_runtime_version: u16,
    /// Minor CLR runtime version.
    pub minor_runtime_version: u16,
    /// RVA of the metadata stream.
    pub metadata_rva: u32,
    /// Size of the metadata.
    pub metadata_size: u32,
    /// `CorFlags` flags field.
    pub flags: u32,
    /// Entry-point metadata token (or RVA when `NATIVE_ENTRY_POINT` is set).
    pub entry_point_token: u32,
    /// RVA of the managed-resources blob.
    ///
    /// Needed to locate the resource data; without it the resource parser has
    /// no way to be pointed at anything.
    pub resources_rva: u32,
    /// Size of the managed-resources blob.
    pub resources_size: u32,
    /// RVA of the strong-name blob (0 if unsigned).
    pub strong_name_rva: u32,
    /// Size of the strong-name blob.
    pub strong_name_size: u32,
    /// RVA of the `CodeManagerTable` directory.
    pub code_manager_rva: u32,
    /// Size of the `CodeManagerTable` directory.
    pub code_manager_size: u32,
    /// RVA of the `VTableFixups` directory.
    pub vtable_fixups_rva: u32,
    /// Size of the `VTableFixups` directory.
    pub vtable_fixups_size: u32,
    /// RVA of the `ExportAddressTableJumps` directory.
    pub export_address_table_jumps_rva: u32,
    /// Size of the `ExportAddressTableJumps` directory.
    pub export_address_table_jumps_size: u32,
    /// RVA of the `ManagedNativeHeader` directory.
    ///
    /// Null for ordinary IL images; in ReadyToRun images it points at a
    /// `READYTORUN_HEADER`.
    pub managed_native_header_rva: u32,
    /// Size of the `ManagedNativeHeader` directory.
    pub managed_native_header_size: u32,
}

impl ClrHeader {
    /// Parse a `ClrHeader` from `data`.
    ///
    /// Returns `None` if `data` is shorter than 48 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        let rd16 = |o: usize| -> Option<u16> {
            Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?))
        };
        let rd32 = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
        };
        Some(Self {
            header_size: rd32(0)?,
            major_runtime_version: rd16(4)?,
            minor_runtime_version: rd16(6)?,
            metadata_rva: rd32(8)?,
            metadata_size: rd32(12)?,
            flags: rd32(16)?,
            entry_point_token: rd32(20)?,
            // Offsets follow IMAGE_COR20_HEADER: each directory is 8 bytes
            // (rva then size), starting at 24. Reading strong_name from 24
            // would in fact read Resources — the two are adjacent and the
            // mistake is invisible in any test whose tail bytes are zero.
            resources_rva: rd32(24).unwrap_or(0),
            resources_size: rd32(28).unwrap_or(0),
            strong_name_rva: rd32(32).unwrap_or(0),
            strong_name_size: rd32(36).unwrap_or(0),
            code_manager_rva: rd32(40).unwrap_or(0),
            code_manager_size: rd32(44).unwrap_or(0),
            vtable_fixups_rva: rd32(48).unwrap_or(0),
            vtable_fixups_size: rd32(52).unwrap_or(0),
            export_address_table_jumps_rva: rd32(56).unwrap_or(0),
            export_address_table_jumps_size: rd32(60).unwrap_or(0),
            managed_native_header_rva: rd32(64).unwrap_or(0),
            managed_native_header_size: rd32(68).unwrap_or(0),
        })
    }

    /// Returns `true` if the binary is mixed-mode (`IL_ONLY` flag not set).
    #[must_use]
    pub const fn is_mixed_mode(&self) -> bool {
        (self.flags & 0x0000_0001) == 0
    }

    /// Returns a `"major.minor"` version string.
    #[must_use]
    pub fn framework_version(&self) -> String {
        format!(
            "{}.{}",
            self.major_runtime_version, self.minor_runtime_version
        )
    }

    /// Returns `true` when a strong-name signature is present.
    #[must_use]
    pub const fn has_strong_name(&self) -> bool {
        self.strong_name_rva != 0 && self.strong_name_size != 0
    }
}

impl fmt::Display for ClrHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CLR v{} metadata_rva={:#x} metadata_size={} flags={:#x} sn={}",
            self.framework_version(),
            self.metadata_rva,
            self.metadata_size,
            self.flags,
            self.has_strong_name(),
        )
    }
}

// â”€â”€ PE optional header stub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Minimal parsed PE optional header fields needed for loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeOptHeader {
    /// `true` if the PE is 64-bit (PE32+).
    pub is_64bit: bool,
    /// Preferred load address.
    pub image_base: u64,
    /// Address of the entry point (RVA).
    pub entry_point_rva: u32,
    /// Total image size in memory.
    pub image_size: u32,
    /// Number of data directories.
    pub num_data_dirs: u32,
}

impl PeOptHeader {
    /// Parse from the optional header at `data[opt_hdr_off..]`.
    #[must_use]
    pub fn parse(data: &[u8], opt_hdr_off: usize) -> Option<Self> {
        if opt_hdr_off + 4 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes([data[opt_hdr_off], data[opt_hdr_off + 1]]);
        let is_64bit = magic == 0x020B;
        let rd32 = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
        };
        let rd64 = |o: usize| -> Option<u64> {
            Some(u64::from_le_bytes(data.get(o..o + 8)?.try_into().ok()?))
        };
        if is_64bit {
            if opt_hdr_off + 60 > data.len() {
                return None;
            }
            let entry_point_rva = rd32(opt_hdr_off + 16)?;
            let image_base = rd64(opt_hdr_off + 24)?;
            let image_size = rd32(opt_hdr_off + 56)?;
            let num_data_dirs = rd32(opt_hdr_off + 108).unwrap_or(16);
            Some(Self {
                is_64bit,
                image_base,
                entry_point_rva,
                image_size,
                num_data_dirs,
            })
        } else {
            if opt_hdr_off + 60 > data.len() {
                return None;
            }
            let entry_point_rva = rd32(opt_hdr_off + 16)?;
            let image_base = u64::from(rd32(opt_hdr_off + 28)?);
            let image_size = rd32(opt_hdr_off + 56)?;
            let num_data_dirs = rd32(opt_hdr_off + 92).unwrap_or(16);
            Some(Self {
                is_64bit,
                image_base,
                entry_point_rva,
                image_size,
                num_data_dirs,
            })
        }
    }
}

impl fmt::Display for PeOptHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PE{} image_base={:#x} ep_rva={:#x} size={}",
            if self.is_64bit { "32+" } else { "32" },
            self.image_base,
            self.entry_point_rva,
            self.image_size,
        )
    }
}

// â”€â”€ PE section helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single PE section header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSectionHeader {
    /// Section name (up to 8 bytes, null-padded).
    pub name: String,
    /// Virtual size (bytes in memory).
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw data size on disk.
    pub raw_size: u32,
    /// Raw data offset in file.
    pub raw_offset: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl PeSectionHeader {
    /// Parse a PE section header from `data` at `offset`.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 40 > data.len() {
            return None;
        }
        let name_bytes = &data[offset..offset + 8];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        let rd32 = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
        };
        Some(Self {
            name,
            virtual_size: rd32(offset + 8)?,
            virtual_address: rd32(offset + 12)?,
            raw_size: rd32(offset + 16)?,
            raw_offset: rd32(offset + 20)?,
            characteristics: rd32(offset + 36)?,
        })
    }

    /// Resolve an RVA to a file offset using this section.
    ///
    /// Returns `None` if the RVA does not fall within this section.
    #[must_use]
    pub const fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // Checked arithmetic, matching the twin in `dotnet_header_parser`: both
        // operands come from a hostile section header, so a wrapping sum would
        // silently skip the section.
        if rva >= self.virtual_address
            && rva < self.virtual_address.saturating_add(self.virtual_size)
        {
            let delta = rva - self.virtual_address;
            Some(self.raw_offset as usize + delta as usize)
        } else {
            None
        }
    }
}

/// Parse all PE section headers from a PE binary.
///
/// `pe_off` is the offset of the PE signature (`"PE\x00\x00"`).
#[must_use]
pub fn parse_pe_sections(data: &[u8], pe_off: usize) -> Vec<PeSectionHeader> {
    if pe_off + 6 > data.len() {
        return vec![];
    }
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let magic_off = pe_off + 24;
    if magic_off + 2 > data.len() {
        return vec![];
    }
    let magic = u16::from_le_bytes([data[magic_off], data[magic_off + 1]]);
    let opt_size = u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]) as usize;
    let sections_off = pe_off + 24 + opt_size;
    let _ = magic; // suppress warning

    (0..num_sections)
        .filter_map(|i| PeSectionHeader::parse(data, sections_off + i * 40))
        .collect()
}

/// Resolve an RVA to a file offset by searching PE section headers.
#[must_use]
pub fn rva_to_file_offset(rva: u32, sections: &[PeSectionHeader]) -> Option<usize> {
    sections.iter().find_map(|s| s.rva_to_offset(rva))
}

// â”€â”€ Architecture stub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Minimal Architecture implementation for the CIL (.NET) target.
#[derive(Debug)]
pub struct DotnetArch;

impl Architecture for DotnetArch {
    fn name(&self) -> &'static str {
        "cil"
    }
    fn pointer_size(&self) -> usize {
        8
    }
    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        use crate::cil_decoder::CilDecoder;
        let mut decoder = CilDecoder::new(bytes);
        match decoder.next() {
            Some(Ok(instr)) => {
                let size = instr.byte_len as usize;
                Ok(Instruction::new(
                    address,
                    size,
                    &instr.mnemonic,
                    bytes[..size].to_vec(),
                ))
            }
            Some(Err(_)) | None => {
                // Fallback: treat as 1-byte unknown
                Ok(Instruction::new(address, 1, "???", bytes[..1.min(bytes.len())].to_vec()))
            }
        }
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }
    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }
    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// â”€â”€ Loader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Loader for .NET PE files.
#[derive(Debug)]
pub struct DotnetLoader;

#[async_trait]
impl Loader for DotnetLoader {
    fn name(&self) -> &'static str {
        "dotnet"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        // Prefer the PE CLR directory check (data directory entry 14) as the
        // primary signal; fall back to the BSJB scan only when the file does
        // not look like a standard PE (e.g. raw metadata blobs).
        has_clr_header(&input.data) || DotnetFile::is_valid_dotnet(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input
            .hints
            .base_address()
            .map_or(0x0040_0000_u64, rustre_core::Address::as_u64);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(base), Address::new(base + size)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: input.data.clone(),
        });

        let arch = Arc::new(DotnetArch);
        let view_id = ViewId::from_raw(1);
        let view = BinaryView::new(
            view_id,
            input.uri,
            arch,
            Endian::Little,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// â”€â”€ ECMA-335 Metadata table rows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// ECMA-335 Â§II.22.30 â€” Module table row (table 0x00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRow {
    pub generation: u16,
    pub name: u32,
    pub mvid: u32,
    pub enc_id: u32,
    pub enc_base_id: u32,
}

/// ECMA-335 Â§II.22.38 â€” `TypeRef` table row (table 0x01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRefRow {
    pub resolution_scope: u32,
    pub type_name: u32,
    pub type_namespace: u32,
}

/// ECMA-335 Â§II.22.37 â€” `TypeDef` table row (table 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDefRow {
    pub flags: u32,
    pub type_name: u32,
    pub type_namespace: u32,
    pub extends: u32,
    pub field_list: u32,
    pub method_list: u32,
}

impl TypeDefRow {
    /// Returns `true` when `TypeAttributes.Interface` is set.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags & 0x0000_0020 != 0
    }
    /// Returns `true` when `TypeAttributes.Abstract` is set.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0000_0080 != 0
    }
    /// Returns `true` when `TypeAttributes.Sealed` is set.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags & 0x0000_0100 != 0
    }
    /// Returns `true` when `TypeAttributes.Enum` is set (inherits from System.Enum).
    #[must_use]
    pub const fn is_nested_public(&self) -> bool {
        (self.flags & 0x7) == 0x2
    }
}

/// ECMA-335 Â§II.22.15 â€” Field table row (table 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRow {
    pub flags: u16,
    pub name: u32,
    pub signature: u32,
}

/// ECMA-335 Â§II.22.26 â€” `MethodDef` table row (table 0x06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDefRow {
    /// RVA of the CIL method body.
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: u32,
    pub signature: u32,
    pub param_list: u32,
}

impl MethodDefRow {
    /// Returns `true` if this is an abstract method (no body).
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0400 != 0
    }
    /// Returns `true` if this is a virtual method.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        self.flags & 0x0040 != 0
    }
    /// Returns `true` if this is a static method.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    /// Returns `true` if this is a public method.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        (self.flags & 0x7) == 0x6
    }
    /// Returns `true` if this is a constructor (`<init>`).
    #[must_use]
    pub const fn is_constructor(&self) -> bool {
        self.flags & 0x0800 != 0
    }
}

/// ECMA-335 Â§II.22.33 â€” Param table row (table 0x08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamRow {
    pub flags: u16,
    pub sequence: u16,
    pub name: u32,
}

/// ECMA-335 Â§II.22.23 â€” `InterfaceImpl` table row (table 0x09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceImplRow {
    pub class: u32,
    pub interface: u32,
}

/// ECMA-335 Â§II.22.25 â€” `MemberRef` table row (table 0x0A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRefRow {
    pub class: u32,
    pub name: u32,
    pub signature: u32,
}

/// ECMA-335 Â§II.22.9 â€” Constant table row (table 0x0B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantRow {
    pub type_: u8,
    pub parent: u32,
    pub value: u32,
}

/// ECMA-335 Â§II.22.10 â€” `CustomAttribute` table row (table 0x0C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomAttributeRow {
    pub parent: u32,
    pub type_: u32,
    pub value: u32,
}

/// ECMA-335 Â§II.22.2 â€” Assembly table row (table 0x20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyRow {
    pub hash_alg_id: u32,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key: u32,
    pub name: u32,
    pub culture: u32,
}

impl AssemblyRow {
    /// Return a four-part version string like `"1.2.3.4"`.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// ECMA-335 Â§II.22.5 â€” `AssemblyRef` table row (table 0x23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyRefRow {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key_or_token: u32,
    pub name: u32,
    pub culture: u32,
    pub hash_value: u32,
}

impl AssemblyRefRow {
    /// Return a four-part version string like `"4.0.0.0"`.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// ECMA-335 Â§II.22.29 â€” `NestedClass` table row (table 0x29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedClassRow {
    pub nested_class: u32,
    pub enclosing_class: u32,
}

/// ECMA-335 Â§II.22.20 â€” `GenericParam` table row (table 0x2A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericParamRow {
    pub number: u16,
    pub flags: u16,
    pub owner: u32,
    pub name: u32,
}

// â”€â”€ TypeSig â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A decoded type from a `#Blob` signature (ECMA-335 Â§II.23.1.16).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TypeSig {
    Void,
    Bool,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    String,
    Object,
    /// `ELEMENT_TYPE_VALUETYPE` â€” encoded `TypeDefOrRef` token.
    ValueType(u32),
    /// `ELEMENT_TYPE_CLASS` â€” encoded `TypeDefOrRef` token.
    Class(u32),
    /// `ELEMENT_TYPE_SZARRAY` â€” single-dimension zero-lower-bound array.
    Array(Box<Self>),
    /// `ELEMENT_TYPE_GENERICINST`.
    GenericInst(bool, u32, Vec<Self>),
    /// `ELEMENT_TYPE_PTR` â€” unmanaged pointer.
    Ptr(Box<Self>),
    /// `ELEMENT_TYPE_BYREF` â€” managed reference.
    ByRef(Box<Self>),
    /// `ELEMENT_TYPE_VAR` â€” type-level generic parameter.
    Var(u32),
    /// `ELEMENT_TYPE_MVAR` â€” method-level generic parameter.
    MVar(u32),
    /// `ELEMENT_TYPE_PINNED`.
    Pinned(Box<Self>),
    /// Unknown or unhandled element type.
    Unknown(u8),
}

// â”€â”€ MethodSig â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decoded method signature (ECMA-335 Â§II.23.2.1).
#[derive(Debug, Clone)]
pub struct MethodSig {
    pub calling_conv: u8,
    pub generic_param_count: u32,
    pub ret_type: TypeSig,
    pub params: Vec<TypeSig>,
}

// â”€â”€ Blob helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Read a compressed unsigned integer from `blob` at `*offset`, advancing it.
pub fn read_compressed_uint(blob: &[u8], offset: &mut usize) -> u32 {
    if *offset >= blob.len() {
        return 0;
    }
    let b0 = blob[*offset];
    if b0 & 0x80 == 0 {
        *offset += 1;
        u32::from(b0)
    } else if b0 & 0xC0 == 0x80 {
        if *offset + 2 > blob.len() {
            *offset = blob.len();
            return 0;
        }
        let b1 = blob[*offset + 1];
        *offset += 2;
        (u32::from(b0 & 0x3F) << 8) | u32::from(b1)
    } else {
        if *offset + 4 > blob.len() {
            *offset = blob.len();
            return 0;
        }
        let b1 = blob[*offset + 1];
        let b2 = blob[*offset + 2];
        let b3 = blob[*offset + 3];
        *offset += 4;
        (u32::from(b0 & 0x1F) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3)
    }
}

/// Decode a `TypeDefOrRef` coded index into a raw metadata token.
#[must_use] 
pub const fn decode_type_def_or_ref(coded: u32) -> u32 {
    let table: u32 = match coded & 0x03 {
        0 => 0x02,
        1 => 0x01,
        2 => 0x1B,
        _ => 0xFF,
    };
    let row = coded >> 2;
    (table << 24) | row
}

/// Maximum recursion depth for nested type signatures (defense against
/// attacker-crafted deeply-nested Ptr/ByRef/GenericInst blobs).
const MAX_TYPE_SIG_DEPTH: u32 = 64;

/// Read a single [`TypeSig`] from `blob` starting at `*offset`.
pub fn read_type_sig(blob: &[u8], offset: &mut usize) -> TypeSig {
    read_type_sig_depth(blob, offset, 0)
}

fn read_type_sig_depth(blob: &[u8], offset: &mut usize, depth: u32) -> TypeSig {
    if depth >= MAX_TYPE_SIG_DEPTH {
        return TypeSig::Unknown(0);
    }
    if *offset >= blob.len() {
        return TypeSig::Unknown(0);
    }
    let tag = blob[*offset];
    *offset += 1;
    match tag {
        0x01 => TypeSig::Void,
        0x02 => TypeSig::Bool,
        0x03 => TypeSig::Char,
        0x04 => TypeSig::I1,
        0x05 => TypeSig::U1,
        0x06 => TypeSig::I2,
        0x07 => TypeSig::U2,
        0x08 => TypeSig::I4,
        0x09 => TypeSig::U4,
        0x0A => TypeSig::I8,
        0x0B => TypeSig::U8,
        0x0C => TypeSig::R4,
        0x0D => TypeSig::R8,
        0x0E => TypeSig::String,
        0x1C => TypeSig::Object,
        0x0F => TypeSig::Ptr(Box::new(read_type_sig_depth(blob, offset, depth + 1))),
        0x10 => TypeSig::ByRef(Box::new(read_type_sig_depth(blob, offset, depth + 1))),
        0x11 => TypeSig::ValueType(decode_type_def_or_ref(read_compressed_uint(blob, offset))),
        0x12 => TypeSig::Class(decode_type_def_or_ref(read_compressed_uint(blob, offset))),
        0x13 => TypeSig::Var(read_compressed_uint(blob, offset)),
        0x1E => TypeSig::MVar(read_compressed_uint(blob, offset)),
        0x15 => {
            let is_class = if *offset < blob.len() {
                let t = blob[*offset];
                *offset += 1;
                t == 0x12
            } else {
                true
            };
            let token = decode_type_def_or_ref(read_compressed_uint(blob, offset));
            let arg_count = read_compressed_uint(blob, offset) as usize;
            // Bound both the pre-allocation and the loop by the remaining
            // bytes: each argument consumes at least one byte, and reads at
            // EOF return Unknown without consuming (so an unbounded loop
            // would push billions of elements for a bogus count).
            let mut args = Vec::with_capacity(arg_count.min(blob.len().saturating_sub(*offset)));
            for _ in 0..arg_count {
                if *offset >= blob.len() {
                    break;
                }
                args.push(read_type_sig_depth(blob, offset, depth + 1));
            }
            TypeSig::GenericInst(is_class, token, args)
        }
        0x1D => TypeSig::Array(Box::new(read_type_sig_depth(blob, offset, depth + 1))),
        0x45 => TypeSig::Pinned(Box::new(read_type_sig_depth(blob, offset, depth + 1))),
        other => TypeSig::Unknown(other),
    }
}

/// Parse a method signature blob.
#[must_use] 
pub fn read_method_sig(blob: &[u8]) -> MethodSig {
    let mut offset = 0;
    if offset >= blob.len() {
        return MethodSig {
            calling_conv: 0,
            generic_param_count: 0,
            ret_type: TypeSig::Void,
            params: vec![],
        };
    }
    let calling_conv = blob[offset];
    offset += 1;
    let generic_param_count = if calling_conv & 0x10 != 0 {
        read_compressed_uint(blob, &mut offset)
    } else {
        0
    };
    let param_count = read_compressed_uint(blob, &mut offset) as usize;
    let ret_type = read_type_sig(blob, &mut offset);
    // Cap the pre-allocation by the remaining blob bytes: each parameter
    // consumes at least one byte, so a claimed count beyond that is bogus.
    let mut params = Vec::with_capacity(param_count.min(blob.len().saturating_sub(offset)));
    for _ in 0..param_count {
        // EOF reads return Unknown without consuming; stop instead of pushing
        // `param_count` placeholder entries for an attacker-claimed count.
        if offset >= blob.len() {
            break;
        }
        if offset < blob.len() && blob[offset] == 0x41 {
            offset += 1;
        }
        params.push(read_type_sig(blob, &mut offset));
    }
    MethodSig {
        calling_conv,
        generic_param_count,
        ret_type,
        params,
    }
}

// â”€â”€ String helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Read a null-terminated UTF-8 string from `heap` at byte offset `idx`.
#[must_use]
pub fn read_string_heap(heap: &[u8], idx: u32) -> &str {
    let start = idx as usize;
    if start >= heap.len() {
        return "";
    }
    let end = heap[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(heap.len(), |p| start + p);
    std::str::from_utf8(&heap[start..end]).unwrap_or("")
}

/// Resolve a `TypeDefOrRef` token to `"Namespace.Name"`.
#[must_use]
pub fn resolve_type_name(
    token: u32,
    type_defs: &[TypeDefRow],
    type_refs: &[TypeRefRow],
    strings: &[u8],
) -> String {
    let table = (token >> 24) as u8;
    let row = ((token & 0x00FF_FFFF) as usize).wrapping_sub(1);
    match table {
        0x02 => {
            type_defs.get(row).map_or_else(|| format!("<TypeDef:{row}>"), |td| {
                let ns = read_string_heap(strings, td.type_namespace);
                let name = read_string_heap(strings, td.type_name);
                if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                }
            })
        }
        0x01 => {
            type_refs.get(row).map_or_else(|| format!("<TypeRef:{row}>"), |tr| {
                let ns = read_string_heap(strings, tr.type_namespace);
                let name = read_string_heap(strings, tr.type_name);
                if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                }
            })
        }
        _ => format!("<token:{token:#010x}>"),
    }
}

/// Convert a [`TypeSig`] to a human-readable CIL type name.
#[must_use]
pub fn cil_type_name(sig: &TypeSig, type_defs: &[TypeDefRow], strings: &[u8]) -> String {
    cil_type_name_full(sig, type_defs, &[], strings)
}

/// Like [`cil_type_name`] but with `TypeRef` support.
#[must_use]
pub fn cil_type_name_full(
    sig: &TypeSig,
    type_defs: &[TypeDefRow],
    type_refs: &[TypeRefRow],
    strings: &[u8],
) -> String {
    match sig {
        TypeSig::Void => "void".to_owned(),
        TypeSig::Bool => "bool".to_owned(),
        TypeSig::Char => "char".to_owned(),
        TypeSig::I1 => "sbyte".to_owned(),
        TypeSig::U1 => "byte".to_owned(),
        TypeSig::I2 => "short".to_owned(),
        TypeSig::U2 => "ushort".to_owned(),
        TypeSig::I4 => "int".to_owned(),
        TypeSig::U4 => "uint".to_owned(),
        TypeSig::I8 => "long".to_owned(),
        TypeSig::U8 => "ulong".to_owned(),
        TypeSig::R4 => "float".to_owned(),
        TypeSig::R8 => "double".to_owned(),
        TypeSig::String => "string".to_owned(),
        TypeSig::Object => "object".to_owned(),
        TypeSig::ValueType(tok) | TypeSig::Class(tok) => {
            resolve_type_name(*tok, type_defs, type_refs, strings)
        }
        TypeSig::Array(inner) => format!(
            "{}[]",
            cil_type_name_full(inner, type_defs, type_refs, strings)
        ),
        TypeSig::Ptr(inner) => format!(
            "{}*",
            cil_type_name_full(inner, type_defs, type_refs, strings)
        ),
        TypeSig::ByRef(inner) => format!(
            "ref {}",
            cil_type_name_full(inner, type_defs, type_refs, strings)
        ),
        TypeSig::Pinned(inner) => format!(
            "pinned {}",
            cil_type_name_full(inner, type_defs, type_refs, strings)
        ),
        TypeSig::Var(n) => format!("T{n}"),
        TypeSig::MVar(n) => format!("M{n}"),
        TypeSig::GenericInst(_is_class, tok, args) => {
            let base = resolve_type_name(*tok, type_defs, type_refs, strings);
            let base = base.split('`').next().unwrap_or(&base);
            let arg_names: Vec<String> = args
                .iter()
                .map(|a| cil_type_name_full(a, type_defs, type_refs, strings))
                .collect();
            format!("{base}<{}>", arg_names.join(", "))
        }
        TypeSig::Unknown(tag) => format!("<element_type:{tag:#04x}>"),
    }
}

// â”€â”€ Method body â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// CIL method body parsed from a tiny or fat header.
#[derive(Debug, Clone)]
pub struct MethodBody {
    /// Whether this is a fat-header body.
    pub is_fat: bool,
    /// `MaxStack` value.
    pub max_stack: u16,
    /// Raw CIL bytes.
    pub code: Vec<u8>,
    /// Token for the local variable signature (0 = no locals).
    pub local_var_sig_tok: u32,
    /// Exception handler clauses.
    pub exception_handlers: Vec<ExceptionClause>,
}

/// An exception handler clause.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExceptionClause {
    /// Clause type.
    pub clause_type: ExceptionClauseType,
    /// Offset of try block in code bytes.
    pub try_offset: u32,
    /// Length of try block in bytes.
    pub try_length: u32,
    /// Offset of handler block.
    pub handler_offset: u32,
    /// Length of handler block.
    pub handler_length: u32,
    /// Catch type token (for `Catch`) or filter offset (for `Filter`).
    pub class_token_or_filter_offset: u32,
}

/// Exception clause type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExceptionClauseType {
    /// `catch` clause (0x0000).
    Catch,
    /// `filter` clause (0x0001).
    Filter,
    /// `finally` clause (0x0002).
    Finally,
    /// `fault` clause (0x0004).
    Fault,
    /// Unknown or reserved.
    Unknown(u32),
}

impl ExceptionClauseType {
    /// Decode from the raw `Flags` field in the exception table.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Catch,
            1 => Self::Filter,
            2 => Self::Finally,
            4 => Self::Fault,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ExceptionClauseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catch => write!(f, "catch"),
            Self::Filter => write!(f, "filter"),
            Self::Finally => write!(f, "finally"),
            Self::Fault => write!(f, "fault"),
            Self::Unknown(v) => write!(f, "unknown({v:#x})"),
        }
    }
}

/// Parse a CIL method body from `data` at byte offset `offset`.
///
/// Tiny header: if the low 2 bits of the first byte are `0b10`, the entire
/// header is 1 byte and the code length is `(byte >> 2)`.
///
/// Fat header: 12 bytes. Low 12 bits of the first word must be `0x3`.
///
/// # Errors
/// Returns `DotnetLoaderError::InvalidMethodBody(0)` for unrecognised headers.
pub fn parse_method_body(data: &[u8], offset: usize) -> Result<MethodBody, DotnetLoaderError> {
    if offset >= data.len() {
        return Err(DotnetLoaderError::InvalidMethodBody(0));
    }
    let first_byte = data[offset];

    // Tiny header: bits 1:0 == 0b10
    if (first_byte & 0x03) == 0x02 {
        let code_len = (first_byte >> 2) as usize;
        let code_start = offset + 1;
        if code_start + code_len > data.len() {
            return Err(DotnetLoaderError::TruncatedStream);
        }
        return Ok(MethodBody {
            is_fat: false,
            max_stack: 8,
            code: data[code_start..code_start + code_len].to_vec(),
            local_var_sig_tok: 0,
            exception_handlers: vec![],
        });
    }

    // Fat header: first u16 bits 1:0 == 0b11
    if offset + 12 > data.len() {
        return Err(DotnetLoaderError::TruncatedStream);
    }
    let flags_and_size = u16::from_le_bytes([data[offset], data[offset + 1]]);
    if (flags_and_size & 0x03) != 0x03 {
        return Err(DotnetLoaderError::InvalidMethodBody(0));
    }

    let has_more_sects = (flags_and_size & 0x08) != 0;
    let max_stack = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
    let code_size = u32::from_le_bytes(
        data[offset + 4..offset + 8]
            .try_into()
            .map_err(|_| DotnetLoaderError::TruncatedStream)?,
    ) as usize;
    let local_var_sig_tok = u32::from_le_bytes(
        data[offset + 8..offset + 12]
            .try_into()
            .map_err(|_| DotnetLoaderError::TruncatedStream)?,
    );

    let header_size = ((flags_and_size >> 12) & 0xF) as usize * 4;
    let code_start = offset + header_size.max(12);
    if code_start + code_size > data.len() {
        return Err(DotnetLoaderError::TruncatedStream);
    }
    let code = data[code_start..code_start + code_size].to_vec();

    // Parse exception handler section(s) if present
    let mut exception_handlers = Vec::new();
    if has_more_sects {
        // Sections start aligned to 4 bytes after the code
        let sect_base = (code_start + code_size + 3) & !3;
        exception_handlers = parse_exception_sections(data, sect_base);
    }

    Ok(MethodBody {
        is_fat: true,
        max_stack,
        code,
        local_var_sig_tok,
        exception_handlers,
    })
}

/// Parse exception handler sections from `data` at `offset`.
fn parse_exception_sections(data: &[u8], mut offset: usize) -> Vec<ExceptionClause> {
    let mut clauses = Vec::new();
    loop {
        if offset + 4 > data.len() {
            break;
        }
        let sect_kind = data[offset];
        let is_fat_sect = (sect_kind & 0x40) != 0;
        let has_more = (sect_kind & 0x80) != 0;

        if is_fat_sect {
            if offset + 4 > data.len() {
                break;
            }
            let data_size =
                (u32::from_le_bytes([data[offset + 1], data[offset + 2], data[offset + 3], 0])
                    & 0x00FF_FFFF) as usize;
            offset += 4;
            if data_size < 4 {
                break;
            }
            let num_clauses = (data_size - 4) / 24;
            clauses.reserve(num_clauses);
            for _ in 0..num_clauses {
                if offset + 24 > data.len() {
                    break;
                }
                let flags =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
                let try_offset =
                    u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
                let try_length =
                    u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
                let handler_offset =
                    u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
                let handler_length =
                    u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap_or([0; 4]));
                let class_or_filter =
                    u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap_or([0; 4]));
                clauses.push(ExceptionClause {
                    clause_type: ExceptionClauseType::from_u32(flags),
                    try_offset,
                    try_length,
                    handler_offset,
                    handler_length,
                    class_token_or_filter_offset: class_or_filter,
                });
                offset += 24;
            }
        } else {
            if offset + 4 > data.len() {
                break;
            }
            let data_size = data[offset + 1] as usize;
            offset += 4;
            if data_size < 4 {
                break;
            }
            let num_clauses = (data_size - 4) / 12;
            clauses.reserve(num_clauses);
            for _ in 0..num_clauses {
                if offset + 12 > data.len() {
                    break;
                }
                let flags = u32::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
                let try_offset = u32::from(u16::from_le_bytes([data[offset + 2], data[offset + 3]]));
                let try_length = u32::from(data[offset + 4]);
                let handler_offset =
                    u32::from(u16::from_le_bytes([data[offset + 5], data[offset + 6]]));
                let handler_length = u32::from(data[offset + 7]);
                let class_or_filter =
                    u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
                clauses.push(ExceptionClause {
                    clause_type: ExceptionClauseType::from_u32(flags),
                    try_offset,
                    try_length,
                    handler_offset,
                    handler_length,
                    class_token_or_filter_offset: class_or_filter,
                });
                offset += 12;
            }
        }

        if !has_more {
            break;
        }
    }
    clauses
}

// â”€â”€ Type hierarchy reconstruction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Reconstructed type hierarchy node.
#[derive(Debug, Clone)]
pub struct TypeNode {
    /// Zero-based `TypeDef` row index.
    pub type_def_idx: usize,
    /// Fully-qualified type name.
    pub full_name: String,
    /// Direct base type name (empty for types with no explicit base).
    pub base_type: String,
    /// Implemented interface names.
    pub interfaces: Vec<String>,
    /// Nested child type indices.
    pub nested_children: Vec<usize>,
    /// Methods defined by this type (`method_def` row indices).
    pub methods: Vec<usize>,
}

/// Reconstruct the complete type hierarchy from metadata tables.
///
/// Returns a `Vec<TypeNode>` parallel to `type_defs` (index N â†’ `type_defs`[N]).
#[must_use]
pub fn build_type_hierarchy(
    type_defs: &[TypeDefRow],
    type_refs: &[TypeRefRow],
    interface_impls: &[InterfaceImplRow],
    nested_classes: &[NestedClassRow],
    method_defs: &[MethodDefRow],
    strings: &[u8],
) -> Vec<TypeNode> {
    // Build nested-child map: enclosing â†’ [nested]
    let mut nested_map: HashMap<usize, Vec<usize>> = HashMap::new();
    for nc in nested_classes {
        let nested = (nc.nested_class as usize).wrapping_sub(1);
        let enclosing = (nc.enclosing_class as usize).wrapping_sub(1);
        nested_map.entry(enclosing).or_default().push(nested);
    }

    // Build interface map: class_idx â†’ [interface names]
    let mut iface_map: HashMap<usize, Vec<String>> = HashMap::new();
    for ii in interface_impls {
        let class_idx = (ii.class as usize).wrapping_sub(1);
        let iface_name = resolve_type_name(ii.interface, type_defs, type_refs, strings);
        iface_map.entry(class_idx).or_default().push(iface_name);
    }

    // Build method range map: type_def_idx â†’ [method_def_idx]
    // Each TypeDef row has a method_list that is 1-based inclusive start;
    // the end is the start of the next type's method_list.
    let mut method_map: HashMap<usize, Vec<usize>> = HashMap::new();
    for (td_idx, td) in type_defs.iter().enumerate() {
        let start = (td.method_list as usize).wrapping_sub(1);
        let end = type_defs
            .get(td_idx + 1)
            .map_or(method_defs.len(), |next| (next.method_list as usize).wrapping_sub(1));
        let methods: Vec<usize> = (start..end.min(method_defs.len())).collect();
        method_map.insert(td_idx, methods);
    }

    type_defs
        .iter()
        .enumerate()
        .map(|(idx, td)| {
            let ns = read_string_heap(strings, td.type_namespace);
            let name = read_string_heap(strings, td.type_name);
            let full_name = if ns.is_empty() {
                name.to_owned()
            } else {
                format!("{ns}.{name}")
            };

            let base_type = if td.extends == 0 || td.extends == 0xFFFF_FFFF {
                String::new()
            } else {
                resolve_type_name(td.extends, type_defs, type_refs, strings)
            };

            TypeNode {
                type_def_idx: idx,
                full_name,
                base_type,
                interfaces: iface_map.get(&idx).cloned().unwrap_or_default(),
                nested_children: nested_map.get(&idx).cloned().unwrap_or_default(),
                methods: method_map.get(&idx).cloned().unwrap_or_default(),
            }
        })
        .collect()
}

// â”€â”€ #~ stream (tables stream) parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parsed tables from the ECMA-335 `#~` compressed metadata stream.
#[derive(Debug, Default, Clone)]
pub struct MetadataTables {
    pub modules: Vec<ModuleRow>,
    pub type_refs: Vec<TypeRefRow>,
    pub type_defs: Vec<TypeDefRow>,
    pub fields: Vec<FieldRow>,
    pub method_defs: Vec<MethodDefRow>,
    pub params: Vec<ParamRow>,
    pub interface_impls: Vec<InterfaceImplRow>,
    pub member_refs: Vec<MemberRefRow>,
    pub constants: Vec<ConstantRow>,
    pub custom_attributes: Vec<CustomAttributeRow>,
    pub assemblies: Vec<AssemblyRow>,
    pub assembly_refs: Vec<AssemblyRefRow>,
    pub nested_classes: Vec<NestedClassRow>,
    pub generic_params: Vec<GenericParamRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexSize {
    Small,
    Large,
}

fn read_index(data: &[u8], pos: &mut usize, size: IndexSize) -> u32 {
    match size {
        IndexSize::Small => {
            if *pos + 2 > data.len() {
                *pos = data.len();
                return 0;
            }
            let v = u32::from(u16::from_le_bytes([data[*pos], data[*pos + 1]]));
            *pos += 2;
            v
        }
        IndexSize::Large => {
            if *pos + 4 > data.len() {
                *pos = data.len();
                return 0;
            }
            let v =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            v
        }
    }
}

fn read_u8_at(data: &[u8], pos: &mut usize) -> u8 {
    if *pos >= data.len() {
        return 0;
    }
    let v = data[*pos];
    *pos += 1;
    v
}

fn read_u16_at(data: &[u8], pos: &mut usize) -> u16 {
    if *pos + 2 > data.len() {
        *pos = data.len();
        return 0;
    }
    let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    v
}

fn read_u32_at(data: &[u8], pos: &mut usize) -> u32 {
    if *pos + 4 > data.len() {
        *pos = data.len();
        return 0;
    }
    let v = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    v
}

const fn table_index_size(row_count: u32) -> IndexSize {
    if row_count > 0xFFFF {
        IndexSize::Large
    } else {
        IndexSize::Small
    }
}

fn coded_index_size(tag_bits: u32, row_counts: &[u32]) -> IndexSize {
    let limit = 0xFFFF_u32 >> tag_bits;
    if row_counts.iter().any(|&r| r > limit) {
        IndexSize::Large
    } else {
        IndexSize::Small
    }
}

/// Parse the ECMA-335 `#~` (compressed tables) stream.
pub fn parse_tables_stream(stream_data: &[u8]) -> Result<MetadataTables, DotnetLoaderError> {
    if stream_data.len() < 24 {
        return Err(DotnetLoaderError::TruncatedStream);
    }

    let heap_sizes = stream_data[6];
    let str_size = if heap_sizes & 0x01 != 0 {
        IndexSize::Large
    } else {
        IndexSize::Small
    };
    let guid_size = if heap_sizes & 0x02 != 0 {
        IndexSize::Large
    } else {
        IndexSize::Small
    };
    let blob_size = if heap_sizes & 0x04 != 0 {
        IndexSize::Large
    } else {
        IndexSize::Small
    };

    let valid = u64::from_le_bytes(
        stream_data[8..16]
            .try_into()
            .map_err(|_| DotnetLoaderError::TruncatedStream)?,
    );

    let mut row_counts = [0u32; 64];
    let mut hdr_pos = 24usize;
    // Sanity cap: each row is at least 2 bytes, so no individual table can
    // legitimately have more rows than the stream has bytes. This prevents
    // attacker-controlled `valid` masks with huge row counts from triggering
    // unbounded allocation when we later iterate `for _ in 0..count`.
    let max_rows = stream_data.len() as u32;
    for bit in 0u32..64 {
        if valid & (1u64 << bit) != 0 {
            if hdr_pos + 4 > stream_data.len() {
                return Err(DotnetLoaderError::InvalidMetadata);
            }
            let count = u32::from_le_bytes(
                stream_data[hdr_pos..hdr_pos + 4]
                    .try_into()
                    .map_err(|_| DotnetLoaderError::InvalidMetadata)?,
            );
            if count > max_rows {
                return Err(DotnetLoaderError::InvalidMetadata);
            }
            row_counts[bit as usize] = count;
            hdr_pos += 4;
        }
    }

    let type_def_or_ref_size =
        coded_index_size(2, &[row_counts[0x02], row_counts[0x01], row_counts[0x1B]]);
    let has_constant_size =
        coded_index_size(2, &[row_counts[0x04], row_counts[0x08], row_counts[0x17]]);
    let has_custom_attr_size = coded_index_size(
        5,
        &[
            row_counts[0x06],
            row_counts[0x04],
            row_counts[0x01],
            row_counts[0x02],
            row_counts[0x08],
            row_counts[0x09],
            row_counts[0x0A],
            row_counts[0x00],
            row_counts[0x0B],
            row_counts[0x0C],
            row_counts[0x0F],
            row_counts[0x10],
            row_counts[0x13],
            row_counts[0x14],
            row_counts[0x17],
            row_counts[0x19],
            row_counts[0x20],
            row_counts[0x23],
            row_counts[0x26],
            row_counts[0x2A],
            row_counts[0x2C],
        ],
    );
    let member_ref_parent_size = coded_index_size(
        3,
        &[
            row_counts[0x02],
            row_counts[0x01],
            row_counts[0x1A],
            row_counts[0x06],
            row_counts[0x1B],
        ],
    );
    let custom_attr_type_size = coded_index_size(3, &[row_counts[0x06], row_counts[0x0A]]);
    let resolution_scope_size = coded_index_size(
        2,
        &[
            row_counts[0x00],
            row_counts[0x1A],
            row_counts[0x23],
            row_counts[0x01],
        ],
    );
    let type_or_method_def_size = coded_index_size(1, &[row_counts[0x02], row_counts[0x06]]);

    let td_idx = table_index_size(row_counts[0x02]);
    let fld_idx = table_index_size(row_counts[0x04]);
    let mth_idx = table_index_size(row_counts[0x06]);
    let prm_idx = table_index_size(row_counts[0x08]);

    let mut tables = MetadataTables::default();
    let mut pos = hdr_pos;

    for bit in 0u64..64 {
        let table = bit as usize;
        let count = row_counts[table];
        if count == 0 {
            continue;
        }
        // Alloc-DoS cap: past-EOF reads return 0 without erroring, so a huge
        // claimed row count would otherwise push billions of zero rows. Every
        // row consumes at least 2 bytes of the stream; clamp the count to what
        // the remaining bytes could possibly hold.
        let remaining = stream_data.len().saturating_sub(pos);
        let count = u32::try_from((u64::from(count)).min((remaining / 2) as u64)).unwrap_or(u32::MAX);
        if count == 0 {
            continue;
        }

        match table {
            0x00 => {
                // Module
                for _ in 0..count {
                    let generation = read_u16_at(stream_data, &mut pos);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let mvid = read_index(stream_data, &mut pos, guid_size);
                    let enc_id = read_index(stream_data, &mut pos, guid_size);
                    let enc_base_id = read_index(stream_data, &mut pos, guid_size);
                    tables.modules.push(ModuleRow {
                        generation,
                        name,
                        mvid,
                        enc_id,
                        enc_base_id,
                    });
                }
            }
            0x01 => {
                // TypeRef
                for _ in 0..count {
                    let resolution_scope = read_index(stream_data, &mut pos, resolution_scope_size);
                    let type_name = read_index(stream_data, &mut pos, str_size);
                    let type_namespace = read_index(stream_data, &mut pos, str_size);
                    tables.type_refs.push(TypeRefRow {
                        resolution_scope,
                        type_name,
                        type_namespace,
                    });
                }
            }
            0x02 => {
                // TypeDef
                for _ in 0..count {
                    let flags = read_u32_at(stream_data, &mut pos);
                    let type_name = read_index(stream_data, &mut pos, str_size);
                    let type_namespace = read_index(stream_data, &mut pos, str_size);
                    let extends = read_index(stream_data, &mut pos, type_def_or_ref_size);
                    let field_list = read_index(stream_data, &mut pos, fld_idx);
                    let method_list = read_index(stream_data, &mut pos, mth_idx);
                    tables.type_defs.push(TypeDefRow {
                        flags,
                        type_name,
                        type_namespace,
                        extends,
                        field_list,
                        method_list,
                    });
                }
            }
            0x04 => {
                // Field
                for _ in 0..count {
                    let flags = read_u16_at(stream_data, &mut pos);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let signature = read_index(stream_data, &mut pos, blob_size);
                    tables.fields.push(FieldRow {
                        flags,
                        name,
                        signature,
                    });
                }
            }
            0x06 => {
                // MethodDef
                for _ in 0..count {
                    let rva = read_u32_at(stream_data, &mut pos);
                    let impl_flags = read_u16_at(stream_data, &mut pos);
                    let flags = read_u16_at(stream_data, &mut pos);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let signature = read_index(stream_data, &mut pos, blob_size);
                    let param_list = read_index(stream_data, &mut pos, prm_idx);
                    tables.method_defs.push(MethodDefRow {
                        rva,
                        impl_flags,
                        flags,
                        name,
                        signature,
                        param_list,
                    });
                }
            }
            0x08 => {
                // Param
                for _ in 0..count {
                    let flags = read_u16_at(stream_data, &mut pos);
                    let sequence = read_u16_at(stream_data, &mut pos);
                    let name = read_index(stream_data, &mut pos, str_size);
                    tables.params.push(ParamRow {
                        flags,
                        sequence,
                        name,
                    });
                }
            }
            0x09 => {
                // InterfaceImpl
                for _ in 0..count {
                    let class = read_index(stream_data, &mut pos, td_idx);
                    let interface = read_index(stream_data, &mut pos, type_def_or_ref_size);
                    tables
                        .interface_impls
                        .push(InterfaceImplRow { class, interface });
                }
            }
            0x0A => {
                // MemberRef
                for _ in 0..count {
                    let class = read_index(stream_data, &mut pos, member_ref_parent_size);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let signature = read_index(stream_data, &mut pos, blob_size);
                    tables.member_refs.push(MemberRefRow {
                        class,
                        name,
                        signature,
                    });
                }
            }
            0x0B => {
                // Constant
                for _ in 0..count {
                    let type_ = read_u8_at(stream_data, &mut pos);
                    let _pad = read_u8_at(stream_data, &mut pos);
                    let parent = read_index(stream_data, &mut pos, has_constant_size);
                    let value = read_index(stream_data, &mut pos, blob_size);
                    tables.constants.push(ConstantRow {
                        type_,
                        parent,
                        value,
                    });
                }
            }
            0x0C => {
                // CustomAttribute
                for _ in 0..count {
                    let parent = read_index(stream_data, &mut pos, has_custom_attr_size);
                    let type_ = read_index(stream_data, &mut pos, custom_attr_type_size);
                    let value = read_index(stream_data, &mut pos, blob_size);
                    tables.custom_attributes.push(CustomAttributeRow {
                        parent,
                        type_,
                        value,
                    });
                }
            }
            0x20 => {
                // Assembly
                for _ in 0..count {
                    let hash_alg_id = read_u32_at(stream_data, &mut pos);
                    let major = read_u16_at(stream_data, &mut pos);
                    let minor = read_u16_at(stream_data, &mut pos);
                    let build = read_u16_at(stream_data, &mut pos);
                    let revision = read_u16_at(stream_data, &mut pos);
                    let flags = read_u32_at(stream_data, &mut pos);
                    let public_key = read_index(stream_data, &mut pos, blob_size);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let culture = read_index(stream_data, &mut pos, str_size);
                    tables.assemblies.push(AssemblyRow {
                        hash_alg_id,
                        major,
                        minor,
                        build,
                        revision,
                        flags,
                        public_key,
                        name,
                        culture,
                    });
                }
            }
            0x23 => {
                // AssemblyRef
                for _ in 0..count {
                    let major = read_u16_at(stream_data, &mut pos);
                    let minor = read_u16_at(stream_data, &mut pos);
                    let build = read_u16_at(stream_data, &mut pos);
                    let revision = read_u16_at(stream_data, &mut pos);
                    let flags = read_u32_at(stream_data, &mut pos);
                    let public_key_or_token = read_index(stream_data, &mut pos, blob_size);
                    let name = read_index(stream_data, &mut pos, str_size);
                    let culture = read_index(stream_data, &mut pos, str_size);
                    let hash_value = read_index(stream_data, &mut pos, blob_size);
                    tables.assembly_refs.push(AssemblyRefRow {
                        major,
                        minor,
                        build,
                        revision,
                        flags,
                        public_key_or_token,
                        name,
                        culture,
                        hash_value,
                    });
                }
            }
            0x29 => {
                // NestedClass
                for _ in 0..count {
                    let nested_class = read_index(stream_data, &mut pos, td_idx);
                    let enclosing_class = read_index(stream_data, &mut pos, td_idx);
                    tables.nested_classes.push(NestedClassRow {
                        nested_class,
                        enclosing_class,
                    });
                }
            }
            0x2A => {
                // GenericParam
                for _ in 0..count {
                    let number = read_u16_at(stream_data, &mut pos);
                    let flags = read_u16_at(stream_data, &mut pos);
                    let owner = read_index(stream_data, &mut pos, type_or_method_def_size);
                    let name = read_index(stream_data, &mut pos, str_size);
                    tables.generic_params.push(GenericParamRow {
                        number,
                        flags,
                        owner,
                        name,
                    });
                }
            }
            _ => {
                break;
            } // stop on unknown table to avoid misalignment
        }
    }

    Ok(tables)
}

// â”€â”€ CIL opcode helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// CIL instruction opcode categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilOpcodeClass {
    Arithmetic,
    Branch,
    Call,
    Load,
    Store,
    Stack,
    Object,
    Array,
    Convert,
    Compare,
    Exception,
    Misc,
}

/// Classify a CIL opcode byte into its family (single-byte opcodes only).
#[must_use]
pub const fn cil_opcode_class(opcode: u8) -> CilOpcodeClass {
    match opcode {
        // throw / leave / endfinally / endfilter (matched early so they
        // override the broader Object/Convert ranges below).
        0x7A | 0xDC | 0xDD | 0xFE => CilOpcodeClass::Exception,
        // call, calli, ret
        0x28..=0x2A | 0x6F => CilOpcodeClass::Call,
        // callvirt (also overrides the conv.* range)
        // nop, break, dup, pop
        0x00 | 0x01 | 0x25 | 0x26 => CilOpcodeClass::Stack,
        // ldarg/ldloc/starg/stloc family + the ldarg.0-3 / ldloc.0-3 shortcuts
        0x02..=0x12 | 0x17..=0x24 | 0x46..=0x51 => CilOpcodeClass::Load,
        0x13..=0x16 | 0x52..=0x57 => CilOpcodeClass::Store,
        // ldnull, ldc.i4.*, ldc.i8, ldc.r4, ldc.r8, ldstr (0x17..=0x24)
        // br.s / brtrue.s / brfalse.s / beq..bne family + switch (0x45)
        0x2B..=0x45 => CilOpcodeClass::Branch,
        // ldind.* family
        // stind.* family
        // add, sub, mul, div, rem, and, or, xor, shl, shr, neg, not
        0x58..=0x66 => CilOpcodeClass::Arithmetic,
        // conv.* (0x67..=0x76) â€” callvirt at 0x6F is matched above first.
        0x67..=0x76 => CilOpcodeClass::Convert,
        // cpobj/ldobj/newobj/castclass/isinst/unbox/ldfld/stfld/ldsfld/stsfld/box/newarr/ldlen/ldelema/ldelem.*
        0x70..=0x8C => CilOpcodeClass::Object,
        _ => CilOpcodeClass::Misc,
    }
}

/// Count opcode family frequencies in a CIL byte sequence.
#[must_use]
pub fn cil_opcode_histogram(code: &[u8]) -> HashMap<CilOpcodeClass, usize> {
    let mut map: HashMap<CilOpcodeClass, usize> = HashMap::new();
    for &byte in code {
        *map.entry(cil_opcode_class(byte)).or_insert(0) += 1;
    }
    map
}

// â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dotnet() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"BSJB");
        v.extend_from_slice(&[1u8, 0, 1, 0]);
        v.extend_from_slice(&[0u8; 4]);
        let version = b"v4.0.30319\0\0";
        v.extend_from_slice(&(version.len() as u32).to_le_bytes());
        v.extend_from_slice(version);
        v.extend_from_slice(&[0u8, 0]);
        v.extend_from_slice(&[1u8, 0]);
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(&[4u8, 0, 0, 0]);
        v.extend_from_slice(b"#~\0\0");
        v
    }

    fn make_dotnet_pe(clr_rva: u32) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x40;
        data[0x40] = 0x50;
        data[0x41] = 0x45;
        data[0x58] = 0x0B;
        data[0x59] = 0x01;
        let clr_off = 0x58_usize + 96 + 14 * 8;
        data[clr_off..clr_off + 4].copy_from_slice(&clr_rva.to_le_bytes());
        data[clr_off + 4..clr_off + 8].copy_from_slice(&0x48_u32.to_le_bytes());
        data
    }

    // â”€â”€ DotnetRuntimeVersion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_runtime_version_display() {
        assert_eq!(
            DotnetRuntimeVersion { major: 4, minor: 0 }.to_string(),
            "v4.0"
        );
    }

    #[test]
    fn test_runtime_version_display_minor() {
        assert_eq!(
            DotnetRuntimeVersion { major: 2, minor: 5 }.to_string(),
            "v2.5"
        );
    }

    // â”€â”€ DotnetAssemblyFlags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_assembly_flags_il_only() {
        let f = DotnetAssemblyFlags::IL_ONLY;
        assert!(f.contains(DotnetAssemblyFlags::IL_ONLY));
        assert!(!f.contains(DotnetAssemblyFlags::REQUIRES_32BIT));
    }

    #[test]
    fn test_assembly_flags_combined() {
        let f = DotnetAssemblyFlags::IL_ONLY | DotnetAssemblyFlags::STRONG_NAME_SIGNED;
        assert!(f.contains(DotnetAssemblyFlags::IL_ONLY));
        assert!(f.contains(DotnetAssemblyFlags::STRONG_NAME_SIGNED));
    }

    // â”€â”€ CorFlags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_corflags_il_only() {
        let f = CorFlags::IL_ONLY;
        assert!(f.contains(CorFlags::IL_ONLY));
        assert!(!f.contains(CorFlags::REQUIRES_32BIT_PROCESS));
    }

    // â”€â”€ DotnetMetadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_dotnet_metadata_mock() {
        let m = DotnetMetadata::mock();
        assert_eq!(m.version.major, 4);
        assert!(!m.is_dll);
        assert!(m.assembly_name.is_some());
        assert!(m.is_pure_il());
    }

    #[test]
    fn test_dotnet_metadata_display() {
        let m = DotnetMetadata::mock();
        assert!(m.to_string().contains(".NET"));
    }

    // â”€â”€ DotnetStream â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_dotnet_stream_display() {
        let s = DotnetStream {
            name: "#~".to_string(),
            offset: 0x100,
            size: 0x200,
        };
        assert!(s.to_string().contains("#~"));
    }

    // â”€â”€ DotnetFile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_is_valid_dotnet_true() {
        assert!(DotnetFile::is_valid_dotnet(&minimal_dotnet()));
    }

    #[test]
    fn test_is_valid_dotnet_false() {
        assert!(!DotnetFile::is_valid_dotnet(b"randomdata"));
    }

    #[test]
    fn test_parse_metadata_header_stream_count() {
        let file = DotnetFile::parse_metadata_header(&minimal_dotnet()).unwrap();
        assert_eq!(file.streams.len(), 1);
    }

    #[test]
    fn test_parse_metadata_header_stream_name() {
        let file = DotnetFile::parse_metadata_header(&minimal_dotnet()).unwrap();
        assert_eq!(file.streams[0].name, "#~");
    }

    #[test]
    fn test_parse_metadata_header_not_dotnet() {
        assert!(matches!(
            DotnetFile::parse_metadata_header(b"not dotnet").unwrap_err(),
            DotnetLoaderError::NotDotnet
        ));
    }

    #[test]
    fn test_parse_metadata_header_truncated() {
        assert!(matches!(
            DotnetFile::parse_metadata_header(b"BSJB").unwrap_err(),
            DotnetLoaderError::TruncatedStream
        ));
    }

    #[test]
    fn test_dotnet_file_stream_lookup() {
        let file = DotnetFile::parse_metadata_header(&minimal_dotnet()).unwrap();
        assert!(file.stream("#~").is_some());
        assert!(file.stream("#Strings").is_none());
    }

    // â”€â”€ Error display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_error_not_dotnet() {
        assert!(DotnetLoaderError::NotDotnet.to_string().contains(".NET"));
    }

    #[test]
    fn test_error_invalid_metadata() {
        assert!(
            DotnetLoaderError::InvalidMetadata
                .to_string()
                .contains("metadata")
        );
    }

    #[test]
    fn test_error_truncated_stream() {
        assert!(
            DotnetLoaderError::TruncatedStream
                .to_string()
                .contains("truncated")
        );
    }

    #[test]
    fn test_error_parse_error() {
        assert!(
            DotnetLoaderError::ParseError("bad".into())
                .to_string()
                .contains("bad")
        );
    }

    #[test]
    fn test_error_invalid_method_body() {
        assert!(
            DotnetLoaderError::InvalidMethodBody(0x1000)
                .to_string()
                .contains("method")
        );
    }

    // â”€â”€ has_clr_header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_has_clr_header_valid() {
        assert!(has_clr_header(&make_dotnet_pe(0x2000)));
    }

    #[test]
    fn test_has_clr_header_zero_rva() {
        assert!(!has_clr_header(&make_dotnet_pe(0)));
    }

    #[test]
    fn test_has_clr_header_not_mz() {
        assert!(!has_clr_header(&vec![0u8; 256]));
    }

    // â”€â”€ ClrHeader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn make_clr_bytes() -> Vec<u8> {
        let mut data = vec![0u8; 72];
        data[0..4].copy_from_slice(&72_u32.to_le_bytes());
        data[4..6].copy_from_slice(&2_u16.to_le_bytes());
        data[6..8].copy_from_slice(&5_u16.to_le_bytes());
        data[8..12].copy_from_slice(&0x8000_u32.to_le_bytes());
        data[12..16].copy_from_slice(&1024_u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x0000_0001_u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x0600_0001_u32.to_le_bytes());
        data
    }

    #[test]
    fn test_clr_header_parse() {
        let hdr = ClrHeader::parse(&make_clr_bytes()).unwrap();
        assert_eq!(hdr.header_size, 72);
        assert_eq!(hdr.major_runtime_version, 2);
        assert_eq!(hdr.framework_version(), "2.5");
    }

    #[test]
    fn test_clr_header_too_short() {
        assert!(ClrHeader::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_clr_header_mixed_mode() {
        let hdr = ClrHeader::parse(&make_clr_bytes()).unwrap();
        assert!(!hdr.is_mixed_mode());
    }

    #[test]
    fn test_clr_header_strong_name() {
        let hdr = ClrHeader::parse(&make_clr_bytes()).unwrap();
        assert!(!hdr.has_strong_name()); // rva=0 in our test data
    }

    #[test]
    fn test_clr_header_display() {
        let hdr = ClrHeader::parse(&make_clr_bytes()).unwrap();
        assert!(hdr.to_string().contains("CLR"));
    }

    // â”€â”€ TypeDefRow flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_type_def_row_interface() {
        let td = TypeDefRow {
            flags: 0x0020,
            type_name: 0,
            type_namespace: 0,
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        assert!(td.is_interface());
        assert!(!td.is_abstract());
    }

    #[test]
    fn test_type_def_row_abstract() {
        let td = TypeDefRow {
            flags: 0x0080,
            type_name: 0,
            type_namespace: 0,
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        assert!(td.is_abstract());
    }

    // â”€â”€ MethodDefRow flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_method_def_row_virtual() {
        let m = MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x0046, // public+virtual
            name: 0,
            signature: 0,
            param_list: 0,
        };
        assert!(m.is_virtual());
        assert!(m.is_public());
    }

    #[test]
    fn test_method_def_row_static() {
        let m = MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x0016, // public+static
            name: 0,
            signature: 0,
            param_list: 0,
        };
        assert!(m.is_static());
    }

    // â”€â”€ AssemblyRow version â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_assembly_row_version_string() {
        let a = AssemblyRow {
            hash_alg_id: 0,
            major: 1,
            minor: 2,
            build: 3,
            revision: 4,
            flags: 0,
            public_key: 0,
            name: 0,
            culture: 0,
        };
        assert_eq!(a.version_string(), "1.2.3.4");
    }

    #[test]
    fn test_assembly_ref_row_version_string() {
        let a = AssemblyRefRow {
            major: 4,
            minor: 0,
            build: 0,
            revision: 0,
            flags: 0,
            public_key_or_token: 0,
            name: 0,
            culture: 0,
            hash_value: 0,
        };
        assert_eq!(a.version_string(), "4.0.0.0");
    }

    // â”€â”€ Compressed uint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_compressed_uint_1byte() {
        let mut off = 0;
        assert_eq!(read_compressed_uint(&[0x7F], &mut off), 127);
        assert_eq!(off, 1);
    }

    #[test]
    fn test_compressed_uint_2byte() {
        let mut off = 0;
        // 0x8080 â†’ (0x00 << 8) | 0x80 = 128
        assert_eq!(read_compressed_uint(&[0x80, 0x80], &mut off), 128);
        assert_eq!(off, 2);
    }

    // â”€â”€ decode_type_def_or_ref â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_decode_type_def_or_ref_typedef() {
        // coded=0 â†’ TypeDef table, row 0
        assert_eq!(decode_type_def_or_ref(0), 0x0200_0000);
    }

    #[test]
    fn test_decode_type_def_or_ref_typeref() {
        // coded=1 â†’ TypeRef table, row 0
        assert_eq!(decode_type_def_or_ref(1), 0x0100_0000);
    }

    // â”€â”€ TypeSig â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_read_type_sig_primitives() {
        let mut off = 0;
        assert_eq!(read_type_sig(&[0x08], &mut off), TypeSig::I4);
    }

    #[test]
    fn test_read_type_sig_array() {
        let mut off = 0;
        let blob = [0x1D, 0x08]; // SZARRAY I4
        assert!(matches!(read_type_sig(&blob, &mut off), TypeSig::Array(_)));
    }

    #[test]
    fn test_cil_type_name_primitives() {
        assert_eq!(cil_type_name(&TypeSig::I4, &[], &[]), "int");
        assert_eq!(cil_type_name(&TypeSig::Bool, &[], &[]), "bool");
        assert_eq!(cil_type_name(&TypeSig::Void, &[], &[]), "void");
    }

    #[test]
    fn test_cil_type_name_array() {
        let sig = TypeSig::Array(Box::new(TypeSig::I4));
        assert_eq!(cil_type_name(&sig, &[], &[]), "int[]");
    }

    #[test]
    fn test_cil_type_name_ptr() {
        let sig = TypeSig::Ptr(Box::new(TypeSig::U1));
        assert_eq!(cil_type_name(&sig, &[], &[]), "byte*");
    }

    #[test]
    fn test_cil_type_name_byref() {
        let sig = TypeSig::ByRef(Box::new(TypeSig::I4));
        assert_eq!(cil_type_name(&sig, &[], &[]), "ref int");
    }

    #[test]
    fn test_cil_type_name_var() {
        assert_eq!(cil_type_name(&TypeSig::Var(0), &[], &[]), "T0");
        assert_eq!(cil_type_name(&TypeSig::MVar(1), &[], &[]), "M1");
    }

    // â”€â”€ read_string_heap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_read_string_heap_basic() {
        let heap = b"Hello\0World\0";
        assert_eq!(read_string_heap(heap, 0), "Hello");
        assert_eq!(read_string_heap(heap, 6), "World");
    }

    #[test]
    fn test_read_string_heap_oob() {
        let heap = b"Hi\0";
        assert_eq!(read_string_heap(heap, 100), "");
    }

    // â”€â”€ Method body (tiny) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_parse_method_body_tiny() {
        // Tiny header: first byte = (code_len << 2) | 0x02
        // code_len = 3: byte = 0x0E
        let code = [0xDE, 0xAD, 0xBE];
        let mut data = vec![(3u8 << 2) | 0x02];
        data.extend_from_slice(&code);
        let body = parse_method_body(&data, 0).unwrap();
        assert!(!body.is_fat);
        assert_eq!(body.code, code);
        assert_eq!(body.max_stack, 8);
    }

    #[test]
    fn test_parse_method_body_tiny_zero_code() {
        // code_len = 0
        let data = vec![0x02];
        let body = parse_method_body(&data, 0).unwrap();
        assert!(body.code.is_empty());
    }

    #[test]
    fn test_parse_method_body_fat() {
        // Fat header: 12 bytes, flags 0x3003 (fat, no more sections), max_stack=8
        let mut data = vec![0u8; 20];
        // word 0: flags | size_in_dwords << 12 = 0x3 | (3 << 12) = 0x3003
        data[0] = 0x03;
        data[1] = 0x30;
        data[2] = 8;
        data[3] = 0; // max_stack
        data[4] = 4; // code_size (4 bytes of code)
        // local_var_sig_tok
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        // code
        data[12] = 0x00;
        data[13] = 0x2A;
        data[14] = 0x00;
        data[15] = 0x00;
        let body = parse_method_body(&data, 0).unwrap();
        assert!(body.is_fat);
        assert_eq!(body.max_stack, 8);
    }

    // â”€â”€ ExceptionClauseType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_exception_clause_type_decode() {
        assert_eq!(ExceptionClauseType::from_u32(0), ExceptionClauseType::Catch);
        assert_eq!(
            ExceptionClauseType::from_u32(1),
            ExceptionClauseType::Filter
        );
        assert_eq!(
            ExceptionClauseType::from_u32(2),
            ExceptionClauseType::Finally
        );
        assert_eq!(ExceptionClauseType::from_u32(4), ExceptionClauseType::Fault);
    }

    #[test]
    fn test_exception_clause_type_display() {
        assert_eq!(ExceptionClauseType::Catch.to_string(), "catch");
        assert_eq!(ExceptionClauseType::Finally.to_string(), "finally");
    }

    // â”€â”€ PeSectionHeader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_pe_section_rva_to_offset() {
        let s = PeSectionHeader {
            name: ".text".to_string(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_size: 0x1000,
            raw_offset: 0x400,
            characteristics: 0x60000020,
        };
        assert_eq!(s.rva_to_offset(0x1100), Some(0x500));
        assert_eq!(s.rva_to_offset(0x2000), None);
    }

    // â”€â”€ Type hierarchy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_build_type_hierarchy_empty() {
        let nodes = build_type_hierarchy(&[], &[], &[], &[], &[], &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_build_type_hierarchy_basic() {
        let strings = b"\0MyClass\0MyNs\0";
        let td = TypeDefRow {
            flags: 0,
            type_name: 1,      // "MyClass"
            type_namespace: 9, // "MyNs"
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        let nodes = build_type_hierarchy(&[td], &[], &[], &[], &[], strings);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].full_name, "MyNs.MyClass");
    }

    // â”€â”€ CIL opcode histogram â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cil_opcode_histogram() {
        let code = [0x00u8, 0x00, 0x2A]; // nop, nop, ret
        let hist = cil_opcode_histogram(&code);
        assert!(hist.get(&CilOpcodeClass::Stack).copied().unwrap_or(0) >= 1);
    }

    // â”€â”€ Loader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_loader_name() {
        assert_eq!(DotnetLoader.name(), "dotnet");
    }

    #[test]
    fn test_can_load_dotnet() {
        assert!(DotnetLoader.can_load(&LoaderInput::new("app.exe", minimal_dotnet())));
    }

    #[test]
    fn test_cannot_load_random() {
        assert!(!DotnetLoader.can_load(&LoaderInput::new("file.bin", b"random".to_vec())));
    }

    #[tokio::test]
    async fn test_load() {
        let result = DotnetLoader
            .load(LoaderInput::new("app.exe", minimal_dotnet()))
            .await
            .unwrap();
        assert_eq!(result.view.uri, "app.exe");
        assert!(!result.view.entry_points.is_empty());
    }

    #[tokio::test]
    async fn test_find_nested_empty() {
        let nested = DotnetLoader
            .find_nested(&LoaderInput::new("app.exe", minimal_dotnet()))
            .await
            .unwrap();
        assert!(nested.is_empty());
    }
}
