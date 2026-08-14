//! `dotnet_method_loader` — Load and decode .NET method bodies from PE/CIL binaries (batch layer).
//!
//! This module provides [`DotnetMethodLoader`], which locates method bodies by RVA,
//! parses fat and tiny CIL headers, decodes local variable signatures from the
//! `#Blob` heap, and collects structured [`MethodBody`] records for all methods in
//! a `MethodDef` table.
//!
//! # Design note — relation to `il_method_loader`
//! [`il_method_loader`] is the **low-level / primary** layer re-exported from
//! `lib.rs` (`IlMethodLoader`, `IlError`, `IlInstruction`, …).  This module
//! (`dotnet_method_loader`) is the **high-level batch** layer: it adds
//! `LocalVarSig` blob decoding, serde-serialisable output, and drives loading
//! across an entire `MethodDef` table via `DotnetMethodLoader`.  Keep both
//! modules distinct.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    DotnetLoaderError, ExceptionClause, ExceptionClauseType, MethodDefRow, PeSectionHeader,
    TypeSig, read_compressed_uint, read_type_sig, rva_to_file_offset,
};

// ── LocalVar ─────────────────────────────────────────────────────────────────

/// A single local variable decoded from a `LocalVarSig` blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalVar {
    /// Zero-based index of this local variable.
    pub index: usize,
    /// Decoded type signature for this local.
    pub type_sig: TypeSig,
    /// Whether this local is `pinned` (`ELEMENT_TYPE_PINNED`).
    pub is_pinned: bool,
    /// Whether this local is passed by reference.
    pub is_byref: bool,
}

impl fmt::Display for LocalVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mods = match (self.is_pinned, self.is_byref) {
            (true, true) => "pinned ref ",
            (true, false) => "pinned ",
            (false, true) => "ref ",
            (false, false) => "",
        };
        write!(f, "[{}] {}{:?}", self.index, mods, self.type_sig)
    }
}

// ── LocalVarSig ──────────────────────────────────────────────────────────────

/// Decoded `LocalVarSig` blob (ECMA-335 §II.23.2.6).
///
/// Contains all local variables declared for a single method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVarSig {
    /// Metadata token of the `StandAloneSig` row referencing this blob.
    pub token: u32,
    /// All local variables, in declaration order.
    pub locals: Vec<LocalVar>,
}

impl LocalVarSig {
    /// Parse a `LocalVarSig` from a blob slice.
    ///
    /// The blob must start with `0x07` (`LOCAL_SIG` calling convention).
    ///
    /// # Errors
    ///
    /// Returns [`DotnetLoaderError::ParseError`] if the leading byte is wrong or
    /// the blob is truncated.
    pub fn parse(blob: &[u8], token: u32) -> Result<Self, DotnetLoaderError> {
        if blob.is_empty() {
            return Err(DotnetLoaderError::ParseError(
                "LocalVarSig: empty blob".into(),
            ));
        }
        if blob[0] != 0x07 {
            return Err(DotnetLoaderError::ParseError(format!(
                "LocalVarSig: expected LOCAL_SIG (0x07), got {:#04x}",
                blob[0]
            )));
        }
        let mut offset = 1usize;
        let count = read_compressed_uint(blob, &mut offset) as usize;
        // Cap pre-allocation: each local consumes >= 1 byte of the blob.
        let mut locals = Vec::with_capacity(count.min(blob.len().saturating_sub(offset)));

        for idx in 0..count {
            // Stop at EOF: read_type_sig returns Unknown without consuming,
            // so a bogus claimed count would otherwise push `count` entries.
            if offset >= blob.len() {
                break;
            }
            // Check for ELEMENT_TYPE_PINNED (0x45) or ELEMENT_TYPE_BYREF (0x10) modifiers.
            let mut is_pinned = false;
            let mut is_byref = false;

            loop {
                if offset >= blob.len() {
                    break;
                }
                match blob[offset] {
                    0x45 => {
                        is_pinned = true;
                        offset += 1;
                    }
                    0x10 => {
                        is_byref = true;
                        offset += 1;
                    }
                    _ => break,
                }
            }

            let type_sig = read_type_sig(blob, &mut offset);
            locals.push(LocalVar {
                index: idx,
                type_sig,
                is_pinned,
                is_byref,
            });
        }

        Ok(Self { token, locals })
    }

    /// Number of local variables.
    #[must_use]
    pub const fn local_count(&self) -> usize {
        self.locals.len()
    }

    /// True when this method has no local variables.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.locals.is_empty()
    }
}

// ── MethodHeader ─────────────────────────────────────────────────────────────

/// Discriminates between the two CIL method body header formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodHeader {
    /// Tiny format: 1-byte header, code length in bits 7:2.
    Tiny {
        /// Number of CIL bytes in the method body.
        code_size: u8,
    },
    /// Fat format: 12-byte header.
    Fat {
        /// Flags and header-size field (bits 15:12 = header size in dwords).
        flags: u16,
        /// Maximum evaluation stack depth.
        max_stack: u16,
        /// Number of CIL bytes in the method body.
        code_size: u32,
        /// Metadata token of the local variable signature (0 = no locals).
        local_var_sig_tok: u32,
    },
}

impl MethodHeader {
    /// Size of this header in bytes.
    #[must_use]
    pub const fn header_size_bytes(&self) -> usize {
        match self {
            Self::Tiny { .. } => 1,
            Self::Fat { flags, .. } => {
                let hdr_dwords = (*flags >> 12) & 0xF;
                (hdr_dwords as usize) * 4
            }
        }
    }

    /// True if the `MoreSects` flag is set (fat header only).
    #[must_use]
    pub const fn has_more_sections(&self) -> bool {
        match self {
            Self::Tiny { .. } => false,
            Self::Fat { flags, .. } => (*flags & 0x08) != 0,
        }
    }

    /// Local var sig token (fat header only; 0 for tiny).
    #[must_use]
    pub const fn local_var_sig_tok(&self) -> u32 {
        match self {
            Self::Tiny { .. } => 0,
            Self::Fat {
                local_var_sig_tok, ..
            } => *local_var_sig_tok,
        }
    }

    /// Maximum evaluation stack depth.
    #[must_use]
    pub const fn max_stack(&self) -> u16 {
        match self {
            Self::Tiny { .. } => 8,
            Self::Fat { max_stack, .. } => *max_stack,
        }
    }

    /// CIL code size in bytes.
    #[must_use]
    pub const fn code_size(&self) -> usize {
        match self {
            Self::Tiny { code_size } => *code_size as usize,
            Self::Fat { code_size, .. } => *code_size as usize,
        }
    }
}

// ── MethodBody ───────────────────────────────────────────────────────────────

/// A fully-decoded CIL method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodBody {
    /// Index into the `MethodDef` table (0-based).
    pub method_def_idx: usize,
    /// Name of the method (from the `#Strings` heap).
    pub name: String,
    /// Parsed method header.
    pub header: MethodHeader,
    /// Raw CIL instruction bytes.
    pub code: Vec<u8>,
    /// Decoded local variable signature, if any.
    pub locals: Option<LocalVarSig>,
    /// Exception handler clauses.
    pub exception_handlers: Vec<ExceptionClause>,
    /// RVA of the method body in the original PE file.
    pub rva: u32,
}

impl MethodBody {
    /// Number of CIL bytes.
    #[must_use]
    pub const fn code_size(&self) -> usize {
        self.code.len()
    }

    /// Maximum evaluation stack depth.
    #[must_use]
    pub const fn max_stack(&self) -> u16 {
        self.header.max_stack()
    }

    /// True when the method has local variables.
    #[must_use]
    pub fn has_locals(&self) -> bool {
        self.locals.as_ref().is_some_and(|l| !l.is_empty())
    }

    /// Number of local variables.
    #[must_use]
    pub fn local_count(&self) -> usize {
        self.locals.as_ref().map_or(0, LocalVarSig::local_count)
    }

    /// True when the method has exception handlers.
    #[must_use]
    pub const fn has_exception_handlers(&self) -> bool {
        !self.exception_handlers.is_empty()
    }

    /// Number of exception handler clauses.
    #[must_use]
    pub const fn exception_handler_count(&self) -> usize {
        self.exception_handlers.len()
    }

    /// Whether the method is a constructor (`<init>` or `<clinit>`).
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == ".ctor" || self.name == ".cctor"
    }
}

impl fmt::Display for MethodBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "method[{}] {} rva={:#x} code={} locals={} handlers={}",
            self.method_def_idx,
            self.name,
            self.rva,
            self.code.len(),
            self.local_count(),
            self.exception_handler_count(),
        )
    }
}

// ── LoadMethodConfig ─────────────────────────────────────────────────────────

/// Configuration for [`DotnetMethodLoader`].
#[derive(Debug, Clone)]
pub struct LoadMethodConfig {
    /// Whether to decode local variable signatures.
    pub decode_locals: bool,
    /// Whether to decode exception handlers.
    pub decode_exceptions: bool,
    /// Skip methods with RVA == 0 (abstract / extern / runtime-managed).
    pub skip_zero_rva: bool,
    /// Maximum allowed code size in bytes (sanity guard).
    pub max_code_size: usize,
}

impl Default for LoadMethodConfig {
    fn default() -> Self {
        Self {
            decode_locals: true,
            decode_exceptions: true,
            skip_zero_rva: true,
            max_code_size: 1024 * 1024, // 1 MiB
        }
    }
}

// ── DotnetMethodLoader ───────────────────────────────────────────────────────

/// Loads and decodes .NET method bodies from a PE file image.
///
/// Given the raw PE bytes, a list of parsed section headers, the `MethodDef`
/// table rows, and the `#Strings` / `#Blob` heap slices, the loader walks
/// every `MethodDef` row with a non-zero RVA, resolves it to a file offset
/// via the section headers, and decodes the CIL method header + body.
pub struct DotnetMethodLoader<'a> {
    /// Raw PE file bytes.
    data: &'a [u8],
    /// Parsed PE section headers for RVA → file-offset resolution.
    sections: &'a [PeSectionHeader],
    /// `#Strings` heap slice.
    strings_heap: &'a [u8],
    /// `#Blob` heap slice.
    blob_heap: &'a [u8],
    /// Loader configuration.
    config: LoadMethodConfig,
    /// Cache of decoded `LocalVarSig` blobs, keyed by blob heap offset.
    local_var_cache: HashMap<u32, LocalVarSig>,
}

impl<'a> DotnetMethodLoader<'a> {
    /// Create a new loader with default configuration.
    #[must_use]
    pub fn new(
        data: &'a [u8],
        sections: &'a [PeSectionHeader],
        strings_heap: &'a [u8],
        blob_heap: &'a [u8],
    ) -> Self {
        Self {
            data,
            sections,
            strings_heap,
            blob_heap,
            config: LoadMethodConfig::default(),
            local_var_cache: HashMap::new(),
        }
    }

    /// Apply custom configuration.
    #[must_use]
    pub const fn with_config(mut self, config: LoadMethodConfig) -> Self {
        self.config = config;
        self
    }

    /// Load a single method body for the `MethodDef` row at `method_def_idx`.
    ///
    /// Returns `None` when `skip_zero_rva` is set and the RVA is 0.
    ///
    /// # Errors
    ///
    /// Returns [`DotnetLoaderError`] for malformed headers or out-of-bounds data.
    pub fn load_method_body(
        &mut self,
        method_def_idx: usize,
        row: &MethodDefRow,
    ) -> Result<Option<MethodBody>, DotnetLoaderError> {
        if row.rva == 0 {
            if self.config.skip_zero_rva {
                return Ok(None);
            }
            return Err(DotnetLoaderError::InvalidMethodBody(0));
        }

        let file_offset = rva_to_file_offset(row.rva, self.sections)
            .ok_or(DotnetLoaderError::UnresolvableRva(row.rva))?;

        if file_offset >= self.data.len() {
            return Err(DotnetLoaderError::UnresolvableRva(row.rva));
        }

        let method_data = &self.data[file_offset..];
        let header = Self::parse_header(method_data, row.rva)?;

        let header_bytes = header.header_size_bytes().max(1);
        let code_size = header.code_size();

        if code_size > self.config.max_code_size {
            return Err(DotnetLoaderError::ParseError(format!(
                "method body at RVA {:#x} claims code_size={code_size} which exceeds limit",
                row.rva
            )));
        }

        let code_start = header_bytes;
        let code_end = code_start + code_size;
        if code_end > method_data.len() {
            return Err(DotnetLoaderError::TruncatedStream);
        }
        let code = method_data[code_start..code_end].to_vec();

        // Decode exception handlers if requested and present.
        let exception_handlers = if self.config.decode_exceptions && header.has_more_sections() {
            let sect_base = (code_start + code_size + 3) & !3;
            self.parse_exception_sections(method_data, sect_base)
        } else {
            Vec::new()
        };

        // Decode local variable signature.
        let locals = if self.config.decode_locals {
            let sig_tok = header.local_var_sig_tok();
            if sig_tok != 0 {
                let blob_idx = sig_tok & 0x00FF_FFFF;
                Some(self.decode_local_var_sig(blob_idx, sig_tok)?)
            } else {
                None
            }
        } else {
            None
        };

        let name = Self::read_string(self.strings_heap, row.name);

        Ok(Some(MethodBody {
            method_def_idx,
            name,
            header,
            code,
            locals,
            exception_handlers,
            rva: row.rva,
        }))
    }

    /// Load all method bodies from a `MethodDef` table slice.
    ///
    /// Methods with RVA == 0 are silently skipped when `skip_zero_rva` is set.
    /// Individual decode errors are collected into the returned error list rather
    /// than aborting the whole scan.
    pub fn load_all(
        &mut self,
        method_defs: &[MethodDefRow],
    ) -> (Vec<MethodBody>, Vec<(usize, DotnetLoaderError)>) {
        let mut bodies = Vec::new();
        let mut errors = Vec::new();

        for (idx, row) in method_defs.iter().enumerate() {
            match self.load_method_body(idx, row) {
                Ok(Some(body)) => bodies.push(body),
                Ok(None) => {}
                Err(e) => errors.push((idx, e)),
            }
        }

        (bodies, errors)
    }

    /// Parse the method header from the raw bytes at the start of the method body.
    fn parse_header(data: &[u8], rva: u32) -> Result<MethodHeader, DotnetLoaderError> {
        if data.is_empty() {
            return Err(DotnetLoaderError::InvalidMethodBody(rva));
        }
        let first = data[0];

        // Tiny header: bits [1:0] == 0b10
        if (first & 0x03) == 0x02 {
            let code_size = first >> 2;
            return Ok(MethodHeader::Tiny { code_size });
        }

        // Fat header: bits [1:0] == 0b11
        if data.len() < 12 {
            return Err(DotnetLoaderError::TruncatedStream);
        }
        let flags = u16::from_le_bytes([data[0], data[1]]);
        if (flags & 0x03) != 0x03 {
            return Err(DotnetLoaderError::InvalidMethodBody(rva));
        }
        let max_stack = u16::from_le_bytes([data[2], data[3]]);
        let code_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let local_var_sig_tok = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Ok(MethodHeader::Fat {
            flags,
            max_stack,
            code_size,
            local_var_sig_tok,
        })
    }

    /// Decode the `LocalVarSig` blob at `blob_idx` in the `#Blob` heap.
    ///
    /// Results are cached by blob index to avoid redundant decoding.
    fn decode_local_var_sig(
        &mut self,
        blob_idx: u32,
        token: u32,
    ) -> Result<LocalVarSig, DotnetLoaderError> {
        if let Some(cached) = self.local_var_cache.get(&blob_idx) {
            return Ok(cached.clone());
        }

        let blob_data = Self::read_blob_heap(self.blob_heap, blob_idx)?;
        let sig = LocalVarSig::parse(blob_data, token)?;
        self.local_var_cache.insert(blob_idx, sig.clone());
        Ok(sig)
    }

    /// Read a length-prefixed blob from the `#Blob` heap at `idx`.
    fn read_blob_heap(heap: &[u8], idx: u32) -> Result<&[u8], DotnetLoaderError> {
        let start = idx as usize;
        if start >= heap.len() {
            return Err(DotnetLoaderError::ParseError(format!(
                "blob heap idx {idx:#x} out of range (heap size {})",
                heap.len()
            )));
        }
        // Length is stored as a compressed unsigned integer.
        let mut pos = start;
        let len = {
            let b0 = heap[pos];
            if b0 & 0x80 == 0 {
                pos += 1;
                b0 as usize
            } else if b0 & 0xC0 == 0x80 {
                if pos + 2 > heap.len() {
                    return Err(DotnetLoaderError::TruncatedStream);
                }
                let v = ((b0 & 0x3F) as usize) << 8 | heap[pos + 1] as usize;
                pos += 2;
                v
            } else {
                if pos + 4 > heap.len() {
                    return Err(DotnetLoaderError::TruncatedStream);
                }
                let v = ((b0 & 0x1F) as usize) << 24
                    | (heap[pos + 1] as usize) << 16
                    | (heap[pos + 2] as usize) << 8
                    | heap[pos + 3] as usize;
                pos += 4;
                v
            }
        };
        let end = pos + len;
        if end > heap.len() {
            return Err(DotnetLoaderError::TruncatedStream);
        }
        Ok(&heap[pos..end])
    }

    /// Read a NUL-terminated string from the strings heap.
    fn read_string(heap: &[u8], idx: u32) -> String {
        let start = idx as usize;
        if start >= heap.len() {
            return String::new();
        }
        let end = heap[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(heap.len(), |p| start + p);
        String::from_utf8_lossy(&heap[start..end]).into_owned()
    }

    /// Parse exception handler sections from the method data starting at `offset`.
    fn parse_exception_sections(
        &self,
        method_data: &[u8],
        mut offset: usize,
    ) -> Vec<ExceptionClause> {
        let mut clauses = Vec::new();
        loop {
            if offset + 4 > method_data.len() {
                break;
            }
            let sect_kind = method_data[offset];
            let is_fat_sect = (sect_kind & 0x40) != 0;
            let has_more = (sect_kind & 0x80) != 0;

            if is_fat_sect {
                if offset + 4 > method_data.len() {
                    break;
                }
                let data_size = u32::from_le_bytes([
                    method_data[offset + 1],
                    method_data[offset + 2],
                    method_data[offset + 3],
                    0,
                ]) as usize
                    & 0x00FF_FFFF;
                offset += 4;
                let num_clauses = data_size.saturating_sub(4) / 24;
                for _ in 0..num_clauses {
                    if offset + 24 > method_data.len() {
                        break;
                    }
                    let flags = u32::from_le_bytes(
                        method_data[offset..offset + 4].try_into().unwrap_or([0; 4]),
                    );
                    let try_offset = u32::from_le_bytes(
                        method_data[offset + 4..offset + 8]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let try_length = u32::from_le_bytes(
                        method_data[offset + 8..offset + 12]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let handler_offset = u32::from_le_bytes(
                        method_data[offset + 12..offset + 16]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let handler_length = u32::from_le_bytes(
                        method_data[offset + 16..offset + 20]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let class_or_filter = u32::from_le_bytes(
                        method_data[offset + 20..offset + 24]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
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
                if offset + 4 > method_data.len() {
                    break;
                }
                let data_size = method_data[offset + 1] as usize;
                offset += 4;
                let num_clauses = data_size.saturating_sub(4) / 12;
                for _ in 0..num_clauses {
                    if offset + 12 > method_data.len() {
                        break;
                    }
                    let flags =
                        u32::from(u16::from_le_bytes([method_data[offset], method_data[offset + 1]]));
                    let try_offset =
                        u32::from(u16::from_le_bytes([method_data[offset + 2], method_data[offset + 3]]));
                    let try_length = u32::from(method_data[offset + 4]);
                    let handler_offset =
                        u32::from(u16::from_le_bytes([method_data[offset + 5], method_data[offset + 6]]));
                    let handler_length = u32::from(method_data[offset + 7]);
                    let class_or_filter = u32::from_le_bytes(
                        method_data[offset + 8..offset + 12]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
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
}

// ── load_method_body (free function) ─────────────────────────────────────────

/// Convenience free function: load a single method body by RVA from raw PE bytes.
///
/// This is the simplest entry point — it constructs a temporary
/// [`DotnetMethodLoader`] with default config and returns the decoded body.
///
/// # Errors
///
/// Returns [`DotnetLoaderError`] if the RVA is unresolvable or the header is
/// malformed.
pub fn load_method_body(
    data: &[u8],
    sections: &[PeSectionHeader],
    strings_heap: &[u8],
    blob_heap: &[u8],
    method_def_idx: usize,
    row: &MethodDefRow,
) -> Result<Option<MethodBody>, DotnetLoaderError> {
    let mut loader = DotnetMethodLoader::new(data, sections, strings_heap, blob_heap);
    loader.load_method_body(method_def_idx, row)
}

// ── MethodBodyStats ───────────────────────────────────────────────────────────

/// Aggregate statistics over a set of loaded method bodies.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MethodBodyStats {
    /// Total number of methods loaded.
    pub total_methods: usize,
    /// Methods with tiny headers.
    pub tiny_methods: usize,
    /// Methods with fat headers.
    pub fat_methods: usize,
    /// Total CIL bytes across all methods.
    pub total_code_bytes: usize,
    /// Largest single method code size.
    pub max_code_size: usize,
    /// Methods that have at least one local variable.
    pub methods_with_locals: usize,
    /// Methods that have at least one exception handler.
    pub methods_with_handlers: usize,
    /// Number of constructor methods (`.ctor` / `.cctor`).
    pub constructor_count: usize,
}

impl MethodBodyStats {
    /// Compute statistics from a slice of loaded method bodies.
    #[must_use]
    pub fn from_bodies(bodies: &[MethodBody]) -> Self {
        let mut stats = Self::default();
        stats.total_methods = bodies.len();
        for body in bodies {
            match body.header {
                MethodHeader::Tiny { .. } => stats.tiny_methods += 1,
                MethodHeader::Fat { .. } => stats.fat_methods += 1,
            }
            let csz = body.code_size();
            stats.total_code_bytes += csz;
            if csz > stats.max_code_size {
                stats.max_code_size = csz;
            }
            if body.has_locals() {
                stats.methods_with_locals += 1;
            }
            if body.has_exception_handlers() {
                stats.methods_with_handlers += 1;
            }
            if body.is_constructor() {
                stats.constructor_count += 1;
            }
        }
        stats
    }

    /// Average code size across all methods; 0.0 when there are no methods.
    #[must_use]
    pub fn avg_code_size(&self) -> f64 {
        if self.total_methods == 0 {
            0.0
        } else {
            self.total_code_bytes as f64 / self.total_methods as f64
        }
    }
}

impl fmt::Display for MethodBodyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MethodBodyStats: total={} tiny={} fat={} code_bytes={} max={} \
             with_locals={} with_handlers={} ctors={}",
            self.total_methods,
            self.tiny_methods,
            self.fat_methods,
            self.total_code_bytes,
            self.max_code_size,
            self.methods_with_locals,
            self.methods_with_handlers,
            self.constructor_count,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LocalVarSig parsing ──────────────────────────────────────────────────

    fn make_local_var_sig_blob(types: &[u8]) -> Vec<u8> {
        // 0x07 = LOCAL_SIG, compressed count, then type tags
        let count = types.len() as u8;
        let mut blob = vec![0x07, count];
        blob.extend_from_slice(types);
        blob
    }

    #[test]
    fn local_var_sig_empty() {
        let blob = vec![0x07, 0x00];
        let sig = LocalVarSig::parse(&blob, 0x1100_0001).unwrap();
        assert_eq!(sig.local_count(), 0);
        assert!(sig.is_empty());
        assert_eq!(sig.token, 0x1100_0001);
    }

    #[test]
    fn local_var_sig_one_int32() {
        // ELEMENT_TYPE_I4 = 0x08
        let blob = make_local_var_sig_blob(&[0x08]);
        let sig = LocalVarSig::parse(&blob, 1).unwrap();
        assert_eq!(sig.local_count(), 1);
        assert_eq!(sig.locals[0].type_sig, TypeSig::I4);
        assert!(!sig.locals[0].is_pinned);
        assert!(!sig.locals[0].is_byref);
    }

    #[test]
    fn local_var_sig_multiple_types() {
        // I4, I8, R4
        let blob = make_local_var_sig_blob(&[0x08, 0x0A, 0x0C]);
        let sig = LocalVarSig::parse(&blob, 2).unwrap();
        assert_eq!(sig.local_count(), 3);
        assert_eq!(sig.locals[0].type_sig, TypeSig::I4);
        assert_eq!(sig.locals[1].type_sig, TypeSig::I8);
        assert_eq!(sig.locals[2].type_sig, TypeSig::R4);
    }

    #[test]
    fn local_var_sig_wrong_leading_byte() {
        let blob = vec![0x06, 0x01, 0x08];
        assert!(LocalVarSig::parse(&blob, 0).is_err());
    }

    #[test]
    fn local_var_sig_empty_blob_errors() {
        assert!(LocalVarSig::parse(&[], 0).is_err());
    }

    #[test]
    fn local_var_sig_byref_flag() {
        // ELEMENT_TYPE_BYREF (0x10) prefix followed by ELEMENT_TYPE_I4
        let blob = vec![0x07, 0x01, 0x10, 0x08];
        let sig = LocalVarSig::parse(&blob, 0).unwrap();
        assert!(sig.locals[0].is_byref);
        assert_eq!(sig.locals[0].type_sig, TypeSig::I4);
    }

    #[test]
    fn local_var_sig_pinned_flag() {
        // ELEMENT_TYPE_PINNED (0x45) prefix followed by ELEMENT_TYPE_U1
        let blob = vec![0x07, 0x01, 0x45, 0x05];
        let sig = LocalVarSig::parse(&blob, 0).unwrap();
        assert!(sig.locals[0].is_pinned);
        assert_eq!(sig.locals[0].type_sig, TypeSig::U1);
    }

    // ── MethodHeader parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_tiny_header() {
        // Tiny: first byte bits [1:0] == 0b10
        // code_size = (byte >> 2) = 5
        let data = vec![0x16u8]; // 0x16 = 0b00010110 → code_size = 5
        let hdr = DotnetMethodLoader::parse_header(&data, 0x1000).unwrap();
        assert!(matches!(hdr, MethodHeader::Tiny { code_size: 5 }));
        assert_eq!(hdr.header_size_bytes(), 1);
        assert_eq!(hdr.code_size(), 5);
        assert!(!hdr.has_more_sections());
        assert_eq!(hdr.max_stack(), 8);
        assert_eq!(hdr.local_var_sig_tok(), 0);
    }

    #[test]
    fn parse_fat_header() {
        // Fat: bits [1:0] == 0b11, flags = 0x3013 (header_dwords=3, MoreSects=0)
        let mut data = vec![0u8; 12];
        let flags: u16 = 0x3003; // bits[1:0]=0b11, header_dwords=3
        data[0..2].copy_from_slice(&flags.to_le_bytes());
        data[2..4].copy_from_slice(&16u16.to_le_bytes()); // max_stack = 16
        data[4..8].copy_from_slice(&10u32.to_le_bytes()); // code_size = 10
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // local_var_sig_tok = 0
        let hdr = DotnetMethodLoader::parse_header(&data, 0x2000).unwrap();
        assert!(matches!(hdr, MethodHeader::Fat { max_stack: 16, code_size: 10, .. }));
        assert_eq!(hdr.code_size(), 10);
        assert_eq!(hdr.max_stack(), 16);
    }

    #[test]
    fn parse_fat_header_with_more_sects() {
        let mut data = vec![0u8; 12];
        let flags: u16 = 0x300B; // bits[1:0]=0b11, MoreSects flag (bit 3)
        data[0..2].copy_from_slice(&flags.to_le_bytes());
        data[4..8].copy_from_slice(&4u32.to_le_bytes());
        let hdr = DotnetMethodLoader::parse_header(&data, 0x3000).unwrap();
        assert!(hdr.has_more_sections());
    }

    #[test]
    fn parse_header_empty_errors() {
        let r = DotnetMethodLoader::parse_header(&[], 0x1000);
        assert!(r.is_err());
    }

    #[test]
    fn parse_header_invalid_first_byte_errors() {
        // bits [1:0] == 0b00 is not a valid header
        let data = vec![0x00u8; 12];
        let r = DotnetMethodLoader::parse_header(&data, 0x1000);
        assert!(r.is_err());
    }

    // ── MethodBody helpers ───────────────────────────────────────────────────

    fn make_tiny_body(name: &str, code: &[u8]) -> MethodBody {
        MethodBody {
            method_def_idx: 0,
            name: name.to_owned(),
            header: MethodHeader::Tiny {
                code_size: code.len() as u8,
            },
            code: code.to_vec(),
            locals: None,
            exception_handlers: Vec::new(),
            rva: 0x1000,
        }
    }

    #[test]
    fn method_body_code_size() {
        let body = make_tiny_body("myMethod", &[0x00, 0x2A]);
        assert_eq!(body.code_size(), 2);
    }

    #[test]
    fn method_body_max_stack_tiny() {
        let body = make_tiny_body("f", &[0x2A]);
        assert_eq!(body.max_stack(), 8);
    }

    #[test]
    fn method_body_has_no_locals_by_default() {
        let body = make_tiny_body("g", &[0x2A]);
        assert!(!body.has_locals());
        assert_eq!(body.local_count(), 0);
    }

    #[test]
    fn method_body_is_constructor_ctor() {
        let body = make_tiny_body(".ctor", &[0x2A]);
        assert!(body.is_constructor());
    }

    #[test]
    fn method_body_is_constructor_cctor() {
        let body = make_tiny_body(".cctor", &[0x2A]);
        assert!(body.is_constructor());
    }

    #[test]
    fn method_body_not_constructor() {
        let body = make_tiny_body("Dispose", &[0x2A]);
        assert!(!body.is_constructor());
    }

    #[test]
    fn method_body_display() {
        let body = make_tiny_body("ToString", &[0x00; 5]);
        let s = format!("{body}");
        assert!(s.contains("ToString"));
        assert!(s.contains("code=5"));
    }

    // ── MethodBodyStats ──────────────────────────────────────────────────────

    #[test]
    fn stats_empty() {
        let stats = MethodBodyStats::from_bodies(&[]);
        assert_eq!(stats.total_methods, 0);
        assert_eq!(stats.avg_code_size(), 0.0);
    }

    #[test]
    fn stats_single_body() {
        let body = make_tiny_body("f", &[0x00; 10]);
        let stats = MethodBodyStats::from_bodies(&[body]);
        assert_eq!(stats.total_methods, 1);
        assert_eq!(stats.tiny_methods, 1);
        assert_eq!(stats.total_code_bytes, 10);
        assert_eq!(stats.max_code_size, 10);
        assert_eq!(stats.avg_code_size(), 10.0);
    }

    #[test]
    fn stats_counts_constructors() {
        let b1 = make_tiny_body(".ctor", &[0x2A]);
        let b2 = make_tiny_body(".cctor", &[0x2A]);
        let b3 = make_tiny_body("Method", &[0x2A]);
        let stats = MethodBodyStats::from_bodies(&[b1, b2, b3]);
        assert_eq!(stats.constructor_count, 2);
    }

    #[test]
    fn stats_display() {
        let stats = MethodBodyStats::from_bodies(&[]);
        let s = format!("{stats}");
        assert!(s.contains("MethodBodyStats"));
        assert!(s.contains("total=0"));
    }

    #[test]
    fn local_var_display() {
        let lv = LocalVar {
            index: 2,
            type_sig: TypeSig::I4,
            is_pinned: false,
            is_byref: true,
        };
        let s = format!("{lv}");
        assert!(s.contains("[2]"));
        assert!(s.contains("ref"));
    }

    #[test]
    fn local_var_sig_display_token() {
        let blob = vec![0x07, 0x00];
        let sig = LocalVarSig::parse(&blob, 0xABCD).unwrap();
        assert_eq!(sig.token, 0xABCD);
    }

    #[test]
    fn method_header_fat_local_var_tok() {
        let mut data = vec![0u8; 12];
        let flags: u16 = 0x3003;
        data[0..2].copy_from_slice(&flags.to_le_bytes());
        data[8..12].copy_from_slice(&0x1100_0005u32.to_le_bytes());
        let hdr = DotnetMethodLoader::parse_header(&data, 0).unwrap();
        assert_eq!(hdr.local_var_sig_tok(), 0x1100_0005);
    }
}
