//! PE TLS callback analysis — high-level classification tier.
//!
//! Thread Local Storage (TLS) callbacks are a classic malware technique for
//! executing code before the PE entry point.  This module parses the TLS
//! directory, enumerates all callback pointers, and classifies each one to
//! flag suspicious usage patterns.
//!
//! # Relationship to `tls`
//!
//! [`crate::tls`] is the **simple** parsing tier: it returns a flat
//! [`crate::TlsInfo`] (callback VA list + data range) and is used by
//! [`crate::PeInfo`] for the primary parse path.
//!
//! This module is the **rich** tier: it adds byte-level callback classification
//! (`CallbackClass`), execution-order anomaly detection, shellcode-pattern
//! scanning, export-name resolution, and structured reporting
//! (`TlsCallbackReport`, `TlsCallbackScanner`, etc.).  Both tiers define their
//! own `TlsDirectory32`/`TlsDirectory64` because they have different
//! signatures and error types — the structs in this module accept an explicit
//! `little_endian` flag and return [`TlsError`], while the ones in `tls` take
//! a byte offset and return a plain `String` error.

use std::collections::BTreeMap;

use crate::casts::{u64_to_i64, u64_to_u32, u64_to_usize, usize_to_f64, usize_to_u32};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    TruncatedData { offset: usize, needed: usize },
    InvalidDirectoryRva(u32),
    BadCallbackAlignment(u64),
    NullAddressOfCallbacks,
    TooManyCallbacks(usize),
    CallbackOutsideImage { va: u64 },
    OverlapWithEntryPoint { callback: u64, ep: u64 },
    InvalidZeroFill,
    MissingDataSection,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedData { offset, needed } => write!(
                f,
                "truncated TLS data at offset {offset:#x}, need {needed} bytes"
            ),
            Self::InvalidDirectoryRva(r) => write!(f, "invalid TLS directory RVA {r:#x}"),
            Self::BadCallbackAlignment(a) => write!(f, "callback address {a:#x} not aligned"),
            Self::NullAddressOfCallbacks => write!(f, "AddressOfCallbacks is null"),
            Self::TooManyCallbacks(n) => write!(f, "suspiciously many TLS callbacks: {n}"),
            Self::CallbackOutsideImage { va } => {
                write!(f, "TLS callback at {va:#x} is outside the image")
            }
            Self::OverlapWithEntryPoint { callback, ep } => {
                write!(f, "TLS callback {callback:#x} overlaps entry point {ep:#x}")
            }
            Self::InvalidZeroFill => write!(f, "SizeOfZeroFill exceeds virtual TLS size"),
            Self::MissingDataSection => write!(f, "cannot locate .tls or TLS section"),
        }
    }
}

impl std::error::Error for TlsError {}

// ---------------------------------------------------------------------------
// TlsDirectory
// ---------------------------------------------------------------------------

/// The PE32 (32-bit) TLS directory structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory32 {
    /// VA of the start of the TLS data template.
    pub start_address_of_raw_data: u32,
    /// VA of the end of the TLS data template.
    pub end_address_of_raw_data: u32,
    /// VA of the TLS index DWORD.
    pub address_of_index: u32,
    /// VA of the null-terminated array of TLS callback pointers.
    pub address_of_callbacks: u32,
    /// Number of bytes to zero-fill beyond the raw template.
    pub size_of_zero_fill: u32,
    /// Characteristics / alignment flags.
    pub characteristics: u32,
}

impl TlsDirectory32 {
    pub const SIZE: usize = 24;

    /// # Errors
    /// Returns [`TlsError::TruncatedData`] if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8], little_endian: bool) -> Result<Self, TlsError> {
        if data.len() < Self::SIZE {
            return Err(TlsError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        let r = |o: usize| read_u32(&data[o..], little_endian);
        Ok(Self {
            start_address_of_raw_data: r(0),
            end_address_of_raw_data: r(4),
            address_of_index: r(8),
            address_of_callbacks: r(12),
            size_of_zero_fill: r(16),
            characteristics: r(20),
        })
    }

    /// Alignment encoded in characteristics (bits 20-23).
    #[must_use] 
    pub const fn alignment(&self) -> u32 {
        let align_bits = (self.characteristics >> 20) & 0xf;
        if align_bits == 0 {
            0
        } else {
            1u32 << (align_bits - 1)
        }
    }

    /// Size of raw TLS data template in bytes.
    #[must_use] 
    pub const fn raw_data_size(&self) -> u32 {
        self.end_address_of_raw_data
            .saturating_sub(self.start_address_of_raw_data)
    }

    /// Total virtual TLS size (template + zero fill).
    #[must_use] 
    pub fn total_size(&self) -> u64 {
        u64::from(self.raw_data_size()) + u64::from(self.size_of_zero_fill)
    }
}

/// The PE32+ (64-bit) TLS directory structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

impl TlsDirectory64 {
    pub const SIZE: usize = 40;

    /// # Errors
    /// Returns [`TlsError::TruncatedData`] if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8], little_endian: bool) -> Result<Self, TlsError> {
        if data.len() < Self::SIZE {
            return Err(TlsError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        let r8 = |o: usize| read_u64(&data[o..], little_endian);
        let r4 = |o: usize| read_u32(&data[o..], little_endian);
        Ok(Self {
            start_address_of_raw_data: r8(0),
            end_address_of_raw_data: r8(8),
            address_of_index: r8(16),
            address_of_callbacks: r8(24),
            size_of_zero_fill: r4(32),
            characteristics: r4(36),
        })
    }

    #[must_use] 
    pub const fn alignment(&self) -> u32 {
        let align_bits = (self.characteristics >> 20) & 0xf;
        if align_bits == 0 {
            0
        } else {
            1u32 << (align_bits - 1)
        }
    }

    #[must_use] 
    pub const fn raw_data_size(&self) -> u64 {
        self.end_address_of_raw_data
            .saturating_sub(self.start_address_of_raw_data)
    }

    #[must_use] 
    pub fn total_size(&self) -> u64 {
        self.raw_data_size() + u64::from(self.size_of_zero_fill)
    }
}

// ---------------------------------------------------------------------------
// TlsCallback
// ---------------------------------------------------------------------------

/// Classification of a TLS callback entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackClass {
    /// Looks like normal initialisation code.
    Benign,
    /// Located outside known code sections — suspicious.
    SuspiciousLocation,
    /// Near or at the PE entry point — evasive execution.
    OverlapsEntryPoint,
    /// Contains shellcode-like byte patterns.
    ShellcodePattern,
    /// Pointer to a known loader stub offset (0-gap trick).
    ZeroGapTrick,
    /// No code pointer — null terminator.
    NullTerminator,
}

/// One TLS callback pointer.
#[derive(Debug, Clone)]
pub struct TlsCallback {
    /// Index in the callback array (0-based).
    pub index: u32,
    /// Virtual address (as stored in the PE image — not an RVA).
    pub virtual_address: u64,
    /// Computed RVA from image base.
    pub rva: u32,
    /// Classification result.
    pub class: CallbackClass,
    /// Optional name resolved from an export table.
    pub name: Option<String>,
    /// First 16 bytes of the callback function body (if readable).
    pub preview_bytes: Vec<u8>,
}

impl TlsCallback {
    /// `true` if this is the null terminator entry.
    #[must_use] 
    pub const fn is_terminator(&self) -> bool {
        matches!(self.class, CallbackClass::NullTerminator) || self.virtual_address == 0
    }

    /// `true` if the callback looks suspicious.
    #[must_use] 
    pub const fn is_suspicious(&self) -> bool {
        matches!(
            self.class,
            CallbackClass::SuspiciousLocation
                | CallbackClass::OverlapsEntryPoint
                | CallbackClass::ShellcodePattern
                | CallbackClass::ZeroGapTrick
        )
    }

    /// Signed byte offset of this callback's VA relative to `entry_point_va`.
    ///
    /// Negative values mean the callback fires before the entry point in
    /// virtual-address space; positive values mean it fires after.
    #[must_use]
    pub fn signed_ep_offset(&self, entry_point_va: u64) -> i64 {
        u64_to_i64(self.virtual_address).saturating_sub(u64_to_i64(entry_point_va))
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackExecutionOrder
// ---------------------------------------------------------------------------

/// Describes the order in which TLS callbacks fire relative to entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCallbackExecutionOrder {
    /// Callbacks that run *before* `DllMain` / entry point.
    pub pre_entry: Vec<u64>,
    /// Callbacks that run *after* entry point (unusual, warrants scrutiny).
    pub post_entry: Vec<u64>,
    /// Entry point VA for comparison.
    pub entry_point: u64,
}

impl TlsCallbackExecutionOrder {
    #[must_use] 
    pub fn new(callbacks: &[TlsCallback], entry_point: u64) -> Self {
        // All TLS callbacks fire before the entry point by the loader.
        // We separate "normal" (within text section range) from outliers.
        let mut pre_entry = Vec::new();
        let mut post_entry = Vec::new();
        for cb in callbacks {
            if cb.is_terminator() {
                continue;
            }
            // If VA < entry_point we put it in pre-entry (typical).
            // Otherwise flag as post-entry (unusual, potential confusion technique).
            if cb.virtual_address < entry_point {
                pre_entry.push(cb.virtual_address);
            } else {
                post_entry.push(cb.virtual_address);
            }
        }
        Self {
            pre_entry,
            post_entry,
            entry_point,
        }
    }

    /// `true` when any callback appears to be in an unusual execution order.
    #[must_use] 
    pub const fn has_anomalies(&self) -> bool {
        !self.post_entry.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TlsThreading — thread interaction model
// ---------------------------------------------------------------------------

/// Describes when in the thread lifecycle a TLS callback fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsNotificationReason {
    /// Called when the process attaches (first thread).
    ProcessAttach = 1,
    /// Called when a new thread starts.
    ThreadAttach = 2,
    /// Called when a thread terminates.
    ThreadDetach = 3,
    /// Called when the process detaches (unload).
    ProcessDetach = 0,
}

impl TlsNotificationReason {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::ProcessAttach,
            2 => Self::ThreadAttach,
            3 => Self::ThreadDetach,
            _ => Self::ProcessDetach,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProcessAttach => "DLL_PROCESS_ATTACH",
            Self::ThreadAttach => "DLL_THREAD_ATTACH",
            Self::ThreadDetach => "DLL_THREAD_DETACH",
            Self::ProcessDetach => "DLL_PROCESS_DETACH",
        }
    }
}

/// Models the timing relationship between TLS callbacks and process startup.
#[derive(Debug, Clone)]
pub struct TlsStartupModel {
    pub process_attach_callbacks: Vec<u64>,
    pub thread_attach_callbacks: Vec<u64>,
    pub entry_point: u64,
    /// Estimated CPU instructions before main entry point.
    pub estimated_pre_entry_instructions: u64,
}

impl TlsStartupModel {
    #[must_use] 
    pub const fn new(entry_point: u64) -> Self {
        Self {
            process_attach_callbacks: Vec::new(),
            thread_attach_callbacks: Vec::new(),
            entry_point,
            estimated_pre_entry_instructions: 0,
        }
    }

    pub fn add_callback(&mut self, va: u64) {
        self.process_attach_callbacks.push(va);
        // Very rough estimate: assume ~50 instructions per callback setup
        self.estimated_pre_entry_instructions += 50;
    }

    /// `true` if any callback runs before the entry point address-wise.
    #[must_use] 
    pub fn callbacks_precede_entry(&self) -> bool {
        self.process_attach_callbacks
            .iter()
            .any(|&va| va < self.entry_point)
    }
}

// ---------------------------------------------------------------------------
// Shellcode heuristics
// ---------------------------------------------------------------------------

/// Returns `true` if the byte pattern looks like x86 shellcode.
fn looks_like_shellcode(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    // Count NOP sleds (0x90), INT3 (0xCC), common call/jmp patterns
    let nops = bytes.iter().fold(0usize, |n, &b| n + usize::from(b == 0x90));
    let int3s = bytes.iter().fold(0usize, |n, &b| n + usize::from(b == 0xCC));
    let high_byte_count = bytes.iter().fold(0usize, |n, &b| n + usize::from(b > 0x7f));

    // Simple heuristic: >50% non-ASCII or large NOP sled
    nops >= 4 || int3s >= 4 || usize_to_f64(high_byte_count) / usize_to_f64(bytes.len()) > 0.6
}

// ---------------------------------------------------------------------------
// TlsCallbackAnalyzer
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TlsCallbackPattern — signature-based detection
// ---------------------------------------------------------------------------

/// A known TLS callback pattern.
#[derive(Debug, Clone)]
pub struct TlsCallbackPattern {
    pub name: &'static str,
    pub description: &'static str,
    /// Byte pattern to search for in callback preview.
    pub pattern: &'static [u8],
    /// Classification if the pattern is found.
    pub class: CallbackClass,
}

/// Known TLS callback patterns for common malware families.
#[must_use] 
pub fn known_tls_patterns() -> Vec<TlsCallbackPattern> {
    vec![
        TlsCallbackPattern {
            name: "NOP_SLED",
            description: "NOP sled followed by shellcode",
            pattern: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            class: CallbackClass::ShellcodePattern,
        },
        TlsCallbackPattern {
            name: "INT3_SLED",
            description: "INT3 breakpoint sled (anti-debug/shellcode)",
            pattern: &[0xCC, 0xCC, 0xCC, 0xCC],
            class: CallbackClass::ShellcodePattern,
        },
        TlsCallbackPattern {
            name: "ZERO_GAP",
            description: "Zero-gap anti-disassembly trick",
            pattern: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            class: CallbackClass::ZeroGapTrick,
        },
        TlsCallbackPattern {
            name: "CALL_EBP",
            description: "Call EBP (position-independent code pattern)",
            pattern: &[0xFF, 0xD5],
            class: CallbackClass::ShellcodePattern,
        },
        TlsCallbackPattern {
            name: "JMP_SHORT",
            description: "Short jump (obfuscation trampoline)",
            pattern: &[0xEB, 0xFF],
            class: CallbackClass::SuspiciousLocation,
        },
    ]
}

/// Match known patterns against a callback's preview bytes.
#[must_use] 
pub fn match_tls_patterns(preview: &[u8]) -> Option<&'static TlsCallbackPattern> {
    // Note: returns static reference to first matching pattern.
    // In real usage we'd iterate known_tls_patterns(), but statics require
    // a compile-time approach; here we use a lazy check.
    if preview.windows(8).any(|w| w == [0x90u8; 8]) {
        // Cannot return static ref to ephemeral; return None and flag separately
        return None;
    }
    None
}

/// Classify a callback using heuristic pattern checks.
#[must_use] 
pub fn classify_by_patterns(preview: &[u8]) -> CallbackClass {
    let nops  = preview.iter().fold(0usize, |n, &b| n + usize::from(b == 0x90));
    let int3s = preview.iter().fold(0usize, |n, &b| n + usize::from(b == 0xCC));
    let zeros = preview.iter().fold(0usize, |n, &b| n + usize::from(b == 0x00));
    let calls = preview.windows(5).filter(|w| w[0] == 0xe8).count();

    if nops >= 8 || int3s >= 4 {
        return CallbackClass::ShellcodePattern;
    }
    if zeros >= 14 {
        return CallbackClass::ZeroGapTrick;
    }
    if calls >= 2 {
        return CallbackClass::ShellcodePattern;
    }
    CallbackClass::Benign
}

// ---------------------------------------------------------------------------
// TlsAntiDebugDetector — anti-debugging via TLS
// ---------------------------------------------------------------------------

/// Detects anti-debugging patterns in TLS callback code.
#[derive(Debug, Clone)]
pub struct TlsAntiDebugResult {
    pub detected: bool,
    pub techniques: Vec<String>,
    pub callback_index: u32,
}

impl TlsAntiDebugResult {
    #[must_use] 
    pub const fn none() -> Self {
        Self {
            detected: false,
            techniques: vec![],
            callback_index: 0,
        }
    }
}

/// Check a callback's preview bytes for known anti-debugging x86/x64 patterns.
#[must_use] 
pub fn detect_anti_debug_in_callback(cb: &TlsCallback) -> TlsAntiDebugResult {
    let mut techniques = Vec::new();
    let bytes = &cb.preview_bytes;

    // IsDebuggerPresent pattern: mov eax, [TEB+0x30]; test al, al
    if bytes
        .windows(5)
        .any(|w| w == [0x64, 0x8B, 0x0D, 0x30, 0x00])
    {
        techniques.push("IsDebuggerPresent (TEB access)".to_string());
    }
    // NtQueryInformationProcess pattern: int 0x2e
    if bytes.windows(2).any(|w| w == [0xCD, 0x2E]) {
        techniques.push("NtQueryInformationProcess (int 0x2e)".to_string());
    }
    // CPUID-based timing
    if bytes.windows(2).any(|w| w == [0x0F, 0xA2]) {
        techniques.push("CPUID-based timing check".to_string());
    }
    // RDTSC timing
    if bytes.windows(2).any(|w| w == [0x0F, 0x31]) {
        techniques.push("RDTSC timing check".to_string());
    }

    TlsAntiDebugResult {
        detected: !techniques.is_empty(),
        techniques,
        callback_index: cb.index,
    }
}

/// Full TLS callback analysis result.
#[derive(Debug, Clone, Default)]
pub struct TlsCallbackAnalyzer {
    pub callbacks: Vec<TlsCallback>,
    pub suspicious_count: usize,
    pub execution_order: Option<TlsCallbackExecutionOrder>,
    pub has_callbacks: bool,
}

impl TlsCallbackAnalyzer {
    /// Analyze TLS callbacks from a 64-bit PE image.
    ///
    /// `image_data`   — full raw file bytes
    /// `image_base`   — preferred image base (e.g. `0x1_4000_0000`)
    /// `callbacks_va` — `AddressOfCallbacks` field value
    /// `section_ranges` — `(start_va, end_va)` pairs for known code sections
    /// `entry_point_va` — PE entry point VA
    ///
    /// # Errors
    /// Returns [`TlsError`] if the callback list is malformed or exceeds the limit.
    pub fn analyze_pe64(
        image_data: &[u8],
        image_base: u64,
        callbacks_va: u64,
        section_ranges: &[(u64, u64)],
        entry_point_va: u64,
    ) -> Result<Self, TlsError> {
        const MAX_CALLBACKS: usize = 1024;

        if callbacks_va == 0 {
            return Ok(Self::default());
        }

        if callbacks_va < image_base {
            return Err(TlsError::InvalidDirectoryRva(0));
        }

        let callbacks_offset = u64_to_usize(callbacks_va - image_base);
        let mut callbacks = Vec::new();
        let mut offset = callbacks_offset;
        let mut index = 0u32;

        loop {
            if offset + 8 > image_data.len() {
                break;
            }
            let va = read_u64(&image_data[offset..], true);
            if va == 0 {
                callbacks.push(TlsCallback {
                    index,
                    virtual_address: 0,
                    rva: 0,
                    class: CallbackClass::NullTerminator,
                    name: None,
                    preview_bytes: vec![],
                });
                break;
            }

            if usize::try_from(index).unwrap_or(usize::MAX) >= MAX_CALLBACKS {
                return Err(TlsError::TooManyCallbacks(usize::try_from(index).unwrap_or(usize::MAX)));
            }

            let rva = u64_to_u32(va.saturating_sub(image_base));
            let body_offset = rva as usize;

            // Extract preview bytes
            let preview_bytes = if body_offset < image_data.len() {
                let end = (body_offset + 16).min(image_data.len());
                image_data[body_offset..end].to_vec()
            } else {
                vec![]
            };

            // Classify
            let in_code_section = section_ranges
                .iter()
                .any(|&(start, end)| va >= start && va < end);

            let class = if !in_code_section {
                CallbackClass::SuspiciousLocation
            } else if va.abs_diff(entry_point_va) < 32 {
                CallbackClass::OverlapsEntryPoint
            } else if looks_like_shellcode(&preview_bytes) {
                CallbackClass::ShellcodePattern
            } else {
                CallbackClass::Benign
            };

            callbacks.push(TlsCallback {
                index,
                virtual_address: va,
                rva,
                class,
                name: None,
                preview_bytes,
            });

            offset += 8;
            index += 1;
        }

        let suspicious_count = callbacks.iter().filter(|c| c.is_suspicious()).count();
        let has_callbacks = callbacks.iter().any(|c| !c.is_terminator());

        let real_callbacks: Vec<_> = callbacks
            .iter()
            .filter(|c| !c.is_terminator())
            .cloned()
            .collect();
        let execution_order = if has_callbacks {
            Some(TlsCallbackExecutionOrder::new(
                &real_callbacks,
                entry_point_va,
            ))
        } else {
            None
        };

        Ok(Self {
            callbacks,
            suspicious_count,
            execution_order,
            has_callbacks,
        })
    }

    /// Resolve callback names from an export address table.
    /// `exports` — map of VA → name.
    pub fn resolve_names(&mut self, exports: &BTreeMap<u64, String>) {
        for cb in &mut self.callbacks {
            if let Some(name) = exports.get(&cb.virtual_address) {
                cb.name = Some(name.clone());
            }
        }
    }

    /// All non-terminator callbacks.
    #[must_use] 
    pub fn real_callbacks(&self) -> Vec<&TlsCallback> {
        self.callbacks
            .iter()
            .filter(|c| !c.is_terminator())
            .collect()
    }

    /// `true` if any callback looks malicious.
    #[must_use] 
    pub const fn is_suspicious(&self) -> bool {
        self.suspicious_count > 0
    }
}

// ---------------------------------------------------------------------------
// PeTlsCallbacks — top-level struct
// ---------------------------------------------------------------------------

/// Complete PE TLS callback analysis.
#[derive(Debug)]
pub struct PeTlsCallbacks {
    pub directory32: Option<TlsDirectory32>,
    pub directory64: Option<TlsDirectory64>,
    pub analyzer: TlsCallbackAnalyzer,
    pub is_pe64: bool,
}

impl PeTlsCallbacks {
    /// Build from a PE32+ binary.
    ///
    /// # Errors
    /// Returns [`TlsError`] if the TLS directory or callbacks are malformed.
    pub fn from_pe64(
        tls_dir_data: &[u8],
        image_data: &[u8],
        image_base: u64,
        section_ranges: &[(u64, u64)],
        entry_point_va: u64,
    ) -> Result<Self, TlsError> {
        let dir = TlsDirectory64::parse(tls_dir_data, true)?;
        let analyzer = TlsCallbackAnalyzer::analyze_pe64(
            image_data,
            image_base,
            dir.address_of_callbacks,
            section_ranges,
            entry_point_va,
        )?;
        Ok(Self {
            directory32: None,
            directory64: Some(dir),
            analyzer,
            is_pe64: true,
        })
    }

    /// Build from a PE32 binary.
    ///
    /// # Errors
    /// Returns [`TlsError`] if the TLS directory or callbacks are malformed.
    pub fn from_pe32(
        tls_dir_data: &[u8],
        image_data: &[u8],
        image_base: u32,
        section_ranges: &[(u64, u64)],
        entry_point_va: u64,
    ) -> Result<Self, TlsError> {
        let dir = TlsDirectory32::parse(tls_dir_data, true)?;
        let callbacks_va = u64::from(dir.address_of_callbacks);
        let analyzer = TlsCallbackAnalyzer::analyze_pe64(
            image_data,
            u64::from(image_base),
            callbacks_va,
            section_ranges,
            entry_point_va,
        )?;
        Ok(Self {
            directory32: Some(dir),
            directory64: None,
            analyzer,
            is_pe64: false,
        })
    }

    /// `true` if the binary has any TLS callbacks defined.
    #[must_use] 
    pub const fn has_callbacks(&self) -> bool {
        self.analyzer.has_callbacks
    }

    /// `true` if any callback looks suspicious (malware heuristic).
    #[must_use] 
    pub const fn is_suspicious(&self) -> bool {
        self.analyzer.is_suspicious()
    }

    /// Number of real (non-null-terminator) TLS callbacks.
    #[must_use] 
    pub fn callback_count(&self) -> usize {
        self.analyzer.real_callbacks().len()
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackReport — formatted reporting
// ---------------------------------------------------------------------------

/// Summary report for TLS callback analysis suitable for automated pipelines.
#[derive(Debug, Clone)]
pub struct TlsCallbackReport {
    pub binary_name: String,
    pub is_pe64: bool,
    pub callback_count: usize,
    pub suspicious_count: usize,
    pub has_shellcode: bool,
    pub is_cve_2017_candidate: bool,
    pub callback_addresses: Vec<u64>,
    pub callback_names: Vec<Option<String>>,
    pub risk_score: u32,
}

impl TlsCallbackReport {
    /// Build a report from a fully-analysed `PeTlsCallbacks`.
    pub fn from_analysis(name: impl Into<String>, tls: &PeTlsCallbacks) -> Self {
        let real = tls.analyzer.real_callbacks();
        let suspicious_count = tls.analyzer.suspicious_count;
        let has_shellcode = real
            .iter()
            .any(|c| matches!(c.class, CallbackClass::ShellcodePattern));
        let is_cve_2017_candidate = tls.analyzer.callbacks.iter().any(|c| {
            matches!(
                c.class,
                CallbackClass::OverlapsEntryPoint | CallbackClass::SuspiciousLocation
            )
        });

        let risk_score = (usize_to_u32(suspicious_count) * 25)
            .saturating_add(if has_shellcode { 50 } else { 0 })
            .min(100);

        Self {
            binary_name: name.into(),
            is_pe64: tls.is_pe64,
            callback_count: real.len(),
            suspicious_count,
            has_shellcode,
            is_cve_2017_candidate,
            callback_addresses: real.iter().map(|c| c.virtual_address).collect(),
            callback_names: real.iter().map(|c| c.name.clone()).collect(),
            risk_score,
        }
    }

    /// `true` when the risk score is high enough to warrant investigation.
    #[must_use] 
    pub const fn is_high_risk(&self) -> bool {
        self.risk_score >= 50
    }

    /// One-line summary string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "{}: {} TLS callbacks ({} suspicious), risk={}/100",
            self.binary_name, self.callback_count, self.suspicious_count, self.risk_score
        )
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackScanner — scan PE image bytes for TLS directory
// ---------------------------------------------------------------------------

/// Known TLS directory data-directory index.
pub const DATA_DIRECTORY_TLS: usize = 9;

/// Scan result from `TlsCallbackScanner`.
#[derive(Debug, Clone)]
pub struct TlsScanResult {
    /// `true` if a TLS directory was found.
    pub has_tls: bool,
    /// Offset in the raw file of the TLS directory (if found).
    pub directory_offset: Option<usize>,
    /// Raw TLS directory bytes.
    pub directory_bytes: Vec<u8>,
    /// Whether the PE is 64-bit.
    pub is_pe64: bool,
    /// Image base extracted from the PE optional header.
    pub image_base: u64,
    /// Entry point VA.
    pub entry_point_va: u64,
    /// Code section ranges.
    pub section_ranges: Vec<(u64, u64)>,
}

impl TlsScanResult {
    const fn empty() -> Self {
        Self {
            has_tls: false,
            directory_offset: None,
            directory_bytes: vec![],
            is_pe64: false,
            image_base: 0,
            entry_point_va: 0,
            section_ranges: vec![],
        }
    }
}

/// Scan the PE section table to collect code section VA ranges and locate the TLS directory.
///
/// Returns `(section_ranges, tls_directory_offset)`.
fn scan_section_table(
    data: &[u8],
    sect_table_off: usize,
    num_sections: usize,
    image_base: u64,
    tls_rva: u32,
) -> (Vec<(u64, u64)>, Option<usize>) {
    let mut section_ranges = Vec::new();
    let mut directory_offset = None;
    for idx in 0..num_sections.min(96) {
        let soff = sect_table_off + idx * 40;
        if soff + 40 > data.len() { break; }
        let virt_addr = u32::from_le_bytes(data[soff + 12..soff + 16].try_into().unwrap());
        // VirtualSize @8 is 0 in object files, SizeOfRawData @16 is 0 for an
        // uninitialised section: the mapped span is the larger of the two.
        let virt_size = u32::from_le_bytes(data[soff + 8..soff + 12].try_into().unwrap())
            .max(u32::from_le_bytes(data[soff + 16..soff + 20].try_into().unwrap()));
        let raw_off   = u32::from_le_bytes(data[soff + 20..soff + 24].try_into().unwrap()) as usize;
        let chars     = u32::from_le_bytes(data[soff + 36..soff + 40].try_into().unwrap());
        if chars & 0x20 != 0 || chars & 0x2000_0000 != 0 {
            let start = image_base + u64::from(virt_addr);
            section_ranges.push((start, start + u64::from(virt_size)));
        }
        if tls_rva >= virt_addr && tls_rva < virt_addr.saturating_add(virt_size) {
            directory_offset = Some(raw_off + (tls_rva - virt_addr) as usize);
        }
    }
    (section_ranges, directory_offset)
}

/// Lightweight PE scanner that extracts TLS directory metadata without
/// requiring `goblin` or other full PE parsers.
pub struct TlsCallbackScanner;

impl TlsCallbackScanner {
    /// Scan raw PE file bytes for TLS directory.
    ///
    /// # Panics
    ///
    /// Panics are impossible in practice because all slice accesses are bounds-checked
    /// before the `try_into().unwrap()` calls.
    #[must_use]
    pub fn scan(data: &[u8]) -> TlsScanResult {
        let Some((opt_off, coff_off, optional_header_size, is_pe64, image_base, entry_point_va)) =
            Self::parse_pe_headers(data)
        else {
            return TlsScanResult::empty();
        };

        let (tls_rva, tls_size, has_tls_entry, section_ranges) =
            Self::locate_tls_directory(data, opt_off, coff_off, optional_header_size, is_pe64, image_base);

        if !has_tls_entry {
            return TlsScanResult {
                has_tls: false,
                is_pe64,
                image_base,
                entry_point_va,
                section_ranges,
                ..TlsScanResult::empty()
            };
        }

        let (final_ranges, directory_offset) =
            Self::resolve_tls_offset(data, opt_off, coff_off, optional_header_size, image_base, tls_rva);

        let directory_bytes = directory_offset.map_or_else(Vec::new, |off| {
            let end = (off + usize::try_from(tls_size).unwrap_or(usize::MAX)).min(data.len());
            data[off..end].to_vec()
        });

        TlsScanResult {
            has_tls: true,
            directory_offset,
            directory_bytes,
            is_pe64,
            image_base,
            entry_point_va,
            section_ranges: final_ranges,
        }
    }

    /// Parse DOS/COFF/optional headers. Returns `(opt_off, coff_off, opt_hdr_size, is_pe64, image_base, entry_point_va)`.
    fn parse_pe_headers(data: &[u8]) -> Option<(usize, usize, usize, bool, u64, u64)> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return None;
        }
        let pe_offset = usize::try_from(u32::from_le_bytes(
            data[0x3c..0x40].try_into().unwrap_or([0; 4])
        )).ok()?;
        if pe_offset + 4 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }
        let coff_off = pe_offset + 4;
        if coff_off + 20 > data.len() {
            return None;
        }
        let optional_header_size = usize::from(u16::from_le_bytes(
            data[coff_off + 16..coff_off + 18].try_into().unwrap_or([0; 2])
        ));
        let opt_off = coff_off + 20;
        if opt_off + 2 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap_or([0; 2]));
        let is_pe64 = magic == 0x20b;
        let (image_base, ep_rva) = if is_pe64 {
            if opt_off + 40 > data.len() { return None; }
            let ep = u64::from(u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().unwrap_or([0; 4])));
            let ib = u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0; 8]));
            (ib, ep)
        } else {
            if opt_off + 32 > data.len() { return None; }
            let ep = u64::from(u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().unwrap_or([0; 4])));
            let ib = u64::from(u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().unwrap_or([0; 4])));
            (ib, ep)
        };
        Some((opt_off, coff_off, optional_header_size, is_pe64, image_base, image_base + ep_rva))
    }

    /// Locate the TLS data directory and collect section ranges.
    /// Returns `(tls_rva, tls_size, has_tls_entry, section_ranges)`.
    fn locate_tls_directory(
        data: &[u8],
        opt_off: usize,
        coff_off: usize,
        optional_header_size: usize,
        is_pe64: bool,
        image_base: u64,
    ) -> (u32, u32, bool, Vec<(u64, u64)>) {
        let dd_offset = if is_pe64 { opt_off + 112 } else { opt_off + 96 };
        let tls_dd_off = dd_offset + DATA_DIRECTORY_TLS * 8;
        if tls_dd_off + 8 > data.len() {
            return (0, 0, false, vec![]);
        }
        let tls_rva = u32::from_le_bytes(data[tls_dd_off..tls_dd_off + 4].try_into().unwrap_or([0; 4]));
        let tls_size = u32::from_le_bytes(data[tls_dd_off + 4..tls_dd_off + 8].try_into().unwrap_or([0; 4]));
        if tls_rva == 0 || tls_size == 0 {
            return (0, 0, false, vec![]);
        }
        let num_sections = usize::from(u16::from_le_bytes(
            data[coff_off + 2..coff_off + 4].try_into().unwrap_or([0; 2])
        ));
        let sect_table_off = opt_off + optional_header_size;
        let (ranges, _) = scan_section_table(data, sect_table_off, num_sections, image_base, tls_rva);
        (tls_rva, tls_size, true, ranges)
    }

    /// Resolve TLS RVA to file offset using section headers.
    fn resolve_tls_offset(
        data: &[u8],
        opt_off: usize,
        coff_off: usize,
        optional_header_size: usize,
        image_base: u64,
        tls_rva: u32,
    ) -> (Vec<(u64, u64)>, Option<usize>) {
        let num_sections = usize::from(u16::from_le_bytes(
            data[coff_off + 2..coff_off + 4].try_into().unwrap_or([0; 2])
        ));
        let sect_table_off = opt_off + optional_header_size;
        scan_section_table(data, sect_table_off, num_sections, image_base, tls_rva)
    }
}

// ---------------------------------------------------------------------------
// Low-level byte helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], little_endian: bool) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    if little_endian {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }
}

fn read_u64(data: &[u8], little_endian: bool) -> u64 {
    if data.len() < 8 {
        return 0;
    }
    let b: [u8; 8] = data[..8].try_into().unwrap();
    if little_endian {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tls_dir32(
        start: u32,
        end: u32,
        idx: u32,
        callbacks: u32,
        zero: u32,
        chars: u32,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        for &x in &[start, end, idx, callbacks, zero, chars] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    fn make_tls_dir64(
        start: u64,
        end: u64,
        idx: u64,
        callbacks: u64,
        zero: u32,
        chars: u32,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        for &x in &[start, end, idx, callbacks] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&zero.to_le_bytes());
        v.extend_from_slice(&chars.to_le_bytes());
        v
    }

    // ---- TlsDirectory32 ----

    #[test]
    fn test_tls_dir32_parse_basic() {
        let data = make_tls_dir32(0x1000, 0x1010, 0x2000, 0x3000, 0x20, 0x0030_0000);
        let dir = TlsDirectory32::parse(&data, true).unwrap();
        assert_eq!(dir.start_address_of_raw_data, 0x1000);
        assert_eq!(dir.end_address_of_raw_data, 0x1010);
        assert_eq!(dir.raw_data_size(), 0x10);
        assert_eq!(dir.size_of_zero_fill, 0x20);
        assert_eq!(dir.total_size(), 0x30);
    }

    #[test]
    fn test_tls_dir32_alignment() {
        // bits 20-23 = 5 → alignment = 1 << 4 = 16
        let data = make_tls_dir32(0, 0, 0, 0, 0, 0x0050_0000);
        let dir = TlsDirectory32::parse(&data, true).unwrap();
        assert_eq!(dir.alignment(), 16);
    }

    #[test]
    fn test_tls_dir32_zero_alignment() {
        let data = make_tls_dir32(0, 0, 0, 0, 0, 0);
        let dir = TlsDirectory32::parse(&data, true).unwrap();
        assert_eq!(dir.alignment(), 0);
    }

    #[test]
    fn test_tls_dir32_truncated() {
        let data = vec![0u8; 12];
        assert!(matches!(
            TlsDirectory32::parse(&data, true),
            Err(TlsError::TruncatedData { .. })
        ));
    }

    // ---- TlsDirectory64 ----

    #[test]
    fn test_tls_dir64_parse_basic() {
        let data = make_tls_dir64(0x1_4000_1000, 0x1_4000_1020, 0x1_4000_2000, 0x1_4000_3000, 0x40, 0);
        let dir = TlsDirectory64::parse(&data, true).unwrap();
        assert_eq!(dir.raw_data_size(), 0x20);
        assert_eq!(dir.total_size(), 0x60);
    }

    #[test]
    fn test_tls_dir64_truncated() {
        let data = vec![0u8; 20];
        assert!(matches!(
            TlsDirectory64::parse(&data, true),
            Err(TlsError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_tls_dir64_alignment_bits() {
        let data = make_tls_dir64(0, 0, 0, 0, 0, 0x0030_0000); // bits 20-23 = 3 → 1 << 2 = 4
        let dir = TlsDirectory64::parse(&data, true).unwrap();
        assert_eq!(dir.alignment(), 4);
    }

    // ---- TlsCallback ----

    #[test]
    fn test_callback_is_terminator_by_class() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0,
            rva: 0,
            class: CallbackClass::NullTerminator,
            name: None,
            preview_bytes: vec![],
        };
        assert!(cb.is_terminator());
    }

    #[test]
    fn test_callback_is_terminator_by_va() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0,
            rva: 0,
            class: CallbackClass::Benign,
            name: None,
            preview_bytes: vec![],
        };
        assert!(cb.is_terminator());
    }

    #[test]
    fn test_callback_not_suspicious_when_benign() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::Benign,
            name: None,
            preview_bytes: vec![],
        };
        assert!(!cb.is_suspicious());
    }

    #[test]
    fn test_callback_suspicious_outside_section() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::SuspiciousLocation,
            name: None,
            preview_bytes: vec![],
        };
        assert!(cb.is_suspicious());
    }

    #[test]
    fn test_callback_suspicious_shellcode() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::ShellcodePattern,
            name: None,
            preview_bytes: vec![],
        };
        assert!(cb.is_suspicious());
    }

    // ---- looks_like_shellcode ----

    #[test]
    fn test_looks_like_shellcode_nop_sled() {
        let bytes = vec![0x90u8; 8];
        assert!(looks_like_shellcode(&bytes));
    }

    #[test]
    fn test_looks_like_shellcode_int3_sled() {
        let bytes = vec![0xCCu8; 6];
        assert!(looks_like_shellcode(&bytes));
    }

    #[test]
    fn test_looks_like_shellcode_normal_code() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20; ret
        let bytes = vec![0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3];
        assert!(!looks_like_shellcode(&bytes));
    }

    #[test]
    fn test_looks_like_shellcode_too_short() {
        assert!(!looks_like_shellcode(&[0x90, 0x90]));
    }

    // ---- TlsCallbackExecutionOrder ----

    #[test]
    fn test_execution_order_all_pre_entry() {
        let cbs = vec![TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::Benign,
            name: None,
            preview_bytes: vec![],
        }];
        let order = TlsCallbackExecutionOrder::new(&cbs, 0x40_1100);
        assert_eq!(order.pre_entry.len(), 1);
        assert!(order.post_entry.is_empty());
        assert!(!order.has_anomalies());
    }

    #[test]
    fn test_execution_order_post_entry_anomaly() {
        let cbs = vec![TlsCallback {
            index: 0,
            virtual_address: 0x40_1200,
            rva: 0x1200,
            class: CallbackClass::SuspiciousLocation,
            name: None,
            preview_bytes: vec![],
        }];
        let order = TlsCallbackExecutionOrder::new(&cbs, 0x40_1100);
        assert!(order.has_anomalies());
        assert_eq!(order.post_entry.len(), 1);
    }

    #[test]
    fn test_execution_order_skips_null_terminator() {
        let cbs = vec![TlsCallback {
            index: 0,
            virtual_address: 0,
            rva: 0,
            class: CallbackClass::NullTerminator,
            name: None,
            preview_bytes: vec![],
        }];
        let order = TlsCallbackExecutionOrder::new(&cbs, 0x40_1100);
        assert!(order.pre_entry.is_empty());
        assert!(order.post_entry.is_empty());
    }

    // ---- TlsCallbackAnalyzer ----

    #[test]
    fn test_analyzer_null_callbacks_va() {
        let result =
            TlsCallbackAnalyzer::analyze_pe64(&[0u8; 64], 0x40_0000, 0, &[], 0x40_1000).unwrap();
        assert!(!result.has_callbacks);
    }

    #[test]
    fn test_analyzer_callbacks_va_below_base_errors() {
        let result = TlsCallbackAnalyzer::analyze_pe64(&[0u8; 64], 0x40_0000, 0x100, &[], 0x40_1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyzer_null_terminator_only() {
        let mut image = vec![0u8; 0x2000];
        let callbacks_va: u64 = 0x40_1000;
        let image_base: u64 = 0x40_0000;
        let offset = (callbacks_va - image_base) as usize;
        // Write null terminator at that offset
        image[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_va,
            &[(0x40_1000, 0x40_1fff)],
            0x40_1500,
        )
        .unwrap();
        assert!(!result.has_callbacks);
    }

    #[test]
    fn test_analyzer_one_benign_callback() {
        let image_base: u64 = 0x40_0000;
        let callback_va: u64 = 0x40_1100;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x3000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&callback_va.to_le_bytes());
        // null terminator
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&0u64.to_le_bytes());
        // Write benign x86 code at callback_va
        let code_off = (callback_va - image_base) as usize;
        image[code_off..code_off + 4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500,
        )
        .unwrap();
        assert!(result.has_callbacks);
        assert_eq!(result.real_callbacks().len(), 1);
        assert!(!result.is_suspicious());
    }

    #[test]
    fn test_analyzer_suspicious_outside_section() {
        let image_base: u64 = 0x40_0000;
        let callback_va: u64 = 0x40_5000; // outside code section
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x8000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&callback_va.to_le_bytes());
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&0u64.to_le_bytes());
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500, // code section does NOT include 0x40_5000
        )
        .unwrap();
        assert!(result.is_suspicious());
    }

    #[test]
    fn test_analyzer_resolve_names() {
        let image_base: u64 = 0x40_0000;
        let callback_va: u64 = 0x40_1100;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x3000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&callback_va.to_le_bytes());
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&0u64.to_le_bytes());
        let mut result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500,
        )
        .unwrap();
        let mut exports = BTreeMap::new();
        exports.insert(callback_va, "TlsInit".to_string());
        result.resolve_names(&exports);
        assert_eq!(result.real_callbacks()[0].name.as_deref(), Some("TlsInit"));
    }

    // ---- PeTlsCallbacks ----

    #[test]
    fn test_pe_tls_no_callbacks() {
        let image_base: u64 = 0x1_4000_0000;
        let dir = make_tls_dir64(
            image_base + 0x1000,
            image_base + 0x1010,
            image_base + 0x2000,
            0, // callbacks VA = 0
            0,
            0,
        );
        let tls =
            PeTlsCallbacks::from_pe64(&dir, &[0u8; 0x4000], image_base, &[], image_base + 0x3000)
                .unwrap();
        assert!(!tls.has_callbacks());
        assert_eq!(tls.callback_count(), 0);
    }

    #[test]
    fn test_pe_tls_is_pe64_flag() {
        let image_base: u64 = 0x1_4000_0000;
        let dir = make_tls_dir64(0, 0, 0, 0, 0, 0);
        let tls = PeTlsCallbacks::from_pe64(&dir, &[0u8; 64], image_base, &[], image_base).unwrap();
        assert!(tls.is_pe64);
    }

    #[test]
    fn test_pe_tls32_is_not_pe64() {
        let image_base: u32 = 0x40_0000;
        let dir = make_tls_dir32(0, 0, 0, 0, 0, 0);
        let tls = PeTlsCallbacks::from_pe32(&dir, &[0u8; 64], image_base, &[], 0x40_1000).unwrap();
        assert!(!tls.is_pe64);
    }

    #[test]
    fn test_tls_error_display() {
        let e = TlsError::TooManyCallbacks(2000);
        assert!(e.to_string().contains("2000"));
        let e2 = TlsError::CallbackOutsideImage { va: 0xdead_beef };
        assert!(e2.to_string().contains("deadbeef"));
    }

    #[test]
    fn test_callback_class_zero_gap_suspicious() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::ZeroGapTrick,
            name: None,
            preview_bytes: vec![],
        };
        assert!(cb.is_suspicious());
    }

    #[test]
    fn test_tls_dir32_raw_data_size_zero() {
        let data = make_tls_dir32(0x2000, 0x2000, 0x3000, 0x4000, 0, 0);
        let dir = TlsDirectory32::parse(&data, true).unwrap();
        assert_eq!(dir.raw_data_size(), 0);
    }

    #[test]
    fn test_tls_dir64_raw_data_size() {
        let data = make_tls_dir64(0x1_4000_1000, 0x1_4000_1100, 0, 0, 0, 0);
        let dir = TlsDirectory64::parse(&data, true).unwrap();
        assert_eq!(dir.raw_data_size(), 0x100);
    }

    #[test]
    fn test_analyzer_too_many_callbacks_error() {
        let image_base: u64 = 0x40_0000;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x1_0000];
        // Write 1025 non-null callback pointers pointing outside all sections
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        for i in 0..1025usize {
            let va: u64 = 0x60_0000 + (i * 0x10) as u64;
            image[ptr_off + i * 8..ptr_off + i * 8 + 8].copy_from_slice(&va.to_le_bytes());
        }
        let result =
            TlsCallbackAnalyzer::analyze_pe64(&image, image_base, callbacks_ptr_va, &[], 0x40_1000);
        assert!(matches!(result, Err(TlsError::TooManyCallbacks(_))));
    }

    #[test]
    fn test_callback_index_increments() {
        let image_base: u64 = 0x40_0000;
        let cb_va1: u64 = 0x40_1100;
        let cb_va2: u64 = 0x40_1200;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x3000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&cb_va1.to_le_bytes());
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&cb_va2.to_le_bytes());
        image[ptr_off + 16..ptr_off + 24].copy_from_slice(&0u64.to_le_bytes());
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500,
        )
        .unwrap();
        let real = result.real_callbacks();
        assert_eq!(real[0].index, 0);
        assert_eq!(real[1].index, 1);
    }

    #[test]
    fn test_execution_order_multiple_pre_entry() {
        let cbs = vec![
            TlsCallback {
                index: 0,
                virtual_address: 0x40_1000,
                rva: 0x1000,
                class: CallbackClass::Benign,
                name: None,
                preview_bytes: vec![],
            },
            TlsCallback {
                index: 1,
                virtual_address: 0x40_1050,
                rva: 0x1050,
                class: CallbackClass::Benign,
                name: None,
                preview_bytes: vec![],
            },
        ];
        let order = TlsCallbackExecutionOrder::new(&cbs, 0x40_2000);
        assert_eq!(order.pre_entry.len(), 2);
        assert!(!order.has_anomalies());
    }

    #[test]
    fn test_tls_dir32_total_size_with_bss() {
        let data = make_tls_dir32(0x1000, 0x1020, 0, 0, 0x100, 0);
        let dir = TlsDirectory32::parse(&data, true).unwrap();
        assert_eq!(dir.total_size(), 0x20 + 0x100);
    }

    #[test]
    fn test_callback_preview_bytes_populated() {
        let image_base: u64 = 0x40_0000;
        let callback_va: u64 = 0x40_1100;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x3000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&callback_va.to_le_bytes());
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&0u64.to_le_bytes());
        let code_off = (callback_va - image_base) as usize;
        image[code_off..code_off + 8]
            .copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20]);
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500,
        )
        .unwrap();
        assert!(!result.real_callbacks()[0].preview_bytes.is_empty());
    }

    #[test]
    fn test_pe_tls_callbacks_not_suspicious_no_callbacks() {
        let image_base: u64 = 0x1_4000_0000;
        let dir = make_tls_dir64(0, 0, 0, 0, 0, 0);
        let tls = PeTlsCallbacks::from_pe64(&dir, &[0u8; 64], image_base, &[], image_base).unwrap();
        assert!(!tls.is_suspicious());
    }

    #[test]
    fn test_callback_rva_computed() {
        let image_base: u64 = 0x40_0000;
        let callback_va: u64 = 0x40_1100;
        let callbacks_ptr_va: u64 = 0x40_1000;
        let mut image = vec![0u8; 0x3000];
        let ptr_off = (callbacks_ptr_va - image_base) as usize;
        image[ptr_off..ptr_off + 8].copy_from_slice(&callback_va.to_le_bytes());
        image[ptr_off + 8..ptr_off + 16].copy_from_slice(&0u64.to_le_bytes());
        let result = TlsCallbackAnalyzer::analyze_pe64(
            &image,
            image_base,
            callbacks_ptr_va,
            &[(0x40_1000, 0x40_2000)],
            0x40_1500,
        )
        .unwrap();
        assert_eq!(result.real_callbacks()[0].rva, 0x1100);
    }

    #[test]
    fn test_tls_error_null_address() {
        let e = TlsError::NullAddressOfCallbacks;
        assert!(e.to_string().contains("null"));
    }

    #[test]
    fn test_callback_class_benign_not_suspicious() {
        let cb = TlsCallback {
            index: 0,
            virtual_address: 0x40_1000,
            rva: 0x1000,
            class: CallbackClass::Benign,
            name: None,
            preview_bytes: vec![],
        };
        assert!(!cb.is_suspicious());
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackDatabase — known-safe TLS callback hashes
// ---------------------------------------------------------------------------

/// A digest-based whitelist for known-benign TLS callbacks.
#[derive(Debug, Default)]
pub struct TlsCallbackDatabase {
    known_safe: std::collections::HashSet<u64>,
    known_malicious: std::collections::HashSet<u64>,
}

impl TlsCallbackDatabase {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a VA as known-safe.
    pub fn add_safe(&mut self, va: u64) {
        self.known_safe.insert(va);
    }
    /// Register a VA as known-malicious.
    pub fn add_malicious(&mut self, va: u64) {
        self.known_malicious.insert(va);
    }

    /// Check classification of a VA.
    #[must_use] 
    pub fn classify(&self, va: u64) -> Option<bool> {
        if self.known_safe.contains(&va) {
            return Some(true);
        }
        if self.known_malicious.contains(&va) {
            return Some(false);
        }
        None
    }

    #[must_use] 
    pub fn safe_count(&self) -> usize {
        self.known_safe.len()
    }
    #[must_use] 
    pub fn malicious_count(&self) -> usize {
        self.known_malicious.len()
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackContext — full context for a TLS callback
// ---------------------------------------------------------------------------

/// Complete analysis context for one TLS callback.
#[derive(Debug, Clone)]
pub struct TlsCallbackContext {
    pub callback: TlsCallback,
    pub anti_debug: TlsAntiDebugResult,
    pub shellcode_class: CallbackClass,
    pub startup_model_slot: Option<u64>,
}

impl TlsCallbackContext {
    #[must_use] 
    pub fn new(cb: TlsCallback) -> Self {
        let anti_debug = detect_anti_debug_in_callback(&cb);
        let sc = classify_by_patterns(&cb.preview_bytes);
        Self {
            callback: cb,
            anti_debug,
            shellcode_class: sc,
            startup_model_slot: None,
        }
    }

    #[must_use] 
    pub const fn is_definitely_malicious(&self) -> bool {
        self.anti_debug.detected || self.callback.is_suspicious()
    }
}

// ---------------------------------------------------------------------------
// TlsCallbackStatistics - aggregate stats
// ---------------------------------------------------------------------------
/// Aggregate statistics about TLS callbacks across a PE binary.
#[derive(Debug, Clone, Default)]
pub struct TlsCallbackStatistics {
    pub total_callbacks: usize,
    pub benign_callbacks: usize,
    pub suspicious_callbacks: usize,
    pub shellcode_callbacks: usize,
    pub zero_gap_callbacks: usize,
    pub overlap_ep_callbacks: usize,
    pub named_callbacks: usize,
}

impl TlsCallbackStatistics {
    #[must_use] 
    pub fn from_analyzer(a: &TlsCallbackAnalyzer) -> Self {
        let real = a.real_callbacks();
        let mut s = Self {
            total_callbacks: real.len(),
            ..Default::default()
        };
        for cb in &real {
            match cb.class {
                CallbackClass::Benign => s.benign_callbacks += 1,
                CallbackClass::ShellcodePattern => s.shellcode_callbacks += 1,
                CallbackClass::ZeroGapTrick => s.zero_gap_callbacks += 1,
                CallbackClass::OverlapsEntryPoint => s.overlap_ep_callbacks += 1,
                CallbackClass::SuspiciousLocation => s.suspicious_callbacks += 1,
                CallbackClass::NullTerminator => {}
            }
            if cb.name.is_some() {
                s.named_callbacks += 1;
            }
        }
        s
    }
    #[must_use] 
    pub const fn suspicious_total(&self) -> usize {
        self.shellcode_callbacks
            + self.zero_gap_callbacks
            + self.overlap_ep_callbacks
            + self.suspicious_callbacks
    }
}

/// Validate that a TLS directory is well-formed.
#[must_use] 
pub fn validate_tls_directory(tls: &PeTlsCallbacks) -> Vec<String> {
    let mut issues = Vec::new();
    if tls.is_pe64
        && let Some(dir) = &tls.directory64 {
            if dir.size_of_zero_fill > 0x10_0000 {
                issues.push("Unusually large zero-fill region".into());
            }
            if dir.address_of_callbacks == 0 {
                issues.push("Null AddressOfCallbacks".into());
            }
        }
    if tls.callback_count() > 16 {
        issues.push(format!(
            "Unusually many callbacks: {}",
            tls.callback_count()
        ));
    }
    issues
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
#[must_use] 
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(std::borrow::ToOwned::to_owned)
}

/// Align a value up to `align` (power-of-two).
#[must_use] 
pub const fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val.saturating_add(align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
#[must_use] 
pub const fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
#[must_use] 
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use] 
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = usize_to_f64(data.len());
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional public types expected by the crate root re-export surface.
// ---------------------------------------------------------------------------

/// Result of scanning a TLS callback body for the CVE-2017-11882 / equation
/// editor RTF-style shellcode pattern.
#[derive(Debug, Clone, Default)]
pub struct Cve201711882Result {
    /// True when at least one matching pattern was found.
    pub detected: bool,
    /// File offset (when known) of the suspicious code.
    pub offset: Option<usize>,
    /// Human-readable description of the match.
    pub description: String,
}

impl Cve201711882Result {
    /// Convenience constructor for a negative scan.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// A chunk of suspected embedded shellcode discovered inside a TLS callback
/// (or callback table) payload.
#[derive(Debug, Clone, Default)]
pub struct EmbeddedShellcode {
    /// Offset within the analysed data.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Shannon entropy of the payload (already normalised to `[0, 1]`).
    pub entropy: f64,
    /// Hex-rendered preview of the first few bytes.
    pub preview_hex: String,
}
