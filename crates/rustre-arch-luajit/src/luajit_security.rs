//! `luajit_security` — LuaJIT security analysis: sandbox escapes, FFI abuse,
//! JIT bypass, memory corruption patterns, and ROP gadget detection.
//!
//! Provides:
//! * [`SandboxEscape`]   — Lua sandbox escape technique detection
//! * [`FFIAbuse`]        — LuaJIT FFI (Foreign Function Interface) abuse
//! * [`JitBypass`]       — JIT compilation bypass / deoptimization tricks
//! * [`MemoryCorruption`]— memory corruption patterns (oob, UAF, type confusion)
//! * [`LuaJitROP`]       — ROP gadget harvesting via JIT-compiled code
//! * [`LuaJitSecurity`]  — top-level facade

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Sandbox Escape
// ---------------------------------------------------------------------------

/// Kind of Lua sandbox escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeKind {
    /// `debug` library usage (debug.getinfo, debug.sethook, etc.).
    DebugLibrary,
    /// `load` / `loadstring` with arbitrary code.
    DynamicLoad,
    /// `dofile` / `loadfile` reading external code.
    FileExec,
    /// `os.execute` executing shell commands.
    OsExecute,
    /// `io` library file operations.
    IoLibrary,
    /// `require` loading untrusted modules.
    RequireAbuse,
    /// `rawget`/`rawset`/`rawequal` bypassing metamethods.
    RawAccess,
    /// `setfenv`/`getfenv` (Lua 5.1 sandbox bypass).
    Setfenv,
    /// `string.rep` or `table.concat` for buffer amplification.
    BufferAmplification,
    /// Coroutine abuse for state confusion.
    CoroutineAbuse,
}

impl fmt::Display for EscapeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DebugLibrary => "debug_library",
            Self::DynamicLoad => "dynamic_load",
            Self::FileExec => "file_exec",
            Self::OsExecute => "os_execute",
            Self::IoLibrary => "io_library",
            Self::RequireAbuse => "require_abuse",
            Self::RawAccess => "raw_access",
            Self::Setfenv => "setfenv",
            Self::BufferAmplification => "buffer_amplification",
            Self::CoroutineAbuse => "coroutine_abuse",
        };
        f.write_str(s)
    }
}

/// A detected sandbox escape.
#[derive(Debug, Clone)]
pub struct EscapeRecord {
    pub address: u64,
    pub kind: EscapeKind,
    pub function_name: String,
    pub severity: u8,
}

/// Sandbox escape detector.
#[derive(Debug, Clone, Default)]
pub struct SandboxEscape {
    /// Detected escape attempts.
    pub escapes: Vec<EscapeRecord>,
    /// Escape kinds seen.
    pub kinds_seen: HashSet<EscapeKind>,
}

impl SandboxEscape {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a Lua function call as a sandbox escape.
    #[must_use]
    pub fn classify_call(func: &str) -> Option<(EscapeKind, u8)> {
        match func {
            "debug.getinfo" | "debug.sethook" | "debug.getupvalue" | "debug.setupvalue"
            | "debug.getmetatable" | "debug.setmetatable" => Some((EscapeKind::DebugLibrary, 85)),
            "load" | "loadstring" | "loadbuffer" => Some((EscapeKind::DynamicLoad, 80)),
            "dofile" | "loadfile" => Some((EscapeKind::FileExec, 90)),
            "os.execute" | "os.exit" => Some((EscapeKind::OsExecute, 95)),
            "io.open" | "io.popen" | "io.write" | "io.read" => Some((EscapeKind::IoLibrary, 75)),
            "require" => Some((EscapeKind::RequireAbuse, 50)),
            "rawget" | "rawset" | "rawequal" | "rawlen" => Some((EscapeKind::RawAccess, 60)),
            "setfenv" | "getfenv" => Some((EscapeKind::Setfenv, 85)),
            "string.rep" => Some((EscapeKind::BufferAmplification, 40)),
            "coroutine.wrap" | "coroutine.resume" | "coroutine.create" => {
                Some((EscapeKind::CoroutineAbuse, 30))
            }
            _ => None,
        }
    }

    /// Record a function call.
    pub fn record_call(&mut self, address: u64, func: &str) {
        if let Some((kind, severity)) = Self::classify_call(func) {
            self.kinds_seen.insert(kind);
            self.escapes.push(EscapeRecord {
                address,
                kind,
                function_name: func.to_string(),
                severity,
            });
        }
    }

    /// Whether serious escape attempts were detected.
    #[must_use]
    pub fn is_dangerous(&self) -> bool {
        self.escapes.iter().any(|e| e.severity >= 75)
    }

    /// Maximum severity.
    #[must_use]
    pub fn max_severity(&self) -> u8 {
        self.escapes.iter().map(|e| e.severity).max().unwrap_or(0)
    }

    /// Escapes of a specific kind.
    #[must_use]
    pub fn of_kind(&self, kind: EscapeKind) -> Vec<&EscapeRecord> {
        self.escapes.iter().filter(|e| e.kind == kind).collect()
    }

    /// Count how many times each escape kind was recorded.
    #[must_use]
    pub fn counts_by_kind(&self) -> HashMap<EscapeKind, usize> {
        let mut counts: HashMap<EscapeKind, usize> = HashMap::with_capacity(self.escapes.len());
        for e in &self.escapes {
            *counts.entry(e.kind).or_insert(0) += 1;
        }
        counts
    }
}

// ---------------------------------------------------------------------------
// FFI Abuse
// ---------------------------------------------------------------------------

/// An FFI call record.
#[derive(Debug, Clone)]
pub struct FfiCallRecord {
    pub address: u64,
    pub call_type: FfiCallType,
    pub target: Option<String>,
    pub risk: u8,
}

/// FFI call type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiCallType {
    /// `ffi.C.*` call to C standard library.
    CStdLib,
    /// `ffi.load` loading a shared library.
    LibLoad,
    /// `ffi.cast` type-casting (type confusion risk).
    TypeCast,
    /// `ffi.new` memory allocation.
    MemAlloc,
    /// `ffi.copy` / `ffi.fill` memory operations.
    MemOp,
    /// `ffi.cdef` type definition (code injection via typedef).
    CDef,
    /// Raw pointer arithmetic.
    PointerArith,
}

/// `LuaJIT` FFI abuse detector.
#[derive(Debug, Clone, Default)]
pub struct FFIAbuse {
    /// Detected calls.
    pub calls: Vec<FfiCallRecord>,
    /// Whether `ffi` library is imported.
    pub ffi_imported: bool,
    /// Libraries loaded via `ffi.load`.
    pub loaded_libraries: HashSet<String>,
    /// Number of type casts.
    pub cast_count: usize,
    /// Number of raw memory operations.
    pub raw_mem_ops: usize,
}

impl FFIAbuse {
    /// Create a new FFI abuse detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify an FFI call by function name.
    #[must_use]
    pub fn classify(func: &str) -> Option<(FfiCallType, u8)> {
        if func == "ffi.load" {
            return Some((FfiCallType::LibLoad, 80));
        }
        if func == "ffi.cast" {
            return Some((FfiCallType::TypeCast, 85));
        }
        if func == "ffi.new" {
            return Some((FfiCallType::MemAlloc, 60));
        }
        if func == "ffi.copy" || func == "ffi.fill" {
            return Some((FfiCallType::MemOp, 70));
        }
        if func == "ffi.cdef" {
            return Some((FfiCallType::CDef, 75));
        }
        if func.starts_with("ffi.C.") {
            return Some((FfiCallType::CStdLib, 65));
        }
        None
    }

    /// Record an FFI import (`require("ffi")`).
    pub const fn record_import(&mut self) {
        self.ffi_imported = true;
    }

    /// Record an FFI call.
    pub fn record_call(&mut self, address: u64, func: &str, target: Option<String>) {
        if let Some((call_type, risk)) = Self::classify(func) {
            match call_type {
                FfiCallType::LibLoad => {
                    if let Some(ref lib) = target {
                        self.loaded_libraries.insert(lib.clone());
                    }
                }
                FfiCallType::TypeCast => {
                    self.cast_count += 1;
                }
                FfiCallType::MemOp => {
                    self.raw_mem_ops += 1;
                }
                _ => {}
            }
            self.calls.push(FfiCallRecord {
                address,
                call_type,
                target,
                risk,
            });
        }
    }

    /// Whether the FFI is used dangerously.
    #[must_use]
    pub const fn is_dangerous(&self) -> bool {
        self.ffi_imported && (self.calls.len() > 2 || self.cast_count > 0)
    }

    /// Maximum risk level.
    #[must_use]
    pub fn max_risk(&self) -> u8 {
        self.calls.iter().map(|c| c.risk).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// JIT Bypass
// ---------------------------------------------------------------------------

/// A JIT bypass technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitBypassTech {
    /// `jit.off()` explicitly disabling JIT.
    JitOff,
    /// `jit.flush()` flushing the JIT cache.
    JitFlush,
    /// Unreachable code / `goto` abuse preventing JIT compilation.
    UnreachableCode,
    /// Excessive function size (too large to JIT).
    OversizedFunction,
    /// NYI (Not Yet Implemented) instruction forcing interpretation.
    NyiInstruction,
    /// `pcall` / `xpcall` abuse to deoptimize traces.
    TraceDeopt,
}

/// JIT bypass record.
#[derive(Debug, Clone)]
pub struct JitBypassRecord {
    pub address: u64,
    pub technique: JitBypassTech,
    pub description: String,
}

/// JIT bypass / deoptimization detector.
#[derive(Debug, Clone, Default)]
pub struct JitBypass {
    pub records: Vec<JitBypassRecord>,
    pub jit_disabled: bool,
    pub trace_count_aborted: usize,
}

impl JitBypass {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a JIT bypass technique.
    pub fn record(
        &mut self,
        address: u64,
        technique: JitBypassTech,
        description: impl Into<String>,
    ) {
        if technique == JitBypassTech::JitOff {
            self.jit_disabled = true;
        }
        if technique == JitBypassTech::TraceDeopt {
            self.trace_count_aborted += 1;
        }
        self.records.push(JitBypassRecord {
            address,
            technique,
            description: description.into(),
        });
    }

    /// Classify a Lua function call for JIT bypass.
    #[must_use]
    pub fn classify_call(func: &str) -> Option<(JitBypassTech, &'static str)> {
        match func {
            "jit.off" => Some((JitBypassTech::JitOff, "JIT explicitly disabled")),
            "jit.flush" => Some((JitBypassTech::JitFlush, "JIT cache flushed")),
            "pcall" | "xpcall" => {
                Some((JitBypassTech::TraceDeopt, "pcall may deoptimize JIT traces"))
            }
            _ => None,
        }
    }

    /// Whether JIT bypass was detected.
    #[must_use]
    pub const fn is_bypassed(&self) -> bool {
        self.jit_disabled || !self.records.is_empty()
    }

    /// Number of distinct bypass techniques.
    #[must_use]
    pub fn technique_count(&self) -> usize {
        let set: HashSet<u8> = self.records.iter().map(|r| r.technique as u8).collect();
        set.len()
    }
}

// ---------------------------------------------------------------------------
// Memory Corruption
// ---------------------------------------------------------------------------

/// Memory corruption pattern kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemCorruptKind {
    /// Out-of-bounds read via FFI/buffer.
    OobRead,
    /// Out-of-bounds write.
    OobWrite,
    /// Use-after-free (lua GC object freed then accessed).
    UseAfterFree,
    /// Type confusion (mismatched FFI type casts).
    TypeConfusion,
    /// Integer overflow in index calculation.
    IntegerOverflow,
    /// Buffer overflow in string/table operations.
    BufferOverflow,
}

/// A memory corruption finding.
#[derive(Debug, Clone)]
pub struct MemCorruptRecord {
    pub address: u64,
    pub kind: MemCorruptKind,
    pub confidence: u8,
    pub notes: String,
}

/// Memory corruption pattern detector.
#[derive(Debug, Clone, Default)]
pub struct MemoryCorruption {
    pub records: Vec<MemCorruptRecord>,
    pub oob_count: usize,
    pub uaf_count: usize,
    pub type_confusion_count: usize,
}

impl MemoryCorruption {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory corruption finding.
    pub fn record(
        &mut self,
        address: u64,
        kind: MemCorruptKind,
        confidence: u8,
        notes: impl Into<String>,
    ) {
        match kind {
            MemCorruptKind::OobRead | MemCorruptKind::OobWrite | MemCorruptKind::BufferOverflow => {
                self.oob_count += 1;
            }
            MemCorruptKind::UseAfterFree => {
                self.uaf_count += 1;
            }
            MemCorruptKind::TypeConfusion => {
                self.type_confusion_count += 1;
            }
            MemCorruptKind::IntegerOverflow => {}
        }
        self.records.push(MemCorruptRecord {
            address,
            kind,
            confidence,
            notes: notes.into(),
        });
    }

    /// Whether dangerous memory corruption patterns exist.
    #[must_use]
    pub const fn is_dangerous(&self) -> bool {
        self.uaf_count > 0 || self.type_confusion_count > 0 || self.oob_count > 2
    }

    /// Records of a specific kind.
    #[must_use]
    pub fn of_kind(&self, kind: MemCorruptKind) -> Vec<&MemCorruptRecord> {
        self.records.iter().filter(|r| r.kind == kind).collect()
    }

    /// Maximum confidence.
    #[must_use]
    pub fn max_confidence(&self) -> u8 {
        self.records.iter().map(|r| r.confidence).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// LuaJIT ROP
// ---------------------------------------------------------------------------

/// A ROP-usable gadget found in JIT-compiled code.
#[derive(Debug, Clone)]
pub struct JitGadget {
    /// Address in JIT code buffer.
    pub address: u64,
    /// Gadget bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic sequence.
    pub mnemonic: String,
    /// Whether a `ret` / `retn` is the terminal instruction.
    pub terminates_with_ret: bool,
}

/// `LuaJIT` ROP gadget harvester.
///
/// `LuaJIT` allocates writable+executable memory for JIT-compiled code, making
/// it a useful source of ROP gadgets in sandboxed environments.
#[derive(Debug, Clone, Default)]
pub struct LuaJitROP {
    /// Found gadgets.
    pub gadgets: Vec<JitGadget>,
    /// JIT code regions registered.
    pub jit_regions: Vec<(u64, usize)>,
    /// Whether JIT mmap regions were detected as executable+writable.
    pub wx_detected: bool,
}

impl LuaJitROP {
    /// Create a new harvester.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a JIT code region.
    pub fn add_region(&mut self, base: u64, len: usize, is_wx: bool) {
        self.jit_regions.push((base, len));
        if is_wx {
            self.wx_detected = true;
        }
    }

    /// Scan bytes for trivial ROP gadgets (patterns ending in 0xC3 = RET).
    pub fn scan_for_gadgets(&mut self, bytes: &[u8], base: u64) {
        for i in 0..bytes.len() {
            if bytes[i] == 0xC3 && i > 0 {
                // Simple 1-byte-before-ret gadget
                let start = i.saturating_sub(4);
                let seq = &bytes[start..=i];
                self.gadgets.push(JitGadget {
                    address: base + start as u64,
                    bytes: seq.to_vec(),
                    mnemonic: format!("{} ; ret", bytes[start.max(i.saturating_sub(1))] as char),
                    terminates_with_ret: true,
                });
            }
        }
    }

    /// Number of gadgets harvested.
    #[must_use]
    pub const fn gadget_count(&self) -> usize {
        self.gadgets.len()
    }

    /// Whether ROP is feasible via JIT regions.
    #[must_use]
    pub const fn is_rop_feasible(&self) -> bool {
        self.wx_detected && self.gadget_count() > 5
    }

    /// Gadgets at or above a minimum number of useful bytes.
    #[must_use]
    pub fn gadgets_min_len(&self, min: usize) -> Vec<&JitGadget> {
        self.gadgets
            .iter()
            .filter(|g| g.bytes.len() >= min)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// A `LuaJIT` security finding.
#[derive(Debug, Clone)]
pub struct LuaJitFinding {
    pub address: u64,
    pub category: &'static str,
    pub message: String,
    pub severity: u8,
}

/// Top-level `LuaJIT` security analysis facade.
#[derive(Debug, Clone)]
pub struct LuaJitSecurity {
    /// Sandbox escape analysis.
    pub sandbox: SandboxEscape,
    /// FFI abuse analysis.
    pub ffi: FFIAbuse,
    /// JIT bypass analysis.
    pub jit_bypass: JitBypass,
    /// Memory corruption analysis.
    pub mem_corrupt: MemoryCorruption,
    /// ROP harvester.
    pub rop: LuaJitROP,
    /// Findings.
    pub findings: Vec<LuaJitFinding>,
    /// Total function calls analyzed.
    pub total_calls: usize,
}

impl Default for LuaJitSecurity {
    fn default() -> Self {
        Self::new()
    }
}

impl LuaJitSecurity {
    /// Create a new security analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sandbox: SandboxEscape::new(),
            ffi: FFIAbuse::new(),
            jit_bypass: JitBypass::new(),
            mem_corrupt: MemoryCorruption::new(),
            rop: LuaJitROP::new(),
            findings: Vec::new(),
            total_calls: 0,
        }
    }

    /// Analyze a function call by name.
    pub fn analyze_call(&mut self, address: u64, func: &str) {
        self.total_calls += 1;

        // Sandbox escape
        self.sandbox.record_call(address, func);
        if let Some((kind, sev)) = SandboxEscape::classify_call(func) {
            self.findings.push(LuaJitFinding {
                address,
                category: "sandbox",
                message: format!("Sandbox escape: {func} ({kind})"),
                severity: sev,
            });
        }

        // FFI
        if func == "require" || func.starts_with("ffi.") {
            if func == "require" { /* handled separately */
            } else {
                self.ffi.record_call(address, func, None);
                if let Some((_, risk)) = FFIAbuse::classify(func) {
                    self.findings.push(LuaJitFinding {
                        address,
                        category: "ffi",
                        message: format!("FFI call: {func}"),
                        severity: risk,
                    });
                }
            }
        }

        // JIT bypass
        if let Some((tech, desc)) = JitBypass::classify_call(func) {
            self.jit_bypass.record(address, tech, desc);
            self.findings.push(LuaJitFinding {
                address,
                category: "jit_bypass",
                message: format!("JIT bypass: {func}"),
                severity: 50,
            });
        }
    }

    /// Aggregate risk score (0–100).
    #[must_use]
    pub fn risk_score(&self) -> u8 {
        let mut s: u32 = 0;
        s += u32::from(self.sandbox.max_severity()) / 4;
        s += u32::from(self.ffi.max_risk()) / 4;
        s += u32::from(self.mem_corrupt.max_confidence()) / 4;
        if self.jit_bypass.jit_disabled {
            s += 10;
        }
        if self.rop.is_rop_feasible() {
            s += 25;
        }
        s.min(100) as u8
    }

    /// Whether the analysis indicates a security threat.
    #[must_use]
    pub fn is_threat(&self) -> bool {
        self.sandbox.is_dangerous()
            || self.ffi.is_dangerous()
            || self.mem_corrupt.is_dangerous()
            || self.rop.is_rop_feasible()
    }

    /// Findings above a severity threshold.
    #[must_use]
    pub fn findings_above(&self, threshold: u8) -> Vec<&LuaJitFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SandboxEscape ─────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_classify_os_execute() {
        assert_eq!(
            SandboxEscape::classify_call("os.execute"),
            Some((EscapeKind::OsExecute, 95))
        );
    }

    #[test]
    fn test_sandbox_classify_debug_lib() {
        assert_eq!(
            SandboxEscape::classify_call("debug.getinfo").map(|(k, _)| k),
            Some(EscapeKind::DebugLibrary)
        );
    }

    #[test]
    fn test_sandbox_classify_load() {
        assert_eq!(
            SandboxEscape::classify_call("load").map(|(k, _)| k),
            Some(EscapeKind::DynamicLoad)
        );
    }

    #[test]
    fn test_sandbox_classify_normal() {
        assert!(SandboxEscape::classify_call("math.sin").is_none());
        assert!(SandboxEscape::classify_call("table.insert").is_none());
    }

    #[test]
    fn test_sandbox_record_call() {
        let mut s = SandboxEscape::new();
        s.record_call(0x1000, "os.execute");
        assert!(s.is_dangerous());
        assert_eq!(s.max_severity(), 95);
    }

    #[test]
    fn test_sandbox_of_kind() {
        let mut s = SandboxEscape::new();
        s.record_call(0x1000, "dofile");
        s.record_call(0x1004, "loadfile");
        assert_eq!(s.of_kind(EscapeKind::FileExec).len(), 2);
    }

    #[test]
    fn test_sandbox_kinds_seen() {
        let mut s = SandboxEscape::new();
        s.record_call(0x1000, "rawget");
        assert!(s.kinds_seen.contains(&EscapeKind::RawAccess));
    }

    // ── FFIAbuse ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ffi_classify_load() {
        assert_eq!(
            FFIAbuse::classify("ffi.load"),
            Some((FfiCallType::LibLoad, 80))
        );
    }

    #[test]
    fn test_ffi_classify_cast() {
        assert_eq!(
            FFIAbuse::classify("ffi.cast").map(|(t, _)| t),
            Some(FfiCallType::TypeCast)
        );
    }

    #[test]
    fn test_ffi_classify_c_call() {
        assert_eq!(
            FFIAbuse::classify("ffi.C.malloc").map(|(t, _)| t),
            Some(FfiCallType::CStdLib)
        );
    }

    #[test]
    fn test_ffi_record_import() {
        let mut ffi = FFIAbuse::new();
        ffi.record_import();
        assert!(ffi.ffi_imported);
    }

    #[test]
    fn test_ffi_record_cast() {
        let mut ffi = FFIAbuse::new();
        ffi.record_import();
        ffi.record_call(0x1000, "ffi.cast", None);
        assert_eq!(ffi.cast_count, 1);
    }

    #[test]
    fn test_ffi_is_dangerous() {
        let mut ffi = FFIAbuse::new();
        ffi.record_import();
        ffi.record_call(0x1000, "ffi.cast", None);
        ffi.record_call(0x1004, "ffi.load", Some("libc.so".to_string()));
        ffi.record_call(0x1008, "ffi.cdef", None);
        assert!(ffi.is_dangerous());
    }

    #[test]
    fn test_ffi_loaded_libraries() {
        let mut ffi = FFIAbuse::new();
        ffi.record_call(0x1000, "ffi.load", Some("libssl.so".to_string()));
        assert!(ffi.loaded_libraries.contains("libssl.so"));
    }

    // ── JitBypass ─────────────────────────────────────────────────────────────

    #[test]
    fn test_jit_classify_off() {
        assert_eq!(
            JitBypass::classify_call("jit.off").map(|(t, _)| t),
            Some(JitBypassTech::JitOff)
        );
    }

    #[test]
    fn test_jit_classify_flush() {
        assert_eq!(
            JitBypass::classify_call("jit.flush").map(|(t, _)| t),
            Some(JitBypassTech::JitFlush)
        );
    }

    #[test]
    fn test_jit_record_off() {
        let mut jb = JitBypass::new();
        jb.record(0x1000, JitBypassTech::JitOff, "jit.off called");
        assert!(jb.jit_disabled);
        assert!(jb.is_bypassed());
    }

    #[test]
    fn test_jit_technique_count() {
        let mut jb = JitBypass::new();
        jb.record(0x1000, JitBypassTech::JitOff, "");
        jb.record(0x1004, JitBypassTech::JitFlush, "");
        jb.record(0x1008, JitBypassTech::JitOff, ""); // duplicate kind
        assert_eq!(jb.technique_count(), 2);
    }

    #[test]
    fn test_jit_pcall_deopt() {
        let mut jb = JitBypass::new();
        jb.record(0x1000, JitBypassTech::TraceDeopt, "pcall");
        assert_eq!(jb.trace_count_aborted, 1);
    }

    // ── MemoryCorruption ──────────────────────────────────────────────────────

    #[test]
    fn test_mem_record_oob() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x1000, MemCorruptKind::OobRead, 80, "buffer overread");
        mc.record(0x1004, MemCorruptKind::OobWrite, 90, "buffer overwrite");
        assert_eq!(mc.oob_count, 2);
    }

    #[test]
    fn test_mem_record_uaf() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x2000, MemCorruptKind::UseAfterFree, 85, "gc freed");
        assert_eq!(mc.uaf_count, 1);
        assert!(mc.is_dangerous());
    }

    #[test]
    fn test_mem_record_type_confusion() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x3000, MemCorruptKind::TypeConfusion, 75, "ffi miscast");
        assert_eq!(mc.type_confusion_count, 1);
        assert!(mc.is_dangerous());
    }

    #[test]
    fn test_mem_of_kind() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x1000, MemCorruptKind::OobRead, 70, "");
        mc.record(0x2000, MemCorruptKind::OobRead, 75, "");
        assert_eq!(mc.of_kind(MemCorruptKind::OobRead).len(), 2);
    }

    #[test]
    fn test_mem_max_confidence() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x1000, MemCorruptKind::OobRead, 60, "");
        mc.record(0x2000, MemCorruptKind::UseAfterFree, 90, "");
        assert_eq!(mc.max_confidence(), 90);
    }

    // ── LuaJitROP ─────────────────────────────────────────────────────────────

    #[test]
    fn test_rop_add_region() {
        let mut rop = LuaJitROP::new();
        rop.add_region(0x10000, 0x1000, true);
        assert!(rop.wx_detected);
        assert_eq!(rop.jit_regions.len(), 1);
    }

    #[test]
    fn test_rop_scan_gadgets() {
        let mut rop = LuaJitROP::new();
        // Bytes with 0xC3 (RET) at positions 2 and 5
        let bytes = [0x48, 0x89, 0xC3, 0x90, 0x90, 0xC3];
        rop.scan_for_gadgets(&bytes, 0x1000);
        assert!(rop.gadget_count() >= 2);
    }

    #[test]
    fn test_rop_is_feasible() {
        let mut rop = LuaJitROP::new();
        rop.add_region(0x10000, 0x1000, true);
        // Insert enough gadgets manually
        for i in 0..6u64 {
            rop.gadgets.push(JitGadget {
                address: 0x10000 + i * 8,
                bytes: vec![0xC3],
                mnemonic: "ret".to_string(),
                terminates_with_ret: true,
            });
        }
        assert!(rop.is_rop_feasible());
    }

    #[test]
    fn test_rop_not_feasible_no_wx() {
        let mut rop = LuaJitROP::new();
        rop.add_region(0x10000, 0x1000, false);
        for i in 0..6u64 {
            rop.gadgets.push(JitGadget {
                address: i,
                bytes: vec![0xC3],
                mnemonic: "ret".to_string(),
                terminates_with_ret: true,
            });
        }
        assert!(!rop.is_rop_feasible()); // wx_detected = false
    }

    // ── LuaJitSecurity ────────────────────────────────────────────────────────

    #[test]
    fn test_security_analyze_os_execute() {
        let mut sec = LuaJitSecurity::new();
        sec.analyze_call(0x1000, "os.execute");
        assert!(sec.sandbox.is_dangerous());
        assert!(!sec.findings.is_empty());
    }

    #[test]
    fn test_security_analyze_jit_off() {
        let mut sec = LuaJitSecurity::new();
        sec.analyze_call(0x1000, "jit.off");
        assert!(sec.jit_bypass.jit_disabled);
    }

    #[test]
    fn test_security_total_calls() {
        let mut sec = LuaJitSecurity::new();
        sec.analyze_call(0x1000, "math.sin");
        sec.analyze_call(0x1004, "table.insert");
        assert_eq!(sec.total_calls, 2);
    }

    #[test]
    fn test_security_risk_score_zero_initially() {
        let sec = LuaJitSecurity::new();
        assert_eq!(sec.risk_score(), 0);
        assert!(!sec.is_threat());
    }

    #[test]
    fn test_security_findings_above() {
        let mut sec = LuaJitSecurity::new();
        sec.analyze_call(0x1000, "os.execute");
        let high = sec.findings_above(90);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_security_is_threat_with_uaf() {
        let mut sec = LuaJitSecurity::new();
        sec.mem_corrupt
            .record(0x1000, MemCorruptKind::UseAfterFree, 90, "");
        assert!(sec.is_threat());
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_sandbox_setfenv_detection() {
        let mut s = SandboxEscape::new();
        s.record_call(0x1000, "setfenv");
        assert!(s.kinds_seen.contains(&EscapeKind::Setfenv));
        assert_eq!(s.of_kind(EscapeKind::Setfenv).len(), 1);
    }

    #[test]
    fn test_ffi_cdef_not_dangerous_alone() {
        let mut ffi = FFIAbuse::new();
        ffi.record_import();
        ffi.record_call(0x1000, "ffi.cdef", None);
        // Only 1 call but ffi_imported — is_dangerous requires calls.len() > 2 OR cast_count > 0
        assert!(!ffi.is_dangerous()); // only 1 call, cast_count = 0
    }

    #[test]
    fn test_jit_not_bypassed_initially() {
        let jb = JitBypass::new();
        assert!(!jb.is_bypassed());
    }

    #[test]
    fn test_rop_gadgets_min_len() {
        let mut rop = LuaJitROP::new();
        rop.gadgets.push(JitGadget {
            address: 0,
            bytes: vec![0x90, 0xC3],
            mnemonic: "nop;ret".into(),
            terminates_with_ret: true,
        });
        rop.gadgets.push(JitGadget {
            address: 2,
            bytes: vec![0xC3],
            mnemonic: "ret".into(),
            terminates_with_ret: true,
        });
        assert_eq!(rop.gadgets_min_len(2).len(), 1);
    }

    #[test]
    fn test_security_ffi_analyze_call() {
        let mut sec = LuaJitSecurity::new();
        sec.analyze_call(0x1000, "ffi.cast");
        assert!(!sec.findings.is_empty());
    }

    #[test]
    fn test_mem_not_dangerous_single_oob() {
        let mut mc = MemoryCorruption::new();
        mc.record(0x1000, MemCorruptKind::OobRead, 60, "");
        mc.record(0x1004, MemCorruptKind::OobWrite, 60, "");
        // oob_count = 2, which is not > 2 → not dangerous
        assert!(!mc.is_dangerous());
    }
}
