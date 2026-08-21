//! `exception_based_antidebug` — Detect and neutralise exception-based
//! anti-debugging techniques.
//!
//! Covers:
//! - SEH-based tricks (INT3 inside exception handler, single-step trap)
//! - VEH-based checks (vectored exception handler presence tests)
//! - INT3 / INT1 / INT 2D abuse
//! - PUSHF + trap-flag setting
//! - `OutputDebugString` + `GetLastError` trick
//! - `RaiseException` with magic codes

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── ExceptionCheckKind ────────────────────────────────────────────────────────

/// Specific anti-debug technique based on exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionCheckKind {
    /// `INT3` (0xCC) used inside code that relies on the debugger swallowing it.
    Int3Breakpoint,
    /// `INT1` (0xF1) — single-step trap.
    Int1Icebp,
    /// `INT 0x2D` — `DbgBreakPoint` in kernel; debugger swallows the exception.
    Int2D,
    /// PUSHF + OR byte [esp], 0x100 + POPF — sets Trap Flag.
    TrapFlagSet,
    /// SEH + divide-by-zero / #DE to detect debugger.
    SehDivideByZero,
    /// SEH + general-protection fault.
    SehGpFault,
    /// SEH with `INT3` inside the handler body.
    SehInt3Handler,
    /// `OutputDebugString` + `GetLastError` delta check.
    OutputDebugStringTrick,
    /// `RaiseException` with a magic code that a debugger would handle.
    RaiseExceptionMagic,
    /// VEH (Vectored Exception Handler) presence test.
    VehPresenceTest,
}

impl std::fmt::Display for ExceptionCheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ExceptionCheckKind {
    /// Returns `true` if the technique inserts a software breakpoint instruction.
    #[must_use]
    pub const fn uses_breakpoint_instruction(self) -> bool {
        matches!(self, Self::Int3Breakpoint | Self::Int1Icebp | Self::Int2D | Self::SehInt3Handler)
    }

    /// Returns `true` for techniques that rely on the Windows SEH chain.
    #[must_use]
    pub const fn uses_seh(self) -> bool {
        matches!(
            self,
            Self::SehDivideByZero | Self::SehGpFault | Self::SehInt3Handler
        )
    }
}

// ── SehTrick ──────────────────────────────────────────────────────────────────

/// A single detected SEH-based anti-debug trick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SehTrick {
    /// Byte offset of the first instruction of the trick.
    pub offset: usize,
    /// Kind of trick.
    pub kind: ExceptionCheckKind,
    /// Byte span of the trick.
    pub span_bytes: usize,
    /// Confidence in [0, 100].
    pub confidence: u32,
    /// Human-readable summary.
    pub description: String,
    /// Offset of the SEH handler, if known (relative to binary start).
    pub handler_offset: Option<usize>,
}

impl SehTrick {
    /// Create a new [`SehTrick`].
    #[must_use]
    pub fn new(
        kind: ExceptionCheckKind,
        offset: usize,
        span_bytes: usize,
        confidence: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            offset,
            kind,
            span_bytes,
            confidence: confidence.min(100),
            description: description.into(),
            handler_offset: None,
        }
    }

    /// Set the known handler offset.
    #[must_use]
    pub const fn with_handler(mut self, handler: usize) -> Self {
        self.handler_offset = Some(handler);
        self
    }
}

// ── SehPatch ──────────────────────────────────────────────────────────────────

/// Patch strategy for an exception-based anti-debug trick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SehPatchStrategy {
    /// Replace triggering instruction(s) with NOPs.
    Nop,
    /// Replace INT3 with NOPW (2-byte NOP).
    NopInt3,
    /// Force the conditional branch after the exception check to always skip the
    /// detection branch.
    ForceJump,
    /// Patch the comparison so the debugger-present condition is never true.
    PatchComparison,
}

/// A binary patch that neutralises a detected exception-based trick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SehPatch {
    /// The underlying trick this patch targets.
    pub trick: SehTrick,
    /// Strategy applied.
    pub strategy: SehPatchStrategy,
    /// Byte offset at which `patch_bytes` should be written.
    pub patch_offset: usize,
    /// Original bytes (for rollback).
    pub original_bytes: Vec<u8>,
    /// Replacement bytes.
    pub patch_bytes: Vec<u8>,
    /// Human-readable description.
    pub description: String,
}

impl SehPatch {
    /// Create a new patch.
    #[must_use]
    pub fn new(
        trick: SehTrick,
        strategy: SehPatchStrategy,
        patch_offset: usize,
        original_bytes: Vec<u8>,
        patch_bytes: Vec<u8>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            trick,
            strategy,
            patch_offset,
            original_bytes,
            patch_bytes,
            description: description.into(),
        }
    }

    /// Apply patch to `binary`.
    pub fn apply(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        let end = self.patch_offset + self.patch_bytes.len();
        if end > binary.len() {
            return Err(format!("patch at 0x{:X}: buffer too short", self.patch_offset));
        }
        binary[self.patch_offset..end].copy_from_slice(&self.patch_bytes);
        Ok(())
    }

    /// Roll back patch.
    pub fn rollback(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        let end = self.patch_offset + self.original_bytes.len();
        if end > binary.len() {
            return Err(format!("rollback at 0x{:X}: buffer too short", self.patch_offset));
        }
        binary[self.patch_offset..end].copy_from_slice(&self.original_bytes);
        Ok(())
    }
}

// ── ExceptionRoute ────────────────────────────────────────────────────────────

/// Describes what happens at each exit of an exception-based check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRoute {
    /// Source offset (branch / call instruction).
    pub from: usize,
    /// Destination offset.
    pub to: usize,
    /// Meaning of this route.
    pub label: String,
}

impl ExceptionRoute {
    /// Create a new route.
    #[must_use]
    pub fn new(from: usize, to: usize, label: impl Into<String>) -> Self {
        Self { from, to, label: label.into() }
    }
}

// ── Byte-pattern database ─────────────────────────────────────────────────────

struct ExcPattern {
    kind: ExceptionCheckKind,
    pattern: &'static [u8],
    mask: &'static [u8],
    confidence: u32,
    description: &'static str,
    patch_bytes: &'static [u8],
    strategy: SehPatchStrategy,
}

fn exc_patterns() -> Vec<ExcPattern> {
    vec![
        // INT3 (single byte 0xCC)
        ExcPattern {
            kind: ExceptionCheckKind::Int3Breakpoint,
            pattern: &[0xCC],
            mask: &[0xFF],
            confidence: 75,
            description: "INT3 software breakpoint (0xCC)",
            patch_bytes: &[0x90],
            strategy: SehPatchStrategy::NopInt3,
        },
        // INT 1 / ICEBP (0xF1)
        ExcPattern {
            kind: ExceptionCheckKind::Int1Icebp,
            pattern: &[0xF1],
            mask: &[0xFF],
            confidence: 80,
            description: "INT 1 (ICEBP) anti-debug trap",
            patch_bytes: &[0x90],
            strategy: SehPatchStrategy::NopInt3,
        },
        // INT 0x2D (CD 2D)
        ExcPattern {
            kind: ExceptionCheckKind::Int2D,
            pattern: &[0xCD, 0x2D],
            mask: &[0xFF, 0xFF],
            confidence: 90,
            description: "INT 0x2D — DbgBreakPoint anti-debug trick",
            patch_bytes: &[0x90, 0x90],
            strategy: SehPatchStrategy::Nop,
        },
        // PUSHF; OR [esp], 0x100; POPF  (Trap Flag set)
        // 9C 81 04 24 00 01 00 00 9D
        ExcPattern {
            kind: ExceptionCheckKind::TrapFlagSet,
            pattern: &[0x9C, 0x81, 0x04, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9D],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 92,
            description: "PUSHF / set TF / POPF — Trap Flag anti-debug",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            strategy: SehPatchStrategy::Nop,
        },
        // PUSHF; OR byte [esp], 0x01; POPF  (shorter 16-bit TF form)
        // 9C 80 0C 24 01 9D
        ExcPattern {
            kind: ExceptionCheckKind::TrapFlagSet,
            pattern: &[0x9C, 0x80, 0x0C, 0x24, 0x01, 0x9D],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 88,
            description: "PUSHF / OR byte TF set / POPF",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            strategy: SehPatchStrategy::Nop,
        },
        // DIV 0 trick: XOR ecx,ecx; DIV ecx
        // 33 C9 F7 F1
        ExcPattern {
            kind: ExceptionCheckKind::SehDivideByZero,
            pattern: &[0x33, 0xC9, 0xF7, 0xF1],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 85,
            description: "XOR ecx,ecx + DIV ecx — divide-by-zero SEH trick",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90],
            strategy: SehPatchStrategy::Nop,
        },
        // RaiseException with magic code 0x40010006 (DBG_PRINTEXCEPTION)
        // push 0x40010006 — 68 06 00 01 40
        ExcPattern {
            kind: ExceptionCheckKind::RaiseExceptionMagic,
            pattern: &[0x68, 0x06, 0x00, 0x01, 0x40],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 82,
            description: "push DBG_PRINTEXCEPTION code (0x40010006)",
            patch_bytes: &[0x68, 0x00, 0x00, 0x00, 0x00],
            strategy: SehPatchStrategy::PatchComparison,
        },
        // RaiseException magic 0xC0000005 (ACCESS_VIOLATION)
        ExcPattern {
            kind: ExceptionCheckKind::RaiseExceptionMagic,
            pattern: &[0x68, 0x05, 0x00, 0x00, 0xC0],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 78,
            description: "push STATUS_ACCESS_VIOLATION as RaiseException code",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90],
            strategy: SehPatchStrategy::Nop,
        },
    ]
}

// ── ExceptionAntidebug ────────────────────────────────────────────────────────

/// Scans binary data for exception-based anti-debug patterns and generates
/// [`SehPatch`] instances to neutralise them.
pub struct ExceptionAntidebug {
    /// Minimum confidence for reporting a detection.
    pub min_confidence: u32,
    /// Whether to also search for API import strings.
    pub scan_api_strings: bool,
}

impl Default for ExceptionAntidebug {
    fn default() -> Self {
        Self { min_confidence: 70, scan_api_strings: true }
    }
}

impl ExceptionAntidebug {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override minimum confidence.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Scan `binary` for exception-based anti-debug tricks.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<SehTrick> {
        let mut tricks: Vec<SehTrick> = Vec::new();

        for ep in &exc_patterns() {
            if ep.confidence < self.min_confidence {
                continue;
            }
            for offset in masked_scan(binary, ep.pattern, ep.mask) {
                tricks.push(SehTrick::new(
                    ep.kind,
                    offset,
                    ep.pattern.len(),
                    ep.confidence,
                    ep.description,
                ));
            }
        }

        if self.scan_api_strings {
            tricks.extend(self.scan_api_strings_internal(binary));
        }

        tricks.sort_by_key(|t| t.offset);
        tricks
    }

    /// Generate patches for all detected tricks.
    #[must_use]
    pub fn generate_patches(&self, binary: &[u8]) -> Vec<SehPatch> {
        let tricks = self.scan(binary);
        let patterns = exc_patterns();
        let mut patches: Vec<SehPatch> = Vec::new();

        for trick in tricks {
            if let Some(ep) = patterns.iter().find(|ep| {
                ep.kind == trick.kind
                    && ep.pattern.len() == trick.span_bytes
                    && trick.offset + ep.patch_bytes.len() <= binary.len()
            }) {
                let orig_end = trick.offset + ep.patch_bytes.len();
                let original_bytes = binary[trick.offset..orig_end].to_vec();
                patches.push(SehPatch::new(
                    trick.clone(),
                    ep.strategy,
                    trick.offset,
                    original_bytes,
                    ep.patch_bytes.to_vec(),
                    format!("neutralised {} at 0x{:X}", trick.kind, trick.offset),
                ));
            } else {
                let end = (trick.offset + trick.span_bytes).min(binary.len());
                let span = end - trick.offset;
                if span == 0 {
                    continue;
                }
                let original_bytes = binary[trick.offset..end].to_vec();
                patches.push(SehPatch::new(
                    trick.clone(),
                    SehPatchStrategy::Nop,
                    trick.offset,
                    original_bytes,
                    vec![0x90u8; span],
                    format!("NOP-patched {} at 0x{:X}", trick.kind, trick.offset),
                ));
            }
        }

        patches
    }

    /// Apply all patches to `binary`.  Returns `(applied, errors)`.
    pub fn neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>) {
        let patches = self.generate_patches(binary);
        let mut applied = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for patch in &patches {
            match patch.apply(binary) {
                Ok(()) => applied += 1,
                Err(e) => errors.push(e),
            }
        }
        (applied, errors)
    }

    /// Build an [`ExceptionRoute`] map from detected tricks.
    ///
    /// Each trick emits a "trigger" route (how the exception fires) and a
    /// "bypass" route (what happens when the check fails to detect a debugger).
    #[must_use]
    pub fn extract_routes(tricks: &[SehTrick]) -> Vec<ExceptionRoute> {
        let mut routes: Vec<ExceptionRoute> = Vec::new();
        for trick in tricks {
            routes.push(ExceptionRoute::new(
                trick.offset,
                trick.offset + trick.span_bytes,
                format!("{} — trigger at 0x{:X}", trick.kind, trick.offset),
            ));
            if let Some(handler) = trick.handler_offset {
                routes.push(ExceptionRoute::new(
                    trick.offset,
                    handler,
                    format!("SEH dispatch to handler at 0x{handler:X}"),
                ));
            }
        }
        routes
    }

    /// Generate a Frida script to hook exception-based checks at runtime.
    #[must_use]
    pub fn frida_script(tricks: &[SehTrick]) -> String {
        let mut script =
            String::from("// Frida exception anti-debug bypass — exception_based_antidebug\n\n");

        let has = |k: ExceptionCheckKind| tricks.iter().any(|t| t.kind == k);

        if has(ExceptionCheckKind::OutputDebugStringTrick) {
            script.push_str(
                "// OutputDebugString trick: hook GetLastError to return consistent value.\n\
                 Interceptor.attach(Module.findExportByName(null, 'GetLastError'), {\n\
                 \tonLeave(retval) { retval.replace(0); }\n\
                 });\n\n",
            );
        }

        if has(ExceptionCheckKind::RaiseExceptionMagic) {
            script.push_str(
                "// RaiseException magic: swallow known anti-debug exception codes.\n\
                 Process.setExceptionHandler(function(details) {\n\
                 \tconst MAGIC = [0x40010006, 0xC0000005];\n\
                 \tif (MAGIC.includes(details.nativeContext.pc)) return true;\n\
                 \treturn false;\n\
                 });\n\n",
            );
        }

        if has(ExceptionCheckKind::Int3Breakpoint) || has(ExceptionCheckKind::Int2D) {
            script.push_str(
                "// INT3/INT2D: register exception callback to skip over breakpoints.\n\
                 Process.setExceptionHandler(function(details) {\n\
                 \tif (details.type === 'breakpoint') {\n\
                 \t\tdetails.context.pc = details.context.pc.add(1);\n\
                 \t\treturn true;\n\
                 \t}\n\
                 \treturn false;\n\
                 });\n\n",
            );
        }

        script
    }

    /// Summary histogram by kind.
    #[must_use]
    pub fn trick_histogram(tricks: &[SehTrick]) -> HashMap<ExceptionCheckKind, usize> {
        let mut map: HashMap<ExceptionCheckKind, usize> = HashMap::new();
        for t in tricks {
            *map.entry(t.kind).or_insert(0) += 1;
        }
        map
    }

    fn scan_api_strings_internal(&self, binary: &[u8]) -> Vec<SehTrick> {
        let entries: &[(&[u8], ExceptionCheckKind, &str)] = &[
            (b"OutputDebugStringA", ExceptionCheckKind::OutputDebugStringTrick, "OutputDebugStringA import"),
            (b"OutputDebugStringW", ExceptionCheckKind::OutputDebugStringTrick, "OutputDebugStringW import"),
            (b"RaiseException", ExceptionCheckKind::RaiseExceptionMagic, "RaiseException import"),
            (b"AddVectoredExceptionHandler", ExceptionCheckKind::VehPresenceTest, "VEH AddVectoredExceptionHandler import"),
        ];
        let mut tricks: Vec<SehTrick> = Vec::new();
        for (sig, kind, desc) in entries {
            let mut pos = 0usize;
            while pos + sig.len() <= binary.len() {
                if &binary[pos..pos + sig.len()] == *sig {
                    tricks.push(SehTrick::new(*kind, pos, sig.len(), 72, *desc));
                    pos += sig.len();
                } else {
                    pos += 1;
                }
            }
        }
        tricks
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in 0..=(data.len() - plen) {
        let hit = pattern
            .iter()
            .enumerate()
            .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
        if hit {
            out.push(pos);
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_int3() {
        let binary = vec![0x90, 0xCC, 0x90];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::Int3Breakpoint));
    }

    #[test]
    fn test_scan_int1_icebp() {
        let binary = vec![0xF1, 0x90];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::Int1Icebp));
    }

    #[test]
    fn test_scan_int2d() {
        let binary = vec![0x90, 0xCD, 0x2D, 0x90];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::Int2D));
    }

    #[test]
    fn test_scan_trap_flag() {
        let binary = vec![0x9C, 0x80, 0x0C, 0x24, 0x01, 0x9D];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::TrapFlagSet));
    }

    #[test]
    fn test_scan_div_zero() {
        let binary = vec![0x33, 0xC9, 0xF7, 0xF1];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::SehDivideByZero));
    }

    #[test]
    fn test_scan_raise_exception_magic() {
        let binary = vec![0x68, 0x06, 0x00, 0x01, 0x40];
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::RaiseExceptionMagic));
    }

    #[test]
    fn test_scan_api_string_ods() {
        let binary = b"OutputDebugStringA\x00";
        let ad = ExceptionAntidebug::new();
        let tricks = ad.scan(binary);
        assert!(tricks.iter().any(|t| t.kind == ExceptionCheckKind::OutputDebugStringTrick));
    }

    #[test]
    fn test_generate_patches_nop_int3() {
        let binary = vec![0x90, 0xCC, 0x90];
        let ad = ExceptionAntidebug::new();
        let patches = ad.generate_patches(&binary);
        assert!(!patches.is_empty());
        let p = patches.iter().find(|p| p.trick.kind == ExceptionCheckKind::Int3Breakpoint).unwrap();
        assert_eq!(p.patch_bytes, vec![0x90]);
    }

    #[test]
    fn test_apply_patch_int3() {
        let mut binary = vec![0x90, 0xCC, 0x90];
        let ad = ExceptionAntidebug::new();
        let patches = ad.generate_patches(&binary);
        for p in &patches {
            if p.trick.kind == ExceptionCheckKind::Int3Breakpoint {
                p.apply(&mut binary).unwrap();
            }
        }
        assert_eq!(binary[1], 0x90);
    }

    #[test]
    fn test_neutralize_returns_count() {
        let mut binary = vec![0xCC, 0xCD, 0x2D, 0xF1];
        let ad = ExceptionAntidebug::new();
        let (applied, errors) = ad.neutralize(&mut binary);
        assert!(applied > 0);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_rollback_patch() {
        let orig = vec![0x90, 0xCC, 0x90];
        let mut binary = orig.clone();
        let ad = ExceptionAntidebug::new();
        let patches = ad.generate_patches(&binary);
        for p in &patches {
            p.apply(&mut binary).unwrap();
        }
        for p in patches.iter().rev() {
            p.rollback(&mut binary).unwrap();
        }
        assert_eq!(binary, orig);
    }

    #[test]
    fn test_extract_routes() {
        let tricks = vec![SehTrick::new(
            ExceptionCheckKind::Int3Breakpoint,
            10,
            1,
            80,
            "test",
        )
        .with_handler(50)];
        let routes = ExceptionAntidebug::extract_routes(&tricks);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].from, 10);
        assert_eq!(routes[1].to, 50);
    }

    #[test]
    fn test_frida_script_output_debug_string() {
        let tricks = vec![SehTrick::new(
            ExceptionCheckKind::OutputDebugStringTrick,
            0,
            18,
            72,
            "test",
        )];
        let script = ExceptionAntidebug::frida_script(&tricks);
        assert!(script.contains("GetLastError"));
    }

    #[test]
    fn test_frida_script_int3() {
        let tricks = vec![SehTrick::new(ExceptionCheckKind::Int3Breakpoint, 0, 1, 75, "test")];
        let script = ExceptionAntidebug::frida_script(&tricks);
        assert!(script.contains("breakpoint"));
    }

    #[test]
    fn test_trick_histogram() {
        let tricks = vec![
            SehTrick::new(ExceptionCheckKind::Int3Breakpoint, 0, 1, 80, "a"),
            SehTrick::new(ExceptionCheckKind::Int3Breakpoint, 5, 1, 80, "b"),
            SehTrick::new(ExceptionCheckKind::Int2D, 10, 2, 90, "c"),
        ];
        let hist = ExceptionAntidebug::trick_histogram(&tricks);
        assert_eq!(hist[&ExceptionCheckKind::Int3Breakpoint], 2);
        assert_eq!(hist[&ExceptionCheckKind::Int2D], 1);
    }

    #[test]
    fn test_confidence_threshold_filters() {
        let binary = vec![0xCC]; // INT3 = confidence 75
        let ad = ExceptionAntidebug::new().with_min_confidence(80);
        let tricks = ad.scan(&binary);
        assert!(tricks.iter().all(|t| t.confidence >= 80));
    }

    #[test]
    fn test_check_kind_predicates() {
        assert!(ExceptionCheckKind::Int3Breakpoint.uses_breakpoint_instruction());
        assert!(!ExceptionCheckKind::TrapFlagSet.uses_breakpoint_instruction());
        assert!(ExceptionCheckKind::SehDivideByZero.uses_seh());
        assert!(!ExceptionCheckKind::Int2D.uses_seh());
    }

    #[test]
    fn test_patch_apply_too_short() {
        let trick = SehTrick::new(ExceptionCheckKind::Int3Breakpoint, 100, 1, 80, "t");
        let patch = SehPatch::new(
            trick,
            SehPatchStrategy::Nop,
            100,
            vec![0xCC],
            vec![0x90],
            "test",
        );
        let mut binary = vec![0u8; 10];
        assert!(patch.apply(&mut binary).is_err());
    }
}
