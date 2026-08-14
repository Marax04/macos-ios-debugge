//! `custom_vm_identifier` — Heuristic identification of custom bytecode VMs.
//!
//! Provides:
//! * [`VmKindClassification`] — distinguish bytecode interpreter / JIT / trampoline
//! * [`FetchDecodeExecutePattern`] — structural FDE loop recognition
//! * [`CustomVmIdentifier`] — main analysis entry point
//! * Handler table detection, dispatch loop heuristics, opcode width inference

#![allow(dead_code)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// VM kind classification
// ─────────────────────────────────────────────────────────────────────────────

/// High-level kind of a code-dispatching pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmKind {
    /// Classic bytecode interpreter with a fetch-decode-execute loop.
    BytecodeInterpreter,
    /// JIT compiler: generates native code at runtime.
    JitCompiler,
    /// Trampoline: thin wrapper that redirects to another function.
    Trampoline,
    /// Switch-dispatch interpreter (specialized form, often higher performance).
    SwitchDispatchInterpreter,
    /// Threaded interpreter (computed goto, GCC extension).
    ThreadedInterpreter,
    /// Could not be classified.
    Unknown,
}

impl std::fmt::Display for VmKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BytecodeInterpreter => "BytecodeInterpreter",
            Self::JitCompiler => "JitCompiler",
            Self::Trampoline => "Trampoline",
            Self::SwitchDispatchInterpreter => "SwitchDispatchInterpreter",
            Self::ThreadedInterpreter => "ThreadedInterpreter",
            Self::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FDE pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence of a Fetch-Decode-Execute loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchDecodeExecutePattern {
    /// Address of the main dispatch / fetch loop head.
    pub loop_head: u64,
    /// Address where the opcode is fetched from the bytecode stream.
    pub fetch_address: u64,
    /// Address of the opcode decode operation (comparison / switch).
    pub decode_address: u64,
    /// Addresses of all identified execute branches (one per opcode).
    pub execute_branches: Vec<u64>,
    /// Inferred instruction pointer register name (e.g. `"rsi"`, `"r12"`).
    pub ip_register: String,
    /// Inferred opcode width (1 or 2 bytes).
    pub opcode_width: u8,
    /// Confidence in this FDE identification.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler table candidate
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate handler table found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerTableCandidate {
    /// Virtual address of the table start.
    pub address: u64,
    /// Number of entries.
    pub entry_count: usize,
    /// Pointer size (4 or 8 bytes).
    pub ptr_size: u8,
    /// Addresses of the handler functions referenced.
    pub handler_addresses: Vec<u64>,
    /// Confidence that this is a real handler table.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// VM identification result
// ─────────────────────────────────────────────────────────────────────────────

/// Full result of the custom VM identification analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomVmResult {
    /// Classified kind.
    pub kind: VmKind,
    /// FDE loop pattern (if found).
    pub fde_pattern: Option<FetchDecodeExecutePattern>,
    /// Handler table candidates (sorted by confidence).
    pub handler_tables: Vec<HandlerTableCandidate>,
    /// Inferred number of distinct opcodes.
    pub estimated_opcode_count: u32,
    /// Inferred bytecode IP register.
    pub ip_register: Option<String>,
    /// Whether the interpreter uses computed-goto (threaded).
    pub is_threaded: bool,
    /// Overall confidence.
    pub overall_confidence: f32,
    /// Detailed evidence notes.
    pub evidence: Vec<String>,
}

impl CustomVmResult {
    pub fn unknown() -> Self {
        Self {
            kind: VmKind::Unknown,
            fde_pattern: None,
            handler_tables: Vec::new(),
            estimated_opcode_count: 0,
            ip_register: None,
            is_threaded: false,
            overall_confidence: 0.0,
            evidence: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CustomVmIdentifier
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies custom bytecode VMs using structural heuristics.
pub struct CustomVmIdentifier {
    /// Minimum confidence to include a finding.
    pub min_confidence: f32,
    /// Assumed pointer size of the target (4 or 8).
    pub ptr_size: u8,
    /// Expected base address range (min, max) for valid code pointers.
    pub code_range: (u64, u64),
}

impl Default for CustomVmIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CustomVmIdentifier {
    /// Create with default settings for an x86-64 userspace binary.
    pub fn new() -> Self {
        Self {
            min_confidence: 0.50,
            ptr_size: 8,
            code_range: (0x0000_0000_4000_0000, 0x0000_7FFF_FFFF_FFFF),
        }
    }

    pub fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    pub fn with_ptr_size(mut self, n: u8) -> Self {
        self.ptr_size = n;
        self
    }

    pub fn with_code_range(mut self, min: u64, max: u64) -> Self {
        self.code_range = (min, max);
        self
    }

    // ── JIT detection ─────────────────────────────────────────────────────────

    /// Detect JIT compiler characteristics.
    ///
    /// JIT compilers typically:
    /// 1. Call `mmap`/`VirtualAlloc` (rwx) early.
    /// 2. Emit code by storing bytes to a writable/executable buffer.
    /// 3. Cast the buffer to a function pointer and call it.
    pub fn detect_jit(&self, bytes: &[u8]) -> (bool, f32) {
        let mut score = 0.0f32;

        // mmap syscall (NR = 9 on Linux x64) or VirtualAlloc IAT call prefix
        let has_mmap = bytes.windows(5).any(|w| {
            w == [0xB8, 0x09, 0x00, 0x00, 0x00] // mov eax, 9 (mmap)
        });
        // VirtualAlloc: detect via common import thunk pattern
        let has_valloc = bytes.windows(2).any(|w| w == [0xFF, 0x15]); // call [IAT]

        if has_mmap { score += 0.30; }
        if has_valloc { score += 0.15; }

        // Pattern: store byte to a pointer register (RDI / RSI / R10 used as write cursor)
        let write_cursor_stores = bytes
            .windows(3)
            .filter(|w| {
                // MOV [reg], al/ax/eax/rax (C6 07, 66 89 07, 89 07, 48 89 07)
                (w[0] == 0xC6 && w[1] == 0x07)
                    || (w[0] == 0x89 && w[1] == 0x07)
                    || (w[0] == 0x48 && w[1] == 0x89 && w[2] == 0x07)
            })
            .count();
        if write_cursor_stores >= 5 {
            score += 0.25;
        }

        // Pattern: increment a write-cursor pointer register (add rdi, imm8)
        let ptr_increments = bytes
            .windows(3)
            .filter(|w| w[0] == 0x48 && w[1] == 0x83 && (w[2] == 0xC7 || w[2] == 0xC6))
            .count();
        if ptr_increments >= 5 {
            score += 0.15;
        }

        // Direct call through a register at the end → calling emitted code
        let call_reg = bytes
            .windows(2)
            .filter(|w| w[0] == 0xFF && matches!(w[1], 0xD0..=0xD7))
            .count();
        if call_reg >= 1 {
            score += 0.10;
        }

        let is_jit = score >= 0.40;
        (is_jit, score.min(1.0))
    }

    // ── Trampoline detection ──────────────────────────────────────────────────

    /// Detect if the code region is a simple trampoline.
    ///
    /// Trampolines are short stubs (≤ 32 bytes) that do one of:
    /// * `jmp [target]`
    /// * `push target; ret`
    /// * `mov rax, target; jmp rax`
    pub fn detect_trampoline(&self, bytes: &[u8]) -> (bool, f32) {
        if bytes.len() > 64 {
            return (false, 0.0);
        }

        // jmp rel32 (E9 xx xx xx xx)
        if bytes.len() >= 5 && bytes[0] == 0xE9 {
            return (true, 0.90);
        }
        // jmp [mem] (FF 25 xx xx xx xx)
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            return (true, 0.85);
        }
        // push imm32; ret (68 xx xx xx xx; C3)
        if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
            return (true, 0.82);
        }
        // mov rax, imm64; jmp rax (48 B8 ...; FF E0)
        if bytes.len() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
            return (true, 0.88);
        }

        (false, 0.0)
    }

    // ── FDE loop detection ────────────────────────────────────────────────────

    /// Find the fetch-decode-execute loop in a code region.
    pub fn find_fde_loop(&self, bytes: &[u8], base_address: u64) -> Option<FetchDecodeExecutePattern> {
        // Key indicators of an FDE loop:
        // 1. A register is used as an instruction pointer (advanced by opcode width)
        // 2. The opcode is fetched from [ip_reg] and decoded (switch or branch tree)
        // 3. Multiple execute branches jump to handler code

        // Strategy: find patterns like:
        //   movzx eax, byte [rsi]   (fetch byte opcode)
        //   inc rsi                  (advance IP)
        //   jmp [table + rax*8]     (execute)

        let fetch_candidates = find_fetch_patterns(bytes, base_address);
        if fetch_candidates.is_empty() {
            return None;
        }

        // Take the highest-scoring fetch site
        let (fetch_addr, ip_reg, opcode_width) = fetch_candidates.into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(addr, _, ip, ow)| (addr, ip, ow))?;

        // Look for decode logic near fetch_addr
        let fetch_off = fetch_addr.saturating_sub(base_address) as usize;
        let window_end = (fetch_off + 128).min(bytes.len());
        let decode_addr = find_decode_pattern(&bytes[fetch_off..window_end], fetch_addr);

        // Count execute branches (jumps following the decode)
        let execute_branches = find_execute_branches(bytes, base_address, decode_addr);
        let branch_count = execute_branches.len();

        let confidence = compute_fde_confidence(branch_count, opcode_width);

        if confidence >= self.min_confidence {
            Some(FetchDecodeExecutePattern {
                loop_head: base_address,
                fetch_address: fetch_addr,
                decode_address: decode_addr,
                execute_branches,
                ip_register: ip_reg,
                opcode_width,
                confidence,
            })
        } else {
            None
        }
    }

    // ── Handler table detection ───────────────────────────────────────────────

    /// Find all candidate handler tables in `bytes`.
    pub fn find_handler_tables(
        &self,
        bytes: &[u8],
        base_address: u64,
    ) -> Vec<HandlerTableCandidate> {
        let ptr_sz = self.ptr_size as usize;
        let (lo, hi) = self.code_range;
        let mut candidates = Vec::new();

        let mut i = 0;
        while i + ptr_sz <= bytes.len() {
            let ptr = read_ptr(&bytes[i..], ptr_sz);
            if ptr >= lo && ptr <= hi {
                // Start of a potential run
                let start_off = i;
                let mut addrs = Vec::new();
                while i + ptr_sz <= bytes.len() {
                    let p = read_ptr(&bytes[i..], ptr_sz);
                    if p < lo || p > hi {
                        break;
                    }
                    addrs.push(p);
                    i += ptr_sz;
                }

                if addrs.len() >= 4 {
                    // Check that handler pointers are distinct and plausibly aligned
                    let unique: HashSet<u64> = addrs.iter().copied().collect();
                    let distinct_ratio = unique.len() as f32 / addrs.len() as f32;
                    let all_aligned = addrs.iter().all(|a| a % 4 == 0);

                    let confidence = distinct_ratio * 0.6
                        + if all_aligned { 0.2 } else { 0.0 }
                        + (addrs.len().min(32) as f32 / 32.0) * 0.2;

                    if confidence >= self.min_confidence {
                        candidates.push(HandlerTableCandidate {
                            address: base_address + start_off as u64,
                            entry_count: addrs.len(),
                            ptr_size: self.ptr_size,
                            handler_addresses: addrs,
                            confidence: confidence.min(1.0),
                        });
                    }
                }
            } else {
                i += 1; // slide one byte at a time when not in a run
            }
        }

        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    // ── Opcode width inference ────────────────────────────────────────────────

    /// Infer the opcode byte width (1 or 2) from the fetch pattern.
    pub fn infer_opcode_width(&self, bytes: &[u8]) -> u8 {
        // If we see `movzx eax, word ptr [rsi]` → 2-byte opcodes
        let word_fetch = bytes.windows(4).any(|w| {
            w[0] == 0x66 && w[1] == 0x0F && w[2] == 0xB7 // movzx eax, word [...]
        });
        if word_fetch { 2 } else { 1 }
    }

    // ── Threaded interpreter detection ────────────────────────────────────────

    /// Detect whether the dispatcher uses computed goto (threaded dispatch).
    pub fn detect_threaded(&self, bytes: &[u8]) -> bool {
        // Threaded interpreters end each handler with jmp [reg] or jmp [reg + disp]
        // where `reg` holds the next handler address fetched from a table.
        let indirect_jumps = bytes
            .windows(2)
            .filter(|w| w[0] == 0xFF && matches!(w[1], 0x20..=0x27 | 0x60..=0x67 | 0xA0..=0xA7))
            .count();

        // Typically, threaded code has >= 1 indirect jump per ~50 bytes
        let density = indirect_jumps as f32 / (bytes.len() as f32 / 50.0).max(1.0);
        density >= 1.0
    }

    // ── Main analysis ─────────────────────────────────────────────────────────

    /// Identify the VM kind and collect all structural evidence.
    pub fn identify(&self, bytes: &[u8], base_address: u64) -> CustomVmResult {
        let mut evidence = Vec::new();

        // 1. Trampoline check (cheapest, eliminates short stubs immediately)
        let (is_trampoline, tramp_conf) = self.detect_trampoline(bytes);
        if is_trampoline && tramp_conf >= self.min_confidence {
            evidence.push(format!("trampoline pattern detected (conf={:.2})", tramp_conf));
            return CustomVmResult {
                kind: VmKind::Trampoline,
                overall_confidence: tramp_conf,
                evidence,
                ..CustomVmResult::unknown()
            };
        }

        // 2. JIT detection
        let (is_jit, jit_conf) = self.detect_jit(bytes);
        if is_jit && jit_conf >= self.min_confidence {
            evidence.push(format!("JIT indicators detected (conf={:.2})", jit_conf));
            return CustomVmResult {
                kind: VmKind::JitCompiler,
                overall_confidence: jit_conf,
                evidence,
                ..CustomVmResult::unknown()
            };
        }

        // 3. FDE loop detection
        let fde = self.find_fde_loop(bytes, base_address);
        if let Some(ref fde_pat) = fde {
            evidence.push(format!(
                "FDE loop at 0x{:x}, IP reg={}, opcode_width={}",
                fde_pat.fetch_address, fde_pat.ip_register, fde_pat.opcode_width
            ));
        }

        // 4. Handler table detection
        let handler_tables = self.find_handler_tables(bytes, base_address);
        if !handler_tables.is_empty() {
            evidence.push(format!(
                "handler table at 0x{:x} with {} entries",
                handler_tables[0].address, handler_tables[0].entry_count
            ));
        }

        // 5. Threaded detection
        let is_threaded = self.detect_threaded(bytes);
        if is_threaded {
            evidence.push("threaded dispatch detected".into());
        }

        // 6. Opcode width
        let _opcode_width = self.infer_opcode_width(bytes);

        // 7. Classify
        let (kind, confidence) = self.classify(
            fde.as_ref(),
            &handler_tables,
            is_threaded,
            is_jit,
            jit_conf,
        );

        let estimated_opcode_count = handler_tables
            .first()
            .map(|t| t.entry_count as u32)
            .or_else(|| fde.as_ref().map(|f| f.execute_branches.len() as u32))
            .unwrap_or(0);

        let ip_register = fde.as_ref().map(|f| f.ip_register.clone());

        CustomVmResult {
            kind,
            fde_pattern: fde,
            handler_tables,
            estimated_opcode_count,
            ip_register,
            is_threaded,
            overall_confidence: confidence,
            evidence,
        }
    }

    fn classify(
        &self,
        fde: Option<&FetchDecodeExecutePattern>,
        tables: &[HandlerTableCandidate],
        is_threaded: bool,
        is_jit: bool,
        jit_conf: f32,
    ) -> (VmKind, f32) {
        if is_jit && jit_conf > 0.5 {
            return (VmKind::JitCompiler, jit_conf);
        }

        if let Some(fde_pat) = fde {
            if is_threaded {
                return (VmKind::ThreadedInterpreter, fde_pat.confidence * 0.9);
            }
            if !tables.is_empty() {
                return (VmKind::SwitchDispatchInterpreter, fde_pat.confidence.max(tables[0].confidence));
            }
            return (VmKind::BytecodeInterpreter, fde_pat.confidence);
        }

        if !tables.is_empty() {
            return (VmKind::BytecodeInterpreter, tables[0].confidence * 0.7);
        }

        (VmKind::Unknown, 0.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a little-endian pointer of `size` bytes.
fn read_ptr(bytes: &[u8], size: usize) -> u64 {
    if bytes.len() < size {
        return 0;
    }
    match size {
        4 => u32::from_le_bytes(bytes[..4].try_into().unwrap_or_default()) as u64,
        8 => u64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()),
        _ => 0,
    }
}

/// Returns `(address, score, ip_register, opcode_width)` for fetch patterns.
fn find_fetch_patterns(bytes: &[u8], base: u64) -> Vec<(u64, f32, String, u8)> {
    let mut results = Vec::new();

    for (i, window) in bytes.windows(4).enumerate() {
        let addr = base + i as u64;

        // movzx eax, byte ptr [rsi]  → 0F B6 06
        if window[0] == 0x0F && window[1] == 0xB6 && window[2] == 0x06 {
            results.push((addr, 0.75, "rsi".into(), 1u8));
        }
        // movzx eax, byte ptr [rdi]  → 0F B6 07
        if window[0] == 0x0F && window[1] == 0xB6 && window[2] == 0x07 {
            results.push((addr, 0.75, "rdi".into(), 1u8));
        }
        // movzx eax, byte ptr [r12] → 41 0F B6 04 24
        if window[0] == 0x41 && window[1] == 0x0F && window[2] == 0xB6 {
            results.push((addr, 0.72, "r12".into(), 1u8));
        }
        // movzx eax, word ptr [rsi] → 66 0F B7 06
        if window[0] == 0x66 && window[1] == 0x0F && window[2] == 0xB7 {
            results.push((addr, 0.70, "rsi".into(), 2u8));
        }
        // mov al, [rsi]  → 8A 06
        if window[0] == 0x8A && window[1] == 0x06 {
            results.push((addr, 0.60, "rsi".into(), 1u8));
        }
        // mov al, [rdi]  → 8A 07
        if window[0] == 0x8A && window[1] == 0x07 {
            results.push((addr, 0.60, "rdi".into(), 1u8));
        }
    }

    results
}

fn find_decode_pattern(bytes: &[u8], base: u64) -> u64 {
    // Look for a switch table reference or comparison chain after the fetch
    for (i, window) in bytes.windows(6).enumerate() {
        // jmp [rax*8 + table]
        if window[0] == 0xFF && window[1] == 0x24 && window[2] == 0xC5 {
            return base + i as u64;
        }
        // cmp eax, imm8; je/jne
        if window[0] == 0x83 && window[1] == 0xF8 {
            return base + i as u64;
        }
    }
    base
}

fn find_execute_branches(bytes: &[u8], base: u64, decode_addr: u64) -> Vec<u64> {
    let mut branches = Vec::new();
    let decode_off = decode_addr.saturating_sub(base) as usize;
    let region = if decode_off < bytes.len() {
        &bytes[decode_off..]
    } else {
        bytes
    };

    for (i, window) in region.windows(6).enumerate() {
        let addr = base + decode_off as u64 + i as u64;
        // je/jne rel32 (0F 84/85 xx xx xx xx)
        if window[0] == 0x0F && matches!(window[1], 0x84 | 0x85) {
            let disp = i32::from_le_bytes(window[2..6].try_into().unwrap_or_default());
            let target = (addr as i64 + 6 + disp as i64) as u64;
            branches.push(target);
        }
        // jz/jnz rel8 (74/75 xx)
        if matches!(window[0], 0x74 | 0x75) {
            let disp = window[1] as i8 as i64;
            let target = (addr as i64 + 2 + disp) as u64;
            branches.push(target);
        }
    }

    // Deduplicate and limit
    branches.sort_unstable();
    branches.dedup();
    branches.truncate(256);
    branches
}

fn compute_fde_confidence(branch_count: usize, opcode_width: u8) -> f32 {
    let branch_score: f32 = match branch_count {
        0 => 0.0,
        1..=3 => 0.25,
        4..=15 => 0.55,
        16..=63 => 0.70,
        64..=255 => 0.85,
        _ => 0.90,
    };
    let width_bonus: f32 = if opcode_width == 1 { 0.05 } else { 0.0 };
    (branch_score + width_bonus).min(1.0f32)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_trampoline_jmp_rel32() {
        let id = CustomVmIdentifier::new();
        // E9 xx xx xx xx = jmp rel32
        let bytes = vec![0xE9u8, 0x10, 0x00, 0x00, 0x00];
        let (is_tramp, conf) = id.detect_trampoline(&bytes);
        assert!(is_tramp);
        assert!(conf >= 0.85);
    }

    #[test]
    fn test_detect_trampoline_not_for_long_code() {
        let id = CustomVmIdentifier::new();
        let bytes = vec![0x90u8; 100];
        let (is_tramp, _) = id.detect_trampoline(&bytes);
        assert!(!is_tramp);
    }

    #[test]
    fn test_infer_opcode_width_byte() {
        let id = CustomVmIdentifier::new();
        let bytes = vec![0x0Fu8, 0xB6, 0x06, 0x90, 0x90]; // movzx eax, byte [rsi]
        assert_eq!(id.infer_opcode_width(&bytes), 1);
    }

    #[test]
    fn test_infer_opcode_width_word() {
        let id = CustomVmIdentifier::new();
        let bytes = vec![0x66u8, 0x0F, 0xB7, 0x06, 0x90]; // movzx eax, word [rsi]
        assert_eq!(id.infer_opcode_width(&bytes), 2);
    }

    #[test]
    fn test_detect_jit_write_cursor() {
        let id = CustomVmIdentifier::new();
        // 5 × mov [rdi], al (C6 07 xx)
        let mut bytes = Vec::new();
        for _ in 0..5 {
            bytes.extend_from_slice(&[0xC6, 0x07, 0xCC]);
        }
        let (_is_jit, conf) = id.detect_jit(&bytes);
        // Should get some score for write cursor stores
        assert!(conf >= 0.20);
    }

    #[test]
    fn test_find_handler_tables_empty() {
        let id = CustomVmIdentifier::new();
        let tables = id.find_handler_tables(&[0u8; 8], 0x400000);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_identify_trampoline() {
        let id = CustomVmIdentifier::new();
        // Short jmp rel32 → must classify as Trampoline
        let bytes = vec![0xE9u8, 0x00, 0x10, 0x00, 0x00];
        let result = id.identify(&bytes, 0x401000);
        assert_eq!(result.kind, VmKind::Trampoline);
    }

    #[test]
    fn test_threaded_detection() {
        let id = CustomVmIdentifier::new();
        // Many jmp [rax] = FF E0 patterns
        let bytes: Vec<u8> = (0..60).flat_map(|_| vec![0xFFu8, 0x20, 0x90]).collect();
        assert!(id.detect_threaded(&bytes));
    }
}
