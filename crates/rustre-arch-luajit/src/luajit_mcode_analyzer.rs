//! LuaJIT machine code (JIT output) analyzer.
//!
//! Analyzes the native x86-64 machine code produced by LuaJIT's JIT compiler,
//! identifying guard checks, type checks, dispatch stubs, trace links, and
//! memory layout of traces.

use std::collections::HashMap;

// ── PatchType ─────────────────────────────────────────────────────────────────

/// The purpose of a machine-code patch region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchType {
    /// A guard exit stub: `jne/je <exit_addr>`.
    GuardExit,
    /// A direct trace-to-trace link: `jmp <trace_mcode>`.
    TraceLink,
    /// A call to a runtime helper stub.
    StubCall,
    /// A deoptimization bailout sequence.
    Deoptimize,
}

impl PatchType {
    /// Short descriptive name.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::GuardExit  => "guard_exit",
            Self::TraceLink  => "trace_link",
            Self::StubCall   => "stub_call",
            Self::Deoptimize => "deopt",
        }
    }
}

// ── McodePatch ────────────────────────────────────────────────────────────────

/// A patched region within JIT-compiled machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McodePatch {
    /// Byte offset from the start of the trace's machine code.
    pub offset: u32,
    /// The bytes at this patch site (the patched sequence).
    pub bytes: Vec<u8>,
    /// What kind of patch this is.
    pub patch_type: PatchType,
}

impl McodePatch {
    /// Create a new patch record.
    #[must_use] 
    pub const fn new(offset: u32, bytes: Vec<u8>, patch_type: PatchType) -> Self {
        Self { offset, bytes, patch_type }
    }

    /// Return the size of the patched region in bytes.
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.bytes.len()
    }
}

// ── TraceExit ─────────────────────────────────────────────────────────────────

/// A side exit from a JIT trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExit {
    /// Sequential exit number within the trace.
    pub exit_num: u16,
    /// Absolute address of the exit stub.
    pub exit_addr: u64,
    /// Index of the snapshot that this exit restores.
    pub snap_ref: u16,
    /// Whether this exit has been hot-patched to link to another trace.
    pub patched: bool,
}

impl TraceExit {
    /// Create a new exit record.
    #[must_use] 
    pub const fn new(exit_num: u16, exit_addr: u64, snap_ref: u16) -> Self {
        Self { exit_num, exit_addr, snap_ref, patched: false }
    }
}

// ── TraceLink ─────────────────────────────────────────────────────────────────

/// A direct link between two JIT traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceLink {
    /// The trace that contains the link.
    pub from_trace: u32,
    /// The target trace.
    pub to_trace: u32,
    /// Absolute address where the link jmp/call is located.
    pub link_addr: u64,
}

// ── TraceStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for a single JIT trace.
#[derive(Debug, Clone, Default)]
pub struct TraceStats {
    /// Total number of side exits.
    pub exit_count: u32,
    /// Total number of trace-to-trace links.
    pub link_count: u32,
    /// Size of the machine code in bytes.
    pub size: u32,
    /// Guard density: guards per 16 bytes of machine code.
    pub guard_density: f64,
}

impl TraceStats {
    /// Compute from a `JitTrace`.
    ///
    /// # Panics
    /// Panics if exit count or link count exceeds `u32::MAX`.
    #[must_use]
    pub fn from_trace(trace: &JitTrace) -> Self {
        let guard_density = if trace.mcode_size == 0 {
            0.0
        } else {
            f64::from(u32::try_from(trace.exits.len()).unwrap_or(u32::MAX)) / (f64::from(trace.mcode_size) / 16.0)
        };
        Self {
            exit_count: u32::try_from(trace.exits.len()).expect("exit count fits in u32"),
            link_count: u32::try_from(trace.links.len()).expect("link count fits in u32"),
            size: trace.mcode_size,
            guard_density,
        }
    }
}

// ── JitTrace ──────────────────────────────────────────────────────────────────

/// A complete JIT-compiled trace record.
#[derive(Debug, Clone)]
pub struct JitTrace {
    /// Unique trace identifier.
    pub trace_id: u32,
    /// Bytecode PC where recording started.
    pub start_pc: u64,
    /// Absolute address of the machine code.
    pub mcode_addr: u64,
    /// Size of the machine code in bytes.
    pub mcode_size: u32,
    /// Side exits of the trace.
    pub exits: Vec<TraceExit>,
    /// Direct links to other traces.
    pub links: Vec<TraceLink>,
}

impl JitTrace {
    /// Create a new empty trace.
    #[must_use] 
    pub const fn new(trace_id: u32, start_pc: u64, mcode_addr: u64, mcode_size: u32) -> Self {
        Self {
            trace_id,
            start_pc,
            mcode_addr,
            mcode_size,
            exits: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Return `true` if any exit has been patched (hot-patched to a new trace).
    #[must_use] 
    pub fn has_patched_exits(&self) -> bool {
        self.exits.iter().any(|e| e.patched)
    }

    /// Return statistics for this trace.
    #[must_use] 
    pub fn stats(&self) -> TraceStats {
        TraceStats::from_trace(self)
    }
}

// ── McodeAnalyzer ─────────────────────────────────────────────────────────────

/// Analyzes a buffer of JIT-compiled machine code for LuaJIT-specific patterns.
pub struct McodeAnalyzer {
    /// The machine code being analyzed.
    mcode: Vec<u8>,
    /// Base address where the mcode is mapped.
    base_addr: u64,
    /// Trace records discovered or provided.
    traces: Vec<JitTrace>,
}

impl McodeAnalyzer {
    /// Create a new analyzer for the given machine code buffer.
    #[must_use] 
    pub const fn new(mcode: Vec<u8>, base_addr: u64) -> Self {
        Self { mcode, base_addr, traces: Vec::new() }
    }

    /// Register a known trace with the analyzer (for cross-trace link resolution).
    pub fn add_trace(&mut self, trace: JitTrace) {
        self.traces.push(trace);
    }

    /// Return the raw machine code bytes.
    #[must_use] 
    pub fn mcode(&self) -> &[u8] {
        &self.mcode
    }

    /// Return the base address.
    #[must_use] 
    pub const fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Scan the machine code for `cmp` + `jcc` patterns that indicate guard
    /// exit checks.
    ///
    /// Heuristic: look for `CMP r/m, imm` (0x83 / 0x81 / 0x3B) followed
    /// immediately within 4 bytes by a conditional jump (0x0F 0x84..0x8F or
    /// short 0x74..0x7F).  Returns list of (offset, `exit_addr`) pairs.
    ///
    /// # Panics
    /// Panics if a guard offset exceeds `u32::MAX`.
    #[must_use]
    pub fn identify_guard_checks(&self) -> Vec<(u32, u64)> {
        let mut guards = Vec::new();
        let mc = &self.mcode;
        let n = mc.len();
        let mut i = 0usize;
        while i + 2 < n {
            let b = mc[i];
            // CMP patterns: 0x83 /7 imm8, 0x81 /7 imm32, 0x3B /r
            let is_cmp = b == 0x83 || b == 0x81 || b == 0x3B || b == 0x39 || b == 0x3D;
            if is_cmp {
                // Advance past the CMP instruction (simplified: skip modrm + 1..4 bytes)
                // 0x83 /7 = opcode + modrm + imm8 (3 bytes)
                // 0x3B /r, 0x39 /r = opcode + modrm (2 bytes)
                // 0x3D = opcode + imm32 (5 bytes)
                // 0x81 /7 = opcode + modrm + imm32 (6 bytes)
                let advance = match b {
                    0x83 => 3usize,
                    0x3B | 0x39 => 2usize,
                    0x3D => 5usize,
                    _ => 6usize,
                };
                let j = i + advance;
                if j + 1 < n {
                    let jb = mc[j];
                    // Short Jcc: 0x74..0x7F
                    if (0x74..=0x7F).contains(&jb) && j + 1 < n {
                        let rel = mc[j + 1].cast_signed();
                        let abs = self.base_addr.wrapping_add(j as u64).wrapping_add(2).wrapping_add_signed(i64::from(rel));
                        guards.push((u32::try_from(j).expect("offset fits in u32"), abs));
                    }
                    // Near Jcc: 0x0F 0x84..0x8F
                    if jb == 0x0F && j + 5 < n {
                        let jcc = mc[j + 1];
                        if (0x84..=0x8F).contains(&jcc) {
                            let rel = i32::from_le_bytes([mc[j+2], mc[j+3], mc[j+4], mc[j+5]]);
                            let abs = (self.base_addr + j as u64 + 6).wrapping_add_signed(i64::from(rel));
                            guards.push((u32::try_from(j).expect("offset fits in u32"), abs));
                        }
                    }
                }
            }
            i += 1;
        }
        guards
    }

    /// Identify type-tag comparison patterns typical of `LuaJIT` guard checks.
    ///
    /// `LuaJIT` stores `TValues` as (value: u64, tag: u32) pairs.  A type check
    /// sequence is:
    /// ```asm
    /// mov eax, [ptr+8]   ; load tag word
    /// cmp eax, ITYPE     ; compare against expected type
    /// jne exit           ; bail on mismatch
    /// ```
    ///
    /// We detect `MOV r32, [r/m+8]` (0x8B /r with disp8=8) followed by
    /// `CMP r32, imm8` (0x83) within 8 bytes.
    ///
    /// # Panics
    /// Panics if a type-check offset exceeds `u32::MAX`.
    #[must_use]
    pub fn identify_type_checks(&self) -> Vec<(u32, u8)> {
        let mut checks = Vec::new();
        let mc = &self.mcode;
        let n = mc.len();
        let mut i = 0usize;
        while i + 4 < n {
            // MOV r32, [r/m+disp8]: opcode 0x8B, ModRM with Mod=01, disp=8
            if mc[i] == 0x8B && i + 3 < n {
                let modrm = mc[i + 1];
                let modfield = (modrm >> 6) & 3;
                let disp = if i + 2 < n { mc[i + 2] } else { 0 };
                if modfield == 0b01 && disp == 8 {
                    // Look for CMP r32,imm8 (0x83) within next 4 bytes
                    let j = i + 3;
                    if j + 1 < n && mc[j] == 0x83 {
                        let tag_imm = if j + 2 < n { mc[j + 2] } else { 0 };
                        checks.push((u32::try_from(i).expect("offset fits in u32"), tag_imm));
                    }
                }
            }
            i += 1;
        }
        checks
    }

    /// Identify calls to runtime dispatch stubs: `CALL rel32` (0xE8) sequences
    /// that land in a region outside the current mcode range (likely stubs).
    ///
    /// Returns list of (`call_offset`, `abs_target`).
    ///
    /// # Panics
    /// Panics if a stub offset exceeds `u32::MAX`.
    #[must_use]
    pub fn identify_dispatch_stubs(&self) -> Vec<(u32, u64)> {
        let mut stubs = Vec::new();
        let mc = &self.mcode;
        let n = mc.len();
        let end_addr = self.base_addr + n as u64;
        let mut i = 0usize;
        while i + 4 < n {
            if mc[i] == 0xE8 {
                let rel = i32::from_le_bytes([mc[i+1], mc[i+2], mc[i+3], mc[i+4]]);
                let abs = (self.base_addr + i as u64 + 5).wrapping_add_signed(i64::from(rel));
                // If target is outside our mcode range, it's a stub call.
                if abs < self.base_addr || abs >= end_addr {
                    stubs.push((u32::try_from(i).expect("offset fits in u32"), abs));
                }
            }
            i += 1;
        }
        stubs
    }

    /// Analyze the full memory layout and produce patch records.
    ///
    /// Combines guard checks, type checks, and stub calls into `McodePatch`
    /// records.
    #[must_use] 
    pub fn trace_memory_layout(&self) -> Vec<McodePatch> {
        let mut patches = Vec::new();

        for (offset, _target) in self.identify_guard_checks() {
            let end = (offset as usize + 6).min(self.mcode.len());
            let bytes = self.mcode[offset as usize..end].to_vec();
            patches.push(McodePatch::new(offset, bytes, PatchType::GuardExit));
        }

        for (offset, _tag) in self.identify_type_checks() {
            let end = (offset as usize + 5).min(self.mcode.len());
            let bytes = self.mcode[offset as usize..end].to_vec();
            patches.push(McodePatch::new(offset, bytes, PatchType::GuardExit));
        }

        for (offset, _target) in self.identify_dispatch_stubs() {
            let end = (offset as usize + 5).min(self.mcode.len());
            let bytes = self.mcode[offset as usize..end].to_vec();
            patches.push(McodePatch::new(offset, bytes, PatchType::StubCall));
        }

        // Sort by offset.
        patches.sort_by_key(|p| p.offset);
        // Deduplicate overlapping patches.
        patches.dedup_by_key(|p| p.offset);
        patches
    }

    /// Compute aggregate statistics for the analyzed mcode.
    ///
    /// If trace records have been added, uses the first trace; otherwise
    /// synthesizes a dummy trace from discovered patterns.
    ///
    /// # Panics
    /// Panics if guard count exceeds `u32::MAX`.
    #[must_use]
    pub fn compute_trace_stats(&self) -> TraceStats {
        if let Some(trace) = self.traces.first() {
            return TraceStats::from_trace(trace);
        }
        let guard_count = u32::try_from(self.identify_guard_checks().len()).expect("guard count fits in u32");
        let stub_count  = u32::try_from(self.identify_dispatch_stubs().len()).expect("stub count fits in u32");
        let size = u32::try_from(self.mcode.len()).expect("mcode length fits in u32");
        let guard_density = if size == 0 {
            0.0
        } else {
            f64::from(guard_count) / (f64::from(size) / 16.0)
        };
        TraceStats {
            exit_count:    guard_count,
            link_count:    stub_count,
            size,
            guard_density,
        }
    }

    /// Build a map from absolute address to patch type for all patches.
    #[must_use] 
    pub fn patch_map(&self) -> HashMap<u64, PatchType> {
        let patches = self.trace_memory_layout();
        patches
            .into_iter()
            .map(|p| (self.base_addr + u64::from(p.offset), p.patch_type))
            .collect()
    }

    /// Return all `JMP rel32` (0xE9) targets — potential trace links.
    ///
    /// # Panics
    /// Panics if a jump offset exceeds `u32::MAX`.
    #[must_use]
    pub fn unconditional_jumps(&self) -> Vec<(u32, u64)> {
        let mut jumps = Vec::new();
        let mc = &self.mcode;
        let n = mc.len();
        let mut i = 0usize;
        while i + 4 < n {
            if mc[i] == 0xE9 {
                let rel = i32::from_le_bytes([mc[i+1], mc[i+2], mc[i+3], mc[i+4]]);
                let abs = (self.base_addr + i as u64 + 5).wrapping_add_signed(i64::from(rel));
                jumps.push((u32::try_from(i).expect("jump offset fits in u32"), abs));
            }
            i += 1;
        }
        jumps
    }

    /// Identify potential trace-link patches: unconditional jumps that land
    /// within any known trace's mcode range.
    #[must_use] 
    pub fn identify_trace_links(&self) -> Vec<(u32, u32)> {
        let mut links = Vec::new();
        for (off, target) in self.unconditional_jumps() {
            for trace in &self.traces {
                let start = trace.mcode_addr;
                let end   = start + u64::from(trace.mcode_size);
                if target >= start && target < end {
                    links.push((off, trace.trace_id));
                }
            }
        }
        links
    }

    /// Scan for REX prefixes (0x40..0x4F) followed by MOV patterns, to count
    /// 64-bit register moves used in value tagging.
    #[must_use] 
    pub fn count_rex_moves(&self) -> u32 {
        let mc = &self.mcode;
        let n = mc.len();
        let mut count = 0u32;
        let mut i = 0usize;
        while i + 1 < n {
            if (0x40..=0x4F).contains(&mc[i]) && (mc[i+1] == 0x8B || mc[i+1] == 0x89) {
                count += 1;
            }
            i += 1;
        }
        count
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_analyzer(bytes: Vec<u8>) -> McodeAnalyzer {
        McodeAnalyzer::new(bytes, 0x1000_0000)
    }

    #[test]
    fn test_empty_mcode() {
        let a = simple_analyzer(vec![]);
        assert!(a.identify_guard_checks().is_empty());
        assert!(a.identify_dispatch_stubs().is_empty());
    }

    #[test]
    fn test_guard_check_short_jcc() {
        // CMP eax, 5  (83 F8 05) + JNE rel8 (75 0A)
        let mcode = vec![0x83, 0xF8, 0x05, 0x75, 0x0A];
        let a = simple_analyzer(mcode);
        let guards = a.identify_guard_checks();
        assert!(!guards.is_empty());
    }

    #[test]
    fn test_dispatch_stub_call() {
        // CALL rel32 to address outside [0x1000_0000, 0x1000_0005]
        // Target: 0x1000_0000 + 5 + 0x0010_0000 = 0x1010_0005
        let rel: i32 = 0x0010_0000;
        let mut mcode = vec![0xE8u8];
        mcode.extend_from_slice(&rel.to_le_bytes());
        let a = simple_analyzer(mcode);
        let stubs = a.identify_dispatch_stubs();
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].1, 0x1010_0005);
    }

    #[test]
    fn test_trace_memory_layout_returns_patches() {
        let mcode = vec![0x83, 0xF8, 0x05, 0x75, 0x0A, 0xE8, 0x00, 0x10, 0x00, 0x00];
        let a = simple_analyzer(mcode);
        let patches = a.trace_memory_layout();
        assert!(!patches.is_empty());
    }

    #[test]
    fn test_compute_trace_stats_with_registered_trace() {
        let mut a = simple_analyzer(vec![0u8; 64]);
        let mut trace = JitTrace::new(1, 0x4000, 0x1000_0000, 64);
        trace.exits.push(TraceExit::new(0, 0x2000, 0));
        trace.exits.push(TraceExit::new(1, 0x2010, 1));
        a.add_trace(trace);
        let stats = a.compute_trace_stats();
        assert_eq!(stats.exit_count, 2);
        assert_eq!(stats.size, 64);
    }

    #[test]
    fn test_compute_trace_stats_synthetic() {
        let mcode = vec![0x83, 0xF8, 0x05, 0x75, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x83, 0xF8, 0x07, 0x75, 0x0A];
        let a = simple_analyzer(mcode);
        let stats = a.compute_trace_stats();
        assert!(stats.exit_count >= 1);
    }

    #[test]
    fn test_trace_exit_patched_flag() {
        let mut exit = TraceExit::new(0, 0x5000, 2);
        assert!(!exit.patched);
        exit.patched = true;
        assert!(exit.patched);
    }

    #[test]
    fn test_trace_has_patched_exits() {
        let mut trace = JitTrace::new(1, 0, 0, 16);
        trace.exits.push(TraceExit::new(0, 0, 0));
        assert!(!trace.has_patched_exits());
        trace.exits[0].patched = true;
        assert!(trace.has_patched_exits());
    }

    #[test]
    fn test_patch_type_names() {
        assert_eq!(PatchType::GuardExit.name(), "guard_exit");
        assert_eq!(PatchType::TraceLink.name(), "trace_link");
        assert_eq!(PatchType::StubCall.name(), "stub_call");
        assert_eq!(PatchType::Deoptimize.name(), "deopt");
    }

    #[test]
    fn test_unconditional_jump_detection() {
        // JMP rel32: E9 10 00 00 00 → target = base + 5 + 16
        let mcode = vec![0xE9u8, 0x10, 0x00, 0x00, 0x00];
        let a = simple_analyzer(mcode);
        let jumps = a.unconditional_jumps();
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].1, 0x1000_0000 + 5 + 0x10);
    }

    #[test]
    fn test_trace_link_resolution() {
        // JMP to within trace 2's mcode
        let base = 0x2000_0000u64;
        let target = base + 10;
        let rel = (target.cast_signed() - (0x1000_0000u64.cast_signed() + 5)) as i32;
        let mut mcode = vec![0xE9u8];
        mcode.extend_from_slice(&rel.to_le_bytes());
        let mut a = McodeAnalyzer::new(mcode, 0x1000_0000);
        let trace2 = JitTrace::new(2, 0x4000, base, 100);
        a.add_trace(trace2);
        let links = a.identify_trace_links();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].1, 2);
    }

    #[test]
    fn test_rex_move_count() {
        // REX.W + MOV r64,r/m64: 48 8B ...
        let mcode = vec![0x48, 0x8B, 0xC0, 0x48, 0x89, 0xC1, 0x00];
        let a = simple_analyzer(mcode);
        assert_eq!(a.count_rex_moves(), 2);
    }

    #[test]
    fn test_mcode_patch_size() {
        let p = McodePatch::new(0, vec![0xE8, 0x00, 0x00, 0x00, 0x00], PatchType::StubCall);
        assert_eq!(p.size(), 5);
    }

    #[test]
    fn test_trace_stats_guard_density() {
        let mut trace = JitTrace::new(1, 0, 0x1000, 32);
        for i in 0..4u16 {
            trace.exits.push(TraceExit::new(i, 0x2000 + u64::from(i) * 8, i));
        }
        let stats = TraceStats::from_trace(&trace);
        // 4 exits / (32/16 = 2 windows) = 2.0
        assert!((stats.guard_density - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_type_check_detection() {
        // MOV eax, [rcx+8]: 8B 41 08  then CMP eax, 0xFF: 83 F8 FF
        let mcode = vec![0x8B, 0x41, 0x08, 0x83, 0xF8, 0xFF];
        let a = simple_analyzer(mcode);
        let checks = a.identify_type_checks();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].1, 0xFF);
    }

    #[test]
    fn test_patch_map_keys_are_absolute() {
        let mcode = vec![0x83, 0xF8, 0x05, 0x75, 0x0A];
        let a = McodeAnalyzer::new(mcode, 0x5000_0000);
        let map = a.patch_map();
        for addr in map.keys() {
            assert!(*addr >= 0x5000_0000);
        }
    }
}
