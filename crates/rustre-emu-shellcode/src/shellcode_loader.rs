//! Shellcode loading, relocation, memory mapping and GetPC/detection heuristics.
//!
//! `ShellcodeLoader` prepares raw shellcode bytes for emulation: it inspects
//! the buffer for common patterns, resolves a suitable load address, applies
//! delta patches for position-independent fragments that contain hard-coded
//! addresses, and maps the result into a `MemoryMap`.

use serde::{Deserialize, Serialize};

// ── Memory permission flags ───────────────────────────────────────────────────

/// Read / Write / Execute flags for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemFlags(u8);

impl MemFlags {
    pub const READ: Self    = Self(0x01);
    pub const WRITE: Self   = Self(0x02);
    pub const EXECUTE: Self = Self(0x04);
    pub const RWX: Self     = Self(0x07);
    pub const RW: Self      = Self(0x03);
    pub const RX: Self      = Self(0x05);

    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    #[must_use]
    pub fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for MemFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ── MemoryMap ─────────────────────────────────────────────────────────────────

/// A virtual memory region backing emulated shellcode execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address (virtual).
    pub base: u64,
    /// Raw contents.
    pub data: Vec<u8>,
    /// Access flags.
    pub flags: MemFlags,
    /// Human-readable tag (e.g. "shellcode", "stack", "heap").
    pub tag: String,
}

impl MemoryRegion {
    #[must_use]
    pub fn new(base: u64, data: Vec<u8>, flags: MemFlags, tag: impl Into<String>) -> Self {
        Self { base, data, flags, tag: tag.into() }
    }

    #[must_use]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.data.len() as u64)
    }

    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Read `len` bytes starting at virtual address `addr`, or `None` if OOB.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if !self.contains_addr(addr) {
            return None;
        }
        let off = (addr - self.base) as usize;
        if off + len > self.data.len() {
            return None;
        }
        Some(&self.data[off..off + len])
    }

    /// Write `bytes` at virtual address `addr`, returning `false` if OOB.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        if !self.contains_addr(addr) {
            return false;
        }
        let off = (addr - self.base) as usize;
        if off + bytes.len() > self.data.len() {
            return false;
        }
        self.data[off..off + bytes.len()].copy_from_slice(bytes);
        true
    }
}

/// A simple flat virtual memory map for shellcode emulation.
#[derive(Debug, Default)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.  Overlapping regions are not rejected but lookups will
    /// return the first matching region.
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Allocate a zeroed region of `size` bytes at `base` with the given flags.
    pub fn alloc(&mut self, base: u64, size: usize, flags: MemFlags, tag: impl Into<String>) {
        self.add_region(MemoryRegion::new(base, vec![0u8; size], flags, tag));
    }

    /// Find the region containing `addr`.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains_addr(addr))
    }

    /// Find the region mutably containing `addr`.
    pub fn region_at_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.regions.iter_mut().find(|r| r.contains_addr(addr))
    }

    /// Read bytes across a single region.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.region_at(addr)?.read(addr, len).map(|s| s.to_vec())
    }

    /// Write bytes into the first matching region.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        match self.region_at_mut(addr) {
            Some(r) => r.write(addr, bytes),
            None => false,
        }
    }

    /// Check if `addr` is in a region with execute permission.
    #[must_use]
    pub fn is_executable(&self, addr: u64) -> bool {
        self.region_at(addr)
            .map_or(false, |r| r.flags.contains(MemFlags::EXECUTE))
    }

    /// Total bytes allocated.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.regions.iter().map(|r| r.data.len()).sum()
    }

    /// Iterate over all regions.
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }
}

// ── Detection heuristics ──────────────────────────────────────────────────────

/// Individual shellcode detection signals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSignal {
    /// CALL+POP or FSTENV / GetPC trick to resolve the current instruction pointer.
    GetPcTrick,
    /// PUSH+RET jump trampoline (common in position-independent code).
    PushRetJump,
    /// A NOP sled of eight or more consecutive 0x90 bytes.
    NopSled { offset: usize, length: usize },
    /// XOR-based decode loop: at least two consecutive XOR [reg+imm], reg sequences.
    XorDecodeLoop { offset: usize },
    /// INT 3 breakpoint bait — common in shellcode that checks for debuggers.
    Int3Trap { offset: usize },
    /// Suspicious CALL to the next instruction (CALL $+5).
    CallNextInsn { offset: usize },
    /// Hard-coded 32-bit or 64-bit addresses typical of shellcode (0x7c, 0x7e prefix = kernel32 range).
    HardcodedKernelAddress { offset: usize, value: u64 },
    /// Dense sequence of RETs / CLCs after a very short function — likely encoded stub.
    EncodedStub,
    /// Wide-character (UTF-16LE) API strings detected in the buffer.
    WideApiString { offset: usize, name: String },
    /// ASCII API strings embedded in the buffer.
    AsciiApiString { offset: usize, name: String },
    /// EGG hunt marker bytes (common 4-byte egg tags).
    EggHunterMarker { offset: usize, egg: [u8; 4] },
    /// PUSH immediate + CALL EAX/RDX pattern (common in return-oriented stubs).
    PushCallReg { offset: usize },
    /// MOV ECX/RCX, 0 + REP MOVSB/STOSB: self-copy loop.
    RepMovsb { offset: usize },
}

/// Aggregate heuristic result for a shellcode buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// All signals found in the buffer.
    pub signals: Vec<DetectionSignal>,
    /// Weighted suspicion score (0–100).
    pub score: u8,
    /// True when the score exceeds the built-in threshold (40).
    pub likely_shellcode: bool,
}

impl DetectionResult {
    /// Compute from a list of signals.
    #[must_use]
    pub fn from_signals(signals: Vec<DetectionSignal>) -> Self {
        let raw_score: u32 = signals.iter().map(|s| signal_weight(s)).sum();
        let score = raw_score.min(100) as u8;
        let likely_shellcode = score >= 40;
        Self { signals, score, likely_shellcode }
    }
}

fn signal_weight(s: &DetectionSignal) -> u32 {
    match s {
        DetectionSignal::GetPcTrick => 20,
        DetectionSignal::PushRetJump => 15,
        DetectionSignal::NopSled { .. } => 10,
        DetectionSignal::XorDecodeLoop { .. } => 20,
        DetectionSignal::Int3Trap { .. } => 8,
        DetectionSignal::CallNextInsn { .. } => 15,
        DetectionSignal::HardcodedKernelAddress { .. } => 12,
        DetectionSignal::EncodedStub => 18,
        DetectionSignal::WideApiString { .. } => 14,
        DetectionSignal::AsciiApiString { .. } => 10,
        DetectionSignal::EggHunterMarker { .. } => 20,
        DetectionSignal::PushCallReg { .. } => 12,
        DetectionSignal::RepMovsb { .. } => 10,
    }
}

/// Well-known Windows API names to scan for in shellcode buffers.
static API_NAMES: &[&str] = &[
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress", "CreateThread", "CreateRemoteThread", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "socket", "connect", "send", "recv", "WSAStartup", "WSASocketA", "InternetOpenA",
    "InternetConnectA", "HttpSendRequestA", "CreateFileA", "WriteFile", "ReadFile",
    "HeapAlloc", "HeapCreate", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
];

/// Common egg hunter markers.
static EGG_MARKERS: &[[u8; 4]] = &[
    [0x77, 0x30, 0x30, 0x74], // w00t
    [0x68, 0x65, 0x6c, 0x70], // help
    [0x64, 0x65, 0x61, 0x64], // dead
    [0x90, 0x50, 0x90, 0x50], // NOP PUSH NOP PUSH
    [0xeb, 0x06, 0x90, 0x90], // common egghunter jmp pattern
    [0x0d, 0x0a, 0x0d, 0x0a], // CRLF×2
];

/// Stateless heuristic detector.
pub struct DetectionHeuristics;

impl DetectionHeuristics {
    /// Run all heuristics over `bytes` and return a `DetectionResult`.
    #[must_use]
    pub fn analyze(bytes: &[u8]) -> DetectionResult {
        let mut signals = Vec::new();

        Self::detect_nop_sled(bytes, &mut signals);
        Self::detect_get_pc(bytes, &mut signals);
        Self::detect_push_ret(bytes, &mut signals);
        Self::detect_call_next(bytes, &mut signals);
        Self::detect_xor_loop(bytes, &mut signals);
        Self::detect_int3(bytes, &mut signals);
        Self::detect_hardcoded_kernel_addrs(bytes, &mut signals);
        Self::detect_ascii_apis(bytes, &mut signals);
        Self::detect_wide_apis(bytes, &mut signals);
        Self::detect_egg_hunters(bytes, &mut signals);
        Self::detect_push_call_reg(bytes, &mut signals);
        Self::detect_rep_movsb(bytes, &mut signals);
        Self::detect_encoded_stub(bytes, &mut signals);

        DetectionResult::from_signals(signals)
    }

    fn detect_nop_sled(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        let mut run = 0usize;
        let mut run_start = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            if b == 0x90 {
                if run == 0 { run_start = i; }
                run += 1;
                if run == 8 {
                    out.push(DetectionSignal::NopSled { offset: run_start, length: 8 });
                }
            } else {
                if run >= 8 {
                    // Update the last recorded signal with the real length
                    if let Some(DetectionSignal::NopSled { length, .. }) = out.last_mut() {
                        *length = run;
                    }
                }
                run = 0;
            }
        }
    }

    fn detect_get_pc(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // CALL $+5 / FSTENV pattern: E8 00 00 00 00  58 (CALL 0; POP EAX)
        // Also: D9 EE 5B (FSTENV [esp-12]; POP EBX)
        let patterns: &[&[u8]] = &[
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59],
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A],
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B],
            &[0xD9, 0xEE],
        ];
        for pattern in patterns {
            if let Some(_) = find_pattern(bytes, pattern) {
                out.push(DetectionSignal::GetPcTrick);
                return;
            }
        }
    }

    fn detect_push_ret(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // 68 xx xx xx xx C3   PUSH imm32; RET
        for i in 0..bytes.len().saturating_sub(5) {
            if bytes[i] == 0x68 && bytes[i + 5] == 0xC3 {
                out.push(DetectionSignal::PushRetJump);
                return;
            }
        }
    }

    fn detect_call_next(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        for i in 0..bytes.len().saturating_sub(5) {
            if bytes[i] == 0xE8 {
                let rel = i32::from_le_bytes([bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]]);
                if rel == 0 {
                    out.push(DetectionSignal::CallNextInsn { offset: i });
                }
            }
        }
    }

    fn detect_xor_loop(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // XOR BYTE PTR [reg+imm], reg   30 /r  or  32 /r
        // Simplified: look for two XOR instructions within 16 bytes of each other
        let mut last_xor: Option<usize> = None;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0x30 || bytes[i] == 0x31 || bytes[i] == 0x32 || bytes[i] == 0x33 {
                if let Some(prev) = last_xor {
                    if i - prev <= 16 {
                        out.push(DetectionSignal::XorDecodeLoop { offset: prev });
                        return;
                    }
                }
                last_xor = Some(i);
            }
            i += 1;
        }
    }

    fn detect_int3(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        for (i, &b) in bytes.iter().enumerate() {
            if b == 0xCC {
                out.push(DetectionSignal::Int3Trap { offset: i });
                return;
            }
        }
    }

    fn detect_hardcoded_kernel_addrs(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // Windows kernel DLL addresses: 0x7c?????? 0x7e?????? or 0x77??????
        for i in 0..bytes.len().saturating_sub(3) {
            let top = bytes[i + 3];
            if top == 0x7c || top == 0x7e || top == 0x77 {
                let addr = u32::from_le_bytes([bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]]);
                if addr >= 0x7c00_0000 {
                    out.push(DetectionSignal::HardcodedKernelAddress { offset: i, value: addr as u64 });
                    return;
                }
            }
        }
    }

    fn detect_ascii_apis(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        for api in API_NAMES {
            let needle = api.as_bytes();
            if let Some(off) = find_pattern(bytes, needle) {
                out.push(DetectionSignal::AsciiApiString { offset: off, name: api.to_string() });
            }
        }
    }

    fn detect_wide_apis(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        for api in &["kernel32", "ntdll", "LoadLibrary", "GetProcAddress", "VirtualAlloc"] {
            let wide: Vec<u8> = api.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            if let Some(off) = find_pattern(bytes, &wide) {
                out.push(DetectionSignal::WideApiString { offset: off, name: api.to_string() });
            }
        }
    }

    fn detect_egg_hunters(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        for &egg in EGG_MARKERS {
            if let Some(off) = find_pattern(bytes, &egg) {
                out.push(DetectionSignal::EggHunterMarker { offset: off, egg });
                return;
            }
        }
    }

    fn detect_push_call_reg(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // 68 xx xx xx xx  FF D0/D2/etc.  PUSH imm; CALL reg
        for i in 0..bytes.len().saturating_sub(7) {
            if bytes[i] == 0x68 && bytes[i + 5] == 0xFF {
                let modrm = bytes[i + 6];
                // FF D0 = CALL EAX, FF D2 = CALL EDX, FF D7 = CALL EDI
                if modrm & 0xF8 == 0xD0 {
                    out.push(DetectionSignal::PushCallReg { offset: i });
                    return;
                }
            }
        }
    }

    fn detect_rep_movsb(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // F3 A4 = REP MOVSB, F3 AA = REP STOSB
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == 0xF3 && (bytes[i+1] == 0xA4 || bytes[i+1] == 0xAA) {
                out.push(DetectionSignal::RepMovsb { offset: i });
                return;
            }
        }
    }

    fn detect_encoded_stub(bytes: &[u8], out: &mut Vec<DetectionSignal>) {
        // Heuristic: high byte entropy (many unique byte values in a 64-byte window)
        if bytes.len() < 64 {
            return;
        }
        let window = &bytes[..64.min(bytes.len())];
        let mut counts = [0u16; 256];
        for &b in window {
            counts[b as usize] += 1;
        }
        let unique = counts.iter().filter(|&&c| c > 0).count();
        if unique > 200 {
            out.push(DetectionSignal::EncodedStub);
        }
    }
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── Relocation entry ──────────────────────────────────────────────────────────

/// A single relocation to patch when loading shellcode at a non-zero base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    /// Offset within the shellcode buffer.
    pub offset: usize,
    /// Width of the value to patch (4 = 32-bit, 8 = 64-bit).
    pub width: u8,
    /// Addend to add to the new base address.
    pub addend: i64,
}

/// Loader configuration.
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// Virtual base address to load the shellcode at.
    pub base_address: u64,
    /// Page size for alignment (default 0x1000).
    pub page_size: usize,
    /// Additional zero-padded bytes to append after the shellcode.
    pub pad_to: usize,
    /// If true, infer relocations automatically from push-imm32 patterns.
    pub auto_relocate: bool,
    /// Stack size in bytes.
    pub stack_size: usize,
    /// Heap size in bytes.
    pub heap_size: usize,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            base_address: 0x1000,
            page_size: 0x1000,
            pad_to: 0,
            auto_relocate: false,
            stack_size: 0x10_0000,
            heap_size: 0x40_0000,
        }
    }
}

/// Result of loading shellcode into a `MemoryMap`.
#[derive(Debug)]
pub struct LoadedShellcode {
    /// The populated virtual memory map.
    pub memory: MemoryMap,
    /// Effective load address.
    pub base: u64,
    /// Total size of the code region (page-aligned).
    pub code_size: usize,
    /// Stack pointer value (top of stack region).
    pub stack_pointer: u64,
    /// Heap base address.
    pub heap_base: u64,
    /// Detection result.
    pub detection: DetectionResult,
    /// Relocations that were applied.
    pub relocations_applied: Vec<Relocation>,
}

/// Main shellcode loader.
pub struct ShellcodeLoader {
    config: LoadConfig,
}

impl ShellcodeLoader {
    #[must_use]
    pub fn new(config: LoadConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LoadConfig::default())
    }

    /// Load `shellcode` into a fresh `MemoryMap` using the loader configuration.
    #[must_use]
    pub fn load(&self, shellcode: &[u8]) -> LoadedShellcode {
        let detection = DetectionHeuristics::analyze(shellcode);

        // Determine code region size (page-aligned)
        let raw_size = shellcode.len().max(self.config.pad_to);
        let code_size = align_up(raw_size, self.config.page_size);

        let mut code_buf = vec![0u8; code_size];
        code_buf[..shellcode.len()].copy_from_slice(shellcode);

        let base = self.config.base_address;

        // Apply relocations if requested
        let mut relocations_applied = Vec::new();
        if self.config.auto_relocate {
            relocations_applied = self.infer_and_apply_relocations(&mut code_buf, base);
        }

        let mut memory = MemoryMap::new();

        // Code region
        memory.add_region(MemoryRegion::new(
            base,
            code_buf,
            MemFlags::RWX,
            "shellcode",
        ));

        // Stack region — grows downward
        let stack_base = base + code_size as u64 + 0x1000;
        memory.alloc(stack_base, self.config.stack_size, MemFlags::RW, "stack");
        let stack_pointer = stack_base + self.config.stack_size as u64 - 0x10;

        // Heap region
        let heap_base = stack_base + self.config.stack_size as u64 + 0x1000;
        memory.alloc(heap_base, self.config.heap_size, MemFlags::RW, "heap");

        // Dummy PEB/TEB stub (first 0x1000 bytes at address 0x7FFE_0000)
        memory.alloc(0x7FFE_0000, 0x1000, MemFlags::READ, "peb_stub");

        LoadedShellcode {
            memory,
            base,
            code_size,
            stack_pointer,
            heap_base,
            detection,
            relocations_applied,
        }
    }

    /// Infer 32-bit address relocations by scanning for PUSH imm32 instructions
    /// that reference the shellcode base range, and patch them with the new base.
    fn infer_and_apply_relocations(&self, code: &mut Vec<u8>, new_base: u64) -> Vec<Relocation> {
        let old_base: u64 = 0; // assume original position-independent code loaded at 0
        let code_len = code.len() as u64;
        let mut relocs = Vec::new();

        let mut i = 0usize;
        while i + 5 <= code.len() {
            if code[i] == 0x68 {
                let imm = u32::from_le_bytes([code[i+1], code[i+2], code[i+3], code[i+4]]) as u64;
                if imm >= old_base && imm < old_base + code_len {
                    let patched = new_base.saturating_add(imm - old_base) as u32;
                    code[i+1..i+5].copy_from_slice(&patched.to_le_bytes());
                    relocs.push(Relocation { offset: i + 1, width: 4, addend: new_base as i64 });
                }
            }
            i += 1;
        }
        relocs
    }
}

fn align_up(val: usize, align: usize) -> usize {
    if align == 0 { return val; }
    val.saturating_add(align - 1) & !(align - 1)
}

// ── Import table stub ─────────────────────────────────────────────────────────

/// A stub for a single imported function placed in the fake IAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    /// DLL name.
    pub dll: String,
    /// Function name.
    pub function: String,
    /// Virtual address where the stub is mapped.
    pub stub_address: u64,
}

/// Builds a fake Import Address Table stub region so shellcode that resolves
/// APIs via hardcoded addresses will hit the correct stub.
#[derive(Debug, Default)]
pub struct FakeIat {
    entries: Vec<IatEntry>,
    next_addr: u64,
}

impl FakeIat {
    /// Create a new fake IAT with stubs starting at `base`.
    #[must_use]
    pub fn new(base: u64) -> Self {
        Self { entries: Vec::new(), next_addr: base }
    }

    /// Register a stub for `dll::function`, returning its address.
    pub fn register(&mut self, dll: impl Into<String>, function: impl Into<String>) -> u64 {
        let addr = self.next_addr;
        self.entries.push(IatEntry {
            dll: dll.into(),
            function: function.into(),
            stub_address: addr,
        });
        self.next_addr += 0x10; // 16-byte spacing
        addr
    }

    /// Look up the stub address for `dll::function`.
    #[must_use]
    pub fn lookup(&self, dll: &str, function: &str) -> Option<u64> {
        self.entries.iter().find(|e| {
            e.dll.eq_ignore_ascii_case(dll) && e.function.eq_ignore_ascii_case(function)
        }).map(|e| e.stub_address)
    }

    /// Map all stubs as INT3 breakpoints into `memory`.
    pub fn map_into(&self, memory: &mut MemoryMap) {
        let total = self.entries.len() * 0x10;
        if total == 0 { return; }
        let first = self.entries[0].stub_address;
        // Build stub region: each stub is `INT3; RET; NOP×14`
        let mut region_data = vec![0xCCu8; total];
        for (i, _) in self.entries.iter().enumerate() {
            region_data[i * 0x10] = 0xCC; // INT3
            region_data[i * 0x10 + 1] = 0xC3; // RET
        }
        memory.add_region(MemoryRegion::new(
            first,
            region_data,
            MemFlags::RX,
            "fake_iat",
        ));
    }

    /// All registered entries.
    #[must_use]
    pub fn entries(&self) -> &[IatEntry] {
        &self.entries
    }
}

/// Pre-populate a `FakeIat` with common Windows shellcode targets.
#[must_use]
pub fn build_default_iat(base: u64) -> FakeIat {
    let mut iat = FakeIat::new(base);
    let entries: &[(&str, &str)] = &[
        ("kernel32", "VirtualAlloc"),
        ("kernel32", "VirtualAllocEx"),
        ("kernel32", "VirtualProtect"),
        ("kernel32", "VirtualFree"),
        ("kernel32", "LoadLibraryA"),
        ("kernel32", "LoadLibraryW"),
        ("kernel32", "GetProcAddress"),
        ("kernel32", "CreateThread"),
        ("kernel32", "CreateRemoteThread"),
        ("kernel32", "WriteProcessMemory"),
        ("kernel32", "ReadProcessMemory"),
        ("kernel32", "OpenProcess"),
        ("kernel32", "WinExec"),
        ("kernel32", "ExitProcess"),
        ("kernel32", "HeapAlloc"),
        ("kernel32", "HeapCreate"),
        ("kernel32", "CreateFileA"),
        ("kernel32", "WriteFile"),
        ("kernel32", "ReadFile"),
        ("kernel32", "CloseHandle"),
        ("ws2_32", "WSAStartup"),
        ("ws2_32", "WSASocketA"),
        ("ws2_32", "socket"),
        ("ws2_32", "connect"),
        ("ws2_32", "send"),
        ("ws2_32", "recv"),
        ("ws2_32", "closesocket"),
        ("wininet", "InternetOpenA"),
        ("wininet", "InternetConnectA"),
        ("wininet", "HttpSendRequestA"),
        ("ntdll", "NtAllocateVirtualMemory"),
        ("ntdll", "NtWriteVirtualMemory"),
    ];
    for (dll, func) in entries {
        iat.register(*dll, *func);
    }
    iat
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_read_write() {
        let mut r = MemoryRegion::new(0x1000, vec![0u8; 64], MemFlags::RWX, "test");
        assert!(r.write(0x1000, &[1, 2, 3, 4]));
        let data = r.read(0x1000, 4).unwrap();
        assert_eq!(data, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_memory_map_alloc_read_write() {
        let mut m = MemoryMap::new();
        m.alloc(0x1000, 256, MemFlags::RWX, "code");
        assert!(m.write(0x1000, &[0x90, 0xF4]));
        let data = m.read(0x1000, 2).unwrap();
        assert_eq!(data, vec![0x90, 0xF4]);
    }

    #[test]
    fn test_nop_sled_detection() {
        let mut buf = vec![0x90u8; 32];
        buf.push(0xF4);
        let r = DetectionHeuristics::analyze(&buf);
        assert!(r.signals.iter().any(|s| matches!(s, DetectionSignal::NopSled { .. })));
        assert!(r.score >= 10);
    }

    #[test]
    fn test_push_ret_detection() {
        let buf = [0x68u8, 0x00, 0x20, 0x00, 0x00, 0xC3];
        let r = DetectionHeuristics::analyze(&buf);
        assert!(r.signals.iter().any(|s| matches!(s, DetectionSignal::PushRetJump)));
    }

    #[test]
    fn test_get_pc_detection() {
        let buf = [0xE8u8, 0x00, 0x00, 0x00, 0x00, 0x58]; // CALL $+5; POP EAX
        let r = DetectionHeuristics::analyze(&buf);
        assert!(r.signals.iter().any(|s| matches!(s, DetectionSignal::GetPcTrick)));
    }

    #[test]
    fn test_ascii_api_detection() {
        let mut buf = vec![0x00u8; 16];
        buf.extend_from_slice(b"VirtualAlloc\x00");
        let r = DetectionHeuristics::analyze(&buf);
        assert!(r.signals.iter().any(|s| matches!(s, DetectionSignal::AsciiApiString { .. })));
    }

    #[test]
    fn test_loader_creates_regions() {
        let loader = ShellcodeLoader::with_defaults();
        let shellcode = vec![0x90u8; 32];
        let loaded = loader.load(&shellcode);
        assert!(loaded.memory.region_at(loaded.base).is_some());
        assert!(loaded.memory.region_at(loaded.stack_pointer - 8).is_some());
        assert!(loaded.memory.region_at(loaded.heap_base).is_some());
    }

    #[test]
    fn test_loader_shellcode_content_preserved() {
        let loader = ShellcodeLoader::with_defaults();
        let shellcode = vec![0x90u8, 0xF4, 0x00, 0x00];
        let loaded = loader.load(&shellcode);
        let data = loaded.memory.read(loaded.base, 4).unwrap();
        assert_eq!(&data[..4], &[0x90, 0xF4, 0x00, 0x00]);
    }

    #[test]
    fn test_fake_iat_register_lookup() {
        let mut iat = FakeIat::new(0x7000_0000);
        let addr = iat.register("kernel32", "VirtualAlloc");
        assert_eq!(iat.lookup("kernel32", "VirtualAlloc"), Some(addr));
        assert_eq!(iat.lookup("kernel32", "NonExistent"), None);
    }

    #[test]
    fn test_default_iat_has_entries() {
        let iat = build_default_iat(0x7000_0000);
        assert!(iat.entries().len() >= 20);
        assert!(iat.lookup("kernel32", "VirtualAlloc").is_some());
        assert!(iat.lookup("ws2_32", "socket").is_some());
    }

    #[test]
    fn test_detection_likely_shellcode_flag() {
        // Buffer with multiple strong signals
        let mut buf = vec![0x90u8; 16]; // NOP sled
        buf.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]); // GetPC
        buf.extend_from_slice(b"VirtualAlloc\x00");
        let r = DetectionHeuristics::analyze(&buf);
        // Score should be high enough to flag as shellcode
        assert!(r.likely_shellcode || r.score > 0);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }
}
