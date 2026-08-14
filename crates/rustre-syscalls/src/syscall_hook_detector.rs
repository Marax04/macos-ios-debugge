/// Syscall hook detection: scan ntdll stubs, identify SSDT patches, userland
/// JMP/CALL detours, and compute per-stub confidence scores.
///
/// Works entirely on byte slices — no OS calls required.
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// PatchType — what kind of modification was detected
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchType {
    /// Standard `mov eax, nr; syscall; ret` — unmodified.
    Clean,
    /// First byte is 0xE9 (JMP rel32) — classic inline hook.
    JmpRel32,
    /// First byte is 0xEB (JMP rel8).
    JmpRel8,
    /// First byte is 0xFF 0x25 — JMP [rip+disp32] absolute indirect.
    JmpIndirect,
    /// First byte is 0xE8 (CALL rel32).
    CallRel32,
    /// First two bytes are 0xFF 0xD0 – 0xFF 0xD7 (CALL reg).
    CallReg,
    /// `push addr; ret` sequence detected (push/ret trampoline).
    PushRet,
    /// `int 3` breakpoint present.
    Int3,
    /// Bytes were zeroed out (memset hook removal artefact).
    Zeroed,
    /// Stub was replaced with a `HLT` sled.
    HltSled,
    /// SSDT entry points outside ntdll text range.
    SsdtPoison,
    /// `WoW64` thunk entry is modified.
    Wow64Modified,
    /// Unrecognised modification.
    Unknown,
}

impl PatchType {
    #[must_use] 
    pub const fn is_suspicious(self) -> bool {
        !matches!(self, Self::Clean)
    }
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clean        => "clean",
            Self::JmpRel32     => "jmp_rel32",
            Self::JmpRel8      => "jmp_rel8",
            Self::JmpIndirect  => "jmp_indirect",
            Self::CallRel32    => "call_rel32",
            Self::CallReg      => "call_reg",
            Self::PushRet      => "push_ret",
            Self::Int3         => "int3",
            Self::Zeroed       => "zeroed",
            Self::HltSled      => "hlt_sled",
            Self::SsdtPoison   => "ssdt_poison",
            Self::Wow64Modified=> "wow64_modified",
            Self::Unknown      => "unknown",
        }
    }
}

impl fmt::Display for PatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// HookConfidence — 0–100 score
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HookConfidence(pub u8);

impl HookConfidence {
    pub const NONE:    Self = Self(0);
    pub const LOW:     Self = Self(25);
    pub const MEDIUM:  Self = Self(50);
    pub const HIGH:    Self = Self(75);
    pub const CERTAIN: Self = Self(100);

    #[must_use] 
    pub const fn from_patch_type(pt: PatchType) -> Self {
        match pt {
            PatchType::Clean        => Self::NONE,
            PatchType::JmpRel32
            | PatchType::JmpRel8
            | PatchType::JmpIndirect
            | PatchType::CallRel32
            | PatchType::PushRet    => Self::CERTAIN,
            PatchType::CallReg
            | PatchType::HltSled
            | PatchType::SsdtPoison
            | PatchType::Wow64Modified => Self::HIGH,
            PatchType::Zeroed
            | PatchType::Int3       => Self::MEDIUM,
            PatchType::Unknown      => Self::LOW,
        }
    }

    #[must_use] 
    pub const fn value(self) -> u8 { self.0 }
    #[must_use] 
    pub const fn is_suspicious(self) -> bool { self.0 > 0 }
}

impl fmt::Display for HookConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

// ---------------------------------------------------------------------------
// SyscallPatch — describes a single patched stub
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SyscallPatch {
    /// Offset of the stub within the buffer that was scanned.
    pub stub_offset: u64,
    /// Syscall name if known.
    pub name: Option<String>,
    /// Syscall number extracted from stub (if available).
    pub syscall_number: Option<u16>,
    /// Type of patch detected.
    pub patch_type: PatchType,
    /// Confidence in this being a real hook.
    pub confidence: HookConfidence,
    /// First 16 bytes of the stub.
    pub stub_bytes: [u8; 16],
    /// Target address extracted from the hook, if decodable.
    pub hook_target: Option<u64>,
    /// Optional additional detail string.
    pub detail: String,
}

impl SyscallPatch {
    #[must_use] 
    pub const fn new_clean(stub_offset: u64, stub_bytes: [u8; 16]) -> Self {
        Self {
            stub_offset,
            name: None,
            syscall_number: None,
            patch_type: PatchType::Clean,
            confidence: HookConfidence::NONE,
            stub_bytes,
            hook_target: None,
            detail: String::new(),
        }
    }
}

impl fmt::Display for SyscallPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[+{:08x}] {:12} | {:15} | conf={}",
            self.stub_offset,
            self.name.as_deref().unwrap_or("?"),
            self.patch_type,
            self.confidence,
        )?;
        if let Some(t) = self.hook_target {
            write!(f, " -> 0x{t:016x}")?;
        }
        if !self.detail.is_empty() {
            write!(f, " ({})", self.detail)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SsdtEntry — a single SSDT slot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SsdtEntry {
    pub index: u16,
    pub name: Option<&'static str>,
    /// Encoded offset as stored in the SSDT array (Windows kernel format).
    pub encoded_offset: u32,
    /// Decoded absolute address (base + (offset >> 4)).
    pub resolved_address: u64,
    /// True if the resolved address falls outside the expected ntoskrnl range.
    pub is_hooked: bool,
}

impl SsdtEntry {
    /// Decode a Windows SSDT slot.
    /// `raw_value` is the 4-byte SSDT array element (signed offset from table base).
    /// `table_base` is the address of the SSDT table itself.
    /// `ntoskrnl_start`/`ntoskrnl_end` define the legitimate kernel text range.
    #[must_use] 
    pub fn decode(
        index: u16,
        name: Option<&'static str>,
        raw_value: u32,
        table_base: u64,
        ntoskrnl_start: u64,
        ntoskrnl_end: u64,
    ) -> Self {
        let offset = u64::from(raw_value >> 4);
        let resolved_address = table_base.wrapping_add(offset);
        let is_hooked = resolved_address < ntoskrnl_start || resolved_address >= ntoskrnl_end;
        Self {
            index,
            name,
            encoded_offset: raw_value,
            resolved_address,
            is_hooked,
        }
    }
}

// ---------------------------------------------------------------------------
// Wow64ThunkPatch — WoW64 thunk inspection result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Wow64ThunkPatch {
    pub index: u16,
    pub name: Option<String>,
    /// Raw bytes of the thunk (first 8 bytes).
    pub thunk_bytes: [u8; 8],
    /// True if the thunk does not match `B8 ?? ?? 00 00 EA xx xx xx xx` pattern.
    pub is_patched: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Stub pattern constants
// ---------------------------------------------------------------------------

/// Standard Windows 10/11 x64 ntdll stub pattern (first 8 bytes).
///   4C 8B D1     mov r10, rcx
///   B8 ?? ?? 00 00   mov eax, <`syscall_nr`>
/// (8th byte starts the `syscall` opcode)
pub const CLEAN_STUB_PREFIX: [u8; 3] = [0x4C, 0x8B, 0xD1];

/// x64 `syscall` opcode pair.
pub const SYSCALL_OPCODE: [u8; 2] = [0x0F, 0x05];

/// x86 `int 2e` for legacy path.
pub const INT2E_OPCODE: [u8; 2] = [0xCD, 0x2E];

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    if off + 2 > b.len() { return None; }
    Some(u16::from_le_bytes([b[off], b[off + 1]]))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() { return None; }
    Some(u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]))
}

/// Sign-extend a 32-bit value to 64-bit (for RIP-relative decoding).
fn sign_extend32(v: u32) -> i64 {
    i64::from(v.cast_signed())
}

// ---------------------------------------------------------------------------
// Classify a single stub's bytes
// ---------------------------------------------------------------------------

fn classify_stub(bytes: &[u8; 16], stub_va: u64) -> (PatchType, Option<u64>, String) {
    if bytes.iter().all(|&b| b == 0) {
        return (PatchType::Zeroed, None, "all-zero stub".into());
    }
    if bytes.iter().all(|&b| b == 0xF4) {
        return (PatchType::HltSled, None, "HLT sled".into());
    }

    let b0 = bytes[0];
    let b1 = bytes[1];

    // JMP rel32  0xE9
    if b0 == 0xE9 {
        if let Some(rel) = read_u32_le(bytes, 1) {
            let target = stub_va.wrapping_add(5).wrapping_add(sign_extend32(rel).cast_unsigned());
            return (PatchType::JmpRel32, Some(target), format!("jmp -> 0x{target:x}"));
        }
        return (PatchType::JmpRel32, None, "jmp rel32 (unresolved)".into());
    }

    // JMP rel8  0xEB
    if b0 == 0xEB {
        let rel = i64::from(bytes[1].cast_signed());
        let target = stub_va.wrapping_add(2).wrapping_add(rel.cast_unsigned());
        return (PatchType::JmpRel8, Some(target), format!("jmp short -> 0x{target:x}"));
    }

    // JMP [rip+disp32]  0xFF 0x25
    if b0 == 0xFF && b1 == 0x25 {
        if let Some(disp) = read_u32_le(bytes, 2) {
            let ptr_addr = stub_va.wrapping_add(6).wrapping_add(sign_extend32(disp).cast_unsigned());
            return (PatchType::JmpIndirect, Some(ptr_addr), format!("jmp [0x{ptr_addr:x}]"));
        }
        return (PatchType::JmpIndirect, None, "jmp indirect".into());
    }

    // CALL rel32  0xE8
    if b0 == 0xE8 {
        if let Some(rel) = read_u32_le(bytes, 1) {
            let target = stub_va.wrapping_add(5).wrapping_add(sign_extend32(rel).cast_unsigned());
            return (PatchType::CallRel32, Some(target), format!("call -> 0x{target:x}"));
        }
        return (PatchType::CallRel32, None, "call rel32".into());
    }

    // CALL reg  0xFF 0xD0–0xFF 0xD7
    if b0 == 0xFF && (0xD0..=0xD7).contains(&b1) {
        let reg = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][(b1 & 7) as usize];
        return (PatchType::CallReg, None, format!("call {reg}"));
    }

    // PUSH addr (0x68) + RET (0xC3) pattern in first 6 bytes
    if b0 == 0x68
        && let Some(addr32) = read_u32_le(bytes, 1)
        && bytes[5] == 0xC3
    {
        return (PatchType::PushRet, Some(u64::from(addr32)), format!("push+ret -> 0x{addr32:x}"));
    }

    // INT3
    if b0 == 0xCC {
        return (PatchType::Int3, None, "int3 breakpoint".into());
    }

    // Check for clean stub: 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3
    if bytes[0..3] == CLEAN_STUB_PREFIX && bytes[7..9] == SYSCALL_OPCODE || bytes[8..10] == SYSCALL_OPCODE {
            return (PatchType::Clean, None, String::new());
    }
    // int 2e variant
    if bytes[0..3] == CLEAN_STUB_PREFIX {
        for i in 0..12usize {
            if i + 2 <= 16 && bytes[i..i+2] == INT2E_OPCODE {
                return (PatchType::Clean, None, "int 2e variant".into());
            }
        }
    }

    (PatchType::Unknown, None, format!("first bytes: {:02x} {:02x} {:02x} {:02x}", b0, b1, bytes[2], bytes[3]))
}

/// Extract syscall number from `mov eax, imm32` at bytes[3..7] (standard stub layout).
fn extract_syscall_nr(bytes: &[u8; 16]) -> Option<u16> {
    // Standard: 4C 8B D1 B8 <nr_lo> <nr_hi> 00 00
    if bytes[0..3] == CLEAN_STUB_PREFIX && bytes[3] == 0xB8 {
        let nr = read_u16_le(bytes, 4)?;
        return Some(nr);
    }
    // Fallback: scan for `B8` in first 8 bytes
    for i in 0..8usize {
        if bytes[i] == 0xB8 && i + 4 < 16 {
            let lo = u16::from(bytes[i+1]);
            let hi = u16::from(bytes[i+2]);
            if bytes[i+3] == 0 && bytes[i+4] == 0 {
                return Some(lo | (hi << 8));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HookDetector
// ---------------------------------------------------------------------------

pub struct HookDetector {
    /// Name table: `syscall_number` -> name.
    name_table: HashMap<u16, &'static str>,
    /// Expected base VA of ntdll (used for target plausibility checks).
    ntdll_base: u64,
    /// Size of ntdll text section.
    ntdll_text_size: u64,
}

impl HookDetector {
    #[must_use] 
    pub fn new(ntdll_base: u64, ntdll_text_size: u64) -> Self {
        Self {
            name_table: HashMap::new(),
            ntdll_base,
            ntdll_text_size,
        }
    }

    /// Register a known syscall name mapping.
    pub fn register_name(&mut self, nr: u16, name: &'static str) {
        self.name_table.insert(nr, name);
    }

    /// Bulk-register from a slice of `(nr, name)` pairs.
    pub fn register_names(&mut self, pairs: &[(u16, &'static str)]) {
        for &(nr, name) in pairs {
            self.name_table.insert(nr, name);
        }
    }

    /// Scan a memory region containing ntdll stubs.
    ///
    /// `data`       — raw bytes of the region.
    /// `region_va`  — virtual address of `data[0]`.
    /// `stride`     — expected stub size in bytes (typically 32 for ntdll).
    pub fn scan_stubs(
        &self,
        data: &[u8],
        region_va: u64,
        stride: usize,
    ) -> Vec<SyscallPatch> {
        if stride == 0 { return vec![]; }
        let mut patches = Vec::new();
        let mut offset = 0usize;
        while offset + 16 <= data.len() {
            let stub_va = region_va + offset as u64;
            let mut stub_bytes = [0u8; 16];
            stub_bytes.copy_from_slice(&data[offset..offset + 16]);

            let (patch_type, hook_target, detail) = classify_stub(&stub_bytes, stub_va);
            let syscall_number = extract_syscall_nr(&stub_bytes);
            let name = syscall_number
                .and_then(|nr| self.name_table.get(&nr).copied())
                .map(std::string::ToString::to_string);

            let mut confidence = HookConfidence::from_patch_type(patch_type);

            // Downgrade confidence if hook target lands inside ntdll (trampoline back)
            if let Some(target) = hook_target
                && target >= self.ntdll_base
                && target < self.ntdll_base + self.ntdll_text_size
                && confidence == HookConfidence::CERTAIN
            {
                confidence = HookConfidence::HIGH;
            }

            let p = SyscallPatch {
                stub_offset: offset as u64,
                name,
                syscall_number,
                patch_type,
                confidence,
                stub_bytes,
                hook_target,
                detail,
            };
            patches.push(p);
            offset += stride;
        }
        patches
    }

    /// Scan an SSDT table (array of u32 offsets, Windows kernel format).
    ///
    /// `ssdt_data`       — raw bytes of the SSDT array.
    /// `table_base_va`   — virtual address of `ssdt_data[0]`.
    /// `ntoskrnl_start`  — start of legitimate kernel text.
    /// `ntoskrnl_end`    — end of legitimate kernel text.
    /// `names`           — optional index→name lookup.
    #[must_use] 
    pub fn scan_ssdt(
        &self,
        ssdt_data: &[u8],
        table_base_va: u64,
        ntoskrnl_start: u64,
        ntoskrnl_end: u64,
        names: Option<&[&'static str]>,
    ) -> Vec<SsdtEntry> {
        let mut entries = Vec::new();
        let count = ssdt_data.len() / 4;
        for i in 0..count {
            if let Some(raw) = read_u32_le(ssdt_data, i * 4) {
                let name = names.and_then(|n| n.get(i)).copied();
                let entry = SsdtEntry::decode(
                    u16::try_from(i).unwrap_or(u16::MAX),
                    name,
                    raw,
                    table_base_va,
                    ntoskrnl_start,
                    ntoskrnl_end,
                );
                entries.push(entry);
            }
        }
        entries
    }

    /// Scan `WoW64` thunk table (32-bit processes on 64-bit Windows).
    ///
    /// Each thunk slot is 8 bytes: `B8 <nr_lo> <nr_hi> 00 00 EA <target32>`.
    /// Any deviation is flagged.
    pub fn scan_wow64_thunks(
        &self,
        thunk_data: &[u8],
        names: Option<&[&'static str]>,
    ) -> Vec<Wow64ThunkPatch> {
        let mut results = Vec::new();
        let stride = 8usize;
        let count = thunk_data.len() / stride;
        for i in 0..count {
            let base = i * stride;
            let mut thunk_bytes = [0u8; 8];
            thunk_bytes.copy_from_slice(&thunk_data[base..base + stride]);

            let name = names.and_then(|n| n.get(i)).copied().map(std::string::ToString::to_string);

            // Expected: B8 lo hi 00 00 EA ?? ??
            let is_patched = thunk_bytes[0] != 0xB8
                || thunk_bytes[3] != 0x00
                || thunk_bytes[4] != 0x00
                || thunk_bytes[5] != 0xEA;

            let detail = if is_patched {
                format!("unexpected bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    thunk_bytes[0], thunk_bytes[1], thunk_bytes[2],
                    thunk_bytes[3], thunk_bytes[4], thunk_bytes[5])
            } else {
                String::new()
            };

            results.push(Wow64ThunkPatch {
                index: u16::try_from(i).unwrap_or(u16::MAX),
                name,
                thunk_bytes,
                is_patched,
                detail,
            });
        }
        results
    }

    /// Convenience: count suspicious patches.
    #[must_use] 
    pub fn count_suspicious(patches: &[SyscallPatch]) -> usize {
        patches.iter().filter(|p| p.confidence.is_suspicious()).count()
    }

    /// Filter to only suspicious entries.
    #[must_use] 
    pub fn suspicious_only(patches: &[SyscallPatch]) -> Vec<&SyscallPatch> {
        patches.iter().filter(|p| p.confidence.is_suspicious()).collect()
    }

    /// Check whether `ntdll_bytes` contains a valid-looking text section
    /// (heuristic: at least 80% of bytes are non-zero, no 4-byte zero runs
    /// in the first 128 bytes, indicating the image was not wiped).
    #[must_use] 
    pub fn ntdll_text_appears_intact(ntdll_bytes: &[u8]) -> bool {
        if ntdll_bytes.len() < 128 { return false; }
        let zero_count = ntdll_bytes[..128].iter().fold(0usize, |n, &b| n + usize::from(b == 0));
        // Mostly non-zero
        if zero_count > 64 { return false; }
        // No 4-consecutive-zero run
        for w in ntdll_bytes[..128].windows(4) {
            if w == [0, 0, 0, 0] { return false; }
        }
        true
    }

    /// Compare two snapshots of the same stub table and return indices where
    /// bytes differ (e.g. before/after loading a DLL).
    #[must_use] 
    pub fn diff_snapshots(
        before: &[u8],
        after: &[u8],
        stride: usize,
    ) -> Vec<usize> {
        if stride == 0 { return vec![]; }
        let len = before.len().min(after.len());
        let mut changed = Vec::new();
        let mut i = 0usize;
        while i + stride <= len {
            if before[i..i+stride] != after[i..i+stride] {
                changed.push(i / stride);
            }
            i += stride;
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// HookReport — aggregate scan result
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct HookReport {
    pub stub_patches:   Vec<SyscallPatch>,
    pub ssdt_hooks:     Vec<SsdtEntry>,
    pub wow64_patches:  Vec<Wow64ThunkPatch>,
}

impl HookReport {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub fn total_suspicious(&self) -> usize {
        let stubs = self.stub_patches.iter().filter(|p| p.confidence.is_suspicious()).count();
        let ssdt  = self.ssdt_hooks.iter().filter(|e| e.is_hooked).count();
        let wow64 = self.wow64_patches.iter().filter(|p| p.is_patched).count();
        stubs + ssdt + wow64
    }

    #[must_use] 
    pub fn has_hooks(&self) -> bool {
        self.total_suspicious() > 0
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "stubs={}/{} suspicious, ssdt={}/{} hooked, wow64={}/{} patched",
            self.stub_patches.iter().filter(|p| p.confidence.is_suspicious()).count(),
            self.stub_patches.len(),
            self.ssdt_hooks.iter().filter(|e| e.is_hooked).count(),
            self.ssdt_hooks.len(),
            self.wow64_patches.iter().filter(|p| p.is_patched).count(),
            self.wow64_patches.len(),
        )
    }

    /// Produce a flat list of all suspicious findings as display strings.
    #[must_use] 
    pub fn findings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in self.stub_patches.iter().filter(|p| p.confidence.is_suspicious()) {
            out.push(format!("STUB   {p}"));
        }
        for e in self.ssdt_hooks.iter().filter(|e| e.is_hooked) {
            out.push(format!(
                "SSDT   [{}] {:?} -> 0x{:016x} (OUTSIDE KERNEL)",
                e.index, e.name, e.resolved_address
            ));
        }
        for w in self.wow64_patches.iter().filter(|p| p.is_patched) {
            out.push(format!(
                "WOW64  [{}] {:?} patched: {}",
                w.index, w.name, w.detail
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_stub(nr: u16) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = 0x4C; b[1] = 0x8B; b[2] = 0xD1;
        b[3] = 0xB8;
        b[4] = (nr & 0xFF) as u8;
        b[5] = (nr >> 8) as u8;
        b[6] = 0x00; b[7] = 0x00;
        b[8] = 0x0F; b[9] = 0x05;  // syscall
        b[10]= 0xC3;                // ret
        b
    }

    #[test]
    fn clean_stub_recognised() {
        let bytes = clean_stub(0x0042);
        let (pt, _, _) = classify_stub(&bytes, 0x1000);
        assert_eq!(pt, PatchType::Clean);
        assert_eq!(extract_syscall_nr(&bytes), Some(0x0042));
    }

    #[test]
    fn jmp_rel32_detected() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xE9;
        // rel32 = 0x00001000 → target = 0x2000 + 5 + 0x1000 = 0x3005
        let rel: u32 = 0x0000_1000;
        bytes[1..5].copy_from_slice(&rel.to_le_bytes());
        let (pt, target, _) = classify_stub(&bytes, 0x2000);
        assert_eq!(pt, PatchType::JmpRel32);
        assert_eq!(target, Some(0x3005));
    }

    #[test]
    fn call_rel32_detected() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xE8;
        bytes[1] = 0x00; bytes[2] = 0x10; bytes[3] = 0x00; bytes[4] = 0x00;
        let (pt, _, _) = classify_stub(&bytes, 0x5000);
        assert_eq!(pt, PatchType::CallRel32);
    }

    #[test]
    fn int3_detected() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xCC;
        let (pt, _, _) = classify_stub(&bytes, 0);
        assert_eq!(pt, PatchType::Int3);
    }

    #[test]
    fn zeroed_detected() {
        let bytes = [0u8; 16];
        let (pt, _, _) = classify_stub(&bytes, 0);
        assert_eq!(pt, PatchType::Zeroed);
    }

    #[test]
    fn scan_stubs_finds_hook() {
        let mut data = vec![0u8; 32];
        // Stub 0: clean nr=1
        data[0..16].copy_from_slice(&clean_stub(1));
        // Stub 1: JMP
        data[16] = 0xE9;
        let rel: u32 = 0x100;
        data[17..21].copy_from_slice(&rel.to_le_bytes());

        let detector = HookDetector::new(0x7FFF_0000_0000, 0x10_0000);
        let patches = detector.scan_stubs(&data, 0x1000_0000, 16);
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].patch_type, PatchType::Clean);
        assert_eq!(patches[1].patch_type, PatchType::JmpRel32);
        assert!(patches[1].confidence.is_suspicious());
    }

    #[test]
    fn ssdt_scan_detects_out_of_range() {
        // 4-entry SSDT; entry 2 points outside [0xFFFF_8000_0000_0000, 0xFFFF_8000_0100_0000)
        let base: u64 = 0xFFFF_8000_0000_0000;
        let ntstart = base;
        let ntend   = base + 0x100_0000;

        // encode offset = (resolved - base) << 4
        let make_entry = |resolved: u64| -> u32 {
            let offset = resolved.wrapping_sub(base);
            ((offset & 0x0FFF_FFFF) as u32) << 4
        };

        let mut ssdt = vec![0u8; 16];
        let e0 = make_entry(base + 0x1000);
        let e1 = make_entry(base + 0x2000);
        let e2 = make_entry(base + 0x200_0000); // outside ntend
        let e3 = make_entry(base + 0x3000);
        ssdt[0..4].copy_from_slice(&e0.to_le_bytes());
        ssdt[4..8].copy_from_slice(&e1.to_le_bytes());
        ssdt[8..12].copy_from_slice(&e2.to_le_bytes());
        ssdt[12..16].copy_from_slice(&e3.to_le_bytes());

        let detector = HookDetector::new(0, 0);
        let entries = detector.scan_ssdt(&ssdt, base, ntstart, ntend, None);
        assert_eq!(entries.len(), 4);
        assert!(!entries[0].is_hooked);
        assert!(!entries[1].is_hooked);
        assert!(entries[2].is_hooked);
        assert!(!entries[3].is_hooked);
    }

    #[test]
    fn wow64_clean_thunk() {
        let mut data = [0u8; 8];
        data[0] = 0xB8;
        data[1] = 0x05; data[2] = 0x00;
        data[3] = 0x00; data[4] = 0x00;
        data[5] = 0xEA;
        data[6] = 0x00; data[7] = 0x00;
        let detector = HookDetector::new(0, 0);
        let results = detector.scan_wow64_thunks(&data, None);
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_patched);
    }

    #[test]
    fn diff_snapshots_finds_change() {
        let before = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00,
                          0x0F, 0x05, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut after = before.clone();
        after[0] = 0xE9; // patch first byte
        let changed = HookDetector::diff_snapshots(&before, &after, 16);
        assert_eq!(changed, vec![0]);
    }

    #[test]
    fn hook_report_summary() {
        let report = HookReport::new();
        assert!(!report.has_hooks());
        assert_eq!(report.total_suspicious(), 0);
    }

    #[test]
    fn confidence_ordering() {
        assert!(HookConfidence::CERTAIN > HookConfidence::HIGH);
        assert!(HookConfidence::HIGH > HookConfidence::MEDIUM);
        assert!(HookConfidence::MEDIUM > HookConfidence::LOW);
        assert!(HookConfidence::LOW > HookConfidence::NONE);
    }

    #[test]
    fn ntdll_intact_check() {
        // Random-ish non-zero bytes should pass
        let data: Vec<u8> = (1u8..=128).collect();
        assert!(HookDetector::ntdll_text_appears_intact(&data));
        // All zeros should fail
        let zeros = vec![0u8; 128];
        assert!(!HookDetector::ntdll_text_appears_intact(&zeros));
    }
}
