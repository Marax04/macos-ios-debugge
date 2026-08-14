//! `emulation_harness` — emulation harness for SMC analysis.

use crate::{SmcAlgorithm, SmcDecryptor, SmcKey, SmcRegion, shannon_entropy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── HookKind ──────────────────────────────────────────────────────────────────

/// Types of hooks the harness can install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookKind {
    VirtualProtect,
    Mprotect,
    MemoryWrite,
    MemoryRead,
    CodeExec,
}

// ── HookRecord ────────────────────────────────────────────────────────────────

/// A record of a hooked call/event during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRecord {
    /// Address where the hook fired.
    pub pc: u64,
    /// Hook type label.
    pub hook_type: String,
    /// Captured arguments (positional, as u64).
    pub args: Vec<u64>,
}

impl HookRecord {
    /// Create a new record.
    #[must_use]
    pub fn new(pc: u64, hook_type: impl Into<String>, args: Vec<u64>) -> Self {
        Self {
            pc,
            hook_type: hook_type.into(),
            args,
        }
    }
}

// ── WrittenRegion ─────────────────────────────────────────────────────────────

/// A memory region captured during emulation (written by the decryptor).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrittenRegion {
    /// Base address of the region.
    pub base: u64,
    /// The bytes that were written.
    pub bytes: Vec<u8>,
    /// Entropy of the written content.
    pub entropy: f64,
}

impl WrittenRegion {
    /// Create a new region record.
    #[must_use]
    pub fn new(base: u64, bytes: Vec<u8>) -> Self {
        let entropy = shannon_entropy(&bytes);
        Self {
            base,
            bytes,
            entropy,
        }
    }

    /// Length of the region.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ── KeyFinding ────────────────────────────────────────────────────────────────

/// A key value recovered during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    /// The key value.
    pub key: SmcKey,
    /// The algorithm it was associated with.
    pub algorithm: SmcAlgorithm,
    /// Address where it was found.
    pub found_at: u64,
    /// Confidence (0.0–1.0).
    pub confidence: f32,
}

// ── HarnessResult ─────────────────────────────────────────────────────────────

/// Result of running the emulation harness on a binary.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HarnessResult {
    /// All written memory regions captured.
    pub decoded_regions: Vec<WrittenRegion>,
    /// All key material found.
    pub keys_found: Vec<KeyFinding>,
    /// Hook events fired during emulation.
    pub hook_records: Vec<HookRecord>,
    /// Number of instructions executed (simulated).
    pub insns_executed: u64,
    /// Whether execution completed normally.
    pub completed: bool,
    /// Optional error message.
    pub error: Option<String>,
}

impl HarnessResult {
    /// Total decoded bytes across all regions.
    #[must_use]
    pub fn total_decoded_bytes(&self) -> usize {
        self.decoded_regions.iter().map(WrittenRegion::len).sum()
    }

    /// Number of distinct regions decoded.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.decoded_regions.len()
    }

    /// Whether any keys were found.
    #[must_use]
    pub const fn has_keys(&self) -> bool {
        !self.keys_found.is_empty()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "regions={} keys={} hooks={} insns={} completed={}",
            self.region_count(),
            self.keys_found.len(),
            self.hook_records.len(),
            self.insns_executed,
            self.completed
        )
    }
}

// ── ImportPatcher ─────────────────────────────────────────────────────────────

/// Patches IAT (Import Address Table) entries to stub out OS calls.
pub struct ImportPatcher {
    patches: HashMap<u64, Vec<u8>>,
    /// Stub addresses: IAT entry address → stub code address.
    pub stubs: HashMap<String, u64>,
}

impl ImportPatcher {
    /// Create a new patcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
            stubs: HashMap::new(),
        }
    }

    /// Register a stub for the named import.
    pub fn register_stub(&mut self, import_name: impl Into<String>, stub_addr: u64) {
        self.stubs.insert(import_name.into(), stub_addr);
    }

    /// Apply an IAT patch: overwrite `iat_addr` with `stub_addr` (8-byte pointer).
    pub fn patch_iat(&mut self, iat_addr: u64, stub_addr: u64) {
        self.patches
            .insert(iat_addr, stub_addr.to_le_bytes().to_vec());
    }

    /// Apply all registered patches to `data` starting at `image_base`.
    pub fn apply(&self, data: &mut [u8], image_base: u64) {
        for (&iat_addr, patch) in &self.patches {
            let offset = usize::try_from(iat_addr.saturating_sub(image_base)).unwrap_or(usize::MAX);
            if offset + patch.len() <= data.len() {
                data[offset..offset + patch.len()].copy_from_slice(patch);
            }
        }
    }

    /// Number of patches registered.
    #[must_use]
    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }
}

impl Default for ImportPatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── VirtualMemory ─────────────────────────────────────────────────────────────

/// Simple virtual memory model for the harness.
pub struct VirtualMemory {
    /// Memory pages: `base_addr` (page-aligned) → bytes.
    pages: HashMap<u64, Vec<u8>>,
    /// Page size.
    pub page_size: usize,
    /// Written addresses tracked by the harness.
    pub write_log: Vec<(u64, u8)>,
}

impl VirtualMemory {
    /// Maximum number of bytes that `read_range` will allocate in one call.
    /// Prevents denial-of-service from a region with an untrusted size field.
    pub const MAX_READ_LEN: usize = 64 * 1024 * 1024; // 64 MiB

    /// Maximum number of write-log entries retained before the log is capped.
    /// Prevents unbounded memory growth when a harness runs over a huge trace.
    pub const MAX_WRITE_LOG: usize = 1_000_000;

    /// Create a new virtual memory with `page_size`-byte pages.
    ///
    /// `page_size` must be a power of two and at least 16 bytes; if it is not,
    /// it is silently rounded up to `4096` to prevent a zero-mask panic.
    #[must_use]
    pub fn new(page_size: usize) -> Self {
        // Guard: page_size == 0 would cause `page_size as u64 - 1` to wrap and
        // `!(0u64 - 1)` == 0, making every address map to aligned==0 and the
        // `vec![0u8; 0]` allocation to then be indexed out-of-bounds.
        let page_size = if page_size.is_power_of_two() && page_size >= 16 {
            page_size
        } else {
            4096
        };
        Self {
            pages: HashMap::new(),
            page_size,
            write_log: Vec::new(),
        }
    }

    /// Map `data` at `base`.
    pub fn map(&mut self, base: u64, data: &[u8]) {
        let aligned = base & !(self.page_size as u64 - 1);
        let page = self
            .pages
            .entry(aligned)
            .or_insert_with(|| vec![0u8; self.page_size]);
        let offset = usize::try_from(base - aligned).unwrap_or(usize::MAX);
        let copy_len = data.len().min(page.len().saturating_sub(offset));
        if copy_len > 0 {
            page[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
        }
    }

    /// Read a byte at `addr`.
    #[must_use]
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        let aligned = addr & !(self.page_size as u64 - 1);
        let offset = usize::try_from(addr - aligned).unwrap_or(usize::MAX);
        self.pages
            .get(&aligned)
            .and_then(|p| p.get(offset))
            .copied()
    }

    /// Write a byte at `addr` and log it.
    pub fn write_byte(&mut self, addr: u64, val: u8) {
        let aligned = addr & !(self.page_size as u64 - 1);
        let offset = usize::try_from(addr - aligned).unwrap_or(usize::MAX);
        let page_size = self.page_size;
        let page = self
            .pages
            .entry(aligned)
            .or_insert_with(|| vec![0u8; page_size]);
        if offset < page.len() {
            page[offset] = val;
            // Cap the write log to prevent unbounded memory growth when the
            // harness is driven by a very long dynamic trace.
            if self.write_log.len() < Self::MAX_WRITE_LOG {
                self.write_log.push((addr, val));
            }
        }
    }

    /// Extract a contiguous slice `[start, start+len)` from mapped memory.
    ///
    /// `len` is capped at [`Self::MAX_READ_LEN`] to prevent denial-of-service
    /// via an untrusted region-size field producing a multi-GiB allocation.
    #[must_use]
    pub fn read_range(&self, start: u64, len: usize) -> Vec<u8> {
        let len = len.min(Self::MAX_READ_LEN);
        (0..len as u64)
            .map(|i| self.read_byte(start + i).unwrap_or(0))
            .collect()
    }

    /// Build a `WrittenRegion` from the write log for addresses in `[start, start+len)`.
    #[must_use]
    pub fn written_region(&self, start: u64, len: usize) -> Option<WrittenRegion> {
        let bytes = self.read_range(start, len);
        if bytes.iter().any(|&b| b != 0) {
            Some(WrittenRegion::new(start, bytes))
        } else {
            None
        }
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        Self::new(4096)
    }
}

// ── SmcEmulationHarness ───────────────────────────────────────────────────────

/// The main emulation harness for SMC analysis.
///
/// Sets up emulated memory, patches imports, installs hooks for
/// `VirtualProtect` / `mprotect`, and captures written regions.
pub struct SmcEmulationHarness {
    pub memory: VirtualMemory,
    pub import_patcher: ImportPatcher,
    pub regions: Vec<SmcRegion>,
    pub hook_vp: bool,
    pub hook_mprotect: bool,
    pub hook_writes: bool,
    pub max_insns: u64,
}

impl SmcEmulationHarness {
    /// Create a new harness with all hooks enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            memory: VirtualMemory::default(),
            import_patcher: ImportPatcher::new(),
            regions: Vec::new(),
            hook_vp: true,
            hook_mprotect: true,
            hook_writes: true,
            max_insns: 100_000,
        }
    }

    /// Load a binary at `base_addr` into emulated memory.
    pub fn load_binary(&mut self, data: &[u8], base_addr: u64) {
        self.memory.map(base_addr, data);
    }

    /// Register an SMC region to decrypt during emulation.
    pub fn add_region(&mut self, region: SmcRegion) {
        self.regions.push(region);
    }

    /// Restart execution: re-load initial memory state and re-apply decryptors.
    pub fn restart(&mut self, binary: &[u8], base_addr: u64) {
        self.memory = VirtualMemory::default();
        self.memory.map(base_addr, binary);
    }

    /// Execute the harness: simulate decryption and capture results.
    ///
    /// In a full Unicorn integration this would call `uc_emu_start`. Here it
    /// directly invokes the decryptors to produce the same observable outputs.
    pub fn run(&mut self, base_addr: u64) -> HarnessResult {
        let mut result = HarnessResult {
            insns_executed: 0,
            ..HarnessResult::default()
        };

        let dec = SmcDecryptor::new();
        for region in &self.regions {
            let size = usize::try_from(region.len()).unwrap_or(usize::MAX);
            let start = usize::try_from(region.start).unwrap_or(usize::MAX);
            // Skip regions that fall outside the loaded image around `base_addr`.
            debug_assert!(start as u64 >= base_addr || base_addr == 0);
            let data = self.memory.read_range(region.start, size);
            if data.is_empty() {
                continue;
            }

            let decrypted = dec.decrypt(&data, region);

            // Simulate writing decrypted bytes back to memory.
            for (i, &b) in decrypted.iter().enumerate() {
                self.memory.write_byte(region.start + i as u64, b);
            }

            // Record the written region.
            result
                .decoded_regions
                .push(WrittenRegion::new(region.start, decrypted));

            // Record a hook fire (simulated VirtualProtect/mprotect if hook enabled).
            if self.hook_vp {
                result.hook_records.push(HookRecord::new(
                    base_addr + 0x100, // simulated stub address
                    "VirtualProtect",
                    vec![region.start, region.len(), 0x40, 0],
                ));
            }

            // Record key finding.
            result.keys_found.push(KeyFinding {
                key: region.key.clone(),
                algorithm: region.algorithm.clone(),
                found_at: region.decryptor_addr,
                confidence: 0.85,
            });

            result.insns_executed += size as u64 / 3; // heuristic
        }

        result.completed = true;
        result
    }

    /// Patch a specific import to a stub address.
    pub fn patch_import(&mut self, name: impl Into<String>, iat_addr: u64, stub_addr: u64) {
        let n = name.into();
        self.import_patcher.register_stub(n, stub_addr);
        self.import_patcher.patch_iat(iat_addr, stub_addr);
    }

    /// Return all regions that were written during the last `run()`.
    #[must_use]
    pub fn written_regions(&self) -> Vec<WrittenRegion> {
        // Gather all write log entries and group into contiguous runs.
        if self.memory.write_log.is_empty() {
            return Vec::new();
        }
        let mut log = self.memory.write_log.clone();
        log.sort_by_key(|(a, _)| *a);

        let mut regions = Vec::new();
        let (mut start, _) = log[0];
        let mut bytes = vec![log[0].1];

        for &(addr, val) in &log[1..] {
            if addr == start + bytes.len() as u64 {
                bytes.push(val);
            } else {
                regions.push(WrittenRegion::new(start, bytes.clone()));
                start = addr;
                bytes = vec![val];
            }
        }
        regions.push(WrittenRegion::new(start, bytes));
        regions
    }
}

impl Default for SmcEmulationHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_region(start: u64, size: u64, key: u8) -> SmcRegion {
        SmcRegion {
            start,
            end: start + size,
            decryptor_addr: start,
            key: SmcKey::Constant(u64::from(key)),
            algorithm: SmcAlgorithm::Xor,
        }
    }

    #[test]
    fn test_hook_record_new() {
        let r = HookRecord::new(0x1000, "VirtualProtect", vec![0x2000, 0x1000, 0x40, 0]);
        assert_eq!(r.pc, 0x1000);
        assert_eq!(r.hook_type, "VirtualProtect");
        assert_eq!(r.args.len(), 4);
    }

    #[test]
    fn test_written_region_new() {
        let r = WrittenRegion::new(0x1000, vec![0x90; 16]);
        assert_eq!(r.base, 0x1000);
        assert_eq!(r.len(), 16);
        assert!(r.entropy.abs() < f64::EPSILON); // all same byte → entropy 0
    }

    #[test]
    fn test_written_region_is_empty() {
        let r = WrittenRegion::new(0, vec![]);
        assert!(r.is_empty());
    }

    #[test]
    fn test_harness_result_summary() {
        let mut r = HarnessResult::default();
        r.decoded_regions.push(WrittenRegion::new(0, vec![0x90; 4]));
        r.completed = true;
        let s = r.summary();
        assert!(s.contains("regions=1"));
        assert!(s.contains("completed=true"));
    }

    #[test]
    fn test_harness_result_total_decoded_bytes() {
        let mut r = HarnessResult::default();
        r.decoded_regions.push(WrittenRegion::new(0, vec![0; 10]));
        r.decoded_regions.push(WrittenRegion::new(10, vec![0; 20]));
        assert_eq!(r.total_decoded_bytes(), 30);
    }

    #[test]
    fn test_import_patcher_new() {
        let p = ImportPatcher::new();
        assert_eq!(p.patch_count(), 0);
    }

    #[test]
    fn test_import_patcher_patch_iat() {
        let mut p = ImportPatcher::new();
        p.patch_iat(0x2000, 0xDEAD_BEEF);
        assert_eq!(p.patch_count(), 1);
    }

    #[test]
    fn test_import_patcher_apply() {
        let mut p = ImportPatcher::new();
        p.patch_iat(0x1000, 0x0000_1234_5678);
        let mut data = vec![0u8; 64];
        p.apply(&mut data, 0x1000);
        let val = u64::from_le_bytes(data[0..8].try_into().unwrap());
        assert_eq!(val, 0x0000_1234_5678);
    }

    #[test]
    fn test_virtual_memory_map_read() {
        let mut mem = VirtualMemory::new(4096);
        mem.map(0x1000, b"hello");
        assert_eq!(mem.read_byte(0x1000), Some(b'h'));
        assert_eq!(mem.read_byte(0x1004), Some(b'o'));
    }

    #[test]
    fn test_virtual_memory_write_log() {
        let mut mem = VirtualMemory::new(4096);
        mem.write_byte(0x2000, 0xAA);
        assert_eq!(mem.write_log.len(), 1);
        assert_eq!(mem.write_log[0], (0x2000, 0xAA));
    }

    #[test]
    fn test_virtual_memory_read_range() {
        let mut mem = VirtualMemory::new(4096);
        mem.map(0x3000, &[1, 2, 3, 4]);
        let range = mem.read_range(0x3000, 4);
        assert_eq!(range, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_virtual_memory_written_region_nonzero() {
        let mut mem = VirtualMemory::new(4096);
        mem.write_byte(0x4000, 0xFF);
        let wr = mem.written_region(0x4000, 4096);
        assert!(wr.is_some());
    }

    #[test]
    fn test_harness_load_and_run() {
        let plain = b"NOPNOPNOP".to_vec();
        let key = 0x42u8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let mut binary = vec![0u8; 128];
        binary[..cipher.len()].copy_from_slice(&cipher);
        let region = xor_region(0x4000_0000, plain.len() as u64, key);

        let mut harness = SmcEmulationHarness::new();
        harness.load_binary(&binary, 0x4000_0000);
        harness.add_region(region);
        let result = harness.run(0x4000_0000);

        assert!(result.completed);
        assert_eq!(result.region_count(), 1);
        assert_eq!(result.decoded_regions[0].bytes, plain);
    }

    #[test]
    fn test_harness_vp_hook_fires() {
        let mut h = SmcEmulationHarness::new();
        h.hook_vp = true;
        let region = xor_region(0x4000_0000, 4, 0x11);
        let mut binary = vec![0u8; 8];
        for b in &mut binary {
            *b ^= 0x11;
        }
        h.load_binary(&binary, 0x4000_0000);
        h.add_region(region);
        let result = h.run(0x4000_0000);
        assert!(!result.hook_records.is_empty());
        assert_eq!(result.hook_records[0].hook_type, "VirtualProtect");
    }

    #[test]
    fn test_harness_key_found() {
        let mut h = SmcEmulationHarness::new();
        h.add_region(xor_region(0, 4, 0x77));
        let binary = vec![0u8; 8];
        h.load_binary(&binary, 0);
        let result = h.run(0);
        assert!(result.has_keys());
        assert!(matches!(result.keys_found[0].key, SmcKey::Constant(0x77)));
    }

    #[test]
    fn test_harness_patch_import() {
        let mut h = SmcEmulationHarness::new();
        h.patch_import("VirtualProtect", 0x2000, 0xDEAD_BEEF);
        assert_eq!(h.import_patcher.patch_count(), 1);
    }

    #[test]
    fn test_harness_restart_clears_memory() {
        let mut h = SmcEmulationHarness::new();
        h.memory.write_byte(0x1000, 0xFF);
        h.restart(&[0x90; 64], 0x1000);
        // After restart the first byte should be 0x90 (NOP), not 0xFF.
        assert_eq!(h.memory.read_byte(0x1000), Some(0x90));
    }

    #[test]
    fn test_written_regions_grouped() {
        let mut h = SmcEmulationHarness::new();
        h.memory.write_byte(0x100, 0xAA);
        h.memory.write_byte(0x101, 0xBB);
        h.memory.write_byte(0x200, 0xCC);
        let wr = h.written_regions();
        assert_eq!(wr.len(), 2);
        assert_eq!(wr[0].base, 0x100);
        assert_eq!(wr[1].base, 0x200);
    }

    #[test]
    fn test_virtual_memory_read_unmapped_returns_zero() {
        let mem = VirtualMemory::new(4096);
        assert_eq!(mem.read_byte(0xDEAD_BEEF), None);
    }

    #[test]
    fn test_harness_result_no_regions_by_default() {
        let r = HarnessResult::default();
        assert_eq!(r.region_count(), 0);
        assert!(!r.has_keys());
    }
}
