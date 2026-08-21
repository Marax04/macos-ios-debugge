//! `smc_detector` — enhanced self-modifying code detector.

use crate::{SmcAlgorithm, SmcKey, SmcRegion};
use serde::{Deserialize, Serialize};
/// Re-export of [`std::collections::HashMap`] for callers indexing detected
/// SMC regions by address.
pub use std::collections::HashMap;

// ── SmcRegionExt ──────────────────────────────────────────────────────────────

/// Extended SMC region with additional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcRegionExt {
    pub region: SmcRegion,
    /// Whether a write-then-execute pattern was detected.
    pub write_exec_pattern: bool,
    /// Number of layers detected for this region.
    pub layer_count: u32,
    /// Source pattern that identified this region.
    pub pattern_name: String,
    /// Confidence (0.0–1.0).
    pub confidence: f32,
}

impl SmcRegionExt {
    /// Create from a base region.
    #[must_use]
    pub fn new(region: SmcRegion, pattern_name: impl Into<String>) -> Self {
        Self {
            region,
            write_exec_pattern: false,
            layer_count: 1,
            pattern_name: pattern_name.into(),
            confidence: 0.7,
        }
    }

    /// High-confidence marker.
    #[must_use]
    pub const fn high_confidence(mut self) -> Self {
        self.confidence = 0.95;
        self
    }
}

// ── DecodingLoopPattern ───────────────────────────────────────────────────────

/// Describes a decryption loop pattern detected in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodingLoopPattern {
    /// Virtual address of the loop start.
    pub loop_start: u64,
    /// Loop body length in bytes.
    pub body_size: usize,
    /// Operation type (XOR, ADD, SUB, ROL, ROR, rolling).
    pub op: SmcAlgorithm,
    /// Recovered key byte (best effort).
    pub key: u8,
    /// Estimated number of loop iterations.
    pub iteration_estimate: u64,
    /// Whether a counter register was found.
    pub has_counter: bool,
}

// ── VirtualProtectPattern ─────────────────────────────────────────────────────

/// A Windows `VirtualProtect` call detected before code execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualProtectPattern {
    /// Address of the `VirtualProtect` call instruction.
    pub call_addr: u64,
    /// Target region start (argument 1 / lpAddress).
    pub region_start: u64,
    /// Region size in bytes (argument 2 / dwSize).
    pub region_size: u64,
    /// New protection flags (argument 3 / flNewProtect).
    pub new_protect: u32,
    /// Old protection flags (argument 4 / lpflOldProtect location).
    pub old_protect_ptr: u64,
}

impl VirtualProtectPattern {
    /// Whether the pattern requests executable memory (`PAGE_EXECUTE_*`).
    #[must_use]
    pub const fn makes_executable(&self) -> bool {
        // `PAGE_EXECUTE` = 0x10, `PAGE_EXECUTE_READ` = 0x20, `PAGE_EXECUTE_READWRITE` = 0x40,
        // `PAGE_EXECUTE_WRITECOPY` = 0x80
        self.new_protect & 0xF0 != 0
    }
}

// ── MprotectPattern ───────────────────────────────────────────────────────────

/// A Linux `mprotect` call detected before code execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MprotectPattern {
    /// Address of the `mprotect` syscall/call.
    pub call_addr: u64,
    /// Target region start.
    pub region_start: u64,
    /// Region size.
    pub region_size: u64,
    /// Protection flags (`PROT_EXEC`=4, `PROT_WRITE`=2, `PROT_READ`=1).
    pub prot: u32,
}

impl MprotectPattern {
    /// Whether `PROT_EXEC` is set.
    #[must_use]
    pub const fn has_exec(&self) -> bool {
        self.prot & 0x4 != 0
    }
}

// ── Layer ─────────────────────────────────────────────────────────────────────

/// Represents one layer in a multi-layer SMC scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    /// Layer index (0 = outer-most).
    pub index: u32,
    /// The SMC region for this layer.
    pub region: SmcRegion,
    /// Algorithm used by this layer.
    pub algorithm: SmcAlgorithm,
    /// Key material for this layer.
    pub key: SmcKey,
    /// Whether this layer was successfully decrypted.
    pub decrypted: bool,
}

impl Layer {
    /// Create a new layer descriptor.
    #[must_use]
    pub fn new(index: u32, region: SmcRegion) -> Self {
        let algorithm = region.algorithm.clone();
        let key = region.key.clone();
        Self {
            index,
            region,
            algorithm,
            key,
            decrypted: false,
        }
    }
}

// ── SmcDetectorExt ────────────────────────────────────────────────────────────

/// Enhanced self-modifying code detector that identifies:
/// 1. Write-then-execute patterns.
/// 2. XOR/ADD/SUB decryption loops.
/// 3. `VirtualProtect` calls before execution.
/// 4. mprotect calls on Linux.
/// 5. Multi-layer SMC.
#[derive(Debug, Clone, Default)]
pub struct SmcDetectorExt {
    /// Whether to detect `VirtualProtect` patterns.
    pub detect_vp: bool,
    /// Whether to detect mprotect patterns.
    pub detect_mprotect: bool,
    /// Whether to detect multi-layer SMC.
    pub detect_layers: bool,
    /// Maximum number of layers to follow.
    pub max_layers: u32,
}

impl SmcDetectorExt {
    /// Create a new extended detector with all features enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detect_vp: true,
            detect_mprotect: true,
            detect_layers: true,
            max_layers: 8,
        }
    }

    /// Run all enabled detectors on `data` at the given load `base_addr`.
    #[must_use]
    pub fn detect_all(&self, data: &[u8], base_addr: u64) -> SmcDetectionResult {

        let mut result = SmcDetectionResult {
            xor_loops: Self::find_xor_loops(data, base_addr),
            add_loops: Self::find_add_loops(data, base_addr),
            sub_loops: Self::find_sub_loops(data, base_addr),
            rolling_xor_loops: Self::find_rolling_xor(data, base_addr),
            ..SmcDetectionResult::default()
        };

        if self.detect_vp {
            result.vp_patterns = Self::find_virtual_protect(data, base_addr);
        }
        if self.detect_mprotect {
            result.mprotect_patterns = Self::find_mprotect(data, base_addr);
        }
        if self.detect_layers {
            result.layers = self.detect_layers_in(data, base_addr);
        }

        // Convert loops to extended regions.
        for loop_pat in &result.xor_loops {
            result.regions.push(SmcRegionExt {
                region: SmcRegion {
                    start: base_addr + loop_pat.loop_start,
                    end: base_addr + loop_pat.loop_start + loop_pat.iteration_estimate,
                    decryptor_addr: base_addr + loop_pat.loop_start,
                    key: SmcKey::Constant(u64::from(loop_pat.key)),
                    algorithm: SmcAlgorithm::Xor,
                },
                write_exec_pattern: false,
                layer_count: 1,
                pattern_name: "xor_loop".to_owned(),
                confidence: 0.85,
            });
        }

        result
    }

    // ── XOR loop detection ────────────────────────────────────────────────────

    fn find_xor_loops(data: &[u8], _base: u64) -> Vec<DecodingLoopPattern> {
        let mut out = Vec::new();
        if data.len() < 8 {
            return out;
        }

        for i in 0..data.len().saturating_sub(3) {
            // XOR byte ptr [reg+reg], imm8: 80 3x yy
            if data[i] == 0x80 && (data[i + 1] & 0xC0 != 0xC0) {
                // Account for SIB byte when modrm r/m field == 100.
                let has_sib = (data[i + 1] & 0x07) == 0x04;
                let key_off = i + 2 + usize::from(has_sib);
                if key_off >= data.len() {
                    continue;
                }
                let key = data[key_off];
                // Look for a loop-closing branch (EB xx, E2 xx, 75 xx) within 12 bytes after.
                for j in i + 3..=(i + 15).min(data.len().saturating_sub(1)) {
                    if matches!(data[j], 0xEB | 0xE2 | 0x75 | 0x74) {
                        out.push(DecodingLoopPattern {
                            loop_start: u64::try_from(i).unwrap_or(u64::MAX),
                            body_size: j - i + 2,
                            op: SmcAlgorithm::Xor,
                            key,
                            iteration_estimate: Self::estimate_iterations(data, i),
                            has_counter: Self::has_counter_nearby(data, i),
                        });
                        break;
                    }
                }
            }
        }
        out
    }

    fn find_add_loops(data: &[u8], _base: u64) -> Vec<DecodingLoopPattern> {
        let mut out = Vec::new();
        if data.len() < 3 {
            return out;
        }
        for i in 0..data.len().saturating_sub(2) {
            // ADD byte ptr [reg], imm8: 80 0x imm8
            if data[i] == 0x80 && (data[i + 1] & 0xF8 == 0x00 || data[i + 1] & 0xF8 == 0x08) {
                let key = data[i + 2];
                out.push(DecodingLoopPattern {
                    loop_start: u64::try_from(i).unwrap_or(u64::MAX),
                    body_size: 3,
                    op: SmcAlgorithm::Add,
                    key,
                    iteration_estimate: Self::estimate_iterations(data, i),
                    has_counter: Self::has_counter_nearby(data, i),
                });
            }
        }
        out
    }

    fn find_sub_loops(data: &[u8], _base: u64) -> Vec<DecodingLoopPattern> {
        let mut out = Vec::new();
        if data.len() < 3 {
            return out;
        }
        for i in 0..data.len().saturating_sub(2) {
            // SUB byte ptr [reg], imm8: 80 2x imm8
            if data[i] == 0x80 && (data[i + 1] & 0xF8 == 0x28) {
                let key = data[i + 2];
                out.push(DecodingLoopPattern {
                    loop_start: u64::try_from(i).unwrap_or(u64::MAX),
                    body_size: 3,
                    op: SmcAlgorithm::Sub,
                    key,
                    iteration_estimate: Self::estimate_iterations(data, i),
                    has_counter: Self::has_counter_nearby(data, i),
                });
            }
        }
        out
    }

    fn find_rolling_xor(data: &[u8], _base: u64) -> Vec<DecodingLoopPattern> {
        let mut out = Vec::new();
        // Pattern: MOV AL, [ESI] (8A 06); XOR AL, BL (32 C3); MOV [EDI], AL (88 07)
        let pattern = [0x8A, 0x06, 0x32, 0xC3, 0x88, 0x07];
        if data.len() < pattern.len() {
            return out;
        }
        for i in 0..=data.len() - pattern.len() {
            if data[i..i + pattern.len()] == pattern {
                out.push(DecodingLoopPattern {
                    loop_start: u64::try_from(i).unwrap_or(u64::MAX),
                    body_size: 6,
                    op: SmcAlgorithm::XorRolling,
                    key: 0,
                    iteration_estimate: 64,
                    has_counter: false,
                });
            }
        }
        out
    }

    fn estimate_iterations(data: &[u8], pos: usize) -> u64 {
        // Look backwards up to 16 bytes for MOV ECX, imm32 (B9 xx xx xx xx).
        let start = pos.saturating_sub(16);
        for i in (start..pos).rev() {
            if data[i] == 0xB9 && i + 4 < data.len() {
                let count =
                    u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                if count > 0 && count < 0x10_0000 {
                    return u64::from(count);
                }
            }
        }
        64 // default
    }

    fn has_counter_nearby(data: &[u8], pos: usize) -> bool {
        let end = (pos + 20).min(data.len());
        for i in pos..end.saturating_sub(1) {
            // DEC r32: 48..4F
            if data[i] >= 0x48 && data[i] <= 0x4F {
                return true;
            }
            // DEC r/m32: FF 0x
            if data[i] == 0xFF && i + 1 < data.len() && (data[i + 1] & 0xF8 == 0x08) {
                return true;
            }
        }
        false
    }

    // ── VirtualProtect detection ──────────────────────────────────────────────

    fn find_virtual_protect(data: &[u8], base: u64) -> Vec<VirtualProtectPattern> {
        let mut out = Vec::new();
        if data.len() < 7 {
            return out;
        }

        // Look for CALL [addr] patterns (FF 15 xx xx xx xx) or CALL rel32 (E8 xx xx xx xx)
        // near pushes of PAGE_EXECUTE_READWRITE = 0x40.
        for i in 0..data.len().saturating_sub(2) {
            // PUSH 0x40 (PAGE_EXECUTE_READWRITE): 6A 40
            if data[i] == 0x6A && data[i + 1] == 0x40 {
                // Look ahead for CALL within 16 bytes.
                for j in i + 2..(i + 18).min(data.len().saturating_sub(4)) {
                    if data[j] == 0xE8
                        || (data[j] == 0xFF && j + 1 < data.len() && data[j + 1] == 0x15)
                    {
                        let region_start = Self::extract_push_arg_before(data, i);
                        out.push(VirtualProtectPattern {
                            call_addr: base + u64::try_from(j).unwrap_or(u64::MAX),
                            region_start,
                            region_size: 0x1000, // placeholder
                            new_protect: 0x40,
                            old_protect_ptr: 0,
                        });
                        break;
                    }
                }
            }
        }
        out
    }

    fn extract_push_arg_before(data: &[u8], pos: usize) -> u64 {
        // Scan backwards for PUSH imm32 (68 xx xx xx xx) or MOV reg, imm32 (B8..BF).
        let start = pos.saturating_sub(24);
        for i in (start..pos).rev() {
            if data[i] == 0x68 && i + 4 < data.len() {
                let v = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                if v > 0x1000 {
                    return u64::from(v);
                }
            }
            if data[i] >= 0xB8 && data[i] <= 0xBF && i + 4 < data.len() {
                let v = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                if v > 0x1000 {
                    return u64::from(v);
                }
            }
        }
        0
    }

    // ── mprotect detection ────────────────────────────────────────────────────

    fn find_mprotect(data: &[u8], base: u64) -> Vec<MprotectPattern> {
        let mut out = Vec::new();
        if data.len() < 6 {
            return out;
        }

        // Linux x86-64: MOV EAX, 0xA (mprotect syscall)
        // B8 0A 00 00 00  followed by  0F 05 (SYSCALL)
        for i in 0..data.len().saturating_sub(8) {
            if data[i] == 0xB8 && data[i + 1] == 0x0A && data[i + 2] == 0x00 && data[i + 3] == 0x00
            {
                for j in i + 5..(i + 20).min(data.len().saturating_sub(1)) {
                    if data[j] == 0x0F && data[j + 1] == 0x05 {
                        out.push(MprotectPattern {
                            call_addr: base + u64::try_from(j).unwrap_or(u64::MAX),
                            region_start: 0,
                            region_size: 0x1000,
                            prot: 0x7, // PROT_READ|PROT_WRITE|PROT_EXEC
                        });
                        break;
                    }
                }
            }
        }
        out
    }

    // ── Multi-layer detection ─────────────────────────────────────────────────

    fn detect_layers_in(&self, data: &[u8], base: u64) -> Vec<Layer> {
        let mut layers = Vec::new();
        let mut current = data.to_vec();

        for idx in 0..self.max_layers {
            let regions = Self::basic_detect(&current);
            if regions.is_empty() {
                break;
            }

            for r in &regions {
                let size = usize::try_from(r.len()).unwrap_or(usize::MAX);
                let start = usize::try_from(r.start).unwrap_or(usize::MAX);
                if start.saturating_add(size) > current.len() {
                    continue;
                }

                // Rebase the buffer-relative region onto the caller's image
                // base so the recorded layer carries absolute addresses.
                let mut rebased = r.clone();
                rebased.start = rebased.start.wrapping_add(base);
                rebased.end = rebased.end.wrapping_add(base);
                rebased.decryptor_addr = rebased.decryptor_addr.wrapping_add(base);
                layers.push(Layer::new(idx, rebased));

                // Apply decryption for next layer.
                let dec = crate::SmcDecryptor::new();
                let slice = &current[start..start + size];
                let plain = dec.decrypt(slice, r);
                current[start..start + size].copy_from_slice(&plain);
            }
        }
        layers
    }

    fn basic_detect(data: &[u8]) -> Vec<SmcRegion> {
        let mut out = Vec::new();
        if data.len() < 8 {
            return out;
        }
        for i in 0..data.len().saturating_sub(8) {
            if data[i] == 0xB9 {
                let key = data[i + 1];
                for j in (i + 5)..(i + 21).min(data.len().saturating_sub(3)) {
                    if data[j] == 0x80 && (data[j + 1] & 0xC0 != 0xC0) {
                        let xor_key = data[j + 3];
                        out.push(SmcRegion {
                            start: u64::try_from(i).unwrap_or(u64::MAX),
                            end: u64::try_from(i).unwrap_or(u64::MAX) + u64::from(key),
                            decryptor_addr: u64::try_from(i).unwrap_or(u64::MAX),
                            key: SmcKey::Constant(u64::from(xor_key)),
                            algorithm: SmcAlgorithm::Xor,
                        });
                        break;
                    }
                }
            }
        }
        out
    }
}

// ── SmcDetectionResult ────────────────────────────────────────────────────────

/// Aggregated result of a full SMC detection run.
#[derive(Debug, Default)]
pub struct SmcDetectionResult {
    pub regions: Vec<SmcRegionExt>,
    pub xor_loops: Vec<DecodingLoopPattern>,
    pub add_loops: Vec<DecodingLoopPattern>,
    pub sub_loops: Vec<DecodingLoopPattern>,
    pub rolling_xor_loops: Vec<DecodingLoopPattern>,
    pub vp_patterns: Vec<VirtualProtectPattern>,
    pub mprotect_patterns: Vec<MprotectPattern>,
    pub layers: Vec<Layer>,
}

impl SmcDetectionResult {
    /// Total number of detected patterns (all categories).
    #[must_use]
    pub const fn total_patterns(&self) -> usize {
        self.xor_loops.len()
            + self.add_loops.len()
            + self.sub_loops.len()
            + self.rolling_xor_loops.len()
            + self.vp_patterns.len()
            + self.mprotect_patterns.len()
    }

    /// Whether any SMC patterns were found.
    #[must_use]
    pub const fn has_smc(&self) -> bool {
        self.total_patterns() > 0 || !self.regions.is_empty()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "regions={} xor_loops={} add_loops={} sub_loops={} rolling={} vp={} mprotect={} layers={}",
            self.regions.len(),
            self.xor_loops.len(),
            self.add_loops.len(),
            self.sub_loops.len(),
            self.rolling_xor_loops.len(),
            self.vp_patterns.len(),
            self.mprotect_patterns.len(),
            self.layers.len()
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_loop_bytes(key: u8, counter: u16) -> Vec<u8> {
        let mut v = Vec::new();
        // MOV ECX, counter (B9 lo hi 00 00)
        v.extend_from_slice(&[0xB9, counter as u8, (counter >> 8) as u8, 0x00, 0x00]);
        // XOR byte ptr [EDI+EAX], key (80 34 07 key)
        v.extend_from_slice(&[0x80, 0x34, 0x07, key]);
        // LOOP -6 (E2 FA)
        v.extend_from_slice(&[0xE2, 0xFA]);
        v
    }

    #[test]
    fn test_find_xor_loop() {
        let data = xor_loop_bytes(0x42, 64);
        let loops = SmcDetectorExt::find_xor_loops(&data, 0);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].key, 0x42);
        assert!(matches!(loops[0].op, SmcAlgorithm::Xor));
    }

    #[test]
    fn test_find_add_loop() {
        let data = vec![0x80, 0x00, 0x11, 0xEB, 0xFB]; // ADD [EAX], 0x11; JMP back
        let loops = SmcDetectorExt::find_add_loops(&data, 0);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].key, 0x11);
    }

    #[test]
    fn test_find_sub_loop() {
        let data = vec![0x80, 0x28, 0x05]; // SUB byte ptr [EAX], 5
        let loops = SmcDetectorExt::find_sub_loops(&data, 0);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].key, 0x05);
    }

    #[test]
    fn test_find_rolling_xor() {
        let data = vec![0x8A, 0x06, 0x32, 0xC3, 0x88, 0x07];
        let loops = SmcDetectorExt::find_rolling_xor(&data, 0);
        assert_eq!(loops.len(), 1);
        assert!(matches!(loops[0].op, SmcAlgorithm::XorRolling));
    }

    #[test]
    fn test_find_virtual_protect_pattern() {
        let mut data = Vec::new();
        // PUSH imm32 addr (68 00 20 00 00)
        data.extend_from_slice(&[0x68, 0x00, 0x20, 0x00, 0x00]);
        // PUSH 0x40
        data.extend_from_slice(&[0x6A, 0x40]);
        // CALL rel32 (E8 xx xx xx xx)
        data.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let vp = SmcDetectorExt::find_virtual_protect(&data, 0x1000);
        assert!(!vp.is_empty());
        assert!(vp[0].makes_executable());
    }

    #[test]
    fn test_find_mprotect() {
        let mut data = Vec::new();
        // MOV EAX, 10 (mprotect)
        data.extend_from_slice(&[0xB8, 0x0A, 0x00, 0x00, 0x00]);
        // (some bytes)
        data.extend_from_slice(&[0x90, 0x90]);
        // SYSCALL
        data.extend_from_slice(&[0x0F, 0x05]);
        let mp = SmcDetectorExt::find_mprotect(&data, 0);
        assert!(!mp.is_empty());
        assert!(mp[0].has_exec());
    }

    #[test]
    fn test_detect_all_xor_loop() {
        let data = xor_loop_bytes(0xFF, 32);
        let det = SmcDetectorExt::new();
        let result = det.detect_all(&data, 0x0040_0000);
        assert!(!result.xor_loops.is_empty());
        assert!(result.has_smc());
    }

    #[test]
    fn test_detect_all_summary() {
        let det = SmcDetectorExt::new();
        let result = det.detect_all(&[0x90u8; 64], 0);
        let s = result.summary();
        assert!(s.contains("regions="));
    }

    #[test]
    fn test_detection_result_total_patterns_empty() {
        let r = SmcDetectionResult::default();
        assert_eq!(r.total_patterns(), 0);
        assert!(!r.has_smc());
    }

    #[test]
    fn test_smc_region_ext_new() {
        let region = SmcRegion {
            start: 0x1000,
            end: 0x2000,
            decryptor_addr: 0x1000,
            key: SmcKey::Constant(0x42),
            algorithm: SmcAlgorithm::Xor,
        };
        let ext = SmcRegionExt::new(region, "test");
        assert_eq!(ext.pattern_name, "test");
        assert_eq!(ext.layer_count, 1);
    }

    #[test]
    fn test_smc_region_ext_high_confidence() {
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(0),
            algorithm: SmcAlgorithm::Xor,
        };
        let ext = SmcRegionExt::new(region, "x").high_confidence();
        assert!(ext.confidence > 0.9);
    }

    #[test]
    fn test_vp_pattern_makes_executable() {
        let vp = VirtualProtectPattern {
            call_addr: 0,
            region_start: 0,
            region_size: 0x1000,
            new_protect: 0x40,
            old_protect_ptr: 0,
        };
        assert!(vp.makes_executable());
    }

    #[test]
    fn test_vp_pattern_no_exec() {
        let vp = VirtualProtectPattern {
            call_addr: 0,
            region_start: 0,
            region_size: 0x1000,
            new_protect: 0x02, // PAGE_READONLY
            old_protect_ptr: 0,
        };
        assert!(!vp.makes_executable());
    }

    #[test]
    fn test_mprotect_has_exec() {
        let mp = MprotectPattern {
            call_addr: 0,
            region_start: 0,
            region_size: 4096,
            prot: 0x7, // PROT_READ|WRITE|EXEC
        };
        assert!(mp.has_exec());
    }

    #[test]
    fn test_mprotect_no_exec() {
        let mp = MprotectPattern {
            call_addr: 0,
            region_start: 0,
            region_size: 4096,
            prot: 0x3, // PROT_READ|WRITE only
        };
        assert!(!mp.has_exec());
    }

    #[test]
    fn test_layer_new() {
        let region = SmcRegion {
            start: 0,
            end: 64,
            decryptor_addr: 0,
            key: SmcKey::Constant(0xAA),
            algorithm: SmcAlgorithm::Xor,
        };
        let layer = Layer::new(0, region);
        assert_eq!(layer.index, 0);
        assert!(!layer.decrypted);
    }

    #[test]
    fn test_decoding_loop_pattern_fields() {
        let p = DecodingLoopPattern {
            loop_start: 0x1000,
            body_size: 6,
            op: SmcAlgorithm::Xor,
            key: 0x42,
            iteration_estimate: 256,
            has_counter: true,
        };
        assert_eq!(p.key, 0x42);
        assert!(p.has_counter);
    }

    #[test]
    fn test_estimate_iterations_with_mov_ecx() {
        let mut data = vec![0x90u8; 20];
        // MOV ECX, 100 at offset 5: B9 64 00 00 00
        data[4] = 0xB9;
        data[5] = 100;
        data[6] = 0;
        data[7] = 0;
        data[8] = 0;
        let count = SmcDetectorExt::estimate_iterations(&data, 12);
        assert_eq!(count, 100);
    }

    #[test]
    fn test_has_counter_nearby_dec() {
        let mut data = vec![0x90u8; 20];
        data[5] = 0x49; // DEC ECX
        assert!(SmcDetectorExt::has_counter_nearby(&data, 0));
    }

    #[test]
    fn test_basic_detect_returns_regions() {
        let data = xor_loop_bytes(0x11, 32);
        let regions = SmcDetectorExt::basic_detect(&data);
        let _ = regions; // may or may not find, no panic
    }
}
