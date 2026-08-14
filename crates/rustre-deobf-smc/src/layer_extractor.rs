//! `layer_extractor` — SMC layer extraction using Unicorn-style emulation stubs.

use crate::{SmcAlgorithm, SmcDecryptor, SmcKey, SmcRegion, shannon_entropy};
use serde::{Deserialize, Serialize};
/// Re-export of [`std::collections::HashMap`] for callers building
/// per-layer metadata tables alongside this module.
pub use std::collections::HashMap;

// ── EmulationConfig ───────────────────────────────────────────────────────────

/// Configuration for decryption-stub emulation.
#[derive(Debug, Clone)]
pub struct EmulationConfig {
    /// Maximum number of instructions to execute.
    pub max_insns: u64,
    /// Timeout in simulated nanoseconds.
    pub timeout_ns: u64,
    /// Memory size for the emulated process (bytes).
    pub memory_size: usize,
    /// Whether to follow calls into sub-functions.
    pub follow_calls: bool,
    /// Stack size in bytes.
    pub stack_size: usize,
    /// Base address for code placement.
    pub code_base: u64,
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            max_insns: 100_000,
            timeout_ns: 5_000_000_000,
            memory_size: 4 * 1024 * 1024, // 4 MB
            follow_calls: false,
            stack_size: 65_536,
            code_base: 0x0040_0000,
        }
    }
}

impl EmulationConfig {
    /// Create a fast configuration (fewer instructions, smaller memory).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            max_insns: 10_000,
            memory_size: 1024 * 1024,
            ..Default::default()
        }
    }
}

// ── ExtractedLayer ────────────────────────────────────────────────────────────

/// A single decryption layer extracted from an SMC binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedLayer {
    /// Layer index (0 = outer-most / first to run).
    pub index: u32,
    /// The decrypted bytes.
    pub bytes: Vec<u8>,
    /// Base virtual address these bytes map to.
    pub base_addr: u64,
    /// Key used to decrypt this layer.
    pub key_used: SmcKey,
    /// Algorithm used.
    pub algorithm: SmcAlgorithm,
    /// Entropy of the input (encrypted) data.
    pub entropy_before: f64,
    /// Entropy of the output (decrypted) data.
    pub entropy_after: f64,
}

impl ExtractedLayer {
    /// Create a new extracted layer.
    #[must_use]
    pub fn new(
        index: u32,
        bytes: Vec<u8>,
        base_addr: u64,
        key_used: SmcKey,
        algorithm: SmcAlgorithm,
        input_bytes: &[u8],
    ) -> Self {
        let entropy_before = shannon_entropy(input_bytes);
        let entropy_after = shannon_entropy(&bytes);
        Self {
            index,
            bytes,
            base_addr,
            key_used,
            algorithm,
            entropy_before,
            entropy_after,
        }
    }

    /// Whether the entropy dropped significantly (suggests successful decryption).
    #[must_use]
    pub fn entropy_dropped(&self) -> bool {
        self.entropy_after < self.entropy_before - 0.5
    }

    /// Length of the decrypted region.
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

// ── LayerAnalysis ─────────────────────────────────────────────────────────────

/// Serde helper for `[u32; 256]` fields.
pub mod serde_u32_256 {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeTuple};

    /// # Errors
    /// Returns a serialization error if the tuple encoding fails.
    pub fn serialize<S: Serializer>(arr: &[u32; 256], ser: S) -> Result<S::Ok, S::Error> {
        let mut tup = ser.serialize_tuple(256)?;
        for v in arr {
            tup.serialize_element(v)?;
        }
        tup.end()
    }

    /// # Errors
    /// Returns a deserialization error if the element count is not 256.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u32; 256], D::Error> {
        let v: Vec<u32> = Vec::deserialize(de)?;
        if v.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 u32 elements, got {}",
                v.len()
            )));
        }
        let mut out = [0u32; 256];
        for (i, x) in v.into_iter().enumerate() {
            out[i] = x;
        }
        Ok(out)
    }
}

/// Entropy and statistical analysis for a single layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerAnalysis {
    /// Layer index.
    pub index: u32,
    /// Entropy before decryption.
    pub entropy_before: f64,
    /// Entropy after decryption.
    pub entropy_after: f64,
    /// Byte frequency histogram of the decrypted output.
    #[serde(with = "serde_u32_256")]
    pub byte_freq: [u32; 256],
    /// Most common byte in the output.
    pub most_common_byte: u8,
    /// Whether the output looks like x86 code.
    pub looks_like_code: bool,
}

impl LayerAnalysis {
    /// Compute analysis from raw data.
    #[must_use]
    pub fn compute(index: u32, before: &[u8], after: &[u8]) -> Self {
        let entropy_before = shannon_entropy(before);
        let entropy_after = shannon_entropy(after);
        let mut freq = [0u32; 256];
        for &b in after {
            freq[usize::from(b)] += 1;
        }
        let most_common_byte = freq
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(i, _)| u8::try_from(i).unwrap_or(u8::MAX));
        let looks_like_code = crate::looks_like_code(after);
        Self {
            index,
            entropy_before,
            entropy_after,
            byte_freq: freq,
            most_common_byte,
            looks_like_code,
        }
    }

    /// Entropy delta (before - after). Positive means decryption reduced entropy.
    #[must_use]
    pub fn entropy_delta(&self) -> f64 {
        self.entropy_before - self.entropy_after
    }
}

// ── LayerExtractor ────────────────────────────────────────────────────────────

/// Extracts SMC layers using a lightweight in-process emulation of the
/// decryption stub (does NOT require an external Unicorn library).
pub struct LayerExtractor {
    pub config: EmulationConfig,
    /// Maximum number of recursive layers to extract.
    pub max_layers: u32,
}

impl Default for LayerExtractor {
    fn default() -> Self {
        Self {
            config: EmulationConfig::default(),
            max_layers: 8,
        }
    }
}

impl LayerExtractor {
    /// Create a new extractor with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom config.
    #[must_use]
    pub const fn with_config(config: EmulationConfig, max_layers: u32) -> Self {
        Self { config, max_layers }
    }

    /// Maximum number of bytes that may be extracted from a single SMC region.
    ///
    /// A region whose length exceeds this is skipped to prevent a denial-of-service
    /// where an attacker-controlled region descriptor causes a multi-GiB allocation.
    pub const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

    /// Extract all layers from `data`, starting with the outermost.
    ///
    /// Each call to the inner emulation attempts to decrypt one layer and
    /// recurses until no more SMC regions are found or `max_layers` is reached.
    #[must_use]
    pub fn extract(&self, data: &[u8], regions: &[SmcRegion]) -> Vec<ExtractedLayer> {
        let mut layers = Vec::new();
        let mut current = data.to_vec();

        for (layer_idx, region) in regions.iter().enumerate().take(self.max_layers as usize) {
            // Guard: region.len() is u64; converting to usize can overflow on
            // 32-bit targets, and even on 64-bit an attacker-supplied region
            // descriptor could request a multi-GiB allocation.
            let size = match usize::try_from(region.len()) {
                Ok(s) if s <= Self::MAX_REGION_BYTES => s,
                _ => continue,
            };
            let Ok(start) = usize::try_from(region.start) else { continue };
            if start + size > current.len() {
                continue;
            }

            let input_bytes = current[start..start + size].to_vec();
            let decrypted = self.emulate_decrypt(&input_bytes, region);

            let layer = ExtractedLayer::new(
                u32::try_from(layer_idx).unwrap_or(u32::MAX),
                decrypted.clone(),
                region.start,
                region.key.clone(),
                region.algorithm.clone(),
                &input_bytes,
            );
            layers.push(layer);

            // Apply decryption for the next layer.
            current[start..start + size].copy_from_slice(&decrypted);
        }

        layers
    }

    /// Emulate decryption of `data` according to `region`.
    ///
    /// Internally this calls [`SmcDecryptor`] (which represents the decoded
    /// key+algorithm from the stub analysis). A real Unicorn integration
    /// would call `uc_emu_start` here.
    #[must_use]
    pub fn emulate_decrypt(&self, data: &[u8], region: &SmcRegion) -> Vec<u8> {
        let dec = SmcDecryptor::new();
        dec.decrypt(data, region)
    }

    /// Extract a single layer and return it with analysis.
    #[must_use]
    pub fn extract_with_analysis(
        &self,
        data: &[u8],
        region: &SmcRegion,
        layer_idx: u32,
    ) -> (ExtractedLayer, LayerAnalysis) {
        let size = usize::try_from(region.len()).unwrap_or(usize::MAX);
        let start = usize::try_from(region.start).unwrap_or(usize::MAX);
        let input_bytes = if start.saturating_add(size) <= data.len() {
            data[start..start + size].to_vec()
        } else {
            data.to_vec()
        };

        let decrypted = self.emulate_decrypt(&input_bytes, region);
        let analysis = LayerAnalysis::compute(layer_idx, &input_bytes, &decrypted);
        let layer = ExtractedLayer::new(
            layer_idx,
            decrypted,
            region.start,
            region.key.clone(),
            region.algorithm.clone(),
            &input_bytes,
        );
        (layer, analysis)
    }

    /// Multi-layer recursive extraction.
    ///
    /// After extracting a layer, re-scans for new SMC regions in the result
    /// and recurses up to `max_layers` times.
    #[must_use]
    pub fn extract_recursive(
        &self,
        data: &[u8],
        regions: &[SmcRegion],
    ) -> Vec<(ExtractedLayer, LayerAnalysis)> {
        const MAX_REGIONS_PER_LAYER: usize = 1024;
        let mut results = Vec::new();
        let mut current = data.to_vec();
        let mut current_regions = regions.to_vec();

        for layer_idx in 0..self.max_layers {
            if current_regions.is_empty() {
                break;
            }

            for region in &current_regions {
                let size = match usize::try_from(region.len()) {
                    Ok(s) if s <= Self::MAX_REGION_BYTES => s,
                    _ => continue,
                };
                let Ok(start) = usize::try_from(region.start) else { continue };
                if start + size > current.len() {
                    continue;
                }

                let input_bytes = current[start..start + size].to_vec();
                let decrypted = self.emulate_decrypt(&input_bytes, region);
                let analysis = LayerAnalysis::compute(layer_idx, &input_bytes, &decrypted);
                let layer = ExtractedLayer::new(
                    layer_idx,
                    decrypted.clone(),
                    region.start,
                    region.key.clone(),
                    region.algorithm.clone(),
                    &input_bytes,
                );
                results.push((layer, analysis));
                current[start..start + size].copy_from_slice(&decrypted);
            }

            // Re-detect SMC regions in updated data.
            // Cap the returned list: an unbounded region list could cause the
            // inner loop to allocate O(regions * region_size) bytes per layer,
            // turning into a denial-of-service when processing adversarial input.
            let new_regions = crate::SmcDetector::new().detect(&current);
            if new_regions.is_empty() {
                break;
            }
            current_regions = new_regions;
            if current_regions.len() > MAX_REGIONS_PER_LAYER {
                current_regions.truncate(MAX_REGIONS_PER_LAYER);
            }
        }

        results
    }

    /// Return total bytes across all extracted layers.
    #[must_use]
    pub fn total_bytes(layers: &[ExtractedLayer]) -> usize {
        layers.iter().map(ExtractedLayer::len).sum()
    }

    /// Return the layer with the lowest output entropy (most likely plaincode).
    #[must_use]
    pub fn best_layer(layers: &[ExtractedLayer]) -> Option<&ExtractedLayer> {
        layers.iter().min_by(|a, b| {
            a.entropy_after
                .partial_cmp(&b.entropy_after)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
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

    fn make_encrypted(plain: &[u8], key: u8) -> Vec<u8> {
        plain.iter().map(|&b| b ^ key).collect()
    }

    #[test]
    fn test_emulation_config_defaults() {
        let cfg = EmulationConfig::default();
        assert!(cfg.max_insns > 0);
        assert!(cfg.memory_size > 0);
    }

    #[test]
    fn test_emulation_config_fast() {
        let cfg = EmulationConfig::fast();
        assert!(cfg.max_insns < 50_000);
    }

    #[test]
    fn test_extracted_layer_new() {
        let plain = b"hello world".to_vec();
        let cipher = make_encrypted(&plain, 0x42);
        let layer = ExtractedLayer::new(
            0,
            plain.clone(),
            0x1000,
            SmcKey::Constant(0x42),
            SmcAlgorithm::Xor,
            &cipher,
        );
        assert_eq!(layer.index, 0);
        assert_eq!(layer.base_addr, 0x1000);
        assert_eq!(layer.len(), plain.len());
    }

    #[test]
    fn test_extracted_layer_entropy_dropped() {
        // High-entropy random data → XOR → lower entropy plaintext
        let plain = vec![0x90u8; 64]; // all NOPs → very low entropy
        let cipher: Vec<u8> = (0u8..64).map(|i| i.wrapping_mul(37).wrapping_add(13)).collect();
        let layer = ExtractedLayer::new(
            0,
            plain,
            0,
            SmcKey::Constant(0),
            SmcAlgorithm::Xor,
            &cipher,
        );
        // entropy_after for all-same-byte is 0; entropy_before for random should be higher
        assert!(layer.entropy_after <= layer.entropy_before + 0.01);
    }

    #[test]
    fn test_extracted_layer_is_empty() {
        let layer = ExtractedLayer::new(0, vec![], 0, SmcKey::Derived, SmcAlgorithm::Xor, &[]);
        assert!(layer.is_empty());
    }

    #[test]
    fn test_layer_analysis_compute() {
        let before = (0u8..255u8).collect::<Vec<_>>();
        let after = vec![0x90u8; 64];
        let a = LayerAnalysis::compute(0, &before, &after);
        assert_eq!(a.most_common_byte, 0x90);
        assert!(a.entropy_delta() >= 0.0);
    }

    #[test]
    fn test_layer_analysis_looks_like_code() {
        // All NOPs look like code.
        let before = vec![0xCC; 64];
        let after = vec![0x90u8; 64];
        let a = LayerAnalysis::compute(0, &before, &after);
        assert!(a.looks_like_code);
    }

    #[test]
    fn test_layer_extractor_default() {
        let ext = LayerExtractor::new();
        assert_eq!(ext.max_layers, 8);
    }

    #[test]
    fn test_layer_extractor_with_config() {
        let cfg = EmulationConfig::fast();
        let ext = LayerExtractor::with_config(cfg, 4);
        assert_eq!(ext.max_layers, 4);
    }

    #[test]
    fn test_emulate_decrypt_xor() {
        let plain = b"RUSTCODE".to_vec();
        let key = 0x5Au8;
        let cipher = make_encrypted(&plain, key);
        let region = xor_region(0, u64::try_from(cipher.len()).unwrap_or(u64::MAX), key);
        let ext = LayerExtractor::new();
        let decrypted = ext.emulate_decrypt(&cipher, &region);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_extract_single_layer() {
        let plain = b"PLAINTEXT_CODE_GOES_HERE".to_vec();
        let key = 0x77u8;
        let cipher = make_encrypted(&plain, key);
        let mut data = vec![0u8; 128];
        data[..cipher.len()].copy_from_slice(&cipher);
        let region = xor_region(0, u64::try_from(plain.len()).unwrap_or(u64::MAX), key);
        let ext = LayerExtractor::new();
        let layers = ext.extract(&data, &[region]);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].bytes, plain);
    }

    #[test]
    fn test_extract_returns_layer_metadata() {
        let data = make_encrypted(b"hello", 0x42);
        let region = xor_region(0, 5, 0x42);
        let ext = LayerExtractor::new();
        let layers = ext.extract(&data, &[region]);
        assert_eq!(layers[0].index, 0);
        assert_eq!(layers[0].base_addr, 0);
    }

    #[test]
    fn test_extract_with_analysis() {
        let plain = b"NOP slide".to_vec();
        let cipher = make_encrypted(&plain, 0x33);
        let region = xor_region(0, u64::try_from(plain.len()).unwrap_or(u64::MAX), 0x33);
        let ext = LayerExtractor::new();
        let (layer, analysis) = ext.extract_with_analysis(&cipher, &region, 0);
        assert_eq!(layer.bytes, plain);
        assert_eq!(analysis.index, 0);
    }

    #[test]
    fn test_total_bytes() {
        let l1 = ExtractedLayer::new(0, vec![0; 10], 0, SmcKey::Derived, SmcAlgorithm::Xor, &[]);
        let l2 = ExtractedLayer::new(1, vec![0; 20], 0, SmcKey::Derived, SmcAlgorithm::Xor, &[]);
        assert_eq!(LayerExtractor::total_bytes(&[l1, l2]), 30);
    }

    #[test]
    fn test_best_layer_lowest_entropy() {
        let high = ExtractedLayer::new(
            0,
            (0u8..255u8).cycle().take(256).collect(),
            0,
            SmcKey::Derived,
            SmcAlgorithm::Xor,
            &[],
        );
        let low = ExtractedLayer::new(
            1,
            vec![0x90; 64],
            0,
            SmcKey::Derived,
            SmcAlgorithm::Xor,
            &[],
        );
        let layers = [high, low];
        let best = LayerExtractor::best_layer(&layers).unwrap();
        assert_eq!(best.index, 1);
    }

    #[test]
    fn test_extract_out_of_range_region_skipped() {
        let data = vec![0u8; 16];
        let region = xor_region(100, 64, 0x42); // way beyond data
        let ext = LayerExtractor::new();
        let layers = ext.extract(&data, &[region]);
        assert!(layers.is_empty());
    }

    #[test]
    fn test_extract_recursive_no_regions() {
        let data = vec![0x90u8; 64];
        let ext = LayerExtractor::new();
        let results = ext.extract_recursive(&data, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_layer_analysis_byte_freq_sum() {
        let before = vec![0u8; 16];
        let after = vec![0xAAu8; 16];
        let a = LayerAnalysis::compute(0, &before, &after);
        let total: u32 = a.byte_freq.iter().sum();
        assert_eq!(usize::try_from(total).unwrap_or(usize::MAX), after.len());
    }

    #[test]
    fn test_emulation_config_code_base() {
        let cfg = EmulationConfig::default();
        assert_eq!(cfg.code_base, 0x0040_0000);
    }

    #[test]
    fn test_extracted_layer_entropy_values() {
        let all_zeros = vec![0u8; 64];
        let layer = ExtractedLayer::new(
            0,
            all_zeros.clone(),
            0,
            SmcKey::Derived,
            SmcAlgorithm::Xor,
            &all_zeros,
        );
        assert_eq!(layer.entropy_after, 0.0);
    }
}
