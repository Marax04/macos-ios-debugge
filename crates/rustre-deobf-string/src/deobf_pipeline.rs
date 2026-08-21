//! Full deobfuscation pipeline: chainable stages with auto-detection.
//!
//! Provides a fluent `PipelineBuilder`, per-stage trace, built-in stages for
//! Base64, Hex, ROT-13, XOR (constant and cyclic), RC4, `ChaCha20`, and an
//! `EncodingDetector`-driven auto-ordering pass.

pub use crate::chacha20::ChaCha20Detector;
use crate::chacha20::chacha20_decrypt;
use crate::{
    Base64Decoder, EncodingDetector, HexDecoder, Rc4, RotN, StringAlgorithm, StringDeobfError,
    XorDecryptor,
};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ── StringDeobfStage trait ────────────────────────────────────────────────────

/// A single deobfuscation stage in the pipeline.
pub trait StringDeobfStage: Send + Sync {
    /// Human-readable stage name.
    fn name(&self) -> &str;

    /// Return true if this stage looks applicable to the current data.
    fn can_apply(&self, data: &[u8]) -> bool;

    /// Apply this stage and return the transformed data.
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError>;

    /// Algorithm identifier.
    fn algorithm(&self) -> StringAlgorithm;
}

// ── StageResult ───────────────────────────────────────────────────────────────

/// The result of applying a single pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    /// Stage name.
    pub stage_name: String,
    /// Algorithm.
    pub algorithm: StringAlgorithm,
    /// Input data passed to this stage.
    pub input: Vec<u8>,
    /// Output data produced.
    pub output: Vec<u8>,
    /// Whether the stage was applied or skipped.
    pub applied: bool,
    /// Error if the stage failed.
    pub error: Option<String>,
}

impl StageResult {
    /// Construct a successful stage result.
    #[must_use]
    pub fn success(name: &str, algo: StringAlgorithm, input: Vec<u8>, output: Vec<u8>) -> Self {
        Self {
            stage_name: name.to_string(),
            algorithm: algo,
            input,
            output,
            applied: true,
            error: None,
        }
    }

    /// Construct a skipped stage result.
    #[must_use]
    pub fn skipped(name: &str, algo: StringAlgorithm, data: Vec<u8>) -> Self {
        Self {
            stage_name: name.to_string(),
            algorithm: algo,
            input: data.clone(),
            output: data,
            applied: false,
            error: None,
        }
    }

    /// Construct an error stage result.
    #[must_use]
    pub fn failed(name: &str, algo: StringAlgorithm, input: Vec<u8>, err: String) -> Self {
        Self {
            stage_name: name.to_string(),
            algorithm: algo,
            input: input.clone(),
            output: input,
            applied: false,
            error: Some(err),
        }
    }

    /// Printable ratio of the output (for quality assessment).
    #[must_use]
    pub fn output_printability(&self) -> f64 {
        if self.output.is_empty() {
            return 0.0;
        }
        self.output
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count() as f64
            / self.output.len() as f64
    }
}

// ── PipelineResult ────────────────────────────────────────────────────────────

/// The full result of running a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Per-stage trace.
    pub trace: Vec<StageResult>,
    /// Final output after all stages.
    pub final_output: Vec<u8>,
    /// UTF-8 string, if the final output is valid UTF-8.
    pub plaintext: Option<String>,
}

impl PipelineResult {
    /// Whether the pipeline produced valid UTF-8.
    #[must_use]
    pub const fn is_utf8(&self) -> bool {
        self.plaintext.is_some()
    }

    /// Number of stages that were actually applied.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.trace.iter().filter(|r| r.applied).count()
    }

    /// Stage that improved printability the most.
    #[must_use]
    pub fn best_stage(&self) -> Option<&StageResult> {
        self.trace.iter().filter(|r| r.applied).max_by(|a, b| {
            a.output_printability()
                .partial_cmp(&b.output_printability())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Serialize the full pipeline result to a JSON string for MCP tool consumption.
    ///
    /// # Errors
    /// Returns an error if serialization fails (should not happen for well-formed data).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the full pipeline result to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ── DeobfPipeline ─────────────────────────────────────────────────────────────

/// Chainable deobfuscation pipeline.
pub struct DeobfPipeline {
    stages: Vec<Box<dyn StringDeobfStage>>,
    /// If true, skip stages where `can_apply` returns false.
    pub skip_inapplicable: bool,
    /// If true, stop after the first successful stage.
    pub stop_on_success: bool,
    /// Minimum printability to consider a stage "successful".
    pub success_threshold: f64,
}

impl DeobfPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            skip_inapplicable: true,
            stop_on_success: false,
            success_threshold: 0.75,
        }
    }

    /// Add a stage.
    pub fn push(&mut self, stage: Box<dyn StringDeobfStage>) {
        self.stages.push(stage);
    }

    /// Number of stages.
    #[must_use]
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Run the pipeline and return a full result with per-stage trace.
    #[must_use]
    pub fn run(&self, input: &[u8]) -> PipelineResult {
        let mut current = input.to_vec();
        let mut trace = Vec::new();

        for stage in &self.stages {
            if self.skip_inapplicable && !stage.can_apply(&current) {
                debug!(stage = stage.name(), "skipping inapplicable stage");
                trace.push(StageResult::skipped(
                    stage.name(),
                    stage.algorithm(),
                    current.clone(),
                ));
                continue;
            }
            debug!(stage = stage.name(), algo = ?stage.algorithm(), "applying pipeline stage");
            match stage.apply(&current) {
                Ok(output) => {
                    let result = StageResult::success(
                        stage.name(),
                        stage.algorithm(),
                        current.clone(),
                        output.clone(),
                    );
                    let printability = result.output_printability();
                    debug!(stage = stage.name(), printability, "stage succeeded");
                    let improved = printability > 0.0;
                    current = output;
                    trace.push(result);
                    if self.stop_on_success
                        && improved
                        && !current.is_empty()
                        && current
                            .iter()
                            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                            .count() as f64
                            / current.len() as f64
                            >= self.success_threshold
                    {
                        break;
                    }
                }
                Err(e) => {
                    warn!(stage = stage.name(), error = %e, "pipeline stage failed");
                    trace.push(StageResult::failed(
                        stage.name(),
                        stage.algorithm(),
                        current.clone(),
                        e.to_string(),
                    ));
                }
            }
        }

        let plaintext = std::str::from_utf8(&current).ok().map(std::borrow::ToOwned::to_owned);
        PipelineResult {
            trace,
            final_output: current,
            plaintext,
        }
    }
}

impl Default for DeobfPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a pipeline and return an `anyhow::Result` for ergonomic propagation of
/// heterogeneous errors from multiple sub-passes.
///
/// Fails if any stage returned an error *and* no stage produced a printable
/// result above the pipeline's `success_threshold`.
pub fn run_pipeline_anyhow(
    pipeline: &DeobfPipeline,
    input: &[u8],
) -> anyhow::Result<PipelineResult> {
    let result = pipeline.run(input);
    // If the pipeline produced no useful output and at least one stage failed,
    // surface the first stage error via anyhow for ergonomic propagation.
    if result.plaintext.is_none()
        && let Some(failed) = result.trace.iter().find(|r| r.error.is_some()) {
            let msg = failed.error.as_deref().unwrap_or("unknown stage error");
            return Err(anyhow::anyhow!("{msg}"))
                .with_context(|| format!("pipeline stage '{}' failed", failed.stage_name));
        }
    Ok(result)
}

// ── PipelineBuilder ───────────────────────────────────────────────────────────

/// Fluent builder for `DeobfPipeline`.
pub struct PipelineBuilder {
    pipeline: DeobfPipeline,
}

impl PipelineBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pipeline: DeobfPipeline::new(),
        }
    }

    /// Add a Base64 decode stage.
    #[must_use]
    pub fn base64(mut self) -> Self {
        self.pipeline.push(Box::new(Base64Stage::new()));
        self
    }

    /// Add a hex decode stage.
    #[must_use]
    pub fn hex(mut self) -> Self {
        self.pipeline.push(Box::new(HexStage::new()));
        self
    }

    /// Add a ROT-13 stage.
    #[must_use]
    pub fn rot13(mut self) -> Self {
        self.pipeline.push(Box::new(Rot13Stage::new()));
        self
    }

    /// Add an XOR constant stage with a specific key.
    #[must_use]
    pub fn xor_constant(mut self, key: u8) -> Self {
        self.pipeline.push(Box::new(XorConstantStage::new(key)));
        self
    }

    /// Add an XOR cyclic stage.
    #[must_use]
    pub fn xor_cyclic(mut self, key: Vec<u8>) -> Self {
        self.pipeline.push(Box::new(XorCyclicStage::new(key)));
        self
    }

    /// Add an RC4 stage.
    #[must_use]
    pub fn rc4(mut self, key: Vec<u8>) -> Self {
        self.pipeline.push(Box::new(Rc4Stage::new(key)));
        self
    }

    /// Add a `ChaCha20` stage.
    #[must_use]
    pub fn chacha20(mut self, key: [u8; 32], nonce: [u8; 12], counter: u32) -> Self {
        self.pipeline
            .push(Box::new(ChaCha20Stage::new(key, nonce, counter)));
        self
    }

    /// Add any custom stage.
    #[must_use]
    pub fn stage(mut self, stage: Box<dyn StringDeobfStage>) -> Self {
        self.pipeline.push(stage);
        self
    }

    /// Stop after the first stage that reaches the printability threshold.
    #[must_use]
    pub const fn stop_on_success(mut self) -> Self {
        self.pipeline.stop_on_success = true;
        self
    }

    /// Set the printability success threshold.
    #[must_use]
    pub const fn success_threshold(mut self, threshold: f64) -> Self {
        self.pipeline.success_threshold = threshold;
        self
    }

    /// Disable skipping inapplicable stages.
    #[must_use]
    pub const fn always_apply(mut self) -> Self {
        self.pipeline.skip_inapplicable = false;
        self
    }

    /// Build the pipeline.
    #[must_use]
    pub fn build(self) -> DeobfPipeline {
        self.pipeline
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Built-in stages ───────────────────────────────────────────────────────────

/// Base64 decode stage.
pub struct Base64Stage;
impl Base64Stage {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
impl Default for Base64Stage {
    fn default() -> Self {
        Self
    }
}
impl StringDeobfStage for Base64Stage {
    fn name(&self) -> &'static str {
        "Base64Decode"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::Base64
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        if let Ok(s) = std::str::from_utf8(data) {
            let clean = s.trim_end_matches('=');
            let b64_chars: usize = clean
                .chars()
                .filter(|c| {
                    c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '-' || *c == '_'
                })
                .count();
            b64_chars * 10 >= clean.len() * 9 // ≥ 90% b64 chars
        } else {
            false
        }
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
        Base64Decoder::decode(s)
    }
}

/// Hex decode stage.
pub struct HexStage;
impl HexStage {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
impl Default for HexStage {
    fn default() -> Self {
        Self
    }
}
impl StringDeobfStage for HexStage {
    fn name(&self) -> &'static str {
        "HexDecode"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::HexEncoded
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(data) {
            let clean = s.trim_start_matches("0x").trim_start_matches("0X");
            clean.len() >= 4 && clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            false
        }
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
        HexDecoder::decode(s)
    }
}

/// ROT-13 stage.
pub struct Rot13Stage;
impl Rot13Stage {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
impl Default for Rot13Stage {
    fn default() -> Self {
        Self
    }
}
impl StringDeobfStage for Rot13Stage {
    fn name(&self) -> &'static str {
        "ROT13"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::RotN
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        data.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
        Ok(RotN::rot13(s).into_bytes())
    }
}

/// XOR with a constant key byte.
pub struct XorConstantStage {
    pub key: u8,
}
impl XorConstantStage {
    #[must_use]
    pub const fn new(key: u8) -> Self {
        Self { key }
    }
}
impl StringDeobfStage for XorConstantStage {
    fn name(&self) -> &'static str {
        "XOR-Constant"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::XorConstant
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let dec: Vec<u8> = data.iter().map(|&b| b ^ self.key).collect();
        dec.iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count() as f64
            / dec.len() as f64
            > 0.5
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        Ok(XorDecryptor::decrypt_constant(data, self.key))
    }
}

/// XOR with a cyclic multi-byte key.
pub struct XorCyclicStage {
    pub key: Vec<u8>,
}
impl XorCyclicStage {
    #[must_use]
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}
impl StringDeobfStage for XorCyclicStage {
    fn name(&self) -> &'static str {
        "XOR-Cyclic"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::XorCyclic
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        !data.is_empty() && !self.key.is_empty()
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        if self.key.is_empty() {
            return Err(StringDeobfError::EmptyKey);
        }
        XorDecryptor::decrypt_cyclic(data, &self.key)
    }
}

/// RC4 stream cipher stage.
pub struct Rc4Stage {
    pub key: Vec<u8>,
}
impl Rc4Stage {
    #[must_use]
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}
impl StringDeobfStage for Rc4Stage {
    fn name(&self) -> &'static str {
        "RC4"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::Rc4
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        !data.is_empty() && !self.key.is_empty()
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        if self.key.is_empty() {
            return Err(StringDeobfError::EmptyKey);
        }
        Ok(Rc4::decrypt(data, &self.key))
    }
}

/// `ChaCha20` stream cipher stage.
pub struct ChaCha20Stage {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub counter: u32,
}
impl ChaCha20Stage {
    #[must_use]
    pub const fn new(key: [u8; 32], nonce: [u8; 12], counter: u32) -> Self {
        Self {
            key,
            nonce,
            counter,
        }
    }
}
impl StringDeobfStage for ChaCha20Stage {
    fn name(&self) -> &'static str {
        "ChaCha20"
    }
    fn algorithm(&self) -> StringAlgorithm {
        StringAlgorithm::ChaCha20
    }
    fn can_apply(&self, data: &[u8]) -> bool {
        !data.is_empty()
    }
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        Ok(chacha20_decrypt(&self.key, &self.nonce, self.counter, data))
    }
}

// ── Auto-detect stage ordering ────────────────────────────────────────────────

/// Detect the most likely encoding sequence and construct a pipeline.
///
/// Uses `EncodingDetector` to probe the first layer; then recursively
/// checks the decoded output for additional layers.
#[must_use]
/// Did decoding actually get us closer to plaintext?
///
/// The auto-builder has a depth limit but no notion of having *arrived*, so it
/// kept peeling layers off an answer it had already reached. Plaintext is
/// frequently valid input for another decoder: hex-decoding `"48656c6c6f"`
/// yields `"Hello"`, which is itself well-formed Base64, and decoding it again
/// gives the three bytes `[29, 233, 101]`. Nothing errors — each step is
/// individually legal — so only comparing text quality across the step can tell
/// a real layer from one decode too many.
fn decoding_improved(before: &[u8], after: &[u8]) -> bool {
    if after.is_empty() {
        return false;
    }
    crate::xor_string_decoder::score_plaintext(after)
        > crate::xor_string_decoder::score_plaintext(before)
}

#[must_use]
pub fn auto_build_pipeline(data: &[u8], max_depth: usize) -> DeobfPipeline {
    let mut builder = PipelineBuilder::new();
    let mut current = data.to_vec();
    for _ in 0..max_depth {
        let algo = EncodingDetector::detect(&current);
        match algo {
            StringAlgorithm::Base64 => {
                let Ok(s) = std::str::from_utf8(&current) else { break };
                let Ok(dec) = Base64Decoder::decode(s) else { break };
                if !decoding_improved(&current, &dec) {
                    break;
                }
                builder = builder.base64();
                current = dec;
                continue;
            }
            StringAlgorithm::HexEncoded => {
                let Ok(s) = std::str::from_utf8(&current) else { break };
                let Ok(dec) = HexDecoder::decode(s) else { break };
                if !decoding_improved(&current, &dec) {
                    break;
                }
                builder = builder.hex();
                current = dec;
                continue;
            }
            StringAlgorithm::RotN => {
                builder = builder.rot13();
                if let Ok(s) = std::str::from_utf8(&current) {
                    current = RotN::rot13(s).into_bytes();
                    continue;
                }
                break;
            }
            StringAlgorithm::XorConstant => {
                let (key, dec) = XorDecryptor::recover_key(&current);
                builder = builder.xor_constant(key);
                current = dec;
                continue;
            }
            _ => break,
        }
    }
    builder.build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Base64Stage ───────────────────────────────────────────────────────────

    #[test]
    fn test_base64_stage_can_apply_yes() {
        let s = Base64Decoder::encode(b"Hello World");
        let stage = Base64Stage::new();
        assert!(stage.can_apply(s.as_bytes()));
    }

    #[test]
    fn test_base64_stage_can_apply_no() {
        let stage = Base64Stage::new();
        assert!(!stage.can_apply(b"\x00\xFF\xFE\xFD\x00\xFF\xFE\xFD"));
    }

    #[test]
    fn test_base64_stage_apply() {
        let stage = Base64Stage::new();
        let enc = Base64Decoder::encode(b"Hello");
        let dec = stage.apply(enc.as_bytes()).unwrap();
        assert_eq!(dec, b"Hello");
    }

    #[test]
    fn test_base64_stage_algorithm() {
        assert_eq!(Base64Stage::new().algorithm(), StringAlgorithm::Base64);
    }

    // ── HexStage ──────────────────────────────────────────────────────────────

    #[test]
    fn test_hex_stage_can_apply() {
        let stage = HexStage::new();
        assert!(stage.can_apply(b"48656c6c6f"));
    }

    #[test]
    fn test_hex_stage_cannot_apply_odd() {
        let stage = HexStage::new();
        assert!(!stage.can_apply(b"48656c6c6"));
    }

    #[test]
    fn test_hex_stage_apply() {
        let stage = HexStage::new();
        let dec = stage.apply(b"48656c6c6f").unwrap();
        assert_eq!(dec, b"Hello");
    }

    // ── Rot13Stage ────────────────────────────────────────────────────────────

    #[test]
    fn test_rot13_stage_apply() {
        let stage = Rot13Stage::new();
        let enc = b"Uryyb Jbeyq";
        let dec = stage.apply(enc).unwrap();
        assert_eq!(dec, b"Hello World");
    }

    #[test]
    fn test_rot13_stage_roundtrip() {
        let stage = Rot13Stage::new();
        let original = b"Secret message";
        let enc = stage.apply(original).unwrap();
        let dec = stage.apply(&enc).unwrap();
        assert_eq!(dec, original);
    }

    // ── XorConstantStage ──────────────────────────────────────────────────────

    #[test]
    fn test_xor_constant_stage_apply() {
        let key = 0x42u8;
        let pt = b"Hello";
        let ct: Vec<u8> = pt.iter().map(|&b| b ^ key).collect();
        let stage = XorConstantStage::new(key);
        let dec = stage.apply(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_xor_constant_stage_name() {
        assert_eq!(XorConstantStage::new(0).name(), "XOR-Constant");
    }

    // ── XorCyclicStage ────────────────────────────────────────────────────────

    #[test]
    fn test_xor_cyclic_stage_apply() {
        let key = b"KEY".to_vec();
        let pt = b"Hello World";
        let ct: Vec<u8> = pt
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 3])
            .collect();
        let stage = XorCyclicStage::new(key);
        let dec = stage.apply(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_xor_cyclic_empty_key_error() {
        let stage = XorCyclicStage::new(vec![]);
        let result = stage.apply(b"data");
        assert!(matches!(result, Err(StringDeobfError::EmptyKey)));
    }

    // ── Rc4Stage ──────────────────────────────────────────────────────────────

    #[test]
    fn test_rc4_stage_roundtrip() {
        let key = b"secretkey".to_vec();
        let pt = b"RC4 encrypted text";
        let ct = Rc4::decrypt(pt, &key);
        let stage = Rc4Stage::new(key);
        let dec = stage.apply(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_rc4_stage_empty_key_error() {
        let stage = Rc4Stage::new(vec![]);
        let result = stage.apply(b"data");
        assert!(matches!(result, Err(StringDeobfError::EmptyKey)));
    }

    // ── ChaCha20Stage ─────────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_stage_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let pt = b"ChaCha20 secret message!";
        let ct = chacha20_decrypt(&key, &nonce, 0, pt);
        let stage = ChaCha20Stage::new(key, nonce, 0);
        let dec = stage.apply(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    // ── DeobfPipeline ─────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_base64_then_xor() {
        let key = 0x20u8;
        let pt = b"Hello World!";
        // Encode: XOR then Base64
        let xored: Vec<u8> = pt.iter().map(|&b| b ^ key).collect();
        let b64 = Base64Decoder::encode(&xored);
        let pipeline = PipelineBuilder::new().base64().xor_constant(key).build();
        let result = pipeline.run(b64.as_bytes());
        assert_eq!(result.final_output, pt);
        assert_eq!(result.plaintext.as_deref(), Some("Hello World!"));
    }

    #[test]
    fn test_pipeline_hex_decode() {
        let pipeline = PipelineBuilder::new().hex().build();
        let result = pipeline.run(b"48656c6c6f");
        assert_eq!(result.final_output, b"Hello");
    }

    #[test]
    fn test_pipeline_empty_input() {
        let pipeline = PipelineBuilder::new().base64().build();
        let result = pipeline.run(&[]);
        assert!(result.final_output.is_empty());
    }

    #[test]
    fn test_pipeline_stage_count() {
        let pipeline = PipelineBuilder::new().base64().hex().rot13().build();
        assert_eq!(pipeline.stage_count(), 3);
    }

    #[test]
    fn test_pipeline_stop_on_success() {
        let pipeline = PipelineBuilder::new()
            .hex()
            .base64()
            .stop_on_success()
            .build();
        let result = pipeline.run(b"48656c6c6f"); // hex for "Hello"
        assert_eq!(result.final_output, b"Hello");
    }

    #[test]
    fn test_pipeline_skips_inapplicable() {
        let pipeline = PipelineBuilder::new().base64().build();
        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07"; // not base64
        let result = pipeline.run(data);
        assert_eq!(result.applied_count(), 0);
    }

    #[test]
    fn test_pipeline_result_trace_length() {
        let pipeline = PipelineBuilder::new().base64().hex().rot13().build();
        let result = pipeline.run(b"dGVzdA=="); // base64 for "test"
        assert_eq!(result.trace.len(), 3);
    }

    #[test]
    fn test_pipeline_result_best_stage() {
        let pipeline = PipelineBuilder::new().base64().build();
        let result = pipeline.run(b"SGVsbG8="); // "Hello"
        // best_stage should be Base64
        if let Some(best) = result.best_stage() {
            assert_eq!(best.stage_name, "Base64Decode");
        }
    }

    // ── PipelineResult helpers ────────────────────────────────────────────────

    #[test]
    fn test_stage_result_printability_printable() {
        let r = StageResult::success(
            "test",
            StringAlgorithm::Base64,
            b"enc".to_vec(),
            b"Hello World".to_vec(),
        );
        assert!(r.output_printability() > 0.9);
    }

    #[test]
    fn test_stage_result_printability_binary() {
        let r = StageResult::success("test", StringAlgorithm::Base64, vec![], vec![0, 1, 2, 3]);
        assert!(r.output_printability() < 0.1);
    }

    // ── Auto-build pipeline ───────────────────────────────────────────────────

    #[test]
    fn test_auto_build_pipeline_base64() {
        let data = Base64Decoder::encode(b"Hello World");
        let pipeline = auto_build_pipeline(data.as_bytes(), 3);
        let result = pipeline.run(data.as_bytes());
        assert_eq!(result.final_output, b"Hello World");
    }

    #[test]
    fn test_auto_build_pipeline_hex() {
        let data = b"48656c6c6f".as_ref();
        let pipeline = auto_build_pipeline(data, 3);
        let result = pipeline.run(data);
        assert_eq!(result.final_output, b"Hello");
    }

    #[test]
    fn test_auto_build_pipeline_unknown() {
        let data = b"\x00\xFF\xFE\xFD";
        let pipeline = auto_build_pipeline(data, 3);
        let _ = pipeline.run(data); // no panic
    }
}
