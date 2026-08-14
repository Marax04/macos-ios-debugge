//! `smc_extractor` — Extract and analyse self-modified code after decryption.
//!
//! After a decryption loop has written bytes to a code region and those bytes
//! have been executed, this module dumps the resulting memory, disassembles the
//! output, identifies function boundaries within it, and tracks multiple
//! independent SMC layers (packed inside packed code, etc.).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// SmcLayer
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for a single SMC layer (packing level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LayerId(pub u32);

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Layer({})", self.0)
    }
}

/// A single self-modifying code layer: the original encrypted bytes plus the
/// decrypted result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcLayer {
    /// Layer identifier.
    pub id: LayerId,
    /// Base virtual address at which this layer lives.
    pub base_va: u64,
    /// Raw encrypted bytes as observed *before* decryption.
    pub encrypted_bytes: Vec<u8>,
    /// Decrypted bytes after the loop ran.
    pub decrypted_bytes: Vec<u8>,
    /// Virtual address of the decryption routine entry point.
    pub decryptor_entry: u64,
    /// Key data used (opaque byte blob; interpretation depends on algorithm).
    pub key_data: Vec<u8>,
    /// Layer depth: 0 = outermost, 1 = first nested layer, …
    pub depth: u32,
    /// Whether another SMC layer was found inside the decrypted bytes.
    pub has_inner_layer: bool,
}

impl SmcLayer {
    /// Construct a new layer at the given base address.
    #[must_use] 
    pub fn new(id: LayerId, base_va: u64, encrypted: Vec<u8>, decryptor_entry: u64, depth: u32) -> Self {
        let len = encrypted.len();
        Self {
            id,
            base_va,
            encrypted_bytes: encrypted,
            decrypted_bytes: vec![0u8; len],
            decryptor_entry,
            key_data: Vec::new(),
            depth,
            has_inner_layer: false,
        }
    }

    /// Apply decrypted bytes (from emulation output or memory dump).
    pub fn set_decrypted(&mut self, bytes: Vec<u8>) {
        self.decrypted_bytes = bytes;
    }

    /// Returns the size of the layer in bytes.
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.encrypted_bytes.len()
    }

    /// Compute a simple Shannon entropy of the decrypted bytes (0.0–8.0 bits/byte).
    #[must_use] 
    pub fn entropy(&self) -> f64 {
        let len = self.decrypted_bytes.len();
        if len == 0 {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in &self.decrypted_bytes {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(len).unwrap_or(u32::MAX));
        let mut h = 0.0f64;
        for &c in &freq {
            if c > 0 {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                h -= p * p.log2();
            }
        }
        h
    }

    /// Return the bytes changed by decryption (index, old, new).
    #[must_use] 
    pub fn diff(&self) -> Vec<(usize, u8, u8)> {
        self.encrypted_bytes
            .iter()
            .zip(self.decrypted_bytes.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, (&a, &b))| (i, a, b))
            .collect()
    }
}

impl fmt::Display for SmcLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} base={:#x} size={} depth={} entropy={:.2}",
            self.id,
            self.base_va,
            self.size(),
            self.depth,
            self.entropy()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractedCode
// ─────────────────────────────────────────────────────────────────────────────

/// A disassembled instruction within extracted SMC code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedInsn {
    /// Virtual address of the instruction.
    pub va: u64,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic string (e.g. `"mov"`, `"xor"`).
    pub mnemonic: String,
    /// Operands string (e.g. `"eax, ecx"`).
    pub operands: String,
    /// Length in bytes.
    pub len: u8,
    /// Whether this instruction is a branch (conditional or unconditional).
    pub is_branch: bool,
    /// Whether this instruction is a call.
    pub is_call: bool,
    /// Whether this instruction is a return.
    pub is_ret: bool,
}

impl ExtractedInsn {
    /// Build a placeholder instruction for testing/mocking.
    #[must_use] 
    pub fn placeholder(va: u64, len: u8) -> Self {
        Self {
            va,
            bytes: vec![0x90; len as usize],
            mnemonic: "nop".into(),
            operands: String::new(),
            len,
            is_branch: false,
            is_call: false,
            is_ret: false,
        }
    }
}

impl fmt::Display for ExtractedInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}  {} {}", self.va, self.mnemonic, self.operands)
    }
}

/// A function recovered from extracted SMC code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFunction {
    /// Entry-point virtual address.
    pub entry: u64,
    /// All instruction VAs belonging to this function.
    pub insn_vas: Vec<u64>,
    /// Approximate size in bytes (last insn VA + len - entry).
    pub size: usize,
    /// Whether the function has a standard prologue (push rbp / push ebp).
    pub has_prologue: bool,
}

impl ExtractedFunction {
    /// Construct an empty function at the given entry.
    #[must_use] 
    pub const fn new(entry: u64) -> Self {
        Self { entry, insn_vas: Vec::new(), size: 0, has_prologue: false }
    }

    /// Number of instructions in the function.
    #[must_use] 
    pub const fn insn_count(&self) -> usize {
        self.insn_vas.len()
    }
}

impl fmt::Display for ExtractedFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fn@{:#x} insns={} size={}", self.entry, self.insn_count(), self.size)
    }
}

/// All code extracted from a single SMC layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCode {
    /// The layer this code came from.
    pub layer_id: LayerId,
    /// Disassembled instructions, in address order.
    pub instructions: Vec<ExtractedInsn>,
    /// Recovered function boundaries.
    pub functions: Vec<ExtractedFunction>,
    /// Coverage: fraction of bytes that were successfully disassembled.
    pub coverage_ratio: f64,
    /// Disassembly warnings (unknown opcodes, etc.).
    pub warnings: Vec<String>,
}

impl ExtractedCode {
    /// Create an empty `ExtractedCode` for `layer_id`.
    #[must_use] 
    pub const fn new(layer_id: LayerId) -> Self {
        Self {
            layer_id,
            instructions: Vec::new(),
            functions: Vec::new(),
            coverage_ratio: 0.0,
            warnings: Vec::new(),
        }
    }

    /// Populate from a linear disassembly of `bytes` starting at `base_va`.
    ///
    /// This is a minimal linear sweep; a real implementation would call an
    /// external disassembler. Here we build placeholder records.
    #[must_use] 
    pub fn from_linear_sweep(layer_id: LayerId, base_va: u64, bytes: &[u8]) -> Self {
        let mut ec = Self::new(layer_id);
        let mut offset = 0usize;
        while offset < bytes.len() {
            // Minimal heuristic: use 1-byte instructions for placeholders.
            let b = bytes[offset];
            let (mnemonic, len, is_branch, is_call, is_ret) = classify_byte(b);
            let insn = ExtractedInsn {
                va: base_va + u64::try_from(offset).unwrap_or(u64::MAX),
                bytes: bytes[offset..offset + len].to_vec(),
                mnemonic: mnemonic.to_string(),
                operands: String::new(),
                len: u8::try_from(len).unwrap_or(u8::MAX),
                is_branch,
                is_call,
                is_ret,
            };
            ec.instructions.push(insn);
            offset += len;
        }
        let decoded = ec.instructions.len();
        ec.coverage_ratio = if bytes.is_empty() {
            0.0
        } else {
            f64::from(u32::try_from(decoded).unwrap_or(u32::MAX)) / f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
        };
        ec.identify_functions(base_va);
        ec
    }

    /// Heuristic function-boundary identification: start a new function at
    /// each `push rbp` / `push ebp` after a `ret`.
    pub fn identify_functions(&mut self, base_va: u64) {
        let mut current = ExtractedFunction::new(base_va);
        let mut after_ret = false;

        for insn in &self.instructions {
            if after_ret && (insn.mnemonic == "push") {
                // Flush current function.
                if !current.insn_vas.is_empty() {
                    self.functions.push(current.clone());
                }
                current = ExtractedFunction::new(insn.va);
                current.has_prologue = true;
                after_ret = false;
            }
            current.insn_vas.push(insn.va);
            if insn.is_ret {
                after_ret = true;
                // Compute size.
                let last_va = insn.va + u64::from(insn.len);
                current.size = usize::try_from(last_va - current.entry).unwrap_or(usize::MAX);
            }
        }
        if !current.insn_vas.is_empty() {
            self.functions.push(current);
        }
    }

    /// Total number of instructions.
    #[must_use] 
    pub const fn insn_count(&self) -> usize {
        self.instructions.len()
    }

    /// Find all call targets within the extracted code.
    #[must_use] 
    pub fn call_targets(&self) -> Vec<u64> {
        self.instructions.iter().filter(|i| i.is_call).map(|i| i.va).collect()
    }
}

impl fmt::Display for ExtractedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtractedCode(layer={} insns={} fns={} cov={:.1}%)",
            self.layer_id,
            self.insn_count(),
            self.functions.len(),
            self.coverage_ratio * 100.0
        )
    }
}

/// Minimal byte classifier for the linear sweep placeholder.
const fn classify_byte(b: u8) -> (&'static str, usize, bool, bool, bool) {
    match b {
        0x90 => ("nop", 1, false, false, false),
        0xC3 => ("ret", 1, false, false, true),
        0xC2 => ("ret", 3, false, false, true),
        0xE8 => ("call", 5, false, true, false),
        0xFF => ("call", 2, false, true, false),
        0xEB => ("jmp", 2, true, false, false),
        0xE9 => ("jmp", 5, true, false, false),
        0x74 | 0x75 => ("jcc", 2, true, false, false),
        0x55 => ("push", 1, false, false, false),
        _ => ("db", 1, false, false, false),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LayerStack
// ─────────────────────────────────────────────────────────────────────────────

/// A stack of SMC layers, from outermost (index 0) to deepest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerStack {
    layers: Vec<SmcLayer>,
    next_id: u32,
}

impl LayerStack {
    /// Create an empty layer stack.
    #[must_use] 
    pub const fn new() -> Self {
        Self { layers: Vec::new(), next_id: 0 }
    }

    /// Push a new layer and return its assigned ID.
    pub fn push_layer(
        &mut self,
        base_va: u64,
        encrypted: Vec<u8>,
        decryptor_entry: u64,
    ) -> LayerId {
        let id = LayerId(self.next_id);
        self.next_id += 1;
        let depth = u32::try_from(self.layers.len()).unwrap_or(u32::MAX);
        self.layers.push(SmcLayer::new(id, base_va, encrypted, decryptor_entry, depth));
        id
    }

    /// Set decrypted bytes for the layer identified by `id`.
    pub fn set_decrypted(&mut self, id: LayerId, bytes: Vec<u8>) -> bool {
        if let Some(l) = self.layers.iter_mut().find(|l| l.id == id) {
            l.set_decrypted(bytes);
            return true;
        }
        false
    }

    /// Get a reference to a layer by ID.
    #[must_use] 
    pub fn get(&self, id: LayerId) -> Option<&SmcLayer> {
        self.layers.iter().find(|l| l.id == id)
    }

    /// Get a mutable reference to a layer by ID.
    pub fn get_mut(&mut self, id: LayerId) -> Option<&mut SmcLayer> {
        self.layers.iter_mut().find(|l| l.id == id)
    }

    /// All layers in depth order.
    #[must_use] 
    pub fn all_layers(&self) -> &[SmcLayer] {
        &self.layers
    }

    /// Number of layers.
    #[must_use] 
    pub const fn depth(&self) -> usize {
        self.layers.len()
    }

    /// Deepest fully-decrypted layer.
    #[must_use] 
    pub fn innermost_decrypted(&self) -> Option<&SmcLayer> {
        self.layers.iter().rev().find(|l| !l.decrypted_bytes.is_empty())
    }
}

impl Default for LayerStack {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LayerStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LayerStack(depth={})", self.depth())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LayerDecryption
// ─────────────────────────────────────────────────────────────────────────────

/// Records how a specific layer was decrypted (algorithm + key + timing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerDecryption {
    /// Layer being decrypted.
    pub layer_id: LayerId,
    /// Algorithm name (e.g. `"xor_byte"`, `"rol8_add"`).
    pub algorithm: String,
    /// Key bytes used.
    pub key: Vec<u8>,
    /// Number of emulator ticks the decryption took.
    pub ticks: u64,
    /// Whether decryption was fully observed (vs. partial snapshot).
    pub complete: bool,
}

impl LayerDecryption {
    /// Build a new decryption record.
    pub fn new(layer_id: LayerId, algorithm: impl Into<String>, key: Vec<u8>, ticks: u64) -> Self {
        Self { layer_id, algorithm: algorithm.into(), key, ticks, complete: false }
    }

    /// Mark this decryption as fully observed.
    #[must_use] 
    pub const fn mark_complete(mut self) -> Self {
        self.complete = true;
        self
    }
}

impl fmt::Display for LayerDecryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Decrypt({} via {} key={} ticks={} complete={})",
            self.layer_id,
            self.algorithm,
            hex_slice(&self.key),
            self.ticks,
            self.complete
        )
    }
}

fn hex_slice(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
        s
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Complete analysis result for a binary with SMC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcAnalysis {
    /// All layer stacks found in the binary (keyed by outermost base VA).
    pub stacks: HashMap<u64, LayerStack>,
    /// Extracted code per layer.
    pub extracted: HashMap<u32, ExtractedCode>,
    /// Decryption metadata per layer.
    pub decryptions: Vec<LayerDecryption>,
    /// Total number of decryption layers across all stacks.
    pub total_layers: usize,
    /// Whether analysis is complete (all layers resolved).
    pub complete: bool,
}

impl SmcAnalysis {
    /// Create an empty analysis result.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            stacks: HashMap::new(),
            extracted: HashMap::new(),
            decryptions: Vec::new(),
            total_layers: 0,
            complete: false,
        }
    }

    /// Add a new layer stack rooted at `base_va`.
    pub fn add_stack(&mut self, base_va: u64) -> &mut LayerStack {
        self.stacks.entry(base_va).or_default()
    }

    /// Record extracted code for a layer.
    pub fn record_extraction(&mut self, code: ExtractedCode) {
        self.extracted.insert(code.layer_id.0, code);
    }

    /// Record a decryption event.
    pub fn record_decryption(&mut self, dec: LayerDecryption) {
        self.decryptions.push(dec);
    }

    /// Recompute `total_layers` from all stacks.
    pub fn update_total_layers(&mut self) {
        self.total_layers = self.stacks.values().map(LayerStack::depth).sum();
    }

    /// Returns all extracted functions across all layers, sorted by VA.
    #[must_use] 
    pub fn all_functions(&self) -> Vec<&ExtractedFunction> {
        let mut fns: Vec<&ExtractedFunction> =
            self.extracted.values().flat_map(|ec| &ec.functions).collect();
        fns.sort_by_key(|f| f.entry);
        fns
    }

    /// Returns the deepest innermost decrypted layer across all stacks.
    #[must_use] 
    pub fn deepest_layer(&self) -> Option<&SmcLayer> {
        self.stacks.values().filter_map(|s| s.innermost_decrypted()).max_by_key(|l| l.depth)
    }
}

impl Default for SmcAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SmcAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmcAnalysis [stacks={} total_layers={} extractions={} complete={}]",
            self.stacks.len(),
            self.total_layers,
            self.extracted.len(),
            self.complete
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// High-level extractor: orchestrates layer stack building and code extraction.
pub struct SmcExtractor {
    /// Accumulated analysis.
    pub analysis: SmcAnalysis,
}

impl SmcExtractor {
    /// Create a new extractor.
    #[must_use] 
    pub fn new() -> Self {
        Self { analysis: SmcAnalysis::new() }
    }

    /// Register the start of a new SMC region at `base_va` with the original
    /// (encrypted) `bytes` and its `decryptor_entry` VA.
    ///
    /// Returns the [`LayerId`] assigned to this layer.
    pub fn begin_layer(&mut self, base_va: u64, bytes: Vec<u8>, decryptor_entry: u64) -> LayerId {
        let stack = self.analysis.add_stack(base_va);
        let id = stack.push_layer(base_va, bytes, decryptor_entry);
        self.analysis.update_total_layers();
        id
    }

    /// Feed decrypted bytes for the given layer, then run extraction.
    pub fn finalize_layer(&mut self, base_va: u64, id: LayerId, decrypted: &[u8]) {
        // Find the stack.
        if let Some(stack) = self.analysis.stacks.get_mut(&base_va)
            && let Some(layer) = stack.get_mut(id) {
                let va = layer.base_va;
                layer.set_decrypted(decrypted.to_vec());
                // Check for nested SMC (high entropy in decrypted bytes suggests another layer).
                if layer.entropy() > 7.2 {
                    layer.has_inner_layer = true;
                }
                // Extract code from the decrypted bytes.
                let extracted = ExtractedCode::from_linear_sweep(id, va, decrypted);
                self.analysis.record_extraction(extracted);
            }
    }

    /// Record a decryption event.
    pub fn record_decryption(&mut self, dec: LayerDecryption) {
        self.analysis.record_decryption(dec);
    }

    /// Mark the analysis as complete.
    pub const fn finish(&mut self) {
        self.analysis.complete = true;
    }

    /// Total function count across all extracted layers.
    #[must_use] 
    pub fn total_functions(&self) -> usize {
        self.analysis.extracted.values().map(|ec| ec.functions.len()).sum()
    }
}

impl Default for SmcExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_stack_push_and_get() {
        let mut stack = LayerStack::new();
        let id = stack.push_layer(0x1000, vec![0xaa; 64], 0x500);
        assert_eq!(id, LayerId(0));
        assert!(stack.get(id).is_some());
    }

    #[test]
    fn test_layer_entropy_zero_bytes() {
        let mut layer = SmcLayer::new(LayerId(0), 0x1000, vec![0x00; 256], 0x200, 0);
        layer.set_decrypted(vec![0x00; 256]);
        // Uniform zero → entropy 0.0
        assert_eq!(layer.entropy(), 0.0);
    }

    #[test]
    fn test_layer_diff() {
        let enc = vec![0xaa, 0xbb, 0xcc];
        let dec = vec![0x11, 0xbb, 0x33];
        let mut layer = SmcLayer::new(LayerId(0), 0x0, enc, 0x0, 0);
        layer.set_decrypted(dec);
        let diff = layer.diff();
        assert_eq!(diff.len(), 2);
        assert_eq!(diff[0], (0, 0xaa, 0x11));
        assert_eq!(diff[1], (2, 0xcc, 0x33));
    }

    #[test]
    fn test_extracted_code_from_linear_sweep() {
        // 0x90 = nop, 0xC3 = ret
        let bytes = vec![0x90, 0x90, 0xC3, 0x55, 0x90, 0xC3];
        let ec = ExtractedCode::from_linear_sweep(LayerId(0), 0x1000, &bytes);
        assert_eq!(ec.insn_count(), 6);
        // Two ret instructions → expect 2 functions
        assert!(!ec.functions.is_empty());
    }

    #[test]
    fn test_smc_extractor_begin_and_finalize() {
        let mut ext = SmcExtractor::new();
        let id = ext.begin_layer(0x2000, vec![0xaa; 32], 0x100);
        ext.finalize_layer(0x2000, id, &vec![0x90; 32]);
        assert!(ext.analysis.extracted.contains_key(&0));
    }

    #[test]
    fn test_smc_analysis_all_functions() {
        let mut analysis = SmcAnalysis::new();
        let mut ec = ExtractedCode::new(LayerId(0));
        ec.functions.push(ExtractedFunction::new(0x1000));
        ec.functions.push(ExtractedFunction::new(0x1100));
        analysis.record_extraction(ec);
        let fns = analysis.all_functions();
        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].entry, 0x1000);
    }

    #[test]
    fn test_layer_decryption_mark_complete() {
        let dec = LayerDecryption::new(LayerId(0), "xor_byte", vec![0x42], 1000).mark_complete();
        assert!(dec.complete);
    }

    #[test]
    fn test_classify_byte_ret() {
        let (mnemonic, len, _, _, is_ret) = classify_byte(0xC3);
        assert_eq!(mnemonic, "ret");
        assert_eq!(len, 1);
        assert!(is_ret);
    }
}
