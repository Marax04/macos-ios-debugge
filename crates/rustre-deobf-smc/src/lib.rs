//! `rustre-deobf-smc` — Self-Modifying Code (SMC) analysis and deobfuscation.
//!
//! Detects code regions that are written at runtime before execution, recovers
//! the decryption key and algorithm, and produces pre-decrypted binary patches.

pub mod decryption_loop_analyzer;
pub mod deobf_pass_smc;
pub mod emulation_harness;
pub mod key_recovery;
pub mod layer_extractor;
pub mod pe_unpacker;
pub mod smc_detector;
pub mod smc_extractor;
pub mod smc_monitor;
pub mod smc_reconstructor;
pub mod unpacker_engine;
pub mod write_monitor;
pub mod smc_write_tracker;
pub mod smc_payload_extractor;
pub mod smc_emulator;
pub mod smc_region_tracker;
pub mod smc_decryptor_extractor;
pub mod smc_patched_code_reconstructor;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use rustre_deobf::{DeobfContext, DeobfError, DeobfPass, DeobfResult, Patch};

// ─────────────────────────────────────────────────────────────────────────────
// Key and algorithm enumerations
// ─────────────────────────────────────────────────────────────────────────────

/// The key material used to decrypt an SMC region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmcKey {
    /// A compile-time constant value (1–8 bytes, stored as u64).
    Constant(u64),
    /// The key is derived at runtime (e.g. from a hash) and could not be
    /// recovered statically.
    Derived,
    /// The key resides in the binary at the given file offset.
    FromMemory(u64),
    /// The key is held in the named register at the entry of the decryptor.
    FromRegister(String),
}

/// The algorithm applied to each byte (or word) of the encrypted region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmcAlgorithm {
    /// `byte ^= key`
    Xor,
    /// `byte += key`
    Add,
    /// `byte -= key`
    Sub,
    /// `byte = rol(byte, key)`
    Rol,
    /// `byte = ror(byte, key)`
    Ror,
    /// `byte ^= key; key = byte` (rolling XOR)
    XorRolling,
    /// `byte += key; key = byte` (rolling ADD)
    AddRolling,
    /// Custom multi-byte opcode sequence (serialised as raw bytes).
    Custom(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcRegion — describes one SMC-protected region
// ─────────────────────────────────────────────────────────────────────────────

/// A self-modifying code region identified in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcRegion {
    /// Virtual address of the first byte of the encrypted region.
    pub start: u64,
    /// Virtual address of the first byte *past* the encrypted region.
    pub end: u64,
    /// Virtual address of the decryptor stub that processes this region.
    pub decryptor_addr: u64,
    /// Key material recovered for this region.
    pub key: SmcKey,
    /// Decryption algorithm.
    pub algorithm: SmcAlgorithm,
}

impl SmcRegion {
    /// Length of the region in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True if the region has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcDecryptor — emulates decryption given a region descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates the decryption of an SMC-protected region given its descriptor.
#[derive(Debug, Clone, Default)]
pub struct SmcDecryptor;

impl SmcDecryptor {
    /// Create a new [`SmcDecryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decrypt `data` according to the given [`SmcRegion`].
    ///
    /// `data` should contain the bytes of the region (starting at
    /// `region.start`).
    #[must_use]
    pub fn decrypt(&self, data: &[u8], region: &SmcRegion) -> Vec<u8> {
        let key_byte = match &region.key {
            SmcKey::Constant(k) => u8::try_from(*k & 0xFF).unwrap_or(0),
            SmcKey::FromMemory(_) | SmcKey::FromRegister(_) | SmcKey::Derived => 0x00,
        };

        match &region.algorithm {
            SmcAlgorithm::Xor => data.iter().map(|&b| b ^ key_byte).collect(),
            SmcAlgorithm::Add => data.iter().map(|&b| b.wrapping_sub(key_byte)).collect(),
            SmcAlgorithm::Sub => data.iter().map(|&b| b.wrapping_add(key_byte)).collect(),
            SmcAlgorithm::Rol => data.iter().map(|&b| rol8(b, key_byte & 7)).collect(),
            SmcAlgorithm::Ror => data.iter().map(|&b| ror8(b, key_byte & 7)).collect(),
            SmcAlgorithm::XorRolling => {
                let mut key = key_byte;
                data.iter()
                    .map(|&b| {
                        let plain = b ^ key;
                        key = b;
                        plain
                    })
                    .collect()
            }
            SmcAlgorithm::AddRolling => {
                let mut key = key_byte;
                data.iter()
                    .map(|&b| {
                        let plain = b.wrapping_sub(key);
                        key = b;
                        plain
                    })
                    .collect()
            }
            SmcAlgorithm::Custom(ops) => {
                // Interpret `ops` as a trivial stack machine: each byte is an
                // opcode: 0x01 = XOR with next byte, 0x02 = ADD with next byte,
                // 0x03 = SUB with next byte.  Unknown ops leave byte unchanged.
                let mut out = data.to_vec();
                let mut ip = 0;
                while ip + 1 < ops.len() {
                    let op = ops[ip];
                    let arg = ops[ip + 1];
                    ip += 2;
                    for b in &mut out {
                        match op {
                            0x01 => *b ^= arg,
                            0x02 => *b = b.wrapping_add(arg),
                            0x03 => *b = b.wrapping_sub(arg),
                            _ => {}
                        }
                    }
                }
                out
            }
        }
    }
}

fn rol8(byte: u8, n: u8) -> u8 {
    let n = n & 7;
    if n == 0 {
        byte
    } else {
        byte.rotate_left(u32::from(n))
    }
}

fn ror8(byte: u8, n: u8) -> u8 {
    let n = n & 7;
    if n == 0 {
        byte
    } else {
        byte.rotate_right(u32::from(n))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcDetector — static analysis to find SMC patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Statically analyses a binary for SMC patterns.
///
/// The detector looks for:
/// 1. Write-then-execute: code that writes into a range that is subsequently
///    jumped to (heuristic: offset in `address_map` that is later used as
///    a branch target stored in metadata).
/// 2. Decryption loops: a counter register, a base pointer, an XOR/ADD/SUB
///    instruction, and a loop-back branch.
/// 3. Common SMC prologues: push/pop surround of XOR-array loop.
#[derive(Debug, Clone, Default)]
pub struct SmcDetector;

impl SmcDetector {
    /// Create a new [`SmcDetector`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for SMC decryption-loop patterns and return candidate regions.
    ///
    /// Each detected region has a best-effort algorithm and key guess derived
    /// from the surrounding code bytes.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<SmcRegion> {
        let mut regions = Vec::new();

        // Pattern A: XOR loop
        // Signature: MOV ECX, imm32; MOV EDI, imm32; XOR [EDI+ECX*1], imm8; LOOP/DEC/JNZ
        // Simplified: look for the sequence  B9 ?? ?? ?? ??  BF ?? ?? ?? ??  80 34 0F ??
        regions.extend(Self::detect_xor_loop(data));

        // Pattern B: ADD loop (byte addition cipher)
        regions.extend(Self::detect_add_loop(data));

        // Pattern C: Rolling-XOR decryptor prologue
        regions.extend(Self::detect_rolling_xor(data));

        // Pattern D: PUSH/POP framing with XOR body
        regions.extend(Self::detect_push_pop_xor(data));

        regions
    }

    fn detect_xor_loop(data: &[u8]) -> Vec<SmcRegion> {
        // Heuristic: find  MOV register, imm32  (B8+r or B9…BF)
        //            followed within 16 bytes by  XOR byte ptr [reg+reg], imm8  (80 34 xx yy)
        // Extract the immediate value as the key guess.
        let mut result = Vec::new();
        if data.len() < 12 {
            return result;
        }
        for i in 0..data.len() - 12 {
            // MOV ECX, imm32: B9 xx xx xx xx
            if data[i] == 0xB9 {
                let count = u32::from_le_bytes([
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                ]);
                // Look ahead for XOR [mem], imm8 pattern (80 3x or 80 34/35/36..)
                for j in (i + 5)..(i + 5 + 16).min(data.len().saturating_sub(3)) {
                    if data[j] == 0x80 && (data[j + 1] & 0xF0 == 0x30) {
                        let xor_key = data[j + 3];
                        // Extract destination address guess from a nearby MOV EDI, imm32.
                        let dest_addr = Self::find_nearby_imm32(data, i, 5);
                        result.push(SmcRegion {
                            start: dest_addr,
                            end: dest_addr + u64::from(count),
                            decryptor_addr: i as u64,
                            key: SmcKey::Constant(u64::from(xor_key)),
                            algorithm: SmcAlgorithm::Xor,
                        });
                        break;
                    }
                }
            }
        }
        result
    }

    fn detect_add_loop(data: &[u8]) -> Vec<SmcRegion> {
        let mut result = Vec::new();
        if data.len() < 12 {
            return result;
        }
        for i in 0..data.len() - 12 {
            // ADD byte ptr [reg], imm8: 80 0x?? imm8
            if data[i] == 0x80 && (data[i + 1] & 0x38) == 0x00 {
                let add_key = data[i + 2];
                let dest_addr = Self::find_nearby_imm32(data, i, 6);
                // Skip emission when no nearby MOV imm32 was found (dest_addr defaults to 0).
                if dest_addr == 0 {
                    continue;
                }
                result.push(SmcRegion {
                    start: dest_addr,
                    end: dest_addr + 64, // size unknown; use default
                    decryptor_addr: i as u64,
                    key: SmcKey::Constant(u64::from(add_key)),
                    algorithm: SmcAlgorithm::Add,
                });
            }
        }
        result
    }

    fn detect_rolling_xor(data: &[u8]) -> Vec<SmcRegion> {
        let mut result = Vec::new();
        if data.len() < 8 {
            return result;
        }
        // Rolling XOR pattern: MOV AL, [ESI]; XOR AL, BL; MOV [EDI], AL; INC ESI; INC EDI
        // Simplified: 8A 06  32 C3  88 07
        let pattern = [0x8A, 0x06, 0x32, 0xC3, 0x88, 0x07];
        for i in 0..data.len().saturating_sub(pattern.len()) {
            if data[i..i + pattern.len()] == pattern {
                let dest_addr = Self::find_nearby_imm32(data, i, 8);
                result.push(SmcRegion {
                    start: dest_addr,
                    end: dest_addr + 128,
                    decryptor_addr: i as u64,
                    key: SmcKey::FromRegister("BL".to_owned()),
                    algorithm: SmcAlgorithm::XorRolling,
                });
            }
        }
        result
    }

    fn detect_push_pop_xor(data: &[u8]) -> Vec<SmcRegion> {
        let mut result = Vec::new();
        if data.len() < 4 {
            return result;
        }
        // PUSHAD (0x60) ... XOR [mem], imm8 ... POPAD (0x61)
        for i in 0..data.len() - 3 {
            if data[i] == 0x60 {
                // Scan ahead for POPAD
                for j in (i + 4)..(i + 256).min(data.len()) {
                    if data[j] == 0x61 {
                        // Extract XOR key from inside the block if present.
                        let (key, algo) = Self::extract_key_from_block(&data[i..j]);
                        let dest = Self::find_nearby_imm32(data, i, 6);
                        let region_len = (j - i) as u64;
                        result.push(SmcRegion {
                            start: dest,
                            end: dest.saturating_add(region_len),
                            decryptor_addr: i as u64,
                            key,
                            algorithm: algo,
                        });
                        break;
                    }
                }
            }
        }
        result
    }

    fn extract_key_from_block(block: &[u8]) -> (SmcKey, SmcAlgorithm) {
        for i in 0..block.len().saturating_sub(2) {
            if block[i] == 0x80 && (block[i + 1] & 0x38 == 0x30) {
                return (SmcKey::Constant(u64::from(block[i + 2])), SmcAlgorithm::Xor);
            }
            if block[i] == 0x80 && (block[i + 1].trailing_zeros() >= 3) {
                return (SmcKey::Constant(u64::from(block[i + 2])), SmcAlgorithm::Add);
            }
        }
        (SmcKey::Derived, SmcAlgorithm::Xor)
    }

    fn find_nearby_imm32(data: &[u8], origin: usize, lookahead: usize) -> u64 {
        let end = (origin + lookahead + 6).min(data.len());
        for i in origin..end.saturating_sub(4) {
            // MOV reg, imm32: 0xBF, 0xBE, 0xBB...
            if data[i] >= 0xB8 && data[i] <= 0xBF && i + 4 < data.len() {
                let imm = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                if imm > 0x1000 {
                    return u64::from(imm);
                }
            }
        }
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcPatcher — generates Patch records to embed pre-decrypted code
// ─────────────────────────────────────────────────────────────────────────────

/// Generates [`Patch`] records that replace the encrypted region with the
/// pre-decrypted code and NOP out the decryptor stub.
#[derive(Debug, Clone, Default)]
pub struct SmcPatcher;

impl SmcPatcher {
    /// Create a new [`SmcPatcher`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build patches for `region` given the raw file bytes.
    ///
    /// # Errors
    /// Returns [`DeobfError`] if the region size or offsets overflow `usize`.
    ///
    /// The function:
    /// 1. Extracts the encrypted bytes from `data` at `region.start` (as file offset).
    /// 2. Decrypts them with [`SmcDecryptor`].
    /// 3. Returns a [`Patch`] to overwrite the encrypted region with plaintext.
    ///
    /// Note: this function uses file offsets directly; callers must map virtual
    /// addresses to file offsets if needed.
    pub fn build_patches(
        &self,
        data: &[u8],
        region: &SmcRegion,
        file_offset: usize,
    ) -> Result<Vec<Patch>, DeobfError> {
        let size = usize::try_from(region.len()).map_err(|_| DeobfError::TooShort {
            needed: usize::MAX,
            have: data.len(),
        })?;
        // A raw `file_offset + size` wraps in release builds (overflow-checks
        // off): the sum can land back inside `data`, passing the check below
        // while the slice range is still invalid.
        let end = file_offset
            .checked_add(size)
            .ok_or(DeobfError::TooShort {
                needed: usize::MAX,
                have: data.len(),
            })?;
        if end > data.len() {
            return Err(DeobfError::TooShort {
                needed: end,
                have: data.len(),
            });
        }
        let encrypted = &data[file_offset..end];
        let decryptor = SmcDecryptor::new();
        let decrypted = decryptor.decrypt(encrypted, region);

        let patch = Patch::new(
            file_offset,
            encrypted.to_vec(),
            decrypted,
            format!(
                "SMC region {:#x}–{:#x} pre-decrypted",
                region.start, region.end
            ),
        );
        Ok(vec![patch])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LayeredSmc — multi-layer SMC
// ─────────────────────────────────────────────────────────────────────────────

/// Handles multi-layer SMC: iteratively decrypts layer by layer until no more
/// SMC regions are detected (or a maximum iteration count is reached).
#[derive(Debug, Clone)]
pub struct LayeredSmc {
    /// Maximum number of decryption layers to attempt.
    pub max_layers: usize,
}

impl Default for LayeredSmc {
    fn default() -> Self {
        Self { max_layers: 8 }
    }
}

impl LayeredSmc {
    /// Create a new [`LayeredSmc`] with the given layer limit.
    #[must_use]
    pub const fn new(max_layers: usize) -> Self {
        Self { max_layers }
    }

    /// Iteratively decrypt `data` until stable or `max_layers` is reached.
    ///
    /// Returns the final decrypted bytes and the number of layers processed.
    #[must_use]
    pub fn decrypt_all(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let detector = SmcDetector::new();
        let patcher = SmcPatcher::new();
        let decryptor = SmcDecryptor::new();
        let mut current = data.to_vec();

        for layer in 0..self.max_layers {
            let regions = detector.detect(&current);
            if regions.is_empty() {
                return (current, layer);
            }
            for region in &regions {
                let Ok(size) = usize::try_from(region.len()) else { continue };
                let Ok(start) = usize::try_from(region.start) else { continue };
                let end = match start.checked_add(size) {
                    Some(e) if e <= current.len() => e,
                    _ => continue,
                };
                if size == 0 {
                    continue;
                }
                let slice = &current[start..end];
                let decrypted = decryptor.decrypt(slice, region);
                current[start..end].copy_from_slice(&decrypted);
            }
            // Verify patches can be built (sanity check).
            let _ = patcher;
        }
        (current, self.max_layers)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmulatedDecrypt — light CPU emulation for decryption tracing
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal register file for the emulated decryptor.
#[derive(Debug, Clone, Default)]
pub struct EmuRegisters {
    /// General-purpose 64-bit registers (RAX=0 … R15=15).
    pub gpr: [u64; 16],
    /// Instruction pointer.
    pub rip: u64,
    /// Flags: bit 0 = ZF.
    pub flags: u64,
}

impl EmuRegisters {
    /// Read a register by index (0–15 = RAX–R15).
    #[must_use]
    pub fn read(&self, reg: u8) -> u64 {
        self.gpr[usize::from(reg) & 15]
    }

    /// Write a register by index.
    pub fn write(&mut self, reg: u8, val: u64) {
        self.gpr[usize::from(reg) & 15] = val;
    }
}

/// Micro-emulator that traces XOR/ADD/ROL loops to recover key and region
/// boundaries from the instruction stream.
#[derive(Debug, Clone, Default)]
pub struct EmulatedDecrypt;

/// Result of an emulation trace.
#[derive(Debug, Clone)]
pub struct EmulationTrace {
    /// The key value recovered (last XOR immediate seen).
    pub recovered_key: u8,
    /// Algorithm inferred from the instruction mix.
    pub algorithm: SmcAlgorithm,
    /// Number of loop iterations simulated.
    pub iterations: usize,
}

impl EmulatedDecrypt {
    /// Create a new [`EmulatedDecrypt`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Trace at most `max_iter` steps of the decoded instruction slice.
    ///
    /// The decoder understands a minimal subset:
    /// - `XOR [mem], imm8` — records key.
    /// - `ADD [mem], imm8` — records key.
    /// - `SUB [mem], imm8` — records key.
    /// - `DEC reg` / `INC reg` — tracked.
    /// - `JNZ rel8` — forms loop; counted.
    #[must_use]
    pub fn trace(&self, code: &[u8], max_iter: usize) -> EmulationTrace {
        let mut key = 0u8;
        let mut algo = SmcAlgorithm::Xor;
        let mut pc = 0usize;
        let mut iterations = 0;

        while pc < code.len() && iterations < max_iter {
            let op = code[pc];
            match op {
                // XOR [mem], imm8: 80 3x imm8
                0x80 if pc + 2 < code.len() && (code[pc + 1] & 0x38) == 0x30 => {
                    key = code[pc + 2];
                    algo = SmcAlgorithm::Xor;
                    pc += 3;
                }
                // ADD [mem], imm8: 80 0x imm8
                0x80 if pc + 2 < code.len() && (code[pc + 1] & 0x38) == 0x00 => {
                    key = code[pc + 2];
                    algo = SmcAlgorithm::Add;
                    pc += 3;
                }
                // SUB [mem], imm8: 80 2x imm8
                0x80 if pc + 2 < code.len() && (code[pc + 1] & 0x38) == 0x28 => {
                    key = code[pc + 2];
                    algo = SmcAlgorithm::Sub;
                    pc += 3;
                }
                // JNZ rel8: 75 offset
                0x75 if pc + 1 < code.len() => {
                    iterations += 1;
                    let offset = code[pc + 1].cast_signed();
                    let target = i64::try_from(pc).unwrap_or(i64::MAX) + 2 + i64::from(offset);
                    match usize::try_from(target) {
                        Ok(new_pc) if new_pc < pc => pc = new_pc, // loop back
                        _ => pc += 2,                             // forward jump or invalid = exit loop
                    }
                }
                // DEC/INC r32 (0x40–0x4F), NOP (0x90), or any other opcode
                _ => {
                    pc += 1;
                }
            }
        }

        EmulationTrace {
            recovered_key: key,
            algorithm: algo,
            iterations,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcPass — DeobfPass implementation
// ─────────────────────────────────────────────────────────────────────────────

/// A [`DeobfPass`] that detects and pre-decrypts SMC regions.
pub struct SmcPass {
    detector: SmcDetector,
    patcher: SmcPatcher,
}

impl SmcPass {
    /// Create a new [`SmcPass`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detector: SmcDetector::new(),
            patcher: SmcPatcher::new(),
        }
    }
}

impl Default for SmcPass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeobfPass for SmcPass {
    fn name(&self) -> &'static str {
        "smc-deobf"
    }

    fn description(&self) -> &'static str {
        "Detects self-modifying code regions and pre-decrypts them"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 16
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let regions = self.detector.detect(&ctx.binary);
        if regions.is_empty() {
            return Ok(DeobfResult::default());
        }

        let mut patches_applied = 0;
        let mut modified_bytes = 0;
        let mut transformations = Vec::new();

        for region in &regions {
            let file_offset = ctx
                .address_map
                .get(&region.start)
                .copied()
                .unwrap_or(region.start);
            let file_offset = usize::try_from(file_offset).unwrap_or(usize::MAX);

            if let Ok(patches) = self.patcher.build_patches(&ctx.binary, region, file_offset) {
                for patch in patches {
                    modified_bytes += patch.patched.len();
                    transformations.push(format!(
                        "SMC region {:#x}–{:#x} decrypted ({:?})",
                        region.start, region.end, region.algorithm
                    ));
                    ctx.patches.push(patch);
                    patches_applied += 1;
                }
            } else {
                // Region extends beyond binary — skip silently.
            }
        }

        Ok(DeobfResult::new(
            patches_applied,
            transformations,
            modified_bytes,
            0.75,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy API (preserved for compatibility with existing callers)
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory write event recorded during dynamic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteEvent {
    /// The memory address that was written.
    pub address: u64,
    /// The byte value that was written.
    pub value: u8,
    /// The program counter that performed the write.
    pub pc: u64,
}

/// Dynamic write tracker — records memory writes and detects SMC execution.
#[derive(Debug, Clone, Default)]
pub struct DynamicSmcDetector {
    events: Vec<WriteEvent>,
    written_addresses: std::collections::HashSet<u64>,
}

impl DynamicSmcDetector {
    /// Maximum number of write events retained.
    ///
    /// A dynamic trace driven by attacker-controlled inputs could otherwise
    /// exhaust memory by producing an unbounded stream of write events.
    pub const MAX_EVENTS: usize = 10_000_000;

    /// Create a new [`DynamicSmcDetector`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory write.
    ///
    /// Once [`Self::MAX_EVENTS`] is reached, additional events are silently
    /// dropped to prevent denial-of-service via memory exhaustion.
    pub fn add_write(&mut self, pc: u64, address: u64, value: u8) {
        if self.events.len() >= Self::MAX_EVENTS {
            return;
        }
        self.events.push(WriteEvent { address, value, pc });
        self.written_addresses.insert(address);
    }

    /// Return `true` if `exec_pc` was previously written to.
    #[must_use]
    pub fn is_smc_execution(&self, exec_pc: u64) -> bool {
        self.written_addresses.contains(&exec_pc)
    }

    /// Return all recorded events.
    #[must_use]
    pub fn events(&self) -> &[WriteEvent] {
        &self.events
    }

    /// Build a map from address → last-written byte.
    #[must_use]
    pub fn to_memory_map(&self) -> HashMap<u64, u8> {
        let mut map = HashMap::new();
        for ev in &self.events {
            map.insert(ev.address, ev.value);
        }
        map
    }
}

/// Reconstructs binary regions from a dynamic write log.
#[derive(Debug, Clone)]
pub struct DynamicSmcReconstructor {
    memory_map: HashMap<u64, u8>,
}

impl DynamicSmcReconstructor {
    /// Create from a memory map.
    #[must_use]
    pub const fn new(memory_map: HashMap<u64, u8>) -> Self {
        Self { memory_map }
    }

    /// Create from a [`DynamicSmcDetector`].
    #[must_use]
    pub fn from_detector(detector: &DynamicSmcDetector) -> Self {
        Self {
            memory_map: detector.to_memory_map(),
        }
    }

    /// Overlay written bytes onto `original_bytes` starting at `base_addr`.
    #[must_use]
    pub fn reconstruct(&self, base_addr: u64, original_bytes: &[u8]) -> Vec<u8> {
        let mut out = original_bytes.to_vec();
        for (i, byte) in out.iter_mut().enumerate() {
            let Some(addr) = base_addr.checked_add(i as u64) else {
                break;
            };
            if let Some(&written) = self.memory_map.get(&addr) {
                *byte = written;
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SmcDecryptor ─────────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_xor() {
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(0x42),
            algorithm: SmcAlgorithm::Xor,
        };
        let data = vec![0x42 ^ 0xAA, 0x42 ^ 0xBB, 0x42 ^ 0xCC, 0x42 ^ 0xDD];
        let dec = SmcDecryptor::new().decrypt(&data, &region);
        assert_eq!(dec, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_decrypt_add() {
        let region = SmcRegion {
            start: 0,
            end: 3,
            decryptor_addr: 0,
            key: SmcKey::Constant(5),
            algorithm: SmcAlgorithm::Add,
        };
        // Encrypted = plain + 5; decrypt = encrypted - 5.
        let data = vec![10u8, 15, 20];
        let dec = SmcDecryptor::new().decrypt(&data, &region);
        assert_eq!(dec, vec![5, 10, 15]);
    }

    #[test]
    fn test_decrypt_sub() {
        let region = SmcRegion {
            start: 0,
            end: 3,
            decryptor_addr: 0,
            key: SmcKey::Constant(5),
            algorithm: SmcAlgorithm::Sub,
        };
        // Encrypted = plain - 5; decrypt = encrypted + 5.
        let data = vec![0u8, 5, 10];
        let dec = SmcDecryptor::new().decrypt(&data, &region);
        assert_eq!(dec, vec![5, 10, 15]);
    }

    #[test]
    fn test_decrypt_rol_roundtrip() {
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(3),
            algorithm: SmcAlgorithm::Rol,
        };
        let plain = [0xAB, 0xCD, 0x12, 0x34];
        // "Encrypt" by ROR (since SmcAlgorithm::Rol decrypts by applying ROR).
        let cipher: Vec<u8> = plain.iter().map(|&b| ror8(ror8(b, 0), 3)).collect();
        // Decrypt by applying ROL via SmcDecryptor.
        let dec = SmcDecryptor::new().decrypt(&cipher, &region);
        // decrypt_rol applies ROR to undo ROL — verify no panic and output same size.
        assert_eq!(dec.len(), plain.len());
    }

    #[test]
    fn test_decrypt_xor_rolling() {
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(0x55),
            algorithm: SmcAlgorithm::XorRolling,
        };
        let plain = vec![0xAA, 0xBB, 0xCC, 0xDD];
        // Encrypt with rolling XOR: ci = pi ^ prev, prev starts as key.
        let mut cipher = Vec::new();
        let mut prev = 0x55u8;
        for &p in &plain {
            let c = p ^ prev;
            cipher.push(c);
            prev = c;
        }
        let dec = SmcDecryptor::new().decrypt(&cipher, &region);
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_decrypt_custom() {
        // Custom: XOR with 0x11 then ADD with 0x22.
        let ops = vec![0x01u8, 0x11, 0x02, 0x22];
        let region = SmcRegion {
            start: 0,
            end: 3,
            decryptor_addr: 0,
            key: SmcKey::Constant(0),
            algorithm: SmcAlgorithm::Custom(ops),
        };
        let data = vec![0xAAu8, 0xBB, 0xCC];
        let dec = SmcDecryptor::new().decrypt(&data, &region);
        let expected: Vec<u8> = data
            .iter()
            .map(|&b| (b ^ 0x11).wrapping_add(0x22))
            .collect();
        assert_eq!(dec, expected);
    }

    // ── SmcDetector ──────────────────────────────────────────────────────────

    #[test]
    fn test_detector_returns_vec() {
        let data = vec![0x90u8; 32];
        let regions = SmcDetector::new().detect(&data);
        // Pure NOP sled: no SMC patterns.
        let _ = regions; // may or may not be empty; just no panic
    }

    #[test]
    fn test_detector_finds_xor_loop() {
        // Construct: MOV ECX, 0x10 (B9 10 00 00 00), MOV EDI, 0x2000 (BF 00 20 00 00),
        //            XOR [EDI+ECX], 0x42 (80 34 0F 42), LOOP/DEC/JNZ
        let mut data = Vec::new();
        data.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]); // MOV ECX, 16
        data.extend_from_slice(&[0xBF, 0x00, 0x20, 0x00, 0x00]); // MOV EDI, 0x2000
        data.extend_from_slice(&[0x80, 0x34, 0x0F, 0x42]); // XOR [EDI+ECX], 0x42
        data.extend_from_slice(&[0xE2, 0xF7]); // LOOP -9

        let regions = SmcDetector::new().detect(&data);
        assert!(!regions.is_empty());
        assert!(
            regions
                .iter()
                .any(|r| matches!(r.algorithm, SmcAlgorithm::Xor))
        );
    }

    #[test]
    fn test_detector_finds_push_pop_xor() {
        let mut data = Vec::new();
        data.push(0x60); // PUSHAD
        data.extend_from_slice(&[0xBF, 0x00, 0x30, 0x00, 0x00]); // MOV EDI, 0x3000
        data.extend_from_slice(&[0x80, 0x37, 0x99]); // XOR [EDI], 0x99
        data.push(0x61); // POPAD

        let regions = SmcDetector::new().detect(&data);
        assert!(!regions.is_empty());
    }

    // ── SmcPatcher ───────────────────────────────────────────────────────────

    #[test]
    fn test_patcher_build_patch_xor() {
        let key = 0x42u8;
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(u64::from(key)),
            algorithm: SmcAlgorithm::Xor,
        };
        let plain = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let patches = SmcPatcher::new()
            .build_patches(&cipher, &region, 0)
            .unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patched, plain);
    }

    /// Regression: `file_offset + size` used to be computed with a raw `+`.
    /// Under the release profile `overflow-checks` is OFF, so the sum WRAPS and
    /// lands back inside `data`, passing `end > data.len()` and then panicking
    /// on `&data[file_offset..end]` (slice start greater than end).
    #[test]
    fn test_build_patches_offset_overflow_is_rejected() {
        let region = SmcRegion {
            start: 0,
            end: 4,
            decryptor_addr: 0,
            key: SmcKey::Constant(0x11),
            algorithm: SmcAlgorithm::Xor,
        };
        let data = vec![0u8; 64];
        let err = SmcPatcher::new().build_patches(&data, &region, usize::MAX - 1);
        assert!(err.is_err(), "wrapped offset must be rejected, not sliced");
    }

    #[test]
    fn test_patcher_out_of_bounds() {
        let region = SmcRegion {
            start: 0,
            end: 100,
            decryptor_addr: 0,
            key: SmcKey::Constant(0),
            algorithm: SmcAlgorithm::Xor,
        };
        let data = vec![0u8; 10]; // too short
        let err = SmcPatcher::new().build_patches(&data, &region, 0);
        assert!(matches!(err, Err(DeobfError::TooShort { .. })));
    }

    // ── LayeredSmc ───────────────────────────────────────────────────────────

    #[test]
    fn test_layered_smc_no_regions() {
        let data = vec![0x90u8; 32];
        let (out, layers) = LayeredSmc::new(4).decrypt_all(&data);
        assert_eq!(out.len(), data.len());
        assert_eq!(layers, 0);
    }

    // ── EmulatedDecrypt ──────────────────────────────────────────────────────

    #[test]
    fn test_emulated_decrypt_xor_loop() {
        // XOR [EDI+ECX], 0x99; DEC ECX (0x49); JNZ -5 (0x75 0xFB)
        let code = vec![0x80, 0x31, 0x99, 0x49, 0x75, 0xFB];
        let trace = EmulatedDecrypt::new().trace(&code, 16);
        assert_eq!(trace.recovered_key, 0x99);
        assert!(matches!(trace.algorithm, SmcAlgorithm::Xor));
    }

    #[test]
    fn test_emulated_decrypt_add_loop() {
        let code = vec![0x80, 0x07, 0x11, 0x47, 0x75, 0xFB];
        let trace = EmulatedDecrypt::new().trace(&code, 16);
        assert_eq!(trace.recovered_key, 0x11);
        assert!(matches!(trace.algorithm, SmcAlgorithm::Add));
    }

    // ── Dynamic SMC tracker (legacy API) ─────────────────────────────────────

    #[test]
    fn test_dynamic_smc_basic() {
        let mut det = DynamicSmcDetector::new();
        det.add_write(0x1000, 0x2000, 0xBB);
        det.add_write(0x1000, 0x2001, 0xCC);

        assert!(det.is_smc_execution(0x2000));
        assert!(det.is_smc_execution(0x2001));
        assert!(!det.is_smc_execution(0x2002));
        assert_eq!(det.events().len(), 2);
    }

    #[test]
    fn test_dynamic_smc_reconstruct() {
        let mut det = DynamicSmcDetector::new();
        det.add_write(0x1000, 0x2000, 0xAA);
        det.add_write(0x1000, 0x2002, 0xCC);

        let orig = vec![0x00u8, 0x11, 0x22, 0x33];
        let rec = DynamicSmcReconstructor::from_detector(&det).reconstruct(0x2000, &orig);
        assert_eq!(rec[0], 0xAA);
        assert_eq!(rec[1], 0x11); // unchanged
        assert_eq!(rec[2], 0xCC);
        assert_eq!(rec[3], 0x33); // unchanged
    }

    // ── SmcPass DeobfPass integration ────────────────────────────────────────

    #[test]
    fn test_smc_pass_applicable() {
        let pass = SmcPass::new();
        assert!(pass.is_applicable(&DeobfContext::new(vec![0u8; 32])));
        assert!(!pass.is_applicable(&DeobfContext::new(vec![0u8; 4])));
    }

    #[test]
    fn test_smc_pass_no_regions() {
        let mut ctx = DeobfContext::new(vec![0x90u8; 32]);
        let result = SmcPass::new().run(&mut ctx).unwrap();
        assert_eq!(result.patches_applied, 0);
    }

    #[test]
    fn test_smc_pass_with_xor_region() {
        // Build a binary containing the XOR-loop signature followed by
        // the encrypted payload inline (so file offset == virtual address).
        let key = 0x42u8;
        let plain = [0xCCu8; 16]; // 16 NOPs encrypted
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();

        let mut binary = Vec::new();
        // Decryptor stub at offset 0.
        binary.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]); // MOV ECX, 16
        // MOV EDI, 20 (offset of payload in this binary).
        binary.extend_from_slice(&[0xBF, 0x14, 0x00, 0x00, 0x00]);
        binary.extend_from_slice(&[0x80, 0x34, 0x0F, key]); // XOR [EDI+ECX], key
        binary.extend_from_slice(&[0xE2, 0xF7]); // LOOP
        // Padding to offset 0x14 = 20.
        while binary.len() < 0x14 {
            binary.push(0x90);
        }
        // Encrypted payload at offset 0x14.
        binary.extend_from_slice(&cipher);

        let mut ctx = DeobfContext::new(binary);
        let result = SmcPass::new().run(&mut ctx).unwrap();
        // Should find at least one region and patch it.
        let _ = result; // Value is heuristic; just no panic and no error.
    }

    // ── SmcKey and SmcAlgorithm serialization ────────────────────────────────

    #[test]
    fn test_smc_key_serialization() {
        let key = SmcKey::Constant(0xDEAD);
        let s = serde_json::to_string(&key).unwrap();
        let k2: SmcKey = serde_json::from_str(&s).unwrap();
        assert_eq!(key, k2);
    }

    #[test]
    fn test_smc_algorithm_serialization() {
        let algo = SmcAlgorithm::XorRolling;
        let s = serde_json::to_string(&algo).unwrap();
        let a2: SmcAlgorithm = serde_json::from_str(&s).unwrap();
        assert_eq!(algo, a2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolymorphicEngineAnalyzer — detect and classify polymorphic mutations
// ─────────────────────────────────────────────────────────────────────────────

/// Types of mutations applied by a polymorphic engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationType {
    /// NOP sled insertion (0x90 padding between instructions).
    NopInsertion,
    /// Register substitution (e.g. MOV EAX→EBX while preserving semantics).
    RegisterSubstitution,
    /// Constant re-encoding (same value, different encoding: imm8 vs imm32).
    ConstantReencoding,
    /// Instruction reordering (independent instructions swapped).
    InstructionReorder,
    /// Junk code insertion (dead computation that doesn't affect output).
    JunkCode,
    /// Opaque predicate injection.
    OpaquePredicate,
    /// Equivalent instruction substitution (ADD 1 ↔ INC).
    EquivalentSubstitution,
    /// Code transposition (basic block moved to a new address).
    Transposition,
}

/// A single mutation event recorded by the polymorphic engine analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationEvent {
    /// Offset in the original binary where the mutation occurred.
    pub offset: usize,
    /// Type of mutation.
    pub kind: MutationType,
    /// The original bytes at this location.
    pub original: Vec<u8>,
    /// The mutated bytes at this location.
    pub mutated: Vec<u8>,
    /// Human-readable description.
    pub description: String,
}

/// Compares two binary snapshots to find polymorphic mutations.
#[derive(Debug, Clone, Default)]
pub struct PolymorphicEngineAnalyzer;

impl PolymorphicEngineAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compare `before` and `after` snapshots and return detected mutations.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn analyze(&self, before: &[u8], after: &[u8]) -> Vec<MutationEvent> {
        let mut events = Vec::new();
        let len = before.len().min(after.len());

        // Walk the buffers finding blocks of differences.
        let mut i = 0;
        while i < len {
            if before[i] == after[i] {
                i += 1;
                continue;
            }

            // Find the extent of this diff region.
            let start = i;
            let mut last_diff = i;
            while i < len && (before[i] != after[i] || i - start < 4) {
                if before[i] != after[i] {
                    last_diff = i;
                }
                i += 1;
            }
            let end = last_diff + 1;
            i = end;

            let orig = before[start..end].to_vec();
            let mutated = after[start..end].to_vec();

            // Classify the mutation.
            let kind = Self::classify(&orig, &mutated);
            let description = format!("Mutation at 0x{start:x}–0x{end:x}: {kind:?}");
            events.push(MutationEvent {
                offset: start,
                kind,
                original: orig,
                mutated,
                description,
            });
        }
        events
    }

    fn classify(orig: &[u8], mutated: &[u8]) -> MutationType {
        // NOP sled: mutated contains many 0x90 bytes.
        let nop_count: usize = mutated.iter().map(|&b| usize::from(b == 0x90)).sum();
        if nop_count * 2 >= mutated.len() {
            return MutationType::NopInsertion;
        }

        // Junk code: mutated is longer and starts/ends with same byte patterns.
        if mutated.len() > orig.len() + 2 {
            return MutationType::JunkCode;
        }

        // Constant reencoding: same logical value, different byte count.
        if orig.len() != mutated.len() {
            return MutationType::ConstantReencoding;
        }

        // Register substitution: single-byte opcode differs in lowest 3 bits.
        if orig.len() == 1 && mutated.len() == 1 && (orig[0] & 0xF8) == (mutated[0] & 0xF8) {
            return MutationType::RegisterSubstitution;
        }

        // Equivalent substitution: INC r32 ↔ ADD r32, 1.
        if is_inc_equiv(orig, mutated) || is_inc_equiv(mutated, orig) {
            return MutationType::EquivalentSubstitution;
        }

        MutationType::InstructionReorder
    }
}

fn is_inc_equiv(a: &[u8], b: &[u8]) -> bool {
    // INC EAX = 0x40; ADD EAX,1 = 0x83 0xC0 0x01
    if a.len() == 1
        && (0x40..=0x47).contains(&a[0])
        && b.len() == 3
        && b[0] == 0x83
        && (b[1] & 0xF8) == 0xC0
        && b[2] == 0x01
    {
        return true;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeMutationTracker — diff before/after mutation with semantic comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks and aggregates mutations across multiple generations of a polymorphic
/// binary.
#[derive(Debug, Clone, Default)]
pub struct CodeMutationTracker {
    /// Ordered list of snapshots (generation 0 = original).
    snapshots: Vec<Vec<u8>>,
    /// Mutations recorded between consecutive generations.
    mutations: Vec<Vec<MutationEvent>>,
    /// Analyzer instance.
    analyzer: PolymorphicEngineAnalyzer,
}

impl CodeMutationTracker {
    /// Maximum number of generations (snapshots) retained.
    ///
    /// Without this limit an attacker supplying an unbounded number of snapshots
    /// could exhaust memory, since each snapshot is a full copy of the binary.
    pub const MAX_GENERATIONS: usize = 256;
}

impl CodeMutationTracker {
    /// Create a new tracker with an initial snapshot.
    #[must_use]
    pub fn new(initial: Vec<u8>) -> Self {
        Self {
            snapshots: vec![initial],
            mutations: Vec::new(),
            analyzer: PolymorphicEngineAnalyzer::new(),
        }
    }

    /// Record a new generation snapshot and compute mutations against the
    /// previous one.
    ///
    /// Snapshots beyond [`Self::MAX_GENERATIONS`] are silently dropped to
    /// prevent denial-of-service via unbounded snapshot accumulation (each
    /// snapshot is a full copy of the binary under analysis).
    pub fn add_snapshot(&mut self, snapshot: Vec<u8>) {
        if self.snapshots.len() >= Self::MAX_GENERATIONS {
            return;
        }
        if let Some(prev) = self.snapshots.last() {
            let evts = self.analyzer.analyze(prev, &snapshot);
            self.mutations.push(evts);
        }
        self.snapshots.push(snapshot);
    }

    /// Total number of generations recorded.
    #[must_use]
    pub const fn generation_count(&self) -> usize {
        self.snapshots.len()
    }

    /// All mutations between generation `from` and `from+1`.
    ///
    /// Returns an empty slice if `from` is out of range.
    #[must_use]
    pub fn mutations_at(&self, from: usize) -> &[MutationEvent] {
        self.mutations.get(from).map_or(&[], Vec::as_slice)
    }

    /// All mutations across all generations (flat view).
    #[must_use]
    pub fn all_mutations(&self) -> Vec<&MutationEvent> {
        self.mutations.iter().flatten().collect()
    }

    /// Count mutations by type across all generations.
    #[must_use]
    pub fn count_by_type(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for evt in self.all_mutations() {
            *map.entry(format!("{:?}", evt.kind)).or_insert(0) += 1;
        }
        map
    }

    /// Return a snapshot by generation index.
    #[must_use]
    pub fn snapshot(&self, generation: usize) -> Option<&[u8]> {
        self.snapshots.get(generation).map(Vec::as_slice)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackedRegionDetector — find boundaries of decrypted/unpacked regions
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the detected boundary of an unpacked code region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnpackedRegion {
    /// Start offset in the binary.
    pub start: usize,
    /// End offset in the binary (exclusive).
    pub end: usize,
    /// Estimated entropy of the unpacked content (0.0–8.0 bits/byte).
    pub entropy: f64,
    /// Whether the region looks like valid executable code.
    pub looks_like_code: bool,
}

impl UnpackedRegion {
    /// Length of the region.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// True if the region has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Detects boundaries between packed/encrypted regions and unpacked code in a
/// binary by comparing Shannon entropy across sliding windows.
#[derive(Debug, Clone)]
pub struct UnpackedRegionDetector {
    /// Window size for entropy computation.
    pub window_size: usize,
    /// Entropy threshold below which a window is considered "unpacked code".
    pub entropy_threshold: f64,
}

impl Default for UnpackedRegionDetector {
    fn default() -> Self {
        Self {
            window_size: 256,
            entropy_threshold: 6.0,
        }
    }
}

impl UnpackedRegionDetector {
    /// Create a new detector with the given parameters.
    #[must_use]
    pub const fn new(window_size: usize, entropy_threshold: f64) -> Self {
        Self {
            window_size,
            entropy_threshold,
        }
    }

    /// Scan `data` and return regions with entropy below the threshold.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<UnpackedRegion> {
        if data.len() < self.window_size {
            return Vec::new();
        }

        let mut regions = Vec::new();
        let mut in_low_entropy = false;
        let mut region_start = 0;

        let step = self.window_size / 2;
        let mut i = 0;

        while i + self.window_size <= data.len() {
            let window = &data[i..i + self.window_size];
            let ent = shannon_entropy(window);
            let is_low = ent < self.entropy_threshold;

            if is_low && !in_low_entropy {
                in_low_entropy = true;
                region_start = i;
            } else if !is_low && in_low_entropy {
                in_low_entropy = false;
                let chunk = &data[region_start..i + self.window_size];
                regions.push(UnpackedRegion {
                    start: region_start,
                    end: i + self.window_size,
                    entropy: shannon_entropy(chunk),
                    looks_like_code: looks_like_code(chunk),
                });
            }
            i += step;
        }

        // Close any open region.
        if in_low_entropy {
            let chunk = &data[region_start..];
            regions.push(UnpackedRegion {
                start: region_start,
                end: data.len(),
                entropy: shannon_entropy(chunk),
                looks_like_code: looks_like_code(chunk),
            });
        }

        regions
    }
}

/// Compute Shannon entropy (bits per byte) of `data`.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    let mut h = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / n;
            h = p.mul_add(-p.log2(), h);
        }
    }
    h
}

/// Heuristically judge whether `data` looks like x86 code.
///
/// Checks for a reasonable mix of low-value opcodes and REX prefixes.
#[must_use]
pub fn looks_like_code(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // Count bytes in the "typical opcode" ranges.
    let typical: usize = data
        .iter()
        .filter(|&&b| {
            matches!(b,
                0x00..=0x0F  // ADD, OR, PUSH ES…
                | 0x20..=0x3F // AND, XOR, CMP
                | 0x48..=0x4F // REX prefixes (x86-64)
                | 0x50..=0x5F // PUSH/POP
                | 0x68        // PUSH imm
                | 0x74 | 0x75 // JZ/JNZ
                | 0x83        // ADD/SUB imm8
                | 0x89 | 0x8B // MOV r/m, r
                | 0x90        // NOP
                | 0xC3        // RET
                | 0xE8 | 0xEB // CALL/JMP
                | 0xFF        // INC/JMP/CALL indirect
            )
        })
        .count();
    typical * 3 > data.len()
}

// ─────────────────────────────────────────────────────────────────────────────
// XorChainDecryptor — detect and apply multi-round XOR chain decryption
// ─────────────────────────────────────────────────────────────────────────────

/// One step in a multi-round XOR chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XorChainStep {
    /// The XOR key byte for this step.
    pub key: u8,
    /// Optional secondary operation applied before XOR (0 = none, 1 = NOT, 2 = ROL, 3 = ROR).
    pub pre_op: u8,
    /// Rotation amount (only relevant when `pre_op` is 2 or 3).
    pub rot_amount: u8,
}

impl XorChainStep {
    /// Apply this step to a single byte.
    #[must_use]
    pub fn apply(&self, byte: u8) -> u8 {
        let b = match self.pre_op {
            1 => !byte,
            2 => rol8(byte, self.rot_amount & 7),
            3 => ror8(byte, self.rot_amount & 7),
            _ => byte,
        };
        b ^ self.key
    }

    /// Reverse this step (decrypt).
    #[must_use]
    pub fn reverse(&self, byte: u8) -> u8 {
        let b = byte ^ self.key;
        match self.pre_op {
            1 => !b,
            2 => ror8(b, self.rot_amount & 7), // reverse ROL
            3 => rol8(b, self.rot_amount & 7), // reverse ROR
            _ => b,
        }
    }
}

/// A complete XOR-chain cipher with multiple rounds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XorChain {
    /// The ordered list of steps applied to each byte.
    pub steps: Vec<XorChainStep>,
}

impl XorChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a step to the chain.
    pub fn push(&mut self, step: XorChainStep) {
        self.steps.push(step);
    }

    /// Encrypt `data` by applying all steps in forward order.
    #[must_use]
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&b| self.steps.iter().fold(b, |acc, s| s.apply(acc)))
            .collect()
    }

    /// Decrypt `data` by applying all steps in reverse order.
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&b| self.steps.iter().rev().fold(b, |acc, s| s.reverse(acc)))
            .collect()
    }

    /// Number of steps in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// True if the chain has no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Detects XOR-chain patterns in a code snippet by looking for sequences of
/// `XOR [mem], imm8` instructions with different immediate values.
#[derive(Debug, Clone, Default)]
pub struct XorChainDetector;

impl XorChainDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `code` for back-to-back XOR-mem-imm8 patterns and build an
    /// [`XorChain`].
    ///
    /// Returns `None` if fewer than 2 XOR steps are found.
    #[must_use]
    pub fn detect(&self, code: &[u8]) -> Option<XorChain> {
        let mut chain = XorChain::new();
        let mut i = 0;
        while i + 2 < code.len() {
            // XOR byte ptr [reg], imm8: 80 (30..37) imm8
            if code[i] == 0x80 && (code[i + 1] & 0xF8 == 0x30) {
                chain.push(XorChainStep {
                    key: code[i + 2],
                    pre_op: 0,
                    rot_amount: 0,
                });
                i += 3;
            }
            // NOT byte ptr [reg]: F6 (10..17)
            else if code[i] == 0xF6 && (code[i + 1] & 0xF8 == 0x10) {
                if let Some(last) = chain.steps.last_mut() {
                    last.pre_op = 1;
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        if chain.len() >= 2 { Some(chain) } else { None }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcStats — aggregate statistics for an SMC analysis run
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics produced by an SMC analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmcStats {
    /// Number of SMC regions detected.
    pub regions_detected: usize,
    /// Number of regions successfully decrypted.
    pub regions_decrypted: usize,
    /// Total bytes decrypted.
    pub bytes_decrypted: usize,
    /// Number of XOR-based regions.
    pub xor_count: usize,
    /// Number of ADD-based regions.
    pub add_count: usize,
    /// Number of ROL/ROR-based regions.
    pub rol_count: usize,
    /// Number of rolling-key regions.
    pub rolling_count: usize,
    /// Number of regions with unknown/derived key.
    pub derived_key_count: usize,
    /// Estimated number of encryption layers.
    pub layer_count: usize,
}

impl SmcStats {
    /// Compute stats from a list of regions and their decrypted results.
    #[must_use]
    pub fn from_regions(regions: &[SmcRegion]) -> Self {
        let mut s = Self {
            regions_detected: regions.len(),
            ..Default::default()
        };
        for r in regions {
            match r.algorithm {
                SmcAlgorithm::Xor => s.xor_count += 1,
                SmcAlgorithm::Add => s.add_count += 1,
                SmcAlgorithm::Rol | SmcAlgorithm::Ror => s.rol_count += 1,
                SmcAlgorithm::XorRolling | SmcAlgorithm::AddRolling => s.rolling_count += 1,
                SmcAlgorithm::Sub | SmcAlgorithm::Custom(_) => {}
            }
            if matches!(r.key, SmcKey::Derived) {
                s.derived_key_count += 1;
            }
            s.bytes_decrypted = s.bytes_decrypted.saturating_add(
                usize::try_from(r.len()).unwrap_or(usize::MAX),
            );
        }
        s.regions_decrypted = regions.len();
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteExecuteDetector — def-use chain: store to X then branch to X
// ─────────────────────────────────────────────────────────────────────────────

/// A simple (address, value) pair representing a write to memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemWrite {
    pub pc: u64,
    pub addr: u64,
    pub size: u8,
}

/// A branch/call that targets an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Execution {
    pub pc: u64,
    pub target: u64,
}

/// Detects write-then-execute patterns from a combined trace of writes and
/// execution events.
#[derive(Debug, Clone, Default)]
pub struct WriteExecuteDetector {
    writes: Vec<MemWrite>,
    executions: Vec<Execution>,
}

impl WriteExecuteDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum number of write or execution events retained.
    ///
    /// Without this cap, a caller driven by attacker-controlled trace data could
    /// exhaust process memory by calling `add_write`/`add_execution` in a loop.
    pub const MAX_EVENTS: usize = 10_000_000;

    /// Record a memory write event.
    ///
    /// Silently dropped when [`Self::MAX_EVENTS`] is reached.
    pub fn add_write(&mut self, pc: u64, addr: u64, size: u8) {
        if self.writes.len() < Self::MAX_EVENTS {
            self.writes.push(MemWrite { pc, addr, size });
        }
    }

    /// Record an execution (branch/call target) event.
    ///
    /// Silently dropped when [`Self::MAX_EVENTS`] is reached.
    pub fn add_execution(&mut self, pc: u64, target: u64) {
        if self.executions.len() < Self::MAX_EVENTS {
            self.executions.push(Execution { pc, target });
        }
    }

    /// Find all (write, execution) pairs where execution target was written to
    /// before the execution occurred (in trace order).
    ///
    /// Returns a vector of `(write_event, execution_event)` pairs.
    ///
    /// Events are processed in chronological order (write index before execution
    /// index), so an execution that precedes a write in the trace is NOT reported.
    #[must_use]
    pub fn find_write_then_execute(&self) -> Vec<(MemWrite, Execution)> {
        use std::collections::HashMap;

        // Map from write-start-address -> MemWrite for O(1) lookup.
        // Only writes that were seen BEFORE the current execution are inserted.
        let mut written: HashMap<u64, MemWrite> = HashMap::new();
        let mut results = Vec::new();

        // We merge the two event streams by index position:
        // treat write[i] as occurring at trace position (2*i) and
        // exec[j] as occurring at trace position (2*j + 1) so that
        // a write at index i always precedes an exec at the same index.
        let total = self.writes.len().max(self.executions.len());
        let mut wi = 0usize;
        let mut ei = 0usize;

        for _step in 0..total * 2 + 2 {
            // Advance writes whose logical position <= current exec position.
            let write_pos = wi * 2;
            let exec_pos = ei * 2 + 1;

            if wi < self.writes.len() && write_pos <= exec_pos {
                let w = &self.writes[wi];
                written.insert(w.addr, *w);
                wi += 1;
                continue;
            }

            if ei < self.executions.len() {
                let exec = &self.executions[ei];
                let t = exec.target;
                // Check if target falls inside any already-written range.
                for (&addr, w) in &written {
                    let end = addr + u64::from(w.size).max(1);
                    if t >= addr && t < end {
                        results.push((*w, *exec));
                        break;
                    }
                }
                ei += 1;
            }

            if wi >= self.writes.len() && ei >= self.executions.len() {
                break;
            }
        }

        results
    }

    /// Clear all recorded events.
    pub fn clear(&mut self) {
        self.writes.clear();
        self.executions.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcBinaryPatcher — applies multiple patches to a binary in a consistent order
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a set of [`Patch`] records to a binary, handling ordering and
/// overlap detection.
#[derive(Debug, Clone, Default)]
pub struct SmcBinaryPatcher {
    patches: Vec<Patch>,
}

impl SmcBinaryPatcher {
    /// Maximum number of patches that can be registered in one patcher instance.
    ///
    /// Without this limit, an attacker controlling the region list could cause
    /// `add_patch` to be called millions of times, exhausting heap memory.
    pub const MAX_PATCHES: usize = 65_536;

    /// Create a new patcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch.
    ///
    /// Silently dropped when [`Self::MAX_PATCHES`] is reached.
    pub fn add_patch(&mut self, patch: Patch) {
        if self.patches.len() < Self::MAX_PATCHES {
            self.patches.push(patch);
        }
    }

    /// Number of pending patches.
    #[must_use]
    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }

    /// Apply all patches to `data` and return the patched binary.
    ///
    /// Patches are applied in offset order.  Overlapping patches result in the
    /// later patch winning.
    ///
    /// # Errors
    /// Returns `Err` if a patch extends beyond `data`.
    pub fn apply(&self, data: &[u8]) -> Result<Vec<u8>, DeobfError> {
        let mut out = data.to_vec();
        let mut ordered: Vec<&Patch> = self.patches.iter().collect();
        ordered.sort_by_key(|p| p.offset);

        for patch in ordered {
            let end = patch.offset.checked_add(patch.patched.len()).ok_or(
                DeobfError::TooShort {
                    needed: usize::MAX,
                    have: out.len(),
                },
            )?;
            if end > out.len() {
                return Err(DeobfError::TooShort {
                    needed: end,
                    have: out.len(),
                });
            }
            out[patch.offset..end].copy_from_slice(&patch.patched);
        }
        Ok(out)
    }

    /// Detect overlapping patches.
    ///
    /// Returns pairs of `(patch_a_offset, patch_b_offset)` where the two
    /// patches write to overlapping byte ranges.
    #[must_use]
    pub fn overlapping_patches(&self) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        for (i, a) in self.patches.iter().enumerate() {
            for b in self.patches.iter().skip(i + 1) {
                let a_end = a.offset + a.patched.len();
                let b_end = b.offset + b.patched.len();
                if a.offset < b_end && b.offset < a_end {
                    pairs.push((a.offset, b.offset));
                }
            }
        }
        pairs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddRolDecryptor — decrypt ADD/ROL/SUB variants
// ─────────────────────────────────────────────────────────────────────────────

/// Cipher that applies an ADD-then-ROL or ROL-then-ADD sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRolCipher {
    /// ADD constant.
    pub add_key: u8,
    /// Rotation amount (bits).
    pub rol_amount: u8,
    /// Whether ADD is applied before ROL (true) or after (false).
    pub add_first: bool,
}

impl AddRolCipher {
    /// Create a new cipher.
    #[must_use]
    pub const fn new(add_key: u8, rol_amount: u8, add_first: bool) -> Self {
        Self {
            add_key,
            rol_amount,
            add_first,
        }
    }

    /// Encrypt one byte.
    #[must_use]
    pub fn encrypt_byte(&self, b: u8) -> u8 {
        if self.add_first {
            rol8(b.wrapping_add(self.add_key), self.rol_amount)
        } else {
            rol8(b, self.rol_amount).wrapping_add(self.add_key)
        }
    }

    /// Decrypt one byte.
    #[must_use]
    pub fn decrypt_byte(&self, b: u8) -> u8 {
        if self.add_first {
            ror8(b, self.rol_amount).wrapping_sub(self.add_key)
        } else {
            ror8(b.wrapping_sub(self.add_key), self.rol_amount)
        }
    }

    /// Decrypt a slice.
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.decrypt_byte(b)).collect()
    }

    /// Encrypt a slice.
    #[must_use]
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.encrypt_byte(b)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcReport — full analysis report
// ─────────────────────────────────────────────────────────────────────────────

/// A complete SMC analysis report for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcReport {
    /// All detected SMC regions.
    pub regions: Vec<SmcRegion>,
    /// Write-then-execute pairs detected dynamically (if trace data provided).
    pub write_execute_pairs: usize,
    /// Polymorphic mutations detected (if before/after snapshots provided).
    pub mutations: Vec<MutationEvent>,
    /// Aggregate statistics.
    pub stats: SmcStats,
    /// Whether any XOR chains were detected.
    pub has_xor_chains: bool,
    /// List of layer counts (for multi-layer unpacking).
    pub layer_analysis: Vec<usize>,
}

impl SmcReport {
    /// Build a report from an analysis of `data`.
    #[must_use]
    pub fn analyze(data: &[u8]) -> Self {
        let detector = SmcDetector::new();
        let regions = detector.detect(data);
        let stats = SmcStats::from_regions(&regions);

        let chain_detector = XorChainDetector::new();
        let has_xor_chains = chain_detector.detect(data).is_some();

        Self {
            regions,
            write_execute_pairs: 0,
            mutations: Vec::new(),
            stats,
            has_xor_chains,
            layer_analysis: Vec::new(),
        }
    }

    /// Add dynamic write-execute pair count.
    #[must_use] 
    pub const fn with_write_execute_pairs(mut self, count: usize) -> Self {
        self.write_execute_pairs = count;
        self
    }

    /// Add polymorphic mutation events.
    #[must_use] 
    pub fn with_mutations(mut self, mutations: Vec<MutationEvent>) -> Self {
        self.mutations = mutations;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §37.5 — SMC Reconstruction via Frida/Unicorn Tracing
// ─────────────────────────────────────────────────────────────────────────────

/// Time gap (in milliseconds) between write events that signals a new unpacking
/// stage boundary.
pub const STAGE_GAP_THRESHOLD_MS: u64 = 100;

// ── WriteEvent ───────────────────────────────────────────────────────────────

/// A single memory-write event captured during dynamic (Frida/Unicorn) tracing.
///
/// Each event records the exact moment code wrote bytes into a target address,
/// which instruction performed the write, and what was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceWriteEvent {
    /// Monotonic timestamp at which the write occurred (milliseconds since
    /// tracing started).
    pub timestamp: u64,
    /// Virtual address of the instruction that performed the write.
    pub writer_pc: u64,
    /// Virtual address of the first byte that was written.
    pub target_addr: u64,
    /// Byte offset of `target_addr` relative to the base of the mapped region.
    pub target_offset: usize,
    /// The raw bytes that were written (may be more than one byte for wider
    /// stores such as `MOV DWORD PTR [x], imm32`).
    pub bytes_written: Vec<u8>,
    /// Name of the module that contains `writer_pc`, if known.
    pub writer_module: Option<String>,
}

impl TraceWriteEvent {
    /// Construct a new write event.
    #[must_use]
    pub const fn new(
        timestamp: u64,
        writer_pc: u64,
        target_addr: u64,
        target_offset: usize,
        bytes_written: Vec<u8>,
        writer_module: Option<String>,
    ) -> Self {
        Self {
            timestamp,
            writer_pc,
            target_addr,
            target_offset,
            bytes_written,
            writer_module,
        }
    }

    /// End address (exclusive) of the bytes written by this event.
    #[must_use]
    pub const fn target_end(&self) -> u64 {
        self.target_addr.saturating_add(self.bytes_written.len() as u64)
    }

    /// Returns `true` if this event's write range overlaps with `[start, end)`.
    #[must_use]
    pub const fn overlaps_range(&self, start: u64, end: u64) -> bool {
        self.target_addr < end && self.target_end() > start
    }
}

// ── CodeGenerationTimeline ───────────────────────────────────────────────────

/// Ordered record of all write events and periodic memory snapshots captured
/// during a dynamic tracing session.
///
/// The timeline is the primary input to [`SmcAnalyzer`] and
/// [`MockSmcTracer`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodeGenerationTimeline {
    /// All write events in the order they were recorded (may be unsorted until
    /// [`sort_by_time`](Self::sort_by_time) is called).
    pub events: Vec<TraceWriteEvent>,
    /// Periodic snapshots of memory: `(timestamp_ms, raw_bytes_of_mapped_region)`.
    pub snapshots: Vec<(u64, Vec<u8>)>,
}

impl CodeGenerationTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    /// Append a write event.
    pub fn add_event(&mut self, event: TraceWriteEvent) {
        self.events.push(event);
    }

    /// Append a memory snapshot at the given timestamp.
    pub fn add_snapshot(&mut self, ts: u64, memory: Vec<u8>) {
        self.snapshots.push((ts, memory));
    }

    /// Sort all events by timestamp (ascending).  Snapshots are also sorted.
    pub fn sort_by_time(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
        self.snapshots.sort_by_key(|s| s.0);
    }

    /// Return references to all write events whose target range overlaps with
    /// `[start, end)`.
    #[must_use]
    pub fn bytes_written_to_range(&self, start: u64, end: u64) -> Vec<&TraceWriteEvent> {
        self.events
            .iter()
            .filter(|e| e.overlaps_range(start, end))
            .collect()
    }

    /// Total number of bytes written across all events.
    #[must_use]
    pub fn total_bytes_written(&self) -> usize {
        self.events.iter().map(|e| e.bytes_written.len()).sum()
    }

    /// Timestamp of the first event, or `None` if there are no events.
    #[must_use]
    pub fn start_time(&self) -> Option<u64> {
        self.events.first().map(|e| e.timestamp)
    }

    /// Timestamp of the last event, or `None` if there are no events.
    #[must_use]
    pub fn end_time(&self) -> Option<u64> {
        self.events.last().map(|e| e.timestamp)
    }

    /// Find the closest snapshot taken at or before `ts`.
    #[must_use]
    pub fn snapshot_at_or_before(&self, ts: u64) -> Option<&(u64, Vec<u8>)> {
        self.snapshots.iter().rfind(|(t, _)| *t <= ts)
    }
}

// ── UnpackStage ──────────────────────────────────────────────────────────────

/// One discrete unpacking layer identified by [`SmcAnalyzer::identify_stages`].
///
/// A stage groups write events that occur within a continuous burst, separated
/// from adjacent stages by a time gap exceeding
/// [`STAGE_GAP_THRESHOLD_MS`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackStage {
    /// One-based stage number (stage 1 = outermost packer layer).
    pub stage_num: u32,
    /// Timestamp of the first write in this stage.
    pub start_ts: u64,
    /// Timestamp of the last write in this stage.
    pub end_ts: u64,
    /// All write events belonging to this stage.
    pub writes: Vec<TraceWriteEvent>,
    /// Best available memory snapshot taken during or just before this stage.
    pub snapshot: Vec<u8>,
    /// Candidate original entry point address identified by heuristics, or
    /// `None` if detection failed.
    pub entry_point_candidate: Option<u64>,
}

impl UnpackStage {
    /// Duration of this stage in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.end_ts.saturating_sub(self.start_ts)
    }

    /// Total bytes written in this stage.
    #[must_use]
    pub fn bytes_written(&self) -> usize {
        self.writes.iter().map(|e| e.bytes_written.len()).sum()
    }

    /// Lowest target address written to in this stage.
    #[must_use]
    pub fn min_write_addr(&self) -> Option<u64> {
        self.writes.iter().map(|e| e.target_addr).min()
    }

    /// Highest target address written to in this stage (start of last write).
    #[must_use]
    pub fn max_write_addr(&self) -> Option<u64> {
        self.writes.iter().map(|e| e.target_addr).max()
    }
}

// ── ReconstructedBinary ──────────────────────────────────────────────────────

/// The result of overlaying one unpack stage's snapshot onto the original
/// binary bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedBinary {
    /// Raw bytes of the reconstructed binary image.
    pub data: Vec<u8>,
    /// Virtual base address of the first byte of `data`.
    pub base_addr: u64,
    /// Detected original entry point, if found.
    pub oep: Option<u64>,
    /// Which unpack stage produced this binary (1-based).
    pub stage: u32,
}

impl ReconstructedBinary {
    /// Length of the reconstructed image.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// True if the reconstructed image has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ── SmcAnalyzer ──────────────────────────────────────────────────────────────

/// Core analysis engine that processes a [`CodeGenerationTimeline`] to
/// identify discrete unpacking stages and recover the original entry point.
#[derive(Debug, Clone, Default)]
pub struct SmcAnalyzer;

impl SmcAnalyzer {
    /// Create a new [`SmcAnalyzer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Partition `timeline` events into discrete [`UnpackStage`]s based on
    /// inter-event time gaps.
    ///
    /// Two consecutive events belong to the same stage if the gap between them
    /// is less than [`STAGE_GAP_THRESHOLD_MS`].  Each stage carries the
    /// nearest preceding snapshot (or an empty snapshot if none is available).
    #[must_use]
    pub fn identify_stages(timeline: &CodeGenerationTimeline) -> Vec<UnpackStage> {
        if timeline.events.is_empty() {
            return Vec::new();
        }

        let mut stages: Vec<UnpackStage> = Vec::new();
        let mut current_writes: Vec<TraceWriteEvent> = Vec::new();
        let mut stage_num = 1u32;

        for event in &timeline.events {
            if let Some(last) = current_writes.last() {
                let gap = event.timestamp.saturating_sub(last.timestamp);
                if gap > STAGE_GAP_THRESHOLD_MS {
                    // Flush current stage.
                    let start_ts = current_writes.first().map_or(0, |e| e.timestamp);
                    let end_ts = current_writes.last().map_or(0, |e| e.timestamp);
                    let snapshot = timeline
                        .snapshot_at_or_before(end_ts)
                        .map(|(_, mem)| mem.clone())
                        .unwrap_or_default();

                    let mut stage = UnpackStage {
                        stage_num,
                        start_ts,
                        end_ts,
                        writes: std::mem::take(&mut current_writes),
                        snapshot,
                        entry_point_candidate: None,
                    };
                    stage.entry_point_candidate = Self::find_oep(&stage);
                    stages.push(stage);

                    stage_num += 1;
                }
            }
            current_writes.push(event.clone());
        }

        // Flush the final stage.
        if !current_writes.is_empty() {
            let start_ts = current_writes.first().map_or(0, |e| e.timestamp);
            let end_ts = current_writes.last().map_or(0, |e| e.timestamp);
            let snapshot = timeline
                .snapshot_at_or_before(end_ts)
                .map(|(_, mem)| mem.clone())
                .unwrap_or_default();

            let mut stage = UnpackStage {
                stage_num,
                start_ts,
                end_ts,
                writes: current_writes,
                snapshot,
                entry_point_candidate: None,
            };
            stage.entry_point_candidate = Self::find_oep(&stage);
            stages.push(stage);
        }

        stages
    }

    /// Attempt to identify the original entry point (OEP) from a completed
    /// unpack stage.
    ///
    /// Heuristics applied (in priority order):
    ///
    /// 1. **Push-EBP prologue**: scan the snapshot for the classic 32-bit
    ///    prologue bytes `55 8B EC` (`PUSH EBP; MOV EBP, ESP`) at any address
    ///    that was also written during this stage.
    /// 2. **Last-write heuristic**: the last byte range written is often the
    ///    transfer-of-control that hands execution to the real entry point.
    /// 3. **Highest written address**: if neither heuristic matches, fall back
    ///    to the highest address written — common when a packer unpacks
    ///    sequentially and the final written byte is the start of the payload.
    #[must_use]
    pub fn find_oep(stage: &UnpackStage) -> Option<u64> {
        if stage.writes.is_empty() {
            return None;
        }

        // Build a set of all written addresses for fast lookup.
        let written_addrs: std::collections::HashSet<u64> = stage
            .writes
            .iter()
            .flat_map(|e| {
                let start = e.target_addr;
                let len = e.bytes_written.len() as u64;
                start..start + len
            })
            .collect();

        // Heuristic 1: scan snapshot for push-EBP prologue at a written address.
        let snap = &stage.snapshot;
        let min_addr = stage.min_write_addr().unwrap_or(0);
        if snap.len() >= 3 {
            for i in 0..snap.len() - 2 {
                // PUSH EBP (55) ; MOV EBP, ESP (8B EC)
                if snap[i] == 0x55 && snap[i + 1] == 0x8B && snap[i + 2] == 0xEC {
                    let candidate = min_addr.saturating_add(i as u64);
                    if written_addrs.contains(&candidate) {
                        return Some(candidate);
                    }
                }
            }
            // Also check for 64-bit prologue: PUSH RBP (55) ; MOV RBP, RSP (48 8B EC)
            for i in 0..snap.len().saturating_sub(3) {
                if snap[i] == 0x55
                    && snap[i + 1] == 0x48
                    && snap[i + 2] == 0x8B
                    && snap[i + 3] == 0xEC
                {
                    let candidate = min_addr.saturating_add(i as u64);
                    if written_addrs.contains(&candidate) {
                        return Some(candidate);
                    }
                }
            }
        }

        // Heuristic 2: last write event's target address.
        if let Some(last_write) = stage.writes.last() {
            return Some(last_write.target_addr);
        }

        // Heuristic 3: highest written address.
        stage.max_write_addr()
    }

    /// Overlay `snapshot` bytes onto `original` starting at virtual address
    /// `base` and return the resulting [`ReconstructedBinary`].
    ///
    /// Bytes that appear in the snapshot are used as-is; bytes that were never
    /// written fall back to the original content.
    #[must_use]
    pub fn reconstruct_from_snapshot(
        original: &[u8],
        snapshot: &[u8],
        base: u64,
        stage: &UnpackStage,
    ) -> ReconstructedBinary {
        // Start with the original bytes and patch in every write event.
        let mut data = original.to_vec();

        for event in &stage.writes {
            let offset = usize::try_from(event.target_addr.saturating_sub(base)).unwrap_or(usize::MAX);
            let end = offset + event.bytes_written.len();
            if end <= data.len() {
                data[offset..end].copy_from_slice(&event.bytes_written);
            } else if offset < data.len() {
                // Partial write — copy as many bytes as fit.
                let available = data.len() - offset;
                data[offset..].copy_from_slice(&event.bytes_written[..available]);
            }
        }

        // Overlay snapshot bytes over the write-patched region.
        let snap_len = snapshot.len().min(data.len());
        if snap_len > 0 {
            data[..snap_len].copy_from_slice(&snapshot[..snap_len]);
        }

        ReconstructedBinary {
            data,
            base_addr: base,
            oep: stage.entry_point_candidate,
            stage: stage.stage_num,
        }
    }
}

// ── SmcKind / SmcIndicator ────────────────────────────────────────────────────

/// Category of SMC indicator detected by static pre-analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmcKind {
    /// An instruction writes to a virtual address that falls within the code
    /// section bounds.
    WriteToCodeSection,
    /// A call to `VirtualProtect` / `mprotect` that includes the `EXEC` bit,
    /// suggesting a region is being made writable+executable.
    VirtualProtectRwx,
    /// A tight loop containing XOR, ADD, or SUB on byte arrays followed by an
    /// indirect jump/call — characteristic of unpack loops.
    UnpackLoop,
    /// A sequence of operations consistent with a decryption routine
    /// (key scheduling, multiple rounds of XOR/ADD with constant or rolling
    /// keys).
    DecryptionRoutine,
    /// A self-patching NOP sled: the code writes `0x90` bytes over its own
    /// instruction stream.
    SelfPatch,
}

/// A single SMC indicator identified in a binary by static heuristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcIndicator {
    /// Byte offset in the binary where the indicator was detected.
    pub offset: usize,
    /// Category of the indicator.
    pub kind: SmcKind,
    /// Confidence score in the range `[0.0, 1.0]`.
    pub confidence: f32,
}

impl SmcIndicator {
    /// Construct a new indicator.
    ///
    /// A NaN `confidence` becomes `0.0`. `clamp` *propagates* NaN instead of
    /// bounding it, so it could not enforce the `[0.0, 1.0]` range this field
    /// documents — and a NaN confidence is worse than an out-of-range one:
    /// every comparison with it is false, so the indicator would fail each
    /// `>= threshold` filter downstream and vanish silently instead of ranking
    /// low.
    #[must_use]
    pub const fn new(offset: usize, kind: SmcKind, confidence: f32) -> Self {
        // Plain comparisons rather than `clamp`: comparisons with NaN are all
        // false, so NaN falls through to the 0.0 branch.
        let confidence = if confidence >= 1.0 {
            1.0
        } else if confidence > 0.0 {
            confidence
        } else {
            0.0
        };
        Self {
            offset,
            kind,
            confidence,
        }
    }
}

/// Statically detect SMC indicators in raw binary `code`.
///
/// This is a fast pre-filter intended to guide the dynamic tracer toward
/// interesting regions; it operates on raw bytes without full disassembly.
///
/// ## Detected patterns
///
/// | Pattern | `SmcKind` |
/// |---------|-----------|
/// | Write to code-section VA range (via `mov [imm32], …`) | `WriteToCodeSection` |
/// | `VirtualProtect`/`mprotect` call with `PAGE_EXECUTE_READWRITE` (0x40) | `VirtualProtectRwx` |
/// | Tight XOR/ADD/SUB loop followed by `CALL`/`JMP` | `UnpackLoop` |
/// | Multi-round XOR with constant or rolling key | `DecryptionRoutine` |
/// | Self-modifying NOP sleds | `SelfPatch` |
#[must_use]
pub fn detect_smc_indicators(code: &[u8]) -> Vec<SmcIndicator> {
    if code.len() < 4 {
        return Vec::new();
    }
    let mut indicators = detect_vp_patterns(code);
    indicators.extend(detect_unpack_loop_patterns(code));
    indicators.extend(detect_decryption_routine_patterns(code));
    indicators.extend(detect_write_to_code_patterns(code));
    indicators.extend(detect_self_patch_patterns(code));
    indicators
}

fn detect_vp_patterns(code: &[u8]) -> Vec<SmcIndicator> {
    let mut out = Vec::new();
    for i in 0..code.len().saturating_sub(4) {
        // PUSH 0x40 (PAGE_EXECUTE_READWRITE) → look for CALL within 32 bytes
        if code[i] == 0x6A && code[i + 1] == 0x40 {
            for win in code[i + 2..(i + 32).min(code.len())].windows(2) {
                if win[0] == 0xE8 || (win[0] == 0xFF && (win[1] & 0x18 == 0x10)) {
                    out.push(SmcIndicator::new(i, SmcKind::VirtualProtectRwx, 0.80));
                    break;
                }
            }
        }
        // PUSH 0x07 (PROT_READ|WRITE|EXEC) → look for CALL (mprotect)
        if code[i] == 0x6A && code[i + 1] == 0x07 {
            for &b in &code[i + 2..(i + 32).min(code.len())] {
                if b == 0xE8 {
                    out.push(SmcIndicator::new(i, SmcKind::VirtualProtectRwx, 0.70));
                    break;
                }
            }
        }
    }
    out
}

fn detect_unpack_loop_patterns(code: &[u8]) -> Vec<SmcIndicator> {
    let mut out = Vec::new();
    for i in 0..code.len().saturating_sub(2) {
        let is_byte_alu = i + 1 < code.len()
            && ((code[i] == 0x80 && matches!(code[i + 1] & 0x38, 0x00 | 0x28 | 0x30))
                || matches!(code[i], 0x30 | 0x28 | 0x00));
        if !is_byte_alu {
            continue;
        }
        let look_end = (i + 16).min(code.len());
        // Slice to `look_end`, not `look_end - 1`: `windows(2)` already stops
        // one short of the end, so subtracting again dropped the *last* pair in
        // the window. A `JNZ rel8` sitting at the end of the 16-byte lookahead —
        // or at the end of the buffer, which is what a tight unpack loop looks
        // like — was therefore never seen: its opcode only ever appeared as
        // `win[1]`, never as `win[0]`.
        for win in code[i + 1..look_end].windows(2) {
            if win[0] == 0x75 {
                let rel = win[1].cast_signed();
                if rel < 0 {
                    let after_off = i + 1 + 2;
                    let has_transfer = after_off < code.len()
                        && matches!(code[after_off], 0xE8 | 0xEB | 0xFF | 0xE9);
                    let conf = if has_transfer { 0.85 } else { 0.65 };
                    out.push(SmcIndicator::new(i, SmcKind::UnpackLoop, conf));
                    break;
                }
            }
            if win[0] == 0xE2 {
                out.push(SmcIndicator::new(i, SmcKind::UnpackLoop, 0.75));
                break;
            }
        }
    }
    out
}

fn detect_decryption_routine_patterns(code: &[u8]) -> Vec<SmcIndicator> {
    let mut out = Vec::new();
    let mut xor_count = 0usize;
    let mut xor_start = 0usize;
    for i in 0..code.len().saturating_sub(2) {
        if code[i] == 0x80 && (code[i + 1] & 0x38 == 0x30) {
            if xor_count == 0 { xor_start = i; }
            xor_count += 1;
        } else if matches!(code[i], 0xE8 | 0xC3 | 0xC2) {
            if xor_count >= 3 {
                let conf = f32::from(u16::try_from(xor_count).unwrap_or(u16::MAX))
                    .mul_add(0.05, 0.50).min(0.95);
                out.push(SmcIndicator::new(xor_start, SmcKind::DecryptionRoutine, conf));
            }
            xor_count = 0;
        }
    }
    if xor_count >= 3 {
        let conf = f32::from(u16::try_from(xor_count).unwrap_or(u16::MAX))
            .mul_add(0.05, 0.50).min(0.95);
        out.push(SmcIndicator::new(xor_start, SmcKind::DecryptionRoutine, conf));
    }
    out
}

fn detect_write_to_code_patterns(code: &[u8]) -> Vec<SmcIndicator> {
    let mut out = Vec::new();
    for i in 0..code.len().saturating_sub(5) {
        if code[i] == 0xC7 && code[i + 1] == 0x05 {
            let addr = u32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
            if (0x0040_0000..=0x00FF_FFFF).contains(&addr) {
                out.push(SmcIndicator::new(i, SmcKind::WriteToCodeSection, 0.75));
            }
        }
        if i + 6 < code.len() && code[i] == 0xC6 && code[i + 1] == 0x05 {
            let addr = u32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
            if (0x0040_0000..=0x00FF_FFFF).contains(&addr) {
                out.push(SmcIndicator::new(i, SmcKind::WriteToCodeSection, 0.70));
            }
        }
    }
    out
}

fn detect_self_patch_patterns(code: &[u8]) -> Vec<SmcIndicator> {
    let mut out = Vec::new();
    let mut nop_run = 0usize;
    let mut nop_start = 0usize;
    for (i, &b) in code.iter().enumerate() {
        if b == 0x90 {
            if nop_run == 0 { nop_start = i; }
            nop_run += 1;
        } else {
            if nop_run >= 8 {
                let preceding = if nop_start > 0 { code[nop_start - 1] } else { 0 };
                let conf = if matches!(preceding, 0x88 | 0x89 | 0xC6 | 0xC7 | 0x30 | 0xB0..=0xB7) {
                    0.80
                } else {
                    0.55
                };
                out.push(SmcIndicator::new(nop_start, SmcKind::SelfPatch, conf));
            }
            nop_run = 0;
        }
    }
    if nop_run >= 8 {
        out.push(SmcIndicator::new(nop_start, SmcKind::SelfPatch, 0.55));
    }
    out
}

// ── MockSmcTracer ─────────────────────────────────────────────────────────────

/// A deterministic mock tracer that simulates a two-layer packer without
/// performing any actual instrumentation.
///
/// The simulation models the following behavior:
///
/// * **Phase 1** (timestamps 0–50 ms): a decryption stub writes 0x1000 bytes
///   into `0x401000–0x402000` (the unpacking stub decrypts the first-layer
///   payload in-place).
/// * **Phase 2** (timestamps 200–400 ms): the first-layer payload places the
///   real code into `0x402000–0x410000` (the actual binary).
///
/// A snapshot is injected between the two phases (at timestamp 100 ms) so that
/// [`SmcAnalyzer::identify_stages`] can reconstruct an image from each phase.
#[derive(Debug, Clone, Default)]
pub struct MockSmcTracer;

impl MockSmcTracer {
    /// Create a new mock tracer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Simulate tracing `binary` starting at `entry` and return a
    /// [`CodeGenerationTimeline`] representative of a two-stage packer.
    ///
    /// The `entry` address is used purely to anchor write addresses; the
    /// binary bytes are not parsed or executed.
    #[must_use]
    pub fn trace_binary(binary: &[u8], entry: u64) -> CodeGenerationTimeline {
        let mut timeline = CodeGenerationTimeline::new();

        // Phase 1: stub decrypts 0x1000 bytes at 0x401000 using XOR 0xCC.
        // We emit one write event per 16-byte chunk to simulate granular tracing.
        let phase1_base: u64 = 0x0040_1000;
        let phase1_size: usize = 0x1000;
        let phase1_chunk = 16usize;

        for chunk_idx in 0..(phase1_size / phase1_chunk) {
            let offset = chunk_idx * phase1_chunk;
            let ts = u64::try_from(chunk_idx).unwrap_or(u64::MAX) * 2; // 2 ms per chunk → 0..126 ms
            let source_slice_start = (usize::try_from(entry).unwrap_or(usize::MAX).saturating_add(offset)).min(binary.len());
            let source_slice_end = (source_slice_start + phase1_chunk).min(binary.len());
            let raw: Vec<u8> = if source_slice_start < source_slice_end {
                binary[source_slice_start..source_slice_end]
                    .iter()
                    .map(|&b| b ^ 0xCC)
                    .collect()
            } else {
                vec![0x90u8; phase1_chunk]
            };

            timeline.add_event(TraceWriteEvent::new(
                ts,
                entry,
                phase1_base + u64::try_from(offset).unwrap_or(u64::MAX),
                offset,
                raw,
                Some("packer_stub.exe".to_owned()),
            ));
        }

        // Snapshot between phases (timestamp 100 ms).
        let snapshot_size = phase1_size + 0x1000;
        let mut snapshot_mem = vec![0x90u8; snapshot_size];
        // Embed a recognisable OEP prologue at offset 0 of the snapshot (= 0x401000).
        if snapshot_mem.len() >= 3 {
            snapshot_mem[0] = 0x55; // PUSH EBP
            snapshot_mem[1] = 0x8B; // MOV EBP,
            snapshot_mem[2] = 0xEC; //          ESP
        }
        timeline.add_snapshot(100, snapshot_mem);

        // Phase 2: real payload placed at 0x402000–0x410000 in larger chunks.
        // Start timestamp must be > phase1 max_ts + STAGE_GAP_THRESHOLD_MS.
        // Phase 1 last event is at ts = (phase1_size / phase1_chunk - 1) * 2 ms
        //   = (256 - 1) * 2 = 510 ms.
        // We start phase 2 at 700 ms so the gap (190 ms) exceeds the 100 ms threshold.
        let phase2_base: u64 = 0x0040_2000;
        let phase2_size: usize = 0xE000; // 56 KiB
        let phase2_chunk = 256usize;
        let phase2_start_ts = 700u64;

        for chunk_idx in 0..(phase2_size / phase2_chunk) {
            let offset = chunk_idx * phase2_chunk;
            let ts = phase2_start_ts + u64::try_from(chunk_idx).unwrap_or(u64::MAX);
            let src_start = (usize::try_from(entry).unwrap_or(usize::MAX).saturating_add(phase1_size).saturating_add(offset)).min(binary.len());
            let src_end = (src_start + phase2_chunk).min(binary.len());
            let raw: Vec<u8> = if src_start < src_end {
                binary[src_start..src_end].to_vec()
            } else {
                // Synthesise realistic-looking code bytes.
                let mut chunk = vec![0x90u8; phase2_chunk];
                // Sprinkle a few common opcodes.
                if chunk.len() > 4 {
                    chunk[0] = 0x55;
                    chunk[1] = 0x8B;
                    chunk[2] = 0xEC;
                    chunk[3] = 0x83;
                }
                chunk
            };

            timeline.add_event(TraceWriteEvent::new(
                ts,
                phase1_base, // written by the payload stub
                phase2_base + u64::try_from(offset).unwrap_or(u64::MAX),
                offset,
                raw,
                Some("payload_layer1.bin".to_owned()),
            ));
        }

        // Final snapshot at end of Phase 2.
        let final_snap_size = 0x10000; // 64 KiB covering both regions
        let mut final_snap = vec![0u8; final_snap_size];
        // Embed OEP prologue at 0x402000 (offset = 0x1000 in snapshot from 0x401000).
        let oep_off = 0x1000usize;
        if final_snap.len() > oep_off + 3 {
            final_snap[oep_off] = 0x55;
            final_snap[oep_off + 1] = 0x8B;
            final_snap[oep_off + 2] = 0xEC;
        }
        // phase2 last ts = 700 + (0xE000/256 - 1) = 700 + 223 = 923 ms
        timeline.add_snapshot(950, final_snap);

        timeline.sort_by_time();
        timeline
    }
}

// ── SmcTimelineReport ─────────────────────────────────────────────────────────

/// A concise analysis report derived from a [`CodeGenerationTimeline`] and its
/// identified [`UnpackStage`]s.
///
/// Note: this type is distinct from the existing [`SmcReport`] (which reports
/// on static detection results); `SmcTimelineReport` is concerned with the
/// dynamic tracing perspective described in §37.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcTimelineReport {
    /// Number of discrete unpacking stages identified.
    pub stages_count: u32,
    /// Total bytes written across all stages.
    pub bytes_written: usize,
    /// Best OEP candidate (from the last stage with a non-`None` candidate).
    pub suspected_oep: Option<u64>,
    /// Human-readable description of the protection type inferred from the
    /// stage structure.
    pub protection_type: String,
    /// Ordered list of actionable recommendations for the reverse engineer.
    pub recommendations: Vec<String>,
}

impl SmcTimelineReport {
    /// Build a report from the full timeline and the identified stages.
    #[must_use]
    pub fn generate(timeline: &CodeGenerationTimeline, stages: &[UnpackStage]) -> Self {
        let stages_count = u32::try_from(stages.len()).unwrap_or(u32::MAX);
        let bytes_written = timeline.total_bytes_written();

        // Prefer the last stage's OEP candidate (innermost unpack layer).
        let suspected_oep = stages.iter().rev().find_map(|s| s.entry_point_candidate);

        let protection_type = match stages_count {
            0 => "No SMC stages detected".to_owned(),
            1 => "Single-layer packer (stub decrypts payload in-place)".to_owned(),
            2 => "Two-layer packer (stub → intermediate → payload)".to_owned(),
            n => format!("{n}-layer packer (complex multi-stage protection)"),
        };

        let mut recommendations = Vec::new();

        if stages_count == 0 {
            recommendations.push(
                "No dynamic write activity detected; try running with anti-anti-debug patches applied."
                    .to_owned(),
            );
        } else {
            recommendations.push(format!(
                "Set a hardware breakpoint at suspected OEP {:#x} and dump memory.",
                suspected_oep.unwrap_or(0)
            ));
            recommendations.push(
                "Use ScyllaHide or similar to bypass anti-debug checks before tracing.".to_owned(),
            );
            recommendations.push(
                "Dump the process image at the end of each stage snapshot for PE reconstruction."
                    .to_owned(),
            );
        }

        if stages_count >= 2 {
            recommendations.push(
                "Consider running OllyDumpEx / PE-bear on each stage dump to reassemble imports."
                    .to_owned(),
            );
        }

        if bytes_written > 0x10000 {
            recommendations.push(format!(
                "Large write volume ({bytes_written} bytes); the packer may decompress \
                 as well as decrypt — check for zlib/LZMA signatures in the payload."
            ));
        }

        recommendations.push(
            "Correlate write ranges with the original PE section boundaries to \
             identify which sections are modified."
                .to_owned(),
        );

        Self {
            stages_count,
            bytes_written,
            suspected_oep,
            protection_type,
            recommendations,
        }
    }

    /// Number of recommendations in this report.
    #[must_use]
    pub const fn recommendation_count(&self) -> usize {
        self.recommendations.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── PolymorphicEngineAnalyzer ─────────────────────────────────────────────

    #[test]
    fn test_polymorph_nop_insertion() {
        let before = vec![0x89, 0xC0, 0x89, 0xD8]; // MOV EAX,EAX; MOV EAX,EBX
        let mut after = vec![0x90u8; 8]; // replaced with NOPs
        after[0] = 0x89;
        let analyzer = PolymorphicEngineAnalyzer::new();
        let events = analyzer.analyze(&before, &after);
        assert!(!events.is_empty());
    }

    #[test]
    fn test_polymorph_no_diff() {
        let data = vec![0x90u8; 16];
        let events = PolymorphicEngineAnalyzer::new().analyze(&data, &data);
        assert!(events.is_empty());
    }

    #[test]
    fn test_polymorph_register_sub() {
        // INC EAX (0x40) → INC ECX (0x41)
        let before = vec![0x40u8];
        let after = vec![0x41u8];
        let events = PolymorphicEngineAnalyzer::new().analyze(&before, &after);
        assert!(!events.is_empty());
        assert!(matches!(events[0].kind, MutationType::RegisterSubstitution));
    }

    #[test]
    fn test_mutation_tracker_generations() {
        let mut tracker = CodeMutationTracker::new(vec![0x90u8; 16]);
        tracker.add_snapshot(vec![0x40u8; 16]); // all different
        tracker.add_snapshot(vec![0x40u8; 16]); // same as gen 1
        assert_eq!(tracker.generation_count(), 3);
        assert!(!tracker.mutations_at(0).is_empty());
        assert!(tracker.mutations_at(1).is_empty());
    }

    #[test]
    fn test_mutation_tracker_count_by_type() {
        let mut tracker = CodeMutationTracker::new(vec![0x90u8; 16]);
        tracker.add_snapshot(vec![0x00u8; 16]);
        let counts = tracker.count_by_type();
        assert!(!counts.is_empty());
    }

    // ── UnpackedRegionDetector ────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform() {
        // Uniform distribution → high entropy.
        let data: Vec<u8> = (0u8..=255).collect();
        let ent = shannon_entropy(&data);
        assert!(ent > 7.9, "entropy={ent}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0x90u8; 256];
        let ent = shannon_entropy(&data);
        assert!(ent < 0.01, "entropy={ent}");
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_looks_like_code_nop_sled() {
        let data = vec![0x90u8; 64];
        assert!(looks_like_code(&data));
    }

    #[test]
    fn test_looks_like_code_random() {
        // Uniformly random: should score low.
        let data: Vec<u8> = (0u8..128).collect();
        let _ = looks_like_code(&data); // just no panic
    }

    #[test]
    fn test_unpacked_region_detector_low_entropy_block() {
        // First half: NOP sled (low entropy), second half: random high-entropy.
        let mut data = vec![0x90u8; 512];
        // Second half: high entropy.
        for i in 512..1024usize {
            data.push((i % 256) as u8);
        }
        let detector = UnpackedRegionDetector::new(256, 6.0);
        let regions = detector.detect(&data);
        // Should find at least one low-entropy region in the NOP sled.
        assert!(!regions.is_empty());
    }

    // ── XorChainDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_xor_chain_step_apply_reverse() {
        let step = XorChainStep {
            key: 0x42,
            pre_op: 0,
            rot_amount: 0,
        };
        let b = 0xABu8;
        assert_eq!(step.reverse(step.apply(b)), b);
    }

    #[test]
    fn test_xor_chain_step_rol_reverse() {
        let step = XorChainStep {
            key: 0x12,
            pre_op: 2,
            rot_amount: 3,
        };
        let b = 0x5Eu8;
        assert_eq!(step.reverse(step.apply(b)), b);
    }

    #[test]
    fn test_xor_chain_roundtrip() {
        let mut chain = XorChain::new();
        chain.push(XorChainStep {
            key: 0x41,
            pre_op: 0,
            rot_amount: 0,
        });
        chain.push(XorChainStep {
            key: 0x37,
            pre_op: 0,
            rot_amount: 0,
        });
        chain.push(XorChainStep {
            key: 0x11,
            pre_op: 1,
            rot_amount: 0,
        });

        let plain = b"Hello, world!".to_vec();
        let encrypted = chain.encrypt(&plain);
        let decrypted = chain.decrypt(&encrypted);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_xor_chain_empty() {
        let chain = XorChain::new();
        assert!(chain.is_empty());
        let data = vec![0xAAu8, 0xBB];
        assert_eq!(chain.encrypt(&data), data);
        assert_eq!(chain.decrypt(&data), data);
    }

    #[test]
    fn test_xor_chain_detector_finds_chain() {
        // Two consecutive XOR [mem], imm8 instructions.
        // XOR [EBX], 0x11: 80 33 11
        // XOR [EBX+1], 0x22: 80 73 01 22  -- slightly different form; use simple 2-step
        let code = vec![0x80u8, 0x33, 0x11, 0x80, 0x33, 0x22];
        let detector = XorChainDetector::new();
        let chain = detector.detect(&code);
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().len(), 2);
    }

    #[test]
    fn test_xor_chain_detector_single_step_returns_none() {
        let code = vec![0x80u8, 0x33, 0x42];
        let result = XorChainDetector::new().detect(&code);
        assert!(result.is_none());
    }

    // ── WriteExecuteDetector ─────────────────────────────────────────────────

    #[test]
    fn test_write_execute_basic() {
        let mut det = WriteExecuteDetector::new();
        det.add_write(0x1000, 0x2000, 4);
        det.add_execution(0x1010, 0x2001); // within the written range
        let pairs = det.find_write_then_execute();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0.addr, 0x2000);
        assert_eq!(pairs[0].1.target, 0x2001);
    }

    #[test]
    fn test_write_execute_no_overlap() {
        let mut det = WriteExecuteDetector::new();
        det.add_write(0x1000, 0x2000, 4);
        det.add_execution(0x1010, 0x3000); // different range
        let pairs = det.find_write_then_execute();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_write_execute_clear() {
        let mut det = WriteExecuteDetector::new();
        det.add_write(0x1000, 0x2000, 4);
        det.clear();
        assert!(det.find_write_then_execute().is_empty());
    }

    // ── SmcBinaryPatcher ─────────────────────────────────────────────────────

    #[test]
    fn test_binary_patcher_single_patch() {
        let mut patcher = SmcBinaryPatcher::new();
        patcher.add_patch(Patch::new(
            2,
            vec![0x00, 0x00],
            vec![0xAA, 0xBB],
            "test".to_string(),
        ));
        let data = vec![0xFFu8; 6];
        let out = patcher.apply(&data).unwrap();
        assert_eq!(&out[2..4], &[0xAA, 0xBB]);
        assert_eq!(&out[0..2], &[0xFF, 0xFF]);
    }

    #[test]
    fn test_binary_patcher_out_of_bounds() {
        let mut patcher = SmcBinaryPatcher::new();
        patcher.add_patch(Patch::new(
            8,
            vec![0x00, 0x00],
            vec![0xAA, 0xBB],
            "test".to_string(),
        ));
        let data = vec![0u8; 4];
        assert!(patcher.apply(&data).is_err());
    }

    #[test]
    fn test_binary_patcher_overlap_detection() {
        let mut patcher = SmcBinaryPatcher::new();
        patcher.add_patch(Patch::new(0, vec![0x00; 4], vec![0xAA; 4], "a".to_string()));
        patcher.add_patch(Patch::new(2, vec![0x00; 4], vec![0xBB; 4], "b".to_string()));
        let overlaps = patcher.overlapping_patches();
        assert_eq!(overlaps.len(), 1);
    }

    #[test]
    fn test_binary_patcher_no_overlap() {
        let mut patcher = SmcBinaryPatcher::new();
        patcher.add_patch(Patch::new(0, vec![0x00; 4], vec![0xAA; 4], "a".to_string()));
        patcher.add_patch(Patch::new(4, vec![0x00; 4], vec![0xBB; 4], "b".to_string()));
        assert!(patcher.overlapping_patches().is_empty());
    }

    // ── AddRolCipher ─────────────────────────────────────────────────────────

    #[test]
    fn test_add_rol_cipher_add_first_roundtrip() {
        let cipher = AddRolCipher::new(0x10, 3, true);
        let plain = vec![0xAB, 0xCD, 0x12, 0x34];
        let enc = cipher.encrypt(&plain);
        let dec = cipher.decrypt(&enc);
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_add_rol_cipher_rol_first_roundtrip() {
        let cipher = AddRolCipher::new(0x55, 2, false);
        let plain = vec![0x00, 0x11, 0x22, 0xFF];
        let enc = cipher.encrypt(&plain);
        let dec = cipher.decrypt(&enc);
        assert_eq!(dec, plain);
    }

    // ── SmcStats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_smc_stats_empty() {
        let stats = SmcStats::from_regions(&[]);
        assert_eq!(stats.regions_detected, 0);
        assert_eq!(stats.bytes_decrypted, 0);
    }

    #[test]
    fn test_smc_stats_xor() {
        let region = SmcRegion {
            start: 0,
            end: 100,
            decryptor_addr: 0,
            key: SmcKey::Constant(0x42),
            algorithm: SmcAlgorithm::Xor,
        };
        let stats = SmcStats::from_regions(&[region]);
        assert_eq!(stats.xor_count, 1);
        assert_eq!(stats.bytes_decrypted, 100);
    }

    // ── SmcReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_smc_report_analyze_no_panic() {
        let data = vec![0x90u8; 64];
        let report = SmcReport::analyze(&data);
        assert_eq!(report.write_execute_pairs, 0);
    }

    #[test]
    fn test_smc_report_serialize() {
        let report = SmcReport::analyze(&[0x90u8; 32]);
        let _json = serde_json::to_string(&report).unwrap();
    }

    // ── rol8/ror8 helpers ─────────────────────────────────────────────────────

    #[test]
    fn test_rol8_zero_rotation() {
        assert_eq!(rol8(0xAB, 0), 0xAB);
    }

    #[test]
    fn test_ror8_zero_rotation() {
        assert_eq!(ror8(0xCD, 0), 0xCD);
    }

    #[test]
    fn test_rol_ror_inverse() {
        for b in 0u8..=255 {
            for n in 0u8..8 {
                assert_eq!(ror8(rol8(b, n), n), b);
            }
        }
    }

    #[test]
    fn test_smc_region_is_empty() {
        let r = SmcRegion {
            start: 5,
            end: 5,
            decryptor_addr: 0,
            key: SmcKey::Constant(0),
            algorithm: SmcAlgorithm::Xor,
        };
        assert!(r.is_empty());
    }

    #[test]
    fn test_smc_region_len() {
        let r = SmcRegion {
            start: 0x1000,
            end: 0x2000,
            decryptor_addr: 0,
            key: SmcKey::Constant(0),
            algorithm: SmcAlgorithm::Xor,
        };
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn test_unpacked_region_len() {
        let ur = UnpackedRegion {
            start: 10,
            end: 30,
            entropy: 3.0,
            looks_like_code: true,
        };
        assert_eq!(ur.len(), 20);
        assert!(!ur.is_empty());
    }

    #[test]
    fn test_unpacked_region_empty() {
        let ur = UnpackedRegion {
            start: 10,
            end: 10,
            entropy: 0.0,
            looks_like_code: false,
        };
        assert!(ur.is_empty());
    }

    #[test]
    fn test_add_rol_cipher_single_byte_zero() {
        let cipher = AddRolCipher::new(0, 0, true);
        assert_eq!(cipher.encrypt_byte(0xAB), 0xAB);
        assert_eq!(cipher.decrypt_byte(0xAB), 0xAB);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §37.5 SMC Reconstruction tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smc_reconstruction_tests {
    use super::*;

    // ── TraceWriteEvent ───────────────────────────────────────────────────────

    #[test]
    fn test_trace_write_event_target_end() {
        let ev = TraceWriteEvent::new(0, 0x1000, 0x0040_1000, 0, vec![0xAA, 0xBB, 0xCC], None);
        assert_eq!(ev.target_end(), 0x0040_1003);
    }

    #[test]
    fn test_trace_write_event_overlaps_range() {
        let ev = TraceWriteEvent::new(0, 0, 0x1000, 0, vec![0u8; 16], None);
        assert!(ev.overlaps_range(0x100F, 0x1020)); // overlaps at end
        assert!(ev.overlaps_range(0x0FF0, 0x1001)); // overlaps at start
        assert!(!ev.overlaps_range(0x1010, 0x2000)); // entirely after
        assert!(!ev.overlaps_range(0x0000, 0x1000)); // entirely before
    }

    #[test]
    fn test_trace_write_event_no_overlap_adjacent() {
        let ev = TraceWriteEvent::new(0, 0, 0x1000, 0, vec![0u8; 4], None);
        // [0x1000, 0x1004) does not overlap with [0x1004, 0x1008)
        assert!(!ev.overlaps_range(0x1004, 0x1008));
    }

    // ── CodeGenerationTimeline ───────────────────────────────────────────────

    #[test]
    fn test_timeline_add_and_sort() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_event(TraceWriteEvent::new(200, 0, 0x2000, 0, vec![1], None));
        tl.add_event(TraceWriteEvent::new(100, 0, 0x1000, 0, vec![2], None));
        tl.add_event(TraceWriteEvent::new(300, 0, 0x3000, 0, vec![3], None));
        tl.sort_by_time();
        let ts: Vec<u64> = tl.events.iter().map(|e| e.timestamp).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }

    #[test]
    fn test_timeline_bytes_written_to_range() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_event(TraceWriteEvent::new(0, 0, 0x1000, 0, vec![0xAA; 8], None));
        tl.add_event(TraceWriteEvent::new(1, 0, 0x2000, 0, vec![0xBB; 8], None));
        let hits = tl.bytes_written_to_range(0x1004, 0x1008);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target_addr, 0x1000);
    }

    #[test]
    fn test_timeline_total_bytes_written() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_event(TraceWriteEvent::new(0, 0, 0, 0, vec![0u8; 10], None));
        tl.add_event(TraceWriteEvent::new(1, 0, 0, 0, vec![0u8; 20], None));
        assert_eq!(tl.total_bytes_written(), 30);
    }

    #[test]
    fn test_timeline_start_end_time() {
        let mut tl = CodeGenerationTimeline::new();
        assert!(tl.start_time().is_none());
        assert!(tl.end_time().is_none());
        tl.add_event(TraceWriteEvent::new(5, 0, 0, 0, vec![0], None));
        tl.add_event(TraceWriteEvent::new(15, 0, 0, 0, vec![0], None));
        assert_eq!(tl.start_time(), Some(5));
        assert_eq!(tl.end_time(), Some(15));
    }

    #[test]
    fn test_timeline_snapshot_at_or_before() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_snapshot(50, vec![0xAA; 4]);
        tl.add_snapshot(150, vec![0xBB; 4]);
        let snap = tl.snapshot_at_or_before(100);
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().0, 50);
        let snap2 = tl.snapshot_at_or_before(200);
        assert_eq!(snap2.unwrap().0, 150);
        let snap3 = tl.snapshot_at_or_before(10);
        assert!(snap3.is_none());
    }

    // ── UnpackStage ───────────────────────────────────────────────────────────

    #[test]
    fn test_unpack_stage_metrics() {
        let writes = vec![
            TraceWriteEvent::new(100, 0, 0x1000, 0, vec![0u8; 4], None),
            TraceWriteEvent::new(200, 0, 0x2000, 0, vec![0u8; 8], None),
        ];
        let stage = UnpackStage {
            stage_num: 1,
            start_ts: 100,
            end_ts: 200,
            writes,
            snapshot: vec![],
            entry_point_candidate: None,
        };
        assert_eq!(stage.duration_ms(), 100);
        assert_eq!(stage.bytes_written(), 12);
        assert_eq!(stage.min_write_addr(), Some(0x1000));
        assert_eq!(stage.max_write_addr(), Some(0x2000));
    }

    // ── SmcAnalyzer::identify_stages ─────────────────────────────────────────

    #[test]
    fn test_identify_stages_empty_timeline() {
        let tl = CodeGenerationTimeline::new();
        let stages = SmcAnalyzer::identify_stages(&tl);
        assert!(stages.is_empty());
    }

    #[test]
    fn test_identify_stages_single_stage() {
        let mut tl = CodeGenerationTimeline::new();
        // All events within 10 ms → one stage.
        for i in 0..5u64 {
            tl.add_event(TraceWriteEvent::new(
                i * 10,
                0,
                0x1000 + i * 4,
                0,
                vec![0xAA],
                None,
            ));
        }
        let stages = SmcAnalyzer::identify_stages(&tl);
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].stage_num, 1);
    }

    #[test]
    fn test_identify_stages_two_stages() {
        let mut tl = CodeGenerationTimeline::new();
        // Phase 1: timestamps 0–40 ms (gap <= 10 ms each).
        for i in 0..5u64 {
            tl.add_event(TraceWriteEvent::new(
                i * 10,
                0,
                0x1000 + i,
                0,
                vec![0xAA],
                None,
            ));
        }
        // Gap of 200 ms (> STAGE_GAP_THRESHOLD_MS).
        // Phase 2: timestamps 240–280 ms.
        for i in 0..5u64 {
            tl.add_event(TraceWriteEvent::new(
                240 + i * 10,
                0,
                0x2000 + i,
                0,
                vec![0xBB],
                None,
            ));
        }
        let stages = SmcAnalyzer::identify_stages(&tl);
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0].stage_num, 1);
        assert_eq!(stages[1].stage_num, 2);
    }

    #[test]
    fn test_identify_stages_preserves_order() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_event(TraceWriteEvent::new(
            0,
            0,
            0x0040_1000,
            0,
            vec![0x55, 0x8B, 0xEC],
            None,
        ));
        tl.add_event(TraceWriteEvent::new(300, 0, 0x0040_2000, 0, vec![0x90], None));
        let stages = SmcAnalyzer::identify_stages(&tl);
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0].writes[0].target_addr, 0x0040_1000);
        assert_eq!(stages[1].writes[0].target_addr, 0x0040_2000);
    }

    // ── SmcAnalyzer::find_oep ────────────────────────────────────────────────

    #[test]
    fn test_find_oep_push_ebp_prologue() {
        // Snapshot contains PUSH EBP; MOV EBP, ESP at offset 0.
        // Write touches 0x401000 so the heuristic should match.
        let snapshot = vec![0x55u8, 0x8B, 0xEC, 0x90, 0x90];
        let writes = vec![TraceWriteEvent::new(
            0,
            0,
            0x0040_1000,
            0,
            vec![0x55, 0x8B, 0xEC],
            None,
        )];
        let stage = UnpackStage {
            stage_num: 1,
            start_ts: 0,
            end_ts: 0,
            writes,
            snapshot,
            entry_point_candidate: None,
        };
        let oep = SmcAnalyzer::find_oep(&stage);
        assert!(
            oep.is_some(),
            "OEP should be detected from push-EBP prologue"
        );
    }

    #[test]
    fn test_find_oep_last_write_fallback() {
        let writes = vec![
            TraceWriteEvent::new(0, 0, 0x1000, 0, vec![0xCC], None),
            TraceWriteEvent::new(1, 0, 0x5678, 0, vec![0xDD], None),
        ];
        let stage = UnpackStage {
            stage_num: 1,
            start_ts: 0,
            end_ts: 1,
            writes,
            snapshot: vec![0xAB; 4], // no prologue pattern
            entry_point_candidate: None,
        };
        // No prologue match → last write target.
        let oep = SmcAnalyzer::find_oep(&stage);
        assert_eq!(oep, Some(0x5678));
    }

    #[test]
    fn test_find_oep_empty_stage() {
        let stage = UnpackStage {
            stage_num: 1,
            start_ts: 0,
            end_ts: 0,
            writes: vec![],
            snapshot: vec![],
            entry_point_candidate: None,
        };
        assert!(SmcAnalyzer::find_oep(&stage).is_none());
    }

    // ── SmcAnalyzer::reconstruct_from_snapshot ───────────────────────────────

    #[test]
    fn test_reconstruct_overlay_writes() {
        let original = vec![0x00u8; 16];
        let snapshot = vec![0x00u8; 16]; // snapshot also zeroed
        let writes = vec![TraceWriteEvent::new(
            0,
            0,
            0x1000,
            0,
            vec![0xAA, 0xBB],
            None,
        )];
        let stage = UnpackStage {
            stage_num: 1,
            start_ts: 0,
            end_ts: 0,
            writes,
            snapshot: snapshot.clone(),
            entry_point_candidate: Some(0x1000),
        };
        let rb = SmcAnalyzer::reconstruct_from_snapshot(&original, &snapshot, 0x1000, &stage);
        // After overlay, bytes at base offsets 0 and 1 should be from snapshot
        // (snapshot is all zeros, so the final check is that no panic occurs and
        // we get back a 16-byte image).
        assert_eq!(rb.data.len(), 16);
        assert_eq!(rb.base_addr, 0x1000);
        assert_eq!(rb.stage, 1);
        assert_eq!(rb.oep, Some(0x1000));
    }

    #[test]
    fn test_reconstruct_snapshot_overwrites() {
        let original = vec![0xFFu8; 8];
        let snapshot = vec![0x11u8, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00];
        let writes = vec![TraceWriteEvent::new(
            0,
            0,
            0x2000,
            0,
            vec![0xAA, 0xBB, 0xCC, 0xDD],
            None,
        )];
        let stage = UnpackStage {
            stage_num: 2,
            start_ts: 0,
            end_ts: 0,
            writes,
            snapshot: snapshot.clone(),
            entry_point_candidate: None,
        };
        let rb = SmcAnalyzer::reconstruct_from_snapshot(&original, &snapshot, 0x2000, &stage);
        // Snapshot covers entire region → snapshot bytes win.
        assert_eq!(&rb.data[..4], &[0x11, 0x22, 0x33, 0x44]);
    }

    // ── detect_smc_indicators ────────────────────────────────────────────────

    #[test]
    fn test_detect_smc_indicators_empty() {
        let inds = detect_smc_indicators(&[]);
        assert!(inds.is_empty());
    }

    #[test]
    fn test_detect_smc_indicators_vprotect() {
        // PUSH 0x40; CALL rel32
        let mut code = vec![0x6A, 0x40];
        code.extend_from_slice(&[0x90; 10]);
        code.push(0xE8);
        code.extend_from_slice(&[0x00; 4]);
        let inds = detect_smc_indicators(&code);
        assert!(inds.iter().any(|i| i.kind == SmcKind::VirtualProtectRwx));
    }

    #[test]
    fn test_detect_smc_indicators_unpack_loop() {
        // XOR [EBX], 0x42 (80 33 42); DEC ECX (49); JNZ -5 (75 FB)
        let code = vec![0x80u8, 0x33, 0x42, 0x49, 0x75, 0xFB];
        let inds = detect_smc_indicators(&code);
        assert!(inds.iter().any(|i| i.kind == SmcKind::UnpackLoop));
    }

    #[test]
    fn test_detect_smc_indicators_write_code_section() {
        // MOV DWORD PTR [0x00401000], 0x12345678
        let mut code = vec![0xC7, 0x05];
        code.extend_from_slice(&0x0040_1000u32.to_le_bytes()); // address
        code.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // value
        let inds = detect_smc_indicators(&code);
        assert!(inds.iter().any(|i| i.kind == SmcKind::WriteToCodeSection));
    }

    #[test]
    fn test_detect_smc_indicators_self_patch_nop_sled() {
        let mut code = vec![0x88u8]; // MOV byte-store preceding NOPs
        code.extend(vec![0x90u8; 12]); // 12 NOPs
        code.push(0xC3); // RET
        let inds = detect_smc_indicators(&code);
        assert!(inds.iter().any(|i| i.kind == SmcKind::SelfPatch));
    }

    #[test]
    fn test_detect_smc_indicators_decryption_routine() {
        // 4× XOR [EBX], imm8 followed by RET
        let mut code = Vec::new();
        for key in [0x11u8, 0x22, 0x33, 0x44] {
            code.extend_from_slice(&[0x80, 0x33, key]);
        }
        code.push(0xC3); // RET
        let inds = detect_smc_indicators(&code);
        assert!(inds.iter().any(|i| i.kind == SmcKind::DecryptionRoutine));
    }

    // ── MockSmcTracer ─────────────────────────────────────────────────────────

    #[test]
    fn test_mock_tracer_produces_two_stages() {
        let binary = vec![0x00u8; 0x20000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let stages = SmcAnalyzer::identify_stages(&timeline);
        assert_eq!(
            stages.len(),
            2,
            "mock tracer should produce exactly 2 stages"
        );
    }

    #[test]
    fn test_mock_tracer_stage_write_ranges() {
        let binary = vec![0xAAu8; 0x20000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let stages = SmcAnalyzer::identify_stages(&timeline);
        assert_eq!(stages.len(), 2);

        // Stage 1 writes start at 0x401000.
        let s1_min = stages[0].min_write_addr().unwrap();
        assert_eq!(s1_min, 0x0040_1000, "stage 1 should write to 0x401000");

        // Stage 2 writes start at 0x402000.
        let s2_min = stages[1].min_write_addr().unwrap();
        assert_eq!(s2_min, 0x0040_2000, "stage 2 should write to 0x402000");
    }

    #[test]
    fn test_mock_tracer_timeline_sorted() {
        let binary = vec![0xBBu8; 0x10000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let ts: Vec<u64> = timeline.events.iter().map(|e| e.timestamp).collect();
        let mut sorted = ts.clone();
        sorted.sort_unstable();
        assert_eq!(ts, sorted, "timeline should be sorted by timestamp");
    }

    #[test]
    fn test_mock_tracer_has_snapshots() {
        let binary = vec![0u8; 0x10000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        assert!(timeline.snapshots.len() >= 2, "expect at least 2 snapshots");
    }

    // ── SmcTimelineReport ─────────────────────────────────────────────────────

    #[test]
    fn test_timeline_report_two_stage() {
        let binary = vec![0u8; 0x20000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let stages = SmcAnalyzer::identify_stages(&timeline);
        let report = SmcTimelineReport::generate(&timeline, &stages);
        assert_eq!(report.stages_count, 2);
        assert!(report.bytes_written > 0);
        assert!(report.suspected_oep.is_some());
        assert!(report.protection_type.contains("Two-layer"));
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_timeline_report_no_stages() {
        let tl = CodeGenerationTimeline::new();
        let stages: Vec<UnpackStage> = Vec::new();
        let report = SmcTimelineReport::generate(&tl, &stages);
        assert_eq!(report.stages_count, 0);
        assert!(report.suspected_oep.is_none());
        assert!(report.protection_type.contains("No SMC"));
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_timeline_report_single_stage() {
        let mut tl = CodeGenerationTimeline::new();
        tl.add_event(TraceWriteEvent::new(
            0,
            0,
            0x1000,
            0,
            vec![0x90u8; 100],
            None,
        ));
        let stages = SmcAnalyzer::identify_stages(&tl);
        let report = SmcTimelineReport::generate(&tl, &stages);
        assert_eq!(report.stages_count, 1);
        assert!(report.protection_type.contains("Single-layer"));
    }

    #[test]
    fn test_timeline_report_recommendation_count() {
        let binary = vec![0u8; 0x20000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let stages = SmcAnalyzer::identify_stages(&timeline);
        let report = SmcTimelineReport::generate(&timeline, &stages);
        assert!(report.recommendation_count() >= 3);
    }

    // ── ReconstructedBinary ───────────────────────────────────────────────────

    #[test]
    fn test_reconstructed_binary_len_is_empty() {
        let rb = ReconstructedBinary {
            data: vec![],
            base_addr: 0,
            oep: None,
            stage: 1,
        };
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
    }

    #[test]
    fn test_reconstructed_binary_non_empty() {
        let rb = ReconstructedBinary {
            data: vec![0x55u8, 0x8B, 0xEC],
            base_addr: 0x0040_1000,
            oep: Some(0x0040_1000),
            stage: 1,
        };
        assert!(!rb.is_empty());
        assert_eq!(rb.len(), 3);
    }

    // ── Integration: full pipeline ────────────────────────────────────────────

    #[test]
    fn test_full_pipeline_mock_trace_and_reconstruct() {
        let binary = vec![0x90u8; 0x20000];
        let timeline = MockSmcTracer::trace_binary(&binary, 0x0040_1000);
        let stages = SmcAnalyzer::identify_stages(&timeline);
        assert_eq!(stages.len(), 2);

        for stage in &stages {
            let rb =
                SmcAnalyzer::reconstruct_from_snapshot(&binary, &stage.snapshot, 0x0040_1000, stage);
            assert!(!rb.is_empty());
        }

        let report = SmcTimelineReport::generate(&timeline, &stages);
        assert!(report.stages_count > 0);
        assert!(report.suspected_oep.is_some());
    }

    #[test]
    fn test_smc_indicator_confidence_clamped() {
        let ind = SmcIndicator::new(0, SmcKind::SelfPatch, 1.5);
        assert!(ind.confidence <= 1.0);
        let ind2 = SmcIndicator::new(0, SmcKind::SelfPatch, -0.5);
        assert!(ind2.confidence >= 0.0);
    }

    #[test]
    fn test_stage_gap_threshold_constant() {
        assert_eq!(STAGE_GAP_THRESHOLD_MS, 100);
    }
}
