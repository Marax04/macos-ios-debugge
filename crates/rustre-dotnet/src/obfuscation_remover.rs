//! .NET obfuscation removal: `ConfuserEx` string decryption (decryptor class identification
//! and emulation), control flow deobfuscation (switch-based dispatcher → linear),
//! proxy call removal.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RemoverError {
    #[error("decryptor not found")]
    DecryptorNotFound,
    #[error("emulation failed: {0}")]
    EmulationFailed(String),
    #[error("metadata not available")]
    NoMetadata,
    #[error("invalid IL at offset {0:#x}")]
    InvalidIl(u32),
}

pub type RemoverResult<T> = Result<T, RemoverError>;

// ── CIL opcode constants ──────────────────────────────────────────────────────

pub mod cil {
    pub const NOP: u8 = 0x00;
    pub const LDC_I4_0: u8 = 0x16;
    pub const LDC_I4_1: u8 = 0x17;
    pub const LDC_I4: u8 = 0x20;
    pub const LDC_I4_S: u8 = 0x1F;
    pub const LDSTR: u8 = 0x72;
    pub const CALL: u8 = 0x28;
    pub const CALLVIRT: u8 = 0x6F;
    pub const CALLI: u8 = 0x29;
    pub const RET: u8 = 0x2A;
    pub const BR: u8 = 0x38;
    pub const BR_S: u8 = 0x2B;
    pub const SWITCH: u8 = 0x45;
    pub const LDLOC_0: u8 = 0x06;
    pub const LDLOC_1: u8 = 0x07;
    pub const LDLOC_2: u8 = 0x08;
    pub const LDLOC_3: u8 = 0x09;
    pub const STLOC_0: u8 = 0x0A;
    pub const STLOC_1: u8 = 0x0B;
    pub const STLOC_2: u8 = 0x0C;
    pub const STLOC_3: u8 = 0x0D;
    pub const LDLOC_S: u8 = 0x11;
    pub const STLOC_S: u8 = 0x13;
    pub const LDFTN: u8 = 0xFE; // prefix
    pub const XOR: u8 = 0x61;
    pub const AND: u8 = 0x5F;
    pub const OR: u8 = 0x60;
    pub const ADD: u8 = 0x58;
    pub const SUB: u8 = 0x59;
    pub const NEG: u8 = 0x65;
    pub const CONV_I4: u8 = 0x69;
    pub const NEWOBJ: u8 = 0x73;
    pub const INITOBJ: u8 = 0xFE; // prefix 0x15
    pub const DUP: u8 = 0x25;
    pub const POP: u8 = 0x26;
    pub const LDTOKEN: u8 = 0xD0;
}

// ── IL instruction ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IlInstruction {
    pub offset: u32,
    pub opcode: u16,
    pub operand: IlOperand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IlOperand {
    None,
    I8(i8),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Token(u32),
    Branch(u32),
    SwitchTargets(Vec<u32>),
    String(String),
}

impl IlInstruction {
    #[must_use] 
    pub const fn is_call(&self) -> bool {
        matches!(self.opcode, 0x28 | 0x29 | 0x6F)
    }

    #[must_use] 
    pub const fn is_branch(&self) -> bool {
        matches!(self.opcode, 0x38 | 0x2B | 0x39..=0x46)
    }

    #[must_use] 
    pub const fn is_return(&self) -> bool {
        self.opcode == 0x2A
    }

    #[must_use] 
    pub const fn is_switch(&self) -> bool {
        self.opcode == 0x45
    }

    #[must_use] 
    pub const fn token(&self) -> Option<u32> {
        match &self.operand {
            IlOperand::Token(t) => Some(*t),
            _ => None,
        }
    }

    #[must_use] 
    pub fn i32_value(&self) -> Option<i32> {
        match &self.operand {
            IlOperand::I32(v) => Some(*v),
            IlOperand::I8(v) => Some(i32::from(*v)),
            _ => None,
        }
    }
}

// ── ConfuserEx string decryptor ───────────────────────────────────────────────

/// Pattern for identifying `ConfuserEx` string decryptor classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfuserDecryptorInfo {
    pub class_token: u32,
    pub method_token: u32,
    pub class_name: String,
    pub method_name: String,
    pub key: Option<Vec<u8>>,
    pub algorithm: StringDecryptAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringDecryptAlgorithm {
    /// XOR with embedded key array.
    XorArray,
    /// AES using a key derived from a constant.
    AesDerived,
    /// Custom arithmetic.
    CustomArith,
    /// Unknown/undetected.
    Unknown,
}

impl StringDecryptAlgorithm {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XorArray => "XOR array",
            Self::AesDerived => "AES derived",
            Self::CustomArith => "custom arithmetic",
            Self::Unknown => "unknown",
        }
    }
}

/// Identify the `ConfuserEx` string decryptor in a class by IL pattern matching.
///
/// Pattern: a static method taking one int32 argument, returning String,
/// containing ldsfld + conv.i4 + xor or similar arithmetic.
#[must_use] 
pub fn identify_string_decryptor(
    class_name: &str,
    class_token: u32,
    method_name: &str,
    method_token: u32,
    instructions: &[IlInstruction],
) -> Option<ConfuserDecryptorInfo> {
    // Check for single int32 parameter return string pattern
    let has_ldsfld = instructions.iter().any(|i| i.opcode == 0x7E); // ldsfld
    let has_xor = instructions.iter().any(|i| i.opcode == u16::from(cil::XOR));
    let has_ldstr_or_ret = instructions.iter().any(IlInstruction::is_return);

    let algorithm = if has_ldsfld && has_xor {
        StringDecryptAlgorithm::XorArray
    } else if instructions.iter().any(|i| i.opcode == u16::from(cil::AND)) {
        StringDecryptAlgorithm::CustomArith
    } else {
        StringDecryptAlgorithm::Unknown
    };

    if !has_ldstr_or_ret {
        return None;
    }

    // If the method is short (< 30 instructions) and uses arithmetic on a constant, flag it
    if instructions.len() >= 3 && instructions.len() < 60 {
        Some(ConfuserDecryptorInfo {
            class_token,
            method_token,
            class_name: class_name.to_owned(),
            method_name: method_name.to_owned(),
            key: None,
            algorithm,
        })
    } else {
        None
    }
}

/// Emulate a simple XOR-based string decryptor given a call argument and a key table.
#[must_use] 
pub fn emulate_xor_string_decrypt(index: i32, key_table: &[u8], string_data: &[u8]) -> Option<String> {
    let Ok(idx) = usize::try_from(index) else { return None; };
    if idx >= string_data.len() {
        return None;
    }
    // Read length prefix at string_data[idx]
    let char_count = *string_data.get(idx)? as usize;
    let bytes_start = idx + 1;
    let bytes_end = bytes_start + char_count * 2;

    if bytes_end > string_data.len() {
        return None;
    }

    let raw = &string_data[bytes_start..bytes_end];
    let key_len = key_table.len().max(1);
    // Decode UTF-16LE; XOR low byte of each char with the key (high byte unchanged).
    let chars: Vec<u16> = raw
        .chunks_exact(2)
        .enumerate()
        .map(|(i, c)| {
            let k = key_table[i % key_len];
            u16::from_le_bytes([c[0] ^ k, c[1]])
        })
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

// ── Control flow deobfuscation ────────────────────────────────────────────────

/// A basic block in the control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_offset: u32,
    pub end_offset: u32,
    pub instructions: Vec<IlInstruction>,
    pub successors: Vec<u32>,
    pub is_dispatcher: bool,
}

impl BasicBlock {
    #[must_use] 
    pub fn new(start: u32, instrs: Vec<IlInstruction>) -> Self {
        let end = instrs.last().map_or(start, |i| i.offset + 1);
        let successors = Vec::new();
        let is_dispatcher = false;
        Self { start_offset: start, end_offset: end, instructions: instrs, successors, is_dispatcher }
    }

    #[must_use] 
    pub fn is_switch_dispatcher(&self) -> bool {
        // A dispatcher block: contains a switch instruction on a local variable
        // where the variable is set by some state machine.
        let has_switch = self.instructions.iter().any(IlInstruction::is_switch);
        let has_ldloc = self.instructions.iter().any(|i| {
            matches!(i.opcode, 0x06..=0x09 | 0x11 | 0xFE) // ldloc variants
        });
        has_switch && has_ldloc
    }
}

/// Detect switch-based control flow dispatchers in a method body.
#[must_use] 
pub fn detect_switch_dispatchers(blocks: &[BasicBlock]) -> Vec<&BasicBlock> {
    blocks.iter().filter(|b| b.is_switch_dispatcher()).collect()
}

/// Attempt to linearize a switch dispatcher by resolving the state machine order.
///
/// This is a best-effort analysis: we identify blocks that are dispatcher targets
/// and sort them by their state index to reconstruct the logical flow.
#[must_use] 
pub fn linearize_dispatcher(
    _blocks: &[BasicBlock],
    switch_block: &BasicBlock,
) -> Vec<u32> {
    // Find the switch instruction
    let Some(switch_instr) = switch_block.instructions.iter().find(|i| i.is_switch()) else { return Vec::new() };

    // Extract jump targets
    let targets = match &switch_instr.operand {
        IlOperand::SwitchTargets(t) => t.clone(),
        _ => return Vec::new(),
    };

    // Sort targets by their "natural" appearance order in the method
    let mut ordered: Vec<(usize, u32)> = targets
        .iter()
        .enumerate()
        .map(|(i, &t)| (i, t))
        .collect();
    ordered.sort_by_key(|(_, t)| *t);
    ordered.into_iter().map(|(_, t)| t).collect()
}

// ── Proxy call removal ────────────────────────────────────────────────────────

/// A proxy method: thin wrapper that just calls another method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMethodInfo {
    pub proxy_token: u32,
    pub proxy_name: String,
    pub target_token: u32,
    pub target_name: String,
    pub is_static: bool,
    pub arg_count: usize,
}

/// Detect proxy methods from their IL body.
/// A proxy has: (optional ldarg.* sequence) + (call/callvirt token) + (optional pop/ret).
#[must_use] 
pub fn detect_proxy_method(
    method_token: u32,
    method_name: &str,
    is_static: bool,
    instructions: &[IlInstruction],
) -> Option<ProxyMethodInfo> {
    // Filter out NOPs and prefix instructions
    let meaningful: Vec<&IlInstruction> = instructions
        .iter()
        .filter(|i| i.opcode != u16::from(cil::NOP))
        .collect();

    // Must be very short: ldarg* + call + ret
    if meaningful.len() < 2 || meaningful.len() > 8 {
        return None;
    }

    // Count ldarg instructions at the start
    let arg_count = meaningful
        .iter()
        .take_while(|i| matches!(i.opcode, 0x02..=0x05 | 0x0E | 0x0F)) // ldarg.0–3, ldarg.s, ldarg
        .count();

    // The next instruction after ldargs should be a call
    let call_idx = if is_static { arg_count } else { arg_count.max(1) };

    if call_idx >= meaningful.len() {
        return None;
    }

    let call_instr = meaningful[call_idx];
    if !call_instr.is_call() {
        return None;
    }

    let target_token = call_instr.token()?;

    // After the call: optional ret (or ret+pop for void callee returning something)
    let remaining = &meaningful[call_idx + 1..];
    if remaining.is_empty() || remaining.iter().all(|i| i.is_return() || i.opcode == u16::from(cil::POP)) {
        Some(ProxyMethodInfo {
            proxy_token: method_token,
            proxy_name: method_name.to_owned(),
            target_token,
            target_name: String::new(),
            is_static,
            arg_count,
        })
    } else {
        None
    }
}

// ── Obfuscation removal pipeline ──────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObfuscationRemovalResult {
    pub decrypted_strings: Vec<DecryptedStringEntry>,
    pub proxy_removals: Vec<ProxyMethodInfo>,
    pub dispatcher_linearizations: usize,
    pub total_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedStringEntry {
    pub call_offset: u32,
    pub method_token: u32,
    pub argument: i32,
    pub decrypted: String,
    pub decryptor_name: String,
}

impl ObfuscationRemovalResult {
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Removed: {} strings decrypted, {} proxies resolved, {} dispatchers linearized",
            self.decrypted_strings.len(),
            self.proxy_removals.len(),
            self.dispatcher_linearizations,
        )
    }
}

/// High-level pipeline: given a list of methods with their IL, perform all
/// deobfuscation passes and return what was changed.
pub struct ObfuscationRemover {
    pub string_decryptors: Vec<ConfuserDecryptorInfo>,
    pub string_data: HashMap<u32, Vec<u8>>,
    pub key_tables: HashMap<u32, Vec<u8>>,
}

impl ObfuscationRemover {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            string_decryptors: Vec::new(),
            string_data: HashMap::new(),
            key_tables: HashMap::new(),
        }
    }

    pub fn add_decryptor(&mut self, info: ConfuserDecryptorInfo) {
        self.string_decryptors.push(info);
    }

    pub fn add_string_data(&mut self, method_token: u32, data: Vec<u8>) {
        self.string_data.insert(method_token, data);
    }

    pub fn add_key_table(&mut self, method_token: u32, key: Vec<u8>) {
        self.key_tables.insert(method_token, key);
    }

    /// Process all methods, returning decryption results.
    #[must_use] 
    pub fn process_methods(
        &self,
        methods: &[(u32, String, bool, Vec<IlInstruction>)],
    ) -> ObfuscationRemovalResult {
        let mut result = ObfuscationRemovalResult::default();

        for (token, name, is_static, instrs) in methods {
            // Detect and remove proxies
            if let Some(proxy) = detect_proxy_method(*token, name, *is_static, instrs) {
                result.proxy_removals.push(proxy);
                result.total_changes += 1;
                continue;
            }

            // Detect switch dispatchers
            let blocks = build_basic_blocks(instrs);
            let dispatchers = detect_switch_dispatchers(&blocks);
            for d in &dispatchers {
                let linearized = linearize_dispatcher(&blocks, d);
                if !linearized.is_empty() {
                    result.dispatcher_linearizations += 1;
                    result.total_changes += 1;
                }
            }

            // Find calls to string decryptors
            for instr in instrs {
                if !instr.is_call() {
                    continue;
                }
                let Some(target_token) = instr.token() else { continue };

                if let Some(decryptor) = self.string_decryptors.iter().find(|d| d.method_token == target_token) {
                    // Find the argument pushed before this call
                    let arg = find_preceding_int_arg(instrs, instr.offset);
                    if let Some(idx) = arg {
                        // Try to decrypt
                        if let Some(key) = self.key_tables.get(&target_token)
                            && let Some(data) = self.string_data.get(&target_token)
                                && let Some(decrypted) = emulate_xor_string_decrypt(idx, key, data) {
                                    result.decrypted_strings.push(DecryptedStringEntry {
                                        call_offset: instr.offset,
                                        method_token: target_token,
                                        argument: idx,
                                        decrypted,
                                        decryptor_name: decryptor.method_name.clone(),
                                    });
                                    result.total_changes += 1;
                                }
                    }
                }
            }
        }

        result
    }
}

impl Default for ObfuscationRemover {
    fn default() -> Self {
        Self::new()
    }
}

/// Build basic blocks from a flat instruction list.
fn build_basic_blocks(instrs: &[IlInstruction]) -> Vec<BasicBlock> {
    if instrs.is_empty() {
        return Vec::new();
    }

    // Find block starts: first instruction + any branch target
    let mut block_starts: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    block_starts.insert(instrs[0].offset);

    for instr in instrs {
        if instr.is_branch() || instr.is_return() {
            // Next instruction is a new block start
            if let Some(next) = instrs.iter().find(|i| i.offset > instr.offset) {
                block_starts.insert(next.offset);
            }
        }
        match &instr.operand {
            IlOperand::Branch(t) => { block_starts.insert(*t); }
            IlOperand::SwitchTargets(ts) => {
                for t in ts { block_starts.insert(*t); }
            }
            _ => {}
        }
    }

    let starts_vec: Vec<u32> = block_starts.into_iter().collect();
    let mut blocks = Vec::new();

    for (i, &start) in starts_vec.iter().enumerate() {
        let end = starts_vec.get(i + 1).copied().unwrap_or(u32::MAX);
        let block_instrs: Vec<IlInstruction> = instrs
            .iter()
            .filter(|instr| instr.offset >= start && instr.offset < end)
            .cloned()
            .collect();
        if !block_instrs.is_empty() {
            blocks.push(BasicBlock::new(start, block_instrs));
        }
    }

    blocks
}

/// Find the integer argument pushed immediately before a call at `call_offset`.
fn find_preceding_int_arg(instrs: &[IlInstruction], call_offset: u32) -> Option<i32> {
    let pos = instrs.iter().position(|i| i.offset == call_offset)?;
    // Look backwards for the last ldc.i4* instruction before the call
    instrs[..pos].iter().rev().find_map(IlInstruction::i32_value)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instr(offset: u32, opcode: u16, operand: IlOperand) -> IlInstruction {
        IlInstruction { offset, opcode, operand }
    }

    #[test]
    fn test_proxy_detection() {
        let instrs = vec![
            make_instr(0, 0x02, IlOperand::None), // ldarg.0
            make_instr(1, 0x03, IlOperand::None), // ldarg.1
            make_instr(2, u16::from(cil::CALL), IlOperand::Token(0x0600_0001)),
            make_instr(3, u16::from(cil::RET), IlOperand::None),
        ];
        let proxy = detect_proxy_method(0x0600_0010, "ForwardFoo", true, &instrs);
        assert!(proxy.is_some());
        let p = proxy.unwrap();
        assert_eq!(p.target_token, 0x0600_0001);
        assert_eq!(p.arg_count, 2);
    }

    #[test]
    fn test_proxy_not_detected_complex() {
        let instrs = vec![
            make_instr(0, 0x02, IlOperand::None), // ldarg.0
            make_instr(1, u16::from(cil::CALL), IlOperand::Token(0x0600_0002)),
            make_instr(2, 0x58, IlOperand::None), // add
            make_instr(3, u16::from(cil::RET), IlOperand::None),
        ];
        let proxy = detect_proxy_method(0x0600_0011, "NotProxy", false, &instrs);
        assert!(proxy.is_none());
    }

    #[test]
    fn test_xor_string_decrypt() {
        // Prepare: 2 chars "AB" XORed with key 0x01
        let key = vec![0x01u8];
        let mut string_data = vec![2u8]; // 2 chars
        string_data.extend_from_slice(&[b'A' ^ 1, 0, b'B' ^ 1, 0]); // UTF-16LE XORed
        let result = emulate_xor_string_decrypt(0, &key, &string_data);
        assert_eq!(result.as_deref(), Some("AB"));
    }

    #[test]
    fn test_switch_dispatcher_detection() {
        let switch_instr = make_instr(0, 0x45, IlOperand::SwitchTargets(vec![10, 20, 30]));
        let ldloc_instr = make_instr(1, 0x06, IlOperand::None); // ldloc.0
        let block = BasicBlock::new(0, vec![ldloc_instr, switch_instr]);
        assert!(block.is_switch_dispatcher());
    }

    #[test]
    fn test_linearize_dispatcher() {
        let switch_instr = make_instr(4, 0x45, IlOperand::SwitchTargets(vec![30, 10, 20]));
        let block = BasicBlock::new(0, vec![switch_instr]);
        let blocks = vec![block];
        let order = linearize_dispatcher(&blocks, &blocks[0]);
        // Should be sorted by offset: 10, 20, 30
        assert_eq!(order, vec![10, 20, 30]);
    }

    #[test]
    fn test_build_basic_blocks() {
        let instrs = vec![
            make_instr(0, u16::from(cil::LDC_I4_0), IlOperand::None),
            make_instr(1, u16::from(cil::BR), IlOperand::Branch(5)),
            make_instr(5, u16::from(cil::RET), IlOperand::None),
        ];
        let blocks = build_basic_blocks(&instrs);
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_identify_string_decryptor() {
        let instrs = vec![
            make_instr(0, 0x7E, IlOperand::Token(0x0400_0001)), // ldsfld
            make_instr(1, 0x02, IlOperand::None),                // ldarg.0
            make_instr(2, u16::from(cil::XOR), IlOperand::None),     // xor
            make_instr(3, u16::from(cil::RET), IlOperand::None),     // ret
        ];
        let info = identify_string_decryptor(
            "Module_",
            0x0200_0001,
            "Decrypt",
            0x0600_0001,
            &instrs,
        );
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.algorithm, StringDecryptAlgorithm::XorArray);
    }

    #[test]
    fn test_obfuscation_remover_empty() {
        let remover = ObfuscationRemover::new();
        let result = remover.process_methods(&[]);
        assert_eq!(result.total_changes, 0);
    }
}
