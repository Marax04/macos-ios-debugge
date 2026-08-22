//! MCP tool: disassemble binary data at an optional base address.
//!
//! The `DisasmTool` accepts a byte buffer (hex-encoded or JSON integer array)
//! and a base address, disassembles it using `iced-x86`, and returns a
//! structured JSON result containing the decoded instructions plus a formatted
//! text listing.

use std::collections::HashMap;

use async_trait::async_trait;
use iced_x86::{Decoder, DecoderOptions, Formatter as _, Instruction, NasmFormatter};
use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── DisasmInput ─────────────────────────────────────────────────────────────

/// Input parameters for the disassemble tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmInput {
    /// Hex-encoded bytes to disassemble (e.g. `"4889E5 4883EC10"`).
    /// Mutually exclusive with `bytes`.
    pub hex: Option<String>,
    /// Raw byte array to disassemble.
    /// Mutually exclusive with `hex`.
    pub bytes: Option<Vec<u8>>,
    /// Base virtual address for the first byte (default: `0`).
    pub base_address: Option<u64>,
    /// Bitness: 16, 32, or 64 (default: `64`).
    pub bitness: Option<u32>,
    /// Maximum number of instructions to decode (default: `256`).
    pub max_instructions: Option<usize>,
    /// Offset into the byte buffer to start decoding (default: `0`).
    pub offset: Option<usize>,
}

impl DisasmInput {
    /// Resolve the byte buffer from either `hex` or `bytes`.
    pub fn resolve_bytes(&self) -> Result<Vec<u8>, McpError> {
        if let Some(hex) = &self.hex {
            return hex_decode(hex);
        }
        if let Some(bytes) = &self.bytes {
            return Ok(bytes.clone());
        }
        Err(McpError::InvalidParams(
            "disasm: provide 'hex' or 'bytes'".into(),
        ))
    }

    /// Effective base address.
    #[must_use]
    pub fn effective_base(&self) -> u64 {
        self.base_address.unwrap_or(0)
    }

    /// Effective bitness.
    #[must_use]
    pub fn effective_bitness(&self) -> u32 {
        match self.bitness {
            Some(16 | 32 | 64) => self.bitness.unwrap(),
            _ => 64,
        }
    }

    /// Effective max instructions.
    #[must_use]
    pub fn effective_max(&self) -> usize {
        match self.max_instructions {
            Some(n) if n > 0 => n,
            _ => 256,
        }
    }

    /// Effective starting offset.
    #[must_use]
    pub fn effective_offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
}

// ─── DecodedInstruction ───────────────────────────────────────────────────────

/// A single decoded instruction record in the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInstruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Instruction length in bytes.
    pub length: u32,
    /// Hex-encoded raw bytes.
    pub bytes: String,
    /// NASM-style mnemonic text.
    pub mnemonic: String,
    /// Full formatted text (mnemonic + operands).
    pub text: String,
    /// Opcode byte sequence (first 4 bytes of raw bytes).
    pub opcode: u32,
    /// Whether this is a call instruction.
    pub is_call: bool,
    /// Whether this is a return instruction.
    pub is_ret: bool,
    /// Whether this is a branch instruction.
    pub is_branch: bool,
    /// Immediate value, if present.
    pub immediate: Option<i64>,
    /// Branch target, if this is a branch.
    pub branch_target: Option<u64>,
}

// ─── DisasmOutput ─────────────────────────────────────────────────────────────

/// Output of the disassemble tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmOutput {
    /// Number of instructions decoded.
    pub count: usize,
    /// Decoded instructions.
    pub instructions: Vec<DecodedInstruction>,
    /// Full formatted text listing.
    pub listing: String,
    /// Base address used for decoding.
    pub base_address: u64,
    /// Total bytes consumed.
    pub bytes_consumed: usize,
    /// Whether the decode reached the end of the buffer without error.
    pub complete: bool,
    /// Statistics.
    pub stats: DisasmStats,
}

/// Summary statistics for a decoded block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisasmStats {
    /// Number of call instructions.
    pub call_count: usize,
    /// Number of return instructions.
    pub ret_count: usize,
    /// Number of branch instructions (excluding calls/rets).
    pub branch_count: usize,
    /// Histogram of mnemonic → count.
    pub mnemonic_histogram: HashMap<String, usize>,
}

impl DisasmStats {
    fn record(&mut self, insn: &DecodedInstruction) {
        if insn.is_call {
            self.call_count += 1;
        }
        if insn.is_ret {
            self.ret_count += 1;
        }
        if insn.is_branch && !insn.is_call && !insn.is_ret {
            self.branch_count += 1;
        }
        *self
            .mnemonic_histogram
            .entry(insn.mnemonic.clone())
            .or_insert(0) += 1;
    }
}

// ─── format_instructions() ────────────────────────────────────────────────────

/// Format a slice of decoded instructions into a text listing.
///
/// Each line has the form:
/// ```text
/// 00007FF6A1234000  48 89 E5           push rbp
/// ```
#[must_use]
pub fn format_instructions(insns: &[DecodedInstruction]) -> String {
    use std::fmt::Write as _;
    // Each line is roughly 16 + 2 + 20 + 2 + ~20 + 1 = ~61 bytes.
    let mut out = String::with_capacity(insns.len() * 64);
    for insn in insns {
        let _ = write!(
            out,
            "{:016X}  {:<20}  {}\n",
            insn.address, insn.bytes, insn.text
        );
    }
    out
}

// ─── Core disassembly ─────────────────────────────────────────────────────────

/// Perform disassembly of `data` starting at `offset` with the given parameters.
pub fn disassemble(
    data: &[u8],
    base_address: u64,
    bitness: u32,
    max_instructions: usize,
    offset: usize,
) -> DisasmOutput {
    let slice = if offset < data.len() {
        &data[offset..]
    } else {
        &[]
    };

    let decoder_ip = base_address.saturating_add(offset as u64);
    let mut decoder = Decoder::with_ip(bitness, slice, decoder_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("");
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);

    let mut instructions: Vec<DecodedInstruction> = Vec::new();
    let mut stats = DisasmStats::default();
    let mut insn = Instruction::default();
    let mut bytes_consumed = 0usize;
    let mut complete = true;

    while decoder.can_decode() && instructions.len() < max_instructions {
        decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            complete = false;
            break;
        }

        let len = insn.len() as u32;
        let ip = insn.ip();
        // Guard against ip < base_address (should not happen, but protect against it)
        let start = ip.saturating_sub(base_address) as usize;
        let end = start.saturating_add(len as usize);
        let raw = if end <= data.len() {
            &data[start..end]
        } else {
            &[]
        };

        let raw_hex = raw.iter().enumerate().fold(
            String::with_capacity(raw.len() * 3),
            |mut s, (i, b)| {
                use std::fmt::Write as _;
                if i > 0 { s.push(' '); }
                let _ = write!(s, "{b:02X}");
                s
            },
        );

        let opcode = if raw.len() >= 1 {
            let mut op = u32::from(raw[0]);
            if raw.len() >= 2 {
                op |= u32::from(raw[1]) << 8;
            }
            if raw.len() >= 3 {
                op |= u32::from(raw[2]) << 16;
            }
            if raw.len() >= 4 {
                op |= u32::from(raw[3]) << 24;
            }
            op
        } else {
            0
        };

        let mut text = String::new();
        formatter.format(&insn, &mut text);

        // Extract mnemonic (first word).
        let mnemonic = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();

        let flow = insn.flow_control();
        let is_call = matches!(
            flow,
            iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
        );
        let is_ret = matches!(flow, iced_x86::FlowControl::Return);
        let is_branch = matches!(
            flow,
            iced_x86::FlowControl::ConditionalBranch
                | iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::IndirectBranch
        ) || is_call;

        let immediate = extract_immediate(&insn);
        let branch_target = if is_branch || is_call {
            extract_near_branch(&insn)
        } else {
            None
        };

        let insn_info = DecodedInstruction {
            address: ip,
            length: len,
            bytes: raw_hex,
            mnemonic: mnemonic.clone(),
            text,
            opcode,
            is_call,
            is_ret,
            is_branch,
            immediate,
            branch_target,
        };
        stats.record(&insn_info);
        instructions.push(insn_info);
        bytes_consumed += len as usize;
    }

    let listing = format_instructions(&instructions);

    DisasmOutput {
        count: instructions.len(),
        instructions,
        listing,
        base_address,
        bytes_consumed,
        complete,
        stats,
    }
}

fn extract_immediate(insn: &Instruction) -> Option<i64> {
    use iced_x86::OpKind;
    for i in 0..insn.op_count() {
        match insn.op_kind(i) {
            OpKind::Immediate8 => return Some(i64::from(insn.immediate8() as i8)),
            OpKind::Immediate8_2nd => return Some(i64::from(insn.immediate8_2nd() as i8)),
            OpKind::Immediate16 => return Some(i64::from(insn.immediate16() as i16)),
            OpKind::Immediate32 => return Some(i64::from(insn.immediate32() as i32)),
            OpKind::Immediate64 => return Some(insn.immediate64() as i64),
            OpKind::Immediate8to32 => return Some(i64::from(insn.immediate8to32())),
            OpKind::Immediate8to64 => return Some(insn.immediate8to64()),
            OpKind::Immediate32to64 => return Some(insn.immediate32to64()),
            _ => {}
        }
    }
    None
}

fn extract_near_branch(insn: &Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    for i in 0..insn.op_count() {
        match insn.op_kind(i) {
            OpKind::NearBranch16 => return Some(u64::from(insn.near_branch16())),
            OpKind::NearBranch32 => return Some(u64::from(insn.near_branch32())),
            OpKind::NearBranch64 => return Some(insn.near_branch64()),
            _ => {}
        }
    }
    None
}

// ─── DisasmTool ──────────────────────────────────────────────────────────────

/// MCP tool: disassemble binary at an address.
///
/// Accepts `hex` (hex-encoded byte string) or `bytes` (integer array), plus
/// optional `base_address`, `bitness`, `max_instructions`, and `offset`.
pub struct DisasmTool;

impl DisasmTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "disassemble".to_owned(),
            description: "Disassemble binary bytes. Provide 'hex' (hex string) or 'bytes' (array). \
                          Optional: base_address (u64), bitness (16/32/64, default 64), \
                          max_instructions (default 256), offset (default 0)."
                .to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": { "type": "string", "description": "Hex-encoded bytes to disassemble" },
                    "bytes": {
                        "type": "array",
                        "items": { "type": "integer", "minimum": 0, "maximum": 255 },
                        "description": "Raw byte array"
                    },
                    "base_address": { "type": "integer", "description": "Base virtual address (default 0)" },
                    "bitness": { "type": "integer", "enum": [16, 32, 64], "description": "CPU bitness (default 64)" },
                    "max_instructions": { "type": "integer", "minimum": 1, "description": "Max instructions to decode" },
                    "offset": { "type": "integer", "minimum": 0, "description": "Byte offset into buffer" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DisasmTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = parse_disasm_input(&args)?;
        let data = input.resolve_bytes()?;

        if data.is_empty() {
            return Err(McpError::InvalidParams("empty byte buffer".into()));
        }

        let output = disassemble(
            &data,
            input.effective_base(),
            input.effective_bitness(),
            input.effective_max(),
            input.effective_offset(),
        );

        Ok(ToolResult {
            content: vec![rustre_mcp_server::ContentBlock::Text {
                text: output.listing.clone(),
            }],
            is_error: false,
        })
    }
}

fn parse_disasm_input(args: &Value) -> Result<DisasmInput, McpError> {
    Ok(DisasmInput {
        hex: args
            .get("hex")
            .and_then(Value::as_str)
            .map(str::to_owned),
        bytes: args.get("bytes").and_then(Value::as_array).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect()
        }),
        base_address: args
            .get("base_address")
            .and_then(Value::as_u64),
        bitness: args
            .get("bitness")
            .and_then(Value::as_u64)
            .map(|n| n as u32),
        max_instructions: args
            .get("max_instructions")
            .and_then(Value::as_u64)
            .map(|n| n as usize),
        offset: args
            .get("offset")
            .and_then(Value::as_u64)
            .map(|n| n as usize),
    })
}

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>, McpError> {
    let s = s.replace(' ', "").replace('\n', "").replace('\t', "");
    if !s.len().is_multiple_of(2) {
        return Err(McpError::InvalidParams("odd-length hex string".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| McpError::InvalidParams(format!("invalid hex at offset {i}")))?;
        out.push(byte);
    }
    Ok(out)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NOP: &[u8] = &[0x90];
    const RET: &[u8] = &[0xC3];
    const CALL_REL: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00]; // call +5

    #[test]
    fn disasm_nop() {
        let out = disassemble(NOP, 0x1000, 64, 256, 0);
        assert_eq!(out.count, 1);
        assert_eq!(out.instructions[0].mnemonic, "nop");
        assert_eq!(out.instructions[0].address, 0x1000);
    }

    #[test]
    fn disasm_ret() {
        let out = disassemble(RET, 0x2000, 64, 256, 0);
        assert_eq!(out.count, 1);
        assert!(out.instructions[0].is_ret);
        assert!(!out.instructions[0].is_call);
    }

    #[test]
    fn disasm_call() {
        let out = disassemble(CALL_REL, 0x0, 64, 256, 0);
        assert_eq!(out.count, 1);
        assert!(out.instructions[0].is_call);
    }

    #[test]
    fn disasm_with_offset() {
        let mut buf = vec![0x00u8]; // invalid-ish lead byte
        buf.extend_from_slice(NOP);
        let out = disassemble(&buf, 0, 64, 256, 1);
        assert_eq!(out.instructions[0].mnemonic, "nop");
    }

    #[test]
    fn format_instructions_format() {
        let insns = vec![DecodedInstruction {
            address: 0x1234,
            length: 1,
            bytes: "90".to_owned(),
            mnemonic: "nop".to_owned(),
            text: "nop".to_owned(),
            opcode: 0x90,
            is_call: false,
            is_ret: false,
            is_branch: false,
            immediate: None,
            branch_target: None,
        }];
        let listing = format_instructions(&insns);
        assert!(listing.contains("0000000000001234"));
        assert!(listing.contains("nop"));
    }

    #[test]
    fn hex_decode_spaces() {
        let v = hex_decode("48 89 E5").unwrap();
        assert_eq!(v, &[0x48, 0x89, 0xE5]);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("ZZ").is_err());
    }

    #[test]
    fn stats_counts() {
        let buf: Vec<u8> = {
            let mut v = vec![0x90u8]; // nop
            v.extend_from_slice(CALL_REL); // call
            v.push(0xC3); // ret
            v
        };
        let out = disassemble(&buf, 0, 64, 256, 0);
        assert_eq!(out.stats.call_count, 1);
        assert_eq!(out.stats.ret_count, 1);
    }
}

// ─── Multi-arch backend (Capstone) + helpers used by disasm.at/disasm.function ──

/// Map an arch slug to a capstone (arch, mode) pair.
fn capstone_arch_mode(arch: &str, bits: u32) -> Option<(capstone::arch::ArchOperand, ())> {
    // sentinel — concrete switch lives in `disassemble_multi_arch`
    let _ = (arch, bits);
    None
}

/// Disassemble `count` instructions starting at `start_va` from `slice`.
/// Dispatches to iced-x86 for `x86/x86_64`, Capstone for everything else.
/// Each instruction record carries `addr`, `bytes_hex`, `text`, `length`,
/// plus best-effort semantic fields (`regs_read` / `regs_written` / eflags) and
/// inline call-target / branch-target annotations (`call_target`).
#[must_use]
pub fn disassemble_multi_arch(
    arch: &str,
    bits: u32,
    slice: &[u8],
    start_va: u64,
    count: usize,
) -> Vec<serde_json::Value> {
    let arch_lc = arch.to_ascii_lowercase();
    // Probe via the arch/mode resolver — currently always None (capstone exposes
    // construction through its typed builder API), but the call wires the helper
    // into the public surface so it can be extended without a churn.
    let _ = capstone_arch_mode(&arch_lc, bits);
    match arch_lc.as_str() {
        "x86" | "x86_64" | "x64" | "amd64" | "i386" | "ia32" => {
            disasm_x86_iced(bits, slice, start_va, count)
        }
        _ => disasm_capstone(&arch_lc, bits, slice, start_va, count),
    }
}

/// Disassemble a function body starting at `start_va`, terminating on `ret`
/// or first invalid byte. Caps at `max_insns`.
#[must_use]
pub fn disassemble_function_body(
    arch: &str,
    bits: u32,
    slice: &[u8],
    start_va: u64,
    max_insns: usize,
) -> Vec<serde_json::Value> {
    let all = disassemble_multi_arch(arch, bits, slice, start_va, max_insns);
    // Trim at first ret-like terminator (best-effort, arch-agnostic via text match).
    let mut out = Vec::with_capacity(all.len());
    for ins in all {
        let is_ret = ins
            .get("text")
            .and_then(|v| v.as_str())
            .map(|t| {
                let t = t.trim_start();
                t == "ret" || t.starts_with("ret ") || t.starts_with("retq")
                    || t.starts_with("retn") || t.starts_with("bx lr") || t.starts_with("ret\t")
            })
            .unwrap_or(false);
        out.push(ins);
        if is_ret { break; }
    }
    out
}

/// Resolve a function start VA: if `addr` is a known function entry returns
/// it as-is; otherwise probe the first 16 bytes at `addr` for a recognised
/// x86 prologue (push rbp / push ebp / sub rsp,X / push rdi-rsi-rbx). The
/// caller is expected to pass the user-supplied VA — when the function table
/// has no entry there but the bytes form a valid prologue we still honour
/// the request rather than rejecting with "no function detected".
#[must_use]
pub fn resolve_function_start(load: &rustre_loader::RichLoadResult, addr: u64) -> u64 {
    // If loader exposes a function table, prefer that.
    if let Some((_, slice)) = rustre_decompiler::slice_at_va(load, addr) {
        if looks_like_x86_prologue(slice) {
            return addr;
        }
        // Scan back up to 32 bytes for a prologue start (handles caller passing
        // an address slightly inside the function header).
        let probe = 32usize.min(slice.len());
        for back in 1..=probe {
            if back as u64 > addr { break; }
            let probe_va = addr - back as u64;
            if let Some((_, s2)) = rustre_decompiler::slice_at_va(load, probe_va) {
                if looks_like_x86_prologue(s2) {
                    return probe_va;
                }
            }
        }
    }
    addr
}

fn looks_like_x86_prologue(s: &[u8]) -> bool {
    if s.is_empty() { return false; }
    // 55 48 89 E5      push rbp; mov rbp, rsp
    if s.len() >= 4 && s[0] == 0x55 && s[1] == 0x48 && s[2] == 0x89 && s[3] == 0xE5 {
        return true;
    }
    // 55 89 E5         push ebp; mov ebp, esp
    if s.len() >= 3 && s[0] == 0x55 && s[1] == 0x89 && s[2] == 0xE5 {
        return true;
    }
    // 48 83 EC ??      sub rsp, imm8
    if s.len() >= 4 && s[0] == 0x48 && s[1] == 0x83 && s[2] == 0xEC {
        return true;
    }
    // 48 81 EC ?? ?? ?? ??   sub rsp, imm32
    if s.len() >= 7 && s[0] == 0x48 && s[1] == 0x81 && s[2] == 0xEC {
        return true;
    }
    // 53 / 56 / 57     push rbx/rsi/rdi (callee-saved prologue start)
    if matches!(s[0], 0x53 | 0x55 | 0x56 | 0x57) {
        return true;
    }
    // 40 53 / 40 55 / 40 56 / 40 57    push r12-r15 via REX
    if s.len() >= 2 && s[0] == 0x40 && matches!(s[1], 0x53 | 0x55 | 0x56 | 0x57) {
        return true;
    }
    // 41 54 / 41 55 / 41 56 / 41 57    push r12/r13/r14/r15
    if s.len() >= 2 && s[0] == 0x41 && matches!(s[1], 0x54 | 0x55 | 0x56 | 0x57) {
        return true;
    }
    false
}

fn disasm_x86_iced(bits: u32, slice: &[u8], start_va: u64, count: usize) -> Vec<serde_json::Value> {
    use iced_x86::Formatter as _;
    struct StrOut(String);
    impl iced_x86::FormatterOutput for StrOut {
        fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
            self.0.push_str(text);
        }
    }

    let mut out = Vec::with_capacity(count);
    let mut cur = 0usize;
    while cur < slice.len() && out.len() < count {
        let Some(iced) =
            rustre_arch_x86::X86LiftAdapter::decode_one_iced(bits, &slice[cur..], start_va + cur as u64)
        else { break };
        let mut fmt = iced_x86::IntelFormatter::new();
        fmt.options_mut().set_space_after_operand_separator(true);
        let mut s = StrOut(String::new());
        fmt.format(&iced, &mut s);
        let len = iced.len();
        let bytes_hex = bytes_to_hex(&slice[cur..cur + len]);

        // Semantic info via iced.
        let mut regs_read = Vec::<String>::new();
        let mut regs_written = Vec::<String>::new();
        let info_factory = iced_x86::InstructionInfoFactory::new();
        // InstructionInfoFactory borrows mutably — recreate per-instruction.
        let mut factory = info_factory;
        let info = factory.info(&iced);
        for r in info.used_registers() {
            let name = format!("{:?}", r.register());
            match r.access() {
                iced_x86::OpAccess::Read | iced_x86::OpAccess::CondRead => {
                    regs_read.push(name);
                }
                iced_x86::OpAccess::Write
                | iced_x86::OpAccess::CondWrite
                | iced_x86::OpAccess::ReadWrite
                | iced_x86::OpAccess::ReadCondWrite => {
                    regs_written.push(name.clone());
                    if matches!(r.access(), iced_x86::OpAccess::ReadWrite | iced_x86::OpAccess::ReadCondWrite) {
                        regs_read.push(name);
                    }
                }
                _ => {}
            }
        }
        // EFLAGS effects.
        let mut eflags = serde_json::Map::new();
        let w = iced.rflags_written();
        let r = iced.rflags_read();
        let m = iced.rflags_modified();
        let u = iced.rflags_undefined();
        let cl = iced.rflags_cleared();
        let st = iced.rflags_set();
        let flag_str = |bits: u32| {
            let mut v = Vec::<&'static str>::new();
            if bits & iced_x86::RflagsBits::CF != 0 { v.push("CF"); }
            if bits & iced_x86::RflagsBits::PF != 0 { v.push("PF"); }
            if bits & iced_x86::RflagsBits::AF != 0 { v.push("AF"); }
            if bits & iced_x86::RflagsBits::ZF != 0 { v.push("ZF"); }
            if bits & iced_x86::RflagsBits::SF != 0 { v.push("SF"); }
            if bits & iced_x86::RflagsBits::OF != 0 { v.push("OF"); }
            if bits & iced_x86::RflagsBits::DF != 0 { v.push("DF"); }
            v
        };
        eflags.insert("read".into(),     serde_json::json!(flag_str(r)));
        eflags.insert("written".into(),  serde_json::json!(flag_str(w)));
        eflags.insert("modified".into(), serde_json::json!(flag_str(m)));
        eflags.insert("undefined".into(),serde_json::json!(flag_str(u)));
        eflags.insert("cleared".into(),  serde_json::json!(flag_str(cl)));
        eflags.insert("set".into(),      serde_json::json!(flag_str(st)));

        // Inline call/branch-target annotation (IDA-style).
        let mut call_target: Option<u64> = None;
        let mut is_call = false;
        let mut is_branch = false;
        match iced.flow_control() {
            iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall => {
                is_call = true;
                if iced.op0_kind() == iced_x86::OpKind::NearBranch64
                    || iced.op0_kind() == iced_x86::OpKind::NearBranch32
                    || iced.op0_kind() == iced_x86::OpKind::NearBranch16
                {
                    call_target = Some(iced.near_branch_target());
                }
            }
            iced_x86::FlowControl::ConditionalBranch
            | iced_x86::FlowControl::UnconditionalBranch
            | iced_x86::FlowControl::IndirectBranch => {
                is_branch = true;
                call_target = Some(iced.near_branch_target());
            }
            _ => {}
        }

        let mut text = s.0;
        if let Some(t) = call_target {
            // Append IDA-style annotation only when it isn't already present.
            let tag = format!("; -> 0x{t:x}");
            if !text.contains(&tag) {
                text.push_str("    ");
                text.push_str(&tag);
            }
        }

        let mut rec = serde_json::Map::new();
        rec.insert("addr".into(),         serde_json::json!(format!("{:#x}", start_va + cur as u64)));
        rec.insert("address".into(),      serde_json::json!(start_va + cur as u64));
        rec.insert("bytes".into(),        serde_json::json!(bytes_hex.clone()));
        rec.insert("bytes_hex".into(),    serde_json::json!(bytes_hex));
        rec.insert("text".into(),         serde_json::json!(text));
        rec.insert("length".into(),       serde_json::json!(len));
        rec.insert("mnemonic".into(),     serde_json::json!(format!("{:?}", iced.mnemonic()).to_lowercase()));
        rec.insert("is_call".into(),      serde_json::json!(is_call));
        rec.insert("is_branch".into(),    serde_json::json!(is_branch));
        if let Some(t) = call_target {
            rec.insert("call_target".into(), serde_json::json!(t));
            rec.insert("call_target_hex".into(), serde_json::json!(format!("{:#x}", t)));
        }
        rec.insert("regs_read".into(),    serde_json::json!(regs_read));
        rec.insert("regs_written".into(), serde_json::json!(regs_written));
        rec.insert("eflags".into(),       serde_json::Value::Object(eflags));

        out.push(serde_json::Value::Object(rec));
        cur += len;
    }
    out
}

fn disasm_capstone(arch: &str, bits: u32, slice: &[u8], start_va: u64, count: usize) -> Vec<serde_json::Value> {
    use capstone::prelude::*;

    // Build a Capstone instance per arch.
    let cs_res: Result<Capstone, _> = match arch {
        "arm" | "arm32" => Capstone::new()
            .arm()
            // Default to classic ARM; only switch to Thumb when caller asks
            // for it via bits==16 (treating bits as a Thumb sentinel).
            .mode(if bits == 16 { capstone::arch::arm::ArchMode::Thumb } else { capstone::arch::arm::ArchMode::Arm })
            .detail(true)
            .build(),
        "thumb" => Capstone::new()
            .arm()
            .mode(capstone::arch::arm::ArchMode::Thumb)
            .detail(true)
            .build(),
        "arm64" | "aarch64" => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        "mips" => Capstone::new()
            .mips()
            .mode(if bits == 64 { capstone::arch::mips::ArchMode::Mips64 } else { capstone::arch::mips::ArchMode::Mips32 })
            .detail(true)
            .build(),
        "mips64" => Capstone::new()
            .mips()
            .mode(capstone::arch::mips::ArchMode::Mips64)
            .detail(true)
            .build(),
        "riscv" | "riscv32" | "riscv64" => Capstone::new()
            .riscv()
            .mode(if bits == 32 { capstone::arch::riscv::ArchMode::RiscV32 } else { capstone::arch::riscv::ArchMode::RiscV64 })
            .detail(true)
            .build(),
        "ppc" | "powerpc" | "ppc32" | "ppc64" => Capstone::new()
            .ppc()
            .mode(if bits == 64 { capstone::arch::ppc::ArchMode::Mode64 } else { capstone::arch::ppc::ArchMode::Mode32 })
            .detail(true)
            .build(),
        "sparc" => Capstone::new()
            .sparc()
            .mode(capstone::arch::sparc::ArchMode::Default)
            .detail(true)
            .build(),
        "m68k" | "68k" => Capstone::new()
            .m68k()
            .mode(capstone::arch::m68k::ArchMode::M68k040)
            .detail(true)
            .build(),
        "wasm" => {
            // No native Capstone wasm; surface a clear sentinel.
            return vec![serde_json::json!({
                "addr": format!("{:#x}", start_va),
                "text": "; wasm decode requires rustre-arch-wasm front-end",
                "arch": "wasm",
                "error": "wasm_not_supported_in_capstone_backend",
                "supported_arches": supported_arches(),
            })];
        }
        other => {
            return vec![serde_json::json!({
                "addr": format!("{:#x}", start_va),
                "text": format!("; unsupported arch '{other}'"),
                "error": "unknown_arch",
                "supported_arches": supported_arches(),
            })];
        }
    };
    let cs = match cs_res {
        Ok(c) => c,
        Err(e) => {
            return vec![serde_json::json!({
                "addr": format!("{:#x}", start_va),
                "error": format!("capstone init failed: {e}"),
            })];
        }
    };

    let insns = match cs.disasm_count(slice, start_va, count) {
        Ok(v) => v,
        Err(e) => return vec![serde_json::json!({
            "addr": format!("{:#x}", start_va),
            "error": format!("capstone decode failed: {e}"),
        })],
    };

    let mut out = Vec::with_capacity(insns.len());
    for i in insns.iter() {
        let mnemonic = i.mnemonic().unwrap_or("").to_string();
        let op_str   = i.op_str().unwrap_or("").to_string();
        let text     = if op_str.is_empty() { mnemonic.clone() } else { format!("{} {}", mnemonic, op_str) };
        let bytes_hex = bytes_to_hex(i.bytes());

        // Semantic info if details enabled.
        let mut regs_read = Vec::<String>::new();
        let mut regs_written = Vec::<String>::new();
        let mut groups = Vec::<String>::new();
        if let Ok(detail) = cs.insn_detail(i) {
            for r in detail.regs_read() {
                if let Some(name) = cs.reg_name(*r) { regs_read.push(name); }
            }
            for r in detail.regs_write() {
                if let Some(name) = cs.reg_name(*r) { regs_written.push(name); }
            }
            for g in detail.groups() {
                if let Some(name) = cs.group_name(*g) { groups.push(name); }
            }
        }

        out.push(serde_json::json!({
            "addr":         format!("{:#x}", i.address()),
            "address":      i.address(),
            "bytes":        bytes_hex.clone(),
            "bytes_hex":    bytes_hex,
            "mnemonic":     mnemonic,
            "operands":     op_str,
            "text":         text,
            "length":       i.bytes().len(),
            "regs_read":    regs_read,
            "regs_written": regs_written,
            "groups":       groups,
        }));
    }
    out
}

/// List of arch slugs accepted by [`disassemble_multi_arch`]. Used in
/// error payloads and exposed publicly so wire tools can advertise the
/// matrix without duplicating the list.
#[must_use]
pub fn supported_arches() -> Vec<&'static str> {
    vec![
        "x86", "x86_64", "x64", "amd64", "i386",
        "arm", "arm32", "thumb",
        "arm64", "aarch64",
        "mips", "mips64",
        "riscv", "riscv32", "riscv64",
        "ppc", "ppc32", "ppc64", "powerpc",
        "sparc",
        "m68k", "68k",
        "wasm",
    ]
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02X}", b);
    }
    s
}

