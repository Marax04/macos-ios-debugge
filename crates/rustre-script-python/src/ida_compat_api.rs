//! IDA Python API compatibility layer.
//!
//! Provides `RustRE` implementations of the most commonly used IDA Python
//! functions so that existing IDA scripts can be run (with minor changes)
//! on top of the `RustRE` analysis engine.
//!
//! The mapping follows the IDA Pro 7.x naming convention.

#![allow(non_snake_case, reason = "IDA Pro 7.x API compatibility: existing IDA Python scripts call GetFunctionName/MakeCode by those exact names, so renaming would remove the only reason this module exists")]

use std::collections::BTreeMap;

pub use std::fmt;

// ─── Segment ──────────────────────────────────────────────────────────────────

/// A binary segment / section.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment name (e.g. ".text", "CODE").
    pub name: String,
    /// Start address (inclusive).
    pub start_ea: u64,
    /// End address (exclusive).
    pub end_ea: u64,
    /// Raw bytes of the segment.
    pub data: Vec<u8>,
}

impl Segment {
    /// Create a segment with a data payload.
    #[must_use]
    pub fn new(name: impl Into<String>, start_ea: u64, data: Vec<u8>) -> Self {
        let end_ea = start_ea + data.len() as u64;
        Self {
            name: name.into(),
            start_ea,
            end_ea,
            data,
        }
    }

    /// Empty segment (no data, just address range).
    ///
    /// # Panics
    ///
    /// Panics if `size` exceeds `usize::MAX` (only possible on 32-bit targets).
    #[must_use]
    pub fn empty(name: impl Into<String>, start_ea: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            start_ea,
            end_ea: start_ea.saturating_add(size),
            data: vec![0u8; usize::try_from(size).expect("segment size exceeds usize")],
        }
    }

    /// Read a byte at absolute address `ea`, returning 0xFF on out-of-bounds.
    #[must_use]
    pub fn read_byte(&self, ea: u64) -> u8 {
        if ea < self.start_ea || ea >= self.end_ea {
            return 0xFF;
        }
        self.data[usize::try_from(ea - self.start_ea).unwrap_or(0)]
    }

    /// Read a LE u16 at `ea`.
    #[must_use]
    pub fn read_word(&self, ea: u64) -> u16 {
        let lo = u16::from(self.read_byte(ea));
        let hi = u16::from(self.read_byte(ea.saturating_add(1)));
        lo | (hi << 8)
    }

    /// Read a LE u32 at `ea`.
    #[must_use]
    pub fn read_dword(&self, ea: u64) -> u32 {
        let lo = u32::from(self.read_word(ea));
        let hi = u32::from(self.read_word(ea.saturating_add(2)));
        lo | (hi << 16)
    }

    /// Read a LE u64 at `ea`.
    #[must_use]
    pub fn read_qword(&self, ea: u64) -> u64 {
        let lo = u64::from(self.read_dword(ea));
        let hi = u64::from(self.read_dword(ea.saturating_add(4)));
        lo | (hi << 32)
    }
}

// ─── Function ─────────────────────────────────────────────────────────────────

/// A function as seen by the IDA compat layer.
#[derive(Debug, Clone)]
pub struct IdaFunction {
    /// Function start address.
    pub start_ea: u64,
    /// Function end address (exclusive).
    pub end_ea: u64,
    /// Function name.
    pub name: String,
    /// Decompiled / disassembly comment.
    pub comment: Option<String>,
}

impl IdaFunction {
    /// Create a new function record.
    #[must_use]
    pub fn new(start_ea: u64, end_ea: u64, name: impl Into<String>) -> Self {
        Self {
            start_ea,
            end_ea,
            name: name.into(),
            comment: None,
        }
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end_ea.saturating_sub(self.start_ea)
    }
}

// ─── Instruction ──────────────────────────────────────────────────────────────

/// A decoded instruction stub (mnemonic + operands).
#[derive(Debug, Clone)]
pub struct IdaInstruction {
    /// Effective address.
    pub ea: u64,
    /// Mnemonic string.
    pub mnem: String,
    /// Operand strings (up to 6).
    pub ops: Vec<String>,
    /// Operand values (numeric).
    pub op_values: Vec<u64>,
    /// Instruction size in bytes.
    pub size: u8,
}

impl IdaInstruction {
    /// Create an instruction.
    #[must_use]
    pub fn new(
        ea: u64,
        mnem: impl Into<String>,
        ops: Vec<String>,
        op_values: Vec<u64>,
        size: u8,
    ) -> Self {
        Self {
            ea,
            mnem: mnem.into(),
            ops,
            op_values,
            size,
        }
    }

    /// Get operand string at index `n`.
    #[must_use]
    pub fn op_str(&self, n: usize) -> &str {
        self.ops.get(n).map_or("", String::as_str)
    }

    /// Get operand value at index `n`.
    #[must_use]
    pub fn op_value(&self, n: usize) -> u64 {
        self.op_values.get(n).copied().unwrap_or(u64::MAX)
    }
}

// ─── IdaCompatApi ─────────────────────────────────────────────────────────────

/// `RustRE` implementation of the common IDA Python API surface.
///
/// Callers first populate segments, functions and instructions, then call
/// the IDA-compatible methods to query them.
#[derive(Debug, Default)]
pub struct IdaCompatApi {
    /// Loaded segments, by start address.
    segments: BTreeMap<u64, Segment>,
    /// Functions, by start address.
    functions: BTreeMap<u64, IdaFunction>,
    /// Instruction cache, by EA.
    instructions: BTreeMap<u64, IdaInstruction>,
    /// Name database: `name → ea`.
    names: BTreeMap<String, u64>,
    /// Comment database: `ea → comment`.
    comments: BTreeMap<u64, String>,
}

impl IdaCompatApi {
    /// Create an empty API instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Loader helpers ────────────────────────────────────────────────────────

    /// Register a segment.
    pub fn add_segment(&mut self, seg: Segment) {
        self.segments.insert(seg.start_ea, seg);
    }

    /// Register a function.
    pub fn add_function(&mut self, func: IdaFunction) {
        self.names.insert(func.name.clone(), func.start_ea);
        self.functions.insert(func.start_ea, func);
    }

    /// Register an instruction.
    pub fn add_instruction(&mut self, insn: IdaInstruction) {
        self.instructions.insert(insn.ea, insn);
    }

    // ── IDA API: name / address ───────────────────────────────────────────────

    /// `MakeName(ea, name)` — assign a name to an address.
    pub fn MakeName(&mut self, ea: u64, name: impl Into<String>) -> bool {
        let name = name.into();
        self.names.insert(name, ea);
        true
    }

    /// `GetFunctionName(ea)` — return the name of the function containing `ea`.
    #[must_use]
    pub fn GetFunctionName(&self, ea: u64) -> String {
        if let Some((_, f)) = self.functions.range(..=ea).next_back()
            && ea < f.end_ea {
                return f.name.clone();
            }
        String::new()
    }

    /// `LocByName(name)` — look up an address by name.  Returns `u64::MAX`
    /// (IDA's `BADADDR`) if not found.
    #[must_use]
    pub fn LocByName(&self, name: &str) -> u64 {
        self.names.get(name).copied().unwrap_or(u64::MAX)
    }

    // ── IDA API: disassembly ──────────────────────────────────────────────────

    /// `GetMnem(ea)` — return the mnemonic string for the instruction at `ea`.
    #[must_use]
    pub fn GetMnem(&self, ea: u64) -> String {
        self.instructions
            .get(&ea)
            .map(|i| i.mnem.clone())
            .unwrap_or_default()
    }

    /// `GetOperandValue(ea, n)` — return the numeric value of operand `n`.
    #[must_use]
    pub fn GetOperandValue(&self, ea: u64, n: usize) -> u64 {
        self.instructions
            .get(&ea)
            .map_or(u64::MAX, |i| i.op_value(n))
    }

    /// `GetOpnd(ea, n)` — return the operand string for operand `n`.
    #[must_use]
    pub fn GetOpnd(&self, ea: u64, n: usize) -> String {
        self.instructions
            .get(&ea)
            .map(|i| i.op_str(n).to_string())
            .unwrap_or_default()
    }

    // ── IDA API: comments ─────────────────────────────────────────────────────

    /// `Comment(ea, comment)` — set a comment at `ea`.
    pub fn Comment(&mut self, ea: u64, comment: impl Into<String>) {
        self.comments.insert(ea, comment.into());
    }

    /// `GetCommentEx(ea, repeatable)` — get the comment at `ea`.
    #[must_use]
    pub fn GetCommentEx(&self, ea: u64, _repeatable: bool) -> String {
        self.comments.get(&ea).cloned().unwrap_or_default()
    }

    // ── IDA API: iteration ────────────────────────────────────────────────────

    /// `Functions(start, end)` — iterate function start addresses in range.
    #[must_use]
    pub fn Functions(&self, start: u64, end: u64) -> Vec<u64> {
        self.functions
            .range(start..end)
            .map(|(&ea, _)| ea)
            .collect()
    }

    /// `Heads(start, end)` — iterate instruction addresses in range.
    #[must_use]
    pub fn Heads(&self, start: u64, end: u64) -> Vec<u64> {
        self.instructions
            .range(start..end)
            .map(|(&ea, _)| ea)
            .collect()
    }

    // ── IDA API: segments ─────────────────────────────────────────────────────

    /// `SegStart(ea)` — start address of the segment containing `ea`.
    #[must_use]
    pub fn SegStart(&self, ea: u64) -> u64 {
        self.find_segment(ea)
            .map_or(u64::MAX, |s| s.start_ea)
    }

    /// `SegEnd(ea)` — end address of the segment containing `ea`.
    #[must_use]
    pub fn SegEnd(&self, ea: u64) -> u64 {
        self.find_segment(ea).map_or(u64::MAX, |s| s.end_ea)
    }

    /// `SegName(ea)` — name of the segment containing `ea`.
    #[must_use]
    pub fn SegName(&self, ea: u64) -> String {
        self.find_segment(ea)
            .map(|s| s.name.clone())
            .unwrap_or_default()
    }

    // ── IDA API: memory reads ─────────────────────────────────────────────────

    /// `Byte(ea)` — read one byte.
    #[must_use]
    pub fn Byte(&self, ea: u64) -> u8 {
        self.find_segment(ea)
            .map_or(0xFF, |s| s.read_byte(ea))
    }

    /// `Word(ea)` — read two bytes LE.
    #[must_use]
    pub fn Word(&self, ea: u64) -> u16 {
        self.find_segment(ea)
            .map_or(0xFFFF, |s| s.read_word(ea))
    }

    /// `Dword(ea)` — read four bytes LE.
    #[must_use]
    pub fn Dword(&self, ea: u64) -> u32 {
        self.find_segment(ea)
            .map_or(0xFFFF_FFFF, |s| s.read_dword(ea))
    }

    /// `Qword(ea)` — read eight bytes LE.
    #[must_use]
    pub fn Qword(&self, ea: u64) -> u64 {
        self.find_segment(ea)
            .map_or(u64::MAX, |s| s.read_qword(ea))
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn find_segment(&self, ea: u64) -> Option<&Segment> {
        self.segments
            .range(..=ea)
            .next_back()
            .map(|(_, s)| s)
            .filter(|s| ea < s.end_ea)
    }
}

// ─── IdaDbgApi ────────────────────────────────────────────────────────────────

/// Stub of IDA's debugger API (idc.GetRegValue, `RunTo`, etc.).
///
/// All methods are stubs that return default/empty values so that IDA scripts
/// using the debugger API compile and run without panicking.
#[derive(Debug, Default)]
pub struct IdaDbgApi {
    /// Simulated register values.
    registers: BTreeMap<String, u64>,
    /// Simulated breakpoints (ea → active).
    breakpoints: BTreeMap<u64, bool>,
}

impl IdaDbgApi {
    /// Create a debug API stub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `GetRegValue(name)` — read a register value.
    #[must_use]
    pub fn GetRegValue(&self, name: &str) -> u64 {
        self.registers.get(name).copied().unwrap_or(0)
    }

    /// `SetRegValue(name, value)` — set a simulated register value.
    pub fn SetRegValue(&mut self, name: impl Into<String>, value: u64) {
        self.registers.insert(name.into(), value);
    }

    /// `AddBpt(ea)` — add a breakpoint stub.
    pub fn AddBpt(&mut self, ea: u64) -> bool {
        self.breakpoints.insert(ea, true);
        true
    }

    /// `DelBpt(ea)` — remove a breakpoint stub.
    pub fn DelBpt(&mut self, ea: u64) -> bool {
        self.breakpoints.remove(&ea).is_some()
    }

    /// `CheckBpt(ea)` — check if a breakpoint is set.
    #[must_use]
    pub fn CheckBpt(&self, ea: u64) -> bool {
        self.breakpoints.get(&ea).copied().unwrap_or(false)
    }

    /// `RunTo(ea)` — stub; returns true.
    #[must_use]
    pub const fn RunTo(&self, _ea: u64) -> bool {
        true
    }

    /// `StepInto()` — stub.
    pub const fn StepInto(&self) {}

    /// `StepOver()` — stub.
    pub const fn StepOver(&self) {}

    /// `GetProcessState()` — stub; returns -1 (not debugging).
    #[must_use]
    pub const fn GetProcessState(&self) -> i32 {
        -1
    }
}

// ─── ScriptEnvironment ────────────────────────────────────────────────────────

/// Combined IDA-compatible scripting environment.
#[derive(Debug, Default)]
pub struct ScriptEnvironment {
    /// Core analysis API.
    pub idc: IdaCompatApi,
    /// Debugger API stubs.
    pub dbg: IdaDbgApi,
}

impl ScriptEnvironment {
    /// Create a new environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_api() -> IdaCompatApi {
        let mut api = IdaCompatApi::new();
        let seg = Segment::new(
            ".text",
            0x1000,
            vec![0x55, 0x48, 0x89, 0xE5, 0xC3, 0xFF, 0x00, 0x01],
        );
        api.add_segment(seg);
        let func = IdaFunction::new(0x1000, 0x1010, "main");
        api.add_function(func);
        let insn = IdaInstruction::new(0x1000, "PUSH", vec!["RBP".to_string()], vec![0], 1);
        api.add_instruction(insn);
        api
    }

    // ── MakeName / LocByName ──────────────────────────────────────────────────

    #[test]
    fn make_name_and_loc_by_name() {
        let mut api = IdaCompatApi::new();
        assert!(api.MakeName(0x4000, "sub_4000"));
        assert_eq!(api.LocByName("sub_4000"), 0x4000);
    }

    #[test]
    fn loc_by_name_missing() {
        let api = IdaCompatApi::new();
        assert_eq!(api.LocByName("missing"), u64::MAX);
    }

    // ── GetFunctionName ───────────────────────────────────────────────────────

    #[test]
    fn get_function_name_in_range() {
        let api = make_api();
        assert_eq!(api.GetFunctionName(0x1000), "main");
        assert_eq!(api.GetFunctionName(0x1005), "main");
    }

    #[test]
    fn get_function_name_out_of_range() {
        let api = make_api();
        assert_eq!(api.GetFunctionName(0x5000), "");
    }

    // ── GetMnem ───────────────────────────────────────────────────────────────

    #[test]
    fn get_mnem_present() {
        let api = make_api();
        assert_eq!(api.GetMnem(0x1000), "PUSH");
    }

    #[test]
    fn get_mnem_missing() {
        let api = make_api();
        assert_eq!(api.GetMnem(0xDEAD), "");
    }

    // ── GetOperandValue / GetOpnd ─────────────────────────────────────────────

    #[test]
    fn get_operand_value() {
        let api = make_api();
        assert_eq!(api.GetOperandValue(0x1000, 0), 0);
        assert_eq!(api.GetOperandValue(0x1000, 5), u64::MAX); // out of range → BADADDR
    }

    #[test]
    fn get_opnd_string() {
        let api = make_api();
        assert_eq!(api.GetOpnd(0x1000, 0), "RBP");
    }

    // ── Comment ───────────────────────────────────────────────────────────────

    #[test]
    fn comment_set_get() {
        let mut api = IdaCompatApi::new();
        api.Comment(0x1234, "my comment");
        assert_eq!(api.GetCommentEx(0x1234, false), "my comment");
    }

    #[test]
    fn comment_missing() {
        let api = IdaCompatApi::new();
        assert_eq!(api.GetCommentEx(0xFFFF, false), "");
    }

    // ── Functions / Heads ─────────────────────────────────────────────────────

    #[test]
    fn functions_range() {
        let api = make_api();
        let funcs = api.Functions(0x0, 0x2000);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0], 0x1000);
    }

    #[test]
    fn functions_empty_range() {
        let api = make_api();
        let funcs = api.Functions(0x5000, 0x6000);
        assert!(funcs.is_empty());
    }

    #[test]
    fn heads_range() {
        let api = make_api();
        let heads = api.Heads(0x1000, 0x1010);
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0], 0x1000);
    }

    // ── SegStart / SegEnd / SegName ───────────────────────────────────────────

    #[test]
    fn seg_start_end() {
        let api = make_api();
        assert_eq!(api.SegStart(0x1002), 0x1000);
        assert_eq!(api.SegEnd(0x1002), 0x1008);
    }

    #[test]
    fn seg_name() {
        let api = make_api();
        assert_eq!(api.SegName(0x1000), ".text");
    }

    #[test]
    fn seg_start_not_found() {
        let api = make_api();
        assert_eq!(api.SegStart(0xDEAD), u64::MAX);
    }

    // ── Byte / Word / Dword / Qword ───────────────────────────────────────────

    #[test]
    fn byte_read() {
        let api = make_api();
        assert_eq!(api.Byte(0x1000), 0x55);
    }

    #[test]
    fn word_read_le() {
        let api = make_api();
        // bytes: 0x55 0x48 → LE u16 = 0x4855
        assert_eq!(api.Word(0x1000), 0x4855);
    }

    #[test]
    fn dword_read_le() {
        let api = make_api();
        // 0x55 0x48 0x89 0xE5 → LE = 0xE5894855
        assert_eq!(api.Dword(0x1000), 0xE589_4855);
    }

    #[test]
    fn qword_read_le() {
        let api = make_api();
        let q = api.Qword(0x1000);
        assert_ne!(q, u64::MAX);
    }

    #[test]
    fn byte_out_of_segment() {
        let api = make_api();
        assert_eq!(api.Byte(0xDEAD), 0xFF);
    }

    // ── IdaDbgApi ─────────────────────────────────────────────────────────────

    #[test]
    fn dbg_set_get_register() {
        let mut dbg = IdaDbgApi::new();
        dbg.SetRegValue("RIP", 0xDEAD_BEEF);
        assert_eq!(dbg.GetRegValue("RIP"), 0xDEAD_BEEF);
    }

    #[test]
    fn dbg_register_missing() {
        let dbg = IdaDbgApi::new();
        assert_eq!(dbg.GetRegValue("XMM99"), 0);
    }

    #[test]
    fn dbg_add_del_bpt() {
        let mut dbg = IdaDbgApi::new();
        assert!(dbg.AddBpt(0x1000));
        assert!(dbg.CheckBpt(0x1000));
        assert!(dbg.DelBpt(0x1000));
        assert!(!dbg.CheckBpt(0x1000));
    }

    #[test]
    fn dbg_run_to_stub() {
        let dbg = IdaDbgApi::new();
        assert!(dbg.RunTo(0x1000));
    }

    #[test]
    fn dbg_process_state_not_debugging() {
        let dbg = IdaDbgApi::new();
        assert_eq!(dbg.GetProcessState(), -1);
    }

    // ── Segment ───────────────────────────────────────────────────────────────

    #[test]
    fn segment_size() {
        let seg = Segment::empty(".bss", 0x3000, 0x100);
        assert_eq!(seg.end_ea, 0x3100);
    }

    #[test]
    fn segment_read_boundary() {
        let seg = Segment::new(".data", 0x2000, vec![0xAA, 0xBB]);
        assert_eq!(seg.read_byte(0x2001), 0xBB);
        assert_eq!(seg.read_byte(0x2002), 0xFF); // out of range
    }

    // ── ScriptEnvironment ─────────────────────────────────────────────────────

    #[test]
    fn script_env_default() {
        let env = ScriptEnvironment::new();
        assert_eq!(env.dbg.GetProcessState(), -1);
    }
}
