//! MHCDE-specific deobfuscation passes: mixed-mode obfuscation removal,
//! handler-based CFG reconstruction, and control-flow unflattening.

use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};

use crate::control_flow_graph_builder::{Addr, BasicBlock, CfgBuilder, ControlFlowGraph};
use crate::dataflow_propagator::{
    DataflowPropagator, VarId,
};

// ─── Pass result types ───────────────────────────────────────────────────────

/// Confidence of a pass finding.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(pub f32);

impl Confidence {
    pub const HIGH: Self = Self(0.9);
    pub const MEDIUM: Self = Self(0.6);
    pub const LOW: Self = Self(0.3);

    #[must_use]
    pub fn is_reliable(self) -> bool {
        self.0 >= 0.6
    }
}

/// A single transformation produced by an MHCDE pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassTransform {
    /// Byte offset of the transformation.
    pub offset: usize,
    /// Number of bytes to replace.
    pub length: usize,
    /// Replacement bytes (NOP-fill if empty).
    pub replacement: Vec<u8>,
    /// Human description.
    pub description: String,
    /// Confidence score.
    pub confidence: Confidence,
}

impl PassTransform {
    /// Create a NOP-fill transform.
    pub fn nop(offset: usize, length: usize, description: impl Into<String>, conf: Confidence) -> Self {
        Self {
            offset,
            length,
            replacement: vec![0x90; length],
            description: description.into(),
            confidence: conf,
        }
    }

    /// Apply this transform to a mutable buffer.
    pub fn apply(&self, buf: &mut [u8]) -> bool {
        let end = self.offset + self.length;
        if end > buf.len() {
            return false;
        }
        if self.replacement.is_empty() {
            for b in &mut buf[self.offset..end] {
                *b = 0x90;
            }
        } else {
            let rlen = self.replacement.len().min(self.length);
            buf[self.offset..self.offset + rlen].copy_from_slice(&self.replacement[..rlen]);
            for b in &mut buf[self.offset + rlen..end] {
                *b = 0x90;
            }
        }
        true
    }
}

/// Result of running a single MHCDE pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    pub pass_name: String,
    pub transforms: Vec<PassTransform>,
    pub findings: Vec<String>,
    pub confidence: Confidence,
}

impl PassResult {
    pub fn new(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            transforms: Vec::new(),
            findings: Vec::new(),
            confidence: Confidence::LOW,
        }
    }

    pub fn push(&mut self, t: PassTransform) {
        self.confidence.0 = self.confidence.0.max(t.confidence.0);
        self.transforms.push(t);
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.findings.push(s.into());
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.transforms.iter().map(|t| t.length).sum()
    }
}

// ─── Pass 1: Mixed-mode obfuscation removal ───────────────────────────────────
//
// Detects interleaved 16-bit/32-bit prefix obfuscation: sequences that use
// operand-size prefix (66h) or address-size prefix (67h) to make disassemblers
// decode a different instruction than the CPU executes. The canonical pattern is:
//
//   66 EB 01 <real_byte>     ; 66-prefixed short jump skips 1 byte (16-bit)
//   90                       ; <- CPU skips this NOP
//
// In practice mixed-mode obfuscators also insert:
//   66 90  (16-bit NOP)
//   67 90  (address-size NOP — always 1-byte instruction in 64-bit mode)
//   66 66 ...  (double prefix — legal for string ops, junk here)

#[derive(Debug, Default, Clone)]
pub struct MixedModePass;

impl MixedModePass {
    /// Scan `data` and return a [`PassResult`].
    #[must_use]
    pub fn run(&self, data: &[u8]) -> PassResult {
        let mut result = PassResult::new("mixed-mode-obfuscation");
        let mut i = 0;
        let mut claimed: Vec<(usize, usize)> = Vec::new();

        while i + 1 < data.len() {
            // Pattern 1: 66 EB rel8 <dead_byte>
            if data[i] == 0x66 && data[i + 1] == 0xEB && i + 3 < data.len() {
                // The 16-bit short jump at [i+1] skips rel8 bytes in 16-bit operand mode.
                // The CPU will execute [i] as 66h prefix on the *next* instruction, but
                // the disassembler decodes 66 EB as a 16-bit jump.  Net: [i..i+3] is
                // a 3-byte opaque sequence + 1 dead byte.
                let rel = data[i + 2] as i8 as isize;
                let skip_end = (i as isize + 3 + rel) as usize;
                let junk_len = skip_end.saturating_sub(i).min(12);
                if !overlaps(&claimed, i, i + junk_len) {
                    result.push(PassTransform::nop(
                        i,
                        junk_len.max(3),
                        format!("66 EB pattern at {i:#x}: 16-bit JMP obfuscation"),
                        Confidence::HIGH,
                    ));
                    claimed.push((i, i + junk_len));
                }
                i += 3;
                continue;
            }

            // Pattern 2: 66 90 (16-bit NOP) — always junk in 64-bit mode
            if data[i] == 0x66 && data[i + 1] == 0x90 {
                if !overlaps(&claimed, i, i + 2) {
                    result.push(PassTransform::nop(
                        i, 2,
                        format!("66 90 at {i:#x}: 16-bit NOP (junk)"),
                        Confidence::MEDIUM,
                    ));
                    claimed.push((i, i + 2));
                }
                i += 2;
                continue;
            }

            // Pattern 3: 67 90 (address-size prefix + NOP) — junk in 64-bit mode
            if data[i] == 0x67 && data[i + 1] == 0x90 {
                if !overlaps(&claimed, i, i + 2) {
                    result.push(PassTransform::nop(
                        i, 2,
                        format!("67 90 at {i:#x}: address-size NOP (junk)"),
                        Confidence::MEDIUM,
                    ));
                    claimed.push((i, i + 2));
                }
                i += 2;
                continue;
            }

            // Pattern 4: double 66 prefix (66 66 …) — degenerate prefix chain
            if data[i] == 0x66 && data[i + 1] == 0x66 {
                // Count how many consecutive 66h bytes there are.
                let mut cnt = 0;
                while i + cnt < data.len() && data[i + cnt] == 0x66 {
                    cnt += 1;
                }
                if cnt >= 2 && !overlaps(&claimed, i, i + cnt) {
                    result.push(PassTransform::nop(
                        i, cnt,
                        format!("{cnt}x 66h prefix chain at {i:#x}: degenerate prefix junk"),
                        Confidence::HIGH,
                    ));
                    claimed.push((i, i + cnt));
                }
                i += cnt;
                continue;
            }

            // Pattern 5: F2/F3 REPNE/REP before a non-string instruction
            // F2 90 / F3 90 are two-byte NOPs used as junk.
            if matches!(data[i], 0xF2 | 0xF3) && data[i + 1] == 0x90 {
                if !overlaps(&claimed, i, i + 2) {
                    result.push(PassTransform::nop(
                        i, 2,
                        format!("{:#04x} 90 at {i:#x}: REP/REPNE + NOP junk", data[i]),
                        Confidence::MEDIUM,
                    ));
                    claimed.push((i, i + 2));
                }
                i += 2;
                continue;
            }

            // Pattern 6: long NOP encoding 0F 1F /0 with arbitrary ModRM + disp
            if data[i] == 0x0F && data[i + 1] == 0x1F && i + 2 < data.len() {
                let modrm = data[i + 2];
                let reg = (modrm >> 3) & 7;
                if reg == 0 {
                    // This is a legitimate multi-byte NOP — still junk if in the middle
                    // of an obfuscated sequence, but we only flag runs of ≥ 2 such NOPs.
                    let len = 3 + modrm_disp_len(modrm);
                    let scan_start = i + len;
                    if scan_start + 2 < data.len()
                        && data[scan_start] == 0x0F
                        && data[scan_start + 1] == 0x1F
                    {
                        let len2 = 3 + modrm_disp_len(data[scan_start + 2]);
                        let total = len + len2;
                        if !overlaps(&claimed, i, i + total) {
                            result.push(PassTransform::nop(
                                i, total,
                                format!("double 0F1F NOP at {i:#x}: multi-byte NOP pair"),
                                Confidence::LOW,
                            ));
                            claimed.push((i, i + total));
                        }
                    }
                }
            }

            i += 1;
        }

        if !result.transforms.is_empty() {
            result.note(format!(
                "found {} mixed-mode obfuscation patterns ({} bytes)",
                result.transforms.len(),
                result.total_bytes()
            ));
        }
        result
    }
}

const fn modrm_disp_len(modrm: u8) -> usize {
    let md = modrm >> 6;
    let rm = modrm & 7;
    match md {
        0 if rm == 5 => 4,
        0 if rm == 4 => 1,
        1 => 1 + if rm == 4 { 1 } else { 0 },
        2 => 4 + if rm == 4 { 1 } else { 0 },
        _ => 0,
    }
}

fn overlaps(claimed: &[(usize, usize)], start: usize, end: usize) -> bool {
    claimed.iter().any(|&(cs, ce)| start < ce && cs < end)
}

// ─── Pass 2: Handler-based CFG reconstruction ─────────────────────────────────
//
// "Handler-based obfuscation" routes control flow through an indirect dispatch
// table.  Each handler is a short code sequence that ends with:
//   MOV [state_var], next_state
//   JMP dispatcher
//
// We detect this by:
// 1. Finding an indirect JMP (FF E? / FF 2?) that is the single exit of a
//    hot block (the dispatcher).
// 2. Collecting all blocks whose only exit is to the dispatcher.
// 3. Sorting handlers by their state-variable assignments to reconstruct
//    the original sequential order.

/// A decoded handler in the handler-based CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerBlock {
    /// Start address of this handler.
    pub start: Addr,
    /// End address (exclusive).
    pub end: Addr,
    /// State value assigned before jumping back to dispatcher.
    pub state_value: Option<u64>,
    /// True if this is the terminal handler (no successor in the chain).
    pub is_terminal: bool,
}

/// Result of handler-based CFG analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerCfgResult {
    /// Address of the dispatcher block.
    pub dispatcher_addr: Addr,
    /// Detected handlers in reconstructed execution order.
    pub handlers: Vec<HandlerBlock>,
    /// Reconstructed linear execution order (handler start addresses).
    pub linear_order: Vec<Addr>,
    /// Number of bytes that could be simplified.
    pub simplifiable_bytes: usize,
}

#[derive(Debug, Default, Clone)]
pub struct HandlerCfgPass;

impl HandlerCfgPass {
    /// Analyse `data` (binary image at virtual base `base`) and reconstruct
    /// the handler-based CFG if present.
    #[must_use]
    pub fn run(&self, data: &[u8], base: Addr) -> Option<HandlerCfgResult> {
        // Step 1: find indirect JMP.
        let dispatcher_addr = self.find_dispatcher(data, base)?;
        let disp_off = (dispatcher_addr - base) as usize;

        // Step 2: find all blocks that jump back to the dispatcher.
        let handlers = self.collect_handlers(data, base, dispatcher_addr);
        if handlers.len() < 2 {
            return None;
        }

        // Step 3: sort by state_value to get linear order.
        let mut sorted = handlers.clone();
        sorted.sort_by(|a, b| {
            a.state_value
                .unwrap_or(u64::MAX)
                .cmp(&b.state_value.unwrap_or(u64::MAX))
        });

        let linear_order = sorted.iter().map(|h| h.start).collect();
        let simplifiable_bytes = sorted
            .iter()
            .map(|h| (h.end.saturating_sub(h.start)) as usize)
            .sum::<usize>()
            .saturating_sub(disp_off);

        Some(HandlerCfgResult {
            dispatcher_addr,
            handlers: sorted,
            linear_order,
            simplifiable_bytes,
        })
    }

    /// Look for a block whose sole exit is an indirect `JMP r/m`.
    fn find_dispatcher(&self, data: &[u8], base: Addr) -> Option<Addr> {
        for i in 0..data.len().saturating_sub(1) {
            // FF E? = JMP r64;  FF 24 = JMP [rsp*x+base] (indirect table)
            if data[i] == 0xFF {
                let modrm_reg = (data[i + 1] >> 3) & 7;
                if matches!(modrm_reg, 4 | 5) {
                    return Some(base + i as Addr);
                }
            }
        }
        None
    }

    /// Collect all basic blocks that end by jumping to `dispatcher`.
    fn collect_handlers(&self, data: &[u8], base: Addr, dispatcher: Addr) -> Vec<HandlerBlock> {
        let mut handlers = Vec::new();
        let mut off = 0;
        let n = data.len();

        while off + 6 < n {
            // Look for:  MOV [mem], imm (C7 0? imm32)  followed by  JMP rel32/rel8 to dispatcher
            if data[off] == 0xC7 && (data[off + 1] & 0xF8 == 0x00 || data[off + 1] == 0x05) {
                // MOV [rip+disp32], imm32 — 10 bytes total
                if off + 10 < n {
                    let imm = u64::from(u32::from_le_bytes([
                        data[off + 6],
                        data[off + 7],
                        data[off + 8],
                        data[off + 9],
                    ]));
                    // Check if the next instruction jumps to the dispatcher.
                    let after = off + 10;
                    let jmp_to_disp = self.jumps_to(data, base, after, dispatcher);
                    if jmp_to_disp {
                        let jmp_len = 2 + if data[after] == 0xE9 { 4 } else { 1 };
                        let handler_end = base + (after + jmp_len) as Addr;
                        // Find the start of this handler by scanning backwards for another JMP.
                        let handler_start = self.find_handler_start(data, base, off);
                        handlers.push(HandlerBlock {
                            start: handler_start,
                            end: handler_end,
                            state_value: Some(imm),
                            is_terminal: false,
                        });
                    }
                }
            }
            off += 1;
        }

        if let Some(last) = handlers.last_mut() {
            last.is_terminal = true;
        }
        handlers
    }

    /// Check whether `data[off]` is a JMP instruction targeting `target`.
    fn jumps_to(&self, data: &[u8], base: Addr, off: usize, target: Addr) -> bool {
        if off >= data.len() {
            return false;
        }
        match data[off] {
            0xE9 if off + 4 < data.len() => {
                let rel = i64::from(i32::from_le_bytes([
                    data[off + 1], data[off + 2], data[off + 3], data[off + 4],
                ]));
                let dst = (base as i64 + off as i64 + 5 + rel) as Addr;
                dst == target
            }
            0xEB if off + 1 < data.len() => {
                let rel = i64::from(data[off + 1] as i8);
                let dst = (base as i64 + off as i64 + 2 + rel) as Addr;
                dst == target
            }
            _ => false,
        }
    }

    /// Scan backwards from `off` to find the start of the enclosing handler.
    fn find_handler_start(&self, data: &[u8], base: Addr, off: usize) -> Addr {
        let lo = off.saturating_sub(128);
        for i in (lo..off).rev() {
            if matches!(data[i], 0xC3 | 0xEB | 0xE9 | 0xCC) {
                return base + (i + 1) as Addr;
            }
        }
        base + lo as Addr
    }
}

// ─── Pass 3: Control-flow unflattening ───────────────────────────────────────
//
// Classic OLLVM-style control-flow flattening creates a dispatch loop:
//   while (state != -1) { switch(state) { case N: ...; state = M; } }
//
// We unflatten by:
// 1. Detecting the dispatcher (a block with ≥ 3 successors that reads a
//    state variable).
// 2. For each "real" basic block, tracing the state assignment to determine
//    the successor in the unflattened CFG.
// 3. Patching the binary so each real block jumps directly to its successor.

/// One real basic block extracted from a flattened CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnflattenedBlock {
    pub orig_addr: Addr,
    pub len: usize,
    /// State value assigned at the end of this block.
    pub assigned_state: Option<u64>,
    /// Successor block in the unflattened CFG.
    pub successor: Option<Addr>,
    /// True when this block has two successors (conditional branch).
    pub is_branch: bool,
    /// State for the taken branch.
    pub taken_state: Option<u64>,
    /// State for the not-taken branch.
    pub not_taken_state: Option<u64>,
}

/// Result of the unflattening pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnflattenResult {
    pub dispatcher_addr: Addr,
    pub state_var: VarId,
    pub blocks: Vec<UnflattenedBlock>,
    /// Patch list: (offset, `JMP_bytes`) to redirect each real block to its successor.
    pub patches: Vec<(usize, Vec<u8>)>,
    /// True when the unflattening appears complete (all successors resolved).
    pub complete: bool,
    pub confidence: Confidence,
}

#[derive(Debug, Default, Clone)]
pub struct ControlFlowUnflattener;

impl ControlFlowUnflattener {
    /// Attempt to unflatten a flattened CFG in `data` (base virtual address `base`).
    #[must_use]
    pub fn run(&self, data: &[u8], base: Addr) -> Option<UnflattenResult> {
        // Build CFG.
        let builder = CfgBuilder::new(base);
        let entry = base;
        let cfg = builder.build(data, entry);

        // Find the dispatcher: a block with the most successors.
        let dispatcher_block = self.find_dispatcher_block(&cfg)?;
        let dispatcher_addr = dispatcher_block.start;

        // State variable heuristic: look for a MOV reg, [state_addr] before the dispatcher.
        let state_var = self.guess_state_var(data, base, dispatcher_addr);

        // Collect real blocks (non-dispatcher, non-prologue blocks that are
        // successors of the dispatcher).
        let real_addrs: Vec<Addr> = dispatcher_block
            .succs
            .iter()
            .copied()
            .filter(|&a| a != dispatcher_addr)
            .collect();

        let mut blocks: Vec<UnflattenedBlock> = real_addrs
            .iter()
            .map(|&addr| self.analyse_real_block(data, base, addr, dispatcher_addr))
            .collect();

        // Resolve successors: state_value → block_addr.
        let state_to_addr: HashMap<u64, Addr> = blocks
            .iter()
            .filter_map(|b| b.assigned_state.map(|s| (s, b.orig_addr)))
            .collect();

        let mut resolved = 0usize;
        for b in &mut blocks {
            if let Some(s) = b.assigned_state {
                if let Some(&succ) = state_to_addr.get(&s) {
                    b.successor = Some(succ);
                    resolved += 1;
                }
            }
        }

        let complete = resolved == blocks.len();
        let confidence = if complete {
            Confidence::HIGH
        } else if resolved > blocks.len() / 2 {
            Confidence::MEDIUM
        } else {
            Confidence::LOW
        };

        // Generate JMP patches.
        let patches = self.generate_patches(data, base, &blocks);

        Some(UnflattenResult {
            dispatcher_addr,
            state_var,
            blocks,
            patches,
            complete,
            confidence,
        })
    }

    fn find_dispatcher_block<'a>(&self, cfg: &'a ControlFlowGraph) -> Option<&'a BasicBlock> {
        cfg.iter_blocks()
            .max_by_key(|b| b.succs.len())
            .filter(|b| b.succs.len() >= 3)
    }

    fn guess_state_var(&self, data: &[u8], base: Addr, dispatcher: Addr) -> VarId {
        let off = (dispatcher - base) as usize;
        let lo = off.saturating_sub(64);
        for i in (lo..off).rev() {
            if i + 5 < data.len() && data[i] == 0xA1 {
                let addr = u64::from_le_bytes([
                    data[i + 1], data[i + 2], data[i + 3], data[i + 4], 0, 0, 0, 0,
                ]);
                return VarId::Heap(addr);
            }
            if i + 3 < data.len() && data[i] == 0x8B && (data[i + 1] & 0xC0) == 0x00 {
                return VarId::Reg("eax".into());
            }
        }
        VarId::Sym("state".into())
    }

    fn analyse_real_block(
        &self,
        data: &[u8],
        base: Addr,
        addr: Addr,
        dispatcher: Addr,
    ) -> UnflattenedBlock {
        let start_off = (addr.saturating_sub(base)) as usize;
        let mut state_val: Option<u64> = None;
        let mut is_branch = false;
        let mut taken_state: Option<u64> = None;
        let mut not_taken_state: Option<u64> = None;
        let mut len = 0;

        let mut i = start_off;
        while i < data.len() && i - start_off < 512 {
            let b = data[i];
            // MOV [mem], imm32: C7 05 ... or C7 00
            if b == 0xC7 && i + 9 < data.len() {
                let imm = u64::from(u32::from_le_bytes([
                    data[i + 6], data[i + 7], data[i + 8], data[i + 9],
                ]));
                // Is there a conditional branch nearby?
                if i + 10 < data.len() && matches!(data[i + 10], 0x74 | 0x75) {
                    is_branch = true;
                    let not_taken_off = i + 12;
                    // Look ahead for another MOV [mem], imm
                    if not_taken_off + 9 < data.len() && data[not_taken_off] == 0xC7 {
                        not_taken_state = Some(u64::from(u32::from_le_bytes([
                            data[not_taken_off + 6],
                            data[not_taken_off + 7],
                            data[not_taken_off + 8],
                            data[not_taken_off + 9],
                        ])));
                    }
                    taken_state = Some(imm);
                } else {
                    state_val = Some(imm);
                }
            }
            // JMP to dispatcher
            if self.jumps_to_addr(data, base, i, dispatcher) {
                len = i + 5 - start_off;
                break;
            }
            i += 1;
        }
        if len == 0 {
            len = i.saturating_sub(start_off).max(1);
        }

        UnflattenedBlock {
            orig_addr: addr,
            len,
            assigned_state: if is_branch { taken_state } else { state_val },
            successor: None,
            is_branch,
            taken_state,
            not_taken_state,
        }
    }

    fn jumps_to_addr(&self, data: &[u8], base: Addr, off: usize, target: Addr) -> bool {
        if off >= data.len() {
            return false;
        }
        match data[off] {
            0xE9 if off + 4 < data.len() => {
                let rel = i64::from(i32::from_le_bytes([
                    data[off + 1], data[off + 2], data[off + 3], data[off + 4],
                ]));
                (base as i64 + off as i64 + 5 + rel) as Addr == target
            }
            0xEB if off + 1 < data.len() => {
                let rel = i64::from(data[off + 1] as i8);
                (base as i64 + off as i64 + 2 + rel) as Addr == target
            }
            _ => false,
        }
    }

    /// Build JMP patch bytes for each resolved block.
    fn generate_patches(
        &self,
        data: &[u8],
        base: Addr,
        blocks: &[UnflattenedBlock],
    ) -> Vec<(usize, Vec<u8>)> {
        let mut patches = Vec::new();
        for b in blocks {
            if let Some(succ) = b.successor {
                // The JMP goes at the end of the real block (before the loop-back JMP).
                let off = (b.orig_addr - base) as usize + b.len;
                if off + 5 <= data.len() {
                    let rel = succ as i64 - (base as i64 + off as i64 + 5);
                    let mut jmp = vec![0xE9u8];
                    jmp.extend_from_slice(&(rel as i32).to_le_bytes());
                    patches.push((off, jmp));
                }
            }
        }
        patches
    }
}

// ─── Pass 4: Opaque constant elimination via dataflow ─────────────────────────
//
// Runs constant propagation and eliminates opaque predicates that were missed
// by the pattern-matching MHCDE pass because they use register chains rather
// than inline patterns.

#[derive(Debug, Default, Clone)]
pub struct OpaqueConstantEliminationPass;

impl OpaqueConstantEliminationPass {
    /// Run constant propagation over a CFG and return patches for branches
    /// whose condition is a compile-time constant.
    #[must_use]
    pub fn run(
        &self,
        data: &[u8],
        base: Addr,
        block_defs: &HashMap<Addr, Vec<(VarId, Option<u64>)>>,
        block_uses: &HashMap<Addr, (Vec<VarId>, Vec<VarId>)>,
    ) -> PassResult {
        let mut result = PassResult::new("opaque-constant-elimination");

        let builder = CfgBuilder::new(base);
        let cfg = builder.build(data, base);
        let df = DataflowPropagator::run(&cfg, block_defs, block_uses);

        for hint in &df.constants.hints {
            // If a constant lands in a register that feeds a branch condition,
            // the branch is opaque.
            if hint.is_branch_cond {
                let off = (hint.block.saturating_sub(base)) as usize + hint.insn_off;
                if off + 2 <= data.len() {
                    result.push(PassTransform::nop(
                        off, 2,
                        format!(
                            "opaque branch at {:#x}: {} = {:#x} (constant)",
                            hint.block, hint.var, hint.value
                        ),
                        Confidence::HIGH,
                    ));
                }
            }
        }

        // Also report dead definitions.
        for (var, _) in df.global_constants {
            result.note(format!("global constant variable: {var}"));
        }
        result.note(format!("dead def count: {}", df.dead_def_count));

        result
    }
}

// ─── Aggregated MHCDE pipeline ───────────────────────────────────────────────

/// Full MHCDE pass pipeline result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MhcdePipelineResult {
    pub mixed_mode: PassResult,
    pub handler_cfg: Option<HandlerCfgResult>,
    pub unflattened: Option<UnflattenResult>,
    pub opaque_const: PassResult,
    /// Combined confidence across all passes.
    pub overall_confidence: Confidence,
    /// Total bytes proposed for transformation.
    pub total_transform_bytes: usize,
}

impl MhcdePipelineResult {
    /// Apply all transforms to a byte buffer.  Returns the number of patches applied.
    pub fn apply_all(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for t in &self.mixed_mode.transforms {
            if t.apply(buf) { count += 1; }
        }
        for t in &self.opaque_const.transforms {
            if t.apply(buf) { count += 1; }
        }
        if let Some(unflat) = &self.unflattened {
            for (off, jmp) in &unflat.patches {
                let end = off + jmp.len();
                if end <= buf.len() {
                    buf[*off..end].copy_from_slice(jmp);
                    count += 1;
                }
            }
        }
        count
    }
}

/// Drive all MHCDE deobfuscation passes over `data`.
#[must_use]
pub fn run_mhcde_pipeline(
    data: &[u8],
    base: Addr,
    block_defs: &HashMap<Addr, Vec<(VarId, Option<u64>)>>,
    block_uses: &HashMap<Addr, (Vec<VarId>, Vec<VarId>)>,
) -> MhcdePipelineResult {
    let mixed_mode = MixedModePass::default().run(data);
    let handler_cfg = HandlerCfgPass::default().run(data, base);
    let unflattened = ControlFlowUnflattener::default().run(data, base);
    let opaque_const = OpaqueConstantEliminationPass::default().run(data, base, block_defs, block_uses);

    let mm_bytes = mixed_mode.total_bytes();
    let oc_bytes = opaque_const.total_bytes();
    let unflat_bytes = unflattened.as_ref().map_or(0, |u| u.patches.len() * 5);
    let total_transform_bytes = mm_bytes + oc_bytes + unflat_bytes;

    let max_conf = [mixed_mode.confidence, opaque_const.confidence]
        .iter()
        .chain(unflattened.iter().map(|u| &u.confidence))
        .copied()
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(Confidence::LOW);

    MhcdePipelineResult {
        mixed_mode,
        handler_cfg,
        unflattened,
        opaque_const,
        overall_confidence: max_conf,
        total_transform_bytes,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixed_mode_66_90() {
        let data = [0x66u8, 0x90, 0x90];
        let result = MixedModePass::default().run(&data);
        assert!(!result.transforms.is_empty());
        assert_eq!(result.transforms[0].length, 2);
    }

    #[test]
    fn test_mixed_mode_double_66() {
        let data = [0x66u8, 0x66, 0x66, 0x90, 0xC3];
        let result = MixedModePass::default().run(&data);
        assert!(!result.transforms.is_empty());
    }

    #[test]
    fn test_pass_transform_apply() {
        let mut buf = [0xC3u8, 0xC3, 0xC3, 0xC3];
        let t = PassTransform::nop(1, 2, "test", Confidence::HIGH);
        assert!(t.apply(&mut buf));
        assert_eq!(buf[1], 0x90);
        assert_eq!(buf[2], 0x90);
        assert_eq!(buf[0], 0xC3);
        assert_eq!(buf[3], 0xC3);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::HIGH.is_reliable());
        assert!(Confidence::MEDIUM.is_reliable());
        assert!(!Confidence::LOW.is_reliable());
    }

    #[test]
    fn test_overlaps() {
        let claimed = vec![(10usize, 20usize), (30, 40)];
        assert!(overlaps(&claimed, 15, 25));
        assert!(!overlaps(&claimed, 20, 30));
        assert!(!overlaps(&claimed, 40, 50));
    }

    #[test]
    fn test_pipeline_noop_on_clean_data() {
        let data = vec![0x90u8, 0x90, 0xC3];
        let defs: HashMap<Addr, Vec<(VarId, Option<u64>)>> = HashMap::new();
        let uses: HashMap<Addr, (Vec<VarId>, Vec<VarId>)> = HashMap::new();
        let result = run_mhcde_pipeline(&data, 0x1000, &defs, &uses);
        // Shouldn't crash, may find NOP sleds but no mixed-mode patterns.
        let _ = result.overall_confidence;
    }
}
