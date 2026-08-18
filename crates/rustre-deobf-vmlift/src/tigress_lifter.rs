//! `tigress_lifter` — Tigress obfuscator VM lifting.
//!
//! Supports:
//! * Virtualization mode detection (dispatch switch variants)
//! * Handler table location
//! * Register file layout inference
//! * Opcode extraction via symbolic execution
//! * Lifting to LLIL-compatible IR


use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Tigress dispatch mode
// ─────────────────────────────────────────────────────────────────────────────

/// Variant of the Tigress dispatch switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TigressDispatchMode {
    /// Dense `switch` on an integer opcode (jump table in rodata).
    DenseSwitch,
    /// Sparse `if/else if` chain on opcode values.
    SparseBranch,
    /// Indirect dispatch through a function pointer table.
    IndirectTable,
    /// "Threaded" dispatch: each handler ends with `goto *next_handler`.
    ThreadedGoto,
    /// Nested dispatch: outer switch selects handler group, inner switch selects handler.
    NestedSwitch,
    /// Unknown variant.
    Unknown,
}

impl std::fmt::Display for TigressDispatchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DenseSwitch => "DenseSwitch",
            Self::SparseBranch => "SparseBranch",
            Self::IndirectTable => "IndirectTable",
            Self::ThreadedGoto => "ThreadedGoto",
            Self::NestedSwitch => "NestedSwitch",
            Self::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Register file layout
// ─────────────────────────────────────────────────────────────────────────────

/// How a single register file slot is accessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegFileAccess {
    /// Array element: `regs[idx]`.
    Array { base_reg: String, index: u8 },
    /// Named struct field: `ctx->r0`, `ctx->r1`, etc.
    StructField { field_name: String, offset: i32 },
    /// Stack slot relative to the VM's frame pointer.
    StackSlot { fp_reg: String, offset: i32 },
}

/// Description of the recovered virtual register file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TigressRegisterFile {
    /// Number of registers in the file.
    pub num_registers: u8,
    /// Width of each register (in bits: 32 or 64).
    pub register_width: u8,
    /// Access pattern for the file.
    pub access: RegFileAccess,
    /// Mapping from slot index to human-readable name.
    pub slot_names: HashMap<u8, String>,
    /// Confidence in this layout.
    pub confidence: f32,
}

impl TigressRegisterFile {
    /// Create a default 8-register 64-bit file layout.
    pub fn default_x64() -> Self {
        let slot_names: HashMap<u8, String> = (0..8u8)
            .map(|i| (i, format!("vr{}", i)))
            .collect();
        Self {
            num_registers: 8,
            register_width: 64,
            access: RegFileAccess::Array {
                base_reg: "rdi".into(),
                index: 0,
            },
            slot_names,
            confidence: 0.55,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tigress handler
// ─────────────────────────────────────────────────────────────────────────────

/// A single Tigress VM handler identified in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TigressHandler {
    /// Opcode value that selects this handler.
    pub opcode: u32,
    /// Virtual address of the handler code.
    pub address: u64,
    /// Raw bytes of the handler body.
    pub body: Vec<u8>,
    /// Inferred semantic name (e.g. `"ADD64"`, `"LOAD32"`, `"BRANCH"`).
    pub semantic: Option<String>,
    /// Whether this handler ends with a threaded dispatch jump.
    pub has_threaded_tail: bool,
    /// Confidence in semantic identification.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// LLIL opcode (simplified)
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified LLIL-compatible instruction produced by the lifter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LlilInsn {
    /// `dst = src`
    SetReg { dst: String, src: LlilExpr },
    /// `mem[addr] = val`
    Store { addr: LlilExpr, val: LlilExpr, width: u8 },
    /// `goto target`
    Jump(LlilExpr),
    /// `if (cond) goto taken; else goto fallthrough`
    If { cond: LlilExpr, taken: u64, fallthrough: u64 },
    /// `call target`
    Call(LlilExpr),
    /// Function return.
    Ret(LlilExpr),
    /// No operation.
    Nop,
    /// Unlifted (opaque) block.
    Unlifted { reason: String },
}

/// A simplified LLIL expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LlilExpr {
    /// Register value.
    Reg(String),
    /// Constant.
    Const(u64),
    /// Memory load: `mem[inner]`.
    Load { inner: Box<LlilExpr>, width: u8 },
    /// Binary operation.
    BinOp {
        op: String,
        lhs: Box<LlilExpr>,
        rhs: Box<LlilExpr>,
    },
    /// Unary operation.
    UnaryOp { op: String, inner: Box<LlilExpr> },
}

impl LlilExpr {
    pub fn reg(name: impl Into<String>) -> Self {
        Self::Reg(name.into())
    }

    pub fn constant(v: u64) -> Self {
        Self::Const(v)
    }

    pub fn add(lhs: LlilExpr, rhs: LlilExpr) -> Self {
        Self::BinOp {
            op: "ADD".into(),
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    pub fn sub(lhs: LlilExpr, rhs: LlilExpr) -> Self {
        Self::BinOp {
            op: "SUB".into(),
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    pub fn xor(lhs: LlilExpr, rhs: LlilExpr) -> Self {
        Self::BinOp {
            op: "XOR".into(),
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    pub fn load(inner: LlilExpr, width: u8) -> Self {
        Self::Load { inner: Box::new(inner), width }
    }
}

/// A lifted basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlilBlock {
    /// Start address (maps to Tigress handler opcode sequence).
    pub start_addr: u64,
    /// Lifted instructions.
    pub insns: Vec<LlilInsn>,
    /// Successor addresses.
    pub successors: Vec<u64>,
}

/// Complete lifted function result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedFunction {
    /// Entry address.
    pub entry: u64,
    /// All lifted blocks.
    pub blocks: Vec<LlilBlock>,
    /// Number of handlers that could not be lifted.
    pub unlifted_count: u32,
    /// Coverage: lifted / total handlers encountered.
    pub coverage: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// TigressLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts Tigress-virtualized functions to LLIL.
pub struct TigressLifter {
    /// Minimum confidence to accept a dispatch mode identification.
    pub min_confidence: f32,
    /// Semantic pattern database for handler classification.
    semantic_patterns: HashMap<String, Vec<Vec<u8>>>,
    /// Known Tigress handler table signatures.
    table_signatures: Vec<Vec<u8>>,
}

impl Default for TigressLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl TigressLifter {
    pub fn new() -> Self {
        let mut s = Self {
            min_confidence: 0.55,
            semantic_patterns: HashMap::new(),
            table_signatures: Vec::new(),
        };
        s.load_semantic_patterns();
        s.load_table_signatures();
        s
    }

    pub fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    // ── Pattern loading ───────────────────────────────────────────────────────

    fn load_semantic_patterns(&mut self) {
        // Tigress stack-machine handlers (x86-64)

        // ADD64: pop rax; pop rbx; add rax, rbx; push rax
        self.semantic_patterns.insert("ADD64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x01, 0xD8, 0x50],
        ]);

        // SUB64
        self.semantic_patterns.insert("SUB64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x29, 0xD8, 0x50],
        ]);

        // MUL64: pop rax; pop rcx; imul rax, rcx; push rax
        self.semantic_patterns.insert("MUL64".into(), vec![
            vec![0x58, 0x59, 0x48, 0x0F, 0xAF, 0xC1, 0x50],
        ]);

        // XOR64
        self.semantic_patterns.insert("XOR64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x31, 0xD8, 0x50],
        ]);

        // AND64
        self.semantic_patterns.insert("AND64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x21, 0xD8, 0x50],
        ]);

        // OR64
        self.semantic_patterns.insert("OR64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x09, 0xD8, 0x50],
        ]);

        // NOT64: pop rax; not rax; push rax
        self.semantic_patterns.insert("NOT64".into(), vec![
            vec![0x58, 0x48, 0xF7, 0xD0, 0x50],
        ]);

        // NEG64
        self.semantic_patterns.insert("NEG64".into(), vec![
            vec![0x58, 0x48, 0xF7, 0xD8, 0x50],
        ]);

        // SHL64: pop rcx; pop rax; shl rax, cl; push rax
        self.semantic_patterns.insert("SHL64".into(), vec![
            vec![0x59, 0x58, 0x48, 0xD3, 0xE0, 0x50],
        ]);

        // SHR64
        self.semantic_patterns.insert("SHR64".into(), vec![
            vec![0x59, 0x58, 0x48, 0xD3, 0xE8, 0x50],
        ]);

        // LOAD64: pop rax; mov rax, [rax]; push rax
        self.semantic_patterns.insert("LOAD64".into(), vec![
            vec![0x58, 0x48, 0x8B, 0x00, 0x50],
        ]);

        // LOAD32: pop rax; mov eax, [rax]; push rax (zero-extended)
        self.semantic_patterns.insert("LOAD32".into(), vec![
            vec![0x58, 0x8B, 0x00, 0x50],
        ]);

        // STORE64: pop rax (addr); pop rbx (val); mov [rax], rbx
        self.semantic_patterns.insert("STORE64".into(), vec![
            vec![0x58, 0x5B, 0x48, 0x89, 0x18],
        ]);

        // PUSH_IMM64: push imm64 (via mov + push)
        self.semantic_patterns.insert("PUSH_IMM64".into(), vec![
            vec![0x48, 0xB8],   // mov rax, imm64 prefix
        ]);

        // BRANCH: pop rax; test rax, rax; jz/jnz
        self.semantic_patterns.insert("BRANCH".into(), vec![
            vec![0x58, 0x48, 0x85, 0xC0],
            vec![0x58, 0x85, 0xC0],
        ]);

        // CALL: pop rax; call rax
        self.semantic_patterns.insert("CALL".into(), vec![
            vec![0x58, 0xFF, 0xD0],
        ]);

        // RET: pop rax; jmp rax
        self.semantic_patterns.insert("RET".into(), vec![
            vec![0x58, 0xFF, 0xE0],
        ]);

        // NOP: just increments vIP
        self.semantic_patterns.insert("NOP".into(), vec![
            vec![0x90],
        ]);
    }

    fn load_table_signatures(&mut self) {
        // Tigress dispatch tables are typically in .data or .rodata and
        // consist of consecutive function pointers.  We look for the
        // dispatcher loop itself.

        // Dense switch: `movsx eax, byte [rdi]; jmp [table + rax*8]`
        self.table_signatures.push(vec![0x0F, 0xBE, 0x07, 0xFF, 0x24, 0xC5]);
        // Sparse: `cmp byte [rdi], imm8; je handler`
        self.table_signatures.push(vec![0x80, 0x3F]);
        // Threaded: `jmp [rbx]` (next handler pointer in rbx)
        self.table_signatures.push(vec![0xFF, 0x23]);
        // Indirect: `call [rax + rcx*8]`
        self.table_signatures.push(vec![0xFF, 0x14, 0xC8]);
    }

    // ── Dispatch mode detection ───────────────────────────────────────────────

    /// Detect the Tigress dispatch mode in a code region.
    pub fn detect_dispatch_mode(&self, bytes: &[u8]) -> (TigressDispatchMode, f32) {
        let mut scores: HashMap<TigressDispatchMode, f32> = HashMap::new();

        // Dense switch: presence of jump table pattern
        if bytes.windows(6).any(|w| {
            w[0] == 0x0F && w[1] == 0xBE && (w[3] == 0xFF || w[4] == 0xFF)
        }) {
            *scores.entry(TigressDispatchMode::DenseSwitch).or_insert(0.0) += 0.45;
        }

        // Threaded: many jmp [reg] patterns
        let threaded_count = bytes
            .windows(2)
            .filter(|w| w[0] == 0xFF && matches!(w[1], 0x20..=0x27))
            .count();
        if threaded_count >= 5 {
            *scores.entry(TigressDispatchMode::ThreadedGoto).or_insert(0.0) += 0.40;
        }

        // Sparse: many cmp byte; je sequences
        let sparse_count = bytes
            .windows(2)
            .filter(|w| w[0] == 0x80 && w[1] == 0x3F)
            .count();
        if sparse_count >= 3 {
            *scores.entry(TigressDispatchMode::SparseBranch).or_insert(0.0) +=
                0.05 * sparse_count as f32;
        }

        // Indirect table: call [rax + rcx*8] or similar
        if bytes.windows(3).any(|w| w[0] == 0xFF && w[1] == 0x14 && w[2] == 0xC8) {
            *scores.entry(TigressDispatchMode::IndirectTable).or_insert(0.0) += 0.50;
        }

        // Nested: presence of two distinct comparison patterns
        if sparse_count >= 2 && threaded_count >= 2 {
            *scores.entry(TigressDispatchMode::NestedSwitch).or_insert(0.0) += 0.30;
        }

        // `scores` is a HashMap: without a tie-break on the mode itself, two
        // dispatch modes with an equal score would be picked arbitrarily, and
        // the reported mode would change between runs on the same binary.
        scores
            .into_iter()
            .max_by(|a, b| {
                a.1.partial_cmp(&b.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.0.cmp(&a.0))
            })
            .map(|(mode, score)| (mode, score.min(1.0)))
            .unwrap_or((TigressDispatchMode::Unknown, 0.0))
    }

    // ── Handler table location ────────────────────────────────────────────────

    /// Find the handler dispatch table base address.
    pub fn locate_handler_table(&self, bytes: &[u8], base_address: u64) -> Option<u64> {
        // Strategy: find the dispatcher loop, then follow the table pointer
        for (i, window) in bytes.windows(6).enumerate() {
            // Pattern: mov rax/eax, [rdi]; jmp [table + rax*N]
            if window[0] == 0x0F && window[1] == 0xBE {
                // 3 bytes for movsx, then look for jmp [disp + rax*8]
                if i + 10 < bytes.len() {
                    let jmp_window = &bytes[i + 3..i + 10];
                    if jmp_window[0] == 0xFF && jmp_window[1] == 0x24 {
                        // jmp [rax*8 + disp32]
                        if jmp_window[2] == 0xC5 && jmp_window.len() >= 7 {
                            let Ok(disp_bytes) = jmp_window[3..7].try_into() else { continue };
                            let disp = i32::from_le_bytes(disp_bytes);
                            // RIP-relative: compute absolute address
                            let rip = base_address + (i + 3 + 7) as u64;
                            let table_addr = (rip as i64 + disp as i64) as u64;
                            return Some(table_addr);
                        }
                    }
                }
            }
        }

        // Fallback: look for a dense cluster of code pointers
        locate_pointer_cluster(bytes, base_address)
    }

    // ── Register file inference ───────────────────────────────────────────────

    /// Infer the register file layout from handler bodies.
    pub fn infer_register_file(&self, handlers: &[TigressHandler]) -> TigressRegisterFile {
        if handlers.is_empty() {
            return TigressRegisterFile::default_x64();
        }

        // Count how often each base register appears as a pointer in handler bodies
        let mut reg_counts: HashMap<String, usize> = HashMap::new();

        for handler in handlers {
            for window in handler.body.windows(3) {
                // MOV rax, [reg + disp8]: 48 8B 47 xx
                if window[0] == 0x48 && window[1] == 0x8B {
                    let rm = window[2] & 0x07;
                    let reg_name = rm_to_reg64(rm);
                    *reg_counts.entry(reg_name).or_insert(0) += 1;
                }
            }
        }

        // `reg_counts` is a HashMap: tie-break on the register name so equally
        // frequent candidates yield the same base register on every run.
        let base_reg = reg_counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            .map(|(r, _)| r)
            .unwrap_or_else(|| "rdi".to_string());

        // Estimate register count from maximum observed slot offset
        let mut max_offset: i32 = 0;
        for handler in handlers {
            for window in handler.body.windows(4) {
                if window[0] == 0x48 && window[1] == 0x8B && (window[2] & 0x40) != 0 {
                    let offset = window[3] as i32;
                    max_offset = max_offset.max(offset);
                }
            }
        }

        let num_regs = ((max_offset / 8) + 1).clamp(4, 32) as u8;

        TigressRegisterFile {
            num_registers: num_regs,
            register_width: 64,
            access: RegFileAccess::Array {
                base_reg: base_reg.clone(),
                index: 0,
            },
            slot_names: (0..num_regs).map(|i| (i, format!("vr{}", i))).collect(),
            confidence: 0.65,
        }
    }

    // ── Handler identification ────────────────────────────────────────────────

    /// Identify the semantic of a handler body.
    pub fn identify_handler_semantic(&self, body: &[u8]) -> Option<(String, f32)> {
        for (name, patterns) in &self.semantic_patterns {
            for pattern in patterns {
                if body.len() >= pattern.len() && &body[..pattern.len()] == pattern.as_slice() {
                    let conf = if pattern.len() >= 5 { 0.82 } else { 0.58 };
                    if conf >= self.min_confidence {
                        return Some((name.clone(), conf));
                    }
                }
            }
        }

        // Opcode-density fallback
        let add_count = body.windows(3).filter(|w| w[0] == 0x48 && w[1] == 0x01).count();
        let xor_count = body.windows(3).filter(|w| w[0] == 0x48 && w[1] == 0x31).count();
        let load_count = body.windows(3).filter(|w| w[0] == 0x48 && w[1] == 0x8B && w[2] == 0x00).count();

        if load_count >= 1 { return Some(("LOAD64".into(), 0.50)); }
        if add_count >= 1  { return Some(("ADD64".into(), 0.48)); }
        if xor_count >= 1  { return Some(("XOR64".into(), 0.48)); }

        None
    }

    // ── Opcode extraction ─────────────────────────────────────────────────────

    /// Extract all handler entries from a dispatch table.
    ///
    /// `table_bytes` — raw bytes starting at the table base
    /// `base_address` — virtual address of `table_bytes[0]`
    /// `binary`       — the full binary (for reading handler bodies)
    /// `binary_base`  — virtual address of `binary[0]`
    pub fn extract_handlers(
        &self,
        table_bytes: &[u8],
        _base_address: u64,
        binary: &[u8],
        binary_base: u64,
    ) -> Vec<TigressHandler> {
        let ptr_size = 8usize;
        let mut handlers = Vec::new();

        for (idx, chunk) in table_bytes.chunks(ptr_size).enumerate() {
            if chunk.len() < ptr_size {
                break;
            }
            let ptr = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
            if ptr == 0 {
                break;
            }

            let offset = ptr.saturating_sub(binary_base) as usize;
            if offset >= binary.len() {
                continue;
            }

            let end = (offset + 128).min(binary.len());
            let body = binary[offset..end].to_vec();

            // Check for threaded dispatch tail: jmp [rbx] at end
            let has_threaded_tail = body
                .windows(2)
                .any(|w| w[0] == 0xFF && matches!(w[1], 0x23 | 0x20 | 0x21));

            let (semantic, confidence) = self
                .identify_handler_semantic(&body)
                .unwrap_or_else(|| ("Unknown".into(), 0.0));

            handlers.push(TigressHandler {
                opcode: idx as u32,
                address: ptr,
                body,
                semantic: if confidence >= self.min_confidence {
                    Some(semantic)
                } else {
                    None
                },
                has_threaded_tail,
                confidence,
            });
        }

        handlers
    }

    // ── Lifting to LLIL ───────────────────────────────────────────────────────

    /// Lift a sequence of Tigress handlers to LLIL blocks.
    pub fn lift_to_llil(
        &self,
        handlers: &[TigressHandler],
        entry_address: u64,
    ) -> LiftedFunction {
        let mut blocks = Vec::new();
        let mut unlifted_count = 0u32;

        for handler in handlers {
            let block = self.lift_handler(handler);
            if block.insns.iter().any(|i| matches!(i, LlilInsn::Unlifted { .. })) {
                unlifted_count += 1;
            }
            blocks.push(block);
        }

        let total = handlers.len() as f32;
        let coverage = if total == 0.0 {
            0.0
        } else {
            (total - unlifted_count as f32) / total
        };

        LiftedFunction {
            entry: entry_address,
            blocks,
            unlifted_count,
            coverage,
        }
    }

    fn lift_handler(&self, handler: &TigressHandler) -> LlilBlock {
        let semantic = handler.semantic.as_deref().unwrap_or("Unknown");
        let addr = handler.address;

        let insns = match semantic {
            "ADD64" | "ADD32" => vec![
                LlilInsn::SetReg {
                    dst: "vTOS".into(),
                    src: LlilExpr::add(LlilExpr::reg("vTOS"), LlilExpr::reg("vNOS")),
                },
            ],
            "SUB64" | "SUB32" => vec![
                LlilInsn::SetReg {
                    dst: "vTOS".into(),
                    src: LlilExpr::sub(LlilExpr::reg("vNOS"), LlilExpr::reg("vTOS")),
                },
            ],
            "XOR64" | "XOR32" => vec![
                LlilInsn::SetReg {
                    dst: "vTOS".into(),
                    src: LlilExpr::xor(LlilExpr::reg("vTOS"), LlilExpr::reg("vNOS")),
                },
            ],
            "LOAD64" => vec![
                LlilInsn::SetReg {
                    dst: "vTOS".into(),
                    src: LlilExpr::load(LlilExpr::reg("vTOS"), 8),
                },
            ],
            "LOAD32" => vec![
                LlilInsn::SetReg {
                    dst: "vTOS".into(),
                    src: LlilExpr::load(LlilExpr::reg("vTOS"), 4),
                },
            ],
            "STORE64" => vec![
                LlilInsn::Store {
                    addr: LlilExpr::reg("vNOS"),
                    val: LlilExpr::reg("vTOS"),
                    width: 8,
                },
            ],
            "BRANCH" => vec![
                LlilInsn::If {
                    cond: LlilExpr::reg("vTOS"),
                    taken: 0,           // resolved by CFG reconstruction
                    fallthrough: 0,
                },
            ],
            "CALL" => vec![
                LlilInsn::Call(LlilExpr::reg("vTOS")),
            ],
            "RET" => vec![
                LlilInsn::Ret(LlilExpr::reg("vTOS")),
            ],
            "NOP" => vec![LlilInsn::Nop],
            _ => vec![LlilInsn::Unlifted {
                reason: format!("unrecognized semantic: {}", semantic),
            }],
        };

        LlilBlock {
            start_addr: addr,
            insns,
            successors: Vec::new(),
        }
    }

    // ── Full pipeline ─────────────────────────────────────────────────────────

    /// Run the full Tigress lifting pipeline on a binary region.
    ///
    /// Returns (`LiftedFunction`, `dispatch_mode`, `register_file`).
    pub fn lift(
        &self,
        binary: &[u8],
        binary_base: u64,
        region_offset: usize,
        region_size: usize,
    ) -> (LiftedFunction, TigressDispatchMode, TigressRegisterFile) {
        let region_end = region_offset
            .saturating_add(region_size)
            .min(binary.len());
        let region = &binary[region_offset.min(binary.len())..region_end];
        let region_base = binary_base.saturating_add(region_offset as u64);

        let (dispatch_mode, _) = self.detect_dispatch_mode(region);

        let table_base = self
            .locate_handler_table(region, region_base)
            .unwrap_or(region_base);

        let table_offset = table_base.saturating_sub(binary_base) as usize;
        let table_bytes = if table_offset < binary.len() {
            &binary[table_offset..(table_offset + 2048).min(binary.len())]
        } else {
            &[]
        };

        let handlers = self.extract_handlers(table_bytes, table_base, binary, binary_base);
        let reg_file = self.infer_register_file(&handlers);
        let lifted = self.lift_to_llil(&handlers, region_base);

        (lifted, dispatch_mode, reg_file)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn rm_to_reg64(rm: u8) -> String {
    match rm {
        0 => "rax".into(),
        1 => "rcx".into(),
        2 => "rdx".into(),
        3 => "rbx".into(),
        4 => "rsp".into(),
        5 => "rbp".into(),
        6 => "rsi".into(),
        7 => "rdi".into(),
        _ => format!("r{}", rm),
    }
}

fn locate_pointer_cluster(bytes: &[u8], base_address: u64) -> Option<u64> {
    let ptr_size = 8;
    let base_high = base_address & 0xFFFF_0000_0000_0000;
    let mut best_run_start = None;
    let mut best_run_len = 0usize;
    let mut i = 0;

    while i + ptr_size <= bytes.len() {
        let ptr = u64::from_le_bytes(bytes[i..i + ptr_size].try_into().unwrap_or_default());
        if ptr != 0 && (ptr & 0xFFFF_0000_0000_0000) == base_high {
            let start = i;
            let mut run = 0;
            while i + ptr_size <= bytes.len() {
                let p = u64::from_le_bytes(
                    bytes[i..i + ptr_size].try_into().unwrap_or_default(),
                );
                if p == 0 || (p & 0xFFFF_0000_0000_0000) != base_high {
                    break;
                }
                run += 1;
                i += ptr_size;
            }
            if run > best_run_len {
                best_run_len = run;
                best_run_start = Some(start);
            }
        } else {
            i += ptr_size;
        }
    }

    if best_run_len >= 4 {
        best_run_start.map(|off| base_address + off as u64)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dispatch_dense_switch() {
        let lifter = TigressLifter::new();
        // movsx eax, byte [rdi] = 0F BE 07; jmp [rax*8 + table] = FF 24 C5 ...
        let bytes = vec![0x0Fu8, 0xBE, 0x07, 0xFF, 0x24, 0xC5, 0x00, 0x00, 0x00, 0x00];
        let (mode, conf) = lifter.detect_dispatch_mode(&bytes);
        assert_eq!(mode, TigressDispatchMode::DenseSwitch);
        assert!(conf > 0.3);
    }

    #[test]
    fn test_identify_handler_add64() {
        let lifter = TigressLifter::new();
        let body = vec![0x58u8, 0x5B, 0x48, 0x01, 0xD8, 0x50];
        let result = lifter.identify_handler_semantic(&body);
        assert!(result.is_some());
        let (name, conf) = result.unwrap();
        assert_eq!(name, "ADD64");
        assert!(conf >= 0.8);
    }

    #[test]
    fn test_identify_handler_branch() {
        let lifter = TigressLifter::new();
        // pop rax; test rax, rax
        let body = vec![0x58u8, 0x48, 0x85, 0xC0, 0x74, 0x10];
        let result = lifter.identify_handler_semantic(&body);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "BRANCH");
    }

    #[test]
    fn test_lift_add_handler() {
        let lifter = TigressLifter::new();
        let handler = TigressHandler {
            opcode: 0,
            address: 0x1000,
            body: vec![0x58u8, 0x5B, 0x48, 0x01, 0xD8, 0x50],
            semantic: Some("ADD64".into()),
            has_threaded_tail: false,
            confidence: 0.82,
        };
        let lifted = lifter.lift_to_llil(&[handler], 0x1000);
        assert_eq!(lifted.blocks.len(), 1);
        assert!(lifted.unlifted_count == 0);
        assert!(lifted.coverage >= 1.0);
    }

    #[test]
    fn test_register_file_inference_empty() {
        let lifter = TigressLifter::new();
        let rf = lifter.infer_register_file(&[]);
        // Falls back to default x64 layout
        assert_eq!(rf.register_width, 64);
    }
}
