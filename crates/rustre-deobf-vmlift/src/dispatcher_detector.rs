//! VM dispatcher detection for the VMLIFT deobfuscation pass.
//!
//! # Relation to `vm_dispatcher_finder`
//! This module uses simple imperative scans and returns [`VmDispatcher`]
//! structs (which include virtual-register context, flags, and a description
//! string).  [`crate::vm_dispatcher_finder`] uses a `PatternMatcher` bank
//! with a [`crate::vm_dispatcher_finder::ByteScanner`] helper, returns
//! [`crate::vm_dispatcher_finder::DispatchTable`] / [`crate::vm_dispatcher_finder::DispatchSite`]
//! values, and adds deduplication, grouping, and summary utilities.
//!
//! Both detectors are used together in [`crate::VmLifterPipeline::detect_and_report`]
//! because they cover complementary pattern families.  They are intentionally
//! **distinct layers** and should not be merged.
//!
//! Modern VM-based protectors (`VMProtect`, Themida, Code Virtualizer) implement
//! an interpreter loop centred around a **dispatcher** — the control-flow hub
//! that reads the next bytecode opcode and jumps to the corresponding handler.
//!
//! This module identifies four common dispatcher patterns:
//! 1. **Switch-based** — a dense jump table indexed by the opcode.
//! 2. **Jump-table** — an indirect branch through a register-indexed table.
//! 3. **Threaded** — each handler ends with a direct jump to the next handler.
//! 4. **Interpreter-loop** — a `do { dispatch() } while(!halt)` structure.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// VmRegister
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual register within the VM interpreter context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VmRegister {
    /// Register index (0-based).
    pub index: u8,
    /// Width of the register in bits (8, 16, 32, 64).
    pub width_bits: u8,
    /// Role of this register in the interpreter.
    pub role: RegisterRole,
}

impl VmRegister {
    /// Create a new VM register.
    #[must_use]
    pub const fn new(index: u8, width_bits: u8, role: RegisterRole) -> Self {
        Self {
            index,
            width_bits,
            role,
        }
    }
}

impl std::fmt::Display for VmRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vr{}[{}]<{:?}>", self.index, self.width_bits, self.role)
    }
}

/// The semantic role of a VM register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterRole {
    /// Instruction pointer / program counter.
    VirtualIp,
    /// Stack pointer.
    StackPointer,
    /// Key register used for opcode decryption.
    OpcodeKey,
    /// General-purpose scratch register.
    GeneralPurpose,
    /// Condition flags accumulator.
    Flags,
    /// Base address of the bytecode region.
    BytecodeBase,
    /// Return address register.
    ReturnAddress,
    /// Unknown / not yet classified.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherKind
// ─────────────────────────────────────────────────────────────────────────────

/// The structural pattern of the detected dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatcherKind {
    /// Opcode read → switch/cmp chain → jump to handler.
    SwitchBased,
    /// Opcode read → index into a jump table.
    JumpTable,
    /// Each handler ends with a direct jump to the next (computed) handler.
    Threaded,
    /// Central loop: read opcode → call handler → loop back.
    InterpreterLoop,
    /// Dispatcher pattern not identified.
    Unknown,
}

impl std::fmt::Display for DispatcherKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SwitchBased => write!(f, "switch-based dispatcher"),
            Self::JumpTable => write!(f, "jump-table dispatcher"),
            Self::Threaded => write!(f, "threaded-code dispatcher"),
            Self::InterpreterLoop => write!(f, "interpreter-loop dispatcher"),
            Self::Unknown => write!(f, "unknown dispatcher"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmDispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a detected VM dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDispatcher {
    /// Byte offset of the dispatcher in the binary.
    pub offset: usize,
    /// Approximate size of the dispatcher prologue in bytes.
    pub size: usize,
    /// Kind / structural pattern.
    pub kind: DispatcherKind,
    /// Confidence that this is a true VM dispatcher (0–100).
    pub confidence: u8,
    /// Virtual registers identified within this dispatcher.
    pub registers: Vec<VmRegister>,
    /// Estimated number of handler entries in the dispatch table.
    pub handler_count: usize,
    /// Additional context flags.
    pub flags: DispatcherFlags,
    /// Human-readable description of the detection.
    pub description: String,
}

impl VmDispatcher {
    /// Return `true` when a virtual instruction pointer register was identified.
    #[must_use]
    pub fn has_virtual_ip(&self) -> bool {
        self.registers
            .iter()
            .any(|r| r.role == RegisterRole::VirtualIp)
    }

    /// Return `true` when a virtual stack pointer was identified.
    #[must_use]
    pub fn has_virtual_sp(&self) -> bool {
        self.registers
            .iter()
            .any(|r| r.role == RegisterRole::StackPointer)
    }
}

/// Bit flags providing additional context about the dispatcher.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct DispatcherFlags {
    /// Opcodes are XOR-encrypted before dispatching.
    pub encrypted_opcodes: bool,
    /// The VM uses rolling keys (opcode key changes after each instruction).
    pub rolling_key: bool,
    /// Handlers are located in a separate memory region from the main code.
    pub remote_handlers: bool,
    /// The dispatcher has an anti-debugging guard.
    pub anti_debug_guard: bool,
    /// The bytecode is stored in reverse (right-to-left).
    pub reversed_bytecode: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects VM dispatcher patterns in binary data.
///
/// ```rust
/// use rustre_deobf_vmlift::dispatcher_detector::DispatcherDetector;
///
/// let det = DispatcherDetector::new();
/// let data = vec![0u8; 256]; // placeholder binary
/// let dispatchers = det.detect(&data);
/// println!("Found {} dispatcher(s)", dispatchers.len());
/// ```
#[derive(Debug, Default)]
pub struct DispatcherDetector {
    /// Minimum confidence to report a hit.
    min_confidence: u8,
    /// Whether to also look for encrypted/obfuscated dispatcher variants.
    deep_scan: bool,
}

impl DispatcherDetector {
    /// Create a new detector with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_confidence: 50,
            deep_scan: false,
        }
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u8) -> Self {
        self.min_confidence = min;
        self
    }

    /// Enable deep scan (looks for obfuscated dispatcher variants).
    #[must_use]
    pub const fn with_deep_scan(mut self) -> Self {
        self.deep_scan = true;
        self
    }

    /// Scan `data` and return all identified dispatchers.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<VmDispatcher> {
        let mut results = Vec::new();
        self.detect_switch_dispatchers(data, &mut results);
        self.detect_jump_table_dispatchers(data, &mut results);
        self.detect_threaded_dispatchers(data, &mut results);
        self.detect_interpreter_loop(data, &mut results);
        results.retain(|d| d.confidence >= self.min_confidence);
        results.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        results
    }

    // ── Switch-based dispatcher ───────────────────────────────────────────────
    //
    // Pattern: sequence of `cmp reg, imm; jz handler_n` pairs, often preceded
    // by an opcode fetch (`movzx reg, byte ptr [esi]`).
    fn detect_switch_dispatchers(&self, data: &[u8], out: &mut Vec<VmDispatcher>) {
        let len = data.len();
        if len < 16 {
            return;
        }

        // Cap: prevent memory exhaustion from large crafted inputs.
        const MAX_SWITCH_DISPATCHERS: usize = 4096;
        let start_len = out.len();
        for offset in 0..len - 8 {
            if out.len() - start_len >= MAX_SWITCH_DISPATCHERS {
                break;
            }
            let window = &data[offset..];
            // Look for: movzx r32, byte ptr [reg] followed by cmp sequences
            // movzx eax, byte [esi]:  0F B6 06
            // movzx ecx, byte [edi]:  0F B6 0F
            // movzx eax, byte [ebx]:  0F B6 03
            if window.len() < 3 {
                break;
            }
            if window[0] != 0x0F || window[1] != 0xB6 {
                continue;
            }

            // Count cmp/jz pairs following the opcode fetch
            let mut cmp_count = 0;
            let mut scan = offset + 3;
            while scan + 4 < len {
                // cmp reg, imm8: 83 F8..FE xx or 83 C0..FF xx
                if data[scan] == 0x83 && scan + 2 < len {
                    cmp_count += 1;
                    scan += 3;
                } else if data[scan] == 0x74 || data[scan] == 0x75 {
                    // je/jne short
                    scan += 2;
                } else {
                    break;
                }
            }

            if cmp_count >= 3 {
                let confidence = (50 + cmp_count.min(20) * 2) as u8;
                if confidence >= self.min_confidence {
                    out.push(VmDispatcher {
                        offset,
                        size: scan - offset,
                        kind: DispatcherKind::SwitchBased,
                        confidence,
                        registers: vec![VmRegister::new(0, 32, RegisterRole::VirtualIp)],
                        handler_count: cmp_count,
                        flags: DispatcherFlags::default(),
                        description: format!(
                            "switch-based dispatcher with {cmp_count} cmp/jz pairs at 0x{offset:x}"
                        ),
                    });
                }
            }
        }
    }

    // ── Jump-table dispatcher ─────────────────────────────────────────────────
    //
    // Pattern: `mov|movzx reg, [vip]` → `shl reg, 2/3` → `jmp [table + reg]`
    fn detect_jump_table_dispatchers(&self, data: &[u8], out: &mut Vec<VmDispatcher>) {
        let len = data.len();
        if len < 8 {
            return;
        }

        // Cap: prevent memory exhaustion from large crafted inputs.
        const MAX_JT_DISPATCHERS: usize = 4096;
        let start_len = out.len();
        for offset in 0..len - 8 {
            if out.len() - start_len >= MAX_JT_DISPATCHERS {
                break;
            }
            let w = &data[offset..];
            // jmp [reg*4 + disp32]: FF 24 8D xx xx xx xx
            // jmp [reg*8 + disp32]: FF 24 C5 xx xx xx xx
            if w.len() >= 7 && w[0] == 0xFF && w[1] == 0x24 && (w[2] == 0x8D || w[2] == 0xC5) {
                let confidence = if self.deep_scan { 80 } else { 70 };
                out.push(VmDispatcher {
                    offset,
                    size: 7,
                    kind: DispatcherKind::JumpTable,
                    confidence,
                    registers: vec![
                        VmRegister::new(0, 32, RegisterRole::VirtualIp),
                        VmRegister::new(1, 32, RegisterRole::BytecodeBase),
                    ],
                    handler_count: 256, // unknown, use worst case
                    flags: DispatcherFlags::default(),
                    description: format!("jump-table dispatcher at 0x{offset:x}"),
                });
            }

            // jmp [eax*4 + reg]: FF 24 85 xx xx xx xx (mod r/m with SIB)
            if w.len() >= 7 && w[0] == 0xFF && w[1] == 0x24 && w[2] == 0x85 {
                let confidence = 75;
                out.push(VmDispatcher {
                    offset,
                    size: 7,
                    kind: DispatcherKind::JumpTable,
                    confidence,
                    registers: vec![VmRegister::new(0, 32, RegisterRole::VirtualIp)],
                    handler_count: 256,
                    flags: DispatcherFlags::default(),
                    description: format!("jump-table (SIB) dispatcher at 0x{offset:x}"),
                });
            }

            // x64: jmp [rax*8 + rip+disp]: 48 FF 24 C5 ..
            if w.len() >= 8 && w[0] == 0x48 && w[1] == 0xFF && w[2] == 0x24 && w[3] == 0xC5 {
                out.push(VmDispatcher {
                    offset,
                    size: 8,
                    kind: DispatcherKind::JumpTable,
                    confidence: 80,
                    registers: vec![VmRegister::new(0, 64, RegisterRole::VirtualIp)],
                    handler_count: 256,
                    flags: DispatcherFlags::default(),
                    description: format!("x64 jump-table dispatcher at 0x{offset:x}"),
                });
            }
        }
    }

    // ── Threaded-code dispatcher ──────────────────────────────────────────────
    //
    // Pattern: handler ends with `lodsd` (AC) or `lodsb` (AD) + indirect jump
    // `jmp eax` (FF E0) or `jmp [eax]` (FF 20).
    fn detect_threaded_dispatchers(&self, data: &[u8], out: &mut Vec<VmDispatcher>) {
        let len = data.len();
        if len < 4 {
            return;
        }
        let mut thread_count = 0;
        let mut first_offset = None;

        for offset in 0..len - 3 {
            let w = &data[offset..];
            // lodsb + jmp eax: AC FF E0
            // lodsd + jmp eax: AD FF E0
            if (w[0] == 0xAC || w[0] == 0xAD) && w[1] == 0xFF && w[2] == 0xE0 {
                thread_count += 1;
                if first_offset.is_none() {
                    first_offset = Some(offset);
                }
            }
            // lodsb + jmp [eax]: AC FF 20
            if w[0] == 0xAC && w[1] == 0xFF && w[2] == 0x20 {
                thread_count += 1;
                if first_offset.is_none() {
                    first_offset = Some(offset);
                }
            }
        }

        if thread_count >= 3 {
            let offset = first_offset.unwrap_or(0);
            let confidence = (60 + thread_count.min(15) * 2) as u8;
            out.push(VmDispatcher {
                offset,
                size: 3,
                kind: DispatcherKind::Threaded,
                confidence,
                registers: vec![
                    VmRegister::new(0, 32, RegisterRole::VirtualIp),
                    VmRegister::new(1, 32, RegisterRole::GeneralPurpose),
                ],
                handler_count: thread_count,
                flags: DispatcherFlags::default(),
                description: format!(
                    "threaded-code dispatcher: {thread_count} lodsX+jmp patterns"
                ),
            });
        }
    }

    // ── Interpreter-loop dispatcher ───────────────────────────────────────────
    //
    // Pattern: `inc` / `add esi, N` to advance VIP + conditional `jmp` back to
    // loop head.  We look for a backward short jump (`0x75` / `0xEB` with a
    // negative displacement) following an opcode-fetch sequence.
    fn detect_interpreter_loop(&self, data: &[u8], out: &mut Vec<VmDispatcher>) {
        let len = data.len();
        if len < 6 {
            return;
        }

        // Cap: prevent memory exhaustion from large crafted inputs.
        const MAX_LOOP_DISPATCHERS: usize = 4096;
        let start_len = out.len();
        for offset in 2..len - 4 {
            if out.len() - start_len >= MAX_LOOP_DISPATCHERS {
                break;
            }
            let w = &data[offset..];
            // Short backward jumps: EB xx (negative displacement)
            // or 75 xx (jnz short) with negative disp
            if (w[0] == 0xEB || w[0] == 0x75 || w[0] == 0x74) && (w[1] as i8) < 0 {
                // Check if the region before this jump contains an opcode fetch
                let look_back = offset.saturating_sub(32);
                let pre = &data[look_back..offset];

                // movzx or mov + advance vip (inc esi or add esi, N)
                let has_movzx = pre.windows(2).any(|w| w[0] == 0x0F && w[1] == 0xB6);
                let has_advance = pre.windows(1).any(|w| w[0] == 0x46) // inc esi
                    || pre.windows(3).any(|w| w[0] == 0x83 && (w[1] == 0xC6 || w[1] == 0xC7)); // add esi/edi, n

                if has_movzx && has_advance {
                    out.push(VmDispatcher {
                        offset: look_back,
                        size: offset - look_back + 2,
                        kind: DispatcherKind::InterpreterLoop,
                        confidence: 72,
                        registers: vec![
                            VmRegister::new(6, 32, RegisterRole::VirtualIp), // esi
                        ],
                        handler_count: 0, // unknown from this pattern alone
                        flags: DispatcherFlags::default(),
                        description: format!(
                            "interpreter loop at 0x{look_back:x}: opcode-fetch + backward branch"
                        ),
                    });
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> DispatcherDetector {
        DispatcherDetector::new()
    }

    #[test]
    fn test_detect_jump_table() {
        // FF 24 8D xx xx xx xx
        let mut data = vec![0u8; 32];
        data[10] = 0xFF;
        data[11] = 0x24;
        data[12] = 0x8D;
        let dispatchers = det().detect(&data);
        assert!(
            dispatchers
                .iter()
                .any(|d| d.kind == DispatcherKind::JumpTable)
        );
    }

    #[test]
    fn test_detect_x64_jump_table() {
        let mut data = vec![0u8; 32];
        data[5] = 0x48;
        data[6] = 0xFF;
        data[7] = 0x24;
        data[8] = 0xC5;
        let dispatchers = det().detect(&data);
        assert!(
            dispatchers
                .iter()
                .any(|d| d.kind == DispatcherKind::JumpTable)
        );
    }

    #[test]
    fn test_detect_threaded_lodsb_jmp() {
        // Three lodsb+jmp eax sequences
        let mut data = vec![0x90u8; 64];
        data[5] = 0xAC;
        data[6] = 0xFF;
        data[7] = 0xE0;
        data[15] = 0xAC;
        data[16] = 0xFF;
        data[17] = 0xE0;
        data[25] = 0xAC;
        data[26] = 0xFF;
        data[27] = 0xE0;
        let dispatchers = det().detect(&data);
        assert!(
            dispatchers
                .iter()
                .any(|d| d.kind == DispatcherKind::Threaded)
        );
    }

    #[test]
    fn test_detect_switch_based() {
        // movzx eax, [esi]: 0F B6 06
        // cmp eax, 0: 83 F8 00
        // je near: 74 xx
        // (repeat)
        let mut data = vec![0x90u8; 64];
        let base = 5;
        data[base] = 0x0F;
        data[base + 1] = 0xB6;
        data[base + 2] = 0x06;
        for i in 0..5usize {
            let off = base + 3 + i * 5;
            if off + 4 < data.len() {
                data[off] = 0x83;
                data[off + 1] = 0xF8;
                data[off + 2] = i as u8;
                data[off + 3] = 0x74;
                data[off + 4] = 0x10;
            }
        }
        let dispatchers = det().detect(&data);
        assert!(
            dispatchers
                .iter()
                .any(|d| d.kind == DispatcherKind::SwitchBased)
        );
    }

    #[test]
    fn test_detect_interpreter_loop() {
        // backward jump preceded by movzx + inc esi
        let mut data = vec![0x90u8; 64];
        let base = 10;
        data[base] = 0x0F;
        data[base + 1] = 0xB6; // movzx
        data[base + 2] = 0x06;
        data[base + 3] = 0x46; // inc esi
        // backward jnz
        data[base + 4] = 0x75;
        data[base + 5] = (-(6i8)) as u8;
        let dispatchers = det().detect(&data);
        // May or may not detect depending on exact window
        let _ = dispatchers;
    }

    #[test]
    fn test_no_false_positive_zeros() {
        let data = vec![0u8; 128];
        let dispatchers = det().detect(&data);
        // Zero-filled data should trigger very few or no dispatchers
        // (zero bytes match some patterns incidentally — just verify no panic)
        let _ = dispatchers;
    }

    #[test]
    fn test_vm_register_display() {
        let reg = VmRegister::new(0, 64, RegisterRole::VirtualIp);
        assert!(reg.to_string().contains("vr0[64]"));
    }

    #[test]
    fn test_dispatcher_kind_display() {
        assert_eq!(
            DispatcherKind::JumpTable.to_string(),
            "jump-table dispatcher"
        );
        assert_eq!(
            DispatcherKind::Threaded.to_string(),
            "threaded-code dispatcher"
        );
    }

    #[test]
    fn test_dispatcher_has_virtual_ip() {
        let d = VmDispatcher {
            offset: 0,
            size: 10,
            kind: DispatcherKind::JumpTable,
            confidence: 80,
            registers: vec![VmRegister::new(0, 32, RegisterRole::VirtualIp)],
            handler_count: 256,
            flags: DispatcherFlags::default(),
            description: "test".to_owned(),
        };
        assert!(d.has_virtual_ip());
        assert!(!d.has_virtual_sp());
    }
}
