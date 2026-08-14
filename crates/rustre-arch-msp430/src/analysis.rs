//! `analysis.rs` — Static analysis passes for MSP430 binaries.
//!
//! Provides:
//!
//! * [`detect_functions`]   — heuristic function detection via call-graph and
//!   PUSH R10/R11 prologue patterns.
//! * [`detect_isr_handlers`] — locate interrupt service routines from the
//!   vector table at `0xFFE0`–`0xFFFF`.
//! * [`scan_strings`]       — find null-terminated ASCII strings in ROM
//!   sections.
//! * [`FunctionInfo`], [`IsrInfo`], [`StringRef`] — result types.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::decoder::{InsnKind, Msp430Insn, Op1, decode_insn};

// ── Result types ─────────────────────────────────────────────────────────────

/// Information about a detected function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Start address of the function.
    pub start: u64,
    /// Set of addresses that call this function.
    pub called_from: Vec<u64>,
    /// Whether the function was detected by prologue pattern.
    pub from_prologue: bool,
    /// Whether this function was reached from the binary entry point.
    pub from_entry: bool,
    /// Estimated byte size (end − start).  May be 0 if unknown.
    pub size: usize,
}

impl FunctionInfo {
    const fn new(start: u64) -> Self {
        Self {
            start,
            called_from: Vec::new(),
            from_prologue: false,
            from_entry: false,
            size: 0,
        }
    }
}

/// Information about a detected interrupt service routine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsrInfo {
    /// Address of the handler function.
    pub handler_addr: u64,
    /// Address in the vector table that pointed to this handler.
    pub vector_addr: u16,
    /// Human-readable vector name (e.g. `"RESET"`, `"PORT1"`).
    pub vector_name: &'static str,
}

/// A string literal found in ROM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRef {
    /// Address of the first byte of the string.
    pub addr: u64,
    /// Decoded string content.
    pub text: String,
    /// Length in bytes including the null terminator.
    pub raw_len: usize,
}

// ── Function detection ────────────────────────────────────────────────────────

/// MSP430 function prologue patterns:
///
/// * `PUSH R10` or `PUSH R11` near the start of a block.
/// * Any address directly targeted by a `CALL` instruction.
///
/// Starting from `entry` (usually the reset-vector target), perform a
/// recursive disassembly limited to `max_insns` instructions and collect
/// all discovered function start addresses.
///
/// `bytes` is a flat image buffer; `base_addr` is the mapped address of
/// `bytes[0]`.
#[must_use]
pub fn detect_functions(
    bytes: &[u8],
    base_addr: u64,
    entry: u64,
    max_insns: usize,
) -> Vec<FunctionInfo> {
    let mut functions: BTreeMap<u64, FunctionInfo> = BTreeMap::new();
    let mut worklist: VecDeque<(u64, bool)> = VecDeque::new(); // (addr, is_entry)
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut insn_budget = max_insns;

    // Seed with the binary entry point.
    worklist.push_back((entry, true));

    // Helper: is `addr` within the image?
    let in_image = |addr: u64| addr >= base_addr && addr < base_addr + bytes.len() as u64;

    while let Some((func_start, is_entry)) = worklist.pop_front() {
        if visited.contains(&func_start) || !in_image(func_start) {
            continue;
        }
        visited.insert(func_start);

        let fi = functions
            .entry(func_start)
            .or_insert_with(|| FunctionInfo::new(func_start));
        fi.from_entry |= is_entry;

        // Decode instructions in this function, following internal branches.
        let mut block_worklist: VecDeque<u64> = VecDeque::new();
        let mut visited_blocks: BTreeSet<u64> = BTreeSet::new();
        block_worklist.push_back(func_start);

        let mut last_addr = func_start;

        while let Some(block_start) = block_worklist.pop_front() {
            if visited_blocks.contains(&block_start) || !in_image(block_start) {
                continue;
            }
            visited_blocks.insert(block_start);

            let mut cur = block_start;
            loop {
                if insn_budget == 0 || !in_image(cur) {
                    break;
                }
                let off = usize::try_from(cur - base_addr).unwrap_or(usize::MAX);
                let Ok(insn) = decode_insn(&bytes[off..], cur) else { break };
                insn_budget -= 1;
                let next = cur + insn.size as u64;
                last_addr = next;

                let is_term = insn.is_terminator();

                // Check prologue: PUSH R10 or PUSH R11 near function start.
                if cur <= func_start + 6
                    && let InsnKind::OneOp {
                        op: Op1::Push, src, ..
                    } = &insn.kind
                        && matches!(src.reg, 10 | 11) {
                            functions
                                .entry(func_start)
                                .and_modify(|f| f.from_prologue = true);
                        }

                // Collect call targets.
                if insn.is_call() {
                    let call_site = cur;
                    if let Some(target) = call_target(&insn)
                        && in_image(target) {
                            let callee = functions
                                .entry(target)
                                .or_insert_with(|| FunctionInfo::new(target));
                            if !callee.called_from.contains(&call_site) {
                                callee.called_from.push(call_site);
                            }
                            // Enqueue callee for analysis.
                            if !visited.contains(&target) {
                                worklist.push_back((target, false));
                            }
                        }
                }

                // Follow branch targets within the function.
                if insn.is_branch() {
                    if let Some(target) = insn.branch_target() {
                        block_worklist.push_back(target);
                    }
                    if insn.is_conditional() {
                        block_worklist.push_back(next);
                    }
                }

                cur = next;
                if is_term && !insn.is_branch() {
                    break;
                }
                if is_term {
                    break;
                }
            }
        }

        // Estimate function size.
        if let Some(fi) = functions.get_mut(&func_start)
            && fi.size == 0 && last_addr > func_start {
                fi.size = usize::try_from(last_addr - func_start).unwrap_or(usize::MAX);
            }
    }

    let mut result: Vec<FunctionInfo> = functions.into_values().collect();
    result.sort_by_key(|f| f.start);
    result
}

fn call_target(insn: &Msp430Insn) -> Option<u64> {
    if let InsnKind::OneOp {
        op: Op1::Call, src, ..
    } = &insn.kind
    {
        return src.ext.map(u64::from);
    }
    None
}

// ── ISR detection ─────────────────────────────────────────────────────────────

/// Well-known MSP430 interrupt vectors (address → name).
static VECTOR_TABLE: &[(u16, &str)] = &[
    (0xFFE2, "PORT1"),
    (0xFFE4, "PORT2"),
    (0xFFE6, "COMP_A"),
    (0xFFE8, "WDT"),
    (0xFFEA, "USCI_RX"),
    (0xFFEC, "USCI_TX"),
    (0xFFEE, "TIMERA1"),
    (0xFFF0, "TIMERA0"),
    (0xFFFC, "NMI"),
    (0xFFFE, "RESET"),
];

/// Scan the MSP430 interrupt vector table and return all non-zero vector entries.
///
/// `mem` must cover address range `0xFFE0`–`0xFFFF` (mapped starting at
/// `base_addr`).  Any vector entry pointing inside `[base_addr, base_addr +
/// mem.len())` is returned.
#[must_use]
pub fn detect_isr_handlers(mem: &[u8], base_addr: u64) -> Vec<IsrInfo> {
    let mut result = Vec::with_capacity(VECTOR_TABLE.len());
    for &(vec_addr, name) in VECTOR_TABLE {
        if u64::from(vec_addr) < base_addr {
            continue;
        }
        let off = usize::try_from(u64::from(vec_addr) - base_addr).unwrap_or(usize::MAX);
        if off + 1 >= mem.len() {
            continue;
        }
        let handler = u16::from_le_bytes([mem[off], mem[off + 1]]);
        if handler == 0x0000 || handler == 0xFFFF {
            // Unprogrammed vector.
            continue;
        }
        result.push(IsrInfo {
            handler_addr: u64::from(handler),
            vector_addr: vec_addr,
            vector_name: name,
        });
    }
    result
}

// ── String literal scanner ────────────────────────────────────────────────────

/// Minimum printable-string length to report.
pub const MIN_STRING_LEN: usize = 4;

/// Scan `bytes` (mapped at `base_addr`) for null-terminated ASCII strings of
/// at least `MIN_STRING_LEN` printable characters.
///
/// Only considers bytes in printable ASCII range (0x20–0x7E) plus common
/// escape characters (`\n`, `\r`, `\t`).
#[must_use]
pub fn scan_strings(bytes: &[u8], base_addr: u64) -> Vec<StringRef> {
    let mut result = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        // Scan a run of printable bytes.
        let start = i;
        while i < bytes.len() && is_printable(bytes[i]) {
            i += 1;
        }
        // Must be followed by a null terminator.
        if i < bytes.len() && bytes[i] == 0 && i - start >= MIN_STRING_LEN {
            let raw_len = i - start + 1; // include null
            let text = String::from_utf8_lossy(&bytes[start..i]).into_owned();
            result.push(StringRef {
                addr: base_addr + start as u64,
                text,
                raw_len,
            });
            i += 1; // skip null
        } else {
            // Not a valid string start; advance one byte.
            if i == start {
                i += 1;
            }
        }
    }

    result
}

const fn is_printable(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

// ── ROM section detection ─────────────────────────────────────────────────────

/// A region of the MSP430 address space with a classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRegion {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Human-readable region name.
    pub name: &'static str,
    /// Whether this region is read-only (ROM / flash).
    pub is_rom: bool,
}

impl MemRegion {
    /// Return `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// Return the default `MSP430G2xx` memory map regions.
#[must_use]
pub fn default_memory_map() -> Vec<MemRegion> {
    vec![
        MemRegion {
            start: 0x0000,
            end: 0x0010,
            name: "SFR",
            is_rom: false,
        },
        MemRegion {
            start: 0x0010,
            end: 0x0100,
            name: "Peripherals",
            is_rom: false,
        },
        MemRegion {
            start: 0x0100,
            end: 0x0200,
            name: "Peripherals2",
            is_rom: false,
        },
        MemRegion {
            start: 0x0200,
            end: 0x0400,
            name: "RAM",
            is_rom: false,
        },
        MemRegion {
            start: 0xC000,
            end: 0xFF00,
            name: "Flash",
            is_rom: true,
        },
        MemRegion {
            start: 0xFF00,
            end: 0xFFE0,
            name: "Flash2",
            is_rom: true,
        },
        MemRegion {
            start: 0xFFE0,
            end: 0x1_0000,
            name: "Vectors",
            is_rom: true,
        },
    ]
}

/// Classify an address according to `default_memory_map`.
#[must_use]
pub fn classify_address(addr: u64) -> Option<&'static str> {
    for region in default_memory_map() {
        if region.contains(addr) {
            // Leak the name — it's a static string, so this is fine.
            return Some(region.name);
        }
    }
    None
}

// ── Cross-reference builder ───────────────────────────────────────────────────

/// Cross-reference: address → set of addresses that reference it.
pub type Xrefs = HashMap<u64, Vec<u64>>;

/// Build a cross-reference map by linearly sweeping `bytes`.
///
/// For every CALL and branch instruction that has a statically-known target,
/// record `target → [caller, ...]`.
#[must_use]
pub fn build_xrefs(bytes: &[u8], base_addr: u64) -> Xrefs {
    let mut xrefs: Xrefs = HashMap::new();
    let mut off = 0usize;
    while off + 1 < bytes.len() {
        let addr = base_addr + off as u64;
        match decode_insn(&bytes[off..], addr) {
            Ok(insn) => {
                let step = insn.size;
                // Branch targets (includes CALL #imm targets via branch_target).
                if let Some(target) = insn.branch_target() {
                    xrefs.entry(target).or_default().push(addr);
                } else if let Some(target) = call_target(&insn) {
                    // Fallback for call forms that branch_target doesn't cover.
                    xrefs.entry(target).or_default().push(addr);
                }
                off += step;
            }
            Err(_) => {
                off += 2;
            }
        }
    }
    xrefs
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_functions ──────────────────────────────────────────────────────

    #[test]
    fn entry_point_is_function() {
        // MOV R4, R5; MOV R4, R5; RETI
        let code: Vec<u8> = vec![0x04, 0x45, 0x04, 0x45, 0x00, 0x13];
        let funcs = detect_functions(&code, 0x4000, 0x4000, 1000);
        assert!(!funcs.is_empty());
        assert_eq!(funcs[0].start, 0x4000);
        assert!(funcs[0].from_entry);
    }

    #[test]
    fn call_target_detected() {
        // At 0x4000: CALL #0x4006; at 0x4004: RETI; at 0x4006: RETI
        let mut code = vec![0u8; 10];
        // CALL #0x4006: 0xB012 + 0x4006
        code[0] = 0xB0;
        code[1] = 0x12;
        code[2] = 0x06;
        code[3] = 0x40;
        code[4] = 0x00;
        code[5] = 0x13; // RETI
        code[6] = 0x00;
        code[7] = 0x13; // RETI (callee)
        let funcs = detect_functions(&code, 0x4000, 0x4000, 1000);
        let addrs: Vec<u64> = funcs.iter().map(|f| f.start).collect();
        assert!(addrs.contains(&0x4006), "callee not detected: {addrs:?}");
    }

    #[test]
    fn push_r10_marks_prologue() {
        // PUSH.W R10 at start: opcode3=4, bw=0, as=0, reg=10 = 0x120A
        let mut code = vec![0u8; 6];
        code[0] = 0x0A;
        code[1] = 0x12; // PUSH.W R10
        code[2] = 0x00;
        code[3] = 0x13; // RETI
        let funcs = detect_functions(&code, 0x4000, 0x4000, 1000);
        assert!(funcs[0].from_prologue, "prologue not detected");
    }

    #[test]
    fn prologue_r11() {
        // PUSH.W R11: reg=11 = 0x120B
        let mut code = vec![0u8; 4];
        code[0] = 0x0B;
        code[1] = 0x12; // PUSH.W R11
        code[2] = 0x00;
        code[3] = 0x13; // RETI
        let funcs = detect_functions(&code, 0x4000, 0x4000, 1000);
        assert!(funcs[0].from_prologue);
    }

    // ── detect_isr_handlers ───────────────────────────────────────────────────

    #[test]
    fn isr_reset_detected() {
        // Construct a minimal 64-KiB image with RESET vector pointing to 0x4400.
        let mut mem = vec![0u8; 0x10000];
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0x44;
        let isrs = detect_isr_handlers(&mem, 0);
        let reset = isrs.iter().find(|i| i.vector_name == "RESET");
        assert!(reset.is_some(), "RESET ISR not found");
        assert_eq!(reset.unwrap().handler_addr, 0x4400);
    }

    #[test]
    fn isr_unprogrammed_skipped() {
        let mem = vec![0xFFu8; 0x10000]; // all 0xFF = unprogrammed flash
        let isrs = detect_isr_handlers(&mem, 0);
        assert!(isrs.is_empty(), "unprogrammed vectors should be skipped");
    }

    #[test]
    fn isr_multiple_vectors() {
        let mut mem = vec![0u8; 0x10000];
        // PORT1 vector at 0xFFE2 → 0x4200
        mem[0xFFE2] = 0x00;
        mem[0xFFE3] = 0x42;
        // WDT vector at 0xFFE8 → 0x4300
        mem[0xFFE8] = 0x00;
        mem[0xFFE9] = 0x43;
        let isrs = detect_isr_handlers(&mem, 0);
        let names: Vec<&str> = isrs.iter().map(|i| i.vector_name).collect();
        assert!(names.contains(&"PORT1"));
        assert!(names.contains(&"WDT"));
    }

    // ── scan_strings ──────────────────────────────────────────────────────────

    #[test]
    fn finds_simple_string() {
        let data = b"Hello, world!\0".to_vec();
        let refs = scan_strings(&data, 0x8000);
        assert!(!refs.is_empty());
        assert_eq!(refs[0].text, "Hello, world!");
        assert_eq!(refs[0].addr, 0x8000);
    }

    #[test]
    fn ignores_short_string() {
        let data = b"Hi\0".to_vec(); // length 2 < MIN_STRING_LEN
        let refs = scan_strings(&data, 0x8000);
        assert!(refs.is_empty());
    }

    #[test]
    fn finds_multiple_strings() {
        let data = b"ABCD\0EFGH\0".to_vec();
        let refs = scan_strings(&data, 0xC000);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].text, "ABCD");
        assert_eq!(refs[1].text, "EFGH");
    }

    #[test]
    fn correct_raw_len_includes_null() {
        let data = b"Test\0".to_vec();
        let refs = scan_strings(&data, 0);
        assert_eq!(refs[0].raw_len, 5); // 4 chars + null
    }

    #[test]
    fn skips_non_printable_bytes() {
        // Binary blob with a short string embedded.
        let mut data = vec![0x01u8, 0x02, 0x03];
        data.extend_from_slice(b"Valid\0");
        data.extend_from_slice(&[0xFF, 0x00]);
        let refs = scan_strings(&data, 0);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].text, "Valid");
    }

    // ── default_memory_map / classify_address ─────────────────────────────────

    #[test]
    fn classify_ram() {
        assert_eq!(classify_address(0x0200), Some("RAM"));
        assert_eq!(classify_address(0x03FF), Some("RAM"));
    }

    #[test]
    fn classify_flash() {
        assert_eq!(classify_address(0xC000), Some("Flash"));
        assert_eq!(classify_address(0xD000), Some("Flash"));
    }

    #[test]
    fn classify_vectors() {
        assert_eq!(classify_address(0xFFFE), Some("Vectors"));
    }

    #[test]
    fn classify_unknown() {
        // 0x0400–0xC000 is unmapped in the default map.
        assert_eq!(classify_address(0x0401), None);
    }

    // ── build_xrefs ───────────────────────────────────────────────────────────

    #[test]
    fn xref_from_call() {
        // CALL #0x4006 at 0x4000
        let mut code = vec![0u8; 8];
        code[0] = 0xB0;
        code[1] = 0x12;
        code[2] = 0x06;
        code[3] = 0x40;
        code[4] = 0x00;
        code[5] = 0x13;
        code[6] = 0x00;
        code[7] = 0x13;
        let xrefs = build_xrefs(&code, 0x4000);
        assert!(xrefs.contains_key(&0x4006), "no xref for callee");
        assert_eq!(xrefs[&0x4006], vec![0x4000]);
    }

    #[test]
    fn xref_from_branch() {
        // JMP +0 at 0x4000 → target 0x4002
        let code = [0x00u8, 0x3C];
        let xrefs = build_xrefs(&code, 0x4000);
        assert!(xrefs.contains_key(&0x4002));
    }

    #[test]
    fn xref_empty_for_no_branches() {
        let code = [0x04u8, 0x45]; // MOV R4, R5
        let xrefs = build_xrefs(&code, 0x4000);
        assert!(xrefs.is_empty());
    }

    // ── MemRegion ─────────────────────────────────────────────────────────────

    #[test]
    fn mem_region_contains() {
        let r = MemRegion {
            start: 0x0200,
            end: 0x0400,
            name: "RAM",
            is_rom: false,
        };
        assert!(r.contains(0x0200));
        assert!(r.contains(0x03FF));
        assert!(!r.contains(0x0400));
        assert!(!r.contains(0x01FF));
    }

    // ── FunctionInfo / IsrInfo ────────────────────────────────────────────────

    #[test]
    fn function_size_estimated() {
        // Two MOV + RETI = 6 bytes.
        let code: Vec<u8> = vec![0x04, 0x45, 0x04, 0x45, 0x00, 0x13];
        let funcs = detect_functions(&code, 0x4000, 0x4000, 1000);
        assert_eq!(funcs[0].size, 6);
    }
}
