//! `string_xref_finder` — locate references to string literals in binary code.
//!
//! Supports:
//! * x86-64 PC-relative LEA (RIP+disp32)
//! * x86-64 / x86 direct MOV imm64/imm32
//! * ARM64 ADRP + ADD page-offset sequences
//! * Thumb2 MOVW/MOVT sequences
//! * Generic data-pointer scan
//!
//! Produces a [`StringXrefMap`] from string addresses to all code locations that
//! reference them, enriched with load-kind metadata.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// StringLoad — how the address was loaded

/// The machine-level mechanism by which a string address is loaded into a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringLoad {
    /// x86-64: `LEA reg, [RIP + disp32]`  (PC-relative)
    X64RipRelLea,
    /// x86-64: `MOV reg, imm64`  (absolute 8-byte immediate)
    X64MovImm64,
    /// x86 32-bit: `PUSH imm32` / `MOV reg, imm32`
    X86MovImm32,
    /// ARM64: `ADRP xN, page` followed by `ADD xN, xN, #off`
    Arm64AdrpAdd,
    /// ARM64: `LDR xN, [pc, #off]` (literal pool load)
    Arm64LdrLit,
    /// Thumb-2: `MOVW rN, lo16` / `MOVT rN, hi16`
    Thumb2MovwMovt,
    /// Data section pointer (found in .rodata / .data scan).
    DataPointer,
    /// Unknown or architecture-independent heuristic.
    Heuristic,
}

impl fmt::Display for StringLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::X64RipRelLea  => "x64-rip-rel-lea",
            Self::X64MovImm64   => "x64-mov-imm64",
            Self::X86MovImm32   => "x86-mov-imm32",
            Self::Arm64AdrpAdd  => "arm64-adrp-add",
            Self::Arm64LdrLit   => "arm64-ldr-lit",
            Self::Thumb2MovwMovt=> "thumb2-movw-movt",
            Self::DataPointer   => "data-ptr",
            Self::Heuristic     => "heuristic",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// StringXref — a single resolved reference

/// One cross-reference from code to a string literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringXref {
    /// Address of the instruction that loads the string address.
    pub insn_addr: u64,
    /// Address of the string data in the binary image.
    pub string_addr: u64,
    /// The string content (if known).
    pub content: Option<String>,
    /// Load mechanism.
    pub load_kind: StringLoad,
    /// Function containing this instruction (0 if unknown).
    pub func_addr: u64,
}

impl StringXref {
    #[must_use] 
    pub const fn new(insn_addr: u64, string_addr: u64, load_kind: StringLoad) -> Self {
        Self {
            insn_addr,
            string_addr,
            content: None,
            load_kind,
            func_addr: 0,
        }
    }

    #[must_use]
    pub fn with_content(mut self, s: impl Into<String>) -> Self {
        self.content = Some(s.into());
        self
    }

    #[must_use] 
    pub const fn with_func(mut self, func: u64) -> Self {
        self.func_addr = func;
        self
    }
}

impl fmt::Display for StringXref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x} -> str@{:#x} ({}) fn={:#x}",
            self.insn_addr, self.string_addr, self.load_kind, self.func_addr)?;
        if let Some(ref c) = self.content {
            let snippet: String = c.chars().take(32).collect();
            write!(f, " \"{snippet}\"")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// XrefPattern — a byte-level matching rule

/// A single byte-pattern that, when found in the code section, may indicate
/// a string-loading instruction.
#[derive(Debug, Clone)]
pub struct XrefPattern {
    /// Human-readable name for this pattern.
    pub name: &'static str,
    /// Prefix bytes to match (None = wildcard).
    pub prefix: Vec<Option<u8>>,
    /// Byte offset within the matched sequence where the address / displacement starts.
    pub addr_offset: usize,
    /// Width of the address / displacement in bytes (4 or 8).
    pub addr_width: usize,
    /// Whether the address is PC-relative (offset from `insn_addr` + `pattern.len()`).
    pub pc_relative: bool,
    /// Load mechanism this pattern corresponds to.
    pub load_kind: StringLoad,
}

impl XrefPattern {
    /// Attempt to match `bytes` starting at position `pos`.
    /// Returns the resolved target address on success.
    #[must_use] 
    pub fn try_match(&self, bytes: &[u8], pos: usize, image_base: u64) -> Option<u64> {
        if pos + self.prefix.len() + self.addr_width > bytes.len() {
            return None;
        }
        // Check prefix bytes.
        for (i, expected) in self.prefix.iter().enumerate() {
            if let Some(b) = expected
                && bytes[pos + i] != *b { return None; }
        }
        // Read the address/displacement.
        let aoff = pos + self.addr_offset;
        if aoff + self.addr_width > bytes.len() {
            return None;
        }
        let raw = match self.addr_width {
            4 => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&bytes[aoff..aoff + 4]);
                if self.pc_relative {
                    // A displacement is SIGNED: it can point backwards.
                    i64::from(i32::from_le_bytes(b))
                } else {
                    // An absolute operand is an unsigned 32-bit ADDRESS.
                    // Sign-extending it turned every address with the high bit
                    // set into `0xFFFFFFFF_8xxxxxxx`, so on an x86-32 image
                    // based at or above 0x8000_0000 every string xref resolved
                    // to garbage. `import_xref.rs::extract_first_arg_imm`
                    // decodes the same operands and gets this right.
                    i64::from(u32::from_le_bytes(b))
                }
            }
            8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[aoff..aoff + 8]);
                i64::from_le_bytes(b)
            }
            _ => return None,
        };

        let target = if self.pc_relative {
            // next_insn = address of the byte immediately after this instruction.
            // image_base here is the VA of the current instruction (insn_va passed by caller),
            // so next_insn = insn_va + instruction_length.
            let instr_len = (self.prefix.len() + self.addr_width) as u64;
            let next_insn = image_base.wrapping_add(instr_len);
            next_insn.cast_signed().wrapping_add(raw).cast_unsigned()
        } else {
            raw.cast_unsigned()
        };
        Some(target)
    }
}

// ---------------------------------------------------------------------------
// ArchStringPattern — architecture-specific pattern set

/// A collection of patterns for a target architecture.
#[derive(Debug, Clone)]
pub struct ArchStringPattern {
    pub arch_name: &'static str,
    pub patterns: Vec<XrefPattern>,
}

impl ArchStringPattern {
    /// Returns the built-in x86-64 pattern set.
    #[must_use] 
    pub fn x86_64() -> Self {
        Self {
            arch_name: "x86_64",
            patterns: vec![
                // LEA reg, [RIP+disp32]: 0x48 0x8D prefix (REX.W + LEA), then ModRM byte
                // We match the common form: 48 8D 05 <disp32>  (LEA rax, [rip+disp32])
                XrefPattern {
                    name: "LEA_RAX_RIP",
                    prefix: vec![Some(0x48), Some(0x8D), Some(0x05)],
                    addr_offset: 3,
                    addr_width: 4,
                    pc_relative: true,
                    load_kind: StringLoad::X64RipRelLea,
                },
                // LEA rcx: 48 8D 0D <disp32>
                XrefPattern {
                    name: "LEA_RCX_RIP",
                    prefix: vec![Some(0x48), Some(0x8D), Some(0x0D)],
                    addr_offset: 3,
                    addr_width: 4,
                    pc_relative: true,
                    load_kind: StringLoad::X64RipRelLea,
                },
                // LEA rdx: 48 8D 15 <disp32>
                XrefPattern {
                    name: "LEA_RDX_RIP",
                    prefix: vec![Some(0x48), Some(0x8D), Some(0x15)],
                    addr_offset: 3,
                    addr_width: 4,
                    pc_relative: true,
                    load_kind: StringLoad::X64RipRelLea,
                },
                // LEA rsi: 48 8D 35 <disp32>
                XrefPattern {
                    name: "LEA_RSI_RIP",
                    prefix: vec![Some(0x48), Some(0x8D), Some(0x35)],
                    addr_offset: 3,
                    addr_width: 4,
                    pc_relative: true,
                    load_kind: StringLoad::X64RipRelLea,
                },
                // LEA rdi: 48 8D 3D <disp32>
                XrefPattern {
                    name: "LEA_RDI_RIP",
                    prefix: vec![Some(0x48), Some(0x8D), Some(0x3D)],
                    addr_offset: 3,
                    addr_width: 4,
                    pc_relative: true,
                    load_kind: StringLoad::X64RipRelLea,
                },
                // MOV rax, imm64: 48 B8 <imm64>
                XrefPattern {
                    name: "MOV_RAX_IMM64",
                    prefix: vec![Some(0x48), Some(0xB8)],
                    addr_offset: 2,
                    addr_width: 8,
                    pc_relative: false,
                    load_kind: StringLoad::X64MovImm64,
                },
                // MOV rcx, imm64: 48 B9 <imm64>
                XrefPattern {
                    name: "MOV_RCX_IMM64",
                    prefix: vec![Some(0x48), Some(0xB9)],
                    addr_offset: 2,
                    addr_width: 8,
                    pc_relative: false,
                    load_kind: StringLoad::X64MovImm64,
                },
                // MOV rsi, imm64: 48 BE <imm64>
                XrefPattern {
                    name: "MOV_RSI_IMM64",
                    prefix: vec![Some(0x48), Some(0xBE)],
                    addr_offset: 2,
                    addr_width: 8,
                    pc_relative: false,
                    load_kind: StringLoad::X64MovImm64,
                },
                // MOV rdi, imm64: 48 BF <imm64>
                XrefPattern {
                    name: "MOV_RDI_IMM64",
                    prefix: vec![Some(0x48), Some(0xBF)],
                    addr_offset: 2,
                    addr_width: 8,
                    pc_relative: false,
                    load_kind: StringLoad::X64MovImm64,
                },
            ],
        }
    }

    /// Returns the built-in x86-32 pattern set.
    #[must_use] 
    pub fn x86_32() -> Self {
        Self {
            arch_name: "x86",
            patterns: vec![
                // PUSH imm32: 68 <imm32>
                XrefPattern {
                    name: "PUSH_IMM32",
                    prefix: vec![Some(0x68)],
                    addr_offset: 1,
                    addr_width: 4,
                    pc_relative: false,
                    load_kind: StringLoad::X86MovImm32,
                },
                // MOV eax, imm32: B8 <imm32>
                XrefPattern {
                    name: "MOV_EAX_IMM32",
                    prefix: vec![Some(0xB8)],
                    addr_offset: 1,
                    addr_width: 4,
                    pc_relative: false,
                    load_kind: StringLoad::X86MovImm32,
                },
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// StringXrefMap

/// Map from string address → all cross-references to that string.
#[derive(Debug, Clone, Default)]
pub struct StringXrefMap {
    map: HashMap<u64, Vec<StringXref>>,
    /// Optional: address → content lookup table (populated during scanning).
    string_content: HashMap<u64, String>,
}

impl StringXrefMap {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Insert a resolved xref.
    pub fn insert(&mut self, xref: StringXref) {
        self.map.entry(xref.string_addr).or_default().push(xref);
    }

    /// Register string content for `addr`.
    pub fn register_string(&mut self, addr: u64, content: String) {
        self.string_content.insert(addr, content);
    }

    /// Return all xrefs pointing to `string_addr`.
    #[must_use] 
    pub fn xrefs_to(&self, string_addr: u64) -> &[StringXref] {
        self.map.get(&string_addr).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Return all unique string addresses referenced by code.
    pub fn all_strings(&self) -> impl Iterator<Item = u64> + '_ {
        self.map.keys().copied()
    }

    /// Total number of xref entries.
    #[must_use] 
    pub fn total_xrefs(&self) -> usize {
        self.map.values().map(std::vec::Vec::len).sum()
    }

    /// Lookup the content for `addr` if registered.
    #[must_use] 
    pub fn content_of(&self, addr: u64) -> Option<&str> {
        self.string_content.get(&addr).map(std::string::String::as_str)
    }

    /// Merge another map into `self`.
    pub fn merge(&mut self, other: Self) {
        for (addr, xrefs) in other.map {
            self.map.entry(addr).or_default().extend(xrefs);
        }
        for (addr, content) in other.string_content {
            self.string_content.entry(addr).or_insert(content);
        }
    }

    /// Strings with the most references first.
    #[must_use] 
    pub fn top_referenced(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self.map.iter()
            .map(|(&a, v)| (a, v.len()))
            .collect();
        // `map` is a HashMap: without a tie-break, equal counts are ordered
        // arbitrarily and `truncate` makes that a difference in CONTENT — which
        // strings appear in the top N would change between runs. Sibling
        // queries (`extract.rs`, `xref_query_engine.rs`) already do this.
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }
}

// ---------------------------------------------------------------------------
// StringXrefFinder

/// Scanner that applies architecture-specific patterns to a code section
/// and builds a [`StringXrefMap`].
#[derive(Debug)]
pub struct StringXrefFinder {
    arch_patterns: Vec<ArchStringPattern>,
    /// Range of valid string addresses (for filtering false positives).
    string_section_range: Option<(u64, u64)>,
    /// Minimum string address (absolute) that is considered valid.
    min_string_addr: u64,
}

impl StringXrefFinder {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            arch_patterns: Vec::new(),
            string_section_range: None,
            min_string_addr: 0x1000,
        }
    }

    /// Use built-in x86-64 patterns.
    #[must_use] 
    pub fn with_x86_64(mut self) -> Self {
        self.arch_patterns.push(ArchStringPattern::x86_64());
        self
    }

    /// Use built-in x86-32 patterns.
    #[must_use] 
    pub fn with_x86_32(mut self) -> Self {
        self.arch_patterns.push(ArchStringPattern::x86_32());
        self
    }

    /// Add a custom architecture pattern set.
    #[must_use] 
    pub fn with_arch_patterns(mut self, patterns: ArchStringPattern) -> Self {
        self.arch_patterns.push(patterns);
        self
    }

    /// Limit string address matches to the given range (virtual addresses).
    #[must_use] 
    pub const fn with_string_range(mut self, start: u64, end: u64) -> Self {
        self.string_section_range = Some((start, end));
        self
    }

    /// Minimum valid string VA (default: 0x1000, filters out null/tiny addresses).
    #[must_use] 
    pub const fn with_min_string_addr(mut self, min: u64) -> Self {
        self.min_string_addr = min;
        self
    }

    /// Scan `code_bytes` (mapped at `code_va`) and return all found string xrefs.
    ///
    /// `func_addr` is the containing function address (0 if not known).
    #[must_use] 
    pub fn scan(
        &self,
        code_bytes: &[u8],
        code_va: u64,
        func_addr: u64,
    ) -> StringXrefMap {
        let mut map = StringXrefMap::new();

        for arch in &self.arch_patterns {
            for pat in &arch.patterns {
                let step = pat.prefix.len() + pat.addr_width;
                if step == 0 { continue; }
                let upper = code_bytes.len().saturating_sub(step).saturating_add(1);
                for pos in 0..upper {
                    // code_va originates from a (possibly adversarial) section
                    // VA and can be arbitrarily large; wrap instead of
                    // panicking/relying on release wraparound.
                    let insn_va = code_va.wrapping_add(pos as u64);
                    if let Some(target) = pat.try_match(code_bytes, pos, insn_va) {
                        if !self.is_valid_string_addr(target) { continue; }
                        let xref = StringXref::new(insn_va, target, pat.load_kind)
                            .with_func(func_addr);
                        map.insert(xref);
                    }
                }
            }
        }
        map
    }

    /// Scan a data section for pointer-sized values that fall within the string range.
    #[must_use] 
    pub fn scan_data_pointers(
        &self,
        data_bytes: &[u8],
        data_va: u64,
        pointer_size: usize,
    ) -> StringXrefMap {
        let mut map = StringXrefMap::new();
        if pointer_size != 4 && pointer_size != 8 { return map; }

        let count = data_bytes.len() / pointer_size;
        for i in 0..count {
            let off = i * pointer_size;
            let ptr_va: u64 = if pointer_size == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&data_bytes[off..off + 8]);
                u64::from_le_bytes(b)
            } else {
                let mut b = [0u8; 4];
                b.copy_from_slice(&data_bytes[off..off + 4]);
                u64::from(u32::from_le_bytes(b))
            };
            if self.is_valid_string_addr(ptr_va) {
                // data_va is likewise attacker-influenced (section VA); wrap
                // rather than risk an overflow panic on malformed input.
                let ref_va = data_va.wrapping_add(off as u64);
                map.insert(StringXref::new(ref_va, ptr_va, StringLoad::DataPointer));
            }
        }
        map
    }

    const fn is_valid_string_addr(&self, addr: u64) -> bool {
        if addr < self.min_string_addr { return false; }
        if let Some((lo, hi)) = self.string_section_range {
            addr >= lo && addr < hi
        } else {
            true
        }
    }
}

impl Default for StringXrefFinder {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64_rip_rel_lea_pattern() {
        // LEA rax, [rip+4]  →  48 8D 05 04 00 00 00
        // Instruction is at VA 0x1000, length = 7 bytes → next insn = 0x1007
        // target = 0x1007 + 4 = 0x100B
        let bytes = vec![0x48u8, 0x8D, 0x05, 0x04, 0x00, 0x00, 0x00];
        let finder = StringXrefFinder::new()
            .with_x86_64()
            .with_min_string_addr(0x100B);
        let map = finder.scan(&bytes, 0x1000, 0);
        assert_eq!(map.total_xrefs(), 1);
        let xrefs = map.xrefs_to(0x100B);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].load_kind, StringLoad::X64RipRelLea);
    }

    #[test]
    fn test_x64_mov_imm64_pattern() {
        // MOV rax, 0x0000000000402000  → 48 B8 00 20 40 00 00 00 00 00
        let mut bytes = vec![0x48u8, 0xB8];
        bytes.extend_from_slice(&0x0000000000402000u64.to_le_bytes());
        let finder = StringXrefFinder::new()
            .with_x86_64()
            .with_min_string_addr(0x1000);
        let map = finder.scan(&bytes, 0x1000, 0x1000);
        assert_eq!(map.total_xrefs(), 1);
        let xrefs = map.xrefs_to(0x402000);
        assert_eq!(xrefs[0].load_kind, StringLoad::X64MovImm64);
    }

    #[test]
    fn test_data_pointer_scan() {
        let target: u64 = 0x402000;
        let mut data = Vec::new();
        data.extend_from_slice(&target.to_le_bytes());
        data.extend_from_slice(&0x0u64.to_le_bytes()); // null pointer → should be filtered
        let finder = StringXrefFinder::new()
            .with_min_string_addr(0x1000);
        let map = finder.scan_data_pointers(&data, 0x5000, 8);
        assert_eq!(map.total_xrefs(), 1);
    }

    /// Regression: `code_va`/`data_va` come from section VAs in a
    /// (possibly adversarial) PE and can be arbitrarily large; scanning
    /// must not panic on overflow when `code_va + pos` or `data_va + off`
    /// would wrap past `u64::MAX`.
    #[test]
    fn scan_near_u64_max_code_va_does_not_panic() {
        let bytes = vec![0x48u8, 0x8D, 0x05, 0x04, 0x00, 0x00, 0x00];
        let finder = StringXrefFinder::new().with_x86_64().with_min_string_addr(0);
        let map = finder.scan(&bytes, u64::MAX - 3, 0);
        // No assertion on contents needed — reaching here without panicking
        // is the regression check.
        let _ = map.total_xrefs();
    }

    #[test]
    fn scan_data_pointers_near_u64_max_data_va_does_not_panic() {
        let target: u64 = 0x402000;
        let mut data = Vec::new();
        data.extend_from_slice(&target.to_le_bytes());
        let finder = StringXrefFinder::new().with_min_string_addr(0x1000);
        let map = finder.scan_data_pointers(&data, u64::MAX - 3, 8);
        assert_eq!(map.total_xrefs(), 1);
    }

    #[test]
    fn test_string_range_filter() {
        let mut bytes = vec![0x48u8, 0xB8];
        bytes.extend_from_slice(&0x0000000000402000u64.to_le_bytes());
        // string range does NOT include 0x402000
        let finder = StringXrefFinder::new()
            .with_x86_64()
            .with_string_range(0x500000, 0x600000)
            .with_min_string_addr(0x1000);
        let map = finder.scan(&bytes, 0x1000, 0);
        assert_eq!(map.total_xrefs(), 0);
    }

    #[test]
    fn test_map_merge() {
        let mut m1 = StringXrefMap::new();
        m1.insert(StringXref::new(0x1000, 0x2000, StringLoad::X64RipRelLea));
        let mut m2 = StringXrefMap::new();
        m2.insert(StringXref::new(0x1010, 0x2000, StringLoad::X64MovImm64));
        m1.merge(m2);
        assert_eq!(m1.xrefs_to(0x2000).len(), 2);
    }

    #[test]
    fn test_top_referenced() {
        let mut map = StringXrefMap::new();
        map.insert(StringXref::new(0x100, 0x200, StringLoad::X64RipRelLea));
        map.insert(StringXref::new(0x110, 0x200, StringLoad::X64RipRelLea));
        map.insert(StringXref::new(0x120, 0x300, StringLoad::X64MovImm64));
        let top = map.top_referenced(1);
        assert_eq!(top[0], (0x200, 2));
    }
}
