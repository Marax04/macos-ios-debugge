//! GOT/PLT analyzer for ELF binaries.
//!
//! [`ElfGotPltAnalyzer`] parses the `.got`, `.got.plt`, `.plt`, and `.plt.got`
//! sections together with the dynamic relocation tables to recover every GOT
//! slot and PLT stub.  The result surfaces the current binding state of each
//! slot so callers can identify lazy-resolved, eagerly-resolved, and corrupted
//! GOT entries (a common indicator of hooking or exploitation).

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86-64 PLT entry size (push + jmp indirect + padding = 16 bytes).
const PLT_ENTRY_SIZE_X64: u64 = 16;
/// `AArch64` PLT entry size (4 instructions × 4 bytes).
const PLT_ENTRY_SIZE_AARCH64: u64 = 16;
/// 32-bit x86 PLT entry size.
const PLT_ENTRY_SIZE_X86: u64 = 16;

/// ELF relocation type `R_X86_64_JUMP_SLOT`.
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// ELF relocation type `R_X86_64_GLOB_DAT`.
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// ELF relocation type `R_386_JUMP_SLOT`.
pub const R_386_JUMP_SLOT: u32 = 7;
/// ELF relocation type `R_386_GLOB_DAT`.
pub const R_386_GLOB_DAT: u32 = 6;
/// ELF relocation type `R_AARCH64_JUMP_SLOT`.
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
/// ELF relocation type `R_AARCH64_GLOB_DAT`.
pub const R_AARCH64_GLOB_DAT: u32 = 1025;

// ---------------------------------------------------------------------------
// GOT slot binding state
// ---------------------------------------------------------------------------

/// The binding state of a single GOT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GotSlotState {
    /// The PLT resolver stub address (lazy binding not yet invoked).
    Unresolved,
    /// The slot has been resolved to the real symbol address.
    Resolved(u64),
    /// The GOT slot value does not match either expected state — possible hook.
    Anomalous(u64),
    /// The slot value is zero (e.g. in an on-disk binary).
    Zero,
}

// ---------------------------------------------------------------------------
// GotEntry
// ---------------------------------------------------------------------------

/// A single entry from the Global Offset Table.
#[derive(Debug, Clone)]
pub struct GotEntry {
    /// Virtual address of this GOT slot.
    pub slot_address: u64,
    /// Current value stored in the GOT slot (from file or runtime).
    pub slot_value: u64,
    /// Symbol name this slot corresponds to (if known).
    pub symbol_name: String,
    /// ELF relocation type that populates this slot.
    pub reloc_type: u32,
    /// Symbol index in the dynamic symbol table.
    pub sym_index: usize,
    /// Interpreted binding state.
    pub state: GotSlotState,
    /// `true` for a `.got.plt` (PLT-related) entry; `false` for a plain `.got` entry.
    pub is_plt_got: bool,
}

impl GotEntry {
    /// Returns `true` if this slot has been resolved to a non-zero address.
    #[must_use] 
    pub const fn is_resolved(&self) -> bool {
        matches!(self.state, GotSlotState::Resolved(_))
    }

    /// Returns `true` if this slot looks potentially hooked.
    #[must_use] 
    pub const fn is_anomalous(&self) -> bool {
        matches!(self.state, GotSlotState::Anomalous(_))
    }

    /// Returns the resolved address if the slot is in [`GotSlotState::Resolved`] state.
    #[must_use] 
    pub const fn resolved_address(&self) -> Option<u64> {
        match self.state {
            GotSlotState::Resolved(a) => Some(a),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PltEntry
// ---------------------------------------------------------------------------

/// A single PLT stub entry.
#[derive(Debug, Clone)]
pub struct PltEntry {
    /// Virtual address of the PLT stub.
    pub stub_address: u64,
    /// Symbol name this stub resolves.
    pub symbol_name: String,
    /// Virtual address of the corresponding GOT slot.
    pub got_slot_address: u64,
    /// Whether this is a lazy binding stub (in `.plt`) vs. eager (in `.plt.got`).
    pub is_lazy: bool,
    /// Index within the PLT (0 = first real stub, i.e. after the resolver).
    pub plt_index: usize,
}

// ---------------------------------------------------------------------------
// Raw relocation record (simplified)
// ---------------------------------------------------------------------------

/// A simplified relocation record fed to the analyzer.
#[derive(Debug, Clone)]
pub struct RelocRecord {
    /// Relocation offset (virtual address of the GOT slot to be patched).
    pub offset: u64,
    /// Relocation type.
    pub reloc_type: u32,
    /// Symbol index in the dynamic symbol table (0 = no symbol).
    pub sym_index: usize,
    /// Addend (for RELA relocations; 0 for REL).
    pub addend: i64,
}

// ---------------------------------------------------------------------------
// Section descriptor
// ---------------------------------------------------------------------------

/// A minimal descriptor for an ELF section used by the analyzer.
#[derive(Debug, Clone)]
pub struct SectionDesc {
    /// Section name (e.g. `.got.plt`).
    pub name:   String,
    /// Virtual address.
    pub vaddr:  u64,
    /// Size in bytes.
    pub size:   u64,
    /// File offset.
    pub offset: u64,
}

impl SectionDesc {
    /// Returns `true` if `addr` falls within this section's virtual address range.
    #[must_use] 
    pub const fn contains_vaddr(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.vaddr.saturating_add(self.size)
    }
}

// ---------------------------------------------------------------------------
// Architecture selector
// ---------------------------------------------------------------------------

/// Supported ELF architectures for PLT entry size calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerArch {
    X86_64,
    X86,
    Aarch64,
    Other,
}

impl AnalyzerArch {
    /// Returns the PLT entry size in bytes for this architecture.
    #[must_use] 
    pub const fn plt_entry_size(self) -> u64 {
        match self {
            Self::X86_64  => PLT_ENTRY_SIZE_X64,
            Self::X86     => PLT_ENTRY_SIZE_X86,
            Self::Aarch64 => PLT_ENTRY_SIZE_AARCH64,
            Self::Other   => 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// Combined result of GOT/PLT analysis.
#[derive(Debug, Clone, Default)]
pub struct GotPltAnalysis {
    /// All GOT entries discovered.
    pub got_entries:  Vec<GotEntry>,
    /// All PLT stubs discovered.
    pub plt_entries:  Vec<PltEntry>,
    /// Total count of lazy-bound slots.
    pub lazy_count:   usize,
    /// Total count of already-resolved slots.
    pub resolved_count: usize,
    /// Slots with anomalous values (potential GOT overwrites).
    pub anomaly_count: usize,
}

impl GotPltAnalysis {
    /// Returns a reference to the GOT entry for a symbol name, if any.
    #[must_use] 
    pub fn got_entry_for(&self, name: &str) -> Option<&GotEntry> {
        self.got_entries.iter().find(|e| e.symbol_name == name)
    }

    /// Returns a reference to the PLT stub for a symbol name, if any.
    #[must_use] 
    pub fn plt_entry_for(&self, name: &str) -> Option<&PltEntry> {
        self.plt_entries.iter().find(|e| e.symbol_name == name)
    }

    /// Returns all anomalous GOT entries.
    #[must_use] 
    pub fn anomalies(&self) -> Vec<&GotEntry> {
        self.got_entries.iter().filter(|e| e.is_anomalous()).collect()
    }
}

// ---------------------------------------------------------------------------
// ElfGotPltAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes the GOT and PLT of an ELF binary from raw bytes and metadata.
///
/// The analyzer requires:
/// * Raw binary data (for reading GOT slot values from file)
/// * Relocation records from `.rela.plt` / `.rel.plt` and `.rela.dyn` / `.rel.dyn`
/// * Section descriptors for `.plt`, `.plt.got`, `.got`, and `.got.plt`
/// * Dynamic symbol names indexed by symbol table index
/// * Target architecture (for PLT entry-size calculation)
pub struct ElfGotPltAnalyzer<'a> {
    data:        &'a [u8],
    sections:    Vec<SectionDesc>,
    relocations: Vec<RelocRecord>,
    dyn_syms:    Vec<String>,
    arch:        AnalyzerArch,
    image_base:  u64,
}

impl<'a> ElfGotPltAnalyzer<'a> {
    /// Create a new analyzer.
    ///
    /// * `data`        — raw ELF file bytes
    /// * `sections`    — all relevant section descriptors
    /// * `relocations` — merged PLT + dynamic relocations
    /// * `dyn_syms`    — dynamic symbol names (index 0 = first entry)
    /// * `arch`        — target architecture
    /// * `image_base`  — virtual base address (0 for PIE until mapped)
    #[must_use] 
    pub const fn new(
        data:        &'a [u8],
        sections:    Vec<SectionDesc>,
        relocations: Vec<RelocRecord>,
        dyn_syms:    Vec<String>,
        arch:        AnalyzerArch,
        image_base:  u64,
    ) -> Self {
        Self { data, sections, relocations, dyn_syms, arch, image_base }
    }

    /// Find a section by name.
    fn find_section(&self, name: &str) -> Option<&SectionDesc> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Read a 64-bit little-endian value at a file offset.
    fn read_u64_at_file_offset(&self, file_off: usize) -> u64 {
        if file_off.checked_add(8).is_none_or(|end| end > self.data.len()) {
            return 0;
        }
        let bytes: [u8; 8] = self.data[file_off..file_off + 8].try_into().unwrap_or([0; 8]);
        u64::from_le_bytes(bytes)
    }

    /// Read a 32-bit little-endian value at a file offset.
    fn read_u32_at_file_offset(&self, file_off: usize) -> u32 {
        if file_off.checked_add(4).is_none_or(|end| end > self.data.len()) {
            return 0;
        }
        let bytes: [u8; 4] = self.data[file_off..file_off + 4].try_into().unwrap_or([0; 4]);
        u32::from_le_bytes(bytes)
    }

    /// Convert a virtual address to a file offset using the sections list.
    fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<usize> {
        for sec in &self.sections {
            if vaddr >= sec.vaddr && vaddr < sec.vaddr.saturating_add(sec.size) {
                let diff = vaddr - sec.vaddr;
                return Some(usize::try_from(sec.offset + diff).unwrap_or(0));
            }
        }
        None
    }

    /// Determine the binding state of a GOT slot value given:
    /// * `slot_value` — the raw u64 read from the file at the GOT slot
    /// * `plt_section` — the `.plt` section descriptor (if present)
    /// * `expected_range` — the expected range of valid text-segment addresses
    const fn classify_slot(
        slot_value: u64,
        plt_section: Option<&SectionDesc>,
        expected_range: (u64, u64),
    ) -> GotSlotState {
        if slot_value == 0 {
            return GotSlotState::Zero;
        }
        // If the slot points back into the PLT it is still unresolved (lazy).
        if let Some(plt) = plt_section
            && plt.contains_vaddr(slot_value) {
                return GotSlotState::Unresolved;
            }
        // Heuristic: if the value looks like a reasonable code/data pointer, mark resolved.
        // Otherwise mark anomalous.
        let (lo, hi) = expected_range;
        if lo == 0 && hi == 0 {
            // No range given — treat any non-zero non-PLT value as resolved.
            return GotSlotState::Resolved(slot_value);
        }
        if slot_value >= lo && slot_value < hi {
            GotSlotState::Resolved(slot_value)
        } else {
            GotSlotState::Anomalous(slot_value)
        }
    }

    /// Compute a bounding virtual-address range from all known sections.
    fn section_addr_range(&self) -> (u64, u64) {
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        for sec in &self.sections {
            if sec.vaddr > 0 {
                lo = lo.min(sec.vaddr);
                hi = hi.max(sec.vaddr.saturating_add(sec.size));
            }
        }
        if lo == u64::MAX { lo = 0; }
        (lo, hi)
    }

    /// Read the GOT slot value at the virtual address described by `reloc`.
    fn read_slot_value(&self, vaddr: u64) -> u64 {
        self.vaddr_to_file_offset(vaddr)
            .map_or(0, |off| {
                if matches!(self.arch, AnalyzerArch::X86) {
                    u64::from(self.read_u32_at_file_offset(off))
                } else {
                    self.read_u64_at_file_offset(off)
                }
            })
    }

    /// Process PLT-type relocations into GOT entries and PLT stubs.
    fn process_plt_relocs(
        &self,
        plt_relocs: &[&RelocRecord],
        plt_section: Option<&SectionDesc>,
        addr_range: (u64, u64),
        entry_size: u64,
        sym_name: &impl Fn(usize) -> String,
    ) -> (Vec<GotEntry>, Vec<PltEntry>) {
        let mut got_entries = Vec::new();
        let mut plt_stubs = Vec::new();
        for (plt_index, reloc) in plt_relocs.iter().enumerate() {
            let slot_addr = reloc.offset;
            let slot_value = self.read_slot_value(slot_addr);
            let state = Self::classify_slot(slot_value, plt_section, addr_range);
            let name = sym_name(reloc.sym_index);
            let stub_addr = plt_section
                .map_or(0, |p| p.vaddr + (plt_index as u64 + 1) * entry_size);
            got_entries.push(GotEntry {
                slot_address: slot_addr,
                slot_value,
                symbol_name: name.clone(),
                reloc_type: reloc.reloc_type,
                sym_index: reloc.sym_index,
                state,
                is_plt_got: true,
            });
            plt_stubs.push(PltEntry {
                stub_address: stub_addr,
                symbol_name: name,
                got_slot_address: slot_addr,
                is_lazy: true,
                plt_index,
            });
        }
        (got_entries, plt_stubs)
    }

    /// Process non-PLT dynamic relocations into GOT entries and optional eager PLT stubs.
    fn process_dyn_relocs(
        &self,
        dyn_relocs: &[&RelocRecord],
        plt_got_section: Option<&SectionDesc>,
        existing_got_count: usize,
        plt_index_start: usize,
        sym_name: &impl Fn(usize) -> String,
    ) -> (Vec<GotEntry>, Vec<PltEntry>) {
        let mut got_entries = Vec::new();
        let mut plt_stubs = Vec::new();
        let mut plt_index = plt_index_start;
        for (dyn_idx, reloc) in dyn_relocs.iter().enumerate() {
            let slot_addr = reloc.offset;
            let slot_value = self.read_slot_value(slot_addr);
            let state = if slot_value == 0 { GotSlotState::Zero } else { GotSlotState::Resolved(slot_value) };
            let name = sym_name(reloc.sym_index);
            // .plt.got entries are 8 bytes each (x86-64 specific).
            let eager_stub_addr = plt_got_section.map(|s| {
                let idx = (existing_got_count + dyn_idx) as u64;
                s.vaddr + idx * 8
            });
            if let Some(stub_addr) = eager_stub_addr {
                plt_stubs.push(PltEntry {
                    stub_address: stub_addr,
                    symbol_name: name.clone(),
                    got_slot_address: slot_addr,
                    is_lazy: false,
                    plt_index,
                });
                plt_index += 1;
            }
            got_entries.push(GotEntry {
                slot_address: slot_addr,
                slot_value,
                symbol_name: name,
                reloc_type: reloc.reloc_type,
                sym_index: reloc.sym_index,
                state,
                is_plt_got: false,
            });
        }
        (got_entries, plt_stubs)
    }

    /// Run the full GOT/PLT analysis.
    #[must_use]
    pub fn analyze_got(&self) -> GotPltAnalysis {
        let plt_section = self.find_section(".plt");
        let plt_got_section = self.find_section(".plt.got");
        let _got_section = self.find_section(".got");
        let got_plt_section = self.find_section(".got.plt");
        let entry_size = self.arch.plt_entry_size();
        let addr_range = self.section_addr_range();
        let sym_name = |idx: usize| -> String {
            self.dyn_syms.get(idx).cloned().unwrap_or_else(|| format!("sym_{idx}"))
        };

        let plt_relocs: Vec<&RelocRecord> = self.relocations.iter()
            .filter(|r| got_plt_section.is_some_and(|s| s.contains_vaddr(r.offset)))
            .collect();
        let dyn_relocs: Vec<&RelocRecord> = self.relocations.iter()
            .filter(|r| !got_plt_section.is_some_and(|s| s.contains_vaddr(r.offset)))
            .collect();

        let (mut got_entries, mut plt_stubs) =
            self.process_plt_relocs(&plt_relocs, plt_section, addr_range, entry_size, &sym_name);

        let plt_count = plt_stubs.len();
        let (dyn_got, dyn_stubs) =
            self.process_dyn_relocs(&dyn_relocs, plt_got_section, got_entries.len(), plt_count, &sym_name);
        got_entries.extend(dyn_got);
        plt_stubs.extend(dyn_stubs);

        let lazy_count     = got_entries.iter().filter(|e| matches!(e.state, GotSlotState::Unresolved)).count();
        let resolved_count = got_entries.iter().filter(|e| e.is_resolved()).count();
        let anomaly_count  = got_entries.iter().filter(|e| e.is_anomalous()).count();

        GotPltAnalysis {
            got_entries,
            plt_entries: plt_stubs,
            lazy_count,
            resolved_count,
            anomaly_count,
        }
    }

    /// Returns only the GOT entries whose slots appear anomalous.
    #[must_use] 
    pub fn anomalous_entries(&self) -> Vec<GotEntry> {
        self.analyze_got()
            .got_entries
            .into_iter()
            .filter(GotEntry::is_anomalous)
            .collect()
    }

    /// Returns the image base virtual address used for relocation.
    #[must_use] 
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Returns a histogram mapping each GOT slot address to how many
    /// relocations reference it.  Useful for detecting aliased entries.
    #[must_use] 
    pub fn got_slot_histogram(&self) -> HashMap<u64, usize> {
        let mut map: HashMap<u64, usize> = HashMap::new();
        for reloc in &self.relocations {
            *map.entry(reloc.offset + self.image_base).or_insert(0) += 1;
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Standalone convenience function
// ---------------------------------------------------------------------------

/// Analyze the GOT and PLT directly from raw ELF bytes + pre-parsed metadata.
///
/// Returns a [`GotPltAnalysis`] summarizing all GOT/PLT entries found.
#[must_use] 
pub fn analyze_got(
    data:        &[u8],
    sections:    Vec<SectionDesc>,
    relocations: Vec<RelocRecord>,
    dyn_syms:    Vec<String>,
    arch:        AnalyzerArch,
    image_base:  u64,
) -> GotPltAnalysis {
    ElfGotPltAnalyzer::new(data, sections, relocations, dyn_syms, arch, image_base).analyze_got()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_got_data(slot_value: u64) -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        // GOT slot at file offset 0x100
        data[0x100..0x108].copy_from_slice(&slot_value.to_le_bytes());
        data
    }

    fn base_sections() -> Vec<SectionDesc> {
        vec![
            SectionDesc { name: ".plt".into(),     vaddr: 0x1000, size: 0x100, offset: 0x000 },
            SectionDesc { name: ".got.plt".into(), vaddr: 0x3000, size: 0x020, offset: 0x100 },
            SectionDesc { name: ".got".into(),     vaddr: 0x4000, size: 0x020, offset: 0x200 },
        ]
    }

    #[test]
    fn test_analyze_got_empty_relocations() {
        let data = vec![0u8; 0x1000];
        let analysis = analyze_got(&data, base_sections(), vec![], vec![], AnalyzerArch::X86_64, 0);
        assert!(analysis.got_entries.is_empty());
        assert!(analysis.plt_entries.is_empty());
        assert_eq!(analysis.lazy_count, 0);
    }

    #[test]
    fn test_analyze_got_single_plt_reloc_zero_slot() {
        let data = vec![0u8; 0x1000];
        let relocs = vec![RelocRecord {
            offset:     0x3000,
            reloc_type: R_X86_64_JUMP_SLOT,
            sym_index:  0,
            addend:     0,
        }];
        let syms = vec!["malloc".into()];
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        assert_eq!(analysis.got_entries.len(), 1);
        assert_eq!(analysis.got_entries[0].symbol_name, "malloc");
        assert_eq!(analysis.got_entries[0].state, GotSlotState::Zero);
        assert!(analysis.got_entries[0].is_plt_got);
    }

    #[test]
    fn test_analyze_got_lazy_slot_points_into_plt() {
        // GOT slot value = 0x1010 (inside .plt at 0x1000-0x1100)
        let slot_value: u64 = 0x1010;
        // File offset for the .got.plt slot (vaddr 0x3000, section offset 0x100)
        let mut data = vec![0u8; 0x200];
        data[0x100..0x108].copy_from_slice(&slot_value.to_le_bytes());
        let relocs = vec![RelocRecord {
            offset:     0x3000,
            reloc_type: R_X86_64_JUMP_SLOT,
            sym_index:  0,
            addend:     0,
        }];
        let syms = vec!["free".into()];
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        assert_eq!(analysis.got_entries[0].state, GotSlotState::Unresolved);
        assert_eq!(analysis.lazy_count, 1);
    }

    #[test]
    fn test_anomaly_detection() {
        // GOT slot value = 0xDEAD_BEEF — outside any known section range
        let slot_value: u64 = 0xDEAD_BEEF_0000_0000;
        let mut data = vec![0u8; 0x200];
        data[0x100..0x108].copy_from_slice(&slot_value.to_le_bytes());
        let sections = vec![
            SectionDesc { name: ".plt".into(),     vaddr: 0x1000, size: 0x100, offset: 0x000 },
            SectionDesc { name: ".got.plt".into(), vaddr: 0x3000, size: 0x020, offset: 0x100 },
        ];
        let relocs = vec![RelocRecord {
            offset:     0x3000,
            reloc_type: R_X86_64_JUMP_SLOT,
            sym_index:  0,
            addend:     0,
        }];
        let syms = vec!["puts".into()];
        let analysis = analyze_got(&data, sections, relocs, syms, AnalyzerArch::X86_64, 0);
        assert_eq!(analysis.anomaly_count, 1);
        assert!(analysis.got_entries[0].is_anomalous());
    }

    #[test]
    fn test_plt_stub_addresses() {
        let data = vec![0u8; 0x1000];
        let relocs = vec![
            RelocRecord { offset: 0x3000, reloc_type: R_X86_64_JUMP_SLOT, sym_index: 0, addend: 0 },
            RelocRecord { offset: 0x3008, reloc_type: R_X86_64_JUMP_SLOT, sym_index: 1, addend: 0 },
        ];
        let syms = vec!["foo".into(), "bar".into()];
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        // PLT stub 0: plt_base + 1*16 = 0x1010
        // PLT stub 1: plt_base + 2*16 = 0x1020
        assert_eq!(analysis.plt_entries[0].stub_address, 0x1010);
        assert_eq!(analysis.plt_entries[1].stub_address, 0x1020);
        assert!(analysis.plt_entries[0].is_lazy);
    }

    #[test]
    fn test_got_entry_for() {
        let data = vec![0u8; 0x1000];
        let relocs = vec![RelocRecord { offset: 0x3000, reloc_type: R_X86_64_JUMP_SLOT, sym_index: 0, addend: 0 }];
        let syms = vec!["write".into()];
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        assert!(analysis.got_entry_for("write").is_some());
        assert!(analysis.got_entry_for("read").is_none());
    }

    #[test]
    fn test_plt_entry_for() {
        let data = vec![0u8; 0x1000];
        let relocs = vec![RelocRecord { offset: 0x3000, reloc_type: R_X86_64_JUMP_SLOT, sym_index: 0, addend: 0 }];
        let syms = vec!["open".into()];
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        assert!(analysis.plt_entry_for("open").is_some());
    }

    #[test]
    fn test_section_contains_vaddr() {
        let sec = SectionDesc { name: ".got.plt".into(), vaddr: 0x3000, size: 0x20, offset: 0 };
        assert!(sec.contains_vaddr(0x3000));
        assert!(sec.contains_vaddr(0x3018));
        assert!(!sec.contains_vaddr(0x3020));
        assert!(!sec.contains_vaddr(0x2FFF));
    }

    #[test]
    fn test_arch_plt_entry_sizes() {
        assert_eq!(AnalyzerArch::X86_64.plt_entry_size(),  16);
        assert_eq!(AnalyzerArch::X86.plt_entry_size(),     16);
        assert_eq!(AnalyzerArch::Aarch64.plt_entry_size(), 16);
    }

    #[test]
    fn test_got_slot_state_methods() {
        assert!(GotSlotState::Resolved(0x0040_0000).eq(&GotSlotState::Resolved(0x0040_0000)));
        let e = GotEntry {
            slot_address: 0x3000,
            slot_value:   0,
            symbol_name:  "x".into(),
            reloc_type:   R_X86_64_JUMP_SLOT,
            sym_index:    0,
            state:        GotSlotState::Resolved(0x0040_0100),
            is_plt_got:   true,
        };
        assert!(e.is_resolved());
        assert!(!e.is_anomalous());
        assert_eq!(e.resolved_address(), Some(0x0040_0100));
    }

    #[test]
    fn test_dyn_sym_fallback_name() {
        let data = vec![0u8; 0x1000];
        let relocs = vec![RelocRecord { offset: 0x3000, reloc_type: R_X86_64_JUMP_SLOT, sym_index: 99, addend: 0 }];
        let syms: Vec<String> = vec![]; // index 99 is out of range
        let analysis = analyze_got(&data, base_sections(), relocs, syms, AnalyzerArch::X86_64, 0);
        assert_eq!(analysis.got_entries[0].symbol_name, "sym_99");
    }
}
