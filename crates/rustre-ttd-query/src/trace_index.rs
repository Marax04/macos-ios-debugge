use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use rustre_core::address::Address as CoreAddress;
use rustre_ttd::{TracePosition, TraceEvent, EventKind};

// ── Index data structures ─────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TraceIndex {
    pub path: PathBuf,
    pub total_positions: u64,
    pub thread_ranges: HashMap<u32, (TracePosition, TracePosition)>,
    pub module_loads: BTreeMap<TracePosition, ModuleLoadEvent>,
    pub call_index: CallIndex,
    pub memory_index: MemoryAccessIndex,
    pub exception_index: ExceptionIndex,
    pub symbol_index: SymbolIndex,
    pub custom_index: HashMap<String, Vec<TracePosition>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadEvent {
    pub position: TracePosition,
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
    pub is_load: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CallIndex {
    // function_name -> sorted list of positions where it was called
    pub by_name: HashMap<String, Vec<TracePosition>>,
    // address -> sorted list of positions
    pub by_address: BTreeMap<u64, Vec<TracePosition>>,
    // call depth timeline: position -> depth
    pub depth_snapshots: BTreeMap<TracePosition, u32>,
    // recursive calls: function -> positions where recursion happened
    pub recursive: HashMap<String, Vec<TracePosition>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryAccessIndex {
    // address range -> sorted access records
    pub accesses: BTreeMap<u64, Vec<MemAccess>>,
    // positions where heap was modified
    pub heap_writes: Vec<TracePosition>,
    // positions where stack was modified
    pub stack_writes: Vec<TracePosition>,
    // UAF candidates: free events + subsequent access within X positions
    pub uaf_candidates: Vec<UafCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccess {
    pub position: TracePosition,
    pub address: u64,
    pub size: u8,
    pub kind: AccessKind,
    pub value: Option<u64>,
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessKind { Read, Write, Execute }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UafCandidate {
    pub alloc_pos: TracePosition,
    pub free_pos: TracePosition,
    pub use_pos: TracePosition,
    pub address: u64,
    pub confidence: f32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExceptionIndex {
    pub exceptions: Vec<ExceptionRecord>,
    pub by_code: HashMap<u32, Vec<usize>>,  // exception code -> indices into exceptions
    pub by_address: BTreeMap<u64, Vec<usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    pub position: TracePosition,
    pub code: u32,
    pub address: u64,
    pub is_first_chance: bool,
    pub thread_id: u32,
    pub description: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SymbolIndex {
    pub symbols: HashMap<String, SymbolInfo>,
    pub by_address: BTreeMap<u64, String>,
    pub by_module: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub module: String,
    pub size: Option<u64>,
    pub call_count: u64,
    pub first_call: Option<TracePosition>,
    pub last_call: Option<TracePosition>,
}

// ── Index builder ─────────────────────────────────────────────────────────────
// Accepts canonical rustre_ttd::TraceEvent events to avoid duplicate type definitions.

pub struct IndexBuilder {
    index: TraceIndex,
    call_stack: HashMap<u32, Vec<(u64, TracePosition)>>,  // tid -> stack of (addr, pos)
    alloc_map: HashMap<u64, (TracePosition, u64)>,  // addr -> (alloc_pos, size)
}

impl IndexBuilder {
    pub fn new(trace_path: impl Into<PathBuf>) -> Self {
        Self {
            index: TraceIndex { path: trace_path.into(), ..Default::default() },
            call_stack: HashMap::new(),
            alloc_map: HashMap::new(),
        }
    }

    pub fn process_event(&mut self, event: &TraceEvent) {
        // Update thread ranges
        let entry = self.index.thread_ranges.entry(event.thread_id).or_insert((event.position, event.position));
        if event.position < entry.0 { entry.0 = event.position; }
        if event.position > entry.1 { entry.1 = event.position; }

        match &event.kind {
            EventKind::Call { from: _, to } => {
                self.index.call_index.by_address
                    .entry(*to)
                    .or_default()
                    .push(event.position);

                // Track call stack for depth snapshots
                let stack = self.call_stack.entry(event.thread_id).or_default();
                stack.push((*to, event.position));

                let depth = stack.len() as u32;
                self.index.call_index.depth_snapshots.insert(event.position, depth);
            }
            EventKind::Return { .. } => {
                if let Some(stack) = self.call_stack.get_mut(&event.thread_id) {
                    stack.pop();
                }
            }
            EventKind::MemRead { addr, len } => {
                self.index.memory_index.accesses
                    .entry(*addr)
                    .or_default()
                    .push(MemAccess {
                        position: event.position,
                        address: *addr,
                        size: (*len).min(255) as u8,
                        kind: AccessKind::Read,
                        value: None,
                        thread_id: event.thread_id,
                    });
            }
            EventKind::MemWrite { addr, data } => {
                self.index.memory_index.accesses
                    .entry(*addr)
                    .or_default()
                    .push(MemAccess {
                        position: event.position,
                        address: *addr,
                        size: data.len().min(255) as u8,
                        kind: AccessKind::Write,
                        value: None,
                        thread_id: event.thread_id,
                    });
                // Track the first write to each address as a synthetic
                // "allocation" so that later analyses can answer
                // "when was this region first defined?" without re-scanning
                // the entire trace.
                self.alloc_map
                    .entry(*addr)
                    .or_insert((event.position, data.len() as u64));
            }
            EventKind::Exception { code, addr } => {
                let idx = self.index.exception_index.exceptions.len();
                self.index.exception_index.exceptions.push(ExceptionRecord {
                    position: event.position,
                    code: *code,
                    address: *addr,
                    is_first_chance: true,
                    thread_id: event.thread_id,
                    description: describe_exception(*code),
                });
                self.index.exception_index.by_address.entry(*addr).or_default().push(idx);
                self.index.exception_index.by_code.entry(*code).or_default().push(idx);
            }
            _ => {}
        }

        self.index.total_positions = self.index.total_positions.max(event.position.sequence);
    }

    /// Look up the recorded first-write ("synthetic alloc") position and
    /// length for `addr`, if any.
    #[must_use]
    pub fn alloc_of(&self, addr: u64) -> Option<(TracePosition, u64)> {
        self.alloc_map.get(&addr).copied()
    }

    /// Number of distinct addresses tracked in the synthetic allocation map.
    #[must_use]
    pub fn alloc_map_len(&self) -> usize {
        self.alloc_map.len()
    }

    #[must_use]
    pub fn finalize(mut self) -> TraceIndex {
        // Sort all position vectors for binary search
        for positions in self.index.call_index.by_name.values_mut() {
            positions.sort_unstable();
            positions.dedup();
        }
        for positions in self.index.call_index.by_address.values_mut() {
            positions.sort_unstable();
        }
        for accesses in self.index.memory_index.accesses.values_mut() {
            accesses.sort_unstable_by_key(|a| a.position);
        }
        // Build by_address symbol index
        for (name, sym) in &self.index.symbol_index.symbols {
            self.index.symbol_index.by_address.insert(sym.address, name.clone());
        }
        self.index
    }
}

fn describe_exception(code: u32) -> String {
    match code {
        0xC000_0005 => "Access Violation".to_string(),
        0xC000_0094 => "Integer Divide By Zero".to_string(),
        0xC000_0096 => "Privileged Instruction".to_string(),
        0xC000_001D => "Illegal Instruction".to_string(),
        0x8000_0003 => "Breakpoint".to_string(),
        0x8000_0004 => "Single Step".to_string(),
        0xC000_0374 => "Heap Corruption".to_string(),
        0xC000_00FD => "Stack Overflow".to_string(),
        _ => format!("Exception {code:#010x}"),
    }
}

// ── Query engine ──────────────────────────────────────────────────────────────

pub struct IndexQueryEngine<'a> {
    index: &'a TraceIndex,
}

impl<'a> IndexQueryEngine<'a> {
    #[must_use]
    pub const fn new(index: &'a TraceIndex) -> Self { Self { index } }

    #[must_use]
    pub fn calls_to_address(&self, addr: u64) -> &[TracePosition] {
        self.index.call_index.by_address.get(&addr).map(std::vec::Vec::as_slice).unwrap_or(&[])
    }

    #[must_use]
    pub fn calls_in_address_range(&self, addr: u64, from: TracePosition, to: TracePosition) -> Vec<TracePosition> {
        self.calls_to_address(addr).iter()
            .filter(|&&p| p >= from && p <= to)
            .copied()
            .collect()
    }

    /// Look up memory accesses in a range expressed as `rustre_core` address types.
    /// This bridges the canonical core address abstraction into the index query engine.
    #[must_use]
    pub fn memory_accesses_in_core_range(&self, start: CoreAddress, end: CoreAddress) -> Vec<&MemAccess> {
        let size = end.as_u64().saturating_sub(start.as_u64());
        self.memory_accesses_in_range(start.as_u64(), size)
    }

    #[must_use]
    pub fn memory_accesses_in_range(&self, addr: u64, size: u64) -> Vec<&MemAccess> {
        let mut results = Vec::new();
        for (&_base, accesses) in self.index.memory_index.accesses.range(addr..addr + size) {
            for acc in accesses {
                if acc.address >= addr && acc.address < addr + size {
                    results.push(acc);
                }
            }
        }
        results
    }

    #[must_use]
    pub fn writes_to_address_after(&self, addr: u64, after: TracePosition) -> Vec<&MemAccess> {
        self.index.memory_index.accesses.get(&addr)
            .map(|accesses| {
                accesses.iter()
                    .filter(|a| a.position >= after && a.kind == AccessKind::Write)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn exceptions_between(&self, from: TracePosition, to: TracePosition) -> Vec<&ExceptionRecord> {
        self.index.exception_index.exceptions.iter()
            .filter(|e| e.position >= from && e.position <= to)
            .collect()
    }

    #[must_use]
    pub fn get_call_depth_at(&self, position: TracePosition) -> u32 {
        self.index.call_index.depth_snapshots
            .range(..=position)
            .next_back()
            .map_or(0, |(_, &depth)| depth)
    }

    #[must_use]
    pub fn module_at_position(&self, position: TracePosition) -> Option<&ModuleLoadEvent> {
        self.index.module_loads.range(..=position)
            .next_back()
            .map(|(_, e)| e)
    }

    #[must_use]
    pub fn generate_flamegraph_data(&self) -> Vec<FlamegraphFrame> {
        let mut frames = Vec::new();
        for (name, sym) in &self.index.symbol_index.symbols {
            frames.push(FlamegraphFrame {
                name: name.clone(),
                value: sym.call_count,
                module: sym.module.clone(),
            });
        }
        frames.sort_by_key(|b| std::cmp::Reverse(b.value));
        frames
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlamegraphFrame {
    pub name: String,
    pub value: u64,
    pub module: String,
}

// ── Index serialization ────────────────────────────────────────────────────────

impl TraceIndex {
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read index: {}", path.display()))?;
        let index: Self = serde_json::from_str(&data)?;
        Ok(index)
    }

    #[must_use]
    pub fn summary(&self) -> IndexSummary {
        IndexSummary {
            total_positions: self.total_positions,
            num_threads: self.thread_ranges.len(),
            num_modules: self.module_loads.len(),
            num_unique_functions: self.symbol_index.symbols.len(),
            num_exceptions: self.exception_index.exceptions.len(),
            num_memory_addresses_tracked: self.memory_index.accesses.len(),
            num_uaf_candidates: self.memory_index.uaf_candidates.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSummary {
    pub total_positions: u64,
    pub num_threads: usize,
    pub num_modules: usize,
    pub num_unique_functions: usize,
    pub num_exceptions: usize,
    pub num_memory_addresses_tracked: usize,
    pub num_uaf_candidates: usize,
}
