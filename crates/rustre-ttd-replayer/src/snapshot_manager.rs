use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

// ── Snapshot types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePosition {
    pub sequence: u64,
    pub step: u32,
}

impl TracePosition {
    #[must_use] 
    pub const fn new(sequence: u64, step: u32) -> Self { Self { sequence, step } }
    #[must_use] 
    pub const fn zero() -> Self { Self { sequence: 0, step: 0 } }
    #[must_use] 
    pub const fn is_zero(&self) -> bool { self.sequence == 0 && self.step == 0 }
}

impl PartialOrd for TracePosition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for TracePosition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sequence.cmp(&other.sequence).then(self.step.cmp(&other.step))
    }
}

impl PartialEq for TracePosition {
    fn eq(&self, other: &Self) -> bool { self.sequence == other.sequence && self.step == other.step }
}

impl Eq for TracePosition {}

// ── Register state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterState {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rsp: u64, pub rbp: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
    pub cs: u16, pub ds: u16, pub es: u16, pub fs: u16, pub gs: u16, pub ss: u16,
    pub mxcsr: u32,
    pub xmm: [[u8; 16]; 16],
}

impl RegisterState {
    #[must_use] 
    pub fn diff(&self, other: &Self) -> Vec<RegisterDiff> {
        let mut diffs = Vec::new();
        macro_rules! check {
            ($field:ident) => {
                if self.$field != other.$field {
                    diffs.push(RegisterDiff { name: stringify!($field).to_string(), old_val: self.$field as u64, new_val: other.$field as u64 });
                }
            }
        }
        check!(rax); check!(rbx); check!(rcx); check!(rdx);
        check!(rsi); check!(rdi); check!(rsp); check!(rbp);
        check!(r8); check!(r9); check!(r10); check!(r11);
        check!(r12); check!(r13); check!(r14); check!(r15);
        check!(rip); check!(rflags);
        diffs
    }

    #[must_use] 
    pub fn get_reg(&self, name: &str) -> Option<u64> {
        match name.to_lowercase().as_str() {
            "rax" | "eax" => Some(self.rax),
            "rbx" | "ebx" => Some(self.rbx),
            "rcx" | "ecx" => Some(self.rcx),
            "rdx" | "edx" => Some(self.rdx),
            "rsi" | "esi" => Some(self.rsi),
            "rdi" | "edi" => Some(self.rdi),
            "rsp" | "esp" => Some(self.rsp),
            "rbp" | "ebp" => Some(self.rbp),
            "rip" | "eip" => Some(self.rip),
            "rflags" | "eflags" => Some(self.rflags),
            "r8"  => Some(self.r8),
            "r9"  => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDiff {
    pub name: String,
    pub old_val: u64,
    pub new_val: u64,
}

// ── Memory snapshot ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub data: Vec<u8>,
    pub protection: MemProtection,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryRegion {
    #[must_use] 
    pub const fn size(&self) -> usize { self.data.len() }

    #[must_use] 
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let off = addr.checked_sub(self.base)? as usize;
        self.data.get(off).copied()
    }

    #[must_use] 
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let off = addr.checked_sub(self.base)? as usize;
        if off + 4 > self.data.len() { return None; }
        Some(u32::from_le_bytes(self.data[off..off+4].try_into().ok()?))
    }

    #[must_use] 
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let off = addr.checked_sub(self.base)? as usize;
        if off + 8 > self.data.len() { return None; }
        Some(u64::from_le_bytes(self.data[off..off+8].try_into().ok()?))
    }

    #[must_use] 
    pub fn diff(&self, other: &Self) -> Vec<MemoryDiff> {
        let mut diffs = Vec::new();
        let len = self.data.len().min(other.data.len());
        let mut i = 0;
        while i < len {
            if self.data[i] == other.data[i] {
                i += 1;
            } else {
                let start = i;
                while i < len && (self.data[i] != other.data[i] || (i > start && i - start < 16)) {
                    i += 1;
                }
                diffs.push(MemoryDiff {
                    address: self.base + start as u64,
                    old_bytes: self.data[start..i].to_vec(),
                    new_bytes: other.data[start..i].to_vec(),
                });
            }
        }
        diffs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiff {
    pub address: u64,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
}

// ── Full snapshot ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub id: u64,
    pub position: TracePosition,
    pub label: Option<String>,
    pub registers: RegisterState,
    pub memory_regions: Vec<MemoryRegion>,
    pub loaded_modules: Vec<ModuleInfo>,
    pub thread_contexts: Vec<ThreadContext>,
    pub snapshot_type: SnapshotType,
    pub parent_id: Option<u64>,
    pub creation_reason: String,
    pub compressed_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotType {
    Full,
    Differential,
    RegistersOnly,
    UserRequested,
    Automatic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: Option<String>,
    pub checksum: Option<u32>,
    pub timestamp: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadContext {
    pub thread_id: u32,
    pub registers: RegisterState,
    pub teb_address: Option<u64>,
    pub stack_base: Option<u64>,
    pub stack_limit: Option<u64>,
    pub is_current: bool,
}

impl ProcessSnapshot {
    #[must_use] 
    pub fn diff_registers(&self, other: &Self) -> Vec<RegisterDiff> {
        self.registers.diff(&other.registers)
    }

    #[must_use] 
    pub fn diff_memory(&self, other: &Self) -> Vec<MemoryDiff> {
        let mut all_diffs = Vec::new();
        for region in &self.regions_map() {
            let other_region = other.memory_regions.iter().find(|r| r.base == region.base);
            if let Some(other_r) = other_region {
                all_diffs.extend(region.diff(other_r));
            }
        }
        all_diffs
    }

    fn regions_map(&self) -> Vec<&MemoryRegion> {
        self.memory_regions.iter().collect()
    }

    #[must_use] 
    pub fn total_memory_bytes(&self) -> usize {
        self.memory_regions.iter().map(|r| r.data.len()).sum()
    }

    #[must_use] 
    pub fn find_module_at(&self, addr: u64) -> Option<&ModuleInfo> {
        self.loaded_modules.iter().find(|m| addr >= m.base && addr < m.base + m.size)
    }

    #[must_use] 
    pub fn read_memory(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        for region in &self.memory_regions {
            let off = addr.checked_sub(region.base)?;
            if off as usize + size <= region.data.len() {
                return Some(region.data[off as usize..off as usize + size].to_vec());
            }
        }
        None
    }
}

// ── Snapshot manager ──────────────────────────────────────────────────────────

pub struct SnapshotManager {
    snapshots: BTreeMap<TracePosition, Vec<ProcessSnapshot>>,
    next_id: u64,
    max_snapshots: usize,
    auto_snapshot_interval: Option<u64>,
    total_memory_used: usize,
    memory_limit_bytes: usize,
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotManager {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            snapshots: BTreeMap::new(),
            next_id: 0,
            max_snapshots: 1000,
            auto_snapshot_interval: Some(100_000),
            total_memory_used: 0,
            memory_limit_bytes: 8 * 1024 * 1024 * 1024,
        }
    }

    #[must_use] 
    pub const fn with_memory_limit(mut self, limit: usize) -> Self { self.memory_limit_bytes = limit; self }
    #[must_use] 
    pub const fn with_max_snapshots(mut self, n: usize) -> Self { self.max_snapshots = n; self }

    pub fn add_snapshot(&mut self, mut snapshot: ProcessSnapshot) -> u64 {
        snapshot.id = self.next_id;
        self.next_id += 1;
        let mem_size = snapshot.total_memory_bytes();
        self.total_memory_used += mem_size;
        while self.total_memory_used > self.memory_limit_bytes {
            self.evict_oldest();
        }
        self.snapshots.entry(snapshot.position.clone()).or_default().push(snapshot);
        self.next_id - 1
    }

    #[must_use] 
    pub fn get_at(&self, pos: &TracePosition) -> Option<&ProcessSnapshot> {
        self.snapshots.get(pos)?.first()
    }

    #[must_use] 
    pub fn get_nearest_before(&self, pos: &TracePosition) -> Option<&ProcessSnapshot> {
        self.snapshots.range(..=pos.clone()).next_back()?.1.first()
    }

    #[must_use] 
    pub fn get_nearest_after(&self, pos: &TracePosition) -> Option<&ProcessSnapshot> {
        self.snapshots.range(pos.clone()..).next()?.1.first()
    }

    #[must_use] 
    pub fn list_all(&self) -> Vec<&ProcessSnapshot> {
        self.snapshots.values().flat_map(|v| v.iter()).collect()
    }

    pub fn remove(&mut self, id: u64) -> Option<ProcessSnapshot> {
        for snaps in self.snapshots.values_mut() {
            if let Some(pos) = snaps.iter().position(|s| s.id == id) {
                let snap = snaps.remove(pos);
                self.total_memory_used = self.total_memory_used.saturating_sub(snap.total_memory_bytes());
                return Some(snap);
            }
        }
        None
    }

    fn evict_oldest(&mut self) {
        if let Some(first_pos) = self.snapshots.keys().next().cloned()
            && let Some(snaps) = self.snapshots.get_mut(&first_pos) {
                if let Some(snap) = snaps.first() {
                    self.total_memory_used = self.total_memory_used.saturating_sub(snap.total_memory_bytes());
                }
                snaps.remove(0);
                if snaps.is_empty() { self.snapshots.remove(&first_pos); }
            }
    }

    #[must_use] 
    pub fn should_auto_snapshot(&self, current_sequence: u64) -> bool {
        self.auto_snapshot_interval.is_some_and(|interval| {
            let last_seq = self.snapshots.keys().next_back().map_or(0, |p| p.sequence);
            current_sequence.wrapping_sub(last_seq) >= interval
        })
    }

    #[must_use] 
    pub fn stats(&self) -> SnapshotStats {
        let total = self.snapshots.values().map(std::vec::Vec::len).sum();
        SnapshotStats {
            total_snapshots: total,
            memory_used_bytes: self.total_memory_used,
            memory_limit_bytes: self.memory_limit_bytes,
            oldest_position: self.snapshots.keys().next().cloned(),
            newest_position: self.snapshots.keys().next_back().cloned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotStats {
    pub total_snapshots: usize,
    pub memory_used_bytes: usize,
    pub memory_limit_bytes: usize,
    pub oldest_position: Option<TracePosition>,
    pub newest_position: Option<TracePosition>,
}

// ── Differential snapshot compression ─────────────────────────────────────────

pub struct DeltaEncoder;

impl DeltaEncoder {
    #[must_use] 
    pub fn encode(base: &ProcessSnapshot, current: &RegisterState, memory: &[MemoryRegion]) -> DeltaSnapshot {
        let reg_diffs = base.registers.diff(current);
        let mut mem_diffs = Vec::new();
        for region in memory {
            let base_region = base.memory_regions.iter().find(|r| r.base == region.base);
            if let Some(br) = base_region {
                mem_diffs.extend(br.diff(region));
            } else {
                mem_diffs.push(MemoryDiff {
                    address: region.base,
                    old_bytes: Vec::new(),
                    new_bytes: region.data.clone(),
                });
            }
        }
        DeltaSnapshot {
            base_id: base.id,
            register_diffs: reg_diffs,
            memory_diffs: mem_diffs,
            estimated_size: 0,
        }
    }

    #[must_use] 
    pub fn size_estimate(delta: &DeltaSnapshot) -> usize {
        let reg_size = delta.register_diffs.len() * 24;
        let mem_size: usize = delta.memory_diffs.iter().map(|d| 8 + d.old_bytes.len() + d.new_bytes.len()).sum();
        reg_size + mem_size
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSnapshot {
    pub base_id: u64,
    pub register_diffs: Vec<RegisterDiff>,
    pub memory_diffs: Vec<MemoryDiff>,
    pub estimated_size: usize,
}

// ── Snapshot query engine ──────────────────────────────────────────────────────

pub struct SnapshotQuery<'a> {
    manager: &'a SnapshotManager,
}

impl<'a> SnapshotQuery<'a> {
    #[must_use] 
    pub const fn new(manager: &'a SnapshotManager) -> Self { Self { manager } }

    #[must_use] 
    pub fn snapshots_where_reg_eq(&self, reg: &str, value: u64) -> Vec<&ProcessSnapshot> {
        self.manager.list_all().into_iter()
            .filter(|s| s.registers.get_reg(reg) == Some(value))
            .collect()
    }

    #[must_use] 
    pub fn snapshots_with_rip_in_module(&self, module: &str) -> Vec<&ProcessSnapshot> {
        self.manager.list_all().into_iter()
            .filter(|s| {
                let rip = s.registers.rip;
                s.find_module_at(rip).is_some_and(|m| m.name.contains(module))
            })
            .collect()
    }

    #[must_use] 
    pub fn find_rip_history(&self, address: u64) -> Vec<(&TracePosition, &ProcessSnapshot)> {
        let mut results = Vec::new();
        for (pos, snaps) in &self.manager.snapshots {
            for snap in snaps {
                if snap.registers.rip == address {
                    results.push((pos, snap));
                }
            }
        }
        results
    }

    #[must_use] 
    pub fn memory_changed_between(&self, start: &TracePosition, end: &TracePosition, address: u64) -> bool {
        let snap_start = self.manager.get_nearest_before(start);
        let snap_end = self.manager.get_nearest_before(end);
        match (snap_start, snap_end) {
            (Some(a), Some(b)) => {
                let v_a = a.read_memory(address, 8);
                let v_b = b.read_memory(address, 8);
                v_a != v_b
            }
            _ => false,
        }
    }
}
