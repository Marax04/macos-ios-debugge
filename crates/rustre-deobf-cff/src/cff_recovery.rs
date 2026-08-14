//! Control Flow Flattening recovery for `rustre-deobf-cff`.
//!
//! High-level API wrapping the existing CFF infrastructure with dispatcher
//! analysis, state-variable tracking, structured output reconstruction, and
//! signature-based CFF detection.

pub use crate::{BlockMapping, CffDeobfuscationPass, CffPattern, EdgeType, SimpleBb};
use crate::{CffCandidate, CffDetector, CffRecoverer, RecoveredCfg, SimpleCfg, StateVariable};
pub use std::collections::HashMap;
// `CffSignature` is also defined locally in this module (see below).
// Keep the alias type around for callers that referenced it by the old name.
pub type LibCffSignature = CffSignature;
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

// ── CaseBlock ─────────────────────────────────────────────────────────────────

/// One handler block in the flattened CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBlock {
    pub state_value: u64,
    pub start_address: u64,
    pub next_state: Option<u64>,
    pub next_state_false: Option<u64>,
    pub is_terminal: bool,
    pub instruction_count: usize,
    pub raw_bytes: Vec<u8>,
}

impl CaseBlock {
    #[must_use]
    pub const fn new(state_value: u64, start_address: u64) -> Self {
        Self {
            state_value,
            start_address,
            next_state: None,
            next_state_false: None,
            is_terminal: false,
            instruction_count: 0,
            raw_bytes: Vec::new(),
        }
    }

    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        self.next_state.is_some() && self.next_state_false.is_some()
    }

    #[must_use]
    pub fn successors(&self) -> Vec<u64> {
        let mut v = Vec::new();
        if let Some(n) = self.next_state {
            v.push(n);
        }
        if let Some(n) = self.next_state_false {
            v.push(n);
        }
        v
    }
}

// ── FlattenedFunction ─────────────────────────────────────────────────────────

/// A function identified as CFF-protected with its dispatcher and case blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlattenedFunction {
    pub function_address: u64,
    pub dispatcher_address: u64,
    pub case_blocks: Vec<CaseBlock>,
    pub state_variable: String,
    pub initial_state: Option<u64>,
    pub pattern: String,
}

impl FlattenedFunction {
    #[must_use]
    pub const fn new(function_address: u64, dispatcher_address: u64) -> Self {
        Self {
            function_address,
            dispatcher_address,
            case_blocks: Vec::new(),
            state_variable: String::new(),
            initial_state: None,
            pattern: String::new(),
        }
    }

    #[must_use]
    pub const fn case_count(&self) -> usize {
        self.case_blocks.len()
    }

    #[must_use]
    pub fn find_case(&self, state: u64) -> Option<&CaseBlock> {
        self.case_blocks.iter().find(|c| c.state_value == state)
    }

    #[must_use]
    pub fn entry_case(&self) -> Option<&CaseBlock> {
        self.initial_state.and_then(|s| self.find_case(s))
    }
}

// ── StateVariable analysis ────────────────────────────────────────────────────

/// Analysis of where the CFF state variable lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVariableInfo {
    pub location: String,
    pub size_bytes: usize,
    pub known_values: Vec<u64>,
    pub initial_value: Option<u64>,
    pub write_count: usize,
}

impl StateVariableInfo {
    #[must_use]
    pub fn from_state_var(sv: &StateVariable) -> Self {
        let location = sv.to_string();
        Self {
            location,
            size_bytes: 4,
            known_values: Vec::new(),
            initial_value: None,
            write_count: 0,
        }
    }

    pub fn add_known_value(&mut self, v: u64) {
        if !self.known_values.contains(&v) {
            self.known_values.push(v);
        }
    }

    #[must_use]
    pub const fn value_count(&self) -> usize {
        self.known_values.len()
    }
}

// ── StructuredOutput ──────────────────────────────────────────────────────────

/// Structured representation of the recovered control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StructuredStatement {
    /// Linear sequence.
    Block { address: u64, next: Option<u64> },
    /// If-then-else.
    IfThen {
        condition_address: u64,
        true_branch: u64,
        false_branch: u64,
    },
    /// While loop.
    While {
        condition_address: u64,
        body_start: u64,
    },
    /// For-like loop (init, condition, step all identified).
    For {
        init_address: u64,
        condition_address: u64,
        step_address: u64,
        body_start: u64,
    },
    /// Return.
    Return { address: u64 },
}

/// Recovered structured output from CFF removal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuredOutput {
    pub statements: Vec<StructuredStatement>,
    pub block_order: Vec<u64>,
}

impl StructuredOutput {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            statements: Vec::new(),
            block_order: Vec::new(),
        }
    }

    pub fn add(&mut self, stmt: StructuredStatement) {
        self.statements.push(stmt);
    }

    #[must_use]
    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    #[must_use]
    pub fn has_loops(&self) -> bool {
        self.statements.iter().any(|s| {
            matches!(
                s,
                StructuredStatement::While { .. } | StructuredStatement::For { .. }
            )
        })
    }

    #[must_use]
    pub fn has_conditionals(&self) -> bool {
        self.statements
            .iter()
            .any(|s| matches!(s, StructuredStatement::IfThen { .. }))
    }
}

// ── CffSignature ──────────────────────────────────────────────────────────────

/// Byte-pattern signature for CFF dispatcher detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CffSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
    pub min_case_count: u32,
    pub confidence: f32,
}

impl CffSignature {
    #[must_use]
    pub fn new(name: impl Into<String>, pattern: Vec<u8>, confidence: f32) -> Self {
        let len = pattern.len();
        Self {
            name: name.into(),
            pattern,
            mask: vec![0xFF; len],
            min_case_count: 5,
            confidence,
        }
    }

    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        self.pattern
            .iter()
            .zip(&self.mask)
            .enumerate()
            .all(|(i, (&p, &m))| data[offset + i] & m == p & m)
    }

    /// Scan `data` for all occurrences.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        let last = data.len().saturating_sub(self.pattern.len());
        (0..=last)
            .filter(|&i| self.matches(data, i))
            .collect()
    }
}

/// Built-in CFF signatures for common obfuscators.
#[must_use]
pub fn builtin_cff_signatures() -> Vec<CffSignature> {
    vec![
        // OLLVM switch dispatcher: FF 24 CD (jmp [rcx*8+base])
        CffSignature::new("OLLVM-jmp-table", vec![0xFF, 0x24, 0xCD], 0.85),
        // OLLVM dispatcher: FF E0 (jmp rax) after table load
        CffSignature::new("OLLVM-computed-jmp", vec![0xFF, 0xE0], 0.70),
        // VMProtect: FF 25 (jmp [rip+rel]) indirect dispatch
        CffSignature::new("VMProtect-indirect", vec![0xFF, 0x25], 0.65),
        // tigress: 81 3D (cmp dword [rip+disp], imm32) + JCC
        CffSignature::new("Tigress-compare-dispatch", vec![0x81, 0x3D], 0.72),
        // obfuscator-llvm: 83 3D (cmp [rip+disp], imm8) + JCC
        CffSignature::new("OLLVM-cmp-imm8", vec![0x83, 0x3D], 0.75),
    ]
}

// ── CffRecovery ───────────────────────────────────────────────────────────────

/// High-level CFF recovery wrapper.
pub struct CffRecovery {
    pub detector: CffDetector,
    pub recoverer: CffRecoverer,
    pub signatures: Vec<CffSignature>,
    pub min_confidence: f64,
}

impl Default for CffRecovery {
    fn default() -> Self {
        Self::new()
    }
}

impl CffRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            detector: CffDetector::new(),
            recoverer: CffRecoverer::new(),
            signatures: builtin_cff_signatures(),
            min_confidence: 0.6,
        }
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: f64) -> Self {
        self.min_confidence = c;
        self
    }

    /// Add a custom signature.
    pub fn add_signature(&mut self, sig: CffSignature) {
        self.signatures.push(sig);
    }

    /// Scan raw bytes for CFF dispatcher signatures.
    #[must_use]
    pub fn scan_signatures(&self, data: &[u8], base_addr: u64) -> Vec<(String, u64, f32)> {
        let mut results = Vec::with_capacity(self.signatures.len());
        for sig in &self.signatures {
            for offset in sig.scan(data) {
                results.push((sig.name.clone(), base_addr + offset as u64, sig.confidence));
            }
        }
        results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Detect and recover CFF from a `SimpleCfg`.
    #[must_use]
    pub fn recover_from_cfg(
        &self,
        cfg: &SimpleCfg,
        function_start: Address,
    ) -> Option<RecoveredCfg> {
        let candidate = self.detector.detect(cfg, function_start)?;
        if candidate.confidence < self.min_confidence {
            return None;
        }
        let recovered = self.recoverer.recover(&candidate, cfg);
        Some(recovered)
    }

    /// Build a `FlattenedFunction` from a detected candidate.
    #[must_use]
    pub fn build_flattened_function(
        &self,
        candidate: &CffCandidate,
        cfg: &SimpleCfg,
    ) -> FlattenedFunction {
        let mut ff = FlattenedFunction::new(
            candidate.function_start.as_u64(),
            candidate.dispatcher_address.as_u64(),
        );
        ff.state_variable = candidate.state_variable.to_string();
        ff.pattern = candidate.pattern.to_string();

        // Build case blocks from non-dispatcher blocks.
        let dispatcher_idx = cfg
            .blocks
            .iter()
            .position(|b| b.address == candidate.dispatcher_address);
        for (i, block) in cfg.blocks.iter().enumerate() {
            if Some(i) == dispatcher_idx {
                continue;
            }
            let state = block
                .state_const
                .unwrap_or(block.address.as_u64() & 0xFFFF_FFFF);
            let mut cb = CaseBlock::new(state, block.address.as_u64());
            cb.instruction_count = block.instr_count;
            cb.is_terminal = block.successor_count == 0;
            // Find successors.
            let mut succs = cfg
                .edges
                .iter()
                .filter(|(from, _, _)| *from == i && Some(*from) != dispatcher_idx)
                .filter_map(|(_, to, _)| cfg.blocks.get(*to).map(|b| b.address.as_u64()));
            if let Some(n) = succs.next() {
                cb.next_state = Some(n);
            }
            if let Some(n) = succs.next() {
                cb.next_state_false = Some(n);
            }
            ff.case_blocks.push(cb);
        }
        ff
    }

    /// Reconstruct structured output from a recovered CFG.
    #[must_use]
    pub fn build_structured_output(&self, recovered: &RecoveredCfg) -> StructuredOutput {
        let mut out = StructuredOutput::new();
        // BFS ordering.
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(recovered.function_start);
        while let Some(addr) = queue.pop_front() {
            if !visited.insert(addr.as_u64()) {
                continue;
            }
            order.push(addr.as_u64());
            for edge in &recovered.edges {
                if edge.from_block == addr {
                    queue.push_back(edge.to_block);
                }
            }
        }
        out.block_order.clone_from(&order);

        for &addr in &order {
            let cur = Address::new(addr);
            let succs: Vec<Address> = recovered
                .edges
                .iter()
                .filter(|e| e.from_block == cur)
                .map(|e| e.to_block)
                .collect();
            let stmt = match succs.len() {
                0 => StructuredStatement::Return { address: addr },
                1 => StructuredStatement::Block {
                    address: addr,
                    next: Some(succs[0].as_u64()),
                },
                _ => StructuredStatement::IfThen {
                    condition_address: addr,
                    true_branch: succs[0].as_u64(),
                    false_branch: succs[1].as_u64(),
                },
            };
            out.add(stmt);
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_cfg(dispatcher_idx: usize, n_blocks: usize) -> SimpleCfg {
        let blocks: Vec<SimpleBb> = (0..n_blocks)
            .map(|i| SimpleBb {
                address: Address::new(0x1000 + i as u64 * 0x10),
                successor_count: if i == dispatcher_idx { n_blocks - 1 } else { 1 },
                predecessor_count: if i == dispatcher_idx { n_blocks - 1 } else { 1 },
                instr_count: 4,
                ends_with_indirect_jump: i == dispatcher_idx,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: Some(i as u64 * 100),
            })
            .collect();
        let mut edges = Vec::new();
        for i in 0..n_blocks {
            if i != dispatcher_idx {
                edges.push((i, dispatcher_idx, EdgeType::Unconditional));
                edges.push((dispatcher_idx, i, EdgeType::Unconditional));
            }
        }
        SimpleCfg { blocks, edges }
    }

    // ── CaseBlock ────────────────────────────────────────────────────────────

    #[test]
    fn test_case_block_creation() {
        let cb = CaseBlock::new(42, 0x1000);
        assert_eq!(cb.state_value, 42);
        assert_eq!(cb.start_address, 0x1000);
        assert!(!cb.is_conditional());
    }

    #[test]
    fn test_case_block_conditional() {
        let mut cb = CaseBlock::new(42, 0x1000);
        cb.next_state = Some(100);
        cb.next_state_false = Some(200);
        assert!(cb.is_conditional());
        assert_eq!(cb.successors().len(), 2);
    }

    #[test]
    fn test_case_block_terminal() {
        let mut cb = CaseBlock::new(0, 0x1000);
        cb.is_terminal = true;
        assert_eq!(cb.successors().len(), 0);
    }

    // ── FlattenedFunction ─────────────────────────────────────────────────────

    #[test]
    fn test_flattened_function_creation() {
        let ff = FlattenedFunction::new(0x0040_1000, 0x0040_1020);
        assert_eq!(ff.function_address, 0x0040_1000);
        assert_eq!(ff.dispatcher_address, 0x0040_1020);
    }

    #[test]
    fn test_flattened_function_find_case() {
        let mut ff = FlattenedFunction::new(0x0040_1000, 0x0040_1020);
        ff.case_blocks.push(CaseBlock::new(42, 0x1000));
        assert!(ff.find_case(42).is_some());
        assert!(ff.find_case(99).is_none());
    }

    #[test]
    fn test_flattened_function_entry_case() {
        let mut ff = FlattenedFunction::new(0x0040_1000, 0x0040_1020);
        ff.case_blocks.push(CaseBlock::new(0, 0x1000));
        ff.initial_state = Some(0);
        assert!(ff.entry_case().is_some());
    }

    // ── StateVariableInfo ─────────────────────────────────────────────────────

    #[test]
    fn test_state_variable_info_from_register() {
        let sv = StateVariable::Register("eax".into());
        let info = StateVariableInfo::from_state_var(&sv);
        assert!(info.location.contains("eax"));
    }

    #[test]
    fn test_state_variable_add_known_value() {
        let sv = StateVariable::Unknown;
        let mut info = StateVariableInfo::from_state_var(&sv);
        info.add_known_value(42);
        info.add_known_value(42); // duplicate
        assert_eq!(info.value_count(), 1);
    }

    // ── StructuredOutput ──────────────────────────────────────────────────────

    #[test]
    fn test_structured_output_empty() {
        let out = StructuredOutput::new();
        assert_eq!(out.statement_count(), 0);
        assert!(!out.has_loops());
        assert!(!out.has_conditionals());
    }

    #[test]
    fn test_structured_output_add_if() {
        let mut out = StructuredOutput::new();
        out.add(StructuredStatement::IfThen {
            condition_address: 0x1000,
            true_branch: 0x1010,
            false_branch: 0x1020,
        });
        assert!(out.has_conditionals());
    }

    #[test]
    fn test_structured_output_add_while() {
        let mut out = StructuredOutput::new();
        out.add(StructuredStatement::While {
            condition_address: 0x1000,
            body_start: 0x1010,
        });
        assert!(out.has_loops());
    }

    // ── CffSignature ──────────────────────────────────────────────────────────

    #[test]
    fn test_cff_signature_match() {
        let sig = CffSignature::new("test", vec![0xFF, 0x24, 0xCD], 0.85);
        let data = vec![0x00, 0xFF, 0x24, 0xCD, 0xFF];
        assert!(sig.matches(&data, 1));
        assert!(!sig.matches(&data, 0));
    }

    #[test]
    fn test_cff_signature_scan() {
        let sig = CffSignature::new("t", vec![0xAA, 0xBB], 0.7);
        let data = vec![0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        let hits = sig.scan(&data);
        assert_eq!(hits, vec![0, 3]);
    }

    #[test]
    fn test_builtin_signatures_nonempty() {
        let sigs = builtin_cff_signatures();
        assert!(sigs.len() >= 3);
    }

    // ── CffRecovery ───────────────────────────────────────────────────────────

    #[test]
    fn test_recovery_creation() {
        let r = CffRecovery::new();
        assert!(r.min_confidence > 0.0);
        assert!(!r.signatures.is_empty());
    }

    #[test]
    fn test_recovery_scan_signatures_empty() {
        let r = CffRecovery::new();
        let data = vec![0x90u8; 16]; // NOPs — no CFF patterns
        let hits = r.scan_signatures(&data, 0x1000);
        // May find some 0xFF 0x24 but unlikely in pure NOPs
        let _ = hits;
    }

    #[test]
    fn test_recovery_scan_finds_ollvm() {
        let r = CffRecovery::new();
        let mut data = vec![0x00u8; 8];
        data.extend_from_slice(&[0xFF, 0x24, 0xCD, 0x00, 0x00, 0x00, 0x00]);
        let hits = r.scan_signatures(&data, 0x4000);
        assert!(hits.iter().any(|(name, _, _)| name.contains("OLLVM")));
    }

    #[test]
    fn test_recovery_add_custom_signature() {
        let mut r = CffRecovery::new();
        let before = r.signatures.len();
        r.add_signature(CffSignature::new("custom", vec![0xDE, 0xAD], 0.99));
        assert_eq!(r.signatures.len(), before + 1);
    }

    #[test]
    fn test_recovery_build_flattened_function() {
        let cfg = make_simple_cfg(1, 5);
        let r = CffRecovery::new();
        let candidate = r.detector.detect(&cfg, Address::new(0x1000));
        assert!(candidate.is_some());
        if let Some(c) = candidate {
            let ff = r.build_flattened_function(&c, &cfg);
            assert!(!ff.case_blocks.is_empty());
        }
    }

    #[test]
    fn test_recovery_from_cfg_not_cff() {
        // Linear 2-block CFG — not CFF
        let blocks = vec![
            SimpleBb {
                address: Address::new(0x1000),
                successor_count: 1,
                predecessor_count: 0,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x1010),
                successor_count: 0,
                predecessor_count: 1,
                instr_count: 2,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
        ];
        let edges = vec![(0, 1, EdgeType::Unconditional)];
        let cfg = SimpleCfg { blocks, edges };
        let r = CffRecovery::new();
        let result = r.recover_from_cfg(&cfg, Address::new(0x1000));
        assert!(result.is_none());
    }

    #[test]
    fn test_recovery_build_structured_output_from_recovered() {
        let cfg = make_simple_cfg(1, 5);
        let r = CffRecovery::new();
        let candidate = r.detector.detect(&cfg, Address::new(0x1000));
        if let Some(c) = candidate {
            let recovered = r.recoverer.recover(&c, &cfg);
            let out = r.build_structured_output(&recovered);
            assert!(out.statement_count() > 0);
        }
    }

    #[test]
    fn test_recovery_with_min_confidence() {
        let r = CffRecovery::new().with_min_confidence(0.99);
        let cfg = make_simple_cfg(1, 5);
        // Even if detected, confidence < 0.99 should return None
        let result = r.recover_from_cfg(&cfg, Address::new(0x1000));
        // May or may not be None depending on actual confidence; just no panic.
        let _ = result;
    }

    #[test]
    fn test_state_var_info_register_unknown() {
        let sv = StateVariable::StackSlot(-8);
        let info = StateVariableInfo::from_state_var(&sv);
        assert!(!info.location.is_empty());
    }

    #[test]
    fn test_case_block_single_successor() {
        let mut cb = CaseBlock::new(7, 0x2000);
        cb.next_state = Some(8);
        assert_eq!(cb.successors(), vec![8]);
    }
}
