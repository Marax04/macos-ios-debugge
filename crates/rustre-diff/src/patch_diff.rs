// patch_diff.rs — Patch analysis: diff two binary versions

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::bindiff_engine::{DiffResult, FunctionInfo, FunctionMatch, InstructionInfo};

// ── Patch types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAnalysis {
    pub version_a: BinaryVersion,
    pub version_b: BinaryVersion,
    pub changed_functions: Vec<FunctionPatch>,
    pub added_functions: Vec<AddedFunction>,
    pub removed_functions: Vec<RemovedFunction>,
    pub patch_stats: PatchStats,
    pub security_relevant: Vec<SecurityRelevantChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryVersion {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub timestamp: u64,
    pub version_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPatch {
    pub address_a: u64,
    pub address_b: u64,
    pub name: String,
    pub similarity: f64,
    pub instruction_diff: InstructionDiff,
    pub block_changes: Vec<BlockChange>,
    pub change_type: ChangeType,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    BugFix,
    SecurityPatch,
    Optimization,
    Refactoring,
    NewFeature,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityImpact {
    High,
    Medium,
    Low,
    None,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionDiff {
    pub added_count: usize,
    pub removed_count: usize,
    pub changed_count: usize,
    pub total_a: usize,
    pub total_b: usize,
    pub diff_ratio: f64,
    pub added_calls: Vec<u64>,
    pub removed_calls: Vec<u64>,
    pub hunks: Vec<DiffHunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub a_start: usize,
    pub a_len: usize,
    pub b_start: usize,
    pub b_len: usize,
    pub kind: HunkKind,
    pub a_instructions: Vec<InstructionSnippet>,
    pub b_instructions: Vec<InstructionSnippet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HunkKind {
    Replace,
    Insert,
    Delete,
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionSnippet {
    pub address: u64,
    pub bytes_hex: String,
    pub disasm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChange {
    pub block_type: BlockChangeType,
    pub address: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockChangeType {
    Added,
    Removed,
    Modified,
    Reordered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedFunction {
    pub address: u64,
    pub name: String,
    pub block_count: usize,
    pub instruction_count: usize,
    pub calls_to: Vec<u64>,
    pub potentially_security_relevant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovedFunction {
    pub address: u64,
    pub name: String,
    pub potentially_security_relevant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStats {
    pub total_changed: usize,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_identical: usize,
    pub pct_changed: f64,
    pub avg_function_similarity: f64,
    pub largest_change_function: Option<String>,
    pub most_changed_subsystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRelevantChange {
    pub function_name: String,
    pub address_a: u64,
    pub address_b: u64,
    pub reason: SecurityReason,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityReason {
    BoundsCheckAdded,
    BoundsCheckRemoved,
    IntegerOverflowCheck,
    NullCheckAdded,
    AuthenticationLogicChanged,
    CryptoFunctionChanged,
    MemoryAllocationChanged,
    ErrorHandlingChanged,
    PrivilegeEscalationPath,
    NetworkHandlerChanged,
    InputValidationChanged,
}

// ── Patch analyzer ─────────────────────────────────────────────────────────────

pub struct PatchAnalyzer {
    primary_funcs: HashMap<u64, FunctionInfo>,
    secondary_funcs: HashMap<u64, FunctionInfo>,
    security_sensitive_names: HashSet<String>,
}

impl PatchAnalyzer {
    #[must_use] 
    pub fn new(
        primary: Vec<FunctionInfo>,
        secondary: Vec<FunctionInfo>,
    ) -> Self {
        let security_sensitive_names: HashSet<String> = [
            "malloc", "free", "realloc", "calloc",
            "memcpy", "memmove", "memset", "strcpy", "strncpy", "sprintf", "snprintf",
            "recv", "send", "accept", "connect",
            "strcmp", "strncmp", "memcmp",
            "CreateFile", "WriteFile", "ReadFile",
            "RegOpenKey", "RegSetValue",
            "LoadLibrary", "GetProcAddress",
            "VirtualAlloc", "VirtualProtect",
            "IsAdmin", "CheckPrivilege", "authenticate", "verify_signature",
            "decrypt", "encrypt", "hash_password",
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

        Self {
            primary_funcs: primary.into_iter().map(|f| (f.address, f)).collect(),
            secondary_funcs: secondary.into_iter().map(|f| (f.address, f)).collect(),
            security_sensitive_names,
        }
    }

    #[must_use] 
    pub fn analyze(&self, diff: &DiffResult, version_a: BinaryVersion, version_b: BinaryVersion) -> PatchAnalysis {
        let changed_functions: Vec<FunctionPatch> = diff
            .matches
            .iter()
            .filter(|m| m.similarity < 0.99)
            .filter_map(|m| self.analyze_function_patch(m))
            .collect();

        let added_functions: Vec<AddedFunction> = diff
            .unmatched_secondary
            .iter()
            .filter_map(|&addr| self.secondary_funcs.get(&addr))
            .map(|f| AddedFunction {
                address: f.address,
                name: f.name.clone(),
                block_count: f.block_count(),
                instruction_count: f.instruction_count(),
                calls_to: f.callee_addresses.clone(),
                potentially_security_relevant: self.is_security_sensitive(&f.name),
            })
            .collect();

        let removed_functions: Vec<RemovedFunction> = diff
            .unmatched_primary
            .iter()
            .filter_map(|&addr| self.primary_funcs.get(&addr))
            .map(|f| RemovedFunction {
                address: f.address,
                name: f.name.clone(),
                potentially_security_relevant: self.is_security_sensitive(&f.name),
            })
            .collect();

        let security_relevant = Self::find_security_changes(&changed_functions, &added_functions, &removed_functions);

        let patch_stats = self.compute_stats(&changed_functions, &added_functions, &removed_functions, diff);

        PatchAnalysis {
            version_a,
            version_b,
            changed_functions,
            added_functions,
            removed_functions,
            patch_stats,
            security_relevant,
        }
    }

    fn analyze_function_patch(&self, fm: &FunctionMatch) -> Option<FunctionPatch> {
        let pf = self.primary_funcs.get(&fm.primary_address)?;
        let sf = self.secondary_funcs.get(&fm.secondary_address)?;

        let instruction_diff = Self::diff_instructions(pf, sf);
        let block_changes = Self::diff_blocks(pf, sf, fm);
        let change_type = self.classify_change(pf, sf, &instruction_diff);
        let security_impact = self.assess_security_impact(pf, sf, &instruction_diff);

        Some(FunctionPatch {
            address_a: fm.primary_address,
            address_b: fm.secondary_address,
            name: fm.primary_name.clone(),
            similarity: fm.similarity,
            instruction_diff,
            block_changes,
            change_type,
            security_impact,
        })
    }

    fn diff_instructions(pf: &FunctionInfo, sf: &FunctionInfo) -> InstructionDiff {
        let a_insns: Vec<&InstructionInfo> = pf
            .basic_blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        let b_insns: Vec<&InstructionInfo> = sf
            .basic_blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .collect();

        // Myers diff on opcode hashes
        let a_hashes: Vec<u32> = a_insns.iter().map(|i| i.opcode_hash).collect();
        let b_hashes: Vec<u32> = b_insns.iter().map(|i| i.opcode_hash).collect();

        let edit_script = myers_diff(&a_hashes, &b_hashes);

        let mut added = 0;
        let mut removed = 0;
        let mut hunks: Vec<DiffHunk> = Vec::new();
        let mut current_hunk: Option<DiffHunk> = None;

        for op in &edit_script {
            match op {
                DiffOp::Equal(_ai, _bi) => {
                    if let Some(h) = current_hunk.take() {
                        hunks.push(h);
                    }
                }
                DiffOp::Insert(bi) => {
                    added += 1;
                    let h = current_hunk.get_or_insert(DiffHunk {
                        a_start: 0,
                        a_len: 0,
                        b_start: *bi,
                        b_len: 0,
                        kind: HunkKind::Insert,
                        a_instructions: vec![],
                        b_instructions: vec![],
                    });
                    h.b_len += 1;
                    if *bi < b_insns.len() {
                        h.b_instructions.push(InstructionSnippet {
                            address: b_insns[*bi].address,
                            bytes_hex: hex::encode(&b_insns[*bi].bytes),
                            disasm: b_insns[*bi].mnemonic.clone(),
                        });
                    }
                }
                DiffOp::Delete(ai) => {
                    removed += 1;
                    let h = current_hunk.get_or_insert(DiffHunk {
                        a_start: *ai,
                        a_len: 0,
                        b_start: 0,
                        b_len: 0,
                        kind: HunkKind::Delete,
                        a_instructions: vec![],
                        b_instructions: vec![],
                    });
                    h.a_len += 1;
                    if *ai < a_insns.len() {
                        h.a_instructions.push(InstructionSnippet {
                            address: a_insns[*ai].address,
                            bytes_hex: hex::encode(&a_insns[*ai].bytes),
                            disasm: a_insns[*ai].mnemonic.clone(),
                        });
                    }
                }
            }
        }
        if let Some(h) = current_hunk {
            hunks.push(h);
        }

        let a_calls: HashSet<u64> = a_insns.iter().filter_map(|i| i.call_target).collect();
        let b_calls: HashSet<u64> = b_insns.iter().filter_map(|i| i.call_target).collect();

        let total = f64::from(u32::try_from(a_insns.len() + b_insns.len()).unwrap_or(u32::MAX));
        let diff_ratio = if total > 0.0 {
            f64::from(u32::try_from(added + removed).unwrap_or(u32::MAX)) / total
        } else {
            0.0
        };

        InstructionDiff {
            added_count: added,
            removed_count: removed,
            changed_count: removed.min(added),
            total_a: a_insns.len(),
            total_b: b_insns.len(),
            diff_ratio,
            added_calls: b_calls.difference(&a_calls).copied().collect(),
            removed_calls: a_calls.difference(&b_calls).copied().collect(),
            hunks,
        }
    }

    fn diff_blocks(pf: &FunctionInfo, sf: &FunctionInfo, fm: &FunctionMatch) -> Vec<BlockChange> {
        let mut changes = Vec::new();

        let matched_a: HashSet<u64> = fm.block_matches.iter().map(|b| b.primary_block).collect();
        let matched_b: HashSet<u64> = fm.block_matches.iter().map(|b| b.secondary_block).collect();

        for block in &pf.basic_blocks {
            if !matched_a.contains(&block.start_address) {
                changes.push(BlockChange {
                    block_type: BlockChangeType::Removed,
                    address: block.start_address,
                    detail: format!("{} instructions removed", block.instruction_count()),
                });
            }
        }
        for block in &sf.basic_blocks {
            if !matched_b.contains(&block.start_address) {
                changes.push(BlockChange {
                    block_type: BlockChangeType::Added,
                    address: block.start_address,
                    detail: format!("{} new instructions", block.instruction_count()),
                });
            }
        }
        for bm in &fm.block_matches {
            if bm.similarity < 0.99 {
                changes.push(BlockChange {
                    block_type: BlockChangeType::Modified,
                    address: bm.primary_block,
                    detail: format!("similarity {:.0}%", bm.similarity * 100.0),
                });
            }
        }

        changes
    }

    fn classify_change(&self, pf: &FunctionInfo, sf: &FunctionInfo, diff: &InstructionDiff) -> ChangeType {
        // Heuristics for change classification
        let shrunk = sf.instruction_count() < pf.instruction_count();
        let grew = sf.instruction_count() > pf.instruction_count();
        let added_check_patterns = !diff.added_calls.is_empty() && diff.removed_calls.is_empty();

        if self.is_security_sensitive(&pf.name) {
            return ChangeType::SecurityPatch;
        }
        if shrunk && diff.diff_ratio < 0.2 {
            return ChangeType::Optimization;
        }
        if grew && added_check_patterns {
            return ChangeType::BugFix;
        }
        if diff.diff_ratio > 0.5 {
            return ChangeType::Refactoring;
        }
        ChangeType::Unknown
    }

    fn assess_security_impact(&self, pf: &FunctionInfo, _sf: &FunctionInfo, diff: &InstructionDiff) -> SecurityImpact {
        if self.is_security_sensitive(&pf.name) {
            return SecurityImpact::High;
        }
        if !diff.added_calls.is_empty() || !diff.removed_calls.is_empty() {
            return SecurityImpact::Medium;
        }
        if diff.diff_ratio > 0.3 {
            return SecurityImpact::Low;
        }
        SecurityImpact::None
    }

    fn is_security_sensitive(&self, name: &str) -> bool {
        self.security_sensitive_names.contains(name)
            || name.contains("auth")
            || name.contains("crypt")
            || name.contains("hash")
            || name.contains("password")
            || name.contains("privilege")
            || name.contains("token")
            || name.contains("verify")
            || name.contains("check")
    }

    fn find_security_changes(
        changed: &[FunctionPatch],
        added: &[AddedFunction],
        _removed: &[RemovedFunction],
    ) -> Vec<SecurityRelevantChange> {
        let mut result = Vec::new();

        for patch in changed {
            if matches!(patch.security_impact, SecurityImpact::High | SecurityImpact::Medium) {
                let reason = if patch.instruction_diff.added_count > patch.instruction_diff.removed_count {
                    SecurityReason::BoundsCheckAdded
                } else if !patch.instruction_diff.added_calls.is_empty() {
                    SecurityReason::InputValidationChanged
                } else {
                    SecurityReason::MemoryAllocationChanged
                };

                result.push(SecurityRelevantChange {
                    function_name: patch.name.clone(),
                    address_a: patch.address_a,
                    address_b: patch.address_b,
                    reason,
                    confidence: if matches!(patch.security_impact, SecurityImpact::High) { 0.9 } else { 0.6 },
                    description: format!(
                        "Function '{}' changed with similarity {:.0}%, +{} -{} instructions",
                        patch.name,
                        patch.similarity * 100.0,
                        patch.instruction_diff.added_count,
                        patch.instruction_diff.removed_count,
                    ),
                });
            }
        }

        for added_fn in added {
            if added_fn.potentially_security_relevant {
                result.push(SecurityRelevantChange {
                    function_name: added_fn.name.clone(),
                    address_a: 0,
                    address_b: added_fn.address,
                    reason: SecurityReason::AuthenticationLogicChanged,
                    confidence: 0.5,
                    description: format!("New security-sensitive function '{}' added", added_fn.name),
                });
            }
        }

        result
    }

    fn compute_stats(
        &self,
        changed: &[FunctionPatch],
        added: &[AddedFunction],
        removed: &[RemovedFunction],
        diff: &DiffResult,
    ) -> PatchStats {
        let total = f64::from(u32::try_from(self.primary_funcs.len().max(1)).unwrap_or(u32::MAX));
        let pct_changed = f64::from(u32::try_from(changed.len() + added.len() + removed.len()).unwrap_or(u32::MAX))
            / total * 100.0;

        let avg_sim = if changed.is_empty() {
            1.0
        } else {
            changed.iter().map(|c| c.similarity).sum::<f64>()
                / f64::from(u32::try_from(changed.len()).unwrap_or(u32::MAX))
        };

        let largest_change = changed
            .iter()
            .min_by(|a, b| a.similarity.partial_cmp(&b.similarity).unwrap())
            .map(|c| c.name.clone());

        PatchStats {
            total_changed: changed.len(),
            total_added: added.len(),
            total_removed: removed.len(),
            total_identical: diff.identical_count(),
            pct_changed,
            avg_function_similarity: avg_sim,
            largest_change_function: largest_change,
            most_changed_subsystem: None,
        }
    }
}

// ── Myers diff ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum DiffOp {
    Equal(usize, usize),
    Insert(usize),
    Delete(usize),
}

fn myers_diff(a: &[u32], b: &[u32]) -> Vec<DiffOp> {
    let old_len = a.len();
    let new_len = b.len();
    let max_edit = old_len + new_len;

    if max_edit == 0 {
        return vec![];
    }

    let frontier_size = 2 * max_edit + 1;
    let mut frontier = vec![0usize; frontier_size];
    // edit_trace[depth] = frontier snapshot AFTER step depth.
    let mut edit_trace: Vec<Vec<usize>> = Vec::new();
    let mut found_depth = max_edit;

    'outer: for depth in 0..=max_edit {
        let diag_start = depth.cast_signed().wrapping_neg();
        let diag_end   = depth.cast_signed();
        let mut diag   = diag_start;
        while diag <= diag_end {
            let fidx = (diag + max_edit.cast_signed()).cast_unsigned();
            let from_above = diag == diag_start
                || (diag != diag_end
                    && frontier[(fidx + 1) % frontier_size]
                        > frontier[(fidx.wrapping_sub(1)) % frontier_size]);
            let mut cur_x = if from_above {
                frontier[(fidx + 1) % frontier_size]
            } else {
                frontier[(fidx.wrapping_sub(1)) % frontier_size] + 1
            };
            let mut cur_y = (cur_x.cast_signed() - diag).cast_unsigned();
            while cur_x < old_len && cur_y < new_len && { let ax = a[cur_x]; ax == b[cur_y] } {
                cur_x += 1;
                cur_y += 1;
            }
            frontier[fidx] = cur_x;
            if cur_x >= old_len && cur_y >= new_len {
                found_depth = depth;
                edit_trace.push(frontier.clone());
                break 'outer;
            }
            diag += 2;
        }
        edit_trace.push(frontier.clone());
    }

    // Backtrack through edit_trace to produce indexed diff ops.
    let mut ops = Vec::new();
    let mut cur_x = old_len;
    let mut cur_y = new_len;

    for step in (1..=found_depth).rev() {
        let prev_frontier = &edit_trace[step - 1];
        let diag   = cur_x.cast_signed() - cur_y.cast_signed();
        let step_i = step.cast_signed();
        let minus_idx = usize::try_from(diag - 1 + max_edit.cast_signed()).unwrap_or(0);
        let plus_idx  = usize::try_from(diag + 1 + max_edit.cast_signed()).unwrap_or(0);
        let prev_diag = if diag == -step_i
            || (diag != step_i && prev_frontier[minus_idx] < prev_frontier[plus_idx])
        {
            diag + 1 // came from above (insert)
        } else {
            diag - 1 // came from left (delete)
        };
        let prev_x = prev_frontier[usize::try_from(prev_diag + max_edit.cast_signed()).unwrap_or(0)];
        let prev_y = usize::try_from(prev_x.cast_signed() - prev_diag).unwrap_or(0);

        let snake_base_x = if prev_diag == diag - 1 { prev_x + 1 } else { prev_x };
        let snake_base_y = if prev_diag == diag + 1 { prev_y + 1 } else { prev_y };
        while cur_x > snake_base_x && cur_y > snake_base_y {
            cur_x -= 1;
            cur_y -= 1;
            ops.push(DiffOp::Equal(cur_x, cur_y));
        }

        if prev_diag == diag - 1 {
            if cur_x > 0 {
                cur_x -= 1;
                ops.push(DiffOp::Delete(cur_x));
            }
        } else if cur_y > 0 {
            cur_y -= 1;
            ops.push(DiffOp::Insert(cur_y));
        }
        cur_x = prev_x;
        cur_y = prev_y;
    }

    // Remaining equal prefix
    while cur_x > 0 && cur_y > 0 {
        cur_x -= 1;
        cur_y -= 1;
        ops.push(DiffOp::Equal(cur_x, cur_y));
    }

    ops.reverse();
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_myers_diff_identical() {
        let a = vec![1u32, 2, 3];
        let b = vec![1u32, 2, 3];
        let ops = myers_diff(&a, &b);
        assert!(ops.iter().all(|o| matches!(o, DiffOp::Equal(_, _))));
    }

    #[test]
    fn test_myers_diff_insert() {
        let a = vec![1u32, 3];
        let b = vec![1u32, 2, 3];
        let ops = myers_diff(&a, &b);
        assert!(ops.iter().any(|o| matches!(o, DiffOp::Insert(_))));
    }
}
