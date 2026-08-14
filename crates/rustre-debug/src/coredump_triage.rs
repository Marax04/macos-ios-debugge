//! Coredump-farm triage mode (Tier 3, item 8 of `rustre_debug_enhancement_plan.md`).
//!
//! Batch-ingest multiple crash dumps (already symbolicated into [`StackFrame`]
//! backtraces via this crate's existing DWARF/PDB engine — this module does not
//! itself parse dump file formats), cluster them by stack-hash signature, and
//! rank clusters by frequency. Useful for triaging fuzzing-campaign crash farms:
//! thousands of crashes usually collapse into a handful of distinct root causes.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::StackFrame;

/// One ingested crash, already backtraced (e.g. via [`crate::Debugger::backtrace`]
/// against a loaded core/minidump, or replayed from a recording).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrashDump {
    /// Caller-assigned identifier (e.g. file path or fuzzer test-case ID).
    pub id: String,
    /// Backtrace at the point of the crash, innermost frame first.
    pub frames: Vec<StackFrame>,
    /// Signal number or exception code, if known.
    pub signal: Option<i32>,
}

/// A group of crashes that share the same stack signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrashCluster {
    /// Hash of the signature frames, stable across dumps with identical stacks.
    pub signature: u64,
    /// IDs of every crash dump assigned to this cluster, in ingestion order.
    pub member_ids: Vec<String>,
    /// Human-readable frame identifiers (function name, or `pc:0x...` if
    /// unresolved) used to compute the signature — for display, not hashing.
    pub signature_frames: Vec<String>,
}

impl CrashCluster {
    /// Number of crashes in this cluster.
    #[must_use]
    pub fn count(&self) -> usize {
        self.member_ids.len()
    }

    /// Whether every frame in the signature is identified in a way that
    /// survives ASLR (a function name, or `module+offset`).
    ///
    /// `false` means at least one frame is identified by its raw address, so
    /// two reports of the same crash from different runs will NOT land in this
    /// cluster. The count is then a floor, not a total — and reading it as a
    /// total is how a recurring crash gets dismissed as a one-off.
    #[must_use]
    pub fn signature_is_aslr_stable(&self) -> bool {
        !self.signature_frames.is_empty()
            && !self
                .signature_frames
                .iter()
                .any(|f| f.starts_with(UNSTABLE_FRAME_PREFIX))
    }
}

/// Marker prefix of a frame identity that is NOT stable across runs.
///
/// Everything else in a signature is module-relative and survives ASLR; an
/// identity starting with this does not, so a cluster containing one may be
/// under-grouped. See [`CrashCluster::signature_is_aslr_stable`].
pub const UNSTABLE_FRAME_PREFIX: &str = "pc:";

/// One frame's identity for hashing purposes.
///
/// Order matters, and the middle rung used to be missing:
/// 1. the resolved function name — stable across runs;
/// 2. **`module+offset`** — also stable, because the offset is relative to the
///    module's own base;
/// 3. the raw PC, which is not stable under ASLR at all.
///
/// Falling straight from (1) to (3) threw away an identity that was sitting in
/// the very same `StackFrame`. The consequence is not cosmetic: with
/// unsymbolicated dumps every run has different absolute addresses, so N
/// reports of ONE recurring crash became N clusters of one, and a crash farm
/// was told there is no recurring crash — the single claim the person triaging
/// it acts on.
fn frame_identity(frame: &StackFrame) -> String {
    if let Some(name) = &frame.function_name {
        return name.clone();
    }
    if let (Some(module), Some(offset)) = (&frame.module, frame.offset) {
        return format!("{module}+{offset:#x}");
    }
    format!("{UNSTABLE_FRAME_PREFIX}{:#x}", frame.pc.as_u64())
}

/// Compute a stable stack-hash signature from the innermost `depth` frames of
/// a backtrace. Using only the top frames (rather than the whole stack) groups
/// crashes that diverge deep in shared library/runtime code but share the same
/// immediate cause.
#[must_use]
pub fn stack_signature(frames: &[StackFrame], depth: usize) -> (u64, Vec<String>) {
    let sig_frames: Vec<String> = frames.iter().take(depth).map(frame_identity).collect();
    let mut hasher = DefaultHasher::new();
    sig_frames.hash(&mut hasher);
    (hasher.finish(), sig_frames)
}

/// Cluster a batch of crash dumps by stack-hash signature (top `depth` frames)
/// and rank clusters by frequency, most common first. Ties broken by
/// signature value for determinism.
#[must_use]
pub fn triage(dumps: &[CrashDump], depth: usize) -> Vec<CrashCluster> {
    let mut clusters: HashMap<u64, CrashCluster> = HashMap::new();
    for dump in dumps {
        let (mut signature, signature_frames) = stack_signature(&dump.frames, depth);
        // No signature frames means the backtrace could not be produced (a
        // failed unwind, or `depth == 0`). Every such dump would otherwise hash
        // to the empty vector and be reported as ONE recurring crash — the
        // single claim someone triaging a crash farm acts on. There is no
        // evidence these crashes are related, so each stands alone; the empty
        // `signature_frames` is what tells the caller the grouping is unknown
        // rather than genuine.
        if signature_frames.is_empty() {
            let mut hasher = DefaultHasher::new();
            dump.id.hash(&mut hasher);
            signature = hasher.finish();
        }
        clusters
            .entry(signature)
            .or_insert_with(|| CrashCluster { signature, member_ids: Vec::new(), signature_frames })
            .member_ids
            .push(dump.id.clone());
    }
    let mut ranked: Vec<CrashCluster> = clusters.into_values().collect();
    ranked.sort_by(|a, b| b.count().cmp(&a.count()).then(a.signature.cmp(&b.signature)));
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn frame(pc: u64, name: Option<&str>) -> StackFrame {
        StackFrame {
            index: 0,
            pc: Address(pc),
            sp: Address(0),
            fp: None,
            function_name: name.map(String::from),
            module: None,
            offset: None,
            source_file: None,
            source_line: None,
        }
    }

    fn dump(id: &str, frames: Vec<StackFrame>) -> CrashDump {
        CrashDump { id: id.into(), frames, signal: Some(11) }
    }

    #[test]
    fn identical_stacks_cluster_together() {
        let a = dump("a", vec![frame(0x1000, Some("parse")), frame(0x2000, Some("main"))]);
        let b = dump("b", vec![frame(0x1000, Some("parse")), frame(0x2000, Some("main"))]);
        let clusters = triage(&[a, b], 2);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].count(), 2);
        assert_eq!(clusters[0].member_ids, vec!["a", "b"]);
    }

    #[test]
    fn different_top_frames_split_into_separate_clusters() {
        let a = dump("a", vec![frame(0x1000, Some("parse"))]);
        let b = dump("b", vec![frame(0x9999, Some("render"))]);
        let clusters = triage(&[a, b], 1);
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn ranked_most_frequent_first() {
        let common = || dump("x", vec![frame(0x1000, Some("hot_bug"))]);
        let rare = dump("y", vec![frame(0x2000, Some("rare_bug"))]);
        let dumps = vec![common(), common(), common(), rare];
        let clusters = triage(&dumps, 1);
        assert_eq!(clusters[0].signature_frames, vec!["hot_bug".to_string()]);
        assert_eq!(clusters[0].count(), 3);
        assert_eq!(clusters[1].count(), 1);
    }

    #[test]
    fn depth_limits_signature_to_top_frames() {
        // Same top frame, different deeper frames — should still cluster together
        // when depth == 1.
        let a = dump("a", vec![frame(0x1000, Some("crash_fn")), frame(0xAAAA, Some("caller_a"))]);
        let b = dump("b", vec![frame(0x1000, Some("crash_fn")), frame(0xBBBB, Some("caller_b"))]);
        let clusters = triage(&[a, b], 1);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].count(), 2);
    }

    #[test]
    fn unresolved_frames_hash_by_pc() {
        let a = dump("a", vec![frame(0x1234, None)]);
        let b = dump("b", vec![frame(0x1234, None)]);
        let c = dump("c", vec![frame(0x5678, None)]);
        let clusters = triage(&[a, b, c], 1);
        assert_eq!(clusters.len(), 2);
        assert!(clusters[0].signature_frames[0].starts_with("pc:0x"));
    }

    /// Crashes whose backtrace could not be produced must not be reported as
    /// one recurring bug.
    ///
    /// An empty frame list hashes to the signature of the empty vector, so every
    /// dump whose unwinding failed landed in a single cluster — and `triage`
    /// then presents it as "this same crash happened N times", the one claim a
    /// person doing triage acts on. Failed unwinds are not rare (that is the
    /// whole reason this crate has two unwinders), and nothing in the output
    /// distinguished the grouping from a genuine one.
    #[test]
    fn dumps_without_a_backtrace_are_not_grouped_as_one_recurring_crash() {
        let clusters = triage(&[dump("crash-a", vec![]), dump("crash-b", vec![])], 4);
        assert_eq!(
            clusters.len(),
            2,
            "two unrelated crashes with no usable backtrace were merged into one cluster: {clusters:?}"
        );
        for c in &clusters {
            assert_eq!(c.count(), 1);
            assert!(
                c.signature_frames.is_empty(),
                "an ungroupable cluster must stay visibly empty, so the caller can tell \
                 it apart from a real signature"
            );
        }

        // A dump with frames must still cluster normally alongside them.
        let with_frames = vec![
            dump("crash-a", vec![]),
            dump("crash-b", vec![frame(0x1000, Some("boom"))]),
            dump("crash-c", vec![frame(0x2000, Some("boom"))]),
        ];
        let clusters = triage(&with_frames, 4);
        assert_eq!(clusters.len(), 2, "the two `boom` crashes group, the empty one stands alone");
        assert_eq!(clusters[0].count(), 2);
    }

    #[test]
    fn empty_batch_yields_no_clusters() {
        assert!(triage(&[], 4).is_empty());
    }

    fn frame_in_module(pc: u64, module: &str, offset: u64) -> StackFrame {
        StackFrame {
            index: 0,
            pc: Address(pc),
            sp: Address(0),
            fp: None,
            function_name: None,
            module: Some(module.to_string()),
            offset: Some(offset),
            source_file: None,
            source_line: None,
        }
    }

    /// Two runs of the SAME unsymbolicated crash must land in one cluster.
    ///
    /// The identity fell straight from "function name" to "raw PC", skipping
    /// the module+offset that was sitting in the same StackFrame. Under ASLR
    /// every run has different absolute addresses, so N reports of one
    /// recurring crash became N clusters of one, and the crash farm was told
    /// there is no recurring crash - the single claim the person triaging it
    /// acts on.
    #[test]
    fn the_same_crash_from_two_runs_clusters_together_despite_aslr() {
        // Same module, same offsets; different load bases.
        let run_a = dump("run-a", vec![
            frame_in_module(0x7f00_0000_1000, "libfoo.so", 0x1000),
            frame_in_module(0x7f00_0000_2000, "libfoo.so", 0x2000),
        ]);
        let run_b = dump("run-b", vec![
            frame_in_module(0x5500_0000_1000, "libfoo.so", 0x1000),
            frame_in_module(0x5500_0000_2000, "libfoo.so", 0x2000),
        ]);
        let clusters = triage(&[run_a, run_b], 2);
        assert_eq!(
            clusters.len(),
            1,
            "the same crash reported twice is one recurring crash, not two one-offs"
        );
        assert_eq!(clusters[0].count(), 2);
        assert!(clusters[0].signature_is_aslr_stable());
    }

    /// A crash whose frames carry neither a name nor a module is identified by
    /// raw address, and the cluster must SAY that its count is a floor.
    #[test]
    fn a_cluster_built_on_raw_addresses_declares_itself_unstable() {
        let bare = dump("bare", vec![frame(0x4141, None), frame(0x4242, None)]);
        let clusters = triage(&[bare], 2);
        assert_eq!(clusters.len(), 1);
        assert!(
            !clusters[0].signature_is_aslr_stable(),
            "a signature made of raw addresses cannot match another run, and must not pass for one that can"
        );

        // A named signature is stable, so the flag is not a constant.
        let named = dump("named", vec![frame(0x1, Some("main")), frame(0x2, Some("run"))]);
        let clusters = triage(&[named], 2);
        assert!(clusters[0].signature_is_aslr_stable());
    }

}
