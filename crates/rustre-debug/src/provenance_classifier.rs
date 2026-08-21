//! Cheat-aware watchpoints (original-IP track, addendum item 3 of
//! `rustre_debug_enhancement_plan.md`).
//!
//! Extends the Tier-1 [`crate::omniscient_query::OmniscientIndex::who_wrote`] query
//! with a provenance classifier: was a given write made by original binary code, or
//! by injected/foreign code (a DLL/.so not in the baseline module list, or bytes
//! inside a known module that no longer match their expected hash — an inline hook)?
//! Neither GDB nor WinDbg have a concept of "writer provenance" in their dataflow
//! model; this turns `who_wrote` into an anti-cheat/anti-tamper R&D primitive: rank
//! writers to a game-state address by whether they came from the shipped binary or
//! from something injected into the process.

use std::collections::BTreeMap;

use rustre_core::address::Address;

use crate::omniscient_query::MemoryWrite;

/// Where a write's instruction pointer falls, relative to a known-good module
/// baseline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Provenance {
    /// The PC falls inside a baselined module's address range and the code
    /// bytes at that location still match the expected hash — original,
    /// unmodified binary code.
    Original { module: String },
    /// The PC falls inside a baselined module's range, but the code bytes no
    /// longer match the expected hash — an inline hook/patch was applied to
    /// otherwise-legitimate code.
    TamperedModule { module: String },
    /// The PC falls inside a baselined module, but NO hash range covers it —
    /// or the caller could not supply the current hash — so tampering was
    /// never checked here.
    ///
    /// This used to be reported as [`Self::Original`], whose own documentation
    /// promises "the code bytes at that location still match the expected
    /// hash". In an anti-tamper tool that is the one claim that matters: an
    /// inline hook placed in a region nobody hashed came back as verified
    /// original, and `is_suspicious()` said `false`. Absence of verification
    /// presented as verification.
    Unverified { module: String },
    /// The PC does not fall inside any baselined module — injected code
    /// (a foreign DLL/.so, a manually-mapped region, JIT'd shellcode, …).
    Foreign,
    /// The write has no known writer PC to classify.
    Unknown,
}

impl Provenance {
    /// `true` for positive evidence of something wrong — a tampered range or
    /// code outside every baselined module.
    ///
    /// Deliberately `false` for [`Self::Unverified`]: not checking is not
    /// evidence of tampering. Use [`Self::is_verified_original`] when the
    /// question is "can I rule this out?", which is the opposite question and
    /// the one this type used to answer wrongly.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        matches!(self, Self::TamperedModule { .. } | Self::Foreign)
    }

    /// `true` only when the bytes at this PC were actually hashed and matched.
    ///
    /// Everything else — unverified, unknown, foreign, tampered — is not a
    /// clean bill of health, and this is the predicate that says so.
    #[must_use]
    pub const fn is_verified_original(&self) -> bool {
        matches!(self, Self::Original { .. })
    }

    /// Triage order for an analyst: 0 = act on it, 1 = look at it, 2 = proved
    /// clean.
    #[must_use]
    pub const fn triage_rank(&self) -> u8 {
        match self {
            Self::TamperedModule { .. } | Self::Foreign => 0,
            Self::Unverified { .. } | Self::Unknown => 1,
            Self::Original { .. } => 2,
        }
    }
}

/// One baselined module: an address range plus expected code hashes for
/// specific sub-ranges (e.g. per-function), so tampering can be localized
/// without hashing the whole module on every query.
#[derive(Debug, Clone)]
pub struct ModuleBaseline {
    pub name: String,
    pub start: u64,
    pub end: u64,
    /// Expected hash for byte ranges within this module, keyed by range start;
    /// value is `(range_len, expected_hash)`. Empty means "trust containment
    /// only" (no tamper detection within the module, just foreign-vs-not).
    expected_hashes: BTreeMap<u64, (u64, u64)>,
}

impl ModuleBaseline {
    #[must_use]
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        Self { name: name.into(), start, end, expected_hashes: BTreeMap::new() }
    }

    /// Record the expected hash (any stable hash the caller computes — this
    /// module doesn't prescribe the hash function) for a byte range within
    /// this module, enabling tamper detection for that range.
    pub fn set_expected_hash(&mut self, range_start: u64, range_len: u64, expected_hash: u64) {
        self.expected_hashes.insert(range_start, (range_len, expected_hash));
    }

    const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Find the hash-checked range containing `addr`, if any was registered.
    fn hash_range_for(&self, addr: u64) -> Option<(u64, u64, u64)> {
        self.expected_hashes
            .range(..=addr)
            .next_back()
            .filter(|&(&start, &(len, _))| addr >= start && addr - start < len)
            .map(|(&start, &(len, hash))| (start, len, hash))
    }
}

/// A set of baselined modules, used to classify write provenance.
#[derive(Debug, Clone, Default)]
pub struct CodeBaseline {
    modules: Vec<ModuleBaseline>,
}

impl CodeBaseline {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_module(&mut self, module: ModuleBaseline) {
        self.modules.push(module);
    }

    fn module_for(&self, addr: u64) -> Option<&ModuleBaseline> {
        self.modules.iter().find(|m| m.contains(addr))
    }

    /// Classify a PC's provenance. `current_hash_lookup` is called with
    /// `(range_start, range_len)` when a hash-checked range is registered for
    /// the containing module, and should return the *current* hash of those
    /// bytes (read live from the target) so it can be compared against the
    /// baseline's expected hash.
    ///
    /// `None` from the lookup means the current bytes could not be read, and
    /// the result is [`Provenance::Unverified`] — never a verdict. Likewise
    /// when no hash-checked range covers `pc`: containment alone proves the
    /// address is inside a known module, not that its code is unmodified.
    #[must_use]
    pub fn classify(
        &self,
        pc: Address,
        current_hash_lookup: impl FnOnce(u64, u64) -> Option<u64>,
    ) -> Provenance {
        let addr = pc.as_u64();
        let Some(module) = self.module_for(addr) else {
            return Provenance::Foreign;
        };
        let name = module.name.clone();
        let Some((start, len, expected)) = module.hash_range_for(addr) else {
            return Provenance::Unverified { module: name };
        };
        match current_hash_lookup(start, len) {
            Some(current) if current == expected => Provenance::Original { module: name },
            Some(_) => Provenance::TamperedModule { module: name },
            None => Provenance::Unverified { module: name },
        }
    }
}

/// One write annotated with its writer's provenance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceTaggedWrite {
    pub write: MemoryWrite,
    pub provenance: Provenance,
}

/// Plain-data description of a module baseline for scripting/JSON boundaries
/// where a closure (as [`CodeBaseline::classify`] takes) can't cross the
/// wire: the caller pre-computes each hash-checked range's *current* hash
/// (e.g. by hashing live-read bytes before making the call) and supplies it
/// directly instead of via a lookup function.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModuleBaselineSpec {
    pub name: String,
    pub start: u64,
    pub end: u64,
    /// `(range_start, range_len, expected_hash, current_hash)` tuples.
    pub hash_checks: Vec<(u64, u64, u64, u64)>,
}

/// Build a [`CodeBaseline`] from plain-data specs and classify one PC against
/// it — the closure-free entry point used at scripting/JSON boundaries (see
/// [`ModuleBaselineSpec`]).
#[must_use]
pub fn classify_from_specs(pc: Address, modules: &[ModuleBaselineSpec]) -> Provenance {
    let mut baseline = CodeBaseline::new();
    // Keyed by (range_start, range_len): two modules can register ranges at
    // the same start, and a start-only key let the last spec's current hash
    // silently answer for both.
    let mut current_by_range: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for spec in modules {
        let mut module = ModuleBaseline::new(spec.name.clone(), spec.start, spec.end);
        for &(range_start, range_len, expected, current) in &spec.hash_checks {
            module.set_expected_hash(range_start, range_len, expected);
            current_by_range.insert((range_start, range_len), current);
        }
        baseline.add_module(module);
    }
    // Keyed by (start, len), and NEVER defaulted. `unwrap_or(0)` used to
    // stand in for a missing current hash, which either matched an expected
    // hash of 0 (a fabricated clean verdict) or mismatched (a fabricated
    // TAMPER report) — a verdict manufactured from a measurement that was
    // never taken.
    baseline.classify(pc, |start, len| current_by_range.get(&(start, len)).copied())
}

/// Classify a batch of writes (e.g. the output of
/// [`crate::omniscient_query::OmniscientIndex::who_wrote`]) against a code
/// baseline, most-suspicious-first (foreign/tampered writes sorted before
/// original ones; ties keep input order).
#[must_use]
pub fn classify_writes<'a>(
    writes: impl IntoIterator<Item = &'a MemoryWrite>,
    baseline: &CodeBaseline,
    mut current_hash_lookup: impl FnMut(u64, u64) -> Option<u64>,
) -> Vec<ProvenanceTaggedWrite> {
    let mut tagged: Vec<ProvenanceTaggedWrite> = writes
        .into_iter()
        .map(|w| {
            let provenance = match w.writer_pc {
                Some(pc) => baseline.classify(pc, &mut current_hash_lookup),
                None => Provenance::Unknown,
            };
            ProvenanceTaggedWrite { write: w.clone(), provenance }
        })
        .collect();
    // Triage order, not a boolean: unverified writes sort after the ones with
    // positive evidence but BEFORE the ones proved clean, so they cannot hide
    // at the bottom of the list next to verified-original code.
    tagged.sort_by_key(|t| t.provenance.triage_rank());
    tagged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadId;

    fn write(pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: 0,
            address: Address(0x1000),
            size: 4,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: None,
        }
    }

    #[test]
    fn pc_outside_any_module_is_foreign() {
        let baseline = CodeBaseline::new();
        let result = baseline.classify(Address(0x9999), |_, _| Some(0));
        assert_eq!(result, Provenance::Foreign);
    }

    /// Containment is not verification.
    ///
    /// A PC inside a baselined module for which NO hash range was registered
    /// used to come back as `Original`, whose own documentation promises the
    /// bytes still match the expected hash. In an anti-tamper tool that is the
    /// one claim that matters: an inline hook in a region nobody hashed was
    /// reported as verified original, and `is_suspicious()` said false. The
    /// test itself encoded the defect - its name asserted it.
    #[test]
    fn pc_inside_module_with_no_hash_check_is_unverified_not_original() {
        let mut baseline = CodeBaseline::new();
        baseline.add_module(ModuleBaseline::new("game.exe", 0x1000, 0x2000));
        let result = baseline.classify(Address(0x1500), |_, _| Some(0));
        assert_eq!(result, Provenance::Unverified { module: "game.exe".into() });
        assert!(!result.is_verified_original(), "nothing was hashed, so nothing is proved clean");
        assert!(!result.is_suspicious(), "not checking is not evidence of tampering either");
    }

    /// A hash range that covers the PC but whose CURRENT hash the caller could
    /// not supply is also unverified - never a verdict.
    #[test]
    fn an_unreadable_current_hash_is_unverified_not_tampered() {
        let mut module = ModuleBaseline::new("game.exe", 0x1000, 0x2000);
        module.set_expected_hash(0x1500, 0x10, 0xABCD);
        let mut baseline = CodeBaseline::new();
        baseline.add_module(module);
        let result = baseline.classify(Address(0x1508), |_, _| None);
        assert_eq!(result, Provenance::Unverified { module: "game.exe".into() });
        assert!(!result.is_suspicious(), "a failed read is not a tamper report");
    }

    /// `classify_from_specs` must not manufacture a verdict from a missing
    /// current hash, and must not let one module answer for another.
    ///
    /// The lookup was keyed by range START only and defaulted to 0, so a
    /// second module registering a range at the same start silently supplied
    /// the first one's current hash - and a genuinely missing entry produced
    /// either a clean verdict (if the expected hash was 0) or a TAMPER report,
    /// both manufactured from a measurement never taken.
    #[test]
    fn specs_never_manufacture_a_verdict_from_a_missing_hash() {
        // Two modules, ranges registered at the same start, different lengths.
        let a = ModuleBaselineSpec {
            name: "a.dll".into(),
            start: 0x1000,
            end: 0x2000,
            hash_checks: vec![(0x1500, 0x10, 0xAAAA, 0xAAAA)],
        };
        let b = ModuleBaselineSpec {
            name: "b.dll".into(),
            start: 0x3000,
            end: 0x4000,
            hash_checks: vec![(0x1500, 0x20, 0xBBBB, 0xCCCC)],
        };
        // The PC is in a.dll, whose own range matches: proved clean.
        assert_eq!(
            classify_from_specs(Address(0x1508), &[a, b]),
            Provenance::Original { module: "a.dll".into() }
        );

        // A module with an expected hash but NO supplied current hash.
        let c = ModuleBaselineSpec {
            name: "c.dll".into(),
            start: 0x5000,
            end: 0x6000,
            hash_checks: vec![],
        };
        let mut baseline = CodeBaseline::new();
        let mut m = ModuleBaseline::new("c.dll", 0x5000, 0x6000);
        m.set_expected_hash(0x5500, 0x10, 0);
        baseline.add_module(m);
        let _ = c;
        // Expected hash of 0 plus a missing measurement used to read as a match.
        assert_eq!(
            baseline.classify(Address(0x5504), |_, _| None),
            Provenance::Unverified { module: "c.dll".into() }
        );
    }

    #[test]
    fn matching_hash_is_original() {
        let mut module = ModuleBaseline::new("game.exe", 0x1000, 0x2000);
        module.set_expected_hash(0x1500, 0x10, 0xABCD);
        let mut baseline = CodeBaseline::new();
        baseline.add_module(module);
        let result = baseline.classify(Address(0x1508), |_, _| Some(0xABCD));
        assert_eq!(result, Provenance::Original { module: "game.exe".into() });
    }

    #[test]
    fn mismatched_hash_is_tampered() {
        let mut module = ModuleBaseline::new("game.exe", 0x1000, 0x2000);
        module.set_expected_hash(0x1500, 0x10, 0xABCD);
        let mut baseline = CodeBaseline::new();
        baseline.add_module(module);
        let result = baseline.classify(Address(0x1508), |_, _| Some(0xFFFF));
        assert_eq!(result, Provenance::TamperedModule { module: "game.exe".into() });
    }

    #[test]
    fn classify_from_specs_detects_tampering() {
        let modules = vec![ModuleBaselineSpec {
            name: "game.exe".into(),
            start: 0x1000,
            end: 0x2000,
            hash_checks: vec![(0x1500, 0x10, 0xABCD, 0xFFFF)],
        }];
        let result = classify_from_specs(Address(0x1508), &modules);
        assert_eq!(result, Provenance::TamperedModule { module: "game.exe".into() });
    }

    #[test]
    fn classify_from_specs_detects_foreign() {
        let modules = vec![ModuleBaselineSpec { name: "game.exe".into(), start: 0x1000, end: 0x2000, hash_checks: vec![] }];
        let result = classify_from_specs(Address(0x9999), &modules);
        assert_eq!(result, Provenance::Foreign);
    }

    #[test]
    fn is_suspicious_flags_foreign_and_tampered_only() {
        assert!(Provenance::Foreign.is_suspicious());
        assert!(Provenance::TamperedModule { module: "x".into() }.is_suspicious());
        assert!(!Provenance::Original { module: "x".into() }.is_suspicious());
        assert!(!Provenance::Unknown.is_suspicious());
    }

    /// Triage order: positive evidence first, then what was never checked,
    /// then what was proved clean.
    ///
    /// The sort key was the boolean `is_suspicious()`, so an UNVERIFIED write
    /// sank to the bottom of the list next to verified-original code - the
    /// place an analyst stops reading.
    #[test]
    fn classify_writes_sorts_by_triage_rank() {
        let mut module = ModuleBaseline::new("game.exe", 0x1000, 0x2000);
        module.set_expected_hash(0x1600, 0x10, 0xABCD);
        let mut baseline = CodeBaseline::new();
        baseline.add_module(module);
        let unverified = write(0x1500); // inside the module, no hash range
        let proved_clean = write(0x1604); // inside a hashed range that matches
        let foreign = write(0x9999);
        let tagged = classify_writes(
            [&unverified, &proved_clean, &foreign],
            &baseline,
            |_, _| Some(0xABCD),
        );
        assert_eq!(tagged[0].provenance, Provenance::Foreign);
        assert_eq!(tagged[1].provenance, Provenance::Unverified { module: "game.exe".into() });
        assert_eq!(tagged[2].provenance, Provenance::Original { module: "game.exe".into() });
    }

    #[test]
    fn no_writer_pc_is_unknown() {
        let mut w = write(0x1500);
        w.writer_pc = None;
        let baseline = CodeBaseline::new();
        let tagged = classify_writes([&w], &baseline, |_, _| Some(0));
        assert_eq!(tagged[0].provenance, Provenance::Unknown);
    }
}
