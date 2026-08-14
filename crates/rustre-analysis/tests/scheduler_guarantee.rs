//! The scheduler's documented guarantee, checked instead of trusted.
//!
//! `ScheduleOrder` states: "The order is guaranteed to satisfy all registered
//! [`PassDependency`] constraints." That is a claim about every dependency in
//! every schedule, so it is checked here over generated graphs rather than on a
//! hand-picked example. An ordering guarantee is exactly the kind that breaks
//! quietly: the passes still all run, just in a wrong order, and whatever
//! consumed the earlier pass's output silently sees stale or missing data.

use rustre_analysis::analysis_scheduler::AnalysisScheduler;

/// Deterministic PRNG — reproducible failures, no external crates.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

/// Build a scheduler with `n` passes and a random ACYCLIC dependency set.
///
/// Acyclicity is guaranteed by construction: edges always point from a lower
/// index to a higher one, so a valid order always exists and any failure is the
/// scheduler's, not the fixture's.
fn random_acyclic(n: usize, edges: usize, seed: u64) -> (AnalysisScheduler, Vec<(String, String)>) {
    let mut rng = Lcg(seed);
    let mut sched = AnalysisScheduler::new();
    let names: Vec<String> = (0..n).map(|i| format!("pass{i}")).collect();
    for name in &names {
        sched.register_default(name.clone()).expect("fresh name");
    }

    let mut deps = Vec::new();
    for _ in 0..edges {
        let a = (rng.next() as usize) % n;
        let b = (rng.next() as usize) % n;
        let (lo, hi) = if a < b { (a, b) } else if b < a { (b, a) } else { continue };
        if sched.add_dependency(names[lo].clone(), names[hi].clone()).is_ok() {
            deps.push((names[lo].clone(), names[hi].clone()));
        }
    }
    (sched, deps)
}

/// Every registered dependency must hold in the produced order.
#[test]
fn the_order_satisfies_every_registered_dependency() {
    for (case, seed) in [0x1u64, 0xDEAD_BEEF, 0x5A5A_1234, 0xFEED_FACE].iter().enumerate() {
        for &(n, e) in &[(4usize, 3usize), (8, 10), (16, 30), (32, 80)] {
            let (sched, deps) = random_acyclic(n, e, *seed);
            let order = sched
                .schedule()
                .unwrap_or_else(|err| panic!("case {case}: acyclic graph failed to schedule: {err:?}"));

            for (before, after) in &deps {
                assert!(
                    order.is_before(before, after),
                    "case {case} (n={n}, e={e}): {before} must precede {after}, \
                     but the order is {:?}",
                    order.order
                );
            }
        }
    }
}

/// Every registered pass must appear exactly once — none dropped, none doubled.
#[test]
fn the_order_contains_each_pass_exactly_once() {
    let (sched, _) = random_acyclic(16, 24, 0x0BAD_C0DE);
    let order = sched.schedule().expect("acyclic");
    let mut seen = std::collections::HashSet::new();
    for name in &order.order {
        assert!(seen.insert(name.clone()), "{name} appears twice in the order");
    }
    assert_eq!(seen.len(), 16, "expected all 16 passes, got {}", seen.len());
    assert_eq!(order.pass_count, order.order.len(), "pass_count disagrees with the order");
}

/// A cycle has no valid order, so scheduling must fail rather than invent one.
#[test]
fn a_cyclic_graph_is_rejected() {
    let mut sched = AnalysisScheduler::new();
    for n in ["a", "b", "c"] {
        sched.register_default(n).expect("fresh");
    }
    sched.add_dependency("a", "b").expect("known");
    sched.add_dependency("b", "c").expect("known");
    sched.add_dependency("c", "a").expect("known");

    assert!(
        sched.schedule().is_err(),
        "a → b → c → a has no valid order, but a schedule was produced anyway"
    );
}

/// Guards the first test against passing vacuously with no dependencies.
#[test]
fn the_generator_actually_produces_dependencies() {
    let (_, deps) = random_acyclic(16, 30, 0xDEAD_BEEF);
    assert!(
        deps.len() >= 8,
        "only {} dependencies generated — the guarantee would hold trivially",
        deps.len()
    );
}
