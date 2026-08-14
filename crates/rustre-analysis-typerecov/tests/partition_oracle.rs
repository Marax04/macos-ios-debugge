//! Independent oracle for `TypeUnifier::solve`'s equivalence partition.
//!
//! Definitional property: `solve` must produce the FINEST partition of type
//! variables consistent with the `Equal` constraints — i.e. exactly the
//! reflexive-transitive closure of the `Equal` relation, and nothing coarser.
//!
//! The oracle below computes that closure by BFS over an adjacency list built
//! straight from the constraint list. It never consults the union-find
//! implementation, and observes the partition only through the PUBLIC surface:
//!   * `class_count` — must equal the number of closure classes.
//!   * co-typing — attaching a distinguishing concrete type to one member of a
//!     class must be visible on every other member of that class and on no
//!     member of any other class.
//! (A mirror of union-find would agree with a union-find bug; a BFS over the
//! raw relation cannot.)

use rustre_analysis_typerecov::type_constraint_generator::{ConstraintKind, Provenance};
use rustre_analysis_typerecov::type_unifier::TypeUnifier;
use rustre_analysis_typerecov::{RecoveredType, TypeConstraint, TypeVar};

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

fn tv(n: u32) -> TypeVar {
    TypeVar::new(n)
}

fn eq(id: u32, a: u32, b: u32) -> TypeConstraint {
    TypeConstraint::certain(
        id,
        ConstraintKind::Equal { lhs: tv(a), rhs: tv(b) },
        Provenance::new(0, ""),
    )
}

fn has_int(id: u32, var: u32, width: u8) -> TypeConstraint {
    TypeConstraint::certain(
        id,
        ConstraintKind::HasType { var: tv(var), ty: RecoveredType::Int { width, signed: true } },
        Provenance::new(0, ""),
    )
}

/// ORACLE: reflexive-transitive closure of the `Equal` relation, as a
/// canonical label per variable (smallest member of its class).
fn closure_labels(nvars: u32, cs: &[TypeConstraint]) -> Vec<u32> {
    let n = nvars as usize;
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    for c in cs {
        if let ConstraintKind::Equal { lhs, rhs } = &c.kind {
            let (a, b) = (lhs.0, rhs.0);
            if (a as usize) < n && (b as usize) < n {
                adj[a as usize].push(b);
                adj[b as usize].push(a);
            }
        }
    }
    let mut label = vec![u32::MAX; n];
    for start in 0..n as u32 {
        if label[start as usize] != u32::MAX {
            continue;
        }
        let mut queue = vec![start];
        label[start as usize] = start;
        while let Some(v) = queue.pop() {
            for &w in &adj[v as usize] {
                if label[w as usize] == u32::MAX {
                    label[w as usize] = start;
                    queue.push(w);
                }
            }
        }
    }
    // Canonicalize to the smallest member of each class.
    let mut min_of = std::collections::BTreeMap::<u32, u32>::new();
    for (v, &l) in label.iter().enumerate() {
        let e = min_of.entry(l).or_insert(v as u32);
        *e = (*e).min(v as u32);
    }
    label.iter().map(|l| min_of[l]).collect()
}

/// Random `Equal`-only constraint sets, biased to hit the shapes that break
/// naive partitioning: self-loops, duplicate edges, long chains, stars,
/// disconnected components and singletons.
fn random_equalities(s: &mut u64, nvars: u32, n: usize) -> Vec<TypeConstraint> {
    let mut cs = Vec::new();
    for i in 0..n {
        let (a, b) = match xs(s) % 5 {
            // self-edge
            0 => {
                let v = (xs(s) % u64::from(nvars)) as u32;
                (v, v)
            }
            // chain edge (i, i+1)
            1 => {
                let v = (xs(s) % u64::from(nvars - 1)) as u32;
                (v, v + 1)
            }
            // star around var 0
            2 => (0, (xs(s) % u64::from(nvars)) as u32),
            // far-apart edge
            _ => (
                (xs(s) % u64::from(nvars)) as u32,
                (xs(s) % u64::from(nvars)) as u32,
            ),
        };
        cs.push(eq(u32::try_from(i).unwrap(), a, b));
    }
    cs
}

#[test]
fn oracle_solve_partition_is_transitive_closure_of_equal() {
    let mut s = 0x51ee_d00d_1234_9999u64;
    // Coverage counters — the test fails if a category dries up.
    let (mut saw_singleton, mut saw_all_one, mut saw_multi, mut saw_selfloop) = (0, 0, 0, 0);

    for iter in 0..1500 {
        let nvars = 2 + (xs(&mut s) % 7) as u32;
        let nedges = (xs(&mut s) % 9) as usize;
        let cs = random_equalities(&mut s, nvars, nedges);
        if cs.iter().any(|c| matches!(&c.kind, ConstraintKind::Equal{lhs,rhs} if lhs==rhs)) {
            saw_selfloop += 1;
        }

        let expect = closure_labels(nvars, &cs);
        let nclasses = {
            let mut v = expect.clone();
            v.sort_unstable();
            v.dedup();
            v.len()
        };
        if expect.iter().filter(|&&l| expect.iter().filter(|&&m| m == l).count() == 1).count() > 0 {
            saw_singleton += 1;
        }
        if nclasses == 1 && nvars > 1 {
            saw_all_one += 1;
        }
        if nclasses > 1 && nclasses < nvars as usize {
            saw_multi += 1;
        }

        // (a) class_count must equal the closure's class count.
        let res = TypeUnifier::new(nvars).solve(&cs).expect("Equal-only sets never conflict");
        assert_eq!(
            res.class_count, nclasses,
            "iter {iter}: class_count {} != closure classes {nclasses}; edges {:?}",
            res.class_count,
            cs.iter()
                .filter_map(|c| match &c.kind {
                    ConstraintKind::Equal { lhs, rhs } => Some((lhs.0, rhs.0)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        );

        // (b) Observable co-typing: give each closure class a DISTINCT width
        // via its smallest member, then every var must read back the width of
        // its own class — coarser (over-merging) or finer (under-merging)
        // partitions both break this.
        let mut classes: Vec<u32> = expect.clone();
        classes.sort_unstable();
        classes.dedup();
        if classes.len() <= 4 {
            let widths = [1u8, 2, 4, 8];
            let mut all = cs.clone();
            for (k, &rep) in classes.iter().enumerate() {
                all.push(has_int(1000 + k as u32, rep, widths[k]));
            }
            let r2 = TypeUnifier::new(nvars).solve(&all).expect("distinct classes cannot conflict");
            for v in 0..nvars {
                let k = classes.iter().position(|&c| c == expect[v as usize]).unwrap();
                assert_eq!(
                    *r2.get(tv(v)),
                    RecoveredType::Int { width: widths[k], signed: true },
                    "iter {iter}: var {v} does not carry its class's type (class rep {})",
                    expect[v as usize]
                );
            }
        }
    }

    assert!(saw_selfloop > 20, "generator produced too few self-edges: {saw_selfloop}");
    assert!(saw_singleton > 50, "generator produced too few singleton classes: {saw_singleton}");
    assert!(saw_all_one > 20, "generator never fully merged all vars: {saw_all_one}");
    assert!(saw_multi > 50, "generator produced too few mixed partitions: {saw_multi}");
}
