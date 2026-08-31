//! Live coverage of the natural-language query front-end (`nl_query`) against a
//! REAL ptrace'd Linux process.
//!
//! Three surfaces are under test, the same three the MCP layer exposes as
//! `debug.nl_query` / `debug.nl_translate` / `debug.nl_capabilities`:
//!
//! * `nl_query::translate`            — question to typed [`NlQuery`]
//! * `nl_query::execute`              — typed query to [`NlQueryResult`]
//! * `nl_query::RULE_BASED_PATTERNS`  — the advertised capability list
//!
//! Nothing here invents a write log. A small C fixture is compiled on the fly
//! (`cc -O0 -static -no-pie`), launched under `LinuxDebugger`, single-stepped
//! with ptrace, and the [`MemoryWrite`]s handed to the executor are the writes
//! that process actually performed — measured by re-reading the global after
//! every step. The external truth for "what should the answer be" comes from
//! the fixture source (two stores, `0x11` then `0x22`) and from
//! `nm --print-size`, never from the debugger.
//!
//! ## Measured capability gap
//!
//! `RULE_BASED_PATTERNS` advertises 11 patterns. All 11 TRANSLATE. Only 4 of
//! the 8 resulting query variants actually ANSWER; the rest execute into a
//! `Text` result that tells the caller to go use a different tool. The
//! capability list does not distinguish the two, so a caller reading it cannot
//! tell an answer from a referral.
//!
//! | advertised pattern | expected (external truth) | reachable with what the crate has | obtained today |
//! |---|---|---|---|
//! | `who wrote to 0x<addr>` | rr/Pernosco: the storing instructions | `OmniscientIndex::who_wrote` | **answers** — 2 writes, real pcs inside `main` |
//! | `who wrote to <addr> before <seq>` | writes up to a cutoff | same, `at_time` bound | **answers** — 1 write |
//! | `trace origin of 0x<addr>` | backward writer chain | `OmniscientIndex::trace_origin` | **answers** — hops on real data |
//! | `causal rank 0x<addr>` | synonym of the above | same | **answers** |
//! | `when did 0x<addr> become <pred>` | first write whose VALUE matched `<pred>` | nothing: `OmniscientIndex` stores write *events*, not values | **every** write returned as a "candidate", value `0`; a predicate no write satisfies still yields 2 hits (`defect_invariant_check_never_evaluates_the_predicate`) |
//! | `find instruction <pattern>` | writes whose instruction matches the mnemonic | no disassembler is consulted | the pattern is echoed and IGNORED: two different patterns produce identical answers (`defect_instruction_search_ignores_the_pattern`) |
//! | `hot addresses` / `top <N> hot addresses` | top-N executed addresses | `ExecutionHeatmap` exists, executor never builds one | referral text (`defect_heatmap_query_returns_no_heatmap`) |
//! | `call chain to sub_<addr>` | reverse call graph | needs `rustre-analysis`, not wired | referral text |
//! | `diff run <A> and run <B>` | semantic diff of two runs | needs two indices, executor gets one | referral text |
//!
//! A second, narrower overclaim lives one layer up: `debug.nl_capabilities`
//! reports `llm_assisted: true` whenever `ANTHROPIC_API_KEY` is set, but
//! `nl_query::translate` calls only `rule_based_translate` — it has no LLM
//! fallback under any feature setting, so the key changes nothing. Pinned by
//! `translate_has_no_llm_fallback_even_with_api_key_set`.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::nl_query::{
    self, NlQuery, NlQueryError, NlQueryResult, RULE_BASED_PATTERNS,
};
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, StopReason, ThreadId};
use std::process::Command;

// ── Fixture ──────────────────────────────────────────────────────────────────

/// `g` is written exactly twice by `main`, with two constants chosen so that
/// "how many writes" and "which values" are answerable from the source alone.
/// Both are POSITIVE, which is what makes the `< 0` predicate test meaningful.
const FIXTURE_C: &str = r#"
#include <stdio.h>
int g = 0;
__attribute__((noinline)) int callee(int x) { return x * 2 + 1; }
int main(void) {
    g = 0x11;
    g = 0x22;
    int b = callee(g);
    printf("%d %d\n", g, b);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    /// `[start, end)` of `main`, from `nm --print-size`.
    main: (u64, u64),
    /// Address of the global `g`, from `nm`.
    g: u64,
}

fn build_fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("nlfixture.c");
    let exe = dir.path().join("nlfixture");
    std::fs::write(&src, FIXTURE_C).ok()?;
    let out = Command::new("cc")
        .args(["-O0", "-g", "-static", "-no-pie", "-fno-pie"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("[fixture] cc failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    let path = exe.to_str()?.to_string();
    let main = symbol_extent(&path, "main")?;
    let g = symbol_addr(&path, "g")?;
    Some(Fixture { _dir: dir, path, main, g })
}

fn symbol_extent(exe: &str, name: &str) -> Option<(u64, u64)> {
    let out = Command::new("nm").args(["--print-size", "--defined-only", exe]).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() == 4 && f[3] == name {
            let addr = u64::from_str_radix(f[0], 16).ok()?;
            let size = u64::from_str_radix(f[1], 16).ok()?;
            return Some((addr, addr + size));
        }
    }
    None
}

fn symbol_addr(exe: &str, name: &str) -> Option<u64> {
    let out = Command::new("nm").args(["--print-size", "--defined-only", exe]).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f.last() == Some(&name) {
            return u64::from_str_radix(f[0], 16).ok();
        }
    }
    None
}

macro_rules! fixture_or_skip {
    () => {
        match build_fixture() {
            Some(f) => f,
            None => {
                eprintln!("[skip] no usable C toolchain / static libc on this host");
                return;
            }
        }
    };
}

// ── Harness ──────────────────────────────────────────────────────────────────

async fn open(fx: &Fixture) -> Option<(LinuxDebugger, ThreadId)> {
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(LaunchOptions::new(fx.path.clone())).await.ok()?;
    Some((dbg, ThreadId(pid.0)))
}

async fn run_to(dbg: &LinuxDebugger, addr: u64) -> bool {
    if dbg.set_breakpoint(Address(addr), BreakpointKind::Software).await.is_err() {
        return false;
    }
    for _ in 0..4000 {
        let Ok(ev) = dbg.continue_execution().await else { return false };
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == addr => return true,
            StopReason::ProcessExit { .. } => return false,
            _ => {}
        }
    }
    false
}

/// The write log the NL executor consumes, OBSERVED off the live process:
/// single-step, re-read the 4 bytes of `g`, and record a [`MemoryWrite`] the
/// moment the value changes, attributing it to the pc that was about to run.
///
/// Returns the index plus `(sequence, new_value, writer_pc)` for each observed
/// change — the second half is the independent record the assertions compare
/// the NL answers against.
async fn observe_writes_to(
    dbg: &LinuxDebugger,
    tid: ThreadId,
    addr: u64,
    max_steps: usize,
) -> (OmniscientIndex, Vec<(u64, u32, u64)>) {
    let mut index = OmniscientIndex::new();
    let mut observed: Vec<(u64, u32, u64)> = Vec::new();
    let as_u32 = |b: &[u8]| -> u32 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&b[..4]);
        u32::from_le_bytes(a)
    };
    let Ok(first) = dbg.read_memory(Address::new(addr), 4).await else {
        return (index, observed);
    };
    let mut prev = as_u32(&first);

    for seq in 1..=max_steps as u64 {
        let Ok(regs) = dbg.get_registers(tid).await else { break };
        let pc = regs.pc;
        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
        let Ok(now) = dbg.read_memory(Address::new(addr), 4).await else { break };
        let now = as_u32(&now);
        if now != prev {
            index.push(MemoryWrite {
                sequence: seq,
                address: Address::new(addr),
                size: 4,
                tid,
                writer_pc: Some(Address::new(pc)),
                source_address: None,
            });
            observed.push((seq, now, pc));
            prev = now;
        }
    }
    (index, observed)
}

/// Launch, run to `main`, observe the writes to `g`, kill. Every caller gets a
/// dead process back regardless of what it then asserts — the kill happens
/// BEFORE the assertions, so a failing assertion cannot orphan the fixture.
async fn live_index(fx: &Fixture) -> Option<(OmniscientIndex, Vec<(u64, u32, u64)>)> {
    let (dbg, tid) = open(fx).await?;
    if !run_to(&dbg, fx.main.0).await {
        let _ = dbg.kill().await;
        eprintln!("[skip] fixture never reached main");
        return None;
    }
    let (index, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;
    let _ = dbg.kill().await;
    Some((index, observed))
}

macro_rules! live_or_skip {
    ($fx:expr) => {
        match live_index($fx).await {
            Some(v) => v,
            None => return,
        }
    };
}

fn writes_of(r: &NlQueryResult) -> &[MemoryWrite] {
    match r {
        NlQueryResult::Writes { writes, .. } => writes,
        other => panic!("expected a Writes result, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. The fixture's own truth — pin the input before anything queries it
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: the live process performs exactly the two stores the source
/// promises, `0x11` then `0x22`, from instructions inside `main`.
///
/// WHY THAT IS RIGHT: every NL answer below is judged against these numbers.
/// If the observation itself were wrong, a wrong NL answer could still match it
/// and the whole file would be green and meaningless.
#[tokio::test]
async fn fixture_performs_exactly_the_two_stores_the_source_promises() {
    let fx = fixture_or_skip!();
    let (_index, observed) = live_or_skip!(&fx);

    let values: Vec<u32> = observed.iter().map(|(_, v, _)| *v).collect();
    assert_eq!(values, vec![0x11, 0x22], "the source stores 0x11 then 0x22; observed {values:x?}");
    for (seq, val, pc) in &observed {
        assert!(
            *pc >= fx.main.0 && *pc < fx.main.1,
            "store of {val:#x} at seq {seq} came from pc {pc:#x}, outside main [{:#x},{:#x})",
            fx.main.0,
            fx.main.1
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. nl_translate produces an EXECUTABLE query for the known questions
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: "who wrote to 0x<g>" translates to `WhoWrote` carrying the very
/// address the question named and an unbounded time, and executing it on the
/// live write log returns BOTH real stores with their real pcs.
///
/// WHY THAT IS RIGHT: a translator that produced a plausible-looking query
/// against a slightly different address would answer "nobody" — indistinguishable
/// from a genuine answer. Comparing pcs to the independently observed ones is
/// what makes the query executable *and* correct, not merely well-formed.
#[tokio::test]
async fn nl_translate_who_wrote_answers_with_the_real_stores() {
    let fx = fixture_or_skip!();
    let (index, observed) = live_or_skip!(&fx);
    assert_eq!(observed.len(), 2, "precondition: two observed stores");

    let q = nl_query::translate(&format!("who wrote to {:#x}", fx.g)).expect("must translate");
    assert_eq!(q, NlQuery::WhoWrote { address: fx.g, at_time: u64::MAX });

    let res = nl_query::execute(&q, &index);
    let writes = writes_of(&res);
    assert_eq!(writes.len(), 2, "both stores must be named; result {res:?}");
    // `who_wrote` is documented most-recent-first ("the first element is the
    // instruction that last wrote it"), so the expected pc order is the
    // observation order REVERSED. Asserting the order, not a set, is what makes
    // "which instruction wrote it last" checkable at all.
    let got: Vec<u64> = writes.iter().filter_map(|w| w.writer_pc).map(|a| a.0).collect();
    let mut want: Vec<u64> = observed.iter().map(|(_, _, pc)| *pc).collect();
    want.reverse();
    assert_eq!(got, want, "the NL answer must cite the pcs ptrace observed, newest first");
    let got_seq: Vec<u64> = writes.iter().map(|w| w.sequence).collect();
    let mut want_seq: Vec<u64> = observed.iter().map(|(s, _, _)| *s).collect();
    want_seq.reverse();
    assert_eq!(got_seq, want_seq, "sequences must be the observed ones, newest first");
}

/// PROVES: the `before <seq>` time bound is honoured — asking before the
/// second store's sequence yields exactly the first store.
///
/// WHY THAT IS RIGHT: the bound is the only part of the translation the
/// question carries beyond the address. A translator that dropped it (or an
/// executor that ignored it) would still return a non-empty, plausible answer.
#[tokio::test]
async fn nl_translate_who_wrote_honours_the_before_bound() {
    let fx = fixture_or_skip!();
    let (index, observed) = live_or_skip!(&fx);
    assert_eq!(observed.len(), 2, "precondition: two observed stores");
    let second_seq = observed[1].0;
    let first_pc = observed[0].2;

    // `at_time` is INCLUSIVE (`who_wrote` = "at or before"), so the cutoff that
    // excludes the second store is `second_seq - 1`. See
    // `defect_before_seq_is_off_by_one_against_the_english_word` for the
    // inclusive/exclusive mismatch this exposes at the NL layer.
    let cutoff = second_seq - 1;
    let q = nl_query::translate(&format!("who wrote to {:#x} before {cutoff}", fx.g))
        .expect("must translate");
    assert_eq!(q, NlQuery::WhoWrote { address: fx.g, at_time: cutoff });

    let writes = writes_of(&nl_query::execute(&q, &index)).to_vec();
    assert_eq!(writes.len(), 1, "only the first store is at or before seq {cutoff}");
    assert_eq!(writes[0].writer_pc.map(|a| a.0), Some(first_pc));

    // And the unbounded form still sees both — proving the bound did the work,
    // not an empty index.
    let all = nl_query::translate(&format!("who wrote to {:#x}", fx.g)).expect("translates");
    assert_eq!(writes_of(&nl_query::execute(&all, &index)).len(), 2);
}

/// DEFECT (off-by-one, low severity). The advertised pattern is
/// `who wrote to <addr> before <seq>`. The translator passes `<seq>` straight
/// into `at_time`, which `OmniscientIndex::who_wrote` documents as "at or
/// BEFORE" — so a write that happened exactly AT `<seq>` is included in an
/// answer the caller asked to stop before.
///
/// Measured live: the second store to `g` happens at sequence `S`; asking
/// "who wrote to g before S" returns 2 writes, including the one at `S`.
///
/// | | expected (external truth) | reachable with what the crate has | obtained today |
/// |---|---|---|---|
/// | `before S`, second store at `S` | 1 write (gdb/rr read "before" as exclusive) | `at_time` is inclusive by contract; the translator would have to pass `seq - 1` | 2 writes |
#[tokio::test]
#[ignore = "DEFECT: 'before <seq>' is inclusive of <seq>; see doc comment"]
async fn defect_before_seq_is_off_by_one_against_the_english_word() {
    let fx = fixture_or_skip!();
    let (index, observed) = live_or_skip!(&fx);
    assert_eq!(observed.len(), 2, "precondition: two observed stores");
    let second_seq = observed[1].0;

    let q = nl_query::translate(&format!("who wrote to {:#x} before {second_seq}", fx.g))
        .expect("must translate");
    let writes = writes_of(&nl_query::execute(&q, &index)).to_vec();
    assert_eq!(
        writes.len(),
        1,
        "the store AT seq {second_seq} is not 'before' it, yet it is reported: {writes:?}"
    );
}

/// PROVES: "trace origin of 0x<g>" and "causal rank 0x<g>" translate to the
/// SAME `CausalRank` query (the capability list calls them synonyms) and both
/// execute into a chain rooted at the address the question named.
///
/// WHY THAT IS RIGHT: `RULE_BASED_PATTERNS` advertises them as synonyms; two
/// different parse paths reach the same variant, so this checks the claim
/// rather than assuming it.
#[tokio::test]
async fn nl_translate_trace_origin_and_causal_rank_are_the_same_query() {
    let fx = fixture_or_skip!();
    let (index, observed) = live_or_skip!(&fx);
    assert!(!observed.is_empty(), "precondition: at least one observed store");

    let a = nl_query::translate(&format!("trace origin of {:#x}", fx.g)).expect("trace origin");
    let b = nl_query::translate(&format!("causal rank {:#x}", fx.g)).expect("causal rank");
    assert_eq!(a, b, "the capability list calls these synonyms");
    assert_eq!(a, NlQuery::CausalRank { address: fx.g, at_time: u64::MAX, hops: 5 });

    match nl_query::execute(&a, &index) {
        NlQueryResult::CausalChain { address, hops, .. } => {
            assert_eq!(address, fx.g);
            assert!(!hops.is_empty(), "an address written twice must have a chain");
            assert_eq!(hops[0].queried_address.0, fx.g, "the chain must start where asked");
        }
        other => panic!("expected CausalChain, got {other:?}"),
    }
}

/// PROVES: an explicit hop limit reaches the executor and truncates the chain.
///
/// WHY THAT IS RIGHT: `1 hops` is smaller than the default 5, so a dropped
/// limit is visible as a longer chain rather than as an identical one.
#[tokio::test]
async fn nl_translate_trace_origin_honours_an_explicit_hop_limit() {
    let fx = fixture_or_skip!();
    let (index, _observed) = live_or_skip!(&fx);

    let q = nl_query::translate(&format!("trace origin of {:#x} 1 hops", fx.g))
        .expect("must translate");
    assert_eq!(q, NlQuery::CausalRank { address: fx.g, at_time: u64::MAX, hops: 1 });
    match nl_query::execute(&q, &index) {
        NlQueryResult::CausalChain { hops, .. } => {
            assert!(hops.len() <= 1, "hop limit 1 must truncate; got {}", hops.len());
        }
        other => panic!("expected CausalChain, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. nl_capabilities lists only what the system can really parse
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: every one of the 11 advertised patterns, instantiated with the LIVE
/// fixture's address, actually translates — the capability list contains no
/// pattern the translator would reject.
///
/// WHY THAT IS RIGHT: a capability list is a promise to callers. The
/// instantiation is written out per pattern rather than generated, so a
/// pattern ADDED to the list without a rule behind it fails the count
/// assertion instead of being silently skipped.
#[tokio::test]
async fn nl_capabilities_lists_only_patterns_that_translate() {
    let fx = fixture_or_skip!();
    let g = fx.g;

    let instantiated: Vec<(&str, String)> = vec![
        ("who wrote to 0x<addr>", format!("who wrote to {g:#x}")),
        ("who wrote to <addr> before <seq>", format!("who wrote to {g:#x} before 100")),
        ("when did 0x<addr> become <pred>", format!("when did {g:#x} become < 0")),
        ("trace origin of 0x<addr>", format!("trace origin of {g:#x}")),
        ("trace origin of 0x<addr> <N> hops", format!("trace origin of {g:#x} 3 hops")),
        ("causal rank 0x<addr>", format!("causal rank {g:#x}")),
        ("diff run <A> and run <B>", "diff run alpha and run beta".to_string()),
        ("hot addresses", "hot addresses".to_string()),
        ("top <N> hot addresses", "top 3 hot addresses".to_string()),
        ("find instruction <pattern>", "find instruction mov".to_string()),
        ("call chain to sub_<addr>", format!("call chain to sub_{g:x}")),
    ];

    assert_eq!(
        instantiated.len(),
        RULE_BASED_PATTERNS.len(),
        "every advertised pattern must be exercised here; the list changed"
    );
    for ((expected, _), (listed, _)) in instantiated.iter().zip(RULE_BASED_PATTERNS) {
        assert_eq!(expected, listed, "capability list order/content changed");
    }
    for (pattern, question) in &instantiated {
        let got = nl_query::translate(question);
        assert!(
            got.is_ok(),
            "advertised pattern {pattern:?} does not translate: {question:?} -> {got:?}"
        );
    }
}

/// PROVES: the capability list documents, in its own comments, that a REGISTER
/// subject is refused — and the translator really refuses it.
///
/// WHY THAT IS RIGHT: this is the one negative claim the list makes. A register
/// silently mapped onto an invented address would produce an empty answer that
/// reads exactly like "that never happened".
#[tokio::test]
async fn nl_capabilities_negative_claim_registers_are_refused() {
    for q in ["when did rax become negative", "when did rsp become < 0"] {
        match nl_query::translate(q) {
            Err(NlQueryError::NotAnAddressableSubject(s)) => {
                assert!(!s.is_empty(), "the refusal must name the subject");
            }
            other => panic!("{q:?} must be refused as a non-addressable subject, got {other:?}"),
        }
    }
}

/// PROVES: `translate` has NO LLM fallback — with `ANTHROPIC_API_KEY` present,
/// an unmatched question is still refused.
///
/// WHY THAT IS RIGHT: `debug.nl_capabilities` reports `llm_assisted: true`
/// purely from that env var, so a caller could reasonably expect the key to
/// widen what translates. It does not: `translate` calls only
/// `rule_based_translate`. This pins the true behaviour, which is the honest
/// one (refuse), and marks the capability report as the overclaiming half.
///
/// | | expected | reachable | obtained |
/// |---|---|---|---|
/// | key set, unmatched question | LLM translates, or a clear "LLM failed" | `llm_translate` exists behind `nl-query-llm`, `translate` never calls it | plain `NoMatch` |
#[tokio::test]
async fn translate_has_no_llm_fallback_even_with_api_key_set() {
    let prev = std::env::var("ANTHROPIC_API_KEY").ok();
    // SAFETY: this suite is run with `--test-threads=1`; the variable is
    // restored below before any assertion can unwind past it.
    unsafe { std::env::set_var("ANTHROPIC_API_KEY", "sk-not-a-real-key") };
    let got = nl_query::translate("explain why the heap is corrupted");
    match prev {
        Some(v) => unsafe { std::env::set_var("ANTHROPIC_API_KEY", v) },
        None => unsafe { std::env::remove_var("ANTHROPIC_API_KEY") },
    }
    assert_eq!(
        got,
        Err(NlQueryError::NoMatch),
        "translate must not pretend an LLM path exists; got {got:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Refusal: a question it cannot translate must NOT be translated at random
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: eleven plausible debugging questions with no matching rule are all
/// REFUSED, none of them silently coerced into a query about some other
/// address.
///
/// WHY THAT IS RIGHT: the failure mode that matters here is not a crash, it is
/// a confident wrong answer. Several of these deliberately contain a hex
/// literal so that a translator tempted to "find an address and guess a query"
/// would be caught rather than rewarded.
#[tokio::test]
async fn unknown_questions_are_refused_not_guessed() {
    let fx = fixture_or_skip!();
    let g = fx.g;
    let questions = vec![
        String::new(),
        "   ".to_string(),
        "why is my program slow".to_string(),
        format!("what is at {g:#x}"),
        format!("show me {g:#x}"),
        format!("who read from {g:#x}"),
        format!("who wrote near {g:#x}"),
        format!("delete everything at {g:#x}"),
        "list threads".to_string(),
        "set a breakpoint on main".to_string(),
        format!("how many times was {g:#x} written"),
    ];
    for q in &questions {
        let got = nl_query::translate(q);
        assert!(
            got.is_err(),
            "{q:?} has no rule behind it and must be refused, but translated to {got:?}"
        );
    }
}

/// PROVES: a question whose SHAPE matches a rule but whose address operand is
/// nonsense is refused with `BadAddress`, naming the offending token — not
/// defaulted to `0x0`.
///
/// WHY THAT IS RIGHT: address `0` is a valid `u64`, and a query against it
/// returns an empty result that is indistinguishable from a truthful "no
/// writes". The error carrying the token is the only way a caller learns the
/// difference.
#[tokio::test]
async fn malformed_operands_are_refused_with_the_offending_token() {
    for (q, tok) in [
        ("who wrote to potato", "potato"),
        ("call chain to sub_zzz", "sub_zzz"),
        ("trace origin of banana", "banana"),
    ] {
        match nl_query::translate(q) {
            Err(NlQueryError::BadAddress(s)) => assert_eq!(s, tok, "for {q:?}"),
            other => panic!("{q:?} must fail with BadAddress({tok:?}), got {other:?}"),
        }
    }
    // A missing operand entirely: no address to invent, so no query.
    for q in ["trace origin of", "causal rank", "who wrote to"] {
        assert!(nl_query::translate(q).is_err(), "{q:?} must be refused");
    }
    // Two `run` keywords but no names after the second: must not become a diff
    // of runs literally called "A" and "B".
    assert!(nl_query::translate("diff run and run").is_err());
}

/// PROVES: a refused question never reaches the executor, and the address a
/// refusal mentions is never queried behind the caller's back.
///
/// WHY THAT IS RIGHT (the test could have been wrong here): `translate` returns
/// a `Result`, so "it was not executed" is structural. What is NOT structural is
/// that the live index would have answered something for the refused subject —
/// this asserts the live index does hold data for `g`, so refusing
/// "who read from g" is a refusal to answer a question it cannot answer, not an
/// empty database.
#[tokio::test]
async fn refusal_is_a_refusal_not_an_empty_database() {
    let fx = fixture_or_skip!();
    let (index, _observed) = live_or_skip!(&fx);

    // The database DOES know about g.
    let ok = nl_query::translate(&format!("who wrote to {:#x}", fx.g)).expect("supported");
    assert_eq!(writes_of(&nl_query::execute(&ok, &index)).len(), 2);

    // The unsupported phrasing about the SAME address is still refused.
    assert!(nl_query::translate(&format!("who read from {:#x}", fx.g)).is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Defects — measured on live data, red, and left ignored
// ═════════════════════════════════════════════════════════════════════════════

/// DEFECT. `when did <addr> become <pred>` is advertised as "first time value
/// matched predicate". The executor never looks at a value: it returns every
/// write to the address as a "candidate" with the value hard-coded to `0`.
///
/// Measured on the live process: `g` holds `0x11` then `0x22`, both positive,
/// so `< 0` is satisfied by ZERO writes. The query reports 2.
///
/// | | expected (external truth) | reachable with what the crate has | obtained today |
/// |---|---|---|---|
/// | `when did g become < 0` | 0 hits — both stored values are positive | `OmniscientIndex` records write EVENTS (seq, addr, size, pc); the stored value is not in it | 2 hits, each with value `0` |
///
/// Closing it needs a value alongside each write (the observer above reads it
/// and throws it away because `MemoryWrite` has nowhere to put it), not a
/// change to the translator — the translation is correct.
#[tokio::test]
#[ignore = "DEFECT: InvariantCheck never evaluates the predicate; see doc comment"]
async fn defect_invariant_check_never_evaluates_the_predicate() {
    let fx = fixture_or_skip!();
    let (index, observed) = live_or_skip!(&fx);
    let values: Vec<u32> = observed.iter().map(|(_, v, _)| *v).collect();
    assert_eq!(values, vec![0x11, 0x22], "precondition: both values positive");

    let q = nl_query::translate(&format!("when did {:#x} become < 0", fx.g)).expect("translates");
    match nl_query::execute(&q, &index) {
        NlQueryResult::InvariantViolations { violations, .. } => {
            assert!(
                violations.is_empty(),
                "no write to g stored a negative value, yet {} were reported: {violations:?}",
                violations.len()
            );
        }
        other => panic!("expected InvariantViolations, got {other:?}"),
    }
}

/// DEFECT. `find instruction <pattern>` is advertised as a
/// "mnemonic/operand pattern scan". The executor never disassembles and never
/// filters: it counts unique writer pcs and echoes the pattern back.
///
/// Measured: `find instruction mov` and `find instruction zzqqxx` produce
/// answers that differ only in the echoed pattern string.
///
/// | | expected | reachable | obtained |
/// |---|---|---|---|
/// | `find instruction mov` on the fixture | the two `mov` stores to `g` | `rustre-arch-x86` is already a dependency of this crate | unfiltered writer-pc count |
/// | `find instruction <nonsense>` | 0 hits | — | the SAME count |
#[tokio::test]
#[ignore = "DEFECT: InstructionSearch ignores its pattern; see doc comment"]
async fn defect_instruction_search_ignores_the_pattern() {
    let fx = fixture_or_skip!();
    let (index, _observed) = live_or_skip!(&fx);

    let real = nl_query::execute(
        &nl_query::translate("find instruction mov").expect("translates"),
        &index,
    );
    let fake = nl_query::execute(
        &nl_query::translate("find instruction zzqqxx").expect("translates"),
        &index,
    );
    let strip = |r: &NlQueryResult, pat: &str| match r {
        NlQueryResult::Text { explanation } => explanation.replace(pat, "<PAT>"),
        other => panic!("expected Text, got {other:?}"),
    };
    assert_ne!(
        strip(&real, "mov"),
        strip(&fake, "zzqqxx"),
        "a mnemonic that appears nowhere must not match what 'mov' matches"
    );
}

/// DEFECT. `hot addresses` / `top <N> hot addresses` is advertised as
/// "ExecutionHeatmap top-N". The result variant `NlQueryResult::Heatmap`
/// exists; the executor never constructs one, returning referral text instead.
///
/// | | expected | reachable | obtained |
/// |---|---|---|---|
/// | `top 3 hot addresses` over a live write log | the 3 most-written addresses | `ExecutionHeatmap` type + the write log this test just measured | `Text` telling the caller to call `debug.build_heatmap` themselves |
#[tokio::test]
#[ignore = "DEFECT: heatmap query returns a referral, not a heatmap; see doc comment"]
async fn defect_heatmap_query_returns_no_heatmap() {
    let fx = fixture_or_skip!();
    let (index, _observed) = live_or_skip!(&fx);

    let q = nl_query::translate("top 3 hot addresses").expect("translates");
    assert_eq!(q, NlQuery::ExecutionHeatmap { top_n: 3 });
    match nl_query::execute(&q, &index) {
        NlQueryResult::Heatmap { .. } => {}
        other => panic!("advertised as a heatmap, executed into {other:?}"),
    }
}

/// PROVES (not a defect, a pinned boundary): three advertised patterns execute
/// into referral `Text` rather than data, and the text NAMES the tool that can
/// answer. This is the honest half of the gap table above.
///
/// WHY THAT IS RIGHT: a referral is acceptable; a referral dressed as an answer
/// is not. Asserting the variant is `Text` and that it names a concrete
/// alternative keeps a future "fix" that returns empty data instead from
/// passing silently.
#[tokio::test]
async fn referral_only_patterns_say_so_and_name_the_real_tool() {
    let fx = fixture_or_skip!();
    let (index, _observed) = live_or_skip!(&fx);

    let call_chain = format!("call chain to sub_{:x}", fx.g);
    for (question, must_mention) in [
        ("diff run alpha and run beta", "semantic_run_diff"),
        ("top 3 hot addresses", "build_heatmap"),
        (call_chain.as_str(), "call_graph"),
    ] {
        let q = nl_query::translate(question).expect("advertised, must translate");
        match nl_query::execute(&q, &index) {
            NlQueryResult::Text { explanation } => assert!(
                explanation.contains(must_mention),
                "{question:?} referral must name {must_mention:?}: {explanation}"
            ),
            other => panic!("{question:?} expected referral Text, got {other:?}"),
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Hygiene
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: this suite leaves no orphaned fixture process behind.
///
/// WHY THAT IS RIGHT: every helper kills the target before its caller asserts,
/// but only an outside observer can prove it. Named `zz_` so cargo's
/// name-ordered `--test-threads=1` run puts it last.
#[tokio::test]
async fn zz_no_orphan_fixture_processes_remain() {
    match Command::new("pgrep").args(["-af", "nlfixture"]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let mine: Vec<&str> =
                s.lines().filter(|l| l.contains("/nlfixture") && !l.contains("pgrep")).collect();
            assert!(mine.is_empty(), "orphaned fixture processes: {mine:?}");
        }
        Err(e) => eprintln!("[skip] pgrep unavailable: {e}"),
    }
}
