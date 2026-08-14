//! Performance baseline + robustness smoke test for the demangle crate.
//! Run: cargo run --release -p rustre-demangle --example `bench_baseline`
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    reason = "benchmark harness: stat math tolerates lossy casts"
)]

use std::time::Instant;

const CORPUS: &[&str] = &[
    "_ZN3foo3barEv",
    "_ZNSt6vectorIiSaIiEE9push_backERKi",
    "_ZN9__gnu_cxx17__normal_iteratorIPKcNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEppEv",
    "_RNvNtCs1234_7mycrate3foo3bar",
    "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
    "?foo@bar@@QEAAHXZ",
    "??0MyClass@@QEAA@XZ",
    "?GetValue@Widget@ns@@QEBAHXZ",
    "_D3std5stdio7writelnFiZv",
    "main.main",
    "net/http.(*Server).ListenAndServe",
    "github.com/user/repo/pkg.(*Type).Method.func1",
    "_TFC4test3Foo3barfS0_FT_T_",
    "$s4test3FooC3baryyF",
    "_ZTV6Widget",
    "_ZTI6Widget",
    "sub_401000",
    "plain_c_symbol",
];

const fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn main() {
    // Robustness: adversarial inputs must not panic or hang.
    let adversarial: Vec<String> = {
        let mut v = vec![
            String::new(),
            "_Z".into(),
            "_ZN".into(),
            "?".into(),
            "_R".into(),
            "_D".into(),
            "_ZN99999999999999999999foo".into(),
            "_ZNS_".repeat(200),
            "_Z1fI".to_string() + &"T_".repeat(500) + "E",
            "?".to_string() + &"@".repeat(1000),
            "_ZN3fooE\u{0301}\u{fe0f}".into(),
            "_D".to_string() + &"9".repeat(300),
        ];
        let mut st = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..2000 {
            let len = (lcg(&mut st) % 64) as usize + 1;
            let s: String = (0..len)
                .map(|_| (lcg(&mut st) % 94 + 33) as u8 as char)
                .collect();
            v.push(format!("_Z{s}"));
            v.push(format!("?{s}"));
            v.push(format!("_R{s}"));
            v.push(s);
        }
        v
    };
    let t = Instant::now();
    for s in &adversarial {
        let _ = rustre_demangle::demangle(s);
    }
    println!(
        "robustness: {} adversarial inputs, no panic, {:?}",
        adversarial.len(),
        t.elapsed()
    );

    // Throughput baseline over representative corpus.
    const ITERS: usize = 20_000;
    let t = Instant::now();
    let mut ok = 0usize;
    for _ in 0..ITERS {
        for s in CORPUS {
            if rustre_demangle::demangle(s).is_some() {
                ok += 1;
            }
        }
    }
    let el = t.elapsed();
    let total = ITERS * CORPUS.len();
    println!(
        "throughput: {} calls in {:?} -> {:.0} calls/s ({} demangled ok, {:.1}%)",
        total,
        el,
        total as f64 / el.as_secs_f64(),
        ok,
        100.0 * ok as f64 / total as f64
    );
}
