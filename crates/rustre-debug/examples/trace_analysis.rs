//! trace_analysis — build a synthetic omniscient write log, run a
//! natural-language query, and print the result.
//!
//! Demonstrates the high-level trace-analysis pipeline:
//!
//! 1. Construct an [`OmniscientIndex`] with a handful of recorded writes
//!    (or, when `RUSTRE_TRACE` is set, note the path — live replay from a
//!    real WinDbg-TTD / rr trace is sketched but not wired in this example).
//! 2. Translate a free-form English question via the [`nl_query`] front-end
//!    into a typed [`NlQuery`].
//! 3. Execute the query against the index with [`nl_query::execute`].
//! 4. Print the human-readable result.
//!
//! # Running
//! ```text
//! cargo run --example trace_analysis --release
//! cargo run --example trace_analysis --release -- "who wrote address 0x1000?"
//! ```
//!
//! # Errors
//! Prints a human-readable error and exits with code 1 when the NL-query
//! translator cannot parse the question.

fn main() {
    let question = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "who wrote address 0x1000?".to_string());

    if let Err(e) = run(&question) {
        eprintln!("trace_analysis: {e}");
        std::process::exit(1);
    }
}

fn run(question: &str) -> anyhow::Result<()> {
    use rustre_debug::nl_query;

    println!("[trace_analysis] question: {question:?}");

    let index = build_index()?;
    println!("[trace_analysis] index: {} write(s)", index.len());

    // Translate the NL question into a typed query.
    let query = nl_query::translate(question)
        .map_err(|e| anyhow::anyhow!("nl_query translate: {e:?}"))?;
    println!("[trace_analysis] parsed query: {query:?}");

    // Execute and print the result.
    let result = nl_query::execute(&query, &index);
    println!("[trace_analysis] result: {result:?}");

    Ok(())
}

/// Build an [`OmniscientIndex`] from a synthetic set of writes.
///
/// In a real integration you would open a WinDbg-TTD or rr trace with
/// `rustre_debug::ttd_open::open_trace`, replay it, and call `index.push()`
/// for each recorded write.
fn build_index() -> anyhow::Result<rustre_debug::omniscient_query::OmniscientIndex> {
    use rustre_debug::omniscient_query::{OmniscientIndex, MemoryWrite};
    use rustre_debug::{ThreadId};
    use rustre_core::address::Address;

    if let Ok(path) = std::env::var("RUSTRE_TRACE") {
        println!(
            "[trace_analysis] RUSTRE_TRACE={path} — live trace replay is not \
             wired in this example; using synthetic data"
        );
    }

    let mut index = OmniscientIndex::new();

    // Three synthetic writes to address 0x1000.
    for seq in 1u64..=3 {
        index.push(MemoryWrite {
            sequence:       seq,
            address:        Address::new(0x1000),
            size:           8,
            tid:            ThreadId(1),
            writer_pc:      Some(Address::new(0x401_000 + seq * 0x20)),
            source_address: None,
        });
    }

    // One write from a different thread to 0x2000 with a source address.
    index.push(MemoryWrite {
        sequence:       4,
        address:        Address::new(0x2000),
        size:           4,
        tid:            ThreadId(2),
        writer_pc:      Some(Address::new(0x402_000)),
        source_address: Some(Address::new(0x1000)),
    });

    Ok(index)
}
