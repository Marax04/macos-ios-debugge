//! `retroactive_print_demo` — annotate an address, replay the write log, print output.
//!
//! Demonstrates [`retroactive_print`]: annotate a watched address with a
//! format string and expression arguments, then replay the recorded write
//! log (the omniscient index) and render one output line per write — exactly
//! as Pernosco's retroactive print does, but without re-running the target.
//!
//! # Steps
//! 1. Build a small [`OmniscientIndex`] with three synthetic writes to 0x1000.
//! 2. Register a [`RetroAnnotation`] for address 0x1000 with a format string
//!    referencing the write metadata.
//! 3. Call [`retro_print`] to evaluate the annotation over the recorded trace.
//! 4. Print each [`RetroPrintEntry::rendered`] output line.
//!
//! # Running
//! ```text
//! cargo run --example retroactive_print_demo --release
//! ```
//!
//! # Errors
//! Exits with code 1 when the annotation produces no output — e.g. no writes
//! were recorded to the annotated address.

fn main() {
    if let Err(e) = run() {
        eprintln!("retroactive_print_demo: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    use rustre_debug::retroactive_print::{RetroAnnotation, retro_print};
    use rustre_debug::time_travel_debug::SnapshotReplayBackend;
    use rustre_debug::omniscient_query::{OmniscientIndex, MemoryWrite};
    use rustre_debug::{ThreadId};
    use rustre_core::address::Address;

    // 1. Build a synthetic trace with three writes to address 0x1000.
    let mut index = OmniscientIndex::new();
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
    println!(
        "[retro_demo] recorded {} write(s) to trace",
        index.len()
    );

    // 2. Annotate address 0x1000 with a simple format that echoes the write
    //    sequence number via the writer_pc register (no live registers are
    //    available in this example, so we get Err placeholders for {0}).
    let ann = RetroAnnotation {
        address: 0x1000,
        format:  "write to 0x1000: writer_pc={0}".to_string(),
        args:    vec!["writer_pc".to_string()],
    };

    // 3. An empty replay backend — no historical register state was recorded,
    //    so arg evaluation returns Err("no historical state") per write.
    let replay = SnapshotReplayBackend::new();

    // Scan all writes up to and including sequence 10.
    let entries = retro_print(&index, &replay, &ann, /*before=*/ 10);

    // 4. Print results.
    println!("[retro_demo] retroactive print output ({} line(s)):", entries.len());
    for e in &entries {
        println!(
            "  seq={:<4}  pc={:?}  {}",
            e.write.sequence,
            e.writer_pc.map(|p| format!("{p:#018x}")),
            e.rendered
        );
    }

    if entries.is_empty() {
        anyhow::bail!(
            "no output lines produced — check that writes match the annotated address"
        );
    }

    println!("[retro_demo] done");
    Ok(())
}
