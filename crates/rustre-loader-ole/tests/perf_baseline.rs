//! Coarse performance baseline for the OLE loader (run with --release).
//! Not a rigorous benchmark; used to compare before/after optimization passes.

use std::time::Instant;

use rustre_loader_ole::{CfbBuilder, CfbReader, OleFile, OleMacroExtractor, is_ole};

fn build_sample(n_streams: usize, stream_len: usize) -> Vec<u8> {
    let mut b = CfbBuilder::new();
    for i in 0..n_streams {
        let data: Vec<u8> = (0..stream_len).map(|j| ((i + j) % 251) as u8).collect();
        b.add_stream(format!("Stream{i}"), data);
    }
    b.build()
}

#[test]
fn perf_baseline() {
    let sample = build_sample(64, 32 * 1024);
    println!("sample size: {} bytes", sample.len());

    let t = Instant::now();
    for _ in 0..50 {
        let reader = CfbReader::parse(sample.clone()).expect("parse");
        let mut total = 0usize;
        for (_, e) in reader.list_all() {
            if let Ok(s) = reader.read_stream(e) {
                total += s.len();
            }
        }
        assert!(total > 0);
    }
    println!("CfbReader parse+read x50: {:?}", t.elapsed());

    let t = Instant::now();
    for _ in 0..200 {
        let f = OleFile::parse(&sample).expect("olefile");
        assert!(!f.streams().is_empty());
    }
    println!("OleFile::parse x200: {:?}", t.elapsed());

    let t = Instant::now();
    for _ in 0..200 {
        assert!(is_ole(&sample));
        let _ = OleMacroExtractor::new().extract_macros(&sample);
    }
    println!("is_ole + extract_macros x200: {:?}", t.elapsed());
}
