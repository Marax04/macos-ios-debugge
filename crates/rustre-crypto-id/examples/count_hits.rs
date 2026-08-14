use std::fs;

fn main() {
    let path = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe";
    let data = fs::read(path).expect("read");
    let summary = rustre_crypto_id::scan_and_summarize(&data);
    println!("total_hits={}", summary.total_hits);
    for (algo, count) in &summary.per_algorithm {
        println!("  {count:4}  {algo}");
    }
    println!("\n--- All hits by offset ---");
    for h in &summary.hits {
        println!("  0x{:08x}  {}  {}  conf={:.2}  len={}", h.offset, h.algorithm, h.constant_name, h.confidence, h.match_length);
    }

    // Also test SHA-256 K scan directly
    println!("\n--- Direct SHA256 K scan ---");
    let sha256_k_hits = rustre_crypto_id::scan_for_sha256_constants(&data);
    println!("scan_for_sha256_constants: {} hits", sha256_k_hits.len());
    for h in &sha256_k_hits {
        println!("  0x{:08x}  {}  conf={:.2}", h.offset, h.constant_name, h.confidence);
    }

    let sha256_init_hits = rustre_crypto_id::scan_for_sha256_init(&data);
    println!("scan_for_sha256_init: {} hits", sha256_init_hits.len());
    for h in &sha256_init_hits {
        println!("  0x{:08x}  {}  conf={:.2}", h.offset, h.constant_name, h.confidence);
    }
}
