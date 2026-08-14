//! In which PE section do our matches land? (Level 7)
//!
//! Our scan walks the **raw file** at offset 0; the decompiler walks mapped
//! sections at virtual addresses. Before concluding that the decompiler misses
//! matches we find, the obvious alternative has to be ruled out: that ours land
//! outside executable code — in headers, data, or the import table — where a
//! byte sequence can occur without being that function.
//!
//! A match in `.text` is a candidate identification. A match anywhere else is an
//! artefact of scanning a file instead of a program.

use std::collections::BTreeMap;

/// Minimal PE section table: `(name, raw_start, raw_size, characteristics)`.
fn sections(pe: &[u8]) -> Option<Vec<(String, u32, u32, u32)>> {
    let lfanew = u32::from_le_bytes(pe.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if pe.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = lfanew + 4;
    let n_sections = u16::from_le_bytes(pe.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(pe.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let table = coff + 20 + opt_size;

    let mut out = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let b = table + i * 40;
        let raw = pe.get(b..b + 40)?;
        let end = raw[..8].iter().position(|&c| c == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw[..end]).into_owned();
        let size = u32::from_le_bytes(raw[16..20].try_into().ok()?);
        let ptr = u32::from_le_bytes(raw[20..24].try_into().ok()?);
        let chars = u32::from_le_bytes(raw[36..40].try_into().ok()?);
        out.push((name, ptr, size, chars));
    }
    Some(out)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let sig_path = a
        .get(1)
        .map_or(r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig", String::as_str);
    let bin_path = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);

    let (Ok(sig), Ok(bin)) = (std::fs::read(sig_path), std::fs::read(bin_path)) else {
        eprintln!("input mancante");
        std::process::exit(2);
    };
    let Some(secs) = sections(&bin) else {
        eprintln!("PE non parsabile");
        std::process::exit(1);
    };
    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        std::process::exit(1);
    };

    let known: std::collections::HashSet<String> =
        rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
            .into_iter()
            .map(|s| s.name)
            .collect();

    let locate = |off: u64| -> (String, bool) {
        for (name, ptr, size, chars) in &secs {
            if off >= u64::from(*ptr) && off < u64::from(*ptr) + u64::from(*size) {
                // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                let exec = chars & 0x2000_0020 != 0;
                return (name.clone(), exec);
            }
        }
        ("(fuori sezione)".to_string(), false)
    };

    let mut by_section: BTreeMap<String, usize> = BTreeMap::new();
    let mut proto_placement: Vec<(String, String, bool)> = Vec::new();

    for m in scanner.scan_fast(&bin, 0) {
        if m.function_name.is_empty() {
            continue;
        }
        let (sec, exec) = locate(m.address);
        *by_section.entry(sec.clone()).or_default() += 1;
        if known.contains(&m.function_name) {
            proto_placement.push((m.function_name, sec, exec));
        }
    }

    println!("sezioni del PE:");
    for (n, ptr, size, chars) in &secs {
        let exec = chars & 0x2000_0020 != 0;
        println!("   {n:<10} raw {ptr:#010x} size {size:#010x} {}", if exec { "ESEGUIBILE" } else { "" });
    }
    println!();
    println!("match per sezione:");
    for (sec, n) in &by_section {
        println!("   {sec:<18} {n}");
    }
    println!();
    println!("dove cadono i nomi CON prototipo:");
    for (name, sec, exec) in &proto_placement {
        println!("   {name:<26} {sec:<12} {}", if *exec { "eseguibile" } else { "NON eseguibile" });
    }
}
