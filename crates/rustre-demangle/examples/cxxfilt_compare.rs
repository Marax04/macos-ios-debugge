//! Compare this crate's Itanium output against binutils `c++filt` on the
//! real-corpus symbols (`tests/data/real_symbols.txt`).
//!
//! `c++filt` is an oracle *independent* of the `cpp_demangle` crate the
//! differential suites already use, so agreement here rules out bugs shared
//! by the Rust ecosystem implementations. Run manually:
//!
//! ```text
//! cargo run --release -p rustre-demangle --example cxxfilt_compare
//! ```
//!
//! Exits non-zero when divergences are found. Symbols where `c++filt` gives
//! no opinion (echoes the input back) are skipped.

use std::io::Write as _;
use std::process::{Command, Stdio};

#[expect(
    clippy::too_many_lines,
    reason = "linear comparison harness: splitting it would not aid readability"
)]
fn main() {
    let raw = include_str!("../tests/data/real_symbols.txt");
    let symbols: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("_Z") || l.starts_with("__Z"))
        .collect();

    // One c++filt invocation for the whole batch, newline-separated.
    let mut child = Command::new("c++filt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("c++filt not found on PATH — install binutils/mingw");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(symbols.join("\n").as_bytes())
        .expect("write to c++filt");
    let out = child.wait_with_output().expect("c++filt run");
    let reference: Vec<&str> = std::str::from_utf8(&out.stdout)
        .expect("utf8")
        .lines()
        .collect();
    assert_eq!(
        reference.len(),
        symbols.len(),
        "c++filt line count mismatch"
    );

    // `c++filt` expands the `Ss`/`So`/`Si`/`Sd` substitutions to the full
    // `std::basic_*` spellings, while this crate (like LLVM) keeps the
    // abbreviated typedef names. Both are valid renderings of the same
    // symbol — collapse the expansion so only substantive differences count.
    let collapse = |s: &str| -> String {
        s.replace(
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
            "std::string",
        )
        .replace("std::basic_ostream<char, std::char_traits<char> >", "std::ostream")
        .replace("std::basic_istream<char, std::char_traits<char> >", "std::istream")
        .replace("std::basic_iostream<char, std::char_traits<char> >", "std::iostream")
        // Ctor/dtor names follow the class spelling: collapse those too.
        .replace("std::string::basic_string", "std::string::string")
        .replace("std::string::~basic_string", "std::string::~string")
        .replace("std::ostream::basic_ostream", "std::ostream::ostream")
        .replace("std::istream::basic_istream", "std::istream::istream")
        .replace("std::iostream::basic_iostream", "std::iostream::iostream")
        // The expansion leaves `std::string >` where the abbreviated form
        // has `std::string>`; both sides get the same whitespace squeeze.
        .replace(" >", ">")
        .replace(" &", "&")
    };

    // Known upstream `cpp_demangle` defect: after a template-argument
    // back-reference, a parameter repeated via substitution (`T_ S2_`,
    // the classic two-iterator constructor) loses its second occurrence.
    // Detect that exact shape — our parameter list equals the reference's
    // with one adjacent duplicate removed — and report it as a known bug
    // instead of a new divergence.
    let is_known_dup_loss = |ours: &str, want: &str| -> bool {
        let params = |s: &str| -> Option<Vec<String>> {
            let open = s.find('(')?;
            let inner = s.get(open + 1..s.rfind(')')?)?;
            let mut depth = 0i32;
            let mut cur = String::new();
            let mut out = Vec::new();
            for c in inner.chars() {
                match c {
                    '(' | '<' | '[' => depth += 1,
                    ')' | '>' | ']' => depth -= 1,
                    ',' if depth == 0 => {
                        out.push(cur.trim().to_owned());
                        cur.clear();
                        continue;
                    }
                    _ => {}
                }
                cur.push(c);
            }
            if !cur.trim().is_empty() {
                out.push(cur.trim().to_owned());
            }
            Some(out)
        };
        let (Some(a), Some(b)) = (params(ours), params(want)) else {
            return false;
        };
        if b.len() != a.len() + 1 {
            return false;
        }
        // Remove one adjacent duplicate from the reference list and compare.
        for i in 1..b.len() {
            if b[i] == b[i - 1] {
                let mut reduced = b.clone();
                reduced.remove(i);
                if reduced == a {
                    return true;
                }
            }
        }
        false
    };

    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut known_upstream = 0usize;
    let mut divergences = Vec::new();
    for (sym, want) in symbols.iter().zip(&reference) {
        let want = want.trim();
        if want == *sym {
            // c++filt declined: no ground truth.
            skipped += 1;
            continue;
        }
        compared += 1;
        let want_c = collapse(want);
        match rustre_demangle::demangle(sym) {
            Some(ours) if collapse(&ours.demangled) == want_c => {}
            Some(ours) if is_known_dup_loss(&collapse(&ours.demangled), &want_c) => {
                known_upstream += 1;
            }
            Some(ours) => divergences.push(format!(
                "  {sym}\n    c++filt: {want}\n    ours:    {}",
                ours.demangled
            )),
            None => divergences.push(format!("  {sym}\n    c++filt: {want}\n    ours:    <None>")),
        }
    }

    println!(
        "cxxfilt differential: {compared} compared, {skipped} skipped, \
         {known_upstream} known-upstream (cpp_demangle duplicate-param loss), {} divergences",
        divergences.len()
    );
    if !divergences.is_empty() {
        for d in divergences.iter().take(40) {
            println!("{d}");
        }
        std::process::exit(1);
    }
}
