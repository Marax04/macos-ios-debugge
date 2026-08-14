//! Probe: compare our output against the reference crates directly, to tell
//! genuine crate bugs apart from wrong test expectations.

fn main() {
    println!("== rustc_demangle reference ==");
    for s in [
        "_ZN71_$LT$Test$u20$as$u20$core..fmt..Debug$GT$3fmt17h1234567890abcdefE",
        "_RNvNtNtC3std2io5stdio6_print",
        "_RNvNtCs1234_7mycrate3foo3bar",
        "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
    ] {
        match rustc_demangle::try_demangle(s) {
            Ok(d) => println!("  OK   {s}\n         -> {d:#}"),
            Err(e) => println!("  ERR  {s}\n         -> {e:?}"),
        }
        println!("  ours -> {:?}", rustre_demangle::demangle(s).map(|r| r.demangled));
    }

    println!("\n== corrected candidates ==");
    for s in [
        // Length prefix recounted: `_$LT$Test$u20$as$u20$core..fmt..Debug$GT$` is 41 chars.
        "_ZN41_$LT$Test$u20$as$u20$core..fmt..Debug$GT$3fmt17h1234567890abcdefE",
        // v0 nested path with a crate disambiguator.
        "_RNvNtNtCs1234_3std2io5stdio6_print",
        "_RNvNtNtCsabc_3std2io5stdio6_print",
    ] {
        match rustc_demangle::try_demangle(s) {
            Ok(d) => println!("  OK   {s}\n         ref  -> {d:#}"),
            Err(e) => println!("  ERR  {s}\n         ref  -> {e:?}"),
        }
        println!("         ours -> {:?}", rustre_demangle::demangle(s).map(|r| r.demangled));
    }

    println!("\n== cpp_demangle reference (Itanium _ZL) ==");
    for s in ["_ZL10static_fnv", "_ZL9static_fnv", "_ZL3fooi"] {
        match cpp_demangle::BorrowedSymbol::new(s.as_bytes()) {
            Ok(sym) => match sym.demangle(&cpp_demangle::DemangleOptions::default()) {
                Ok(d) => println!("  OK   {s} -> {d}"),
                Err(e) => println!("  ERR  {s} -> {e:?}"),
            },
            Err(e) => println!("  ERR  {s} -> {e:?}"),
        }
        println!("  ours -> {:?}", rustre_demangle::demangle(s).map(|r| r.demangled));
    }

    println!("\n== Go generics ==");
    for s in [
        "main.Map[go.shape.int,go.shape.string].Get",
        "slices.Sort[go.shape.int]",
    ] {
        println!("  {s}");
        println!("    simplify=true  -> {:?}",
            rustre_demangle::go_demangler::decode_go_symbol(s, true).map(|g| g.demangled));
        println!("    simplify=false -> {:?}",
            rustre_demangle::go_demangler::decode_go_symbol(s, false).map(|g| g.demangled));
    }

    println!("\n== Swift ==");
    for s in [
        "_TF4main3fooFT_T_",
        "_TFC4main3Foo3barfT_T_",
        "$s10Foundation4DataV5countSivg",
        "$s4main3fooyyF",
    ] {
        println!("  {s} -> {:?}", rustre_demangle::demangle(s).map(|r| r.demangled));
    }
}
