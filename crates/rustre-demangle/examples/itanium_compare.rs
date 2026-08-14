//! Compare the three Itanium implementations against `cpp_demangle` (the
//! reference) to decide which should become the single engine.

fn reference(sym: &str) -> Option<String> {
    let s = cpp_demangle::BorrowedSymbol::new(sym.as_bytes()).ok()?;
    s.demangle(&cpp_demangle::DemangleOptions::default()).ok()
}

const CORPUS: &[&str] = &[
    "_Z3fooi",
    "_Z3foov",
    "_Z3barPKc",
    "_Z3addii",
    "_ZN3foo3barEv",
    "_ZN2ns5funcsEid",
    "_ZN9wikipedia7article6formatEv",
    "_ZNSt6vectorIiSaIiEE9push_backERKi",
    "_ZNSt12basic_stringIcSt11char_traitsIcESaIcEE5clearEv",
    "_ZNSaIcEC1Ev",
    "_ZNSs4sizeEv",
    "_ZN4Test1fEv",
    "_ZNK4Test1fEv",
    "_ZN4TestC1Ev",
    "_ZN4TestD1Ev",
    "_ZTV6Widget",
    "_ZTI6Widget",
    "_ZTS6Widget",
    "_Z1fPFivE",
    "_Z1fA37_iPS_",
    "_ZL9static_fnv",
    "_Z4funcIiEvT_",
    "_ZplRK1XS1_",
    "_ZN1N1TIiiE2mfES0_IddE",
    "_Z1fIiEvRAszplcvT__ELi1E_c",
    "_ZNK1C1fIiEEvv",
    "_Z3fooIiiEvT_T0_",
    "_ZSt4moveIRPcENSt16remove_referenceIT_E4typeEOS3_",
];

fn score(name: &str, f: impl Fn(&str) -> Option<String>) {
    let mut exact = 0usize;
    let mut differs = 0usize;
    let mut none = 0usize;
    let mut diffs = Vec::new();
    for sym in CORPUS {
        let want = reference(sym);
        let got = f(sym);
        match (&want, &got) {
            (Some(w), Some(g)) if w == g => exact += 1,
            (Some(w), Some(g)) => {
                differs += 1;
                diffs.push(format!("    {sym}\n      ref: {w}\n      got: {g}"));
            }
            (Some(w), None) => {
                none += 1;
                diffs.push(format!("    {sym}\n      ref: {w}\n      got: <None>"));
            }
            (None, _) => exact += 1, // reference itself rejects: not counted against
        }
    }
    println!("{name}: exact={exact} differs={differs} none={none} / {}", CORPUS.len());
    for d in diffs.iter().take(6) {
        println!("{d}");
    }
    if diffs.len() > 6 {
        println!("    … and {} more", diffs.len() - 6);
    }
    println!();
}

fn main() {
    score("backends (cpp_demangle wrapper)", |s| {
        rustre_demangle::demangle(s).map(|r| r.demangled)
    });
    score("cpp_demangler::demangle_itanium", |s| {
        rustre_demangle::cpp_demangler::demangle_itanium(s).ok()
    });
    score("itanium_full", |s| {
        rustre_demangle::itanium_full::demangle_itanium(s)
    });
    score("itanium_native (crate root)", |s| {
        rustre_demangle::ItaniumNativeDemangler::demangle(s)
    });
}
