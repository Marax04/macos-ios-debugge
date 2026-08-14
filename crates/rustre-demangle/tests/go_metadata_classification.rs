//! Go linker-metadata section markers classify as `LinkerArtifact`.
//!
//! The `go:` and `type:` namespaces are compiler/linker-internal, and both are
//! explicit entries in `decline.rs`'s `ARTIFACT_PREFIXES`. The section-boundary
//! markers in those namespaces — `go:buildid`, the FIPS `go:*fipsstart/end`
//! pair, the bare wildcard `type:*` — do not decode and must land in
//! `LinkerArtifact`, not `Unknown`.
//!
//! The distinction matters because these are one artifact-rule edit away from
//! `Unknown`: they match no other benign rule (they are not leading-dot
//! sections, not `__x__` forms, not C identifiers — they carry a `:`), so if
//! `go:`/`type:` were ever removed from `ARTIFACT_PREFIXES` they would fall
//! straight through to the defect bucket. The whole-corpus census
//! (`decline_census.rs`) would catch that, but only with a generic "something
//! is Unknown" message; this test names the shape and the reason, so the
//! failure points at the Go metadata rule directly.
//!
//! The name-bearing forms in these namespaces (`go:itab.…`, `type:.eq.…`) are
//! deliberately NOT asserted here: they decode — the itab forms echo, the type
//! descriptors rewrite to `type descriptor for …` — and whether an echo of a
//! compiler-internal itab should count as a decode or an artifact is a
//! no-oracle judgment call left as-is. This test pins only the unambiguous
//! section markers.

use rustre_demangle::decline::{decline_reason, DeclineReason};

#[test]
fn go_section_markers_are_linker_artifacts() {
    let markers = [
        "go:buildid",
        "go:buildinfo",
        "go:fipsinfo",
        "go:datafipsstart",
        "go:datafipsend",
        "go:noptrdatafipsstart",
        "go:noptrdatafipsend",
        "go:rodatafipsstart",
        "go:rodatafipsend",
        "go:textfipsstart",
        "go:textfipsend",
        "type:*",
    ];
    for s in markers {
        assert!(
            rustre_demangle::demangle(s).is_none(),
            "{s} is a section marker with no demangling and must not decode"
        );
        assert_eq!(
            decline_reason(s),
            DeclineReason::LinkerArtifact,
            "{s} must classify as LinkerArtifact, not fall through to Unknown"
        );
    }
}
