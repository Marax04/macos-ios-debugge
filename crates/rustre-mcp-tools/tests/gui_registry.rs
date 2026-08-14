//! Tests for `rustre_mcp_tools::tool_registry` — **the registry the GUI ships**.
//!
//! Why this file exists (pass 5 of the crate review, 2026-07-29):
//!
//! `ToolRegistry` is defined TWICE in this crate — once in `lib.rs` and once in
//! `tool_registry.rs`. `tests/blitz.rs` does `use rustre_mcp_tools::*`, and a
//! locally-defined item always beats a glob import in Rust name resolution, so
//! its three `tool_registry_*` tests exercise the **`lib.rs`** type while
//! carrying the other module's name.
//!
//! The uncovered twin is the one in production: `rustre-gui` calls
//! `tool_registry::{ToolRegistry, register_builtin_tools}` from
//! `src/ui/panels/mcp_panel.rs:22` and `src/ui/app.rs:1104`, and `rustre-gui`
//! has no tests directory at all. So the tested copy was the one nobody ships
//! and the shipped copy was the one nobody tested.
//!
//! Everything here imports by **full path**, so there is no ambiguity about
//! which type is under test.

use rustre_mcp_tools::tool_registry::{ToolCategory, ToolDescriptor, ToolRegistry,
                                      register_builtin_tools};

fn descriptor(name: &str, category: ToolCategory) -> ToolDescriptor {
    ToolDescriptor::new(name, "test descriptor", category)
}

/// The GUI's own entry point must actually populate the registry.
///
/// `register_builtin_tools` is called on every GUI start and no test ever
/// exercised it. A registry that silently stayed empty would leave the MCP
/// panel blank with nothing failing anywhere.
#[test]
fn register_builtin_tools_populates_the_registry() {
    let mut r = ToolRegistry::new();
    assert_eq!(r.all_descriptors().len(), 0, "a fresh registry is empty");

    register_builtin_tools(&mut r);

    let all = r.all_descriptors();
    assert!(
        all.len() >= 8,
        "the builtin set should register several tools, got {}",
        all.len()
    );
    for d in &all {
        assert!(!d.name.trim().is_empty(), "a builtin tool has an empty name");
        assert!(
            !d.description.trim().is_empty(),
            "tool '{}' has no description — a model choosing tools cannot use it",
            d.name
        );
    }

    // Names must be unique: the registry is a map from name to behaviour.
    let mut names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), before, "builtin tool names must be unique");
}

/// Re-registering a tool must UPDATE it, not accumulate index entries.
///
/// This is the defect this file was written to catch. `register` pushed the
/// tool's name into `tags_index` unconditionally, so registering the same tool
/// twice — which the GUI does whenever it rebuilds its panel — made `by_tag`
/// return the same descriptor twice. `by_category` filters the descriptor map
/// directly and so never showed the fault, which is why it stayed invisible.
#[test]
fn re_registering_does_not_duplicate_index_entries() {
    let mut r = ToolRegistry::new();

    let first = descriptor("dup_probe", ToolCategory::Analysis).tag("probe");
    assert!(r.register(first), "first registration is new");

    let second = descriptor("dup_probe", ToolCategory::Analysis).tag("probe");
    assert!(
        !r.register(second),
        "re-registering an existing name reports 'not new'"
    );

    assert_eq!(
        r.all_descriptors().len(),
        1,
        "the descriptor map must hold one entry"
    );
    assert_eq!(
        r.by_tag("probe").len(),
        1,
        "by_tag must not return the same tool twice after re-registration"
    );
}

/// An update that CHANGES the tags must not leave the old tag behind.
///
/// The same unconditional-push bug also meant a tool kept answering to tags it
/// no longer carried. Fixing the duplication without fixing this would swap one
/// wrong answer for another.
#[test]
fn re_registering_with_new_tags_drops_the_old_ones() {
    let mut r = ToolRegistry::new();
    r.register(descriptor("retag", ToolCategory::Analysis).tag("old"));
    r.register(descriptor("retag", ToolCategory::Analysis).tag("new"));

    assert_eq!(
        r.by_tag("new").len(),
        1,
        "the tool must be findable under its current tag"
    );
    assert!(
        r.by_tag("old").is_empty(),
        "a tag the tool no longer carries must not still find it"
    );
}

/// `get` / `contains` must distinguish a registered tool from an absent one.
#[test]
fn lookup_reports_absence_rather_than_guessing() {
    let mut r = ToolRegistry::new();
    r.register(descriptor("present", ToolCategory::Analysis));

    assert!(r.contains("present"));
    assert!(r.get("present").is_some());
    assert!(
        !r.contains("never_registered"),
        "an unregistered name must not be reported as present"
    );
    assert!(
        r.get("never_registered").is_none(),
        "lookup of an unknown tool must return None, not a placeholder"
    );
}

/// Disabling removes a tool from `available_tools` without deleting it.
#[test]
fn disable_hides_from_available_but_keeps_the_descriptor() {
    let mut r = ToolRegistry::new();
    r.register(descriptor("toggle", ToolCategory::Analysis));
    assert_eq!(r.available_tools().len(), 1);

    assert!(r.disable("toggle"), "disabling a known tool succeeds");
    assert!(
        r.available_tools().is_empty(),
        "a disabled tool is not available"
    );
    assert!(
        r.get("toggle").is_some(),
        "disabling must not remove the descriptor"
    );

    assert!(r.enable("toggle"));
    assert_eq!(r.available_tools().len(), 1, "re-enabling restores it");

    assert!(
        !r.disable("never_registered"),
        "disabling an unknown tool must report failure, not silently succeed"
    );
}
