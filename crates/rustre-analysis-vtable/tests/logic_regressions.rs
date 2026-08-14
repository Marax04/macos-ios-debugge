//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_vtable::rtti_parser::{MemRegion, RttiParser, RttiParserConfig};

/// A tiny synthetic 32-bit MSVC RTTI image.
///
/// Layout (all VAs absolute, since 32-bit RTTI references are absolute):
///   0x1000 COL      : sig=0, vtable_offset=0, cd_offset=0, td=0x2000, ch=0x3000
///   0x2000 TypeDesc : vftable ptr, spare ptr, then the decorated name at +8
///   0x3000 Hierarchy: sig=0, attributes=0, num_bases=1, array=0x4000
///   0x4000 BaseArray: [0x5000]
///   0x5000 BCD      : td=0x2000, contained=0, mdisp=8, pdisp=-1, vdisp=0, attr=0
const BASE: u64 = 0x1000;
const COL_VA: u64 = 0x1000;
const TD_VA: u64 = 0x2000;
const NAME: &[u8] = b".?AVFoo@@\0";

fn image() -> Vec<u8> {
    let mut d = vec![0u8; 0x5000];
    let put32 = |d: &mut Vec<u8>, va: u64, v: u32| {
        let off = (va - BASE) as usize;
        d[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };

    // COL
    put32(&mut d, 0x1000, 0); // signature 0 → 32-bit
    put32(&mut d, 0x1004, 0); // vtable offset
    put32(&mut d, 0x1008, 0); // cd offset
    put32(&mut d, 0x100C, 0x2000); // type descriptor
    put32(&mut d, 0x1010, 0x3000); // class hierarchy

    // TypeDescriptor: name lives at td + 2 * ptr_size = 0x2000 + 8.
    let name_off = (TD_VA + 8 - BASE) as usize;
    d[name_off..name_off + NAME.len()].copy_from_slice(NAME);

    // Class hierarchy descriptor
    put32(&mut d, 0x3000, 0); // signature
    put32(&mut d, 0x3004, 0); // attributes
    put32(&mut d, 0x3008, 1); // num base classes
    put32(&mut d, 0x300C, 0x4000); // base class array

    // Base class array: one entry
    put32(&mut d, 0x4000, 0x5000);

    // Base class descriptor at 0x5000
    put32(&mut d, 0x5000, 0x2000); // type descriptor of the base
    put32(&mut d, 0x5004, 0); // num contained bases
    put32(&mut d, 0x5008, 8); // mdisp
    put32(&mut d, 0x500C, u32::MAX); // pdisp = -1 (non-virtual)
    put32(&mut d, 0x5010, 0); // vdisp
    put32(&mut d, 0x5014, 0); // attributes
    d
}

fn parser() -> RttiParser {
    let mut p = RttiParser::with_config(RttiParserConfig {
        ptr_size: 4,
        image_base: BASE,
        max_recursion: 8,
    });
    p.add_region(MemRegion::new(BASE, image()));
    p
}

/// The decorated name sits at `td_va + 2 * ptr_size`, exactly as the comment
/// above the code says. Writing `(td_va + 2) * ptr_size` multiplies the whole
/// address instead, so the read lands far outside the image and the class name
/// — and with it every base class — is lost.
#[test]
fn type_descriptor_name_offset_is_not_multiplied() {
    let mut p = parser();
    let rtti = p
        .parse_msvc_col(COL_VA)
        .expect("a well-formed 32-bit COL must parse");

    assert!(
        rtti.type_descriptor.raw_name.contains("Foo"),
        "decorated name should have been read from td + 2*ptr_size, got {:?}",
        rtti.type_descriptor.raw_name
    );
}

/// The same precedence mistake is repeated inside the base-class descriptor
/// parser, so a class with one base came back with none.
#[test]
fn base_classes_survive_the_name_lookup() {
    let mut p = parser();
    let rtti = p
        .parse_msvc_col(COL_VA)
        .expect("a well-formed 32-bit COL must parse");

    assert_eq!(
        rtti.hierarchy.num_base_classes, 1,
        "the hierarchy descriptor declares one base"
    );
    assert_eq!(
        rtti.hierarchy.base_classes.len(),
        1,
        "the declared base must actually be recovered, not silently dropped"
    );
}

// ── build_dispatch_table: slot indexing ────────────────────────────────────

use rustre_analysis_vtable::hierarchy::{
    build_dispatch_table, ClassNode, InheritanceGraph,
};
use rustre_analysis_vtable::{Vtable, VtableDatabase, VtableEntry};

/// Slot index is the position in the entry list, exactly as
/// `resolve_virtual_dispatch` treats it (`vtable.entries.get(slot_index)`).
/// Deriving it as `offset / 8` hardcodes a 64-bit pointer, so on a 32-bit
/// image (4-byte slots) two adjacent methods collapse into one slot and a
/// third disappears — the dispatch table silently mixes unrelated methods.
#[test]
fn dispatch_slots_are_entry_indices_not_byte_offsets_over_eight() {
    // A 32-bit vtable: 4-byte slots.
    let vt = Vtable {
        base_address: 0x9000,
        entries: vec![
            VtableEntry::new(0, 0x1000),
            VtableEntry::new(4, 0x2000),
            VtableEntry::new(8, 0x3000),
        ],
        class_name: Some("Foo".to_string()),
        offset_to_top: None,
    };

    let mut db = VtableDatabase::default();
    db.vtables.insert(0x9000, vt);

    let mut graph = InheritanceGraph::new();
    graph.classes.insert(
        "Foo".to_string(),
        ClassNode {
            name: "Foo".to_string(),
            bases: vec![],
            derived: vec![],
            vtable_addresses: vec![0x9000],
            rtti_address: None,
            has_virtual_base: false,
            virtual_function_count: 3,
        },
    );

    let table = build_dispatch_table("Foo", &graph, &db);

    assert_eq!(
        table.len(),
        3,
        "three entries occupy three distinct slots, got {table:?}"
    );
    assert_eq!(table.get(&0).map(Vec::as_slice), Some(&[0x1000u64][..]));
    assert_eq!(table.get(&1).map(Vec::as_slice), Some(&[0x2000u64][..]));
    assert_eq!(table.get(&2).map(Vec::as_slice), Some(&[0x3000u64][..]));
}

/// A 64-bit vtable must keep working — the fix must not merely swap one
/// hardcoded pointer size for another.
#[test]
fn dispatch_slots_are_correct_for_eight_byte_vtables_too() {
    let vt = Vtable {
        base_address: 0xA000,
        entries: vec![
            VtableEntry::new(0, 0x1000),
            VtableEntry::new(8, 0x2000),
        ],
        class_name: Some("Bar".to_string()),
        offset_to_top: None,
    };

    let mut db = VtableDatabase::default();
    db.vtables.insert(0xA000, vt);

    let mut graph = InheritanceGraph::new();
    graph.classes.insert(
        "Bar".to_string(),
        ClassNode {
            name: "Bar".to_string(),
            bases: vec![],
            derived: vec![],
            vtable_addresses: vec![0xA000],
            rtti_address: None,
            has_virtual_base: false,
            virtual_function_count: 2,
        },
    );

    let table = build_dispatch_table("Bar", &graph, &db);
    assert_eq!(table.get(&0).map(Vec::as_slice), Some(&[0x1000u64][..]));
    assert_eq!(table.get(&1).map(Vec::as_slice), Some(&[0x2000u64][..]));
}

// ── InheritanceGrapher::dfs ────────────────────────────────────────────────

use petgraph::Direction;
use rustre_analysis_vtable::inheritance_grapher::InheritanceGrapher;
use rustre_analysis_vtable::{RttiAbi, RttiInfo};

fn rtti(name: &str, bases: &[&str], addr: u64) -> RttiInfo {
    RttiInfo {
        type_name: name.to_string(),
        base_classes: bases.iter().map(|s| (*s).to_string()).collect(),
        rtti_address: addr,
        abi: RttiAbi::Itanium,
    }
}

/// Marking nodes visited at PUSH time is only sound for BFS, where first
/// discovery is also the shortest path. On a LIFO it emits siblings before
/// descending, so the sequence is neither DFS pre-order nor BFS.
///
/// A diamond makes the difference observable: from D, a real DFS must finish
/// one parent's subtree (reaching A) before emitting the other parent.
#[test]
fn dfs_completes_a_subtree_before_moving_to_the_sibling() {
    let mut g = InheritanceGrapher::new();
    // D : B, C ;  B : A ;  C : A     (Outgoing = derived → base)
    g.build_from_rtti(&[
        rtti("D", &["B", "C"], 0x10),
        rtti("B", &["A"], 0x20),
        rtti("C", &["A"], 0x30),
        rtti("A", &[], 0x40),
    ]);

    let d = g.find_node("D").expect("D present");
    let order: Vec<String> = g
        .dfs(d, Direction::Outgoing)
        .into_iter()
        .map(|n| g.node_weight(n).unwrap().name.clone())
        .collect();

    assert_eq!(order.len(), 3, "B, C and A must all be reached: {order:?}");

    // Whichever parent is explored first, A (its base) must be emitted before
    // the other parent — that is what "depth first" means.
    let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
    let (first_parent, second_parent) = if pos("B") < pos("C") {
        ("B", "C")
    } else {
        ("C", "B")
    };
    assert!(
        pos(first_parent) < pos("A") && pos("A") < pos(second_parent),
        "expected {first_parent} → A → {second_parent} (depth first), got {order:?}"
    );
}

/// A straight chain has only one possible order, and it must be that one.
#[test]
fn dfs_on_a_chain_follows_the_chain() {
    let mut g = InheritanceGrapher::new();
    g.build_from_rtti(&[
        rtti("C", &["B"], 0x10),
        rtti("B", &["A"], 0x20),
        rtti("A", &[], 0x30),
    ]);

    let c = g.find_node("C").unwrap();
    let order: Vec<String> = g
        .dfs(c, Direction::Outgoing)
        .into_iter()
        .map(|n| g.node_weight(n).unwrap().name.clone())
        .collect();
    assert_eq!(order, vec!["B".to_string(), "A".to_string()]);
}
