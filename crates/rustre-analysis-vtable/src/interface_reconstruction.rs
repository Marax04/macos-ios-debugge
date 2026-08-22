//! `interface_reconstruction` — final stage of the vtable pipeline:
//! vtable → method demangling → reconstructed C++ interface.
//!
//! Takes a recovered [`Vtable`] (optionally with linked [`RttiInfo`]) and
//! produces a [`ReconstructedInterface`]: a class declaration with per-slot
//! method entries, each classified (constructor / destructor / pure-virtual /
//! operator / plain method), demangled via the crate demangler, and attributed
//! to the class that declared it (own vs. inherited-and-not-overridden).
//!
//! The reconstruction can be rendered back to compilable-looking C++ with
//! [`ReconstructedInterface::to_cpp_decl`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::demangler::{demangle, is_itanium_mangled, is_msvc_mangled};
use crate::{RttiInfo, Vtable, VtableDatabase};

// ─────────────────────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a virtual method slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// A constructor (rare in vtables, but present in some ABI thunk tables).
    Constructor,
    /// A (possibly deleting) destructor.
    Destructor,
    /// A pure-virtual stub (`__cxa_pure_virtual` / `_purecall`).
    PureVirtual,
    /// An overloaded operator (`operator==`, `operator[]`, …).
    Operator,
    /// An ordinary virtual method.
    Method,
    /// Slot with no name information at all.
    Unknown,
}

/// One reconstructed virtual method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedMethod {
    /// 0-based slot index in the vtable.
    pub slot: usize,
    /// Target function address.
    pub address: u64,
    /// The raw (possibly mangled) symbol name, if any.
    pub raw_name: Option<String>,
    /// Demangled name (equals `raw_name` when it was not mangled).
    pub demangled: Option<String>,
    /// The unqualified method name (`draw`, `~Shape`, `operator==`, …).
    pub method_name: String,
    /// The class that the symbol says declared/defined this method, if
    /// recoverable from a qualified demangled name (`Shape` in `Shape::draw`).
    pub owner_class: Option<String>,
    /// Classification of the slot.
    pub kind: MethodKind,
}

impl ReconstructedMethod {
    /// True if this slot is implemented by a base class (symbol owner differs
    /// from `class_name`) — i.e. inherited and not overridden.
    #[must_use]
    pub fn is_inherited_in(&self, class_name: &str) -> bool {
        match &self.owner_class {
            Some(owner) => owner != class_name,
            None => false,
        }
    }
}

/// A reconstructed C++ interface (class shape as seen through its vtable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedInterface {
    /// Class name (from RTTI, or a synthesized `class_ADDR` placeholder).
    pub class_name: String,
    /// Vtable base address.
    pub vtable_address: u64,
    /// Direct base classes from RTTI (empty when unknown).
    pub base_classes: Vec<String>,
    /// Methods, one per vtable slot, in slot order.
    pub methods: Vec<ReconstructedMethod>,
    /// Whether at least one slot is pure-virtual.
    pub is_abstract: bool,
}

impl ReconstructedInterface {
    /// Methods declared (or overridden) by this class itself.
    #[must_use]
    pub fn own_methods(&self) -> Vec<&ReconstructedMethod> {
        self.methods
            .iter()
            .filter(|m| !m.is_inherited_in(&self.class_name))
            .collect()
    }

    /// Methods inherited from a base class and not overridden.
    #[must_use]
    pub fn inherited_methods(&self) -> Vec<&ReconstructedMethod> {
        self.methods
            .iter()
            .filter(|m| m.is_inherited_in(&self.class_name))
            .collect()
    }

    /// Render the interface as a C++ class declaration.
    #[must_use]
    pub fn to_cpp_decl(&self) -> String {
        let mut out = String::new();
        out.push_str("class ");
        out.push_str(&self.class_name);
        if !self.base_classes.is_empty() {
            out.push_str(" : ");
            let bases: Vec<String> = self
                .base_classes
                .iter()
                .map(|b| format!("public {b}"))
                .collect();
            out.push_str(&bases.join(", "));
        }
        out.push_str(" {\npublic:\n");
        for m in &self.methods {
            let decl = match m.kind {
                MethodKind::Destructor => format!("virtual ~{}();", self.class_name),
                MethodKind::PureVirtual => {
                    format!("virtual void {}() = 0;", slot_name(m))
                }
                MethodKind::Constructor => format!("{}();", self.class_name),
                MethodKind::Operator | MethodKind::Method => {
                    format!("virtual void {}();", slot_name(m))
                }
                MethodKind::Unknown => format!("virtual void {}();", slot_name(m)),
            };
            let inherited = if m.is_inherited_in(&self.class_name) {
                format!("  // inherited from {}", m.owner_class.as_deref().unwrap_or("?"))
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    {decl}  // slot {} @ {:#x}{inherited}\n",
                m.slot, m.address
            ));
        }
        out.push_str("};\n");
        out
    }
}

/// Unqualified, C++-identifier-safe name for a slot.
fn slot_name(m: &ReconstructedMethod) -> String {
    if m.method_name.is_empty() || m.method_name.starts_with('~') {
        format!("slot_{}", m.slot)
    } else {
        m.method_name.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Names of pure-virtual call stubs.
const PURE_STUB_NAMES: &[&str] = &[
    "__cxa_pure_virtual",
    "___cxa_pure_virtual",
    "_purecall",
    "__purecall",
    "__pure_virtual",
];

/// Reconstructs C++ interfaces from recovered vtables.
#[derive(Debug, Clone, Default)]
pub struct InterfaceReconstructor {
    /// Function addresses known to be pure-virtual stubs.
    pure_stub_addresses: HashSet<u64>,
}

impl InterfaceReconstructor {
    /// Create a new reconstructor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pure-virtual stub address (e.g., resolved `_purecall`).
    pub fn add_pure_stub(&mut self, addr: u64) {
        self.pure_stub_addresses.insert(addr);
    }

    /// Reconstruct the interface of a single vtable.
    ///
    /// `rtti` supplies the class name and base classes when available.
    #[must_use]
    pub fn reconstruct(&self, vtable: &Vtable, rtti: Option<&RttiInfo>) -> ReconstructedInterface {
        let class_name = vtable
            .class_name
            .clone()
            .or_else(|| rtti.map(|r| r.type_name.clone()))
            .unwrap_or_else(|| format!("class_{:x}", vtable.base_address));
        let base_classes = rtti.map(|r| r.base_classes.clone()).unwrap_or_default();

        let methods: Vec<ReconstructedMethod> = vtable
            .entries
            .iter()
            .enumerate()
            .map(|(slot, e)| self.reconstruct_method(slot, e.target_address, e.function_name.as_deref()))
            .collect();

        let is_abstract = methods.iter().any(|m| m.kind == MethodKind::PureVirtual);

        ReconstructedInterface {
            class_name,
            vtable_address: vtable.base_address,
            base_classes,
            methods,
            is_abstract,
        }
    }

    /// Reconstruct interfaces for every vtable in a database, linking RTTI.
    #[must_use]
    pub fn reconstruct_all(&self, db: &VtableDatabase) -> Vec<ReconstructedInterface> {
        let mut out: Vec<ReconstructedInterface> = db
            .vtables
            .values()
            .map(|vt| self.reconstruct(vt, db.rtti_for_vtable(vt.base_address)))
            .collect();
        out.sort_by_key(|i| i.vtable_address);
        out
    }

    fn reconstruct_method(
        &self,
        slot: usize,
        address: u64,
        raw_name: Option<&str>,
    ) -> ReconstructedMethod {
        let raw = raw_name.map(str::to_owned);

        // Pure-virtual detection by address first, then by name.
        let is_pure_addr = self.pure_stub_addresses.contains(&address);
        let is_pure_name = raw
            .as_deref()
            .is_some_and(|n| PURE_STUB_NAMES.contains(&n));

        let demangled = raw.as_deref().map(|n| {
            if is_itanium_mangled(n) || is_msvc_mangled(n) {
                demangle(n)
            } else {
                n.to_owned()
            }
        });

        let (method_name, owner_class) = demangled
            .as_deref().map_or_else(|| (format!("slot_{slot}"), None), split_qualified);

        let kind = if is_pure_addr || is_pure_name {
            MethodKind::PureVirtual
        } else if raw.is_none() {
            MethodKind::Unknown
        } else {
            classify(&method_name, raw.as_deref().unwrap_or(""))
        };

        ReconstructedMethod {
            slot,
            address,
            raw_name: raw,
            demangled,
            method_name,
            owner_class,
            kind,
        }
    }
}

/// Split a demangled qualified name into (unqualified name, owner class).
///
/// `"Shape::draw()"` → (`"draw"`, `Some("Shape")`);
/// `"Ns::Shape::~Shape()"` → (`"~Shape"`, `Some("Ns::Shape")`);
/// `"free_func"` → (`"free_func"`, `None`).
fn split_qualified(demangled: &str) -> (String, Option<String>) {
    // Strip the argument list (first '(' to the end) before splitting so we
    // don't split on "::" inside parameter types.
    let head = demangled.split('(').next().unwrap_or(demangled).trim();
    match head.rfind("::") {
        Some(pos) => {
            let owner = head[..pos].to_owned();
            let name = head[pos + 2..].to_owned();
            if owner.is_empty() || name.is_empty() {
                (head.to_owned(), None)
            } else {
                (name, Some(owner))
            }
        }
        None => (head.to_owned(), None),
    }
}

/// Classify a slot from the unqualified method name and raw symbol.
fn classify(method_name: &str, raw: &str) -> MethodKind {
    if method_name.starts_with('~') || raw.starts_with("??1") || itanium_is_dtor(raw) {
        MethodKind::Destructor
    } else if raw.starts_with("??0") || itanium_is_ctor(raw) {
        MethodKind::Constructor
    } else if method_name.starts_with("operator") {
        MethodKind::Operator
    } else {
        MethodKind::Method
    }
}

/// Itanium: destructor encodings are `D0`/`D1`/`D2` inside a nested name.
fn itanium_is_dtor(raw: &str) -> bool {
    raw.starts_with("_ZN") && (raw.contains("D0E") || raw.contains("D1E") || raw.contains("D2E"))
}

/// Itanium: constructor encodings are `C1`/`C2`/`C3` inside a nested name.
fn itanium_is_ctor(raw: &str) -> bool {
    raw.starts_with("_ZN") && (raw.contains("C1E") || raw.contains("C2E"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RttiAbi, VtableEntry};

    fn vtable_with(entries: Vec<VtableEntry>, class: Option<&str>) -> Vtable {
        let mut vt = Vtable::new(0x4000);
        vt.class_name = class.map(str::to_owned);
        for e in entries {
            vt.add_entry(e);
        }
        vt
    }

    #[test]
    fn split_qualified_basic() {
        assert_eq!(
            split_qualified("Shape::draw()"),
            ("draw".into(), Some("Shape".into()))
        );
    }

    #[test]
    fn split_qualified_nested_namespace() {
        assert_eq!(
            split_qualified("Ns::Shape::~Shape()"),
            ("~Shape".into(), Some("Ns::Shape".into()))
        );
    }

    #[test]
    fn split_qualified_free_function() {
        assert_eq!(split_qualified("free_func"), ("free_func".into(), None));
    }

    #[test]
    fn split_qualified_ignores_args_with_colons() {
        assert_eq!(
            split_qualified("Shape::set(std::string const&)"),
            ("set".into(), Some("Shape".into()))
        );
    }

    #[test]
    fn classify_destructor_msvc() {
        assert_eq!(classify("~Shape", "??1Shape@@UEAA@XZ"), MethodKind::Destructor);
    }

    #[test]
    fn classify_destructor_itanium_raw() {
        assert_eq!(classify("x", "_ZN5ShapeD1Ev"), MethodKind::Destructor);
    }

    #[test]
    fn classify_constructor_itanium_raw() {
        assert_eq!(classify("Shape", "_ZN5ShapeC1Ev"), MethodKind::Constructor);
    }

    #[test]
    fn classify_operator() {
        assert_eq!(classify("operator==", "sym"), MethodKind::Operator);
    }

    #[test]
    fn classify_plain_method() {
        assert_eq!(classify("draw", "_ZN5Shape4drawEv"), MethodKind::Method);
    }

    #[test]
    fn reconstruct_named_vtable() {
        let vt = vtable_with(
            vec![
                VtableEntry::with_name(0, 0x1000, "_ZN5ShapeD1Ev"),
                VtableEntry::with_name(8, 0x1010, "_ZN5Shape4drawEv"),
                VtableEntry::new(16, 0x1020),
            ],
            Some("Shape"),
        );
        let iface = InterfaceReconstructor::new().reconstruct(&vt, None);
        assert_eq!(iface.class_name, "Shape");
        assert_eq!(iface.methods.len(), 3);
        assert_eq!(iface.methods[0].kind, MethodKind::Destructor);
        assert_eq!(iface.methods[1].kind, MethodKind::Method);
        assert_eq!(iface.methods[1].method_name, "draw");
        assert_eq!(iface.methods[1].owner_class.as_deref(), Some("Shape"));
        assert_eq!(iface.methods[2].kind, MethodKind::Unknown);
        assert!(!iface.is_abstract);
    }

    #[test]
    fn reconstruct_pure_virtual_by_name_and_address() {
        let mut rec = InterfaceReconstructor::new();
        rec.add_pure_stub(0x2000);
        let vt = vtable_with(
            vec![
                VtableEntry::with_name(0, 0x1000, "__cxa_pure_virtual"),
                VtableEntry::new(8, 0x2000), // unnamed, but known stub address
            ],
            Some("IFace"),
        );
        let iface = rec.reconstruct(&vt, None);
        assert_eq!(iface.methods[0].kind, MethodKind::PureVirtual);
        assert_eq!(iface.methods[1].kind, MethodKind::PureVirtual);
        assert!(iface.is_abstract);
    }

    #[test]
    fn reconstruct_uses_rtti_name_and_bases() {
        let vt = vtable_with(vec![VtableEntry::new(0, 0x1000)], None);
        let rtti = RttiInfo {
            type_name: "Circle".into(),
            base_classes: vec!["Shape".into()],
            rtti_address: 0x9000,
            abi: RttiAbi::Itanium,
        };
        let iface = InterfaceReconstructor::new().reconstruct(&vt, Some(&rtti));
        assert_eq!(iface.class_name, "Circle");
        assert_eq!(iface.base_classes, vec!["Shape".to_string()]);
    }

    #[test]
    fn reconstruct_placeholder_class_name() {
        let vt = vtable_with(vec![VtableEntry::new(0, 0x1000)], None);
        let iface = InterfaceReconstructor::new().reconstruct(&vt, None);
        assert_eq!(iface.class_name, "class_4000");
    }

    #[test]
    fn inherited_vs_own_methods() {
        let vt = vtable_with(
            vec![
                VtableEntry::with_name(0, 0x1000, "_ZN6Circle4drawEv"),
                VtableEntry::with_name(8, 0x1010, "_ZN5Shape4areaEv"),
            ],
            Some("Circle"),
        );
        let iface = InterfaceReconstructor::new().reconstruct(&vt, None);
        // draw is Circle's own; area is inherited from Shape.
        let own = iface.own_methods();
        let inherited = iface.inherited_methods();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].method_name, "draw");
        assert_eq!(inherited.len(), 1);
        assert_eq!(inherited[0].owner_class.as_deref(), Some("Shape"));
    }

    #[test]
    fn cpp_decl_rendering() {
        let vt = vtable_with(
            vec![
                VtableEntry::with_name(0, 0x1000, "_ZN5ShapeD1Ev"),
                VtableEntry::with_name(8, 0x1010, "__cxa_pure_virtual"),
                VtableEntry::with_name(16, 0x1020, "_ZN5Shape4drawEv"),
            ],
            Some("Shape"),
        );
        let rtti = RttiInfo {
            type_name: "Shape".into(),
            base_classes: vec!["Object".into()],
            rtti_address: 0x9000,
            abi: RttiAbi::Itanium,
        };
        let decl = InterfaceReconstructor::new()
            .reconstruct(&vt, Some(&rtti))
            .to_cpp_decl();
        assert!(decl.contains("class Shape : public Object {"), "{decl}");
        assert!(decl.contains("virtual ~Shape();"), "{decl}");
        assert!(decl.contains("= 0;"), "{decl}");
        assert!(decl.contains("virtual void draw();"), "{decl}");
        assert!(decl.ends_with("};\n"), "{decl}");
    }

    #[test]
    fn reconstruct_all_links_rtti_and_sorts() {
        let mut db = VtableDatabase::new();
        let mut vt1 = Vtable::new(0x5000);
        vt1.add_entry(VtableEntry::new(0, 0x1000));
        let mut vt2 = Vtable::new(0x4000);
        vt2.add_entry(VtableEntry::new(0, 0x1010));
        db.add_vtable(vt1);
        db.add_vtable(vt2);
        db.add_rtti(RttiInfo {
            type_name: "Widget".into(),
            base_classes: vec![],
            rtti_address: 0x9000,
            abi: RttiAbi::Msvc,
        });
        db.link_vtable_rtti(0x4000, 0x9000);
        let ifaces = InterfaceReconstructor::new().reconstruct_all(&db);
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].vtable_address, 0x4000);
        assert_eq!(ifaces[0].class_name, "Widget");
        assert_eq!(ifaces[1].vtable_address, 0x5000);
    }

    #[test]
    fn msvc_named_slot_demangles() {
        let vt = vtable_with(
            vec![
                VtableEntry::with_name(0, 0x1000, "??1Widget@@UEAA@XZ"),
                VtableEntry::with_name(8, 0x1010, "plain_name"),
            ],
            Some("Widget"),
        );
        let iface = InterfaceReconstructor::new().reconstruct(&vt, None);
        assert_eq!(iface.methods[0].kind, MethodKind::Destructor);
        // Plain (unmangled) names pass through untouched.
        assert_eq!(iface.methods[1].demangled.as_deref(), Some("plain_name"));
        assert_eq!(iface.methods[1].kind, MethodKind::Method);
    }
}
