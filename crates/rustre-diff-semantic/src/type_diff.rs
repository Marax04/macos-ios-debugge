//! `type_diff` — Type-level diff for struct/union/enum/typedef changes.
//!
//! Computes the set of [`TypeChange`] operations needed to transform one
//! [`TypeDescriptor`] into another, then classifies each change as breaking or
//! non-breaking and produces a human-readable impact summary.

use std::collections::HashMap;
use std::fmt;

// ── TypeKind ──────────────────────────────────────────────────────────────────

/// The category of a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeKind {
    /// A `struct` — laid out sequentially.
    Struct,
    /// A `union` — all members at offset 0, size = largest member.
    Union,
    /// An enumeration.
    Enum,
    /// A typedef alias.
    Typedef,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Struct => write!(f, "struct"),
            Self::Union => write!(f, "union"),
            Self::Enum => write!(f, "enum"),
            Self::Typedef => write!(f, "typedef"),
        }
    }
}

// ── FieldDescriptor ───────────────────────────────────────────────────────────

/// Describes a single field within a struct, union, or enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    /// Field or variant name.
    pub name: String,
    /// Type name as a string, e.g. `"uint32_t"`, `"char *"`.
    pub type_name: String,
    /// Byte offset within the parent type (0 for union members and enum values).
    pub offset: u32,
    /// Size in bytes of this field.
    pub size: u32,
}

impl FieldDescriptor {
    /// Return the byte range `[offset, offset + size)`.
    #[must_use]
    pub const fn byte_range(&self) -> (u32, u32) {
        (self.offset, self.offset + self.size)
    }
}

// ── TypeDescriptor ────────────────────────────────────────────────────────────

/// A complete description of a named type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDescriptor {
    /// Type name.
    pub name: String,
    /// Category of this type.
    pub kind: TypeKind,
    /// Total size in bytes.
    pub size: u32,
    /// Ordered list of fields (or enum variants).
    pub fields: Vec<FieldDescriptor>,
    /// Associated method names (for struct-like types in C++ / Rust style).
    pub methods: Vec<String>,
}

impl TypeDescriptor {
    /// Look up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Return a `HashMap` from field name to descriptor for fast lookup.
    #[must_use]
    pub fn field_map(&self) -> HashMap<String, &FieldDescriptor> {
        self.fields.iter().map(|f| (f.name.clone(), f)).collect()
    }
}

// ── TypeChange ────────────────────────────────────────────────────────────────

/// A single atomic change between two versions of a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeChange {
    /// A new field was added at the given offset.
    FieldAdded {
        name: String,
        type_: String,
        offset: u32,
    },
    /// A field was removed from the type.
    FieldRemoved {
        name: String,
        type_: String,
        offset: u32,
    },
    /// A field was renamed (but its type and offset are unchanged).
    FieldRenamed {
        old_name: String,
        new_name: String,
    },
    /// A field's type string changed.
    FieldTypeChanged {
        name: String,
        old: String,
        new: String,
    },
    /// A field's byte offset changed (layout shift).
    FieldOffsetChanged {
        name: String,
        old: u32,
        new: u32,
    },
    /// The total size of the type changed.
    SizeChanged {
        old: u32,
        new: u32,
    },
    /// A new enum variant was added.
    EnumVariantAdded {
        name: String,
        value: i64,
    },
    /// An existing enum variant was removed.
    EnumVariantRemoved {
        name: String,
        value: i64,
    },
    /// A new method was added to the type.
    MethodAdded {
        name: String,
    },
    /// An existing method was removed from the type.
    MethodRemoved {
        name: String,
    },
}

impl TypeChange {
    /// Return `true` if this change is ABI/API breaking.
    #[must_use]
    pub const fn is_breaking(&self) -> bool {
        matches!(
            self,
            Self::FieldRemoved { .. }
                | Self::FieldTypeChanged { .. }
                | Self::FieldOffsetChanged { .. }
                | Self::SizeChanged { .. }
                | Self::EnumVariantRemoved { .. }
                | Self::MethodRemoved { .. }
        )
    }

    /// A short human-readable summary of the change.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::FieldAdded { name, type_, offset } => {
                format!("+ field `{name}: {type_}` at offset {offset}")
            }
            Self::FieldRemoved { name, type_, offset } => {
                format!("- field `{name}: {type_}` at offset {offset}")
            }
            Self::FieldRenamed { old_name, new_name } => {
                format!("~ field renamed `{old_name}` → `{new_name}`")
            }
            Self::FieldTypeChanged { name, old, new } => {
                format!("~ field `{name}` type changed: `{old}` → `{new}`")
            }
            Self::FieldOffsetChanged { name, old, new } => {
                format!("~ field `{name}` offset: {old} → {new}")
            }
            Self::SizeChanged { old, new } => {
                format!("~ size: {old} → {new} bytes")
            }
            Self::EnumVariantAdded { name, value } => {
                format!("+ enum variant `{name}` = {value}")
            }
            Self::EnumVariantRemoved { name, value } => {
                format!("- enum variant `{name}` = {value}")
            }
            Self::MethodAdded { name } => format!("+ method `{name}`"),
            Self::MethodRemoved { name } => format!("- method `{name}`"),
        }
    }
}

impl fmt::Display for TypeChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

// ── ImpactSummary ─────────────────────────────────────────────────────────────

/// Aggregated impact summary for a set of type changes.
#[derive(Debug, Clone, Default)]
pub struct ImpactSummary {
    /// Number of breaking changes.
    pub breaking: usize,
    /// Number of non-breaking changes.
    pub non_breaking: usize,
    /// Human-readable description of the most severe change.
    pub headline: String,
}

impl ImpactSummary {
    /// Return `true` if any breaking changes are present.
    #[must_use]
    pub const fn has_breaking_changes(&self) -> bool {
        self.breaking > 0
    }

    /// Total change count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.breaking + self.non_breaking
    }
}

// ── TypeDiff ──────────────────────────────────────────────────────────────────

/// Stateless type diffing engine.
#[derive(Debug, Clone, Default)]
pub struct TypeDiff;

impl TypeDiff {
    /// Create a new `TypeDiff`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the list of changes required to transform `old` into `new`.
    ///
    /// The algorithm:
    /// 1. Compare overall size.
    /// 2. For each field in `old`: check if it exists in `new` by name.
    ///    - If yes: check type and offset.
    ///    - If no: check if a field at the same offset with same type exists
    ///      (→ `FieldRenamed`), otherwise `FieldRemoved`.
    /// 3. Fields present in `new` but not `old` → `FieldAdded`.
    /// 4. For enum types: compare field names as variant names.
    /// 5. Compare method sets.
    #[must_use]
    pub fn diff_types(old: &TypeDescriptor, new: &TypeDescriptor) -> Vec<TypeChange> {
        let mut changes: Vec<TypeChange> = Vec::new();

        // Size change
        if old.size != new.size {
            changes.push(TypeChange::SizeChanged { old: old.size, new: new.size });
        }

        let old_field_map = old.field_map();
        let new_field_map = new.field_map();

        // Identify fields that exist in new but by different names at same type+offset
        // (used for rename detection)
        let mut rename_candidates: HashMap<(String, u32), &FieldDescriptor> = HashMap::new();
        for f in &new.fields {
            rename_candidates.insert((f.type_name.clone(), f.offset), f);
        }

        let mut renamed_new_fields: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Check old fields
        for old_field in &old.fields {
            if let Some(new_field) = new_field_map.get(&old_field.name) {
                // Same name — check type and offset
                if old_field.type_name != new_field.type_name {
                    changes.push(TypeChange::FieldTypeChanged {
                        name: old_field.name.clone(),
                        old: old_field.type_name.clone(),
                        new: new_field.type_name.clone(),
                    });
                }
                if old_field.offset != new_field.offset {
                    changes.push(TypeChange::FieldOffsetChanged {
                        name: old_field.name.clone(),
                        old: old_field.offset,
                        new: new_field.offset,
                    });
                }
            } else {
                // Field not found by name — look for a rename candidate
                let key = (old_field.type_name.clone(), old_field.offset);
                if let Some(candidate) = rename_candidates.get(&key)
                    && !old_field_map.contains_key(&candidate.name)
                {
                    // The candidate name doesn't exist in old → likely a rename
                    changes.push(TypeChange::FieldRenamed {
                        old_name: old_field.name.clone(),
                        new_name: candidate.name.clone(),
                    });
                    renamed_new_fields.insert(candidate.name.clone());
                    continue;
                }
                // Not renamed — removed
                changes.push(TypeChange::FieldRemoved {
                    name: old_field.name.clone(),
                    type_: old_field.type_name.clone(),
                    offset: old_field.offset,
                });
            }
        }

        // Check new fields that aren't in old (and weren't part of a rename)
        for new_field in &new.fields {
            if !old_field_map.contains_key(&new_field.name) && !renamed_new_fields.contains(&new_field.name) {
                changes.push(TypeChange::FieldAdded {
                    name: new_field.name.clone(),
                    type_: new_field.type_name.clone(),
                    offset: new_field.offset,
                });
            }
        }

        // Method changes
        let old_methods: std::collections::HashSet<&str> =
            old.methods.iter().map(String::as_str).collect();
        let new_methods: std::collections::HashSet<&str> =
            new.methods.iter().map(String::as_str).collect();
        for m in old_methods.difference(&new_methods) {
            changes.push(TypeChange::MethodRemoved { name: m.to_string() });
        }
        for m in new_methods.difference(&old_methods) {
            changes.push(TypeChange::MethodAdded { name: m.to_string() });
        }

        changes
    }

    /// Build an [`ImpactSummary`] for a slice of changes.
    #[must_use]
    pub fn summarize_impact(changes: &[TypeChange]) -> ImpactSummary {
        let mut summary = ImpactSummary::default();
        for change in changes {
            if change.is_breaking() {
                summary.breaking += 1;
            } else {
                summary.non_breaking += 1;
            }
        }
        summary.headline = if summary.breaking > 0 {
            format!(
                "{} breaking change(s), {} non-breaking change(s)",
                summary.breaking, summary.non_breaking
            )
        } else if summary.non_breaking > 0 {
            format!("{} non-breaking change(s)", summary.non_breaking)
        } else {
            "No changes".to_owned()
        };
        summary
    }

    /// Convenience: diff two types and immediately return an impact summary.
    #[must_use]
    pub fn impact(old: &TypeDescriptor, new: &TypeDescriptor) -> ImpactSummary {
        let changes = Self::diff_types(old, new);
        Self::summarize_impact(&changes)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_struct(name: &str, size: u32, fields: Vec<(&str, &str, u32, u32)>) -> TypeDescriptor {
        TypeDescriptor {
            name: name.to_owned(),
            kind: TypeKind::Struct,
            size,
            fields: fields
                .into_iter()
                .map(|(n, t, o, s)| FieldDescriptor {
                    name: n.to_owned(),
                    type_name: t.to_owned(),
                    offset: o,
                    size: s,
                })
                .collect(),
            methods: vec![],
        }
    }

    #[test]
    fn test_no_changes_identical_types() {
        let t = simple_struct("Foo", 8, vec![("x", "u32", 0, 4), ("y", "u32", 4, 4)]);
        let changes = TypeDiff::diff_types(&t, &t);
        assert!(changes.is_empty(), "identical types should produce no changes");
    }

    #[test]
    fn test_size_changed() {
        let old = simple_struct("Foo", 8, vec![("x", "u32", 0, 4)]);
        let new = simple_struct("Foo", 12, vec![("x", "u32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::SizeChanged { old: 8, new: 12 })));
    }

    #[test]
    fn test_field_added() {
        let old = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let new = simple_struct("Foo", 8, vec![("x", "u32", 0, 4), ("y", "u32", 4, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::FieldAdded { name, .. } if name == "y")));
    }

    #[test]
    fn test_field_removed() {
        let old = simple_struct("Foo", 8, vec![("x", "u32", 0, 4), ("y", "u32", 4, 4)]);
        let new = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::FieldRemoved { name, .. } if name == "y")));
    }

    #[test]
    fn test_field_type_changed() {
        let old = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let new = simple_struct("Foo", 4, vec![("x", "i32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::FieldTypeChanged { name, old, new }
            if name == "x" && old == "u32" && new == "i32")));
    }

    #[test]
    fn test_field_offset_changed() {
        let old = simple_struct("Foo", 8, vec![("y", "u32", 4, 4)]);
        let new = simple_struct("Foo", 8, vec![("y", "u32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::FieldOffsetChanged { name, old: 4, new: 0 }
            if name == "y")));
    }

    #[test]
    fn test_field_renamed() {
        let old = simple_struct("Foo", 4, vec![("old_name", "u32", 0, 4)]);
        let new = simple_struct("Foo", 4, vec![("new_name", "u32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::FieldRenamed { old_name, new_name }
            if old_name == "old_name" && new_name == "new_name")));
    }

    #[test]
    fn test_method_added() {
        let old = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let mut new = old.clone();
        new.methods.push("do_work".into());
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::MethodAdded { name } if name == "do_work")));
    }

    #[test]
    fn test_method_removed() {
        let mut old = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        old.methods.push("do_work".into());
        let new = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let changes = TypeDiff::diff_types(&old, &new);
        assert!(changes.iter().any(|c| matches!(c, TypeChange::MethodRemoved { name } if name == "do_work")));
    }

    #[test]
    fn test_impact_summary_breaking() {
        let old = simple_struct("Foo", 8, vec![("x", "u32", 0, 4), ("y", "u32", 4, 4)]);
        let new = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let impact = TypeDiff::impact(&old, &new);
        assert!(impact.has_breaking_changes());
    }

    #[test]
    fn test_impact_summary_no_changes() {
        let t = simple_struct("Foo", 4, vec![("x", "u32", 0, 4)]);
        let impact = TypeDiff::impact(&t, &t);
        assert!(!impact.has_breaking_changes());
        assert_eq!(impact.total(), 0);
        assert!(impact.headline.contains("No changes"));
    }

    #[test]
    fn test_type_change_is_breaking_removed() {
        let c = TypeChange::FieldRemoved { name: "x".into(), type_: "u32".into(), offset: 0 };
        assert!(c.is_breaking());
    }

    #[test]
    fn test_type_change_is_not_breaking_added() {
        let c = TypeChange::FieldAdded { name: "x".into(), type_: "u32".into(), offset: 0 };
        assert!(!c.is_breaking());
    }

    #[test]
    fn test_type_change_display() {
        let c = TypeChange::SizeChanged { old: 4, new: 8 };
        let s = c.to_string();
        assert!(s.contains("4") && s.contains("8"));
    }

    #[test]
    fn test_field_descriptor_byte_range() {
        let f = FieldDescriptor {
            name: "x".into(),
            type_name: "u32".into(),
            offset: 8,
            size: 4,
        };
        assert_eq!(f.byte_range(), (8, 12));
    }

    #[test]
    fn test_type_kind_display() {
        assert_eq!(TypeKind::Struct.to_string(), "struct");
        assert_eq!(TypeKind::Enum.to_string(), "enum");
        assert_eq!(TypeKind::Union.to_string(), "union");
        assert_eq!(TypeKind::Typedef.to_string(), "typedef");
    }

    #[test]
    fn test_multiple_changes_counted() {
        let old = simple_struct("S", 8, vec![("a", "u32", 0, 4), ("b", "u32", 4, 4)]);
        let new_type = TypeDescriptor {
            name: "S".into(),
            kind: TypeKind::Struct,
            size: 12,
            fields: vec![
                FieldDescriptor { name: "a".into(), type_name: "u64".into(), offset: 0, size: 8 },
                FieldDescriptor { name: "c".into(), type_name: "u32".into(), offset: 8, size: 4 },
            ],
            methods: vec![],
        };
        let changes = TypeDiff::diff_types(&old, &new_type);
        assert!(changes.len() >= 3); // SizeChanged + FieldTypeChanged(a) + FieldAdded(c) + FieldRemoved/renamed(b)
    }
}
