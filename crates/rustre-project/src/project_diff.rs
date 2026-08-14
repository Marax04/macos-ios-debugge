//! `project_diff` — compute and apply structural diffs between two project states.
//!
//! [`ProjectDiff`] captures a set of [`ProjectChange`] entries, each describing
//! a single mutation (add/remove/modify) to a binary, function, comment, xref,
//! symbol, or annotation.  The public entry point is [`diff_projects`].

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── ChangeKind ────────────────────────────────────────────────────────────────

/// The type of mutation captured in a [`ProjectChange`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeKind {
    /// An entity was added in the new state.
    Added,
    /// An entity was removed in the new state.
    Removed,
    /// An entity was present in both states but one or more fields changed.
    Modified,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => f.write_str("added"),
            Self::Removed => f.write_str("removed"),
            Self::Modified => f.write_str("modified"),
        }
    }
}

// ── EntityKind ────────────────────────────────────────────────────────────────

/// Which logical entity a change applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    Binary,
    Function,
    Comment,
    Xref,
    Symbol,
    Annotation,
    Bookmark,
    Patch,
    Script,
    Note,
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Binary => "binary",
            Self::Function => "function",
            Self::Comment => "comment",
            Self::Xref => "xref",
            Self::Symbol => "symbol",
            Self::Annotation => "annotation",
            Self::Bookmark => "bookmark",
            Self::Patch => "patch",
            Self::Script => "script",
            Self::Note => "note",
        };
        f.write_str(s)
    }
}

// ── ProjectChange ─────────────────────────────────────────────────────────────

/// A single change between two project snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectChange {
    /// The type of entity affected.
    pub entity: EntityKind,
    /// The kind of change.
    pub kind: ChangeKind,
    /// A stable key identifying the entity (e.g. `"binary:<sha256>"`,
    /// `"function:<binary_id>:<addr_hex>"`).
    pub key: String,
    /// Human-readable description.
    pub description: String,
    /// Optional JSON-serialised previous value.
    pub before: Option<String>,
    /// Optional JSON-serialised new value.
    pub after: Option<String>,
}

impl ProjectChange {
    /// Create an `Added` change.
    pub fn added(entity: EntityKind, key: impl Into<String>, description: impl Into<String>, after: Option<String>) -> Self {
        Self {
            entity,
            kind: ChangeKind::Added,
            key: key.into(),
            description: description.into(),
            before: None,
            after,
        }
    }

    /// Create a `Removed` change.
    pub fn removed(entity: EntityKind, key: impl Into<String>, description: impl Into<String>, before: Option<String>) -> Self {
        Self {
            entity,
            kind: ChangeKind::Removed,
            key: key.into(),
            description: description.into(),
            before,
            after: None,
        }
    }

    /// Create a `Modified` change.
    pub fn modified(
        entity: EntityKind,
        key: impl Into<String>,
        description: impl Into<String>,
        before: Option<String>,
        after: Option<String>,
    ) -> Self {
        Self {
            entity,
            kind: ChangeKind::Modified,
            key: key.into(),
            description: description.into(),
            before,
            after,
        }
    }
}

impl fmt::Display for ProjectChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} {}", self.kind, self.entity, self.key)?;
        if !self.description.is_empty() {
            write!(f, " — {}", self.description)?;
        }
        Ok(())
    }
}

// ── ProjectSnapshot ───────────────────────────────────────────────────────────

/// A lightweight, serialisable snapshot of project state used for diffing.
///
/// In a real deployment this would be populated from the SQLite database.
/// The diff engine works on these in-memory maps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectSnapshot {
    /// `sha256 → path`
    pub binaries: HashMap<String, String>,
    /// `"<binary_id>:<addr_hex>" → name`
    pub functions: HashMap<String, String>,
    /// `"<binary_id>:<addr_hex>" → body`
    pub comments: HashMap<String, String>,
    /// `"<binary_id>:<from_hex>:<to_hex>:<type>" → ()`
    pub xrefs: HashSet<String>,
    /// `"<binary_id>:<addr_hex>:<name>" → symbol_type`
    pub symbols: HashMap<String, String>,
    /// `"<binary_id>:<addr_hex>:<idx>" → body`
    pub annotations: HashMap<String, String>,
    /// `"<binary_id>:<addr_hex>" → label`
    pub bookmarks: HashMap<String, String>,
    /// `"<binary_id>:<addr_hex>" → description`
    pub patches: HashMap<String, String>,
    /// `name → language`
    pub scripts: HashMap<String, String>,
    /// `title → body_sha256`
    pub notes: HashMap<String, String>,
}

impl ProjectSnapshot {
    /// Create a new empty snapshot.
    #[must_use] 
     
    pub fn new() -> Self {
        Self::default()
    }

    // ── Builder helpers ───────────────────────────────────────────────────────

    pub fn add_binary(&mut self, sha256: impl Into<String>, path: impl Into<String>) {
        self.binaries.insert(sha256.into(), path.into());
    }

    pub fn add_function(&mut self, binary_id: u64, addr: u64, name: impl Into<String>) {
        self.functions.insert(format!("{binary_id}:{addr:x}"), name.into());
    }

    pub fn add_comment(&mut self, binary_id: u64, addr: u64, body: impl Into<String>) {
        self.comments.insert(format!("{binary_id}:{addr:x}"), body.into());
    }

    pub fn add_xref(&mut self, binary_id: u64, from: u64, to: u64, xref_type: &str) {
        self.xrefs.insert(format!("{binary_id}:{from:x}:{to:x}:{xref_type}"));
    }

    pub fn add_symbol(&mut self, binary_id: u64, addr: u64, name: &str, sym_type: impl Into<String>) {
        self.symbols.insert(format!("{binary_id}:{addr:x}:{name}"), sym_type.into());
    }

    pub fn add_annotation(&mut self, binary_id: u64, addr: u64, idx: usize, body: impl Into<String>) {
        self.annotations.insert(format!("{binary_id}:{addr:x}:{idx}"), body.into());
    }

    pub fn add_bookmark(&mut self, binary_id: u64, addr: u64, label: impl Into<String>) {
        self.bookmarks.insert(format!("{binary_id}:{addr:x}"), label.into());
    }

    pub fn add_patch(&mut self, binary_id: u64, addr: u64, description: impl Into<String>) {
        self.patches.insert(format!("{binary_id}:{addr:x}"), description.into());
    }

    pub fn add_script(&mut self, name: impl Into<String>, language: impl Into<String>) {
        self.scripts.insert(name.into(), language.into());
    }

    pub fn add_note(&mut self, title: impl Into<String>, body_hash: impl Into<String>) {
        self.notes.insert(title.into(), body_hash.into());
    }
}

// ── ProjectDiff ───────────────────────────────────────────────────────────────

/// The result of comparing two [`ProjectSnapshot`]s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectDiff {
    /// Ordered list of changes (added first, then removed, then modified).
    pub changes: Vec<ProjectChange>,
}

impl ProjectDiff {
    /// Return `true` when no changes were detected.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

   #[must_use] 
     /// Total number of changes.
     
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Iterate changes that match the given [`ChangeKind`].
    pub fn by_kind(&self, kind: &ChangeKind) -> impl Iterator<Item = &ProjectChange> {
        self.changes.iter().filter(move |c| &c.kind == kind)
    }

    /// Iterate changes that apply to the given [`EntityKind`].
    pub fn by_entity(&self, entity: &EntityKind) -> impl Iterator<Item = &ProjectChange> {
        self.changes.iter().filter(move |c| &c.entity == entity)
    }

  #[must_use] 
      /// Count changes grouped by [`ChangeKind`].
     
    pub fn kind_counts(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for c in &self.changes {
            *m.entry(c.kind.to_string()).or_insert(0) += 1;
        }
   
          m
    }

    /// Count changes grouped by [`EntityKind`].
    #[must_use] 
    pub fn entity_counts(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for c in &self.changes {
            *m.entry(c.entity.to_string()).or_insert(0) += 1;
        }
        m
    }

    /// Format as a human-readable summary line.
    #[must_use] 
    pub fn summary(&self) -> String {
        let added = self.by_kind(&ChangeKind::Added).count();
        let removed = self.by_kind(&ChangeKind::Removed).count();
        let modified = self.by_kind(&ChangeKind::Modified).count();
        format!("+{added} -{removed} ~{modified} ({} total)", self.len())
    }
}

impl fmt::Display for ProjectDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProjectDiff: {}", self.summary())?;
        for c in &self.changes {
            writeln!(f, "  {c}")?;
        }
        Ok(())
    }
}

// ── diff_projects ─────────────────────────────────────────────────────────────

/// Compare two snapshots and return a [`ProjectDiff`] with all detected changes.
///
/// The diff is computed for each entity table independently using symmetric set
/// difference on the stable keys, then value comparison for potential modifications.
#[must_use] 
pub fn diff_projects(old: &ProjectSnapshot, new: &ProjectSnapshot) -> ProjectDiff {
    let mut changes = Vec::new();

    // ── Binaries ──────────────────────────────────────────────────────────────
    diff_map(
        &old.binaries,
        &new.binaries,
        EntityKind::Binary,
        |k, v| format!("binary added: path={v} sha256={k}"),
        |k, v| format!("binary removed: path={v} sha256={k}"),
        |k, ov, nv| format!("binary path changed: sha256={k} {ov} → {nv}"),
        &mut changes,
    );

    // ── Functions ─────────────────────────────────────────────────────────────
    diff_map(
        &old.functions,
        &new.functions,
        EntityKind::Function,
        |k, v| format!("function added: {k} name={v}"),
        |k, v| format!("function removed: {k} name={v}"),
        |k, ov, nv| format!("function renamed: {k} {ov:?} → {nv:?}"),
        &mut changes,
    );

    // ── Comments ──────────────────────────────────────────────────────────────
    diff_map(
        &old.comments,
        &new.comments,
        EntityKind::Comment,
        |k, _| format!("comment added at {k}"),
        |k, _| format!("comment removed at {k}"),
        |k, _, _| format!("comment modified at {k}"),
        &mut changes,
    );

    // ── Xrefs ─────────────────────────────────────────────────────────────────
    for key in new.xrefs.difference(&old.xrefs) {
        changes.push(ProjectChange::added(
            EntityKind::Xref,
            key.clone(),
            format!("xref added: {key}"),
            None,
        ));
    }
    for key in old.xrefs.difference(&new.xrefs) {
        changes.push(ProjectChange::removed(
            EntityKind::Xref,
            key.clone(),
            format!("xref removed: {key}"),
            None,
        ));
    }

    // ── Symbols ───────────────────────────────────────────────────────────────
    diff_map(
        &old.symbols,
        &new.symbols,
        EntityKind::Symbol,
        |k, v| format!("symbol added: {k} type={v}"),
        |k, v| format!("symbol removed: {k} type={v}"),
        |k, ov, nv| format!("symbol type changed: {k} {ov} → {nv}"),
        &mut changes,
    );

    // ── Annotations ───────────────────────────────────────────────────────────
    diff_map(
        &old.annotations,
        &new.annotations,
        EntityKind::Annotation,
        |k, _| format!("annotation added at {k}"),
        |k, _| format!("annotation removed at {k}"),
        |k, _, _| format!("annotation modified at {k}"),
        &mut changes,
    );

    // ── Bookmarks ─────────────────────────────────────────────────────────────
    diff_map(
        &old.bookmarks,
        &new.bookmarks,
        EntityKind::Bookmark,
        |k, v| format!("bookmark added: {k} label={v:?}"),
        |k, v| format!("bookmark removed: {k} label={v:?}"),
        |k, ov, nv| format!("bookmark label changed: {k} {ov:?} → {nv:?}"),
        &mut changes,
    );

    // ── Patches ───────────────────────────────────────────────────────────────
    diff_map(
        &old.patches,
        &new.patches,
        EntityKind::Patch,
        |k, _| format!("patch added at {k}"),
        |k, _| format!("patch removed at {k}"),
        |k, _, _| format!("patch modified at {k}"),
        &mut changes,
    );

    // ── Scripts ───────────────────────────────────────────────────────────────
    diff_map(
        &old.scripts,
        &new.scripts,
        EntityKind::Script,
        |k, v| format!("script added: {k} lang={v}"),
        |k, v| format!("script removed: {k} lang={v}"),
        |k, ov, nv| format!("script language changed: {k} {ov} → {nv}"),
        &mut changes,
    );

    // ── Notes ─────────────────────────────────────────────────────────────────
    diff_map(
        &old.notes,
        &new.notes,
        EntityKind::Note,
        |k, _| format!("note added: {k:?}"),
        |k, _| format!("note removed: {k:?}"),
        |k, _, _| format!("note body changed: {k:?}"),
        &mut changes,
    );

    // Stable sort: Added < Removed < Modified, then by entity, then by key.
    changes.sort_by(|a, b| {
        let kord = kind_order(&a.kind).cmp(&kind_order(&b.kind));
        if kord != std::cmp::Ordering::Equal {
            return kord;
        }
        a.entity.to_string().cmp(&b.entity.to_string())
            .then_with(|| a.key.cmp(&b.key))
    });

    ProjectDiff { changes }
}

fn kind_order(k: &ChangeKind) -> u8 {
    match k {
        ChangeKind::Added => 0,
        ChangeKind::Removed => 1,
        ChangeKind::Modified => 2,
    }
}

/// Generic helper: diff two `HashMap<String, String>` tables.
fn diff_map<FA, FR, FM>(
    old: &HashMap<String, String>,
    new: &HashMap<String, String>,
    entity: EntityKind,
    desc_added: FA,
    desc_removed: FR,
    desc_modified: FM,
    out: &mut Vec<ProjectChange>,
) where
    FA: Fn(&str, &str) -> String,
    FR: Fn(&str, &str) -> String,
    FM: Fn(&str, &str, &str) -> String,
{
    for (key, new_val) in new {
        match old.get(key) {
            None => out.push(ProjectChange::added(
                entity.clone(),
                key.clone(),
                desc_added(key, new_val),
                Some(new_val.clone()),
            )),
            Some(old_val) if old_val != new_val => out.push(ProjectChange::modified(
                entity.clone(),
                key.clone(),
                desc_modified(key, old_val, new_val),
                Some(old_val.clone()),
                Some(new_val.clone()),
            )),
            Some(_) => {} // unchanged
        }
    }
    for (key, old_val) in old {
        if !new.contains_key(key) {
            out.push(ProjectChange::removed(
                entity.clone(),
                key.clone(),
                desc_removed(key, old_val),
                Some(old_val.clone()),
            ));
        }
    }
}

// ── DiffApplicator ────────────────────────────────────────────────────────────

/// Applies a [`ProjectDiff`] to a [`ProjectSnapshot`], producing a new snapshot.
///
/// Changes are applied in the order they appear in `diff.changes`.  Conflicts
/// (e.g. trying to remove an entity that does not exist in the target) are
/// silently skipped and recorded in the returned [`ApplyReport`].
pub struct DiffApplicator;

/// Report produced by [`DiffApplicator::apply`].
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: Vec<String>,
}

impl ApplyReport {
    #[must_use] 
    pub fn is_clean(&self) -> bool {
        self.skipped.is_empty()
    }
}

impl DiffApplicator {
    /// Apply `diff` to a clone of `base` and return the resulting snapshot.
    #[must_use] 
    pub fn apply(base: &ProjectSnapshot, diff: &ProjectDiff) -> (ProjectSnapshot, ApplyReport) {
        let mut snap = base.clone();
        let mut report = ApplyReport::default();

        for change in &diff.changes {
            match (&change.entity, &change.kind) {
                // ── Binaries ─────────────────────────────────────────────────
                (EntityKind::Binary, ChangeKind::Added) => {
                    let val = change.after.clone().unwrap_or_default();
                    snap.binaries.insert(change.key.clone(), val);
                    report.applied += 1;
                }
                (EntityKind::Binary, ChangeKind::Removed) => {
                    if snap.binaries.remove(&change.key).is_some() {
                        report.applied += 1;
                    } else {
                        report.skipped.push(format!("binary remove: key not found: {}", change.key));
                    }
                }
                (EntityKind::Binary, ChangeKind::Modified) => {
                    if let Some(v) = snap.binaries.get_mut(&change.key) {
                        if let Some(a) = &change.after { v.clone_from(a); }
                        report.applied += 1;
                    } else {
                        report.skipped.push(format!("binary modify: key not found: {}", change.key));
                    }
                }

                // ── Functions ─────────────────────────────────────────────────
                (EntityKind::Function, ChangeKind::Added) => {
                    snap.functions.insert(change.key.clone(), change.after.clone().unwrap_or_default());
                    report.applied += 1;
                }
                (EntityKind::Function, ChangeKind::Removed) => {
                    if snap.functions.remove(&change.key).is_some() {
                        report.applied += 1;
                    } else {
                        report.skipped.push(format!("function remove: {}", change.key));
                    }
                }
                (EntityKind::Function, ChangeKind::Modified) => {
                    if let Some(v) = snap.functions.get_mut(&change.key) {
                        if let Some(a) = &change.after { v.clone_from(a); }
                        report.applied += 1;
                    } else {
                        report.skipped.push(format!("function modify: {}", change.key));
                    }
                }

                // ── Xrefs ────────────────────────────────────────────────────
                (EntityKind::Xref, ChangeKind::Added) => {
                    snap.xrefs.insert(change.key.clone());
                    report.applied += 1;
                }
                (EntityKind::Xref, ChangeKind::Removed) => {
                    if snap.xrefs.remove(&change.key) {
                        report.applied += 1;
                    } else {
                        report.skipped.push(format!("xref remove: {}", change.key));
                    }
                }
                (EntityKind::Xref, ChangeKind::Modified) => {
                    // Xrefs have no mutable fields; skip gracefully.
                    report.skipped.push(format!("xref modify not supported: {}", change.key));
                }

                // ── Comments, Annotations, Bookmarks, Patches, Scripts, Notes ─
                _ => {
                    let map = match &change.entity {
                        EntityKind::Comment => Some(&mut snap.comments),
                        EntityKind::Annotation => Some(&mut snap.annotations),
                        EntityKind::Bookmark => Some(&mut snap.bookmarks),
                        EntityKind::Patch => Some(&mut snap.patches),
                        EntityKind::Script => Some(&mut snap.scripts),
                        EntityKind::Note => Some(&mut snap.notes),
                        EntityKind::Symbol => Some(&mut snap.symbols),
                        _ => None,
                    };
                    if let Some(m) = map {
                        match &change.kind {
                            ChangeKind::Added => {
                                m.insert(change.key.clone(), change.after.clone().unwrap_or_default());
                                report.applied += 1;
                            }
                            ChangeKind::Removed => {
                                if m.remove(&change.key).is_some() {
                                    report.applied += 1;
                                } else {
                                    report.skipped.push(format!("{} remove: {}", change.entity, change.key));
                                }
                            }
                            ChangeKind::Modified => {
                                if let Some(v) = m.get_mut(&change.key) {
                                    if let Some(a) = &change.after { v.clone_from(a); }
                                    report.applied += 1;
                                } else {
                                    report.skipped.push(format!("{} modify: {}", change.entity, change.key));
                                }
                            }
                        }
                    }
                }
            }
        }

        (snap, report)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_old() -> ProjectSnapshot {
        let mut s = ProjectSnapshot::new();
        s.add_binary("aaaa", "/bin/foo");
        s.add_binary("bbbb", "/bin/bar");
        s.add_function(1, 0x1000, "main");
        s.add_function(1, 0x2000, "helper");
        s.add_comment(1, 0x1000, "entry point");
        s.add_xref(1, 0x1000, 0x2000, "call");
        s.add_symbol(1, 0x1000, "main", "function");
        s.add_script("init.py", "python");
        s
    }

    fn make_new() -> ProjectSnapshot {
        let mut s = ProjectSnapshot::new();
        s.add_binary("aaaa", "/bin/foo");         // unchanged
        s.add_binary("cccc", "/bin/baz");          // new
        // "bbbb" removed
        s.add_function(1, 0x1000, "main_renamed"); // modified
        s.add_function(1, 0x2000, "helper");       // unchanged
        s.add_function(1, 0x3000, "new_fn");       // added
        s.add_comment(1, 0x1000, "entry point");   // unchanged
        s.add_xref(1, 0x1000, 0x2000, "call");    // unchanged
        s.add_xref(1, 0x2000, 0x3000, "call");    // added
        s.add_symbol(1, 0x1000, "main_renamed", "function"); // symbol for renamed fn
        s.add_script("init.py", "python");          // unchanged
        s.add_script("analysis.py", "python");      // added
        s
    }

    #[test]
    fn diff_detects_binary_added() {
        let d = diff_projects(&make_old(), &make_new());
        let adds: Vec<_> = d.by_kind(&ChangeKind::Added)
            .filter(|c| c.entity == EntityKind::Binary)
            .collect();
        assert!(!adds.is_empty(), "expected at least one binary add");
        assert!(adds.iter().any(|c| c.key == "cccc"));
    }

    #[test]
    fn diff_detects_binary_removed() {
        let d = diff_projects(&make_old(), &make_new());
        let rems: Vec<_> = d.by_kind(&ChangeKind::Removed)
            .filter(|c| c.entity == EntityKind::Binary)
            .collect();
        assert!(rems.iter().any(|c| c.key == "bbbb"));
    }

    #[test]
    fn diff_detects_function_added() {
        let d = diff_projects(&make_old(), &make_new());
        assert!(d.by_entity(&EntityKind::Function)
            .any(|c| c.kind == ChangeKind::Added && c.key.contains("3000")));
    }

    #[test]
    fn diff_detects_function_modified() {
        let d = diff_projects(&make_old(), &make_new());
        assert!(d.by_entity(&EntityKind::Function)
            .any(|c| c.kind == ChangeKind::Modified && c.key.contains("1000")));
    }

    #[test]
    fn diff_detects_xref_added() {
        let d = diff_projects(&make_old(), &make_new());
        assert!(d.by_entity(&EntityKind::Xref)
            .any(|c| c.kind == ChangeKind::Added));
    }

    #[test]
    fn diff_no_changes_on_identical() {
        let s = make_old();
        let d = diff_projects(&s, &s);
        assert!(d.is_empty());
    }

    #[test]
    fn diff_summary_format() {
        let d = diff_projects(&make_old(), &make_new());
        let s = d.summary();
        assert!(s.starts_with('+'));
        assert!(s.contains('-'));
    }

    #[test]
    fn diff_kind_counts() {
        let d = diff_projects(&make_old(), &make_new());
        let counts = d.kind_counts();
        assert!(counts.get("added").copied().unwrap_or(0) > 0);
    }

    #[test]
    fn diff_entity_counts() {
        let d = diff_projects(&make_old(), &make_new());
        let counts = d.entity_counts();
        assert!(counts.get("function").copied().unwrap_or(0) > 0);
    }

    #[test]
    fn apply_add_binary() {
        let base = ProjectSnapshot::new();
        let mut diff = ProjectDiff::default();
        diff.changes.push(ProjectChange::added(
            EntityKind::Binary, "deadbeef", "add", Some("/tmp/x".into()),
        ));
        let (snap, report) = DiffApplicator::apply(&base, &diff);
        assert!(snap.binaries.contains_key("deadbeef"));
        assert_eq!(report.applied, 1);
        assert!(report.is_clean());
    }

    #[test]
    fn apply_remove_binary() {
        let mut base = ProjectSnapshot::new();
        base.add_binary("aabb", "/bin/a");
        let mut diff = ProjectDiff::default();
        diff.changes.push(ProjectChange::removed(EntityKind::Binary, "aabb", "remove", None));
        let (snap, report) = DiffApplicator::apply(&base, &diff);
        assert!(!snap.binaries.contains_key("aabb"));
        assert_eq!(report.applied, 1);
    }

    #[test]
    fn apply_skip_missing_remove() {
        let base = ProjectSnapshot::new();
        let mut diff = ProjectDiff::default();
        diff.changes.push(ProjectChange::removed(EntityKind::Binary, "nothere", "remove", None));
        let (_, report) = DiffApplicator::apply(&base, &diff);
        assert!(!report.is_clean());
        assert_eq!(report.applied, 0);
    }

    #[test]
    fn apply_add_xref() {
        let base = ProjectSnapshot::new();
        let mut diff = ProjectDiff::default();
        diff.changes.push(ProjectChange::added(EntityKind::Xref, "1:1000:2000:call", "add xref", None));
        let (snap, _) = DiffApplicator::apply(&base, &diff);
        assert!(snap.xrefs.contains("1:1000:2000:call"));
    }

    #[test]
    fn display_change() {
        let c = ProjectChange::added(EntityKind::Function, "1:1000", "main added", None);
        let s = c.to_string();
        assert!(s.contains("added"));
        assert!(s.contains("function"));
    }

    #[test]
    fn display_diff() {
        let d = diff_projects(&make_old(), &make_new());
        let s = d.to_string();
        assert!(s.contains("ProjectDiff"));
    }
}
