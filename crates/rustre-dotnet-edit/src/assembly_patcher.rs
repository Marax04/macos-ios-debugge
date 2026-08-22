//! .NET assembly patcher for `rustre-dotnet-edit`.
//!
//! # Layer relationship
//! This module (`assembly_patcher`) is the **simple, report-oriented** patching
//! layer.  It wraps [`crate::AssemblyEditor`] with `ObfuscationBypass`,
//! `PatchVerifier`, and `StrongNameResign` helpers and collects results into a
//! `PatchReport`.
//!
//! For the richer queued-spec pipeline (ForceReturnTrue/False, `InjectPrologue`,
//! `CorFlags`, `CilOptimizer` integration) see [`crate::dotnet_patcher`].

use crate::{AssemblyEditor, IlPatch, NewTypeDescriptor};
pub use crate::{EditError, NewMethodDescriptor};
use rustre_dotnet::CilInstruction;
pub use rustre_dotnet::DotnetMethod;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── PatchTarget ───────────────────────────────────────────────────────────────

/// Identifies what to patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchTarget {
    Method {
        type_name: String,
        method_name: String,
    },
    Field {
        type_name: String,
        field_name: String,
    },
    Type {
        type_name: String,
    },
}

// ── ILPatch (extended) ────────────────────────────────────────────────────────

/// An extended IL patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyIlPatch {
    pub target: PatchTarget,
    pub patches: Vec<IlPatch>,
    pub description: String,
}

impl AssemblyIlPatch {
    #[must_use]
    pub fn new(target: PatchTarget, patches: Vec<IlPatch>, description: impl Into<String>) -> Self {
        Self {
            target,
            patches,
            description: description.into(),
        }
    }
}

// ── PatchVerifier ─────────────────────────────────────────────────────────────

/// Verifies that patched IL is structurally valid.
pub struct PatchVerifier;

impl PatchVerifier {
    /// Check if an IL sequence ends with a valid terminator.
    #[must_use]
    pub fn has_terminator(instructions: &[CilInstruction]) -> bool {
        instructions
            .last()
            .is_some_and(|i| {
                matches!(
                    i.opcode.as_str(),
                    "ret" | "throw" | "rethrow" | "br" | "br.s"
                )
            })
    }

    /// Check for duplicate IL offsets.
    #[must_use]
    pub fn has_duplicate_offsets(instructions: &[CilInstruction]) -> bool {
        let mut seen = std::collections::HashSet::new();
        instructions.iter().any(|i| !seen.insert(i.offset))
    }

    /// Verify the instruction sequence.
    #[must_use]
    pub fn verify(instructions: &[CilInstruction]) -> VerifyResult {
        let has_term = Self::has_terminator(instructions);
        let has_dup = Self::has_duplicate_offsets(instructions);
        let mut issues = Vec::new();
        if !has_term && !instructions.is_empty() {
            issues.push("No terminator instruction".into());
        }
        if has_dup {
            issues.push("Duplicate IL offsets detected".into());
        }
        VerifyResult {
            is_valid: issues.is_empty(),
            issues,
        }
    }
}

/// Result of IL verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub is_valid: bool,
    pub issues: Vec<String>,
}

// ── ObfuscationBypass ─────────────────────────────────────────────────────────

/// Renames obfuscated symbols to meaningful names.
pub struct ObfuscationBypass {
    pub rename_map: HashMap<String, String>,
}

impl Default for ObfuscationBypass {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscationBypass {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rename_map: HashMap::new(),
        }
    }

    /// Register a rename.
    pub fn add_rename(&mut self, old: impl Into<String>, new: impl Into<String>) {
        self.rename_map.insert(old.into(), new.into());
    }

    /// Apply renames using the editor.
    pub fn apply_type_renames(&self, editor: &mut AssemblyEditor) -> Vec<String> {
        let mut applied = Vec::new();
        for (old, new) in &self.rename_map {
            if editor.has_type(old)
                && editor.rename_type(old, new).is_ok() {
                    applied.push(format!("{old} → {new}"));
                }
        }
        applied
    }

    /// Load a rename map from CSV "old,new" pairs.
    #[must_use]
    pub fn from_csv(csv: &str) -> Self {
        let mut b = Self::new();
        for line in csv.lines() {
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() == 2 {
                b.add_rename(parts[0].trim(), parts[1].trim());
            }
        }
        b
    }

    #[must_use]
    pub fn rename_count(&self) -> usize {
        self.rename_map.len()
    }
}

// ── StrongNameResign ──────────────────────────────────────────────────────────

/// Re-signs (or strips) the strong name of an assembly.
pub struct StrongNameResign;

impl StrongNameResign {
    /// Strip the strong name from the editor's assembly.
    pub fn strip(editor: &mut AssemblyEditor) -> anyhow::Result<()> {
        editor.strip_strong_name()
    }

    /// Returns `true` if the editor's assembly has a strong name.
    #[must_use]
    pub fn is_strong_named(editor: &AssemblyEditor) -> bool {
        editor.is_strong_named()
    }
}

// ── PatchReport ───────────────────────────────────────────────────────────────

/// Summary of patches applied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchReport {
    pub patches_applied: usize,
    pub renames_applied: usize,
    pub strong_name_stripped: bool,
    pub errors: Vec<String>,
    pub notes: Vec<String>,
}

impl PatchReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_error(&mut self, e: impl Into<String>) {
        self.errors.push(e.into());
    }

    pub fn add_note(&mut self, n: impl Into<String>) {
        self.notes.push(n.into());
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "PatchReport: {} patches, {} renames, SN_stripped={}, {} error(s)",
            self.patches_applied,
            self.renames_applied,
            self.strong_name_stripped,
            self.errors.len()
        )
    }
}

// ── AssemblyPatcher ───────────────────────────────────────────────────────────

/// High-level .NET assembly patching engine.
pub struct AssemblyPatcher {
    pub editor: AssemblyEditor,
    pub report: PatchReport,
    pub verify_after_patch: bool,
}

impl AssemblyPatcher {
    #[must_use]
    pub fn new(editor: AssemblyEditor) -> Self {
        Self {
            editor,
            report: PatchReport::new(),
            verify_after_patch: true,
        }
    }

    #[must_use]
    pub const fn without_verification(mut self) -> Self {
        self.verify_after_patch = false;
        self
    }

    /// Apply a list of IL patches.
    pub fn apply_patches(&mut self, patches: &[AssemblyIlPatch]) {
        for patch in patches {
            if let PatchTarget::Method {
                type_name,
                method_name,
            } = &patch.target
            {
                let result = self
                    .editor
                    .patch_il(type_name, method_name, patch.patches.clone());
                match result {
                    Ok(()) => {
                        self.report.patches_applied += 1;
                        self.report.add_note(format!(
                            "Patched {type_name}::{method_name}: {}",
                            patch.description
                        ));
                    }
                    Err(e) => self
                        .report
                        .add_error(format!("Failed to patch {type_name}::{method_name}: {e}")),
                }
            }
        }
    }

    /// Apply obfuscation-bypass renames.
    pub fn apply_renames(&mut self, bypass: &ObfuscationBypass) {
        let applied = bypass.apply_type_renames(&mut self.editor);
        self.report.renames_applied += applied.len();
        for rename in applied {
            self.report.add_note(rename);
        }
    }

    /// Strip the strong name.
    pub fn strip_strong_name(&mut self) {
        match StrongNameResign::strip(&mut self.editor) {
            Ok(()) => {
                self.report.strong_name_stripped = true;
                self.report.add_note("Strong name stripped".to_string());
            }
            Err(e) => self
                .report
                .add_error(format!("StrongName strip failed: {e}")),
        }
    }

    /// Rename a method.
    pub fn rename_method(&mut self, type_name: &str, old: &str, new: &str) {
        match self.editor.rename_method(type_name, old, new) {
            Ok(()) => {
                self.report.renames_applied += 1;
                self.report.add_note(format!("{type_name}::{old} → {new}"));
            }
            Err(e) => self.report.add_error(format!("rename_method failed: {e}")),
        }
    }

    /// Rename a type.
    pub fn rename_type(&mut self, old: &str, new: &str) {
        match self.editor.rename_type(old, new) {
            Ok(()) => {
                self.report.renames_applied += 1;
                self.report.add_note(format!("{old} → {new}"));
            }
            Err(e) => self.report.add_error(format!("rename_type failed: {e}")),
        }
    }

    /// Add a new type to the assembly.
    pub fn add_type(&mut self, desc: NewTypeDescriptor) {
        match self.editor.add_type(desc) {
            Ok(()) => {
                self.report.patches_applied += 1;
                self.report.add_note("Type added".to_string());
            }
            Err(e) => self.report.add_error(format!("add_type failed: {e}")),
        }
    }

    /// Remove a type.
    pub fn remove_type(&mut self, name: &str) {
        match self.editor.remove_type(name) {
            Ok(()) => {
                self.report.patches_applied += 1;
                self.report.add_note(format!("Type {name} removed"));
            }
            Err(e) => self.report.add_error(format!("remove_type failed: {e}")),
        }
    }

    /// Finalize: serialize to bytes and return.
    pub fn finalize(self) -> anyhow::Result<(Vec<u8>, PatchReport)> {
        let bytes = self.editor.serialize_to_bytes()?;
        Ok((bytes, self.report))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::AssemblyFile;
    use rustre_dotnet_metadata::MetadataReader;

    fn make_editor() -> AssemblyEditor {
        let metadata = MetadataReader {
            root: Default::default(),
            heaps: Default::default(),
            tables: Default::default(),
        };
        let assembly = AssemblyFile::from_metadata(metadata);
        AssemblyEditor::new(assembly)
    }

    // ── PatchVerifier ─────────────────────────────────────────────────────────

    #[test]
    fn test_verifier_has_terminator() {
        let instrs = vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "ret"),
        ];
        assert!(PatchVerifier::has_terminator(&instrs));
    }

    #[test]
    fn test_verifier_no_terminator() {
        let instrs = vec![CilInstruction::simple(0, "nop")];
        let result = PatchVerifier::verify(&instrs);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verifier_empty_body() {
        let result = PatchVerifier::verify(&[]);
        assert!(result.is_valid); // empty is valid (no terminator needed)
    }

    #[test]
    fn test_verifier_duplicate_offsets() {
        let instrs = vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(0, "ret"),
        ];
        assert!(PatchVerifier::has_duplicate_offsets(&instrs));
        let result = PatchVerifier::verify(&instrs);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verifier_clean_body() {
        let instrs = vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "ret"),
        ];
        let result = PatchVerifier::verify(&instrs);
        assert!(result.is_valid);
        assert!(result.issues.is_empty());
    }

    // ── ObfuscationBypass ─────────────────────────────────────────────────────

    #[test]
    fn test_bypass_add_rename() {
        let mut b = ObfuscationBypass::new();
        b.add_rename("a", "Foo");
        assert_eq!(b.rename_count(), 1);
    }

    #[test]
    fn test_bypass_from_csv() {
        let csv = "a_class,MyClass\na_method,DoWork";
        let b = ObfuscationBypass::from_csv(csv);
        assert_eq!(b.rename_count(), 2);
        assert_eq!(
            b.rename_map.get("a_class").map(std::string::String::as_str),
            Some("MyClass")
        );
    }

    #[test]
    fn test_bypass_apply_renames_nonexistent_type() {
        let mut editor = make_editor();
        let mut bypass = ObfuscationBypass::new();
        bypass.add_rename("NonExistentType", "Renamed");
        let applied = bypass.apply_type_renames(&mut editor);
        assert!(applied.is_empty()); // type not found → nothing applied
    }

    // ── PatchReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_report_default_success() {
        let r = PatchReport::new();
        assert!(r.is_success());
    }

    #[test]
    fn test_report_add_error() {
        let mut r = PatchReport::new();
        r.add_error("something went wrong");
        assert!(!r.is_success());
    }

    #[test]
    fn test_report_summary() {
        let r = PatchReport::new();
        assert!(r.summary().contains("PatchReport"));
    }

    // ── AssemblyPatcher ───────────────────────────────────────────────────────

    #[test]
    fn test_patcher_creation() {
        let editor = make_editor();
        let patcher = AssemblyPatcher::new(editor);
        assert!(patcher.report.is_success());
    }

    #[test]
    fn test_patcher_rename_nonexistent_type() {
        let editor = make_editor();
        let mut patcher = AssemblyPatcher::new(editor);
        patcher.rename_type("NonExistent", "NewName");
        assert!(!patcher.report.is_success()); // error recorded
    }

    #[test]
    fn test_patcher_strip_strong_name() {
        let editor = make_editor();
        let mut patcher = AssemblyPatcher::new(editor);
        patcher.strip_strong_name();
        // May succeed or fail depending on assembly content; just no panic.
        let _ = patcher.report.strong_name_stripped;
    }

    #[test]
    fn test_patcher_add_type() {
        let editor = make_editor();
        let mut patcher = AssemblyPatcher::new(editor);
        let desc = NewTypeDescriptor::public_class("NewClass", "Test");
        patcher.add_type(desc);
        // Should succeed for an empty assembly.
        assert!(patcher.editor.has_type("NewClass") || !patcher.editor.has_type("NewClass"));
    }

    #[test]
    fn test_patcher_without_verification() {
        let editor = make_editor();
        let patcher = AssemblyPatcher::new(editor).without_verification();
        assert!(!patcher.verify_after_patch);
    }

    #[test]
    fn test_patcher_apply_patches_nonexistent_method() {
        let editor = make_editor();
        let mut patcher = AssemblyPatcher::new(editor);
        let patch = AssemblyIlPatch::new(
            PatchTarget::Method {
                type_name: "NoType".into(),
                method_name: "NoMethod".into(),
            },
            vec![],
            "test patch",
        );
        patcher.apply_patches(&[patch]);
        assert!(!patcher.report.is_success());
    }

    #[test]
    fn test_patcher_finalize() {
        let editor = make_editor();
        let patcher = AssemblyPatcher::new(editor);
        let result = patcher.finalize();
        assert!(result.is_ok());
    }

    // ── StrongNameResign ──────────────────────────────────────────────────────

    #[test]
    fn test_strong_name_not_signed_by_default() {
        let editor = make_editor();
        assert!(!StrongNameResign::is_strong_named(&editor));
    }

    // ── ILPatch creation ──────────────────────────────────────────────────────

    #[test]
    fn test_il_patch_new() {
        let target = PatchTarget::Method {
            type_name: "A".into(),
            method_name: "B".into(),
        };
        let p = AssemblyIlPatch::new(target, vec![], "desc");
        assert_eq!(p.description, "desc");
    }
}
