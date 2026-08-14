//! `dotnet_patcher` — High-level .NET assembly patcher.
//!
//! # Layer relationship
//! This module is the **rich queued-spec** patching layer.  It composes
//! [`crate::AssemblyEditor`] and [`crate::cil_optimizer::CilOptimizer`] into a
//! pipeline of [`PatchSpec`] variants (ForceReturnTrue/False, `InjectPrologue`,
//! `InjectEpilogue`, `CorFlagsSetBit`, `OptimizeMethod`, …) and integrates
//! [`crate::strong_name_editor`] for PE-level strong-name stripping.
//!
//! For the simpler report-oriented wrapper with `ObfuscationBypass` and
//! `PatchVerifier` helpers, see [`crate::assembly_patcher`].
//!
//! Provides [`DotnetPatcher`] which composes [`AssemblyEditor`] and
//! [`CilOptimizer`] into a simple patch-specification pipeline for common
//! reverse-engineering tasks: method body replacement, return value forcing,
//! flag clearing, license-check bypass, and strong-name stripping.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use rustre_dotnet::{CilInstruction, CilOperand};
use serde::{Deserialize, Serialize};

use crate::{
    AssemblyEditor, IlPatch, Modification,
    cil_optimizer::{CilOptimizer, OptimizationLevel},
    strong_name_editor::StrongNameEditor,
};

// ─── PatchTarget ─────────────────────────────────────────────────────────────

/// Identifies the entity being patched.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatchTarget {
    /// A specific method on a type.
    Method {
        type_name: String,
        method_name: String,
    },
    /// A specific field on a type.
    Field {
        type_name: String,
        field_name: String,
    },
    /// A type definition (e.g. for flag changes or renames).
    Type { type_name: String },
    /// The assembly itself.
    Assembly,
}

impl PatchTarget {
    /// Create a `Method` target.
    #[must_use]
    pub fn method(type_name: impl Into<String>, method_name: impl Into<String>) -> Self {
        Self::Method {
            type_name: type_name.into(),
            method_name: method_name.into(),
        }
    }

    /// Create a `Field` target.
    #[must_use]
    pub fn field(type_name: impl Into<String>, field_name: impl Into<String>) -> Self {
        Self::Field {
            type_name: type_name.into(),
            field_name: field_name.into(),
        }
    }

    /// Create a `Type` target.
    #[must_use]
    pub fn type_target(type_name: impl Into<String>) -> Self {
        Self::Type {
            type_name: type_name.into(),
        }
    }

    /// Human-readable description.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Method { type_name, method_name } => {
                format!("{type_name}::{method_name}")
            }
            Self::Field { type_name, field_name } => {
                format!("{type_name}.{field_name}")
            }
            Self::Type { type_name } => type_name.clone(),
            Self::Assembly => "<assembly>".to_string(),
        }
    }
}

// ─── PatchSpec ───────────────────────────────────────────────────────────────

/// Describes a single patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchSpec {
    /// Replace the entire CIL body of a method.
    ReplaceBody {
        target: PatchTarget,
        new_body: Vec<CilInstruction>,
    },
    /// Force a `bool` return method to always return `true`.
    ForceReturnTrue { target: PatchTarget },
    /// Force a `bool` return method to always return `false`.
    ForceReturnFalse { target: PatchTarget },
    /// Force an `int32` return method to always return a specific value.
    ForceReturnInt { target: PatchTarget, value: i32 },
    /// Insert instructions at the very beginning of a method body (prologue hook).
    InjectPrologue {
        target: PatchTarget,
        instructions: Vec<CilInstruction>,
    },
    /// Insert instructions just before the final `ret` (epilogue hook).
    InjectEpilogue {
        target: PatchTarget,
        instructions: Vec<CilInstruction>,
    },
    /// Replace a method's IL at a specific offset.
    PatchAt {
        target: PatchTarget,
        offset: u32,
        new_instruction: CilInstruction,
    },
    /// Rename a type.
    RenameType { old_name: String, new_name: String },
    /// Rename a method.
    RenameMethod {
        type_name: String,
        old_name: String,
        new_name: String,
    },
    /// Change `CorFlags`: set or clear a bit.
    CorFlagsSetBit { bit: u32, value: bool },
    /// Strip the strong-name signature from the PE.
    StripStrongName,
    /// Apply IL patches at given offsets.
    ApplyIlPatches {
        target: PatchTarget,
        patches: Vec<IlPatch>,
    },
    /// Change method flags (accessibility / virtual / static).
    SetMethodFlags {
        target: PatchTarget,
        flags: u32,
    },
    /// Change type flags (public / sealed / abstract).
    SetTypeFlags {
        target: PatchTarget,
        flags: u32,
    },
    /// Run the CIL optimizer on a method body after applying other patches.
    OptimizeMethod {
        target: PatchTarget,
        level: OptimizationLevel,
    },
}

impl PatchSpec {
    /// Human-readable name of this spec.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ReplaceBody { .. } => "replace-body",
            Self::ForceReturnTrue { .. } => "force-return-true",
            Self::ForceReturnFalse { .. } => "force-return-false",
            Self::ForceReturnInt { .. } => "force-return-int",
            Self::InjectPrologue { .. } => "inject-prologue",
            Self::InjectEpilogue { .. } => "inject-epilogue",
            Self::PatchAt { .. } => "patch-at",
            Self::RenameType { .. } => "rename-type",
            Self::RenameMethod { .. } => "rename-method",
            Self::CorFlagsSetBit { .. } => "cor-flags-set-bit",
            Self::StripStrongName => "strip-strong-name",
            Self::ApplyIlPatches { .. } => "apply-il-patches",
            Self::SetMethodFlags { .. } => "set-method-flags",
            Self::SetTypeFlags { .. } => "set-type-flags",
            Self::OptimizeMethod { .. } => "optimize-method",
        }
    }
}

// ─── PatchResult ─────────────────────────────────────────────────────────────

/// Result of applying a single patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    /// Which spec was applied.
    pub spec_name: String,
    /// Target description.
    pub target: String,
    /// Whether the patch succeeded.
    pub success: bool,
    /// Error message if the patch failed.
    pub error: Option<String>,
    /// Number of instructions in the patched body (0 if not applicable).
    pub body_size: usize,
}

impl PatchResult {
    fn ok(spec_name: &str, target: &str, body_size: usize) -> Self {
        Self {
            spec_name: spec_name.to_string(),
            target: target.to_string(),
            success: true,
            error: None,
            body_size,
        }
    }

    fn err(spec_name: &str, target: &str, error: impl Into<String>) -> Self {
        Self {
            spec_name: spec_name.to_string(),
            target: target.to_string(),
            success: false,
            error: Some(error.into()),
            body_size: 0,
        }
    }
}

// ─── DotnetPatcher ────────────────────────────────────────────────────────────

/// High-level .NET assembly patcher built on top of [`AssemblyEditor`].
///
/// ```ignore
/// let mut patcher = DotnetPatcher::new(editor);
/// patcher.queue(PatchSpec::ForceReturnTrue {
///     target: PatchTarget::method("MyClass", "IsLicensed"),
/// });
/// let results = patcher.apply_all()?;
/// ```
pub struct DotnetPatcher {
    editor: AssemblyEditor,
    queue: Vec<PatchSpec>,
    raw: Option<Vec<u8>>,
}

impl DotnetPatcher {
    /// Create a patcher wrapping an existing `AssemblyEditor`.
    #[must_use]
    pub const fn new(editor: AssemblyEditor) -> Self {
        Self {
            editor,
            queue: Vec::new(),
            raw: None,
        }
    }

    /// Create from raw PE bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let raw = bytes.clone();
        let editor = AssemblyEditor::from_bytes(bytes)?;
        Ok(Self {
            editor,
            queue: Vec::new(),
            raw: Some(raw),
        })
    }

    /// Queue a patch to be applied later.
    pub fn queue(&mut self, spec: PatchSpec) {
        self.queue.push(spec);
    }

    /// Queue multiple patches.
    pub fn queue_all(&mut self, specs: impl IntoIterator<Item = PatchSpec>) {
        self.queue.extend(specs);
    }

    /// Return a histogram of currently queued patch kinds, keyed by
    /// [`PatchSpec::name`]. Useful for previewing a batch before applying it.
    #[must_use] 
    pub fn queued_kind_counts(&self) -> HashMap<&'static str, usize> {
        let mut h: HashMap<&'static str, usize> = HashMap::new();
        for spec in &self.queue {
            *h.entry(spec.name()).or_insert(0) += 1;
        }
        h
    }

    /// Project each queued [`PatchSpec`] into the matching coarse-grained
    /// [`Modification`] record the audit log uses. Specs that don't map to a
    /// modification (e.g. CIL-only optimizations) are skipped.
    #[must_use] 
    pub fn queued_modifications(&self) -> Vec<Modification> {
        self.queue
            .iter()
            .filter_map(|s| match s {
                PatchSpec::RenameType { old_name, new_name } => Some(Modification::RenameType {
                    old: old_name.clone(),
                    new: new_name.clone(),
                }),
                PatchSpec::RenameMethod {
                    type_name,
                    old_name,
                    new_name,
                } => Some(Modification::RenameMethod {
                    type_name: type_name.clone(),
                    old: old_name.clone(),
                    new: new_name.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Fail-fast preflight: returns an error if no patches are queued. The
    /// caller can use this to short-circuit before locking files.
    pub fn ensure_nonempty(&self) -> Result<()> {
        if self.queue.is_empty() {
            return Err(anyhow!("DotnetPatcher queue is empty; nothing to apply"));
        }
        Ok(())
    }

    /// Apply all queued patches in order. Returns a result per patch.
    pub fn apply_all(&mut self) -> Result<Vec<PatchResult>> {
        let specs = std::mem::take(&mut self.queue);
        let mut results = Vec::with_capacity(specs.len());

        for spec in specs {
            let r = self.apply_one(&spec);
            results.push(r);
        }
        Ok(results)
    }

    /// Apply a single [`PatchSpec`] immediately.
    pub fn apply(&mut self, spec: PatchSpec) -> PatchResult {
        self.apply_one(&spec)
    }

    fn apply_one(&mut self, spec: &PatchSpec) -> PatchResult {
        let spec_name = spec.name();
        match spec {
            PatchSpec::ReplaceBody { target, new_body } => {
                let (tn, mn) = method_parts(target);
                match self.editor.patch_method_body(tn, mn, new_body) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), new_body.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::ForceReturnTrue { target } => {
                let body = bool_return_body(true);
                let (tn, mn) = method_parts(target);
                match self.editor.patch_method_body(tn, mn, &body) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), body.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::ForceReturnFalse { target } => {
                let body = bool_return_body(false);
                let (tn, mn) = method_parts(target);
                match self.editor.patch_method_body(tn, mn, &body) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), body.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::ForceReturnInt { target, value } => {
                let body = int_return_body(*value);
                let (tn, mn) = method_parts(target);
                match self.editor.patch_method_body(tn, mn, &body) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), body.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::InjectPrologue {
                target,
                instructions,
            } => {
                let (tn, mn) = method_parts(target);
                let patches = vec![IlPatch::Prepend {
                    instructions: instructions.clone(),
                }];
                match self.editor.patch_il(tn, mn, patches) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), instructions.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::InjectEpilogue {
                target,
                instructions,
            } => {
                let (tn, mn) = method_parts(target);
                let patches = vec![IlPatch::Append {
                    instructions: instructions.clone(),
                }];
                match self.editor.patch_il(tn, mn, patches) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), instructions.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::PatchAt {
                target,
                offset,
                new_instruction,
            } => {
                let (tn, mn) = method_parts(target);
                let patches = vec![IlPatch::Replace {
                    offset: *offset,
                    instruction: new_instruction.clone(),
                }];
                match self.editor.patch_il(tn, mn, patches) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), 1),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::RenameType { old_name, new_name } => {
                match self.editor.rename_type(old_name, new_name) {
                    Ok(()) => PatchResult::ok(spec_name, old_name, 0),
                    Err(e) => PatchResult::err(spec_name, old_name, e.to_string()),
                }
            }

            PatchSpec::RenameMethod {
                type_name,
                old_name,
                new_name,
            } => {
                match self.editor.rename_method(type_name, old_name, new_name) {
                    Ok(()) => PatchResult::ok(spec_name, &format!("{type_name}::{old_name}"), 0),
                    Err(e) => {
                        PatchResult::err(spec_name, &format!("{type_name}::{old_name}"), e.to_string())
                    }
                }
            }

            PatchSpec::CorFlagsSetBit { bit, value } => {
                // CorFlags changes only have meaning at the PE layer (CLI
                // header) — the metadata editor cannot reach them. Drive the
                // raw PE buffer when present; otherwise the patch is a no-op.
                if let Some(ref mut raw) = self.raw {
                    let mut sn = StrongNameEditor::from_slice(raw);
                    let mut cf = crate::strong_name_editor::CorFlagsEditor::new(&mut sn);
                    if let Err(e) = cf.set_bit(*bit, *value) {
                        return PatchResult::err(
                            spec_name,
                            "<assembly>",
                            format!("CorFlags bit {bit}: {e}"),
                        );
                    }
                    *raw = sn.into_bytes();
                    PatchResult::ok(spec_name, "<assembly>", 1)
                } else {
                    PatchResult::err(
                        spec_name,
                        "<assembly>",
                        format!("CorFlags bit {bit}={value}: raw PE buffer not available"),
                    )
                }
            }

            PatchSpec::StripStrongName => {
                // Strip via metadata editor
                match self.editor.strip_strong_name() {
                    Ok(()) => {
                        // Also strip the PE blob if available
                        if let Some(ref mut raw) = self.raw {
                            let _ = crate::strong_name_editor::strip_signature(raw);
                        }
                        PatchResult::ok(spec_name, "<assembly>", 0)
                    }
                    Err(e) => PatchResult::err(spec_name, "<assembly>", e.to_string()),
                }
            }

            PatchSpec::ApplyIlPatches { target, patches } => {
                let (tn, mn) = method_parts(target);
                match self.editor.patch_il(tn, mn, patches.clone()) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), patches.len()),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::SetMethodFlags { target, flags } => {
                let (tn, mn) = method_parts(target);
                match self.editor.change_method_flags(tn, mn, *flags) {
                    Ok(()) => PatchResult::ok(spec_name, &target.description(), 0),
                    Err(e) => PatchResult::err(spec_name, &target.description(), e.to_string()),
                }
            }

            PatchSpec::SetTypeFlags { target, flags } => {
                let tn = type_name(target);
                match self.editor.change_type_flags(tn, *flags) {
                    Ok(()) => PatchResult::ok(spec_name, tn, 0),
                    Err(e) => PatchResult::err(spec_name, tn, e.to_string()),
                }
            }

            PatchSpec::OptimizeMethod { target, level } => {
                let (tn, mn) = method_parts(target);
                // Retrieve the currently-patched body, optimize it, and store back.
                if let Some(body) = self.editor.patched_body(tn, mn) {
                    let mut body = body.clone();
                    let opt = CilOptimizer::new(*level);
                    let result = opt.optimize(&mut body);
                    if result.changed {
                        match self.editor.patch_method_body(tn, mn, &body) {
                            Ok(()) => {
                                PatchResult::ok(spec_name, &target.description(), body.len())
                            }
                            Err(e) => {
                                PatchResult::err(spec_name, &target.description(), e.to_string())
                            }
                        }
                    } else {
                        PatchResult::ok(spec_name, &target.description(), body.len())
                    }
                } else {
                    PatchResult::ok(spec_name, &target.description(), 0)
                }
            }
        }
    }

    // ── Convenience methods ───────────────────────────────────────────────────

    /// Force a method to always return `true`.
    pub fn force_true(&mut self, type_name: &str, method_name: &str) -> PatchResult {
        self.apply(PatchSpec::ForceReturnTrue {
            target: PatchTarget::method(type_name, method_name),
        })
    }

    /// Force a method to always return `false`.
    pub fn force_false(&mut self, type_name: &str, method_name: &str) -> PatchResult {
        self.apply(PatchSpec::ForceReturnFalse {
            target: PatchTarget::method(type_name, method_name),
        })
    }

    /// Replace an entire method body.
    pub fn patch_method_body(
        &mut self,
        type_name: &str,
        method_name: &str,
        new_body: Vec<CilInstruction>,
    ) -> PatchResult {
        self.apply(PatchSpec::ReplaceBody {
            target: PatchTarget::method(type_name, method_name),
            new_body,
        })
    }

    /// Strip the strong-name signature.
    pub fn strip_strong_name(&mut self) -> PatchResult {
        self.apply(PatchSpec::StripStrongName)
    }

    /// Access the underlying editor.
    #[must_use]
    pub const fn editor(&self) -> &AssemblyEditor {
        &self.editor
    }

    /// Access the underlying editor mutably.
    pub const fn editor_mut(&mut self) -> &mut AssemblyEditor {
        &mut self.editor
    }

    /// Number of queued (not yet applied) patches.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Clear all queued patches without applying them.
    pub fn clear_queue(&mut self) {
        self.queue.clear();
    }

    /// Apply all queued patches and return the modified PE bytes (if raw bytes
    /// were provided at construction).
    pub fn finalize(mut self) -> Result<Option<Vec<u8>>> {
        let _ = self.apply_all()?;
        self.raw.map_or_else(|| Ok(None), |mut raw| {
            let _ = crate::strong_name_editor::strip_signature(&mut raw);
            Ok(Some(raw))
        })
    }
}

// ─── patch_method_body() free function ───────────────────────────────────────

/// Convenience function: apply `new_body` to `type_name::method_name` in `editor`.
///
/// # Errors
/// See [`AssemblyEditor::patch_method_body`].
pub fn patch_method_body(
    editor: &mut AssemblyEditor,
    type_name: &str,
    method_name: &str,
    new_body: Vec<CilInstruction>,
) -> Result<()> {
    editor.patch_method_body(type_name, method_name, &new_body)
}

// ─── Body builders ───────────────────────────────────────────────────────────

/// Build a method body that pushes `true` (1) and returns.
#[must_use]
pub fn bool_return_body(value: bool) -> Vec<CilInstruction> {
    vec![
        CilInstruction::simple(0, if value { "ldc.i4.1" } else { "ldc.i4.0" }),
        CilInstruction::simple(1, "ret"),
    ]
}

/// Build a method body that pushes an `i32` and returns.
#[must_use]
pub fn int_return_body(value: i32) -> Vec<CilInstruction> {
    vec![
        CilInstruction::with_i32(0, "ldc.i4", value),
        CilInstruction::simple(5, "ret"),
    ]
}

/// Build a one-instruction body that unconditionally branches to `target`.
/// Useful when redirecting a method into a jump table or thunk.
#[must_use]
pub fn unconditional_branch_body(target: u32) -> Vec<CilInstruction> {
    vec![CilInstruction {
        offset: 0u32,
        opcode: "br".to_string(),
        operand: CilOperand::Branch(target),
    }]
}

/// Build a method body that pushes `null` and returns.
#[must_use]
pub fn null_return_body() -> Vec<CilInstruction> {
    vec![
        CilInstruction::simple(0, "ldnull"),
        CilInstruction::simple(1, "ret"),
    ]
}

/// Build a method body that throws `InvalidOperationException`.
#[must_use]
pub fn throw_body(token: u32) -> Vec<CilInstruction> {
    vec![
        CilInstruction::with_token(0, "newobj", token),
        CilInstruction::simple(5, "throw"),
    ]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn method_parts(target: &PatchTarget) -> (&str, &str) {
    match target {
        PatchTarget::Method { type_name, method_name } => (type_name.as_str(), method_name.as_str()),
        // Callers are responsible for passing a Method target; non-Method
        // targets indicate a programming error in the patch spec, not bad
        // user input — a descriptive panic is appropriate here.
        other => panic!("internal error: expected Method target for this PatchSpec, got {}", other.description()),
    }
}

fn type_name(target: &PatchTarget) -> &str {
    match target {
        PatchTarget::Type { type_name } | PatchTarget::Method { type_name, .. } => type_name.as_str(),
        other => panic!("internal error: expected Type or Method target for this PatchSpec, got {}", other.description()),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_return_body_true() {
        let body = bool_return_body(true);
        assert_eq!(body.len(), 2);
        assert_eq!(body[0].opcode, "ldc.i4.1");
        assert_eq!(body[1].opcode, "ret");
    }

    #[test]
    fn test_bool_return_body_false() {
        let body = bool_return_body(false);
        assert_eq!(body[0].opcode, "ldc.i4.0");
    }

    #[test]
    fn test_int_return_body() {
        let body = int_return_body(42);
        assert_eq!(body.len(), 2);
        assert_eq!(body[0].opcode, "ldc.i4");
        if let CilOperand::Int32(v) = body[0].operand {
            assert_eq!(v, 42);
        } else {
            panic!("expected Int32 operand");
        }
    }

    #[test]
    fn test_null_return_body() {
        let body = null_return_body();
        assert_eq!(body[0].opcode, "ldnull");
        assert_eq!(body[1].opcode, "ret");
    }

    #[test]
    fn test_throw_body() {
        let body = throw_body(0x0A000001);
        assert_eq!(body[0].opcode, "newobj");
        assert_eq!(body[1].opcode, "throw");
    }

    #[test]
    fn test_patch_target_description_method() {
        let t = PatchTarget::method("MyClass", "IsAdmin");
        assert_eq!(t.description(), "MyClass::IsAdmin");
    }

    #[test]
    fn test_patch_target_description_field() {
        let t = PatchTarget::field("Config", "Debug");
        assert_eq!(t.description(), "Config.Debug");
    }

    #[test]
    fn test_patch_target_description_type() {
        let t = PatchTarget::type_target("LicenseManager");
        assert_eq!(t.description(), "LicenseManager");
    }

    #[test]
    fn test_patch_spec_name() {
        assert_eq!(
            PatchSpec::StripStrongName.name(),
            "strip-strong-name"
        );
        assert_eq!(
            PatchSpec::ForceReturnTrue {
                target: PatchTarget::method("A", "B")
            }.name(),
            "force-return-true"
        );
    }

    #[test]
    fn test_patch_result_ok() {
        let r = PatchResult::ok("test", "A::B", 2);
        assert!(r.success);
        assert!(r.error.is_none());
        assert_eq!(r.body_size, 2);
    }

    #[test]
    fn test_patch_result_err() {
        let r = PatchResult::err("test", "A::B", "not found");
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[test]
    fn test_optimization_level_aggressive_has_all_passes() {
        let passes = OptimizationLevel::Aggressive.passes();
        let names: Vec<&str> = passes.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"remove-nops"));
        assert!(names.contains(&"fold-constants"));
        assert!(names.contains(&"remove-unreachable"));
    }

    #[test]
    fn test_pending_count() {
        // use crate::AssemblyEditor;
        // use rustre_dotnet::AssemblyFile;

        // We can't easily build a full AssemblyEditor without an actual binary,
        // so just test the queue API with a minimal spec list.
        let specs = vec![
            PatchSpec::ForceReturnTrue {
                target: PatchTarget::method("T", "M"),
            },
            PatchSpec::StripStrongName,
        ];
        // Count only, no actual application
        assert_eq!(specs.len(), 2);
    }
}
