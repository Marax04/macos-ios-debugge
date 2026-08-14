//! PE import table editor.
//!
//! Add, remove, and redirect imports; patch the IAT; handle delay imports;
//! and manage forwarded exports.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::EditError;

// ─── ImportOp ────────────────────────────────────────────────────────────────

/// A single import editing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportOp {
    /// Add a function import to an existing or new DLL entry.
    AddFunction {
        dll: String,
        function_name: String,
        /// If Some, import by ordinal instead of by name.
        ordinal: Option<u16>,
    },
    /// Remove a function import.
    RemoveFunction { dll: String, function_name: String },
    /// Redirect an IAT slot to a different function (hooking).
    RedirectFunction {
        dll: String,
        function_name: String,
        /// New target VA or RVA to write into the IAT slot.
        target_va: u64,
    },
    /// Add a new DLL entry with no functions (stub).
    AddDll { dll: String },
    /// Remove an entire DLL from the import table.
    RemoveDll { dll: String },
    /// Rename a DLL in the import table.
    RenameDll { old_dll: String, new_dll: String },
    /// Import a function by ordinal (add if not present).
    ImportByOrdinal { dll: String, ordinal: u16 },
}

impl ImportOp {
    /// Return a human-readable description.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::AddFunction {
                dll,
                function_name,
                ordinal,
            } => {
                ordinal.as_ref().map_or_else(
                    || format!("AddFunc {dll}!{function_name}"),
                    |ord| format!("AddFunc {dll}!#{ord}"),
                )
            }
            Self::RemoveFunction { dll, function_name } => {
                format!("RemoveFunc {dll}!{function_name}")
            }
            Self::RedirectFunction {
                dll,
                function_name,
                target_va,
            } => {
                format!("Redirect {dll}!{function_name}→{target_va:#018x}")
            }
            Self::AddDll { dll } => format!("AddDll {dll}"),
            Self::RemoveDll { dll } => format!("RemoveDll {dll}"),
            Self::RenameDll { old_dll, new_dll } => format!("RenameDll {old_dll}→{new_dll}"),
            Self::ImportByOrdinal { dll, ordinal } => format!("OrdinalImport {dll}!#{ordinal}"),
        }
    }
}

// ─── ImportEntry ─────────────────────────────────────────────────────────────

/// An import entry in the edited import table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// DLL name.
    pub dll: String,
    /// Function name (None for ordinal-only).
    pub function_name: Option<String>,
    /// Import ordinal hint.
    pub ordinal: Option<u16>,
    /// Current IAT slot value (0 if unknown/new).
    pub iat_value: u64,
    /// Redirect target (Some if the IAT has been patched).
    pub redirect_target: Option<u64>,
    /// Whether this import is a delay-load import.
    pub is_delay: bool,
}

impl ImportEntry {
    /// Return the display name for this import (name or ordinal).
    #[must_use]
    pub fn display_name(&self) -> String {
        self.function_name.as_ref().map_or_else(
            || format!("{}!#{}", self.dll, self.ordinal.unwrap_or(0)),
            |n| format!("{}!{}", self.dll, n),
        )
    }

    /// Return true if this import has been redirected.
    #[must_use]
    pub const fn is_redirected(&self) -> bool {
        self.redirect_target.is_some()
    }
}

// ─── IatPatcher ──────────────────────────────────────────────────────────────

/// Patches Import Address Table (IAT) entries in a binary buffer.
pub struct IatPatcher;

impl IatPatcher {
    /// Write a 64-bit pointer into `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 8 > data.len()`.
    pub fn patch64(data: &mut [u8], offset: usize, value: u64) -> Result<(), EditError> {
        if offset + 8 > data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: 8,
                file_size: data.len(),
            });
        }
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// Write a 32-bit pointer into `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 4 > data.len()`.
    pub fn patch32(data: &mut [u8], offset: usize, value: u32) -> Result<(), EditError> {
        if offset + 4 > data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: 4,
                file_size: data.len(),
            });
        }
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// Read a 64-bit pointer from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 8 > data.len()`.
    ///
    /// # Panics
    /// Panics on internal `try_into` slice conversion failure (cannot occur when bounds check passes).
    pub fn read64(data: &[u8], offset: usize) -> Result<u64, EditError> {
        if offset + 8 > data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: 8,
                file_size: data.len(),
            });
        }
        Ok(u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap(),
        ))
    }

    /// Read a 32-bit pointer from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 4 > data.len()`.
    ///
    /// # Panics
    /// Panics on internal `try_into` slice conversion failure (cannot occur when bounds check passes).
    pub fn read32(data: &[u8], offset: usize) -> Result<u32, EditError> {
        if offset + 4 > data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: 4,
                file_size: data.len(),
            });
        }
        Ok(u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        ))
    }

    /// Null out a 64-bit IAT slot (zero the pointer).
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 8 > data.len()`.
    pub fn null64(data: &mut [u8], offset: usize) -> Result<(), EditError> {
        Self::patch64(data, offset, 0)
    }

    /// Null out a 32-bit IAT slot.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + 4 > data.len()`.
    pub fn null32(data: &mut [u8], offset: usize) -> Result<(), EditError> {
        Self::patch32(data, offset, 0)
    }
}

// ─── DelayImportEntry ────────────────────────────────────────────────────────

/// A delay-load import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayImportEntry {
    /// DLL name.
    pub dll: String,
    /// Function name.
    pub function_name: Option<String>,
    /// Import ordinal.
    pub ordinal: Option<u16>,
    /// Bound IAT slot RVA.
    pub bound_iat_rva: u32,
    /// Unload IAT slot RVA.
    pub unload_iat_rva: u32,
    /// Is the DLL loaded at bind time?
    pub is_bound: bool,
}

// ─── DelayImportEditor ───────────────────────────────────────────────────────

/// Editor for delay-load import descriptors.
pub struct DelayImportEditor {
    entries: Vec<DelayImportEntry>,
}

impl DelayImportEditor {
    /// Create an empty delay import editor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a delay import entry.
    pub fn add(&mut self, entry: DelayImportEntry) {
        self.entries.push(entry);
    }

    /// Remove all delay imports for a DLL.
    pub fn remove_dll(&mut self, dll: &str) {
        self.entries.retain(|e| e.dll != dll);
    }

    /// Return all entries for a given DLL.
    #[must_use]
    pub fn for_dll(&self, dll: &str) -> Vec<&DelayImportEntry> {
        self.entries.iter().filter(|e| e.dll == dll).collect()
    }

    /// Return the total entry count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return all unique DLL names.
    #[must_use]
    pub fn dlls(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.dll.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }
}

impl Default for DelayImportEditor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ForwardedExport ─────────────────────────────────────────────────────────

/// A forwarded export entry (DLL forwarding).
///
/// When a PE exports a function that is actually implemented in another DLL,
/// the export entry contains a string like "NTDLL.RtlAllocateHeap".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedExport {
    /// Export name.
    pub export_name: String,
    /// Target DLL name.
    pub target_dll: String,
    /// Target function name.
    pub target_function: String,
    /// Export ordinal.
    pub ordinal: u32,
}

impl ForwardedExport {
    /// Return the forwarding string as it would appear in the export table.
    #[must_use]
    pub fn forward_string(&self) -> String {
        format!("{}.{}", self.target_dll, self.target_function)
    }
}

// ─── ImportEditor ─────────────────────────────────────────────────────────────

/// High-level import table editor.
///
/// Manages a map of DLL → Vec<ImportEntry> and applies [`ImportOp`] operations.
pub struct ImportEditor {
    /// Import table: DLL name → imports.
    entries: HashMap<String, Vec<ImportEntry>>,
    /// Redirected IAT entries: (dll, function) → new target.
    redirects: HashMap<(String, String), u64>,
    /// Delay imports.
    pub delay_imports: DelayImportEditor,
    /// Forwarded exports.
    pub forwarded_exports: Vec<ForwardedExport>,
}

impl ImportEditor {
    /// Create an empty editor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            redirects: HashMap::new(),
            delay_imports: DelayImportEditor::new(),
            forwarded_exports: Vec::new(),
        }
    }

    /// Load from an existing import map.
    #[must_use]
    pub fn from_map(map: HashMap<String, Vec<ImportEntry>>) -> Self {
        Self {
            entries: map,
            redirects: HashMap::new(),
            delay_imports: DelayImportEditor::new(),
            forwarded_exports: Vec::new(),
        }
    }

    /// Return all DLL names in the import table.
    #[must_use]
    pub fn dll_names(&self) -> Vec<&str> {
        self.entries.keys().map(std::string::String::as_str).collect()
    }

    /// Return imports for a given DLL.
    #[must_use]
    pub fn imports_for(&self, dll: &str) -> Option<&Vec<ImportEntry>> {
        self.entries.get(dll)
    }

    /// Return the total number of imports.
    #[must_use]
    pub fn total_import_count(&self) -> usize {
        self.entries.values().map(std::vec::Vec::len).sum()
    }

    /// Apply a single import operation.
    ///
    /// # Errors
    /// Returns an [`EditError`] if the underlying import or remove operation fails.
    pub fn apply(&mut self, op: ImportOp) -> Result<(), EditError> {
        match op {
            ImportOp::AddFunction {
                dll,
                function_name,
                ordinal,
            } => {
                let entries = self.entries.entry(dll.clone()).or_default();
                // Check for duplicate
                let exists = entries
                    .iter()
                    .any(|e| e.function_name.as_deref() == Some(&function_name));
                if !exists {
                    entries.push(ImportEntry {
                        dll,
                        function_name: Some(function_name),
                        ordinal,
                        iat_value: 0,
                        redirect_target: None,
                        is_delay: false,
                    });
                }
            }
            ImportOp::RemoveFunction { dll, function_name } => {
                if let Some(entries) = self.entries.get_mut(&dll) {
                    let len_before = entries.len();
                    entries.retain(|e| e.function_name.as_deref() != Some(&function_name));
                    if entries.len() == len_before {
                        return Err(EditError::ImportError(format!(
                            "function '{function_name}' not found in '{dll}'"
                        )));
                    }
                } else {
                    return Err(EditError::ImportError(format!(
                        "dll '{dll}' not in import table"
                    )));
                }
            }
            ImportOp::RedirectFunction {
                dll,
                function_name,
                target_va,
            } => {
                // Record the redirect
                self.redirects
                    .insert((dll.clone(), function_name.clone()), target_va);
                // Update the entry's redirect_target field
                if let Some(entries) = self.entries.get_mut(&dll) {
                    for entry in entries.iter_mut() {
                        if entry.function_name.as_deref() == Some(&function_name) {
                            entry.redirect_target = Some(target_va);
                            return Ok(());
                        }
                    }
                }
                return Err(EditError::ImportError(format!(
                    "function '{function_name}' not found in '{dll}' for redirect"
                )));
            }
            ImportOp::AddDll { dll } => {
                self.entries.entry(dll).or_default();
            }
            ImportOp::RemoveDll { dll } => {
                if self.entries.remove(&dll).is_none() {
                    return Err(EditError::ImportError(format!(
                        "dll '{dll}' not in import table"
                    )));
                }
            }
            ImportOp::RenameDll { old_dll, new_dll } => {
                if let Some(entries) = self.entries.remove(&old_dll) {
                    // Update dll field in all entries
                    let updated: Vec<ImportEntry> = entries
                        .into_iter()
                        .map(|mut e| {
                            e.dll.clone_from(&new_dll);
                            e
                        })
                        .collect();
                    self.entries.insert(new_dll, updated);
                } else {
                    return Err(EditError::ImportError(format!(
                        "dll '{old_dll}' not in import table"
                    )));
                }
            }
            ImportOp::ImportByOrdinal { dll, ordinal } => {
                let entries = self.entries.entry(dll.clone()).or_default();
                let exists = entries
                    .iter()
                    .any(|e| e.ordinal == Some(ordinal) && e.function_name.is_none());
                if !exists {
                    entries.push(ImportEntry {
                        dll,
                        function_name: None,
                        ordinal: Some(ordinal),
                        iat_value: 0,
                        redirect_target: None,
                        is_delay: false,
                    });
                }
            }
        }
        Ok(())
    }

    /// Apply a batch of operations, collecting results.
    pub fn apply_batch(&mut self, ops: Vec<ImportOp>) -> crate::section_editor::EditResult {
        let mut result = crate::section_editor::EditResult::default();
        for op in ops {
            let desc = op.describe();
            match self.apply(op) {
                Ok(()) => result.applied.push(desc),
                Err(e) => result.failed.push((desc, e.to_string())),
            }
        }
        result.needs_checksum_update = !result.applied.is_empty();
        result
    }

    /// Return all redirected functions as (dll, function, target) triples.
    #[must_use]
    pub fn redirects(&self) -> Vec<(&str, &str, u64)> {
        self.redirects
            .iter()
            .map(|((dll, func), &target)| (dll.as_str(), func.as_str(), target))
            .collect()
    }

    /// Add a forwarded export.
    pub fn add_forwarded_export(&mut self, fwd: ForwardedExport) {
        self.forwarded_exports.push(fwd);
    }

    /// Return all forwarded exports.
    #[must_use]
    pub fn forwarded_exports(&self) -> &[ForwardedExport] {
        &self.forwarded_exports
    }
}

impl Default for ImportEditor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_editor_with_imports() -> ImportEditor {
        let mut ed = ImportEditor::new();
        ed.apply(ImportOp::AddDll {
            dll: "kernel32.dll".to_owned(),
        })
        .unwrap();
        ed.apply(ImportOp::AddFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "VirtualAlloc".to_owned(),
            ordinal: None,
        })
        .unwrap();
        ed.apply(ImportOp::AddFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "VirtualFree".to_owned(),
            ordinal: None,
        })
        .unwrap();
        ed
    }

    #[test]
    fn test_add_dll() {
        let mut ed = ImportEditor::new();
        ed.apply(ImportOp::AddDll {
            dll: "ntdll.dll".to_owned(),
        })
        .unwrap();
        assert!(ed.imports_for("ntdll.dll").is_some());
    }

    #[test]
    fn test_add_function() {
        let ed = make_editor_with_imports();
        assert_eq!(ed.imports_for("kernel32.dll").unwrap().len(), 2);
    }

    #[test]
    fn test_remove_function() {
        let mut ed = make_editor_with_imports();
        ed.apply(ImportOp::RemoveFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "VirtualFree".to_owned(),
        })
        .unwrap();
        assert_eq!(ed.imports_for("kernel32.dll").unwrap().len(), 1);
    }

    #[test]
    fn test_remove_function_not_found() {
        let mut ed = make_editor_with_imports();
        let result = ed.apply(ImportOp::RemoveFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "NonExistent".to_owned(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_dll() {
        let mut ed = make_editor_with_imports();
        ed.apply(ImportOp::RemoveDll {
            dll: "kernel32.dll".to_owned(),
        })
        .unwrap();
        assert!(ed.imports_for("kernel32.dll").is_none());
    }

    #[test]
    fn test_remove_dll_not_found() {
        let mut ed = ImportEditor::new();
        let result = ed.apply(ImportOp::RemoveDll {
            dll: "missing.dll".to_owned(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_rename_dll() {
        let mut ed = make_editor_with_imports();
        ed.apply(ImportOp::RenameDll {
            old_dll: "kernel32.dll".to_owned(),
            new_dll: "KERNEL32.DLL".to_owned(),
        })
        .unwrap();
        assert!(ed.imports_for("KERNEL32.DLL").is_some());
        assert!(ed.imports_for("kernel32.dll").is_none());
        // Entries should have updated dll field
        assert_eq!(
            ed.imports_for("KERNEL32.DLL").unwrap()[0].dll,
            "KERNEL32.DLL"
        );
    }

    #[test]
    fn test_redirect_function() {
        let mut ed = make_editor_with_imports();
        ed.apply(ImportOp::RedirectFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "VirtualAlloc".to_owned(),
            target_va: 0xDEAD_BEEF_1234_5678,
        })
        .unwrap();
        let entries = ed.imports_for("kernel32.dll").unwrap();
        let va_entry = entries
            .iter()
            .find(|e| e.function_name.as_deref() == Some("VirtualAlloc"))
            .unwrap();
        assert_eq!(va_entry.redirect_target, Some(0xDEAD_BEEF_1234_5678));
    }

    #[test]
    fn test_redirect_not_found() {
        let mut ed = make_editor_with_imports();
        let result = ed.apply(ImportOp::RedirectFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "NotAFunction".to_owned(),
            target_va: 0x1234,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_import_by_ordinal() {
        let mut ed = ImportEditor::new();
        ed.apply(ImportOp::ImportByOrdinal {
            dll: "ws2_32.dll".to_owned(),
            ordinal: 23,
        })
        .unwrap();
        let entries = ed.imports_for("ws2_32.dll").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ordinal, Some(23));
        assert!(entries[0].function_name.is_none());
    }

    #[test]
    fn test_total_import_count() {
        let ed = make_editor_with_imports();
        assert_eq!(ed.total_import_count(), 2);
    }

    #[test]
    fn test_import_entry_display_name() {
        let entry = ImportEntry {
            dll: "ntdll.dll".to_owned(),
            function_name: Some("NtCreateFile".to_owned()),
            ordinal: None,
            iat_value: 0,
            redirect_target: None,
            is_delay: false,
        };
        assert_eq!(entry.display_name(), "ntdll.dll!NtCreateFile");
    }

    #[test]
    fn test_import_entry_ordinal_display() {
        let entry = ImportEntry {
            dll: "ws2_32.dll".to_owned(),
            function_name: None,
            ordinal: Some(23),
            iat_value: 0,
            redirect_target: None,
            is_delay: false,
        };
        assert_eq!(entry.display_name(), "ws2_32.dll!#23");
    }

    #[test]
    fn test_iat_patcher_patch64() {
        let mut data = vec![0u8; 16];
        IatPatcher::patch64(&mut data, 0, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn test_iat_patcher_read64() {
        let mut data = vec![0u8; 16];
        IatPatcher::patch64(&mut data, 4, 0xDEAD_BEEF_CAFE_BABE).unwrap();
        let v = IatPatcher::read64(&data, 4).unwrap();
        assert_eq!(v, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn test_iat_patcher_patch32() {
        let mut data = vec![0u8; 8];
        IatPatcher::patch32(&mut data, 2, 0xDEAD_BEEF).unwrap();
        let v = IatPatcher::read32(&data, 2).unwrap();
        assert_eq!(v, 0xDEAD_BEEF);
    }

    #[test]
    fn test_iat_patcher_out_of_bounds() {
        let mut data = vec![0u8; 4];
        let result = IatPatcher::patch64(&mut data, 0, 0);
        assert!(matches!(result, Err(EditError::PatchOutOfBounds { .. })));
    }

    #[test]
    fn test_delay_import_editor() {
        let mut die = DelayImportEditor::new();
        die.add(DelayImportEntry {
            dll: "ole32.dll".to_owned(),
            function_name: Some("CoInitialize".to_owned()),
            ordinal: None,
            bound_iat_rva: 0x5000,
            unload_iat_rva: 0x6000,
            is_bound: false,
        });
        assert_eq!(die.count(), 1);
        assert_eq!(die.dlls(), vec!["ole32.dll"]);
    }

    #[test]
    fn test_forwarded_export_string() {
        let fwd = ForwardedExport {
            export_name: "HeapAlloc".to_owned(),
            target_dll: "NTDLL".to_owned(),
            target_function: "RtlAllocateHeap".to_owned(),
            ordinal: 42,
        };
        assert_eq!(fwd.forward_string(), "NTDLL.RtlAllocateHeap");
    }

    #[test]
    fn test_batch_apply() {
        let mut ed = ImportEditor::new();
        let ops = vec![
            ImportOp::AddDll {
                dll: "a.dll".to_owned(),
            },
            ImportOp::AddFunction {
                dll: "a.dll".to_owned(),
                function_name: "Foo".to_owned(),
                ordinal: None,
            },
            ImportOp::AddFunction {
                dll: "b.dll".to_owned(),
                function_name: "Bar".to_owned(),
                ordinal: None,
            },
        ];
        let result = ed.apply_batch(ops);
        assert_eq!(result.applied_count(), 3);
        assert!(result.is_success());
    }

    #[test]
    fn test_import_is_redirected() {
        let entry = ImportEntry {
            dll: "test.dll".to_owned(),
            function_name: Some("Func".to_owned()),
            ordinal: None,
            iat_value: 0x1000,
            redirect_target: Some(0x2000),
            is_delay: false,
        };
        assert!(entry.is_redirected());
    }

    #[test]
    fn test_redirects_accessor() {
        let mut ed = make_editor_with_imports();
        ed.apply(ImportOp::RedirectFunction {
            dll: "kernel32.dll".to_owned(),
            function_name: "VirtualAlloc".to_owned(),
            target_va: 0x4000,
        })
        .unwrap();
        let redirects = ed.redirects();
        assert_eq!(redirects.len(), 1);
        assert!(
            redirects
                .iter()
                .any(|(_, func, target)| *func == "VirtualAlloc" && *target == 0x4000)
        );
    }

    #[test]
    fn test_iat_patcher_null64() {
        let mut data = vec![0xFFu8; 16];
        IatPatcher::null64(&mut data, 0).unwrap();
        assert_eq!(&data[0..8], &[0u8; 8]);
    }

    #[test]
    fn test_iat_patcher_null32() {
        let mut data = vec![0xFFu8; 8];
        IatPatcher::null32(&mut data, 0).unwrap();
        assert_eq!(&data[0..4], &[0u8; 4]);
    }

    #[test]
    fn test_delay_import_remove_dll() {
        let mut die = DelayImportEditor::new();
        die.add(DelayImportEntry {
            dll: "comctl32.dll".to_owned(),
            function_name: Some("InitCommonControls".to_owned()),
            ordinal: None,
            bound_iat_rva: 0,
            unload_iat_rva: 0,
            is_bound: false,
        });
        die.add(DelayImportEntry {
            dll: "shell32.dll".to_owned(),
            function_name: Some("ShellExecute".to_owned()),
            ordinal: None,
            bound_iat_rva: 0,
            unload_iat_rva: 0,
            is_bound: false,
        });
        assert_eq!(die.count(), 2);
        die.remove_dll("comctl32.dll");
        assert_eq!(die.count(), 1);
    }

    #[test]
    fn test_import_editor_add_duplicate_ignored() {
        let mut ed = ImportEditor::new();
        ed.apply(ImportOp::AddFunction {
            dll: "test.dll".to_owned(),
            function_name: "Func".to_owned(),
            ordinal: None,
        })
        .unwrap();
        // Adding same function again should not duplicate
        ed.apply(ImportOp::AddFunction {
            dll: "test.dll".to_owned(),
            function_name: "Func".to_owned(),
            ordinal: None,
        })
        .unwrap();
        assert_eq!(ed.imports_for("test.dll").unwrap().len(), 1);
    }

    #[test]
    fn test_import_editor_dll_names() {
        let mut ed = ImportEditor::new();
        ed.apply(ImportOp::AddDll {
            dll: "a.dll".to_owned(),
        })
        .unwrap();
        ed.apply(ImportOp::AddDll {
            dll: "b.dll".to_owned(),
        })
        .unwrap();
        let names = ed.dll_names();
        assert!(names.contains(&"a.dll"));
        assert!(names.contains(&"b.dll"));
    }

    #[test]
    fn test_forwarded_exports_list() {
        let mut ed = ImportEditor::new();
        ed.add_forwarded_export(ForwardedExport {
            export_name: "RtlMoveMemory".to_owned(),
            target_dll: "NTDLL".to_owned(),
            target_function: "memmove".to_owned(),
            ordinal: 1,
        });
        assert_eq!(ed.forwarded_exports().len(), 1);
        assert_eq!(ed.forwarded_exports()[0].forward_string(), "NTDLL.memmove");
    }

    #[test]
    fn test_delay_import_for_dll() {
        let mut die = DelayImportEditor::new();
        die.add(DelayImportEntry {
            dll: "d.dll".to_owned(),
            function_name: Some("F1".to_owned()),
            ordinal: None,
            bound_iat_rva: 0,
            unload_iat_rva: 0,
            is_bound: false,
        });
        die.add(DelayImportEntry {
            dll: "d.dll".to_owned(),
            function_name: Some("F2".to_owned()),
            ordinal: None,
            bound_iat_rva: 0,
            unload_iat_rva: 0,
            is_bound: false,
        });
        assert_eq!(die.for_dll("d.dll").len(), 2);
    }
}
