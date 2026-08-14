//! PDB auto-discovery for a given binary path.
//!
//! Locates a matching `.pdb` next to a binary the way MSVC/Rust release
//! builds typically lay them out, so callers don't have to feed the path in
//! manually.

use std::path::{Path, PathBuf};

use rustre_loader_pe::PeInfo;

/// Try to locate a PDB file matching `binary_path`. Checks:
///   1. `<stem>.pdb` in the same directory as the binary
///   2. `<stem>.pdb` in a sibling `pdb/` directory
///   3. The PDB path embedded in the PE `CodeView` debug directory (if `pe_info` is provided)
///
/// Returns the first existing path, or `None`.
#[must_use]
pub fn discover_pdb_for_binary(
    binary_path: &Path,
    pe_info: Option<&PeInfo>,
) -> Option<PathBuf> {
    let stem = binary_path.file_stem()?;
    let parent = binary_path.parent().unwrap_or_else(|| Path::new("."));

    // 1. <stem>.pdb beside the binary
    let sibling = parent.join(format!("{}.pdb", stem.to_string_lossy()));
    if sibling.is_file() {
        return Some(sibling);
    }

    // 2. <stem>.pdb in a sibling `pdb/` directory
    let in_pdb_dir = parent.join("pdb").join(format!("{}.pdb", stem.to_string_lossy()));
    if in_pdb_dir.is_file() {
        return Some(in_pdb_dir);
    }

    // 3. CodeView-embedded PDB path
    if let Some(info) = pe_info
        && let Some(embedded) = info.pdb_path()
    {
        let embedded_path = PathBuf::from(embedded);
        if embedded_path.is_file() {
            return Some(embedded_path);
        }
        // Try just the filename next to the binary, in case the embedded
        // path is the build-machine absolute path that no longer exists.
        if let Some(name) = embedded_path.file_name() {
            let local = parent.join(name);
            if local.is_file() {
                return Some(local);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_sibling_pdb() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("foo.exe");
        let pdb = dir.path().join("foo.pdb");
        fs::write(&exe, b"x").unwrap();
        fs::write(&pdb, b"y").unwrap();
        assert_eq!(discover_pdb_for_binary(&exe, None), Some(pdb));
    }

    #[test]
    fn finds_pdb_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bar.exe");
        fs::write(&exe, b"x").unwrap();
        let sub = dir.path().join("pdb");
        fs::create_dir(&sub).unwrap();
        let pdb = sub.join("bar.pdb");
        fs::write(&pdb, b"y").unwrap();
        assert_eq!(discover_pdb_for_binary(&exe, None), Some(pdb));
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("baz.exe");
        fs::write(&exe, b"x").unwrap();
        assert!(discover_pdb_for_binary(&exe, None).is_none());
    }
}
