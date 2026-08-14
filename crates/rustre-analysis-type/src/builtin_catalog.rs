//! Built-in type catalog.
//!
//! Provides a curated database of well-known C/C++/Win32 type definitions so
//! that `analysis_type_query` can answer name-based lookups for Windows
//! structs, PE structures, VCRT placeholders, C-runtime integer typedefs, and
//! common STL container shapes.
//!
//! The catalog is populated lazily on first access via [`once_cell`]-style
//! `OnceLock`, so the construction cost is paid once per process.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// A single field within a struct-shaped [`TypeRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltinField {
    pub name: String,
    pub ty: String,
    pub offset: usize,
}

/// A record describing one entry in the built-in type catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeRecord {
    pub name: String,
    pub size: Option<usize>,
    /// One of `"typedef"`, `"struct"`, `"handle"`, `"primitive"`, `"placeholder"`.
    pub kind: String,
    pub fields: Vec<BuiltinField>,
}

impl TypeRecord {
    fn typedef(name: &str, size: usize) -> Self {
        Self {
            name: name.to_string(),
            size: Some(size),
            kind: "typedef".to_string(),
            fields: Vec::new(),
        }
    }

    fn handle(name: &str) -> Self {
        Self {
            name: name.to_string(),
            size: Some(8),
            kind: "handle".to_string(),
            fields: Vec::new(),
        }
    }

    fn primitive(name: &str, size: usize) -> Self {
        Self {
            name: name.to_string(),
            size: Some(size),
            kind: "primitive".to_string(),
            fields: Vec::new(),
        }
    }

    fn placeholder(name: &str) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            kind: "placeholder".to_string(),
            fields: Vec::new(),
        }
    }

    fn structure(name: &str, size: usize, fields: Vec<(&str, &str, usize)>) -> Self {
        Self {
            name: name.to_string(),
            size: Some(size),
            kind: "struct".to_string(),
            fields: fields
                .into_iter()
                .map(|(n, t, o)| BuiltinField {
                    name: n.to_string(),
                    ty: t.to_string(),
                    offset: o,
                })
                .collect(),
        }
    }
}

static CATALOG: OnceLock<Vec<TypeRecord>> = OnceLock::new();

fn catalog() -> &'static Vec<TypeRecord> {
    CATALOG.get_or_init(build_catalog)
}

/// Return a snapshot of every built-in type record.
#[must_use]
pub fn list_builtin_types() -> Vec<TypeRecord> {
    catalog().clone()
}

/// Look up a built-in type by case-insensitive exact match.
#[must_use]
pub fn lookup_builtin_type(name: &str) -> Option<TypeRecord> {
    let key = name.to_ascii_lowercase();
    catalog()
        .iter()
        .find(|r| r.name.to_ascii_lowercase() == key)
        .cloned()
}

fn build_catalog() -> Vec<TypeRecord> {
    let mut v = Vec::new();
    push_windows_core(&mut v);
    push_pe_structures(&mut v);
    push_vcrt(&mut v);
    push_c_runtime(&mut v);
    push_stl_placeholders(&mut v);
    v
}

fn push_windows_core(v: &mut Vec<TypeRecord>) {
    // Handles — opaque pointer-sized values.
    for h in ["HANDLE", "HWND", "HMODULE", "HINSTANCE", "HKEY", "HBITMAP", "HDC", "HFONT", "HICON", "HMENU"] {
        v.push(TypeRecord::handle(h));
    }
    // Integer / pointer typedefs.
    v.push(TypeRecord::typedef("DWORD", 4));
    v.push(TypeRecord::typedef("WORD", 2));
    v.push(TypeRecord::typedef("BYTE", 1));
    v.push(TypeRecord::typedef("BOOL", 4));
    v.push(TypeRecord::typedef("HRESULT", 4));
    v.push(TypeRecord::typedef("LPVOID", 8));
    v.push(TypeRecord::typedef("LPCVOID", 8));
    v.push(TypeRecord::typedef("LPCSTR", 8));
    v.push(TypeRecord::typedef("LPSTR", 8));
    v.push(TypeRecord::typedef("LPWSTR", 8));
    v.push(TypeRecord::typedef("LPCWSTR", 8));
    v.push(TypeRecord::typedef("LPARAM", 8));
    v.push(TypeRecord::typedef("WPARAM", 8));
    v.push(TypeRecord::typedef("LRESULT", 8));
    v.push(TypeRecord::typedef("ATOM", 2));
    v.push(TypeRecord::typedef("LONG", 4));
    v.push(TypeRecord::typedef("ULONG", 4));
    v.push(TypeRecord::typedef("LONGLONG", 8));
    v.push(TypeRecord::typedef("ULONGLONG", 8));

    // Structs (first 3 fields + total size).
    v.push(TypeRecord::structure("LARGE_INTEGER", 8, vec![
        ("LowPart", "DWORD", 0),
        ("HighPart", "LONG", 4),
        ("QuadPart", "LONGLONG", 0),
    ]));
    v.push(TypeRecord::structure("ULARGE_INTEGER", 8, vec![
        ("LowPart", "DWORD", 0),
        ("HighPart", "DWORD", 4),
        ("QuadPart", "ULONGLONG", 0),
    ]));
    v.push(TypeRecord::structure("SYSTEMTIME", 16, vec![
        ("wYear", "WORD", 0),
        ("wMonth", "WORD", 2),
        ("wDayOfWeek", "WORD", 4),
    ]));
    v.push(TypeRecord::structure("FILETIME", 8, vec![
        ("dwLowDateTime", "DWORD", 0),
        ("dwHighDateTime", "DWORD", 4),
        ("", "", 0),
    ]));
    v.push(TypeRecord::structure("SECURITY_ATTRIBUTES", 24, vec![
        ("nLength", "DWORD", 0),
        ("lpSecurityDescriptor", "LPVOID", 8),
        ("bInheritHandle", "BOOL", 16),
    ]));
    v.push(TypeRecord::structure("OVERLAPPED", 32, vec![
        ("Internal", "ULONG_PTR", 0),
        ("InternalHigh", "ULONG_PTR", 8),
        ("Offset", "DWORD", 16),
    ]));
    v.push(TypeRecord::structure("POINT", 8, vec![
        ("x", "LONG", 0),
        ("y", "LONG", 4),
        ("", "", 0),
    ]));
    v.push(TypeRecord::structure("RECT", 16, vec![
        ("left", "LONG", 0),
        ("top", "LONG", 4),
        ("right", "LONG", 8),
    ]));
    v.push(TypeRecord::structure("SIZE", 8, vec![
        ("cx", "LONG", 0),
        ("cy", "LONG", 4),
        ("", "", 0),
    ]));
    v.push(TypeRecord::structure("MSG", 48, vec![
        ("hwnd", "HWND", 0),
        ("message", "UINT", 8),
        ("wParam", "WPARAM", 16),
    ]));
    v.push(TypeRecord::structure("PROCESS_INFORMATION", 24, vec![
        ("hProcess", "HANDLE", 0),
        ("hThread", "HANDLE", 8),
        ("dwProcessId", "DWORD", 16),
    ]));
    v.push(TypeRecord::structure("STARTUPINFOA", 104, vec![
        ("cb", "DWORD", 0),
        ("lpReserved", "LPSTR", 8),
        ("lpDesktop", "LPSTR", 16),
    ]));
    v.push(TypeRecord::structure("STARTUPINFOW", 104, vec![
        ("cb", "DWORD", 0),
        ("lpReserved", "LPWSTR", 8),
        ("lpDesktop", "LPWSTR", 16),
    ]));
    v.push(TypeRecord::structure("WIN32_FIND_DATAA", 320, vec![
        ("dwFileAttributes", "DWORD", 0),
        ("ftCreationTime", "FILETIME", 4),
        ("ftLastAccessTime", "FILETIME", 12),
    ]));
    v.push(TypeRecord::structure("WIN32_FIND_DATAW", 592, vec![
        ("dwFileAttributes", "DWORD", 0),
        ("ftCreationTime", "FILETIME", 4),
        ("ftLastAccessTime", "FILETIME", 12),
    ]));
}

fn push_pe_structures(v: &mut Vec<TypeRecord>) {
    v.push(TypeRecord::structure("IMAGE_DOS_HEADER", 64, vec![
        ("e_magic", "WORD", 0),
        ("e_cblp", "WORD", 2),
        ("e_cp", "WORD", 4),
    ]));
    v.push(TypeRecord::structure("IMAGE_FILE_HEADER", 20, vec![
        ("Machine", "WORD", 0),
        ("NumberOfSections", "WORD", 2),
        ("TimeDateStamp", "DWORD", 4),
    ]));
    v.push(TypeRecord::structure("IMAGE_DATA_DIRECTORY", 8, vec![
        ("VirtualAddress", "DWORD", 0),
        ("Size", "DWORD", 4),
        ("", "", 0),
    ]));
    v.push(TypeRecord::structure("IMAGE_OPTIONAL_HEADER32", 224, vec![
        ("Magic", "WORD", 0),
        ("MajorLinkerVersion", "BYTE", 2),
        ("MinorLinkerVersion", "BYTE", 3),
    ]));
    v.push(TypeRecord::structure("IMAGE_OPTIONAL_HEADER64", 240, vec![
        ("Magic", "WORD", 0),
        ("MajorLinkerVersion", "BYTE", 2),
        ("MinorLinkerVersion", "BYTE", 3),
    ]));
    v.push(TypeRecord::structure("IMAGE_NT_HEADERS32", 248, vec![
        ("Signature", "DWORD", 0),
        ("FileHeader", "IMAGE_FILE_HEADER", 4),
        ("OptionalHeader", "IMAGE_OPTIONAL_HEADER32", 24),
    ]));
    v.push(TypeRecord::structure("IMAGE_NT_HEADERS64", 264, vec![
        ("Signature", "DWORD", 0),
        ("FileHeader", "IMAGE_FILE_HEADER", 4),
        ("OptionalHeader", "IMAGE_OPTIONAL_HEADER64", 24),
    ]));
    v.push(TypeRecord::structure("IMAGE_SECTION_HEADER", 40, vec![
        ("Name", "BYTE[8]", 0),
        ("VirtualSize", "DWORD", 8),
        ("VirtualAddress", "DWORD", 12),
    ]));
    v.push(TypeRecord::structure("IMAGE_IMPORT_DESCRIPTOR", 20, vec![
        ("OriginalFirstThunk", "DWORD", 0),
        ("TimeDateStamp", "DWORD", 4),
        ("ForwarderChain", "DWORD", 8),
    ]));
    v.push(TypeRecord::structure("IMAGE_EXPORT_DIRECTORY", 40, vec![
        ("Characteristics", "DWORD", 0),
        ("TimeDateStamp", "DWORD", 4),
        ("MajorVersion", "WORD", 8),
    ]));
    v.push(TypeRecord::structure("IMAGE_TLS_DIRECTORY32", 24, vec![
        ("StartAddressOfRawData", "DWORD", 0),
        ("EndAddressOfRawData", "DWORD", 4),
        ("AddressOfIndex", "DWORD", 8),
    ]));
    v.push(TypeRecord::structure("IMAGE_TLS_DIRECTORY64", 40, vec![
        ("StartAddressOfRawData", "ULONGLONG", 0),
        ("EndAddressOfRawData", "ULONGLONG", 8),
        ("AddressOfIndex", "ULONGLONG", 16),
    ]));
}

fn push_vcrt(v: &mut Vec<TypeRecord>) {
    v.push(TypeRecord::structure("_iobuf", 48, vec![
        ("_ptr", "char*", 0),
        ("_cnt", "int", 8),
        ("_base", "char*", 16),
    ]));
    v.push(TypeRecord::structure("FILE", 48, vec![
        ("_Placeholder", "void*", 0),
        ("", "", 0),
        ("", "", 0),
    ]));
    v.push(TypeRecord::placeholder("__crt_locale_data"));
}

fn push_c_runtime(v: &mut Vec<TypeRecord>) {
    v.push(TypeRecord::typedef("size_t", 8));
    v.push(TypeRecord::typedef("ssize_t", 8));
    v.push(TypeRecord::typedef("ptrdiff_t", 8));
    v.push(TypeRecord::typedef("intptr_t", 8));
    v.push(TypeRecord::typedef("uintptr_t", 8));
    v.push(TypeRecord::primitive("int8_t", 1));
    v.push(TypeRecord::primitive("int16_t", 2));
    v.push(TypeRecord::primitive("int32_t", 4));
    v.push(TypeRecord::primitive("int64_t", 8));
    v.push(TypeRecord::primitive("uint8_t", 1));
    v.push(TypeRecord::primitive("uint16_t", 2));
    v.push(TypeRecord::primitive("uint32_t", 4));
    v.push(TypeRecord::primitive("uint64_t", 8));
    v.push(TypeRecord::primitive("char", 1));
    v.push(TypeRecord::primitive("wchar_t", 2));
    v.push(TypeRecord::primitive("short", 2));
    v.push(TypeRecord::primitive("int", 4));
    v.push(TypeRecord::primitive("long", 4));
    v.push(TypeRecord::primitive("float", 4));
    v.push(TypeRecord::primitive("double", 8));
    v.push(TypeRecord::primitive("void*", 8));
}

fn push_stl_placeholders(v: &mut Vec<TypeRecord>) {
    // MSVC ABI: std::string and std::wstring are 32 bytes (SSO + size + capacity).
    v.push(TypeRecord::structure("std::string", 32, vec![
        ("_Mypair", "_Compressed_pair", 0),
        ("_Mysize", "size_t", 16),
        ("_Myres", "size_t", 24),
    ]));
    v.push(TypeRecord::structure("std::wstring", 32, vec![
        ("_Mypair", "_Compressed_pair", 0),
        ("_Mysize", "size_t", 16),
        ("_Myres", "size_t", 24),
    ]));
    v.push(TypeRecord::structure("std::vector", 24, vec![
        ("_Myfirst", "T*", 0),
        ("_Mylast", "T*", 8),
        ("_Myend", "T*", 16),
    ]));
    v.push(TypeRecord::placeholder("std::map"));
    v.push(TypeRecord::structure("std::shared_ptr", 16, vec![
        ("_Ptr", "T*", 0),
        ("_Rep", "_Ref_count_base*", 8),
        ("", "", 0),
    ]));
    v.push(TypeRecord::structure("std::unique_ptr", 8, vec![
        ("_Mypair", "T*", 0),
        ("", "", 0),
        ("", "", 0),
    ]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_non_empty_and_unique_by_name() {
        let all = list_builtin_types();
        assert!(all.len() >= 80, "expected at least 80 entries, got {}", all.len());
        let mut names: Vec<&str> = all.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate type names in catalog");
    }

    #[test]
    fn windows_core_handles_present() {
        for h in ["HANDLE", "HWND", "HMODULE"] {
            let r = lookup_builtin_type(h).unwrap_or_else(|| panic!("missing {h}"));
            assert_eq!(r.kind, "handle");
            assert_eq!(r.size, Some(8));
        }
    }

    #[test]
    fn windows_typedefs_sized() {
        assert_eq!(lookup_builtin_type("DWORD").unwrap().size, Some(4));
        assert_eq!(lookup_builtin_type("WORD").unwrap().size, Some(2));
        assert_eq!(lookup_builtin_type("BYTE").unwrap().size, Some(1));
        assert_eq!(lookup_builtin_type("BOOL").unwrap().size, Some(4));
        assert_eq!(lookup_builtin_type("LPCWSTR").unwrap().size, Some(8));
    }

    #[test]
    fn pe_structures_have_anchor_fields() {
        let dos = lookup_builtin_type("IMAGE_DOS_HEADER").unwrap();
        assert_eq!(dos.kind, "struct");
        assert_eq!(dos.fields[0].name, "e_magic");
        assert_eq!(dos.size, Some(64));

        let nt64 = lookup_builtin_type("IMAGE_NT_HEADERS64").unwrap();
        assert_eq!(nt64.fields[0].name, "Signature");
        assert!(nt64.size.unwrap() >= 248);

        let sec = lookup_builtin_type("IMAGE_SECTION_HEADER").unwrap();
        assert_eq!(sec.size, Some(40));
    }

    #[test]
    fn case_insensitive_lookup() {
        assert!(lookup_builtin_type("dword").is_some());
        assert!(lookup_builtin_type("Handle").is_some());
        assert!(lookup_builtin_type("image_dos_header").is_some());
    }

    #[test]
    fn unknown_type_returns_none() {
        assert!(lookup_builtin_type("NotARealTypeXYZ").is_none());
    }

    #[test]
    fn c_runtime_types_present() {
        assert_eq!(lookup_builtin_type("size_t").unwrap().size, Some(8));
        assert_eq!(lookup_builtin_type("uint32_t").unwrap().size, Some(4));
        assert_eq!(lookup_builtin_type("int64_t").unwrap().size, Some(8));
        assert_eq!(lookup_builtin_type("uint8_t").unwrap().kind, "primitive");
    }

    #[test]
    fn vcrt_types_present() {
        assert!(lookup_builtin_type("FILE").is_some());
        assert!(lookup_builtin_type("_iobuf").is_some());
        let locale = lookup_builtin_type("__crt_locale_data").unwrap();
        assert_eq!(locale.kind, "placeholder");
        assert!(locale.size.is_none());
    }

    #[test]
    fn stl_placeholders_present() {
        let s = lookup_builtin_type("std::string").unwrap();
        assert_eq!(s.size, Some(32));
        assert!(lookup_builtin_type("std::vector").is_some());
        assert!(lookup_builtin_type("std::shared_ptr").is_some());
        assert!(lookup_builtin_type("std::unique_ptr").is_some());
        let m = lookup_builtin_type("std::map").unwrap();
        assert_eq!(m.kind, "placeholder");
    }

    #[test]
    fn record_roundtrips_through_serde_json() {
        let r = lookup_builtin_type("RECT").unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let back: TypeRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
