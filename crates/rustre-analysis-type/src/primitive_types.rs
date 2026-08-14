//! `primitive_types` — pre-populated catalogue of all C/C++ primitive types.
//!
//! Every standard primitive is registered at module initialisation: C99/C11
//! standard integers, ISO C floating-point types, Windows SDK typedefs
//! (`BYTE`, `WORD`, `DWORD`, `QWORD`, `HANDLE`, `BOOL`, etc.) and common POSIX typedefs
//! (`pid_t`, `uid_t`, `gid_t`, `off_t`, `ssize_t`, etc.).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Primitive type descriptor ──────────────────────────────────────────────────

/// Signedness of a primitive integer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signedness {
    Signed,
    Unsigned,
    NotApplicable,
}

/// High-level family of a primitive type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveFamily {
    Void,
    Boolean,
    Integer,
    Float,
    /// A pointer-sized integer (`uintptr_t` / `ptrdiff_t` / `size_t`).
    PtrSizedInteger,
    /// A wide-character type (`wchar_t`, `char16_t`, `char32_t`).
    WideChar,
    /// An opaque handle (HANDLE, HMODULE, …).
    OpaqueHandle,
}

/// A fully-described primitive type.
///
/// Note: only `Serialize` is derived; deserialization is not supported for
/// static-lifetime types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrimitiveType {
    /// Canonical C name (e.g. `"uint32_t"`).
    pub name: &'static str,
    /// Byte width; 0 for `void`.
    pub size: u8,
    pub signedness: Signedness,
    pub family: PrimitiveFamily,
    /// Alternative / alias names (e.g. `"DWORD"` → `["unsigned long", "uint32_t"]`).
    pub aliases: &'static [&'static str],
}

// ── Static primitive table ────────────────────────────────────────────────────

static PRIMITIVES: &[PrimitiveType] = &[
    // ── void ──────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "void",
        size: 0,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Void,
        aliases: &[],
    },
    // ── bool ──────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "bool",
        size: 1,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Boolean,
        aliases: &["_Bool", "BOOL"],
    },
    // ── char ──────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "char",
        size: 1,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["CHAR"],
    },
    PrimitiveType {
        name: "signed char",
        size: 1,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["int8_t"],
    },
    PrimitiveType {
        name: "unsigned char",
        size: 1,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["uint8_t", "BYTE", "UCHAR", "u8"],
    },
    // ── short ─────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "short",
        size: 2,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["short int", "signed short", "int16_t"],
    },
    PrimitiveType {
        name: "unsigned short",
        size: 2,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["uint16_t", "WORD", "USHORT", "WCHAR"],
    },
    // ── int ───────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "int",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["signed int", "signed", "int32_t", "INT"],
    },
    PrimitiveType {
        name: "unsigned int",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["uint32_t", "DWORD", "UINT", "u32"],
    },
    // ── long ──────────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "long",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["long int", "signed long", "LONG"],
    },
    PrimitiveType {
        name: "unsigned long",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["ULONG"],
    },
    // ── long long ─────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "long long",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[
            "long long int",
            "signed long long",
            "int64_t",
            "LONGLONG",
            "INT64",
            "__int64",
        ],
    },
    PrimitiveType {
        name: "unsigned long long",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["uint64_t", "QWORD", "ULONGLONG", "UINT64", "DWORD64"],
    },
    // ── floating-point ────────────────────────────────────────────────────────
    PrimitiveType {
        name: "float",
        size: 4,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Float,
        aliases: &["FLOAT"],
    },
    PrimitiveType {
        name: "double",
        size: 8,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Float,
        aliases: &["DOUBLE"],
    },
    PrimitiveType {
        name: "long double",
        size: 10,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Float,
        aliases: &[],
    },
    // ── ptr-sized integers ────────────────────────────────────────────────────
    PrimitiveType {
        name: "size_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &["SIZE_T"],
    },
    PrimitiveType {
        name: "ptrdiff_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &[],
    },
    PrimitiveType {
        name: "uintptr_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &["ULONG_PTR", "DWORD_PTR"],
    },
    PrimitiveType {
        name: "intptr_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &["LONG_PTR"],
    },
    // ── wide-char ─────────────────────────────────────────────────────────────
    PrimitiveType {
        name: "wchar_t",
        size: 2,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::WideChar,
        aliases: &["TCHAR"],
    },
    PrimitiveType {
        name: "char16_t",
        size: 2,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::WideChar,
        aliases: &[],
    },
    PrimitiveType {
        name: "char32_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::WideChar,
        aliases: &[],
    },
    // ── Windows opaque handles ────────────────────────────────────────────────
    PrimitiveType {
        name: "HANDLE",
        size: 8,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::OpaqueHandle,
        aliases: &[],
    },
    PrimitiveType {
        name: "HMODULE",
        size: 8,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::OpaqueHandle,
        aliases: &["HINSTANCE"],
    },
    PrimitiveType {
        name: "HKEY",
        size: 8,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::OpaqueHandle,
        aliases: &[],
    },
    PrimitiveType {
        name: "HWND",
        size: 8,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::OpaqueHandle,
        aliases: &[],
    },
    PrimitiveType {
        name: "HRESULT",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "NTSTATUS",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    // ── POSIX types ───────────────────────────────────────────────────────────
    PrimitiveType {
        name: "pid_t",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "uid_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "gid_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "off_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &["off64_t"],
    },
    PrimitiveType {
        name: "ssize_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::PtrSizedInteger,
        aliases: &[],
    },
    PrimitiveType {
        name: "mode_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "dev_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "ino_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "nlink_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "time_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "clock_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "suseconds_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    PrimitiveType {
        name: "socklen_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &[],
    },
    // ── extra fixed-width aliases ─────────────────────────────────────────────
    PrimitiveType {
        name: "int8_t",
        size: 1,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["i8"],
    },
    PrimitiveType {
        name: "int16_t",
        size: 2,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["i16"],
    },
    PrimitiveType {
        name: "int32_t",
        size: 4,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["i32"],
    },
    PrimitiveType {
        name: "int64_t",
        size: 8,
        signedness: Signedness::Signed,
        family: PrimitiveFamily::Integer,
        aliases: &["i64"],
    },
    PrimitiveType {
        name: "uint8_t",
        size: 1,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["u8"],
    },
    PrimitiveType {
        name: "uint16_t",
        size: 2,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["u16"],
    },
    PrimitiveType {
        name: "uint32_t",
        size: 4,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["u32"],
    },
    PrimitiveType {
        name: "uint64_t",
        size: 8,
        signedness: Signedness::Unsigned,
        family: PrimitiveFamily::Integer,
        aliases: &["u64"],
    },
    // ── SIMD / extended ───────────────────────────────────────────────────────
    PrimitiveType {
        name: "__m128",
        size: 16,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Float,
        aliases: &["__m128i", "__m128d"],
    },
    PrimitiveType {
        name: "__m256",
        size: 32,
        signedness: Signedness::NotApplicable,
        family: PrimitiveFamily::Float,
        aliases: &["__m256i", "__m256d"],
    },
];

// ── PrimitiveRegistry ─────────────────────────────────────────────────────────

/// Lookup index over all primitive types.  Allows O(1) lookup by canonical
/// name or alias.
pub struct PrimitiveRegistry {
    /// `canonical_name → &PrimitiveType`
    by_name: HashMap<&'static str, &'static PrimitiveType>,
    /// `alias → canonical_name`
    alias_map: HashMap<&'static str, &'static str>,
}

impl PrimitiveRegistry {
    /// Build the registry from the static primitive table.
    #[must_use]
    pub fn new() -> Self {
        let mut by_name: HashMap<&'static str, &'static PrimitiveType> =
            HashMap::with_capacity(PRIMITIVES.len());
        let mut alias_map: HashMap<&'static str, &'static str> = HashMap::new();

        for p in PRIMITIVES {
            by_name.insert(p.name, p);
            for &alias in p.aliases {
                alias_map.insert(alias, p.name);
            }
        }

        Self { by_name, alias_map }
    }

    /// Look up by canonical name (e.g. `"uint32_t"`).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static PrimitiveType> {
        self.by_name.get(name).copied()
    }

    /// Resolve any alias or canonical name to a `PrimitiveType`.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&'static PrimitiveType> {
        if let Some(p) = self.by_name.get(name) {
            return Some(p);
        }
        let canonical = self.alias_map.get(name)?;
        self.by_name.get(canonical).copied()
    }

    /// Infer the best C type name for a value of `byte_size` bytes that is
    /// known to be `signed`.
    #[must_use]
    pub const fn signed_int_for_size(size: u8) -> &'static str {
        match size {
            1 => "int8_t",
            2 => "int16_t",
            4 => "int32_t",
            8 => "int64_t",
            _ => "int",
        }
    }

    /// Infer the best C type name for a value of `byte_size` bytes that is
    /// known to be `unsigned`.
    #[must_use]
    pub const fn unsigned_int_for_size(size: u8) -> &'static str {
        match size {
            1 => "uint8_t",
            2 => "uint16_t",
            4 => "uint32_t",
            8 => "uint64_t",
            _ => "unsigned int",
        }
    }

    /// Infer the best C float type for the given byte width.
    #[must_use]
    pub const fn float_for_size(size: u8) -> &'static str {
        match size {
            4 => "float",
            10 | 12 | 16 => "long double",
            _ => "double",
        }
    }

    /// Return all registered primitives in declaration order.
    #[must_use]
    pub fn all() -> &'static [PrimitiveType] {
        PRIMITIVES
    }

    /// Return the number of registered primitives.
    #[must_use]
    pub fn count(&self) -> usize {
        self.by_name.len()
    }
}

impl Default for PrimitiveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_lookup_canonical() {
        let reg = PrimitiveRegistry::new();
        let p = reg.get("uint32_t").expect("uint32_t must exist");
        assert_eq!(p.size, 4);
        assert_eq!(p.signedness, Signedness::Unsigned);
    }

    #[test]
    fn test_registry_lookup_alias_dword() {
        let reg = PrimitiveRegistry::new();
        let p = reg.resolve("DWORD").expect("DWORD must resolve");
        assert_eq!(p.name, "unsigned int");
        assert_eq!(p.size, 4);
    }

    #[test]
    fn test_registry_lookup_alias_handle() {
        let reg = PrimitiveRegistry::new();
        let p = reg.resolve("HANDLE").expect("HANDLE must exist");
        assert_eq!(p.family, PrimitiveFamily::OpaqueHandle);
    }

    #[test]
    fn test_registry_posix_pid_t() {
        let reg = PrimitiveRegistry::new();
        let p = reg.get("pid_t").expect("pid_t must exist");
        assert_eq!(p.size, 4);
        assert_eq!(p.signedness, Signedness::Signed);
    }

    #[test]
    fn test_registry_signed_int_for_size() {
        assert_eq!(PrimitiveRegistry::signed_int_for_size(1), "int8_t");
        assert_eq!(PrimitiveRegistry::signed_int_for_size(4), "int32_t");
        assert_eq!(PrimitiveRegistry::signed_int_for_size(8), "int64_t");
    }

    #[test]
    fn test_registry_float_for_size() {
        assert_eq!(PrimitiveRegistry::float_for_size(4), "float");
        assert_eq!(PrimitiveRegistry::float_for_size(8), "double");
    }

    #[test]
    fn test_all_primitives_non_empty() {
        assert!(!PrimitiveRegistry::all().is_empty());
    }

    #[test]
    fn test_registry_count() {
        let reg = PrimitiveRegistry::new();
        assert!(reg.count() > 10);
    }

    #[test]
    fn test_registry_void() {
        let reg = PrimitiveRegistry::new();
        let p = reg.get("void").expect("void must exist");
        assert_eq!(p.size, 0);
        assert_eq!(p.family, PrimitiveFamily::Void);
    }

    #[test]
    fn test_registry_wchar_t() {
        let reg = PrimitiveRegistry::new();
        let p = reg.get("wchar_t").expect("wchar_t must exist");
        assert_eq!(p.family, PrimitiveFamily::WideChar);
    }

    #[test]
    fn test_bool_aliases() {
        let reg = PrimitiveRegistry::new();
        let via_bool = reg.get("bool").unwrap();
        let via_alias = reg.resolve("_Bool").unwrap();
        assert_eq!(via_bool.name, via_alias.name);
    }
}
