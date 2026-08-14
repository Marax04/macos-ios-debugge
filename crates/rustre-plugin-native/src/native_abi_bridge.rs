// rustre-plugin-native/src/native_abi_bridge.rs
//
// ABI bridging utilities for native shared-library plugins.  Defines a stable
// C ABI version constant, calling-convention markers, and helpers for
// transferring strings and byte buffers across the FFI boundary.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Current ABI version. Bumped whenever the binary layout of the plugin
/// registration entry-point or any vtable changes.
pub const RUSTRE_NATIVE_ABI_VERSION: u32 = 1;

/// Magic value embedded in `PluginVTable::magic` so the host can detect
/// libraries that were built against a different SDK.
pub const RUSTRE_NATIVE_ABI_MAGIC: u32 = 0x5253_5245; // "RSRE"

/// Calling conventions that a native plugin entry-point may use.
///
/// The host always exposes its entry-point as `extern "C"`. Plugins may
/// declare additional helpers using other conventions; this enum is used by
/// the symbol resolver to record what convention was advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    /// Standard C calling convention (`extern "C"`).
    C,
    /// `extern "system"` — same as C on Unix, `__stdcall` on Windows x86.
    System,
    /// Rust's unstable calling convention. Never use across a dynamic
    /// library boundary; recorded only for diagnostics.
    Rust,
}

impl CallConv {
    /// Human-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::System => "system",
            Self::Rust => "Rust",
        }
    }
}

/// Opaque type-erased function pointer.  The bridge stores symbols as
/// `FunctionPtr` so the loader can pass them around without specialising.
///
/// Callers must cast back to the correct `extern "C" fn(...)` signature
/// before invoking — there is no run-time signature verification.
#[derive(Debug, Clone, Copy)]
pub struct FunctionPtr {
    /// Raw address of the function. `0` indicates an unresolved symbol.
    pub addr: usize,
    /// Calling convention advertised by the symbol table.
    pub conv: CallConv,
}

impl FunctionPtr {
    /// Construct an unresolved pointer.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            addr: 0,
            conv: CallConv::C,
        }
    }

    /// Whether this pointer refers to a real address.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        self.addr != 0
    }

    /// Construct from a raw address.
    #[must_use]
    pub const fn from_raw(addr: usize, conv: CallConv) -> Self {
        Self { addr, conv }
    }
}

/// FFI-safe vtable that every native plugin must export through a
/// `rustre_plugin_register` symbol.
///
/// The host validates `magic` and `abi_version` before calling any function
/// pointer in this table.
#[repr(C)]
#[derive(Debug)]
pub struct PluginVTable {
    /// Must equal [`RUSTRE_NATIVE_ABI_MAGIC`].
    pub magic: u32,
    /// Must equal [`RUSTRE_NATIVE_ABI_VERSION`].
    pub abi_version: u32,
    /// Plugin name as a NUL-terminated UTF-8 string.
    pub name: *const c_char,
    /// Plugin version `"major.minor.patch"`.
    pub version: *const c_char,
    /// Optional: free a heap-allocated `*mut c_char` that the plugin returned
    /// (e.g. error strings).  When `None`, the host assumes static lifetime.
    pub free_string: Option<unsafe extern "C" fn(*mut c_char)>,
}

// Vtable contains only POD + raw pointers to immutable plugin data; safe to
// share across threads.
unsafe impl Send for PluginVTable {}
unsafe impl Sync for PluginVTable {}

/// Helpers for moving owned Rust strings to/from the FFI boundary.
#[derive(Debug, Default)]
pub struct NativeAbiBridge;

impl NativeAbiBridge {
    /// Borrow a NUL-terminated string returned by a plugin.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to a NUL-terminated UTF-8 string that
    /// lives at least as long as the returned `&str`.
    #[must_use]
    pub unsafe fn read_cstr<'a>(ptr: *const c_char) -> Option<&'a str> {
        if ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ptr) }.to_str().ok()
    }

    /// Allocate a `CString` from a Rust `&str` for handoff to a plugin.
    ///
    /// # Errors
    ///
    /// Returns `None` when the input contains an interior NUL byte.
    #[must_use]
    pub fn into_cstring(s: &str) -> Option<CString> {
        CString::new(s).ok()
    }

    /// Validate a vtable that a plugin handed back through its registration
    /// entry-point.
    ///
    /// # Errors
    ///
    /// Returns a textual reason whenever `magic` or `abi_version` are wrong.
    pub fn validate_vtable(vt: &PluginVTable) -> Result<(), String> {
        if vt.magic != RUSTRE_NATIVE_ABI_MAGIC {
            return Err(format!(
                "vtable magic mismatch: expected {:#x}, found {:#x}",
                RUSTRE_NATIVE_ABI_MAGIC, vt.magic
            ));
        }
        if vt.abi_version != RUSTRE_NATIVE_ABI_VERSION {
            return Err(format!(
                "vtable ABI version mismatch: host {}, plugin {}",
                RUSTRE_NATIVE_ABI_VERSION, vt.abi_version
            ));
        }
        // Reject null name/version pointers before the caller tries to dereference them.
        if vt.name.is_null() {
            return Err("vtable name pointer is null".to_string());
        }
        if vt.version.is_null() {
            return Err("vtable version pointer is null".to_string());
        }
        Ok(())
    }
}

// ── Plugin entry-point signature ─────────────────────────────────────────────

/// Signature of the `rustre_plugin_register` symbol every native plugin
/// must export.  The plugin returns a pointer to a statically-allocated
/// [`PluginVTable`] (the host never frees it).
pub type PluginRegisterFn = unsafe extern "C" fn() -> *const PluginVTable;

/// Canonical symbol name for plugin entry-points.
pub const PLUGIN_REGISTER_SYMBOL: &[u8] = b"rustre_plugin_register";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callconv_str() {
        assert_eq!(CallConv::C.as_str(), "C");
        assert_eq!(CallConv::System.as_str(), "system");
        assert_eq!(CallConv::Rust.as_str(), "Rust");
    }

    #[test]
    fn function_ptr_null() {
        let p = FunctionPtr::null();
        assert!(!p.is_resolved());
    }

    #[test]
    fn function_ptr_resolved() {
        let p = FunctionPtr::from_raw(0xdead_beef, CallConv::C);
        assert!(p.is_resolved());
        assert_eq!(p.addr, 0xdead_beef);
    }

    #[test]
    fn into_cstring_roundtrip() {
        let c = NativeAbiBridge::into_cstring("hello").unwrap();
        unsafe {
            let s = NativeAbiBridge::read_cstr(c.as_ptr()).unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn into_cstring_with_nul_fails() {
        assert!(NativeAbiBridge::into_cstring("bad\0string").is_none());
    }

    #[test]
    fn validate_vtable_ok() {
        let name = CString::new("p").unwrap();
        let ver = CString::new("0.1.0").unwrap();
        let vt = PluginVTable {
            magic: RUSTRE_NATIVE_ABI_MAGIC,
            abi_version: RUSTRE_NATIVE_ABI_VERSION,
            name: name.as_ptr(),
            version: ver.as_ptr(),
            free_string: None,
        };
        assert!(NativeAbiBridge::validate_vtable(&vt).is_ok());
    }

    #[test]
    fn validate_vtable_bad_magic() {
        let name = CString::new("p").unwrap();
        let ver = CString::new("0").unwrap();
        let vt = PluginVTable {
            magic: 0,
            abi_version: RUSTRE_NATIVE_ABI_VERSION,
            name: name.as_ptr(),
            version: ver.as_ptr(),
            free_string: None,
        };
        assert!(NativeAbiBridge::validate_vtable(&vt).is_err());
    }

    #[test]
    fn validate_vtable_bad_version() {
        let name = CString::new("p").unwrap();
        let ver = CString::new("0").unwrap();
        let vt = PluginVTable {
            magic: RUSTRE_NATIVE_ABI_MAGIC,
            abi_version: RUSTRE_NATIVE_ABI_VERSION + 99,
            name: name.as_ptr(),
            version: ver.as_ptr(),
            free_string: None,
        };
        assert!(NativeAbiBridge::validate_vtable(&vt).is_err());
    }
}
