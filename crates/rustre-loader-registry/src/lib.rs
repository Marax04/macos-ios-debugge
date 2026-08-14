//! `rustre-loader-registry`
//!
//! Composition crate: wires every `rustre-loader-*` sub-crate into the
//! [`MultiFormatRegistry`] exposed by the `rustre-loader` hub via thin
//! [`MultiFormatLoader`] adapters.
//!
//! This crate exists as a separate composition layer (rather than living in
//! the hub) so that sub-crates can depend on `rustre-loader` for shared
//! traits without creating a Cargo dependency cycle.

use rustre_loader::{AutoLoader, DetectedFormat, MultiFormatLoader, MultiFormatRegistry, RichLoadResult};

// Re-export each sub-crate's primary loader type at the registry level so
// callers can reach them without taking another direct dependency.
pub use rustre_loader_android::DexHeader as AndroidDexHeader;
pub use rustre_loader_console::ConsoleLoader;
pub use rustre_loader_dotnet::DotnetLoader;
pub use rustre_loader_elf::ElfLoader;
pub use rustre_loader_firmware::FirmwareInfo;
pub use rustre_loader_java::JavaLoader;
pub use rustre_loader_lua::LuaLoader;
pub use rustre_loader_luajit::LuaJitLoader;
pub use rustre_loader_macho::MachoParser;
pub use rustre_loader_ole::OleLoader;
pub use rustre_loader_pdf::PdfLoader;
pub use rustre_loader_pe::PeLoader;
pub use rustre_loader_wasm::WasmLoader;

macro_rules! adapter {
    (
        $name:ident, $tag:literal, $desc:literal, $exts:expr,
        $probe_fn:expr, $format_str:literal, $marker:ty
    ) => {
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name(::core::marker::PhantomData<$marker>);

        impl $name {
            /// Tag identifying this adapter (matches [`MultiFormatLoader::name`]).
            pub const TAG: &'static str = $tag;
            /// Construct an adapter instance.
            #[must_use]
            pub const fn new() -> Self { Self(::core::marker::PhantomData) }
        }

        impl MultiFormatLoader for $name {
            fn name(&self) -> &'static str { $tag }
            fn extensions(&self) -> &[&str] { &$exts }
            fn description(&self) -> &'static str { $desc }
            fn probe(&self, bytes: &[u8]) -> u8 { ($probe_fn)(bytes) }
            fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
                if ($probe_fn)(bytes) == 0 {
                    return Err(anyhow::anyhow!(concat!("not a ", $format_str, " image")));
                }
                Ok(RichLoadResult::new(bytes.to_vec()).with_format($format_str))
            }
        }
    };
}

// -- Adapter probes ---------------------------------------------------------

fn probe_android(b: &[u8]) -> u8 {
    if rustre_loader_android::is_dex(b) || rustre_loader_android::is_apk(b) { 250 } else { 0 }
}
fn probe_console(b: &[u8]) -> u8 {
    if rustre_loader_console::detect_format(b).is_some() { 230 } else { 0 }
}
fn probe_dotnet(b: &[u8]) -> u8 {
    if rustre_loader_dotnet::is_dotnet(b) { 240 } else { 0 }
}
fn probe_elf(b: &[u8]) -> u8 { if AutoLoader::is_elf(b) { 254 } else { 0 } }
fn probe_firmware(b: &[u8]) -> u8 {
    match rustre_loader_firmware::detect_firmware_kind(b) {
        rustre_loader_firmware::FirmwareKind::Unknown => 0,
        _ => 200,
    }
}
fn probe_java(b: &[u8]) -> u8 {
    if rustre_loader_java::is_class(b) || rustre_loader_java::is_jar(b) { 254 } else { 0 }
}
fn probe_lua(b: &[u8]) -> u8 {
    if rustre_loader_lua::is_lua_bytecode(b) { 254 } else { 0 }
}
fn probe_luajit(b: &[u8]) -> u8 {
    if rustre_loader_luajit::is_luajit(b) { 254 } else { 0 }
}
fn probe_macho(b: &[u8]) -> u8 {
    matches!(
        AutoLoader::detect_format(b),
        DetectedFormat::MachoLe32
            | DetectedFormat::MachoLe64
            | DetectedFormat::MachoBe32
            | DetectedFormat::MachoBe64
            | DetectedFormat::FatMacho
    )
    .then_some(254)
    .unwrap_or(0)
}
fn probe_ole(b: &[u8]) -> u8 {
    if rustre_loader_ole::is_ole(b) { 254 } else { 0 }
}
fn probe_pdf(b: &[u8]) -> u8 {
    if rustre_loader_pdf::is_pdf(b) { 254 } else { 0 }
}
fn probe_pe(b: &[u8]) -> u8 {
    // `MZ` alone is only the DOS header: every 16-bit DOS executable starts with
    // it, and claiming those as PE would both mis-label them and hand them to a
    // loader that cannot read them. The real test — already available in the
    // sub-crate this adapter wraps — follows `e_lfanew` at 0x3C and checks for
    // the `PE\0\0` signature there.
    if rustre_loader_pe::pe_analyzer::PeAnalyzer::is_pe(b) {
        199
    } else {
        0
    }
}
fn probe_wasm(b: &[u8]) -> u8 {
    if b.starts_with(&[0x00, 0x61, 0x73, 0x6d]) { 254 } else { 0 }
}

// -- Adapter types ----------------------------------------------------------

adapter!(AndroidLoaderAdapter, "android", "Android DEX/APK", ["dex", "apk", "vdex"],
    probe_android, "Android", AndroidDexHeader);
adapter!(ConsoleLoaderAdapter, "console", "Retro console ROM (NES/SNES/GB/GBA/Genesis/...)",
    ["nes", "smc", "sfc", "gb", "gbc", "gba", "md", "gen"], probe_console, "Console ROM", ConsoleLoader);
adapter!(DotnetLoaderAdapter, "dotnet", ".NET / CIL assembly",
    ["exe", "dll"], probe_dotnet, ".NET", DotnetLoader);
adapter!(ElfLoaderAdapter, "elf-full", "ELF executable / shared library (rustre-loader-elf)",
    ["elf", "so", "axf", "out"], probe_elf, "ELF", ElfLoader);
adapter!(FirmwareLoaderAdapter, "firmware", "Embedded firmware image",
    ["bin", "img", "rom", "fw"], probe_firmware, "Firmware", FirmwareInfo);
adapter!(JavaLoaderAdapter, "java-full", "Java class file / JAR (rustre-loader-java)",
    ["class", "jar"], probe_java, "Java", JavaLoader);
adapter!(LuaLoaderAdapter, "lua-full", "Lua bytecode (rustre-loader-lua)",
    ["luac", "luab"], probe_lua, "Lua Bytecode", LuaLoader);
adapter!(LuaJitLoaderAdapter, "luajit", "LuaJIT bytecode",
    ["luac"], probe_luajit, "LuaJIT", LuaJitLoader);
adapter!(MachoLoaderAdapter, "macho-full", "Mach-O binary (rustre-loader-macho)",
    ["dylib", "o", "macho"], probe_macho, "Mach-O", MachoParser);
adapter!(OleLoaderAdapter, "ole", "OLE Compound Document (DOC/XLS/PPT)",
    ["doc", "xls", "ppt", "msi"], probe_ole, "OLE Compound Document", OleLoader);
adapter!(PdfLoaderAdapter, "pdf", "Portable Document Format",
    ["pdf"], probe_pdf, "PDF", PdfLoader);
adapter!(PeLoaderAdapter, "pe-full", "Windows Portable Executable (rustre-loader-pe)",
    ["exe", "dll", "sys", "efi"], probe_pe, "PE", PeLoader);
adapter!(WasmLoaderAdapter, "wasm-full", "WebAssembly module (rustre-loader-wasm)",
    ["wasm"], probe_wasm, "WebAssembly", WasmLoader);

/// Register every sub-crate adapter into the given registry.
///
/// Idempotent in spirit but does push duplicates if called twice -- callers
/// that need a single, fully-wired registry should prefer
/// [`default_full_registry`].
pub fn register_all_subcrate_loaders(r: &MultiFormatRegistry) {
    r.register(AndroidLoaderAdapter::new());
    r.register(ConsoleLoaderAdapter::new());
    r.register(DotnetLoaderAdapter::new());
    r.register(ElfLoaderAdapter::new());
    r.register(FirmwareLoaderAdapter::new());
    r.register(JavaLoaderAdapter::new());
    r.register(LuaLoaderAdapter::new());
    r.register(LuaJitLoaderAdapter::new());
    r.register(MachoLoaderAdapter::new());
    r.register(OleLoaderAdapter::new());
    r.register(PdfLoaderAdapter::new());
    r.register(PeLoaderAdapter::new());
    r.register(WasmLoaderAdapter::new());
}

/// Build a [`MultiFormatRegistry`] containing the built-in stubs **and**
/// every `rustre-loader-*` sub-crate adapter.
#[must_use]
pub fn default_full_registry() -> MultiFormatRegistry {
    let r = rustre_loader::default_multi_format_registry();
    register_all_subcrate_loaders(&r);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare DOS `MZ` is not a PE. The probe used to accept it on the strength
    /// of the two magic bytes alone, so every 16-bit DOS executable — and
    /// anything else beginning with `MZ` — was claimed by the PE adapter.
    #[test]
    fn probe_pe_rejects_a_dos_stub_without_a_pe_signature() {
        let mut dos = vec![0u8; 0x100];
        dos[0] = b'M';
        dos[1] = b'Z';
        // e_lfanew left at 0, and no "PE\0\0" anywhere.
        assert_eq!(probe_pe(&dos), 0);
    }

    /// The same bytes plus a real `PE\0\0` at the offset `e_lfanew` points to.
    #[test]
    fn probe_pe_accepts_an_image_with_a_real_pe_signature() {
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        let pe_off = 0x80u32;
        pe[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        let off = pe_off as usize;
        pe[off..off + 4].copy_from_slice(b"PE\0\0");
        assert_eq!(probe_pe(&pe), 199);
    }

    /// Short input must not panic and must not be claimed.
    #[test]
    fn probe_pe_refuses_input_too_short_to_hold_a_header() {
        assert_eq!(probe_pe(b"MZ"), 0);
        assert_eq!(probe_pe(&[]), 0);
    }
}
