//! `rustre-plugin-native`
//!
//! Native (shared-library) plugin support for `RustRE`: dynamic loading of
//! `.dll`/`.so`/`.dylib` files, ABI bridging, and symbol resolution.

pub mod native_plugin_loader;
pub mod native_abi_bridge;
pub mod native_symbol_resolver;

pub use native_abi_bridge::{CallConv, FunctionPtr, NativeAbiBridge};
pub use native_plugin_loader::{DylibHandle, NativePlugin, NativePluginLoader};
pub use native_symbol_resolver::{ExportedSymbol, NativeSymbolResolver, SymbolKind};
