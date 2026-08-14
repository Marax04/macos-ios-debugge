# rustre-debug-registry

## Purpose
Composition crate that wires every concrete `rustre-debug-*` backend into the `rustre-debug` hub. Lives outside the hub so the hub itself avoids path-deps on its sub-crates (which all depend on the hub). Centralises construction and dispatch of debugger backends.

## Dependencies
- `rustre-core`
- `rustre-debug` (hub providing the `Debugger` trait)
- Backend crates: `rustre-debug-frida`, `rustre-debug-gdb`, `rustre-debug-kgdb`, `rustre-debug-linux`, `rustre-debug-macos`, `rustre-debug-unicorn`, `rustre-debug-windbg`, `rustre-debug-windows`

## Public API

### `pub fn all() -> Vec<Box<dyn Debugger>>`
- **Input**: none.
- **Output**: `Vec` of boxed trait objects, one instance per wired backend (Frida, GDB, KGDB, Linux ptrace, macOS, Unicorn emulator, WinDbg, Windows native). Each is constructed via `Default::default()`.
- **Attributes**: `#[must_use]`.
- **Behavior**: Returns a fresh vector on every call. Callers iterate and query `Debugger::name` / `Debugger::supported_architectures` to select an appropriate backend for a given target. No filtering, ordering guarantees beyond source order, no error path.

## Behavior Summary
- Pure factory/registry module: a single function returning default-constructed instances of all known debugger backends behind the `Debugger` trait object.
- No state, no configuration, no I/O at the registry layer; all real behavior lives in the backend crates.
- Acts as the single point where adding a new debugger backend requires a code change (insert new `Box::new(...)` entry).

## Testability
- Testable in isolation: `all()` can be asserted to return a non-empty vector with the expected count (8) and distinct `name()` values per element.
- No external resources required for construction (defaults only); actual backend operations would require platform-specific environments.

## Output
```json
{ "crate": "rustre-debug-registry", "purpose": "Composition crate wiring all rustre-debug-* backends into the rustre-debug hub via a single all() factory", "fn_count": 1, "testable": true }
```
