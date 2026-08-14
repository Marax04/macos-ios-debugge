# rustre-loader-registry

Composition crate che cabla ogni sub-crate `rustre-loader-*` nel `MultiFormatRegistry` esposto dall'hub `rustre-loader`, tramite sottili adattatori `MultiFormatLoader`. Esiste come livello separato per evitare cicli Cargo tra sub-crate e hub.

## Cargo.toml

- name: `rustre-loader-registry` v0.1.0, edition 2024
- dependencies: `rustre-loader` + tutti i 13 sub-loader (android, console, dotnet, elf, firmware, java, lua, luajit, macho, ole, pdf, pe, wasm), `anyhow`

## Re-exports

Espone i tipi loader primari di ogni sub-crate:
`AndroidDexHeader`, `ConsoleLoader`, `DotnetLoader`, `ElfLoader`, `FirmwareInfo`, `JavaLoader`, `LuaLoader`, `LuaJitLoader`, `MachoParser`, `OleLoader`, `PdfLoader`, `PeLoader`, `WasmLoader`.

## Adapter types (generati dal macro `adapter!`)

Ognuno è uno zero-sized struct `#[derive(Debug, Default, Clone, Copy)]` che implementa `MultiFormatLoader`:

| Adapter | TAG | Estensioni | Probe score | Format string |
|---|---|---|---|---|
| `AndroidLoaderAdapter` | `android` | dex, apk, vdex | 250 | Android |
| `ConsoleLoaderAdapter` | `console` | nes, smc, sfc, gb, gbc, gba, md, gen | 230 | Console ROM |
| `DotnetLoaderAdapter` | `dotnet` | exe, dll | 240 | .NET |
| `ElfLoaderAdapter` | `elf-full` | elf, so, axf, out | 254 | ELF |
| `FirmwareLoaderAdapter` | `firmware` | bin, img, rom, fw | 200 | Firmware |
| `JavaLoaderAdapter` | `java-full` | class, jar | 254 | Java |
| `LuaLoaderAdapter` | `lua-full` | luac, luab | 254 | Lua Bytecode |
| `LuaJitLoaderAdapter` | `luajit` | luac | 254 | LuaJIT |
| `MachoLoaderAdapter` | `macho-full` | dylib, o, macho | 254 | Mach-O |
| `OleLoaderAdapter` | `ole` | doc, xls, ppt, msi | 254 | OLE Compound Document |
| `PdfLoaderAdapter` | `pdf` | pdf | 254 | PDF |
| `PeLoaderAdapter` | `pe-full` | exe, dll, sys, efi | 199 | PE |
| `WasmLoaderAdapter` | `wasm-full` | wasm | 254 | WebAssembly |

Per ognuno: `const TAG: &'static str`, `const fn new() -> Self`.

### Impl `MultiFormatLoader`

- `name() -> &'static str` ritorna TAG
- `extensions() -> &[&str]` array statico
- `description() -> &'static str`
- `probe(&[u8]) -> u8` chiama la probe-fn specifica (score sopra o 0)
- `load(&[u8]) -> anyhow::Result<RichLoadResult>`: se probe == 0 ritorna `anyhow::Error("not a <fmt> image")`, altrimenti `Ok(RichLoadResult::new(bytes.to_vec()).with_format(<fmt>))`

## API pubblica

### `pub fn register_all_subcrate_loaders(r: &MultiFormatRegistry)`

Registra tutti e 13 gli adattatori nel registry passato. Non idempotente: chiamate ripetute producono duplicati.

- Input: `&MultiFormatRegistry` (da `rustre-loader`)
- Output: `()` (effetto: 13 `r.register(...)`)

### `pub fn default_full_registry() -> MultiFormatRegistry`

Costruisce un `MultiFormatRegistry` pre-popolato con gli stub built-in di `rustre_loader::default_multi_format_registry()` **e** i 13 adapter sub-crate.

- Input: nessuno (`#[must_use]`)
- Output: `MultiFormatRegistry` completamente cablato

## Probe functions (private, file-scope)

`probe_android`, `probe_console`, `probe_dotnet`, `probe_elf`, `probe_firmware`, `probe_java`, `probe_lua`, `probe_luajit`, `probe_macho`, `probe_ole`, `probe_pdf`, `probe_pe`, `probe_wasm`. Delegano alle helper `is_*` / `detect_*` dei sub-crate o a `AutoLoader::detect_format` / `AutoLoader::is_elf`. PE usa solo il magic `b"MZ"`, WASM usa `\0asm`.

## I/O

- Input principale: `&[u8]` (byte di un file binario) tramite `probe` / `load`
- Output `load`: `RichLoadResult` con campo `format` impostato (i bytes vengono clonati con `to_vec()`)
- Errori: `anyhow::Error` con messaggio `"not a <format> image"` quando probe fallisce
- Nessun I/O di filesystem o rete: crate puramente in-memory

## Testabilità

Tutto pubblico (`new`, `TAG`, trait `MultiFormatLoader`, `register_all_subcrate_loaders`, `default_full_registry`) è testabile in unit test usando piccoli buffer con magic bytes noti (`MZ`, `\0asm`, `%PDF`, ELF `\x7fELF`, ecc.). Nessuna dipendenza da file su disco o servizi esterni.
