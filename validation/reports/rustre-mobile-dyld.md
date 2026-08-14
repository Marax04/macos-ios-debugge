# rustre-mobile-dyld

Apple dyld shared cache parser for the RustRE Suite. Supports modern `dyld_shared_cache` formats including sub-caches (macOS Big Sur+, iOS 15+), slide info v1-v4, and image extraction.

## Cargo.toml

- **Name**: `rustre-mobile-dyld` v0.1.0, edition 2024
- **Dependencies**: `anyhow`, `thiserror`, `serde`, `serde_json`, `goblin`, `bitflags`
- **Dev-deps**: `serde_json`

## Modules

`cache_header`, `dyld_cache_analysis`, `dyld_cache_parser`, `dyld_exports_trie`, `dyld_fixups`, `images`, `mappings`, `objc_selector_db`, `shared_cache_extractor`, `slide_info`, `subcaches`, `dyld_cache_image_extractor`, `dyld_fixup_chains`, `dyld_shared_cache_analyzer`, `dyld_bind_info_parser`, `dyld_rebase_info_parser`, `dyld_symbol_table`, `objc_optimizer`.

## Public API (lib.rs)

### Types

- **`DyldError`** (enum, `thiserror`): `InvalidMagic{expected,actual}`, `Truncated(usize)`, `InvalidOffset(u64)`, `ImageNotFound(String)`, `Parse(String)`, `SubcacheNotFound(String)`, `SlideFixup(String)`, `Io(String)`.
- **`DyldHeader`**: parsed header (magic, mapping/images offsets+counts, base, code-sig, slide-info, uuid, platform, format, sub-cache fields).
- **`DyldMapping`**: VM mapping entry (address, size, file_offset, init_prot, max_prot, flags).
- **`DyldImage`**: image metadata (address, mod_time, inode, path_offset, path).
- **`DyldSymbol`**: name, address, image_path, flags.
- **`ExtractReport`**: `extracted_count`, `failed_count`, `total_bytes`, `failures: Vec<String>`.
- **`SlideFixup`**: mapping_va, mapping_size, optional `slide_info::SlideInfo`.
- **`DyldCache`**: full parsed cache (header, mappings, images, symbols, raw data).
- **`DyldCacheHeader`**: full raw on-disk header through dyld-1042 (iOS 16/macOS 13).

### Functions / methods

**DyldHeader**
- `parse(data: &[u8]) -> Result<Self, DyldError>` — I: raw cache bytes (≥0x100). O: header struct.
- `uuid_string(&self) -> String` — formatted UUID.
- `is_arm64(&self) -> bool`, `platform_name(&self) -> &'static str`, `is_simulator(&self) -> bool`.

**DyldMapping**
- `is_executable/writable/readable(&self) -> bool`
- `end_address(&self) -> u64`, `contains_va(&self, va: u64) -> bool`
- `va_to_file_offset(&self, va: u64) -> Option<u64>`
- `prot_string(&self) -> String` (e.g. `"r-x"`)

**DyldImage**
- `filename(&self) -> &str`, `is_system_framework(&self) -> bool`, `is_swift_overlay(&self) -> bool`.

**DyldSymbol**
- `is_weak(&self) -> bool`, `is_objc(&self) -> bool`, `is_swift(&self) -> bool`.

**SlideFixup**
- `new(mapping_va, mapping_size, slide_info) -> Self`
- `apply(&self, data: &mut [u8], slide: u64) -> Result<usize, DyldError>` — I: mutable mapping bytes + ASLR slide. O: count of patched pointer locations.

**DyldCache**
- `parse(data: &[u8]) -> Result<Self, DyldError>` — I: full cache file bytes. O: parsed cache with mappings + images.
- `find_image(&self, path: &str) -> Option<&DyldImage>`
- `find_images_containing(&self, fragment: &str) -> Vec<&DyldImage>`
- `find_symbols_for_image(&self, image_path: &str) -> Vec<&DyldSymbol>`
- `find_symbol(&self, name: &str) -> Option<&DyldSymbol>`
- `image_count(&self) -> usize`, `symbol_count(&self) -> usize`
- `va_to_file_offset(&self, va: u64) -> Option<u64>`
- `read_at_va(&self, va: u64, len: usize) -> Option<&[u8]>`
- `extract_image_data(&self, image: &DyldImage) -> Result<Vec<u8>, DyldError>` — raw region copy.
- `extract_image(&self, image_path: &str) -> Result<Vec<u8>, DyldError>` — Mach-O extraction with goblin segment sizing + slide fixup (slide=0).
- `extract_all(&self, output_dir: &Path) -> Result<ExtractReport, DyldError>` — writes every image to disk.
- `mock() -> Self` — minimal test cache (2 images, 3 symbols).

**DyldCacheHeader**
- `MIN_SIZE: usize = 72`
- `parse(data: &[u8]) -> Result<Self, DyldError>`
- `magic_str(&self) -> &str`

## I/O Summary

- **Input**: raw `dyld_shared_cache` bytes (`&[u8]`); image paths; mutable byte buffers for slide rebasing; output directory `Path` for `extract_all`.
- **Output**: structured `DyldCache`/`DyldHeader`/`DyldCacheHeader`; `Vec<u8>` of extracted Mach-O; `ExtractReport`; serde JSON via Serialize/Deserialize on all major structs.
- **Errors**: `DyldError` variants for magic/offset/truncation/IO/slide failures.

## Testability

The crate has a built-in `#[cfg(test)]` module with 25+ unit tests covering parsing, mapping/image/symbol predicates, mock-based lookups, and serde round-trip. `DyldCache::mock()` provides a constructor-free fixture, so the library is testable without real dyld cache files.
