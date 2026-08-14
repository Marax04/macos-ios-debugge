# rustre-loader-console

Console/ROM and homebrew-platform loader crate. Implements full header parsing,
memory-map construction, bank-switching detection and entry-point resolution for
classic and modern console formats, plus a generic stdin/console pass-through
loader.

## Cargo

- Package: `rustre-loader-console` v0.1.0, edition 2024
- Internal deps: `rustre-core` (shared loader traits — depending on
  `rustre-loader` is explicitly forbidden to avoid a workspace cycle)
- External: `async-trait`, `serde`, `serde-big-array`, `tokio (full)`,
  `thiserror`, `bitflags`, `bytecount`

## Modules (all `pub mod`)

| Module | Purpose |
|--------|---------|
| `format_detection` | Magic-byte format sniffing helpers |
| `nca_format` | Switch NCA (Nintendo Content Archive) parsing |
| `nso_loader`, `switch_nso_loader`, `nso_nro`, `switch_formats` | Switch NSO/NRO/RomFs |
| `ps_loader`, `self_format`, `ps2_elf_loader` | PlayStation SELF + PS2 ELF |
| `xex`, `xex_loader`, `xbox_xex_loader` | Xbox 360 XEX2 |
| `gba_rom_loader` | Standalone GBA rom loader module |
| `console_rom_header`, `console_memory_map`, `console_symbol_provider` | Cross-platform support utilities |
| `lib.rs` (root) | NES, SNES, Game Boy, GBA, Genesis loaders + generic `ConsoleLoader` |

Re-exports from `switch_formats`: `NRO_MAGIC`, `NSO_MAGIC`, `NroHeader`,
`NsoBss`, `NsoHeader`, `NsoModuleInfo`, `NsoSegmentInfo`, `RomFsEntry`,
`RomFsHeader`, `SwitchError`, `SwitchFormats`, `SwitchRomFs`.

## Public API (top-level, lib.rs)

### Free functions
- `xor_checksum(data: &[u8], skip_offset: Option<usize>) -> u8` — 8-bit XOR
  checksum, optionally skipping a byte (used by ROM header verification).
- `detect_format(data: &[u8]) -> Option<String>` — magic-based detector. Returns
  `"pe" | "elf" | "java-class" | "lua-bytecode" | "luajit-bytecode" | "dex" |
  "zip" | "pdf" | "ole2" | "gzip" | "nes" | "snes" | "gameboy" | "gba" |
  "genesis"` or `None`.
- `is_nes`, `is_snes`, `is_gb`, `is_gba` — per-platform sniffers.

### Generic architecture stub
- `ConsoleArch { new(name, ptr_size, endian) }` — implements `rustre_core::arch::Architecture`
  with a 1-byte “data” disassembler used as a placeholder until a real
  architecture backend is attached.

### Console stream (stdin pass-through)
- `ConsoleStream { byte_count, is_binary, detected_format }` + `analyse(&[u8])`.
- `StreamStats { null_bytes, printable_ascii, max_byte, min_byte }` + `compute(&[u8])`.
- `ConsoleLoader` — implements `Loader`; `can_load` always returns `true`;
  maps `input.data` read-only at `hints.base_address()` (default 0) with
  `unknown` arch, 64-bit LE.

### NES / iNES
- Constants: `NES_MAGIC = b"NES\x1a"`, `NES_PRG_BANK_SIZE = 16K`,
  `NES_CHR_BANK_SIZE = 8K`.
- Enums: `NesTvSystem { Ntsc, Pal, DualCompatible }`,
  `NesMirroring { Horizontal, Vertical, FourScreen, MapperControlled }`.
- Bitflags: `NesFlags { HAS_BATTERY, HAS_TRAINER, IS_PLAYCHOICE, IS_VS_UNISYSTEM, IS_NES2 }`.
- `NesHeader::parse(&[u8])` — decodes the 16-byte iNES header (mapper, flag6/7/9).
  Helpers: `prg_rom_size`, `chr_rom_size`, `prg_rom_offset` (accounts for the
  512-byte trainer), `has_battery`, `has_trainer`, `is_playchoice`,
  `is_vs_unisystem`, `is_nes2`, `bank_switching_scheme()` (resolves ~50
  mappers to their cartridge family name), `reset_vector`, `nmi_vector`,
  `irq_vector` — last bank, little-endian 16-bit CPU vectors.
- `NesLoader` — maps PRG-ROM at $8000 (mirroring NROM-128 at $C000), CHR-ROM
  read-only at a synthetic 0x2000_0000-aligned RAM region, and a 2 KiB
  read/write WRAM stub. Entry = reset vector; arch `"6502"`.

### SNES
- Constants: `SNES_LOROM_HEADER_OFFSET = 0x7FB0`, `SNES_HIROM_HEADER_OFFSET = 0xFFB0`,
  `SNES_EXLOROM_HEADER_OFFSET`, `SNES_EXHIROM_HEADER_OFFSET`.
- `SnesMapMode { LoRom, HiRom, ExLoRom, ExHiRom, Sa1Rom, Sdd1Rom, Unknown(u8) }`
  with `from_byte`.
- `SnesHeader { title, map_mode, chipset, rom_size_kb_pow2, sram_size_kb_pow2,
  country, licensee, version, complement, checksum, header_offset }`. APIs:
  `parse` (auto-scores LoROM vs HiROM offsets), `parse_at`, `checksum_valid`,
  `has_copier_header` (detects 512-byte SMC copier header by `len % 1024 == 512`),
  `lorom_reset_vector`, `hirom_reset_vector`, `coprocessor()` (DSP, SuperFX,
  OBC1, SA-1, S-DD1, S-RTC, …).
- `SnesLoader` — strips copier header, builds per-bank segments
  (LoROM: $XX:8000–$XX:FFFF in 32K chunks; HiROM: 64K banks at $C0_0000+),
  plus 32 KiB SRAM at $70_0000. Entry = reset vector; arch `"65816"`.

### Game Boy
- `GB_LOGO: [u8; 48]` — Nintendo logo bytes that must appear at $0104.
- `GbCartType` — exhaustive enum over MBC0/1/2/3/5/6/7, MMM01, HuC1/3,
  Pocket Camera, Bandai TAMA5 and `Unknown(u8)`; `from_byte`, `mbc_name`.
- `GbHeader { title, manufacturer_code, cgb_flag, sgb_flag, cart_type,
  rom_size_code, ram_size_code, destination, old_licensee, version,
  header_checksum, global_checksum }`. APIs: `parse`,
  `verify_header_checksum` (subtractive checksum across $0134–$014C),
  `rom_size_bytes` (32 KiB << code, overflow-guarded), `sram_size_bytes`,
  `is_cgb`, `is_sgb`.
- `GbLoader` — maps fixed bank0 at $0000, switchable bank1 at $4000, optional
  ext-RAM at $A000, WRAM at $C000, HRAM at $FF80. Entry $0100; arch `"lr35902"`.

### Game Boy Advance, Genesis, and additional sub-loaders
- GBA constants `GBA_ENTRY_INSTR`, `GBA_LOGO_OFFSET`, `GBA_LOGO_SIZE`,
  `GBA_HEADER_SIZE`; `GbaSaveType { None, Eeprom, Sram, Flash64, Flash128 }`;
  GBA loader struct.
- Genesis (Mega Drive) loader (`is_genesis`, header parser, loader).
- Per-platform loaders exposed via sub-modules: PS1 SELF (`self_format`,
  `ps_loader`), PS2 ELF (`ps2_elf_loader`), Xbox360 XEX (`xex`, `xex_loader`,
  `xbox_xex_loader`), Switch NSO/NRO/RomFs (`switch_formats`,
  `switch_nso_loader`, `nso_loader`, `nso_nro`), Switch NCA (`nca_format`).

## I/O contract

All concrete loaders implement `rustre_core::loader::Loader` (async):
- `name() -> &'static str` (e.g. `"nes"`, `"snes"`, `"gameboy"`, `"console"`).
- `can_load(&LoaderInput) -> bool` — magic/heuristic check, returns `true`
  unconditionally for `ConsoleLoader`.
- `load(LoaderInput) -> Result<LoadResult, CoreError>` — parses the header,
  populates a `Memory` with `Segment`s at the documented CPU addresses,
  derives entry points (reset vectors when available), wraps everything in a
  `BinaryView` with a `ConsoleArch` stub of the right pointer-size/endianness.
- `find_nested(&LoaderInput) -> Result<Vec<NestedBinary>, CoreError>` — every
  console loader returns `Ok(vec![])`; nested-binary discovery is delegated to
  composite Switch/Xbox loaders inside the sub-modules.

Errors are mapped to `CoreError::InvalidFormat { message }`. Header parsers
return `Result<Self, String>` so they can be used outside the `Loader` trait.

## Behavior notes

- The crate is loader-only: every architecture is a `ConsoleArch` placeholder
  (1-byte `"data"` disassembly, no branches, no registers). Real disassembly is
  expected from sibling crates once the view is loaded.
- Memory maps mirror the documented hardware layout, not the raw file layout
  (NROM mirroring, LoROM/HiROM banking, GB HRAM stub, etc.). SRAM/WRAM
  regions are zero-filled with `READ|WRITE` permissions so analyses can plant
  data without re-mapping.
- Heuristics (SNES `snes_header_score`, GB Nintendo-logo check, NES iNES magic,
  GBA branch instruction at offset 0) are deliberately conservative to
  minimise false positives in `detect_format` and the per-loader `can_load`.
- Numeric decoding is overflow-guarded where input is untrusted (e.g.
  `GbHeader::rom_size_bytes` rejects shift codes that would exceed `usize`).

## Testability

- `Cargo.toml` declares `tokio` (full) under `[dev-dependencies]`, indicating
  async tests are intended. No `#[cfg(test)]` module is present in `lib.rs` in
  the inspected window, and no `tests/` directory ships with the crate.
- Header parsers (`NesHeader::parse`, `SnesHeader::parse`/`parse_at`,
  `GbHeader::parse`) are pure functions over `&[u8]` and easy to unit-test;
  the `Loader::load` implementations are async and require a Tokio runtime,
  which is satisfied by the dev-dependency.
- Considered testable.

## Counts

- Total `pub fn` / `pub async fn` across the crate: 43 (lib.rs: 8; sub-modules
  range from 0–10).
