# rustre-arch-dex

## Scopo
Implementazione dell'architettura Dalvik/ART per la suite RustRE. Copre l'intero
instruction set DEX (256+ opcode incluso il range 0xE3-0xFF), tutti i formati
operando (10x/12x/11n/...51l/45cc/4rcc), tipi del formato DEX, signature di
metodo, type descriptor, e gli opcode ART ottimizzati. Fornisce decoder,
lifter verso IL (Dalvik->LLIL e Dalvik->DexIL), analizzatore di code item,
type system, string pool, generatore Smali, e detector di obfuscation
(ProGuard / R8 / encrypted strings / reflection abuse).

Dipendenze: `rustre-core` (Architecture trait, Address, Endian, CoreError,
InstrFlags), `thiserror`, `serde`.

## Moduli pubblici
- `art_opcodes` - opcode ART ottimizzati + mapper a opcode standard
- `dalvik_lifter_full` - lifter completo Dalvik -> LLIL (256 opcode)
- `dalvik_type_system` - type system Dalvik (parser descriptor, gerarchia tipi)
- `dex_lifter` - lifter Dalvik -> DexIL
- `dex_method_analyzer` - parsing code_item, basic block, try/catch
- `dex_obfuscation` - detector ProGuard/R8/strings cifrate/reflection
- `dex_string_pool` - DEX string pool con StringId/DexString
- `dex_type_system` - TypeDescriptor, ClassType, MethodProto
- `full_opcode_table` - tabella opcode completa + `decode_dex_insn`
- `smali_generator` - generatore testo Smali (classi/metodi/istruzioni)

## Funzioni pubbliche principali (firme)

### lib.rs (root)
- `pub fn decode_dex(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError>` - decodifica una singola istruzione Dalvik, ritorna (mnemonic, operandi, dimensione in byte, flags)
- `pub const fn is_art_optimized_opcode(op: u8) -> bool`
- `pub const fn art_opcode_name(op: u8) -> &'static str`
- `pub fn lookup_dex_opcode(opcode: u8) -> Option<&'static DexOpcodeRef>`
- `pub fn dex_param_count(descriptor: &str) -> usize` - conta i parametri da uno shorty/proto descriptor
- `pub fn dex_find_blocks(code: &[u8]) -> Result<Vec<DexBasicBlock>, DexDecodeError>` - basic block discovery
- `pub fn dex_vreg(n: u8) -> String` / `pub fn dex_preg(n: u8) -> String`
- `pub fn dex_param_regs(total_regs: u8, param_count: u8) -> Vec<u8>` - calcolo registri parametro per convenzione DEX
- `pub fn lookup_dex_class(descriptor: &str) -> Option<&'static DexWellKnownClass>`
- `pub fn identify_dex_idiom(mnemonic: &str, operands: &str) -> DexIdiom`
- `pub fn dex_internal_to_java_name(internal: &str) -> String` (es. `java/lang/String` -> `java.lang.String`)
- `pub fn java_name_to_dex_descriptor(java_name: &str) -> String`
- `pub fn dex_simple_class_name(descriptor: &str) -> &str`
- `pub fn dex_instr_cost(mnemonic: &str) -> u32`
- `pub fn smali_reg(n: u16) -> String`
- `pub fn smali_method_ref(class, method, proto) -> String`
- `pub fn smali_field_ref(class, field, field_type) -> String`
- `pub fn lookup_dex_method(class: &str, method: &str) -> Option<&'static DexWellKnownMethod>`
- `pub fn dex_extract_call_sites(...)` - estrae call_site da bytecode
- `pub const fn packed_switch_payload_size(entries: u16) -> u32`
- `pub const fn sparse_switch_payload_size(entries: u16) -> u32`

### Tipi principali
- `DexArch` - implementa `rustre_core::arch::Architecture`
- `DexLinearDisassembler<'a>` - disassemblatore lineare
- `DexAccessFlags(u32)` - costanti + `has_field_flag` / `has_method_flag`
- `DexTypeDescriptor(String)` - `new`, `as_str`, `kind`, `class_name`, `array_element`
- `DescriptorKind` enum + `register_slots`, `is_wide`
- `DexMethodSignature { shorty, return_type, params }` + `arg_register_count`
- `DexCodeItemHeader::decode(&[u8])`
- `DexFormat` enum (33 varianti) + `base_code_units`
- `DexDecodeError` - thiserror (Truncated, UnknownOpcode)
- `DexItemType` - 19 tipi item map list
- `DexWellKnownClass`, `DexWellKnownMethod`, `DexCallSite`, `DexMethodHandleKind`
- `DexAnnotationVisibility`, `DexAnnotationValueType`
- `DexBasicBlock`, `DexMethodStats`, `DexComplexityMetrics`, `DexCallingConv`
- `DexRegSet(u64)`, `DexReturnType`, `DexIdiom`, `DexOpcodeRef`
- Costanti: `DEX_MAGIC`, `DEX_MAGIC_035..039`, `CDEX_MAGIC`, `DEX_ENDIAN_CONSTANT`, `DEX_REVERSE_ENDIAN_CONSTANT`, `DEX_CODE_ITEM_HEADER_SIZE = 16`, `DEX_PACKED_SWITCH_IDENT = 0x0100`, `DEX_SPARSE_SWITCH_IDENT = 0x0200`, `DEX_FILL_ARRAY_DATA_IDENT = 0x0300`

### Sotto-moduli (esposti)
- `full_opcode_table::decode_dex_insn(bytes) -> Result<DecodedInsn, DecodeError>` - decoder alternativo basato su tabella
- `art_opcodes::decode_art_insn(bytes) -> Option<ArtInsnInfo>`, `ArtToStandardMapper`
- `dalvik_lifter_full::DalvikLifterFull`, `dalvik_mnemonic(op: u8) -> &'static str`
- `dex_lifter::DexLifter`
- `dex_string_pool::parse_string_id_list(...)`, `DexStringPool`
- `dex_method_analyzer::DexMethodAnalyzer`, `CodeItem`, `TryCatchHandler`
- `dex_obfuscation::DexObfuscation` (facade), `ProGuardPatterns`, `R8Optimizer`, `SingleLetterNames`, `EncryptedStrings`, `ReflectionAbuse`
- `smali_generator::SmaliGenerator`, `SmaliClass`, `SmaliMethod`, `SmaliVerifier`, `SmaliFormatter`, `java_to_descriptor`, `descriptor_to_java`, `build_method_signature`
- `dex_type_system::TypeDescriptor`, `ClassType`, `MethodProto`, `DexTypeSystem`
- `dalvik_type_system::DalvikType`, `TypeDescriptorParser`, `MethodSignature`, `TypeHierarchy`, `InterfaceSet`, `ArrayType`, `PrimitiveConversion`

## Input / Output
- **Input**: slice di byte (`&[u8]`) di bytecode Dalvik a code-unit boundary little-endian, descrittori tipo/metodo come stringhe DEX, code_item raw header.
- **Output**: tuple di disassembly `(mnemonic, operands, size, InstrFlags)`, `DecodedInsn` strutturata, basic block, signature/method-proto parsate, gerarchie di tipi, sorgente Smali, finding di obfuscation.

## Ground truth verificabile esternamente
1. **DEX specification ufficiale Android**: https://source.android.com/docs/core/runtime/dex-format e https://source.android.com/docs/core/runtime/dalvik-bytecode - encoding di tutti gli opcode 0x00..0xFF, formati operando (10x/12x/.../51l), magic `dex\n0xx`, costanti endian (0x12345678/0x78563412), DEX_CODE_ITEM header (16 byte), payload identifiers (0x0100/0x0200/0x0300).
2. **`dexdump` / `baksmali`** (Android SDK build-tools): disassembly e Smali di riferimento da confrontare con `decode_dex` e `SmaliGenerator` su APK reali (es. `framework.jar` AOSP, app Play Store).
3. **`apktool`**: per smontare APK e ottenere Smali ground truth.
4. **AOSP `libdexfile`** (`art/libdexfile/dex/`): semantica codice di riferimento per opcode ART (0xE3..0xFF) e CompactDex.
5. **Java VM Spec / JNI signatures**: descrittori tipo (`Ljava/lang/String;`, `[B`, `I`, `V`) e regole di register slot (long/double = 2 slot).
6. **Access flags**: tabella in `dex-format.html` (PUBLIC=0x1, PRIVATE=0x2, ..., CONSTRUCTOR=0x10000).
7. Testset DEX pubblici per cross-check: APK open source su F-Droid.

## Tool MCP esistenti utilizzabili per validazione
Nessun tool MCP del server `rustre-mcp` espone direttamente API DEX-specifiche; la validazione passa attraverso i wrapper generici:
- `mcp__rustre-mcp__project_open` + `mcp__rustre-mcp__binary_info` su un file `.dex` / `.apk` (classes.dex estratto).
- `mcp__rustre-mcp__analysis_disasm_at_path` - disassembly generico (non DEX-aware ufficialmente, ma utile per byte-level).
- `mcp__rustre-mcp__binary_search_bytes` per cercare il magic `dex\n035\0` / `cdex`.
- `mcp__rustre-mcp__binary_read` / `binary_hexdump` per verificare manualmente header DEX e code_item.
- `mcp__rustre-mcp__yara_scan_file` con regola per `dex\n` magic.
- `mcp__codewalker__*` non applicabile (GTA V).
- Confronto cross-tool: nessun MCP DEX dedicato disponibile -> usare `dexdump`/`baksmali` da shell come oracolo esterno.

## Testabilita
Si: il crate ha una directory `tests/` (test di integrazione). Tutte le funzioni
pubbliche di decoding sono pure (byte-in -> struttura-out) e verificabili
costruendo sequenze di byte note dalla DEX spec o estraendo `classes.dex`
da APK reali e confrontando con `dexdump -d`.
