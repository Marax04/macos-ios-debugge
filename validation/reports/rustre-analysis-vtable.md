# rustre-analysis-vtable

## Scopo
C++ vtable e RTTI recovery per RustRE Suite. Scansiona sezioni dati per array di puntatori che puntano in sezioni eseguibili (euristica vtable) e decodifica strutture RTTI MSVC (`__RTTICompleteObjectLocator`) e Itanium (`__cxa_type_info`) per ricostruire gerarchie di classi C++. Include demangling, inheritance graph, override map, abstract class inference, multiple inheritance layout, vtable diff/patching detection e statistiche aggregate.

## Moduli pubblici
- `class_hierarchy`, `cpp_class_hierarchy`, `hierarchy` — grafi di ereditarietà
- `rtti_parser`, `rtti_recovery`, `msvc_rtti` — parsing RTTI
- `vtable_finder`, `vtable_recovery`, `vtable_reconstructor`, `vtable_validator`, `vtable_integrity` — discovery/validazione vtable
- `virtual_dispatch_analyzer`, `virtual_override_map`, `override_map` — risoluzione chiamate virtuali
- `demangler` — demangling Itanium/MSVC
- `cluster` — clustering vtable / inferenza derivazioni
- `inheritance_grapher`

## Tipi pubblici principali
- `VtableError` (enum errori)
- `VtableEntry { offset, target_address, function_name }`
- `Vtable { base_address, entries, class_name, offset_to_top }`
- `RttiInfo { type_name, base_classes, rtti_address, abi }`
- `RttiAbi { Itanium, Msvc, Unknown }`
- `Section { name, base_address, data, executable, writable, readable }`
- `VtableDatabase { vtables, rtti, vtable_to_rtti }`
- `AbstractClassInfo`, `SubObject`, `MultipleInheritanceLayout`
- `VtableCandidate`, `VtableDiff`, `VtableStats`

## Funzioni / metodi pubblici (lib.rs core)

### VtableDetector
- `new(ptr_size) -> Self`
- `detect(&self, data_section: &Section, code_sections: &[Section]) -> Result<Vec<Vtable>, VtableError>` — euristica: array consecutivi di puntatori in `.text`, min 2 e max 1024 entry.

### ItaniumRttiDecoder
- `decode(addr, ro_section, ptr_size, known_names) -> Result<RttiInfo, VtableError>` — decodifica `__class_type_info` / `__si_class_type_info` (depth max 32 per anti-DOS).

### MsvcRttiDecoder
- `decode_col(col_addr, rdata_section, image_base) -> Result<RttiInfo, VtableError>` — decodifica `_RTTICompleteObjectLocator` (32 e 64-bit).
- `demangle_msvc(name) -> String` — strip `.?AV`/`.?AU` e `@@`, sostituzione `@` → `::`.

### RttiDecoder (facade)
- `new(ptr_size, image_base)`
- `decode_itanium(addr, ro_section, known_names) -> Result<RttiInfo, _>`
- `decode_msvc_col(col_addr, rdata_section) -> Result<RttiInfo, _>`

### VtableDatabase
- `new()`, `add_vtable(Vtable)`, `add_rtti(RttiInfo)`
- `link_vtable_rtti(vtable_addr, rtti_addr)` — propaga class_name
- `rtti_for_vtable(vtable_addr) -> Option<&RttiInfo>`
- `find_by_class(class_name) -> Vec<&Vtable>`

### PureVirtualDetector
- `new()`, `add_stub_address(addr)`
- `is_pure_virtual(entry) -> bool`
- `annotate(&self, vtable: &mut Vtable) -> usize`
- `count_in_database(db) -> usize`

### AbstractClassInference
- `new()`, `with_detector(PureVirtualDetector)`
- `infer(db) -> Vec<AbstractClassInfo>`

### MultipleInheritanceLayout
- `new(derived_class, object_size)`, `add_sub_object(SubObject)`
- `primary_vtable() -> Option<u64>`, `secondary_vtables() -> Vec<(usize,u64)>`, `base_count() -> usize`

### VtableScanner
- `new(ptr_size, min_slots)`, `add_code_range(start,end)`
- `is_code_address(addr) -> bool`
- `scan(data, base) -> Vec<VtableCandidate>` — con stima confidence (0.60 base, 0.85 se RTTI prefix presente).

### VtableSlotAnnotator
- `new()`, `add_symbol(addr,name)`, `load_symbols(map)`
- `annotate(&self, vtable: &mut Vtable) -> usize`
- `annotate_all(db) -> usize`, `symbol_count() -> usize`

### VtableComparer
- `new()`, `diff(original, patched) -> Vec<VtableDiff>`, `is_identical(...) -> bool`

### Helpers
- `make_ptr_section(base, ptrs, executable) -> Section`
- `make_str_section(base, s) -> Section`

### Re-export
Da `cluster`: `SlotMap`, `VirtualSlot`, `VtableCluster`, `cluster_vtables`, `infer_derivations`.
Da `override_map`: `MethodSlot`, `OverrideAnalyzer`, `OverrideAnalyzerConfig`, `OverrideDiff`, `OverrideMap`, `OverrideReport`, `OverrideStats`, `SlotKey`, `SlotState`, `all_slot_overriders`, `reconstruct_override_chain`.
Da `demangler`: `demangle`, `demangle_itanium`, `demangle_msvc`, `demangle_msvc_function`, `is_itanium_mangled`, `is_msvc_mangled`.
Da `hierarchy`: `ClassNode`, `HierarchyStats`, `InheritanceGraph`, `VirtualDispatchSite`, `build_dispatch_table`, `compute_hierarchy_stats`, `resolve_virtual_dispatch`.

## Input / Output
- **Input**: byte slice di sezioni binarie (`.text`, `.rdata`/`.rodata`/`.data`), pointer size (4/8), image base, optional symbol map.
- **Output**: `Vtable` (base + entries), `RttiInfo` (type_name + base_classes), `VtableCandidate` (con confidence), `VtableStats`, layout MI, override map, inheritance graph, abstract-class report, diff vtable.

## Ground truth verificabile esternamente
- **MSVC binaries con RTTI** (es. binari Visual Studio non-stripped): IDA Pro mostra `_RTTICompleteObjectLocator` e nomi classi (`class_informer` plugin); confrontare `type_name` e `base_classes` decodificati.
- **Itanium binaries** (Linux ELF C++ con `_ZTV*`/`_ZTI*` symbols): confrontare con `nm`/`c++filt` o `readelf -s`.
- **Demangling**: confrontare `demangle_msvc` con `undname.exe` (MSVC) e `demangle_itanium` con `c++filt` (GNU binutils).
- **PureVirtual**: cercare `__cxa_pure_virtual`/`_purecall` con `nm` o IDA.
- **VtableScanner**: confronto numero candidate con plugin IDA `class_informer`/`vtbl_scan`.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_xref_*` — usabile per validare che target_address di vtable entries siano in code section.
- `mcp__ida-pro-mcp__run_class_informer` — ground truth MSVC RTTI.
- `mcp__ida-pro-mcp__run_flare_struct_typer` — recovery strutture.
- `mcp__rustre-mcp__symbols_demangle_msvc` / `symbols_demangle_itanium` / `symbols_demangle_auto` — confronto demangling.
- `mcp__rustre-mcp__analyze_function` / `analyze_strings` — supporto.
- Nessun tool MCP rustre-mcp dedicato specificamente a vtable/RTTI recovery: gap da esporre.

## Testabilità
Sì — la crate include test unitari interni completi (detector, decoder Itanium/MSVC, demangle, database). Test E2E richiedono binario MSVC/Itanium reale con RTTI; usare `cargo-zyphora.exe` (MSVC PE 64-bit) come ground truth confrontando con `mcp__ida-pro-mcp__run_class_informer`.
