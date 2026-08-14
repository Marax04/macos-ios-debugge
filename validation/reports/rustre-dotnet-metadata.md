# rustre-dotnet-metadata

## Purpose
Parser e analizzatore di metadata .NET / CLI (ECMA-335) per file PE managed (assemblies .NET). Espone reader per heap (Strings/UserStrings/GUID/Blob), tabelle metadata, signature parser (type/method/field/locals), CIL method body, custom attributes, type system, generic resolver, assembly resolver, IL disassembler e validation.

## Cargo.toml
- edition: 2024
- deps: anyhow, thiserror, serde
- dev-deps: serde_json
- nessuna feature flag.

## Moduli pubblici (lib.rs)
- `metadata_analyzer`, `metadata_full`, `metadata_resolver`, `generic_resolver`
- `attribute_reader`, `assembly_resolver`, `metadata_tables`, `il_disassembler`, `type_system`
- moduli costanti: `table_id`, `method_semantics`, `event_attributes`, `property_attributes`, `impl_map_attributes`, `coded_index`, `element_type`, `table_ids`

## API top-level (lib.rs)
- `parse_metadata_direct(data: &[u8]) -> Result<MetadataReader>` — entry-point: parsa root CLI/metadata da byte slice del PE.
- `parse_method_sig_blob(blob: &[u8]) -> Result<MethodSigInfo>` — decodifica method signature ECMA-335.
- `parse_field_sig_blob(blob: &[u8]) -> Result<String>` — field sig in stringa leggibile.
- `parse_local_var_sig(blob: &[u8]) -> Result<Vec<String>>` — local variables signature.
- `parse_array_shape(blob: &[u8]) -> Result<ArrayShape>` — array shape (rank, sizes, lobounds).
- `pretty_print_type_sig(blob: &[u8]) -> Result<String>` — type sig in formato leggibile.
- `parse_custom_attribute_blob(blob: &[u8]) -> Result<DecodedCustomAttribute>` — decodifica blob CA generico.
- `parse_custom_attribute_blob_typed(...)` — variante typed con info ctor.
- `parse_method_body(image: &[u8], file_offset: usize) -> Result<CilMethodBody>` — parsa CIL body (tiny/fat) inclusi exception clauses.
- `validate_metadata(reader: &MetadataReader) -> ValidationResult` — verifica integrità tabelle, riferimenti, indici.
- `build_test_metadata_blob(...)` — helper di test.

## Tipi principali esposti
- `MetadataReader` — front-end di lettura, naviga tabelle/heap.
- `MetadataRoot`, `MetadataHeaps`, `MetadataTables` — strutture parse-level.
- `StringHeap`, `UserStringHeap`, `GuidHeap`, `BlobHeap` — accesso heap.
- Tutte le row tipizzate ECMA-335: `ModuleRow`, `TypeRefRow`, `TypeDefRow`, `FieldRow`, `MethodDefRow`, `ParamRow`, `InterfaceImplRow`, `MemberRefRow`, `ConstantRow`, `CustomAttributeRow`, `AssemblyRow`, `AssemblyRefRow`, `NestedClassRow`, `FieldMarshalRow`, `DeclSecurityRow`, `ClassLayoutRow`, `FieldLayoutRow`, `StandAloneSigRow`, `EventMapRow`, `EventRow`, `PropertyMapRow`, `PropertyRow`, `MethodSemanticsRow`, `MethodImplRow`, `ModuleRefRow`, `TypeSpecRow`, `ImplMapRow`, `FieldRvaRow`, `FileRow`, `ExportedTypeRow`, `ManifestResourceRow`, `GenericParamRow`, `MethodSpecRow`, `GenericParamConstraintRow`.
- Token/ref: `TypeRef`, `FieldRef`, `MethodRef`, `ParamRef`, `TokenResolution`.
- View ergonomiche: `TypeDefView`, `MethodDefView`.
- Signature: `MethodSigInfo`, `ArrayShape`.
- Custom attr: `CustomAttributeNamedArg`, `CustomAttributeValue`, `DecodedCustomAttribute`.
- CLI/CIL: `CliHeader`, `CliHeaderParser`, `CilMethodBody`, `ExceptionClause`, `ExceptionClauseKind`.
- Aggregati di alto livello: `AssemblyManifest`, `TypeModel`, `PInvokeDecl`, `MethodSpecInfo`.
- Validation: `ValidationIssue`, `ValidationResult`, `MetadataStats`, `MetadataIndexer`.
- Enums: `MetadataError` (thiserror), `NestedVisibility`, `TypeVisibility`, `ConstantValue`, `SecurityAction`.

## Sotto-moduli — comportamento
- **type_system**: `parse_type_sig`, `parse_method_sig`, `parse_field_sig`, `parse_locals_sig` (versioni `Option`-based, lower-level), più `TypeSig`/`MethodSig`/`SigReader`, `TypeDescriptor`, `TypeResolver`, `InheritanceNode`, `InterfaceMap`, `GenericContext`, `CallingConv`, `ElementType`, `GenericInst`.
- **metadata_tables**: definizioni `TableIndex`, schemi tabelle, parser righe binarie.
- **metadata_resolver**, **generic_resolver**, **assembly_resolver**: risoluzione token, sostituzione parametri generici, lookup assembly refs.
- **attribute_reader**: lettura/decodifica custom attributes tipizzati.
- **il_disassembler**: disassemblaggio CIL opcodes da method body.
- **metadata_analyzer**, **metadata_full**: analisi aggregata e statistiche.
- **costanti** (`table_id`, `coded_index`, `element_type`, ecc.): valori ECMA-335 spec.

## Comportamento previsto
Input principale: byte slice di assembly .NET (PE managed) o singoli blob heap. Output: strutture deserializzate Rust, signature stringify, valori CA decodificati, body CIL, ValidationResult. Errori via `anyhow::Result` / `MetadataError`. Nessun side-effect IO: parser puramente in-memory.

## Testabilità
Testable: sì. Già presenti `tests/blitz.rs` e `tests/blitz2.rs`. API tutte pure-function su `&[u8]`, deterministica. `build_test_metadata_blob` fornito come fixture builder. Si possono usare assembly .NET reali (es. mscorlib, System.dll) per test integration.

## Conteggi
- 11 pub fn top-level in lib.rs
- 18 pub fn liberi totali + ~386 metodi pub impl
- 264 pub fn/struct/enum totali nel crate
- 9 sotto-moduli pubblici principali + 7 moduli costanti
