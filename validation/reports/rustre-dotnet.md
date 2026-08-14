# rustre-dotnet

## Overview
- **Crate**: `rustre-dotnet` v0.1.0, edition 2024
- **Purpose**: High-level .NET assembly model on top of `rustre-dotnet-metadata`. Provides
  ergonomic access to types, methods, fields, properties, events, generic instantiations,
  custom attributes, and CIL method bodies. Adds CLR loader, JIT/heap analysis, IL printer,
  CIL CFG + stack verifier, string-decryption, packer detection, obfuscation removal, and
  a C# reconstructor layer.
- **Dependencies**: `anyhow`, `thiserror`, `serde`, `rustre-dotnet-metadata` (path),
  `bitflags`, `ahash`.
- **Tests**: 2 integration test files (`tests/blitz.rs`, `tests/blitz2.rs`) → crate is
  testable.

## Module map (`lib.rs` re-exports)
- `cil_control_flow` — CIL basic-block CFG, edges, EH regions, dominators.
- `cil_stack_analyzer` — abstract stack types, stack effects, join points, verifier.
- `clr_analysis` — CLR header / metadata-root / stream parsing (`MetadataRoot`,
  `MetadataStream`, `ClrFlags` bitflags), error type `ClrAnalysisError`.
- `clr_jit_analysis` — JIT tier modelling: `CompilationTier`, `TieredCompilation`,
  `PgoData`/`PgoEdge`, `JitCompiledMethod`, `JitArtifact`, `DecompileJitResult`,
  `ClrJitAnalysis`, `JitSummary`.
- `clr_loader` — strong-typed wrapper over metadata tables: `AssemblyDef`, `AssemblyRef`,
  `ModuleDef`, `TypeDef`, `MethodDef`, `FieldDef`, `MemberRef`, attribute newtypes
  (`TypeAttributes`, `MethodAttributes`, `MethodImplAttributes`, `FieldAttributes`),
  `PublicKeyToken`, top-level `ClrLoader`. Errors via `ClrLoaderError`.
- `csharp_reconstructor` — pattern detectors (`AsyncMethodDetector`, `LinqPatternDetector`,
  `AttributeParser`) and model (`CsharpMethod`, `CsharpClass`, `ReconstructedProperty`,
  `CsharpReconstructor`).
- `dotnet_heap_analyzer` — CLR runtime heap model: `MethodTable`(+`MethodTableFlags`),
  `ObjectHeader`, `HeapObject`, `ObjectField`/`FieldValue`, `CorElementType`, `GcRoot`,
  `HeapSegment`, `HeapStats`, `HeapAnalyzer`, generation keys.
- `dotnet_il_printer` — pretty-printing CIL: `IlPrinter`, `IlPrintConfig`,
  `IlDisplayConfig`, `Opcode`, `Operand`, `Instruction`, `MethodBody`, `MethodSignature`,
  `ExceptionHandler`/`HandlerKind`, `StackEffect`, `StackDepthTracker`.
- `dotnet_metadata_tables` — table layout helpers (47 pub items).
- `dotnet_packer_detection` — heuristics for .NET packers (ConfuserEx, Eazfuscator, etc.).
- `dotnet_string_decrypt` — `EncryptedStrTable`, `DecryptionMethod`, `IntKey`,
  `XorDecryptor`, `StringDecryptScanner`, `EncryptedStringCatalog`, `RawCilInsn`,
  `PatternMatch`, `DecryptedResult`.
- `il_decoder` — raw CIL byte → opcode decoding (8 pub fns).
- `obfuscation_remover` — `ObfuscationRemover`, `BasicBlock`, `IlInstruction`/`IlOperand`,
  `ConfuserDecryptorInfo`/`StringDecryptAlgorithm`, `ProxyMethodInfo`,
  `ObfuscationRemovalResult`, `DecryptedStringEntry`, plus free fns
  `identify_string_decryptor`, `emulate_xor_string_decrypt`, `detect_switch_dispatchers`,
  `linearize_dispatcher`, `detect_proxy_method`.

## Top-level (`lib.rs`) public API

### Error
- `enum DotnetError { TypeNotFound, MethodNotFound, FieldNotFound, InvalidSignature, IoError }`
  with `Display`, `Error`, `From<io::Error>`.

### CIL instruction model
- `enum CilOperand { None, Int8, Int32, Int64, Float32, Float64, String, Token, Branch, Switch }`
  (Serialize/Deserialize).
- `struct CilInstruction { offset, opcode, operand }`
  - constructors: `simple`, `branch`, `with_token`, `with_i32`
  - queries: `is_unconditional_branch`, `is_branch`, `is_terminator`, `branch_targets`,
    `byte_size`
- `struct LocalVar { index, type_name, is_pinned }` + `new(idx, type_name)`.
- `enum ExceptionHandlerKind { Catch, Filter, Finally, Fault }` (default Catch, Display).
- `struct ExceptionHandler { kind, try_start, try_end, handler_start, handler_end,
  catch_type, filter_start }`
  - `protects(offset)`, `handles(offset)` (const).
- `struct MethodBody { locals, instructions, exception_handlers, max_stack, init_locals }`
  - `instruction_at(offset)`, `try_instructions_for(handler)`, `branch_targets`,
    `offset_map`, `opcode_histogram`, `has_exception_handlers`, `has_finally`, `code_size`.

### Signatures and generics
- `struct MethodSignature { return_type, params:Vec<(String,String)>, is_static, is_vararg,
  generic_param_count }` → `format(name)`, `param_count`, `returns_void`.
- `struct GenericParam { number, name, flags, constraints }` → `is_reference_type_constrained`,
  `is_value_type_constrained`, `has_default_constructor_constraint`.
- `struct GenericInstantiation { open_type, type_arguments }` → `format`, `arity`.

### Attributes
- `enum AttributeValue { Bool, Byte, SByte, Char, Int16, UInt16, Int32, UInt32, Int64,
  UInt64, Single, Double, String, Type, Array(Vec<Self>), Null }` (Display).
- `struct AttributeArgument { name, value }`.
- `struct CustomAttribute { attr_type, positional_args, named_args, raw_blob }` →
  `from_blob`, `is_type(name)` (matches simple, `.Name`, `::Name`).
- `struct SecurityDeclaration { action, permission_set }`.

### Properties / Events
- `struct PropertyModel { name, type_name, flags, getter, setter, custom_attributes,
  has_default, default_value }` → `has_getter`, `has_setter`, `is_read_only`,
  `is_write_only`, `signature`.
- `struct EventModel { name, type_name, flags, add, remove, raise, custom_attributes }` →
  `has_add`, `has_remove`.

### Flag decoders
- `struct MethodFlags(u32)`: `from_raw`, `is_public/private/protected/internal/static/
  virtual/abstract/sealed/final/special_name/rt_special_name/pinvoke/constructor/
  class_constructor`, `access_modifier()`.
- `struct FieldFlags(u16)`: `from_raw`, `is_public/private/protected/internal/static/
  init_only/literal/not_serialized/special_name`, `has_default`, `has_field_rva`,
  `access_modifier`.
- `struct TypeFlags(u32)`: `from_raw`, `visibility() -> TypeVisibility`, plus
  `is_sealed/abstract/interface/explicit_layout/sequential_layout/unicode/ansi/
  auto_class/serializable/before_field_init/rt_special_name/special_name/import`,
  `has_security`.
- `enum TypeVisibility { NotPublic, Public, NestedPublic, NestedPrivate, NestedFamily,
  NestedAssembly, NestedFamilyAndAssembly, NestedFamilyOrAssembly }`.

### High-level method / field / type
- `struct DotnetMethod { name, signature, body, flags, rva, impl_flags,
  custom_attributes, generic_params, overrides }` → `is_constructor`,
  `is_static_constructor`, `is_property_accessor`, `is_event_accessor`,
  `method_flags`, `is_static`, `is_virtual`, `is_abstract`, `has_body`,
  `instruction_count`, `param_count`, `branch_instructions`,
  `has_custom_attributes`, `get_custom_attribute(name)`.
- `struct DotnetField { name, type_name, flags, is_static, custom_attributes,
  marshal_info, constant_value, field_rva, offset }` → `is_literal`, `is_init_only`,
  `field_flags`, `format()`.
- `struct MarshalInfo { native_type, blob }`.
- `struct ClassLayout { packing_size, class_size }`.
- `enum DotnetTypeKind { Class, Interface, Struct, Enum, Delegate }`.
- `struct DotnetType { name, namespace, full_name, base_type, interfaces, methods,
  fields, properties, events, nested_types, custom_attributes, generic_params,
  kind_tag, flags, layout }` → `is_class/interface/struct/enum/delegate`,
  `access_modifier`, `kind()` keyword, `is_abstract`, `is_sealed`, `find_method`,
  `find_methods`, `find_field`, `find_property`, `find_event`, `constructors`,
  `static_constructor`, `static_methods`, `instance_methods`, `virtual_methods`,
  `abstract_methods`, `static_fields`, `instance_fields`, `constant_fields`,
  `get_custom_attribute`, `has_custom_attributes`, `implements(iface)`,
  `method_count`, `field_count`.

### Assembly / Module
- `struct AssemblyVersion { major, minor, build, revision }` (Display `a.b.c.d`).
- `struct AssemblyInfo { name, version, culture, public_key, hash_alg, flags }` →
  `is_strong_named`, `is_retargetable`, `display_name`.
- `struct AssemblyReference { name, version, culture, public_key_or_token, hash_value,
  flags }` → `is_retargetable`, `display_name`.
- `struct ModuleInfo { name, mvid:[u8;16] }`.

### Internal helpers (private)
- `opcode_name`, `opcode_name_hi`, `prefix1_opcode_name`, `decode_element_type`,
  `parse_method_body`, `decode_operand`, `decode_operand_hi` — full ECMA-335 §III opcode
  table + fat/tiny method body decoder.

## Behaviour summary
The crate is a self-contained .NET assembly representation layer. Inputs are PE+CLR byte
buffers (passed through `rustre-dotnet-metadata` and the local `clr_loader`); outputs are
strongly-typed `DotnetType` / `DotnetMethod` / `DotnetField` graphs with CIL bodies
decoded into `CilInstruction` streams, plus rich analyses: control-flow CFG (`CilCfg`,
`CilDominator`), stack verification (`StackVerifier`, `VerifyResult`), JIT/PGO modelling,
heap/MT/object reconstruction, IL pretty-printing, string-decryption (XOR, ConfuserEx
algorithms), packer detection, obfuscation removal (switch flattening, proxy methods),
and a C# reconstruction layer (async state machines, LINQ patterns, attributes,
properties, classes). Flag bytes are decoded into `MethodFlags`/`FieldFlags`/`TypeFlags`
typed wrappers per ECMA-335.

Tiny vs fat method-body headers are both parsed in `parse_method_body`; fat header size
field is interpreted in 4-byte units (minimum 3). Branch decoding produces absolute
offsets relative to the start of the code section.

## Stats
- Public functions: 329 (across 14 source files)
- Public types (struct/enum/trait/mod): ~531 public items total
- Test files: 2 (blitz.rs, blitz2.rs) — crate is testable end-to-end.
