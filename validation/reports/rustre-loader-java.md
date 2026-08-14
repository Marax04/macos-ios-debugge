# rustre-loader-java — Public Functions

Crate: `rustre-loader-java` — Loader Java per `.class` file e archivi JAR. Parsing, disassembly bytecode JVM, type system, decompilazione, analisi sicurezza, parsing manifest, e classpath.

Conteggio funzioni pubbliche: **217**.

Elenco signature (raggruppate per file).

---

## `src/lib.rs`

- `JavaClass::parse(data: &[u8]) -> Result<Self, JavaLoaderError>` — parsa un file `.class` Java (magic CAFEBABE, constant pool, fields, methods).
- `is_class(data: &[u8]) -> bool` — true se i primi 4 byte sono `0xCAFEBABE`.
- `is_jar(data: &[u8]) -> bool` — true se i dati sono archivio ZIP con almeno una entry `.class`.
- `JvmInstruction::cp_index(&self) -> Option<u16>` — indice nel constant pool se l'istruzione referenzia CP.
- `JvmDisassembler::disassemble(&self, code: &[u8]) -> Vec<JvmInstruction>` — disassembla un blocco di bytecode JVM.
- `JavaTypeParser::parse_field(&self, desc: &str) -> Option<JavaType>` — parsa un field descriptor (es. `"I"`, `"Ljava/lang/String;"`).
- `JavaTypeParser::parse_method(&self, desc: &str) -> Option<(Vec<JavaType>, JavaType)>` — parsa un method descriptor restituendo (params, return).
- `JavaClass::string_literals(&self) -> Vec<&str>` — estrae literal stringa dal constant pool.
- `JavaClass::method_calls(&self) -> Vec<String>` — elenco method ref dal constant pool.
- `JavaClass::uses_reflection(&self) -> bool` — euristica: usa `java/lang/reflect`.
- `JavaClass::uses_crypto(&self) -> bool` — euristica: usa API `javax/crypto` o `java/security`.
- `JavaClass::obfuscation_score(&self) -> f64` — score 0..1 di offuscamento (nomi corti/non-ascii).
- `JavaClass::is_obfuscated(&self) -> bool` — true se score sopra soglia.
- `ClassFile::parse(data: &[u8]) -> Result<Self, JavaLoaderError>` — parsing completo class file (variante con attributi).
- `AttributeParser::parse_code_attribute(data: &[u8], cp: &[ConstantPoolEntry]) -> Result<CodeAttribute, JavaLoaderError>` — parsa attributo `Code` (max_stack, locals, exception table).
- `AttributeParser::parse_exceptions_attribute(data: &[u8], cp: &[ConstantPoolEntry]) -> Result<Vec<String>, JavaLoaderError>` — parsa lista throws.
- `AttributeParser::parse_inner_classes(data: &[u8], cp: &[ConstantPoolEntry]) -> Result<Vec<InnerClass>, JavaLoaderError>` — parsa inner classes.
- `AttributeParser::parse_signature_attribute(data: &[u8], cp: &[ConstantPoolEntry]) -> Result<String, JavaLoaderError>` — parsa generics signature.
- `BytecodeScanner::find_string_usage(code: &CodeAttribute, cp: &[ConstantPoolEntry]) -> Vec<StringRef>` — scan ldc/ldc_w per uso di stringhe.
- `BytecodeScanner::find_method_calls(code: &CodeAttribute, cp: &[ConstantPoolEntry]) -> Vec<MethodCallRef>` — scan invoke* per chiamate metodo.
- `BytecodeScanner::find_field_accesses(code: &CodeAttribute, cp: &[ConstantPoolEntry]) -> Vec<FieldAccessRef>` — scan getfield/putfield/getstatic/putstatic.
- `ClassHierarchy::build_hierarchy(classes: &[ClassFile]) -> ClassHierarchy` — costruisce gerarchia da elenco di classi.
- `ClassHierarchy::is_subclass_of(&self, class: &str, target: &str) -> bool` — risale catena super class.
- `ClassHierarchy::find_implementations(&self, interface: &str) -> Vec<String>` — trova implementazioni di interfaccia.
- `PatternDetector::detect_design_patterns(class: &ClassFile) -> Vec<DesignPattern>` — rileva design pattern noti.
- `PatternDetector::detect_singleton(class: &ClassFile) -> bool` — euristica Singleton.
- `PatternDetector::detect_factory(class: &ClassFile) -> bool` — euristica Factory.
- `PatternDetector::detect_builder(class: &ClassFile) -> bool` — euristica Builder.
- `PatternDetector::detect_observer(class: &ClassFile) -> bool` — euristica Observer.
- `PatternDetector::detect_decorator(class: &ClassFile) -> bool` — euristica Decorator.
- `JarLoader::from_bytes(data: &[u8]) -> Self` — costruisce loader JAR da contenuto in memoria.
- `JarLoader::entries(&self) -> &[JarEntry]` — restituisce tutte le entry ZIP.
- `JarLoader::get(&self, path: &str) -> Option<&[u8]>` — dati di una entry per path.
- `JarLoader::class_entries(&self) -> Vec<&JarEntry>` — filtra entry `.class`.
- `JarAnalyzer::analyze(jar: &JarLoader) -> JarReport` — produce report di analisi JAR.

## `src/java_type_system.rs`

- `JavaType::simple_name(&self) -> String` — nome semplice del tipo.
- `JavaType::to_descriptor(&self) -> String` — serializza tipo in JVM descriptor.
- `FieldDescriptor::to_descriptor(&self) -> String` — serializza field descriptor.
- `MethodDescriptor::param_slots(&self) -> usize` — slot stack consumati (long/double = 2).
- `MethodDescriptor::to_descriptor(&self) -> String` — serializza method descriptor.
- `DescriptorParser::parse_field(desc: &str) -> Result<FieldDescriptor, DescriptorError>` — parser strict di field descriptor.
- `DescriptorParser::parse_method(desc: &str) -> Result<MethodDescriptor, DescriptorError>` — parser strict di method descriptor.
- `TypeRegistry::new() -> Self` — crea registry tipi vuoto.
- `TypeRegistry::add_class(...)` — registra classe con super e interfacce.
- `TypeRegistry::is_subclass_of(&self, child: &str, ancestor: &str) -> bool` — verifica sotto-classe.
- `TypeRegistry::implements(&self, class: &str, iface: &str) -> bool` — verifica implementazione interfaccia.
- `TypeRegistry::ancestors(&self, class: &str) -> Vec<String>` — catena di antenati.
- `TypeRegistry::common_ancestor(&self, a: &str, b: &str) -> Option<String>` — LCA tra due classi.
- `TypeRegistry::direct_subclasses(&self, parent: &str) -> Vec<&str>` — sotto-classi dirette.

## `src/jar_security_analysis.rs`

- `DeserializationFinding::is_unchecked(&self) -> bool` — true se deserializzazione senza validation.
- `ReflectionFinding::can_bypass_access(&self) -> bool` — uso di `setAccessible(true)`.
- `NativeCodeFinding::is_gadget(&self) -> bool` — chiamata nativa potenzialmente gadget.
- `CommandInjectionFinding::is_injection(&self) -> bool` — Runtime.exec con input dinamico.
- `ClassLoaderFinding::can_load_arbitrary_code(&self) -> bool` — uso di defineClass/URLClassLoader.
- `JarSecurityReport::findings_at_or_above(&self, level: RiskLevel) -> Vec<RiskLevel>` — filtra per severità.
- `JarSecurityReport::mock() -> Self` — istanza mock per test.
- `JarSecurityReport::high_risk_count(&self) -> usize` — numero finding ad alto rischio.
- `JarSecurityReport::has_critical(&self) -> bool` — presenza di finding critici.
- `JarSecurityReport::affected_classes(&self) -> Vec<String>` — elenco classi coinvolte.
- `JarSecurityReport::recompute_risk(&mut self)` — ricalcola score complessivo.
- `JarSecurityAnalyzer::analyze_class_bytes(&self, class_name: &str, data: &[u8]) -> JarSecurityReport` — analisi sicurezza su singola classe.

## `src/jar_manifest_parser.rs`

- `ManifestSection::new() -> Self` — sezione manifest vuota.
- `ManifestSection::named(name: impl Into<String>) -> Self` — sezione con nome.
- `ManifestSection::get(&self, key: &str) -> Option<&str>` — lookup attributo.
- `ManifestSection::insert(&mut self, key: String, value: String)` — inserisce attributo.
- `Manifest::new() -> Self` — manifest vuoto.
- `Manifest::get_main_class(&self) -> Option<&str>` — Main-Class.
- `Manifest::get_class_path(&self) -> Vec<String>` — Class-Path split.
- `Manifest::get_sealed(&self) -> bool` — Sealed: true/false.
- `Manifest::manifest_version(&self) -> Option<&str>` — Manifest-Version.
- `Manifest::implementation_version(&self) -> Option<&str>` — Implementation-Version.
- `SignatureBundle::stub(subject: impl Into<String>) -> Self` — bundle firma di test.
- `Manifest::main_class(&self) -> Option<&str>` — alias get_main_class.
- `ManifestParser::parse_manifest(&self, data: &[u8]) -> Manifest` — parse da bytes.
- `ManifestParser::parse_manifest_str(&self, text: &str) -> Manifest` — parse da stringa.
- `ManifestParser::verify_signature_file(&self, sf_data: &[u8]) -> Vec<SfEntry>` — verifica file `.SF`.
- `ManifestParser::parse_meta_inf(...)` — parse contenuto META-INF.
- `ManifestParser::analyse(...)` — analisi aggregata di manifest + firme.
- `ManifestParser::extract_entries(&self, manifest: &Manifest) -> Vec<ManifestEntry>` — estrae entry per-file.

## `src/class_file_parser.rs`

- `FieldInfo::name<'a>(&self, cp: &'a [CpEntry]) -> &'a str` — nome field via CP.
- `FieldInfo::descriptor<'a>(&self, cp: &'a [CpEntry]) -> &'a str` — descriptor field via CP.
- `MethodInfo::name<'a>(&self, cp: &'a [CpEntry]) -> &'a str` — nome metodo.
- `MethodInfo::descriptor<'a>(&self, cp: &'a [CpEntry]) -> &'a str` — descriptor metodo.
- `MethodInfo::code_attribute_raw(&self) -> Option<&[u8]>` — raw bytes attributo Code.
- `ClassFile::parse(data: &[u8]) -> Result<Self, ClassParseError>` — parsa class file.
- `ClassFile::resolve_class_name(&self) -> &str` — nome binario classe.
- `ClassFile::resolve_super_name(&self) -> &str` — nome super classe.
- `ClassFile::resolve_utf8(&self, idx: usize) -> &str` — utf8 dal CP.
- `ClassFile::parse_code_attribute(data: &[u8]) -> Result<CodeAttribute, ClassParseError>` — parse attributo Code (statico).
- `ClassFile::string_literals(&self) -> Vec<&str>` — literal stringa CP.
- `ClassFile::method_refs(&self) -> Vec<String>` — method refs CP.
- `ClassFile::interface_names(&self) -> Vec<&str>` — interfacce implementate.
- `ClassFile::source_file(&self) -> Option<&str>` — attributo SourceFile.
- `ClassFile::obfuscation_score(&self) -> f64` — score offuscamento.
- `ClassFile::cp_tag_histogram(&self) -> HashMap<u8, usize>` — distribuzione tag CP.
- `ClassParserBuilder::parse(mut self) -> Result<ClassFile, ClassParseError>` — esegue parsing.

## `src/jar_decompiler.rs`

- `ConstantPool::stats(&self) -> ConstantPoolStats` — statistiche CP.
- `ConstantPool::utf8_strings(&self) -> Vec<&str>` — tutte le utf8.
- `ConstantPool::referenced_classes(&self) -> Vec<String>` — classi referenziate.
- `ConstantPool::method_refs(&self) -> Vec<String>` — method refs.
- `ConstantPool::integer_constants(&self) -> Vec<i32>` — costanti integer.
- `ConstantPool::search_strings(&self, pattern: &str) -> Vec<&str>` — ricerca stringhe per pattern.
- `ConstantPool::utf8_at(&self, idx: usize) -> &str` — utf8 per indice.
- `MethodBody::from_bytecode(...)` — costruisce body da bytecode.
- `MethodBody::basic_block_count(&self) -> usize` — numero basic block.
- `MethodBody::has_calls(&self) -> bool` — contiene invoke*.
- `MethodBody::cyclomatic_complexity(&self) -> usize` — complessità ciclomatica.
- `MethodBody::callee_cp_indices(&self) -> Vec<u16>` — indici CP dei callee.
- `AnnotationParser::parse(...)` — parsing annotazioni.
- `AnnotationUtil::is_deprecated(annotations: &[JavaAnnotation]) -> bool` — flag @Deprecated.
- `AnnotationUtil::filter_by_type<'a>(...)` — filtra annotazioni per tipo.
- `InnerClassInfo::new(...)` — costruttore.
- `InnerClassParser::parse(data: &[u8], cp: &[ConstantPoolEntry]) -> Vec<InnerClassInfo>` — parse attributo InnerClasses.
- `JarDisassembler::disassemble(&self, class: &JavaClass) -> String` — disassembla intera classe.
- `JarDisassembler::disassemble_code(&self, code: &[u8]) -> String` — disassembla blocco code.
- `JarDisassembler::render_instruction(instr: &JvmInstruction) -> String` — rende singola istruzione.
- `JarDisassembler::opcode_histogram(&self, code: &[u8]) -> HashMap<String, usize>` — istogramma opcodes.
- `JarDecompiler::new() -> Self` — costruttore.
- `JarDecompiler::add_class(&mut self, class: &JavaClass)` — aggiunge classe.
- `JarDecompiler::add_class_bytes(&mut self, name: &str, data: &[u8])` — aggiunge da bytes.
- `JarDecompiler::get_class(&self, name: &str) -> Option<&DecompiledClass>` — recupera classe decompilata.
- `JarDecompiler::class_names(&self) -> Vec<&str>` — elenco classi.
- `JarDecompiler::all_external_refs(&self) -> Vec<String>` — referenze esterne aggregate.
- `JarDecompiler::most_complex_class(&self) -> Option<&DecompiledClass>` — classe con complessità massima.

## `src/jar_loader.rs`

- `JarMetadata::main_class(&self) -> Option<&str>` — Main-Class.
- `JarMetadata::class_path(&self) -> Vec<&str>` — Class-Path split.
- `JarMetadata::is_sealed(&self) -> bool` — Sealed.
- `JarMetadata::spec_version(&self) -> Option<&str>` — Specification-Version.
- `JarMetadata::impl_version(&self) -> Option<&str>` — Implementation-Version.
- `JarMetadata::manifest_version(&self) -> Option<&str>` — Manifest-Version.
- `Classpath::add_in_jar(&mut self, path: String)` — aggiunge percorso in-jar.
- `Classpath::add_external(&mut self, path: String)` — aggiunge percorso esterno.
- `Classpath::find_class(&self, binary_name: &str) -> Option<&ClasspathEntry>` — risolve classe nel classpath.
- `DependencyGraph::add_class(&mut self, name: String)` — aggiunge nodo classe.
- `DependencyGraph::add_dep(&mut self, from: &str, to: String)` — aggiunge arco di dipendenza.
- `DependencyGraph::transitive_deps<'a>(&'a self, root: &'a str) -> HashSet<&'a str>` — chiusura transitiva.
- `DependencyGraph::roots(&self) -> Vec<&str>` — radici del grafo.
- `Jar::parse(data: &[u8], target_version: u32) -> Result<Self, JarError>` — parser JAR completo.
- `Jar::main_class(&self) -> Option<&str>` — Main-Class.
- `Jar::class(&self, binary_name: &str) -> Option<&ClassFile>` — lookup classe per nome binario.
- `Jar::class_names(&self) -> Vec<&str>` — tutti i nomi classi.
- `Jar::all_string_literals(&self) -> Vec<(&str, Vec<&str>)>` — literal stringa per classe.
- `Jar::package_stats(&self) -> HashMap<&str, usize>` — n. classi per package.
- `Jar::is_signed(&self) -> bool` — presenza META-INF/*.SF.
- `Jar::resources(&self) -> Vec<&str>` — entry non-class.
- `Jar::spi_providers(&self) -> HashMap<&str, Vec<&str>>` — provider Service Provider Interface.

## `src/jar_analyzer.rs`

- `JarManifest::parse(data: &[u8]) -> Result<Self, JarError>` — parsing manifest.
- `JarManifest::effective_module_name(&self) -> Option<&str>` — Automatic-Module-Name o derivato.
- `JarAnalyzer::new(data: &'a [u8]) -> Result<Self, JarError>` — costruttore.
- `JarAnalyzer::list_entries(&self) -> Vec<ZipEntry>` — tutte le entry ZIP.
- `JarAnalyzer::class_files(&self) -> Vec<ZipEntry>` — entry `.class`.
- `JarAnalyzer::resources(&self) -> Vec<ZipEntry>` — entry risorse.
- `JarAnalyzer::meta_inf_entries(&self) -> Vec<ZipEntry>` — entry META-INF.
- `JarAnalyzer::manifest(&self) -> Result<JarManifest, JarError>` — parsing manifest.
- `JarAnalyzer::entry_data(&self, name: &str) -> Option<Vec<u8>>` — dati di una entry (decompressi).
- `JarAnalyzer::entry_count(&self) -> usize` — numero entry.
- `JpmsModule::provided_services(&self) -> Vec<&str>` — `provides` JPMS.
- `JpmsModule::used_services(&self) -> Vec<&str>` — `uses` JPMS.
- `JpmsModule::parse(data: &[u8]) -> Result<JpmsModule, JarError>` — parsa module-info.class.
- `ServiceScanner::scan(analyzer: &JarAnalyzer<'_>) -> Vec<ServiceEntry>` — scan META-INF/services.

## `src/bytecode_analyzer.rs`

- `CpInfo::parse(data: &[u8]) -> Result<(Self, usize), BytecodeError>` — parsa una CP entry, ritorna (entry, byte consumati).
- `ConstantPool::get(&self, index: usize) -> Option<&CpInfo>` — lookup CP.
- `ConstantPool::utf8(&self, index: usize) -> Option<&str>` — utf8 per indice.
- `ConstantPool::class_name(&self, index: usize) -> Option<&str>` — nome classe per indice.
- `ConstantPool::iter(&self) -> impl Iterator<Item = (usize, &CpInfo)>` — iteratore.
- `ConstantPool::all_strings(&self) -> Vec<&str>` — tutte le utf8.
- `CodeAttribute::instruction_count(&self) -> usize` — numero istruzioni.
- `CodeAttribute::parse_code_attribute(...)` — parser dell'attributo Code.
- `CallSiteCollector::collect(&self, code: &[u8]) -> Vec<CallSite>` — call site da bytecode.
- `ClassAnalysis::parse(data: &[u8]) -> Result<Self, BytecodeError>` — analisi classe.
- `ClassAnalysis::all_call_sites(&self) -> Vec<CallSite>` — tutti i call site.
- `ClassAnalysis::methods_named(&self, name: &str) -> Vec<&MethodAnalysis>` — metodi per nome.

## `src/classfile_parser.rs`

- `ClassFile::java_version(&self) -> String` — stringa "Java N" dalla major version.
- `ConstantPool::utf8(&self, index: u16) -> Option<&str>` — utf8 per indice.
- `ClassFile::class_name(&self) -> Option<&str>` — nome questa classe.
- `ClassFile::super_name(&self) -> Option<&str>` — nome super classe.
- `ClassFile::parse(data: &[u8]) -> Result<ClassFile, ParseError>` — parse class file.

## `src/bytecode_analysis.rs`

- `instruction_width(code: &[u8], pc: usize) -> usize` — larghezza in byte dell'istruzione a `pc` (gestisce wide/tableswitch/lookupswitch).
- `build_cfg(code: &[u8], exc_table: &[ExceptionTableEntry]) -> BTreeMap<u32, BasicBlock>` — costruisce control flow graph.
- `compute_stack_depths(blocks: &mut BTreeMap<u32, BasicBlock>, code: &[u8])` — propaga profondità stack per blocco.
- `reconstruct_try_catch(exc_table: &[ExceptionTableEntry]) -> Vec<TryCatch>` — ricostruisce blocchi try/catch dalla exception table.
- `find_subroutines(code: &[u8]) -> Vec<Subroutine>` — individua subroutine (jsr/ret).
- `collect_narrowing_hints<S: std::hash::BuildHasher>(...)` — raccoglie hint di type narrowing (checkcast/instanceof).
- `MethodCfg::analyze(code_attr: &CodeAttribute, cp_class_names: &HashMap<u16, String>) -> Self` — analisi CFG di un metodo.
- `MethodCfg::largest_block(&self) -> Option<&BasicBlock>` — blocco più grande.
- `MethodCfg::handler_pcs(&self) -> Vec<u32>` — PC degli exception handler.

## `src/class_parser_full.rs`

- `ConstantPool::get(&self, idx: u16) -> Result<&CpEntry, ClassParseError>` — lookup con error.
- `ConstantPool::utf8(&self, idx: u16) -> Result<&str, ClassParseError>` — utf8 con error.
- `ConstantPool::class_name(&self, idx: u16) -> Result<&str, ClassParseError>` — nome classe con error.
- `MethodInfo::code(&self) -> Option<&CodeAttribute>` — attributo Code.
- `MethodInfo::checked_exceptions(&self) -> &[u16]` — indici CP delle checked exceptions.
- `MethodInfo::signature(&self) -> Option<&str>` — generics signature.
- `MethodInfo::visible_annotations(&self) -> &[Annotation]` — annotazioni runtime-visible.
- `ClassFile::parse(data: &[u8]) -> Result<Self, ClassParseError>` — parser completo.
- `ClassFile::this_class_name(&self) -> Option<&str>` — nome questa classe.
- `ClassFile::super_class_name(&self) -> Option<&str>` — nome super.
- `ClassFile::interface_names(&self) -> Vec<&str>` — interfacce.
- `ClassFile::source_file(&self) -> Option<&str>` — attributo SourceFile.
- `ClassFile::signature(&self) -> Option<&str>` — generics signature di classe.
- `ClassFile::bootstrap_methods(&self) -> &[BootstrapMethod]` — invokedynamic bootstrap.
- `ClassFile::inner_classes(&self) -> &[InnerClassEntry]` — inner classes.
- `ClassFile::nest_members(&self) -> &[u16]` — nest members (JEP 181).
- `ClassFile::permitted_subclasses(&self) -> &[u16]` — sealed classes permitted.
- `ClassFile::record_components(&self) -> &[RecordComponentInfo]` — componenti record.
- `ClassFile::visible_annotations(&self) -> &[Annotation]` — annotazioni runtime-visible di classe.
- `ClassFile::is_record(&self) -> bool` — true se classe record.
- `ClassFile::find_method(&self, name: &str, descriptor: &str) -> Option<&MethodInfo>` — lookup metodo.
- `ClassFile::string_literals(&self) -> Vec<&str>` — literal stringa.
- `ClassFile::referenced_classes(&self) -> HashMap<u16, &str>` — classi referenziate via ClassRef.

## `src/bytecode_disassembler.rs`

- `JvmInsn::resolve_cp_operand<'c>(&self, class: &'c ClassFile) -> Option<&'c CpEntry>` — risolve l'operand CP.
- `BytecodeDisassembler::disassemble_code(&self, code: &[u8]) -> Vec<JvmInsn>` — disassembla un blocco.
- `BytecodeDisassembler::format_instruction(&self, insn: &JvmInsn) -> String` — formatta istruzione testuale.
- `BytecodeDisassembler::detect_try_catch_blocks(...)` — rileva blocchi try/catch dal CFG.
- `BytecodeDisassembler::branch_targets(&self, insns: &[JvmInsn]) -> Vec<u32>` — target dei branch.

## `src/bytecode_disasm.rs`

- `JvmInstr::branch_target(&self) -> Option<u32>` — target di branch se istruzione di salto.
- `disassemble(bytecode: &[u8]) -> Vec<JvmInstr>` — disassembler standalone.
- `decode_at(code: &[u8], pc: usize) -> Option<JvmInstr>` — decodifica singola istruzione a `pc`.
- `build_pc_map(instrs: &[JvmInstr]) -> HashMap<u32, usize>` — mappa PC → indice nell'elenco istruzioni.
