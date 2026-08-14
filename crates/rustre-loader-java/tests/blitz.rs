//! Exhaustive black-box tests for `rustre-loader-java`.
use rustre_loader_java::*;

// ─── helpers ────────────────────────────────────────────────────────────

/// Build a minimal valid .class byte sequence with a small constant pool.
/// CP layout (1-indexed):
///  1: Utf8 "`MyCls`"
///  2: `ClassRef` -> 1
///  3: Utf8 "java/lang/Object"
///  4: `ClassRef` -> 3
fn minimal_class() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // magic
    d.extend_from_slice(&[0, 0]);                    // minor
    d.extend_from_slice(&[0, 52]);                   // major = 52 (Java 8)
    d.extend_from_slice(&[0, 5]);                    // cp_count = 5 (4 real entries)
    // #1 Utf8 "MyCls"
    d.push(1);
    d.extend_from_slice(&(5u16).to_be_bytes());
    d.extend_from_slice(b"MyCls");
    // #2 ClassRef -> 1
    d.push(7);
    d.extend_from_slice(&1u16.to_be_bytes());
    // #3 Utf8 "java/lang/Object"
    d.push(1);
    d.extend_from_slice(&16u16.to_be_bytes());
    d.extend_from_slice(b"java/lang/Object");
    // #4 ClassRef -> 3
    d.push(7);
    d.extend_from_slice(&3u16.to_be_bytes());
    // access_flags = PUBLIC | SUPER
    d.extend_from_slice(&0x0021u16.to_be_bytes());
    // this_class = 2
    d.extend_from_slice(&2u16.to_be_bytes());
    // super_class = 4
    d.extend_from_slice(&4u16.to_be_bytes());
    // interfaces_count
    d.extend_from_slice(&0u16.to_be_bytes());
    // fields_count
    d.extend_from_slice(&0u16.to_be_bytes());
    // methods_count
    d.extend_from_slice(&0u16.to_be_bytes());
    d
}

// ─── JavaVersion ────────────────────────────────────────────────────────

#[test]
fn java_release_subtract() {
    assert_eq!(JavaVersion { major: 52, minor: 0 }.java_release(), 8);
    assert_eq!(JavaVersion { major: 61, minor: 0 }.java_release(), 17);
}

#[test]
fn java_release_saturates_on_small_major() {
    assert_eq!(JavaVersion { major: 10, minor: 0 }.java_release(), 0);
    assert_eq!(JavaVersion { major: 0, minor: 0 }.java_release(), 0);
}

#[test]
fn java_version_display() {
    assert_eq!(format!("{}", JavaVersion { major: 52, minor: 0 }), "Java 8");
}

#[test]
fn java_version_eq_and_copy() {
    let a = JavaVersion { major: 52, minor: 3 };
    let b = a;
    assert_eq!(a, b);
}

// ─── is_class / is_jar ──────────────────────────────────────────────────

#[test]
fn is_class_detects_magic() {
    assert!(is_class(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0]));
}

#[test]
fn is_class_rejects_wrong_magic() {
    assert!(!is_class(&[0xCA, 0xFE, 0xBA, 0xBF]));
    assert!(!is_class(&[]));
    assert!(!is_class(&[0xCA, 0xFE, 0xBA]));
}

#[test]
fn is_jar_requires_pk_and_class_substring() {
    let mut d = b"PK\x03\x04".to_vec();
    d.extend_from_slice(b"foo.class");
    assert!(is_jar(&d));
}

#[test]
fn is_jar_rejects_non_pk() {
    assert!(!is_jar(b"abcdefoo.class"));
}

#[test]
fn is_jar_rejects_pk_without_class_entry() {
    assert!(!is_jar(b"PK\x03\x04hello world"));
}

// ─── JavaClass::parse happy ─────────────────────────────────────────────

#[test]
fn parse_minimal_class_succeeds() {
    let d = minimal_class();
    let c = JavaClass::parse(&d).expect("parse");
    assert_eq!(c.version.major, 52);
    assert_eq!(c.class_name, "MyCls");
    assert_eq!(c.super_name.as_deref(), Some("java/lang/Object"));
    assert!(c.interfaces.is_empty());
    assert!(c.fields.is_empty());
    assert!(c.methods.is_empty());
    assert!(c.flags.contains(JavaClassFlags::PUBLIC));
    assert!(c.flags.contains(JavaClassFlags::SUPER));
}

#[test]
fn is_interface_and_is_abstract_reflect_flags() {
    let mut d = minimal_class();
    // overwrite access_flags at known offset (after CP).
    // Find the access_flags position: after cp serialization, which we built.
    // Easier: parse to know position—use the data fact that we wrote 0x0021,
    // then locate it by sequence.
    let pos = d.windows(2).position(|w| w == [0x00, 0x21]).unwrap();
    d[pos] = 0x06;
    d[pos + 1] = 0x00; // INTERFACE (0x0200) | ABSTRACT (0x0400) = 0x0600
    let c = JavaClass::parse(&d).unwrap();
    assert!(c.is_interface());
    assert!(c.is_abstract());
}

// ─── JavaClass::parse errors ────────────────────────────────────────────

#[test]
fn parse_empty_is_truncated() {
    assert!(matches!(JavaClass::parse(&[]), Err(JavaLoaderError::TruncatedData)));
}

#[test]
fn parse_short_is_truncated() {
    assert!(matches!(
        JavaClass::parse(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0]),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn parse_wrong_magic_is_invalid_magic() {
    let d = vec![0; 32];
    assert!(matches!(JavaClass::parse(&d), Err(JavaLoaderError::InvalidMagic)));
}

#[test]
fn parse_unknown_cp_tag_is_invalid_constant_pool() {
    let mut d = Vec::new();
    d.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    d.extend_from_slice(&[0, 0, 0, 52]);
    d.extend_from_slice(&2u16.to_be_bytes()); // cp_count = 2 -> 1 real entry
    d.push(250); // unknown tag
    let err = JavaClass::parse(&d).unwrap_err();
    assert!(matches!(err, JavaLoaderError::InvalidConstantPool));
}

#[test]
fn parse_truncated_in_cp_utf8() {
    let mut d = Vec::new();
    d.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]);
    d.extend_from_slice(&2u16.to_be_bytes());
    d.push(1);
    d.extend_from_slice(&100u16.to_be_bytes()); // declared len = 100, but no body
    assert!(matches!(JavaClass::parse(&d), Err(JavaLoaderError::TruncatedData)));
}

#[test]
fn parse_truncated_after_header() {
    let mut d = Vec::new();
    d.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]);
    d.extend_from_slice(&1u16.to_be_bytes()); // cp_count = 1 (no entries)
    // No further bytes -> truncated when reading access_flags etc.
    assert!(matches!(JavaClass::parse(&d), Err(JavaLoaderError::TruncatedData)));
}

// ─── ConstantPoolEntry Display ──────────────────────────────────────────

#[test]
fn cp_entry_display_variants() {
    assert_eq!(format!("{}", ConstantPoolEntry::Utf8("hi".into())), "Utf8(hi)");
    assert_eq!(format!("{}", ConstantPoolEntry::Integer(-5)), "Integer(-5)");
    assert_eq!(format!("{}", ConstantPoolEntry::Long(7)), "Long(7)");
    assert_eq!(format!("{}", ConstantPoolEntry::ClassRef(3)), "ClassRef(3)");
    assert_eq!(format!("{}", ConstantPoolEntry::StringRef(4)), "StringRef(4)");
    assert_eq!(
        format!("{}", ConstantPoolEntry::FieldRef { class: 1, nat: 2 }),
        "FieldRef(1,2)"
    );
    assert_eq!(
        format!("{}", ConstantPoolEntry::MethodRef { class: 1, nat: 2 }),
        "MethodRef(1,2)"
    );
    assert_eq!(
        format!("{}", ConstantPoolEntry::NameAndType { name: 1, desc: 2 }),
        "NameAndType(1,2)"
    );
    assert_eq!(format!("{}", ConstantPoolEntry::Other(99)), "Other(99)");
}

// ─── JvmOpcode ──────────────────────────────────────────────────────────

#[test]
fn opcode_roundtrip_known() {
    for b in 0x00u8..=0xC9 {
        let op = JvmOpcode::from_byte(b);
        // Each known byte should decode to a non-Unknown value, except for
        // gaps in the JVM table (none in 0x00..=0xC9 actually). Mnemonic must
        // be present.
        if op != JvmOpcode::Unknown {
            assert!(!op.mnemonic().is_empty());
            assert_eq!(op as u8, b, "opcode {b:#x} round-trip failed");
        }
    }
}

#[test]
fn opcode_unknown_for_high_bytes() {
    assert_eq!(JvmOpcode::from_byte(0xFE), JvmOpcode::Unknown);
    assert_eq!(JvmOpcode::from_byte(0xFF), JvmOpcode::Unknown);
}

#[test]
fn opcode_is_invoke_set() {
    assert!(JvmOpcode::Invokevirtual.is_invoke());
    assert!(JvmOpcode::Invokestatic.is_invoke());
    assert!(JvmOpcode::Invokedynamic.is_invoke());
    assert!(!JvmOpcode::Nop.is_invoke());
}

#[test]
fn opcode_is_branch_set() {
    assert!(JvmOpcode::Goto.is_branch());
    assert!(JvmOpcode::Ifnull.is_branch());
    assert!(JvmOpcode::Tableswitch.is_branch());
    assert!(!JvmOpcode::Iadd.is_branch());
}

#[test]
fn opcode_is_return_set() {
    assert!(JvmOpcode::Return.is_return());
    assert!(JvmOpcode::Ireturn.is_return());
    assert!(!JvmOpcode::Goto.is_return());
}

#[test]
fn opcode_display_equals_mnemonic() {
    assert_eq!(format!("{}", JvmOpcode::Nop), "nop");
    assert_eq!(format!("{}", JvmOpcode::Invokestatic), "invokestatic");
}

// ─── JvmDisassembler ────────────────────────────────────────────────────

#[test]
fn disasm_empty() {
    let d = JvmDisassembler::new();
    assert!(d.disassemble(&[]).is_empty());
}

#[test]
fn disasm_simple_no_operand_seq() {
    let d = JvmDisassembler::new();
    let v = d.disassemble(&[0x00, 0x01, 0xB1]); // nop, aconst_null, return
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].opcode, JvmOpcode::Nop);
    assert_eq!(v[1].opcode, JvmOpcode::AconstNull);
    assert_eq!(v[2].opcode, JvmOpcode::Return);
    assert_eq!(v[0].offset, 0);
    assert_eq!(v[1].offset, 1);
    assert_eq!(v[2].offset, 2);
}

#[test]
fn disasm_with_operands() {
    let d = JvmDisassembler::new();
    // bipush 5 ; sipush 0x1234 ; return
    let v = d.disassemble(&[0x10, 5, 0x11, 0x12, 0x34, 0xB1]);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].opcode, JvmOpcode::Bipush);
    assert_eq!(v[0].operands, vec![5]);
    assert_eq!(v[1].opcode, JvmOpcode::Sipush);
    assert_eq!(v[1].operands, vec![0x12, 0x34]);
}

#[test]
fn disasm_unknown_stops() {
    let d = JvmDisassembler::new();
    let v = d.disassemble(&[0x00, 0xFE, 0x00]);
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].opcode, JvmOpcode::Unknown);
}

#[test]
fn jvm_instruction_cp_index() {
    let i = JvmInstruction {
        offset: 0,
        opcode: JvmOpcode::Invokestatic,
        operands: vec![0x00, 0x05],
    };
    assert_eq!(i.cp_index(), Some(5));
    assert!(i.is_invoke());

    let short = JvmInstruction {
        offset: 0,
        opcode: JvmOpcode::Bipush,
        operands: vec![1],
    };
    assert_eq!(short.cp_index(), None);
}

#[test]
fn jvm_instruction_display() {
    let i = JvmInstruction {
        offset: 7,
        opcode: JvmOpcode::Nop,
        operands: vec![],
    };
    assert_eq!(format!("{i}"), "0007 nop");
}

// ─── JavaDescriptorParser ───────────────────────────────────────────────

#[test]
fn parse_field_primitive() {
    let p = JavaDescriptorParser::new();
    assert_eq!(p.parse_field("I"), Some(JavaType::Int));
    assert_eq!(p.parse_field("Z"), Some(JavaType::Boolean));
    assert_eq!(p.parse_field("J"), Some(JavaType::Long));
    assert_eq!(p.parse_field("V"), Some(JavaType::Void));
}

#[test]
fn parse_field_reference() {
    let p = JavaDescriptorParser::new();
    assert_eq!(
        p.parse_field("Ljava/lang/String;"),
        Some(JavaType::Reference("java/lang/String".into()))
    );
}

#[test]
fn parse_field_array() {
    let p = JavaDescriptorParser::new();
    assert_eq!(
        p.parse_field("[I"),
        Some(JavaType::Array(Box::new(JavaType::Int)))
    );
    assert_eq!(
        p.parse_field("[[B"),
        Some(JavaType::Array(Box::new(JavaType::Array(Box::new(JavaType::Byte)))))
    );
}

#[test]
fn parse_field_rejects_trailing_garbage() {
    let p = JavaDescriptorParser::new();
    assert_eq!(p.parse_field("Ixxx"), None);
    assert_eq!(p.parse_field(""), None);
    assert_eq!(p.parse_field("Q"), None);
}

#[test]
fn parse_field_rejects_unterminated_ref() {
    let p = JavaDescriptorParser::new();
    assert_eq!(p.parse_field("Ljava/lang/String"), None);
}

#[test]
fn parse_method_simple() {
    let p = JavaDescriptorParser::new();
    let (params, ret) = p.parse_method("(I)V").unwrap();
    assert_eq!(params, vec![JavaType::Int]);
    assert_eq!(ret, JavaType::Void);
}

#[test]
fn parse_method_no_params() {
    let p = JavaDescriptorParser::new();
    let (params, ret) = p.parse_method("()Ljava/lang/String;").unwrap();
    assert!(params.is_empty());
    assert_eq!(ret, JavaType::Reference("java/lang/String".into()));
}

#[test]
fn parse_method_many_params() {
    let p = JavaDescriptorParser::new();
    let (params, ret) = p.parse_method("(I[BLjava/lang/String;Z)J").unwrap();
    assert_eq!(params.len(), 4);
    assert_eq!(params[0], JavaType::Int);
    assert_eq!(params[1], JavaType::Array(Box::new(JavaType::Byte)));
    assert_eq!(params[2], JavaType::Reference("java/lang/String".into()));
    assert_eq!(params[3], JavaType::Boolean);
    assert_eq!(ret, JavaType::Long);
}

#[test]
fn parse_method_rejects_no_paren() {
    let p = JavaDescriptorParser::new();
    assert!(p.parse_method("I)V").is_none());
    assert!(p.parse_method("").is_none());
}

#[test]
fn parse_method_rejects_no_close() {
    let p = JavaDescriptorParser::new();
    assert!(p.parse_method("(II").is_none());
}

#[test]
fn java_type_display() {
    assert_eq!(format!("{}", JavaType::Int), "int");
    assert_eq!(format!("{}", JavaType::Boolean), "boolean");
    assert_eq!(
        format!("{}", JavaType::Reference("java/lang/String".into())),
        "java.lang.String"
    );
    assert_eq!(
        format!("{}", JavaType::Array(Box::new(JavaType::Int))),
        "int[]"
    );
}

// ─── JavaClassFlags ─────────────────────────────────────────────────────

#[test]
fn class_flags_bits_correct() {
    assert_eq!(JavaClassFlags::PUBLIC.bits(), 0x0001);
    assert_eq!(JavaClassFlags::INTERFACE.bits(), 0x0200);
    assert_eq!(JavaClassFlags::ENUM.bits(), 0x4000);
}

// ─── JavaLoader ────────────────────────────────────────────────────────

#[test]
fn loader_name_is_java() {
    use rustre_core::Loader;
    assert_eq!(JavaLoader.name(), "java");
}

#[test]
fn loader_can_load_class_and_jar() {
    use rustre_core::{Loader, LoaderInput};
    let class_data = minimal_class();
    let input = LoaderInput::new("test", class_data);
    assert!(JavaLoader.can_load(&input));

    let mut jar = b"PK\x03\x04".to_vec();
    jar.extend_from_slice(b"foo.class");
    let input2 = LoaderInput::new("j", jar);
    assert!(JavaLoader.can_load(&input2));
}

#[test]
fn loader_rejects_random_bytes() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("x", vec![0; 100]);
    assert!(!JavaLoader.can_load(&input));
}

#[tokio::test]
async fn loader_load_returns_view() {
    use rustre_core::{Loader, LoaderInput};
    let d = minimal_class();
    let input = LoaderInput::new("c", d);
    let _ = JavaLoader.load(input).await.expect("load");
}

#[tokio::test]
async fn find_nested_returns_empty_for_non_jar() {
    use rustre_core::{Loader, LoaderInput};
    let d = minimal_class();
    let input = LoaderInput::new("c", d);
    let nested = JavaLoader.find_nested(&input).await.unwrap();
    assert!(nested.is_empty());
}

// ─── JavaArch ──────────────────────────────────────────────────────────

#[test]
fn java_arch_basic() {
    use rustre_core::arch::Architecture;
    use rustre_core::endian::Endian;
    let a = JavaArch;
    assert_eq!(a.name(), "jvm");
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.endian(), Endian::Big);
    assert_eq!(a.registers().len(), 4);
    assert_eq!(a.calling_conventions().len(), 1);
}

#[test]
fn java_arch_disasm_one_byte() {
    use rustre_core::address::Address;
    use rustre_core::arch::Architecture;
    let a = JavaArch;
    let insn = a.disassemble(Address::new(0), &[0x00, 0x01]).unwrap();
    assert_eq!(insn.mnemonic, "nop");
}

// ─── JavaClassAnalyzer ─────────────────────────────────────────────────

#[test]
fn analyzer_string_literals_filters() {
    let d = minimal_class();
    let c = JavaClass::parse(&d).unwrap();
    let a = JavaClassAnalyzer::new(&c);
    let lits = a.string_literals();
    // "MyCls" and "java/lang/Object" — neither starts with '(' or '['
    assert!(lits.contains(&"MyCls"));
    assert!(lits.contains(&"java/lang/Object"));
}

#[test]
fn analyzer_obfuscation_score_empty_class_is_zero() {
    let d = minimal_class();
    let c = JavaClass::parse(&d).unwrap();
    let a = JavaClassAnalyzer::new(&c);
    assert_eq!(a.obfuscation_score(), 0.0);
    assert!(!a.is_obfuscated());
}

#[test]
fn analyzer_no_crypto_no_reflection_default() {
    let d = minimal_class();
    let c = JavaClass::parse(&d).unwrap();
    let a = JavaClassAnalyzer::new(&c);
    assert!(!a.uses_crypto());
    assert!(!a.uses_reflection());
}

// ─── AttributeParser ───────────────────────────────────────────────────

#[test]
fn parse_code_attr_minimal() {
    // max_stack=1, max_locals=2, code_len=1, code=[0xB1], exc_count=0, sub_attr_count=0
    let mut d = vec![];
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(&2u16.to_be_bytes());
    d.extend_from_slice(&1u32.to_be_bytes());
    d.push(0xB1);
    d.extend_from_slice(&0u16.to_be_bytes());
    d.extend_from_slice(&0u16.to_be_bytes());
    let cp = vec![ConstantPoolEntry::Other(0)];
    let ca = AttributeParser::parse_code_attribute(&d, &cp).unwrap();
    assert_eq!(ca.max_stack, 1);
    assert_eq!(ca.max_locals, 2);
    assert_eq!(ca.bytecode, vec![0xB1]);
    assert!(ca.exception_table.is_empty());
    assert!(ca.attributes.is_empty());
}

#[test]
fn parse_code_attr_truncated() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    assert!(matches!(
        AttributeParser::parse_code_attribute(&[0; 4], &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn parse_code_attr_code_overflow() {
    let mut d = vec![];
    d.extend_from_slice(&0u16.to_be_bytes());
    d.extend_from_slice(&0u16.to_be_bytes());
    d.extend_from_slice(&1000u32.to_be_bytes()); // huge code_len
    let cp = vec![ConstantPoolEntry::Other(0)];
    assert!(matches!(
        AttributeParser::parse_code_attribute(&d, &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn parse_exceptions_attr_empty() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    let d = 0u16.to_be_bytes();
    let e = AttributeParser::parse_exceptions_attribute(&d, &cp).unwrap();
    assert!(e.exceptions.is_empty());
}

#[test]
fn parse_exceptions_attr_truncated() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    assert!(matches!(
        AttributeParser::parse_exceptions_attribute(&[], &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
    // count says 2 but no body
    let mut d = vec![];
    d.extend_from_slice(&2u16.to_be_bytes());
    assert!(matches!(
        AttributeParser::parse_exceptions_attribute(&d, &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn parse_inner_classes_empty() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    let d = 0u16.to_be_bytes();
    let ic = AttributeParser::parse_inner_classes(&d, &cp).unwrap();
    assert!(ic.is_empty());
}

#[test]
fn parse_inner_classes_truncated() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    assert!(matches!(
        AttributeParser::parse_inner_classes(&[], &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn parse_signature_attr() {
    let cp = vec![
        ConstantPoolEntry::Other(0),
        ConstantPoolEntry::Utf8("Ljava/util/List;".into()),
    ];
    let d = 1u16.to_be_bytes();
    let s = AttributeParser::parse_signature_attribute(&d, &cp).unwrap();
    assert_eq!(s, "Ljava/util/List;");
}

#[test]
fn parse_signature_attr_truncated() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    assert!(matches!(
        AttributeParser::parse_signature_attribute(&[], &cp),
        Err(JavaLoaderError::TruncatedData)
    ));
}

// ─── JavaBytecodeAnalyzer ──────────────────────────────────────────────

#[test]
fn bytecode_find_string_usage_ldc() {
    // CP: #1 Utf8 "hi", #2 StringRef -> 1
    let cp = vec![
        ConstantPoolEntry::Other(0),
        ConstantPoolEntry::Utf8("hi".into()),
        ConstantPoolEntry::StringRef(1),
    ];
    let code = CodeAttribute {
        max_stack: 0,
        max_locals: 0,
        bytecode: vec![0x12, 2, 0xB1], // ldc #2; return
        exception_table: vec![],
        attributes: vec![],
    };
    let refs = JavaBytecodeAnalyzer::find_string_usage(&code, &cp);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].string_value, "hi");
    assert_eq!(refs[0].opcode_offset, 0);
}

#[test]
fn bytecode_find_method_calls() {
    // #1 Utf8 "C", #2 ClassRef ->1, #3 Utf8 "m", #4 Utf8 "()V",
    // #5 NameAndType{name=3,desc=4}, #6 MethodRef{class=2,nat=5}
    let cp = vec![
        ConstantPoolEntry::Other(0),
        ConstantPoolEntry::Utf8("C".into()),
        ConstantPoolEntry::ClassRef(1),
        ConstantPoolEntry::Utf8("m".into()),
        ConstantPoolEntry::Utf8("()V".into()),
        ConstantPoolEntry::NameAndType { name: 3, desc: 4 },
        ConstantPoolEntry::MethodRef { class: 2, nat: 5 },
    ];
    // invokestatic #6 (0xB8 hi lo) ; return
    let code = CodeAttribute {
        max_stack: 0,
        max_locals: 0,
        bytecode: vec![0xB8, 0x00, 0x06, 0xB1],
        exception_table: vec![],
        attributes: vec![],
    };
    let refs = JavaBytecodeAnalyzer::find_method_calls(&code, &cp);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].class_name, "C");
    assert_eq!(refs[0].method_name, "m");
    assert_eq!(refs[0].descriptor, "()V");
}

#[test]
fn bytecode_find_field_accesses() {
    let cp = vec![
        ConstantPoolEntry::Other(0),
        ConstantPoolEntry::Utf8("C".into()),
        ConstantPoolEntry::ClassRef(1),
        ConstantPoolEntry::Utf8("f".into()),
        ConstantPoolEntry::Utf8("I".into()),
        ConstantPoolEntry::NameAndType { name: 3, desc: 4 },
        ConstantPoolEntry::FieldRef { class: 2, nat: 5 },
    ];
    // getstatic #6 ; putstatic #6 ; return
    let code = CodeAttribute {
        max_stack: 0,
        max_locals: 0,
        bytecode: vec![0xB2, 0x00, 0x06, 0xB3, 0x00, 0x06, 0xB1],
        exception_table: vec![],
        attributes: vec![],
    };
    let refs = JavaBytecodeAnalyzer::find_field_accesses(&code, &cp);
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].field_name, "f");
    assert!(refs[0].is_static);
    assert!(!refs[0].is_write);
    assert!(refs[1].is_write);
}

// ─── ClassHierarchy ────────────────────────────────────────────────────

fn mkcls(name: &str, super_n: Option<&str>, ifaces: &[&str]) -> ClassFile {
    ClassFile {
        version: JavaVersion { major: 52, minor: 0 },
        flags: JavaClassFlags::empty(),
        class_name: name.into(),
        super_name: super_n.map(String::from),
        interfaces: ifaces.iter().map(|s| (*s).to_string()).collect(),
        fields: vec![],
        methods: vec![],
        constant_pool: vec![],
    }
}

#[test]
fn hierarchy_is_subclass_reflexive() {
    let classes = vec![mkcls("A", Some("java/lang/Object"), &[])];
    let h = ClassHierarchyBuilder::build_hierarchy(&classes);
    assert!(h.is_subclass_of("A", "A"));
}

#[test]
fn hierarchy_is_subclass_chain() {
    let classes = vec![
        mkcls("A", Some("java/lang/Object"), &[]),
        mkcls("B", Some("A"), &[]),
        mkcls("C", Some("B"), &[]),
    ];
    let h = ClassHierarchyBuilder::build_hierarchy(&classes);
    assert!(h.is_subclass_of("C", "A"));
    assert!(h.is_subclass_of("B", "A"));
    assert!(!h.is_subclass_of("A", "C"));
}

#[test]
fn hierarchy_find_implementations() {
    let classes = vec![
        mkcls("Impl", Some("java/lang/Object"), &["IFoo"]),
        mkcls("Other", Some("java/lang/Object"), &[]),
    ];
    let h = ClassHierarchyBuilder::build_hierarchy(&classes);
    let impls = h.find_implementations("IFoo");
    assert_eq!(impls, vec!["Impl".to_string()]);
}

#[test]
fn hierarchy_unknown_class_false() {
    let h = ClassHierarchyBuilder::build_hierarchy(&[]);
    assert!(!h.is_subclass_of("X", "Y"));
}

// ─── DesignPattern Display ─────────────────────────────────────────────

#[test]
fn design_pattern_display() {
    assert_eq!(format!("{}", DesignPattern::Singleton), "Singleton");
    assert_eq!(format!("{}", DesignPattern::Factory), "Factory");
    assert_eq!(format!("{}", DesignPattern::Builder), "Builder");
    assert_eq!(format!("{}", DesignPattern::Observer), "Observer");
    assert_eq!(format!("{}", DesignPattern::Decorator), "Decorator");
}

// ─── ClassFile::parse ──────────────────────────────────────────────────

#[test]
fn classfile_parse_minimal() {
    let d = minimal_class();
    let cf = ClassFile::parse(&d).expect("parse");
    assert_eq!(cf.class_name, "MyCls");
    assert!(cf.methods.is_empty());
}

#[test]
fn classfile_parse_invalid_magic() {
    assert!(matches!(
        ClassFile::parse(&[0; 20]),
        Err(JavaLoaderError::InvalidMagic)
    ));
}

// ─── JarLoader::from_bytes ─────────────────────────────────────────────

#[test]
fn jar_loader_on_empty_data() {
    let j = JarLoader::from_bytes(&[]);
    assert!(j.entries().is_empty());
    assert!(j.class_entries().is_empty());
    assert!(j.get("foo").is_none());
}

// ─── Error Display ─────────────────────────────────────────────────────

#[test]
fn error_display_messages() {
    assert_eq!(format!("{}", JavaLoaderError::InvalidMagic), "invalid magic");
    assert_eq!(format!("{}", JavaLoaderError::TruncatedData), "truncated data");
    assert_eq!(
        format!("{}", JavaLoaderError::InvalidConstantPool),
        "invalid constant pool"
    );
    assert_eq!(
        format!("{}", JavaLoaderError::ParseError("x".into())),
        "parse error: x"
    );
}
