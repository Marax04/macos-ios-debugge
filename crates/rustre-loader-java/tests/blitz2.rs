//! Adversarial test suite for rustre-loader-java.

use rustre_core::Loader;
use rustre_loader_java::*;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn make_minimal_class() -> Vec<u8> {
    // Minimal valid class: magic + minor + major + cp_count=1 (no entries) +
    // access_flags + this_class=0 + super_class=0 + interfaces=0 + fields=0 + methods=0 + attrs=0
    let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
    v.extend_from_slice(&0u16.to_be_bytes()); // minor
    v.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)
    v.extend_from_slice(&1u16.to_be_bytes()); // cp_count = 1 (zero entries: i in [1,1))
    v.extend_from_slice(&0x0021u16.to_be_bytes()); // access_flags PUBLIC|SUPER
    v.extend_from_slice(&0u16.to_be_bytes()); // this_class idx 0 -> <class#0>
    v.extend_from_slice(&0u16.to_be_bytes()); // super_class 0 -> None
    v.extend_from_slice(&0u16.to_be_bytes()); // interfaces
    v.extend_from_slice(&0u16.to_be_bytes()); // fields
    v.extend_from_slice(&0u16.to_be_bytes()); // methods
    v.extend_from_slice(&0u16.to_be_bytes()); // attributes (not consumed by JavaClass)
    v
}

// ─── Magic / detection ────────────────────────────────────────────────

#[test]
fn t01_is_class_magic_positive() {
    assert!(is_class(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0]));
}

#[test]
fn t02_is_class_magic_negative() {
    assert!(!is_class(&[0xCA, 0xFE, 0xBA, 0xBF]));
    assert!(!is_class(&[]));
    assert!(!is_class(&[0xCA]));
}

#[test]
fn t03_is_jar_positive() {
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(b"xxxxxx.class");
    assert!(is_jar(&data));
}

#[test]
fn t04_is_jar_negative_no_pk() {
    assert!(!is_jar(b"abc.class"));
}

#[test]
fn t05_is_jar_negative_pk_but_no_class() {
    assert!(!is_jar(b"PK\x03\x04nofileshere"));
}

// ─── JavaVersion ──────────────────────────────────────────────────────

#[test]
fn t06_java_version_release() {
    let v = JavaVersion { major: 52, minor: 0 };
    assert_eq!(v.java_release(), 8);
}

#[test]
fn t07_java_version_release_saturates_below_44() {
    let v = JavaVersion { major: 30, minor: 0 };
    assert_eq!(v.java_release(), 0);
}

#[test]
fn t08_java_version_release_zero() {
    let v = JavaVersion { major: 0, minor: 0 };
    assert_eq!(v.java_release(), 0);
}

#[test]
fn t09_java_version_release_max() {
    let v = JavaVersion {
        major: u16::MAX,
        minor: 0,
    };
    assert_eq!(v.java_release(), u16::MAX - 44);
}

#[test]
fn t10_java_version_display() {
    let v = JavaVersion { major: 61, minor: 0 };
    assert_eq!(format!("{v}"), "Java 17");
}

#[test]
fn t11_java_version_eq() {
    let a = JavaVersion { major: 52, minor: 0 };
    let b = JavaVersion { major: 52, minor: 0 };
    let c = JavaVersion { major: 61, minor: 0 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ─── ConstantPoolEntry Display ────────────────────────────────────────

#[test]
fn t12_cpe_display_variants() {
    assert_eq!(
        format!("{}", ConstantPoolEntry::Utf8("hi".into())),
        "Utf8(hi)"
    );
    assert_eq!(format!("{}", ConstantPoolEntry::Integer(7)), "Integer(7)");
    assert_eq!(format!("{}", ConstantPoolEntry::Long(-1)), "Long(-1)");
    assert_eq!(format!("{}", ConstantPoolEntry::ClassRef(5)), "ClassRef(5)");
    assert_eq!(format!("{}", ConstantPoolEntry::StringRef(3)), "StringRef(3)");
    assert_eq!(
        format!("{}", ConstantPoolEntry::FieldRef { class: 1, nat: 2 }),
        "FieldRef(1,2)"
    );
    assert_eq!(
        format!("{}", ConstantPoolEntry::MethodRef { class: 1, nat: 2 }),
        "MethodRef(1,2)"
    );
    assert_eq!(
        format!("{}", ConstantPoolEntry::NameAndType { name: 4, desc: 6 }),
        "NameAndType(4,6)"
    );
    assert_eq!(format!("{}", ConstantPoolEntry::Other(99)), "Other(99)");
}

// ─── JavaClass::parse ─────────────────────────────────────────────────

#[test]
fn t13_parse_minimal_class_ok() {
    let data = make_minimal_class();
    let cls = JavaClass::parse(&data).expect("parse");
    assert_eq!(cls.version.major, 52);
    assert!(cls.flags.contains(JavaClassFlags::PUBLIC));
    assert!(cls.super_name.is_none());
    assert!(cls.fields.is_empty());
    assert!(cls.methods.is_empty());
}

#[test]
fn t14_parse_too_short() {
    assert!(matches!(
        JavaClass::parse(&[0xCA, 0xFE]),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn t15_parse_invalid_magic() {
    let data = vec![0u8; 32];
    assert!(matches!(
        JavaClass::parse(&data),
        Err(JavaLoaderError::InvalidMagic)
    ));
}

#[test]
fn t16_parse_empty() {
    assert!(matches!(
        JavaClass::parse(&[]),
        Err(JavaLoaderError::TruncatedData)
    ));
}

#[test]
fn t17_parse_unknown_cp_tag() {
    let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE];
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&52u16.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes()); // cp_count=2 → 1 entry
    data.push(99); // bogus tag
    let err = JavaClass::parse(&data).unwrap_err();
    assert!(matches!(err, JavaLoaderError::InvalidConstantPool));
}

#[test]
fn t18_parse_truncated_in_cp() {
    let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE];
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&52u16.to_be_bytes());
    data.extend_from_slice(&3u16.to_be_bytes()); // 2 entries promised
    data.push(1); // utf8 but truncated
    let err = JavaClass::parse(&data).unwrap_err();
    assert!(matches!(err, JavaLoaderError::TruncatedData));
}

#[test]
fn t19_is_interface_flag() {
    let mut data = make_minimal_class();
    // access_flags offset = 4+2+2+2 = 10 (cp empty)
    data[10] = 0x02;
    data[11] = 0x00; // INTERFACE 0x0200
    let cls = JavaClass::parse(&data).unwrap();
    assert!(cls.is_interface());
    assert!(!cls.is_abstract());
}

#[test]
fn t20_is_abstract_flag() {
    let mut data = make_minimal_class();
    data[10] = 0x04;
    data[11] = 0x00; // ABSTRACT 0x0400
    let cls = JavaClass::parse(&data).unwrap();
    assert!(cls.is_abstract());
}

// ─── LCG fuzz on parsers — must never panic ───────────────────────────

#[test]
fn t21_fuzz_javaclass_parse() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() as usize) % 256;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = JavaClass::parse(&buf);
    }
}

#[test]
fn t22_fuzz_classfile_parse() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() as usize) % 256;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = ClassFile::parse(&buf);
    }
}

#[test]
fn t23_fuzz_with_correct_magic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = 10 + (g() as usize) % 200;
        let mut buf = vec![0xCA, 0xFE, 0xBA, 0xBE];
        for _ in 4..n {
            buf.push(g() as u8);
        }
        let _ = JavaClass::parse(&buf);
    }
}

#[test]
fn t24_fuzz_descriptor_parser() {
    let p = JavaDescriptorParser::new();
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() as usize) % 32;
        let s: String = (0..n)
            .map(|_| (b'A' + (g() as u8 % 30)) as char)
            .collect();
        let _ = p.parse_field(&s);
        let _ = p.parse_method(&s);
    }
}

#[test]
fn t25_fuzz_disassembler() {
    let d = JvmDisassembler::new();
    let mut g = lcg();
    for _ in 0..100 {
        let n = (g() as usize) % 128;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = d.disassemble(&buf);
    }
}

#[test]
fn t26_fuzz_attribute_parsers() {
    let mut g = lcg();
    let cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Other(0)];
    for _ in 0..200 {
        let n = (g() as usize) % 64;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = AttributeParser::parse_code_attribute(&buf, &cp);
        let _ = AttributeParser::parse_exceptions_attribute(&buf, &cp);
        let _ = AttributeParser::parse_inner_classes(&buf, &cp);
        let _ = AttributeParser::parse_signature_attribute(&buf, &cp);
    }
}

// ─── JvmOpcode ────────────────────────────────────────────────────────

#[test]
fn t27_opcode_roundtrip_all_known() {
    // Every documented byte 0x00..=0xC9 maps to a non-Unknown opcode and yields the same byte
    for b in 0x00u8..=0xC9 {
        let op = JvmOpcode::from_byte(b);
        if op != JvmOpcode::Unknown {
            assert_eq!(op as u8, b, "byte {b:#x} round-trip");
        }
    }
}

#[test]
fn t28_opcode_unknown_for_high_bytes() {
    for b in 0xCAu8..=0xFE {
        assert_eq!(JvmOpcode::from_byte(b), JvmOpcode::Unknown, "byte {b:#x}");
    }
}

#[test]
fn t29_opcode_mnemonic_nonempty() {
    for b in 0x00u8..=0xC9 {
        let op = JvmOpcode::from_byte(b);
        assert!(!op.mnemonic().is_empty());
    }
}

#[test]
fn t30_opcode_classification() {
    assert!(JvmOpcode::Invokevirtual.is_invoke());
    assert!(JvmOpcode::Invokedynamic.is_invoke());
    assert!(!JvmOpcode::Nop.is_invoke());
    assert!(JvmOpcode::Goto.is_branch());
    assert!(JvmOpcode::Tableswitch.is_branch());
    assert!(!JvmOpcode::Iadd.is_branch());
    assert!(JvmOpcode::Return.is_return());
    assert!(JvmOpcode::Ireturn.is_return());
    assert!(!JvmOpcode::Athrow.is_return());
}

#[test]
fn t31_opcode_display() {
    assert_eq!(format!("{}", JvmOpcode::Nop), "nop");
    assert_eq!(format!("{}", JvmOpcode::Goto), "goto");
}

#[test]
fn t32_opcode_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    for b in 0u8..=0xC9 {
        s.insert(JvmOpcode::from_byte(b));
    }
    // Ensure no duplicates among the distinct-byte opcodes (all unique)
    assert!(s.len() >= 200);
    // Hash/Eq consistency
    for b in 0u8..=0xC9 {
        let a = JvmOpcode::from_byte(b);
        let c = JvmOpcode::from_byte(b);
        assert_eq!(a, c);
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        a.hash(&mut h1);
        c.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// ─── JvmInstruction / JvmDisassembler ─────────────────────────────────

#[test]
fn t33_disasm_empty() {
    let d = JvmDisassembler::new();
    assert!(d.disassemble(&[]).is_empty());
}

#[test]
fn t34_disasm_zero_operand_chain() {
    let d = JvmDisassembler::new();
    let code = vec![0x00, 0x60, 0xB1]; // nop, iadd, return
    let ins = d.disassemble(&code);
    assert_eq!(ins.len(), 3);
    assert_eq!(ins[0].opcode, JvmOpcode::Nop);
    assert_eq!(ins[1].opcode, JvmOpcode::Iadd);
    assert_eq!(ins[2].opcode, JvmOpcode::Return);
}

#[test]
fn t35_disasm_bipush_operand() {
    let d = JvmDisassembler::new();
    let code = vec![0x10, 0x7F, 0xB1];
    let ins = d.disassemble(&code);
    assert_eq!(ins[0].opcode, JvmOpcode::Bipush);
    assert_eq!(ins[0].operands, vec![0x7F]);
    assert_eq!(ins[1].opcode, JvmOpcode::Return);
}

#[test]
fn t36_disasm_unknown_breaks() {
    let d = JvmDisassembler::new();
    let code = vec![0x00, 0xFF, 0x00];
    let ins = d.disassemble(&code);
    assert_eq!(ins.len(), 2);
    assert_eq!(ins[1].opcode, JvmOpcode::Unknown);
}

#[test]
fn t37_jvm_instruction_cp_index() {
    let i = JvmInstruction {
        offset: 0,
        opcode: JvmOpcode::Invokevirtual,
        operands: vec![0x12, 0x34],
    };
    assert_eq!(i.cp_index(), Some(0x1234));
    assert!(i.is_invoke());
    let j = JvmInstruction {
        offset: 0,
        opcode: JvmOpcode::Nop,
        operands: vec![],
    };
    assert_eq!(j.cp_index(), None);
}

#[test]
fn t38_jvm_instruction_display() {
    let i = JvmInstruction {
        offset: 42,
        opcode: JvmOpcode::Nop,
        operands: vec![],
    };
    assert_eq!(format!("{i}"), "0042 nop");
}

// ─── JavaDescriptorParser ─────────────────────────────────────────────

#[test]
fn t39_parse_field_primitives() {
    let p = JavaDescriptorParser::new();
    assert_eq!(p.parse_field("I"), Some(JavaType::Int));
    assert_eq!(p.parse_field("J"), Some(JavaType::Long));
    assert_eq!(p.parse_field("Z"), Some(JavaType::Boolean));
    assert_eq!(p.parse_field("V"), Some(JavaType::Void));
    assert_eq!(p.parse_field("B"), Some(JavaType::Byte));
}

#[test]
fn t40_parse_field_reference() {
    let p = JavaDescriptorParser::new();
    assert_eq!(
        p.parse_field("Ljava/lang/String;"),
        Some(JavaType::Reference("java/lang/String".into()))
    );
}

#[test]
fn t41_parse_field_array() {
    let p = JavaDescriptorParser::new();
    assert_eq!(
        p.parse_field("[I"),
        Some(JavaType::Array(Box::new(JavaType::Int)))
    );
    assert_eq!(
        p.parse_field("[[B"),
        Some(JavaType::Array(Box::new(JavaType::Array(Box::new(
            JavaType::Byte
        )))))
    );
}

#[test]
fn t42_parse_field_invalid() {
    let p = JavaDescriptorParser::new();
    assert_eq!(p.parse_field(""), None);
    assert_eq!(p.parse_field("X"), None);
    assert_eq!(p.parse_field("II"), None); // trailing chars
    assert_eq!(p.parse_field("L"), None); // unterminated
    assert_eq!(p.parse_field("Ljava/lang/String"), None);
}

#[test]
fn t43_parse_method_basic() {
    let p = JavaDescriptorParser::new();
    let (params, ret) = p.parse_method("()V").unwrap();
    assert!(params.is_empty());
    assert_eq!(ret, JavaType::Void);
}

#[test]
fn t44_parse_method_complex() {
    let p = JavaDescriptorParser::new();
    let (params, ret) = p.parse_method("(ILjava/lang/String;[B)I").unwrap();
    assert_eq!(params.len(), 3);
    assert_eq!(params[0], JavaType::Int);
    assert_eq!(
        params[1],
        JavaType::Reference("java/lang/String".into())
    );
    assert_eq!(params[2], JavaType::Array(Box::new(JavaType::Byte)));
    assert_eq!(ret, JavaType::Int);
}

#[test]
fn t45_parse_method_invalid() {
    let p = JavaDescriptorParser::new();
    assert!(p.parse_method("").is_none());
    assert!(p.parse_method("V").is_none());
    assert!(p.parse_method("()").is_none()); // no return type
    assert!(p.parse_method("(X)V").is_none());
}

#[test]
fn t46_javatype_display() {
    assert_eq!(format!("{}", JavaType::Int), "int");
    assert_eq!(
        format!("{}", JavaType::Reference("java/lang/String".into())),
        "java.lang.String"
    );
    assert_eq!(
        format!("{}", JavaType::Array(Box::new(JavaType::Int))),
        "int[]"
    );
}

// ─── JavaClassFlags ───────────────────────────────────────────────────

#[test]
fn t47_class_flags_bits_truncate() {
    let f = JavaClassFlags::from_bits_truncate(0xFFFF);
    // Should contain only the documented bits — but from_bits_truncate keeps known bits only.
    assert!(f.contains(JavaClassFlags::PUBLIC));
    assert!(f.contains(JavaClassFlags::INTERFACE));
}

#[test]
fn t48_class_flags_eq_hash() {
    let a = JavaClassFlags::PUBLIC | JavaClassFlags::STATIC;
    let b = JavaClassFlags::PUBLIC | JavaClassFlags::STATIC;
    assert_eq!(a, b);
    let c = JavaClassFlags::PUBLIC;
    assert_ne!(a, c);
}

#[test]
fn t49_class_flags_serde_roundtrip() {
    let f = JavaClassFlags::PUBLIC | JavaClassFlags::FINAL;
    let s = serde_json::to_string(&f).unwrap();
    let back: JavaClassFlags = serde_json::from_str(&s).unwrap();
    assert_eq!(f, back);
}

// ─── Send/Sync threaded stress ────────────────────────────────────────

#[test]
fn t50_threaded_loader_send_sync() {
    use std::sync::Arc;
    use std::thread;
    let loader = Arc::new(JavaLoader);
    let mut handles = vec![];
    for _ in 0..4 {
        let l = Arc::clone(&loader);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = l.name();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t51_threaded_parse_send_sync() {
    use std::sync::Arc;
    use std::thread;
    let data = Arc::new(make_minimal_class());
    let mut handles = vec![];
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = JavaClass::parse(&d).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── JavaArch ────────────────────────────────────────────────────────

#[test]
fn t52_java_arch_basic() {
    use rustre_core::arch::Architecture;
    let a = JavaArch;
    assert_eq!(a.name(), "jvm");
    assert_eq!(a.pointer_size(), 8);
    assert!(a.registers().len() == 4);
    assert!(!a.calling_conventions().is_empty());
}

#[test]
fn t53_java_arch_disassemble() {
    use rustre_core::address::Address;
    use rustre_core::arch::Architecture;
    let a = JavaArch;
    let ins = a.disassemble(Address::new(0), &[0u8]).unwrap();
    assert_eq!(ins.size, 1);
}

// ─── Loader trait ─────────────────────────────────────────────────────

#[tokio::test]
async fn t54_loader_can_load_class() {
    let loader = JavaLoader;
    let input = rustre_core::LoaderInput::new("test.class", make_minimal_class());
    assert!(loader.can_load(&input));
}

#[tokio::test]
async fn t55_loader_can_load_rejects_garbage() {
    let loader = JavaLoader;
    let input = rustre_core::LoaderInput::new("x", vec![0u8; 64]);
    assert!(!loader.can_load(&input));
}

#[tokio::test]
async fn t56_loader_load_minimal() {
    let loader = JavaLoader;
    let input = rustre_core::LoaderInput::new("test.class", make_minimal_class());
    let _res = loader.load(input).await.unwrap();
}

#[tokio::test]
async fn t57_loader_find_nested_on_non_jar() {
    let loader = JavaLoader;
    let input = rustre_core::LoaderInput::new("x", make_minimal_class());
    let nested = loader.find_nested(&input).await.unwrap();
    assert!(nested.is_empty());
}

// ─── AttributeParser ──────────────────────────────────────────────────

#[test]
fn t58_parse_code_attribute_minimal() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    let mut data = Vec::new();
    data.extend_from_slice(&2u16.to_be_bytes()); // max_stack
    data.extend_from_slice(&3u16.to_be_bytes()); // max_locals
    data.extend_from_slice(&1u32.to_be_bytes()); // code_len
    data.push(0xB1); // return
    data.extend_from_slice(&0u16.to_be_bytes()); // exc_count
    data.extend_from_slice(&0u16.to_be_bytes()); // sub_attr_count
    let code = AttributeParser::parse_code_attribute(&data, &cp).unwrap();
    assert_eq!(code.max_stack, 2);
    assert_eq!(code.max_locals, 3);
    assert_eq!(code.bytecode, vec![0xB1]);
}

#[test]
fn t59_parse_code_attribute_truncated() {
    let cp: Vec<ConstantPoolEntry> = vec![];
    assert!(AttributeParser::parse_code_attribute(&[1, 2, 3], &cp).is_err());
}

#[test]
fn t60_parse_exceptions_attribute() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_be_bytes()); // count=0
    let res = AttributeParser::parse_exceptions_attribute(&data, &cp).unwrap();
    assert!(res.exceptions.is_empty());
}

#[test]
fn t61_parse_exceptions_truncated() {
    let cp: Vec<ConstantPoolEntry> = vec![];
    assert!(AttributeParser::parse_exceptions_attribute(&[], &cp).is_err());
    let mut data = Vec::new();
    data.extend_from_slice(&5u16.to_be_bytes()); // claims 5 entries
    assert!(AttributeParser::parse_exceptions_attribute(&data, &cp).is_err());
}

#[test]
fn t62_parse_inner_classes_empty() {
    let cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Other(0)];
    let data = 0u16.to_be_bytes();
    let r = AttributeParser::parse_inner_classes(&data, &cp).unwrap();
    assert!(r.is_empty());
}

#[test]
fn t63_parse_inner_classes_truncated() {
    let cp: Vec<ConstantPoolEntry> = vec![];
    let mut data = Vec::new();
    data.extend_from_slice(&3u16.to_be_bytes());
    assert!(AttributeParser::parse_inner_classes(&data, &cp).is_err());
}

#[test]
fn t64_parse_signature_attribute() {
    let cp = vec![
        ConstantPoolEntry::Other(0),
        ConstantPoolEntry::Utf8("sigvalue".into()),
    ];
    let data = 1u16.to_be_bytes();
    let s = AttributeParser::parse_signature_attribute(&data, &cp).unwrap();
    assert_eq!(s, "sigvalue");
}

#[test]
fn t65_parse_signature_truncated() {
    let cp: Vec<ConstantPoolEntry> = vec![];
    assert!(AttributeParser::parse_signature_attribute(&[], &cp).is_err());
}

// ─── JavaClassAnalyzer ────────────────────────────────────────────────

fn analyzer_class() -> JavaClass {
    JavaClass {
        version: JavaVersion { major: 52, minor: 0 },
        flags: JavaClassFlags::PUBLIC,
        class_name: "X".into(),
        super_name: None,
        interfaces: vec![],
        fields: vec![JavaField {
            name: "a".into(),
            descriptor: "I".into(),
            flags: JavaClassFlags::PRIVATE,
        }],
        methods: vec![JavaMethod {
            name: "m".into(),
            descriptor: "()V".into(),
            flags: JavaClassFlags::PUBLIC,
        }],
        constant_pool: vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::Utf8("hello".into()),
            ConstantPoolEntry::Utf8("(I)V".into()),
        ],
    }
}

#[test]
fn t66_analyzer_strings() {
    let c = analyzer_class();
    let a = JavaClassAnalyzer::new(&c);
    let s = a.string_literals();
    assert!(s.contains(&"hello"));
    // Descriptors filtered out (start with '(')
    assert!(!s.contains(&"(I)V"));
}

#[test]
fn t67_analyzer_obfuscation_score_range() {
    let c = analyzer_class();
    let a = JavaClassAnalyzer::new(&c);
    let s = a.obfuscation_score();
    assert!((0.0..=1.0).contains(&s), "score out of range: {s}");
}

#[test]
fn t68_analyzer_empty_class_zero_score() {
    let c = JavaClass {
        version: JavaVersion { major: 52, minor: 0 },
        flags: JavaClassFlags::empty(),
        class_name: "X".into(),
        super_name: None,
        interfaces: vec![],
        fields: vec![],
        methods: vec![],
        constant_pool: vec![ConstantPoolEntry::Other(0)],
    };
    let a = JavaClassAnalyzer::new(&c);
    assert_eq!(a.obfuscation_score(), 0.0);
}

// ─── DesignPattern Display ────────────────────────────────────────────

#[test]
fn t69_design_pattern_display() {
    assert_eq!(format!("{}", DesignPattern::Singleton), "Singleton");
    assert_eq!(format!("{}", DesignPattern::Factory), "Factory");
    assert_eq!(format!("{}", DesignPattern::Builder), "Builder");
}

// ─── ClassHierarchy ───────────────────────────────────────────────────

#[test]
fn t70_hierarchy_subclass_self() {
    let h = ClassHierarchy::default();
    assert!(h.is_subclass_of("A", "A"));
}

#[test]
fn t71_hierarchy_build_and_query() {
    let cf_obj = ClassFile {
        version: JavaVersion { major: 52, minor: 0 },
        flags: JavaClassFlags::PUBLIC,
        class_name: "Obj".into(),
        super_name: None,
        interfaces: vec![],
        fields: vec![],
        methods: vec![],
        constant_pool: vec![],
    };
    let cf_sub = ClassFile {
        version: JavaVersion { major: 52, minor: 0 },
        flags: JavaClassFlags::PUBLIC,
        class_name: "Sub".into(),
        super_name: Some("Obj".into()),
        interfaces: vec!["I".into()],
        fields: vec![],
        methods: vec![],
        constant_pool: vec![],
    };
    let h = ClassHierarchyBuilder::build_hierarchy(&[cf_obj, cf_sub]);
    assert!(h.is_subclass_of("Sub", "Obj"));
    assert!(!h.is_subclass_of("Obj", "Sub"));
    let impls = h.find_implementations("I");
    assert!(impls.contains(&"Sub".to_string()));
}

#[test]
fn t72_hierarchy_unknown_class() {
    let h = ClassHierarchy::default();
    assert!(!h.is_subclass_of("Foo", "Bar"));
}

// ─── ClassFile::parse (richer) ────────────────────────────────────────

#[test]
fn t73_classfile_parse_minimal() {
    let data = make_minimal_class();
    let cls = ClassFile::parse(&data).unwrap();
    assert_eq!(cls.version.major, 52);
    assert!(cls.methods.is_empty());
}

#[test]
fn t74_classfile_parse_invalid_magic() {
    let data = vec![0u8; 32];
    assert!(matches!(
        ClassFile::parse(&data),
        Err(JavaLoaderError::InvalidMagic)
    ));
}

// ─── boundary numeric edge cases ──────────────────────────────────────

#[test]
fn t75_parse_field_long_class_name() {
    let p = JavaDescriptorParser::new();
    let name = "a/b/c/d/e/f/g/h/VeryDeeplyNestedClassName";
    let desc = format!("L{name};");
    assert_eq!(
        p.parse_field(&desc),
        Some(JavaType::Reference(name.into()))
    );
}

#[test]
fn t76_parse_method_many_params() {
    let p = JavaDescriptorParser::new();
    let mut sig = String::from("(");
    for _ in 0..50 {
        sig.push('I');
    }
    sig.push_str(")V");
    let (params, ret) = p.parse_method(&sig).unwrap();
    assert_eq!(params.len(), 50);
    assert_eq!(ret, JavaType::Void);
}

#[test]
fn t77_opcode_invariant_branches_and_returns_disjoint() {
    for b in 0u8..=0xC9 {
        let op = JvmOpcode::from_byte(b);
        if op == JvmOpcode::Unknown {
            continue;
        }
        // A return is not a branch, and vice versa
        assert!(
            !(op.is_branch() && op.is_return()),
            "{op:?} should not be both branch and return"
        );
    }
}

#[test]
fn t78_javatype_eq() {
    assert_eq!(JavaType::Int, JavaType::Int);
    assert_ne!(JavaType::Int, JavaType::Long);
    assert_eq!(
        JavaType::Array(Box::new(JavaType::Int)),
        JavaType::Array(Box::new(JavaType::Int))
    );
}

#[test]
fn t79_bytecode_analyzer_empty_code() {
    let cp = vec![ConstantPoolEntry::Other(0)];
    let code = CodeAttribute {
        max_stack: 0,
        max_locals: 0,
        bytecode: vec![],
        exception_table: vec![],
        attributes: vec![],
    };
    assert!(JavaBytecodeAnalyzer::find_string_usage(&code, &cp).is_empty());
    assert!(JavaBytecodeAnalyzer::find_method_calls(&code, &cp).is_empty());
    assert!(JavaBytecodeAnalyzer::find_field_accesses(&code, &cp).is_empty());
}

#[test]
fn t80_constant_pool_clone() {
    let e = ConstantPoolEntry::Utf8("x".into());
    let c = e.clone();
    assert_eq!(format!("{e}"), format!("{c}"));
}
