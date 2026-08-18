//! Build a **real** [`DecompiledProject`] from **real** `.dex` / `.apk` bytes.
//!
//! Class names, superclasses, method names, descriptors, parameter and return
//! types, and the `static` / `native` flags are all decoded from the input by
//! `rustre_mobile_smali::dex_to_smali`, which in turn uses the DEX parser in
//! `rustre-loader-android` and this workspace's Dalvik disassembler.
//!
//! Method **bodies** are not reconstructed here: instead of inventing one,
//! each body records how many Dalvik instructions the real method contains.
//! An empty body would be a claim about the program; a count is a measurement.

use std::path::Path;

use rustre_mobile_smali::dex_to_smali::classes_from_dex_bytes;
use rustre_mobile_smali::{SmaliAccess, SmaliClass, parse_method_descriptor, parse_type_descriptor};

use crate::{DecompiledProject, JadxError, JavaClass, JavaMethod};

/// `dex\n035\0`-style magic.
const DEX_MAGIC: &[u8; 4] = b"dex\n";

/// Split a class descriptor (`Lcom/example/Foo$Bar;`) into package and name.
#[must_use]
pub fn split_descriptor(desc: &str) -> (String, String) {
    let java = parse_type_descriptor(desc);
    java.rsplit_once('.').map_or_else(
        || (String::new(), java.clone()),
        |(pkg, name)| (pkg.to_owned(), name.to_owned()),
    )
}

fn method_from_smali(m: &rustre_mobile_smali::SmaliMethod) -> JavaMethod {
    let (params, ret) = parse_method_descriptor(&m.signature);
    let instrs = m.instructions.len();
    JavaMethod {
        name: m.name.clone(),
        signature: format!("{}{}", m.name, m.signature),
        return_type: ret,
        params,
        body: format!("// {instrs} Dalvik instruction(s); body not decompiled"),
        is_static: m.access.contains(SmaliAccess::STATIC),
        is_native: m.access.contains(SmaliAccess::NATIVE),
    }
}

/// Render a declaration-level Java skeleton for a decoded class.
#[must_use]
pub fn class_skeleton(class: &SmaliClass, package: &str, name: &str) -> String {
    let mut s = String::new();
    if !package.is_empty() {
        s.push_str(&format!("package {package};\n\n"));
    }
    let sup = parse_type_descriptor(&class.super_class);
    s.push_str(&format!("class {name} extends {sup} {{\n"));
    for f in &class.fields {
        s.push_str(&format!(
            "    {} {};\n",
            parse_type_descriptor(&f.type_desc),
            f.name
        ));
    }
    for m in &class.methods {
        let (params, ret) = parse_method_descriptor(&m.signature);
        s.push_str(&format!(
            "    {ret} {}({}); // {} Dalvik instruction(s)\n",
            m.name,
            params.join(", "),
            m.instructions.len()
        ));
    }
    s.push_str("}\n");
    s
}

/// Decode every class in one `.dex` blob into a [`DecompiledProject`].
///
/// # Errors
/// Returns [`JadxError::Parse`] when `data` is not a parsable DEX file.
pub fn project_from_dex_bytes(data: &[u8]) -> Result<DecompiledProject, JadxError> {
    let classes = classes_from_dex_bytes(data).map_err(|e| JadxError::Parse(e.to_string()))?;
    Ok(project_from_smali_classes(&classes))
}

/// Convert already-decoded smali classes into a project.
#[must_use]
pub fn project_from_smali_classes(classes: &[SmaliClass]) -> DecompiledProject {
    let java: Vec<JavaClass> = classes
        .iter()
        .map(|c| {
            let (package, class_name) = split_descriptor(&c.name);
            JavaClass {
                source: class_skeleton(c, &package, &class_name),
                class_name,
                package,
                methods: c.methods.iter().map(method_from_smali).collect(),
                super_class: Some(parse_type_descriptor(&c.super_class)),
            }
        })
        .collect();
    let total = java.len();
    DecompiledProject {
        classes: java,
        total,
        failed: 0,
    }
}

/// Extract every `classes*.dex` blob from an APK (a ZIP archive).
///
/// # Errors
/// Returns [`JadxError::Parse`] if the archive cannot be read, and
/// [`JadxError::NotFound`] if it contains no DEX entry.
pub fn dex_blobs_from_apk(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, JadxError> {
    use std::io::Read as _;
    let cursor = std::io::Cursor::new(data);
    let mut zip =
        zip::ZipArchive::new(cursor).map_err(|e| JadxError::Parse(format!("not a ZIP/APK: {e}")))?;
    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_owned()))
        .filter(|n| n.ends_with(".dex"))
        .collect();

    if names.is_empty() {
        return Err(JadxError::NotFound(
            "APK contains no .dex entry".to_owned(),
        ));
    }

    let mut out = Vec::new();
    for name in names {
        let mut entry = zip
            .by_name(&name)
            .map_err(|e| JadxError::Parse(format!("cannot read {name}: {e}")))?;
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| JadxError::Io(format!("cannot read {name}: {e}")))?;
        out.push((name, buf));
    }
    Ok(out)
}

/// Decode a `.dex` or `.apk` file on disk into a [`DecompiledProject`].
///
/// # Errors
/// Returns [`JadxError::NotFound`] when the path does not exist,
/// [`JadxError::Io`] when it cannot be read, and [`JadxError::Parse`] when it
/// is neither a DEX file nor an APK containing one.
pub fn project_from_path(path: impl AsRef<Path>) -> Result<DecompiledProject, JadxError> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(JadxError::NotFound(format!(
            "input not found on disk: {}",
            path.display()
        )));
    }
    let data = std::fs::read(path).map_err(|e| JadxError::Io(e.to_string()))?;
    project_from_bytes(&data)
}

/// Decode a `.dex` or `.apk` blob into a [`DecompiledProject`].
///
/// # Errors
/// Returns [`JadxError::Parse`] when `data` is neither a DEX file nor an APK
/// containing at least one parsable DEX file.
pub fn project_from_bytes(data: &[u8]) -> Result<DecompiledProject, JadxError> {
    if data.len() >= 4 && &data[..4] == DEX_MAGIC {
        return project_from_dex_bytes(data);
    }
    if data.len() >= 2 && &data[..2] == b"PK" {
        let blobs = dex_blobs_from_apk(data)?;
        let mut all = Vec::new();
        let mut failed = 0usize;
        for (name, blob) in blobs {
            match classes_from_dex_bytes(&blob) {
                Ok(mut c) => all.append(&mut c),
                Err(e) => {
                    failed += 1;
                    let _ = name;
                    let _ = e;
                }
            }
        }
        if all.is_empty() && failed > 0 {
            return Err(JadxError::Parse(
                "no DEX entry in this APK could be parsed".to_owned(),
            ));
        }
        let mut project = project_from_smali_classes(&all);
        project.failed = failed;
        return Ok(project);
    }
    Err(JadxError::Parse(
        "input is neither a DEX file (dex\\n magic) nor a ZIP/APK".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid DEX file in memory:
    /// one class `LFoo;` extending `Ljava/lang/Object;` with one direct
    /// method `<init>()V` whose body is a single `return-void`.
    ///
    /// Nothing about the decode below is stubbed — this is a real DEX byte
    /// stream, laid out per the DEX spec, that the parser walks.
    pub fn minimal_dex() -> Vec<u8> {
        fn uleb(v: u32, out: &mut Vec<u8>) {
            let mut v = v;
            loop {
                let mut b = (v & 0x7F) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
        }

        let strings = ["LFoo;", "Ljava/lang/Object;", "V", "<init>"];

        const HEADER: usize = 112;
        let string_ids_off = HEADER;
        let type_ids_off = string_ids_off + strings.len() * 4;
        let proto_ids_off = type_ids_off + 3 * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + 8;
        let data_off = class_defs_off + 32;

        // ── data section ──
        let mut data = Vec::new();
        let mut string_data_offs = Vec::new();
        for s in strings {
            string_data_offs.push(data_off + data.len());
            uleb(u32::try_from(s.chars().count()).unwrap(), &mut data);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        while (data_off + data.len()) % 4 != 0 {
            data.push(0);
        }
        let code_off = data_off + data.len();
        data.extend_from_slice(&1u16.to_le_bytes()); // registers_size
        data.extend_from_slice(&1u16.to_le_bytes()); // ins_size
        data.extend_from_slice(&0u16.to_le_bytes()); // outs_size
        data.extend_from_slice(&0u16.to_le_bytes()); // tries_size
        data.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        data.extend_from_slice(&1u32.to_le_bytes()); // insns_size
        data.extend_from_slice(&0x000Eu16.to_le_bytes()); // return-void

        let class_data_off = data_off + data.len();
        uleb(0, &mut data); // static_fields_size
        uleb(0, &mut data); // instance_fields_size
        uleb(1, &mut data); // direct_methods_size
        uleb(0, &mut data); // virtual_methods_size
        uleb(0, &mut data); // method_idx_diff
        uleb(0x0001_0001, &mut data); // ACC_PUBLIC | ACC_CONSTRUCTOR
        uleb(u32::try_from(code_off).unwrap(), &mut data);

        // ── assemble ──
        let total = data_off + data.len();
        let mut f = vec![0u8; total];
        f[0..8].copy_from_slice(b"dex\n035\0");
        let put32 = |f: &mut Vec<u8>, at: usize, v: u32| {
            f[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut f, 32, u32::try_from(total).unwrap()); // file_size
        put32(&mut f, 36, 112); // header_size
        put32(&mut f, 40, 0x1234_5678); // endian_tag
        put32(&mut f, 56, u32::try_from(strings.len()).unwrap());
        put32(&mut f, 60, u32::try_from(string_ids_off).unwrap());
        put32(&mut f, 64, 3);
        put32(&mut f, 68, u32::try_from(type_ids_off).unwrap());
        put32(&mut f, 72, 1);
        put32(&mut f, 76, u32::try_from(proto_ids_off).unwrap());
        put32(&mut f, 80, 0);
        put32(&mut f, 84, 0);
        put32(&mut f, 88, 1);
        put32(&mut f, 92, u32::try_from(method_ids_off).unwrap());
        put32(&mut f, 96, 1);
        put32(&mut f, 100, u32::try_from(class_defs_off).unwrap());
        put32(&mut f, 104, u32::try_from(data.len()).unwrap());
        put32(&mut f, 108, u32::try_from(data_off).unwrap());

        for (i, off) in string_data_offs.iter().enumerate() {
            put32(&mut f, string_ids_off + i * 4, u32::try_from(*off).unwrap());
        }
        // type_ids -> string indices 0,1,2
        for i in 0..3u32 {
            put32(&mut f, type_ids_off + (i as usize) * 4, i);
        }
        // proto: shorty_idx=2 ("V"), return_type_idx=2 ("V"), parameters_off=0
        put32(&mut f, proto_ids_off, 2);
        put32(&mut f, proto_ids_off + 4, 2);
        put32(&mut f, proto_ids_off + 8, 0);
        // method_id: class_idx=0, proto_idx=0, name_idx=3
        f[method_ids_off..method_ids_off + 2].copy_from_slice(&0u16.to_le_bytes());
        f[method_ids_off + 2..method_ids_off + 4].copy_from_slice(&0u16.to_le_bytes());
        put32(&mut f, method_ids_off + 4, 3);
        // class_def
        put32(&mut f, class_defs_off, 0); // class_idx -> LFoo;
        put32(&mut f, class_defs_off + 4, 0x0001); // access_flags
        put32(&mut f, class_defs_off + 8, 1); // superclass_idx -> Object
        put32(&mut f, class_defs_off + 12, 0); // interfaces_off
        put32(&mut f, class_defs_off + 16, 0xFFFF_FFFF); // source_file_idx
        put32(&mut f, class_defs_off + 20, 0); // annotations_off
        put32(&mut f, class_defs_off + 24, u32::try_from(class_data_off).unwrap());
        put32(&mut f, class_defs_off + 28, 0); // static_values_off

        f[data_off..].copy_from_slice(&data);
        f
    }

    #[test]
    fn real_dex_bytes_yield_a_real_project() {
        let dex = minimal_dex();
        let p = project_from_dex_bytes(&dex).unwrap();
        assert_eq!(p.total, 1);
        let c = &p.classes[0];
        assert_eq!(c.class_name, "Foo");
        assert!(c.package.is_empty());
        assert_eq!(c.super_class.as_deref(), Some("java.lang.Object"));
        assert_eq!(c.methods.len(), 1);
        assert_eq!(c.methods[0].name, "<init>");
        assert_eq!(c.methods[0].return_type, "void");
        // The body is a measurement, not an invention.
        assert!(c.methods[0].body.contains('1'));
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            project_from_bytes(b"hello world"),
            Err(JadxError::Parse(_))
        ));
    }

    #[test]
    fn missing_path_is_named() {
        match project_from_path("no-such-file.apk") {
            Err(JadxError::NotFound(m)) => assert!(m.contains("no-such-file.apk")),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn truncated_dex_magic_is_a_parse_error() {
        let mut data = b"dex\n035\0".to_vec();
        data.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            project_from_bytes(&data),
            Err(JadxError::Parse(_))
        ));
    }

    #[test]
    fn descriptor_splits_into_package_and_name() {
        let (pkg, name) = split_descriptor("Lcom/example/app/MainActivity;");
        assert_eq!(pkg, "com.example.app");
        assert_eq!(name, "MainActivity");
    }

    #[test]
    fn unpackaged_descriptor_has_empty_package() {
        let (pkg, name) = split_descriptor("LFoo;");
        assert!(pkg.is_empty());
        assert_eq!(name, "Foo");
    }

    #[test]
    fn empty_zip_has_no_dex() {
        // Minimal empty ZIP: end-of-central-directory record only.
        let mut eocd = b"PK\x05\x06".to_vec();
        eocd.extend_from_slice(&[0u8; 18]);
        assert!(matches!(
            project_from_bytes(&eocd),
            Err(JadxError::NotFound(_))
        ));
    }
}
