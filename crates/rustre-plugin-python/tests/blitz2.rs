//! Deep adversarial tests for rustre-plugin-python.

use pyo3::exceptions::{
    PyAttributeError, PyImportError, PyKeyError, PyRuntimeError, PyTypeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rustre_plugin_python::python_error_handler::{ErrorContext, PyError, PythonErrorHandler};
use rustre_plugin_python::python_re_module::{
    PyArgSpec, PyClass, PyFunction, PyFunctionKind, PythonReModule,
};
use rustre_plugin_python::python_type_bridge::{BridgeValue, PyToRust, PythonTypeBridge, RustToPy};
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// Seeded LCG.
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ── ErrorContext ─────────────────────────────────────────────────────────────

#[test]
fn ctx_default_is_empty() {
    let c = ErrorContext::default();
    assert!(c.plugin.is_none() && c.script.is_none() && c.function.is_none());
}

#[test]
fn ctx_empty_display_is_no_context() {
    assert_eq!(ErrorContext::empty().to_string(), "<no-context>");
}

#[test]
fn ctx_builder_partial_plugin_only() {
    let c = ErrorContext::empty().with_plugin("p");
    let s = c.to_string();
    assert!(s.contains("plugin=p"));
    assert!(!s.contains("script="));
    assert!(!s.contains("fn="));
}

#[test]
fn ctx_builder_full_chain_order() {
    let c = ErrorContext::empty()
        .with_plugin("alpha")
        .with_script("beta.py")
        .with_function("gamma");
    let s = c.to_string();
    // plugin must come before script which comes before fn.
    let p = s.find("plugin=").unwrap();
    let sc = s.find("script=").unwrap();
    let fnp = s.find("fn=").unwrap();
    assert!(p < sc && sc < fnp);
    assert!(s.starts_with('[') && s.ends_with(']'));
}

#[test]
fn ctx_overwrite_overrides_previous_value() {
    let c = ErrorContext::empty().with_plugin("a").with_plugin("b");
    assert_eq!(c.plugin.as_deref(), Some("b"));
}

#[test]
fn ctx_fuzz_string_inputs_never_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 32) as usize;
        let mut bytes = Vec::with_capacity(n);
        for _ in 0..n {
            bytes.push(((g() % 90) + 32) as u8); // printable ascii
        }
        let s = String::from_utf8(bytes).unwrap();
        let c = ErrorContext::empty()
            .with_plugin(s.clone())
            .with_script(s.clone())
            .with_function(s.clone());
        let _ = c.to_string();
    }
}

// ── PyError ──────────────────────────────────────────────────────────────────

#[test]
fn pyerror_kind_all_variants() {
    for (e, k) in [
        (PyError::Type("a".into()), "TypeError"),
        (PyError::Value("a".into()), "ValueError"),
        (PyError::Key("a".into()), "KeyError"),
        (PyError::Attribute("a".into()), "AttributeError"),
        (PyError::Import("a".into()), "ImportError"),
        (PyError::Runtime("a".into()), "RuntimeError"),
        (
            PyError::Other {
                class: "X".into(),
                message: "y".into(),
            },
            "Other",
        ),
    ] {
        assert_eq!(e.kind(), k);
    }
}

#[test]
fn pyerror_message_returns_inner() {
    assert_eq!(PyError::Type("zz".into()).message(), "zz");
    assert_eq!(
        PyError::Other {
            class: "X".into(),
            message: "mm".into()
        }
        .message(),
        "mm"
    );
}

#[test]
fn pyerror_display_includes_kind_and_message() {
    let e = PyError::Value("oops".into());
    let s = e.to_string();
    assert!(s.contains("ValueError"));
    assert!(s.contains("oops"));
}

#[test]
fn pyerror_display_other_uses_class() {
    let e = PyError::Other {
        class: "MyErr".into(),
        message: "msg".into(),
    };
    assert_eq!(e.to_string(), "MyErr: msg");
}

#[test]
fn pyerror_eq_consistency_pairs() {
    let mk = |i: u64| match i % 7 {
        0 => PyError::Type(format!("{i}")),
        1 => PyError::Value(format!("{i}")),
        2 => PyError::Key(format!("{i}")),
        3 => PyError::Attribute(format!("{i}")),
        4 => PyError::Import(format!("{i}")),
        5 => PyError::Runtime(format!("{i}")),
        _ => PyError::Other {
            class: format!("c{i}"),
            message: format!("m{i}"),
        },
    };
    let mut g = lcg();
    for _ in 0..30 {
        let a = mk(g() % 50);
        let b = a.clone();
        assert_eq!(a, b);
    }
}

#[test]
fn pyerror_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(PyError::Runtime("x".into()));
    assert!(e.to_string().contains("RuntimeError"));
}

// ── PythonErrorHandler ──────────────────────────────────────────────────────

#[test]
fn classify_all_known_kinds() {
    Python::with_gil(|py| {
        let cases: Vec<(PyErr, &str)> = vec![
            (PyTypeError::new_err("t"), "TypeError"),
            (PyValueError::new_err("v"), "ValueError"),
            (PyKeyError::new_err("k"), "KeyError"),
            (PyAttributeError::new_err("a"), "AttributeError"),
            (PyImportError::new_err("i"), "ImportError"),
            (PyRuntimeError::new_err("r"), "RuntimeError"),
        ];
        for (err, kind) in cases {
            let cls = PythonErrorHandler::classify(py, &err);
            assert_eq!(cls.kind(), kind);
        }
    });
}

#[test]
fn classify_unknown_becomes_other() {
    Python::with_gil(|py| {
        // ZeroDivisionError isn't in the matched list — should hit Other.
        let code = "raise ZeroDivisionError('div by zero')";
        let err = py.run(&std::ffi::CString::new(code).unwrap(), None, None).unwrap_err();
        let cls = PythonErrorHandler::classify(py, &err);
        assert_eq!(cls.kind(), "Other");
        if let PyError::Other { class, .. } = cls {
            assert!(class.contains("ZeroDivisionError"));
        } else {
            panic!("expected Other");
        }
    });
}

#[test]
fn rebuild_roundtrip_all_kinds() {
    Python::with_gil(|py| {
        for original in [
            PyError::Type("t".into()),
            PyError::Value("v".into()),
            PyError::Key("k".into()),
            PyError::Attribute("a".into()),
            PyError::Import("i".into()),
            PyError::Runtime("r".into()),
        ] {
            let rebuilt = PythonErrorHandler::rebuild(&original);
            let back = PythonErrorHandler::classify(py, &rebuilt);
            assert_eq!(back.kind(), original.kind());
        }
    });
}

#[test]
fn rebuild_other_becomes_runtime() {
    Python::with_gil(|py| {
        let original = PyError::Other {
            class: "Foo".into(),
            message: "bar".into(),
        };
        let rebuilt = PythonErrorHandler::rebuild(&original);
        let back = PythonErrorHandler::classify(py, &rebuilt);
        assert_eq!(back.kind(), "RuntimeError");
        assert!(back.message().contains("Foo"));
        assert!(back.message().contains("bar"));
    });
}

#[test]
fn traceback_empty_when_none() {
    Python::with_gil(|py| {
        let err = PyValueError::new_err("no tb");
        assert!(PythonErrorHandler::traceback(py, &err).is_empty());
    });
}

#[test]
fn classify_fuzz_messages_never_panic() {
    Python::with_gil(|py| {
        let mut g = lcg();
        for _ in 0..50 {
            let n = (g() % 20) as usize;
            let mut s = String::new();
            for _ in 0..n {
                s.push(((g() % 90 + 32) as u8) as char);
            }
            let err = PyValueError::new_err(s.clone());
            let cls = PythonErrorHandler::classify(py, &err);
            assert_eq!(cls.kind(), "ValueError");
        }
    });
}

// ── PyFunctionKind / PyArgSpec / PyFunction / PyClass ────────────────────────

#[test]
fn funcion_kind_display_all() {
    assert_eq!(PyFunctionKind::ModuleLevel.to_string(), "module");
    assert_eq!(PyFunctionKind::StaticMethod.to_string(), "staticmethod");
    assert_eq!(PyFunctionKind::InstanceMethod.to_string(), "method");
    assert_eq!(PyFunctionKind::ClassMethod.to_string(), "classmethod");
}

#[test]
fn argspec_positional_defaults() {
    let a = PyArgSpec::positional("x");
    assert_eq!(a.name, "x");
    assert!(a.type_annotation.is_none());
    assert!(!a.has_default);
    assert!(!a.is_vararg);
    assert!(!a.is_kwargs);
}

#[test]
fn argspec_display_plain() {
    assert_eq!(PyArgSpec::positional("x").to_string(), "x");
}

#[test]
fn argspec_display_typed() {
    assert_eq!(
        PyArgSpec::positional("x").with_type("int").to_string(),
        "x: int"
    );
}

#[test]
fn argspec_display_default() {
    let a = PyArgSpec::positional("x").with_default();
    assert_eq!(a.to_string(), "x = ...");
}

#[test]
fn argspec_display_vararg() {
    let mut a = PyArgSpec::positional("args");
    a.is_vararg = true;
    assert!(a.to_string().starts_with("*args"));
}

#[test]
fn argspec_display_kwargs() {
    let mut a = PyArgSpec::positional("kw");
    a.is_kwargs = true;
    assert!(a.to_string().starts_with("**kw"));
}

#[test]
fn argspec_display_kwargs_takes_precedence_over_vararg() {
    let mut a = PyArgSpec::positional("z");
    a.is_vararg = true;
    a.is_kwargs = true;
    assert!(a.to_string().starts_with("**z"));
    assert!(!a.to_string().starts_with("*z "));
}

#[test]
fn function_new_defaults() {
    let f = PyFunction::new("n", "d");
    assert_eq!(f.name, "n");
    assert_eq!(f.doc, "d");
    assert!(f.args.is_empty());
    assert!(f.return_type.is_none());
    assert_eq!(f.kind, PyFunctionKind::ModuleLevel);
    assert!(f.tags.is_empty());
}

#[test]
fn function_builder_chain() {
    let f = PyFunction::new("foo", "doc")
        .arg(PyArgSpec::positional("x").with_type("int"))
        .arg(PyArgSpec::positional("y").with_type("str"))
        .returns("bool")
        .kind(PyFunctionKind::StaticMethod)
        .tag("t1")
        .tag("t2");
    assert_eq!(f.args.len(), 2);
    assert_eq!(f.return_type.as_deref(), Some("bool"));
    assert_eq!(f.kind, PyFunctionKind::StaticMethod);
    assert_eq!(f.tags, vec!["t1".to_string(), "t2".to_string()]);
}

#[test]
fn function_stub_no_args_no_return() {
    let f = PyFunction::new("foo", "");
    assert_eq!(f.stub_signature(), "def foo():");
}

#[test]
fn function_stub_with_return_only() {
    let f = PyFunction::new("foo", "").returns("int");
    assert_eq!(f.stub_signature(), "def foo() -> int:");
}

#[test]
fn function_stub_full() {
    let f = PyFunction::new("foo", "")
        .arg(PyArgSpec::positional("a").with_type("int"))
        .arg(PyArgSpec::positional("b").with_type("str").with_default())
        .returns("None");
    assert_eq!(
        f.stub_signature(),
        "def foo(a: int, b: str = ...) -> None:"
    );
}

#[test]
fn function_display_format() {
    let f = PyFunction::new("foo", "").kind(PyFunctionKind::ClassMethod);
    assert_eq!(f.to_string(), "foo (classmethod)");
}

#[test]
fn class_builder_chain() {
    let c = PyClass::new("C", "doc")
        .property("p1")
        .property("p2")
        .inherits("Base")
        .make_iterable()
        .method(PyFunction::new("m", ""));
    assert_eq!(c.properties.len(), 2);
    assert_eq!(c.base_class.as_deref(), Some("Base"));
    assert!(c.iterable);
    assert_eq!(c.methods.len(), 1);
}

#[test]
fn class_display_no_base() {
    let c = PyClass::new("Foo", "");
    assert_eq!(c.to_string(), "class Foo");
}

#[test]
fn class_display_with_base() {
    let c = PyClass::new("Foo", "").inherits("Bar");
    assert_eq!(c.to_string(), "class Foo(Bar)");
}

#[test]
fn class_methods_tagged_filters() {
    let c = PyClass::new("C", "")
        .method(PyFunction::new("a", "").tag("x"))
        .method(PyFunction::new("b", "").tag("y"))
        .method(PyFunction::new("c", "").tag("x").tag("y"));
    assert_eq!(c.methods_tagged("x").len(), 2);
    assert_eq!(c.methods_tagged("y").len(), 2);
    assert_eq!(c.methods_tagged("none").len(), 0);
}

// ── PythonReModule ──────────────────────────────────────────────────────────

#[test]
fn module_new_is_empty() {
    let m = PythonReModule::new("rustre");
    assert_eq!(m.module_name, "rustre");
    assert_eq!(m.function_count(), 0);
    assert_eq!(m.class_count(), 0);
}

#[test]
fn module_register_and_lookup() {
    let mut m = PythonReModule::new("x").with_doc("doc");
    assert_eq!(m.doc, "doc");
    m.register_function(PyFunction::new("f1", ""));
    m.register_function(PyFunction::new("f2", "").tag("g"));
    m.register_class(PyClass::new("C1", ""));
    m.register_constant("K", "1");
    m.register_submodule("sub");
    assert_eq!(m.function_count(), 2);
    assert_eq!(m.class_count(), 1);
    assert!(m.function("f1").is_some());
    assert!(m.function("missing").is_none());
    assert!(m.class("C1").is_some());
    assert!(m.class("missing").is_none());
    assert_eq!(m.functions_tagged("g").len(), 1);
    assert_eq!(m.functions_tagged("none").len(), 0);
}

#[test]
fn module_register_many_fuzz() {
    let mut g = lcg();
    let mut m = PythonReModule::new("rustre");
    let mut expected_names: HashSet<String> = HashSet::new();
    for _ in 0..50 {
        let n = format!("f{}", g() % 1000);
        expected_names.insert(n.clone());
        m.register_function(PyFunction::new(n, ""));
    }
    // every distinct name should be findable.
    for n in &expected_names {
        assert!(m.function(n).is_some(), "missing {n}");
    }
}

#[test]
fn stub_contains_constants_classes_and_functions() {
    let mut m = PythonReModule::new("x").with_doc("hello");
    m.register_constant("VERSION", "\"1\"");
    m.register_class(
        PyClass::new("Foo", "fdoc")
            .property("p")
            .method(PyFunction::new("m", "mdoc").returns("int")),
    );
    m.register_function(PyFunction::new("g", "gdoc").returns("None"));
    let stub = m.generate_stub();
    assert!(stub.contains("# Stub for module 'x'"));
    assert!(stub.contains("hello"));
    assert!(stub.contains("VERSION"));
    assert!(stub.contains("class Foo(object):"));
    assert!(stub.contains("def m() -> int:"));
    assert!(stub.contains("def g() -> None:"));
    assert!(stub.contains("@property"));
}

#[test]
fn stub_uses_base_class_when_present() {
    let mut m = PythonReModule::new("x");
    m.register_class(PyClass::new("D", "").inherits("B"));
    assert!(m.generate_stub().contains("class D(B):"));
}

// ── BridgeValue type names ──────────────────────────────────────────────────

#[test]
fn bridge_type_name_all() {
    assert_eq!(BridgeValue::None.type_name(), "None");
    assert_eq!(BridgeValue::Bool(false).type_name(), "bool");
    assert_eq!(BridgeValue::Int(0).type_name(), "int");
    assert_eq!(BridgeValue::Float(0.0).type_name(), "float");
    assert_eq!(BridgeValue::Str(String::new()).type_name(), "str");
    assert_eq!(BridgeValue::Bytes(Vec::new()).type_name(), "bytes");
    assert_eq!(BridgeValue::List(Vec::new()).type_name(), "list");
    assert_eq!(BridgeValue::Tuple(Vec::new()).type_name(), "tuple");
    assert_eq!(BridgeValue::Dict(HashMap::new()).type_name(), "dict");
}

// ── Bridge round-trips ─────────────────────────────────────────────────────

#[test]
fn roundtrip_none() {
    Python::with_gil(|py| {
        let v = BridgeValue::None;
        let o = v.to_py(py).unwrap();
        let back = BridgeValue::from_py(&o).unwrap();
        assert_eq!(back, v);
    });
}

#[test]
fn roundtrip_bool_both() {
    Python::with_gil(|py| {
        for b in [true, false] {
            let v = BridgeValue::Bool(b);
            let o = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&o).unwrap();
            assert_eq!(back, v);
        }
    });
}

#[test]
fn roundtrip_int_boundaries() {
    Python::with_gil(|py| {
        for &i in &[0i64, 1, -1, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
            let v = BridgeValue::Int(i);
            let o = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&o).unwrap();
            assert_eq!(back, v);
        }
    });
}

#[test]
fn roundtrip_int_fuzz() {
    Python::with_gil(|py| {
        let mut g = lcg();
        for _ in 0..60 {
            let i = g() as i64;
            let v = BridgeValue::Int(i);
            let o = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&o).unwrap();
            assert_eq!(back, v);
        }
    });
}

#[test]
fn roundtrip_float_special() {
    Python::with_gil(|py| {
        for &f in &[0.0, -0.0, 1.5, -1.5, f64::MAX, f64::MIN, f64::EPSILON] {
            let v = BridgeValue::Float(f);
            let o = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&o).unwrap();
            assert_eq!(back, v);
        }
    });
}

#[test]
fn roundtrip_bytes_empty_and_random() {
    Python::with_gil(|py| {
        let v0 = BridgeValue::Bytes(vec![]);
        let o0 = v0.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&o0).unwrap(), v0);

        let mut g = lcg();
        for _ in 0..20 {
            let n = (g() % 100) as usize;
            let mut b = Vec::with_capacity(n);
            for _ in 0..n {
                b.push((g() & 0xff) as u8);
            }
            let v = BridgeValue::Bytes(b);
            let o = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
        }
    });
}

#[test]
fn roundtrip_str_unicode() {
    Python::with_gil(|py| {
        for s in ["", "hello", "héllo", "🦀rust", "\0middle"] {
            let v = BridgeValue::Str(s.to_string());
            let o = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
        }
    });
}

#[test]
fn roundtrip_list_empty() {
    Python::with_gil(|py| {
        let v = BridgeValue::List(vec![]);
        let o = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
    });
}

#[test]
fn roundtrip_tuple() {
    Python::with_gil(|py| {
        let v = BridgeValue::Tuple(vec![
            BridgeValue::Int(1),
            BridgeValue::Str("x".into()),
            BridgeValue::None,
        ]);
        let o = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
    });
}

#[test]
fn roundtrip_dict_multiple_keys() {
    Python::with_gil(|py| {
        let mut map = HashMap::new();
        map.insert("a".to_string(), BridgeValue::Int(1));
        map.insert("b".to_string(), BridgeValue::Bool(true));
        map.insert("c".to_string(), BridgeValue::Str("z".into()));
        let v = BridgeValue::Dict(map);
        let o = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
    });
}

#[test]
fn roundtrip_nested_mixed() {
    Python::with_gil(|py| {
        let mut inner = HashMap::new();
        inner.insert("k".to_string(), BridgeValue::Bytes(vec![1, 2, 3]));
        let v = BridgeValue::List(vec![
            BridgeValue::Dict(inner),
            BridgeValue::Tuple(vec![BridgeValue::Float(2.5), BridgeValue::None]),
        ]);
        let o = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&o).unwrap(), v);
    });
}

// ── Depth limit ─────────────────────────────────────────────────────────────

#[test]
fn to_py_rejects_over_max_depth() {
    Python::with_gil(|py| {
        // Build 70 nested lists, exceeding the limit of 64.
        let mut v = BridgeValue::Int(0);
        for _ in 0..70 {
            v = BridgeValue::List(vec![v]);
        }
        let err = v.to_py(py).unwrap_err();
        assert!(err.is_instance_of::<PyValueError>(py));
        assert!(err.to_string().to_lowercase().contains("depth"));
    });
}

#[test]
fn to_py_accepts_at_or_below_max_depth() {
    Python::with_gil(|py| {
        let mut v = BridgeValue::Int(0);
        for _ in 0..30 {
            v = BridgeValue::List(vec![v]);
        }
        assert!(v.to_py(py).is_ok());
    });
}

#[test]
fn from_py_rejects_over_max_depth() {
    Python::with_gil(|py| {
        let code = r"
x = 0
for _ in range(70):
    x = [x]
result = x
";
        let locals = PyDict::new(py);
        py.run(
            &std::ffi::CString::new(code).unwrap(),
            None,
            Some(&locals),
        )
        .unwrap();
        let obj = locals.get_item("result").unwrap().unwrap();
        let err = BridgeValue::from_py(&obj).unwrap_err();
        assert!(err.is_instance_of::<PyValueError>(py));
    });
}

// ── PyToRust fallback ───────────────────────────────────────────────────────

#[test]
fn from_py_unknown_falls_back_to_str() {
    Python::with_gil(|py| {
        let code = r"
class X:
    def __str__(self):
        return 'CUSTOM'
result = X()
";
        let locals = PyDict::new(py);
        py.run(
            &std::ffi::CString::new(code).unwrap(),
            None,
            Some(&locals),
        )
        .unwrap();
        let obj = locals.get_item("result").unwrap().unwrap();
        let v = BridgeValue::from_py(&obj).unwrap();
        assert_eq!(v, BridgeValue::Str("CUSTOM".into()));
    });
}

#[test]
fn from_py_python_list_of_mixed_types() {
    Python::with_gil(|py| {
        let py_list = PyList::empty(py);
        py_list.append(1i64).unwrap();
        py_list.append("hi").unwrap();
        py_list.append(true).unwrap();
        py_list.append(py.None()).unwrap();
        let v = BridgeValue::from_py(py_list.as_any()).unwrap();
        if let BridgeValue::List(items) = v {
            assert_eq!(items.len(), 4);
            // bool may be detected as bool (not int) because we check PyBool before PyInt.
            assert!(matches!(items[0], BridgeValue::Int(1) | BridgeValue::Bool(true)));
            assert_eq!(items[1], BridgeValue::Str("hi".into()));
            assert_eq!(items[3], BridgeValue::None);
        } else {
            panic!("expected list");
        }
    });
}

// ── PythonTypeBridge thin wrapper ───────────────────────────────────────────

#[test]
fn bridge_wrapper_roundtrip() {
    Python::with_gil(|py| {
        let v = BridgeValue::Int(7);
        let o = PythonTypeBridge::to_python(py, &v).unwrap();
        let back = PythonTypeBridge::from_python(&o).unwrap();
        assert_eq!(back, v);
    });
}

// ── Send/Sync stress (data structures, not GIL-bound types) ─────────────────

#[test]
fn errorcontext_send_sync_threaded() {
    let c = Arc::new(
        ErrorContext::empty()
            .with_plugin("p")
            .with_script("s")
            .with_function("f"),
    );
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&c);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(c.to_string().contains("plugin=p"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn pyerror_send_sync_threaded() {
    let e = Arc::new(PyError::Runtime("boom".into()));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(e.kind(), "RuntimeError");
                assert_eq!(e.message(), "boom");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn bridgevalue_send_sync_threaded() {
    let v = Arc::new(BridgeValue::List(vec![
        BridgeValue::Int(1),
        BridgeValue::Str("x".into()),
        BridgeValue::None,
    ]));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let v = Arc::clone(&v);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(v.type_name(), "list");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── Hash consistency for hashable types (Bridge subset) ──────────────────────

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn pyerror_eq_hash_like_pairs_30() {
    // PyError doesn't impl Hash, but Eq pairs must be consistent.
    let mut g = lcg();
    for _ in 0..30 {
        let s = format!("{}", g() % 1000);
        let a = PyError::Value(s.clone());
        let b = PyError::Value(s.clone());
        let c = PyError::Type(s.clone());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}

#[test]
fn errorcontext_pairs_clone_eq() {
    // ErrorContext doesn't impl Eq, but to_string equality is a fine proxy.
    let mut g = lcg();
    for _ in 0..30 {
        let s = format!("p{}", g() % 99);
        let a = ErrorContext::empty().with_plugin(s.clone());
        let b = a.clone();
        assert_eq!(a.to_string(), b.to_string());
    }
}

#[test]
fn string_hashable_pairs() {
    // 30 pairs hashed via DefaultHasher — sanity that Hash works for the
    // String parts we use.
    let mut g = lcg();
    for _ in 0..30 {
        let s = format!("{}", g());
        assert_eq!(hash_of(&s), hash_of(&s.clone()));
    }
}

// ── register_module via PyO3 ─────────────────────────────────────────────────

#[test]
fn register_module_installs_attrs() {
    Python::with_gil(|py| {
        let m = PyModule::new(py, "test_rustre").unwrap();
        let mut module = PythonReModule::new("test_rustre").with_doc("hello");
        module.register_function(PyFunction::new("g", "gd"));
        module.register_class(PyClass::new("C", "cd"));
        module.register_constant("K", "1");
        module.register_module(py, &m).unwrap();
        let doc: String = m.getattr("__doc__").unwrap().extract().unwrap();
        assert_eq!(doc, "hello");
        let k: String = m.getattr("K").unwrap().extract().unwrap();
        assert_eq!(k, "1");
        let funcs = m.getattr("__rustre_functions__").unwrap();
        assert!(funcs.downcast::<PyList>().is_ok());
        let classes = m.getattr("__rustre_classes__").unwrap();
        assert!(classes.downcast::<PyList>().is_ok());
    });
}
