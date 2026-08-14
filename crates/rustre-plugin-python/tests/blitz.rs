// Exhaustive integration tests for rustre-plugin-python.

use std::collections::HashMap;

use pyo3::exceptions::{
    PyAttributeError, PyImportError, PyKeyError, PyRuntimeError, PyTypeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

use rustre_plugin_python::python_error_handler::{ErrorContext, PyError, PythonErrorHandler};
use rustre_plugin_python::python_re_module::{
    self, PyArgSpec, PyClass, PyFunction, PyFunctionKind, PythonReModule,
};
use rustre_plugin_python::python_type_bridge::{
    BridgeValue, PyToRust, PythonTypeBridge, RustToPy,
};

// ── ErrorContext ─────────────────────────────────────────────────────────────

#[test]
fn ctx_empty_display() {
    let c = ErrorContext::empty();
    assert_eq!(c.to_string(), "<no-context>");
}

#[test]
fn ctx_default_eq_empty() {
    let a = ErrorContext::default();
    let b = ErrorContext::empty();
    assert_eq!(a.plugin, b.plugin);
    assert_eq!(a.script, b.script);
    assert_eq!(a.function, b.function);
}

#[test]
fn ctx_with_plugin_only() {
    let c = ErrorContext::empty().with_plugin("myplug");
    let s = c.to_string();
    assert!(s.contains("plugin=myplug"), "got: {s}");
    assert!(!s.contains("script="));
    assert!(!s.contains("fn="));
    assert!(s.starts_with('[') && s.ends_with(']'));
}

#[test]
fn ctx_with_script_only() {
    let c = ErrorContext::empty().with_script("foo.py");
    assert_eq!(c.to_string(), "[script=foo.py]");
}

#[test]
fn ctx_with_function_only() {
    let c = ErrorContext::empty().with_function("bar");
    assert_eq!(c.to_string(), "[fn=bar]");
}

#[test]
fn ctx_all_three_order_preserved() {
    let c = ErrorContext::empty()
        .with_plugin("p")
        .with_script("s")
        .with_function("f");
    assert_eq!(c.to_string(), "[plugin=p script=s fn=f]");
}

#[test]
fn ctx_builder_overwrites() {
    let c = ErrorContext::empty().with_plugin("a").with_plugin("b");
    assert_eq!(c.plugin.as_deref(), Some("b"));
}

#[test]
fn ctx_clone_equiv() {
    let c = ErrorContext::empty().with_plugin("p");
    let d = c.clone();
    assert_eq!(c.to_string(), d.to_string());
}

#[test]
fn ctx_accepts_empty_strings() {
    let c = ErrorContext::empty().with_plugin("").with_script("").with_function("");
    let s = c.to_string();
    // empty values are still present (Option::Some(""))
    assert!(s.contains("plugin="));
    assert!(s.contains("script="));
    assert!(s.contains("fn="));
}

// ── PyError ──────────────────────────────────────────────────────────────────

#[test]
fn pyerror_kind_strings() {
    assert_eq!(PyError::Type("a".into()).kind(), "TypeError");
    assert_eq!(PyError::Value("a".into()).kind(), "ValueError");
    assert_eq!(PyError::Key("a".into()).kind(), "KeyError");
    assert_eq!(PyError::Attribute("a".into()).kind(), "AttributeError");
    assert_eq!(PyError::Import("a".into()).kind(), "ImportError");
    assert_eq!(PyError::Runtime("a".into()).kind(), "RuntimeError");
    assert_eq!(
        PyError::Other { class: "C".into(), message: "m".into() }.kind(),
        "Other"
    );
}

#[test]
fn pyerror_message_for_each_variant() {
    assert_eq!(PyError::Type("t".into()).message(), "t");
    assert_eq!(PyError::Value("v".into()).message(), "v");
    assert_eq!(PyError::Key("k".into()).message(), "k");
    assert_eq!(PyError::Attribute("a".into()).message(), "a");
    assert_eq!(PyError::Import("i".into()).message(), "i");
    assert_eq!(PyError::Runtime("r".into()).message(), "r");
    assert_eq!(
        PyError::Other { class: "C".into(), message: "msg".into() }.message(),
        "msg"
    );
}

#[test]
fn pyerror_display_categorised() {
    let e = PyError::Value("bad".into());
    assert_eq!(e.to_string(), "ValueError: bad");
}

#[test]
fn pyerror_display_other_uses_class() {
    let e = PyError::Other { class: "MyExc".into(), message: "oops".into() };
    assert_eq!(e.to_string(), "MyExc: oops");
}

#[test]
fn pyerror_eq_and_clone() {
    let a = PyError::Type("x".into());
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, PyError::Value("x".into()));
}

#[test]
fn pyerror_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(PyError::Runtime("boom".into()));
    assert!(e.to_string().contains("boom"));
}

// ── PythonErrorHandler classify ──────────────────────────────────────────────

#[test]
fn classify_each_builtin_kind() {
    Python::with_gil(|py| {
        let cases: Vec<(PyErr, &str)> = vec![
            (PyTypeError::new_err("t"), "TypeError"),
            (PyValueError::new_err("v"), "ValueError"),
            (PyKeyError::new_err("k"), "KeyError"),
            (PyAttributeError::new_err("a"), "AttributeError"),
            (PyImportError::new_err("i"), "ImportError"),
            (PyRuntimeError::new_err("r"), "RuntimeError"),
        ];
        for (err, expected_kind) in cases {
            let c = PythonErrorHandler::classify(py, &err);
            assert_eq!(c.kind(), expected_kind);
        }
    });
}

#[test]
fn classify_other_falls_through() {
    Python::with_gil(|py| {
        // ZeroDivisionError isn't in the explicit list -> Other
        let code = "raise ZeroDivisionError('div by zero')";
        let err = py.run(&std::ffi::CString::new(code).unwrap(), None, None).unwrap_err();
        let c = PythonErrorHandler::classify(py, &err);
        match c {
            PyError::Other { class, message } => {
                assert!(class.contains("ZeroDivisionError"), "class={class}");
                assert!(message.contains("div by zero"), "msg={message}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    });
}

#[test]
fn classify_message_contains_text() {
    Python::with_gil(|py| {
        let err = PyValueError::new_err("specific text 12345");
        let c = PythonErrorHandler::classify(py, &err);
        assert!(c.message().contains("specific text 12345"));
    });
}

#[test]
fn rebuild_roundtrip_all_kinds() {
    Python::with_gil(|py| {
        let originals = vec![
            PyError::Type("t".into()),
            PyError::Value("v".into()),
            PyError::Key("k".into()),
            PyError::Attribute("a".into()),
            PyError::Import("i".into()),
            PyError::Runtime("r".into()),
        ];
        for orig in originals {
            let rebuilt = PythonErrorHandler::rebuild(&orig);
            let reclassified = PythonErrorHandler::classify(py, &rebuilt);
            assert_eq!(reclassified.kind(), orig.kind(), "kind mismatch for {orig:?}");
        }
    });
}

#[test]
fn rebuild_other_becomes_runtime() {
    Python::with_gil(|py| {
        let orig = PyError::Other { class: "Custom".into(), message: "stuff".into() };
        let rebuilt = PythonErrorHandler::rebuild(&orig);
        let reclassified = PythonErrorHandler::classify(py, &rebuilt);
        assert_eq!(reclassified.kind(), "RuntimeError");
        assert!(reclassified.message().contains("Custom"));
        assert!(reclassified.message().contains("stuff"));
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
fn traceback_present_when_raised() {
    Python::with_gil(|py| {
        let code = "def f():\n    raise ValueError('x')\nf()\n";
        let err = py.run(&std::ffi::CString::new(code).unwrap(), None, None).unwrap_err();
        let tb = PythonErrorHandler::traceback(py, &err);
        assert!(!tb.is_empty(), "traceback should not be empty for raised err");
    });
}

// ── PyFunctionKind ───────────────────────────────────────────────────────────

#[test]
fn pyfunctionkind_display() {
    assert_eq!(PyFunctionKind::ModuleLevel.to_string(), "module");
    assert_eq!(PyFunctionKind::StaticMethod.to_string(), "staticmethod");
    assert_eq!(PyFunctionKind::InstanceMethod.to_string(), "method");
    assert_eq!(PyFunctionKind::ClassMethod.to_string(), "classmethod");
}

#[test]
fn pyfunctionkind_eq() {
    assert_eq!(PyFunctionKind::ModuleLevel, PyFunctionKind::ModuleLevel);
    assert_ne!(PyFunctionKind::ModuleLevel, PyFunctionKind::StaticMethod);
}

// ── PyArgSpec ────────────────────────────────────────────────────────────────

#[test]
fn argspec_positional_defaults() {
    let a = PyArgSpec::positional("x");
    assert_eq!(a.name, "x");
    assert!(a.type_annotation.is_none());
    assert!(!a.has_default);
    assert!(!a.is_vararg);
    assert!(!a.is_kwargs);
    assert_eq!(a.to_string(), "x");
}

#[test]
fn argspec_with_type() {
    let a = PyArgSpec::positional("x").with_type("int");
    assert_eq!(a.to_string(), "x: int");
}

#[test]
fn argspec_with_default_no_type() {
    let a = PyArgSpec::positional("x").with_default();
    assert_eq!(a.to_string(), "x = ...");
}

#[test]
fn argspec_full_render() {
    let a = PyArgSpec::positional("x").with_type("int").with_default();
    assert_eq!(a.to_string(), "x: int = ...");
}

#[test]
fn argspec_vararg_render() {
    let mut a = PyArgSpec::positional("args");
    a.is_vararg = true;
    assert_eq!(a.to_string(), "*args");
}

#[test]
fn argspec_kwargs_render() {
    let mut a = PyArgSpec::positional("kw");
    a.is_kwargs = true;
    assert_eq!(a.to_string(), "**kw");
}

#[test]
fn argspec_kwargs_beats_vararg_when_both_set() {
    let mut a = PyArgSpec::positional("x");
    a.is_vararg = true;
    a.is_kwargs = true;
    // kwargs branch is checked first
    assert_eq!(a.to_string(), "**x");
}

// ── PyFunction ───────────────────────────────────────────────────────────────

#[test]
fn pyfunction_new_defaults() {
    let f = PyFunction::new("foo", "doc");
    assert_eq!(f.name, "foo");
    assert_eq!(f.doc, "doc");
    assert!(f.args.is_empty());
    assert!(f.return_type.is_none());
    assert_eq!(f.kind, PyFunctionKind::ModuleLevel);
    assert!(f.tags.is_empty());
}

#[test]
fn pyfunction_stub_no_args_no_return() {
    let f = PyFunction::new("foo", "d");
    assert_eq!(f.stub_signature(), "def foo():");
}

#[test]
fn pyfunction_stub_with_return_only() {
    let f = PyFunction::new("foo", "d").returns("int");
    assert_eq!(f.stub_signature(), "def foo() -> int:");
}

#[test]
fn pyfunction_stub_multi_args() {
    let f = PyFunction::new("foo", "d")
        .arg(PyArgSpec::positional("a").with_type("int"))
        .arg(PyArgSpec::positional("b").with_type("str").with_default())
        .returns("bool");
    assert_eq!(
        f.stub_signature(),
        "def foo(a: int, b: str = ...) -> bool:"
    );
}

#[test]
fn pyfunction_kind_builder() {
    let f = PyFunction::new("foo", "d").kind(PyFunctionKind::StaticMethod);
    assert_eq!(f.kind, PyFunctionKind::StaticMethod);
}

#[test]
fn pyfunction_tag_accumulates() {
    let f = PyFunction::new("foo", "d").tag("a").tag("b").tag("c");
    assert_eq!(f.tags, vec!["a", "b", "c"]);
}

#[test]
fn pyfunction_display_contains_kind() {
    let f = PyFunction::new("foo", "d").kind(PyFunctionKind::ClassMethod);
    let s = f.to_string();
    assert!(s.contains("foo"));
    assert!(s.contains("classmethod"));
}

// ── PyClass ──────────────────────────────────────────────────────────────────

#[test]
fn pyclass_new_defaults() {
    let c = PyClass::new("C", "doc");
    assert_eq!(c.name, "C");
    assert!(c.methods.is_empty());
    assert!(c.properties.is_empty());
    assert!(c.base_class.is_none());
    assert!(!c.iterable);
}

#[test]
fn pyclass_method_and_property_accumulate() {
    let c = PyClass::new("C", "")
        .method(PyFunction::new("a", ""))
        .method(PyFunction::new("b", ""))
        .property("p1")
        .property("p2");
    assert_eq!(c.methods.len(), 2);
    assert_eq!(c.properties, vec!["p1", "p2"]);
}

#[test]
fn pyclass_inherits_display() {
    let c = PyClass::new("Sub", "").inherits("Base");
    assert_eq!(c.to_string(), "class Sub(Base)");
}

#[test]
fn pyclass_no_base_display() {
    let c = PyClass::new("Sub", "");
    assert_eq!(c.to_string(), "class Sub");
}

#[test]
fn pyclass_make_iterable() {
    let c = PyClass::new("C", "").make_iterable();
    assert!(c.iterable);
}

#[test]
fn pyclass_methods_tagged_filters() {
    let c = PyClass::new("C", "")
        .method(PyFunction::new("a", "").tag("x"))
        .method(PyFunction::new("b", "").tag("y"))
        .method(PyFunction::new("c", "").tag("x").tag("y"));
    assert_eq!(c.methods_tagged("x").len(), 2);
    assert_eq!(c.methods_tagged("y").len(), 2);
    assert_eq!(c.methods_tagged("z").len(), 0);
}

// ── PythonReModule ───────────────────────────────────────────────────────────

#[test]
fn module_new_empty() {
    let m = PythonReModule::new("foo");
    assert_eq!(m.module_name, "foo");
    assert_eq!(m.function_count(), 0);
    assert_eq!(m.class_count(), 0);
    assert!(m.doc.is_empty());
}

#[test]
fn module_with_doc() {
    let m = PythonReModule::new("foo").with_doc("hello");
    assert_eq!(m.doc, "hello");
}

#[test]
fn module_register_function_increments() {
    let mut m = PythonReModule::new("x");
    m.register_function(PyFunction::new("a", ""));
    m.register_function(PyFunction::new("b", ""));
    assert_eq!(m.function_count(), 2);
}

#[test]
fn module_register_class_increments() {
    let mut m = PythonReModule::new("x");
    m.register_class(PyClass::new("A", ""));
    assert_eq!(m.class_count(), 1);
}

#[test]
fn module_find_missing_returns_none() {
    let m = PythonReModule::new("x");
    assert!(m.function("nope").is_none());
    assert!(m.class("nope").is_none());
}

#[test]
fn module_find_existing() {
    let mut m = PythonReModule::new("x");
    m.register_function(PyFunction::new("foo", "d"));
    m.register_class(PyClass::new("Bar", "d"));
    assert!(m.function("foo").is_some());
    assert!(m.class("Bar").is_some());
}

#[test]
fn module_register_constant() {
    let mut m = PythonReModule::new("x");
    m.register_constant("PI", "3.14");
    let stub = m.generate_stub();
    assert!(stub.contains("PI"));
    assert!(stub.contains("3.14"));
}

#[test]
fn module_register_submodule() {
    let mut m = PythonReModule::new("x");
    m.register_submodule("x.sub");
    // submodules is private but observable via the field through Debug
    let dbg = format!("{m:?}");
    assert!(dbg.contains("x.sub"));
}

#[test]
fn module_functions_tagged() {
    let mut m = PythonReModule::new("x");
    m.register_function(PyFunction::new("a", "").tag("g1"));
    m.register_function(PyFunction::new("b", "").tag("g2"));
    m.register_function(PyFunction::new("c", "").tag("g1"));
    assert_eq!(m.functions_tagged("g1").len(), 2);
    assert_eq!(m.functions_tagged("missing").len(), 0);
}

#[test]
fn module_generate_stub_contains_classes_and_functions() {
    let mut m = PythonReModule::new("x").with_doc("docstr");
    m.register_function(PyFunction::new("foo", "fdoc").returns("int"));
    m.register_class(
        PyClass::new("Bar", "cdoc")
            .property("p")
            .method(PyFunction::new("m", "mdoc").kind(PyFunctionKind::InstanceMethod)),
    );
    let stub = m.generate_stub();
    assert!(stub.contains("docstr"));
    assert!(stub.contains("def foo()"));
    assert!(stub.contains("class Bar(object)"));
    assert!(stub.contains("@property"));
    assert!(stub.contains("def p(self)"));
    assert!(stub.contains("def m()"));
}

#[test]
fn module_generate_stub_inherits_base() {
    let mut m = PythonReModule::new("x");
    m.register_class(PyClass::new("Sub", "d").inherits("Base"));
    let stub = m.generate_stub();
    assert!(stub.contains("class Sub(Base)"));
}

#[test]
fn module_register_module_sets_attrs() {
    Python::with_gil(|py| {
        let mut m = PythonReModule::new("rustre_test").with_doc("docs");
        m.register_function(PyFunction::new("foo", "fd"));
        m.register_class(PyClass::new("Bar", "cd"));
        m.register_constant("VERSION", "1");

        let module = PyModule::new(py, "rustre_test").unwrap();
        m.register_module(py, &module).unwrap();

        let doc: String = module.getattr("__doc__").unwrap().extract().unwrap();
        assert_eq!(doc, "docs");

        let fns = module.getattr("__rustre_functions__").unwrap();
        let fns = fns.downcast::<PyList>().unwrap();
        assert_eq!(fns.len(), 1);

        let cls = module.getattr("__rustre_classes__").unwrap();
        let cls = cls.downcast::<PyList>().unwrap();
        assert_eq!(cls.len(), 1);

        let v: String = module.getattr("VERSION").unwrap().extract().unwrap();
        assert_eq!(v, "1");
    });
}

#[test]
fn module_register_module_no_doc_no_attr() {
    Python::with_gil(|py| {
        let m = PythonReModule::new("x");
        let module = PyModule::new(py, "x").unwrap();
        m.register_module(py, &module).unwrap();
        // empty constants -> attribute lists still exist
        assert!(module.getattr("__rustre_functions__").is_ok());
        assert!(module.getattr("__rustre_classes__").is_ok());
    });
}

#[test]
fn module_default_register_runs() {
    Python::with_gil(|py| {
        let module = PyModule::new(py, "rustre").unwrap();
        python_re_module::register_module(py, &module).unwrap();
        let v: String = module.getattr("__version__").unwrap().extract().unwrap();
        assert_eq!(v, "0.1.0");
        // Should have functions registered.
        let fns = module.getattr("__rustre_functions__").unwrap();
        let fns = fns.downcast::<PyList>().unwrap();
        assert!(fns.len() >= 7);
    });
}

// ── BridgeValue ──────────────────────────────────────────────────────────────

#[test]
fn bridge_type_names_all() {
    assert_eq!(BridgeValue::None.type_name(), "None");
    assert_eq!(BridgeValue::Bool(true).type_name(), "bool");
    assert_eq!(BridgeValue::Int(0).type_name(), "int");
    assert_eq!(BridgeValue::Float(0.0).type_name(), "float");
    assert_eq!(BridgeValue::Str(String::new()).type_name(), "str");
    assert_eq!(BridgeValue::Bytes(Vec::new()).type_name(), "bytes");
    assert_eq!(BridgeValue::List(vec![]).type_name(), "list");
    assert_eq!(BridgeValue::Tuple(vec![]).type_name(), "tuple");
    assert_eq!(BridgeValue::Dict(HashMap::new()).type_name(), "dict");
}

#[test]
fn bridge_roundtrip_none() {
    Python::with_gil(|py| {
        let v = BridgeValue::None;
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), BridgeValue::None);
    });
}

#[test]
fn bridge_roundtrip_bool_true_false() {
    Python::with_gil(|py| {
        for b in [true, false] {
            let v = BridgeValue::Bool(b);
            let obj = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&obj).unwrap(), BridgeValue::Bool(b));
        }
    });
}

#[test]
fn bridge_roundtrip_int_extremes() {
    Python::with_gil(|py| {
        for &i in &[0_i64, 1, -1, i64::MAX, i64::MIN, 42] {
            let v = BridgeValue::Int(i);
            let obj = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&obj).unwrap(), BridgeValue::Int(i));
        }
    });
}

#[test]
fn bridge_roundtrip_float_basic() {
    Python::with_gil(|py| {
        for &f in &[0.0_f64, -1.5, 1.5, f64::MIN_POSITIVE, 1e300] {
            let v = BridgeValue::Float(f);
            let obj = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&obj).unwrap(), BridgeValue::Float(f));
        }
    });
}

#[test]
fn bridge_roundtrip_str_empty_and_unicode() {
    Python::with_gil(|py| {
        for s in ["", "hello", "héllo 世界 🚀", "\0embedded"] {
            let v = BridgeValue::Str(s.to_string());
            let obj = v.to_py(py).unwrap();
            assert_eq!(
                BridgeValue::from_py(&obj).unwrap(),
                BridgeValue::Str(s.to_string())
            );
        }
    });
}

#[test]
fn bridge_roundtrip_bytes_empty_and_binary() {
    Python::with_gil(|py| {
        for b in [vec![], vec![0u8, 1, 2, 255], vec![0xFF; 1024]] {
            let v = BridgeValue::Bytes(b.clone());
            let obj = v.to_py(py).unwrap();
            assert_eq!(BridgeValue::from_py(&obj).unwrap(), BridgeValue::Bytes(b));
        }
    });
}

#[test]
fn bridge_roundtrip_list_empty() {
    Python::with_gil(|py| {
        let v = BridgeValue::List(vec![]);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_list_heterogeneous() {
    Python::with_gil(|py| {
        let v = BridgeValue::List(vec![
            BridgeValue::Int(1),
            BridgeValue::Str("two".into()),
            BridgeValue::Bool(true),
            BridgeValue::None,
        ]);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_nested_list() {
    Python::with_gil(|py| {
        let v = BridgeValue::List(vec![BridgeValue::List(vec![BridgeValue::Int(1)])]);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_tuple_empty() {
    Python::with_gil(|py| {
        let v = BridgeValue::Tuple(vec![]);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_tuple_values() {
    Python::with_gil(|py| {
        let v = BridgeValue::Tuple(vec![BridgeValue::Int(1), BridgeValue::Int(2)]);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_dict_empty() {
    Python::with_gil(|py| {
        let v = BridgeValue::Dict(HashMap::new());
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_dict_multikey() {
    Python::with_gil(|py| {
        let mut m = HashMap::new();
        m.insert("a".to_string(), BridgeValue::Int(1));
        m.insert("b".to_string(), BridgeValue::Str("x".into()));
        m.insert("c".to_string(), BridgeValue::None);
        let v = BridgeValue::Dict(m);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_roundtrip_dict_nested() {
    Python::with_gil(|py| {
        let mut inner = HashMap::new();
        inner.insert("x".to_string(), BridgeValue::Int(1));
        let mut outer = HashMap::new();
        outer.insert("inner".to_string(), BridgeValue::Dict(inner));
        let v = BridgeValue::Dict(outer);
        let obj = v.to_py(py).unwrap();
        assert_eq!(BridgeValue::from_py(&obj).unwrap(), v);
    });
}

#[test]
fn bridge_from_python_unknown_falls_to_str() {
    Python::with_gil(|py| {
        // Make an object that's none of the supported types: a python set.
        let code = "s = {1, 2, 3}";
        let locals = PyDict::new(py);
        py.run(
            &std::ffi::CString::new(code).unwrap(),
            None,
            Some(&locals),
        )
        .unwrap();
        let s = locals.get_item("s").unwrap().unwrap();
        let v = BridgeValue::from_py(&s).unwrap();
        match v {
            BridgeValue::Str(_) => {}
            other => panic!("expected Str fallback, got {other:?}"),
        }
    });
}

#[test]
fn bridge_python_int_overflow_yields_err() {
    Python::with_gil(|py| {
        // 2**100 won't fit in i64
        let code = "v = 2**100";
        let locals = PyDict::new(py);
        py.run(
            &std::ffi::CString::new(code).unwrap(),
            None,
            Some(&locals),
        )
        .unwrap();
        let v = locals.get_item("v").unwrap().unwrap();
        let res = BridgeValue::from_py(&v);
        assert!(res.is_err(), "expected overflow error, got {res:?}");
    });
}

#[test]
fn bridge_python_bool_is_classified_as_bool_not_int() {
    // In Python, bool is a subclass of int. The downcast::<PyBool> branch
    // is checked before PyInt, so True/False should round-trip as Bool.
    Python::with_gil(|py| {
        let code = "v = True";
        let locals = PyDict::new(py);
        py.run(
            &std::ffi::CString::new(code).unwrap(),
            None,
            Some(&locals),
        )
        .unwrap();
        let v = locals.get_item("v").unwrap().unwrap();
        let bv = BridgeValue::from_py(&v).unwrap();
        assert_eq!(bv, BridgeValue::Bool(true));
    });
}

#[test]
fn bridge_to_python_int_type() {
    Python::with_gil(|py| {
        let v = BridgeValue::Int(42);
        let obj = v.to_py(py).unwrap();
        assert!(obj.downcast::<PyInt>().is_ok());
    });
}

#[test]
fn bridge_to_python_str_type() {
    Python::with_gil(|py| {
        let v = BridgeValue::Str("hi".into());
        let obj = v.to_py(py).unwrap();
        assert!(obj.downcast::<PyString>().is_ok());
    });
}

#[test]
fn bridge_to_python_bytes_type() {
    Python::with_gil(|py| {
        let v = BridgeValue::Bytes(vec![1, 2, 3]);
        let obj = v.to_py(py).unwrap();
        assert!(obj.downcast::<PyBytes>().is_ok());
    });
}

#[test]
fn bridge_to_python_float_type() {
    Python::with_gil(|py| {
        let v = BridgeValue::Float(1.5);
        let obj = v.to_py(py).unwrap();
        assert!(obj.downcast::<PyFloat>().is_ok());
    });
}

#[test]
fn bridge_to_python_tuple_type() {
    Python::with_gil(|py| {
        let v = BridgeValue::Tuple(vec![BridgeValue::Int(1)]);
        let obj = v.to_py(py).unwrap();
        assert!(obj.downcast::<PyTuple>().is_ok());
    });
}

#[test]
fn bridge_typebridge_wrappers_match_direct() {
    Python::with_gil(|py| {
        let v = BridgeValue::Int(7);
        let a = PythonTypeBridge::to_python(py, &v).unwrap();
        let back = PythonTypeBridge::from_python(&a).unwrap();
        assert_eq!(back, BridgeValue::Int(7));
    });
}

#[test]
fn bridge_clone_eq() {
    let v = BridgeValue::Int(5);
    assert_eq!(v.clone(), v);
    assert_ne!(BridgeValue::Int(1), BridgeValue::Int(2));
}
