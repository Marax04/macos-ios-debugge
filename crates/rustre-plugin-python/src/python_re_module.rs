// rustre-plugin-python/src/python_re_module.rs
//
// Python RE module for RustRE.
// Exposes the reverse-engineering platform to Python scripts by registering
// functions and classes into a named Python module via PyO3.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::fmt;

// ── PyFunctionKind ────────────────────────────────────────────────────────────

/// How a Python function is bound in the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyFunctionKind {
    /// Top-level module function.
    ModuleLevel,
    /// Static method on a class (no `self`).
    StaticMethod,
    /// Instance method (receives `self` as first argument).
    InstanceMethod,
    /// Class method (receives `cls` as first argument).
    ClassMethod,
}

impl fmt::Display for PyFunctionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleLevel => write!(f, "module"),
            Self::StaticMethod => write!(f, "staticmethod"),
            Self::InstanceMethod => write!(f, "method"),
            Self::ClassMethod => write!(f, "classmethod"),
        }
    }
}

// ── PyArgSpec ─────────────────────────────────────────────────────────────────

/// Description of a single argument in a Python function signature.
#[derive(Debug, Clone)]
pub struct PyArgSpec {
    /// Argument name.
    pub name: String,
    /// Python type annotation string, e.g. `"int"`, `"str"`, `"Optional[str]"`.
    pub type_annotation: Option<String>,
    /// Whether this argument has a default value.
    pub has_default: bool,
    /// Whether this is a `*args` variadic argument.
    pub is_vararg: bool,
    /// Whether this is a `**kwargs` variadic argument.
    pub is_kwargs: bool,
}

impl PyArgSpec {
    /// Construct a plain positional argument.
    #[must_use]
    pub fn positional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_annotation: None,
            has_default: false,
            is_vararg: false,
            is_kwargs: false,
        }
    }

    /// Add a type annotation.
    #[must_use]
    pub fn with_type(mut self, annotation: impl Into<String>) -> Self {
        self.type_annotation = Some(annotation.into());
        self
    }

    /// Mark this argument as having a default value.
    #[must_use]
    pub const fn with_default(mut self) -> Self {
        self.has_default = true;
        self
    }
}

impl fmt::Display for PyArgSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_kwargs {
            write!(f, "**{}", self.name)?;
        } else if self.is_vararg {
            write!(f, "*{}", self.name)?;
        } else {
            write!(f, "{}", self.name)?;
        }
        if let Some(ty) = &self.type_annotation {
            write!(f, ": {ty}")?;
        }
        if self.has_default {
            write!(f, " = ...")?;
        }
        Ok(())
    }
}

// ── PyFunction ────────────────────────────────────────────────────────────────

/// A Python callable registered in the RE module.
#[derive(Debug, Clone)]
pub struct PyFunction {
    /// Function name as it appears in Python.
    pub name: String,
    /// Human-readable docstring.
    pub doc: String,
    /// Argument specifications (in declaration order).
    pub args: Vec<PyArgSpec>,
    /// Return type annotation string.
    pub return_type: Option<String>,
    /// How this function is bound.
    pub kind: PyFunctionKind,
    /// Tags for grouping (e.g. `"analysis"`, `"disasm"`, `"types"`).
    pub tags: Vec<String>,
}

impl PyFunction {
    /// Construct a new module-level function descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, doc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            doc: doc.into(),
            args: Vec::new(),
            return_type: None,
            kind: PyFunctionKind::ModuleLevel,
            tags: Vec::new(),
        }
    }

    /// Add an argument.
    #[must_use]
    pub fn arg(mut self, spec: PyArgSpec) -> Self {
        self.args.push(spec);
        self
    }

    /// Set the return type annotation.
    #[must_use]
    pub fn returns(mut self, ty: impl Into<String>) -> Self {
        self.return_type = Some(ty.into());
        self
    }

    /// Set the function kind.
    #[must_use]
    pub fn kind(mut self, kind: PyFunctionKind) -> Self {
        self.kind = kind;
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Render the Python stub signature for this function.
    ///
    /// Produces `def name(args) -> RetType:` (PEP 484 style).
    #[must_use]
    pub fn stub_signature(&self) -> String {
        let args: Vec<String> = self.args.iter().map(|a| a.to_string()).collect();
        let ret = self
            .return_type
            .as_deref()
            .map_or(String::new(), |r| format!(" -> {r}"));
        format!("def {}({}){ret}:", self.name, args.join(", "))
    }
}

impl fmt::Display for PyFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.kind)
    }
}

// ── PyClass ───────────────────────────────────────────────────────────────────

/// A Python class registered in the RE module.
#[derive(Debug, Clone)]
pub struct PyClass {
    /// Class name.
    pub name: String,
    /// Docstring.
    pub doc: String,
    /// Methods defined on this class.
    pub methods: Vec<PyFunction>,
    /// Properties (getters).
    pub properties: Vec<String>,
    /// Optional base class name.
    pub base_class: Option<String>,
    /// Whether the class is iterable.
    pub iterable: bool,
}

impl PyClass {
    /// Construct a new class descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, doc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            doc: doc.into(),
            methods: Vec::new(),
            properties: Vec::new(),
            base_class: None,
            iterable: false,
        }
    }

    /// Add a method.
    #[must_use]
    pub fn method(mut self, method: PyFunction) -> Self {
        self.methods.push(method);
        self
    }

    /// Add a read-only property.
    #[must_use]
    pub fn property(mut self, name: impl Into<String>) -> Self {
        self.properties.push(name.into());
        self
    }

    /// Set the base class.
    #[must_use]
    pub fn inherits(mut self, base: impl Into<String>) -> Self {
        self.base_class = Some(base.into());
        self
    }

    /// Mark class as iterable.
    #[must_use]
    pub const fn make_iterable(mut self) -> Self {
        self.iterable = true;
        self
    }

    /// Return only the methods with the given tag.
    #[must_use]
    pub fn methods_tagged(&self, tag: &str) -> Vec<&PyFunction> {
        self.methods.iter().filter(|m| m.tags.iter().any(|t| t == tag)).collect()
    }
}

impl fmt::Display for PyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self
            .base_class
            .as_deref()
            .map_or(String::new(), |b| format!("({b})"));
        write!(f, "class {}{base}", self.name)
    }
}

// ── PythonReModule ────────────────────────────────────────────────────────────

/// Registry of all functions and classes that form the `rustre` Python module.
///
/// # Usage
///
/// ```
/// use rustre_plugin_python::python_re_module::{
///     PyArgSpec, PyClass, PyFunction, PythonReModule,
/// };
///
/// let mut module = PythonReModule::new("rustre");
/// module.register_function(
///     PyFunction::new("disassemble", "Disassemble bytes at address.")
///         .arg(PyArgSpec::positional("addr").with_type("int"))
///         .returns("list[Instruction]")
/// );
/// assert_eq!(module.function_count(), 1);
/// ```
#[derive(Debug)]
pub struct PythonReModule {
    /// Module name used in `import`.
    pub module_name: String,
    /// Module-level docstring.
    pub doc: String,
    /// Registered free functions.
    functions: Vec<PyFunction>,
    /// Registered classes.
    classes: Vec<PyClass>,
    /// Module-level constants (name → Python repr string).
    constants: HashMap<String, String>,
    /// Sub-module names.
    submodules: Vec<String>,
}

impl PythonReModule {
    /// Create an empty module.
    #[must_use]
    pub fn new(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            doc: String::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            constants: HashMap::new(),
            submodules: Vec::new(),
        }
    }

    /// Set the module docstring.
    #[must_use]
    pub fn with_doc(mut self, doc: impl Into<String>) -> Self {
        self.doc = doc.into();
        self
    }

    /// Register a function in the module.
    pub fn register_function(&mut self, func: PyFunction) {
        self.functions.push(func);
    }

    /// Register a class in the module.
    pub fn register_class(&mut self, class: PyClass) {
        self.classes.push(class);
    }

    /// Register a module-level constant.
    pub fn register_constant(&mut self, name: impl Into<String>, repr: impl Into<String>) {
        self.constants.insert(name.into(), repr.into());
    }

    /// Register a sub-module name.
    pub fn register_submodule(&mut self, name: impl Into<String>) {
        self.submodules.push(name.into());
    }

    /// Number of registered functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of registered classes.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Find a function by name.
    #[must_use]
    pub fn function(&self, name: &str) -> Option<&PyFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Find a class by name.
    #[must_use]
    pub fn class(&self, name: &str) -> Option<&PyClass> {
        self.classes.iter().find(|c| c.name == name)
    }

    /// Return functions matching a given tag.
    #[must_use]
    pub fn functions_tagged(&self, tag: &str) -> Vec<&PyFunction> {
        self.functions
            .iter()
            .filter(|f| f.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Escape a value that will be placed inside a `"""…"""` docstring.
    ///
    /// The `doc` fields are plain `pub String`s that any caller can set, and
    /// these docs describe *Python* code — so a doc legitimately containing
    /// `"""` is not far-fetched. Interpolated raw it would close the docstring
    /// early and leave the generated stub syntactically broken (or carrying
    /// whatever followed as code). Escaping the backslash first and then every
    /// quote is deliberately blunt: it needs no reasoning about trailing
    /// quotes or overlapping triples to be correct.
    ///
    /// Same shape as `qemu_escape_opt_value` in `rustre-sandbox-vm`.
    fn escape_docstring(doc: &str) -> String {
        doc.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// Generate a `.pyi` stub file content for this module.
    #[must_use]
    pub fn generate_stub(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("# Stub for module '{}'", self.module_name));
        if !self.doc.is_empty() {
            lines.push(format!("\"\"\"{}\"\"\"\n", Self::escape_docstring(&self.doc)));
        }

        // Constants.
        for (name, repr) in &self.constants {
            lines.push(format!("{name}: ... = {repr}"));
        }
        if !self.constants.is_empty() {
            lines.push(String::new());
        }

        // Classes.
        for cls in &self.classes {
            let base = cls.base_class.as_deref().unwrap_or("object");
            lines.push(format!("class {}({base}):", cls.name));
            lines.push(format!("    \"\"\"{}\"\"\"", Self::escape_docstring(&cls.doc)));
            for prop in &cls.properties {
                lines.push(format!("    @property"));
                lines.push(format!("    def {prop}(self): ..."));
            }
            for method in &cls.methods {
                lines.push(format!("    {}", method.stub_signature()));
                lines.push(format!(
                    "        \"\"\"{}\"\"\"",
                    Self::escape_docstring(&method.doc)
                ));
            }
            lines.push(String::new());
        }

        // Module functions.
        for func in &self.functions {
            lines.push(func.stub_signature());
            lines.push(format!("    \"\"\"{}\"\"\"", Self::escape_docstring(&func.doc)));
            lines.push(String::new());
        }

        lines.join("\n")
    }

    /// Register the module's contents into a PyO3 Python module object.
    ///
    /// This is called from the `#[pymodule]` init function.
    ///
    /// # Errors
    ///
    /// Returns a `PyErr` if any PyO3 operation fails.
    pub fn register_module<'py>(&self, py: Python<'py>, m: &Bound<'py, PyModule>) -> PyResult<()> {
        // Set module docstring.
        if !self.doc.is_empty() {
            m.setattr("__doc__", self.doc.as_str())?;
        }

        // Register constants as module attributes.
        for (name, repr) in &self.constants {
            m.setattr(name.as_str(), repr.as_str())?;
        }

        // Register each function as a no-op placeholder (real implementations
        // are registered by the host via `#[pyfunction]` macros; this method
        // sets up the metadata layer).
        let fn_list = PyList::empty(py);
        for func in &self.functions {
            let entry = PyDict::new(py);
            entry.set_item("name", func.name.as_str())?;
            entry.set_item("doc", func.doc.as_str())?;
            entry.set_item("kind", func.kind.to_string())?;
            fn_list.append(entry)?;
        }
        m.setattr("__rustre_functions__", fn_list)?;

        // Register class descriptors.
        let cls_list = PyList::empty(py);
        for cls in &self.classes {
            let entry = PyDict::new(py);
            entry.set_item("name", cls.name.as_str())?;
            entry.set_item("doc", cls.doc.as_str())?;
            entry.set_item("methods", cls.methods.len().to_string())?;
            cls_list.append(entry)?;
        }
        m.setattr("__rustre_classes__", cls_list)?;

        Ok(())
    }
}

/// Build and register the default `rustre` Python module.
///
/// Called by the PyO3 module initialiser in the main plugin host.
///
/// # Errors
///
/// Returns a `PyErr` if any PyO3 registration step fails.
pub fn register_module<'py>(py: Python<'py>, m: &Bound<'py, PyModule>) -> PyResult<()> {
    let mut module = PythonReModule::new("rustre")
        .with_doc("RustRE Python bindings — reverse-engineering automation API.");

    // ── Core functions ────────────────────────────────────────────────────────
    module.register_function(
        PyFunction::new("get_functions", "Return all functions in the current binary.")
            .returns("list[Function]")
            .tag("analysis"),
    );
    module.register_function(
        PyFunction::new("get_function_at", "Return the function starting at addr.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .returns("Optional[Function]")
            .tag("analysis"),
    );
    module.register_function(
        PyFunction::new("disassemble", "Disassemble bytes at addr.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .arg(PyArgSpec::positional("count").with_type("int").with_default())
            .returns("list[Instruction]")
            .tag("disasm"),
    );
    module.register_function(
        PyFunction::new("read_bytes", "Read raw bytes from the loaded binary.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .arg(PyArgSpec::positional("length").with_type("int"))
            .returns("bytes")
            .tag("memory"),
    );
    module.register_function(
        PyFunction::new("define_function", "Manually define a function at addr.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .returns("Function")
            .tag("analysis"),
    );
    module.register_function(
        PyFunction::new("set_comment", "Set a comment at addr.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .arg(PyArgSpec::positional("comment").with_type("str"))
            .returns("None")
            .tag("annotation"),
    );
    module.register_function(
        PyFunction::new("get_string_at", "Read a null-terminated string from addr.")
            .arg(PyArgSpec::positional("addr").with_type("int"))
            .returns("Optional[str]")
            .tag("memory"),
    );

    // ── Core classes ──────────────────────────────────────────────────────────
    let function_class = PyClass::new("Function", "Represents an analysed function.")
        .property("address")
        .property("name")
        .property("size")
        .method(
            PyFunction::new("instructions", "Return a list of Instructions in this function.")
                .kind(PyFunctionKind::InstanceMethod)
                .returns("list[Instruction]"),
        )
        .method(
            PyFunction::new("rename", "Rename the function.")
                .kind(PyFunctionKind::InstanceMethod)
                .arg(PyArgSpec::positional("new_name").with_type("str"))
                .returns("None"),
        )
        .method(
            PyFunction::new("callers", "Return functions that call this one.")
                .kind(PyFunctionKind::InstanceMethod)
                .returns("list[Function]"),
        );

    let instruction_class = PyClass::new("Instruction", "A single disassembled instruction.")
        .property("address")
        .property("mnemonic")
        .property("operands")
        .property("size")
        .method(
            PyFunction::new("is_call", "True if this instruction is a call.")
                .kind(PyFunctionKind::InstanceMethod)
                .returns("bool"),
        )
        .method(
            PyFunction::new("is_branch", "True if this is a branch.")
                .kind(PyFunctionKind::InstanceMethod)
                .returns("bool"),
        );

    module.register_class(function_class);
    module.register_class(instruction_class);

    // Register into the Python module object.
    module.register_module(py, m)?;

    // Version constant.
    m.setattr("__version__", "0.1.0")?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_module() -> PythonReModule {
        let mut m = PythonReModule::new("rustre");
        m.register_function(
            PyFunction::new("get_functions", "Get all functions.")
                .returns("list[Function]")
                .tag("analysis"),
        );
        m.register_function(
            PyFunction::new("disassemble", "Disassemble.")
                .arg(PyArgSpec::positional("addr").with_type("int"))
                .returns("list[Instruction]")
                .tag("disasm"),
        );
        m.register_class(
            PyClass::new("Function", "A function.")
                .property("address")
                .method(
                    PyFunction::new("rename", "Rename.")
                        .kind(PyFunctionKind::InstanceMethod),
                ),
        );
        m.register_constant("VERSION", "\"0.1.0\"");
        m
    }

    #[test]
    fn test_function_count() {
        let m = sample_module();
        assert_eq!(m.function_count(), 2);
    }

    #[test]
    fn test_class_count() {
        let m = sample_module();
        assert_eq!(m.class_count(), 1);
    }

    #[test]
    fn test_find_function() {
        let m = sample_module();
        let f = m.function("get_functions").unwrap();
        assert_eq!(f.name, "get_functions");
    }

    #[test]
    fn test_find_class() {
        let m = sample_module();
        let c = m.class("Function").unwrap();
        assert_eq!(c.name, "Function");
    }

    #[test]
    fn test_functions_by_tag() {
        let m = sample_module();
        let tagged = m.functions_tagged("analysis");
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].name, "get_functions");
    }

    #[test]
    fn test_stub_generation() {
        let m = sample_module();
        let stub = m.generate_stub();
        assert!(stub.contains("def get_functions"));
        assert!(stub.contains("class Function"));
        assert!(stub.contains("VERSION"));
    }

    /// A `doc` containing `"""` used to close the generated docstring early,
    /// leaving the rest of the doc sitting in the stub as Python code. Docs
    /// that describe Python are exactly where triple quotes turn up, so this
    /// was reachable without malice.
    #[test]
    fn test_stub_escapes_quotes_in_docs() {
        let mut m = PythonReModule::new("rustre");
        m.register_function(PyFunction::new(
            "f",
            "closes here: \"\"\" then import os; os.system('x')",
        ));
        m.register_class(PyClass::new("C", "trailing quote\"").method(
            PyFunction::new("meth", "back\\slash and \"\"\"")
                .kind(PyFunctionKind::InstanceMethod),
        ));
        let stub = m.generate_stub();

        // No unescaped triple quote may survive inside a docstring body: every
        // `"""` in the output must be one of the delimiters we emitted.
        for line in stub.lines() {
            let body = line.trim_start();
            if let Some(rest) = body.strip_prefix("\"\"\"") {
                let inner = rest.strip_suffix("\"\"\"").unwrap_or(rest);
                assert!(
                    !inner.contains("\"\"\""),
                    "unescaped triple quote inside a docstring: {line:?}"
                );
                assert!(
                    !inner.ends_with('\\') || inner.ends_with("\\\\"),
                    "docstring ends with a lone backslash, which escapes the \
                     closing delimiter: {line:?}"
                );
            }
        }
        // The text itself is still there — escaped, inside the docstring. What
        // must not survive is the raw delimiter that would have ended it.
        assert!(stub.contains("\\\"\\\"\\\""));
    }

    #[test]
    fn test_stub_signature() {
        let f = PyFunction::new("my_fn", "doc")
            .arg(PyArgSpec::positional("x").with_type("int"))
            .returns("str");
        assert_eq!(f.stub_signature(), "def my_fn(x: int) -> str:");
    }

    #[test]
    fn test_arg_display() {
        let a = PyArgSpec::positional("name").with_type("str").with_default();
        assert!(a.to_string().contains("name: str = ..."));
    }

    #[test]
    fn test_class_display() {
        let c = PyClass::new("MyClass", "doc").inherits("BaseClass");
        assert!(c.to_string().contains("MyClass(BaseClass)"));
    }

    #[test]
    fn test_function_display() {
        let f = PyFunction::new("fn1", "doc");
        assert!(f.to_string().contains("fn1"));
        assert!(f.to_string().contains("module"));
    }

    #[test]
    fn test_class_methods_tagged() {
        let c = PyClass::new("C", "doc")
            .method(PyFunction::new("a", "a").tag("slow"))
            .method(PyFunction::new("b", "b").tag("fast"))
            .method(PyFunction::new("c", "c").tag("slow"));
        let slow = c.methods_tagged("slow");
        assert_eq!(slow.len(), 2);
    }

    #[test]
    fn test_register_submodule() {
        let mut m = PythonReModule::new("rustre");
        m.register_submodule("rustre.types");
        assert_eq!(m.submodules.len(), 1);
    }

    #[test]
    fn test_function_not_found() {
        let m = sample_module();
        assert!(m.function("nonexistent").is_none());
    }

    #[test]
    fn test_class_iterable() {
        let c = PyClass::new("Results", "doc").make_iterable();
        assert!(c.iterable);
    }
}
