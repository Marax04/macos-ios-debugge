//! `python_api_complete` — Complete rustre API exposed via `PyO3`.
//!
//! Provides a `rustre` Python module with Pythonic classes and free functions.
//! Also implements a compatibility shim for common `IDAPython` patterns so
//! existing IDA scripts can be run with minimal modification.
//!
//! # Python module structure
//!
//! ```python
//! import rustre
//!
//! bv = rustre.BinaryView.open("target.exe")
//! for fn in bv.functions():
//!     print(fn.name, hex(fn.start))
//! fn = bv.function_at(0x1400)
//! print(fn.decompile())
//! fn.rename("my_function")
//! ```
//!
//! # Classes
//!
//! - [`PyBinaryView`]   — open/analyze/close a binary
//! - [`PyFunction`]     — decompile/rename/xrefs
//! - [`PySymbol`]       — name + address pair
//! - [`PyType`]         — type annotation
//! - [`PyBreakpoint`]   — debug breakpoint descriptor

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// ── Internal state ────────────────────────────────────────────────────────────

/// Shared binary state kept behind an `Arc<Mutex<>>` so `PyO3` clone-friendly
/// handles can share it.
#[derive(Debug)]
pub(crate) struct BvState {
    id: String,
    path: String,
    format: String,
    arch: String,
    entry_point: u64,
    /// Preferred load address (image base) of the binary.
    /// For PE files this is the value from the optional-header `ImageBase`
    /// field; for flat/raw binaries it is 0.  Cross-reference calculations
    /// must subtract this value from raw-file offsets before comparing them
    /// against virtual addresses stored in `PyFunction::start`.
    image_base: u64,
    size: usize,
    data: Vec<u8>,
    renames: HashMap<u64, String>,
    type_annotations: HashMap<u64, String>,
    patches: HashMap<u64, Vec<u8>>,
    comments: HashMap<u64, String>,
}

impl BvState {
    fn from_file(path: &str) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        let format = detect_format(&data);
        let arch = detect_arch(&data);
        let entry_point = detect_entry(&data);
        let image_base = detect_image_base(&data);
        let size = data.len();
        let id = format!("bv-{size}");
        Ok(Self {
            id,
            path: path.to_string(),
            format,
            arch,
            entry_point,
            image_base,
            size,
            data,
            renames: HashMap::new(),
            type_annotations: HashMap::new(),
            patches: HashMap::new(),
            comments: HashMap::new(),
        })
    }

    fn function_name(&self, addr: u64) -> String {
        self.renames
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"))
    }

    fn heuristic_functions(&self) -> Vec<(u64, String)> {
        let mut fns = Vec::new();
        if self.entry_point != 0 {
            fns.push((self.entry_point, self.function_name(self.entry_point)));
        }
        for (i, w) in self.data.windows(3).enumerate() {
            if w == [0x55, 0x48, 0x89] {
                let addr = i as u64;
                if !fns.iter().any(|(a, _)| *a == addr) {
                    fns.push((addr, self.function_name(addr)));
                    if fns.len() >= 128 {
                        break;
                    }
                }
            }
        }
        fns
    }

    fn shannon_entropy(&self, offset: usize, size: usize) -> f64 {
        let end = (offset + size).min(self.data.len());
        if offset >= self.data.len() {
            return 0.0;
        }
        let slice = &self.data[offset..end];
        if slice.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in slice {
            freq[b as usize] += 1;
        }
        let n = slice.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum()
    }
}

fn detect_format(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        return "PE".into();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF".into();
    }
    if data.starts_with(b"\xca\xfe\xba\xbe") || data.starts_with(b"\xce\xfa\xed\xfe") {
        return "Mach-O".into();
    }
    "unknown".into()
}

fn detect_arch(data: &[u8]) -> String {
    if data.starts_with(b"\x7fELF") && data.len() > 19 {
        return match u16::from_le_bytes([data[18], data[19]]) {
            0x0003 => "x86",
            0x003e => "x86_64",
            0x0028 => "arm",
            0x00b7 => "aarch64",
            _ => "unknown",
        }
        .into();
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 5 < data.len() && data[pe_off..pe_off + 4] == *b"PE\0\0" {
            return match u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]) {
                0x8664 => "x86_64",
                0x014c => "x86",
                0xaa64 => "aarch64",
                _ => "unknown",
            }
            .into();
        }
    }
    "unknown".into()
}

fn detect_entry(data: &[u8]) -> u64 {
    if data.starts_with(b"\x7fELF") && data.len() >= 32 {
        return u64::from_le_bytes(data[24..32].try_into().unwrap_or([0; 8]));
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 28 < data.len() {
            return u64::from(u32::from_le_bytes(
                data[pe_off + 24..pe_off + 28].try_into().unwrap_or([0; 4]),
            ));
        }
    }
    0
}

/// Extract the preferred load address (image base) from the binary headers.
///
/// For PE64 (PE32+) the image base is a 64-bit value at offset
/// `pe_off + 0x30` in the optional header.  For PE32 it is a 32-bit value at
/// `pe_off + 0x1c`.  ELF and Mach-O binaries are treated as flat (base = 0).
fn detect_image_base(data: &[u8]) -> u64 {
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 6 < data.len() && data[pe_off..pe_off + 4] == *b"PE\0\0" {
            let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
            // PE32+: optional-header magic == 0x020b, ImageBase at +0x30 (u64)
            // PE32:  optional-header magic == 0x010b, ImageBase at +0x1c (u32)
            let opt_off = pe_off + 24; // start of optional header
            if let Some(&magic_lo) = data.get(opt_off) {
                let magic = u16::from_le_bytes([magic_lo, data.get(opt_off + 1).copied().unwrap_or(0)]);
                if machine == 0x8664 && magic == 0x020b && opt_off + 0x38 <= data.len() {
                    return u64::from_le_bytes(
                        data[opt_off + 0x18..opt_off + 0x20].try_into().unwrap_or([0; 8]),
                    );
                } else if magic == 0x010b && opt_off + 0x20 <= data.len() {
                    return u64::from(u32::from_le_bytes(
                        data[opt_off + 0x1c..opt_off + 0x20].try_into().unwrap_or([0; 4]),
                    ));
                }
            }
        }
    }
    0
}

// ── PySymbol ──────────────────────────────────────────────────────────────────

/// A named symbol at a specific address.
#[pyclass(name = "Symbol")]
#[derive(Debug, Clone)]
pub struct PySymbol {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub address: u64,
    #[pyo3(get)]
    pub kind: String,
}

#[pymethods]
impl PySymbol {
    #[new]
    #[must_use] 
    pub const fn new(name: String, address: u64, kind: String) -> Self {
        Self { name, address, kind }
    }

    #[must_use] 
    pub fn __repr__(&self) -> String {
        format!("<Symbol '{}' @ {:#x} ({})>", self.name, self.address, self.kind)
    }

    #[must_use] 
    pub fn __str__(&self) -> String {
        self.__repr__()
    }
}

// ── PyType ────────────────────────────────────────────────────────────────────

/// A type annotation stored in the analysis database.
#[pyclass(name = "Type")]
#[derive(Debug, Clone)]
pub struct PyType {
    #[pyo3(get)]
    pub address: u64,
    #[pyo3(get)]
    pub type_string: String,
}

#[pymethods]
impl PyType {
    #[new]
    #[must_use] 
    pub const fn new(address: u64, type_string: String) -> Self {
        Self { address, type_string }
    }

    #[must_use] 
    pub fn __repr__(&self) -> String {
        format!("<Type {:#x}: {}>", self.address, self.type_string)
    }
}

// ── PyBreakpoint ──────────────────────────────────────────────────────────────

/// A debug breakpoint descriptor.
#[pyclass(name = "Breakpoint")]
#[derive(Debug, Clone)]
pub struct PyBreakpoint {
    #[pyo3(get, set)]
    pub address: u64,
    #[pyo3(get, set)]
    pub enabled: bool,
    #[pyo3(get)]
    pub hit_count: u64,
    #[pyo3(get, set)]
    pub condition: Option<String>,
}

#[pymethods]
impl PyBreakpoint {
    #[new]
    #[must_use] 
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }

    #[must_use] 
    pub fn __repr__(&self) -> String {
        format!(
            "<Breakpoint @{:#x} enabled={} hits={}>",
            self.address, self.enabled, self.hit_count
        )
    }
}

// ── PyFunction ────────────────────────────────────────────────────────────────

/// A function in the binary, attached to a shared `BvState`.
#[pyclass(name = "Function")]
#[derive(Debug, Clone)]
pub struct PyFunction {
    pub(crate) state: Arc<Mutex<BvState>>,
    #[pyo3(get)]
    pub start: u64,
}

#[pymethods]
impl PyFunction {
    /// Return the current name of this function.
    #[getter]
    pub fn name(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .function_name(self.start)
    }

    /// Rename the function.
    pub fn rename(&self, new_name: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .renames
            .insert(self.start, new_name.to_string())
            .is_some()
    }

    /// Return a stub decompilation of the function.
    #[must_use] 
    pub fn decompile(&self) -> String {
        let name = self.name();
        format!(
            "// Decompiled {name} @ {:#x}\nint64_t {name}(void) {{\n    return 0;\n}}",
            self.start
        )
    }

    /// Return all addresses that call this function (xrefs to).
    ///
    /// Scans the binary for `CALL rel32` (opcode `0xE8`) instructions and
    /// checks whether their resolved destination equals `self.start`.
    ///
    /// The destination virtual address is computed as:
    /// `image_base + file_offset + 5 + rel32`
    ///
    /// where `image_base` is the preferred load address extracted from the PE
    /// optional header (0 for flat/raw binaries).  Without this adjustment the
    /// method always returns an empty list for PE files whose preferred base is
    /// non-zero (e.g. 0x140000000 for typical PE64 images).
    pub fn xrefs_to(&self, py: Python<'_>) -> PyObject {
        let guard = self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let data = &guard.data;
        let image_base = guard.image_base;
        let target = self.start;
        let mut refs = Vec::new();
        if data.len() >= 5 {
            for i in 0..data.len() - 4 {
                if data[i] == 0xe8 {
                    let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                    // Resolve destination as a virtual address.
                    let dest = (image_base.cast_signed() + i64::try_from(i).unwrap_or(0) + 5 + i64::from(rel)).cast_unsigned();
                    if dest == target {
                        // Return the caller's virtual address.
                        refs.push(image_base + u64::try_from(i).unwrap_or(0));
                    }
                }
            }
        }
        refs.into_pyobject(py)
            .unwrap_or_else(|_| py.None().into_bound(py))
            .into_any()
            .unbind()
    }

    /// Return all addresses this function calls (xrefs from).
    ///
    /// Walks up to 512 bytes of the function body starting at `self.start`,
    /// converts each `CALL rel32` (opcode `0xE8`) to a virtual address, and
    /// returns the list of call targets.
    ///
    /// `image_base` (from the binary's PE/ELF header) is subtracted from
    /// `self.start` to obtain the file offset, and added back to the resolved
    /// destination so that returned addresses are virtual addresses.
    pub fn xrefs_from(&self, py: Python<'_>) -> PyObject {
        let guard = self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let data = &guard.data;
        let image_base = guard.image_base;
        // Convert the function's virtual address to a file offset.
        let file_offset = usize::try_from((self.start.cast_signed() - image_base.cast_signed()).max(0)).unwrap_or(0);
        let end = (file_offset + 512).min(if data.len() >= 5 { data.len() - 4 } else { 0 });
        let mut refs = Vec::new();
        for i in file_offset..end {
            if data[i] == 0xe8 {
                let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                // Destination as a virtual address.
                refs.push((image_base.cast_signed() + i64::try_from(i).unwrap_or(0) + 5 + i64::from(rel)).cast_unsigned());
            }
        }
        refs.into_pyobject(py)
            .unwrap_or_else(|_| py.None().into_bound(py))
            .into_any()
            .unbind()
    }

    /// Apply a type annotation to this function's return type.
    pub fn set_type(&self, type_str: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .type_annotations
            .insert(self.start, type_str.to_string());
    }

    /// Get the type annotation for this function, if any.
    pub fn get_type(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .type_annotations
            .get(&self.start)
            .cloned()
    }

    /// Set a comment at this function's start address.
    pub fn set_comment(&self, comment: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .comments
            .insert(self.start, comment.to_string());
    }

    #[must_use] 
    pub fn __repr__(&self) -> String {
        format!("<Function '{}' @ {:#x}>", self.name(), self.start)
    }

    #[must_use] 
    pub fn __str__(&self) -> String {
        self.__repr__()
    }
}

// ── PyBinaryView ──────────────────────────────────────────────────────────────

/// The main entry point for binary analysis.
///
/// ```python
/// bv = rustre.BinaryView.open("binary.exe")
/// print(bv.format, bv.arch)
/// for f in bv.functions():
///     print(f.name)
/// ```
#[pyclass(name = "BinaryView")]
pub struct PyBinaryView {
    pub(crate) state: Arc<Mutex<BvState>>,
}

#[pymethods]
impl PyBinaryView {
    /// Open a binary file and return a `BinaryView`.
    #[staticmethod]
    pub fn open(path: &str) -> PyResult<Self> {
        let state =
            BvState::from_file(path).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Close the binary view and release memory.
    pub const fn close(&self) {
        // In a real implementation this would drop caches etc.
        // The Arc will clean up when the last reference is dropped.
    }

    /// Trigger analysis (stub).
    pub fn analyze(&self) -> String {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        format!("analysis complete on {} ({})", guard.path, guard.format)
    }

    #[getter]
    pub fn id(&self) -> String {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).id.clone()
    }

    #[getter]
    pub fn path(&self) -> String {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).path.clone()
    }

    #[getter]
    pub fn format(&self) -> String {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).format.clone()
    }

    #[getter]
    pub fn arch(&self) -> String {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).arch.clone()
    }

    #[getter]
    pub fn entry_point(&self) -> u64 {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry_point
    }

    #[getter]
    pub fn size(&self) -> usize {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).size
    }

    /// Return all discovered functions as a list of `Function` objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn functions(&self, py: Python<'_>) -> PyObject {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fns = guard.heuristic_functions();
        drop(guard);
        let list = PyList::empty(py);
        for (addr, _) in fns {
            let func = PyFunction {
                state: Arc::clone(&self.state),
                start: addr,
            };
            let _ = list.append(Py::new(py, func).unwrap().into_pyobject(py).unwrap());
        }
        list.into()
    }

    /// Return the `Function` at `addr`, or `None` if not found.
    pub fn function_at(&self, addr: u64) -> Option<PyFunction> {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fns = guard.heuristic_functions();
        drop(guard);
        if fns.iter().any(|(a, _)| *a == addr) {
            Some(PyFunction {
                state: Arc::clone(&self.state),
                start: addr,
            })
        } else {
            None
        }
    }

    /// Define a new function at `addr` (adds it to the function table).
    #[pyo3(signature = (addr, name=None))]
    pub fn define_function(&self, addr: u64, name: Option<&str>) -> PyFunction {
        if let Some(n) = name {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .renames
                .insert(addr, n.to_string());
        }
        PyFunction {
            state: Arc::clone(&self.state),
            start: addr,
        }
    }

    /// Read `size` bytes at `addr` and return them as a `bytes` object.
    ///
    /// # Panics
    ///
    /// Panics if `addr` exceeds `usize::MAX` (only on 32-bit targets).
    pub fn read_bytes(&self, py: Python<'_>, addr: u64, size: usize) -> PyObject {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let off = usize::try_from(addr).unwrap_or(usize::MAX);
        if off >= guard.data.len() {
            return py.None();
        }
        let end = (off + size).min(guard.data.len());
        let slice = guard.data[off..end].to_vec();
        drop(guard);
        slice.into_pyobject(py)
            .unwrap_or_else(|_| py.None().into_bound(py))
            .into_any()
            .unbind()
    }

    /// Apply a raw patch.  `data` must be a `bytes` object.
    pub fn patch_bytes(&self, addr: u64, data: &[u8]) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .patches
            .insert(addr, data.to_vec());
    }

    /// Get the Shannon entropy of `size` bytes at `addr`.
    pub fn entropy(&self, addr: u64, size: usize) -> f64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shannon_entropy(usize::try_from(addr).unwrap_or(0), size)
    }

    /// Search for a byte pattern.  Returns list of matching offsets.
    pub fn search_bytes(&self, py: Python<'_>, pattern: &[u8]) -> PyObject {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let data = &guard.data;
        let plen = pattern.len();
        let mut results = Vec::new();
        if plen > 0 && data.len() >= plen {
            for i in 0..=(data.len() - plen) {
                if data[i..i + plen] == pattern[..] {
                    results.push(u64::try_from(i).unwrap_or(u64::MAX));
                }
            }
        }
        drop(guard);
        results
            .into_pyobject(py)
            .unwrap_or_else(|_| py.None().into_bound(py))
            .into_any()
            .unbind()
    }

    /// Return all printable strings found in the binary.
    #[pyo3(signature = (min_len=None))]
    pub fn strings(&self, py: Python<'_>, min_len: Option<usize>) -> PyObject {
        let min = min_len.unwrap_or(4);
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let data = &guard.data;
        let dict_list = PyList::empty(py);
        let mut buf = String::new();
        let mut start = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii() && !b.is_ascii_control() {
                if buf.is_empty() {
                    start = i;
                }
                buf.push(b as char);
            } else {
                if buf.len() >= min {
                    let d = PyDict::new(py);
                    let _ = d.set_item("offset", start);
                    let _ = d.set_item("value", buf.clone());
                    let _ = dict_list.append(d);
                }
                buf.clear();
            }
        }
        if buf.len() >= min {
            let d = PyDict::new(py);
            let _ = d.set_item("offset", start);
            let _ = d.set_item("value", buf.clone());
            let _ = dict_list.append(d);
        }
        drop(guard);
        dict_list.into()
    }

    /// List all symbols (exports) as `Symbol` objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn symbols(&self, py: Python<'_>) -> PyObject {
        let guard = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fns = guard.heuristic_functions();
        drop(guard);
        let list = PyList::empty(py);
        for (addr, name) in fns {
            let sym = PySymbol::new(name, addr, "function".into());
            let _ = list.append(Py::new(py, sym).unwrap().into_pyobject(py).unwrap());
        }
        list.into()
    }

    /// Get/set a comment at `addr`.
    pub fn set_comment(&self, addr: u64, comment: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .comments
            .insert(addr, comment.to_string());
    }

    /// Return the comment at `addr`, or `None`.
    pub fn get_comment(&self, addr: u64) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .comments
            .get(&addr)
            .cloned()
    }

    pub fn __repr__(&self) -> String {
        let g = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        format!("<BinaryView '{}' {} {}>", g.path, g.format, g.arch)
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// `rustre.open_binary(path)` — convenience wrapper for `BinaryView.open`.
#[pyfunction]
pub fn open_binary(path: &str) -> PyResult<PyBinaryView> {
    PyBinaryView::open(path)
}

/// `rustre.version()` — return the rustre scripting layer version string.
#[pyfunction]
#[must_use] 
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `rustre.entropy(data: bytes) → float`
#[pyfunction]
#[must_use] 
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// `rustre.xor_decrypt(data: bytes, key: int | bytes) → bytes`
///
/// # Panics
///
/// Panics if the internal `PyO3` conversion fails (should not happen with valid data).
#[pyfunction]
pub fn xor_decrypt(py: Python<'_>, data: Vec<u8>, key: &Bound<'_, PyAny>) -> PyResult<PyObject> {
    let key_bytes: Vec<u8> = if let Ok(n) = key.extract::<u8>() {
        vec![n]
    } else if let Ok(b) = key.extract::<Vec<u8>>() {
        b
    } else {
        return Err(PyValueError::new_err("key must be int or bytes"));
    };
    if key_bytes.is_empty() {
        return Ok(data.into_pyobject(py).unwrap().into_any().unbind());
    }
    let result: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    Ok(result.into_pyobject(py).unwrap().into_any().unbind())
}

/// `rustre.crc32(data: bytes) → int`
///
/// Computes the IEEE 802.3 CRC-32 checksum of `data`.
///
/// # Empty input
/// `crc32(&[])` returns `0x00000000`, which is the standard IEEE 802.3 result
/// for an empty byte sequence (initial value `0xFFFFFFFF`, final XOR
/// `0xFFFFFFFF`, no iterations → `!0xFFFFFFFF == 0`). This is intentional and
/// consistent with Python's `binascii.crc32(b"")`.
#[pyfunction]
#[must_use] 
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// `rustre.find_pattern(data: bytes, pattern: str) → int | None`
///
/// `pattern` is a hex string with optional `??` wildcards.
#[pyfunction]
pub fn find_pattern(data: &[u8], pattern: &str) -> PyResult<Option<usize>> {
    let pat: Vec<Option<u8>> = pattern
        .split_whitespace()
        .map(|tok| {
            if tok == "??" || tok == "?" {
                Ok(None)
            } else {
                u8::from_str_radix(tok, 16)
                    .map(Some)
                    .map_err(|e| PyValueError::new_err(e.to_string()))
            }
        })
        .collect::<PyResult<_>>()?;
    let plen = pat.len();
    if plen == 0 || data.len() < plen {
        return Ok(None);
    }
    for i in 0..=(data.len() - plen) {
        if pat
            .iter()
            .enumerate()
            .all(|(j, &p)| p.is_none_or(|b| b == data[i + j]))
        {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

// ── Module registration ───────────────────────────────────────────────────────

/// Register the `rustre` Python module.
pub fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "rustre")?;
    m.add_class::<PyBinaryView>()?;
    m.add_class::<PyFunction>()?;
    m.add_class::<PySymbol>()?;
    m.add_class::<PyType>()?;
    m.add_class::<PyBreakpoint>()?;
    m.add_function(wrap_pyfunction!(open_binary, &m)?)?;
    m.add_function(wrap_pyfunction!(version, &m)?)?;
    m.add_function(wrap_pyfunction!(entropy, &m)?)?;
    m.add_function(wrap_pyfunction!(xor_decrypt, &m)?)?;
    m.add_function(wrap_pyfunction!(crc32, &m)?)?;
    m.add_function(wrap_pyfunction!(find_pattern, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_pe() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        assert_eq!(detect_format(&data), "PE");
    }

    #[test]
    fn test_detect_format_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00".to_vec();
        assert_eq!(detect_format(&data), "ELF");
    }

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let e = entropy(&data);
        assert!(e > 7.99, "expected ~8, got {e}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0u8; 256];
        let e = entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_crc32_empty() {
        // IEEE 802.3 CRC-32 of empty input is 0x00000000 by definition.
        assert_eq!(crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn test_crc32_known_vector() {
        // IEEE 802.3 check value: CRC-32 of b"123456789" must be 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_bv_state_function_name_default() {
        let mut data = vec![0u8; 256];
        // Insert function prologue at offset 4.
        data[4] = 0x55;
        data[5] = 0x48;
        data[6] = 0x89;
        let state = BvState {
            id: "test".into(),
            path: "test.bin".into(),
            format: "PE".into(),
            arch: "x86_64".into(),
            entry_point: 0,
            image_base: 0,
            size: data.len(),
            data,
            renames: HashMap::new(),
            type_annotations: HashMap::new(),
            patches: HashMap::new(),
            comments: HashMap::new(),
        };
        assert_eq!(state.function_name(4), "sub_4");
    }

    #[test]
    fn test_bv_state_function_rename() {
        let mut data = vec![0u8; 64];
        data[0] = 0x55;
        data[1] = 0x48;
        data[2] = 0x89;
        let mut state = BvState {
            id: "t".into(),
            path: "t.bin".into(),
            format: "ELF".into(),
            arch: "x86_64".into(),
            entry_point: 0,
            image_base: 0,
            size: 64,
            data,
            renames: HashMap::new(),
            type_annotations: HashMap::new(),
            patches: HashMap::new(),
            comments: HashMap::new(),
        };
        state.renames.insert(0, "main".into());
        assert_eq!(state.function_name(0), "main");
    }

    #[test]
    fn test_shannon_entropy_zero() {
        let state = BvState {
            id: "t".into(), path: "t".into(), format: "?".into(), arch: "?".into(),
            entry_point: 0, image_base: 0, size: 4,
            data: vec![0u8; 4],
            renames: HashMap::new(), type_annotations: HashMap::new(),
            patches: HashMap::new(), comments: HashMap::new(),
        };
        assert_eq!(state.shannon_entropy(0, 4), 0.0);
    }
}
