//! `python_ida_compat` — `IDAPython` API compatibility layer via `PyO3`.
//!
//! Implements a substantial subset of the IDA Python API so that existing
//! IDA scripts can run on top of rustre with minimal modification.
//!
//! # Supported namespaces
//!
//! | IDA module | Coverage |
//! |---|---|
//! | `idc` | `get_name`, `set_name`, `get_operand_value`, `create_insn`, `op_plain_offset`, `get_wide_byte`, `get_wide_word`, `get_wide_dword`, `get_wide_qword`, `set_cmt`, `get_cmt`, `find_binary` |
//! | `idaapi` | `get_func`, `FlowChart`, `BasicBlock`, `FUNCATTR_START`, `FUNCATTR_END`, `get_byte`, `put_byte` |
//! | `idautils` | `Functions`, `Names`, `CodeRefsTo`, `DataRefsTo`, `XrefsTo`, `XrefsFrom` |
//! | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_original_byte` |
//! | `ida_segment` | `getseg`, `get_segm_name`, `Segments` |
//!
//! All functions operate on the current "active database" set by
//! `set_active_database(path)`.

#![allow(non_snake_case, reason = "IDA Pro 7.x API compatibility: the names are the contract with existing IDA scripts")]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};

// ── Internal database ─────────────────────────────────────────────────────────

/// Minimal in-process database that backs the IDA compat layer.
#[derive(Debug, Default)]
struct IdaDb {
    data: Vec<u8>,
    path: String,
    names: HashMap<u64, String>,        // ea → name
    comments: HashMap<u64, String>,     // ea → comment
    functions: HashMap<u64, u64>,       // start → end (start + estimated size)
    patches: HashMap<u64, u8>,          // ea → patched byte
}

impl IdaDb {
    fn from_file(path: &str) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        let mut db = Self {
            data,
            path: path.to_string(),
            ..Default::default()
        };
        db.auto_detect_functions();
        Ok(db)
    }

    fn read_byte(&self, ea: u64) -> u8 {
        if let Some(&b) = self.patches.get(&ea) {
            return b;
        }
        self.data.get(usize::try_from(ea).unwrap_or(usize::MAX)).copied().unwrap_or(0xFF)
    }

    fn write_byte(&mut self, ea: u64, b: u8) {
        self.patches.insert(ea, b);
    }

    fn read_bytes(&self, ea: u64, size: usize) -> Vec<u8> {
        (0..size).map(|i| self.read_byte(ea + i as u64)).collect()
    }

    fn auto_detect_functions(&mut self) {
        // ELF entry.
        if self.data.starts_with(b"\x7fELF") && self.data.len() >= 32 {
            let entry = u64::from_le_bytes(self.data[24..32].try_into().unwrap_or([0; 8]));
            if entry != 0 {
                self.functions.insert(entry, entry + 64);
            }
        }
        // PE entry.
        if self.data.starts_with(b"MZ") && self.data.len() > 0x40 {
            let pe_off = u32::from_le_bytes([
                self.data.get(0x3c).copied().unwrap_or(0),
                self.data.get(0x3d).copied().unwrap_or(0),
                self.data.get(0x3e).copied().unwrap_or(0),
                self.data.get(0x3f).copied().unwrap_or(0),
            ]) as usize;
            if pe_off + 28 < self.data.len() {
                let ep = u64::from(u32::from_le_bytes(
                    self.data[pe_off + 24..pe_off + 28].try_into().unwrap_or([0; 4]),
                ));
                if ep != 0 {
                    self.functions.insert(ep, ep + 64);
                }
            }
        }
        // Scan for prologues.
        let max = if self.data.len() >= 3 { self.data.len() - 2 } else { 0 };
        for i in 0..max {
            if self.data[i] == 0x55 && self.data[i + 1] == 0x48 && self.data[i + 2] == 0x89 {
                let ea = i as u64;
                self.functions.entry(ea).or_insert(ea + 64);
                if self.functions.len() >= 512 {
                    break;
                }
            }
        }
    }

    fn get_name_at(&self, ea: u64) -> String {
        if let Some(n) = self.names.get(&ea) {
            return n.clone();
        }
        if self.functions.contains_key(&ea) {
            return format!("sub_{ea:x}");
        }
        String::new()
    }
}

/// Global "active" IDA database.
fn active_db() -> &'static Mutex<Option<IdaDb>> {
    static DB: OnceLock<Mutex<Option<IdaDb>>> = OnceLock::new();
    DB.get_or_init(|| Mutex::new(None))
}

fn with_db<F, T>(f: F) -> PyResult<T>
where
    F: FnOnce(&IdaDb) -> T,
{
    let guard = active_db().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref().map_or_else(|| Err(PyValueError::new_err(
            "no active database — call rustre.ida.open(path) first",
        )), |db| Ok(f(db)))
}

fn with_db_mut<F, T>(f: F) -> PyResult<T>
where
    F: FnOnce(&mut IdaDb) -> T,
{
    let mut guard = active_db().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_mut().map_or_else(|| Err(PyValueError::new_err("no active database")), |db| Ok(f(db)))
}

// ── Database open/close ───────────────────────────────────────────────────────

/// `set_active_database(path)` — Load a binary as the active IDA-compat DB.
#[pyfunction]
pub fn set_active_database(path: &str) -> PyResult<()> {
    let db = IdaDb::from_file(path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    *active_db().lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(db);
    Ok(())
}

/// Convenience alias used in many IDA scripts: `open_database(path)`.
#[pyfunction]
pub fn open_database(path: &str) -> PyResult<()> {
    set_active_database(path)
}

/// Return the file path of the currently active database, or `None` if no
/// database has been opened yet.  Uses the `path` field stored in `IdaDb`.
#[pyfunction]
pub fn get_database_path() -> Option<String> {
    active_db()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|db| db.path.clone())
}

// ── idc namespace ─────────────────────────────────────────────────────────────

/// `idc.get_name(ea) → str`
#[pyfunction]
pub fn idc_get_name(ea: u64) -> PyResult<String> {
    with_db(|db| db.get_name_at(ea))
}

/// `idc.set_name(ea, name) → bool`
#[pyfunction]
pub fn idc_set_name(ea: u64, name: String) -> PyResult<bool> {
    with_db_mut(|db| {
        db.names.insert(ea, name);
        true
    })
}

/// `idc.get_operand_value(ea, n) → int`  (stub — returns 0 for n>0, byte at ea for n=0)
#[pyfunction]
pub fn idc_get_operand_value(ea: u64, n: usize) -> PyResult<i64> {
    with_db(|db| {
        if n == 0 {
            i64::from(db.read_byte(ea))
        } else {
            0
        }
    })
}

/// `idc.create_insn(ea) → int`  (stub — returns byte count of stub disasm)
#[pyfunction]
pub fn idc_create_insn(ea: u64) -> PyResult<usize> {
    with_db(|db| {
        let b = db.read_byte(ea);
        match b {
            0xe8 | 0xe9 => 5,
            0x83 | 0x74 | 0x75 => 3,
            0x48 | 0x89 | 0x8b => 2,
            _ => 1,
        }
    })
}

/// `idc.op_plain_offset(ea, n, base)` — no-op stub, returns True.
#[pyfunction]
#[must_use] 
pub const fn idc_op_plain_offset(_ea: u64, _n: usize, _base: u64) -> bool {
    true
}

/// `idc.get_wide_byte(ea) → int`
#[pyfunction]
pub fn idc_get_wide_byte(ea: u64) -> PyResult<u8> {
    with_db(|db| db.read_byte(ea))
}

/// `idc.get_wide_word(ea) → int`
#[pyfunction]
pub fn idc_get_wide_word(ea: u64) -> PyResult<u16> {
    with_db(|db| {
        let lo = u16::from(db.read_byte(ea));
        let hi = u16::from(db.read_byte(ea + 1));
        lo | (hi << 8)
    })
}

/// `idc.get_wide_dword(ea) → int`
#[pyfunction]
pub fn idc_get_wide_dword(ea: u64) -> PyResult<u32> {
    with_db(|db| {
        let bytes = db.read_bytes(ea, 4);
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

/// `idc.get_wide_qword(ea) → int`
#[pyfunction]
pub fn idc_get_wide_qword(ea: u64) -> PyResult<u64> {
    with_db(|db| {
        let bytes = db.read_bytes(ea, 8);
        u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
    })
}

/// `idc.set_cmt(ea, comment, repeatable) → bool`
#[pyfunction]
pub fn idc_set_cmt(ea: u64, comment: String, _repeatable: bool) -> PyResult<bool> {
    with_db_mut(|db| {
        db.comments.insert(ea, comment);
        true
    })
}

/// `idc.get_cmt(ea, repeatable) → str`
#[pyfunction]
pub fn idc_get_cmt(ea: u64, _repeatable: bool) -> PyResult<String> {
    with_db(|db| db.comments.get(&ea).cloned().unwrap_or_default())
}

/// `idc.find_binary(ea, flag, searchstr) → ea`
///
/// Searches for a hex pattern starting at `ea`.  Returns `idc.BADADDR` on failure.
#[pyfunction]
pub fn idc_find_binary(ea: u64, _flag: u32, searchstr: &str) -> PyResult<u64> {
    with_db(|db| {
        let pat: Vec<Option<u8>> = searchstr
            .split_whitespace()
            .map(|tok| {
                if tok == "??" || tok == "?" {
                    None
                } else {
                    u8::from_str_radix(tok, 16).ok()
                }
            })
            .collect();
        let plen = pat.len();
        let start = usize::try_from(ea).unwrap_or(0);
        if plen == 0 || start >= db.data.len() || db.data.len() < plen {
            return 0xFFFF_FFFF_FFFF_FFFFu64;
        }
        let end = db.data.len() - plen;
        for i in start..=end {
            if pat.iter().enumerate().all(|(j, &p)| {
                p.is_none_or(|b| b == db.read_byte(i as u64 + j as u64))
            }) {
                return i as u64;
            }
        }
        0xFFFF_FFFF_FFFF_FFFFu64
    })
}

// ── idaapi namespace ──────────────────────────────────────────────────────────

/// `idaapi.FUNCATTR_START` constant
pub const FUNCATTR_START: u32 = 0;
/// `idaapi.FUNCATTR_END` constant
pub const FUNCATTR_END: u32 = 4;

/// `idaapi.get_func(ea) → func_t | None`
///
/// Returns a dict with `start_ea`, `end_ea`, `name` keys.
///
/// # Panics
///
/// Panics if `PyO3` conversion fails for dict items.
#[pyfunction]
pub fn idaapi_get_func(py: Python<'_>, ea: u64) -> PyResult<PyObject> {
    with_db(|db| {
        // Find the function that contains ea.
        let found = db.functions.iter().find(|&(&start, &end)| {
            ea >= start && ea < end
        });
        match found {
            Some((&start, &end)) => {
                let d = pyo3::types::PyDict::new(py);
                let _ = d.set_item("start_ea", start);
                let _ = d.set_item("end_ea", end);
                let _ = d.set_item("name", db.get_name_at(start));
                d.into_pyobject(py).unwrap().into_any().unbind()
            }
            None => py.None(),
        }
    })
}

/// `idaapi.get_byte(ea) → int`
#[pyfunction]
pub fn idaapi_get_byte(ea: u64) -> PyResult<u8> {
    with_db(|db| db.read_byte(ea))
}

/// `idaapi.put_byte(ea, value)` — patch a byte.
#[pyfunction]
pub fn idaapi_put_byte(ea: u64, value: u8) -> PyResult<()> {
    with_db_mut(|db| db.write_byte(ea, value))
}

/// Stub `idaapi.FlowChart` — yields single `BasicBlock` covering the function.
#[pyclass(name = "FlowChart")]
pub struct PyFlowChart {
    pub start_ea: u64,
    pub end_ea: u64,
    pub current: usize,
}

#[pymethods]
impl PyFlowChart {
    #[new]
    pub fn new(func: &Bound<'_, PyAny>) -> PyResult<Self> {
        let start_ea: u64 = func.getattr("start_ea")?.extract()?;
        let end_ea: u64 = func.getattr("end_ea").map_or(start_ea + 64, |v| v.extract().unwrap_or(start_ea + 64));
        Ok(Self { start_ea, end_ea, current: 0 })
    }

    #[must_use] 
    pub const fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[must_use] 
    pub fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyBasicBlock> {
        if slf.current == 0 {
            slf.current += 1;
            Some(PyBasicBlock {
                start_ea: slf.start_ea,
                end_ea: slf.end_ea,
            })
        } else {
            None
        }
    }
}

/// Stub `idaapi.BasicBlock`.
#[pyclass(name = "BasicBlock")]
#[derive(Clone)]
pub struct PyBasicBlock {
    #[pyo3(get)]
    pub start_ea: u64,
    #[pyo3(get)]
    pub end_ea: u64,
}

#[pymethods]
impl PyBasicBlock {
    #[must_use] 
    pub fn __repr__(&self) -> String {
        format!("<BasicBlock {:#x}..{:#x}>", self.start_ea, self.end_ea)
    }
}

// ── idautils namespace ────────────────────────────────────────────────────────

/// `idautils.Functions(start=0, end=MAXADDR) → iter[ea]`
///
/// # Panics
///
/// Panics if `PyO3` list construction fails.
#[pyfunction]
#[pyo3(signature = (start=None, end=None))]
pub fn idautils_Functions(py: Python<'_>, start: Option<u64>, end: Option<u64>) -> PyResult<PyObject> {
    let lo = start.unwrap_or(0);
    let hi = end.unwrap_or(u64::MAX);
    with_db(|db| {
        let mut addrs: Vec<u64> = db
            .functions
            .keys()
            .copied()
            .filter(|&a| a >= lo && a < hi)
            .collect();
        addrs.sort_unstable();
        let list = PyList::new(py, &addrs).unwrap();
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `idautils.Names() → iter[(ea, name)]`
///
/// # Panics
///
/// Panics if `PyO3` conversion fails.
#[pyfunction]
pub fn idautils_Names(py: Python<'_>) -> PyResult<PyObject> {
    with_db(|db| {
        let mut pairs: Vec<(u64, String)> = db.names.iter().map(|(&a, n)| (a, n.clone())).collect();
        // Also include auto-detected function names.
        for &a in db.functions.keys() {
            if !db.names.contains_key(&a) {
                pairs.push((a, db.get_name_at(a)));
            }
        }
        pairs.sort_by_key(|(a, _)| *a);
        let list = PyList::empty(py);
        for (ea, name) in pairs {
            let tup = pyo3::types::PyTuple::new(py, [ea.into_pyobject(py).unwrap().into_any(),
                name.into_pyobject(py).unwrap().into_any()])
                .unwrap();
            let _ = list.append(tup);
        }
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `idautils.CodeRefsTo(ea, flow) → iter[ea]`
///
/// # Panics
///
/// Panics if `PyO3` list construction fails.
#[pyfunction]
pub fn idautils_CodeRefsTo(py: Python<'_>, ea: u64, _flow: bool) -> PyResult<PyObject> {
    with_db(|db| {
        let mut refs = Vec::new();
        if db.data.len() >= 5 {
            for i in 0..db.data.len() - 4 {
                let iu64 = u64::try_from(i).unwrap_or(u64::MAX);
                if db.read_byte(iu64) == 0xe8 {
                    let rel = i32::from_le_bytes([
                        db.read_byte(iu64 + 1),
                        db.read_byte(iu64 + 2),
                        db.read_byte(iu64 + 3),
                        db.read_byte(iu64 + 4),
                    ]);
                    let dest = (i64::try_from(i).unwrap_or(0) + 5 + i64::from(rel)).cast_unsigned();
                    if dest == ea {
                        refs.push(iu64);
                    }
                }
            }
        }
        let list = PyList::new(py, &refs).unwrap();
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `idautils.DataRefsTo(ea) → iter[ea]`  (stub — empty)
#[pyfunction]
#[must_use] 
pub fn idautils_DataRefsTo(py: Python<'_>, _ea: u64) -> PyObject {
    PyList::empty(py).into()
}

/// `idautils.XrefsTo(ea, flags=0) → iter[xref]`
///
/// Each xref object has attributes `frm` (from address) and `type` (integer).
///
/// # Panics
///
/// Panics if `PyO3` list construction fails.
#[pyfunction]
#[pyo3(signature = (ea, _flags=None))]
pub fn idautils_XrefsTo(py: Python<'_>, ea: u64, _flags: Option<u32>) -> PyResult<PyObject> {
    with_db(|db| {
        let mut refs = Vec::new();
        if db.data.len() >= 5 {
            for i in 0..db.data.len() - 4 {
                let iu64 = u64::try_from(i).unwrap_or(u64::MAX);
                if db.read_byte(iu64) == 0xe8 {
                    let rel = i32::from_le_bytes([
                        db.read_byte(iu64 + 1),
                        db.read_byte(iu64 + 2),
                        db.read_byte(iu64 + 3),
                        db.read_byte(iu64 + 4),
                    ]);
                    let dest = (i64::try_from(i).unwrap_or(0) + 5 + i64::from(rel)).cast_unsigned();
                    if dest == ea {
                        refs.push(iu64);
                    }
                }
            }
        }
        let list = PyList::empty(py);
        for frm in refs {
            let d = pyo3::types::PyDict::new(py);
            let _ = d.set_item("frm", frm);
            let _ = d.set_item("type", 17u32); // fl_CN = call near
            let _ = list.append(d);
        }
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `idautils.XrefsFrom(ea, flags=0) → iter[xref]`
///
/// # Panics
///
/// Panics if `PyO3` list construction fails.
#[pyfunction]
#[pyo3(signature = (ea, _flags=None))]
pub fn idautils_XrefsFrom(py: Python<'_>, ea: u64, _flags: Option<u32>) -> PyResult<PyObject> {
    with_db(|db| {
        let start = usize::try_from(ea).unwrap_or(0);
        let end = (start + 256).min(if db.data.len() >= 5 { db.data.len() - 4 } else { 0 });
        let list = PyList::empty(py);
        for i in start..end {
            let iu64 = u64::try_from(i).unwrap_or(u64::MAX);
            if db.read_byte(iu64) == 0xe8 {
                let rel = i32::from_le_bytes([
                    db.read_byte(iu64 + 1),
                    db.read_byte(iu64 + 2),
                    db.read_byte(iu64 + 3),
                    db.read_byte(iu64 + 4),
                ]);
                let dest = (i64::try_from(i).unwrap_or(0) + 5 + i64::from(rel)).cast_unsigned();
                let d = pyo3::types::PyDict::new(py);
                let _ = d.set_item("to", dest);
                let _ = d.set_item("type", 17u32);
                let _ = list.append(d);
            }
        }
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

// ── ida_bytes namespace ───────────────────────────────────────────────────────

/// `ida_bytes.get_bytes(ea, size) → bytes`
///
/// # Panics
///
/// Panics if `PyO3` conversion fails.
#[pyfunction]
pub fn ida_bytes_get_bytes(py: Python<'_>, ea: u64, size: usize) -> PyResult<PyObject> {
    with_db(|db| {
        let bytes = db.read_bytes(ea, size);
        bytes.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `ida_bytes.patch_bytes(ea, data: bytes)`
#[pyfunction]
pub fn ida_bytes_patch_bytes(ea: u64, data: &[u8]) -> PyResult<()> {
    with_db_mut(|db| {
        for (i, b) in data.iter().enumerate() {
            db.write_byte(ea + i as u64, *b);
        }
    })
}

/// `ida_bytes.get_original_byte(ea) → int`  (returns unpatched data byte)
///
/// # Panics
///
/// Panics if `ea` exceeds `usize::MAX` (only on 32-bit targets).
#[pyfunction]
pub fn ida_bytes_get_original_byte(ea: u64) -> PyResult<u8> {
    with_db(|db| db.data.get(usize::try_from(ea).unwrap_or(usize::MAX)).copied().unwrap_or(0xFF))
}

// ── ida_segment namespace ─────────────────────────────────────────────────────

/// `ida_segment.Segments() → iter[ea]`  (start address of each segment)
///
/// # Panics
///
/// Panics if `PyO3` list construction fails.
#[pyfunction]
pub fn ida_segment_Segments(py: Python<'_>) -> PyResult<PyObject> {
    with_db(|db| {
        // Return synthetic segment start addresses based on file format.
        let starts: Vec<u64> = if db.data.starts_with(b"MZ") {
            vec![0x1000, 0x5000, 0x6000]
        } else if db.data.starts_with(b"\x7fELF") {
            vec![0x0, 0x1000]
        } else {
            vec![0x0]
        };
        let list = PyList::new(py, &starts).unwrap();
        list.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `ida_segment.getseg(ea) → segment_t | None`
///
/// # Panics
///
/// Panics if `PyO3` dict construction fails.
#[pyfunction]
pub fn ida_segment_getseg(py: Python<'_>, ea: u64) -> PyResult<PyObject> {
    with_db(|_db| {
        let d = pyo3::types::PyDict::new(py);
        let _ = d.set_item("start_ea", ea & !0xfff_u64);
        let _ = d.set_item("end_ea", (ea & !0xfff_u64) + 0x1000u64);
        let name = if ea < 0x5000 { ".text" } else { ".data" };
        let _ = d.set_item("name", name);
        d.into_pyobject(py).unwrap().into_any().unbind()
    })
}

/// `ida_segment.get_segm_name(segm) → str`
#[pyfunction]
pub fn ida_segment_get_segm_name(segm: &Bound<'_, PyAny>) -> PyResult<String> {
    segm.getattr("name")
        .and_then(|v| v.extract::<String>())
        .or(Ok("?".into()))
}

// ── Module registration ───────────────────────────────────────────────────────

/// Register the `rustre.ida` submodule and all IDA-compat submodules.
pub fn register_ida_compat_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let ida = PyModule::new(py, "ida")?;

    // Top-level DB functions.
    ida.add_function(wrap_pyfunction!(set_active_database, &ida)?)?;
    ida.add_function(wrap_pyfunction!(open_database, &ida)?)?;
    ida.add_function(wrap_pyfunction!(get_database_path, &ida)?)?;

    // idc submodule.
    let idc = PyModule::new(py, "idc")?;
    idc.add_function(wrap_pyfunction!(idc_get_name, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_set_name, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_operand_value, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_create_insn, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_op_plain_offset, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_wide_byte, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_wide_word, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_wide_dword, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_wide_qword, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_set_cmt, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_get_cmt, &idc)?)?;
    idc.add_function(wrap_pyfunction!(idc_find_binary, &idc)?)?;
    idc.add("BADADDR", 0xFFFF_FFFF_FFFF_FFFFu64)?;
    idc.add("SEARCH_DOWN", 1u32)?;
    idc.add("SEARCH_CASE", 4u32)?;
    idc.add("SEARCH_UP", 2u32)?;
    ida.add_submodule(&idc)?;

    // idaapi submodule.
    let idaapi = PyModule::new(py, "idaapi")?;
    idaapi.add_function(wrap_pyfunction!(idaapi_get_func, &idaapi)?)?;
    idaapi.add_function(wrap_pyfunction!(idaapi_get_byte, &idaapi)?)?;
    idaapi.add_function(wrap_pyfunction!(idaapi_put_byte, &idaapi)?)?;
    idaapi.add_class::<PyFlowChart>()?;
    idaapi.add_class::<PyBasicBlock>()?;
    idaapi.add("FUNCATTR_START", FUNCATTR_START)?;
    idaapi.add("FUNCATTR_END", FUNCATTR_END)?;
    idaapi.add("BADADDR", 0xFFFF_FFFF_FFFF_FFFFu64)?;
    ida.add_submodule(&idaapi)?;

    // idautils submodule.
    let idautils = PyModule::new(py, "idautils")?;
    idautils.add_function(wrap_pyfunction!(idautils_Functions, &idautils)?)?;
    idautils.add_function(wrap_pyfunction!(idautils_Names, &idautils)?)?;
    idautils.add_function(wrap_pyfunction!(idautils_CodeRefsTo, &idautils)?)?;
    idautils.add_function(wrap_pyfunction!(idautils_DataRefsTo, &idautils)?)?;
    idautils.add_function(wrap_pyfunction!(idautils_XrefsTo, &idautils)?)?;
    idautils.add_function(wrap_pyfunction!(idautils_XrefsFrom, &idautils)?)?;
    ida.add_submodule(&idautils)?;

    // ida_bytes submodule.
    let ida_bytes = PyModule::new(py, "ida_bytes")?;
    ida_bytes.add_function(wrap_pyfunction!(ida_bytes_get_bytes, &ida_bytes)?)?;
    ida_bytes.add_function(wrap_pyfunction!(ida_bytes_patch_bytes, &ida_bytes)?)?;
    ida_bytes.add_function(wrap_pyfunction!(ida_bytes_get_original_byte, &ida_bytes)?)?;
    ida.add_submodule(&ida_bytes)?;

    // ida_segment submodule.
    let ida_segment = PyModule::new(py, "ida_segment")?;
    ida_segment.add_function(wrap_pyfunction!(ida_segment_Segments, &ida_segment)?)?;
    ida_segment.add_function(wrap_pyfunction!(ida_segment_getseg, &ida_segment)?)?;
    ida_segment.add_function(wrap_pyfunction!(ida_segment_get_segm_name, &ida_segment)?)?;
    ida.add_submodule(&ida_segment)?;

    parent.add_submodule(&ida)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    /// Serializes all tests in this module so that the process-global
    /// `active_db()` singleton is not mutated concurrently. Each test calls
    /// `lock_tests()` first; the returned guard is held for the duration of
    /// the test, forcing strictly sequential execution regardless of Cargo's
    /// default multi-threaded test harness.
    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_tests() -> MutexGuard<'static, ()> {
        // Recover from poisoning so a panicking test does not cascade into
        // every subsequent test failing with PoisonError.
        test_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn make_test_db(data: Vec<u8>) {
        let db = IdaDb {
            data,
            path: "test".into(),
            ..Default::default()
        };
        // Same poison recovery as production paths (with_db / with_db_mut).
        let mut guard = active_db()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *guard = Some(db);
    }

    #[test]
    fn test_idc_get_name_default() {
        let _g = lock_tests();
        make_test_db(vec![0u8; 64]);
        // No name set, no function — returns empty string.
        let result = idc_get_name(0x1234).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_idc_set_get_name() {
        let _g = lock_tests();
        make_test_db(vec![0u8; 64]);
        idc_set_name(0x1000, "main".into()).unwrap();
        assert_eq!(idc_get_name(0x1000).unwrap(), "main");
    }

    #[test]
    fn test_idc_get_set_cmt() {
        let _g = lock_tests();
        make_test_db(vec![0u8; 64]);
        idc_set_cmt(0x0, "test comment".into(), false).unwrap();
        assert_eq!(idc_get_cmt(0x0, false).unwrap(), "test comment");
    }

    #[test]
    fn test_idc_read_bytes() {
        let _g = lock_tests();
        make_test_db(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(idc_get_wide_byte(0).unwrap(), 0xde);
        assert_eq!(idc_get_wide_word(0).unwrap(), 0xadde);
        assert_eq!(idc_get_wide_dword(0).unwrap(), 0xefbe_adde);
    }

    #[test]
    fn test_idaapi_get_byte_patch() {
        let _g = lock_tests();
        make_test_db(vec![0x90; 64]);
        idaapi_put_byte(0, 0xcc).unwrap();
        assert_eq!(idaapi_get_byte(0).unwrap(), 0xcc);
        // Original data unchanged.
        assert_eq!(
            with_db(|db| db.data[0]).unwrap(),
            0x90
        );
    }

    #[test]
    fn test_idc_find_binary_found() {
        let _g = lock_tests();
        make_test_db(vec![0x00, 0x48, 0x89, 0xc3, 0x00]);
        let ea = idc_find_binary(0, 0, "48 89 c3").unwrap();
        assert_eq!(ea, 1);
    }

    #[test]
    fn test_idc_find_binary_not_found() {
        let _g = lock_tests();
        make_test_db(vec![0x00; 32]);
        let ea = idc_find_binary(0, 0, "ff ff ff").unwrap();
        assert_eq!(ea, 0xFFFF_FFFF_FFFF_FFFFu64);
    }

    #[test]
    fn test_auto_detect_functions_prologue() {
        let mut data = vec![0u8; 128];
        data[8] = 0x55;
        data[9] = 0x48;
        data[10] = 0x89;
        let mut db = IdaDb {
            data,
            path: "t".into(),
            ..Default::default()
        };
        db.auto_detect_functions();
        assert!(db.functions.contains_key(&8));
    }
}
