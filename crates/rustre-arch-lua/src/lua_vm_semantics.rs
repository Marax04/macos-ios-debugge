//! Complete Lua VM semantic model.
//!
//! Provides:
//! - [`LuaValue`] — runtime value representation
//! - [`LuaTable`] — table with array and hash parts, metamethods
//! - [`LuaMetatable`] — metamethod dispatch
//! - [`GcSemantics`] — garbage collection model
//! - [`UpvalueClosing`] — upvalue closing semantics
//! - [`YieldResume`] — coroutine yield/resume semantics
//! - [`LuaVmSemantics`] — top-level VM facade

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// LuaValue
// ---------------------------------------------------------------------------

/// A Lua runtime value.
#[derive(Debug, Clone, PartialEq)]
pub enum LuaValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    /// Table reference (index into a table arena for simplicity).
    Table(usize),
    /// Function reference.
    Function(usize),
    /// Userdata opaque handle.
    Userdata(usize),
    /// Thread (coroutine) reference.
    Thread(usize),
}

impl LuaValue {
    /// Return the Lua type name string.
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Boolean(_) => "boolean",
            Self::Integer(_) | Self::Float(_) => "number",
            Self::String(_) => "string",
            Self::Table(_) => "table",
            Self::Function(_) => "function",
            Self::Userdata(_) => "userdata",
            Self::Thread(_) => "thread",
        }
    }

    /// Lua truthiness: only `nil` and `false` are falsy.
    #[must_use] 
    pub const fn is_truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Boolean(false))
    }

    /// `true` if this is a numeric type.
    #[must_use] 
    pub const fn is_number(&self) -> bool {
        matches!(self, Self::Integer(_) | Self::Float(_))
    }

    /// Try to convert to f64 (for arithmetic).
    #[must_use] 
    pub fn to_f64(&self) -> Option<f64> {
        match self {
            Self::Integer(n) => Some(crate::lua_int_to_f64(*n)),
            Self::Float(f) => Some(*f),
            Self::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    /// Try to convert to i64 (integer coercion).
    #[must_use] 
    pub fn to_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            Self::Float(f) => crate::f64_to_exact_i64(*f),
            Self::String(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    /// Lua `#` length operator.
    #[must_use] 
    pub fn length(&self) -> Option<i64> {
        match self {
            Self::String(s) => i64::try_from(s.len()).ok(),
            _ => None,
        }
    }
}

impl std::fmt::Display for LuaValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Table(id) => write!(f, "table: 0x{id:x}"),
            Self::Function(id) => write!(f, "function: 0x{id:x}"),
            Self::Userdata(id) => write!(f, "userdata: 0x{id:x}"),
            Self::Thread(id) => write!(f, "thread: 0x{id:x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LuaTable
// ---------------------------------------------------------------------------

/// A Lua table (both array and hash parts).
#[derive(Debug, Clone)]
pub struct LuaTable {
    /// Array part (1-based indices stored at 0-based).
    pub array: Vec<LuaValue>,
    /// Hash part.
    pub hash: HashMap<String, LuaValue>,
    /// Reference to a metatable (if any), stored as table ID.
    pub metatable: Option<usize>,
}

impl LuaTable {
    /// Create a new empty table.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            array: Vec::new(),
            hash: HashMap::new(),
            metatable: None,
        }
    }

    /// Create with pre-allocated capacity.
    #[must_use] 
    pub fn with_capacity(array_hint: usize, hash_hint: usize) -> Self {
        Self {
            array: Vec::with_capacity(array_hint),
            hash: HashMap::with_capacity(hash_hint),
            metatable: None,
        }
    }

    /// Get a value by integer key (1-based).
    #[must_use] 
    pub fn rawgeti(&self, key: i64) -> &LuaValue {
        let Ok(idx) = usize::try_from(key - 1) else {
            return &LuaValue::Nil;
        };
        self.array.get(idx).unwrap_or(&LuaValue::Nil)
    }

    /// Maximum array index accepted by rawseti (prevents OOM on attacker-supplied keys).
    pub const MAX_ARRAY_KEY: i64 = 1 << 24; // 16 Mi entries ≈ 128 MiB of LuaValue

    /// Set a value by integer key (1-based).
    pub fn rawseti(&mut self, key: i64, value: LuaValue) {
        if (1..=Self::MAX_ARRAY_KEY).contains(&key) {
            let Ok(idx) = usize::try_from(key - 1) else { return };
            if idx >= self.array.len() {
                self.array.resize(idx + 1, LuaValue::Nil);
            }
            self.array[idx] = value;
        }
    }

    /// Get by string key.
    #[must_use] 
    pub fn rawget_str(&self, key: &str) -> &LuaValue {
        self.hash.get(key).unwrap_or(&LuaValue::Nil)
    }

    /// Set by string key.
    pub fn rawset_str(&mut self, key: String, value: LuaValue) {
        if value == LuaValue::Nil {
            self.hash.remove(&key);
        } else {
            self.hash.insert(key, value);
        }
    }

    /// Return the Lua-compatible length (#t).
    ///
    /// Follows the Lua 5.x definition: the length is any border.
    #[must_use] 
    pub fn length(&self) -> i64 {
        // Find last non-nil in array part
        let mut len = 0i64;
        for (i, v) in self.array.iter().enumerate() {
            if v != &LuaValue::Nil {
                len = i64::try_from(i + 1).unwrap_or(i64::MAX);
            }
        }
        len
    }

    /// `true` if the table has no entries.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.array.iter().all(|v| v == &LuaValue::Nil) && self.hash.is_empty()
    }

    /// Total number of non-nil entries.
    #[must_use] 
    pub fn count(&self) -> usize {
        let arr = self.array.iter().filter(|v| *v != &LuaValue::Nil).count();
        arr + self.hash.len()
    }
}

impl Default for LuaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LuaMetatable
// ---------------------------------------------------------------------------

/// Standard Lua metamethod event names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetaEvent {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Unm,
    Idiv,
    // Bitwise
    Band,
    Bor,
    Bxor,
    Bnot,
    Shl,
    Shr,
    // String
    Concat,
    Len,
    // Comparison
    Eq,
    Lt,
    Le,
    // Access
    Index,
    Newindex,
    Call,
    // GC
    Gc,
    // Misc
    Tostring,
    Name,
    // Coroutine
    Close,
}

impl MetaEvent {
    #[must_use] 
    pub const fn event_name(self) -> &'static str {
        match self {
            Self::Add => "__add",
            Self::Sub => "__sub",
            Self::Mul => "__mul",
            Self::Div => "__div",
            Self::Mod => "__mod",
            Self::Pow => "__pow",
            Self::Unm => "__unm",
            Self::Idiv => "__idiv",
            Self::Band => "__band",
            Self::Bor => "__bor",
            Self::Bxor => "__bxor",
            Self::Bnot => "__bnot",
            Self::Shl => "__shl",
            Self::Shr => "__shr",
            Self::Concat => "__concat",
            Self::Len => "__len",
            Self::Eq => "__eq",
            Self::Lt => "__lt",
            Self::Le => "__le",
            Self::Index => "__index",
            Self::Newindex => "__newindex",
            Self::Call => "__call",
            Self::Gc => "__gc",
            Self::Tostring => "__tostring",
            Self::Name => "__name",
            Self::Close => "__close",
        }
    }
}

/// A Lua metatable — maps metamethod events to handler function IDs.
#[derive(Debug, Clone, Default)]
pub struct LuaMetatable {
    handlers: HashMap<&'static str, usize>,
}

impl LuaMetatable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a metamethod handler.
    pub fn set(&mut self, event: MetaEvent, func_id: usize) {
        self.handlers.insert(event.event_name(), func_id);
    }

    /// Get the handler function ID for an event, if set.
    #[must_use] 
    pub fn get(&self, event: MetaEvent) -> Option<usize> {
        self.handlers.get(event.event_name()).copied()
    }

    /// `true` if this metatable has a handler for `event`.
    #[must_use] 
    pub fn has(&self, event: MetaEvent) -> bool {
        self.handlers.contains_key(event.event_name())
    }

    /// Number of metamethods set.
    #[must_use] 
    pub fn count(&self) -> usize {
        self.handlers.len()
    }
}

// ---------------------------------------------------------------------------
// GcSemantics
// ---------------------------------------------------------------------------

/// Garbage collection object colour (tri-colour mark-and-sweep).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcColor {
    /// Not yet visited.
    White,
    /// Currently being processed (reachable, children not yet scanned).
    Gray,
    /// Fully processed (reachable, all children scanned).
    Black,
}

/// GC object state.
#[derive(Debug, Clone)]
pub struct GcObject {
    pub id: usize,
    pub color: GcColor,
    pub size_bytes: usize,
    pub has_finalizer: bool,
}

impl GcObject {
    #[must_use] 
    pub const fn new(id: usize, size_bytes: usize) -> Self {
        Self {
            id,
            color: GcColor::White,
            size_bytes,
            has_finalizer: false,
        }
    }
}

/// Simplified GC state machine.
#[derive(Debug, Default)]
pub struct GcSemantics {
    objects: Vec<GcObject>,
    /// Threshold (bytes) before next GC cycle.
    pub threshold: usize,
    /// Accumulated allocation since last GC.
    pub allocated: usize,
}

impl GcSemantics {
    #[must_use] 
    pub const fn new(threshold: usize) -> Self {
        Self {
            objects: Vec::new(),
            threshold,
            allocated: 0,
        }
    }

    /// Allocate a new GC-managed object.
    pub fn alloc(&mut self, size_bytes: usize) -> usize {
        let id = self.objects.len();
        self.objects.push(GcObject::new(id, size_bytes));
        self.allocated += size_bytes;
        id
    }

    /// Mark an object as reachable (gray → black).
    pub fn mark(&mut self, id: usize) {
        if let Some(obj) = self.objects.get_mut(id) {
            obj.color = GcColor::Gray;
        }
    }

    /// Finish marking — transition gray → black.
    pub fn mark_done(&mut self, id: usize) {
        if let Some(obj) = self.objects.get_mut(id) && obj.color == GcColor::Gray {
            obj.color = GcColor::Black;
        }
    }

    /// Sweep: collect all white (unreachable) objects.
    /// Returns the number of bytes freed.
    pub fn sweep(&mut self) -> usize {
        let mut freed = 0;
        for obj in &mut self.objects {
            if obj.color == GcColor::White {
                freed += obj.size_bytes;
            } else {
                // Reset black → white for next cycle.
                obj.color = GcColor::White;
            }
        }
        self.allocated = self.allocated.saturating_sub(freed);
        freed
    }

    /// `true` if GC should trigger.
    #[must_use] 
    pub const fn should_collect(&self) -> bool {
        self.allocated >= self.threshold
    }

    /// Number of live objects.
    #[must_use] 
    pub fn live_count(&self) -> usize {
        self.objects
            .iter()
            .filter(|o| o.color != GcColor::White)
            .count()
    }

    /// Total allocated bytes tracked.
    #[must_use] 
    pub const fn allocated_bytes(&self) -> usize {
        self.allocated
    }
}

// ---------------------------------------------------------------------------
// UpvalueClosing
// ---------------------------------------------------------------------------

/// State of an upvalue.
#[derive(Debug, Clone, PartialEq)]
pub enum UpvalueState {
    /// Open: points to a stack slot.
    Open { stack_level: usize },
    /// Closed: value has been captured.
    Closed(LuaValue),
}

/// A single upvalue.
#[derive(Debug, Clone)]
pub struct Upvalue {
    pub id: usize,
    pub state: UpvalueState,
}

impl Upvalue {
    /// Create an open upvalue at `stack_level`.
    #[must_use] 
    pub const fn open(id: usize, stack_level: usize) -> Self {
        Self {
            id,
            state: UpvalueState::Open { stack_level },
        }
    }

    /// `true` if this upvalue is open (stack-allocated).
    #[must_use] 
    pub const fn is_open(&self) -> bool {
        matches!(self.state, UpvalueState::Open { .. })
    }

    /// Close this upvalue by capturing the given value.
    pub fn close(&mut self, value: LuaValue) {
        self.state = UpvalueState::Closed(value);
    }

    /// Read the upvalue (for closed upvalues).
    #[must_use] 
    pub const fn get(&self) -> Option<&LuaValue> {
        match &self.state {
            UpvalueState::Closed(v) => Some(v),
            UpvalueState::Open { .. } => None,
        }
    }
}

/// Manages upvalue closing when a scope exits.
#[derive(Debug, Default)]
pub struct UpvalueClosing {
    upvalues: Vec<Upvalue>,
    next_id: usize,
}

impl UpvalueClosing {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new open upvalue for `stack_level`.
    pub fn create_open(&mut self, stack_level: usize) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.upvalues.push(Upvalue::open(id, stack_level));
        id
    }

    /// Close all upvalues at or above `stack_level`, capturing their values.
    pub fn close_upvalues(&mut self, stack_level: usize, stack: &[LuaValue]) {
        for uv in &mut self.upvalues {
            if let UpvalueState::Open { stack_level: sl } = uv.state && sl >= stack_level {
                let val = stack.get(sl).cloned().unwrap_or(LuaValue::Nil);
                uv.close(val);
            }
        }
    }

    /// Get an upvalue by ID.
    #[must_use] 
    pub fn get(&self, id: usize) -> Option<&Upvalue> {
        self.upvalues.iter().find(|u| u.id == id)
    }

    /// Number of open upvalues.
    #[must_use] 
    pub fn open_count(&self) -> usize {
        self.upvalues.iter().filter(|u| u.is_open()).count()
    }

    /// Number of closed upvalues.
    #[must_use] 
    pub fn closed_count(&self) -> usize {
        self.upvalues.iter().filter(|u| !u.is_open()).count()
    }
}

// ---------------------------------------------------------------------------
// YieldResume — coroutine semantics
// ---------------------------------------------------------------------------

/// Coroutine status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoroutineStatus {
    /// Running on the current thread.
    Running,
    /// Suspended (yielded).
    Suspended,
    /// Completed normally.
    Dead,
    /// Completed with an error.
    Error,
    /// Normal (waiting for a sub-coroutine to resume).
    Normal,
}

impl std::fmt::Display for CoroutineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Dead | Self::Error => "dead",
            // Lua reports errors as dead
            Self::Normal => "normal",
        };
        write!(f, "{s}")
    }
}

/// A Lua coroutine state.
#[derive(Debug, Clone)]
pub struct Coroutine {
    pub id: usize,
    pub status: CoroutineStatus,
    /// Values yielded or returned.
    pub pending_values: Vec<LuaValue>,
    /// Saved program counter.
    pub saved_pc: usize,
}

impl Coroutine {
    #[must_use] 
    pub const fn new(id: usize) -> Self {
        Self {
            id,
            status: CoroutineStatus::Suspended,
            pending_values: Vec::new(),
            saved_pc: 0,
        }
    }

    /// Yield from the coroutine, capturing `values`.
    pub fn do_yield(&mut self, values: Vec<LuaValue>) {
        self.pending_values = values;
        self.status = CoroutineStatus::Suspended;
    }

    /// Resume the coroutine with `args`.  Returns true if successful.
    pub fn do_resume(&mut self, args: Vec<LuaValue>) -> bool {
        if self.status != CoroutineStatus::Suspended {
            return false;
        }
        self.pending_values = args;
        self.status = CoroutineStatus::Running;
        true
    }

    /// Mark the coroutine as dead.
    pub fn finish(&mut self, return_values: Vec<LuaValue>) {
        self.pending_values = return_values;
        self.status = CoroutineStatus::Dead;
    }

    /// `true` if the coroutine can be resumed.
    #[must_use] 
    pub fn can_resume(&self) -> bool {
        self.status == CoroutineStatus::Suspended
    }
}

/// Manages multiple coroutines.
#[derive(Debug, Default)]
pub struct YieldResume {
    coroutines: Vec<Coroutine>,
    current: Option<usize>,
}

impl YieldResume {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new coroutine.  Returns its ID.
    pub fn create(&mut self) -> usize {
        let id = self.coroutines.len();
        self.coroutines.push(Coroutine::new(id));
        id
    }

    /// Resume coroutine `id` with `args`.
    pub fn resume(&mut self, id: usize, args: Vec<LuaValue>) -> bool {
        if let Some(co) = self.coroutines.get_mut(id) && co.do_resume(args) {
            self.current = Some(id);
            return true;
        }
        false
    }

    /// Yield from the currently running coroutine.
    pub fn yield_current(&mut self, values: Vec<LuaValue>) -> bool {
        if let Some(id) = self.current && let Some(co) = self.coroutines.get_mut(id) {
            co.do_yield(values);
            self.current = None;
            return true;
        }
        false
    }

    /// Get a coroutine by ID.
    #[must_use] 
    pub fn get(&self, id: usize) -> Option<&Coroutine> {
        self.coroutines.get(id)
    }

    /// Status of coroutine `id`.
    #[must_use] 
    pub fn status(&self, id: usize) -> CoroutineStatus {
        self.coroutines
            .get(id)
            .map_or(CoroutineStatus::Dead, |c| c.status)
    }

    /// Number of coroutines.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.coroutines.len()
    }
}

// ---------------------------------------------------------------------------
// LuaVmSemantics — top-level facade
// ---------------------------------------------------------------------------

/// Top-level Lua VM semantic model.
#[derive(Debug, Default)]
pub struct LuaVmSemantics {
    pub gc: GcSemantics,
    pub upvalues: UpvalueClosing,
    pub coroutines: YieldResume,
}

impl LuaVmSemantics {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            gc: GcSemantics::new(1024 * 1024),
            upvalues: UpvalueClosing::new(),
            coroutines: YieldResume::new(),
        }
    }

    /// Allocate a table in the GC arena.
    pub fn alloc_table(&mut self) -> usize {
        self.gc.alloc(64)
    }

    /// Allocate a function closure.
    pub fn alloc_closure(&mut self, upvalue_count: usize) -> usize {
        self.gc.alloc(32 + upvalue_count * 8)
    }

    /// Create an open upvalue for a stack slot.
    pub fn open_upvalue(&mut self, stack_level: usize) -> usize {
        self.upvalues.create_open(stack_level)
    }

    /// Close upvalues when a block exits.
    pub fn close_scope(&mut self, level: usize, stack: &[LuaValue]) {
        self.upvalues.close_upvalues(level, stack);
    }

    /// Create a new coroutine.
    pub fn new_coroutine(&mut self) -> usize {
        self.coroutines.create()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. LuaValue type names ──────────────────────────────────────────────
    #[test]
    fn test_type_name() {
        assert_eq!(LuaValue::Nil.type_name(), "nil");
        assert_eq!(LuaValue::Boolean(true).type_name(), "boolean");
        assert_eq!(LuaValue::Integer(42).type_name(), "number");
        assert_eq!(LuaValue::Float(2.5_f64).type_name(), "number");
        assert_eq!(LuaValue::String("x".into()).type_name(), "string");
        assert_eq!(LuaValue::Table(0).type_name(), "table");
        assert_eq!(LuaValue::Function(0).type_name(), "function");
    }

    #[test]
    fn test_is_truthy() {
        assert!(LuaValue::Integer(0).is_truthy()); // 0 is truthy in Lua!
        assert!(LuaValue::Boolean(true).is_truthy());
        assert!(!LuaValue::Nil.is_truthy());
        assert!(!LuaValue::Boolean(false).is_truthy());
        assert!(LuaValue::String(String::new()).is_truthy()); // empty string is truthy
    }

    #[test]
    fn test_to_f64() {
        assert_eq!(LuaValue::Integer(7).to_f64(), Some(7.0));
        assert_eq!(LuaValue::Float(2.5).to_f64(), Some(2.5));
        assert!(LuaValue::Nil.to_f64().is_none());
    }

    #[test]
    fn test_to_integer() {
        assert_eq!(LuaValue::Integer(5).to_integer(), Some(5));
        assert_eq!(LuaValue::Float(3.0).to_integer(), Some(3));
        assert!(LuaValue::Float(3.5).to_integer().is_none());
    }

    #[test]
    fn test_string_length() {
        assert_eq!(LuaValue::String("hello".into()).length(), Some(5));
        assert!(LuaValue::Integer(1).length().is_none());
    }

    #[test]
    fn test_lua_value_display() {
        assert_eq!(format!("{}", LuaValue::Nil), "nil");
        assert_eq!(format!("{}", LuaValue::Boolean(false)), "false");
        assert_eq!(format!("{}", LuaValue::Integer(42)), "42");
    }

    // ── 2. LuaTable ─────────────────────────────────────────────────────────
    #[test]
    fn test_table_rawgeti_rawseti() {
        let mut t = LuaTable::new();
        t.rawseti(1, LuaValue::Integer(10));
        t.rawseti(3, LuaValue::Integer(30));
        assert_eq!(t.rawgeti(1), &LuaValue::Integer(10));
        assert_eq!(t.rawgeti(2), &LuaValue::Nil);
        assert_eq!(t.rawgeti(3), &LuaValue::Integer(30));
    }

    #[test]
    fn test_table_rawget_rawset_str() {
        let mut t = LuaTable::new();
        t.rawset_str("name".into(), LuaValue::String("lua".into()));
        assert_eq!(t.rawget_str("name"), &LuaValue::String("lua".into()));
        // Setting nil removes the key
        t.rawset_str("name".into(), LuaValue::Nil);
        assert_eq!(t.rawget_str("name"), &LuaValue::Nil);
    }

    #[test]
    fn test_table_length() {
        let mut t = LuaTable::new();
        assert_eq!(t.length(), 0);
        t.rawseti(1, LuaValue::Integer(1));
        t.rawseti(2, LuaValue::Integer(2));
        assert_eq!(t.length(), 2);
    }

    #[test]
    fn test_table_is_empty() {
        let t = LuaTable::new();
        assert!(t.is_empty());
    }

    #[test]
    fn test_table_count() {
        let mut t = LuaTable::new();
        t.rawseti(1, LuaValue::Integer(1));
        t.rawset_str("k".into(), LuaValue::Boolean(true));
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn test_table_with_capacity() {
        let t = LuaTable::with_capacity(8, 4);
        assert!(t.is_empty());
    }

    // ── 3. LuaMetatable ─────────────────────────────────────────────────────
    #[test]
    fn test_metatable_set_get() {
        let mut mt = LuaMetatable::new();
        mt.set(MetaEvent::Add, 42);
        assert_eq!(mt.get(MetaEvent::Add), Some(42));
        assert_eq!(mt.get(MetaEvent::Sub), None);
    }

    #[test]
    fn test_metatable_has() {
        let mut mt = LuaMetatable::new();
        mt.set(MetaEvent::Index, 1);
        assert!(mt.has(MetaEvent::Index));
        assert!(!mt.has(MetaEvent::Call));
    }

    #[test]
    fn test_metatable_count() {
        let mut mt = LuaMetatable::new();
        mt.set(MetaEvent::Add, 1);
        mt.set(MetaEvent::Sub, 2);
        assert_eq!(mt.count(), 2);
    }

    #[test]
    fn test_meta_event_names() {
        assert_eq!(MetaEvent::Add.event_name(), "__add");
        assert_eq!(MetaEvent::Index.event_name(), "__index");
        assert_eq!(MetaEvent::Close.event_name(), "__close");
    }

    // ── 4. GcSemantics ──────────────────────────────────────────────────────
    #[test]
    fn test_gc_alloc() {
        let mut gc = GcSemantics::new(1024);
        let id1 = gc.alloc(32);
        let id2 = gc.alloc(64);
        assert_ne!(id1, id2);
        assert_eq!(gc.allocated_bytes(), 96);
    }

    #[test]
    fn test_gc_mark_sweep() {
        let mut gc = GcSemantics::new(1024);
        let id = gc.alloc(128);
        gc.mark(id);
        gc.mark_done(id);
        let freed = gc.sweep();
        assert_eq!(freed, 0); // black object was not freed
    }

    #[test]
    fn test_gc_sweep_frees_white() {
        let mut gc = GcSemantics::new(1024);
        gc.alloc(100);
        gc.alloc(200);
        let freed = gc.sweep(); // both are white → freed
        assert_eq!(freed, 300);
    }

    #[test]
    fn test_gc_should_collect() {
        let mut gc = GcSemantics::new(100);
        gc.alloc(50);
        assert!(!gc.should_collect());
        gc.alloc(60);
        assert!(gc.should_collect());
    }

    // ── 5. UpvalueClosing ────────────────────────────────────────────────────
    #[test]
    fn test_upvalue_open() {
        let mut uc = UpvalueClosing::new();
        let id = uc.create_open(3);
        let uv = uc.get(id).unwrap();
        assert!(uv.is_open());
    }

    #[test]
    fn test_upvalue_close() {
        let mut uc = UpvalueClosing::new();
        let id = uc.create_open(2);
        let stack = vec![LuaValue::Nil, LuaValue::Nil, LuaValue::Integer(42)];
        uc.close_upvalues(2, &stack);
        let uv = uc.get(id).unwrap();
        assert!(!uv.is_open());
        assert_eq!(uv.get(), Some(&LuaValue::Integer(42)));
    }

    #[test]
    fn test_upvalue_count() {
        let mut uc = UpvalueClosing::new();
        uc.create_open(0);
        uc.create_open(1);
        assert_eq!(uc.open_count(), 2);
        assert_eq!(uc.closed_count(), 0);
    }

    // ── 6. YieldResume ───────────────────────────────────────────────────────
    #[test]
    fn test_coroutine_create() {
        let mut yr = YieldResume::new();
        let id = yr.create();
        assert_eq!(yr.status(id), CoroutineStatus::Suspended);
    }

    #[test]
    fn test_coroutine_resume() {
        let mut yr = YieldResume::new();
        let id = yr.create();
        let ok = yr.resume(id, vec![LuaValue::Integer(1)]);
        assert!(ok);
        assert_eq!(yr.status(id), CoroutineStatus::Running);
    }

    #[test]
    fn test_coroutine_yield() {
        let mut yr = YieldResume::new();
        let id = yr.create();
        yr.resume(id, vec![]);
        yr.yield_current(vec![LuaValue::String("hi".into())]);
        assert_eq!(yr.status(id), CoroutineStatus::Suspended);
    }

    #[test]
    fn test_coroutine_dead_cannot_resume() {
        let mut yr = YieldResume::new();
        let id = yr.create();
        if let Some(co) = yr.coroutines.get_mut(id) {
            co.finish(vec![]);
        }
        assert!(!yr.resume(id, vec![]));
    }

    #[test]
    fn test_coroutine_status_display() {
        assert_eq!(format!("{}", CoroutineStatus::Suspended), "suspended");
        assert_eq!(format!("{}", CoroutineStatus::Dead), "dead");
        assert_eq!(format!("{}", CoroutineStatus::Running), "running");
    }

    #[test]
    fn test_coroutine_count() {
        let mut yr = YieldResume::new();
        yr.create();
        yr.create();
        assert_eq!(yr.count(), 2);
    }

    // ── 7. LuaVmSemantics ────────────────────────────────────────────────────
    #[test]
    fn test_vm_alloc_table() {
        let mut vm = LuaVmSemantics::new();
        let id = vm.alloc_table();
        let _ = id; // just no panic
    }

    #[test]
    fn test_vm_open_upvalue() {
        let mut vm = LuaVmSemantics::new();
        let id = vm.open_upvalue(0);
        let uv = vm.upvalues.get(id).unwrap();
        assert!(uv.is_open());
    }

    #[test]
    fn test_vm_new_coroutine() {
        let mut vm = LuaVmSemantics::new();
        let id = vm.new_coroutine();
        assert_eq!(vm.coroutines.status(id), CoroutineStatus::Suspended);
    }

    #[test]
    fn test_vm_close_scope() {
        let mut vm = LuaVmSemantics::new();
        let uv_id = vm.open_upvalue(1);
        let stack = vec![LuaValue::Nil, LuaValue::Float(2.71)];
        vm.close_scope(1, &stack);
        let uv = vm.upvalues.get(uv_id).unwrap();
        assert!(!uv.is_open());
    }

    // ── 8. Coroutine can_resume ───────────────────────────────────────────────
    #[test]
    fn test_coroutine_can_resume() {
        let co = Coroutine::new(0);
        assert!(co.can_resume());
        let mut co2 = Coroutine::new(1);
        co2.do_resume(vec![]);
        assert!(!co2.can_resume()); // now Running
    }

    // ── 9. LuaTable metatable field ──────────────────────────────────────────
    #[test]
    fn test_table_metatable_none() {
        let t = LuaTable::new();
        assert!(t.metatable.is_none());
    }

    // ── 10. GcColor transitions ───────────────────────────────────────────────
    #[test]
    fn test_gc_color_transitions() {
        let mut gc = GcSemantics::new(1024);
        let id = gc.alloc(16);
        assert_eq!(gc.objects[id].color, GcColor::White);
        gc.mark(id);
        assert_eq!(gc.objects[id].color, GcColor::Gray);
        gc.mark_done(id);
        assert_eq!(gc.objects[id].color, GcColor::Black);
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_lua_value_is_number() {
        assert!(LuaValue::Integer(1).is_number());
        assert!(LuaValue::Float(1.0).is_number());
        assert!(!LuaValue::String("1".into()).is_number());
        assert!(!LuaValue::Nil.is_number());
    }

    #[test]
    fn test_lua_string_to_f64() {
        let v = LuaValue::String("2.5".into());
        let f = v.to_f64().unwrap();
        assert!((f - 2.5_f64).abs() < 1e-9);
    }

    #[test]
    fn test_lua_string_to_integer() {
        let v = LuaValue::String("42".into());
        assert_eq!(v.to_integer(), Some(42));
    }

    #[test]
    fn test_table_large_array() {
        let mut t = LuaTable::new();
        for i in 1..=100i64 {
            t.rawseti(i, LuaValue::Integer(i));
        }
        assert_eq!(t.length(), 100);
        assert_eq!(t.count(), 100);
    }

    #[test]
    fn test_gc_live_count() {
        let mut gc = GcSemantics::new(4096);
        let id = gc.alloc(32);
        gc.mark(id);
        gc.mark_done(id);
        assert_eq!(gc.live_count(), 1);
    }

    #[test]
    fn test_upvalue_state_variants() {
        let uv_open = Upvalue::open(0, 3);
        assert!(matches!(
            uv_open.state,
            UpvalueState::Open { stack_level: 3 }
        ));
        let mut uv = Upvalue::open(1, 0);
        uv.close(LuaValue::Boolean(true));
        assert!(matches!(uv.state, UpvalueState::Closed(_)));
    }

    #[test]
    fn test_coroutine_finish() {
        let mut co = Coroutine::new(0);
        co.do_resume(vec![]);
        co.finish(vec![LuaValue::Integer(42)]);
        assert_eq!(co.status, CoroutineStatus::Dead);
        assert_eq!(co.pending_values[0], LuaValue::Integer(42));
    }

    #[test]
    fn test_coroutine_status_normal() {
        assert_eq!(format!("{}", CoroutineStatus::Normal), "normal");
    }

    #[test]
    fn test_metatable_all_events() {
        let events = [
            MetaEvent::Add,
            MetaEvent::Sub,
            MetaEvent::Mul,
            MetaEvent::Div,
            MetaEvent::Index,
            MetaEvent::Newindex,
            MetaEvent::Call,
            MetaEvent::Gc,
            MetaEvent::Tostring,
            MetaEvent::Close,
        ];
        for e in events {
            assert!(!e.event_name().is_empty());
        }
    }

    #[test]
    fn test_gc_semantics_new_zero_allocated() {
        let gc = GcSemantics::new(1024);
        assert_eq!(gc.allocated_bytes(), 0);
        assert!(!gc.should_collect());
    }

    #[test]
    fn test_vm_alloc_closure() {
        let mut vm = LuaVmSemantics::new();
        let id = vm.alloc_closure(3);
        let _ = id; // no panic
    }
}
