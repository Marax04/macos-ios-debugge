//! `cil_injector` — CIL code injection and instrumentation engine.
//!
//! Provides:
//! * [`CilInjector`] — top-level injector
//! * [`InjectionPoint`] — where to inject (before/after method entry, before return…)
//! * [`CodeSnippet`] — a reusable CIL instruction sequence
//! * [`HookInstaller`] — high-level hook installation
//! * [`ProxyMethod`] — generates a proxy/wrapper for an existing method
//! * [`InstrumentMethod`] — adds entry/exit logging/tracing to a method
//! * [`InjectReport`] — records what was injected

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use rustre_dotnet::{CilInstruction, CilOperand};

// ─── InjectionPoint ───────────────────────────────────────────────────────────

/// Specifies _where_ in a method body a code snippet should be inserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionPoint {
    /// Before the very first instruction.
    MethodEntry,
    /// Immediately before every `ret` instruction.
    BeforeReturn,
    /// Immediately after the instruction at the given CIL offset.
    AfterOffset(u32),
    /// Immediately before the instruction at the given CIL offset.
    BeforeOffset(u32),
    /// Replace the instruction at the given offset entirely.
    ReplaceOffset(u32),
    /// Prepend before every instruction whose opcode matches.
    BeforeOpcode(String),
    /// Append after every call to the specified method token.
    AfterCall(u32),
}

impl InjectionPoint {
    /// Returns a human-readable description of this injection point.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::MethodEntry => "method entry".to_string(),
            Self::BeforeReturn => "before return".to_string(),
            Self::AfterOffset(o) => format!("after 0x{o:04X}"),
            Self::BeforeOffset(o) => format!("before 0x{o:04X}"),
            Self::ReplaceOffset(o) => format!("replace 0x{o:04X}"),
            Self::BeforeOpcode(op) => format!("before {op}"),
            Self::AfterCall(t) => format!("after call to token 0x{t:08X}"),
        }
    }
}

// ─── CodeSnippet ──────────────────────────────────────────────────────────────

/// A named, reusable CIL instruction sequence.
#[derive(Debug, Clone)]
pub struct CodeSnippet {
    /// Name of this snippet, used for reporting.
    pub name: String,
    /// The CIL instructions.
    pub instructions: Vec<CilInstruction>,
    /// Estimated stack depth delta of this snippet.
    pub stack_delta: i32,
}

impl CodeSnippet {
    /// Create a snippet from a list of instructions.
    #[must_use]
    pub fn new(name: impl Into<String>, instructions: Vec<CilInstruction>) -> Self {
        Self {
            name: name.into(),
            stack_delta: 0,
            instructions,
        }
    }

    /// Create a `nop` pad of `count` instructions.
    #[must_use]
    pub fn nops(name: impl Into<String>, count: usize) -> Self {
        let instructions = (0..count)
            .map(|i| CilInstruction::simple(i as u32, "nop"))
            .collect();
        Self {
            name: name.into(),
            instructions,
            stack_delta: 0,
        }
    }

    /// Create a snippet that pushes an integer constant and pops it (pure side-effect guard).
    #[must_use]
    pub fn push_pop_const(name: impl Into<String>, value: i32) -> Self {
        Self {
            name: name.into(),
            instructions: vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4".into(),
                    operand: CilOperand::Int32(value),
                },
                CilInstruction::simple(5, "pop"),
            ],
            stack_delta: 0,
        }
    }

    /// Number of instructions in this snippet.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if this snippet has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ─── HookInstaller ────────────────────────────────────────────────────────────

/// Installs trampoline hooks at method entry or exit points.
#[derive(Debug, Clone, Default)]
pub struct HookInstaller {
    /// Registered hooks: `method_full_name → (point, snippet)`.
    hooks: Vec<(String, InjectionPoint, CodeSnippet)>,
}

impl HookInstaller {
    /// Create an empty hook installer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook on the given method at the given injection point.
    pub fn add_hook(
        &mut self,
        method: impl Into<String>,
        point: InjectionPoint,
        snippet: CodeSnippet,
    ) {
        self.hooks.push((method.into(), point, snippet));
    }

    /// Number of registered hooks.
    #[must_use]
    pub const fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    /// Returns `true` if a hook is registered for the given method.
    #[must_use]
    pub fn has_hook(&self, method: &str) -> bool {
        self.hooks.iter().any(|(m, _, _)| m == method)
    }

    /// List all hooked method names.
    #[must_use]
    pub fn hooked_methods(&self) -> Vec<&str> {
        self.hooks.iter().map(|(m, _, _)| m.as_str()).collect()
    }

    /// Apply all registered hooks to the given method's instruction list.
    ///
    /// # Errors
    /// Returns an error if an injection offset is not found.
    pub fn apply_to(&self, method_name: &str, instrs: &mut Vec<CilInstruction>) -> Result<usize> {
        let mut applied = 0usize;
        for (hook_method, point, snippet) in &self.hooks {
            if hook_method != method_name {
                continue;
            }
            apply_snippet_at(instrs, point, snippet)?;
            applied += 1;
        }
        Ok(applied)
    }
}

// ─── ProxyMethod ──────────────────────────────────────────────────────────────

/// Generates a proxy (wrapper) method that delegates to an existing method.
#[derive(Debug, Clone)]
pub struct ProxyMethod {
    /// Name of the original method.
    pub original_method: String,
    /// Name of the new proxy method.
    pub proxy_name: String,
    /// Token of the original method to call.
    pub original_token: u32,
    /// Whether the proxy should be public.
    pub is_public: bool,
    /// Whether the proxy should be static.
    pub is_static: bool,
    /// Number of parameters.
    pub param_count: usize,
}

impl ProxyMethod {
    /// Create a proxy method descriptor.
    #[must_use]
    pub fn new(
        original_method: impl Into<String>,
        proxy_name: impl Into<String>,
        original_token: u32,
        param_count: usize,
    ) -> Self {
        Self {
            original_method: original_method.into(),
            proxy_name: proxy_name.into(),
            original_token,
            is_public: true,
            is_static: true,
            param_count,
        }
    }

    /// Generate the CIL body of the proxy method.
    ///
    /// The body loads all arguments (ldarg.0 … ldarg.N) then calls the original.
    #[must_use]
    pub fn generate_body(&self) -> Vec<CilInstruction> {
        let mut instrs = Vec::with_capacity(self.param_count + 2);
        let mut offset = 0u32;
        for i in 0..self.param_count {
            let (opcode, operand) = match i {
                0 => ("ldarg.0", CilOperand::None),
                1 => ("ldarg.1", CilOperand::None),
                2 => ("ldarg.2", CilOperand::None),
                3 => ("ldarg.3", CilOperand::None),
                _ => ("ldarg.s", CilOperand::Int8(i as i8)),
            };
            instrs.push(CilInstruction {
                offset,
                opcode: opcode.into(),
                operand,
            });
            offset += 1;
        }
        instrs.push(CilInstruction {
            offset,
            opcode: if self.is_static {
                "call".into()
            } else {
                "callvirt".into()
            },
            operand: CilOperand::Token(self.original_token),
        });
        offset += 5;
        instrs.push(CilInstruction::simple(offset, "ret"));
        instrs
    }
}

// ─── InstrumentMethod ─────────────────────────────────────────────────────────

/// Adds entry/exit instrumentation (logging, timing) to an existing method.
#[derive(Debug, Clone)]
pub struct InstrumentMethod {
    /// Name label for this instrumentation.
    pub label: String,
    /// Token of the logging method to call on entry.
    pub entry_logger_token: Option<u32>,
    /// Token of the logging method to call before each `ret`.
    pub exit_logger_token: Option<u32>,
    /// Whether to measure elapsed time (adds a `Stopwatch` initialisation pattern).
    pub measure_time: bool,
}

impl InstrumentMethod {
    /// Create a simple entry+exit logger instrumentation.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            entry_logger_token: None,
            exit_logger_token: None,
            measure_time: false,
        }
    }

    /// Set the entry logger method token.
    #[must_use]
    pub const fn with_entry_logger(mut self, token: u32) -> Self {
        self.entry_logger_token = Some(token);
        self
    }

    /// Set the exit logger method token.
    #[must_use]
    pub const fn with_exit_logger(mut self, token: u32) -> Self {
        self.exit_logger_token = Some(token);
        self
    }

    /// Enable elapsed-time measurement.
    #[must_use]
    pub const fn with_timing(mut self) -> Self {
        self.measure_time = true;
        self
    }

    /// Generate the entry-side prologue instructions.
    #[must_use]
    pub fn entry_prologue(&self) -> Vec<CilInstruction> {
        let mut out = Vec::new();
        if let Some(token) = self.entry_logger_token {
            out.push(CilInstruction {
                offset: 0,
                opcode: "ldstr".into(),
                operand: CilOperand::Token(token),
            });
            out.push(CilInstruction::simple(5, "pop"));
        }
        out
    }

    /// Generate the exit-side epilogue instructions (to insert before each `ret`).
    #[must_use]
    pub fn exit_epilogue(&self) -> Vec<CilInstruction> {
        let mut out = Vec::new();
        if let Some(token) = self.exit_logger_token {
            out.push(CilInstruction {
                offset: 0,
                opcode: "ldstr".into(),
                operand: CilOperand::Token(token),
            });
            out.push(CilInstruction::simple(5, "pop"));
        }
        out
    }

    /// Apply instrumentation to a mutable instruction list.
    ///
    /// # Errors
    /// Returns an error if the method body is empty.
    pub fn apply(&self, instrs: &mut Vec<CilInstruction>) -> Result<()> {
        if instrs.is_empty() {
            return Err(anyhow!("cannot instrument empty method body"));
        }
        // Insert entry prologue at start.
        let prologue = self.entry_prologue();
        for (i, instr) in prologue.into_iter().enumerate() {
            instrs.insert(i, instr);
        }
        // Insert exit epilogue before each `ret`.
        let epilogue = self.exit_epilogue();
        if !epilogue.is_empty() {
            let mut i = 0usize;
            while i < instrs.len() {
                if instrs[i].opcode == "ret" {
                    for (j, ep) in epilogue.iter().enumerate() {
                        instrs.insert(i + j, ep.clone());
                    }
                    i += epilogue.len() + 1;
                } else {
                    i += 1;
                }
            }
        }
        Ok(())
    }
}

// ─── InjectReport ─────────────────────────────────────────────────────────────

/// Records all injections performed during a session.
#[derive(Debug, Clone, Default)]
pub struct InjectReport {
    /// List of injected snippets: `(method, injection_point_description, snippet_name)`.
    pub injections: Vec<(String, String, String)>,
    /// Errors that occurred during injection.
    pub errors: Vec<String>,
}

impl InjectReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful injection.
    pub fn record_injection(
        &mut self,
        method: impl Into<String>,
        point_desc: impl Into<String>,
        snippet_name: impl Into<String>,
    ) {
        self.injections
            .push((method.into(), point_desc.into(), snippet_name.into()));
    }

    /// Record an error.
    pub fn record_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Returns the total number of successful injections.
    #[must_use]
    pub const fn injection_count(&self) -> usize {
        self.injections.len()
    }

    /// Returns `true` if all injections were successful.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns a short summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} injections, {} errors",
            self.injection_count(),
            self.errors.len()
        )
    }
}

// ─── CilInjector ─────────────────────────────────────────────────────────────

/// Top-level CIL code injection engine.
///
/// Maintains a mutable map of method name → instruction list and applies
/// injection operations, recording results in an [`InjectReport`].
#[derive(Debug, Default)]
pub struct CilInjector {
    /// Method bodies managed by this injector.
    bodies: HashMap<String, Vec<CilInstruction>>,
    /// Accumulated inject report.
    pub report: InjectReport,
}

impl CilInjector {
    /// Create a new injector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method body.
    pub fn register_method(
        &mut self,
        method_name: impl Into<String>,
        instructions: Vec<CilInstruction>,
    ) {
        self.bodies.insert(method_name.into(), instructions);
    }

    /// Returns the current instruction list for a method.
    #[must_use]
    pub fn get_body(&self, method_name: &str) -> Option<&Vec<CilInstruction>> {
        self.bodies.get(method_name)
    }

    /// Returns the number of registered methods.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.bodies.len()
    }

    /// Inject a code snippet into a method.
    ///
    /// # Errors
    /// Returns an error if the method is not found or the injection point is invalid.
    pub fn inject(
        &mut self,
        method_name: &str,
        point: &InjectionPoint,
        snippet: &CodeSnippet,
    ) -> Result<()> {
        let instrs = self
            .bodies
            .get_mut(method_name)
            .ok_or_else(|| anyhow!("method '{method_name}' not registered"))?;

        apply_snippet_at(instrs, point, snippet)?;

        self.report
            .record_injection(method_name, point.description(), snippet.name.clone());
        Ok(())
    }

    /// Apply an [`InstrumentMethod`] instrumentation to a registered method.
    ///
    /// # Errors
    /// Returns an error if the method is not found or the body is empty.
    pub fn instrument(&mut self, method_name: &str, instr: &InstrumentMethod) -> Result<()> {
        let instrs = self
            .bodies
            .get_mut(method_name)
            .ok_or_else(|| anyhow!("method '{method_name}' not registered"))?;

        instr.apply(instrs)?;

        self.report
            .record_injection(method_name, "instrumented".to_string(), instr.label.clone());
        Ok(())
    }

    /// Install all hooks from a [`HookInstaller`] onto registered methods.
    pub fn install_hooks(&mut self, installer: &HookInstaller) {
        for method_name in installer.hooked_methods() {
            if let Some(instrs) = self.bodies.get_mut(method_name) {
                let result = installer.apply_to(method_name, instrs);
                match result {
                    Ok(n) if n > 0 => {
                        self.report
                            .record_injection(method_name, "hook", "hook_installer");
                    }
                    Err(e) => {
                        self.report.record_error(format!("{method_name}: {e}"));
                    }
                    _ => {}
                }
            }
        }
    }

    /// Generate and register a proxy method.
    ///
    /// # Errors
    /// Never errors in the current implementation (always succeeds).
    pub fn register_proxy(&mut self, proxy: &ProxyMethod) -> Result<()> {
        let body = proxy.generate_body();
        self.bodies.insert(proxy.proxy_name.clone(), body);
        self.report.record_injection(
            &proxy.proxy_name,
            "proxy generated",
            format!("proxy of {}", proxy.original_method),
        );
        Ok(())
    }

    /// Remove a method body from the injector.
    pub fn remove_method(&mut self, method_name: &str) -> bool {
        self.bodies.remove(method_name).is_some()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn apply_snippet_at(
    instrs: &mut Vec<CilInstruction>,
    point: &InjectionPoint,
    snippet: &CodeSnippet,
) -> Result<()> {
    match point {
        InjectionPoint::MethodEntry => {
            for (i, s) in snippet.instructions.iter().enumerate() {
                instrs.insert(i, s.clone());
            }
        }
        InjectionPoint::BeforeReturn => {
            let mut i = 0usize;
            while i < instrs.len() {
                if instrs[i].opcode == "ret" {
                    for (j, s) in snippet.instructions.iter().enumerate() {
                        instrs.insert(i + j, s.clone());
                    }
                    i += snippet.len() + 1;
                } else {
                    i += 1;
                }
            }
        }
        InjectionPoint::AfterOffset(offset) => {
            let pos = instrs
                .iter()
                .position(|instr| instr.offset == *offset)
                .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
            for (j, s) in snippet.instructions.iter().enumerate() {
                instrs.insert(pos + 1 + j, s.clone());
            }
        }
        InjectionPoint::BeforeOffset(offset) => {
            let pos = instrs
                .iter()
                .position(|instr| instr.offset == *offset)
                .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
            for (j, s) in snippet.instructions.iter().enumerate() {
                instrs.insert(pos + j, s.clone());
            }
        }
        InjectionPoint::ReplaceOffset(offset) => {
            let pos = instrs
                .iter()
                .position(|instr| instr.offset == *offset)
                .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
            instrs.remove(pos);
            for (j, s) in snippet.instructions.iter().enumerate() {
                instrs.insert(pos + j, s.clone());
            }
        }
        InjectionPoint::BeforeOpcode(opcode) => {
            let mut i = 0usize;
            while i < instrs.len() {
                if instrs[i].opcode == *opcode {
                    for (j, s) in snippet.instructions.iter().enumerate() {
                        instrs.insert(i + j, s.clone());
                    }
                    i += snippet.len() + 1;
                } else {
                    i += 1;
                }
            }
        }
        InjectionPoint::AfterCall(token) => {
            let mut i = 0usize;
            while i < instrs.len() {
                let is_call_to_token = (instrs[i].opcode == "call"
                    || instrs[i].opcode == "callvirt")
                    && matches!(instrs[i].operand, CilOperand::Token(t) if t == *token);
                if is_call_to_token {
                    for (j, s) in snippet.instructions.iter().enumerate() {
                        instrs.insert(i + 1 + j, s.clone());
                    }
                    i += snippet.len() + 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::{CilInstruction, CilOperand};

    fn simple_body() -> Vec<CilInstruction> {
        vec![
            CilInstruction::simple(0, "nop"),
            CilInstruction::simple(1, "ret"),
        ]
    }

    fn body_with_call(token: u32) -> Vec<CilInstruction> {
        vec![
            CilInstruction {
                offset: 0,
                opcode: "call".into(),
                operand: CilOperand::Token(token),
            },
            CilInstruction::simple(5, "ret"),
        ]
    }

    // ── InjectionPoint ────────────────────────────────────────────────────────

    #[test]
    fn test_injection_point_description_entry() {
        assert_eq!(InjectionPoint::MethodEntry.description(), "method entry");
    }

    #[test]
    fn test_injection_point_description_before_return() {
        assert_eq!(InjectionPoint::BeforeReturn.description(), "before return");
    }

    #[test]
    fn test_injection_point_description_after_offset() {
        assert!(
            InjectionPoint::AfterOffset(0x10)
                .description()
                .contains("0010")
        );
    }

    #[test]
    fn test_injection_point_description_before_opcode() {
        let d = InjectionPoint::BeforeOpcode("call".into()).description();
        assert!(d.contains("call"));
    }

    // ── CodeSnippet ───────────────────────────────────────────────────────────

    #[test]
    fn test_snippet_new() {
        let s = CodeSnippet::new("test", vec![CilInstruction::simple(0, "nop")]);
        assert_eq!(s.name, "test");
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_snippet_nops() {
        let s = CodeSnippet::nops("pad", 5);
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn test_snippet_push_pop() {
        let s = CodeSnippet::push_pop_const("guard", 42);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn test_snippet_is_empty() {
        let s = CodeSnippet::new("empty", vec![]);
        assert!(s.is_empty());
    }

    // ── HookInstaller ─────────────────────────────────────────────────────────

    #[test]
    fn test_hook_installer_add_hook() {
        let mut h = HookInstaller::new();
        let s = CodeSnippet::nops("hook", 1);
        h.add_hook("MyClass::Foo", InjectionPoint::MethodEntry, s);
        assert_eq!(h.hook_count(), 1);
        assert!(h.has_hook("MyClass::Foo"));
    }

    #[test]
    fn test_hook_installer_hooked_methods() {
        let mut h = HookInstaller::new();
        h.add_hook(
            "A::foo",
            InjectionPoint::MethodEntry,
            CodeSnippet::nops("n", 1),
        );
        h.add_hook(
            "B::bar",
            InjectionPoint::BeforeReturn,
            CodeSnippet::nops("n", 1),
        );
        assert_eq!(h.hooked_methods().len(), 2);
    }

    #[test]
    fn test_hook_installer_apply_to_injects() {
        let mut h = HookInstaller::new();
        h.add_hook(
            "method",
            InjectionPoint::MethodEntry,
            CodeSnippet::nops("n", 2),
        );
        let mut instrs = simple_body();
        let applied = h.apply_to("method", &mut instrs).unwrap();
        assert_eq!(applied, 1);
        assert_eq!(instrs.len(), 4); // 2 nops + nop + ret
    }

    #[test]
    fn test_hook_installer_no_match() {
        let h = HookInstaller::new();
        let mut instrs = simple_body();
        let applied = h.apply_to("unknown", &mut instrs).unwrap();
        assert_eq!(applied, 0);
    }

    // ── ProxyMethod ───────────────────────────────────────────────────────────

    #[test]
    fn test_proxy_method_generate_body_no_params() {
        let p = ProxyMethod::new("Target::Foo", "Proxy::Foo", 0x0A000001, 0);
        let body = p.generate_body();
        assert_eq!(body.last().unwrap().opcode, "ret");
    }

    #[test]
    fn test_proxy_method_generate_body_with_params() {
        let p = ProxyMethod::new("Target::Bar", "Proxy::Bar", 0x0A000002, 3);
        let body = p.generate_body();
        // 3 ldarg.* + call + ret
        assert_eq!(body.len(), 5);
        assert_eq!(body[0].opcode, "ldarg.0");
        assert_eq!(body[1].opcode, "ldarg.1");
        assert_eq!(body[2].opcode, "ldarg.2");
    }

    #[test]
    fn test_proxy_method_ends_with_ret() {
        let p = ProxyMethod::new("A::B", "P::B", 0x0A000003, 2);
        let body = p.generate_body();
        assert_eq!(body.last().unwrap().opcode, "ret");
    }

    // ── InstrumentMethod ──────────────────────────────────────────────────────

    #[test]
    fn test_instrument_new() {
        let i = InstrumentMethod::new("tracer");
        assert_eq!(i.label, "tracer");
        assert!(i.entry_logger_token.is_none());
    }

    #[test]
    fn test_instrument_with_tokens() {
        let i = InstrumentMethod::new("log")
            .with_entry_logger(0x70000001)
            .with_exit_logger(0x70000002);
        assert!(i.entry_logger_token.is_some());
        assert!(i.exit_logger_token.is_some());
    }

    #[test]
    fn test_instrument_apply_to_body() {
        let i = InstrumentMethod::new("test")
            .with_entry_logger(0x70000001)
            .with_exit_logger(0x70000002);
        let mut body = simple_body();
        i.apply(&mut body).unwrap();
        // entry prologue (2) + nop + exit epilogue (2) + ret
        assert!(body.len() > 2);
    }

    #[test]
    fn test_instrument_apply_empty_body_err() {
        let i = InstrumentMethod::new("test");
        let mut body: Vec<CilInstruction> = vec![];
        assert!(i.apply(&mut body).is_err());
    }

    #[test]
    fn test_instrument_no_loggers_no_change() {
        let i = InstrumentMethod::new("passthrough");
        let mut body = simple_body();
        let original_len = body.len();
        i.apply(&mut body).unwrap();
        assert_eq!(body.len(), original_len);
    }

    // ── InjectReport ──────────────────────────────────────────────────────────

    #[test]
    fn test_inject_report_new() {
        let r = InjectReport::new();
        assert_eq!(r.injection_count(), 0);
        assert!(r.is_clean());
    }

    #[test]
    fn test_inject_report_record_injection() {
        let mut r = InjectReport::new();
        r.record_injection("Method::Foo", "method entry", "my_snippet");
        assert_eq!(r.injection_count(), 1);
    }

    #[test]
    fn test_inject_report_record_error() {
        let mut r = InjectReport::new();
        r.record_error("something went wrong");
        assert!(!r.is_clean());
    }

    #[test]
    fn test_inject_report_summary() {
        let mut r = InjectReport::new();
        r.record_injection("A", "entry", "s");
        r.record_error("oops");
        assert!(r.summary().contains("1 injections"));
        assert!(r.summary().contains("1 errors"));
    }

    // ── CilInjector ───────────────────────────────────────────────────────────

    #[test]
    fn test_cil_injector_register_and_get() {
        let mut inj = CilInjector::new();
        inj.register_method("Foo::Bar", simple_body());
        assert!(inj.get_body("Foo::Bar").is_some());
        assert_eq!(inj.method_count(), 1);
    }

    #[test]
    fn test_cil_injector_inject_method_entry() {
        let mut inj = CilInjector::new();
        inj.register_method("Foo::Bar", simple_body());
        let snippet = CodeSnippet::nops("pad", 3);
        inj.inject("Foo::Bar", &InjectionPoint::MethodEntry, &snippet)
            .unwrap();
        assert_eq!(inj.get_body("Foo::Bar").unwrap().len(), 5); // 3+2
    }

    #[test]
    fn test_cil_injector_inject_unknown_method_err() {
        let mut inj = CilInjector::new();
        let snippet = CodeSnippet::nops("pad", 1);
        let result = inj.inject("Unknown", &InjectionPoint::MethodEntry, &snippet);
        assert!(result.is_err());
    }

    #[test]
    fn test_cil_injector_inject_before_return() {
        let mut inj = CilInjector::new();
        inj.register_method("M::F", simple_body());
        let snippet = CodeSnippet::nops("before_ret", 2);
        inj.inject("M::F", &InjectionPoint::BeforeReturn, &snippet)
            .unwrap();
        let body = inj.get_body("M::F").unwrap();
        assert!(body.len() > 2);
        assert_eq!(body.last().unwrap().opcode, "ret");
    }

    #[test]
    fn test_cil_injector_inject_after_offset() {
        let mut inj = CilInjector::new();
        inj.register_method("M::G", simple_body());
        let snippet = CodeSnippet::nops("after0", 1);
        inj.inject("M::G", &InjectionPoint::AfterOffset(0), &snippet)
            .unwrap();
        assert_eq!(inj.get_body("M::G").unwrap().len(), 3);
    }

    #[test]
    fn test_cil_injector_inject_after_offset_bad_err() {
        let mut inj = CilInjector::new();
        inj.register_method("M::H", simple_body());
        let snippet = CodeSnippet::nops("bad", 1);
        let result = inj.inject("M::H", &InjectionPoint::AfterOffset(999), &snippet);
        assert!(result.is_err());
    }

    #[test]
    fn test_cil_injector_replace_offset() {
        let mut inj = CilInjector::new();
        inj.register_method("M::I", simple_body());
        let snippet = CodeSnippet::new(
            "replace",
            vec![CilInstruction {
                offset: 0,
                opcode: "ldc.i4.0".into(),
                operand: CilOperand::None,
            }],
        );
        inj.inject("M::I", &InjectionPoint::ReplaceOffset(0), &snippet)
            .unwrap();
        let body = inj.get_body("M::I").unwrap();
        assert_eq!(body[0].opcode, "ldc.i4.0");
    }

    #[test]
    fn test_cil_injector_report_populated() {
        let mut inj = CilInjector::new();
        inj.register_method("M::J", simple_body());
        let snippet = CodeSnippet::nops("x", 1);
        inj.inject("M::J", &InjectionPoint::MethodEntry, &snippet)
            .unwrap();
        assert_eq!(inj.report.injection_count(), 1);
        assert!(inj.report.is_clean());
    }

    #[test]
    fn test_cil_injector_remove_method() {
        let mut inj = CilInjector::new();
        inj.register_method("M::K", simple_body());
        assert!(inj.remove_method("M::K"));
        assert!(!inj.remove_method("M::K"));
    }

    #[test]
    fn test_cil_injector_register_proxy() {
        let mut inj = CilInjector::new();
        let proxy = ProxyMethod::new("Original::Foo", "Proxy::Foo", 0x0A000001, 1);
        inj.register_proxy(&proxy).unwrap();
        assert!(inj.get_body("Proxy::Foo").is_some());
    }

    #[test]
    fn test_cil_injector_instrument_method() {
        let mut inj = CilInjector::new();
        inj.register_method("M::L", simple_body());
        let inst = InstrumentMethod::new("tracer")
            .with_entry_logger(0x70000001)
            .with_exit_logger(0x70000002);
        inj.instrument("M::L", &inst).unwrap();
        assert!(inj.report.injection_count() > 0);
    }

    #[test]
    fn test_cil_injector_before_opcode_injection() {
        let mut inj = CilInjector::new();
        let body = vec![
            CilInstruction::simple(0, "call"),
            CilInstruction::simple(5, "call"),
            CilInstruction::simple(10, "ret"),
        ];
        inj.register_method("M::M", body);
        let snippet = CodeSnippet::nops("before_call", 1);
        inj.inject(
            "M::M",
            &InjectionPoint::BeforeOpcode("call".into()),
            &snippet,
        )
        .unwrap();
        let final_body = inj.get_body("M::M").unwrap();
        // 1 nop before each of 2 calls + 2 calls + ret = 5
        assert_eq!(final_body.len(), 5);
    }

    #[test]
    fn test_cil_injector_after_call_token() {
        let mut inj = CilInjector::new();
        inj.register_method("M::N", body_with_call(0x0A000001));
        let snippet = CodeSnippet::nops("after_call", 1);
        inj.inject("M::N", &InjectionPoint::AfterCall(0x0A000001), &snippet)
            .unwrap();
        let body = inj.get_body("M::N").unwrap();
        assert_eq!(body.len(), 3); // call + nop + ret
    }
}
