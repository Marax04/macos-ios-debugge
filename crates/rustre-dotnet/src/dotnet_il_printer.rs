// dotnet_il_printer.rs — .NET CIL instruction pretty printer
// Covers all opcode families, exception handlers, stack-depth tracking,
// and configurable output formatting.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

// ─── Configuration ────────────────────────────────────────────────────────────

/// Display-related flags for the IL printer (at most 3 bools).
#[derive(Debug, Clone)]
pub struct IlDisplayConfig {
    pub show_offsets: bool,
    pub show_stack_effects: bool,
    pub show_metadata_tokens: bool,
}

impl Default for IlDisplayConfig {
    fn default() -> Self {
        Self {
            show_offsets: true,
            show_stack_effects: false,
            show_metadata_tokens: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IlPrintConfig {
    pub display: IlDisplayConfig,
    pub use_color: bool,
    pub indent_try_blocks: bool,
    pub max_inline_bytes: usize,
}

impl Default for IlPrintConfig {
    fn default() -> Self {
        Self {
            display: IlDisplayConfig::default(),
            use_color: false,
            indent_try_blocks: true,
            max_inline_bytes: 8,
        }
    }
}

// ─── Opcodes ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Opcode {
    Nop,
    Break,
    Ldarg0, Ldarg1, Ldarg2, Ldarg3,
    Ldloc0, Ldloc1, Ldloc2, Ldloc3,
    Stloc0, Stloc1, Stloc2, Stloc3,
    Ldarg(u16), Ldarga(u16), Starg(u16),
    Ldloc(u16), Ldloca(u16), Stloc(u16),
    LdargS(u8), LdargaS(u8), StargS(u8),
    LdlocS(u8), LdlocaS(u8), StlocS(u8),
    LdnullC,
    LdcI4M1, LdcI40, LdcI41, LdcI42, LdcI43, LdcI44, LdcI45, LdcI46, LdcI47, LdcI48,
    LdcI4S(i8), LdcI4(i32), LdcI8(i64), LdcR4(u32), LdcR8(u64),
    Dup, Pop,
    Jmp(u32), Call(u32), Calli(u32), Ret,
    BrS(i8), BrtrueS(i8), BrfalseS(i8),
    BeqS(i8), BgeS(i8), BgtS(i8), BleS(i8), BltS(i8), BneUnS(i8),
    BgeUnS(i8), BgtUnS(i8), BleUnS(i8), BltUnS(i8),
    Br(i32), Brtrue(i32), Brfalse(i32),
    Beq(i32), Bge(i32), Bgt(i32), Ble(i32), Blt(i32), BneUn(i32),
    BgeUn(i32), BgtUn(i32), BleUn(i32), BltUn(i32),
    Switch(Vec<i32>),
    LdindI1, LdindU1, LdindI2, LdindU2, LdindI4, LdindU4,
    LdindI8, LdindI, LdindR4, LdindR8, LdindRef,
    StindRef, StindI1, StindI2, StindI4, StindI8, StindR4, StindR8,
    Add, Sub, Mul, Div, DivUn, Rem, RemUn,
    And, Or, Xor, Shl, Shr, ShrUn, Neg, Not,
    ConvI1, ConvI2, ConvI4, ConvI8, ConvR4, ConvR8, ConvU4, ConvU8,
    ConvRUn, ConvOvfI1Un, ConvOvfI2Un, ConvOvfI4Un, ConvOvfI8Un,
    ConvOvfU1Un, ConvOvfU2Un, ConvOvfU4Un, ConvOvfU8Un, ConvOvfIUn,
    ConvOvfI1, ConvOvfI2, ConvOvfI4, ConvOvfI8,
    ConvOvfU1, ConvOvfU2, ConvOvfU4, ConvOvfU8, ConvU2, ConvU1, ConvI, ConvU,
    ConvOvfI, ConvOvfU,
    Callvirt(u32), Cpobj(u32), Ldobj(u32), Ldstr(u32),
    Newobj(u32), Castclass(u32), Isinst(u32),
    Unbox(u32), Throw, Ldfld(u32), Ldflda(u32), Stfld(u32),
    Ldsfld(u32), Ldsflda(u32), Stsfld(u32),
    Stobj(u32), Box(u32), Newarr(u32), Ldlen,
    Ldelema(u32), LdelemI1, LdelemU1, LdelemI2, LdelemU2,
    LdelemI4, LdelemU4, LdelemI8, LdelemI, LdelemR4, LdelemR8,
    LdelemRef, StelemI, StelemI1, StelemI2, StelemI4, StelemI8,
    StelemR4, StelemR8, StelemRef, Stelem(u32), Ldelem(u32),
    UnboxAny(u32),
    AddOvf, AddOvfUn, MulOvf, MulOvfUn, SubOvf, SubOvfUn, EndFinally,
    Leave(i32), LeaveS(i8), StindI,
    Ldtoken(u32), LdvirtFtn(u32), Ldftn(u32),
    InitObj(u32), Constrained(u32), Cpblk, Initblk, Sizeof(u32), Rethrow,
    Refanytype, Refanyval(u32), Mkrefany(u32), Arglist,
    Ceq, Cgt, CgtUn, Clt, CltUn,
    Localloc, Endfilter, Unaligned(u8), Volatile, Tailcall, Readonly,
    CalliInd,
    MethodSpec(u32),
}

// ─── Operand kind (for formatting) ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    None,
    InlineI(i32),
    InlineI8(i64),
    InlineR4(f32),
    InlineR8(f64),
    InlineString(u32),
    InlineMethod(u32),
    InlineField(u32),
    InlineType(u32),
    InlineTok(u32),
    InlineVar(u16),
    ShortInlineVar(u8),
    InlineBranch(i32),
    ShortInlineBranch(i8),
    InlineSwitch(Vec<i32>),
    Prefix(u8),
}

// ─── Stack effect ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct StackEffect {
    pub pop:  i32,
    pub push: i32,
}

impl StackEffect {
    #[must_use] 
    pub const fn net(self) -> i32 { self.push - self.pop }
}

// ─── Exception Handler ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerKind {
    Catch(u32),   // token of exception type
    Filter,
    Finally,
    Fault,
}

#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub kind:          HandlerKind,
    pub try_start:     u32,
    pub try_end:       u32,
    pub handler_start: u32,
    pub handler_end:   u32,
    pub filter_start:  Option<u32>,
}

// ─── Instruction ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset:   u32,
    pub opcode:   Opcode,
    pub operand:  Operand,
    pub size:     u8,
}

// ─── Method Body ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LocalVar {
    pub index:    u16,
    pub type_sig: Vec<u8>,
    pub name:     Option<String>,
}

#[derive(Debug, Clone)]
pub struct MethodBody {
    pub name:          String,
    pub max_stack:     u16,
    pub locals:        Vec<LocalVar>,
    pub instructions:  Vec<Instruction>,
    pub handlers:      Vec<ExceptionHandler>,
    pub init_locals:   bool,
}

// ─── Method Signature ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ReturnType {
    Void,
    ByValue(String),
    ByRef(String),
}

#[derive(Debug, Clone)]
pub struct ParamType {
    pub name: Option<String>,
    pub ty:   String,
    pub by_ref: bool,
}

#[derive(Debug, Clone)]
pub struct MethodSignature {
    pub return_type: ReturnType,
    pub params:      Vec<ParamType>,
    pub is_static:   bool,
    pub is_generic:  bool,
    pub generic_param_count: u8,
}

impl fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ret = match &self.return_type {
            ReturnType::Void => "void".to_string(),
            ReturnType::ByValue(s) => s.clone(),
            ReturnType::ByRef(s) => format!("ref {s}"),
        };
        write!(f, "{ret} (")?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            if p.by_ref { write!(f, "ref ")?; }
            write!(f, "{}", p.ty)?;
            if let Some(n) = &p.name { write!(f, " {n}")?; }
        }
        write!(f, ")")
    }
}

// ─── Stack Tracker ────────────────────────────────────────────────────────────

pub struct StackDepthTracker {
    depths: HashMap<u32, i32>,
}

impl Default for StackDepthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDepthTracker {
    #[must_use] 
    pub fn new() -> Self {
        Self { depths: HashMap::new() }
    }

    #[must_use] 
    pub fn compute(instructions: &[Instruction], handlers: &[ExceptionHandler]) -> Self {
        let mut tracker = Self::new();
        // Handler entry points push one value (the exception object)
        for h in handlers {
            if matches!(h.kind, HandlerKind::Catch(_) | HandlerKind::Filter) {
                tracker.depths.insert(h.handler_start, 1);
            }
        }

        let mut current: i32 = 0;
        for insn in instructions {
            if let Some(&d) = tracker.depths.get(&insn.offset) {
                current = d;
            } else {
                tracker.depths.insert(insn.offset, current);
            }
            let effect = stack_effect_of(&insn.opcode, &insn.operand);
            current = (current + effect.net()).max(0);
        }
        tracker
    }

    #[must_use] 
    pub fn depth_at(&self, offset: u32) -> Option<i32> {
        self.depths.get(&offset).copied()
    }
}

#[must_use] 
pub const fn stack_effect_of(op: &Opcode, _operand: &Operand) -> StackEffect {
    match op {
        Opcode::Ldarg0 | Opcode::Ldarg1 | Opcode::Ldarg2 | Opcode::Ldarg3
        | Opcode::Ldarg(_) | Opcode::LdargS(_)
        | Opcode::Ldloc0 | Opcode::Ldloc1 | Opcode::Ldloc2 | Opcode::Ldloc3
        | Opcode::Ldloc(_) | Opcode::LdlocS(_)
        | Opcode::LdnullC | Opcode::LdcI4M1
        | Opcode::LdcI40 | Opcode::LdcI41 | Opcode::LdcI42 | Opcode::LdcI43
        | Opcode::LdcI44 | Opcode::LdcI45 | Opcode::LdcI46 | Opcode::LdcI47 | Opcode::LdcI48
        | Opcode::LdcI4S(_) | Opcode::LdcI4(_) | Opcode::LdcI8(_)
        | Opcode::LdcR4(_) | Opcode::LdcR8(_)
        | Opcode::Ldlen
        | Opcode::Ldftn(_) | Opcode::LdvirtFtn(_) | Opcode::Ldtoken(_)
        | Opcode::Arglist | Opcode::Sizeof(_) | Opcode::Ldstr(_) | Opcode::Ldarga(_) | Opcode::LdargaS(_) | Opcode::Ldloca(_) | Opcode::LdlocaS(_) | Opcode::Ldsflda(_)
        => StackEffect { pop: 0, push: 1 },

        Opcode::Stloc0 | Opcode::Stloc1 | Opcode::Stloc2 | Opcode::Stloc3
        | Opcode::Stloc(_) | Opcode::StlocS(_)
        | Opcode::Starg(_) | Opcode::StargS(_)
        | Opcode::Pop | Opcode::Throw | Opcode::Rethrow | Opcode::EndFinally | Opcode::BrtrueS(_) | Opcode::BrfalseS(_) | Opcode::Brtrue(_) | Opcode::Brfalse(_) | Opcode::Switch(_) | Opcode::Endfilter | Opcode::InitObj(_)
        => StackEffect { pop: 1, push: 0 },

        Opcode::Dup => StackEffect { pop: 1, push: 2 },

        Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::DivUn
        | Opcode::Rem | Opcode::RemUn | Opcode::And | Opcode::Or | Opcode::Xor
        | Opcode::Shl | Opcode::Shr | Opcode::ShrUn
        | Opcode::AddOvf | Opcode::AddOvfUn | Opcode::MulOvf | Opcode::MulOvfUn
        | Opcode::SubOvf | Opcode::SubOvfUn
        | Opcode::Ceq | Opcode::Cgt | Opcode::CgtUn | Opcode::Clt | Opcode::CltUn
        | Opcode::LdelemI1 | Opcode::LdelemU1 | Opcode::LdelemI2 | Opcode::LdelemU2
        | Opcode::LdelemI4 | Opcode::LdelemU4 | Opcode::LdelemI8 | Opcode::LdelemI
        | Opcode::LdelemR4 | Opcode::LdelemR8 | Opcode::LdelemRef | Opcode::Ldelem(_)
        => StackEffect { pop: 2, push: 1 },

        Opcode::Neg | Opcode::Not
        | Opcode::ConvI1 | Opcode::ConvI2 | Opcode::ConvI4 | Opcode::ConvI8
        | Opcode::ConvR4 | Opcode::ConvR8 | Opcode::ConvU4 | Opcode::ConvU8
        | Opcode::ConvU2 | Opcode::ConvU1 | Opcode::ConvI | Opcode::ConvU
        | Opcode::ConvRUn | Opcode::ConvOvfI1 | Opcode::ConvOvfI2 | Opcode::ConvOvfI4
        | Opcode::ConvOvfI8 | Opcode::ConvOvfU1 | Opcode::ConvOvfU2 | Opcode::ConvOvfU4
        | Opcode::ConvOvfU8 | Opcode::ConvOvfI | Opcode::ConvOvfU
        | Opcode::Castclass(_) | Opcode::Isinst(_) | Opcode::Box(_) | Opcode::Unbox(_)
        | Opcode::UnboxAny(_) | Opcode::Ldobj(_)
        | Opcode::LdindI1 | Opcode::LdindU1 | Opcode::LdindI2 | Opcode::LdindU2
        | Opcode::LdindI4 | Opcode::LdindU4 | Opcode::LdindI8 | Opcode::LdindI
        | Opcode::LdindR4 | Opcode::LdindR8 | Opcode::LdindRef
        | Opcode::Ldflda(_) | Opcode::Ldfld(_) | Opcode::Ldsfld(_)
        | Opcode::Newarr(_) | Opcode::Calli(_) | Opcode::Localloc | Opcode::Mkrefany(_) | Opcode::Refanyval(_) | Opcode::Refanytype | Opcode::ConvOvfI1Un | Opcode::ConvOvfI2Un | Opcode::ConvOvfI4Un
        | Opcode::ConvOvfI8Un | Opcode::ConvOvfU1Un | Opcode::ConvOvfU2Un
        | Opcode::ConvOvfU4Un | Opcode::ConvOvfU8Un | Opcode::ConvOvfIUn
        => StackEffect { pop: 1, push: 1 },

        Opcode::Stfld(_) | Opcode::StindI1 | Opcode::StindI2 | Opcode::StindI4
        | Opcode::StindI8 | Opcode::StindR4 | Opcode::StindR8 | Opcode::StindRef
        | Opcode::StindI | Opcode::Stsfld(_) | Opcode::Stobj(_) | Opcode::BeqS(_) | Opcode::BgeS(_) | Opcode::BgtS(_) | Opcode::BleS(_)
        | Opcode::BltS(_) | Opcode::BneUnS(_) | Opcode::BgeUnS(_) | Opcode::BgtUnS(_)
        | Opcode::BleUnS(_) | Opcode::BltUnS(_)
        | Opcode::Beq(_) | Opcode::Bge(_) | Opcode::Bgt(_) | Opcode::Ble(_)
        | Opcode::Blt(_) | Opcode::BneUn(_) | Opcode::BgeUn(_) | Opcode::BgtUn(_)
        | Opcode::BleUn(_) | Opcode::BltUn(_) | Opcode::Cpobj(_)
        => StackEffect { pop: 2, push: 0 },

        Opcode::StelemI | Opcode::StelemI1 | Opcode::StelemI2 | Opcode::StelemI4
        | Opcode::StelemI8 | Opcode::StelemR4 | Opcode::StelemR8 | Opcode::StelemRef
        | Opcode::Stelem(_) | Opcode::Ldelema(_) | Opcode::Cpblk | Opcode::Initblk
        => StackEffect { pop: 3, push: 0 },

        Opcode::Call(t) | Opcode::Callvirt(t) | Opcode::Newobj(t) => {
            // Approximation: 0 net. Caller should decode signature.
            let _ = t;
            StackEffect { pop: 0, push: 1 }
        }
        Opcode::Nop | Opcode::Break | Opcode::Ret | Opcode::Jmp(_) | Opcode::BrS(_) | Opcode::Br(_) | Opcode::Leave(_) | Opcode::LeaveS(_) | Opcode::Constrained(_) | Opcode::Unaligned(_) | Opcode::Volatile
        | Opcode::Tailcall | Opcode::Readonly | Opcode::CalliInd | Opcode::MethodSpec(_)
        => StackEffect { pop: 0, push: 0 },

        }
}

// ─── IlPrinter ────────────────────────────────────────────────────────────────

pub struct IlPrinter {
    config: IlPrintConfig,
}

impl IlPrinter {
    #[must_use] 
    pub const fn new(config: IlPrintConfig) -> Self { Self { config } }
    #[must_use] 
    pub fn with_defaults() -> Self { Self::new(IlPrintConfig::default()) }

    #[must_use] 
    pub fn print_method_body(&self, body: &MethodBody) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "// Method: {}", body.name);
        let _ = writeln!(out, "// .maxstack {}", body.max_stack);
        if body.init_locals && !body.locals.is_empty() {
            let _ = writeln!(out, ".locals init (");
            for lv in &body.locals {
                let name = lv.name.as_deref().unwrap_or("unnamed");
                let _ = writeln!(out, "    [{idx}] <sig> {name}", idx = lv.index);
            }
            let _ = writeln!(out, ")");
        }

        let tracker = StackDepthTracker::compute(&body.instructions, &body.handlers);
        let handler_map = build_handler_map(&body.handlers);
        let indent = if self.config.indent_try_blocks { "    " } else { "" };
        let mut try_depth = 0usize;

        for insn in &body.instructions {
            // Open/close try/handler regions
            if let Some(events) = handler_map.get(&insn.offset) {
                for evt in events {
                    match evt {
                        BlockEvent::TryStart => {
                            let _ = writeln!(out, "{}.try {{", "    ".repeat(try_depth));
                            try_depth += 1;
                        }
                        BlockEvent::TryEnd => {
                            try_depth = try_depth.saturating_sub(1);
                            let _ = writeln!(out, "{}}}", "    ".repeat(try_depth));
                        }
                        BlockEvent::HandlerStart(kind) => {
                            let label = match kind {
                                HandlerKind::Catch(tok) => format!("catch [0x{tok:08x}]"),
                                HandlerKind::Filter     => "filter".to_string(),
                                HandlerKind::Finally    => "finally".to_string(),
                                HandlerKind::Fault      => "fault".to_string(),
                            };
                            let _ = writeln!(out, "{}{label} {{", "    ".repeat(try_depth.saturating_sub(1)));
                        }
                        BlockEvent::HandlerEnd => {
                            let _ = writeln!(out, "{}}}", "    ".repeat(try_depth.saturating_sub(1)));
                        }
                    }
                }
            }

            let cur_indent = if self.config.indent_try_blocks {
                indent.repeat(try_depth)
            } else {
                String::new()
            };

            let formatted = self.format_instruction(insn, &tracker);
            let _ = writeln!(out, "{cur_indent}{formatted}");
        }

        out
    }

    #[must_use] 
    pub fn format_instruction(&self, insn: &Instruction, tracker: &StackDepthTracker) -> String {
        let mut s = String::new();
        if self.config.display.show_offsets {
            let _ = write!(s, "IL_{:04X}: ", insn.offset);
        }
        let mnemonic = opcode_mnemonic(&insn.opcode);
        let _ = write!(s, "{mnemonic}");
        let operand_str = self.format_operand(&insn.operand, insn.offset);
        if !operand_str.is_empty() {
            let _ = write!(s, " {operand_str}");
        }
        if self.config.display.show_stack_effects {
            let eff = stack_effect_of(&insn.opcode, &insn.operand);
            let _ = write!(s, "  // stack: {}", eff.net());
        }
        if self.config.display.show_stack_effects
            && let Some(depth) = tracker.depth_at(insn.offset) {
                let _ = write!(s, " (depth={depth})");
            }
        s
    }

    #[must_use] 
    pub fn format_operand(&self, operand: &Operand, current_offset: u32) -> String {
        match operand {
            Operand::None => String::new(),
            Operand::InlineI(v)  => format!("{v}"),
            Operand::InlineI8(v) => format!("{v}L"),
            Operand::InlineR4(v) => format!("{v:?}"),
            Operand::InlineR8(v) => format!("{v:?}"),
            Operand::InlineString(tok) => {
                if self.config.display.show_metadata_tokens {
                    format!("(0x{tok:08X})")
                } else {
                    "\"<string>\"".to_string()
                }
            }
            Operand::InlineMethod(tok) | Operand::InlineField(tok) | Operand::InlineType(tok) | Operand::InlineTok(tok) => {
                if self.config.display.show_metadata_tokens {
                    format!("[0x{tok:08X}]")
                } else {
                    String::new()
                }
            }
            Operand::InlineVar(v)      => format!("V_{v}"),
            Operand::ShortInlineVar(v) => format!("V_{v}"),
            Operand::InlineBranch(delta) => {
                let target = current_offset.wrapping_add((*delta).cast_unsigned()).wrapping_add(5);
                format!("IL_{target:04X}")
            }
            Operand::ShortInlineBranch(delta) => {
                let target = current_offset.wrapping_add(u32::from((*delta).cast_unsigned())).wrapping_add(2);
                format!("IL_{target:04X}")
            }
            Operand::InlineSwitch(targets) => {
                let formatted: Vec<String> = targets.iter().enumerate().map(|(i, t)| {
                    let abs = current_offset.wrapping_add((*t).cast_unsigned());
                    format!("case {i}: IL_{abs:04X}")
                }).collect();
                format!("({})", formatted.join(", "))
            }
            Operand::Prefix(b) => format!("0x{b:02x}"),
        }
    }

    #[must_use] 
    pub fn format_exception_handler(&self, h: &ExceptionHandler) -> String {
        let kind_str = match &h.kind {
            HandlerKind::Catch(tok) => format!("catch [0x{tok:08X}]"),
            HandlerKind::Filter     => "filter".to_string(),
            HandlerKind::Finally    => "finally".to_string(),
            HandlerKind::Fault      => "fault".to_string(),
        };
        format!(
            ".try IL_{:04X}..IL_{:04X} {} IL_{:04X}..IL_{:04X}",
            h.try_start, h.try_end, kind_str, h.handler_start, h.handler_end
        )
    }

    #[must_use] 
    pub fn format_signature(&self, sig: &MethodSignature) -> String {
        format!("{sig}")
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum BlockEvent {
    TryStart,
    TryEnd,
    HandlerStart(HandlerKind),
    HandlerEnd,
}

fn build_handler_map(handlers: &[ExceptionHandler]) -> HashMap<u32, Vec<BlockEvent>> {
    let mut map: HashMap<u32, Vec<BlockEvent>> = HashMap::new();
    for h in handlers {
        map.entry(h.try_start).or_default().push(BlockEvent::TryStart);
        map.entry(h.try_end).or_default().push(BlockEvent::TryEnd);
        map.entry(h.handler_start).or_default().push(BlockEvent::HandlerStart(h.kind.clone()));
        map.entry(h.handler_end).or_default().push(BlockEvent::HandlerEnd);
    }
    map
}

// Load/store/branch opcodes (first third of the full table).
const fn opcode_mnemonic(op: &Opcode) -> &'static str {
    match op {
        Opcode::Nop         => "nop",
        Opcode::Break       => "break",
        Opcode::Ldarg0      => "ldarg.0",
        Opcode::Ldarg1      => "ldarg.1",
        Opcode::Ldarg2      => "ldarg.2",
        Opcode::Ldarg3      => "ldarg.3",
        Opcode::LdargS(_)   => "ldarg.s",
        Opcode::Ldarg(_)    => "ldarg",
        Opcode::LdargaS(_)  => "ldarga.s",
        Opcode::Ldarga(_)   => "ldarga",
        Opcode::StargS(_)   => "starg.s",
        Opcode::Starg(_)    => "starg",
        Opcode::Ldloc0      => "ldloc.0",
        Opcode::Ldloc1      => "ldloc.1",
        Opcode::Ldloc2      => "ldloc.2",
        Opcode::Ldloc3      => "ldloc.3",
        Opcode::LdlocS(_)   => "ldloc.s",
        Opcode::Ldloc(_)    => "ldloc",
        Opcode::LdlocaS(_)  => "ldloca.s",
        Opcode::Ldloca(_)   => "ldloca",
        Opcode::StlocS(_)   => "stloc.s",
        Opcode::Stloc0      => "stloc.0",
        Opcode::Stloc1      => "stloc.1",
        Opcode::Stloc2      => "stloc.2",
        Opcode::Stloc3      => "stloc.3",
        Opcode::Stloc(_)    => "stloc",
        Opcode::LdnullC     => "ldnull",
        Opcode::LdcI4M1     => "ldc.i4.m1",
        Opcode::LdcI40      => "ldc.i4.0",
        Opcode::LdcI41      => "ldc.i4.1",
        Opcode::LdcI42      => "ldc.i4.2",
        Opcode::LdcI43      => "ldc.i4.3",
        Opcode::LdcI44      => "ldc.i4.4",
        Opcode::LdcI45      => "ldc.i4.5",
        Opcode::LdcI46      => "ldc.i4.6",
        Opcode::LdcI47      => "ldc.i4.7",
        Opcode::LdcI48      => "ldc.i4.8",
        Opcode::LdcI4S(_)   => "ldc.i4.s",
        Opcode::LdcI4(_)    => "ldc.i4",
        Opcode::LdcI8(_)    => "ldc.i8",
        Opcode::LdcR4(_)    => "ldc.r4",
        Opcode::LdcR8(_)    => "ldc.r8",
        Opcode::Dup         => "dup",
        Opcode::Pop         => "pop",
        Opcode::Jmp(_)      => "jmp",
        Opcode::Call(_)     => "call",
        Opcode::Calli(_) | Opcode::CalliInd => "calli",
        Opcode::Ret         => "ret",
        Opcode::BrS(_)      => "br.s",
        Opcode::BrtrueS(_)  => "brtrue.s",
        Opcode::BrfalseS(_) => "brfalse.s",
        Opcode::BeqS(_)     => "beq.s",
        Opcode::BgeS(_)     => "bge.s",
        Opcode::BgtS(_)     => "bgt.s",
        Opcode::BleS(_)     => "ble.s",
        Opcode::BltS(_)     => "blt.s",
        Opcode::BneUnS(_)   => "bne.un.s",
        Opcode::BgeUnS(_)   => "bge.un.s",
        Opcode::BgtUnS(_)   => "bgt.un.s",
        Opcode::BleUnS(_)   => "ble.un.s",
        Opcode::BltUnS(_)   => "blt.un.s",
        Opcode::Br(_)       => "br",
        Opcode::Brtrue(_)   => "brtrue",
        Opcode::Brfalse(_)  => "brfalse",
        Opcode::Beq(_)      => "beq",
        Opcode::Bge(_)      => "bge",
        Opcode::Bgt(_)      => "bgt",
        Opcode::Ble(_)      => "ble",
        Opcode::Blt(_)      => "blt",
        Opcode::BneUn(_)    => "bne.un",
        Opcode::BgeUn(_)    => "bge.un",
        Opcode::BgtUn(_)    => "bgt.un",
        Opcode::BleUn(_)    => "ble.un",
        Opcode::BltUn(_)    => "blt.un",
        Opcode::Switch(_)   => "switch",
        _ => opcode_mnemonic2(op),
    }
}

// Memory/arithmetic/conv opcodes (second third).
const fn opcode_mnemonic2(op: &Opcode) -> &'static str {
    match op {
        Opcode::LdindI1  => "ldind.i1",  Opcode::LdindU1  => "ldind.u1",
        Opcode::LdindI2  => "ldind.i2",  Opcode::LdindU2  => "ldind.u2",
        Opcode::LdindI4  => "ldind.i4",  Opcode::LdindU4  => "ldind.u4",
        Opcode::LdindI8  => "ldind.i8",  Opcode::LdindI   => "ldind.i",
        Opcode::LdindR4  => "ldind.r4",  Opcode::LdindR8  => "ldind.r8",
        Opcode::LdindRef => "ldind.ref",
        Opcode::StindRef => "stind.ref", Opcode::StindI1  => "stind.i1",
        Opcode::StindI2  => "stind.i2",  Opcode::StindI4  => "stind.i4",
        Opcode::StindI8  => "stind.i8",  Opcode::StindR4  => "stind.r4",
        Opcode::StindR8  => "stind.r8",
        Opcode::Add    => "add",   Opcode::Sub    => "sub",
        Opcode::Mul    => "mul",   Opcode::Div    => "div",
        Opcode::DivUn  => "div.un", Opcode::Rem   => "rem",
        Opcode::RemUn  => "rem.un", Opcode::And   => "and",
        Opcode::Or     => "or",    Opcode::Xor   => "xor",
        Opcode::Shl    => "shl",   Opcode::Shr   => "shr",
        Opcode::ShrUn  => "shr.un", Opcode::Neg  => "neg",
        Opcode::Not    => "not",
        Opcode::ConvI1 => "conv.i1", Opcode::ConvI2 => "conv.i2",
        Opcode::ConvI4 => "conv.i4", Opcode::ConvI8 => "conv.i8",
        Opcode::ConvR4 => "conv.r4", Opcode::ConvR8 => "conv.r8",
        Opcode::ConvU4 => "conv.u4", Opcode::ConvU8 => "conv.u8",
        Opcode::Callvirt(_)  => "callvirt", Opcode::Cpobj(_)  => "cpobj",
        Opcode::Ldobj(_)     => "ldobj",    Opcode::Ldstr(_)  => "ldstr",
        Opcode::Newobj(_)    => "newobj",   Opcode::Castclass(_) => "castclass",
        Opcode::Isinst(_)    => "isinst",   Opcode::ConvRUn   => "conv.r.un",
        Opcode::Unbox(_)     => "unbox",    Opcode::Throw     => "throw",
        Opcode::Ldfld(_)     => "ldfld",    Opcode::Ldflda(_) => "ldflda",
        Opcode::Stfld(_)     => "stfld",    Opcode::Ldsfld(_) => "ldsfld",
        Opcode::Ldsflda(_)   => "ldsflda",  Opcode::Stsfld(_) => "stsfld",
        Opcode::Stobj(_)     => "stobj",    Opcode::Box(_)    => "box",
        Opcode::Newarr(_)    => "newarr",   Opcode::Ldlen     => "ldlen",
        Opcode::Ldelema(_)   => "ldelema",
        _ => opcode_mnemonic3(op),
    }
}

// Array/object metadata/prefix opcodes (final third).
const fn opcode_mnemonic3(op: &Opcode) -> &'static str {
    match op {
        Opcode::LdelemI1  => "ldelem.i1",  Opcode::LdelemU1  => "ldelem.u1",
        Opcode::LdelemI2  => "ldelem.i2",  Opcode::LdelemU2  => "ldelem.u2",
        Opcode::LdelemI4  => "ldelem.i4",  Opcode::LdelemU4  => "ldelem.u4",
        Opcode::LdelemI8  => "ldelem.i8",  Opcode::LdelemI   => "ldelem.i",
        Opcode::LdelemR4  => "ldelem.r4",  Opcode::LdelemR8  => "ldelem.r8",
        Opcode::LdelemRef => "ldelem.ref",
        Opcode::StelemI  => "stelem.i",  Opcode::StelemI1 => "stelem.i1",
        Opcode::StelemI2 => "stelem.i2", Opcode::StelemI4 => "stelem.i4",
        Opcode::StelemI8 => "stelem.i8", Opcode::StelemR4 => "stelem.r4",
        Opcode::StelemR8 => "stelem.r8", Opcode::StelemRef=> "stelem.ref",
        Opcode::Stelem(_)   => "stelem",    Opcode::Ldelem(_)   => "ldelem",
        Opcode::UnboxAny(_) => "unbox.any",
        Opcode::AddOvf  => "add.ovf",    Opcode::AddOvfUn => "add.ovf.un",
        Opcode::MulOvf  => "mul.ovf",    Opcode::MulOvfUn => "mul.ovf.un",
        Opcode::SubOvf  => "sub.ovf",    Opcode::SubOvfUn => "sub.ovf.un",
        Opcode::EndFinally  => "endfinally", Opcode::Leave(_)  => "leave",
        Opcode::LeaveS(_)   => "leave.s",   Opcode::StindI    => "stind.i",
        Opcode::Ldtoken(_)  => "ldtoken",    Opcode::LdvirtFtn(_) => "ldvirtftn",
        Opcode::Ldftn(_)    => "ldftn",      Opcode::InitObj(_) => "initobj",
        Opcode::Constrained(_) => "constrained.",
        Opcode::Cpblk => "cpblk",  Opcode::Initblk => "initblk",
        Opcode::Sizeof(_) => "sizeof",   Opcode::Rethrow   => "rethrow",
        Opcode::Refanytype  => "refanytype", Opcode::Refanyval(_) => "refanyval",
        Opcode::Mkrefany(_) => "mkrefany",   Opcode::Arglist     => "arglist",
        Opcode::Ceq   => "ceq",  Opcode::Cgt   => "cgt",  Opcode::CgtUn => "cgt.un",
        Opcode::Clt   => "clt",  Opcode::CltUn => "clt.un",
        Opcode::Localloc  => "localloc",  Opcode::Endfilter  => "endfilter",
        Opcode::Unaligned(_) => "unaligned.", Opcode::Volatile => "volatile.",
        Opcode::Tailcall    => "tail.",      Opcode::Readonly  => "readonly.",
        Opcode::MethodSpec(_) => "methodspec",
        Opcode::ConvU2 => "conv.u2", Opcode::ConvU1 => "conv.u1",
        Opcode::ConvI  => "conv.i",  Opcode::ConvU  => "conv.u",
        Opcode::ConvOvfI  => "conv.ovf.i",  Opcode::ConvOvfU  => "conv.ovf.u",
        Opcode::ConvOvfI1 => "conv.ovf.i1", Opcode::ConvOvfI2 => "conv.ovf.i2",
        Opcode::ConvOvfI4 => "conv.ovf.i4", Opcode::ConvOvfI8 => "conv.ovf.i8",
        Opcode::ConvOvfU1 => "conv.ovf.u1", Opcode::ConvOvfU2 => "conv.ovf.u2",
        Opcode::ConvOvfU4 => "conv.ovf.u4", Opcode::ConvOvfU8 => "conv.ovf.u8",
        Opcode::ConvOvfI1Un => "conv.ovf.i1.un", Opcode::ConvOvfI2Un => "conv.ovf.i2.un",
        Opcode::ConvOvfI4Un => "conv.ovf.i4.un", Opcode::ConvOvfI8Un => "conv.ovf.i8.un",
        Opcode::ConvOvfU1Un => "conv.ovf.u1.un", Opcode::ConvOvfU2Un => "conv.ovf.u2.un",
        Opcode::ConvOvfU4Un => "conv.ovf.u4.un", Opcode::ConvOvfU8Un => "conv.ovf.u8.un",
        Opcode::ConvOvfIUn  => "conv.ovf.i.un",
        // All other variants are covered by opcode_mnemonic / opcode_mnemonic2.
        _ => unreachable!(),
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insn(offset: u32, opcode: Opcode, operand: Operand) -> Instruction {
        Instruction { offset, opcode, operand, size: 1 }
    }

    #[test]
    fn test_nop_mnemonic() {
        assert_eq!(opcode_mnemonic(&Opcode::Nop), "nop");
    }

    #[test]
    fn test_add_stack_effect() {
        let eff = stack_effect_of(&Opcode::Add, &Operand::None);
        assert_eq!(eff.pop, 2);
        assert_eq!(eff.push, 1);
        assert_eq!(eff.net(), -1);
    }

    #[test]
    fn test_ldarg0_stack_push() {
        let eff = stack_effect_of(&Opcode::Ldarg0, &Operand::None);
        assert_eq!(eff.net(), 1);
    }

    #[test]
    fn test_ret_stack_zero() {
        let eff = stack_effect_of(&Opcode::Ret, &Operand::None);
        assert_eq!(eff.net(), 0);
    }

    #[test]
    fn test_format_inline_i() {
        let printer = IlPrinter::with_defaults();
        let s = printer.format_operand(&Operand::InlineI(42), 0);
        assert_eq!(s, "42");
    }

    #[test]
    fn test_format_branch_target() {
        let printer = IlPrinter::with_defaults();
        // InlineBranch(0) from offset 0 → target = 0+0+5 = 5
        let s = printer.format_operand(&Operand::InlineBranch(0), 0);
        assert_eq!(s, "IL_0005");
    }

    #[test]
    fn test_format_short_branch_target() {
        let printer = IlPrinter::with_defaults();
        let s = printer.format_operand(&Operand::ShortInlineBranch(3), 0);
        // target = 0 + 3 + 2 = 5
        assert_eq!(s, "IL_0005");
    }

    #[test]
    fn test_format_instruction_with_offset() {
        let printer = IlPrinter::with_defaults();
        let insn = make_insn(0, Opcode::Nop, Operand::None);
        let tracker = StackDepthTracker::new();
        let s = printer.format_instruction(&insn, &tracker);
        assert!(s.contains("IL_0000"));
        assert!(s.contains("nop"));
    }

    #[test]
    fn test_print_empty_body() {
        let printer = IlPrinter::with_defaults();
        let body = MethodBody {
            name: "TestMethod".to_string(),
            max_stack: 2,
            locals: vec![],
            instructions: vec![
                make_insn(0, Opcode::LdcI41, Operand::None),
                make_insn(1, Opcode::Ret, Operand::None),
            ],
            handlers: vec![],
            init_locals: false,
        };
        let output = printer.print_method_body(&body);
        assert!(output.contains("TestMethod"));
        assert!(output.contains("ldc.i4.1"));
        assert!(output.contains("ret"));
    }

    #[test]
    fn test_exception_handler_format() {
        let printer = IlPrinter::with_defaults();
        let h = ExceptionHandler {
            kind: HandlerKind::Finally,
            try_start: 0,
            try_end: 10,
            handler_start: 10,
            handler_end: 20,
            filter_start: None,
        };
        let s = printer.format_exception_handler(&h);
        assert!(s.contains("finally"));
        assert!(s.contains("IL_0000"));
    }

    #[test]
    fn test_stack_tracker_basic() {
        let instructions = vec![
            make_insn(0, Opcode::LdcI41, Operand::None),
            make_insn(1, Opcode::LdcI42, Operand::None),
            make_insn(2, Opcode::Add, Operand::None),
        ];
        let tracker = StackDepthTracker::compute(&instructions, &[]);
        assert_eq!(tracker.depth_at(0), Some(0));
        assert_eq!(tracker.depth_at(1), Some(1));
        assert_eq!(tracker.depth_at(2), Some(2));
    }

    #[test]
    fn test_stack_tracker_after_add() {
        let instructions = vec![
            make_insn(0, Opcode::LdcI41, Operand::None),
            make_insn(1, Opcode::LdcI42, Operand::None),
            make_insn(2, Opcode::Add, Operand::None),
            make_insn(3, Opcode::Ret, Operand::None),
        ];
        let tracker = StackDepthTracker::compute(&instructions, &[]);
        // After ldcI41 (push 1) = depth 1; after ldcI42 = 2; after add = 1 (not 3)
        assert_eq!(tracker.depth_at(3), Some(1));
    }

    #[test]
    fn test_method_signature_display() {
        let sig = MethodSignature {
            return_type: ReturnType::Void,
            params: vec![
                ParamType { name: Some("x".into()), ty: "int32".into(), by_ref: false },
            ],
            is_static: false,
            is_generic: false,
            generic_param_count: 0,
        };
        let s = format!("{sig}");
        assert!(s.contains("void"));
        assert!(s.contains("int32"));
    }

    #[test]
    fn test_switch_operand_format() {
        let printer = IlPrinter::with_defaults();
        let s = printer.format_operand(&Operand::InlineSwitch(vec![0, 10]), 0);
        assert!(s.contains("case 0"));
        assert!(s.contains("case 1"));
    }

    #[test]
    fn test_throw_stack_effect() {
        let eff = stack_effect_of(&Opcode::Throw, &Operand::None);
        assert_eq!(eff.pop, 1);
        assert_eq!(eff.push, 0);
    }

    #[test]
    fn test_dup_stack_effect() {
        let eff = stack_effect_of(&Opcode::Dup, &Operand::None);
        assert_eq!(eff.pop, 1);
        assert_eq!(eff.push, 2);
        assert_eq!(eff.net(), 1);
    }

    #[test]
    fn test_all_conv_mnemonics_present() {
        let convs = [
            opcode_mnemonic(&Opcode::ConvI1),
            opcode_mnemonic(&Opcode::ConvI2),
            opcode_mnemonic(&Opcode::ConvI4),
            opcode_mnemonic(&Opcode::ConvR8),
        ];
        for m in &convs {
            assert!(m.starts_with("conv"));
        }
    }
}
