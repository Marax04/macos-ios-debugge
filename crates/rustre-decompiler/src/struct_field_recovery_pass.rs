//! Struct-field recovery pass.
//!
//! Drives [`StructRecoveryEngine`] from raw instructions: each `[base ± K]`
//! access is recorded as a [`FieldAccess`], one [`TypeVar`] is assigned per
//! distinct base ([`BaseKind::Rsp`], [`BaseKind::Rbp`], or per-malloc heap
//! return), and the resulting [`StructDatabase`] is serialized into the
//! [`DecompilerContext`] annotation `recovered_structs` and prepended to the
//! pseudo-code as `struct StackS_*` declarations.
//!
//! Operand rewriting: any memory operand whose base appears in the database is
//! rewritten in-place inside `ctx.pseudo_code_lines` to
//! `<base_ident>.field_<hexoff>` so the emitted C reflects struct field access.

use std::collections::HashMap;

use rustre_analysis_typerecov::struct_recovery_engine::{
    FieldAccess, RecoveredStruct, StructDatabase, StructRecoveryEngine,
};
use rustre_analysis_typerecov::TypeVar;
use rustre_core::arch::Instruction;
use serde::Serialize;

use crate::mem_operand::{parse_mem_operands, BaseKind, MemOperand};
use crate::{DecompOptions, DecompVariable, DecompilerContext, DecompilerError, DecompilerPass, VarStorage};

/// JSON-friendly view of a [`RecoveredStruct`] for emission via
/// `ctx.annotation("recovered_structs")` and the
/// `decompiler.recover_structs` MCP tool.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveredStructJson {
    pub name: String,
    pub base_kind: String,
    pub total_size: u32,
    pub has_padding: bool,
    pub fields: Vec<RecoveredFieldJson>,
    pub c_decl: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveredFieldJson {
    pub offset: u32,
    pub size: u8,
    pub ty: String,
    pub name: String,
    pub access_count: usize,
    pub has_write: bool,
}

/// Pass that recovers struct layouts from memory-access patterns.
#[derive(Debug, Default)]
pub struct StructFieldRecoveryPass;

impl StructFieldRecoveryPass {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Scan instructions to record field accesses and heap base tags.
///
/// Returns the access engine, the base→TypeVar map, and the set of heap
/// register names (those whose [`TypeVar`] was allocated after a heap allocator call).
fn collect_field_accesses(
    instructions: &[Instruction],
) -> (StructRecoveryEngine, HashMap<BaseKind, TypeVar>, HashMap<String, TypeVar>) {
    let mut base_vars: HashMap<BaseKind, TypeVar> = HashMap::new();
    let mut heap_regs: HashMap<String, TypeVar> = HashMap::new();
    let heap_call_names = ["malloc", "calloc", "realloc", "operator new", "_Znwm"];
    let mut next_id: u32 = 1;
    let mut engine = StructRecoveryEngine::new_64bit();

    for instr in instructions {
        let mnem = instr.mnemonic.to_lowercase();
        if mnem == "call" {
            let ops = instr.operands.trim().to_lowercase();
            if heap_call_names.iter().any(|n| ops.contains(n)) {
                let v = TypeVar::new(next_id);
                next_id += 1;
                heap_regs.insert("rax".to_string(), v);
                base_vars.insert(BaseKind::Reg("rax".to_string()), v);
            }
            continue;
        }
        if mnem == "lea" { continue; }
        let ops_str = instr.operands.as_str();
        let mems = parse_mem_operands(ops_str);
        if mems.is_empty() { continue; }
        for mem in &mems {
            let is_write = mem_is_write_operand(ops_str, &mnem, mem);
            let tv = base_vars.get(&mem.base).copied().unwrap_or_else(|| {
                let v = TypeVar::new(next_id);
                next_id += 1;
                base_vars.insert(mem.base.clone(), v);
                v
            });
            let offset_u32 = u32::try_from(mem.displacement.unsigned_abs()).unwrap_or(u32::MAX);
            let size = if mem.size_bytes == 0 { 8 } else { mem.size_bytes };
            let acc = if is_write {
                FieldAccess::write(tv, offset_u32, size, instr.address.0)
            } else {
                FieldAccess::read(tv, offset_u32, size, instr.address.0)
            };
            engine.record(acc);
        }
    }
    (engine, base_vars, heap_regs)
}

/// Build the JSON view and the renamed struct list from a recovered database.
fn build_struct_json_view(
    db: &StructDatabase,
    var_to_base: &HashMap<TypeVar, BaseKind>,
    heap_regs: &HashMap<String, TypeVar>,
    fn_address: u64,
) -> (Vec<RecoveredStructJson>, Vec<RecoveredStruct>) {
    let mut json_view: Vec<RecoveredStructJson> = Vec::new();
    let mut renamed: Vec<RecoveredStruct> = Vec::new();
    for s in db.all_structs() {
        let base = var_to_base.get(&s.base_var).cloned().unwrap_or_else(|| BaseKind::Reg("unknown".into()));
        let kind_str = match &base {
            BaseKind::Rbp | BaseKind::Rsp => "stack".to_string(),
            BaseKind::Reg(r) => if heap_regs.contains_key(r) { "heap".to_string() } else { "reg".to_string() },
        };
        let prefix = match kind_str.as_str() { "stack" => "Stack", "heap" => "Heap", _ => "Mem" };
        let new_name = format!("{}S_{:08x}", prefix, fn_address.wrapping_add(u64::from(s.base_var.0)));
        let mut s2 = s.clone();
        s2.name.clone_from(&new_name);
        let c_decl = s2.to_c_decl();
        json_view.push(RecoveredStructJson {
            name: new_name,
            base_kind: kind_str,
            total_size: s2.total_size,
            has_padding: s2.has_padding,
            fields: s2.fields.iter().map(|f| RecoveredFieldJson {
                offset: f.offset, size: f.size, ty: f.ty.display_name(),
                name: f.name.clone(), access_count: f.access_count, has_write: f.has_write,
            }).collect(),
            c_decl,
        });
        renamed.push(s2);
    }
    (json_view, renamed)
}

/// Annotate the context with the recovered struct JSON, prepend C declarations,
/// add decompiler variables, and rewrite mem-ref operands in the pseudo-code.
fn annotate_and_emit_structs(
    ctx: &mut DecompilerContext,
    json_view: &[RecoveredStructJson],
    renamed: &[RecoveredStruct],
    var_to_base: &HashMap<TypeVar, BaseKind>,
) {
    let json = serde_json::to_string(json_view).unwrap_or_default();
    ctx.annotate("recovered_structs", json);
    ctx.annotate("recovered_struct_count", json_view.len().to_string());
    if !renamed.is_empty() {
        let header: Vec<String> = renamed.iter()
            .flat_map(|s| s.to_c_decl().lines().map(str::to_string).collect::<Vec<_>>())
            .collect();
        let existing = std::mem::take(&mut ctx.pseudo_code_lines);
        ctx.pseudo_code_lines = header;
        ctx.pseudo_code_lines.extend(existing);
    }
    for (idx, s) in renamed.iter().enumerate() {
        let Some(base) = var_to_base.get(&s.base_var) else { continue };
        let storage = match base {
            BaseKind::Rbp | BaseKind::Rsp => VarStorage::Stack(0),
            BaseKind::Reg(r) => VarStorage::Register(r.clone()),
        };
        ctx.add_variable(DecompVariable {
            name: format!("{}_{idx}", base.ident_prefix()),
            type_str: format!("struct {}", s.name),
            is_parameter: false,
            storage,
        });
    }
    let mut rewrite_table: HashMap<BaseKind, (String, String)> = HashMap::new();
    for (idx, s) in renamed.iter().enumerate() {
        if let Some(base) = var_to_base.get(&s.base_var) {
            rewrite_table.insert(base.clone(), (format!("{}_{idx}", base.ident_prefix()), s.name.clone()));
        }
    }
    if !rewrite_table.is_empty() {
        for line in &mut ctx.pseudo_code_lines {
            rewrite_mem_refs(line, &rewrite_table);
        }
    }
}

impl DecompilerPass for StructFieldRecoveryPass {
    fn name(&self) -> &'static str {
        "struct_field_recovery"
    }

    fn run(
        &self,
        ctx: &mut DecompilerContext,
        _address: u64,
        instructions: &[Instruction],
    ) -> Result<(), DecompilerError> {
        let (engine, base_vars, heap_regs) = collect_field_accesses(instructions);
        if engine.access_count() == 0 { return Ok(()); }
        let mut db = StructDatabase::new();
        for s in engine.recover_structs_all() { db.insert(s); }
        let var_to_base: HashMap<TypeVar, BaseKind> =
            base_vars.iter().map(|(k, v)| (*v, k.clone())).collect();
        let (json_view, renamed) = build_struct_json_view(&db, &var_to_base, &heap_regs, ctx.address);
        annotate_and_emit_structs(ctx, &json_view, &renamed, &var_to_base);
        Ok(())
    }

    fn is_enabled(&self, opts: &DecompOptions) -> bool {
        opts.passes.emit_struct_fields
    }

    fn description(&self) -> &'static str {
        "Recover struct layouts from [base±K] field-access patterns"
    }
}

/// Decide whether a memory operand at position `mem` in an instruction's
/// operand string is being written.
fn mem_is_write_operand(ops: &str, mnem: &str, operand: &MemOperand) -> bool {
    // Single-operand mnemonics that store through a memory operand.
    if matches!(mnem, "push" | "pop") {
        return mnem == "pop";
    }
    // For two-operand forms the destination is the first operand.  Locate the
    // first '[' in `ops` and check whether `mem`'s `displacement` matches the
    // first bracketed group; if there is only one bracket group, the slot
    // (dst vs src) is decided by the position of the comma.
    let first_bracket = ops.find('[');
    let comma = ops.find(',');
    match (first_bracket, comma) {
        (Some(b), Some(c)) => {
            if b < c {
                // First mem operand is destination → write for store-style.
                // The supplied `mem` could be either the first or a second
                // bracket group.  Without re-parsing we treat ALL bracket
                // groups occurring before the comma as writes only when the
                // mnemonic is one that stores.
                let _ = operand;
                matches!(
                    mnem,
                    "mov" | "movq" | "movl" | "movw" | "movb" | "add" | "sub" | "and" | "or"
                        | "xor" | "inc" | "dec" | "neg" | "not" | "shl" | "shr" | "sal" | "sar"
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

fn rewrite_mem_refs(line: &mut String, table: &HashMap<BaseKind, (String, String)>) {
    let mems = parse_mem_operands(line);
    if mems.is_empty() {
        return;
    }
    // Recompose the line by scanning for `[...]` groups in original case.
    let mut out = String::with_capacity(line.len());
    let mut rest: &str = line.as_str();
    let mut mem_iter = mems.into_iter();
    while let Some(start) = rest.find('[') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(']') else { break };
        let before_bracket_start = rest[..start].rfind(',').map_or(0, |p| p + 1);
        let before = &rest[..before_bracket_start];
        let prefix_in_group = &rest[before_bracket_start..start];

        if let Some(mem) = mem_iter.next() {
            if let Some((ident, _struct_name)) = table.get(&mem.base) {
                let off = mem.displacement.unsigned_abs();
                let replacement = format!("{ident}.field_{off:x}");
                out.push_str(before);
                // Drop any "qword ptr " prefix the user kept before the bracket.
                let stripped = strip_size_prefix(prefix_in_group);
                out.push_str(stripped);
                out.push_str(&replacement);
            } else {
                out.push_str(&rest[..end + start + 2]);
            }
        } else {
            out.push_str(&rest[..end + start + 2]);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    *line = out;
}

fn strip_size_prefix(s: &str) -> &str {
    let lower = s.to_lowercase();
    for p in [
        "qword ptr ",
        "dword ptr ",
        "word ptr ",
        "byte ptr ",
        "xmmword ptr ",
        "ymmword ptr ",
        "zmmword ptr ",
        "oword ptr ",
    ] {
        if (lower.ends_with(p) || lower.contains(p))
            && let Some(idx) = lower.rfind(p) {
                return &s[..idx];
            }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::Instruction;

    fn ins(addr: u64, mnem: &str, ops: &str) -> Instruction {
        let mut i = Instruction::new(Address(addr), 1, mnem, vec![]);
        i.operands = ops.to_string();
        i
    }

    #[test]
    fn recovers_three_fields_from_rsp_writes() {
        let instructions = vec![
            ins(0x1000, "mov", "qword ptr [rsp + 0], rax"),
            ins(0x1004, "mov", "qword ptr [rsp + 8], rbx"),
            ins(0x1008, "mov", "dword ptr [rsp + 16], ecx"),
        ];
        let mut ctx = DecompilerContext::new(0x1000, "f", DecompOptions::default());
        let pass = StructFieldRecoveryPass::new();
        pass.run(&mut ctx, 0x1000, &instructions).unwrap();
        let json = ctx.annotation("recovered_structs").expect("annotation present");
        assert!(json.contains("field_0"));
        assert!(json.contains("field_8"));
        assert!(json.contains("field_10"));
        let count: usize = ctx.annotation("recovered_struct_count").unwrap().parse().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn heap_base_after_malloc() {
        let instructions = vec![
            ins(0x1000, "call", "malloc"),
            ins(0x1004, "mov", "qword ptr [rax + 0], rdi"),
            ins(0x1008, "mov", "qword ptr [rax + 8], rsi"),
        ];
        let mut ctx = DecompilerContext::new(0x1000, "f", DecompOptions::default());
        let pass = StructFieldRecoveryPass::new();
        pass.run(&mut ctx, 0x1000, &instructions).unwrap();
        let json = ctx.annotation("recovered_structs").unwrap();
        assert!(json.contains("\"base_kind\":\"heap\""));
    }
}
