//! `dalvik_lift` — Dalvik bytecode → SSA / Java AST lifting pass.
//!
//! This module converts the raw Dalvik instruction stream produced by the DEX
//! parser into a higher-level SSA representation, then further simplifies it
//! into the `java_ast` node types consumed by `java_emitter`.
//!
//! The overall pipeline is:
//!
//! ```text
//! DEX method bytecode
//!     │
//!     ▼
//! DalvikMethod  ─── parse_dalvik ──→  Vec<DalvikInsn>
//!     │
//!     ▼
//! SsaBuilder ────── build_ssa ───→  SsaMethod
//!     │
//!     ▼
//! SsaToJava ─────── lift ─────────→  AstMethod
//! ```

use std::collections::HashMap;

use super::java_ast::{AstMethod, BinOp, Expr, JavaType, Modifiers, Primitive, Statement};

// ─────────────────────────────────────────────────────────────────────────────
// Raw Dalvik instruction (post-decode)
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded Dalvik instruction from the DEX method code.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DalvikInsn {
    /// Byte offset within the code buffer.
    pub offset: u32,
    /// Opcode mnemonic.
    pub mnemonic: String,
    /// Destination register (if any).
    pub dest: Option<u16>,
    /// Source registers.
    pub srcs: Vec<u16>,
    /// Literal integer operand (if any).
    pub lit: Option<i64>,
    /// String operand (if any).
    pub string: Option<String>,
    /// Type operand (if any).
    pub type_ref: Option<String>,
    /// Method reference (if any).
    pub method_ref: Option<String>,
    /// Field reference (if any).
    pub field_ref: Option<String>,
    /// Branch target offset (if any).
    pub branch_target: Option<i32>,
}

impl DalvikInsn {
    /// Returns `true` if this is a branch instruction.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.branch_target.is_some()
            || self.mnemonic.starts_with("if-")
            || self.mnemonic == "goto"
            || self.mnemonic == "goto/16"
            || self.mnemonic == "goto/32"
    }

    /// Returns `true` if this is a return instruction.
    #[must_use]
    pub fn is_return(&self) -> bool {
        self.mnemonic.starts_with("return")
    }

    /// Returns `true` if this is an invoke instruction.
    #[must_use]
    pub fn is_invoke(&self) -> bool {
        self.mnemonic.starts_with("invoke")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA variable
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA variable name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SsaVar {
    /// Base name (e.g. `"r0"` for Dalvik register 0).
    pub base: String,
    /// SSA version number.
    pub version: u32,
}

impl SsaVar {
    #[must_use]
    pub fn new(base: impl Into<String>, version: u32) -> Self {
        Self {
            base: base.into(),
            version,
        }
    }

    /// Returns the Java-friendly variable name.
    #[must_use]
    pub fn java_name(&self) -> String {
        if self.version == 0 {
            self.base.clone()
        } else {
            format!("{}_{}", self.base, self.version)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA instruction
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA instruction — a single assignment `dest = op(srcs…)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsaInsn {
    /// Destination (None for instructions with no result, like stores).
    pub dest: Option<SsaVar>,
    /// Operation.
    pub op: SsaOp,
}

/// The operation performed by an `SsaInsn`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SsaOp {
    Assign(SsaVar),
    Phi(Vec<SsaVar>),
    IntLit(i64),
    StringLit(String),
    NullLit,
    BinOp {
        op: BinOp,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    UnaryOp {
        op: super::java_ast::UnaryOp,
        src: SsaVar,
    },
    Invoke {
        kind: InvokeKind,
        object: Option<SsaVar>,
        class: String,
        method: String,
        args: Vec<SsaVar>,
        ret_type: JavaType,
    },
    FieldGet {
        object: Option<SsaVar>,
        class: String,
        field: String,
        field_type: JavaType,
    },
    FieldPut {
        object: Option<SsaVar>,
        class: String,
        field: String,
        value: SsaVar,
    },
    ArrayGet {
        array: SsaVar,
        index: SsaVar,
        elem_type: JavaType,
    },
    ArrayPut {
        array: SsaVar,
        index: SsaVar,
        value: SsaVar,
    },
    ArrayLen(SsaVar),
    NewObject {
        class: String,
        args: Vec<SsaVar>,
    },
    NewArray {
        elem_type: JavaType,
        size: SsaVar,
    },
    Cast {
        src: SsaVar,
        target: JavaType,
    },
    InstanceOf {
        src: SsaVar,
        class: String,
    },
    Throw(SsaVar),
    Return(Option<SsaVar>),
    Branch {
        kind: BranchKind,
        lhs: SsaVar,
        rhs: Option<SsaVar>,
        target: u32,
    },
    Goto(u32),
}

/// Kind of an invoke instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InvokeKind {
    Virtual,
    Static,
    Direct,
    Interface,
    Super,
}

/// Kind of a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BranchKind {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    EqZ,
    NeZ,
    LtZ,
    LeZ,
    GtZ,
    GeZ,
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA basic block
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the SSA CFG.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsaBlock {
    pub id: u32,
    pub instructions: Vec<SsaInsn>,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
}

/// The SSA representation of one method.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsaMethod {
    pub name: String,
    pub class: String,
    pub blocks: Vec<SsaBlock>,
    pub entry: u32,
    pub variables: HashMap<SsaVar, JavaType>,
}

impl SsaMethod {
    /// Find a block by its ID.
    #[must_use]
    pub fn block(&self, id: u32) -> Option<&SsaBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Returns the entry block.
    #[must_use]
    pub fn entry_block(&self) -> Option<&SsaBlock> {
        self.block(self.entry)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA builder (Dalvik → SSA)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an SSA method from a list of raw Dalvik instructions.
pub struct SsaBuilder {
    register_versions: HashMap<u16, u32>,
    next_version: HashMap<u16, u32>,
    variables: HashMap<SsaVar, JavaType>,
}

impl SsaBuilder {
    /// Create a new `SsaBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            register_versions: HashMap::new(),
            next_version: HashMap::new(),
            variables: HashMap::new(),
        }
    }

    /// Assign a new SSA version to register `r`.
    pub fn new_version(&mut self, r: u16) -> SsaVar {
        let ver = self.next_version.entry(r).or_insert(0);
        let v = *ver;
        *ver += 1;
        let base = format!("r{r}");
        let var = SsaVar::new(base, v);
        self.register_versions.insert(r, v);
        var
    }

    /// Read the current SSA version of register `r`.
    #[must_use]
    pub fn current(&self, r: u16) -> SsaVar {
        let ver = self.register_versions.get(&r).copied().unwrap_or(0);
        SsaVar::new(format!("r{r}"), ver)
    }

    /// Record a type for a variable.
    pub fn set_type(&mut self, var: SsaVar, ty: JavaType) {
        self.variables.insert(var, ty);
    }

    /// Build an `SsaMethod` from raw instructions.  This is a simplified
    /// single-block builder (no proper CFG construction — that requires a full
    /// dominator-tree algorithm).
    pub fn build(&mut self, name: &str, class: &str, insns: &[DalvikInsn]) -> SsaMethod {
        let mut ssa_insns = Vec::with_capacity(insns.len());

        for insn in insns {
            let ssa = self.lift_insn(insn);
            ssa_insns.extend(ssa);
        }

        let block = SsaBlock {
            id: 0,
            instructions: ssa_insns,
            successors: vec![],
            predecessors: vec![],
        };

        SsaMethod {
            name: name.to_owned(),
            class: class.to_owned(),
            blocks: vec![block],
            entry: 0,
            variables: self.variables.clone(),
        }
    }

    fn lift_insn(&mut self, insn: &DalvikInsn) -> Vec<SsaInsn> {
        let mut result = Vec::new();

        match insn.mnemonic.as_str() {
            // "nop" — skip; "move-result-*" — handled by invoke lifting.
            "nop" | "move-result" | "move-result-wide" | "move-result-object" => {}

            "move" | "move/from16" | "move/16" | "move-object" | "move-object/from16" => {
                if let (Some(d), Some(&s)) = (insn.dest, insn.srcs.first()) {
                    let dest = self.new_version(d);
                    let src = self.current(s);
                    result.push(SsaInsn {
                        dest: Some(dest),
                        op: SsaOp::Assign(src),
                    });
                }
            }

            "return-void" => {
                result.push(SsaInsn {
                    dest: None,
                    op: SsaOp::Return(None),
                });
            }

            "return" | "return-wide" | "return-object" => {
                if let Some(&r) = insn.srcs.first() {
                    let v = self.current(r);
                    result.push(SsaInsn {
                        dest: None,
                        op: SsaOp::Return(Some(v)),
                    });
                }
            }

            "const/4" | "const/16" | "const" | "const/high16" | "const-wide" | "const-wide/16"
            | "const-wide/32" | "const-wide/high16" => {
                if let Some(d) = insn.dest {
                    let dest = self.new_version(d);
                    let lit = insn.lit.unwrap_or(0);
                    result.push(SsaInsn {
                        dest: Some(dest),
                        op: SsaOp::IntLit(lit),
                    });
                }
            }

            "const-string" | "const-string/jumbo" => {
                if let Some(d) = insn.dest {
                    let dest = self.new_version(d);
                    let s = insn.string.clone().unwrap_or_default();
                    result.push(SsaInsn {
                        dest: Some(dest),
                        op: SsaOp::StringLit(s),
                    });
                }
            }

            op if op.starts_with("invoke") => {
                let kind = match op {
                    "invoke-virtual" | "invoke-virtual/range" => InvokeKind::Virtual,
                    "invoke-super" | "invoke-super/range" => InvokeKind::Super,
                    "invoke-direct" | "invoke-direct/range" => InvokeKind::Direct,
                    "invoke-interface" | "invoke-interface/range" => InvokeKind::Interface,
                    _ => InvokeKind::Static,
                };
                let method_ref = insn.method_ref.as_deref().unwrap_or("");
                let (class, method) = split_method_ref(method_ref);
                let (object, args) = if kind != InvokeKind::Static && !insn.srcs.is_empty() {
                    let obj = self.current(insn.srcs[0]);
                    let arg_vars: Vec<SsaVar> =
                        insn.srcs[1..].iter().map(|&r| self.current(r)).collect();
                    (Some(obj), arg_vars)
                } else {
                    let arg_vars: Vec<SsaVar> =
                        insn.srcs.iter().map(|&r| self.current(r)).collect();
                    (None, arg_vars)
                };

                result.push(SsaInsn {
                    dest: None,
                    op: SsaOp::Invoke {
                        kind,
                        object,
                        class: class.to_owned(),
                        method: method.to_owned(),
                        args,
                        ret_type: JavaType::Unknown,
                    },
                });
            }

            op if op.starts_with("add-")
                || op.starts_with("sub-")
                || op.starts_with("mul-")
                || op.starts_with("div-")
                || op.starts_with("rem-")
                || op.starts_with("and-")
                || op.starts_with("or-")
                || op.starts_with("xor-") =>
            {
                if let Some(d) = insn.dest {
                    let bin_op = arith_op(op);
                    let dest = self.new_version(d);
                    let lhs = self.current(insn.srcs.first().copied().unwrap_or(0));
                    let rhs = self.current(insn.srcs.get(1).copied().unwrap_or(0));
                    result.push(SsaInsn {
                        dest: Some(dest),
                        op: SsaOp::BinOp {
                            op: bin_op,
                            lhs,
                            rhs,
                        },
                    });
                }
            }

            op if op.starts_with("new-instance") => {
                if let (Some(d), Some(cls)) = (insn.dest, insn.type_ref.as_deref()) {
                    let dest = self.new_version(d);
                    result.push(SsaInsn {
                        dest: Some(dest),
                        op: SsaOp::NewObject {
                            class: cls.to_owned(),
                            args: vec![],
                        },
                    });
                }
            }

            op if op.starts_with("throw") => {
                if let Some(&r) = insn.srcs.first() {
                    let v = self.current(r);
                    result.push(SsaInsn {
                        dest: None,
                        op: SsaOp::Throw(v),
                    });
                }
            }

            _ => {} // unhandled instruction — drop
        }

        result
    }
}

impl Default for SsaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA → Java AST lift
// ─────────────────────────────────────────────────────────────────────────────

/// Lift an `SsaMethod` to an `AstMethod`.
#[must_use]
pub fn lift_to_java(
    ssa: &SsaMethod,
    modifiers: Modifiers,
    params: Vec<(String, JavaType)>,
    return_type: JavaType,
) -> AstMethod {
    let mut statements: Vec<Statement> = Vec::new();
    let mut locals: Vec<(String, JavaType)> = Vec::new();

    if let Some(entry) = ssa.entry_block() {
        for insn in &entry.instructions {
            if let Some(s) = lift_ssa_insn(insn, ssa, &mut locals) {
                statements.push(s);
            }
        }
    }

    AstMethod {
        modifiers,
        name: ssa.name.clone(),
        params,
        return_type,
        body: Some(statements),
        throws: vec![],
        annotations: vec![],
        locals,
    }
}

fn lift_ssa_insn(
    insn: &SsaInsn,
    ssa: &SsaMethod,
    locals: &mut Vec<(String, JavaType)>,
) -> Option<Statement> {
    match &insn.op {
        SsaOp::Return(None) => Some(Statement::Return(None)),

        SsaOp::Return(Some(v)) => {
            let _ty = ssa.variables.get(v).cloned().unwrap_or(JavaType::Unknown);
            Some(Statement::Return(Some(Expr::Var(v.java_name()))))
        }

        SsaOp::IntLit(n) => insn.dest.as_ref().map(|d| {
            let ty = JavaType::Primitive(Primitive::Int);
            locals.push((d.java_name(), ty.clone()));
            Statement::LocalDecl {
                ty,
                name: d.java_name(),
                init: Some(Expr::IntLit(*n)),
            }
        }),

        SsaOp::StringLit(s) => insn.dest.as_ref().map(|d| {
            let ty = JavaType::Reference("java.lang.String".to_owned());
            locals.push((d.java_name(), ty.clone()));
            Statement::LocalDecl {
                ty,
                name: d.java_name(),
                init: Some(Expr::StringLit(s.clone())),
            }
        }),

        SsaOp::Assign(src) => insn.dest.as_ref().map(|d| {
            let ty = ssa.variables.get(src).cloned().unwrap_or(JavaType::Unknown);
            locals.push((d.java_name(), ty.clone()));
            Statement::LocalDecl {
                ty,
                name: d.java_name(),
                init: Some(Expr::Var(src.java_name())),
            }
        }),

        SsaOp::Invoke {
            kind,
            object,
            class,
            method,
            args,
            ret_type,
        } => {
            let arg_exprs: Vec<Expr> = args.iter().map(|v| Expr::Var(v.java_name())).collect();
            let expr =
                build_invoke_expr(*kind, object.as_ref(), class, method, arg_exprs, ret_type);
            Some(invoke_to_stmt(insn, expr, ret_type, locals))
        }

        SsaOp::Throw(v) => Some(Statement::Throw(Expr::Var(v.java_name()))),

        SsaOp::NewObject { class, args } => insn.dest.as_ref().map(|d| {
            let arg_exprs: Vec<Expr> = args.iter().map(|v| Expr::Var(v.java_name())).collect();
            let ty = JavaType::Reference(class.clone());
            locals.push((d.java_name(), ty.clone()));
            Statement::LocalDecl {
                ty,
                name: d.java_name(),
                init: Some(Expr::NewObject {
                    class: class.clone(),
                    args: arg_exprs,
                }),
            }
        }),

        SsaOp::BinOp { op, lhs, rhs } => insn.dest.as_ref().map(|d| {
            let ty = JavaType::Primitive(Primitive::Int);
            locals.push((d.java_name(), ty.clone()));
            Statement::LocalDecl {
                ty,
                name: d.java_name(),
                init: Some(Expr::BinOp {
                    op: *op,
                    lhs: Box::new(Expr::Var(lhs.java_name())),
                    rhs: Box::new(Expr::Var(rhs.java_name())),
                }),
            }
        }),

        _ => None,
    }
}

fn build_invoke_expr(
    kind: InvokeKind,
    object: Option<&SsaVar>,
    class: &str,
    method: &str,
    args: Vec<Expr>,
    ret_type: &JavaType,
) -> Expr {
    if kind == InvokeKind::Static {
        return Expr::InvokeStatic {
            class: class.to_owned(),
            method: method.to_owned(),
            args,
            ret: ret_type.clone(),
        };
    }
    let obj = object.map_or(Expr::This, |v| Expr::Var(v.java_name()));
    match kind {
        InvokeKind::Virtual | InvokeKind::Interface => Expr::InvokeVirtual {
            object: Box::new(obj),
            method: method.to_owned(),
            args,
            ret: ret_type.clone(),
        },
        InvokeKind::Direct => Expr::InvokeDirect {
            object: Box::new(obj),
            method: method.to_owned(),
            args,
            ret: ret_type.clone(),
        },
        InvokeKind::Super => Expr::InvokeSuper {
            method: method.to_owned(),
            args,
            ret: ret_type.clone(),
        },
        InvokeKind::Static => unreachable!(),
    }
}

fn invoke_to_stmt(
    insn: &SsaInsn,
    expr: Expr,
    ret_type: &JavaType,
    locals: &mut Vec<(String, JavaType)>,
) -> Statement {
    if ret_type.is_void() {
        Statement::Expr(expr)
    } else if let Some(d) = &insn.dest {
        locals.push((d.java_name(), ret_type.clone()));
        Statement::LocalDecl {
            ty: ret_type.clone(),
            name: d.java_name(),
            init: Some(expr),
        }
    } else {
        Statement::Expr(expr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Split `"Lcom/example/Foo;->bar(I)V"` into `("com.example.Foo", "bar")`.
fn split_method_ref(r: &str) -> (&str, &str) {
    r.find("->").map_or((r, ""), |arrow| {
        let class = &r[..arrow];
        let method = &r[arrow + 2..];
        let method = method.find('(').map_or(method, |i| &method[..i]);
        (class, method)
    })
}

fn arith_op(mnemonic: &str) -> BinOp {
    let base = mnemonic.split('/').next().unwrap_or(mnemonic);
    let base = base
        .trim_end_matches("-int")
        .trim_end_matches("-long")
        .trim_end_matches("-float")
        .trim_end_matches("-double");
    match base {
        "sub" | "rsub" => BinOp::Sub,
        "mul" => BinOp::Mul,
        "div" => BinOp::Div,
        "rem" => BinOp::Rem,
        "and" => BinOp::And,
        "or" => BinOp::Or,
        "xor" => BinOp::Xor,
        "shl" => BinOp::Shl,
        "shr" => BinOp::Shr,
        "ushr" => BinOp::UShr,
        _ => BinOp::Add,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insn(mnemonic: &str) -> DalvikInsn {
        DalvikInsn {
            offset: 0,
            mnemonic: mnemonic.to_owned(),
            dest: None,
            srcs: vec![],
            lit: None,
            string: None,
            type_ref: None,
            method_ref: None,
            field_ref: None,
            branch_target: None,
        }
    }

    #[test]
    fn test_dalvik_insn_is_return() {
        assert!(make_insn("return-void").is_return());
        assert!(make_insn("return").is_return());
        assert!(!make_insn("nop").is_return());
    }

    #[test]
    fn test_dalvik_insn_is_invoke() {
        assert!(make_insn("invoke-virtual").is_invoke());
        assert!(make_insn("invoke-static").is_invoke());
        assert!(!make_insn("nop").is_invoke());
    }

    #[test]
    fn test_dalvik_insn_is_branch() {
        assert!(make_insn("goto").is_branch());
        assert!(make_insn("if-eq").is_branch());
        assert!(!make_insn("nop").is_branch());
    }

    #[test]
    fn test_ssa_var_java_name_v0() {
        let v = SsaVar::new("r0", 0);
        assert_eq!(v.java_name(), "r0");
    }

    #[test]
    fn test_ssa_var_java_name_versioned() {
        let v = SsaVar::new("r0", 3);
        assert_eq!(v.java_name(), "r0_3");
    }

    #[test]
    fn test_ssa_builder_new_version() {
        let mut b = SsaBuilder::new();
        let v0 = b.new_version(0);
        let v1 = b.new_version(0);
        assert_eq!(v0.version, 0);
        assert_eq!(v1.version, 1);
    }

    #[test]
    fn test_ssa_builder_current() {
        let mut b = SsaBuilder::new();
        b.new_version(5);
        let cur = b.current(5);
        assert_eq!(cur.version, 0);
        b.new_version(5);
        let cur2 = b.current(5);
        assert_eq!(cur2.version, 1);
    }

    #[test]
    fn test_build_return_void() {
        let mut builder = SsaBuilder::new();
        let insns = vec![make_insn("return-void")];
        let ssa = builder.build("test", "Lfoo;", &insns);
        let entry = ssa.entry_block().expect("entry");
        assert!(
            entry
                .instructions
                .iter()
                .any(|i| matches!(&i.op, SsaOp::Return(None)))
        );
    }

    #[test]
    fn test_build_const_lit() {
        let mut insn = make_insn("const/4");
        insn.dest = Some(0);
        insn.lit = Some(42);
        let mut builder = SsaBuilder::new();
        let ssa = builder.build("test", "Lfoo;", &[insn]);
        let entry = ssa.entry_block().expect("entry");
        assert!(
            entry
                .instructions
                .iter()
                .any(|i| matches!(&i.op, SsaOp::IntLit(42)))
        );
    }

    #[test]
    fn test_lift_to_java_return_void() {
        let mut builder = SsaBuilder::new();
        let insns = vec![make_insn("return-void")];
        let ssa = builder.build("<init>", "Lfoo;", &insns);
        let method = lift_to_java(
            &ssa,
            Modifiers::public(),
            vec![],
            JavaType::Primitive(Primitive::Void),
        );
        assert!(method.body.as_ref().is_some_and(|b| !b.is_empty()));
    }

    #[test]
    fn test_split_method_ref() {
        let (cls, meth) = split_method_ref("Ljava/lang/Object;-><init>()V");
        assert_eq!(cls, "Ljava/lang/Object;");
        assert_eq!(meth, "<init>");
    }

    #[test]
    fn test_arith_op() {
        assert_eq!(arith_op("add-int"), BinOp::Add);
        assert_eq!(arith_op("sub-long"), BinOp::Sub);
        assert_eq!(arith_op("mul-float"), BinOp::Mul);
    }

    #[test]
    fn test_invoke_kind_eq() {
        assert_eq!(InvokeKind::Static, InvokeKind::Static);
        assert_ne!(InvokeKind::Static, InvokeKind::Virtual);
    }
}
