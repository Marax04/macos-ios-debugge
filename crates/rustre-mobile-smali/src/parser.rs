//! `parser` — Recursive-descent parser for Smali source files.
//!
//! Consumes a token stream produced by `lexer::tokenize()` and emits a
//! `SmaliFile` containing all class/method/field definitions.

use super::lexer::{RegisterKind, Spanned, Token};
use super::{
    SmaliAccess, SmaliClass, SmaliError, SmaliField, SmaliInstr, SmaliMethod, SmaliOp,
    SmaliOperand, SmaliReg,
};

// ─────────────────────────────────────────────────────────────────────────────
// ParsedFile
// ─────────────────────────────────────────────────────────────────────────────

/// The top-level result of parsing a single `.smali` file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmaliFile {
    /// The primary class defined in this file.
    pub class: SmaliClass,
    /// Source file annotation from `.source`.
    pub source_file: Option<String>,
    /// Any annotations attached at the class level.
    pub class_annotations: Vec<SmaliAnnotation>,
}

/// A parsed annotation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmaliAnnotation {
    /// Visibility: `system`, `build`, `runtime`.
    pub visibility: String,
    /// Type descriptor of the annotation class.
    pub type_desc: String,
    /// Key-value pairs.
    pub elements: Vec<(String, SmaliAnnotationValue)>,
}

/// The value of an annotation element.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SmaliAnnotationValue {
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
    Type(String),
    Enum(String, String), // (type, field)
    Array(Vec<Self>),
    Null,
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser state
// ─────────────────────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Spanned>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Spanned>) -> Self {
        // Strip Newline tokens for easier lookahead.
        let tokens: Vec<_> = tokens
            .into_iter()
            .filter(|s| !matches!(s.token, Token::Newline))
            .collect();
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).map_or(&Token::Eof, |s| &s.token)
    }

    fn advance(&mut self) -> &Token {
        let tok = self.tokens.get(self.pos).map_or(&Token::Eof, |s| &s.token);
        self.pos += 1;
        tok
    }

    fn consume_ident_like(&mut self) -> Option<String> {
        match self.peek().clone() {
            Token::Ident(s)
            | Token::TypeDesc(s)
            | Token::Keyword(s)
            | Token::Opcode(s)
            | Token::Directive(s) => {
                self.advance();
                Some(s)
            }
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level parse entry
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a list of tokens (as produced by `lexer::tokenize`) into a `SmaliFile`.
///
/// # Errors
///
/// Returns [`SmaliError`] if the token stream does not form a valid Smali file
/// (e.g. missing class/super directive operands).
pub fn parse(tokens: Vec<Spanned>) -> Result<SmaliFile, SmaliError> {
    let mut p = Parser::new(tokens);
    parse_file(&mut p)
}

/// Parse a Smali source string directly.
///
/// # Errors
///
/// Returns [`SmaliError`] if lexing fails or the resulting token stream cannot
/// be parsed into a valid Smali file.
pub fn parse_str(src: &str) -> Result<SmaliFile, SmaliError> {
    let tokens = super::lexer::tokenize(src)?;
    parse(tokens)
}

fn parse_file(p: &mut Parser) -> Result<SmaliFile, SmaliError> {
    let mut source_file: Option<String> = None;
    let mut class_name = String::new();
    let mut super_class = "Ljava/lang/Object;".to_owned();
    let mut access = SmaliAccess::empty();
    let mut interfaces: Vec<String> = Vec::new();
    let mut methods: Vec<SmaliMethod> = Vec::new();
    let mut fields: Vec<SmaliField> = Vec::new();
    let mut class_annotations: Vec<SmaliAnnotation> = Vec::new();

    while !matches!(p.peek(), Token::Eof) {
        match p.peek().clone() {
            Token::Directive(d) => match d.as_str() {
                "class" => {
                    p.advance();
                    access = parse_access_flags(p);
                    class_name = consume_type_or_ident(p)
                        .ok_or_else(|| SmaliError::ParseError("expected class name".to_owned()))?;
                }
                "super" => {
                    p.advance();
                    super_class = consume_type_or_ident(p)
                        .ok_or_else(|| SmaliError::ParseError("expected super class".to_owned()))?;
                }
                "source" => {
                    p.advance();
                    if let Token::StringLiteral(s) = p.peek().clone() {
                        p.advance();
                        source_file = Some(s);
                    }
                }
                "implements" => {
                    p.advance();
                    if let Some(iface) = consume_type_or_ident(p) {
                        interfaces.push(iface);
                    }
                }
                "field" => {
                    p.advance();
                    if let Ok(field) = parse_field(p, &class_name) {
                        fields.push(field);
                    }
                }
                "method" => {
                    p.advance();
                    if let Ok(method) = parse_method(p, &class_name) {
                        methods.push(method);
                    }
                }
                "annotation" => {
                    p.advance();
                    class_annotations.push(parse_annotation(p));
                }
                _ => {
                    p.advance();
                }
            },
            _ => {
                p.advance();
            }
        }
    }

    Ok(SmaliFile {
        class: SmaliClass {
            name: class_name,
            super_class,
            access,
            methods,
            fields,
            interfaces,
        },
        source_file,
        class_annotations,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Access flags
// ─────────────────────────────────────────────────────────────────────────────

fn parse_access_flags(p: &mut Parser) -> SmaliAccess {
    let mut flags = SmaliAccess::empty();
    while let Token::Keyword(kw) = p.peek().clone() {
        flags |= match kw.as_str() {
            "public" => SmaliAccess::PUBLIC,
            "private" => SmaliAccess::PRIVATE,
            "protected" => SmaliAccess::PROTECTED,
            "static" => SmaliAccess::STATIC,
            "final" => SmaliAccess::FINAL,
            "constructor" => SmaliAccess::CONSTRUCTOR,
            "native" => SmaliAccess::NATIVE,
            "abstract" => SmaliAccess::ABSTRACT,
            _ => SmaliAccess::empty(),
        };
        p.advance();
    }
    flags
}

// ─────────────────────────────────────────────────────────────────────────────
// Field
// ─────────────────────────────────────────────────────────────────────────────

fn parse_field(p: &mut Parser, _class: &str) -> Result<SmaliField, SmaliError> {
    let access = parse_access_flags(p);
    // Field header: `name:TypeDesc`
    let header = consume_ident_or_str(p)
        .ok_or_else(|| SmaliError::ParseError("expected field name:type".to_owned()))?;
    let (name, type_desc) = if let Some(colon) = header.find(':') {
        (header[..colon].to_owned(), header[colon + 1..].to_owned())
    } else if let Token::Label(l) = p.peek().clone() {
        // The lexer reads `name:Type` (no surrounding whitespace) as an
        // identifier followed by a `:Type` label token; recover the type from
        // the label text after the leading colon.
        p.advance();
        (header, l.trim_start_matches(':').to_owned())
    } else {
        // Try next token as separate type.
        if matches!(p.peek(), Token::Colon) {
            p.advance();
        }
        let td = consume_type_or_ident(p).unwrap_or_default();
        (header, td)
    };

    // Optional initial value `= <literal>`
    let initial = if matches!(p.peek(), Token::Ident(s) if s == "=") {
        p.advance();
        if let Token::IntLiteral(n) = p.peek().clone() {
            p.advance();
            Some(n)
        } else {
            p.advance(); // skip non-int literal
            None
        }
    } else {
        None
    };

    Ok(SmaliField {
        name,
        type_desc,
        access,
        initial,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Method
// ─────────────────────────────────────────────────────────────────────────────

fn parse_method(p: &mut Parser, class: &str) -> Result<SmaliMethod, SmaliError> {
    let access = parse_access_flags(p);

    // Method header: `name(sig)ret` as a single ident token.
    let full = consume_ident_or_str(p)
        .ok_or_else(|| SmaliError::ParseError("expected method signature".to_owned()))?;

    let (name, signature) = if let Some(paren) = full.find('(') {
        (full[..paren].to_owned(), full[paren..].to_owned())
    } else {
        (full, "()V".to_owned())
    };

    // Parse registers directive if present.
    let mut registers: u8 = 0;
    let mut instructions: Vec<SmaliInstr> = Vec::new();

    loop {
        match p.peek().clone() {
            Token::Directive(d) if d == "end method" => {
                p.advance();
                break;
            }
            Token::Directive(d) if d == "registers" => {
                p.advance();
                if let Token::IntLiteral(n) = p.peek().clone() {
                    p.advance();
                    registers = u8::try_from(n.clamp(0, 255)).unwrap_or(0);
                }
            }
            Token::Directive(d) if d == "locals" => {
                p.advance();
                if let Token::IntLiteral(n) = p.peek().clone() {
                    p.advance();
                    registers = u8::try_from(n.clamp(0, 255)).unwrap_or(0);
                }
            }
            Token::Eof => break,
            _ => {
                let instr = parse_instruction(p);
                instructions.push(instr);
            }
        }
    }

    Ok(SmaliMethod {
        name,
        class: class.to_owned(),
        signature,
        access,
        registers,
        instructions,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction
// ─────────────────────────────────────────────────────────────────────────────

fn parse_instruction(p: &mut Parser) -> SmaliInstr {
    // Consume optional label.
    let label = if let Token::Label(l) = p.peek().clone() {
        p.advance();
        Some(l)
    } else {
        None
    };

    // Next must be an opcode or directive (for `.line`, `.catch`, etc.).
    let op_str = match p.peek().clone() {
        Token::Opcode(s) => {
            p.advance();
            s
        }
        Token::Directive(d) => {
            p.advance();
            consume_rest_of_line(p);
            return SmaliInstr {
                op: SmaliOp::Other(format!(".{d}")),
                operands: vec![],
                label,
            };
        }
        Token::Eof => {
            return SmaliInstr {
                op: SmaliOp::Nop,
                operands: vec![],
                label,
            };
        }
        other => {
            // Skip unexpected token.
            let s = format!("{other:?}");
            p.advance();
            return SmaliInstr {
                op: SmaliOp::Other(s),
                operands: vec![],
                label,
            };
        }
    };

    let op = opcode_from_str(&op_str);
    let operands = parse_operands(p);

    SmaliInstr {
        op,
        operands,
        label,
    }
}

fn consume_rest_of_line(p: &mut Parser) {
    // Consume until we see something that looks like the start of a new statement.
    while !matches!(
        p.peek(),
        Token::Eof | Token::Directive(_) | Token::Opcode(_) | Token::Label(_)
    ) {
        p.advance();
    }
}

fn parse_operands(p: &mut Parser) -> Vec<SmaliOperand> {
    let mut operands = Vec::new();

    // Handle register range `{v0 .. v3}` or register list `{v0, v1}`.
    if matches!(p.peek(), Token::LBrace) {
        p.advance();
        while !matches!(p.peek(), Token::RBrace | Token::Eof) {
            if let Token::Register(n, kind) = p.peek().clone() {
                p.advance();
                let n_lo = u8::try_from(n & 0xff).unwrap_or(0);
                let reg_num = if kind == RegisterKind::Param {
                    64u8.saturating_add(n_lo)
                } else {
                    n_lo
                };
                operands.push(SmaliOperand::Reg(SmaliReg { num: reg_num }));
            } else if matches!(p.peek(), Token::Comma) {
                p.advance();
            } else if matches!(p.peek(), Token::DotDot) {
                p.advance(); // range syntax `{v0 .. v3}` — skip the `..`
            } else {
                break;
            }
        }
        if matches!(p.peek(), Token::RBrace) {
            p.advance();
        }
        // Consume the trailing method reference if present.
        if matches!(p.peek(), Token::Comma) {
            p.advance();
        }
    }

    // Now consume comma-separated operands.
    loop {
        match p.peek().clone() {
            Token::Eof
            | Token::Directive(_)
            | Token::Opcode(_)
            | Token::Label(_)
            | Token::LBrace => break,
            Token::Comma => {
                p.advance();
            }
            Token::Register(n, kind) => {
                p.advance();
                let n_lo = u8::try_from(n & 0xff).unwrap_or(0);
                let reg_num = if kind == RegisterKind::Param {
                    64u8.saturating_add(n_lo)
                } else {
                    n_lo
                };
                operands.push(SmaliOperand::Reg(SmaliReg { num: reg_num }));
            }
            Token::IntLiteral(n) => {
                p.advance();
                operands.push(SmaliOperand::Literal(n));
            }
            Token::FloatLiteral(f) => {
                p.advance();
                // Reinterpret the float's bit pattern as i64 to losslessly preserve it.
                operands.push(SmaliOperand::Literal(i64::from_le_bytes(f.to_le_bytes())));
            }
            Token::StringLiteral(s) => {
                p.advance();
                operands.push(SmaliOperand::Str(s));
            }
            Token::NullLiteral => {
                p.advance();
                operands.push(SmaliOperand::Literal(0));
            }
            Token::TypeDesc(t) => {
                p.advance();
                // Could be a type ref or the start of a field/method ref.
                if matches!(p.peek(), Token::Arrow) {
                    p.advance(); // ->
                    if let Some(rest) = consume_ident_or_str(p) {
                        // field or method ref
                        let full = format!("{t}->{rest}");
                        if rest.contains('(') {
                            operands.push(SmaliOperand::MethodRef(full));
                        } else {
                            operands.push(SmaliOperand::FieldRef(full));
                        }
                    } else {
                        operands.push(SmaliOperand::TypeRef(t));
                    }
                } else {
                    operands.push(SmaliOperand::TypeRef(t));
                }
            }
            Token::Ident(s) => {
                p.advance();
                if matches!(p.peek(), Token::Arrow) {
                    p.advance(); // ->
                    if let Some(rest) = consume_ident_or_str(p) {
                        let full = format!("{s}->{rest}");
                        if rest.contains('(') {
                            operands.push(SmaliOperand::MethodRef(full));
                        } else {
                            operands.push(SmaliOperand::FieldRef(full));
                        }
                    } else {
                        operands.push(SmaliOperand::TypeRef(s));
                    }
                } else if s == "null" {
                    operands.push(SmaliOperand::Literal(0));
                } else {
                    operands.push(SmaliOperand::TypeRef(s));
                }
            }
            _ => {
                p.advance();
                break;
            }
        }
    }
    operands
}

// ─────────────────────────────────────────────────────────────────────────────
// Annotation
// ─────────────────────────────────────────────────────────────────────────────

fn parse_annotation(p: &mut Parser) -> SmaliAnnotation {
    let visibility = p.consume_ident_like().unwrap_or_default();
    let type_desc = consume_type_or_ident(p).unwrap_or_default();
    let mut elements = Vec::new();

    loop {
        match p.peek().clone() {
            Token::Directive(d) if d == "end annotation" => {
                p.advance();
                break;
            }
            Token::Eof => break,
            Token::Ident(key) => {
                p.advance();
                // Expect `=`
                if let Token::Ident(eq) = p.peek().clone()
                    && eq == "="
                {
                    p.advance();
                }
                let val = parse_annotation_value(p);
                elements.push((key, val));
            }
            _ => {
                p.advance();
            }
        }
    }

    SmaliAnnotation {
        visibility,
        type_desc,
        elements,
    }
}

fn parse_annotation_value(p: &mut Parser) -> SmaliAnnotationValue {
    let token = p.peek().clone();
    p.advance();
    match token {
        Token::IntLiteral(n) => SmaliAnnotationValue::Int(n),
        Token::FloatLiteral(f) => SmaliAnnotationValue::Float(f),
        Token::StringLiteral(s) => SmaliAnnotationValue::String(s),
        Token::TypeDesc(t) => SmaliAnnotationValue::Type(t),
        _ => SmaliAnnotationValue::Null,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Opcode mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map a mnemonic to a [`SmaliOp`].
#[must_use]
pub fn opcode_from_str(s: &str) -> SmaliOp {
    match s {
        "nop" => SmaliOp::Nop,
        "move" | "move/from16" | "move/16" => SmaliOp::Move,
        "move-wide" | "move-wide/from16" | "move-wide/16" => SmaliOp::MoveWide,
        "move-object" | "move-object/from16" | "move-object/16" => SmaliOp::MoveObject,
        "move-result" | "move-result-wide" | "move-result-object" => SmaliOp::MoveResult,
        "return-void" => SmaliOp::ReturnVoid,
        "return" | "return-wide" | "return-object" => SmaliOp::Return,
        "const/4" => SmaliOp::Const4,
        "const/16" => SmaliOp::Const16,
        "const" | "const/high16" | "const-wide" | "const-wide/16" | "const-wide/32"
        | "const-wide/high16" => SmaliOp::Const,
        "const-string" | "const-string/jumbo" => SmaliOp::ConstString,
        "goto" | "goto/16" | "goto/32" => SmaliOp::Goto,
        "if-eq" => SmaliOp::IfEq,
        "if-ne" => SmaliOp::IfNe,
        "if-lt" => SmaliOp::IfLt,
        "if-ge" => SmaliOp::IfGe,
        "if-gt" => SmaliOp::IfGt,
        "if-le" => SmaliOp::IfLe,
        "if-eqz" => SmaliOp::IfEqz,
        "if-nez" => SmaliOp::IfNez,
        "if-ltz" | "if-gez" | "if-gtz" | "if-lez" => SmaliOp::Other(s.to_owned()),
        "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-byte" | "iget-char"
        | "iget-short" => SmaliOp::IGet,
        "iput" | "iput-wide" | "iput-object" | "iput-boolean" | "iput-byte" | "iput-char"
        | "iput-short" => SmaliOp::IPut,
        "sget" | "sget-wide" | "sget-object" | "sget-boolean" | "sget-byte" | "sget-char"
        | "sget-short" => SmaliOp::SGet,
        "sput" | "sput-wide" | "sput-object" | "sput-boolean" | "sput-byte" | "sput-char"
        | "sput-short" => SmaliOp::SPut,
        "invoke-virtual" | "invoke-virtual/range" => SmaliOp::InvokeVirtual,
        "invoke-super" | "invoke-super/range" => SmaliOp::InvokeSuper,
        "invoke-direct" | "invoke-direct/range" => SmaliOp::InvokeDirect,
        "invoke-static" | "invoke-static/range" => SmaliOp::InvokeStatic,
        "invoke-interface" | "invoke-interface/range" => SmaliOp::InvokeInterface,
        "new-instance" => SmaliOp::NewInstance,
        "array-length" => SmaliOp::ArrayLength,
        "check-cast" => SmaliOp::CheckCast,
        other => SmaliOp::Other(other.to_owned()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn consume_type_or_ident(p: &mut Parser) -> Option<String> {
    match p.peek().clone() {
        Token::TypeDesc(s) | Token::Ident(s) | Token::Keyword(s) => {
            p.advance();
            Some(s)
        }
        _ => None,
    }
}

fn consume_ident_or_str(p: &mut Parser) -> Option<String> {
    match p.peek().clone() {
        Token::Ident(s)
        | Token::TypeDesc(s)
        | Token::Opcode(s)
        | Token::Keyword(s)
        | Token::StringLiteral(s) => {
            p.advance();
            Some(s)
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_CLASS: &str = r#"
.class public Lcom/example/Foo;
.super Ljava/lang/Object;
.source "Foo.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static bar(I)I
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
"#;

    #[test]
    fn test_parse_class_name() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        assert_eq!(file.class.name, "Lcom/example/Foo;");
    }

    #[test]
    fn test_parse_super() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        assert_eq!(file.class.super_class, "Ljava/lang/Object;");
    }

    #[test]
    fn test_parse_source() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        assert_eq!(file.source_file.as_deref(), Some("Foo.java"));
    }

    #[test]
    fn test_parse_method_count() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        assert_eq!(file.class.methods.len(), 2);
    }

    #[test]
    fn test_parse_constructor() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        let ctor = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "<init>")
            .expect("constructor");
        assert!(ctor.is_constructor());
        assert!(ctor.access.contains(SmaliAccess::PUBLIC));
    }

    #[test]
    fn test_parse_static_method() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        let bar = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "bar")
            .expect("bar");
        assert!(bar.access.contains(SmaliAccess::STATIC));
    }

    #[test]
    fn test_parse_registers() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        let bar = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "bar")
            .expect("bar");
        assert_eq!(bar.registers, 2);
    }

    #[test]
    fn test_parse_instructions_not_empty() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        let bar = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "bar")
            .expect("bar");
        assert!(!bar.instructions.is_empty());
    }

    #[test]
    fn test_parse_return_void_instr() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        let ctor = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "<init>")
            .expect("ctor");
        assert!(
            ctor.instructions
                .iter()
                .any(|i| i.op == SmaliOp::ReturnVoid)
        );
    }

    #[test]
    fn test_parse_field() {
        let src = ".class public Lfoo;\n.super Ljava/lang/Object;\n.field private count:I\n";
        let file = parse_str(src).expect("parse");
        assert_eq!(file.class.fields.len(), 1);
        assert_eq!(file.class.fields[0].name, "count");
        assert_eq!(file.class.fields[0].type_desc, "I");
    }

    #[test]
    fn test_parse_interface() {
        let src = ".class public interface Lfoo;\n.super Ljava/lang/Object;\n.implements Ljava/io/Serializable;\n";
        let file = parse_str(src).expect("parse");
        assert!(!file.class.interfaces.is_empty());
    }

    #[test]
    fn test_parse_access_flags() {
        let file = parse_str(SIMPLE_CLASS).expect("parse");
        assert!(file.class.access.contains(SmaliAccess::PUBLIC));
    }

    #[test]
    fn test_parse_empty_method() {
        let src = ".class public Lfoo;\n.super Ljava/lang/Object;\n.method public doNothing()V\n    return-void\n.end method\n";
        let file = parse_str(src).expect("parse");
        assert_eq!(file.class.methods.len(), 1);
    }

    #[test]
    fn test_opcode_mapping() {
        assert_eq!(opcode_from_str("nop"), SmaliOp::Nop);
        assert_eq!(opcode_from_str("invoke-virtual"), SmaliOp::InvokeVirtual);
        assert_eq!(opcode_from_str("invoke-direct"), SmaliOp::InvokeDirect);
        assert_eq!(opcode_from_str("return-void"), SmaliOp::ReturnVoid);
        assert_eq!(opcode_from_str("const/4"), SmaliOp::Const4);
        assert_eq!(opcode_from_str("const-string"), SmaliOp::ConstString);
        assert_eq!(opcode_from_str("new-instance"), SmaliOp::NewInstance);
    }

    #[test]
    fn test_parse_const_string_operand() {
        let src = r#".class public Lfoo;
.super Ljava/lang/Object;
.method public test()V
    .registers 1
    const-string v0, "hello"
    return-void
.end method
"#;
        let file = parse_str(src).expect("parse");
        let test = file
            .class
            .methods
            .iter()
            .find(|m| m.name == "test")
            .expect("test");
        let cs = test
            .instructions
            .iter()
            .find(|i| i.op == SmaliOp::ConstString)
            .expect("const-string");
        assert!(
            cs.operands
                .iter()
                .any(|o| matches!(o, SmaliOperand::Str(s) if s == "hello"))
        );
    }
}
