//! `lambda_recovery` — Lambda / SAM conversion recovery pass.
//!
//! Modern Android applications compiled with D8/R8 use `invoke-custom` and
//! bootstrap method tables to implement lambda expressions and method
//! references.  This module detects these patterns in the lifted Java AST
//! and converts them back to idiomatic lambda syntax.
//!
//! # Detection patterns
//!
//! | Pattern | Detection | Output |
//! |---------|-----------|--------|
//! | Anonymous inner class implementing a SAM | Class with single method body | `(…) -> body` |
//! | `invoke-dynamic` / `invoke-custom` bootstrap | Static helper + bootstrap desc | `Foo::bar` or `(x) -> …` |
//! | `Runnable` lambda | Anonymous class with `run()` | `() -> { … }` |
//! | `Comparator` | Anonymous class with `compare(a,b)` | `(a, b) -> a - b` |
//!
//! This pass mutates `AstClass` in place, replacing anonymous inner class
//! references with `LambdaExpr` nodes in parent method bodies.

use super::java_ast::{AstClass, AstMethod, Expr, JavaType, LambdaBody, LambdaExpr, Statement};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the lambda recovery pass on a class.
///
/// This replaces eligible anonymous inner classes with lambda expressions
/// inline in the outer class methods.  The pass is idempotent.
pub fn recover_lambdas(cls: &mut AstClass) {
    // Phase 1: identify SAM inner classes.
    let sam_candidates = find_sam_candidates(cls);

    // Phase 2: replace `new AnonymousSAM()` allocations with lambda expressions.
    for method in &mut cls.methods {
        if let Some(body) = &mut method.body {
            rewrite_stmts(body, &sam_candidates);
        }
    }

    // Phase 3: remove the converted inner classes.
    cls.inner_classes.retain(|inner| {
        !sam_candidates
            .iter()
            .any(|c: &SamCandidate| c.class_name == inner.name)
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// SAM candidate detection
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a detected SAM-implementing anonymous inner class.
#[derive(Debug, Clone)]
pub(crate) struct SamCandidate {
    /// Simple name of the anonymous inner class.
    class_name: String,
    /// Name of the single abstract method.
    sam_method: String,
    /// Parameter names and types.
    params: Vec<(String, JavaType)>,
    /// Body statements of the SAM method.
    body: Vec<Statement>,
    /// The functional interface type.
    interface_type: Option<String>,
}

fn find_sam_candidates(cls: &AstClass) -> Vec<SamCandidate> {
    let mut candidates = Vec::new();
    for inner in &cls.inner_classes {
        if let Some(candidate) = try_as_sam(inner) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn try_as_sam(cls: &AstClass) -> Option<SamCandidate> {
    // A SAM candidate:
    // - Is anonymous (has a generated name like `1` or starts with `$`)
    // - Implements exactly one interface
    // - Has exactly one non-constructor method
    // - That method is not native/abstract
    let is_anonymous =
        cls.name.starts_with('$') || cls.name.chars().next().is_some_and(|c| c.is_ascii_digit());

    if !is_anonymous {
        return None;
    }

    if cls.interfaces.len() != 1 {
        return None;
    }

    let concrete_methods: Vec<&AstMethod> = cls
        .methods
        .iter()
        .filter(|m| !m.is_constructor() && !m.modifiers.is_native() && !m.modifiers.is_abstract())
        .collect();

    if concrete_methods.len() != 1 {
        return None;
    }

    let method = concrete_methods[0];
    let body = method.body.clone().unwrap_or_default();

    // If the interface is a well-known SAM, validate that the concrete method
    // name matches the expected SAM method name.  This eliminates false positives
    // where an anonymous class overrides a *different* method of the interface
    // (e.g. a default method) rather than the single abstract one.
    let iface = cls.interfaces.first().map_or("", String::as_str);
    let sam_name = method.name.clone();
    if is_known_sam(iface)
        && let Some(expected) = sam_method_name(iface)
        && sam_name != expected
    {
        return None;
    }

    Some(SamCandidate {
        class_name: cls.name.clone(),
        sam_method: sam_name,
        params: method.params.clone(),
        body,
        interface_type: cls.interfaces.first().cloned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// AST rewriting
// ─────────────────────────────────────────────────────────────────────────────

fn rewrite_stmts(stmts: &mut [Statement], candidates: &[SamCandidate]) {
    for stmt in stmts.iter_mut() {
        rewrite_stmt(stmt, candidates);
    }
}

fn rewrite_stmt(stmt: &mut Statement, candidates: &[SamCandidate]) {
    match stmt {
        Statement::LocalDecl { init: Some(e), .. }
        | Statement::Assign { value: e, .. }
        | Statement::Expr(e)
        | Statement::Return(Some(e))
        | Statement::Throw(e) => {
            rewrite_expr(e, candidates);
        }
        Statement::If { cond, then, else_ } => {
            rewrite_expr(cond, candidates);
            rewrite_stmt(then, candidates);
            if let Some(e) = else_ {
                rewrite_stmt(e, candidates);
            }
        }
        Statement::While { cond, body } => {
            rewrite_expr(cond, candidates);
            rewrite_stmt(body, candidates);
        }
        Statement::Block(stmts) => {
            rewrite_stmts(stmts, candidates);
        }
        Statement::TryCatch {
            body,
            catches,
            finally,
        } => {
            rewrite_stmt(body, candidates);
            for catch in catches {
                rewrite_stmts(&mut catch.body, candidates);
            }
            if let Some(f) = finally {
                rewrite_stmt(f, candidates);
            }
        }
        _ => {}
    }
}

fn rewrite_expr(expr: &mut Expr, candidates: &[SamCandidate]) {
    match expr {
        Expr::NewObject { class, args } => {
            // Check if this `new X(…)` creates a SAM instance.
            if let Some(candidate) = candidates.iter().find(|c| &c.class_name == class) {
                // Detect whether this SAM body is actually a method reference.
                let method_ref_syntax =
                    detect_method_ref(candidate).map(|mr| mr.reference_syntax());
                let lambda = LambdaExpr {
                    params: candidate.params.clone(),
                    body: if candidate.body.len() == 1 {
                        if let Statement::Return(Some(e)) = &candidate.body[0] {
                            LambdaBody::Expr(e.clone())
                        } else {
                            LambdaBody::Block(candidate.body.clone())
                        }
                    } else {
                        LambdaBody::Block(candidate.body.clone())
                    },
                    interface_type: candidate.interface_type.clone(),
                    method_ref_syntax,
                };
                *expr = Expr::Lambda(Box::new(lambda));
                return;
            }
            // Recurse into constructor args.
            for arg in args.iter_mut() {
                rewrite_expr(arg, candidates);
            }
        }
        Expr::InvokeVirtual { object, args, .. }
        | Expr::InvokeDirect { object, args, .. }
        | Expr::InvokeInterface { object, args, .. } => {
            rewrite_expr(object, candidates);
            for arg in args.iter_mut() {
                rewrite_expr(arg, candidates);
            }
        }
        Expr::InvokeStatic { args, .. } | Expr::InvokeSuper { args, .. } => {
            for arg in args.iter_mut() {
                rewrite_expr(arg, candidates);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rewrite_expr(lhs, candidates);
            rewrite_expr(rhs, candidates);
        }
        Expr::UnaryOp { expr: inner, .. } | Expr::Cast { expr: inner, .. } => {
            rewrite_expr(inner, candidates);
        }
        Expr::Ternary { cond, then, else_ } => {
            rewrite_expr(cond, candidates);
            rewrite_expr(then, candidates);
            rewrite_expr(else_, candidates);
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Method reference recovery
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a method reference candidate (e.g. `Foo::bar`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodRefCandidate {
    /// Owning class (simple or FQN).
    pub class: String,
    /// Method name.
    pub method: String,
    /// Whether this is a static method reference.
    pub is_static: bool,
    /// The functional interface type.
    pub interface_type: Option<String>,
}

impl MethodRefCandidate {
    /// Returns the `ClassName::methodName` string.
    #[must_use]
    pub fn reference_syntax(&self) -> String {
        let cls = self.class.rsplit('.').next().unwrap_or(&self.class);
        format!("{}::{}", cls, self.method)
    }
}

/// Detect method-reference patterns in a SAM body.
///
/// A SAM body is a method reference if it consists of a single `return`
/// statement that is a single method call forwarding all parameters.
#[must_use]
pub(crate) fn detect_method_ref(candidate: &SamCandidate) -> Option<MethodRefCandidate> {
    if candidate.body.len() != 1 {
        return None;
    }
    let stmt = &candidate.body[0];

    let (Statement::Return(Some(call)) | Statement::Expr(call)) = stmt else {
        return None;
    };

    // Check if the call is a static invoke whose arguments are exactly
    // the SAM parameters in order.
    if let Expr::InvokeStatic {
        class,
        method,
        args,
        ..
    } = call
    {
        let param_names: Vec<&str> = candidate.params.iter().map(|(n, _)| n.as_str()).collect();
        let arg_names: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                if let Expr::Var(v) = a {
                    Some(v.as_str())
                } else {
                    None
                }
            })
            .collect();

        if param_names == arg_names {
            // Validate: if there is a known expected SAM method name for this
            // interface, confirm the candidate SAM body actually implements it.
            // This prevents accidentally treating a helper method as a SAM.
            let iface = candidate.interface_type.as_deref().unwrap_or("");
            if is_known_sam(iface)
                && let Some(expected) = sam_method_name(iface)
                && candidate.sam_method != expected
            {
                return None;
            }
            return Some(MethodRefCandidate {
                class: class.clone(),
                method: method.clone(),
                is_static: true,
                interface_type: candidate.interface_type.clone(),
            });
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Known SAM interfaces
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the fully-qualified interface name is a well-known SAM.
#[must_use]
pub fn is_known_sam(interface: &str) -> bool {
    matches!(
        interface,
        "java.lang.Runnable"
            | "java.util.concurrent.Callable"
            | "java.util.function.Consumer"
            | "java.util.function.Supplier"
            | "java.util.function.Function"
            | "java.util.function.BiFunction"
            | "java.util.function.Predicate"
            | "java.util.function.BiPredicate"
            | "java.util.function.UnaryOperator"
            | "java.util.function.BinaryOperator"
            | "java.util.Comparator"
            | "android.os.Handler$Callback"
            | "android.view.View$OnClickListener"
            | "android.text.TextWatcher"
    )
}

/// Returns the SAM method name for a known functional interface.
#[must_use]
pub fn sam_method_name(interface: &str) -> Option<&'static str> {
    match interface {
        "java.lang.Runnable" => Some("run"),
        "java.util.concurrent.Callable" => Some("call"),
        "java.util.function.Consumer" => Some("accept"),
        "java.util.function.Supplier" => Some("get"),
        "java.util.function.Function"
        | "java.util.function.UnaryOperator"
        | "java.util.function.BiFunction"
        | "java.util.function.BinaryOperator" => Some("apply"),
        "java.util.function.Predicate" | "java.util.function.BiPredicate" => Some("test"),
        "java.util.Comparator" => Some("compare"),
        "android.view.View$OnClickListener" => Some("onClick"),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::java_ast::{Modifiers, Primitive};
    use super::*;

    fn make_runnable_sam() -> SamCandidate {
        SamCandidate {
            class_name: "$1".to_owned(),
            sam_method: "run".to_owned(),
            params: vec![],
            body: vec![Statement::Return(None)],
            interface_type: Some("java.lang.Runnable".to_owned()),
        }
    }

    #[test]
    fn test_is_known_sam_runnable() {
        assert!(is_known_sam("java.lang.Runnable"));
    }

    #[test]
    fn test_is_known_sam_comparator() {
        assert!(is_known_sam("java.util.Comparator"));
    }

    #[test]
    fn test_is_not_known_sam() {
        assert!(!is_known_sam("com.example.MyCallback"));
    }

    #[test]
    fn test_sam_method_name_runnable() {
        assert_eq!(sam_method_name("java.lang.Runnable"), Some("run"));
    }

    #[test]
    fn test_sam_method_name_consumer() {
        assert_eq!(
            sam_method_name("java.util.function.Consumer"),
            Some("accept")
        );
    }

    #[test]
    fn test_sam_method_name_unknown() {
        assert_eq!(sam_method_name("com.example.Foo"), None);
    }

    #[test]
    fn test_method_ref_candidate_reference_syntax() {
        let c = MethodRefCandidate {
            class: "java.util.Arrays".to_owned(),
            method: "sort".to_owned(),
            is_static: true,
            interface_type: None,
        };
        assert_eq!(c.reference_syntax(), "Arrays::sort");
    }

    #[test]
    fn test_detect_method_ref_simple() {
        let candidate = SamCandidate {
            class_name: "$1".to_owned(),
            sam_method: "run".to_owned(),
            params: vec![("p0".to_owned(), JavaType::Primitive(Primitive::Int))],
            body: vec![Statement::Return(Some(Expr::InvokeStatic {
                class: "java.util.Arrays".to_owned(),
                method: "sort".to_owned(),
                args: vec![Expr::Var("p0".to_owned())],
                ret: JavaType::Primitive(Primitive::Void),
            }))],
            interface_type: Some("java.lang.Runnable".to_owned()),
        };
        let result = detect_method_ref(&candidate);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.method, "sort");
        assert!(r.is_static);
    }

    #[test]
    fn test_detect_method_ref_not_forwarding_params() {
        let candidate = SamCandidate {
            class_name: "$1".to_owned(),
            sam_method: "run".to_owned(),
            params: vec![("p0".to_owned(), JavaType::Primitive(Primitive::Int))],
            body: vec![Statement::Return(Some(Expr::InvokeStatic {
                class: "Foo".to_owned(),
                method: "bar".to_owned(),
                args: vec![Expr::IntLit(0)], // not forwarding p0
                ret: JavaType::Primitive(Primitive::Void),
            }))],
            interface_type: None,
        };
        let result = detect_method_ref(&candidate);
        assert!(result.is_none());
    }

    #[test]
    fn test_runnable_sam_is_known_but_not_method_ref() {
        let sam = make_runnable_sam();
        assert_eq!(sam.interface_type.as_deref(), Some("java.lang.Runnable"));
        assert!(is_known_sam(sam.interface_type.as_deref().unwrap()));
        // A bare `return;` body is not a forwarding method reference.
        assert!(detect_method_ref(&sam).is_none());
    }

    #[test]
    fn test_recover_lambdas_replaces_inner_class() {
        // Build an AstClass with one anonymous inner class (SAM) and a
        // method that creates it.
        let sam_body = vec![Statement::Return(None)];
        let sam_method = AstMethod {
            modifiers: Modifiers::public(),
            name: "run".to_owned(),
            params: vec![],
            return_type: JavaType::Primitive(Primitive::Void),
            body: Some(sam_body),
            throws: vec![],
            annotations: vec![],
            locals: vec![],
        };

        let mut inner = AstClass::new("$1", "com.example");
        inner.interfaces = vec!["java.lang.Runnable".to_owned()];
        inner.methods = vec![sam_method];

        let outer_method = AstMethod {
            modifiers: Modifiers::public(),
            name: "doSomething".to_owned(),
            params: vec![],
            return_type: JavaType::Primitive(Primitive::Void),
            body: Some(vec![
                Statement::LocalDecl {
                    ty: JavaType::Reference("java.lang.Runnable".to_owned()),
                    name: "r".to_owned(),
                    init: Some(Expr::NewObject {
                        class: "$1".to_owned(),
                        args: vec![],
                    }),
                },
                Statement::Return(None),
            ]),
            throws: vec![],
            annotations: vec![],
            locals: vec![],
        };

        let mut cls = AstClass::new("Outer", "com.example");
        cls.inner_classes = vec![inner];
        cls.methods = vec![outer_method];

        recover_lambdas(&mut cls);

        // The inner class should have been removed.
        assert!(cls.inner_classes.is_empty(), "inner classes still present");

        // The method body should contain a lambda.
        let body = cls.methods[0].body.as_ref().expect("body");
        let has_lambda = body.iter().any(|s| {
            matches!(
                s,
                Statement::LocalDecl {
                    init: Some(Expr::Lambda(_)),
                    ..
                }
            )
        });
        assert!(has_lambda, "expected lambda expression in method body");
    }

    #[test]
    fn test_recover_lambdas_noop_on_non_sam() {
        // A class with no inner classes — pass should be a no-op.
        let mut cls = AstClass::mock("Foo", "com.example");
        let method_count = cls.methods.len();
        recover_lambdas(&mut cls);
        assert_eq!(cls.methods.len(), method_count);
    }

    #[test]
    fn test_try_as_sam_non_anonymous() {
        let cls = AstClass::new("NormalClass", "com.example");
        assert!(try_as_sam(&cls).is_none());
    }

    #[test]
    fn test_try_as_sam_multiple_interfaces() {
        let mut cls = AstClass::new("$1", "com.example");
        cls.interfaces = vec!["A".to_owned(), "B".to_owned()];
        assert!(try_as_sam(&cls).is_none());
    }
}
