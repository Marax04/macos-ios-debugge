//! Post-structuring AST transformations.
//!
//! These passes run on a fully structured `StructuredNode` tree and refine
//! the output into higher-level idioms that the initial DREAM pass leaves
//! unmerged:
//!
//! * **Short-circuit synthesis** — fuse `if (a) { if (b) { … } }` into
//!   `if (a && b) { … }`, and `if (a) { x } else { if (b) { x } }` /
//!   the dual into `if (a || b) { x }`.
//! * **For-loop synthesis** — recognise a `while`-shaped loop whose body
//!   ends with an `Assign` matching the loop induction variable and convert
//!   the kind to `For`.  The init and step are encoded into the `condition`
//!   string as `init; cond; step` so the C emitter can render them.
//! * **Switch-from-chain synthesis** — collapse an `if (x == c1) … else if
//!   (x == c2) …` chain into a single `Switch` over `x`.
//!
//! All passes preserve semantics: when a pattern does not match exactly,
//! the original node is returned unchanged.

use crate::{LoopKind, Statement, StructuredAst, StructuredNode, SwitchCase};

/// Run every post-pass in the standard order on a `StructuredAst`.
#[must_use]
pub fn run_all(ast: StructuredAst) -> StructuredAst {
    let root = transform(ast.root);
    let goto_count = root.goto_count();
    StructuredAst {
        root,
        goto_count,
        ..ast
    }
}

/// Recursive transform — descends children first, then applies local fusions.
#[must_use]
pub fn transform(node: StructuredNode) -> StructuredNode {
    // Post-order: first transform children.
    let descended = match node {
        StructuredNode::Sequence(children) => {
            StructuredNode::Sequence(children.into_iter().map(transform).collect())
        }
        StructuredNode::If {
            condition,
            then_branch,
        } => StructuredNode::If {
            condition,
            then_branch: Box::new(transform(*then_branch)),
        },
        StructuredNode::IfElse {
            condition,
            then_branch,
            else_branch,
        } => StructuredNode::IfElse {
            condition,
            then_branch: Box::new(transform(*then_branch)),
            else_branch: Box::new(transform(*else_branch)),
        },
        StructuredNode::Loop {
            kind,
            condition,
            body,
        } => StructuredNode::Loop {
            kind,
            condition,
            body: Box::new(transform(*body)),
        },
        StructuredNode::Switch { expr, cases } => StructuredNode::Switch {
            expr,
            cases: cases
                .into_iter()
                .map(|c| SwitchCase {
                    value: c.value,
                    body: Box::new(transform(*c.body)),
                })
                .collect(),
        },
        other => other,
    };

    // Apply local fusions in order.
    let n = fuse_short_circuit(descended);
    let n = fuse_for_loop(n);
    fuse_switch_chain(n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Short-circuit && / || synthesis
// ─────────────────────────────────────────────────────────────────────────────

/// Fuse nested `If` / `IfElse` patterns into short-circuit form.
#[must_use]
pub fn fuse_short_circuit(node: StructuredNode) -> StructuredNode {
    match node {
        // if (a) { if (b) { t } }  →  if (a && b) { t }
        StructuredNode::If {
            condition: outer,
            then_branch,
        } => match *then_branch {
            StructuredNode::If {
                condition: inner,
                then_branch: inner_then,
            } => StructuredNode::If {
                condition: combine_and(&outer, &inner),
                then_branch: inner_then,
            },
            other => StructuredNode::If {
                condition: outer,
                then_branch: Box::new(other),
            },
        },

        // if (a) { t } else { if (b) { t' } else { e } }
        //   special case where t' == t  →  if (a || b) { t } else { e }
        StructuredNode::IfElse {
            condition: outer,
            then_branch,
            else_branch,
        } => {
            if let StructuredNode::If {
                condition: inner,
                then_branch: inner_then,
            } = &*else_branch
                && structurally_equal(&then_branch, inner_then) {
                    // if (a) { t } else { if (b) { t } }  →  if (a || b) { t }
                    return StructuredNode::If {
                        condition: combine_or(&outer, inner),
                        then_branch,
                    };
                }
            if let StructuredNode::IfElse {
                condition: inner,
                then_branch: inner_then,
                else_branch: inner_else,
            } = &*else_branch
                && structurally_equal(&then_branch, inner_then) {
                    // if (a) { t } else { if (b) { t } else { e } }
                    //   →  if (a || b) { t } else { e }
                    return StructuredNode::IfElse {
                        condition: combine_or(&outer, inner),
                        then_branch,
                        else_branch: inner_else.clone(),
                    };
                }
            StructuredNode::IfElse {
                condition: outer,
                then_branch,
                else_branch,
            }
        }

        other => other,
    }
}

fn combine_and(a: &str, b: &str) -> String {
    format!("({a}) && ({b})")
}

fn combine_or(a: &str, b: &str) -> String {
    format!("({a}) || ({b})")
}

fn structurally_equal(a: &StructuredNode, b: &StructuredNode) -> bool {
    a == b
}

// ─────────────────────────────────────────────────────────────────────────────
// For-loop synthesis
// ─────────────────────────────────────────────────────────────────────────────

/// Recognise a `while` whose body ends with an induction-variable assignment
/// and convert it to a `For`.
///
/// The init (when present as the previous sibling in an enclosing
/// `Sequence`) is fused into the loop condition string using the C-friendly
/// format `init; cond; step` so the emitter can split it.  When no init is
/// available, the format `; cond; step` is used.
///
/// Pattern recognised:
/// ```text
/// Sequence([
///   BasicBlock { stmts: [Assign { lhs: i, rhs: init } ] },   // optional
///   Loop { While, cond,
///          body: Sequence([..., BasicBlock { stmts: [..., Assign { lhs: i, rhs: step }] }]) }
/// ])
/// ```
///
/// # Panics
///
/// Panics if a sequence collapses to a single child but the resulting
/// `out` buffer is unexpectedly empty (a logic invariant violation).
#[must_use]
pub fn fuse_for_loop(node: StructuredNode) -> StructuredNode {
    let StructuredNode::Sequence(children) = node else {
        return fuse_for_loop_solo(node);
    };

    let mut out: Vec<StructuredNode> = Vec::with_capacity(children.len());
    let mut i = 0;
    while i < children.len() {
        let take_pair = i + 1 < children.len()
            && matches!(&children[i], StructuredNode::BasicBlock { .. })
            && matches!(&children[i + 1], StructuredNode::Loop { kind: LoopKind::While, .. });
        if take_pair {
            // Try to extract init from the BB and step from the loop body.
            let init_bb = &children[i];
            let loop_node = &children[i + 1];
            if let Some(fused) = try_make_for(init_bb, loop_node) {
                out.push(fused);
                i += 2;
                continue;
            }
        }
        out.push(fuse_for_loop_solo(children[i].clone()));
        i += 1;
    }
    if out.len() == 1 {
        return out.into_iter().next().unwrap();
    }
    StructuredNode::Sequence(out)
}

fn fuse_for_loop_solo(node: StructuredNode) -> StructuredNode {
    // A bare While with a recognisable step in the body — encode as For with
    // empty init.
    if let StructuredNode::Loop {
        kind: LoopKind::While,
        condition,
        body,
    } = &node
        && let Some((step, induct)) = find_trailing_step(body)
            && condition_mentions(condition, &induct) {
                let new_body = strip_trailing_assign(body, &induct);
                return StructuredNode::Loop {
                    kind: LoopKind::For,
                    condition: format!("; {condition}; {step}"),
                    body: Box::new(new_body),
                };
            }
    node
}

fn try_make_for(init_bb: &StructuredNode, loop_node: &StructuredNode) -> Option<StructuredNode> {
    let StructuredNode::BasicBlock { stmts, .. } = init_bb else {
        return None;
    };
    let StructuredNode::Loop {
        kind: LoopKind::While,
        condition,
        body,
    } = loop_node
    else {
        return None;
    };

    // Look at the last Assign of init_bb.
    let init_assign = stmts.iter().rev().find_map(|s| {
        if let Statement::Assign { lhs, rhs } = s {
            Some((lhs.clone(), rhs.clone()))
        } else {
            None
        }
    })?;

    let (step_text, induct) = find_trailing_step(body)?;
    if induct != init_assign.0 {
        return None;
    }
    if !condition_mentions(condition, &induct) {
        return None;
    }
    let init_text = format!("{} = {}", init_assign.0, init_assign.1);
    let new_body = strip_trailing_assign(body, &induct);
    Some(StructuredNode::Loop {
        kind: LoopKind::For,
        condition: format!("{init_text}; {condition}; {step_text}"),
        body: Box::new(new_body),
    })
}

/// Return (`step_text`, `induction_var`) if the loop body's last statement is
/// `Assign { lhs: i, rhs: expr }`.
fn find_trailing_step(body: &StructuredNode) -> Option<(String, String)> {
    let stmts = trailing_stmts(body)?;
    let last = stmts.last()?;
    if let Statement::Assign { lhs, rhs } = last {
        Some((format!("{lhs} = {rhs}"), lhs.clone()))
    } else {
        None
    }
}

fn trailing_stmts(node: &StructuredNode) -> Option<&Vec<Statement>> {
    match node {
        StructuredNode::BasicBlock { stmts, .. } => Some(stmts),
        StructuredNode::Sequence(children) => children.last().and_then(trailing_stmts),
        _ => None,
    }
}

fn condition_mentions(cond: &str, var: &str) -> bool {
    // Token-level membership check; avoids matching substrings of other names.
    cond.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == var)
}

fn strip_trailing_assign(node: &StructuredNode, var: &str) -> StructuredNode {
    match node {
        StructuredNode::BasicBlock { id, stmts } => {
            let mut stmts = stmts.clone();
            if matches!(stmts.last(), Some(Statement::Assign { lhs, .. }) if lhs == var) {
                stmts.pop();
            }
            StructuredNode::BasicBlock {
                id: *id,
                stmts,
            }
        }
        StructuredNode::Sequence(children) => {
            let mut new_children = children.clone();
            if let Some(last) = new_children.pop() {
                let stripped = strip_trailing_assign(&last, var);
                new_children.push(stripped);
            }
            StructuredNode::Sequence(new_children)
        }
        other => other.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Switch synthesis from if-else-if chains
// ─────────────────────────────────────────────────────────────────────────────

/// Detect `if (x == c1) a else if (x == c2) b else …` chains and collapse
/// them into a single `Switch` node when at least three distinct constant
/// comparisons share the same left-hand side.
#[must_use]
pub fn fuse_switch_chain(node: StructuredNode) -> StructuredNode {
    let Some((cases, default, scrutinee)) = collect_chain(&node) else { return node };
    if cases.len() < 3 {
        return node;
    }
    let mut case_nodes: Vec<SwitchCase> = cases
        .into_iter()
        .map(|(v, body)| SwitchCase {
            value: Some(v),
            body: Box::new(body),
        })
        .collect();
    if let Some(d) = default {
        case_nodes.push(SwitchCase {
            value: None,
            body: Box::new(d),
        });
    }
    StructuredNode::Switch {
        expr: scrutinee,
        cases: case_nodes,
    }
}

/// What [`collect_chain`] recovers from an else-if ladder: the `(value, body)`
/// pairs in source order, the trailing `else` body if there is one, and the
/// scrutinee expression every arm compares against.
///
/// Named because the bare tuple needed an `#[allow(clippy::type_complexity)]`,
/// and because a reader meeting `(Vec<(i64, _)>, Option<_>, String)` at a call
/// site has no way to know which `String` it is.
type SwitchChain = (Vec<(i64, StructuredNode)>, Option<StructuredNode>, String);

fn collect_chain(node: &StructuredNode) -> Option<SwitchChain> {
    let mut current = node.clone();
    let mut cases: Vec<(i64, StructuredNode)> = Vec::new();
    let mut scrutinee: Option<String> = None;
    loop {
        match current {
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => {
                let (var, val) = parse_eq_condition(&condition)?;
                if let Some(ref s) = scrutinee {
                    if s != &var {
                        return None;
                    }
                } else {
                    scrutinee = Some(var);
                }
                cases.push((val, *then_branch));
                current = *else_branch;
            }
            StructuredNode::If {
                condition,
                then_branch,
            } => {
                let (var, val) = parse_eq_condition(&condition)?;
                if let Some(ref s) = scrutinee {
                    if s != &var {
                        return None;
                    }
                } else {
                    scrutinee = Some(var);
                }
                cases.push((val, *then_branch));
                return Some((cases, None, scrutinee?));
            }
            other => {
                // Terminal else arm — treat as default.
                return Some((cases, Some(other), scrutinee?));
            }
        }
    }
}

/// Parse a condition shaped like `x == 3` and return `(x, 3)`.  Whitespace
/// around the operator is tolerated; either side may carry the constant.
fn parse_eq_condition(cond: &str) -> Option<(String, i64)> {
    let s = cond.trim();
    let parts: Vec<&str> = s.split("==").collect();
    if parts.len() != 2 {
        return None;
    }
    let lhs = parts[0].trim();
    let rhs = parts[1].trim();
    if let Ok(v) = rhs.parse::<i64>() {
        return Some((lhs.to_string(), v));
    }
    if let Ok(v) = lhs.parse::<i64>() {
        return Some((rhs.to_string(), v));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockId;

    fn bb(id: u32, stmts: Vec<Statement>) -> StructuredNode {
        StructuredNode::BasicBlock {
            id: BlockId::new(id),
            stmts,
        }
    }

    #[test]
    fn short_circuit_and() {
        let inner = StructuredNode::If {
            condition: "b".to_string(),
            then_branch: Box::new(bb(2, vec![])),
        };
        let outer = StructuredNode::If {
            condition: "a".to_string(),
            then_branch: Box::new(inner),
        };
        let fused = fuse_short_circuit(outer);
        match fused {
            StructuredNode::If { condition, .. } => {
                assert!(condition.contains("&&"));
                assert!(condition.contains('a'));
                assert!(condition.contains('b'));
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn short_circuit_or() {
        let target = bb(9, vec![Statement::Return(Some("1".to_string()))]);
        let inner = StructuredNode::If {
            condition: "b".to_string(),
            then_branch: Box::new(target.clone()),
        };
        let outer = StructuredNode::IfElse {
            condition: "a".to_string(),
            then_branch: Box::new(target),
            else_branch: Box::new(inner),
        };
        let fused = fuse_short_circuit(outer);
        match fused {
            StructuredNode::If { condition, .. } => {
                assert!(condition.contains("||"));
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn switch_chain_collapse() {
        // if (x == 1) A else if (x == 2) B else if (x == 3) C else D
        let chain = StructuredNode::IfElse {
            condition: "x == 1".to_string(),
            then_branch: Box::new(bb(1, vec![])),
            else_branch: Box::new(StructuredNode::IfElse {
                condition: "x == 2".to_string(),
                then_branch: Box::new(bb(2, vec![])),
                else_branch: Box::new(StructuredNode::IfElse {
                    condition: "x == 3".to_string(),
                    then_branch: Box::new(bb(3, vec![])),
                    else_branch: Box::new(bb(4, vec![])),
                }),
            }),
        };
        let fused = fuse_switch_chain(chain);
        match fused {
            StructuredNode::Switch { expr, cases } => {
                assert_eq!(expr, "x");
                assert_eq!(cases.len(), 4); // 3 cases + default
                assert_eq!(cases[0].value, Some(1));
                assert_eq!(cases[1].value, Some(2));
                assert_eq!(cases[2].value, Some(3));
                assert!(cases[3].value.is_none());
            }
            other => panic!("expected Switch, got {other:?}"),
        }
    }

    #[test]
    fn for_loop_synthesis() {
        // i = 0; while (i < 10) { body; i = i + 1; }
        let init_bb = bb(
            0,
            vec![Statement::Assign {
                lhs: "i".to_string(),
                rhs: "0".to_string(),
            }],
        );
        let body_bb = bb(
            1,
            vec![
                Statement::Raw("work()".to_string()),
                Statement::Assign {
                    lhs: "i".to_string(),
                    rhs: "i + 1".to_string(),
                },
            ],
        );
        let loop_node = StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "i < 10".to_string(),
            body: Box::new(body_bb),
        };
        let seq = StructuredNode::Sequence(vec![init_bb, loop_node]);
        let fused = fuse_for_loop(seq);
        match fused {
            StructuredNode::Loop { kind, condition, .. } => {
                assert_eq!(kind, LoopKind::For);
                assert!(condition.contains("i = 0"));
                assert!(condition.contains("i < 10"));
                assert!(condition.contains("i = i + 1"));
            }
            other => panic!("expected For loop, got {other:?}"),
        }
    }

    #[test]
    fn parse_eq_condition_basic() {
        assert_eq!(parse_eq_condition("x == 5"), Some(("x".to_string(), 5)));
        assert_eq!(parse_eq_condition("7 == y"), Some(("y".to_string(), 7)));
        assert_eq!(parse_eq_condition("x > 5"), None);
    }
}
