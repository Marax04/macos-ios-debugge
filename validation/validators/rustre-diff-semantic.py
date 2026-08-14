"""Validator for rustre-diff-semantic crate."""
import re
from pathlib import Path

CRATE = Path(r"C:\Users\Fra\Desktop\RustRE\crates\rustre-diff-semantic\src")

EXPECTED_MODULES = [
    "ast_differ", "behavior_diff", "call_site_diff", "control_flow_diff",
    "function_diff", "ir_semantic_diff", "lib", "mlil_diff", "patch_analysis",
    "semantic_comparison", "semantic_equivalence", "semantic_hash",
    "similarity", "similarity_score", "type_diff", "variable_diff",
]

EXPECTED_SYMBOLS = [
    "compute_node_hash", "node_similarity", "AstDiffer", "BehaviorDiff",
    "CallSiteDiffer", "ControlFlowDiffer", "diff_signatures",
    "IrSemanticDiffer", "SemanticHash", "make_simple_func",
]


def validate() -> bool:
    if not CRATE.exists():
        print(f"FAIL: missing {CRATE}")
        return False
    files = {p.stem for p in CRATE.glob("*.rs")}
    missing = [m for m in EXPECTED_MODULES if m not in files]
    if missing:
        print(f"FAIL: missing modules {missing}")
        return False
    blob = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in CRATE.glob("*.rs"))
    missing_syms = [s for s in EXPECTED_SYMBOLS if not re.search(rf"\b{s}\b", blob)]
    if missing_syms:
        print(f"FAIL: missing symbols {missing_syms}")
        return False
    pub_count = len(re.findall(r"^pub (fn|struct|enum|trait|async fn)", blob, re.M))
    if pub_count < 150:
        print(f"FAIL: pub items {pub_count} < 150")
        return False
    print(f"OK: {len(files)} modules, {pub_count} pub items")
    return True


if __name__ == "__main__":
    import sys
    sys.exit(0 if validate() else 1)
