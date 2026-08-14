"""Independent validator for rustre-graph crate.

Validates the rustre-graph crate against the spec in
validation/reports/rustre-graph.md using only the Python stdlib.

Checks:
- Cargo.toml: name, version, edition, expected dependencies, library-only.
- src/ module layout matches the documented modules.
- Public API surface: count `pub fn` / `pub async fn` across src/.
- Key symbols referenced in the report exist somewhere in src/.
- tests/blitz.rs and tests/blitz2.rs exist.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRATE_NAME = "rustre-graph"

# Resolve crate dir: <repo>/crates/rustre-graph
THIS = Path(__file__).resolve()
REPO = THIS.parents[2]  # .../RustRE
CRATE_DIR = REPO / "crates" / CRATE_NAME

EXPECTED_MODULES = [
    "lib.rs",
    "db.rs",
    "query_engine.rs",
    "analysis_graph.rs",
    "graph_algorithms_extended.rs",
    "graph_persistence.rs",
    "graph_export.rs",
    "collaboration.rs",
]

EXPECTED_DEPS = [
    "rustre-core",
    "rusqlite",
    "mysql",
    "petgraph",
    "serde",
    "serde_json",
    "thiserror",
    "parking_lot",
    "tokio",
    "uuid",
]

# Symbols that should appear (definition or use) in the crate sources.
EXPECTED_SYMBOLS = [
    "KnowledgeGraph",
    "run_migrations",
    "DatabaseEngine",
    "SqliteEngine",
    "MysqlEngine",
    "GraphParam",
    "GraphValue",
    "GraphError",
    "QueryEngine",
    "GraphQuery",
    "QueryBuilder",
    "parse_sql",
    "QueryCache",
    "AnalysisGraph",
    "FunctionNode",
    "DataNode",
    "CallEdge",
    "DataFlowEdge",
    "TypeEdge",
    "GraphExport",
    "GraphMetrics",
    "SCCFinder",
    "PageRank",
    "BetweennessCentrality",
    "ClosenessCentrality",
    "GraphPartitioning",
    "MaxFlow",
    "MinCut",
    "SpanningTree",
    "GraphColoring",
    "GraphPersistence",
    "PersistedNode",
    "PersistedEdge",
    "NodeKind",
    "EdgeKind",
    "NodeSerializer",
    "EdgeSerializer",
    "GraphMigration",
    "GraphTransaction",
    "GraphBackup",
    "PersistError",
    "ExportNode",
    "ExportEdge",
    "ExportGraph",
    "ExportFilter",
    "GraphMLExporter",
    "GEXFExporter",
    "DotExporter",
    "CytoscapeExporter",
    "Neo4jCypherExporter",
    "CsvExporter",
    "write_export",
    "ExportFormat",
    "CollabEvent",
    "EventPayload",
    "Actor",
    "EventStore",
    "DeltaExporter",
    "DeltaImporter",
    "ImportResult",
    "ConflictResolver",
    "ConflictStrategy",
    "SyncSession",
    "HttpSyncer",
    "WsSyncChannel",
    "WsMessage",
    "UndoHistory",
    "AuditTrail",
    "CollaborationManager",
]

MIN_PUB_FN = 350  # report says 395; allow some slack
MAX_PUB_FN = 500


def parse_cargo_toml(text: str) -> dict:
    """Tiny TOML-ish parser sufficient for [package] and [dependencies] tables."""
    result: dict = {}
    current = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"\[([^\]]+)\]", line)
        if m:
            current = m.group(1).strip()
            result.setdefault(current, {})
            continue
        if current is None:
            continue
        m = re.match(r"([A-Za-z0-9_\-]+)\s*=\s*(.+)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        result[current][key] = val
    return result


def unquote(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def count_pub_fns(src_dir: Path) -> int:
    pat = re.compile(r"\bpub(?:\([^)]*\))?\s+(?:async\s+)?fn\b")
    total = 0
    for f in src_dir.rglob("*.rs"):
        try:
            total += len(pat.findall(f.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            pass
    return total


def gather_src_text(src_dir: Path) -> str:
    chunks = []
    for f in src_dir.rglob("*.rs"):
        try:
            chunks.append(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n".join(chunks)


def main() -> int:
    mismatches: list[str] = []
    fixed = 0  # validator does not auto-fix
    saved = False

    if not CRATE_DIR.is_dir():
        mismatches.append(f"crate dir missing: {CRATE_DIR}")
        _emit(mismatches, fixed, saved)
        return 0

    cargo_path = CRATE_DIR / "Cargo.toml"
    if not cargo_path.is_file():
        mismatches.append("Cargo.toml missing")
    else:
        cfg = parse_cargo_toml(cargo_path.read_text(encoding="utf-8", errors="replace"))
        pkg = cfg.get("package", {})
        name = unquote(pkg.get("name", ""))
        version = unquote(pkg.get("version", ""))
        edition = unquote(pkg.get("edition", ""))
        if name != "rustre-graph":
            mismatches.append(f"package.name expected 'rustre-graph', got '{name}'")
        if not version.startswith("0.1"):
            mismatches.append(f"package.version expected 0.1.x, got '{version}'")
        if edition != "2024":
            mismatches.append(f"package.edition expected '2024', got '{edition}'")

        deps_keys = set(cfg.get("dependencies", {}).keys())
        for d in EXPECTED_DEPS:
            if d not in deps_keys:
                mismatches.append(f"missing dependency: {d}")

        # library-only: no [[bin]] section, no src/main.rs
        if "bin" in cfg or any(k.startswith("bin.") for k in cfg):
            mismatches.append("unexpected [[bin]] section (should be library-only)")
        if (CRATE_DIR / "src" / "main.rs").exists():
            mismatches.append("unexpected src/main.rs (should be library-only)")

    src_dir = CRATE_DIR / "src"
    if not src_dir.is_dir():
        mismatches.append("src/ missing")
    else:
        for mod in EXPECTED_MODULES:
            if not (src_dir / mod).is_file():
                mismatches.append(f"missing module: src/{mod}")

        n_pub = count_pub_fns(src_dir)
        if n_pub < MIN_PUB_FN or n_pub > MAX_PUB_FN:
            mismatches.append(
                f"pub fn count {n_pub} outside expected window [{MIN_PUB_FN},{MAX_PUB_FN}] (report: 395)"
            )

        all_text = gather_src_text(src_dir)
        for sym in EXPECTED_SYMBOLS:
            if not re.search(r"\b" + re.escape(sym) + r"\b", all_text):
                mismatches.append(f"symbol not found in src/: {sym}")

    tests_dir = CRATE_DIR / "tests"
    for t in ("blitz.rs", "blitz2.rs"):
        if not (tests_dir / t).is_file():
            mismatches.append(f"missing integration test: tests/{t}")

    _emit(mismatches, fixed, saved)
    return 0


def _emit(mismatches: list[str], fixed: int, saved: bool) -> None:
    out = {
        "crate": CRATE_NAME,
        "fixed": fixed,
        "mismatches": len(mismatches),
        "details": mismatches,
        "saved": saved,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    sys.exit(main())
