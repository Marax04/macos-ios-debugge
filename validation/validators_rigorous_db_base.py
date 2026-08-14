#!/usr/bin/env python3
"""
Rigorous validator for module 'db_base'.

All 16 db_base_* tools are backed by rustre_db::base_migrations(), which
returns exactly 3 hard-coded migrations defined in
  crates/rustre-db/src/db_schema.rs

We reproduce the exact SQL strings here so we can compute independently:
  - counts, names, versions, min/max, contiguity
  - byte lengths of up_sql and down_sql
  - which migrations have down_sql

Output: validation/rigorous_db_base.json
"""

import json
import subprocess
import sys

# ---------------------------------------------------------------------------
# Ground truth: exact SQL strings from db_schema.rs
# ---------------------------------------------------------------------------

M001_UP = r"""
CREATE TABLE IF NOT EXISTS nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    key          TEXT    NOT NULL,
    payload      BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(kind, key)
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);

CREATE TABLE IF NOT EXISTS edges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    src_id       INTEGER NOT NULL,
    dst_id       INTEGER NOT NULL,
    payload      BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY (src_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (dst_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_edges_kind     ON edges(kind);
CREATE INDEX IF NOT EXISTS idx_edges_src      ON edges(src_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst      ON edges(dst_id);
CREATE INDEX IF NOT EXISTS idx_edges_kind_src ON edges(kind, src_id);
"""

M001_DOWN = r"""
DROP TABLE IF EXISTS edges;
DROP TABLE IF EXISTS nodes;
"""

M002_UP = r"""
CREATE TABLE IF NOT EXISTS events (
    offset       INTEGER PRIMARY KEY AUTOINCREMENT,
    stream       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    payload      BLOB    NOT NULL,
    metadata     BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_stream      ON events(stream);
CREATE INDEX IF NOT EXISTS idx_events_kind        ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_stream_off  ON events(stream, offset);
"""

M002_DOWN = r"""
DROP TABLE IF EXISTS events;
"""

M003_UP = r"""
CREATE TABLE IF NOT EXISTS kv_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

M003_DOWN = r"""
DROP TABLE IF EXISTS kv_meta;
"""

# Canonical migration list (matches base_migrations() in Rust)
MIGRATIONS = [
    {"version": 1, "name": "create_graph_tables",  "up_sql": M001_UP, "down_sql": M001_DOWN},
    {"version": 2, "name": "create_events_table",   "up_sql": M002_UP, "down_sql": M002_DOWN},
    {"version": 3, "name": "create_kv_meta_table",  "up_sql": M003_UP, "down_sql": M003_DOWN},
]

# ---------------------------------------------------------------------------
# Pre-computed expected values
# ---------------------------------------------------------------------------

EXPECTED_COUNT = len(MIGRATIONS)
EXPECTED_NAMES = [m["name"] for m in MIGRATIONS]
EXPECTED_VERSIONS = [m["version"] for m in MIGRATIONS]
EXPECTED_MIN_VERSION = min(m["version"] for m in MIGRATIONS)
EXPECTED_MAX_VERSION = max(m["version"] for m in MIGRATIONS)
EXPECTED_FIRST_VERSION = MIGRATIONS[0]["version"]

# contiguity: versions sorted, each step must be exactly +1
sorted_versions = sorted(EXPECTED_VERSIONS)
EXPECTED_CONTIGUOUS = all(
    sorted_versions[i + 1] == sorted_versions[i] + 1
    for i in range(len(sorted_versions) - 1)
)

# Migrations with non-empty down_sql
EXPECTED_WITH_DOWN = [
    {"version": m["version"], "name": m["name"]}
    for m in MIGRATIONS
    if m["down_sql"] and m["down_sql"].strip()
]

# Unique versions
from collections import Counter
version_counts = Counter(m["version"] for m in MIGRATIONS)
EXPECTED_UNIQUE = all(c == 1 for c in version_counts.values())
EXPECTED_DUPLICATES = [v for v, c in sorted(version_counts.items()) if c > 1]

# SQL byte lengths
UP_BYTES_EACH  = [len(m["up_sql"].encode("utf-8")) for m in MIGRATIONS]
DOWN_BYTES_EACH = [len(m["down_sql"].encode("utf-8")) if m["down_sql"] else 0 for m in MIGRATIONS]
EXPECTED_UP_BYTES    = sum(UP_BYTES_EACH)
EXPECTED_DOWN_BYTES  = sum(DOWN_BYTES_EACH)
EXPECTED_TOTAL_BYTES = EXPECTED_UP_BYTES + EXPECTED_DOWN_BYTES
EXPECTED_AVG_BYTES   = EXPECTED_UP_BYTES / EXPECTED_COUNT

# Largest up_sql
largest_idx = UP_BYTES_EACH.index(max(UP_BYTES_EACH))
EXPECTED_LARGEST = {
    "version":  MIGRATIONS[largest_idx]["version"],
    "name":     MIGRATIONS[largest_idx]["name"],
    "up_bytes": UP_BYTES_EACH[largest_idx],
}

# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)


def send(obj):
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()


def recv():
    raw = proc.stdout.readline()
    if not raw:
        raise RuntimeError("MCP server closed stdout unexpectedly")
    return json.loads(raw)


def call_tool(tool_name, args=None, req_id=None):
    if args is None:
        args = {}
    send({
        "jsonrpc": "2.0",
        "id": req_id or tool_name,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    })
    resp = recv()
    if "error" in resp:
        return None, resp["error"].get("message", str(resp["error"]))
    text = resp["result"]["content"][0]["text"]
    return json.loads(text), None


# Initialize
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous-db-base", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []


def check(tool, field, got, expected, note=""):
    global checks_passed, checks_failed
    if got == expected:
        checks_passed += 1
        print(f"  PASS  {tool}.{field}")
    else:
        checks_failed += 1
        entry = {
            "tool": tool,
            "field": field,
            "expected": expected,
            "got": got,
        }
        if note:
            entry["note"] = note
        mismatches.append(entry)
        print(f"  FAIL  {tool}.{field}  expected={expected!r}  got={got!r}")


# --- 1. db_base_migrations_count ---
data, err = call_tool("db_base_migrations_count")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_count", "error": err})
else:
    check("db_base_migrations_count", "count", data.get("count"), EXPECTED_COUNT)

# --- 2. db_base_migrations_list ---
data, err = call_tool("db_base_migrations_list")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_list", "error": err})
else:
    check("db_base_migrations_list", "count", data.get("count"), EXPECTED_COUNT)
    got_migrations = data.get("migrations", [])
    expected_migrations = [{"version": m["version"], "name": m["name"]} for m in MIGRATIONS]
    check("db_base_migrations_list", "migrations", got_migrations, expected_migrations)

# --- 3. db_base_migrations_max_version ---
data, err = call_tool("db_base_migrations_max_version")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_max_version", "error": err})
else:
    check("db_base_migrations_max_version", "max_version", data.get("max_version"), EXPECTED_MAX_VERSION)

# --- 4. db_base_migrations_names ---
data, err = call_tool("db_base_migrations_names")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_names", "error": err})
else:
    check("db_base_migrations_names", "count", data.get("count"), EXPECTED_COUNT)
    check("db_base_migrations_names", "names", data.get("names"), EXPECTED_NAMES)

# --- 5. db_base_migrations_find_by_version (version=2, exists) ---
data, err = call_tool("db_base_migrations_find_by_version", {"version": 2})
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_find_by_version", "error": err})
else:
    expected_found = {"version": 2, "name": "create_events_table"}
    check("db_base_migrations_find_by_version", "found(v=2)", data.get("found"), expected_found)

# --- 6. db_base_migrations_find_by_version (version=99, missing) ---
data, err = call_tool("db_base_migrations_find_by_version", {"version": 99})
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_find_by_version(v=99)", "error": err})
else:
    check("db_base_migrations_find_by_version", "found(v=99)", data.get("found"), None)

# --- 7. db_base_migrations_versions ---
data, err = call_tool("db_base_migrations_versions")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_versions", "error": err})
else:
    check("db_base_migrations_versions", "versions", data.get("versions"), EXPECTED_VERSIONS)

# --- 8. db_base_migrations_min_version ---
data, err = call_tool("db_base_migrations_min_version")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_min_version", "error": err})
else:
    check("db_base_migrations_min_version", "min_version", data.get("min_version"), EXPECTED_MIN_VERSION)

# --- 9. db_base_migrations_is_contiguous ---
data, err = call_tool("db_base_migrations_is_contiguous")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_is_contiguous", "error": err})
else:
    check("db_base_migrations_is_contiguous", "contiguous", data.get("contiguous"), EXPECTED_CONTIGUOUS)
    check("db_base_migrations_is_contiguous", "first_gap", data.get("first_gap"), None)

# --- 10. db_base_migrations_first_version ---
data, err = call_tool("db_base_migrations_first_version")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_first_version", "error": err})
else:
    check("db_base_migrations_first_version", "first_version", data.get("first_version"), EXPECTED_FIRST_VERSION)

# --- 11. db_base_migrations_summary ---
data, err = call_tool("db_base_migrations_summary")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_summary", "error": err})
else:
    check("db_base_migrations_summary", "count", data.get("count"), EXPECTED_COUNT)
    check("db_base_migrations_summary", "names", data.get("names"), EXPECTED_NAMES)

# --- 12. db_base_migrations_with_down_sql ---
data, err = call_tool("db_base_migrations_with_down_sql")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_with_down_sql", "error": err})
else:
    check("db_base_migrations_with_down_sql", "count", data.get("count"), len(EXPECTED_WITH_DOWN))
    check("db_base_migrations_with_down_sql", "items", data.get("items"), EXPECTED_WITH_DOWN)

# --- 13. db_base_migrations_unique_versions ---
data, err = call_tool("db_base_migrations_unique_versions")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_unique_versions", "error": err})
else:
    check("db_base_migrations_unique_versions", "unique", data.get("unique"), EXPECTED_UNIQUE)
    check("db_base_migrations_unique_versions", "duplicates", data.get("duplicates"), EXPECTED_DUPLICATES)

# --- 14. db_base_migrations_total_sql_bytes ---
data, err = call_tool("db_base_migrations_total_sql_bytes")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_total_sql_bytes", "error": err})
else:
    check("db_base_migrations_total_sql_bytes", "up_bytes",    data.get("up_bytes"),    EXPECTED_UP_BYTES)
    check("db_base_migrations_total_sql_bytes", "down_bytes",  data.get("down_bytes"),  EXPECTED_DOWN_BYTES)
    check("db_base_migrations_total_sql_bytes", "total_bytes", data.get("total_bytes"), EXPECTED_TOTAL_BYTES)

# --- 15. db_base_migrations_avg_sql_bytes ---
data, err = call_tool("db_base_migrations_avg_sql_bytes")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_avg_sql_bytes", "error": err})
else:
    # avg_bytes is a float; compare within epsilon
    got_avg = data.get("avg_bytes")
    if got_avg is not None and abs(float(got_avg) - EXPECTED_AVG_BYTES) < 0.5:
        checks_passed += 1
        print(f"  PASS  db_base_migrations_avg_sql_bytes.avg_bytes")
    else:
        checks_failed += 1
        mismatches.append({
            "tool": "db_base_migrations_avg_sql_bytes",
            "field": "avg_bytes",
            "expected": EXPECTED_AVG_BYTES,
            "got": got_avg,
        })
        print(f"  FAIL  db_base_migrations_avg_sql_bytes.avg_bytes  expected={EXPECTED_AVG_BYTES}  got={got_avg}")
    check("db_base_migrations_avg_sql_bytes", "total_bytes", data.get("total_bytes"), EXPECTED_UP_BYTES)

# --- 16. db_base_migrations_largest_up_sql ---
data, err = call_tool("db_base_migrations_largest_up_sql")
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_largest_up_sql", "error": err})
else:
    check("db_base_migrations_largest_up_sql", "version",  data.get("version"),  EXPECTED_LARGEST["version"])
    check("db_base_migrations_largest_up_sql", "name",     data.get("name"),     EXPECTED_LARGEST["name"])
    check("db_base_migrations_largest_up_sql", "up_bytes", data.get("up_bytes"), EXPECTED_LARGEST["up_bytes"])

# --- 17. db_base_migrations_has_version (version=1, present) ---
data, err = call_tool("db_base_migrations_has_version", {"version": 1})
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_has_version(v=1)", "error": err})
else:
    check("db_base_migrations_has_version", "found(v=1)", data.get("found"), True)

# --- 18. db_base_migrations_has_version (version=99, absent) ---
data, err = call_tool("db_base_migrations_has_version", {"version": 99})
if err:
    checks_failed += 1
    mismatches.append({"tool": "db_base_migrations_has_version(v=99)", "error": err})
else:
    check("db_base_migrations_has_version", "found(v=99)", data.get("found"), False)

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
proc.stdin.close()
proc.wait(timeout=5)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
tools_hardened = 16  # all db_base tools (16 distinct tools, 18 checks)

report = {
    "module": "db_base",
    "tools_hardened": tools_hardened,
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
    "notes": {
        "computed_up_bytes_per_migration": dict(
            zip([m["name"] for m in MIGRATIONS], UP_BYTES_EACH)
        ),
        "computed_down_bytes_per_migration": dict(
            zip([m["name"] for m in MIGRATIONS], DOWN_BYTES_EACH)
        ),
    },
}

OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_db_base.json"
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)

print()
print(f"Module      : db_base")
print(f"Tools       : {tools_hardened}")
print(f"Checks pass : {checks_passed}")
print(f"Checks fail : {checks_failed}")
print(f"Mismatches  : {len(mismatches)}")
print(f"Report      : {OUT}")

sys.exit(0 if checks_failed == 0 else 1)
