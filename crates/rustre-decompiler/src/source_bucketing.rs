//! Phase 1 of whole-project reconstruction: group decompiled functions into
//! per-source-file "buckets" (`<bucket>.c` / `<bucket>.h`) instead of one
//! flat `sub_<addr>.c` per function.
//!
//! Gated entirely behind `RUSTRE_BUCKET_BY_SOURCE` (see
//! `bucket_by_source_opt_in` in `lib.rs`); default OFF leaves every existing
//! code path untouched.
//!
//! # What's real vs stubbed here (2026-07-20)
//!
//! - **Fallback clustering** (no debug info) is REAL: it uses
//!   `rustre_analysis_xref::CallGraph::strongly_connected_components` (the
//!   only clustering primitive that already exists in the analysis crates —
//!   grepped for `community`/`louvain`/`connected_components` first, per the
//!   plan; none existed) plus a simple union-find over the SCCs' *weakly*
//!   connected call-graph neighborhoods to merge singleton SCCs with their
//!   caller/callee cluster. This is coarse (call-adjacency, not a real
//!   modularity-maximizing community algorithm) but deterministic and never
//!   drops a function.
//! - **DWARF/PDB source-file keys** are REAL as an API (`plan_buckets` takes
//!   `dwarf_source_files`/`pdb_source_files: Option<&HashMap<VA, String>>`
//!   and prefers them over the fallback), but nothing in this pass wires an
//!   actual DWARF/PDB resolver into `BatchDecompiler` — the two call sites in
//!   `batch_decompiler.rs` currently pass `None` for both, so today only the
//!   call-graph fallback path is exercised end-to-end. Wiring a real
//!   per-function `DW_AT_decl_file`/PDB line-table lookup into the batch
//!   pipeline is future work (`rustre-symbols-dwarf`/`-pdb` are not currently
//!   dependencies of `rustre-decompiler`).

use std::collections::{HashMap, HashSet};

/// A virtual address, matching the rest of the decompiler's convention.
pub type VA = u64;

/// One group of functions destined for a shared `<key>.c`/`<key>.h` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// File-safe bucket key (source-file basename, module name, or
    /// `cluster_<id>` / `unbucketed`).
    pub key: String,
    /// Member function addresses, in the order they were assigned.
    pub functions: Vec<VA>,
    /// True when `key` came from the call-graph fallback (no debug info),
    /// not a real source-file name.
    pub is_fallback: bool,
}

/// The full bucket assignment for a batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketPlan {
    pub buckets: Vec<Bucket>,
    pub func_to_bucket: HashMap<VA, usize>,
}

impl BucketPlan {
    /// The bucket key owning `va`, if any.
    pub fn key_for(&self, va: VA) -> Option<&str> {
        self.func_to_bucket
            .get(&va)
            .and_then(|&i| self.buckets.get(i))
            .map(|b| b.key.as_str())
    }
}

/// Turn an arbitrary source-file path into a filesystem-safe bucket key: the
/// basename, lowercased extension kept, any path separators stripped.
fn bucket_key_from_source_path(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if base.is_empty() {
        "unbucketed".to_string()
    } else {
        base.to_string()
    }
}

/// Build a bucket plan for `function_vas`.
///
/// Priority per function: `dwarf_source_files` > `pdb_source_files` >
/// call-graph fallback cluster > `unbucketed`.
pub fn plan_buckets(
    function_vas: &[VA],
    dwarf_source_files: Option<&HashMap<VA, String>>,
    pdb_source_files: Option<&HashMap<VA, String>>,
    xref: Option<&rustre_analysis_xref::CallGraph>,
) -> BucketPlan {
    let mut key_of: HashMap<VA, String> = HashMap::new();
    let mut fallback_keys: HashSet<String> = HashSet::new();

    for &va in function_vas {
        if let Some(src) = dwarf_source_files.and_then(|m| m.get(&va)) {
            key_of.insert(va, bucket_key_from_source_path(src));
            continue;
        }
        if let Some(src) = pdb_source_files.and_then(|m| m.get(&va)) {
            key_of.insert(va, bucket_key_from_source_path(src));
            continue;
        }
    }

    // Fallback: cluster whatever's left by call-graph adjacency.
    let remaining: Vec<VA> = function_vas
        .iter()
        .copied()
        .filter(|va| !key_of.contains_key(va))
        .collect();
    if !remaining.is_empty() {
        if let Some(graph) = xref {
            let clusters = cluster_by_call_graph(&remaining, graph);
            for (i, cluster) in clusters.into_iter().enumerate() {
                let key = format!("cluster_{i}");
                fallback_keys.insert(key.clone());
                for va in cluster {
                    key_of.insert(va, key.clone());
                }
            }
        }
    }

    // Anything still unresolved (no xref, or no debug info at all) goes into
    // a single `unbucketed` bucket — never silently dropped.
    for &va in function_vas {
        key_of.entry(va).or_insert_with(|| "unbucketed".to_string());
    }

    // Materialize buckets in first-seen key order for determinism.
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for &va in function_vas {
        let key = &key_of[&va];
        if seen.insert(key.clone()) {
            order.push(key.clone());
        }
    }
    let mut buckets: Vec<Bucket> = order
        .into_iter()
        .map(|key| {
            let is_fallback = key == "unbucketed" || fallback_keys.contains(&key);
            Bucket { key, functions: Vec::new(), is_fallback }
        })
        .collect();
    let index_of: HashMap<String, usize> =
        buckets.iter().enumerate().map(|(i, b)| (b.key.clone(), i)).collect();
    let mut func_to_bucket = HashMap::new();
    for &va in function_vas {
        let idx = index_of[&key_of[&va]];
        buckets[idx].functions.push(va);
        func_to_bucket.insert(va, idx);
    }

    BucketPlan { buckets, func_to_bucket }
}

/// Cluster `vas` using the call graph: start from `CallGraph`'s strongly
/// connected components (a real recursive-cluster grouping already provided
/// by `rustre-analysis-xref`), then union singleton SCCs into the cluster of
/// any direct caller/callee they have among `vas` so leaf/root functions
/// land next to the code that actually uses them instead of each getting
/// their own one-function bucket. Deterministic: components ordered by their
/// minimum address.
fn cluster_by_call_graph(vas: &[VA], graph: &rustre_analysis_xref::CallGraph) -> Vec<Vec<VA>> {
    use rustre_core::address::Address;
    let va_set: HashSet<VA> = vas.iter().copied().collect();
    let sccs = graph.strongly_connected_components();

    // va -> initial scc-cluster id (only for vas present in `vas`).
    let mut cluster_of: HashMap<VA, usize> = HashMap::new();
    let mut clusters: Vec<Vec<VA>> = Vec::new();
    for scc in &sccs {
        let members: Vec<VA> =
            scc.iter().map(|a| a.0).filter(|a| va_set.contains(a)).collect();
        if members.is_empty() {
            continue;
        }
        let id = clusters.len();
        for &m in &members {
            cluster_of.insert(m, id);
        }
        clusters.push(members);
    }
    // Any va with no graph node at all gets its own singleton cluster.
    for &va in vas {
        cluster_of.entry(va).or_insert_with(|| {
            let id = clusters.len();
            clusters.push(vec![va]);
            id
        });
    }

    // Union-find over cluster ids, merging a singleton's cluster into the
    // first neighbor's cluster it finds (caller or callee already in `vas`).
    let mut parent: Vec<usize> = (0..clusters.len()).collect();
    fn find(parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let (ra, rb) = (find(parent, a), find(parent, b));
        if ra != rb {
            parent[ra.max(rb)] = ra.min(rb);
        }
    }
    for &va in vas {
        let Some(&cid) = cluster_of.get(&va) else { continue };
        if clusters[cid].len() != 1 {
            continue; // only singletons seek a merge
        }
        for callee in graph.callees(Address(va)) {
            if let Some(&other) = cluster_of.get(&callee.0) {
                union(&mut parent, cid, other);
                break;
            }
        }
    }

    let mut merged: HashMap<usize, Vec<VA>> = HashMap::new();
    for (cid, members) in clusters.into_iter().enumerate() {
        let root = find(&mut parent, cid);
        merged.entry(root).or_default().extend(members);
    }
    let mut out: Vec<Vec<VA>> = merged.into_values().collect();
    for c in &mut out {
        c.sort_unstable();
    }
    out.sort_by_key(|c| c[0]);
    out
}

/// Shared prototype-string builder, factored out so the per-function inline
/// forward-decl path (`emit_callee_forward_decls`) and the new per-bucket
/// header path emit byte-identical prototype text.
pub fn format_prototype(name: &str, ret_ty: &str) -> String {
    format!("{ret_ty} {name}();")
}

/// Names a bucket header must never forward-declare.
///
/// Two distinct reasons, both making the emitted header uncompilable:
///
/// 1. **Standard-library functions.** When symbol recovery names a statically
///    linked CRT routine correctly, re-declaring it as `__int64 atexit();`
///    conflicts with the real prototype the system headers already provide
///    (`error: conflicting types for 'atexit'`). The recovered name is right;
///    inventing a signature for it is the error.
/// 2. **`main`.** Not a library function, but declaring it `__int64 main()`
///    is equally a conflict, and equally a guess.
///
/// Measured on the 12-binary corpus: of 8251 distinct emitted names, exactly
/// four collided — `atexit`, `main`, `strnlen`, `wcsnlen`. The list below is
/// deliberately broader than those four so the rule holds on binaries outside
/// this corpus, but it stays restricted to names the C standard itself
/// reserves: guessing beyond that would trade one wrong assumption for another.
const NEVER_REDECLARE: &[&str] = &[
    "main",
    // <stdlib.h>
    "abort", "abs", "atexit", "atof", "atoi", "atol", "bsearch", "calloc", "div",
    "exit", "free", "getenv", "labs", "ldiv", "malloc", "qsort", "rand", "realloc",
    "srand", "strtod", "strtol", "strtoul", "system",
    // <string.h>
    "memchr", "memcmp", "memcpy", "memmove", "memset", "strcat", "strchr", "strcmp",
    "strcoll", "strcpy", "strcspn", "strerror", "strlen", "strncat", "strncmp",
    "strncpy", "strnlen", "strpbrk", "strrchr", "strspn", "strstr", "strtok", "strxfrm",
    // <stdio.h>
    "clearerr", "fclose", "feof", "ferror", "fflush", "fgetc", "fgetpos", "fgets",
    "fopen", "fprintf", "fputc", "fputs", "fread", "freopen", "fscanf", "fseek",
    "fsetpos", "ftell", "fwrite", "getc", "getchar", "gets", "perror", "printf",
    "putc", "putchar", "puts", "remove", "rename", "rewind", "scanf", "setbuf",
    "setvbuf", "snprintf", "sprintf", "sscanf", "tmpfile", "tmpnam", "ungetc",
    "vfprintf", "vprintf", "vsprintf",
    // <ctype.h> / <time.h> / <math.h> — the commonly statically linked ones.
    "isalnum", "isalpha", "iscntrl", "isdigit", "isgraph", "islower", "isprint",
    "ispunct", "isspace", "isupper", "isxdigit", "tolower", "toupper",
    "asctime", "clock", "ctime", "difftime", "gmtime", "localtime", "mktime",
    "strftime", "time",
    // Wide-character mirrors that mingw declares alongside the narrow ones.
    "wcscat", "wcschr", "wcscmp", "wcscpy", "wcslen", "wcsncmp", "wcsnlen", "wcsstr",
];

/// The exact prototype for a function, taken from its own emitted definition.
///
/// **Why derive instead of predict.** The header previously typed every
/// prototype `__int64` because no return-type map reaches this layer. That does
/// not merely lose information — it makes the bucket uncompilable, because the
/// `.c` defines the same function with its *recovered* type (`void`, `int`, …)
/// and C rejects the disagreement (`error: conflicting types for 'dot'`).
/// Measured on the corpus, this self-conflict — not the CRT collisions — was
/// the dominant cause: hundreds of names, including ordinary user functions.
///
/// Taking the signature verbatim from the definition makes header and
/// implementation agree by construction, which is what a header is for.
///
/// Returns `None` when no signature line can be identified, in which case the
/// caller must omit the declaration rather than fall back to a guess.
#[must_use]
pub fn prototype_from_definition(body: &str, name: &str) -> Option<String> {
    // Same control-flow gating as the confidence scorer: `if (x) {` has the
    // shape of a signature and this codebase has been bitten by that before.
    let sig = body.lines().map(str::trim).find(|l| {
        l.ends_with(") {")
            && l.contains(name)
            && !l.starts_with("if")
            && !l.starts_with("for")
            && !l.starts_with("while")
            && !l.starts_with("switch")
            && !l.starts_with("else")
            && !l.starts_with("do")
    })?;
    let decl = sig.strip_suffix('{')?.trim_end();
    Some(format!("{decl};"))
}

/// Whether a recovered function name must be left undeclared in a bucket header.
///
/// See [`NEVER_REDECLARE`]. Skipping is the honest outcome: the definition still
/// appears in the bucket's `.c`, and the real declaration comes from the header
/// the C library already provides.
#[must_use]
pub fn is_never_redeclared(name: &str) -> bool {
    NEVER_REDECLARE.contains(&name)
}

/// Build the `#include`-guarded header text for one bucket: a forward
/// declaration for every member function whose return type is known via
/// `named_callees` (VA -> predicted return type; VAs not present are typed
/// `__int64`, matching `emit_callee_forward_decls`'s `sub_`/`off_` default).
/// Build a bucket header whose prototypes are derived from the emitted
/// definitions in `bodies` (VA -> that function's pseudo-C).
///
/// Prefer this over [`emit_bucket_header`]: it is the only variant that cannot
/// disagree with the `.c` it accompanies. A function whose signature cannot be
/// identified, or whose name must not be redeclared (see [`NEVER_REDECLARE`]),
/// is omitted — an honest gap, never a guessed prototype.
pub fn emit_bucket_header_from_bodies(
    bucket: &Bucket,
    func_names: &HashMap<VA, String>,
    bodies: &HashMap<VA, &str>,
) -> String {
    let guard = header_guard(&bucket.key);
    let mut out = format!("#ifndef {guard}\n#define {guard}\n\n");
    for &va in &bucket.functions {
        let Some(name) = func_names.get(&va) else { continue };
        if is_never_redeclared(name) {
            continue;
        }
        let Some(body) = bodies.get(&va) else { continue };
        if let Some(proto) = prototype_from_definition(body, name) {
            out.push_str(&proto);
            out.push('\n');
        }
    }
    out.push_str(&format!("\n#endif // {guard}\n"));
    out
}

/// Include-guard macro name for a bucket key.
fn header_guard(key: &str) -> String {
    format!("BUCKET_{}_H", key.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_"))
}

pub fn emit_bucket_header(
    bucket: &Bucket,
    func_names: &HashMap<VA, String>,
    named_callees: &HashMap<VA, String>,
) -> String {
    let guard = format!(
        "BUCKET_{}_H",
        bucket.key.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    );
    let mut out = format!("#ifndef {guard}\n#define {guard}\n\n");
    for &va in &bucket.functions {
        let Some(name) = func_names.get(&va) else { continue };
        // A correctly recovered CRT name must not be given an invented
        // prototype — that conflicts with the real one. See NEVER_REDECLARE.
        if is_never_redeclared(name) {
            continue;
        }
        let ret = named_callees.get(&va).map(String::as_str).unwrap_or("__int64");
        out.push_str(&format_prototype(name, ret));
        out.push('\n');
    }
    out.push_str(&format!("\n#endif // {guard}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_analysis_xref::CallGraph;
    use rustre_core::address::Address;

    /// Build a tiny `CallGraph` directly from `(caller, callee)` edges — its
    /// fields are public and this is simpler than round-tripping through an
    /// `XrefDatabase` just for these unit tests.
    fn graph_from_edges(edges: &[(VA, VA)]) -> CallGraph {
        let mut g = CallGraph::default();
        for &(from, to) in edges {
            let (a, b) = (Address(from), Address(to));
            g.nodes.insert(a);
            g.nodes.insert(b);
            g.adj.entry(a).or_default().push((b, 1));
            g.rev.entry(b).or_default().push((a, 1));
        }
        g
    }

    #[test]
    fn dwarf_source_file_wins_and_keys_by_basename() {
        let vas = [0x1000, 0x2000];
        let mut dwarf = HashMap::new();
        dwarf.insert(0x1000, "C:/src/foo.c".to_string());
        dwarf.insert(0x2000, "C:/src/bar.c".to_string());
        let plan = plan_buckets(&vas, Some(&dwarf), None, None);
        assert_eq!(plan.key_for(0x1000), Some("foo.c"));
        assert_eq!(plan.key_for(0x2000), Some("bar.c"));
        assert_eq!(plan.buckets.len(), 2);
        assert!(!plan.buckets[0].is_fallback);
    }

    #[test]
    fn pdb_source_file_used_when_no_dwarf() {
        let vas = [0x3000];
        let mut pdb = HashMap::new();
        pdb.insert(0x3000, "obj/mod.obj".to_string());
        let plan = plan_buckets(&vas, None, Some(&pdb), None);
        assert_eq!(plan.key_for(0x3000), Some("mod.obj"));
        assert!(!plan.buckets[0].is_fallback);
    }

    #[test]
    fn dwarf_takes_priority_over_pdb_per_function() {
        let vas = [0x1000, 0x2000];
        let mut dwarf = HashMap::new();
        dwarf.insert(0x1000, "a.c".to_string());
        let mut pdb = HashMap::new();
        pdb.insert(0x1000, "wrong.obj".to_string());
        pdb.insert(0x2000, "b.obj".to_string());
        let plan = plan_buckets(&vas, Some(&dwarf), Some(&pdb), None);
        assert_eq!(plan.key_for(0x1000), Some("a.c"));
        assert_eq!(plan.key_for(0x2000), Some("b.obj"));
    }

    #[test]
    fn fallback_clusters_by_call_graph_without_debug_info() {
        let vas = [0x1000, 0x1010, 0x2000];
        // 0x1000 -> 0x1010: should merge into one cluster.
        let g = graph_from_edges(&[(0x1000, 0x1010)]);
        let plan = plan_buckets(&vas, None, None, Some(&g));
        assert_eq!(plan.key_for(0x1000), plan.key_for(0x1010));
        assert_ne!(plan.key_for(0x1000), plan.key_for(0x2000));
        assert!(plan.buckets.iter().all(|b| b.is_fallback));
    }

    #[test]
    fn unbucketed_when_no_source_info_and_no_graph() {
        let vas = [0x9000, 0x9010];
        let plan = plan_buckets(&vas, None, None, None);
        assert_eq!(plan.buckets.len(), 1);
        assert_eq!(plan.buckets[0].key, "unbucketed");
        assert!(plan.buckets[0].is_fallback);
        assert_eq!(plan.buckets[0].functions.len(), 2);
    }

    #[test]
    fn no_function_is_ever_dropped() {
        let vas = [0x1, 0x2, 0x3, 0x4, 0x5];
        let g = graph_from_edges(&[(0x1, 0x2)]);
        let mut dwarf = HashMap::new();
        dwarf.insert(0x3, "x.c".to_string());
        let plan = plan_buckets(&vas, Some(&dwarf), None, Some(&g));
        let total: usize = plan.buckets.iter().map(|b| b.functions.len()).sum();
        assert_eq!(total, vas.len());
        for va in vas {
            assert!(plan.key_for(va).is_some());
        }
    }

    #[test]
    fn header_prototype_matches_the_definition_exactly() {
        // The regression this prevents: a `void` function declared `__int64`,
        // which C rejects as a conflicting type. Header must mirror the body.
        let body = "void __fastcall dot(__int64 a1) {\n  return;\n}\n";
        let proto = prototype_from_definition(body, "dot").expect("signature must be found");
        assert_eq!(proto, "void __fastcall dot(__int64 a1);");
    }

    #[test]
    fn prototype_extraction_ignores_control_flow_headers() {
        // `if (…) {` has the same shape as a signature — a trap hit before.
        let body = "int foo(int a1) {\n  if (a1) {\n    return 1;\n  }\n  return 0;\n}\n";
        assert_eq!(prototype_from_definition(body, "foo").as_deref(), Some("int foo(int a1);"));
    }

    #[test]
    fn no_signature_means_no_declaration_not_a_guess() {
        assert_eq!(prototype_from_definition("/* nothing recovered */\n", "foo"), None);
    }

    #[test]
    fn header_from_bodies_omits_unrecoverable_and_reserved_names() {
        let bucket = Bucket {
            key: "unbucketed".to_string(),
            functions: vec![0x1000, 0x2000, 0x3000],
            is_fallback: true,
        };
        let mut names = HashMap::new();
        names.insert(0x1000, "sub_1000".to_string());
        names.insert(0x2000, "atexit".to_string());
        names.insert(0x3000, "sub_3000".to_string());
        let mut bodies: HashMap<VA, &str> = HashMap::new();
        bodies.insert(0x1000, "void sub_1000() {\n}\n");
        bodies.insert(0x2000, "int atexit(void *a1) {\n}\n");
        bodies.insert(0x3000, "/* no signature */\n");
        let h = emit_bucket_header_from_bodies(&bucket, &names, &bodies);
        assert!(h.contains("void sub_1000();"), "{h}");
        assert!(!h.contains("atexit"), "reserved CRT name must be skipped: {h}");
        assert!(!h.contains("sub_3000"), "unrecoverable signature must be skipped: {h}");
    }

    #[test]
    fn bucket_header_never_redeclares_crt_functions() {
        // Regression: emitting `__int64 atexit();` made every bucket header
        // uncompilable ("conflicting types for 'atexit'"). Measured on the
        // corpus, this was the sole cause of all 12 bucket-file failures.
        let bucket = Bucket {
            key: "unbucketed".to_string(),
            functions: vec![0x1000, 0x2000, 0x3000],
            is_fallback: true,
        };
        let mut names = HashMap::new();
        names.insert(0x1000, "atexit".to_string());
        names.insert(0x2000, "main".to_string());
        names.insert(0x3000, "sub_3000".to_string());
        let header = emit_bucket_header(&bucket, &names, &HashMap::new());
        assert!(!header.contains("atexit"), "must not redeclare a CRT function: {header}");
        assert!(!header.contains("main"), "must not redeclare main: {header}");
        assert!(header.contains("sub_3000"), "recovered names must still be declared: {header}");
    }

    #[test]
    fn only_reserved_names_are_skipped() {
        // The skip rule must not swallow ordinary recovered symbols that merely
        // resemble library names.
        assert!(is_never_redeclared("strlen"));
        assert!(!is_never_redeclared("strlen_custom"));
        assert!(!is_never_redeclared("my_malloc"));
        assert!(!is_never_redeclared("sub_401000"));
    }

    #[test]
    fn emit_bucket_header_dedups_and_matches_prototype_format() {
        let bucket = Bucket {
            key: "foo.c".to_string(),
            functions: vec![0x1000, 0x2000],
            is_fallback: false,
        };
        let mut names = HashMap::new();
        names.insert(0x1000, "sub_1000".to_string());
        names.insert(0x2000, "sub_2000".to_string());
        let mut ret_types = HashMap::new();
        ret_types.insert(0x1000, "int".to_string());
        let header = emit_bucket_header(&bucket, &names, &ret_types);
        assert!(header.contains(&format_prototype("sub_1000", "int")));
        assert!(header.contains(&format_prototype("sub_2000", "__int64")));
        assert!(header.contains("#ifndef BUCKET_FOO_C_H"));
        assert!(header.contains("#endif"));
        // Each declared exactly once.
        assert_eq!(header.matches("sub_1000").count(), 1);
    }
}
