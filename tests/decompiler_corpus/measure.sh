#!/bin/bash
# measure.sh — the ONLY sanctioned way to produce a corpus number.
#
# ─── Why this exists ─────────────────────────────────────────────────────────
#
# On 2026-07-23 a session spent an hour proving a change was neutral, and could
# not: `out/` had been regenerated in place by another agent at 11:20, and
# `tests/fidelity.rs` was edited at 11:33 — during the test run that was reading
# it. Both fidelity harnesses read below their recorded baselines, for reasons
# that had nothing to do with the change under test.
#
# Many agents own `rustre-decompiler` concurrently. That makes every ABSOLUTE
# number in this repo uninterpretable on its own: `out/` is not an oracle, it is
# just whatever the last writer left there. This script fixes that with two
# rules, and it is the whole point of the file:
#
#   1. SELF-VS-SELF. Every run writes its own immutable snapshot under `runs/`.
#      Comparisons are snapshot-vs-snapshot, never against `out/`. A snapshot
#      nobody else can write is a baseline that survives concurrent edits.
#
#   2. NO NUMBER FROM A MOVING TREE. The inputs (decompiler sources, harnesses,
#      driver binary) are fingerprinted before AND after. If the fingerprint
#      moved, the run is marked TAINTED and the metrics are NOT published:
#      an admission beats a plausible wrong number, which is the same principle
#      the `reconstruction` module applies to confidence.
#
# It also catches the stale-binary trap documented in CLAUDE.md: a source newer
# than the driver means you are measuring the previous build.
#
# ─── Usage ───────────────────────────────────────────────────────────────────
#   ./measure.sh --label before          # snapshot + metrics
#   ./measure.sh --label after --compare before
#   ./measure.sh --label after --compare before --full   # + gcc recompilability
#
# Exit codes: 0 clean · 1 metrics regressed vs --compare · 3 TAINTED (tree moved)
set -uo pipefail

cd "$(dirname "$0")"
CORPUS="$PWD"
ROOT="$(cd ../.. && pwd)"
DRIVER="$ROOT/target/release/examples/dump_decompile.exe"
RUNS="$CORPUS/runs"

LABEL=""
COMPARE=""
FULL=0
PATH_B=0
while [ $# -gt 0 ]; do
  case "$1" in
    --label)   LABEL="${2:-}"; shift 2 ;;
    --compare) COMPARE="${2:-}"; shift 2 ;;
    --path-b) PATH_B=1; shift ;;
    --full)    FULL=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$LABEL" ] || LABEL="run_$(date +%Y%m%d_%H%M%S)"
DEST="$RUNS/$LABEL"

# ── Fingerprint: everything whose change would invalidate the numbers ────────
# Content hash, not mtime: a rebuild that produces identical bytes is not a
# reason to discard a run, but an edited source is.
fingerprint() {
  {
    find "$ROOT/crates/rustre-decompiler/src" \
         "$ROOT/crates/rustre-arch-x86/src" \
         "$ROOT/crates/rustre-il-lift/src" \
         -name '*.rs' -type f 2>/dev/null | sort | xargs md5sum 2>/dev/null
    md5sum "$CORPUS/fidelity.sh" "$CORPUS/check.sh" "$CORPUS/ida_defs.h" 2>/dev/null
    md5sum "$ROOT/crates/rustre-decompiler/tests/fidelity.rs" 2>/dev/null
    md5sum "$DRIVER" 2>/dev/null
  } | md5sum | cut -d' ' -f1
}

if [ ! -x "$DRIVER" ]; then
  echo "FATAL: driver missing: $DRIVER" >&2
  echo "  build it first: cargo build --release -p rustre-decompiler --examples" >&2
  exit 2
fi

# Stale-binary guard: a source newer than the driver means the driver predates
# the code you think you are measuring. This has cost more than one session.
STALE=$(find "$ROOT/crates/rustre-decompiler/src" -name '*.rs' -newer "$DRIVER" 2>/dev/null | head -3)
if [ -n "$STALE" ]; then
  echo "FATAL: driver is STALE — these sources are newer than the binary:" >&2
  echo "$STALE" | sed 's/^/  /' >&2
  echo "  rebuild before measuring, or you are measuring the previous build." >&2
  exit 2
fi

# ── Fingerprint of the MEASURING INSTRUMENTS themselves ─────────────────────
# A stricter metric lowers a number without the decompiler getting worse. That
# happened for real: teaching `fidelity_arity.py` to check every definition
# instead of the first one moved arity 123 -> 122, and the comparison shouted
# REGRESSION at an improvement. Numbers produced by different versions of the
# harness are not comparable, and saying so is better than flagging the wrong
# thing — the same rule this script already applies to a moving source tree.
# #8230 - l'elenco copriva SETTE file. `fidelity.sh` e `check.sh` erano gia'
# in `fingerprint()` (che invalida una corsa se cambiano DURANTE) ma non qui
# (che annota un confronto se sono cambiati FRA due corse). Sono definizioni
# di METRICA, non solo input: il 2026-08-29 ho reso `fidelity.sh` capace di
# vedere path B -- modifica che sposta un numero senza che il codice emesso
# cambi, il caso esatto per cui questa annotazione esiste -- e il confronto
# non l'ha dichiarato.
# `readability.py` e `callsite_consistency.py` erano fuori da ENTRAMBI.
harness_fingerprint() {
  md5sum "$CORPUS/fidelity_arity.py" "$CORPUS/behavior.py" "$CORPUS/sig_sanity.py" \
         "$CORPUS/cross_build.py" "$CORPUS/unresolved.py" "$CORPUS/prototypes.json" \
         "$CORPUS/behavior_spec.json" \
         "$CORPUS/fidelity.sh" "$CORPUS/check.sh" \
         "$CORPUS/readability.py" "$CORPUS/callsite_consistency.py" \
         "$CORPUS/callsite_truth.py" \
         2>/dev/null | md5sum | cut -d' ' -f1
}
HARNESS_FP=$(harness_fingerprint)

FP_BEFORE=$(fingerprint)
echo "== measure.sh: label=$LABEL fingerprint=${FP_BEFORE:0:12} harness=${HARNESS_FP:0:8} =="

rm -rf "$DEST"
mkdir -p "$DEST/out"

# ── 1. Regenerate into the run's OWN snapshot (never into out/) ──────────────
gen_fail=0
for f in "$CORPUS"/bin/*.exe; do
  n=$(basename "$f" .exe)
  HL=""; [ "$PATH_B" = 1 ] && HL="--hlil-experimental"
  if ! "$DRIVER" "$f" "$DEST/out/$n" $HL >/dev/null 2>&1; then
    echo "  GEN FAIL: $n"
    gen_fail=$((gen_fail+1))
  fi
done
c_count=$(find "$DEST/out" -name '*.c' ! -name '*.hlil.c' | wc -l)
echo "  generated: $c_count .c files, $gen_fail generation failures"
if [ "$PATH_B" = 1 ]; then
  b_count=$(find "$DEST/out" -name '*.hlil.c' | wc -l)
  echo "  generated (path B): $b_count .hlil.c units"
  # Uno ZERO qui non e' "path B non ha unita'": e' il gate che non ha preso.
  # Vedi la regola del denominatore accanto allo zero.
  [ "$b_count" -gt 0 ] || echo "  *** ATTENZIONE: --path-b chiesto ma 0 unita' path B: flag --hlil-experimental inefficace ***"
fi

# ── 2. Brace balance — literals stripped FIRST ───────────────────────────────
# Braces inside emitted string literals false-flag balanced files (a real
# regression source since string-literal emission landed 2026-07-14).
find "$DEST/out" -name '*.c' ! -name '*.hlil.c' -print0 \
  | xargs -0 perl -0777 -ne '
      s/"(\\.|[^"\\])*"//gs;
      my $o = () = /\{/g;
      my $c = () = /\}/g;
      print "UNBALANCED $ARGV $o/$c\n" if $o != $c;
    ' > "$DEST/braces.txt" 2>/dev/null
unbalanced=$(wc -l < "$DEST/braces.txt")
echo "  brace balance: $unbalanced unbalanced"

# ── 3. Arity fidelity, against THIS snapshot ────────────────────────────────
bash "$CORPUS/fidelity.sh" "$DEST/out" > "$DEST/fidelity.txt" 2>&1
arity=$(grep -oE 'TOTAL: [0-9]+/[0-9]+' "$DEST/fidelity.txt" | tail -1 | sed 's/TOTAL: //')
echo "  arity fidelity (legacy, n=16): ${arity:-n/a}"

# Widened arity metric (n≈135). The legacy 16 are a subset of this set, kept
# above only so a historical number stays comparable; THIS is the one with a
# usable gradient, and it separates phantom args from missed ones.
python "$CORPUS/fidelity_arity.py" "$DEST/out" > "$DEST/arity.txt" 2>&1
python "$CORPUS/fidelity_arity.py" "$DEST/out" --json > "$DEST/arity.json" 2>/dev/null
# Paths go through argv, never inside a `-c` string: Git Bash rewrites POSIX
# paths to Windows form only for ARGUMENTS, so an embedded `/c/...` literal
# reaches Windows Python unconverted and silently fails to open — which is
# exactly how this metric first reported a confident `n=0`.
read -r arity_n arity_ok arity_over arity_under arity_pct <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["checked"],d["correct"],d["over"],d["under"],d["pct"])' \
    "$DEST/arity.json" 2>/dev/null || echo "0 0 0 0 null"
)"
echo "  arity fidelity (n=$arity_n): $arity_ok correct (${arity_pct}%)  over=$arity_over under=$arity_under"

# ── Behavioural fidelity: compile, LINK and RUN the emitted C against the
#    original. The only metric here that measures the stated goal rather than a
#    proxy for it. See behavior.py.
# ONE invocation, both outputs (`--json-out`). This used to be two identical
# runs differing only in output format, and behaviour is the expensive metric:
# it compiles, links the transitive closure and EXECUTES every function in the
# spec against 2000-3300 objects per bucket. Measured on runs/wip_0815:
# behavior.txt at 20:03:48, behavior.json at 20:33:55 -- ~30 minutes to reprint
# the same analysis, i.e. a full measurement cost ~62 minutes instead of ~32.
python "$CORPUS/behavior.py" "$DEST/out" --json-out "$DEST/behavior.json" \
       > "$DEST/behavior.txt" 2>&1
read -r beh_total beh_agree <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["total"],d["agree"])' \
    "$DEST/behavior.json" 2>/dev/null || echo "0 0"
)"
echo "  behaviour: $beh_agree/$beh_total agree on all inputs"
# ⚠ NON tutti i bucket comportamentali leggono QUESTO snapshot.
#
# `behavior.py:609`: un bucket puo' dichiarare un `out_dir` proprio, e 17 dei 25
# lo fanno, puntando a `behav/out` -- un albero FISSO che `measure.sh` NON
# rigenera. Quei bucket sono quindi **immuni** a qualunque modifica del
# decompilatore misurata da qui: una corsa `--label before/after` non puo'
# vederne l'effetto.
#
# Costo reale, gia' pagato due volte: il 2026-08-20 produsse una diagnosi
# sbagliata, e il 2026-08-29 fece leggere 23/62 dove il numero vero era 47/62
# (una MISCELA: 8 bucket dallo snapshot + 17 da behav/out non aggiornato).
#
# Finche' non e' risolto, la misura lo DICHIARA invece di tacerlo.
esterni=$(python - "$CORPUS/behavior_spec.json" <<'PYEOF'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
b=d.get("buckets", d)
tot=sum(1 for v in b.values() if isinstance(v,dict))
ext=sum(1 for v in b.values() if isinstance(v,dict) and v.get("out_dir"))
print(f"{ext}/{tot}")
PYEOF
)
case "$esterni" in
  0/*) ;;
  *) echo "    ⚠ $esterni bucket leggono un albero ESTERNO allo snapshot (behav/out):"
     echo "      immuni alle modifiche misurate qui. Vedi behavior.py:609." ;;
esac

# ── Signature sanity: defects decidable from the signature text alone.
#    Tracked separately from recompilability so a naming regression cannot hide
#    inside an unchanged total dominated by an unrelated class.
python "$CORPUS/sig_sanity.py" "$DEST/out" > "$DEST/sig_sanity.txt" 2>&1
python "$CORPUS/sig_sanity.py" "$DEST/out" --json > "$DEST/sig_sanity.json" 2>/dev/null
read -r sig_n sig_dup sig_shadow <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["signatures"],d["duplicate_param"],d["shadows_keyword"])' \
    "$DEST/sig_sanity.json" 2>/dev/null || echo "0 0 0"
)"
echo "  signatures: $sig_n scanned, duplicate_param=$sig_dup shadows_keyword=$sig_shadow"

# ── Cross-build consistency: the corpus as its own control group.
#    ~1360 runtime functions are reconstructed from several independently
#    compiled binaries; two reconstructions that disagree cannot both be right,
#    and no ground truth is needed to say so. Complements the prototype metric,
#    which only covers ~135 names and cannot see a defect present in one build.
python "$CORPUS/cross_build.py" "$DEST/out" > "$DEST/cross_build.txt" 2>&1
python "$CORPUS/cross_build.py" "$DEST/out" --json > "$DEST/cross_build.json" 2>/dev/null
read -r xb_n xb_bad <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["compared"],d["inconsistent"])' \
    "$DEST/cross_build.json" 2>/dev/null || echo "0 0"
)"
echo "  cross-build: $xb_n functions in >=2 builds, $xb_bad inconsistent"

# ── Unresolved data symbols: what the project references but never defines.
#    22773 `extern off_…` declarations and ZERO definitions, so ~half the emitted
#    files cannot link. `-fsyntax-only` accepts an undefined extern by design, so
#    the recompilability metric is structurally unable to see this.
#    `actionable` excludes addresses outside the image (relocations / runtime
#    references, legitimately extern) — the raw count overstates the defect ~4x.
python "$CORPUS/unresolved.py" "$DEST/out" > "$DEST/unresolved.txt" 2>&1
python "$CORPUS/unresolved.py" "$DEST/out" --json > "$DEST/unresolved.json" 2>/dev/null
read -r unres_files unres_act unres_code unres_def <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["files_with_unresolved"],d["actionable"],d["code_as_data"],d["data_symbols_defined"])' \
    "$DEST/unresolved.json" 2>/dev/null || echo "0 0 0 0"
)"
echo "  unresolved: $unres_files files reference undefined data; actionable=$unres_act code_as_data=$unres_code defined=$unres_def"

# ── Leggibilita': l'unica dimensione su cui path A batte path B ──────────────
#
# Nove metriche sopra misurano CORRETTEZZA. Nessuna misura quanto il testo sia
# LEGGIBILE -- e CLAUDE.md mette «readable» PRIMA di «recompilable».
#
# Misurato il 2026-08-29: path A ha 0 goto, path B ne ha 11387 (in 22,8% dei
# file, mediana 2); righe +31%, cast 2,2x, profondita' +1. Senza questa riga la
# commutazione del deliverable su B sarebbe sembrata un miglioramento puro,
# mentre e' uno SCAMBIO.
#
# Sta QUI, e non in uno script che qualcuno deve ricordarsi di lanciare, per la
# stessa ragione per cui `QualityAnalyser` (1173 righe) non ha mai misurato
# nulla: una capacita' che nessuno esegue non esiste.
python "$CORPUS/readability.py" "$DEST/out" --json > "$DEST/readability.json" 2>/dev/null
read -r rd_goto rd_righe rd_cast <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["goto"],d["righe_per_unita"],d["cast_per_unita"])'     "$DEST/readability.json" 2>/dev/null || echo "0 0 0"
)"
echo "  readability: goto=$rd_goto righe/unita=$rd_righe cast/unita=$rd_cast"

# callsite_consistency: arieta' con cui una funzione e' DEFINITA contro
# quella con cui e' CHIAMATA nello stesso progetto. Nessuna verita' esterna:
# se il codice si contraddice, un lato sbaglia. Ed e' cieca per costruzione a
# check.sh, perche' gcc accetta f(a,b,c,d) contro `__int64 f();`.
python "$CORPUS/callsite_consistency.py" "$DEST/out" --json > "$DEST/callsite.json" 2>/dev/null
read -r cs_def cs_over cs_under <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["definitions"],d["over"],d["under"])'     "$DEST/callsite.json" 2>/dev/null || echo "0 0 0"
)"
echo "  callsite: def=$cs_def over=$cs_over under=$cs_under"

# callsite_truth: gli argomenti ai siti contro i PROTOTIPI PUBBLICATI.
# callsite_consistency misura la coerenza INTERNA e non distingue "coerente e
# giusto" da "coerente e sbagliato due volte": misurato 29-08, path A chiama
# pthread_mutex_unlock (arieta' vera 1) con 2 argomenti E la definisce con 2,
# quindi risulta coerente pur sbagliando due volte.
python "$CORPUS/callsite_truth.py" "$DEST/out" --json > "$DEST/callsite_truth.json" 2>/dev/null
read -r ct_sites ct_ok <<<"$(
  python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["sites"],d["correct_pct"])'     "$DEST/callsite_truth.json" 2>/dev/null || echo "0 0"
)"
echo "  callsite_truth: $ct_ok% corretti su $ct_sites siti con firma nota"

# ── 3b. Colonna PATH B (solo con --path-b) ──────────────────────────────────
# ACCANTO alle colonne path A, mai al posto: due letture della stessa corsa.
# I 4 harness senza flag proprio leggono MEASURE_PATH_B; i 2 che hanno gia'
# --path-b usano il loro flag. Vocabolario diverso, stesso significato.
if [ "$PATH_B" = 1 ]; then
  echo "  ---- path B ----"
  MEASURE_PATH_B=1 python "$CORPUS/fidelity_arity.py" "$DEST/out" --json       > "$DEST/arity_b.json" 2>/dev/null
  read -r b_n b_ok b_over b_under b_pct <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["checked"],d["correct"],d["over"],d["under"],d["pct"])'       "$DEST/arity_b.json" 2>/dev/null || echo "0 0 0 0 null"
  )"
  echo "  [B] arity fidelity (n=$b_n): $b_ok correct (${b_pct}%)  over=$b_over under=$b_under"

  python "$CORPUS/behavior.py" "$DEST/out" --path-b --json-out "$DEST/behavior_b.json"       > "$DEST/behavior_b.txt" 2>&1
  read -r bb_total bb_agree <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["total"],d["agree"])'       "$DEST/behavior_b.json" 2>/dev/null || echo "0 0"
  )"
  echo "  [B] behaviour: $bb_agree/$bb_total agree on all inputs"

  MEASURE_PATH_B=1 python "$CORPUS/sig_sanity.py" "$DEST/out" --json       > "$DEST/sig_sanity_b.json" 2>/dev/null
  read -r sb_n sb_dup sb_shadow <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["signatures"],d["duplicate_param"],d["shadows_keyword"])'       "$DEST/sig_sanity_b.json" 2>/dev/null || echo "0 0 0"
  )"
  echo "  [B] signatures: $sb_n scanned, duplicate_param=$sb_dup shadows_keyword=$sb_shadow"

  MEASURE_PATH_B=1 python "$CORPUS/unresolved.py" "$DEST/out" --json       > "$DEST/unresolved_b.json" 2>/dev/null
  read -r ub_files ub_act ub_code ub_def <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["files_with_unresolved"],d["actionable"],d["code_as_data"],d["data_symbols_defined"])'       "$DEST/unresolved_b.json" 2>/dev/null || echo "0 0 0 0"
  )"
  echo "  [B] unresolved: $ub_files files; actionable=$ub_act code_as_data=$ub_code defined=$ub_def"
  python "$CORPUS/readability.py" "$DEST/out" --path-b --json > "$DEST/readability_b.json" 2>/dev/null
  read -r rb_goto rb_righe rb_cast <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["goto"],d["righe_per_unita"],d["cast_per_unita"])'       "$DEST/readability_b.json" 2>/dev/null || echo "0 0 0"
  )"
  echo "  [B] readability: goto=$rb_goto righe/unita=$rb_righe cast/unita=$rb_cast"
  python "$CORPUS/callsite_consistency.py" "$DEST/out" --path-b --json > "$DEST/callsite_b.json" 2>/dev/null
  read -r csb_def csb_over csb_under <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["definitions"],d["over"],d["under"])'       "$DEST/callsite_b.json" 2>/dev/null || echo "0 0 0"
  )"
  echo "  [B] callsite: def=$csb_def over=$csb_over under=$csb_under"
  python "$CORPUS/callsite_truth.py" "$DEST/out" --path-b --json > "$DEST/callsite_truth_b.json" 2>/dev/null
  read -r ctb_sites ctb_ok <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["sites"],d["correct_pct"])'       "$DEST/callsite_truth_b.json" 2>/dev/null || echo "0 0"
  )"
  echo "  [B] callsite_truth: $ctb_ok% corretti su $ctb_sites siti"
  MEASURE_PATH_B=1 python "$CORPUS/cross_build.py" "$DEST/out" --json > "$DEST/cross_build_b.json" 2>/dev/null
  read -r xb_bn xb_bbad <<<"$(
    python -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["compared"],d["inconsistent"])'       "$DEST/cross_build_b.json" 2>/dev/null || echo "0 0"
  )"
  echo "  [B] cross-build: $xb_bn functions in >=2 builds, $xb_bbad inconsistent"
  echo "  ---------------"
fi

# ── 4. Recompilability (opt-in: ~11k gcc invocations) ───────────────────────
recompile="skipped"
if [ "$FULL" = "1" ]; then
  # Buckets run in PARALLEL. Serially this is ~11k gcc invocations at ~0.6 s each
  # — about two hours — and a job that long does not survive: two background runs
  # were killed partway (at 7/12 and 6/12 buckets), producing no metrics at all.
  # A measurement nobody can afford to finish is a measurement that does not
  # exist, so wall time is a correctness concern here, not an optimisation.
  #
  # Each bucket writes its own file and they are concatenated afterwards:
  # appending to one file from parallel jobs interleaves lines and corrupts the
  # per-bucket `TOTAL:` tallies the comparison depends on.
  : > "$DEST/check.txt"
  JOBS=$(( $(nproc 2>/dev/null || echo 4) / 4 ))
  [ "$JOBS" -lt 1 ] && JOBS=1
  [ "$JOBS" -gt 8 ] && JOBS=8
  printf '%s\n' "$DEST"/out/*/ \
    | xargs -P "$JOBS" -I{} sh -c \
        'bash "$1/check.sh" "$2" > "$2/../.check_$(basename "$2").txt" 2>&1' _ "$CORPUS" {}
  # The per-bucket files land in $DEST/out/, not $DEST/: the xargs argument keeps
  # its trailing slash, so `"$2/.."` resolves to $DEST/out/sampleX/.. = $DEST/out.
  # Reading them from the wrong directory produced an empty check.txt and a
  # confident `recompilability: /` — a whole parallel pass silently discarded.
  cat "$DEST"/out/.check_*.txt >> "$DEST/check.txt" 2>/dev/null
  rm -f "$DEST"/out/.check_*.txt
  # check.sh prints "TOTAL: <pass>/<total> passing"; with this separator the
  # numbers land in $2 and $3. Using $3/$4 (the total and the word "passing")
  # yields a confident nonsense figure like "2656/0" — verified, not assumed.
  recompile=$(awk -F'[:/ ]+' '/^TOTAL:/ {p+=$2; t+=$3} END {print p"/"t}' "$DEST/check.txt")
  echo "  recompilability: $recompile"
fi

# ── 5. Per-function confidence + evidence, for drift comparison ─────────────
python - "$DEST" <<'PY'
import json, os, sys
dest = sys.argv[1]
funcs, silent, no_expl = {}, 0, 0
root = os.path.join(dest, "out")
for d in sorted(os.listdir(root)):
    p = os.path.join(root, d, "summary.json")
    if not os.path.exists(p):
        continue
    for f in json.load(open(p))["files"]:
        funcs[f"{d}:{f['address']}"] = {
            "confidence": f["confidence"],
            "explain": f.get("confidence_explain"),
        }
        if f.get("confidence_silent_wrongness"):
            silent += 1
        if f.get("confidence_explain") is None:
            no_expl += 1
json.dump(funcs, open(os.path.join(dest, "confidence.json"), "w"))
print(f"  functions: {len(funcs)}  silent_wrongness: {silent}  missing_evidence: {no_expl}")
# 8310: i due numeri servono alla shell per metrics.json e per il confronto.
open(os.path.join(dest, "confidence_counts.txt"), "w").write(f"{silent} {no_expl}")
PY

# 8310: rileggi i due conteggi prodotti dal blocco sopra.
read -r sw_silent sw_noexpl < "$DEST/confidence_counts.txt" 2>/dev/null || true
: "${sw_silent:=0}" "${sw_noexpl:=0}"

# ── 6. Publish ONLY if the tree held still ──────────────────────────────────
FP_AFTER=$(fingerprint)
TAINTED=0
if [ "$FP_BEFORE" != "$FP_AFTER" ]; then
  TAINTED=1
  echo
  echo "  *** TAINTED: the tree changed DURING this run ***"
  echo "  before=${FP_BEFORE:0:12} after=${FP_AFTER:0:12}"
  echo "  Another agent edited a source or harness while measuring."
  echo "  These numbers describe no single tree state. Not published. Re-run."
fi

cat > "$DEST/metrics.json" <<EOF
{
  "label": "$LABEL",
  "tainted": $([ $TAINTED = 1 ] && echo true || echo false),
  "harness_fingerprint": "$HARNESS_FP",
  "fingerprint_before": "$FP_BEFORE",
  "fingerprint_after": "$FP_AFTER",
  "c_files": $c_count,
  "generation_failures": $gen_fail,
  "unbalanced_braces": $unbalanced,
  "arity_fidelity_legacy": "${arity:-null}",
  "arity_checked": $arity_n,
  "arity_correct": $arity_ok,
  "arity_over": $arity_over,
  "arity_under": $arity_under,
  "behaviour_tested": $beh_total,
  "behaviour_agree": $beh_agree,
  "signatures": $sig_n,
  "duplicate_param": $sig_dup,
  "shadows_keyword": $sig_shadow,
  "crossbuild_compared": $xb_n,
  "crossbuild_inconsistent": $xb_bad,
  "unresolved_files": $unres_files,
  "unresolved_actionable": $unres_act,
  "unresolved_code_as_data": $unres_code,
  "data_symbols_defined": $unres_def,
  "recompilability": "$recompile",
  "readability_goto": ${rd_goto:-0},
  "readability_cast_per_unit": "${rd_cast:-0}",
  "callsite_definitions": ${cs_def:-0},
  "callsite_over": ${cs_over:-0},
  "callsite_under": ${cs_under:-0},
  "silent_wrongness": ${sw_silent:-0},
  "missing_evidence": ${sw_noexpl:-0},
  "callsite_truth_sites": ${ct_sites:-0},
  "callsite_truth_pct": ${ct_ok:-0}
}
EOF
[ $TAINTED = 1 ] && exit 3

# ── 7. Self-vs-self comparison ──────────────────────────────────────────────
if [ -n "$COMPARE" ]; then
  BASE="$RUNS/$COMPARE"
  if [ ! -f "$BASE/metrics.json" ]; then
    echo "  no such run to compare: $COMPARE" >&2
    exit 2
  fi
  if [ "$(python -c 'import json,sys;print(json.load(open(sys.argv[1]))["tainted"])' "$BASE/metrics.json")" = "True" ]; then
    echo "  baseline '$COMPARE' is TAINTED — comparison refused." >&2
    exit 2
  fi
  echo
  echo "== $COMPARE -> $LABEL =="
  BASE_HFP=$(python -c 'import json,sys;print(json.load(open(sys.argv[1])).get("harness_fingerprint",""))' "$BASE/metrics.json" 2>/dev/null)
  if [ -z "$BASE_HFP" ]; then
    # Baseline predates harness fingerprinting: we cannot know which version of
    # the metrics produced it. Unknown is not the same as equal, and asserting a
    # regression on an unknown basis is the exact failure this script exists to
    # prevent.
    echo "  NOTE: '$COMPARE' was recorded before the harness was fingerprinted,"
    echo "        so it is unknown whether the same metric code produced it."
    echo "        Differences below are reported but NOT called regressions."
    HARNESS_MOVED=1
  elif [ "$BASE_HFP" != "$HARNESS_FP" ]; then
    echo "  NOTE: the measuring harness itself changed since '$COMPARE'"
    echo "        (${BASE_HFP:0:8} -> ${HARNESS_FP:0:8}). A metric that got stricter"
    echo "        lowers its number without the decompiler getting worse, so the"
    echo "        differences below are NOT attributable to emitted code."
    HARNESS_MOVED=1
  else
    HARNESS_MOVED=0
  fi
  HARNESS_MOVED=$HARNESS_MOVED python - "$BASE" "$DEST" <<'PY' || exit 1
import json, os, sys
base, new = sys.argv[1], sys.argv[2]
mb = json.load(open(os.path.join(base, "metrics.json")))
mn = json.load(open(os.path.join(new,  "metrics.json")))
regressed = False
for k in ("c_files", "unbalanced_braces", "arity_fidelity_legacy", "arity_checked",
          "arity_correct", "arity_over", "arity_under",
          "behaviour_tested", "behaviour_agree", "signatures",
          "duplicate_param", "shadows_keyword", "crossbuild_compared",
          "crossbuild_inconsistent", "unresolved_files",
          "unresolved_actionable", "unresolved_code_as_data",
          "data_symbols_defined", "recompilability",
          "generation_failures",
          "readability_goto", "readability_cast_per_unit",
          "callsite_definitions", "callsite_over", "callsite_under",
          "silent_wrongness", "missing_evidence",
          "callsite_truth_sites", "callsite_truth_pct"):
    a, b = mb.get(k), mn.get(k)
    flag = ""
    # "skipped" is the absence of a measurement, not a different one. Flagging
    # `11117/11144 -> skipped` as a change trains the reader to ignore the flags,
    # which is worse than not printing them.
    if "skipped" in (a, b):
        print(f"  {k:24} {a}  ->  {b}   (not measured this run)")
        continue
    if a != b:
        # Lower is better for defect counts, higher for correct-counts and ratios.
        if k in ("unbalanced_braces", "generation_failures", "arity_over",
                 "arity_under", "duplicate_param", "shadows_keyword",
                 "crossbuild_inconsistent", "unresolved_files",
                 "unresolved_actionable", "unresolved_code_as_data"):
            worse = (b or 0) > (a or 0)
        elif k in ("arity_correct", "behaviour_agree"):
            worse = (b or 0) < (a or 0)
        elif isinstance(a, str) and "/" in str(a) and "/" in str(b):
            # A malformed ratio ("/" with no numbers) means the pass did not run.
            # Crashing the whole comparison over it loses every other metric, so
            # it is reported as unknown instead.
            try:
                worse = int(str(b).split("/")[0]) < int(str(a).split("/")[0])
            except ValueError:
                print(f"  {k:24} {a}  ->  {b}   (unparseable, pass did not run)")
                continue
        else:
            worse = False
        moved = os.environ.get("HARNESS_MOVED") == "1"
        # With a changed harness a lower number is not evidence of worse output.
        flag = ("  <== changed (harness differs)" if moved
                else ("  <== REGRESSION" if worse else "  <== changed"))
        regressed = regressed or (worse and not moved)
    print(f"  {k:24} {a}  ->  {b}{flag}")

# Per-function behavioural status. A count-only comparison cannot see one
# function regressing while another improves; naming the function is what makes
# the number actionable.
try:
    bb = json.load(open(os.path.join(base, "behavior.json"))).get("functions", {})
    bn = json.load(open(os.path.join(new,  "behavior.json"))).get("functions", {})
    moved = [(k, bb[k], bn[k]) for k in sorted(bb.keys() & bn.keys()) if bb[k] != bn[k]]
    for k, was, now in moved:
        worse = was == "AGREE" and now != "AGREE"
        print(f"  behaviour {k}: {was} -> {now}{'  <== REGRESSION' if worse else ''}")
        regressed = regressed or worse
except (OSError, ValueError):
    pass

cb = json.load(open(os.path.join(base, "confidence.json")))
cn = json.load(open(os.path.join(new,  "confidence.json")))
drift = [k for k in cb.keys() & cn.keys()
         if cb[k]["confidence"] != cn[k]["confidence"]]
print(f"  {'confidence drift':24} {len(drift)} of {len(cb.keys() & cn.keys())} shared functions")
for k in drift[:5]:
    print(f"      {k}: {cb[k]['confidence']} -> {cn[k]['confidence']}  ({cn[k]['explain']})")
only_b, only_n = cb.keys() - cn.keys(), cn.keys() - cb.keys()
if only_b or only_n:
    print(f"  {'functions gone/new':24} -{len(only_b)} / +{len(only_n)}")
sys.exit(1 if regressed else 0)
PY
fi

# ── 8. Retention: keep every run's METRICS, prune old emitted trees ─────────
# Each snapshot's `out/` is ~53 MB, so a few runs fill the disk and the script
# quietly becomes something you avoid running — which defeats it. Comparisons
# only read metrics.json / confidence.json / behavior.json (all small), so the
# emitted tree is kept for the two most recent runs (enough to diff the actual C
# of a before/after pair) and dropped for older ones. Metrics are never deleted:
# the history of numbers is the point.
# `runs/` is SHARED: other agents record snapshots here too. A count-only rule
# deletes someone else's `before/` while they are still working towards their
# `after/` — and this file tells them to `diff -rq` those two trees, so the
# pruning would break the very workflow the docs prescribe. Age is therefore a
# veto: a snapshot younger than MIN_AGE_H is never pruned no matter how many
# newer runs exist. Metrics are still never deleted.
KEEP_OUT=2
MIN_AGE_H=6
mapfile -t ALL_RUNS < <(ls -1dt "$RUNS"/*/ 2>/dev/null)
for i in "${!ALL_RUNS[@]}"; do
  d="${ALL_RUNS[$i]}"
  [ "$i" -ge "$KEEP_OUT" ] && [ -d "${d}out" ] || continue
  if [ -n "$(find "$d" -maxdepth 0 -mmin +$((MIN_AGE_H * 60)) 2>/dev/null)" ]; then
    rm -rf "${d}out"
    echo "  pruned emitted tree of $(basename "$d") (metrics kept)"
  else
    echo "  kept $(basename "$d") — younger than ${MIN_AGE_H}h, may belong to a run in progress"
  fi
done

echo
echo "snapshot: $DEST"
