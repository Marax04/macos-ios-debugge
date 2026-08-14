#!/usr/bin/env bash
# Regenerate the real-symbol corpora used by tests/real_corpus.rs and
# tests/pdb_corpus.rs.
#
#   ./regenerate.sh          # rewrite both corpus files in place
#   ./regenerate.sh --check  # verify the checked-in files are reproducible
#
# Why this is a script and not a comment: both corpora have already been
# corrupted once by ad-hoc regeneration.
#
#   * `nm` prints `ADDRESS TYPE NAME`, and Go generic symbols contain spaces
#     (`internal/sync.(*HashTrieMap[go.shape.interface {},…]).Load`). Taking
#     the last whitespace-separated field truncated 13 of them to fragments
#     like `{}]).Load` and lost the symbols themselves.
#   * `sample3_rust.exe` is stripped, so `nm` yields no Rust or MSVC symbols at
#     all. Those live only in the PDBs, and for years neither backend had any
#     real-world coverage because of it.
#
# Both traps are silent: you get a plausible-looking file either way.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin="$here/../../../../tests/decompiler_corpus/bin"

if [[ ! -d $bin ]]; then
  echo "corpus binaries not found at $bin" >&2
  exit 1
fi

# Everything from the NAME field onward, so names containing spaces survive.
extract_nm() {
  for exe in "$bin"/*.exe; do
    nm "$exe" 2>/dev/null || true
  done | awk '{
      if ($1 ~ /^[0-9a-fA-F]+$/) { $1=""; $2="" } else { $1="" }
      print
    }' | sed 's/^[[:space:]]*//' | grep -v '^$' | sort -u
}

# `S_PUB32` records are the linker-visible public symbols — the names a
# demangler actually receives.
extract_pdb() {
  for pdb in "$bin"/*.pdb; do
    [[ -e $pdb ]] || continue
    llvm-pdbutil dump --publics "$pdb" 2>/dev/null || true
  done | grep -oE 'S_PUB32 \[size = [0-9]+\] `[^`]+`' \
    | sed -E 's/.*`(.*)`/\1/' | sort -u
}

# A corpus that lost a whole symbol class still looks fine at a glance, so
# assert the properties whose absence caused the past breakages.
sanity_check() {
  local nm_file=$1 pdb_file=$2 failed=0

  if ! grep -q 'interface {}' "$nm_file"; then
    echo "FAIL: no space-bearing Go generic symbols — nm fields were split" >&2
    failed=1
  fi
  if grep -q '^{}' "$nm_file"; then
    echo "FAIL: truncated symbol fragments present (lines starting with '{}')" >&2
    failed=1
  fi
  if ! grep -qE '^_R[CNMXYIKB]' "$pdb_file"; then
    echo "FAIL: no Rust v0 symbols in the PDB corpus" >&2
    failed=1
  fi
  if ! grep -q '^?' "$pdb_file"; then
    echo "FAIL: no MSVC symbols in the PDB corpus" >&2
    failed=1
  fi
  return $failed
}

tmp_nm="$(mktemp)"
tmp_pdb="$(mktemp)"
# PE IMPORT TABLES — a third source, invisible to `nm`.
#
# `nm` lists a PE binary's defined and undefined symbols but not its import
# directory, so the names the program calls into KERNEL32/msvcrt never reached
# either corpus. They matter for one specific reason: 58 of them begin with an
# underscore (`_amsg_exit`, `__C_specific_handler`, `___lc_codepage_func`),
# which is exactly the shape that made the old `_R`/`_T`/`_D` prefix rules
# invent phantom defects. This is real ground truth for the case `src/sigil.rs`
# exists to prevent, and it cost nothing to collect.
extract_imports() {
  for f in "$bin"/*.exe; do
    # `|| true` for the same reason `extract_nm` needs it: a statically linked
    # Go binary has no import directory, and a `grep` that matches nothing
    # returns 1, which under `set -e` kills the whole run.
    objdump -p "$f" 2>/dev/null |
      { grep -oE "<none>[[:space:]]+[0-9a-f]{4}[[:space:]]+\S+" || true; } |
      awk '{print $3}'
  done | LC_ALL=C sort -u
}

# PDB PROCEDURE RECORDS — a fourth source, invisible to `--publics`.
#
# `extract_pdb` above takes only `S_PUB32`. The procedure records a few bytes
# away hold the *already-demangled* name: an MSVC-targeting compiler writes the
# decoded form into debug info, so a PDB carries both. That is a symbol shape a
# demangler normally never sees, and the crate had no category for it — 223 of
# these landed in `DeclineReason::Unknown`, which is held at zero precisely so
# an unrecognised shape gets named rather than parked.
extract_pdb_procs() {
  for pdb in "$bin"/*.pdb; do
    [[ -e $pdb ]] || continue
    llvm-pdbutil dump --symbols "$pdb" 2>/dev/null || true
  done | { grep -oE 'S_(GPROC32|LPROC32|THUNK32|LDATA32|GDATA32) .*`[^`]+`' || true; } \
    | sed -E 's/.*`(.*)`/\1/' | LC_ALL=C sort -u
}

tmp_imp=$(mktemp)
tmp_proc=$(mktemp)
trap 'rm -f "$tmp_nm" "$tmp_pdb" "$tmp_imp" "$tmp_proc"' EXIT

extract_nm > "$tmp_nm"
extract_pdb > "$tmp_pdb"
extract_imports > "$tmp_imp"
extract_pdb_procs > "$tmp_proc"
sanity_check "$tmp_nm" "$tmp_pdb"

# The proc corpus exists for the already-demangled shape, so it must contain
# it. Without this the record kinds could drift to ones carrying mangled names
# and the corpus would still look populated.
if ! grep -q '::' "$tmp_proc"; then
  echo "no scope-separated names in the proc corpus — check the record kinds" >&2
  exit 1
fi

# The import corpus must be plain C: an import name carrying an ABI sigil would
# mean the extraction picked up something other than the import directory.
if grep -qE '^(_Z|_R|\$s|\?)' "$tmp_imp"; then
  echo "import extraction picked up mangled names — check the objdump format" >&2
  exit 1
fi

if [[ ${1-} == --check ]]; then
  status=0
  diff -u "$here/real_symbols.txt" "$tmp_nm" || status=1
  diff -u "$here/pdb_symbols.txt" "$tmp_pdb" || status=1
  diff -u "$here/import_symbols.txt" "$tmp_imp" || status=1
  diff -u "$here/pdb_proc_symbols.txt" "$tmp_proc" || status=1
  [[ $status -eq 0 ]] && echo "corpora are reproducible"
  exit $status
fi

cp "$tmp_nm" "$here/real_symbols.txt"
cp "$tmp_pdb" "$here/pdb_symbols.txt"
cp "$tmp_imp" "$here/import_symbols.txt"
cp "$tmp_proc" "$here/pdb_proc_symbols.txt"
echo "real_symbols.txt: $(wc -l < "$here/real_symbols.txt") symbols"
echo "pdb_symbols.txt:  $(wc -l < "$here/pdb_symbols.txt") symbols"
echo "import_symbols.txt: $(wc -l < "$here/import_symbols.txt") symbols"
echo "pdb_proc_symbols.txt: $(wc -l < "$here/pdb_proc_symbols.txt") symbols"
