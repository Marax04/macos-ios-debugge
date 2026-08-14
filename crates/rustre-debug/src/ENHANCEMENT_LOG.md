
## Iter 219 (2026-07-21) — REAL fix: unbounded allocation in msf_reader.rs::read_stream (untrusted PDB size)
- Fresh angle after the field-completeness audit closed: iters 208-212's
  checked-arithmetic/sanity-cap hardening pass only covered the CFI code
  (linux_debugger.rs/windows_debugger.rs/dwarf_cfi.rs) — never swept the
  MSF/PDB reader (`codeview/msf_reader.rs`), which parses equally
  untrusted external file data (any `.pdb` handed to `debug.load_types`).
- Found: `read_stream`'s `Vec::with_capacity(info.size as usize)` uses
  `info.size` — a raw u32 straight from the stream directory, up to
  ~4.29 GB — with NO sanity cap, unlike every ELF/PE section size
  elsewhere in the crate. Traced a real amplification path: a crafted
  directory needs only `size/page_size` cheap 4-byte page-index entries
  (all can point at the same valid page) to make `parse()` itself
  succeed, so a ~33 MB crafted `.pdb` can trigger a ~4.29 GB allocation
  attempt in `read_stream` — a real DoS surface, not theoretical.
- Fixed: added `MAX_STREAM_SIZE = 256 MiB` cap (same value as the
  ELF/PE precedent) and a new `MsfError::StreamTooLarge` variant,
  checked immediately after the existing `is_absent()` check, before the
  allocation. New test `read_stream_rejects_a_declared_size_past_the_
  sanity_cap`: parses a real, otherwise-valid MSF container via the
  existing `fixture()`, mutates one stream's declared `size` field past
  the cap post-parse (mirrors the exact "directory says one thing, real
  data implies another" adversarial scenario), confirms rejection instead
  of ever reaching `Vec::with_capacity`.
- `cargo test --lib -p rustre-debug msf_reader`: 11/11 (was 10), zero
  regressions among existing msf_reader tests, including the two live
  real-PDB tests (`parse_real_pdb_if_present`/`real_pdb_types_import_
  end_to_end`) which are unaffected since real PDBs stay well under the
  cap. Full-suite Windows re-verification pending.

## Iter 221 (2026-07-21) — REAL fix: 3 more unbounded-allocation gaps, same bug class in twin CodeView parsers
- Continued the fresh angle from iter 219: the crate has TWO parallel
  CodeView type-record parser implementations (`cv_type_records.rs` /
  `codeview_types.rs` vs `codeview_type_parser.rs`) and two parallel
  line-table parsers (`codeview_parser.rs` vs `mod.rs`) — a legacy split
  worth checking for divergent hardening.
- Confirmed the divergence is real: `codeview_type_parser.rs::
  parse_arglist` already caps `LF_ARGLIST`'s untrusted `count` against
  the buffer (explicit comment: "avoid huge allocations"), but its twin
  `cv_type_records.rs::decode_arglist` and `codeview_types.rs`'s
  `LF_ARGLIST` match arm did NOT — both fed a raw untrusted u32 (up to
  ~4.29B, ~17GB at 4 bytes/entry) straight into `Vec::with_capacity`.
  Same for line tables: `mod.rs`'s line-subsection parser already caps
  `num_lines.min(65536)`, but `codeview_parser.rs::parse_line_subsection`
  didn't.
- Fixed all 3: capped each allocation hint to what the buffer/reader can
  actually hold (`data.len()/4` or `reader.remaining()/4` for arglists,
  `.min(65536)` matching the existing sibling constant for line tables).
  Loop bodies were already correctly bounds-checked — only the
  pre-sizing allocation was the gap, same class as iter 219's msf_reader
  fix.
- New tests: `test_decode_arglist_with_huge_declared_count_does_not_
  over_allocate` (cv_type_records.rs) and `parse_arglist_with_huge_
  declared_count_does_not_over_allocate` (new `arglist_allocation_tests`
  module in codeview_types.rs, since that file had no existing test
  module) — both construct a real record with `count = u32::MAX` and a
  tiny buffer, confirm graceful handling instead of an allocation abort.
- Windows `cargo test --lib -p rustre-debug`: **850/0** (was 848, +2).
  Linux (WSL) `cargo test --release --lib -- --test-threads=1`: **846/0**
  (was 844, +2). Zero regressions on either platform.
- **Lesson for future sessions**: when a crate has duplicate/legacy-split
  parser implementations for the same format, a fix applied to one twin
  is NOT proof the other twin got it too — diff the twins explicitly
  rather than assuming parity. This is exactly how iter 219's discovery
  ("audit exhausted" was wrong) generalizes: fresh angles keep finding
  real bugs even after multiple audit passes each declared their own
  scope clean.

## Iter 222 (2026-07-21) — swept remaining allocation sites, no more untrusted-file-data gaps found
Extended iter 221's twin-implementation-diff angle to a crate-wide sweep
of every `Vec::with_capacity`/`vec![0u8; N]` site fed by a non-literal
size. Found: macos_debugger.rs's thread/image counts come from live
kernel calls (task_threads/dyld), not parsed file data — already
precedent-capped where relevant (iter 114). cv_symbol_records.rs has NO
with_capacity calls at all — the earlier-suspected symbol-record twin gap
doesn't exist. windows_debugger.rs/macos_debugger.rs/linux_debugger.rs's
`read_memory`'s `size` param is CALLER-supplied via the MCP layer (a
trusted control-plane request), not untrusted external file/target data
— a different trust boundary than this session's established scope
(iters 208-212, 219, 221 all target malformed FILE/target data, not
caller-request parameters). Considered but not fixed as out of scope;
noting it here in case a future session decides API-request-size capping
is worth doing as a separate, deliberate goal. No further untrusted-file
allocation gaps found in this sweep — this specific vein (twin-parser
allocation-cap divergence) is now genuinely exhausted, unlike iters 213/
218's earlier premature "exhausted" claims which a fresh angle overturned.

## Iter 223 (2026-07-21) — final crate-wide with_capacity sweep, confirms iter 222's closure
Extended the sweep beyond codeview/ to every `with_capacity` call in the
crate (expression_evaluator.rs, lib.rs, memory_search.rs, source_map.rs,
debug_session_recorder.rs, register_context.rs, multi_target_debugger.rs,
memory_layout_view.rs). All are sized from already-bounded real data
(parsed row counts from validated structures, live input string length,
existing in-memory buffer length) — none feed a raw untrusted size field
from external file/target data directly into an allocation the way the
iter 219/221 bugs did. Re-confirmed msf_reader's num_streams/n_pages are
correctly bounds-checked (sizes_end/pages_end against directory.len())
BEFORE their with_capacity calls, not after — genuinely safe, not a
missed case. Windows 850/0 stable. This is the third and final
confirmation (after iters 222's initial sweep) that the untrusted-
allocation vein is exhausted crate-wide, not just within codeview/.

## Iter 224 (2026-07-21) — subtraction-underflow sweep of codeview/, no bugs found
Tried a genuinely different bug class from iters 219-223's allocation-cap
work: raw `a - b` subtraction on parsed/untrusted values, which could
underflow-panic in a debug build if b > a (same class iter 208/209 fixed
for CFI code, via checked_sub). Swept every non-trivial subtraction in
codeview/ (codeview_parser.rs, mod.rs's parse_file_checksums/lookup_
nearest/section-rva-to-offset, cv_stream_parser.rs's lookup_va,
codeview_symbol_parser.rs's nearest_function). Every instance checked out
already-safe: loop-bound subtractions are inside a `while pos+N <=
data.len()` guard that guarantees non-negative results, and every
"nearest address" `min_by_key(|x| addr - x)` pattern is preceded by a
`.filter(|x| x <= addr)` that makes the subtraction safe by construction.
No fix needed — a genuine negative result, not a missed case. Windows
850/0 unaffected (no code change this iteration).

## Iter 225 (2026-07-21) — subtraction-underflow sweep extended beyond codeview/, still clean
Extended iter 224's underflow sweep to source_map.rs (DWARF .debug_line
state machine — genuinely untrusted external binary data), memory_
layout_view.rs, memory_search.rs, watchpoint_engine.rs. All clean:
source_map.rs's opcode-opcode_base subtraction is only reached in the
branch where opcode>=opcode_base is already structurally guaranteed by
the preceding if/else chain; memory_layout_view.rs's HeapChunk::padding()
looked like a real candidate (user_addr - header_addr, live untrusted
heap memory) but its one production constructor (parse_chunk) always
sets user_addr = header_addr + header_size() — the invariant holds
unconditionally by construction, not just defensively. No fixes needed.
Windows 850/0 unaffected. **Four independent sweeps (allocation-cap x2,
subtraction-underflow x2) are now clean across the whole crate.** This
genuinely looks like the exhaustive-hardening work is done for real this
time — further micro-sweeps of the same classes are very unlikely to
find more. Remaining real next steps are unchanged: externally-blocked
items (macOS host, TTD sample, Linux PTRACE_SEIZE per iter 188) or a
new user-supplied goal.

## Iter 226 (2026-07-21) — third bug class (non-progressing loop / hang-on-malformed-data), clean
Tried a third distinct bug class from iters 219-225: a `while pos < ...`
loop that could hang forever if malformed data caused `pos` to stop
advancing (worse than a panic — a hang instead of a crash). Traced the
most bare/highest-risk loop (`cv_symbol_records.rs::decode_binary_
annotations`, `while pos < data.len()` with no fixed per-iteration size
guard) and the main TPI record loop (`codeview_type_parser.rs::
parse_stream`) and its `parse_fieldlist` sub-loop. All three provably
advance `pos` by a guaranteed-positive amount every iteration (either a
minimum fixed-size check before the loop body, or a `break` on the only
zero-advance code path) — no hang possible. **Five independent sweeps
(allocation-cap x2, subtraction-underflow x2, non-progressing-loop x1)
are now clean across the crate.** This is a strong, convergent signal
that the exhaustive low-level hardening work is genuinely done. Windows
850/0 unaffected (no code change). Remaining real next steps: externally
-blocked items (macOS host, TTD sample, Linux PTRACE_SEIZE per iter 188)
or a new user-supplied goal — recommend the next session lead with asking
the user rather than inventing a sixth micro-sweep of diminishing value.

## Iter 227 (2026-07-21) — clippy pass, no real bugs found
Tried a genuinely different verification tool: `cargo clippy -p rustre-
debug --lib`. 198 warnings total, overwhelmingly style/idiom lints
(mostly `unsafe` block usage warnings already known/accepted for FFI
code). Checked the two semantically-distinct ones by hand: "implicit
borrow as raw pointer" (windows_debugger.rs:1265, `Module32NextW(snapshot,
&mut entry)`) is correct Win32 API usage, just not using clippy's
preferred explicit `&raw mut` syntax; "contains_key followed by insert"
(windows_debugger.rs:1359, the pdata_cache from iter 205) is functionally
correct, just not using the `Entry` API. Neither is a bug. No fixes
applied — pure style suggestions, not correctness issues, out of scope
for this session's hardening focus. Confirms (via an automated tool,
independent of the 5 manual sweeps in iters 219-226) that no further
real issues are readily surfacing in rustre-debug right now.
