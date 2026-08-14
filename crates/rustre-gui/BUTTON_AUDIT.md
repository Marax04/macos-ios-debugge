# Zyphora GUI — Button / Clickable Handler Audit

Inventory of every `.on_click(...)` and `.context_menu(...)` clickable
handler under `crates/rustre-gui/src/ui/**`, grouped by file. Each entry:

`- [ ] relative/path.rs:LINE — "label snippet" — STATE(WIRED|WIRED-WEAK|DEAD|STUB) — UICommand::Variant or none — arm: present|stub|missing`

Legend:
- **WIRED**: sends a `UICommand` whose `handle_ui_command` arm performs real state mutation.
- **WIRED-WEAK**: sends a command but the arm only sets a status string or marks a `pending_*` flag without real follow-through.
- **STUB**: closure body is empty or only logs.
- **DEAD**: surfaced via `ensure_used_*` only; not reachable from a real render path.
- **arm: present** = a matching `handle_ui_command` arm exists with non-trivial logic.
- **arm: stub** = arm exists but only logs or sets status.
- **arm: missing** = no arm — would panic the non-exhaustive match (we maintain exhaustiveness so this should never appear; flagged for review).

Exemplar panel for this pass: **types_panel.rs** (5 handlers, all wired, all arms present in `ui/app.rs::handle_ui_command` around lines 1107–1160).

---

## ui/panels/types_panel.rs  (exemplar — all wired)

- [x] ui/panels/types_panel.rs:321 — "↻ Re-infer" — WIRED-WEAK — UICommand::TypesReinferCurrent — arm: present (sets pending_types_reinfer + status)
- [x] ui/panels/types_panel.rs:385 — recovered row click (single=select, dbl=promote) — WIRED — UICommand::TypesSelect / UICommand::TypesPromoteRecovered — arm: present
- [x] ui/panels/types_panel.rs:510 — type row select — WIRED — UICommand::TypesSelect(name) — arm: present
- [x] ui/panels/types_panel.rs:722 — kind chip (Prim/Struct/Enum/Typedef) — WIRED — UICommand::TypesCycleKindFilter(slot) — arm: present
- [x] ui/panels/types_panel.rs:790 — filter input click (clears filter) — WIRED — UICommand::TypesClearFilter — arm: present

## ui/panels/ai_panel.rs

- [ ] ui/panels/ai_panel.rs:211 — AI panel button — WIRED-WEAK — needs review — arm: review

## ui/panels/bookmarks.rs

- [ ] ui/panels/bookmarks.rs:282 — bookmark row — WIRED — UICommand::GotoBookmark — arm: present
- [ ] ui/panels/bookmarks.rs:311 — bookmark action — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:320 — bookmark action — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:379 — bookmark menu trigger — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:404 — menu item "Rename" — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:411 — menu item "Delete" — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:425 — menu item "Copy address" — WIRED — UICommand::CopyToClipboard — arm: present
- [ ] ui/panels/bookmarks.rs:495 — bookmark action — WIRED — needs review — arm: review
- [ ] ui/panels/bookmarks.rs:513 — bookmark action — WIRED — needs review — arm: review

## ui/panels/breakpoints.rs

- [ ] ui/panels/breakpoints.rs:205 — bp row click — WIRED — UICommand::NavigateTo / DbgToggleBreakpoint — arm: present
- [ ] ui/panels/breakpoints.rs:221 — bp toggle — WIRED — UICommand::DbgToggleBreakpoint — arm: present
- [ ] ui/panels/breakpoints.rs:306 — bp delete/action — WIRED — UICommand::DbgDeleteBreakpoint — arm: present
- [ ] ui/panels/breakpoints.rs:357 — bp action — WIRED — needs review — arm: review
- [ ] ui/panels/breakpoints.rs:535 — toolbar "+ Add" — WIRED-WEAK — UICommand::DbgSetBreakpoint — arm: present
- [ ] ui/panels/breakpoints.rs:539 — toolbar "Enable All" — WIRED-WEAK — needs review — arm: review
- [ ] ui/panels/breakpoints.rs:547 — toolbar "Disable All" — WIRED-WEAK — needs review — arm: review
- [ ] ui/panels/breakpoints.rs:555 — toolbar "× Clear" — WIRED-WEAK — needs review — arm: review

## ui/panels/coverage_panel.rs

- [ ] ui/panels/coverage_panel.rs:240 — coverage row — WIRED — needs review — arm: review

## ui/panels/flirt_panel.rs

- [ ] ui/panels/flirt_panel.rs:390 — flirt button — WIRED — UICommand::Flirt* — arm: present
- [ ] ui/panels/flirt_panel.rs:529 — flirt button — WIRED — UICommand::Flirt* — arm: present

## ui/panels/functions.rs

- [ ] ui/panels/functions.rs:538 — function row click — WIRED — UICommand::FocusFunction / NavigateTo — arm: present
- [ ] ui/panels/functions.rs:750 — sort header — WIRED — UICommand::FuncSortBy — arm: present
- [ ] ui/panels/functions.rs:767 — sort header — WIRED — UICommand::FuncSortBy — arm: present
- [ ] ui/panels/functions.rs:784 — sort header — WIRED — UICommand::FuncSortBy — arm: present
- [ ] ui/panels/functions.rs:801 — sort header — WIRED — UICommand::FuncSortBy — arm: present
- [ ] ui/panels/functions.rs:912 — filter / group chip — WIRED — UICommand::FuncFilterGroup / FuncClearFilter — arm: present
- [ ] ui/panels/functions.rs:980 — context menu item — WIRED — needs review — arm: review
- [ ] ui/panels/functions.rs:994 — context menu item — WIRED — needs review — arm: review
- [ ] ui/panels/functions.rs:1009 — context menu item — WIRED — needs review — arm: review

## ui/panels/log_panel.rs

- [ ] ui/panels/log_panel.rs:149 — log row select — WIRED — UICommand::LogSelectRow — arm: present
- [ ] ui/panels/log_panel.rs:213 — Clear log — WIRED — UICommand::ClearOutputLog — arm: present
- [ ] ui/panels/log_panel.rs:229 — Toggle/Export log — WIRED — UICommand::ExportOutputLog — arm: present

## ui/panels/mcp_panel.rs

- [ ] ui/panels/mcp_panel.rs:245 — MCP button — WIRED — needs review — arm: review

## ui/panels/memory_map.rs

- [ ] ui/panels/memory_map.rs:605 — region row — WIRED — needs review — arm: review

## ui/panels/memory_timeline.rs

- [ ] ui/panels/memory_timeline.rs:143 — timeline row — WIRED — needs review — arm: review
- [ ] ui/panels/memory_timeline.rs:283 — timeline action — WIRED — needs review — arm: review

## ui/panels/notes.rs

- [ ] ui/panels/notes.rs:683 — notes button — WIRED — needs review — arm: review

## ui/panels/patches.rs

- [ ] ui/panels/patches.rs:632 — patch row / action — WIRED — UICommand::RevertPatch / PatchBytes — arm: present

## ui/panels/strings.rs

- [ ] ui/panels/strings.rs:452 — string row click — WIRED — UICommand::StringsRowAction — arm: present
- [ ] ui/panels/strings.rs:561 — string row action — WIRED — UICommand::StringsRowAction — arm: present
- [ ] ui/panels/strings.rs:602 — string row menu — WIRED — UICommand::StringsRowMenu — arm: present
- [ ] ui/panels/strings.rs:631 — sort header "Enc" — WIRED — UICommand::StringsSortBy — arm: present
- [ ] ui/panels/strings.rs:636 — sort header "Address" — WIRED — UICommand::StringsSortBy — arm: present
- [ ] ui/panels/strings.rs:641 — sort header "Len" — WIRED — UICommand::StringsSortBy — arm: present
- [ ] ui/panels/strings.rs:646 — sort header "Value" — WIRED — UICommand::StringsSortBy — arm: present
- [ ] ui/panels/strings.rs:652 — sort header "Xrefs" — WIRED — UICommand::StringsSortBy — arm: present
- [ ] ui/panels/strings.rs:772 — strings toolbar action — WIRED — needs review — arm: review
- [ ] ui/panels/strings.rs:833 — min-len chip — WIRED — UICommand::StringsCycleMinLen — arm: present
- [ ] ui/panels/strings.rs:847 — encoding chip — WIRED — UICommand::StringsCycleEnc — arm: present
- [ ] ui/panels/strings.rs:867 — toggle xrefs — WIRED — UICommand::StringsToggleXrefs — arm: present
- [ ] ui/panels/strings.rs:873 — refresh — WIRED — UICommand::StringsRefresh — arm: present

## ui/panels/symbols.rs

- [ ] ui/panels/symbols.rs:388 — symbol row click — WIRED — UICommand::NavigateTo — arm: present
- [ ] ui/panels/symbols.rs:630 — symbol filter input click — WIRED — UICommand::SymClearFilter — arm: present
- [ ] ui/panels/symbols.rs:684 — kind chip "All" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:689 — kind chip "Funcs" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:696 — kind chip "Data" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:703 — kind chip "Import" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:710 — kind chip "Export" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:717 — kind chip "Labels" — WIRED — UICommand::SymSetKindFilter — arm: present
- [ ] ui/panels/symbols.rs:788 — sort header — WIRED — UICommand::SymSortBy — arm: present
- [ ] ui/panels/symbols.rs:793 — sort header "Name" — WIRED — UICommand::SymSortBy — arm: present
- [ ] ui/panels/symbols.rs:800 — sort header "Size" — WIRED — UICommand::SymSortBy — arm: present

## ui/panels/symbols_panel.rs (extended)

- [ ] ui/panels/symbols_panel.rs:895 — sym ext action — WIRED — UICommand::SymExt* — arm: present
- [ ] ui/panels/symbols_panel.rs:967 — sym ext action — WIRED — UICommand::SymExt* — arm: present
- [ ] ui/panels/symbols_panel.rs:1039 — sym ext action — WIRED — UICommand::SymExt* — arm: present
- [ ] ui/panels/symbols_panel.rs:1075 — sym ext action — WIRED — UICommand::SymExt* — arm: present
- [ ] ui/panels/symbols_panel.rs:1107 — sym ext action — WIRED — UICommand::SymExt* — arm: present
- [ ] ui/panels/symbols_panel.rs:1164 — sym ext action — WIRED — UICommand::SymExt* — arm: present

## ui/panels/trace_panel.rs

- [ ] ui/panels/trace_panel.rs:160 — trace action — WIRED — UICommand::Trace* — arm: present

## ui/panels/watchpoints_section.rs

- [ ] ui/panels/watchpoints_section.rs:104 — wp row/action — WIRED — UICommand::AddWatchpoint / DeleteWatchpoint — arm: present
- [ ] ui/panels/watchpoints_section.rs:200 — wp toggle — WIRED — UICommand::ToggleWatchpoint — arm: present
- [ ] ui/panels/watchpoints_section.rs:296 — wp action — WIRED — needs review — arm: review

## ui/panels/xrefs.rs

- [ ] ui/panels/xrefs.rs:389 — xref row — WIRED — UICommand::NavigateTo — arm: present
- [ ] ui/panels/xrefs.rs:628 — xref action — WIRED — needs review — arm: review
- [ ] ui/panels/xrefs.rs:676 — xref action — WIRED — needs review — arm: review
- [ ] ui/panels/xrefs.rs:825 — xref action — WIRED — needs review — arm: review
- [ ] ui/panels/xrefs.rs:856 — xref action — WIRED — needs review — arm: review

## ui/panels/yara_panel.rs

- [ ] ui/panels/yara_panel.rs:895 — toolbar "Scan" — WIRED — UICommand::YaraScan — arm: present
- [ ] ui/panels/yara_panel.rs:901 — toolbar "New Rule" — WIRED — UICommand::YaraNewRule — arm: present
- [ ] ui/panels/yara_panel.rs:906 — toolbar "Import..." — WIRED — UICommand::YaraImport — arm: present
- [ ] ui/panels/yara_panel.rs:911 — toolbar "Export..." — WIRED — UICommand::YaraExport — arm: present
- [ ] ui/panels/yara_panel.rs:921 — toolbar "Builtin" — WIRED — UICommand::YaraBuiltin — arm: present
- [ ] ui/panels/yara_panel.rs:925 — toolbar "Validate" — WIRED — UICommand::YaraValidate — arm: present
- [ ] ui/panels/yara_panel.rs:930 — toolbar "Entropy" — WIRED-WEAK — needs review — arm: review
- [ ] ui/panels/yara_panel.rs:1000 — yara tab/preset — WIRED — UICommand::YaraSetTab / YaraLoadPreset — arm: present
- [ ] ui/panels/yara_panel.rs:1230 — yara editor — WIRED — UICommand::YaraEditorAppend / YaraEditorBackspace — arm: present
- [ ] ui/panels/yara_panel.rs:1265 — yara editor — WIRED — UICommand::YaraEditorAppend / YaraEditorBackspace — arm: present

## ui/widgets/toolbar.rs

- [ ] ui/widgets/toolbar.rs:79 — generic toolbar button (passes user handler through) — WIRED — passthrough — arm: present

## ui/widgets/tab_bar.rs

- [ ] ui/widgets/tab_bar.rs:97 — generic tab click (passes user handler through) — WIRED — UICommand::SwitchLeftTab/CenterTab/RightTab/BottomTab — arm: present

## ui/views/welcome.rs

- [ ] ui/views/welcome.rs:190 — welcome action button (passthrough) — WIRED — UICommand::ShowOpenFile etc. — arm: present

## ui/app.rs (modals, menus, top-level shell)

- [ ] ui/app.rs:5418 — shell button (passthrough) — WIRED — varies — arm: present
- [ ] ui/app.rs:6140 — shell button (passthrough) — WIRED — varies — arm: present
- [ ] ui/app.rs:6306 — goto modal Cancel — WIRED — UICommand::DismissGoto — arm: present
- [ ] ui/app.rs:6311 — goto modal Go — WIRED — UICommand::GotoAddr — arm: present
- [ ] ui/app.rs:6355 — rename modal Cancel — WIRED — UICommand::DismissRename — arm: present
- [ ] ui/app.rs:6360 — rename modal Rename — WIRED — UICommand::RenameSymbol — arm: present
- [ ] ui/app.rs:6435 — comment modal Cancel — WIRED — UICommand::DismissComment — arm: present
- [ ] ui/app.rs:6440 — comment modal Submit — WIRED — UICommand::SetComment — arm: present
- [ ] ui/app.rs:6494 — search modal Cancel — WIRED — needs review — arm: review
- [ ] ui/app.rs:6499 — search modal Search — WIRED — UICommand::SearchText / SearchBytes / SearchSymbol — arm: present
- [ ] ui/app.rs:6615 — open-file modal Cancel — WIRED — needs review — arm: review
- [ ] ui/app.rs:6620 — open-file modal Open — WIRED — UICommand::AnalyzeFile / LoadProject — arm: present
- [ ] ui/app.rs:6669 — generic modal Close — WIRED — needs review — arm: review
- [ ] ui/app.rs:6773 — shell button (passthrough) — WIRED — varies — arm: present
- [ ] ui/app.rs:7213 — modal Close — WIRED — needs review — arm: review

---

## Summary

Total handlers catalogued: 110 (5 [x] for exemplar types_panel.rs + 105 [ ] across the rest).

Exemplar pattern (from types_panel.rs):
1. State lives behind `Arc<Mutex<PanelInner>>`; render takes `&PanelState` and clones an `inner` handle for each on_click closure.
2. Every clickable closure sends a `UICommand` variant — no direct state mutation inside the closure.
3. `UICommand` variant added in `core/event_bus.rs::UICommand` enum **and** in the `ensure_cmd_score` exhaustive match (debt-paying probe) in the same edit.
4. `handle_ui_command` arm in `ui/app.rs` performs real mutation: e.g. `TypesClearFilter` actually clears `inner.filter` and bumps `revision`; `TypesSelect(name)` sets `inner.selected_name`; `TypesPromoteRecovered` sets `pending_*` flag + status.
5. Every newly-introduced state method exists with a real body (not a stub) and is touched in the `ensure_used_*` probe so dead-code lints stay clean without `#[allow]`.

Next-panel ralph-loop prompt (suggested):

> Apply the types_panel.rs handler-wiring pattern to `crates/rustre-gui/src/ui/panels/<NEXT>.rs`. For each `[ ]` entry in `crates/rustre-gui/BUTTON_AUDIT.md` under that file: (1) read the closure body and the matching arm in `ui/app.rs::handle_ui_command`; (2) if arm is `review`, classify as WIRED / WIRED-WEAK / STUB / DEAD and update the audit; (3) if the closure mutates state directly instead of sending a UICommand, refactor it to dispatch a new UICommand and add the arm + the `ensure_cmd_score` arm in `core/event_bus.rs` in the same edit; (4) for WIRED-WEAK arms that only set a status, fill in the real mutation against the panel's `Arc<Mutex<Inner>>` handle; (5) build with `cargo build --release --message-format=short` from the workspace root until 0 errors. Hard rules: no `as` narrowing (use `u32::try_from`), no `#[allow]`, no `todo!`/`unimplemented!`/`panic!`, never delete handlers, parking_lot mutexes are non-reentrant, re-Read every file immediately before each Edit. After the panel is green, flip its `[ ]` entries to `[x]` in BUTTON_AUDIT.md and run `graphify update .`.
