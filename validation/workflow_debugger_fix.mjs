export const meta = {
  name: 'debugger-fix-batch',
  description: 'Fix 4 concrete debugger gaps: Windows CFI backtrace (0/1 frame), debug_evaluate schema mismatch, debug_launch path param ignored, symbol_resolver PDB load wire',
  phases: [
    { title: 'Diagnose', detail: 'Locate exact files/lines for each of the 4 bugs' },
    { title: 'FixWindowsCFI', detail: 'Port DWARF-CFI pipeline to Windows .pdata + PE unwind info parsing' },
    { title: 'FixEvaluateSchema', detail: 'Align debug_evaluate wrapper schema field name (expression vs expr)' },
    { title: 'FixLaunchPath', detail: 'Repair debug_launch path parameter handling — currently only binary_id works' },
    { title: 'WireSymbolResolver', detail: 'Wire debug_load_symbols → debug_resolve_symbol end-to-end so backtrace symbolicates on live sessions' },
    { title: 'Verify', detail: 'cargo test rustre-debug on Windows + Linux WSL + live MCP probe' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('Diagnose')
const diag = await agent(
  `Diagnose 4 concrete debugger bugs. For each, find exact file:line.

BUG 1: Windows CFI backtrace returns 1 frame only.
Linux test backtrace_unwinds_past_the_first_frame_via_dwarf_cfi passes. Windows via MCP live returned only frame 0. Find where WindowsDebugger::backtrace unwinds — search ${CWD}/crates/rustre-debug/src/windows_debugger.rs. Is DWARF CFI reader called? Or is there frame-pointer-only fallback?

BUG 2: debug_evaluate schema/handler mismatch.
Wrapper schema declares field "expression" (or "expr"?), handler internally requires the other. Find in ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs the debug.evaluate registration. Report schema field name vs handler req_str/req_str_arg call.

BUG 3: debug_launch path parameter ignored.
Live test: passing binary_id="C:/.../notepad.exe" launches live, but path="C:/.../notepad.exe" with binary_id="bin-0001" returns mock. Look at debug.launch handler in tools/debug.rs — around line 549. Is args.get("path") reaching normalize_exe_path? Any middleware stripping the path field?

BUG 4: symbol_resolver PDB load end-to-end.
debug_load_symbols is exposed. Verify the chain: load_symbols persists into session, resolve_symbol reads back, backtrace's symbolicate_frame consumes the resolver. Grep for symbolicate_frame in windows_debugger.rs.

Return {bug1:{file,line,current_behavior,fix_recipe}, bug2:{...}, bug3:{...}, bug4:{...}, notes:string}`,
  { label: 'diagnose', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      bug1:{type:'object'}, bug2:{type:'object'}, bug3:{type:'object'}, bug4:{type:'object'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('FixWindowsCFI')
const cfi = await agent(
  `Fix Windows CFI backtrace to unwind past frame 0.

Diagnosis: ${JSON.stringify(diag.bug1)}

Windows uses PE .pdata section for unwind info (RUNTIME_FUNCTION entries + UNWIND_INFO). On Linux DWARF .debug_frame is used and Linux backtrace works.

STEPS:
1. Read ${CWD}/crates/rustre-debug/src/windows_debugger.rs backtrace().
2. If it's frame-pointer only, add a PE unwind path:
   - For each frame, read PE headers of the current module, find .pdata section, look up RUNTIME_FUNCTION for the current RIP.
   - Decode UNWIND_INFO (UnwindOpCodes: UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE/SMALL, UWOP_SAVE_NONVOL, UWOP_SET_FPREG).
   - Compute the caller's RSP + return-address address, read u64 there → RIP of next frame.
   - Adjust RSP accordingly.
3. Add cfg(windows) test analogous to backtrace_unwinds_past_the_first_frame_via_dwarf_cfi: launch a small helper program, single-step a few times deep into a call, backtrace, assert frames >= 2.
4. cd ${CWD} && cargo build --release -p rustre-debug 2>&1 | tail -20. Iterate.
5. On success: cargo test --release -p rustre-debug windows_debugger::live_tests::backtrace 2>&1 | tail -10.

Return {method_used:string, pdata_parsed:bool, test_added:bool, test_passes:bool, build_ok:bool, notes:string}`,
  { label: 'cfi', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      method_used:{type:'string'},
      pdata_parsed:{type:'boolean'},
      test_added:{type:'boolean'},
      test_passes:{type:'boolean'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FixEvaluateSchema')
const eval_ = await agent(
  `Fix debug_evaluate schema/handler mismatch.

Diagnosis: ${JSON.stringify(diag.bug2)}

STEPS:
1. Read the debug.evaluate registration in ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs. Both schema and handler must use the SAME field name.
2. Standard: use "expression" (more descriptive). Update handler to req_str("expression") if it currently uses "expr", OR change schema to "expr".
3. Add test: call debug_evaluate with the correct field name and verify it returns a value.
4. cd ${CWD} && cargo build --release -p rustre-mcp-tools 2>&1 | tail -10.

Return {field_name_used:string, files_edited:[string], build_ok:bool}`,
  { label: 'eval', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      field_name_used:{type:'string'},
      files_edited:{type:'array', items:{type:'string'}},
      build_ok:{type:'boolean'},
    },
    required:['build_ok']
  }}
)

phase('FixLaunchPath')
const launch = await agent(
  `Fix debug_launch when passed 'path' parameter.

Diagnosis: ${JSON.stringify(diag.bug3)}

Repro: debug_launch{binary_id: "bin-0001", path: "C:/Windows/System32/notepad.exe"} returns mock. debug_launch{binary_id: "C:/Windows/System32/notepad.exe"} returns live.

Root cause candidate: args.get("path") returning None even when path was passed. Could be JSON schema additionalProperties: false stripping unknown fields, or a validator layer.

STEPS:
1. Read debug.launch schema (should list "path" in properties, additionalProperties:false but "path" IS in the list).
2. Read handler args extraction. args.get("path").and_then(as_str).and_then(normalize_exe_path).
3. Add eprintln! debug: eprintln!("[LAUNCH] args = {}", args); at handler entry. Rebuild+test manually with path param.
4. Fix root cause. If it's a serde deser issue, ensure path is deserialized as String not Option or filtered.
5. Add regression test: call debug.launch with {binary_id, path} where binary_id is bogus but path is real; assert response has live:true.
6. cd ${CWD} && cargo build --release -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15.

Return {root_cause:string, fix_applied:string, test_added:bool, build_ok:bool}`,
  { label: 'launch', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      root_cause:{type:'string'},
      fix_applied:{type:'string'},
      test_added:{type:'boolean'},
      build_ok:{type:'boolean'},
    },
    required:['root_cause','build_ok']
  }}
)

phase('WireSymbolResolver')
const sym = await agent(
  `Wire symbol resolver end-to-end so debug_backtrace symbolicates real function names.

Diagnosis: ${JSON.stringify(diag.bug4)}

STEPS:
1. Read ${CWD}/crates/rustre-debug/src/windows_debugger.rs backtrace + symbolicate_frame if exists.
2. debug_load_symbols must persist a CodeView SymbolResolver into the session (LiveSession struct in mcp-tools/src/tools/debug.rs).
3. debug_backtrace should look up name/module/offset for each frame's addr via the resolver.
4. Test: launch notepad, load_symbols with notepad.pdb bytes (or synthesize a minimal test PDB), backtrace, assert at least frame 0 has non-null name.
5. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15.

Return {resolver_persisted_in_session:bool, backtrace_looks_up_names:bool, test_added:bool, build_ok:bool}`,
  { label: 'sym', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      resolver_persisted_in_session:{type:'boolean'},
      backtrace_looks_up_names:{type:'boolean'},
      test_added:{type:'boolean'},
      build_ok:{type:'boolean'},
    },
    required:['build_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Full verification of 4 fixes.

STEPS:
1. taskkill //F //IM rustre-mcp.exe (ignore not-found). sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. cargo test --release -p rustre-debug --lib 2>&1 | tail -5. Report passed/failed.
4. WSL Ubuntu Linux: wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/Fra/Desktop/RustRE && /home/marax/.cargo/bin/cargo test --release -p rustre-debug --lib 2>&1 | tail -3". Report Linux passed/failed.
5. MCP live probe: spawn rustre-mcp.exe stdio via Python. Test:
   - debug.launch{binary_id, path} → should return live:true (bug3 fix)
   - debug.evaluate{session_id, expression:"$rip"} → should return real value (bug2 fix)
   - debug.backtrace → should return >= 2 frames on notepad.exe stepped a few times (bug1 fix)
   - debug.load_symbols → debug.backtrace should have named frames (bug4 fix)
6. Report {windows_lib_tests:{passed,failed}, linux_lib_tests:{passed,failed}, mcp_live_results:{bug1_frames_count,bug2_evaluated_value,bug3_launch_via_path_live,bug4_frame0_name}, verdict:string, remaining_issues:[string]}`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      windows_lib_tests:{type:'object'},
      linux_lib_tests:{type:'object'},
      mcp_live_results:{type:'object'},
      verdict:{type:'string'},
      remaining_issues:{type:'array', items:{type:'string'}},
    },
    required:['verdict']
  }}
)

return { status:'debugger-fix-complete', diag, cfi, eval:eval_, launch, sym, verify }
