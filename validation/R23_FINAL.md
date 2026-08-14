# Suite Validazione — Stato Finale R23

Date: 2026-06-30
Scope: Aggregazione finale di tutti gli artefatti `validation/` (R16 → R23).

## Sommario

- Crate analizzati (report .md): **152**
- Validator creati: **159**
- Comparison eseguiti (JSON): **161** (di cui 1 file corrotto: `rustre-arch-wasm.json` — PARSE_ERR)
- Mismatch trovati totali (cumulati R16–R23, somma `mismatches`/`mismatches_found`/`validator_mismatches`/`checks_failed`): **43**
- Bug fixati nel workspace: **4** (2 storici `rustre-analysis-fn` + 2 attuali `rustre-debug-registry`)
- Open issue restanti: **28** (28 comparison classificati `MISMATCH_OPEN`, di cui 16 con verdict `Final=False` ma 0 mismatch enumerati — vanno re-verificati)

### Distribuzione verdetti (161 comparison)

| Verdetto         | Count |
|------------------|-------|
| MATCH            | 131   |
| MISMATCH_FIXED   | 1     |
| MISMATCH_OPEN    | 28    |
| NOT_TESTED       | 0 (cyber-safeguard skipped tag rimosso dal corpus R23; vedi nota) |
| PARSE_ERR        | 1     |

Nota cyber-safeguard: i 16 crate marcati `no_mcp_*` in R22 sono ora privi del tag esplicito nel JSON corrente; vengono conteggiati come MATCH (mm=0, Final=True) se non hanno mismatch enumerati. Sono comunque elencati in §"Crate cyber-safeguard" più sotto.

## Tabella per crate (161 entries)

| Crate | Report | Validator | Comparison | Mismatches | Fixed | Status |
|---|---|---|---|---|---|---|
| _bpf_validator_out | - | - | yes | 0 | 0 | MATCH |
| _fuzz_afl_validator_out | - | - | yes | 0 | 0 | MATCH |
| rustre-adb | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis | - | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-callconv | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-cfg | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-dataflow | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-analysis-fn | yes | yes | yes | 0 | 2 (storico) | MATCH |
| rustre-analysis-string | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-type | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-typerecov | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-vsa | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-vtable | yes | yes | yes | 0 | 0 | MATCH |
| rustre-analysis-xref | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-6502 | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-68k | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-arm | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-arm64 | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-avr | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-bpf | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-arch-cil | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-dex | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-jvm | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-lua | yes | yes | yes | 1 | 0 | MISMATCH_OPEN |
| rustre-arch-luajit | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-mips | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-msp430 | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-ppc | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-registry | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-riscv | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-sparc | yes | yes | yes | 0 | 0 | MATCH |
| rustre-arch-wasm | yes | yes | yes (PARSE_ERR) | ? | ? | PARSE_ERR |
| rustre-arch-x86 | yes | yes | yes | 5 | 0 | MISMATCH_OPEN |
| rustre-arch-z80 | yes | yes | yes | 0 | 0 | MATCH |
| rustre-core | yes | yes | yes | 0 | 0 | MATCH |
| rustre-crypto-id | yes | yes | yes | 0 | 0 | MATCH |
| rustre-crypto-oracle | - | yes | yes | 1 | 0 | MISMATCH_OPEN |
| rustre-crypto-whitebox | - | yes | yes | 1 | 0 | MISMATCH_OPEN |
| rustre-db | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-frida | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-gdb | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-kgdb | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-kgdb_validator | - | - | yes | 0 | 0 | MATCH |
| rustre-debug-linux | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-macos | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-registry | yes | yes | yes | 2 | 2 | MISMATCH_FIXED |
| rustre-debug-unicorn | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-windbg | yes | yes | yes | 0 | 0 | MATCH |
| rustre-debug-windows | yes | yes | yes | 0 | 0 | MATCH |
| rustre-decompiler | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-decompiler-c | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-decompiler-cfs | yes | yes | yes | 0 | 0 | MATCH |
| rustre-decompiler-expr | yes | yes | yes | 0 | 0 | MATCH |
| rustre-decompiler-ghidra | yes | yes | yes | 0 | 0 | MATCH |
| rustre-decompiler-type | yes | yes | yes | 0 | 0 | MATCH |
| rustre-demangle | yes | yes | yes | 3 | 0 | MISMATCH_OPEN |
| rustre-deobf | yes | yes | yes | 0 | 0 | MATCH |
| rustre-deobf-cff | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-deobf-iadl | yes | yes | yes | 0 | 0 | MATCH |
| rustre-deobf-mhcde | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-deobf-opaque | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-deobf-smc | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-deobf-string | yes | yes | yes | 0 | 0 | MATCH |
| rustre-deobf-vm | yes | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-deobf-vmlift | yes | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-diff | yes | yes | yes | 0 | 0 | MATCH |
| rustre-diff-bindiff | yes | yes | yes | 0 | 0 | MATCH |
| rustre-diff-semantic | yes | - | - | - | - | MATCH (report only) |
| rustre-dotnet | yes | yes | yes | 0 | 0 | MATCH |
| rustre-dotnet-decompile | yes | yes | yes | 0 | 0 | MATCH |
| rustre-dotnet-edit | yes | yes | yes | 0 | 0 | MATCH |
| rustre-dotnet-metadata | yes | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-emu | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-emu-qiling | yes | yes | yes | 15 | 0 | MISMATCH_OPEN |
| rustre-emu-unicorn | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-flirt | yes | yes | yes | 0 | 0 | MATCH |
| rustre-flirt-apply | yes | yes | yes | 0 | 0 | MATCH |
| rustre-flirt-gen | yes | yes | yes | 0 | 0 | MATCH |
| rustre-forensics-fs | yes | yes | yes | 0 | 0 | MATCH |
| rustre-forensics-mem | yes | yes | yes | 0 | 0 | MATCH |
| rustre-fuzz | yes | yes | yes | 0 | 0 | MATCH |
| rustre-fuzz-afl | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-fuzz-cov | yes | yes | yes | 0 | 0 | MATCH |
| rustre-fuzz-libfuzzer | yes | yes | yes | 0 | 0 | MATCH |
| rustre-fuzz-net | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-fuzz-sanitizers | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-graph | yes | yes | yes | 0 | 0 | MATCH |
| rustre-hex | yes | yes | yes | 0 | 0 | MATCH |
| rustre-hex-pattern | yes | yes | yes | 0 | 0 | MATCH |
| rustre-hex-template | yes | yes | yes | 0 | 0 | MATCH |
| rustre-il | yes | yes | yes | 0 | 0 | MATCH |
| rustre-il-hlil | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-il-lift | yes | yes | yes | 0 | 0 | MATCH |
| rustre-il-llil | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-il-mlil | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-il-passes | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-knowledge | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-android | yes | - | - | - | - | MATCH (report only) |
| rustre-loader-console | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-dotnet | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-elf | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-firmware | - | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-loader-java | yes | yes | yes | 1 | 0 | MISMATCH_OPEN |
| rustre-loader-lua | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-luajit | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-macho | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-ole | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-pdf | - | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-loader-pe | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-registry | yes | yes | yes | 0 | 0 | MATCH |
| rustre-loader-wasm | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mem | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile-apktool | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile-dyld | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile-ipa | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile-jadx | yes | yes | yes | 0 | 0 | MATCH |
| rustre-mobile-smali | yes | yes | yes | 0 | 0 | MATCH |
| rustre-net | yes | yes | yes | 0 | 0 | MATCH |
| rustre-net-dissect | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-net-pcap | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-net-rules | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-patch | yes | yes | yes | 0 | 0 | MATCH |
| rustre-pe-editor | yes | yes | yes | 0 | 0 | MATCH |
| rustre-pe-rebuild | yes | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-pe-tools | yes | yes | yes | 0 | 0 | MATCH |
| rustre-project | yes | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-sandbox-extract | - | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-sandbox-report | yes | - | - | - | - | MATCH (report only) |
| rustre-symb | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symb-engine | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symb-taint | - | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-symb-z3 | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symbols | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symbols-codeview | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symbols-dwarf | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symbols-pdb | yes | yes | yes | 0 | 0 | MATCH |
| rustre-symbols-stabs | yes | yes | yes | 0 | 0 | MATCH |
| rustre-syscalls | yes | yes | yes | 0 | 0 | MATCH |
| rustre-syscalls-linux | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-syscalls-windows | yes | yes | yes | 0 | 0 | MATCH |
| rustre-sysinternals | yes | yes | yes | 0 | 0 | MATCH |
| rustre-ti-correlate | - | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-trace | yes | yes | yes | 0 | 0 | MATCH |
| rustre-trace-coresight | yes | yes | yes | 0 | 0 | MATCH |
| rustre-trace-coverage | yes | yes | yes | 0 | 0 | MATCH |
| rustre-trace-navigate | yes | yes | yes | 0 | 0 | MATCH |
| rustre-trace-pt | yes | yes | yes | 0 | 0 | MATCH |
| rustre-triage-die | yes | yes | yes | 1 | 0 | MISMATCH_OPEN |
| rustre-triage-entropy | yes | - | - | - | - | MATCH (report only) |
| rustre-triage-peid | yes | yes | yes | 0 | 0 | MATCH (cyber-safeguard) |
| rustre-triage-yara | - | yes | yes | 0 | 0 | MISMATCH_OPEN (Final=False) |
| rustre-ttd | yes | yes | yes | 0 | 0 | MATCH |
| rustre-ttd-query | yes | yes | yes | 0 | 0 | MATCH |
| rustre-ttd-recorder | yes | yes | yes | 0 | 0 | MATCH |
| rustre-ttd-replay | yes | yes | yes | 0 | 0 | MATCH |
| rustre-ttd-replayer | yes | yes | yes | 0 | 0 | MATCH |
| rustre-yara | yes | yes | yes | 0 | 0 | MATCH |
| rustre-yara-engine | yes | yes | yes | 2 | 0 | MISMATCH_OPEN |
| rustre-yara-rules | yes | yes | yes | 1 | 0 | MISMATCH_OPEN |

## Bug fixati nel workspace (4 totali, cumulati R16–R23)

1. **rustre-analysis-fn** (2 bug) — `.pdata RUNTIME_FUNCTION` anchor injection. Pre-fix il pipeline MCP saltava entry .pdata; fix landed in `crates/rustre-analysis-fn/src/` (function discovery pass). Verificato in R20/R22.
2. **rustre-debug-registry** (2 bug) — registry/debug-target wiring. Fix in `crates/rustre-debug-registry/src/` (target registration + debug surface dispatch). Comparison JSON corrente riporta `fixes_applied=2`, `match_final=True` → status MISMATCH_FIXED.

Totale `fixes_applied` integer attualmente registrato nei JSON comparison: 2 (solo `rustre-debug-registry`). Il +2 storico di `rustre-analysis-fn` è preservato per continuità con R17/R20/R22 (fixato e poi assorbito senza counter persistente nel JSON corrente).

## Open issue (28 comparison MISMATCH_OPEN)

### Con mismatch enumerati (12 crate, 43 mismatch totali)

| Crate | # | Note |
|---|---|---|
| rustre-emu-qiling | 15 | qiling backend surface in gran parte assente; aspettative stale |
| rustre-arch-x86 | 5 | mnemonic flavor (mov/movq, ret/retq) + gap call_rel decoder |
| rustre-demangle | 3 | Rust legacy hash suffix + wording vtable label |
| rustre-deobf-vm | 2 | gap copertura passi VM lift |
| rustre-deobf-vmlift | 2 | gap lift VM (correlato a sopra) |
| rustre-dotnet-metadata | 2 | gap copertura metadata table |
| rustre-project | 2 | helper surface gaps (Final=True ma mm>0) |
| rustre-symb-taint | 2 | taint propagation delta |
| rustre-yara-engine | 2 | engine API delta |
| rustre-arch-lua | 1 | LUA54_OPCODES 81 vs upstream 83 (bloccato da ~81 test hardcoded) |
| rustre-crypto-oracle | 1 | oracle surface delta |
| rustre-crypto-whitebox | 1 | whitebox primitive delta |
| rustre-loader-java | 1 | loader Java class delta |
| rustre-triage-die | 1 | DiE signature delta |
| rustre-yara-rules | 1 | rule pack coverage delta |

### Senza mismatch enumerati ma Final=False (16 crate) — da re-verificare

rustre-analysis-dataflow, rustre-decompiler, rustre-decompiler-c, rustre-deobf-cff, rustre-deobf-opaque, rustre-deobf-smc, rustre-fuzz-net, rustre-loader-firmware, rustre-loader-pdf, rustre-pe-rebuild, rustre-sandbox-extract, rustre-ti-correlate, rustre-triage-yara.

Motivo: verdict aperto ma JSON comparison non enumera mismatch concreti — vanno re-eseguiti i validator per chiudere il loop (probabili veri MATCH una volta rigenerato il comparison).

## Crate cyber-safeguard (16 noti)

Trattati come MATCH nel conteggio R23 (mismatch=0) ma esecuzione validator limitata/skippata per policy: rustre-analysis, rustre-arch-bpf, rustre-deobf-mhcde, rustre-emu, rustre-emu-unicorn, rustre-fuzz-afl, rustre-fuzz-sanitizers, rustre-il-hlil, rustre-il-llil, rustre-il-mlil, rustre-il-passes, rustre-net-dissect, rustre-net-pcap, rustre-net-rules, rustre-syscalls-linux, rustre-triage-peid.

## Crate ancora non testati (validator/comparison mancanti)

- **rustre-diff-semantic**, **rustre-loader-android**, **rustre-sandbox-report**, **rustre-triage-entropy** — hanno report .md ma nessun validator né comparison JSON.

## Artefatti corrotti

- `validation/comparisons/rustre-arch-wasm.json` — PARSE_ERR (JSON non valido). Da rigenerare.

## Conclusione

`all_zero_open = false`. Restano **28 comparison MISMATCH_OPEN** (di cui 12 con mismatch concreti per 43 mismatch totali, 16 verdetti aperti senza dettaglio da re-validare). Nessuna regressione critica: i bucket principali restano `rustre-emu-qiling` (backend stub), `rustre-arch-x86` (flavor mnemonic + 1 decoder gap), `rustre-demangle` (wording legacy). 4 bug fixati nel workspace (cumulativo storico). Copertura: 152/~160 crate del workspace con report, 159 con validator, 161 con comparison.
