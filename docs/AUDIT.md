# RustRE — AUDIT AGGIORNATO
> Generato: 2026-06-05 | Totale: **1,397,501 righe** su 190 crate | Target: **4,000,000 righe**
> Gap residuo: ~2,602,499 righe | GUI (rustre-gui, docking, views, themes): esclusa dallo sviluppo

---

## Legenda

| Icona | Significato |
|-------|-------------|
| ✅✅ | TOP — 10K+ righe, multi-file, contenuto denso |
| ✅ | BUONO — 7K-10K righe, ben sviluppato |
| 🟡 | MEDIO — 5K-7K righe, necessita espansione |
| 🔴 | INDIETRO — <5K righe (solo GUI, non toccabile) |
| ⚠️ | MONOLITICO — buone righe ma 1 solo file, va decomposto in moduli |

---

## TIER ✅✅ TOP (10K+ righe) — 14 crate

| Crate | Righe | File | Note |
|-------|-------|------|------|
| rustre-il-lift | 58,013 | 45 | ✅✅ Eccellente — lifter multi-arch |
| rustre-core | 15,068 | 18 | ✅✅ Base solida |
| rustre-mem | 13,142 | 27 | ✅✅ MemoryProvider completo |
| rustre-forensics-mem | 10,950 | 10 | ✅✅ Volatility-style |
| rustre-loader-pe | 11,022 | 16 | ✅✅ PE/PE+ loader |
| rustre-loader-elf | 10,678 | 15 | ✅✅ ELF loader |
| rustre-forensics-plugins | 10,538 | 13 | ✅✅ 10+ plugin |
| rustre-dotnet-decompile | 10,619 | 4 | ✅✅ CIL→C# |
| rustre-il-passes | 10,230 | 5 | ✅✅ IR trasformazioni |
| rustre-graph | 10,208 | 5 | ✅✅ Knowledge graph |
| rustre-analysis-type | 10,917 | 12 | ✅✅ Type recovery |
| rustre-deobf-vm | 10,020 | 9 | ✅✅ VM deobf |
| rustre-mobile-jadx | 10,130 | 8 | ✅✅ DEX→Java |
| rustre-analysis-dataflow | 9,091 | 11 | ✅✅ (borderline) |

---

## TIER ✅ BUONO (7K-9.9K righe) — 36 crate

| Crate | Righe | File | Priorità espansione |
|-------|-------|------|---------------------|
| rustre-net-proxy | 9,472 | **1** ⚠️ | DECOMP in moduli |
| rustre-net-dissect | 9,284 | **1** ⚠️ | DECOMP in moduli |
| rustre-analysis-vsa | 9,770 | 7 | OK, aggiungere |
| rustre-mobile-ios | 9,770 | 12 | OK |
| rustre-il-llil | 9,558 | 4 | OK |
| rustre-il-mlil | 9,181 | 5 | OK |
| rustre-arch-arm | 9,192 | 5 | OK |
| rustre-decompiler-cfs | 8,736 | 4 | OK |
| rustre-arch-x86 | 8,834 | 10 | OK |
| rustre-il-hlil | 8,235 | 4 | OK |
| rustre-analysis-cfg | 8,330 | 11 | OK |
| rustre-arch-6502 | 8,347 | 8 | OK |
| rustre-forensics | 7,418 | 7 | OK |
| rustre-forensics-fs | 7,608 | 9 | OK |
| rustre-fuzz-afl | 7,640 | 5 | OK |
| rustre-triage | 7,819 | 7 | OK |
| rustre-threatintel | 7,831 | 17 | OK |
| rustre-il-lift (dup) | — | — | già sopra |
| rustre-arch-jvm | 7,669 | 5 | OK |
| rustre-loader-macho | 7,631 | 4 | OK |
| rustre-adb | 7,506 | 8 | OK |
| rustre-loader-firmware | 7,689 | 8 | OK |
| rustre-agent | 7,619 | 7 | OK |
| rustre-arch-msp430 | 7,527 | 8 | OK |
| rustre-deobf-vmlift | 7,386 | 10 | OK |
| rustre-arch-mips | 7,352 | 3 | Pochi file — aggiungere |
| rustre-arch-bpf | 7,283 | 3 | Pochi file |
| rustre-hex-template | 7,273 | 4 | OK |
| rustre-arch-luajit | 7,270 | 5 | OK |
| rustre-arch-riscv | 7,266 | **2** ⚠️ | Quasi monolitico |
| rustre-hex | 7,272 | 3 | Pochi file |
| rustre-hex-pattern | 7,184 | 3 | Pochi file |
| rustre-analysis-string | 7,042 | 9 | OK |
| rustre-dotnet-metadata | 7,047 | 3 | Pochi file |
| rustre-dotnet | 6,923 | 5 | OK |
| rustre-mcp | 7,203 | 7 | OK |
| rustre-mcp-server | 7,291 | 3 | Pochi file |
| rustre-analysis | 7,439 | 6 | OK |
| rustre-debug | 7,965 | 5 | OK |

---

## TIER 🟡 MEDIO (5K-7K righe) — 133 crate non-GUI

Questi crate hanno il minimo ma vanno espansi significativamente verso 8K-15K:

### Sotto-categoria 🟡A (6K-7K) — espansione media necessaria

| Crate | Righe | File | Gap a 10K |
|-------|-------|------|-----------|
| rustre-deobf | 7,175 | 8 | +2,825 |
| rustre-script | 8,276 | 8 | +1,724 |
| rustre-analysis-xref | 6,767 | 7 | +3,233 |
| rustre-analysis-vtable | 6,645 | 9 | +3,355 |
| rustre-diff-semantic | 6,650 | 8 | +3,350 |
| rustre-diff-bindiff | 6,636 | 4 | +3,364 |
| rustre-debug-linux | 6,945 | 5 | +3,055 |
| rustre-debug-kgdb | 6,895 | 5 | +3,105 |
| rustre-debug-macos | 6,868 | 6 | +3,132 |
| rustre-fuzz-sanitizers | 6,968 | 5 | +3,032 |
| rustre-emu | 6,945 | 8 | +3,055 |
| rustre-loader-android | 6,927 | 8 | +3,073 |
| rustre-mobile-smali | 6,956 | 7 | +3,044 |
| rustre-events | 6,803 | 4 | +3,197 |
| rustre-crypto-oracle | 6,611 | 7 | +3,389 |
| rustre-debug-frida | 6,693 | 3 | +3,307 |
| rustre-crypto-id | 6,813 | 6 | +3,187 |
| rustre-agent-prompts | 6,499 | 5 | +3,501 |
| rustre-script-rhai | 6,596 | 6 | +3,404 |
| rustre-script-python | 6,570 | 5 | +3,430 |
| rustre-script-lua | 6,701 | 5 | +3,299 |
| rustre-arch-arm64 | 7,594 | 3 | +2,406 |
| rustre-debug-windows | 6,410 | 2 | +3,590 |
| rustre-dotnet-edit | 6,834 | 4 | +3,166 |
| rustre-deobf-cff | 6,425 | 4 | +3,575 |
| rustre-cli | 6,518 | 6 | +3,482 |
| rustre-decompiler-ghidra | 5,967 | 6 | +4,033 |
| rustre-flirt | 6,179 | 5 | +3,821 |
| rustre-flirt-apply | 6,122 | 9 | +3,878 |
| rustre-flirt-gen | 6,034 | 9 | +3,966 |
| rustre-triage-die | 6,857 | 6 | +3,143 |
| rustre-triage-peid | 6,139 | 5 | +3,861 |
| rustre-triage-entropy | 6,299 | 10 | +3,701 |
| rustre-debug-windbg | 6,028 | 5 | +3,972 |
| rustre-debug-gdb | 6,332 | 5 | +3,668 |
| rustre-fuzz-net | 6,852 | 7 | +3,148 |
| rustre-fuzz-cov | 6,854 | 7 | +3,146 |
| rustre-fuzz-libfuzzer | 6,544 | 6 | +3,456 |
| rustre-mobile-dyld | 7,556 | 9 | +2,444 |
| rustre-mobile-android | 6,494 | 5 | +3,506 |
| rustre-hex-view | 6,922 | 6 | +3,078 |
| rustre-project | 6,768 | 9 | +3,232 |
| rustre-sandbox | 6,786 | 3 | +3,214 |
| rustre-loader | 7,620 | 8 | +2,380 |
| rustre-analysis-callconv | 6,608 | 6 | +3,392 |
| rustre-loader-firmware (dup) | — | — | — |
| rustre-arch-dex | 6,721 | 6 | +3,279 |
| rustre-daemon | 6,301 | 7 | +3,699 |
| rustre-deobf-antianti | 6,113 | 8 | +3,887 |
| rustre-plugin-api | 6,273 | 8 | +3,727 |
| rustre-loader-console | 6,216 | 6 | +3,784 |
| rustre-pe-tools | 6,796 | 6 | +3,204 |

### Sotto-categoria 🟡B (5K-6K) — espansione grande necessaria

| Crate | Righe | File | Note critica |
|-------|-------|------|--------------|
| rustre-syscalls-linux | 5,738 | **1** ⚠️ | MONOLITICO |
| rustre-syscalls-windows | 5,624 | **1** ⚠️ | MONOLITICO |
| rustre-net-dissect (dup) | — | — | già sopra |
| rustre-symb-engine | 5,299 | **1** ⚠️ | MONOLITICO |
| rustre-trace-pt | 5,274 | **1** ⚠️ | MONOLITICO |
| rustre-ttd-recorder | 5,181 | **1** ⚠️ | MONOLITICO |
| rustre-net-proxy (dup) | — | — | già sopra |
| rustre-arch-riscv (dup) | — | — | già sopra |
| rustre-arch-68k | 5,659 | 2 | quasi monolitico |
| rustre-decompiler-expr | 5,526 | 2 | quasi monolitico |
| rustre-symbols | 5,779 | 8 | OK |
| rustre-fuzz | 7,110 | 6 | già OK |
| rustre-arch-wasm | 6,036 | 6 | OK |
| rustre-arch-z80 | 6,093 | 5 | OK |
| rustre-arch-lua | 6,168 | 3 | Pochi file |
| rustre-arch-ppc | 6,216 | 3 | Pochi file |
| rustre-arch-sparc | 5,247 | 4 | Espandere |
| rustre-arch-avr | 5,348 | 4 | Espandere |
| rustre-arch-cil | 5,249 | 5 | Espandere |
| rustre-analysis-fn | 6,226 | 7 | OK |
| rustre-symb | 5,897 | 7 | Espandere |
| rustre-symb-taint | 5,256 | 6 | Espandere |
| rustre-symb-z3 | 5,258 | 7 | Espandere |
| rustre-deobf-string | 5,788 | 7 | OK |
| rustre-deobf-opaque | 5,714 | 5 | Espandere |
| rustre-deobf-smc | 5,685 | 6 | Espandere |
| rustre-deobf-mba | 6,037 | 2 | Quasi monolitico |
| rustre-deobf-mhcde | 6,249 | 7 | OK |
| rustre-deobf-iadl | 6,074 | 7 | OK |
| rustre-diff | 5,665 | 8 | OK |
| rustre-demangle | 6,468 | 5 | OK |
| rustre-decompiler | 5,855 | 4 | Espandere |
| rustre-decompiler-c | 5,031 | 5 | Espandere |
| rustre-decompiler-type | 5,335 | 4 | Espandere |
| rustre-debug-unicorn | 5,646 | 4 | Espandere |
| rustre-crypto-whitebox | 5,924 | 3 | Pochi file |
| rustre-net | 6,845 | 3 | Pochi file |
| rustre-net-pcap | 6,166 | 3 | Pochi file |
| rustre-net-rules | 5,572 | 2 | Espandere |
| rustre-yara | 5,989 | 5 | OK |
| rustre-yara-engine | 5,029 | 3 | Pochi file |
| rustre-yara-rules | 6,179 | 4 | OK |
| rustre-sandbox-extract | 5,455 | 4 | Espandere |
| rustre-sandbox-monitor | 5,420 | 4 | Espandere |
| rustre-sandbox-report | 5,364 | 5 | Espandere |
| rustre-sandbox-vm | 5,277 | **1** ⚠️ | MONOLITICO |
| rustre-ti-correlate | 6,000 | 6 | OK |
| rustre-ti-malpedia | 5,502 | 11 | OK |
| rustre-ti-misp | 6,351 | 10 | OK |
| rustre-ti-vt | 5,866 | 10 | OK |
| rustre-trace | 5,983 | 4 | Espandere |
| rustre-trace-coresight | 5,260 | 4 | Espandere |
| rustre-trace-coverage | 5,219 | 4 | Espandere |
| rustre-trace-navigate | 5,208 | 2 | Quasi monolitico |
| rustre-ttd | 5,345 | 4 | Espandere |
| rustre-ttd-query | 5,136 | 3 | Pochi file |
| rustre-ttd-replay | 6,863 | 7 | OK |
| rustre-ttd-replayer | 5,287 | 6 | OK |
| rustre-mobile-ipa | 5,793 | 7 | OK |
| rustre-mobile-apktool | 5,587 | 8 | OK |
| rustre-loader-java | 5,985 | 4 | Espandere |
| rustre-loader-lua | 5,859 | 6 | OK |
| rustre-loader-luajit | 5,930 | 7 | OK |
| rustre-loader-dotnet | 6,061 | 7 | OK |
| rustre-loader-ole | 6,104 | 6 | OK |
| rustre-loader-wasm | 5,713 | 5 | Espandere |
| rustre-loader-pdf | 5,151 | 5 | Espandere |
| rustre-mcp-federation | 5,284 | 3 | Pochi file |
| rustre-mcp-tools | 6,082 | 2 | Quasi monolitico |
| rustre-symbols-pdb | 5,252 | 10 | OK |
| rustre-symbols-codeview | 5,286 | 5 | Espandere |
| rustre-symbols-dwarf | 5,330 | 5 | Espandere |
| rustre-symbols-stabs | 5,080 | 6 | Espandere |
| rustre-syscalls | 5,306 | 4 | Espandere |
| rustre-sysinternals | 5,024 | 4 | Espandere |
| rustre-triage-yara | 5,072 | 5 | Espandere |
| rustre-bin | 5,911 | 6 | Espandere |
| rustre-pe-editor | 6,024 | 5 | Espandere |
| rustre-pe-rebuild | 5,812 | 5 | Espandere |
| rustre-plugin-host | 5,233 | 6 | Espandere |
| rustre-arch | 5,809 | 6 | Espandere |
| rustre-agent-llm | 6,187 | 5 | Espandere |
| rustre-agent-workflow | 6,062 | 4 | Espandere |
| rustre-emu-unicorn | 5,208 | 7 | Espandere |
| rustre-emu-qiling | 5,885 | 5 | Espandere |
| rustre-emu-shellcode | 5,813 | 8 | OK |

---

## TIER 🔴 GUI — NON TOCCARE (sviluppata dall'utente)

| Crate | Righe | Note |
|-------|-------|------|
| rustre-gui | 73,949 | 🚫 GUI sviluppata dall'utente |
| rustre-gui-docking | 2,294 | 🚫 GUI |
| rustre-gui-views | 2,339 | 🚫 GUI |
| rustre-gui-themes | 2,516 | 🚫 GUI |

---

## Crate MONOLITICI da decomporre urgentemente

Questi hanno un buon numero di righe ma un solo file — contro P1 "Plugin everywhere" dell'architettura:

| Crate | Righe | Problema | Azione |
|-------|-------|----------|--------|
| rustre-net-proxy | 9,472 | 1 file | Suddividere in proxy_core/http_mitm/tls_intercept/traffic_log |
| rustre-net-dissect | 9,284 | 1 file | Suddividere in dissector_registry/protocol_*/ |
| rustre-syscalls-linux | 5,738 | 1 file | Suddividere in syscall_table/tracer/formatter |
| rustre-syscalls-windows | 5,624 | 1 file | Suddividere in api_monitor/hook_engine/report |
| rustre-ttd-recorder | 5,181 | 1 file | Suddividere in recorder/trace_writer/compression |
| rustre-symb-engine | 5,299 | 1 file | Suddividere in path_explorer/state_machine/solver_bridge |
| rustre-trace-pt | 5,274 | 1 file | Suddividere in pt_decoder/coverage/trace_builder |
| rustre-sandbox-vm | 5,277 | 1 file | Suddividere in vm_manager/snapshot/network |

---

## Piano di lavoro prioritizzato

### Fase 3A — Decomporre monolitici (impatto immediato su architettura)
Suddividere i crate a 1 file in 4-6 moduli ciascuno. Aggiunge ~3-5K righe per crate di contenuto denso.

### Fase 3B — Portare tutti i 🟡B da 5K a 8K
147 crate × +3K = ~441K righe extra

### Fase 3C — Portare tutti i 🟡A e ✅ da 7K a 12K
~80 crate × +5K = ~400K righe extra

### Fase 3D — Portare i TOP da 10K a 20K+
14 crate × +10K = ~140K righe extra

### Stima progressi
| Fase | Righe aggiunte | Totale atteso |
|------|----------------|---------------|
| Attuale | — | ~1.40M |
| +3A | ~50K | ~1.45M |
| +3B | ~441K | ~1.89M |
| +3C | ~400K | ~2.29M |
| +3D | ~140K | ~2.43M |
| Round aggiuntivi | ~1.57M | **~4.0M** |

---

## Confronto con info.txt — Crate critici da sviluppare

### rustre-core (15K) — ✅✅ ma mancano ancora:
- [ ] `binary_view.rs` come struct principale (quasi monolitico nel lib.rs)
- [ ] `permissions.rs` separato
- [ ] `event_bus.rs` separato dal lib.rs

### rustre-mem (13K) — ✅✅ ma mancano:
- [ ] `CompositeMemoryProvider` completo
- [ ] `TraceMemoryProvider` per TTD replay
- [ ] `PatchedMemoryProvider`

### rustre-il-lift (58K) — ✅✅ eccellente, continuare ad espandere

### rustre-arch-x86 (8.8K) — ✅ ma il lifter x86 dovrebbe essere 30-50K (per spec info.txt)
- [ ] Completare tutti i 3000+ opcode handlers per LLIL lift
- [ ] AVX-512 masking
- [ ] Tutti gli FPU x87 opcodes

### rustre-ttd (5.3K) — 🟡 il sistema TTD è frammentato e incompleto
- [ ] `rustre-ttd`: solo posizioni/indice
- [ ] `rustre-ttd-recorder`: monolitico, recorder ETW Windows
- [ ] `rustre-ttd-replay`: buono (6.8K)
- [ ] `rustre-ttd-replayer`: quasi duplicato
- [ ] `rustre-ttd-query`: query engine

### rustre-symb (5.9K) — 🟡 symbolic execution è sottosviluppata
- [ ] Path explosion mitigation
- [ ] Concolic execution end-to-end
- [ ] Integrazione Z3 reale (non solo stubs)

### rustre-deobf-vmlift (7.4K) — 🟡 necessita:
- [ ] ISA reconstruction completa
- [ ] Handler pattern matching per VMProtect2/3
- [ ] Lift a LLIL output completo

---

*Documento da aggiornare ad ogni sessione di sviluppo.*
